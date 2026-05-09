from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .governance import DecisionSigner
from .models import SignatureEnvelope, canonical_json, new_id, to_primitive, utc_now


MODEL_SOURCE_TYPES = {
    "local_path",
    "huggingface_model_id",
    "openai_compatible_endpoint",
    "ollama_endpoint",
    "external_gateway",
    "fine_tuned_checkpoint",
}
TRUST_LEVELS = {"untrusted", "quarantine", "reviewed", "trusted"}
REGISTRY_SCHEMA_VERSION = "1.1.0"
MUTABLE_EXTERNAL_SOURCE_TYPES = {
    "openai_compatible_endpoint",
    "external_gateway",
}
TRANSIENT_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".ipynb_checkpoints",
}
TRANSIENT_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.tmp",
    "*.log",
    "*.swp",
    "*.swo",
    "*~",
    ".DS_Store",
}
POLICY_PROFILE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


@dataclass(frozen=True)
class GovernedModelRecord:
    model_id: str
    source_type: str
    source: str
    license: str
    content_hash: str
    immutable_identifier: str
    metadata: dict[str, Any]
    trust_level: str
    policy_profile: str
    provenance_ref: str
    admissibility_status: str
    signature_status: str
    registered_at: str
    registry_schema_version: str
    signature: SignatureEnvelope | None = None


class GovernedModelRegistry:
    def __init__(self, registry_path: str | Path) -> None:
        self.path = Path(registry_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(
                json.dumps({"models": {}}, indent=2),
                encoding="utf-8",
            )
        self._state = json.loads(self.path.read_text(encoding="utf-8"))
        self._state.setdefault("models", {})
        self._state.setdefault("immutable_index", {})
        if not self._state["immutable_index"]:
            for model_id, raw in self._state["models"].items():
                immutable_identifier = raw.get("immutable_identifier")
                if immutable_identifier:
                    self._state["immutable_index"][immutable_identifier] = model_id

    def register(
        self,
        *,
        source_type: str,
        source: str,
        license: str,
        content_hash: str | None,
        immutable_identifier: str | None,
        metadata: dict[str, Any],
        trust_level: str,
        policy_profile: str,
        provenance_ref: str,
        signer: DecisionSigner | None = None,
    ) -> GovernedModelRecord:
        source = source.strip()
        if not source:
            raise ValueError("source is required")
        if source_type not in MODEL_SOURCE_TYPES:
            raise ValueError(f"unsupported model source_type: {source_type}")
        if trust_level not in TRUST_LEVELS:
            raise ValueError(f"unsupported trust_level: {trust_level}")
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        if not provenance_ref:
            raise ValueError("provenance_ref is required")
        self._validate_policy_profile(policy_profile)

        normalized_metadata = dict(metadata)
        self._validate_source_constraints(
            source_type=source_type,
            source=source,
            trust_level=trust_level,
            metadata=normalized_metadata,
        )

        digest = content_hash or self._derive_content_hash(
            source_type=source_type,
            source=source,
            immutable_identifier=immutable_identifier,
        )
        if not self._valid_hash(digest):
            raise ValueError("content_hash must be a sha256 hex digest")

        resolved_immutable_identifier = self._resolve_immutable_identifier(
            source_type=source_type,
            source=source,
            immutable_identifier=immutable_identifier,
            content_hash=digest,
            metadata=normalized_metadata,
        )

        existing_id = self._state["immutable_index"].get(
            resolved_immutable_identifier,
        )
        if existing_id:
            existing = self.get(existing_id)
            if (
                existing.source_type == source_type
                and existing.source == source
                and existing.content_hash == digest.lower()
            ):
                return existing
            raise ValueError(
                "immutable_identifier already registered with a different source",
            )

        admissibility_status = self._derive_admissibility_status(
            source_type=source_type,
            trust_level=trust_level,
            metadata=normalized_metadata,
        )

        unsigned = {
            "model_id": new_id("model"),
            "source_type": source_type,
            "source": source,
            "license": (license or "unknown").strip() or "unknown",
            "content_hash": digest.lower(),
            "immutable_identifier": resolved_immutable_identifier,
            "metadata": normalized_metadata,
            "trust_level": trust_level,
            "policy_profile": policy_profile,
            "provenance_ref": provenance_ref,
            "admissibility_status": admissibility_status,
            "signature_status": "pending",
            "registered_at": utc_now(),
            "registry_schema_version": REGISTRY_SCHEMA_VERSION,
        }
        signature = signer.sign(unsigned) if signer else None

        model_id = str(unsigned["model_id"])
        license_value = str(unsigned["license"])
        content_hash_value = str(unsigned["content_hash"])
        registered_at_value = str(unsigned["registered_at"])

        record = GovernedModelRecord(
            model_id=model_id,
            source_type=source_type,
            source=source,
            license=license_value,
            content_hash=content_hash_value,
            immutable_identifier=resolved_immutable_identifier,
            metadata=normalized_metadata,
            trust_level=trust_level,
            policy_profile=policy_profile,
            provenance_ref=provenance_ref,
            admissibility_status=admissibility_status,
            signature=signature,
            signature_status="signed" if signature else "unsigned",
            registered_at=registered_at_value,
            registry_schema_version=REGISTRY_SCHEMA_VERSION,
        )
        self._state["models"][record.model_id] = to_primitive(record)
        self._state["immutable_index"][record.immutable_identifier] = record.model_id
        self._save()
        return record

    def get(self, model_id: str) -> GovernedModelRecord:
        raw = self._state["models"].get(model_id)
        if not raw:
            raise KeyError(f"unknown model: {model_id}")
        signature = raw.get("signature")
        return GovernedModelRecord(
            model_id=raw["model_id"],
            source_type=raw["source_type"],
            source=raw["source"],
            license=raw["license"],
            content_hash=raw["content_hash"],
            immutable_identifier=raw["immutable_identifier"],
            metadata=dict(raw.get("metadata", {})),
            trust_level=raw["trust_level"],
            policy_profile=raw["policy_profile"],
            provenance_ref=raw["provenance_ref"],
            admissibility_status=raw["admissibility_status"],
            signature_status=raw.get(
                "signature_status",
                "signed" if signature else "unsigned",
            ),
            registered_at=raw["registered_at"],
            registry_schema_version=raw.get(
                "registry_schema_version",
                "1.0.0",
            ),
            signature=(
                SignatureEnvelope(
                    algorithm=signature["algorithm"],
                    key_id=signature["key_id"],
                    signature=signature["signature"],
                    signed_at=signature["signed_at"],
                )
                if signature
                else None
            ),
        )

    def list(self) -> list[GovernedModelRecord]:
        return [self.get(model_id) for model_id in sorted(self._state["models"])]

    def assert_executable(self, model_id: str) -> GovernedModelRecord:
        record = self.get(model_id)
        if record.admissibility_status != "admissible":
            raise ValueError("model is not admissible")
        if record.trust_level not in {"reviewed", "trusted"}:
            raise ValueError("model trust level is insufficient for execution")
        return record

    @staticmethod
    def hash_local_path(path: str | Path) -> str:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"model path not found: {target}")

        manifest_entries: list[dict[str, Any]] = []
        if target.is_file():
            manifest_entries.append(
                {
                    "relative_path": target.name,
                    "size": target.stat().st_size,
                    "sha256": _file_sha256(target),
                },
            )
        else:
            for item in _iter_stable_files(target):
                relative_path = item.relative_to(target).as_posix()
                manifest_entries.append(
                    {
                        "relative_path": relative_path,
                        "size": item.stat().st_size,
                        "sha256": _file_sha256(item),
                    },
                )

        hasher = hashlib.sha256()
        for entry in manifest_entries:
            hasher.update(canonical_json(entry).encode("utf-8"))
        return hasher.hexdigest()

    @staticmethod
    def _validate_policy_profile(policy_profile: str) -> None:
        value = policy_profile.strip()
        if not value:
            raise ValueError("policy_profile is required")
        if not POLICY_PROFILE_PATTERN.fullmatch(value):
            raise ValueError(
                "policy_profile must be a lowercase slug "
                "containing letters, digits, '-' or '_'",
            )

    @staticmethod
    def _validate_source_constraints(
        *,
        source_type: str,
        source: str,
        trust_level: str,
        metadata: dict[str, Any],
    ) -> None:
        if source_type == "local_path":
            target = Path(source)
            if not target.exists():
                raise FileNotFoundError(f"model path not found: {target}")
            metadata.setdefault("source_mutability", "local_immutable_by_hash")
            return

        if source_type == "huggingface_model_id":
            revision = GovernedModelRegistry._huggingface_revision(source, metadata)
            if revision:
                metadata["revision"] = revision
                metadata.setdefault("source_mutability", "pinned_revision")
            else:
                metadata.setdefault("source_mutability", "mutable_model_id")
                if trust_level in {"reviewed", "trusted"}:
                    raise ValueError(
                        "huggingface_model_id with reviewed/trusted trust level "
                        "requires immutable revision (source '<id>@<revision>' "
                        "or metadata.revision)",
                    )
            return

        if source_type in MUTABLE_EXTERNAL_SOURCE_TYPES:
            metadata.setdefault("source_mutability", "mutable_external_endpoint")
            proof = str(metadata.get("immutable_endpoint_proof", "")).strip()
            if trust_level in {"reviewed", "trusted"} and not proof:
                raise ValueError(
                    "mutable endpoint registration with reviewed/trusted trust "
                    "requires metadata.immutable_endpoint_proof",
                )
            return

        if source_type == "ollama_endpoint":
            metadata.setdefault("source_mutability", "local_runtime_endpoint")
            if trust_level == "trusted":
                raise ValueError(
                    "ollama_endpoint cannot be registered with trusted trust_level",
                )

    @staticmethod
    def _derive_admissibility_status(
        *,
        source_type: str,
        trust_level: str,
        metadata: dict[str, Any],
    ) -> str:
        if trust_level in {"untrusted", "quarantine"}:
            return "restricted"
        if source_type == "huggingface_model_id" and not metadata.get("revision"):
            return "restricted"
        if source_type in MUTABLE_EXTERNAL_SOURCE_TYPES and not metadata.get(
            "immutable_endpoint_proof",
        ):
            return "restricted"
        return "admissible"

    @staticmethod
    def _resolve_immutable_identifier(
        *,
        source_type: str,
        source: str,
        immutable_identifier: str | None,
        content_hash: str,
        metadata: dict[str, Any],
    ) -> str:
        explicit = (immutable_identifier or "").strip()
        if explicit:
            return explicit

        if source_type == "local_path":
            return f"sha256:{content_hash.lower()}"

        if source_type == "huggingface_model_id":
            revision = GovernedModelRegistry._huggingface_revision(source, metadata)
            if revision:
                source_id = source.split("@", 1)[0]
                return f"hf://{source_id}@{revision}"

        return content_hash.lower()

    @staticmethod
    def _derive_content_hash(
        *,
        source_type: str,
        source: str,
        immutable_identifier: str | None,
    ) -> str:
        if source_type == "local_path":
            return GovernedModelRegistry.hash_local_path(source)
        return GovernedModelRegistry._derive_identifier_hash(
            source_type,
            source,
            immutable_identifier,
        )

    @staticmethod
    def _huggingface_revision(source: str, metadata: dict[str, Any]) -> str | None:
        if "@" in source:
            maybe_revision = source.rsplit("@", 1)[1].strip()
            if maybe_revision:
                return maybe_revision
        revision = str(metadata.get("revision", "")).strip()
        return revision or None

    @staticmethod
    def _derive_identifier_hash(
        source_type: str,
        source: str,
        immutable_identifier: str | None,
    ) -> str:
        material = {
            "source_type": source_type,
            "source": source,
            "immutable_identifier": immutable_identifier,
        }
        return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()

    @staticmethod
    def _valid_hash(value: str) -> bool:
        return len(value) == 64 and all(
            char in "0123456789abcdefABCDEF" for char in value
        )

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def _is_transient_directory(name: str) -> bool:
    return name in TRANSIENT_DIRECTORY_NAMES


def _is_transient_file(name: str) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in TRANSIENT_FILE_PATTERNS)


def _iter_stable_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in root.walk(top_down=True):
        dirnames[:] = sorted(
            dirname for dirname in dirnames if not _is_transient_directory(dirname)
        )
        for filename in sorted(filenames):
            if _is_transient_file(filename):
                continue
            files.append(current_root / filename)
    return files


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
