from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
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
    registered_at: str
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
        if source_type not in MODEL_SOURCE_TYPES:
            raise ValueError(f"unsupported model source_type: {source_type}")
        if trust_level not in TRUST_LEVELS:
            raise ValueError(f"unsupported trust_level: {trust_level}")
        if not provenance_ref:
            raise ValueError("provenance_ref is required")
        if not policy_profile:
            raise ValueError("policy_profile is required")

        digest = content_hash or self._derive_identifier_hash(
            source_type,
            source,
            immutable_identifier,
        )
        if not self._valid_hash(digest):
            raise ValueError("content_hash must be a sha256 hex digest")

        unsigned = {
            "model_id": new_id("model"),
            "source_type": source_type,
            "source": source,
            "license": license or "unknown",
            "content_hash": digest.lower(),
            "immutable_identifier": immutable_identifier or digest.lower(),
            "metadata": metadata,
            "trust_level": trust_level,
            "policy_profile": policy_profile,
            "provenance_ref": provenance_ref,
            "admissibility_status": "admissible",
            "registered_at": utc_now(),
        }
        signature = signer.sign(unsigned) if signer else None
        record = GovernedModelRecord(signature=signature, **unsigned)
        self._state["models"][record.model_id] = to_primitive(record)
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
            registered_at=raw["registered_at"],
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
        hasher = hashlib.sha256()
        if target.is_file():
            _hash_file(target, hasher, target.name)
        else:
            for item in sorted(target.rglob("*")):
                if item.is_file():
                    _hash_file(item, hasher, str(item.relative_to(target)))
        return hasher.hexdigest()

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
        return len(value) == 64 and all(char in "0123456789abcdefABCDEF" for char in value)

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def _hash_file(path: Path, hasher: Any, name: str) -> None:
    hasher.update(name.replace("\\", "/").encode("utf-8"))
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
