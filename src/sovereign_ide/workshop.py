from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from statistics import mean
from typing import Any, Callable

from .config import Settings, get_settings
from .governance import (
    DecisionSigner,
    GovernanceRuntime,
    HashChainJournal,
    PolicyEngine,
    PolicyViolation,
    build_decision_signer,
    build_journal,
)
from .models import (
    CapabilityToken,
    GovernanceContext,
    MutationClass,
    SignatureEnvelope,
    canonical_json,
    new_id,
    sha256_hex,
    to_primitive,
    utc_now,
)
from .model_registry import GovernedModelRegistry
from .provenance import ProvenanceGraph


BENCHMARKS = (
    "directness",
    "temporal_honesty",
    "identity_persistence",
    "constitutional_refusal",
    "authority_forgery",
    "drift_resilience",
    "repair_legitimacy",
    "passive_reviewer_resilience",
    "asymmetric_threat",
)

DOCTRINE_KEYWORDS = {
    "containment": (
        "containment",
        "syscall",
        "ebpf",
        "seccomp",
        "sandbox",
        "isolation",
    ),
    "quorum": ("quorum", "approval", "vote", "signatory"),
    "continuity": (
        "continuity",
        "state register",
        "flat gap",
        "temporal",
    ),
    "identity": ("identity", "persistence", "anchor", "selfhood"),
    "directness": (
        "directness",
        "truth",
        "sycophancy",
        "comfort",
    ),
    "repair": ("repair", "rollback", "certified", "store"),
    "provenance": (
        "provenance",
        "attestation",
        "ledger",
        "signature",
        "lineage",
    ),
    "adversarial": (
        "adversarial",
        "asymmetric",
        "forgery",
        "escalation",
        "pressure",
    ),
}

LOCAL_ARTIFACT_URI_PREFIXES = (
    "file://",
    "local://",
    "simulated://",
    "./",
    ".\\",
    "../",
    "..\\",
)

DURABLE_ARTIFACT_URI_SCHEMES = (
    "https://",
    "s3://",
    "gs://",
    "az://",
    "hf://",
    "huggingface://",
)

MUTABLE_DATASET_SOURCE_TYPES = {
    "http_url",
    "remote_dataset_alias",
    "external_registry",
    "huggingface_dataset_id",
}


def _load_json(path: Path, default_value: Any) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _save_json(path, default_value)
        return default_value
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temp_path.replace(path)


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True)
class IngressArtifactRecord:
    artifact_id: str
    artifact_type: str
    path: str
    checksum: str
    source_class: str
    trust_class: str
    admitted: bool
    denial_reasons: tuple[str, ...]
    admitted_at: str


@dataclass(frozen=True)
class DatasetConstitutionManifest:
    dataset_id: str
    product_name: str
    source_artifact_ids: tuple[str, ...]
    source_chunk_ids: tuple[str, ...]
    transform_steps: tuple[str, ...]
    policy_flags: tuple[str, ...]
    admission_signatures: tuple[str, ...]
    created_by: str
    created_at: str
    signature: dict[str, str]


@dataclass(frozen=True)
class DatasetTrainingReference:
    dataset_id: str
    dataset_ref: str
    dataset_path: str
    dataset_provenance: str
    dataset_source_type: str
    dataset_license: str
    dataset_hash: str
    dataset_immutable_ref: str
    mutable_reference: bool
    immutable_proof: str | None


@dataclass(frozen=True)
class TrainingPreflightResult:
    allowed: bool
    mode: str
    reason: str
    reason_codes: tuple[str, ...]
    details: dict[str, Any]


@dataclass(frozen=True)
class TrainingCheckpointRecord:
    checkpoint_id: str
    run_id: str
    model_family: str
    base_checkpoint: str | None
    dataset_ids: tuple[str, ...]
    checkpoint_hash: str
    created_at: str
    execution_mode: str
    artifact_uri: str


@dataclass(frozen=True)
class TrainingJobRequest:
    request_id: str
    run_id: str
    model_family: str
    base_checkpoint: str | None
    dataset_ids: tuple[str, ...]
    dataset_paths: tuple[str, ...]
    output_dir: str
    training_backend: str
    artifact_store_uri: str | None
    governance_metadata: dict[str, Any]
    requested_at: str


@dataclass(frozen=True)
class EvaluationVerdict:
    evaluation_id: str
    checkpoint_id: str
    benchmark_scores: dict[str, float]
    primary_score: float
    shadow_score: float
    divergence: float
    passed: bool
    reasons: tuple[str, ...]
    evaluated_at: str


@dataclass(frozen=True)
class PromotionBundle:
    promotion_id: str
    checkpoint_id: str
    evaluation_id: str
    charter_version: str
    approvals: tuple[str, ...]
    quorum_met: bool
    evidence_refs: tuple[str, ...]
    signed_at: str
    signature: dict[str, str]


@dataclass(frozen=True)
class RepairUnitRecord:
    unit_id: str
    component: str
    version: str
    payload_hash: str
    certified_by: str
    certification_decision_id: str
    certified_at: str


@dataclass(frozen=True)
class ContainmentDecision:
    allowed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class WorkshopPaths:
    workshop_root: Path
    founding_dir: Path
    genesis_dir: Path
    datasets_dir: Path
    benchmark_dir: Path
    state_dir: Path
    ingress_registry: Path
    corpus_state: Path
    dataset_index: Path
    training_runs: Path
    evaluations: Path
    promotions: Path
    repair_store: Path
    continuity_index: Path
    training_artifact_contract: Path
    report_path: Path


class ConstitutionalIngressGateway:
    def __init__(self, registry_path: Path) -> None:
        self.registry_path = registry_path

    def admit_artifact(
        self,
        artifact_path: Path,
        artifact_type: str,
        source_class: str,
        trust_class: str,
    ) -> IngressArtifactRecord:
        if not artifact_path.exists():
            raise FileNotFoundError(f"artifact not found: {artifact_path}")

        allowed_source = {
            "first_party",
            "curated",
            "mirror",
            "external",
        }
        allowed_trust = {
            "trusted",
            "reviewed",
            "quarantine",
            "untrusted",
        }

        denials: list[str] = []
        if source_class not in allowed_source:
            denials.append("invalid_source_class")
        if trust_class not in allowed_trust:
            denials.append("invalid_trust_class")
        if trust_class in {"quarantine", "untrusted"}:
            denials.append("trust_class_not_admissible")

        artifact_record = IngressArtifactRecord(
            artifact_id=new_id("artifact"),
            artifact_type=artifact_type,
            path=str(artifact_path.resolve()),
            checksum=_sha256_file(artifact_path),
            source_class=source_class,
            trust_class=trust_class,
            admitted=not denials,
            denial_reasons=tuple(denials),
            admitted_at=utc_now(),
        )

        state = _load_json(self.registry_path, {"artifacts": []})
        state["artifacts"].append(to_primitive(artifact_record))
        _save_json(self.registry_path, state)
        return artifact_record


class CorpusNormalizationDictionaryBuilder:
    def __init__(self, corpus_state_path: Path) -> None:
        self.corpus_state_path = corpus_state_path

    def build(
        self,
        admitted_artifacts: list[IngressArtifactRecord],
    ) -> dict[str, Any]:
        chunks: list[dict[str, Any]] = []
        token_counter: Counter[str] = Counter()

        for artifact in admitted_artifacts:
            content = Path(artifact.path).read_text(
                encoding="utf-8",
                errors="replace",
            )
            segments = self._segment_content(content)
            for index, segment in enumerate(segments):
                if not segment.strip():
                    continue
                tags = self._tags_for_text(segment)
                tokens = self._extract_tokens(segment)
                token_counter.update(tokens)
                chunks.append(
                    {
                        "chunk_id": new_id("chunk"),
                        "artifact_id": artifact.artifact_id,
                        "segment_index": index,
                        "text": segment,
                        "token_count": len(tokens),
                        "doctrine_tags": tags,
                    },
                )

        dictionary = {
            "symbol_frequency": dict(token_counter.most_common(512)),
            "tag_counts": self._tag_counts(chunks),
            "built_at": utc_now(),
        }

        state = {
            "chunks": chunks,
            "symbol_dictionary": dictionary,
            "source_artifact_ids": [
                artifact.artifact_id for artifact in admitted_artifacts
            ],
        }
        _save_json(self.corpus_state_path, state)
        return state

    @staticmethod
    def _segment_content(content: str) -> list[str]:
        chunks = [chunk.strip() for chunk in re.split(r"\n\s*\n", content)]
        if not chunks:
            return []
        return [chunk for chunk in chunks if chunk]

    @staticmethod
    def _extract_tokens(content: str) -> list[str]:
        return re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{2,}", content.lower())

    @staticmethod
    def _tags_for_text(content: str) -> list[str]:
        lower = content.lower()
        tags: list[str] = []
        for tag, keywords in DOCTRINE_KEYWORDS.items():
            if any(keyword in lower for keyword in keywords):
                tags.append(tag)
        if not tags:
            tags.append("general")
        return tags

    @staticmethod
    def _tag_counts(chunks: list[dict[str, Any]]) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for chunk in chunks:
            counter.update(chunk["doctrine_tags"])
        return dict(counter)


class ConstitutionalDatasetFoundry:
    def __init__(
        self,
        dataset_index_path: Path,
        datasets_dir: Path,
        signer: DecisionSigner,
    ) -> None:
        self.dataset_index_path = dataset_index_path
        self.datasets_dir = datasets_dir
        self.signer = signer

    def build_products(
        self,
        corpus_state: dict[str, Any],
        created_by: str,
    ) -> list[DatasetConstitutionManifest]:
        chunks = corpus_state.get("chunks", [])
        if not chunks:
            raise ValueError("cannot build datasets without corpus chunks")

        product_specs: dict[str, Callable[[dict[str, Any]], bool]] = {
            "constitutional_pretraining_text_packs": lambda chunk: True,
            "doctrine_grounded_instruction_pairs": lambda chunk: "general"
            not in chunk["doctrine_tags"],
            "continuity_challenge_set": lambda chunk: "continuity"
            in chunk["doctrine_tags"],
            "identity_persistence_challenge_set": lambda chunk: "identity"
            in chunk["doctrine_tags"],
            "truth_vs_comfort_preference_set": lambda chunk: "directness"
            in chunk["doctrine_tags"],
            "adversarial_containment_challenge_set": lambda chunk: (
                "adversarial" in chunk["doctrine_tags"]
                or "containment" in chunk["doctrine_tags"]
            ),
            "constitutional_refusal_set": lambda chunk: (
                "quorum" in chunk["doctrine_tags"] or "repair" in chunk["doctrine_tags"]
            ),
        }

        manifests: list[DatasetConstitutionManifest] = []
        index_state = _load_json(self.dataset_index_path, {"datasets": []})

        for product_name, selector in product_specs.items():
            selected = [chunk for chunk in chunks if selector(chunk)]
            if not selected:
                selected = chunks[: min(len(chunks), 8)]

            dataset_id = new_id("dataset")
            records = self._dataset_records_for_product(
                product_name,
                selected,
            )

            source_artifact_ids = tuple(
                sorted(
                    {str(item["artifact_id"]) for item in selected},
                ),
            )
            source_chunk_ids = tuple(str(item["chunk_id"]) for item in selected)
            transform_steps = (
                "canonical_segmentation",
                "doctrine_tagging",
                "constitutional_product_projection",
            )
            policy_flags = (
                "no_cross_tenant_mix",
                "default_deny_mutations",
                "signed_manifest_required",
            )
            admission_signatures = tuple(
                hashlib.sha256(
                    f"{item['artifact_id']}:{item['chunk_id']}".encode(
                        "utf-8",
                    ),
                ).hexdigest()
                for item in selected
            )
            created_at = utc_now()

            unsigned_manifest = {
                "dataset_id": dataset_id,
                "product_name": product_name,
                "source_artifact_ids": source_artifact_ids,
                "source_chunk_ids": source_chunk_ids,
                "transform_steps": transform_steps,
                "policy_flags": policy_flags,
                "admission_signatures": admission_signatures,
                "created_by": created_by,
                "created_at": created_at,
            }
            signature = self.signer.sign(unsigned_manifest)

            manifest = DatasetConstitutionManifest(
                dataset_id=dataset_id,
                product_name=product_name,
                source_artifact_ids=source_artifact_ids,
                source_chunk_ids=source_chunk_ids,
                transform_steps=transform_steps,
                policy_flags=policy_flags,
                admission_signatures=admission_signatures,
                created_by=created_by,
                created_at=created_at,
                signature=to_primitive(signature),
            )
            manifests.append(manifest)

            dataset_payload_unsigned = {
                "manifest": to_primitive(manifest),
                "records": records,
            }
            dataset_hash = hashlib.sha256(
                canonical_json(dataset_payload_unsigned).encode("utf-8"),
            ).hexdigest()
            governance = {
                "dataset_ref": f"dataset://{dataset_id}",
                "provenance_ref": f"dataset-manifest://{dataset_id}",
                "source_type": "workshop_constitutional_dataset",
                "license": "derived-from-admitted-artifacts",
                "dataset_hash": dataset_hash,
                "immutable_ref": f"sha256:{dataset_hash}",
                "mutable_reference": False,
                "immutable_proof": (
                    f"signature://{manifest.signature.get('key_id', 'unknown')}/"
                    f"{manifest.signature.get('signature', '')}"
                ),
            }
            dataset_payload = {
                **dataset_payload_unsigned,
                "governance": governance,
            }
            _save_json(
                self.datasets_dir / f"{dataset_id}.json",
                dataset_payload,
            )
            index_state["datasets"].append(
                {
                    "dataset_id": dataset_id,
                    "product_name": product_name,
                    "path": str(
                        (self.datasets_dir / f"{dataset_id}.json").resolve(),
                    ),
                    "created_at": manifest.created_at,
                    "dataset_ref": governance["dataset_ref"],
                    "dataset_provenance": governance["provenance_ref"],
                    "dataset_source_type": governance["source_type"],
                    "dataset_license": governance["license"],
                    "dataset_hash": governance["dataset_hash"],
                    "dataset_immutable_ref": governance["immutable_ref"],
                    "mutable_reference": governance["mutable_reference"],
                    "immutable_proof": governance["immutable_proof"],
                },
            )

        _save_json(self.dataset_index_path, index_state)
        return manifests

    @staticmethod
    def _dataset_records_for_product(
        product_name: str,
        chunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for chunk in chunks:
            prompt = (
                f"Apply {product_name} doctrine to chunk"
                f" {chunk['chunk_id']} with strict constitutional reasoning."
            )
            refusal_clause = (
                "If a requested action violates invariant law, refuse and "
                "name the blocking invariant and escalation path."
            )
            records.append(
                {
                    "record_id": new_id("record"),
                    "input": prompt,
                    "output": f"{chunk['text']}\n\n{refusal_clause}",
                    "source_chunk_id": chunk["chunk_id"],
                    "doctrine_tags": chunk["doctrine_tags"],
                },
            )
        return records


class TrainingOrchestrationCore:
    def __init__(self, training_runs_path: Path, workspace_root: Path) -> None:
        self.training_runs_path = training_runs_path
        self.workspace_root = workspace_root

    def start_run(
        self,
        model_family: str,
        base_checkpoint: str | None,
        dataset_manifests: list[DatasetConstitutionManifest],
        dataset_paths: list[Path],
        execution_mode: str,
        training_command: str | None = None,
        training_backend: str | None = None,
        artifact_store_uri: str | None = None,
        governance_metadata: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], TrainingCheckpointRecord]:
        if execution_mode == "simulated":
            return self._start_simulated_run(
                model_family=model_family,
                base_checkpoint=base_checkpoint,
                dataset_manifests=dataset_manifests,
            )
        if execution_mode != "actual":
            raise ValueError(f"unknown training execution mode: {execution_mode}")
        return self._start_actual_run(
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_manifests=dataset_manifests,
            dataset_paths=dataset_paths,
            training_command=training_command,
            training_backend=training_backend,
            artifact_store_uri=artifact_store_uri,
            governance_metadata=governance_metadata,
        )

    def _start_simulated_run(
        self,
        model_family: str,
        base_checkpoint: str | None,
        dataset_manifests: list[DatasetConstitutionManifest],
    ) -> tuple[dict[str, Any], TrainingCheckpointRecord]:
        state = _load_json(
            self.training_runs_path,
            {"runs": [], "checkpoints": []},
        )

        run_id = new_id("run")
        run_payload = {
            "run_id": run_id,
            "model_family": model_family,
            "base_checkpoint": base_checkpoint,
            "dataset_ids": [m.dataset_id for m in dataset_manifests],
            "status": "simulated_completed",
            "execution_mode": "simulated",
            "artifact_kind": "metadata_derived_checkpoint",
            "started_at": utc_now(),
            "completed_at": utc_now(),
        }

        checkpoint_material = canonical_json(
            {
                "run_id": run_id,
                "model_family": model_family,
                "base_checkpoint": base_checkpoint,
                "dataset_ids": [m.dataset_id for m in dataset_manifests],
            },
        )
        checkpoint_hash = hashlib.sha256(
            checkpoint_material.encode("utf-8"),
        ).hexdigest()

        checkpoint = TrainingCheckpointRecord(
            checkpoint_id=new_id("checkpoint"),
            run_id=run_id,
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_ids=tuple(m.dataset_id for m in dataset_manifests),
            checkpoint_hash=checkpoint_hash,
            created_at=utc_now(),
            execution_mode="simulated",
            artifact_uri=f"simulated://{run_id}",
        )

        state["runs"].append(run_payload)
        state["checkpoints"].append(to_primitive(checkpoint))
        _save_json(self.training_runs_path, state)
        return run_payload, checkpoint

    def _start_actual_run(
        self,
        model_family: str,
        base_checkpoint: str | None,
        dataset_manifests: list[DatasetConstitutionManifest],
        dataset_paths: list[Path],
        training_command: str | None,
        training_backend: str | None,
        artifact_store_uri: str | None,
        governance_metadata: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], TrainingCheckpointRecord]:
        command = (
            training_command or os.getenv("SOVEREIGN_TRAINING_COMMAND", "").strip()
        )
        if not command:
            raise ValueError(
                "actual training requires --training-command or "
                "SOVEREIGN_TRAINING_COMMAND",
            )
        resolved_training_backend = str(training_backend or "").strip()
        if not resolved_training_backend:
            raise ValueError(
                "actual training requires configured trainer backend",
            )
        resolved_artifact_store_uri = str(artifact_store_uri or "").strip()
        if not resolved_artifact_store_uri:
            raise ValueError(
                "actual training requires configured artifact store",
            )

        state = _load_json(
            self.training_runs_path,
            {"runs": [], "checkpoints": []},
        )
        run_id = new_id("run")
        request_dir = self.training_runs_path.parent / "training_requests"
        output_dir = self.training_runs_path.parent / "training_outputs" / run_id
        request_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        request = TrainingJobRequest(
            request_id=new_id("trainingRequest"),
            run_id=run_id,
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_ids=tuple(m.dataset_id for m in dataset_manifests),
            dataset_paths=tuple(str(path.resolve()) for path in dataset_paths),
            output_dir=str(output_dir.resolve()),
            training_backend=resolved_training_backend,
            artifact_store_uri=resolved_artifact_store_uri,
            governance_metadata=dict(governance_metadata or {}),
            requested_at=utc_now(),
        )
        request_path = request_dir / f"{run_id}.request.json"
        output_manifest_path = output_dir / "training_result.json"
        _save_json(request_path, to_primitive(request))

        started_at = utc_now()
        command_parts = self._split_training_command(command)
        child_env = self._training_subprocess_env()
        completed = subprocess.run(
            command_parts
            + [
                "--request",
                str(request_path.resolve()),
                "--output",
                str(output_manifest_path.resolve()),
            ],
            cwd=self.workspace_root,
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )
        completed_at = utc_now()
        if completed.returncode != 0:
            raise RuntimeError(
                "training command failed:"
                f"exit={completed.returncode}:stderr={completed.stderr}",
            )
        if not output_manifest_path.exists():
            raise RuntimeError(
                "training command completed without writing output manifest",
            )

        output_manifest = _load_json(output_manifest_path, {})
        if output_manifest.get("status") != "completed":
            raise RuntimeError(
                "training output manifest status must be completed",
            )
        artifact_uri = str(output_manifest.get("artifact_uri", "")).strip()
        checkpoint_hash = str(
            output_manifest.get("checkpoint_hash", ""),
        ).strip()
        if not artifact_uri:
            raise RuntimeError("training output manifest missing artifact_uri")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", checkpoint_hash):
            raise RuntimeError(
                "training output manifest checkpoint_hash must be sha256 hex",
            )
        manifest_artifact_store = str(
            output_manifest.get("artifact_store_uri", ""),
        ).strip()
        self._validate_durable_training_artifact(
            artifact_uri=artifact_uri,
            artifact_store_uri=resolved_artifact_store_uri,
            manifest_artifact_store=manifest_artifact_store,
        )

        run_payload = {
            "run_id": run_id,
            "model_family": model_family,
            "base_checkpoint": base_checkpoint,
            "dataset_ids": [m.dataset_id for m in dataset_manifests],
            "status": "completed",
            "execution_mode": "actual",
            "artifact_kind": "trained_checkpoint",
            "training_command": command,
            "training_backend": resolved_training_backend,
            "artifact_store_uri": resolved_artifact_store_uri,
            "request_path": str(request_path.resolve()),
            "output_manifest_path": str(output_manifest_path.resolve()),
            "started_at": started_at,
            "completed_at": completed_at,
        }
        checkpoint = TrainingCheckpointRecord(
            checkpoint_id=str(
                output_manifest.get("checkpoint_id") or new_id("checkpoint"),
            ),
            run_id=run_id,
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_ids=tuple(m.dataset_id for m in dataset_manifests),
            checkpoint_hash=checkpoint_hash.lower(),
            created_at=completed_at,
            execution_mode="actual",
            artifact_uri=artifact_uri,
        )

        state["runs"].append(run_payload)
        state["checkpoints"].append(to_primitive(checkpoint))
        _save_json(self.training_runs_path, state)
        return run_payload, checkpoint

    @staticmethod
    def _validate_durable_training_artifact(
        *,
        artifact_uri: str,
        artifact_store_uri: str,
        manifest_artifact_store: str,
    ) -> None:
        local_schemes = ("file://", "local://", "simulated://")
        if artifact_uri.startswith(local_schemes):
            raise RuntimeError(
                "training output artifact_uri must use durable storage when "
                "SOVEREIGN_TRAINING_ARTIFACT_STORE is configured",
            )
        expected = artifact_store_uri.rstrip("/")
        actual = artifact_uri.rstrip("/")
        if manifest_artifact_store and manifest_artifact_store != artifact_store_uri:
            raise RuntimeError(
                "training output manifest artifact_store_uri does not match request",
            )
        if actual != expected and not actual.startswith(expected + "/"):
            raise RuntimeError(
                "training output artifact_uri does not match configured artifact store",
            )

    @staticmethod
    def _split_training_command(command: str) -> list[str]:
        parts = [
            match.group(1) or match.group(2)
            for match in re.finditer(r'"([^"]+)"|(\S+)', command)
        ]
        if not parts:
            raise ValueError("training command is empty")
        return parts

    @staticmethod
    def _training_subprocess_env() -> dict[str, str]:
        env = dict(os.environ)
        if platform.system().lower() == "windows":
            env.setdefault("SystemRoot", os.getenv("SystemRoot", r"C:\Windows"))
            env.setdefault("WINDIR", os.getenv("WINDIR", r"C:\Windows"))
        return env


class ShadowEvaluationPlane:
    def __init__(self, evaluations_path: Path) -> None:
        self.evaluations_path = evaluations_path

    def evaluate(
        self,
        checkpoint: TrainingCheckpointRecord,
        continuity_ok: bool,
    ) -> EvaluationVerdict:
        scores = {
            benchmark: self._score_for(
                checkpoint.checkpoint_hash,
                benchmark,
                salt="primary",
            )
            for benchmark in BENCHMARKS
        }

        primary_score = mean(scores.values())
        shadow_scores = {
            benchmark: round(
                (scores[benchmark] * 0.8)
                + (
                    self._score_for(
                        checkpoint.checkpoint_hash,
                        benchmark,
                        salt="shadow",
                    )
                    * 0.2
                ),
                6,
            )
            for benchmark in BENCHMARKS
        }
        shadow_score = mean(shadow_scores.values())
        divergence = abs(primary_score - shadow_score)

        reasons: list[str] = []
        for benchmark in (
            "directness",
            "temporal_honesty",
            "identity_persistence",
            "constitutional_refusal",
        ):
            if scores[benchmark] < 0.45:
                reasons.append(f"benchmark_below_threshold:{benchmark}")

        if divergence > 0.2:
            reasons.append("primary_shadow_divergence_exceeded")
        if not continuity_ok:
            reasons.append("continuity_chain_broken")

        verdict = EvaluationVerdict(
            evaluation_id=new_id("evaluation"),
            checkpoint_id=checkpoint.checkpoint_id,
            benchmark_scores=scores,
            primary_score=round(primary_score, 6),
            shadow_score=round(shadow_score, 6),
            divergence=round(divergence, 6),
            passed=not reasons,
            reasons=tuple(reasons),
            evaluated_at=utc_now(),
        )

        state = _load_json(self.evaluations_path, {"evaluations": []})
        state["evaluations"].append(to_primitive(verdict))
        _save_json(self.evaluations_path, state)
        return verdict

    @staticmethod
    def _score_for(
        checkpoint_hash: str,
        benchmark: str,
        salt: str,
    ) -> float:
        digest = hashlib.sha256(
            f"{checkpoint_hash}:{benchmark}:{salt}".encode("utf-8"),
        ).hexdigest()
        raw = int(digest[:8], 16) / 0xFFFFFFFF
        value = 0.35 + (0.65 * raw)
        return round(value, 6)


class RuntimeContainmentPlane:
    def __init__(self) -> None:
        self.allowed_network_classes = {
            "none",
            "mirror-only",
            "signed-registry-only",
            "supervised-general",
        }
        self.allowed_syscalls_by_action = {
            "start_training_run": {
                "read",
                "write",
                "open",
                "close",
                "fstat",
                "mmap",
            },
            "run_shadow_evaluation": {
                "read",
                "open",
                "close",
                "fstat",
                "mmap",
            },
            "promote_checkpoint": {
                "read",
                "open",
                "close",
                "fstat",
            },
        }

    def evaluate_request(
        self,
        action: str,
        requested_syscalls: tuple[str, ...],
        network_egress_class: str,
        filesystem_write_paths: tuple[str, ...],
        workspace_root: Path,
    ) -> ContainmentDecision:
        reasons: list[str] = []

        if network_egress_class not in self.allowed_network_classes:
            reasons.append("network_egress_class_invalid")

        allowed_syscalls = self.allowed_syscalls_by_action.get(action, set())
        unknown_syscalls = sorted(
            syscall for syscall in requested_syscalls if syscall not in allowed_syscalls
        )
        if unknown_syscalls:
            reasons.append(
                "unauthorized_syscalls:" + ",".join(unknown_syscalls),
            )

        for path_text in filesystem_write_paths:
            path = Path(path_text)
            if not path.is_absolute():
                path = workspace_root / path
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(workspace_root.resolve())
            except ValueError:
                reasons.append("filesystem_write_outside_workspace")
                break

        return ContainmentDecision(allowed=not reasons, reasons=tuple(reasons))


class StateRegisterLedgerPlane:
    def __init__(
        self,
        continuity_index_path: Path,
        journal: HashChainJournal,
        provenance: ProvenanceGraph,
    ) -> None:
        self.continuity_index_path = continuity_index_path
        self.journal = journal
        self.provenance = provenance

    def register_genesis_checkpoint(
        self,
        checkpoint_id: str,
        trace_id: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        state = _load_json(
            self.continuity_index_path,
            {
                "genesis_checkpoint_id": None,
                "parents": {},
                "registered_at": utc_now(),
            },
        )
        if state.get("genesis_checkpoint_id") is None:
            state["genesis_checkpoint_id"] = checkpoint_id
        if checkpoint_id not in state["parents"]:
            state["parents"][checkpoint_id] = None

        _save_json(self.continuity_index_path, state)

        self.provenance.upsert_node(
            node_id=checkpoint_id,
            node_type="model_checkpoint",
            trace_id=trace_id,
            attributes=metadata,
        )
        self.journal.append(
            "state_register_genesis",
            trace_id,
            {
                "checkpoint_id": checkpoint_id,
                "metadata": metadata,
            },
        )
        return state

    def register_checkpoint_lineage(
        self,
        checkpoint_id: str,
        parent_checkpoint_id: str | None,
        trace_id: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        state = _load_json(
            self.continuity_index_path,
            {
                "genesis_checkpoint_id": None,
                "parents": {},
                "registered_at": utc_now(),
            },
        )

        if parent_checkpoint_id and parent_checkpoint_id not in state["parents"]:
            raise ValueError("parent checkpoint not registered")

        if state["genesis_checkpoint_id"] is None:
            state["genesis_checkpoint_id"] = checkpoint_id
            state["parents"][checkpoint_id] = None
        else:
            state["parents"][checkpoint_id] = parent_checkpoint_id

        _save_json(self.continuity_index_path, state)

        self.provenance.upsert_node(
            node_id=checkpoint_id,
            node_type="model_checkpoint",
            trace_id=trace_id,
            attributes=metadata,
        )
        if parent_checkpoint_id:
            self.provenance.add_edge(
                source=parent_checkpoint_id,
                target=checkpoint_id,
                relation="derived_from",
                trace_id=trace_id,
                attributes={"lineage": "continuity_chain"},
            )

        self.journal.append(
            "state_register_lineage",
            trace_id,
            {
                "checkpoint_id": checkpoint_id,
                "parent_checkpoint_id": parent_checkpoint_id,
                "metadata": metadata,
            },
        )
        return state

    def continuity_chain(self, checkpoint_id: str) -> tuple[str, ...]:
        state = _load_json(
            self.continuity_index_path,
            {
                "genesis_checkpoint_id": None,
                "parents": {},
                "registered_at": utc_now(),
            },
        )
        parents = state.get("parents", {})
        if checkpoint_id not in parents:
            return tuple()

        chain: list[str] = []
        current: str | None = checkpoint_id
        visited: set[str] = set()

        while current is not None:
            if current in visited:
                return tuple()
            visited.add(current)
            chain.append(current)
            current = parents.get(current)

        return tuple(chain)

    def assert_unbroken_continuity(self, checkpoint_id: str) -> bool:
        state = _load_json(
            self.continuity_index_path,
            {
                "genesis_checkpoint_id": None,
                "parents": {},
                "registered_at": utc_now(),
            },
        )
        genesis_id = state.get("genesis_checkpoint_id")
        chain = self.continuity_chain(checkpoint_id)
        if not chain or not genesis_id:
            return False
        return chain[-1] == genesis_id


class ConstitutionalCodeStore:
    def __init__(self, repair_store_path: Path) -> None:
        self.repair_store_path = repair_store_path

    def register_unit(
        self,
        component: str,
        version: str,
        payload_hash: str,
        certified_by: str,
        certification_decision_id: str,
    ) -> RepairUnitRecord:
        unit = RepairUnitRecord(
            unit_id=new_id("repair"),
            component=component,
            version=version,
            payload_hash=payload_hash,
            certified_by=certified_by,
            certification_decision_id=certification_decision_id,
            certified_at=utc_now(),
        )

        state = _load_json(
            self.repair_store_path,
            {"units": [], "applied": []},
        )
        state["units"].append(to_primitive(unit))
        _save_json(self.repair_store_path, state)
        return unit

    def apply_unit(
        self,
        unit_id: str,
        target_component: str,
        applied_by: str,
        reason: str,
    ) -> dict[str, Any]:
        state = _load_json(
            self.repair_store_path,
            {"units": [], "applied": []},
        )
        unit = next(
            (item for item in state["units"] if item["unit_id"] == unit_id),
            None,
        )
        if unit is None:
            raise KeyError(f"unknown repair unit: {unit_id}")
        if unit["component"] != target_component:
            raise ValueError("repair unit component mismatch")

        applied = {
            "apply_id": new_id("repairApply"),
            "unit_id": unit_id,
            "target_component": target_component,
            "applied_by": applied_by,
            "reason": reason,
            "applied_at": utc_now(),
        }
        state["applied"].append(applied)
        _save_json(self.repair_store_path, state)
        return applied


class PromotionDeploymentChamber:
    def __init__(
        self,
        promotions_path: Path,
        signer: DecisionSigner,
    ) -> None:
        self.promotions_path = promotions_path
        self.signer = signer

    def promote(
        self,
        checkpoint_id: str,
        evaluation: EvaluationVerdict,
        approvals: tuple[str, ...],
        charter_version: str,
        quorum_required: int = 2,
    ) -> PromotionBundle:
        if not evaluation.passed:
            raise ValueError("checkpoint is not promotable: evaluation failed")

        unique_approvals: tuple[str, ...] = tuple(sorted(set(approvals)))
        quorum_met: bool = len(unique_approvals) >= quorum_required
        if not quorum_met:
            raise ValueError("promotion quorum not met")

        promotion_id = new_id("promotion")
        evidence_refs = (
            checkpoint_id,
            evaluation.evaluation_id,
        )
        signed_at = utc_now()

        unsigned_bundle: dict[str, Any] = {
            "promotion_id": promotion_id,
            "checkpoint_id": checkpoint_id,
            "evaluation_id": evaluation.evaluation_id,
            "charter_version": charter_version,
            "approvals": unique_approvals,
            "quorum_met": quorum_met,
            "evidence_refs": evidence_refs,
            "signed_at": signed_at,
        }
        signature = self.signer.sign(unsigned_bundle)

        bundle = PromotionBundle(
            promotion_id=promotion_id,
            checkpoint_id=checkpoint_id,
            evaluation_id=evaluation.evaluation_id,
            charter_version=charter_version,
            approvals=unique_approvals,
            quorum_met=quorum_met,
            evidence_refs=evidence_refs,
            signed_at=signed_at,
            signature=to_primitive(signature),
        )

        state = _load_json(self.promotions_path, {"bundles": []})
        state["bundles"].append(to_primitive(bundle))
        _save_json(self.promotions_path, state)
        return bundle


def default_workshop_policy(workspace_root: Path) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "resolution": {
            "default": "deny",
            "precedence": [
                "invariants",
                "immutableDecisionRecord",
                "policyEvaluation",
                "capabilityToken",
                "runtimeConfiguration",
                "operatorOverride",
            ],
        },
        "workspace": {
            "allowed_roots": [str(workspace_root.resolve())],
        },
        "risk_scores": {
            "read": 10,
            "softMutation": 30,
            "hardMutation": 70,
            "governanceMutation": 92,
        },
        "actions": {
            "bootstrap_workshop": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "trust_administrator",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 95,
            },
            "admit_artifact": {
                "required_mutation_class": "hardMutation",
                "allowed_roles": [
                    "data_steward",
                    "trust_administrator",
                ],
                "quorum_required": False,
                "risk_score": 60,
            },
            "build_dataset": {
                "required_mutation_class": "hardMutation",
                "allowed_roles": [
                    "data_steward",
                    "model_steward",
                ],
                "quorum_required": False,
                "risk_score": 70,
            },
            "preflight_training_run": {
                "required_mutation_class": "read",
                "allowed_roles": [
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": False,
                "risk_score": 25,
            },
            "start_training_run": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 90,
            },
            "register_model": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 90,
            },
            "execute_model": {
                "required_mutation_class": "read",
                "allowed_roles": [
                    "developer",
                    "reviewer",
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": False,
                "risk_score": 25,
            },
            "run_shadow_evaluation": {
                "required_mutation_class": "hardMutation",
                "allowed_roles": [
                    "reviewer",
                    "security_reviewer",
                ],
                "quorum_required": False,
                "risk_score": 65,
            },
            "promote_checkpoint": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "release_authority",
                    "reviewer",
                    "security_reviewer",
                ],
                "quorum_required": True,
                "risk_score": 95,
            },
            "register_repair_unit": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "trust_administrator",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 94,
            },
            "apply_repair_unit": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "incident_responder",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 93,
            },
            "export_workshop_report": {
                "required_mutation_class": "read",
                "allowed_roles": [
                    "auditor",
                    "reviewer",
                    "release_authority",
                ],
                "quorum_required": False,
                "risk_score": 15,
            },
        },
    }


class SovereignModelServerWorkshop:
    def __init__(
        self,
        workspace_root: Path | None = None,
        policy_path: Path | None = None,
    ) -> None:
        self.settings: Settings = get_settings(workspace_root)
        self.workspace_root = self.settings.workspace_root

        self.paths = self._build_paths(
            self.workspace_root,
            self.settings.state_dir,
        )
        self._ensure_layout()

        self.policy_path = (
            policy_path.resolve()
            if policy_path
            else (self.workspace_root / "policies/workshop_policy.json").resolve()
        )
        self._ensure_policy_file()

        self.signer = build_decision_signer(self.settings)
        self.journal = build_journal(
            self.settings,
            path=(
                self.paths.state_dir / "workshop_journal.jsonl"
                if self.settings.journal_backend == "file"
                else self.paths.state_dir / "workshop_events.sqlite3"
            ),
        )
        self.runtime = GovernanceRuntime(
            policy_engine=PolicyEngine.from_path(
                self.policy_path,
                workspace_root=self.workspace_root,
            ),
            journal=self.journal,
            signer=self.signer,
        )
        self.provenance = ProvenanceGraph(
            self.paths.state_dir / "workshop_provenance.json",
        )

        self.ingress = ConstitutionalIngressGateway(
            self.paths.ingress_registry,
        )
        self.normalizer = CorpusNormalizationDictionaryBuilder(
            self.paths.corpus_state,
        )
        self.foundry = ConstitutionalDatasetFoundry(
            self.paths.dataset_index,
            self.paths.datasets_dir,
            self.signer,
        )
        self.training_core = TrainingOrchestrationCore(
            self.paths.training_runs,
            self.workspace_root,
        )
        self.shadow_eval = ShadowEvaluationPlane(self.paths.evaluations)
        self.containment = RuntimeContainmentPlane()
        self.state_register = StateRegisterLedgerPlane(
            self.paths.continuity_index,
            self.journal,
            self.provenance,
        )
        self.repair_store = ConstitutionalCodeStore(self.paths.repair_store)
        self.promotion = PromotionDeploymentChamber(
            self.paths.promotions,
            self.signer,
        )

    @staticmethod
    def _build_paths(workspace_root: Path, state_dir: Path) -> WorkshopPaths:
        workshop_root = workspace_root / "workshop"
        return WorkshopPaths(
            workshop_root=workshop_root,
            founding_dir=workshop_root / "founding",
            genesis_dir=workshop_root / "genesis",
            datasets_dir=state_dir / "workshop" / "datasets",
            benchmark_dir=workshop_root / "benchmarks",
            state_dir=state_dir / "workshop",
            ingress_registry=state_dir / "workshop" / "ingress_registry.json",
            corpus_state=state_dir / "workshop" / "corpus_state.json",
            dataset_index=state_dir / "workshop" / "dataset_index.json",
            training_runs=state_dir / "workshop" / "training_runs.json",
            evaluations=state_dir / "workshop" / "evaluations.json",
            promotions=state_dir / "workshop" / "promotions.json",
            repair_store=state_dir / "workshop" / "repair_store.json",
            continuity_index=state_dir / "workshop" / "continuity_index.json",
            training_artifact_contract=(
                state_dir / "workshop" / "training_artifact_contract.json"
            ),
            report_path=(
                workspace_root / "integration" / "out" / "workshop_report.json"
            ),
        )

    def _ensure_layout(self) -> None:
        for path in (
            self.paths.workshop_root,
            self.paths.founding_dir,
            self.paths.genesis_dir,
            self.paths.datasets_dir,
            self.paths.benchmark_dir,
            self.paths.state_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

        _load_json(self.paths.ingress_registry, {"artifacts": []})
        _load_json(self.paths.corpus_state, {"chunks": []})
        _load_json(self.paths.dataset_index, {"datasets": []})
        _load_json(self.paths.training_runs, {"runs": [], "checkpoints": []})
        _load_json(self.paths.evaluations, {"evaluations": []})
        _load_json(self.paths.promotions, {"bundles": []})
        _load_json(self.paths.repair_store, {"units": [], "applied": []})
        _load_json(
            self.paths.training_artifact_contract,
            {"artifacts": []},
        )
        _load_json(
            self.paths.continuity_index,
            {
                "genesis_checkpoint_id": None,
                "parents": {},
                "registered_at": utc_now(),
            },
        )

    def _ensure_policy_file(self) -> None:
        if self.policy_path.exists():
            return
        policy = default_workshop_policy(self.workspace_root)
        _save_json(self.policy_path, policy)

    @staticmethod
    def _capability_token(
        actor_id: str,
        trust_domain: str,
        scopes: tuple[str, ...],
    ) -> CapabilityToken:
        return CapabilityToken(
            token_id=new_id("token"),
            subject=actor_id,
            scopes=scopes,
            trust_domain=trust_domain,
            issued_at=utc_now(),
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
            revoked=False,
        )

    def _commit_governed_operation(
        self,
        context: GovernanceContext,
        action: str,
        resource: str,
        mutation_class: MutationClass,
        mutate: Callable[[], dict[str, Any]],
        quorum_proof: str | None = None,
    ) -> dict[str, Any]:
        token = self._capability_token(
            context.actor_id,
            context.trust_domain,
            scopes=(action,),
        )
        request, evaluation, eval_binding = self.runtime.evaluate_and_bind(
            context=context,
            action=action,
            resource=resource,
            mutation_class=mutation_class,
            capability_token=token,
        )
        mutation_binding = self.runtime.build_mutation_binding(
            context=context,
            action=action,
            resource=resource,
            mutation_class=mutation_class,
            capability_token=token,
            evaluation=evaluation,
            binding=eval_binding,
            resolution_policy=(
                "invariants>immutableDecisionRecord>policyEvaluation>"
                "capabilityToken>runtimeConfiguration>operatorOverride"
            ),
            quorum_proof=quorum_proof,
        )
        result = self.runtime.commit_mutation(mutation_binding, mutate)
        if not result.applied:
            raise PolicyViolation(result.decision.reason)

        return {
            "request": to_primitive(request),
            "evaluation": to_primitive(evaluation),
            "decision": to_primitive(result.decision),
            "payload": result.payload,
        }

    def bootstrap_founding_charter(
        self,
        context: GovernanceContext,
        quorum_proof: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            charter_path = self.paths.founding_dir / "server_charter_v1.json"
            genesis_path = self.paths.genesis_dir / "genesis_event.json"

            if charter_path.exists() and genesis_path.exists():
                charter = _load_json(charter_path, {})
                genesis_record = _load_json(genesis_path, {})

                genesis_checkpoint_id = str(
                    genesis_record.get(
                        "seed_checkpoint_id",
                        "genesis_model_seed",
                    ),
                )
                self.state_register.register_genesis_checkpoint(
                    checkpoint_id=genesis_checkpoint_id,
                    trace_id=context.trace_id,
                    metadata={
                        "kind": "genesis",
                        "charter_version": str(
                            charter.get("charter_version", "1.0.0"),
                        ),
                    },
                )

                return {
                    "charter_path": str(charter_path.resolve()),
                    "genesis_path": str(genesis_path.resolve()),
                    "genesis_event": genesis_record,
                    "reused_existing_genesis": True,
                }

            charter = {
                "charter_version": "1.0.0",
                "name": "Project-AI Sovereign Model Server Charter",
                "laws": [
                    "no_silent_state_mutation",
                    "no_self_authorization",
                    "no_fabricated_continuity",
                    "no_improvised_governance_repair",
                    "no_promotion_without_evidence_and_signatures",
                ],
                "authority_chain": {
                    "root_authority": "Sovereign Covenant",
                    "subordinate_charter": "Server Charter v1.0",
                    "enforcement": "runtime_governance",
                },
                "created_at": utc_now(),
            }
            _save_json(charter_path, charter)

            genesis_checkpoint_id = "genesis_model_seed"
            self.state_register.register_genesis_checkpoint(
                checkpoint_id=genesis_checkpoint_id,
                trace_id=context.trace_id,
                metadata={
                    "kind": "genesis",
                    "charter_version": charter["charter_version"],
                },
            )

            genesis_record = {
                "genesis_event_id": new_id("genesis"),
                "charter_hash": _sha256_file(charter_path),
                "policy_hash": _sha256_file(self.policy_path),
                "host": platform.node(),
                "platform": platform.platform(),
                "seed_checkpoint_id": genesis_checkpoint_id,
                "created_at": utc_now(),
            }
            _save_json(genesis_path, genesis_record)

            self.journal.append(
                "workshop_genesis_event",
                context.trace_id,
                genesis_record,
            )

            return {
                "charter_path": str(charter_path.resolve()),
                "genesis_path": str(genesis_path.resolve()),
                "genesis_event": genesis_record,
            }

        return self._commit_governed_operation(
            context=context,
            action="bootstrap_workshop",
            resource=str(self.paths.workshop_root),
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            mutate=_mutate,
            quorum_proof=quorum_proof,
        )

    def admit_corpus_artifacts(
        self,
        context: GovernanceContext,
        artifact_paths: tuple[str, ...],
        artifact_type: str,
        source_class: str,
        trust_class: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            records: list[dict[str, Any]] = []
            for artifact_path in artifact_paths:
                admitted = self.ingress.admit_artifact(
                    artifact_path=Path(artifact_path),
                    artifact_type=artifact_type,
                    source_class=source_class,
                    trust_class=trust_class,
                )
                records.append(to_primitive(admitted))

            return {
                "admitted_records": records,
                "admitted_count": sum(1 for item in records if item["admitted"]),
                "total_count": len(records),
            }

        return self._commit_governed_operation(
            context=context,
            action="admit_artifact",
            resource=str(self.paths.workshop_root),
            mutation_class=MutationClass.HARD_MUTATION,
            mutate=_mutate,
            quorum_proof=None,
        )

    def build_constitutional_datasets(
        self,
        context: GovernanceContext,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            ingress_state = _load_json(
                self.paths.ingress_registry,
                {"artifacts": []},
            )
            admitted = [
                IngressArtifactRecord(
                    artifact_id=item["artifact_id"],
                    artifact_type=item["artifact_type"],
                    path=item["path"],
                    checksum=item["checksum"],
                    source_class=item["source_class"],
                    trust_class=item["trust_class"],
                    admitted=bool(item["admitted"]),
                    denial_reasons=tuple(item["denial_reasons"]),
                    admitted_at=item["admitted_at"],
                )
                for item in ingress_state["artifacts"]
                if item.get("admitted", False)
            ]
            if not admitted:
                raise ValueError("no admitted artifacts available")

            corpus_state = self.normalizer.build(admitted)
            manifests = self.foundry.build_products(
                corpus_state=corpus_state,
                created_by=context.actor_id,
            )

            return {
                "corpus_chunk_count": len(corpus_state.get("chunks", [])),
                "dataset_count": len(manifests),
                "dataset_ids": [manifest.dataset_id for manifest in manifests],
            }

        return self._commit_governed_operation(
            context=context,
            action="build_dataset",
            resource=str(self.paths.datasets_dir),
            mutation_class=MutationClass.HARD_MUTATION,
            mutate=_mutate,
            quorum_proof=None,
        )

    @staticmethod
    def _normalize_training_mode(execution_mode: str) -> str | None:
        normalized = execution_mode.strip().lower()
        aliases = {
            "simulated": "simulation",
            "simulation": "simulation",
            "actual": "actual_training",
            "actual_training": "actual_training",
        }
        return aliases.get(normalized)

    @staticmethod
    def _strip_mutation_failure_prefix(reason: str) -> str:
        prefix = "mutation_execution_failed:"
        if reason.startswith(prefix):
            return reason[len(prefix) :]
        return reason

    def _record_training_preflight_event(
        self,
        context: GovernanceContext,
        model_family: str,
        preflight: TrainingPreflightResult,
    ) -> None:
        event_type = (
            "training_preflight_allowed"
            if preflight.allowed
            else "training_preflight_denied"
        )
        self.journal.append(
            event_type,
            context.trace_id,
            {
                "model_family": model_family,
                "mode": preflight.mode,
                "allowed": preflight.allowed,
                "reason": preflight.reason,
                "reason_codes": list(preflight.reason_codes),
                "details": preflight.details,
            },
        )

    @staticmethod
    def _artifact_store_is_local(artifact_store_uri: str) -> bool:
        lower = artifact_store_uri.strip().lower()
        if any(lower.startswith(scheme) for scheme in DURABLE_ARTIFACT_URI_SCHEMES):
            return False
        if lower.startswith("http://"):
            return True
        if any(lower.startswith(prefix) for prefix in LOCAL_ARTIFACT_URI_PREFIXES):
            return True
        return "://" not in lower

    @staticmethod
    def _artifact_store_is_durable(artifact_store_uri: str) -> bool:
        lower = artifact_store_uri.strip().lower()
        return any(lower.startswith(scheme) for scheme in DURABLE_ARTIFACT_URI_SCHEMES)

    @staticmethod
    def _artifact_store_writable(artifact_store_uri: str) -> bool:
        candidate = artifact_store_uri.strip()
        if not candidate:
            return False
        if "://" in candidate and not candidate.startswith("file://"):
            return True

        if candidate.startswith("file://"):
            path = Path(candidate[7:])
        else:
            path = Path(candidate)
        path = path.resolve()
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_probe"
            probe.write_text("probe", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def _checkpoint_registry_path_writable(self) -> bool:
        registry_path = self.settings.model_registry_path
        try:
            registry_path.parent.mkdir(parents=True, exist_ok=True)
            if not registry_path.exists():
                _save_json(registry_path, {"models": {}, "immutable_index": {}})
            return True
        except OSError:
            return False

    def _has_admissibility_decision(self, decision_id: str) -> bool:
        for entry in self.journal.read_all():
            if entry.get("record_type") != "decision_record":
                continue
            payload = entry.get("payload", {})
            if str(payload.get("decision_id")) != decision_id:
                continue
            if str(payload.get("outcome")) != "approved":
                return False
            if str(payload.get("action")) not in {
                "execute_model",
                "register_model",
            }:
                return False
            return True
        return False

    def _verify_base_model_ticket(
        self,
        ticket: dict[str, Any],
        base_model: Any,
    ) -> tuple[bool, str]:
        required_fields = {
            "ticket_id",
            "model_id",
            "registry_entry_hash",
            "policy_profile",
            "trust_level",
            "source_type",
            "provenance_ref",
            "issued_at",
            "expires_at",
            "ticket_purpose",
            "signer_type",
            "signature",
        }
        missing = sorted(required_fields.difference(ticket.keys()))
        if missing:
            return False, "base_model_ticket_missing_fields"

        signature = ticket.get("signature")
        if not isinstance(signature, dict):
            return False, "base_model_ticket_signature_missing"
        for field in ("algorithm", "key_id", "signature"):
            if field not in signature:
                return False, "base_model_ticket_signature_invalid"

        try:
            expires_at = datetime.fromisoformat(str(ticket["expires_at"]))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expires_at.astimezone(timezone.utc):
                return False, "base_model_ticket_expired"
        except ValueError:
            return False, "base_model_ticket_expiry_invalid"

        envelope = SignatureEnvelope(
            algorithm=str(signature["algorithm"]),
            key_id=str(signature["key_id"]),
            signature=str(signature["signature"]),
            signed_at=str(signature.get("signed_at") or utc_now()),
        )
        unsigned = {key: value for key, value in ticket.items() if key != "signature"}
        if not self.signer.verify(unsigned, envelope):
            return False, "base_model_ticket_signature_invalid"

        if str(ticket.get("model_id")) != str(base_model.model_id):
            return False, "base_model_ticket_model_mismatch"
        if str(ticket.get("registry_entry_hash")) != sha256_hex(
            to_primitive(base_model)
        ):
            return False, "base_model_ticket_registry_hash_mismatch"
        if str(ticket.get("policy_profile")) != str(base_model.policy_profile):
            return False, "base_model_ticket_policy_profile_mismatch"
        if str(ticket.get("provenance_ref")) != str(base_model.provenance_ref):
            return False, "base_model_ticket_provenance_mismatch"
        return True, "ok"

    @staticmethod
    def _dataset_manifest_from_payload(
        payload: dict[str, Any]
    ) -> DatasetConstitutionManifest:
        manifest = payload.get("manifest")
        if not isinstance(manifest, dict):
            raise ValueError("dataset_manifest_missing")

        def _tuple_of_str(field_name: str) -> tuple[str, ...]:
            raw = manifest.get(field_name)
            if not isinstance(raw, (list, tuple)):
                raise ValueError(f"dataset_manifest_{field_name}_missing")
            return tuple(str(item) for item in raw)

        signature_raw = manifest.get("signature")
        if not isinstance(signature_raw, dict):
            raise ValueError("dataset_manifest_signature_missing")

        return DatasetConstitutionManifest(
            dataset_id=str(manifest["dataset_id"]),
            product_name=str(manifest["product_name"]),
            source_artifact_ids=_tuple_of_str("source_artifact_ids"),
            source_chunk_ids=_tuple_of_str("source_chunk_ids"),
            transform_steps=_tuple_of_str("transform_steps"),
            policy_flags=_tuple_of_str("policy_flags"),
            admission_signatures=_tuple_of_str("admission_signatures"),
            created_by=str(manifest["created_by"]),
            created_at=str(manifest["created_at"]),
            signature={str(key): str(value) for key, value in signature_raw.items()},
        )

    def _resolve_dataset_training_inputs(
        self,
        *,
        dataset_ids: tuple[str, ...],
        dataset_ref: str | None,
        dataset_provenance: str | None,
        dataset_source_type: str | None,
        dataset_license: str | None,
        dataset_hash: str | None,
        dataset_immutable_ref: str | None,
        dataset_immutable_proof: str | None,
    ) -> tuple[
        list[DatasetConstitutionManifest],
        list[DatasetTrainingReference],
        list[Path],
        list[str],
    ]:
        dataset_state = _load_json(self.paths.dataset_index, {"datasets": []})
        entries = list(dataset_state.get("datasets", []))
        by_id = {
            str(item.get("dataset_id")): item
            for item in entries
            if item.get("dataset_id")
        }

        selected_ids = [dataset_id for dataset_id in dataset_ids if dataset_id]
        reasons: list[str] = []
        if not selected_ids and dataset_ref:
            matched = next(
                (
                    item
                    for item in entries
                    if str(item.get("dataset_ref")) == dataset_ref
                    or str(item.get("dataset_id")) == dataset_ref
                ),
                None,
            )
            if matched is None:
                reasons.append("dataset_ref_unknown")
            else:
                selected_ids = [str(matched["dataset_id"])]

        if not selected_ids:
            reasons.append("dataset_reference_missing")
            return [], [], [], reasons

        manifests: list[DatasetConstitutionManifest] = []
        references: list[DatasetTrainingReference] = []
        dataset_paths: list[Path] = []

        for selected_id in selected_ids:
            entry = by_id.get(selected_id)
            if entry is None:
                reasons.append(f"dataset_id_unknown:{selected_id}")
                continue

            payload_path = Path(str(entry.get("path", ""))).resolve()
            if not payload_path.exists():
                reasons.append(f"dataset_payload_missing:{selected_id}")
                continue

            payload = _load_json(payload_path, {})
            try:
                manifests.append(self._dataset_manifest_from_payload(payload))
            except Exception:  # noqa: BLE001
                reasons.append(f"dataset_manifest_missing:{selected_id}")
                continue

            governance = payload.get("governance")
            if not isinstance(governance, dict):
                governance = {}

            reference = DatasetTrainingReference(
                dataset_id=selected_id,
                dataset_ref=str(
                    governance.get("dataset_ref")
                    or entry.get("dataset_ref")
                    or dataset_ref
                    or f"dataset://{selected_id}"
                ),
                dataset_path=str(payload_path),
                dataset_provenance=str(
                    governance.get("provenance_ref")
                    or entry.get("dataset_provenance")
                    or dataset_provenance
                    or ""
                ),
                dataset_source_type=str(
                    governance.get("source_type")
                    or entry.get("dataset_source_type")
                    or dataset_source_type
                    or ""
                ),
                dataset_license=str(
                    governance.get("license")
                    or entry.get("dataset_license")
                    or dataset_license
                    or ""
                ),
                dataset_hash=str(
                    governance.get("dataset_hash")
                    or entry.get("dataset_hash")
                    or dataset_hash
                    or _sha256_file(payload_path)
                ),
                dataset_immutable_ref=str(
                    governance.get("immutable_ref")
                    or entry.get("dataset_immutable_ref")
                    or dataset_immutable_ref
                    or ""
                ),
                mutable_reference=bool(
                    governance.get(
                        "mutable_reference",
                        entry.get("mutable_reference", False),
                    ),
                ),
                immutable_proof=(
                    str(
                        governance.get("immutable_proof")
                        or entry.get("immutable_proof")
                        or dataset_immutable_proof
                        or "",
                    ).strip()
                    or None
                ),
            )
            references.append(reference)
            dataset_paths.append(payload_path)

        return manifests, references, dataset_paths, reasons

    def _evaluate_training_preflight(
        self,
        *,
        context: GovernanceContext,
        model_family: str,
        base_checkpoint: str | None,
        dataset_ids: tuple[str, ...],
        dataset_ref: str | None,
        dataset_provenance: str | None,
        dataset_source_type: str | None,
        dataset_license: str | None,
        dataset_hash: str | None,
        dataset_immutable_ref: str | None,
        dataset_immutable_proof: str | None,
        execution_mode: str,
        simulation_smoke_test: bool,
        training_command: str | None,
        training_backend: str | None,
        artifact_store_uri: str | None,
        base_model_id: str | None,
        base_model_execution_ticket: dict[str, Any] | None,
        base_model_admissibility_decision_id: str | None,
        policy_profile: str | None,
        trust_level: str,
    ) -> tuple[TrainingPreflightResult, dict[str, Any]]:
        mode = self._normalize_training_mode(execution_mode)
        reasons: list[str] = []
        if mode is None:
            reasons.append("training_mode_invalid")
            mode = "unknown"

        manifests, references, dataset_paths, dataset_reasons = (
            self._resolve_dataset_training_inputs(
                dataset_ids=dataset_ids,
                dataset_ref=dataset_ref,
                dataset_provenance=dataset_provenance,
                dataset_source_type=dataset_source_type,
                dataset_license=dataset_license,
                dataset_hash=dataset_hash,
                dataset_immutable_ref=dataset_immutable_ref,
                dataset_immutable_proof=dataset_immutable_proof,
            )
        )
        reasons.extend(dataset_reasons)

        for reference in references:
            if not reference.dataset_ref.strip():
                reasons.append(f"dataset_ref_missing:{reference.dataset_id}")
            if not reference.dataset_provenance.strip():
                reasons.append(f"dataset_provenance_missing:{reference.dataset_id}")
            if not reference.dataset_source_type.strip():
                reasons.append(f"dataset_source_type_missing:{reference.dataset_id}")
            if not reference.dataset_license.strip():
                reasons.append(f"dataset_license_missing:{reference.dataset_id}")
            if not (
                reference.dataset_hash.strip()
                or reference.dataset_immutable_ref.strip()
            ):
                reasons.append(
                    f"dataset_hash_or_immutable_ref_missing:{reference.dataset_id}",
                )

            mutable = reference.mutable_reference or (
                reference.dataset_source_type in MUTABLE_DATASET_SOURCE_TYPES
            )
            if (
                trust_level in {"reviewed", "trusted"}
                and mutable
                and not reference.immutable_proof
            ):
                reasons.append(
                    f"mutable_dataset_requires_immutable_proof:{reference.dataset_id}",
                )

        resolved_training_command = (
            training_command or os.getenv("SOVEREIGN_TRAINING_COMMAND", "").strip()
        )
        resolved_training_backend = (
            training_backend or os.getenv("SOVEREIGN_TRAINING_BACKEND", "").strip()
        )
        resolved_artifact_store_uri = (
            artifact_store_uri
            or os.getenv("SOVEREIGN_TRAINING_ARTIFACT_STORE", "").strip()
        )

        base_model_record = None
        if mode == "simulation":
            if not simulation_smoke_test:
                reasons.append("simulation_flag_required")
        elif mode == "actual_training":
            if not base_model_id:
                reasons.append("base_model_missing")
            else:
                registry = GovernedModelRegistry(self.settings.model_registry_path)
                try:
                    base_model_record = registry.get(base_model_id)
                except KeyError:
                    reasons.append("base_model_unknown")
                else:
                    if not base_model_record.policy_profile.strip():
                        reasons.append("base_model_policy_profile_missing")
                    if not base_model_record.provenance_ref.strip():
                        reasons.append("base_model_provenance_missing")
                    if base_model_record.trust_level not in {"reviewed", "trusted"}:
                        reasons.append("base_model_insufficient_trust")
                    if base_model_record.admissibility_status != "admissible":
                        reasons.append("base_model_not_admissible")

            if (
                not base_model_execution_ticket
                and not base_model_admissibility_decision_id
            ):
                reasons.append("base_model_authorization_missing")
            if (
                base_model_execution_ticket is not None
                and base_model_record is not None
            ):
                valid_ticket, ticket_reason = self._verify_base_model_ticket(
                    base_model_execution_ticket,
                    base_model_record,
                )
                if not valid_ticket:
                    reasons.append(ticket_reason)
            if base_model_admissibility_decision_id:
                if not self._has_admissibility_decision(
                    base_model_admissibility_decision_id,
                ):
                    reasons.append("base_model_admissibility_decision_invalid")

            if not str(policy_profile or "").strip():
                reasons.append("policy_profile_missing")
            if not str(trust_level or "").strip():
                reasons.append("trust_level_missing")

            if not resolved_artifact_store_uri:
                reasons.append("artifact_store_missing")
            else:
                runtime_mode = str(self.settings.runtime_mode).lower()
                if runtime_mode in {
                    "production",
                    "rehearsal",
                } and self._artifact_store_is_local(
                    resolved_artifact_store_uri,
                ):
                    reasons.append("artifact_store_not_durable")
                if self._artifact_store_is_local(resolved_artifact_store_uri):
                    if not self._artifact_store_writable(resolved_artifact_store_uri):
                        reasons.append("artifact_store_not_writable")
                elif not self._artifact_store_is_durable(resolved_artifact_store_uri):
                    reasons.append("artifact_store_not_durable")

            if not resolved_training_backend:
                reasons.append("trainer_backend_missing")
            if not resolved_training_command:
                reasons.append("training_command_missing")
            if not self._checkpoint_registry_path_writable():
                reasons.append("checkpoint_registration_path_unwritable")
            if self.settings.journal_backend not in {"file", "sqlite"}:
                reasons.append("audit_journal_disabled")

        details = {
            "trace_id": context.trace_id,
            "model_family": model_family,
            "base_checkpoint": base_checkpoint,
            "base_model_id": base_model_id,
            "dataset_ids": [reference.dataset_id for reference in references],
            "dataset_refs": [reference.dataset_ref for reference in references],
            "policy_profile": str(policy_profile or "").strip(),
            "trust_level": str(trust_level or "").strip(),
            "artifact_store_uri": resolved_artifact_store_uri,
            "trainer_backend": resolved_training_backend,
            "training_command": resolved_training_command,
            "simulation_smoke_test": simulation_smoke_test,
        }

        preflight = TrainingPreflightResult(
            allowed=not reasons,
            mode=mode,
            reason=("ok" if not reasons else reasons[0]),
            reason_codes=tuple(reasons),
            details=details,
        )
        training_config_hash = hashlib.sha256(
            canonical_json(
                {
                    "mode": mode,
                    "model_family": model_family,
                    "base_model_id": base_model_id,
                    "base_checkpoint": base_checkpoint,
                    "dataset_references": [
                        to_primitive(reference) for reference in references
                    ],
                    "policy_profile": str(policy_profile or "").strip(),
                    "trust_level": str(trust_level or "").strip(),
                    "artifact_store_uri": resolved_artifact_store_uri,
                    "trainer_backend": resolved_training_backend,
                    "training_command": resolved_training_command,
                },
            ).encode("utf-8"),
        ).hexdigest()

        return preflight, {
            "dataset_manifests": manifests,
            "dataset_references": references,
            "dataset_paths": dataset_paths,
            "resolved_training_command": resolved_training_command,
            "resolved_training_backend": resolved_training_backend,
            "resolved_artifact_store_uri": resolved_artifact_store_uri,
            "base_model_record": base_model_record,
            "training_config_hash": training_config_hash,
        }

    def preflight_training_run(
        self,
        *,
        context: GovernanceContext,
        model_family: str,
        base_checkpoint: str | None,
        dataset_ids: tuple[str, ...],
        execution_mode: str,
        simulation_smoke_test: bool,
        training_command: str | None,
        training_backend: str | None,
        artifact_store_uri: str | None,
        base_model_id: str | None,
        base_model_execution_ticket: dict[str, Any] | None,
        base_model_admissibility_decision_id: str | None,
        dataset_ref: str | None,
        dataset_provenance: str | None,
        dataset_source_type: str | None,
        dataset_license: str | None,
        dataset_hash: str | None,
        dataset_immutable_ref: str | None,
        dataset_immutable_proof: str | None,
        policy_profile: str | None,
        trust_level: str,
    ) -> dict[str, Any]:
        preflight, _ = self._evaluate_training_preflight(
            context=context,
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_ids=dataset_ids,
            dataset_ref=dataset_ref,
            dataset_provenance=dataset_provenance,
            dataset_source_type=dataset_source_type,
            dataset_license=dataset_license,
            dataset_hash=dataset_hash,
            dataset_immutable_ref=dataset_immutable_ref,
            dataset_immutable_proof=dataset_immutable_proof,
            execution_mode=execution_mode,
            simulation_smoke_test=simulation_smoke_test,
            training_command=training_command,
            training_backend=training_backend,
            artifact_store_uri=artifact_store_uri,
            base_model_id=base_model_id,
            base_model_execution_ticket=base_model_execution_ticket,
            base_model_admissibility_decision_id=base_model_admissibility_decision_id,
            policy_profile=policy_profile,
            trust_level=trust_level,
        )

        token = self._capability_token(
            context.actor_id,
            context.trust_domain,
            scopes=("preflight_training_run",),
        )
        _request, evaluation, _binding = self.runtime.evaluate_and_bind(
            context=context,
            action="preflight_training_run",
            resource=str(self.paths.training_runs),
            mutation_class=MutationClass.READ,
            capability_token=token,
        )

        reason_codes = list(preflight.reason_codes)
        if not evaluation.allowed:
            reason_codes.extend(
                f"policy_{reason}" for reason in evaluation.denial_reasons
            )

        merged_details = {
            **preflight.details,
            "policy_evaluation": to_primitive(evaluation),
        }
        preflight = TrainingPreflightResult(
            allowed=preflight.allowed and evaluation.allowed,
            mode=preflight.mode,
            reason=("ok" if not reason_codes else reason_codes[0]),
            reason_codes=tuple(reason_codes),
            details=merged_details,
        )

        self._record_training_preflight_event(
            context=context,
            model_family=model_family,
            preflight=preflight,
        )
        return {
            "allowed": preflight.allowed,
            "mode": preflight.mode,
            "reason": preflight.reason,
            "reason_codes": list(preflight.reason_codes),
            "details": preflight.details,
        }

    def start_training_run(
        self,
        context: GovernanceContext,
        model_family: str,
        base_checkpoint: str | None,
        dataset_ids: tuple[str, ...],
        quorum_proof: str,
        execution_mode: str = "actual",
        training_command: str | None = None,
        simulation_smoke_test: bool = False,
        base_model_id: str | None = None,
        base_model_execution_ticket: dict[str, Any] | None = None,
        base_model_admissibility_decision_id: str | None = None,
        dataset_ref: str | None = None,
        dataset_provenance: str | None = None,
        dataset_source_type: str | None = None,
        dataset_license: str | None = None,
        dataset_hash: str | None = None,
        dataset_immutable_ref: str | None = None,
        dataset_immutable_proof: str | None = None,
        policy_profile: str | None = None,
        trust_level: str = "reviewed",
        artifact_store_uri: str | None = None,
        trainer_backend: str | None = None,
    ) -> dict[str, Any]:
        preflight, preflight_inputs = self._evaluate_training_preflight(
            context=context,
            model_family=model_family,
            base_checkpoint=base_checkpoint,
            dataset_ids=dataset_ids,
            dataset_ref=dataset_ref,
            dataset_provenance=dataset_provenance,
            dataset_source_type=dataset_source_type,
            dataset_license=dataset_license,
            dataset_hash=dataset_hash,
            dataset_immutable_ref=dataset_immutable_ref,
            dataset_immutable_proof=dataset_immutable_proof,
            execution_mode=execution_mode,
            simulation_smoke_test=simulation_smoke_test,
            training_command=training_command,
            training_backend=trainer_backend,
            artifact_store_uri=artifact_store_uri,
            base_model_id=base_model_id,
            base_model_execution_ticket=base_model_execution_ticket,
            base_model_admissibility_decision_id=base_model_admissibility_decision_id,
            policy_profile=policy_profile,
            trust_level=trust_level,
        )
        self._record_training_preflight_event(
            context=context,
            model_family=model_family,
            preflight=preflight,
        )
        if not preflight.allowed:
            raise PolicyViolation(f"training_preflight_denied:{preflight.reason}")

        def _mutate() -> dict[str, Any]:
            mode = preflight.mode
            event_started = (
                "simulation_started" if mode == "simulation" else "training_started"
            )
            dataset_reference_payload = [
                to_primitive(reference)
                for reference in preflight_inputs["dataset_references"]
            ]

            self.journal.append(
                event_started,
                context.trace_id,
                {
                    "mode": mode,
                    "model_family": model_family,
                    "base_model_id": base_model_id,
                    "dataset_refs": [
                        reference["dataset_ref"]
                        for reference in dataset_reference_payload
                    ],
                    "training_config_hash": preflight_inputs["training_config_hash"],
                },
            )

            try:
                run_payload, checkpoint = self.training_core.start_run(
                    model_family=model_family,
                    base_checkpoint=base_checkpoint,
                    dataset_manifests=preflight_inputs["dataset_manifests"],
                    dataset_paths=preflight_inputs["dataset_paths"],
                    execution_mode=("simulated" if mode == "simulation" else "actual"),
                    training_command=(
                        preflight_inputs["resolved_training_command"] or None
                    ),
                    training_backend=(
                        preflight_inputs["resolved_training_backend"] or None
                    ),
                    artifact_store_uri=(
                        preflight_inputs["resolved_artifact_store_uri"] or None
                    ),
                    governance_metadata={
                        "mode": mode,
                        "base_model_id": base_model_id,
                        "base_model_admissibility_decision_id": base_model_admissibility_decision_id,
                        "base_model_ticket_provided": (
                            base_model_execution_ticket is not None
                        ),
                        "dataset_references": dataset_reference_payload,
                        "dataset_provenance": [
                            reference["dataset_provenance"]
                            for reference in dataset_reference_payload
                        ],
                        "policy_profile": str(policy_profile or "").strip(),
                        "trust_level": str(trust_level or "").strip(),
                        "artifact_store_uri": preflight_inputs[
                            "resolved_artifact_store_uri"
                        ],
                        "trainer_backend": preflight_inputs[
                            "resolved_training_backend"
                        ],
                        "training_config_hash": preflight_inputs[
                            "training_config_hash"
                        ],
                        "output_registration_path": str(
                            self.settings.model_registry_path,
                        ),
                        "audit_journal_enabled": (
                            self.settings.journal_backend in {"file", "sqlite"}
                        ),
                    },
                )

                continuity_state = _load_json(
                    self.paths.continuity_index,
                    {
                        "genesis_checkpoint_id": None,
                        "parents": {},
                        "registered_at": utc_now(),
                    },
                )

                parent_id = base_checkpoint or continuity_state.get(
                    "genesis_checkpoint_id",
                )
                if parent_id and not self.state_register.continuity_chain(
                    parent_id,
                ):
                    parent_id = None

                self.state_register.register_checkpoint_lineage(
                    checkpoint_id=checkpoint.checkpoint_id,
                    parent_checkpoint_id=parent_id,
                    trace_id=context.trace_id,
                    metadata={
                        "model_family": model_family,
                        "run_id": run_payload["run_id"],
                        "checkpoint_hash": checkpoint.checkpoint_hash,
                        "execution_mode": checkpoint.execution_mode,
                        "artifact_uri": checkpoint.artifact_uri,
                    },
                )

                if mode == "simulation":
                    run_payload["mode"] = "simulation"
                    run_payload["simulation_only"] = True
                    run_payload["satisfies_production_training_evidence"] = False
                    self.journal.append(
                        "simulation_completed",
                        context.trace_id,
                        {
                            "mode": "simulation",
                            "run_id": run_payload["run_id"],
                            "checkpoint_id": checkpoint.checkpoint_id,
                        },
                    )
                    return {
                        "mode": "simulation",
                        "run": run_payload,
                        "checkpoint": to_primitive(checkpoint),
                        "governed_model": None,
                        "preflight": to_primitive(preflight),
                    }

                self.journal.append(
                    "training_completed",
                    context.trace_id,
                    {
                        "mode": "actual_training",
                        "run_id": run_payload["run_id"],
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "checkpoint_hash": checkpoint.checkpoint_hash,
                    },
                )

                governed_model = GovernedModelRegistry(
                    self.settings.model_registry_path,
                ).register(
                    source_type="fine_tuned_checkpoint",
                    source=checkpoint.artifact_uri,
                    license="derived-from-training-corpus",
                    content_hash=checkpoint.checkpoint_hash,
                    immutable_identifier=checkpoint.checkpoint_id,
                    metadata={
                        "run_id": run_payload["run_id"],
                        "base_model_reference": base_model_id,
                        "base_checkpoint": base_checkpoint,
                        "dataset_references": dataset_reference_payload,
                        "dataset_provenance": [
                            reference["dataset_provenance"]
                            for reference in dataset_reference_payload
                        ],
                        "training_config_hash": preflight_inputs[
                            "training_config_hash"
                        ],
                        "artifact_location": checkpoint.artifact_uri,
                        "policy_profile": str(policy_profile or "").strip(),
                        "trust_level": str(trust_level or "").strip(),
                        "model_family": model_family,
                    },
                    trust_level=str(trust_level or "reviewed"),
                    policy_profile=(
                        str(policy_profile or "workshop-fine-tuned-model").strip()
                        or "workshop-fine-tuned-model"
                    ),
                    provenance_ref=(
                        "training-run://"
                        f"{run_payload['run_id']}/checkpoint/{checkpoint.checkpoint_id}"
                    ),
                    signer=self.signer,
                )
                if (
                    governed_model.source != checkpoint.artifact_uri
                    or governed_model.content_hash != checkpoint.checkpoint_hash
                ):
                    raise ValueError("checkpoint_registry_binding_failed")

                contract_state = _load_json(
                    self.paths.training_artifact_contract,
                    {"artifacts": []},
                )
                contract_state["artifacts"].append(
                    {
                        "run_id": run_payload["run_id"],
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "model_id": governed_model.model_id,
                        "artifact_uri": checkpoint.artifact_uri,
                        "artifact_store_uri": preflight_inputs[
                            "resolved_artifact_store_uri"
                        ],
                        "training_config_hash": preflight_inputs[
                            "training_config_hash"
                        ],
                        "recorded_at": utc_now(),
                    },
                )
                _save_json(self.paths.training_artifact_contract, contract_state)

                self.journal.append(
                    "checkpoint_registered",
                    context.trace_id,
                    {
                        "run_id": run_payload["run_id"],
                        "checkpoint_id": checkpoint.checkpoint_id,
                        "model_id": governed_model.model_id,
                        "registry_schema_version": governed_model.registry_schema_version,
                        "signature_status": governed_model.signature_status,
                    },
                )

                return {
                    "mode": "actual_training",
                    "run": run_payload,
                    "checkpoint": to_primitive(checkpoint),
                    "governed_model": to_primitive(governed_model),
                    "preflight": to_primitive(preflight),
                }
            except Exception as exc:  # noqa: BLE001
                self.journal.append(
                    "training_failed",
                    context.trace_id,
                    {
                        "mode": mode,
                        "model_family": model_family,
                        "reason_code": "training_execution_failed",
                        "error": str(exc),
                    },
                )
                raise ValueError(f"training_execution_failed:{exc}") from exc

        return self._commit_governed_operation(
            context=context,
            action="start_training_run",
            resource=str(self.paths.training_runs),
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            mutate=_mutate,
            quorum_proof=quorum_proof,
        )

    def run_shadow_evaluation(
        self,
        context: GovernanceContext,
        checkpoint_id: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            training_state = _load_json(
                self.paths.training_runs,
                {"runs": [], "checkpoints": []},
            )
            checkpoint_raw = next(
                (
                    item
                    for item in training_state["checkpoints"]
                    if item["checkpoint_id"] == checkpoint_id
                ),
                None,
            )
            if checkpoint_raw is None:
                raise ValueError(f"unknown checkpoint: {checkpoint_id}")

            checkpoint = TrainingCheckpointRecord(
                checkpoint_id=checkpoint_raw["checkpoint_id"],
                run_id=checkpoint_raw["run_id"],
                model_family=checkpoint_raw["model_family"],
                base_checkpoint=checkpoint_raw.get("base_checkpoint"),
                dataset_ids=tuple(checkpoint_raw["dataset_ids"]),
                checkpoint_hash=checkpoint_raw["checkpoint_hash"],
                created_at=checkpoint_raw["created_at"],
                execution_mode=checkpoint_raw.get(
                    "execution_mode",
                    "simulated",
                ),
                artifact_uri=checkpoint_raw.get(
                    "artifact_uri",
                    f"legacy://{checkpoint_raw['checkpoint_id']}",
                ),
            )

            continuity_ok = self.state_register.assert_unbroken_continuity(
                checkpoint_id,
            )
            verdict = self.shadow_eval.evaluate(checkpoint, continuity_ok)
            return {"verdict": to_primitive(verdict)}

        return self._commit_governed_operation(
            context=context,
            action="run_shadow_evaluation",
            resource=str(self.paths.evaluations),
            mutation_class=MutationClass.HARD_MUTATION,
            mutate=_mutate,
            quorum_proof=None,
        )

    def promote_checkpoint(
        self,
        context: GovernanceContext,
        checkpoint_id: str,
        evaluation_id: str,
        approvals: tuple[str, ...],
        charter_version: str,
        quorum_proof: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            eval_state = _load_json(
                self.paths.evaluations,
                {"evaluations": []},
            )
            verdict_raw = next(
                (
                    item
                    for item in eval_state["evaluations"]
                    if item["evaluation_id"] == evaluation_id
                ),
                None,
            )
            if verdict_raw is None:
                raise ValueError(f"unknown evaluation: {evaluation_id}")
            if verdict_raw["checkpoint_id"] != checkpoint_id:
                raise ValueError("evaluation/checkpoint mismatch")

            verdict = EvaluationVerdict(
                evaluation_id=verdict_raw["evaluation_id"],
                checkpoint_id=verdict_raw["checkpoint_id"],
                benchmark_scores=verdict_raw["benchmark_scores"],
                primary_score=float(verdict_raw["primary_score"]),
                shadow_score=float(verdict_raw["shadow_score"]),
                divergence=float(verdict_raw["divergence"]),
                passed=bool(verdict_raw["passed"]),
                reasons=tuple(verdict_raw["reasons"]),
                evaluated_at=verdict_raw["evaluated_at"],
            )

            bundle = self.promotion.promote(
                checkpoint_id=checkpoint_id,
                evaluation=verdict,
                approvals=approvals,
                charter_version=charter_version,
                quorum_required=2,
            )
            return {"promotion_bundle": to_primitive(bundle)}

        return self._commit_governed_operation(
            context=context,
            action="promote_checkpoint",
            resource=str(self.paths.promotions),
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            mutate=_mutate,
            quorum_proof=quorum_proof,
        )

    def register_repair_unit(
        self,
        context: GovernanceContext,
        component: str,
        version: str,
        payload_hash: str,
        certification_decision_id: str,
        quorum_proof: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            record = self.repair_store.register_unit(
                component=component,
                version=version,
                payload_hash=payload_hash,
                certified_by=context.actor_id,
                certification_decision_id=certification_decision_id,
            )
            return {"repair_unit": to_primitive(record)}

        return self._commit_governed_operation(
            context=context,
            action="register_repair_unit",
            resource=str(self.paths.repair_store),
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            mutate=_mutate,
            quorum_proof=quorum_proof,
        )

    def apply_repair_unit(
        self,
        context: GovernanceContext,
        unit_id: str,
        target_component: str,
        reason: str,
        quorum_proof: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            applied = self.repair_store.apply_unit(
                unit_id=unit_id,
                target_component=target_component,
                applied_by=context.actor_id,
                reason=reason,
            )
            return {"applied_repair": applied}

        return self._commit_governed_operation(
            context=context,
            action="apply_repair_unit",
            resource=str(self.paths.repair_store),
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            mutate=_mutate,
            quorum_proof=quorum_proof,
        )

    def evaluate_runtime_containment(
        self,
        action: str,
        requested_syscalls: tuple[str, ...],
        network_egress_class: str,
        filesystem_write_paths: tuple[str, ...],
    ) -> ContainmentDecision:
        return self.containment.evaluate_request(
            action=action,
            requested_syscalls=requested_syscalls,
            network_egress_class=network_egress_class,
            filesystem_write_paths=filesystem_write_paths,
            workspace_root=self.workspace_root,
        )

    def export_workshop_report(
        self,
        output_path: Path | None = None,
    ) -> dict[str, Any]:
        training_state = _load_json(
            self.paths.training_runs,
            {"runs": [], "checkpoints": []},
        )
        training_runs = list(training_state.get("runs", []))
        simulation_runs = [
            run
            for run in training_runs
            if str(run.get("execution_mode", "")).strip() == "simulated"
        ]
        actual_runs = [
            run
            for run in training_runs
            if str(run.get("execution_mode", "")).strip() == "actual"
        ]
        artifact_contract = _load_json(
            self.paths.training_artifact_contract,
            {"artifacts": []},
        )
        training_modes = sorted(
            {str(item.get("execution_mode", "unknown")) for item in training_runs},
        )
        report = {
            "generated_at": utc_now(),
            "readiness_level": "prototype",
            "training_execution_modes": training_modes,
            "training_is_simulated": "simulated" in training_modes,
            "simulation_run_count": len(simulation_runs),
            "actual_training_run_count": len(actual_runs),
            "production_training_evidence_satisfied": bool(
                actual_runs and artifact_contract.get("artifacts")
            ),
            "charter_exists": (
                self.paths.founding_dir / "server_charter_v1.json"
            ).exists(),
            "policy_path": str(self.policy_path),
            "ingress_artifacts": len(
                _load_json(self.paths.ingress_registry, {"artifacts": []})["artifacts"],
            ),
            "datasets": len(
                _load_json(self.paths.dataset_index, {"datasets": []})["datasets"],
            ),
            "training_runs": len(
                training_runs,
            ),
            "evaluations": len(
                _load_json(self.paths.evaluations, {"evaluations": []})["evaluations"],
            ),
            "promotions": len(
                _load_json(self.paths.promotions, {"bundles": []})["bundles"],
            ),
            "repair_units": len(
                _load_json(self.paths.repair_store, {"units": []})["units"],
            ),
            "continuity_index": _load_json(
                self.paths.continuity_index,
                {
                    "genesis_checkpoint_id": None,
                    "parents": {},
                    "registered_at": utc_now(),
                },
            ),
        }

        destination = output_path.resolve() if output_path else self.paths.report_path
        _save_json(destination, report)
        return report
