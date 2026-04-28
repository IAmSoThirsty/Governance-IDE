from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
from statistics import mean
from typing import Any, Callable

from .config import Settings, get_settings
from .governance import (
    GovernanceRuntime,
    HashChainJournal,
    HMACDecisionSigner,
    PolicyEngine,
    PolicyViolation,
)
from .models import (
    CapabilityToken,
    GovernanceContext,
    MutationClass,
    canonical_json,
    new_id,
    to_primitive,
    utc_now,
)
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
class TrainingCheckpointRecord:
    checkpoint_id: str
    run_id: str
    model_family: str
    base_checkpoint: str | None
    dataset_ids: tuple[str, ...]
    checkpoint_hash: str
    created_at: str


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
        signer: HMACDecisionSigner,
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

        product_specs = {
            "constitutional_pretraining_text_packs":
                lambda chunk: True,
            "doctrine_grounded_instruction_pairs":
                lambda chunk: "general" not in chunk["doctrine_tags"],
            "continuity_challenge_set":
                lambda chunk: "continuity" in chunk["doctrine_tags"],
            "identity_persistence_challenge_set":
                lambda chunk: "identity" in chunk["doctrine_tags"],
            "truth_vs_comfort_preference_set":
                lambda chunk: "directness" in chunk["doctrine_tags"],
            "adversarial_containment_challenge_set":
                lambda chunk: (
                    "adversarial" in chunk["doctrine_tags"]
                    or "containment" in chunk["doctrine_tags"]
                ),
            "constitutional_refusal_set":
                lambda chunk: (
                    "quorum" in chunk["doctrine_tags"]
                    or "repair" in chunk["doctrine_tags"]
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

            unsigned_manifest = {
                "dataset_id": dataset_id,
                "product_name": product_name,
                "source_artifact_ids": tuple(
                    sorted(
                        {
                            item["artifact_id"]
                            for item in selected
                        },
                    ),
                ),
                "source_chunk_ids": tuple(
                    item["chunk_id"] for item in selected
                ),
                "transform_steps": (
                    "canonical_segmentation",
                    "doctrine_tagging",
                    "constitutional_product_projection",
                ),
                "policy_flags": (
                    "no_cross_tenant_mix",
                    "default_deny_mutations",
                    "signed_manifest_required",
                ),
                "admission_signatures": tuple(
                    hashlib.sha256(
                        f"{item['artifact_id']}:{item['chunk_id']}".encode(
                            "utf-8",
                        ),
                    ).hexdigest()
                    for item in selected
                ),
                "created_by": created_by,
                "created_at": utc_now(),
            }
            signature = self.signer.sign(unsigned_manifest)

            manifest = DatasetConstitutionManifest(
                dataset_id=dataset_id,
                product_name=product_name,
                source_artifact_ids=unsigned_manifest[
                    "source_artifact_ids"
                ],
                source_chunk_ids=unsigned_manifest["source_chunk_ids"],
                transform_steps=unsigned_manifest["transform_steps"],
                policy_flags=unsigned_manifest["policy_flags"],
                admission_signatures=unsigned_manifest[
                    "admission_signatures"
                ],
                created_by=created_by,
                created_at=unsigned_manifest["created_at"],
                signature=to_primitive(signature),
            )
            manifests.append(manifest)

            dataset_payload = {
                "manifest": to_primitive(manifest),
                "records": records,
            }
            _save_json(self.datasets_dir / f"{dataset_id}.json", dataset_payload)
            index_state["datasets"].append(
                {
                    "dataset_id": dataset_id,
                    "product_name": product_name,
                    "path": str(
                        (self.datasets_dir / f"{dataset_id}.json").resolve(),
                    ),
                    "created_at": manifest.created_at,
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
    def __init__(self, training_runs_path: Path) -> None:
        self.training_runs_path = training_runs_path

    def start_run(
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
            "status": "completed",
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
        )

        state["runs"].append(run_payload)
        state["checkpoints"].append(to_primitive(checkpoint))
        _save_json(self.training_runs_path, state)
        return run_payload, checkpoint


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
            syscall
            for syscall in requested_syscalls
            if syscall not in allowed_syscalls
        )
        if unknown_syscalls:
            reasons.append(
                "unauthorized_syscalls:"
                + ",".join(unknown_syscalls),
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

        if (
            parent_checkpoint_id
            and parent_checkpoint_id not in state["parents"]
        ):
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
            (
                item
                for item in state["units"]
                if item["unit_id"] == unit_id
            ),
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
        signer: HMACDecisionSigner,
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

        unique_approvals = tuple(sorted(set(approvals)))
        quorum_met = len(unique_approvals) >= quorum_required
        if not quorum_met:
            raise ValueError("promotion quorum not met")

        unsigned_bundle = {
            "promotion_id": new_id("promotion"),
            "checkpoint_id": checkpoint_id,
            "evaluation_id": evaluation.evaluation_id,
            "charter_version": charter_version,
            "approvals": unique_approvals,
            "quorum_met": quorum_met,
            "evidence_refs": (
                checkpoint_id,
                evaluation.evaluation_id,
            ),
            "signed_at": utc_now(),
        }
        signature = self.signer.sign(unsigned_bundle)

        bundle = PromotionBundle(
            promotion_id=unsigned_bundle["promotion_id"],
            checkpoint_id=checkpoint_id,
            evaluation_id=evaluation.evaluation_id,
            charter_version=charter_version,
            approvals=unique_approvals,
            quorum_met=quorum_met,
            evidence_refs=unsigned_bundle["evidence_refs"],
            signed_at=unsigned_bundle["signed_at"],
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
            "start_training_run": {
                "required_mutation_class": "governanceMutation",
                "allowed_roles": [
                    "model_steward",
                    "release_authority",
                ],
                "quorum_required": True,
                "risk_score": 90,
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

        self.paths = self._build_paths(self.workspace_root, self.settings.state_dir)
        self._ensure_layout()

        self.policy_path = (
            policy_path.resolve()
            if policy_path
            else (self.workspace_root / "policies/workshop_policy.json").resolve()
        )
        self._ensure_policy_file()

        self.signer = HMACDecisionSigner(self.settings.signing_key)
        self.journal = HashChainJournal(self.paths.state_dir / "workshop_journal.jsonl")
        self.runtime = GovernanceRuntime(
            policy_engine=PolicyEngine.from_path(self.policy_path),
            journal=self.journal,
            signer=self.signer,
        )
        self.provenance = ProvenanceGraph(self.paths.state_dir / "workshop_provenance.json")

        self.ingress = ConstitutionalIngressGateway(self.paths.ingress_registry)
        self.normalizer = CorpusNormalizationDictionaryBuilder(self.paths.corpus_state)
        self.foundry = ConstitutionalDatasetFoundry(
            self.paths.dataset_index,
            self.paths.datasets_dir,
            self.signer,
        )
        self.training_core = TrainingOrchestrationCore(self.paths.training_runs)
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
            report_path=workspace_root / "integration" / "out" / "workshop_report.json",
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
            expires_at=(
                datetime.now(timezone.utc) + timedelta(minutes=30)
            ).isoformat(),
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
            charter_path = self.paths.founding_dir / "server_charter_v1.json"
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
            genesis_path = self.paths.genesis_dir / "genesis_event.json"
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
                "admitted_count": sum(
                    1 for item in records if item["admitted"]
                ),
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

    def start_training_run(
        self,
        context: GovernanceContext,
        model_family: str,
        base_checkpoint: str | None,
        dataset_ids: tuple[str, ...],
        quorum_proof: str,
    ) -> dict[str, Any]:
        def _mutate() -> dict[str, Any]:
            dataset_state = _load_json(self.paths.dataset_index, {"datasets": []})
            dataset_paths = {
                item["dataset_id"]: Path(item["path"])
                for item in dataset_state.get("datasets", [])
            }
            missing = [
                dataset_id
                for dataset_id in dataset_ids
                if dataset_id not in dataset_paths
            ]
            if missing:
                raise ValueError(f"unknown dataset ids: {','.join(missing)}")

            manifests: list[DatasetConstitutionManifest] = []
            for dataset_id in dataset_ids:
                payload = _load_json(dataset_paths[dataset_id], {})
                manifest = payload.get("manifest")
                if not manifest:
                    raise ValueError(f"manifest missing for dataset: {dataset_id}")
                manifests.append(
                    DatasetConstitutionManifest(
                        dataset_id=manifest["dataset_id"],
                        product_name=manifest["product_name"],
                        source_artifact_ids=tuple(manifest["source_artifact_ids"]),
                        source_chunk_ids=tuple(manifest["source_chunk_ids"]),
                        transform_steps=tuple(manifest["transform_steps"]),
                        policy_flags=tuple(manifest["policy_flags"]),
                        admission_signatures=tuple(
                            manifest["admission_signatures"],
                        ),
                        created_by=manifest["created_by"],
                        created_at=manifest["created_at"],
                        signature=manifest["signature"],
                    ),
                )

            run_payload, checkpoint = self.training_core.start_run(
                model_family=model_family,
                base_checkpoint=base_checkpoint,
                dataset_manifests=manifests,
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
                },
            )

            return {
                "run": run_payload,
                "checkpoint": to_primitive(checkpoint),
            }

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
            eval_state = _load_json(self.paths.evaluations, {"evaluations": []})
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

    def export_workshop_report(self, output_path: Path | None = None) -> dict[str, Any]:
        report = {
            "generated_at": utc_now(),
            "charter_exists": (self.paths.founding_dir / "server_charter_v1.json").exists(),
            "policy_path": str(self.policy_path),
            "ingress_artifacts": len(
                _load_json(self.paths.ingress_registry, {"artifacts": []})[
                    "artifacts"
                ],
            ),
            "datasets": len(
                _load_json(self.paths.dataset_index, {"datasets": []})[
                    "datasets"
                ],
            ),
            "training_runs": len(
                _load_json(self.paths.training_runs, {"runs": []})["runs"],
            ),
            "evaluations": len(
                _load_json(self.paths.evaluations, {"evaluations": []})[
                    "evaluations"
                ],
            ),
            "promotions": len(
                _load_json(self.paths.promotions, {"bundles": []})[
                    "bundles"
                ],
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
