from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
import json
from typing import Any

from .models import new_id, to_primitive, utc_now


class ArtifactType(str, Enum):
    EXTENSION = "extension"
    MODEL = "model"
    PROMPT_PACK = "promptPack"
    RETRIEVAL_INDEX = "retrievalIndex"
    POLICY_BUNDLE = "policyBundle"


class PromotionTier(str, Enum):
    COMMUNITY = "community"
    ENTERPRISE_REVIEWED = "enterprise-reviewed"
    SOVEREIGN_APPROVED = "sovereign-approved"
    ENCLAVE_ALLOWED = "enclave-allowed"


TIER_ORDER = {
    PromotionTier.COMMUNITY.value: 0,
    PromotionTier.ENTERPRISE_REVIEWED.value: 1,
    PromotionTier.SOVEREIGN_APPROVED.value: 2,
    PromotionTier.ENCLAVE_ALLOWED.value: 3,
}


@dataclass(frozen=True)
class PromotionEvent:
    promotion_id: str
    from_tier: str
    to_tier: str
    decision_record_id: str
    promoted_at: str
    reason: str


@dataclass(frozen=True)
class ArtifactEvidenceRecord:
    evidence_id: str
    artifact_id: str
    evidence_type: str
    passed: bool
    evidence_ref: str
    recorded_at: str
    details: dict[str, Any]


@dataclass(frozen=True)
class ArtifactLifecycleRecord:
    artifact_id: str
    artifact_type: ArtifactType
    publisher: str
    checksum: str
    signature_verified: bool
    static_scan_passed: bool
    dependency_scan_passed: bool
    provenance_verified: bool
    airgap_manifest_approved: bool
    current_tier: str
    revoked: bool
    incident_refs: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    promotion_history: tuple[PromotionEvent, ...]


class SupplyChainRegistry:
    """Tiered promotion memory for extensions/models/policy artifacts."""

    def __init__(self, state_path: str | Path) -> None:
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(
                json.dumps({"artifacts": {}, "evidence": {}}, indent=2),
            )
        self._state = json.loads(self.path.read_text(encoding="utf-8"))
        self._state.setdefault("artifacts", {})
        self._state.setdefault("evidence", {})

    def register_candidate(
        self,
        artifact_id: str,
        artifact_type: ArtifactType,
        publisher: str,
        checksum: str,
        signature_verified: bool,
        static_scan_passed: bool,
        dependency_scan_passed: bool,
        provenance_verified: bool,
        airgap_manifest_approved: bool,
    ) -> ArtifactLifecycleRecord:
        if artifact_id in self._state["artifacts"]:
            raise ValueError("artifact already registered")

        record = ArtifactLifecycleRecord(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            publisher=publisher,
            checksum=checksum,
            signature_verified=signature_verified,
            static_scan_passed=static_scan_passed,
            dependency_scan_passed=dependency_scan_passed,
            provenance_verified=provenance_verified,
            airgap_manifest_approved=airgap_manifest_approved,
            current_tier=PromotionTier.COMMUNITY.value,
            revoked=False,
            incident_refs=tuple(),
            evidence_ids=tuple(),
            promotion_history=tuple(),
        )
        self._state["artifacts"][artifact_id] = to_primitive(record)
        self._save()
        return record

    def register_evidence(
        self,
        artifact_id: str,
        evidence_type: str,
        passed: bool,
        evidence_ref: str,
        details: dict[str, Any] | None = None,
    ) -> ArtifactEvidenceRecord:
        record = self.get_record(artifact_id)
        if not evidence_type:
            raise ValueError("evidence_type is required")
        if not evidence_ref:
            raise ValueError("evidence_ref is required")

        evidence = ArtifactEvidenceRecord(
            evidence_id=new_id("evidence"),
            artifact_id=artifact_id,
            evidence_type=evidence_type,
            passed=passed,
            evidence_ref=evidence_ref,
            recorded_at=utc_now(),
            details=details or {},
        )
        self._state["evidence"][evidence.evidence_id] = to_primitive(
            evidence,
        )
        updated = replace(
            record,
            evidence_ids=record.evidence_ids + (evidence.evidence_id,),
        )
        self._state["artifacts"][artifact_id] = to_primitive(updated)
        self._save()
        return evidence

    def promote(
        self,
        artifact_id: str,
        target_tier: PromotionTier,
        decision_record_id: str,
        reason: str,
        attested_workload: bool,
    ) -> ArtifactLifecycleRecord:
        record = self.get_record(artifact_id)

        if record.revoked:
            raise ValueError("revoked artifact cannot be promoted")

        current_rank = TIER_ORDER[record.current_tier]
        target_rank = TIER_ORDER[target_tier.value]
        if target_rank < current_rank:
            raise ValueError("downgrade is not a promotion")
        if target_rank == current_rank:
            return record

        blockers = self._promotion_blockers(
            record,
            target_tier,
            attested_workload,
        )
        if blockers:
            raise ValueError("promotion denied: " + ";".join(blockers))

        event = PromotionEvent(
            promotion_id=new_id("promo"),
            from_tier=record.current_tier,
            to_tier=target_tier.value,
            decision_record_id=decision_record_id,
            promoted_at=utc_now(),
            reason=reason,
        )

        updated = replace(
            record,
            current_tier=target_tier.value,
            promotion_history=record.promotion_history + (event,),
        )
        self._state["artifacts"][artifact_id] = to_primitive(updated)
        self._save()
        return updated

    def revoke(
        self,
        artifact_id: str,
        incident_ref: str,
    ) -> ArtifactLifecycleRecord:
        record = self.get_record(artifact_id)
        updated = replace(
            record,
            revoked=True,
            incident_refs=record.incident_refs + (incident_ref,),
        )
        self._state["artifacts"][artifact_id] = to_primitive(updated)
        self._save()
        return updated

    def get_record(self, artifact_id: str) -> ArtifactLifecycleRecord:
        serialized = self._state["artifacts"].get(artifact_id)
        if serialized is None:
            raise KeyError(f"unknown artifact: {artifact_id}")
        return self._record_from_dict(serialized)

    def list_by_tier(
        self,
        tier: PromotionTier,
    ) -> list[ArtifactLifecycleRecord]:
        records = []
        for serialized in self._state["artifacts"].values():
            record = self._record_from_dict(serialized)
            if record.current_tier == tier.value:
                records.append(record)
        return records

    def _promotion_blockers(
        self,
        record: ArtifactLifecycleRecord,
        target_tier: PromotionTier,
        attested_workload: bool,
    ) -> list[str]:
        blockers: list[str] = []

        if not record.signature_verified:
            blockers.append("signature_not_verified")
        if not record.static_scan_passed:
            blockers.append("static_scan_failed")
        if not record.dependency_scan_passed:
            blockers.append("dependency_scan_failed")

        if target_tier in {
            PromotionTier.SOVEREIGN_APPROVED,
            PromotionTier.ENCLAVE_ALLOWED,
        } and not record.provenance_verified:
            blockers.append("provenance_not_verified")

        if target_tier == PromotionTier.ENCLAVE_ALLOWED:
            if not record.airgap_manifest_approved:
                blockers.append("airgap_manifest_not_approved")
            if not attested_workload:
                blockers.append("attested_workload_required")

        required_evidence = self._required_evidence_types(target_tier)
        for evidence_type in required_evidence:
            if not self._has_passing_evidence(record, evidence_type):
                blockers.append(f"evidence_missing:{evidence_type}")

        if (
            target_tier == PromotionTier.ENCLAVE_ALLOWED
            and attested_workload
            and not self._has_passing_evidence(record, "attested_workload")
        ):
            blockers.append("evidence_missing:attested_workload")

        return blockers

    @staticmethod
    def _required_evidence_types(
        target_tier: PromotionTier,
    ) -> tuple[str, ...]:
        evidence = [
            "signature",
            "static_scan",
            "dependency_scan",
        ]
        if target_tier in {
            PromotionTier.SOVEREIGN_APPROVED,
            PromotionTier.ENCLAVE_ALLOWED,
        }:
            evidence.append("provenance")
        if target_tier == PromotionTier.ENCLAVE_ALLOWED:
            evidence.append("airgap_manifest")
        return tuple(evidence)

    def _has_passing_evidence(
        self,
        record: ArtifactLifecycleRecord,
        evidence_type: str,
    ) -> bool:
        for evidence_id in record.evidence_ids:
            raw = self._state["evidence"].get(evidence_id)
            if not raw:
                continue
            evidence = self._evidence_from_dict(raw)
            if (
                evidence.artifact_id == record.artifact_id
                and evidence.evidence_type == evidence_type
                and evidence.passed
            ):
                return True
        return False

    def _record_from_dict(
        self,
        raw: dict[str, Any],
    ) -> ArtifactLifecycleRecord:
        events = tuple(
            PromotionEvent(
                promotion_id=item["promotion_id"],
                from_tier=item["from_tier"],
                to_tier=item["to_tier"],
                decision_record_id=item["decision_record_id"],
                promoted_at=item["promoted_at"],
                reason=item["reason"],
            )
            for item in raw.get("promotion_history", [])
        )
        return ArtifactLifecycleRecord(
            artifact_id=raw["artifact_id"],
            artifact_type=ArtifactType(raw["artifact_type"]),
            publisher=raw["publisher"],
            checksum=raw["checksum"],
            signature_verified=bool(raw["signature_verified"]),
            static_scan_passed=bool(raw["static_scan_passed"]),
            dependency_scan_passed=bool(raw["dependency_scan_passed"]),
            provenance_verified=bool(raw["provenance_verified"]),
            airgap_manifest_approved=bool(raw["airgap_manifest_approved"]),
            current_tier=str(raw["current_tier"]),
            revoked=bool(raw["revoked"]),
            incident_refs=tuple(raw.get("incident_refs", [])),
            evidence_ids=tuple(raw.get("evidence_ids", [])),
            promotion_history=events,
        )

    @staticmethod
    def _evidence_from_dict(
        raw: dict[str, Any],
    ) -> ArtifactEvidenceRecord:
        return ArtifactEvidenceRecord(
            evidence_id=raw["evidence_id"],
            artifact_id=raw["artifact_id"],
            evidence_type=raw["evidence_type"],
            passed=bool(raw["passed"]),
            evidence_ref=raw["evidence_ref"],
            recorded_at=raw["recorded_at"],
            details=dict(raw.get("details", {})),
        )

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
