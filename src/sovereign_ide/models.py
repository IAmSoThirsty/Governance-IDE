from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any
from uuid import uuid4


class MutationClass(str, Enum):
    READ = "read"
    SOFT_MUTATION = "softMutation"
    HARD_MUTATION = "hardMutation"
    GOVERNANCE_MUTATION = "governanceMutation"


class DecisionOutcome(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    COMPENSATED = "compensated"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def to_primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if is_dataclass(value):
        return to_primitive(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_primitive(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_primitive(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SignatureEnvelope:
    algorithm: str
    key_id: str
    signature: str
    signed_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    subject: str
    scopes: tuple[str, ...]
    trust_domain: str
    issued_at: str
    expires_at: str
    revoked: bool = False

    def is_active(self, at_time: str | None = None) -> bool:
        if self.revoked:
            return False
        now = (
            datetime.fromisoformat(at_time)
            if at_time
            else datetime.now(timezone.utc)
        )
        expires = datetime.fromisoformat(self.expires_at)
        return now < expires


@dataclass(frozen=True)
class GovernanceContext:
    trace_id: str
    actor_id: str
    actor_roles: tuple[str, ...]
    tenant: str
    trust_domain: str
    workspace_root: str
    classification: str
    policy_pack_version: str


@dataclass(frozen=True)
class PolicyEvaluationRequest:
    request_id: str
    trace_id: str
    action: str
    resource: str
    mutation_class: MutationClass
    requested_by: str
    requested_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class PolicyEvaluationResult:
    evaluation_id: str
    request_id: str
    trace_id: str
    allowed: bool
    denial_reasons: tuple[str, ...]
    obligations: tuple[str, ...]
    risk_score: int
    matched_rules: tuple[str, ...]
    policy_pack_version: str
    evaluated_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class GovernanceEvaluationBinding:
    binding_id: str
    trace_id: str
    request_id: str
    evaluation_id: str
    request_hash: str
    context_hash: str
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class MutationGovernanceBinding:
    trace_id: str
    action: str
    resource: str
    mutation_class: MutationClass
    capability_token: CapabilityToken
    governance_context: GovernanceContext
    policy_evaluation: PolicyEvaluationResult
    evaluation_binding: GovernanceEvaluationBinding
    resolution_policy: str
    quorum_proof: str | None = None


@dataclass(frozen=True)
class DecisionRecord:
    decision_id: str
    trace_id: str
    action: str
    resource: str
    mutation_class: MutationClass
    outcome: DecisionOutcome
    reason: str
    policy_evaluation_id: str
    binding_id: str
    capability_token_id: str
    governance_context_hash: str
    resolution_policy: str
    quorum_proof: str | None
    previous_decision_hash: str | None
    created_at: str
    signature: SignatureEnvelope


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    trace_id: str
    decision_id: str
    event_type: str
    severity: str
    details: Mapping[str, Any]
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class CompensationTransaction:
    compensation_id: str
    trace_id: str
    target_decision_id: str
    reason: str
    executed_by: str
    evidence_refs: tuple[str, ...]
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ToolExecution:
    execution_id: str
    trace_id: str
    tool_name: str
    operation: str
    input_hash: str
    output_hash: str
    exit_code: int
    started_at: str
    ended_at: str


@dataclass(frozen=True)
class PatchProposal:
    patch_id: str
    trace_id: str
    target_files: tuple[str, ...]
    diff_hash: str
    rationale: str
    risk_posture: str
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ApprovalDecision:
    approval_id: str
    trace_id: str
    patch_id: str
    approver: str
    approver_role: str
    approved: bool
    reason: str
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class BuildArtifact:
    artifact_id: str
    trace_id: str
    name: str
    version: str
    checksum: str
    provenance_ref: str
    signed_by: str
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class ReleaseBundle:
    bundle_id: str
    artifact_ids: tuple[str, ...]
    promotion_tier: str
    signed_by: str
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class RetrievalLabels:
    tenant: str
    project: str
    trust_domain: str
    classification: str
    exportable: bool
    provenance_class: str
    trust_score: float
    embedding_lineage: str


@dataclass(frozen=True)
class RetrievalChunk:
    chunk_id: str
    source_uri: str
    content: str
    labels: RetrievalLabels
    retrieved_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class PromptContext:
    trace_id: str
    tenant: str
    trust_domain: str
    clearance: str
    constitution_version: str
    machine_policy_version: str
    user_objective: str
    evidence_chunk_ids: tuple[str, ...] = field(default_factory=tuple)


def tuple_from_sequence(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(str(value) for value in values)
