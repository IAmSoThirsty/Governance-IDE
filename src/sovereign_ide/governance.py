from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from contextlib import closing, contextmanager
from pathlib import Path
import hmac
import hashlib
import json
import os
import sqlite3
from typing import Any, Callable, Protocol

from .models import (
    AuditEvent,
    CapabilityToken,
    CompensationTransaction,
    DecisionOutcome,
    DecisionRecord,
    GovernanceContext,
    GovernanceEvaluationBinding,
    MutationClass,
    MutationGovernanceBinding,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
    SignatureEnvelope,
    canonical_json,
    new_id,
    sha256_hex,
    to_primitive,
    utc_now,
)
from .validation import load_policy_pack, validate_policy_pack


MUTATION_ORDER = {
    MutationClass.READ.value: 0,
    MutationClass.SOFT_MUTATION.value: 1,
    MutationClass.HARD_MUTATION.value: 2,
    MutationClass.GOVERNANCE_MUTATION.value: 3,
}


class GovernanceError(RuntimeError):
    """Raised when governance invariants are violated."""


class PolicyViolation(GovernanceError):
    """Raised when a mutation request violates policy."""


class JournalIntegrityError(GovernanceError):
    """Raised when append-only journal integrity verification fails."""


class DecisionSigner(Protocol):
    key_id: str

    def sign(self, payload: dict[str, Any]) -> SignatureEnvelope:
        ...

    def verify(
        self,
        payload: dict[str, Any],
        envelope: SignatureEnvelope,
    ) -> bool:
        ...


@dataclass(frozen=True)
class MutationCommitResult:
    applied: bool
    decision: DecisionRecord
    payload: dict[str, Any] | None


class HashChainJournal:
    """Append-only journal with hash chaining for replay integrity."""

    def __init__(self, journal_path: str | Path) -> None:
        self.path = Path(journal_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._entry_count = 0
        self._last_hash: str | None = None
        self._hydrate_state()

    def _hydrate_state(self) -> None:
        verified_entries = self._load_and_verify_entries()
        if not verified_entries:
            self._entry_count = 0
            self._last_hash = None
            return

        last_entry = verified_entries[-1]
        self._entry_count = int(last_entry["sequence"])
        self._last_hash = str(last_entry["entry_hash"])

    @staticmethod
    def _entry_hash_input(entry: dict[str, Any]) -> dict[str, Any]:
        hash_input = dict(entry)
        hash_input.pop("entry_hash", None)
        return hash_input

    def _verify_entry(
        self,
        entry: dict[str, Any],
        *,
        expected_sequence: int,
        previous_hash: str | None,
        line_number: int,
    ) -> None:
        required_fields = {
            "entry_id",
            "sequence",
            "timestamp",
            "record_type",
            "trace_id",
            "payload",
            "previous_hash",
            "entry_hash",
        }
        missing = required_fields.difference(entry.keys())
        if missing:
            raise JournalIntegrityError(
                "journal_entry_missing_fields:"
                f"line={line_number}:missing={','.join(sorted(missing))}",
            )

        try:
            sequence = int(entry["sequence"])
        except (TypeError, ValueError) as exc:
            raise JournalIntegrityError(
                f"journal_entry_invalid_sequence:line={line_number}",
            ) from exc

        if sequence != expected_sequence:
            raise JournalIntegrityError(
                "journal_sequence_mismatch:"
                f"line={line_number}:"
                f"expected={expected_sequence}:"
                f"actual={sequence}",
            )

        if entry.get("previous_hash") != previous_hash:
            raise JournalIntegrityError(
                "journal_previous_hash_mismatch:"
                f"line={line_number}:"
                f"expected={previous_hash}:"
                f"actual={entry.get('previous_hash')}",
            )

        expected_entry_hash = hashlib.sha256(
            canonical_json(self._entry_hash_input(entry)).encode("utf-8"),
        ).hexdigest()
        if entry.get("entry_hash") != expected_entry_hash:
            raise JournalIntegrityError(
                "journal_entry_hash_mismatch:"
                f"line={line_number}:"
                f"expected={expected_entry_hash}:"
                f"actual={entry.get('entry_hash')}",
            )

    def _load_and_verify_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        previous_hash: str | None = None
        expected_sequence = 1

        for line_number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise JournalIntegrityError(
                    f"journal_entry_invalid_json:line={line_number}",
                ) from exc

            self._verify_entry(
                entry,
                expected_sequence=expected_sequence,
                previous_hash=previous_hash,
                line_number=line_number,
            )
            entries.append(entry)
            previous_hash = str(entry["entry_hash"])
            expected_sequence += 1

        return entries

    def append(
        self,
        record_type: str,
        trace_id: str,
        payload: Any,
    ) -> dict[str, Any]:
        with self._journal_lock():
            self._hydrate_state()
            entry = {
                "entry_id": new_id("journal"),
                "sequence": self._entry_count + 1,
                "timestamp": utc_now(),
                "record_type": record_type,
                "trace_id": trace_id,
                "payload": to_primitive(payload),
                "previous_hash": self._last_hash,
            }
            entry_hash = hashlib.sha256(
                canonical_json(entry).encode("utf-8"),
            ).hexdigest()
            entry["entry_hash"] = entry_hash

            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

            self._entry_count += 1
            self._last_hash = entry_hash
            return entry

    def read_all(self) -> list[dict[str, Any]]:
        return self._load_and_verify_entries()

    def replay_trace(self, trace_id: str) -> list[dict[str, Any]]:
        return [
            entry for entry in self.read_all() if entry["trace_id"] == trace_id
        ]

    @contextmanager
    def _journal_lock(self):
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class HMACDecisionSigner:
    """Development/local signer only; replace with Ed25519/KMS/HSM for production."""

    def __init__(self, key_material: str, key_id: str = "local-hmac") -> None:
        self._key = key_material.encode("utf-8")
        self.key_id = key_id

    def sign(self, payload: dict[str, Any]) -> SignatureEnvelope:
        digest = hmac.new(
            self._key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return SignatureEnvelope(
            algorithm="HMAC-SHA256",
            key_id=self.key_id,
            signature=digest,
        )

    def verify(
        self,
        payload: dict[str, Any],
        envelope: SignatureEnvelope,
    ) -> bool:
        expected = hmac.new(
            self._key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, envelope.signature)


class Ed25519DecisionSigner:
    """Production signer scaffold backed by cryptography when configured."""

    def __init__(
        self,
        private_key_pem: str,
        key_id: str = "ed25519",
    ) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Ed25519 signing requires the cryptography package",
            ) from exc
        self._serialization = serialization
        self._private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        self._public_key = self._private_key.public_key()
        self.key_id = key_id

    def sign(self, payload: dict[str, Any]) -> SignatureEnvelope:
        signature = self._private_key.sign(
            canonical_json(payload).encode("utf-8"),
        ).hex()
        return SignatureEnvelope(
            algorithm="Ed25519",
            key_id=self.key_id,
            signature=signature,
        )

    def verify(
        self,
        payload: dict[str, Any],
        envelope: SignatureEnvelope,
    ) -> bool:
        try:
            self._public_key.verify(
                bytes.fromhex(envelope.signature),
                canonical_json(payload).encode("utf-8"),
            )
            return True
        except Exception:  # noqa: BLE001
            return False


class SQLiteEventJournal(HashChainJournal):
    """SQLite-backed append-only hash-chain journal for local runtime mode."""

    def __init__(self, journal_path: str | Path) -> None:
        self.path = Path(journal_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entry_count = 0
        self._last_hash: str | None = None
        self._init_db()
        self._hydrate_state()

    def _init_db(self) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    entry_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT,
                    entry_hash TEXT NOT NULL UNIQUE
                )
                """,
            )
            db.commit()

    def _load_raw_entries(self) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute(
                """
                SELECT entry_id, sequence, timestamp, record_type, trace_id,
                       payload_json, previous_hash, entry_hash
                FROM events
                ORDER BY sequence ASC
                """,
            ).fetchall()
        return [
            {
                "entry_id": row[0],
                "sequence": row[1],
                "timestamp": row[2],
                "record_type": row[3],
                "trace_id": row[4],
                "payload": json.loads(row[5]),
                "previous_hash": row[6],
                "entry_hash": row[7],
            }
            for row in rows
        ]

    def _load_and_verify_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        previous_hash: str | None = None
        expected_sequence = 1
        for line_number, entry in enumerate(self._load_raw_entries(), start=1):
            self._verify_entry(
                entry,
                expected_sequence=expected_sequence,
                previous_hash=previous_hash,
                line_number=line_number,
            )
            entries.append(entry)
            previous_hash = str(entry["entry_hash"])
            expected_sequence += 1
        return entries

    def append(
        self,
        record_type: str,
        trace_id: str,
        payload: Any,
    ) -> dict[str, Any]:
        with self._journal_lock():
            self._hydrate_state()
            entry = {
                "entry_id": new_id("journal"),
                "sequence": self._entry_count + 1,
                "timestamp": utc_now(),
                "record_type": record_type,
                "trace_id": trace_id,
                "payload": to_primitive(payload),
                "previous_hash": self._last_hash,
            }
            entry_hash = hashlib.sha256(
                canonical_json(entry).encode("utf-8"),
            ).hexdigest()
            entry["entry_hash"] = entry_hash
            with closing(sqlite3.connect(self.path)) as db:
                db.execute(
                    """
                    INSERT INTO events (
                        sequence, entry_id, timestamp, record_type, trace_id,
                        payload_json, previous_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["sequence"],
                        entry["entry_id"],
                        entry["timestamp"],
                        entry["record_type"],
                        entry["trace_id"],
                        canonical_json(entry["payload"]),
                        entry["previous_hash"],
                        entry["entry_hash"],
                    ),
                )
                db.commit()
            self._entry_count += 1
            self._last_hash = entry_hash
            return entry


def build_journal(settings: Any, *, path: str | Path | None = None) -> HashChainJournal:
    if settings.journal_backend == "file":
        return HashChainJournal(path or settings.journal_path)
    return SQLiteEventJournal(path or settings.sqlite_journal_path)


def build_decision_signer(settings: Any) -> DecisionSigner:
    if settings.signer_backend == "hmac-dev":
        return HMACDecisionSigner(settings.signing_key)
    if settings.signer_backend == "ed25519":
        key = os.getenv("SOVEREIGN_ED25519_PRIVATE_KEY_PEM", "").strip()
        if not key:
            raise ValueError(
                "SOVEREIGN_ED25519_PRIVATE_KEY_PEM is required for ed25519 signing",
            )
        return Ed25519DecisionSigner(key, key_id=os.getenv("SOVEREIGN_SIGNER_KEY_ID", "ed25519"))
    raise ValueError("SOVEREIGN_SIGNER_BACKEND must be hmac-dev or ed25519")


class PolicyEngine:
    """Evaluates mutation requests under conservative default-deny policy."""

    def __init__(self, policy_pack: dict[str, Any]) -> None:
        validate_policy_pack(policy_pack)
        self.policy_pack = policy_pack

    @classmethod
    def from_path(
        cls,
        policy_path: str | Path,
        workspace_root: str | Path | None = None,
    ) -> "PolicyEngine":
        policy = load_policy_pack(policy_path, workspace_root=workspace_root)
        return cls(policy)

    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        context: GovernanceContext,
        capability_token: CapabilityToken,
    ) -> PolicyEvaluationResult:
        denials: list[str] = []
        obligations: list[str] = []
        matched_rules: list[str] = []

        resolution = self.policy_pack.get("resolution", {})
        if resolution.get("default", "deny") != "deny":
            denials.append("resolution_default_not_deny")

        action_rules = self.policy_pack.get("actions", {})
        action_rule = action_rules.get(request.action)
        if not action_rule:
            denials.append("action_not_defined")
        else:
            matched_rules.append(f"action:{request.action}")
            required_class = action_rule.get(
                "required_mutation_class",
                request.mutation_class.value,
            )
            if (
                MUTATION_ORDER[request.mutation_class.value]
                < MUTATION_ORDER.get(required_class, 99)
            ):
                denials.append("mutation_class_too_low")

            allowed_roles = set(action_rule.get("allowed_roles", []))
            if allowed_roles and not allowed_roles.intersection(
                context.actor_roles,
            ):
                denials.append("role_not_authorized")

            if action_rule.get("quorum_required", False):
                obligations.append("quorum_proof_required")

        if not capability_token.is_active(utc_now()):
            denials.append("capability_token_inactive")

        if request.action not in capability_token.scopes:
            denials.append("capability_scope_missing")

        if capability_token.trust_domain != context.trust_domain:
            denials.append("capability_trust_domain_mismatch")

        roots = self.policy_pack.get("workspace", {}).get("allowed_roots", [])
        if roots and not self._resource_allowed(request.resource, roots):
            denials.append("resource_outside_allowed_roots")

        risk_scores = self.policy_pack.get("risk_scores", {})
        risk_score = int(risk_scores.get(request.mutation_class.value, 70))
        if action_rule and "risk_score" in action_rule:
            risk_score = int(action_rule["risk_score"])

        return PolicyEvaluationResult(
            evaluation_id=new_id("evaluation"),
            request_id=request.request_id,
            trace_id=request.trace_id,
            allowed=not denials,
            denial_reasons=tuple(denials),
            obligations=tuple(obligations),
            risk_score=risk_score,
            matched_rules=tuple(matched_rules),
            policy_pack_version=self.policy_pack.get("version", "unknown"),
        )

    @staticmethod
    def _resource_allowed(resource: str, allowed_roots: list[str]) -> bool:
        resource_path = Path(resource)
        if not resource_path.is_absolute():
            resource_path = Path.cwd() / resource_path

        try:
            resolved_resource = resource_path.resolve(strict=False)
        except OSError:
            return False

        for root in allowed_roots:
            root_path = Path(root)
            if not root_path.is_absolute():
                root_path = Path.cwd() / root_path

            try:
                resolved_root = root_path.resolve(strict=False)
                resolved_resource.relative_to(resolved_root)
                return True
            except (OSError, ValueError):
                continue

        return False


class GovernanceRuntime:
    """Executes governed mutation flow with immutable decisions."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        journal: HashChainJournal,
        signer: DecisionSigner,
    ) -> None:
        self.policy_engine = policy_engine
        self.journal = journal
        self.signer = signer
        self._requests: dict[str, PolicyEvaluationRequest] = {}
        self._evaluations: dict[str, PolicyEvaluationResult] = {}
        self._bindings: dict[str, GovernanceEvaluationBinding] = {}
        self._decisions: dict[str, DecisionRecord] = {}
        self._last_decision_hash: str | None = None
        self._hydrate_decisions_from_journal()

    def evaluate_and_bind(
        self,
        context: GovernanceContext,
        action: str,
        resource: str,
        mutation_class: MutationClass,
        capability_token: CapabilityToken,
    ) -> tuple[
        PolicyEvaluationRequest,
        PolicyEvaluationResult,
        GovernanceEvaluationBinding,
    ]:
        request = PolicyEvaluationRequest(
            request_id=new_id("request"),
            trace_id=context.trace_id,
            action=action,
            resource=resource,
            mutation_class=mutation_class,
            requested_by=context.actor_id,
        )
        evaluation = self.policy_engine.evaluate(
            request,
            context,
            capability_token,
        )

        binding = GovernanceEvaluationBinding(
            binding_id=new_id("binding"),
            trace_id=context.trace_id,
            request_id=request.request_id,
            evaluation_id=evaluation.evaluation_id,
            request_hash=sha256_hex(request),
            context_hash=sha256_hex(context),
        )

        self._requests[request.request_id] = request
        self._evaluations[evaluation.evaluation_id] = evaluation
        self._bindings[binding.binding_id] = binding

        self.journal.append(
            "policy_evaluation_request",
            context.trace_id,
            request,
        )
        self.journal.append(
            "policy_evaluation_result",
            context.trace_id,
            evaluation,
        )
        self.journal.append(
            "governance_evaluation_binding",
            context.trace_id,
            binding,
        )

        return request, evaluation, binding

    def build_mutation_binding(
        self,
        context: GovernanceContext,
        action: str,
        resource: str,
        mutation_class: MutationClass,
        capability_token: CapabilityToken,
        evaluation: PolicyEvaluationResult,
        binding: GovernanceEvaluationBinding,
        resolution_policy: str,
        quorum_proof: str | None = None,
    ) -> MutationGovernanceBinding:
        if evaluation.evaluation_id != binding.evaluation_id:
            raise GovernanceError("evaluation/binding mismatch")

        return MutationGovernanceBinding(
            trace_id=context.trace_id,
            action=action,
            resource=resource,
            mutation_class=mutation_class,
            capability_token=capability_token,
            governance_context=context,
            policy_evaluation=evaluation,
            evaluation_binding=binding,
            resolution_policy=resolution_policy,
            quorum_proof=quorum_proof,
        )

    def commit_mutation(
        self,
        mutation_binding: MutationGovernanceBinding,
        mutate: Callable[[], dict[str, Any]],
    ) -> MutationCommitResult:
        self._validate_mutation_binding(mutation_binding)

        request = self._requests.get(
            mutation_binding.evaluation_binding.request_id,
        )
        evaluation = self._evaluations.get(
            mutation_binding.evaluation_binding.evaluation_id,
        )
        if request is None or evaluation is None:
            raise GovernanceError("missing bound request/evaluation state")

        if request.trace_id != mutation_binding.trace_id:
            raise GovernanceError("trace mismatch between request and binding")

        self._validate_binding_consistency(
            mutation_binding,
            request,
            evaluation,
        )

        denials = list(evaluation.denial_reasons)
        obligations = set(evaluation.obligations)

        if not evaluation.allowed and not denials:
            denials.append("policy_disallowed")

        if (
            "quorum_proof_required" in obligations
            and not mutation_binding.quorum_proof
        ):
            denials.append("quorum_proof_missing")

        if denials:
            decision = self._record_decision(
                binding=mutation_binding,
                outcome=DecisionOutcome.DENIED,
                reason=";".join(denials),
            )
            self._record_audit(
                decision,
                "mutation_denied",
                {"denials": denials},
            )
            return MutationCommitResult(
                applied=False,
                decision=decision,
                payload=None,
            )

        try:
            payload = mutate()
        except Exception as exc:  # noqa: BLE001
            decision = self._record_decision(
                binding=mutation_binding,
                outcome=DecisionOutcome.DENIED,
                reason=f"mutation_execution_failed:{exc}",
            )
            self._record_audit(
                decision,
                "mutation_failed",
                {"error": str(exc)},
            )
            return MutationCommitResult(
                applied=False,
                decision=decision,
                payload=None,
            )

        decision = self._record_decision(
            binding=mutation_binding,
            outcome=DecisionOutcome.APPROVED,
            reason="policy_allowed",
        )
        self._record_audit(decision, "mutation_applied", payload)
        return MutationCommitResult(
            applied=True,
            decision=decision,
            payload=payload,
        )

    def compensate(
        self,
        target_decision_id: str,
        context: GovernanceContext,
        reason: str,
        compensate_fn: Callable[[], dict[str, Any]],
    ) -> tuple[CompensationTransaction, DecisionRecord, dict[str, Any]]:
        target = self._decisions.get(target_decision_id)
        if target is None:
            raise GovernanceError("target decision not found")
        if target.outcome != DecisionOutcome.APPROVED:
            raise GovernanceError("only approved decisions can be compensated")

        compensation_action = f"compensate:{target.action}"
        compensation_token = CapabilityToken(
            token_id=new_id("token"),
            subject=context.actor_id,
            scopes=(compensation_action,),
            trust_domain=context.trust_domain,
            issued_at=utc_now(),
            expires_at=(
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
            revoked=False,
        )

        (
            _,
            synthetic_eval,
            synthetic_binding,
        ) = self.evaluate_and_bind(
            context=context,
            action=compensation_action,
            resource=target.resource,
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            capability_token=compensation_token,
        )

        binding = self.build_mutation_binding(
            context=context,
            action=compensation_action,
            resource=target.resource,
            mutation_class=MutationClass.GOVERNANCE_MUTATION,
            capability_token=compensation_token,
            evaluation=synthetic_eval,
            binding=synthetic_binding,
            resolution_policy=(
                "invariants>decision>policy>capability>runtime>override"
            ),
            quorum_proof="compensation-authorized",
        )

        self._validate_binding_consistency(
            binding,
            self._requests[synthetic_binding.request_id],
            synthetic_eval,
        )

        if synthetic_eval.denial_reasons:
            joined_denials = ";".join(synthetic_eval.denial_reasons)
            denied_decision = self._record_decision(
                binding=binding,
                outcome=DecisionOutcome.DENIED,
                reason=f"compensation_denied:{joined_denials}",
            )
            self._record_audit(
                denied_decision,
                "compensation_denied",
                {"denials": list(synthetic_eval.denial_reasons)},
            )
            raise PolicyViolation(
                f"compensation denied by policy: {joined_denials}",
            )

        if (
            "quorum_proof_required" in synthetic_eval.obligations
            and not binding.quorum_proof
        ):
            denied_decision = self._record_decision(
                binding=binding,
                outcome=DecisionOutcome.DENIED,
                reason="compensation_denied:quorum_proof_missing",
            )
            self._record_audit(
                denied_decision,
                "compensation_denied",
                {"denials": ["quorum_proof_missing"]},
            )
            raise PolicyViolation("compensation requires quorum proof")

        try:
            payload = compensate_fn()
        except Exception as exc:  # noqa: BLE001
            denied_decision = self._record_decision(
                binding=binding,
                outcome=DecisionOutcome.DENIED,
                reason=f"compensation_execution_failed:{exc}",
            )
            self._record_audit(
                denied_decision,
                "compensation_failed",
                {"error": str(exc)},
            )
            raise GovernanceError(
                f"compensation execution failed: {exc}",
            ) from exc

        transaction = CompensationTransaction(
            compensation_id=new_id("comp"),
            trace_id=context.trace_id,
            target_decision_id=target_decision_id,
            reason=reason,
            executed_by=context.actor_id,
            evidence_refs=(target_decision_id,),
        )

        self.journal.append(
            "compensation_transaction",
            context.trace_id,
            transaction,
        )

        decision = self._record_decision(
            binding=binding,
            outcome=DecisionOutcome.COMPENSATED,
            reason=f"compensation_for:{target_decision_id}:{reason}",
        )
        self._record_audit(decision, "compensation_applied", payload)
        return transaction, decision, payload

    def replay_trace(self, trace_id: str) -> list[dict[str, Any]]:
        return self.journal.replay_trace(trace_id)

    def _hydrate_decisions_from_journal(self) -> None:
        previous_decision_hash: str | None = None

        for entry in self.journal.read_all():
            if entry.get("record_type") != "decision_record":
                continue
            payload = entry.get("payload", {})
            decision = self._decision_from_payload(payload)
            unsigned_payload = self._unsigned_decision_payload(payload)

            if not self.signer.verify(unsigned_payload, decision.signature):
                raise JournalIntegrityError(
                    f"decision_signature_invalid:{decision.decision_id}",
                )

            if decision.previous_decision_hash != previous_decision_hash:
                raise JournalIntegrityError(
                    "decision_chain_broken:"
                    f"decision={decision.decision_id}:"
                    f"expected_previous={previous_decision_hash}:"
                    f"actual_previous={decision.previous_decision_hash}",
                )

            self._decisions[decision.decision_id] = decision
            previous_decision_hash = sha256_hex(decision)

        self._last_decision_hash = previous_decision_hash

    @staticmethod
    def _decision_from_payload(payload: dict[str, Any]) -> DecisionRecord:
        try:
            signature_raw = payload["signature"]
            return DecisionRecord(
                decision_id=payload["decision_id"],
                trace_id=payload["trace_id"],
                action=payload["action"],
                resource=payload["resource"],
                mutation_class=MutationClass(payload["mutation_class"]),
                outcome=DecisionOutcome(payload["outcome"]),
                reason=payload["reason"],
                policy_evaluation_id=payload["policy_evaluation_id"],
                binding_id=payload["binding_id"],
                capability_token_id=payload["capability_token_id"],
                governance_context_hash=payload["governance_context_hash"],
                resolution_policy=payload["resolution_policy"],
                quorum_proof=payload.get("quorum_proof"),
                previous_decision_hash=payload.get("previous_decision_hash"),
                created_at=payload["created_at"],
                signature=SignatureEnvelope(
                    algorithm=signature_raw["algorithm"],
                    key_id=signature_raw["key_id"],
                    signature=signature_raw["signature"],
                    signed_at=signature_raw["signed_at"],
                ),
            )
        except (KeyError, ValueError) as exc:
            raise JournalIntegrityError(
                "decision_payload_invalid",
            ) from exc

    @staticmethod
    def _unsigned_decision_payload(payload: dict[str, Any]) -> dict[str, Any]:
        required = [
            "decision_id",
            "trace_id",
            "action",
            "resource",
            "mutation_class",
            "outcome",
            "reason",
            "policy_evaluation_id",
            "binding_id",
            "capability_token_id",
            "governance_context_hash",
            "resolution_policy",
            "created_at",
        ]
        missing = [field for field in required if field not in payload]
        if missing:
            raise JournalIntegrityError(
                "decision_payload_missing_fields:" + ",".join(missing),
            )

        return {
            "decision_id": payload["decision_id"],
            "trace_id": payload["trace_id"],
            "action": payload["action"],
            "resource": payload["resource"],
            "mutation_class": payload["mutation_class"],
            "outcome": payload["outcome"],
            "reason": payload["reason"],
            "policy_evaluation_id": payload["policy_evaluation_id"],
            "binding_id": payload["binding_id"],
            "capability_token_id": payload["capability_token_id"],
            "governance_context_hash": payload["governance_context_hash"],
            "resolution_policy": payload["resolution_policy"],
            "quorum_proof": payload.get("quorum_proof"),
            "previous_decision_hash": payload.get("previous_decision_hash"),
            "created_at": payload["created_at"],
        }

    def _validate_mutation_binding(
        self,
        binding: MutationGovernanceBinding,
    ) -> None:
        required = [
            binding.trace_id,
            binding.action,
            binding.resource,
            binding.mutation_class.value,
            binding.capability_token.token_id,
            binding.governance_context.trace_id,
            binding.evaluation_binding.binding_id,
            binding.policy_evaluation.evaluation_id,
            binding.resolution_policy,
        ]
        if any(not value for value in required):
            raise GovernanceError("incomplete mutation governance binding")

        if binding.trace_id != binding.governance_context.trace_id:
            raise GovernanceError("binding trace/context mismatch")

        if (
            binding.policy_evaluation.evaluation_id
            != binding.evaluation_binding.evaluation_id
        ):
            raise GovernanceError("binding evaluation id mismatch")

    def _validate_binding_consistency(
        self,
        binding: MutationGovernanceBinding,
        request: PolicyEvaluationRequest,
        evaluation: PolicyEvaluationResult,
    ) -> None:
        if request.action != binding.action:
            raise GovernanceError("binding/request action mismatch")
        if request.resource != binding.resource:
            raise GovernanceError("binding/request resource mismatch")
        if request.mutation_class != binding.mutation_class:
            raise GovernanceError("binding/request mutation class mismatch")

        if request.request_id != evaluation.request_id:
            raise GovernanceError("request/evaluation request_id mismatch")
        if evaluation.evaluation_id != binding.policy_evaluation.evaluation_id:
            raise GovernanceError("binding/policy evaluation mismatch")

        if binding.trace_id != request.trace_id:
            raise GovernanceError("binding/request trace mismatch")
        if binding.trace_id != evaluation.trace_id:
            raise GovernanceError("binding/evaluation trace mismatch")
        if binding.trace_id != binding.evaluation_binding.trace_id:
            raise GovernanceError("binding/evaluation binding trace mismatch")

        if binding.evaluation_binding.request_id != request.request_id:
            raise GovernanceError("evaluation binding request mismatch")
        if (
            binding.evaluation_binding.evaluation_id
            != evaluation.evaluation_id
        ):
            raise GovernanceError("evaluation binding evaluation mismatch")

        if binding.evaluation_binding.request_hash != sha256_hex(request):
            raise GovernanceError("evaluation binding request hash mismatch")
        if (
            binding.evaluation_binding.context_hash
            != sha256_hex(binding.governance_context)
        ):
            raise GovernanceError("evaluation binding context hash mismatch")

        if binding.capability_token.subject != request.requested_by:
            raise GovernanceError("capability subject/request actor mismatch")
        if not binding.capability_token.is_active(utc_now()):
            raise GovernanceError("capability token inactive")
        if binding.action not in binding.capability_token.scopes:
            raise GovernanceError("capability token missing action scope")
        if (
            binding.capability_token.trust_domain
            != binding.governance_context.trust_domain
        ):
            raise GovernanceError("capability token trust-domain mismatch")

    def _record_decision(
        self,
        binding: MutationGovernanceBinding,
        outcome: DecisionOutcome,
        reason: str,
    ) -> DecisionRecord:
        created_at = utc_now()
        unsigned_payload = {
            "decision_id": new_id("decision"),
            "trace_id": binding.trace_id,
            "action": binding.action,
            "resource": binding.resource,
            "mutation_class": binding.mutation_class.value,
            "outcome": outcome.value,
            "reason": reason,
            "policy_evaluation_id": binding.policy_evaluation.evaluation_id,
            "binding_id": binding.evaluation_binding.binding_id,
            "capability_token_id": binding.capability_token.token_id,
            "governance_context_hash": sha256_hex(binding.governance_context),
            "resolution_policy": binding.resolution_policy,
            "quorum_proof": binding.quorum_proof,
            "previous_decision_hash": self._last_decision_hash,
            "created_at": created_at,
        }
        signature = self.signer.sign(unsigned_payload)

        decision = DecisionRecord(
            decision_id=unsigned_payload["decision_id"],
            trace_id=unsigned_payload["trace_id"],
            action=unsigned_payload["action"],
            resource=unsigned_payload["resource"],
            mutation_class=binding.mutation_class,
            outcome=outcome,
            reason=reason,
            policy_evaluation_id=unsigned_payload["policy_evaluation_id"],
            binding_id=unsigned_payload["binding_id"],
            capability_token_id=unsigned_payload["capability_token_id"],
            governance_context_hash=(
                unsigned_payload["governance_context_hash"]
            ),
            resolution_policy=unsigned_payload["resolution_policy"],
            quorum_proof=unsigned_payload["quorum_proof"],
            previous_decision_hash=unsigned_payload["previous_decision_hash"],
            created_at=created_at,
            signature=signature,
        )

        self._decisions[decision.decision_id] = decision
        self._last_decision_hash = sha256_hex(decision)
        self.journal.append("decision_record", binding.trace_id, decision)
        return decision

    def _record_audit(
        self,
        decision: DecisionRecord,
        event_type: str,
        details: dict[str, Any],
    ) -> None:
        event = AuditEvent(
            event_id=new_id("audit"),
            trace_id=decision.trace_id,
            decision_id=decision.decision_id,
            event_type=event_type,
            severity=(
                "info"
                if decision.outcome != DecisionOutcome.DENIED
                else "warn"
            ),
            details=details,
        )
        self.journal.append("audit_event", decision.trace_id, event)
