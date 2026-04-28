from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

from .models import new_id, utc_now


CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
    "sovereign": 4,
}


@dataclass(frozen=True)
class TrustDomainExchangeRule:
    source_domain: str
    target_domain: str
    max_classification: str
    allow_exportable_only: bool = True
    quorum_required: bool = True


@dataclass(frozen=True)
class ArtifactExchangeRequest:
    exchange_id: str
    trace_id: str
    source_domain: str
    target_domain: str
    artifact_id: str
    artifact_type: str
    classification: str
    exportable: bool
    requested_by: str
    requested_at: str


@dataclass(frozen=True)
class ArtifactExchangeDecision:
    decision_id: str
    exchange_id: str
    allowed: bool
    reason: str
    obligations: tuple[str, ...]
    evaluated_at: str


class FederationPolicyEngine:
    """Conservative default-deny evaluator for cross-domain exchange."""

    def __init__(
        self,
        trusted_domains: tuple[str, ...],
        rules: tuple[TrustDomainExchangeRule, ...],
    ) -> None:
        self.trusted_domains = set(trusted_domains)
        self.rules = rules

    def evaluate(
        self,
        request: ArtifactExchangeRequest,
        trust_bundle_fresh: bool,
    ) -> ArtifactExchangeDecision:
        obligations: list[str] = []

        if not trust_bundle_fresh:
            return self._deny(request, "trust_bundle_not_fresh")

        if request.source_domain not in self.trusted_domains:
            return self._deny(request, "source_domain_not_trusted")
        if request.target_domain not in self.trusted_domains:
            return self._deny(request, "target_domain_not_trusted")

        rule = self._find_rule(request.source_domain, request.target_domain)
        if rule is None:
            return self._deny(request, "no_exchange_rule_defined")

        if rule.allow_exportable_only and not request.exportable:
            return self._deny(request, "artifact_not_exportable")

        request_rank = CLASSIFICATION_ORDER.get(request.classification)
        if request_rank is None:
            return self._deny(request, "unknown_classification")

        max_rank = CLASSIFICATION_ORDER.get(rule.max_classification)
        if max_rank is None:
            return self._deny(request, "rule_invalid_max_classification")

        if request_rank > max_rank:
            return self._deny(request, "classification_exceeds_rule")

        if rule.quorum_required:
            obligations.append("quorum_proof_required")

        return ArtifactExchangeDecision(
            decision_id=new_id("federationDecision"),
            exchange_id=request.exchange_id,
            allowed=True,
            reason="exchange_allowed",
            obligations=tuple(obligations),
            evaluated_at=utc_now(),
        )

    def _find_rule(
        self,
        source_domain: str,
        target_domain: str,
    ) -> TrustDomainExchangeRule | None:
        for rule in self.rules:
            if (
                rule.source_domain == source_domain
                and rule.target_domain == target_domain
            ):
                return rule
        return None

    def _deny(
        self,
        request: ArtifactExchangeRequest,
        reason: str,
    ) -> ArtifactExchangeDecision:
        return ArtifactExchangeDecision(
            decision_id=new_id("federationDecision"),
            exchange_id=request.exchange_id,
            allowed=False,
            reason=reason,
            obligations=tuple(),
            evaluated_at=utc_now(),
        )


class FederatedArtifactLedger:
    """Append-only ledger for federation exchange requests and decisions."""

    def __init__(self, ledger_path: str | Path) -> None:
        self.path = Path(ledger_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._sequence = 0
        self._last_hash: str | None = None
        self._hydrate()

    def _hydrate(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            self._sequence = max(self._sequence, int(item.get("sequence", 0)))
            self._last_hash = item.get("entry_hash")

    def append(
        self,
        request: ArtifactExchangeRequest,
        decision: ArtifactExchangeDecision,
    ) -> dict[str, str | int | dict[str, str | bool | tuple[str, ...]]]:
        payload = {
            "request": {
                "exchange_id": request.exchange_id,
                "trace_id": request.trace_id,
                "source_domain": request.source_domain,
                "target_domain": request.target_domain,
                "artifact_id": request.artifact_id,
                "artifact_type": request.artifact_type,
                "classification": request.classification,
                "exportable": request.exportable,
                "requested_by": request.requested_by,
                "requested_at": request.requested_at,
            },
            "decision": {
                "decision_id": decision.decision_id,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "obligations": decision.obligations,
                "evaluated_at": decision.evaluated_at,
            },
        }

        entry = {
            "entry_id": new_id("federationLedger"),
            "sequence": self._sequence + 1,
            "recorded_at": utc_now(),
            "payload": payload,
            "previous_hash": self._last_hash,
        }
        digest = hashlib.sha256(
            json.dumps(
                entry,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        ).hexdigest()
        entry["entry_hash"] = digest

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self._sequence += 1
        self._last_hash = digest
        return entry

    def list_for_domain(
        self,
        trust_domain: str,
    ) -> list[dict[str, str | int | dict]]:
        entries: list[dict[str, str | int | dict]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            payload = entry.get("payload", {})
            request = payload.get("request", {})
            if (
                request.get("source_domain") == trust_domain
                or request.get("target_domain") == trust_domain
            ):
                entries.append(entry)
        return entries
