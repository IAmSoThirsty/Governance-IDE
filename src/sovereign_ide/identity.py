from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from .models import CapabilityToken, MutationClass, new_id


MUTATION_RANK = {
    MutationClass.READ: 0,
    MutationClass.SOFT_MUTATION: 1,
    MutationClass.HARD_MUTATION: 2,
    MutationClass.GOVERNANCE_MUTATION: 3,
}


class TrustDimension(str, Enum):
    IDENTITY_VALIDITY = "identity_validity"
    POSTURE_VALIDITY = "posture_validity"
    PROVENANCE_VALIDITY = "provenance_validity"
    POLICY_FRESHNESS = "policy_freshness"
    ATTESTATION_FRESHNESS = "attestation_freshness"


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class HumanIdentity:
    human_id: str
    roles: tuple[str, ...]
    tenant: str
    trust_domain: str
    active: bool = True


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    trust_domain: str
    attested: bool
    posture_state: str
    posture_valid_until: str


@dataclass(frozen=True)
class WorkloadIdentity:
    workload_id: str
    workload_type: str
    trust_domain: str
    attested: bool
    attestation_valid_until: str


@dataclass(frozen=True)
class TrustBundle:
    bundle_id: str
    trust_domain: str
    issuer: str
    issued_at: str
    expires_at: str
    policy_pack_version: str
    policy_valid_until: str
    posture_valid_until: str
    provenance_valid_until: str
    attestation_valid_until: str
    revoked: bool = False


@dataclass(frozen=True)
class TrustDimensionStatus:
    dimension: TrustDimension
    healthy: bool
    reason: str
    expires_at: str


@dataclass(frozen=True)
class TrustPosture:
    trust_domain: str
    bundle_id: str
    policy_pack_version: str
    evaluated_at: str
    dimensions: tuple[TrustDimensionStatus, ...]

    def dimension(self, item: TrustDimension) -> TrustDimensionStatus:
        for status in self.dimensions:
            if status.dimension == item:
                return status
        raise KeyError(f"unknown trust dimension: {item.value}")

    @property
    def healthy(self) -> bool:
        return all(status.healthy for status in self.dimensions)

    def degraded_dimensions(self) -> tuple[TrustDimensionStatus, ...]:
        return tuple(
            status for status in self.dimensions if not status.healthy
        )

    def max_allowed_mutation_class(self) -> MutationClass:
        identity = self.dimension(TrustDimension.IDENTITY_VALIDITY)
        provenance = self.dimension(TrustDimension.PROVENANCE_VALIDITY)
        policy = self.dimension(TrustDimension.POLICY_FRESHNESS)
        posture = self.dimension(TrustDimension.POSTURE_VALIDITY)
        attestation = self.dimension(TrustDimension.ATTESTATION_FRESHNESS)

        if (
            not identity.healthy
            or not provenance.healthy
            or not policy.healthy
        ):
            return MutationClass.READ
        if not posture.healthy or not attestation.healthy:
            return MutationClass.SOFT_MUTATION
        return MutationClass.GOVERNANCE_MUTATION

    def requires_reattestation(self, threshold_minutes: int = 30) -> bool:
        status = self.dimension(TrustDimension.ATTESTATION_FRESHNESS)
        expires = _parse_utc(status.expires_at)
        now = _parse_utc(self.evaluated_at)
        return (expires - now) <= timedelta(minutes=threshold_minutes)


class IdentityAuthority:
    """Issues and validates capability tokens under trust-decay controls."""

    def __init__(self, expected_policy_version: str) -> None:
        self.expected_policy_version = expected_policy_version

    def evaluate_trust_posture(
        self,
        bundle: TrustBundle,
        as_of: datetime | None = None,
    ) -> TrustPosture:
        now = as_of or _utc_now()

        identity_ok = (
            not bundle.revoked
            and now < _parse_utc(bundle.expires_at)
        )
        posture_ok = now < _parse_utc(bundle.posture_valid_until)
        provenance_ok = now < _parse_utc(bundle.provenance_valid_until)
        policy_ok = (
            bundle.policy_pack_version == self.expected_policy_version
            and now < _parse_utc(bundle.policy_valid_until)
        )
        attestation_ok = now < _parse_utc(bundle.attestation_valid_until)

        dimensions = (
            TrustDimensionStatus(
                dimension=TrustDimension.IDENTITY_VALIDITY,
                healthy=identity_ok,
                reason=(
                    "active"
                    if identity_ok
                    else "bundle_expired_or_revoked"
                ),
                expires_at=bundle.expires_at,
            ),
            TrustDimensionStatus(
                dimension=TrustDimension.POSTURE_VALIDITY,
                healthy=posture_ok,
                reason=("posture_fresh" if posture_ok else "posture_stale"),
                expires_at=bundle.posture_valid_until,
            ),
            TrustDimensionStatus(
                dimension=TrustDimension.PROVENANCE_VALIDITY,
                healthy=provenance_ok,
                reason=(
                    "provenance_fresh"
                    if provenance_ok
                    else "provenance_stale"
                ),
                expires_at=bundle.provenance_valid_until,
            ),
            TrustDimensionStatus(
                dimension=TrustDimension.POLICY_FRESHNESS,
                healthy=policy_ok,
                reason=(
                    "policy_fresh"
                    if policy_ok
                    else "policy_version_or_freshness_violation"
                ),
                expires_at=bundle.policy_valid_until,
            ),
            TrustDimensionStatus(
                dimension=TrustDimension.ATTESTATION_FRESHNESS,
                healthy=attestation_ok,
                reason=(
                    "attestation_fresh"
                    if attestation_ok
                    else "attestation_stale"
                ),
                expires_at=bundle.attestation_valid_until,
            ),
        )

        return TrustPosture(
            trust_domain=bundle.trust_domain,
            bundle_id=bundle.bundle_id,
            policy_pack_version=bundle.policy_pack_version,
            evaluated_at=now.isoformat(),
            dimensions=dimensions,
        )

    def issue_capability_token(
        self,
        actor_id: str,
        scopes: tuple[str, ...],
        trust_posture: TrustPosture,
        requested_mutation_class: MutationClass,
        ttl_minutes: int = 15,
    ) -> CapabilityToken:
        if not trust_posture.dimension(
            TrustDimension.IDENTITY_VALIDITY,
        ).healthy:
            raise PermissionError("identity dimension is not healthy")

        max_allowed = trust_posture.max_allowed_mutation_class()
        if (
            MUTATION_RANK[requested_mutation_class]
            > MUTATION_RANK[max_allowed]
        ):
            raise PermissionError(
                "requested mutation class exceeds trust posture allowance",
            )

        now = _utc_now()
        max_expiry_candidates = [
            _parse_utc(status.expires_at)
            for status in trust_posture.dimensions
            if status.healthy
        ]
        posture_cap = (
            min(max_expiry_candidates)
            if max_expiry_candidates
            else now
        )
        requested_expiry = now + timedelta(minutes=max(ttl_minutes, 1))
        expires_at = min(requested_expiry, posture_cap)

        return CapabilityToken(
            token_id=new_id("token"),
            subject=actor_id,
            scopes=scopes,
            trust_domain=trust_posture.trust_domain,
            issued_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            revoked=False,
        )

    def validate_capability_token(
        self,
        token: CapabilityToken,
        required_scope: str,
        trust_domain: str,
        at_time: datetime | None = None,
    ) -> bool:
        timestamp = (at_time or _utc_now()).isoformat()
        if not token.is_active(timestamp):
            return False
        if required_scope not in token.scopes:
            return False
        if token.trust_domain != trust_domain:
            return False
        return True
