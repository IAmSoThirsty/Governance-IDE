from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
from pathlib import Path
import json
import re
from typing import Any, Callable

from .models import new_id, utc_now


ALLOWED_SIGNATURE_ALGORITHMS = {
    "ed25519",
    "rsa-pss-sha256",
    "ecdsa-p256-sha256",
    "hmac-sha256",
}
ALLOWED_CLASSIFICATIONS = {"internal", "confidential", "secret", "sovereign"}
SHA256_CHECKSUM_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class TransferItem:
    artifact_id: str
    artifact_type: str
    checksum: str
    provenance_ref: str
    promotion_tier: str


@dataclass(frozen=True)
class TransferSignature:
    signer: str
    algorithm: str
    signature: str


@dataclass(frozen=True)
class TransferApproval:
    approved_by: tuple[str, ...]
    decision_record_id: str


@dataclass(frozen=True)
class TransferManifest:
    manifest_version: str
    bundle_id: str
    source_domain: str
    target_domain: str
    created_at: str
    classification: str
    items: tuple[TransferItem, ...]
    signatures: tuple[TransferSignature, ...]
    approval: TransferApproval


@dataclass(frozen=True)
class ManifestValidationResult:
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


class AirgapBundleGuard:
    """Validates and ingests signed transfer bundles for disconnected tiers."""

    def __init__(
        self,
        allowed_source_domains: tuple[str, ...],
        allowed_target_domains: tuple[str, ...],
        trusted_hmac_keys: dict[str, str] | None = None,
        required_approver_roles: tuple[str, ...] = (
            "enclave_operator",
            "trust_administrator",
        ),
        external_signature_verifier: (
            Callable[[TransferManifest, TransferSignature], bool] | None
        ) = None,
    ) -> None:
        self.allowed_source_domains = set(allowed_source_domains)
        self.allowed_target_domains = set(allowed_target_domains)
        self.trusted_hmac_keys = trusted_hmac_keys or {}
        self.required_approver_roles = set(required_approver_roles)
        self.external_signature_verifier = external_signature_verifier

    def load_manifest(self, manifest_file: str | Path) -> TransferManifest:
        raw = json.loads(Path(manifest_file).read_text(encoding="utf-8"))
        return self._from_raw(raw)

    def validate_manifest(
        self,
        manifest: TransferManifest,
        trust_bundle_fresh: bool,
        scanner_attested: bool,
    ) -> ManifestValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        if manifest.manifest_version != "1.0.0":
            errors.append("unsupported_manifest_version")

        if not manifest.bundle_id:
            errors.append("bundle_id_missing")

        if not manifest.created_at:
            errors.append("created_at_missing")
        else:
            try:
                _ = datetime.fromisoformat(
                    manifest.created_at.replace("Z", "+00:00"),
                )
            except ValueError:
                errors.append("created_at_invalid_isoformat")

        if manifest.source_domain not in self.allowed_source_domains:
            errors.append("source_domain_not_allowed")

        if manifest.target_domain not in self.allowed_target_domains:
            errors.append("target_domain_not_allowed")

        if manifest.classification not in ALLOWED_CLASSIFICATIONS:
            errors.append("invalid_classification")

        if not trust_bundle_fresh:
            errors.append("trust_bundle_not_fresh")

        if not scanner_attested:
            errors.append("scanner_not_attested")

        if not manifest.signatures:
            errors.append("missing_signatures")

        seen_signers: set[str] = set()
        signed_payload = self._signed_manifest_payload(manifest).encode(
            "utf-8",
        )

        for signature in manifest.signatures:
            if signature.algorithm not in ALLOWED_SIGNATURE_ALGORITHMS:
                errors.append("unsupported_signature_algorithm")
            if not signature.signer:
                errors.append("missing_signature_signer")
            if signature.signer in seen_signers:
                errors.append("duplicate_signature_signer")
            seen_signers.add(signature.signer)

            try:
                signature_bytes = base64.b64decode(
                    signature.signature.strip(),
                    validate=True,
                )
            except (ValueError, binascii.Error):
                errors.append(
                    f"signature_payload_invalid_base64:{signature.signer}",
                )
                continue

            if not signature_bytes:
                errors.append(
                    f"signature_payload_empty:{signature.signer}",
                )
                continue

            if not self._verify_signature(
                manifest,
                signature,
                signature_bytes,
                signed_payload,
            ):
                errors.append(
                    f"signature_verification_failed:{signature.signer}",
                )

        if not manifest.items:
            errors.append("bundle_items_missing")

        seen_artifact_ids: set[str] = set()

        for item in manifest.items:
            if item.artifact_id in seen_artifact_ids:
                errors.append(f"duplicate_artifact_id:{item.artifact_id}")
            seen_artifact_ids.add(item.artifact_id)

            if not SHA256_CHECKSUM_PATTERN.match(item.checksum):
                errors.append(f"invalid_checksum_format:{item.artifact_id}")
            if not item.provenance_ref:
                errors.append(f"missing_provenance_ref:{item.artifact_id}")
            if not item.promotion_tier:
                errors.append(f"missing_promotion_tier:{item.artifact_id}")

        approvers = set(manifest.approval.approved_by)
        if not self.required_approver_roles.issubset(approvers):
            errors.append("required_approvers_missing")

        if not manifest.approval.decision_record_id:
            errors.append("approval_decision_record_missing")

        if manifest.classification == "sovereign" and len(manifest.items) < 2:
            warnings.append("single_item_sovereign_bundle")

        return ManifestValidationResult(
            valid=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    def ingest_manifest(
        self,
        manifest: TransferManifest,
        mirror_index_path: str | Path,
        trust_bundle_fresh: bool,
        scanner_attested: bool,
    ) -> dict[str, Any]:
        result = self.validate_manifest(
            manifest,
            trust_bundle_fresh=trust_bundle_fresh,
            scanner_attested=scanner_attested,
        )
        if not result.valid:
            raise ValueError(
                "manifest validation failed: " + ";".join(result.errors),
            )

        mirror_path = Path(mirror_index_path)
        mirror_path.parent.mkdir(parents=True, exist_ok=True)
        if mirror_path.exists():
            state = json.loads(mirror_path.read_text(encoding="utf-8"))
        else:
            state = {"bundles": []}

        record = {
            "ingest_id": new_id("ingest"),
            "recorded_at": utc_now(),
            "bundle_id": manifest.bundle_id,
            "source_domain": manifest.source_domain,
            "target_domain": manifest.target_domain,
            "classification": manifest.classification,
            "item_count": len(manifest.items),
            "approval_decision_record_id": (manifest.approval.decision_record_id),
        }
        state["bundles"].append(record)
        mirror_path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return record

    @staticmethod
    def _signed_manifest_payload(manifest: TransferManifest) -> str:
        payload = {
            "manifestVersion": manifest.manifest_version,
            "bundleId": manifest.bundle_id,
            "sourceDomain": manifest.source_domain,
            "targetDomain": manifest.target_domain,
            "createdAt": manifest.created_at,
            "classification": manifest.classification,
            "items": [
                {
                    "artifactId": item.artifact_id,
                    "artifactType": item.artifact_type,
                    "checksum": item.checksum,
                    "provenanceRef": item.provenance_ref,
                    "promotionTier": item.promotion_tier,
                }
                for item in manifest.items
            ],
            "approval": {
                "approvedBy": list(manifest.approval.approved_by),
                "decisionRecordId": manifest.approval.decision_record_id,
            },
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def _verify_signature(
        self,
        manifest: TransferManifest,
        signature: TransferSignature,
        signature_bytes: bytes,
        signed_payload: bytes,
    ) -> bool:
        if signature.algorithm == "hmac-sha256":
            key_material = self.trusted_hmac_keys.get(signature.signer)
            if not key_material:
                return False

            expected = hmac.new(
                key_material.encode("utf-8"),
                signed_payload,
                hashlib.sha256,
            ).digest()
            return hmac.compare_digest(expected, signature_bytes)

        if self.external_signature_verifier is None:
            return False

        try:
            return bool(self.external_signature_verifier(manifest, signature))
        except Exception:  # noqa: BLE001
            return False

    def _from_raw(self, raw: dict[str, Any]) -> TransferManifest:
        items = tuple(
            TransferItem(
                artifact_id=item["artifactId"],
                artifact_type=item["artifactType"],
                checksum=item["checksum"],
                provenance_ref=item["provenanceRef"],
                promotion_tier=item["promotionTier"],
            )
            for item in raw.get("items", [])
        )
        signatures = tuple(
            TransferSignature(
                signer=item["signer"],
                algorithm=item["algorithm"],
                signature=item["signature"],
            )
            for item in raw.get("signatures", [])
        )
        approval_raw = raw.get("approval", {})
        approval = TransferApproval(
            approved_by=tuple(approval_raw.get("approvedBy", [])),
            decision_record_id=str(approval_raw.get("decisionRecordId", "")),
        )

        return TransferManifest(
            manifest_version=str(raw.get("manifestVersion", "")),
            bundle_id=str(raw.get("bundleId", "")),
            source_domain=str(raw.get("sourceDomain", "")),
            target_domain=str(raw.get("targetDomain", "")),
            created_at=str(raw.get("createdAt", "")),
            classification=str(raw.get("classification", "")),
            items=items,
            signatures=signatures,
            approval=approval,
        )
