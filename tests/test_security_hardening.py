from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sovereign_ide.airgap import AirgapBundleGuard  # noqa: E402
from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.federation import (  # noqa: E402
    ArtifactExchangeRequest,
    FederatedArtifactLedger,
    FederatedLedgerIntegrityError,
    FederationPolicyEngine,
    TrustDomainExchangeRule,
)
from sovereign_ide.governance import (  # noqa: E402
    GovernanceError,
    GovernanceRuntime,
    HashChainJournal,
    HMACDecisionSigner,
    JournalIntegrityError,
    PolicyEngine,
    PolicyViolation,
)
from sovereign_ide.models import (  # noqa: E402
    CapabilityToken,
    DecisionOutcome,
    GovernanceContext,
    MutationClass,
    PolicyEvaluationRequest,
    canonical_json,
    new_id,
    utc_now,
)
from sovereign_ide.supply_chain import (  # noqa: E402
    ArtifactType,
    PromotionTier,
    SupplyChainRegistry,
)
from sovereign_ide.validation import (  # noqa: E402
    ValidationError,
    validate_readiness_contract,
)


class GovernanceHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.journal_path = self.root / "governance_journal.jsonl"
        self.signing_key = "a" * 64

        self.policy = {
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
            "workspace": {"allowed_roots": [str(self.root)]},
            "risk_scores": {
                "read": 10,
                "softMutation": 35,
                "hardMutation": 70,
                "governanceMutation": 90,
            },
            "actions": {
                "apply_patch": {
                    "required_mutation_class": "hardMutation",
                    "allowed_roles": ["developer", "reviewer"],
                    "quorum_required": True,
                },
                "run_tests": {
                    "required_mutation_class": "softMutation",
                    "allowed_roles": ["developer", "reviewer"],
                    "quorum_required": False,
                },
                "compensate:apply_patch": {
                    "required_mutation_class": "governanceMutation",
                    "allowed_roles": ["incident_responder"],
                    "quorum_required": False,
                },
            },
        }

        self.runtime = GovernanceRuntime(
            policy_engine=PolicyEngine(self.policy),
            journal=HashChainJournal(self.journal_path),
            signer=HMACDecisionSigner(self.signing_key),
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _context(
        self,
        *,
        actor: str = "dev1",
        roles: tuple[str, ...] = ("developer",),
    ) -> GovernanceContext:
        return GovernanceContext(
            trace_id=new_id("trace"),
            actor_id=actor,
            actor_roles=roles,
            tenant="tenant1",
            trust_domain="domain1",
            workspace_root=str(self.root),
            classification="confidential",
            policy_pack_version="1.0.0",
        )

    def _token(
        self,
        actor: str,
        scopes: tuple[str, ...],
    ) -> CapabilityToken:
        return CapabilityToken(
            token_id=new_id("token"),
            subject=actor,
            scopes=scopes,
            trust_domain="domain1",
            issued_at=utc_now(),
            expires_at="2999-01-01T00:00:00+00:00",
            revoked=False,
        )

    def _bound_mutation(
        self,
        *,
        context: GovernanceContext,
        action: str,
        resource: str,
        mutation_class: MutationClass,
        token: CapabilityToken,
        quorum_proof: str | None,
    ):
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
        return request, evaluation, eval_binding, mutation_binding

    def _approved_apply_patch_decision(self) -> str:
        context = self._context(actor="dev1", roles=("developer",))
        token = self._token("dev1", ("apply_patch",))
        _, _, _, binding = self._bound_mutation(
            context=context,
            action="apply_patch",
            resource=str(self.root / "src" / "mod.py"),
            mutation_class=MutationClass.HARD_MUTATION,
            token=token,
            quorum_proof="quorum-proof",
        )
        result = self.runtime.commit_mutation(
            binding,
            lambda: {"status": "applied"},
        )
        self.assertTrue(result.applied)
        self.assertEqual(result.decision.outcome, DecisionOutcome.APPROVED)
        return result.decision.decision_id

    def test_policy_rejects_workspace_prefix_escape_path(self) -> None:
        context = self._context(actor="dev1", roles=("developer",))
        token = self._token("dev1", ("run_tests",))

        _, _, _, binding = self._bound_mutation(
            context=context,
            action="run_tests",
            resource=str(Path(str(self.root) + "-escape") / "outside.py"),
            mutation_class=MutationClass.SOFT_MUTATION,
            token=token,
            quorum_proof=None,
        )

        result = self.runtime.commit_mutation(
            binding,
            lambda: {"status": "applied"},
        )
        self.assertFalse(result.applied)
        self.assertEqual(result.decision.outcome, DecisionOutcome.DENIED)
        self.assertIn("resource_outside_allowed_roots", result.decision.reason)

    def test_commit_rejects_binding_request_action_mismatch(self) -> None:
        context = self._context(actor="dev1", roles=("developer",))
        token = self._token("dev1", ("run_tests", "apply_patch"))

        _, evaluation, eval_binding, _ = self._bound_mutation(
            context=context,
            action="run_tests",
            resource=str(self.root / "src" / "inside.py"),
            mutation_class=MutationClass.SOFT_MUTATION,
            token=token,
            quorum_proof=None,
        )

        mismatched_binding = self.runtime.build_mutation_binding(
            context=context,
            action="apply_patch",
            resource=str(self.root / "src" / "inside.py"),
            mutation_class=MutationClass.SOFT_MUTATION,
            capability_token=token,
            evaluation=evaluation,
            binding=eval_binding,
            resolution_policy=(
                "invariants>immutableDecisionRecord>policyEvaluation>"
                "capabilityToken>runtimeConfiguration>operatorOverride"
            ),
            quorum_proof=None,
        )

        with self.assertRaises(GovernanceError):
            self.runtime.commit_mutation(
                mismatched_binding,
                lambda: {"status": "should-never-apply"},
            )

    def test_compensation_side_effects_do_not_run_before_policy(self) -> None:
        target_decision_id = self._approved_apply_patch_decision()

        side_effect = {"executed": False}

        def _compensate() -> dict[str, bool]:
            side_effect["executed"] = True
            return {"ok": True}

        denied_context = self._context(
            actor="dev1",
            roles=("developer",),
        )

        with self.assertRaises(PolicyViolation):
            self.runtime.compensate(
                target_decision_id=target_decision_id,
                context=denied_context,
                reason="unauthorized-compensation-attempt",
                compensate_fn=_compensate,
            )

        self.assertFalse(side_effect["executed"])

    def test_journal_hash_chain_tamper_is_detected(self) -> None:
        self._approved_apply_patch_decision()

        lines = [
            json.loads(line)
            for line in self.journal_path.read_text(
                encoding="utf-8",
            ).splitlines()
            if line.strip()
        ]
        lines[0]["entry_hash"] = "tampered"
        self.journal_path.write_text(
            "\n".join(json.dumps(entry) for entry in lines) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(JournalIntegrityError):
            HashChainJournal(self.journal_path)

    def test_decision_signature_tamper_is_detected(self) -> None:
        self._approved_apply_patch_decision()

        entries = [
            json.loads(line)
            for line in self.journal_path.read_text(
                encoding="utf-8",
            ).splitlines()
            if line.strip()
        ]

        for entry in entries:
            if entry.get("record_type") == "decision_record":
                entry["payload"]["signature"]["signature"] = "tampered"
                break

        previous_hash = None
        for sequence, entry in enumerate(entries, start=1):
            entry["sequence"] = sequence
            entry["previous_hash"] = previous_hash
            hash_input = dict(entry)
            hash_input.pop("entry_hash", None)
            entry["entry_hash"] = hashlib.sha256(
                canonical_json(hash_input).encode("utf-8"),
            ).hexdigest()
            previous_hash = entry["entry_hash"]

        self.journal_path.write_text(
            "\n".join(json.dumps(entry) for entry in entries) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(JournalIntegrityError):
            GovernanceRuntime(
                policy_engine=PolicyEngine(self.policy),
                journal=HashChainJournal(self.journal_path),
                signer=HMACDecisionSigner(self.signing_key),
            )


class FederationAndAirgapHardeningTests(unittest.TestCase):
    def test_federation_denies_unknown_classification(self) -> None:
        engine = FederationPolicyEngine(
            trusted_domains=("d1", "d2"),
            rules=(TrustDomainExchangeRule("d1", "d2", "confidential"),),
        )
        request = ArtifactExchangeRequest(
            exchange_id=new_id("exchange"),
            trace_id=new_id("trace"),
            source_domain="d1",
            target_domain="d2",
            artifact_id="artifact-1",
            artifact_type="model",
            classification="ultra-secret-unknown",
            exportable=True,
            requested_by="operator",
            requested_at=utc_now(),
        )

        decision = engine.evaluate(request, trust_bundle_fresh=True)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_classification")

    def test_airgap_valid_hmac_manifest_passes(self) -> None:
        signing_key = "shared-hmac-key-for-tests"
        guard = AirgapBundleGuard(
            allowed_source_domains=("enterprise-connected",),
            allowed_target_domains=("airgap-enclave",),
            trusted_hmac_keys={"release_authority": signing_key},
        )

        raw = {
            "manifestVersion": "1.0.0",
            "bundleId": "bundle-test-001",
            "sourceDomain": "enterprise-connected",
            "targetDomain": "airgap-enclave",
            "createdAt": "2026-04-28T00:00:00+00:00",
            "classification": "confidential",
            "items": [
                {
                    "artifactId": "artifact-1",
                    "artifactType": "model",
                    "checksum": "sha256:" + ("a" * 64),
                    "provenanceRef": "attestation:artifact-1",
                    "promotionTier": "sovereign-approved",
                }
            ],
            "signatures": [],
            "approval": {
                "approvedBy": ["enclave_operator", "trust_administrator"],
                "decisionRecordId": "decision_1",
            },
        }

        unsigned_manifest = guard._from_raw(raw)
        payload = guard._signed_manifest_payload(unsigned_manifest).encode(
            "utf-8",
        )
        signature = base64.b64encode(
            hmac.new(
                signing_key.encode("utf-8"),
                payload,
                hashlib.sha256,
            ).digest(),
        ).decode("utf-8")

        raw["signatures"] = [
            {
                "signer": "release_authority",
                "algorithm": "hmac-sha256",
                "signature": signature,
            }
        ]

        manifest = guard._from_raw(raw)
        result = guard.validate_manifest(
            manifest,
            trust_bundle_fresh=True,
            scanner_attested=True,
        )
        self.assertTrue(result.valid, msg=result.errors)

    def test_airgap_invalid_checksum_is_rejected(self) -> None:
        guard = AirgapBundleGuard(
            allowed_source_domains=("enterprise-connected",),
            allowed_target_domains=("airgap-enclave",),
            trusted_hmac_keys={"release_authority": "key"},
        )

        raw = {
            "manifestVersion": "1.0.0",
            "bundleId": "bundle-test-002",
            "sourceDomain": "enterprise-connected",
            "targetDomain": "airgap-enclave",
            "createdAt": "2026-04-28T00:00:00+00:00",
            "classification": "confidential",
            "items": [
                {
                    "artifactId": "artifact-2",
                    "artifactType": "model",
                    "checksum": "sha256:abcd",
                    "provenanceRef": "attestation:artifact-2",
                    "promotionTier": "sovereign-approved",
                }
            ],
            "signatures": [
                {
                    "signer": "release_authority",
                    "algorithm": "hmac-sha256",
                    "signature": base64.b64encode(
                        b"not-valid",
                    ).decode("utf-8"),
                }
            ],
            "approval": {
                "approvedBy": ["enclave_operator", "trust_administrator"],
                "decisionRecordId": "decision_2",
            },
        }

        manifest = guard._from_raw(raw)
        result = guard.validate_manifest(
            manifest,
            trust_bundle_fresh=True,
            scanner_attested=True,
        )
        self.assertFalse(result.valid)
        self.assertTrue(
            any(
                issue.startswith("invalid_checksum_format:")
                for issue in result.errors
            ),
        )


class SettingsHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        get_settings.cache_clear()

    def tearDown(self) -> None:
        get_settings.cache_clear()

    def test_placeholder_signing_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "\n".join(
                    [
                        (
                            "SOVEREIGN_SIGNING_KEY="
                            "REPLACE_WITH_64_BYTE_HEX_OR_HIGH_ENTROPY_SECRET"
                        ),
                        "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                        "SOVEREIGN_STATE_DIR=state",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    get_settings(root)

    def test_valid_signing_key_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "\n".join(
                    [
                        f"SOVEREIGN_SIGNING_KEY={'b' * 64}",
                        "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                        "SOVEREIGN_STATE_DIR=state",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {}, clear=True):
                settings = get_settings(root)
                self.assertEqual(settings.workspace_root, root.resolve())
                self.assertEqual(settings.signing_key, "b" * 64)


class ArtifactValidationHardeningTests(unittest.TestCase):
    def test_policy_placeholder_renders_to_current_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            policy_path = root / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "version": "1.0.0",
                        "resolution": {
                            "default": "deny",
                            "precedence": ["invariants"],
                        },
                        "workspace": {
                            "allowed_roots": [
                                "${SOVEREIGN_WORKSPACE_ROOT}",
                            ],
                        },
                        "risk_scores": {
                            "read": 10,
                            "softMutation": 35,
                            "hardMutation": 70,
                            "governanceMutation": 90,
                        },
                        "actions": {
                            "run_tests": {
                                "required_mutation_class": "softMutation",
                                "allowed_roles": ["developer"],
                                "quorum_required": False,
                            },
                        },
                    },
                ),
                encoding="utf-8",
            )

            engine = PolicyEngine.from_path(policy_path, workspace_root=root)
            context = GovernanceContext(
                trace_id=new_id("trace"),
                actor_id="dev1",
                actor_roles=("developer",),
                tenant="tenant1",
                trust_domain="domain1",
                workspace_root=str(root),
                classification="confidential",
                policy_pack_version="1.0.0",
            )
            token = CapabilityToken(
                token_id=new_id("token"),
                subject="dev1",
                scopes=("run_tests",),
                trust_domain="domain1",
                issued_at=utc_now(),
                expires_at="2999-01-01T00:00:00+00:00",
                revoked=False,
            )
            request = PolicyEvaluationRequest(
                request_id=new_id("request"),
                trace_id=context.trace_id,
                action="run_tests",
                resource=str(root / "inside.py"),
                mutation_class=MutationClass.SOFT_MUTATION,
                requested_by="dev1",
            )

            evaluation = engine.evaluate(request, context, token)
            self.assertTrue(evaluation.allowed, msg=evaluation.denial_reasons)

    def test_readiness_contract_forbids_runtime_production_claims(self) -> None:
        contract = {
            "version": "1.0.0",
            "readiness_levels": {
                "runtime": {
                    "description": "local service checks",
                    "claims_allowed": ["runtime ready"],
                    "claims_forbidden": ["production ready"],
                },
                "production": {
                    "description": "deployment release checks",
                    "required_evidence": ["release manifest"],
                    "claims_allowed": ["production deployment ready"],
                },
            },
        }

        validate_readiness_contract(contract)

    def test_readiness_contract_rejects_soft_runtime_claims(self) -> None:
        contract = {
            "version": "1.0.0",
            "readiness_levels": {
                "runtime": {
                    "description": "local service checks",
                    "claims_allowed": ["ready"],
                    "claims_forbidden": ["maybe later"],
                },
                "production": {
                    "description": "deployment release checks",
                    "required_evidence": ["release manifest"],
                    "claims_allowed": ["production deployment ready"],
                },
            },
        }

        with self.assertRaises(ValidationError):
            validate_readiness_contract(contract)

    def test_federation_ledger_hash_chain_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "federation.jsonl"
            ledger = FederatedArtifactLedger(ledger_path)
            request = ArtifactExchangeRequest(
                exchange_id=new_id("exchange"),
                trace_id=new_id("trace"),
                source_domain="d1",
                target_domain="d2",
                artifact_id="artifact-1",
                artifact_type="model",
                classification="confidential",
                exportable=True,
                requested_by="operator",
                requested_at=utc_now(),
            )
            decision = FederationPolicyEngine(
                trusted_domains=("d1", "d2"),
                rules=(TrustDomainExchangeRule("d1", "d2", "confidential"),),
            ).evaluate(request, trust_bundle_fresh=True)
            ledger.append(request, decision)

            entries = [
                json.loads(line)
                for line in ledger_path.read_text(
                    encoding="utf-8",
                ).splitlines()
                if line.strip()
            ]
            entries[0]["payload"]["decision"]["reason"] = "tampered"
            ledger_path.write_text(
                "\n".join(json.dumps(entry) for entry in entries) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(FederatedLedgerIntegrityError):
                FederatedArtifactLedger(ledger_path)


class SupplyChainEvidenceHardeningTests(unittest.TestCase):
    def test_promotion_requires_bound_evidence_not_just_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = SupplyChainRegistry(Path(tmp) / "supply_chain.json")
            registry.register_candidate(
                artifact_id="artifact-1",
                artifact_type=ArtifactType.EXTENSION,
                publisher="publisher",
                checksum="a" * 64,
                signature_verified=True,
                static_scan_passed=True,
                dependency_scan_passed=True,
                provenance_verified=False,
                airgap_manifest_approved=False,
            )

            with self.assertRaisesRegex(ValueError, "evidence_missing"):
                registry.promote(
                    artifact_id="artifact-1",
                    target_tier=PromotionTier.ENTERPRISE_REVIEWED,
                    decision_record_id="decision_1",
                    reason="no evidence bound",
                    attested_workload=False,
                )

    def test_promotion_passes_with_required_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = SupplyChainRegistry(Path(tmp) / "supply_chain.json")
            registry.register_candidate(
                artifact_id="artifact-1",
                artifact_type=ArtifactType.EXTENSION,
                publisher="publisher",
                checksum="a" * 64,
                signature_verified=True,
                static_scan_passed=True,
                dependency_scan_passed=True,
                provenance_verified=False,
                airgap_manifest_approved=False,
            )
            for evidence_type in (
                "signature",
                "static_scan",
                "dependency_scan",
            ):
                registry.register_evidence(
                    artifact_id="artifact-1",
                    evidence_type=evidence_type,
                    passed=True,
                    evidence_ref=f"evidence://{evidence_type}/artifact-1",
                )

            promoted = registry.promote(
                artifact_id="artifact-1",
                target_tier=PromotionTier.ENTERPRISE_REVIEWED,
                decision_record_id="decision_1",
                reason="evidence bound",
                attested_workload=False,
            )

            self.assertEqual(
                promoted.current_tier,
                PromotionTier.ENTERPRISE_REVIEWED.value,
            )


if __name__ == "__main__":
    unittest.main()
