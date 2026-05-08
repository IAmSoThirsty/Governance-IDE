from __future__ import annotations

from contextlib import redirect_stdout
import io
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

from sovereign_ide.cli import build_parser  # noqa: E402
from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.governance import (  # noqa: E402
    SQLiteEventJournal,
    build_decision_signer,
)
from sovereign_ide.model_registry import GovernedModelRegistry  # noqa: E402
from sovereign_ide.service import verify_execution_ticket  # noqa: E402


def _write_policy(root: Path) -> None:
    policies = root / "policies"
    policies.mkdir(parents=True, exist_ok=True)
    (policies / "baseline_policy.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "resolution": {"default": "deny", "precedence": ["invariants"]},
                "workspace": {"allowed_roots": ["${SOVEREIGN_WORKSPACE_ROOT}"]},
                "risk_scores": {
                    "read": 10,
                    "softMutation": 35,
                    "hardMutation": 70,
                    "governanceMutation": 90,
                },
                "actions": {
                    "register_model": {
                        "required_mutation_class": "governanceMutation",
                        "allowed_roles": ["model_steward"],
                        "quorum_required": True,
                    },
                    "execute_model": {
                        "required_mutation_class": "read",
                        "allowed_roles": ["model_steward"],
                        "quorum_required": False,
                    },
                },
            },
        ),
        encoding="utf-8",
    )


class ModelRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        _write_policy(self.root)
        (self.root / ".env").write_text(
            "\n".join(
                [
                    f"SOVEREIGN_SIGNING_KEY={'f' * 64}",
                    "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                    "SOVEREIGN_STATE_DIR=state",
                    "SOVEREIGN_JOURNAL_BACKEND=sqlite",
                ],
            ),
            encoding="utf-8",
        )
        self.model_path = self.root / "model.bin"
        self.model_path.write_text("weights", encoding="utf-8")
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        get_settings.cache_clear()

    def tearDown(self) -> None:
        get_settings.cache_clear()
        self.env_patch.stop()
        self.temp_dir.cleanup()

    def _run_cli(self, args: list[str]) -> dict:
        code, payload = self._run_cli_with_exit(args)
        self.assertEqual(code, 0)
        return payload

    def _run_cli_with_exit(self, args: list[str]) -> tuple[int, dict]:
        parser = build_parser()
        parsed = parser.parse_args(args)
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = int(parsed.func(parsed))
        return exit_code, json.loads(output.getvalue())

    def _register_local_model(
        self,
        registry: GovernedModelRegistry,
        *,
        immutable_identifier: str | None = None,
    ):
        return registry.register(
            source_type="local_path",
            source=str(self.model_path),
            license="test-license",
            content_hash=GovernedModelRegistry.hash_local_path(self.model_path),
            immutable_identifier=immutable_identifier,
            metadata={"family": "unit-test"},
            trust_level="reviewed",
            policy_profile="default-model-policy",
            provenance_ref="provenance://model.bin",
        )

    def test_model_register_list_and_execution_ticket_are_governed(self) -> None:
        registered = self._run_cli(
            [
                "model-register",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--source-type",
                "local_path",
                "--source",
                str(self.model_path),
                "--license",
                "test-license",
                "--trust-level",
                "reviewed",
                "--policy-profile",
                "default-model-policy",
                "--provenance-ref",
                "provenance://model.bin",
                "--quorum-proof",
                "model-registration-quorum",
            ],
        )
        self.assertEqual(registered["decision"]["outcome"], "approved")
        model_id = registered["payload"]["model"]["model_id"]
        self.assertEqual(
            registered["payload"]["model"]["source_type"],
            "local_path",
        )
        self.assertIsNotNone(registered["payload"]["model"]["signature"])

        listed = self._run_cli(["models-list", "--workspace-root", str(self.root)])
        self.assertEqual(listed["models"][0]["model_id"], model_id)

        ticket = self._run_cli(
            [
                "model-execution-ticket",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--model-id",
                model_id,
            ],
        )
        self.assertTrue(ticket["allowed"])
        self.assertEqual(ticket["reason"], "ok")
        self.assertEqual(len(ticket["governance_decision_hash"]), 64)
        self.assertEqual(ticket["decision"]["outcome"], "approved")
        self.assertEqual(
            ticket["payload"]["status"],
            "governed_execution_authorized",
        )
        execution_ticket = ticket["payload"]["execution_ticket"]
        for field in (
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
        ):
            self.assertIn(field, execution_ticket)
        self.assertEqual(execution_ticket["model_id"], model_id)

        signer = build_decision_signer(get_settings(self.root))
        valid, reason = verify_execution_ticket(execution_ticket, signer)
        self.assertTrue(valid, msg=reason)

    def test_cli_execution_ticket_unknown_model_denied_with_reason(self) -> None:
        exit_code, payload = self._run_cli_with_exit(
            [
                "model-execution-ticket",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--model-id",
                "does-not-exist",
            ],
        )
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["reason"], "unknown_model")

    def test_cli_execution_ticket_invalid_signer_configuration_denied(self) -> None:
        (self.root / ".env").write_text(
            "\n".join(
                [
                    f"SOVEREIGN_SIGNING_KEY={'f' * 64}",
                    "SOVEREIGN_RUNTIME_MODE=production",
                    "SOVEREIGN_SIGNER_BACKEND=hmac-dev",
                    "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                    "SOVEREIGN_STATE_DIR=state",
                    "SOVEREIGN_JOURNAL_BACKEND=sqlite",
                ],
            ),
            encoding="utf-8",
        )
        get_settings.cache_clear()

        exit_code, payload = self._run_cli_with_exit(
            [
                "model-execution-ticket",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--model-id",
                "model-any",
            ],
        )
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["allowed"])
        self.assertTrue(
            payload["reason"].startswith("invalid_signer_configuration:"),
        )

    def test_cli_ticket_inspect_rejects_tampered_and_expired(self) -> None:
        registered = self._run_cli(
            [
                "model-register",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--source-type",
                "local_path",
                "--source",
                str(self.model_path),
                "--license",
                "test-license",
                "--trust-level",
                "reviewed",
                "--policy-profile",
                "default-model-policy",
                "--provenance-ref",
                "provenance://model.bin",
                "--quorum-proof",
                "model-registration-quorum",
            ],
        )
        model_id = registered["payload"]["model"]["model_id"]

        issued = self._run_cli(
            [
                "model-execution-ticket",
                "--workspace-root",
                str(self.root),
                "--actor",
                "steward",
                "--roles",
                "model_steward",
                "--tenant",
                "tenant1",
                "--trust-domain",
                "domain1",
                "--model-id",
                model_id,
            ],
        )
        ticket = issued["payload"]["execution_ticket"]

        tampered_ticket = dict(ticket)
        tampered_ticket["model_id"] = "tampered"
        tampered_ticket_path = self.root / "ticket_tampered.json"
        tampered_ticket_path.write_text(
            json.dumps(tampered_ticket, indent=2),
            encoding="utf-8",
        )
        tampered_exit, tampered_payload = self._run_cli_with_exit(
            [
                "model-execution-ticket-inspect",
                "--workspace-root",
                str(self.root),
                "--ticket-file",
                str(tampered_ticket_path),
            ],
        )
        self.assertEqual(tampered_exit, 1)
        self.assertFalse(tampered_payload["allowed"])
        self.assertEqual(tampered_payload["reason"], "signature_invalid")

        valid_ticket_path = self.root / "ticket_valid.json"
        valid_ticket_path.write_text(
            json.dumps(ticket, indent=2),
            encoding="utf-8",
        )
        expired_exit, expired_payload = self._run_cli_with_exit(
            [
                "model-execution-ticket-inspect",
                "--workspace-root",
                str(self.root),
                "--ticket-file",
                str(valid_ticket_path),
                "--at-time",
                "2999-01-01T00:00:00+00:00",
            ],
        )
        self.assertEqual(expired_exit, 1)
        self.assertFalse(expired_payload["allowed"])
        self.assertEqual(expired_payload["reason"], "ticket_expired")

    def test_unreviewed_model_cannot_get_execution_ticket(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)
        record = registry.register(
            source_type="huggingface_model_id",
            source="org/model",
            license="unknown",
            content_hash="a" * 64,
            immutable_identifier="org/model@rev",
            metadata={},
            trust_level="quarantine",
            policy_profile="default",
            provenance_ref="hf://org/model",
        )
        with self.assertRaises(ValueError):
            registry.assert_executable(record.model_id)

    def test_sqlite_event_journal_verifies_hash_chain(self) -> None:
        journal = SQLiteEventJournal(self.root / "events.sqlite3")
        journal.append("event", "trace1", {"index": 1})
        journal.append("event", "trace1", {"index": 2})
        entries = SQLiteEventJournal(self.root / "events.sqlite3").read_all()
        self.assertEqual([entry["sequence"] for entry in entries], [1, 2])

    def test_local_file_registration_has_schema_and_signature_status(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)
        record = self._register_local_model(registry)

        self.assertEqual(record.signature_status, "unsigned")
        self.assertEqual(record.registry_schema_version, "1.1.0")
        self.assertTrue(record.immutable_identifier.startswith("sha256:"))

    def test_local_directory_hash_is_stable_and_ignores_transient_files(self) -> None:
        model_dir = self.root / "model_dir"
        nested = model_dir / "nested"
        nested.mkdir(parents=True, exist_ok=True)
        (model_dir / "config.json").write_text('{"layers": 3}', encoding="utf-8")
        (nested / "weights.bin").write_text("weights-v1", encoding="utf-8")

        hash_before = GovernedModelRegistry.hash_local_path(model_dir)

        transient_dir = model_dir / "__pycache__"
        transient_dir.mkdir(parents=True, exist_ok=True)
        (transient_dir / "ignore.pyc").write_bytes(b"compiled")
        cache_dir = model_dir / ".pytest_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "cache.log").write_text("transient", encoding="utf-8")

        hash_after_transient = GovernedModelRegistry.hash_local_path(model_dir)
        self.assertEqual(hash_before, hash_after_transient)

        (nested / "weights.bin").write_text("weights-v2", encoding="utf-8")
        hash_after_change = GovernedModelRegistry.hash_local_path(model_dir)
        self.assertNotEqual(hash_before, hash_after_change)

    def test_huggingface_without_revision_rejected_for_reviewed_trust(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        with self.assertRaisesRegex(ValueError, "requires immutable revision"):
            registry.register(
                source_type="huggingface_model_id",
                source="org/model",
                license="apache-2.0",
                content_hash=None,
                immutable_identifier=None,
                metadata={},
                trust_level="reviewed",
                policy_profile="default-model-policy",
                provenance_ref="hf://org/model",
            )

    def test_huggingface_without_revision_is_restricted_for_low_trust(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        record = registry.register(
            source_type="huggingface_model_id",
            source="org/model",
            license="apache-2.0",
            content_hash=None,
            immutable_identifier=None,
            metadata={},
            trust_level="quarantine",
            policy_profile="default-model-policy",
            provenance_ref="hf://org/model",
        )
        self.assertEqual(record.admissibility_status, "restricted")

    def test_mutable_endpoint_requires_explicit_immutable_proof_for_reviewed(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        with self.assertRaisesRegex(ValueError, "immutable_endpoint_proof"):
            registry.register(
                source_type="openai_compatible_endpoint",
                source="https://api.example.invalid/v1",
                license="service-terms",
                content_hash=None,
                immutable_identifier=None,
                metadata={},
                trust_level="reviewed",
                policy_profile="default-model-policy",
                provenance_ref="endpoint://api.example.invalid/v1",
            )

        low_trust_record = registry.register(
            source_type="openai_compatible_endpoint",
            source="https://api.example.invalid/v1",
            license="service-terms",
            content_hash=None,
            immutable_identifier=None,
            metadata={},
            trust_level="quarantine",
            policy_profile="default-model-policy",
            provenance_ref="endpoint://api.example.invalid/v1",
        )
        self.assertEqual(low_trust_record.admissibility_status, "restricted")

    def test_duplicate_immutable_identifier_is_deterministic(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        first = self._register_local_model(
            registry,
            immutable_identifier="sha256:fixed-model-id",
        )
        second = self._register_local_model(
            registry,
            immutable_identifier="sha256:fixed-model-id",
        )
        self.assertEqual(first.model_id, second.model_id)

        other_path = self.root / "other-model.bin"
        other_path.write_text("different-weights", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "immutable_identifier already registered"):
            registry.register(
                source_type="local_path",
                source=str(other_path),
                license="test-license",
                content_hash=GovernedModelRegistry.hash_local_path(other_path),
                immutable_identifier="sha256:fixed-model-id",
                metadata={"family": "unit-test"},
                trust_level="reviewed",
                policy_profile="default-model-policy",
                provenance_ref="provenance://other-model.bin",
            )

    def test_invalid_trust_level_rejected(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        with self.assertRaisesRegex(ValueError, "unsupported trust_level"):
            registry.register(
                source_type="local_path",
                source=str(self.model_path),
                license="test-license",
                content_hash=GovernedModelRegistry.hash_local_path(self.model_path),
                immutable_identifier=None,
                metadata={},
                trust_level="not-a-trust-level",
                policy_profile="default-model-policy",
                provenance_ref="provenance://model.bin",
            )

    def test_invalid_policy_profile_rejected(self) -> None:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)

        with self.assertRaisesRegex(ValueError, "policy_profile"):
            registry.register(
                source_type="local_path",
                source=str(self.model_path),
                license="test-license",
                content_hash=GovernedModelRegistry.hash_local_path(self.model_path),
                immutable_identifier=None,
                metadata={},
                trust_level="reviewed",
                policy_profile="Invalid Profile!",
                provenance_ref="provenance://model.bin",
            )


if __name__ == "__main__":
    unittest.main()
