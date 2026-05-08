from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib import request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.governance import HashChainJournal  # noqa: E402
from sovereign_ide.model_registry import GovernedModelRegistry  # noqa: E402
from sovereign_ide.service import (  # noqa: E402
    build_execution_ticket,
    build_runtime,
    make_handler,
    verify_execution_ticket,
)

try:  # pragma: no cover - optional dependency in local dev
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - optional dependency in local dev
    HAS_CRYPTOGRAPHY = False


def _write_policy(root: Path) -> None:
    policy_dir = root / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "baseline_policy.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "resolution": {
                    "default": "deny",
                    "precedence": ["invariants"],
                },
                "workspace": {
                    "allowed_roots": ["${SOVEREIGN_WORKSPACE_ROOT}"],
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
                    "execute_model": {
                        "required_mutation_class": "read",
                        "allowed_roles": ["developer"],
                        "quorum_required": False,
                    },
                },
            },
        ),
        encoding="utf-8",
    )


def _write_app_catalog(root: Path) -> None:
    deployments_dir = root / "deployments"
    deployments_dir.mkdir(parents=True, exist_ok=True)
    (deployments_dir / "app_catalog.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "apps": [
                    {
                        "id": "runtime-service-api",
                        "display_name": "Runtime Service API",
                        "category": "core",
                        "status": "enabled",
                        "description": "HTTP runtime surface.",
                        "surfaces": [
                            {"type": "api", "ref": "/v1/apps"},
                        ],
                        "requirements": [],
                        "governance_actions": [],
                        "tags": ["api"],
                    },
                    {
                        "id": "workshop-model-training",
                        "display_name": "Workshop Model Fine-Tuning",
                        "category": "modeling",
                        "status": "requires_configuration",
                        "description": "Actual fine-tuning surface.",
                        "surfaces": [
                            {"type": "cli", "ref": "workshop-train"},
                        ],
                        "requirements": ["SOVEREIGN_TRAINING_COMMAND"],
                        "governance_actions": ["start_training_run"],
                        "tags": ["training"],
                    },
                ],
            },
        ),
        encoding="utf-8",
    )


class ServiceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        _write_policy(self.root)
        _write_app_catalog(self.root)
        (self.root / ".env").write_text(
            "\n".join(
                [
                    f"SOVEREIGN_SIGNING_KEY={'c' * 64}",
                    "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                    "SOVEREIGN_STATE_DIR=state",
                ],
            ),
            encoding="utf-8",
        )
        get_settings.cache_clear()
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.root),
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.base_url = (
            f"http://127.0.0.1:{self.server.server_address[1]}"
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.env_patch.stop()
        get_settings.cache_clear()
        self.temp_dir.cleanup()

    def _get_json(self, path: str) -> dict:
        with request.urlopen(self.base_url + path, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post_json(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _register_reviewed_model(self) -> str:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)
        model_path = self.root / "model.bin"
        model_path.write_text("weights", encoding="utf-8")
        record = registry.register(
            source_type="local_path",
            source=str(model_path),
            license="test-license",
            content_hash=GovernedModelRegistry.hash_local_path(model_path),
            immutable_identifier="model.bin:sha256",
            metadata={"family": "unit-test"},
            trust_level="reviewed",
            policy_profile="default-model-policy",
            provenance_ref="provenance://model.bin",
        )
        return record.model_id

    def test_health_and_ready_endpoints(self) -> None:
        health = self._get_json("/health")
        self.assertEqual(health["status"], "ok")

        ready = self._get_json("/ready")
        self.assertEqual(ready["status"], "ready")
        self.assertTrue(ready["checks"])

    def test_policy_evaluate_and_replay(self) -> None:
        trace_id = "trace_service_test"
        result = self._post_json(
            "/v1/policy/evaluate",
            {
                "context": {
                    "trace_id": trace_id,
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
                "action": "run_tests",
                "resource": str(self.root / "inside.py"),
                "mutation_class": "softMutation",
                "scopes": ["run_tests"],
            },
        )

        self.assertTrue(result["evaluation"]["allowed"])
        replay = self._get_json(f"/v1/audit/replay?trace_id={trace_id}")
        self.assertEqual(replay["trace_id"], trace_id)
        self.assertEqual(len(replay["entries"]), 3)

    def test_apps_catalog_endpoint_lists_and_filters_apps(self) -> None:
        catalog = self._get_json("/v1/apps")
        self.assertEqual(catalog["app_count"], 2)
        self.assertEqual(
            [app["id"] for app in catalog["apps"]],
            ["runtime-service-api", "workshop-model-training"],
        )

        filtered = self._get_json("/v1/apps?status=requires_configuration")
        self.assertEqual(filtered["app_count"], 1)
        self.assertEqual(filtered["apps"][0]["id"], "workshop-model-training")

    def test_models_endpoint_lists_registered_models(self) -> None:
        models = self._get_json("/v1/models")
        self.assertEqual(models["models"], [])

    def test_execution_ticket_endpoint_returns_signed_ticket(self) -> None:
        model_id = self._register_reviewed_model()
        response = self._post_json(
            "/v1/models/execution-ticket",
            {
                "model_id": model_id,
                "ticket_purpose": "unit_test_inference",
                "ticket_ttl_seconds": 120,
                "context": {
                    "trace_id": "trace_execution_ticket_api",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )

        payload = response["payload"]
        self.assertEqual(payload["status"], "governed_execution_authorized")
        ticket = payload["execution_ticket"]
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
            self.assertIn(field, ticket)
        self.assertEqual(ticket["model_id"], model_id)
        self.assertEqual(ticket["ticket_purpose"], "unit_test_inference")

        runtime = build_runtime(self.root)
        valid, reason = verify_execution_ticket(ticket, runtime.signer)
        self.assertTrue(valid, msg=reason)

    def test_service_token_protects_ready_and_api(self) -> None:
        with patch.dict(os.environ, {"SOVEREIGN_SERVICE_TOKEN": "secret"}):
            health = self._get_json("/health")
            self.assertEqual(health["status"], "ok")

            with self.assertRaises(Exception):
                self._get_json("/ready")

            with self.assertRaises(Exception):
                self._get_json("/v1/apps")

            req = request.Request(
                self.base_url + "/ready",
                headers={"Authorization": "Bearer secret"},
            )
            with request.urlopen(req, timeout=5) as response:
                ready = json.loads(response.read().decode("utf-8"))
            self.assertEqual(ready["status"], "ready")


class JournalLockingTests(unittest.TestCase):
    def test_stale_journal_instances_rehydrate_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.jsonl"
            first = HashChainJournal(journal_path)
            second = HashChainJournal(journal_path)

            first.append("event", "trace", {"index": 1})
            second.append("event", "trace", {"index": 2})

            entries = HashChainJournal(journal_path).read_all()
            self.assertEqual([entry["sequence"] for entry in entries], [1, 2])
            self.assertEqual(
                entries[1]["previous_hash"],
                entries[0]["entry_hash"],
            )


class ExecutionTicketSignerPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        _write_policy(self.root)
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        get_settings.cache_clear()

    def tearDown(self) -> None:
        self.env_patch.stop()
        get_settings.cache_clear()
        self.temp_dir.cleanup()

    def _write_env(self, lines: list[str]) -> None:
        (self.root / ".env").write_text("\n".join(lines), encoding="utf-8")
        get_settings.cache_clear()

    def _register_reviewed_model(self) -> tuple[GovernedModelRegistry, str]:
        settings = get_settings(self.root)
        model_path = self.root / "model.bin"
        model_path.write_text("weights", encoding="utf-8")
        registry = GovernedModelRegistry(settings.model_registry_path)
        record = registry.register(
            source_type="local_path",
            source=str(model_path),
            license="test-license",
            content_hash=GovernedModelRegistry.hash_local_path(model_path),
            immutable_identifier="model.bin:sha256",
            metadata={"family": "unit-test"},
            trust_level="reviewed",
            policy_profile="default-model-policy",
            provenance_ref="provenance://model.bin",
        )
        return registry, record.model_id

    def test_missing_ed25519_key_is_rejected_in_production_mode(self) -> None:
        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=production",
                "SOVEREIGN_SIGNER_BACKEND=ed25519",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
            ],
        )

        with self.assertRaises(ValueError):
            build_runtime(self.root)

    def test_hmac_signer_rejected_outside_local_mode(self) -> None:
        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=production",
                "SOVEREIGN_SIGNER_BACKEND=hmac-dev",
                f"SOVEREIGN_SIGNING_KEY={'d' * 64}",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
            ],
        )

        with self.assertRaises(ValueError):
            build_runtime(self.root)

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography not installed")
    def test_valid_ed25519_ticket_signing_and_verification(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        keys_dir = self.root / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        private_key_path = keys_dir / "ed25519_private.pem"
        private_key_path.write_text(private_key_pem, encoding="utf-8")

        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=production",
                "SOVEREIGN_SIGNER_BACKEND=ed25519",
                "SOVEREIGN_SIGNER_KEY_ID=prod-key-001",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
                f"SOVEREIGN_ED25519_PRIVATE_KEY_PATH={private_key_path}",
            ],
        )

        runtime = build_runtime(self.root)
        registry, model_id = self._register_reviewed_model()
        model = registry.assert_executable(model_id)

        ticket = build_execution_ticket(
            runtime,
            model,
            purpose="unit_test_inference",
            ttl_seconds=120,
        )
        self.assertEqual(ticket["signature"]["algorithm"], "Ed25519")

        valid, reason = verify_execution_ticket(ticket, runtime.signer)
        self.assertTrue(valid, msg=reason)

    def test_execution_ticket_payload_tampering_is_rejected(self) -> None:
        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=local",
                "SOVEREIGN_SIGNER_BACKEND=hmac-dev",
                f"SOVEREIGN_SIGNING_KEY={'e' * 64}",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
            ],
        )

        runtime = build_runtime(self.root)
        registry, model_id = self._register_reviewed_model()
        model = registry.assert_executable(model_id)

        ticket = build_execution_ticket(
            runtime,
            model,
            purpose="unit_test_inference",
            ttl_seconds=120,
        )
        ticket["model_id"] = "tampered-model-id"

        valid, reason = verify_execution_ticket(ticket, runtime.signer)
        self.assertFalse(valid)
        self.assertEqual(reason, "signature_invalid")

    def test_execution_ticket_invalid_signature_is_rejected(self) -> None:
        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=local",
                "SOVEREIGN_SIGNER_BACKEND=hmac-dev",
                f"SOVEREIGN_SIGNING_KEY={'f' * 64}",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
            ],
        )

        runtime = build_runtime(self.root)
        registry, model_id = self._register_reviewed_model()
        model = registry.assert_executable(model_id)

        ticket = build_execution_ticket(
            runtime,
            model,
            purpose="unit_test_inference",
            ttl_seconds=120,
        )
        ticket["signature"]["signature"] = "0" * len(
            ticket["signature"]["signature"],
        )

        valid, reason = verify_execution_ticket(ticket, runtime.signer)
        self.assertFalse(valid)
        self.assertEqual(reason, "signature_invalid")

    def test_execution_ticket_expired_is_rejected(self) -> None:
        self._write_env(
            [
                "SOVEREIGN_RUNTIME_MODE=local",
                "SOVEREIGN_SIGNER_BACKEND=hmac-dev",
                f"SOVEREIGN_SIGNING_KEY={'9' * 64}",
                "SOVEREIGN_POLICY_PATH=policies/baseline_policy.json",
                "SOVEREIGN_STATE_DIR=state",
            ],
        )

        runtime = build_runtime(self.root)
        registry, model_id = self._register_reviewed_model()
        model = registry.assert_executable(model_id)

        ticket = build_execution_ticket(
            runtime,
            model,
            purpose="unit_test_inference",
            ttl_seconds=60,
            issued_at="2026-01-01T00:00:00+00:00",
        )

        valid, reason = verify_execution_ticket(
            ticket,
            runtime.signer,
            at_time="2026-01-01T00:02:00+00:00",
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "ticket_expired")


if __name__ == "__main__":
    unittest.main()
