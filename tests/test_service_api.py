from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib import error, request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.governance import HashChainJournal, build_journal  # noqa: E402
from sovereign_ide.models import GovernanceContext, new_id  # noqa: E402
from sovereign_ide.model_registry import GovernedModelRegistry  # noqa: E402
from sovereign_ide.service import (  # noqa: E402
    build_execution_ticket,
    build_runtime,
    make_handler,
    verify_execution_ticket,
)
from sovereign_ide.workshop import SovereignModelServerWorkshop  # noqa: E402

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
                    "register_model": {
                        "required_mutation_class": "governanceMutation",
                        "allowed_roles": ["model_steward", "release_authority"],
                        "quorum_required": True,
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

    def _post_json_with_status(self, path: str, payload: dict) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _inject_model_record(self, record: dict) -> None:
        settings = get_settings(self.root)
        state = {
            "models": {},
            "immutable_index": {},
        }
        if settings.model_registry_path.exists():
            state = json.loads(settings.model_registry_path.read_text(encoding="utf-8"))
            state.setdefault("models", {})
            state.setdefault("immutable_index", {})

        state["models"][record["model_id"]] = record
        immutable_identifier = record.get("immutable_identifier")
        if immutable_identifier:
            state["immutable_index"][immutable_identifier] = record["model_id"]
        settings.model_registry_path.parent.mkdir(parents=True, exist_ok=True)
        settings.model_registry_path.write_text(
            json.dumps(state, indent=2),
            encoding="utf-8",
        )

    def _workshop_context(self, actor: str, roles: tuple[str, ...]) -> GovernanceContext:
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

    def _prepare_workshop_dataset_ids(self) -> tuple[str, ...]:
        docs_dir = self.root / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)
        (docs_dir / "constitutional_a.txt").write_text(
            "containment quorum continuity identity provenance",
            encoding="utf-8",
        )
        (docs_dir / "constitutional_b.txt").write_text(
            "directness refusal repair adversarial governance",
            encoding="utf-8",
        )

        workshop = SovereignModelServerWorkshop(workspace_root=self.root)
        workshop.bootstrap_founding_charter(
            context=self._workshop_context(
                actor="authority",
                roles=("trust_administrator", "release_authority"),
            ),
            quorum_proof="founding-quorum",
        )
        workshop.admit_corpus_artifacts(
            context=self._workshop_context(
                actor="data-steward",
                roles=("data_steward", "model_steward"),
            ),
            artifact_paths=(
                str(docs_dir / "constitutional_a.txt"),
                str(docs_dir / "constitutional_b.txt"),
            ),
            artifact_type="constitutional_doc",
            source_class="curated",
            trust_class="reviewed",
        )
        built = workshop.build_constitutional_datasets(
            context=self._workshop_context(
                actor="model-steward",
                roles=("model_steward", "data_steward"),
            ),
        )
        return tuple(built["payload"]["dataset_ids"])

    def _workshop_replay(self, trace_id: str) -> list[dict]:
        settings = get_settings(self.root)
        journal = build_journal(
            settings,
            path=(
                self.root / "state" / "workshop" / "workshop_journal.jsonl"
                if settings.journal_backend == "file"
                else self.root / "state" / "workshop" / "workshop_events.sqlite3"
            ),
        )
        return journal.replay_trace(trace_id)

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
        self.assertIn("runtime_mode", health)
        self.assertIn("signer_type", health)
        self.assertIn("service_token_required", health)

        ready = self._get_json("/ready")
        self.assertEqual(ready["status"], "ready")
        self.assertTrue(ready["checks"])

    def test_evidence_status_endpoint_is_read_only_and_secret_safe(self) -> None:
        status = self._get_json("/v1/evidence/status")
        self.assertIn("classification", status)
        self.assertIn("allowed", status)
        self.assertIn("issues", status)
        self.assertIn("manifest_summary", status)
        self.assertIn("runtime_mode", status)
        self.assertIn("signer_backend", status)

        raw = json.dumps(status)
        self.assertNotIn("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", raw)
        self.assertNotIn("service-token-very-long-value", raw)

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

    def test_model_register_endpoint_registers_model_with_governed_response(self) -> None:
        model_path = self.root / "registered_model.bin"
        model_path.write_text("weights", encoding="utf-8")

        status, response = self._post_json_with_status(
            "/v1/models/register",
            {
                "source_type": "local_path",
                "source": str(model_path),
                "license": "test-license",
                "trust_level": "reviewed",
                "policy_profile": "default-model-policy",
                "provenance_ref": "provenance://registered_model.bin",
                "metadata": {"family": "unit-test"},
                "quorum_proof": "register-quorum",
                "context": {
                    "trace_id": "trace_model_register_success",
                    "actor_id": "steward1",
                    "actor_roles": ["model_steward"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )

        self.assertEqual(status, 200)
        self.assertTrue(response["allowed"])
        self.assertEqual(response["reason"], "ok")
        self.assertIn("governance_decision_hash", response)
        model = response["model"]
        self.assertEqual(model["source_type"], "local_path")
        self.assertEqual(model["trust_level"], "reviewed")
        self.assertEqual(model["policy_profile"], "default-model-policy")

        listed = self._get_json("/v1/models")
        self.assertEqual(len(listed["models"]), 1)
        self.assertEqual(listed["models"][0]["model_id"], model["model_id"])

    def test_model_register_denies_mutable_endpoint_without_immutable_proof(self) -> None:
        status, response = self._post_json_with_status(
            "/v1/models/register",
            {
                "source_type": "openai_compatible_endpoint",
                "source": "https://api.example.invalid/v1",
                "license": "service-terms",
                "trust_level": "reviewed",
                "policy_profile": "default-model-policy",
                "provenance_ref": "endpoint://api.example.invalid/v1",
                "metadata": {},
                "quorum_proof": "register-quorum",
                "context": {
                    "trace_id": "trace_model_register_mutable_denied",
                    "actor_id": "steward1",
                    "actor_roles": ["model_steward"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )

        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertIn("immutable_endpoint_proof", response["reason"])

    def test_audit_events_endpoint_returns_projected_read_only_events(self) -> None:
        trace_id = "trace_audit_events_projection"
        status, denied = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "unknown_model_for_audit_projection",
                "context": {
                    "trace_id": trace_id,
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(denied["allowed"])

        events = self._get_json(
            f"/v1/audit/events?trace_id={trace_id}&limit=25",
        )
        self.assertGreaterEqual(events["event_count"], 1)
        first = events["events"][0]
        self.assertIn("record_type", first)
        self.assertIn("timestamp", first)
        self.assertIn("source_journal", first)
        self.assertIn("payload", first)
        self.assertTrue(
            any(item["record_type"] == "execution_ticket_denied" for item in events["events"]),
        )

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

        self.assertTrue(response["allowed"])
        self.assertEqual(response["reason"], "ok")
        self.assertIsNotNone(response["governance_decision_hash"])
        self.assertEqual(len(response["governance_decision_hash"]), 64)

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

    def test_execution_ticket_unknown_model_is_denied_with_clear_reason(self) -> None:
        status, response = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "model_does_not_exist",
                "context": {
                    "trace_id": "trace_unknown_model_denial",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertEqual(response["reason"], "unknown_model")
        self.assertIsNotNone(response["governance_decision_hash"])

    def test_execution_ticket_missing_policy_profile_is_denied(self) -> None:
        self._inject_model_record(
            {
                "model_id": "model_missing_policy",
                "source_type": "local_path",
                "source": str(self.root / "model.bin"),
                "license": "test-license",
                "content_hash": "a" * 64,
                "immutable_identifier": "sha256:" + ("a" * 64),
                "metadata": {"source_mutability": "local_immutable_by_hash"},
                "trust_level": "reviewed",
                "policy_profile": "",
                "provenance_ref": "provenance://model.bin",
                "admissibility_status": "admissible",
                "signature_status": "unsigned",
                "registered_at": "2026-01-01T00:00:00+00:00",
                "registry_schema_version": "1.1.0",
                "signature": None,
            },
        )

        status, response = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "model_missing_policy",
                "context": {
                    "trace_id": "trace_missing_policy_denial",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertEqual(response["reason"], "missing_policy_profile")

    def test_execution_ticket_missing_provenance_is_denied(self) -> None:
        self._inject_model_record(
            {
                "model_id": "model_missing_provenance",
                "source_type": "local_path",
                "source": str(self.root / "model.bin"),
                "license": "test-license",
                "content_hash": "b" * 64,
                "immutable_identifier": "sha256:" + ("b" * 64),
                "metadata": {"source_mutability": "local_immutable_by_hash"},
                "trust_level": "reviewed",
                "policy_profile": "default-model-policy",
                "provenance_ref": "",
                "admissibility_status": "admissible",
                "signature_status": "unsigned",
                "registered_at": "2026-01-01T00:00:00+00:00",
                "registry_schema_version": "1.1.0",
                "signature": None,
            },
        )

        status, response = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "model_missing_provenance",
                "context": {
                    "trace_id": "trace_missing_provenance_denial",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertEqual(response["reason"], "missing_provenance")

    def test_execution_ticket_insufficient_trust_is_denied(self) -> None:
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
            policy_profile="default-model-policy",
            provenance_ref="hf://org/model",
        )

        status, response = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": record.model_id,
                "context": {
                    "trace_id": "trace_insufficient_trust_denial",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertEqual(response["reason"], "insufficient_trust_level")

    def test_execution_ticket_mutable_source_without_proof_is_denied(self) -> None:
        self._inject_model_record(
            {
                "model_id": "model_mutable_endpoint",
                "source_type": "openai_compatible_endpoint",
                "source": "https://api.example.invalid/v1",
                "license": "service-terms",
                "content_hash": "c" * 64,
                "immutable_identifier": "sha256:" + ("c" * 64),
                "metadata": {"source_mutability": "mutable_external_endpoint"},
                "trust_level": "reviewed",
                "policy_profile": "default-model-policy",
                "provenance_ref": "endpoint://api.example.invalid/v1",
                "admissibility_status": "admissible",
                "signature_status": "unsigned",
                "registered_at": "2026-01-01T00:00:00+00:00",
                "registry_schema_version": "1.1.0",
                "signature": None,
            },
        )

        status, response = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "model_mutable_endpoint",
                "context": {
                    "trace_id": "trace_mutable_source_denial",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertEqual(
            response["reason"],
            "mutable_source_requires_immutable_proof",
        )

    def test_execution_ticket_invalid_signer_configuration_is_denied(self) -> None:
        get_settings.cache_clear()
        with patch.dict(
            os.environ,
            {
                "SOVEREIGN_RUNTIME_MODE": "production",
                "SOVEREIGN_SIGNER_BACKEND": "hmac-dev",
                "SOVEREIGN_SIGNING_KEY": "d" * 64,
            },
            clear=False,
        ):
            status, response = self._post_json_with_status(
                "/v1/models/execution-ticket",
                {
                    "model_id": "model_any",
                    "context": {
                        "trace_id": "trace_invalid_signer_denial",
                        "actor_id": "dev1",
                        "actor_roles": ["developer"],
                        "tenant": "tenant1",
                        "trust_domain": "domain1",
                        "classification": "confidential",
                    },
                },
            )
        get_settings.cache_clear()

        self.assertEqual(status, 403)
        self.assertFalse(response["allowed"])
        self.assertTrue(response["reason"].startswith("invalid_signer_configuration:"))

    def test_execution_ticket_success_and_denial_are_recorded_in_journal(self) -> None:
        model_id = self._register_reviewed_model()
        trace_id_success = "trace_ticket_success_journal"
        success = self._post_json(
            "/v1/models/execution-ticket",
            {
                "model_id": model_id,
                "context": {
                    "trace_id": trace_id_success,
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertTrue(success["allowed"])
        replay_success = self._get_json(f"/v1/audit/replay?trace_id={trace_id_success}")
        self.assertTrue(
            any(
                entry["record_type"] == "execution_ticket_issued"
                for entry in replay_success["entries"]
            ),
        )

        trace_id_denial = "trace_ticket_denial_journal"
        status, denial = self._post_json_with_status(
            "/v1/models/execution-ticket",
            {
                "model_id": "unknown_model_for_denial",
                "context": {
                    "trace_id": trace_id_denial,
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 403)
        self.assertFalse(denial["allowed"])
        replay_denial = self._get_json(f"/v1/audit/replay?trace_id={trace_id_denial}")
        self.assertTrue(
            any(
                entry["record_type"] == "execution_ticket_denied"
                for entry in replay_denial["entries"]
            ),
        )

    def test_execution_ticket_inspect_rejects_tampered_and_expired_tickets(self) -> None:
        model_id = self._register_reviewed_model()
        issued = self._post_json(
            "/v1/models/execution-ticket",
            {
                "model_id": model_id,
                "ticket_purpose": "inspect_test",
                "ticket_ttl_seconds": 120,
                "context": {
                    "trace_id": "trace_ticket_inspect_issue",
                    "actor_id": "dev1",
                    "actor_roles": ["developer"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        ticket = issued["payload"]["execution_ticket"]

        tampered = dict(ticket)
        tampered["model_id"] = "tampered"
        status_tampered, response_tampered = self._post_json_with_status(
            "/v1/models/execution-ticket/inspect",
            {
                "trace_id": "trace_ticket_inspect_tampered",
                "ticket": tampered,
            },
        )
        self.assertEqual(status_tampered, 403)
        self.assertFalse(response_tampered["allowed"])
        self.assertEqual(response_tampered["reason"], "signature_invalid")

        runtime = build_runtime(self.root)
        settings = get_settings(self.root)
        model = GovernedModelRegistry(settings.model_registry_path).get(model_id)
        expired_ticket = build_execution_ticket(
            runtime,
            model,
            purpose="inspect_test",
            ttl_seconds=60,
            issued_at="2026-01-01T00:00:00+00:00",
        )
        status_expired, response_expired = self._post_json_with_status(
            "/v1/models/execution-ticket/inspect",
            {
                "trace_id": "trace_ticket_inspect_expired",
                "ticket": expired_ticket,
                "at_time": "2026-01-01T00:02:00+00:00",
            },
        )
        self.assertEqual(status_expired, 403)
        self.assertFalse(response_expired["allowed"])
        self.assertEqual(response_expired["reason"], "ticket_expired")

    def test_workshop_preflight_api_enforces_simulation_flag_with_journal_evidence(self) -> None:
        dataset_ids = self._prepare_workshop_dataset_ids()

        denied_trace = "trace_workshop_preflight_denied"
        status_denied, denied = self._post_json_with_status(
            "/v1/workshop/training/preflight",
            {
                "model_family": "project-ai-workshop-sim",
                "dataset_ids": list(dataset_ids),
                "execution_mode": "simulated",
                "simulation_smoke_test": False,
                "context": {
                    "trace_id": denied_trace,
                    "actor_id": "trainer",
                    "actor_roles": ["model_steward", "release_authority"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status_denied, 403)
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["mode"], "simulation")
        self.assertEqual(denied["reason"], "simulation_flag_required")

        denied_entries = self._workshop_replay(denied_trace)
        self.assertTrue(
            any(
                entry["record_type"] == "training_preflight_denied"
                for entry in denied_entries
            ),
        )

        allowed_trace = "trace_workshop_preflight_allowed"
        status_allowed, allowed = self._post_json_with_status(
            "/v1/workshop/training/preflight",
            {
                "model_family": "project-ai-workshop-sim",
                "dataset_ids": list(dataset_ids),
                "execution_mode": "simulated",
                "simulation_smoke_test": True,
                "context": {
                    "trace_id": allowed_trace,
                    "actor_id": "trainer",
                    "actor_roles": ["model_steward", "release_authority"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status_allowed, 200)
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["mode"], "simulation")
        self.assertEqual(allowed["reason"], "ok")

        allowed_entries = self._workshop_replay(allowed_trace)
        self.assertTrue(
            any(
                entry["record_type"] == "training_preflight_allowed"
                for entry in allowed_entries
            ),
        )

    def test_workshop_training_run_api_returns_simulation_mode_and_no_checkpoint_registration(self) -> None:
        dataset_ids = self._prepare_workshop_dataset_ids()
        trace_id = "trace_workshop_run_simulation"

        status, response = self._post_json_with_status(
            "/v1/workshop/training/run",
            {
                "model_family": "project-ai-workshop-sim",
                "dataset_ids": list(dataset_ids),
                "execution_mode": "simulated",
                "simulation_smoke_test": True,
                "quorum_proof": "train-quorum",
                "context": {
                    "trace_id": trace_id,
                    "actor_id": "trainer",
                    "actor_roles": ["model_steward", "release_authority"],
                    "tenant": "tenant1",
                    "trust_domain": "domain1",
                    "classification": "confidential",
                },
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(response["allowed"])
        self.assertEqual(response["mode"], "simulation")
        self.assertEqual(response["reason"], "ok")

        payload = response["result"]["payload"]
        self.assertEqual(payload["mode"], "simulation")
        self.assertIsNone(payload["governed_model"])

        entries = self._workshop_replay(trace_id)
        record_types = [entry["record_type"] for entry in entries]
        self.assertIn("simulation_started", record_types)
        self.assertIn("simulation_completed", record_types)
        self.assertNotIn("checkpoint_registered", record_types)

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
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("11" * 32),
        )
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
