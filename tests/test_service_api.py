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
from sovereign_ide.service import make_handler  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
