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
from sovereign_ide.governance import SQLiteEventJournal  # noqa: E402
from sovereign_ide.model_registry import GovernedModelRegistry  # noqa: E402


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
        parser = build_parser()
        parsed = parser.parse_args(args)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(parsed.func(parsed), 0)
        return json.loads(output.getvalue())

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
        self.assertEqual(ticket["decision"]["outcome"], "approved")
        self.assertEqual(
            ticket["payload"]["status"],
            "governed_execution_authorized",
        )

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


if __name__ == "__main__":
    unittest.main()
