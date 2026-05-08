from __future__ import annotations

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

from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.models import GovernanceContext, new_id  # noqa: E402
from sovereign_ide.workshop import (  # noqa: E402
    ContainmentDecision,
    PolicyViolation,
    SovereignModelServerWorkshop,
)


class WorkshopServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

        (self.root / ".env").write_text(
            "\n".join(
                [
                    f"SOVEREIGN_SIGNING_KEY={'a' * 64}",
                    "SOVEREIGN_POLICY_PATH=policies/workshop_policy.json",
                    "SOVEREIGN_STATE_DIR=state",
                ]
            ),
            encoding="utf-8",
        )

        docs_dir = self.root / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)
        (docs_dir / "octoreflex_notes.txt").write_text(
            (
                "Containment must occur below cognition with syscall controls.\n\n"
                "Quorum approvals are required for privileged promotion paths.\n\n"
                "State register continuity and attested provenance are mandatory."
            ),
            encoding="utf-8",
        )
        (docs_dir / "directness_notes.txt").write_text(
            (
                "Directness favors truth over comfort and resists sycophancy.\n\n"
                "Identity persistence requires validated anchors and temporal honesty."
            ),
            encoding="utf-8",
        )

        get_settings.cache_clear()
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()

        self.workshop = SovereignModelServerWorkshop(
            workspace_root=self.root,
            policy_path=self.root / "policies/workshop_policy.json",
        )

        self.artifact_paths = (
            str(self.root / "docs" / "octoreflex_notes.txt"),
            str(self.root / "docs" / "directness_notes.txt"),
        )

    def tearDown(self) -> None:
        self.env_patch.stop()
        get_settings.cache_clear()
        self.temp_dir.cleanup()

    def _context(
        self,
        actor: str,
        roles: tuple[str, ...],
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

    def _bootstrap_and_prepare_datasets(self) -> tuple[str, ...]:
        self.workshop.bootstrap_founding_charter(
            context=self._context(
                actor="authority",
                roles=("trust_administrator", "release_authority"),
            ),
            quorum_proof="founding-quorum",
        )

        self.workshop.admit_corpus_artifacts(
            context=self._context(
                actor="data-steward",
                roles=("data_steward", "model_steward"),
            ),
            artifact_paths=self.artifact_paths,
            artifact_type="constitutional_doc",
            source_class="curated",
            trust_class="reviewed",
        )

        build_result = self.workshop.build_constitutional_datasets(
            context=self._context(
                actor="model-steward",
                roles=("model_steward", "data_steward"),
            ),
        )
        return tuple(build_result["payload"]["dataset_ids"])

    def _train_until_passed_eval(
        self,
        dataset_ids: tuple[str, ...],
    ) -> tuple[str, str]:
        for index in range(1, 41):
            train_result = self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                model_family=f"project-ai-constitutional-{index}",
                base_checkpoint=None,
                dataset_ids=dataset_ids,
                quorum_proof="train-quorum",
                execution_mode="simulated",
            )
            checkpoint_id = train_result["payload"]["checkpoint"][
                "checkpoint_id"
            ]

            eval_result = self.workshop.run_shadow_evaluation(
                context=self._context(
                    actor="reviewer",
                    roles=("reviewer", "security_reviewer"),
                ),
                checkpoint_id=checkpoint_id,
            )
            verdict = eval_result["payload"]["verdict"]
            if verdict["passed"]:
                return checkpoint_id, verdict["evaluation_id"]

        self.fail("Unable to produce promotable checkpoint in allotted attempts")

    def test_bootstrap_generates_charter_and_genesis(self) -> None:
        result = self.workshop.bootstrap_founding_charter(
            context=self._context(
                actor="authority",
                roles=("trust_administrator", "release_authority"),
            ),
            quorum_proof="founding-quorum",
        )

        self.assertEqual(result["decision"]["outcome"], "approved")
        self.assertTrue(
            (self.root / "workshop" / "founding" / "server_charter_v1.json").exists(),
        )
        self.assertTrue(
            (self.root / "workshop" / "genesis" / "genesis_event.json").exists(),
        )

    def test_end_to_end_training_eval_and_promotion(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        checkpoint_id, evaluation_id = self._train_until_passed_eval(dataset_ids)

        promote_result = self.workshop.promote_checkpoint(
            context=self._context(
                actor="release-authority",
                roles=("release_authority", "reviewer"),
            ),
            checkpoint_id=checkpoint_id,
            evaluation_id=evaluation_id,
            approvals=("approverA", "approverB"),
            charter_version="1.0.0",
            quorum_proof="promotion-quorum",
        )

        self.assertEqual(promote_result["decision"]["outcome"], "approved")
        self.assertTrue(
            promote_result["payload"]["promotion_bundle"]["quorum_met"],
        )

    def test_training_report_discloses_simulation_mode(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        train_result = self.workshop.start_training_run(
            context=self._context(
                actor="trainer",
                roles=("model_steward", "release_authority"),
            ),
            model_family="project-ai-constitutional-simulated",
            base_checkpoint=None,
            dataset_ids=dataset_ids,
            quorum_proof="train-quorum",
            execution_mode="simulated",
        )

        self.assertEqual(
            train_result["payload"]["run"]["status"],
            "simulated_completed",
        )
        self.assertEqual(
            train_result["payload"]["run"]["execution_mode"],
            "simulated",
        )
        report = self.workshop.export_workshop_report()
        self.assertEqual(report["readiness_level"], "prototype")
        self.assertTrue(report["training_is_simulated"])
        self.assertIn("simulated", report["training_execution_modes"])

    def test_actual_training_requires_configured_trainer(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                model_family="project-ai-constitutional-actual",
                base_checkpoint=None,
                dataset_ids=dataset_ids,
                quorum_proof="train-quorum",
            )
        self.assertIn("actual training requires", str(raised.exception))

    def test_actual_training_uses_trainer_output_manifest(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        trainer_path = self.root / "trainer_stub.py"
        trainer_path.write_text(
            "\n".join(
                [
                    "from pathlib import Path",
                    "import argparse",
                    "import hashlib",
                    "import json",
                    "parser = argparse.ArgumentParser()",
                    "parser.add_argument('--request', required=True)",
                    "parser.add_argument('--output', required=True)",
                    "args = parser.parse_args()",
                    "request = json.loads(Path(args.request).read_text())",
                    "material = json.dumps(request, sort_keys=True)",
                    "digest = hashlib.sha256(material.encode()).hexdigest()",
                    "Path(args.output).write_text(json.dumps({",
                    "    'status': 'completed',",
                    "    'checkpoint_id': 'checkpoint_actual_test',",
                    "    'artifact_uri': 'file://' + request['output_dir'],",
                    "    'checkpoint_hash': digest,",
                    "}))",
                ],
            ),
            encoding="utf-8",
        )

        train_result = self.workshop.start_training_run(
            context=self._context(
                actor="trainer",
                roles=("model_steward", "release_authority"),
            ),
            model_family="project-ai-constitutional-actual",
            base_checkpoint=None,
            dataset_ids=dataset_ids,
            quorum_proof="train-quorum",
            execution_mode="actual",
            training_command=f'"{sys.executable}" "{trainer_path}"',
        )

        self.assertEqual(train_result["payload"]["run"]["status"], "completed")
        self.assertEqual(
            train_result["payload"]["run"]["execution_mode"],
            "actual",
        )
        self.assertEqual(
            train_result["payload"]["checkpoint"]["checkpoint_id"],
            "checkpoint_actual_test",
        )
        self.assertEqual(
            train_result["payload"]["checkpoint"]["execution_mode"],
            "actual",
        )
        self.assertIsNotNone(train_result["payload"]["governed_model"])
        self.assertEqual(
            train_result["payload"]["governed_model"]["source_type"],
            "fine_tuned_checkpoint",
        )

    def test_actual_training_rejects_local_artifact_when_store_configured(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        trainer_path = self.root / "local_artifact_trainer.py"
        trainer_path.write_text(
            "\n".join(
                [
                    "from pathlib import Path",
                    "import argparse",
                    "import json",
                    "parser = argparse.ArgumentParser()",
                    "parser.add_argument('--request', required=True)",
                    "parser.add_argument('--output', required=True)",
                    "args = parser.parse_args()",
                    "request = json.loads(Path(args.request).read_text())",
                    "Path(args.output).write_text(json.dumps({",
                    "    'status': 'completed',",
                    "    'checkpoint_id': 'checkpoint_local_artifact',",
                    "    'artifact_uri': 'file://' + request['output_dir'],",
                    "    'checkpoint_hash': '" + ("d" * 64) + "',",
                    "}))",
                ],
            ),
            encoding="utf-8",
        )

        with patch.dict(
            os.environ,
            {
                "SOVEREIGN_TRAINING_ARTIFACT_STORE": (
                    "https://huggingface.co/example/model"
                ),
            },
        ):
            with self.assertRaises(PolicyViolation) as raised:
                self.workshop.start_training_run(
                    context=self._context(
                        actor="trainer",
                        roles=("model_steward", "release_authority"),
                    ),
                    model_family="project-ai-constitutional-actual",
                    base_checkpoint=None,
                    dataset_ids=dataset_ids,
                    quorum_proof="train-quorum",
                    execution_mode="actual",
                    training_command=f'"{sys.executable}" "{trainer_path}"',
                )
        self.assertIn("durable storage", str(raised.exception))

    def test_actual_training_request_carries_artifact_store_contract(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        trainer_path = self.root / "durable_artifact_trainer.py"
        trainer_path.write_text(
            "\n".join(
                [
                    "from pathlib import Path",
                    "import argparse",
                    "import json",
                    "parser = argparse.ArgumentParser()",
                    "parser.add_argument('--request', required=True)",
                    "parser.add_argument('--output', required=True)",
                    "args = parser.parse_args()",
                    "request = json.loads(Path(args.request).read_text())",
                    "artifact_store = request['artifact_store_uri']",
                    "Path(args.output).write_text(json.dumps({",
                    "    'status': 'completed',",
                    "    'checkpoint_id': 'checkpoint_durable_artifact',",
                    "    'artifact_uri': artifact_store,",
                    "    'artifact_store_uri': artifact_store,",
                    "    'checkpoint_hash': '" + ("e" * 64) + "',",
                    "}))",
                ],
            ),
            encoding="utf-8",
        )

        with patch.dict(
            os.environ,
            {
                "SOVEREIGN_TRAINING_BACKEND": "huggingface-jobs",
                "SOVEREIGN_TRAINING_ARTIFACT_STORE": (
                    "https://huggingface.co/example/model"
                ),
            },
        ):
            train_result = self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                model_family="project-ai-constitutional-actual",
                base_checkpoint=None,
                dataset_ids=dataset_ids,
                quorum_proof="train-quorum",
                execution_mode="actual",
                training_command=f'"{sys.executable}" "{trainer_path}"',
            )

        self.assertEqual(
            train_result["payload"]["run"]["training_backend"],
            "huggingface-jobs",
        )
        self.assertEqual(
            train_result["payload"]["run"]["artifact_store_uri"],
            "https://huggingface.co/example/model",
        )
        self.assertEqual(
            train_result["payload"]["checkpoint"]["artifact_uri"],
            "https://huggingface.co/example/model",
        )

    def test_promotion_denied_without_quorum(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        checkpoint_id, evaluation_id = self._train_until_passed_eval(dataset_ids)

        with self.assertRaises(PolicyViolation):
            self.workshop.promote_checkpoint(
                context=self._context(
                    actor="release-authority",
                    roles=("release_authority", "reviewer"),
                ),
                checkpoint_id=checkpoint_id,
                evaluation_id=evaluation_id,
                approvals=("approverA",),
                charter_version="1.0.0",
                quorum_proof="promotion-quorum",
            )

    def test_runtime_containment_rejects_unauthorized_syscall(self) -> None:
        decision: ContainmentDecision = self.workshop.evaluate_runtime_containment(
            action="promote_checkpoint",
            requested_syscalls=("read", "ptrace"),
            network_egress_class="none",
            filesystem_write_paths=(str(self.root / "state" / "x.log"),),
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            any(reason.startswith("unauthorized_syscalls") for reason in decision.reasons),
        )

    def test_repair_unit_register_and_apply(self) -> None:
        self.workshop.bootstrap_founding_charter(
            context=self._context(
                actor="authority",
                roles=("trust_administrator", "release_authority"),
            ),
            quorum_proof="founding-quorum",
        )

        register_result = self.workshop.register_repair_unit(
            context=self._context(
                actor="authority",
                roles=("trust_administrator", "release_authority"),
            ),
            component="policy_engine",
            version="1.0.1",
            payload_hash="f" * 64,
            certification_decision_id="decision_certified_1",
            quorum_proof="repair-register-quorum",
        )

        unit_id = register_result["payload"]["repair_unit"]["unit_id"]

        apply_result = self.workshop.apply_repair_unit(
            context=self._context(
                actor="incident",
                roles=("incident_responder", "release_authority"),
            ),
            unit_id=unit_id,
            target_component="policy_engine",
            reason="post-incident hardening",
            quorum_proof="repair-apply-quorum",
        )

        self.assertEqual(apply_result["decision"]["outcome"], "approved")
        self.assertEqual(
            apply_result["payload"]["applied_repair"]["target_component"],
            "policy_engine",
        )


if __name__ == "__main__":
    unittest.main()
