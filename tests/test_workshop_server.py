from __future__ import annotations

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

from sovereign_ide.config import get_settings  # noqa: E402
from sovereign_ide.models import GovernanceContext, new_id  # noqa: E402
from sovereign_ide.model_registry import GovernedModelRegistry  # noqa: E402
from sovereign_ide.service import request_execution_ticket  # noqa: E402
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

    def _register_base_model(self, *, trust_level: str = "reviewed") -> str:
        settings = get_settings(self.root)
        registry = GovernedModelRegistry(settings.model_registry_path)
        base_model_path = self.root / "base_model.bin"
        base_model_path.write_text("base-weights", encoding="utf-8")
        record = registry.register(
            source_type="local_path",
            source=str(base_model_path),
            license="test-license",
            content_hash=GovernedModelRegistry.hash_local_path(base_model_path),
            immutable_identifier="base-model:sha256",
            metadata={"family": "base"},
            trust_level=trust_level,
            policy_profile="default-model-policy",
            provenance_ref="provenance://base_model.bin",
        )
        return record.model_id

    def _issue_base_model_ticket(self, model_id: str) -> tuple[dict, str]:
        response = request_execution_ticket(
            self.root,
            context=self._context(
                actor="steward",
                roles=("model_steward",),
            ),
            model_id=model_id,
            ticket_purpose="fine_tuning_base_model",
            ticket_ttl_seconds=900,
        )
        self.assertTrue(response["allowed"], msg=response)
        decision = response.get("decision") or {}
        decision_id = str(decision.get("decision_id") or "")
        return response["payload"]["execution_ticket"], decision_id

    def _actual_training_kwargs(
        self,
        *,
        dataset_ids: tuple[str, ...],
        base_model_id: str,
        base_ticket: dict,
        **overrides: object,
    ) -> dict:
        kwargs: dict[str, object] = {
            "model_family": "project-ai-constitutional-actual",
            "base_checkpoint": None,
            "dataset_ids": dataset_ids,
            "quorum_proof": "train-quorum",
            "execution_mode": "actual",
            "training_command": '"python" "-V"',
            "base_model_id": base_model_id,
            "base_model_execution_ticket": base_ticket,
            "policy_profile": "workshop-fine-tuned-model",
            "trust_level": "reviewed",
            "artifact_store_uri": "https://huggingface.co/example/model",
            "trainer_backend": "huggingface-jobs",
        }
        kwargs.update(overrides)
        return kwargs

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
                simulation_smoke_test=True,
            )
            checkpoint_id = train_result["payload"]["checkpoint"]["checkpoint_id"]

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
            simulation_smoke_test=True,
        )

        self.assertEqual(
            train_result["payload"]["run"]["status"],
            "simulated_completed",
        )
        self.assertEqual(
            train_result["payload"]["run"]["execution_mode"],
            "simulated",
        )
        self.assertEqual(train_result["payload"]["mode"], "simulation")
        self.assertIsNone(train_result["payload"]["governed_model"])
        report = self.workshop.export_workshop_report()
        self.assertEqual(report["readiness_level"], "prototype")
        self.assertTrue(report["training_is_simulated"])
        self.assertIn("simulated", report["training_execution_modes"])

    def test_simulation_requires_explicit_smoke_test_flag(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                model_family="project-ai-constitutional-simulated",
                base_checkpoint=None,
                dataset_ids=dataset_ids,
                quorum_proof="train-quorum",
                execution_mode="simulated",
                simulation_smoke_test=False,
            )
        self.assertIn("simulation_flag_required", str(raised.exception))

    def test_simulation_writes_audit_events_and_not_checkpoint_registered(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        context = self._context(
            actor="trainer",
            roles=("model_steward", "release_authority"),
        )
        result = self.workshop.start_training_run(
            context=context,
            model_family="project-ai-constitutional-simulated",
            base_checkpoint=None,
            dataset_ids=dataset_ids,
            quorum_proof="train-quorum",
            execution_mode="simulated",
            simulation_smoke_test=True,
        )
        self.assertEqual(result["payload"]["mode"], "simulation")
        self.assertIsNone(result["payload"]["governed_model"])

        replay = self.workshop.runtime.replay_trace(context.trace_id)
        record_types = {entry["record_type"] for entry in replay}
        self.assertIn("training_preflight_allowed", record_types)
        self.assertIn("simulation_started", record_types)
        self.assertIn("simulation_completed", record_types)
        self.assertNotIn("checkpoint_registered", record_types)

    def test_actual_training_preflight_allows_with_required_evidence(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)

        preflight = self.workshop.preflight_training_run(
            context=self._context(
                actor="trainer",
                roles=("model_steward", "release_authority"),
            ),
            model_family="project-ai-constitutional-actual",
            base_checkpoint=None,
            dataset_ids=dataset_ids,
            execution_mode="actual",
            simulation_smoke_test=False,
            training_command='"python" "-V"',
            training_backend="huggingface-jobs",
            artifact_store_uri="https://huggingface.co/example/model",
            base_model_id=base_model_id,
            base_model_execution_ticket=base_ticket,
            base_model_admissibility_decision_id=None,
            dataset_ref=None,
            dataset_provenance=None,
            dataset_source_type=None,
            dataset_license=None,
            dataset_hash=None,
            dataset_immutable_ref=None,
            dataset_immutable_proof=None,
            policy_profile="workshop-fine-tuned-model",
            trust_level="reviewed",
        )
        self.assertTrue(preflight["allowed"], msg=preflight)
        self.assertEqual(preflight["mode"], "actual_training")
        self.assertEqual(preflight["reason"], "ok")

    def test_actual_training_denied_without_registered_base_model(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id="",
                    base_ticket={},
                    base_model_execution_ticket=None,
                ),
            )
        self.assertIn("base_model_missing", str(raised.exception))

    def test_actual_training_denied_without_dataset_reference(self) -> None:
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=tuple(),
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                ),
            )
        self.assertIn("dataset_reference_missing", str(raised.exception))

    def test_actual_training_denied_without_dataset_provenance(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)

        dataset_index = json.loads(
            self.workshop.paths.dataset_index.read_text(encoding="utf-8")
        )
        dataset_path = Path(dataset_index["datasets"][0]["path"])
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        payload.setdefault("governance", {})["provenance_ref"] = ""
        dataset_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        dataset_index["datasets"][0]["dataset_provenance"] = ""
        self.workshop.paths.dataset_index.write_text(
            json.dumps(dataset_index, indent=2),
            encoding="utf-8",
        )

        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                ),
            )
        self.assertIn("dataset_provenance_missing", str(raised.exception))

    def test_actual_training_denied_without_artifact_store(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)

        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                    artifact_store_uri="",
                ),
            )
        self.assertIn("artifact_store_missing", str(raised.exception))

    def test_actual_training_denied_without_policy_profile(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)

        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                    policy_profile="",
                ),
            )
        self.assertIn("policy_profile_missing", str(raised.exception))

    def test_actual_training_denied_when_mutable_dataset_lacks_immutable_proof(
        self,
    ) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)

        dataset_index = json.loads(
            self.workshop.paths.dataset_index.read_text(encoding="utf-8")
        )
        dataset_path = Path(dataset_index["datasets"][0]["path"])
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        governance = payload.setdefault("governance", {})
        governance["source_type"] = "external_registry"
        governance["mutable_reference"] = True
        governance["immutable_proof"] = ""
        dataset_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        dataset_index["datasets"][0]["dataset_source_type"] = "external_registry"
        dataset_index["datasets"][0]["mutable_reference"] = True
        dataset_index["datasets"][0]["immutable_proof"] = ""
        self.workshop.paths.dataset_index.write_text(
            json.dumps(dataset_index, indent=2),
            encoding="utf-8",
        )

        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                ),
            )
        self.assertIn("mutable_dataset_requires_immutable_proof", str(raised.exception))

    def test_actual_training_denied_when_base_model_lacks_admissibility(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model(trust_level="quarantine")

        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=self._context(
                    actor="trainer",
                    roles=("model_steward", "release_authority"),
                ),
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket={},
                    base_model_execution_ticket=None,
                    base_model_admissibility_decision_id="decision_fake",
                ),
            )
        self.assertIn("base_model_insufficient_trust", str(raised.exception))

    def test_actual_training_requires_configured_trainer(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
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
                training_command='"python" "-V"',
                base_model_id=base_model_id,
                base_model_execution_ticket=base_ticket,
                policy_profile="workshop-fine-tuned-model",
                trust_level="reviewed",
                artifact_store_uri="https://huggingface.co/example/model",
                trainer_backend="",
            )
        self.assertIn("trainer_backend_missing", str(raised.exception))

    def test_actual_training_uses_trainer_output_manifest(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
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
                    "artifact_store = request['artifact_store_uri']",
                    "Path(args.output).write_text(json.dumps({",
                    "    'status': 'completed',",
                    "    'checkpoint_id': 'checkpoint_actual_test',",
                    "    'artifact_uri': artifact_store,",
                    "    'artifact_store_uri': artifact_store,",
                    "    'checkpoint_hash': digest,",
                    "}))",
                ],
            ),
            encoding="utf-8",
        )

        context = self._context(
            actor="trainer",
            roles=("model_steward", "release_authority"),
        )

        train_result = self.workshop.start_training_run(
            context=context,
            model_family="project-ai-constitutional-actual",
            base_checkpoint=None,
            dataset_ids=dataset_ids,
            quorum_proof="train-quorum",
            execution_mode="actual",
            training_command=f'"{sys.executable}" "{trainer_path}"',
            base_model_id=base_model_id,
            base_model_execution_ticket=base_ticket,
            policy_profile="workshop-fine-tuned-model",
            trust_level="reviewed",
            artifact_store_uri="https://huggingface.co/example/model-actual",
            trainer_backend="huggingface-jobs",
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
        governed_model = train_result["payload"]["governed_model"]
        self.assertEqual(
            governed_model["metadata"]["base_model_reference"],
            base_model_id,
        )
        self.assertTrue(governed_model["metadata"]["dataset_references"])
        self.assertTrue(governed_model["metadata"]["training_config_hash"])

        replay = self.workshop.runtime.replay_trace(context.trace_id)
        record_types = [entry["record_type"] for entry in replay]
        self.assertIn("training_preflight_allowed", record_types)
        self.assertIn("training_started", record_types)
        self.assertIn("training_completed", record_types)
        self.assertIn("checkpoint_registered", record_types)

    def test_actual_training_rejects_local_artifact_when_store_configured(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
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
                    base_model_id=base_model_id,
                    base_model_execution_ticket=base_ticket,
                    policy_profile="workshop-fine-tuned-model",
                    trust_level="reviewed",
                    trainer_backend="huggingface-jobs",
                )
        self.assertIn("durable storage", str(raised.exception))

    def test_actual_training_request_carries_artifact_store_contract(self) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
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
                base_model_id=base_model_id,
                base_model_execution_ticket=base_ticket,
                policy_profile="workshop-fine-tuned-model",
                trust_level="reviewed",
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

    def test_failed_actual_training_records_failure_and_skips_checkpoint_registration(
        self,
    ) -> None:
        dataset_ids = self._bootstrap_and_prepare_datasets()
        base_model_id = self._register_base_model()
        base_ticket, _ = self._issue_base_model_ticket(base_model_id)
        trainer_path = self.root / "failing_trainer.py"
        trainer_path.write_text(
            "\n".join(
                [
                    "import sys",
                    "raise SystemExit(2)",
                ],
            ),
            encoding="utf-8",
        )

        context = self._context(
            actor="trainer",
            roles=("model_steward", "release_authority"),
        )
        with self.assertRaises(PolicyViolation) as raised:
            self.workshop.start_training_run(
                context=context,
                **self._actual_training_kwargs(
                    dataset_ids=dataset_ids,
                    base_model_id=base_model_id,
                    base_ticket=base_ticket,
                    training_command=f'"{sys.executable}" "{trainer_path}"',
                ),
            )
        self.assertIn("training_execution_failed", str(raised.exception))

        replay = self.workshop.runtime.replay_trace(context.trace_id)
        record_types = [entry["record_type"] for entry in replay]
        self.assertIn("training_failed", record_types)
        self.assertNotIn("checkpoint_registered", record_types)

        registry = GovernedModelRegistry(get_settings(self.root).model_registry_path)
        fine_tuned_entries = [
            model
            for model in registry.list()
            if model.source_type == "fine_tuned_checkpoint"
        ]
        self.assertEqual(fine_tuned_entries, [])

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
            any(
                reason.startswith("unauthorized_syscalls")
                for reason in decision.reasons
            ),
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
