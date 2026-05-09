from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sovereign_ide.production_evidence import (  # noqa: E402
    CLASSIFICATION_PRODUCTION_READY_PASS,
    CLASSIFICATION_REHEARSAL_ONLY_PASS,
    CATEGORY_DEPENDENCY_SECURITY_BLOCKED,
    CATEGORY_ENVIRONMENT_BLOCKED,
    CATEGORY_PRODUCTION_EVIDENCE_BLOCKED,
    evaluate_production_evidence,
)


class ProductionEvidenceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temp_dir.name).resolve()
        self.key_path = self.workspace_root / "keys" / "ed25519_private.pem"
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_text(
            "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",
            encoding="utf-8",
        )

        self.manifest_path = self.workspace_root / "production_evidence_manifest.json"
        self.manifest_path.write_text(
            json.dumps(self._manifest(), indent=2),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _env(self, **overrides: str) -> dict[str, str]:
        base = {
            "SOVEREIGN_RUNTIME_MODE": "production",
            "SOVEREIGN_SIGNER_BACKEND": "ed25519",
            "SOVEREIGN_ED25519_PRIVATE_KEY_PATH": str(self.key_path),
            "SOVEREIGN_SERVICE_TOKEN": "service-token-very-long-value",
            "SOVEREIGN_SECRET_SOURCE": "azure_key_vault",
            "SOVEREIGN_IMAGE_REF": "registry.example.com/sovereign/sovereign-ide-runtime:0.2.0",
            "SOVEREIGN_IMAGE_DIGEST": "sha256:" + ("a" * 64),
            "SOVEREIGN_TRAINING_ARTIFACT_STORE": "https://huggingface.co/org/model",
            "SOVEREIGN_TRAINING_BACKEND": "huggingface-jobs",
            "SOVEREIGN_STATE_BACKEND": "persistent_volume",
            "SOVEREIGN_STATE_URI": "pvc://sovereign-ide-state",
            "SOVEREIGN_JOURNAL_BACKEND": "sqlite",
            "SOVEREIGN_PRODUCTION_EVIDENCE_MANIFEST": str(self.manifest_path),
        }
        base.update(overrides)
        return base

    def _manifest(self, **overrides: str) -> dict[str, str]:
        manifest = {
            "manifest_type": "production_evidence",
            "schema_version": "1.0.0",
            "release_commit": "7344a9f",
            "release_tag": "v0.2.0",
            "registry_image_ref": "registry.example.com/sovereign/sovereign-ide-runtime:0.2.0",
            "image_digest": "sha256:" + ("a" * 64),
            "runtime_mode": "production",
            "signer_type": "ed25519",
            "ed25519_key_source_type": "file_path",
            "secret_source": "azure_key_vault",
            "artifact_store_backend": "huggingface",
            "trainer_backend": "huggingface-jobs",
            "storage_backend": "persistent_volume",
            "audit_journal_backend": "sqlite",
            "ci_run_id": "gha:123456",
            "build_timestamp": "2026-05-09T14:00:00+00:00",
            "sbom_location": "https://artifacts.example.com/sbom.spdx.json",
            "dependency_scan_result_location": "https://artifacts.example.com/dependency-scan.json",
            "dependency_scan_status": "pass",
        }
        manifest.update(overrides)
        return manifest

    def test_manifest_validation_success(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(),
            manifest_path=self.manifest_path,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.classification, CLASSIFICATION_PRODUCTION_READY_PASS)
        self.assertEqual(result.issues, tuple())

    def test_missing_manifest_denied(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(),
            manifest_path=self.workspace_root / "missing_manifest.json",
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_PRODUCTION_EVIDENCE_BLOCKED)
        self.assertTrue(
            any(issue.code == "manifest_not_found" for issue in result.issues)
        )

    def test_local_image_denied_for_production(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(SOVEREIGN_IMAGE_REF="localhost/sovereign-ide-runtime:local"),
            manifest_path=self.manifest_path,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_ENVIRONMENT_BLOCKED)
        self.assertTrue(any(issue.code == "image_ref_local" for issue in result.issues))

    def test_missing_digest_denied(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(SOVEREIGN_IMAGE_DIGEST=""),
            manifest_path=self.manifest_path,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_ENVIRONMENT_BLOCKED)
        self.assertTrue(
            any(issue.code == "image_digest_missing" for issue in result.issues)
        )

    def test_hmac_dev_denied_for_production(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(SOVEREIGN_SIGNER_BACKEND="hmac-dev"),
            manifest_path=self.manifest_path,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_ENVIRONMENT_BLOCKED)
        self.assertTrue(
            any(issue.code == "signer_backend_not_ed25519" for issue in result.issues)
        )

    def test_missing_ed25519_evidence_denied(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(
                SOVEREIGN_ED25519_PRIVATE_KEY_PATH="",
                SOVEREIGN_ED25519_PRIVATE_KEY_PEM="",
            ),
            manifest_path=self.manifest_path,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_ENVIRONMENT_BLOCKED)
        self.assertTrue(
            any(issue.code == "ed25519_key_source_missing" for issue in result.issues)
        )

    def test_rehearsal_override_is_explicit_and_non_production(self) -> None:
        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(),
            manifest_path=self.workspace_root / "missing_manifest.json",
            allow_local_env_file=True,
            allow_local_image=True,
            allow_missing_manifest=True,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.classification, CLASSIFICATION_REHEARSAL_ONLY_PASS)
        self.assertFalse(result.production_claim)
        self.assertIn("-AllowLocalEnvFile", result.overrides_active)
        self.assertIn("-AllowLocalImage", result.overrides_active)
        self.assertIn("-AllowMissingReleaseManifest", result.overrides_active)

    def test_dependency_security_failure_classification(self) -> None:
        manifest_with_failed_scan = self._manifest(dependency_scan_status="fail")
        self.manifest_path.write_text(
            json.dumps(manifest_with_failed_scan), encoding="utf-8"
        )

        result = evaluate_production_evidence(
            workspace_root=self.workspace_root,
            env=self._env(),
            manifest_path=self.manifest_path,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.classification, CATEGORY_DEPENDENCY_SECURITY_BLOCKED)
        self.assertTrue(
            any(
                issue.code.startswith("dependency_scan_status")
                for issue in result.issues
            )
        )


if __name__ == "__main__":
    unittest.main()
