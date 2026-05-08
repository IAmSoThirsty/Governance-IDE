from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sovereign_ide.app_catalog import (  # noqa: E402
    AppCatalogError,
    filter_app_catalog,
    load_app_catalog,
    validate_app_catalog,
)
from sovereign_ide.cli import build_parser  # noqa: E402


def _catalog() -> dict:
    return {
        "version": "1.0.0",
        "apps": [
            {
                "id": "runtime-service-api",
                "display_name": "Runtime Service API",
                "category": "core",
                "status": "enabled",
                "description": "HTTP runtime surface.",
                "surfaces": [{"type": "api", "ref": "/v1/apps"}],
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
                "surfaces": [{"type": "cli", "ref": "workshop-train"}],
                "requirements": ["SOVEREIGN_TRAINING_COMMAND"],
                "governance_actions": ["start_training_run"],
                "tags": ["training"],
            },
        ],
    }


class AppCatalogTests(unittest.TestCase):
    def test_catalog_loads_sorted_and_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deployments").mkdir()
            (root / "deployments" / "app_catalog.json").write_text(
                json.dumps(_catalog()),
                encoding="utf-8",
            )

            catalog = load_app_catalog(root)
            self.assertEqual(catalog["app_count"], 2)
            self.assertEqual(catalog["apps"][0]["id"], "runtime-service-api")

            filtered = filter_app_catalog(
                catalog,
                category="modeling",
                status="requires_configuration",
            )
            self.assertEqual(filtered["app_count"], 1)
            self.assertEqual(filtered["apps"][0]["id"], "workshop-model-training")

    def test_catalog_rejects_duplicate_ids(self) -> None:
        catalog = _catalog()
        catalog["apps"].append(dict(catalog["apps"][0]))

        with self.assertRaises(AppCatalogError):
            validate_app_catalog(catalog)

    def test_apps_list_cli_outputs_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deployments").mkdir()
            (root / "deployments" / "app_catalog.json").write_text(
                json.dumps(_catalog()),
                encoding="utf-8",
            )
            parser = build_parser()
            args = parser.parse_args(
                [
                    "apps-list",
                    "--workspace-root",
                    str(root),
                    "--status",
                    "requires_configuration",
                ],
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(args.func(args), 0)

            payload = json.loads(output.getvalue())
            self.assertEqual(payload["app_count"], 1)
            self.assertEqual(payload["apps"][0]["id"], "workshop-model-training")


if __name__ == "__main__":
    unittest.main()
