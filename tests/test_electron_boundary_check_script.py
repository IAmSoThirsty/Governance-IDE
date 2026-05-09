from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = ROOT / "workbench" / "electron" / "scripts" / "check.js"


class ElectronBoundaryCheckScriptTests(unittest.TestCase):
    def test_check_script_enforces_required_security_boundaries(self) -> None:
        content = CHECK_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("contextIsolation: true", content)
        self.assertIn("nodeIntegration: false", content)
        self.assertIn("sandbox: true", content)
        self.assertIn("main_missing_api_route_allowlist", content)
        self.assertIn("main_missing_route_deny_default", content)
        self.assertIn("preload_must_not_expose_fs_modules", content)
        self.assertIn("renderer_must_not_reference_exec", content)

    def test_check_script_runs_audit_only_when_explicitly_enabled(self) -> None:
        content = CHECK_SCRIPT.read_text(encoding="utf-8")

        self.assertIn('process.env.SOVEREIGN_CHECK_NPM_AUDIT !== "1"', content)
        self.assertIn('"--audit-level=high"', content)
        self.assertIn('"--json"', content)
        self.assertIn("npm_audit_high_or_critical", content)


if __name__ == "__main__":
    unittest.main()
