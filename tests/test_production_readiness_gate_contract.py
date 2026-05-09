from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = ROOT / "scripts" / "production_readiness_gate.ps1"


class ProductionReadinessGateContractTests(unittest.TestCase):
    def test_gate_script_declares_block_categories(self) -> None:
        content = GATE_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("repo-code blocked", content)
        self.assertIn("environment blocked", content)
        self.assertIn("production-evidence blocked", content)
        self.assertIn("dependency-security blocked", content)

    def test_rehearsal_output_is_explicit_and_non_production(self) -> None:
        content = GATE_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("Rehearsal override gate passed (no production-readiness claim)", content)
        self.assertIn("Active overrides", content)
        self.assertIn("Overridden evidence", content)


if __name__ == "__main__":
    unittest.main()
