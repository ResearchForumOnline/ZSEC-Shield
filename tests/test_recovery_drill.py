from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from zsec_shield.cli import EXIT_OK, main
from zsec_shield.recovery_drill import RECOVERY_DRILL_SCHEMA, run_recovery_drill


class RecoveryDrillTests(unittest.TestCase):
    def test_isolated_recovery_drill_passes_all_controls(self) -> None:
        result = run_recovery_drill()

        self.assertEqual(RECOVERY_DRILL_SCHEMA, result["schema"])
        self.assertTrue(result["passed"])
        self.assertFalse(result["independent_certification"])
        self.assertEqual("isolated synthetic data only", result["scope"])
        self.assertEqual(5, result["summary"]["passed"])
        self.assertEqual(0, result["summary"]["failed"])
        self.assertEqual(
            {
                "encrypted_authenticated_copy",
                "authenticated_restore",
                "no_overwrite_restore",
                "ciphertext_tamper_rejected",
                "device_key_loss_and_recovery",
            },
            {check["id"] for check in result["checks"]},
        )

    def test_cli_emits_the_validated_drill_report(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = main(["recovery-drill", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(EXIT_OK, code)
        self.assertEqual(RECOVERY_DRILL_SCHEMA, result["schema"])
        self.assertTrue(result["passed"])


if __name__ == "__main__":
    unittest.main()
