from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from zsec_shield.cli import EXIT_FINDINGS, EXIT_OK, main
from zsec_shield.models import Rule


class StatusScanIntegrationTests(unittest.TestCase):
    def test_status_reports_evidence_from_last_completed_scan(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            scan = root / "scan"
            scan.mkdir()
            marker = b"zsec-shield-benign-status-test-marker"
            (scan / "sample.bin").write_bytes(marker)
            test_rule = Rule(
                "test:status-marker",
                "Benign status test marker",
                "literal",
                "medium",
                "Synthetic rule used only by the integration test.",
                "test suite",
                literal=marker,
            )

            with (
                patch("zsec_shield.cli.builtin_rules", return_value=(test_rule,)),
                redirect_stdout(StringIO()),
            ):
                scan_code = main(["--state-dir", str(state), "check", str(scan), "--json"])
            self.assertEqual(EXIT_FINDINGS, scan_code)

            output = StringIO()
            with redirect_stdout(output):
                status_code = main(["--state-dir", str(state), "status", "--json"])
            self.assertEqual(EXIT_OK, status_code)
            payload = json.loads(output.getvalue())
            self.assertEqual("zsec.shield.status.v1", payload["schema"])
            self.assertEqual(1, payload["contract_version"])
            self.assertIsInstance(payload["last_scan"], str)
            self.assertEqual(1, payload["findings"])
            self.assertTrue(payload["last_scan_diagnostic"]["available"])
            self.assertIsNone(payload["last_scan_diagnostic"]["error"])


if __name__ == "__main__":
    unittest.main()
