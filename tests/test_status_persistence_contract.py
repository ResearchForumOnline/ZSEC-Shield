from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.cli import EXIT_INCOMPLETE, EXIT_OK, main


class StatusPersistenceContractTests(unittest.TestCase):
    def test_completed_check_populates_bridge_fields(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            scan = root / "scan"
            scan.mkdir()
            (scan / "clean.txt").write_text("ordinary content", encoding="utf-8")

            with redirect_stdout(StringIO()):
                check_code = main(["--state-dir", str(state), "check", str(scan), "--json"])
            self.assertEqual(EXIT_OK, check_code)

            output = StringIO()
            with redirect_stdout(output):
                status_code = main(["--state-dir", str(state), "status", "--json"])
            self.assertEqual(EXIT_OK, status_code)
            payload = json.loads(output.getvalue())
            self.assertEqual("zsec.shield.status.v2", payload["schema"])
            self.assertEqual(2, payload["contract_version"])
            self.assertIsInstance(payload["last_scan"], str)
            self.assertTrue(payload["last_scan"].endswith("Z"))
            self.assertEqual("no_configured_rule_matches", payload["last_scan_outcome"])
            self.assertEqual(0, payload["last_scan_errors"])
            self.assertEqual(1, payload["last_scan_files_hashed"])
            self.assertEqual(16, payload["last_scan_bytes_hashed"])
            self.assertEqual(0, payload["findings"])
            self.assertEqual(0, payload["quarantine_count"])
            self.assertTrue(payload["last_scan_diagnostic"]["available"])
            self.assertIsNone(payload["last_scan_diagnostic"]["error"])

    def test_incomplete_check_remains_incomplete_in_persisted_status(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            missing = root / "does-not-exist"

            with redirect_stdout(StringIO()):
                check_code = main(["--state-dir", str(state), "check", str(missing), "--json"])
            self.assertEqual(EXIT_INCOMPLETE, check_code)

            output = StringIO()
            with redirect_stdout(output):
                status_code = main(["--state-dir", str(state), "status", "--json"])
            self.assertEqual(EXIT_OK, status_code)
            payload = json.loads(output.getvalue())
            self.assertEqual("zsec.shield.status.v2", payload["schema"])
            self.assertEqual("incomplete", payload["last_scan_outcome"])
            self.assertGreaterEqual(payload["last_scan_errors"], 1)
            self.assertEqual(0, payload["last_scan_files_hashed"])
            self.assertEqual(0, payload["last_scan_bytes_hashed"])
            self.assertEqual(0, payload["findings"])


if __name__ == "__main__":
    unittest.main()
