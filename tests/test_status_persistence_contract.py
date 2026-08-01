from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.cli import EXIT_OK, main


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
            self.assertIsInstance(payload["last_scan"], str)
            self.assertTrue(payload["last_scan"].endswith("Z"))
            self.assertEqual(0, payload["findings"])
            self.assertEqual(0, payload["quarantine_count"])
            self.assertTrue(payload["last_scan_diagnostic"]["available"])
            self.assertIsNone(payload["last_scan_diagnostic"]["error"])


if __name__ == "__main__":
    unittest.main()
