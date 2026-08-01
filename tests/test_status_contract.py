from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.cli import EXIT_OK, main


class StatusContractTests(unittest.TestCase):
    def test_desktop_bridge_contract_v1(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--state-dir", str(state), "status", "--json"])
            self.assertEqual(EXIT_OK, code)
            payload = json.loads(output.getvalue())
            self.assertEqual(1, payload["contract_version"])
            self.assertIsInstance(payload["version"], str)
            self.assertIsInstance(payload["platform"], str)
            self.assertIsInstance(payload["definitions"], str)
            self.assertIn("built-in:", payload["definitions"])
            self.assertIsNone(payload["last_scan"])
            self.assertEqual(0, payload["findings"])
            self.assertIsInstance(payload["quarantine_count"], int)
            self.assertEqual(payload["quarantine"]["entries"], payload["quarantine_count"])


if __name__ == "__main__":
    unittest.main()
