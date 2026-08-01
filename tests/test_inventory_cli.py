from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.cli import EXIT_OK, main
from zsec_shield.inventory import collect_inventory, select_adapter
from zsec_shield.inventory.windows import windows_marketing_name


class InventoryAndCliTests(unittest.TestCase):
    def test_inventory_is_explicitly_read_only(self) -> None:
        inventory = collect_inventory()
        self.assertEqual("zsec.shield.inventory.v1", inventory["schema"])
        self.assertTrue(inventory["read_only"])
        self.assertIn(inventory["adapter"], {"windows", "macos", "linux", "generic"})

    def test_adapter_selection_and_windows_build_mapping(self) -> None:
        self.assertEqual("windows", select_adapter("Windows").adapter_name)
        self.assertEqual("macos", select_adapter("Darwin").adapter_name)
        self.assertEqual("linux", select_adapter("Linux").adapter_name)
        self.assertEqual("Windows 10", windows_marketing_name(19045))
        self.assertEqual("Windows 11", windows_marketing_name(22631))

    def test_clean_check_emits_structured_json(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan = root / "scan"
            scan.mkdir()
            (scan / "clean.txt").write_text("ordinary", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--state-dir", str(root / "state"), "check", str(scan), "--json"])
            self.assertEqual(EXIT_OK, code)
            report = json.loads(output.getvalue())
            self.assertEqual("zsec.shield.report.v1", report["schema"])
            self.assertEqual("no_configured_rule_matches", report["outcome"])
            self.assertFalse(report["policy"]["real_time_protection"])
            self.assertEqual("absent", report["feed"]["state"])

    def test_status_does_not_create_state_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "not-created"
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--state-dir", str(state), "status", "--json"])
            self.assertEqual(EXIT_OK, code)
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
