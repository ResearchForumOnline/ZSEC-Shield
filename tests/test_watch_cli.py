from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from zsec_shield.cli import EXIT_FINDINGS, EXIT_INCOMPLETE, main
from zsec_shield.models import Rule
from zsec_shield.quarantine import list_entries


def cli_rule() -> Rule:
    return Rule(
        rule_id="test:watch-cli",
        name="Watch CLI marker",
        kind="literal",
        severity="high",
        description="Benign watch CLI marker.",
        source="test suite",
        literal=b"zsec-watch-cli-test",
    )


class WatchCliTests(unittest.TestCase):
    def test_json_lines_contract_and_default_no_quarantine(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan_root = root / "scan"
            scan_root.mkdir()
            target = scan_root / "marker.bin"
            target.write_bytes(cli_rule().literal or b"")
            output = StringIO()
            with (
                patch("zsec_shield.cli.builtin_rules", return_value=(cli_rule(),)),
                redirect_stdout(output),
            ):
                code = main(
                    [
                        "--state-dir",
                        str(root / "state"),
                        "watch",
                        str(scan_root),
                        "--backend",
                        "polling",
                        "--duration-seconds",
                        "0.1",
                        "--json-lines",
                    ]
                )
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            target_exists = target.exists()
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertTrue(target_exists)
        self.assertEqual("session_started", records[0]["event"])
        self.assertEqual("session_completed", records[-1]["event"])
        self.assertEqual(
            list(range(1, len(records) + 1)), [record["sequence"] for record in records]
        )
        self.assertEqual(1, len({record["session_id"] for record in records}))
        self.assertFalse(records[0]["policy"]["primary_antivirus"])
        self.assertFalse(records[0]["policy"]["quarantine_requested"])

    def test_quarantine_only_happens_with_explicit_flag_and_uses_zba_vault(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan_root = root / "scan"
            state_dir = root / "state"
            scan_root.mkdir()
            target = scan_root / "marker.bin"
            target.write_bytes(cli_rule().literal or b"")
            output = StringIO()
            with (
                patch("zsec_shield.cli.builtin_rules", return_value=(cli_rule(),)),
                redirect_stdout(output),
            ):
                code = main(
                    [
                        "--state-dir",
                        str(state_dir),
                        "protect",
                        str(scan_root),
                        "--backend",
                        "polling",
                        "--duration-seconds",
                        "0.1",
                        "--quarantine",
                        "--json-lines",
                    ]
                )
            records, errors = list_entries(state_dir)
            metadata = json.loads(
                (
                    state_dir
                    / "quarantine"
                    / "entries"
                    / records[0]["id"]
                    / "metadata.json"
                ).read_text(encoding="utf-8")
            )
            target_exists = target.exists()
        self.assertEqual(EXIT_FINDINGS, code)
        self.assertFalse(target_exists)
        self.assertEqual([], errors)
        self.assertEqual("zero.security.zba.quarantine.v1", metadata["zba"]["spec"])
        self.assertEqual("boundary", metadata["zba"]["phase"])
        self.assertEqual("sealed", metadata["zba"]["evidence_status"])

    def test_invalid_feed_refuses_before_watching(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            scan_root = root / "scan"
            state_dir = root / "state"
            scan_root.mkdir()
            feed_dir = state_dir / "feed"
            feed_dir.mkdir(parents=True)
            (feed_dir / "current.json").write_text("{}", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "--state-dir",
                        str(state_dir),
                        "watch",
                        str(scan_root),
                        "--duration-seconds",
                        "0.1",
                        "--json-lines",
                    ]
                )
            error = json.loads(output.getvalue())
        self.assertEqual(EXIT_INCOMPLETE, code)
        self.assertEqual("WatchError", error["error"])
        self.assertIn("refused to start", error["message"])


if __name__ == "__main__":
    unittest.main()
