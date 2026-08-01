from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import literal_rule, make_signing_material, signed_feed
from zsec_shield.cli import EXIT_FINDINGS, EXIT_OK, main


class CliUpdateTests(unittest.TestCase):
    def test_signed_update_is_used_by_check_and_reported_by_status(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            scan = root / "scan"
            scan.mkdir()
            private_key, keyring = make_signing_material(root)
            feed = root / "feed.json"
            pattern = b"benign-cli-feed-pattern"
            feed.write_bytes(
                signed_feed(
                    private_key,
                    sequence=7,
                    rules=[literal_rule("feed:cli-pattern", pattern)],
                )
            )

            update_output = StringIO()
            with redirect_stdout(update_output):
                update_code = main(
                    [
                        "--state-dir",
                        str(state),
                        "--keyring",
                        str(keyring),
                        "update",
                        "--file",
                        str(feed),
                        "--json",
                    ]
                )
            self.assertEqual(EXIT_OK, update_code)
            self.assertEqual(7, json.loads(update_output.getvalue())["sequence"])

            target = scan / "sample.bin"
            target.write_bytes(b"prefix-" + pattern + b"-suffix")
            check_output = StringIO()
            with redirect_stdout(check_output):
                check_code = main(
                    [
                        "--state-dir",
                        str(state),
                        "--keyring",
                        str(keyring),
                        "check",
                        str(scan),
                        "--json",
                    ]
                )
            self.assertEqual(EXIT_FINDINGS, check_code)
            report = json.loads(check_output.getvalue())
            self.assertEqual("feed:cli-pattern", report["scan"]["findings"][0]["matches"][0]["id"])

            status_output = StringIO()
            with redirect_stdout(status_output):
                status_code = main(
                    [
                        "--state-dir",
                        str(state),
                        "--keyring",
                        str(keyring),
                        "status",
                        "--json",
                    ]
                )
            self.assertEqual(EXIT_OK, status_code)
            status = json.loads(status_output.getvalue())
            self.assertEqual(1, status["findings"])
            self.assertIn("sequence-7", status["definitions"])


if __name__ == "__main__":
    unittest.main()
