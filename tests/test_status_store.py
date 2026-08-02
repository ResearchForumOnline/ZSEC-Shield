from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.status_store import last_scan_path, load_last_scan, save_last_scan


class StatusStoreTests(unittest.TestCase):
    def test_round_trip_and_missing_state(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.assertEqual((None, None), load_last_scan(state))
            save_last_scan(
                state,
                completed_at="2026-08-01T12:00:00Z",
                findings=2,
                issues=0,
                files_hashed=12,
                bytes_hashed=3456,
                outcome="configured_rule_matches_detected",
            )
            value, error = load_last_scan(state)
            self.assertIsNone(error)
            assert value is not None
            self.assertEqual(2, value["findings"])
            self.assertEqual(12, value["files_hashed"])
            self.assertEqual(3456, value["bytes_hashed"])
            self.assertEqual("2026-08-01T12:00:00Z", value["completed_at"])

    def test_legacy_v1_summary_is_migrated_without_invented_metrics(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            path = last_scan_path(state)
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "schema": "zsec.shield.last-scan.v1",
                        "completed_at": "2026-08-01T12:00:00Z",
                        "findings": 0,
                        "issues": 0,
                        "outcome": "no_configured_rule_matches",
                    }
                ),
                encoding="utf-8",
            )
            value, error = load_last_scan(state)
            self.assertIsNone(error)
            assert value is not None
            self.assertEqual("zsec.shield.last-scan.v1", value["schema"])
            self.assertIsNone(value["files_hashed"])
            self.assertIsNone(value["bytes_hashed"])

    def test_invalid_v2_counters_outcomes_and_invariants_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            path = last_scan_path(state)
            path.parent.mkdir(parents=True)
            base = {
                "schema": "zsec.shield.last-scan.v2",
                "completed_at": "2026-08-01T12:00:00Z",
                "findings": 0,
                "issues": 0,
                "files_hashed": 1,
                "bytes_hashed": 10,
                "outcome": "no_configured_rule_matches",
            }
            cases = (
                ("negative metric", {**base, "files_hashed": -1}, "counters"),
                ("boolean metric", {**base, "bytes_hashed": True}, "counters"),
                ("unknown outcome", {**base, "outcome": "clean"}, "outcome"),
                ("false clean outcome", {**base, "findings": 1}, "inconsistent"),
                (
                    "empty finding outcome",
                    {**base, "outcome": "configured_rule_matches_detected"},
                    "inconsistent",
                ),
            )
            for name, payload, error_fragment in cases:
                with self.subTest(name=name):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    value, error = load_last_scan(state)
                    self.assertIsNone(value)
                    self.assertIsInstance(error, str)
                    self.assertIn(error_fragment, error)


if __name__ == "__main__":
    unittest.main()
