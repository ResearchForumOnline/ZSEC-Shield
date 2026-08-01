from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.status_store import load_last_scan, save_last_scan


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
                outcome="configured_rule_matches_detected",
            )
            value, error = load_last_scan(state)
            self.assertIsNone(error)
            assert value is not None
            self.assertEqual(2, value["findings"])
            self.assertEqual("2026-08-01T12:00:00Z", value["completed_at"])


if __name__ == "__main__":
    unittest.main()
