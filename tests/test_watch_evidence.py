from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.errors import WatchError
from zsec_shield.watch_evidence import RotatingNdjsonLog, WatchEvidenceSink


class WatchEvidenceTests(unittest.TestCase):
    def test_evidence_must_stay_below_excluded_state_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(WatchError, "below the excluded state"):
                WatchEvidenceSink(
                    state_dir=root / "state",
                    health_file=root / "outside.json",
                    event_log=None,
                    event_log_max_bytes=64 * 1024,
                    event_log_backups=1,
                    heartbeat_seconds=30,
                )

    def test_ndjson_rotation_is_bounded_and_preserves_complete_records(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            path = state / "companion" / "events.ndjson"
            log = RotatingNdjsonLog(path, state, max_bytes=64 * 1024, backups=2)
            for sequence in range(5):
                log.append(
                    {
                        "schema": "test.watch-event.v1",
                        "sequence": sequence,
                        "payload": "x" * 30_000,
                    }
                )
            candidates = [
                path,
                path.with_name("events.ndjson.1"),
                path.with_name("events.ndjson.2"),
            ]
            existing = [candidate for candidate in candidates if candidate.exists()]
            self.assertEqual(3, len(existing))
            self.assertTrue(all(candidate.stat().st_size <= 64 * 1024 for candidate in existing))
            sequences: set[int] = set()
            for candidate in existing:
                for line in candidate.read_text(encoding="utf-8").splitlines():
                    sequences.add(json.loads(line)["sequence"])
            self.assertEqual({0, 1, 2, 3, 4}, sequences)

    def test_health_snapshot_is_compact_atomic_and_explicitly_non_primary(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            health_path = state / "companion" / "health.json"
            sink = WatchEvidenceSink(
                state_dir=state,
                health_file=health_path,
                event_log=None,
                event_log_max_bytes=64 * 1024,
                event_log_backups=1,
                heartbeat_seconds=30,
            )
            sink.record(
                {
                    "schema": "zsec.shield.watch-event.v1",
                    "version": "0.2.0",
                    "session_id": "test-session",
                    "sequence": 1,
                    "generated_at": "2026-08-21T12:00:00Z",
                    "event": "session_started",
                    "backend_active": "native",
                    "roots": [str(Path(temporary) / "Downloads")],
                    "policy": {
                        "product": "ZSEC Antivirus",
                        "primary_antivirus": False,
                        "real_time_protection": False,
                        "pre_access_enforcement": False,
                    },
                }
            )
            baselining = json.loads(health_path.read_text(encoding="utf-8"))
            sink.record(
                {
                    "schema": "zsec.shield.watch-event.v1",
                    "version": "0.2.0",
                    "session_id": "test-session",
                    "sequence": 2,
                    "generated_at": "2026-08-21T12:00:00Z",
                    "event": "health_heartbeat",
                    "backend_active": "native",
                    "operational_incomplete": False,
                    "reconciliation_phase": "initial_baseline",
                    "stats": {
                        "files_hashed": 0,
                        "reconciliation_files_hashed": 7,
                        "reconciliation_bytes_hashed": 70,
                        "event_queue_capacity": 4096,
                        "event_queue_raw_depth": 3,
                        "event_queue_pending_paths": 2,
                        "event_queue_total_depth": 5,
                    },
                }
            )
            progress = json.loads(health_path.read_text(encoding="utf-8"))
            sink.record(
                {
                    "schema": "zsec.shield.watch-event.v1",
                    "version": "0.2.0",
                    "session_id": "test-session",
                    "sequence": 3,
                    "generated_at": "2026-08-21T12:00:01Z",
                    "event": "scan_completed",
                    "triggers": ["initial_baseline"],
                    "outcome": "no_configured_rule_matches",
                    "scan": {"stats": {"files_hashed": 1, "bytes_hashed": 8}},
                }
            )
            health = json.loads(health_path.read_text(encoding="utf-8"))
        self.assertEqual("zsec.antivirus.companion-health.v1", health["schema"])
        self.assertEqual("ZSEC Antivirus", health["product"])
        self.assertEqual("baselining", baselining["operational_state"])
        self.assertEqual("baselining", progress["operational_state"])
        self.assertEqual(0, progress["counters"]["files_hashed"])
        self.assertEqual(7, progress["counters"]["reconciliation_files_hashed"])
        self.assertEqual(4096, progress["counters"]["event_queue_capacity"])
        self.assertEqual(5, progress["counters"]["event_queue_total_depth"])
        self.assertEqual("healthy", health["operational_state"])
        self.assertEqual("native", health["backend_active"])
        self.assertEqual(str(Path(sys.executable).resolve()), health["runtime_executable"])
        self.assertEqual(64, len(health["runtime_sha256"]))
        self.assertFalse(health["policy"]["primary_antivirus"])
        self.assertFalse(health["policy"]["real_time_protection"])
        self.assertFalse(health["policy"]["pre_access_enforcement"])


if __name__ == "__main__":
    unittest.main()
