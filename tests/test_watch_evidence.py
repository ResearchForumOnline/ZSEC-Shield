from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from zsec_shield.errors import WatchError
from zsec_shield.watch_evidence import (
    HEALTH_WRITE_RETRY_DELAYS_SECONDS,
    RotatingNdjsonLog,
    WatchEvidenceSink,
)


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
            inventorying = json.loads(health_path.read_text(encoding="utf-8"))
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
                    "reconciliation_phase": "initial_metadata_inventory",
                    "stats": {
                        "files_hashed": 0,
                        "reconciliation_files_hashed": 0,
                        "reconciliation_bytes_hashed": 0,
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
                    "event": "metadata_inventory_completed",
                    "triggers": ["initial_metadata_inventory"],
                    "outcome": "metadata_inventory_complete",
                    "scan": {"stats": {"files_hashed": 0, "bytes_hashed": 0}},
                }
            )
            health = json.loads(health_path.read_text(encoding="utf-8"))
        self.assertEqual("zsec.antivirus.companion-health.v1", health["schema"])
        self.assertEqual("ZSEC Antivirus", health["product"])
        self.assertEqual("inventorying_metadata", inventorying["operational_state"])
        self.assertEqual("inventorying_metadata", progress["operational_state"])
        self.assertEqual(0, progress["counters"]["files_hashed"])
        self.assertEqual(0, progress["counters"]["reconciliation_files_hashed"])
        self.assertEqual(4096, progress["counters"]["event_queue_capacity"])
        self.assertEqual(5, progress["counters"]["event_queue_total_depth"])
        self.assertEqual("healthy", health["operational_state"])
        self.assertEqual("native", health["backend_active"])
        self.assertEqual(str(Path(sys.executable).resolve()), health["runtime_executable"])
        self.assertEqual(64, len(health["runtime_sha256"]))
        self.assertFalse(health["policy"]["primary_antivirus"])
        self.assertFalse(health["policy"]["real_time_protection"])
        self.assertFalse(health["policy"]["pre_access_enforcement"])

    def test_superseded_aggregate_is_logged_without_rewriting_health(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            health_path = state / "companion" / "health.json"
            event_path = state / "companion" / "events.ndjson"
            sink = WatchEvidenceSink(
                state_dir=state,
                health_file=health_path,
                event_log=event_path,
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
            health_before = health_path.read_bytes()
            with patch(
                "zsec_shield.watch_evidence.atomic_write_json",
                side_effect=AssertionError("benign aggregate must not rewrite health"),
            ):
                sink.record(
                    {
                        "schema": "zsec.shield.watch-event.v1",
                        "version": "0.2.0",
                        "session_id": "test-session",
                        "sequence": 2,
                        "generated_at": "2026-08-21T12:00:01Z",
                        "event": "events_superseded",
                        "count": 5_000,
                        "sample_paths": ["one", "two"],
                        "sample_paths_omitted": 4_998,
                        "reason": "paths_vanished_during_scan",
                    }
                )

            self.assertEqual(health_before, health_path.read_bytes())
            records = [
                json.loads(line)
                for line in event_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(["session_started", "events_superseded"], [
                record["event"] for record in records
            ])
            self.assertEqual(5_000, records[-1]["count"])

    def test_health_snapshot_retries_a_brief_windows_sharing_violation(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            sink = WatchEvidenceSink(
                state_dir=state,
                health_file=state / "companion" / "health.json",
                event_log=None,
                event_log_max_bytes=64 * 1024,
                event_log_backups=1,
                heartbeat_seconds=30,
            )
            sharing_violation = PermissionError("health snapshot is temporarily in use")
            sharing_violation.winerror = 32  # type: ignore[attr-defined]
            with (
                patch(
                    "zsec_shield.watch_evidence.atomic_write_json",
                    side_effect=[sharing_violation, sharing_violation, None],
                ) as write,
                patch("zsec_shield.watch_evidence.time.sleep") as sleep,
            ):
                sink.record({"event": "session_started"})

            self.assertEqual(3, write.call_count)
            self.assertEqual(
                [
                    ((HEALTH_WRITE_RETRY_DELAYS_SECONDS[0],), {}),
                    ((HEALTH_WRITE_RETRY_DELAYS_SECONDS[1],), {}),
                ],
                sleep.call_args_list,
            )

    def test_health_snapshot_does_not_mask_a_persistent_sharing_violation(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            sink = WatchEvidenceSink(
                state_dir=state,
                health_file=state / "companion" / "health.json",
                event_log=None,
                event_log_max_bytes=64 * 1024,
                event_log_backups=1,
                heartbeat_seconds=30,
            )

            def persistent_failure(*_args: object, **_kwargs: object) -> None:
                failure = PermissionError("health snapshot remains in use")
                failure.winerror = 32  # type: ignore[attr-defined]
                raise failure

            with (
                patch(
                    "zsec_shield.watch_evidence.atomic_write_json",
                    side_effect=persistent_failure,
                ) as write,
                patch("zsec_shield.watch_evidence.time.sleep") as sleep,
                self.assertRaisesRegex(WatchError, "cannot update watch health snapshot"),
            ):
                sink.record({"event": "session_started"})

            self.assertEqual(len(HEALTH_WRITE_RETRY_DELAYS_SECONDS) + 1, write.call_count)
            self.assertEqual(len(HEALTH_WRITE_RETRY_DELAYS_SECONDS), sleep.call_count)


if __name__ == "__main__":
    unittest.main()
