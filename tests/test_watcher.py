from __future__ import annotations

import os
import struct
import sys
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from watchdog.events import FileCreatedEvent, FileMovedEvent

from zsec_shield.errors import WatchError
from zsec_shield.models import Rule, ScanIssue, ScanResult
from zsec_shield.scanner import Scanner, ScannerConfig
from zsec_shield.watcher import (
    SNAPSHOT_FINGERPRINT_BYTES,
    SNAPSHOT_PATH_KEY_BYTES,
    DebouncedPathQueue,
    ForegroundProtectionWatcher,
    WatchConfig,
    WatchEventHandler,
    _configure_windows_native_change_mask,
    _file_fingerprint,
    _snapshot_path_key,
    normalize_watch_roots,
    watch_policy,
)


class FakeObserver:
    def __init__(self, timeout: float, start_hook: Callable[[FakeObserver], None] | None = None):
        self.timeout = timeout
        self.start_hook = start_hook
        self.handler: WatchEventHandler | None = None
        self.roots: list[Path] = []
        self.alive = False

    def schedule(
        self, handler: WatchEventHandler, path: str, *, recursive: bool
    ) -> object:
        self.handler = handler
        self.roots.append(Path(path))
        if not recursive:
            raise AssertionError("watch roots must be recursive")
        return object()

    def start(self) -> None:
        self.alive = True
        if self.start_hook is not None:
            self.start_hook(self)

    def stop(self) -> None:
        self.alive = False

    def join(self, timeout: float | None = None) -> None:
        del timeout

    def is_alive(self) -> bool:
        return self.alive


def make_test_rule(pattern: bytes = b"zsec-watch-test-marker") -> Rule:
    return Rule(
        rule_id="test:watch-marker",
        name="Watch marker",
        kind="literal",
        severity="high",
        description="Benign watch-mode test marker.",
        source="test suite",
        literal=pattern,
    )


class WatchQueueTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows notification mask test")
    def test_windows_native_mask_ignores_last_access_only_changes(self) -> None:
        from watchdog.observers import winapi

        original = int(winapi.WATCHDOG_FILE_NOTIFY_FLAGS)
        try:
            _configure_windows_native_change_mask()
            narrowed = int(winapi.WATCHDOG_FILE_NOTIFY_FLAGS)
            self.assertEqual(0, narrowed & int(winapi.FILE_NOTIFY_CHANGE_LAST_ACCESS))
            self.assertEqual(
                original & ~int(winapi.FILE_NOTIFY_CHANGE_LAST_ACCESS),
                narrowed,
            )
        finally:
            winapi.WATCHDOG_FILE_NOTIFY_FLAGS = original

    def test_duplicate_events_are_debounced_and_state_is_excluded_pre_queue(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = [10.0]
            events = DebouncedPathQueue(
                excluded_paths=(root / "state",),
                debounce_seconds=0.5,
                max_events=16,
                clock=lambda: now[0],
            )
            target = root / "scan" / "sample.bin"
            events.submit(target, "created", False)
            events.submit(target, "modified", False)
            events.submit(root / "state" / "quarantine" / "object", "created", False)
            self.assertEqual([], events.due())
            now[0] = 10.5
            due = events.due()
        self.assertEqual(1, len(due))
        self.assertEqual({"created", "modified"}, due[0].event_types)
        self.assertEqual(2, events.events_received)
        self.assertEqual(1, events.events_debounced)
        self.assertEqual(1, events.events_excluded)

    def test_queue_overflow_is_latched_and_counted(self) -> None:
        with TemporaryDirectory() as temporary:
            queue = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.1,
                max_events=16,
            )
            for index in range(17):
                queue.submit(Path(temporary) / f"{index}.bin", "created", False)
        self.assertTrue(queue.overflowed.is_set())
        self.assertEqual(1, queue.events_dropped)

    def test_queue_telemetry_reports_raw_pending_and_capacity_without_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.5,
                max_events=16,
            )
            events.submit(root / "raw.bin", "created", False)
            raw = events.telemetry()
            events.ingest()
            pending = events.telemetry()
        self.assertEqual(16, raw["event_queue_capacity"])
        self.assertEqual(1, raw["event_queue_raw_depth"])
        self.assertEqual(0, raw["event_queue_pending_paths"])
        self.assertEqual(1, raw["event_queue_total_depth"])
        self.assertEqual(0, pending["event_queue_raw_depth"])
        self.assertEqual(1, pending["event_queue_pending_paths"])
        self.assertEqual(1, pending["event_queue_total_depth"])

    def test_debounce_starts_when_observer_submits_not_when_consumer_ingests(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = [10.0]
            events = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.5,
                max_events=16,
                clock=lambda: now[0],
            )
            target = root / "observed.bin"
            events.submit(target, "created", False)
            now[0] = 10.5
            due = events.due()
        self.assertEqual(1, len(due))
        self.assertEqual(target.absolute(), due[0].path)

    def test_moved_event_scans_destination_not_old_name(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = [1.0]
            events = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.1,
                max_events=16,
                clock=lambda: now[0],
            )
            handler = WatchEventHandler(events)
            source = root / "partial.download"
            destination = root / "complete.exe"
            handler.on_moved(FileMovedEvent(str(source), str(destination)))
            events.ingest()
            now[0] = 1.1
            due = events.due()
        self.assertEqual(
            [destination.absolute(), source.absolute()],
            [item.path for item in due],
        )
        event_types = {str(item.path): item.event_types for item in due}
        self.assertEqual({"moved_to"}, event_types[str(destination.absolute())])
        self.assertEqual({"moved_from"}, event_types[str(source.absolute())])

    def test_pending_paths_share_the_raw_queue_bound_and_overflow_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            queue = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.5,
                max_events=16,
            )
            for index in range(16):
                queue.submit(root / f"{index}.bin", "modified", False)
            queue.ingest()
            queue.submit(root / "overflow.bin", "modified", False)
            queue.ingest()
        self.assertTrue(queue.overflowed.is_set())
        self.assertGreaterEqual(queue.events_dropped, 1)
        self.assertLessEqual(queue.pending_high_water, 16)

    def test_submit_enforces_combined_raw_and_pending_capacity(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.5,
                max_events=16,
            )
            for index in range(16):
                events.submit(root / f"{index}.bin", "modified", False)
            events.ingest()
            full = events.telemetry()
            events.submit(root / "17.bin", "modified", False)
            refused = events.telemetry()
        self.assertEqual(16, full["event_queue_pending_paths"])
        self.assertEqual(16, full["event_queue_total_depth"])
        self.assertEqual(16, full["event_queue_capacity"])
        self.assertEqual(0, refused["event_queue_raw_depth"])
        self.assertEqual(16, refused["event_queue_total_depth"])
        self.assertEqual(1, refused["events_dropped"])
        self.assertTrue(events.overflowed.is_set())

    def test_repeated_modifications_cannot_postpone_scan_forever(self) -> None:
        with TemporaryDirectory() as temporary:
            now = [10.0]
            target = Path(temporary) / "busy.bin"
            queue = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.75,
                max_events=16,
                clock=lambda: now[0],
            )
            queue.submit(target, "modified", False)
            queue.ingest()
            for _ in range(5):
                now[0] += 0.4
                queue.submit(target, "modified", False)
                queue.ingest()
            due = queue.due()
        self.assertEqual([target.absolute()], [item.path for item in due])

    def test_due_can_drain_a_bounded_slice_without_losing_pending_paths(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = [1.0]
            queue = DebouncedPathQueue(
                excluded_paths=(),
                debounce_seconds=0.1,
                max_events=16,
                clock=lambda: now[0],
            )
            for index in range(4):
                queue.submit(root / f"{index}.bin", "created", False)
            queue.ingest()
            now[0] = 1.1
            first = queue.due(maximum=2)
            remaining = queue.telemetry()
            second = queue.due(maximum=2)
        self.assertEqual(2, len(first))
        self.assertEqual(2, remaining["event_queue_pending_paths"])
        self.assertEqual(2, len(second))
        self.assertEqual(0, queue.telemetry()["event_queue_total_depth"])


class WatchEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scan_root = self.root / "scan"
        self.state_dir = self.root / "state"
        self.scan_root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _config(self, **overrides: Any) -> WatchConfig:
        values: dict[str, Any] = {
            "roots": (self.scan_root,),
            "state_dir": self.state_dir,
            "backend": "polling",
            "debounce_seconds": 0.05,
            "poll_seconds": 0.05,
            "reconcile_seconds": 10.0,
        }
        values.update(overrides)
        return WatchConfig(**values)

    def test_policy_keeps_existing_protection_and_requires_quarantine_opt_in(self) -> None:
        policy = watch_policy(False)
        self.assertFalse(policy["kernel_or_os_access_mediation"])
        self.assertFalse(policy["primary_antivirus"])
        self.assertTrue(policy["existing_protection_must_remain_active"])
        self.assertFalse(policy["automatic_provider_changes"])
        self.assertFalse(policy["quarantine_requested"])

    def test_roots_are_canonical_deduplicated_and_never_inside_state(self) -> None:
        child = self.scan_root / "child"
        child.mkdir()
        roots = normalize_watch_roots((child, self.scan_root), self.state_dir)
        self.assertEqual((self.scan_root.absolute(),), tuple(root.path for root in roots))
        self.state_dir.mkdir()
        with self.assertRaisesRegex(WatchError, "inside the excluded state"):
            normalize_watch_roots((self.state_dir,), self.state_dir)

    def test_high_cardinality_snapshot_entries_are_fixed_size_and_bounded(self) -> None:
        entry_count = 25_000
        snapshot: dict[bytes, bytes] = {}
        long_parent = "nested-" + ("x" * 240)
        for index in range(entry_count):
            path = Path("C:/protected") / long_parent / f"file-{index:08d}.bin"
            metadata = cast(
                os.stat_result,
                SimpleNamespace(
                    st_dev=3,
                    st_ino=index + 1,
                    st_size=index * 17,
                    st_mtime=1_700_000_000.0,
                    st_mtime_ns=1_700_000_000_000_000_000 + index,
                    st_ctime=1_700_000_000.0,
                    st_ctime_ns=1_700_000_000_000_000_000 + index,
                    st_file_attributes=32,
                ),
            )
            snapshot[_snapshot_path_key(path)] = _file_fingerprint(metadata)

        self.assertEqual(entry_count, len(snapshot))
        self.assertEqual({SNAPSHOT_PATH_KEY_BYTES}, {len(key) for key in snapshot})
        self.assertEqual(
            {SNAPSHOT_FINGERPRINT_BYTES},
            {len(value) for value in snapshot.values()},
        )
        estimated_bytes = sys.getsizeof(snapshot) + sum(
            sys.getsizeof(key) + sys.getsizeof(value)
            for key, value in snapshot.items()
        )
        self.assertLess(estimated_bytes / entry_count, 240)

    def test_snapshot_key_is_canonical_fixed_size_and_unicode_safe(self) -> None:
        direct = Path("C:/protected/δ-data/report.bin")
        equivalent = Path("C:/protected/δ-data/../δ-data/report.bin")
        direct_key = _snapshot_path_key(direct)

        self.assertEqual(SNAPSHOT_PATH_KEY_BYTES, len(direct_key))
        self.assertEqual(direct_key, _snapshot_path_key(equivalent))

    def test_fingerprint_packing_rejects_out_of_range_metadata_without_aliasing(self) -> None:
        def metadata(**overrides: int | float) -> os.stat_result:
            values: dict[str, int | float] = {
                "st_dev": 3,
                "st_ino": 4,
                "st_size": 5,
                "st_mtime": -1.0,
                "st_mtime_ns": -1,
                "st_ctime": -2.0,
                "st_ctime_ns": -2,
                "st_file_attributes": 32,
            }
            values.update(overrides)
            return cast(os.stat_result, SimpleNamespace(**values))

        negative_time = _file_fingerprint(metadata())
        positive_time = _file_fingerprint(metadata(st_mtime_ns=1, st_ctime_ns=2))
        self.assertEqual(SNAPSHOT_FINGERPRINT_BYTES, len(negative_time))
        self.assertNotEqual(negative_time, positive_time)
        with self.assertRaises(struct.error):
            _file_fingerprint(metadata(st_size=1 << 64))
        with self.assertRaises(struct.error):
            _file_fingerprint(metadata(st_file_attributes=1 << 32))

    def test_unrepresentable_metadata_is_scanned_and_never_cached(self) -> None:
        target = self.scan_root / "unrepresentable.bin"
        target.write_bytes(b"must fail open to content inspection")
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=10.0),
            polling_observer_factory=FakeObserver,
        )

        with patch(
            "zsec_shield.watcher._file_fingerprint",
            side_effect=struct.error("metadata out of packed range"),
        ):
            summary = watcher.run(duration_seconds=0.35)

        self.assertGreaterEqual(summary.stats.files_hashed, 1)
        self.assertEqual({}, watcher._reconciliation_snapshot)
        self.assertTrue(summary.operational_incomplete)
        self.assertGreaterEqual(summary.stats.issues, 1)

    def test_watcher_disables_redundant_scanner_path_set_after_root_validation(self) -> None:
        target = self.scan_root / "bounded.bin"
        target.write_bytes(b"bounded")
        scanner = Scanner(())
        watcher = ForegroundProtectionWatcher(
            scanner,
            self._config(),
            polling_observer_factory=FakeObserver,
        )
        with patch.object(scanner, "scan", wraps=scanner.scan) as scan:
            watcher.run(duration_seconds=0.1)

        self.assertGreaterEqual(scan.call_count, 1)
        self.assertTrue(
            all(call.kwargs.get("deduplicate_paths") is False for call in scan.call_args_list)
        )
        self.assertTrue(
            all(
                isinstance(key, bytes) and isinstance(value, bytes)
                for key, value in watcher._reconciliation_snapshot.items()
            )
        )

    def test_auto_backend_discloses_native_failure_and_uses_polling(self) -> None:
        def fail_native(_timeout: float) -> FakeObserver:
            raise OSError("test native backend failure")

        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(backend="auto"),
            on_record=records.append,
            native_observer_factory=fail_native,
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.1)
        self.assertEqual("polling", summary.backend_active)
        self.assertIn("test native backend failure", summary.fallback_reason or "")
        self.assertFalse(summary.operational_incomplete)
        self.assertIn("backend_fallback", [record["event"] for record in records])

    def test_explicit_native_backend_failure_refuses_to_start(self) -> None:
        def fail_native(_timeout: float) -> FakeObserver:
            raise OSError("native unavailable")

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(backend="native"),
            native_observer_factory=fail_native,
        )
        with self.assertRaisesRegex(WatchError, "native watch backend failed"):
            watcher.run(duration_seconds=0.1)

    def test_backend_death_returns_incomplete_instead_of_silent_success(self) -> None:
        class DeadObserver(FakeObserver):
            def is_alive(self) -> bool:
                return False

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(),
            polling_observer_factory=DeadObserver,
        )
        summary = watcher.run(duration_seconds=0.2)
        self.assertTrue(summary.operational_incomplete)
        self.assertEqual("incomplete", summary.outcome)
        self.assertEqual("watch_backend_stopped", summary.health_issues[0]["code"])

    def test_event_ingest_thread_start_failure_stops_observer(self) -> None:
        observer = FakeObserver(0.05)
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(),
            polling_observer_factory=lambda _timeout: observer,
        )
        with (
            patch(
                "zsec_shield.watcher.threading.Thread.start",
                side_effect=RuntimeError("test thread refusal"),
            ),
            self.assertRaisesRegex(WatchError, "event ingestion worker failed to start"),
        ):
            watcher.run(duration_seconds=0.1)
        self.assertFalse(observer.alive)

    def test_queue_overflow_stops_with_explicit_coverage_failure(self) -> None:
        def fill_queue(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")
            for index in range(17):
                observer.handler.on_created(
                    FileCreatedEvent(str(self.scan_root / f"missing-{index}.bin"))
                )

        def factory(timeout: float) -> FakeObserver:
            return FakeObserver(timeout, fill_queue)

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(event_queue_size=16),
            polling_observer_factory=factory,
        )
        summary = watcher.run(duration_seconds=0.2)
        self.assertTrue(summary.operational_incomplete)
        self.assertEqual(1, summary.stats.events_dropped)
        self.assertEqual("watch_event_queue_overflow", summary.health_issues[0]["code"])

    def test_inventory_concurrently_ingests_and_coalesces_repeated_events(self) -> None:
        target_observed = threading.Event()
        release_inventory = threading.Event()
        producer_done = threading.Event()
        producer_threads: list[threading.Thread] = []
        target = self.scan_root / "00-target.bin"
        target.write_bytes(b"benign before the inventory event")
        (self.scan_root / "99-tail.bin").write_bytes(b"keeps the inventory active")

        class BlockingScanner(Scanner):
            def scan(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
                original_filter = kwargs.get("file_filter")
                if original_filter is None:
                    return super().scan(*args, **kwargs)

                def block_after_target(path: Path, metadata: os.stat_result) -> bool:
                    include = original_filter(path, metadata)
                    if path == target:
                        target_observed.set()
                        if not release_inventory.wait(timeout=5):
                            raise AssertionError(
                                "event producer did not release metadata inventory"
                            )
                    return include

                kwargs["file_filter"] = block_after_target
                return super().scan(*args, **kwargs)

        def start_producer(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")

            def produce() -> None:
                if not target_observed.wait(timeout=5):
                    release_inventory.set()
                    return
                target.write_bytes(make_test_rule().literal or b"")
                for _ in range(32):
                    observer.handler.on_created(FileCreatedEvent(str(target)))
                    threading.Event().wait(0.01)
                producer_done.set()
                release_inventory.set()

            thread = threading.Thread(target=produce, daemon=True)
            producer_threads.append(thread)
            thread.start()

        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            BlockingScanner((make_test_rule(),)),
            self._config(event_queue_size=16),
            on_record=records.append,
            polling_observer_factory=lambda timeout: FakeObserver(timeout, start_producer),
        )
        summary = watcher.run(duration_seconds=1.0)
        for thread in producer_threads:
            thread.join(timeout=5)
        self.assertTrue(producer_done.is_set())
        self.assertFalse(summary.operational_incomplete)
        self.assertEqual(32, summary.stats.events_received)
        self.assertGreater(summary.stats.events_debounced, 0)
        self.assertEqual(0, summary.stats.events_dropped)
        self.assertEqual(16, summary.stats.event_queue_capacity)
        self.assertEqual(0, summary.stats.event_queue_total_depth)
        event_scans = [
            record
            for record in records
            if record["event"] == "scan_completed"
        ]
        self.assertTrue(event_scans)
        self.assertEqual(1, event_scans[-1]["scan"]["stats"]["findings"])
        self.assertLessEqual(
            summary.stats.event_queue_total_depth,
            summary.stats.event_queue_capacity,
        )

    def test_inventory_interleaves_a_new_file_scan_before_inventory_finishes(self) -> None:
        first_observed = threading.Event()
        producer_done = threading.Event()
        producer_threads: list[threading.Thread] = []
        first = self.scan_root / "00-first.bin"
        first.write_bytes(b"first")
        (self.scan_root / "50-middle.bin").write_bytes(b"middle")
        (self.scan_root / "99-tail.bin").write_bytes(b"tail")
        live = self.scan_root / "25-live.bin"

        class SlowInventoryScanner(Scanner):
            def scan(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
                original_filter = kwargs.get("file_filter")
                if original_filter is None:
                    return super().scan(*args, **kwargs)

                def pause_after_first(path: Path, metadata: os.stat_result) -> bool:
                    include = original_filter(path, metadata)
                    if path == first:
                        first_observed.set()
                        if not producer_done.wait(timeout=5):
                            raise AssertionError("live event producer did not finish")
                    return include

                kwargs["file_filter"] = pause_after_first
                return super().scan(*args, **kwargs)

        def start_producer(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")

            def produce() -> None:
                if not first_observed.wait(timeout=5):
                    producer_done.set()
                    return
                live.write_bytes(make_test_rule().literal or b"")
                observer.handler.on_created(FileCreatedEvent(str(live)))
                threading.Event().wait(0.08)
                producer_done.set()

            thread = threading.Thread(target=produce, daemon=True)
            producer_threads.append(thread)
            thread.start()

        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            SlowInventoryScanner((make_test_rule(),)),
            self._config(event_queue_size=32),
            on_record=records.append,
            polling_observer_factory=lambda timeout: FakeObserver(timeout, start_producer),
        )
        summary = watcher.run(duration_seconds=0.1)
        for thread in producer_threads:
            thread.join(timeout=5)
        event_index = next(
            index
            for index, record in enumerate(records)
            if record["event"] == "scan_completed"
        )
        inventory_index = next(
            index
            for index, record in enumerate(records)
            if record["event"] == "metadata_inventory_completed"
            and record["triggers"] == ["initial_metadata_inventory"]
        )
        self.assertLess(event_index, inventory_index)
        self.assertGreaterEqual(summary.stats.findings, 1)
        self.assertEqual(0, summary.stats.event_queue_total_depth)

    def test_unique_events_during_inventory_overflow_fail_closed(self) -> None:
        inventory_started = threading.Event()
        release_inventory = threading.Event()
        producer_threads: list[threading.Thread] = []

        class BlockingScanner(Scanner):
            def scan(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
                inventory_started.set()
                if not release_inventory.wait(timeout=5):
                    raise AssertionError("event producer did not release metadata inventory")
                return super().scan(*args, **kwargs)

        def start_producer(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")

            def produce() -> None:
                if not inventory_started.wait(timeout=5):
                    release_inventory.set()
                    return
                for index in range(17):
                    observer.handler.on_created(
                        FileCreatedEvent(str(self.scan_root / f"unique-{index}.bin"))
                    )
                    threading.Event().wait(0.01)
                release_inventory.set()

            thread = threading.Thread(target=produce, daemon=True)
            producer_threads.append(thread)
            thread.start()

        watcher = ForegroundProtectionWatcher(
            BlockingScanner(()),
            self._config(event_queue_size=16),
            polling_observer_factory=lambda timeout: FakeObserver(timeout, start_producer),
        )
        summary = watcher.run(duration_seconds=1.0)
        for thread in producer_threads:
            thread.join(timeout=5)
        self.assertTrue(summary.operational_incomplete)
        self.assertEqual("incomplete", summary.outcome)
        self.assertGreaterEqual(summary.stats.events_dropped, 1)
        self.assertLessEqual(
            summary.stats.event_queue_total_depth,
            summary.stats.event_queue_capacity,
        )
        self.assertIn(
            "watch_event_queue_overflow",
            [issue["code"] for issue in summary.health_issues],
        )

    def test_shutdown_overflow_is_reported_incomplete(self) -> None:
        class StopOverflowObserver(FakeObserver):
            def stop(inner_self) -> None:
                if inner_self.handler is None:
                    raise AssertionError("observer was started without a handler")
                for index in range(17):
                    inner_self.handler.on_created(
                        FileCreatedEvent(str(self.scan_root / f"stop-{index}.bin"))
                    )
                super().stop()

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(event_queue_size=16),
            polling_observer_factory=StopOverflowObserver,
        )
        summary = watcher.run(duration_seconds=0.1)
        self.assertTrue(summary.operational_incomplete)
        self.assertEqual("incomplete", summary.outcome)
        self.assertGreaterEqual(summary.stats.events_dropped, 1)
        self.assertIn(
            "watch_event_queue_overflow",
            [issue["code"] for issue in summary.health_issues],
        )

    def test_shutdown_with_unprocessed_backlog_is_reported_incomplete(self) -> None:
        class StopBacklogObserver(FakeObserver):
            def stop(inner_self) -> None:
                if inner_self.handler is None:
                    raise AssertionError("observer was started without a handler")
                inner_self.handler.on_created(
                    FileCreatedEvent(str(self.scan_root / "stop-backlog.bin"))
                )
                super().stop()

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(),
            polling_observer_factory=StopBacklogObserver,
        )
        summary = watcher.run(duration_seconds=0.1)
        self.assertTrue(summary.operational_incomplete)
        self.assertEqual("incomplete", summary.outcome)
        self.assertEqual(1, summary.stats.event_queue_total_depth)
        self.assertIn(
            "watch_event_backlog_unprocessed",
            [issue["code"] for issue in summary.health_issues],
        )

    def test_state_and_quarantine_are_excluded_from_startup_inventory(self) -> None:
        nested_state = self.scan_root / ".zero-state"
        (nested_state / "quarantine").mkdir(parents=True)
        (nested_state / "quarantine" / "marker.bin").write_bytes(
            make_test_rule().literal or b""
        )
        watcher = ForegroundProtectionWatcher(
            Scanner((make_test_rule(),), ScannerConfig(excluded_paths=(nested_state,))),
            self._config(state_dir=nested_state),
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.1)
        self.assertEqual(0, summary.stats.findings)
        self.assertGreaterEqual(summary.stats.events_excluded, 0)

    def test_size_skip_is_an_incomplete_scope_not_a_clean_result(self) -> None:
        (self.scan_root / "large.bin").write_bytes(b"12345")
        watcher = ForegroundProtectionWatcher(
            Scanner((), ScannerConfig(max_file_bytes=4)),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=0.1),
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.3)
        self.assertEqual("incomplete", summary.outcome)
        self.assertEqual("scan_scope_incomplete", summary.health_issues[0]["code"])
        self.assertEqual(1, summary.stats.unresolved_files)
        self.assertEqual(0, summary.stats.metadata_files_unchanged)
        self.assertEqual(1, summary.stats.issues)

    def test_short_lived_event_is_superseded_without_poisoning_session_health(self) -> None:
        records: list[dict[str, Any]] = []

        def submit_missing(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")
            observer.handler.on_created(FileCreatedEvent(str(self.scan_root / "gone.tmp")))

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(debounce_seconds=0.05),
            on_record=records.append,
            polling_observer_factory=lambda timeout: FakeObserver(timeout, submit_missing),
        )
        # macOS CI can spend most of a 200 ms window starting the observer. Keep
        # this an integration-style timing test, but leave enough time for the
        # configured 50 ms debounce to become due on slower hosted runners.
        summary = watcher.run(duration_seconds=1.0)
        self.assertFalse(summary.operational_incomplete)
        self.assertEqual("no_configured_rule_matches", summary.outcome)
        self.assertEqual(1, summary.stats.events_superseded)
        self.assertIn("event_superseded", [record["event"] for record in records])

    def test_path_vanishing_inside_scan_is_superseded_but_other_errors_stay_sticky(self) -> None:
        records: list[dict[str, Any]] = []
        scanner = Scanner(())
        watcher = ForegroundProtectionWatcher(
            scanner,
            self._config(),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
        )
        vanished = self.scan_root / "vanished-during-open.bin"
        vanished_result = ScanResult(
            started_at="2026-08-22T00:00:00Z",
            completed_at="2026-08-22T00:00:01Z",
            roots=[str(vanished)],
            issues=[ScanIssue(str(vanished), "file_open_failed", "[WinError 2] missing")],
        )
        with patch.object(scanner, "scan", return_value=vanished_result):
            reconciled = watcher._scan_paths([vanished], ["created"])
        self.assertEqual([], reconciled.issues)
        self.assertFalse(watcher._operational_incomplete)
        self.assertEqual(1, watcher._stats.events_superseded)
        self.assertEqual("path_vanished_during_scan", records[-2]["reason"])

        retained = self.scan_root / "retained.bin"
        retained.write_bytes(b"ordinary")
        permission_result = ScanResult(
            started_at="2026-08-22T00:00:02Z",
            completed_at="2026-08-22T00:00:03Z",
            roots=[str(retained)],
            issues=[ScanIssue(str(retained), "file_open_failed", "Permission denied")],
        )
        with patch.object(scanner, "scan", return_value=permission_result):
            reconciled = watcher._scan_paths([retained], ["modified"])
        self.assertEqual(1, len(reconciled.issues))
        self.assertTrue(watcher._operational_incomplete)

    def test_mass_disappearance_inside_scan_is_one_bounded_evidence_record(self) -> None:
        records: list[dict[str, Any]] = []
        scanner = Scanner(())
        watcher = ForegroundProtectionWatcher(
            scanner,
            self._config(),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
        )
        vanished_count = 5_000
        vanished_paths = [
            self.scan_root / "deleted-tree" / f"file-{index}.bin"
            for index in range(vanished_count)
        ]
        vanished_result = ScanResult(
            started_at="2026-08-22T00:00:00Z",
            completed_at="2026-08-22T00:00:01Z",
            roots=[str(self.scan_root / "deleted-tree")],
            issues=[
                ScanIssue(str(path), "file_open_failed", "[WinError 2] missing")
                for path in vanished_paths
            ],
        )

        with patch.object(scanner, "scan", return_value=vanished_result):
            reconciled = watcher._scan_paths(
                [self.scan_root / "deleted-tree"], ["modified"]
            )

        self.assertEqual([], reconciled.issues)
        self.assertFalse(watcher._operational_incomplete)
        self.assertEqual(vanished_count, watcher._stats.events_superseded)
        superseded_records = [
            record
            for record in records
            if record["event"] in {"event_superseded", "events_superseded"}
        ]
        self.assertEqual(1, len(superseded_records))
        aggregate = superseded_records[0]
        self.assertEqual("events_superseded", aggregate["event"])
        self.assertEqual(vanished_count, aggregate["count"])
        self.assertEqual(8, len(aggregate["sample_paths"]))
        self.assertEqual(vanished_count - 8, aggregate["sample_paths_omitted"])
        self.assertEqual("paths_vanished_during_scan", aggregate["reason"])
        self.assertEqual(["modified"], aggregate["triggers"])

    def test_real_polling_backend_detects_file_created_after_inventory(self) -> None:
        target = self.scan_root / "arriving.bin"
        wrote_target = threading.Event()
        records: list[dict[str, Any]] = []

        def record(value: dict[str, Any]) -> None:
            records.append(value)
            if value["event"] == "metadata_inventory_completed" and value["triggers"] == [
                "initial_metadata_inventory"
            ]:
                target.write_bytes(
                    b"prefix-" + (make_test_rule().literal or b"") + b"-suffix"
                )
                wrote_target.set()

        watcher = ForegroundProtectionWatcher(
            Scanner((make_test_rule(),)),
            self._config(),
            on_record=record,
        )
        summary = watcher.run(duration_seconds=1.0)
        self.assertTrue(wrote_target.is_set())
        self.assertEqual(1, summary.stats.findings)
        event_scans = [
            value
            for value in records
            if value["event"] == "scan_completed"
        ]
        self.assertTrue(event_scans)
        self.assertTrue(target.exists(), "quarantine must remain off by default")

    def test_periodic_heartbeat_proves_the_backend_loop_is_alive(self) -> None:
        records: list[dict[str, Any]] = []
        now = [0.0]

        def advance_clock(seconds: float) -> None:
            now[0] += seconds

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(heartbeat_seconds=0.1),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
            clock=lambda: now[0],
        )
        with patch("zsec_shield.watcher.time.sleep", side_effect=advance_clock):
            summary = watcher.run(duration_seconds=0.25)
        heartbeats = [record for record in records if record["event"] == "health_heartbeat"]
        self.assertFalse(summary.operational_incomplete)
        self.assertGreaterEqual(len(heartbeats), 1)
        self.assertEqual("polling", heartbeats[0]["backend_active"])
        self.assertFalse(heartbeats[0]["policy"]["real_time_protection"])
        self.assertFalse(heartbeats[0]["policy"]["pre_access_enforcement"])

    def test_initial_metadata_inventory_emits_progress_without_hashing(self) -> None:
        for index in range(5):
            (self.scan_root / f"inventory-{index}.bin").write_bytes(b"bounded inventory")
        records: list[dict[str, Any]] = []
        now = [0.0]

        def advancing_clock() -> float:
            now[0] += 0.06
            return now[0]

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(heartbeat_seconds=0.1),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
            clock=advancing_clock,
        )
        summary = watcher.run(duration_seconds=0.1)
        progress = [
            record
            for record in records
            if record["event"] == "health_heartbeat"
            and record.get("reconciliation_phase") == "initial_metadata_inventory"
        ]
        self.assertTrue(progress)
        self.assertGreaterEqual(
            progress[-1]["stats"]["reconciliation_files_observed"], 1
        )
        self.assertTrue(
            all(record["stats"]["files_hashed"] == 0 for record in progress)
        )
        self.assertTrue(
            all(record["stats"]["bytes_hashed"] == 0 for record in progress)
        )
        self.assertTrue(
            all(record["stats"]["scan_batches"] == 0 for record in progress)
        )
        self.assertTrue(
            all(record["stats"]["reconciliation_files_hashed"] == 0 for record in progress)
        )
        self.assertTrue(
            all(record["stats"]["reconciliation_bytes_hashed"] == 0 for record in progress)
        )
        self.assertEqual(4096, progress[-1]["stats"]["event_queue_capacity"])
        phase_counts = [
            record["stats"]["reconciliation_files_hashed"] for record in progress
        ]
        self.assertEqual(sorted(phase_counts), phase_counts)
        self.assertTrue(
            all(
                record["stats"]["reconciliation_files_hashed"]
                <= record["stats"]["reconciliation_files_observed"]
                for record in progress
            )
        )
        self.assertEqual(0, summary.stats.files_hashed)
        self.assertEqual(0, summary.stats.bytes_hashed)
        inventory = next(
            record for record in records if record["event"] == "metadata_inventory_completed"
        )
        self.assertEqual("metadata_inventory_complete", inventory["outcome"])
        self.assertEqual(0, inventory["scan"]["stats"]["files_hashed"])

    def test_periodic_deadlines_are_rearmed_after_slow_initial_inventory(self) -> None:
        (self.scan_root / "slow-inventory.bin").write_bytes(b"metadata only")
        now = [0.0]

        class SlowInventoryScanner(Scanner):
            calls = 0

            def scan(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
                self.calls += 1
                if self.calls == 1:
                    now[0] += 301.0
                return super().scan(*args, **kwargs)

        def clock() -> float:
            return now[0]

        def advance(seconds: float) -> None:
            now[0] += seconds

        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            SlowInventoryScanner(()),
            self._config(
                reconcile_seconds=300.0,
                full_rescan_seconds=300.0,
            ),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
            clock=clock,
        )
        with patch("zsec_shield.watcher.time.sleep", side_effect=advance):
            summary = watcher.run(duration_seconds=0.2)

        periodic_triggers = {
            trigger
            for record in records
            if record["event"] in {"reconciliation_completed", "scan_completed"}
            for trigger in record.get("triggers", [])
            if trigger.startswith("periodic_")
        }
        self.assertEqual(set(), periodic_triggers)
        self.assertEqual(1, summary.stats.reconciliations)
        self.assertEqual(0, summary.stats.full_reconciliations)

    def test_reconciliation_consumes_prior_snapshot_payloads_while_streaming(self) -> None:
        for index in range(4):
            (self.scan_root / f"stable-{index}.bin").write_bytes(b"stable")
        scanner = Scanner(())
        watcher = ForegroundProtectionWatcher(
            scanner,
            self._config(),
            polling_observer_factory=FakeObserver,
        )
        watcher._reconcile("initial_metadata_inventory", full=False, metadata_only=True)
        self.assertEqual(4, len(watcher._reconciliation_snapshot))

        remaining_sizes: list[int] = []
        original_scan = scanner.scan

        def observe_consumption(*args: Any, **kwargs: Any) -> ScanResult:
            original_filter = kwargs["file_filter"]

            def observed_filter(path: Path, metadata: os.stat_result) -> bool:
                include = original_filter(path, metadata)
                remaining_sizes.append(len(watcher._reconciliation_snapshot))
                return include

            kwargs["file_filter"] = observed_filter
            return original_scan(*args, **kwargs)

        with patch.object(scanner, "scan", side_effect=observe_consumption):
            watcher._reconcile("periodic_reconciliation", full=False)

        self.assertEqual([3, 2, 1, 0], remaining_sizes)
        self.assertEqual(4, len(watcher._reconciliation_snapshot))
        self.assertEqual(4, watcher._stats.metadata_files_unchanged)

    def test_metadata_reconciliation_does_not_rehash_unchanged_files(self) -> None:
        target = self.scan_root / "stable.bin"
        target.write_bytes(b"stable reconciliation test")
        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(
                reconcile_seconds=0.1,
                full_rescan_seconds=10.0,
                heartbeat_seconds=0.1,
            ),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.45)
        periodic = [
            record
            for record in records
            if record["event"] == "reconciliation_completed"
            and record["triggers"] == ["periodic_reconciliation"]
        ]
        # The initial inventory plus at least one periodic reconciliation is
        # sufficient to prove the unchanged-file path. Requiring two periodic
        # passes inside this short real-time window made the test depend on the
        # host scheduler (and intermittently fail on slower macOS runners).
        self.assertGreaterEqual(summary.stats.reconciliations, 2)
        self.assertEqual(0, summary.stats.full_reconciliations)
        self.assertEqual(0, summary.stats.files_hashed)
        self.assertGreaterEqual(summary.stats.metadata_files_unchanged, 1)
        self.assertTrue(periodic)
        self.assertTrue(
            all(record["scan"]["stats"]["files_hashed"] == 0 for record in periodic)
        )
        self.assertTrue(all(record["outcome"] == "no_metadata_changes" for record in periodic))

    def test_metadata_reconciliation_hashes_a_changed_file_without_an_event(self) -> None:
        target = self.scan_root / "changed-without-event.bin"
        target.write_bytes(b"first version")
        changed = False

        def record(value: dict[str, Any]) -> None:
            nonlocal changed
            if (
                not changed
                and value["event"] == "metadata_inventory_completed"
                and value["triggers"] == ["initial_metadata_inventory"]
            ):
                target.write_bytes(b"second version with a different size")
                changed = True

        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=10.0),
            on_record=record,
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.35)
        self.assertTrue(changed)
        self.assertEqual(1, summary.stats.files_hashed)

    def test_full_rescan_ignores_metadata_cache_on_its_bounded_interval(self) -> None:
        target = self.scan_root / "daily-full-sweep.bin"
        target.write_bytes(b"full rescan coverage test")
        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=0.25),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
        )
        summary = watcher.run(duration_seconds=0.65)
        full_scans = [
            record
            for record in records
            if record["event"] == "scan_completed"
            and record["triggers"] == ["periodic_full_rescan"]
        ]
        self.assertGreaterEqual(summary.stats.full_reconciliations, 1)
        self.assertGreaterEqual(summary.stats.files_hashed, 1)
        self.assertTrue(full_scans)
        self.assertTrue(
            all(record["scan"]["stats"]["files_hashed"] == 1 for record in full_scans)
        )

    def test_full_rescan_catches_same_fingerprint_content_change(self) -> None:
        marker = make_test_rule().literal or b""
        target = self.scan_root / "restored-metadata.bin"
        target.write_bytes(b"x" * len(marker))
        changed = False

        def record(value: dict[str, Any]) -> None:
            nonlocal changed
            if (
                not changed
                and value["event"] == "metadata_inventory_completed"
                and value["triggers"] == ["initial_metadata_inventory"]
            ):
                target.write_bytes(marker)
                changed = True

        watcher = ForegroundProtectionWatcher(
            Scanner((make_test_rule(),)),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=0.25),
            on_record=record,
            polling_observer_factory=FakeObserver,
        )
        with patch(
            "zsec_shield.watcher._file_fingerprint",
            return_value=b"x" * SNAPSHOT_FINGERPRINT_BYTES,
        ):
            summary = watcher.run(duration_seconds=0.55)
        self.assertTrue(changed)
        self.assertGreaterEqual(summary.stats.findings, 1)

    def test_snapshot_key_collision_cannot_suppress_cache_independent_full_rescan(
        self,
    ) -> None:
        first = self.scan_root / "collision-a.bin"
        second = self.scan_root / "collision-b.bin"
        first.write_bytes(b"ordinary first file")
        second.write_bytes(make_test_rule().literal or b"")
        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            Scanner((make_test_rule(),)),
            self._config(reconcile_seconds=0.1, full_rescan_seconds=0.25),
            on_record=records.append,
            polling_observer_factory=FakeObserver,
        )

        with patch(
            "zsec_shield.watcher._snapshot_path_key",
            return_value=b"c" * SNAPSHOT_PATH_KEY_BYTES,
        ):
            summary = watcher.run(duration_seconds=0.55)

        full_scans = [
            record
            for record in records
            if record["event"] == "scan_completed"
            and record["triggers"] == ["periodic_full_rescan"]
        ]
        self.assertTrue(full_scans)
        self.assertTrue(
            all(record["scan"]["stats"]["files_hashed"] == 2 for record in full_scans)
        )
        self.assertGreaterEqual(summary.stats.findings, 1)

    def test_heartbeat_reports_live_event_queue_counters(self) -> None:
        target = self.scan_root / "heartbeat-event.bin"

        def submit_event(observer: FakeObserver) -> None:
            if observer.handler is None:
                raise AssertionError("observer was started without a handler")
            target.write_bytes(b"benign heartbeat counter test")
            observer.handler.on_created(FileCreatedEvent(str(target)))

        records: list[dict[str, Any]] = []
        watcher = ForegroundProtectionWatcher(
            Scanner(()),
            self._config(heartbeat_seconds=0.1),
            on_record=records.append,
            polling_observer_factory=lambda timeout: FakeObserver(timeout, submit_event),
        )
        summary = watcher.run(duration_seconds=0.3)
        heartbeats = [record for record in records if record["event"] == "health_heartbeat"]
        self.assertFalse(summary.operational_incomplete)
        self.assertGreaterEqual(len(heartbeats), 1)
        self.assertEqual(1, heartbeats[-1]["stats"]["events_received"])
        self.assertEqual(0, heartbeats[-1]["stats"]["events_dropped"])
        self.assertEqual(4096, heartbeats[-1]["stats"]["event_queue_capacity"])
        self.assertLessEqual(
            heartbeats[-1]["stats"]["event_queue_total_depth"],
            heartbeats[-1]["stats"]["event_queue_capacity"],
        )


if __name__ == "__main__":
    unittest.main()
