"""Foreground post-change protection with a polling fallback.

This module is a companion-mode foundation. It does not mediate kernel access,
register as a platform security provider, or replace an existing antivirus.
"""

from __future__ import annotations

import contextlib
import os
import queue
import stat
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from watchdog.events import FileSystemEvent, FileSystemEventHandler, FileSystemMovedEvent
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from zsec_shield.errors import FeedError, QuarantinePartialError, WatchError, ZsecShieldError
from zsec_shield.models import ScanResult
from zsec_shield.quarantine import quarantine_finding
from zsec_shield.scanner import Scanner
from zsec_shield.util import format_utc, update_lock

WatchBackend = Literal["auto", "native", "polling"]

DEFAULT_DEBOUNCE_SECONDS = 0.75
DEFAULT_POLL_SECONDS = 1.0
DEFAULT_RECONCILE_SECONDS = 60.0
DEFAULT_FULL_RESCAN_SECONDS = 24 * 60 * 60.0
DEFAULT_EVENT_QUEUE_SIZE = 4096
DEFAULT_HEARTBEAT_SECONDS = 30.0


class _Observer(Protocol):
    def schedule(
        self,
        event_handler: FileSystemEventHandler,
        path: str,
        *,
        recursive: bool,
    ) -> object: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def join(self, timeout: float | None = None) -> None: ...

    def is_alive(self) -> bool: ...


ObserverFactory = Callable[[float], _Observer]
RecordCallback = Callable[[dict[str, Any]], None]
Clock = Callable[[], float]
HealthCheck = Callable[[], str | None]


@dataclass(frozen=True, slots=True)
class WatchConfig:
    roots: tuple[Path, ...]
    state_dir: Path
    backend: WatchBackend = "auto"
    debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS
    poll_seconds: float = DEFAULT_POLL_SECONDS
    reconcile_seconds: float = DEFAULT_RECONCILE_SECONDS
    full_rescan_seconds: float = DEFAULT_FULL_RESCAN_SECONDS
    cross_filesystems: bool = False
    quarantine: bool = False
    event_queue_size: int = DEFAULT_EVENT_QUEUE_SIZE
    heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS

    def __post_init__(self) -> None:
        if self.backend not in {"auto", "native", "polling"}:
            raise WatchError("watch backend must be auto, native, or polling")
        if not 0.05 <= self.debounce_seconds <= 30:
            raise WatchError("debounce_seconds must be between 0.05 and 30")
        if not 0.05 <= self.poll_seconds <= 60:
            raise WatchError("poll_seconds must be between 0.05 and 60")
        if not 0.1 <= self.reconcile_seconds <= 24 * 60 * 60:
            raise WatchError("reconcile_seconds must be between 0.1 and 86400")
        if not self.reconcile_seconds <= self.full_rescan_seconds <= 7 * 24 * 60 * 60:
            raise WatchError(
                "full_rescan_seconds must be at least reconcile_seconds and at most 604800"
            )
        if not 16 <= self.event_queue_size <= 1_000_000:
            raise WatchError("event_queue_size must be between 16 and 1000000")
        if not 0.1 <= self.heartbeat_seconds <= 3600:
            raise WatchError("heartbeat_seconds must be between 0.1 and 3600")
        if not self.roots:
            raise WatchError("at least one watch directory is required")


@dataclass(frozen=True, slots=True)
class WatchRoot:
    path: Path
    key: str
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class QueuedPathEvent:
    path: Path
    event_type: str
    is_directory: bool


@dataclass(slots=True)
class PendingPath:
    path: Path
    event_types: set[str] = field(default_factory=set)
    first_seen_at: float = 0.0
    due_at: float = 0.0


@dataclass(slots=True)
class WatchStats:
    events_received: int = 0
    events_debounced: int = 0
    events_excluded: int = 0
    events_outside_scope: int = 0
    events_cross_filesystem: int = 0
    events_superseded: int = 0
    events_dropped: int = 0
    scan_batches: int = 0
    files_hashed: int = 0
    bytes_hashed: int = 0
    findings: int = 0
    issues: int = 0
    quarantine_completed: int = 0
    quarantine_partial: int = 0
    quarantine_failed: int = 0
    reconciliations: int = 0
    full_reconciliations: int = 0
    metadata_files_observed: int = 0
    metadata_files_unchanged: int = 0
    unresolved_files: int = 0
    pending_high_water: int = 0
    oldest_pending_milliseconds: int = 0
    event_queue_capacity: int = 0
    event_queue_raw_depth: int = 0
    event_queue_pending_paths: int = 0
    event_queue_total_depth: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "events_received": self.events_received,
            "events_debounced": self.events_debounced,
            "events_excluded": self.events_excluded,
            "events_outside_scope": self.events_outside_scope,
            "events_cross_filesystem": self.events_cross_filesystem,
            "events_superseded": self.events_superseded,
            "events_dropped": self.events_dropped,
            "scan_batches": self.scan_batches,
            "files_hashed": self.files_hashed,
            "bytes_hashed": self.bytes_hashed,
            "findings": self.findings,
            "issues": self.issues,
            "quarantine_completed": self.quarantine_completed,
            "quarantine_partial": self.quarantine_partial,
            "quarantine_failed": self.quarantine_failed,
            "reconciliations": self.reconciliations,
            "full_reconciliations": self.full_reconciliations,
            "metadata_files_observed": self.metadata_files_observed,
            "metadata_files_unchanged": self.metadata_files_unchanged,
            "unresolved_files": self.unresolved_files,
            "pending_high_water": self.pending_high_water,
            "oldest_pending_milliseconds": self.oldest_pending_milliseconds,
            "event_queue_capacity": self.event_queue_capacity,
            "event_queue_raw_depth": self.event_queue_raw_depth,
            "event_queue_pending_paths": self.event_queue_pending_paths,
            "event_queue_total_depth": self.event_queue_total_depth,
        }


@dataclass(frozen=True, slots=True)
class WatchSummary:
    started_at: str
    completed_at: str
    backend_requested: WatchBackend
    backend_active: str
    fallback_reason: str | None
    roots: tuple[str, ...]
    interrupted: bool
    operational_incomplete: bool
    stats: WatchStats
    health_issues: tuple[dict[str, str], ...]
    quarantine_requested: bool

    @property
    def outcome(self) -> str:
        if self.interrupted:
            return "interrupted"
        if self.operational_incomplete:
            return "incomplete"
        if self.stats.findings:
            return "configured_rule_matches_detected"
        return "no_configured_rule_matches"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "zsec.shield.watch-summary.v1",
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
            "backend_requested": self.backend_requested,
            "backend_active": self.backend_active,
            "fallback_reason": self.fallback_reason,
            "roots": list(self.roots),
            "interrupted": self.interrupted,
            "operational_incomplete": self.operational_incomplete,
            "stats": self.stats.to_dict(),
            "health_issues": list(self.health_issues),
            "policy": watch_policy(self.quarantine_requested),
        }


def watch_policy(quarantine_requested: bool) -> dict[str, Any]:
    return {
        "product": "ZSEC Antivirus",
        "engine": "ZSEC Shield",
        "mode": "foreground-post-change-protection",
        "real_time_protection": False,
        "pre_access_enforcement": False,
        "background_service": False,
        "kernel_or_os_access_mediation": False,
        "primary_antivirus": False,
        "existing_protection_must_remain_active": True,
        "automatic_provider_changes": False,
        "quarantine_requested": quarantine_requested,
        "quarantine_requires_explicit_flag": True,
        "no_match_meaning": "no configured rule matches in completed scans only",
    }


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(_absolute(path))))


def _file_fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return metadata used only to avoid redundant short-interval hashing.

    Native events remain authoritative for immediate change notification. A
    separate bounded full rescan deliberately ignores this cache so a missed
    event or preserved size/timestamp cannot suppress hashing indefinitely.
    """

    return (
        int(getattr(metadata, "st_dev", 0)),
        int(getattr(metadata, "st_ino", 0)),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _is_within(path_key: str, parent_key: str) -> bool:
    try:
        return os.path.commonpath((path_key, parent_key)) == parent_key
    except ValueError:
        return False


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def normalize_watch_roots(roots: tuple[Path, ...], state_dir: Path) -> tuple[WatchRoot, ...]:
    state_key = _path_key(state_dir)
    candidates: list[WatchRoot] = []
    for requested in roots:
        path = _absolute(requested)
        key = _path_key(path)
        if _is_within(key, state_key):
            raise WatchError(f"watch root is inside the excluded state directory: {path}")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WatchError(f"watch root is not accessible: {path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise WatchError(f"watch root must not be a symlink or reparse point: {path}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise WatchError(f"watch root must be an existing directory: {path}")
        candidates.append(
            WatchRoot(
                path,
                key,
                int(getattr(metadata, "st_dev", 0)),
                int(getattr(metadata, "st_ino", 0)),
            )
        )

    unique: list[WatchRoot] = []
    for candidate in sorted(candidates, key=lambda item: (len(item.key), item.key)):
        if any(candidate.key == root.key or _is_within(candidate.key, root.key) for root in unique):
            continue
        unique.append(candidate)
    if not unique:
        raise WatchError("no distinct watch directory remains after normalization")
    return tuple(unique)


@contextlib.contextmanager
def watch_lock(state_dir: Path) -> Iterator[None]:
    """Prevent two foreground watch sessions from sharing one mutable state root."""

    try:
        with update_lock(state_dir / "status" / ".watch.lock"):
            yield
    except FeedError as exc:
        raise WatchError("another foreground watch session is using this state directory") from exc


class DebouncedPathQueue:
    """Bound event ingestion and coalesce repeated paths after a quiet period."""

    def __init__(
        self,
        *,
        excluded_paths: tuple[Path, ...],
        debounce_seconds: float,
        max_events: int,
        clock: Clock = time.monotonic,
    ) -> None:
        self._excluded = tuple(_path_key(path) for path in excluded_paths)
        self._debounce_seconds = debounce_seconds
        self._max_coalesce_seconds = max(2.0, debounce_seconds)
        self._max_events = max_events
        self._clock = clock
        self._queue: queue.Queue[QueuedPathEvent] = queue.Queue(maxsize=max_events)
        self._pending: dict[str, PendingPath] = {}
        self._state_lock = threading.RLock()
        self.overflowed = threading.Event()
        self.events_received = 0
        self.events_excluded = 0
        self.events_dropped = 0
        self.events_debounced = 0
        self.pending_high_water = 0

    def submit(self, path: Path, event_type: str, is_directory: bool) -> None:
        key = _path_key(path)
        with self._state_lock:
            if any(_is_within(key, excluded) for excluded in self._excluded):
                self.events_excluded += 1
                return
            self.events_received += 1
            pending = self._pending.get(key)
            if pending is not None:
                self.events_debounced += 1
                now = self._clock()
                pending.event_types.add(event_type)
                if event_type in {
                    "closed_after_write",
                    "moved_to",
                    "moved_from",
                    "deleted",
                }:
                    pending.due_at = now
                else:
                    pending.due_at = min(
                        now + self._debounce_seconds,
                        pending.first_seen_at + self._max_coalesce_seconds,
                    )
                return
            if len(self._pending) + self._queue.qsize() >= self._max_events:
                self.events_dropped += 1
                self.overflowed.set()
                return
            try:
                self._queue.put_nowait(
                    QueuedPathEvent(_absolute(path), event_type, is_directory)
                )
            except queue.Full:
                self.events_dropped += 1
                self.overflowed.set()

    def ingest(self) -> None:
        while True:
            with self._state_lock:
                try:
                    event = self._queue.get_nowait()
                except queue.Empty:
                    return
                key = _path_key(event.path)
                pending = self._pending.get(key)
                if pending is None:
                    # Keep raw plus coalesced work within the same configured
                    # bound. Overflow is fail-closed even when unique paths were
                    # already drained out of queue.Queue into this dictionary.
                    if len(self._pending) + self._queue.qsize() >= self._max_events:
                        self.events_dropped += 1
                        self.overflowed.set()
                        continue
                    now = self._clock()
                    pending = PendingPath(event.path, first_seen_at=now)
                    self._pending[key] = pending
                    self.pending_high_water = max(
                        self.pending_high_water, len(self._pending)
                    )
                else:
                    self.events_debounced += 1
                    now = self._clock()
                pending.event_types.add(event.event_type)
                if event.event_type in {
                    "closed_after_write",
                    "moved_to",
                    "moved_from",
                    "deleted",
                }:
                    pending.due_at = now
                else:
                    pending.due_at = min(
                        now + self._debounce_seconds,
                        pending.first_seen_at + self._max_coalesce_seconds,
                    )

    def due(self) -> list[PendingPath]:
        self.ingest()
        with self._state_lock:
            now = self._clock()
            keys = sorted(
                key for key, pending in self._pending.items() if pending.due_at <= now
            )
            return [self._pending.pop(key) for key in keys]

    def clear_overflow(self) -> int:
        with self._state_lock:
            dropped = self.events_dropped
            self.events_dropped = 0
            self.overflowed.clear()
            return dropped

    def oldest_pending_age_seconds(self) -> float:
        with self._state_lock:
            if not self._pending:
                return 0.0
            oldest = min(item.first_seen_at for item in self._pending.values())
            return max(0.0, self._clock() - oldest)

    def telemetry(self) -> dict[str, int]:
        """Return one internally consistent, non-destructive queue snapshot."""

        with self._state_lock:
            raw_depth = self._queue.qsize()
            pending_paths = len(self._pending)
            if self._pending:
                oldest = min(item.first_seen_at for item in self._pending.values())
                oldest_pending_milliseconds = int(
                    max(0.0, self._clock() - oldest) * 1000
                )
            else:
                oldest_pending_milliseconds = 0
            return {
                "events_received": self.events_received,
                "events_debounced": self.events_debounced,
                "events_excluded": self.events_excluded,
                "events_dropped": self.events_dropped,
                "pending_high_water": self.pending_high_water,
                "oldest_pending_milliseconds": oldest_pending_milliseconds,
                "event_queue_capacity": self._max_events,
                "event_queue_raw_depth": raw_depth,
                "event_queue_pending_paths": pending_paths,
                "event_queue_total_depth": raw_depth + pending_paths,
            }


class WatchEventHandler(FileSystemEventHandler):
    def __init__(self, event_queue: DebouncedPathQueue) -> None:
        super().__init__()
        self._event_queue = event_queue

    def on_created(self, event: FileSystemEvent) -> None:
        self._event_queue.submit(Path(os.fsdecode(event.src_path)), "created", event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._event_queue.submit(Path(os.fsdecode(event.src_path)), "modified", False)

    def on_moved(self, event: FileSystemMovedEvent) -> None:
        self._event_queue.submit(
            Path(os.fsdecode(event.src_path)), "moved_from", event.is_directory
        )
        self._event_queue.submit(
            Path(os.fsdecode(event.dest_path)), "moved_to", event.is_directory
        )

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._event_queue.submit(Path(os.fsdecode(event.src_path)), "deleted", event.is_directory)

    def on_closed(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._event_queue.submit(Path(os.fsdecode(event.src_path)), "closed_after_write", False)


def _native_observer(timeout: float) -> _Observer:
    _configure_windows_native_change_mask()
    return cast(_Observer, Observer(timeout=timeout))


def _configure_windows_native_change_mask() -> None:
    """Ignore access-time-only Windows notifications that our own reads can cause.

    Watchdog's default ReadDirectoryChangesW mask includes LAST_ACCESS.  A
    baseline antivirus read can therefore report every inspected file as
    modified, overflow the bounded queue, and stop the companion.  Last-access
    changes do not alter file content; name, creation, attributes, size,
    security, and last-write notifications remain enabled.
    """

    if os.name != "nt":
        return
    from watchdog.observers import winapi

    last_access = int(winapi.FILE_NOTIFY_CHANGE_LAST_ACCESS)
    current = int(winapi.WATCHDOG_FILE_NOTIFY_FLAGS)
    narrowed = current & ~last_access
    if narrowed <= 0:
        raise WatchError("Windows native watch notification mask is invalid")
    winapi.WATCHDOG_FILE_NOTIFY_FLAGS = narrowed


def _polling_observer(timeout: float) -> _Observer:
    return cast(_Observer, PollingObserver(timeout=timeout))


class ForegroundProtectionWatcher:
    """Run bounded scans in response to filesystem events while in the foreground."""

    def __init__(
        self,
        scanner: Scanner,
        config: WatchConfig,
        *,
        on_record: RecordCallback | None = None,
        native_observer_factory: ObserverFactory = _native_observer,
        polling_observer_factory: ObserverFactory = _polling_observer,
        health_check: HealthCheck | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self.scanner = scanner
        self.config = config
        self.roots = normalize_watch_roots(config.roots, config.state_dir)
        self._on_record = on_record or (lambda _record: None)
        self._native_factory = native_observer_factory
        self._polling_factory = polling_observer_factory
        self._health_check = health_check or (lambda: None)
        self._clock = clock
        self._events = DebouncedPathQueue(
            excluded_paths=(config.state_dir,),
            debounce_seconds=config.debounce_seconds,
            max_events=config.event_queue_size,
            clock=clock,
        )
        self._handler = WatchEventHandler(self._events)
        self._observer: _Observer | None = None
        self._active_backend = "not-started"
        self._fallback_reason: str | None = None
        self._stats = WatchStats()
        self._health_issues: list[dict[str, str]] = []
        self._health_issue_keys: set[tuple[str, str]] = set()
        self._scan_issue_keys: set[tuple[str, str, str]] = set()
        self._operational_incomplete = False
        self._reconciliation_snapshot: dict[
            str, tuple[int, int, int, int, int, int]
        ] = {}
        self._session_id = str(uuid.uuid4())
        self._record_sequence = 0
        self._event_ingest_failure: str | None = None

    def _emit(self, event: str, **fields: Any) -> None:
        self._record_sequence += 1
        self._on_record(
            {
                "schema": "zsec.shield.watch-event.v1",
                "session_id": self._session_id,
                "sequence": self._record_sequence,
                "generated_at": format_utc(),
                "event": event,
                **fields,
            }
        )

    def _stats_snapshot(self) -> dict[str, int]:
        """Return live counters without waiting for session shutdown."""
        snapshot = self._stats.to_dict()
        event_telemetry = self._events.telemetry()
        snapshot["events_received"] = event_telemetry["events_received"]
        snapshot["events_debounced"] = event_telemetry["events_debounced"]
        snapshot["events_excluded"] = event_telemetry["events_excluded"]
        snapshot["events_dropped"] += event_telemetry["events_dropped"]
        snapshot["pending_high_water"] = max(
            snapshot["pending_high_water"], event_telemetry["pending_high_water"]
        )
        snapshot["oldest_pending_milliseconds"] = event_telemetry[
            "oldest_pending_milliseconds"
        ]
        for name in (
            "event_queue_capacity",
            "event_queue_raw_depth",
            "event_queue_pending_paths",
            "event_queue_total_depth",
        ):
            snapshot[name] = event_telemetry[name]
        return snapshot

    def _ingest_events(self, stop: threading.Event) -> None:
        """Continuously move raw observer events into the bounded coalescing map."""

        interval = max(0.005, min(0.05, self.config.debounce_seconds / 4))
        try:
            while not stop.wait(interval):
                self._events.ingest()
            self._events.ingest()
        except BaseException as exc:  # pragma: no cover - defensive thread boundary
            self._event_ingest_failure = (
                f"{type(exc).__name__}: {exc}"
                .replace("\r", " ")
                .replace("\n", " ")[:500]
            )

    def _event_pipeline_is_healthy(self) -> bool:
        if self._event_ingest_failure is not None:
            self._health_issue(
                "watch_event_ingest_stopped",
                f"event ingestion stopped unexpectedly: {self._event_ingest_failure}",
            )
            return False
        if self._events.overflowed.is_set():
            dropped = self._events.clear_overflow()
            self._stats.events_dropped += dropped
            self._health_issue(
                "watch_event_queue_overflow",
                f"lost {dropped} queued filesystem event(s); coverage is unknown",
            )
            return False
        return True

    def _new_observer(self, backend: str) -> _Observer:
        factory = self._native_factory if backend == "native" else self._polling_factory
        observer = factory(self.config.poll_seconds)
        try:
            for root in self.roots:
                observer.schedule(self._handler, os.fspath(root.path), recursive=True)
            observer.start()
        except BaseException:
            with contextlib.suppress(Exception):
                observer.stop()
            with contextlib.suppress(Exception):
                observer.join(timeout=5)
            raise
        return observer

    def _start_observer(self) -> None:
        requested = self.config.backend
        if requested == "polling":
            try:
                self._observer = self._new_observer("polling")
            except Exception as exc:
                raise WatchError(f"polling watch backend failed to start: {exc}") from exc
            self._active_backend = "polling"
            return

        try:
            self._observer = self._new_observer("native")
            self._active_backend = "native"
            return
        except Exception as exc:
            if requested == "native":
                raise WatchError(f"native watch backend failed to start: {exc}") from exc
            self._fallback_reason = f"native backend unavailable: {type(exc).__name__}: {exc}"
            with contextlib.suppress(Exception):
                if self._observer is not None:
                    self._observer.stop()
                    self._observer.join(timeout=5)
            self._observer = None

        try:
            self._observer = self._new_observer("polling")
        except Exception as exc:
            raise WatchError(
                f"native backend failed and polling fallback failed to start: {exc}"
            ) from exc
        self._active_backend = "polling"
        self._emit("backend_fallback", reason=self._fallback_reason)

    def _stop_observer(self) -> None:
        observer = self._observer
        self._observer = None
        if observer is None:
            return
        with contextlib.suppress(Exception):
            observer.stop()
        with contextlib.suppress(Exception):
            observer.join(timeout=10)

    def _health_issue(self, code: str, message: str) -> None:
        sanitized = message.replace("\r", " ").replace("\n", " ")[:500]
        key = (code, sanitized)
        if key in self._health_issue_keys:
            return
        self._health_issue_keys.add(key)
        issue = {"code": code, "message": sanitized}
        self._health_issues.append(issue)
        self._stats.issues += 1
        self._operational_incomplete = True
        self._emit("health_issue", **issue)

    def _scope_for(self, path: Path) -> WatchRoot | None:
        key = _path_key(path)
        return next((root for root in self.roots if _is_within(key, root.key)), None)

    def _scan_pending(self, pending: PendingPath) -> None:
        scope = self._scope_for(pending.path)
        if scope is None:
            self._stats.events_outside_scope += 1
            return
        try:
            metadata = pending.path.lstat()
        except FileNotFoundError:
            # Short-lived browser/download/temp files commonly disappear before
            # their debounce deadline. Record that race without poisoning the
            # health of the whole session; periodic reconciliation still checks
            # everything that remains in scope.
            self._stats.events_superseded += 1
            self._reconciliation_snapshot.pop(_path_key(pending.path), None)
            self._emit(
                "event_superseded",
                path=str(pending.path),
                triggers=sorted(pending.event_types),
                reason="path_vanished_before_scan",
            )
            return
        except OSError as exc:
            self._health_issue("watch_path_unreadable", f"cannot inspect {pending.path}: {exc}")
            return
        if (
            not self.config.cross_filesystems
            and scope.device
            and getattr(metadata, "st_dev", 0)
            and metadata.st_dev != scope.device
        ):
            self._stats.events_cross_filesystem += 1
            self._health_issue(
                "watch_cross_filesystem_skipped",
                f"event crossed the configured filesystem boundary: {pending.path}",
            )
            return
        self._scan_paths([pending.path], sorted(pending.event_types))

    def _scan_paths(
        self,
        paths: list[Path],
        triggers: list[str],
        *,
        file_filter: Callable[[Path, os.stat_result], bool] | None = None,
        file_observer: Callable[[Path, os.stat_result, bool], None] | None = None,
        event: str = "scan_completed",
        no_hash_outcome: str | None = None,
    ) -> ScanResult:
        result = self.scanner.scan(
            paths,
            file_filter=file_filter,
            file_observer=file_observer,
        )
        self._stats.scan_batches += 1
        self._stats.files_hashed += result.stats.files_hashed
        self._stats.bytes_hashed += result.stats.bytes_hashed
        self._stats.findings += len(result.findings)
        new_scan_issues = 0
        for issue in result.issues:
            key = (issue.path, issue.code, issue.message)
            if key not in self._scan_issue_keys:
                self._scan_issue_keys.add(key)
                new_scan_issues += 1
        self._stats.issues += new_scan_issues
        if result.issues:
            self._operational_incomplete = True
        skipped = {
            "symlinks_or_reparse_points": result.stats.skipped_symlinks,
            "special_files": result.stats.skipped_special,
            "files_above_size_limit": result.stats.skipped_too_large,
        }
        coverage_gap = any(skipped.values())
        if coverage_gap:
            details = ", ".join(f"{name}={count}" for name, count in skipped.items() if count)
            self._health_issue(
                "scan_scope_incomplete",
                f"one or more observed paths were not inspected: {details}",
            )

        quarantine_records: list[dict[str, Any]] = []
        if self.config.quarantine:
            for finding in result.findings:
                try:
                    record = quarantine_finding(finding, self.config.state_dir)
                    quarantine_records.append(
                        {
                            "id": record["id"],
                            "state": record["state"],
                            "original_path": record["original_path"],
                            "sha256": record["sha256"],
                        }
                    )
                    self._stats.quarantine_completed += 1
                except QuarantinePartialError as exc:
                    quarantine_records.append(
                        {"id": exc.entry_id, "state": "copy_only", "error": str(exc)}
                    )
                    self._stats.quarantine_partial += 1
                    self._stats.issues += 1
                    self._operational_incomplete = True
                except ZsecShieldError as exc:
                    quarantine_records.append(
                        {
                            "id": None,
                            "state": "failed",
                            "path": finding.path,
                            "error": str(exc),
                        }
                    )
                    self._stats.quarantine_failed += 1
                    self._stats.issues += 1
                    self._operational_incomplete = True

        if coverage_gap:
            outcome = "incomplete"
        elif no_hash_outcome is not None and result.stats.files_hashed == 0:
            outcome = no_hash_outcome
        else:
            outcome = _scan_outcome(result)
        self._emit(
            event,
            triggers=triggers,
            outcome=outcome,
            scan=result.to_dict(),
            quarantine=quarantine_records,
        )
        return result

    def _reconcile(self, trigger: str, *, full: bool) -> None:
        self._stats.reconciliations += 1
        if full:
            self._stats.full_reconciliations += 1
        previous = self._reconciliation_snapshot
        current: dict[str, tuple[int, int, int, int, int, int]] = {}
        unresolved: set[str] = set()
        observed = 0
        unchanged = 0
        hashed_in_progress = 0
        bytes_hashed = 0
        unresolved_in_progress = 0
        reconciliation_started = self._clock()
        next_progress_heartbeat = self._clock() + self.config.heartbeat_seconds

        def emit_progress_heartbeat() -> None:
            nonlocal next_progress_heartbeat
            now = self._clock()
            if now < next_progress_heartbeat:
                return
            progress_stats = self._stats_snapshot()
            progress_stats["reconciliation_files_observed"] = observed
            progress_stats["reconciliation_files_unchanged"] = unchanged
            progress_stats["reconciliation_files_hashed"] = hashed_in_progress
            progress_stats["reconciliation_bytes_hashed"] = bytes_hashed
            progress_stats["reconciliation_unresolved_files"] = unresolved_in_progress
            progress_stats["reconciliation_elapsed_milliseconds"] = int(
                max(0.0, now - reconciliation_started) * 1000
            )
            self._emit(
                "health_heartbeat",
                backend_active=self._active_backend,
                roots=[str(root.path) for root in self.roots],
                operational_incomplete=(
                    self._operational_incomplete
                    or self._events.overflowed.is_set()
                    or self._event_ingest_failure is not None
                ),
                reconciliation_phase=trigger,
                stats=progress_stats,
                policy=watch_policy(self.config.quarantine),
            )
            next_progress_heartbeat = now + self.config.heartbeat_seconds

        def changed_since_last_reconciliation(path: Path, metadata: os.stat_result) -> bool:
            nonlocal observed, unchanged
            key = _path_key(path)
            fingerprint = _file_fingerprint(metadata)
            observed += 1
            changed = full or previous.get(key) != fingerprint
            if not changed:
                unchanged += 1
                current[key] = fingerprint
            emit_progress_heartbeat()
            return changed

        def record_successful_hash(
            path: Path, metadata: os.stat_result, was_hashed: bool
        ) -> None:
            nonlocal bytes_hashed, hashed_in_progress, unresolved_in_progress
            key = _path_key(path)
            if was_hashed:
                # Keep this phase-local counter distinct from the completed-batch
                # files_hashed total, which is updated only after Scanner returns.
                hashed_in_progress += 1
                bytes_hashed += int(metadata.st_size)
                current[key] = _file_fingerprint(metadata)
            else:
                unresolved_in_progress += 1
                unresolved.add(key)
            emit_progress_heartbeat()

        self._scan_paths(
            [root.path for root in self.roots],
            [trigger],
            file_filter=changed_since_last_reconciliation,
            file_observer=record_successful_hash,
            event="scan_completed" if full else "reconciliation_completed",
            no_hash_outcome=None if full else "no_metadata_changes",
        )
        self._reconciliation_snapshot = current
        self._stats.metadata_files_observed += observed
        self._stats.metadata_files_unchanged += unchanged
        self._stats.unresolved_files = len(unresolved)

    def _backend_is_healthy(self) -> bool:
        observer = self._observer
        if observer is not None and observer.is_alive():
            return True
        self._health_issue(
            "watch_backend_stopped",
            f"{self._active_backend} watch backend stopped unexpectedly; coverage is unknown",
        )
        return False

    def _roots_are_healthy(self) -> bool:
        for root in self.roots:
            try:
                metadata = root.path.lstat()
            except OSError as exc:
                self._health_issue(
                    "watch_root_unavailable", f"watch root failed: {root.path}: {exc}"
                )
                return False
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse_point(metadata)
            ):
                self._health_issue(
                    "watch_root_identity_changed",
                    f"watch root is no longer the original regular directory: {root.path}",
                )
                return False
            device = int(getattr(metadata, "st_dev", 0))
            inode = int(getattr(metadata, "st_ino", 0))
            if (root.device and device and root.device != device) or (
                root.inode and inode and root.inode != inode
            ):
                self._health_issue(
                    "watch_root_identity_changed",
                    f"watch root device/inode changed: {root.path}",
                )
                return False
        return True

    def run(self, duration_seconds: float | None = None) -> WatchSummary:
        if duration_seconds is not None and not 0.1 <= duration_seconds <= 7 * 24 * 60 * 60:
            raise WatchError("duration_seconds must be between 0.1 and 604800")
        started_at = format_utc()
        started_monotonic = self._clock()
        interrupted = False
        self._start_observer()
        self._emit(
            "session_started",
            backend_requested=self.config.backend,
            backend_active=self._active_backend,
            fallback_reason=self._fallback_reason,
            roots=[str(root.path) for root in self.roots],
            policy=watch_policy(self.config.quarantine),
        )
        next_reconcile = self._clock() + self.config.reconcile_seconds
        next_full_rescan = self._clock() + self.config.full_rescan_seconds
        next_health_check = self._clock() + min(5.0, self.config.reconcile_seconds)
        next_heartbeat = self._clock() + self.config.heartbeat_seconds
        ingest_stop = threading.Event()
        ingest_thread = threading.Thread(
            target=self._ingest_events,
            args=(ingest_stop,),
            name="zsec-watch-event-ingest",
            daemon=True,
        )
        ingest_started = False
        try:
            try:
                ingest_thread.start()
            except RuntimeError as exc:
                raise WatchError("event ingestion worker failed to start") from exc
            ingest_started = True
            # Start the observer first so changes during the mandatory baseline scan
            # enter the bounded queue instead of falling into a startup gap. A
            # dedicated ingestion worker coalesces that raw work while the baseline
            # scanner owns this thread; it never scans or discards event paths.
            self._reconcile("initial_baseline", full=True)
            while True:
                if not self._event_pipeline_is_healthy():
                    break
                now = self._clock()
                if duration_seconds is not None and now - started_monotonic >= duration_seconds:
                    break
                if not self._backend_is_healthy() or not self._roots_are_healthy():
                    break
                if now >= next_health_check:
                    health_error = self._health_check()
                    if health_error is not None:
                        self._health_issue("watch_trust_state_changed", health_error)
                        break
                    next_health_check = now + min(5.0, self.config.reconcile_seconds)
                for pending in self._events.due():
                    self._scan_pending(pending)
                now = self._clock()
                if now >= next_heartbeat:
                    self._emit(
                        "health_heartbeat",
                        backend_active=self._active_backend,
                        roots=[str(root.path) for root in self.roots],
                        operational_incomplete=self._operational_incomplete,
                        stats=self._stats_snapshot(),
                        policy=watch_policy(self.config.quarantine),
                    )
                    next_heartbeat = now + self.config.heartbeat_seconds
                if now >= next_full_rescan:
                    self._reconcile("periodic_full_rescan", full=True)
                    next_full_rescan = now + self.config.full_rescan_seconds
                    next_reconcile = now + self.config.reconcile_seconds
                elif now >= next_reconcile:
                    self._reconcile("periodic_reconciliation", full=False)
                    next_reconcile = now + self.config.reconcile_seconds
                time.sleep(min(0.05, self.config.debounce_seconds / 2))
        except KeyboardInterrupt:
            interrupted = True
        finally:
            # Close the producer before the consumer so no observer callback can
            # arrive after the final drain and evidence snapshot.
            self._stop_observer()
            ingest_stop.set()
            if ingest_started:
                ingest_thread.join(timeout=5)
            if ingest_started and ingest_thread.is_alive():
                self._health_issue(
                    "watch_event_ingest_stopped",
                    "event ingestion worker did not stop within its bounded deadline",
                )
            self._events.ingest()
            self._event_pipeline_is_healthy()
            event_telemetry = self._events.telemetry()
            if event_telemetry["event_queue_total_depth"]:
                self._health_issue(
                    "watch_event_backlog_unprocessed",
                    "observer stopped with "
                    f"{event_telemetry['event_queue_total_depth']} queued path(s) "
                    "not scanned; coverage is unknown",
                )
            self._stats.events_received = event_telemetry["events_received"]
            self._stats.events_debounced = event_telemetry["events_debounced"]
            self._stats.events_excluded = event_telemetry["events_excluded"]
            self._stats.events_dropped += event_telemetry["events_dropped"]
            self._stats.pending_high_water = max(
                self._stats.pending_high_water, event_telemetry["pending_high_water"]
            )
            self._stats.oldest_pending_milliseconds = event_telemetry[
                "oldest_pending_milliseconds"
            ]
            self._stats.event_queue_capacity = event_telemetry["event_queue_capacity"]
            self._stats.event_queue_raw_depth = event_telemetry["event_queue_raw_depth"]
            self._stats.event_queue_pending_paths = event_telemetry[
                "event_queue_pending_paths"
            ]
            self._stats.event_queue_total_depth = event_telemetry[
                "event_queue_total_depth"
            ]

        summary = WatchSummary(
            started_at=started_at,
            completed_at=format_utc(),
            backend_requested=self.config.backend,
            backend_active=self._active_backend,
            fallback_reason=self._fallback_reason,
            roots=tuple(str(root.path) for root in self.roots),
            interrupted=interrupted,
            operational_incomplete=self._operational_incomplete,
            stats=self._stats,
            health_issues=tuple(self._health_issues),
            quarantine_requested=self.config.quarantine,
        )
        self._emit("session_completed", summary=summary.to_dict())
        return summary


def _scan_outcome(result: ScanResult) -> str:
    if result.issues:
        return "incomplete"
    if result.findings:
        return "configured_rule_matches_detected"
    return "no_configured_rule_matches"
