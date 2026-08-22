"""Bounded local evidence for a supervised foreground watch process.

Evidence files must stay under the scanner state directory, which the watcher
already excludes. This prevents log and heartbeat writes from feeding back into
filesystem-event scanning.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from zsec_shield.errors import WatchError
from zsec_shield.util import atomic_write_json, format_utc

MIN_EVENT_LOG_BYTES = 64 * 1024
MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024
MIN_EVENT_LOG_BACKUPS = 1
MAX_EVENT_LOG_BACKUPS = 10


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(_absolute(path))))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((_path_key(path), _path_key(parent))) == _path_key(parent)
    except ValueError:
        return False


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def _validate_evidence_path(path: Path, state_dir: Path) -> Path:
    absolute = _absolute(path)
    state = _absolute(state_dir)
    if absolute == state or not _is_within(absolute, state):
        raise WatchError("watch evidence files must be located below the excluded state directory")

    current = absolute.parent
    parents: list[Path] = []
    while current != state:
        parents.append(current)
        parent = current.parent
        if parent == current or not _is_within(current, state):
            raise WatchError("watch evidence path escaped the state directory")
        current = parent
    for candidate in reversed(parents):
        if not candidate.exists():
            continue
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise WatchError(
                f"cannot inspect watch evidence directory: {candidate}: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            raise WatchError(
                f"watch evidence directory must not be a link or reparse point: {candidate}"
            )
    if absolute.exists():
        try:
            metadata = absolute.lstat()
        except OSError as exc:
            raise WatchError(f"cannot inspect watch evidence file: {absolute}: {exc}") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            raise WatchError(
                f"watch evidence path must be a regular, non-link file: {absolute}"
            )
    return absolute


class RotatingNdjsonLog:
    """Append complete NDJSON records and retain a bounded number of files."""

    def __init__(
        self,
        path: Path,
        state_dir: Path,
        *,
        max_bytes: int,
        backups: int,
    ) -> None:
        if not MIN_EVENT_LOG_BYTES <= max_bytes <= MAX_EVENT_LOG_BYTES:
            raise WatchError(
                f"event log max_bytes must be between {MIN_EVENT_LOG_BYTES} "
                f"and {MAX_EVENT_LOG_BYTES}"
            )
        if not MIN_EVENT_LOG_BACKUPS <= backups <= MAX_EVENT_LOG_BACKUPS:
            raise WatchError(
                f"event log backups must be between {MIN_EVENT_LOG_BACKUPS} "
                f"and {MAX_EVENT_LOG_BACKUPS}"
            )
        self.path = _validate_evidence_path(path, state_dir)
        self.state_dir = _absolute(state_dir)
        self.max_bytes = max_bytes
        self.backups = backups

    def append(self, record: dict[str, Any]) -> None:
        encoded = (
            json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise WatchError("one watch event is larger than the configured event-log bound")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_evidence_path(self.path, self.state_dir)
        try:
            current_size = self.path.stat().st_size if self.path.exists() else 0
        except OSError as exc:
            raise WatchError(f"cannot inspect watch event log: {exc}") from exc
        if current_size and current_size + len(encoded) > self.max_bytes:
            self._rotate()
        self._append_bytes(encoded)

    def _backup(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def _rotate(self) -> None:
        oldest = self._backup(self.backups)
        if oldest.exists():
            _validate_evidence_path(oldest, self.state_dir)
            try:
                oldest.unlink()
            except OSError as exc:
                raise WatchError(f"cannot remove oldest watch event log: {exc}") from exc
        for index in range(self.backups - 1, 0, -1):
            source = self._backup(index)
            if not source.exists():
                continue
            _validate_evidence_path(source, self.state_dir)
            target = self._backup(index + 1)
            if target.exists():
                _validate_evidence_path(target, self.state_dir)
            try:
                os.replace(source, target)
            except OSError as exc:
                raise WatchError(f"cannot rotate watch event log: {exc}") from exc
        target = self._backup(1)
        if target.exists():
            _validate_evidence_path(target, self.state_dir)
        try:
            os.replace(self.path, target)
        except OSError as exc:
            raise WatchError(f"cannot rotate current watch event log: {exc}") from exc

    def _append_bytes(self, encoded: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            flags |= no_follow
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise WatchError(f"cannot open watch event log: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
                raise WatchError("opened watch event log is not a regular, non-reparse file")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise WatchError("watch event log append made no progress")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as exc:
            raise WatchError(f"cannot append watch event log: {exc}") from exc
        finally:
            os.close(descriptor)


class WatchEvidenceSink:
    """Persist a rotating event stream plus a compact atomic health snapshot."""

    def __init__(
        self,
        *,
        state_dir: Path,
        health_file: Path | None,
        event_log: Path | None,
        event_log_max_bytes: int,
        event_log_backups: int,
        heartbeat_seconds: float,
    ) -> None:
        self.state_dir = _absolute(state_dir)
        self.health_file = (
            _validate_evidence_path(health_file, state_dir) if health_file is not None else None
        )
        self.event_log = (
            RotatingNdjsonLog(
                event_log,
                state_dir,
                max_bytes=event_log_max_bytes,
                backups=event_log_backups,
            )
            if event_log is not None
            else None
        )
        self.heartbeat_seconds = heartbeat_seconds
        self.process_started_at = format_utc()
        self.runtime_executable = str(Path(sys.executable).resolve())
        self.runtime_sha256 = _sha256_file(Path(self.runtime_executable))
        self.backend_active: str | None = None
        self.roots: list[str] = []
        self.policy: dict[str, Any] = {}
        self.operational_state = "starting"
        self.last_outcome: str | None = None
        self.counters: dict[str, int] = {}

    def record(self, payload: dict[str, Any]) -> None:
        if self.event_log is not None:
            self.event_log.append(payload)
        if self.health_file is None:
            return

        event = payload.get("event")
        if event == "session_started":
            self.backend_active = _optional_string(payload.get("backend_active"))
            roots = payload.get("roots")
            if isinstance(roots, list) and all(isinstance(value, str) for value in roots):
                self.roots = roots
            policy = payload.get("policy")
            if isinstance(policy, dict):
                self.policy = policy
            self.operational_state = "baselining"
        elif event == "health_issue":
            self.operational_state = "degraded"
        elif event == "scan_completed":
            self.last_outcome = _optional_string(payload.get("outcome"))
            scan = payload.get("scan")
            if isinstance(scan, dict) and isinstance(scan.get("stats"), dict):
                self.counters = _integer_values(scan["stats"])
            if self.last_outcome == "incomplete":
                self.operational_state = "degraded"
            elif payload.get("triggers") == ["initial_baseline"]:
                self.operational_state = "healthy"
        elif event == "reconciliation_completed":
            self.last_outcome = _optional_string(payload.get("outcome"))
            scan = payload.get("scan")
            if isinstance(scan, dict) and isinstance(scan.get("stats"), dict):
                self.counters = _integer_values(scan["stats"])
            if self.last_outcome == "incomplete":
                self.operational_state = "degraded"
        elif event == "health_heartbeat":
            self.backend_active = _optional_string(payload.get("backend_active"))
            stats = payload.get("stats")
            if isinstance(stats, dict):
                self.counters = _integer_values(stats)
            if payload.get("operational_incomplete") is True:
                self.operational_state = "degraded"
        elif event == "session_completed":
            self.operational_state = "stopped"
            summary = payload.get("summary")
            if isinstance(summary, dict):
                self.last_outcome = _optional_string(summary.get("outcome"))
                stats = summary.get("stats")
                if isinstance(stats, dict):
                    self.counters = _integer_values(stats)

        health = {
            "schema": "zsec.antivirus.companion-health.v1",
            "product": "ZSEC Antivirus",
            "engine": "ZSEC Shield",
            "version": payload.get("version"),
            "process_id": os.getpid(),
            "process_started_at": self.process_started_at,
            "runtime_executable": self.runtime_executable,
            "runtime_sha256": self.runtime_sha256,
            "updated_at": payload.get("generated_at"),
            "heartbeat_seconds": self.heartbeat_seconds,
            "session_id": payload.get("session_id"),
            "sequence": payload.get("sequence"),
            "last_event": event,
            "operational_state": self.operational_state,
            "backend_active": self.backend_active,
            "roots": self.roots,
            "last_outcome": self.last_outcome,
            "counters": self.counters,
            "policy": self.policy,
        }
        atomic_write_json(self.health_file, health, mode=0o600)


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _integer_values(value: dict[str, Any]) -> dict[str, int]:
    return {
        key: item
        for key, item in value.items()
        if isinstance(key, str) and type(item) is int
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise WatchError(f"cannot hash the active runtime executable: {exc}") from exc
    return digest.hexdigest()
