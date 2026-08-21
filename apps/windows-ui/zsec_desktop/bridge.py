"""Bounded, shell-free bridge between the desktop client and ZSEC CLI.

The UI process is an unprivileged orchestrator.  The versioned JSON contracts,
not console wording or exit code alone, determine what may be displayed.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zsec_desktop.contracts import (
    ContractError,
    validate_companion_status,
    validate_feed_update,
    validate_quarantine_list,
    validate_readiness,
    validate_scan_report,
    validate_status,
    validate_watch_event,
)

MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_WATCH_LINE_BYTES = 4 * 1024 * 1024


class BridgeError(RuntimeError):
    """The CLI failed, timed out, exceeded a bound, or violated a contract."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    payload: dict[str, Any]
    stderr: str


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BridgeError(f"cannot inspect executable path: {path}: {exc}") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def _regular_file(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise BridgeError(f"cannot inspect {label}: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(absolute)
    ):
        raise BridgeError(f"{label} must be a regular non-link file: {absolute}")
    try:
        return absolute.resolve(strict=True)
    except OSError as exc:
        raise BridgeError(f"cannot resolve {label}: {exc}") from exc


def discover_cli(explicit: Path | None = None) -> tuple[str, ...]:
    """Resolve a fixed executable without invoking a command shell."""

    configured = explicit
    if configured is None:
        environment = os.environ.get("ZSEC_GUI_CLI")
        configured = Path(environment) if environment else None
    if configured is not None:
        return (str(_regular_file(configured, "ZSEC CLI")),)

    # The packaged Windows layout keeps the GUI and engine in sibling folders:
    # ``App\ZSEC Antivirus.exe`` and ``Engine\zsec-shield.exe``. Resolve that
    # fixed path before consulting PATH so a user cannot accidentally bind the
    # desktop to an unrelated executable with the same filename.
    if getattr(sys, "frozen", False) and os.name == "nt":
        bundled = Path(sys.executable).absolute().parent.parent / "Engine" / "zsec-shield.exe"
        if bundled.exists():
            return (str(_regular_file(bundled, "bundled ZSEC CLI")),)

    candidates = (
        "zero-security.exe",
        "zero-security",
        "zsec-shield.exe",
        "zsec-shield",
    )
    for candidate in candidates:
        located = shutil.which(candidate)
        if located:
            return (str(_regular_file(Path(located), "ZSEC CLI")),)

    # Source-tree mode is intentionally explicit and uses this exact interpreter.
    # Importing the package proves that ``python -m zsec_shield`` is available.
    try:
        __import__("zsec_shield")
    except ImportError as exc:
        raise BridgeError(
            "Cannot locate zero-security or zsec-shield. Set ZSEC_GUI_CLI to the "
            "reviewed executable."
        ) from exc
    return (str(_regular_file(Path(sys.executable), "Python runtime")), "-m", "zsec_shield")


def _creation_flags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _bounded_text(path: Path, maximum: int, label: str) -> str:
    try:
        size = path.stat().st_size
        if size > maximum:
            raise BridgeError(f"{label} exceeded the {maximum}-byte bound")
        return path.read_text(encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise BridgeError(f"{label} was not valid UTF-8") from exc
    except OSError as exc:
        raise BridgeError(f"cannot read {label}: {exc}") from exc


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BridgeError("ZSEC returned invalid JSON") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise BridgeError("ZSEC JSON response must be an object")
    return value


class ZsecBridge:
    """Safe desktop façade over public CLI contracts."""

    def __init__(
        self,
        *,
        state_dir: Path,
        cli: Path | None = None,
        companion_status_script: Path | None = None,
    ) -> None:
        self.state_dir = state_dir.expanduser().absolute()
        self.cli_prefix = discover_cli(cli)
        self.companion_status_script = companion_status_script

    def _argv(self, *arguments: str, with_state: bool = True) -> tuple[str, ...]:
        prefix = list(self.cli_prefix)
        if with_state:
            prefix.extend(("--state-dir", str(self.state_dir)))
        prefix.extend(arguments)
        return tuple(prefix)

    def _run_json(
        self,
        argv: Sequence[str],
        *,
        expected_codes: frozenset[int],
        timeout: float,
        validator: Callable[[Any], dict[str, Any]],
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        if not argv:
            raise BridgeError("empty command")
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        with tempfile.TemporaryDirectory(prefix="zsec-gui-command-") as temporary:
            stdout_path = Path(temporary) / "stdout.json"
            stderr_path = Path(temporary) / "stderr.txt"
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                try:
                    process = subprocess.Popen(
                        list(argv),
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        shell=False,
                        close_fds=True,
                        env=environment,
                        creationflags=_creation_flags(),
                    )
                except OSError as exc:
                    raise BridgeError(f"could not start ZSEC: {exc}") from exc
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if cancel is not None and cancel.is_set():
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                        raise BridgeError("operation cancelled")
                    if time.monotonic() >= deadline:
                        process.kill()
                        process.wait(timeout=5)
                        raise BridgeError(f"ZSEC command exceeded the {timeout:g}-second timeout")
                    try:
                        if stdout_path.stat().st_size > MAX_STDOUT_BYTES:
                            process.kill()
                            process.wait(timeout=5)
                            raise BridgeError("ZSEC stdout exceeded its safety bound")
                        if stderr_path.stat().st_size > MAX_STDERR_BYTES:
                            process.kill()
                            process.wait(timeout=5)
                            raise BridgeError("ZSEC stderr exceeded its safety bound")
                    except OSError as exc:
                        process.kill()
                        process.wait(timeout=5)
                        raise BridgeError(f"cannot monitor ZSEC output: {exc}") from exc
                    time.sleep(0.05)
                exit_code = int(process.returncode)
            stdout = _bounded_text(stdout_path, MAX_STDOUT_BYTES, "ZSEC stdout")
            stderr = _bounded_text(stderr_path, MAX_STDERR_BYTES, "ZSEC stderr").strip()
        payload = _json_object(stdout)
        if exit_code not in expected_codes:
            if payload.get("schema") == "zsec.shield.error.v1":
                message = str(payload.get("message", "ZSEC command failed"))[:1000]
                raise BridgeError(message)
            raise BridgeError(f"ZSEC exited with unexpected code {exit_code}")
        try:
            validated = validator(payload)
        except ContractError as exc:
            raise BridgeError(f"unsafe ZSEC response: {exc}") from exc
        return CommandResult(tuple(argv), exit_code, validated, stderr)

    def status(self) -> CommandResult:
        return self._run_json(
            self._argv("status", "--json"),
            expected_codes=frozenset({0, 2}),
            timeout=30,
            validator=validate_status,
        )

    def replacement_readiness(self) -> CommandResult:
        return self._run_json(
            self._argv(
                "replacement-readiness", "--platform", "windows", "--json", with_state=False
            ),
            expected_codes=frozenset({2}),
            timeout=30,
            validator=validate_readiness,
        )

    def quarantine_entries(self) -> CommandResult:
        return self._run_json(
            self._argv("quarantine", "list", "--json"),
            expected_codes=frozenset({0, 2}),
            timeout=30,
            validator=validate_quarantine_list,
        )

    def restore_quarantine(self, entry_id: str, destination: Path | None = None) -> CommandResult:
        arguments = ["quarantine", "restore", entry_id]
        if destination is not None:
            arguments.extend(("--destination", str(destination.expanduser().absolute())))
        arguments.append("--json")

        def validate_restore(value: Any) -> dict[str, Any]:
            root = _json_object(json.dumps(value))
            if root.get("schema") != "zsec.shield.restore-result.v1":
                raise ContractError("unsupported restore-result schema")
            if root.get("id") != entry_id:
                raise ContractError("restore result does not match the requested entry")
            if not isinstance(root.get("destination"), str) or not root["destination"]:
                raise ContractError("restore destination is invalid")
            return root

        return self._run_json(
            self._argv(*arguments),
            expected_codes=frozenset({0}),
            timeout=300,
            validator=validate_restore,
        )

    def scan(
        self,
        paths: Sequence[Path],
        *,
        quarantine: bool,
        max_file_bytes: int,
        cross_filesystems: bool = False,
        report_path: Path | None = None,
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        if not paths:
            raise BridgeError("choose at least one scan path")
        if not 1 <= max_file_bytes <= 16 * 1024 * 1024 * 1024:
            raise BridgeError("maximum file size must be between 1 byte and 16 GiB")
        resolved: list[str] = []
        for path in paths:
            candidate = path.expanduser().absolute()
            if not candidate.exists():
                raise BridgeError(f"scan path does not exist: {candidate}")
            resolved.append(str(candidate))
        arguments = ["check", *resolved, "--max-file-bytes", str(max_file_bytes), "--json"]
        if quarantine:
            arguments.append("--quarantine")
        if cross_filesystems:
            arguments.append("--cross-filesystems")
        if report_path is not None:
            reports = self._reports_directory(create=True)
            absolute_report = report_path.expanduser().absolute()
            try:
                if os.path.commonpath((str(absolute_report), str(reports))) != str(reports):
                    raise BridgeError("scan report path must stay below the ZSEC reports directory")
            except ValueError as exc:
                raise BridgeError("scan report path is on an unexpected volume") from exc
            if absolute_report.suffix.lower() != ".json":
                raise BridgeError("scan report must use a .json filename")
            arguments.extend(("--report", str(absolute_report)))
        return self._run_json(
            self._argv(*arguments),
            expected_codes=frozenset({0, 1, 2}),
            timeout=6 * 60 * 60,
            validator=validate_scan_report,
            cancel=cancel,
        )

    def new_report_path(self) -> Path:
        reports = self._reports_directory(create=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return reports / f"scan-{stamp}-{uuid.uuid4().hex[:8]}.json"

    def list_reports(self) -> list[dict[str, Any]]:
        reports = self._reports_directory(create=False)
        if not reports.exists():
            return []
        values: list[dict[str, Any]] = []
        try:
            candidates = sorted(reports.glob("*.json"), key=lambda path: path.name, reverse=True)
        except OSError as exc:
            raise BridgeError(f"cannot enumerate reports: {exc}") from exc
        for candidate in candidates[:500]:
            try:
                regular = _regular_file(candidate, "scan report")
                if regular.parent != reports:
                    raise BridgeError("report escaped the reports directory")
                size = regular.stat().st_size
                payload = validate_scan_report(
                    _json_object(_bounded_text(regular, MAX_STDOUT_BYTES, "scan report"))
                )
            except (BridgeError, ContractError, OSError) as exc:
                values.append(
                    {
                        "path": str(candidate),
                        "name": candidate.name,
                        "size": None,
                        "generated_at": None,
                        "outcome": "invalid",
                        "error": str(exc)[:500],
                    }
                )
                continue
            values.append(
                {
                    "path": str(regular),
                    "name": regular.name,
                    "size": size,
                    "generated_at": payload.get("generated_at"),
                    "outcome": payload.get("outcome"),
                    "error": None,
                }
            )
        return values

    def read_report(self, path: Path) -> dict[str, Any]:
        reports = self._reports_directory(create=False)
        regular = _regular_file(path, "scan report")
        if regular.parent != reports:
            raise BridgeError("report must be a direct file in the ZSEC reports directory")
        try:
            return validate_scan_report(
                _json_object(_bounded_text(regular, MAX_STDOUT_BYTES, "scan report"))
            )
        except ContractError as exc:
            raise BridgeError(f"unsafe scan report: {exc}") from exc

    def _reports_directory(self, *, create: bool) -> Path:
        state = self.state_dir
        reports = state / "reports"
        if create:
            try:
                state.mkdir(parents=True, exist_ok=True, mode=0o700)
                reports.mkdir(exist_ok=True, mode=0o700)
            except OSError as exc:
                raise BridgeError(f"cannot create reports directory: {exc}") from exc
        for candidate in (state, reports):
            if not candidate.exists():
                continue
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise BridgeError(f"cannot inspect reports directory: {exc}") from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse_point(candidate)
            ):
                raise BridgeError(f"reports path must be a regular non-link directory: {candidate}")
        return reports.absolute()

    def update_feed_file(self, path: Path) -> CommandResult:
        source = _regular_file(path, "signed feed file")
        return self._run_json(
            self._argv("update", "--file", str(source), "--json"),
            expected_codes=frozenset({0}),
            timeout=120,
            validator=validate_feed_update,
        )

    def companion_status(self) -> CommandResult:
        if os.name != "nt":
            raise BridgeError("Windows companion status is available only on Windows")
        script = self.companion_status_script
        if script is None:
            if getattr(sys, "frozen", False) and os.name == "nt":
                script = (
                    Path(sys.executable).absolute().parent.parent
                    / "Tools"
                    / "Get-ZsecAntivirusCompanionStatus.ps1"
                )
            else:
                project_root = Path(__file__).resolve().parents[3]
                script = (
                    project_root
                    / "windows"
                    / "companion"
                    / "Get-ZsecAntivirusCompanionStatus.ps1"
                )
        script = _regular_file(script, "companion status script")
        system_root = os.environ.get("SYSTEMROOT")
        if not system_root:
            raise BridgeError("SystemRoot is unavailable")
        powershell = _regular_file(
            Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            "Windows PowerShell",
        )
        argv = (
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-File",
            str(script),
            "-StateDirectory",
            str(self.state_dir),
        )
        return self._run_json(
            argv,
            expected_codes=frozenset({0, 2}),
            timeout=60,
            validator=validate_companion_status,
        )

    def start_watch(
        self,
        paths: Sequence[Path],
        *,
        on_event: Callable[[dict[str, Any]], None],
        on_complete: Callable[[int, str | None], None],
        quarantine: bool = False,
    ) -> WatchSession:
        if not paths:
            raise BridgeError("choose at least one monitoring directory")
        roots: list[str] = []
        for path in paths:
            candidate = path.expanduser().absolute()
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise BridgeError(
                    f"cannot inspect monitoring directory: {candidate}: {exc}"
                ) from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse_point(candidate)
            ):
                raise BridgeError(
                    f"monitoring root must be a regular non-link directory: {candidate}"
                )
            roots.append(str(candidate))
        session = WatchSession(
            argv=self._argv("watch", *roots, "--json-lines"),
            on_event=on_event,
            on_complete=on_complete,
            quarantine=quarantine,
        )
        session.start()
        return session


class WatchSession:
    """One bounded foreground post-change session owned by the UI."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        on_event: Callable[[dict[str, Any]], None],
        on_complete: Callable[[int, str | None], None],
        quarantine: bool,
    ) -> None:
        arguments = list(argv)
        if quarantine:
            arguments.append("--quarantine")
        self.argv = tuple(arguments)
        self.on_event = on_event
        self.on_complete = on_complete
        self._process: subprocess.Popen[bytes] | None = None
        self._thread: threading.Thread | None = None
        self._stopped_by_user = False

    def start(self) -> None:
        if self._thread is not None:
            raise BridgeError("watch session was already started")
        self._thread = threading.Thread(target=self._run, name="zsec-watch-bridge", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopped_by_user = True
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def _run(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        stderr_buffer = bytearray()
        stderr_lock = threading.Lock()
        error: str | None = None
        exit_code = 2
        try:
            process = subprocess.Popen(
                list(self.argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                env=environment,
                creationflags=_creation_flags(),
            )
            self._process = process
            stdout = process.stdout
            stderr = process.stderr
            assert stdout is not None
            assert stderr is not None

            def read_stderr() -> None:
                while True:
                    chunk = stderr.read(65536)
                    if not chunk:
                        return
                    with stderr_lock:
                        if len(stderr_buffer) + len(chunk) > MAX_STDERR_BYTES:
                            process.kill()
                            return
                        stderr_buffer.extend(chunk)

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()
            pending = bytearray()
            while True:
                chunk = stdout.read(65536)
                if not chunk:
                    break
                pending.extend(chunk)
                if len(pending) > MAX_WATCH_LINE_BYTES and b"\n" not in pending:
                    raise BridgeError("watch event exceeded its line-size bound")
                while b"\n" in pending:
                    raw, _, remainder = pending.partition(b"\n")
                    pending = bytearray(remainder)
                    if not raw.strip():
                        continue
                    if len(raw) > MAX_WATCH_LINE_BYTES:
                        raise BridgeError("watch event exceeded its line-size bound")
                    try:
                        event = validate_watch_event(
                            _json_object(raw.decode("utf-8", errors="strict"))
                        )
                    except (UnicodeError, ContractError, BridgeError) as exc:
                        raise BridgeError(f"unsafe watch event: {exc}") from exc
                    self.on_event(event)
            if pending.strip():
                raise BridgeError("watch stream ended with an incomplete JSON record")
            exit_code = int(process.wait(timeout=10))
            stderr_thread.join(timeout=2)
            if self._stopped_by_user:
                error = "Stopped by the user; no completed coverage claim is available."
            elif exit_code not in {0, 1, 2, 130}:
                error = f"watch exited with unexpected code {exit_code}"
            elif exit_code in {2, 130}:
                error = "Watch ended incomplete or interrupted."
        except (BridgeError, OSError, subprocess.SubprocessError) as exc:
            error = str(exc)
            active_process = self._process
            if active_process is not None and active_process.poll() is None:
                active_process.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    active_process.wait(timeout=5)
        finally:
            if error is None and stderr_buffer:
                try:
                    decoded = bytes(stderr_buffer).decode("utf-8", errors="strict").strip()
                except UnicodeError:
                    decoded = "Watch stderr was not valid UTF-8."
                error = decoded or None
            self.on_complete(exit_code, error)


__all__ = [
    "BridgeError",
    "CommandResult",
    "WatchSession",
    "ZsecBridge",
    "discover_cli",
]
