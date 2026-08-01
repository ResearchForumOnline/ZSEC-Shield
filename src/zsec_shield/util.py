"""Small security-sensitive helpers shared across modules."""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from zsec_shield.errors import FeedError


class _MsvcrtModule(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, file_descriptor: int, mode: int, byte_count: int, /) -> None: ...


class _FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, file_descriptor: int, operation: int, /) -> None: ...


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_utc(value: datetime | None = None) -> str:
    current = value or utc_now()
    return current.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FeedError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: bytes | str) -> Any:
    try:
        text = raw.decode("utf-8", "strict") if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as exc:
        raise FeedError("JSON must be valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                FeedError(f"non-finite JSON number rejected: {value}")
            ),
        )
    except FeedError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise FeedError(f"invalid JSON: {exc}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, data, mode=mode)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def update_lock(path: Path) -> Iterator[None]:
    """Take a non-blocking, cross-platform advisory lock for feed updates."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        if os.name == "nt":
            windows_locking = cast(_MsvcrtModule, importlib.import_module("msvcrt"))

            handle.seek(0)
            if handle.read(1) == b"":
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                windows_locking.locking(handle.fileno(), windows_locking.LK_NBLCK, 1)
            except OSError as exc:
                raise FeedError("another feed update is already in progress") from exc
        else:
            posix_locking = cast(_FcntlModule, importlib.import_module("fcntl"))

            try:
                posix_locking.flock(handle.fileno(), posix_locking.LOCK_EX | posix_locking.LOCK_NB)
            except OSError as exc:
                raise FeedError("another feed update is already in progress") from exc
        yield
    finally:
        if os.name == "nt":
            windows_locking = cast(_MsvcrtModule, importlib.import_module("msvcrt"))

            with contextlib.suppress(OSError):
                handle.seek(0)
                windows_locking.locking(handle.fileno(), windows_locking.LK_UNLCK, 1)
        else:
            posix_locking = cast(_FcntlModule, importlib.import_module("fcntl"))

            with contextlib.suppress(OSError):
                posix_locking.flock(handle.fileno(), posix_locking.LOCK_UN)
        handle.close()
