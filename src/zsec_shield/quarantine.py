"""Opt-in, recoverable quarantine storage with content verification."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zsec_shield.errors import FeedError, QuarantineError, QuarantinePartialError
from zsec_shield.models import FileFinding
from zsec_shield.paths import quarantine_entries_dir
from zsec_shield.util import atomic_write_json, format_utc, strict_json_loads

METADATA_SCHEMA = "zsec.shield.quarantine.v1"
CONTENT_NAME = "content.bin"
METADATA_NAME = "metadata.json"
COPY_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def _snapshot(metadata: os.stat_result) -> SourceSnapshot:
    return SourceSnapshot(
        device=metadata.st_dev,
        inode=getattr(metadata, "st_ino", 0),
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _same_snapshot(left: SourceSnapshot, right: SourceSnapshot) -> bool:
    inode_matches = not (left.inode and right.inode) or left.inode == right.inode
    return (
        left.device == right.device
        and inode_matches
        and left.size == right.size
        and left.modified_ns == right.modified_ns
    )


def _copy_regular_source(source: Path, destination: Path) -> tuple[str, SourceSnapshot]:
    try:
        before_stat = source.lstat()
    except OSError as exc:
        raise QuarantineError(f"cannot inspect source file: {exc}") from exc
    if (
        not stat.S_ISREG(before_stat.st_mode)
        or stat.S_ISLNK(before_stat.st_mode)
        or _is_reparse_point(before_stat)
    ):
        raise QuarantineError("quarantine source must be a regular, non-link file")
    before = _snapshot(before_stat)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise QuarantineError(f"cannot open source file: {exc}") from exc
    digest = hashlib.sha256()
    try:
        opened_stat = os.fstat(descriptor)
        opened = _snapshot(opened_stat)
        if not stat.S_ISREG(opened_stat.st_mode) or not _same_snapshot(before, opened):
            raise QuarantineError("source file identity changed before quarantine copy")
        with destination.open("xb") as target:
            while True:
                chunk = os.read(descriptor, COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        after = _snapshot(os.fstat(descriptor))
        if not _same_snapshot(opened, after) or destination.stat().st_size != opened.size:
            raise QuarantineError("source file changed during quarantine copy")
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    finally:
        os.close(descriptor)
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)
    return digest.hexdigest(), before


def quarantine_finding(finding: FileFinding, state_dir: Path) -> dict[str, Any]:
    source = Path(finding.path)
    if not source.is_absolute():
        raise QuarantineError("quarantine requires an absolute source path")
    entries = quarantine_entries_dir(state_dir)
    entries.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(entries, 0o700)
    entry_id = str(uuid.uuid4())
    temporary = Path(tempfile.mkdtemp(prefix=f".{entry_id}.", dir=str(entries)))
    final = entries / entry_id
    try:
        with contextlib.suppress(OSError):
            os.chmod(temporary, 0o700)
        digest, snapshot = _copy_regular_source(source, temporary / CONTENT_NAME)
        if digest != finding.sha256 or snapshot.size != finding.size:
            raise QuarantineError("source no longer matches the verified scan finding")
        metadata: dict[str, Any] = {
            "schema": METADATA_SCHEMA,
            "id": entry_id,
            "state": "copy_ready",
            "original_path": str(source),
            "sha256": digest,
            "size": snapshot.size,
            "original_mode": snapshot.mode,
            "original_modified_ns": snapshot.modified_ns,
            "created_at": format_utc(),
            "quarantined_at": None,
            "restore_history": [],
            "matches": [match.to_dict() for match in finding.matches],
        }
        atomic_write_json(temporary / METADATA_NAME, metadata, mode=0o600)
        temporary.rename(final)
    except BaseException:
        with contextlib.suppress(OSError):
            shutil.rmtree(temporary)
        raise

    # The verified copy is published before deletion. If deletion cannot be
    # completed, the record remains a recoverable copy_only entry and the caller
    # receives a partial-operation error instead of a false quarantine claim.
    try:
        current = _snapshot(source.lstat())
        if not _same_snapshot(snapshot, current):
            raise QuarantinePartialError(
                "verified recovery copy created, but source changed before removal",
                entry_id,
            )
        source.unlink()
    except QuarantinePartialError:
        metadata["state"] = "copy_only"
        atomic_write_json(final / METADATA_NAME, metadata, mode=0o600)
        raise
    except OSError as exc:
        metadata["state"] = "copy_only"
        atomic_write_json(final / METADATA_NAME, metadata, mode=0o600)
        raise QuarantinePartialError(
            f"verified recovery copy created, but original could not be removed: {exc}",
            entry_id,
        ) from exc

    metadata["state"] = "quarantined"
    metadata["quarantined_at"] = format_utc()
    atomic_write_json(final / METADATA_NAME, metadata, mode=0o600)
    return metadata


def _validate_entry_id(entry_id: str) -> str:
    try:
        parsed = uuid.UUID(entry_id)
    except ValueError as exc:
        raise QuarantineError("quarantine entry ID must be a UUID") from exc
    normalized = str(parsed)
    if normalized != entry_id.lower():
        raise QuarantineError("quarantine entry ID must use canonical UUID form")
    return normalized


def _read_metadata(entry: Path) -> dict[str, Any]:
    path = entry / METADATA_NAME
    try:
        if path.stat().st_size > 256 * 1024:
            raise QuarantineError("quarantine metadata is unexpectedly large")
        value = strict_json_loads(path.read_bytes())
    except FeedError as exc:
        raise QuarantineError(f"invalid quarantine metadata: {exc}") from exc
    except OSError as exc:
        raise QuarantineError(f"cannot read quarantine metadata: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != METADATA_SCHEMA:
        raise QuarantineError("unsupported quarantine metadata schema")
    required = {
        "schema",
        "id",
        "state",
        "original_path",
        "sha256",
        "size",
        "original_mode",
        "original_modified_ns",
        "created_at",
        "quarantined_at",
        "restore_history",
        "matches",
    }
    if set(value) != required or value.get("id") != entry.name:
        raise QuarantineError("quarantine metadata fields or identity are invalid")
    digest = value.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise QuarantineError("quarantine metadata digest is invalid")
    return value


def list_entries(state_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    entries_dir = quarantine_entries_dir(state_dir)
    if not entries_dir.exists():
        return [], []
    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    try:
        candidates = sorted(entries_dir.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise QuarantineError(f"cannot list quarantine: {exc}") from exc
    for entry in candidates:
        if entry.name.startswith("."):
            continue
        try:
            _validate_entry_id(entry.name)
            metadata = _read_metadata(entry)
            records.append(
                {
                    "id": metadata["id"],
                    "state": metadata["state"],
                    "original_path": metadata["original_path"],
                    "sha256": metadata["sha256"],
                    "size": metadata["size"],
                    "created_at": metadata["created_at"],
                    "quarantined_at": metadata["quarantined_at"],
                    "restore_count": len(metadata["restore_history"]),
                    "matches": metadata["matches"],
                }
            )
        except QuarantineError as exc:
            errors.append({"entry": entry.name, "error": str(exc)})
    return records, errors


def _hash_regular_file(path: Path) -> tuple[str, int]:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            raise QuarantineError("quarantine content is not a regular, non-link file")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(COPY_CHUNK_BYTES), b""):
                size += len(chunk)
                digest.update(chunk)
        return digest.hexdigest(), size
    except QuarantineError:
        raise
    except OSError as exc:
        raise QuarantineError(f"cannot verify quarantine content: {exc}") from exc


def restore_entry(
    entry_id: str, state_dir: Path, destination: Path | None = None
) -> dict[str, Any]:
    normalized = _validate_entry_id(entry_id)
    entry = quarantine_entries_dir(state_dir) / normalized
    metadata = _read_metadata(entry)
    content = entry / CONTENT_NAME
    digest, size = _hash_regular_file(content)
    if digest != metadata["sha256"] or size != metadata["size"]:
        raise QuarantineError("quarantine content failed its SHA-256 or size check")
    target = Path(metadata["original_path"]) if destination is None else destination
    target = target.expanduser().absolute()
    if target.exists() or target.is_symlink():
        raise QuarantineError(f"restore destination already exists: {target}")
    try:
        parent_metadata = target.parent.lstat()
    except OSError as exc:
        raise QuarantineError(f"restore parent is unavailable: {exc}") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode) or _is_reparse_point(parent_metadata):
        raise QuarantineError("restore parent must be an existing, non-reparse directory")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".zsec-shield-restore.", dir=str(target.parent)
    )
    temporary = Path(temporary_name)
    copied_digest = hashlib.sha256()
    copied_size = 0
    try:
        with content.open("rb") as source, os.fdopen(descriptor, "wb") as output:
            for chunk in iter(lambda: source.read(COPY_CHUNK_BYTES), b""):
                copied_digest.update(chunk)
                copied_size += len(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if copied_digest.hexdigest() != digest or copied_size != size:
            raise QuarantineError("restore copy verification failed")
        with contextlib.suppress(OSError):
            os.chmod(temporary, int(metadata["original_mode"]) & 0o777)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise QuarantineError(f"restore destination appeared during restore: {target}") from exc
        except OSError as exc:
            raise QuarantineError(
                "filesystem does not support the required no-overwrite restore operation"
            ) from exc
        temporary.unlink()
        with contextlib.suppress(OSError):
            os.utime(
                target,
                ns=(int(metadata["original_modified_ns"]), int(metadata["original_modified_ns"])),
            )
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise

    history = metadata["restore_history"]
    if not isinstance(history, list):
        raise QuarantineError("restore history is invalid")
    history.append({"restored_at": format_utc(), "destination": str(target)})
    metadata["state"] = "restored"
    metadata["restore_history"] = history[-100:]
    atomic_write_json(entry / METADATA_NAME, metadata, mode=0o600)
    return {
        "id": normalized,
        "state": "restored",
        "destination": str(target),
        "sha256": digest,
        "size": size,
        "recovery_copy_retained": True,
    }
