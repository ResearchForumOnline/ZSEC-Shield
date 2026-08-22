"""Opt-in, recoverable quarantine with authenticated encrypted storage."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zsec_shield.crypto_vault import (
    VaultEnvelope,
    create_envelope,
    load_device_root,
    sign_metadata,
    unwrap_content_key,
    verify_metadata,
)
from zsec_shield.errors import FeedError, QuarantineError, QuarantinePartialError
from zsec_shield.models import FileFinding
from zsec_shield.paths import quarantine_entries_dir
from zsec_shield.util import atomic_write_json, canonical_json_bytes, format_utc, strict_json_loads
from zsec_shield.zba import create_quarantine_record, validate_quarantine_record

LEGACY_METADATA_SCHEMA = "zsec.shield.quarantine.v1"
METADATA_SCHEMA = "zero.security.quarantine.v2"
LEGACY_CONTENT_NAME = "content.bin"
CONTENT_NAME = "content.zsv2"
METADATA_NAME = "metadata.json"
COPY_CHUNK_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024


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


def _inspect_regular_source(source: Path) -> SourceSnapshot:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise QuarantineError(f"cannot inspect source file: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
    ):
        raise QuarantineError("quarantine source must be a regular, non-link file")
    return _snapshot(metadata)


def _encrypt_regular_source(
    source: Path,
    destination: Path,
    *,
    expected: SourceSnapshot,
    content_key: bytes,
    content_nonce: bytes,
    aad: bytes,
) -> tuple[str, bytes]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise QuarantineError(f"cannot open source file: {exc}") from exc
    digest = hashlib.sha256()
    encryptor = Cipher(algorithms.AES(content_key), modes.GCM(content_nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    try:
        opened_stat = os.fstat(descriptor)
        opened = _snapshot(opened_stat)
        if not stat.S_ISREG(opened_stat.st_mode) or not _same_snapshot(expected, opened):
            raise QuarantineError("source file identity changed before quarantine encryption")
        with destination.open("xb") as target:
            while True:
                chunk = os.read(descriptor, COPY_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                target.write(encryptor.update(chunk))
            target.write(encryptor.finalize())
            target.flush()
            os.fsync(target.fileno())
        after = _snapshot(os.fstat(descriptor))
        if not _same_snapshot(opened, after) or destination.stat().st_size != opened.size:
            raise QuarantineError("source file changed during quarantine encryption")
    except BaseException:
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    finally:
        os.close(descriptor)
    with contextlib.suppress(OSError):
        os.chmod(destination, 0o600)
    return digest.hexdigest(), encryptor.tag


def _aad_projection(metadata: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "schema",
        "id",
        "original_path",
        "sha256",
        "size",
        "original_mode",
        "original_modified_ns",
        "created_at",
        "matches",
        "zba",
    )
    return {field: metadata[field] for field in fields}


def _write_v2_metadata(path: Path, metadata: dict[str, Any], state_dir: Path) -> dict[str, Any]:
    device = load_device_root(state_dir, create=False)
    signed = sign_metadata(device, metadata)
    atomic_write_json(path, signed, mode=0o600)
    return signed


def quarantine_finding(finding: FileFinding, state_dir: Path) -> dict[str, Any]:
    source = Path(finding.path)
    if not source.is_absolute():
        raise QuarantineError("quarantine requires an absolute source path")
    snapshot = _inspect_regular_source(source)
    if snapshot.size != finding.size:
        raise QuarantineError("source no longer matches the verified scan finding")
    entries = quarantine_entries_dir(state_dir)
    entries.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(entries, 0o700)
    entry_id = str(uuid.uuid4())
    created_at = format_utc()
    temporary = Path(tempfile.mkdtemp(prefix=f".{entry_id}.", dir=str(entries)))
    final = entries / entry_id
    device = load_device_root(state_dir, create=True)
    metadata: dict[str, Any] = {
        "schema": METADATA_SCHEMA,
        "id": entry_id,
        "state": "copy_ready",
        "original_path": str(source),
        "sha256": finding.sha256,
        "size": snapshot.size,
        "original_mode": snapshot.mode,
        "original_modified_ns": snapshot.modified_ns,
        "created_at": created_at,
        "quarantined_at": None,
        "restore_history": [],
        "matches": [match.to_dict() for match in finding.matches],
        "zba": create_quarantine_record(
            entry_id=entry_id, payload_sha256=finding.sha256, created_at=created_at
        ),
    }
    aad = canonical_json_bytes(_aad_projection(metadata))
    envelope, content_key = create_envelope(device, entry_id=entry_id, aad=aad)
    try:
        with contextlib.suppress(OSError):
            os.chmod(temporary, 0o700)
        digest, content_tag = _encrypt_regular_source(
            source,
            temporary / CONTENT_NAME,
            expected=snapshot,
            content_key=content_key,
            content_nonce=envelope.content_nonce,
            aad=aad,
        )
        if digest != finding.sha256:
            raise QuarantineError("source no longer matches the verified scan finding")
        metadata["vault"] = envelope.to_dict(device.protection)
        metadata["content_tag"] = base64.b64encode(content_tag).decode("ascii")
        metadata = sign_metadata(device, metadata)
        atomic_write_json(temporary / METADATA_NAME, metadata, mode=0o600)
        temporary.rename(final)
    except BaseException:
        with contextlib.suppress(OSError):
            shutil.rmtree(temporary)
        raise
    finally:
        content_key = b""

    # The authenticated recovery copy is published before deletion. If the
    # original cannot be removed, the record remains an honest copy_only entry.
    try:
        current = _snapshot(source.lstat())
        if not _same_snapshot(snapshot, current):
            raise QuarantinePartialError(
                "authenticated recovery copy created, but source changed before removal",
                entry_id,
            )
        source.unlink()
    except QuarantinePartialError:
        metadata["state"] = "copy_only"
        _write_v2_metadata(final / METADATA_NAME, metadata, state_dir)
        raise
    except OSError as exc:
        metadata["state"] = "copy_only"
        _write_v2_metadata(final / METADATA_NAME, metadata, state_dir)
        raise QuarantinePartialError(
            f"authenticated recovery copy created, but original could not be removed: {exc}",
            entry_id,
        ) from exc

    metadata["state"] = "quarantined"
    metadata["quarantined_at"] = format_utc()
    return _write_v2_metadata(final / METADATA_NAME, metadata, state_dir)


def _validate_entry_id(entry_id: str) -> str:
    try:
        parsed = uuid.UUID(entry_id)
    except ValueError as exc:
        raise QuarantineError("quarantine entry ID must be a UUID") from exc
    normalized = str(parsed)
    if normalized != entry_id.lower():
        raise QuarantineError("quarantine entry ID must use canonical UUID form")
    return normalized


def _read_metadata(entry: Path, state_dir: Path) -> dict[str, Any]:
    path = entry / METADATA_NAME
    try:
        if path.stat().st_size > MAX_METADATA_BYTES:
            raise QuarantineError("quarantine metadata is unexpectedly large")
        value = strict_json_loads(path.read_bytes())
    except FeedError as exc:
        raise QuarantineError(f"invalid quarantine metadata: {exc}") from exc
    except OSError as exc:
        raise QuarantineError(f"cannot read quarantine metadata: {exc}") from exc
    if not isinstance(value, dict):
        raise QuarantineError("quarantine metadata must be an object")
    schema = value.get("schema")
    common = {
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
    if schema == LEGACY_METADATA_SCHEMA:
        required = common
    elif schema == METADATA_SCHEMA:
        required = common | {"zba", "vault", "content_tag", "metadata_mac"}
    else:
        raise QuarantineError("unsupported quarantine metadata schema")
    if set(value) != required or value.get("id") != entry.name:
        raise QuarantineError("quarantine metadata fields or identity are invalid")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not _valid_sha256(digest):
        raise QuarantineError("quarantine metadata digest is invalid")
    if not isinstance(value.get("size"), int) or int(value["size"]) < 0:
        raise QuarantineError("quarantine metadata size is invalid")
    if value.get("state") not in {"copy_ready", "copy_only", "quarantined", "restored"}:
        raise QuarantineError("quarantine state is invalid")
    if not isinstance(value.get("restore_history"), list) or not isinstance(
        value.get("matches"), list
    ):
        raise QuarantineError("quarantine metadata lists are invalid")
    if schema == METADATA_SCHEMA:
        device = load_device_root(state_dir, create=False)
        verify_metadata(device, value)
        VaultEnvelope.from_dict(value["vault"])
        if value["vault"].get("device_key_protection") != device.protection:
            raise QuarantineError("vault device-key protection record is inconsistent")
        _decode_content_tag(value.get("content_tag"))
        validate_quarantine_record(value["zba"], entry_id=entry.name, payload_sha256=digest)
        canonical_json_bytes(_aad_projection(value))
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
            metadata = _read_metadata(entry, state_dir)
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
                    "encrypted": metadata["schema"] == METADATA_SCHEMA,
                }
            )
        except QuarantineError as exc:
            errors.append({"entry": entry.name, "error": str(exc)})
    return records, errors


def _validate_regular_content(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise QuarantineError(f"cannot inspect quarantine content: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
    ):
        raise QuarantineError("quarantine content is not a regular, non-link file")
    return metadata


def _hash_regular_file(path: Path) -> tuple[str, int]:
    _validate_regular_content(path)
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(COPY_CHUNK_BYTES), b""):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise QuarantineError(f"cannot verify quarantine content: {exc}") from exc
    return digest.hexdigest(), size


def _decrypt_content(
    content: Path,
    output: BinaryIO,
    *,
    metadata: dict[str, Any],
    state_dir: Path,
) -> tuple[str, int]:
    content_stat = _validate_regular_content(content)
    if content_stat.st_size != metadata["size"]:
        raise QuarantineError("encrypted quarantine content size is invalid")
    device = load_device_root(state_dir, create=False)
    envelope = VaultEnvelope.from_dict(metadata["vault"])
    aad = canonical_json_bytes(_aad_projection(metadata))
    content_key = unwrap_content_key(
        device, entry_id=str(metadata["id"]), envelope=envelope, aad=aad
    )
    tag = _decode_content_tag(metadata["content_tag"])
    decryptor = Cipher(
        algorithms.AES(content_key), modes.GCM(envelope.content_nonce, tag)
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    digest = hashlib.sha256()
    size = 0
    try:
        with content.open("rb") as source:
            for chunk in iter(lambda: source.read(COPY_CHUNK_BYTES), b""):
                plaintext = decryptor.update(chunk)
                digest.update(plaintext)
                size += len(plaintext)
                output.write(plaintext)
            plaintext = decryptor.finalize()
            digest.update(plaintext)
            size += len(plaintext)
            output.write(plaintext)
    except InvalidTag as exc:
        raise QuarantineError("encrypted quarantine content authentication failed") from exc
    except OSError as exc:
        raise QuarantineError(f"cannot decrypt quarantine content: {exc}") from exc
    finally:
        content_key = b""
    return digest.hexdigest(), size


def _decode_content_tag(value: Any) -> bytes:
    if not isinstance(value, str):
        raise QuarantineError("vault content tag must be base64 text")
    try:
        tag = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise QuarantineError("vault content tag is invalid base64") from exc
    if len(tag) != 16:
        raise QuarantineError("vault content tag length is invalid")
    return tag


def restore_entry(
    entry_id: str, state_dir: Path, destination: Path | None = None
) -> dict[str, Any]:
    normalized = _validate_entry_id(entry_id)
    entry = quarantine_entries_dir(state_dir) / normalized
    metadata = _read_metadata(entry, state_dir)
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
        prefix=".zero-security-restore.", dir=str(target.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            if metadata["schema"] == METADATA_SCHEMA:
                digest, size = _decrypt_content(
                    entry / CONTENT_NAME, output, metadata=metadata, state_dir=state_dir
                )
            else:
                digest, size = _copy_legacy_content(entry / LEGACY_CONTENT_NAME, output)
            output.flush()
            os.fsync(output.fileno())
        if digest != metadata["sha256"] or size != metadata["size"]:
            raise QuarantineError("quarantine content failed its SHA-256 or size check")
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
    history.append({"restored_at": format_utc(), "destination": str(target)})
    metadata["state"] = "restored"
    metadata["restore_history"] = history[-100:]
    if metadata["schema"] == METADATA_SCHEMA:
        _write_v2_metadata(entry / METADATA_NAME, metadata, state_dir)
    else:
        atomic_write_json(entry / METADATA_NAME, metadata, mode=0o600)
    return {
        "id": normalized,
        "state": "restored",
        "destination": str(target),
        "sha256": digest,
        "size": size,
        "recovery_copy_retained": True,
        "encrypted": metadata["schema"] == METADATA_SCHEMA,
    }


def _copy_legacy_content(content: Path, output: BinaryIO) -> tuple[str, int]:
    expected_digest, expected_size = _hash_regular_file(content)
    copied_digest = hashlib.sha256()
    copied_size = 0
    try:
        with content.open("rb") as source:
            for chunk in iter(lambda: source.read(COPY_CHUNK_BYTES), b""):
                copied_digest.update(chunk)
                copied_size += len(chunk)
                output.write(chunk)
    except OSError as exc:
        raise QuarantineError(f"cannot restore legacy quarantine content: {exc}") from exc
    if copied_digest.hexdigest() != expected_digest or copied_size != expected_size:
        raise QuarantineError("legacy restore copy verification failed")
    return expected_digest, expected_size


def _valid_sha256(value: str) -> bool:
    if len(value) != 64 or value != value.lower():
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True
