"""Credential-free, signed, data-only automatic intelligence updates.

The network is an untrusted transport.  Only a feed accepted by ``feed.py``'s
embedded Ed25519 trust root can change scanner data.  This module never accepts
commands, Python, binaries, installer arguments, or executable signatures.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from zsec_shield.errors import FeedError
from zsec_shield.feed import download_feed, load_keyring
from zsec_shield.intelligence import IntelligenceError, validate_catalog
from zsec_shield.paths import (
    application_update_notice_path,
    application_update_state_path,
    application_update_status_path,
    automatic_update_status_path,
    intelligence_document_path,
    intelligence_envelope_path,
    intelligence_last_known_good_path,
    intelligence_state_path,
)
from zsec_shield.util import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    format_utc,
    strict_json_loads,
    update_lock,
    utc_now,
)

DEFAULT_INTELLIGENCE_URL = "https://talktoai.org/zsec/intelligence/v1/feed.json"
DEFAULT_APPLICATION_UPDATE_URL = "https://talktoai.org/zsec/updates/v1/stable.json"
UPDATE_STATUS_SCHEMA = "zsec.shield.automatic-update-status.v1"
APPLICATION_UPDATE_STATUS_SCHEMA = "zsec.shield.application-update-status.v1"
APPLICATION_UPDATE_STATE_SCHEMA = "zsec.shield.application-update-client-state.v1"
CHECK_INTERVAL = timedelta(hours=24)
MAX_JITTER = timedelta(hours=2)
STATUS_LIMIT = 64 * 1024
MAX_INTELLIGENCE_BYTES = 8 * 1024 * 1024
INTELLIGENCE_ENVELOPE_SCHEMA = "zsec.signed-envelope.v1"
INTELLIGENCE_PAYLOAD_SCHEMA = "zsec.intelligence.payload.v1"
INTELLIGENCE_STATE_SCHEMA = "zsec.intelligence.client-state.v1"
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_VALIDITY = timedelta(days=14)
DATA_ONLY_POLICY = {
    "auto_remediation_allowed": False,
    "data_only": True,
    "detection_rules_derived": False,
    "malware_samples_allowed": False,
    "remote_commands_allowed": False,
}


@dataclass(frozen=True, slots=True)
class AutomaticUpdateStatus:
    state: str
    last_checked_at: str | None
    last_success_at: str | None
    next_check_at: str
    feed_sequence: int | None
    feed_expires_at: str | None
    source: str
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": UPDATE_STATUS_SCHEMA,
            "state": self.state,
            "last_checked_at": self.last_checked_at,
            "last_success_at": self.last_success_at,
            "next_check_at": self.next_check_at,
            "feed_sequence": self.feed_sequence,
            "feed_expires_at": self.feed_expires_at,
            "source": self.source,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class ApplicationUpdateStatus:
    state: str
    installed_version: str
    available_version: str | None
    sequence: int | None
    last_checked_at: str | None
    last_success_at: str | None
    next_check_at: str
    source: str
    automatic_install: bool
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": APPLICATION_UPDATE_STATUS_SCHEMA,
            "state": self.state,
            "installed_version": self.installed_version,
            "available_version": self.available_version,
            "sequence": self.sequence,
            "last_checked_at": self.last_checked_at,
            "last_success_at": self.last_success_at,
            "next_check_at": self.next_check_at,
            "source": self.source,
            "automatic_install": self.automatic_install,
            "error": self.error,
        }


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FeedError(f"automatic update status {field} is invalid")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FeedError(f"automatic update status {field} is invalid") from exc
    return result.astimezone(UTC)


def _validate_status(value: Any) -> AutomaticUpdateStatus:
    expected = {
        "schema",
        "state",
        "last_checked_at",
        "last_success_at",
        "next_check_at",
        "feed_sequence",
        "feed_expires_at",
        "source",
        "error",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise FeedError("automatic update status fields are invalid")
    if value["schema"] != UPDATE_STATUS_SCHEMA:
        raise FeedError("automatic update status schema is invalid")
    if value["state"] not in {"never_checked", "current", "updated", "error"}:
        raise FeedError("automatic update status state is invalid")
    source = value["source"]
    if not isinstance(source, str) or not source.startswith("https://") or len(source) > 2048:
        raise FeedError("automatic update status source is invalid")
    _parse_time(value["next_check_at"], "next_check_at")
    for field in ("last_checked_at", "last_success_at", "feed_expires_at"):
        if value[field] is not None:
            _parse_time(value[field], field)
    sequence = value["feed_sequence"]
    if sequence is not None and (
        isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
    ):
        raise FeedError("automatic update status feed_sequence is invalid")
    error = value["error"]
    if error is not None and (not isinstance(error, str) or not 1 <= len(error) <= 500):
        raise FeedError("automatic update status error is invalid")
    return AutomaticUpdateStatus(
        state=value["state"],
        last_checked_at=value["last_checked_at"],
        last_success_at=value["last_success_at"],
        next_check_at=value["next_check_at"],
        feed_sequence=sequence,
        feed_expires_at=value["feed_expires_at"],
        source=source,
        error=error,
    )


def _jitter() -> timedelta:
    # A CSPRNG prevents a fleet installed from one image from creating a daily
    # thundering herd. The signed sequence, not timing, determines acceptance.
    span = int(MAX_JITTER.total_seconds())
    return timedelta(seconds=secrets.randbelow((span * 2) + 1) - span)


def _next_check(now: datetime) -> datetime:
    return now + CHECK_INTERVAL + _jitter()


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) > 256:
        raise FeedError("intelligence signature is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FeedError("intelligence signature is invalid") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise FeedError("intelligence signature is invalid")
    return decoded


def verify_intelligence_envelope(
    raw: bytes,
    keyring_path: Path,
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify the signed envelope and strict, non-executable advisory catalog."""
    if len(raw) > MAX_INTELLIGENCE_BYTES:
        raise FeedError("intelligence envelope exceeds the size limit")
    current = (now or utc_now()).astimezone(UTC)
    value = strict_json_loads(raw)
    expected = {"schema", "algorithm", "key_id", "payload", "signature"}
    if not isinstance(value, dict) or set(value) != expected:
        raise FeedError("intelligence envelope fields are invalid")
    if value["schema"] != INTELLIGENCE_ENVELOPE_SCHEMA or value["algorithm"] != "ed25519":
        raise FeedError("intelligence envelope identity is invalid")
    key_id = value["key_id"]
    if not isinstance(key_id, str):
        raise FeedError("intelligence key ID is invalid")
    keyring = load_keyring(keyring_path, now=current)
    trusted = keyring.get(key_id)
    if trusted is None or trusted.status != "active":
        raise FeedError("intelligence signing key is not active and trusted")
    if trusted.not_before and current < trusted.not_before:
        raise FeedError("intelligence signing key is not valid yet")
    if trusted.not_after and current >= trusted.not_after:
        raise FeedError("intelligence signing key has expired")
    payload = value["payload"]
    if not isinstance(payload, dict):
        raise FeedError("intelligence payload must be an object")
    try:
        Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
            _decode_signature(value["signature"]), canonical_json_bytes(payload) + b"\n"
        )
    except (InvalidSignature, ValueError) as exc:
        raise FeedError("intelligence signature verification failed") from exc
    payload_fields = {
        "schema",
        "sequence",
        "generated_at",
        "expires_at",
        "catalog_sha256",
        "catalog",
        "policy",
    }
    if set(payload) != payload_fields or payload["schema"] != INTELLIGENCE_PAYLOAD_SCHEMA:
        raise FeedError("intelligence payload fields or schema are invalid")
    if payload["policy"] != DATA_ONLY_POLICY:
        raise FeedError("intelligence payload violates the data-only policy")
    sequence = payload["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence < 2**63:
        raise FeedError("intelligence sequence is invalid")
    generated = _parse_time(payload["generated_at"], "generated_at")
    expires = _parse_time(payload["expires_at"], "expires_at")
    if generated > current + MAX_CLOCK_SKEW:
        raise FeedError("intelligence generation time is in the future")
    if expires <= current or expires <= generated or expires - generated > MAX_VALIDITY:
        raise FeedError("intelligence expiry is invalid")
    catalog = payload["catalog"]
    try:
        validate_catalog(catalog)
    except IntelligenceError as exc:
        raise FeedError(f"intelligence catalog is invalid: {exc}") from exc
    digest = hashlib.sha256(canonical_json_bytes(catalog) + b"\n").hexdigest()
    if payload["catalog_sha256"] != digest:
        raise FeedError("intelligence catalog digest does not match the signed payload")
    return value, payload


def _load_intelligence_state(state_dir: Path) -> dict[str, Any] | None:
    path = intelligence_state_path(state_dir)
    if not path.exists():
        return None
    value = strict_json_loads(path.read_bytes())
    expected = {"schema", "max_sequence", "catalog_sha256", "key_id", "installed_at"}
    if not isinstance(value, dict) or set(value) != expected:
        raise FeedError("intelligence rollback state fields are invalid")
    if value["schema"] != INTELLIGENCE_STATE_SCHEMA:
        raise FeedError("intelligence rollback state schema is invalid")
    if (
        isinstance(value["max_sequence"], bool)
        or not isinstance(value["max_sequence"], int)
        or value["max_sequence"] < 1
    ):
        raise FeedError("intelligence rollback sequence is invalid")
    return value


def install_intelligence_envelope(
    raw: bytes,
    state_dir: Path,
    keyring_path: Path,
    *,
    now: datetime | None = None,
) -> tuple[str, dict[str, Any]]:
    """Atomically install a verified catalog while retaining the prior envelope."""
    current = (now or utc_now()).astimezone(UTC)
    envelope, payload = verify_intelligence_envelope(raw, keyring_path, now=current)
    canonical_catalog = canonical_json_bytes(payload["catalog"]) + b"\n"
    normalized_envelope = (
        json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    lock_path = state_dir / "intelligence" / ".update.lock"
    with update_lock(lock_path):
        previous = _load_intelligence_state(state_dir)
        outcome = "installed"
        if previous is not None:
            maximum = previous["max_sequence"]
            if payload["sequence"] < maximum:
                raise FeedError("intelligence rollback sequence was rejected")
            if payload["sequence"] == maximum:
                if payload["catalog_sha256"] != previous["catalog_sha256"]:
                    raise FeedError("intelligence sequence reuse with changed content was rejected")
                outcome = "unchanged"
        active_envelope = intelligence_envelope_path(state_dir)
        if active_envelope.is_file():
            atomic_write_bytes(
                intelligence_last_known_good_path(state_dir),
                active_envelope.read_bytes(),
                mode=0o600,
            )
        # All objects are independently atomic. The state record is the final
        # commit marker, so partially written data is never reported as current.
        atomic_write_bytes(intelligence_document_path(state_dir), canonical_catalog, mode=0o600)
        atomic_write_bytes(active_envelope, normalized_envelope, mode=0o600)
        atomic_write_json(
            intelligence_state_path(state_dir),
            {
                "schema": INTELLIGENCE_STATE_SCHEMA,
                "max_sequence": payload["sequence"],
                "catalog_sha256": payload["catalog_sha256"],
                "key_id": envelope["key_id"],
                "installed_at": format_utc(current),
            },
            mode=0o600,
        )
    return outcome, payload


def load_automatic_update_status(
    state_dir: Path,
    *,
    source: str = DEFAULT_INTELLIGENCE_URL,
    now: datetime | None = None,
) -> AutomaticUpdateStatus:
    current = (now or utc_now()).astimezone(UTC)
    path = automatic_update_status_path(state_dir)
    if not path.exists():
        return AutomaticUpdateStatus(
            "never_checked", None, None, format_utc(current), None, None, source, None
        )
    try:
        if not path.is_file() or path.stat().st_size > STATUS_LIMIT:
            raise FeedError("automatic update status is not a bounded regular file")
        status = _validate_status(strict_json_loads(path.read_bytes()))
    except (OSError, FeedError) as exc:
        # Corrupt schedule evidence must cause a check now, never suppress one.
        return AutomaticUpdateStatus(
            "error", None, None, format_utc(current), None, None, source, str(exc)[:500]
        )
    if status.source != source:
        # A release-owned endpoint change is checked immediately. Remote content
        # can never rewrite this value.
        return AutomaticUpdateStatus(
            "never_checked",
            status.last_checked_at,
            status.last_success_at,
            format_utc(current),
            status.feed_sequence,
            status.feed_expires_at,
            source,
            None,
        )
    return status


def automatic_update_due(status: AutomaticUpdateStatus, now: datetime | None = None) -> bool:
    current = (now or utc_now()).astimezone(UTC)
    return current >= _parse_time(status.next_check_at, "next_check_at")


def run_automatic_update(
    state_dir: Path,
    keyring_path: Path,
    *,
    source: str = DEFAULT_INTELLIGENCE_URL,
    timeout: float = 15.0,
    force: bool = False,
    now: datetime | None = None,
) -> AutomaticUpdateStatus:
    current = (now or utc_now()).astimezone(UTC)
    previous = load_automatic_update_status(state_dir, source=source, now=current)
    if not force and not automatic_update_due(previous, current):
        return previous
    checked_at = format_utc(current)
    next_check_at = format_utc(_next_check(current))
    try:
        raw = download_feed(source, timeout=timeout)
        outcome, payload = install_intelligence_envelope(
            raw, state_dir, keyring_path, now=current
        )
        status = AutomaticUpdateStatus(
            "updated" if outcome == "installed" else "current",
            checked_at,
            checked_at,
            next_check_at,
            payload["sequence"],
            payload["expires_at"],
            source,
            None,
        )
    except (FeedError, OSError) as exc:
        # Preserve last-known-good feed and prior success evidence. A transport or
        # verification failure never empties, downgrades, or edits active rules.
        status = AutomaticUpdateStatus(
            "error",
            checked_at,
            previous.last_success_at,
            next_check_at,
            previous.feed_sequence,
            previous.feed_expires_at,
            source,
            f"{type(exc).__name__}: {exc}".replace("\r", " ").replace("\n", " ")[:500],
        )
    atomic_write_json(automatic_update_status_path(state_dir), status.to_dict(), mode=0o600)
    return status


def verify_application_update_envelope(
    raw: bytes,
    keyring_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify application metadata while making execution structurally impossible."""
    if len(raw) > STATUS_LIMIT:
        raise FeedError("application update envelope is too large")
    current = (now or utc_now()).astimezone(UTC)
    envelope = strict_json_loads(raw)
    expected = {"schema", "algorithm", "key_id", "payload", "signature"}
    if not isinstance(envelope, dict) or set(envelope) != expected:
        raise FeedError("application update envelope fields are invalid")
    if envelope["schema"] != "zsec.signed-envelope.v1" or envelope["algorithm"] != "ed25519":
        raise FeedError("application update envelope identity is invalid")
    keyring = load_keyring(keyring_path, now=current)
    trusted = keyring.get(envelope["key_id"])
    if trusted is None or trusted.status != "active":
        raise FeedError("application update signing key is not active and trusted")
    if trusted.not_before and current < trusted.not_before:
        raise FeedError("application update signing key is not valid yet")
    if trusted.not_after and current >= trusted.not_after:
        raise FeedError("application update signing key has expired")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise FeedError("application update payload is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(
            _decode_signature(envelope["signature"]), canonical_json_bytes(payload) + b"\n"
        )
    except (InvalidSignature, ValueError) as exc:
        raise FeedError("application update signature verification failed") from exc
    payload_fields = {
        "schema",
        "sequence",
        "generated_at",
        "expires_at",
        "channel",
        "notification_only",
        "auto_install_allowed",
        "release",
    }
    if set(payload) != payload_fields or payload["schema"] != "zsec.application-update.payload.v1":
        raise FeedError("application update payload fields or schema are invalid")
    if (
        payload["channel"] != "stable"
        or payload["notification_only"] is not True
        or payload["auto_install_allowed"] is not False
    ):
        raise FeedError("application update payload violates notification-only policy")
    generated = _parse_time(payload["generated_at"], "generated_at")
    expires = _parse_time(payload["expires_at"], "expires_at")
    if generated > current + MAX_CLOCK_SKEW or expires <= current:
        raise FeedError("application update validity window is invalid")
    if expires <= generated or expires - generated > MAX_VALIDITY:
        raise FeedError("application update validity exceeds policy")
    sequence = payload["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise FeedError("application update sequence is invalid")
    release = payload["release"]
    expected_release = {
        "schema",
        "version",
        "channel",
        "minimum_supported_version",
        "release_notes_url",
        "source_revision",
        "notification_only",
        "auto_install_allowed",
        "artifacts",
    }
    if not isinstance(release, dict) or set(release) != expected_release:
        raise FeedError("application release fields are invalid")
    if (
        release["schema"] != "zsec.application-release-source.v1"
        or release["notification_only"] is not True
        or release["auto_install_allowed"] is not False
    ):
        raise FeedError("application release is not notification-only")
    if not isinstance(release["version"], str) or not 1 <= len(release["version"]) <= 32:
        raise FeedError("application release version is invalid")
    _parse_release_version(release["version"])
    if not isinstance(release["artifacts"], list) or not release["artifacts"]:
        raise FeedError("application release artifacts are invalid")
    for artifact in release["artifacts"]:
        if not isinstance(artifact, dict):
            raise FeedError("application release artifact is invalid")
        if set(artifact) != {
            "architecture",
            "authenticode",
            "filename",
            "operating_system",
            "sha256",
            "size",
            "url",
        }:
            raise FeedError("application release artifact fields are invalid")
        digest = artifact["sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            raise FeedError("application release artifact digest is invalid")
        try:
            bytes.fromhex(digest)
        except ValueError as exc:
            raise FeedError("application release artifact digest is invalid") from exc
        if not isinstance(artifact["url"], str) or not artifact["url"].startswith("https://"):
            raise FeedError("application release artifact URL is invalid")
    return {
        "schema": "zsec.shield.application-update-notification.v1",
        "sequence": sequence,
        "version": release["version"],
        "release_notes_url": release["release_notes_url"],
        "artifacts": release["artifacts"],
        "expires_at": payload["expires_at"],
        "automatic_install": False,
        "policy": "notification only; no content is downloaded or executed",
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _parse_release_version(value: Any) -> tuple[int, ...]:
    """Return a bounded numeric release tuple suitable for update ordering."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value) is None:
        raise FeedError("application release version is invalid")
    components = tuple(int(component) for component in value.split("."))
    if any(component > 65535 for component in components):
        raise FeedError("application release version is invalid")
    return components + (0,) * (4 - len(components))


def _validate_application_update_status(value: Any) -> ApplicationUpdateStatus:
    expected = {
        "schema", "state", "installed_version", "available_version", "sequence",
        "last_checked_at", "last_success_at", "next_check_at", "source",
        "automatic_install", "error",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise FeedError("application update status fields are invalid")
    if value["schema"] != APPLICATION_UPDATE_STATUS_SCHEMA:
        raise FeedError("application update status schema is invalid")
    if value["state"] not in {"never_checked", "current", "available", "error"}:
        raise FeedError("application update status state is invalid")
    _parse_release_version(value["installed_version"])
    if value["available_version"] is not None:
        _parse_release_version(value["available_version"])
    sequence = value["sequence"]
    if sequence is not None and (
        isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
    ):
        raise FeedError("application update status sequence is invalid")
    for field in ("last_checked_at", "last_success_at"):
        if value[field] is not None:
            _parse_time(value[field], field)
    _parse_time(value["next_check_at"], "next_check_at")
    source = value["source"]
    if not isinstance(source, str) or not source.startswith("https://") or len(source) > 2048:
        raise FeedError("application update status source is invalid")
    if value["automatic_install"] is not False:
        raise FeedError("application update status automatic-install policy is invalid")
    error = value["error"]
    if error is not None and (not isinstance(error, str) or not 1 <= len(error) <= 500):
        raise FeedError("application update status error is invalid")
    return ApplicationUpdateStatus(
        value["state"], value["installed_version"], value["available_version"],
        sequence, value["last_checked_at"], value["last_success_at"],
        value["next_check_at"], source, False, error,
    )


def load_application_update_status(
    state_dir: Path,
    installed_version: str,
    *,
    source: str = DEFAULT_APPLICATION_UPDATE_URL,
    now: datetime | None = None,
) -> ApplicationUpdateStatus:
    current = (now or utc_now()).astimezone(UTC)
    _parse_release_version(installed_version)
    path = application_update_status_path(state_dir)
    fallback = ApplicationUpdateStatus(
        "never_checked", installed_version, None, None, None, None,
        format_utc(current), source, False, None,
    )
    if not path.exists():
        return fallback
    try:
        if not path.is_file() or path.stat().st_size > STATUS_LIMIT:
            raise FeedError("application update status is not a bounded regular file")
        status = _validate_application_update_status(strict_json_loads(path.read_bytes()))
    except (OSError, FeedError) as exc:
        return ApplicationUpdateStatus(
            "error", installed_version, None, None, None, None,
            format_utc(current), source, False, str(exc)[:500],
        )
    if status.source != source or status.installed_version != installed_version:
        return ApplicationUpdateStatus(
            "never_checked", installed_version, status.available_version, status.sequence,
            status.last_checked_at, status.last_success_at, format_utc(current),
            source, False, None,
        )
    return status


def _load_application_update_state(state_dir: Path) -> dict[str, Any] | None:
    path = application_update_state_path(state_dir)
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > STATUS_LIMIT:
        raise FeedError("application update rollback state is not a bounded regular file")
    value = strict_json_loads(path.read_bytes())
    expected = {"schema", "max_sequence", "manifest_sha256", "release_version", "checked_at"}
    if not isinstance(value, dict) or set(value) != expected:
        raise FeedError("application update rollback state fields are invalid")
    if value["schema"] != APPLICATION_UPDATE_STATE_SCHEMA:
        raise FeedError("application update rollback state schema is invalid")
    if (
        isinstance(value["max_sequence"], bool)
        or not isinstance(value["max_sequence"], int)
        or value["max_sequence"] < 1
    ):
        raise FeedError("application update rollback sequence is invalid")
    digest = value["manifest_sha256"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise FeedError("application update rollback digest is invalid")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise FeedError("application update rollback digest is invalid") from exc
    _parse_release_version(value["release_version"])
    _parse_time(value["checked_at"], "checked_at")
    return value


def run_automatic_application_update_check(
    state_dir: Path,
    keyring_path: Path,
    installed_version: str,
    *,
    source: str = DEFAULT_APPLICATION_UPDATE_URL,
    timeout: float = 15.0,
    force: bool = False,
    now: datetime | None = None,
) -> ApplicationUpdateStatus:
    """Persist a signed update notice; never download or execute an artifact."""
    current = (now or utc_now()).astimezone(UTC)
    previous = load_application_update_status(
        state_dir, installed_version, source=source, now=current
    )
    if not force and current < _parse_time(previous.next_check_at, "next_check_at"):
        return previous
    checked_at = format_utc(current)
    next_check_at = format_utc(_next_check(current))
    try:
        raw = download_feed(source, timeout=timeout)
        notice = verify_application_update_envelope(raw, keyring_path, now=current)
        lock_path = state_dir / "application-update" / ".update.lock"
        with update_lock(lock_path):
            state = _load_application_update_state(state_dir)
            if state is not None:
                if notice["sequence"] < state["max_sequence"]:
                    raise FeedError("application update rollback sequence was rejected")
                if (
                    notice["sequence"] == state["max_sequence"]
                    and notice["manifest_sha256"] != state["manifest_sha256"]
                ):
                    raise FeedError(
                        "application update sequence reuse with changed content was rejected"
                    )
            atomic_write_json(application_update_notice_path(state_dir), notice, mode=0o600)
            atomic_write_json(
                application_update_state_path(state_dir),
                {
                    "schema": APPLICATION_UPDATE_STATE_SCHEMA,
                    "max_sequence": notice["sequence"],
                    "manifest_sha256": notice["manifest_sha256"],
                    "release_version": notice["version"],
                    "checked_at": checked_at,
                },
                mode=0o600,
            )
        available = _parse_release_version(notice["version"]) > _parse_release_version(
            installed_version
        )
        status = ApplicationUpdateStatus(
            "available" if available else "current", installed_version,
            notice["version"] if available else None, notice["sequence"], checked_at,
            checked_at, next_check_at, source, False, None,
        )
    except (FeedError, OSError) as exc:
        status = ApplicationUpdateStatus(
            "error", installed_version, previous.available_version, previous.sequence,
            checked_at, previous.last_success_at, next_check_at, source, False,
            f"{type(exc).__name__}: {exc}".replace("\r", " ").replace("\n", " ")[:500],
        )
    atomic_write_json(application_update_status_path(state_dir), status.to_dict(), mode=0o600)
    return status
