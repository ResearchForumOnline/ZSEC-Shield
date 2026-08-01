"""Strict Ed25519 verification and fail-closed installation of data-only rules."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from zsec_shield.errors import FeedError
from zsec_shield.models import Rule, RuleKind, Severity
from zsec_shield.paths import (
    feed_document_path,
    feed_lock_path,
    feed_state_path,
)
from zsec_shield.util import (
    atomic_write_json,
    canonical_json_bytes,
    format_utc,
    strict_json_loads,
    update_lock,
    utc_now,
)

ENVELOPE_SCHEMA = "zsec.shield.feed.v1"
PAYLOAD_SCHEMA = "zsec.shield.rules.v1"
KEYRING_SCHEMA = "zsec.shield.keyring.v1"
STATE_SCHEMA = "zsec.shield.feed-state.v1"
MAX_FEED_BYTES = 2 * 1024 * 1024
MAX_RULES = 2048
MAX_LITERAL_BYTES = 4096
MAX_FEED_LIFETIME = timedelta(days=90)
MAX_CLOCK_SKEW = timedelta(minutes=5)
RULE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
SEVERITIES: set[str] = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True, slots=True)
class TrustedKey:
    key_id: str
    public_key: bytes
    status: str
    not_before: datetime | None
    not_after: datetime | None


@dataclass(frozen=True, slots=True)
class VerifiedFeed:
    document: dict[str, Any]
    sequence: int
    generated_at: datetime
    expires_at: datetime
    key_id: str
    payload_sha256: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class FeedStatus:
    state: str
    path: str
    keyring_path: str
    sequence: int | None = None
    key_id: str | None = None
    rules_count: int = 0
    generated_at: str | None = None
    expires_at: str | None = None
    payload_sha256: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "path": self.path,
            "keyring_path": self.keyring_path,
            "sequence": self.sequence,
            "key_id": self.key_id,
            "rules_count": self.rules_count,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "payload_sha256": self.payload_sha256,
            "error": self.error,
        }


def _expect_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    present = set(value)
    if present != expected:
        missing = sorted(expected - present)
        unexpected = sorted(present - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unexpected:
            details.append(f"unexpected={','.join(unexpected)}")
        raise FeedError(f"invalid {context} fields ({'; '.join(details)})")


def _bounded_string(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise FeedError(f"{field} must be a string of {minimum}..{maximum} characters")
    if any(ord(character) < 32 and character not in "\t" for character in value):
        raise FeedError(f"{field} contains disallowed control characters")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    text = _bounded_string(value, field, 20, 35)
    if not text.endswith("Z"):
        raise FeedError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise FeedError(f"{field} is not a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise FeedError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def _decode_base64(value: Any, field: str, expected_length: int | None = None) -> bytes:
    text = _bounded_string(value, field, 4, 8192)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FeedError(f"{field} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != text:
        raise FeedError(f"{field} must use canonical padded base64")
    if expected_length is not None and len(decoded) != expected_length:
        raise FeedError(f"{field} must decode to {expected_length} bytes")
    return decoded


def load_keyring(path: Path, now: datetime | None = None) -> dict[str, TrustedKey]:
    current = (now or utc_now()).astimezone(UTC)
    try:
        if path.stat().st_size > 256 * 1024:
            raise FeedError("keyring is larger than 256 KiB")
        raw = path.read_bytes()
    except OSError as exc:
        raise FeedError(f"cannot read keyring: {path}: {exc}") from exc
    root = strict_json_loads(raw)
    if not isinstance(root, dict):
        raise FeedError("keyring root must be an object")
    _expect_exact_keys(root, {"schema", "keys"}, "keyring")
    if root["schema"] != KEYRING_SCHEMA:
        raise FeedError(f"unsupported keyring schema: {root['schema']!r}")
    records = root["keys"]
    if not isinstance(records, list) or len(records) > 64:
        raise FeedError("keyring keys must be an array with at most 64 entries")

    result: dict[str, TrustedKey] = {}
    allowed = {"key_id", "algorithm", "public_key", "status", "not_before", "not_after"}
    required = {"key_id", "algorithm", "public_key", "status"}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise FeedError(f"keyring key {index} must be an object")
        present = set(record)
        if not required.issubset(present) or not present.issubset(allowed):
            raise FeedError(f"keyring key {index} has invalid fields")
        key_id = _bounded_string(record["key_id"], f"keys[{index}].key_id", 3, 128)
        if not RULE_ID_PATTERN.fullmatch(key_id):
            raise FeedError(f"keys[{index}].key_id has an invalid format")
        if key_id in result:
            raise FeedError(f"duplicate key_id rejected: {key_id}")
        if record["algorithm"] != "ed25519":
            raise FeedError(f"key {key_id} uses an unsupported algorithm")
        status_value = record["status"]
        if status_value not in {"active", "revoked"}:
            raise FeedError(f"key {key_id} has an invalid status")
        public_key = _decode_base64(record["public_key"], f"key {key_id} public_key", 32)
        not_before = (
            _timestamp(record["not_before"], "not_before") if "not_before" in record else None
        )
        not_after = _timestamp(record["not_after"], "not_after") if "not_after" in record else None
        if not_before and not_after and not_after <= not_before:
            raise FeedError(f"key {key_id} validity window is inverted")
        result[key_id] = TrustedKey(key_id, public_key, status_value, not_before, not_after)

    # Time checks are performed again during verification; this pass makes malformed
    # or currently unusable trust stores visible in status without accepting a feed.
    for record in result.values():
        if (
            record.not_before
            and record.not_after
            and not record.not_before <= current < record.not_after
        ):
            continue
    return result


def _validate_rule(record: Any, index: int) -> Rule:
    if not isinstance(record, dict):
        raise FeedError(f"rules[{index}] must be an object")
    _expect_exact_keys(
        record,
        {"id", "name", "kind", "severity", "description", "source", "value"},
        f"rules[{index}]",
    )
    rule_id = _bounded_string(record["id"], f"rules[{index}].id", 3, 128)
    if not RULE_ID_PATTERN.fullmatch(rule_id) or rule_id.startswith("builtin:"):
        raise FeedError(f"rules[{index}].id has an invalid or reserved format")
    name = _bounded_string(record["name"], f"rules[{index}].name", 1, 160)
    description = _bounded_string(record["description"], f"rules[{index}].description", 1, 500)
    source = _bounded_string(record["source"], f"rules[{index}].source", 1, 300)
    kind_value = record["kind"]
    if kind_value not in {"sha256", "literal"}:
        raise FeedError(f"rules[{index}].kind must be sha256 or literal")
    kind: RuleKind = kind_value
    severity_value = record["severity"]
    if severity_value not in SEVERITIES:
        raise FeedError(f"rules[{index}].severity is invalid")
    severity: Severity = severity_value
    value = record["value"]
    if kind == "sha256":
        digest = _bounded_string(value, f"rules[{index}].value", 64, 64).lower()
        if not SHA256_PATTERN.fullmatch(digest):
            raise FeedError(f"rules[{index}].value must be a SHA-256 hex digest")
        return Rule(rule_id, name, kind, severity, description, source, digest=digest)
    literal = _decode_base64(value, f"rules[{index}].value")
    if not literal or len(literal) > MAX_LITERAL_BYTES:
        raise FeedError(f"rules[{index}].value must decode to 1..{MAX_LITERAL_BYTES} bytes")
    return Rule(rule_id, name, kind, severity, description, source, literal=literal)


def verify_feed_document(
    raw: bytes,
    keyring: dict[str, TrustedKey],
    now: datetime | None = None,
) -> VerifiedFeed:
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError(f"feed is larger than {MAX_FEED_BYTES} bytes")
    current = (now or utc_now()).astimezone(UTC)
    root = strict_json_loads(raw)
    if not isinstance(root, dict):
        raise FeedError("feed root must be an object")
    _expect_exact_keys(
        root,
        {"schema", "algorithm", "key_id", "payload", "signature"},
        "feed envelope",
    )
    if root["schema"] != ENVELOPE_SCHEMA or root["algorithm"] != "ed25519":
        raise FeedError("unsupported feed schema or signature algorithm")
    key_id = _bounded_string(root["key_id"], "key_id", 3, 128)
    trusted = keyring.get(key_id)
    if trusted is None:
        raise FeedError(f"feed key is not trusted: {key_id}")
    if trusted.status != "active":
        raise FeedError(f"feed key is revoked: {key_id}")
    if trusted.not_before and current < trusted.not_before:
        raise FeedError(f"feed key is not valid yet: {key_id}")
    if trusted.not_after and current >= trusted.not_after:
        raise FeedError(f"feed key has expired: {key_id}")
    payload = root["payload"]
    if not isinstance(payload, dict):
        raise FeedError("feed payload must be an object")
    canonical = canonical_json_bytes(payload)
    signature = _decode_base64(root["signature"], "signature", 64)
    try:
        Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(signature, canonical)
    except (InvalidSignature, ValueError) as exc:
        raise FeedError("feed signature verification failed") from exc

    _expect_exact_keys(
        payload,
        {"schema", "sequence", "generated_at", "expires_at", "rules"},
        "signed payload",
    )
    if payload["schema"] != PAYLOAD_SCHEMA:
        raise FeedError(f"unsupported signed payload schema: {payload['schema']!r}")
    sequence = payload["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence < 2**63:
        raise FeedError("sequence must be an integer between 1 and 2^63-1")
    generated_at = _timestamp(payload["generated_at"], "generated_at")
    expires_at = _timestamp(payload["expires_at"], "expires_at")
    if generated_at > current + MAX_CLOCK_SKEW:
        raise FeedError("feed generated_at is too far in the future")
    if expires_at <= current:
        raise FeedError("feed has expired")
    if expires_at <= generated_at:
        raise FeedError("feed expiry must be later than generation time")
    if expires_at - generated_at > MAX_FEED_LIFETIME:
        raise FeedError("feed validity window exceeds 90 days")
    records = payload["rules"]
    if not isinstance(records, list) or len(records) > MAX_RULES:
        raise FeedError(f"rules must be an array with at most {MAX_RULES} entries")
    rules = tuple(_validate_rule(record, index) for index, record in enumerate(records))
    identifiers = [rule.rule_id for rule in rules]
    if len(set(identifiers)) != len(identifiers):
        raise FeedError("duplicate rule IDs are not allowed")
    return VerifiedFeed(
        document=root,
        sequence=sequence,
        generated_at=generated_at,
        expires_at=expires_at,
        key_id=key_id,
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
        rules=rules,
    )


def _read_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        if path.stat().st_size > 64 * 1024:
            raise FeedError("feed state is unexpectedly large")
        value = strict_json_loads(path.read_bytes())
    except OSError as exc:
        raise FeedError(f"cannot read feed state: {exc}") from exc
    if not isinstance(value, dict):
        raise FeedError("feed state must be an object")
    _expect_exact_keys(
        value,
        {"schema", "max_sequence", "current_payload_sha256", "key_id", "updated_at"},
        "feed state",
    )
    if value["schema"] != STATE_SCHEMA:
        raise FeedError("unsupported feed state schema")
    sequence = value["max_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise FeedError("feed state sequence is invalid")
    digest = value["current_payload_sha256"]
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        raise FeedError("feed state digest is invalid")
    _bounded_string(value["key_id"], "feed state key_id", 3, 128)
    _timestamp(value["updated_at"], "feed state updated_at")
    return value


def inspect_feed(
    state_dir: Path,
    keyring_path: Path,
    now: datetime | None = None,
) -> tuple[FeedStatus, tuple[Rule, ...]]:
    document_path = feed_document_path(state_dir)
    state_path = feed_state_path(state_dir)
    if not document_path.exists() and not state_path.exists():
        return (
            FeedStatus("absent", str(document_path), str(keyring_path)),
            (),
        )
    try:
        if not document_path.is_file() or not state_path.is_file():
            raise FeedError("feed document and rollback state must both exist")
        if document_path.stat().st_size > MAX_FEED_BYTES:
            raise FeedError("installed feed exceeds the size limit")
        keyring = load_keyring(keyring_path, now=now)
        verified = verify_feed_document(document_path.read_bytes(), keyring, now=now)
        state = _read_state(state_path)
        if state is None:
            raise FeedError("feed rollback state is missing")
        if state["max_sequence"] != verified.sequence:
            raise FeedError("feed sequence does not match rollback state")
        if state["current_payload_sha256"] != verified.payload_sha256:
            raise FeedError("feed payload does not match rollback state")
        status = FeedStatus(
            "valid",
            str(document_path),
            str(keyring_path),
            sequence=verified.sequence,
            key_id=verified.key_id,
            rules_count=len(verified.rules),
            generated_at=format_utc(verified.generated_at),
            expires_at=format_utc(verified.expires_at),
            payload_sha256=verified.payload_sha256,
        )
        return status, verified.rules
    except (FeedError, OSError) as exc:
        return (
            FeedStatus(
                "invalid",
                str(document_path),
                str(keyring_path),
                error=str(exc),
            ),
            (),
        )


class _HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, maximum: int = 3) -> None:
        super().__init__()
        self.maximum = maximum
        self.count = 0

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        self.count += 1
        if self.count > self.maximum:
            raise FeedError("feed download exceeded the redirect limit")
        absolute = urllib.parse.urljoin(request.full_url, new_url)
        parsed = urllib.parse.urlsplit(absolute)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise FeedError("feed redirects must remain credential-free HTTPS URLs")
        return super().redirect_request(request, file_pointer, code, message, headers, absolute)


def download_feed(url: str, timeout: float = 15.0) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise FeedError("remote feeds require a credential-free HTTPS URL without a fragment")
    redirect_handler = _HTTPSOnlyRedirectHandler()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        redirect_handler,
    )
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "ZSEC-Shield/0.1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https":
                raise FeedError("feed download did not finish on HTTPS")
            length_header = response.headers.get("Content-Length")
            if length_header:
                try:
                    if int(length_header) > MAX_FEED_BYTES:
                        raise FeedError("remote feed exceeds the size limit")
                except ValueError as exc:
                    raise FeedError("remote feed has an invalid Content-Length") from exc
            downloaded = response.read(MAX_FEED_BYTES + 1)
            if not isinstance(downloaded, bytes):
                raise FeedError("feed download returned non-byte content")
            raw = downloaded
    except FeedError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FeedError(f"feed download failed: {exc}") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError("remote feed exceeds the size limit")
    return raw


def read_local_feed(path: Path) -> bytes:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise FeedError("local feed must be a regular, non-symlink file")
        if before.st_size > MAX_FEED_BYTES:
            raise FeedError("local feed exceeds the size limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise FeedError("local feed changed type while opening")
            raw = b""
            while len(raw) <= MAX_FEED_BYTES:
                chunk = os.read(descriptor, min(65536, MAX_FEED_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(descriptor)
    except FeedError:
        raise
    except OSError as exc:
        raise FeedError(f"cannot read local feed: {path}: {exc}") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError("local feed exceeds the size limit")
    return raw


def install_feed(
    raw: bytes,
    state_dir: Path,
    keyring_path: Path,
    now: datetime | None = None,
) -> tuple[str, VerifiedFeed]:
    current = (now or utc_now()).astimezone(UTC)
    keyring = load_keyring(keyring_path, now=current)
    verified = verify_feed_document(raw, keyring, now=current)
    document_path = feed_document_path(state_dir)
    state_path = feed_state_path(state_dir)
    with update_lock(feed_lock_path(state_dir)):
        previous = _read_state(state_path)
        outcome = "installed"
        if previous is not None:
            maximum = previous["max_sequence"]
            if verified.sequence < maximum:
                raise FeedError(
                    f"feed rollback rejected: sequence {verified.sequence} is below {maximum}"
                )
            if verified.sequence == maximum:
                if verified.payload_sha256 != previous["current_payload_sha256"]:
                    raise FeedError(
                        "feed sequence reuse with different signed content was rejected"
                    )
                outcome = "unchanged"
        normalized = (
            json.dumps(
                verified.document,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        # Two atomic files cannot be committed as one filesystem transaction. Writing
        # either half alone leaves inspect_feed in an explicit invalid state, never a
        # silently accepted older or partially installed feed.
        from zsec_shield.util import atomic_write_bytes

        atomic_write_bytes(document_path, normalized, mode=0o600)
        atomic_write_json(
            state_path,
            {
                "schema": STATE_SCHEMA,
                "max_sequence": verified.sequence,
                "current_payload_sha256": verified.payload_sha256,
                "key_id": verified.key_id,
                "updated_at": format_utc(current),
            },
            mode=0o600,
        )
    return outcome, verified
