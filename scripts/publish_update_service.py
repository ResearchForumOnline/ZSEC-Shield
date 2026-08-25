"""Build and verify ZSEC's signed, static, data-only update service."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from zsec_shield.errors import FeedError
from zsec_shield.feed import ENVELOPE_SCHEMA as RULE_ENVELOPE_SCHEMA
from zsec_shield.feed import PAYLOAD_SCHEMA as RULE_PAYLOAD_SCHEMA
from zsec_shield.feed import TrustedKey, verify_feed_document
from zsec_shield.util import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "intelligence" / "desktop-advisories.json"
DEFAULT_RELEASE = ROOT / "updates" / "application-release.json"
DEFAULT_RULES = ROOT / "rules" / "scanner-rules.json"
DEFAULT_OUTPUT = ROOT / "web" / "zsec"
KEY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ENVELOPE_FIELDS = {"algorithm", "key_id", "payload", "schema", "signature"}
SAFETY_POLICY = {
    "auto_remediation_allowed": False,
    "data_only": True,
    "detection_rules_derived": False,
    "malware_samples_allowed": False,
    "remote_commands_allowed": False,
}
RULE_SOURCE_POLICY = {
    "advisory_conversion_allowed": False,
    "data_only": True,
    "malware_samples_allowed": False,
    "purpose": "eicar-wiring-test-only",
    "remote_commands_allowed": False,
}


class PublishError(ValueError):
    """A fail-closed publication or verification error."""


def _strict_json(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise PublishError(f"non-finite JSON number rejected: {value}")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise PublishError(f"duplicate JSON key rejected: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublishError(f"invalid JSON: {exc}") from exc


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PublishError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PublishError(f"{field} is invalid") from exc
    if parsed.utcoffset() != datetime.min.replace(tzinfo=UTC).utcoffset():
        raise PublishError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _decode_private_key(text: str) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PublishError("private key must be canonical base64") from exc
    if base64.b64encode(raw).decode() != text or len(raw) != 32:
        raise PublishError("private key must be canonical base64 for exactly 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_private_key(path: Path | None) -> Ed25519PrivateKey:
    if path is not None:
        try:
            text = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise PublishError(f"cannot read private-key file: {exc}") from exc
    else:
        text = os.environ.get("ZSEC_UPDATE_SIGNING_KEY_B64", "").strip()
    if not text:
        raise PublishError(
            "set ZSEC_UPDATE_SIGNING_KEY_B64 or provide --private-key-file; "
            "never store the private key in the repository"
        )
    return _decode_private_key(text)


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def _validate_common(
    sequence: int,
    generated_at: str,
    expires_at: str,
    key_id: str,
    *,
    now: datetime,
) -> None:
    if sequence < 1:
        raise PublishError("sequence must be at least 1")
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise PublishError("key-id has an invalid format")
    generated = _timestamp(generated_at, "generated-at")
    expires = _timestamp(expires_at, "expires-at")
    if expires <= generated:
        raise PublishError("expires-at must be later than generated-at")
    if (expires - generated).total_seconds() > 14 * 24 * 60 * 60:
        raise PublishError("publication validity cannot exceed 14 days")
    if generated > now + timedelta(minutes=5):
        raise PublishError("generated-at cannot be more than five minutes in the future")
    if expires <= now:
        raise PublishError("expires-at must be later than the verification time")


def _validate_catalog(catalog: Any) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise PublishError("catalog root must be an object")
    expected = {"advisories", "generated_at", "policy", "schema", "sources"}
    if set(catalog) != expected or catalog.get("schema") != "zsec.desktop-intelligence.v1":
        raise PublishError("catalog has an unsupported shape or schema")
    if catalog.get("policy") != SAFETY_POLICY:
        raise PublishError("catalog safety policy is not the required data-only policy")
    advisories = catalog.get("advisories")
    sources = catalog.get("sources")
    if not isinstance(advisories, list) or not 1 <= len(advisories) <= 4096:
        raise PublishError("catalog must contain 1..4096 advisories")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 4:
        raise PublishError("catalog must contain 1..4 sources")
    ids = [record.get("id") for record in advisories if isinstance(record, dict)]
    if len(ids) != len(advisories) or any(not isinstance(value, str) for value in ids):
        raise PublishError("every advisory must have a string id")
    if len(ids) != len(set(ids)):
        raise PublishError("catalog contains duplicate advisory ids")
    return catalog


def _validate_release(release: Any) -> dict[str, Any]:
    if not isinstance(release, dict):
        raise PublishError("application release root must be an object")
    expected = {
        "artifacts", "auto_install_allowed", "channel", "minimum_supported_version",
        "notification_only", "release_notes_url", "schema", "source_revision", "version",
    }
    if set(release) != expected or release.get("schema") != "zsec.application-release-source.v1":
        raise PublishError("application release has an unsupported shape or schema")
    if (
        release.get("notification_only") is not True
        or release.get("auto_install_allowed") is not False
    ):
        raise PublishError("unsigned application releases must be notification-only")
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise PublishError("application release must contain artifacts")
    names: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise PublishError("artifact must be an object")
        required = {
            "architecture",
            "authenticode",
            "filename",
            "operating_system",
            "sha256",
            "size",
            "url",
        }
        if set(record) != required:
            raise PublishError("artifact has invalid fields")
        if record["filename"] in names:
            raise PublishError("duplicate artifact filename")
        names.add(record["filename"])
        if not isinstance(record["sha256"], str) or not SHA256_PATTERN.fullmatch(record["sha256"]):
            raise PublishError("artifact sha256 is invalid")
        if not isinstance(record["size"], int) or record["size"] < 1:
            raise PublishError("artifact size is invalid")
        if not str(record["url"]).startswith("https://"):
            raise PublishError("artifact URL must use HTTPS")
        if record["operating_system"] == "windows" and record["authenticode"] != "unsigned":
            raise PublishError("current Windows release truthfully remains unsigned")
    return release


def _eicar_rule_records() -> tuple[dict[str, Any], ...]:
    eicar = b"".join(
        (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EIC",
            b"AR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
    )
    return (
        {
            "description": (
                "Harmless standardized antivirus wiring test; not malware and not an "
                "efficacy claim."
            ),
            "id": "feed:eicar-test-file",
            "kind": "literal",
            "name": "EICAR antivirus wiring test",
            "severity": "info",
            "source": "https://www.eicar.org/download-anti-malware-testfile/",
            "value": base64.b64encode(eicar).decode("ascii"),
        },
        {
            "description": "Exact SHA-256 of the canonical harmless EICAR test file; not malware.",
            "id": "feed:eicar-test-file-sha256",
            "kind": "sha256",
            "name": "EICAR antivirus wiring test SHA-256",
            "severity": "info",
            "source": "https://www.eicar.org/download-anti-malware-testfile/",
            "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        },
    )


def _validate_rule_source(source: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(source, dict):
        raise PublishError("scanner rule source root must be an object")
    if set(source) != {"policy", "rules", "schema"}:
        raise PublishError("scanner rule source has invalid fields")
    if source.get("schema") != "zsec.scanner-rule-source.v1":
        raise PublishError("scanner rule source schema is invalid")
    if source.get("policy") != RULE_SOURCE_POLICY:
        raise PublishError("scanner rule source must remain EICAR wiring-test-only")
    rules = source.get("rules")
    if not isinstance(rules, list) or len(rules) != 2:
        raise PublishError("scanner rule source must contain the two canonical EICAR checks")

    # The publication source is deliberately locked to the harmless, standardized
    # EICAR wiring check. Advisory records are not heuristically converted into
    # signatures, and no unreviewed malware indicator can enter this endpoint.
    expected = _eicar_rule_records()
    if tuple(rules) != expected:
        raise PublishError("scanner rule source differs from the canonical EICAR checks")
    return expected


def sign_payload(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    signature = key.sign(canonical_json(payload))
    return {
        "algorithm": "ed25519", "key_id": key_id, "payload": payload,
        "schema": "zsec.signed-envelope.v1", "signature": base64.b64encode(signature).decode(),
    }


def sign_rule_payload(
    payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    # The scanner-feed contract predates the publication envelopes and signs
    # canonical JSON without the publisher's trailing transport newline.
    signature = key.sign(canonical_json_bytes(payload))
    return {
        "algorithm": "ed25519",
        "key_id": key_id,
        "payload": payload,
        "schema": RULE_ENVELOPE_SCHEMA,
        "signature": base64.b64encode(signature).decode(),
    }


def verify_envelope(raw: bytes, public_key: Ed25519PublicKey) -> dict[str, Any]:
    root = _strict_json(raw)
    if not isinstance(root, dict) or set(root) != ENVELOPE_FIELDS:
        raise PublishError("signed envelope fields are invalid")
    if root["schema"] != "zsec.signed-envelope.v1" or root["algorithm"] != "ed25519":
        raise PublishError("signed envelope schema or algorithm is invalid")
    if not isinstance(root["key_id"], str) or not KEY_ID_PATTERN.fullmatch(root["key_id"]):
        raise PublishError("signed envelope key-id is invalid")
    try:
        signature = base64.b64decode(root["signature"], validate=True)
        if base64.b64encode(signature).decode() != root["signature"] or len(signature) != 64:
            raise ValueError
        public_key.verify(signature, canonical_json(root["payload"]))
    except (InvalidSignature, ValueError, binascii.Error, TypeError) as exc:
        raise PublishError("signed envelope verification failed") from exc
    return root


def build(
    *, catalog_path: Path, release_path: Path, rules_path: Path = DEFAULT_RULES,
    output: Path, key: Ed25519PrivateKey,
    key_id: str, sequence: int, generated_at: str, expires_at: str,
    expected_public_key: str | None, verification_time: datetime | None = None,
) -> dict[str, Any]:
    current = (verification_time or datetime.now(UTC)).astimezone(UTC)
    _validate_common(sequence, generated_at, expires_at, key_id, now=current)
    public = public_key_b64(key)
    if expected_public_key and public != expected_public_key:
        raise PublishError("signing key does not match ZSEC_UPDATE_PUBLIC_KEY_B64")
    catalog = _validate_catalog(_strict_json(catalog_path.read_bytes()))
    release = _validate_release(_strict_json(release_path.read_bytes()))
    rule_records = _validate_rule_source(_strict_json(rules_path.read_bytes()))
    catalog_bytes = canonical_json(catalog)
    intelligence_payload = {
        "catalog": catalog, "catalog_sha256": _digest(catalog_bytes), "expires_at": expires_at,
        "generated_at": generated_at, "policy": SAFETY_POLICY,
        "schema": "zsec.intelligence.payload.v1", "sequence": sequence,
    }
    update_payload = {
        "auto_install_allowed": False, "channel": "stable", "expires_at": expires_at,
        "generated_at": generated_at, "notification_only": True, "release": release,
        "schema": "zsec.application-update.payload.v1", "sequence": sequence,
    }
    rule_payload = {
        "expires_at": expires_at,
        "generated_at": generated_at,
        "rules": list(rule_records),
        "schema": RULE_PAYLOAD_SCHEMA,
        "sequence": sequence,
    }
    intelligence = canonical_json(sign_payload(intelligence_payload, key, key_id))
    update = canonical_json(sign_payload(update_payload, key, key_id))
    rules = canonical_json(sign_rule_payload(rule_payload, key, key_id))
    sequence_name = f"{sequence:020d}"
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="zsec-update-stage-", dir=output.parent))
    try:
        audit_payload = {
            "expires_at": expires_at,
            "generated_at": generated_at,
            "intelligence_sha256": _digest(intelligence),
            "rules_sha256": _digest(rules),
            "schema": "zsec.update-publication-audit.v2",
            "sequence": sequence,
            "update_sha256": _digest(update),
        }
        paths = {
            "intelligence/v1/feed.json": intelligence,
            "rules/v1/feed.json": rules,
            "updates/v1/stable.json": update,
            f"updates/v1/audit/{sequence_name}.json": canonical_json(
                sign_payload(audit_payload, key, key_id)
            ),
            "updates/v1/public-key.json": canonical_json({
                "algorithm": "ed25519", "key_id": key_id, "public_key": public,
                "schema": "zsec.update-public-key.v1",
            }),
        }
        for relative, raw in paths.items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        verify_tree(
            stage,
            key.public_key(),
            expected_sequence=sequence,
            now=current,
        )
        if output.exists():
            audit = output / "updates" / "v1" / "audit" / f"{sequence_name}.json"
            audit_key = f"updates/v1/audit/{sequence_name}.json"
            if audit.exists() and audit.read_bytes() != paths[audit_key]:
                raise PublishError(
                    "refusing to overwrite an existing sequence with different bytes"
                )
        output.mkdir(parents=True, exist_ok=True)
        for relative in sorted(paths):
            source = stage / relative
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".tmp")
            temporary.write_bytes(source.read_bytes())
            os.replace(temporary, destination)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return {
        "intelligence_sha256": _digest(intelligence), "key_id": key_id,
        "output": str(output), "public_key": public, "sequence": sequence,
        "rules_sha256": _digest(rules), "update_sha256": _digest(update),
    }


def verify_tree(
    output: Path,
    public_key: Ed25519PublicKey,
    expected_sequence: int | None = None,
    now: datetime | None = None,
) -> None:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    feed = verify_envelope((output / "intelligence/v1/feed.json").read_bytes(), public_key)
    update = verify_envelope((output / "updates/v1/stable.json").read_bytes(), public_key)
    payloads = (
        (feed, "zsec.intelligence.payload.v1"),
        (update, "zsec.application-update.payload.v1"),
    )
    for envelope, schema in payloads:
        payload = envelope["payload"]
        if not isinstance(payload, dict) or payload.get("schema") != schema:
            raise PublishError(f"unexpected payload schema: {schema}")
        sequence = payload.get("sequence")
        if not isinstance(sequence, int) or sequence < 1:
            raise PublishError("payload sequence is invalid")
        if expected_sequence is not None and sequence != expected_sequence:
            raise PublishError("payload sequence does not match expected sequence")
        generated = _timestamp(payload.get("generated_at"), "generated_at")
        expires = _timestamp(payload.get("expires_at"), "expires_at")
        if expires <= generated:
            raise PublishError("payload validity window is inverted")
        if expires - generated > timedelta(days=14):
            raise PublishError("payload validity window exceeds 14 days")
        if generated > current + timedelta(minutes=5):
            raise PublishError("payload generation time is too far in the future")
        if expires <= current:
            raise PublishError("payload has expired")
    if feed["payload"].get("policy") != SAFETY_POLICY:
        raise PublishError("published intelligence is not data-only")
    if update["payload"].get("notification_only") is not True:
        raise PublishError("application update must be notification-only")
    if update["payload"].get("auto_install_allowed") is not False:
        raise PublishError("application auto-install must remain disabled")
    sequence = feed["payload"]["sequence"]
    if update["payload"]["sequence"] != sequence:
        raise PublishError("intelligence and application sequences differ")
    public_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    rule_raw = (output / "rules/v1/feed.json").read_bytes()
    rule_root = _strict_json(rule_raw)
    if not isinstance(rule_root, dict) or not isinstance(rule_root.get("key_id"), str):
        raise PublishError("scanner rule envelope is invalid")
    trusted = TrustedKey(rule_root["key_id"], public_raw, "active", None, None)
    try:
        verified_rules = verify_feed_document(
            rule_raw,
            {trusted.key_id: trusted},
            now=current,
        )
    except FeedError as exc:
        raise PublishError(f"scanner rule feed verification failed: {exc}") from exc
    if verified_rules.sequence != sequence:
        raise PublishError("scanner rule and publication sequences differ")
    rule_payload_records = rule_root.get("payload", {}).get("rules")
    if not isinstance(rule_payload_records, list) or tuple(rule_payload_records) != (
        _eicar_rule_records()
    ):
        raise PublishError("scanner rule feed is not the bounded EICAR wiring-test set")
    audit_path = output / "updates/v1/audit" / f"{sequence:020d}.json"
    audit = verify_envelope(audit_path.read_bytes(), public_key)
    audit_payload = audit["payload"]
    audit_fields = {
        "expires_at",
        "generated_at",
        "intelligence_sha256",
        "rules_sha256",
        "schema",
        "sequence",
        "update_sha256",
    }
    if not isinstance(audit_payload, dict) or set(audit_payload) != audit_fields:
        raise PublishError("publication audit fields are invalid")
    if audit_payload.get("sequence") != sequence:
        raise PublishError("publication audit sequence is invalid")
    if audit_payload.get("schema") != "zsec.update-publication-audit.v2":
        raise PublishError("publication audit schema is invalid")
    if audit_payload.get("generated_at") != feed["payload"]["generated_at"]:
        raise PublishError("publication audit generation time is invalid")
    if audit_payload.get("expires_at") != feed["payload"]["expires_at"]:
        raise PublishError("publication audit expiry time is invalid")
    if len({feed["key_id"], update["key_id"], rule_root["key_id"], audit["key_id"]}) != 1:
        raise PublishError("publication endpoint key IDs differ")
    if audit_payload.get("intelligence_sha256") != _digest(
        (output / "intelligence/v1/feed.json").read_bytes()
    ):
        raise PublishError("publication audit intelligence digest is invalid")
    if audit_payload.get("update_sha256") != _digest(
        (output / "updates/v1/stable.json").read_bytes()
    ):
        raise PublishError("publication audit update digest is invalid")
    if audit_payload.get("rules_sha256") != _digest(rule_raw):
        raise PublishError("publication audit scanner-rule digest is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--expires-at", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        key = load_private_key(args.private_key_file)
        result = build(
            catalog_path=args.catalog, release_path=args.release, output=args.output,
            rules_path=args.rules,
            key=key, key_id=args.key_id, sequence=args.sequence,
            generated_at=args.generated_at, expires_at=args.expires_at,
            expected_public_key=os.environ.get("ZSEC_UPDATE_PUBLIC_KEY_B64"),
        )
    except (OSError, PublishError) as exc:
        print(json.dumps({"error": str(exc), "ok": False}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
