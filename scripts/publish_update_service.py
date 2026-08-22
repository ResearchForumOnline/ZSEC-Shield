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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "intelligence" / "desktop-advisories.json"
DEFAULT_RELEASE = ROOT / "updates" / "application-release.json"
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


def _validate_common(sequence: int, generated_at: str, expires_at: str, key_id: str) -> None:
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


def sign_payload(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    signature = key.sign(canonical_json(payload))
    return {
        "algorithm": "ed25519", "key_id": key_id, "payload": payload,
        "schema": "zsec.signed-envelope.v1", "signature": base64.b64encode(signature).decode(),
    }


def verify_envelope(raw: bytes, public_key: Ed25519PublicKey) -> dict[str, Any]:
    root = _strict_json(raw)
    if not isinstance(root, dict) or set(root) != ENVELOPE_FIELDS:
        raise PublishError("signed envelope fields are invalid")
    if root["schema"] != "zsec.signed-envelope.v1" or root["algorithm"] != "ed25519":
        raise PublishError("signed envelope schema or algorithm is invalid")
    try:
        signature = base64.b64decode(root["signature"], validate=True)
        if base64.b64encode(signature).decode() != root["signature"] or len(signature) != 64:
            raise ValueError
        public_key.verify(signature, canonical_json(root["payload"]))
    except (InvalidSignature, ValueError, binascii.Error, TypeError) as exc:
        raise PublishError("signed envelope verification failed") from exc
    return root


def build(
    *, catalog_path: Path, release_path: Path, output: Path, key: Ed25519PrivateKey,
    key_id: str, sequence: int, generated_at: str, expires_at: str,
    expected_public_key: str | None,
) -> dict[str, Any]:
    _validate_common(sequence, generated_at, expires_at, key_id)
    public = public_key_b64(key)
    if expected_public_key and public != expected_public_key:
        raise PublishError("signing key does not match ZSEC_UPDATE_PUBLIC_KEY_B64")
    catalog = _validate_catalog(_strict_json(catalog_path.read_bytes()))
    release = _validate_release(_strict_json(release_path.read_bytes()))
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
    intelligence = canonical_json(sign_payload(intelligence_payload, key, key_id))
    update = canonical_json(sign_payload(update_payload, key, key_id))
    sequence_name = f"{sequence:020d}"
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="zsec-update-stage-", dir=output.parent))
    try:
        audit_payload = {
            "expires_at": expires_at,
            "generated_at": generated_at,
            "intelligence_sha256": _digest(intelligence),
            "schema": "zsec.update-publication-audit.v1",
            "sequence": sequence,
            "update_sha256": _digest(update),
        }
        paths = {
            "intelligence/v1/feed.json": intelligence,
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
        verify_tree(stage, key.public_key(), expected_sequence=sequence)
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
        "update_sha256": _digest(update),
    }


def verify_tree(
    output: Path,
    public_key: Ed25519PublicKey,
    expected_sequence: int | None = None,
) -> None:
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
    if feed["payload"].get("policy") != SAFETY_POLICY:
        raise PublishError("published intelligence is not data-only")
    if update["payload"].get("notification_only") is not True:
        raise PublishError("application update must be notification-only")
    if update["payload"].get("auto_install_allowed") is not False:
        raise PublishError("application auto-install must remain disabled")
    sequence = feed["payload"]["sequence"]
    if update["payload"]["sequence"] != sequence:
        raise PublishError("intelligence and application sequences differ")
    audit_path = output / "updates/v1/audit" / f"{sequence:020d}.json"
    audit = verify_envelope(audit_path.read_bytes(), public_key)
    audit_payload = audit["payload"]
    if not isinstance(audit_payload, dict) or audit_payload.get("sequence") != sequence:
        raise PublishError("publication audit sequence is invalid")
    if audit_payload.get("intelligence_sha256") != _digest(
        (output / "intelligence/v1/feed.json").read_bytes()
    ):
        raise PublishError("publication audit intelligence digest is invalid")
    if audit_payload.get("update_sha256") != _digest(
        (output / "updates/v1/stable.json").read_bytes()
    ):
        raise PublishError("publication audit update digest is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
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
