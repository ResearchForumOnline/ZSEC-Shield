from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zsec_shield.feed import ENVELOPE_SCHEMA, KEYRING_SCHEMA, PAYLOAD_SCHEMA
from zsec_shield.util import canonical_json_bytes, format_utc


def make_signing_material(
    directory: Path, key_id: str = "test:primary"
) -> tuple[Ed25519PrivateKey, Path]:
    private_key = Ed25519PrivateKey.generate()
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "schema": KEYRING_SCHEMA,
        "keys": [
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key": base64.b64encode(public).decode("ascii"),
                "status": "active",
            }
        ],
    }
    path = directory / "keyring.json"
    path.write_text(json.dumps(keyring), encoding="utf-8")
    return private_key, path


def signed_feed(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "test:primary",
    sequence: int = 1,
    rules: list[dict[str, Any]] | None = None,
    now: datetime | None = None,
    expires_delta: timedelta = timedelta(days=7),
    extra_payload: dict[str, Any] | None = None,
) -> bytes:
    current = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    payload: dict[str, Any] = {
        "schema": PAYLOAD_SCHEMA,
        "sequence": sequence,
        "generated_at": format_utc(current),
        "expires_at": format_utc(current + expires_delta),
        "rules": rules or [],
    }
    if extra_payload:
        payload.update(extra_payload)
    signature = private_key.sign(canonical_json_bytes(payload))
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "algorithm": "ed25519",
        "key_id": key_id,
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(envelope, sort_keys=True).encode("utf-8")


def literal_rule(rule_id: str, pattern: bytes, severity: str = "high") -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": "Test literal",
        "kind": "literal",
        "severity": severity,
        "description": "Deterministic test-only byte pattern.",
        "source": "test suite",
        "value": base64.b64encode(pattern).decode("ascii"),
    }
