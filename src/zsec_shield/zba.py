"""Minimal ZBA 1.1 provenance profile for Zero Security vault objects.

ZBA supplies typed lifecycle and commitment semantics. It is deliberately not
used as a cipher or a substitute for authenticated encryption.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from zsec_shield.errors import QuarantineError
from zsec_shield.util import canonical_json_bytes

ZBA_SPEC = "zero.security.zba.quarantine.v1"
ZBA_DOMAIN = b"ZERO-SECURITY/ZBA-QUARANTINE/V1\x00"
ZERO_COMMITMENT = "0" * 64


def create_quarantine_record(
    *, entry_id: str, payload_sha256: str, created_at: str
) -> dict[str, Any]:
    """Create the sealed boundary record authenticated with a vault object."""

    record: dict[str, Any] = {
        "spec": ZBA_SPEC,
        "asset_id": entry_id,
        "sequence": 0,
        "operation": "quarantine.encrypt",
        "polarity": "neutral",
        "phase": "boundary",
        "recursion_depth": 0,
        "policy_id": "zero-security-quarantine",
        "policy_version": 1,
        "previous_commitment": ZERO_COMMITMENT,
        "payload_commitment": payload_sha256,
        "event_time": created_at,
        "actor_id": "local-device",
        "evidence_status": "sealed",
        "commitment_algorithm": "sha256",
    }
    record["commitment"] = _commitment(record)
    return record


def validate_quarantine_record(
    record: Any, *, entry_id: str, payload_sha256: str
) -> dict[str, Any]:
    """Validate the exact typed record used by the current vault profile."""

    if not isinstance(record, dict):
        raise QuarantineError("ZBA record must be an object")
    required = {
        "spec",
        "asset_id",
        "sequence",
        "operation",
        "polarity",
        "phase",
        "recursion_depth",
        "policy_id",
        "policy_version",
        "previous_commitment",
        "payload_commitment",
        "event_time",
        "actor_id",
        "evidence_status",
        "commitment_algorithm",
        "commitment",
    }
    if set(record) != required:
        raise QuarantineError("ZBA record fields are invalid")
    fixed = {
        "spec": ZBA_SPEC,
        "asset_id": entry_id,
        "sequence": 0,
        "operation": "quarantine.encrypt",
        "polarity": "neutral",
        "phase": "boundary",
        "recursion_depth": 0,
        "policy_id": "zero-security-quarantine",
        "policy_version": 1,
        "previous_commitment": ZERO_COMMITMENT,
        "payload_commitment": payload_sha256,
        "actor_id": "local-device",
        "evidence_status": "sealed",
        "commitment_algorithm": "sha256",
    }
    for field, expected in fixed.items():
        if record.get(field) != expected:
            raise QuarantineError(f"ZBA record field is invalid: {field}")
    event_time = record.get("event_time")
    if not isinstance(event_time, str) or not event_time.endswith("Z"):
        raise QuarantineError("ZBA event time is invalid")
    commitment = record.get("commitment")
    if not isinstance(commitment, str) or not _is_sha256(commitment):
        raise QuarantineError("ZBA commitment is invalid")
    if not hmac.compare_digest(commitment, _commitment(record)):
        raise QuarantineError("ZBA commitment verification failed")
    return record


def _commitment(record: dict[str, Any]) -> str:
    projection = {key: value for key, value in record.items() if key != "commitment"}
    previous = projection.get("previous_commitment")
    if not isinstance(previous, str) or not _is_sha256(previous):
        raise QuarantineError("ZBA predecessor commitment is invalid")
    return hashlib.sha256(
        ZBA_DOMAIN + bytes.fromhex(previous) + canonical_json_bytes(projection)
    ).hexdigest()


def _is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return value == value.lower()
