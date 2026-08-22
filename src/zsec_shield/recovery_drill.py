"""Isolated recovery self-test for the authenticated encrypted quarantine path."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from zsec_shield.errors import QuarantineError
from zsec_shield.models import Rule
from zsec_shield.quarantine import CONTENT_NAME, quarantine_finding, restore_entry
from zsec_shield.scanner import Scanner
from zsec_shield.util import atomic_write_bytes, format_utc

RECOVERY_DRILL_SCHEMA = "zsec.antivirus.recovery-drill.v1"
_PATTERN = b"zsec-benign-recovery-drill-pattern"


def _check(name: str, operation: Callable[[], None]) -> dict[str, Any]:
    try:
        operation()
    except Exception as exc:
        return {
            "id": name,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {"id": name, "passed": True, "error": None}


def run_recovery_drill() -> dict[str, Any]:
    """Exercise recovery controls using only a disposable synthetic fixture.

    This is a local self-test, not independent certification. Every path is below
    one temporary directory and is removed when the drill ends.
    """

    checks: list[dict[str, Any]] = []
    started_at = format_utc()
    with TemporaryDirectory(prefix="zsec-recovery-drill-") as temporary:
        content = b"ZSEC recovery drill\x00" + _PATTERN + os.urandom(32)
        root = Path(temporary)
        state_dir = root / "state"
        source_dir = root / "source"
        restore_dir = root / "restore"
        source_dir.mkdir()
        restore_dir.mkdir()
        source = source_dir / "synthetic-fixture.bin"
        source.write_bytes(content)
        expected_digest = hashlib.sha256(content).hexdigest()

        rule = Rule(
            "local:recovery-drill",
            "ZSEC benign recovery drill",
            "literal",
            "high",
            "Synthetic local fixture used only by the recovery self-test.",
            "ZSEC recovery drill",
            literal=_PATTERN,
        )
        scanner = Scanner((rule,))
        try:
            scan = scanner.scan([source])
        finally:
            scanner.close()
        if len(scan.findings) != 1 or scan.findings[0].sha256 != expected_digest:
            raise QuarantineError("synthetic recovery fixture was not scanned exactly")

        record = quarantine_finding(scan.findings[0], state_dir)
        entry = state_dir / "quarantine" / "entries" / record["id"]
        content_path = entry / CONTENT_NAME
        key_path = state_dir / "vault" / "keys" / "device-root.json"

        def verify_encrypted_copy() -> None:
            ciphertext = content_path.read_bytes()
            if source.exists():
                raise QuarantineError("source remained after completed quarantine")
            if ciphertext == content or _PATTERN in ciphertext:
                raise QuarantineError("quarantine payload is not encrypted")
            if record.get("state") != "quarantined":
                raise QuarantineError("quarantine did not reach the committed state")

        checks.append(_check("encrypted_authenticated_copy", verify_encrypted_copy))

        restored = restore_dir / "verified-restore.bin"

        def verify_restore() -> None:
            result = restore_entry(record["id"], state_dir, restored)
            if not result.get("recovery_copy_retained"):
                raise QuarantineError("restore did not retain the recovery copy")
            if hashlib.sha256(restored.read_bytes()).hexdigest() != expected_digest:
                raise QuarantineError("restored fixture digest does not match")

        checks.append(_check("authenticated_restore", verify_restore))

        def verify_no_overwrite() -> None:
            try:
                restore_entry(record["id"], state_dir, restored)
            except QuarantineError as exc:
                if "already exists" not in str(exc):
                    raise
            else:
                raise QuarantineError("restore unexpectedly overwrote an existing file")
            if hashlib.sha256(restored.read_bytes()).hexdigest() != expected_digest:
                raise QuarantineError("existing restore changed during no-overwrite test")

        checks.append(_check("no_overwrite_restore", verify_no_overwrite))

        original_ciphertext = content_path.read_bytes()
        tampered_destination = restore_dir / "tampered-restore.bin"

        def verify_tamper_rejection() -> None:
            if not original_ciphertext:
                raise QuarantineError("encrypted recovery payload is empty")
            tampered = bytes((original_ciphertext[0] ^ 1,)) + original_ciphertext[1:]
            atomic_write_bytes(content_path, tampered)
            try:
                restore_entry(record["id"], state_dir, tampered_destination)
            except QuarantineError as exc:
                if "authentication failed" not in str(exc):
                    raise
            else:
                raise QuarantineError("tampered ciphertext was restored")
            finally:
                atomic_write_bytes(content_path, original_ciphertext)
            if tampered_destination.exists():
                raise QuarantineError("tampered restore left an output file")

        checks.append(_check("ciphertext_tamper_rejected", verify_tamper_rejection))

        key_backup = key_path.read_bytes()
        unavailable_destination = restore_dir / "missing-key-restore.bin"
        recovered_destination = restore_dir / "recovered-key-restore.bin"

        def verify_key_loss_and_recovery() -> None:
            key_path.unlink()
            try:
                restore_entry(record["id"], state_dir, unavailable_destination)
            except QuarantineError as exc:
                if "device root key is unavailable" not in str(exc):
                    raise
            else:
                raise QuarantineError("restore unexpectedly succeeded without the device root")
            finally:
                atomic_write_bytes(key_path, key_backup)
            if unavailable_destination.exists():
                raise QuarantineError("missing-key restore left an output file")
            restore_entry(record["id"], state_dir, recovered_destination)
            if hashlib.sha256(recovered_destination.read_bytes()).hexdigest() != expected_digest:
                raise QuarantineError("recovered-key restore digest does not match")

        checks.append(_check("device_key_loss_and_recovery", verify_key_loss_and_recovery))

    passed = all(check["passed"] for check in checks)
    return {
        "schema": RECOVERY_DRILL_SCHEMA,
        "product": "ZSEC Antivirus",
        "started_at": started_at,
        "completed_at": format_utc(),
        "passed": passed,
        "scope": "isolated synthetic data only",
        "independent_certification": False,
        "checks": checks,
        "summary": {
            "passed": sum(1 for check in checks if check["passed"]),
            "failed": sum(1 for check in checks if not check["passed"]),
            "total": len(checks),
        },
    }


__all__ = ["RECOVERY_DRILL_SCHEMA", "run_recovery_drill"]
