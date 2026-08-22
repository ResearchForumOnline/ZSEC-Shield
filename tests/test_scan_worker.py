from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from zsec_shield.errors import ScanWorkerError
from zsec_shield.models import Rule
from zsec_shield.scan_worker import WORKER_PROTOCOL, BoundedScanWorker, _decode
from zsec_shield.scanner import Scanner, ScannerConfig


def _rule(
    identifier: str,
    *,
    literal: bytes | None = None,
    digest: str | None = None,
) -> Rule:
    return Rule(
        rule_id=identifier,
        name=identifier,
        kind="literal" if literal is not None else "sha256",
        severity="high",
        description="bounded worker test rule",
        source="test",
        literal=literal,
        digest=digest,
    )


def test_out_of_process_worker_matches_literal_across_chunks_and_digest(tmp_path: Path) -> None:
    content = (b"A" * 4094) + b"ZSEC-SPLIT-RULE" + (b"B" * 5000)
    target = tmp_path / "candidate.bin"
    target.write_bytes(content)
    rules = (
        _rule("literal-split", literal=b"ZSEC-SPLIT-RULE"),
        _rule("digest-exact", digest=hashlib.sha256(content).hexdigest()),
    )
    scanner = Scanner(
        rules,
        ScannerConfig(
            chunk_bytes=4096,
            worker_isolation=True,
            worker_max_requests=1,
        ),
    )
    try:
        result = scanner.scan([target])
    finally:
        scanner.close()

    assert result.issues == []
    assert result.stats.files_hashed == 1
    assert result.stats.bytes_hashed == len(content)
    assert len(result.findings) == 1
    assert [match.rule_id for match in result.findings[0].matches] == [
        "digest-exact",
        "literal-split",
    ]


def test_worker_is_restarted_after_bounded_request_count(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    scanner = Scanner(
        (),
        ScannerConfig(worker_isolation=True, worker_max_requests=1),
    )
    try:
        result = scanner.scan([first, second])
    finally:
        scanner.close()

    assert result.issues == []
    assert result.stats.files_hashed == 2
    assert result.stats.bytes_hashed == 11


def test_worker_failure_is_incomplete_and_never_falls_back(tmp_path: Path) -> None:
    target = tmp_path / "candidate.bin"
    target.write_bytes(b"configured exact literal")
    scanner = Scanner(
        (_rule("would-match", literal=b"configured exact literal"),),
        ScannerConfig(worker_isolation=True),
    )
    try:
        with patch.object(
            scanner._worker,
            "inspect",
            side_effect=ScanWorkerError("worker deadline exceeded"),
        ):
            result = scanner.scan([target])
    finally:
        scanner.close()

    assert result.findings == []
    assert result.stats.files_hashed == 0
    assert [issue.code for issue in result.issues] == ["content_worker_failed"]
    assert "deadline exceeded" in result.issues[0].message


def test_worker_protocol_rejects_duplicate_unknown_and_mismatched_fields() -> None:
    with pytest.raises(ScanWorkerError, match="duplicate key"):
        _decode(b'{"protocol":"one","protocol":"two"}')

    worker = BoundedScanWorker((), chunk_bytes=4096, max_file_bytes=4096)
    valid = {
        "protocol": WORKER_PROTOCOL,
        "request_id": "a" * 32,
        "ok": True,
        "sha256": hashlib.sha256(b"").hexdigest(),
        "bytes_read": 0,
        "literal_rule_ids": [],
        "observations": [],
    }
    with pytest.raises(ScanWorkerError, match="correlation mismatch"):
        worker._validate_response(valid, 0, "b" * 32)

    valid["unknown"] = False
    with pytest.raises(ScanWorkerError, match="missing or unknown fields"):
        worker._validate_response(valid, 0, "a" * 32)
