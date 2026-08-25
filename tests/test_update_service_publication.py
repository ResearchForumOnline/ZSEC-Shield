from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.publish_update_service import (
    PublishError,
    build,
    sign_rule_payload,
    verify_envelope,
    verify_tree,
)
from zsec_shield.feed import TrustedKey, verify_feed_document

ROOT = Path(__file__).resolve().parents[1]
VERIFICATION_TIME = datetime(2026, 8, 22, 19, 0, tzinfo=UTC)


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def test_release_publication_preserves_last_valid_intelligence_on_refresh_failure() -> None:
    workflow = (ROOT / ".github/workflows/publish-update-service.yml").read_text(
        encoding="utf-8"
    )
    assert "if python scripts/update_desktop_intelligence.py --dry-run --json; then" in workflow
    assert "publishing the last validated intelligence catalog" in workflow
    assert workflow.index("--dry-run --json; then") < workflow.index(
        "python scripts/update_desktop_intelligence.py --json"
    )


def _build(output: Path, sequence: int = 7) -> dict[str, object]:
    key = _key()
    return build(
        catalog_path=ROOT / "intelligence/desktop-advisories.json",
        release_path=ROOT / "updates/application-release.json",
        output=output,
        key=key,
        key_id="zsec:update-test-2026",
        sequence=sequence,
        generated_at="2026-08-22T19:00:00Z",
        expires_at="2026-09-05T19:00:00Z",
        expected_public_key=_public_b64(key),
        verification_time=VERIFICATION_TIME,
    )


def test_build_is_deterministic_signed_and_versioned(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_result = _build(first)
    second_result = _build(second)
    assert first_result["intelligence_sha256"] == second_result["intelligence_sha256"]
    assert first_result["rules_sha256"] == second_result["rules_sha256"]
    assert first_result["update_sha256"] == second_result["update_sha256"]
    assert (first / "intelligence/v1/feed.json").read_bytes() == (
        second / "intelligence/v1/feed.json"
    ).read_bytes()
    assert (first / "rules/v1/feed.json").read_bytes() == (
        second / "rules/v1/feed.json"
    ).read_bytes()
    audit = first / "updates/v1/audit/00000000000000000007.json"
    assert audit.is_file()
    assert audit.stat().st_size < 1_500
    verify_tree(
        first,
        _key().public_key(),
        expected_sequence=7,
        now=VERIFICATION_TIME,
    )
    envelope = verify_envelope(
        (first / "updates/v1/stable.json").read_bytes(), _key().public_key()
    )
    assert envelope["payload"]["notification_only"] is True
    assert envelope["payload"]["auto_install_allowed"] is False
    public_raw = _key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    verified_rules = verify_feed_document(
        (first / "rules/v1/feed.json").read_bytes(),
        {"zsec:update-test-2026": TrustedKey(
            "zsec:update-test-2026", public_raw, "active", None, None
        )},
        now=VERIFICATION_TIME,
    )
    assert verified_rules.sequence == 7
    assert [rule.rule_id for rule in verified_rules.rules] == [
        "feed:eicar-test-file",
        "feed:eicar-test-file-sha256",
    ]
    literal = next(rule.literal for rule in verified_rules.rules if rule.kind == "literal")
    assert literal is not None
    assert len(literal) == 68
    assert hashlib.sha256(literal).hexdigest() == next(
        rule.digest for rule in verified_rules.rules if rule.kind == "sha256"
    )
    assert all(rule.severity == "info" for rule in verified_rules.rules)


def test_wrong_expected_public_key_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PublishError, match="does not match"):
        build(
            catalog_path=ROOT / "intelligence/desktop-advisories.json",
            release_path=ROOT / "updates/application-release.json",
            output=tmp_path / "out",
            key=_key(),
            key_id="zsec:update-test-2026",
            sequence=1,
            generated_at="2026-08-22T19:00:00Z",
            expires_at="2026-08-23T19:00:00Z",
            expected_public_key=base64.b64encode(b"x" * 32).decode(),
            verification_time=VERIFICATION_TIME,
        )


def test_tampered_envelope_is_rejected(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _build(output)
    path = output / "intelligence/v1/feed.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["payload"]["sequence"] = 8
    with pytest.raises(PublishError, match="verification failed"):
        verify_envelope(json.dumps(document).encode(), _key().public_key())


def test_sequence_cannot_be_reused_for_different_bytes(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _build(output)
    release = json.loads(
        (ROOT / "updates/application-release.json").read_text(encoding="utf-8")
    )
    release["version"] = "9.9.9-test-mutation"
    changed = tmp_path / "release.json"
    changed.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(PublishError, match="overwrite an existing sequence"):
        build(
            catalog_path=ROOT / "intelligence/desktop-advisories.json",
            release_path=changed,
            output=output,
            key=_key(),
            key_id="zsec:update-test-2026",
            sequence=7,
            generated_at="2026-08-22T19:00:00Z",
            expires_at="2026-09-05T19:00:00Z",
            expected_public_key=_public_b64(_key()),
            verification_time=VERIFICATION_TIME,
        )


def test_verification_rejects_partial_endpoint_and_audit_digest_mismatch(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _build(output)
    stable = output / "updates/v1/stable.json"
    stable.write_bytes(stable.read_bytes()[:64])
    with pytest.raises((PublishError, json.JSONDecodeError)):
        verify_tree(
            output,
            _key().public_key(),
            expected_sequence=7,
            now=VERIFICATION_TIME,
        )

    output = tmp_path / "digest-mismatch"
    _build(output)
    feed = output / "intelligence/v1/feed.json"
    document = json.loads(feed.read_text(encoding="utf-8"))
    document["payload"]["catalog"]["entries"] = []
    # Re-signing the endpoint proves the independently signed audit digest is
    # also required; a valid endpoint signature alone cannot rewrite history.
    payload = document["payload"]
    document["signature"] = base64.b64encode(
        _key().sign(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
            + b"\n"
        )
    ).decode()
    feed.write_text(
        json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PublishError, match="audit intelligence digest"):
        verify_tree(
            output,
            _key().public_key(),
            expected_sequence=7,
            now=VERIFICATION_TIME,
        )


def test_scanner_rule_endpoint_tampering_fails_closed(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _build(output)
    path = output / "rules/v1/feed.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["payload"]["rules"][0]["severity"] = "critical"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PublishError, match="scanner rule feed verification failed"):
        verify_tree(
            output,
            _key().public_key(),
            expected_sequence=7,
            now=VERIFICATION_TIME,
        )


def test_validly_resigned_non_eicar_rule_is_still_rejected(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _build(output)
    path = output / "rules/v1/feed.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["payload"]["rules"][0]["value"] = base64.b64encode(
        b"not the canonical EICAR wiring check"
    ).decode()
    resigned = sign_rule_payload(
        document["payload"], _key(), "zsec:update-test-2026"
    )
    path.write_text(json.dumps(resigned), encoding="utf-8")
    with pytest.raises(PublishError, match="not the bounded EICAR"):
        verify_tree(
            output,
            _key().public_key(),
            expected_sequence=7,
            now=VERIFICATION_TIME,
        )


def test_scanner_rule_source_cannot_import_advisories_or_unknown_indicators(
    tmp_path: Path,
) -> None:
    source = json.loads((ROOT / "rules/scanner-rules.json").read_text(encoding="utf-8"))
    source["policy"]["advisory_conversion_allowed"] = True
    source["rules"].append({
        "description": "Unreviewed indicator must not publish.",
        "id": "feed:unreviewed",
        "kind": "sha256",
        "name": "Unreviewed",
        "severity": "critical",
        "source": "advisory conversion",
        "value": "0" * 64,
    })
    changed = tmp_path / "rules.json"
    changed.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(PublishError, match="EICAR wiring-test-only"):
        build(
            catalog_path=ROOT / "intelligence/desktop-advisories.json",
            release_path=ROOT / "updates/application-release.json",
            rules_path=changed,
            output=tmp_path / "out",
            key=_key(),
            key_id="zsec:update-test-2026",
            sequence=7,
            generated_at="2026-08-22T19:00:00Z",
            expires_at="2026-09-05T19:00:00Z",
            expected_public_key=_public_b64(_key()),
            verification_time=VERIFICATION_TIME,
        )


def test_stale_or_future_publication_window_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PublishError, match="expires-at must be later"):
        build(
            catalog_path=ROOT / "intelligence/desktop-advisories.json",
            release_path=ROOT / "updates/application-release.json",
            output=tmp_path / "stale",
            key=_key(),
            key_id="zsec:update-test-2026",
            sequence=7,
            generated_at="2026-08-01T19:00:00Z",
            expires_at="2026-08-08T19:00:00Z",
            expected_public_key=_public_b64(_key()),
            verification_time=VERIFICATION_TIME,
        )
    with pytest.raises(PublishError, match="five minutes in the future"):
        build(
            catalog_path=ROOT / "intelligence/desktop-advisories.json",
            release_path=ROOT / "updates/application-release.json",
            output=tmp_path / "future",
            key=_key(),
            key_id="zsec:update-test-2026",
            sequence=7,
            generated_at="2026-08-22T19:06:00Z",
            expires_at="2026-08-23T19:06:00Z",
            expected_public_key=_public_b64(_key()),
            verification_time=VERIFICATION_TIME,
        )
