from __future__ import annotations

import io
import json
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tests.helpers import make_signing_material
from tests.test_automatic_updates import application_envelope, envelope
from zsec_shield.automatic_updates import (
    STATUS_LIMIT,
    run_automatic_update,
    verify_application_update_envelope,
)
from zsec_shield.errors import FeedError
from zsec_shield.feed import (
    MAX_FEED_BYTES,
    MAX_INTELLIGENCE_BYTES,
    _download_https_feed,
    _HTTPSOnlyRedirectHandler,
    download_feed,
    download_intelligence_feed,
)
from zsec_shield.paths import intelligence_document_path

ROOT = Path(__file__).resolve().parents[1]
URL = "https://example.invalid/zsec/intelligence/v1/feed.json"


class FeedResponse(io.BytesIO):
    def __init__(self, raw: bytes, *, content_length: bool = True) -> None:
        super().__init__(raw)
        self.headers = {"Content-Length": str(len(raw))} if content_length else {}
        self.requested_sizes: list[int] = []

    def geturl(self) -> str:
        return URL

    def read(self, size: int = -1) -> bytes:
        self.requested_sizes.append(size)
        return super().read(size)


def transport(raw: bytes, *, content_length: bool = True) -> tuple[Mock, FeedResponse]:
    response = FeedResponse(raw, content_length=content_length)
    opener = Mock()
    opener.open.return_value = response
    return opener, response


def test_large_valid_intelligence_download_verifies_and_installs(tmp_path: Path) -> None:
    private_key, keyring = make_signing_material(tmp_path)
    now = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
    catalog = json.loads(
        (ROOT / "intelligence/desktop-advisories.json").read_text(encoding="utf-8")
    )
    raw = envelope(private_key, catalog, now, 25)
    # JSON whitespace preserves the exact signed payload if a future catalog is
    # smaller; the regression must always exercise the formerly rejected size.
    raw += b" " * max(0, MAX_FEED_BYTES + 100 - len(raw))
    assert MAX_FEED_BYTES < len(raw) < MAX_INTELLIGENCE_BYTES
    opener, response = transport(raw)
    with patch("zsec_shield.feed.urllib.request.build_opener", return_value=opener):
        status = run_automatic_update(
            tmp_path / "state", keyring, source=URL, timeout=7.0, force=True, now=now
        )
    assert status.state == "updated"
    assert status.feed_sequence == 25
    assert (
        json.loads(intelligence_document_path(tmp_path / "state").read_text(encoding="utf-8"))
        == catalog
    )
    assert response.requested_sizes == [MAX_INTELLIGENCE_BYTES + 1]
    assert opener.open.call_args.kwargs["timeout"] == 7.0


@pytest.mark.parametrize("content_length", [True, False])
def test_general_rules_download_keeps_two_mib_limit(content_length: bool) -> None:
    opener, response = transport(b"x" * (MAX_FEED_BYTES + 1), content_length=content_length)
    with (
        patch("zsec_shield.feed.urllib.request.build_opener", return_value=opener),
        pytest.raises(FeedError, match="size limit"),
    ):
        download_feed(URL)
    assert response.requested_sizes == ([] if content_length else [MAX_FEED_BYTES + 1])


@pytest.mark.parametrize("content_length", [True, False])
def test_intelligence_download_rejects_above_eight_mib(content_length: bool) -> None:
    opener, response = transport(
        b"x" * (MAX_INTELLIGENCE_BYTES + 1), content_length=content_length
    )
    with (
        patch("zsec_shield.feed.urllib.request.build_opener", return_value=opener),
        pytest.raises(FeedError, match="size limit"),
    ):
        download_intelligence_feed(URL)
    assert response.requested_sizes == (
        [] if content_length else [MAX_INTELLIGENCE_BYTES + 1]
    )


@pytest.mark.parametrize(
    "limit", [None, True, 0, -1, 1, MAX_FEED_BYTES - 1, MAX_INTELLIGENCE_BYTES + 1, 2**63, 1.0]
)
def test_transport_refuses_arbitrary_or_unlimited_limits(limit: object) -> None:
    with (
        patch("zsec_shield.feed.urllib.request.build_opener") as opener,
        pytest.raises(FeedError, match="supported fixed size limit"),
    ):
        _download_https_feed(URL, 15.0, maximum_bytes=limit)  # type: ignore[arg-type]
    opener.assert_not_called()


@pytest.mark.parametrize("downloader", [download_feed, download_intelligence_feed])
def test_public_typed_transports_expose_no_size_override(downloader: object) -> None:
    with pytest.raises(TypeError):
        downloader(URL, maximum_bytes=2**63)  # type: ignore[operator]


@pytest.mark.parametrize(
    "target", ["http://example.invalid/feed", "https://user:secret@example.invalid/feed"]
)
def test_intelligence_redirect_restrictions_remain(target: str) -> None:
    handler = _HTTPSOnlyRedirectHandler()
    request = urllib.request.Request(URL)
    with pytest.raises(FeedError, match="credential-free HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, target)


def test_intelligence_redirect_count_remains_bounded() -> None:
    handler = _HTTPSOnlyRedirectHandler()
    request = urllib.request.Request(URL)
    for _ in range(3):
        handler.redirect_request(request, None, 302, "Found", {}, URL)
    with pytest.raises(FeedError, match="redirect limit"):
        handler.redirect_request(request, None, 302, "Found", {}, URL)


def test_application_envelope_keeps_sixty_four_kib_limit(tmp_path: Path) -> None:
    private_key, keyring = make_signing_material(tmp_path)
    now = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
    release = json.loads((ROOT / "updates/application-release.json").read_text())
    raw = application_envelope(private_key, release, now)
    raw += b" " * (STATUS_LIMIT + 1 - len(raw))
    with pytest.raises(FeedError, match="too large"):
        verify_application_update_envelope(raw, keyring, now=now)


def test_large_intelligence_still_rejects_bad_signature(tmp_path: Path) -> None:
    private_key, keyring = make_signing_material(tmp_path)
    now = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
    catalog = json.loads(
        (ROOT / "intelligence/desktop-advisories.json").read_text(encoding="utf-8")
    )
    document = json.loads(envelope(private_key, catalog, now, 25))
    document["payload"]["sequence"] = 26
    raw = json.dumps(document).encode()
    raw += b" " * max(0, MAX_FEED_BYTES + 100 - len(raw))
    opener, _ = transport(raw)
    with patch("zsec_shield.feed.urllib.request.build_opener", return_value=opener):
        status = run_automatic_update(
            tmp_path / "state", keyring, source=URL, force=True, now=now
        )
    assert status.state == "error"
    assert "signature" in (status.error or "")
    assert not intelligence_document_path(tmp_path / "state").exists()


@pytest.mark.parametrize("failure", ["expired", "rollback"])
def test_large_intelligence_failure_preserves_verified_catalog(
    tmp_path: Path, failure: str
) -> None:
    private_key, keyring = make_signing_material(tmp_path)
    now = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
    catalog = json.loads(
        (ROOT / "intelligence/desktop-advisories.json").read_text(encoding="utf-8")
    )
    state = tmp_path / "state"

    def large_envelope(generated_at: datetime, sequence: int) -> bytes:
        raw = envelope(private_key, catalog, generated_at, sequence)
        raw += b" " * max(0, MAX_FEED_BYTES + 100 - len(raw))
        assert MAX_FEED_BYTES < len(raw) < MAX_INTELLIGENCE_BYTES
        return raw

    accepted_opener, _ = transport(large_envelope(now, 25))
    with patch(
        "zsec_shield.feed.urllib.request.build_opener", return_value=accepted_opener
    ):
        accepted = run_automatic_update(
            state, keyring, source=URL, force=True, now=now
        )
    assert accepted.state == "updated"
    before = intelligence_document_path(state).read_bytes()

    generated_at = now - timedelta(days=8) if failure == "expired" else now
    sequence = 26 if failure == "expired" else 24
    refused_opener, response = transport(large_envelope(generated_at, sequence))
    with patch(
        "zsec_shield.feed.urllib.request.build_opener", return_value=refused_opener
    ):
        refused = run_automatic_update(
            state, keyring, source=URL, force=True, now=now
        )
    assert refused.state == "error"
    expected_error = "expiry" if failure == "expired" else "rollback"
    assert expected_error in (refused.error or "")
    assert refused.last_success_at == accepted.last_success_at
    assert refused.feed_sequence == accepted.feed_sequence
    assert intelligence_document_path(state).read_bytes() == before
    assert response.requested_sizes == [MAX_INTELLIGENCE_BYTES + 1]
