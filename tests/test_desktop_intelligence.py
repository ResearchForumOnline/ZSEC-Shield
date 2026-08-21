from __future__ import annotations

import hashlib
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.intelligence import (
    APPLE_SECURITY_URL,
    CISA_KEV_URL,
    MSRC_CVRF_PREFIX,
    MSRC_UPDATES_URL,
    UBUNTU_USN_URL,
    HTTPSourceFetcher,
    IntelligenceError,
    SourceArtifact,
    build_catalog,
    catalog_bytes,
    collect_catalog,
    install_catalog,
    parse_apple_security,
    parse_cisa_kev,
    parse_microsoft_msrc,
    parse_ubuntu_usn,
    update_desktop_intelligence,
    validate_catalog,
)


def _artifact(source_id: str, url: str, value: object, **kwargs: str) -> SourceArtifact:
    raw = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    assert isinstance(raw, bytes)
    return SourceArtifact(
        source_id,
        url,
        raw,
        hashlib.sha256(raw).hexdigest(),
        kwargs.get("etag"),
        kwargs.get("last_modified"),
    )


def _cisa_document(
    *,
    released: str = "2026-08-21T12:00:00Z",
    name: str = "Microsoft Windows Test Vulnerability",
) -> dict[str, object]:
    records = [
        {
            "cveID": "CVE-2026-12345",
            "vendorProject": "Microsoft",
            "product": "Windows 11",
            "vulnerabilityName": name,
            "dateAdded": "2026-08-21",
            "shortDescription": "Windows contains a local privilege escalation issue.",
            "requiredAction": "Apply mitigations from the vendor.",
            "dueDate": "2026-08-28",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-269"],
        },
        {
            "cveID": "CVE-2026-54321",
            "vendorProject": "Example",
            "product": "Network Appliance",
            "vulnerabilityName": "Example appliance issue",
            "dateAdded": "2026-08-20",
            "shortDescription": "A dedicated appliance contains an issue.",
            "requiredAction": "Follow vendor instructions.",
            "dueDate": "2026-08-27",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-20"],
        },
    ]
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.08.21",
        "dateReleased": released,
        "count": len(records),
        "vulnerabilities": records,
    }


def _msrc_index() -> dict[str, object]:
    return {
        "@odata.context": "https://api.msrc.microsoft.com/$metadata#Updates",
        "value": [
            {
                "ID": "Edge Stable Channel",
                "InitialReleaseDate": "2026-08-20T07:00:00Z",
                "CurrentReleaseDate": "2026-08-20T07:00:00Z",
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/Edge",
            },
            {
                "ID": "2026-Jul",
                "InitialReleaseDate": "2026-07-14T07:00:00Z",
                "CurrentReleaseDate": "2026-07-20T07:00:00Z",
                "CvrfUrl": MSRC_CVRF_PREFIX + "2026-Jul",
            },
            {
                "ID": "2026-Aug",
                "InitialReleaseDate": "2026-08-11T07:00:00Z",
                "CurrentReleaseDate": "2026-08-21T07:00:00Z",
                "CvrfUrl": MSRC_CVRF_PREFIX + "2026-Aug",
            },
        ],
    }


def _msrc_document() -> dict[str, object]:
    return {
        "DocumentTracking": {
            "Identification": {"ID": {"Value": "2026-Aug"}},
            "InitialReleaseDate": "2026-08-11T07:00:00Z",
            "CurrentReleaseDate": "2026-08-21T07:00:00Z",
        },
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "w11", "Value": "Windows 11 Version 26H1 for x64-based Systems"},
                {"ProductID": "server", "Value": "Windows Server 2025"},
            ]
        },
        "Vulnerability": [
            {
                "Title": {"Value": "Test Elevation of Privilege Vulnerability"},
                "Notes": [{"Type": 2, "Value": "<p>A Windows component flaw.</p>"}],
                "CVE": "CVE-2026-30001",
                "ProductStatuses": [{"Type": 3, "ProductID": ["w11"]}],
                "Threats": [
                    {
                        "Type": 1,
                        "Description": {
                            "Value": (
                                "Publicly Disclosed:No;Exploited:Yes;"
                                "Latest Software Release:Likely"
                            )
                        },
                    }
                ],
                "CVSSScoreSets": [{"BaseScore": 9.1, "ProductID": ["w11"]}],
                "RevisionHistory": [{"Date": "2026-08-12T10:00:00Z"}],
            },
            {
                "Title": {"Value": "Server-only vulnerability"},
                "Notes": [{"Type": 2, "Value": "Server issue."}],
                "CVE": "CVE-2026-30002",
                "ProductStatuses": [{"Type": 3, "ProductID": ["server"]}],
                "Threats": [],
                "CVSSScoreSets": [{"BaseScore": 7.5}],
                "RevisionHistory": [],
            },
        ],
    }


UBUNTU_RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Ubuntu Security Notices</title>
<item><title>USN-9000-1: Linux kernel vulnerabilities</title>
<link>https://ubuntu.com/security/notices/USN-9000-1</link>
<pubDate>Thu, 20 Aug 2026 23:47:34 +0000</pubDate>
<description>Kernel issues CVE-2026-40001 and CVE-2026-40002 were fixed.</description></item>
<item><title>USN-8999-1: Example server package</title>
<link>https://ubuntu.com/security/notices/USN-8999-1</link>
<pubDate>Wed, 19 Aug 2026 10:00:00 +0000</pubDate>
<description>A server package issue was fixed.</description></item>
</channel></rss>"""


APPLE_HTML = b"""<!doctype html><html><body><h2>Apple security updates</h2>
<table><tr><th>Name and information link</th><th>Available for</th><th>Release date</th></tr>
<tr><td><a href="https://support.apple.com/en-us/148281">macOS Tahoe 26.6.2</a></td>
<td>macOS Tahoe</td><td>17 Aug 2026</td></tr>
<tr><td><a href="https://support.apple.com/en-us/148282">iOS 26.6.1</a></td>
<td>iPhone</td><td>17 Aug 2026</td></tr></table></body></html>"""


class DesktopIntelligenceParserTests(unittest.TestCase):
    def test_cisa_filters_non_desktop_and_records_known_exploitation(self) -> None:
        result = parse_cisa_kev(_artifact("cisa-kev", CISA_KEV_URL, _cisa_document()))
        self.assertEqual(1, len(result.advisories))
        advisory = result.advisories[0]
        self.assertEqual("cisa-kev:cve-2026-12345", advisory["id"])
        self.assertTrue(advisory["exploited"])
        self.assertIn("windows", advisory["platforms"])
        validate_catalog(build_catalog([result]))

    def test_cisa_count_mismatch_fails_closed(self) -> None:
        document = _cisa_document()
        document["count"] = 99
        with self.assertRaisesRegex(IntelligenceError, "count"):
            parse_cisa_kev(_artifact("cisa-kev", CISA_KEV_URL, document))

    def test_microsoft_selects_desktop_products_and_cvss(self) -> None:
        index = _artifact("microsoft-msrc", MSRC_UPDATES_URL, _msrc_index())
        document = _artifact(
            "microsoft-msrc",
            MSRC_CVRF_PREFIX + "2026-Aug",
            _msrc_document(),
        )
        result = parse_microsoft_msrc(index, document, "2026-Aug")
        self.assertEqual(1, len(result.advisories))
        advisory = result.advisories[0]
        self.assertEqual("critical", advisory["severity"])
        self.assertTrue(advisory["exploited"])
        self.assertEqual(["CVE-2026-30001"], advisory["cve_ids"])
        validate_catalog(build_catalog([result]))

    def test_ubuntu_rss_rejects_entities_and_filters_server_only_item(self) -> None:
        result = parse_ubuntu_usn(_artifact("ubuntu-usn", UBUNTU_USN_URL, UBUNTU_RSS))
        self.assertEqual(1, len(result.advisories))
        self.assertEqual(
            ["CVE-2026-40001", "CVE-2026-40002"],
            result.advisories[0]["cve_ids"],
        )
        malicious = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///x">]><rss />'
        with self.assertRaisesRegex(IntelligenceError, "entities"):
            parse_ubuntu_usn(_artifact("ubuntu-usn", UBUNTU_USN_URL, malicious))

    def test_apple_ingests_only_reviewable_desktop_rows(self) -> None:
        result = parse_apple_security(
            _artifact(
                "apple-security",
                APPLE_SECURITY_URL,
                APPLE_HTML,
                last_modified="Mon, 17 Aug 2026 21:16:26 GMT",
            )
        )
        self.assertEqual(1, len(result.advisories))
        self.assertEqual("apple-security:148281", result.advisories[0]["id"])
        self.assertEqual(["macos"], result.advisories[0]["platforms"])

    def test_catalog_is_deterministic_and_rejects_command_fields(self) -> None:
        result = parse_cisa_kev(_artifact("cisa-kev", CISA_KEV_URL, _cisa_document()))
        first = catalog_bytes(build_catalog([result]))
        second = catalog_bytes(build_catalog([result]))
        self.assertEqual(first, second)
        catalog = json.loads(first)
        catalog["commands"] = ["do-not-run"]
        with self.assertRaisesRegex(IntelligenceError, "unexpected=commands"):
            validate_catalog(catalog)

    def test_zba_commitment_is_typed_provenance_not_a_detection_claim(self) -> None:
        result = parse_cisa_kev(_artifact("cisa-kev", CISA_KEV_URL, _cisa_document()))
        catalog = build_catalog([result])
        advisory = catalog["advisories"][0]
        self.assertEqual("observed", advisory["zba"]["phase"])
        self.assertEqual("authoritative-advisory", advisory["zba"]["evidence"])
        advisory["title"] = "tampered"
        with self.assertRaisesRegex(IntelligenceError, "ZBA commitment mismatch"):
            validate_catalog(catalog)


class DesktopIntelligenceInstallTests(unittest.TestCase):
    def test_install_update_backup_and_rollback_protection(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "catalog.json"
            state = root / "state.json"
            backups = root / "backups"
            first_result = parse_cisa_kev(
                _artifact(
                    "cisa-kev",
                    CISA_KEV_URL,
                    _cisa_document(released="2026-08-20T12:00:00Z"),
                )
            )
            first = install_catalog(
                build_catalog([first_result]),
                output,
                state,
                backups,
                now=datetime(2026, 8, 20, 13, tzinfo=UTC),
            )
            self.assertEqual("installed", first.outcome)
            old_bytes = output.read_bytes()
            newer_result = parse_cisa_kev(
                _artifact(
                    "cisa-kev",
                    CISA_KEV_URL,
                    _cisa_document(
                        released="2026-08-21T12:00:00Z",
                        name="Revised Microsoft Windows Test Vulnerability",
                    ),
                )
            )
            updated = install_catalog(
                build_catalog([newer_result]),
                output,
                state,
                backups,
                now=datetime(2026, 8, 21, 13, tzinfo=UTC),
            )
            self.assertEqual("updated", updated.outcome)
            backup_catalog = backups / first.catalog_sha256 / output.name
            self.assertEqual(old_bytes, backup_catalog.read_bytes())

            older_result = parse_cisa_kev(
                _artifact(
                    "cisa-kev",
                    CISA_KEV_URL,
                    _cisa_document(released="2026-08-19T12:00:00Z"),
                )
            )
            with self.assertRaisesRegex(IntelligenceError, "rollback"):
                install_catalog(build_catalog([older_result]), output, state, backups)

    def test_same_version_changed_content_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "catalog.json"
            state = root / "state.json"
            backups = root / "backups"
            base = parse_cisa_kev(
                _artifact("cisa-kev", CISA_KEV_URL, _cisa_document(name="First title"))
            )
            install_catalog(build_catalog([base]), output, state, backups)
            changed = parse_cisa_kev(
                _artifact("cisa-kev", CISA_KEV_URL, _cisa_document(name="Changed title"))
            )
            with self.assertRaisesRegex(IntelligenceError, "version reuse"):
                install_catalog(build_catalog([changed]), output, state, backups)

    def test_dry_run_writes_no_catalog_state_cache_or_backup(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _artifact("cisa-kev", CISA_KEV_URL, _cisa_document())

            def fetch(source_id: str, url: str, cache_key: str) -> SourceArtifact:
                self.assertEqual(
                    ("cisa-kev", CISA_KEV_URL, "cisa-kev"),
                    (source_id, url, cache_key),
                )
                return fixture

            result = update_desktop_intelligence(
                output_path=root / "catalog.json",
                state_path=root / "state.json",
                cache_dir=root / "cache",
                backup_dir=root / "backups",
                source_ids=["cisa-kev"],
                dry_run=True,
                fetcher=fetch,
            )
            self.assertTrue(result.dry_run)
            self.assertEqual([], list(root.iterdir()))

    def test_offline_fetcher_requires_valid_cache_and_url_allowlist(self) -> None:
        with TemporaryDirectory() as temporary:
            fetcher = HTTPSourceFetcher(Path(temporary), offline=True)
            with self.assertRaisesRegex(IntelligenceError, "not allowlisted"):
                fetcher("cisa-kev", "https://example.com/feed.json", "bad-url")
            with self.assertRaisesRegex(IntelligenceError, "cache is missing"):
                fetcher("cisa-kev", CISA_KEV_URL, "cisa-kev")

    def test_collect_catalog_fetches_latest_microsoft_document(self) -> None:
        index = _artifact("microsoft-msrc", MSRC_UPDATES_URL, _msrc_index())
        document = _artifact(
            "microsoft-msrc",
            MSRC_CVRF_PREFIX + "2026-Aug",
            _msrc_document(),
        )
        seen: list[tuple[str, str, str]] = []

        def fetch(source_id: str, url: str, cache_key: str) -> SourceArtifact:
            seen.append((source_id, url, cache_key))
            return index if url == MSRC_UPDATES_URL else document

        catalog = collect_catalog(
            fetch,
            ["microsoft-msrc"],
            now=datetime(2026, 8, 21, tzinfo=UTC),
        )
        self.assertEqual(1, len(catalog["advisories"]))
        self.assertEqual(MSRC_CVRF_PREFIX + "2026-Aug", seen[1][1])


if __name__ == "__main__":
    unittest.main()
