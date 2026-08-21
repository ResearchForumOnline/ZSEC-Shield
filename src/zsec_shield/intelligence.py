"""Deterministic, data-only desktop security advisory intelligence.

This module deliberately does not create scanner rules, download samples, run
commands, or apply remediations.  It converts a small allowlist of authoritative
public sources into a strict advisory catalog for human review and higher-level
policy decisions.
"""

from __future__ import annotations

import contextlib
import email.utils
import hashlib
import html
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Protocol

from zsec_shield.errors import FeedError
from zsec_shield.util import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    format_utc,
    strict_json_loads,
    update_lock,
    utc_now,
)

CATALOG_SCHEMA = "zsec.desktop-intelligence.v1"
STATE_SCHEMA = "zsec.desktop-intelligence-state.v1"
ZBA_INTELLIGENCE_SPEC = "zsec.zba.intelligence.v1"
ZBA_DOMAIN = b"ZSEC/ZBA/DESKTOP-INTELLIGENCE/V1\x00"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_ADVISORIES = 4096
MAX_TEXT = 700
SOURCE_IDS = ("cisa-kev", "microsoft-msrc", "ubuntu-usn", "apple-security")
PLATFORMS = frozenset({"windows", "macos", "linux", "browser", "cross-platform"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.ASCII)
MSRC_DOCUMENT_PATTERN = re.compile(r"^[0-9]{4}-[A-Z][a-z]{2}$", re.ASCII)
USN_PATTERN = re.compile(r"^USN-[0-9]+-[0-9]+", re.ASCII)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_CVRF_PREFIX = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"
UBUNTU_USN_URL = "https://ubuntu.com/security/notices/rss.xml"
APPLE_SECURITY_URL = "https://support.apple.com/en-us/100100"


class IntelligenceError(FeedError):
    """An advisory source, catalog, cache, or rollback check failed closed."""


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    source_id: str
    url: str
    raw: bytes
    body_sha256: str
    etag: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True, slots=True)
class SourceResult:
    source: dict[str, Any]
    advisories: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class UpdateResult:
    outcome: str
    catalog: dict[str, Any]
    catalog_sha256: str
    output_path: str
    state_path: str
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "catalog_sha256": self.catalog_sha256,
            "advisories": len(self.catalog["advisories"]),
            "sources": [source["source_id"] for source in self.catalog["sources"]],
            "generated_at": self.catalog["generated_at"],
            "output_path": self.output_path,
            "state_path": self.state_path,
            "dry_run": self.dry_run,
            "safety": self.catalog["policy"],
        }


class Fetcher(Protocol):
    def __call__(self, source_id: str, url: str, cache_key: str) -> SourceArtifact: ...


def _exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    present = set(value)
    if present != expected:
        missing = sorted(expected - present)
        unexpected = sorted(present - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unexpected:
            details.append(f"unexpected={','.join(unexpected)}")
        raise IntelligenceError(f"invalid {context} fields ({'; '.join(details)})")


def _text(value: Any, field: str, minimum: int = 1, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise IntelligenceError(f"{field} must be a string")
    normalized = " ".join(value.replace("\x00", " ").split())
    if not minimum <= len(normalized) <= maximum:
        raise IntelligenceError(
            f"{field} must contain {minimum}..{maximum} normalized characters"
        )
    if any(ord(character) < 32 for character in normalized):
        raise IntelligenceError(f"{field} contains a control character")
    return normalized


def _truncate_text(value: str, maximum: int = MAX_TEXT) -> str:
    normalized = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", value)).split())
    if len(normalized) <= maximum:
        return normalized
    return normalized[: maximum - 1].rstrip() + "…"


def _parse_time(value: Any, field: str) -> datetime:
    text = _text(value, field, 8, 80)
    parsed: datetime | None = None
    try:
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
            parsed = datetime.fromisoformat(text).replace(tzinfo=UTC)
        else:
            candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
            parsed = datetime.fromisoformat(candidate)
    except ValueError:
        with contextlib.suppress(TypeError, ValueError, OverflowError):
            parsed = email.utils.parsedate_to_datetime(text)
    if parsed is None:
        with contextlib.suppress(ValueError):
            parsed = datetime.strptime(text, "%d %b %Y").replace(tzinfo=UTC)
    if parsed is None:
        raise IntelligenceError(f"{field} is not a supported timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _time(value: Any, field: str) -> str:
    return format_utc(_parse_time(value, field))


def _https_url(value: Any, field: str, hosts: set[str] | None = None) -> str:
    text = _text(value, field, 12, 1000)
    parsed = urllib.parse.urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise IntelligenceError(f"{field} must be a credential-free HTTPS URL")
    if hosts is not None and parsed.hostname.lower() not in hosts:
        raise IntelligenceError(f"{field} uses a host outside its source allowlist")
    return text


def _source_url_allowed(source_id: str, url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        return False
    normalized = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc.lower(), parsed.path, "", "")
    )
    if source_id == "cisa-kev":
        return normalized == CISA_KEV_URL
    if source_id == "ubuntu-usn":
        return normalized == UBUNTU_USN_URL
    if source_id == "apple-security":
        return normalized == APPLE_SECURITY_URL
    if source_id == "microsoft-msrc":
        if normalized == MSRC_UPDATES_URL:
            return True
        if normalized.startswith(MSRC_CVRF_PREFIX):
            document_id = normalized.removeprefix(MSRC_CVRF_PREFIX)
            return bool(MSRC_DOCUMENT_PATTERN.fullmatch(document_id))
    return False


def _load_json(raw: bytes, source: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise IntelligenceError(f"{source} source size is outside the accepted range")
    try:
        value = strict_json_loads(raw)
    except FeedError as exc:
        raise IntelligenceError(f"{source} returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise IntelligenceError(f"{source} root must be an object")
    return value


def _platforms_for_text(value: str) -> tuple[str, ...]:
    lowered = value.casefold()
    result: set[str] = set()
    if re.search(r"\bwindows(?:\s+(?:10|11))?\b|\bwin32\b|\bwinrar\b", lowered):
        result.add("windows")
    if re.search(r"\bmacos\b|\bmac os\b|\bos x\b|\bsafari\b|\bapple xcode\b", lowered):
        result.add("macos")
    if re.search(
        r"\blinux\b|\bubuntu\b|\bdebian\b|\bfedora\b|\bred hat\b|\bglibc\b",
        lowered,
    ):
        result.add("linux")
    if re.search(
        r"\bchrom(?:e|ium)\b|\bfirefox\b|\bedge\b|\bsafari\b|\bthunderbird\b",
        lowered,
    ):
        result.add("browser")
    if re.search(r"\badobe (?:acrobat|reader)\b|\b7-zip\b|\blibreoffice\b", lowered):
        result.add("cross-platform")
    return tuple(sorted(result))


def _advisory(
    *,
    advisory_id: str,
    source_id: str,
    source_url: str,
    record_url: str,
    record_id: str,
    title: str,
    summary: str,
    published_at: str,
    modified_at: str,
    platforms: Iterable[str],
    cve_ids: Iterable[str],
    severity: str,
    exploited: bool | None,
    ransomware: bool | None,
    action: str,
    products: Iterable[str],
    source_body_sha256: str,
    parser: str,
) -> dict[str, Any]:
    normalized_platforms = sorted(set(platforms))
    normalized_cves = sorted(set(cve_ids))
    normalized_products = sorted({_text(item, "product", 1, 300) for item in products})[:32]
    projection: dict[str, Any] = {
        "id": _text(advisory_id, "advisory id", 3, 160),
        "source_id": _text(source_id, "source id", 3, 64),
        "source_url": _https_url(source_url, "source_url"),
        "record_url": _https_url(record_url, "record_url"),
        "title": _text(_truncate_text(title, 300), "title", 1, 300),
        "summary": _text(_truncate_text(summary), "summary"),
        "published_at": _time(published_at, "published_at"),
        "modified_at": _time(modified_at, "modified_at"),
        "platforms": normalized_platforms,
        "cve_ids": normalized_cves,
        "severity": severity,
        "exploited": exploited,
        "ransomware": ransomware,
        "action": _text(_truncate_text(action, 500), "action", 1, 500),
        "products": normalized_products,
        "provenance": {
            "source_body_sha256": source_body_sha256,
            "source_record_id": _text(record_id, "source record id", 1, 160),
            "parser": _text(parser, "parser", 3, 80),
        },
    }
    commitment = hashlib.sha256(ZBA_DOMAIN + canonical_json_bytes(projection)).hexdigest()
    return {
        **projection,
        "zba": {
            "spec": ZBA_INTELLIGENCE_SPEC,
            "phase": "observed",
            "evidence": "authoritative-advisory",
            "commitment": commitment,
        },
    }


def _source_summary(
    *,
    source_id: str,
    authority: str,
    url: str,
    version: str,
    body_sha256: str,
    advisories: Iterable[dict[str, Any]],
    parser: str,
) -> dict[str, Any]:
    records = list(advisories)
    contribution = hashlib.sha256(canonical_json_bytes(records)).hexdigest()
    semantic_records: list[dict[str, Any]] = []
    for record in records:
        semantic = {key: value for key, value in record.items() if key not in {"provenance", "zba"}}
        provenance = record["provenance"]
        semantic["provenance"] = {
            "source_record_id": provenance["source_record_id"],
            "parser": provenance["parser"],
        }
        semantic_records.append(semantic)
    semantic_digest = hashlib.sha256(canonical_json_bytes(semantic_records)).hexdigest()
    return {
        "source_id": source_id,
        "authority": authority,
        "url": url,
        "version": _time(version, f"{source_id} version"),
        "body_sha256": body_sha256,
        "contribution_sha256": contribution,
        "semantic_sha256": semantic_digest,
        "advisory_count": len(records),
        "parser": parser,
    }


def parse_cisa_kev(artifact: SourceArtifact) -> SourceResult:
    root = _load_json(artifact.raw, "CISA KEV")
    required = {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"}
    if not required.issubset(root):
        raise IntelligenceError("CISA KEV is missing required catalog fields")
    version = _time(root["dateReleased"], "CISA dateReleased")
    records = root["vulnerabilities"]
    count = root["count"]
    if isinstance(count, bool) or not isinstance(count, int) or not isinstance(records, list):
        raise IntelligenceError("CISA KEV count or vulnerabilities field is invalid")
    if count != len(records) or count < 1 or count > 100_000:
        raise IntelligenceError("CISA KEV count does not match its vulnerability array")

    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()
    required_record = {
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "knownRansomwareCampaignUse",
    }
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not required_record.issubset(record):
            raise IntelligenceError(f"CISA KEV record {index} is missing required fields")
        cve = _text(record["cveID"], f"CISA record {index} CVE", 13, 32).upper()
        if not CVE_PATTERN.fullmatch(cve) or cve in seen:
            raise IntelligenceError(f"CISA KEV record {index} has an invalid or duplicate CVE")
        seen.add(cve)
        vendor = _text(record["vendorProject"], f"CISA record {index} vendor", 1, 200)
        product = _text(record["product"], f"CISA record {index} product", 1, 200)
        title = _text(record["vulnerabilityName"], f"CISA record {index} title", 1, 300)
        summary = _text(
            _truncate_text(str(record["shortDescription"])),
            f"CISA record {index} description",
        )
        platforms = _platforms_for_text(f"{vendor} {product} {title} {summary}")
        if not platforms:
            continue
        ransomware_value = _text(
            record["knownRansomwareCampaignUse"],
            f"CISA record {index} ransomware field",
            2,
            32,
        ).casefold()
        if ransomware_value not in {"known", "unknown"}:
            raise IntelligenceError(f"CISA record {index} has an unknown ransomware value")
        ransomware = True if ransomware_value == "known" else None
        severity = "critical" if ransomware else "high"
        published = _time(record["dateAdded"], f"CISA record {index} dateAdded")
        advisories.append(
            _advisory(
                advisory_id=f"cisa-kev:{cve.casefold()}",
                source_id=artifact.source_id,
                source_url=artifact.url,
                record_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                record_id=cve,
                title=title,
                summary=summary,
                published_at=published,
                modified_at=published,
                platforms=platforms,
                cve_ids=[cve],
                severity=severity,
                exploited=True,
                ransomware=ransomware,
                action=str(record["requiredAction"]),
                products=[f"{vendor} {product}"],
                source_body_sha256=artifact.body_sha256,
                parser="cisa-kev-json-v1",
            )
        )
    advisories.sort(key=lambda item: item["id"])
    source = _source_summary(
        source_id=artifact.source_id,
        authority="Cybersecurity and Infrastructure Security Agency",
        url=artifact.url,
        version=version,
        body_sha256=artifact.body_sha256,
        advisories=advisories,
        parser="cisa-kev-json-v1",
    )
    return SourceResult(source, tuple(advisories))


def _latest_msrc_document(index_artifact: SourceArtifact, now: datetime) -> tuple[str, str]:
    root = _load_json(index_artifact.raw, "Microsoft MSRC update index")
    records = root.get("value")
    if not isinstance(records, list) or not records or len(records) > 10_000:
        raise IntelligenceError("Microsoft MSRC update index has an invalid value array")
    candidates: list[tuple[datetime, str, str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise IntelligenceError(f"Microsoft update index record {index} is not an object")
        for field in ("ID", "InitialReleaseDate", "CvrfUrl"):
            if field not in record:
                raise IntelligenceError(f"Microsoft update index record {index} lacks {field}")
        raw_document_id = record["ID"]
        if not isinstance(raw_document_id, str):
            raise IntelligenceError(f"Microsoft update index record {index} ID is invalid")
        document_id = " ".join(raw_document_id.split())
        if not MSRC_DOCUMENT_PATTERN.fullmatch(document_id):
            continue
        initial = _parse_time(record["InitialReleaseDate"], "Microsoft InitialReleaseDate")
        if initial > now:
            continue
        url = _https_url(
            record["CvrfUrl"],
            "Microsoft CvrfUrl",
            {"api.msrc.microsoft.com"},
        )
        expected = MSRC_CVRF_PREFIX + document_id
        if url != expected:
            raise IntelligenceError("Microsoft CVRF URL does not match its document ID")
        candidates.append((initial, document_id, url))
    if not candidates:
        raise IntelligenceError("Microsoft update index contains no usable monthly document")
    _initial, document_id, url = max(candidates)
    return document_id, url


def _msrc_value(value: Any) -> str | None:
    if isinstance(value, dict) and isinstance(value.get("Value"), str):
        return str(value["Value"])
    return None


def parse_microsoft_msrc(
    index_artifact: SourceArtifact,
    document_artifact: SourceArtifact,
    document_id: str,
) -> SourceResult:
    root = _load_json(document_artifact.raw, "Microsoft MSRC CVRF")
    tracking = root.get("DocumentTracking")
    tree = root.get("ProductTree")
    vulnerabilities = root.get("Vulnerability")
    if not isinstance(tracking, dict) or not isinstance(tree, dict):
        raise IntelligenceError("Microsoft CVRF tracking or product tree is invalid")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 20_000:
        raise IntelligenceError("Microsoft CVRF vulnerability array is invalid")
    identification = tracking.get("Identification")
    tracked_id = None
    if isinstance(identification, dict):
        tracked_id = _msrc_value(identification.get("ID"))
    if tracked_id != document_id:
        raise IntelligenceError("Microsoft CVRF document identity mismatch")
    version = _time(tracking.get("CurrentReleaseDate"), "Microsoft CurrentReleaseDate")
    initial_release = _time(tracking.get("InitialReleaseDate"), "Microsoft InitialReleaseDate")
    names = tree.get("FullProductName")
    if not isinstance(names, list) or not names or len(names) > 50_000:
        raise IntelligenceError("Microsoft CVRF product list is invalid")
    products: dict[str, str] = {}
    for index, record in enumerate(names):
        if not isinstance(record, dict):
            raise IntelligenceError(f"Microsoft product record {index} is invalid")
        product_id = _text(record.get("ProductID"), f"Microsoft product {index} ID", 1, 80)
        product_name = _text(record.get("Value"), f"Microsoft product {index} name", 1, 300)
        if product_id in products:
            raise IntelligenceError(f"Microsoft product ID is duplicated: {product_id}")
        products[product_id] = product_name

    combined_body_digest = hashlib.sha256(
        b"MSRC-INDEX\x00"
        + bytes.fromhex(index_artifact.body_sha256)
        + b"MSRC-CVRF\x00"
        + bytes.fromhex(document_artifact.body_sha256)
    ).hexdigest()
    advisories: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(vulnerabilities):
        if not isinstance(record, dict):
            raise IntelligenceError(f"Microsoft vulnerability {index} is invalid")
        cve = _text(record.get("CVE"), f"Microsoft vulnerability {index} CVE", 13, 32).upper()
        if not CVE_PATTERN.fullmatch(cve) or cve in seen:
            raise IntelligenceError(f"Microsoft vulnerability {index} has invalid/duplicate CVE")
        seen.add(cve)
        statuses = record.get("ProductStatuses")
        if not isinstance(statuses, list):
            raise IntelligenceError(f"Microsoft vulnerability {cve} product status is invalid")
        affected_ids: set[str] = set()
        for status in statuses:
            if not isinstance(status, dict) or not isinstance(status.get("ProductID"), list):
                raise IntelligenceError(f"Microsoft vulnerability {cve} has invalid products")
            for product_id in status["ProductID"]:
                if not isinstance(product_id, str) or product_id not in products:
                    raise IntelligenceError(f"Microsoft vulnerability {cve} uses unknown product")
                affected_ids.add(product_id)
        affected_names = sorted({products[product_id] for product_id in affected_ids})
        desktop_products = [
            name
            for name in affected_names
            if re.search(
                r"^(?:Windows (?:10|11)|Microsoft Edge|Microsoft Defender|"
                r"Microsoft Office|Office for Mac)|\.NET Framework .* Windows (?:10|11)",
                name,
                re.IGNORECASE,
            )
            and "server" not in name.casefold()
            and "online" not in name.casefold()
        ]
        if not desktop_products:
            continue
        product_text = " ".join(desktop_products)
        platform_set = set(_platforms_for_text(product_text))
        lowered_products = product_text.casefold()
        if " for mac" in lowered_products or "defender for endpoint for mac" in lowered_products:
            platform_set.add("macos")
        if (
            "windows 10" in lowered_products
            or "windows 11" in lowered_products
            or "microsoft office" in lowered_products
            or "microsoft edge" in lowered_products
        ):
            platform_set.add("windows")
        if "microsoft edge" in lowered_products:
            platform_set.add("browser")
        platforms = tuple(sorted(platform_set))
        title_value = _msrc_value(record.get("Title")) or cve
        notes = record.get("Notes")
        description = title_value
        if isinstance(notes, list):
            for note in notes:
                if isinstance(note, dict) and note.get("Type") == 2:
                    note_value = note.get("Value")
                    if isinstance(note_value, str) and note_value.strip():
                        description = note_value
                        break
        scores = record.get("CVSSScoreSets")
        maximum_score = 0.0
        if isinstance(scores, list):
            for score in scores:
                if isinstance(score, dict):
                    value = score.get("BaseScore")
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        maximum_score = max(maximum_score, float(value))
        if maximum_score >= 9.0:
            severity = "critical"
        elif maximum_score >= 7.0:
            severity = "high"
        elif maximum_score >= 4.0:
            severity = "medium"
        elif maximum_score > 0:
            severity = "low"
        else:
            severity = "unknown"
        exploited: bool | None = None
        threats = record.get("Threats")
        if isinstance(threats, list):
            for threat in threats:
                if not isinstance(threat, dict) or threat.get("Type") != 1:
                    continue
                value = _msrc_value(threat.get("Description"))
                if not value:
                    continue
                match = re.search(r"(?:^|;)Exploited:(Yes|No)(?:;|$)", value, re.I)
                if match:
                    exploited = match.group(1).casefold() == "yes"
                    break
        revisions = record.get("RevisionHistory")
        modified = initial_release
        if isinstance(revisions, list):
            dates = [
                _time(revision["Date"], f"Microsoft {cve} revision date")
                for revision in revisions
                if isinstance(revision, dict) and "Date" in revision
            ]
            if dates:
                modified = max(dates)
        advisories.append(
            _advisory(
                advisory_id=f"microsoft-msrc:{cve.casefold()}",
                source_id=document_artifact.source_id,
                source_url=index_artifact.url,
                record_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                record_id=cve,
                title=f"{cve}: {title_value}",
                summary=description,
                published_at=initial_release,
                modified_at=modified,
                platforms=platforms,
                cve_ids=[cve],
                severity=severity,
                exploited=exploited,
                ransomware=None,
                action="Install the applicable Microsoft security update after asset review.",
                products=desktop_products,
                source_body_sha256=combined_body_digest,
                parser="microsoft-cvrf-v3-desktop-v1",
            )
        )
    advisories.sort(key=lambda item: item["id"])
    source = _source_summary(
        source_id=document_artifact.source_id,
        authority="Microsoft Security Response Center",
        url=index_artifact.url,
        version=version,
        body_sha256=combined_body_digest,
        advisories=advisories,
        parser="microsoft-cvrf-v3-desktop-v1",
    )
    return SourceResult(source, tuple(advisories))


def parse_ubuntu_usn(artifact: SourceArtifact) -> SourceResult:
    if not artifact.raw or len(artifact.raw) > MAX_SOURCE_BYTES:
        raise IntelligenceError("Ubuntu USN source size is outside the accepted range")
    upper = artifact.raw[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise IntelligenceError("Ubuntu USN XML declarations/entities are not allowed")
    try:
        root = ET.fromstring(artifact.raw)
    except ET.ParseError as exc:
        raise IntelligenceError(f"Ubuntu USN RSS is invalid XML: {exc}") from exc
    if root.tag != "rss":
        raise IntelligenceError("Ubuntu USN source is not an RSS document")
    channel = root.find("channel")
    if channel is None:
        raise IntelligenceError("Ubuntu USN RSS channel is missing")
    items = channel.findall("item")
    if not items or len(items) > 512:
        raise IntelligenceError("Ubuntu USN RSS item count is outside the accepted range")
    advisories: list[dict[str, Any]] = []
    versions: list[str] = []
    seen: set[str] = set()
    desktop_terms = re.compile(
        r"kernel|firefox|chromium|thunderbird|libreoffice|gnome|kde|xorg|wayland|"
        r"sudo|systemd|cups|networkmanager|openssh|bluez|mesa|graphics|desktop",
        re.IGNORECASE,
    )
    for index, item in enumerate(items):
        title = item.findtext("title")
        link = item.findtext("link")
        published_text = item.findtext("pubDate")
        description = item.findtext("description")
        values = (title, link, published_text, description)
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise IntelligenceError(f"Ubuntu USN item {index} is missing required text")
        assert title is not None
        assert link is not None
        assert published_text is not None
        assert description is not None
        match = USN_PATTERN.match(title.strip())
        if match is None or match.group(0) in seen:
            raise IntelligenceError(f"Ubuntu USN item {index} has invalid/duplicate identity")
        usn_id = match.group(0)
        seen.add(usn_id)
        published = _time(published_text, f"Ubuntu USN item {index} pubDate")
        versions.append(published)
        if not desktop_terms.search(f"{title} {description}"):
            continue
        record_url = _https_url(link, f"Ubuntu USN item {index} link", {"ubuntu.com"})
        if record_url != f"https://ubuntu.com/security/notices/{usn_id}":
            raise IntelligenceError(f"Ubuntu USN item {index} link does not match its ID")
        cves = sorted(set(re.findall(r"CVE-[0-9]{4}-[0-9]{4,}", description, re.I)))
        cves = [cve.upper() for cve in cves]
        advisories.append(
            _advisory(
                advisory_id=f"ubuntu-usn:{usn_id.casefold()}",
                source_id=artifact.source_id,
                source_url=artifact.url,
                record_url=record_url,
                record_id=usn_id,
                title=title,
                summary=description,
                published_at=published,
                modified_at=published,
                platforms=["linux"],
                cve_ids=cves[:256],
                severity="unknown",
                exploited=None,
                ransomware=None,
                action="Apply the Ubuntu security update for each applicable installed package.",
                products=[title.split(":", 1)[-1].strip()],
                source_body_sha256=artifact.body_sha256,
                parser="ubuntu-usn-rss-v1",
            )
        )
    advisories.sort(key=lambda item: item["id"])
    source = _source_summary(
        source_id=artifact.source_id,
        authority="Canonical Ubuntu Security Team",
        url=artifact.url,
        version=max(versions),
        body_sha256=artifact.body_sha256,
        advisories=advisories,
        parser="ubuntu-usn-rss-v1",
    )
    return SourceResult(source, tuple(advisories))


class _AppleTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[tuple[str, str | None]]] = []
        self._row: list[tuple[str, str | None]] | None = None
        self._cell_parts: list[str] | None = None
        self._cell_link: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell_parts = []
            self._cell_link = None
        elif tag == "a" and self._cell_parts is not None:
            href = dict(attrs).get("href")
            if href:
                self._cell_link = href

    def handle_data(self, data: str) -> None:
        if self._cell_parts is not None:
            self._cell_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._row is not None and self._cell_parts is not None:
            self._row.append((" ".join("".join(self._cell_parts).split()), self._cell_link))
            self._cell_parts = None
            self._cell_link = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None


def parse_apple_security(artifact: SourceArtifact) -> SourceResult:
    if not artifact.raw or len(artifact.raw) > MAX_SOURCE_BYTES:
        raise IntelligenceError("Apple security source size is outside the accepted range")
    try:
        content = artifact.raw.decode("utf-8-sig", "strict")
    except UnicodeDecodeError as exc:
        raise IntelligenceError("Apple security page must be UTF-8") from exc
    if "Apple security updates" not in content:
        raise IntelligenceError("Apple security table marker is missing")
    parser = _AppleTableParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception as exc:
        raise IntelligenceError(f"Apple security HTML is malformed: {exc}") from exc
    advisories: list[dict[str, Any]] = []
    versions: list[str] = []
    seen: set[str] = set()
    desktop = re.compile(r"\bmacOS\b|\bSafari\b|\bXcode\b|\bGarageBand\b", re.I)
    for row_index, row in enumerate(parser.rows):
        if len(row) != 3:
            continue
        (name, link), (available_for, _), (date_text, _) = row
        if not desktop.search(f"{name} {available_for}"):
            continue
        try:
            published = _time(date_text, f"Apple row {row_index} release date")
        except IntelligenceError:
            continue
        versions.append(published)
        if link is None:
            # Apple occasionally lists an update before publishing its advisory.
            # Without a record URL there is no reviewable evidence object to ingest.
            continue
        record_url = _https_url(link, f"Apple row {row_index} link", {"support.apple.com"})
        path = urllib.parse.urlsplit(record_url).path.rstrip("/")
        article_id = path.rsplit("/", 1)[-1]
        if not article_id.isdigit() or article_id in seen:
            raise IntelligenceError(f"Apple row {row_index} has invalid/duplicate article ID")
        seen.add(article_id)
        advisories.append(
            _advisory(
                advisory_id=f"apple-security:{article_id}",
                source_id=artifact.source_id,
                source_url=artifact.url,
                record_url=record_url,
                record_id=article_id,
                title=name,
                summary=f"Apple security release for {available_for}.",
                published_at=published,
                modified_at=published,
                platforms=["macos"] + (["browser"] if "safari" in name.casefold() else []),
                cve_ids=[],
                severity="unknown",
                exploited=None,
                ransomware=None,
                action=(
                    "Install the applicable Apple software update through the supported "
                    "update channel."
                ),
                products=[available_for],
                source_body_sha256=artifact.body_sha256,
                parser="apple-security-table-v1",
            )
        )
    if not versions or not advisories:
        raise IntelligenceError("Apple security table yielded no desktop advisories")
    version = max(versions)
    if artifact.last_modified:
        last_modified = _time(artifact.last_modified, "Apple Last-Modified")
        version = max(version, last_modified)
    advisories.sort(key=lambda item: item["id"])
    source = _source_summary(
        source_id=artifact.source_id,
        authority="Apple Product Security",
        url=artifact.url,
        version=version,
        body_sha256=artifact.body_sha256,
        advisories=advisories,
        parser="apple-security-table-v1",
    )
    return SourceResult(source, tuple(advisories))


def build_catalog(results: Iterable[SourceResult]) -> dict[str, Any]:
    normalized = sorted(results, key=lambda result: result.source["source_id"])
    if not normalized:
        raise IntelligenceError("at least one advisory source is required")
    source_ids = [result.source["source_id"] for result in normalized]
    if len(set(source_ids)) != len(source_ids):
        raise IntelligenceError("duplicate advisory source IDs are not allowed")
    advisories = [item for result in normalized for item in result.advisories]
    advisories.sort(
        key=lambda item: (item["published_at"], item["source_id"], item["id"]),
        reverse=True,
    )
    if not advisories or len(advisories) > MAX_ADVISORIES:
        raise IntelligenceError("advisory count is outside the accepted range")
    catalog: dict[str, Any] = {
        "schema": CATALOG_SCHEMA,
        "generated_at": max(result.source["version"] for result in normalized),
        "policy": {
            "data_only": True,
            "remote_commands_allowed": False,
            "auto_remediation_allowed": False,
            "detection_rules_derived": False,
            "malware_samples_allowed": False,
        },
        "sources": [result.source for result in normalized],
        "advisories": advisories,
    }
    validate_catalog(catalog)
    return catalog


def validate_catalog(catalog: Any) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise IntelligenceError("desktop intelligence catalog must be an object")
    _exact_keys(catalog, {"schema", "generated_at", "policy", "sources", "advisories"}, "catalog")
    if catalog["schema"] != CATALOG_SCHEMA:
        raise IntelligenceError("desktop intelligence catalog schema is unsupported")
    generated = _time(catalog["generated_at"], "catalog generated_at")
    policy = catalog["policy"]
    if not isinstance(policy, dict):
        raise IntelligenceError("catalog policy must be an object")
    expected_policy = {
        "data_only": True,
        "remote_commands_allowed": False,
        "auto_remediation_allowed": False,
        "detection_rules_derived": False,
        "malware_samples_allowed": False,
    }
    if policy != expected_policy:
        raise IntelligenceError("catalog policy violates the data-only safety contract")
    sources = catalog["sources"]
    advisories = catalog["advisories"]
    if not isinstance(sources, list) or not sources or len(sources) > len(SOURCE_IDS):
        raise IntelligenceError("catalog sources array is invalid")
    if not isinstance(advisories, list) or not 1 <= len(advisories) <= MAX_ADVISORIES:
        raise IntelligenceError("catalog advisories array is invalid")
    source_map: dict[str, dict[str, Any]] = {}
    source_counts: dict[str, int] = {}
    source_versions: list[str] = []
    source_fields = {
        "source_id",
        "authority",
        "url",
        "version",
        "body_sha256",
        "contribution_sha256",
        "semantic_sha256",
        "advisory_count",
        "parser",
    }
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise IntelligenceError(f"catalog source {index} must be an object")
        _exact_keys(source, source_fields, f"catalog source {index}")
        source_id = _text(source["source_id"], f"source {index} id", 3, 64)
        if source_id not in SOURCE_IDS or source_id in source_map:
            raise IntelligenceError(f"catalog source ID is unsupported/duplicate: {source_id}")
        _text(source["authority"], f"source {source_id} authority", 3, 200)
        url = _https_url(source["url"], f"source {source_id} URL")
        if not _source_url_allowed(source_id, url):
            raise IntelligenceError(f"catalog source URL is not allowlisted: {source_id}")
        version = _time(source["version"], f"source {source_id} version")
        source_versions.append(version)
        for field in ("body_sha256", "contribution_sha256", "semantic_sha256"):
            if not isinstance(source[field], str) or not SHA256_PATTERN.fullmatch(source[field]):
                raise IntelligenceError(f"source {source_id} {field} is invalid")
        count = source["advisory_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise IntelligenceError(f"source {source_id} advisory_count is invalid")
        _text(source["parser"], f"source {source_id} parser", 3, 80)
        source_map[source_id] = source
        source_counts[source_id] = 0
    if generated != max(source_versions):
        raise IntelligenceError("catalog generated_at does not equal the newest source version")

    advisory_fields = {
        "id",
        "source_id",
        "source_url",
        "record_url",
        "title",
        "summary",
        "published_at",
        "modified_at",
        "platforms",
        "cve_ids",
        "severity",
        "exploited",
        "ransomware",
        "action",
        "products",
        "provenance",
        "zba",
    }
    identifiers: set[str] = set()
    contributions: dict[str, list[dict[str, Any]]] = {source_id: [] for source_id in source_map}
    for index, advisory in enumerate(advisories):
        if not isinstance(advisory, dict):
            raise IntelligenceError(f"catalog advisory {index} must be an object")
        _exact_keys(advisory, advisory_fields, f"catalog advisory {index}")
        identifier = _text(advisory["id"], f"advisory {index} id", 3, 160)
        if identifier in identifiers:
            raise IntelligenceError(f"duplicate advisory ID: {identifier}")
        identifiers.add(identifier)
        source_id = _text(advisory["source_id"], f"advisory {identifier} source", 3, 64)
        if source_id not in source_map:
            raise IntelligenceError(f"advisory {identifier} uses an unknown source")
        if advisory["source_url"] != source_map[source_id]["url"]:
            raise IntelligenceError(f"advisory {identifier} source URL mismatch")
        _https_url(advisory["record_url"], f"advisory {identifier} record URL")
        _text(advisory["title"], f"advisory {identifier} title", 1, 300)
        _text(advisory["summary"], f"advisory {identifier} summary")
        published = _parse_time(advisory["published_at"], f"advisory {identifier} published_at")
        modified = _parse_time(advisory["modified_at"], f"advisory {identifier} modified_at")
        if modified < published:
            raise IntelligenceError(f"advisory {identifier} modified_at predates published_at")
        platforms = advisory["platforms"]
        if (
            not isinstance(platforms, list)
            or not platforms
            or platforms != sorted(set(platforms))
            or not set(platforms).issubset(PLATFORMS)
        ):
            raise IntelligenceError(f"advisory {identifier} platforms are invalid")
        cves = advisory["cve_ids"]
        if (
            not isinstance(cves, list)
            or len(cves) > 256
            or cves != sorted(set(cves))
            or any(not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve) for cve in cves)
        ):
            raise IntelligenceError(f"advisory {identifier} CVE list is invalid")
        if advisory["severity"] not in SEVERITIES:
            raise IntelligenceError(f"advisory {identifier} severity is invalid")
        for field in ("exploited", "ransomware"):
            if advisory[field] is not None and not isinstance(advisory[field], bool):
                raise IntelligenceError(f"advisory {identifier} {field} must be boolean/null")
        _text(advisory["action"], f"advisory {identifier} action", 1, 500)
        products = advisory["products"]
        if (
            not isinstance(products, list)
            or not products
            or len(products) > 32
            or products != sorted(set(products))
        ):
            raise IntelligenceError(f"advisory {identifier} products are invalid")
        for product in products:
            _text(product, f"advisory {identifier} product", 1, 300)
        provenance = advisory["provenance"]
        if not isinstance(provenance, dict):
            raise IntelligenceError(f"advisory {identifier} provenance is invalid")
        _exact_keys(
            provenance,
            {"source_body_sha256", "source_record_id", "parser"},
            f"advisory {identifier} provenance",
        )
        if (
            not isinstance(provenance["source_body_sha256"], str)
            or not SHA256_PATTERN.fullmatch(provenance["source_body_sha256"])
            or provenance["source_body_sha256"] != source_map[source_id]["body_sha256"]
        ):
            raise IntelligenceError(f"advisory {identifier} provenance digest is invalid")
        _text(provenance["source_record_id"], f"advisory {identifier} record id", 1, 160)
        _text(provenance["parser"], f"advisory {identifier} parser", 3, 80)
        zba = advisory["zba"]
        if not isinstance(zba, dict):
            raise IntelligenceError(f"advisory {identifier} ZBA record is invalid")
        _exact_keys(zba, {"spec", "phase", "evidence", "commitment"}, f"advisory {identifier} ZBA")
        if (
            zba["spec"] != ZBA_INTELLIGENCE_SPEC
            or zba["phase"] != "observed"
            or zba["evidence"] != "authoritative-advisory"
            or not isinstance(zba["commitment"], str)
            or not SHA256_PATTERN.fullmatch(zba["commitment"])
        ):
            raise IntelligenceError(f"advisory {identifier} ZBA fields are invalid")
        projection = {key: value for key, value in advisory.items() if key != "zba"}
        expected = hashlib.sha256(ZBA_DOMAIN + canonical_json_bytes(projection)).hexdigest()
        if zba["commitment"] != expected:
            raise IntelligenceError(f"advisory {identifier} ZBA commitment mismatch")
        source_counts[source_id] += 1
        contributions[source_id].append(advisory)
    for source_id, source in source_map.items():
        if source_counts[source_id] != source["advisory_count"]:
            raise IntelligenceError(f"source {source_id} advisory count mismatch")
        ordered = sorted(contributions[source_id], key=lambda item: item["id"])
        contribution = hashlib.sha256(canonical_json_bytes(ordered)).hexdigest()
        if contribution != source["contribution_sha256"]:
            raise IntelligenceError(f"source {source_id} contribution digest mismatch")
        semantic_ordered: list[dict[str, Any]] = []
        for advisory in ordered:
            semantic = {
                key: value
                for key, value in advisory.items()
                if key not in {"provenance", "zba"}
            }
            semantic["provenance"] = {
                "source_record_id": advisory["provenance"]["source_record_id"],
                "parser": advisory["provenance"]["parser"],
            }
            semantic_ordered.append(semantic)
        semantic_digest = hashlib.sha256(
            canonical_json_bytes(semantic_ordered)
        ).hexdigest()
        if semantic_digest != source["semantic_sha256"]:
            raise IntelligenceError(f"source {source_id} semantic digest mismatch")
    return catalog


def catalog_bytes(catalog: dict[str, Any]) -> bytes:
    validate_catalog(catalog)
    encoded = (
        json.dumps(catalog, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > MAX_CATALOG_BYTES:
        raise IntelligenceError("desktop intelligence catalog exceeds the size limit")
    return encoded


def _validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntelligenceError("desktop intelligence state must be an object")
    _exact_keys(
        value,
        {"schema", "current_catalog_sha256", "sources", "installed_at"},
        "desktop intelligence state",
    )
    if value["schema"] != STATE_SCHEMA:
        raise IntelligenceError("desktop intelligence state schema is unsupported")
    if (
        not isinstance(value["current_catalog_sha256"], str)
        or not SHA256_PATTERN.fullmatch(value["current_catalog_sha256"])
    ):
        raise IntelligenceError("desktop intelligence state digest is invalid")
    _time(value["installed_at"], "desktop intelligence state installed_at")
    sources = value["sources"]
    if not isinstance(sources, list) or not sources:
        raise IntelligenceError("desktop intelligence state sources are invalid")
    seen: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise IntelligenceError(f"desktop intelligence state source {index} is invalid")
        _exact_keys(
            source,
            {"source_id", "version", "semantic_sha256"},
            f"state source {index}",
        )
        source_id = _text(source["source_id"], f"state source {index} ID", 3, 64)
        if source_id not in SOURCE_IDS or source_id in seen:
            raise IntelligenceError(f"state source ID is unsupported/duplicate: {source_id}")
        seen.add(source_id)
        _time(source["version"], f"state source {source_id} version")
        if (
            not isinstance(source["semantic_sha256"], str)
            or not SHA256_PATTERN.fullmatch(source["semantic_sha256"])
        ):
            raise IntelligenceError(f"state source {source_id} digest is invalid")
    return value


def _read_existing(output_path: Path, state_path: Path) -> tuple[bytes, dict[str, Any]] | None:
    if output_path.exists() != state_path.exists():
        raise IntelligenceError(
            "catalog and rollback state must either both exist or both be absent"
        )
    if not output_path.exists():
        return None
    try:
        raw = output_path.read_bytes()
        state_raw = state_path.read_bytes()
    except OSError as exc:
        raise IntelligenceError(f"cannot read current intelligence state: {exc}") from exc
    if len(raw) > MAX_CATALOG_BYTES or len(state_raw) > 256 * 1024:
        raise IntelligenceError("current intelligence catalog/state exceeds the size limit")
    try:
        catalog = strict_json_loads(raw)
        state = strict_json_loads(state_raw)
    except FeedError as exc:
        raise IntelligenceError(f"current intelligence catalog/state is invalid: {exc}") from exc
    validate_catalog(catalog)
    _validate_state(state)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != state["current_catalog_sha256"]:
        raise IntelligenceError("current catalog does not match rollback state")
    return raw, state


def _check_rollback(previous: dict[str, Any], catalog: dict[str, Any]) -> None:
    old_sources = {source["source_id"]: source for source in previous["sources"]}
    new_sources = {source["source_id"]: source for source in catalog["sources"]}
    removed = sorted(set(old_sources) - set(new_sources))
    if removed:
        raise IntelligenceError(f"source removal rejected: {','.join(removed)}")
    for source_id, old in old_sources.items():
        new = new_sources[source_id]
        old_version = _parse_time(old["version"], f"old {source_id} version")
        new_version = _parse_time(new["version"], f"new {source_id} version")
        if new_version < old_version:
            raise IntelligenceError(f"source rollback rejected: {source_id}")
        if (
            new_version == old_version
            and new["semantic_sha256"] != old["semantic_sha256"]
        ):
            raise IntelligenceError(
                f"source version reuse with changed content rejected: {source_id}"
            )


def install_catalog(
    catalog: dict[str, Any],
    output_path: Path,
    state_path: Path,
    backup_dir: Path,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
) -> UpdateResult:
    encoded = catalog_bytes(catalog)
    digest = hashlib.sha256(encoded).hexdigest()
    current = _read_existing(output_path, state_path)
    outcome = "validated"
    if current is not None:
        old_raw, old_state = current
        _check_rollback(old_state, catalog)
        old_digest = old_state["current_catalog_sha256"]
        outcome = "unchanged" if old_digest == digest else "updated"
    elif not dry_run:
        outcome = "installed"
    if dry_run:
        return UpdateResult(
            outcome,
            catalog,
            digest,
            str(output_path),
            str(state_path),
            True,
        )
    lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    with update_lock(lock_path):
        current = _read_existing(output_path, state_path)
        if current is not None:
            old_raw, old_state = current
            _check_rollback(old_state, catalog)
            old_digest = old_state["current_catalog_sha256"]
            if old_digest == digest:
                return UpdateResult(
                    "unchanged",
                    catalog,
                    digest,
                    str(output_path),
                    str(state_path),
                    False,
                )
            backup = backup_dir / old_digest
            backup_catalog = backup / output_path.name
            backup_state = backup / state_path.name
            if backup_catalog.exists() or backup_state.exists():
                if not backup_catalog.is_file() or not backup_state.is_file():
                    raise IntelligenceError("existing rollback backup is incomplete")
                if backup_catalog.read_bytes() != old_raw:
                    raise IntelligenceError("existing rollback backup catalog does not match")
            else:
                atomic_write_bytes(backup_catalog, old_raw, mode=0o600)
                atomic_write_bytes(backup_state, state_path.read_bytes(), mode=0o600)
        atomic_write_bytes(output_path, encoded, mode=0o600)
        installed_at = format_utc((now or utc_now()).astimezone(UTC))
        atomic_write_json(
            state_path,
            {
                "schema": STATE_SCHEMA,
                "current_catalog_sha256": digest,
                "sources": [
                    {
                        "source_id": source["source_id"],
                        "version": source["version"],
                        "semantic_sha256": source["semantic_sha256"],
                    }
                    for source in catalog["sources"]
                ],
                "installed_at": installed_at,
            },
            mode=0o600,
        )
    return UpdateResult(outcome, catalog, digest, str(output_path), str(state_path), False)


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, source_id: str, maximum: int = 3) -> None:
        super().__init__()
        self.source_id = source_id
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
        absolute = urllib.parse.urljoin(request.full_url, new_url)
        if self.count > self.maximum or not _source_url_allowed(self.source_id, absolute):
            raise IntelligenceError("advisory source redirect left its URL allowlist")
        return super().redirect_request(request, file_pointer, code, message, headers, absolute)


class HTTPSourceFetcher:
    def __init__(
        self,
        cache_dir: Path,
        *,
        timeout: float = 30.0,
        write_cache: bool = True,
        offline: bool = False,
    ) -> None:
        if timeout <= 0 or timeout > 120:
            raise IntelligenceError("source timeout must be within 0..120 seconds")
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.write_cache = write_cache
        self.offline = offline

    def _cache_paths(self, cache_key: str) -> tuple[Path, Path]:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,79}", cache_key):
            raise IntelligenceError("invalid advisory cache key")
        return self.cache_dir / f"{cache_key}.body", self.cache_dir / f"{cache_key}.json"

    def _read_cache(
        self,
        cache_key: str,
        source_id: str,
        url: str,
    ) -> tuple[bytes, dict[str, Any]] | None:
        body_path, metadata_path = self._cache_paths(cache_key)
        if body_path.exists() != metadata_path.exists():
            raise IntelligenceError(f"advisory cache is incomplete: {cache_key}")
        if not body_path.exists():
            return None
        try:
            body = body_path.read_bytes()
            metadata = strict_json_loads(metadata_path.read_bytes())
        except (OSError, FeedError) as exc:
            raise IntelligenceError(f"cannot read advisory cache {cache_key}: {exc}") from exc
        if not isinstance(metadata, dict):
            raise IntelligenceError(f"advisory cache metadata is invalid: {cache_key}")
        _exact_keys(
            metadata,
            {"schema", "source_id", "url", "body_sha256", "etag", "last_modified"},
            f"cache {cache_key}",
        )
        if (
            metadata["schema"] != "zsec.desktop-intelligence-cache.v1"
            or metadata["source_id"] != source_id
            or metadata["url"] != url
            or len(body) > MAX_SOURCE_BYTES
            or hashlib.sha256(body).hexdigest() != metadata["body_sha256"]
        ):
            raise IntelligenceError(f"advisory cache validation failed: {cache_key}")
        for field in ("etag", "last_modified"):
            if metadata[field] is not None and not isinstance(metadata[field], str):
                raise IntelligenceError(f"advisory cache {field} is invalid: {cache_key}")
        return body, metadata

    def __call__(self, source_id: str, url: str, cache_key: str) -> SourceArtifact:
        if source_id not in SOURCE_IDS or not _source_url_allowed(source_id, url):
            raise IntelligenceError(f"advisory source URL is not allowlisted: {source_id}")
        cached = self._read_cache(cache_key, source_id, url)
        if self.offline:
            if cached is None:
                raise IntelligenceError(f"offline cache is missing: {cache_key}")
            body, metadata = cached
            return SourceArtifact(
                source_id,
                url,
                body,
                metadata["body_sha256"],
                metadata["etag"],
                metadata["last_modified"],
            )
        headers = {
            "Accept": "application/json, application/rss+xml, text/xml, text/html",
            "User-Agent": "ZSEC-Desktop-Intelligence/0.1 (+https://talktoai.org/zero-security/)",
        }
        if cached is not None:
            _body, metadata = cached
            if metadata["etag"]:
                headers["If-None-Match"] = metadata["etag"]
            if metadata["last_modified"]:
                headers["If-Modified-Since"] = metadata["last_modified"]
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _AllowlistedRedirectHandler(source_id),
        )
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=self.timeout) as response:
                final_url = response.geturl()
                if not _source_url_allowed(source_id, final_url):
                    raise IntelligenceError("advisory source response left its URL allowlist")
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        if int(length) > MAX_SOURCE_BYTES:
                            raise IntelligenceError("advisory source exceeds the size limit")
                    except ValueError as exc:
                        raise IntelligenceError(
                            "advisory source Content-Length is invalid"
                        ) from exc
                body = response.read(MAX_SOURCE_BYTES + 1)
                if len(body) > MAX_SOURCE_BYTES:
                    raise IntelligenceError("advisory source exceeds the size limit")
                etag = response.headers.get("ETag")
                last_modified = response.headers.get("Last-Modified")
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and cached is not None:
                body, metadata = cached
                return SourceArtifact(
                    source_id,
                    url,
                    body,
                    metadata["body_sha256"],
                    metadata["etag"],
                    metadata["last_modified"],
                )
            raise IntelligenceError(
                f"advisory source HTTP failure: {source_id}: {exc.code}"
            ) from exc
        except IntelligenceError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IntelligenceError(f"advisory source download failed: {source_id}: {exc}") from exc
        digest = hashlib.sha256(body).hexdigest()
        if self.write_cache:
            body_path, metadata_path = self._cache_paths(cache_key)
            atomic_write_bytes(body_path, body, mode=0o600)
            atomic_write_json(
                metadata_path,
                {
                    "schema": "zsec.desktop-intelligence-cache.v1",
                    "source_id": source_id,
                    "url": url,
                    "body_sha256": digest,
                    "etag": etag,
                    "last_modified": last_modified,
                },
                mode=0o600,
            )
        return SourceArtifact(source_id, url, body, digest, etag, last_modified)


def collect_catalog(
    fetcher: Fetcher,
    source_ids: Iterable[str] = SOURCE_IDS,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    selected = tuple(source_ids)
    if not selected or len(set(selected)) != len(selected):
        raise IntelligenceError("advisory source selection must be nonempty and unique")
    unknown = sorted(set(selected) - set(SOURCE_IDS))
    if unknown:
        raise IntelligenceError(f"unsupported advisory source: {','.join(unknown)}")
    current = (now or utc_now()).astimezone(UTC)
    results: list[SourceResult] = []
    for source_id in selected:
        if source_id == "cisa-kev":
            results.append(parse_cisa_kev(fetcher(source_id, CISA_KEV_URL, "cisa-kev")))
        elif source_id == "ubuntu-usn":
            results.append(parse_ubuntu_usn(fetcher(source_id, UBUNTU_USN_URL, "ubuntu-usn")))
        elif source_id == "apple-security":
            results.append(
                parse_apple_security(fetcher(source_id, APPLE_SECURITY_URL, "apple-security"))
            )
        elif source_id == "microsoft-msrc":
            index_artifact = fetcher(source_id, MSRC_UPDATES_URL, "microsoft-msrc-index")
            document_id, document_url = _latest_msrc_document(index_artifact, current)
            document_artifact = fetcher(
                source_id,
                document_url,
                f"microsoft-msrc-{document_id.casefold()}",
            )
            results.append(
                parse_microsoft_msrc(index_artifact, document_artifact, document_id)
            )
    return build_catalog(results)


def update_desktop_intelligence(
    *,
    output_path: Path,
    state_path: Path,
    cache_dir: Path,
    backup_dir: Path,
    source_ids: Iterable[str] = SOURCE_IDS,
    timeout: float = 30.0,
    offline: bool = False,
    dry_run: bool = False,
    now: datetime | None = None,
    fetcher: Fetcher | None = None,
) -> UpdateResult:
    active_fetcher = fetcher or HTTPSourceFetcher(
        cache_dir,
        timeout=timeout,
        write_cache=not dry_run,
        offline=offline,
    )
    catalog = collect_catalog(active_fetcher, source_ids, now=now)
    return install_catalog(
        catalog,
        output_path,
        state_path,
        backup_dir,
        now=now,
        dry_run=dry_run,
    )
