"""Deterministic static QA for the two Zero product pages."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
PAGES = {
    "zero-security": "https://talktoai.org/zero-security/",
    "zero-browser": "https://talktoai.org/zero-browser/",
}
FAQ_COUNTS = {
    "zero-security": 6,
    "zero-browser": 7,
}
INFO_PAGES = {
    "zero-browser/high-risk-browsing": (
        "https://talktoai.org/zero-browser/high-risk-browsing/"
    ),
}

class DownloadPolicy(TypedDict):
    canonical: str
    fingerprints: int
    artifacts: set[str]


DOWNLOAD_PAGES: dict[str, DownloadPolicy] = {
    "zero-security/download": {
        "canonical": "https://talktoai.org/zero-security/download/",
        "fingerprints": 3,
        "artifacts": {
            "/downloads/zero-security/zsec-shield-0.3.0-windows-x86_64.zip",
            "/downloads/zero-security/zsec-antivirus-desktop-0.3.2-windows-x86_64.zip",
            "/downloads/zero-security/zsec-shield-0.3.0-macos-arm64.tar.gz",
            "/downloads/zero-security/zsec-shield-0.3.0-linux-x86_64.tar.gz",
            "/downloads/zero-security/zsec_shield-0.3.0-py3-none-any.whl",
        },
    },
    "zero-browser/download": {
        "canonical": "https://talktoai.org/zero-browser/download/",
        "fingerprints": 2,
        "artifacts": {
            "/downloads/zero-browser/zsec-browser-community-0.3.2-windows-x64-unsigned.zip",
            "/downloads/zero-browser/zsec-browser-shields-0.4.2-chromium-mv3.zip",
        },
    },
}
PRIVACY_PAGE = "https://talktoai.org/zero-browser/privacy/"


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.h1_count = 0
        self.faq_count = 0
        self.mobile_nav_count = 0
        self.canonicals: list[str] = []
        self.assets: list[str] = []
        self.meta_descriptions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(str(values["id"]))
        if tag == "h1":
            self.h1_count += 1
        classes = str(values.get("class") or "").split()
        if tag == "details" and "mobile-nav" in classes:
            self.mobile_nav_count += 1
        elif tag == "details":
            self.faq_count += 1
        if tag == "link" and values.get("rel") == "canonical" and values.get("href"):
            self.canonicals.append(str(values["href"]))
        if tag == "meta" and values.get("name") == "description" and values.get("content"):
            self.meta_descriptions.append(str(values["content"]))
        for field in ("href", "src"):
            reference = values.get(field)
            if reference and not str(reference).startswith(("#", "mailto:")):
                self.assets.append(str(reference))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def local_asset(page: Path, reference: str) -> Path | None:
    parsed = urlparse(reference)
    if parsed.scheme in {"http", "https"}:
        if parsed.netloc not in {"talktoai.org", "www.talktoai.org"}:
            return None
        if not parsed.path.startswith("/assets/"):
            return None
        return WEB / parsed.path.lstrip("/")
    if parsed.scheme:
        return None
    if parsed.path.startswith("/downloads/"):
        # Public release artifacts are built by the gated cross-platform release
        # workflow and deployed beside, rather than committed beneath, web/.
        return None
    return (page.parent / parsed.path).resolve()


def validate_page(slug: str, canonical: str) -> None:
    page = WEB / slug / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    expected_faqs = FAQ_COUNTS[slug]
    require(parser.faq_count == expected_faqs, f"{slug}: visible FAQ count")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(len(parser.meta_descriptions) == 1, f"{slug}: meta description missing")
    require(80 <= len(parser.meta_descriptions[0]) <= 180, f"{slug}: meta description length")

    script_match = re.search(
        r'<script type="application/ld\+json">(?P<json>[\s\S]*?)</script>', text
    )
    if script_match is None:
        raise ValueError(f"{slug}: JSON-LD missing")
    script_text = script_match.group("json")
    data = json.loads(script_text)
    graph = data.get("@graph") if isinstance(data, dict) else None
    if not isinstance(graph, list):
        raise ValueError(f"{slug}: JSON-LD graph missing")
    faq = next(
        (
            item
            for item in graph
            if isinstance(item, dict) and item.get("@type") == "FAQPage"
        ),
        None,
    )
    require(
        faq is not None and len(faq.get("mainEntity", [])) == expected_faqs,
        f"{slug}: FAQ schema",
    )

    digest = base64.b64encode(hashlib.sha256(script_text.encode("utf-8")).digest()).decode()
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require(f"sha256-{digest}" in htaccess, f"{slug}: CSP JSON-LD hash mismatch")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")

    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def validate_privacy_page() -> None:
    page = WEB / "zero-browser" / "privacy" / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require(parser.h1_count == 1, "zero-browser/privacy: expected exactly one H1")
    require(parser.mobile_nav_count == 1, "zero-browser/privacy: expected one mobile navigation")
    require(parser.canonicals == [PRIVACY_PAGE], "zero-browser/privacy: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), "zero-browser/privacy: duplicate HTML id")
    require(len(parser.meta_descriptions) == 1, "zero-browser/privacy: description missing")
    require(
        80 <= len(parser.meta_descriptions[0]) <= 180,
        "zero-browser/privacy: description length",
    )
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require("script-src 'none'" in htaccess, "zero-browser/privacy: script CSP missing")
    require("frame-ancestors 'none'" in htaccess, "zero-browser/privacy: frame CSP missing")
    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"zero-browser/privacy: missing local asset {reference}")


def validate_info_page(slug: str, canonical: str) -> None:
    page = WEB / slug / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(len(parser.meta_descriptions) == 1, f"{slug}: description missing")
    require(80 <= len(parser.meta_descriptions[0]) <= 180, f"{slug}: description length")
    require("<script" not in text.casefold(), f"{slug}: executable script is not permitted")
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require("script-src 'none'" in htaccess, f"{slug}: script CSP missing")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")
    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def validate_download_page(slug: str, policy: DownloadPolicy) -> None:
    page = WEB / slug / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    canonical = str(policy["canonical"])
    expected_artifacts = set(policy["artifacts"])
    expected_fingerprints = int(policy["fingerprints"])
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(len(parser.meta_descriptions) == 1, f"{slug}: description missing")
    require(80 <= len(parser.meta_descriptions[0]) <= 180, f"{slug}: description length")
    require("<script" not in text.casefold(), f"{slug}: executable script is not permitted")
    require("PENDING" not in text and "TO-BE-BUILT" not in text, f"{slug}: placeholder")
    fingerprints = re.findall(
        r"<code\s+data-[^>]*sha[^>]*>([0-9a-f]{64})</code>", text
    )
    require(
        len(fingerprints) == expected_fingerprints,
        f"{slug}: expected {expected_fingerprints} exact SHA-256 fingerprints",
    )
    require(len(fingerprints) == len(set(fingerprints)), f"{slug}: duplicate fingerprint")
    references = {urlparse(reference).path for reference in parser.assets}
    require(expected_artifacts <= references, f"{slug}: required artifact link missing")
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require("script-src 'none'" in htaccess, f"{slug}: script CSP missing")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")
    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def main() -> int:
    for slug, canonical in PAGES.items():
        validate_page(slug, canonical)
    for slug, policy in DOWNLOAD_PAGES.items():
        validate_download_page(slug, policy)
    validate_privacy_page()
    for slug, canonical in INFO_PAGES.items():
        validate_info_page(slug, canonical)
    sitemap = ET.parse(WEB / "sitemap.xml")
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locations = {node.text for node in sitemap.findall("sm:url/sm:loc", namespace)}
    require(
        set(PAGES.values())
        | {str(policy["canonical"]) for policy in DOWNLOAD_PAGES.values()}
        | {PRIVACY_PAGE}
        | set(INFO_PAGES.values())
        <= locations,
        "product, download or privacy URLs missing from sitemap",
    )
    robots = (WEB / "robots.txt").read_text(encoding="utf-8")
    require("Sitemap: https://talktoai.org/sitemap.xml" in robots, "robots sitemap missing")
    css = (WEB / "assets" / "style.css").read_text(encoding="utf-8")
    require(css.count("{") == css.count("}"), "CSS braces are unbalanced")
    require(".webp" not in css, "CSS references an unavailable WebP asset")
    print(
        "Validated two product pages, two download pages, browser privacy and guidance, "
        "fingerprints, JSON-LD/CSP hashes, assets, sitemap, robots and CSS."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, ET.ParseError) as exc:
        print(f"site validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
