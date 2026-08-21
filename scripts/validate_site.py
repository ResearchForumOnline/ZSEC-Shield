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
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
PAGES = {
    "zero-security": "https://talktoai.org/zero-security/",
    "zero-browser": "https://talktoai.org/zero-browser/",
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.h1_count = 0
        self.faq_count = 0
        self.canonicals: list[str] = []
        self.assets: list[str] = []
        self.meta_descriptions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(str(values["id"]))
        if tag == "h1":
            self.h1_count += 1
        if tag == "details":
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
    return (page.parent / parsed.path).resolve()


def validate_page(slug: str, canonical: str) -> None:
    page = WEB / slug / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.faq_count == 6, f"{slug}: expected six visible FAQs")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(len(parser.meta_descriptions) == 1, f"{slug}: meta description missing")
    require(80 <= len(parser.meta_descriptions[0]) <= 180, f"{slug}: meta description length")

    script_match = re.search(
        r'<script type="application/ld\+json">(?P<json>[\s\S]*?)</script>', text
    )
    require(script_match is not None, f"{slug}: JSON-LD missing")
    script_text = script_match.group("json")
    data = json.loads(script_text)
    graph = data.get("@graph") if isinstance(data, dict) else None
    require(isinstance(graph, list), f"{slug}: JSON-LD graph missing")
    faq = next((item for item in graph if item.get("@type") == "FAQPage"), None)
    require(faq is not None and len(faq.get("mainEntity", [])) == 6, f"{slug}: FAQ schema")

    digest = base64.b64encode(hashlib.sha256(script_text.encode("utf-8")).digest()).decode()
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require(f"sha256-{digest}" in htaccess, f"{slug}: CSP JSON-LD hash mismatch")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")

    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def main() -> int:
    for slug, canonical in PAGES.items():
        validate_page(slug, canonical)
    sitemap = ET.parse(WEB / "sitemap.xml")
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locations = {node.text for node in sitemap.findall("sm:url/sm:loc", namespace)}
    require(set(PAGES.values()) <= locations, "product URLs missing from sitemap")
    robots = (WEB / "robots.txt").read_text(encoding="utf-8")
    require("Sitemap: https://talktoai.org/sitemap.xml" in robots, "robots sitemap missing")
    css = (WEB / "assets" / "style.css").read_text(encoding="utf-8")
    require(css.count("{") == css.count("}"), "CSS braces are unbalanced")
    require(".webp" not in css, "CSS references an unavailable WebP asset")
    print("Validated two product pages, JSON-LD/CSP hashes, assets, sitemap, robots and CSS.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, ET.ParseError) as exc:
        print(f"site validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
