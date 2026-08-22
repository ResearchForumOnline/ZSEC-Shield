"""Deterministic static QA for the ZSEC GitHub Pages and TalkToAI surfaces."""

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
GITHUB_PAGES_CANONICAL = "https://talktoai.org/zero-security/"
PAGES = {
    "zero-security": "https://talktoai.org/zero-security/",
    "zero-browser": "https://talktoai.org/zero-browser/",
}
FAQ_COUNTS = {
    "zero-security": 6,
    "zero-browser": 7,
}
COPY_REQUIREMENTS = {
    "zero-security": (
        "ZSEC Antivirus Community 0.3.13",
        "Microsoft Defender supplies supported Windows real-time enforcement",
        "ZSEC does not uninstall a provider",
        "is not registered as the primary provider",
    ),
    "zero-browser": (
        "ZSEC Browser Community 0.3.12",
        "all WebView2 resource-source kinds",
        "Journalist preset",
        "does not seek, accelerate or mute playback",
    ),
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
    required_text: tuple[str, ...]


ANTIVIRUS_RELEASE_BASE = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/download/v0.3.13/"
)
ANTIVIRUS_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.13"
)
ANTIVIRUS_RELEASE_REVISION = "dcaa2ec1f4c58854a350fcb1ef920dc5112e26ba"
BROWSER_RELEASE_BASE = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/download/v0.3.12/"
)
BROWSER_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.12"
)
BROWSER_RELEASE_REVISION = "ece60f377b2d4cfc594ad4a29b619be7617ed45f"
JSON_LD_DOWNLOADS = {
    "zero-security": ANTIVIRUS_RELEASE_BASE
    + "zsec-antivirus-desktop-0.3.13-windows-x86_64.zip",
    "zero-browser": BROWSER_RELEASE_BASE
    + "zsec-browser-community-0.3.12-windows-x64-unsigned.zip",
}

DOWNLOAD_PAGES: dict[str, DownloadPolicy] = {
    "zero-security/download": {
        "canonical": "https://talktoai.org/zero-security/download/",
        "fingerprints": 8,
        "artifacts": {
            ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.13-windows-x86_64.zip",
            ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.13-windows-x86_64.zip.sha256",
            ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.13-windows-x86_64.zip.json",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-windows-x86_64.zip",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-windows-x86_64.zip.sha256",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-macos-arm64.tar.gz",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-macos-arm64.tar.gz.sha256",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-linux-x86_64.tar.gz",
            ANTIVIRUS_RELEASE_BASE + "zsec-shield-0.3.13-linux-x86_64.tar.gz.sha256",
            ANTIVIRUS_RELEASE_BASE + "zsec_shield-0.3.13-py3-none-any.whl",
            ANTIVIRUS_RELEASE_BASE + "zsec_shield-0.3.13.tar.gz",
            ANTIVIRUS_RELEASE_BASE + "SHA256SUMS.txt",
            ANTIVIRUS_RELEASE_BASE + "SHA256SUMS-python.txt",
        },
        "required_text": (
            ANTIVIRUS_RELEASE_REVISION,
            "45,062,027 bytes",
            "f1a36ac2cf0070dc14c6c73ac088fa8ab698aefee5a30eebd802e6f9dae65d82",
            "352ecaab6d1a54a95382c70d97b12a96d1370d394296652f96aa3c0942b794cf",
            "749abc51af97d3409a6e4fcd5e535f5afb0cd85c8694459031c6e61b5ebbca7b",
            "32dec8a9493013bb715a613ea44ac447c2cf4826a878a3c0cc4c20a8fa5ad6fc",
            "9b4088ae99d8fc5b0de0ba7e70ed3d3cc8c26b67ff67a14fc86540e213232c51",
            "13,229,221 bytes",
            "46d38071fb4d3cdab3128fc0f53828a887b158eabc6a925dc995745fdd955184",
            "12,622,684 bytes",
            "45941ec7c3be491577763f56c92e289b60689c399b91ef4cd3995c0779996d90",
            "23,930,115 bytes",
            "88fc70ae54177d4e78a26de7a3a2b0c177fe24cd7a4b56d9f025f42eb6cf15e0",
            "100,455-byte",
            "de4914820be7cc516efc2f5454092bb5389265bb164243d0f925e596ab2aa25f",
            "340,846-byte",
            "c9bb2880927ed7ba0f0caa99a9854986005ba9407fd0aded020e37dfeaa8b92c",
            "acceptance state was <code>initializing</code>",
            "health decision <code>degraded</code>, not healthy",
            "ZSEC's primary, provider, pre-access and real-time flags all remained false",
            ".\\Install-ZsecAntivirusDesktop.ps1 -PlanOnly",
            ".\\Install-ZsecAntivirusDesktop.ps1 -Open",
        ),
    },
    "zero-browser/download": {
        "canonical": "https://talktoai.org/zero-browser/download/",
        "fingerprints": 4,
        "artifacts": {
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.12-windows-x64-unsigned.zip",
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.12-windows-x64-unsigned.zip.sha256",
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.12-windows-x64-unsigned.zip.json",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip.sha256",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip.json",
        },
        "required_text": (
            BROWSER_RELEASE_REVISION,
            "4,206,951 bytes",
            "09c16fe915923db98e9ed6f2936e7d1d2b48c7b3fb31aa27865fdd064cee8c61",
            "2,123 bytes",
            "f1b6781030cd5ba751eff1c381b0c953f13c9839eac547284f479b0fc76d9962",
            "122 bytes",
            "851438b8b53d23d5aa34d87a9813c32ea28a4c71b401c35e5e226cb4f1c1ef42",
            "b571451fa2b3c6f7c69072bee8942d5191d8dfe0df4bde0aa10ac9c2d08f856f",
            "WebView2 SDK 1.0.4129.50",
            "not an installed Evergreen runtime version or a Microsoft signature on ZSEC",
            "YouTube controls are best effort",
        ),
    },
}
PRIVACY_PAGE = "https://talktoai.org/zero-browser/privacy/"

RELEASE_SURFACE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "index.html": (
        "ZSEC Antivirus 0.3.13 · ZSEC Browser 0.3.12",
        ANTIVIRUS_RELEASE_REVISION,
        ANTIVIRUS_RELEASE_TAG,
    ),
    "zero-security/index.html": (
        "0.3.13 Community package",
        ANTIVIRUS_RELEASE_REVISION,
        "45,062,027 bytes",
        "f1a36ac2cf0070dc14c6c73ac088fa8ab698aefee5a30eebd802e6f9dae65d82",
        ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.13-windows-x86_64.zip",
        "initializing/baselining",
        "remained <strong>degraded</strong>",
    ),
    "zero-browser/index.html": (
        "0.3.12 Community package",
        BROWSER_RELEASE_REVISION,
        "4,206,951 bytes",
        "09c16fe915923db98e9ed6f2936e7d1d2b48c7b3fb31aa27865fdd064cee8c61",
        BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.12-windows-x64-unsigned.zip",
        "release-specific installed-runtime result",
    ),
    "zero-browser/privacy/index.html": (
        BROWSER_RELEASE_REVISION,
        "4,206,951-byte Windows archive",
        "09c16fe915923db98e9ed6f2936e7d1d2b48c7b3fb31aa27865fdd064cee8c61",
        "2,123-byte metadata JSON",
        "f1b6781030cd5ba751eff1c381b0c953f13c9839eac547284f479b0fc76d9962",
    ),
    "llms.txt": (
        ANTIVIRUS_RELEASE_REVISION,
        BROWSER_RELEASE_REVISION,
        "Accepted Windows desktop identity",
        "45,062,027 bytes",
        "Accepted cross-platform core identities",
        "Accepted Windows browser identity",
        "4,206,951 bytes",
        "No release-specific installed-runtime result is claimed",
        ANTIVIRUS_RELEASE_TAG,
        BROWSER_RELEASE_TAG,
    ),
}

RELEASE_SURFACE_TAGS: dict[str, set[str]] = {
    "index.html": {"v0.3.13"},
    "zero-security/index.html": {"v0.3.13"},
    "zero-browser/index.html": {"v0.3.12"},
    "zero-browser/privacy/index.html": {"v0.3.12"},
    "llms.txt": {"v0.3.12", "v0.3.13"},
}

RESIDUAL_OLD_IDENTITIES = (
    "zsec-antivirus-desktop-0.3.7",
    "zsec-browser-community-0.3.7",
    "zsec-shield-0.3.0",
    "zsec_shield-0.3.0",
    "v0.3.9",
    "1956eb0a55385e61008fe8d0e85f1e7e3ba13446",
    "25cded39f58d9c9e1cc593d39fbdd885f63c695db7e2dc0258c25ee4aee15cd0",
    "b41c9cbe1c682abc403d803b0857e8d8f71589d57718a6b55af7b1e0e3593e15",
    "21237a456ba3a3457bc4cc816a1182fdb2aa746e49ffc39f61496f2a371e8030",
    "2e46d12c345e853282af97214b35b3c3badaea86",
)

UNSUPPORTED_MARKETING = (
    "coming soon",
    "preview package",
    "pegasus-proof",
    "pegasus immunity",
    "immune to pegasus",
    "blocks pegasus",
    "microsoft-signed zsec",
    "zsec-signed by microsoft",
    "guaranteed youtube ad blocking",
)


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.h1_count = 0
        self.faq_count = 0
        self.mobile_nav_count = 0
        self.canonicals: list[str] = []
        self.assets: list[str] = []
        self.fragments: list[str] = []
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
            if reference and str(reference).startswith("#"):
                self.fragments.append(str(reference)[1:])
            elif reference and not str(reference).startswith("mailto:"):
                self.assets.append(str(reference))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_project_prefix_safe(text: str, label: str) -> None:
    require(
        re.search(r'(?:href|src)="/', text) is None,
        f"{label}: root-relative link breaks GitHub Pages project-prefix hosting",
    )


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
    raw = page.read_bytes()
    text = raw.decode("utf-8")
    parser = PageParser()
    parser.feed(text)
    require_project_prefix_safe(text, slug)
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    expected_faqs = FAQ_COUNTS[slug]
    require(parser.faq_count == expected_faqs, f"{slug}: visible FAQ count")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(set(parser.fragments) <= set(parser.ids), f"{slug}: broken local fragment")
    require(len(parser.meta_descriptions) == 1, f"{slug}: meta description missing")
    require(80 <= len(parser.meta_descriptions[0]) <= 180, f"{slug}: meta description length")
    for required_copy in COPY_REQUIREMENTS[slug]:
        require(required_copy in text, f"{slug}: required 0.3.12 claim boundary missing")

    script_match = re.search(
        br'<script type="application/ld\+json">(?P<json>[\s\S]*?)</script>', raw
    )
    if script_match is None:
        raise ValueError(f"{slug}: JSON-LD missing")
    script_bytes = script_match.group("json")
    script_text = script_bytes.decode("utf-8")
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
    software = next(
        (
            item
            for item in graph
            if isinstance(item, dict)
            and item.get("@id")
            == (
                "https://talktoai.org/zero-security/#software"
                if slug == "zero-security"
                else "https://talktoai.org/zero-browser/#desktop-software"
            )
        ),
        None,
    )
    require(
        software is not None
        and software.get("downloadUrl") == JSON_LD_DOWNLOADS[slug],
        f"{slug}: JSON-LD direct downloadUrl mismatch",
    )

    digest = base64.b64encode(hashlib.sha256(script_bytes).digest()).decode()
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require(f"sha256-{digest}" in htaccess, f"{slug}: CSP JSON-LD hash mismatch")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")

    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def validate_github_pages_landing() -> None:
    page = WEB / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require(parser.h1_count == 1, "web/index.html: expected exactly one H1")
    require(parser.mobile_nav_count == 1, "web/index.html: expected one mobile navigation")
    require(
        parser.canonicals == [GITHUB_PAGES_CANONICAL],
        "web/index.html: canonical TalkToAI URL mismatch",
    )
    require(len(parser.ids) == len(set(parser.ids)), "web/index.html: duplicate HTML id")
    require(
        set(parser.fragments) <= set(parser.ids),
        "web/index.html: broken local fragment",
    )
    require(len(parser.meta_descriptions) == 1, "web/index.html: description missing")
    require(
        80 <= len(parser.meta_descriptions[0]) <= 180,
        "web/index.html: description length",
    )
    require("<script" not in text.casefold(), "web/index.html: executable script is not permitted")
    require_project_prefix_safe(text, "web/index.html")
    for required_copy in (
        "ZSEC Antivirus 0.3.13 · ZSEC Browser 0.3.12",
        "Microsoft Defender remains the supported Windows real-time enforcement provider",
        "not a registered primary antivirus",
        "WebView2 is Microsoft-maintained, not a ZSEC Chromium fork",
        "does not detect Pegasus",
        ANTIVIRUS_RELEASE_TAG,
        "https://talktoai.org/zero-security/",
        "https://talktoai.org/zero-browser/",
    ):
        require(required_copy in text, "web/index.html: evidence or canonical link missing")
    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"web/index.html: missing local asset {reference}")


def validate_privacy_page() -> None:
    page = WEB / "zero-browser" / "privacy" / "index.html"
    text = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(text)
    require_project_prefix_safe(text, "zero-browser/privacy")
    require(parser.h1_count == 1, "zero-browser/privacy: expected exactly one H1")
    require(parser.mobile_nav_count == 1, "zero-browser/privacy: expected one mobile navigation")
    require(parser.canonicals == [PRIVACY_PAGE], "zero-browser/privacy: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), "zero-browser/privacy: duplicate HTML id")
    require(
        set(parser.fragments) <= set(parser.ids),
        "zero-browser/privacy: broken local fragment",
    )
    require(len(parser.meta_descriptions) == 1, "zero-browser/privacy: description missing")
    require(
        80 <= len(parser.meta_descriptions[0]) <= 180,
        "zero-browser/privacy: description length",
    )
    for required_copy in (
        "ZSEC Browser Community 0.3.12",
        "bounded <code>browser-data.json</code>",
        "The Journalist preset is therefore not an ephemeral",
        "ZSEC does not proxy searches",
    ):
        require(required_copy in text, "zero-browser/privacy: 0.3.12 privacy boundary")
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
    require_project_prefix_safe(text, slug)
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(set(parser.fragments) <= set(parser.ids), f"{slug}: broken local fragment")
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
    require_project_prefix_safe(text, slug)
    canonical = str(policy["canonical"])
    expected_artifacts = set(policy["artifacts"])
    expected_fingerprints = int(policy["fingerprints"])
    required_text = tuple(policy["required_text"])
    require(parser.h1_count == 1, f"{slug}: expected exactly one H1")
    require(parser.mobile_nav_count == 1, f"{slug}: expected one mobile navigation")
    require(parser.canonicals == [canonical], f"{slug}: canonical mismatch")
    require(len(parser.ids) == len(set(parser.ids)), f"{slug}: duplicate HTML id")
    require(set(parser.fragments) <= set(parser.ids), f"{slug}: broken local fragment")
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
    references = set(parser.assets)
    require(expected_artifacts <= references, f"{slug}: required artifact link missing")
    for required_copy in required_text:
        require(required_copy in text, f"{slug}: exact release evidence missing")
    htaccess = (page.parent / ".htaccess").read_text(encoding="utf-8")
    require("script-src 'none'" in htaccess, f"{slug}: script CSP missing")
    require("frame-ancestors 'none'" in htaccess, f"{slug}: frame CSP missing")
    require("Permissions-Policy" in htaccess, f"{slug}: permissions policy missing")
    for reference in parser.assets:
        target = local_asset(page, reference)
        if target is not None:
            require(target.exists(), f"{slug}: missing local asset {reference}")


def validate_release_surfaces() -> None:
    for relative_path, required_values in RELEASE_SURFACE_REQUIREMENTS.items():
        text = (WEB / relative_path).read_text(encoding="utf-8")
        lowered = text.casefold()
        for required_value in required_values:
            require(
                required_value in text,
                f"{relative_path}: required release identity or boundary missing",
            )
        for old_identity in RESIDUAL_OLD_IDENTITIES:
            require(
                old_identity not in text,
                f"{relative_path}: residual old release identity {old_identity}",
            )
        for unsupported in UNSUPPORTED_MARKETING:
            require(
                unsupported not in lowered,
                f"{relative_path}: unsupported marketing phrase {unsupported}",
            )
        require("untagged-" not in lowered, f"{relative_path}: draft release URL leaked")
        download_tags = re.findall(
            r"https://github\.com/ResearchForumOnline/ZSEC-Shield/releases/download/([^/]+)/",
            text,
        )
        allowed_tags = RELEASE_SURFACE_TAGS[relative_path]
        require(
            set(download_tags) <= allowed_tags,
            f"{relative_path}: download URL uses the wrong product release tag",
        )


def main() -> int:
    validate_release_surfaces()
    validate_github_pages_landing()
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
        "Validated the GitHub Pages landing, two product pages, two download pages, "
        "browser privacy and guidance, "
        "exact product-specific release identities, residual-version guards, fingerprints, "
        "raw-byte JSON-LD/CSP hashes, assets, sitemap, robots and CSS."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, ET.ParseError) as exc:
        print(f"site validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
