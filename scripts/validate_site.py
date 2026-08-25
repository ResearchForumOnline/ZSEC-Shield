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
    "zero-browser": 8,
}
COPY_REQUIREMENTS = {
    "zero-security": (
        "ZSEC Antivirus Community 0.3.29",
        "Microsoft Defender supplies supported Windows real-time enforcement",
        "ZSEC does not uninstall a provider",
        "is not registered as the primary provider",
    ),
    "zero-browser": (
        "ZSEC Browser Community 0.3.25",
        "all WebView2 resource-source kinds",
        "Page-requested windows are blocked by default",
        "Sign-in Setup Assistant",
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
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/download/v0.3.29-windows/"
)
ANTIVIRUS_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.29-windows"
)
ANTIVIRUS_RELEASE_REVISION = "d4bf4815817057b54a4677a27cc543809f9d3467"
GITHUB_PAGES_ANTIVIRUS_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.22-windows"
)
CORE_RELEASE_BASE = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/download/v0.3.14/"
)
CORE_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.14"
)
CORE_RELEASE_REVISION = "57557ae4dd03765a59b05a3a0e0006edc13b7bd4"
BROWSER_RELEASE_BASE = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/download/v0.3.25-browser/"
)
BROWSER_RELEASE_TAG = (
    "https://github.com/ResearchForumOnline/ZSEC-Shield/releases/tag/v0.3.25-browser"
)
BROWSER_RELEASE_REVISION = "cd0fff58072403dddaf3810aacbdb2288a01139d"
JSON_LD_DOWNLOADS = {
    "zero-security": ANTIVIRUS_RELEASE_BASE
    + "zsec-antivirus-desktop-0.3.29-windows-x86_64.zip",
    "zero-browser": BROWSER_RELEASE_BASE
    + "zsec-browser-community-0.3.25-windows-x64-unsigned.zip",
}

DOWNLOAD_PAGES: dict[str, DownloadPolicy] = {
    "zero-security/download": {
        "canonical": "https://talktoai.org/zero-security/download/",
        "fingerprints": 7,
        "artifacts": {
            ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.29-windows-x86_64.zip",
            ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.29-windows-x86_64.zip.sha256",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-windows-x86_64.zip",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-windows-x86_64.zip.sha256",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-macos-arm64.tar.gz",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-macos-arm64.tar.gz.sha256",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-linux-x86_64.tar.gz",
            CORE_RELEASE_BASE + "zsec-shield-0.3.14-linux-x86_64.tar.gz.sha256",
            CORE_RELEASE_BASE + "zsec_shield-0.3.14-py3-none-any.whl",
            CORE_RELEASE_BASE + "zsec_shield-0.3.14.tar.gz",
            CORE_RELEASE_BASE + "SHA256SUMS.txt",
            CORE_RELEASE_BASE + "SHA256SUMS-python.txt",
        },
        "required_text": (
            ANTIVIRUS_RELEASE_REVISION,
            "33,846,149 bytes",
            "7da82615a1fd38cd781c6e74394243b54ce762926c252b79b42dc2685ff8bd13",
            "cb2c53b028f4b194030c0394de616d0053a60c0aae4ce3d6dcaddef43d1332d4",
            "13,437,103 bytes",
            "e822570ea5472b45643350d02d910688f185a2b4917efb48251b652444ffb591",
            "12,805,932 bytes",
            "81d28ff2f7077bf779e67363ba28dd107d66d3982d38d8463d197ff10faea950",
            "24,240,917 bytes",
            "2d947e8788039aef57bafa8bcd161e9dba891e5a36c6adacc9dc5d868f7f0517",
            "106,309-byte",
            "4eb3f1aba3734dcef323285177cc6719b0bf63bdd3f2e1152db586046d4be968",
            "350,963-byte",
            "16b7bee7c06117b0084e6ee076bb9f4b2319a1d8fbfbbdd4633003074501b03f",
            "Application updates remain notification-only until publisher signing is available",
            "ZSEC does not register as the primary provider",
            ".\\Install-ZsecAntivirusDesktop.ps1 -PlanOnly",
            ".\\Install-ZsecAntivirusDesktop.ps1 -Open",
        ),
    },
    "zero-browser/download": {
        "canonical": "https://talktoai.org/zero-browser/download/",
        "fingerprints": 4,
        "artifacts": {
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.25-windows-x64-unsigned.zip",
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.25-windows-x64-unsigned.zip.sha256",
            BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.25-windows-x64-unsigned.zip.json",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip.sha256",
            "https://talktoai.org/downloads/zero-browser/zsec-browser-shields-0.5.2-chromium-mv3.zip.json",
        },
        "required_text": (
            BROWSER_RELEASE_REVISION,
            "4,265,007 bytes",
            "ecd59e8fb86560f0f2a4b5c645f956ef59e9140debcbbb25d6f3d3bd571ee548",
            "2,123 bytes",
            "67f230dcbad5c04c023285691bfe487f270162ce2f9ab49b596b46d558705857",
            "122 bytes",
            "488c50ea52a8e44c940541a0d8c21207b79e165ef8ba12f309d6dd8758c7f15a",
            "b571451fa2b3c6f7c69072bee8942d5191d8dfe0df4bde0aa10ac9c2d08f856f",
            "WebView2 SDK 1.0.4129.50",
            "not an installed Evergreen runtime version or a Microsoft signature on ZSEC",
            "YouTube controls are best effort",
        ),
    },
}
PRIVACY_PAGE = "https://talktoai.org/zero-browser/privacy/"

RELEASE_SURFACE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "zero-security/index.html": (
        "0.3.29 Community package",
        ANTIVIRUS_RELEASE_REVISION,
        "33,846,149-byte",
        "7da82615a1fd38cd781c6e74394243b54ce762926c252b79b42dc2685ff8bd13",
        ANTIVIRUS_RELEASE_BASE + "zsec-antivirus-desktop-0.3.29-windows-x86_64.zip",
        "Microsoft Defender supplies supported Windows real-time enforcement",
    ),
    "zero-browser/index.html": (
        "0.3.25 Community package",
        BROWSER_RELEASE_REVISION,
        "4,265,007 bytes",
        "ecd59e8fb86560f0f2a4b5c645f956ef59e9140debcbbb25d6f3d3bd571ee548",
        BROWSER_RELEASE_BASE + "zsec-browser-community-0.3.25-windows-x64-unsigned.zip",
        "user-operated local encrypted password vault",
        "Review-first sign-in setup",
        "Source-browser cookies, sessions, tokens, passwords and profiles are never copied",
        "Page-requested windows are blocked by default",
        "release-specific installed-runtime result",
    ),
    "zero-browser/privacy/index.html": (
        BROWSER_RELEASE_REVISION,
        "4,265,007-byte Windows archive",
        "ecd59e8fb86560f0f2a4b5c645f956ef59e9140debcbbb25d6f3d3bd571ee548",
        "2,123-byte metadata JSON",
        "67f230dcbad5c04c023285691bfe487f270162ce2f9ab49b596b46d558705857",
        "Password saving and filling are independent opt-in settings",
        "The separate Sign-in Setup Assistant does not use the source profile",
        "cannot guarantee protection from every malicious site",
    ),
    "llms.txt": (
        ANTIVIRUS_RELEASE_REVISION,
        BROWSER_RELEASE_REVISION,
        "Accepted Windows desktop identity",
        "33,846,149 bytes",
        "Accepted cross-platform core identities",
        "Accepted Windows browser identity",
        "4,265,007 bytes",
        "No release-specific installed-runtime result is claimed",
        ANTIVIRUS_RELEASE_TAG,
        BROWSER_RELEASE_TAG,
    ),
}

RELEASE_SURFACE_TAGS: dict[str, set[str]] = {
    "zero-security/index.html": {"v0.3.29-windows"},
    "zero-browser/index.html": {"v0.3.25-browser"},
    "zero-browser/privacy/index.html": {"v0.3.25-browser"},
    "llms.txt": {"v0.3.29-windows", "v0.3.25-browser", "v0.3.14"},
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
        require(required_copy in text, f"{slug}: required product claim boundary missing")

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
        "ZSEC Antivirus 0.3.22 · ZSEC Browser 0.3.25",
        "Microsoft Defender remains the supported Windows real-time enforcement provider",
        "not a registered primary antivirus",
        "WebView2 is Microsoft-maintained, not a ZSEC Chromium fork",
        "does not detect Pegasus",
        GITHUB_PAGES_ANTIVIRUS_RELEASE_TAG,
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
        "ZSEC Browser Community 0.3.25",
        "bounded <code>browser-data.json</code>",
        "The separate Sign-in Setup Assistant does not use the source profile",
        "The Journalist preset is therefore not an ephemeral",
        "ZSEC does not proxy searches",
    ):
        require(required_copy in text, "zero-browser/privacy: 0.3.25 privacy boundary")
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
