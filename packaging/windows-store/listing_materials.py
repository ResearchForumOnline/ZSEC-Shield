"""Validate and render the offline ZSEC Microsoft Store listing drafts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

STORE_ROOT = Path(__file__).resolve().parent
LISTINGS_ROOT = STORE_ROOT / "listings"
OUTPUT_PATH = STORE_ROOT / "PARTNER_CENTER_DRAFT.md"
FIELD_OUTPUT_PATH = STORE_ROOT / "out" / "PARTNER_CENTER_FIELDS.md"
SCHEMA = "zsec.microsoft-store-listing.v1"
EXPECTED_URLS = {
    "antivirus": {
        "website_url": "https://talktoai.org/zero-security/",
        "support_url": "https://github.com/ResearchForumOnline/ZSEC-Shield/issues",
        "privacy_policy_url": "https://talktoai.org/zero-security/#privacy",
        "vulnerability_reporting_url": "https://talktoai.org/.well-known/security.txt",
    },
    "browser": {
        "website_url": "https://talktoai.org/zero-browser/",
        "support_url": "https://github.com/ResearchForumOnline/ZSEC-Shield/issues",
        "privacy_policy_url": "https://talktoai.org/zero-browser/privacy/",
        "vulnerability_reporting_url": "https://talktoai.org/.well-known/security.txt",
    },
}
FORBIDDEN_CLAIMS = (
    "100% protection",
    "guaranteed protection",
    "replaces microsoft defender",
    "zsec provides real-time antivirus protection",
    "zsec is a maintained chromium fork",
    "guarantees anonymous browsing",
    "zsec stops every exploit",
)


class ListingMaterialError(RuntimeError):
    """A Partner Center listing draft invariant failed."""


def _load_packaging_module() -> Any:
    path = STORE_ROOT / "build_store_package.py"
    spec = importlib.util.spec_from_file_location("zsec_store_package_for_listing", path)
    if spec is None or spec.loader is None:
        raise ListingMaterialError("could not load Store packaging version contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ListingMaterialError(f"could not read listing JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ListingMaterialError(f"listing root must be an object: {path}")
    return value


def _strings(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.extend(_strings(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_strings(child))
    return found


def _require_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ListingMaterialError(f"{label} must be non-empty text")
    if value != value.strip():
        raise ListingMaterialError(f"{label} has leading or trailing whitespace")
    if len(value) > maximum:
        raise ListingMaterialError(f"{label} exceeds {maximum} characters")
    return value


def _require_string_list(value: Any, label: str, *, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ListingMaterialError(f"{label} must contain {minimum} to {maximum} entries")
    return [_require_text(item, f"{label} entry", 1000) for item in value]


def _validate_url(value: Any, label: str) -> str:
    url = _require_text(value, label, 2048)
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ListingMaterialError(f"{label} must be a public HTTPS URL without credentials")
    return url


def validate_listing(data: dict[str, Any], packaging: Any) -> dict[str, Any]:
    required_top = {
        "schema",
        "product_key",
        "language",
        "product_name",
        "source_version",
        "category",
        "listing",
        "restricted_capabilities",
        "certification",
        "age_rating",
        "pricing_availability",
        "screenshots",
    }
    if set(data) != required_top:
        raise ListingMaterialError("listing top-level fields differ from the fixed contract")
    if data["schema"] != SCHEMA:
        raise ListingMaterialError("unexpected listing schema")
    key = data["product_key"]
    if key not in packaging.PRODUCTS:
        raise ListingMaterialError(f"unknown product_key: {key!r}")
    product = packaging.PRODUCTS[key]
    if data["product_name"] != product.display_name:
        raise ListingMaterialError("product_name differs from the package display name")
    if data["language"] != "en-US":
        raise ListingMaterialError("initial listing must match the package's en-us resource")
    current_version = packaging.source_version(product)
    if data["source_version"] != current_version:
        stale = data["source_version"]
        raise ListingMaterialError(
            f"{key} listing version {stale!r} is stale; current is {current_version!r}"
        )

    listing = data["listing"]
    if not isinstance(listing, dict):
        raise ListingMaterialError("listing field must be an object")
    short = _require_text(listing.get("short_description"), "short_description", 1000)
    if len(short) > 270:
        raise ListingMaterialError(
            "short_description must remain within the recommended 270 characters"
        )
    paragraphs = _require_string_list(
        listing.get("description_paragraphs"), "description_paragraphs", minimum=2, maximum=12
    )
    description = "\n\n".join(paragraphs)
    if len(description) > 10_000:
        raise ListingMaterialError("full description exceeds 10000 characters")
    features = _require_string_list(listing.get("features"), "features", minimum=3, maximum=20)
    for feature in features:
        if len(feature) > 200:
            raise ListingMaterialError("feature exceeds 200 characters")
        if feature.startswith(("-", "*", "•")):
            raise ListingMaterialError("features must not contain their own bullet marker")
    for name, expected in EXPECTED_URLS[key].items():
        if _validate_url(listing.get(name), name) != expected:
            raise ListingMaterialError(f"{name} differs from the reviewed canonical URL")
    _require_text(listing.get("license_terms"), "license_terms", 10_000)
    _require_text(listing.get("copyright_trademark"), "copyright_trademark", 200)
    _require_text(listing.get("developed_by"), "developed_by", 255)
    keywords = _require_string_list(listing.get("keywords"), "keywords", minimum=1, maximum=7)
    for keyword in keywords:
        if len(keyword) > 40:
            raise ListingMaterialError("keyword exceeds 40 characters")
    keyword_words = {
        word.casefold()
        for keyword in keywords
        for word in re.findall(r"[A-Za-z0-9]+", keyword)
    }
    if len(keyword_words) > 21:
        raise ListingMaterialError("keywords exceed 21 unique words")
    system_requirements = _require_string_list(
        listing.get("additional_system_requirements"),
        "additional_system_requirements",
        minimum=1,
        maximum=11,
    )
    if any(len(requirement) > 200 for requirement in system_requirements):
        raise ListingMaterialError("additional system requirement exceeds 200 characters")

    capabilities = data["restricted_capabilities"]
    if not isinstance(capabilities, dict) or set(capabilities) != {"runFullTrust"}:
        raise ListingMaterialError("restricted capabilities must contain only runFullTrust")
    justification = _require_text(
        capabilities["runFullTrust"].get("justification"),
        "runFullTrust justification",
        4000,
    )
    if "runFullTrust" not in justification:
        raise ListingMaterialError("restricted-capability justification must name runFullTrust")

    certification = data["certification"]
    if not isinstance(certification, dict) or set(certification) != {
        "notes",
        "additional_testing_information",
        "test_account_required",
        "tester_steps",
        "pre_submission_gates",
    }:
        raise ListingMaterialError("certification fields differ from the fixed contract")
    notes = _require_text(certification.get("notes"), "certification notes", 2000)
    additional_testing = _require_text(
        certification.get("additional_testing_information"),
        "additional testing information",
        2000,
    )
    if certification.get("test_account_required") is not False:
        raise ListingMaterialError("test_account_required must remain false")
    tester_steps = _require_string_list(
        certification.get("tester_steps"), "tester_steps", minimum=5, maximum=20
    )
    gates = _require_string_list(
        certification.get("pre_submission_gates"), "pre_submission_gates", minimum=3, maximum=20
    )

    age = data["age_rating"]
    _require_text(age.get("questionnaire_note"), "age questionnaire note", 4000)
    if age.get("must_complete_iarc") is not True or not isinstance(age.get("facts"), dict):
        raise ListingMaterialError("age rating must require IARC and include factual inputs")
    facts = age["facts"]
    if key == "browser":
        if facts.get("general_web_browser") is not True:
            raise ListingMaterialError("browser listing must disclose general web access")
        if facts.get("third_party_user_generated_content_accessible") is not True:
            raise ListingMaterialError(
                "browser listing must disclose third-party user content access"
            )
        if facts.get("parental_controls") is not False:
            raise ListingMaterialError("browser listing must not claim parental controls")
    elif facts.get("general_web_browser") is not False:
        raise ListingMaterialError("antivirus listing must not claim to be a web browser")

    pricing = data["pricing_availability"]
    if (
        pricing.get("base_price") != "Free"
        or pricing.get("free_trial") is not False
        or pricing.get("in_app_purchases") is not False
        or pricing.get("subscription") is not False
    ):
        raise ListingMaterialError(
            "pricing must remain Free with no trial, purchases, or subscription"
        )
    checklist = _require_string_list(
        pricing.get("checklist"), "pricing checklist", minimum=4, maximum=20
    )

    screenshots = data["screenshots"]
    if screenshots.get("device_family") != "Desktop" or screenshots.get("format") != "PNG":
        raise ListingMaterialError("screenshots must target Desktop and use PNG")
    dimensions = screenshots.get("minimum_dimensions")
    if (
        not isinstance(dimensions, list)
        or len(dimensions) != 2
        or not all(isinstance(value, int) for value in dimensions)
        or dimensions[0] < 1366
        or dimensions[1] < 768
    ):
        raise ListingMaterialError("desktop screenshot minimum must be at least 1366x768")
    if screenshots.get("max_file_size_mb") != 50:
        raise ListingMaterialError("screenshot size limit must remain 50 MB")
    if screenshots.get("required_minimum") != 1 or screenshots.get("maximum_count") != 10:
        raise ListingMaterialError("screenshot count limits differ from Microsoft guidance")
    recommended = screenshots.get("recommended_count")
    if not isinstance(recommended, int) or not 4 <= recommended <= 10:
        raise ListingMaterialError("provide at least four recommended Desktop screenshots")
    capture = _require_string_list(
        screenshots.get("capture_requirements"), "capture_requirements", minimum=4, maximum=20
    )
    shots = screenshots.get("shots")
    if not isinstance(shots, list) or len(shots) != recommended:
        raise ListingMaterialError("screenshot plan must match recommended_count")
    identifiers: set[str] = set()
    for shot in shots:
        if not isinstance(shot, dict) or set(shot) != {"id", "caption", "content"}:
            raise ListingMaterialError("screenshot entry fields differ from the fixed contract")
        identifier = _require_text(shot["id"], "screenshot id", 80)
        if identifier in identifiers:
            raise ListingMaterialError("screenshot ids must be unique")
        identifiers.add(identifier)
        _require_text(shot["caption"], "screenshot caption", 200)
        _require_text(shot["content"], "screenshot content", 500)

    combined = "\n".join(_strings(data)).casefold()
    for claim in FORBIDDEN_CLAIMS:
        if claim in combined:
            raise ListingMaterialError(f"forbidden unsupported claim appears in listing: {claim!r}")
    if "partner_center_" in combined or "todo" in combined or "tbd" in combined:
        raise ListingMaterialError("listing contains an unresolved placeholder")
    if key == "antivirus":
        for phrase in ("not a primary antivirus", "post-change", "microsoft defender"):
            if phrase not in combined:
                raise ListingMaterialError(f"antivirus evidence boundary is missing: {phrase!r}")
    else:
        for phrase in (
            "not a separately maintained chromium fork",
            "third-party websites",
            "webview2",
        ):
            if phrase not in combined:
                raise ListingMaterialError(f"browser evidence boundary is missing: {phrase!r}")

    return {
        "product_key": key,
        "source_version": current_version,
        "short_description_characters": len(short),
        "description_characters": len(description),
        "feature_count": len(features),
        "keyword_count": len(keywords),
        "keyword_unique_word_count": len(keyword_words),
        "additional_system_requirement_count": len(system_requirements),
        "certification_notes_characters": len(notes),
        "additional_testing_information_characters": len(additional_testing),
        "tester_step_count": len(tester_steps),
        "pre_submission_gate_count": len(gates),
        "pricing_check_count": len(checklist),
        "screenshot_count": len(shots),
        "run_full_trust_justification_characters": len(justification),
        "capture_requirement_count": len(capture),
    }


def load_and_validate() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    packaging = _load_packaging_module()
    paths = sorted(LISTINGS_ROOT.glob("*.json"))
    if [path.name for path in paths] != ["zsec-antivirus.en-US.json", "zsec-browser.en-US.json"]:
        raise ListingMaterialError("listing directory must contain exactly the two reviewed drafts")
    listings = [_read(path) for path in paths]
    reports = [validate_listing(listing, packaging) for listing in listings]
    report = {
        "schema": "zsec.microsoft-store-listing-validation.v1",
        "listing_count": len(listings),
        "products": reports,
        "submission_status": "draft-not-submitted",
        "identity_status": "Partner Center identities still required",
    }
    return listings, report


def _bullets(values: list[str]) -> list[str]:
    return [f"- {value}" for value in values]


def render(listings: list[dict[str, Any]]) -> str:
    lines = [
        "# Microsoft Store Partner Center draft — not submitted",
        "",
        "These copy-and-paste materials are validated against the current ZSEC source versions.",
        "They do not contain or replace the two Partner Center package identities. Do not upload",
        "or submit until every pre-submission gate below passes against the exact Store package.",
        "",
        "Microsoft field limits used by the validator:",
        "",
        "- Description: 10,000 characters maximum.",
        "- Short description: 1,000 maximum; kept below the recommended 270 characters.",
        "- Features: up to 20, each no more than 200 characters.",
        "- Keywords: up to 7 terms, each no more than 40 characters, with no more than",
        "  21 unique words across all terms.",
        "- Additional system requirements: up to 11 items, each no more than 200 characters.",
        "- Copyright/trademark: 200 characters maximum; Developed by: 255 maximum.",
        "- Additional Testing Information / Notes for certification: 2,000 characters maximum.",
        "- Desktop screenshots: PNG, at least 1366x768, no more than 50 MB; one required,",
        "  four or more recommended, and ten maximum.",
        "- IARC questionnaire: required for the first submission.",
        "- Restricted-capability declaration: required because both manifests use runFullTrust.",
        "",
    ]
    for data in listings:
        listing = data["listing"]
        certification = data["certification"]
        pricing = data["pricing_availability"]
        screenshots = data["screenshots"]
        lines.extend(
            [
                f"## {data['product_name']}",
                "",
                f"Source version: `{data['source_version']}`",
                f"Listing language: `{data['language']}`",
                f"Suggested category: `{data['category']['primary']}`",
                "",
                data["category"]["selection_note"],
                "",
                "### Short description",
                "",
                listing["short_description"],
                "",
                "### Full description",
                "",
                "\n\n".join(listing["description_paragraphs"]),
                "",
                "### Product features",
                "",
                *_bullets(listing["features"]),
                "",
                "### URLs and license",
                "",
                f"- Website: {listing['website_url']}",
                f"- Support: {listing['support_url']}",
                f"- Privacy policy: {listing['privacy_policy_url']}",
                f"- Vulnerability reporting: {listing['vulnerability_reporting_url']}",
                f"- License terms: {listing['license_terms']}",
                f"- Copyright/trademark: {listing['copyright_trademark']}",
                f"- Developed by: {listing['developed_by']}",
                "",
                "### Discovery and system requirements",
                "",
                "Keywords (enter as separate terms):",
                "",
                *_bullets(listing["keywords"]),
                "",
                "Additional system requirements (enter as separate items):",
                "",
                *_bullets(listing["additional_system_requirements"]),
                "",
                "### Restricted capability: runFullTrust",
                "",
                data["restricted_capabilities"]["runFullTrust"]["justification"],
                "",
                "### Additional Testing Information",
                "",
                certification["additional_testing_information"],
                "",
                "### Supporting internal certification detail",
                "",
                certification["notes"],
                "",
                "Test account required: **No**",
                "",
                "### Certification tester steps",
                "",
                *[
                    f"{number}. {step}"
                    for number, step in enumerate(certification["tester_steps"], start=1)
                ],
                "",
                "### Age and content notes",
                "",
                data["age_rating"]["questionnaire_note"],
                "",
                "Factual questionnaire inputs:",
                "",
                *[
                    f"- `{name}`: `{str(value).lower()}`"
                    for name, value in data["age_rating"]["facts"].items()
                ],
                "",
                "### Free pricing and availability checklist",
                "",
                f"Base price: **{pricing['base_price']}**",
                "Trial, purchases, and subscription: **None**",
                "",
                *_bullets(pricing["checklist"]),
                "",
                "### Screenshot requirements and plan",
                "",
                (
                    f"Desktop `{screenshots['format']}`, minimum "
                    f"`{screenshots['minimum_dimensions'][0]}x"
                    f"{screenshots['minimum_dimensions'][1]}`, "
                    f"maximum `{screenshots['max_file_size_mb']} MB`; plan: "
                    f"`{screenshots['recommended_count']}` screenshots."
                ),
                "",
                *_bullets(screenshots["capture_requirements"]),
                "",
            ]
        )
        for number, shot in enumerate(screenshots["shots"], start=1):
            lines.extend(
                [
                    f"{number}. **{shot['id']}** — {shot['caption']}",
                    f"   Capture: {shot['content']}",
                ]
            )
        lines.extend(
            [
                "",
                "### Pre-submission gates",
                "",
                *_bullets(certification["pre_submission_gates"]),
                "",
            ]
        )
    lines.extend(
        [
            "## Authoritative Microsoft guidance",
            "",
            "- Store listing fields: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/add-and-edit-store-listing-info",
            "- Screenshots and images: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/screenshots-and-images",
            "- Age ratings: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/age-ratings",
            "- Submission options and certification notes: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/manage-submission-options",
            "- App capabilities: https://learn.microsoft.com/windows/apps/package-and-deploy/app-capability-declarations",
            "- Package requirements: https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/app-package-requirements",
            "",
        ]
    )
    return "\n".join(lines)


def _copy_block(lines: list[str], heading: str, value: str, maximum: int) -> None:
    lines.extend(
        [
            f"### {heading} — {len(value):,}/{maximum:,} characters",
            "",
            value,
            "",
        ]
    )


def render_field_sheet(listings: list[dict[str, Any]]) -> str:
    """Render a concise, copy-ready Partner Center field sheet."""

    packaging = _load_packaging_module()
    lines = [
        "# Microsoft Store field sheet — offline draft, not submitted",
        "",
        "Generated from the validated repository listing sources. No Partner Center field",
        "was edited and no submission was made. Counts include spaces and line breaks",
        "exactly as rendered below.",
        "",
        "Microsoft currently documents 10,000 characters for Description, 1,000 for",
        "Short description (under 270 recommended), 20 Product features at 200 each,",
        "7 Keywords at 40 each and 21 unique words total, 11 Additional system",
        "requirements at 200 each, 200 for Copyright/trademark, 255 for Developed by,",
        "10,000 for license terms, and 2,000 for Notes for certification. Partner Center",
        "currently presents the last field under Additional Testing Information.",
        "",
        "The public Microsoft page requires a justification for each restricted",
        "capability but does not state a character maximum; this repository enforces a",
        "conservative 4,000-character safety cap for each runFullTrust justification.",
        "",
    ]
    for data in listings:
        listing = data["listing"]
        certification = data["certification"]
        version = data["source_version"]
        description = "\n\n".join(listing["description_paragraphs"])
        lines.extend(
            [
                f"## {data['product_name']}",
                "",
                f"- Product name: `{data['product_name']}` (select the reserved name)",
                f"- Language: `{data['language']}`",
                f"- Source version: `{version}`",
                f"- Store package version: `{packaging.store_version(version)}`",
                f"- Category: `{data['category']['primary']}` (confirm the closest current portal option)",
                "- Price: `Free`; no trial, subscription, add-on, or in-app purchase",
                "- Device family: `Windows Desktop` only",
                "- What's new in this version: leave blank for the first submission",
                "",
            ]
        )
        _copy_block(lines, "Short description", listing["short_description"], 1000)
        _copy_block(lines, "Description", description, 10_000)
        lines.extend([f"### Product features — {len(listing['features'])}/20 entries", ""])
        for number, feature in enumerate(listing["features"], start=1):
            lines.append(f"{number}. [{len(feature)}/200] {feature}")
        lines.extend(["", f"### Keywords — {len(listing['keywords'])}/7 terms", ""])
        for keyword in listing["keywords"]:
            lines.append(f"- [{len(keyword)}/40] {keyword}")
        unique_words = {
            word.casefold()
            for keyword in listing["keywords"]
            for word in re.findall(r"[A-Za-z0-9]+", keyword)
        }
        lines.extend(["", f"Unique keyword words: `{len(unique_words)}/21`", ""])
        lines.extend(
            [
                (
                    "### Additional system requirements — "
                    f"{len(listing['additional_system_requirements'])}/11 entries"
                ),
                "",
            ]
        )
        for requirement in listing["additional_system_requirements"]:
            lines.append(f"- [{len(requirement)}/200] {requirement}")
        lines.extend(
            [
                "",
                "### URLs",
                "",
                f"- Website: {listing['website_url']}",
                f"- Support: {listing['support_url']}",
                f"- Privacy policy: {listing['privacy_policy_url']}",
                f"- Vulnerability reporting: {listing['vulnerability_reporting_url']}",
                "",
            ]
        )
        _copy_block(lines, "Applicable license terms", listing["license_terms"], 10_000)
        _copy_block(
            lines,
            "Copyright and trademark info",
            listing["copyright_trademark"],
            200,
        )
        _copy_block(lines, "Developed by", listing["developed_by"], 255)
        justification = data["restricted_capabilities"]["runFullTrust"]["justification"]
        _copy_block(lines, "runFullTrust justification (repository cap)", justification, 4000)
        _copy_block(
            lines,
            "Additional Testing Information",
            certification["additional_testing_information"],
            2000,
        )
        lines.extend(
            [
                "### IARC facts — answer from submitted behavior, not a target rating",
                "",
                data["age_rating"]["questionnaire_note"],
                "",
                *[
                    f"- `{name}`: `{str(value).lower()}`"
                    for name, value in data["age_rating"]["facts"].items()
                ],
                "",
                "### Screenshot gate",
                "",
                (
                    f"Provide {data['screenshots']['recommended_count']} truthful Desktop PNGs "
                    "from the exact Store package candidate. At least one is required; four or "
                    "more are recommended; ten is the maximum. Do not reuse development-path "
                    "captures as Store evidence."
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## Authoritative field guidance",
            "",
            "- https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/add-and-edit-store-listing-info",
            "- https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/add-additional-information",
            "- https://learn.microsoft.com/windows/apps/publish/publish-your-app/msix/manage-submission-options",
            "",
            "## Stop conditions",
            "",
            "Do not submit until the exact Partner Center identities, Store package upload,",
            "WACK review, clean-VM packaged-path acceptance, current URL review, screenshots,",
            "IARC answers, market selection, and manual publishing hold have all been reviewed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="rewrite the checked-in Markdown draft"
    )
    parser.add_argument(
        "--write-fields",
        action="store_true",
        help="write the ignored, copy-ready Partner Center field sheet under out/",
    )
    args = parser.parse_args()
    listings, report = load_and_validate()
    document = render(listings)
    field_document = render_field_sheet(listings)
    report["rendered_markdown_sha256"] = hashlib.sha256(document.encode("utf-8")).hexdigest()
    report["field_sheet_markdown_sha256"] = hashlib.sha256(
        field_document.encode("utf-8")
    ).hexdigest()
    if args.write:
        OUTPUT_PATH.write_text(document, encoding="utf-8", newline="\n")
    elif not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_text(encoding="utf-8") != document:
        raise ListingMaterialError(
            "PARTNER_CENTER_DRAFT.md is stale; run listing_materials.py --write"
        )
    if args.write_fields:
        FIELD_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        FIELD_OUTPUT_PATH.write_text(field_document, encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ListingMaterialError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
