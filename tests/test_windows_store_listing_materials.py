from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "packaging" / "windows-store" / "listing_materials.py"
SPEC = importlib.util.spec_from_file_location("zsec_store_listing_materials", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
materials = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = materials
SPEC.loader.exec_module(materials)


def _validated() -> tuple[list[dict[str, object]], object, dict[str, object]]:
    packaging = materials._load_packaging_module()
    listings, report = materials.load_and_validate()
    return listings, packaging, report


def test_partner_center_materials_are_current_and_rendered() -> None:
    listings, _, report = _validated()
    assert report["submission_status"] == "draft-not-submitted"
    assert report["identity_status"] == "Partner Center identities still required"
    assert [item["product_key"] for item in listings] == ["antivirus", "browser"]
    rendered = materials.render(listings)
    assert materials.OUTPUT_PATH.read_text(encoding="utf-8") == rendered
    assert "# Microsoft Store Partner Center draft — not submitted" in rendered
    assert "Restricted capability: runFullTrust" in rendered
    assert "Additional Testing Information" in rendered

    field_sheet = materials.render_field_sheet(listings)
    assert "ZSEC Antivirus" in field_sheet
    assert "0.3.31.0" in field_sheet
    assert "ZSEC Browser" in field_sheet
    assert "0.3.26.0" in field_sheet
    assert "offline draft, not submitted" in field_sheet


def test_listing_limits_and_truth_boundaries_are_enforced() -> None:
    listings, packaging, _ = _validated()
    for listing in listings:
        report = materials.validate_listing(listing, packaging)
        assert report["short_description_characters"] <= 270
        assert report["description_characters"] <= 10_000
        assert report["feature_count"] <= 20
        assert report["keyword_count"] <= 7
        assert report["keyword_unique_word_count"] <= 21
        assert report["additional_system_requirement_count"] <= 11
        assert report["additional_testing_information_characters"] <= 2000
        assert report["screenshot_count"] >= 4


def test_additional_testing_information_limit_is_enforced() -> None:
    listings, packaging, _ = _validated()
    too_long = copy.deepcopy(listings[0])
    too_long["certification"]["additional_testing_information"] = "x" * 2001
    with pytest.raises(materials.ListingMaterialError, match="additional testing information"):
        materials.validate_listing(too_long, packaging)


def test_keyword_contract_is_enforced() -> None:
    listings, packaging, _ = _validated()
    too_many = copy.deepcopy(listings[1])
    too_many["listing"]["keywords"] = [f"term {index}" for index in range(8)]
    with pytest.raises(materials.ListingMaterialError, match="keywords must contain"):
        materials.validate_listing(too_many, packaging)


def test_stale_listing_version_is_rejected() -> None:
    listings, packaging, _ = _validated()
    stale = copy.deepcopy(listings[0])
    stale["source_version"] = "0.0.1"
    with pytest.raises(materials.ListingMaterialError, match=r"listing version.*is stale"):
        materials.validate_listing(stale, packaging)


def test_unsupported_security_claim_is_rejected() -> None:
    listings, packaging, _ = _validated()
    misleading = copy.deepcopy(listings[0])
    misleading["listing"]["description_paragraphs"].append(
        "ZSEC provides real-time antivirus protection."
    )
    with pytest.raises(materials.ListingMaterialError, match="forbidden unsupported claim"):
        materials.validate_listing(misleading, packaging)


def test_browser_cannot_hide_unrestricted_web_content() -> None:
    listings, packaging, _ = _validated()
    browser = copy.deepcopy(listings[1])
    browser["age_rating"]["facts"]["general_web_browser"] = False
    with pytest.raises(materials.ListingMaterialError, match="general web access"):
        materials.validate_listing(browser, packaging)


def test_free_pricing_cannot_drift_to_monetization() -> None:
    listings, packaging, _ = _validated()
    monetized = copy.deepcopy(listings[1])
    monetized["pricing_availability"]["in_app_purchases"] = True
    with pytest.raises(materials.ListingMaterialError, match="pricing must remain Free"):
        materials.validate_listing(monetized, packaging)


def test_reviewed_privacy_and_support_urls_are_exact() -> None:
    listings, packaging, _ = _validated()
    changed = copy.deepcopy(listings[0])
    changed["listing"]["privacy_policy_url"] = "https://example.com/privacy"
    with pytest.raises(materials.ListingMaterialError, match="reviewed canonical URL"):
        materials.validate_listing(changed, packaging)
