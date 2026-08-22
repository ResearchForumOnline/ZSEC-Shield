from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "specs" / "journalist-high-risk-profile.v1.json"
DOCUMENT_PATH = ROOT / "docs" / "JOURNALIST_HIGH_RISK_PROFILE.md"


def load_profile() -> dict[str, Any]:
    value = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_high_risk_profile_has_fail_closed_claim_boundary() -> None:
    profile = load_profile()
    assert profile["schema"] == "zsec.journalist-high-risk-profile.v1"
    assert profile["profile_id"] == "journalist-high-risk"
    assert profile["profile_version"] == 1
    assert profile["status"] == "design-and-current-control-contract"
    assert profile["claim_boundary"] == {
        "existing_primary_antivirus_required": True,
        "mercenary_spyware_detection": False,
        "mobile_zero_click_coverage": False,
        "pegasus_immunity": False,
        "threat_actor_attribution": False,
        "zba_is_cipher": False,
    }


def test_zba_role_is_provenance_not_security_primitive() -> None:
    role = load_profile()["zba_role"]
    assert set(role["allowed"]) == {
        "typed lifecycle state",
        "provenance commitment",
        "evidence status vocabulary",
    }
    assert set(role["prohibited"]) == {
        "cryptographic cipher",
        "entropy or key derivation",
        "exploit mitigation",
        "malware classification",
        "threat actor attribution",
    }


def test_control_contract_is_complete_and_source_bound() -> None:
    profile = load_profile()
    controls = profile["controls"]
    assert isinstance(controls, list) and controls
    control_by_id = {control["id"]: control for control in controls}
    assert len(control_by_id) == len(controls)

    required = {
        "browser-evergreen-runtime",
        "browser-host-and-permission-boundary",
        "browser-extension-identity",
        "browser-strict-third-party-active-content",
        "browser-download-confirmation",
        "browser-clear-history-on-exit",
        "browser-ephemeral-session",
        "browser-enhanced-security-jit-reduction",
        "windows-defender-backed-real-time",
        "windows-security-posture",
        "incident-response-preservation",
        "account-fido-and-advanced-protection",
        "apple-mobile-lockdown-and-expert-response",
        "zsec-native-primary-antivirus",
        "zba-security-receipts",
    }
    assert set(control_by_id) == required

    allowed_actions = {
        "already_enforced",
        "implement_now",
        "release_gated",
        "external_required",
    }
    allowed_states = {
        "implemented",
        "partial",
        "not_implemented",
        "external_required",
        "outside_zsec",
    }
    source_ids = {source["id"] for source in profile["sources"]}

    for control in controls:
        assert control["area"]
        assert control["decision"]
        assert control["action_class"] in allowed_actions
        assert control["current_state"] in allowed_states
        assert control["source_ids"]
        assert set(control["source_ids"]) <= source_ids

        if control["action_class"] == "release_gated":
            assert control.get("gate")
        if control["current_state"] not in {"implemented", "partial"}:
            continue

        evidence = control.get("evidence")
        assert isinstance(evidence, list) and evidence
        for item in evidence:
            relative = PurePosixPath(item["path"])
            assert not relative.is_absolute()
            assert ".." not in relative.parts
            path = ROOT.joinpath(*relative.parts)
            assert path.is_file(), path
            text = path.read_text(encoding="utf-8")
            markers = item.get("contains")
            assert isinstance(markers, list) and markers
            for marker in markers:
                assert marker in text, f"{marker!r} missing from {relative}"

    assert control_by_id["browser-enhanced-security-jit-reduction"]["action_class"] == (
        "release_gated"
    )
    assert control_by_id["windows-defender-backed-real-time"]["current_state"] == (
        "external_required"
    )
    assert control_by_id["zsec-native-primary-antivirus"]["current_state"] == (
        "not_implemented"
    )


def test_authoritative_sources_are_https_and_uniquely_named() -> None:
    sources = load_profile()["sources"]
    source_ids = [source["id"] for source in sources]
    urls = [source["url"] for source in sources]
    assert len(source_ids) == len(set(source_ids))
    assert len(urls) == len(set(urls))
    assert all(url.startswith("https://") for url in urls)
    assert {
        "Apple",
        "Google Threat Analysis Group",
        "Microsoft",
        "UK National Cyber Security Centre",
        "Citizen Lab",
        "Amnesty International Security Lab",
        "Access Now",
    } <= {source["authority"] for source in sources}


def test_human_profile_states_the_operational_and_claim_boundaries() -> None:
    document = DOCUMENT_PATH.read_text(encoding="utf-8")
    normalized_document = " ".join(document.split())
    required_phrases = (
        "## Implement-now versus release-gated matrix",
        "## Incident-response handoff",
        "## ZBA and ZMath: unique value with a strict boundary",
        "claim that ZSEC detects or prevents Pegasus",
        "The current ZSEC Antivirus companion",
        "Defender as the supported real-time enforcement layer",
        "sandbox_attestation_complete: false",
        "public indicators alone cannot establish that a device is uncompromised",
        "ZBA must never be used as a malware score",
    )
    for phrase in required_phrases:
        assert phrase in normalized_document

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include specs *.md *.json" in manifest
