from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "browser_release.py"
SPEC = importlib.util.spec_from_file_location("zsec_browser_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
INCLUDE = MODULE.INCLUDE
build = MODULE.build


def test_browser_archive_is_complete_deterministic_and_explicitly_unsigned(tmp_path: Path) -> None:
    first, checksum, metadata = build(tmp_path / "first")
    second, _, _ = build(tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert checksum.read_text(encoding="ascii") == f"{digest}  {first.name}\n"

    with zipfile.ZipFile(first) as bundle:
        assert bundle.namelist() == sorted(INCLUDE)
        assert "src/high-risk-browsing.js" in bundle.namelist()
        assert "src/runtime-health.js" in bundle.namelist()
        assert "src/settings-transaction.js" in bundle.namelist()
        assert "MERCENARY_SPYWARE_DEFENCE.md" in bundle.namelist()
        assert "easylist.lock.json" in bundle.namelist()
        assert "rules/easylist.json" in bundle.namelist()
        assert "third_party/easylist-20260817.txt" in bundle.namelist()
        assert "third_party/easylist-provenance.json" in bundle.namelist()
        assert "third_party/EASYLIST-LICENSE.txt" in bundle.namelist()
        assert "src/youtube-cosmetic-rules.js" in bundle.namelist()
        archived_manifest = json.loads(bundle.read("manifest.json"))
        assert archived_manifest["manifest_version"] == 3
        assert archived_manifest["version"] == "0.5.2"
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in bundle.infolist())

        easylist_bytes = bundle.read("rules/easylist.json")
        easylist_rules = json.loads(easylist_bytes)
        retained_source = bundle.read("third_party/easylist-20260817.txt")
        easylist_lock = json.loads(bundle.read("easylist.lock.json"))
        provenance = json.loads(bundle.read("third_party/easylist-provenance.json"))
        assert len(easylist_rules) == easylist_lock["ruleset"]["rule_count"] == 49_464
        assert hashlib.sha256(easylist_bytes).hexdigest() == (
            easylist_lock["ruleset"]["output_sha256"]
        )
        assert hashlib.sha256(retained_source).hexdigest() == (
            easylist_lock["ruleset"]["source_sha256"]
        )
        assert provenance["output"]["sha256"] == easylist_lock["ruleset"]["output_sha256"]
        assert provenance["output"]["rules"] == 49_464
        assert easylist_lock["ruleset"]["acceptable_ads_included"] is False
        assert easylist_lock["policy"]["acceptable_ads_default"] is False
        assert provenance["policy"]["acceptable_ads_included"] is False
        source_text = retained_source.decode("utf-8").casefold()
        assert "allow nonintrusive advertising" not in source_text
        assert "acceptable ads" not in source_text

    release = json.loads(metadata.read_text(encoding="utf-8"))
    assert release["artifact"] == first.name
    assert first.name.startswith("zsec-browser-shields-")
    assert release["product"] == "ZSEC Browser Shields"
    assert release["version"] == "0.5.2"
    assert release["sha256"] == digest
    assert release["signed_store_package"] is False
    assert release["installation_channel"] == "unpacked-community"
    assert release["easylist"]["rule_count"] == 49_464
    assert release["easylist"]["output_sha256"] == (
        "81d9ba06866a37595397ce62cbc4ccd310c8d9bdc6ed92c9b8b9c89b194ea9d6"
    )
    assert release["easylist"]["acceptable_ads_included"] is False
    assert release["easylist"]["enabled_by_default"] is True
    assert release["easylist"]["upstream_release_tag"] == "adblockplus-4.43.2"

    with zipfile.ZipFile(first) as bundle:
        for name, file_metadata in release["easylist"]["files"].items():
            archived = bundle.read(name)
            assert len(archived) == file_metadata["bytes"]
            assert hashlib.sha256(archived).hexdigest() == file_metadata["sha256"]
