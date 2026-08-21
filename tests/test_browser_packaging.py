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
        archived_manifest = json.loads(bundle.read("manifest.json"))
        assert archived_manifest["manifest_version"] == 3
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in bundle.infolist())

    release = json.loads(metadata.read_text(encoding="utf-8"))
    assert release["artifact"] == first.name
    assert first.name.startswith("zsec-browser-shields-")
    assert release["product"] == "ZSEC Browser Shields"
    assert release["sha256"] == digest
    assert release["signed_store_package"] is False
    assert release["installation_channel"] == "unpacked-developer-preview"
