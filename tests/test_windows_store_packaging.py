from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "packaging" / "windows-store" / "build_store_package.py"
SPEC = importlib.util.spec_from_file_location("zsec_windows_store", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
store = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = store
SPEC.loader.exec_module(store)


def _write(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _identity(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "antivirus": {
                    "identity_name": "ResearchForumOnline.ZSECAntivirus",
                    "publisher": "CN=11111111-1111-1111-1111-111111111111",
                    "publisher_display_name": "Research Forum Online",
                },
                "browser": {
                    "identity_name": "ResearchForumOnline.ZSECBrowser",
                    "publisher": "CN=11111111-1111-1111-1111-111111111111",
                    "publisher_display_name": "Research Forum Online",
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _payload(tmp_path: Path, product_key: str) -> Path:
    product = store.PRODUCTS[product_key]
    version = store.source_version(product)
    root = tmp_path / f"{product_key}-payload"
    content = root / "payload" if product_key == "browser" else root
    files = {
        product.executable: b"MZ\x00store-test-launcher",
    }
    if product_key == "antivirus":
        files["Engine/zsec-shield.exe"] = b"MZ\x00store-test-engine"
        files["Tools/Start-ZsecAntivirusCompanion.ps1"] = b"# test\n"
        manifest = {
            "schema": product.manifest_schema,
            "version": version,
            "entrypoints": {"desktop": product.executable, "engine": "Engine/zsec-shield.exe"},
        }
    else:
        files["App/WebView2Loader.dll"] = b"MZ\x00store-test-loader"
        manifest = {
            "schema": product.manifest_schema,
            "version": version,
            "launcher": product.executable,
        }
    entries = []
    for relative, data in files.items():
        digest = _write(content.joinpath(*relative.split("/")), data)
        entry = {"path": relative, "sha256": digest}
        entry["bytes" if product_key == "browser" else "size"] = len(data)
        entries.append(entry)
    manifest["files"] = entries
    root.mkdir(parents=True, exist_ok=True)
    (root / product.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def _layout_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_repository_store_contract_is_minimal_and_current() -> None:
    result = store.validate_repository()
    assert result["identity_status"].startswith("Partner Center values required")
    assert set(result["products"]) == {"antivirus", "browser"}
    for product in result["products"].values():
        assert product["store_version"].endswith(".0")
        assert product["capabilities"] == ["runFullTrust"]


def test_partner_center_placeholders_are_rejected() -> None:
    example = json.loads(
        (ROOT / "packaging" / "windows-store" / "store-identity.example.json").read_text(
            encoding="utf-8"
        )
    )
    with pytest.raises(store.StorePackageError, match="still a placeholder"):
        store.validate_identity(example["antivirus"])


@pytest.mark.parametrize("product_key", ["antivirus", "browser"])
def test_store_layout_staging_is_deterministic(tmp_path: Path, product_key: str) -> None:
    product = store.PRODUCTS[product_key]
    payload = _payload(tmp_path, product_key)
    identity = _identity(tmp_path / "identity.json")
    first = tmp_path / "first"
    second = tmp_path / "second"
    store.stage_layout(product, payload, identity, first)
    store.stage_layout(product, payload, identity, second)
    assert _layout_hashes(first) == _layout_hashes(second)
    provenance = store.validate_staged_layout(first, product)
    assert provenance["capabilities"] == ["runFullTrust"]
    assert provenance["store_version"] == store.store_version(store.source_version(product))


def test_stale_browser_payload_is_rejected(tmp_path: Path) -> None:
    payload = _payload(tmp_path, "browser")
    manifest_path = payload / "build-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "0.0.1"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(store.StorePackageError, match="does not match current source version"):
        store.stage_layout(
            store.PRODUCTS["browser"],
            payload,
            _identity(tmp_path / "identity.json"),
            tmp_path / "layout",
        )


@pytest.mark.parametrize("product_key", ["antivirus", "browser"])
def test_windows_sdk_makeappx_accepts_rendered_desktop_manifest(
    tmp_path: Path, product_key: str
) -> None:
    makeappx = store.find_makeappx()
    if makeappx is None:
        pytest.skip("Windows SDK MakeAppx.exe is not installed")
    product = store.PRODUCTS[product_key]
    layout = tmp_path / "layout"
    store.stage_layout(
        product,
        _payload(tmp_path, product_key),
        _identity(tmp_path / "identity.json"),
        layout,
    )
    output = tmp_path / "schema-validation.msix"
    artifact = store.pack_msix(layout, product, output, makeappx)
    assert output.is_file()
    assert artifact["signed"] is False
    assert artifact["submission_status"] == "not-submitted"
