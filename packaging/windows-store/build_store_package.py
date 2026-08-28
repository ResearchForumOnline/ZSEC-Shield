"""Validate and stage ZSEC desktop payloads for Microsoft Store MSIX packaging.

This tool intentionally does not invent Partner Center identity values, sign a
package, or submit anything.  It produces a deterministic package layout and,
when a Windows SDK MakeAppx.exe is available, an unsigned Store-upload MSIX.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from html import escape
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
STORE_ROOT = Path(__file__).resolve().parent
FOUNDATION_NS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
RESTRICTED_NS = (
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
)
DESKTOP_NS = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
UAP11_NS = "http://schemas.microsoft.com/appx/manifest/uap/windows10/11"
PLACEHOLDER_TOKEN = "PARTNER_CENTER_"
IDENTITY_NAME_PATTERN = re.compile(r"[A-Za-z0-9.-]{3,50}")
VERSION_PATTERN = re.compile(r"0|[1-9][0-9]{0,4}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
FORBIDDEN_PATH_PARTS = {"", ".", ".."}
ANTIVIRUS_REQUIRED_RUNTIME_PATHS = frozenset(
    PurePosixPath(path)
    for path in (
        "App/ZSEC Antivirus.exe",
        "Engine/zsec-shield.exe",
        "Tools/Get-ZsecAntivirusCompanionStatus.ps1",
        "Tools/Install-ZsecAntivirusCompanion.ps1",
        "Tools/Invoke-ZsecWindowsProtectionAction.ps1",
        "Tools/Start-ZsecAntivirusCompanion.ps1",
        "Tools/Sync-ZsecAntivirusCompanion.ps1",
        "Tools/Uninstall-ZsecAntivirusCompanion.ps1",
    )
)


class StorePackageError(RuntimeError):
    """A Store package invariant was not satisfied."""


@dataclass(frozen=True)
class Product:
    key: str
    display_name: str
    template: Path
    asset_directory: Path
    executable: str
    manifest_schema: str
    manifest_name: str


PRODUCTS = {
    "antivirus": Product(
        key="antivirus",
        display_name="ZSEC Antivirus",
        template=STORE_ROOT / "manifests" / "zsec-antivirus.appxmanifest.xml.in",
        asset_directory=STORE_ROOT / "assets" / "antivirus",
        executable="App/ZSEC Antivirus.exe",
        manifest_schema="zsec.antivirus.windows-desktop-distribution.v1",
        manifest_name="DESKTOP-MANIFEST.json",
    ),
    "browser": Product(
        key="browser",
        display_name="ZSEC Browser",
        template=STORE_ROOT / "manifests" / "zsec-browser.appxmanifest.xml.in",
        asset_directory=STORE_ROOT / "assets" / "browser",
        executable="App/ZSEC Browser.exe",
        manifest_schema="zsec.browser.desktop-preview-build.v2",
        manifest_name="build-manifest.json",
    ),
}

ASSET_SIZES = {
    "Square44x44Logo.png": (44, 44),
    "StoreLogo.png": (50, 50),
    "Square150x150Logo.png": (150, 150),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StorePackageError(f"could not read JSON: {path}") from exc


def source_version(product: Product) -> str:
    if product.key == "antivirus":
        with (ROOT / "pyproject.toml").open("rb") as stream:
            value = tomllib.load(stream).get("project", {}).get("version")
    else:
        build_script = (ROOT / "windows" / "browser" / "Build-ZsecBrowserPreview.ps1").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r'^\$ProductVersion\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
            build_script,
            flags=re.MULTILINE,
        )
        value = match.group(1) if match else None
    if not isinstance(value, str):
        raise StorePackageError(f"could not determine {product.display_name} version")
    return value


def store_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) not in {3, 4} or any(VERSION_PATTERN.fullmatch(part) is None for part in parts):
        raise StorePackageError(f"version is not MSIX-compatible: {version!r}")
    if len(parts) == 3:
        parts.append("0")
    return ".".join(str(int(part)) for part in parts)


def validate_identity(identity: Any) -> dict[str, str]:
    if not isinstance(identity, dict):
        raise StorePackageError("identity entry must be a JSON object")
    expected = {"identity_name", "publisher", "publisher_display_name"}
    if set(identity) != expected:
        raise StorePackageError(f"identity entry must contain exactly {sorted(expected)}")
    values: dict[str, str] = {}
    for name in sorted(expected):
        value = identity[name]
        if not isinstance(value, str) or not value.strip():
            raise StorePackageError(f"identity {name} must be a non-empty string")
        if PLACEHOLDER_TOKEN in value:
            raise StorePackageError(
                f"identity {name} is still a placeholder; copy the exact value from Partner Center"
            )
        if any(ord(character) < 32 for character in value):
            raise StorePackageError(f"identity {name} contains a control character")
        values[name] = value
    if IDENTITY_NAME_PATTERN.fullmatch(values["identity_name"]) is None:
        raise StorePackageError("identity_name is not a valid MSIX package identity name")
    if not values["publisher"].startswith("CN="):
        raise StorePackageError(
            "publisher must be the exact Package/Identity/Publisher subject from Partner Center"
        )
    if len(values["publisher_display_name"]) > 256:
        raise StorePackageError("publisher_display_name is longer than 256 characters")
    return values


def load_identity(path: Path, product: Product) -> dict[str, str]:
    config = read_json(path)
    if not isinstance(config, dict) or product.key not in config:
        raise StorePackageError(f"identity file has no {product.key!r} entry")
    return validate_identity(config[product.key])


def render_manifest(product: Product, identity: dict[str, str], version: str) -> bytes:
    template = product.template.read_text(encoding="utf-8")
    replacements = {
        "@IDENTITY_NAME@": escape(identity["identity_name"], quote=True),
        "@PUBLISHER@": escape(identity["publisher"], quote=True),
        "@PUBLISHER_DISPLAY_NAME@": escape(identity["publisher_display_name"], quote=True),
        "@VERSION@": escape(store_version(version), quote=True),
    }
    for token, value in replacements.items():
        if token not in template:
            raise StorePackageError(f"manifest template is missing token {token}")
        template = template.replace(token, value)
    if "@" in template:
        raise StorePackageError("manifest template contains an unresolved token")
    document = template.encode("utf-8")
    validate_manifest(document, product, version)
    return document


def validate_manifest(document: bytes, product: Product, version: str) -> None:
    try:
        root = ET.fromstring(document)
    except ET.ParseError as exc:
        raise StorePackageError("rendered AppxManifest.xml is not well-formed XML") from exc
    namespace = {"f": FOUNDATION_NS, "r": RESTRICTED_NS, "d": DESKTOP_NS}
    identity = root.find("f:Identity", namespace)
    if identity is None:
        raise StorePackageError("manifest Identity element is missing")
    expected = {
        "Version": store_version(version),
        "ProcessorArchitecture": "x64",
    }
    for name, value in expected.items():
        if identity.get(name) != value:
            raise StorePackageError(f"manifest Identity/{name} must be {value!r}")
    application = root.find("f:Applications/f:Application", namespace)
    if application is None:
        raise StorePackageError("manifest full-trust Application element is missing")
    if application.get("Executable", "").replace("\\", "/") != product.executable:
        raise StorePackageError("manifest executable does not match the product contract")
    if application.get("EntryPoint") != "Windows.FullTrustApplication":
        raise StorePackageError("manifest application must use Windows.FullTrustApplication")
    startup_extensions = application.findall("f:Extensions/d:Extension", namespace)
    if product.key == "antivirus":
        if len(startup_extensions) != 1:
            raise StorePackageError("antivirus manifest must declare exactly one startup task")
        extension = startup_extensions[0]
        if extension.get("Category") != "windows.startupTask":
            raise StorePackageError("antivirus manifest extension must be windows.startupTask")
        if extension.get("Executable", "").replace("\\", "/") != product.executable:
            raise StorePackageError("antivirus startup task executable must match the GUI")
        if extension.get("EntryPoint") != "Windows.FullTrustApplication":
            raise StorePackageError("antivirus startup task must use full-trust activation")
        if extension.get(f"{{{UAP11_NS}}}Parameters") != "--startup":
            raise StorePackageError("antivirus startup task must use the --startup mode")
        task = extension.find("d:StartupTask", namespace)
        if task is None:
            raise StorePackageError("antivirus startup task declaration is missing")
        expected_task = {
            "TaskId": "ZSECAntivirusStartup",
            "Enabled": "true",
            "DisplayName": "ZSEC Antivirus",
        }
        if task.attrib != expected_task:
            raise StorePackageError("antivirus startup task contract is invalid")
    elif startup_extensions:
        raise StorePackageError("browser manifest must not declare an antivirus startup task")
    capabilities = root.findall("f:Capabilities/*", namespace)
    declared = {(item.tag, item.get("Name")) for item in capabilities}
    expected_capability = {(f"{{{RESTRICTED_NS}}}Capability", "runFullTrust")}
    if declared != expected_capability:
        raise StorePackageError(
            "Store manifest capabilities must be minimized to rescap:runFullTrust"
        )


def _read_png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise StorePackageError(f"asset is not a valid PNG: {path}")
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def validate_assets(product: Product) -> None:
    actual = {path.name for path in product.asset_directory.glob("*.png") if path.is_file()}
    if actual != set(ASSET_SIZES):
        raise StorePackageError(
            f"{product.display_name} Store assets differ from the required base-scale set"
        )
    for filename, expected in ASSET_SIZES.items():
        path = product.asset_directory / filename
        if _read_png_size(path) != expected:
            raise StorePackageError(f"Store asset has the wrong dimensions: {path}")


def validate_repository() -> dict[str, Any]:
    result: dict[str, Any] = {"schema": "zsec.windows-store-readiness.v1", "products": {}}
    test_identity = {
        "identity_name": "Example.ZSEC.Product",
        "publisher": "CN=00000000-0000-0000-0000-000000000000",
        "publisher_display_name": "Example Publisher",
    }
    for product in PRODUCTS.values():
        version = source_version(product)
        validate_assets(product)
        document = render_manifest(product, test_identity, version)
        result["products"][product.key] = {
            "source_version": version,
            "store_version": store_version(version),
            "manifest_template_sha256": sha256(product.template),
            "rendered_test_manifest_sha256": hashlib.sha256(document).hexdigest(),
            "capabilities": ["runFullTrust"],
        }
    result["identity_status"] = "Partner Center values required; no values are embedded"
    result["makeappx"] = str(find_makeappx()) if find_makeappx() else None
    return result


def _safe_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value or value.startswith("/") or ":" in value:
        raise StorePackageError(f"unsafe payload path in build manifest: {value!r}")
    path = PurePosixPath(value)
    if any(part in FORBIDDEN_PATH_PARTS for part in path.parts):
        raise StorePackageError(f"unsafe payload path in build manifest: {value!r}")
    return path


def _payload_contract(
    product: Product, payload_root: Path
) -> tuple[Path, str, dict[PurePosixPath, str]]:
    if product.key == "browser":
        manifest_path = payload_root / product.manifest_name
        content_root = payload_root / "payload"
    else:
        manifest_path = payload_root / product.manifest_name
        content_root = payload_root
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != product.manifest_schema:
        raise StorePackageError(f"unexpected {product.display_name} payload manifest schema")
    version = manifest.get("version")
    if version != source_version(product):
        current = source_version(product)
        raise StorePackageError(
            f"payload version {version!r} does not match current source version {current!r}"
        )
    if product.key == "antivirus":
        if manifest.get("entrypoints", {}).get("desktop") != product.executable:
            raise StorePackageError("antivirus payload desktop entrypoint is unexpected")
    elif manifest.get("launcher") != product.executable:
        raise StorePackageError("browser payload launcher is unexpected")
    files: dict[PurePosixPath, str] = {}
    for entry in manifest.get("files", []):
        if not isinstance(entry, dict):
            raise StorePackageError("payload manifest file entry is not an object")
        relative = _safe_relative_path(entry.get("path"))
        digest = entry.get("sha256")
        if SHA256_PATTERN.fullmatch(str(digest)) is None:
            raise StorePackageError(f"payload manifest SHA-256 is invalid: {relative}")
        if relative in files:
            raise StorePackageError(f"duplicate payload path: {relative}")
        files[relative] = str(digest)
    executable = PurePosixPath(product.executable)
    if executable not in files:
        raise StorePackageError("payload manifest does not include the Store executable")
    if product.key == "antivirus":
        missing_runtime = sorted(
            str(path) for path in ANTIVIRUS_REQUIRED_RUNTIME_PATHS - files.keys()
        )
        if missing_runtime:
            raise StorePackageError(
                "antivirus payload omits required Store runtime files: "
                f"{missing_runtime}"
            )
    actual = {
        PurePosixPath(path.relative_to(content_root).as_posix()): sha256(path)
        for path in content_root.rglob("*")
        if path.is_file() and not path.is_symlink() and path != manifest_path
    }
    if actual != files:
        missing = sorted(str(path) for path in files.keys() - actual.keys())
        extra = sorted(str(path) for path in actual.keys() - files.keys())
        changed = sorted(
            str(path) for path in files.keys() & actual.keys() if files[path] != actual[path]
        )
        detail = f"missing={missing}, extra={extra}, changed={changed}"
        raise StorePackageError(f"payload differs from its manifest ({detail})")
    return content_root, str(version), files


def _copy_files(
    content_root: Path,
    destination: Path,
    files: Iterable[PurePosixPath],
) -> None:
    for relative in sorted(files, key=str):
        source = content_root.joinpath(*relative.parts)
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def stage_layout(
    product: Product,
    payload_root: Path,
    identity_path: Path,
    output: Path,
) -> dict[str, Any]:
    payload_root = payload_root.resolve(strict=True)
    identity = load_identity(identity_path.resolve(strict=True), product)
    content_root, version, manifest_files = _payload_contract(product, payload_root)
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise StorePackageError(f"refusing to overwrite non-empty staging directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    # Browser installer/status scripts are direct-distribution helpers, not Store
    # runtime content. Antivirus needs its sibling Engine and Tools directories.
    prefixes = ("App/",) if product.key == "browser" else ("App/", "Engine/", "Tools/")
    selected = [path for path in manifest_files if str(path).startswith(prefixes)]
    _copy_files(content_root, output, selected)
    assets = output / "Assets"
    assets.mkdir(parents=True, exist_ok=True)
    for filename in sorted(ASSET_SIZES):
        shutil.copyfile(product.asset_directory / filename, assets / filename)
    (output / "AppxManifest.xml").write_bytes(render_manifest(product, identity, version))
    package_files = []
    for path in sorted(
        (item for item in output.rglob("*") if item.is_file()), key=lambda p: p.as_posix()
    ):
        relative = path.relative_to(output).as_posix()
        package_files.append(
            {"path": relative, "sha256": sha256(path), "bytes": path.stat().st_size}
        )
    provenance = {
        "schema": "zsec.windows-store-stage.v1",
        "product": product.display_name,
        "source_version": version,
        "store_version": store_version(version),
        "architecture": "x64",
        "capabilities": ["runFullTrust"],
        "identity_name": identity["identity_name"],
        "publisher": identity["publisher"],
        "files": package_files,
    }
    provenance_path = output / "store-package-files.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    validate_staged_layout(output, product)
    return provenance


def validate_staged_layout(layout: Path, product: Product) -> dict[str, Any]:
    layout = layout.resolve(strict=True)
    provenance = read_json(layout / "store-package-files.json")
    if provenance.get("schema") != "zsec.windows-store-stage.v1":
        raise StorePackageError("unexpected Store staging provenance schema")
    expected = {entry["path"]: entry["sha256"] for entry in provenance.get("files", [])}
    actual = {
        path.relative_to(layout).as_posix(): sha256(path)
        for path in layout.rglob("*")
        if path.is_file() and path.name != "store-package-files.json"
    }
    if actual != expected:
        raise StorePackageError("staged Store layout differs from store-package-files.json")
    if product.key == "antivirus":
        staged_paths = {PurePosixPath(path) for path in actual}
        missing_runtime = sorted(
            str(path) for path in ANTIVIRUS_REQUIRED_RUNTIME_PATHS - staged_paths
        )
        if missing_runtime:
            raise StorePackageError(
                "staged antivirus layout omits required runtime files: "
                f"{missing_runtime}"
            )
    version = str(provenance.get("source_version"))
    validate_manifest((layout / "AppxManifest.xml").read_bytes(), product, version)
    executable = layout.joinpath(*PurePosixPath(product.executable).parts)
    if not executable.is_file():
        raise StorePackageError("staged Store executable is missing")
    return provenance


def find_makeappx() -> Path | None:
    discovered = shutil.which("makeappx.exe") or shutil.which("makeappx")
    if discovered:
        return Path(discovered)
    kits = Path(r"C:\Program Files (x86)\Windows Kits\10\bin")
    candidates = sorted(kits.glob("*/x64/makeappx.exe"), reverse=True)
    return candidates[0] if candidates else None


def pack_msix(
    layout: Path, product: Product, output: Path, makeappx: Path | None
) -> dict[str, Any]:
    provenance = validate_staged_layout(layout, product)
    tool = makeappx.resolve(strict=True) if makeappx else find_makeappx()
    if tool is None:
        raise StorePackageError(
            "MakeAppx.exe was not found. Install a current Windows SDK, then pass "
            "--makeappx with its x64 MakeAppx.exe path."
        )
    output = output.resolve()
    if output.exists():
        raise StorePackageError(f"refusing to overwrite MSIX artifact: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(tool), "pack", "/o", "/d", str(layout.resolve()), "/p", str(output)],
        check=True,
        timeout=900,
    )
    artifact = {
        "schema": "zsec.windows-store-msix.v1",
        "product": product.display_name,
        "source_version": provenance["source_version"],
        "store_version": provenance["store_version"],
        "artifact": output.name,
        "artifact_sha256": sha256(output),
        "artifact_bytes": output.stat().st_size,
        "signed": False,
        "submission_status": "not-submitted",
    }
    metadata = output.with_suffix(output.suffix + ".json")
    metadata.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{artifact['artifact_sha256']}  {output.name}\n",
        encoding="ascii",
        newline="\n",
    )
    return artifact


def _product(value: str) -> Product:
    return PRODUCTS[value]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate templates, assets, versions, and capabilities")

    stage = subparsers.add_parser("stage", help="create a deterministic unpacked MSIX layout")
    stage.add_argument("--product", choices=sorted(PRODUCTS), required=True)
    stage.add_argument("--payload", type=Path, required=True)
    stage.add_argument("--identity", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-stage", help="verify a previously staged layout")
    verify.add_argument("--product", choices=sorted(PRODUCTS), required=True)
    verify.add_argument("--layout", type=Path, required=True)

    pack = subparsers.add_parser("pack", help="build an unsigned MSIX with Windows SDK MakeAppx")
    pack.add_argument("--product", choices=sorted(PRODUCTS), required=True)
    pack.add_argument("--layout", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--makeappx", type=Path)

    args = parser.parse_args()
    if args.command == "validate":
        result = validate_repository()
    elif args.command == "stage":
        result = stage_layout(_product(args.product), args.payload, args.identity, args.output)
    elif args.command == "verify-stage":
        result = validate_staged_layout(args.layout, _product(args.product))
    else:
        result = pack_msix(args.layout, _product(args.product), args.output, args.makeappx)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (StorePackageError, FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
