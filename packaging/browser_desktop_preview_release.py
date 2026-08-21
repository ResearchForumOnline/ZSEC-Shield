"""Package an exact, deterministic ZSEC Browser desktop developer preview."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    build_directory = args.build_directory.resolve(strict=True)
    output_directory = args.output_directory.resolve(strict=False)
    payload = build_directory / "payload"
    build_manifest_path = build_directory / "build-manifest.json"
    build_manifest = load_json(build_manifest_path)

    if build_manifest.get("schema") != "zsec.browser.desktop-preview-build.v2":
        raise ValueError("unexpected ZSEC Browser desktop build manifest")
    if build_manifest.get("standalone_chromium_fork") is not False:
        raise ValueError("the developer preview must not claim to be a Chromium fork")
    if build_manifest.get("signed_zsec_binary") is not False:
        raise ValueError("the local developer preview must remain explicitly unsigned")

    expected_files = {
        str(entry["path"]): str(entry["sha256"])
        for entry in build_manifest.get("files", [])
    }
    actual_files = {
        path.relative_to(payload).as_posix(): sha256(path)
        for path in payload.rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        raise ValueError("payload files do not match the exact build manifest")

    version = str(build_manifest["version"])
    output_directory.mkdir(parents=True, exist_ok=True)
    archive_name = f"zsec-browser-desktop-preview-{version}-windows-x64-unsigned.zip"
    archive_path = output_directory / archive_name
    root_name = f"zsec-browser-desktop-preview-{version}"

    entries = [
        (path, path.relative_to(payload).as_posix())
        for path in payload.rglob("*")
        if path.is_file()
    ]
    entries.append((build_manifest_path, "build-manifest.json"))
    with zipfile.ZipFile(
        archive_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for source, relative in sorted(entries, key=lambda item: item[1]):
            info = zipfile.ZipInfo(f"{root_name}/{relative}", ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(
                info,
                source.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )

    metadata = {
        "schema": "zsec.browser.desktop-preview-release.v1",
        "product": "ZSEC Browser Desktop Preview",
        "version": version,
        "channel": "local-developer-preview",
        "platform": "windows-x64",
        "architecture": build_manifest["architecture"],
        "artifact": archive_name,
        "artifact_sha256": sha256(archive_path),
        "artifact_bytes": archive_path.stat().st_size,
        "signed_zsec_binary": False,
        "public_production_ready": False,
        "standalone_chromium_fork": False,
        "default_browser_changed": False,
        "system_security_products_modified": False,
        "engine": {
            "distribution": build_manifest["engine_distribution"],
            "maintained_by": build_manifest["engine_maintained_by"],
            "sdk_version": build_manifest["webview2_sdk_version"],
            "sdk_nuget_sha256": build_manifest["webview2_nuget_sha256"],
            "sdk_nuget_sha512_base64": build_manifest["webview2_nuget_sha512_base64"],
        },
        "policy": {
            "source": "ZSEC Browser Shields 0.4.0 reviewed data rules",
            "tracker_domain_count": build_manifest["tracker_domain_count"],
            "tracking_parameter_count": build_manifest["tracking_parameter_count"],
        },
        "installation": (
            "Extract the archive, review README.md, then run "
            "Install-ZsecBrowserPreview.ps1 from PowerShell."
        ),
        "claims_boundary": (
            "Unsigned local developer preview. Not a maintained Chromium fork, "
            "not antivirus, and not approved for public production distribution."
        ),
    }
    metadata_path = archive_path.with_suffix(archive_path.suffix + ".json")
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
