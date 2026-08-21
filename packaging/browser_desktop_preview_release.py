"""Package an exact, deterministic ZSEC Browser Community desktop build."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any

ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)
SOURCE_REPOSITORY = "https://github.com/ResearchForumOnline/ZSEC-Shield"
SOURCE_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument(
        "--source-revision",
        required=True,
        help="Exact 40-character lowercase Git commit used for the build.",
    )
    args = parser.parse_args()

    source_revision = args.source_revision
    if SOURCE_REVISION_PATTERN.fullmatch(source_revision) is None:
        raise ValueError("source revision must be a 40-character lowercase Git commit")

    build_directory = args.build_directory.resolve(strict=True)
    output_directory = args.output_directory.resolve(strict=False)
    payload = build_directory / "payload"
    build_manifest_path = build_directory / "build-manifest.json"
    build_manifest = load_json(build_manifest_path)

    if build_manifest.get("schema") != "zsec.browser.desktop-preview-build.v2":
        raise ValueError("unexpected ZSEC Browser desktop build manifest")
    if build_manifest.get("standalone_chromium_fork") is not False:
        raise ValueError("the Community build must not claim to be a Chromium fork")
    if build_manifest.get("signed_zsec_binary") is not False:
        raise ValueError("the local Community build must remain explicitly unsigned")

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
    archive_name = f"zsec-browser-community-{version}-windows-x64-unsigned.zip"
    archive_path = output_directory / archive_name
    root_name = f"zsec-browser-community-{version}"

    release_provenance = {
        "schema": "zsec.browser.community-provenance.v1",
        "product": "ZSEC Browser Community",
        "version": version,
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": source_revision,
        "signed_zsec_binary": False,
        "standalone_chromium_fork": False,
    }

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
        provenance_info = zipfile.ZipInfo(
            f"{root_name}/release-provenance.json", ZIP_TIMESTAMP
        )
        provenance_info.compress_type = zipfile.ZIP_DEFLATED
        provenance_info.external_attr = 0o100644 << 16
        archive.writestr(
            provenance_info,
            json.dumps(release_provenance, indent=2, sort_keys=True) + "\n",
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )

    metadata = {
        "schema": "zsec.browser.community-release.v1",
        "product": "ZSEC Browser",
        "version": version,
        "channel": "website-evaluation",
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
        "source_repository": SOURCE_REPOSITORY,
        "source_revision": source_revision,
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
            "Unsigned Community evaluation. Not a maintained Chromium fork, "
            "not antivirus, and not approved as a primary browser or managed "
            "production deployment."
        ),
    }
    metadata_path = archive_path.with_suffix(archive_path.suffix + ".json")
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(
        f"{metadata['artifact_sha256']}  {archive_name}\n",
        encoding="ascii",
    )
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
