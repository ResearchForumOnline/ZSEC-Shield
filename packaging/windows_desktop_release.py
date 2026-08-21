"""Build and validate the ZSEC Antivirus Windows desktop distribution."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import native_release as native

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUI_SPEC = PROJECT_ROOT / "packaging" / "zsec-antivirus-desktop.spec"
CLI_SPEC = PROJECT_ROOT / "packaging" / "zsec-shield.spec"
ICON_SOURCE = PROJECT_ROOT / "assets" / "brand" / "zeroq-icon.png"
PRODUCT = "ZSEC Antivirus"

TOOLS: tuple[Path, ...] = (
    PROJECT_ROOT / "windows" / "companion" / "Install-ZsecAntivirusCompanion.ps1",
    PROJECT_ROOT / "windows" / "companion" / "Start-ZsecAntivirusCompanion.ps1",
    PROJECT_ROOT / "windows" / "companion" / "Get-ZsecAntivirusCompanionStatus.ps1",
    PROJECT_ROOT / "windows" / "companion" / "Uninstall-ZsecAntivirusCompanion.ps1",
)

DOCUMENTS: tuple[tuple[Path, str], ...] = (
    (PROJECT_ROOT / "LICENSE", "LICENSE.txt"),
    (PROJECT_ROOT / "apps" / "windows-ui" / "README.md", "DESKTOP.md"),
    (PROJECT_ROOT / "docs" / "PRIVACY_CONTRACT.md", "PRIVACY.md"),
    (PROJECT_ROOT / "docs" / "THREAT_MODEL.md", "THREAT_MODEL.md"),
    (PROJECT_ROOT / "docs" / "REPLACEMENT_READINESS.md", "REPLACEMENT_READINESS.md"),
    (PROJECT_ROOT / "packaging" / "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"),
)


class DesktopReleaseError(RuntimeError):
    """The Windows desktop package failed a release invariant."""


def _write_windows_version_file(path: Path, version: str) -> None:
    values = native.windows_version_tuple(version)
    dotted = f"{version}.0"
    content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={values!r},
    prodvers={values!r},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'ZSEC contributors'),
          StringStruct('FileDescription', 'ZSEC Antivirus desktop client'),
          StringStruct('FileVersion', '{dotted}'),
          StringStruct('InternalName', 'zsec-antivirus-desktop'),
          StringStruct('LegalCopyright', 'Licensed under Apache-2.0'),
          StringStruct('OriginalFilename', 'ZSEC Antivirus.exe'),
          StringStruct('ProductName', 'ZSEC Antivirus'),
          StringStruct('ProductVersion', '{dotted}'),
        ],
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
"""
    path.write_text(content, encoding="utf-8", newline="\n")


def _run_pyinstaller(
    spec: Path,
    *,
    dist: Path,
    work: Path,
    cache: Path,
    environment: dict[str, str],
) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--distpath",
            str(dist),
            "--workpath",
            str(work),
            str(spec),
        ],
        cwd=PROJECT_ROOT,
        env={**environment, "PYINSTALLER_CONFIG_DIR": str(cache)},
        check=True,
        timeout=900,
    )


def _copy_required(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise DesktopReleaseError(f"required regular file is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _write_manifest(root: Path, version: str) -> dict[str, Any]:
    files = native._manifest_files(root)
    manifest: dict[str, Any] = {
        "schema": "zsec.antivirus.windows-desktop-distribution.v1",
        "product": PRODUCT,
        "version": version,
        "target": {"os": "windows", "architecture": "x86_64"},
        "source": {
            "revision": native._source_revision(),
            "tree_state": native._source_tree_state(),
        },
        "entrypoints": {
            "desktop": "App/ZSEC Antivirus.exe",
            "engine": "Engine/zsec-shield.exe",
        },
        "runtime_policy": {
            "scanner": "on-demand",
            "automatic_monitoring": "per-user post-change companion",
            "pre_access_enforcement": False,
            "primary_antivirus": False,
            "windows_security_provider": False,
            "existing_provider_must_remain_active": True,
            "automatic_provider_removal": False,
            "telemetry": False,
        },
        "distribution": {
            "layout": "two-process pyinstaller-onedir",
            "publisher_code_signing": "not-performed-by-this-build",
            "automatic_binary_updater": False,
        },
        "files": files,
    }
    manifest_path = root / "DESKTOP-MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def build(output_dir: Path) -> dict[str, Any]:
    if (
        platform.system() != "Windows"
        or native.normalize_architecture(platform.machine()) != "x86_64"
    ):
        raise DesktopReleaseError("the desktop package must be built on Windows x86-64")
    version = native.project_version()
    expected_pyinstaller = native.expected_pyinstaller_version()
    actual_pyinstaller = importlib.metadata.version("pyinstaller")
    if actual_pyinstaller != expected_pyinstaller:
        raise DesktopReleaseError(
            f"PyInstaller {actual_pyinstaller} is installed; expected {expected_pyinstaller}"
        )
    for required in (GUI_SPEC, CLI_SPEC, ICON_SOURCE, *(value[0] for value in DOCUMENTS), *TOOLS):
        if not required.is_file():
            raise DesktopReleaseError(f"required build input is missing: {required}")

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"zsec-antivirus-desktop-{version}-windows-x86_64"
    archive = output_dir / f"{stem}.zip"
    checksum = output_dir / f"{stem}.zip.sha256"
    if archive.exists() or checksum.exists():
        raise DesktopReleaseError(f"refusing to overwrite existing artifact: {archive.name}")

    build_root = PROJECT_ROOT / "build" / "windows-desktop"
    build_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="build-", dir=build_root) as temporary_name:
        temporary = Path(temporary_name)
        version_file = temporary / "windows-version-info.txt"
        icon_file = temporary / "zsec-antivirus.ico"
        _write_windows_version_file(version_file, version)
        subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "packaging" / "make_windows_icon.py"),
                str(ICON_SOURCE),
                str(icon_file),
            ],
            cwd=PROJECT_ROOT,
            check=True,
            timeout=60,
        )
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONHASHSEED": "0",
                "ZSEC_SHIELD_WINDOWS_VERSION_FILE": str(version_file),
                "ZSEC_GUI_WINDOWS_VERSION_FILE": str(version_file),
                "ZSEC_GUI_WINDOWS_ICON": str(icon_file),
            }
        )

        cli_dist = temporary / "cli-dist"
        gui_dist = temporary / "gui-dist"
        _run_pyinstaller(
            CLI_SPEC,
            dist=cli_dist,
            work=temporary / "cli-work",
            cache=temporary / "cli-cache",
            environment=environment,
        )
        _run_pyinstaller(
            GUI_SPEC,
            dist=gui_dist,
            work=temporary / "gui-work",
            cache=temporary / "gui-cache",
            environment=environment,
        )

        cli_root = cli_dist / "zsec-shield"
        gui_root = gui_dist / "zsec-antivirus-desktop"
        cli_executable = cli_root / "zsec-shield.exe"
        gui_executable = gui_root / "ZSEC Antivirus.exe"
        if not cli_executable.is_file() or not gui_executable.is_file():
            raise DesktopReleaseError("PyInstaller did not create both required executables")
        native._smoke_test(cli_executable, temporary / "smoke-state", version)
        subprocess.run([str(gui_executable), "--help"], check=True, timeout=30)

        stage = temporary / "stage" / stem
        shutil.copytree(gui_root, stage / "App")
        shutil.copytree(cli_root, stage / "Engine")
        for tool in TOOLS:
            _copy_required(tool, stage / "Tools" / tool.name)
        for source, name in DOCUMENTS:
            _copy_required(source, stage / name)
        _copy_required(
            PROJECT_ROOT / "windows" / "desktop" / "Install-ZsecAntivirusDesktop.ps1",
            stage / "Install-ZsecAntivirusDesktop.ps1",
        )
        _copy_required(
            PROJECT_ROOT / "windows" / "desktop" / "Get-ZsecAntivirusDesktopStatus.ps1",
            stage / "Get-ZsecAntivirusDesktopStatus.ps1",
        )
        _copy_required(
            PROJECT_ROOT / "windows" / "desktop" / "Uninstall-ZsecAntivirusDesktop.ps1",
            stage / "Uninstall-ZsecAntivirusDesktop.ps1",
        )
        native._copy_licenses(stage)
        manifest = _write_manifest(stage, version)
        native._create_archive(stage, archive, "windows")

    digest = native.sha256_file(archive)
    native._write_text_atomic(checksum, f"{digest}  {archive.name}\n")
    result = {
        "schema": "zsec.antivirus.windows-desktop-build-result.v1",
        "product": PRODUCT,
        "version": version,
        "archive": str(archive),
        "sha256": digest,
        "checksum_file": str(checksum),
        "source_revision": manifest["source"]["revision"],
        "source_tree_state": manifest["source"]["tree_state"],
        "publisher_code_signing": "not-performed-by-this-build",
        "existing_provider_must_remain_active": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "dist" / "windows-desktop"
    )
    arguments = parser.parse_args(argv)
    try:
        build(arguments.output_dir)
    except (
        DesktopReleaseError,
        native.ReleaseError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
