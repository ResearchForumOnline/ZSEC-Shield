"""Build and validate inspectable native ZSEC Shield release archives."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = PROJECT_ROOT / "packaging" / "zsec-shield.spec"
SCHEMA_PATH = PROJECT_ROOT / "packaging" / "native-manifest.schema.json"
VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SOURCE_VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)
REVISION_PATTERN = re.compile(r"^[0-9a-f]{7,64}$")
MAX_LICENSE_BYTES = 2 * 1024 * 1024
VENDORED_PYTHON_LICENSE = PROJECT_ROOT / "packaging" / "licenses" / "CPython-3.11-LICENSE.txt"
VENDORED_PYTHON_LICENSE_SHA256 = "3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf"

DOCUMENTS: tuple[tuple[Path, str], ...] = (
    (PROJECT_ROOT / "LICENSE", "LICENSE"),
    (PROJECT_ROOT / "README.md", "README.md"),
    (PROJECT_ROOT / "SECURITY.md", "SECURITY.md"),
    (PROJECT_ROOT / "docs" / "THREAT_MODEL.md", "THREAT_MODEL.md"),
    (PROJECT_ROOT / "docs" / "FEED_FORMAT.md", "FEED_FORMAT.md"),
    (PROJECT_ROOT / "docs" / "OPERATIONS.md", "OPERATIONS.md"),
    (PROJECT_ROOT / "docs" / "FOREGROUND_WATCH_MODE.md", "FOREGROUND_WATCH_MODE.md"),
    (PROJECT_ROOT / "docs" / "NATIVE_DISTRIBUTION.md", "NATIVE_DISTRIBUTION.md"),
    (PROJECT_ROOT / "docs" / "PLATFORM_SUPPORT.md", "PLATFORM_SUPPORT.md"),
    (PROJECT_ROOT / "docs" / "REPLACEMENT_READINESS.md", "REPLACEMENT_READINESS.md"),
    (PROJECT_ROOT / "docs" / "FULL_ANTIVIRUS_PROGRAM.md", "WINDOWS_PROGRAM.md"),
    (PROJECT_ROOT / "docs" / "MACOS_DESKTOP_PROGRAM.md", "MACOS_PROGRAM.md"),
    (PROJECT_ROOT / "docs" / "LINUX_DESKTOP_PROGRAM.md", "LINUX_PROGRAM.md"),
    (PROJECT_ROOT / "packaging" / "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"),
    (SCHEMA_PATH, "native-manifest.schema.json"),
)

PLATFORM_COMPANION_DOCUMENTS: dict[str, tuple[tuple[Path, str], ...]] = {
    "windows": (
        (PROJECT_ROOT / "windows" / "companion" / "README.md", "COMPANION.md"),
        (
            PROJECT_ROOT / "windows" / "companion" / "Install-ZsecAntivirusCompanion.ps1",
            "Install-ZsecAntivirusCompanion.ps1",
        ),
        (
            PROJECT_ROOT / "windows" / "companion" / "Start-ZsecAntivirusCompanion.ps1",
            "Start-ZsecAntivirusCompanion.ps1",
        ),
        (
            PROJECT_ROOT / "windows" / "companion" / "Get-ZsecAntivirusCompanionStatus.ps1",
            "Get-ZsecAntivirusCompanionStatus.ps1",
        ),
        (
            PROJECT_ROOT / "windows" / "companion" / "Uninstall-ZsecAntivirusCompanion.ps1",
            "Uninstall-ZsecAntivirusCompanion.ps1",
        ),
    ),
    "macos": (
        (PROJECT_ROOT / "packaging" / "companion" / "README.md", "COMPANION.md"),
        (PROJECT_ROOT / "packaging" / "companion" / "macos" / "install.sh", "install.sh"),
        (PROJECT_ROOT / "packaging" / "companion" / "macos" / "run.sh", "run.sh"),
        (PROJECT_ROOT / "packaging" / "companion" / "macos" / "status.sh", "status.sh"),
        (
            PROJECT_ROOT / "packaging" / "companion" / "macos" / "uninstall.sh",
            "uninstall.sh",
        ),
        (
            PROJECT_ROOT
            / "packaging"
            / "companion"
            / "macos"
            / "com.talktoai.zsec-antivirus-companion.plist.template",
            "com.talktoai.zsec-antivirus-companion.plist.template",
        ),
    ),
    "linux": (
        (PROJECT_ROOT / "packaging" / "companion" / "README.md", "COMPANION.md"),
        (PROJECT_ROOT / "packaging" / "companion" / "linux" / "install.sh", "install.sh"),
        (PROJECT_ROOT / "packaging" / "companion" / "linux" / "run.sh", "run.sh"),
        (PROJECT_ROOT / "packaging" / "companion" / "linux" / "status.sh", "status.sh"),
        (
            PROJECT_ROOT / "packaging" / "companion" / "linux" / "uninstall.sh",
            "uninstall.sh",
        ),
        (
            PROJECT_ROOT
            / "packaging"
            / "companion"
            / "linux"
            / "zsec-antivirus-companion.service.template",
            "zsec-antivirus-companion.service.template",
        ),
    ),
}

NOTICE_DISTRIBUTIONS: tuple[tuple[str, str, bool], ...] = (
    ("cryptography", "runtime", True),
    ("watchdog", "runtime filesystem-event observer", True),
    ("cffi", "runtime dependency", False),
    ("pycparser", "runtime dependency", False),
    ("pyinstaller", "build tool and bundled bootloader", True),
    ("pyinstaller-hooks-contrib", "build tool hooks", False),
    ("altgraph", "build tool dependency", False),
)


class ReleaseError(RuntimeError):
    """Raised when a release invariant is not satisfied."""


def _load_project() -> dict[str, Any]:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        document = tomllib.load(handle)
    project = document.get("project")
    if not isinstance(project, dict):
        raise ReleaseError("pyproject.toml has no [project] table")
    return project


def project_version() -> str:
    """Return the single verified source/package version."""
    project = _load_project()
    metadata_version = project.get("version")
    if not isinstance(metadata_version, str) or not VERSION_PATTERN.fullmatch(metadata_version):
        raise ReleaseError("project version must use strict MAJOR.MINOR.PATCH form")
    source = (PROJECT_ROOT / "src" / "zsec_shield" / "__init__.py").read_text(encoding="utf-8")
    match = SOURCE_VERSION_PATTERN.search(source)
    if match is None or match.group(1) != metadata_version:
        raise ReleaseError("pyproject.toml and zsec_shield.__version__ do not match")
    return metadata_version


def expected_pyinstaller_version() -> str:
    project = _load_project()
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict):
        raise ReleaseError("pyproject.toml has no optional dependencies")
    requirements = optional.get("native")
    if not isinstance(requirements, list):
        raise ReleaseError("pyproject.toml has no native dependency group")
    matches = [
        requirement.removeprefix("pyinstaller==")
        for requirement in requirements
        if isinstance(requirement, str) and requirement.startswith("pyinstaller==")
    ]
    if len(matches) != 1 or not VERSION_PATTERN.fullmatch(matches[0]):
        raise ReleaseError("native dependencies must pin exactly one PyInstaller version")
    return matches[0]


def verify_release_tag(tag: str) -> str:
    version = project_version()
    expected = f"v{version}"
    if tag != expected:
        raise ReleaseError(f"release tag {tag!r} does not match project version {expected!r}")
    return version


def normalize_system(value: str) -> str:
    normalized = value.casefold()
    names = {"windows": "windows", "darwin": "macos", "linux": "linux"}
    try:
        return names[normalized]
    except KeyError as exc:
        raise ReleaseError(f"unsupported native build operating system: {value}") from exc


def normalize_architecture(value: str) -> str:
    normalized = value.casefold().replace("-", "_")
    names = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    try:
        return names[normalized]
    except KeyError as exc:
        raise ReleaseError(f"unsupported native build architecture: {value}") from exc


def windows_version_tuple(version: str) -> tuple[int, int, int, int]:
    match = VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ReleaseError("Windows resource version must use MAJOR.MINOR.PATCH form")
    values = tuple(int(value) for value in match.groups())
    if any(value > 65535 for value in values):
        raise ReleaseError("Windows resource version components must be at most 65535")
    return values[0], values[1], values[2], 0


def write_windows_version_file(path: Path, version: str) -> None:
    file_version = windows_version_tuple(version)
    dotted = f"{version}.0"
    content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={file_version!r},
    prodvers={file_version!r},
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
          StringStruct('FileDescription', 'ZSEC Shield file scanner'),
          StringStruct('FileVersion', '{dotted}'),
          StringStruct('InternalName', 'zsec-shield'),
          StringStruct('LegalCopyright', 'Licensed under Apache-2.0'),
          StringStruct('OriginalFilename', 'zsec-shield.exe'),
          StringStruct('ProductName', 'ZSEC Shield'),
          StringStruct('ProductVersion', '{dotted}'),
        ],
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
"""
    path.write_text(content, encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_license_path(path: Path) -> bool:
    lowered = [part.casefold() for part in path.parts]
    name = path.name.casefold()
    return (
        "licenses" in lowered
        or name.startswith("license")
        or name.startswith("copying")
        or name.startswith("notice")
    )


def _copy_distribution_licenses(
    distribution_name: str, role: str, required: bool, destination: Path
) -> dict[str, Any] | None:
    try:
        distribution = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError as exc:
        if required:
            raise ReleaseError(
                f"required distribution is not installed: {distribution_name}"
            ) from exc
        return None

    component_dir = destination / re.sub(r"[^A-Za-z0-9_.-]", "_", distribution_name)
    copied: list[str] = []
    for package_path in distribution.files or ():
        relative = Path(str(package_path))
        if not _is_license_path(relative) or ".." in relative.parts:
            continue
        source = Path(str(distribution.locate_file(package_path)))
        if not source.is_file() or source.stat().st_size > MAX_LICENSE_BYTES:
            continue
        flattened = "__".join(relative.parts[-3:])
        target = component_dir / flattened
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != source.read_bytes():
            suffix = hashlib.sha256(str(relative).encode()).hexdigest()[:10]
            target = target.with_name(f"{target.stem}-{suffix}{target.suffix}")
        shutil.copyfile(source, target)
        copied.append(target.relative_to(destination.parent).as_posix())

    if required and not copied:
        raise ReleaseError(f"no license text found for required distribution: {distribution_name}")
    return {
        "name": distribution.metadata["Name"] or distribution_name,
        "version": distribution.version,
        "role": role,
        "license_files": sorted(set(copied)),
    }


def _runtime_python_license_candidates() -> tuple[Path, ...]:
    return (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
        Path(sys.executable).resolve().parent / "LICENSE.txt",
    )


def _verified_vendored_python_license() -> Path:
    if not VENDORED_PYTHON_LICENSE.is_file():
        raise ReleaseError("the vendored CPython license fallback is missing")
    if sha256_file(VENDORED_PYTHON_LICENSE) != VENDORED_PYTHON_LICENSE_SHA256:
        raise ReleaseError("the vendored CPython license fallback failed its SHA-256 check")
    return VENDORED_PYTHON_LICENSE


def _resolve_python_license(candidates: Iterable[Path] | None = None) -> Path:
    vendored_license = _verified_vendored_python_license()
    runtime_candidates = (
        _runtime_python_license_candidates() if candidates is None else tuple(candidates)
    )
    return next((path for path in runtime_candidates if path.is_file()), vendored_license)


def _copy_licenses(bundle_root: Path) -> list[dict[str, Any]]:
    licenses_root = bundle_root / "LICENSES"
    licenses_root.mkdir(parents=True, exist_ok=True)
    python_license = _resolve_python_license()
    python_target = licenses_root / "Python" / "LICENSE.txt"
    python_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(python_license, python_target)
    components: list[dict[str, Any]] = [
        {
            "name": "Python",
            "version": platform.python_version(),
            "role": "runtime",
            "license_files": [python_target.relative_to(bundle_root).as_posix()],
        }
    ]
    for distribution_name, role, required in NOTICE_DISTRIBUTIONS:
        component = _copy_distribution_licenses(distribution_name, role, required, licenses_root)
        if component is not None:
            components.append(component)
    return components


def _copy_documents(bundle_root: Path, target_os: str) -> None:
    platform_documents = PLATFORM_COMPANION_DOCUMENTS.get(target_os)
    if platform_documents is None:
        raise ReleaseError(f"no companion package is defined for target OS: {target_os}")
    for source, destination_name in (*DOCUMENTS, *platform_documents):
        if not source.is_file():
            raise ReleaseError(f"required distribution document is missing: {source}")
        shutil.copyfile(source, bundle_root / destination_name)


def _manifest_files(bundle_root: Path) -> list[dict[str, Any]]:
    root = bundle_root.resolve()
    records: list[dict[str, Any]] = []
    for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(bundle_root).as_posix()
        if relative == "NATIVE-MANIFEST.json":
            continue
        if path.is_symlink():
            target = os.readlink(path)
            resolved_target = (path.parent / target).resolve()
            try:
                resolved_target.relative_to(root)
            except ValueError as exc:
                raise ReleaseError(f"bundle symlink escapes archive root: {relative}") from exc
            records.append({"path": relative, "type": "symlink", "target": target})
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseError(f"unsupported object in native bundle: {relative}")
        records.append(
            {
                "path": relative,
                "type": "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return records


def _source_revision() -> str | None:
    environment_revision = os.environ.get("GITHUB_SHA", "").casefold()
    if environment_revision:
        if not REVISION_PATTERN.fullmatch(environment_revision):
            raise ReleaseError("GITHUB_SHA is not a hexadecimal source revision")
        return environment_revision
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={PROJECT_ROOT.as_posix()}",
                "rev-parse",
                "HEAD",
            ],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    revision = result.stdout.strip().casefold()
    return revision if REVISION_PATTERN.fullmatch(revision) else None


def _source_tree_state() -> str:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={PROJECT_ROOT.as_posix()}",
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "unknown"
    return "modified" if result.stdout.strip() else "clean"


def _bundled_trust_key_count() -> int:
    keyring_path = PROJECT_ROOT / "src" / "zsec_shield" / "data" / "trusted_keys.json"
    document = json.loads(keyring_path.read_text(encoding="utf-8"))
    if document.get("schema") != "zsec.shield.keyring.v1" or not isinstance(
        document.get("keys"), list
    ):
        raise ReleaseError("bundled trust keyring does not match the expected data-only schema")
    return len(document["keys"])


def _write_manifest(
    bundle_root: Path,
    *,
    version: str,
    target_os: str,
    architecture: str,
    entrypoint: str,
    pyinstaller_version: str,
    components: list[dict[str, Any]],
) -> Path:
    manifest = {
        "schema": "zsec.shield.native-distribution.v2",
        "product": "ZSEC Shield",
        "version": version,
        "target": {"os": target_os, "architecture": architecture},
        "build": {
            "built_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "python_version": platform.python_version(),
            "pyinstaller_version": pyinstaller_version,
            "source_revision": _source_revision(),
            "source_tree_state": _source_tree_state(),
            "publisher_code_signing": "not-performed-by-this-build",
        },
        "runtime_policy": {
            "modes": ["on-demand", "foreground-post-change-protection"],
            "pre_access_enforcement": False,
            "background_service": False,
            "per_user_background_companion": True,
            "real_time_protection": False,
            "automatic_quarantine": False,
            "opt_in_companion_quarantine": True,
            "telemetry": False,
            "bundled_trust_keys": _bundled_trust_key_count(),
        },
        "entrypoint": entrypoint,
        "layout": "pyinstaller-onedir",
        "components": components,
        "files": _manifest_files(bundle_root),
    }
    path = bundle_root / "NATIVE-MANIFEST.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def _smoke_test(executable: Path, state_dir: Path, version: str) -> None:
    version_result = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if version_result.stdout.strip() != f"zsec-shield {version}":
        raise ReleaseError("frozen executable returned an unexpected version")
    watch_help_result = subprocess.run(
        [str(executable), "watch", "--help"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    watch_help_tokens = set(watch_help_result.stdout.casefold().split())
    required_watch_options = {"--backend", "--reconcile-seconds", "--quarantine"}
    if not required_watch_options.issubset(watch_help_tokens):
        raise ReleaseError("frozen executable does not expose the bounded watch interface")
    status_result = subprocess.run(
        [str(executable), "--state-dir", str(state_dir), "status", "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    status = json.loads(status_result.stdout)
    required_status_fields = {
        "schema",
        "contract_version",
        "last_scan_outcome",
        "last_scan_errors",
        "last_scan_files_hashed",
        "last_scan_bytes_hashed",
        "last_scan_diagnostic",
    }
    if (
        not required_status_fields.issubset(status)
        or status.get("schema") != "zsec.shield.status.v2"
        or status.get("contract_version") != 2
        or status.get("last_scan_outcome") is not None
        or type(status.get("last_scan_errors")) is not int
        or status.get("last_scan_errors") != 0
        or status.get("last_scan_files_hashed") is not None
        or status.get("last_scan_bytes_hashed") is not None
        or status.get("last_scan_diagnostic") != {"available": False, "error": None}
        or status.get("scanner_mode") != "on-demand"
        or status.get("real_time_protection") is not False
    ):
        raise ReleaseError("frozen executable status contract smoke test failed")

    readiness_result = subprocess.run(
        [str(executable), "replacement-readiness", "--json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        readiness = json.loads(readiness_result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseError(
            "frozen executable readiness output is not valid JSON"
        ) from exc
    if (
        readiness_result.returncode != 2
        or readiness.get("schema") != "zero.security.replacement-readiness.v1"
        or readiness.get("decision") != "keep_existing_protection"
        or readiness.get("eligible_for_primary_replacement") is not False
        or readiness.get("existing_provider_must_remain_active") is not True
        or readiness.get("automatic_uninstall_available") is not False
    ):
        raise ReleaseError("frozen executable replacement guard smoke test failed")


def _create_archive(bundle_root: Path, archive: Path, target_os: str) -> None:
    if target_os == "windows":
        with zipfile.ZipFile(
            archive, mode="x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as output:
            for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
                if path.is_dir():
                    continue
                if path.is_symlink():
                    raise ReleaseError("Windows ZIP bundle unexpectedly contains a symbolic link")
                output.write(
                    path, (Path(bundle_root.name) / path.relative_to(bundle_root)).as_posix()
                )
        return
    with tarfile.open(archive, mode="x:gz", compresslevel=9, format=tarfile.PAX_FORMAT) as output:
        output.add(bundle_root, arcname=bundle_root.name, recursive=True)


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_native(output_dir: Path) -> dict[str, Any]:
    version = project_version()
    expected_pyinstaller = expected_pyinstaller_version()
    try:
        installed_pyinstaller = importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError as exc:
        raise ReleaseError('PyInstaller is missing; install the project with ".[native]"') from exc
    if installed_pyinstaller != expected_pyinstaller:
        raise ReleaseError(
            f"PyInstaller {installed_pyinstaller} is installed; expected {expected_pyinstaller}"
        )

    target_os = normalize_system(platform.system())
    architecture = normalize_architecture(platform.machine())
    artifact_stem = f"zsec-shield-{version}-{target_os}-{architecture}"
    archive_suffix = ".zip" if target_os == "windows" else ".tar.gz"
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{artifact_stem}{archive_suffix}"
    sidecar = archive.with_name(f"{archive.name}.sha256")
    if archive.exists() or sidecar.exists():
        raise ReleaseError(f"refusing to overwrite an existing release artifact: {archive.name}")

    build_parent = PROJECT_ROOT / "build" / "native"
    build_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="build-", dir=build_parent) as temporary_name:
        temporary = Path(temporary_name)
        pyinstaller_dist = temporary / "dist"
        pyinstaller_work = temporary / "work"
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = "0"
        environment["PYINSTALLER_CONFIG_DIR"] = str(temporary / "pyinstaller-cache")
        if target_os == "windows":
            version_file = temporary / "windows-version-info.txt"
            write_windows_version_file(version_file, version)
            environment["ZSEC_SHIELD_WINDOWS_VERSION_FILE"] = str(version_file)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                "--clean",
                "--noconfirm",
                "--distpath",
                str(pyinstaller_dist),
                "--workpath",
                str(pyinstaller_work),
                str(SPEC_PATH),
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            check=True,
            timeout=600,
        )
        frozen_root = pyinstaller_dist / "zsec-shield"
        executable_name = "zsec-shield.exe" if target_os == "windows" else "zsec-shield"
        frozen_executable = frozen_root / executable_name
        if not frozen_executable.is_file():
            raise ReleaseError(f"PyInstaller did not create {frozen_executable}")
        _smoke_test(frozen_executable, temporary / "smoke-state", version)

        staged_root = temporary / "stage" / artifact_stem
        shutil.copytree(frozen_root, staged_root, symlinks=True)
        _copy_documents(staged_root, target_os)
        components = _copy_licenses(staged_root)
        _write_manifest(
            staged_root,
            version=version,
            target_os=target_os,
            architecture=architecture,
            entrypoint=executable_name,
            pyinstaller_version=installed_pyinstaller,
            components=components,
        )
        _create_archive(staged_root, archive, target_os)

    digest = sha256_file(archive)
    _write_text_atomic(sidecar, f"{digest}  {archive.name}\n")
    result = {
        "schema": "zsec.shield.native-build-result.v1",
        "version": version,
        "target": {"os": target_os, "architecture": architecture},
        "archive": str(archive),
        "sha256": digest,
        "checksum_file": str(sidecar),
        "publisher_code_signing": "not-performed-by-this-build",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def write_checksums(directory: Path, output: Path) -> list[tuple[str, str]]:
    directory = directory.expanduser().resolve()
    output = output.expanduser().resolve()
    if not directory.is_dir():
        raise ReleaseError(f"asset directory does not exist: {directory}")
    candidates = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.is_symlink() or path.resolve() == output:
            continue
        if path.name.endswith(".sha256") or path.name.startswith("SHA256SUMS"):
            continue
        if not (
            path.name.endswith(".zip")
            or path.name.endswith(".tar.gz")
            or path.name.endswith(".whl")
        ):
            continue
        candidates.append(path)
    if not candidates:
        raise ReleaseError(f"no release archives found in {directory}")
    records = [(sha256_file(path), path.name) for path in candidates]
    _write_text_atomic(output, "".join(f"{digest}  {name}\n" for digest, name in records))
    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build and smoke-test one native archive")
    build.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "dist" / "native")
    verify = commands.add_parser("verify-tag", help="verify vVERSION matches the source")
    verify.add_argument("tag", nargs="?", help="tag; defaults to GITHUB_REF_NAME")
    checksums = commands.add_parser("checksums", help="write combined release checksums")
    checksums.add_argument("directory", type=Path)
    checksums.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            build_native(args.output_dir)
        elif args.command == "verify-tag":
            tag = args.tag or os.environ.get("GITHUB_REF_NAME")
            if not tag:
                raise ReleaseError("no release tag was provided")
            version = verify_release_tag(tag)
            print(f"release tag verified for ZSEC Shield {version}")
        elif args.command == "checksums":
            records = write_checksums(args.directory, args.output)
            print(f"wrote {len(records)} checksum(s) to {args.output}")
        else:  # pragma: no cover - argparse prevents this branch
            raise ReleaseError(f"unknown command: {args.command}")
    except (OSError, ReleaseError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
