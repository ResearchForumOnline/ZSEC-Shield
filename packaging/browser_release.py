"""Build a deterministic, reviewable ZSEC Browser Shields extension archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "browser" / "zeroq-shields"
INCLUDE = (
    "manifest.json",
    "PRIVACY.md",
    "README.md",
    "THREAT_MODEL.md",
    "assets/zeroq-icon.png",
    "popup/index.html",
    "popup/popup.css",
    "popup/popup.js",
    "rules/link-cleaning.json",
    "rules/privacy.json",
    "src/policy.js",
    "src/service-worker.js",
    "src/youtube-cleanup.js",
)
ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_revision() -> tuple[str | None, bool | None]:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--", "browser/zeroq-shields"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
        return revision, dirty
    except (OSError, subprocess.CalledProcessError):
        return None, None


def build(output_dir: Path) -> tuple[Path, Path, Path]:
    manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))
    version = str(manifest["version"])
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"zsec-browser-shields-{version}-chromium-mv3.zip"

    missing = [name for name in INCLUDE if not (EXTENSION / name).is_file()]
    if missing:
        raise FileNotFoundError(f"extension release inputs missing: {', '.join(missing)}")

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name in sorted(INCLUDE):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, (EXTENSION / name).read_bytes(), compresslevel=9)

    digest = sha256(archive)
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")

    revision, dirty = source_revision()
    metadata = archive.with_suffix(archive.suffix + ".json")
    metadata.write_text(
        json.dumps(
            {
                "schema": "https://talktoai.org/zero-browser/download/artifact-v1.json",
                "product": "ZSEC Browser Shields",
                "version": version,
                "artifact": archive.name,
                "sha256": digest,
                "manifest_version": manifest["manifest_version"],
                "minimum_chrome_version": manifest["minimum_chrome_version"],
                "signed_store_package": False,
                "installation_channel": "unpacked-developer-preview",
                "source_revision": revision,
                "source_dirty_at_build": dirty,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return archive, checksum, metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "browser")
    args = parser.parse_args()
    archive, checksum, metadata = build(args.output_dir.resolve())
    print(archive)
    print(checksum)
    print(metadata)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
