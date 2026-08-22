"""Build a deterministic, reviewable ZSEC Browser Shields extension archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "browser" / "zeroq-shields"
EASYLIST_FILES = (
    "easylist.lock.json",
    "rules/easylist.json",
    "third_party/EASYLIST-LICENSE.txt",
    "third_party/easylist-20260817.txt",
    "third_party/easylist-provenance.json",
)
INCLUDE = (
    "MERCENARY_SPYWARE_DEFENCE.md",
    *EASYLIST_FILES,
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
    "src/popup-state.js",
    "src/runtime-health.js",
    "src/settings-transaction.js",
    "src/high-risk-browsing.js",
    "src/service-worker.js",
    "src/youtube-cosmetic-rules.js",
    "src/youtube-cleanup.js",
)
ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def release_input(name: str) -> Path:
    if name == "MERCENARY_SPYWARE_DEFENCE.md":
        return ROOT / "docs" / name
    return EXTENSION / name


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def validated_easylist_metadata(manifest: dict[str, object]) -> dict[str, object]:
    """Verify the separately packaged EasyList artifacts against their lock."""

    lock_path = EXTENSION / "easylist.lock.json"
    rules_path = EXTENSION / "rules" / "easylist.json"
    provenance_path = EXTENSION / "third_party" / "easylist-provenance.json"
    license_path = EXTENSION / "third_party" / "EASYLIST-LICENSE.txt"
    lock = load_object(lock_path)
    provenance = load_object(provenance_path)
    if lock.get("schema") != "zsec.browser.easylist-lock.v1":
        raise ValueError("unsupported EasyList lock schema")
    if provenance.get("schema") != "zsec.browser.easylist-provenance.v1":
        raise ValueError("unsupported EasyList provenance schema")

    upstream = lock.get("upstream")
    ruleset = lock.get("ruleset")
    policy = lock.get("policy")
    output = provenance.get("output")
    provenance_policy = provenance.get("policy")
    source = provenance.get("source")
    if not all(
        isinstance(value, dict)
        for value in (upstream, ruleset, policy, output, provenance_policy, source)
    ):
        raise ValueError("EasyList lock or provenance has an invalid structure")
    upstream = cast(dict[str, object], upstream)
    ruleset = cast(dict[str, object], ruleset)
    policy = cast(dict[str, object], policy)
    output = cast(dict[str, object], output)
    provenance_policy = cast(dict[str, object], provenance_policy)
    source = cast(dict[str, object], source)

    rule_resources = manifest.get("declarative_net_request", {})
    if not isinstance(rule_resources, dict):
        raise ValueError("manifest declarativeNetRequest resources are invalid")
    resources = rule_resources.get("rule_resources", [])
    easylist_resources = [
        resource
        for resource in resources
        if isinstance(resource, dict) and resource.get("id") == "easylist_ads"
    ]
    if easylist_resources != [
        {"id": "easylist_ads", "enabled": True, "path": "rules/easylist.json"}
    ]:
        raise ValueError("manifest must enable exactly one locked EasyList ruleset")

    source_relative = ruleset.get("source_output_path")
    if not isinstance(source_relative, str):
        raise ValueError("EasyList retained source path is invalid")
    source_path = EXTENSION / source_relative
    expected_paths = {
        "rules": "rules/easylist.json",
        "source": "third_party/easylist-20260817.txt",
    }
    if (
        ruleset.get("output_path") != expected_paths["rules"]
        or source_relative != expected_paths["source"]
    ):
        raise ValueError("EasyList lock paths escaped the reviewed release layout")

    required_files = (rules_path, source_path, provenance_path, license_path)
    missing = [str(path.relative_to(EXTENSION)) for path in required_files if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"EasyList release inputs missing: {', '.join(missing)}")

    rules_bytes = rules_path.read_bytes()
    source_bytes = source_path.read_bytes()
    expected_rule_count = ruleset.get("rule_count")
    rules = json.loads(rules_bytes.decode("utf-8"))
    if not isinstance(rules, list) or len(rules) != expected_rule_count:
        raise ValueError("EasyList rule count does not match its lock")
    if (
        len(rules_bytes) != ruleset.get("output_bytes")
        or hashlib.sha256(rules_bytes).hexdigest() != ruleset.get("output_sha256")
        or len(source_bytes) != ruleset.get("source_bytes")
        or hashlib.sha256(source_bytes).hexdigest() != ruleset.get("source_sha256")
    ):
        raise ValueError("EasyList rules or retained source failed exact size/hash validation")

    provenance_matches = (
        output.get("path") == ruleset.get("output_path")
        and output.get("sha256") == ruleset.get("output_sha256")
        and output.get("bytes") == ruleset.get("output_bytes")
        and output.get("rules") == expected_rule_count
        and source.get("source_sha256") == ruleset.get("source_sha256")
        and source.get("release_commit") == upstream.get("release_commit")
        and source.get("release_tag") == upstream.get("release_tag")
    )
    if not provenance_matches:
        raise ValueError("EasyList provenance does not match its exact lock")

    source_text = source_bytes.decode("utf-8", "strict")
    source_text_folded = source_text.casefold()
    unacceptable_markers = ("allow nonintrusive advertising", "acceptable ads")
    if (
        ruleset.get("title") != "EasyList"
        or ruleset.get("acceptable_ads_included") is not False
        or policy.get("acceptable_ads_default") is not False
        or provenance_policy.get("acceptable_ads_included") is not False
        or any(marker in source_text_folded for marker in unacceptable_markers)
    ):
        raise ValueError("Acceptable Ads must not be bundled or enabled")

    file_metadata = {}
    for relative in EASYLIST_FILES:
        path = EXTENSION / relative
        file_metadata[relative] = {
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    return {
        "acceptable_ads_included": False,
        "enabled_by_default": True,
        "files": file_metadata,
        "license": lock.get("license"),
        "network_filtering_only": policy.get("network_filtering_only"),
        "output_sha256": ruleset.get("output_sha256"),
        "retained_source_sha256": ruleset.get("source_sha256"),
        "rule_count": expected_rule_count,
        "ruleset_id": ruleset.get("id"),
        "ruleset_version": ruleset.get("version"),
        "security_rule_priority_floor": policy.get("security_rule_priority_floor"),
        "upstream_release_commit": upstream.get("release_commit"),
        "upstream_release_tag": upstream.get("release_tag"),
    }


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
                [
                    "git",
                    "status",
                    "--porcelain",
                    "--",
                    "browser/zeroq-shields",
                    "docs/MERCENARY_SPYWARE_DEFENCE.md",
                ],
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
    easylist = validated_easylist_metadata(manifest)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"zsec-browser-shields-{version}-chromium-mv3.zip"

    missing = [name for name in INCLUDE if not release_input(name).is_file()]
    if missing:
        raise FileNotFoundError(f"extension release inputs missing: {', '.join(missing)}")

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name in sorted(INCLUDE):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, release_input(name).read_bytes(), compresslevel=9)

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
                "easylist": easylist,
                "signed_store_package": False,
                "installation_channel": "unpacked-community",
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
