"""Import one pinned EasyList DNR ruleset from an exact eyeo release archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

MAX_ARCHIVE_ENTRIES = 5000
MAX_MEMBER_BYTES = 16 * 1024 * 1024


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _read_exact_member(
    archive: zipfile.ZipFile, name: str, *, expected_size: int, expected_hash: str
) -> bytes:
    matches = [member for member in archive.infolist() if member.filename == name]
    if len(matches) != 1:
        raise ValueError(f"archive must contain exactly one {name!r} entry")
    member = matches[0]
    if member.is_dir() or member.file_size != expected_size or member.file_size > MAX_MEMBER_BYTES:
        raise ValueError(f"archive member size or type is invalid: {name}")
    value = archive.read(member)
    if len(value) != expected_size or _sha256(value) != expected_hash:
        raise ValueError(f"archive member failed its exact hash: {name}")
    return value


def import_easylist(archive_path: Path, lock_path: Path, extension_root: Path) -> dict[str, Any]:
    lock = _load_object(lock_path)
    if lock.get("schema") != "zsec.browser.easylist-lock.v1":
        raise ValueError("unsupported EasyList lock schema")
    upstream = lock["upstream"]
    ruleset = lock["ruleset"]
    policy = lock["policy"]

    archive_bytes = archive_path.read_bytes()
    if (
        len(archive_bytes) != upstream["archive_bytes"]
        or _sha256(archive_bytes) != upstream["archive_sha256"]
    ):
        raise ValueError("eyeo release archive failed its exact size or SHA-256 lock")

    with zipfile.ZipFile(archive_path) as archive:
        if len(archive.infolist()) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("eyeo release archive has too many entries")
        source = _read_exact_member(
            archive,
            ruleset["source_entry"],
            expected_size=ruleset["source_bytes"],
            expected_hash=ruleset["source_sha256"],
        )
        source_dnr = _read_exact_member(
            archive,
            ruleset["dnr_entry"],
            expected_size=ruleset["dnr_bytes"],
            expected_hash=ruleset["dnr_sha256"],
        )

    source_text = source.decode("utf-8", "strict")
    if "! Title: EasyList\n" not in source_text or "Allow nonintrusive advertising" in source_text:
        raise ValueError("pinned source is not the expected EasyList-only subscription")
    if "! Version: " + str(ruleset["version"]) not in source_text:
        raise ValueError("EasyList source version does not match the lock")

    parsed = json.loads(source_dnr.decode("utf-8", "strict"))
    if not isinstance(parsed, list) or len(parsed) != ruleset["rule_count"]:
        raise ValueError("EasyList DNR rule count does not match the lock")
    priority_map = {int(key): int(value) for key, value in ruleset["priority_map"].items()}
    identifiers: set[int] = set()
    action_counts: dict[str, int] = {}
    for index, rule in enumerate(parsed):
        if not isinstance(rule, dict):
            raise ValueError(f"EasyList DNR rule {index} is not an object")
        identifier = rule.get("id")
        priority = rule.get("priority")
        action = rule.get("action")
        if not isinstance(identifier, int) or identifier in identifiers:
            raise ValueError("EasyList DNR rule identifiers are invalid or duplicated")
        identifiers.add(identifier)
        if priority not in priority_map:
            raise ValueError(f"unexpected EasyList source priority: {priority!r}")
        rule["priority"] = priority_map[priority]
        if not isinstance(action, dict) or not isinstance(action.get("type"), str):
            raise ValueError("EasyList DNR action is invalid")
        action_type = action["type"]
        action_counts[action_type] = action_counts.get(action_type, 0) + 1

    if (
        min(identifiers) != ruleset["minimum_rule_id"]
        or max(identifiers) != ruleset["maximum_rule_id"]
    ):
        raise ValueError("EasyList DNR identifier range does not match the lock")
    if max(priority_map.values()) >= int(policy["security_rule_priority_floor"]):
        raise ValueError("EasyList priorities could override ZSEC security rules")
    output = (json.dumps(parsed, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(output) != ruleset["output_bytes"] or _sha256(output) != ruleset["output_sha256"]:
        raise ValueError("generated EasyList DNR output does not match the lock")

    output_path = extension_root / ruleset["output_path"]
    source_output_path = extension_root / ruleset["source_output_path"]
    provenance_path = extension_root / "third_party" / "easylist-provenance.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    source_output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    source_output_path.write_bytes(source)
    provenance = {
        "schema": "zsec.browser.easylist-provenance.v1",
        "source": {
            "publisher": upstream["publisher"],
            "release_tag": upstream["release_tag"],
            "release_commit": upstream["release_commit"],
            "archive_url": upstream["archive_url"],
            "archive_sha256": upstream["archive_sha256"],
            "ruleset_id": ruleset["id"],
            "ruleset_title": ruleset["title"],
            "ruleset_version": ruleset["version"],
            "source_sha256": ruleset["source_sha256"],
            "dnr_sha256": ruleset["dnr_sha256"],
        },
        "output": {
            "path": ruleset["output_path"],
            "sha256": ruleset["output_sha256"],
            "bytes": ruleset["output_bytes"],
            "rules": ruleset["rule_count"],
            "minimum_rule_id": ruleset["minimum_rule_id"],
            "maximum_rule_id": ruleset["maximum_rule_id"],
            "priorities": sorted(set(priority_map.values())),
            "actions": dict(sorted(action_counts.items())),
        },
        "policy": {
            "network_filtering_only": True,
            "acceptable_ads_included": False,
            "security_rule_priority_floor": policy["security_rule_priority_floor"],
            "remote_code_allowed": False,
        },
        "license": lock["license"],
    }
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path("browser/zeroq-shields/easylist.lock.json"),
    )
    parser.add_argument(
        "--extension-root",
        type=Path,
        default=Path("browser/zeroq-shields"),
    )
    args = parser.parse_args()
    result = import_easylist(
        args.archive.resolve(strict=True),
        args.lock.resolve(strict=True),
        args.extension_root.resolve(strict=True),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
