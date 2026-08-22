"""Compile reviewed MV3 data rules into the ZSEC desktop browser policy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules_directory", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    rules_directory = args.rules_directory.resolve(strict=True)
    manifest_path = args.manifest.resolve(strict=True)
    output_directory = args.output_directory.resolve(strict=False)
    privacy_path = rules_directory / "privacy.json"
    link_cleaning_path = rules_directory / "link-cleaning.json"

    manifest = load_json(manifest_path)
    privacy_rules = load_json(privacy_path)
    link_rules = load_json(link_cleaning_path)

    domains: set[str] = set()
    for rule in privacy_rules:
        if rule.get("action", {}).get("type") != "block":
            continue
        for domain in rule.get("condition", {}).get("requestDomains", []):
            normalized = str(domain).strip().lower().rstrip(".")
            if normalized:
                domains.add(normalized)

    parameters: set[str] = set()
    for rule in link_rules:
        transform = rule.get("action", {}).get("redirect", {}).get("transform", {})
        query_transform = transform.get("queryTransform", {})
        for parameter in query_transform.get("removeParams", []):
            normalized = str(parameter).strip().lower()
            if normalized:
                parameters.add(normalized)

    if manifest.get("manifest_version") != 3:
        raise ValueError("ZSEC Browser Shields must remain a Manifest V3 policy source")
    if manifest.get("name") != "ZSEC Browser Shields":
        raise ValueError("unexpected ZSEC Browser Shields identity")
    if not domains or not parameters:
        raise ValueError("compiled desktop policy cannot be empty")

    output_directory.mkdir(parents=True, exist_ok=True)
    domain_path = output_directory / "tracker-domains.txt"
    parameter_path = output_directory / "tracking-parameters.txt"
    provenance_path = output_directory / "policy-provenance.json"

    domain_path.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    parameter_path.write_text("\n".join(sorted(parameters)) + "\n", encoding="utf-8")
    provenance = {
        "schema": "zsec.browser.desktop-policy.v1",
        "policy_type": "data-only deterministic MV3 rule adaptation",
        "source_extension": {
            "name": manifest["name"],
            "version": manifest["version"],
            "manifest_version": manifest["manifest_version"],
        },
        "inputs": {
            "manifest_sha256": sha256(manifest_path),
            "privacy_rules_sha256": sha256(privacy_path),
            "link_cleaning_rules_sha256": sha256(link_cleaning_path),
        },
        "outputs": {
            "tracker_domain_count": len(domains),
            "tracking_parameter_count": len(parameters),
            "tracker_domains_sha256": sha256(domain_path),
            "tracking_parameters_sha256": sha256(parameter_path),
        },
        "claims_boundary": (
            "This compilation ports a reviewed subset of extension data rules. "
            "It does not establish full Chrome extension compatibility or complete ad blocking."
        ),
    }
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(provenance, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
