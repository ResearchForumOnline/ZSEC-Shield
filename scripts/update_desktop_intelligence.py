#!/usr/bin/env python3
"""Fetch and validate the ZSEC data-only desktop advisory catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zsec_shield.intelligence import (  # noqa: E402
    SOURCE_IDS,
    IntelligenceError,
    update_desktop_intelligence,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a strict, data-only desktop advisory catalog from allowlisted "
            "government and vendor sources. This never downloads samples, creates "
            "detection rules, executes commands, or applies updates."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "intelligence" / "desktop-advisories.json",
        help="validated advisory catalog destination",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=ROOT / "intelligence" / "desktop-advisories.state.json",
        help="rollback-protection state destination",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=ROOT / ".cache" / "zsec-desktop-intelligence",
        help="validated conditional-request cache",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=ROOT / "intelligence" / "backups",
        help="content-addressed rollback backup directory",
    )
    parser.add_argument(
        "--source",
        action="append",
        choices=SOURCE_IDS,
        dest="sources",
        help="source to include; repeat to select several (default: all)",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use only previously validated cache entries",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch, parse, validate, and check rollback without writing anything",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON result")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = update_desktop_intelligence(
            output_path=args.output.expanduser().absolute(),
            state_path=args.state.expanduser().absolute(),
            cache_dir=args.cache_dir.expanduser().absolute(),
            backup_dir=args.backup_dir.expanduser().absolute(),
            source_ids=args.sources or SOURCE_IDS,
            timeout=args.timeout,
            offline=args.offline,
            dry_run=args.dry_run,
        )
    except IntelligenceError as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "outcome": "failed_closed",
                        "error": str(exc),
                        "dry_run": args.dry_run,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        else:
            print(f"ZSEC desktop intelligence failed closed: {exc}", file=sys.stderr)
        return 2
    report = result.to_dict()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"{report['outcome']}: {report['advisories']} advisory record(s) from "
            f"{len(report['sources'])} source(s); SHA-256 {report['catalog_sha256']}"
        )
        if result.dry_run:
            print("Dry-run completed: catalog, state, cache, and backups were not written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
