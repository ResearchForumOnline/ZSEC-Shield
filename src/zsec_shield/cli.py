"""Command-line interface for the on-demand ZSEC Shield MVP."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from zsec_shield import __version__
from zsec_shield.errors import QuarantinePartialError, ZsecShieldError
from zsec_shield.feed import (
    download_feed,
    inspect_feed,
    install_feed,
    read_local_feed,
)
from zsec_shield.inventory import collect_inventory
from zsec_shield.models import ScanIssue
from zsec_shield.paths import default_state_dir, resolve_keyring_path
from zsec_shield.quarantine import list_entries, quarantine_finding, restore_entry
from zsec_shield.rules import builtin_rules
from zsec_shield.scanner import DEFAULT_CHUNK_BYTES, DEFAULT_MAX_FILE_BYTES, Scanner, ScannerConfig
from zsec_shield.status_store import load_last_scan, save_last_scan
from zsec_shield.util import atomic_write_json, format_utc

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _add_scan_parser(subparsers: Any, name: str, help_text: str) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path.cwd()])
    parser.add_argument(
        "--max-file-bytes",
        type=_positive_integer,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"skip files larger than this many bytes (default: {DEFAULT_MAX_FILE_BYTES})",
    )
    parser.add_argument("--chunk-bytes", type=_positive_integer, default=DEFAULT_CHUNK_BYTES)
    parser.add_argument(
        "--cross-filesystems",
        action="store_true",
        help="allow directory traversal to cross filesystem/device boundaries",
    )
    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="opt in to removing matched files into recoverable quarantine",
    )
    parser.add_argument("--report", type=Path, help="atomically write the JSON report to this path")
    parser.add_argument("--json", action="store_true", help="write structured JSON to stdout")
    parser.set_defaults(handler=_command_check)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zsec-shield",
        description=(
            "Deterministic on-demand scanning; not complete antivirus or real-time protection."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--state-dir", type=Path, help="override the local state directory")
    parser.add_argument("--keyring", type=Path, help="trusted Ed25519 public-key ring")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_scan_parser(subparsers, "check", "scan paths with built-in and verified feed rules")
    _add_scan_parser(subparsers, "scan", "alias for check")

    update = subparsers.add_parser("update", help="verify and install a signed data-only rule feed")
    source = update.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="credential-free HTTPS feed URL")
    source.add_argument("--file", type=Path, help="local regular feed file")
    update.add_argument("--timeout", type=float, default=15.0, help="HTTPS timeout in seconds")
    update.add_argument("--json", action="store_true")
    update.set_defaults(handler=_command_update)

    status = subparsers.add_parser("status", help="show scanner, feed, and quarantine status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=_command_status)

    inventory = subparsers.add_parser("inventory", help="collect read-only platform inventory")
    inventory.add_argument("--json", action="store_true")
    inventory.set_defaults(handler=_command_inventory)

    quarantine = subparsers.add_parser("quarantine", help="list or restore recovery entries")
    quarantine_subparsers = quarantine.add_subparsers(dest="quarantine_command", required=True)
    quarantine_list = quarantine_subparsers.add_parser("list", help="list recovery entries")
    quarantine_list.add_argument("--json", action="store_true")
    quarantine_list.set_defaults(handler=_command_quarantine_list)
    restore = quarantine_subparsers.add_parser(
        "restore", help="restore one entry without overwriting"
    )
    restore.add_argument("entry_id")
    restore.add_argument("--destination", type=Path)
    restore.add_argument("--json", action="store_true")
    restore.set_defaults(handler=_command_restore)
    return parser


def _state_dir(args: argparse.Namespace) -> Path:
    path = args.state_dir if args.state_dir is not None else default_state_dir()
    return path.expanduser().absolute()


def _keyring_path(args: argparse.Namespace, state_dir: Path) -> Path:
    return resolve_keyring_path(state_dir, args.keyring)


def _emit_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _command_check(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    keyring_path = _keyring_path(args, state_dir)
    feed_status, feed_rules = inspect_feed(state_dir, keyring_path)
    rules = builtin_rules() + feed_rules
    scanner = Scanner(
        rules,
        ScannerConfig(
            max_file_bytes=args.max_file_bytes,
            chunk_bytes=args.chunk_bytes,
            cross_filesystems=args.cross_filesystems,
            excluded_paths=(state_dir,),
        ),
    )
    result = scanner.scan(args.paths)
    quarantine_results: list[dict[str, Any]] = []
    if args.quarantine:
        for finding in result.findings:
            try:
                record = quarantine_finding(finding, state_dir)
                quarantine_results.append(
                    {
                        "id": record["id"],
                        "state": record["state"],
                        "original_path": record["original_path"],
                        "sha256": record["sha256"],
                    }
                )
            except QuarantinePartialError as exc:
                quarantine_results.append(
                    {"id": exc.entry_id, "state": "copy_only", "error": str(exc)}
                )
                result.issues.append(ScanIssue(finding.path, "quarantine_partial", str(exc)))
            except ZsecShieldError as exc:
                quarantine_results.append(
                    {"id": None, "state": "failed", "path": finding.path, "error": str(exc)}
                )
                result.issues.append(ScanIssue(finding.path, "quarantine_failed", str(exc)))
        result.stats.errors = len(result.issues)

    incomplete = bool(result.issues) or feed_status.state == "invalid"
    if incomplete:
        outcome = "incomplete"
    elif result.findings:
        outcome = "configured_rule_matches_detected"
    else:
        outcome = "no_configured_rule_matches"
    try:
        save_last_scan(
            state_dir,
            completed_at=result.completed_at,
            findings=len(result.findings),
            issues=len(result.issues),
            outcome=outcome,
        )
    except OSError as exc:
        result.issues.append(ScanIssue(str(state_dir), "status_summary_failed", str(exc)))
        result.stats.errors = len(result.issues)
        incomplete = True
        outcome = "incomplete"
    report = {
        "schema": "zsec.shield.report.v1",
        "version": __version__,
        "generated_at": format_utc(),
        "command": args.command,
        "outcome": outcome,
        "policy": {
            "scanner_mode": "on-demand",
            "feed_behavior": "data-only rules; no commands or actions are accepted",
            "quarantine_requested": bool(args.quarantine),
            "real_time_protection": False,
        },
        "inventory": collect_inventory(),
        "feed": feed_status.to_dict(),
        "rules": {
            "built_in": len(builtin_rules()),
            "verified_feed": len(feed_rules),
            "total": len(rules),
        },
        "scan": result.to_dict(),
        "quarantine": quarantine_results,
        "limitations": [
            "No configured match does not prove that a system is clean.",
            (
                "Files above the configured size limit, unreadable files, links, special "
                "files, and skipped filesystems are not inspected."
            ),
            (
                "This MVP has no kernel driver, behavior monitoring, memory scanning, "
                "cloud reputation, or real-time protection."
            ),
        ],
    }
    if args.report is not None:
        atomic_write_json(args.report.expanduser().absolute(), report, mode=0o600)
    if args.json:
        _emit_json(report)
    else:
        _print_check_summary(report, args.report)
    if incomplete:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if result.findings else EXIT_OK


def _print_check_summary(report: dict[str, Any], report_path: Path | None) -> None:
    stats = report["scan"]["stats"]
    print(f"ZSEC Shield {report['version']} - on-demand deterministic check")
    print(
        f"Hashed {stats['files_hashed']} file(s), {stats['bytes_hashed']} byte(s); "
        f"matched {stats['findings']} file(s); operational issues {stats['errors']}."
    )
    feed = report["feed"]
    print(f"Rule feed: {feed['state']} ({feed['rules_count']} verified rule(s)).")
    for finding in report["scan"]["findings"]:
        names = ", ".join(match["id"] for match in finding["matches"])
        print(f"MATCH [{finding['severity'].upper()}] {finding['path']} ({names})")
    for issue in report["scan"]["issues"]:
        print(f"INCOMPLETE {issue['path']}: {issue['code']}: {issue['message']}", file=sys.stderr)
    if report["quarantine"]:
        print(f"Quarantine operations: {len(report['quarantine'])} (recovery copies retained).")
    if report_path is not None:
        print(f"JSON report: {report_path.expanduser().absolute()}")
    print("Result is rule-limited and on-demand; it is not a declaration that the system is clean.")


def _command_update(args: argparse.Namespace) -> int:
    if not 1 <= args.timeout <= 120:
        raise ZsecShieldError("timeout must be between 1 and 120 seconds")
    state_dir = _state_dir(args)
    keyring_path = _keyring_path(args, state_dir)
    if args.url is not None:
        raw = download_feed(args.url, timeout=args.timeout)
        source = args.url
    else:
        raw = read_local_feed(args.file.expanduser().absolute())
        source = str(args.file.expanduser().absolute())
    outcome, verified = install_feed(raw, state_dir, keyring_path)
    result = {
        "schema": "zsec.shield.update-result.v1",
        "version": __version__,
        "updated_at": format_utc(),
        "outcome": outcome,
        "source": source,
        "keyring_path": str(keyring_path),
        "key_id": verified.key_id,
        "sequence": verified.sequence,
        "rules_count": len(verified.rules),
        "expires_at": format_utc(verified.expires_at),
        "payload_sha256": verified.payload_sha256,
        "policy": "signed data-only rules; no command fields are accepted",
    }
    if args.json:
        _emit_json(result)
    else:
        print(
            f"Feed {outcome}: sequence {verified.sequence}, {len(verified.rules)} rule(s), "
            f"key {verified.key_id}, expires {format_utc(verified.expires_at)}."
        )
    return EXIT_OK


def _command_status(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    keyring_path = _keyring_path(args, state_dir)
    feed_status, _ = inspect_feed(state_dir, keyring_path)
    entries, quarantine_errors = list_entries(state_dir)
    last_scan, last_scan_error = load_last_scan(state_dir)
    counts: dict[str, int] = {}
    for entry in entries:
        state = str(entry["state"])
        counts[state] = counts.get(state, 0) + 1
    inventory = collect_inventory()
    host = inventory.get("host", {})
    platform_name = str(host.get("system") or sys.platform).lower()
    feed_label = (
        f"sequence-{feed_status.sequence}"
        if feed_status.sequence is not None
        else feed_status.state
    )
    definitions = f"built-in:{__version__};feed:{feed_label}"[:80]
    result = {
        "schema": "zsec.shield.status.v1",
        "contract_version": 1,
        "version": __version__,
        "generated_at": format_utc(),
        "platform": platform_name,
        "definitions": definitions,
        "last_scan": last_scan["completed_at"] if last_scan else None,
        "findings": last_scan["findings"] if last_scan else 0,
        "last_scan_diagnostic": {"available": last_scan is not None, "error": last_scan_error},
        "quarantine_count": len(entries),
        "scanner_mode": "on-demand",
        "real_time_protection": False,
        "state_dir": str(state_dir),
        "built_in_rules": len(builtin_rules()),
        "feed": feed_status.to_dict(),
        "quarantine": {
            "entries": len(entries),
            "states": counts,
            "metadata_errors": quarantine_errors,
        },
        "inventory": inventory,
    }
    if args.json:
        _emit_json(result)
    else:
        print(f"ZSEC Shield {__version__}: on-demand scanner (real-time protection: no)")
        print(f"State directory: {state_dir}")
        print(f"Feed: {feed_status.state}; verified rules: {feed_status.rules_count}")
        if feed_status.error:
            print(f"Feed error: {feed_status.error}", file=sys.stderr)
        print(f"Quarantine entries: {len(entries)}; metadata errors: {len(quarantine_errors)}")
    return (
        EXIT_INCOMPLETE
        if feed_status.state == "invalid" or quarantine_errors or last_scan_error
        else EXIT_OK
    )


def _command_inventory(args: argparse.Namespace) -> int:
    result = collect_inventory()
    if args.json:
        _emit_json(result)
    else:
        host = result["host"]
        print(
            f"Adapter: {result['adapter']} "
            f"(supported={str(result['supported']).lower()}, read-only=true)"
        )
        print(f"Host: {host['hostname']} | {host['system']} {host['release']} | {host['machine']}")
        for observation in result["observations"]:
            print(f"- {observation}")
    return EXIT_OK


def _command_quarantine_list(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    entries, errors = list_entries(state_dir)
    result = {
        "schema": "zsec.shield.quarantine-list.v1",
        "generated_at": format_utc(),
        "state_dir": str(state_dir),
        "entries": entries,
        "errors": errors,
    }
    if args.json:
        _emit_json(result)
    else:
        if not entries:
            print("No quarantine entries.")
        for entry in entries:
            print(f"{entry['id']}  {entry['state']}  {entry['original_path']}  {entry['sha256']}")
        for error in errors:
            print(f"INVALID {error['entry']}: {error['error']}", file=sys.stderr)
    return EXIT_INCOMPLETE if errors else EXIT_OK


def _command_restore(args: argparse.Namespace) -> int:
    result = restore_entry(args.entry_id, _state_dir(args), args.destination)
    payload = {
        "schema": "zsec.shield.restore-result.v1",
        "restored_at": format_utc(),
        **result,
    }
    if args.json:
        _emit_json(payload)
    else:
        print(
            f"Restored {result['id']} to {result['destination']}; verified recovery copy retained."
        )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except ZsecShieldError as exc:
        payload = {
            "schema": "zsec.shield.error.v1",
            "error": type(exc).__name__,
            "message": str(exc),
        }
        if getattr(args, "json", False):
            _emit_json(payload)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE
    except Exception as exc:
        if args.debug:
            raise
        payload = {
            "schema": "zsec.shield.error.v1",
            "error": "UnexpectedError",
            "message": f"unexpected failure: {type(exc).__name__}: {exc}",
        }
        if getattr(args, "json", False):
            _emit_json(payload)
        else:
            print(payload["message"], file=sys.stderr)
        return EXIT_INCOMPLETE


def entrypoint() -> None:
    raise SystemExit(main())
