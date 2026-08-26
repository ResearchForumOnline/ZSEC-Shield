"""Command-line interface for ZSEC Shield scanning and post-change watch mode."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from zsec_shield import __version__
from zsec_shield.automatic_updates import (
    DEFAULT_APPLICATION_UPDATE_URL,
    DEFAULT_INTELLIGENCE_URL,
    load_application_update_status,
    load_automatic_update_status,
    run_automatic_application_update_check,
    run_automatic_update,
    verify_application_update_envelope,
)
from zsec_shield.errors import QuarantinePartialError, WatchError, ZsecShieldError
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
from zsec_shield.readiness import replacement_readiness
from zsec_shield.recovery_drill import run_recovery_drill
from zsec_shield.rules import builtin_rules
from zsec_shield.scanner import DEFAULT_CHUNK_BYTES, DEFAULT_MAX_FILE_BYTES, Scanner, ScannerConfig
from zsec_shield.status_store import load_last_scan, save_last_scan
from zsec_shield.util import atomic_write_json, format_utc
from zsec_shield.watch_evidence import WatchEvidenceSink
from zsec_shield.watcher import ForegroundProtectionWatcher, WatchConfig, watch_lock

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


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
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


def _add_watch_parser(subparsers: Any, name: str, help_text: str) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path.cwd()])
    parser.add_argument(
        "--backend",
        choices=("auto", "native", "polling"),
        default="auto",
        help="prefer native OS events, require them, or deliberately poll",
    )
    parser.add_argument(
        "--debounce-seconds",
        type=_positive_float,
        default=0.75,
        help="quiet period used to combine duplicate events (default: 0.75)",
    )
    parser.add_argument(
        "--poll-seconds",
        type=_positive_float,
        default=1.0,
        help="polling fallback interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--reconcile-seconds",
        type=_positive_float,
        default=60.0,
        help="metadata reconciliation interval used to reduce missed-event risk (default: 60)",
    )
    parser.add_argument(
        "--full-rescan-seconds",
        type=_positive_float,
        default=24 * 60 * 60.0,
        help="cache-independent full hashing interval (default: 86400)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=_positive_float,
        help="stop after this duration; omit to run until interrupted",
    )
    parser.add_argument(
        "--event-queue-size",
        type=_positive_integer,
        default=4096,
        help="bounded raw event queue capacity (default: 4096)",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=_positive_float,
        default=30.0,
        help="health heartbeat interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=_positive_integer,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"do not inspect files larger than this (default: {DEFAULT_MAX_FILE_BYTES})",
    )
    parser.add_argument("--chunk-bytes", type=_positive_integer, default=DEFAULT_CHUNK_BYTES)
    parser.add_argument(
        "--cross-filesystems",
        action="store_true",
        help="allow watched scans to cross filesystem/device boundaries",
    )
    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="explicitly opt in to quarantining configured-rule matches",
    )
    parser.add_argument("--report", type=Path, help="write the final session report atomically")
    parser.add_argument(
        "--health-file",
        type=Path,
        help="atomically write compact health below the excluded state directory",
    )
    parser.add_argument(
        "--event-log",
        type=Path,
        help="append bounded NDJSON evidence below the excluded state directory",
    )
    parser.add_argument(
        "--event-log-max-bytes",
        type=_positive_integer,
        default=4 * 1024 * 1024,
        help="rotate the event log before it exceeds this bound (default: 4194304)",
    )
    parser.add_argument(
        "--event-log-backups",
        type=_positive_integer,
        default=3,
        help="number of rotated event logs to retain (default: 3)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress routine console output; evidence files remain active",
    )
    parser.add_argument(
        "--json-lines",
        "--json",
        dest="json",
        action="store_true",
        help="emit newline-delimited structured watch events",
    )
    parser.set_defaults(handler=_command_watch)


def build_parser() -> argparse.ArgumentParser:
    invoked_as = Path(sys.argv[0]).stem.lower()
    program_name = "zero-security" if invoked_as == "zero-security" else "zsec-shield"
    parser = argparse.ArgumentParser(
        prog=program_name,
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
    _add_watch_parser(
        subparsers,
        "watch",
        "foreground post-change protection; not kernel real-time protection",
    )
    _add_watch_parser(
        subparsers,
        "protect",
        "alias for foreground post-change protection; existing antivirus stays active",
    )

    update = subparsers.add_parser("update", help="verify and install a signed data-only rule feed")
    source = update.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="credential-free HTTPS feed URL")
    source.add_argument("--file", type=Path, help="local regular feed file")
    update.add_argument("--timeout", type=float, default=15.0, help="HTTPS timeout in seconds")
    update.add_argument("--json", action="store_true")
    update.set_defaults(handler=_command_update)

    automatic = subparsers.add_parser(
        "update-intelligence",
        help="check the release-owned signed, data-only advisory catalog",
    )
    automatic.add_argument("--url", default=DEFAULT_INTELLIGENCE_URL, help=argparse.SUPPRESS)
    automatic.add_argument("--timeout", type=float, default=15.0)
    automatic.add_argument("--force", action="store_true", help="check now even if not due")
    automatic.add_argument("--json", action="store_true")
    automatic.set_defaults(handler=_command_update_intelligence)

    application_update = subparsers.add_parser(
        "check-application-update",
        help="verify a notification-only application release manifest",
    )
    application_update.add_argument(
        "--url", default=DEFAULT_APPLICATION_UPDATE_URL, help=argparse.SUPPRESS
    )
    application_update.add_argument("--timeout", type=float, default=15.0)
    application_update.add_argument("--json", action="store_true")
    application_update.set_defaults(handler=_command_check_application_update)

    automatic_application_update = subparsers.add_parser(
        "update-application-notice",
        help="schedule a signed, notification-only application update check",
    )
    automatic_application_update.add_argument(
        "--url", default=DEFAULT_APPLICATION_UPDATE_URL, help=argparse.SUPPRESS
    )
    automatic_application_update.add_argument("--timeout", type=float, default=15.0)
    automatic_application_update.add_argument(
        "--force", action="store_true", help="check now even if not due"
    )
    automatic_application_update.add_argument("--json", action="store_true")
    automatic_application_update.set_defaults(handler=_command_update_application_notice)

    status = subparsers.add_parser("status", help="show scanner, feed, and quarantine status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(handler=_command_status)

    inventory = subparsers.add_parser("inventory", help="collect read-only platform inventory")
    inventory.add_argument("--json", action="store_true")
    inventory.set_defaults(handler=_command_inventory)

    runtime = subparsers.add_parser(
        "runtime-identity",
        help="report the exact executable hosting the ZSEC Antivirus engine",
    )
    runtime.add_argument("--json", action="store_true")
    runtime.set_defaults(handler=_command_runtime_identity)

    readiness = subparsers.add_parser(
        "replacement-readiness",
        help="fail closed unless every primary-antivirus replacement gate is evidenced",
    )
    readiness.add_argument(
        "--platform",
        choices=("windows", "linux", "macos"),
        help="inspect a platform programme instead of the detected desktop",
    )
    readiness.add_argument("--json", action="store_true")
    readiness.set_defaults(handler=_command_replacement_readiness)

    recovery_drill = subparsers.add_parser(
        "recovery-drill",
        help="self-test encrypted quarantine and restore with isolated synthetic data",
    )
    recovery_drill.add_argument("--json", action="store_true")
    recovery_drill.set_defaults(handler=_command_recovery_drill)

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
            worker_isolation=True,
        ),
    )
    try:
        result = scanner.scan(args.paths)
    finally:
        scanner.close()
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
    elif result.observations:
        outcome = "review_observations"
    else:
        outcome = "no_configured_rule_matches"
    try:
        save_last_scan(
            state_dir,
            completed_at=result.completed_at,
            findings=len(result.findings),
            issues=len(result.issues),
            files_hashed=result.stats.files_hashed,
            bytes_hashed=result.stats.bytes_hashed,
            observations=len(result.observations),
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
            "content_worker": "bounded_out_of_process_rules_and_review_providers",
            "content_worker_reduced_privilege": False,
            "feed_behavior": "data-only rules; no commands or actions are accepted",
            "quarantine_requested": bool(args.quarantine),
            "heuristic_observations_quarantine_eligible": False,
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
    return EXIT_FINDINGS if result.findings or result.observations else EXIT_OK


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
    for observation in report["scan"]["observations"]:
        print(
            "REVIEW "
            f"[{observation['severity'].upper()}] {observation['path']} "
            f"({observation['provider']}:{observation['category']}; no auto-quarantine)"
        )
    for issue in report["scan"]["issues"]:
        print(f"INCOMPLETE {issue['path']}: {issue['code']}: {issue['message']}", file=sys.stderr)
    if report["quarantine"]:
        print(f"Quarantine operations: {len(report['quarantine'])} (recovery copies retained).")
    if report_path is not None:
        print(f"JSON report: {report_path.expanduser().absolute()}")
    print("Result is rule-limited and on-demand; it is not a declaration that the system is clean.")


def _command_watch(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    keyring_path = _keyring_path(args, state_dir)
    feed_status, feed_rules = inspect_feed(state_dir, keyring_path)
    if feed_status.state == "invalid":
        raise WatchError(
            "foreground watch refused to start because the configured feed/trust state is invalid"
        )
    initial_feed_identity = (
        feed_status.state,
        feed_status.sequence,
        feed_status.payload_sha256,
        feed_status.expires_at,
    )

    scanner = Scanner(
        builtin_rules() + feed_rules,
        ScannerConfig(
            max_file_bytes=args.max_file_bytes,
            chunk_bytes=args.chunk_bytes,
            cross_filesystems=args.cross_filesystems,
            excluded_paths=(state_dir,),
            worker_isolation=True,
        ),
    )
    evidence = WatchEvidenceSink(
        state_dir=state_dir,
        health_file=args.health_file,
        event_log=args.event_log,
        event_log_max_bytes=args.event_log_max_bytes,
        event_log_backups=args.event_log_backups,
        heartbeat_seconds=args.heartbeat_seconds,
    )

    def feed_health() -> str | None:
        current, _rules = inspect_feed(state_dir, keyring_path)
        if current.state == "invalid":
            return "configured feed/trust state became invalid; watch stopped fail-closed"
        identity = (current.state, current.sequence, current.payload_sha256, current.expires_at)
        if identity != initial_feed_identity:
            return "configured feed changed; restart watch to load and bind the new rules"
        return None

    def emit(record: dict[str, Any]) -> None:
        payload = {"version": __version__, **record}
        evidence.record(payload)
        if args.quiet:
            return
        if args.json:
            print(json.dumps(payload, sort_keys=True, ensure_ascii=False), flush=True)
        else:
            _print_watch_event(payload)

    watcher = ForegroundProtectionWatcher(
        scanner,
        WatchConfig(
            roots=tuple(args.paths),
            state_dir=state_dir,
            backend=args.backend,
            debounce_seconds=args.debounce_seconds,
            poll_seconds=args.poll_seconds,
            reconcile_seconds=args.reconcile_seconds,
            full_rescan_seconds=args.full_rescan_seconds,
            cross_filesystems=args.cross_filesystems,
            quarantine=bool(args.quarantine),
            event_queue_size=args.event_queue_size,
            heartbeat_seconds=args.heartbeat_seconds,
        ),
        on_record=emit,
        health_check=feed_health,
    )
    try:
        with watch_lock(state_dir):
            summary = watcher.run(duration_seconds=args.duration_seconds)
    finally:
        scanner.close()
    report = {
        "schema": "zsec.shield.watch-report.v1",
        "version": __version__,
        "generated_at": format_utc(),
        "command": args.command,
        "feed": feed_status.to_dict(),
        "rules": {
            "built_in": len(builtin_rules()),
            "verified_feed": len(feed_rules),
            "total": len(scanner.rules),
        },
        "content_worker": {
            "mode": "bounded_out_of_process_rules_and_review_providers",
            "reduced_privilege": False,
            "hostile_format_parser_gate_met": False,
        },
        "session": summary.to_dict(),
        "limitations": [
            "This foreground companion observes filesystem events but does not mediate access.",
            "It is not a kernel or operating-system primary antivirus provider.",
            (
                "Event backends can lose events; reconciliation reduces but cannot "
                "eliminate that risk."
            ),
            "No configured match does not prove that a file or system is clean.",
            "Keep the existing antivirus and operating-system protections active.",
        ],
    }
    if args.report is not None:
        atomic_write_json(args.report.expanduser().absolute(), report, mode=0o600)
    if not args.json and not args.quiet:
        print(
            "Foreground watch ended: "
            f"{summary.outcome}; findings {summary.stats.findings}; "
            f"issues {summary.stats.issues}; backend {summary.backend_active}."
        )
        if args.report is not None:
            print(f"JSON report: {args.report.expanduser().absolute()}")
    if summary.interrupted:
        return 130
    if summary.operational_incomplete:
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if summary.stats.findings else EXIT_OK


def _print_watch_event(record: dict[str, Any]) -> None:
    event = record["event"]
    if event == "session_started":
        roots = ", ".join(record["roots"])
        print(
            "ZSEC Antivirus foreground post-change protection started "
            f"({record['backend_active']}) for {roots}."
        )
        print("Keep the existing antivirus active; this mode does not block kernel access.")
        if record["policy"]["quarantine_requested"]:
            print("Explicit quarantine opt-in is active for configured-rule matches.")
        else:
            print("Quarantine is off; matched files will not be moved.")
    elif event == "backend_fallback":
        print(f"WATCH FALLBACK {record['reason']}", file=sys.stderr)
    elif event == "health_issue":
        print(f"WATCH INCOMPLETE {record['code']}: {record['message']}", file=sys.stderr)
    elif event == "scan_completed":
        scan = record["scan"]
        for finding in scan["findings"]:
            names = ", ".join(match["id"] for match in finding["matches"])
            print(f"MATCH [{finding['severity'].upper()}] {finding['path']} ({names})")
        for issue in scan["issues"]:
            print(
                f"INCOMPLETE {issue['path']}: {issue['code']}: {issue['message']}",
                file=sys.stderr,
            )


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


def _command_update_intelligence(args: argparse.Namespace) -> int:
    if not 1 <= args.timeout <= 120:
        raise ZsecShieldError("timeout must be between 1 and 120 seconds")
    state_dir = _state_dir(args)
    status = run_automatic_update(
        state_dir,
        _keyring_path(args, state_dir),
        source=args.url,
        timeout=args.timeout,
        force=bool(args.force),
    )
    result = status.to_dict()
    if args.json:
        _emit_json(result)
    else:
        print(
            f"Intelligence update: {status.state}; sequence "
            f"{status.feed_sequence or 'not installed'}; next check {status.next_check_at}."
        )
        if status.error:
            print(f"Update error: {status.error}", file=sys.stderr)
    return EXIT_INCOMPLETE if status.state == "error" else EXIT_OK


def _command_check_application_update(args: argparse.Namespace) -> int:
    if not 1 <= args.timeout <= 120:
        raise ZsecShieldError("timeout must be between 1 and 120 seconds")
    state_dir = _state_dir(args)
    result = verify_application_update_envelope(
        download_feed(args.url, timeout=args.timeout),
        _keyring_path(args, state_dir),
    )
    if args.json:
        _emit_json(result)
    else:
        print(
            f"Verified ZSEC {result['version']} application update notice; "
            "automatic installation is disabled."
        )
    return EXIT_OK


def _command_update_application_notice(args: argparse.Namespace) -> int:
    if not 1 <= args.timeout <= 120:
        raise ZsecShieldError("timeout must be between 1 and 120 seconds")
    state_dir = _state_dir(args)
    status = run_automatic_application_update_check(
        state_dir,
        _keyring_path(args, state_dir),
        __version__,
        source=args.url,
        timeout=args.timeout,
        force=bool(args.force),
    )
    if args.json:
        _emit_json(status.to_dict())
    else:
        print(
            f"Application update notice: {status.state}; installed {status.installed_version}; "
            f"available {status.available_version or 'none'}; next check {status.next_check_at}."
        )
        if status.error:
            print(f"Update notice error: {status.error}", file=sys.stderr)
    return EXIT_INCOMPLETE if status.state == "error" else EXIT_OK


def _command_status(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    keyring_path = _keyring_path(args, state_dir)
    feed_status, _ = inspect_feed(state_dir, keyring_path)
    update_status = load_automatic_update_status(state_dir)
    application_update_status = load_application_update_status(state_dir, __version__)
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
        "schema": "zsec.shield.status.v2",
        "contract_version": 2,
        "version": __version__,
        "generated_at": format_utc(),
        "platform": platform_name,
        "definitions": definitions,
        "last_scan": last_scan["completed_at"] if last_scan else None,
        "findings": last_scan["findings"] if last_scan else 0,
        "observations": last_scan["observations"] if last_scan else 0,
        "last_scan_outcome": last_scan["outcome"] if last_scan else None,
        "last_scan_errors": last_scan["issues"] if last_scan else 0,
        "last_scan_files_hashed": last_scan["files_hashed"] if last_scan else None,
        "last_scan_bytes_hashed": last_scan["bytes_hashed"] if last_scan else None,
        "last_scan_diagnostic": {"available": last_scan is not None, "error": last_scan_error},
        "quarantine_count": len(entries),
        "scanner_mode": "on-demand",
        "content_worker": {
            "mode": "bounded_out_of_process_rules_and_review_providers",
            "path_disclosure": False,
            "broker_digest_verification": True,
            "reduced_privilege": False,
            "hostile_format_parser_gate_met": False,
        },
        "real_time_protection": False,
        "state_dir": str(state_dir),
        "built_in_rules": len(builtin_rules()),
        "feed": feed_status.to_dict(),
        "update_status": {
            key: value
            for key, value in update_status.to_dict().items()
            if key != "schema"
        },
        "application_update_status": {
            key: value
            for key, value in application_update_status.to_dict().items()
            if key != "schema"
        },
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


def _command_runtime_identity(args: argparse.Namespace) -> int:
    executable = Path(sys.executable).resolve()
    digest = hashlib.sha256()
    try:
        with executable.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ZsecShieldError(f"cannot hash active runtime executable: {exc}") from exc
    result = {
        "schema": "zsec.antivirus.runtime-identity.v1",
        "product": "ZSEC Antivirus",
        "engine": "ZSEC Shield",
        "version": __version__,
        "runtime_executable": str(executable),
        "runtime_sha256": digest.hexdigest(),
        "read_only": True,
    }
    if args.json:
        _emit_json(result)
    else:
        print(
            f"ZSEC Antivirus {__version__} runtime: "
            f"{result['runtime_executable']} ({result['runtime_sha256']})"
        )
    return EXIT_OK


def _command_replacement_readiness(args: argparse.Namespace) -> int:
    result = replacement_readiness(args.platform)
    if args.json:
        _emit_json(result)
    else:
        print("Zero Security replacement decision: KEEP EXISTING PROTECTION")
        print(f"Platform programme: {result['platform']}")
        print("Eligible to replace the current antivirus: no")
        print(f"Blocking production gates: {result['gate_counts']['not_met']}")
        for gate in result["blocking_gates"]:
            print(f"- NOT MET {gate['id']}: {gate['title']}")
        print(result["next_action"])
    # This command is intended to guard uninstall and cutover automation. The
    # preview cannot return success while replacement evidence is incomplete.
    return EXIT_INCOMPLETE


def _command_recovery_drill(args: argparse.Namespace) -> int:
    result = run_recovery_drill()
    if args.json:
        _emit_json(result)
    else:
        outcome = "PASSED" if result["passed"] else "FAILED"
        print(f"ZSEC Antivirus isolated recovery drill: {outcome}")
        for check in result["checks"]:
            state = "PASS" if check["passed"] else "FAIL"
            print(f"- {state} {check['id']}")
            if check["error"]:
                print(f"  {check['error']}")
        print("This local self-test is not independent replacement certification.")
    return EXIT_OK if result["passed"] else EXIT_INCOMPLETE


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
