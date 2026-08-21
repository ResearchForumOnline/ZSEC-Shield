"""Bounded, non-following filesystem scanner with streaming rule matching."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zsec_shield.errors import ScanConfigurationError
from zsec_shield.models import FileFinding, Rule, RuleMatch, ScanIssue, ScanResult, ScanStats
from zsec_shield.rules import highest_severity
from zsec_shield.util import format_utc, utc_now

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    chunk_bytes: int = DEFAULT_CHUNK_BYTES
    cross_filesystems: bool = False
    excluded_paths: tuple[Path, ...] = ()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(_absolute(path))))


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def _same_opened_file(before: os.stat_result, opened: os.stat_result) -> bool:
    before_device = getattr(before, "st_dev", 0)
    opened_device = getattr(opened, "st_dev", 0)
    if (
        before_device and opened_device and before_device != opened_device
    ) or before.st_size != opened.st_size:
        return False
    before_inode = getattr(before, "st_ino", 0)
    opened_inode = getattr(opened, "st_ino", 0)
    return not (before_inode and opened_inode and before_inode != opened_inode)


class Scanner:
    def __init__(self, rules: tuple[Rule, ...], config: ScannerConfig | None = None) -> None:
        self.rules = tuple(sorted(rules, key=lambda rule: rule.rule_id))
        self.config = config or ScannerConfig()
        if not 1 <= self.config.max_file_bytes <= 16 * 1024 * 1024 * 1024:
            raise ScanConfigurationError("max_file_bytes must be between 1 and 16 GiB")
        if not 4096 <= self.config.chunk_bytes <= 16 * 1024 * 1024:
            raise ScanConfigurationError("chunk_bytes must be between 4096 and 16 MiB")
        identifiers = [rule.rule_id for rule in self.rules]
        if len(set(identifiers)) != len(identifiers):
            raise ScanConfigurationError("rule IDs must be unique")
        for rule in self.rules:
            if rule.kind == "sha256" and rule.digest is None:
                raise ScanConfigurationError(f"SHA-256 rule has no digest: {rule.rule_id}")
            if rule.kind == "literal" and not rule.literal:
                raise ScanConfigurationError(f"literal rule has no pattern: {rule.rule_id}")
        self._excluded = tuple(_path_key(path) for path in self.config.excluded_paths)
        self._literal_rules = tuple(rule for rule in self.rules if rule.kind == "literal")
        self._digest_rules = tuple(rule for rule in self.rules if rule.kind == "sha256")
        self._maximum_literal = max(
            (len(rule.literal or b"") for rule in self._literal_rules),
            default=0,
        )

    def scan(
        self,
        roots: list[Path],
        *,
        file_filter: Callable[[Path, os.stat_result], bool] | None = None,
        file_observer: Callable[[Path, os.stat_result, bool], None] | None = None,
    ) -> ScanResult:
        if not roots:
            raise ScanConfigurationError("at least one scan path is required")
        started = utc_now()
        absolute_roots = [_absolute(root) for root in roots]
        stats = ScanStats(roots_requested=len(absolute_roots))
        issues: list[ScanIssue] = []
        findings: list[FileFinding] = []
        seen_paths: set[str] = set()
        for root in sorted(absolute_roots, key=_path_key):
            for path, metadata in self._iter_regular_files(root, stats, issues):
                key = _path_key(path)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                if file_filter is not None:
                    try:
                        if not file_filter(path, metadata):
                            continue
                    except Exception as exc:
                        self._issue(issues, path, "file_filter_failed", exc)
                        continue
                hashed_before = stats.files_hashed
                finding = self._scan_file(path, metadata, stats, issues)
                hashed = stats.files_hashed > hashed_before
                if file_observer is not None:
                    try:
                        file_observer(path, metadata, hashed)
                    except Exception as exc:
                        self._issue(issues, path, "file_observer_failed", exc)
                if finding is not None:
                    findings.append(finding)
        findings.sort(key=lambda finding: os.path.normcase(finding.path))
        issues.sort(key=lambda issue: (os.path.normcase(issue.path), issue.code))
        stats.findings = len(findings)
        stats.errors = len(issues)
        return ScanResult(
            started_at=format_utc(started),
            completed_at=format_utc(),
            roots=[str(path) for path in absolute_roots],
            findings=findings,
            issues=issues,
            stats=stats,
        )

    def _is_excluded(self, path: Path) -> bool:
        candidate = _path_key(path)
        for excluded in self._excluded:
            try:
                if os.path.commonpath((candidate, excluded)) == excluded:
                    return True
            except ValueError:
                continue
        return False

    def _issue(
        self,
        issues: list[ScanIssue],
        path: Path,
        code: str,
        error: BaseException | str,
    ) -> None:
        message = str(error).replace("\r", " ").replace("\n", " ")[:500]
        issues.append(ScanIssue(str(_absolute(path)), code, message))

    def _iter_regular_files(
        self,
        root: Path,
        stats: ScanStats,
        issues: list[ScanIssue],
    ) -> Iterator[tuple[Path, os.stat_result]]:
        if self._is_excluded(root):
            stats.skipped_excluded += 1
            return
        try:
            root_metadata = root.lstat()
        except OSError as exc:
            self._issue(issues, root, "root_unreadable", exc)
            return
        if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata):
            stats.skipped_symlinks += 1
            return
        if stat.S_ISREG(root_metadata.st_mode):
            yield root, root_metadata
            return
        if not stat.S_ISDIR(root_metadata.st_mode):
            stats.skipped_special += 1
            return

        root_device = root_metadata.st_dev
        stack: list[Path] = [root]
        visited: set[tuple[int, int]] = set()
        while stack:
            directory = stack.pop()
            try:
                directory_metadata = directory.lstat()
            except OSError as exc:
                self._issue(issues, directory, "directory_unreadable", exc)
                continue
            identity = (directory_metadata.st_dev, getattr(directory_metadata, "st_ino", 0))
            if identity[1] and identity in visited:
                stats.skipped_symlinks += 1
                continue
            visited.add(identity)
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(
                        iterator, key=lambda entry: (entry.name.casefold(), entry.name)
                    )
            except OSError as exc:
                self._issue(issues, directory, "directory_unreadable", exc)
                continue
            child_directories: list[Path] = []
            for entry in entries:
                path = Path(entry.path)
                if self._is_excluded(path):
                    stats.skipped_excluded += 1
                    continue
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    self._issue(issues, path, "entry_unreadable", exc)
                    continue
                if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                    stats.skipped_symlinks += 1
                elif stat.S_ISDIR(metadata.st_mode):
                    child_device = getattr(metadata, "st_dev", 0)
                    if (
                        not self.config.cross_filesystems
                        and root_device
                        and child_device
                        and child_device != root_device
                    ):
                        stats.skipped_filesystems += 1
                    else:
                        child_directories.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    yield path, metadata
                else:
                    stats.skipped_special += 1
            stack.extend(reversed(child_directories))

    def _scan_file(
        self,
        path: Path,
        before: os.stat_result,
        stats: ScanStats,
        issues: list[ScanIssue],
    ) -> FileFinding | None:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            self._issue(issues, path, "file_open_failed", exc)
            return None
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_opened_file(before, opened):
                self._issue(issues, path, "file_changed_before_scan", "file identity changed")
                return None
            if opened.st_size > self.config.max_file_bytes:
                stats.skipped_too_large += 1
                return None
            digest = hashlib.sha256()
            literal_matches: set[str] = set()
            tail = b""
            bytes_read = 0
            while True:
                chunk = os.read(descriptor, self.config.chunk_bytes)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if bytes_read > self.config.max_file_bytes:
                    stats.skipped_too_large += 1
                    return None
                digest.update(chunk)
                window = tail + chunk
                for rule in self._literal_rules:
                    if rule.rule_id not in literal_matches and (rule.literal or b"") in window:
                        literal_matches.add(rule.rule_id)
                if self._maximum_literal > 1:
                    tail = window[-(self._maximum_literal - 1) :]
            after = os.fstat(descriptor)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or bytes_read != opened.st_size
            ):
                self._issue(issues, path, "file_changed_during_scan", "file changed while hashing")
                return None
            hex_digest = digest.hexdigest()
            matched_rules = [
                rule for rule in self._literal_rules if rule.rule_id in literal_matches
            ]
            matched_rules.extend(rule for rule in self._digest_rules if rule.digest == hex_digest)
            stats.files_hashed += 1
            stats.bytes_hashed += bytes_read
            if not matched_rules:
                return None
            matches = [
                RuleMatch.from_rule(rule)
                for rule in sorted(matched_rules, key=lambda item: item.rule_id)
            ]
            modified = datetime.fromtimestamp(opened.st_mtime, UTC)
            return FileFinding(
                path=str(_absolute(path)),
                sha256=hex_digest,
                size=bytes_read,
                modified_at=format_utc(modified),
                severity=highest_severity(match.severity for match in matches),
                matches=matches,
            )
        except OSError as exc:
            self._issue(issues, path, "file_read_failed", exc)
            return None
        finally:
            os.close(descriptor)
