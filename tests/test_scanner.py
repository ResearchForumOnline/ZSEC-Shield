from __future__ import annotations

import hashlib
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.models import Rule
from zsec_shield.rules import builtin_rules
from zsec_shield.scanner import Scanner, ScannerConfig


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_clean_file_is_hashed_without_a_finding(self) -> None:
        (self.root / "clean.txt").write_text("ordinary content", encoding="utf-8")
        result = Scanner(builtin_rules()).scan([self.root])
        self.assertEqual(1, result.stats.files_hashed)
        self.assertEqual([], result.findings)
        self.assertEqual([], result.issues)

    def test_file_filter_can_skip_unchanged_files_without_hashing_them(self) -> None:
        target = self.root / "unchanged.bin"
        target.write_bytes(b"unchanged")
        observed: list[Path] = []
        result = Scanner(()).scan(
            [self.root],
            file_filter=lambda path, _metadata: observed.append(path) is not None,
        )
        self.assertEqual([target], observed)
        self.assertEqual(0, result.stats.files_hashed)
        self.assertEqual([], result.issues)

    def test_file_filter_failure_is_an_incomplete_scan_issue(self) -> None:
        target = self.root / "filter-error.bin"
        target.write_bytes(b"filter error")

        def fail(_path: Path, _metadata: os.stat_result) -> bool:
            raise RuntimeError("test filter failure")

        result = Scanner(()).scan([self.root], file_filter=fail)
        self.assertEqual(0, result.stats.files_hashed)
        self.assertEqual("file_filter_failed", result.issues[0].code)

    def test_sha256_rule_matches_exact_digest(self) -> None:
        content = b"deterministic digest test"
        target = self.root / "sample.bin"
        target.write_bytes(content)
        rule = Rule(
            "feed:test-sha",
            "Test SHA",
            "sha256",
            "medium",
            "Test digest match.",
            "test suite",
            digest=hashlib.sha256(content).hexdigest(),
        )
        result = Scanner((rule,)).scan([self.root])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("feed:test-sha", result.findings[0].matches[0].rule_id)

    def test_literal_rule_matches_across_chunk_boundary(self) -> None:
        pattern = b"cross-boundary-pattern"
        target = self.root / "boundary.bin"
        target.write_bytes(b"A" * 4090 + pattern + b"tail")
        rule = Rule(
            "feed:test-literal",
            "Test literal",
            "literal",
            "high",
            "Test literal match.",
            "test suite",
            literal=pattern,
        )
        result = Scanner((rule,), ScannerConfig(chunk_bytes=4096)).scan([self.root])
        self.assertEqual(1, len(result.findings))

    def test_eicar_builtins_match_literal_and_hash(self) -> None:
        rules = builtin_rules()
        eicar = next(rule.literal for rule in rules if rule.rule_id == "builtin:eicar-test-file")
        self.assertIsNotNone(eicar)
        assert eicar is not None
        matches = []
        digest = hashlib.sha256(eicar).hexdigest()
        for rule in rules:
            if rule.kind == "literal" and rule.literal in eicar:
                matches.append(rule.rule_id)
            if rule.kind == "sha256" and rule.digest == digest:
                matches.append(rule.rule_id)
        self.assertEqual(
            ["builtin:eicar-test-file", "builtin:eicar-test-file-sha256"],
            matches,
        )

    def test_oversize_file_is_skipped_and_reported_in_stats(self) -> None:
        (self.root / "large.bin").write_bytes(b"x" * 100)
        result = Scanner((), ScannerConfig(max_file_bytes=50)).scan([self.root])
        self.assertEqual(0, result.stats.files_hashed)
        self.assertEqual(1, result.stats.skipped_too_large)

    def test_symlink_is_not_followed(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable in this test environment")
        try:
            result = Scanner(()).scan([self.root])
            self.assertEqual(1, result.stats.skipped_symlinks)
            self.assertEqual(0, result.stats.files_hashed)
        finally:
            outside.unlink(missing_ok=True)

    def test_missing_root_is_an_operational_issue(self) -> None:
        result = Scanner(()).scan([self.root / "missing"])
        self.assertEqual(1, result.stats.errors)
        self.assertEqual("root_unreadable", result.issues[0].code)

    def test_explicit_exclusion_is_not_scanned(self) -> None:
        excluded = self.root / "state"
        excluded.mkdir()
        (excluded / "data.bin").write_bytes(os.urandom(32))
        result = Scanner((), ScannerConfig(excluded_paths=(excluded,))).scan([self.root])
        self.assertEqual(0, result.stats.files_hashed)
        self.assertEqual(1, result.stats.skipped_excluded)


if __name__ == "__main__":
    unittest.main()
