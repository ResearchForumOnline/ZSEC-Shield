from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.errors import QuarantineError
from zsec_shield.models import Rule
from zsec_shield.quarantine import list_entries, quarantine_finding, restore_entry
from zsec_shield.scanner import Scanner


class QuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scan_root = self.root / "scan"
        self.state_dir = self.root / "state"
        self.scan_root.mkdir()
        self.pattern = b"benign-quarantine-test-pattern"
        self.rule = Rule(
            "feed:quarantine-test",
            "Quarantine test",
            "literal",
            "high",
            "Benign test rule.",
            "test suite",
            literal=self.pattern,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _finding(self, target: Path):
        result = Scanner((self.rule,)).scan([target])
        self.assertEqual(1, len(result.findings))
        return result.findings[0]

    def test_opt_in_quarantine_and_no_overwrite_restore(self) -> None:
        original = self.scan_root / "sample.bin"
        content = b"prefix" + self.pattern + b"suffix"
        original.write_bytes(content)
        finding = self._finding(original)
        record = quarantine_finding(finding, self.state_dir)
        self.assertEqual("quarantined", record["state"])
        self.assertEqual("zero.security.quarantine.v2", record["schema"])
        expected_protection = (
            "windows-dpapi-current-user" if os.name == "nt" else "filesystem-0600-preview"
        )
        self.assertEqual(expected_protection, record["vault"]["device_key_protection"])
        self.assertFalse(original.exists())
        entries, errors = list_entries(self.state_dir)
        self.assertEqual([], errors)
        self.assertEqual(record["id"], entries[0]["id"])

        destination = self.scan_root / "restored.bin"
        restored = restore_entry(record["id"], self.state_dir, destination)
        self.assertTrue(restored["recovery_copy_retained"])
        self.assertEqual(content, destination.read_bytes())
        with self.assertRaisesRegex(QuarantineError, "already exists"):
            restore_entry(record["id"], self.state_dir, destination)

    def test_quarantine_bytes_are_encrypted_and_ciphertext_tamper_fails(self) -> None:
        original = self.scan_root / "encrypted.bin"
        content = b"secret-prefix" + self.pattern + b"secret-suffix"
        original.write_bytes(content)
        record = quarantine_finding(self._finding(original), self.state_dir)
        entry = self.state_dir / "quarantine" / "entries" / record["id"]
        encrypted = entry / "content.zsv2"
        ciphertext = encrypted.read_bytes()
        self.assertNotEqual(content, ciphertext)
        self.assertNotIn(self.pattern, ciphertext)

        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        encrypted.write_bytes(ciphertext)
        destination = self.scan_root / "tampered-restore.bin"
        with self.assertRaisesRegex(QuarantineError, "authentication failed"):
            restore_entry(record["id"], self.state_dir, destination)
        self.assertFalse(destination.exists())

    def test_metadata_and_zba_tamper_fail_before_restore(self) -> None:
        original = self.scan_root / "metadata.bin"
        original.write_bytes(b"metadata" + self.pattern)
        record = quarantine_finding(self._finding(original), self.state_dir)
        entry = self.state_dir / "quarantine" / "entries" / record["id"]
        metadata_path = entry / "metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["zba"]["phase"] = "emerging"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        destination = self.scan_root / "metadata-tamper.bin"
        with self.assertRaisesRegex(QuarantineError, "metadata authentication failed"):
            restore_entry(record["id"], self.state_dir, destination)
        self.assertFalse(destination.exists())

    def test_changed_file_is_not_removed(self) -> None:
        original = self.scan_root / "changed.bin"
        original.write_bytes(self.pattern)
        finding = self._finding(original)
        original.write_bytes(b"changed after scan")
        with self.assertRaisesRegex(QuarantineError, "no longer matches"):
            quarantine_finding(finding, self.state_dir)
        self.assertTrue(original.exists())
        entries, _ = list_entries(self.state_dir)
        self.assertEqual([], entries)


if __name__ == "__main__":
    unittest.main()
