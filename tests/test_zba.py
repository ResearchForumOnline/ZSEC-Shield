from __future__ import annotations

import copy
import unittest

from zsec_shield.errors import QuarantineError
from zsec_shield.zba import create_quarantine_record, validate_quarantine_record


class ZbaQuarantineRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry_id = "11111111-2222-3333-4444-555555555555"
        self.digest = "a" * 64
        self.record = create_quarantine_record(
            entry_id=self.entry_id,
            payload_sha256=self.digest,
            created_at="2026-08-21T12:00:00Z",
        )

    def test_reference_record_validates(self) -> None:
        validated = validate_quarantine_record(
            self.record, entry_id=self.entry_id, payload_sha256=self.digest
        )
        self.assertEqual("boundary", validated["phase"])
        self.assertEqual("sealed", validated["evidence_status"])

    def test_typed_or_committed_field_mutation_is_rejected(self) -> None:
        for field, replacement in (
            ("phase", "emerging"),
            ("evidence_status", "checked"),
            ("operation", "quarantine.restore"),
            ("commitment", "b" * 64),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.record)
                mutated[field] = replacement
                with self.assertRaises(QuarantineError):
                    validate_quarantine_record(
                        mutated, entry_id=self.entry_id, payload_sha256=self.digest
                    )


if __name__ == "__main__":
    unittest.main()
