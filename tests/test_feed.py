from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import literal_rule, make_signing_material, signed_feed
from zsec_shield.errors import FeedError
from zsec_shield.feed import inspect_feed, install_feed, load_keyring, verify_feed_document
from zsec_shield.paths import feed_document_path
from zsec_shield.util import strict_json_loads


class FeedVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
        self.private_key, self.keyring_path = make_signing_material(self.root)
        self.keyring = load_keyring(self.keyring_path, now=self.now)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_ed25519_feed_produces_typed_rule(self) -> None:
        raw = signed_feed(
            self.private_key,
            now=self.now,
            rules=[literal_rule("feed:test-pattern", b"safe-test-pattern")],
        )
        verified = verify_feed_document(raw, self.keyring, now=self.now)
        self.assertEqual(1, verified.sequence)
        self.assertEqual("feed:test-pattern", verified.rules[0].rule_id)
        self.assertEqual(b"safe-test-pattern", verified.rules[0].literal)

    def test_payload_tampering_fails_signature(self) -> None:
        document = json.loads(signed_feed(self.private_key, now=self.now))
        document["payload"]["sequence"] = 2
        with self.assertRaisesRegex(FeedError, "signature"):
            verify_feed_document(json.dumps(document).encode(), self.keyring, now=self.now)

    def test_expired_feed_is_rejected(self) -> None:
        generated = self.now - timedelta(days=2)
        raw = signed_feed(
            self.private_key,
            now=generated,
            expires_delta=timedelta(days=1),
        )
        with self.assertRaisesRegex(FeedError, "expired"):
            verify_feed_document(raw, self.keyring, now=self.now)

    def test_signed_unknown_payload_field_is_rejected(self) -> None:
        raw = signed_feed(
            self.private_key,
            now=self.now,
            extra_payload={"commands": ["not allowed"]},
        )
        with self.assertRaisesRegex(FeedError, "unexpected=commands"):
            verify_feed_document(raw, self.keyring, now=self.now)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(FeedError, "duplicate JSON key"):
            strict_json_loads('{"schema":"one","schema":"two"}')

    def test_rollback_and_sequence_reuse_are_rejected(self) -> None:
        state_dir = self.root / "state"
        install_feed(
            signed_feed(self.private_key, sequence=2, now=self.now),
            state_dir,
            self.keyring_path,
            now=self.now,
        )
        with self.assertRaisesRegex(FeedError, "rollback"):
            install_feed(
                signed_feed(self.private_key, sequence=1, now=self.now),
                state_dir,
                self.keyring_path,
                now=self.now,
            )
        with self.assertRaisesRegex(FeedError, "sequence reuse"):
            install_feed(
                signed_feed(
                    self.private_key,
                    sequence=2,
                    now=self.now,
                    rules=[literal_rule("feed:different", b"different")],
                ),
                state_dir,
                self.keyring_path,
                now=self.now,
            )

    def test_installed_feed_is_reverified_and_tamper_fails_closed(self) -> None:
        state_dir = self.root / "state"
        install_feed(
            signed_feed(
                self.private_key,
                now=self.now,
                rules=[literal_rule("feed:active", b"active")],
            ),
            state_dir,
            self.keyring_path,
            now=self.now,
        )
        status, rules = inspect_feed(state_dir, self.keyring_path, now=self.now)
        self.assertEqual("valid", status.state)
        self.assertEqual(1, len(rules))
        document_path = feed_document_path(state_dir)
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["payload"]["rules"] = []
        document_path.write_text(json.dumps(document), encoding="utf-8")
        status, rules = inspect_feed(state_dir, self.keyring_path, now=self.now)
        self.assertEqual("invalid", status.state)
        self.assertEqual((), rules)


if __name__ == "__main__":
    unittest.main()
