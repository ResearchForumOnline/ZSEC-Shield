from __future__ import annotations

import base64
import hashlib
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.helpers import make_signing_material
from zsec_shield.automatic_updates import (
    automatic_update_due,
    install_intelligence_envelope,
    load_application_update_status,
    load_automatic_update_status,
    run_automatic_application_update_check,
    run_automatic_update,
    verify_application_update_envelope,
    verify_intelligence_envelope,
)
from zsec_shield.errors import FeedError
from zsec_shield.paths import (
    application_update_notice_path,
    intelligence_document_path,
    intelligence_last_known_good_path,
)
from zsec_shield.util import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]


def envelope(
    private_key: Ed25519PrivateKey,
    catalog: dict[str, object],
    now: datetime,
    sequence: int,
) -> bytes:
    payload = {
        "schema": "zsec.intelligence.payload.v1",
        "sequence": sequence,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "catalog_sha256": hashlib.sha256(canonical_json_bytes(catalog) + b"\n").hexdigest(),
        "catalog": catalog,
        "policy": {
            "auto_remediation_allowed": False,
            "data_only": True,
            "detection_rules_derived": False,
            "malware_samples_allowed": False,
            "remote_commands_allowed": False,
        },
    }
    signature = private_key.sign(canonical_json_bytes(payload) + b"\n")
    return json.dumps(
        {
            "schema": "zsec.signed-envelope.v1",
            "algorithm": "ed25519",
            "key_id": "test:primary",
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ).encode()


def application_envelope(
    private_key: Ed25519PrivateKey,
    release: dict[str, object],
    now: datetime,
    sequence: int = 12,
) -> bytes:
    payload = {
        "schema": "zsec.application-update.payload.v1",
        "sequence": sequence,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "channel": "stable",
        "notification_only": True,
        "auto_install_allowed": False,
        "release": release,
    }
    signature = private_key.sign(canonical_json_bytes(payload) + b"\n")
    return json.dumps(
        {
            "schema": "zsec.signed-envelope.v1",
            "algorithm": "ed25519",
            "key_id": "test:primary",
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ).encode()


class AutomaticUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key, self.keyring = make_signing_material(self.root)
        self.now = datetime(2026, 8, 22, 18, 0, tzinfo=UTC)
        self.catalog = json.loads(
            (ROOT / "intelligence" / "desktop-advisories.json").read_text(encoding="utf-8")
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signed_catalog_installs_and_retains_last_known_good(self) -> None:
        first = envelope(self.private_key, self.catalog, self.now, 10)
        outcome, payload = install_intelligence_envelope(
            first, self.root / "state", self.keyring, now=self.now
        )
        self.assertEqual("installed", outcome)
        self.assertEqual(10, payload["sequence"])
        # Source contribution validation requires deterministic ordering, so use
        # a later identical catalog to exercise replacement/LKG retention.
        second = envelope(self.private_key, self.catalog, self.now, 11)
        install_intelligence_envelope(second, self.root / "state", self.keyring, now=self.now)
        last_good = json.loads(
            intelligence_last_known_good_path(self.root / "state").read_text(encoding="utf-8")
        )
        self.assertEqual(10, last_good["payload"]["sequence"])
        installed = json.loads(
            intelligence_document_path(self.root / "state").read_text(encoding="utf-8")
        )
        self.assertEqual(self.catalog, installed)

    def test_tamper_and_rollback_fail_closed(self) -> None:
        raw = envelope(self.private_key, self.catalog, self.now, 5)
        document = json.loads(raw)
        document["payload"]["sequence"] = 6
        with self.assertRaisesRegex(FeedError, "signature"):
            verify_intelligence_envelope(json.dumps(document).encode(), self.keyring, now=self.now)
        install_intelligence_envelope(raw, self.root / "state", self.keyring, now=self.now)
        with self.assertRaisesRegex(FeedError, "rollback"):
            install_intelligence_envelope(
                envelope(self.private_key, self.catalog, self.now, 4),
                self.root / "state",
                self.keyring,
                now=self.now,
            )

    def test_failed_check_retains_success_and_catalog(self) -> None:
        state = self.root / "state"
        raw = envelope(self.private_key, self.catalog, self.now, 2)
        with patch("zsec_shield.automatic_updates.download_feed", return_value=raw):
            successful = run_automatic_update(
                state, self.keyring, force=True, now=self.now
            )
        before = intelligence_document_path(state).read_bytes()
        with patch("zsec_shield.automatic_updates.download_feed", side_effect=FeedError("offline")):
            failed = run_automatic_update(
                state, self.keyring, force=True, now=self.now + timedelta(days=1)
            )
        self.assertEqual("error", failed.state)
        self.assertEqual(successful.last_success_at, failed.last_success_at)
        self.assertEqual(before, intelligence_document_path(state).read_bytes())
        self.assertFalse(automatic_update_due(failed, self.now + timedelta(days=1)))

    def test_missing_or_corrupt_schedule_checks_immediately(self) -> None:
        state = self.root / "state"
        self.assertTrue(
            automatic_update_due(load_automatic_update_status(state, now=self.now), self.now)
        )
        status_path = state / "feed" / "automatic-update-status.json"
        status_path.parent.mkdir(parents=True)
        status_path.write_text("not-json", encoding="utf-8")
        status = load_automatic_update_status(state, now=self.now)
        self.assertEqual("error", status.state)
        self.assertTrue(automatic_update_due(status, self.now))

    def test_application_manifest_is_verified_notification_only(self) -> None:
        release = json.loads((ROOT / "updates" / "application-release.json").read_text())
        raw = application_envelope(self.private_key, release, self.now)
        notice = verify_application_update_envelope(
            raw, self.keyring, now=self.now
        )
        self.assertFalse(notice["automatic_install"])
        self.assertEqual(release["version"], notice["version"])
        signed = json.loads(raw)
        signed["payload"]["auto_install_allowed"] = True
        with self.assertRaisesRegex(FeedError, "signature"):
            verify_application_update_envelope(
                json.dumps(signed).encode(), self.keyring, now=self.now
            )

    def test_automatic_application_notice_is_scheduled_and_never_installs(self) -> None:
        state = self.root / "state"
        release = json.loads((ROOT / "updates" / "application-release.json").read_text())
        release["version"] = "0.3.31"
        raw = application_envelope(self.private_key, release, self.now, sequence=20)
        with patch("zsec_shield.automatic_updates.download_feed", return_value=raw) as fetch:
            first = run_automatic_application_update_check(
                state, self.keyring, "0.3.30", now=self.now
            )
            second = run_automatic_application_update_check(
                state, self.keyring, "0.3.30", now=self.now + timedelta(hours=1)
            )
        self.assertEqual("available", first.state)
        self.assertEqual("0.3.31", first.available_version)
        self.assertFalse(first.automatic_install)
        self.assertEqual(first, second)
        fetch.assert_called_once()
        notice = json.loads(application_update_notice_path(state).read_text(encoding="utf-8"))
        self.assertFalse(notice["automatic_install"])
        self.assertIn("no content is downloaded or executed", notice["policy"])

    def test_application_notice_rejects_rollback_and_keeps_last_verified_notice(self) -> None:
        state = self.root / "state"
        release = json.loads((ROOT / "updates" / "application-release.json").read_text())
        release["version"] = "0.3.31"
        accepted = application_envelope(self.private_key, release, self.now, sequence=20)
        with patch("zsec_shield.automatic_updates.download_feed", return_value=accepted):
            successful = run_automatic_application_update_check(
                state, self.keyring, "0.3.30", force=True, now=self.now
            )
        before = application_update_notice_path(state).read_bytes()
        rolled_back = application_envelope(
            self.private_key, release, self.now + timedelta(days=1), sequence=19
        )
        with patch("zsec_shield.automatic_updates.download_feed", return_value=rolled_back):
            failed = run_automatic_application_update_check(
                state,
                self.keyring,
                "0.3.30",
                force=True,
                now=self.now + timedelta(days=1),
            )
        self.assertEqual("error", failed.state)
        self.assertIn("rollback", failed.error or "")
        self.assertEqual(successful.last_success_at, failed.last_success_at)
        self.assertEqual(before, application_update_notice_path(state).read_bytes())

    def test_application_notice_corrupt_schedule_checks_immediately(self) -> None:
        state = self.root / "state"
        path = state / "application-update" / "status.json"
        path.parent.mkdir(parents=True)
        path.write_text("not-json", encoding="utf-8")
        status = load_application_update_status(state, "0.3.30", now=self.now)
        self.assertEqual("error", status.state)
        next_check = datetime.fromisoformat(status.next_check_at.replace("Z", "+00:00"))
        self.assertEqual(self.now, next_check)

    def test_application_manifest_rejects_expiry_truncation_and_wrong_key(self) -> None:
        release = json.loads((ROOT / "updates" / "application-release.json").read_text())
        raw = application_envelope(self.private_key, release, self.now)
        with self.assertRaisesRegex(FeedError, "validity"):
            verify_application_update_envelope(
                raw, self.keyring, now=self.now + timedelta(days=8)
            )
        with self.assertRaises((FeedError, json.JSONDecodeError)):
            verify_application_update_envelope(raw[: len(raw) // 2], self.keyring, now=self.now)

        wrong_root = self.root / "wrong"
        wrong_root.mkdir()
        wrong_private, _wrong_keyring = make_signing_material(wrong_root)
        wrong_raw = application_envelope(wrong_private, release, self.now)
        with self.assertRaisesRegex(FeedError, "signature"):
            verify_application_update_envelope(wrong_raw, self.keyring, now=self.now)

    def test_resigned_application_manifest_cannot_authorize_provider_changes(self) -> None:
        release = json.loads((ROOT / "updates" / "application-release.json").read_text())
        release["provider_action"] = "disable-existing-antivirus"
        raw = application_envelope(self.private_key, release, self.now)
        with self.assertRaisesRegex(FeedError, "release fields"):
            verify_application_update_envelope(raw, self.keyring, now=self.now)

        release.pop("provider_action")
        release["auto_install_allowed"] = True
        raw = application_envelope(self.private_key, release, self.now)
        with self.assertRaisesRegex(FeedError, "not notification-only"):
            verify_application_update_envelope(raw, self.keyring, now=self.now)


if __name__ == "__main__":
    unittest.main()
