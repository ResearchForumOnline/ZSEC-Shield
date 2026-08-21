from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from zsec_shield.cli import EXIT_INCOMPLETE, main
from zsec_shield.readiness import READINESS_SCHEMA, normalize_platform, replacement_readiness


class ReplacementReadinessTests(unittest.TestCase):
    def test_supported_platforms_fail_closed_with_unique_blockers(self) -> None:
        expected_platform_gate = {
            "windows": "windows_minifilter",
            "linux": "linux_realtime_broker",
            "macos": "macos_endpoint_security",
        }
        for platform_name, expected_gate in expected_platform_gate.items():
            with self.subTest(platform=platform_name):
                result = replacement_readiness(platform_name)
                blocker_ids = [gate["id"] for gate in result["blocking_gates"]]
                self.assertEqual(READINESS_SCHEMA, result["schema"])
                self.assertEqual(platform_name, result["platform"])
                self.assertFalse(result["eligible_for_primary_replacement"])
                self.assertTrue(result["existing_provider_must_remain_active"])
                self.assertFalse(result["automatic_uninstall_available"])
                self.assertFalse(result["manual_override_available"])
                self.assertIn(expected_gate, blocker_ids)
                self.assertEqual(len(blocker_ids), len(set(blocker_ids)))
                self.assertEqual(len(blocker_ids), result["gate_counts"]["not_met"])

    def test_platform_normalization_is_explicit(self) -> None:
        self.assertEqual("windows", normalize_platform("Windows"))
        self.assertEqual("linux", normalize_platform("Linux"))
        self.assertEqual("macos", normalize_platform("Darwin"))
        self.assertEqual("macos", normalize_platform("macOS"))
        self.assertEqual("unsupported", normalize_platform("Plan 9"))

    def test_cli_is_a_nonzero_guard_and_does_not_create_state(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "must-not-exist"
            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "--state-dir",
                        str(state),
                        "replacement-readiness",
                        "--platform",
                        "linux",
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            self.assertEqual(EXIT_INCOMPLETE, code)
            self.assertEqual(READINESS_SCHEMA, result["schema"])
            self.assertEqual("keep_existing_protection", result["decision"])
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
