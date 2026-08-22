"""Non-mutating contract tests for macOS and Linux per-user companions."""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MACOS = ROOT / "macos"
LINUX = ROOT / "linux"
SHELL_SCRIPTS = tuple(
    platform / name
    for platform in (MACOS, LINUX)
    for name in ("install.sh", "run.sh", "status.sh", "uninstall.sh")
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class CompanionPackageTests(unittest.TestCase):
    def test_expected_package_is_self_contained(self) -> None:
        expected = {
            ROOT / "README.md",
            ROOT / "test_companion_packages.py",
            MACOS / "com.talktoai.zsec-antivirus-companion.plist.template",
            LINUX / "zsec-antivirus-companion.service.template",
            *SHELL_SCRIPTS,
        }
        self.assertEqual(expected, {path for path in ROOT.rglob("*") if path.is_file()})

    def test_launchers_use_native_bounded_non_quarantine_mode(self) -> None:
        for launcher in (MACOS / "run.sh", LINUX / "run.sh"):
            text = read(launcher)
            with self.subTest(launcher=launcher):
                self.assertIn('protect "$protected_root"', text)
                self.assertIn("--backend native", text)
                self.assertIn("--event-queue-size 2048", text)
                self.assertIn("--max-file-bytes 67108864", text)
                self.assertIn("--event-log-max-bytes 4194304", text)
                self.assertIn("--event-log-backups 3", text)
                self.assertIn("--quiet", text)
                self.assertNotIn("--quarantine", text)
                self.assertIn("pinned CLI changed", text)
                self.assertNotIn("eval ", text)
                self.assertNotIn("source ", text)

    def test_macos_launchagent_restart_and_single_job_contract(self) -> None:
        template = MACOS / "com.talktoai.zsec-antivirus-companion.plist.template"
        root = ET.parse(template).getroot()
        text = read(template)
        self.assertEqual(root.tag, "plist")
        self.assertEqual(text.count("<key>Label</key>"), 1)
        self.assertIn("com.talktoai.zsec-antivirus-companion", text)
        self.assertIn("<key>RunAtLoad</key>", text)
        self.assertIn("<key>KeepAlive</key>", text)
        self.assertIn("<key>SuccessfulExit</key>", text)
        self.assertIn("<key>ThrottleInterval</key>", text)
        self.assertIn("<integer>30</integer>", text)
        self.assertEqual(text.count("@@LAUNCHER@@"), 1)
        self.assertEqual(text.count("@@CONFIG_DIR@@"), 1)
        self.assertEqual(text.count("/dev/null"), 2)

    def test_linux_user_unit_has_restart_backoff_and_hardening(self) -> None:
        text = read(LINUX / "zsec-antivirus-companion.service.template")
        required = (
            "Restart=on-failure",
            "RestartSec=30s",
            "StartLimitIntervalSec=300",
            "StartLimitBurst=5",
            "KillMode=control-group",
            "UMask=0077",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            'ReadWritePaths="@@STATE_DIR@@"',
            "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any",
            "MemoryMax=512M",
            "TasksMax=64",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "StandardOutput=null",
            "StandardError=null",
            "WantedBy=default.target",
        )
        for value in required:
            self.assertIn(value, text)
        self.assertEqual(text.count("ExecStart="), 1)
        self.assertIn('ExecStart="@@LAUNCHER@@" "@@CONFIG_DIR@@"', text)

    def test_installers_are_per_user_fail_closed_and_rollback_owned_files(self) -> None:
        mac = read(MACOS / "install.sh")
        linux = read(LINUX / "install.sh")
        for text in (mac, linux):
            self.assertIn('"$(id -u)" -ne 0', text)
            self.assertIn("refusing to overwrite", text)
            self.assertIn("completed=false", text)
            self.assertIn("rollback()", text)
            self.assertIn("existing_protection_unchanged=true", text)
            self.assertIn("primary_antivirus=false", text)
            self.assertIn("pre_access_enforcement=false", text)
        self.assertIn('launchctl bootstrap "$domain" "$plist_path"', mac)
        self.assertIn('launchctl bootout "$domain" "$plist_path"', mac)
        self.assertIn("required macOS SHA-256 utility is unavailable", mac)
        self.assertIn('systemctl --user enable --now "$unit_name"', linux)
        self.assertIn('systemctl --user disable --now "$unit_name"', linux)
        self.assertIn("sha256sum is unavailable", linux)
        self.assertNotIn("enable-linger", linux)

    def test_uninstallers_preserve_state_and_refuse_modified_owned_definitions(self) -> None:
        for uninstaller in (MACOS / "uninstall.sh", LINUX / "uninstall.sh"):
            text = read(uninstaller)
            with self.subTest(uninstaller=uninstaller):
                self.assertIn("preserved_state_directory=$state_dir", text)
                self.assertIn("changed; refusing removal", text)
                self.assertNotIn("rm -rf", text)
                self.assertNotIn('rm -f "$state_dir"', text)
                self.assertIn("existing_protection_unchanged=true", text)

    def test_scripts_do_not_mutate_platform_security_controls(self) -> None:
        combined = "\n".join(read(path).lower() for path in SHELL_SCRIPTS)
        forbidden = (
            "sudo ",
            "spctl ",
            "csrutil ",
            "defaults write",
            "set-mppreference",
            "add-mppreference",
            "ufw ",
            "firewall-cmd",
            "iptables ",
            "nft ",
            "loginctl enable-linger",
            "systemctl --system",
        )
        for command in forbidden:
            self.assertNotIn(command, combined)

    def test_docs_state_the_non_primary_boundary(self) -> None:
        text = read(ROOT / "README.md")
        for statement in (
            "not kernel pre-access",
            "stay active and unchanged",
            "Quarantine is deliberately not enabled",
            "enable systemd lingering",
            "state is preserved",
            "not a clean-system verdict",
        ):
            self.assertIn(statement, text)

    @unittest.skipUnless(shutil.which("sh"), "no compatible sh found for syntax-only checks")
    def test_shell_syntax_when_available(self) -> None:
        shell = shutil.which("sh")
        assert shell is not None
        for script in SHELL_SCRIPTS:
            relative = script.relative_to(ROOT).as_posix()
            with self.subTest(script=relative):
                subprocess.run(
                    [shell, "-n", relative],
                    cwd=ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "LC_ALL": "C"},
                )


if __name__ == "__main__":
    unittest.main()
