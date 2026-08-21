from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPANION_ROOT = PROJECT_ROOT / "windows" / "companion"
INSTALLER = COMPANION_ROOT / "Install-ZsecAntivirusCompanion.ps1"
LAUNCHER = COMPANION_ROOT / "Start-ZsecAntivirusCompanion.ps1"
STATUS = COMPANION_ROOT / "Get-ZsecAntivirusCompanionStatus.ps1"
UNINSTALLER = COMPANION_ROOT / "Uninstall-ZsecAntivirusCompanion.ps1"


class WindowsCompanionStaticTests(unittest.TestCase):
    def test_all_companion_scripts_and_review_document_are_present(self) -> None:
        for path in (INSTALLER, LAUNCHER, STATUS, UNINSTALLER, COMPANION_ROOT / "README.md"):
            self.assertTrue(path.is_file(), path)

    def test_installer_is_limited_per_user_single_instance_and_bounded(self) -> None:
        content = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("ZSEC Antivirus", content)
        self.assertIn("-AtLogOn -User $ownerName", content)
        self.assertIn("-LogonType Interactive", content)
        self.assertIn("-RunLevel Limited", content)
        self.assertIn("-MultipleInstances IgnoreNew", content)
        self.assertIn("-Priority 8", content)
        self.assertIn("-RestartCount 3", content)
        self.assertIn("-RestartInterval (New-TimeSpan -Minutes 1)", content)
        self.assertIn("event_queue_size = 8192", content)
        self.assertIn("metadata_reconcile_seconds = 300", content)
        self.assertIn("cache_independent_full_rescan_seconds = 86400", content)
        self.assertIn("full_rescan_seconds = 86400.0", content)
        self.assertIn("max_file_bytes = 268435456", content)
        self.assertIn("event_log_max_bytes = 4194304", content)
        self.assertIn("event_log_backups = 3", content)
        self.assertIn("quarantine_enabled = [bool]$EnableQuarantine", content)
        self.assertIn('"runtime-identity" "--json"', content)
        self.assertIn("runtime_sha256 = $runtimeHash", content)
        self.assertIn('$RunValueName = "ZSEC Antivirus Companion"', content)
        self.assertIn("function Test-IsAccessDeniedError", content)
        self.assertIn("[int64]$exception.HResult -eq -2147024891", content)
        self.assertIn("-not (Test-IsAccessDeniedError $registrationError)", content)
        self.assertRegex(
            content,
            r"Register-ScheduledTask[\s\S]*?-InputObject \$definition\s+`\s*"
            r"-ErrorAction Stop \| Out-Null",
        )
        self.assertIn("New-ItemProperty", content)
        self.assertIn("supervisor_kind = $supervisorKind", content)
        self.assertIn("if ($PlanOnly)", content)
        self.assertNotIn("-RunLevel Highest", content)
        self.assertNotIn("-LogonType Password", content)

    def test_launcher_uses_existing_watch_engine_and_quarantine_is_explicit(self) -> None:
        content = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('"watch"', content)
        self.assertIn('"--health-file"', content)
        self.assertIn('"--event-log"', content)
        self.assertIn('"--full-rescan-seconds"', content)
        self.assertIn('"--quiet"', content)
        self.assertIn("ProcessPriorityClass]::BelowNormal", content)
        self.assertIn("if ([bool]$config.quarantine_enabled)", content)
        self.assertIn('$arguments += "--quarantine"', content)
        self.assertIn("Start-Process", content)
        self.assertIn("-WindowStyle Hidden", content)
        self.assertIn("$actualRuntimeHash = Get-Sha256 $runtimeExecutable", content)
        self.assertIn(
            "@(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual).Count",
            content,
        )

    def test_status_uses_supported_wsc_aggregate_and_never_decodes_product_state(self) -> None:
        content = STATUS.read_text(encoding="utf-8")
        self.assertIn("WscGetSecurityProviderHealth(0x4", content)
        self.assertIn("aggregate_health = $healthName", content)
        self.assertIn("product_state_raw = [int]$product.productState", content)
        self.assertIn("product_state_interpreted = $false", content)
        self.assertIn("Get-MpComputerStatus", content)
        self.assertIn("confirmed_active = $false", content)
        self.assertIn("primary_provider_uninstall_allowed = $false", content)
        self.assertIn("cutover_allowed = $false", content)
        self.assertIn("runtime_hash_verified = $runtimeHashVerified", content)
        self.assertIn("(Get-NormalizedPath ([string]$installation.runtime_executable))", content)
        self.assertIn("$installation.supervisor.registry_path -eq $RunKeyPath", content)
        self.assertIn("$runRegistration.value_data -eq $expectedRunData", content)
        self.assertIn("registration_verified = $supervisorRegistrationVerified", content)
        self.assertIn(
            "$updatedAt = ([DateTimeOffset]$health.updated_at).ToUniversalTime()",
            content,
        )
        self.assertNotIn(
            "[DateTimeOffset]::Parse([string]$health.updated_at)",
            content,
        )

    def test_rollback_is_owned_and_preserves_scanner_security_state(self) -> None:
        content = UNINSTALLER.read_text(encoding="utf-8")
        self.assertIn("Installation ownership/path verification failed", content)
        self.assertIn("Scheduled Task no longer matches the owned installation", content)
        self.assertIn("Unregister-ScheduledTask", content)
        self.assertIn("Remove-ItemProperty", content)
        self.assertIn("$runAtRemoval.value_data -ne $expectedRunData", content)
        self.assertIn("HKCU Run value data changed", content)
        self.assertIn("Remove-Item -LiteralPath $installRoot -Recurse", content)
        self.assertIn('(Join-Path $state "feed")', content)
        self.assertIn('(Join-Path $state "quarantine")', content)
        self.assertIn(
            "$updatedAt = ([DateTimeOffset]$health.updated_at).ToUniversalTime()",
            content,
        )
        self.assertNotIn(
            "[DateTimeOffset]::Parse([string]$health.updated_at)",
            content,
        )
        self.assertNotIn("Win32_Product", content)
        self.assertNotIn("msiexec", content.casefold())
        self.assertNotIn("Remove-Item -LiteralPath $RunKeyPath", content)

    def test_scripts_have_no_provider_disable_or_exclusion_commands(self) -> None:
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in (INSTALLER, LAUNCHER, STATUS, UNINSTALLER)
        ).casefold()
        forbidden = (
            "set-mppreference",
            "add-mppreference",
            "remove-mppreference",
            "disablewindowsoptionalfeature",
            "uninstall-package",
            "uninstall-windowsfeature",
            "net stop",
            "stop-service -name windefend",
            "securitycenter2).delete",
        )
        for value in forbidden:
            self.assertNotIn(value.casefold(), combined)

    def test_source_distribution_includes_companion_scripts(self) -> None:
        manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include windows *.md *.ps1", manifest)


@unittest.skipUnless(os.name == "nt", "Scheduled Task plan/status tests require Windows")
class WindowsCompanionReadOnlyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.powershell = shutil.which("powershell.exe")
        cls.cli = shutil.which("zero-security.exe") or shutil.which("zsec-shield.exe")
        if cls.powershell is None or cls.cli is None:
            raise unittest.SkipTest("PowerShell or installed ZSEC CLI is unavailable")

    def test_plan_only_returns_exact_safe_plan_without_creating_state(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            result = subprocess.run(
                [
                    self.powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(INSTALLER),
                    "-CliPath",
                    self.cli,
                    "-ProtectedRoot",
                    str(root),
                    "-StateDirectory",
                    str(state),
                    "-PlanOnly",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                if (
                    "current-user Run value 'ZSEC Antivirus Companion' already exists"
                    in result.stderr
                ):
                    self.skipTest("an installed ZSEC companion owns the per-user Run registration")
                self.fail(f"PlanOnly failed: {result.stderr}")
            plan = json.loads(result.stdout)
            self.assertFalse(state.exists())
        self.assertEqual("zsec.antivirus.windows-companion-plan.v1", plan["schema"])
        self.assertEqual("ZSEC Antivirus", plan["product"])
        self.assertEqual("InteractiveToken / LeastPrivilege", plan["principal"])
        self.assertEqual("scheduled_task", plan["supervisor"]["preferred"]["kind"])
        fallback = plan["supervisor"]["access_denied_fallback"]
        self.assertEqual("hkcu_run", fallback["kind"])
        self.assertTrue(fallback["eligible_only_after_scheduled_task_access_denied"])
        self.assertEqual(
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            fallback["registry_path"],
        )
        self.assertEqual("ZSEC Antivirus Companion", fallback["value_name"])
        self.assertIn("Start-ZsecAntivirusCompanion.ps1", fallback["value_data"])
        self.assertIn("config.json", fallback["value_data"])
        self.assertTrue(plan["plan_only"])
        self.assertFalse(plan["quarantine_enabled"])
        runtime_path = Path(plan["runtime_executable"])
        self.assertTrue(runtime_path.is_file())
        self.assertEqual(
            hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
            plan["runtime_sha256"],
        )
        self.assertEqual("IgnoreNew", plan["settings"]["multiple_instances"])
        self.assertFalse(plan["policy"]["primary_antivirus"])
        self.assertFalse(plan["policy"]["cutover_allowed"])

    def test_status_is_read_only_and_reports_existing_protection_without_inference(self) -> None:
        with TemporaryDirectory() as temporary:
            state = Path(temporary) / "absent-state"
            result = subprocess.run(
                [
                    self.powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(STATUS),
                    "-StateDirectory",
                    str(state),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            status = json.loads(result.stdout)
            self.assertFalse(state.exists())
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("not_installed", status["decision"])
        self.assertFalse(status["primary_provider_uninstall_allowed"])
        self.assertFalse(status["cutover_allowed"])
        evidence = status["existing_primary_protection"]
        self.assertEqual(
            "WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)",
            evidence["method"],
        )
        for registration in evidence.get("registered_products", []):
            self.assertFalse(registration["product_state_interpreted"])


if __name__ == "__main__":
    unittest.main()
