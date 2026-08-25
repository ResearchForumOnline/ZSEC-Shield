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
ACTION = COMPANION_ROOT / "Invoke-ZsecWindowsProtectionAction.ps1"
UNINSTALLER = COMPANION_ROOT / "Uninstall-ZsecAntivirusCompanion.ps1"
SYNC = COMPANION_ROOT / "Sync-ZsecAntivirusCompanion.ps1"
DEFENDER_AGE_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "defender_scan_age_evidence.ps1"
DEFENDER_HISTORY_FIXTURE = (
    PROJECT_ROOT / "tests" / "fixtures" / "defender_protection_history_evidence.ps1"
)
SUPERVISOR_LIFECYCLE_FIXTURE = (
    PROJECT_ROOT / "tests" / "fixtures" / "supervisor_lifecycle_evidence.ps1"
)
HKCU_SUPERVISOR_STOP_FIXTURE = (
    PROJECT_ROOT / "tests" / "fixtures" / "hkcu_supervisor_stop.ps1"
)


class WindowsCompanionStaticTests(unittest.TestCase):
    def test_all_companion_scripts_and_review_document_are_present(self) -> None:
        for path in (
            INSTALLER,
            LAUNCHER,
            STATUS,
            ACTION,
            UNINSTALLER,
            SYNC,
            COMPANION_ROOT / "README.md",
        ):
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
        self.assertIn("supervisor_event_log_max_bytes = 262144", content)
        self.assertIn("supervisor_event_log_backups = 2", content)
        self.assertIn('supervisor_event_log = $supervisorEventLogPath', content)
        self.assertIn('"$supervisorEventLogPath.1"', content)
        self.assertIn('"$supervisorEventLogPath.2"', content)
        self.assertIn("[string[]]$ProtectedRoot", content)
        self.assertIn('(Join-Path $env:USERPROFILE "Downloads")', content)
        self.assertIn('[Environment]::GetFolderPath("Desktop")', content)
        self.assertIn('[Environment]::GetFolderPath("MyDocuments")', content)
        self.assertIn('(Join-Path $env:USERPROFILE "Documents")', content)
        self.assertNotIn('[IO.Path]::GetTempPath()', content)
        self.assertIn("Test-Path -LiteralPath $_ -PathType Container", content)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", content)
        self.assertIn("between one and eight distinct protected roots", content)
        self.assertIn("A protected root cannot contain the excluded ZSEC state directory", content)
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
        self.assertIn("$maximumRapidFailures = 5", content)
        self.assertIn("$lifetimeSeconds -ge 300.0", content)
        self.assertIn("[Math]::Pow(2, $rapidFailures)", content)
        self.assertIn("Start-Sleep -Seconds", content)
        self.assertIn("exit $process.ExitCode", content)
        self.assertIn('schema = "zsec.antivirus.supervisor-event.v1"', content)
        self.assertIn('reason = $Reason', content)
        self.assertIn('"watcher_exit_restart_scheduled"', content)
        self.assertIn('"watcher_exit_rapid_failure_limit"', content)
        self.assertIn("supervisor_event_log_max_bytes", content)
        self.assertIn("supervisor_event_log_backups", content)
        self.assertIn("[System.IO.File]::AppendAllText", content)
        self.assertIn("Move-Item -LiteralPath $source -Destination $destination", content)
        exit_event = content.index('-Event "watcher_exited"')
        restart = content.index("Start-Sleep -Seconds ([int]$restartDelaySeconds)")
        self.assertLess(exit_event, restart)
        lifecycle_writer = content[
            content.index("function Write-SupervisorLifecycleEvent") :
            content.index("function Invoke-IntelligenceCheck")
        ]
        for sensitive_value in (
            "$argumentLine",
            "$normalizedRoots",
            "$stdout",
            "$stderr",
            "protected_roots",
            "command_line",
            "environment",
        ):
            self.assertNotIn(sensitive_value, lifecycle_writer)
        self.assertIn('"Local\\ZSEC-Antivirus-Companion-"', content)
        self.assertIn("System.Threading.Mutex", content)
        self.assertIn("if (-not $createdNew)", content)
        self.assertIn("$supervisorMutex.ReleaseMutex()", content)
        self.assertIn("$supervisorMutex.Dispose()", content)
        self.assertIn("function Invoke-DefenderSecurityIntelligenceMaintenance", content)
        self.assertIn("Get-MpComputerStatus -ErrorAction Stop", content)
        self.assertIn("Update-MpSignature -ErrorAction Stop", content)
        self.assertIn('return "provider_not_active"', content)
        self.assertIn(
            "Bring local monitoring online before any network-backed maintenance", content
        )
        for forbidden in (
            "Set-MpPreference",
            "Add-MpPreference",
            "Remove-MpPreference",
            "DisableRealtimeMonitoring",
        ):
            self.assertNotIn(forbidden, content)
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
        self.assertIn("function ConvertTo-DefenderAgeEvidence", content)
        self.assertIn(
            "$Defender.signatures.antivirus_age_days = ConvertTo-DefenderAgeEvidence",
            content,
        )
        self.assertIn(
            "$Defender.scans.quick_scan_age_days = ConvertTo-DefenderAgeEvidence",
            content,
        )
        self.assertIn(
            "$Defender.scans.full_scan_age_days = ConvertTo-DefenderAgeEvidence",
            content,
        )
        self.assertIn("Set-DefenderAgeAndFeatureEvidence", content)
        self.assertIn("-Defender $defender", content)
        self.assertNotIn("[int]$signatureAge", content)
        self.assertNotIn("[int]$quickAge", content)
        self.assertNotIn("[int]$fullAge", content)
        self.assertIn('source = "Get-MpPreference.EnableNetworkProtection"', content)
        self.assertIn("Get-MpPreference -ErrorAction Stop", content)
        self.assertIn('$defender.network_protection.state = "active"', content)
        self.assertIn('$defender.network_protection.state = "audit"', content)
        self.assertIn('$defender.network_protection.state = "disabled"', content)
        self.assertIn("companion health decision", content)
        self.assertIn("function Get-DefenderProtectionHistoryEvidence", content)
        self.assertIn("Get-MpThreatDetection -ErrorAction Stop", content)
        self.assertIn("Get-MpThreat -ErrorAction Stop", content)
        self.assertIn("protection_history = $null", content)
        self.assertIn(
            "$defender.protection_history = Get-DefenderProtectionHistoryEvidence",
            content,
        )
        self.assertIn("resource_paths_included = $false", content)
        self.assertIn("process_names_included = $false", content)
        self.assertIn("user_names_included = $false", content)
        self.assertIn("cloud_upload_performed = $false", content)
        self.assertNotIn('Get-OptionalProperty -InputObject $detection -Name "Resources"', content)
        self.assertNotIn(
            'Get-OptionalProperty -InputObject $detection -Name "ProcessName"', content
        )
        self.assertNotIn('Get-OptionalProperty -InputObject $detection -Name "DomainUser"', content)
        self.assertIn("function Get-SupervisorLifecycleEvidence", content)
        self.assertIn("function ConvertTo-SupervisorLifecycleRecord", content)
        self.assertIn('schema -ne "zsec.antivirus.supervisor-event.v1"', content)
        self.assertIn("latest_exit = $latestExit", content)
        self.assertIn("lifecycle = $supervisorLifecycleEvidence", content)
        self.assertIn("A previous signed companion can be inspected and restored", content)
        self.assertIn("$lifecycleConfigPresent.Count -eq 0", content)
        self.assertIn("$lifecycleConfigPresent.Count -ne $lifecycleConfigNames.Count", content)
        self.assertNotIn("stdout_file =", content)
        self.assertNotIn("stderr_file =", content)

    def test_defender_scan_age_fixture_preserves_active_evidence(self) -> None:
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-File",
                str(DEFENDER_AGE_FIXTURE),
                "-StatusScript",
                str(STATUS),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            self.fail(
                "Defender scan-age fixture failed: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        evidence = json.loads(result.stdout)
        self.assertEqual("zsec.tests.defender-scan-age-evidence.v1", evidence["schema"])
        self.assertTrue(evidence["sentinel_maps_to_null"])
        self.assertTrue(evidence["signature_sentinel_maps_to_null"])
        self.assertEqual(3, evidence["normal_age_days"])
        self.assertTrue(evidence["confirmed_active"])
        self.assertTrue(evidence["baseline_features_confirmed"])

    def test_defender_protection_history_is_bounded_and_excludes_private_fields(
        self,
    ) -> None:
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-File",
                str(DEFENDER_HISTORY_FIXTURE),
                "-StatusScript",
                str(STATUS),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            self.fail(
                "Defender protection-history fixture failed: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        evidence = json.loads(result.stdout)
        self.assertEqual(
            "zsec.tests.defender-protection-history-evidence.v1",
            evidence["schema"],
        )
        self.assertEqual(24, evidence["total_detection_records"])
        self.assertEqual(20, evidence["returned_records"])
        self.assertEqual(2, evidence["recent_30_days_count"])
        self.assertEqual(2, evidence["attention_required_count"])
        self.assertEqual(1, evidence["remediation_failed_count"])
        self.assertEqual("detected", evidence["first_status"])
        self.assertEqual("real_time", evidence["first_source"])
        self.assertEqual("severe", evidence["first_severity"])
        self.assertEqual(200, evidence["first_name_length"])
        self.assertTrue(evidence["local_only"])
        self.assertFalse(evidence["resource_paths_included"])
        self.assertFalse(evidence["cloud_upload_performed"])

    def test_supervisor_lifecycle_fixture_rotates_and_retains_secret_free_exit_evidence(
        self,
    ) -> None:
        powershells = list(
            dict.fromkeys(
                path
                for path in (shutil.which("powershell.exe"), shutil.which("pwsh"))
                if path is not None
            )
        )
        if not powershells:
            self.skipTest("PowerShell is unavailable")
        for powershell in powershells:
            with self.subTest(powershell=powershell), TemporaryDirectory() as temporary:
                result = subprocess.run(
                    [
                        powershell,
                        "-NoLogo",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "RemoteSigned",
                        "-File",
                        str(SUPERVISOR_LIFECYCLE_FIXTURE),
                        "-LauncherScript",
                        str(LAUNCHER),
                        "-StatusScript",
                        str(STATUS),
                        "-TemporaryDirectory",
                        temporary,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    self.fail(
                        "Supervisor lifecycle fixture failed: "
                        f"stdout={result.stdout!r} stderr={result.stderr!r}"
                    )
                evidence = json.loads(result.stdout)
                self.assertEqual(
                    "zsec.tests.supervisor-lifecycle-evidence.v1", evidence["schema"]
                )
                self.assertEqual(3, evidence["rotated_files"])
                self.assertTrue(evidence["bounded_files"])
                self.assertTrue(evidence["records_present"])
                self.assertTrue(evidence["fields_exact"])
                self.assertTrue(evidence["evidence_valid"])
                self.assertEqual("watcher_started", evidence["latest_event"])
                self.assertEqual(
                    "watcher_exit_restart_scheduled",
                    evidence["latest_exit_reason"],
                )

    def test_rollback_is_owned_and_preserves_scanner_security_state(self) -> None:
        content = UNINSTALLER.read_text(encoding="utf-8")
        self.assertIn("Installation ownership/path verification failed", content)
        self.assertIn("Scheduled Task no longer matches the owned installation", content)
        self.assertIn("Unregister-ScheduledTask", content)
        self.assertIn("Remove-ItemProperty", content)
        self.assertIn("$runAtRemoval.value_data -ne $expectedRunData", content)
        self.assertIn("HKCU Run value data changed", content)
        self.assertIn("function Get-OwnedHkcuSupervisorProcess", content)
        self.assertIn("function Stop-OwnedHkcuSupervisorProcess", content)
        self.assertIn("Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid", content)
        self.assertIn('Get-CimInstance `\n        -ClassName Win32_Process', content)
        self.assertIn('[string]$owner.Sid -ne $ownerSid', content)
        self.assertIn('$observedCommandLine -notin', content)
        self.assertIn('$createdAt -gt $lifecycle.generated_at.AddSeconds(5)', content)
        self.assertIn('"Local\\ZSEC-Antivirus-Companion-$OwnerSid"', content)
        self.assertIn("Installed companion launcher hash verification failed", content)
        scheduled_branch = content.index('if ($supervisorKind -eq "scheduled_task") {')
        scheduled_import = content.index("Import-Module ScheduledTasks", scheduled_branch)
        self.assertGreater(scheduled_import, scheduled_branch)
        self.assertIn("Remove-OwnedCompanionDirectory -Path $installRoot", content)
        self.assertIn("Remove-Item -LiteralPath $Path -Recurse", content)
        self.assertIn("function Remove-OwnedCompanionDirectory", content)
        self.assertIn("AddSeconds(10)", content)
        self.assertIn("catch [IO.IOException]", content)
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
        self.assertNotIn("Get-CimInstance -ClassName Win32_Process -ErrorAction", content)
        self.assertNotIn("taskkill", content.casefold())
        action = content[content.index("if ($null -ne $task) {") :]
        remove_run = action.index("Remove-ItemProperty")
        stop_supervisor = action.index("$ownedSupervisorStopped = Stop-OwnedHkcuSupervisorProcess")
        stop_heartbeat = action.index("$ownedProcessStopped = Stop-OwnedHeartbeatProcess")
        delete_files = action.index("Remove-OwnedCompanionDirectory -Path $installRoot")
        self.assertLess(remove_run, stop_supervisor)
        self.assertLess(stop_supervisor, stop_heartbeat)
        self.assertLess(stop_heartbeat, delete_files)

    @unittest.skipUnless(os.name == "nt", "Live process identity fixture requires Windows")
    def test_hkcu_supervisor_stop_requires_exact_live_process_identity(self) -> None:
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("Windows PowerShell is unavailable")
        with TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(HKCU_SUPERVISOR_STOP_FIXTURE),
                    "-UninstallerScript",
                    str(UNINSTALLER),
                    "-TemporaryDirectory",
                    temporary,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        if result.returncode != 0:
            self.fail(
                "HKCU supervisor-stop fixture failed: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        evidence = json.loads(result.stdout)
        self.assertEqual("zsec.tests.hkcu-supervisor-stop.v1", evidence["schema"])
        self.assertTrue(evidence["exact_identity_resolved"])
        self.assertTrue(evidence["command_line_mismatch_rejected"])
        self.assertTrue(evidence["pid_reuse_rejected"])
        self.assertTrue(evidence["exact_process_stopped"])

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

    def test_sync_migrates_legacy_config_instead_of_verifying_an_incompatible_pair(
        self,
    ) -> None:
        content = SYNC.read_text(encoding="utf-8")
        self.assertIn("function Test-CurrentSupervisorEvidenceConfig", content)
        self.assertIn('"supervisor_event_log"', content)
        self.assertIn("$configMigrationRequired = -not", content)
        self.assertIn("-not $configMigrationRequired", content)
        self.assertIn("config_migration_required = $configMigrationRequired", content)
        self.assertIn('"supervisor-events.ndjson.2"', content)
        self.assertRegex(
            content,
            r"elseif \(\s*"
            r"\(Get-NormalizedPath \(\[string\]\$previousInstallation\.cli_path\)\) "
            r"-eq \$cli -and\s*-not \$configMigrationRequired\s*\)",
        )

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
            protected = root / "protected"
            protected.mkdir()
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
                    str(protected),
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
        self.assertEqual(
            262144,
            plan["resource_bounds"]["supervisor_event_log_max_bytes"],
        )
        self.assertEqual(2, plan["resource_bounds"]["supervisor_event_log_backups"])
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
