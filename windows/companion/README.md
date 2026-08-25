# ZSEC Antivirus Windows companion

The Windows desktop package runs `Sync-ZsecAntivirusCompanion.ps1` as part of
its activation transaction. A fresh install provisions and starts the owned
per-user supervisor automatically. An upgrade preserves reviewed nonvolatile roots and
quarantine preference, migrates the companion to the new immutable engine,
waits for verified registration, integrity, process identity and a fresh heartbeat,
then reports either baseline-in-progress or healthy. It restores the prior companion if verification
fails. This lifecycle does not modify or remove an existing antivirus provider.

Status: reversible per-user automation for the existing foreground post-change
engine. It is not a Windows service, kernel minifilter, AMSI/ELAM provider,
Windows Security provider, or primary antivirus. Keep Malwarebytes, Microsoft
Defender when it is the selected provider, and all native Windows protections
enabled.

The scripts are intentionally review-first. No repository build or test invokes
the mutation path. `-PlanOnly` resolves the preferred current-user Scheduled
Task, the access-denied-only `HKCU` Run fallback, executable hashes, protected
roots, state paths, settings, and rollback boundary without creating a directory,
registering a task, or writing the registry.

## Review the exact plan

Run from an ordinary, non-elevated PowerShell session:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Install-ZsecAntivirusCompanion.ps1 `
  -PlanOnly
```

The secure Windows default monitors each existing current-user Desktop,
Downloads and Documents folder. The volatile Windows Temp directory is not a
default root because applications routinely hold transient files with exclusive
locks; those incomplete reads would correctly degrade the session. A standard folder that Windows
resolves to an absent or reparse-point location is skipped instead of making an
automatic install fail. Pass one to eight `-ProtectedRoot` values to use a
different bounded set of existing, regular, non-reparse directories. The installer deduplicates exact
roots and refuses any root inside, equal to, or containing its mutable state
directory. It finds `zero-security.exe`, retaining `zsec-shield.exe` as a
compatibility fallback, or accepts an explicit reviewed `-CliPath`.

Plan output fixes the safety policy to:

```json
{
  "primary_antivirus": false,
  "real_time_protection": false,
  "pre_access_enforcement": false,
  "windows_security_registration": false,
  "existing_protection_must_remain_active": true,
  "automatic_provider_changes": false,
  "primary_provider_uninstall_allowed": false,
  "cutover_allowed": false
}
```

## Install after review

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Install-ZsecAntivirusCompanion.ps1
```

The installer first attempts one current-user logon Scheduled Task. It does not
request elevation. If, and only if, `Register-ScheduledTask` returns Windows
access denied (`0x80070005` or native error 5), it falls back to the exact
current-user value below:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value name: ZSEC Antivirus Companion
Value data: "<system powershell.exe>" <exact launcher and config arguments>
```

Any other task-registration failure aborts and rolls back. An existing value is
never overwritten. The value is `REG_SZ`, contains absolute paths to the copied
launcher and generated config, and is read back byte-for-byte before installation
succeeds. No machine-wide registry key is used.

The installer copies the small launcher and generated configuration to
`%LOCALAPPDATA%\ZSEC\Shield\companion`, which is already excluded from scanning.
The task uses the current user's interactive token at limited privilege. It is
transparent in Task Scheduler and is named with the current user SID to prevent
cross-user collision.

Installation refuses to overwrite any existing task or non-empty companion
directory. It verifies the chosen supervisor and records `supervisor_kind` plus
its exact task or registry data in `installation.json`. A failed read-back removes
only the exact task or Run value created by that attempt and its generated files.
Use `-StartNow` to make starting immediately explicit for either supervisor;
otherwise the first start is at the next logon.

Quarantine is off. `-EnableQuarantine` is a separate explicit install-time choice
and calls the existing encrypted, recoverable quarantine path. It should be used
only after restore has been tested on disposable files.

## Resource and restart bounds

The generated configuration is deliberately conservative:

| Control | Bound |
| --- | --- |
| Scanner concurrency | One serial watcher/scanner process |
| Event work | 8,192 total raw/coalesced paths; either overflow ends incomplete |
| Duplicate events | 0.75-second quiet-period debounce plus a hard anti-starvation age |
| File input | 256 MiB maximum per file, streamed in 1 MiB chunks |
| Reconciliation | Five-minute metadata inventory; only new, changed or unresolved files are hashed |
| Cache-independent sweep | Full content rescan every 24 hours and on every start |
| Process scheduling | Task priority `8` plus child `BelowNormal` priority |
| Event evidence | 4 MiB current NDJSON plus three rotated backups |
| Supervisor lifecycle evidence | 256 KiB metadata-only NDJSON plus two rotated backups |
| Health | Atomic heartbeat every 30 seconds; stale after 105 seconds |
| Restart | Scheduled Task: at most three retries, one minute apart; HKCU Run: no automatic retry |
| Multiple instances | Scheduled Task `IgnoreNew`; both supervisors use the engine's state-directory lock |

Only a completed stable hash enters the session-local reconciliation snapshot.
Oversized, unreadable and unstable files remain unresolved and health stays
incomplete. Metadata-only passes have their own evidence and never claim a clean
or no-match content scan. These bounds limit queue memory, file-buffer memory,
concurrency, scheduling priority, log storage, restart churn and unchanged-tree
disk reads. They are not a Windows Job Object or a hard CPU/RSS quota; sustained
file churn and the daily full sweep can still use CPU and disk I/O. A future hard
resource sandbox requires its own measured design and compatibility gates.

Watcher stdout and stderr remain current-run diagnostics and may be truncated by
the next child launch. Crash/restart provenance is retained independently in
`supervisor-events.ndjson` before a restart or crash-loop exit. Its fixed schema
contains only timestamps, supervisor/watcher process IDs, exit code, bounded
lifetime and retry counters, restart scheduling and an enumerated reason. It does
not copy command lines, environment data, protected paths, stdout or stderr.
Status reports only validated lifecycle records, and lifecycle history does not
turn a fresh, process-verified initial metadata inventory into a warning.

The task settings follow Microsoft's documented `New-ScheduledTaskSettingsSet`
controls for `IgnoreNew`, background priority, restart count, and restart
interval. The principal uses the documented `Interactive` logon type and
`Limited` run level:

- <https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtasksettingsset>
- <https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskprincipal>

## Health proof

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Get-ZsecAntivirusCompanionStatus.ps1
```

A healthy result requires all of the following:

1. owned installation/config schemas and current-user SID;
2. exact chosen supervisor registration: Scheduled Task description/action/
   `IgnoreNew`, or the owned HKCU Run path/name/value data;
3. SHA-256 match for the installed launcher and selected CLI executable;
4. Scheduled Task state `Running`, when that supervisor is installed;
5. a fresh heartbeat from a live process whose executable path matches the
   configured CLI;
6. watcher operational state `healthy` only after the initial baseline completed
   (startup remains `baselining`); and
7. Windows Security Center aggregate antivirus health `GOOD` from the supported
   `WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)` API.

The status output also lists `root\SecurityCenter2` antivirus registrations and
their raw `productState` only as presence evidence. Those undocumented integers
are not decoded. Microsoft Defender is reported separately from
`Get-MpComputerStatus`; a mere Defender registration never becomes a claim that
Defender is active. On a machine where Malwarebytes is primary, Defender's own
antivirus/real-time fields can correctly be false while the supported WSC
aggregate remains `GOOD`.

The same evidence object reports Defender behavior monitoring, downloaded-file
inspection, on-access protection, network inspection, tamper state, security
intelligence version/timestamp, last supported scan timestamps, and the observed
states of `WinDefend`, `WdNisSvc`, `MDCoreSvc`, `wscsvc`, and
`SecurityHealthService`. Missing version/timestamp evidence can never become a
"current intelligence" result.

When Windows permits the current account to read it, the Defender evidence also
includes a bounded summary of active and past detections from the supported
`Get-MpThreatDetection` cmdlet, with optional threat names/severity from
`Get-MpThreat`. The summary returns at most 20 newest records plus 30-day,
attention, and remediation-failure counts. It is local-only and deliberately
omits affected resource paths, process names, and user names. Permission denial
or unavailable Defender history remains explicit absent evidence; it does not
become a clean-history claim.

- <https://learn.microsoft.com/powershell/module/defender/get-mpthreatdetection>
- <https://learn.microsoft.com/powershell/module/defender/get-mpthreat>

The desktop packages a separate fixed-action helper for three user-requested
Defender operations:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Invoke-ZsecWindowsProtectionAction.ps1 `
  -Action UpdateSignatures
```

The other accepted values are `QuickScan` and `FullScan`. The helper cannot run
an arbitrary command, select or disable a provider, change Defender preferences,
add an exclusion, alter Security Center registration, or remove software. Its
versioned result explicitly records all those configuration/removal booleans as
false, and the desktop rejects a contradictory result.

The UI derives a separate provider-handoff interlock from complete registration
inventory, WSC `GOOD`, Defender active/baseline controls, current Defender
intelligence, tamper protection, and no pending/unknown Defender reboot. With
Malwarebytes still registered it can at most report
"eligible for operator cutover; Defender remains enforcement." It provides no
automated uninstall. After Malwarebytes is absent, the UI reports a verified
Defender-backed handoff only while the same evidence remains true. This is not a
claim that ZSEC supplies pre-access enforcement.

Microsoft documents the WSC API as returning aggregate category health, with
`GOOD` meaning the category needs no attention. It does not identify which
registered product supplies that health:

- <https://learn.microsoft.com/windows/win32/api/wscapi/nf-wscapi-wscgetsecurityproviderhealth>
- <https://learn.microsoft.com/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider_health>

Status never authorizes provider removal. `primary_provider_uninstall_allowed`
and `cutover_allowed` are always `false` in this companion programme.

## Exact rollback

Review rollback first:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Uninstall-ZsecAntivirusCompanion.ps1 `
  -PlanOnly
```

Then uninstall:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Uninstall-ZsecAntivirusCompanion.ps1
```

Uninstall validates the current-user ownership marker, supervisor kind, state
path, and install path before changing anything. For a Scheduled Task it verifies
and removes only the exact owned task. For HKCU Run it removes only the value
named `ZSEC Antivirus Companion`, only when the current value data still exactly
matches the recorded launcher/config command. A missing value is left missing;
a changed value makes uninstall fail closed without deleting state. A fresh,
path-bound heartbeat may be used to stop only the verified companion process.
The generated `companion` subtree is then removed. If that directory was an
empty pre-existing directory, the empty directory is restored.

Feed state, rollback state, encrypted quarantine, device keys, reports outside
the companion subtree, Malwarebytes, Defender, Windows Security registration,
firewall settings, exclusions, services, drivers, and software packages are
preserved. The scripts contain no cutover or primary-provider uninstall path.

## Honest boundary

The companion automatically scans post-change file events while the user is
logged on. It cannot hold a file open/execute decision, inspect process memory,
replace an approved provider, or prove that no transient file executed before a
scan. Queue/backend/root/feed failures are visible and non-successful. The
proper replacement-antivirus programme and its separate FltMgr, AMSI, ELAM,
protected-service, MVI/WSC, signing, efficacy, and rollback gates remain in
[`FULL_ANTIVIRUS_PROGRAM.md`](../../docs/FULL_ANTIVIRUS_PROGRAM.md).
