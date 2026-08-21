# ZSEC Antivirus Windows companion

Status: reversible per-user automation for the existing foreground post-change
engine. It is not a Windows service, kernel minifilter, AMSI/ELAM provider,
Windows Security provider, or primary antivirus. Keep Malwarebytes, Microsoft
Defender when it is the selected provider, and all native Windows protections
enabled.

The scripts are intentionally review-first. No repository build or test invokes
the mutation path. `-PlanOnly` resolves the exact current-user task, executable,
hashes, Downloads root, state paths, settings, and rollback boundary without
creating a directory or registering a task.

## Review the exact plan

Run from an ordinary, non-elevated PowerShell session:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned `
  -File .\windows\companion\Install-ZsecAntivirusCompanion.ps1 `
  -PlanOnly
```

The default protected root is `%USERPROFILE%\Downloads`. Use `-ProtectedRoot`
to choose another existing, regular, non-reparse directory. The installer finds
`zero-security.exe`, retaining `zsec-shield.exe` as a compatibility fallback, or
accepts an explicit reviewed `-CliPath`.

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

This registers one current-user logon task. It does not request elevation. It
copies the small launcher and generated configuration to
`%LOCALAPPDATA%\ZSEC\Shield\companion`, which is already excluded from scanning.
The task uses the current user's interactive token at limited privilege. It is
transparent in Task Scheduler and is named with the current user SID to prevent
cross-user collision.

Installation refuses to overwrite any existing task or non-empty companion
directory. It verifies the registered action, owner, and single-instance setting
by reading them back. A failed registration/read-back removes only artifacts
created by that attempt. Use `-StartNow` to make starting immediately explicit;
otherwise the first start is at the next logon.

Quarantine is off. `-EnableQuarantine` is a separate explicit install-time choice
and calls the existing encrypted, recoverable quarantine path. It should be used
only after restore has been tested on disposable files.

## Resource and restart bounds

The generated configuration is deliberately conservative:

| Control | Bound |
| --- | --- |
| Scanner concurrency | One serial watcher/scanner process |
| Raw event queue | 2,048 entries; overflow ends incomplete |
| Duplicate events | 0.75-second quiet-period debounce |
| File input | 64 MiB maximum per file, streamed in 1 MiB chunks |
| Reconciliation | One Downloads rescan every five minutes |
| Process scheduling | Task priority `8` plus child `BelowNormal` priority |
| Event evidence | 4 MiB current NDJSON plus three rotated backups |
| Health | Atomic heartbeat every 30 seconds; stale after 105 seconds |
| Restart | At most three Task Scheduler retries, one minute apart |
| Multiple task instances | `IgnoreNew`, plus the engine's state-directory lock |

These bounds limit queue memory, file-buffer memory, concurrency, scheduling
priority, log storage, and restart churn. They are not a Windows Job Object or a
hard CPU/RSS quota; sustained file churn can still use CPU and disk I/O. A future
hard resource sandbox requires its own measured design and compatibility gates.

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
2. exact Scheduled Task description, action, and `IgnoreNew` setting;
3. SHA-256 match for the installed launcher and selected CLI executable;
4. task state `Running`;
5. a fresh heartbeat from a live process whose executable path matches the
   configured CLI;
6. watcher operational state `healthy`; and
7. Windows Security Center aggregate antivirus health `GOOD` from the supported
   `WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)` API.

The status output also lists `root\SecurityCenter2` antivirus registrations and
their raw `productState` only as presence evidence. Those undocumented integers
are not decoded. Microsoft Defender is reported separately from
`Get-MpComputerStatus`; a mere Defender registration never becomes a claim that
Defender is active. On a machine where Malwarebytes is primary, Defender's own
antivirus/real-time fields can correctly be false while the supported WSC
aggregate remains `GOOD`.

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

Uninstall validates the current-user ownership marker, exact task description,
action, state path, and install path before changing anything. It stops and
unregisters only that task, refuses deletion if the task does not stop or no
longer matches, and removes only the generated `companion` subtree. If that
directory was an empty pre-existing directory, the empty directory is restored.

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
