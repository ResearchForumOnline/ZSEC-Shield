# ZSEC Antivirus Windows desktop

Status: unprivileged Community desktop client for the implemented ZSEC
Shield contracts. It is not a primary antivirus, Windows Security provider,
pre-access enforcement component, protected service, installer, or replacement
authorization. Keep Malwarebytes or the currently active Windows antivirus and
all native Windows protections enabled.

The runnable desktop client is intentionally separated from the browser and website.
It adds no service, Scheduled Task, registry value, driver, root certificate,
firewall rule, antivirus exclusion, provider registration, telemetry endpoint,
account login, or remote-command surface.

The Windows interface uses a dark protection-centre layout with a persistent
left navigation rail, rounded evidence cards, animated local-operation state,
keyboard-accessible native controls, and a reduced-motion setting. Motion
communicates verified background activity; it never substitutes for a health
contract or turns an incomplete state green.

## Run from source

From the repository root, with the existing project environment active:

```powershell
$env:PYTHONPATH = "$(Resolve-Path .\src);$(Resolve-Path .\apps\windows-ui)"
python -m zsec_desktop
```

An installed, reviewed CLI can be selected explicitly:

```powershell
$env:PYTHONPATH = "$(Resolve-Path .\apps\windows-ui)"
python -m zsec_desktop --cli "C:\Program Files\ZSEC\zero-security.exe"
```

`ZSEC_GUI_CLI` is also accepted. The bridge resolves the executable to a regular
non-link file and never invokes a command shell.

## Implemented desktop surfaces

| Surface | Current callable contract | Desktop policy |
| --- | --- | --- |
| Overview and health | `status --json` / `zsec.shield.status.v2` | Unknown schemas and inconsistent counters fail closed. “No configured rule matches” is never rendered as “clean.” |
| Scanner | `check PATH... --json` / `zsec.shield.report.v1` | Runs outside the UI thread, has bounded output and timeout/cancel handling, excludes ZSEC state through the engine, and writes validated local reports. |
| Automatic monitoring | Windows companion status plus `watch PATH --json-lines` / `zsec.shield.watch-event.v1` | Clearly labelled post-change user-mode monitoring. The installed companion may start at logon; a UI-started session ends with the UI. Neither is pre-access protection. |
| Quarantine | `quarantine list --json`, `quarantine restore ID --json` | Restore requires a user-selected non-existing destination. No delete/purge button is exposed. Quarantine opt-in resets off after each action. |
| Feeds | `status --json`, `update --file FILE --json` | Local reviewed signed-feed files only. The UI deliberately exposes no arbitrary remote URL because the current rule-feed downloader has HTTPS/signature controls but no release-owned hostname allowlist. |
| Reports | Validated files directly below the ZSEC state `reports` directory | Regular non-link JSON files, size bounded, exact schema required. Invalid reports remain visibly invalid. |
| Security/YubiKey | Current cryptographic/quarantine facts plus design status | AES-256-GCM/DPAPI facts are separated from unimplemented YubiKey recovery. No fake enrolment control is present. |
| Replacement readiness | `replacement-readiness --platform windows --json` / `zero.security.replacement-readiness.v1` | Exit `2` plus the blocking decision are both required. There is no override, uninstall, provider-disable, or exclusion action. |
| Settings | Local UI scan bounds and resolved command/state paths | No secrets, provider changes, remote URLs, or persistent quarantine default. |

The Windows companion's supported read-only status script additionally validates
its owned supervisor registration, launcher/runtime hashes, heartbeat freshness,
process identity, post-change policy, and Windows Security Center aggregate
antivirus health. Raw `SecurityCenter2.productState` values are never decoded as
health claims.

## Process and privilege boundary

The current Community UI is an ordinary current-user process. It communicates with
the scanner through fixed argument arrays and versioned JSON; `shell=True` is
never used. Each bounded command has:

- stdin disconnected;
- an exact executable prefix;
- a clean argument vector with global state selection before the subcommand;
- a command-specific exit-code allowlist;
- a timeout or explicit long-scan cancellation path;
- 16 MiB stdout and 2 MiB stderr bounds;
- strict UTF-8 and JSON object parsing; and
- a contract validator that rejects future/unknown schemas and contradictory
  protection or cutover claims.

The UI does not import a result merely because a process exits zero. Conversely,
replacement readiness is expected to exit `2`; changing that code without a new
reviewed contract remains a desktop error. Scan status, companion health, and
replacement eligibility are three separate facts.

The foreground watcher emits flushed NDJSON. The desktop bounds each record,
validates the event schema, retains at most 500 visible entries, and marks a
user-terminated session incomplete. The installed logon companion remains a
separate reviewed PowerShell path and is not silently installed by this UI.

## Production Windows stack

The durable Windows product should use a signed .NET 10 LTS desktop client.
Microsoft currently recommends WinUI 3 with the Windows App SDK for a new native
Windows application; WPF remains a mature, supported fallback when deployment
simplicity and the smaller established desktop surface outweigh the newest Fluent
controls. The UI must remain unelevated.
It should communicate through a versioned, mutually authenticated named-pipe
protocol to a separately signed protected orchestrator service once that service
exists and passes the programme gates.

Recommended production split:

```text
Signed unelevated WPF/WinUI client
        |
        | authenticated, versioned named-pipe requests
        v
Signed protected orchestrator service
        |
        +-- restricted scanner/parser workers
        +-- authenticated encrypted quarantine service
        +-- signed update verifier and last-known-good activation
        +-- read-only health/evidence service
        `-- future approved AMSI/minifilter/Windows Security integrations
```

The UI must never hold a feed-signing key, binary-update key, device quarantine
root, YubiKey PIN, provider credential, or privileged service token. File parsing
and malware verdict work must not occur in the GUI process. Named-pipe ACLs must
bind the intended local user/service identities, every request needs a bounded
schema and correlation ID, and privileged actions require service-side policy
authorization rather than trusting a UI button.

Tk is used to make the current Python contracts visible without adding a large
unsigned GUI dependency. This Community client is not the production stack
and should not be publicly described as a completed Windows antivirus app.

## Required production states

The dashboard must derive its state from evidence:

- **No scan:** no validated persisted result exists.
- **No configured rule matches:** the exact completed scope had no configured
  matches; never use “clean,” “safe,” or “fully protected.”
- **Matches detected:** one or more exact configured rules matched.
- **Incomplete:** unreadable/skipped/oversized input, invalid feed, monitoring
  gap, queue overflow, backend loss, or other issue prevented a complete result.
- **Post-change companion healthy:** owned registration, hashes, live heartbeat,
  policy, process, and aggregate existing-antivirus health all validate.
- **Replacement blocked:** the current mandatory state on Windows; it cannot be
  dismissed or overridden.

If any contract, counter, timestamp, hash, policy field, or expected exit code is
unknown or inconsistent, the UI shows unavailable/degraded and keeps the existing
provider requirement visible.

## YubiKey boundary

YubiKey support is designed but not implemented. A valid future consumer recovery
flow needs capability detection and an evidence-backed choice between:

- FIDO2/WebAuthn with the PRF extension, after the exact Windows/runtime/key
  matrix is tested; or
- managed PIV with certificate issuance, renewal, revocation, escrow, and
  administrator separation.

Routine quarantine must remain automatic through the OS-protected device root.
The YubiKey may wrap a recovery key; it must never become a home-grown encryption
algorithm, a malware detector, or a requirement to touch the key for every scan.
No reusable PIN, raw private key, recovery secret, or unwrapped device root may
appear in UI state, logs, crash dumps, analytics, or IPC payloads.

## Test commands

The GUI-specific contract and bridge tests are:

```powershell
$env:PYTHONPATH = "$(Resolve-Path .\src);$(Resolve-Path .\apps\windows-ui)"
python -m pytest -q tests\test_windows_gui_contracts.py
python -m ruff check apps\windows-ui\zsec_desktop tests\test_windows_gui_contracts.py
python -m compileall -q apps\windows-ui\zsec_desktop
```

The new tests prove:

1. malformed and contradictory status cannot become a green state;
2. primary-replacement, uninstall, and cutover booleans remain hard false;
3. quarantine IDs, states, duplicates, and hashes are validated;
4. the bridge consumes the live status and intentionally nonzero readiness
   contracts without a shell;
5. a benign live scan writes a bounded report which is revalidated before use;
6. a future/unknown report schema is rejected; and
7. the bridge exposes local signed-feed installation but no remote feed URL or
   provider removal method.

Before a signed Windows package can be distributed, add clean Windows 10/11 VM
tests for DPI scaling, high contrast, keyboard-only navigation, screen readers,
Unicode/long paths, standard-user operation, SmartScreen/Defender coexistence,
companion installed/not-installed/degraded states, scan cancellation, process
crash, report tampering, stale heartbeat, update rollback, power loss, repair,
and uninstall. None of those tests authorize removal of Malwarebytes.

The full replacement gates remain in
[`../../docs/FULL_ANTIVIRUS_PROGRAM.md`](../../docs/FULL_ANTIVIRUS_PROGRAM.md),
[`../../docs/REPLACEMENT_READINESS.md`](../../docs/REPLACEMENT_READINESS.md), and
[`../../docs/YUBIKEY_RECOVERY.md`](../../docs/YUBIKEY_RECOVERY.md).
