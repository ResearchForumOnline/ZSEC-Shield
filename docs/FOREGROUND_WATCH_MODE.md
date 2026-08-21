# Foreground post-change protection

Status: working source-level development preview. This mode is a safer, useful
step beyond manually repeated checks. It is **not** kernel or operating-system
pre-access enforcement, a background service, or a primary antivirus provider.
Keep Microsoft Defender, Malwarebytes, XProtect, the relevant Linux controls,
and organisational endpoint protection active.

## Run it

Monitor one or more existing directories until `Ctrl+C`:

```bash
zero-security watch ./Downloads ./incoming
```

`protect` is an alias. A bounded evaluation run and an atomic final report are
available without installing any service:

```bash
zero-security watch ./incoming \
  --duration-seconds 300 \
  --report ./reports/watch-session.json
```

The default is detection/reporting only. Matched files remain where they are.
Quarantine is a deliberate, visible opt-in:

```bash
zero-security watch ./incoming --quarantine
```

Do not enable that option for irreplaceable data until encrypted quarantine and
restore have been exercised on disposable copies.

## Coverage model

The implementation uses [`watchdog` 6.0.0](https://pypi.org/project/watchdog/),
pinned as a runtime dependency. Its platform observer selects the supported native
backend for the host: `ReadDirectoryChangesW` on Windows, inotify on Linux, and
FSEvents on macOS; its OS-independent polling observer is the disclosed fallback.
The project's own documentation describes polling as slower and not recommended
when a native observer is available.

The startup and steady-state order is:

1. validate every requested root and exclude the Zero Security state directory;
2. verify the configured signed feed and bind the session to its exact identity;
3. acquire an exclusive lock for that state directory;
4. start the filesystem observer;
5. run a complete baseline scan while changes are already being queued;
6. coalesce duplicate create, modify, close-after-write, and move-destination
   events by absolute path after a configurable quiet period;
7. scan due paths with the same bounded `Scanner` used by `check`;
8. inventory file identity and metadata at the reconciliation interval, hashing
   only new, changed, or previously unresolved files whose earlier content was
   successfully verified;
9. ignore that metadata cache on a separate bounded full-rescan interval (24
   hours by default), limiting how long a persistent same-size/timestamp-restored
   change can remain suppressed by metadata equality; and
10. stop non-successfully if monitoring health or bound trust state is lost.

Native event notification does not make this pre-access protection. Another
process can open, execute, rename, replace, or delete a file before the user-mode
scan completes. A periodic reconciliation can discover some missed changes but
cannot prove there was no transient execution or close every event-loss window.

Use `--backend native` when a native observer is mandatory and absence must block
startup. The default `auto` attempts native events and falls back to polling only
at initial startup, recording the reason. `--backend polling` deliberately selects
polling. Runtime backend death never silently switches after the baseline because
that would create an unmeasured coverage gap; the session stops incomplete instead.

## Safety and failure contract

The watcher deliberately fails closed as an operational result:

- an invalid feed/trust state refuses startup with exit `2`;
- feed identity change or expiry during a session stops it with exit `2` and
  requires restart, so one session never mixes unreported rule sets;
- a dead event backend, changed/unavailable root identity, bounded queue overflow,
  unreadable/vanished observed path, or incomplete scan stops or marks the session
  incomplete;
- symlink/reparse, special-file, and over-size skips are reported as incomplete
  scope, not as a clean result;
- the state directory and all quarantine objects are excluded before event enqueue
  and again by the scanner, preventing a quarantine/rescan loop;
- recursive traversal stays on the original filesystem by default; and
- only one watch session may use a given mutable state directory at a time.

Raw plus coalesced pending event work shares one bound (`4096` entries by default)
to prevent memory exhaustion. Duplicate events are debounced (`0.75` seconds by
default), but repeated writes cannot postpone work beyond a hard coalescing age;
close-after-write, move and deletion events become due immediately. Raw or pending
overflow is never discarded as harmless: the dropped count is recorded and the
session ends incomplete. Tune only with measurement:

```bash
zero-security watch ./incoming \
  --debounce-seconds 0.5 \
  --event-queue-size 8192 \
  --reconcile-seconds 60 \
  --full-rescan-seconds 86400
```

The metadata snapshot is session-local and contains only files that completed a
stable descriptor-based hash. Oversized, unreadable, unstable, or failed files
remain unresolved, are retried, and keep health incomplete. A restart always runs
a new baseline. Metadata equality is scheduling data, not cryptographic evidence;
ZBA/ZMath is not used to decide cache validity.

Setting `--cross-filesystems` expands scope and risk; it should be an informed
operator choice. File-system event semantics also differ on network, virtual,
encrypted, overlay, removable, and remote filesystems. Validate the exact target
filesystem before relying on the companion for workflow automation.

## Quarantine, encryption, and ZBA

`--quarantine` calls the existing verified quarantine path only for an actual
configured-rule finding. It does not add a second delete/move implementation. The
source is streamed into an authenticated AES-256-GCM recovery object, verified, and
removed only if it still matches the scan evidence. A failed removal becomes an
explicit `copy_only` incomplete result.

The existing ZBA 1.1 record is automatically included and authenticated with the
object. It represents typed boundary/provenance state (`boundary` phase, `sealed`
evidence, SHA-256 commitments). ZBA/ZMath is not used as an event detector, cipher,
signature algorithm, or replacement for operating-system enforcement. Detection,
encryption, signing, and event monitoring remain established and testable
mechanisms.

## Machine output

`--json-lines` (or `--json`) emits newline-delimited
`zsec.shield.watch-event.v1` records. Every record has:

- one random `session_id` shared by the session;
- a strictly increasing `sequence` starting at `1`;
- a UTC generation time and event name;
- explicit active/requested backend and fallback details at startup;
- full scan result and quarantine result for each content batch;
- separate `reconciliation_completed` records with `no_metadata_changes` when no
  bytes were hashed, never a fabricated clean or no-match content result; and
- a final `zsec.shield.watch-summary.v1` with outcome, counters, health issues,
  roots, and the non-primary policy.

The optional report is `zsec.shield.watch-report.v1` and is written with atomic
same-directory replacement and owner-only permissions where supported. NDJSON is
intended for a supervising UI or test harness; record ordering is local to one
process and is not a cryptographic audit log.

## Exit codes

| Code | Watch meaning |
| --- | --- |
| `0` | The bounded session completed with no configured rule matches and no known operational gap. This does not mean clean. |
| `1` | One or more configured rules matched and the session otherwise completed. |
| `2` | Startup was refused or monitoring/scanning/quarantine coverage was incomplete. |
| `130` | The operator interrupted the session. |

An unbounded foreground run normally ends with `Ctrl+C`, so `130` is expected. A
supervisor must not convert `2` or backend silence into “protected.”

## Coexistence and production boundary

This command performs no Windows Security registration, provider selection,
Microsoft Virus Initiative action, service installation, launch-agent/systemd
installation, exclusion management, or antivirus removal. It must not ask users to
disable another product. Two scanners may both inspect a file, so performance and
file-lock interactions should be measured with the existing protection enabled.

A proper replacement antivirus still requires the documented platform enforcement,
publisher signing, updater, efficacy/false-positive, coexistence, recovery, and
certification gates. On Windows that includes a supported minifilter/service/AMSI/
ELAM architecture and the approved Windows Security/MVI path; this watcher does not
simulate or weaken those gates.

## Verification gates for this preview

Release CI must pass:

1. unit tests for debounce starvation, state exclusion, move-source/destination
   handling, raw-plus-pending overflow, backend fallback, backend death, and root
   validation;
2. cache tests proving unchanged trees are not repeatedly hashed, failed/oversized
   files never enter the verified snapshot, metadata-only work has distinct
   evidence, and full rescans ignore metadata equality;
3. an integration test using the real polling observer and a file created after
   the baseline;
4. CLI tests proving default no-quarantine, explicit encrypted quarantine with the
   ZBA record, ordered session output, and invalid-feed refusal;
5. all existing scanner/feed/quarantine/status/replacement tests;
6. Ruff, strict mypy, wheel/sdist build, and native-manifest schema tests; and
7. native archive smoke evidence that `watch --help` exists while
   `replacement-readiness` still returns `keep_existing_protection` and exit `2`.

Platform-specific native-event, high-churn, sleep/resume, filesystem, coexistence,
and long-duration soak evidence remains required before any broader protection
claim.
