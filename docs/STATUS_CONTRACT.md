# Desktop status bridge contract

ZSEC Shield exposes a versioned, machine-readable snapshot for desktop and other local
consumers:

```bash
zsec-shield status --json
```

The current schema is `zsec.shield.status.v2` with `contract_version: 2`. Consumers
must reject unknown schemas and inconsistent fields instead of guessing that a scan
was successful.

## Last-scan evidence

The v2 payload retains every v1 field and adds:

| Field | Type | Meaning |
| --- | --- | --- |
| `last_scan_outcome` | string or null | `no_configured_rule_matches`, `configured_rule_matches_detected`, `incomplete`, or no prior scan |
| `last_scan_errors` | non-negative integer | Persisted issue count from the last scan |
| `last_scan_files_hashed` | non-negative integer or null | Files hashed; null means no scan or an older summary without this evidence |
| `last_scan_bytes_hashed` | non-negative integer or null | Bytes hashed; null means no scan or an older summary without this evidence |

`last_scan_diagnostic.available` says whether a validated local summary was loaded.
Its `error` field reports malformed or unreadable summary state.

`application_update_status` is separate notification evidence. Its state is
`never_checked`, `current`, `available`, or `error`; `automatic_install` is always
false. It does not change scan outcome, protection health, or replacement readiness.
Corrupt schedule state triggers a new signed check instead of suppressing checks, and
a failed check retains the last verified notice while reporting the error.

## Fail-closed consumer states

A consumer may show a clean/ready state only when all of these are true:

1. `last_scan_diagnostic.available` is true and its error is null.
2. `last_scan` is present.
3. `last_scan_outcome` is exactly `no_configured_rule_matches`.
4. `last_scan_errors` and `findings` are both zero.

`incomplete` is never a clean result, even if its error counter is zero. This can
happen when a rule feed is invalid. Findings, diagnostic failures, inconsistent
counters, unknown schemas, and legacy v1 scan snapshots must map to attention or
unavailable—not ready.

A status command that successfully reports a historical incomplete scan still exits
zero. The original `check` command exits 2 for an incomplete scan.

## Persisted-summary migration

New scans use `zsec.shield.last-scan.v2` and persist outcome, issues, and file/byte
counters. Exact v1 summaries remain readable so upgrades do not erase history. Their
missing file/byte counters are normalized to null; consumers must not invent zero work.

This bridge reports evidence from a deterministic on-demand scanner. “No configured
rule matches” is not proof that a machine is clean and does not imply real-time
protection, behavioral monitoring, cloud reputation, or antivirus certification.

Primary-antivirus eligibility is deliberately a separate contract. Consumers
must never infer replacement readiness from scan status, inventory, EICAR, or a
zero exit here. Use `zero-security replacement-readiness --json` and follow the
[replacement-readiness contract](REPLACEMENT_READINESS.md); the current preview
returns a blocking decision and exit code `2` on every supported platform.
