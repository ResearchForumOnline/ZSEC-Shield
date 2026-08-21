# Operations

## Safe evaluation sequence

1. Install in a Python virtual environment on a test machine.
2. Run `zsec-shield status --json`; an absent feed is expected until a trust key is
   deliberately configured.
3. Run `zsec-shield check TEST_PATH --report REPORT.json` without quarantine.
4. Review findings, skipped counters, and issues. Treat a match as a review signal,
   not proof of malicious intent.
5. Test quarantine only on disposable copies. Confirm `quarantine list`, restore to
   a new destination, and compare SHA-256.
6. Pin a reviewed Ed25519 public key before testing feed update.

## Foreground post-change protection

After the on-demand workflow has been validated, run the automatic file-event
monitor only as a foreground companion:

```bash
zero-security watch ./incoming
```

Keep the existing antivirus and platform protections active. The observer starts
before a mandatory baseline scan, debounces duplicate events, excludes the state
and quarantine trees before enqueue, and periodically reconciles the roots. Native
observer startup may fall back to polling with an explicit event. A backend death,
queue overflow, root identity change, or feed/trust change ends the session
incomplete rather than silently claiming continued coverage.

Quarantine remains disabled unless `--quarantine` is supplied. A normal watch
session is read-only apart from state locks/reports and any routine status/feed
reads; it does not register a provider, configure exclusions, disable another
product, or install persistence. See
[the complete foreground-mode contract](FOREGROUND_WATCH_MODE.md).

On Windows, automatic current-user launch is available only through the
review-first [ZSEC Antivirus companion](../windows/companion/README.md). Run its
installer with `-PlanOnly` before registration and its uninstaller with
`-PlanOnly` before rollback. A healthy companion requires fresh process/task/hash
evidence and supported Windows Security Center aggregate antivirus health. Raw
`SecurityCenter2.productState` is recorded but not decoded, and the companion
never authorizes removal or cutover of the existing primary provider.

When integrating `status --json`, apply the
[desktop status bridge contract](STATUS_CONTRACT.md). A ready state requires the exact
successful no-match outcome plus zero findings and zero errors. Never infer success
from a timestamp and zero findings alone; incomplete and legacy scan states fail closed.

## Permissions

Run with the least privilege that can read the intended paths. Do not elevate merely
to suppress an unreadable-file report. Protect the state and keyring directories so
untrusted users cannot modify them. Public keys are not secrets, but their integrity
is security-critical.

## Reports

`--report` uses an atomic same-directory replacement and requests owner-only file
permissions where supported. Reports include absolute paths, hostname, OS details,
hashes, and errors; treat them as potentially sensitive operational records.

## Feed incident response

If a signing key may be compromised:

1. Stop feed distribution.
2. Mark the key `revoked` in each independently distributed local keyring.
3. Run `status`; the current feed should become `invalid` and contribute zero rules.
4. Review the installed feed and prior reports as untrusted data.
5. Distribute a new public key through an authenticated channel, then publish a new
   feed at a sequence higher than the local rollback record.

Do not delete rollback state simply to accept a lower sequence. That defeats rollback
protection. Restore both feed and state from a known-good local backup if repair is
needed.

## Quarantine incident response

A `copy_only` entry means a verified recovery copy exists but the original was not
removed. Resolve directory permissions or file locks and rescan before any new action.
A `restored` entry retains its content object by design. There is no automatic expiry
or deletion in this MVP; storage retention is an operator policy decision.
