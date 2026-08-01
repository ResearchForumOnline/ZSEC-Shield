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

