# Primary-antivirus replacement readiness

Status: public-preview safety contract. The current decision is **keep existing
protection** on Windows, macOS, and Linux.

Zero Security exposes a machine-readable guard for installers, desktop clients,
automation, and support tools:

```bash
zero-security replacement-readiness --json
zero-security replacement-readiness --platform windows --json
zero-security replacement-readiness --platform macos --json
zero-security replacement-readiness --platform linux --json
```

`zsec-shield` remains a compatible command name. The guard does not create a
state directory, modify another product, or inspect private user files.

## Current contract

The schema is `zero.security.replacement-readiness.v1`. In every current preview
build it reports:

```json
{
  "decision": "keep_existing_protection",
  "eligible_for_primary_replacement": false,
  "existing_provider_must_remain_active": true,
  "automatic_uninstall_available": false,
  "manual_override_available": false
}
```

The command intentionally exits with code `2`. That non-success result is the
cutover interlock: a packaging script, installer, user interface, or automation
must not treat a preview as authorized to remove, disable, exclude, or supersede
the active antivirus. There is no environment variable, state-file switch,
command-line override, or local evidence-ingestion route that can turn the
preview decision into success.

The payload also lists implemented preview foundations and every known blocking
gate for the selected platform. A blocker remains `not_met` until immutable
evidence for the exact release is reviewed through a future, separately designed
release-authority process. Editing local JSON is never release evidence.

## Shared release gates

All three desktop programmes require, at minimum:

- locked, versioned malware and cleanware evaluation with declared thresholds;
- publisher-signed binaries, installers, packages, and update metadata;
- expiring staged updates, health halts, freeze protection, and tested rollback;
- hostile-file parser isolation and bounded resource consumption;
- a supported operating-system, hardware, filesystem, and application matrix;
- crash, corruption, key-loss, quarantine, restore, and recovery drills;
- coexistence, transactional cutover, and automatic provider restoration; and
- staffed security response, false-positive handling, revocation, and recovery.

Platform enforcement gates are defined in the
[Windows programme](FULL_ANTIVIRUS_PROGRAM.md),
[macOS programme](MACOS_DESKTOP_PROGRAM.md), and
[Linux programme](LINUX_DESKTOP_PROGRAM.md).

## Cutover invariant

Zero Security may offer a user-confirmed removal or mode change for another
antivirus only after all of these are true for the exact signed candidate:

1. Every shared and platform gate has independently reviewable evidence.
2. A clean-machine coexistence pilot and an upgrade pilot both pass.
3. Zero Security is staged without weakening the current provider.
4. Local self-tests, update freshness, on-access wiring, quarantine, restore,
   reboot or restart persistence, and operating-system health checks pass.
5. The platform reports or otherwise verifies Zero Security active and current
   using the supported integration path available on that operating system.
6. A tested rollback can restore the previous product or native platform
   protection without leaving the machine unprotected.
7. The user explicitly confirms the old-provider change after seeing the
   verified state and recovery route.

The user's everyday desktop is the final cutover target, never the first pilot.
Malwarebytes, Microsoft Defender, XProtect, Gatekeeper, SIP, and Linux mandatory
access controls must not be disabled to make an unfinished build appear ready.

## Consumer rules

- Reject unknown schemas, unknown decisions, missing fields, inconsistent gate
  counts, or a success exit paired with `eligible_for_primary_replacement: false`.
- Render `keep_existing_protection` as a blocking state, not a warning that can
  be dismissed.
- Do not provide an uninstall button, exclusion wizard, provider-disable action,
  or hidden support override while `automatic_uninstall_available` is false.
- Keep scan status and replacement readiness separate. A successful on-demand
  scan never satisfies a production replacement gate.
- Log the exact version, platform, decision, and blocker identifiers without
  filenames, file contents, credentials, or browsing history.

This version of the contract is intentionally one-way. A future release that can
become eligible requires a new reviewed schema, signed release evidence, tests
for tampering and rollback, and an installer design that fails safely at every
transition.
