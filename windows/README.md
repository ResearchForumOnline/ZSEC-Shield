# ZSEC Antivirus for Windows

This directory separates two very different deliverables:

- [`companion`](companion) contains a reversible, per-user Scheduled Task wrapper
  for the working foreground post-change scanner; and
- the future supported Windows replacement-antivirus programme remains gated.

The companion is automatic only while its current-user task/process is healthy.
It is not a production primary antivirus, registered AMSI provider, file-system
minifilter, ELAM driver, protected antimalware service, or Windows Security Center
provider.

The complete implementation and certification programme is defined in
[`docs/FULL_ANTIVIRUS_PROGRAM.md`](../docs/FULL_ANTIVIRUS_PROGRAM.md).

## Do not install placeholders

**Never install, load, register, or distribute a placeholder, sample, stub,
proof-of-concept, or always-clean driver/provider.** That prohibition covers:

- runtime minifilters and their INF/service entries;
- 32-bit and 64-bit AMSI COM providers;
- ELAM boot drivers;
- protected-service prototypes;
- Windows Security Center registration adapters; and
- installers that disable or remove an existing antivirus.

A compiled binary, test signature, loadable driver, EICAR result, or working UI
is not permission to install a component on an everyday computer.

## Current safe development boundary

Keep Malwarebytes or Microsoft Defender active. Do not change its exclusions,
service state, registration, or update settings. Safe work on the everyday PC is
limited to user-mode source/build/test work, read-only WSC status inspection,
benign copied fixtures, production of packages that are not installed, and an
explicitly reviewed per-user companion. Companion installation must follow its
plan/install/status/rollback contract and does not relax any replacement gate.

All minifilter, AMSI registration, ELAM, protected-service, WSC, coexistence,
malware-corpus, cutover, and rollback testing occurs first in disposable,
snapshotted Windows VMs. Dedicated signed pilot hardware comes only after the
user-mode, driver-verification, signing, update, efficacy, and recovery gates in
the full programme pass.

## Intended Windows component map

```text
windows UI (unelevated)
        |
authenticated local IPC
        |
protected antimalware service (after ELAM/MVI approval)
        |-- restricted scanner workers
        |-- quarantine/remediation
        |-- reputation client
        |-- signed TUF updater
        |-- approved WSC integration
        |
        +-- x86 AMSI provider
        +-- x64 AMSI provider
        `-- thin runtime minifilter

ELAM boot driver is separate from the runtime minifilter.
```

The minifilter performs only bounded interception and verdict enforcement.
Hostile parsing and detection run in restricted user-mode workers. AMSI providers
are thin in-process bridges and must never report content clean merely because
the service failed. ELAM, protected-service registration, and WSC registration
use only the Microsoft-approved vendor path.

## Cutover rule

Zero Security may replace Malwarebytes on a machine only after the full
programme's G0–G8 gates pass for the exact signed release. The installer must
stage and self-test Zero, use the approved WSC registration path, read back that
Zero is active and current, and only then offer a user-confirmed change to the
old provider. Any failure rolls back and verifies Malwarebytes or Defender is
active again. The user's everyday PC is the final target, not the first test
machine.
