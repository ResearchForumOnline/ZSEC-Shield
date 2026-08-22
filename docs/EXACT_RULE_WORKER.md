# Bounded rule and review-provider worker protocol

Status: implemented Community process-separation layer. This is not the
reduced-privilege hostile-parser sandbox required for primary-antivirus
replacement.

## Purpose

The user-scoped CLI broker owns path resolution, link/reparse policy, descriptor
opening, file identity checks, signed rules, result construction and quarantine
authority. It streams bytes from the validated open descriptor to a dedicated
child process. The worker receives no source path, state path, quarantine key,
remediation command or update authority.

The broker and worker independently calculate SHA-256. A usable response must:

- use protocol `zsec.scan-worker.v1`;
- carry the exact 128-bit request correlation ID;
- contain no missing, duplicate or unknown fields;
- fit the one MiB control/response ceiling;
- report exactly the declared byte count;
- contain only configured literal-rule IDs and at most 32 strictly bounded,
  explicitly quarantine-ineligible observations; and
- agree with the broker's SHA-256 calculation.

Unknown protocol versions, malformed UTF-8/JSON, duplicate keys, oversized
frames, worker death, response timeout, byte-count disagreement, digest
disagreement, file mutation and transport failure all produce an incomplete file
result. The broker does not retry the file in-process.

## Current lifecycle and bounds

- One broker owns at most one worker and sends one request at a time.
- Content frames are no larger than the configured scan chunk (one MiB by
  default).
- Control and result frames are limited to one MiB.
- Input is limited by the scanner's explicit per-file ceiling (64 MiB by
  default).
- The broker applies a bounded response deadline (45 seconds by default).
- A worker is replaced after 512 requests by default; tests can use a smaller
  value to exercise replacement.
- On POSIX, the child attempts to disable core dumps and apply address-space,
  descriptor and process-count limits. Unsupported unprivileged limits do not
  turn the child into a sandbox.
- The child never performs feed installation, file enumeration, quarantine,
  restore, inventory, update or GUI operations.

## Review-only providers and exact non-claims

The child currently inherits the invoking user's security authority. The Python
multiprocessing transport is process separation, not Windows AppContainer,
restricted-token, Job Object, macOS sandbox/XPC or Linux namespace/seccomp
confinement. It does not satisfy the `parser_isolation` replacement-readiness
gate. The current worker adds bounded PE metadata, conservative script-chain and
ZIP central-directory checks. It retains at most 16 MiB for these providers,
never extracts an archive, and never executes inspected content. Windows PE paths
may also receive a broker-side, cache-only WinVerifyTrust check after file identity
validation. Informational metadata is not a review result. No provider observation
is eligible for automatic quarantine. There is still no document/macro, behavioral,
memory or pre-access inspection.

Before a complex hostile-format parser or auto-remediation provider is added,
Windows requires a one-shot
native launcher with capability-free AppContainer isolation, Job Object process
and memory limits, child-process prohibition, explicit handle inheritance,
compatible process mitigations, a minimal environment and negative network/
filesystem/credential-access tests. Linux and macOS need independently tested
native equivalents. A containment setup failure must never launch an ordinary
same-user parser as a fallback.

## Policy boundary

The worker reports evidence, not policy. The broker resolves returned rule IDs
against the already verified rule set and owns all severity and quarantine
decisions. A worker response never means a file or system is clean. The strongest
negative result remains: no configured exact rule matched the bytes that were
successfully inspected under this engine and policy version.
