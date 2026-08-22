# Changelog

## 0.3.2 - 2026-08-22

- expanded the reversible Windows companion installer from one protected root to
  one through eight exact roots, with safe existing-folder defaults and strict
  state-directory/reparse-point exclusion;
- added bounded heartbeat progress evidence during mandatory baseline and
  reconciliation scans so long scans do not look like a dead protection process;
- preserved the post-change Community boundary, existing-provider coexistence,
  opt-in encrypted quarantine, and the fail-closed Malwarebytes replacement gate;
  and
- advanced the new desktop bytes to a distinct side-by-side version instead of
  rewriting the published 0.3.1 artifact.

## 0.3.1 - 2026-08-22

- added the path-free bounded exact-rule content worker used by CLI scan and
  foreground watch commands;
- added independent broker SHA-256 verification, strict correlation IDs,
  duplicate/unknown-field rejection, bounded frames, periodic worker
  replacement and fail-closed worker/protocol outcomes;
- exposed the exact worker boundary in status and GUI Health evidence without
  claiming reduced privilege, hostile-format parsing or a completed replacement
  gate;
- repaired the Windows GUI watch contract so verified metadata-reconciliation
  events remain renderable rather than being rejected as unknown; and
- preserved 0.3.0 artifact identity and advanced the new bytes to a distinct
  candidate version for side-by-side installation and rollback.

## 0.3.0 - 2026-08-21

- reserved version 0.3.0 for this materially new feature set rather
  than reusing the already-published 0.1.2 version;
- added the fail-closed `zero-security replacement-readiness` contract for
  Windows, macOS, and Linux; the preview always keeps existing protection active;
- added opt-in foreground post-change protection through `watch`/`protect`, using
  native filesystem events with a disclosed polling fallback, mandatory baseline,
  debounce, bounded queue, periodic reconciliation, state exclusion, and explicit
  incomplete results when known coverage or bound feed trust is lost;
- added the reversible ZSEC Antivirus per-user Windows companion: plan-only
  inspection, limited logon Scheduled Task, bounded queue/log/restart settings,
  heartbeat and WSC aggregate-health proof, raw non-interpreted provider evidence,
  and ownership-verified rollback that cannot remove a primary provider;
- added reversible macOS LaunchAgent and hardened Linux systemd-user companion
  packages with pinned runtime identity, bounded health evidence, plan/status/
  uninstall workflows, and no platform-security-control changes;
- added a strict daily desktop advisory catalog from CISA, Microsoft, Apple and
  Ubuntu with raw and semantic digests, ZBA-typed provenance, atomic updates,
  content-addressed backup, and fail-closed rollback protection;
- specified separate production-grade macOS Endpoint Security and Linux
  fanotify desktop programmes with platform signing, key custody, coexistence,
  rollback, efficacy, and support gates;
- added a canonical ZSEC Browser privacy page and deterministic site validation;
- added ZSEC Browser Desktop Preview 0.2.3 for Windows: a visible WebView2
  Chromium shell with native ZSEC UI, isolated profile, default-deny permissions,
  HTTPS upgrading, certificate-error cancellation, explicit downloads, compiled
  ZSEC blocker/link-cleaning policy, versioned per-user install/status/uninstall,
  and live runtime acceptance checks;
- pinned the Microsoft WebView2 SDK to 1.0.4129.50 with official NuGet SHA-512
  and locked SHA-256 verification, while keeping the ZSEC binary explicitly
  unsigned and the maintained-Chromium-fork/signing/updater gates visible;
- established ZSEC Antivirus as the full replacement-antivirus programme while
  preserving the current ZSEC Shield preview boundary;
- encrypted all new quarantine objects with per-object AES-256-GCM keys and an
  automatically DPAPI-sealed device root on Windows;
- authenticated canonical immutable metadata and a ZBA 1.1 lifecycle record as
  AAD, plus a separate MAC over mutable quarantine metadata;
- retained fail-closed legacy v1 restore compatibility without silently treating
  incompatible ZME1 research formats as one format;
- added ciphertext, metadata-tamper, ZBA-mutation, and no-plaintext-publication
  tests;
- added ZSEC Browser Shields, a Manifest V3 extension with local privacy rules,
  per-site pause, best-effort YouTube cleanup, and static security validation;
- documented the open-core boundary, privacy contract, recovery design, research
  integration, full Windows antivirus/MVI programme, and evidence-based claims;
- added the ZSEC Antivirus/ZSEC Browser brand system and product website sources.

## 0.1.2 - 2026-08-02

Status evidence repair:

- introduced status contract v2 with persisted last-scan outcome, error, file, and byte counts;
- made incomplete scans remain explicitly incomplete after status refresh;
- retained exact v1 summaries without inventing missing file or byte evidence;
- added strict outcome/counter validation, nonexistent-path regressions, and native smoke tests.
## 0.1.1 - 2026-08-02

Native packaging repair:

- added a checksum-pinned CPython license fallback for macOS and Linux runners whose
  Python installation does not expose a root license file;
- included the fallback in source distributions and added regression coverage for
  fallback selection and bundle inclusion.

## 0.1.0 - 2026-08-01

Initial cross-platform MVP:

- deterministic streaming SHA-256 and exact literal matching;
- built-in EICAR test detection;
- opt-in, recoverable quarantine with no-overwrite restore;
- strict Ed25519-signed, data-only feeds with expiry and rollback protection;
- read-only Windows, macOS, and Linux inventory adapters;
- structured JSON reports, CLI exit codes, tests, packaging, and CI.
- inspectable PyInstaller one-directory builds for Windows, macOS, and Linux;
- native manifests, per-file and per-archive SHA-256 metadata, and license notices;
- executable smoke tests and a version-gated GitHub Actions release matrix;
- draft-only release automation with no publisher signing.

This release does not provide complete antivirus or kernel real-time protection.
