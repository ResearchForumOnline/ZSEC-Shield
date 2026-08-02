# Changelog

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
