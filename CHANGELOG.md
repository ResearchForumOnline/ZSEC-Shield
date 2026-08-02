# Changelog

## Unreleased

Store-readiness packaging:

- added inspectable PyInstaller one-directory builds for Windows, macOS, and Linux;
- added native manifests, per-file and per-archive SHA-256 metadata, and license notices;
- added executable smoke tests and a version-gated GitHub Actions release matrix;
- release automation creates a draft for human review and performs no publisher signing.

## 0.1.0 - 2026-08-01

Initial cross-platform MVP:

- deterministic streaming SHA-256 and exact literal matching;
- built-in EICAR test detection;
- opt-in, recoverable quarantine with no-overwrite restore;
- strict Ed25519-signed, data-only feeds with expiry and rollback protection;
- read-only Windows, macOS, and Linux inventory adapters;
- structured JSON reports, CLI exit codes, tests, packaging, and CI.

This release does not provide complete antivirus or kernel real-time protection.
