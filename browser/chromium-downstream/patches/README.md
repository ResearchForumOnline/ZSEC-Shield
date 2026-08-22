# ZSEC Chromium downstream patches

This directory is intentionally empty of Chromium code changes at this revision.
`series.json` locks the exact upstream base and the ordered patch inventory. An
empty series means ZSEC has not yet created or validated a Chromium source
patch; it must never be described as a maintained fork on that basis.

Future entries must be reviewable `git format-patch` text files. Each entry must
include its one-based order, relative path, SHA-256, purpose, and the upstream
area it changes. The policy validator rejects missing, reordered, oversized,
reparse-point, binary, hash-mismatched, path-escaping, or security-weakening
patches before any supported build host may use them.

The patch validator is a review gate, not proof that a patch is secure. Every
patch still requires source review, license review, a supported-host Chromium
build, upstream tests, ZSEC browser tests, and signed release/update gates.
