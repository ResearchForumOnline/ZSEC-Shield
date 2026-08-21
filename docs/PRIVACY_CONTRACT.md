# Zero Security privacy contract

The local preview has no analytics endpoint, advertising identifier, account,
remote-control channel, or automatic sample upload.

## Local processing

- File hashing, rule matching, quarantine encryption, and browser blocking occur
  locally.
- Browser history, page content, form data, cookies, and search queries are not
  collected by Zero Browser Preview.
- Private browsing must not add persistent Zero Browser history or diagnostics.

## Network requests

- Update checks may disclose only product, version, platform, architecture,
  channel, and a coarse rollout cohort.
- Rule feeds remain signed data. They cannot request commands or system changes.
- Future reputation lookup should use hash-prefix queries; full hashes or samples
  require a separate disclosed flow.

## Diagnostics and samples

- Crash/diagnostic upload is a separate opt-in.
- URLs, query strings, local paths, usernames, filenames, cookies, form content,
  extension inventory, and memory contents are excluded or scrubbed.
- A suspicious file is never uploaded by default. Per-item upload must identify
  purpose, destination, retention, region, sharing, and deletion policy before
  transmission.

## Claims

"Local-first" does not mean "no network requests." Update and opt-in diagnostic
flows must be documented precisely. The project will not claim "zero telemetry"
if any telemetry is enabled.
