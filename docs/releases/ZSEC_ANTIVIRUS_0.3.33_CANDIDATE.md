# ZSEC Antivirus 0.3.33 candidate

This is the next compatibility candidate, not the already published 0.3.32
archive or the Store-signed 0.3.32.0 edition. No 0.3.33 tag, direct release or
Microsoft Store submission has been made by preparing this source candidate.

## Diagnosed compatibility failure

The production signed intelligence envelope is 2,379,423 bytes. It is already
compact UTF-8; all 1,648 advisory records and its pinned-key Ed25519 signature
verify. The existing intelligence verifier accepts at most 8 MiB, but its shared
network transport rejects any response over 2 MiB. The restored canonical HTTPS
redirect reaches the daily signed mirror; it cannot fix the downloader mismatch.

## Narrow fix

- Keep the public rules/general downloader at its existing fixed 2 MiB limit.
- Introduce a named intelligence downloader fixed to the verifier's existing
  8 MiB limit. Only the intelligence update caller uses it.
- Expose no public size override. The internal helper accepts only exact integer
  values for the two fixed limits, rejecting arbitrary/unlimited requests.
- Preserve credential-free HTTPS, at most three redirects, timeout, bounded
  Content-Length and actual-body reads, pinned-key signatures, expiry and rollback
  protection. Application metadata retains its 64 KiB verification limit.
- Keep all records and the signed publisher contract unchanged.
- Set package/source version 0.3.33 and display the GUI version from that source.

Transport regressions cover valid signed intelligence above 2 MiB, default
oversize refusal, intelligence refusal above 8 MiB with and without a length
header, unsupported limits, absent public size overrides, redirect restrictions,
the application-envelope bound and invalid signatures. Explicit large signed
expired and rollback responses retain the previously verified catalog and
last-success status. Existing key and last-known-good tests remain in the suite.

## Candidate verification

On 30 September 2026 the complete suite passed: **327 tests and 14 subtests**.
Ruff passed and mypy reported no issues in all 28 source modules.

The actual canonical intelligence URL downloaded through the new typed transport
and installed in disposable state. Its pinned signature verified, sequence 60
was accepted, and all 1,648 advisories were retained with exact catalog equality.
The envelope expires at `2026-10-07T16:40:49Z`; its SHA-256 is
`8f431483c6d5430d2a24bb2a64325707c5978923886e7c783b3fb8070f2710f5`.
The sanitized [live verification receipt](ZSEC_INTELLIGENCE_0.3.33_CANONICAL.json)
records the 2,379,423-byte response, disposable-state scope and unchanged key and
privacy contracts. No application or Windows protection-provider action was
performed by that check.

Fresh direct and Store-upload builds require separate exact source and artifact
receipts before publication or submission. Preparing an unsigned MSIX is not
certification, publication or installation evidence.
