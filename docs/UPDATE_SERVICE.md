# ZSEC static update service

The publisher creates three independently verified artifacts:

- `https://talktoai.org/zsec/intelligence/v1/feed.json`
- `https://talktoai.org/zsec/rules/v1/feed.json`
- `https://talktoai.org/zsec/updates/v1/stable.json`

The intelligence endpoint contains only the strictly validated advisory catalog.
It contains no executable content, malware samples, commands, detection signatures,
or permission to remediate a device. It is never converted into scanner rules. The
rules endpoint uses the separate, strict `zsec.shield.feed.v1` contract and is
currently locked to two informational checks for the harmless canonical EICAR test
file. Those checks validate scanner/feed wiring; they do not establish malware
detection efficacy. The application endpoint is notification-only while the
distributed Windows package is unsigned; it cannot authorize an automatic install.

All three documents use Ed25519. The signature covers canonical UTF-8 JSON
of `payload` with sorted keys and no insignificant whitespace. Clients must bundle
the public root key out of band, verify the signature before reading payload data,
persist the greatest accepted sequence, reject a lower sequence, reject equal
sequence with different bytes, and reject expired metadata. The downloadable
`public-key.json` is diagnostic and **must not** bootstrap trust by itself.

Every publication also writes a small, signed, zero-padded audit record binding the
sequence to all three endpoint digests. The complete catalog is not duplicated daily,
which prevents unbounded repository growth. GitHub Pages deploys the complete `web`
artifact atomically.

Application metadata does not select, disable, uninstall, register, or reconfigure
an antivirus provider. The current unsigned Windows application remains
notification-only: the verifier accepts no command, argument, provider-action, or
automatic-install field. Microsoft Defender or another active Windows Security
provider must remain active across an update check, a failed download, and an
application restart.

## Failure and rollback invariants

- Verify the pinned Ed25519 key, exact envelope fields, validity window, sequence,
  artifact SHA-256 and artifact size before treating metadata as current.
- Treat the advisory catalog and scanner rules as different schemas and different
  data classes. Never derive a literal or digest rule from advisory text.
- A truncated response, unknown field, wrong key, invalid signature, expired
  envelope, digest mismatch, or audit mismatch is an update failure—not an empty
  feed and never a clean-device result.
- Preserve the last verified intelligence catalog and its greatest accepted
  sequence after every failed check. Never replace it with partially downloaded
  bytes.
- Reject a lower sequence. Accepting an equal sequence is permitted only when its
  canonical signed bytes are identical to the already accepted document.
- Download application packages to a fresh non-executable staging name, verify the
  declared byte count and SHA-256, then activate atomically. A partial download must
  be deleted and must not become a future resume source unless a separately designed
  authenticated chunk protocol is introduced.
- Before activation, retain the exact prior installed version. Failed activation or
  failed post-install health checks must restore that version without touching
  quarantine, reports, settings, device keys, rollback state, or the active Windows
  protection provider.
- Do not label application auto-update production-ready until the downloader,
  staging, activation, health gate and rollback path have executable adversarial
  tests. Signed metadata by itself is not a safe binary updater.

## Production key setup

Generate the Ed25519 key once in an offline administrative environment. Store the
raw 32-byte private key as canonical padded base64 in the protected GitHub
environment secret `ZSEC_UPDATE_SIGNING_KEY_B64`. Store its raw public-key base64
as the environment variable `ZSEC_UPDATE_PUBLIC_KEY_B64`. Configure the
`update-production` environment and restrict deployment to the protected `main`
branch. Scheduled operation must not require a human reviewer. Never place a private key in Git, an Actions artifact,
a log, a Pages directory, or a TalkToAI server checkout.

The one-time helper refuses to put the private key inside the repository, refuses
overwrites, and never prints private-key material:

```powershell
python scripts/generate_update_signing_key.py `
  --private-output D:\offline-zsec-keys\update-private.b64 `
  --public-output D:\offline-zsec-keys\update-public.b64
```

Move the private file to offline protected storage immediately after setting the
GitHub environment secret. On Windows, apply restrictive NTFS permissions to that
directory before generation; POSIX systems additionally receive mode `0600`.

The workflow compares the signing key's derived public key with the protected
public value, runs publisher and intelligence tests, refuses unrelated changes,
and commits only generated `web/zsec/**` assets. OIDC is enabled for Pages
deployment, but GitHub does not provide a native Ed25519 signing service; replacing
the encrypted secret with a cloud HSM/KMS requires a reviewed signing adapter and
short-lived OIDC authentication.

## Publication operation

1. Update and validate `intelligence/desktop-advisories.json`.
2. Review `updates/application-release.json`; hashes and sizes must describe the
   already published release exactly.
3. The daily workflow refreshes authoritative sources, selects the next sequence,
   and creates a seven-day validity window automatically. Manual dispatch can
   supply explicit values for recovery and controlled testing.
4. Validity is capped at 14 days so a frozen mirror eventually fails closed.
5. The workflow publishes through the protected environment.
6. Verify all three canonical endpoints, their signatures, content types, cache rules,
   and versioned copies after deployment.

The current client installs scanner rules only through an explicit local CLI action;
the publisher does not silently change a device. After confirming the HTTPS endpoint
and certificate, an operator can install it with:

```powershell
zsec-shield update --url https://talktoai.org/zsec/rules/v1/feed.json --json
```

An absent, expired, invalid, rolled-back, or tampered rule feed remains an explicit
feed state. It is never reported as a clean scan and never disables the two built-in
EICAR wiring checks or the active Windows Security provider.

Local deterministic generation is available for testing:

```powershell
$env:ZSEC_UPDATE_SIGNING_KEY_B64 = '<raw-private-key-base64>'
$env:ZSEC_UPDATE_PUBLIC_KEY_B64 = '<raw-public-key-base64>'
python scripts/publish_update_service.py --key-id zsec:update-primary-2026 `
  --sequence 1 --generated-at 2026-08-22T20:00:00Z `
  --expires-at 2026-09-05T20:00:00Z
```

Do not reuse a sequence for different bytes. The publisher refuses this locally;
branch protection and the production environment must prevent bypassing it in CI.
