# ZSEC static update service

ZSEC clients retrieve independently signed metadata from two stable HTTPS endpoints:

- `https://talktoai.org/zsec/intelligence/v1/feed.json`
- `https://talktoai.org/zsec/updates/v1/stable.json`

The intelligence endpoint contains only the strictly validated advisory catalog.
It contains no executable content, malware samples, commands, detection signatures,
or permission to remediate a device. The application endpoint is notification-only
while the distributed Windows package is unsigned; it cannot authorize an automatic
installation.

Both documents use an Ed25519 envelope. The signature covers canonical UTF-8 JSON
of `payload` with sorted keys and no insignificant whitespace. Clients must bundle
the public root key out of band, verify the signature before reading payload data,
persist the greatest accepted sequence, reject a lower sequence, reject equal
sequence with different bytes, and reject expired metadata. The downloadable
`public-key.json` is diagnostic and **must not** bootstrap trust by itself.

Every publication also writes a small, signed, zero-padded audit record binding the
sequence to both endpoint digests. The complete catalog is not duplicated daily,
which prevents unbounded repository growth. GitHub Pages deploys the complete `web`
artifact atomically.

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
6. Verify both canonical endpoints, their signatures, content types, cache rules,
   and versioned copies after deployment.

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
