# Signed data-only feed format

ZSEC Shield accepts a strict JSON envelope. The Ed25519 signature covers the RFC
8259-style canonical JSON encoding of the `payload`: UTF-8, sorted object keys, no
insignificant whitespace, and no non-finite numbers.

```json
{
  "algorithm": "ed25519",
  "key_id": "operator:primary-2026",
  "payload": {
    "expires_at": "2026-08-08T12:00:00Z",
    "generated_at": "2026-08-01T12:00:00Z",
    "rules": [
      {
        "description": "Exact digest from an independently verified sample.",
        "id": "feed:example-sha256",
        "kind": "sha256",
        "name": "Example known-file digest",
        "severity": "high",
        "source": "https://security.example/advisory/123",
        "value": "0000000000000000000000000000000000000000000000000000000000000000"
      },
      {
        "description": "Exact benign example pattern.",
        "id": "feed:example-literal",
        "kind": "literal",
        "name": "Example literal",
        "severity": "medium",
        "source": "operator test",
        "value": "ZXhhbXBsZQ=="
      }
    ],
    "schema": "zsec.shield.rules.v1",
    "sequence": 1
  },
  "schema": "zsec.shield.feed.v1",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

The displayed digest is illustrative and the signature placeholder is invalid.

## Keyring

Public keys use raw 32-byte Ed25519 encoding in canonical padded base64:

```json
{
  "keys": [
    {
      "algorithm": "ed25519",
      "key_id": "operator:primary-2026",
      "not_after": "2027-01-01T00:00:00Z",
      "not_before": "2026-08-01T00:00:00Z",
      "public_key": "BASE64_RAW_32_BYTE_PUBLIC_KEY",
      "status": "active"
    }
  ],
  "schema": "zsec.shield.keyring.v1"
}
```

`not_before` and `not_after` are optional. `status` is required and is either
`active` or `revoked`. The packaged keyring contains no keys.

## Rule constraints

- At most 2,048 rules and a 2 MiB feed document.
- Rule IDs are unique, lower-case stable identifiers; `builtin:` is reserved.
- `sha256` values are exactly 64 hexadecimal characters.
- `literal` values are canonical padded base64 decoding to 1–4,096 bytes.
- Severity is `info`, `low`, `medium`, `high`, or `critical`.
- A feed validity window cannot exceed 90 days, must not be expired, and generation
  time cannot be more than five minutes in the future.
- Sequence numbers increase monotonically. Equal sequence and digest is idempotent;
  equal sequence with different content and lower sequences are rejected.

Every listed field is required. Any additional field is rejected, even when the
payload was signed. This deliberate rigidity is what keeps the feed data-only.

## Signing guidance

Keep private keys offline or in a dedicated signing service. Build and review the
payload, canonicalize it exactly as the client does, sign the canonical payload
bytes with Ed25519, then publish the envelope over HTTPS. Rotate keys by distributing
a reviewed public-key ring before signing with the new key. Mark a compromised key
`revoked` locally; do not rely on a feed signed by the compromised key to revoke
itself.

