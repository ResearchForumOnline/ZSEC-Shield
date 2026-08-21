# ZSV2 encrypted quarantine profile

Status: implementation-aligned specification for
`zero-security-quarantine-aes256gcm-v1`, 21 August 2026.

This document specifies the encrypted quarantine object written by
`src/zsec_shield/crypto_vault.py` and `src/zsec_shield/quarantine.py`. It freezes
the current names, field sets, byte derivations, AAD, and failure behavior so the
token `ZSV2` has one meaning.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and
**MAY** are normative requirements. “Current reader” describes checks already
enforced by the Python implementation. A stated release gate that is stricter
than the current reader is not a claim that the gate is already implemented.

## 1. Scope and identifiers

ZSV2 is a directory-framed, device-bound encrypted quarantine profile. It is not
a standalone portable file format. A conforming current object has this identity:

| Identifier | Exact value |
| --- | --- |
| Metadata schema | `zero.security.quarantine.v2` |
| Vault format | `ZSV2` |
| Vault profile | `zero-security-quarantine-aes256gcm-v1` |
| Content cipher | `AES-256-GCM` |
| Key derivation | `HKDF-SHA-256` |
| ZBA record profile | `zero.security.zba.quarantine.v1` |
| Device-root record schema | `zero.security.device-root.v1` |

All comparisons are case-sensitive. A reader MUST require all relevant
identifiers and MUST NOT treat `ZME1`, `ZME1-AV`, a `.zmath` file, a CallChat
Shield envelope, or an arbitrary `version: 1` object as ZSV2.

The current profile is classical authenticated encryption. It is not a
post-quantum, quantum-key-distribution, “AES-512,” or novel-cipher profile. ZBA is
bound metadata, not the source of encryption strength.

## 2. Object framing

Given application state directory `STATE` and canonical entry UUID `ENTRY_ID`,
the current object is:

```text
STATE/
  vault/
    keys/
      device-root.json
  quarantine/
    entries/
      ENTRY_ID/
        metadata.json
        content.zsv2
```

`ENTRY_ID` MUST be the lowercase canonical hyphenated text form produced by a
UUID parser. The metadata `id` MUST equal the directory name exactly.

`content.zsv2` contains only the AES-GCM ciphertext bytes. It has no magic,
header, nonce, or appended authentication tag. The nonce and key-wrap material
are in the authenticated `vault` object in `metadata.json`; the 16-byte content
authentication tag is in `content_tag`. Consequently, copying or parsing
`content.zsv2` without its exact metadata, entry ID, and correct device root is
unsupported.

AES-GCM preserves length, so the ciphertext file length MUST equal metadata
`size`, which is also the expected plaintext length. Empty plaintext is valid and
produces an empty content file plus a 16-byte tag.

The metadata file MUST be valid UTF-8 JSON, no larger than 262,144 bytes. The
current parser rejects duplicate object keys and non-finite JSON numbers. Writers
emit indented, key-sorted JSON followed by a newline, but cryptographic operations
use the canonical encoding in section 5 rather than those presentation bytes.

## 3. Device root

### 3.1 Record

`STATE/vault/keys/device-root.json` has exactly these fields:

```json
{
  "protected_key": "BASE64",
  "protection": "windows-dpapi-current-user",
  "schema": "zero.security.device-root.v1"
}
```

No extra or missing field is permitted. The decoded root key MUST be 32 bytes.

The two syntactically accepted protection values are:

- `windows-dpapi-current-user`: REQUIRED for the current Windows profile;
- `filesystem-0600-preview`: a non-Windows development preview only.

Windows readers MUST refuse `filesystem-0600-preview`. Non-Windows readers MUST
refuse a DPAPI record they cannot unseal. Filesystem mode `0600` is not equivalent
to an OS keystore and MUST NOT be marketed as production device-key sealing.

### 3.2 Windows DPAPI profile

On first authorised creation, the implementation generates 32 bytes with the OS
CSPRNG and calls CurrentUser DPAPI with:

- description: `Zero Security device root`;
- optional entropy bytes:
  `ZERO-SECURITY/DEVICE-ROOT/V1` followed by byte `00`;
- `CRYPTPROTECT_UI_FORBIDDEN` (`0x1`).

`protected_key` stores standard Base64 of the resulting opaque DPAPI blob. DPAPI
output is platform/profile-bound and may be nondeterministic; it MUST NOT be used
as a cross-platform golden vector.

An implementation MUST NOT create a missing device root while merely listing or
restoring entries. Creation is allowed only during an operation that is explicitly
authorised to create new protected content. Losing the Windows profile or root
record can make every entry under that state directory unrecoverable.

### 3.3 Threat boundary

DPAPI CurrentUser protects the root at rest against offline access outside that
user context. It does not stop malicious code already executing as the same user
from requesting unseal. ZSV2 does not claim resistance to a fully compromised
endpoint, administrator, debugger in the protected process, or plaintext theft
before quarantine/after restore.

## 4. Metadata schema

The top-level metadata object MUST contain exactly these 16 fields:

| Field | Type and current-profile meaning |
| --- | --- |
| `schema` | String; exact `zero.security.quarantine.v2` |
| `id` | String; lowercase canonical UUID equal to the entry directory |
| `state` | String; one of `copy_ready`, `copy_only`, `quarantined`, `restored` |
| `original_path` | String; absolute source path captured at quarantine time |
| `sha256` | String; 64 lowercase hexadecimal characters, digest of plaintext |
| `size` | Non-negative JSON integer; plaintext and ciphertext byte length |
| `original_mode` | Non-negative JSON integer; captured permission-mode bits |
| `original_modified_ns` | Non-negative JSON integer; captured modification time in nanoseconds |
| `created_at` | String; UTC timestamp ending `Z`, second precision for current writers |
| `quarantined_at` | `null` or UTC timestamp string; set after successful source removal |
| `restore_history` | Array of restore event objects; current writer retains the last 100 |
| `matches` | Array of detection-match objects captured from the verified finding |
| `zba` | Exact ZBA quarantine object from section 6 |
| `vault` | Exact vault-envelope object from section 7 |
| `content_tag` | Standard Base64 text decoding to exactly 16 bytes |
| `metadata_mac` | 64-character lowercase hexadecimal HMAC-SHA-256 |

Each current detection match written by the scanner has exactly these string
fields:

```json
{
  "description": "...",
  "id": "...",
  "kind": "sha256 or literal",
  "name": "...",
  "severity": "info, low, medium, high, or critical",
  "source": "..."
}
```

Each current restore-history item written by the application has exactly:

```json
{
  "destination": "ABSOLUTE PATH",
  "restored_at": "UTC TIMESTAMP ENDING Z"
}
```

The present Python reader verifies that `matches` and `restore_history` are
arrays, but does not yet fully validate every nested item or every timestamp/path
type at metadata-load time. Full nested shape, type, length, path, timestamp, and
integer-range validation is a production/interchange gate. Until that gate is
implemented and tested, metadata produced outside the reference writer MUST be
treated as untrusted even when its MAC verifies.

### 4.1 State meaning

- `copy_ready`: an authenticated encrypted recovery copy exists and source
  deletion has not been confirmed. It may remain after interruption.
- `copy_only`: the recovery copy exists but the original was not safely removed.
- `quarantined`: the recovery copy exists and the source was removed after an
  identity recheck.
- `restored`: at least one verified no-overwrite restore was published. The
  encrypted recovery copy is retained.

`state`, `quarantined_at`, and `restore_history` are mutable operational fields.
They are covered by the metadata MAC but deliberately excluded from content/key
AAD, allowing honest state updates without re-encrypting the file. This profile
has no independent monotonic counter or external rollback witness; an older
complete, valid metadata snapshot may therefore evade rollback detection. Do not
claim rollback-proof audit history from this profile alone.

## 5. Canonical JSON profile

The implementation's canonical byte function is:

```text
UTF8(JSON(value,
          ensure_ascii = false,
          allow_nan = false,
          separators = (",", ":"),
          sort_keys = true))
```

There is no whitespace outside JSON strings. Object keys are sorted as Python
string keys. Non-ASCII characters are emitted as UTF-8. NaN and infinities are
forbidden. The strict input parser also rejects duplicate keys.

This restricted encoding is stable for the current metadata domain, but it is
not declared byte-for-byte RFC 8785 JCS. Cross-language writers MUST use published
golden canonical bytes, constrain numbers to interoperable integers, and prove
that escaping/key sorting matches before claiming conformance. A later switch to
JCS or CBOR is a new profile, not a silent implementation change.

## 6. ZBA quarantine record

`zba` MUST contain exactly the following 16 fields:

| Field | Exact value or rule |
| --- | --- |
| `spec` | `zero.security.zba.quarantine.v1` |
| `asset_id` | Equal to entry `id` |
| `sequence` | Integer `0` |
| `operation` | `quarantine.encrypt` |
| `polarity` | `neutral` |
| `phase` | `boundary` |
| `recursion_depth` | Integer `0` |
| `policy_id` | `zero-security-quarantine` |
| `policy_version` | Integer `1` |
| `previous_commitment` | 64 lowercase zero characters |
| `payload_commitment` | Equal to top-level plaintext `sha256` |
| `event_time` | String ending `Z`; current writer copies `created_at` |
| `actor_id` | `local-device` |
| `evidence_status` | `sealed` |
| `commitment_algorithm` | `sha256` |
| `commitment` | 64 lowercase hexadecimal characters computed below |

Let `P` be the ZBA object with `commitment` removed. Let `PREV` be the 32 bytes
decoded from `previous_commitment`. Then:

```text
ZBA_DOMAIN = ASCII("ZERO-SECURITY/ZBA-QUARANTINE/V1") || 00
commitment = lowercase_hex(
    SHA256(ZBA_DOMAIN || PREV || canonical_json(P))
)
```

The current validator rejects an unknown/missing ZBA field, a changed fixed
value, a non-lowercase/malformed commitment, an invalid event-time suffix, or a
commitment mismatch.

This is a single typed boundary record, not a complete append-only ZBA 1.1 event
lineage. The ZBA record is included in content/key AAD and the whole metadata
object is MACed. AES-GCM/HKDF/HMAC/DPAPI—not ZBA notation—supply cryptographic
security.

## 7. Vault envelope

`vault` MUST contain exactly these nine string fields:

| Field | Exact value or decoded length |
| --- | --- |
| `format` | `ZSV2` |
| `profile` | `zero-security-quarantine-aes256gcm-v1` |
| `cipher` | `AES-256-GCM` |
| `key_derivation` | `HKDF-SHA-256` |
| `device_key_protection` | `windows-dpapi-current-user` or development-only `filesystem-0600-preview`; must match loaded root |
| `salt` | Standard Base64; 32 decoded bytes |
| `wrap_nonce` | Standard Base64; 12 decoded bytes |
| `wrapped_key` | Standard Base64; 48 decoded bytes (32 ciphertext + 16 GCM tag) |
| `content_nonce` | Standard Base64; 12 decoded bytes |

Writers MUST emit padded RFC 4648 standard Base64. The current reader uses strict
alphabet validation and exact decoded lengths. Before broad interchange, readers
SHOULD additionally reject any spelling that does not equal a decode/re-encode
round trip, thereby enforcing one canonical Base64 representation.

Unknown fields, algorithms, profiles, protection labels, or lengths MUST be
rejected. Algorithm agility is accomplished with a new reviewed profile and
migration, never by accepting a string supplied by the object and dispatching to
an unapproved algorithm.

## 8. AAD

The exact AAD object contains these ten top-level metadata fields:

```text
schema
id
original_path
sha256
size
original_mode
original_modified_ns
created_at
matches
zba
```

AAD bytes are `canonical_json(AAD_OBJECT)` using section 5. Although the Python
dictionary projection lists fields in the order above, canonical key sorting
determines the final byte order.

The identical AAD byte string MUST be used for:

1. AES-GCM wrapping of the content key; and
2. AES-GCM encryption of the content bytes.

Changing any AAD field must make both content-key unwrap and content
authentication fail. The vault envelope, content tag, state, quarantine time, and
restore history are excluded from AAD because they either are outputs of
encryption or are mutable. They are instead authenticated by the metadata MAC.

Visible AAD metadata is not encrypted. In particular, `original_path`, scanner
matches, size, time, and ZBA labels may reveal sensitive information to a reader
of the state directory. Future metadata-confidentiality work requires a new
profile and explicit searchable/index metadata; it must not silently encrypt
fields while retaining this identifier.

## 9. Key hierarchy and derivation

All randomly generated values MUST come from the operating system CSPRNG.

For each new entry, generate independently:

- `DEK`: 32-byte content-encryption key;
- `SALT`: 32-byte HKDF salt;
- `WRAP_NONCE`: 12-byte AES-GCM nonce;
- `CONTENT_NONCE`: 12-byte AES-GCM nonce.

Let `ROOT` be the 32-byte unsealed device root and `ENTRY_ASCII` be the canonical
UUID text encoded as ASCII.

```text
WRAP_INFO = ASCII("ZERO-SECURITY/ZSV2/KEY-WRAP/V1") || 00
WRAP_KEY = HKDF-SHA-256(
    input_key_material = ROOT,
    salt = SALT,
    info = WRAP_INFO || ENTRY_ASCII,
    output_length = 32
)

WRAPPED_KEY = AES-256-GCM-ENCRYPT(
    key = WRAP_KEY,
    nonce = WRAP_NONCE,
    plaintext = DEK,
    aad = AAD
)
```

`WRAPPED_KEY` is stored as the AEAD library's 48-byte `ciphertext || tag` output.
The entry ID in HKDF `info` prevents a wrapped key from being transplanted between
entry identities even if other metadata could be reproduced.

The current implementation uses a fresh DEK for every content object. GCM nonce
uniqueness remains a required independent invariant; ZBA labels or a metadata MAC
cannot repair nonce reuse. A writer MUST abort rather than intentionally reuse a
DEK/nonce pair. Random generation failure is fatal.

After use, Python variables holding DEK bytes are dropped, but immutable-language
runtime copies cannot be guaranteed wiped. Documentation MUST NOT claim verified
secure memory erasure.

## 10. Content encryption

Content is encrypted as one AES-256-GCM message with:

```text
key       = DEK
nonce     = CONTENT_NONCE
aad       = AAD
plaintext = exact source-file byte stream
```

The current implementation processes 1 MiB chunks but creates one logical GCM
message and one final 16-byte tag. It writes ciphertext only to `content.zsv2`,
flushes and fsyncs it, and stores the tag separately as `content_tag` in metadata.
Chunk size is an implementation detail and does not frame independent records.

Before publication, the writer computes SHA-256 over plaintext while encrypting
and MUST confirm it equals the verified scanner finding. It also checks the source
file's device, inode where meaningful, size, and modification time before and
after reading. The source MUST be a regular non-link, non-reparse file.

The writer publishes the authenticated encrypted entry directory before it tries
to remove the source. It MUST never delete the source merely because an
unauthenticated or partial copy exists. A changed source or removal failure
results in `copy_only` and a surfaced partial-success condition.

## 11. Metadata authentication

The metadata MAC key is derived once per device-root context:

```text
MAC_INFO = ASCII("ZERO-SECURITY/ZSV2/METADATA-MAC/V1") || 00
MAC_KEY = HKDF-SHA-256(
    input_key_material = ROOT,
    salt = absent/null HKDF salt,
    info = MAC_INFO,
    output_length = 32
)
```

Let `UNSIGNED` be the complete top-level metadata object with
`metadata_mac` removed. Then:

```text
metadata_mac = lowercase_hex(
    HMAC-SHA-256(MAC_KEY, canonical_json(UNSIGNED))
)
```

The MAC covers the schema, identity, mutable state, paths, digest/size, times,
restore history, matches, ZBA record, complete vault object, and content tag. It
does not cover the ciphertext bytes directly; the GCM tag covers ciphertext and
AAD.

A reader MUST compare the MAC in constant time. The current reader verifies the
metadata MAC before it parses/uses the envelope, tag, or ZBA object. Keeping this
order limits parser work on unauthenticated current-profile metadata. It does not
remove the need for bounded strict JSON parsing before the MAC can be located.

The MAC is symmetric and local: it does not prove which person or independently
trusted service created the entry. Anyone who controls the device root can create
valid metadata. There is no external signature, trusted time, transparency log,
or rollback witness in this profile.

## 12. Reader rejection requirements

A reader MUST fail closed and release no plaintext when any applicable check
fails. At minimum, reject:

1. an entry name that is not a canonical UUID;
2. missing, oversized, invalid-UTF-8, duplicate-key, non-object, or non-finite
   metadata JSON;
3. unsupported schema, or any extra/missing top-level metadata field;
4. metadata `id` not exactly equal to the entry directory;
5. malformed/non-lowercase SHA-256, negative/non-integer size, invalid state, or
   non-array matches/history;
6. an unavailable, malformed, wrong-platform, or wrong-length device root;
7. metadata-MAC type/length/authentication failure;
8. a non-object vault, extra/missing vault field, wrong format/profile/algorithm,
   unsupported protection, mismatched device protection, malformed Base64, or
   wrong decoded length;
9. a malformed or wrong-length content tag;
10. a non-object ZBA record, extra/missing field, wrong fixed value, ID/digest
    mismatch, malformed time/commitment, or commitment failure;
11. AAD canonicalization failure;
12. missing content, a link/reparse/special content object, or ciphertext length
    different from metadata size;
13. content-key unwrap authentication failure;
14. content GCM authentication failure, including wrong AAD/nonce/tag/key or
    modified/truncated/extended ciphertext;
15. decrypted plaintext SHA-256 or size different from metadata;
16. an existing/symlink restore target, unavailable/non-directory/reparse parent,
    or inability to publish with the required no-overwrite operation.

The current restore decrypts into a temporary file in the destination directory,
flushes and fsyncs it, verifies digest and size, applies the saved mode on a
best-effort basis, and uses a hard link as the no-overwrite publication primitive.
It rejects filesystems that cannot supply this operation. It never overwrites an
existing destination and retains the encrypted recovery copy.

Plaintext written to a temporary file before a late authentication failure MUST
be removed and never published. Crash-residue handling and verified secure
deletion of temporary plaintext are separate operational hardening requirements;
ordinary unlink is not a guarantee of media erasure.

## 13. Legacy and migration rules

### 13.1 Existing plaintext quarantine v1

The implementation retains read/restore support for legacy schema
`zsec.shield.quarantine.v1` with `content.bin`. That content is not encrypted and
has no ZSV2 vault, ZBA record, content tag, or metadata MAC. New writers MUST NOT
create it, callers MUST report it as `encrypted: false`, and its presence MUST NOT
be described as protected by ZSV2.

A future v1-to-ZSV2 migration MUST:

1. require an explicit migration operation and record the source entry identity;
2. validate the legacy exact field set, regular-file constraints, SHA-256, and
   size before treating bytes as input;
3. create a new canonical UUID, fresh DEK, salt, and nonces;
4. build fresh ZSV2 metadata/ZBA/AAD; never rename `content.bin` or relabel v1;
5. publish and read-back-verify the new authenticated entry before altering the
   legacy object;
6. retain the legacy object by default until the user approves a separately
   auditable deletion;
7. keep an external migration journal mapping old and new IDs.

The current exact v2 metadata field set has no `migration` extension field. A
migration tool must therefore keep its journal outside the v2 object until a new
schema explicitly defines an authenticated migration field.

### 13.2 Historical ZME1-family objects

Historical corpus formats bearing `ZME1`, `ZME1-AV`, or generic v1 labels MUST
use separate, exact source-profile identifiers. There is no generic ZME1
auto-detector and no byte-preserving ZME1-to-ZSV2 conversion.

An importer may be designed only when the exact source format, licence, KDF,
factor encoding, canonical header/AAD, authentication behavior, limits, and test
vectors are known. It MUST authenticate and decrypt with that source profile,
then re-encrypt verified plaintext as a new ZSV2 object with fresh randomness. It
MUST NOT guess among colliding shapes, accept unauthenticated metadata, downgrade
on failure, or reuse source keys/nonces.

Unknown legacy objects remain unsupported. A conversion failure leaves the source
untouched and produces no apparently valid ZSV2 entry.

### 13.3 Future ZSV profiles

Any incompatible change to canonicalization, metadata field set, AAD projection,
key derivation, nonce/tag placement, root protection, or content framing requires
a new profile and, when metadata shape changes, a new metadata schema. Readers
MUST dispatch only after exact identifier validation. Downgrade fallback is
forbidden after a current-profile authentication failure.

## 14. Golden-vector requirements

Before ZSV2 is declared portable or independently implementable, the repository
MUST publish immutable deterministic vectors generated without production keys.
DPAPI creation and `os.urandom` are intentionally nondeterministic, so vector
generation must inject fixed primitive inputs at a test-only boundary; production
randomness behavior must remain unchanged.

### 14.1 Positive vector set

At minimum, vectors MUST include:

- empty plaintext;
- a short ASCII plaintext;
- binary plaintext containing every byte value and embedded zero bytes;
- plaintext spanning more than one 1 MiB processing chunk;
- metadata containing non-ASCII but valid UTF-8 path/match text;
- at least two entries under one root to prove entry-ID and salt separation;
- state re-MAC examples for `copy_ready`, `copy_only`, `quarantined`, and
  `restored` without changing AAD-bound bytes.

Every positive vector MUST publish:

- suite/vector version and creation tool revision;
- fixed 32-byte root, 32-byte DEK, 32-byte salt, 12-byte wrap nonce, and 12-byte
  content nonce as lowercase hex **test values**;
- canonical entry UUID and complete logical metadata inputs;
- exact canonical ZBA projection bytes and commitment;
- exact canonical AAD bytes and SHA-256 of those bytes;
- HKDF `info`, derived wrap key, wrapped-key bytes, and decoded lengths;
- ciphertext bytes, detached content tag, and plaintext SHA-256/size;
- canonical unsigned-metadata bytes, derived metadata-MAC key, and metadata MAC;
- final `metadata.json` and `content.zsv2` fixture bytes;
- an explicit statement that all keys are public test fixtures and forbidden in
  production.

Publishing intermediate values is intentional: it locates interoperability
errors in canonicalization, HKDF, key wrapping, streaming GCM, or metadata MAC
without requiring guesswork.

At least two independent implementations in different language/runtime stacks
MUST reproduce every expected byte before the profile is called interoperable.
Round-trip success within one implementation is insufficient.

### 14.2 Negative vector set

Negative vectors MUST change one condition at a time and name the expected first
failure class. Include, at minimum:

- every top-level metadata field removed, added, duplicated, or type-changed;
- non-canonical/mismatched UUID, wrong schema, and each allowed-state violation;
- malformed, oversized, non-UTF-8, duplicate-key, NaN, and infinity JSON;
- every ZBA fixed field and commitment independently mutated;
- every AAD field independently mutated;
- every vault identifier mutated and every decoded length off by one;
- invalid/non-ASCII Base64, alternate/noncanonical Base64 spelling, and tag
  lengths 0, 15, and 17;
- wrong root, wrong entry ID, wrong salt, wrong wrap nonce, and wrapped-key bit
  flip;
- wrong content nonce, content-tag bit flip, and first/middle/last ciphertext bit
  flips;
- emptying, truncating, extending, replacing, linking, or reparsing content;
- plaintext hash and size mismatch after otherwise successful decryption;
- metadata rollback to an older valid MACed state, documented as **not detected**
  by this profile absent an independent checkpoint;
- pre-existing restore destination and destination-appears-during-restore race;
- wrong-platform root protection and unavailable device root;
- attempts to parse each known ZME1 collision as ZSV2, all rejected before any
  decryption attempt.

Negative suites MUST assert that no destination plaintext was published and that
source/legacy objects were not deleted on failure.

### 14.3 Vector stability

Vector files MUST have SHA-256 checksums in a signed release manifest. Changes to
expected cryptographic bytes require either correction of a documented vector
error or a new profile; they must not be regenerated casually after an
implementation change. Parser-only hardening may add negative vectors without
changing positive bytes.

## 15. Conformance statement

An implementation may claim **ZSV2 current-profile read conformance** only if it:

- enforces the exact identifiers and field sets;
- reproduces all positive cryptographic bytes;
- rejects all mandatory negative vectors without publishing plaintext;
- implements the platform/root-protection policy it claims;
- reports whether legacy v1 support is present and clearly labels it unencrypted;
- documents metadata visibility, endpoint-compromise limits, rollback limits,
  recovery requirements, and unsupported migration profiles.

Write conformance additionally requires CSPRNG generation, nonce discipline,
source identity/race checks, encrypted-copy-first publication, honest `copy_only`
handling, durable writes, and no source deletion before verified publication.

Restore conformance additionally requires metadata/key/content authentication,
post-decryption hash/size validation, temporary-file containment, no-overwrite
publication, and recovery-copy retention.

Passing these requirements establishes compatibility with this profile. It does
not by itself establish independent cryptographic review, malware-detection
efficacy, endpoint security, post-quantum security, secure deletion, or protection
against a compromised current-user context.
