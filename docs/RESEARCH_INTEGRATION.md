# Research integration policy

Status: implementation-aligned design record, 21 August 2026.

This document records what the Zero Security Suite may reuse from the reviewed
ZSEC, ZMath, ZBA, ZeroThink, CallChat Shield, OpenZero, browser/privacy, and
antivirus research corpus. It is a provenance and engineering boundary, not a
claim that every researched idea is present in the product or has passed an
independent security assessment.

The current integration rule is deliberately conservative:

- use reviewed, standard cryptography for security properties;
- use Zero Boundary Algebra (ZBA) only for typed lifecycle and provenance;
- keep incompatible historical formats in explicitly named legacy profiles;
- copy code only when its licence and provenance permit it;
- keep research-credit and provider-restricted work out of commercial products;
- fail closed on unknown schemas, profiles, algorithms, or critical fields.

## 1. Accepted architecture

The current public core has three distinct layers. They must not be collapsed in
documentation, code, or marketing.

| Layer | Current responsibility | Security boundary |
| --- | --- | --- |
| ZBA quarantine profile | Typed boundary state, asset identity, policy label, payload commitment, and a deterministic record commitment | Does not encrypt, derive keys, establish entropy, or supply post-quantum security |
| ZSV2 quarantine profile | Automatic device-bound key handling, authenticated encryption, authenticated metadata, and safe restore framing | AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, OS randomness, and Windows DPAPI |
| Quarantine workflow | Source identity checks, encrypted-copy-first publication, fail-closed removal, no-overwrite restore, and digest/size verification | Filesystem safety, atomic publication, strict parsing, and recovery-copy retention |

On Windows, routine quarantine is automatic. A random 256-bit device root is
sealed for the current Windows user with DPAPI. Every quarantined object receives
a fresh random 256-bit content-encryption key, per-entry salt, key-wrap nonce,
and content nonce. No routine password or recovery-key prompt is required.

The resulting convenience has a defined limit: code executing as the same
Windows user may be able to ask DPAPI to unseal the root. ZSV2 protects stored
quarantine material and detects unauthorised modification; it is not a defence
against a fully compromised logged-in endpoint.

The byte-level ZSV2 profile, including framing, metadata, AAD, key wrapping,
rejection, migration, and vector requirements, is specified in
[`../specs/ZSV2.md`](../specs/ZSV2.md).

## 2. ZBA 1.1 integration

The reviewed ZBA 1.1 paper defines a typed state calculus. Its directional-zero
symbols are tagged workflow states, not extra real numbers and not cryptographic
primitives. Wire values must therefore be descriptive strings. The current
quarantine profile uses `"boundary"` and `"neutral"`; it never serialises a
phase as numeric `-0`, `0`, or `+0`.

ZBA contributes the following ideas to the suite:

- distinct typed fields for asset, operation, polarity, boundary phase,
  recursion depth, policy, predecessor, payload commitment, actor, and evidence
  status;
- a deterministic, domain-separated commitment over a restricted canonical JSON
  projection;
- fail-closed validation of the exact profile field set;
- inclusion of the ZBA record in the AEAD additional authenticated data (AAD),
  so relabelling it breaks content-key unwrap and content authentication;
- a vocabulary for future append-only lifecycle evidence.

ZBA does **not** contribute a cipher, KDF, random-number generator, key store,
signature algorithm, quantum key, malware detector, or endpoint isolation
mechanism. The numerals and modulo-9 mirror mnemonic have no cryptographic
strength. Security claims must name the established primitive and implementation
that supplies the property.

The implementation in `src/zsec_shield/zba.py` is a minimal, single boundary
record for a quarantine object. It is not the complete ZBA 1.1 transition chain:
it fixes sequence `0`, a zero predecessor, `quarantine.encrypt`, neutral polarity,
boundary phase, and sealed evidence. Later quarantine state and restore-history
changes are authenticated by the ZSV2 metadata MAC, not appended as ZBA lineage.
The product must not claim full ZBA lifecycle-chain conformance until an explicit
transition log, policy verifier, rollback control, vectors, and conformance report
exist.

The paper is licensed CC BY 4.0 and its reference artifacts are identified as
MIT-licensed. Any direct reuse must preserve the applicable attribution and
notices. This repository paraphrases the concepts and implements its own narrow
quarantine profile; it must not silently relicense copied paper text or artifacts.

## 3. Research-corpus decisions

The local corpus is evidence and design input, not one homogeneously licensed
codebase. The following decisions apply before any further import.

| Corpus component | Reusable result | Integration status |
| --- | --- | --- |
| ZSEC scanner/feed repository | Deterministic local scanning, signed data-only feeds, no remote commands, local package-manager authority | Suitable donor where its Apache-2.0 provenance is retained and the imported revision is recorded |
| ZBA 1.1 paper and reference artifacts | Typed state/provenance vocabulary, commitment discipline, negative-vector model | Use under CC BY 4.0 / MIT as applicable; maintain the crypto boundary above |
| CallChat ZShield | PBKDF2/HKDF/AES-GCM composition, authenticated canonical headers, bounds, and tamper tests | Design evidence only until the exact source file's licence and provenance are recorded; its container is not ZSV2 |
| ZMath automatic protection | Local automatic-key UX, non-exportable browser keys, recovery setup, and self-test concepts | Design evidence only; browser storage and Windows DPAPI have different threat models |
| OpenZero browser extension | Manifest V3 permission/consent patterns, bounded actions, local rules | Design evidence only while its audited snapshot has no reusable public licence; it is not a browser distribution or antivirus engine |
| ZSEC ANTIVIRUS draft | Product concepts, screens, naming prompts, and research notes | No security implementation is inherited; stubs or mockups must not become product claims |
| ZeroThink legacy protected files | Migration evidence and examples of why custom stream constructions need scrutiny | Read-only legacy compatibility, if ever required; do not use the bespoke counter-stream construction for new encryption |
| QPU/quantum-factor experiments | Research evidence about provenance binding and factor separation | Excluded from commercial product inputs and claims under the restriction in section 6 |

Before copying a source file, record its origin repository, exact revision or
SHA-256, author, licence, modifications, and required notices. An absent licence
is not permission to publish or relicense the code. Independently reimplementing
an idea still requires a security review and must avoid copying protected
expression.

## 4. Canonical format naming

The corpus contains multiple incompatible formats using the name `ZME1` or a
generic version `1`. At least the following shapes were observed:

1. a CallChat Shield object with a nested header containing format, version,
   profile, payload, KDF, and cipher fields;
2. a ZMath object with top-level format, version, mode, metadata, exclusive, and
   ciphertext fields;
3. an antivirus draft with `header.magic` equal to `ZME1-AV` and separate crypto,
   payload, provenance, and integrity objects.

These formats are not aliases and must never be selected by filename extension,
the token `ZME1`, or a loose `version == 1` check.

`ZSV2` is the canonical namespace for the current suite's encrypted quarantine
profile. A valid object requires all three identifiers:

- metadata schema `zero.security.quarantine.v2`;
- vault format `ZSV2`;
- vault profile `zero-security-quarantine-aes256gcm-v1`.

The `content.zsv2` file is raw ciphertext, not a self-describing standalone
container. Its authenticated `metadata.json`, matching entry directory, and
device-root context are mandatory. New incompatible formats require a new schema
and profile. A parser must not guess.

## 5. Automatic protection and recovery

Automation is a product requirement, but it cannot erase recovery and consent
boundaries.

- Routine local quarantine may create and use the DPAPI-sealed device root
  without asking the user to handle key material.
- The original is removed only after the encrypted, authenticated recovery copy
  is durably published. Failure leaves an honest `copy_only` record.
- Restore authenticates metadata, key wrap, ciphertext, plaintext digest, and
  size before a no-overwrite destination is published.
- The encrypted recovery copy remains after restore.
- Device loss, Windows-profile loss, DPAPI reset, or unrecoverable root-key
  deletion can make all ZSV2 entries unrecoverable. The UI and backup guidance
  must say so before a production release.

An optional YubiKey/passkey route is a future recovery mechanism, not part of the
current ZSV2 profile. It should wrap a distinct recovery key or a copy of the
device root; it must not replace per-entry randomness, expose the raw root in the
UI, store a PIN, or require a physical touch for every automatic quarantine.
Enrollment, a recovery self-test, revocation, replacement, and an offline recovery
code policy are release gates. WebAuthn PRF support must be tested on the actual
browser/authenticator matrix before it is promised.

## 6. IonQ and externally restricted research

The audited research record contains a written non-commercial boundary around
relevant IonQ/QPU credits, results, and outputs. Zero Security is intended for
public and commercial use, so the suite must exclude that material unless and
until the rights holder supplies explicit written commercial permission.

The exclusion covers, at minimum:

- provider-funded or credit-funded job outputs and measurement results;
- derived QPU factors, seeds, lookup tables, fixtures, and benchmark numbers;
- provider job identifiers or circuit evidence used as a product trust signal;
- model or algorithm tuning derived from restricted results;
- marketing that names the provider, implies endorsement, or describes the
  commercial product as provider-backed or quantum-encrypted.

This does not prevent use of independently authored ZBA concepts under their
published licence, standard cryptographic primitives, local CSPRNG output, or
future quantum-safe standards implemented from appropriately licensed public
specifications. It prevents restricted research outputs from entering commercial
code, tests, data, services, or claims.

Any future exception requires a provenance memo containing the written
permission, permitted fields of use, attribution wording, commercial scope,
expiry, publication terms, and the exact artifacts released from quarantine.

## 7. Open-core and licensing boundary

This repository is Apache-2.0 open core. Anything described as open source must
ship with source that recipients can inspect, modify, and redistribute under its
licence. “Open source but not viewable or editable” is contradictory and must not
appear in product copy.

The public core includes the scanner, data-only feed format and verifier, ZSV2
quarantine and ZBA profile, browser extension/rules that are actually released,
tests, threat models, and reproducible packaging. A useful offline/local product
must remain available without a commercial account.

Separately licensed components may include OEM engines/signatures, managed
reputation and sync services, enterprise fleet controls, customer-support systems,
and production signing/HSM infrastructure. These must be separate modules or
services with truthful licences and explicit APIs. They may not silently weaken
local protection, bypass consent, introduce feed-driven commands, or make the
open core unusable.

Obfuscation, minification, native compilation, and code scrambling are not
security boundaries. Official binaries are distinguished through publisher
signatures, reproducible build evidence, update metadata, and trademarks—not by
claiming that shipped client code cannot be inspected.

Secrets, signing roots, HSM credentials, server authorisation policy, abuse
controls, and private customer data do not belong in a public repository or a
distributed client. Their confidentiality is compatible with an open-source
client because they are operational secrets, not hidden client logic.

## 8. Browser and product claim boundary

Research can support a privacy/security extension now and a maintained Chromium
distribution later. It does not yet support calling the extension a new browser
engine, saying it is “better than Brave,” promising universal YouTube ad blocking,
or claiming that it stops hackers.

A future browser distribution must preserve Chromium sandboxing and Site
Isolation, merge upstream security fixes on a measured emergency cadence, publish
third-party notices, use signed reproducible updates, avoid restricted Chrome
services and artwork, and measure rule efficacy. It must not install a TLS root
certificate or intercept HTTPS merely to block ads. YouTube and other anti-adblock
sites require best-effort, frequently tested language.

Security claims are versioned evidence statements. Unit tests, EICAR handling,
or a successful feature demonstration establish only the tested path. Claims of
malware efficacy, real-time antivirus protection, phishing prevention, privacy,
or browser performance require a disclosed corpus, methodology, date, build,
comparison baseline, and limitations.

## 9. Integration and release gates

No research-derived security component is production-ready merely because it is
novel, automated, or visually polished. The following gates apply:

1. **Provenance:** origin, exact revision/hash, licence, and modifications are
   recorded; restricted provider outputs are absent.
2. **Specification:** schema, profile, algorithms, byte encoding, AAD, limits,
   failure behavior, and downgrade handling are frozen.
3. **Vectors:** deterministic positive and negative golden vectors pass in at
   least two independent implementations before interchange is claimed.
4. **Key lifecycle:** creation, sealing, backup, recovery, rotation, compromise,
   device migration, and destruction behavior is documented and tested.
5. **Parser safety:** duplicate keys, non-finite numbers, unknown fields, invalid
   Unicode, over-limit values, malformed Base64, and unsupported algorithms fail
   closed.
6. **Filesystem safety:** links/reparse points, source races, partial writes,
   deletion failure, destination races, permissions, and crash recovery are
   exercised on supported Windows filesystems.
7. **Independent review:** the cryptographic construction and Windows threat
   model receive external review before high-assurance claims.
8. **Supply chain:** dependencies/builds are pinned; SBOM, SHA-256 manifest,
   publisher signature, signed update metadata, rollback protection, and an
   emergency revocation path exist.
9. **Recovery drill:** a fresh machine/profile restore is demonstrated using the
   documented recovery mechanism without exposing the raw root.
10. **Claims:** the release page states exactly what is on-demand, best effort,
    preview-only, externally licensed, or not yet shipped.

## 10. Source-of-truth mapping

| Requirement | Current source of truth |
| --- | --- |
| ZSV2 constants, device root, HKDF, AES-GCM key wrap, metadata HMAC, DPAPI | `src/zsec_shield/crypto_vault.py` |
| Entry framing, AAD projection, content encryption, strict metadata field set, restore | `src/zsec_shield/quarantine.py` |
| ZBA quarantine record and commitment | `src/zsec_shield/zba.py` |
| Restricted canonical JSON and strict JSON parsing | `src/zsec_shield/util.py` |
| Public/private module boundary | `OPEN_CORE.md` |
| Product scope and unsupported claims | `docs/PRODUCT_ARCHITECTURE.md` and `docs/CLAIMS_POLICY.md` |
| Recovery design status | `docs/YUBIKEY_RECOVERY.md` |
| Normative interchange and migration requirements | `specs/ZSV2.md` |

Where this document and code differ, the discrepancy is a release blocker. Do not
silently change a deployed format to make the prose true; revise the schema or
profile, publish migration notes and vectors, and preserve the previous reader.
