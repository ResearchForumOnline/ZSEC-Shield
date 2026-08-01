# Threat model

## Assets and trust boundaries

ZSEC Shield protects the integrity of its local decisions, reports, feed cache, and
quarantine recovery objects. It treats scanned paths and downloaded feed bytes as
untrusted. The operator-controlled keyring and private local state directory are
trusted inputs; an attacker who can replace either can deny service. Feed private
keys never belong on the scanning host.

## Covered threats

- Known-file detection by exact SHA-256.
- Known byte-pattern detection with bounded literal signatures.
- A harmless EICAR test-file signal.
- Feed tampering, unknown signing keys, revoked/out-of-window keys, expired feeds,
  schema extension, duplicate JSON keys, non-canonical base64, rollback, and sequence
  reuse.
- Accidental recursion through symlinks, junctions/reparse points, devices, sockets,
  or a different mounted filesystem.
- Accidental destructive action: quarantine is opt-in, copy verification precedes
  removal, partial operations are explicit, and restore will not overwrite.

## Out of scope

- Zero-day and polymorphic detection, packed/encrypted content, archives and document
  internals, scripts requiring semantic analysis, behavioral detection, memory and
  process inspection, boot sectors, firmware, browser protection, email filtering,
  cloud reputation, and network traffic.
- Kernel-enforced or real-time protection. A process can change a path before or
  after an on-demand scan.
- Recovery after an attacker gains write access to both the state directory and
  trusted keyring.
- Availability against extremely deep, large, permission-hostile, or concurrently
  mutating trees. Limits and errors are reported rather than hidden.
- Authenticating rule quality. A valid signature proves which trusted key signed a
  payload, not that every detection rule is correct.

## Filesystem race handling

The scanner opens regular files without following links where the operating system
supports `O_NOFOLLOW`, compares file identity/size, streams bytes, and checks size and
modification time again. Windows reparse points are skipped. These checks reduce,
but cannot eliminate, time-of-check/time-of-use races in a hostile writable tree.

Quarantine reopens and rehashes the source into a private entry before removal. The
final name-based unlink still has a narrow race on general-purpose filesystems; do
not grant untrusted users write access to a directory while quarantining from it.

## Feed safety properties

Feed payloads are strict, signed data objects. Exact field allowlists prevent a feed
from becoming a remote command language. Valid rules can only compare an already
computed SHA-256 or search for a bounded literal byte sequence. They cannot execute
code or initiate side effects. Every use re-verifies the installed feed and its
rollback record. Any inconsistency disables all feed-derived rules.

