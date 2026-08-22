# ZSEC Browser local password vault

## Security boundary

The Community Windows browser vault is local-only. It does not sync credentials,
send secrets to TalkToAI, expose a localhost API, inject a host object into web
content, or log credential values. Its storage root is below the browser product
data root and is rejected if the vault or records directory is a reparse point.
Files are bounded, strictly shaped JSON containers whose sensitive values are
encrypted.

The automatic key hierarchy is:

1. Windows CSPRNG creates a 256-bit device key.
2. Windows DPAPI protects that key in `CurrentUser` scope with application-specific
   optional entropy. The stored DPAPI blob cannot be unprotected by another normal
   Windows account or by copying it to another Windows profile.
3. A separately generated 256-bit vault master key is wrapped with keys derived
   from the device key.
4. Each password record uses fresh random salt and IV. HKDF-SHA-256 derives
   independent AES-256-CBC and HMAC-SHA-256 keys from the master key. HMAC covers
   the domain label, salt, IV, and ciphertext and is verified in fixed-time before
   any decryption. This is encrypt-then-MAC with independent keys.

The two random key layers make rotation and future recovery-key support possible
without re-encrypting every password. DPAPI is the operating-system binding and
the vault master key is the data-encryption boundary. They are not claimed to be
two independent authentication factors: malware running as the unlocked Windows
user may invoke DPAPI and inspect browser memory.

## Threats addressed

- Offline theft or copying of browser product-data files.
- Accidental plaintext credential disclosure in browser state or logs.
- Ciphertext, IV, salt, record-ID, or authentication-tag tampering.
- Cross-record substitution through record-ID-specific domain separation.
- Path redirection through vault/record-directory reparse points.
- Biased password generation; random character selection uses rejection sampling
  and Fisher-Yates shuffling with the Windows CSPRNG.

## Threats not addressed

- Malware, debuggers, screen readers, or injected code running as the unlocked
  interactive user and able to inspect the browser process.
- Keyloggers, screen capture, clipboard monitoring, or a compromised page.
- A stolen unlocked Windows session.
- Windows account or DPAPI master-key compromise.
- Cloud sync, cross-device recovery, shared vaults, breach monitoring, or hardware
  token authentication. Those require separate reviewed protocols.

The service locks and clears its in-memory master-key byte array. Managed strings
returned to the UI cannot be reliably zeroized by .NET, so the UI must minimize
their lifetime, never log them, mask password controls, and clear the clipboard
using the existing timed clipboard policy.

## ZMath/ZBA role

`zmath_commitment` is a SHA-256 commitment over a domain-separated projection of
the encrypted record. It provides a stable provenance/boundary label for ZSEC
evidence. It is deliberately **not** used as a cipher, key-derivation function,
authentication tag, randomness source, or claim of cryptographic superiority.
AES, HMAC, HKDF, DPAPI, and the Windows CSPRNG provide the security properties.

## Integration API

`BrowserVaultService` implements `IVaultService` and is constructed with the
browser product-data root:

```csharp
IVaultService vault = new BrowserVaultService(productRoot);
vault.Unlock(); // initializes once, then uses DPAPI CurrentUser automatically
BrowserVaultEntry saved = vault.Save(entry);
IList<BrowserVaultEntry> matches = vault.Search("example");
vault.Lock();
```

`Unlock()` never accepts a web-originated value. `Save`, `Get`, `Search`, `Delete`,
and `GeneratePassword` are intended only for trusted native UI code. WebView2 host
objects and web messaging remain disabled; a webpage must never receive this
service reference.
