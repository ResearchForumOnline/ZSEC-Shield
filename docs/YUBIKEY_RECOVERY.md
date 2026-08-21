# YubiKey and passkey recovery design

Status: designed, not yet shipped in the preview.

Zero Security should remain automatic during everyday use while still providing
a recovery path when a Windows profile or device is lost. A YubiKey option is a
recovery factor, not a replacement for file encryption or an excuse to keep no
backup.

## Intended flows

### Automatic local use

- Routine encrypt/restore uses a device root protected by the operating system.
- No password, PIN, or physical touch is requested for every scan.
- The application never stores a reusable YubiKey PIN.

### Enrol recovery key

- The user explicitly starts enrolment and sees which device/account is being
  protected.
- Prefer a FIDO2/WebAuthn authenticator supporting the PRF extension when the
  deployed platform support matrix is verified.
- Derive a wrapping key using a domain-separated context and random salt.
- Wrap, but never expose, the device recovery key.
- Produce two independently stored recovery records and immediately run a
  non-destructive recovery self-test.

### Recover

- Require physical authenticator presence and local user verification where
  available.
- Authenticate the recovery manifest, unwrap into protected process memory, and
  re-seal a new device root to the new operating-system profile.
- Append a ZBA recovery transition; retain the prior lineage and device
  revocation record.

## Alternative for managed deployments

YubiKey PIV can wrap a recovery key using an organisation-managed certificate.
That profile needs certificate lifecycle, revocation, backup, and administrator
separation. It is not interchangeable with consumer passkeys.

## Required gates

- Tested authenticator capability detection and clear unsupported-device errors.
- Lost-key and revoked-key drills.
- No silent cloud account recovery.
- No raw private key or recovery secret in logs, telemetry, crash dumps, or UI.
- Recovery metadata covered by authenticated encryption/signatures.
- Two-person approval for enterprise escrow export.
