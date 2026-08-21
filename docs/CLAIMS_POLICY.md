# Public claims policy

## Allowed for the current preview

- Open-source, deterministic, local, on-demand scanner.
- Foreground post-change protection or automatic file-event monitoring, when
  immediately qualified as user-mode, post-change, non-primary, and best effort;
  default detection only, with explicit polling fallback and incomplete failures.
- Source and self-contained command-line preview coverage on specifically
  identified Windows, macOS, and Linux artifact combinations.
- Signed data-only rule-feed verification.
- Automatic authenticated encryption for new quarantine entries when enabled by
  the shipped version and verified tests.
- Local browser ad/tracker rules with no browsing-data upload.
- Best-effort YouTube ad-interface cleanup.

## Prohibited without additional evidence

- "Complete antivirus", unqualified "real-time protection", pre-access blocking,
  or replacement of Microsoft
  Defender, Malwarebytes, XProtect, another antivirus, or an endpoint agent.
- "Desktop app" when the delivered product is a command-line archive, or broad
  Windows/macOS/Linux support without an exact OS/architecture/delivery matrix.
- Equivalent platform key protection while macOS or Linux uses
  `filesystem-0600-preview` rather than an approved production key store.
- Claims that XProtect, Gatekeeper, SIP, FileVault, Linux security updates,
  SELinux, AppArmor, Secure Boot, or other native controls can be disabled.
- "100% protection", "unhackable", "zero-day proof", or "stops all hackers".
- Detection-rate, false-positive, speed, or cache-size figures without a dated,
  reproducible benchmark.
- "Post-quantum encryption" unless a standardised and tested PQC profile is
  actually deployed.
- "Quantum encrypted" based only on a quantum-job record or evidence anchor.
- "No data collected" if update or diagnostic requests are present.
- "Better than Brave" without a published threat model and comparative test.

The current `replacement-readiness` result is a blocking contract. Marketing,
installers, support tools, and user interfaces may not convert its
`keep_existing_protection` decision into a dismissible warning or provider-removal
offer.

ZBA is described as a typed state/provenance calculus. Established authenticated
encryption, signatures, operating-system key protection, and release engineering
provide the security properties.
