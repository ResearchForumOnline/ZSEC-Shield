# Public claims policy

## Allowed for Community 0.3.11

- Open-source, deterministic, local, on-demand scanner.
- Foreground post-change protection or automatic file-event monitoring, when
  immediately qualified as user-mode, post-change, non-primary, and best effort;
  default detection only, with explicit polling fallback and incomplete failures.
- Reversible per-user Windows companion launch, when qualified as a limited-user
  Scheduled Task supervising the post-change mode—not a service or primary AV.
- Source and self-contained command-line coverage on specifically
  identified Windows, macOS, and Linux artifact combinations.
- Signed data-only rule-feed verification.
- Automatic authenticated encryption for new quarantine entries when enabled by
  the shipped version and verified tests.
- Local browser ad/tracker rules with no browsing-data upload.
- A Windows protection control plane that reports supported Windows Security
  Center and Microsoft Defender evidence and offers only fixed Defender
  intelligence-update, quick-scan and confirmed full-scan actions.
- “Microsoft Defender real-time enforcement verified” only when the strict live
  Defender contract confirms it; the statement must identify Defender—not
  ZSEC—as the enforcing provider.
- Bounded YouTube request, player-data and interface protection, immediately
  qualified as exact-host, best effort and not guaranteed against site changes.
- A Journalist high-risk preset, immediately qualified as exposure reduction:
  it disables new app-history recording, requests app-history clearing on clean
  exit, and enables the disclosed native strict and YouTube controls. It is not
  an ephemeral browser profile, spyware verdict or exploit guarantee.

## Prohibited without additional evidence

- "Complete antivirus", unqualified "real-time protection", ZSEC-native
  pre-access blocking, or representing ZSEC as the registered primary provider.
  A supported provider handoff may be described only as operator-cutover
  eligibility after the exact Defender/Windows Security gates pass; the current
  ZSEC UI does not remove Microsoft Defender, Malwarebytes, XProtect, another
  antivirus, or an endpoint agent.
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
offer. That native-ZSEC gate is separate from the Windows control plane's
provider-handoff interlock: an eligible handoff means Microsoft Defender can
remain the supported real-time provider, not that ZSEC has become one.

ZBA is described as a typed state/provenance calculus. Established authenticated
encryption, signatures, operating-system key protection, and release engineering
provide the security properties.
