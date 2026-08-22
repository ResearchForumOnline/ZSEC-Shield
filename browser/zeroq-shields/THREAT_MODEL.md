# ZSEC Browser Shields threat model

## Protected properties

- Block configured ad/tracker requests before they reach the network.
- Keep settings and per-site exceptions local.
- Keep remote rule data from becoming an executable-code channel.
- Provide an obvious breakage escape hatch.
- When explicitly selected, reduce two documented exploit-delivery surfaces:
  plaintext navigation and third-party active web content.

## Non-goals

- Perfect ad blocking on every site or every YouTube experiment.
- Malware scanning, phishing verdicts, zero-day immunity, anonymity, or VPN.
- Proving that a permitted first-party or non-blocked resource is benign.
- Protection after the browser, extension process, profile, or operating system
  has been compromised.

## Controls

- Manifest V3 declarative rules and packaged content code only.
- No `eval`, dynamic functions, remote scripts, TLS interception, or affiliate
  rewriting.
- Bounded, normalized domain exceptions rebuilt as explicit allow rules.
- An opt-in two-rule High-Risk Browsing profile. Its priority exceeds site-pause
  allows and it accepts no remote inputs or domain verdicts.
- Minimal storage and no product-controlled network endpoint.
- Static validation and deterministic unit tests.

High-Risk Browsing may reduce exposure but cannot inspect or repair Chromium,
the operating system, or content already executing in a renderer. A successful
rule update proves only that the local policy was installed, not that every
future exploit path is blocked.

An extension update can change code and permissions, so official releases must
be signed by the store or platform, reviewed, reproducibly packaged where
practical, and accompanied by source and a component manifest.
