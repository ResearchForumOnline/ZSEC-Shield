# ZSEC Browser Shields threat model

## Protected properties

- Block configured ad/tracker requests before they reach the network.
- Keep settings and per-site exceptions local.
- Keep remote rule data from becoming an executable-code channel.
- Provide an obvious breakage escape hatch.

## Non-goals

- Perfect ad blocking on every site or every YouTube experiment.
- Malware scanning, phishing verdicts, exploit prevention, anonymity, or VPN.
- Protection after the browser, extension process, profile, or operating system
  has been compromised.

## Controls

- Manifest V3 declarative rules and packaged content code only.
- No `eval`, dynamic functions, remote scripts, TLS interception, or affiliate
  rewriting.
- Bounded, normalized domain exceptions rebuilt as explicit allow rules.
- Minimal storage and no product-controlled network endpoint.
- Static validation and deterministic unit tests.

An extension update can change code and permissions, so official releases must
be signed by the store or platform, reviewed, reproducibly packaged where
practical, and accompanied by source and a component manifest.
