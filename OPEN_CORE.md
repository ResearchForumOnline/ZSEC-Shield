# Zero Security open-core boundary

Zero Security is an **open-core** security programme. The public repository is
auditable and modifiable under Apache-2.0. Optional commercial services and
licensed integrations may be distributed separately under different terms.

## Public and auditable

- ZSEC Shield deterministic on-demand scanner.
- Signed, data-only detection feed format and verifier.
- Automated encrypted quarantine format and ZBA lifecycle records.
- Zero Browser privacy extension, local blocking rules, and source.
- Threat models, privacy contracts, test fixtures, reproducible packaging, and
  update-verification specifications.

## Separately licensed or private

- Third-party OEM antimalware engines and their proprietary signatures.
- Production signing infrastructure, offline root keys, HSM policy, and release
  credentials.
- Managed reputation, encrypted sync, enterprise fleet administration, and
  customer-support systems.
- Future real-time Windows service/minifilter components until their source,
  certification, and release model are ready for public review.

Private modules are not described as open source. Minification, compilation, or
obfuscation may raise reverse-engineering cost, but none is treated as a security
boundary. Keys and server-side authorisation remain outside distributed clients.

The public core must remain useful without a commercial account. A closed module
cannot silently weaken the scanner, bypass user consent, enable remote commands,
or make an unsupported protection claim.
