# Security policy

Please report sensitive vulnerabilities privately through the repository's
[security policy](https://github.com/ResearchForumOnline/ZSEC-Shield/security/policy).
Do not include passwords, API tokens, private signing keys, quarantine contents, or
unredacted host reports.

Useful reports include the ZSEC Shield version, operating system, exact command,
expected behavior, observed behavior, and a minimal non-sensitive reproducer.

Security invariants for this project:

- no AI or remote execution in the runtime;
- no command/action fields in feeds;
- no unsigned, expired, rolled-back, or schema-invalid feed rules;
- no implicit quarantine or overwrite restore;
- no “system is clean” claim from a limited scan;
- no secrets or private signing keys committed to the repository.

Community 0.3.12 source covers the cross-platform ZSEC Shield core, the Windows ZSEC
Antivirus control plane, and ZSEC Browser Community. Browser Shields Community
0.5.2 remains separately versioned. All ZSEC desktop and native Community binaries
are unsigned: a version name, tag, adjacent checksum, or passing workflow alone is
not publisher identity or release acceptance. Verify the exact published revision,
artifact SHA-256, manifest, and platform/runtime evidence on the authenticated
release page. Test with disposable data or browser profiles and keep an operating-
system or supported endpoint protection provider active.
