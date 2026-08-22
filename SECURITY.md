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

ZSEC Shield v0.1.2 is the latest formal GitHub prerelease. TalkToAI currently hosts
unsigned evaluation artifacts for ZSEC Antivirus 0.3 and ZSEC Browser Shields 0.4
from draft pull request #5. ZSEC Browser Community 0.3.0 is an unsigned source and
local-evidence build at revision `9b60c31d246a851a5dc325cf384fb529c2759a07`.
Test evaluation builds only with disposable data or browser profiles and keep
existing security controls active.
