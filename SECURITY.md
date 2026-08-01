# Security policy

Please report sensitive vulnerabilities privately through the maintainer contact
route linked from [talktoai.org/zsec](https://talktoai.org/zsec/). Do not include
passwords, API tokens, private signing keys, quarantine contents, or unredacted host
reports.

Useful reports include the ZSEC Shield version, operating system, exact command,
expected behavior, observed behavior, and a minimal non-sensitive reproducer.

Security invariants for this project:

- no AI or remote execution in the runtime;
- no command/action fields in feeds;
- no unsigned, expired, rolled-back, or schema-invalid feed rules;
- no implicit quarantine or overwrite restore;
- no “system is clean” claim from a limited scan;
- no secrets or private signing keys committed to the repository.

The MVP is alpha software. Test it on disposable data before relying on its recovery
workflow.

