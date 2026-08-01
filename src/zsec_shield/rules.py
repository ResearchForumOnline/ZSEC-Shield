"""Built-in signatures and rule helpers."""

from __future__ import annotations

from collections.abc import Iterable

from zsec_shield.models import SEVERITY_RANK, Rule, Severity


def builtin_rules() -> tuple[Rule, ...]:
    # Split deliberately so the harmless EICAR test string is not stored as one
    # contiguous source-code token. It is assembled only by the scanner process.
    eicar = b"".join(
        (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EIC",
            b"AR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
    )
    return (
        Rule(
            rule_id="builtin:eicar-test-file",
            name="EICAR antivirus test file",
            kind="literal",
            severity="high",
            description="Harmless industry-standard antivirus test pattern; not malware.",
            source="ZSEC Shield built-in",
            literal=eicar,
        ),
        Rule(
            rule_id="builtin:eicar-test-file-sha256",
            name="EICAR antivirus test file SHA-256",
            kind="sha256",
            severity="high",
            description="Exact SHA-256 of the canonical EICAR test file; not malware.",
            source="ZSEC Shield built-in",
            digest="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ),
    )


def highest_severity(values: Iterable[Severity]) -> Severity:
    return max(values, key=lambda value: SEVERITY_RANK[value], default="info")
