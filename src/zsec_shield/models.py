"""Typed, serializable models used by the scanner and feed verifier."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
RuleKind = Literal["sha256", "literal"]

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    name: str
    kind: RuleKind
    severity: Severity
    description: str
    source: str
    digest: str | None = None
    literal: bytes | None = None

    def public_dict(self) -> dict[str, str]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "kind": self.kind,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class RuleMatch:
    rule_id: str
    name: str
    kind: RuleKind
    severity: Severity
    description: str
    source: str

    @classmethod
    def from_rule(cls, rule: Rule) -> RuleMatch:
        return cls(
            rule_id=rule.rule_id,
            name=rule.name,
            kind=rule.kind,
            severity=rule.severity,
            description=rule.description,
            source=rule.source,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "kind": self.kind,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
        }


@dataclass(slots=True)
class FileFinding:
    path: str
    sha256: str
    size: int
    modified_at: str
    severity: Severity
    matches: list[RuleMatch]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "modified_at": self.modified_at,
            "severity": self.severity,
            "matches": [match.to_dict() for match in self.matches],
        }


@dataclass(frozen=True, slots=True)
class ScanIssue:
    path: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


@dataclass(slots=True)
class ScanStats:
    roots_requested: int = 0
    files_hashed: int = 0
    bytes_hashed: int = 0
    findings: int = 0
    errors: int = 0
    skipped_symlinks: int = 0
    skipped_special: int = 0
    skipped_too_large: int = 0
    skipped_filesystems: int = 0
    skipped_excluded: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "roots_requested": self.roots_requested,
            "files_hashed": self.files_hashed,
            "bytes_hashed": self.bytes_hashed,
            "findings": self.findings,
            "errors": self.errors,
            "skipped_symlinks": self.skipped_symlinks,
            "skipped_special": self.skipped_special,
            "skipped_too_large": self.skipped_too_large,
            "skipped_filesystems": self.skipped_filesystems,
            "skipped_excluded": self.skipped_excluded,
        }


@dataclass(slots=True)
class ScanResult:
    started_at: str
    completed_at: str
    roots: list[str]
    findings: list[FileFinding] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "roots": self.roots,
            "findings": [finding.to_dict() for finding in self.findings],
            "issues": [issue.to_dict() for issue in self.issues],
            "stats": self.stats.to_dict(),
        }
