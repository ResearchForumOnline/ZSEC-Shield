"""Bounded, review-only content inspection providers.

These providers run inside the existing path-free content worker. They parse no
more than a small in-memory copy, never extract archives, never execute content,
and return observations that are ineligible for automatic quarantine.
"""

from __future__ import annotations

import io
import math
import re
import struct
import zipfile
from collections import Counter
from typing import Any

MAX_INSPECTION_BYTES = 16 * 1024 * 1024
MAX_OBSERVATIONS = 32
MAX_ARCHIVE_ENTRIES = 4096
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_RATIO = 1000


def _observation(
    provider: str,
    category: str,
    severity: str,
    summary: str,
    **evidence: str | int | bool,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "category": category,
        "severity": severity,
        "summary": summary[:300],
        "evidence": evidence,
        "quarantine_eligible": False,
    }


def _entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def inspect_pe(value: bytes, declared_size: int) -> list[dict[str, Any]]:
    if len(value) < 64 or value[:2] != b"MZ":
        return []
    try:
        pe_offset = struct.unpack_from("<I", value, 0x3C)[0]
        if pe_offset > len(value) - 24 or value[pe_offset : pe_offset + 4] != b"PE\0\0":
            return [_observation("pe", "malformed_pe", "medium", "Malformed PE header")]
        header = struct.unpack_from("<HHIIIHH", value, pe_offset + 4)
        machine, section_count, timestamp, _, _, optional_size, characteristics = header
        if section_count < 1 or section_count > 96:
            return [
                _observation(
                    "pe",
                    "malformed_pe",
                    "medium",
                    "PE section count is outside the bounded policy",
                    section_count=section_count,
                )
            ]
        optional = pe_offset + 24
        section_table = optional + optional_size
        if section_table + section_count * 40 > len(value):
            return [
                _observation(
                    "pe",
                    "analysis_limited",
                    "info",
                    "PE metadata extends beyond the bounded inspection window",
                )
            ]
        magic = struct.unpack_from("<H", value, optional)[0] if optional_size >= 2 else 0
        is_pe32_plus = magic == 0x20B
        directory_count_offset = optional + (108 if is_pe32_plus else 92)
        directory_offset = optional + (112 if is_pe32_plus else 96)
        certificate_present = False
        minimum_optional = 128 if is_pe32_plus else 112
        if optional_size >= minimum_optional and directory_count_offset + 4 <= len(value):
            directory_count = struct.unpack_from("<I", value, directory_count_offset)[0]
            security_entry = directory_offset + 4 * 8
            if directory_count > 4 and security_entry + 8 <= optional + optional_size:
                certificate_offset, certificate_size = struct.unpack_from(
                    "<II", value, security_entry
                )
                certificate_present = (
                    certificate_offset > 0
                    and certificate_size >= 8
                    and certificate_offset + certificate_size <= declared_size
                )
        wx_sections: list[str] = []
        high_entropy_sections: list[str] = []
        for index in range(section_count):
            offset = section_table + index * 40
            raw_name = value[offset : offset + 8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")[:16] or f"section-{index}"
            raw_size, raw_offset = struct.unpack_from("<II", value, offset + 16)
            flags = struct.unpack_from("<I", value, offset + 36)[0]
            if flags & 0x20000000 and flags & 0x80000000:
                wx_sections.append(name)
            if raw_size and raw_offset < len(value):
                sample = value[raw_offset : min(raw_offset + raw_size, len(value))]
                if len(sample) >= 4096 and _entropy(sample) >= 7.6:
                    high_entropy_sections.append(name)
        observations = [
            _observation(
                "pe",
                "metadata",
                "info",
                "Portable Executable metadata inspected",
                machine=f"0x{machine:04x}",
                sections=section_count,
                timestamp=timestamp,
                characteristics=f"0x{characteristics:04x}",
                certificate_table_present=certificate_present,
            )
        ]
        if wx_sections:
            observations.append(
                _observation(
                    "pe",
                    "writable_executable_sections",
                    "medium",
                    "PE contains writable and executable sections",
                    sections=",".join(wx_sections[:8]),
                )
            )
        if high_entropy_sections:
            observations.append(
                _observation(
                    "pe",
                    "high_entropy_sections",
                    "low",
                    "PE contains high-entropy section data; packed or compressed "
                    "content is possible",
                    sections=",".join(high_entropy_sections[:8]),
                )
            )
        return observations
    except (IndexError, struct.error, ValueError):
        return [_observation("pe", "malformed_pe", "medium", "Malformed PE metadata")]


_DOWNLOAD = re.compile(
    rb"(?:downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|urlmon|http://|https://)",
    re.IGNORECASE,
)
_EXECUTE = re.compile(
    rb"(?:invoke-expression|\biex\b|start-process|wscript\.shell|shell\.application|rundll32|regsvr32)",
    re.IGNORECASE,
)
_ENCODED = re.compile(rb"(?:-enc(?:odedcommand)?\b|frombase64string)", re.IGNORECASE)
_INJECTION = re.compile(
    rb"(?:virtualalloc(?:ex)?|writeprocessmemory|createremotethread|ntunmapviewofsection)",
    re.IGNORECASE,
)


def inspect_script(value: bytes) -> list[dict[str, Any]]:
    sample = value[: 1024 * 1024]
    if b"\0" in sample[:4096] and not sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return []
    lowered = sample.lower()
    language_markers = sum(
        marker in lowered
        for marker in (b"powershell", b"param(", b"#!/bin/", b"function ", b"createobject(")
    )
    if language_markers == 0:
        return []
    observations: list[dict[str, Any]] = []
    if _DOWNLOAD.search(sample) and _EXECUTE.search(sample):
        observations.append(
            _observation(
                "script",
                "download_execute_chain",
                "high",
                "Script combines network retrieval with an execution primitive",
            )
        )
    if _ENCODED.search(sample) and (b"powershell" in lowered or b"frombase64string" in lowered):
        observations.append(
            _observation(
                "script",
                "encoded_execution",
                "medium",
                "Script contains encoded-command or Base64 execution indicators",
            )
        )
    injection_hits = {match.group(0).lower() for match in _INJECTION.finditer(sample)}
    if len(injection_hits) >= 2:
        observations.append(
            _observation(
                "script",
                "process_injection_primitives",
                "high",
                "Script references multiple process-injection primitives",
                primitive_count=len(injection_hits),
            )
        )
    return observations


def inspect_zip(value: bytes, declared_size: int) -> list[dict[str, Any]]:
    if not value.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return []
    if declared_size > MAX_INSPECTION_BYTES:
        return [
            _observation(
                "archive",
                "analysis_limited",
                "info",
                "ZIP exceeds the bounded in-memory metadata inspection limit",
                declared_size=declared_size,
                inspection_limit=MAX_INSPECTION_BYTES,
            )
        ]
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            entries = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        return [
            _observation(
                "archive",
                "malformed_archive",
                "medium",
                "ZIP metadata could not be parsed safely",
                error=type(exc).__name__,
            )
        ]
    total_uncompressed = sum(max(0, entry.file_size) for entry in entries)
    total_compressed = sum(max(0, entry.compress_size) for entry in entries)
    encrypted = sum(bool(entry.flag_bits & 1) for entry in entries)
    traversal = 0
    nested = 0
    extreme_entry = 0
    extreme_ratio = 0
    for entry in entries:
        normalized = entry.filename.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if (
            normalized.startswith(("/", "\\"))
            or (len(normalized) >= 2 and normalized[1] == ":")
            or any(part == ".." for part in parts)
        ):
            traversal += 1
        if normalized.lower().endswith((".zip", ".jar", ".docx", ".xlsx", ".pptx")):
            nested += 1
        if entry.file_size > MAX_ARCHIVE_ENTRY_BYTES:
            extreme_entry += 1
        ratio = entry.file_size / max(1, entry.compress_size)
        if entry.file_size >= 10 * 1024 * 1024 and ratio > MAX_ARCHIVE_RATIO:
            extreme_ratio += 1
    observations = [
        _observation(
            "archive",
            "metadata",
            "info",
            "ZIP central-directory metadata inspected without extraction",
            entries=len(entries),
            total_compressed=total_compressed,
            total_uncompressed=total_uncompressed,
            encrypted_entries=encrypted,
            nested_archives=nested,
        )
    ]
    if traversal:
        observations.append(
            _observation(
                "archive",
                "path_traversal",
                "high",
                "Archive contains absolute or parent-traversal paths",
                affected_entries=traversal,
            )
        )
    if (
        len(entries) > MAX_ARCHIVE_ENTRIES
        or total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES
        or extreme_entry
        or extreme_ratio
    ):
        observations.append(
            _observation(
                "archive",
                "expansion_risk",
                "high",
                "Archive metadata exceeds bounded extraction-safety thresholds",
                entries=len(entries),
                extreme_entries=extreme_entry,
                extreme_ratios=extreme_ratio,
                total_uncompressed=total_uncompressed,
            )
        )
    if encrypted:
        observations.append(
            _observation(
                "archive",
                "encrypted_entries",
                "low",
                "Archive contains encrypted entries that were not content-inspected",
                encrypted_entries=encrypted,
            )
        )
    return observations


def inspect_content(value: bytes, declared_size: int) -> list[dict[str, Any]]:
    observations = [
        *inspect_pe(value, declared_size),
        *inspect_script(value),
        *inspect_zip(value, declared_size),
    ]
    return observations[:MAX_OBSERVATIONS]
