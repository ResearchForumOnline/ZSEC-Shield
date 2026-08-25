"""Create and verify evidence manifests for Microsoft Store screenshots.

This tool deliberately does not capture, crop, redact, or otherwise edit images.
It validates exact clean-VM captures and binds them to the package and executable
that were used for the capture. Human review for visible personal data and truthful
on-screen state remains a required gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import zlib
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = "zsec.windows-store-screenshots.v1"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_DECODED_SIZE = 512 * 1024 * 1024
MINIMUM_WIDTH = 1366
MINIMUM_HEIGHT = 768
MANIFEST_NAME = "capture-manifest.json"
LISTING_NAMES = {
    "antivirus": "zsec-antivirus.en-US.json",
    "browser": "zsec-browser.en-US.json",
}
EXECUTABLE_NAMES = {
    "antivirus": "ZSEC Antivirus.exe",
    "browser": "ZSEC Browser.exe",
}
FORBIDDEN_PNG_CHUNKS = {
    b"acTL": "animated PNG control",
    b"fcTL": "animated PNG frame control",
    b"fdAT": "animated PNG frame data",
    b"tEXt": "text metadata",
    b"zTXt": "compressed text metadata",
    b"iTXt": "international text metadata",
    b"eXIf": "EXIF metadata",
    b"tRNS": "transparency metadata",
}
UTC_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
HEX_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class ScreenshotValidationError(RuntimeError):
    """A screenshot provenance or image invariant failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScreenshotValidationError(f"could not read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise ScreenshotValidationError(f"{label} root must be an object")
    return value


def _require_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise ScreenshotValidationError(f"{label} is not a file: {path}")
    return path


def load_plan(product: str, listing_path: Path) -> dict[str, Any]:
    if product not in LISTING_NAMES:
        raise ScreenshotValidationError(f"unsupported product: {product!r}")
    listing = _read_json(_require_file(listing_path, "listing"), "listing")
    if listing.get("product_key") != product:
        raise ScreenshotValidationError("listing product_key differs from requested product")
    version = listing.get("source_version")
    if not isinstance(version, str) or not version:
        raise ScreenshotValidationError("listing source_version must be non-empty text")
    screenshots = listing.get("screenshots")
    if not isinstance(screenshots, dict):
        raise ScreenshotValidationError("listing screenshots must be an object")
    if screenshots.get("format") != "PNG" or screenshots.get("device_family") != "Desktop":
        raise ScreenshotValidationError("listing must define Desktop PNG screenshots")
    if screenshots.get("minimum_dimensions") != [MINIMUM_WIDTH, MINIMUM_HEIGHT]:
        raise ScreenshotValidationError("listing screenshot minimum must be exactly 1366x768")
    if screenshots.get("max_file_size_mb") != 50:
        raise ScreenshotValidationError("listing screenshot size limit must be exactly 50 MB")
    shots = screenshots.get("shots")
    if not isinstance(shots, list) or len(shots) != 5:
        raise ScreenshotValidationError("listing must contain the reviewed five-shot plan")
    identifiers: list[str] = []
    for shot in shots:
        if not isinstance(shot, dict) or not isinstance(shot.get("id"), str):
            raise ScreenshotValidationError("every screenshot plan entry must have a text id")
        identifier = shot["id"]
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identifier):
            raise ScreenshotValidationError(f"unsafe screenshot id: {identifier!r}")
        if identifier in identifiers:
            raise ScreenshotValidationError("screenshot ids must be unique")
        identifiers.append(identifier)
    return {
        "product": product,
        "source_version": version,
        "shots": [
            {"id": identifier, "filename": f"{index:02d}-{identifier}.png"}
            for index, identifier in enumerate(identifiers, start=1)
        ],
    }


def _chunks(data: bytes, path: Path) -> Iterable[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ScreenshotValidationError(f"not a PNG file: {path.name}")
    offset = len(PNG_SIGNATURE)
    saw_iend = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ScreenshotValidationError(f"truncated PNG chunk header: {path.name}")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(data):
            raise ScreenshotValidationError(f"truncated PNG chunk: {path.name}")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : chunk_end])[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ScreenshotValidationError(f"PNG chunk CRC mismatch: {path.name}")
        if saw_iend:
            raise ScreenshotValidationError(f"PNG contains data after IEND: {path.name}")
        yield chunk_type, payload
        offset = chunk_end
        if chunk_type == b"IEND":
            saw_iend = True
            if offset != len(data):
                raise ScreenshotValidationError(f"PNG contains trailing data: {path.name}")
    if not saw_iend:
        raise ScreenshotValidationError(f"PNG has no IEND chunk: {path.name}")


def inspect_png(path: Path) -> dict[str, int | str]:
    _require_file(path, "screenshot")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ScreenshotValidationError(f"screenshot exceeds 50 MiB: {path.name}")
    data = path.read_bytes()
    parsed = list(_chunks(data, path))
    if not parsed or parsed[0][0] != b"IHDR" or parsed[-1][0] != b"IEND":
        raise ScreenshotValidationError(f"PNG chunk order is invalid: {path.name}")
    if sum(chunk_type == b"IHDR" for chunk_type, _ in parsed) != 1:
        raise ScreenshotValidationError(f"PNG must contain one IHDR: {path.name}")
    if sum(chunk_type == b"IEND" for chunk_type, _ in parsed) != 1:
        raise ScreenshotValidationError(f"PNG must contain one IEND: {path.name}")
    ihdr = parsed[0][1]
    if len(ihdr) != 13:
        raise ScreenshotValidationError(f"invalid IHDR length: {path.name}")
    width, height, depth, colour, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", ihdr
    )
    if width < MINIMUM_WIDTH or height < MINIMUM_HEIGHT:
        raise ScreenshotValidationError(
            f"screenshot must be at least 1366x768: {path.name} is {width}x{height}"
        )
    if (depth, colour, compression, filtering, interlace) != (8, 2, 0, 0, 0):
        raise ScreenshotValidationError(
            f"screenshot must be a static, non-interlaced 8-bit RGB PNG: {path.name}"
        )
    for chunk_type, _ in parsed:
        if chunk_type in FORBIDDEN_PNG_CHUNKS:
            reason = FORBIDDEN_PNG_CHUNKS[chunk_type]
            raise ScreenshotValidationError(f"PNG contains forbidden {reason}: {path.name}")
    idat_parts = [payload for chunk_type, payload in parsed if chunk_type == b"IDAT"]
    if not idat_parts:
        raise ScreenshotValidationError(f"PNG has no image data: {path.name}")
    expected_size = height * (1 + width * 3)
    if expected_size > MAX_DECODED_SIZE:
        raise ScreenshotValidationError(f"PNG decoded size is unreasonably large: {path.name}")
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(b"".join(idat_parts), expected_size + 1)
        if len(raw) > expected_size or decompressor.unconsumed_tail:
            raise ScreenshotValidationError(f"PNG image data is too long: {path.name}")
        raw += decompressor.flush()
    except zlib.error as exc:
        raise ScreenshotValidationError(f"PNG image data cannot be decoded: {path.name}") from exc
    if len(raw) != expected_size or decompressor.unused_data or not decompressor.eof:
        raise ScreenshotValidationError(f"PNG image data length is invalid: {path.name}")
    stride = 1 + width * 3
    if any(raw[offset] > 4 for offset in range(0, len(raw), stride)):
        raise ScreenshotValidationError(f"PNG uses an invalid row filter: {path.name}")
    return {
        "filename": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "width": width,
        "height": height,
        "file_size": size,
    }


def inspect_screenshots(directory: Path, plan: dict[str, Any]) -> list[dict[str, Any]]:
    if not directory.is_dir():
        raise ScreenshotValidationError(f"screenshot directory does not exist: {directory}")
    expected = [shot["filename"] for shot in plan["shots"]]
    actual = sorted(path.name for path in directory.iterdir() if path.suffix.lower() == ".png")
    if actual != sorted(expected):
        raise ScreenshotValidationError(
            f"PNG filenames differ from the reviewed plan; expected {expected}, found {actual}"
        )
    evidence: list[dict[str, Any]] = []
    for shot in plan["shots"]:
        details = inspect_png(directory / shot["filename"])
        evidence.append({"id": shot["id"], **details})
    return evidence


def build_manifest(
    *,
    product: str,
    screenshot_directory: Path,
    listing_path: Path,
    package_path: Path,
    executable_path: Path,
    captured_at: str,
    synthetic_state_only: bool,
    reviewed_no_personal_data: bool,
    no_taskbar_or_other_apps: bool,
    no_composited_overlays: bool,
) -> dict[str, Any]:
    attestations = {
        "synthetic_state_only": synthetic_state_only,
        "personal_data_reviewed": reviewed_no_personal_data,
        "taskbar_or_other_apps_visible": not no_taskbar_or_other_apps,
        "composited_overlays": not no_composited_overlays,
    }
    if attestations != {
        "synthetic_state_only": True,
        "personal_data_reviewed": True,
        "taskbar_or_other_apps_visible": False,
        "composited_overlays": False,
    }:
        raise ScreenshotValidationError("all clean-capture attestations must be explicitly true")
    if not UTC_TIMESTAMP.fullmatch(captured_at):
        raise ScreenshotValidationError("captured_at must use UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(captured_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ScreenshotValidationError("captured_at is not a valid UTC timestamp") from exc
    plan = load_plan(product, listing_path)
    package = _require_file(package_path, "Store package")
    executable = _require_file(executable_path, "packaged executable")
    if package.suffix.lower() not in {".msix", ".msixbundle"}:
        raise ScreenshotValidationError("Store package must be an MSIX or MSIX bundle")
    expected_executable = EXECUTABLE_NAMES[product]
    if executable.name != expected_executable:
        raise ScreenshotValidationError(
            f"packaged executable must be named {expected_executable!r}"
        )
    screenshots = inspect_screenshots(screenshot_directory, plan)
    return {
        "schema": SCHEMA,
        "product": product,
        "source_version": plan["source_version"],
        "listing": {"filename": listing_path.name, "sha256": sha256_file(listing_path)},
        "package": {"filename": package.name, "sha256": sha256_file(package)},
        "executable": {"filename": executable.name, "sha256": sha256_file(executable)},
        "capture": {
            "environment": "clean-windows-vm",
            "captured_at": captured_at,
            "display_scale_percent": 100,
            **attestations,
        },
        "screenshots": screenshots,
    }


def validate_manifest(
    *,
    manifest_path: Path,
    product: str,
    screenshot_directory: Path,
    listing_path: Path,
    package_path: Path,
    executable_path: Path,
) -> dict[str, Any]:
    manifest = _read_json(_require_file(manifest_path, "capture manifest"), "capture manifest")
    capture = manifest.get("capture")
    if not isinstance(capture, dict):
        raise ScreenshotValidationError("capture manifest has no capture object")
    expected = build_manifest(
        product=product,
        screenshot_directory=screenshot_directory,
        listing_path=listing_path,
        package_path=package_path,
        executable_path=executable_path,
        captured_at=capture.get("captured_at", ""),
        synthetic_state_only=capture.get("synthetic_state_only") is True,
        reviewed_no_personal_data=capture.get("personal_data_reviewed") is True,
        no_taskbar_or_other_apps=capture.get("taskbar_or_other_apps_visible") is False,
        no_composited_overlays=capture.get("composited_overlays") is False,
    )
    if manifest != expected:
        raise ScreenshotValidationError(
            "capture manifest differs from the current files, listing plan, or fixed contract"
        )
    for section in ("listing", "package", "executable"):
        digest = manifest[section].get("sha256")
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            raise ScreenshotValidationError(f"invalid {section} SHA-256")
    return manifest


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--product", required=True, choices=sorted(LISTING_NAMES))
    parser.add_argument("--screenshots", required=True, type=Path)
    parser.add_argument("--listing", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create a manifest after human review")
    _common_arguments(create)
    create.add_argument("--captured-at", required=True)
    create.add_argument("--synthetic-state-only", action="store_true")
    create.add_argument("--reviewed-no-personal-data", action="store_true")
    create.add_argument("--no-taskbar-or-other-apps", action="store_true")
    create.add_argument("--no-composited-overlays", action="store_true")
    create.add_argument("--output", type=Path)
    validate = subparsers.add_parser("validate", help="validate a manifest and its exact inputs")
    _common_arguments(validate)
    validate.add_argument("--manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "create":
        manifest = build_manifest(
            product=args.product,
            screenshot_directory=args.screenshots,
            listing_path=args.listing,
            package_path=args.package,
            executable_path=args.executable,
            captured_at=args.captured_at,
            synthetic_state_only=args.synthetic_state_only,
            reviewed_no_personal_data=args.reviewed_no_personal_data,
            no_taskbar_or_other_apps=args.no_taskbar_or_other_apps,
            no_composited_overlays=args.no_composited_overlays,
        )
        output = args.output or args.screenshots / MANIFEST_NAME
        output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        manifest = validate_manifest(
            manifest_path=args.manifest,
            product=args.product,
            screenshot_directory=args.screenshots,
            listing_path=args.listing,
            package_path=args.package,
            executable_path=args.executable,
        )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ScreenshotValidationError, ValueError) as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        raise SystemExit(2) from exc
