from __future__ import annotations

import importlib.util
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "packaging" / "windows-store" / "validate_screenshots.py"
SPEC = importlib.util.spec_from_file_location("zsec_store_screenshots", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
screenshots = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = screenshots
SPEC.loader.exec_module(screenshots)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(width: int = 1366, height: int = 768, *, colour: int = 2, extra: bytes = b"") -> bytes:
    channels = 3 if colour == 2 else 4
    scanline = b"\x00" + (b"\x23\x45\x67\xff"[:channels] * width)
    return b"".join(
        [
            screenshots.PNG_SIGNATURE,
            _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, colour, 0, 0, 0)),
            extra,
            _chunk(b"IDAT", zlib.compress(scanline * height)),
            _chunk(b"IEND", b""),
        ]
    )


def _fixture(tmp_path: Path, product: str) -> dict[str, Path | str]:
    listing = ROOT / "packaging" / "windows-store" / "listings" / screenshots.LISTING_NAMES[product]
    plan = screenshots.load_plan(product, listing)
    capture_dir = tmp_path / product
    capture_dir.mkdir()
    for shot in plan["shots"]:
        (capture_dir / shot["filename"]).write_bytes(_png())
    package = tmp_path / f"ZSEC-{product}.msix"
    package.write_bytes(b"exact store candidate")
    executable = tmp_path / screenshots.EXECUTABLE_NAMES[product]
    executable.write_bytes(b"exact packaged executable")
    return {
        "product": product,
        "screenshot_directory": capture_dir,
        "listing_path": listing,
        "package_path": package,
        "executable_path": executable,
        "captured_at": "2026-08-25T12:00:00Z",
    }


def _build(args: dict[str, Path | str]) -> dict[str, object]:
    return screenshots.build_manifest(
        **args,
        synthetic_state_only=True,
        reviewed_no_personal_data=True,
        no_taskbar_or_other_apps=True,
        no_composited_overlays=True,
    )


@pytest.mark.parametrize("product", ["antivirus", "browser"])
def test_manifest_round_trip_binds_exact_inputs(tmp_path: Path, product: str) -> None:
    args = _fixture(tmp_path, product)
    manifest = _build(args)
    manifest_path = Path(args["screenshot_directory"]) / screenshots.MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    validated = screenshots.validate_manifest(
        manifest_path=manifest_path,
        product=product,
        screenshot_directory=Path(args["screenshot_directory"]),
        listing_path=Path(args["listing_path"]),
        package_path=Path(args["package_path"]),
        executable_path=Path(args["executable_path"]),
    )
    assert validated == manifest
    assert validated["capture"] == {
        "environment": "clean-windows-vm",
        "captured_at": "2026-08-25T12:00:00Z",
        "display_scale_percent": 100,
        "synthetic_state_only": True,
        "personal_data_reviewed": True,
        "taskbar_or_other_apps_visible": False,
        "composited_overlays": False,
    }
    serialized = json.dumps(validated)
    assert str(tmp_path) not in serialized
    assert [item["id"] for item in validated["screenshots"]] == [
        shot["id"] for shot in screenshots.load_plan(product, Path(args["listing_path"]))["shots"]
    ]


def test_missing_or_extra_png_is_rejected(tmp_path: Path) -> None:
    args = _fixture(tmp_path, "antivirus")
    capture_dir = Path(args["screenshot_directory"])
    (capture_dir / "01-overview.png").unlink()
    (capture_dir / "wrong.png").write_bytes(_png())
    with pytest.raises(screenshots.ScreenshotValidationError, match="filenames differ"):
        _build(args)


@pytest.mark.parametrize(
    ("image", "message"),
    [
        (_png(width=1365), "at least 1366x768"),
        (_png(colour=6), "8-bit RGB"),
        (_png(extra=_chunk(b"tEXt", b"user\x00private")), "text metadata"),
        (_png(extra=_chunk(b"acTL", struct.pack(">II", 1, 0))), "animated PNG"),
    ],
)
def test_unsafe_png_structures_are_rejected(tmp_path: Path, image: bytes, message: str) -> None:
    args = _fixture(tmp_path, "browser")
    capture_dir = Path(args["screenshot_directory"])
    (capture_dir / "01-new-tab.png").write_bytes(image)
    with pytest.raises(screenshots.ScreenshotValidationError, match=message):
        _build(args)


def test_package_or_executable_change_invalidates_manifest(tmp_path: Path) -> None:
    args = _fixture(tmp_path, "browser")
    manifest = _build(args)
    manifest_path = Path(args["screenshot_directory"]) / screenshots.MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    Path(args["package_path"]).write_bytes(b"different package")
    with pytest.raises(screenshots.ScreenshotValidationError, match="differs"):
        screenshots.validate_manifest(
            manifest_path=manifest_path,
            product="browser",
            screenshot_directory=Path(args["screenshot_directory"]),
            listing_path=Path(args["listing_path"]),
            package_path=Path(args["package_path"]),
            executable_path=Path(args["executable_path"]),
        )


def test_all_human_attestations_are_mandatory(tmp_path: Path) -> None:
    args = _fixture(tmp_path, "antivirus")
    with pytest.raises(screenshots.ScreenshotValidationError, match="all clean-capture"):
        screenshots.build_manifest(
            **args,
            synthetic_state_only=True,
            reviewed_no_personal_data=False,
            no_taskbar_or_other_apps=True,
            no_composited_overlays=True,
        )


def test_capture_timestamp_must_be_a_real_utc_date(tmp_path: Path) -> None:
    args = _fixture(tmp_path, "antivirus")
    args["captured_at"] = "2026-99-25T12:00:00Z"
    with pytest.raises(screenshots.ScreenshotValidationError, match="valid UTC timestamp"):
        _build(args)
