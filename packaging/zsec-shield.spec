"""Auditable PyInstaller onedir definition for the ZSEC Shield CLI."""

from pathlib import Path
import os
import sys


PROJECT_ROOT = Path(SPECPATH).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"
WINDOWS_VERSION_FILE = os.environ.get("ZSEC_SHIELD_WINDOWS_VERSION_FILE")

analysis = Analysis(
    [str(SOURCE_ROOT / "zsec_shield" / "__main__.py")],
    pathex=[str(SOURCE_ROOT)],
    binaries=[],
    datas=[
        (
            str(SOURCE_ROOT / "zsec_shield" / "data" / "trusted_keys.json"),
            "zsec_shield/data",
        )
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["ensurepip", "pydoc", "tkinter", "unittest", "venv"],
    noarchive=False,
    optimize=0,
)

python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="zsec-shield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=WINDOWS_VERSION_FILE if sys.platform == "win32" else None,
)

distribution = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="zsec-shield",
)
