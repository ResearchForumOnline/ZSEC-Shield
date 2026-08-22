# ruff: noqa: F821, I001
"""Auditable PyInstaller onedir definition for the ZSEC Antivirus Windows GUI."""

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(SPECPATH).resolve().parent
GUI_ROOT = PROJECT_ROOT / "apps" / "windows-ui"
SOURCE_ROOT = PROJECT_ROOT / "src"
WINDOWS_VERSION_FILE = os.environ.get("ZSEC_GUI_WINDOWS_VERSION_FILE")
WINDOWS_ICON = os.environ.get("ZSEC_GUI_WINDOWS_ICON")

analysis = Analysis(
    [str(GUI_ROOT / "zsec_desktop" / "__main__.py")],
    pathex=[str(GUI_ROOT), str(SOURCE_ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "tkinter",
        "tkinter.filedialog",
        "tkinter.messagebox",
        "tkinter.ttk",
        "pystray._win32",
        "PIL.Image",
        "PIL.ImageDraw",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["ensurepip", "pydoc", "unittest", "venv"],
    noarchive=False,
    optimize=0,
)

python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="ZSEC Antivirus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=WINDOWS_VERSION_FILE if sys.platform == "win32" else None,
    icon=WINDOWS_ICON if sys.platform == "win32" else None,
)

distribution = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="zsec-antivirus-desktop",
)
