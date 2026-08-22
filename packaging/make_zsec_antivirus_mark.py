"""Generate the deterministic raster master for ZSEC Antivirus packaging."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUI_ROOT = PROJECT_ROOT / "apps" / "windows-ui"
if str(GUI_ROOT) not in sys.path:
    sys.path.insert(0, str(GUI_ROOT))

from zsec_desktop.brand import render_mark  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "destination",
        nargs="?",
        type=Path,
        default=PROJECT_ROOT / "assets" / "brand" / "zsec-antivirus-mark.png",
    )
    args = parser.parse_args()
    destination = args.destination.resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    render_mark(1024).save(destination, format="PNG", optimize=False, compress_level=9)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
