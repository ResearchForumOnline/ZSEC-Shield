"""Generate deterministic base-scale Microsoft Store package logo assets."""

from __future__ import annotations

import hashlib
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
PRODUCTS = {
    "antivirus": ROOT / "assets" / "brand" / "zsec-antivirus-mark.png",
    "browser": ROOT / "assets" / "brand" / "zeroq-icon.png",
}
SIZES = {
    "Square44x44Logo.png": 44,
    "StoreLogo.png": 50,
    "Square150x150Logo.png": 150,
}


def generate() -> None:
    for product, source_path in PRODUCTS.items():
        with Image.open(source_path) as opened:
            source = opened.convert("RGBA")
        if source.width != source.height:
            raise ValueError(f"Store logo source must be square: {source_path}")
        destination = Path(__file__).resolve().parent / "assets" / product
        destination.mkdir(parents=True, exist_ok=True)
        for filename, size in SIZES.items():
            # Keep a 10% transparent safe area so Windows never clips the mark.
            mark_size = max(1, round(size * 0.8))
            mark = source.resize((mark_size, mark_size), Image.Resampling.LANCZOS)
            canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            offset = ((size - mark_size) // 2, (size - mark_size) // 2)
            canvas.alpha_composite(mark, offset)
            output = destination / filename
            canvas.save(output, format="PNG", optimize=False, compress_level=9)
            digest = hashlib.sha256(output.read_bytes()).hexdigest()
            print(f"{output.relative_to(ROOT).as_posix()} {size}x{size} {digest}")


if __name__ == "__main__":
    generate()
