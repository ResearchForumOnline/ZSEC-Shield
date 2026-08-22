"""Deterministic small-size ZSEC Antivirus brand rendering."""

from __future__ import annotations

from typing import Any


def render_mark(size: int = 64) -> Any:
    """Render the geometric mark with supersampling for crisp tray/title icons."""

    if not 16 <= size <= 1024:
        raise ValueError("brand mark size must be between 16 and 1024 pixels")
    from PIL import Image, ImageDraw

    scale = 4
    canvas = size * scale
    image = Image.new("RGBA", (canvas, canvas), (8, 17, 31, 255))
    draw = ImageDraw.Draw(image)

    def points(values: tuple[tuple[float, float], ...]) -> list[tuple[int, int]]:
        return [(round(x * canvas), round(y * canvas)) for x, y in values]

    radius = round(canvas * 0.22)
    draw.rounded_rectangle(
        (0, 0, canvas - 1, canvas - 1),
        radius=radius,
        fill=(8, 17, 31, 255),
    )
    shield = points(
        ((0.50, 0.10), (0.83, 0.23), (0.83, 0.47), (0.78, 0.64),
         (0.67, 0.78), (0.50, 0.90), (0.33, 0.78), (0.22, 0.64),
         (0.17, 0.47), (0.17, 0.23))
    )
    draw.polygon(shield, fill=(16, 37, 56, 255))
    draw.line(
        [*shield, shield[0]],
        fill=(46, 100, 112, 255),
        width=max(2, canvas // 32),
        joint="curve",
    )
    zed = points(
        ((0.31, 0.30), (0.70, 0.30), (0.70, 0.41), (0.48, 0.61),
         (0.71, 0.61), (0.71, 0.73), (0.29, 0.73), (0.29, 0.62),
         (0.52, 0.41), (0.31, 0.41))
    )
    draw.polygon(zed, fill=(53, 228, 207, 255))
    return image.resize((size, size), Image.Resampling.LANCZOS)


__all__ = ["render_mark"]
