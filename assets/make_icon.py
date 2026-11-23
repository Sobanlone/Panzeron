"""Regenerates assets/panzeron.ico and the web favicon (requires Pillow + NumPy).

The icon is the Panzeron dragon (assets/dragon-source.png) in ember red on the dark rounded tile, lit by a soft orb glow.
Small sizes (16/24/32 px) are drawn separately with a bigger dragon and no glow detail so the silhouette stays readable.
Usage: python assets/make_icon.py            (run from the project folder)
"""
from __future__ import annotations
import io
import math
import struct
from pathlib import Path

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "dragon-source.png"
ICO, FAVICON = ROOT / "assets" / "panzeron.ico", ROOT / "panzeron" / "web" / "favicon.png"
BASE = 1024                                    # master canvas; every size is downsampled from this
SIZES = [256, 128, 64, 48, 32, 24, 16]


def dragon_mask() -> Image.Image:
    """Soft alpha mask of the dragon, cropped tight (same extraction as make_dragon.py)."""
    rgb = np.asarray(Image.open(SRC).convert("RGB")).astype(float)
    bg = np.median(rgb[:40, :40].reshape(-1, 3), axis=0)[1]
    ink = np.percentile(rgb[..., 1][rgb[..., 1] < 60], 50)
    a = np.clip((bg - rgb[..., 1]) / (bg - ink), 0, 1)
    a[a < 0.04] = 0
    ys, xs = np.where(a > 0.02)
    m = Image.fromarray((a * 255).astype("uint8"), "L").crop((xs.min(), ys.min(), xs.max() + 1, ys.max() + 1))
    return m


def vertical_gradient(size, top, bottom) -> Image.Image:
    g = np.linspace(0, 1, size[1])[:, None, None]
    arr = np.array(top)[None, None, :] * (1 - g) + np.array(bottom)[None, None, :] * g
    arr = np.repeat(arr, size[0], axis=1).astype("uint8")
    return Image.fromarray(arr, "RGB")


def tile(S: int, mask: Image.Image, fill: float, glow: bool) -> Image.Image:
    """One icon at S x S. `fill` = dragon's long side as a fraction of the tile."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    rad = round(S * 0.23)
    plate = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(plate).rounded_rectangle([0, 0, S - 1, S - 1], radius=rad, fill=(9, 10, 16, 255))
    img = Image.alpha_composite(img, plate)

    # soft crimson / blue light behind the dragon (the "orb")
    if glow:
        lights = Image.new("RGBA", (S, S), (0, 0, 0, 0)); d = ImageDraw.Draw(lights)
        c = S / 2; R = S * 0.36
        d.ellipse([c - R, c - R, c + R, c + R], fill=(196, 30, 40, 120))
        d.ellipse([c - R * 1.1, c - R * 1.25, c + R * 0.2, c - R * 0.1], fill=(10, 132, 255, 70))
        lights = lights.filter(ImageFilter.GaussianBlur(S * 0.09))
        lights.putalpha(ImageChops.multiply(lights.getchannel("A"), plate.getchannel("A")))
        img = Image.alpha_composite(img, lights)
        ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(ring).ellipse([c - R, c - R, c + R, c + R], outline=(255, 255, 255, 38), width=max(1, S // 170))
        img = Image.alpha_composite(img, ring.filter(ImageFilter.GaussianBlur(0.6)))

    # the dragon: bright ember at the head, deeper red at the tail
    scale = S * fill / max(mask.size)
    m = mask.resize((max(1, round(mask.width * scale)), max(1, round(mask.height * scale))), Image.LANCZOS)
    colour = vertical_gradient(m.size, (255, 92, 70), (205, 14, 28)).convert("RGBA")
    colour.putalpha(m)
    pos = ((S - m.width) // 2, (S - m.height) // 2)
    if glow:                                       # faint red halo so the dragon lifts off the tile
        halo = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        h = Image.new("RGBA", m.size, (255, 40, 40, 255)); h.putalpha(m.point(lambda v: int(v * .55)))
        halo.paste(h, pos)
        img = Image.alpha_composite(img, halo.filter(ImageFilter.GaussianBlur(S * 0.022)))
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0)); layer.paste(colour, pos)
    img = Image.alpha_composite(img, layer)

    # thin bright rim on the tile edge (glass feel) — only where it will survive downsampling
    if S >= 256:
        rim = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(rim).rounded_rectangle([1, 1, S - 2, S - 2], radius=rad, outline=(255, 255, 255, 34), width=max(2, S // 256))
        img = Image.alpha_composite(img, rim)
    return img


def render(size: int, mask: Image.Image) -> Image.Image:
    small = size <= 32
    big = tile(BASE if not small else 512, mask, fill=0.90 if small else 0.80, glow=not small)
    out = big.resize((size, size), Image.LANCZOS)
    if size <= 48:                                 # crisp up the tiny ones a touch
        out = out.filter(ImageFilter.UnsharpMask(radius=0.6, percent=70, threshold=0))
    return out


def write_ico(path: Path, frames: dict[int, Image.Image]) -> None:
    """Writes a multi-size .ico with one PNG frame per size (so each size is exactly what we drew)."""
    blobs = []
    for s, im in sorted(frames.items(), reverse=True):
        b = io.BytesIO(); im.save(b, "PNG", optimize=True); blobs.append((s, b.getvalue()))
    head = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs); entries = b""
    for s, data in blobs:
        entries += struct.pack("<BBBBHHII", 0 if s >= 256 else s, 0 if s >= 256 else s, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    path.write_bytes(head + entries + b"".join(d for _, d in blobs))


if __name__ == "__main__":
    mask = dragon_mask()
    frames = {s: render(s, mask) for s in SIZES}
    write_ico(ICO, frames)
    render(256, mask).resize((128, 128), Image.LANCZOS).save(FAVICON, optimize=True)
    print(f"Wrote {ICO.relative_to(ROOT)} ({ICO.stat().st_size // 1024} KB, sizes {SIZES}) and {FAVICON.relative_to(ROOT)}")
