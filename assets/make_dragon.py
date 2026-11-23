"""Regenerates panzeron/web/img/dragon.png from assets/dragon-source.png (requires Pillow + NumPy).

The source is a flat red dragon on white. The web UI needs it as a *mask*: a white silhouette whose alpha channel is the
dragon's shape, so CSS can paint it in the user's accent colour (see .bo-dragon in panzeron/web/css/app.css).
Usage: python assets/make_dragon.py            (run from the project folder)
"""
from pathlib import Path
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "assets" / "dragon-source.png", ROOT / "panzeron" / "web" / "img" / "dragon.png"
LONG_SIDE = 640          # shown at roughly 80 px (so 160 px on a 2x display); 640 stays crisp when scaled up in the settings preview

rgb = np.asarray(Image.open(SRC).convert("RGB")).astype(float)
bg = np.median(rgb[:40, :40].reshape(-1, 3), axis=0)[1]          # paper white (green channel: the dragon is nearly 0 there)
ink = np.percentile(rgb[..., 1][rgb[..., 1] < 60], 50)            # dragon red's green value
alpha = np.clip((bg - rgb[..., 1]) / (bg - ink), 0, 1)            # soft, anti-aliased coverage
alpha[alpha < 0.04] = 0                                           # drop paper noise
alpha = np.clip(alpha * 1.04, 0, 1)

ys, xs = np.where(alpha > 0.02)
pad = int(0.02 * max(xs.max() - xs.min(), ys.max() - ys.min()))
box = (max(xs.min() - pad, 0), max(ys.min() - pad, 0), min(xs.max() + pad + 1, alpha.shape[1]), min(ys.max() + pad + 1, alpha.shape[0]))
mask = Image.fromarray((alpha * 255).astype("uint8"), "L").crop(box)
scale = LONG_SIDE / max(mask.size)
mask = mask.resize((round(mask.width * scale), round(mask.height * scale)), Image.LANCZOS)

out = Image.new("RGBA", mask.size, (255, 255, 255, 0)); out.putalpha(mask)
out.save(OUT, optimize=True)
print(f"Wrote {OUT.relative_to(ROOT)}  {out.size[0]}x{out.size[1]}  {OUT.stat().st_size // 1024} KB  aspect(w/h)={out.width / out.height:.3f}")
