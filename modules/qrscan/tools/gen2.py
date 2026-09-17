#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corpus recipe: 37 flat/rotated/degraded QR images, for `oracle.py`
(`CONVENTIONS.md` §9's "recipe for committed data" — except these images are
NOT committed, 21 MB and regenerable; this recipe is the anchor).

Needs: `segno` (BSD-3-Clause, `pip show segno`), Pillow.

usage: gen2.py [output-dir]   (default: "corpus2", created if missing)

Writes `<output-dir>/manifest.tsv` (path, description, expected decoded text)
plus the PGM/PNG images themselves.
"""
import sys, segno, os, math, random
from PIL import Image, ImageFilter, ImageOps

out = sys.argv[1] if len(sys.argv) > 1 else "corpus2"
os.makedirs(out, exist_ok=True)
cases = []


def add(p, t, d):
    cases.append((p, t, d))


texts = {"v1": "HELLO", "v4": "https://example.com/abcdefghij", "v10": "N" * 250, "v20": "N" * 800}
for name, txt in texts.items():
    q = segno.make(txt, error='q', micro=False)
    for scale in (3, 4, 6, 10):
        p = f"{out}/{name}_s{scale}.png"
        q.save(p, scale=scale, border=4, kind='png')
        Image.open(p).convert('L').save(p[:-4] + ".pgm")
        add(p[:-4] + ".pgm", txt, f"{name}(v{q.version}) scale={scale}")
# rotation sweep on v1 and v20 at 6 px/module, rotated by PIL
for name in ("v1", "v20"):
    q = segno.make(texts[name], error='q', micro=False)
    q.save(f"{out}/{name}_rot.png", scale=6, border=6, kind='png')
    base = Image.open(f"{out}/{name}_rot.png").convert('L')
    for deg in (5, 17, 33, 45, 58, 77):
        p = f"{out}/{name}_rot{deg}.pgm"
        base.rotate(deg, resample=Image.BICUBIC, expand=True, fillcolor=255).save(p)
        add(p, texts[name], f"{name}(v{q.version}) rotated {deg}deg")
# realistic capture: gaussian blur + illumination gradient + gaussian noise
random.seed(7)
q = segno.make(texts["v10"], error='q', micro=False)
q.save(f"{out}/cap.png", scale=8, border=6, kind='png')
base = Image.open(f"{out}/cap.png").convert('L')
w, h = base.size
for blur, grad, noise in ((1.0, 0, 0), (2.0, 0, 0), (0, 120, 0), (1.0, 120, 20), (0, 0, 40)):
    im = base.filter(ImageFilter.GaussianBlur(blur)) if blur else base.copy()
    px = im.load()
    for y in range(h):
        for x in range(w):
            v = px[x, y]
            if grad: v = int(v * (1.0 - grad / 255.0 * (x / w)))
            if noise: v = v + int(random.gauss(0, noise))
            px[x, y] = max(0, min(255, v))
    p = f"{out}/cap_b{blur}_g{grad}_n{noise}.pgm"
    im.save(p)
    add(p, texts["v10"], f"v10 capture blur={blur} grad={grad} noise={noise}")
# perspective (external): PIL quad transform, tilt about vertical axis
q = segno.make(texts["v10"], error='q', micro=False)
q.save(f"{out}/persp.png", scale=8, border=8, kind='png')
base = Image.open(f"{out}/persp.png").convert('L')
w, h = base.size
for k in (0.10, 0.20, 0.30, 0.40):
    d = int(h * k / 2)
    quad = (0, -d, 0, h + d, w, d, w, h - d)  # source quad for the destination rect
    im = base.transform((w, h), Image.QUAD, quad, resample=Image.BICUBIC, fillcolor=255)
    p = f"{out}/persp_{int(k * 100)}.pgm"
    im.save(p)
    add(p, texts["v10"], f"v10 perspective k={k}")
with open(f"{out}/manifest.tsv", "w") as f:
    for p, t, d in cases:
        f.write(f"{p}\t{d}\t{t}\n")
print("generated", len(cases))
