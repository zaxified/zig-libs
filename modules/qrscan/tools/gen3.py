#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corpus recipe: 24 perspective-projected QR images, for `oracle.py`
(`CONVENTIONS.md` §9's "recipe for committed data" — except these images are
NOT committed, they regenerate). Simulates a plane tilted about its vertical
axis in front of a pinhole camera, 0-40 degrees, at three symbol versions.

Needs: `segno` (BSD-3-Clause, `pip show segno`), Pillow, numpy.

usage: gen3.py [output-dir]   (default: "corpus3", created if missing)

Writes `<output-dir>/manifest.tsv` (path, description, expected decoded text)
plus the PGM images themselves.
"""
import sys, segno, os, math, numpy as np
from PIL import Image

out = sys.argv[1] if len(sys.argv) > 1 else "corpus3"
os.makedirs(out, exist_ok=True)
cases = []


def coeffs(src, dst):
    # solve for PIL PERSPECTIVE: maps dst -> src
    A = []
    B = []
    for (xd, yd), (xs, ys) in zip(dst, src):
        A.append([xd, yd, 1, 0, 0, 0, -xs * xd, -xs * yd]); B.append(xs)
        A.append([0, 0, 0, xd, yd, 1, -ys * xd, -ys * yd]); B.append(ys)
    return np.linalg.solve(np.array(A, dtype=float), np.array(B, dtype=float))


texts = {"v1": "HELLO", "v6": "https://example.com/abcdefghijklmnop-123456", "v13": "N" * 400}
for name, txt in texts.items():
    q = segno.make(txt, error='q', micro=False)
    q.save(f"{out}/{name}.png", scale=6, border=8, kind='png')
    base = Image.open(f"{out}/{name}.png").convert('L')
    w, h = base.size
    W, H = int(w * 1.6), int(h * 1.6)
    ox, oy = (W - w) // 2, (H - h) // 2
    canvas = Image.new('L', (W, H), 255)
    canvas.paste(base, (ox, oy))
    for deg in (0, 5, 10, 15, 20, 25, 30, 40):
        t = math.radians(deg)
        d = w * 3.0
        f = d

        # plane rotated about the vertical axis, pinhole at distance d
        def proj(u, v):
            X = f * u * math.cos(t) / (d - u * math.sin(t))
            Y = v * d / (d - u * math.sin(t))
            return (W / 2 + X, H / 2 + Y)

        corners = [(-w / 2, -h / 2), (w / 2, -h / 2), (w / 2, h / 2), (-w / 2, h / 2)]
        dst = [proj(u, v) for u, v in corners]
        src = [(W / 2 + u, H / 2 + v) for u, v in corners]
        c = coeffs(src, dst)
        im = canvas.transform((W, H), Image.PERSPECTIVE, c, resample=Image.BICUBIC, fillcolor=255)
        p = f"{out}/{name}_t{deg}.pgm"
        im.save(p)
        cases.append((p, txt, f"{name}(v{q.version}) tilt {deg}deg about vertical axis"))
with open(f"{out}/manifest.tsv", "w") as f:
    for p, t, d in cases:
        f.write(f"{p}\t{d}\t{t}\n")
print("generated", len(cases))
