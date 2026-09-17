#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle: zxing-cpp (Apache-2.0, verified via `pip show
zxing-cpp` -> `License-Expression: Apache-2.0`) against this module's public
API, over the corpora `gen2.py`/`gen3.py` generate (`CONVENTIONS.md` §9).
ZXing is *run*, never read; nothing of its source is reproduced here. ZBar
(LGPL) is not used anywhere in this recipe.

Talks to `qrscan` only through the `qrscan-demo` example CLI
(`modules/qrscan/example/main.zig`), itself built only against qrscan's
published API (`@import("qrscan")`, `@import("qr")`) -- no module internals
reached from here or from that example.

Needs: Python 3 + `zxing-cpp` + `Pillow` (`pip install zxing-cpp pillow`).

usage: oracle.py <qrscan-demo-binary> <corpus-dir> [<corpus-dir> ...]

Each <corpus-dir> must contain a manifest.tsv as gen2.py/gen3.py write it
(path, description, expected decoded text).
"""
import subprocess, sys
from PIL import Image
import zxingcpp


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <qrscan-demo-binary> <corpus-dir> [<corpus-dir> ...]", file=sys.stderr)
        return 2
    demo = sys.argv[1]
    ok_z = ok_q = n = 0
    for corpus in sys.argv[2:]:
        rows = []
        with open(f"{corpus}/manifest.tsv") as f:
            for line in f:
                p, desc, want = line.rstrip("\n").split("\t")
                n += 1
                im = Image.open(p)
                r = zxingcpp.read_barcode(im)
                z = r.text if r else None
                okz = z == want
                out = subprocess.run([demo, "-q", p], capture_output=True, text=True)
                got = out.stdout.strip()
                okq = got == want
                ok_z += okz
                ok_q += okq
                rows.append((desc, "ZXing:" + ("OK" if okz else "FAIL"), "qrscan:" + ("OK" if okq else "FAIL"),
                             "" if okq else (out.stderr.strip().splitlines()[0] if out.stderr.strip() else got[:60])))
        w = max(len(r[0]) for r in rows)
        print(f"== {corpus} ==")
        for r in rows:
            print(f"{r[0]:<{w}}  {r[1]:<12} {r[2]:<13} {r[3]}")
    print(f"\ntotal {n}: ZXing {ok_z}/{n}, qrscan {ok_q}/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
