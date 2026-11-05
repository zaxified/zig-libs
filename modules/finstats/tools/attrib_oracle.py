#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Foreign vectors for `brinsonAttribution`, frozen into
`src/testdata/attrib_oracle_vectors.zig` and replayed by `src/attrib_oracle_test.zig`.

    D=$(mktemp -d)   # the file below is foreign: its own empty directory, never committed
    curl -fsSL -o "$D/attribution_model.py" https://raw.githubusercontent.com/JerBouma/FinanceToolkit/da43cc7813052252a84e8a91add3a837c6182bb2/financetoolkit/portfolio/attribution_model.py
    V=~/.local/share/zig-libs/oracle-venvs/finstats
    $V/bin/python -I modules/finstats/tools/attrib_oracle.py "$D/attribution_model.py" \
      | zig fmt --stdin > modules/finstats/src/testdata/attrib_oracle_vectors.zig

What answers for what (black box over our inputs; the foreign file is MIT and is read
whole before running, it imports numpy, pandas, scipy and nothing else):

  - brinsonAttribution -- FinanceToolkit `get_brinson_fachler_attribution`, pinned by
    commit and sha256 (5.5k stars, MIT, active, 2026-11). Includes the two edge rules
    its docs table shows: a segment the portfolio does not hold is pure allocation
    whatever its stated return, a segment outside the benchmark with no return of its
    own is compared with the benchmark as a whole.
  - BHB allocation, the negative control: (wp - wb) * rb, written here. The replay
    requires the vectors to differ from it, so a vector set that could not tell
    Brinson-Fachler from BHB fails rather than passes.

Weights sum to 1 in every case: FinanceToolkit normalises them and the module does not
(its documented assumption), and that difference is not what these vectors test. Short
positions are out for the same reason: FinanceToolkit treats wp < 0 as not held.
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

import numpy as np
import pandas as pd

FOREIGN_SHA256 = "a608d5e493dfb3c0801dbe4000d8d0a779b001c14b89877855cfa50f7e06be1c"

rng = np.random.default_rng(20261105)


def load_foreign(path):
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest != FOREIGN_SHA256:
        sys.exit(f"attribution_model.py sha256 {digest}, expected {FOREIGN_SHA256}")
    spec = importlib.util.spec_from_file_location("ft_attribution_model", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def f(x):
    x = float(x)
    return "nan" if np.isnan(x) else repr(x)


def floats(xs):
    return "&.{" + ", ".join(f(x) for x in xs) + "}"


def simplex(m):
    return rng.dirichlet(np.ones(m))


def renorm(w):
    return w / w.sum()


def cases():
    """(label, wp, wb, rp, rb); NaN marks a return that is not there."""
    out = []
    for m in (2, 3, 5, 11):
        out.append((f"plain {m}", simplex(m), simplex(m), rng.normal(0.01, 0.05, m), rng.normal(0.01, 0.05, m)))

    m = 5
    wp, wb = simplex(m), simplex(m)
    wp[1] = 0.0
    wb[0] = 0.0
    out.append(("not held, outside the benchmark, both returns stated", renorm(wp), renorm(wb),
                rng.normal(0.01, 0.05, m), rng.normal(0.01, 0.05, m)))

    m = 6
    wp, rp = simplex(m), rng.normal(0.01, 0.05, m)
    wp[[0, 2]] = 0.0
    rp[[0, 2]] = np.nan
    out.append(("not held, no portfolio return", renorm(wp), simplex(m), rp, rng.normal(0.01, 0.05, m)))

    m = 4
    wb, rb = simplex(m), rng.normal(0.01, 0.05, m)
    wb[0] = 0.0
    rb[0] = np.nan
    out.append(("outside the benchmark, no benchmark return", simplex(m), renorm(wb),
                rng.normal(0.01, 0.05, m), rb))

    m = 7
    wp, wb, rp, rb = simplex(m), simplex(m), rng.normal(0.01, 0.05, m), rng.normal(0.01, 0.05, m)
    wp[1] = 0.0
    rp[1] = np.nan
    wb[3] = 0.0
    rb[3] = np.nan
    out.append(("both holes", renorm(wp), renorm(wb), rp, rb))
    return out


def brinson(o, ft):
    o.append("pub const Bf = struct { label: []const u8, wp: []const f64, wb: []const f64, rp: []const f64,"
             " rb: []const f64, alloc: []const f64, sel: []const f64, inter: []const f64,"
             " bhb_alloc: []const f64, total_active: f64 };")
    o.append("pub const bf_cases = [_]Bf{")
    for label, wp, wb, rp, rb in cases():
        names = [f"S{i:02d}" for i in range(len(wp))]
        s = lambda xs: pd.Series(xs, index=names, dtype=float)
        res = ft.get_brinson_fachler_attribution(s(wp), s(rp), s(wb), s(rb))
        seg = res.loc[names]
        total = res.loc["Total"]
        # held at zero weight or outside the benchmark, BHB and BF only differ where wp != wb
        filled = np.where(np.isnan(rb), float(total["Benchmark Return"]), rb)
        bhb = (wp - wb) * filled
        o.append(f'    .{{ .label = "{label}", .wp = {floats(wp)}, .wb = {floats(wb)}, .rp = {floats(rp)},'
                 f" .rb = {floats(rb)}, .alloc = {floats(seg['Allocation Effect'])},"
                 f" .sel = {floats(seg['Selection Effect'])}, .inter = {floats(seg['Interaction Effect'])},"
                 f" .bhb_alloc = {floats(bhb)}, .total_active = {f(total['Total Effect'])} }},")
    o.append("};")


def main():
    ft = load_foreign(sys.argv[1])
    o = ["// SPDX-License-Identifier: MIT",
         "// Generated by modules/finstats/tools/attrib_oracle.py: FinanceToolkit answers over our",
         "// own seeded inputs. Replayed by src/attrib_oracle_test.zig. Do not edit by hand.",
         "",
         'const nan = @import("std").math.nan(f64);',
         ""]
    brinson(o, ft)
    sys.stdout.write("\n".join(o) + "\n")


if __name__ == "__main__":
    main()
