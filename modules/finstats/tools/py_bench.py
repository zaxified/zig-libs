#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Python side of tools/bench.zig: `py_bench.py <work dir> <workload>`.

Reads `<work dir>/returns.f64` (the little-endian f64 series the Zig driver wrote)
into a NumPy array and times ONLY the library call on it (the file read, the
import and the array construction are outside the clock): double the batch until
it takes over 100 ms, then the best of five batches, as testkit.bench.timeIt does
for the Zig side. Prints `name <TAB> ns/op <TAB> count` (count = series length,
the sides must agree). The versions go to stderr as the banner.

empyrical-reloaded's functions are NumPy code (the "compiled core" here is
NumPy's C loops); quantstats works on pandas, so it is not the timed side.
"""
import sys
import time

import empyrical as ep
import numpy as np


def main():
    work, name = sys.argv[1], sys.argv[2]
    r = np.fromfile(f"{work}/returns.f64", dtype="<f8")
    n = len(r)
    ops = {
        "sharpe": lambda: ep.sharpe_ratio(r, 0.0, annualization=252),
        "sortino": lambda: ep.sortino_ratio(r, 0.0, annualization=252),
        "max_dd": lambda: ep.max_drawdown(r),
        "cagr": lambda: ep.annual_return(r, annualization=252),
        "calmar": lambda: ep.calmar_ratio(r, annualization=252),
        "stability": lambda: ep.stability_of_timeseries(r),
        # riskMetrics' ann_vol, downside, var95, cvar95, mdd (the ones empyrical has)
        "risk_row": lambda: (
            ep.annual_volatility(r), ep.downside_risk(r), ep.value_at_risk(r, cutoff=0.05),
            ep.conditional_value_at_risk(r, cutoff=0.05), ep.max_drawdown(r)),
    }
    op = ops[name]
    k = 1
    while True:
        t = time.perf_counter()
        for _ in range(k):
            op()
        if time.perf_counter() - t > 0.1:
            break
        k *= 2
    best = float("inf")
    for _ in range(5):
        t = time.perf_counter()
        for _ in range(k):
            op()
        best = min(best, (time.perf_counter() - t) / k)
    sys.stderr.write(f"empyrical-reloaded {ep.__version__} numpy {np.__version__} python {sys.version.split()[0]}\n")
    sys.stdout.write(f"{name}\t{best * 1e9:.1f}\t{n}\n")


if __name__ == "__main__":
    main()
