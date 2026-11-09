#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for dataframe S2 wave W5 (windows and dynamic groups): what pandas 3.1
and polars 2.1 answer for rolling windows with `closed`/`step`/forward/weights/`win_type`,
time-window `rolling_*_by` / `corr` / `cov` / `rank`, `ewm` with `times` and `sum`,
`ewm_mean_by` / `ewm_sum_by`, `ewm` `cov`/`corr`, `cum_*(reverse)`, `over(order_by,
mapping_strategy)`, and `group_by_dynamic` / `resample` with `period`, `offset`, `closed`,
`label`, `start_by`, `origin`, `include_boundaries` and the rule aliases. Frozen into
src/oracle2d_vectors.json and replayed by src/s2w5_oracle_test.zig. No line of dataframe
is consulted: the expected values are what the engines answer.

    python tools/oracle2d.py src/oracle2d_vectors.json      (see tools/README.md)

SciPy is not installed. pandas' `rolling(win_type=)` imports it only to ask
`scipy.signal.windows.<name>(M, **params)` for the window; this script puts a stand-in
module in `sys.modules` that answers with numpy implementations of the formulas in
SciPy's documentation, checked here against numpy's own `hamming`, `hanning`,
`bartlett`, `blackman` and `kaiser` where numpy has them. The aggregation over the window
(weighted mean, weighted sum, NaN handling, `min_periods`) is pandas' own code.
Where both engines have a feature they must agree (or the run fails).
"""
import json
import math
import sys
import types

import numpy as np
import pandas as pd
import polars as pl

cases = []
problems = []

NAN = float("nan")


def cell(v):
    if v is None or v is pd.NaT:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        v = float(v)
        if math.isnan(v) or math.isinf(v):
            return None
        return v
    if isinstance(v, (list, tuple, np.ndarray)):
        return [cell(x) for x in v]
    if isinstance(v, pd.Timestamp):
        return int(v.as_unit("us").asm8.view("i8"))
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


def close(a, b):
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, list) or isinstance(b, list):
        return len(a) == len(b) and all(close(x, y) for x, y in zip(a, b))
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def agree(cid, a, b, names=("pandas", "polars")):
    if not close(a, b):
        problems.append(f"{cid}: {names[0]} {a} != {names[1]} {b}")


# ── the scipy stand-in (formulas of the SciPy documentation) ───────────────────────────


def _gc(M, a):
    fac = np.linspace(-np.pi, np.pi, M)
    w = np.zeros(M)
    for k, ak in enumerate(a):
        w += ak * np.cos(k * fac)
    return w


def sw_boxcar(M):
    return np.ones(M)


def sw_triang(M):
    if M == 1:
        return np.ones(1)
    n = np.arange(1, (M + 1) // 2 + 1)
    if M % 2 == 0:
        w = (2 * n - 1.0) / M
        return np.r_[w, w[::-1]]
    w = 2 * n / (M + 1.0)
    return np.r_[w, w[-2::-1]]


def sw_hamming(M):
    return np.ones(1) if M == 1 else _gc(M, [0.54, 0.46])


def sw_hann(M):
    return np.ones(1) if M == 1 else _gc(M, [0.5, 0.5])


def sw_bartlett(M):
    if M == 1:
        return np.ones(1)
    n = np.arange(0, M)
    return np.where(np.less_equal(n, (M - 1) / 2.0), 2.0 * n / (M - 1), 2.0 - 2.0 * n / (M - 1))


def sw_barthann(M):
    if M == 1:
        return np.ones(1)
    n = np.arange(0, M)
    fac = np.abs(n / (M - 1.0) - 0.5)
    return 0.62 - 0.48 * fac + 0.38 * np.cos(2 * np.pi * fac)


def sw_blackman(M):
    return np.ones(1) if M == 1 else _gc(M, [0.42, 0.50, 0.08])


def sw_blackmanharris(M):
    return np.ones(1) if M == 1 else _gc(M, [0.35875, 0.48829, 0.14128, 0.01168])


def sw_nuttall(M):
    return np.ones(1) if M == 1 else _gc(M, [0.3635819, 0.4891775, 0.1365995, 0.0106411])


def sw_flattop(M):
    return np.ones(1) if M == 1 else _gc(M, [0.21557895, 0.41663158, 0.277263158, 0.083578947, 0.006947368])


def sw_parzen(M):
    if M == 1:
        return np.ones(1)
    n = np.arange(-(M - 1) / 2.0, (M - 1) / 2.0 + 0.5, 1.0)
    na = np.extract(n < -(M - 1) / 4.0, n)
    nb = np.extract(abs(n) <= (M - 1) / 4.0, n)
    wa = 2 * (1 - np.abs(na) / (M / 2.0)) ** 3.0
    wb = 1 - 6 * (np.abs(nb) / (M / 2.0)) ** 2.0 + 6 * (np.abs(nb) / (M / 2.0)) ** 3.0
    return np.r_[wa, wb, wa[::-1]]


def sw_bohman(M):
    if M == 1:
        return np.ones(1)
    fac = np.abs(np.linspace(-1, 1, M)[1:-1])
    w = (1 - fac) * np.cos(np.pi * fac) + 1.0 / np.pi * np.sin(np.pi * fac)
    return np.r_[0, w, 0]


def sw_cosine(M):
    return np.ones(1) if M == 1 else np.sin(np.pi / M * (np.arange(0, M) + 0.5))


def sw_exponential(M, tau=1.0):
    if M == 1:
        return np.ones(1)
    center = (M - 1) / 2
    return np.exp(-np.abs(np.arange(0, M) - center) / tau)


def sw_gaussian(M, std):
    if M == 1:
        return np.ones(1)
    n = np.arange(0, M) - (M - 1.0) / 2.0
    return np.exp(-(n**2) / (2 * std * std))


def sw_general_gaussian(M, p, sig):
    if M == 1:
        return np.ones(1)
    n = np.arange(0, M) - (M - 1.0) / 2.0
    return np.exp(-0.5 * np.abs(n / sig) ** (2 * p))


def sw_kaiser(M, beta):
    if M == 1:
        return np.ones(1)
    n = np.arange(0, M)
    alpha = (M - 1) / 2.0
    return np.i0(beta * np.sqrt(1 - ((n - alpha) / alpha) ** 2.0)) / np.i0(beta)


WIN = {k[3:]: v for k, v in globals().items() if k.startswith("sw_")}

# The stand-ins agree with numpy's own where numpy has the window.
for M in (2, 3, 4, 5, 8, 9):
    assert np.allclose(sw_hamming(M), np.hamming(M)), M
    assert np.allclose(sw_hann(M), np.hanning(M)), M
    assert np.allclose(sw_bartlett(M), np.bartlett(M)), M
    assert np.allclose(sw_blackman(M), np.blackman(M)), M
    assert np.allclose(sw_kaiser(M, 5.0), np.kaiser(M, 5.0)), M


def install_scipy_standin():
    sc = types.ModuleType("scipy")
    sc.__version__ = "1.17.0"
    sig = types.ModuleType("scipy.signal")
    win = types.ModuleType("scipy.signal.windows")
    for name, fn in WIN.items():
        setattr(win, name, fn)
    sig.windows = win
    sc.signal = sig
    sys.modules.update({"scipy": sc, "scipy.signal": sig, "scipy.signal.windows": win})


install_scipy_standin()


# ── helpers ─────────────────────────────────────────────────────────────────────────

H = 3_600_000_000  # one hour in microseconds
MIN = 60_000_000


def series(n, seed, nulls=(), scale=10.0, ints=False):
    rs = np.random.RandomState(seed)
    xs = np.round(rs.uniform(-scale, scale, n), 3)
    if ints:
        xs = np.round(xs).astype(np.int64)
    out = [float(x) if not ints else int(x) for x in xs]
    for i in nulls:
        out[i] = None
    return out


def f64(xs):
    return np.array([NAN if x is None else x for x in xs], dtype=float)


def add(cid, kind, frame, expect, **kw):
    d = {"id": cid, "kind": kind, "frame": frame, "expect": expect}
    d.update(kw)
    cases.append(d)


def wcase(cid, frame, value, op, expect, **kw):
    add(cid, "window", frame, expect, value=value, op=op, **kw)


# ── 1. rolling: closed / step / forward / center on rows (pandas) ──────────────────────
X = series(14, 11, nulls=(3, 8))
XS = pd.Series(f64(X))
for func in ("mean", "sum", "min", "max", "std", "count"):
    for closed in ("right", "left", "both", "neither"):
        for mp in (None, 1):
            if func == "count" and mp is None:
                continue  # pandas 3.1: count's default min_periods is the window; ours is 0 (documented)
            kw = {"window": 3, "closed": closed}
            if mp is not None:
                kw["min_periods"] = mp
            r = getattr(XS.rolling(**kw), func)()
            op = {"k": "rolling", "window": 3, "func": func, "closed": closed}
            if mp is not None:
                op["min_periods"] = mp
            wcase(f"roll-closed-{func}-{closed}-mp{mp}", {"x": X}, "x", op, cells(r))
for func in ("mean", "sum"):
    for step in (2, 3):
        r = getattr(XS.rolling(3, min_periods=1, step=step), func)()
        full = [None] * len(X)
        for i, v in zip(r.index, r.values):
            full[i] = cell(v)
        wcase(
            f"roll-step{step}-{func}", {"x": X}, "x",
            {"k": "rolling", "window": 3, "func": func, "min_periods": 1, "step": step}, full,
        )
for func in ("mean", "sum", "min", "max", "std"):
    for w in (1, 3, 4):
        idx = pd.api.indexers.FixedForwardWindowIndexer(window_size=w)
        r = getattr(XS.rolling(idx, min_periods=1), func)()
        wcase(
            f"roll-forward{w}-{func}", {"x": X}, "x",
            {"k": "rolling", "window": w, "func": func, "min_periods": 1, "forward": True}, cells(r),
        )
for func in ("mean", "sum"):
    for w in (3, 4):
        r = getattr(XS.rolling(w, center=True, min_periods=1, closed="both"), func)()
        wcase(
            f"roll-center-both-{w}-{func}", {"x": X}, "x",
            {"k": "rolling", "window": w, "func": func, "min_periods": 1, "center": True, "closed": "both"},
            cells(r),
        )
# partitions
G = [i % 3 for i in range(14)]
r = XS.groupby(pd.Series(G)).rolling(3, min_periods=1, closed="left").mean().reset_index(level=0, drop=True).sort_index()
wcase("roll-closed-left-part", {"x": X, "g": G}, "x",
      {"k": "rolling", "window": 3, "func": "mean", "min_periods": 1, "closed": "left"}, cells(r), partition=["g"])

# ── 2. rolling weights (polars) and win_type (pandas, stand-in windows) ────────────────
XN = series(12, 21)
SN = pl.Series(XN)
for func in ("sum", "mean", "min", "max", "var", "std"):
    for w in ([1.0, 2.0, 3.0], [0.5, 0.25, 2.0, 1.0]):
        for mp in (None, 1):
            for center in (False, True):
                kw = {"weights": w}
                if mp:
                    kw["min_samples"] = mp
                r = getattr(SN, "rolling_" + func)(len(w), center=center, **kw).to_list()
                op = {"k": "rolling", "window": len(w), "func": func, "weights": w, "center": center}
                if mp:
                    op["min_periods"] = mp
                wcase(f"roll-weights-{func}-{len(w)}-mp{mp}-c{center}", {"x": XN}, "x", op, cells(r))

WINS = [
    ({"name": "boxcar"}, {}), ({"name": "triang"}, {}), ({"name": "hamming"}, {}), ({"name": "hann"}, {}),
    ({"name": "bartlett"}, {}), ({"name": "barthann"}, {}), ({"name": "blackman"}, {}),
    ({"name": "blackmanharris"}, {}), ({"name": "nuttall"}, {}), ({"name": "flattop"}, {}),
    ({"name": "parzen"}, {}), ({"name": "bohman"}, {}), ({"name": "cosine"}, {}),
    ({"name": "exponential", "tau": 2.5}, {"tau": 2.5}), ({"name": "gaussian", "std": 1.2}, {"std": 1.2}),
    ({"name": "general_gaussian", "p": 1.5, "sig": 1.7}, {"p": 1.5, "sig": 1.7}),
    ({"name": "kaiser", "beta": 6.0}, {"beta": 6.0}),
]
XW = series(15, 31, nulls=(4, 9))
XWS = pd.Series(f64(XW))
for wt, params in WINS:
    for w in (3, 4, 5, 8):
        for func in ("mean", "sum"):
            for mp in (None, 1):
                kw = {"win_type": wt["name"]}
                if mp:
                    kw["min_periods"] = mp
                r = getattr(XWS.rolling(w, **kw), func)(**params)
                op = {"k": "rolling", "window": w, "func": func, "win_type": wt}
                if mp:
                    op["min_periods"] = mp
                wcase(f"roll-wintype-{wt['name']}-{w}-{func}-mp{mp}", {"x": XW}, "x", op, cells(r))

# ── 3. time windows: closed, rank_by, corr/cov ───────────────────────────────────────
T = [0, 40 * MIN, 70 * MIN, 130 * MIN, 150 * MIN, 151 * MIN, 270 * MIN, 400 * MIN, 410 * MIN, 480 * MIN, 600 * MIN]
XT = series(len(T), 41, nulls=(5,))
YT = series(len(T), 42, nulls=(7,))
dts = pl.Series(T).cast(pl.Datetime("us"))
dfp = pl.DataFrame({"t": dts, "x": XT})
tidx = pd.DatetimeIndex(pd.to_datetime(T, unit="us"))
XTS = pd.Series(f64(XT), index=tidx)
YTS = pd.Series(f64(YT), index=tidx)
PL_CLOSED = {"right": "right", "left": "left", "both": "both", "neither": "none"}
for func in ("sum", "mean", "min", "max", "std"):
    for closed in ("right", "left", "both", "neither"):
        for mp in (1, 2):
            r = dfp.select(getattr(pl.col("x"), f"rolling_{func}_by")("t", "3h", closed=PL_CLOSED[closed], min_samples=mp))["x"].to_list()
            rp = getattr(XTS.rolling("3h", closed=closed, min_periods=mp), func)().tolist()
            agree(f"rt-{func}-{closed}-{mp}", cells(r), cells(rp))
            wcase(f"rolling-time-{func}-{closed}-mp{mp}", {"t": T, "x": XT}, "x",
                  {"k": "rolling_time", "time_col": "t", "period": 3 * H, "func": func, "closed": closed, "min_periods": mp},
                  cells(r))
for method in ("average", "min", "max", "dense"):
    for closed in ("right", "both"):
        r = dfp.select(pl.col("x").rolling_rank_by("t", "3h", method=method, closed=PL_CLOSED[closed], min_samples=1))["x"].to_list()
        wcase(f"rolling-rank-by-{method}-{closed}", {"t": T, "x": XT}, "x",
              {"k": "rolling_rank", "time_col": "t", "period": 3 * H, "method": method, "closed": closed, "min_periods": 1},
              cells(r))
for stat in ("corr", "cov"):
    for closed in ("right", "left", "both", "neither"):
        for mp in (None, 2):
            kw = {"closed": closed}
            if mp:
                kw["min_periods"] = mp
            r = getattr(XTS.rolling("3h", **kw), stat)(YTS)
            op = {"k": "rolling_" + stat, "other": "y", "time_col": "t", "period": 3 * H, "closed": closed}
            if mp:
                op["min_periods"] = mp
            wcase(f"rolling-time-{stat}-{closed}-mp{mp}", {"t": T, "x": XT, "y": YT}, "x", op, cells(r))

# ── 4. ewm: times, sum, by, cov/corr ──────────────────────────────────────────────────
XE = series(12, 51, nulls=(3, 4))
YE = series(12, 52, nulls=(6,))
TE = [0, 1 * H, 3 * H, 4 * H, 8 * H, 9 * H, 12 * H, 12 * H + 30 * MIN, 15 * H, 16 * H, 20 * H, 21 * H]
tei = pd.DatetimeIndex(pd.to_datetime(TE, unit="us"))
XES = pd.Series(f64(XE))
YES = pd.Series(f64(YE))
for adjust in (True, False):
    for ign in (False, True):
        for mp in (0, 3):
            r = XES.ewm(halflife=pd.Timedelta("2h"), times=tei, adjust=adjust, ignore_na=ign, min_periods=mp).mean()
            wcase(f"ewm-times-adj{adjust}-ign{ign}-mp{mp}", {"t": TE, "x": XE}, "x",
                  {"k": "ewm", "halflife": 2.0 * H, "adjust": adjust, "ignore_na": ign, "min_periods": mp, "func": "mean", "times_col": "t"},
                  cells(r))
for decay in ({"alpha": 0.3}, {"com": 1.5}, {"span": 5.0}, {"halflife": 2.0}):
    for ign in (False, True):
        for mp in (0, 2):
            r = XES.ewm(ignore_na=ign, min_periods=mp, **decay).sum()
            op = {"k": "ewm", "adjust": True, "ignore_na": ign, "min_periods": mp, "func": "sum"}
            op.update(decay)
            wcase(f"ewm-sum-{list(decay)[0]}-ign{ign}-mp{mp}", {"x": XE}, "x", op, cells(r))
# polars ewm_sum on data without nulls (it answers null where the cell is null; pandas carries)
XEN = series(10, 53)
r = pl.Series(XEN).ewm_sum(alpha=0.4).to_list()
rp = pd.Series(XEN).ewm(alpha=0.4).sum().tolist()
agree("ewm-sum-engines", cells(r), cells(rp))
wcase("ewm-sum-polars", {"x": XEN}, "x", {"k": "ewm", "alpha": 0.4, "func": "sum"}, cells(r))
TEN = [0, 1 * H, 3 * H, 4 * H, 8 * H, 9 * H, 12 * H, 13 * H, 15 * H, 16 * H]
dfe = pl.DataFrame({"t": pl.Series(TEN).cast(pl.Datetime("us")), "x": XEN})
dfn = pl.DataFrame({"t": pl.Series(TE).cast(pl.Datetime("us")), "x": XE})
for name, d, tt, xs in (("clean", dfe, TEN, XEN), ("nulls", dfn, TE, XE)):
    for func in ("mean", "sum"):
        r = d.select(getattr(pl.col("x"), f"ewm_{func}_by")("t", half_life="2h"))["x"].to_list()
        wcase(f"ewm-by-{func}-{name}", {"t": tt, "x": xs}, "x",
              {"k": "ewm_by", "time_col": "t", "half_life": 2 * H, "func": func}, cells(r))
for decay in ({"alpha": 0.3}, {"com": 1.5}, {"span": 5.0}, {"halflife": 2.0}):
    for adjust in (True, False):
        for ign in (False, True):
            for bias in (False, True):
                for mp in (0, 3):
                    kw = dict(adjust=adjust, ignore_na=ign, min_periods=mp, **decay)
                    c = XES.ewm(**kw).cov(YES, bias=bias)
                    op = {"k": "ewm_cov", "other": "y", "bias": bias, "adjust": adjust, "ignore_na": ign, "min_periods": mp}
                    op.update(decay)
                    wcase(f"ewm-cov-{list(decay)[0]}-adj{adjust}-ign{ign}-b{bias}-mp{mp}", {"x": XE, "y": YE}, "x", op, cells(c))
            kw = dict(adjust=adjust, ignore_na=ign, min_periods=0, **decay)
            c = XES.ewm(**kw).corr(YES)
            op = {"k": "ewm_corr", "other": "y", "adjust": adjust, "ignore_na": ign, "min_periods": 0}
            op.update(decay)
            wcase(f"ewm-corr-{list(decay)[0]}-adj{adjust}-ign{ign}", {"x": XE, "y": YE}, "x", op, cells(c))

# ── 5. cum reverse, order_by, mapping_strategy (polars) ──────────────────────────────
XC = series(12, 61, nulls=(2, 7))
XI = series(12, 62, ints=True)
GC = ["a", "b", "a", "c", "b", "a", "b", "c", "a", "b", "a", "c"]
OC = [5, 3, 9, 1, 8, 2, 7, 4, 6, 0, 10, 11]
dfc = pl.DataFrame({"x": XC, "xi": XI, "g": GC, "o": OC})
for fn in ("cum_sum", "cum_prod", "cum_min", "cum_max"):
    for col, vals in (("x", XC), ("xi", XI)):
        for part in (False, True):
            e = getattr(pl.col(col), fn)(reverse=True)
            e = e.over("g") if part else e
            r = dfc.select(e.alias("r"))["r"].to_list()
            wcase(f"cum-rev-{fn}-{col}-part{part}", {"x": vals, "g": GC}, "x", {"k": fn}, cells(r),
                  partition=["g"] if part else [], reverse=True)
r = pd.Series(GC).groupby(GC).cumcount(ascending=False).tolist()
wcase("cum-rev-count", {"x": XC, "g": GC}, "x", {"k": "cum_count"}, cells(r), partition=["g"], reverse=True)
for desc in (False, True):
    for fn, op in (("cum_sum", {"k": "cum_sum"}),):
        r = dfc.select(pl.col("xi").cum_sum().over("g", order_by="o", descending=desc).alias("r"))["r"].to_list()
        wcase(f"over-order-cumsum-desc{desc}", {"x": XI, "g": GC, "o": OC}, "x", op, cells(r),
              partition=["g"], order_by=["o"], desc=desc)
    r = dfc.select(pl.col("x").shift(1).over("g", order_by="o", descending=desc).alias("r"))["r"].to_list()
    wcase(f"over-order-shift-desc{desc}", {"x": XC, "g": GC, "o": OC}, "x", {"k": "shift", "n": 1}, cells(r),
          partition=["g"], order_by=["o"], desc=desc)
    r = dfc.select(pl.col("x").rolling_sum(2, min_samples=1).over("g", order_by="o", descending=desc).alias("r"))["r"].to_list()
    wcase(f"over-order-rolling-desc{desc}", {"x": XC, "g": GC, "o": OC}, "x",
          {"k": "rolling", "window": 2, "func": "sum", "min_periods": 1}, cells(r),
          partition=["g"], order_by=["o"], desc=desc)
r = dfc.select(pl.col("xi").cum_sum().over("g", order_by="o", mapping_strategy="join").alias("r"))["r"].to_list()
wcase("over-join-cumsum", {"x": XI, "g": GC, "o": OC}, "x", {"k": "cum_sum"}, cells(r),
      partition=["g"], order_by=["o"], mapping="join")
# polars does not keep first-seen group order under order_by + explode (it came out c, a, b for
# a, b, c), so the ordered explode is checked on one partition; the unordered one keeps it.
G1 = ["a"] * len(GC)
df1 = pl.DataFrame({"x": XI, "g": G1, "o": OC})
r = df1.select(pl.col("x").cum_sum().over("g", order_by="o", mapping_strategy="explode").alias("r"))["r"].to_list()
wcase("over-explode-cumsum-onegroup", {"x": XI, "g": G1, "o": OC}, "x", {"k": "cum_sum"}, cells(r),
      partition=["g"], order_by=["o"], mapping="explode")
r = dfc.select(pl.col("xi").cum_sum().over("g", mapping_strategy="explode").alias("r"))["r"].to_list()
wcase("over-explode-cumsum-noorder", {"x": XI, "g": GC, "o": OC}, "x", {"k": "cum_sum"}, cells(r),
      partition=["g"], mapping="explode")

# ── 6. group_by_dynamic / resample ───────────────────────────────────────────────────
base_us = int(np.datetime64("2020-01-01T00:00", "us").astype("int64"))
MINS = [7, 20, 65, 80, 150, 151, 300, 310]
TD = [base_us + m * MIN for m in MINS]
XD = series(len(TD), 71, ints=True)
GD = ["a", "b", "a", "a", "b", "b", "a", "b"]
AGGS = [("sum", "sum"), ("count", "count"), ("first", "first"), ("last", "last"), ("min", "min"), ("max", "max")]


def plagg():
    return [getattr(pl.col("x"), f)().alias(o) for o, f in AGGS]


def us_of(v):
    return int(pd.Timestamp(v).as_unit("us").asm8.view("i8"))


def dyn_case(cid, frame_t, frame_x, kwargs, spec, by=None, zero_ok=False):
    d = pl.DataFrame({"t": pl.Series(frame_t).cast(pl.Datetime("us")), "x": frame_x, **({"g": by} if by else {})})
    kw = dict(kwargs)
    if by:
        kw["group_by"] = "g"
    r = d.group_by_dynamic("t", **kw).agg(plagg())
    r = r.sort(["g", "t"]) if by else r.sort("t")
    cols = r.columns
    rows = [[us_of(v) if hasattr(v, "year") else cell(v) for v in row] for row in r.iter_rows()]
    frame = {"t": frame_t, "x": frame_x}
    if by:
        frame["g"] = by
    spec = dict(spec)
    if by:
        spec["by"] = ["g"]
    add(cid, "dynamic", frame, {"cols": cols, "rows": rows}, spec=spec,
        aggs=[{"src": "x", "out": o, "func": f} for o, f in AGGS])


dyn_case("dyn-plain", TD, XD, dict(every="1h"), {"every": "1h"})
dyn_case("dyn-period2h", TD, XD, dict(every="1h", period="2h"), {"every": "1h", "period": "2h"})
dyn_case("dyn-period90m", TD, XD, dict(every="1h", period="90m"), {"every": "1h", "period": "90m"})
dyn_case("dyn-period3h-by", TD, XD, dict(every="1h", period="3h"), {"every": "1h", "period": "3h"}, by=GD)
dyn_case("dyn-offset15", TD, XD, dict(every="1h", offset="15m"), {"every": "1h", "offset": "15m"})
dyn_case("dyn-offset-15", TD, XD, dict(every="1h", offset="-15m"), {"every": "1h", "offset": "-15m"})
for closed in ("left", "right", "both", "none"):
    dyn_case(f"dyn-closed-{closed}", TD, XD, dict(every="1h", closed=closed), {"every": "1h", "closed": closed})
    dyn_case(f"dyn-closed-{closed}-p2h", TD, XD, dict(every="1h", period="2h", closed=closed),
             {"every": "1h", "period": "2h", "closed": closed})
for label in ("left", "right", "datapoint"):
    dyn_case(f"dyn-label-{label}", TD, XD, dict(every="1h", label=label), {"every": "1h", "label": label})
dyn_case("dyn-startby-datapoint", TD, XD, dict(every="1h", start_by="datapoint"), {"every": "1h", "start_by": "datapoint"})
dyn_case("dyn-startby-datapoint-90m", TD, XD, dict(every="90m", start_by="datapoint"), {"every": "90m", "start_by": "datapoint"})
dyn_case("dyn-startby-datapoint-by", TD, XD, dict(every="1h", start_by="datapoint"), {"every": "1h", "start_by": "datapoint"}, by=GD)
dyn_case("dyn-90m", TD, XD, dict(every="90m"), {"every": "90m"})
dyn_case("dyn-complex", TD, XD, dict(every="1h", period="3h", offset="30m", closed="right", label="right"),
         {"every": "1h", "period": "3h", "offset": "30m", "closed": "right", "label": "right"})
dyn_case("dyn-boundaries", TD, XD, dict(every="1h", include_boundaries=True), {"every": "1h", "include_boundaries": True})
dyn_case("dyn-boundaries-by-p2h", TD, XD, dict(every="1h", period="2h", include_boundaries=True),
         {"every": "1h", "period": "2h", "include_boundaries": True}, by=GD)
# first value on the grid, closed right
TG = [base_us + m * MIN for m in (0, 30, 60, 61, 120, 200)]
XG = series(len(TG), 72, ints=True)
dyn_case("dyn-closed-right-ongrid", TG, XG, dict(every="1h", closed="right"), {"every": "1h", "closed": "right"})
dyn_case("dyn-closed-right-p2h-ongrid", TG, XG, dict(every="1h", period="2h", closed="right"),
         {"every": "1h", "period": "2h", "closed": "right"})
# weeks and months
days = [1, 2, 3, 6, 8, 9, 15, 17, 22, 40, 41, 75]
TW = [int(np.datetime64(f"2020-01-01T00:00", "us").astype("int64")) + (d - 1) * 24 * H + (d % 5) * H for d in days]
XW2 = series(len(TW), 73, ints=True)
for sb in ("window", "monday", "wednesday", "sunday", "datapoint", "saturday"):
    dyn_case(f"dyn-week-{sb}", TW, XW2, dict(every="1w", start_by=sb), {"every": "1w", "start_by": sb})
dyn_case("dyn-2w", TW, XW2, dict(every="2w"), {"every": "2w"})
dyn_case("dyn-1mo", TW, XW2, dict(every="1mo"), {"every": "1mo"})
dyn_case("dyn-1mo-p2mo", TW, XW2, dict(every="1mo", period="2mo"), {"every": "1mo", "period": "2mo"})
dyn_case("dyn-1mo-p2mo-right", TW, XW2, dict(every="1mo", period="2mo", closed="right", label="right"),
         {"every": "1mo", "period": "2mo", "closed": "right", "label": "right"})
dyn_case("dyn-1q", TW, XW2, dict(every="1q"), {"every": "1q"})
dyn_case("dyn-1mo-offset3d", TW, XW2, dict(every="1mo", offset="3d"), {"every": "1mo", "offset": "3d"})
dyn_case("dyn-1mo-datapoint", TW, XW2, dict(every="1mo", start_by="datapoint"), {"every": "1mo", "start_by": "datapoint"})

# pandas resample: origin, closed, label, offset, rules.
RMIN = [3, 14, 29, 47, 61, 62, 98, 110, 133, 190, 205, 251]
TR = [int(np.datetime64("2020-03-04T10:00", "us").astype("int64")) + m * MIN for m in RMIN]
XR = series(len(TR), 74, ints=True)


def res_case(cid, t, x, rule_or_freq, spec, **pkw):
    ser = pd.Series(np.array(x, dtype=float), index=pd.DatetimeIndex(pd.to_datetime(t, unit="us")))
    rs = ser.resample(rule_or_freq, **pkw)
    r = rs.agg(["sum", "count"])
    r = r[r["count"] > 0]
    rows = []
    for ts_, row in r.iterrows():
        rows.append([cell(pd.Timestamp(ts_)), cell(row["sum"]), cell(row["count"])])
    add(cid, "dynamic_pd", {"t": t, "x": x}, {"cols": ["t", "s", "n"], "rows": rows}, spec=spec,
        aggs=[{"src": "x", "out": "s", "func": "sum"}, {"src": "x", "out": "n", "func": "count"}])


for rule in ("17min", "15min", "1h", "30min", "2h", "10min"):
    for origin in ("start_day", "start", "epoch"):
        res_case(f"res-{rule}-{origin}", TR, XR, rule, {"rule": rule, "origin": origin}, origin=origin)
    res_case(f"res-{rule}-default", TR, XR, rule, {"rule": rule})
for closed, label in (("left", "left"), ("right", "right"), ("right", "left"), ("left", "right")):
    res_case(f"res-30min-{closed}-{label}", TR, XR, "30min",
             {"rule": "30min", "closed": closed, "label": label, "origin": "start_day"}, closed=closed, label=label)
res_case("res-30min-offset", TR, XR, "30min", {"rule": "30min", "offset": "7m"}, offset="7min")
res_case("res-17min-end", TR, XR, "17min", {"rule": "17min", "origin": "end", "closed": "right", "label": "right"}, origin="end", closed="right", label="right")
res_case("res-17min-end_day", TR, XR, "17min", {"rule": "17min", "origin": "end_day", "closed": "right", "label": "right"}, origin="end_day", closed="right", label="right")
# calendar rules
CD = [1, 2, 20, 31, 32, 59, 60, 61, 90, 91, 120, 200, 201, 300, 366, 400]
TC = [int(np.datetime64("2020-01-01T00:00", "us").astype("int64")) + (d - 1) * 24 * H + (d * 7 % 23) * H for d in CD]
XC2 = series(len(TC), 75, ints=True)
for rule in ("MS", "QS", "YS", "ME", "QE", "YE", "W", "W-MON", "W-WED", "W-SAT", "D"):
    res_case(f"res-rule-{rule}", TC, XC2, rule, {"rule": rule})

# ── write ───────────────────────────────────────────────────────────────────────────
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
out = sys.argv[1] if len(sys.argv) > 1 else "oracle2d_vectors.json"
with open(out, "w") as fh:
    json.dump({"pandas": pd.__version__, "polars": pl.__version__, "cases": cases}, fh, separators=(",", ":"))
print(f"{len(cases)} cases -> {out}")
