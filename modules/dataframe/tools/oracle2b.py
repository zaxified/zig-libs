#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the constructors, small Expr functions, selectors, name verbs and
column functions of dataframe S2 wave W3: polars 2.1 and pandas 3.1 (numpy / Python's math
where neither has the function) over small generated inputs, frozen into
src/oracle2b_vectors.json and replayed by src/s2w3_oracle_test.zig. No line of dataframe is
consulted here: the expected values are what the engines answer. (A separate script and
file from oracle2.py on purpose: two waves regenerating one vectors file would conflict.)

    python tools/oracle2b.py src/oracle2b_vectors.json      (see tools/README.md)

A case the engine raises on is reported on stderr and left out of the file.
"""
import datetime as dt
import json
import math
import sys

import numpy as np
import pandas as pd
import polars as pl

cases = []
problems = []


def case(id, kind, engine, expect, **kw):
    cases.append({"id": id, "kind": kind, "engine": engine, "expect": expect, **kw})


def run(id, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001 - report and go on
        problems.append(f"{id}: {type(e).__name__}: {str(e)[:160]}")


def cell(v):
    if v is None or v is pd.NaT or v is pd.NA:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        v = float(v)
        return None if math.isnan(v) else (v if math.isfinite(v) else ("inf" if v > 0 else "-inf"))
    if isinstance(v, dt.datetime):
        return int((v - dt.datetime(1970, 1, 1)) / dt.timedelta(microseconds=1))
    if isinstance(v, dt.timedelta):
        return int(v / dt.timedelta(microseconds=1))
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, pd.Timestamp):
        return int(v.as_unit("us").asm8.view("i8"))
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


def pl_eval(df, e):
    return cells(df.select(e.alias("o"))["o"].to_list())


# ── Expr functions ───────────────────────────────────────────────────────────

def g_expr():
    li = [7, -7, 7, -7, 5, None, 0, -9223372036854775807]
    ri = [2, 2, -2, -2, 0, 3, 5, -1]

    def f():
        out = []
        for a, b in zip(li, ri):
            out.append(None if a is None or b == 0 else int(np.sign(a) * np.sign(b) * (abs(a) // abs(b))))
        case("truncdiv-int", "expr", "numpy", out, op="truncdiv", cols={"l": li, "r": ri})
    run("truncdiv-int", f)

    lf = [7.5, -7.5, 1.0, -0.5, 9.0, None, 2.5]
    rf = [2.0, 2.0, 0.3, 0.25, 3.0, 1.0, -2.0]

    def f2():
        out = [None if a is None else float(np.trunc(a / b)) for a, b in zip(lf, rf)]
        case("truncdiv-float", "expr", "numpy", out, op="truncdiv", cols={"l": lf, "r": rf})
    run("truncdiv-float", f2)

    xs = [-3.0, -1.0, -0.1, 0.0, 0.5, 1.0, 2.0, 2.5, 3.0, 5.0, 6.5, 10.0, 26.0, 27.5, 30.0, None]
    case("erfc", "expr", "python-math", [None if x is None else math.erfc(x) for x in xs], op="erfc", cols={"x": xs})

    ts = ["a.b*c", "(x)|[y]{z}", "^$\\", "plain", "# & - ~", "", None, "a b\tc"]
    run("escape_regex", lambda: case("escape_regex", "expr", "polars", pl_eval(pl.DataFrame({"x": ts}, schema={"x": pl.String}), pl.col("x").str.escape_regex()), op="escape_regex", cols={"x": ts}))

    xv = [1.0, 2.0, 3.0, 1.0, 3.0, None, 2.0, 0.0, 5.0]
    lo = [1.0, 1.0, 1.0, 2.0, 2.0, 1.0, None, 1.0, 1.0]
    hi = [3.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0, 3.0, None]
    for closed in ["both", "left", "right", "none"]:
        def f3(closed=closed):
            df = pl.DataFrame({"x": xv, "lo": lo, "hi": hi})
            case(f"is_between-{closed}", "expr", "polars", pl_eval(df, pl.col("x").is_between(pl.col("lo"), pl.col("hi"), closed=closed)), op="is_between", closed=closed, cols={"x": xv, "lo": lo, "hi": hi})
        run(f"is_between-{closed}", f3)

    a = ["x", "y", None, None, "p"]
    b = [1, None, 3, None, 5]
    c = ["u", "v", "w", None, "z"]
    for sep in ["", "-"]:
        for ign in [False, True]:
            def f4(sep=sep, ign=ign):
                df = pl.DataFrame({"a": a, "b": b, "c": c}, schema={"a": pl.String, "b": pl.Int64, "c": pl.String})
                case(f"concat_str-{sep!r}-{ign}", "expr", "polars", pl_eval(df, pl.concat_str(["a", "b", "c"], separator=sep, ignore_nulls=ign)), op="concat_str", separator=sep, ignore_nulls=ign, cols={"a": a, "b": b, "c": c})
            run(f"concat_str-{sep}-{ign}", f4)

    def f5():
        s = pd.Series(a, dtype="object")
        o = s.str.cat(pd.Series(c, dtype="object"), sep="|", na_rep="?")
        case("str_cat-na_rep", "expr", "pandas", [None if (v is None or v is np.nan or v != v) else v for v in o.tolist()], op="concat_str", separator="|", na_rep="?", cols={"a": a, "c": c})
    run("str_cat", f5)

    fa = [1, None, 3, 4]
    fb = [10, 20, None, 40]
    fc = [100, 200, 300, 400]

    def f6():
        df = pl.DataFrame({"a": fa, "b": fb, "c": fc})
        case("fold-add", "expr", "polars", pl_eval(df, pl.fold(pl.lit(0), lambda x, y: x + y, [pl.col("a"), pl.col("b"), pl.col("c")])), op="fold_add", cols={"a": fa, "b": fb, "c": fc})
        case("reduce-mul", "expr", "polars", pl_eval(df, pl.reduce(lambda x, y: x * y, [pl.col("a"), pl.col("b"), pl.col("c")])), op="reduce_mul", cols={"a": fa, "b": fb, "c": fc})
    run("fold", f6)

    starts = ["2024-01-01", "2024-01-10", "2024-01-06", "2024-02-28", None, "2024-03-01"]
    ends = ["2024-01-31", "2024-01-01", "2024-01-13", "2024-03-04", "2024-03-01", "2024-03-01"]
    for tag, kw in [("default", {}), ("holidays", {"holidays": [dt.date(2024, 1, 15), dt.date(2024, 1, 20), dt.date(2024, 1, 15)]}), ("mask", {"week_mask": (True, True, True, True, True, True, False)})]:
        def f7(tag=tag, kw=kw):
            df = pl.DataFrame({"s": starts, "e": ends}).with_columns(pl.col("s").str.to_date(), pl.col("e").str.to_date())
            e = pl.business_day_count(pl.col("s"), pl.col("e"), **kw)
            params = {}
            if "holidays" in kw:
                params["holidays"] = [d.isoformat() for d in kw["holidays"]]
            if "week_mask" in kw:
                params["week_mask"] = list(kw["week_mask"])
            case(f"business_day_count-{tag}", "expr", "polars", pl_eval(df, e), op="business_day_count", cols={"s": starts, "e": ends}, **params)
        run(f"bdc-{tag}", f7)

    secs = [0, 1700000000, -86400, None, 253402300799]
    for unit in ["s", "ms", "us", "d"]:
        def f8(unit=unit):
            vals = secs if unit != "d" else [0, 19000, -1, None, 100]
            vals = vals if unit != "ms" else [0, 1700000000123, -1, None, 5]
            vals = vals if unit != "us" else [0, 1700000000123456, -1, None, 5]
            df = pl.DataFrame({"x": vals}, schema={"x": pl.Int64})
            e = pl.from_epoch(pl.col("x"), time_unit=unit)
            case(f"from_epoch-{unit}", "expr", "polars", pl_eval(df, e), op="from_epoch", unit=unit, cols={"x": vals})
        run(f"from_epoch-{unit}", f8)

    ys = [2024, 2023, 1970, 2000, None]
    ms = [2, 12, 1, 2, 3]
    ds = [29, 31, 1, 29, 1]

    def f9():
        df = pl.DataFrame({"y": ys, "m": ms, "d": ds}, schema={"y": pl.Int64, "m": pl.Int64, "d": pl.Int64})
        case("make_date", "expr", "polars", pl_eval(df, pl.date(pl.col("y"), pl.col("m"), pl.col("d"))), op="make_date", cols={"y": ys, "m": ms, "d": ds})
    run("make_date", f9)

    hs = [0, 23, 12, 1, 5]
    mi = [0, 59, 30, 2, 0]
    ss = [0, 59, 15, 3, 0]
    us = [0, 999999, 5, 4, 0]

    def f10():
        df = pl.DataFrame({"y": ys, "m": ms, "d": ds, "h": hs, "mi": mi, "s": ss, "us": us}, schema={k: pl.Int64 for k in ["y", "m", "d", "h", "mi", "s", "us"]})
        case("make_datetime", "expr", "polars", pl_eval(df, pl.datetime(pl.col("y"), pl.col("m"), pl.col("d"), pl.col("h"), pl.col("mi"), pl.col("s"), pl.col("us"))), op="make_datetime", cols={"y": ys, "m": ms, "d": ds, "h": hs, "mi": mi, "s": ss, "us": us})
    run("make_datetime", f10)

    wk = [0, 1, None, -1, 2]
    dy = [1, 0, 3, 0, -5]

    def f11():
        df = pl.DataFrame({"w": wk, "d": dy, "h": [1, 2, 3, 4, 5]}, schema={"w": pl.Int64, "d": pl.Int64, "h": pl.Int64})
        case("make_duration", "expr", "polars", pl_eval(df, pl.duration(weeks=pl.col("w"), days=pl.col("d"), hours=pl.col("h"))), op="make_duration", cols={"w": wk, "d": dy, "h": [1, 2, 3, 4, 5]})
    run("make_duration", f11)

    xs = [2.675, -2.675, 1.005, 0.5, -0.5, 123.456, -123.456, 7.0, None]
    for d in [0, 1, 2, -1]:
        def f12(d=d):
            out = [None if x is None else float(np.trunc(x * 10.0 ** d) / 10.0 ** d) for x in xs]
            case(f"trunc_decimals-{d}", "expr", "numpy", out, op="trunc_decimals", decimals=d, cols={"x": xs})
        run(f"trunc-{d}", f12)


# ── constructors ─────────────────────────────────────────────────────────────

def g_ctor():
    def ir(args):
        s, e, st = args
        case(f"int_range-{s}-{e}-{st}", "ctor", "polars", pl.select(pl.int_range(s, e, st)).to_series().to_list(), fn="intRange", args=list(args))
    for args in [(0, 10, 1), (0, 10, 3), (5, 0, -2), (5, 0, 1), (0, 0, 1), (-3, 3, 2)]:
        run(f"int_range{args}", lambda args=args: ir(args))

    def irs():
        s = [0, 2, None, 5]
        e = [3, 2, 4, 3]
        out = pl.select(pl.int_ranges(pl.lit(pl.Series(s, dtype=pl.Int64)), pl.lit(pl.Series(e, dtype=pl.Int64)))).to_series().to_list()
        case("int_ranges", "ctor", "polars", out, fn="intRanges", args=[s, e, 1])
    run("int_ranges", irs)

    for closed in ["both", "left", "right", "none"]:
        for (lo, hi, n) in [(0.0, 1.0, 5), (0.1, 0.7, 4), (0.0, 1.0, 1), (0.0, 1.0, 0), (-2.0, 2.0, 3)]:
            def ls(closed=closed, lo=lo, hi=hi, n=n):
                out = pl.select(pl.linear_space(lo, hi, n, closed=closed)).to_series().to_list()
                case(f"linear_space-{closed}-{lo}-{hi}-{n}", "ctor", "polars", cells(out), fn="linearSpace", args=[lo, hi, n, closed])
            run(f"linear_space-{closed}-{n}", ls)

    def dr(id, start, end, interval, closed):
        out = pl.date_range(start, end, interval, closed=closed, eager=True).to_list()
        case(id, "ctor", "polars", cells(out), fn="dateRange", args=[start.isoformat(), end.isoformat(), interval, closed])
    D = dt.date
    for id, st, en, iv, cl in [
        ("date_range-day", D(2024, 1, 1), D(2024, 1, 5), "1d", "both"),
        ("date_range-2d-left", D(2024, 1, 1), D(2024, 1, 7), "2d", "left"),
        ("date_range-2d-right", D(2024, 1, 1), D(2024, 1, 7), "2d", "right"),
        ("date_range-2d-none", D(2024, 1, 1), D(2024, 1, 7), "2d", "none"),
        ("date_range-week", D(2024, 1, 1), D(2024, 2, 20), "1w", "both"),
        ("date_range-month-end", D(2024, 1, 31), D(2024, 6, 30), "1mo", "both"),
        ("date_range-quarter", D(2024, 1, 15), D(2025, 1, 15), "1q", "both"),
        ("date_range-year-leap", D(2020, 2, 29), D(2024, 3, 1), "1y", "both"),
        ("date_range-empty", D(2024, 1, 5), D(2024, 1, 1), "1d", "both"),
        ("date_range-same", D(2024, 1, 5), D(2024, 1, 5), "1d", "both"),
        ("date_range-same-left", D(2024, 1, 5), D(2024, 1, 5), "1d", "left"),
    ]:
        run(id, lambda id=id, st=st, en=en, iv=iv, cl=cl: dr(id, st, en, iv, cl))

    def dtr(id, start, end, interval, closed):
        out = pl.datetime_range(start, end, interval, closed=closed, eager=True, time_unit="us").to_list()
        case(id, "ctor", "polars", cells(out), fn="datetimeRange", args=[start.isoformat(), end.isoformat(), interval, closed])
    T = dt.datetime
    for id, st, en, iv, cl in [
        ("datetime_range-6h", T(2024, 1, 1), T(2024, 1, 2), "6h", "both"),
        ("datetime_range-90m-left", T(2024, 1, 1, 0, 30), T(2024, 1, 1, 6, 0), "90m", "left"),
        ("datetime_range-90m-right", T(2024, 1, 1, 0, 30), T(2024, 1, 1, 6, 0), "90m", "right"),
        ("datetime_range-month", T(2024, 1, 31, 12), T(2024, 5, 31, 12), "1mo", "both"),
        ("datetime_range-ms", T(2024, 1, 1), T(2024, 1, 1, 0, 0, 0, 3000), "1ms", "both"),
        ("datetime_range-none", T(2024, 1, 1), T(2024, 1, 1, 3), "1h", "none"),
    ]:
        run(id, lambda id=id, st=st, en=en, iv=iv, cl=cl: dtr(id, st, en, iv, cl))

    def pdr(id, fn, start, freq, periods, business):
        if business:
            out = pd.bdate_range(start, periods=periods, freq=freq).tolist() if freq else pd.bdate_range(start, periods=periods).tolist()
        else:
            out = pd.date_range(start, periods=periods, freq=freq).tolist()
        vals = [cell(x) if fn == "datetimeRangePeriods" else pd.Timestamp(x).date().isoformat() for x in out]
        iv = {"2D": "2d", "7h": "7h", "ME": "1mo", "B": "1d"}[freq]
        case(id, "ctor", "pandas", vals, fn=fn, args=[start, periods, iv, business])
    run("pd-date_range-periods", lambda: pdr("pd-date_range-periods", "dateRangePeriods", "2024-01-01", "2D", 4, False))
    run("pd-date_range-hours", lambda: pdr("pd-date_range-hours", "datetimeRangePeriods", "2024-01-01 05:00:00", "7h", 5, False))
    run("pd-date_range-month-end-start", lambda: pdr("pd-date_range-month", "dateRangePeriods", "2024-01-31", "ME", 4, False))
    run("pd-bdate-weekend", lambda: pdr("pd-bdate-weekend", "dateRangePeriods", "2024-01-06", "B", 7, True))
    run("pd-bdate-friday", lambda: pdr("pd-bdate-friday", "dateRangePeriods", "2024-01-05", "B", 5, True))

    def bd(id, start, end, closed):
        out = pd.bdate_range(start, end, inclusive=closed).tolist()
        case(id, "ctor", "pandas", [pd.Timestamp(x).date().isoformat() for x in out], fn="dateRangeBusiness", args=[start, end, "1d", closed])
    run("bdate-range", lambda: bd("bdate_range", "2024-01-05", "2024-01-22", "both"))
    run("bdate-range-left", lambda: bd("bdate_range-left", "2024-01-05", "2024-01-22", "left"))

    def sp(id, start, end, periods):
        out = pd.date_range(start, end, periods=periods).tolist()
        case(id, "ctor", "pandas", cells(out), fn="datetimeSpace", args=[start, end, periods])
    run("space", lambda: sp("pd-date_range-space", "2024-01-01", "2024-01-02", 4))
    run("space7", lambda: sp("pd-date_range-space7", "2024-01-01 00:00:00", "2024-01-01 00:00:01", 7))

    case("ones-int", "ctor", "numpy", [1, 1, 1], fn="ones", args=[3, False])
    case("zeros-float", "ctor", "numpy", [0.0, 0.0], fn="zeros", args=[2, True])


# ── frame cases ──────────────────────────────────────────────────────────────

def g_frame():
    xs = [1.0, 2.0, 2.5, 3.0, None, 10.0, 0.0, 4.0]

    def h(id, **kw):
        out = pl.Series("x", xs).hist(**kw)
        case(id, "frame", "polars", {k: cells(out[k].to_list()) if k != "category" else [str(c) for c in out[k].to_list()] for k in out.columns}, fn="hist", col={"x": xs}, args=kw)
    run("hist-edges", lambda: h("hist-edges", bins=[0, 2, 4, 10]))
    run("hist-count3", lambda: h("hist-count3", bin_count=3))
    run("hist-count4", lambda: h("hist-count4", bin_count=4))
    run("hist-nocat", lambda: h("hist-nocat", bins=[0, 5, 10], include_category=False))

    def hconst():
        out = pl.Series("x", [5.0, 5.0, None]).hist(bin_count=2)
        case("hist-const", "frame", "polars", {k: cells(out[k].to_list()) if k != "category" else [str(c) for c in out[k].to_list()] for k in out.columns}, fn="hist", col={"x": [5.0, 5.0, None]}, args={"bin_count": 2})
    run("hist-const", hconst)

    def uc():
        v = [3, 1, 3, None, 1, 3]
        case("unique_counts", "frame", "polars", {"x": cells(pl.Series("x", v).unique_counts().to_list())}, fn="uniqueCounts", col={"x": v}, args={})
        t = ["b", "a", "b", "b", None, None]
        case("unique_counts-text", "frame", "polars", {"x": cells(pl.Series("x", t).unique_counts().to_list())}, fn="uniqueCounts", col={"x": t}, args={})
    run("unique_counts", uc)

    def cs():
        d = {"a": [1, None, 3, 4], "b": [None, 2, 4, 5], "c": [3, 4, None, 6]}
        out = pl.DataFrame(d).select(pl.cum_sum_horizontal("a", "b", "c").struct.unnest())
        case("cum_sum_horizontal", "frame", "polars", {k: cells(out[k].to_list()) for k in out.columns}, fn="cumSumHorizontal", cols=d, args={})
    run("cum_sum_horizontal", cs)

    def al():
        f1 = {"k": [3, 1, 2], "u": ["a", "b", "c"]}
        f2 = {"k": [2, 5], "v": [10.0, 50.0]}
        for rev in [False, True]:
            out = pl.align_frames(pl.DataFrame(f1), pl.DataFrame(f2), on="k", descending=rev)
            case(f"align_frames-{rev}", "frame", "polars", [{k: cells(o[k].to_list()) for k in o.columns} for o in out], fn="alignFrames", frames=[f1, f2], args={"on": ["k"], "reverse": rev})
    run("align_frames", al)

    def nm():
        cols = ["abab", "Cde", "x_y", "Hello World", "A1"]
        df = pl.DataFrame({c: [1] for c in cols})
        for tag, e, args in [
            ("lower", pl.all().name.to_lowercase(), {"op": "lower"}),
            ("upper", pl.all().name.to_uppercase(), {"op": "upper"}),
            ("replace-regex", pl.all().name.replace("[ab]", "Z"), {"op": "replace", "pattern": "[ab]", "with": "Z", "literal": False}),
            ("replace-literal", pl.all().name.replace("ab", "$1", literal=True), {"op": "replace", "pattern": "ab", "with": "$1", "literal": True}),
            ("replace-group", pl.all().name.replace("(.)_(.)", "$2-$1"), {"op": "replace", "pattern": "(.)_(.)", "with": "$2-$1", "literal": False}),
        ]:
            run(f"names-{tag}", lambda tag=tag, e=e, args=args: case(f"names-{tag}", "frame", "polars", df.select(e).columns, fn="names", cols=cols, args=args))
        out = pd.DataFrame({c: [1] for c in cols}).rename(columns=lambda c: c.replace("_", "").upper())
        case("names-pandas-rename-func", "frame", "pandas", list(out.columns), fn="names", cols=cols, args={"op": "func_strip_us_upper"})
    run("names", nm)

    def sel():
        names = ["abc", "ab1", "123", "a b", "", "ABC", "x_y"]
        # a column named "" is refused by both engines' frames; keep to non-empty names
        names = [n for n in names if n]
        df = pl.DataFrame({n: [1] for n in names})
        import polars.selectors as cs
        for tag, s in [("alpha", cs.alpha()), ("alphanumeric", cs.alphanumeric()), ("digit", cs.digit())]:
            run(f"sel-{tag}", lambda tag=tag, s=s: case(f"selector-{tag}", "frame", "polars", df.select(s).columns, fn="selector", cols=names, args={"op": tag}))
    run("selectors", sel)


g_expr()
g_ctor()
g_frame()
for p in problems:
    print("PROBLEM", p, file=sys.stderr)
print(f"{len(cases)} cases, {len(problems)} problems", file=sys.stderr)
with open(sys.argv[1], "w") as fh:
    json.dump(cases, fh, indent=1)
    fh.write("\n")
