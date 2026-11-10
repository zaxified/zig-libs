#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for dataframe S2 wave W10, the cheap parity gaps: polars 2.1 `str.find`,
pandas 3.1 `corrwith`, polars `struct.json_encode`, `DataFrame.unstack`, pandas `wide_to_long`,
polars `bin_intervals`/`bin_quantiles`/`bin_ranks` and `dt.offset_by` on a zoned column, frozen
into src/oracle2i_vectors.json and replayed by src/s2w10_oracle_test.zig. No line of dataframe
is consulted here: the expected values are what the engines answer.

    python tools/oracle2i.py src/oracle2i_vectors.json      (see tools/README.md)

Where pandas and polars both have a function and disagree, both answers are written (`-pd`,
`-pl`) and the replay's `known` list says which one dataframe follows. A case an engine raises
on is recorded with `"error": true` when the error is the answer (an invalid pattern, rows that
do not identify themselves) and reported on stderr otherwise. pandas' `corrwith(method="spearman")`
needs SciPy, which is not installed: the Spearman answer is taken from pandas' own
`DataFrame.corr(method="spearman")` over the two columns side by side (`pandas-recipe`).
"""
import json
import math
import sys

import numpy as np
import pandas as pd
import polars as pl

cases = []
problems = []
notes = []


def case(id, kind, engine, expect, **kw):
    cases.append({"id": id, "kind": kind, "engine": engine, "expect": expect, **kw})


def run(id, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{id}: {type(e).__name__}: {str(e)[:160]}")


def cell(v):
    if v is None or v is pd.NA or v is pd.NaT:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        return None if math.isnan(v) else float(v)
    if isinstance(v, (dict,)):
        return {k: cell(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [cell(x) for x in v]
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


# ── str.find (polars) ───────────────────────────────────────────────────────────────────────────

TEXTS = ["aé1b22", "abc", None, "", "ñ9", "日本語 123", "xx", "a.b", "  lead", "😀x9", "ABC", "a\nb", "é", "9é9"]


def g_find():
    df = pl.DataFrame({"x": TEXTS}, schema={"x": pl.String})
    for i, (pat, lit) in enumerate([
        (r"\d", False), (r"\d+$", False), ("b", False), ("é", False), ("", False), (r"(?i)abc", False),
        (r"^$", False), (r"x*", False), (".", True), ("a.b", True), (r"\w+", False), (r"[é9]", False),
        ("", True), ("b2", True), (r"(?m)^b", False), (r"\bx", False), (r".$", False),
    ]):
        def one(i=i, pat=pat, lit=lit):
            r = df.select(pl.col("x").str.find(pat, literal=lit).alias("o"))["o"].to_list()
            case(f"find-{i}-pl", "expr", "polars", cells(r), op="find", pattern=pat, literal=lit, cols={"x": TEXTS})
        run(f"find-{i}", one)

    def bad():
        try:
            df.select(pl.col("x").str.find("[").alias("o"))
        except Exception as e:  # noqa: BLE001
            case("find-bad-pl", "expr", "polars", None, op="find", pattern="[", literal=False, cols={"x": TEXTS}, error=True)
            notes.append(f"find invalid pattern raises {type(e).__name__}")
            return
        problems.append("find invalid pattern did not raise")
    run("find-bad", bad)

    def pdfind():
        # pandas `str.find` is literal, counts characters and answers -1; kept for the notes.
        s = pd.Series(TEXTS, dtype=pd.StringDtype("python", na_value=pd.NA))
        for i, sub in enumerate(["b", "é", "9", "x"]):
            case(f"find-lit{i}-pd", "expr", "pandas", cells(s.str.find(sub).tolist()), op="find", pattern=sub, literal=True, cols={"x": TEXTS})
    run("find-pd", pdfind)


# ── corrwith (pandas) ───────────────────────────────────────────────────────────────────────────

def frame_json(d):
    return {"names": list(d.keys()), "cols": [cells(v) for v in d.values()]}


def g_corrwith():
    nan = float("nan")
    A = {"x": [1, 2, 3, 4, 5.0], "y": [2, 1, 4, 3, nan], "z": [1, 1, 1, 1, 1], "zl": [5, 4, 3, 2, 9.0], "i": [1, 2, 3, 4, 6]}
    B = {"x": [5, 3, 4, 1, 2.0], "y": [1, 2, 3, 4, 5], "ar": [1, 2, 3, 4, 5], "z": [1, 2, 3, 4, 5], "i": [2, 1, 4, 3, 5]}
    C = {"x": [1.0, nan, 3, 4, 5, 7, 9], "k": [1, 2, 3, 4, 5, 6, 7], "t": [3, 3, 1, 2, 2, 5, 6.0]}
    D = {"x": [2.0, 1, nan, 5, 4, 3, 8], "k": [7, 6, 5, 4, 3, 2, 1], "t": [1, 2, 3, 4, 5, 6, 8.0]}
    for name, L, R in (("a", A, B), ("c", C, D)):
        pl_, pr_ = pd.DataFrame(L), pd.DataFrame(R)

        def one(name=name, L=L, R=R, pl_=pl_, pr_=pr_):
            for drop in (False, True):
                r = pl_.corrwith(pr_, drop=drop)
                case(f"corrwith-{name}-drop{int(drop)}", "corrwith", "pandas", {"names": [str(k) for k in r.index], "corr": cells(r.tolist())},
                     left=frame_json(L), right=frame_json(R), method="pearson", drop=drop)
            shared = [c for c in L if c in R]
            rho = []
            for c in shared:
                both = pd.concat([pl_[c].rename("l"), pr_[c].rename("r")], axis=1)
                rho.append(both.corr(method="spearman").iloc[0, 1])
            names = shared + sorted(set(L) ^ set(R))
            rho = rho + [None] * (len(names) - len(shared))
            case(f"corrwith-{name}-spearman", "corrwith", "pandas-recipe", {"names": names, "corr": cells(rho)},
                 left=frame_json(L), right=frame_json(R), method="spearman", drop=False)
        run(f"corrwith-{name}", one)

    def mismatch():
        try:
            pd.DataFrame(A).corrwith(pd.DataFrame(B).iloc[:3])
        except Exception as e:  # noqa: BLE001
            notes.append(f"corrwith length mismatch raises {type(e).__name__}")
            return
        notes.append("corrwith of different lengths aligns on the row index (pandas): dataframe has no index, so it refuses; known")
    run("corrwith-mismatch", mismatch)


# ── struct.json_encode (polars) ─────────────────────────────────────────────────────────────────

def g_json():
    rows = [
        {"x": 1, "y": "q\"é\n"}, None, {"x": None, "y": None}, {"x": 7, "y": "日本 \\ / \t"}, {"x": -3, "y": ""},
    ]
    df = pl.DataFrame({"a": rows}, schema={"a": pl.Struct({"x": pl.Int64, "y": pl.String})})

    def one():
        r = df.select(pl.col("a").struct.json_encode().alias("o"))["o"].to_list()
        case("json-ints-pl", "json_encode", "polars", cells(r), cols={"a": rows}, fields=[["x", "int"], ["y", "text"]])
    run("json-ints", one)
    rows2 = [{"f": 1.5, "b": True, "l": [1, 2]}, {"f": 2.0, "b": False, "l": []}, {"f": float("nan"), "b": None, "l": None},
             {"f": 1e20, "b": True, "l": [4]}, {"f": -0.0, "b": False, "l": [5]}]
    df2 = pl.DataFrame({"a": rows2}, schema={"a": pl.Struct({"f": pl.Float64, "b": pl.Boolean, "l": pl.List(pl.Int64)})})

    def two():
        r = df2.select(pl.col("a").struct.json_encode().alias("o"))["o"].to_list()
        case("json-mixed-pl", "json_encode", "polars", cells(r), cols={"a": [{k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in x.items()} for x in rows2]},
             fields=[["f", "float"], ["b", "bool"], ["l", "list"]], nan_field="f")
        notes.append(f"json_encode floats: {r}")
    run("json-mixed", two)
    rows_e = [{"f": 1e-7}, {"f": 1.5e-10}, {"f": 12345678.9}]
    dfe = pl.DataFrame({"a": rows_e}, schema={"a": pl.Struct({"f": pl.Float64})})

    def expo():
        r = dfe.select(pl.col("a").struct.json_encode().alias("o"))["o"].to_list()
        case("json-float-exp-pl", "json_encode", "polars", cells(r), cols={"a": rows_e}, fields=[["f", "float"]])
    run("json-float-exp", expo)
    rows3 = [{"a": {"b": 1, "c": [{"d": "x"}]}, "e": None}, {"a": None, "e": 2}]
    df3 = pl.DataFrame({"a": rows3}, schema={"a": pl.Struct({"a": pl.Struct({"b": pl.Int64, "c": pl.List(pl.Struct({"d": pl.String}))}), "e": pl.Int64})})

    def three():
        r = df3.select(pl.col("a").struct.json_encode().alias("o"))["o"].to_list()
        case("json-nested-pl", "json_encode", "polars", cells(r), cols={"a": rows3}, fields=[["a", "record"], ["e", "int"]])
    run("json-nested", three)


# ── unstack (polars) ────────────────────────────────────────────────────────────────────────────

def g_unstack():
    ints = list(range(23))
    base = {"a": [1, 2, 3, 4, 5], "b": ["x", "y", "z", "w", "v"]}
    wide = {"a": ints, "b": [str(i) for i in ints]}
    nul = {"a": [1, None, 3], "f": [1.5, 2.5, None], "t": [True, None, False]}

    def types(d):
        out = []
        for v in d.values():
            s = pl.Series(v)
            out.append({pl.Int64: "int", pl.String: "text", pl.Float64: "float", pl.Boolean: "bool"}.get(s.dtype, "int"))
        return out

    def add(id, d, **kw):
        def one():
            df = pl.DataFrame(d)
            r = df.unstack(**{k: v for k, v in kw.items() if k != "_spec"})
            out = {"names": r.columns, "cols": [cells(r[c].to_list()) for c in r.columns]}
            spec = dict(kw)
            case(id, "unstack", "polars", out, frame={"names": list(d.keys()), "types": types(d), "cols": [cells(v) for v in d.values()]}, spec=spec)
        run(id, one)

    add("unstack-v2", base, step=2)
    add("unstack-h2", base, step=2, how="horizontal")
    add("unstack-h3-fill", base, step=3, how="horizontal", fill_values=0)
    add("unstack-cols", base, step=2, columns="a")
    add("unstack-cols-fill", base, step=2, columns="a", how="horizontal", fill_values=[-1])
    add("unstack-big", base, step=7)
    add("unstack-fill-list", base, step=2, fill_values=[0, "q"])
    add("unstack-order", base, step=3, columns=["b", "a"])
    add("unstack-pad-v", wide, step=2)
    add("unstack-pad-h", wide, step=2, how="horizontal")
    add("unstack-1", wide, step=1, how="horizontal")
    add("unstack-all", wide, step=23)
    add("unstack-100h", wide, step=100, how="horizontal")
    add("unstack-nul-v", nul, step=2, fill_values=[7, 0.5, True])
    add("unstack-nul-h", nul, step=2, how="horizontal", fill_values=9)
    add("unstack-nul-none", nul, step=2)
    for st in (0,):
        def bad(st=st):
            try:
                pl.DataFrame(base).unstack(step=st)
            except Exception as e:  # noqa: BLE001
                notes.append(f"unstack step={st} raises {type(e).__name__}")
        run(f"unstack-bad{st}", bad)
    add_err = []
    for id, d, kw in (("unstack-err-fillcount", nul, dict(step=2, fill_values=[1])), ("unstack-err-nocol", nul, dict(step=2, columns="zz"))):
        def one(id=id, d=d, kw=kw):
            try:
                pl.DataFrame(d).unstack(**kw)
            except Exception as e:  # noqa: BLE001
                case(id, "unstack", "polars", None, frame={"names": list(d.keys()), "types": types(d), "cols": [cells(v) for v in d.values()]}, spec=kw, error=True)
                return
            problems.append(id + " did not raise")
        run(id, one)


# ── wide_to_long (pandas) ───────────────────────────────────────────────────────────────────────

def g_wide():
    def add(id, d, stubs, i, j="year", sep="", suffix=r"\d+"):
        def one():
            df = pd.DataFrame(d)
            r = pd.wide_to_long(df, stubs, i=i, j=j, sep=sep, suffix=suffix).reset_index()
            out = {"names": [str(c) for c in r.columns], "cols": [cells(r[c].tolist()) for c in r.columns]}
            case(id, "wide_to_long", "pandas", out, frame={"names": list(d.keys()), "cols": [cells(v) for v in d.values()]},
                 stubnames=stubs, i=i if isinstance(i, list) else [i], j=j, sep=sep, suffix=suffix)
        run(id, one)

    nan = float("nan")
    add("w2l-basic", {"id": [1, 2, 3], "A1970": [1.0, 2, 3], "A1980": [4.0, 5, 6], "B1970": [7, 8, 9], "B1980": [10, 11, 12]}, ["A", "B"], "id")
    add("w2l-missing", {"id": [1, 2, 3], "A1970": [1.0, 2, 3], "A1980": [4.0, 5, 6], "A1990": [0.5, nan, 1], "B1970": [7, 8, 9], "B1980": [10, 11, 12]}, ["A", "B"], "id")
    add("w2l-unsorted", {"id": [3, 1, 2], "A1980": [4.0, 5, 6], "A1970": [1.0, 2, 3], "B1970": [7, 8, 9], "B1990": [10, 11, 12]}, ["A", "B"], "id")
    add("w2l-one-other", {"id": [3, 1, 2], "k": ["q", "r", "s"], "A1980": [4.0, 5, 6], "A1970": [1.0, 2, 3], "B1970": [7, 8, 9], "B1990": [10, 11, 12]}, ["A", "B"], "id")
    add("w2l-two-i", {"id": [3, 1, 2], "k": ["q", "r", "s"], "A1980": [4.0, 5, 6], "A1970": [1.0, 2, 3], "B1970": [7, 8, 9], "B1990": [10, 11, 12]}, ["A", "B"], ["id", "k"])
    add("w2l-two-i-swapped", {"id": [3, 1, 2], "k": ["q", "r", "s"], "A1980": [4.0, 5, 6], "A1970": [1.0, 2, 3]}, ["A"], ["k", "id"])
    add("w2l-sep-w", {"id": [1, 2], "A_1": [1, 2], "A_x": [3, 4], "B_1": [5, 6], "B_x": [7, 8]}, ["A", "B"], "id", j="t", sep="_", suffix=r"\w+")
    add("w2l-sep-d", {"id": [1, 2], "A_1": [1, 2], "A_2": [3, 4], "B_1": [5, 6], "B_2": [7, 8]}, ["A", "B"], "id", j="t", sep="_", suffix=r"\d+")
    add("w2l-sep-dot", {"id": [3, 1, 2], "A.a": [4.0, 5, 6], "A.b": [7, 8, 9]}, ["A"], "id", j="y", sep=".", suffix="[a-z]")
    add("w2l-leading-zero", {"id": [3, 1, 2], "A01": [4.0, 5, 6], "A02": [7, 8, 9]}, ["A"], "id")
    add("w2l-stubprefix", {"id": [1, 2], "Ax1": [1, 2], "Ax2": [3, 4], "x1": [5, 6]}, ["Ax"], "id", j="t")
    add("w2l-nonmatch-kept", {"id": [1, 2], "A_1": [1, 2], "A_x": [3, 4]}, ["A"], "id", j="t", sep="_", suffix=r"\d+")
    add("w2l-text-values", {"id": [1, 2], "N1": ["a", "b"], "N2": ["c", None]}, ["N"], "id", j="n")
    add("w2l-float-suffix", {"id": [1, 2], "A1.5": [1, 2], "A2.5": [3, 4]}, ["A"], "id", j="t", suffix=r"\d+\.\d+")
    add("w2l-stub-order", {"id": [1, 2], "A1": [1, 2], "B1": [5, 6], "A2": [3, 4], "B2": [7, 8]}, ["B", "A"], "id", j="t")

    def notunique():
        try:
            pd.wide_to_long(pd.DataFrame({"id": [1, 1], "A1": [1, 2], "A2": [3, 4]}), ["A"], i="id", j="t")
        except Exception as e:  # noqa: BLE001
            case("w2l-notunique", "wide_to_long", "pandas", None, frame={"names": ["id", "A1", "A2"], "cols": [[1, 1], [1, 2], [3, 4]]},
                 stubnames=["A"], i=["id"], j="t", sep="", suffix=r"\d+", error=True)
            return
        problems.append("wide_to_long non-unique did not raise")
    run("w2l-notunique", notunique)


# ── offset_by on a zoned column (polars) ────────────────────────────────────────────────────────

def g_offset():
    plan = [
        ("Europe/Prague", ["2024-03-30 12:00:00", "2024-03-30 02:30:00", "2024-10-26 12:00:00", "2024-10-27 01:30:00", "2024-10-27 03:30:00",
                           "2024-01-31 12:00:00", "2024-03-31 01:59:59", "2024-10-26 02:30:00", "2024-10-26 02:00:00", "2024-10-26 02:59:59",
                           "2024-10-28 02:30:00", "2024-03-30 02:00:00", "2024-03-30 02:59:59", "2024-09-27 02:30:00", "2024-03-31 03:30:00",
                           "2024-12-31 23:59:59", "2024-02-29 08:15:30"],
         ["1d", "-1d", "24h", "1h", "1w", "1mo", "-1mo", "1mo1d", "1d1h", "1h1d", "2d12h", "1y", "1q", "1mo1h", "0d", "30m", "-2d6h", "45s", "3w", "2mo", "1d30m"]),
        ("America/New_York", ["2024-03-09 02:30:00", "2024-11-02 01:30:00", "2024-03-09 12:00:00", "2024-11-03 00:30:00", "2024-03-10 03:30:00", "2024-02-29 12:00:00"],
         ["1d", "1mo", "-1d", "24h", "1d2h", "1w"]),
        ("Australia/Lord_Howe", ["2024-04-05 01:45:00", "2024-10-05 02:15:00", "2024-10-05 12:00:00"], ["1d", "-1d", "24h", "1mo"]),
        ("Asia/Kolkata", ["2024-03-30 12:00:00", "2024-02-29 23:00:00"], ["1d", "1mo", "1h", "1d1h"]),
        ("UTC", ["2024-03-30 12:00:00", "2024-01-31 12:00:00"], ["1d", "1mo", "1h", "1d1h"]),
        # The input itself in a fold, in either pass, and results landing in a fold from either side.
        ("Europe/Prague", ["2024-10-27 02:30:00"], ["0d", "1d", "-1d", "1mo", "-1mo", "1w", "-1w", "1d1h", "24h"], "earliest"),
        ("Europe/Prague", ["2024-10-27 02:30:00"], ["0d", "1d", "-1d", "1mo", "-1mo", "1w", "-1w", "1d1h", "24h"], "latest"),
        ("Europe/Prague", ["2024-10-28 02:30:00", "2024-11-27 02:30:00", "2024-10-20 02:30:00", "2024-09-27 02:30:00", "2024-10-26 02:30:00"],
         ["-1d", "-1mo", "1w", "1mo", "1d", "-1w", "7d"]),
        ("Australia/Lord_Howe", ["2024-04-06 01:45:00", "2024-04-08 01:45:00"], ["1d", "-1d"]),
        ("Australia/Lord_Howe", ["2024-04-07 01:45:00"], ["1d", "-1d", "0d"], "latest"),
    ]
    for entry in plan:
        zone, locals_, bys = entry[:3]
        amb = entry[3] if len(entry) > 3 else "earliest"
        s = pl.Series(locals_).str.to_datetime("%Y-%m-%d %H:%M:%S").dt.replace_time_zone(zone, ambiguous=amb, non_existent="null")
        # Inputs that name no instant (a gap) are left out: the test needs the instants.
        keep = [x for x in s.to_list() if x is not None]
        s = pl.Series(keep, dtype=pl.Datetime("us", zone)) if keep else s
        inst = [int(v) for v in s.dt.epoch("us").to_list()]
        for by in bys:
            def one(zone=zone, by=by, s=s, inst=inst, amb=amb):
                r = pl.DataFrame({"t": s}).select(pl.col("t").dt.offset_by(by).dt.epoch("us").alias("o"))["o"].to_list()
                case(f"offset-{zone}-{by}-{amb}-{len(inst)}", "offset_by_tz", "polars", cells(r), zone=zone, by=by, inst=inst)
            run(f"offset-{zone}-{by}-{amb}", one)


# ── bin_intervals / bin_quantiles / bin_ranks (polars) ──────────────────────────────────────────

def g_bins():
    ints = list(range(11))
    flt = [-2.0, -1, 0, 1, 2, None, 5, 1.5]
    tie = [1, 1, 2, 2, 3, 3, 3, 10]
    shuf = [3.0, 1, 2, None, 2, 1]
    one = [4.0]
    txt = ["a", "c", "b", "e", None]
    dtypes = {"int": pl.Int64, "float": pl.Float64, "text": pl.String}

    def add(id, vals, ty, op, arg, labels=False, inc=False, right=False, expect_error=False):
        def one_case():
            df = pl.DataFrame({"x": vals}, schema={"x": dtypes[ty]})
            kw = dict(labels=labels if labels else False, include_intervals=inc)
            if op != "ranks":
                kw["right_closed"] = right
            f = {"intervals": pl.Expr.bin_intervals, "quantiles": pl.Expr.bin_quantiles, "ranks": pl.Expr.bin_ranks}[op]
            spec = {"op": op, "arg": arg, "labels": labels or None, "include_intervals": inc, "right_closed": right}
            frame = {"names": ["x"], "types": [ty], "cols": [cells(vals)]}
            try:
                r = df.select(f(pl.col("x"), arg, **kw).alias("o"))["o"].to_list()
            except Exception as e:  # noqa: BLE001
                if expect_error:
                    case(id, "bins", "polars", None, frame=frame, spec=spec, error=True)
                    return
                raise
            if expect_error:
                problems.append(id + " did not raise")
                return
            case(id, "bins", "polars", cells(r), frame=frame, spec=spec)
        run(id, one_case)

    add("bi-lab", flt, "float", "intervals", [-1, 1], labels=["a", "b", "c"])
    add("bi-idx", flt, "float", "intervals", [-1, 1])
    add("bi-right", flt, "float", "intervals", [-1, 1], right=True)
    add("bi-inc", flt, "float", "intervals", [-1, 1], labels=["a", "b", "c"], inc=True)
    add("bi-inc-idx", flt, "float", "intervals", [-1, 1], inc=True)
    add("bi-n3", flt, "float", "intervals", 3)
    add("bi-n3-lab", flt, "float", "intervals", 3, labels=["x", "y", "z"])
    add("bi-n1", flt, "float", "intervals", 1)
    add("bi-empty", flt, "float", "intervals", [], labels=["only"])
    add("bi-equal", flt, "float", "intervals", [1, 1])
    add("bi-n0", flt, "float", "intervals", 0, expect_error=True)
    add("bi-badlab", flt, "float", "intervals", [-1, 1], labels=["a"], expect_error=True)
    add("bi-duplab", flt, "float", "intervals", [-1, 1], labels=["a", "a", "b"], expect_error=True)
    add("bi-desc", ints, "int", "intervals", [5, 2], expect_error=True)
    for n in (3, 4, 7):
        add(f"bi-int-n{n}", ints, "int", "intervals", n)
        add(f"bi-int-n{n}-right", ints, "int", "intervals", n, right=True)
        add(f"bi-int-n{n}-inc", ints, "int", "intervals", n, inc=True)
        add(f"bi-int-n{n}-inc-right", ints, "int", "intervals", n, inc=True, right=True)
    add("bi-int-float-breaks", tie, "int", "intervals", [1.5])
    add("bi-ties", tie, "int", "intervals", [2, 3], labels=list("abc"), inc=True)
    add("bi-ties-right", tie, "int", "intervals", [2, 3], labels=list("abc"), inc=True, right=True)
    add("bi-float-int-breaks-inc", [1.0, 2.0], "float", "intervals", [1], inc=True)
    add("bi-text", txt, "text", "intervals", ["b", "d"], labels=list("xyz"))
    add("bi-text-n", txt, "text", "intervals", 2, expect_error=True)
    add("bi-one", one, "float", "intervals", 2)
    add("bi-bign", [1.0, 2.0], "float", "intervals", 1000000)
    add("bi-n-neg", [1.0, 2.0], "float", "intervals", -1, expect_error=True)
    add("bi-null-only", [None, None], "float", "intervals", 2)
    add("bi-empty-frame", [], "float", "intervals", 2)

    add("bq-list", flt, "float", "quantiles", [0.25, 0.75])
    add("bq-n4", flt, "float", "quantiles", 4)
    add("bq-n4-lab", flt, "float", "quantiles", 4, labels=list("abcd"))
    add("bq-inc", flt, "float", "quantiles", 2, inc=True)
    add("bq-right", flt, "float", "quantiles", [0.5], right=True)
    add("bq-decreasing", flt, "float", "quantiles", [0.5, 0.2], expect_error=True)
    add("bq-range", flt, "float", "quantiles", [1.5], expect_error=True)
    add("bq-empty", flt, "float", "quantiles", [])
    add("bq-ints", tie, "int", "quantiles", [0.1, 0.25, 0.75])
    add("bq-ints-inc", tie, "int", "quantiles", 3, labels=list("abc"), inc=True)
    add("bq-text", txt, "text", "quantiles", 2, labels=list("xy"), expect_error=True)
    add("bq-n7", ints, "int", "quantiles", 7)
    add("bq-frac", ints, "int", "quantiles", [0.33, 0.55, 0.999], inc=True)
    add("bq-zero", ints, "int", "quantiles", [0.0], inc=True)
    add("bq-one", ints, "int", "quantiles", [1.0], inc=True)
    add("bq-shuf", shuf, "float", "quantiles", 3)
    add("bq-n0", ints, "int", "quantiles", 0, expect_error=True)
    add("bq-null-only", [None, None], "float", "quantiles", 2)
    for q in (0.29, 0.57, 0.58, 0.07):
        add(f"bq-100-{q}", list(range(100)), "int", "quantiles", [q], inc=True)

    add("br-list", flt, "float", "ranks", [0.25, 0.75])
    add("br-n3", flt, "float", "ranks", 3)
    add("br-lab", flt, "float", "ranks", 2, labels=["lo", "hi"])
    add("br-inc", flt, "float", "ranks", 2, inc=True)
    add("br-equal", flt, "float", "ranks", [0.5, 0.5])
    add("br-n0", flt, "float", "ranks", 0, expect_error=True)
    add("br-n1", flt, "float", "ranks", 1)
    add("br-n20", flt, "float", "ranks", 20)
    add("br-ties", tie, "int", "ranks", [0.25, 0.75])
    add("br-ties-inc", tie, "int", "ranks", 3, labels=list("abc"), inc=True)
    add("br-text", txt, "text", "ranks", 2, labels=list("xy"))
    add("br-shuf", shuf, "float", "ranks", 3)
    add("br-shuf-half", shuf, "float", "ranks", [0.5])
    add("br-empty-frame", [], "float", "ranks", 2)
    add("br-null-only", [None, None], "float", "ranks", 2)
    for n in (4, 7):
        add(f"br-int-n{n}", ints, "int", "ranks", n)
    for r in (0.5, 0.95, 0.99, 0.05, 0.45, 0.09, 0.17, 0.0, 1.0):
        add(f"br-11-{r}", ints, "int", "ranks", [r], inc=True)
    for r in (0.29, 0.57, 0.58, 0.07, 0.28, 0.55):
        add(f"br-100-{r}", list(range(100)), "int", "ranks", [r], inc=True)
    add("br-frac2", ints, "int", "ranks", [0.3, 0.55], inc=True)
    # NaN: polars bins it with the largest values; this module's one missing rule makes it null.
    nanv = [-2.0, -1, 0, 1, 2, None, 5, 1.5, float("nan")]
    for op, arg in (("intervals", [-1, 1]), ("intervals", 3), ("quantiles", 4), ("ranks", 3)):
        def nan_case(op=op, arg=arg):
            df = pl.DataFrame({"x": nanv})
            f = {"intervals": pl.Expr.bin_intervals, "quantiles": pl.Expr.bin_quantiles, "ranks": pl.Expr.bin_ranks}[op]
            r = df.select(f(pl.col("x"), arg, labels=False).alias("o"))["o"].to_list()
            case(f"nan-{op}-{arg}", "bins", "polars", cells(r), frame={"names": ["x"], "types": ["float"], "cols": [[None if (isinstance(v, float) and math.isnan(v)) else v for v in nanv]]}, spec={"op": op, "arg": arg, "labels": None, "include_intervals": False, "right_closed": False}, nan_at=[8])
        run(f"nan-{op}", nan_case)


for g in (g_find, g_corrwith, g_json, g_unstack, g_wide, g_offset, g_bins):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{g.__name__}: {type(e).__name__}: {e}")

out = sys.argv[1] if len(sys.argv) > 1 else "oracle2i_vectors.json"
with open(out, "w") as fh:
    json.dump(cases, fh, indent=0, ensure_ascii=False)
    fh.write("\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for n in notes:
    sys.stderr.write("NOTE " + n + "\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
