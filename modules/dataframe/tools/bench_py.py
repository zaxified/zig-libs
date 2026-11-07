#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Foreign side of `zig build bench-dataframe`: pandas, polars or DuckDB timing one
verb over the tables `tools/bench.zig` wrote, one thread each.

usage: bench_py.py <pandas|polars|duckdb> <work dir> <workload>
stdout: `name TAB ns/op TAB count` (testkit.bench's format); stderr: the banner.

Only the operation is timed: tables are loaded before the clock starts, and the
result is forced to a materialized table (all three engines). Batch doubling
over 100 ms, then best of five, as testkit.bench does for our side. The count
is output rows + |floor(sum of one output column)|; values are multiples of
0.25, so an exact sum agrees across engines or the run fails.

Order contracts: pandas groupby `sort=False` is first-seen order, like ours;
polars `group_by` without `maintain_order` and DuckDB's GROUP BY are unordered, a
weaker contract than ours, which favours them. Sort is stable on all sides.
"""
import math
import os
import sys
import time

os.environ["POLARS_MAX_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["ARROW_NUM_THREADS"] = "1"
import numpy as np  # noqa: E402

engine, work, name = sys.argv[1], sys.argv[2], sys.argv[3]


def cols():
    c = {}
    for k in ("k_int", "k2", "k_hi", "n"):
        c[k] = np.fromfile(f"{work}/{k}.i64", dtype=np.int64)
    for k in ("v", "w"):
        c[k] = np.fromfile(f"{work}/{k}.f64", dtype=np.float64)
    c["k_nul"] = np.fromfile(f"{work}/k_nul.f64", dtype=np.float64)
    with open(f"{work}/k_txt.txt") as f:
        c["k_txt"] = f.read().split("\n")[:-1]
    r = {
        "k_hi": np.fromfile(f"{work}/r_k_hi.i64", dtype=np.int64),
        "rv": np.fromfile(f"{work}/r_rv.f64", dtype=np.float64),
    }
    t = {"k_txt": None, "tv": np.fromfile(f"{work}/t_tv.f64", dtype=np.float64)}
    with open(f"{work}/t_k_txt.txt") as f:
        t["k_txt"] = f.read().split("\n")[:-1]
    return c, r, t


def cnt(rows, s):
    s = 0.0 if s is None or (isinstance(s, float) and math.isnan(s)) else float(s)
    return int(rows) + int(abs(math.floor(s)))


def pandas_ops(c, r, t):
    import pandas as pd

    sys.stderr.write(f"pandas {pd.__version__}\n")
    L = pd.DataFrame({k: (pd.array(v, dtype="str") if k == "k_txt" else v) for k, v in c.items()})
    R = pd.DataFrame(r)
    T = pd.DataFrame({"k_txt": pd.array(t["k_txt"], dtype="str"), "tv": t["tv"]})

    def g1():
        o = L.groupby("k_int", sort=False).agg(s=("v", "sum"), m=("w", "mean"))
        return cnt(len(o), o["s"].sum())

    def g1n():
        o = L.groupby("k_nul", sort=False, dropna=False).agg(s=("v", "sum"), m=("w", "mean"))
        return cnt(len(o), o["s"].sum())

    def g2():
        o = L.groupby("k_hi", sort=False).agg(s=("v", "sum"))
        return cnt(len(o), o["s"].sum())

    def g3():
        o = L.groupby("k_txt", sort=False).agg(s=("v", "sum"), m=("w", "mean"))
        return cnt(len(o), o["s"].sum())

    def g4():
        o = L.groupby(["k_int", "k2"], sort=False).agg(s=("v", "sum"))
        return cnt(len(o), o["s"].sum())

    def g5():
        o = L.groupby("k_int", sort=False).agg(c=("v", "count"), sd=("w", "std"), md=("w", "median"))
        return cnt(len(o), o["c"].sum())

    def j(how):
        def f():
            o = L.merge(R, on="k_hi", how=how, sort=False)
            return cnt(len(o), o["rv"].sum())

        return f

    def j3():
        o = L.merge(T, on="k_txt", how="inner", sort=False)
        return cnt(len(o), o["tv"].sum())

    def s1():
        o = L.sort_values("v", kind="stable")
        return cnt(len(o), o["n"].iloc[0])

    def s2():
        o = L.sort_values(["k_int", "v"], ascending=[True, False], kind="stable")
        return cnt(len(o), o["n"].iloc[0])

    def s3():
        o = L.sort_values("k_txt", kind="stable")
        return cnt(len(o), o["n"].iloc[0])

    def fl():
        o = L[(L["v"] > 0) & (L["k_int"] < 500)]
        return cnt(len(o), o["v"].sum())

    def pv():
        o = L.pivot_table(index="k_int", columns="k2", values="v", aggfunc="sum", sort=False)
        return cnt(len(o), o.sum().sum())

    def ds():
        o = L.drop_duplicates(subset=["k_hi"], keep="first")
        return cnt(len(o), o["v"].sum())

    def ml():
        o = L.melt(id_vars=["n"], value_vars=["v", "w"])
        return cnt(len(o), o["value"].sum())

    def mu():
        o = L.assign(p=L["v"] * L["w"])
        return cnt(len(o), o["n"].iloc[-1])

    def ro():
        o = L.assign(p=L["v"].rolling(20).mean())
        return cnt(len(o), o["n"].iloc[-1])

    def cs():
        o = L.assign(p=L["v"].cumsum())
        return cnt(len(o), o["p"].iloc[-1])

    return dict(group_int=g1, group_null=g1n, group_hi=g2, group_txt=g3, group_two=g4, group_stats=g5,
                join_inner=j("inner"), join_left=j("left"), join_txt=j3, sort_float=s1,
                sort_two=s2, sort_txt=s3, filter=fl, pivot=pv, distinct=ds, melt=ml,
                mutate=mu, rolling=ro, cumsum=cs)


def polars_ops(c, r, t):
    import polars as pl

    sys.stderr.write(f"polars {pl.__version__} threads={pl.thread_pool_size()}\n")
    L = pl.DataFrame(c).with_columns(pl.col("k_nul").fill_nan(None))
    R = pl.DataFrame(r)
    T = pl.DataFrame(t)

    def g(by, aggs, col):
        def f():
            o = L.group_by(by).agg(aggs)
            return cnt(o.height, o[col].sum())

        return f

    def j(how):
        def f():
            o = L.join(R, on="k_hi", how=how)
            return cnt(o.height, o["rv"].sum())

        return f

    def j3():
        o = L.join(T, on="k_txt", how="inner")
        return cnt(o.height, o["tv"].sum())

    def srt(by, desc):
        def f():
            o = L.sort(by, descending=desc, maintain_order=True)
            return cnt(o.height, o["n"][0])

        return f

    def fl():
        o = L.filter((pl.col("v") > 0) & (pl.col("k_int") < 500))
        return cnt(o.height, o["v"].sum())

    def pv():
        o = L.pivot(on="k2", index="k_int", values="v", aggregate_function="sum")
        vals = [x for x in o.columns if x != "k_int"]
        return cnt(o.height, o.select(pl.sum_horizontal(vals)).to_series().sum())

    def ds():
        o = L.unique(subset=["k_hi"], keep="first", maintain_order=True)
        return cnt(o.height, o["v"].sum())

    def ml():
        o = L.unpivot(index=["n"], on=["v", "w"])
        return cnt(o.height, o["value"].sum())

    def mu():
        o = L.with_columns((pl.col("v") * pl.col("w")).alias("p"))
        return cnt(o.height, o["n"][-1])

    def ro():
        o = L.with_columns(pl.col("v").rolling_mean(20).alias("p"))
        return cnt(o.height, o["n"][-1])

    def cs():
        o = L.with_columns(pl.col("v").cum_sum().alias("p"))
        return cnt(o.height, o["p"][-1])

    s, m = pl.col("v").sum().alias("s"), pl.col("w").mean().alias("m")
    return dict(group_int=g("k_int", [s, m], "s"), group_null=g("k_nul", [s, m], "s"), group_hi=g("k_hi", [s], "s"),
                group_txt=g("k_txt", [s, m], "s"), group_two=g(["k_int", "k2"], [s], "s"),
                group_stats=g("k_int", [pl.col("v").count().alias("c"), pl.col("w").std().alias("sd"),
                                        pl.col("w").median().alias("md")], "c"),
                join_inner=j("inner"), join_left=j("left"), join_txt=j3, sort_float=srt("v", False),
                sort_two=srt(["k_int", "v"], [False, True]), sort_txt=srt("k_txt", False), filter=fl,
                pivot=pv, distinct=ds, melt=ml, mutate=mu, rolling=ro, cumsum=cs)


def duckdb_ops(c, r, t):
    import duckdb
    import polars as pl

    sys.stderr.write(f"duckdb {duckdb.__version__} threads=1\n")
    db = duckdb.connect(":memory:", config={"threads": 1, "preserve_insertion_order": True})
    for tn, d in (("L", c), ("R", r), ("T", t)):
        arrow = pl.DataFrame(d).with_columns(pl.col(pl.Float64).fill_nan(None)).to_arrow()  # noqa: F841 (read by DuckDB's replacement scan)
        db.execute(f"create table {tn} as select * from arrow")

    def q(sel, col="s"):
        def f():
            db.execute(f"create or replace temp table o as {sel}")
            a = db.execute(f"select count(*), sum({col}) from o").fetchone()
            return cnt(a[0], a[1])

        return f

    def first(sel):
        def f():
            db.execute(f"create or replace temp table o as {sel}")
            n = db.execute("select count(*) from o").fetchone()[0]
            a = db.execute("select n from o limit 1").fetchone()
            return cnt(n, a[0])

        return f

    return dict(
        group_int=q("select k_int, sum(v) s, avg(w) m from L group by k_int"),
        group_null=q("select k_nul, sum(v) s, avg(w) m from L group by k_nul"),
        group_hi=q("select k_hi, sum(v) s from L group by k_hi"),
        group_txt=q("select k_txt, sum(v) s, avg(w) m from L group by k_txt"),
        group_two=q("select k_int, k2, sum(v) s from L group by k_int, k2"),
        group_stats=q("select k_int, count(v) s, stddev_samp(w) sd, median(w) md from L group by k_int"),
        join_inner=q("select L.*, rv s from L join R using (k_hi)"),
        join_left=q("select L.*, rv s from L left join R using (k_hi)"),
        join_txt=q("select L.*, tv s from L join T using (k_txt)"),
        sort_float=first("select * from L order by v"),
        sort_two=first("select * from L order by k_int asc, v desc"),
        sort_txt=first("select * from L order by k_txt"),
        filter=q("select *, v s from L where v > 0 and k_int < 500"),
        pivot=None,
        distinct=q("select k_hi, first(v) s from L group by k_hi"),
        melt=q("select n, unnest(['v','w']) variable, unnest([v,w]) s from L"),
        mutate=None, rolling=None, cumsum=None)


def main():
    c, r, t = cols()
    ops = {"pandas": pandas_ops, "polars": polars_ops, "duckdb": duckdb_ops}[engine](c, r, t)
    op = ops[name]
    if op is None:
        raise SystemExit(f"{engine}: no like-for-like form of {name}")
    n = 1
    while True:
        t0 = time.perf_counter_ns()
        for _ in range(n):
            op()
        if time.perf_counter_ns() - t0 > 100_000_000:
            break
        n *= 2
    best = None
    count = 0
    for _ in range(5):
        t0 = time.perf_counter_ns()
        for _ in range(n):
            count = op()
        d = time.perf_counter_ns() - t0
        best = d if best is None else min(best, d)
    print(f"{name}\t{best / n:.1f}\t{count}")


main()
