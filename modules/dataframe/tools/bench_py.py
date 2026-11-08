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

I/O rows: `read_csv` parses the bytes of `l.csv` (loaded before the clock; table L
as ours wrote it), count = rows + sum of `v`. The writers (`write_csv`,
`write_json` records, `write_ndjson`) serialize L to an in-memory buffer (pandas
`StringIO`, polars `BytesIO`); their count is the OUTPUT BYTE LENGTH, so it agrees
only where the engines' text agrees. DuckDB has no I/O rows here.

Order contracts: pandas groupby `sort=False` is first-seen order, like ours;
polars `group_by` without `maintain_order` and DuckDB's GROUP BY are unordered, a
weaker contract than ours, which favours them. Sort is stable on all sides.
"""
import io
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
    a = {
        "n": np.fromfile(f"{work}/a_n.i64", dtype=np.int64),
        "av": np.fromfile(f"{work}/a_av.f64", dtype=np.float64),
    }
    with open(f"{work}/d_txt.txt") as f:
        d = {"d_txt": f.read().split("\n")[:-1]}
    return c, r, t, a, d


_csv = []


def csv_bytes():
    if not _csv:
        with open(f"{work}/l.csv", "rb") as f:
            _csv.append(f.read())
    return _csv[0]


def cnt(rows, s):
    s = 0.0 if s is None or (isinstance(s, float) and math.isnan(s)) else float(s)
    return int(rows) + int(abs(math.floor(s)))


def pandas_ops(c, r, t, a, d):
    import pandas as pd

    sys.stderr.write(f"pandas {pd.__version__}\n")
    L = pd.DataFrame({k: (pd.array(v, dtype="str") if k == "k_txt" else v) for k, v in c.items()})
    R = pd.DataFrame(r)
    T = pd.DataFrame({"k_txt": pd.array(t["k_txt"], dtype="str"), "tv": t["tv"]})
    A = pd.DataFrame(a)
    D = pd.DataFrame({"d_txt": pd.array(d["d_txt"], dtype="str")})

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

    def rc():
        o = pd.read_csv(io.BytesIO(csv_bytes()))
        return cnt(len(o), o["v"].sum())

    def wc():
        b = io.StringIO()
        L.to_csv(b, index=False)
        return b.tell()

    def wj():
        b = io.StringIO()
        L.to_json(b, orient="records")
        return b.tell()

    def wn():
        b = io.StringIO()
        L.to_json(b, orient="records", lines=True)
        return b.tell()

    def fn():
        o = L.assign(k_nul=L["k_nul"].ffill())
        return cnt(len(o), o["k_nul"].sum())

    def ja():
        o = pd.merge_asof(L, A, on="n")
        return cnt(len(o), o["av"].sum())

    def tk():
        o = L.nlargest(100, "v")
        return cnt(len(o), o["v"].sum())

    def ws():
        o = L.assign(p=L.groupby("k_int")["v"].shift(1))
        return cnt(len(o), o["p"].sum())

    def wr():
        o = L.assign(p=L.groupby("k_int")["v"].rank(method="average"))
        return cnt(len(o), o["p"].sum())

    def vc():
        o = L["k_txt"].value_counts()
        return cnt(len(o), o.sum())

    def de():
        o = L[["v", "w"]].describe()
        return cnt(len(o), o.loc[["count", "min", "max"], "v"].sum())

    def cc():
        o = pd.concat([L, L], ignore_index=True)
        return cnt(len(o), o["v"].sum())

    def sc():
        o = L.assign(p=L["k_txt"].str.contains("99", regex=False))
        return cnt(len(o), o["p"].sum())

    def sp():
        o = D.assign(d=pd.to_datetime(D["d_txt"], format="%Y-%m-%d"))
        return cnt(len(o), o["d"].dt.day.sum())

    return dict(fill_null=fn, join_asof=ja, top_k=tk, win_shift=ws, win_rank=wr, value_counts=vc,
                describe=de, concat=cc, str_contains=sc, strptime=sp,
                read_csv=rc, write_csv=wc, write_json=wj, write_ndjson=wn, group_int=g1, group_null=g1n, group_hi=g2, group_txt=g3, group_two=g4, group_stats=g5,
                join_inner=j("inner"), join_left=j("left"), join_txt=j3, sort_float=s1,
                sort_two=s2, sort_txt=s3, filter=fl, pivot=pv, distinct=ds, melt=ml,
                mutate=mu, rolling=ro, cumsum=cs)


def polars_ops(c, r, t, a, d):
    import polars as pl

    sys.stderr.write(f"polars {pl.__version__} threads={pl.thread_pool_size()}\n")
    L = pl.DataFrame(c).with_columns(pl.col("k_nul").fill_nan(None))
    R = pl.DataFrame(r)
    T = pl.DataFrame(t)
    A = pl.DataFrame(a)
    D = pl.DataFrame(d)

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

    def rc():
        o = pl.read_csv(csv_bytes())
        return cnt(o.height, o["v"].sum())

    def wc():
        b = io.BytesIO()
        L.write_csv(b)
        return b.tell()

    def wj():
        b = io.BytesIO()
        L.write_json(b)
        return b.tell()

    def wn():
        b = io.BytesIO()
        L.write_ndjson(b)
        return b.tell()

    def fn():
        o = L.with_columns(pl.col("k_nul").fill_null(strategy="forward"))
        return cnt(o.height, o["k_nul"].sum())

    def ja():
        o = L.join_asof(A, on="n")
        return cnt(o.height, o["av"].sum())

    def tk():
        o = L.top_k(100, by="v")
        return cnt(o.height, o["v"].sum())

    def ws():
        o = L.with_columns(pl.col("v").shift(1).over("k_int").alias("p"))
        return cnt(o.height, o["p"].sum())

    def wr():
        o = L.with_columns(pl.col("v").rank("average").over("k_int").alias("p"))
        return cnt(o.height, o["p"].sum())

    def vc():
        o = L["k_txt"].value_counts(sort=True)
        return cnt(o.height, o["count"].sum())

    def de():
        o = L.select("v", "w").describe()
        # polars adds a null_count row pandas lacks: the count's rows are the 8 shared ones.
        s = o.filter(pl.col("statistic").is_in(["count", "min", "max"]))["v"].sum()
        return cnt(o.height - 1, s)

    def cc():
        # rechunk: a materialized result like ours and pandas', not two chunks by reference
        o = pl.concat([L, L], how="vertical", rechunk=True)
        return cnt(o.height, o["v"].sum())

    def sc():
        o = L.with_columns(pl.col("k_txt").str.contains("99", literal=True).alias("p"))
        return cnt(o.height, o["p"].sum())

    def sp():
        o = D.with_columns(pl.col("d_txt").str.strptime(pl.Date, "%Y-%m-%d").alias("d"))
        return cnt(o.height, o["d"].dt.day().sum())

    s, m = pl.col("v").sum().alias("s"), pl.col("w").mean().alias("m")
    return dict(fill_null=fn, join_asof=ja, top_k=tk, win_shift=ws, win_rank=wr, value_counts=vc,
                describe=de, concat=cc, str_contains=sc, strptime=sp, read_csv=rc, write_csv=wc, write_json=wj, write_ndjson=wn, group_int=g("k_int", [s, m], "s"), group_null=g("k_nul", [s, m], "s"), group_hi=g("k_hi", [s], "s"),
                group_txt=g("k_txt", [s, m], "s"), group_two=g(["k_int", "k2"], [s], "s"),
                group_stats=g("k_int", [pl.col("v").count().alias("c"), pl.col("w").std().alias("sd"),
                                        pl.col("w").median().alias("md")], "c"),
                join_inner=j("inner"), join_left=j("left"), join_txt=j3, sort_float=srt("v", False),
                sort_two=srt(["k_int", "v"], [False, True]), sort_txt=srt("k_txt", False), filter=fl,
                pivot=pv, distinct=ds, melt=ml, mutate=mu, rolling=ro, cumsum=cs)


def duckdb_ops(c, r, t, a, d):
    import duckdb
    import polars as pl

    sys.stderr.write(f"duckdb {duckdb.__version__} threads=1\n")
    db = duckdb.connect(":memory:", config={"threads": 1, "preserve_insertion_order": True})
    for tn, dd in (("L", c), ("R", r), ("T", t), ("A", a)):
        arrow = pl.DataFrame(dd).with_columns(pl.col(pl.Float64).fill_nan(None)).to_arrow()  # noqa: F841 (read by DuckDB's replacement scan)
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
        mutate=None, rolling=None, cumsum=None,
        fill_null=None, win_shift=None, win_rank=None, describe=None, strptime=None,
        join_asof=q("select L.*, av s from L asof left join A on L.n >= A.n"),
        top_k=q("select *, v s from L order by v desc limit 100"),
        value_counts=q("select k_txt, count(*) s from L group by k_txt order by s desc"),
        concat=q("select v s from (select * from L union all select * from L)"),
        str_contains=q("select contains(k_txt, '99')::int s from L"),
        read_csv=None, write_csv=None, write_json=None, write_ndjson=None)


def main():
    c, r, t, a, d = cols()
    ops = {"pandas": pandas_ops, "polars": polars_ops, "duckdb": duckdb_ops}[engine](c, r, t, a, d)
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
