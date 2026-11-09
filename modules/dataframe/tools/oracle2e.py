#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for dataframe S2 wave W6 (list and struct rest, ordered categoricals):
what polars 2.1 and pandas 3.1 answer for the list set operations, `gather`, `gather_every`,
`shift`, `diff`, `item`, `to_struct`, `repeat_by`, `concat`, `list.eval`/`list.filter`/`list.agg`
with `pl.element()`; `struct.rename_fields`/`with_fields`/`eval` and `name.prefix_fields`/
`suffix_fields`/`map_fields`; and for `Enum` / `CategoricalDtype(ordered=True)`: sort, order
comparison, codes, min/max and the `Series.cat` verbs. Frozen into src/oracle2e_vectors.json and
replayed by src/s2w6_oracle_test.zig. No line of dataframe is consulted: the expected values are
what the engines answer; where both have a feature they must agree (or the run fails).

    python tools/oracle2e.py src/oracle2e_vectors.json      (see tools/README.md)

The inputs are small random lists drawn from a fixed seed. A case carries its rows as JSON text
(`rows`, what `readJson` reads), the operation and its arguments, and `expect`, the cells of the
result column. `sample` has no vector: the engines' generators differ, only properties agree
(hand test).
"""
import json
import random
import sys

import pandas as pd
import polars as pl

cases = []
problems = []
rng = random.Random(20261109)


def cell(v):
    if v is None or (isinstance(v, float) and v != v):
        return None
    if isinstance(v, bool):
        return bool(v)
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    if isinstance(v, (list, tuple)):
        return [cell(x) for x in v]
    if isinstance(v, dict):
        return {k: cell(x) for k, x in v.items()}
    return str(v)


def add(cid, op, rows, expect, **args):
    cases.append({"id": cid, "op": op, "rows": json.dumps(rows, separators=(",", ":")), "args": args, "expect": cell(expect)})


def agree(cid, a, b):
    if cell(a) != cell(b):
        problems.append(f"{cid}: pandas {a} != polars {b}")


def rand_list(maxlen=6, lo=0, hi=5, null_p=0.15, list_null_p=0.12):
    if rng.random() < list_null_p:
        return None
    return [None if rng.random() < null_p else rng.randint(lo, hi) for _ in range(rng.randint(0, maxlen))]


def lists_df(cols):
    return pl.DataFrame({k: pl.Series(v, dtype=pl.List(pl.Int64)) for k, v in cols.items()})


skipped = []


def run_list(cid, op, df, expr, rows, **args):
    try:
        got = df.select(expr.alias("r")).to_series().to_list()
    except pl.exceptions.PolarsError as e:
        # polars raises for some inputs (a data-dependent length mismatch inside the kernel);
        # there is no answer to freeze, and the id is printed so the gap is visible.
        skipped.append(f"{cid}: {type(e).__name__}")
        return
    add(cid, op, rows, got, **args)


# ── list: set operations, gather, shift, diff, ... ───────────────────────────────
N = 30
for rnd in range(6):
    A = [rand_list() for _ in range(N)]
    B = [rand_list() for _ in range(N)]
    # Distinguishing orders: x = [1,2,3], y = [3,2] first.
    if rnd == 0:
        A[0], B[0] = [1, 2, 3], [3, 2]
        A[1], B[1] = [3, 1, 3, None], [None, 1, 1]
    rows = [{"a": a, "b": b} for a, b in zip(A, B)]
    df = lists_df({"a": A, "b": B})
    for op in ("set_union", "set_intersection", "set_difference", "set_symmetric_difference"):
        run_list(f"list-{op}-{rnd}", op, df, getattr(pl.col("a").list, op)(pl.col("b")), rows)
    run_list(f"list-concat-{rnd}", "concat", df, pl.col("a").list.concat(pl.col("b")), rows)
    for n in (1, 2, -1, -3, 0):
        run_list(f"list-shift{n}-{rnd}", "shift", df, pl.col("a").list.shift(n), rows, n=n)
    for n, off in ((2, 0), (2, 1), (3, 1), (1, 0), (2, 5)):
        run_list(f"list-gather_every{n}_{off}-{rnd}", "gather_every", df, pl.col("a").list.gather_every(n, off), rows, n=n, offset=off)
    for n in (1, 2, 3):
        run_list(f"list-diff{n}-{rnd}", "diff", df, pl.col("a").list.diff(n), rows, n=n, drop=False)
        run_list(f"list-diffdrop{n}-{rnd}", "diff", df, pl.col("a").list.diff(n, "drop"), rows, n=n, drop=True)
    I = [[rng.randint(-4, 5) for _ in range(rng.randint(0, 4))] if rng.random() > 0.1 else None for _ in range(N)]
    rows_i = [{"a": a, "i": i} for a, i in zip(A, I)]
    run_list(f"list-gather-{rnd}", "gather", lists_df({"a": A, "i": I}), pl.col("a").list.gather(pl.col("i"), null_on_oob=True), rows_i)
    Y = [([rng.randint(0, 3)] if rng.random() < 0.5 else rand_list(3)) for _ in range(N)]
    Y1 = [y if (y is None or len(y) <= 1) else y[:1] for y in Y]
    add(f"list-item1-{rnd}", "item", [{"y": y} for y in Y1], lists_df({"y": Y1}).select(pl.col("y").list.item(allow_empty=True).alias("r")).to_series().to_list())
    for names in (["p", "q"], ["u"], ["a", "b", "c", "d"]):
        run_list(f"list-to_struct{len(names)}-{rnd}", "to_struct", lists_df({"a": A}), pl.col("a").list.to_struct(names), [{"a": a} for a in A], names=names)
    V = [rng.choice([None, 1, 2, 7, -3]) for _ in range(N)]
    C = [rng.choice([None, 0, 1, 2, 3]) for _ in range(N)]
    rows_v = [{"v": v, "n": c} for v, c in zip(V, C)]
    got = pl.DataFrame({"v": V, "n": C}, schema={"v": pl.Int64, "n": pl.Int64}).select(pl.col("v").repeat_by(pl.col("n")).alias("r")).to_series().to_list()
    add(f"list-repeat_by-{rnd}", "repeat_by", rows_v, got)
    # eval / filter / agg
    rows_a = [{"a": a} for a in A]
    dfa = lists_df({"a": A})
    for k in (2, -1, 5):
        run_list(f"list-eval_mul{k}-{rnd}", "eval_mul", dfa, pl.col("a").list.eval(pl.element() * k), rows_a, k=k)
        run_list(f"list-eval_add{k}-{rnd}", "eval_add", dfa, pl.col("a").list.eval(pl.element() + k), rows_a, k=k)
    for k in (0, 2, 3):
        run_list(f"list-filter_gt{k}-{rnd}", "filter_gt", dfa, pl.col("a").list.filter(pl.element() > k), rows_a, k=k)
        run_list(f"list-eval_filter_gt{k}-{rnd}", "filter_gt", dfa, pl.col("a").list.eval(pl.element().filter(pl.element() > k)), rows_a, k=k)
    got = dfa.select(pl.col("a").list.agg(pl.element().sum()).alias("r")).to_series().to_list()
    add(f"list-agg_sum-{rnd}", "agg_sum", rows_a, got)

# set operations over text
for rnd in range(2):
    words = ["a", "b", "c", "d", None]

    def wl():
        return None if rng.random() < 0.1 else [rng.choice(words) for _ in range(rng.randint(0, 5))]
    A = [wl() for _ in range(20)]
    B = [wl() for _ in range(20)]
    dft = pl.DataFrame({"a": pl.Series(A, dtype=pl.List(pl.String)), "b": pl.Series(B, dtype=pl.List(pl.String))})
    rows = [{"a": a, "b": b} for a, b in zip(A, B)]
    for op in ("set_union", "set_intersection", "set_difference", "set_symmetric_difference"):
        run_list(f"list-text-{op}-{rnd}", op, dft, getattr(pl.col("a").list, op)(pl.col("b")), rows)

# ── struct ───────────────────────────────────────────────────────────────────────
for rnd in range(3):
    S = [None if rng.random() < 0.15 else {"a": rng.choice([None, 1, 2, -4, 9]), "b": rng.choice([None, "x", "yy", "Zed"])} for _ in range(20)]
    rows = [{"s": s} for s in S]
    dfs = pl.DataFrame({"s": S}, schema={"s": pl.Struct({"a": pl.Int64, "b": pl.String})})
    sc = pl.col("s")
    def run_s(cid, op, expr, **args):
        got = dfs.select(expr.alias("r")).to_series().to_list()
        add(cid, op, rows, got, **args)
    run_s(f"struct-rename-{rnd}", "rename_fields", sc.struct.rename_fields(["p", "q"]), names=["p", "q"])
    run_s(f"struct-prefix-{rnd}", "prefix_fields", sc.name.prefix_fields("f_"), text="f_")
    run_s(f"struct-suffix-{rnd}", "suffix_fields", sc.name.suffix_fields("_z"), text="_z")
    run_s(f"struct-upper-{rnd}", "upper_fields", sc.name.map_fields(lambda n: n.upper()))
    for k in (10, -2):
        run_s(f"struct-with_fields{k}-{rnd}", "with_fields", sc.struct.with_fields((pl.field("a") * k).alias("c"), pl.field("b").str.to_uppercase().alias("b")), k=k)
        run_s(f"struct-eval{k}-{rnd}", "struct_eval", sc.struct.eval((pl.field("a") + k).alias("a")), k=k)

# ── Enum / ordered categoricals ──────────────────────────────────────────────────
CATS = ["low", "mid", "high"]
CATS2 = ["xs", "s", "m", "l", "xl"]
for rnd, cats in enumerate((CATS, CATS2, CATS, CATS2)):
    vals = [None if rng.random() < 0.2 else rng.choice(cats) for _ in range(24)]
    rows = [{"s": v} for v in vals]
    en = pl.Series("s", vals, dtype=pl.Enum(cats))
    pdf = pd.Series(vals, dtype=pd.CategoricalDtype(cats, ordered=True))
    for desc in (False, True):
        pl_sorted = en.sort(descending=desc, nulls_last=False).to_list()
        pd_sorted = pdf.sort_values(ascending=not desc, na_position="first").tolist()
        agree(f"cat-sort-{rnd}-{desc}", pd_sorted, pl_sorted)
        add(f"cat-sort-{rnd}-{desc}", "cat_sort", rows, pl_sorted, categories=cats, desc=desc)
    for opn, f_pl in (("lt", lambda s, x: s < x), ("le", lambda s, x: s <= x), ("gt", lambda s, x: s > x), ("ge", lambda s, x: s >= x)):
        for lit in (cats[0], cats[len(cats) // 2], cats[-1]):
            got = pl.DataFrame({"s": en}).select(f_pl(pl.col("s"), lit).alias("r")).to_series().to_list()
            pd_got = [None if v is None else bool(b) for v, b in zip(vals, f_pl(pdf, lit).tolist())]
            agree(f"cat-{opn}-{rnd}-{lit}", pd_got, got)
            add(f"cat-{opn}-{rnd}-{lit}", "cat_cmp", rows, got, categories=cats, cmp=opn, lit=lit)
    pl_codes = en.to_physical().to_list()
    pd_codes = [None if c < 0 else int(c) for c in pdf.cat.codes.tolist()]
    agree(f"cat-codes-{rnd}", pd_codes, pl_codes)
    add(f"cat-codes-{rnd}", "cat_codes", rows, pl_codes, categories=cats)
    pl_min, pl_max = en.min(), en.max()
    agree(f"cat-minmax-{rnd}", [pdf.min(), pdf.max()], [pl_min, pl_max])
    add(f"cat-min-{rnd}", "cat_min", rows, pl_min, categories=cats)
    add(f"cat-max-{rnd}", "cat_max", rows, pl_max, categories=cats)
    # cast with a value outside the list (non-strict): null, in both engines
    outside = vals + ["zzz"]
    pl_lax = pl.Series(outside, dtype=pl.String).cast(pl.Enum(cats), strict=False).to_list()
    pd_lax = [None if v != v or v is None else v for v in pd.Series(outside, dtype=pd.CategoricalDtype(cats, ordered=True)).tolist()]
    agree(f"cat-lax-{rnd}", pd_lax, pl_lax)
    add(f"cat-lax-{rnd}", "cat_values", [{"s": v} for v in outside], pl_lax, categories=cats)

# pandas Series.cat verbs on an unordered, lexical category (the pandas default)
base = ["a", "b", "c", "a", None, "c", "b"]
rows = [{"s": v} for v in base]
ps = pd.Series(base, dtype="category")


def cat_case(cid, verb, series, **args):
    add(cid, verb, rows, {"values": [None if v != v else v for v in series.tolist()], "categories": [str(c) for c in series.cat.categories],
                          "codes": [None if c < 0 else int(c) for c in series.cat.codes.tolist()], "ordered": bool(series.cat.ordered)}, **args)


def cat_error(cid, verb, fn, **args):
    try:
        fn()
    except (ValueError, TypeError):
        add(cid, verb, rows, "error", **args)
        return
    problems.append(f"{cid}: pandas did not raise")


cat_case("cat-add", "add_categories", ps.cat.add_categories(["z", "y"]), cats=["z", "y"])
cat_error("cat-add-dup", "add_categories", lambda: ps.cat.add_categories(["a"]), cats=["a"])
cat_case("cat-remove", "remove_categories", ps.cat.remove_categories(["b"]), cats=["b"])
cat_case("cat-remove2", "remove_categories", ps.cat.remove_categories(["a", "c"]), cats=["a", "c"])
cat_error("cat-remove-missing", "remove_categories", lambda: ps.cat.remove_categories(["q"]), cats=["q"])
cat_case("cat-remove_unused", "remove_unused", ps.cat.add_categories(["z"]).cat.remove_unused_categories())
cat_case("cat-set", "set_categories", ps.cat.set_categories(["c", "a", "q"]), cats=["c", "a", "q"], ordered=None)
cat_case("cat-set-ordered", "set_categories", ps.cat.set_categories(["c", "b"], ordered=True), cats=["c", "b"], ordered=True)
cat_error("cat-set-dup", "set_categories", lambda: ps.cat.set_categories(["a", "a"]), cats=["a", "a"], ordered=None)
cat_case("cat-reorder", "reorder_categories", ps.cat.reorder_categories(["c", "b", "a"]), cats=["c", "b", "a"], ordered=None)
cat_case("cat-reorder-ordered", "reorder_categories", ps.cat.reorder_categories(["b", "c", "a"], ordered=True), cats=["b", "c", "a"], ordered=True)
cat_error("cat-reorder-short", "reorder_categories", lambda: ps.cat.reorder_categories(["a", "b"]), cats=["a", "b"], ordered=None)
cat_error("cat-reorder-extra", "reorder_categories", lambda: ps.cat.reorder_categories(["a", "b", "x"]), cats=["a", "b", "x"], ordered=None)
cat_case("cat-rename-list", "rename_list", ps.cat.rename_categories(["x", "y", "z"]), cats=["x", "y", "z"])
cat_case("cat-rename-map", "rename_map", ps.cat.rename_categories({"a": "A", "c": "C"}), pairs=[["a", "A"], ["c", "C"]])
cat_error("cat-rename-short", "rename_list", lambda: ps.cat.rename_categories(["x", "y"]), cats=["x", "y"])
cat_error("cat-rename-dup", "rename_list", lambda: ps.cat.rename_categories(["x", "x", "z"]), cats=["x", "x", "z"])
cat_case("cat-as_ordered", "as_ordered", ps.cat.as_ordered())
cat_case("cat-as_unordered", "as_unordered", ps.cat.as_ordered().cat.as_unordered())

# ── write ───────────────────────────────────────────────────────────────────────
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
out = sys.argv[1] if len(sys.argv) > 1 else "oracle2e_vectors.json"
with open(out, "w") as fh:
    json.dump({"pandas": pd.__version__, "polars": pl.__version__, "cases": cases}, fh, separators=(",", ":"))
print(f"{len(cases)} cases -> {out}")
if skipped:
    print(f"{len(skipped)} skipped (polars raised): " + "; ".join(skipped[:12]), file=sys.stderr)
