#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle: pandas and polars over generated tables. Written for `tabular` (its
verb names and specs) and moved here when step R retired that module (2026-11-08): its
output, filtered by `filter_vectors.py` to the verbs `dataframe` has, is
src/oracle_vectors.json, replayed by src/oracle_test.zig. No line of either module is
consulted here: the expected values are what the two engines answer.

    python modules/dataframe/tools/oracle.py \
      | python3 modules/dataframe/tools/filter_vectors.py > modules/dataframe/src/oracle_vectors.json

Every case runs on both engines where both have the operation. A disagreement between
them must carry a `label` naming the difference and `follow` naming the engine this
module follows, or the run fails: an unlabelled disagreement is a question nobody has
answered. Output tables are compared by column name; NaN and null are both "missing"
in the frozen rows (a table of ours keeps them apart only where a label says so). Each
engine's output column kinds are frozen too. Integers compare exactly, here and in the
replay. `.decimal` cells have no counterpart in either engine: Zig-only tests.
"""
import json
import math
import sys

import numpy as np
import pandas as pd
import polars as pl

N_ROWS = 20
SEEDS = (11, 22, 33)
tables = {}
cases = []
stats = {"both": 0, "pandas": 0, "polars": 0, "disagree": 0}
TWO53 = 2**53


def gen(seed):
    r = np.random.default_rng(seed)
    n = N_ROWS

    def pick(vals, p=None):
        return [vals[i] for i in r.choice(len(vals), size=n, p=p)]

    words = ["Alpha", "beta", " gamma ", "DELTA", "epsilon", "", None]
    return {
        "i": ("int", list(range(n))),
        "g": ("text", pick(["a", "b", "c", None], [0.35, 0.3, 0.25, 0.1])),
        "h": ("int", [int(x) for x in r.integers(0, 5, n)]),
        "k": ("float", [None if r.random() < 0.15 else float(r.integers(0, 6)) for _ in range(n)]),
        "x": ("float", [None if r.random() < 0.2 else round(float(r.normal(0, 10)), 3) for _ in range(n)]),
        "y": ("float", [round(float(r.normal(5, 3)), 3) for _ in range(n)]),
        "n": ("int", [int(x) for x in r.integers(-50, 50, n)]),
        "t": ("text", pick(words)),
        "s": ("text", pick(["12", "3.5", "-7", "x", "", None, "1e2", "nan", "inf", "-inf", "0x10", "1_000"])),
        "big": ("int", [TWO53 + int(x) for x in r.integers(0, 4, n)]),
        "mx": ("mixnum", pick([1, 1.0, 2, 2.0, 2.5, 3, None])),
        "w": ("int", [int(x) for x in np.cumsum(r.integers(1, 5, n)) * 86_400_000_000]),
        "b": ("bool", [bool(x) for x in r.integers(0, 2, n)]),
    }


def gen_right(seed):
    r = np.random.default_rng(seed + 1000)
    n = 10
    return {
        "h": ("int", [int(x) for x in r.integers(0, 7, n)]),
        "g": ("text", [["a", "b", "z", None][i] for i in r.integers(0, 4, n)]),
        "k": ("float", [None if r.random() < 0.2 else float(r.integers(0, 6)) for _ in range(n)]),
        "rv": ("float", [round(float(r.normal(0, 1)), 3) for _ in range(n)]),
        "y": ("float", [round(float(r.normal(0, 1)), 3) for _ in range(n)]),
        "big": ("int", [TWO53 + int(x) for x in r.integers(0, 6, n)]),
        "mx": ("mixnum", [[1.0, 2, 2.5, 4, None][i] for i in r.integers(0, 5, n)]),
    }


def gen_wide(seed, n, tag):
    """More distinct keys than the hash table's first 64 slots hold, with nulls."""
    r = np.random.default_rng(seed + 4000 + n)
    d = {
        "ki": ("int", [int(x) for x in r.integers(0, 120, n)]),
        "kt": ("text", [None if r.random() < 0.05 else f"w{int(r.integers(0, 90))}" for _ in range(n)]),
        "kf": ("float", [None if r.random() < 0.05 else float(r.integers(0, 100)) / 2 for _ in range(n)]),
    }
    if tag == "l":
        d["i"] = ("int", list(range(n)))
        d["v"] = ("float", [round(float(x), 3) for x in r.normal(0, 5, n)])
    else:
        d["rv"] = ("float", [round(float(x), 3) for x in r.normal(0, 5, n)])
    return d


def gen_nan(seed):
    """A float key and value holding real NaN and null side by side."""
    r = np.random.default_rng(seed + 2000)
    n = 16
    keys = [1.0, 2.0, float("nan"), None]
    vals = [1.5, -2.25, 4.0, float("nan"), None]
    return {
        "kn": ("float", [keys[i] for i in r.integers(0, 4, n)]),
        "xn": ("float", [vals[i] for i in r.integers(0, 5, n)]),
    }


def gen_asof(seed):
    r = np.random.default_rng(seed + 3000)
    return (
        {
            "on": ("int", sorted(int(x) for x in r.integers(0, 100, 12))),
            "by": ("text", [["p", "q"][i] for i in r.integers(0, 2, 12)]),
            "lv": ("float", [round(float(x), 3) for x in r.normal(0, 1, 12)]),
        },
        {
            "on": ("int", sorted(int(x) for x in r.integers(0, 100, 15))),
            "by": ("text", [["p", "q", "r"][i] for i in r.integers(0, 3, 15)]),
            "rv": ("float", [round(float(x), 3) for x in r.normal(0, 1, 15)]),
        },
    )


def to_pd(t):
    d = {}
    for c, (ty, vals) in t.items():
        if ty == "text":
            d[c] = pd.array(vals, dtype="str")
        elif ty in ("float", "mixnum"):
            d[c] = np.array([float("nan") if v is None else float(v) for v in vals], dtype=float)
        elif ty == "int":
            d[c] = np.array(vals, dtype=np.int64)
        else:
            d[c] = np.array(vals, dtype=bool)
    return pd.DataFrame(d)


def to_pl(t):
    sch = {"text": pl.String, "float": pl.Float64, "int": pl.Int64, "bool": pl.Boolean, "mixnum": pl.Float64}
    out = {}
    for c, (ty, v) in t.items():
        if ty == "mixnum":
            v = [None if x is None else float(x) for x in v]
        out[c] = pl.Series(c, v, dtype=sch[ty])
    return pl.DataFrame(out)


def cell(v):
    if v is None or v is pd.NA or v is pd.NaT:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        v = float(v)
        if math.isnan(v):
            return None
        if math.isinf(v):
            return "inf" if v > 0 else "-inf"
        if v == 0:
            return 0.0  # -0.0 and 0.0 are one number here
        return v
    return str(v)


def kind_pd(dt):
    k = getattr(dt, "kind", "O")
    return {"i": "int", "u": "int", "f": "float", "b": "bool"}.get(k, "text")


def kind_pl(dt):
    if dt.is_integer():
        return "int"
    if dt.is_float():
        return "float"
    if dt == pl.Boolean:
        return "bool"
    if dt == pl.Null:
        return "null"
    return "text"


def norm_pd(df):
    df = df.reset_index(drop=True)
    cols = [str(c) for c in df.columns]
    rows = [[cell(df.iloc[i, j]) for j in range(len(cols))] for i in range(len(df))]
    return cols, rows, [kind_pd(x) for x in df.dtypes]


def norm_pl(df):
    cols = list(df.columns)
    rows = [[cell(v) for v in r] for r in df.rows()]
    return cols, rows, [kind_pl(x) for x in df.dtypes]


def cell_key(v):
    if v is None:
        return (0, 0.0, "")
    if isinstance(v, bool):
        return (1, float(v), "")
    if isinstance(v, int):
        return (2, v, "")
    if isinstance(v, float):
        return (2, round(v, 9), "")
    return (3, 0.0, v)


def by_name(cols, rows, order, names):
    idx = [cols.index(n) for n in names]
    out = [[r[i] for i in idx] for r in rows]
    if order == "any":
        out.sort(key=lambda r: [cell_key(v) for v in r])
    return out


def near(a, b):
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    if isinstance(a, bool) or isinstance(b, bool):
        return float(a) == float(b)
    # Integers exactly, also against a float: past 2^53 the difference is the point.
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    if isinstance(a, int) or isinstance(b, int):
        i, f = (a, b) if isinstance(a, int) else (b, a)
        if abs(i) >= TWO53:
            return f == int(f) and int(f) == i
    a, b = float(a), float(b)
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def same(p, q, order):
    if sorted(p[0]) != sorted(q[0]) or len(p[1]) != len(q[1]):
        return False
    names = sorted(p[0])
    x = by_name(p[0], p[1], order, names)
    y = by_name(q[0], q[1], order, names)
    return all(near(u, v) for r, s in zip(x, y) for u, v in zip(r, s))


def case(cid, verb, spec, table, fp=None, fq=None, right=None, order="exact", label=None, follow=None, extra=None):
    """fp(pandas frame[, right]), fq(polars frame[, right]); either may be None."""
    T = tables[table]
    R = tables[right] if right else None
    p = q = None
    if fp:
        p = norm_pd(fp(to_pd(T), to_pd(R)) if right else fp(to_pd(T)))
    if fq:
        q = norm_pl(fq(to_pl(T), to_pl(R)) if right else fq(to_pl(T)))
    entry = {"id": cid, "verb": verb, "spec": spec, "table": table, "order": order}
    if right:
        entry["right"] = right
    if extra:
        entry.update(extra)
    if p and q:
        stats["both"] += 1
        agree = same(p, q, order)
        if not agree:
            stats["disagree"] += 1
            if not label:
                sys.stderr.write(f"UNLABELLED DISAGREEMENT {cid}\n pandas {p}\n polars {q}\n")
                sys.exit(1)
            entry["label"] = label
        use = (p if follow != "polars" else q) if not agree else p
        entry["engine"] = "both" if agree else (follow or "pandas")
    else:
        use = p or q
        entry["engine"] = "pandas" if p else "polars"
        stats[entry["engine"]] += 1
    # Frozen: the columns the verb made or was told about, plus the row id. The rest is
    # input passing through, compared by the id, and would only make the file bigger.
    said = json.dumps(spec)
    kept = [i for i, c in enumerate(use[0]) if c not in T or c == "i" or f'"{c}"' in said]
    entry["width"] = len(use[0])
    entry["expect"] = {"columns": [use[0][i] for i in kept], "rows": [[r[i] for i in kept] for r in use[1]]}
    # Each engine's kinds by column name; its own order of columns can differ.
    for key, res in (("ptypes", p), ("qtypes", q)):
        if res:
            kinds = dict(zip(res[0], res[2]))
            entry[key] = [kinds.get(use[0][i], "null") for i in kept]
    # Bin numbers and row positions: pandas writes them as float only to hold a NaN.
    funcs = [g.get("func") for g in spec.get("aggs", [])]
    if "ptypes" in entry and (verb == "cut" or "arg_min" in funcs or "arg_max" in funcs):
        entry["ptypes"] = ["int" if c == "o" else k for c, k in zip(entry["expect"]["columns"], entry["ptypes"])]
    cases.append(entry)


AGGS_BOTH = {
    "sum": (lambda s: s.sum(), lambda c: c.sum()),
    "mean": (lambda s: s.mean(), lambda c: c.mean()),
    "count": (lambda s: s.count(), lambda c: c.count()),
    "min": (lambda s: s.min(), lambda c: c.min()),
    "max": (lambda s: s.max(), lambda c: c.max()),
    "first": (lambda s: s.first(), lambda c: c.drop_nulls().first()),
    "last": (lambda s: s.last(), lambda c: c.drop_nulls().last()),
    "std": (lambda s: s.std(), lambda c: c.std()),
    "var": (lambda s: s.var(), lambda c: c.var()),
    "median": (lambda s: s.median(), lambda c: c.median()),
    "nunique": (lambda s: s.nunique(), lambda c: c.drop_nulls().n_unique()),
    "size": (lambda s: s.size(), lambda c: c.len()),
    "prod": (lambda s: s.prod(), lambda c: c.drop_nulls().product()),
    "skew": (lambda s: s.skew(), lambda c: c.drop_nulls().skew(bias=False)),
    "kurt": (lambda s: s.apply(lambda v: v.kurt()), lambda c: c.drop_nulls().kurtosis(bias=False)),
}


def agg_cases(tag, tn):
    for func, (fp, fq) in AGGS_BOTH.items():
        for by in (["g"], ["h"], ["g", "h"]):
            for src in ("x", "n"):
                if func in ("skew", "kurt") and src == "n" and by != ["h"]:
                    continue
                spec = {"by": by, "aggs": [{"src": src, "func": func, "out": "o"}], "skip_na": True}
                # Group keys in first-seen order on both sides, missing keys kept.
                case(
                    f"{tag}-agg-{func}-{'+'.join(by)}-{src}",
                    "aggregate",
                    spec,
                    tn,
                    lambda d, by=by, src=src, fp=fp: fp(d.groupby(by, sort=False, dropna=False)[src]).rename("o").reset_index(),
                    lambda d, by=by, src=src, fq=fq: d.group_by(by, maintain_order=True).agg(fq(pl.col(src)).alias("o")),
                )
    for q in (0.1, 0.5, 0.75, 1.0):
        spec = {"by": ["g"], "aggs": [{"src": "x", "func": "quantile", "q": q, "out": "o"}], "skip_na": True}
        case(
            f"{tag}-agg-quantile-{q}",
            "aggregate",
            spec,
            tn,
            lambda d, q=q: d.groupby("g", sort=False, dropna=False)["x"].quantile(q).rename("o").reset_index(),
            lambda d, q=q: d.group_by("g", maintain_order=True).agg(pl.col("x").quantile(q, interpolation="linear").alias("o")),
        )
    # pandas only: sem, mode, argmin, argmax, any, all
    only = {
        "sem": lambda s: s.sem(),
        "any": lambda s: s.any(),
        "all": lambda s: s.all(),
        "mode": lambda s: s.agg(lambda v: v.mode().iloc[0] if len(v.mode()) else float("nan")),
        "arg_min": lambda s: s.agg(lambda v: v.idxmin() if v.notna().any() else float("nan")),
        "arg_max": lambda s: s.agg(lambda v: v.idxmax() if v.notna().any() else float("nan")),
    }
    for func, fp in only.items():
        case(
            f"{tag}-agg-{func}",
            "aggregate",
            {"by": ["h"], "aggs": [{"src": "x", "func": func, "out": "o"}], "skip_na": True},
            tn,
            lambda d, fp=fp: fp(d.groupby("h", sort=False)["x"]).rename("o").reset_index(),
        )
    # Group sorting and dropped missing keys: pandas' defaults, polars' explicit.
    case(
        f"{tag}-agg-sorted-dropna",
        "aggregate",
        {"by": ["g"], "aggs": [{"src": "x", "func": "sum", "out": "o"}], "skip_na": True, "sort": True, "dropkeys": True},
        tn,
        lambda d: d.groupby("g")["x"].sum().rename("o").reset_index(),
        lambda d: d.filter(pl.col("g").is_not_null()).group_by("g").agg(pl.col("x").sum().alias("o")).sort("g"),
    )


def sort_cases(tag, tn):
    grid = [
        ("x", True, "last"),
        ("x", False, "last"),
        ("x", True, "first"),
        ("x", False, "first"),
        ("t", True, "last"),
        ("g", False, "first"),
        ("n", False, "last"),
    ]
    for key, asc, pos in grid:
        case(
            f"{tag}-sort-{key}-{asc}-{pos}",
            "sort",
            {"keys": [{"k": key, "dir": "asc" if asc else "desc"}], "missing": pos},
            tn,
            lambda d, key=key, asc=asc, pos=pos: d.sort_values(key, ascending=asc, na_position=pos, kind="stable"),
            lambda d, key=key, asc=asc, pos=pos: d.sort(key, descending=not asc, nulls_last=pos == "last", maintain_order=True),
        )
    case(
        f"{tag}-sort-multi",
        "sort",
        {"keys": [{"k": "g", "dir": "asc"}, {"k": "x", "dir": "desc"}, {"k": "n", "dir": "asc"}], "missing": "last"},
        tn,
        lambda d: d.sort_values(["g", "x", "n"], ascending=[True, False, True], na_position="last", kind="stable"),
        lambda d: d.sort(["g", "x", "n"], descending=[False, True, False], nulls_last=True, maintain_order=True),
    )
    case(
        f"{tag}-nlargest",
        "nlargest",
        {"col": "x", "n": 5, "dir": "desc"},
        tn,
        lambda d: d.nlargest(5, "x", keep="first"),
        lambda d: d.filter(pl.col("x").is_not_null()).sort("x", descending=True, maintain_order=True).head(5),
    )
    case(
        f"{tag}-nsmallest",
        "nlargest",
        {"col": "x", "n": 5, "dir": "asc"},
        tn,
        lambda d: d.nsmallest(5, "x", keep="first"),
        lambda d: d.filter(pl.col("x").is_not_null()).sort("x", maintain_order=True).head(5),
    )


def col(n):
    return {"col": n}


def lit(v):
    return {"lit": v}


def bin_(op, l, r):
    return {"bin": op, "l": l, "r": r}


def un(op, x):
    return {"un": op, "x": x}


def expr_cases(tag, tn):
    arith = [
        ("add", lambda a, b: a + b),
        ("sub", lambda a, b: a - b),
        ("mul", lambda a, b: a * b),
        ("div", lambda a, b: a / b),
        ("floordiv", lambda a, b: a // b),
        ("mod", lambda a, b: a % b),
    ]
    for name, op in arith:
        for (lc, rc) in (("x", "y"), ("n", "y"), ("x", "n")):
            case(
                f"{tag}-mut-{name}-{lc}-{rc}",
                "mutate",
                {"out": "o", "expr": bin_(name, col(lc), col(rc))},
                tn,
                lambda d, op=op, lc=lc, rc=rc: d.assign(o=op(d[lc], d[rc])),
                lambda d, op=op, lc=lc, rc=rc: d.with_columns(op(pl.col(lc), pl.col(rc)).alias("o")),
            )
    # Integer-only: zero divisors excluded by construction (h + 1 >= 1).
    for name, op in arith[:3] + arith[4:6]:
        e = bin_(name, col("n"), bin_("add", col("h"), lit(1)))
        case(
            f"{tag}-mut-int-{name}",
            "mutate",
            {"out": "o", "expr": e},
            tn,
            lambda d, op=op: d.assign(o=op(d["n"], d["h"] + 1)),
            lambda d, op=op: d.with_columns(op(pl.col("n"), pl.col("h") + 1).alias("o")),
        )
    unary = [
        ("neg", lambda s: -s, lambda c: -c),
        ("abs", lambda s: s.abs(), lambda c: c.abs()),
        ("floor", lambda s: np.floor(s), lambda c: c.floor()),
        ("ceil", lambda s: np.ceil(s), lambda c: c.ceil()),
        ("exp", lambda s: np.exp(s / 100), None),
    ]
    for name, fp, fq in unary[:4]:
        case(
            f"{tag}-mut-{name}",
            "mutate",
            {"out": "o", "expr": un(name, col("x"))},
            tn,
            lambda d, fp=fp: d.assign(o=fp(d["x"])),
            lambda d, fq=fq: d.with_columns(fq(pl.col("x")).alias("o")),
        )
    case(
        f"{tag}-mut-round-half-even",
        "mutate",
        {"out": "o", "expr": un("round", bin_("div", col("n"), lit(2.0)))},
        tn,
        lambda d: d.assign(o=(d["n"] / 2.0).round()),
        lambda d: d.with_columns((pl.col("n") / 2.0).round(0).alias("o")),
        label="round: pandas half to even, polars half away from zero by default",
        follow="pandas",
    )
    case(
        f"{tag}-mut-pos-log-sqrt",
        "mutate",
        {"out": "o", "expr": un("sqrt", un("log", bin_("add", un("abs", col("y")), lit(1.5))))},
        tn,
        lambda d: d.assign(o=np.sqrt(np.log(d["y"].abs() + 1.5))),
        lambda d: d.with_columns((pl.col("y").abs() + 1.5).log().sqrt().alias("o")),
    )
    # Text.
    tl = [
        ("lower", lambda s: s.str.lower(), lambda c: c.str.to_lowercase()),
        ("upper", lambda s: s.str.upper(), lambda c: c.str.to_uppercase()),
        ("strip", lambda s: s.str.strip(), lambda c: c.str.strip_chars()),
        ("length", lambda s: s.str.len(), lambda c: c.str.len_chars()),
    ]
    for name, fp, fq in tl:
        case(
            f"{tag}-text-{name}",
            "mutate",
            {"out": "o", "expr": un(name, col("t"))},
            tn,
            lambda d, fp=fp: d.assign(o=fp(d["t"])),
            lambda d, fq=fq: d.with_columns(fq(pl.col("t")).alias("o")),
        )
    case(
        f"{tag}-text-concat",
        "mutate",
        {"out": "o", "expr": bin_("concat", col("g"), lit("!"))},
        tn,
        lambda d: d.assign(o=d["g"] + "!"),
        lambda d: d.with_columns((pl.col("g") + pl.lit("!")).alias("o")),
    )
    case(
        f"{tag}-text-replace",
        "mutate",
        {"out": "o", "expr": {"replace": col("t"), "from": "a", "to": "XY"}},
        tn,
        lambda d: d.assign(o=d["t"].str.replace("a", "XY", regex=False)),
        lambda d: d.with_columns(pl.col("t").str.replace_all("a", "XY", literal=True).alias("o")),
    )
    # Predicates that keep rows.
    preds = [
        ("gt", bin_("gt", col("x"), lit(0.0)), lambda d: d["x"] > 0, lambda: pl.col("x") > 0),
        ("xy", bin_("lt", col("x"), col("y")), lambda d: d["x"] < d["y"], lambda: pl.col("x") < pl.col("y")),
        ("ne", bin_("ne", col("g"), lit("a")), lambda d: d["g"].notna() & (d["g"] != "a"), lambda: pl.col("g") != "a"),
        ("and", bin_("and", bin_("gt", col("n"), lit(0)), bin_("le", col("y"), lit(5.0))), lambda d: (d["n"] > 0) & (d["y"] <= 5), lambda: (pl.col("n") > 0) & (pl.col("y") <= 5)),
        ("or", bin_("or", bin_("gt", col("x"), lit(5.0)), bin_("eq", col("g"), lit("b"))), lambda d: (d["x"] > 5) | (d["g"] == "b"), lambda: (pl.col("x") > 5) | (pl.col("g") == "b")),
        ("isin", {"in": col("h"), "vals": [1, 3]}, lambda d: d["h"].isin([1, 3]), lambda: pl.col("h").is_in([1, 3])),
        ("isnull", un("is_null", col("x")), lambda d: d["x"].isna(), lambda: pl.col("x").is_null()),
        ("contains", bin_("contains", col("t"), lit("a")), lambda d: d["t"].str.contains("a", regex=False, na=False), lambda: pl.col("t").str.contains("a", literal=True)),
        ("starts", bin_("starts_with", col("g"), lit("a")), lambda d: d["g"].str.startswith("a", na=False), lambda: pl.col("g").str.starts_with("a")),
    ]
    for name, e, fp, fq in preds:
        case(
            f"{tag}-where-{name}",
            "where",
            {"expr": e},
            tn,
            lambda d, fp=fp: d[fp(d)],
            lambda d, fq=fq: d.filter(fq()),
        )
    case(
        f"{tag}-where-not-kleene",
        "where",
        {"expr": un("not", bin_("gt", col("x"), lit(0.0)))},
        tn,
        lambda d: d[~(d["x"] > 0)],
        lambda d: d.filter(~(pl.col("x") > 0)),
        label="not(null > 0): SQL and polars null (row dropped), pandas' NaN compare False so not is True (row kept)",
        follow="polars",
    )
    case(
        f"{tag}-mut-ifelse",
        "mutate",
        {"out": "o", "expr": {"if": bin_("gt", col("n"), lit(0)), "then": col("y"), "else": lit(0.0)}},
        tn,
        lambda d: d.assign(o=np.where(d["n"] > 0, d["y"], 0.0)),
        lambda d: d.with_columns(pl.when(pl.col("n") > 0).then(pl.col("y")).otherwise(0.0).alias("o")),
    )
    case(
        f"{tag}-mut-coalesce",
        "mutate",
        {"out": "o", "expr": {"coalesce": [col("x"), col("k"), lit(-1.0)]}},
        tn,
        lambda d: d.assign(o=d["x"].fillna(d["k"]).fillna(-1.0)),
        lambda d: d.with_columns(pl.coalesce(pl.col("x"), pl.col("k"), pl.lit(-1.0)).alias("o")),
    )
    # Coercion.
    case(
        f"{tag}-cast-text-float",
        "cast",
        {"col": "s", "to": "float"},
        tn,
        lambda d: d.assign(s=pd.to_numeric(d["s"], errors="coerce")),
        lambda d: d.with_columns(pl.col("s").cast(pl.Float64, strict=False)),
    )
    case(
        f"{tag}-cast-float-int",
        "cast",
        {"col": "y", "to": "int"},
        tn,
        lambda d: d.assign(y=d["y"].astype(np.int64)),
        lambda d: d.with_columns(pl.col("y").cast(pl.Int64)),
    )
    case(
        f"{tag}-cast-int-float",
        "cast",
        {"col": "n", "to": "float"},
        tn,
        lambda d: d.assign(n=d["n"].astype(float)),
        lambda d: d.with_columns(pl.col("n").cast(pl.Float64)),
    )
    case(
        f"{tag}-cast-int-text",
        "cast",
        {"col": "n", "to": "text"},
        tn,
        lambda d: d.assign(n=d["n"].astype(str)),
        lambda d: d.with_columns(pl.col("n").cast(pl.String)),
    )
    case(
        f"{tag}-cast-bool-int",
        "cast",
        {"col": "b", "to": "int"},
        tn,
        lambda d: d.assign(b=d["b"].astype(np.int64)),
        lambda d: d.with_columns(pl.col("b").cast(pl.Int64)),
    )


def window_cases(tag, tn):
    def both(name, op, fp, fq, cols=("x", "n"), **kw):
        for src in cols:
            for by in (None, ["g"]):
                spec = {"value": src, "op": op, "by": by or []}
                pv = (lambda d, src=src, by=by, fp=fp: d.assign(o=fp(d.groupby(by, sort=False, dropna=False)[src] if by else d[src], d[src])))
                qv = None
                if fq:
                    qv = (lambda d, src=src, by=by, fq=fq: d.with_columns((fq(pl.col(src)).over(by) if by else fq(pl.col(src))).alias("o")))
                case(f"{tag}-win-{name}-{src}-{'+'.join(by or [])}", "window", spec, tn, pv, qv, **kw)

    # A grouped frame has no `.apply` shape that keeps row order for everything, so
    # the per-group forms below use the methods pandas has on SeriesGroupBy.
    both("shift1", {"shift": 1}, lambda g, s: g.shift(1), lambda c: c.shift(1))
    both("shift-2", {"shift": -2}, lambda g, s: g.shift(-2), lambda c: c.shift(-2))
    both("diff1", {"diff": 1}, lambda g, s: g.diff(1), lambda c: c.diff(1))
    both("diff2", {"diff": 2}, lambda g, s: g.diff(2), lambda c: c.diff(2))
    both("cumsum", {"cum": "sum"}, lambda g, s: g.cumsum(), lambda c: c.cum_sum())
    both("cumprod", {"cum": "prod"}, lambda g, s: g.cumprod(), lambda c: c.cum_prod(), cols=("y",))
    both("cummin", {"cum": "min"}, lambda g, s: g.cummin(), lambda c: c.cum_min())
    both("cummax", {"cum": "max"}, lambda g, s: g.cummax(), lambda c: c.cum_max())
    both("ffill", {"ffill": None}, lambda g, s: g.ffill(), lambda c: c.forward_fill(), cols=("x", "t"))
    both("bfill", {"bfill": None}, lambda g, s: g.bfill(), lambda c: c.backward_fill(), cols=("x", "t"))
    both("ffill1", {"ffill": 1}, lambda g, s: g.ffill(limit=1), lambda c: c.forward_fill(limit=1), cols=("x",))
    both("bfill2", {"bfill": 2}, lambda g, s: g.bfill(limit=2), lambda c: c.backward_fill(limit=2), cols=("x",))
    for method in ("average", "min", "max", "first", "dense"):
        plm = "ordinal" if method == "first" else method
        for desc in (False, True):
            both(
                f"rank-{method}-{desc}",
                {"rank": method, "desc": desc},
                lambda g, s, method=method, desc=desc: g.rank(method=method, ascending=not desc),
                lambda c, plm=plm, desc=desc: c.rank(method=plm, descending=desc),
                cols=("x",),
                label=None,
            )
    for w, mp, center in ((3, None, False), (3, 1, False), (5, 2, True), (4, 1, True)):
        for func in ("mean", "sum", "min", "max", "std", "var", "median"):
            plf = {"mean": "rolling_mean", "sum": "rolling_sum", "min": "rolling_min", "max": "rolling_max", "std": "rolling_std", "var": "rolling_var", "median": "rolling_median"}[func]
            spec_op = {"rolling": w, "func": func, "min_periods": mp, "center": center}
            mp_val = w if mp is None else mp
            for by in (None, ["g"]):
                case(
                    f"{tag}-win-rolling-{w}-{mp}-{center}-{func}-{'+'.join(by or [])}",
                    "window",
                    {"value": "x", "op": spec_op, "by": by or []},
                    tn,
                    (lambda d, w=w, mp_val=mp_val, center=center, func=func: d.assign(o=getattr(d["x"].rolling(w, min_periods=mp_val, center=center), func)()))
                    if not by
                    else (lambda d, by=by, w=w, mp_val=mp_val, center=center, func=func: d.assign(o=d.groupby(by, sort=False, dropna=False)["x"].transform(lambda s: getattr(s.rolling(w, min_periods=mp_val, center=center), func)()))),
                    (lambda d, w=w, mp_val=mp_val, center=center, plf=plf: d.with_columns(getattr(pl.col("x"), plf)(w, min_samples=mp_val, center=center).alias("o")))
                    if not by
                    else (lambda d, by=by, w=w, mp_val=mp_val, center=center, plf=plf: d.with_columns(getattr(pl.col("x"), plf)(w, min_samples=mp_val, center=center).over(by).alias("o"))),
                )
    for func in ("mean", "sum", "min", "max", "std", "var"):
        case(
            f"{tag}-win-expanding-{func}",
            "window",
            {"value": "x", "op": {"expanding": func, "min_periods": 2}, "by": []},
            tn,
            lambda d, func=func: d.assign(o=getattr(d["x"].expanding(min_periods=2), func)()),
        )
    case(
        f"{tag}-win-expanding-median",
        "window",
        {"value": "x", "op": {"expanding": "median", "min_periods": 1}, "by": []},
        tn,
        lambda d: d.assign(o=d["x"].expanding(min_periods=1).median()),
    )
    for adjust in (True, False):
        for ignore in (False, True):
            for mp in (0, 3):
                for func in ("mean", "var", "std"):
                    spec_op = {"ewm_com": 1.5, "adjust": adjust, "ignore_na": ignore, "min_periods": mp, "func": func}
                    fqn = {"mean": "ewm_mean", "var": "ewm_var", "std": "ewm_std"}[func]
                    kw = {} if func == "mean" else {"bias": False}
                    case(
                        f"{tag}-win-ewm-{adjust}-{ignore}-{mp}-{func}",
                        "window",
                        {"value": "x", "op": spec_op, "by": []},
                        tn,
                        lambda d, adjust=adjust, ignore=ignore, mp=mp, func=func: d.assign(o=getattr(d["x"].ewm(com=1.5, adjust=adjust, ignore_na=ignore, min_periods=mp), func)()),
                        lambda d, adjust=adjust, ignore=ignore, mp=mp, fqn=fqn, kw=kw: d.with_columns(getattr(pl.col("x"), fqn)(com=1.5, adjust=adjust, ignore_nulls=ignore, min_samples=max(mp, 1), **kw).alias("o")),
                        label="ewm on a null row: pandas repeats the running value, polars gives null there (the running state is the same)",
                        follow="pandas",
                    )
    case(
        f"{tag}-win-interp-extend",
        "window",
        {"value": "x", "op": {"interpolate": True}, "by": []},
        tn,
        lambda d: d.assign(o=d["x"].interpolate(limit_direction="forward")),
    )
    case(
        f"{tag}-win-interp",
        "window",
        {"value": "x", "op": {"interpolate": False}, "by": []},
        tn,
        fq=lambda d: d.with_columns(pl.col("x").interpolate().alias("o")),
    )
    case(
        f"{tag}-win-pctchange",
        "window",
        {"value": "y", "op": {"pct_change": 1}, "by": []},
        tn,
        lambda d: d.assign(o=d["y"].pct_change(1, fill_method=None)),
        lambda d: d.with_columns(pl.col("y").pct_change(1).alias("o")),
    )
    case(
        f"{tag}-win-cumcount",
        "window",
        {"value": "x", "op": {"cum": "count"}, "by": ["g"]},
        tn,
        lambda d: d.assign(o=d.groupby("g", sort=False, dropna=False).cumcount()),
    )
    for func in ("sum", "mean", "max", "std", "first", "size", "nunique", "median"):
        fq = {
            "sum": lambda c: c.sum(),
            "mean": lambda c: c.mean(),
            "max": lambda c: c.max(),
            "std": lambda c: c.std(),
            "first": lambda c: c.drop_nulls().first(),
            "size": lambda c: c.len(),
            "nunique": lambda c: c.drop_nulls().n_unique(),
            "median": lambda c: c.median(),
        }[func]
        case(
            f"{tag}-win-transform-{func}",
            "window",
            {"value": "x", "op": {"transform": func}, "by": ["g"]},
            tn,
            lambda d, func=func: d.assign(o=d.groupby("g", sort=False, dropna=False)["x"].transform(func)),
            lambda d, fq=fq: d.with_columns(fq(pl.col("x")).over("g").alias("o")),
        )
    day = 86_400_000_000
    for days in (3, 7):
        for func in ("mean", "sum", "min", "max"):
            plf = {"mean": "rolling_mean_by", "sum": "rolling_sum_by", "min": "rolling_min_by", "max": "rolling_max_by"}[func]
            case(
                f"{tag}-win-rolltime-{days}-{func}",
                "window",
                {"value": "x", "op": {"rolling_time": "w", "period": days * day, "func": func, "min_periods": 1}, "by": []},
                tn,
                lambda d, days=days, func=func: d.assign(o=getattr(d.set_index(pd.to_datetime(d["w"], unit="us"))["x"].rolling(f"{days}D", min_periods=1, closed="right"), func)().values),
                lambda d, days=days, plf=plf: d.with_columns(getattr(pl.col("x"), plf)(pl.col("w").cast(pl.Datetime("us")), window_size=f"{days}d", min_samples=1, closed="right").alias("o")),
            )


UNMATCHED_LABEL = "a right-only row nulls the left's int columns: pandas goes through float64 and loses values past 2^53, polars stays int64"


def join_cases(tag, tn, rn):
    pd_how = {"inner": "inner", "left": "left", "right": "right", "full": "outer"}
    pl_how = {"inner": "inner", "left": "left", "right": "right", "full": "full"}
    for how in pd_how:
        for on in (["h"], ["g"], ["k"], ["g", "h"]):
            for rcols in (["rv"],):
                right_cols = on + rcols
                spec = {"on": on, "how": how, "keep": right_cols, "coalesce": True, "null_keys": "match"}
                case(
                    f"{tag}-join-{how}-{'+'.join(on)}",
                    "join",
                    spec,
                    tn,
                    lambda l, r, on=on, how=how, rc=right_cols: l.merge(r[rc], on=on, how=pd_how[how]),
                    lambda l, r, on=on, how=how, rc=right_cols: l.join(r.select(rc), on=on, how=pl_how[how], nulls_equal=True, coalesce=True),
                    right=rn,
                    order="any",
                    label=UNMATCHED_LABEL,
                    follow="polars",
                )
        spec = {"on": ["k"], "how": how, "keep": ["k", "rv"], "coalesce": True, "null_keys": "no_match"}
        case(
            f"{tag}-join-{how}-nullsnomatch",
            "join",
            spec,
            tn,
            None,
            lambda l, r, how=how: l.join(r.select(["k", "rv"]), on="k", how=pl_how[how], nulls_equal=False, coalesce=True),
            right=rn,
            order="any",
        )
    for how, plh in (("semi", "semi"), ("anti", "anti")):
        for on in (["h"], ["g"]):
            case(
                f"{tag}-join-{how}-{on[0]}",
                "join",
                {"on": on, "how": how, "keep": [on[0], "rv"], "null_keys": "no_match"},
                tn,
                None,
                lambda l, r, on=on, plh=plh: l.join(r.select(on), on=on, how=plh),
                right=rn,
            )
    case(
        f"{tag}-join-cross",
        "join",
        {"how": "cross", "keep": ["rv"]},
        tn,
        lambda l, r: l[["n"]].merge(r[["rv"]], how="cross"),
        lambda l, r: l.select("n").join(r.select("rv"), how="cross"),
        right=rn,
        extra={"pre_select": ["n"]},
    )
    case(
        f"{tag}-join-suffix",
        "join",
        {"on": ["h"], "how": "inner", "keep": ["h", "y"], "suffix": "_r", "coalesce": False, "null_keys": "match"},
        tn,
        lambda l, r: l.merge(r[["h", "y"]], on="h", how="inner", suffixes=("", "_r")),
        lambda l, r: l.join(r.select(["h", "y"]), on="h", how="inner", suffix="_r"),
        right=rn,
        order="any",
    )
    case(
        f"{tag}-join-right-on",
        "join",
        {"on": ["h"], "right_on": ["k"], "how": "inner", "keep": ["k", "rv"], "coalesce": False, "null_keys": "match"},
        tn,
        fq=lambda l, r: l.with_columns(pl.col("h").cast(pl.Float64).alias("__h")).join(r.select(["k", "rv"]), left_on="__h", right_on="k", how="inner").drop("__h"),
        right=rn,
        order="any",
    )


def reshape_cases(tag, tn, rn):
    for agg, plagg in (("sum", "sum"), ("mean", "mean"), ("max", "max"), ("count", "len")):
        case(
            f"{tag}-pivot-{agg}",
            "pivot",
            {"r": "h", "c": "g", "v": "y", "agg": agg, "skip_na": True},
            tn,
            lambda d, agg=agg: d[d["g"].notna()].pivot_table(index="h", columns="g", values="y", aggfunc=agg, sort=False).reset_index(),
            lambda d, plagg=plagg: d.filter(pl.col("g").is_not_null()).pivot(on="g", index="h", values="y", aggregate_function=plagg),
            order="any",
            label="pivot, a cell no row fell into: pandas NaN, polars' sum 0",
            follow="pandas",
            extra={"pre_drop_null": "g"},
        )
    case(
        f"{tag}-pivot-fill",
        "pivot",
        {"r": "h", "c": "b", "v": "y", "agg": "sum", "skip_na": True, "fill": 0.0},
        tn,
        lambda d: d.assign(b=d["b"].astype(np.int64)).pivot_table(index="h", columns="b", values="y", aggfunc="sum", fill_value=0.0, sort=False).reset_index(),
        order="any",
        extra={"pre_cast_int": "b"},
    )
    case(
        f"{tag}-melt",
        "melt",
        {"ids": ["n"], "vals": ["x", "y"]},
        tn,
        lambda d: d.melt(id_vars=["n"], value_vars=["x", "y"]),
        lambda d: d.unpivot(index=["n"], on=["x", "y"]),
        order="any",
    )
    for keep, plk in (("first", "first"), ("last", "last"), ("none", "none")):
        for keys in (["g"], ["h", "g"]):
            case(
                f"{tag}-distinct-{keep}-{'+'.join(keys)}",
                "distinct",
                {"keys": keys, "keep": keep},
                tn,
                lambda d, keys=keys, keep=keep: d.drop_duplicates(subset=keys, keep=False if keep == "none" else keep),
                lambda d, keys=keys, plk=plk: d.unique(subset=keys, keep=plk, maintain_order=True),
                order="any",
            )
    for how in ("any", "all"):
        case(
            f"{tag}-dropna-{how}",
            "dropna",
            {"subset": ["x", "k"], "how": how},
            tn,
            lambda d, how=how: d.dropna(subset=["x", "k"], how=how),
            (lambda d: d.drop_nulls(subset=["x", "k"])) if how == "any" else (lambda d: d.filter(pl.col("x").is_not_null() | pl.col("k").is_not_null())),
        )
    case(
        f"{tag}-fillna",
        "fillna",
        {"subset": ["x"], "value": -1.5},
        tn,
        lambda d: d.fillna({"x": -1.5}),
        lambda d: d.with_columns(pl.col("x").fill_null(-1.5)),
    )
    case(
        f"{tag}-value-counts",
        "value_counts",
        {"cols": ["g"]},
        tn,
        lambda d: d["g"].value_counts().rename("count").reset_index(),
        lambda d: d.filter(pl.col("g").is_not_null())["g"].value_counts(sort=True),
        order="any",
    )
    case(
        f"{tag}-describe",
        "describe",
        {"cols": ["x", "y", "n"]},
        tn,
        lambda d: d[["x", "y", "n"]].describe().reset_index().rename(columns={"index": "statistic"}),
    )
    case(
        f"{tag}-clip",
        "clip",
        {"col": "x", "lower": -5.0, "upper": 5.0},
        tn,
        lambda d: d.assign(x=d["x"].clip(-5.0, 5.0)),
        lambda d: d.with_columns(pl.col("x").clip(-5.0, 5.0)),
    )
    case(
        f"{tag}-replace",
        "replace",
        {"col": "g", "pairs": [["a", "A"], ["b", "B"]]},
        tn,
        lambda d: d.assign(g=d["g"].replace({"a": "A", "b": "B"})),
        lambda d: d.with_columns(pl.col("g").replace({"a": "A", "b": "B"})),
    )
    for right_c, low in ((True, False), (True, True), (False, False), (False, True)):
        case(
            f"{tag}-cut-{right_c}-{low}",
            "cut",
            {"col": "y", "edges": [0.0, 3.0, 5.0, 7.0, 20.0], "right": right_c, "lowest": low},
            tn,
            lambda d, right_c=right_c, low=low: d.assign(o=pd.cut(d["y"], [0.0, 3.0, 5.0, 7.0, 20.0], labels=False, right=right_c, include_lowest=low)),
        )
    case(
        f"{tag}-tail",
        "tail",
        {"n": 4},
        tn,
        lambda d: d.tail(4),
        lambda d: d.tail(4),
    )
    case(
        f"{tag}-concat",
        "concat",
        {},
        tn,
        lambda l, r: pd.concat([l[["h", "x", "g"]], r[["h", "rv", "g"]]], ignore_index=True),
        lambda l, r: pl.concat([l.select(["h", "x", "g"]), r.select(["h", "rv", "g"])], how="diagonal"),
        right=rn,
        extra={"left_cols": ["h", "x", "g"], "right_cols": ["h", "rv", "g"]},
    )


def nan_cases(tag, tn):
    """Where NaN and null part ways: the labels the brief asks for."""
    case(
        f"{tag}-nan-group-sum",
        "aggregate",
        {"by": ["kn"], "aggs": [{"src": "xn", "func": "sum", "out": "o"}], "skip_na": True},
        tn,
        lambda d: d.groupby("kn", sort=False, dropna=False)["xn"].sum().rename("o").reset_index(),
        lambda d: d.group_by("kn", maintain_order=True).agg(pl.col("xn").fill_nan(None).sum().alias("o")),
        order="any",
        label="NaN grouping: pandas has one missing key, polars keeps NaN and null apart",
        follow="pandas",
    )
    case(
        f"{tag}-nan-sum-propagates",
        "aggregate",
        {"by": [], "aggs": [{"src": "xn", "func": "sum", "out": "o"}], "skip_na": True},
        tn,
        lambda d: pd.DataFrame({"o": [d["xn"].sum()]}),
        lambda d: d.select(pl.col("xn").sum().alias("o")),
        label="NaN in a sum: pandas skips it as missing, polars skips only null and NaN propagates",
        follow="pandas",
    )
    case(
        f"{tag}-nan-sort",
        "sort",
        {"keys": [{"k": "xn", "dir": "asc"}], "missing": "last"},
        tn,
        lambda d: d.sort_values("xn", na_position="last", kind="stable"),
        lambda d: d.sort("xn", nulls_last=True, maintain_order=True),
        label="null ordering: pandas one missing class at na_position, polars NaN as largest number then nulls; frozen rows show both as missing so they agree unless stability differs",
        follow="pandas",
    )
    case(
        f"{tag}-nan-join",
        "join",
        {"on": ["kn"], "how": "inner", "keep": ["kn"], "coalesce": True, "null_keys": "match"},
        tn,
        lambda d, r: d.merge(r[["kn"]].rename(columns={}), on="kn", how="inner", suffixes=("", "_r")),
        lambda d, r: d.join(r.select("kn"), on="kn", how="inner", nulls_equal=True),
        right=tn,
        order="any",
        label="NaN join keys: pandas matches NaN with NaN and with null (one missing class), polars matches NaN with NaN and null with null only",
        follow="pandas",
    )
    case(
        f"{tag}-nan-nunique",
        "aggregate",
        {"by": [], "aggs": [{"src": "kn", "func": "nunique", "out": "o"}], "skip_na": True},
        tn,
        lambda d: pd.DataFrame({"o": [d["kn"].nunique()]}),
        lambda d: d.select(pl.col("kn").fill_nan(None).drop_nulls().n_unique().alias("o")),
    )
    case(
        f"{tag}-nan-where",
        "where",
        {"expr": bin_("ge", col("xn"), lit(0.0))},
        tn,
        lambda d: d[d["xn"] >= 0],
        lambda d: d.filter(pl.col("xn") >= 0),
        label="NaN >= 0: pandas False, polars true (NaN the largest float)",
        follow="pandas",
    )


def asof_cases(tag, ln, rn):
    for direction in ("backward", "forward", "nearest"):
        for by in (None, "by"):
            for exact in (True, False):
                if not exact and direction == "nearest":
                    continue
                spec = {"on": "on", "by": [by] if by else [], "direction": direction, "allow_exact": exact}
                case(
                    f"{tag}-asof-{direction}-{by}-{exact}",
                    "asof",
                    spec,
                    ln,
                    lambda l, r, by=by, direction=direction, exact=exact: pd.merge_asof(l, r[["on", "rv"] + ([by] if by else [])], on="on", by=by, direction=direction, allow_exact_matches=exact),
                    (lambda l, r, by=by, direction=direction: l.join_asof(r.select(["on", "rv"] + ([by] if by else [])), on="on", by=by, strategy=direction)) if exact else None,
                    right=rn,
                    label="nearest on a tie: engines may pick either side" if direction == "nearest" else None,
                    follow="pandas",
                )
    case(
        f"{tag}-asof-tolerance",
        "asof",
        {"on": "on", "by": [], "direction": "backward", "allow_exact": True, "tolerance": 3.0},
        ln,
        lambda l, r: pd.merge_asof(l, r[["on", "rv"]], on="on", tolerance=3),
        lambda l, r: l.join_asof(r.select(["on", "rv"]), on="on", strategy="backward", tolerance=3),
        right=rn,
    )


def edge_cases(tag, tn, rn, wl, wr):
    """Past 2^53, a key column of ints and floats, int against float keys, tables that
    outgrow the hash table's first slots."""
    for func, (fp, fq) in AGGS_BOTH.items():
        if func in ("skew", "kurt", "std", "var", "prod", "median"):
            continue
        case(
            f"{tag}-big-agg-{func}",
            "aggregate",
            {"by": ["h"], "aggs": [{"src": "big", "func": func, "out": "o"}], "skip_na": True},
            tn,
            lambda d, fp=fp: fp(d.groupby("h", sort=False)["big"]).rename("o").reset_index(),
            lambda d, fq=fq: d.group_by("h", maintain_order=True).agg(fq(pl.col("big")).alias("o")),
        )
    for key in ("big", "mx"):
        case(
            f"{tag}-key-group-{key}",
            "aggregate",
            {"by": [key], "aggs": [{"src": "y", "func": "sum", "out": "o"}], "skip_na": True},
            tn,
            lambda d, key=key: d.groupby(key, sort=False, dropna=False)["y"].sum().rename("o").reset_index(),
            lambda d, key=key: d.group_by(key, maintain_order=True).agg(pl.col("y").sum().alias("o")),
        )
        case(
            f"{tag}-key-sort-{key}",
            "sort",
            {"keys": [{"k": key, "dir": "desc"}], "missing": "last"},
            tn,
            lambda d, key=key: d.sort_values(key, ascending=False, na_position="last", kind="stable"),
            lambda d, key=key: d.sort(key, descending=True, nulls_last=True, maintain_order=True),
        )
        for keep in ("first", "last"):
            case(
                f"{tag}-key-distinct-{key}-{keep}",
                "distinct",
                {"keys": [key], "keep": keep},
                tn,
                lambda d, key=key, keep=keep: d.drop_duplicates(subset=[key], keep=keep),
                lambda d, key=key, keep=keep: d.unique(subset=[key], keep=keep, maintain_order=True),
                order="any",
            )
        for how, pdh, plh in (("inner", "inner", "inner"), ("left", "left", "left"), ("full", "outer", "full")):
            case(
                f"{tag}-key-join-{key}-{how}",
                "join",
                {"on": [key], "how": how, "keep": [key, "rv"], "coalesce": True, "null_keys": "match"},
                tn,
                lambda l, r, key=key, pdh=pdh: l.merge(r[[key, "rv"]], on=key, how=pdh),
                lambda l, r, key=key, plh=plh: l.join(r.select([key, "rv"]), on=key, how=plh, nulls_equal=True, coalesce=True),
                right=rn,
                order="any",
                label=UNMATCHED_LABEL,
                follow="polars",
            )
    case(
        f"{tag}-key-join-int-float",
        "join",
        {"on": ["h"], "right_on": ["k"], "how": "inner", "keep": ["k", "rv"], "coalesce": False, "null_keys": "match"},
        tn,
        lambda l, r: l.merge(r[["k", "rv"]].rename(columns={"k": "__k"}), left_on="h", right_on="__k", how="inner").drop(columns="__k"),
        lambda l, r: l.with_columns(pl.col("h").cast(pl.Float64).alias("__h")).join(r.select(["k", "rv"]), left_on="__h", right_on="k", how="inner").drop("__h"),
        right=rn,
        order="any",
    )
    limit = TWO53 + 1
    case(
        f"{tag}-big-where-eq",
        "where",
        {"expr": bin_("eq", col("big"), lit(limit))},
        tn,
        lambda d: d[d["big"] == limit],
        lambda d: d.filter(pl.col("big") == limit),
    )
    case(
        f"{tag}-big-where-gt",
        "where",
        {"expr": bin_("gt", col("big"), lit(limit))},
        tn,
        lambda d: d[d["big"] > limit],
        lambda d: d.filter(pl.col("big") > limit),
    )
    case(
        f"{tag}-big-mutate-add",
        "mutate",
        {"out": "o", "expr": bin_("add", col("big"), lit(1))},
        tn,
        lambda d: d.assign(o=d["big"] + 1),
        lambda d: d.with_columns((pl.col("big") + 1).alias("o")),
    )
    case(
        f"{tag}-mx-where-in",
        "where",
        {"expr": {"in": col("mx"), "vals": [1, 2.5]}},
        tn,
        lambda d: d[d["mx"].isin([1.0, 2.5])],
        lambda d: d.filter(pl.col("mx").is_in([1.0, 2.5])),
    )
    big_int_label = "an int column with gaps: pandas goes through float64 and loses 2^53 + 1, polars stays int64"
    for name, op, fp, fq, label, follow in (
        ("cumsum", {"cum": "sum"}, lambda s: s.cumsum(), lambda c: c.cum_sum(), None, None),
        ("cummax", {"cum": "max"}, lambda s: s.cummax(), lambda c: c.cum_max(), None, None),
        ("diff", {"diff": 1}, lambda s: s.diff(1), lambda c: c.diff(1), big_int_label, "polars"),
        ("shift", {"shift": 1}, lambda s: s.shift(1), lambda c: c.shift(1), big_int_label, "polars"),
    ):
        case(f"{tag}-big-win-{name}", "window", {"value": "big", "op": op, "by": []}, tn, lambda d, fp=fp: d.assign(o=fp(d["big"])), lambda d, fq=fq: d.with_columns(fq(pl.col("big")).alias("o")), label=label, follow=follow)
    for func, fq in (("sum", lambda c: c.sum()), ("max", lambda c: c.max())):
        case(
            f"{tag}-big-win-transform-{func}",
            "window",
            {"value": "big", "op": {"transform": func}, "by": ["h"]},
            tn,
            lambda d, func=func: d.assign(o=d.groupby("h", sort=False)["big"].transform(func)),
            lambda d, fq=fq: d.with_columns(fq(pl.col("big")).over("h").alias("o")),
        )
    case(
        f"{tag}-cast-text-int",
        "cast",
        {"col": "s", "to": "int"},
        tn,
        None,
        lambda d: d.with_columns(pl.col("s").cast(pl.Int64, strict=False)),
    )
    # Wide tables.
    for key in ("ki", "kt", "kf"):
        case(
            f"{tag}-wide-group-{key}",
            "aggregate",
            {"by": [key], "aggs": [{"src": "v", "func": "sum", "out": "o"}, {"src": "v", "func": "max", "out": "p"}], "skip_na": True},
            wl,
            lambda d, key=key: d.groupby(key, sort=False, dropna=False)["v"].agg(o="sum", p="max").reset_index(),
            lambda d, key=key: d.group_by(key, maintain_order=True).agg(pl.col("v").sum().alias("o"), pl.col("v").max().alias("p")),
        )
        case(
            f"{tag}-wide-distinct-{key}",
            "distinct",
            {"keys": [key], "keep": "first"},
            wl,
            lambda d, key=key: d.drop_duplicates(subset=[key], keep="first"),
            lambda d, key=key: d.unique(subset=[key], keep="first", maintain_order=True),
        )
        case(
            f"{tag}-wide-sort-{key}",
            "sort",
            {"keys": [{"k": key, "dir": "asc"}], "missing": "first"},
            wl,
            lambda d, key=key: d.sort_values(key, na_position="first", kind="stable"),
            lambda d, key=key: d.sort(key, nulls_last=False, maintain_order=True),
        )
        for how, pdh, plh in (("inner", "inner", "inner"), ("full", "outer", "full")):
            case(
                f"{tag}-wide-join-{key}-{how}",
                "join",
                {"on": [key], "how": how, "keep": [key, "rv"], "coalesce": True, "null_keys": "match"},
                wl,
                lambda l, r, key=key, pdh=pdh: l[["i", key]].merge(r[[key, "rv"]], on=key, how=pdh),
                lambda l, r, key=key, plh=plh: l.select(["i", key]).join(r.select([key, "rv"]), on=key, how=plh, nulls_equal=True, coalesce=True),
                right=wr,
                order="any",
                extra={"pre_select": ["i", key]},
            )
        case(
            f"{tag}-wide-transform-{key}",
            "window",
            {"value": "v", "op": {"transform": "sum"}, "by": [key]},
            wl,
            lambda d, key=key: d.assign(o=d.groupby(key, sort=False, dropna=False)["v"].transform("sum")),
            lambda d, key=key: d.with_columns(pl.col("v").sum().over(key).alias("o")),
        )
    case(
        f"{tag}-wide-group-two",
        "aggregate",
        {"by": ["ki", "kt"], "aggs": [{"src": "v", "func": "sum", "out": "o"}], "skip_na": True},
        wl,
        lambda d: d.groupby(["ki", "kt"], sort=False, dropna=False)["v"].sum().rename("o").reset_index(),
        lambda d: d.group_by(["ki", "kt"], maintain_order=True).agg(pl.col("v").sum().alias("o")),
    )


def main():
    for seed in SEEDS:
        tag = f"s{seed}"
        tables[f"t{seed}"] = gen(seed)
        tables[f"r{seed}"] = gen_right(seed)
        tables[f"n{seed}"] = gen_nan(seed)
        al, ar = gen_asof(seed)
        tables[f"al{seed}"] = al
        tables[f"ar{seed}"] = ar
        agg_cases(tag, f"t{seed}")
        sort_cases(tag, f"t{seed}")
        expr_cases(tag, f"t{seed}")
        window_cases(tag, f"t{seed}")
        join_cases(tag, f"t{seed}", f"r{seed}")
        reshape_cases(tag, f"t{seed}", f"r{seed}")
        nan_cases(tag, f"n{seed}")
        asof_cases(tag, f"al{seed}", f"ar{seed}")
        tables[f"wl{seed}"] = gen_wide(seed, 200, "l")
        tables[f"wr{seed}"] = gen_wide(seed, 150, "r")
        edge_cases(tag, f"t{seed}", f"r{seed}", f"wl{seed}", f"wr{seed}")

    def tbl(t):
        cols = [{"name": c, "type": ty} for c, (ty, _) in t.items()]
        n = len(next(iter(t.values()))[1])

        def enc(v):
            if isinstance(v, float) and math.isnan(v):
                return "NaN"
            return v

        return {"columns": cols, "rows": [[enc(t[c][1][i]) for c in t] for i in range(n)]}

    out = {
        "generator": "tools/oracle.py",
        "pandas": pd.__version__,
        "polars": pl.__version__,
        "numpy": np.__version__,
        "tables": {k: tbl(v) for k, v in tables.items()},
        "cases": cases,
    }
    json.dump(out, sys.stdout, separators=(",", ":"), ensure_ascii=True)
    sys.stdout.write("\n")
    sys.stderr.write(f"{len(cases)} cases: {stats}\n")


main()
