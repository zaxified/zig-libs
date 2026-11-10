#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for dataframe S2 wave W11, real fixed-width numeric dtypes: how polars 2.1 and
pandas 3.1 behave for Int8/16/32/64, UInt8/16/32/64, Float32 and Float64 (supertypes, overflow,
weak literals, unary ops, aggregates, casts, f64 -> f32, CSV/JSON writing and reading with a
declared width, join/group/sort keys, when/coalesce/fill_null, repr names), frozen into
src/oracle2j_vectors.json. No line of dataframe is consulted: the expected values are what the
engines answer.

    python tools/oracle2j.py src/oracle2j_vectors.json      (see tools/README.md)

One case = {id, kind, engine, op, in, dtype_out, expect, error}. Ids end in `-pl` (polars), `-pd`
(pandas, numpy dtypes) or `-pdn` (pandas nullable dtypes; written only where it differs from the
numpy answer, or where the case needs a null, which numpy cannot hold). Dtype names are polars short
names (i8 .. u64 f32 f64 bool str) for both engines. NaN / inf are the strings "nan" / "inf" /
"-inf"; a Float32 result also carries `bits`, the list of f32 bit patterns ("0x3dcccccd", null for a
null), so the replay can compare exactly. `"error": true` means the engine raised and that IS the
answer (`msg` holds the exception class and the start of its text). Per-cell kinds (cast, read)
write `{"error": true}` as the cell of a value the engine refused and set the case flag when any
cell did. Text results (writers, repr) are `expect: [text]`; table results (joins, group_by) are
`expect: [[cell, ...], ...]` rows. Rows that hold a null are dropped for the numpy pandas case
(numpy has no null), so its `in` can be shorter than the polars one.
"""
import io
import json
import math
import struct
import sys
import warnings
from collections import Counter

import numpy as np
import pandas as pd
import polars as pl

warnings.simplefilter("ignore")
np.seterr(all="ignore")

cases = []
problems = []
notes = []

DT = ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64"]
PL = {"i8": pl.Int8, "i16": pl.Int16, "i32": pl.Int32, "i64": pl.Int64, "u8": pl.UInt8, "u16": pl.UInt16,
      "u32": pl.UInt32, "u64": pl.UInt64, "f32": pl.Float32, "f64": pl.Float64, "bool": pl.Boolean, "str": pl.String}
NP = {"i8": "int8", "i16": "int16", "i32": "int32", "i64": "int64", "u8": "uint8", "u16": "uint16",
      "u32": "uint32", "u64": "uint64", "f32": "float32", "f64": "float64", "bool": "bool", "str": "str"}
NU = {"i8": "Int8", "i16": "Int16", "i32": "Int32", "i64": "Int64", "u8": "UInt8", "u16": "UInt16",
      "u32": "UInt32", "u64": "UInt64", "f32": "Float32", "f64": "Float64", "bool": "boolean", "str": "string"}
SN = {"int8": "i8", "int16": "i16", "int32": "i32", "int64": "i64", "uint8": "u8", "uint16": "u16",
      "uint32": "u32", "uint64": "u64", "float32": "f32", "float64": "f64", "boolean": "bool", "bool": "bool",
      "string": "str", "str": "str", "object": "obj", "int128": "i128"}
F32MAX = float(np.finfo(np.float32).max)
F64MAX = sys.float_info.max
EXC = (Exception, pl.exceptions.PanicException)
HARNESS_BUGS = (NameError, SyntaxError, UnboundLocalError)


def isint(dt):
    return dt[0] in "iu"


def issigned(dt):
    return dt[0] == "i"


def width(dt):
    return int(dt[1:])


def imin(dt):
    return -(2 ** (width(dt) - 1)) if issigned(dt) else 0


def imax(dt):
    return 2 ** (width(dt) - 1) - 1 if issigned(dt) else 2 ** width(dt) - 1


def fmax(dt):
    return F32MAX if dt == "f32" else F64MAX


def sname(dt):
    s = str(dt).lower()
    return SN.get(s, s)


def enc(v):
    if v is None or v is pd.NA or v is pd.NaT:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        v = float(v)
        if math.isnan(v):
            return "nan"
        if math.isinf(v):
            return "inf" if v > 0 else "-inf"
        return v
    if isinstance(v, dict):
        return {k: enc(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [enc(x) for x in v]
    return str(v)


def enc_in(dt, vals):
    return [enc(float(np.float32(v)) if dt == "f32" and isinstance(v, float) else v) for v in vals]


def f32bits(v):
    if v is None or isinstance(v, (dict, list, bool)):
        return None
    if isinstance(v, str):
        if v not in ("nan", "inf", "-inf"):
            return None
        v = float(v)
    return "0x%08x" % int(np.float32(v).view(np.uint32))


class Res:
    """A result a thunk builds by hand (rows, text, ...)."""

    def __init__(self, dtype, vals):
        self.dtype, self.vals = dtype, vals


def out_of(res):
    if isinstance(res, Res):
        return res.dtype, res.vals
    if isinstance(res, pl.Series):
        return sname(res.dtype), res.to_list()
    if isinstance(res, pd.Series):
        return sname(res.dtype), res.tolist()
    if isinstance(res, np.generic):
        return sname(res.dtype), [res.item()]
    if res is None or res is pd.NA:
        return "null", [None]
    if isinstance(res, bool):
        return "bool", [res]
    if isinstance(res, int):
        return "i64", [res]
    if isinstance(res, float):
        return "f64", [res]
    if isinstance(res, str):
        return "str", [res]
    raise TypeError(f"harness: result {type(res)}")


def build(id, kind, engine, op, inp, thunk, extra):
    c = {"id": id, "kind": kind, "engine": engine, "op": op, "in": inp}
    try:
        dt, vals = out_of(thunk())
        c.update({"dtype_out": dt, "expect": enc(vals), "error": False})
        if dt == "f32":
            c["bits"] = [f32bits(x) for x in c["expect"]]
    except HARNESS_BUGS as e:
        problems.append(f"{id}: HARNESS {type(e).__name__}: {e}")
        c.update({"dtype_out": None, "expect": None, "error": True, "msg": "harness"})
    except EXC as e:  # noqa: BLE001 - the engine's refusal is the answer
        c.update({"dtype_out": None, "expect": None, "error": True, "msg": f"{type(e).__name__}: {str(e)[:48]}".replace("\n", " ")})
    c.update(extra)
    return c


def mkpl(dt, vals):
    return pl.Series("a", vals, dtype=PL[dt], strict=True)


def mkpd(dt, vals, nullable):
    if nullable:
        return pd.Series(vals, dtype=NU[dt])
    return pd.Series(np.array(vals, dtype=NP[dt]))


def plx(s, f):
    return pl.DataFrame({"a": s}).select(f(pl.col("a")).alias("a"))["a"]


def tri(id, kind, op, spec, plf, pdf, np_ok=True, **extra):
    """spec = {name: (dtype, values)} with equal-length columns. plf/pdf get the named Series."""
    names = list(spec)
    n = len(spec[names[0]][1])
    inp = {k: {"dtype": d, "values": enc_in(d, v)} for k, (d, v) in spec.items()}
    keep = [i for i in range(n) if all(spec[k][1][i] is not None for k in names)]
    nonull = {k: (d, [v[i] for i in keep]) for k, (d, v) in spec.items()}
    inp_nn = {k: {"dtype": d, "values": enc_in(d, v)} for k, (d, v) in nonull.items()}
    has_null = len(keep) != n
    if plf:
        cases.append(build(id + "-pl", kind, "pl", op, inp, lambda: plf(*[mkpl(d, v) for k, (d, v) in spec.items()]), extra))
    pdc = None
    if pdf and np_ok:
        pdc = build(id + "-pd", kind, "pd", op, inp_nn, lambda: pdf(*[mkpd(d, v, False) for k, (d, v) in nonull.items()]), extra)
        cases.append(pdc)
    if pdf:
        pdn = build(id + "-pdn", kind, "pd", op, inp, lambda: pdf(*[mkpd(d, v, True) for k, (d, v) in spec.items()]), extra)
        key = lambda c: (c["dtype_out"], json.dumps(c["expect"]), c["error"])  # noqa: E731
        if has_null or pdc is None or key(pdn) != key(pdc):
            cases.append(pdn)


def vals_arith(dt):
    """Seven rows pairing extremes of both sides; a null last (row 6 is a null on the left)."""
    lo, hi = (-fmax(dt), fmax(dt)) if not isint(dt) else (imin(dt), imax(dt))
    return lo, hi


# 1 supertype ------------------------------------------------------------------------------------

BINOPS = {"add": lambda a, b: a + b, "sub": lambda a, b: a - b, "mul": lambda a, b: a * b,
          "truediv": lambda a, b: a / b, "floordiv": lambda a, b: a // b, "mod": lambda a, b: a % b}


def g_supertype():
    for x in DT:
        for y in DT:
            alo, ahi = vals_arith(x)
            blo, bhi = vals_arith(y)
            one, zero = (1, 0) if isint(x) else (1.0, 0.0)
            oneb, zerob = (1, 0) if isint(y) else (1.0, 0.0)
            two = 2 if isint(y) else 2.0
            a = [alo, ahi, ahi, one, zero, None]
            b = [bhi, blo, bhi, oneb, zerob, two]
            for opn, f in BINOPS.items():
                n = 6 if opn in ("add", "truediv") else 5  # the null row only where it decides nothing else
                tri(f"st-{opn}-{x}-{y}", "supertype", opn, {"a": (x, a[:n]), "b": (y, b[:n])}, f, f)
            tri(f"st-concat-{x}-{y}", "supertype_concat", "concat", {"a": (x, a), "b": (y, b)},
                lambda a, b: pl.concat([pl.DataFrame({"a": a}), pl.DataFrame({"a": b})], how="vertical_relaxed")["a"],
                lambda a, b: pd.concat([a, b], ignore_index=True))


# 2 overflow -------------------------------------------------------------------------------------

def g_overflow():
    ops = {"add1": lambda a: a + 1, "sub1": lambda a: a - 1, "mul2": lambda a: a * 2, "mulneg1": lambda a: a * -1,
           "floordivneg1": lambda a: a // -1, "mod0": lambda a: a % 0, "floordiv0": lambda a: a // 0,
           "modneg1": lambda a: a % -1}
    for dt in DT[:8]:
        v = [imin(dt), imax(dt), 0, 1, -1] if issigned(dt) else [0, 1, 2, imax(dt)]
        for n, f in ops.items():
            tri(f"ov-{n}-{dt}", "overflow", n, {"a": (dt, v)}, f, f)


# 3 weak literals --------------------------------------------------------------------------------

LITS = [0, 1, -1, 127, 128, 255, 256, 1000, 2 ** 31, 2 ** 32, 2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 1.5, 0.1]


def g_literals():
    for dt in DT:
        v = ([imin(dt), imax(dt), 1, None] if isint(dt) else [-fmax(dt), fmax(dt), 1.0, None])
        for i, lit in enumerate(LITS):
            tag = f"lit-{dt}-{i}"
            ex = {"lit": enc(lit)}
            pls = {"add": lambda c, L=lit: c + L, "mul": lambda c, L=lit: c * L, "eq": lambda c, L=lit: c == L,
                   "lt": lambda c, L=lit: c < L, "fill_null": lambda c, L=lit: c.fill_null(L)}
            pds = {"add": lambda s, L=lit: s + L, "mul": lambda s, L=lit: s * L, "eq": lambda s, L=lit: s == L,
                   "lt": lambda s, L=lit: s < L, "fill_null": lambda s, L=lit: s.fillna(L)}
            for opn in pls:
                tri(f"{tag}-{opn}", "weak_literal", opn, {"a": (dt, v if opn == "fill_null" else v[:3])}, lambda a, f=pls[opn]: plx(a, f), pds[opn],
                    np_ok=opn != "fill_null", **ex)


# 4 unary ----------------------------------------------------------------------------------------

def g_unary():
    ops = {"neg": (lambda c: -c, lambda s: -s), "abs": (lambda c: c.abs(), lambda s: s.abs()),
           "sign": (lambda c: c.sign(), lambda s: np.sign(s)), "sqrt": (lambda c: c.sqrt(), lambda s: np.sqrt(s)),
           "pow2": (lambda c: c.pow(2), lambda s: s.pow(2)), "pow0.5": (lambda c: c.pow(0.5), lambda s: s.pow(0.5)),
           "is_nan": (lambda c: c.is_nan(), lambda s: np.isnan(s)), "round1": (lambda c: c.round(1), lambda s: s.round(1))}
    nan = float("nan")
    for dt in DT:
        if isint(dt):
            v = [imin(dt), imax(dt), 0, 1, -1] if issigned(dt) else [0, 1, 4, imax(dt)]
        else:
            v = [-1.5, 2.5, 0.0, -0.0, nan, 0.25, 1e30, -fmax(dt)]
        for n, (p, q) in ops.items():
            tri(f"un-{n}-{dt}", "unary", n, {"a": (dt, v)}, lambda a, f=p: plx(a, f), q)


# 5 aggregates -----------------------------------------------------------------------------------

AGG = {"sum": (lambda c: c.sum(), lambda s: s.sum()), "mean": (lambda c: c.mean(), lambda s: s.mean()),
       "median": (lambda c: c.median(), lambda s: s.median()), "min": (lambda c: c.min(), lambda s: s.min()),
       "max": (lambda c: c.max(), lambda s: s.max()), "std": (lambda c: c.std(), lambda s: s.std()),
       "var": (lambda c: c.var(), lambda s: s.var()), "quantile": (lambda c: c.quantile(0.5), lambda s: s.quantile(0.5)),
       "product": (lambda c: c.product(), lambda s: s.prod()), "n_unique": (lambda c: c.n_unique(), lambda s: s.nunique()),
       "first": (lambda c: c.first(), lambda s: s.iloc[0]), "last": (lambda c: c.last(), lambda s: s.iloc[-1]),
       "mode": (lambda c: c.mode(), lambda s: s.mode()), "cum_sum": (lambda c: c.cum_sum(), lambda s: s.cumsum()),
       "cum_prod": (lambda c: c.cum_prod(), lambda s: s.cumprod()), "cum_min": (lambda c: c.cum_min(), lambda s: s.cummin()),
       "cum_max": (lambda c: c.cum_max(), lambda s: s.cummax()), "diff": (lambda c: c.diff(), lambda s: s.diff()),
       "pct_change": (lambda c: c.pct_change(), lambda s: s.pct_change()), "rank": (lambda c: c.rank(), lambda s: s.rank())}


def g_agg():
    for dt in DT:
        if isint(dt):
            big = [imax(dt), imax(dt), 1, 2] if not issigned(dt) else [imax(dt), imax(dt), imin(dt), 3]
            small = [1, 2, 2, 5, 3]
        else:
            big = [fmax(dt), fmax(dt), 1.0, 2.0]
            small = [1.5, 2.5, 2.5, 4.0, 0.5]
        for cn, col in (("big", big), ("small", small)):
            for n, (p, q) in AGG.items():
                tri(f"ag-{n}-{dt}-{cn}", "aggregate", n, {"a": (dt, col)}, lambda a, f=p: plx(a, f), q, col=cn)
        nul = [1, None, 3, 3] if isint(dt) else [1.5, None, 2.5, 2.5]
        for n in ("sum", "mean", "min", "cum_sum", "n_unique", "diff"):
            p, q = AGG[n]
            tri(f"ag-{n}-{dt}-null", "aggregate", n, {"a": (dt, nul)}, lambda a, f=p: plx(a, f), q, np_ok=False, col="null")
        # group_by
        for cn, col in (("big", big), ("small", small)):
            keys = [1, 1, 2, 2][:len(col)] + [2] * max(0, len(col) - 4)
            for n in ("sum", "mean"):
                tri(f"gb-{n}-{dt}-{cn}", "group_agg", n, {"k": ("i64", keys), "a": (dt, col)},
                    lambda k, a, n=n: pl.DataFrame({"k": k, "a": a}).group_by("k", maintain_order=True).agg(getattr(pl.col("a"), n)())["a"],
                    lambda k, a, n=n: getattr(pd.DataFrame({"k": k, "a": a}).groupby("k", sort=False)["a"], n)(), col=cn)


# 6 cast and 7 f64 -> f32 ------------------------------------------------------------------------

STRS = [" 7", "7", "7.0", "1e3", "0x10", "-0", "+5", "", "300", "-1", "3.5", "abc", "nan", "inf", "99999999999999999999"]
FLT = [float("nan"), float("inf"), float("-inf"), -0.0, 0.0, 0.5, -0.5, 1.5, -1.5, 2.5, 127.0, 128.0, 255.0, 256.0, -129.0,
       32768.0, 65536.0, 2.0 ** 31, 2.0 ** 32, float(2 ** 53 + 1), 2.0 ** 63, 2.0 ** 64, -(2.0 ** 63), 1e10, 1e300, F32MAX, 16777217.0]
INTC = [-129, -128, -1, 0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1, 2 ** 32,
        2 ** 53 + 1, 2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, -(2 ** 31) - 1, -(2 ** 63)]


def cast_inputs(src):
    if src == "bool":
        return [True, False]
    if src == "str":
        return STRS
    if src in ("f32", "f64"):
        out, seen = [], set()
        for v in FLT:
            w = float(np.float32(v)) if src == "f32" else v
            k = repr(w)
            if k not in seen:
                seen.add(k)
                out.append(w)
        return out
    return [v for v in INTC if imin(src) <= v <= imax(src)]


def cell_of(r):
    return (r.tolist() if isinstance(r, pd.Series) else r.to_list())[0]


def per_value(id, kind, engine, op, src, dst, vals, fn, **extra):
    cells, dts, errs = [], set(), Counter()
    for v in vals:
        try:
            r = fn(v)
            dts.add(sname(r.dtype))
            cells.append(cell_of(r))
        except HARNESS_BUGS as e:
            problems.append(f"{id}: HARNESS {e}")
            cells.append({"error": True})
        except EXC as e:  # noqa: BLE001
            cells.append({"error": True})
            errs[type(e).__name__] += 1
    c = {"id": id, "kind": kind, "engine": engine, "op": op,
         "in": {"a": {"dtype": src, "values": enc_in(src, vals)}}, "dtype_out": "|".join(sorted(dts)) or dst,
         "expect": [x if isinstance(x, dict) else enc(x) for x in cells], "error": bool(errs), **extra}
    if errs:
        c["errs"] = dict(errs)
    if dst == "f32":
        c["bits"] = [None if isinstance(x, dict) else f32bits(enc(x)) for x in cells]
    cases.append(c)


def g_cast():
    for src in DT + ["str", "bool"]:
        vals = cast_inputs(src)
        for dst in DT:
            t = PL[dst]
            ps = lambda v, src=src: pl.Series([v], dtype=PL[src], strict=True)  # noqa: E731
            per_value(f"cast-strict-{src}-{dst}-pl", "cast", "pl", "strict", src, dst, vals, lambda v, ps=ps, t=t: ps(v).cast(t, strict=True))
            per_value(f"cast-nonstrict-{src}-{dst}-pl", "cast", "pl", "nonstrict", src, dst, vals, lambda v, ps=ps, t=t: ps(v).cast(t, strict=False))
            per_value(f"cast-wrap-{src}-{dst}-pl", "cast", "pl", "wrap", src, dst, vals, lambda v, ps=ps, t=t: ps(v).cast(t, wrap_numerical=True))
            if src == "str":
                mk = lambda v: pd.Series([v], dtype="str")  # noqa: E731
                mn = lambda v: pd.Series([v], dtype="string")  # noqa: E731
            else:
                mk = lambda v, src=src: pd.Series(np.array([v], dtype=NP[src]))  # noqa: E731
                mn = lambda v, src=src: pd.Series([v], dtype=NU[src])  # noqa: E731
            per_value(f"cast-astype-{src}-{dst}-pd", "cast", "pd", "astype", src, dst, vals, lambda v, mk=mk, d=NP[dst]: mk(v).astype(d))
            per_value(f"cast-astype-{src}-{dst}-pdn", "cast", "pd", "astype", src, dst, vals, lambda v, mn=mn, d=NU[dst]: mn(v).astype(d))
        if src == "str":
            per_value("cast-coerce-str-any-pd", "cast", "pd", "to_numeric_coerce", src, "f64", vals,
                      lambda v: pd.to_numeric(pd.Series([v], dtype="str"), errors="coerce"))
    # the cast family of one value of each text, polars str -> int with literal parse rules is above.


def g_f32():
    v = [0.1, 1e300, -1e300, 1e-50, 3.4028235e38, 16777217.0, float("nan"), float("inf"), 1e-45, 1.0 / 3, 3.5e38, -3.5e38]
    tri("f32-f64_to_f32", "cast", "f64_to_f32", {"a": ("f64", v)}, lambda a: a.cast(pl.Float32), lambda a: a.astype("float32"))
    w = [0.1, 1.0 / 3, 1e-45, 3.4028235e38, 16777216.0, 1e7, 0.5, -0.0, 16777217.0]
    tri("f32-f32_to_f64", "cast", "f32_to_f64", {"a": ("f32", w)}, lambda a: a.cast(pl.Float64), lambda a: a.astype("float64"))


# 8 write ----------------------------------------------------------------------------------------

def g_write():
    nan = float("nan")
    fl = [0.1, 1.0 / 3, 1e-45, 3.4028235e38, 16777216.0, 1e7, 1e16, 0.5, -0.0, nan, float("inf"), 1.7976931348623157e308, 123456789.123456789]
    for dt in DT:
        v = ([imin(dt), imax(dt), 0, 1, None] if isint(dt) else fl[:11] + ([] if dt == "f32" else fl[11:]) + [None])
        fm = {
            "csv": (lambda a: pl.DataFrame({"x": a}).write_csv(), lambda a: pd.DataFrame({"x": a}).to_csv(index=False)),
            "json": (lambda a: pl.DataFrame({"x": a}).write_json(), lambda a: pd.DataFrame({"x": a}).to_json(orient="records")),
            "ndjson": (lambda a: pl.DataFrame({"x": a}).write_ndjson(), lambda a: pd.DataFrame({"x": a}).to_json(orient="records", lines=True)),
            "table": (None, lambda a: pd.DataFrame({"x": a}).to_json(orient="table", index=False)),
        }
        for n, (p, q) in fm.items():
            tri(f"wr-{n}-{dt}", "write", n, {"a": (dt, v)}, p and (lambda a, p=p: Res("str", [p(a)])), lambda a, q=q: Res("str", [q(a)]))


# 9 read -----------------------------------------------------------------------------------------

RV = ["5", "127", "128", "255", "256", "-1", "-129", "300", "65536", "2147483648", "4294967296", "9223372036854775808",
      "18446744073709551615", "-9223372036854775809", "1.0", "1e2", "", " 5", "5.5", "abc", "0x10", "3.4028235e38", "1e39", "0.1"]
RJ = ["5", "127", "128", "255", "256", "-1", "-129", "300", "2147483648", "9223372036854775808", "18446744073709551615",
      "1.0", "1e2", "null", "\"5\"", "\"\"", "5.5", "true", "3.4028235e38", "1e39", "0.1"]


def g_read():
    for dt in DT:
        t = PL[dt]

        def rd(id, op, engine, vals, mk, fn):
            cells, errs = [], Counter()
            for v in vals:
                try:
                    cells.append(cell_of(fn(mk(v))))
                except EXC as e:  # noqa: BLE001
                    cells.append({"error": True})
                    errs[type(e).__name__] += 1
            c = {"id": id, "kind": "read", "engine": engine, "op": op, "in": {"x": {"dtype": "str", "values": vals}, "schema": {"dtype": dt, "values": []}},
                 "dtype_out": dt, "expect": [x if isinstance(x, dict) else enc(x) for x in cells], "error": bool(errs)}
            if errs:
                c["errs"] = dict(errs)
            if dt == "f32":
                c["bits"] = [None if isinstance(x, dict) else f32bits(enc(x)) for x in cells]
            cases.append(c)
        csv = lambda v: io.BytesIO(f"x,y\n{v},1\n".encode())  # noqa: E731
        js = lambda v: io.BytesIO(f'[{{"x":{v}}}]'.encode())  # noqa: E731
        nd = lambda v: io.BytesIO(f'{{"x":{v}}}\n'.encode())  # noqa: E731
        rd(f"rd-csv-{dt}-pl", "read_csv", "pl", RV, csv, lambda b: pl.read_csv(b, schema={"x": t, "y": pl.Int64})["x"])
        rd(f"rd-json-{dt}-pl", "read_json", "pl", RJ, js, lambda b: pl.read_json(b, schema={"x": t})["x"])
        rd(f"rd-ndjson-{dt}-pl", "read_ndjson", "pl", RJ, nd, lambda b: pl.read_ndjson(b, schema={"x": t})["x"])
        for tag, d in (("pd", NP[dt]), ("pdn", NU[dt])):
            rd(f"rd-csv-{dt}-{tag}", "read_csv", "pd", RV, csv, lambda b, d=d: pd.read_csv(b, dtype={"x": d})["x"])
            rd(f"rd-json-{dt}-{tag}", "read_json", "pd", RJ, lambda v: io.StringIO(f'[{{"x":{v}}}]'), lambda b, d=d: pd.read_json(b, dtype={"x": d})["x"])
            rd(f"rd-ndjson-{dt}-{tag}", "read_ndjson", "pd", RJ, lambda v: io.StringIO(f'{{"x":{v}}}\n'), lambda b, d=d: pd.read_json(b, lines=True, dtype={"x": d})["x"])


# 10 keys ----------------------------------------------------------------------------------------

def g_keys():
    pairs = [("i8", "i64"), ("i64", "i8"), ("u8", "i64"), ("i32", "i64"), ("u32", "i64"), ("u64", "i64"), ("i64", "u64"),
             ("i32", "f64"), ("f32", "f64"), ("i8", "u8"), ("i16", "i32"), ("u64", "f64"), ("i64", "f64"), ("u32", "i32")]
    for x, y in pairs:
        if "u64" in (x, y) and "i64" in (x, y):
            lk, rk = [1, 2 ** 63, 2 ** 64 - 1, 5], [1, -1, 2 ** 63 - 1, 5]
            if x == "i64":
                lk, rk = rk, lk
        elif "f" in x + y:
            lk, rk = [1, 2, 3, 100], [1, 2.5, 100, 3]
        else:
            lk, rk = [1, 2, 3, 100], [100, 3, 4, 1]
        inp = {"left_k": {"dtype": x, "values": enc_in(x, lk)}, "right_k": {"dtype": y, "values": enc_in(y, rk)},
               "left_v": {"dtype": "i64", "values": [10, 20, 30, 40]}, "right_w": {"dtype": "i64", "values": [1, 2, 3, 4]}}
        for how in ("inner",):
            def pl_j():
                l = pl.DataFrame({"k": pl.Series(lk, dtype=PL[x]), "v": [10, 20, 30, 40]})
                r = pl.DataFrame({"k": pl.Series(rk, dtype=PL[y]), "w": [1, 2, 3, 4]})
                j = l.join(r, on="k", how=how).sort("v")
                return Res(sname(j["k"].dtype), [list(t) for t in j.select("v", "w", "k").iter_rows()])

            def pd_j(nullable):
                def f():
                    mk = (lambda d, v: pd.Series(v, dtype=NU[d])) if nullable else (lambda d, v: pd.Series(np.array(v, dtype=NP[d])))
                    l = pd.DataFrame({"k": mk(x, lk), "v": [10, 20, 30, 40]})
                    r = pd.DataFrame({"k": mk(y, rk), "w": [1, 2, 3, 4]})
                    j = pd.merge(l, r, on="k", how=how).sort_values("v")
                    return Res(sname(j["k"].dtype), [[x_ for x_ in t] for t in j[["v", "w", "k"]].itertuples(index=False)])
                return f
            cases.append(build(f"key-join-{x}-{y}-pl", "join", "pl", "inner_join_rows_v_w_k", inp, pl_j, {}))
            a = build(f"key-join-{x}-{y}-pd", "join", "pd", "inner_join_rows_v_w_k", inp, pd_j(False), {})
            b = build(f"key-join-{x}-{y}-pdn", "join", "pd", "inner_join_rows_v_w_k", inp, pd_j(True), {})
            cases.append(a)
            if (a["dtype_out"], json.dumps(a["expect"])) != (b["dtype_out"], json.dumps(b["expect"])):
                cases.append(b)

    # group_by on a u64 key above 2^63, sort
    ku = [2 ** 63, 2 ** 63, 2 ** 64 - 1, 1, 2 ** 63 + 1]
    inp = {"k": {"dtype": "u64", "values": ku}, "v": {"dtype": "i64", "values": [1, 2, 3, 4, 5]}}
    cases.append(build("key-groupby-u64-pl", "group_by", "pl", "group_by_sum_len", inp, lambda: Res("u64", [
        list(t) for t in pl.DataFrame({"k": pl.Series(ku, dtype=pl.UInt64), "v": [1, 2, 3, 4, 5]}).group_by("k", maintain_order=True).agg(pl.col("v").sum(), pl.len()).iter_rows()]), {}))
    for tag, nullable in (("pd", False), ("pdn", True)):
        def g(nullable=nullable):
            k = pd.Series(ku, dtype="UInt64") if nullable else pd.Series(np.array(ku, dtype="uint64"))
            r = pd.DataFrame({"k": k, "v": [1, 2, 3, 4, 5]}).groupby("k", sort=False)["v"].agg(["sum", "size"]).reset_index()
            return Res(sname(r["k"].dtype), [list(t) for t in r.itertuples(index=False)])
        cases.append(build(f"key-groupby-u64-{tag}", "group_by", "pd", "group_by_sum_len", inp, g, {}))
    su = [2 ** 64 - 1, 1, 2 ** 63, 2 ** 63 - 1, 0]
    spec = {"a": ("u64", su)}
    tri("key-sort-u64", "sort", "sort", spec, lambda a: a.sort(), lambda a: a.sort_values(ignore_index=True))
    tri("key-sort-u64-desc", "sort", "sort_desc", spec, lambda a: a.sort(descending=True), lambda a: a.sort_values(ascending=False, ignore_index=True))
    # unique / n_unique across a mixed concat
    for x, y, a, b in (("i8", "i64", [1, 2, 2], [2, 3, 3]), ("u64", "i64", [2 ** 63, 1], [-1, 1]), ("i32", "f64", [1, 2], [2.0, 2.5]),
                       ("u8", "i8", [255, 1], [-1, 1])):
        sp = {"a": (x, a), "b": (y, b)}
        cc = lambda a, b: pl.concat([pl.DataFrame({"a": a}), pl.DataFrame({"a": b})], how="vertical_relaxed")["a"]  # noqa: E731
        tri(f"key-concat-unique-{x}-{y}", "unique", "concat_unique", sp, lambda a, b, cc=cc: cc(a, b).unique(maintain_order=True),
            lambda a, b: pd.concat([a, b], ignore_index=True).drop_duplicates(ignore_index=True))
        tri(f"key-concat-nunique-{x}-{y}", "unique", "concat_n_unique", sp, lambda a, b, cc=cc: plx(cc(a, b), lambda c: c.n_unique()),
            lambda a, b: pd.concat([a, b], ignore_index=True).nunique())


# 11 combining -----------------------------------------------------------------------------------

PD_COMBINE = {("i8", "i16"), ("i16", "i8"), ("i8", "u8"), ("u8", "i8"), ("u8", "i64"), ("i64", "u8"), ("i64", "u64"), ("u64", "i64"),
              ("i32", "f32"), ("f32", "i32"), ("f32", "f64"), ("f64", "f32"), ("i8", "f64"), ("u64", "f64"), ("u32", "i32"), ("i32", "u32"),
              ("u16", "f32"), ("i16", "f32"), ("u8", "u16"), ("u32", "u64")}


def g_combine():
    for x in DT:
        for y in DT:
            pdok = x == y or (x, y) in PD_COMBINE  # pandas only on a subset: the file size
            one = (lambda d: [1, None, 3, 4] if isint(d) else [1.5, None, 2.5, 4.0])
            sp = {"a": (x, one(x)), "b": (y, [5, 6, 7, None] if isint(y) else [5.5, 6.5, 7.5, None])}
            c = [True, False, True, False]
            tri(f"cb-when-{x}-{y}", "combine", "when_then_otherwise", sp,
                lambda a, b: pl.DataFrame({"a": a, "b": b}).select(pl.when(pl.Series(c)).then(pl.col("a")).otherwise(pl.col("b")).alias("o"))["o"],
                (lambda a, b: a.where(pd.Series(c), b)) if pdok else None)
            tri(f"cb-coalesce-{x}-{y}", "combine", "coalesce", sp,
                lambda a, b: pl.DataFrame({"a": a, "b": b}).select(pl.coalesce("a", "b").alias("o"))["o"],
                (lambda a, b: a.combine_first(b)) if pdok else None)
            tri(f"cb-fill_null-{x}-{y}", "combine", "fill_null_column", sp,
                lambda a, b: pl.DataFrame({"a": a, "b": b}).select(pl.col("a").fill_null(pl.col("b")).alias("o"))["o"],
                (lambda a, b: a.fillna(b)) if pdok else None, np_ok=False)


# 12 repr ----------------------------------------------------------------------------------------

def g_repr():
    for dt in DT + ["bool", "str"]:
        v = [True] if dt == "bool" else ["a"] if dt == "str" else [1]
        for tag, mk in (("pl", None), ("pd", False), ("pdn", True)):
            def f(dt=dt, v=v, tag=tag, mk=mk):
                if tag == "pl":
                    s = pl.Series("x", v, dtype=PL[dt])
                    return Res(sname(s.dtype), [str(s.dtype), str(pl.DataFrame({"x": s}))])
                s = mkpd(dt, v, mk) if dt != "str" and dt != "bool" else pd.Series(v, dtype=(NU if mk else NP)[dt])
                return Res(sname(s.dtype), [str(s.dtype), str(pd.DataFrame({"x": s}))])
            cases.append(build(f"repr-{dt}-{tag}", "repr", "pl" if tag == "pl" else "pd", "dtype_str_and_frame",
                               {"a": {"dtype": dt, "values": v}}, f, {}))


# summaries on stderr ----------------------------------------------------------------------------

def summaries():
    byid = {c["id"]: c for c in cases}

    def grid(op, eng):
        notes.append(f"GRID {op} {eng} (row = left dtype, col = right dtype)")
        notes.append("      " + " ".join(f"{d:>5}" for d in DT))
        for x in DT:
            row = []
            for y in DT:
                c = byid.get(f"st-{op}-{x}-{y}-{eng}")
                row.append(("ERR" if c["error"] else c["dtype_out"]) if c else "?")
            notes.append(f"{x:>5} " + " ".join(f"{r:>5}" for r in row))
    for op in ("add", "truediv", "floordiv", "mod"):
        for eng in ("pl", "pd"):
            grid(op, eng)
    for eng in ("pl", "pd"):
        notes.append(f"GRID concat {eng}")
        for x in DT:
            notes.append(f"{x:>5} " + " ".join(f"{(byid.get(f'st-concat-{x}-{y}-{eng}') or {'dtype_out': '?'})['dtype_out'] or 'ERR':>5}" for y in DT))
    errs = Counter()
    for c in cases:
        if c.get("error") and c.get("msg"):
            errs[c["msg"].split(":")[0] + " " + c["msg"].split(":", 1)[-1][:40]] += 1
    for k, n in errs.most_common(25):
        notes.append(f"ERRCOUNT {n} {k}")


for g in (g_supertype, g_overflow, g_literals, g_unary, g_agg, g_cast, g_f32, g_write, g_read, g_keys, g_combine, g_repr):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{g.__name__}: {type(e).__name__}: {e}")
    sys.stderr.write(f"done {g.__name__}: {len(cases)}\n")

summaries()
sz = Counter()
for c in cases:
    sz[c["kind"]] += len(json.dumps(c, separators=(",", ":")))
notes.append("BYTES " + " ".join(f"{k}={v // 1000}k" for k, v in sz.most_common()))
out = sys.argv[1] if len(sys.argv) > 1 else "oracle2j_vectors.json"
with open(out, "w") as fh:
    fh.write("[\n")
    fh.write(",\n".join(json.dumps(c, ensure_ascii=False, separators=(",", ":")) for c in cases))
    fh.write("\n]\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for n in notes:
    sys.stderr.write("NOTE " + n + "\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
