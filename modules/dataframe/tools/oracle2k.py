#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the dataframe parity additions of 2026-11-10: what polars 2.1 and pandas 3.1
answer for `str.extract_many` / `str.find_many`, `read_fwf`, `date_ranges` / `datetime_ranges` /
`linear_spaces`, `to_latex(index=False)`, `str.json_decode` and the time-of-day (`pl.Time`) core
(cast str <-> time, CSV read with try_parse_dates / a Time schema, JSON/CSV writing, repr),
frozen into src/oracle2k_vectors.json. No line of dataframe is consulted: the expected values are
what the engines answer.

    python tools/oracle2k.py src/oracle2k_vectors.json      (see tools/README.md)

One case = {id, kind, engine, op, in, expect, error}. Ids end in `-pl` (polars) or `-pd` (pandas).
`"error": true` means the engine raised and that IS the answer (`msg` holds the exception class
and the start of its text). Kinds and their shapes:

  extract_many / find_many   in {text:[str|null], patterns:[str], ascii_case_insensitive, overlapping, leftmost}
                             expect [[str] | [int] | null] per text row; dtype_out "list[str]" / "list[u32]"
  read_fwf                   in {text, opts:{colspecs|widths|"infer", header, names, skiprows, dtype, na_values,
                             infer_nrows, nrows, delimiter}}; expect {columns, dtypes, rows}
  date_ranges / datetime_ranges / linear_spaces
                             in {starts, ends, interval, closed [, num_samples]}; expect [[cell] | null] per row
                             (dates "YYYY-MM-DD", datetimes epoch microseconds, floats; "nan" / "inf" as text)
  to_latex                   in {columns:[{name, dtype, values}], opts:{escape, na_rep, caption, label, header}};
                             expect [text]
  json_decode                in {values:[str|null], dtype?}; expect {dtype:<dtype tree>, cells:[...]}
  time_*                     see g_time

A dtype tree is {"t": "i64"|"f64"|"str"|"bool"|"null"|"time"|..., "inner": tree} for a list and
{"t": "struct", "fields": [{"name", ...tree}]} for a struct. NaN / inf are the strings "nan" /
"inf" / "-inf".
"""
import datetime as dt
import io
import json
import math
import random
import sys
import warnings
from collections import Counter

# `DataFrame.to_latex` renders through `Styler`, which needs jinja2; the pinned venv lacks it, the system's
# pure-python copy is appended (never prepended, so it cannot shadow the venv's numpy and friends).
sys.path.append("/usr/lib/python3/dist-packages")

import numpy as np
import pandas as pd
import polars as pl

warnings.simplefilter("ignore")

cases = []
problems = []
EXC = (Exception, pl.exceptions.PanicException)
HARNESS_BUGS = (NameError, SyntaxError, UnboundLocalError, TypeError, AttributeError)
EPOCH = dt.datetime(1970, 1, 1)


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
    if isinstance(v, dt.datetime):
        return (v - EPOCH) // dt.timedelta(microseconds=1)
    if isinstance(v, dt.date):
        return v.isoformat()
    return str(v)


def tree(d):
    """The dtype of a polars column as a small tree."""
    if isinstance(d, pl.List):
        return {"t": "list", "inner": tree(d.inner)}
    if isinstance(d, pl.Struct):
        return {"t": "struct", "fields": [{"name": f.name, **tree(f.dtype)} for f in d.fields]}
    m = {pl.Int64: "i64", pl.Int32: "i32", pl.Int16: "i16", pl.Int8: "i8", pl.UInt64: "u64", pl.UInt16: "u16", pl.UInt8: "u8", pl.Int128: "i128", pl.Float64: "f64", pl.String: "str", pl.Boolean: "bool", pl.Null: "null",
         pl.Date: "date", pl.Time: "time", pl.UInt32: "u32", pl.Datetime: "ts", pl.Duration: "dur", pl.Object: "obj"}
    for k, v in m.items():
        if d == k or isinstance(d, k):
            return {"t": v}
    return {"t": str(d)}


def pdname(d):
    s = str(d).lower()
    return {"int64": "i64", "float64": "f64", "bool": "bool", "object": "str", "str": "str", "string": "str",
            "boolean": "bool"}.get(s, s)


def add(id, kind, engine, op, inp, thunk, **extra):
    c = {"id": id, "kind": kind, "engine": engine, "op": op, "in": inp}
    try:
        res = thunk()
        c.update({"expect": res, "error": False})
    except HARNESS_BUGS as e:
        problems.append(f"{id}: HARNESS {type(e).__name__}: {e}")
        c.update({"expect": None, "error": True, "msg": "harness"})
    except EXC as e:  # noqa: BLE001 - the engine's refusal is the answer
        c.update({"expect": None, "error": True, "msg": f"{type(e).__name__}: {str(e)[:60]}".replace("\n", " ")})
    c.update(extra)
    cases.append(c)


# a) extract_many / find_many ---------------------------------------------------------------------

XM = [
    # (tag, texts, patterns)
    ("docs", ["discontent", None, "", "winter"], ["winter", "disco", "onte", "discontent"]),
    ("rhap", ["rhapsody", "rhapsody rhap"], ["rhap", "ody", "coalesce"]),
    ("case", ["Hello HELLO hello", "hElLo", None], ["hello"]),
    ("case2", ["The Cat sat. THE END", "the"], ["the", "CAT", "end"]),
    ("utf8", ["héllo wörld", "ö ö", "日本語テキスト日本"], ["ö", "llo", "日本", "本語"]),
    ("utf8fold", ["É é É", "STRASSE straße"], ["é", "Straße", "strasse"]),
    ("nomatch", ["abc", "", "xyz"], ["q", "zz"]),
    ("overlap", ["aaa", "aaaa", "abab"], ["aa", "a", "ab", "ba"]),
    ("sameend", ["abc", "xabcx"], ["c", "bc", "abc"]),
    ("samestart", ["abcd", "abcdabcd"], ["ab", "abcd", "abc"]),
    ("leftmost", ["abcd", "xbcdab"], ["bc", "abcd", "ab"]),
    ("dups", ["abab", "ab ab"], ["ab", "ab", "b"]),
    ("chain", ["she sells sea shells", "hers"], ["she", "he", "hers", "his", "shells"]),
    ("single", ["aXbXc"], ["X"]),
    ("emptylist", ["abc", None], []),
    ("emptypat", ["abc"], [""]),
    ("emptypat2", ["abc", "a"], ["a", ""]),
    ("emptyutf8", ["é", "aé日", ""], [""]),
    ("emptyutf8-2", ["aé日b"], ["é", ""]),
    ("emptyutf8-3", ["aé日b"], ["日", "", "ab"]),
    ("longpat", ["ab"], ["abcdef"]),
    ("nested", ["abcde", "xabcdex"], ["abcde", "bcd", "c", "abc", "de"]),
    ("digits", ["a1b22c333", "x-y_z"], ["1", "22", "333", "-", "_"]),
]


def g_many():
    n = 0
    for tag, texts, pats in XM:
        for fold in (False, True):
            for ov, lm in ((False, False), (True, False), (False, True), (True, True)):
                if ov and lm and tag != "docs":
                    continue  # polars refuses the combination (`ValueError`); the docs case records that once per flag set
                inp = {"text": texts, "patterns": pats, "ascii_case_insensitive": fold, "overlapping": ov, "leftmost": lm}
                key = f"{int(fold)}{int(ov)}{int(lm)}"
                for kind, meth in (("extract_many", "extract_many"), ("find_many", "find_many")):
                    def f(meth=meth):
                        s = pl.Series("x", texts, dtype=pl.String)
                        r = s.to_frame().select(getattr(pl.col("x").str, meth)(pats, ascii_case_insensitive=fold, overlapping=ov, leftmost=lm).alias("o"))["o"]
                        return enc(r.to_list())
                    add(f"{kind}-{tag}-{key}-pl", kind, "pl", kind, inp, f, dtype_out="list[str]" if kind == "extract_many" else "list[u32]")
                    n += 1
    return n


# b) read_fwf ---------------------------------------------------------------------------------------

DOC = ("id8141  360.242940   149.910199   11950.7\n"
       "id1594  444.953632   166.985655   11788.4\n"
       "id1849  364.136849   183.628767   11806.2\n"
       "id1230  413.836124   184.375703   11916.0\n"
       "id1948  502.953953   173.237159   12468.3\n")
FW = [
    ("docs-colspecs", DOC, {"colspecs": [[0, 6], [8, 20], [21, 33], [34, 43]], "header": None, "names": ["id", "a", "b", "c"]}),
    ("docs-infer", DOC, {"colspecs": "infer", "header": None, "names": ["id", "a", "b", "c"]}),
    ("docs-widths", DOC, {"widths": [6, 14, 13, 10], "header": None, "names": ["id", "a", "b", "c"]}),
    ("docs-noheader-nonames", DOC, {"colspecs": "infer", "header": None}),
    ("header-infer", "k   v\nab  12\ncd   7\n", {"colspecs": "infer"}),
    ("header-widths", "k   v\nab  12\ncd   7\n", {"widths": [4, 2]}),
    ("blank-short", "k   v\nab  12\n\ncd   7\nef\nxx  99 trailing\n", {"widths": [4, 2]}),
    ("blank-infer", "k   v\nab  12\n\ncd   7\n", {"colspecs": "infer"}),
    ("skiprows", "junk\nk v\na 1\nb 2\n", {"widths": [2, 1], "skiprows": 1}),
    ("skiprows-infer", "junk line\nk v\na 1\nb 2\n", {"colspecs": "infer", "skiprows": 1}),
    ("na-default", "t     n\nx     NA\ny     5\nz     \n", {"widths": [6, 2]}),
    ("na-values", "t   n\nx   -\ny   5\nz   none\n", {"widths": [4, 4], "na_values": ["-", "none"]}),
    ("dtype-str", "a   b\n001 2\n002 3\n", {"widths": [4, 1], "dtype": {"a": "str"}}),
    ("dtype-f64", "a b\n1 2\n3 4\n", {"widths": [2, 1], "dtype": {"a": "f64"}}),
    ("dtype-i64", "a  b\n1  2\n3  4\n", {"widths": [3, 1], "dtype": {"b": "i64"}}),
    ("ints-floats", "i  f   s\n1  1.5 a\n22 2   b\n", {"widths": [3, 4, 1]}),
    ("bools", "b\nTrue\nFalse\ntrue\n", {"widths": [5]}),
    ("bools-mixed", "b    c\nTrue 1\nFalse2\n", {"widths": [5, 1]}),
    ("multibyte", "name 1\nÉé   2\nüö   3\n", {"widths": [5, 1]}),
    ("multibyte-infer", "naïve  x\nÉé     2\nüö     3\n", {"colspecs": "infer"}),
    ("cjk", "名前  年\n日本  2\n語    3\n", {"widths": [4, 1]}),
    ("overlap", "abcdef\nghijkl\n", {"colspecs": [[0, 4], [2, 6]], "header": None}),
    ("past-end", "ab\ncd\n", {"colspecs": [[0, 1], [5, 9]], "header": None}),
    ("reversed", "abcd\nefgh\n", {"colspecs": [[3, 1], [0, 2]], "header": None}),
    ("zero-width", "abcd\nefgh\n", {"colspecs": [[1, 1], [2, 4]], "header": None}),
    ("tabs", "a\tb\n1\t2\n", {"colspecs": "infer"}),
    ("crlf", "a  b\r\n1  2\r\n3  4\r\n", {"widths": [3, 1]}),
    ("trailing-nl-none", "a b\n1 2", {"widths": [2, 1]}),
    ("infer-nrows-1", "a  b\n1  2\nxxxxyy\n", {"colspecs": "infer", "infer_nrows": 1}),
    ("infer-nrows-2", "a  b\n1  2\nxxxxyy\n", {"colspecs": "infer", "infer_nrows": 2}),
    ("nrows", "a b\n1 2\n3 4\n5 6\n", {"widths": [2, 1], "nrows": 2}),
    ("negative", "a   b\n-1  -2.5\n+3  1e3\n", {"widths": [4, 4]}),
    ("leading-spaces", "a    b\n  1  xx\n 22  yy\n", {"widths": [5, 3]}),
    ("delim-dash", "a--b\n1--2\n3--4\n", {"widths": [3, 1], "delimiter": "-"}),
    ("wide-infer-gap", "a    b     c\n1    2     3\n4    5     6\n", {"colspecs": "infer"}),
    ("one-col", "a\n1\n2\n", {"colspecs": "infer"}),
    ("empty-cell-text", "a  b\nx  \ny  z\n", {"widths": [3, 1]}),
    ("dup-names", "a b\n1 2\n", {"widths": [2, 1], "names": ["x", "x"]}),
    ("names-with-header", "a b\n1 2\n3 4\n", {"widths": [2, 1], "names": ["p", "q"]}),
    ("names-header0", "a b\n1 2\n3 4\n", {"widths": [2, 1], "names": ["p", "q"], "header": 0}),
]


def g_fwf():
    for tag, text, o in FW:
        def f(o=o, text=text):
            kw = {}
            if "widths" in o:
                kw["widths"] = o["widths"]
            elif o.get("colspecs") == "infer":
                kw["colspecs"] = "infer"
            else:
                kw["colspecs"] = [tuple(x) for x in o["colspecs"]]
            if "header" in o:
                kw["header"] = o["header"]
            for k in ("names", "skiprows", "na_values", "infer_nrows", "nrows", "delimiter"):
                if k in o:
                    kw[k] = o[k]
            if "dtype" in o:
                kw["dtype"] = {k: {"i64": "int64", "f64": "float64", "str": "str"}[v] for k, v in o["dtype"].items()}
            df = pd.read_fwf(io.StringIO(text), **kw)
            return {"columns": [str(c) for c in df.columns], "dtypes": [pdname(d) for d in df.dtypes],
                    "rows": [[enc(None if (not isinstance(v, str) and pd.isna(v)) else v) for v in r] for r in df.itertuples(index=False, name=None)]}
        add(f"fwf-{tag}-pd", "read_fwf", "pd", "read_fwf", {"text": text, "opts": o}, f)


# c) ranges -----------------------------------------------------------------------------------------

D = dt.date
T = dt.datetime


def us(*a):
    return (T(*a) - EPOCH) // dt.timedelta(microseconds=1)


def g_ranges():
    dcases = [
        ("docs", [D(2022, 1, 1), D(2022, 1, 2)], [D(2022, 1, 3)], "1d", "both"),
        ("left", [D(2022, 1, 1), D(2022, 1, 2)], [D(2022, 1, 3)], "1d", "left"),
        ("right", [D(2022, 1, 1), D(2022, 1, 2)], [D(2022, 1, 3)], "1d", "right"),
        ("none", [D(2022, 1, 1), D(2022, 1, 2)], [D(2022, 1, 3)], "1d", "none"),
        ("2d", [D(2022, 1, 1)], [D(2022, 1, 10)], "2d", "both"),
        ("3d-none", [D(2022, 1, 1)], [D(2022, 1, 10)], "3d", "none"),
        ("week", [D(2022, 1, 1)], [D(2022, 2, 1)], "1w", "both"),
        ("2w", [D(2022, 1, 1)], [D(2022, 3, 1)], "2w", "left"),
        ("month", [D(2022, 1, 31)], [D(2022, 6, 30)], "1mo", "both"),
        ("month-eom", [D(2022, 1, 31)], [D(2022, 5, 31)], "1mo", "left"),
        ("month-1st", [D(2022, 1, 1), D(2022, 3, 15)], [D(2022, 4, 1)], "1mo", "both"),
        ("quarter", [D(2020, 2, 29)], [D(2021, 3, 1)], "1q", "both"),
        ("year", [D(2020, 2, 29)], [D(2024, 3, 1)], "1y", "both"),
        ("2mo", [D(2022, 1, 1)], [D(2022, 12, 31)], "2mo", "right"),
        ("nulls", [D(2022, 1, 1), None, D(2022, 1, 9)], [D(2022, 1, 3)], "1d", "both"),
        ("null-end", [D(2022, 1, 1), D(2022, 1, 2)], [None, D(2022, 1, 4)], "1d", "both"),
        ("both-null", [None], [None], "1d", "both"),
        ("reversed", [D(2022, 1, 5)], [D(2022, 1, 1)], "1d", "both"),
        ("equal", [D(2022, 1, 1)], [D(2022, 1, 1)], "1d", "both"),
        ("equal-none", [D(2022, 1, 1)], [D(2022, 1, 1)], "1d", "none"),
        ("equal-left", [D(2022, 1, 1)], [D(2022, 1, 1)], "1d", "left"),
        ("pairs", [D(2022, 1, 1), D(2022, 2, 1), D(2022, 3, 1)], [D(2022, 1, 3), D(2022, 2, 2), D(2022, 3, 5)], "1d", "both"),
        ("broadcast-start", [D(2022, 1, 1)], [D(2022, 1, 3), D(2022, 1, 5)], "1d", "both"),
        ("mismatch", [D(2022, 1, 1), D(2022, 1, 2)], [D(2022, 1, 3), D(2022, 1, 4), D(2022, 1, 5)], "1d", "both"),
        ("empty-starts", [], [D(2022, 1, 3)], "1d", "both"),
        ("leap", [D(2024, 2, 27)], [D(2024, 3, 2)], "1d", "both"),
        ("1w1d", [D(2022, 1, 1)], [D(2022, 1, 30)], "1w1d", "both"),
        ("12h", [D(2022, 1, 1)], [D(2022, 1, 3)], "12h", "both"),
        ("bad-0d", [D(2022, 1, 1)], [D(2022, 1, 3)], "0d", "both"),
        ("bad-neg", [D(2022, 1, 1)], [D(2022, 1, 3)], "-1d", "both"),
        ("bad-text", [D(2022, 1, 1)], [D(2022, 1, 3)], "xyz", "both"),
        ("old", [D(1969, 12, 30)], [D(1970, 1, 2)], "1d", "both"),
        ("far", [D(1900, 1, 1)], [D(1900, 1, 3)], "1d", "both"),
    ]
    for tag, st, en, iv, cl in dcases:
        inp = {"starts": enc(st), "ends": enc(en), "interval": iv, "closed": cl}

        def f(st=st, en=en, iv=iv, cl=cl):
            r = pl.date_ranges(pl.Series("s", st, dtype=pl.Date), pl.Series("e", en, dtype=pl.Date), interval=iv, closed=cl, eager=True)
            return enc(r.to_list())
        add(f"daterange-{tag}-pl", "date_ranges", "pl", "date_ranges", inp, f)
    tcases = [
        ("docs", [us(2022, 1, 1), us(2022, 1, 2)], [us(2022, 1, 3)], "1d", "both"),
        ("hour", [us(2022, 1, 1)], [us(2022, 1, 1, 3)], "1h", "both"),
        ("hour-left", [us(2022, 1, 1)], [us(2022, 1, 1, 3)], "1h", "left"),
        ("hour-right", [us(2022, 1, 1)], [us(2022, 1, 1, 3)], "1h", "right"),
        ("hour-none", [us(2022, 1, 1)], [us(2022, 1, 1, 3)], "1h", "none"),
        ("90m", [us(2022, 1, 1)], [us(2022, 1, 1, 6)], "90m", "both"),
        ("30s", [us(2022, 1, 1)], [us(2022, 1, 1, 0, 2)], "30s", "both"),
        ("500ms", [us(2022, 1, 1)], [us(2022, 1, 1, 0, 0, 2)], "500ms", "both"),
        ("1us", [us(2022, 1, 1)], [us(2022, 1, 1, 0, 0, 0, 5)], "1us", "both"),
        ("month", [us(2022, 1, 31)], [us(2022, 6, 30)], "1mo", "both"),
        ("month-time", [us(2022, 1, 15, 10, 30)], [us(2022, 4, 15, 10, 30)], "1mo", "both"),
        ("week", [us(2022, 1, 1)], [us(2022, 2, 1)], "1w", "both"),
        ("year", [us(2020, 2, 29)], [us(2024, 3, 1)], "1y", "both"),
        ("nulls", [us(2022, 1, 1), None, us(2022, 1, 9)], [us(2022, 1, 3)], "1d", "both"),
        ("reversed", [us(2022, 1, 2)], [us(2022, 1, 1)], "1d", "both"),
        ("equal", [us(2022, 1, 1)], [us(2022, 1, 1)], "1h", "both"),
        ("equal-none", [us(2022, 1, 1)], [us(2022, 1, 1)], "1h", "none"),
        ("pairs", [us(2022, 1, 1), us(2022, 2, 1)], [us(2022, 1, 1, 2), us(2022, 2, 1, 1)], "1h", "both"),
        ("mismatch", [us(2022, 1, 1), us(2022, 1, 2)], [us(2022, 1, 3), us(2022, 1, 4), us(2022, 1, 5)], "1d", "both"),
        ("1d1h", [us(2022, 1, 1)], [us(2022, 1, 5)], "1d1h", "both"),
        ("bad-0h", [us(2022, 1, 1)], [us(2022, 1, 2)], "0h", "both"),
        ("bad-text", [us(2022, 1, 1)], [us(2022, 1, 2)], "xyz", "both"),
        ("neg-epoch", [-3_600_000_000], [3_600_000_000], "30m", "both"),
        ("dst-naive", [us(2022, 3, 26, 22)], [us(2022, 3, 27, 6)], "2h", "both"),
    ]
    for tag, st, en, iv, cl in tcases:
        inp = {"starts": st, "ends": en, "interval": iv, "closed": cl}

        def f(st=st, en=en, iv=iv, cl=cl):
            r = pl.datetime_ranges(pl.Series("s", st, dtype=pl.Datetime("us")), pl.Series("e", en, dtype=pl.Datetime("us")), interval=iv, closed=cl, eager=True)
            return enc(r.to_list())
        add(f"datetimerange-{tag}-pl", "datetime_ranges", "pl", "datetime_ranges", inp, f)
    lcases = [
        ("docs", [1.0, -1.0], [3.0, 2.0], [3, 3], "both"),
        ("docs-perrow", [1.0, -1.0], [3.0, 2.0], [3, 4], "both"),
        ("perrow-5", [1.0, -1.0, 0.0], [3.0, 2.0, 1.0], [3, 4, 5], "both"),
        ("scalar-n", [0.0, 10.0], [1.0, 20.0], [5], "both"),
        ("left", [0.0], [4.0], [4], "left"),
        ("right", [0.0], [4.0], [4], "right"),
        ("none", [0.0], [4.0], [4], "none"),
        ("none-5", [0.0], [1.0], [5], "none"),
        ("n1", [7.0], [9.0], [1], "both"),
        ("n1-left", [7.0], [9.0], [1], "left"),
        ("n1-right", [7.0], [9.0], [1], "right"),
        ("n1-none", [7.0], [9.0], [1], "none"),
        ("n0", [0.0, 1.0], [1.0, 2.0], [0], "both"),
        ("n2", [0.0], [1.0], [2], "both"),
        ("n2-none", [0.0], [1.0], [2], "none"),
        ("n3-none", [0.0], [1.0], [3], "none"),
        ("reversed", [5.0], [1.0], [5], "both"),
        ("equal", [2.0], [2.0], [3], "both"),
        ("fraction", [0.0], [1.0], [4], "both"),
        ("neg", [-10.0], [10.0], [5], "both"),
        ("thirds", [0.1], [0.7], [4], "both"),
        ("null-start", [1.0, None, 3.0], [2.0, 5.0, 4.0], [3], "both"),
        ("null-end", [1.0, 3.0], [None, 4.0], [3], "both"),
        ("null-n", [1.0, 2.0], [2.0, 3.0], [3, None], "both"),
        ("inf", [0.0, float("inf")], [1.0, 1.0], [3], "both"),
        ("nan", [float("nan")], [1.0], [3], "both"),
        ("mismatch", [1.0, 2.0], [1.0, 2.0, 3.0], [3], "both"),
        ("broadcast-end", [1.0, 2.0], [9.0], [3], "both"),
        ("empty", [], [1.0], [3], "both"),
        ("big-n", [0.0], [1.0], [11], "both"),
        ("neg-n", [0.0], [1.0], [-1], "both"),
    ]
    import random
    rnd = random.Random(2026)
    for closed in ("both", "left", "right", "none"):
        for k in range(12):
            rows = 6
            st = [round(rnd.uniform(-10, 10), rnd.choice([0, 1, 3])) for _ in range(rows)]
            en = [x + rnd.choice([1, 2, 3, 7, 0.1, 0.7, 13.3]) for x in st]
            ns = [rnd.randint(1, 12) for _ in range(rows)]
            lcases.append((f"sweep-{closed}-{k:02d}", st, en, ns, closed))
    for tag, st, en, ns, cl in lcases:
        inp = {"starts": enc(st), "ends": enc(en), "num_samples": ns, "closed": cl}

        def f(st=st, en=en, ns=ns, cl=cl):
            r = pl.linear_spaces(pl.Series("s", st, dtype=pl.Float64), pl.Series("e", en, dtype=pl.Float64), pl.Series("n", ns, dtype=pl.Int64) if len(ns) != 1 else ns[0],
                                 closed=cl, eager=True)
            return enc(r.to_list())
        add(f"linspace-{tag}-pl", "linear_spaces", "pl", "linear_spaces", inp, f)


# d) to_latex ---------------------------------------------------------------------------------------

PDT = {"i64": "int64", "f64": "float64", "str": "str", "bool": "bool", "Int64": "Int64", "boolean": "boolean"}


def lat(id, cols, **o):
    def f():
        df = pd.DataFrame({c["name"]: pd.Series(c["values"], dtype=PDT[c["dtype"]]) for c in cols})
        kw = {k: v for k, v in o.items()}
        return [df.to_latex(index=False, **kw)]
    shown = [{**c, "values": enc(c["values"])} for c in cols]
    add(id + "-pd", "to_latex", "pd", "to_latex", {"columns": shown, "opts": o}, f)


def g_latex():
    C = lambda name, dtype, values: {"name": name, "dtype": dtype, "values": values}  # noqa: E731
    people = [C("name", "str", ["Raphael", "Donatello"]), C("age", "i64", [26, 45]), C("height", "f64", [181.23, 177.65])]
    lat("lat-docs", people)
    lat("lat-docs-caption", people, caption="People", label="tab:p")
    lat("lat-caption-only", people, caption="People")
    lat("lat-label-only", people, label="tab:p")
    lat("lat-noheader", people, header=False)
    lat("lat-ints", [C("a", "i64", [1, -2, 300000]), C("b", "i64", [0, 10 ** 15, -7])])
    lat("lat-floats", [C("x", "f64", [1.0, 0.5, 1 / 3, 1e10, 1e-7, 123456.789, -0.0, 100.0])])
    lat("lat-floats-big", [C("x", "f64", [1e15, 1e16, 1.5e300, 2 ** 53 * 1.0, 0.1 + 0.2])])
    lat("lat-floats-special", [C("x", "f64", [float("nan"), float("inf"), float("-inf"), 1.5])])
    lat("lat-bool", [C("b", "bool", [True, False, True])])
    lat("lat-nullable-int", [C("a", "Int64", [1, None, 3])])
    lat("lat-nullable-bool", [C("a", "boolean", [True, None, False])])
    lat("lat-float-null", [C("a", "f64", [1.5, None, 3.0])])
    lat("lat-str-null", [C("a", "str", ["x", None, "z"])])
    lat("lat-str-null-narep", [C("a", "str", ["x", None, "z"])], na_rep="--")
    lat("lat-float-null-narep", [C("a", "f64", [1.5, None, 3.0])], na_rep="--")
    lat("lat-nullable-narep", [C("a", "Int64", [1, None, 3])], na_rep="--")
    lat("lat-narep-empty", [C("a", "str", ["x", None])], na_rep="")
    spec = ["a&b", "50%", "$5", "#1", "x_y", "{z}", "~t", "^c", "back\\slash", "a b", "<>", "'q'", "\"dq\"", "é日本", "tab\tx", "line\nbreak"]
    lat("lat-specials-raw", [C("t", "str", spec)])
    lat("lat-specials-esc", [C("t", "str", spec)], escape=True)
    lat("lat-header-esc", [C("a_b&c", "i64", [1]), C("50%", "i64", [2])], escape=True)
    lat("lat-header-raw", [C("a_b&c", "i64", [1]), C("50%", "i64", [2])], escape=False)
    lat("lat-esc-caption", people, escape=True, caption="A & B_c", label="tab:a_b")
    lat("lat-mixed-cols", [C("s", "str", ["a", "b"]), C("i", "i64", [1, 2]), C("f", "f64", [0.5, 1.5]), C("b", "bool", [True, False])])
    lat("lat-mixed-noheader", [C("s", "str", ["a", "b"]), C("i", "i64", [1, 2])], header=False)
    lat("lat-one-col", [C("only", "i64", [1, 2, 3])])
    lat("lat-empty-rows", [C("a", "i64", []), C("b", "str", [])])
    lat("lat-empty-rows-noheader", [C("a", "i64", [])], header=False)
    lat("lat-colname-int-like", [C("0", "i64", [1])])
    lat("lat-empty-string", [C("a", "str", ["", " ", "x "])])
    lat("lat-unicode-esc", [C("a", "str", ["é & ü"])], escape=True)
    lat("lat-esc-null", [C("a", "str", ["x_y", None])], escape=True, na_rep="n_a")
    lat("lat-wide-numbers", [C("a", "f64", [123456789.123456789, 0.000012345])])
    rf = random.Random(7)
    lat("lat-floats-random", [C("x", "f64", [rf.choice([1, -1]) * rf.random() * 10 ** rf.randint(-8, 22) for _ in range(60)])])
    lat("lat-floats-ties", [C("x", "f64", [0.0000005, 0.0000015, 0.0000025, 2.5e-6, 1.0000005, 123.4567895, 0.9999995, 1e22, 1e23, 2.0 ** 60, 2.0 ** 53 + 2])])
    lat("lat-int-as-float", [C("a", "f64", [1.0, 2.0, 3.0])])


# e) json_decode ------------------------------------------------------------------------------------

JD = [
    ("docs", ['{"a":1, "b": true}', None, '{"a":2, "b": false}']),
    ("objects-missing", ['{"a":1}', '{"b":"x","a":2.5}', "null"]),
    ("objects-int-float", ['{"a":1}', '{"a":2.5}']),
    ("objects-nested", ['{"a":{"b":1,"c":[1,2]}}', '{"a":{"b":2,"c":[]}}']),
    ("objects-mixed-type", ['{"a":1}', '{"a":"x"}']),
    ("objects-null-field", ['{"a":null}', '{"a":null}']),
    ("objects-empty", ["{}", "{}"]),
    ("objects-empty-and-full", ["{}", '{"a":1}']),
    ("arrays-int", ["[1,2,3]", " [] ", None]),
    ("arrays-float", ["[1,2.5]", "[3]"]),
    ("arrays-str", ['["a","b"]', "[]", '["c"]']),
    ("arrays-mixed", ['[1,"a"]', "[2]"]),
    ("arrays-nested", ["[[1,2],[3]]", "[[4]]"]),
    ("arrays-null-elem", ["[1,null,3]", "[null]"]),
    ("arrays-empty-only", ["[]", "[]"]),
    ("arrays-objects", ['[{"a":1},{"a":2}]', '[{"a":3,"b":"x"}]']),
    ("scalars-int", ["7", "-2", None]),
    ("scalars-float", ["1.5", "2", "-0.5e2"]),
    ("scalars-str", ['"s"', '"é"', '"a\\nb"']),
    ("scalars-bool", ["true", "false", None]),
    ("scalars-big-int", ["9223372036854775807", "-9223372036854775808"]),
    ("scalars-too-big", ["9223372036854775808", "1"]),
    ("scalars-u64", ["18446744073709551615"]),
    ("scalars-exp", ["1e3", "2E-2"]),
    ("mix-num-obj", ["1", '{"a":1}', '"s"']),
    ("mix-int-str", ["1", '"x"']),
    ("mix-int-bool", ["1", "true"]),
    ("mix-arr-obj", ["[1]", '{"a":1}']),
    ("mix-arr-int", ["[1]", "2"]),
    ("null-text", ["null", "null"]),
    ("null-and-int", ["null", "1", None]),
    ("only-none", [None, None]),
    ("empty-input", []),
    ("blanks-int", ["  1  ", "\t2\n"]),
    ("blanks-obj", [' {"a" : 1 } ', "\n{\"a\":2}\t"]),
    ("blanks-arr", ["\t[1]\n", " [ 2 , 3 ] "]),
    ("unicode-key", ['{"é":1,"日本":"x"}']),
    ("escaped", ['{"a":"\\u00e9\\"q\\""}']),
    ("dup-keys", ['{"a":1,"a":2}']),
    ("key-order", ['{"b":1,"a":2}', '{"c":1,"a":2}']),
    ("deep-obj", ['{"a":{"b":{"c":{"d":1}}}}']),
    ("obj-list-struct", ['{"a":[{"x":1}]}', '{"a":[{"x":2,"y":"s"}]}']),
    ("neg-zero", ["-0", "0"]),
    ("float-int-struct", ['{"a":1,"b":1.0}']),
    ("date-text", ['"2026-11-10"', None]),
    ("bad-empty", [""]),
    ("bad-blank", ["  "]),
    ("bad-unclosed", ["{"]),
    ("bad-two", ["1 2"]),
    ("bad-trailing-comma", ["[1,]"]),
    ("bad-trailing-junk", ['{"a":1}x']),
    ("bad-nul", ["nul"]),
    ("bad-single-quote", ["{'a':1}"]),
    ("bad-nan", ["NaN"]),
    ("bad-leading-zero", ["01"]),
    ("bad-plus", ["+1"]),
    ("bad-one-of-two", ["1", "{"]),
    ("bad-lone-surrogate", ['"\\ud800"']),
]


def g_json():
    for tag, vals in JD:
        def f(vals=vals):
            s = pl.Series("j", vals, dtype=pl.String)
            r = s.str.json_decode(infer_schema_length=None)
            return {"dtype": tree(r.dtype), "cells": enc(r.to_list())}
        add(f"jd-{tag}-pl", "json_decode", "pl", "json_decode", {"values": vals}, f)
        if tag in ("docs", "arrays-int", "scalars-int", "scalars-float", "objects-int-float", "date-text", "scalars-str"):
            def f100(vals=vals):
                r = pl.Series("j", vals, dtype=pl.String).str.json_decode()
                return {"dtype": tree(r.dtype), "cells": enc(r.to_list())}
            add(f"jd-{tag}-default-pl", "json_decode", "pl", "json_decode_default", {"values": vals}, f100)
    # a declared dtype
    for tag, vals, d in (("dtype-i8", ["7", None, "-2"], pl.Int8), ("dtype-i8-big", ["300"], pl.Int8), ("dtype-str-obj", ['{"a":1}', "[2]"], pl.String),
                         ("dtype-f64-int", ["1", "2"], pl.Float64), ("dtype-i64-float", ["1.5"], pl.Int64), ("dtype-list-i64", ["[1,2]", "[]"], pl.List(pl.Int64)),
                         ("dtype-struct", ['{"a":1,"b":2}'], pl.Struct({"a": pl.Int64})), ("dtype-date", ['"2026-11-10"'], pl.Date),
                         ("dtype-bool-int", ["1"], pl.Boolean)):
        def fd(vals=vals, d=d):
            r = pl.Series("j", vals, dtype=pl.String).str.json_decode(d)
            return {"dtype": tree(r.dtype), "cells": enc(r.to_list())}
        add(f"jd-{tag}-pl", "json_decode", "pl", "json_decode_dtype", {"values": vals, "dtype": str(d)}, fd)


# f) the time core ------------------------------------------------------------------------------------

def ns_of(v):
    return v if v is None else (v.hour * 3600 + v.minute * 60 + v.second) * 10 ** 9 + v.microsecond * 1000


def g_time():
    strs = ["00:00:00", "01:02:03", "01:02", "1:02:03", "23:59:59.999999", "23:59:59.9999999", "00:00:00.12", "12:00:00.123456789", "12:00:00.1234567891",
            "24:00:00", "23:60:00", "23:59:60", "01:02:03.", "-01:02:03", "+01:02:03", " 01:02:03", "01:02:03 ", "", "abc", "01-02-03", "12:00:00 PM",
            "T01:02:03", "01:02:03Z", "01.02.03", "1:2:3", "001:02:03", "01:02:03.5", "00:00", "23:59", "0:0:0", "12", "1202", "01:02:03,5", "٠١:٠٢:٠٣",
            "  01:02:03", "\t01:02:03", "1:2", "01:2", "1:02", "00:00:00.00000000000000000000", "1:2:3.", "::", "01:02:03:04", "01:02:03.1.2", "1:002:03", "12:34:56.7890123456789"]
    for strict in (False, True):
        cells = []
        for v in strs:
            try:
                cells.append(enc(pl.Series([v], dtype=pl.String).cast(pl.Time, strict=strict).cast(pl.Int64).to_list()[0]))
            except EXC:
                cells.append({"error": True})
        cases.append({"id": f"time-cast-str-{'strict' if strict else 'lax'}-pl", "kind": "time_cast_str", "engine": "pl", "op": "strict" if strict else "lax",
                      "in": {"values": strs}, "expect": cells, "error": any(isinstance(c, dict) for c in cells), "unit": "ns"})
    # to_time
    cells = []
    for v in strs:
        try:
            cells.append(enc(pl.Series([v], dtype=pl.String).str.to_time(strict=False).cast(pl.Int64).to_list()[0]))
        except EXC:
            cells.append({"error": True})
    cases.append({"id": "time-str-to-time-pl", "kind": "time_cast_str", "engine": "pl", "op": "to_time", "in": {"values": strs}, "expect": cells,
                  "error": any(isinstance(c, dict) for c in cells), "unit": "ns"})
    ns = [0, 3_723_000_000_000, 86_399_999_999_000, 120_000_000, 43_200_000_005_000, 1, 999, 1_000, 43_200_000_000_000, 86_399_999_999_999, None]

    def tostr(ns=ns):
        return [pl.Series([v], dtype=pl.Int64).cast(pl.Time).cast(pl.String).to_list()[0] for v in ns]
    add("time-cast-str-from-time-pl", "time_to_str", "pl", "cast_string", {"ns": ns}, lambda: tostr(), unit="ns")
    # out of range int -> time
    big = [-1, 86_400_000_000_000, 86_399_999_999_999, 2 ** 62, -(2 ** 62)]
    cells = []
    for v in big:
        try:
            cells.append(enc(pl.Series([v], dtype=pl.Int64).cast(pl.Time).cast(pl.Int64).to_list()[0]))
        except EXC:
            cells.append({"error": True})
    cases.append({"id": "time-cast-int-time-pl", "kind": "time_cast_int", "engine": "pl", "op": "strict", "in": {"ns": big}, "expect": cells,
                  "error": any(isinstance(c, dict) for c in cells), "unit": "ns"})
    cells = []
    for v in big:
        try:
            cells.append(enc(pl.Series([v], dtype=pl.Int64).cast(pl.Time, strict=False).cast(pl.Int64).to_list()[0]))
        except EXC:
            cells.append({"error": True})
    cases.append({"id": "time-cast-int-time-nonstrict-pl", "kind": "time_cast_int", "engine": "pl", "op": "nonstrict", "in": {"ns": big}, "expect": cells,
                  "error": any(isinstance(c, dict) for c in cells), "unit": "ns"})
    # time -> duration, -> int
    def t2d():
        s = pl.Series([3_723_000_000_000, 0, None], dtype=pl.Int64).cast(pl.Time)
        return {"dur_us": enc(s.cast(pl.Duration("us")).dt.total_microseconds().to_list()), "i64": enc(s.cast(pl.Int64).to_list())}
    add("time-cast-dur-pl", "time_cast_out", "pl", "duration_int", {"ns": [3_723_000_000_000, 0, None]}, t2d)
    # read_csv
    csv = "t,u,v,w\n01:02:03,01:02,x,2022-01-01\n23:59:59.999999,,y,2022-01-02\n00:00:00.120,13:30,z,\n"
    csv2 = "t\n01:02:03\n23:59:59.9999999\n"
    csv3 = "t\n01:02:03\n01:02\n"
    csv4 = "t\n01:02:03\nabc\n"
    csv5 = "t\n25:00:00\n"
    csv6 = "t\n1:02:03\n"
    csv7 = "t\n\n01:02:03\n"
    csv8 = "t,n\n12:00:00.5,1\n12:00:00.123456789,2\n"
    probes = (("hm-only", "t\n01:02\n13:30\n"), ("h1m2", "t\n1:02\n"), ("h1m1", "t\n1:2\n3:4\n"), ("ratio", "t\n1:2\n10:20\n"),
              ("h1-hms", "t\n1:02:03\n"), ("frac-only", "t\n01:02:03.5\n"), ("lead-space", "t\n 01:02:03\n"), ("trail-space", "t\n01:02:03 \n"),
              ("time-int", "t\n01:02:03\n5\n"), ("time-text", "t\n01:02:03\nx\n"), ("h24", "t\n24:00:00\n"), ("big", "t\n99:99\n"),
              ("hm-null", "t,u\n01:02,1\n,2\n"), ("hms-null", "t,u\n01:02:03,1\n,2\n"), ("long-frac", "t\n01:02:03.1234567891\n"))
    for tag, text in probes:
        for mode, kw in (("try", {"try_parse_dates": True}), ("schema", {"schema_overrides": {"t": pl.Time}})):
            def f(text=text, kw=kw):
                df = pl.read_csv(io.BytesIO(text.encode()), **kw)
                return {"columns": df.columns, "dtypes": [tree(d) for d in df.dtypes],
                        "rows": [[(ns_of(v) if isinstance(v, dt.time) else enc(v)) for v in r] for r in df.iter_rows()]}
            add(f"time-csv-probe-{mode}-{tag}-pl", "time_read_csv", "pl", "read_csv", {"text": text, "opts": {("try_parse_dates" if mode == "try" else "schema_overrides"): (True if mode == "try" else {"t": "Time"})}}, f, unit="ns")
    for tag, text, kw in (("try-parse", csv, {"try_parse_dates": True}), ("try-parse-ns", csv2, {"try_parse_dates": True}), ("try-parse-hm", csv3, {"try_parse_dates": True}),
                          ("try-parse-bad", csv4, {"try_parse_dates": True}), ("try-parse-25", csv5, {"try_parse_dates": True}),
                          ("try-parse-1digit", csv6, {"try_parse_dates": True}), ("try-parse-blank", csv7, {"try_parse_dates": True}),
                          ("try-parse-frac", csv8, {"try_parse_dates": True}),
                          ("schema-u", csv, {"schema_overrides": {"u": pl.Time}}), ("schema-t", csv, {"schema_overrides": {"t": pl.Time}}),
                          ("schema-t-bad", csv4, {"schema_overrides": {"t": pl.Time}}), ("schema-t-25", csv5, {"schema_overrides": {"t": pl.Time}}),
                          ("schema-t-hm", csv3, {"schema_overrides": {"t": pl.Time}}), ("schema-t-1digit", csv6, {"schema_overrides": {"t": pl.Time}}),
                          ("schema-t-ns", csv2, {"schema_overrides": {"t": pl.Time}}), ("schema-t-frac", csv8, {"schema_overrides": {"t": pl.Time}}),
                          ("plain", csv, {}), ("no-parse-hm", csv3, {})):
        def f(text=text, kw=kw):
            df = pl.read_csv(io.BytesIO(text.encode()), **kw)
            return {"columns": df.columns, "dtypes": [tree(d) for d in df.dtypes],
                    "rows": [[(ns_of(v) if isinstance(v, dt.time) else enc(v)) for v in r] for r in df.iter_rows()]}
        add(f"time-csv-{tag}-pl", "time_read_csv", "pl", "read_csv", {"text": text, "opts": {k: (str(v) if not isinstance(v, (bool, dict)) else (v if isinstance(v, bool) else {a: str(b) for a, b in v.items()})) for k, v in kw.items()}}, f, unit="ns")
    # writers
    def frame():
        return pl.DataFrame({"t": pl.Series([3_723_000_000_000, 86_399_999_999_000, 120_000_000, 43_200_000_005_000, 0, None], dtype=pl.Int64).cast(pl.Time),
                             "n": [1, 2, 3, 4, 5, 6]})
    tv = [3_723_000_000_000, 86_399_999_999_000, 120_000_000, 43_200_000_005_000, 0, None]
    inp = {"ns": tv, "n": [1, 2, 3, 4, 5, 6]}
    add("time-write-json-pl", "time_write", "pl", "write_json", inp, lambda: [frame().write_json()], unit="ns")
    add("time-write-ndjson-pl", "time_write", "pl", "write_ndjson", inp, lambda: [frame().write_ndjson()], unit="ns")
    add("time-write-csv-pl", "time_write", "pl", "write_csv", inp, lambda: [frame().write_csv()], unit="ns")
    add("time-write-json-one-pl", "time_write", "pl", "write_json_col", inp, lambda: [frame().select("t").write_json()], unit="ns")
    add("time-repr-pl", "time_repr", "pl", "str_frame", inp, lambda: [str(frame())], unit="ns")
    add("time-repr-dtype-pl", "time_repr", "pl", "str_dtype", inp, lambda: [str(frame()["t"].dtype)], unit="ns")
    add("time-repr-series-pl", "time_repr", "pl", "str_series", inp, lambda: [str(frame()["t"])], unit="ns")


for g in (g_many, g_fwf, g_ranges, g_latex, g_json, g_time):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{g.__name__}: {type(e).__name__}: {e}")
    sys.stderr.write(f"done {g.__name__}: {len(cases)}\n")

cnt = Counter((c["kind"], c["engine"]) for c in cases)
out = sys.argv[1] if len(sys.argv) > 1 else "oracle2k_vectors.json"
cases.sort(key=lambda c: c["id"])
with open(out, "w") as fh:
    fh.write("[\n")
    fh.write(",\n".join(json.dumps(c, ensure_ascii=False, separators=(",", ":"), sort_keys=True) for c in cases))
    fh.write("\n]\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for k, n in sorted(cnt.items()):
    sys.stderr.write(f"COUNT {k[0]} {k[1]} {n}\n")
for c in cases:
    if c.get("error") and c.get("msg"):
        sys.stderr.write(f"ERRCASE {c['id']}: {c['msg']}\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
