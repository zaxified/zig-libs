#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the str, dt and duration gaps of dataframe S2 wave W4: pandas 3.1 and
polars 2.1 over small generated inputs, frozen into src/oracle2c_vectors.json and replayed by
src/s2w4_oracle_test.zig. No line of dataframe is consulted here: the expected values are what
the engines answer. (A separate script and file from oracle2.py / oracle2b.py on purpose.)

    python tools/oracle2c.py src/oracle2c_vectors.json      (see tools/README.md)

A case the engine raises on is reported on stderr and left out of the file.
"""
import datetime as dt
import io
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
    if isinstance(v, (list, tuple, np.ndarray)):
        return [cell(x) for x in v]
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


def pser(xs):
    return pd.Series(xs, dtype="string")


def pl_eval(df, e):
    return cells(df.select(e.alias("o"))["o"].to_list())


S = "string"
# ── str: split / rsplit / partition / split_exact ────────────────────────────

WS = ["  a b  c ", "x", "", None, "a\tb\nc d", "one two three four", "α β", "a  b", " lead", "trail  "]


def g_split():
    for n in (-1, 1, 2):
        def f(n=n):
            r = pser(WS).str.split(n=n)
            case(f"split_ws-n{n}", "expr", "pandas", cells([list(x) if isinstance(x, (list, np.ndarray)) else None for x in r]),
                 op="split_ws", cols={"x": WS}, limit=None if n == -1 else n + 1)
        run(f"split_ws-n{n}", f)
    RS = ["a,b,c", "a", "", None, ",a,", "a,,b", "abcabc", "a,b,c,d,e"]
    for by, n in ((",", -1), (",", 1), (",", 2), ("ab", -1), ("ab", 1), (",,", -1)):
        def f(by=by, n=n):
            r = pser(RS).str.rsplit(by, n=n)
            case(f"rsplit-{by}-n{n}", "expr", "pandas", cells([list(x) if isinstance(x, (list, np.ndarray)) else None for x in r]),
                 op="rsplit", cols={"x": RS}, by=by, limit=None if n == -1 else n + 1)
        run(f"rsplit-{by}-n{n}", f)
    PS = ["a=b=c", "abc", None, "", "=x", "x=", "==", "a=="]
    for last in (False, True):
        def f(last=last):
            r = pser(PS).str.rpartition("=") if last else pser(PS).str.partition("=")
            exp = {str(c): cells(r[c].tolist()) for c in r.columns}
            case(f"partition-{last}", "expr_rec", "pandas", exp, op="partition", cols={"x": PS}, sep="=", last=last)
        run(f"partition-{last}", f)

    SE = ["a_b_c_d", "a_b", "a", None, "", "_a__", "a__b"]
    for n in (0, 1, 2, 5):
        def f(n=n):
            df = pl.DataFrame({"x": SE})
            r = df.select(pl.col("x").str.split_exact("_", n).alias("o")).unnest("o")
            exp = {c: cells(r[c].to_list()) for c in r.columns}
            case(f"split_exact-{n}", "expr_rec", "polars", exp, op="split_fields", cols={"x": SE}, by="_", n=n, rest=False)
        run(f"split_exact-{n}", f)
    for n in (1, 2, 3, 6):
        def f(n=n):
            df = pl.DataFrame({"x": SE})
            r = df.select(pl.col("x").str.splitn("_", n).alias("o")).unnest("o")
            exp = {c: cells(r[c].to_list()) for c in r.columns}
            case(f"splitn-{n}", "expr_rec", "polars", exp, op="split_fields", cols={"x": SE}, by="_", n=n, rest=True)
        run(f"splitn-{n}", f)

    # expand into columns
    EX = ["a|b|c", "a", "", None, "|x|", "p|q", "a||b"]
    for n in (-1, 1, 2):
        def f(n=n):
            r = pser(EX).str.split("|", n=n, expand=True)
            exp = {str(c): cells(r[c].tolist()) for c in r.columns}
            case(f"splitcols-lit-n{n}", "frame", "pandas", exp, fn="splitColumns", cols={"x": EX},
                 args={"by": "|", "limit": None if n == -1 else n + 1})
        run(f"splitcols-lit-n{n}", f)

    def f2():
        r = pser(WS).str.split(expand=True)
        exp = {str(c): cells(r[c].tolist()) for c in r.columns}
        case("splitcols-ws", "frame", "pandas", exp, fn="splitColumns", cols={"x": WS}, args={})
    run("splitcols-ws", f2)

    def f3():
        RX = ["a , b,c", "x", None, "1 ,2 , 3 ,4"]
        r = pser(RX).str.split(r"\s*,\s*", expand=True, regex=True)
        exp = {str(c): cells(r[c].tolist()) for c in r.columns}
        case("splitcols-regex", "frame", "pandas", exp, fn="splitColumns", cols={"x": RX}, args={"by": r"\s*,\s*", "regex": True})
    run("splitcols-regex", f3)

    DM = ["a|b", "b|c", "", None, "a", "c|a|b", "a|a", "|a"]
    for sep in ("|", ","):
        def f(sep=sep):
            data = [x.replace("|", sep) if x else x for x in DM]
            r = pser(data).str.get_dummies(sep)
            exp = {str(c): cells(r[c].tolist()) for c in r.columns}
            case(f"get_dummies-{sep}", "frame", "pandas", exp, fn="getDummies", cols={"x": data}, args={"sep": sep})
        run(f"get_dummies-{sep}", f)


# ── str: wrap, slice_replace, encode, misc ───────────────────────────────────

WR = [
    "The quick brown fox jumps over the lazy dog",
    "A very-long-hyphenated-word-here and some more words",
    "abcdefghijklmnopqrstuvwxyz",
    "tab\tseparated\tvalues here",
    "line one\nline two\r\nline three",
    "  leading and trailing  ",
    "",
    None,
    "double  spaces   inside text",
    "re-do the well-known twenty-one-year-old test -- with dashes--and more",
    "x" * 30 + " y",
    "-----------------------",
    "a-b-c-d-e-f-g-h-i-j-k",
    "café crème brûlée naïve façade",
    "1-2-3 4-5-6 foo-1bar baz-bar-1",
]


def g_wrap():
    for w in (5, 10, 20, 40):
        for long_ in (True, False):
            for hy in (True, False):
                def f(w=w, long_=long_, hy=hy):
                    r = pser(WR).str.wrap(w, break_long_words=long_, break_on_hyphens=hy)
                    case(f"wrap-{w}-{long_}-{hy}", "expr", "pandas", cells(r.tolist()), op="wrap", cols={"x": WR},
                         width=w, break_long_words=long_, break_on_hyphens=hy)
                run(f"wrap-{w}-{long_}-{hy}", f)


def g_slice_replace():
    X = ["abcdef", "", "ab", None, "héllo wörld", "a"]
    for st, sp, rp in ((1, 3, "X"), (None, 2, "X"), (2, None, "X"), (-2, None, "X"), (3, 1, "X"), (None, None, "X"),
                       (-3, -1, "ZZ"), (10, 12, "Q"), (0, 0, "I"), (2, 2, "I"), (None, 0, "I"), (-10, 2, "")):
        def f(st=st, sp=sp, rp=rp):
            r = pser(X).str.slice_replace(st, sp, rp)
            case(f"slice_replace-{st}-{sp}-{rp}", "expr", "pandas", cells(r.tolist()), op="slice_replace", cols={"x": X},
                 start=st, stop=sp, repl=rp)
        run(f"slice_replace-{st}-{sp}-{rp}", f)


def g_encode():
    X = ["hello", "héllo", "", None, "a b", "日本"]
    for how in ("hex", "base64"):
        def f(how=how):
            case(f"encode-{how}", "expr", "polars", pl_eval(pl.DataFrame({"x": X}), pl.col("x").str.encode(how)),
                 op="encode", cols={"x": X}, how=how)
        run(f"encode-{how}", f)
    HX = ["6869", "4A4b", "abc", "zz", "", None, "ff", "68 69", "e697a5"]
    B6 = ["aGk=", "aGk", "/w==", "", None, "aGVsbG8=", "aG k=", "====", "5pel"]
    for how, data in (("hex", HX), ("base64", B6)):
        def f(how=how, data=data):
            r = pl.DataFrame({"x": data}).select(pl.col("x").str.decode(how, strict=False).alias("o"))["o"].to_list()
            out = []
            for b in r:
                if b is None:
                    out.append(None)
                else:
                    try:
                        out.append(b.decode("utf-8"))
                    except UnicodeDecodeError:
                        out.append(None)
            case(f"decode-{how}", "expr", "polars", out, op="decode", cols={"x": data}, how=how)
        run(f"decode-{how}", f)


def g_misc_str():
    A = ["apple", "banana", "cherry", None, "", "ab", "Apple"]
    for pats in (("a", "b"), ("ch", "ba", "x"), ("",), ()):
        for end in (False, True):
            def f(pats=pats, end=end):
                s = pser(A)
                r = s.str.endswith(pats) if end else s.str.startswith(pats)
                case(f"affix-{'|'.join(pats)}-{end}", "expr", "pandas", cells(r.tolist()), op="affix_any", cols={"x": A},
                     patterns=list(pats), end=end)
            run(f"affix-{'|'.join(pats)}-{end}", f)
    R = ["banana", "aaa", "", None, "abc", "xaxaxa"]
    for n in (1, 2, 3, 10):
        def f(n=n):
            r = pser(R).str.replace("a", "X", n=n, regex=False)
            case(f"replace_n-{n}", "expr", "pandas", cells(r.tolist()), op="replace_n", cols={"x": R}, frm="a", to="X", n=n)
        run(f"replace_n-{n}", f)
        def f2(n=n):
            r = pser(R).str.replace("a+", "X", n=n, regex=True)
            case(f"replace_regex_n-{n}", "expr", "pandas", cells(r.tolist()), op="replace_regex", cols={"x": R}, pattern="a+", to="X", n=n)
        run(f"replace_regex_n-{n}", f2)
    M = ["abc", "ab", "xab", "123", "12a", None, "", "ABC", "abab"]
    for pat in ("ab", "a|ab", r"\d+", "(?i)abc", "(ab)+", ""):
        for full in (False, True):
            def f(pat=pat, full=full):
                s = pser(M)
                r = s.str.fullmatch(pat) if full else s.str.match(pat)
                case(f"match-{pat}-{full}", "expr", "pandas", cells(r.tolist()), op="match_regex", cols={"x": M}, pattern=pat, full=full)
            run(f"match-{pat}-{full}", f)
    I = ["abc", "héllo", "", None, "日本", "a\x7f"]
    def f4():
        case("isascii", "expr", "pandas", cells(pser(I).str.isascii().tolist()), op="is_ascii", cols={"x": I})
    run("isascii", f4)


# ── dt: parsing without a format ─────────────────────────────────────────────

def g_parse():
    iso = ["2024-01-05", "2024-01-05T10:20:30", "2024-01-05 10:20:30.5", None, "2024-12-31T23:59:59.123456", "bad", "2024-02-30"]
    def f():
        r = pd.to_datetime(pd.Series(iso, dtype=S), format="ISO8601", errors="coerce")
        case("to_datetime-iso8601", "expr", "pandas", cells(r.tolist()), op="to_datetime", cols={"x": iso}, mode="iso8601", dayfirst=False, to="timestamp")
    run("to_datetime-iso8601", f)
    mixed = ["2024-01-05", "01/02/2024", "13/01/2024", "Jan 5, 2024", "5 January 2024", "2024/03/04 10:11:12", None, "bad", "03-04-2024"]
    # pandas with dayfirst=True reads year-first text as year-day-month ("2024-01-05" is May 1;
    # its own docs warn); that quirk is not followed, so the year-first cells are left out there.
    for dayfirst in (False, True):
        def f(dayfirst=dayfirst):
            data = [x for x in mixed if not (dayfirst and x and x[:4] in ("2024"))]
            r = pd.to_datetime(pd.Series(data, dtype=S), format="mixed", dayfirst=dayfirst, errors="coerce")
            case(f"to_datetime-mixed-{dayfirst}", "expr", "pandas", cells(r.tolist()), op="to_datetime", cols={"x": data}, mode="mixed", dayfirst=dayfirst, to="timestamp")
        run(f"to_datetime-mixed-{dayfirst}", f)
    homog = {
        "iso": ["2024-01-05", "2024-02-07", None],
        "isots": ["2024-01-05T10:20:30", "2024-02-07 01:02:03", None],
        "slash-ymd": ["2024/03/04 10:11:12", "2024/03/05 00:00:01", None],
        "slash-dmy": ["01/02/2024", "13/02/2024", None],
        "slash-dmy2": ["13/02/2024", "01/02/2024", None],
        "dot": ["05.03.2024", "06.03.2024"],
        "dash-dmy": ["05-03-2024", "06-03-2024"],
        "name": ["Jan 5, 2024", "Feb 6, 2024"],
        "name2": ["5 Jan 2024", "6 Feb 2024"],
        "allnull": [None, None],
    }
    for nm, data in homog.items():
        if nm == "allnull":
            continue
        for dayfirst in (False, True):
            if dayfirst and nm in ("iso", "isots", "slash-ymd"):
                continue
            def f(nm=nm, data=data, dayfirst=dayfirst):
                r = pd.to_datetime(pd.Series(data, dtype=S), dayfirst=dayfirst, errors="coerce")
                case(f"to_datetime-infer-pd-{nm}-{dayfirst}", "expr", "pandas", cells(r.tolist()), op="to_datetime", cols={"x": data}, mode="infer", dayfirst=dayfirst, to="timestamp")
            run(f"to_datetime-infer-pd-{nm}-{dayfirst}", f)
        def g(nm=nm, data=data):
            r = pl.DataFrame({"x": data}).select(pl.col("x").str.to_datetime(time_unit="us", strict=False).alias("o"))["o"].to_list()
            case(f"to_datetime-infer-pl-{nm}", "expr", "polars", cells(r), op="to_datetime", cols={"x": data}, mode="infer", dayfirst=True, to="timestamp")
        run(f"to_datetime-infer-pl-{nm}", g)
        sys.stderr.write(f"probe polars infer {nm}: " + str(pl.DataFrame({"x": data}).select(pl.col("x").str.to_datetime(time_unit="us", strict=False))["x"].to_list()) + "\n")


# ── dt: durations ────────────────────────────────────────────────────────────

TD = [90061000000, -1, 0, None, 86399999999, 1500000, -86400000000, -90061000001, 1]


def g_td():
    td = pd.to_timedelta(pd.Series(TD, dtype="Int64"), unit="us")
    case("td-total_seconds_f64", "expr", "pandas", cells(td.dt.total_seconds().tolist()), op="dt_part", part="total_seconds_f64", cols={"x": TD}, types={"x": "duration"})
    for fld, part in (("days", "td_days"), ("seconds", "td_seconds"), ("microseconds", "td_microseconds"), ("nanoseconds", "td_nanoseconds")):
        case(f"td-{fld}", "expr", "pandas", cells(getattr(td.dt, fld).tolist()), op="dt_part", part=part, cols={"x": TD}, types={"x": "duration"})
    comp = td.dt.components
    case("td-components", "expr_rec", "pandas", {c: cells(comp[c].tolist()) for c in comp.columns}, op="td_components", cols={"x": TD}, types={"x": "duration"})
    # polars whole-unit forms stay as before: cross-check the int form next to the float
    s = pl.Series(TD, dtype=pl.Duration("us"))
    case("td-total_seconds-polars", "expr", "polars", cells(s.dt.total_seconds().to_list()), op="dt_part", part="total_seconds", cols={"x": TD}, types={"x": "duration"})

    G = ["a", "a", "b", "b", "b", "a", "c"]
    D = [1000000, 2500000, 3000000, 7000000, 5000001, 9, None]
    df = pd.DataFrame({"g": G, "d": pd.to_timedelta(pd.Series(D, dtype="Int64"), unit="us")})
    for fn in ("sum", "mean", "median", "std", "min", "max"):
        def f(fn=fn):
            r = df.groupby("g", sort=False)["d"].agg(fn)
            case(f"agg-duration-{fn}", "agg", "pandas", {"g": list(r.index), "o": cells(r.tolist())}, cols={"g": G, "d": D}, types={"d": "duration"}, func=fn)
        run(f"agg-duration-{fn}", f)
    TS = [1700000000000000, 1700000003000000, 1700000007500000, 1700000100000001, None, 1600000000000000, 1]
    G2 = ["a", "a", "a", "b", "b", "c", "c"]
    dft = pd.DataFrame({"g": G2, "t": pd.to_datetime(pd.Series(TS, dtype="Int64"), unit="us")})
    for fn in ("mean", "median", "std", "min", "max"):
        def f(fn=fn):
            r = dft.groupby("g", sort=False)["t"].agg(fn)
            case(f"agg-timestamp-{fn}", "agg", "pandas", {"g": list(r.index), "o": cells(r.tolist())}, cols={"g": G2, "d": TS}, types={"d": "timestamp"}, func=fn)
        run(f"agg-timestamp-{fn}", f)

    for unit, mult in (("ms", 1000), ("s", 1_000_000), ("us", 1)):
        def f(unit=unit):
            txt = '[{"d":1500},{"d":null},{"d":-2},{"d":86400000}]'
            r = pd.read_json(io.StringIO(txt), dtype={"d": f"timedelta64[{unit}]"})
            case(f"json-duration-{unit}", "json", "pandas", {"d": cells(r["d"].tolist())}, text=txt, unit=unit, col="d")
        run(f"json-duration-{unit}", f)


# ── dt: replace, combine, offsets, business days ─────────────────────────────

def us(y, mo, d, h=0, mi=0, s=0, micro=0):
    return int((dt.datetime(y, mo, d, h, mi, s, micro) - dt.datetime(1970, 1, 1)) / dt.timedelta(microseconds=1))


TS = [us(2024, 1, 31, 10, 20, 30, 123), us(2024, 2, 29), us(2023, 12, 31, 23, 59, 59), None, us(2024, 3, 15, 12), us(1969, 7, 20, 20, 17)]


def g_dt():
    s = pl.Series(TS, dtype=pl.Datetime("us"))
    df = pl.DataFrame({"x": s})
    for kw in ({"year": 2028}, {"month": 3}, {"day": 1}, {"hour": 5, "minute": 6}, {"second": 59, "microsecond": 5}, {"year": 2023, "month": 2, "day": 28}):
        key = "-".join(f"{k}{v}" for k, v in kw.items())
        def f(kw=kw, key=key):
            case(f"replace-{key}", "expr", "polars", pl_eval(df, pl.col("x").dt.replace(**kw)), op="dt_replace", cols={"x": TS}, parts=kw)
        run(f"replace-{key}", f)

    D = ["2024-01-05", "2024-02-29", None, "2023-12-31"]
    T = ["10:20:30", "00:00:00", "23:59:59.123456", "12:00"]
    def f2():
        d2 = pl.DataFrame({"d": [dt.date(2024, 1, 5), dt.date(2024, 2, 29), None, dt.date(2023, 12, 31)], "t": [dt.time(10, 20, 30), dt.time(0), dt.time(23, 59, 59, 123456), dt.time(12)]})
        case("combine", "expr", "polars", pl_eval(d2, pl.col("d").dt.combine(pl.col("t"))), op="dt_combine",
             cols={"d": D, "t": ["10:20:30", "00:00:00", "23:59:59.123456", "12:00:00"]})
    run("combine", f2)

    Z = [us(2024, 1, 15, 12), us(2024, 7, 15, 12), us(2024, 3, 31, 0, 30), us(2024, 10, 27, 0, 59), us(2024, 10, 27, 1, 0), None, us(1999, 6, 1)]
    for zone in ("Europe/Prague", "America/New_York", "Australia/Lord_Howe", "Asia/Kolkata", "UTC", "Europe/Dublin"):
        for kind in ("base", "dst", "total"):
            def f(zone=zone, offset=kind):
                s = pl.Series(Z, dtype=pl.Datetime("us")).dt.replace_time_zone("UTC").dt.convert_time_zone(zone)
                dfz = pl.DataFrame({"x": s})
                if kind == "base":
                    exp = pl_eval(dfz, pl.col("x").dt.base_utc_offset())
                elif kind == "dst":
                    exp = pl_eval(dfz, pl.col("x").dt.dst_offset())
                else:
                    b = pl_eval(dfz, pl.col("x").dt.base_utc_offset())
                    d = pl_eval(dfz, pl.col("x").dt.dst_offset())
                    exp = [None if x is None else x + y for x, y in zip(b, d)]
                case(f"tz_offset-{zone}-{kind}", "expr", "polars", exp, op="tz_offset", cols={"x": Z}, zone=zone, offset=kind)
            run(f"tz_offset-{zone}-{kind}", f)

    BD = ["2024-01-05", "2024-01-06", "2024-01-07", "2024-01-08", "2024-12-25", "2024-12-26", None, "2024-01-01"]
    hol = ["2024-01-01", "2024-12-25", "2024-12-26"]
    masks = {"default": None, "satsun": [False, False, False, False, False, True, True], "sunthu": [True, True, True, True, False, False, True], "tue": [False, True, False, False, False, False, False]}
    sd = pl.DataFrame({"x": pl.Series([None if x is None else dt.date.fromisoformat(x) for x in BD])})
    for mn, mk in masks.items():
        for use_hol in (False, True):
            def f(mn=mn, mk=mk, use_hol=use_hol):
                kw = {}
                if mk:
                    kw["week_mask"] = mk
                if use_hol:
                    kw["holidays"] = [dt.date.fromisoformat(h) for h in hol]
                case(f"is_business_day-{mn}-{use_hol}", "expr", "polars", pl_eval(sd, pl.col("x").dt.is_business_day(**kw)),
                     op="is_business_day", cols={"x": BD}, week_mask=mk, holidays=hol if use_hol else [])
            run(f"is_business_day-{mn}-{use_hol}", f)
            for n in (0, 1, 3, -1, -4, 10, -11, 33):
                for roll in ("forward", "backward"):
                    def g(mn=mn, mk=mk, use_hol=use_hol, n=n, roll=roll):
                        kw = {"roll": roll}
                        if mk:
                            kw["week_mask"] = mk
                        if use_hol:
                            kw["holidays"] = [dt.date.fromisoformat(h) for h in hol]
                        r = pl_eval(sd, pl.col("x").dt.add_business_days(n, **kw))
                        case(f"add_business_days-{mn}-{use_hol}-{n}-{roll}", "expr", "polars", r, op="add_business_days", cols={"x": BD},
                             n=n, week_mask=mk, holidays=hol if use_hol else [], roll=roll)
                    run(f"add_business_days-{mn}-{use_hol}-{n}-{roll}", g)


for g in (g_split, g_wrap, g_slice_replace, g_encode, g_misc_str, g_parse, g_td, g_dt):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{g.__name__}: {type(e).__name__}: {e}")

out = sys.argv[1] if len(sys.argv) > 1 else "oracle2c_vectors.json"
with open(out, "w") as fh:
    json.dump(cases, fh, indent=0, ensure_ascii=False)
    fh.write("\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
