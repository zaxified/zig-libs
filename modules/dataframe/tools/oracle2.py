#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the verbs `dataframe` added in D2 (structure, analysis, element
functions, dt accessor, reshape, series functions, frame operations): pandas and polars
over small generated inputs, frozen into src/oracle2_vectors.json and replayed by
src/oracle2_test.zig. No line of dataframe is consulted here: the expected values are
what the two engines answer.

    python tools/oracle2.py src/oracle2_vectors.json      (see tools/README.md)

Two kinds of case. A *scalar* case runs one cell function over a list of cells
(`round`, `strptime`, `slice`, ...). A *frame* case runs one verb over a small table
(`fill_null`, `qcut`, `pivot_many`, ...). Every case runs on both engines where both
have the operation. A disagreement between them must carry a `label` naming the
difference and `follow` naming the engine this module follows (the LABELS table), or
the run fails: an unlabelled disagreement is a question nobody has answered. An engine
that raises on a case is recorded (`pandas_error` / `polars_error`) and the other one
is the oracle; when both raise the case expects an error. NaN and null are both
"missing" in the frozen cells.
"""
import json
import math
import re
import sys

import numpy as np
import pandas as pd
import polars as pl

scalar_cases = []
frame_cases = []
problems = []
stats = {}  # group -> {both, agree, labelled, pandas, polars, none}


def ts_us(v):
    """Microseconds since the epoch of a pandas Timestamp (`.value` is nanoseconds and overflows)."""
    return int(pd.Timestamp(v).as_unit("us").asm8.view("i8"))


def us(s):
    return int(np.datetime64(s, "us").astype("int64"))


# ── values ──────────────────────────────────────────────────────────────────


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
        return 0.0 if v == 0 else v
    return str(v)


def enc(v):
    """JSON form of an input cell: NaN and infinities as the strings the replay reads."""
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "inf" if v > 0 else "-inf"
    if isinstance(v, (list, tuple)):
        return [enc(x) for x in v]
    return v


def near(a, b):
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    if isinstance(a, bool) or isinstance(b, bool):
        return float(a) == float(b)
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    a, b = float(a), float(b)
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def lists_same(p, q):
    return len(p) == len(q) and all(near(x, y) for x, y in zip(p, q))


def attempt(f, *args):
    try:
        return f(*args), None
    except Exception as e:  # an engine that lacks the operation or refuses the input
        return None, f"{type(e).__name__}: {str(e).splitlines()[0][:110] if str(e) else ''}"


# Disagreements between the engines: case id prefix -> (label, engine followed).
LABELS = {}


def label_for(cid):
    for k, v in LABELS.items():
        if k.startswith("*") and k[1:] in cid:  # a key with a star matches anywhere in the id
            return v
    best = None
    for k, v in LABELS.items():
        if k.startswith("*"):
            continue
        if cid.startswith(k) and (best is None or len(k) > len(best[0])):
            best = (k, v)
    return best[1] if best else None


def bump(group, key):
    stats.setdefault(group, dict(both=0, agree=0, labelled=0, pandas=0, polars=0, none=0))[key] += 1


LABELS.update({
    "pivot_many-first": ("`first` of a cell holding a null first: pandas takes the first non-null, polars the first value", "pandas"),
    "strptime-ymd": ("leading whitespace: polars skips it, pandas refuses", "pandas"),
    "qcut-": ("polars checks only the interior quantiles for repeats, pandas also the lowest and the highest edge", "pandas"),
    "dt-nanosecond": ("pandas' nanosecond is the part below the microsecond (0 for a microsecond clock); polars' is the fraction of the second in nanoseconds", "polars"),
    "dt-is_leap_year": ("a missing time: pandas answers False (NaT), polars null", "polars"),
    "dt-is_business_day": ("a missing time: pandas answers False (NaT), polars null", "polars"),
    "strptime-frac": ("`%f` is the decimal fraction in pandas (Python); chrono reads its digits as a count of nanoseconds, so .123456 is 123 us", "pandas"),
    "strptime-y2": ("`%y` pivot: pandas 69 to 1969 and 00..68 to 20xx (POSIX); chrono 00..69 to 20xx, 70..99 to 19xx", "polars"),
    "strptime-mdy": ("`%y` pivot, as strptime-y2", "polars"),
    "*naTrue": ("with dummy_na the missing column is `_null` in polars, `_nan` in pandas; this module uses the word null throughout", "polars"),
    "strptime-month": ("`%B` accepts an abbreviated month in polars, not in pandas", "pandas"),
    "strptime-wday": ("a weekday name that does not fit the date: pandas ignores it, polars returns null", "pandas"),
    "strptime-doy": ("`%j` past the end of the year: pandas rolls into the next year, polars returns null", "polars"),
    "strptime-tz": ("`%z`: pandas takes Z, +01 and an absent offset (as UTC), polars only +hhmm and +hh:mm", "pandas"),
    "strftime-8": ("`%f` is six digits in pandas (Python), nine in polars (chrono nanoseconds)", "pandas"),
    "strftime-22": ("`%f` as above", "pandas"),
    "strftime-34": ("`%s` is the epoch seconds of the UTC instant in polars, of the local time in naive pandas", "polars"),
    "truncate-1w": ("pandas floors weeks from the epoch (a Thursday), polars from a Monday", "polars"),
    "truncate-2w": ("as truncate-1w", "polars"),
    "truncate-3w": ("as truncate-1w", "polars"),
    "truncate-4w": ("as truncate-1w", "polars"),
    "dt-time": ("the time of day as text: pandas keeps the fraction of the second, polars cuts it off", "pandas"),
    "bday-": ("from a weekend, pandas BDay counts the roll to Monday as the first day, polars rolls first (roll=forward)", "polars"),
    "str-reverse": ("polars reverses grapheme clusters, pandas code points", "pandas"),
    "str-uni-title": ("non-ASCII case mapping differs between Python and Rust; this module's case functions are ASCII (SPEC Backlog)", "polars"),
    "fill-an-": ("a NaN is a missing cell for pandas' fill, an ordinary value for polars' fill_null; this module treats NaN as missing throughout (SPEC)", "pandas"),
    "fill-at-zero": ("zero strategy on text: pandas casts to 0, polars fills the empty string", "polars"),
    "interpolate-": ("a gap after the last present value: pandas repeats the last value (limit_direction forward), polars leaves null", "polars"),
    "dummies-": ("polars always writes a `_null` column (also without nulls) and keeps the dummies in place; pandas appends them, and writes `_nan` with dummy_na only", "pandas"),
    "merge_ordered-": ("a text/number mix is not an issue here; see label of the case", "pandas"),
    "transpose-mixed": ("a mix of text and numbers: pandas keeps the cells (object), polars casts the numbers to text", "pandas"),
    "agg-quantile-nearest": ("`nearest` at a half-way position: numpy/pandas round to even, polars rounds up", "pandas"),
})

# ── scalar cases ────────────────────────────────────────────────────────────


def mk_pd(kind, vals):
    if kind == "float":
        return pd.Series([np.nan if v is None else v for v in vals], dtype="float64")
    if kind == "int":
        return pd.Series(pd.array(vals, dtype="Int64"))
    if kind == "text":
        return pd.Series(vals, dtype="str")
    if kind == "bool":
        return pd.Series(pd.array(vals, dtype="boolean"))
    if kind == "ts":
        return pd.Series(np.array([np.datetime64("NaT") if v is None else np.datetime64(int(v), "us") for v in vals], dtype="datetime64[us]"))
    raise ValueError(kind)


def mk_pl(kind, vals):
    if kind == "float":
        return pl.Series(vals, dtype=pl.Float64)
    if kind == "int":
        return pl.Series(vals, dtype=pl.Int64)
    if kind == "text":
        return pl.Series(vals, dtype=pl.String)
    if kind == "bool":
        return pl.Series(vals, dtype=pl.Boolean)
    if kind == "ts":
        return pl.Series(vals, dtype=pl.Int64).cast(pl.Datetime("us"))
    raise ValueError(kind)


def out_list(r, out_kind):
    """An engine's answer as a list of cells."""
    if isinstance(r, pd.DataFrame):
        r = r.iloc[:, 0]
    if isinstance(r, pd.Series):
        if out_kind == "ts":
            return [None if pd.isna(v) else ts_us(v) for v in r]
        return [whole(cell(v), out_kind) for v in r]
    if isinstance(r, pl.Series):
        if out_kind == "ts":
            r = r.dt.timestamp("us")
        return [whole(cell(v), out_kind) for v in r.to_list()]
    return [whole(cell(v), out_kind) for v in r]


def whole(v, out_kind):
    """pandas holds an int column with a missing cell as float: 1969.0 is the int 1969."""
    if out_kind in ("int", "ts") and isinstance(v, float) and v == int(v):
        return int(v)
    return v


def scase(cid, group, fn, args, vals, in_kind, out_kind, fp=None, fq=None, extra=None, gap=False):
    """fp(pandas Series), fq(polars Series): each returns a Series or a list."""
    p = q = None
    perr = qerr = None
    if fp:
        r, perr = attempt(lambda: out_list(fp(mk_pd(in_kind, vals)), out_kind))
        p = r
    if fq:
        r, qerr = attempt(lambda: out_list(fq(mk_pl(in_kind, vals)), out_kind))
        q = r
    e = {"id": cid, "group": group, "fn": fn, "args": args, "in": enc(vals), "in_kind": in_kind, "out_kind": out_kind}
    if extra:
        e.update(extra)
    if perr:
        e["pandas_error"] = perr
    if qerr:
        e["polars_error"] = qerr
    if gap:
        # A directive this module refuses on purpose: the replay pins the refusal; the engines' answers are kept for reference.
        e["engine"] = "gap"
        e["expect"] = enc(p if p is not None else q)
        bump(group, "none")
    else:
        finish(e, group, cid, p, q, lambda x: enc(x), (fp is not None, fq is not None))
    scalar_cases.append(e)


def finish(e, group, cid, p, q, encode, attempted=(True, True), errors_ok=False):
    """Choose the engine followed, label a disagreement, put `expect` in `e`."""
    if p is not None and q is not None:
        bump(group, "both")
        if lists_same(p, q):
            bump(group, "agree")
            e["engine"] = "both"
            use = p
        else:
            lab = label_for(cid)
            if not lab:
                problems.append(f"UNLABELLED DISAGREEMENT {cid}\n   pandas {p}\n   polars {q}\n   input  {e.get('in', e.get('table'))}")
                lab = ("UNLABELLED", "pandas")
            bump(group, "labelled")
            e["label"], e["engine"] = lab
            use = p if lab[1] == "pandas" else q
            e["other"] = encode(q if lab[1] == "pandas" else p)
    elif p is not None or q is not None:
        e["engine"] = "pandas" if p is not None else "polars"
        bump(group, e["engine"])
        use = p if p is not None else q
    else:
        bump(group, "none")
        e["engine"] = "none"
        use = None
        # Both engines refused: the case expects an error, where an error is the verb's contract.
        if errors_ok and all(attempted) and e.get("pandas_error") and e.get("polars_error"):
            e["expect_error"] = True
    e["expect"] = None if use is None else encode(use)


# ── data ────────────────────────────────────────────────────────────────────

NAN = float("nan")
INF = float("inf")

ROUND_FLOATS = [0.5, 1.5, 2.5, 3.5, -0.5, -1.5, -2.5, 0.0, 2.675, 1.005, 0.125, 0.375, 0.285, 1.45, 0.045, 4.35, 1234.5678, -1234.5678, 2.5e-5, 123456789.125, 1e15, 5e-324, 1e300, None, NAN, INF, -INF]
ROUND_INTS = [15, 25, 35, -15, -25, 5, 14, 16, 0, 149, 150, 151, 1234567, None]
SIG_FLOATS = [0.0, 123.456, 0.000123456, 2.5, 3.5, 0.15, 0.25, 12345.0, -2.5, -0.0015, 1e-10, 1234567.0, 99.95, 9.995, 0.9995, 1e300, None, NAN, INF]
SIG_INTS = [0, 15, 25, 35, 125, 135, 12345, -12345, 99999, 1, None]

TS_STR = [
    "1969-12-31 23:59:59.999999", "1970-01-01", "1900-03-01 12:00", "1600-01-01", "2000-01-01", "2000-02-29 13:14:15.123456",
    "2000-12-31", "2004-12-31", "2005-01-01", "2005-01-02", "2005-12-31", "2006-01-01", "2006-01-02", "2008-12-28",
    "2008-12-29", "2008-12-31", "2009-01-01", "2009-01-04", "2010-01-03", "2010-01-04", "2015-12-31", "2016-01-01",
    "2016-01-03", "2020-12-31", "2021-01-01", "2021-01-03", "2021-01-04", "2021-03-31", "2021-04-01", "2021-06-30",
    "2021-09-30", "2021-10-01", "2024-02-29", "2026-11-07 23:59:59.999999", "2100-02-28", "2100-03-01", "2262-04-11",
]
TS = [us(s) for s in TS_STR]

# Floors, offsets and business days: times of day, month ends, week ends, leap days.
TS2_STR = [
    "2021-01-29 10:30", "2021-01-31", "2020-02-29 23:59:59.999999", "2021-03-31 12:00", "2021-12-31",
    "1999-12-31 23:00", "2000-03-01", "2021-06-15 08:15:30.500", "1970-01-01", "1969-12-31 23:59:59",
    "2021-01-03 00:00", "2021-01-04 00:00", "2021-01-10 23:59", "2021-01-01 00:00", "2021-01-02 15:00",
]
TS2 = [us(s) for s in TS2_STR]

# Mondays to Sundays around a month end, and the year ends.
BDAY_STR = ["2021-01-01 09:00", "2021-01-02 09:00", "2021-01-03", "2021-01-04", "2021-01-08 17:30", "2021-01-09",
            "2021-01-10 12:00", "2021-01-29", "2021-01-30", "2020-12-31", "2024-02-29", "1969-12-31", "1970-01-03"]
BDAY = [us(s) for s in BDAY_STR]


def run_scalar_cases():
    # round ----------------------------------------------------------------
    for d in (0, 1, 2, 3, -1, -2):
        scase(f"round-half_even-f-{d}", "round", "round", {"decimals": d, "mode": "half_even"}, ROUND_FLOATS, "float", "float",
              lambda s, d=d: s.round(d), lambda s, d=d: s.round(d, mode="half_to_even"))
        scase(f"round-half_away-f-{d}", "round", "round", {"decimals": d, "mode": "half_away"}, ROUND_FLOATS, "float", "float",
              None, lambda s, d=d: s.round(d, mode="half_away_from_zero"))
    for d in (-2, -1, 0, 1):
        scase(f"round-half_even-i-{d}", "round", "round", {"decimals": d, "mode": "half_even"}, ROUND_INTS, "int", "int",
              lambda s, d=d: s.round(d), lambda s, d=d: s.round(d, mode="half_to_even"))
        scase(f"round-half_away-i-{d}", "round", "round", {"decimals": d, "mode": "half_away"}, ROUND_INTS, "int", "int",
              None, lambda s, d=d: s.round(d, mode="half_away_from_zero"))
    # round_sig_figs ------------------------------------------------------------
    for g in (1, 2, 3, 5):
        scase(f"sigfigs-f-{g}", "round_sig_figs", "round_sig_figs", {"digits": g}, SIG_FLOATS, "float", "float", None, lambda s, g=g: s.round_sig_figs(g))
        scase(f"sigfigs-i-{g}", "round_sig_figs", "round_sig_figs", {"digits": g}, SIG_INTS, "int", "int", None, lambda s, g=g: s.round_sig_figs(g))
    # is_close -------------------------------------------------------------------
    pairs = [(1.0, 1.0 + 1e-9), (1.0, 1.1), (0.0, 1e-10), (INF, INF), (INF, -INF), (NAN, NAN), (NAN, 1.0), (None, 1.0), (1.0, None),
             (1e10, 1e10 + 1), (100.0, 101.0), (-5.0, -5.000001), (0.0, 0.0), (1e-300, 2e-300), (1e308, 1.0000001e308), (3.0, 3.0)]
    for rt, at in ((1e-5, 0.0), (1e-9, 0.0), (1e-9, 1e-8), (0.0, 0.0), (0.0, 0.5), (0.01, 0.1)):
        for ne in (False, True):
            def fq(rt=rt, at=at, ne=ne):
                df = pl.DataFrame({"a": pl.Series([p[0] for p in pairs], dtype=pl.Float64), "b": pl.Series([p[1] for p in pairs], dtype=pl.Float64)})
                return df.select(pl.col("a").is_close(pl.col("b"), rel_tol=rt, abs_tol=at, nans_equal=ne))["a"]
            e = {"id": f"is_close-{rt}-{at}-{ne}", "group": "is_close", "fn": "is_close", "args": {"rel_tol": rt, "abs_tol": at, "nans_equal": ne},
                 "in": enc([list(p) for p in pairs]), "in_kind": "pair", "out_kind": "bool"}
            q, qerr = attempt(lambda: out_list(fq(), "bool"))
            if qerr:
                e["polars_error"] = qerr
            finish(e, "is_close", e["id"], None, q, enc)
            scalar_cases.append(e)
    # dt accessor -----------------------------------------------------------------
    D = {
        "year": (lambda s: s.dt.year, lambda s: s.dt.year()),
        "month": (lambda s: s.dt.month, lambda s: s.dt.month()),
        "day": (lambda s: s.dt.day, lambda s: s.dt.day()),
        "hour": (lambda s: s.dt.hour, lambda s: s.dt.hour()),
        "minute": (lambda s: s.dt.minute, lambda s: s.dt.minute()),
        "second": (lambda s: s.dt.second, lambda s: s.dt.second()),
        "millisecond": (lambda s: s.dt.microsecond // 1000, lambda s: s.dt.millisecond()),
        "microsecond": (lambda s: s.dt.microsecond, lambda s: s.dt.microsecond()),
        "nanosecond": (lambda s: s.dt.nanosecond, lambda s: s.dt.nanosecond()),
        "weekday": (lambda s: s.dt.dayofweek + 1, lambda s: s.dt.weekday()),
        "day_of_year": (lambda s: s.dt.dayofyear, lambda s: s.dt.ordinal_day()),
        "iso_week": (lambda s: s.dt.isocalendar().week, lambda s: s.dt.week()),
        "iso_year": (lambda s: s.dt.isocalendar().year, lambda s: s.dt.iso_year()),
        "quarter": (lambda s: s.dt.quarter, lambda s: s.dt.quarter()),
        "days_in_month": (lambda s: s.dt.days_in_month, lambda s: s.dt.days_in_month()),
        "is_leap_year": (lambda s: s.dt.is_leap_year, lambda s: s.dt.is_leap_year()),
        "is_month_start": (lambda s: s.dt.is_month_start, lambda s: s.dt.is_month_start()),
        "is_month_end": (lambda s: s.dt.is_month_end, lambda s: s.dt.is_month_end()),
        "is_quarter_start": (lambda s: s.dt.is_quarter_start, lambda s: s.dt.is_quarter_start()),
        "is_quarter_end": (lambda s: s.dt.is_quarter_end, lambda s: s.dt.is_quarter_end()),
        "is_year_start": (lambda s: s.dt.is_year_start, lambda s: s.dt.is_year_start()),
        "is_year_end": (lambda s: s.dt.is_year_end, lambda s: s.dt.is_year_end()),
        "is_business_day": (lambda s: s.dt.dayofweek < 5, lambda s: s.dt.is_business_day()),
        "month_name": (lambda s: s.dt.month_name(), lambda s: s.dt.to_string("%B")),
        "day_name": (lambda s: s.dt.day_name(), lambda s: s.dt.to_string("%A")),
        "epoch_days": (lambda s: s.astype("int64") // 86_400_000_000, lambda s: s.dt.epoch("d")),
        "epoch_seconds": (lambda s: s.astype("int64") // 1_000_000, lambda s: s.dt.epoch("s")),
        "epoch_ms": (lambda s: s.astype("int64") // 1_000, lambda s: s.dt.epoch("ms")),
        "epoch_us": (lambda s: s.astype("int64"), lambda s: s.dt.epoch("us")),
        "date": (lambda s: s.dt.strftime("%Y-%m-%d"), lambda s: s.dt.date().cast(pl.String)),
        "time": (lambda s: s.dt.time.astype(str), lambda s: s.dt.time().cast(pl.String)),
        "month_start": (lambda s: s - pd.to_timedelta(s.dt.day - 1, unit="D"), lambda s: s.dt.month_start()),
        "month_end": (lambda s: s + pd.to_timedelta(s.dt.days_in_month - s.dt.day, unit="D"), lambda s: s.dt.month_end()),
    }
    kinds = {"month_name": "text", "day_name": "text", "date": "text", "time": "text", "month_start": "ts", "month_end": "ts"}
    for name, (fp, fq) in D.items():
        ok = "bool" if name.startswith("is_") else kinds.get(name, "int")
        vals = TS + [None] if name in ("year", "month", "day", "weekday", "iso_week", "is_leap_year", "is_business_day", "month_name", "date") else TS
        scase(f"dt-{name}", "dt", "dt_part", {"part": name}, vals, "ts", ok, fp, fq)
    # strptime -------------------------------------------------------------------------
    P = [
        ("ymd", "%Y-%m-%d", ["2021-03-04", "2021-3-4", "2021-02-30", "2021-13-01", "  2021-03-04", "2021-03-04 ", "20210304", "", None, "2021-03-04T00:00", "0001-01-01", "9999-12-31", "2024-02-29", "2023-02-29", "1969-12-31"]),
        ("dmy", "%d/%m/%Y", ["04/03/2021", "4/3/2021", "31/12/1999", "31/04/2021", "29/02/2000", "29/02/1900"]),
        ("compact", "%Y%m%d", ["20210304", "2021034", "202103041", "19700101"]),
        ("dt", "%Y-%m-%d %H:%M:%S", ["2021-03-04 05:06:07", "2021-03-04 5:06:07", "2021-03-04 24:00:00", "2021-03-04 23:59:60", "2021-03-04 23:59:59", "2021-03-04 05:06:07.123", "2021-03-04T05:06:07"]),
        ("frac", "%Y-%m-%d %H:%M:%S.%f", ["2021-03-04 05:06:07.123456", "2021-03-04 05:06:07.1", "2021-03-04 05:06:07.123456789", "2021-03-04 05:06:07.000001", "2021-03-04 05:06:07"]),
        ("y2", "%y-%m-%d", ["21-03-04", "69-01-01", "68-12-31", "70-01-01", "00-01-01", "99-12-31"]),
        ("mon", "%b %d %Y", ["Mar 04 2021", "mar 04 2021", "MAR 04 2021", "March 04 2021", "Sep 1 2021", "Sept 01 2021"]),
        ("month", "%B %d, %Y", ["March 04, 2021", "march 4, 2021", "Mar 04, 2021", "May 31, 2021"]),
        ("wday", "%a %d %b %Y", ["Thu 04 Mar 2021", "Mon 04 Mar 2021", "thu 04 mar 2021"]),
        ("doy", "%j %Y", ["064 2021", "366 2020", "366 2021", "001 1970", "64 2021", "000 2021"]),
        ("ampm", "%Y-%m-%d %I:%M %p", ["2021-03-04 05:06 PM", "2021-03-04 12:00 AM", "2021-03-04 12:00 PM", "2021-03-04 5:06 pm", "2021-03-04 13:00 PM", "2021-03-04 00:30 AM"]),
        ("tz", "%Y-%m-%d %H:%M:%S%z", ["2021-03-04 05:06:07+0100", "2021-03-04 05:06:07-0530", "2021-03-04 05:06:07Z", "2021-03-04 05:06:07+01:00", "2021-03-04 05:06:07+01", "2021-03-04 05:06:07"]),
        ("tzc", "%Y-%m-%d %H:%M:%S%:z", ["2021-03-04 05:06:07+01:00", "2021-03-04 05:06:07-05:30", "2021-03-04 05:06:07+0100"]),
        ("FT", "%F %T", ["2021-03-04 05:06:07", "2021-03-04 5:06:07"]),
        ("mdy", "%m/%d/%y", ["03/04/21", "12/31/69", "01/01/70"]),
        ("hm", "%Y-%m-%d %H:%M", ["2021-03-04 05:06", "2021-03-04 05:06:07", "2021-03-04 5:6"]),
        ("dots", "%d.%m.%Y %H:%M", ["04.03.2021 05:06", "4.3.2021 5:06"]),
        ("isow", "%G-W%V-%u", ["2021-W09-4", "2020-W53-7", "2021-W53-1", "2021-W01-1"]),
        ("lit", "ts=%Y-%m-%d%%", ["ts=2021-03-04%", "ts=2021-03-04"]),
        ("text", "%Y-%m-%dT%H:%M:%S", ["2021-03-04T05:06:07", "2021-03-04 05:06:07"]),
    ]
    for tag, fmt, vals in P:
        def fp(s, fmt=fmt):
            r = pd.to_datetime(s, format=fmt, errors="coerce", utc=True)
            return r.dt.tz_localize(None)

        def fq(s, fmt=fmt):
            r = s.str.strptime(pl.Datetime("us"), fmt, strict=False)
            return r

        def fq_tz(s, fmt=fmt):
            r = s.str.strptime(pl.Datetime("us", "UTC"), fmt, strict=False)
            return r.dt.replace_time_zone(None)

        has_tz = "%z" in fmt or "%:z" in fmt
        scase(f"strptime-{tag}", "strptime", "strptime", {"fmt": fmt}, vals, "text", "ts", fp, fq_tz if has_tz else fq)
    # strftime -----------------------------------------------------------------------------
    FT_STR = ["2021-03-04 05:06:07.123456", "2020-12-31 23:59:59", "2021-01-03 00:00:00", "2000-02-29 12:00:00", "1999-01-01 00:30:00",
              "2021-01-01 13:45:59.5", "2005-01-02 07:08:09", "2021-07-04 00:00:00", "1970-01-01 00:00:00", "2008-12-29 12:34:56"]
    FT = [us(s) for s in FT_STR]
    sup = ["%Y-%m-%d %H:%M:%S", "%y", "%b %d", "%B", "%a", "%A", "%j", "%I:%M %p", "%f", "%u", "%V", "%G", "%%", "%F", "%T", "%R", "%D", "%h",
           "%Y%m%dT%H%M%S", "%z", "%Z", "%:z", "%H:%M:%S.%f", "%y%j", "%d/%m/%Y", "%I%p", "[%Y]"]
    unsup = ["%e", "%w", "%U", "%W", "%C", "%k", "%l", "%s", "%n", "%P", "%c", "%x", "%X", "%3f", "%.3f", "%.f", "%-d", "%_d"]
    for k, fmt in enumerate(sup + unsup):
        scase(f"strftime-{k}", "strftime", "strftime", {"fmt": fmt, "supported": fmt in sup}, FT, "ts", "text",
              lambda s, fmt=fmt: s.dt.tz_localize("UTC").dt.strftime(fmt), lambda s, fmt=fmt: s.dt.replace_time_zone("UTC").dt.strftime(fmt), gap=fmt in unsup)
    # offset_by / truncate ---------------------------------------------------------------
    def dur_kwargs(every):
        m = re.fullmatch(r"(-?)((?:\d+[a-z]+)+)", every)
        sign = -1 if m.group(1) else 1
        kw = {}
        for n, u in re.findall(r"(\d+)([a-z]+)", m.group(2)):
            n = int(n) * sign
            key = {"y": "years", "mo": "months", "q": "months", "w": "weeks", "d": "days", "h": "hours", "m": "minutes", "s": "seconds", "ms": "milliseconds"}[u]
            n = n * 3 if u == "q" else n
            kw[key] = kw.get(key, 0) + n
        return kw

    for every in ("1d", "-1d", "1h", "90m", "1w", "1mo", "-1mo", "3mo", "1q", "1y", "12mo", "1y2mo", "-1y", "2h30m", "-3d12h", "0d", "500ms"):
        scase(f"offset_by-{every}", "offset_by", "offset_by", {"every": every}, TS2, "ts", "ts",
              lambda s, every=every: s + pd.DateOffset(**dur_kwargs(every)), lambda s, every=every: s.dt.offset_by(every))

    def pd_floor(every):
        m = re.fullmatch(r"(\d+)(ms|s|m|h|d|w|mo|q|y)", every)
        n, u = int(m.group(1)), m.group(2)
        if u in ("ms", "s", "h", "d"):
            return lambda s: s.dt.floor({"ms": f"{n}ms", "s": f"{n}s", "h": f"{n}h", "d": f"{n}D"}[u])
        if u == "m":
            return lambda s: s.dt.floor(f"{n}min")
        if u == "w":
            return lambda s: s.dt.floor(f"{7 * n}D")
        if n == 1:
            per = {"mo": "M", "q": "Q", "y": "Y"}[u]
            return lambda s: s.dt.to_period(per).dt.start_time
        return None

    for every in ("1d", "1h", "15m", "30s", "500ms", "1w", "2w", "3w", "4w", "1mo", "3mo", "1q", "1y", "2d", "7d", "5h", "1h30m", "2y", "6mo"):
        f = None
        try:
            f = pd_floor(every)
        except Exception:
            f = None
        scase(f"truncate-{every}", "truncate", "truncate", {"every": every}, TS2, "ts", "ts", f, lambda s, every=every: s.dt.truncate(every))
    # business days ------------------------------------------------------------------------
    for n in (0, 1, -1, 4, 5, -5, 6, 10, -3, 260):
        scase(f"bday-{n}", "add_business_days", "add_business_days", {"n": n}, BDAY, "ts", "ts",
              lambda s, n=n: s.apply(lambda t: t + pd.offsets.BDay(n)), lambda s, n=n: s.dt.add_business_days(n, roll="forward"))
    string_cases()


TEXTS = ["hello world", "Hello World", "héllo wörld", "", "  padded  ", "a", "abc", "日本語テキスト", None, "-42", "+7", "0042",
         "12abc", "ABC123", "it's a dog's life", "MiXeD CaSe", "hello-world foo_bar", "\tTab\n", "tab\there", "x" * 12, "1,234", "-", "٣٤"]
TEXTS_UNI = ["straße", "ǆungla", "İstanbul", "ΑΣ", "ÀÉÎõü", "ß", "ﬁne", "\u00e9clair", "e\u0301clair"]


def string_cases():
    both = TEXTS
    # slice / head / tail / char_at / reverse ---------------------------------------------
    for off, ln in ((0, None), (1, None), (2, 3), (0, 0), (-3, None), (-3, 2), (-100, None), (100, 2), (1, 100), (3, 1)):
        def fp(s, off=off, ln=ln):
            # pandas has no length: stop = start + length, for a start from the left
            return s.str.slice(off, None if ln is None else off + ln)

        scase(f"str-slice-{off}-{ln}", "str", "slice", {"offset": off, "length": ln}, both, "text", "text",
              fp if (ln is None or off >= 0) else None, lambda s, off=off, ln=ln: s.str.slice(off, ln))
    for n in (0, 1, 3, 100, -1, -3):
        scase(f"str-head-{n}", "str", "head", {"n": n}, both, "text", "text", lambda s, n=n: s.str[:n], lambda s, n=n: s.str.head(n))
        scase(f"str-tail-{n}", "str", "tail", {"n": n}, both, "text", "text", (lambda s, n=n: s.str[-n:]) if n != 0 else None, lambda s, n=n: s.str.tail(n))
    for i in (0, 1, -1, 5, -5, 100):
        scase(f"str-char_at-{i}", "str", "char_at", {"i": i}, both, "text", "text", lambda s, i=i: s.str.get(i), lambda s, i=i: s.str.get(i, null_on_oob=True))
    scase("str-reverse", "str", "reverse", {}, both + ["e\u0301clair", "\u00e9clair"], "text", "text", lambda s: s.str[::-1], lambda s: s.str.reverse())
    # pad / zfill / repeat ---------------------------------------------------------------------
    for w in (0, 3, 8, 15):
        for fill in ("*", "é"):
            scase(f"str-pad-left-{w}-{ord(fill)}", "str", "pad", {"width": w, "side": "left", "fill": fill}, both, "text", "text",
                  lambda s, w=w, fill=fill: s.str.pad(w, "left", fill), lambda s, w=w, fill=fill: s.str.pad_start(w, fill))
            scase(f"str-pad-right-{w}-{ord(fill)}", "str", "pad", {"width": w, "side": "right", "fill": fill}, both, "text", "text",
                  lambda s, w=w, fill=fill: s.str.pad(w, "right", fill), lambda s, w=w, fill=fill: s.str.pad_end(w, fill))
            scase(f"str-pad-both-{w}-{ord(fill)}", "str", "pad", {"width": w, "side": "both", "fill": fill}, both, "text", "text",
                  lambda s, w=w, fill=fill: s.str.center(w, fill), None)
    for w in (0, 2, 5, 8):
        scase(f"str-zfill-{w}", "str", "zfill", {"width": w}, both, "text", "text", lambda s, w=w: s.str.zfill(w), lambda s, w=w: s.str.zfill(w))
    for n in (0, 1, 3):
        scase(f"str-repeat-{n}", "str", "repeat", {"n": n}, both, "text", "text", lambda s, n=n: s.str.repeat(n), lambda s, n=n: s.str.repeat(n))
    # strip -------------------------------------------------------------------------------------------
    for chars in (None, "xa ", "-+", "\t\n"):
        for side, pm, qm in (("both", "strip", "strip_chars"), ("start", "lstrip", "strip_chars_start"), ("end", "rstrip", "strip_chars_end")):
            scase(f"str-strip-{side}-{chars!r}", "str", "strip", {"chars": chars, "side": side}, both, "text", "text",
                  lambda s, pm=pm, chars=chars: getattr(s.str, pm)(chars), lambda s, qm=qm, chars=chars: getattr(s.str, qm)(chars))
    scase("str-translate", "str", "translate", {"from": "abc", "to": "xyz", "delete": "l"}, both, "text", "text",
          lambda s: s.str.translate(str.maketrans("abc", "xyz", "l")), None)
    scase("str-translate-del", "str", "translate", {"from": "", "to": "", "delete": "aeiou "}, both, "text", "text",
          lambda s: s.str.translate(str.maketrans("", "", "aeiou ")), None)
    # to_integer -----------------------------------------------------------------------------------------
    nums = ["12", "-12", "+12", " 12", "12 ", "ff", "FF", "0xff", "1_000", "", "12a", "99999999999999999999", "-9223372036854775808", "9223372036854775807",
            "9223372036854775808", "0", "-0", "007", "z", "1.5", "1e2", None, "101", "777"]
    for base in (10, 16, 2, 8, 36):
        scase(f"str-to_integer-{base}", "str", "to_integer", {"base": base}, nums, "text", "int", None, lambda s, base=base: s.str.to_integer(base=base, strict=False))
    # case -----------------------------------------------------------------------------------------------
    scase("str-capitalize", "str", "capitalize", {}, both, "text", "text", lambda s: s.str.capitalize(), None)
    scase("str-swapcase", "str", "swapcase", {}, both, "text", "text", lambda s: s.str.swapcase(), None)
    scase("str-title", "str", "title", {}, both, "text", "text", lambda s: s.str.title(), lambda s: s.str.to_titlecase())
    for fn in ("capitalize", "swapcase"):
        scase(f"str-uni-{fn}", "str_unicode", fn, {}, TEXTS_UNI, "text", "text", lambda s, fn=fn: getattr(s.str, fn)(), None)
    scase("str-uni-title", "str_unicode", "title", {}, TEXTS_UNI, "text", "text", lambda s: s.str.title(), lambda s: s.str.to_titlecase())
    for cls, m in (("alpha", "isalpha"), ("digit", "isdigit"), ("alnum", "isalnum"), ("space", "isspace"), ("lower", "islower"), ("upper", "isupper"), ("title", "istitle")):
        scase(f"str-is-{cls}", "str", "is_class", {"class": cls}, both + TEXTS_UNI + [" ", "  ", "ABC", "abc", "Abc Def", "Abc def", "1", "²"], "text", "bool",
              lambda s, m=m: getattr(s.str, m)(), None)
    # contains_any / replace_many / count_matches ---------------------------------------------------------
    pats = ["World", "dog", "é", "xyz"]
    for fold in (False, True):
        scase(f"str-contains_any-{fold}", "str", "contains_any", {"patterns": pats, "fold": fold}, both, "text", "bool", None,
              lambda s, fold=fold: s.str.contains_any(pats, ascii_case_insensitive=fold))
        scase(f"str-contains_any-empty-{fold}", "str", "contains_any", {"patterns": [], "fold": fold}, both, "text", "bool", None,
              lambda s, fold=fold: s.str.contains_any([], ascii_case_insensitive=fold))
    rep_sets = [(["b", "ab"], ["1", "2"]), (["ab", "b"], ["2", "1"]), (["bc", "abcd"], ["1", "2"]), (["abcd", "bc"], ["2", "1"]), (["c", "bc"], ["1", "2"]), (["bc", "c"], ["2", "1"]), (["o", "l"], ["0", "1"]), (["lo", "l", "o"], ["A", "B", "C"]), (["l", "lo"], ["B", "A"]), (["Hello", "hello"], ["X", "Y"]), (["é"], ["e"]), (["ab", "abc"], ["1", "2"])]
    for k, (pt, wt) in enumerate(rep_sets):
        for fold in (False, True):
            scase(f"str-replace_many-{k}-{fold}", "str", "replace_many", {"patterns": pt, "with": wt, "fold": fold}, both + ["abc", "abcd", "xabcdx", "bcbc", "abab"], "text", "text", None,
                  lambda s, pt=pt, wt=wt, fold=fold: s.str.replace_many(pt, wt, ascii_case_insensitive=fold))
    scase("str-replace_many-one", "str", "replace_many", {"patterns": ["o", "l"], "with": ["_"], "fold": False}, both, "text", "text", None,
          lambda s: s.str.replace_many(["o", "l"], ["_"]))
    for p in ("l", "ll", "o w", "aa", "é", "-"):
        scase(f"str-count_matches-{p}", "str", "count_matches", {"p": p}, both + ["aaaa", "aaa", "banana"], "text", "int",
              lambda s, p=p: s.str.count(re.escape(p)), lambda s, p=p: s.str.count_matches(p, literal=True))


# ── frames ──────────────────────────────────────────────────────────────────


def to_pd_df(t):
    d = {}
    for c, ty, vals in t:
        if ty == "text":
            d[c] = pd.Series(vals, dtype="str")
        elif ty == "float":
            d[c] = pd.Series([np.nan if v is None else v for v in vals], dtype="float64")
        elif ty == "int":
            d[c] = pd.Series(pd.array(vals, dtype="Int64")) if any(v is None for v in vals) else pd.Series(np.array(vals, dtype="int64"))
        elif ty == "bool":
            d[c] = pd.Series(pd.array(vals, dtype="boolean")) if any(v is None for v in vals) else pd.Series(np.array(vals, dtype=bool))
        elif ty == "timestamp":
            d[c] = mk_pd("ts", vals)
        else:
            raise ValueError(ty)
    return pd.DataFrame(d)


def to_pl_df(t):
    d = {}
    for c, ty, vals in t:
        d[c] = mk_pl({"timestamp": "ts"}.get(ty, ty), vals).alias(c)
    return pl.DataFrame(d)


def norm_pd(df):
    df = df.reset_index(drop=True)
    cols = [str(c) for c in df.columns]
    kinds = []
    data = []
    for j in range(len(cols)):
        s = df.iloc[:, j]
        if pd.api.types.is_datetime64_any_dtype(s.dtype):
            data.append([None if pd.isna(v) else ts_us(v) for v in s])
            kinds.append("int")
        else:
            data.append([cell(v) for v in s])
            k = getattr(s.dtype, "kind", "O")
            kinds.append({"i": "int", "u": "int", "f": "float", "b": "bool"}.get(k, "text"))
            if str(s.dtype) in ("Int64", "UInt32", "Int32", "UInt8"):
                kinds[-1] = "int"
            if str(s.dtype) == "boolean":
                kinds[-1] = "bool"
    return cols, [list(r) for r in zip(*data)] if data else [], kinds


def norm_pl(df):
    cols = list(df.columns)
    data = []
    kinds = []
    for c in cols:
        s = df[c]
        dt = s.dtype
        if isinstance(dt, pl.Datetime):
            data.append([cell(v) for v in s.dt.timestamp("us").to_list()])
            kinds.append("int")
            continue
        data.append([cell(v) for v in s.to_list()])
        kinds.append("int" if dt.is_integer() else "float" if dt.is_float() else "bool" if dt == pl.Boolean else "null" if dt == pl.Null else "text")
    return cols, [list(r) for r in zip(*data)] if data else [], kinds


def cell_key(v):
    if v is None:
        return (0, 0.0, "")
    if isinstance(v, bool):
        return (1, float(v), "")
    if isinstance(v, (int, float)):
        return (2, round(float(v), 9), "")
    return (3, 0.0, str(v))


def frames_same(p, q, order, positional=False):
    if len(p[1]) != len(q[1]):
        return False
    if positional:
        if len(p[0]) != len(q[0]):
            return False
        x, y = p[1], q[1]
    else:
        if sorted(p[0]) != sorted(q[0]):
            return False
        names = sorted(p[0])
        x = [[r[p[0].index(n)] for n in names] for r in p[1]]
        y = [[r[q[0].index(n)] for n in names] for r in q[1]]
    if order == "any":
        x = sorted(x, key=lambda r: [cell_key(v) for v in r])
        y = sorted(y, key=lambda r: [cell_key(v) for v in r])
    return all(near(u, v) for r, s in zip(x, y) for u, v in zip(r, s))


def tbl_json(t):
    n = len(t[0][2]) if t else 0
    return {"columns": [{"name": c, "type": ty} for c, ty, _ in t], "rows": [[enc(t[j][2][i]) for j in range(len(t))] for i in range(n)]}


def fcase(cid, group, verb, spec, table, fp=None, fq=None, right=None, order="exact", positional=False, errors_ok=False):
    """fp(pandas frame[, right]) / fq(polars frame[, right]) -> a frame."""
    p = q = None
    perr = qerr = None
    if fp:
        r, perr = attempt(lambda: norm_pd(fp(to_pd_df(table), to_pd_df(right)) if right else fp(to_pd_df(table))))
        p = r
    if fq:
        r, qerr = attempt(lambda: norm_pl(fq(to_pl_df(table), to_pl_df(right)) if right else fq(to_pl_df(table))))
        q = r
    # `full`: the verb's whole output is the engines' (the others add a column to the input, which
    # the engines' frames here leave out): then the width counts too.
    full = group in ("w2_describe", "w2_vc", "w2_quant", "w2_join", "w2_pivot", "w2_fillna", "dummies", "join_where", "merge_ordered", "transpose", "pivot_many", "group_by_dynamic", "aggregate_stats", "frame_arith", "top_k", "rle", "n_unique") and verb != "rle_id"
    e = {"id": cid, "group": group, "verb": verb, "spec": enc(spec), "table": tbl_json(table), "order": order, "positional": positional, "full": full}
    if right:
        e["right"] = tbl_json(right)
    if perr:
        e["pandas_error"] = perr
    if qerr:
        e["polars_error"] = qerr
    if errors_ok and fp and fq and (perr is None) != (qerr is None):
        # One engine refuses where the other answers: a disagreement about the error itself.
        bump(group, "both")
        lab = label_for(cid)
        if not lab:
            problems.append(f"UNLABELLED ERROR DISAGREEMENT {cid}\n   pandas {perr or p}\n   polars {qerr or q}")
            lab = ("UNLABELLED", "pandas")
        bump(group, "labelled")
        e["label"], e["engine"] = lab
        use = (p if lab[1] == "pandas" else q)
        if use is None:
            e["expect_error"] = True
    elif p is not None and q is not None:
        bump(group, "both")
        if frames_same(p, q, order, positional):
            bump(group, "agree")
            e["engine"] = "both"
            use = p
        else:
            lab = label_for(cid)
            if not lab:
                problems.append(f"UNLABELLED DISAGREEMENT {cid}\n   pandas {p}\n   polars {q}")
                lab = ("UNLABELLED", "pandas")
            bump(group, "labelled")
            e["label"], e["engine"] = lab
            use = p if lab[1] == "pandas" else q
            oth = q if lab[1] == "pandas" else p
            e["other"] = {"columns": oth[0], "rows": [[enc(v) for v in r] for r in oth[1]]}
    elif p is not None or q is not None:
        e["engine"] = "pandas" if p is not None else "polars"
        bump(group, e["engine"])
        use = p if p is not None else q
    else:
        bump(group, "none")
        e["engine"] = "none"
        use = None
        if errors_ok and fp and fq and perr and qerr:
            e["expect_error"] = True
    if use is not None:
        e["width"] = len(use[0])
        e["expect"] = {"columns": use[0], "rows": [[enc(v) for v in r] for r in use[1]]}
        e["ptypes"] = dict(zip(p[0], p[2])) if p is not None else None
        e["qtypes"] = dict(zip(q[0], q[2])) if q is not None else None
    frame_cases.append(e)


def rng_floats(r, n, nulls=0.3, scale=10.0, ndigits=3):
    return [None if r.random() < nulls else round(float(r.normal(0, scale)), ndigits) for _ in range(n)]


def frame_cases_all():
    fill_cases()
    qcut_cases()
    factorize_cases()
    interpolate_cases()
    dynamic_cases()
    pivot_many_cases()
    dummies_cases()
    join_cases()
    transpose_cases()
    peak_cases()
    agg_cases()
    more_cases()
    w2_cases()


def retype(types):
    """Our declared kind where an engine's frame is object-typed or float-promoted (the cells still match)."""
    e = frame_cases[-1]
    if e.get("ptypes") is not None:
        e["ptypes"].update(types)
    if e.get("qtypes") is not None:
        e["qtypes"].update(types)


def w2_cases():
    """Dataframe S2 wave W2: the everyday single-parameter options (describe, value_counts, cut/qcut,
    rank, quantile lists, join, sort, fillna, interpolate, pivot margins)."""
    # describe
    n_ = [1.0, None, 3.5, 2.0, None, 9.0, 4.0, 2.0]
    txt = ["a", "b", "a", None, "c", "b", "a", "c"]
    bl = [True, False, True, True, False, True, True, False]
    mm = [4, 5, 6, 8, 1, 2, 2, 7]
    tn = [("t", "text", txt), ("n", "float", n_)]
    tnmb = [("t", "text", txt), ("n", "float", n_), ("m", "int", mm), ("b", "bool", bl)]

    def desc(**kw):
        return lambda d: d.describe(**kw).reset_index().rename(columns={"index": "statistic"})

    for tag, pcts in (("p1", [0.1, 0.9]), ("p2", [0.05, 0.95, 0.33]), ("p3", [0.5]), ("p4", [0.0, 1.0])):
        fcase(f"w2-describe-{tag}", "w2_describe", "describe_with", {"cols": ["n", "m"], "percentiles": pcts}, tnmb, lambda d, pcts=pcts: d[["n", "m"]].describe(percentiles=pcts).reset_index().rename(columns={"index": "statistic"}))
    fcase("w2-describe-all-tn", "w2_describe", "describe_with", {"all": True}, tn, desc(include="all"))
    retype({"n": "float"})
    fcase("w2-describe-all-tnmb", "w2_describe", "describe_with", {"all": True, "percentiles": [0.2]}, tnmb, desc(include="all", percentiles=[0.2]))
    retype({"n": "float", "m": "float"})
    fcase("w2-describe-default-tn", "w2_describe", "describe_with", {}, tn, desc())
    fcase("w2-describe-exclude-number", "w2_describe", "describe_with", {"exclude": ["int", "float"]}, tnmb, desc(exclude="number"))
    fcase("w2-describe-include-bool", "w2_describe", "describe_with", {"include": ["bool"]}, tnmb, desc(include=[bool]))
    fcase("w2-describe-include-int-float", "w2_describe", "describe_with", {"include": ["int", "float"]}, tnmb, desc(include="number"))

    # value_counts
    vx = [("x", "float", [3.0, 1.0, 2.0, 2.0, None, 3.0, 3.0, None])]
    vt = [("x", "text", ["q", "p", "r", "r", None, "q", "q", "z"])]
    for tname, tab in (("f", vx), ("t", vt)):
        for tag, (nm, srt, asc, dn) in {"plain": (False, True, False, True), "norm": (True, True, False, True), "unsorted": (False, False, False, True), "asc": (False, True, True, True), "norm-keep": (True, True, False, False), "unsorted-keep": (False, False, False, False)}.items():
            def fp(d, nm=nm, srt=srt, asc=asc, dn=dn):
                o = d["x"].value_counts(normalize=nm, sort=srt, ascending=asc, dropna=dn).reset_index()
                o.columns = ["x", "count"]
                return o

            fcase(f"w2-vc-{tname}-{tag}", "w2_vc", "value_counts", {"cols": ["x"], "normalize": nm, "sort": srt, "ascending": asc, "keep_missing": not dn}, tab, fp)

    # cut / qcut
    cx = [("i", "int", list(range(8))), ("x", "float", [1.0, 2.0, 3.0, 4.0, 5.0, 10.0, None, 2.5])]

    def lab(s):
        return s.map(lambda v: None if pd.isna(v) else str(v))

    for tag, kw in (("b3", dict(bins=3)), ("b4p1", dict(bins=4, precision=1)), ("b3left", dict(bins=3, right=False)), ("b5p2", dict(bins=5, precision=2)),
                    ("edges", dict(bins=[0.0, 2.0, 5.0, 10.0])), ("edges-low", dict(bins=[1.0, 3.0, 10.0], include_lowest=True)), ("edges-left", dict(bins=[1.0, 3.0, 10.0, 11.0], right=False))):
        spec = {"col": "x", "out": "o", "interval_labels": True, "precision": kw.get("precision", 3), "right": kw.get("right", True), "lowest": kw.get("include_lowest", False)}
        if isinstance(kw["bins"], list):
            spec["edges"] = [float(v) for v in kw["bins"]]
        else:
            spec["bins"] = kw["bins"]
        fcase(f"w2-cut-{tag}", "w2_cut", "cut_w2", spec, cx, lambda d, kw=kw: pd.DataFrame({"i": d["i"], "o": lab(pd.cut(d["x"], **kw).astype("object"))}))
    for nb in (3, 4):
        fcase(f"w2-qcut-{nb}", "w2_cut", "qcut_w2", {"col": "x", "out": "o", "bins": nb, "interval_labels": True}, cx, lambda d, nb=nb: pd.DataFrame({"i": d["i"], "o": lab(pd.qcut(d["x"], nb).astype("object"))}))

    # rank
    rx = [("i", "int", list(range(7))), ("x", "float", [2.0, 1.0, None, 1.0, 3.0, None, 2.0])]
    for method in ("average", "min", "max", "first", "dense"):
        for na in ("keep", "top", "bottom"):
            for pct in (False, True):
                for desc_ in (False, True):
                    fcase(f"w2-rank-{method}-{na}-{pct}-{desc_}", "w2_rank", "rank_w2", {"method": method, "na": na, "pct": pct, "desc": desc_}, rx,
                          lambda d, method=method, na=na, pct=pct, desc_=desc_: pd.DataFrame({"i": d["i"], "r": d["x"].rank(method=method, na_option=na, pct=pct, ascending=not desc_)}))
                    if not pct and method != "average":
                        retype({"r": "int"})

    # quantile lists
    qn = [("n", "float", n_), ("m", "int", mm), ("k", "float", [5.0, 1.0, 7.0, 3.0, 2.0, 8.0, 6.0, 4.0])]
    for interp in ("linear", "lower", "higher", "midpoint", "nearest"):
        for qs in ([0.1, 0.5, 0.9], [0.0, 0.25, 0.333, 1.0]):
            fcase(f"w2-quant-{interp}-{len(qs)}", "w2_quant", "quantiles", {"qs": qs, "interpolation": interp}, qn,
                  lambda d, interp=interp, qs=qs: d.quantile(qs, interpolation=interp).reset_index().rename(columns={"index": "quantile"}))
            if interp in ("lower", "higher", "nearest"):
                retype({"m": "float"})  # pandas keeps the int column int here; the module's quantile is a float
    for qs in ([0.1, 0.3, 0.5, 0.75, 1.0], [0.0, 0.5]):
        fcase(f"w2-quant-equi-{len(qs)}", "w2_quant", "quantiles", {"cols": ["n"], "qs": qs, "interpolation": "equiprobable"}, qn, None,
              lambda d, qs=qs: pl.DataFrame({"quantile": qs, "n": [d["n"].quantile(q, interpolation="equiprobable") for q in qs]}))

    # join
    jl = [("k", "int", [1, 2, 3, 3, 5, 6]), ("a", "text", ["x", "y", "z", "w", "u", None]), ("v", "float", [1.0, 2.0, 3.0, 4.0, 5.0, 6.0])]
    jr = [("k", "int", [3, 4, 3, 5, 7]), ("b", "float", [10.0, 20.0, 30.0, 40.0, 50.0]), ("v", "float", [7.0, 8.0, 9.0, 0.5, 1.5])]
    ju = [("k", "int", [3, 4, 5, 7]), ("b", "float", [10.0, 20.0, 40.0, 50.0]), ("v", "float", [7.0, 8.0, 0.5, 1.5])]
    for how, pdhow in (("inner", "inner"), ("left", "left"), ("right", "right"), ("full", "outer")):
        spec = {"on": "k", "how": how, "suffix": "_y", "left_suffix": "_x", "indicator": "_merge", "coalesce": how in ("right", "full")}
        fcase(f"w2-join-ind-{how}", "w2_join", "join_w2", spec, jl, lambda l, r, pdhow=pdhow: l.merge(r, on="k", how=pdhow, indicator=True), right=jr, order="any")
        retype({"_merge": "text"})
    fcase("w2-join-sort-full", "w2_join", "join_w2", {"on": "k", "how": "full", "suffix": "_y", "left_suffix": "_x", "sort": True, "coalesce": True}, jl, lambda l, r: l.merge(r, on="k", how="outer", sort=True), right=jr, order="any")
    fcase("w2-join-sort-inner", "w2_join", "join_w2", {"on": "k", "how": "inner", "suffix": "_y", "left_suffix": "_x", "sort": True}, jl, lambda l, r: l.merge(r, on="k", how="inner", sort=True), right=jr, order="any")
    fcase("w2-join-suffix-left-only", "w2_join", "join_w2", {"on": "k", "how": "left", "left_suffix": "_l"}, jl, lambda l, r: l.merge(r, on="k", how="left", suffixes=("_l", None)), right=jr, order="any")
    fcase("w2-join-validate-m1", "w2_join", "join_w2", {"on": "k", "how": "left", "validate": "many_to_one", "suffix": "_y", "left_suffix": "_x"}, jl, lambda l, r: l.merge(r, on="k", how="left", validate="m:1"), right=ju, order="any")
    fcase("w2-join-validate-mm", "w2_join", "join_w2", {"on": "k", "how": "inner", "validate": "many_to_many", "suffix": "_y", "left_suffix": "_x"}, jl, lambda l, r: l.merge(r, on="k", how="inner", validate="m:m"), right=jr, order="any")
    fcase("w2-join-common", "w2_join", "join_w2", {"how": "inner"}, [("k", "int", [1, 2, 3]), ("a", "float", [1.0, 2.0, 3.0])], lambda l, r: l.merge(r, how="inner"), right=[("k", "int", [3, 1]), ("b", "float", [30.0, 10.0])], order="any")
    for how in ("left", "full"):
        fcase(f"w2-join-keepkeys-{how}", "w2_join", "join_w2", {"on": "k", "how": how, "keep_right_keys": True}, jl, None,
              lambda l, r, how=how: l.join(r, on="k", how=how, coalesce=False), right=jr, order="any")

    # sort with a placement of missing cells per key (polars nulls_last is a list)
    sx = [("i", "int", list(range(8))), ("a", "float", [1.0, None, 2.0, 1.0, None, 2.0, None, 1.0]), ("b", "float", [5.0, 3.0, None, 2.0, None, 1.0, 4.0, None])]
    for fa, fb, da, db in ((False, True, False, False), (True, False, False, True), (True, True, True, False), (False, False, True, True)):
        spec = {"key": "a", "dir": "desc" if da else "asc", "missing": "last" if fa else "first", "then_by": [{"key": "b", "dir": "desc" if db else "asc", "missing": "last" if fb else "first"}]}
        fcase(f"w2-sort-{fa}-{fb}-{da}-{db}", "w2_sort", "sort_w2", spec, sx, None,
              lambda d, fa=fa, fb=fb, da=da, db=db: d.sort(["a", "b"], descending=[da, db], nulls_last=[fa, fb], maintain_order=True))

    # fillna
    fx = [("a", "float", [1.0, None, None, 4.0, None]), ("b", "float", [None, 2.0, None, None, 5.0]), ("c", "float", [None, None, 3.0, None, None])]
    fcase("w2-fillna-dict", "w2_fillna", "fillna_w2", {"per_column": [{"col": "a", "value": 0.5}, {"col": "c", "value": -1.0}]}, fx, lambda d: d.fillna({"a": 0.5, "c": -1.0}))
    for lim in (1, 2):
        fcase(f"w2-fillna-limit{lim}", "w2_fillna", "fillna_w2", {"value": 9.0, "limit": lim}, fx, lambda d, lim=lim: d.fillna(9.0, limit=lim))
        fcase(f"w2-fillna-dict-limit{lim}", "w2_fillna", "fillna_w2", {"per_column": [{"col": "b", "value": 7.0}], "limit": lim}, fx, lambda d, lim=lim: d.fillna({"b": 7.0}, limit=lim))
    for how in ("forward", "backward"):
        for lim in (None, 1):
            fcase(f"w2-fillnull-across-{how}-{lim}", "w2_fillna", "fill_null_across", {"strategy": how, "limit": lim}, fx,
                  lambda d, how=how, lim=lim: d.ffill(axis=1, limit=lim) if how == "forward" else d.bfill(axis=1, limit=lim))

    # interpolate limit_*
    ix = [("i", "int", list(range(11))), ("x", "float", [None, None, 1.0, None, None, None, 5.0, None, None, 8.0, None])]
    for dr in ("forward", "backward", "both"):
        for area in (None, "inside", "outside"):
            for lim in (None, 1, 2):
                fcase(f"w2-interp-{dr}-{area}-{lim}", "w2_interp", "interpolate", {"col": "x", "method": "linear", "limit": lim, "limit_direction": dr, "limit_area": area}, ix,
                      lambda d, dr=dr, area=area, lim=lim: pd.DataFrame({"i": d["i"], "x": d["x"].interpolate(method="linear", limit=lim, limit_direction=dr, limit_area=area)}))

    # pivot_table margins
    px = [("r", "text", ["a", "a", "b", "b", "c", "a", "c"]), ("c", "text", ["x", "y", "x", "y", "x", "x", "x"]), ("v", "float", [1.0, 2.0, 3.0, None, 5.0, 6.0, 7.5]), ("w", "float", [5.0, 6.0, 7.0, 8.0, 9.0, 1.0, 2.0])]
    for agg in ("sum", "mean", "max", "min"):
        for name in ("All", "Tot"):
            fcase(f"w2-pivot-margins-{agg}-{name}", "w2_pivot", "pivot_w2", {"row_key": "r", "col_key": "c", "value_col": "v", "agg": agg, "skip_na": True, "margins": True, "margins_name": name}, px,
                  lambda d, agg=agg, name=name: d.pivot_table(index="r", columns="c", values="v", aggfunc=agg, margins=True, margins_name=name).reset_index().rename_axis(columns=None))
    for fv in (0, -1.5):
        fcase(f"w2-pivot-fill-{fv}", "w2_pivot", "pivot_w2", {"row_key": "r", "col_key": "c", "value_col": "v", "agg": "sum", "skip_na": True, "fill_value": fv}, px,
              lambda d, fv=fv: d.pivot_table(index="r", columns="c", values="v", aggfunc="sum", fill_value=fv).reset_index().rename_axis(columns=None))
    fcase("w2-pivot-many-aggs", "w2_pivot", "pivot_many_w2", {"row_key": "r", "col_key": "c", "values": ["v", "w"], "aggs": ["sum", "max"], "skip_na": True}, px,
          lambda d: d.pivot_table(index="r", columns="c", values=["v", "w"], aggfunc={"v": "sum", "w": "max"}).pipe(lambda o: o.set_axis([f"{a}_{b}" for a, b in o.columns], axis=1)).reset_index())


IDX = ("i", "int", list(range(10)))


def fill_cases():
    cols = {
        "ai": ("int", [1, None, None, 4, None, 6, None, None, None, 10]),
        "af": ("float", [None, 1.5, None, None, 4.0, None, 6.5, None, None, None]),
        "an": ("float", [2.0, NAN, 3.0, None, NAN, 5.0, NAN, None, 1.0, NAN]),
        "at": ("text", [None, "a", None, None, "b", None, None, "c", None, None]),
        "ab": ("bool", [None, True, None, False, None, None, True, None, None, None]),
        "aj": ("int", [3, None, 3, 4, None, 4, 4, None, None, None]),
    }
    for c, (ty, vals) in cols.items():
        t = [IDX, (c, ty, vals)]
        for st in ("forward", "backward", "mean", "min", "max", "zero", "one"):
            for lim in ((None, 1, 2) if st in ("forward", "backward") else (None,)):
                def fp(d, c=c, st=st, lim=lim):
                    s = d[c]
                    if st == "forward":
                        r = s.ffill(limit=lim)
                    elif st == "backward":
                        r = s.bfill(limit=lim)
                    elif st == "mean":
                        r = s.fillna(s.mean())
                    elif st == "min":
                        r = s.fillna(s.min())
                    elif st == "max":
                        r = s.fillna(s.max())
                    elif st == "zero":
                        r = s.fillna(0)
                    else:
                        r = s.fillna(1)
                    return pd.DataFrame({"i": d["i"], c: r})

                def fq(d, c=c, st=st, lim=lim):
                    kw = {"limit": lim} if lim else {}
                    return d.select("i", pl.col(c).fill_null(strategy=st, **kw))

                # pandas fills a text or bool column with a number it then refuses (or warns about)
                fcase(f"fill-{c}-{st}-{lim}", "fill_null", "fill_null", {"subset": [c], "strategy": st, "limit": lim}, t,
                      None if (st in ("zero", "one", "mean") and ty in ("text", "bool")) else fp, fq)


def qcut_cases():
    r = np.random.default_rng(5)
    tables = {
        "ties": [("i", "int", list(range(20))), ("x", "int", [1, 1, 1, 1, 2, 2, 3, 3, 3, 3, 3, 4, 5, 5, 6, 7, 8, 9, 10, 10])],
        "rnd": [("i", "int", list(range(20))), ("x", "float", rng_floats(r, 20, 0.15))],
        "small": [("i", "int", list(range(5))), ("x", "float", [3.5, 1.0, 2.0, 5.0, 4.0])],
        "const": [("i", "int", list(range(6))), ("x", "float", [2.0] * 6)],
    }
    for tag, t in tables.items():
        xs = [v for v in t[1][2] if v is not None]
        for kind, arg in (("bins", 2), ("bins", 3), ("bins", 4), ("bins", 5), ("bins", 10), ("probs", [0, 0.1, 0.5, 0.9, 1]), ("probs", [0, 0.5, 1]), ("probs", [0.25, 0.75])):
            probs = arg if kind == "probs" else [k / arg for k in range(arg + 1)]
            if probs[0] != 0 or probs[-1] != 1:
                # An open-ended list needs the engines' own handling; ours takes edges at the quantiles given.
                pass
            edges = np.unique(np.quantile(xs, probs))
            nb_raise = len(probs) - 1
            nb_drop = max(len(edges) - 1, 0)
            for dup in ("raise", "drop"):
                nb = nb_raise if dup == "raise" else nb_drop
                if nb < 1 or (kind == "probs" and (probs[0] != 0 or probs[-1] != 1)):
                    continue
                labels = [f"b{k}" for k in range(nb)]
                q_arg = arg

                def fp(d, q_arg=q_arg, labels=labels, dup=dup):
                    return pd.DataFrame({"i": d["i"], "o": pd.qcut(d["x"], q_arg, labels=labels, duplicates=dup).astype("object").where(d["x"].notna(), None)})

                def fq(d, q_arg=q_arg, labels=labels, dup=dup, xs=xs):
                    qs = [k / q_arg for k in range(q_arg + 1)][1:-1] if isinstance(q_arg, int) else q_arg[1:-1]
                    # polars counts the bins from the distinct interior breaks
                    nl = len(np.unique(np.quantile(xs, qs))) + 1 if dup == "drop" else len(labels)
                    return d.select("i", pl.col("x").qcut(qs, labels=[f"b{k}" for k in range(nl)], allow_duplicates=(dup == "drop")).cast(pl.String).alias("o"))

                spec = {"col": "x", "out": "o", "labels": labels, "duplicates": dup}
                spec["bins" if kind == "bins" else "probs"] = arg
                fcase(f"qcut-{tag}-{kind}-{arg}-{dup}", "qcut", "qcut", spec, t, fp, None if dup == "drop" else fq, errors_ok=True)


def factorize_cases():
    ts = {
        "txt": [("i", "int", list(range(8))), ("k", "text", ["b", "a", None, "b", "c", "a", None, "d"])],
        "int": [("i", "int", list(range(8))), ("k", "int", [3, 1, 2, 3, 1, 5, 2, 9])],
        "flt": [("i", "int", list(range(8))), ("k", "float", [3.5, 1.0, None, 3.5, 1.0, NAN, 2.0, None])],
    }
    for tag, t in ts.items():
        for srt in (False, True):
            def fp(d, srt=srt):
                codes, _ = pd.factorize(d["k"], sort=srt, use_na_sentinel=True)
                return pd.DataFrame({"i": d["i"], "code": codes})

            fcase(f"factorize-{tag}-sort{srt}-minus", "factorize", "factorize", {"cols": ["k"], "out": "code", "sort": srt, "missing": "minus_one"}, t, fp, None)
        # polars: the dense rank less one is the sorted code (null stays null)
        fcase(f"factorize-{tag}-sortTrue-null", "factorize", "factorize", {"cols": ["k"], "out": "code", "sort": True, "missing": "null"}, t, None,
              lambda d: d.select("i", (pl.col("k").fill_nan(None).rank("dense") - 1 if tag == "flt" else pl.col("k").rank("dense") - 1).cast(pl.Int64).alias("code")))


def interpolate_cases():
    r = np.random.default_rng(9)
    t0 = [("i", "int", list(range(8))), ("x", "float", [None, 1.0, None, None, 4.0, None, 10.0, None]), ("t", "int", [0, 1, 3, 4, 8, 9, 10, 15])]
    ts = {"hand": t0}
    for sd in (1, 2, 3):
        rr = np.random.default_rng(sd)
        ts[f"rnd{sd}"] = [("i", "int", list(range(16))), ("x", "float", rng_floats(rr, 16, 0.4, 5.0)), ("t", "int", [int(v) for v in np.cumsum(rr.integers(1, 6, 16))])]
    ts["nomid"] = [("i", "int", list(range(5))), ("x", "float", [None, None, 3.0, None, None]), ("t", "int", [0, 2, 4, 6, 8])]
    ts["alln"] = [("i", "int", list(range(4))), ("x", "float", [None, None, None, None]), ("t", "int", [0, 1, 2, 3])]
    for tag, t in ts.items():
        fcase(f"interpolate-{tag}-linear", "interpolate", "interpolate", {"col": "x", "method": "linear"}, t,
              lambda d: pd.DataFrame({"i": d["i"], "x": d["x"].interpolate(method="linear")}),
              lambda d: d.select("i", pl.col("x").interpolate()))
        fcase(f"interpolate-{tag}-by", "interpolate", "interpolate", {"col": "x", "method": "linear", "by": "t"}, t,
              lambda d: pd.DataFrame({"i": d["i"], "x": d.set_index("t")["x"].interpolate(method="index").to_numpy()}),
              lambda d: d.select("i", pl.col("x").interpolate_by("t")))
        fcase(f"interpolate-{tag}-nearest", "interpolate", "interpolate", {"col": "x", "method": "nearest"}, t,
              lambda d: pd.DataFrame({"i": d["i"], "x": d["x"].interpolate(method="nearest")}), None)
        fcase(f"interpolate-{tag}-nearest-by", "interpolate", "interpolate", {"col": "x", "method": "nearest", "by": "t"}, t,
              lambda d: pd.DataFrame({"i": d["i"], "x": d.set_index("t")["x"].interpolate(method="nearest").to_numpy()}), None)


def dynamic_cases():
    for sd in (1, 2):
        r = np.random.default_rng(sd)
        n = 30
        ts = sorted(int(v) for v in r.integers(us("2021-01-04"), us("2021-03-20"), n))
        t = [("t", "timestamp", ts), ("k", "text", [["a", "b"][i] for i in r.integers(0, 2, n)]), ("v", "float", rng_floats(r, n, 0.2))]
        aggs = [{"src": "v", "func": f, "out": o} for f, o in (("sum", "s"), ("mean", "m"), ("count", "c"), ("min", "lo"), ("max", "hi"))]

        def agg_pd(g):
            return g["v"].agg(["sum", "mean", "count", "min", "max"]).rename(columns={"sum": "s", "mean": "m", "count": "c", "min": "lo", "max": "hi"})

        for every, rule in (("1h", "1h"), ("6h", "6h"), ("1d", "1D"), ("30m", "30min"), ("1w", "W-MON"), ("1mo", "MS"), ("12h", "12h")):
            def fp(d, rule=rule):
                kw = dict(closed="left", label="left") if rule == "W-MON" else {}
                g = d.set_index("t").resample(rule, **kw)
                out = agg_pd(g)
                n = g["v"].size()
                out = out[n > 0]
                out.index.name = "t"
                return out.reset_index()

            def fq(d, every=every):
                return d.sort("t").group_by_dynamic("t", every=every, closed="left", label="left").agg(
                    pl.col("v").sum().alias("s"), pl.col("v").mean().alias("m"), pl.col("v").count().alias("c"), pl.col("v").min().alias("lo"), pl.col("v").max().alias("hi"))

            fcase(f"dynamic-s{sd}-{every}", "group_by_dynamic", "group_by_dynamic", {"index": "t", "every": every, "by": [], "aggs": aggs}, t, fp, fq)

            def fp2(d, rule=rule):
                kw = dict(closed="left", label="left") if rule == "W-MON" else {}
                parts = []
                for key, sub in d.groupby("k"):
                    g = sub.set_index("t").resample(rule, **kw)
                    out = agg_pd(g)
                    out = out[g["v"].size() > 0]
                    out.index.name = "t"
                    out = out.reset_index()
                    out.insert(0, "k", key)
                    parts.append(out)
                return pd.concat(parts)

            def fq2(d, every=every):
                return d.sort("k", "t").group_by_dynamic("t", every=every, group_by="k", closed="left", label="left").agg(
                    pl.col("v").sum().alias("s"), pl.col("v").mean().alias("m"), pl.col("v").count().alias("c"), pl.col("v").min().alias("lo"), pl.col("v").max().alias("hi"))

            fcase(f"dynamic-s{sd}-{every}-by", "group_by_dynamic", "group_by_dynamic", {"index": "t", "every": every, "by": ["k"], "aggs": aggs}, t, fp2, fq2, order="any")


def pivot_many_cases():
    t = [("r", "text", ["a", "a", "b", "b", "b", "c", "a", "c", "c", "b"]), ("c", "text", ["x", "y", "x", "x", "y", "y", "x", "x", "x", "y"]),
         ("v1", "float", [1.0, 2.0, 3.0, 4.0, None, 6.0, 7.0, 8.0, 9.0, 10.0]), ("v2", "int", [10, 20, 30, 40, 50, 60, 70, 80, 90, 100])]
    for agg in ("sum", "mean", "count", "min", "max", "first", "last", "median"):
        def fp(d, agg=agg):
            f = {"first": "first", "last": "last"}.get(agg, agg)
            p = d.pivot_table(index="r", columns="c", values=["v1", "v2"], aggfunc=f, dropna=True)
            p.columns = [f"{a}_{b}" for a, b in p.columns]
            return p.reset_index()

        def fq(d, agg=agg):
            d = d.drop_nulls(["r", "c"])
            return d.pivot(on="c", index="r", values=["v1", "v2"], aggregate_function=getattr(pl.element(), agg)())

        fcase(f"pivot_many-{agg}", "pivot_many", "pivot_many", {"row_key": "r", "col_key": "c", "values": ["v1", "v2"], "agg": agg, "skip_na": True}, t, fp, fq, order="any")


def dummies_cases():
    t = [("i", "int", list(range(6))), ("a", "text", ["x", "y", None, "x", "z", "y"]), ("b", "text", ["p", "p", "q", None, "q", "p"]), ("n", "float", [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]), ("f", "bool", [True, False, True, True, False, None])]
    for cols in (["a"], ["a", "b"], []):
        for drop_first in (False, True):
            for dna in (False, True):
                use = cols or ["a", "b"]

                def fp(d, use=use, drop_first=drop_first, dna=dna):
                    return pd.get_dummies(d, columns=use, dtype=int, prefix_sep="_", drop_first=drop_first, dummy_na=dna)

                def fq(d, use=use, drop_first=drop_first):
                    return d.to_dummies(columns=use, separator="_", drop_first=drop_first)

                fcase(f"dummies-{'+'.join(cols) or 'default'}-df{drop_first}-na{dna}", "dummies", "dummies",
                      {"cols": cols if cols else ["a", "b"], "separator": "_", "drop_first": drop_first, "dummy_na": dna}, [x for x in t if x[0] != "f"], fp, fq)


def join_cases():
    r = np.random.default_rng(3)
    L = [("i", "int", list(range(10))), ("t", "float", [1.0, 2.0, 3.0, None, 5.0, 6.0, 7.0, 8.0, 2.0, 9.0]), ("v", "int", [10 * k for k in range(10)])]
    R = [("lo", "float", [1.0, 4.0, 6.0, 2.0, None]), ("hi", "float", [3.0, 6.0, 9.0, 2.0, 5.0]), ("name", "text", ["p", "q", "r", "s", "u"]), ("v", "int", [1, 2, 3, 4, 5])]
    ops = {"lt": "<", "le": "<=", "gt": ">", "ge": ">=", "eq": "==", "ne": "!="}
    cases = {
        "between": [("t", "ge", "lo"), ("t", "le", "hi")],
        "open": [("t", "gt", "lo"), ("t", "lt", "hi")],
        "lt": [("t", "lt", "lo")],
        "ge": [("t", "ge", "hi")],
        "eq": [("t", "eq", "lo")],
        "ne": [("t", "ne", "lo")],
    }
    for tag, preds in cases.items():
        def fp(l, rr, preds=preds):
            m = l.merge(rr, how="cross", suffixes=("", "_right"))
            keep = np.ones(len(m), dtype=bool)
            for a, op, b in preds:
                x, y = m[a], m[b]
                keep &= {"lt": x < y, "le": x <= y, "gt": x > y, "ge": x >= y, "eq": x == y, "ne": x != y}[op].to_numpy() & x.notna().to_numpy() & y.notna().to_numpy()
            return m[keep]

        def fq(l, rr, preds=preds):
            exprs = []
            for a, op, b in preds:
                x, y = pl.col(a), pl.col(b)
                exprs.append({"lt": x < y, "le": x <= y, "gt": x > y, "ge": x >= y, "eq": x == y, "ne": x != y}[op])
            return l.join_where(rr, *exprs, suffix="_right")

        fcase(f"join_where-{tag}", "join_where", "join_where", {"preds": [list(p) for p in preds], "suffix": "_right"}, L, fp, fq, right=R, order="any")
    # merge_ordered
    A = [("k", "int", [1, 3, 5, 7, 9]), ("a", "float", [1.0, None, 5.0, 7.0, 9.5])]
    B = [("k", "int", [2, 3, 4, 7, 8]), ("b", "text", ["x", "y", None, "w", "v"])]
    C = [("k", "int", [3, 5, 5, 11]), ("a", "float", [30.0, 50.0, 51.0, 110.0])]
    for tag, l, rr in (("plain", A, B), ("dupkey", A, C), ("same_name", A, [("k", "int", [1, 2, 7]), ("a", "float", [0.5, 0.25, 70.0])])):
        for ff in (False, True):
            def fp(d, e, ff=ff):
                return pd.merge_ordered(d, e, on="k", fill_method="ffill" if ff else None, suffixes=("", "_y"))

            def fq(d, e):
                return d.join(e, on="k", how="full", coalesce=True, suffix="_y").sort("k")

            fcase(f"merge_ordered-{tag}-ff{ff}", "merge_ordered", "merge_ordered", {"on": ["k"], "fill_forward": ff, "suffix": "_y"}, l, fp, None if ff else fq, right=rr)


def transpose_cases():
    ts = {
        "float": [("a", "float", [1.0, 2.5, None]), ("b", "float", [4.0, None, 6.0])],
        "intfloat": [("a", "int", [1, 2, 3]), ("b", "float", [0.5, 1.5, 2.5])],
        "int": [("a", "int", [1, 2, 3]), ("b", "int", [4, 5, 6]), ("c", "int", [7, 8, 9])],
        "mixed": [("a", "int", [1, 2]), ("b", "text", ["x", "y"])],
        "text": [("a", "text", ["p", None]), ("b", "text", ["q", "r"])],
        "bool": [("a", "bool", [True, False]), ("b", "bool", [False, False])],
        "boolint": [("a", "bool", [True, False]), ("b", "int", [3, 4])],
    }
    for tag, t in ts.items():
        def fp(d):
            o = d.T.reset_index(drop=True)
            o.columns = [f"column_{k}" for k in range(o.shape[1])]
            return o

        fcase(f"transpose-{tag}", "transpose", "transpose", {}, t, fp, lambda d: d.transpose(include_header=False), positional=True)
        names = [c for c, _, _ in t]

        def fp2(d, names=names):
            o = d.T.reset_index(drop=True)
            o.columns = [f"column_{k}" for k in range(o.shape[1])]
            o.insert(0, "column", names)
            return o

        fcase(f"transpose-{tag}-header", "transpose", "transpose", {"header_name": "column"}, t, fp2, lambda d: d.transpose(include_header=True, header_name="column"), positional=True)
    t = [("id", "text", ["r0", "r1", "r2"]), ("a", "float", [1.0, 2.0, 3.0]), ("b", "float", [4.0, 5.0, 6.0])]
    fcase("transpose-names_from", "transpose", "transpose", {"names_from": "id"}, t,
          lambda d: d.set_index("id").T.reset_index(drop=True), lambda d: d.transpose(include_header=False, column_names="id"), positional=True)


def peak_cases():
    lists = {
        "asc": [1.0, 2.0, 3.0, 4.0, 5.0], "desc": [5.0, 4.0, 3.0, 2.0, 1.0], "flat": [1.0, 1.0, 1.0], "plateau": [1.0, 3.0, 3.0, 2.0],
        "zigzag": [1.0, 3.0, 2.0, 4.0, 1.0, 5.0], "one": [1.0], "two": [1.0, 2.0], "two_eq": [2.0, 2.0], "null_mid": [1.0, None, 3.0, 2.0],
        "null_end": [None, 3.0, 2.0, 5.0], "nan": [1.0, NAN, 3.0, 2.0, 4.0], "neg": [-1.0, -3.0, -2.0, -5.0, -4.0], "inf": [1.0, INF, 2.0, -INF, 0.0],
    }
    for tag, v in lists.items():
        t = [("i", "int", list(range(len(v)))), ("x", "float", v)]
        for which, m in (("max", "peak_max"), ("min", "peak_min")):
            fcase(f"peaks-{tag}-{which}", "peaks", "peaks", {"col": "x", "which": which, "out": "o"}, t, None,
                  lambda d, m=m: d.select("i", getattr(pl.col("x"), m)().alias("o")))
    t = [("i", "int", list(range(7))), ("x", "int", [1, 5, 2, 2, 7, 3, 3])]
    for which, m in (("max", "peak_max"), ("min", "peak_min")):
        fcase(f"peaks-int-{which}", "peaks", "peaks", {"col": "x", "which": which, "out": "o"}, t, None, lambda d, m=m: d.select("i", getattr(pl.col("x"), m)().alias("o")))


def agg_cases():
    r = np.random.default_rng(21)
    g = ["a"] * 1 + ["b"] * 2 + ["c"] * 3 + ["d"] * 4 + ["e"] * 5 + ["f"] * 4 + ["h"] * 6 + ["k"] * 3
    n = len(g)
    x = [5.0] + [1.0, 3.0] + [2.0, 4.0, 9.0] + [1.0, 2.0, 4.0, 8.0] + [3.5, None, 1.5, 7.0, 2.0] + [2.0, 2.0, 2.0, 2.0] + rng_floats(r, 6, 0.2, 5.0, 2) + [None, None, 1.0]
    t = [("g", "text", g), ("x", "float", x)]
    gs = lambda d: d.groupby("g", sort=False)["x"]
    for func, pdf, plf in (("std", lambda s, dd: s.std(ddof=dd), lambda c, dd: c.std(ddof=dd)), ("var", lambda s, dd: s.var(ddof=dd), lambda c, dd: c.var(ddof=dd)),
                           ("sem", lambda s, dd: s.sem(ddof=dd), None)):
        for dd in (0, 1, 2, 3):
            aggs = [{"src": "x", "func": func, "out": "o", "ddof": dd}]
            fcase(f"agg-{func}-ddof{dd}", "aggregate_stats", "aggregate", {"by": ["g"], "aggs": aggs, "skip_na": True}, t,
                  lambda d, pdf=pdf, dd=dd: pdf(gs(d), dd).rename("o").reset_index(),
                  (lambda d, plf=plf, dd=dd: d.group_by("g", maintain_order=True).agg(plf(pl.col("x"), dd).alias("o"))) if plf else None)
    for func, pdf, plf in (("skew", lambda s: s.skew(), lambda c: c.drop_nulls().skew(bias=False)), ("kurt", lambda s: s.apply(lambda v: v.kurt()), lambda c: c.drop_nulls().kurtosis(bias=False))):
        fcase(f"agg-{func}-small", "aggregate_stats", "aggregate", {"by": ["g"], "aggs": [{"src": "x", "func": func, "out": "o"}], "skip_na": True}, t,
              lambda d, pdf=pdf: pdf(gs(d)).rename("o").reset_index(), lambda d, plf=plf: d.group_by("g", maintain_order=True).agg(plf(pl.col("x")).alias("o")))
    for interp in ("linear", "lower", "higher", "midpoint", "nearest"):
        for q in (0.0, 0.1, 0.25, 0.4, 0.5, 0.75, 0.9, 1.0):
            aggs = [{"src": "x", "func": "quantile", "out": "o", "q": q, "interp": interp}]
            fcase(f"agg-quantile-{interp}-{q}", "aggregate_stats", "aggregate", {"by": ["g"], "aggs": aggs, "skip_na": True}, t,
                  lambda d, q=q, interp=interp: gs(d).quantile(q, interpolation=interp).rename("o").reset_index(),
                  lambda d, q=q, interp=interp: d.group_by("g", maintain_order=True).agg(pl.col("x").quantile(q, interpolation=interp).alias("o")))


def hz_polars(func, plf, sk):
    """polars' min/max_horizontal always skip nulls; sum/mean have ignore_nulls."""
    if func in ("min", "max"):
        return (lambda d: d.select("i", getattr(pl, plf)("a", "b", "c").alias("o"))) if sk else None
    return lambda d: d.select("i", getattr(pl, plf)("a", "b", "c", ignore_nulls=sk).alias("o"))


def more_cases():
    """The rest of the new verbs, with the engines' counterparts where they have them."""
    r = np.random.default_rng(31)
    h = [("i", "int", list(range(6))), ("a", "float", [1.0, None, 3.0, 4.0, None, 6.0]), ("b", "float", [10.0, 20.0, None, 40.0, None, 60.0]), ("c", "int", [1, 2, 3, 4, 5, 6]),
         ("p", "bool", [True, None, False, True, False, None]), ("q", "bool", [True, True, None, False, None, False])]
    for func, plf, pdf in (("sum", "sum_horizontal", lambda d, sk: d[["a", "b", "c"]].sum(axis=1, skipna=sk)), ("min", "min_horizontal", lambda d, sk: d[["a", "b", "c"]].min(axis=1, skipna=sk)),
                           ("max", "max_horizontal", lambda d, sk: d[["a", "b", "c"]].max(axis=1, skipna=sk)), ("mean", "mean_horizontal", lambda d, sk: d[["a", "b", "c"]].mean(axis=1, skipna=sk))):
        for sk in (True, False):
            fcase(f"horizontal-{func}-skip{sk}", "horizontal", "horizontal", {"cols": ["a", "b", "c"], "func": func, "out": "o", "skip_na": sk}, h,
                  lambda d, pdf=pdf, sk=sk: pd.DataFrame({"i": d["i"], "o": pdf(d, sk)}),
                  hz_polars(func, plf, sk))
    for func, plf in (("all", "all_horizontal"), ("any", "any_horizontal")):
        for sk in (True, False):
            fcase(f"horizontal-{func}-skip{sk}", "horizontal", "horizontal", {"cols": ["p", "q"], "func": func, "out": "o", "skip_na": sk}, h,
                  lambda d, func=func, sk=sk: pd.DataFrame({"i": d["i"], "o": getattr(d[["p", "q"]], func)(axis=1, skipna=sk)}),
                  (lambda d, plf=plf: d.select("i", getattr(pl, plf)("p", "q").alias("o"))) if not sk else None)
    # duplicate masks
    dt = [("i", "int", list(range(8))), ("k", "text", ["a", "b", "a", None, "b", "a", None, "c"]), ("v", "int", [1, 2, 1, 3, 2, 4, 3, 5])]
    for keys in (["k"], ["k", "v"]):
        for first, mask in (("first", "duplicated_first"), ("last", "duplicated_last"), (False, "is_duplicated")):
            def fp(d, keys=keys, first=first):
                return pd.DataFrame({"i": d["i"], "o": d.duplicated(subset=keys, keep=first)})

            def fq(d, keys=keys, mask=mask):
                s = d.select("i", pl.struct(keys).alias("s"))
                if mask == "duplicated_first":
                    o = pl.struct(keys).is_duplicated() & ~pl.struct(keys).is_first_distinct()
                elif mask == "duplicated_last":
                    o = pl.struct(keys).is_duplicated() & ~pl.struct(keys).is_last_distinct()
                elif mask == "is_duplicated":
                    o = pl.struct(keys).is_duplicated()
                elif mask == "is_unique":
                    o = pl.struct(keys).is_unique()
                elif mask == "is_first_distinct":
                    o = pl.struct(keys).is_first_distinct()
                else:
                    o = pl.struct(keys).is_last_distinct()
                return d.select("i", o.alias("o"))

            fcase(f"dupmask-{'+'.join(keys)}-{mask}", "duplicate_mask", "duplicate_mask", {"keys": keys, "mask": mask, "out": "o"}, dt, fp, fq)
        for mask in ("is_unique", "is_first_distinct", "is_last_distinct"):
            fcase(f"dupmask-{'+'.join(keys)}-{mask}", "duplicate_mask", "duplicate_mask", {"keys": keys, "mask": mask, "out": "o"}, dt, None,
                  lambda d, keys=keys, mask=mask: d.select("i", getattr(pl.struct(keys), mask)().alias("o")))
    # top_k
    tk = [("i", "int", list(range(10))), ("x", "float", [3.0, 1.0, 3.0, None, 5.0, 5.0, 2.0, 3.0, 1.0, 5.0]), ("y", "int", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])]
    for n in (1, 3, 5):
        for largest in (True, False):
            def fp(d, n=n, largest=largest):
                return (d.nlargest(n, ["x", "y"]) if largest else d.nsmallest(n, ["x", "y"]))[["i", "x", "y"]]

            def fq(d, n=n, largest=largest):
                d = d.drop_nulls("x")
                return d.top_k(n, by=["x", "y"]) if largest else d.bottom_k(n, by=["x", "y"])

            fcase(f"topk-{n}-{'large' if largest else 'small'}", "top_k", "top_k", {"by": ["x", "y"], "n": n, "largest": largest, "keep": "first"}, tk, fp, fq)
    # rle / rle_id
    rl = [("i", "int", list(range(10))), ("x", "int", [1, 1, 2, 2, 2, 3, 1, 1, 3, 3])]
    fcase("rle-id", "rle", "rle_id", {"col": "x", "out": "o"}, rl, None, lambda d: d.select("i", pl.col("x").rle_id().alias("o")))
    rl2 = [("i", "int", list(range(8))), ("x", "text", ["a", "a", None, None, "b", "a", "a", "a"])]
    fcase("rle-id-text", "rle", "rle_id", {"col": "x", "out": "o"}, rl2, None, lambda d: d.select("i", pl.col("x").rle_id().alias("o")))
    fcase("rle-runs", "rle", "rle", {"col": "x"}, rl, None, lambda d: d.select(pl.col("x").rle()).unnest("x"))
    # arg_sort / search_sorted-like: arg_true / unique counts are covered by the structure tests
    # frame arithmetic with a scalar, and compare
    ar = [("a", "float", [1.0, 2.0, None, 4.0]), ("b", "float", [10.0, 20.0, 30.0, 40.0]), ("c", "int", [1, 2, 3, 4])]
    for op, sym in (("add", "+"), ("sub", "-"), ("mul", "*"), ("div", "/")):
        fcase(f"arith_scalar-{op}", "frame_arith", "arith_scalar", {"op": op, "value": 2.0, "value_kind": "float"}, ar,
              lambda d, sym=sym: eval(f"d {sym} 2.0"), lambda d, sym=sym: d.select([eval(f"pl.col(c) {sym} 2.0") for c in d.columns]))
    # extreme / horizontal sums over ints exactly
    ex = [("g", "text", ["a", "a", "b", "b"]), ("x", "float", [1.0, NAN, 2.0, 3.0]), ("y", "int", [4, 1, 7, 2])]
    fcase("nunique-count-missing", "n_unique", "n_unique", {"col": "x", "count_missing": True}, ex, lambda d: pd.DataFrame({"o": [d["x"].nunique(dropna=False)]}), None)
    fcase("nunique-skip-missing", "n_unique", "n_unique", {"col": "x", "count_missing": False}, ex, lambda d: pd.DataFrame({"o": [d["x"].nunique(dropna=True)]}), None)


def main():
    run_scalar_cases()
    frame_cases_all()
    doc = {
        "generator": "tools/oracle2.py",
        "pandas": pd.__version__,
        "polars": pl.__version__,
        "numpy": np.__version__,
        "scalar": scalar_cases,
        "frames": frame_cases,
    }
    with open(sys.argv[1], "w") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=True)
        f.write("\n")
    sys.stderr.write(f"{len(scalar_cases)} scalar + {len(frame_cases)} frame cases\n")
    for g, s in stats.items():
        sys.stderr.write(f"  {g:22} {s}\n")
    errs = [(c["id"], c.get("pandas_error"), c.get("polars_error")) for c in scalar_cases + frame_cases if c.get("pandas_error") or c.get("polars_error")]
    sys.stderr.write(f"{len(errs)} cases with an engine error\n")
    with open(sys.argv[1] + ".report", "w") as f:
        for p in problems:
            f.write(p + "\n")
        for e in errs:
            f.write(f"ERR {e[0]} | pandas: {e[1]} | polars: {e[2]}\n")
    if problems:
        sys.stderr.write(f"{len(problems)} UNLABELLED disagreements (see {sys.argv[1]}.report)\n")
        sys.exit(1)


main()
