#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the time zone carried by a column (dataframe S2 wave W7): pandas 3.1
(`datetime64[us, zone]`) and polars 2.1 (`Datetime("us", time_zone=...)`) over instants around
the DST changes of Europe/Prague and America/New_York, a zone with a 30-minute offset, UTC, and
instants before 1970 and after 2037. Frozen into src/oracle2g_vectors.json and replayed by
src/s2w7_oracle_test.zig. No line of dataframe is consulted here: the expected values are what
the engines answer.

    python tools/oracle2g.py src/oracle2g_vectors.json      (see tools/README.md)

A case both engines answer alike is written once (`engine: "both"`); where they differ both
answers are written (`-pd`, `-pl`) and the replay's `known` list says which one dataframe
follows. A case an engine raises on is written for the other engine alone and reported on
stderr (`error` cases record the refusal, so the replay can check that dataframe refuses too).
"""
import json
import math
import sys

import numpy as np
import pandas as pd
import polars as pl

cases = []
notes = []

S = 1_000_000


def utc(y, mo, d, h=0, mi=0, s=0, us=0):
    """Microseconds since the epoch of a UTC wall clock."""
    t = pd.Timestamp(year=y, month=mo, day=d, hour=h, minute=mi, second=s, tz="UTC")
    return int(t.value // 1000) + us


def cell(v):
    if v is None or v is pd.NaT or v is pd.NA:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        return None if math.isnan(v) else float(v)
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


# ── series builders ──────────────────────────────────────────────────────────

def pl_inst(us, zone):
    s = pl.Series("x", us, dtype=pl.Int64).cast(pl.Datetime("us")).dt.replace_time_zone("UTC")
    return s.dt.convert_time_zone(zone) if zone else s


def pd_inst(us, zone):
    s = pd.Series(pd.to_datetime(pd.array(us, dtype="Int64"), unit="us", utc=True))
    return s.dt.tz_convert(zone) if zone else s


def pl_naive(texts):
    return pl.Series("x", texts, dtype=pl.String).str.to_datetime("%Y-%m-%dT%H:%M:%S%.f", time_unit="us", strict=True)


def pd_naive(texts):
    return pd.Series(pd.to_datetime(pd.array(texts, dtype="string"), format="ISO8601")).astype("datetime64[us]")


def pl_epoch(s):
    return cells(s.dt.epoch("us").to_list())


def pd_epoch(s):
    out = []
    for x in s:
        out.append(None if x is pd.NaT or pd.isna(x) else int(x.tz_convert("UTC").value) // 1000 if x.tzinfo else int(x.value) // 1000)
    return out


def emit(id, kind, engines, **kw):
    """engines: list of (name, thunk). Written once when both agree."""
    got = {}
    for name, fn in engines:
        try:
            got[name] = ("ok", fn())
        except Exception as e:  # noqa: BLE001
            got[name] = ("error", f"{type(e).__name__}: {str(e)[:140]}")
    oks = {n: v[1] for n, v in got.items() if v[0] == "ok"}
    errs = {n: v[1] for n, v in got.items() if v[0] == "error"}
    for n, e in errs.items():
        notes.append(f"{id}: {n} raises {e}")
    if not oks:
        cases.append({"id": id, "kind": kind, "engine": "both", "error": True, "expect": None, **kw})
        return
    vals = list(oks.values())
    if len(oks) == 2 and vals[0] != vals[1]:
        for n, v in oks.items():
            cases.append({"id": f"{id}-{n}", "kind": kind, "engine": n, "expect": v, **kw})
        notes.append(f"{id}: engines differ")
    else:
        name = "both" if len(oks) == 2 else next(iter(oks))
        cases.append({"id": id, "kind": kind, "engine": name, "expect": vals[0], **kw})
        if errs and len(oks) == 1:
            cases[-1]["other_raises"] = next(iter(errs.values()))


ZONES = ["Europe/Prague", "America/New_York", "Asia/Kolkata", "UTC"]

# Instants (UTC) around the changes, plus one before 1970, one after 2037, one with a fraction.
INSTANTS = [
    utc(2024, 3, 30, 23, 30), utc(2024, 3, 31, 0, 59, 59), utc(2024, 3, 31, 1, 0, 0), utc(2024, 3, 31, 12),
    utc(2024, 10, 26, 22, 30), utc(2024, 10, 27, 0, 30), utc(2024, 10, 27, 1, 30), utc(2024, 10, 27, 23, 30),
    utc(2024, 3, 10, 6, 59, 59), utc(2024, 3, 10, 7, 0, 0), utc(2024, 11, 3, 5, 30), utc(2024, 11, 3, 6, 30),
    utc(2024, 1, 1, 0, 0, 0), utc(2024, 12, 31, 23, 59, 59, 999999), utc(1999, 12, 31, 23, 30),
    utc(2038, 1, 19, 3, 14, 7), utc(2050, 7, 1, 12, 0, 0, 123456), utc(2100, 1, 1),
]
PRE1970 = [utc(1969, 12, 31, 23, 59, 59), utc(1960, 6, 15, 12), utc(1930, 1, 15, 8)]


# ── 1. the wall clock a zoned column shows (dt fields, convert_time_zone) ───

def g_fields():
    for zone in ZONES:
        for tag, inst in (("", INSTANTS), ("-pre1970", PRE1970)):
            xs = inst + [None] if tag == "" else inst

            def pl_f(xs=xs, zone=zone):
                s = pl_inst(xs, zone)
                return {
                    "year": cells(s.dt.year().to_list()), "month": cells(s.dt.month().to_list()),
                    "day": cells(s.dt.day().to_list()), "hour": cells(s.dt.hour().to_list()),
                    "minute": cells(s.dt.minute().to_list()), "second": cells(s.dt.second().to_list()),
                    "weekday": cells(s.dt.weekday().to_list()), "day_of_year": cells(s.dt.ordinal_day().to_list()),
                    "date": cells(s.dt.strftime("%Y-%m-%d").to_list()),
                    "epoch_us": pl_epoch(s),
                }

            def pd_f(xs=xs, zone=zone):
                s = pd_inst(xs, zone)
                d = s.dt
                return {
                    "year": cells(d.year), "month": cells(d.month), "day": cells(d.day), "hour": cells(d.hour),
                    "minute": cells(d.minute), "second": cells(d.second),
                    "weekday": cells([None if pd.isna(x) else int(x) + 1 for x in d.dayofweek]),
                    "day_of_year": cells(d.dayofyear),
                    "date": cells(d.strftime("%Y-%m-%d")),
                    "epoch_us": pd_epoch(s),
                }

            emit(f"fields-{zone}{tag}", "fields", [("polars", pl_f), ("pandas", pd_f)], zone=zone, inst=xs)


# ── 2. strftime with %z / %Z / %:z ──────────────────────────────────────────

def g_strftime():
    fmts = ["%Y-%m-%dT%H:%M:%S%z", "%H:%M %Z", "%Y-%m-%d %H:%M:%S %:z", "%d.%m.%Y %H:%M %Z%z"]
    for zone in ZONES:
        for i, fmt in enumerate(fmts):
            xs = INSTANTS[:12] + [None]
            emit(f"strftime-{zone}-{i}", "strftime",
                 [("polars", lambda xs=xs, zone=zone, fmt=fmt: cells(pl_inst(xs, zone).dt.strftime(fmt).to_list())),
                  ("pandas", lambda xs=xs, zone=zone, fmt=fmt: cells(pd_inst(xs, zone).dt.strftime(fmt)))],
                 zone=zone, inst=xs, fmt=fmt)


# ── 3. replace_time_zone / tz_localize: naive wall clock to instants ───────

PLAIN = ["2024-01-15T12:00:00", "2024-07-15T12:00:00.250000", "2024-03-31T01:59:59", "2024-03-31T03:00:00",
         "2024-10-27T01:59:59", "2024-10-27T03:00:00", "1999-12-31T23:30:00", "2050-07-01T12:00:00"]
FOLD = {"Europe/Prague": ["2024-10-27T02:00:00", "2024-10-27T02:30:00", "2024-10-27T02:59:59"],
        "America/New_York": ["2024-11-03T01:00:00", "2024-11-03T01:30:00", "2024-11-03T01:59:59"],
        "Asia/Kolkata": [], "UTC": []}
GAP = {"Europe/Prague": ["2024-03-31T02:00:00", "2024-03-31T02:30:00", "2024-03-31T02:59:59"],
       "America/New_York": ["2024-03-10T02:00:00", "2024-03-10T02:30:00", "2024-03-10T02:59:59"],
       "Asia/Kolkata": [], "UTC": []}


def pl_local(texts, zone, ambiguous, non_existent="null"):
    return pl_epoch(pl_naive(texts).dt.replace_time_zone(zone, ambiguous=ambiguous, non_existent=non_existent))


def pd_local(texts, zone, ambiguous, nonexistent):
    s = pd_naive(texts)
    amb = ambiguous
    if isinstance(ambiguous, bool):
        amb = np.array([ambiguous] * len(s))
    return pd_epoch(s.dt.tz_localize(zone, ambiguous=amb, nonexistent=nonexistent))


def g_replace():
    for zone in ZONES:
        for pname, pl_amb, pd_amb in (("earlier", "earliest", True), ("later", "latest", False), ("null", "null", "NaT")):
            xs = PLAIN + [None]
            emit(f"replace-plain-{zone}-{pname}", "replace",
                 [("polars", lambda xs=xs, zone=zone, a=pl_amb: pl_local(xs, zone, a)),
                  ("pandas", lambda xs=xs, zone=zone, a=pd_amb: pd_local(xs, zone, a, "NaT"))],
                 zone=zone, policy=pname, wall=xs)
            if FOLD[zone]:
                xs = FOLD[zone]
                emit(f"replace-fold-{zone}-{pname}", "replace",
                     [("polars", lambda xs=xs, zone=zone, a=pl_amb: pl_local(xs, zone, a)),
                      ("pandas", lambda xs=xs, zone=zone, a=pd_amb: pd_local(xs, zone, a, "NaT"))],
                     zone=zone, policy=pname, wall=xs)
        if GAP[zone]:
            xs = GAP[zone]
            emit(f"replace-gap-{zone}-null", "replace",
                 [("polars", lambda xs=xs, zone=zone: pl_local(xs, zone, "earliest")),
                  ("pandas", lambda xs=xs, zone=zone: pd_local(xs, zone, True, "NaT"))],
                 zone=zone, policy="null", wall=xs)
            # `compatible` of a gap: moved forward by the size of the jump (Python fold=0). pandas
            # takes a timedelta for that; polars has no such mode (its non_existent is raise/null).
            emit(f"replace-gap-{zone}-compatible", "replace",
                 [("pandas", lambda xs=xs, zone=zone: pd_local(xs, zone, True, pd.Timedelta("1h")))],
                 zone=zone, policy="compatible", wall=xs)
        for pname, pl_amb, pd_amb in (("compatible", "earliest", True),):
            xs = FOLD[zone] or ["2024-01-15T12:00:00"]
            emit(f"replace-fold-{zone}-compatible", "replace",
                 [("polars", lambda xs=xs, zone=zone, a=pl_amb: pl_local(xs, zone, a)),
                  ("pandas", lambda xs=xs, zone=zone, a=pd_amb: pd_local(xs, zone, a, "NaT"))],
                 zone=zone, policy="compatible", wall=xs)
    # replace on an already zoned column: the wall clock of the old zone read in the new zone
    # (polars; pandas tz_localize refuses an aware series), and replace_time_zone(None): the wall clock.
    xs = INSTANTS[:12]
    emit("replace-zoned-to-new", "replace_zoned",
         [("polars", lambda: pl_epoch(pl_inst(xs, "Europe/Prague").dt.replace_time_zone("America/New_York", ambiguous="earliest", non_existent="null"))),
          ("pandas", lambda: pd_epoch(pd_inst(xs, "Europe/Prague").dt.tz_localize("America/New_York")))],
         zone_from="Europe/Prague", zone="America/New_York", inst=xs)
    emit("replace-zoned-to-none", "replace_naive",
         [("polars", lambda: pl_epoch(pl_inst(xs, "Europe/Prague").dt.replace_time_zone(None))),
          ("pandas", lambda: pd_epoch(pd_inst(xs, "Europe/Prague").dt.tz_localize(None)))],
         zone_from="Europe/Prague", inst=xs)
    emit("convert-to-none", "convert_naive",
         [("pandas", lambda: pd_epoch(pd_inst(xs, "Europe/Prague").dt.tz_convert(None)))],
         zone_from="Europe/Prague", inst=xs)
    # convert_time_zone / tz_convert of a naive column: both refuse
    emit("convert-naive", "convert_of_naive",
         [("polars", lambda: pl_naive(PLAIN[:2]).dt.convert_time_zone("Europe/Prague").dt.epoch("us").to_list()),
          ("pandas", lambda: pd_naive(PLAIN[:2]).dt.tz_convert("Europe/Prague").tolist())],
         zone="Europe/Prague")


# ── 4. truncate / floor on a zoned column ───────────────────────────────────

def g_truncate():
    xs = [utc(2024, 3, 30, 22, 17, 5), utc(2024, 3, 31, 6, 40), utc(2024, 3, 31, 21, 45), utc(2024, 4, 1, 3, 10),
          utc(2024, 10, 26, 21, 50), utc(2024, 10, 27, 12, 25), utc(2024, 10, 27, 23, 45), utc(2024, 11, 3, 20, 5),
          utc(2024, 3, 10, 12, 0), utc(2024, 7, 15, 12, 20, 30, 777777), utc(1999, 12, 31, 23, 30), utc(2024, 11, 3, 17, 5)]
    every = [("1d", "1D"), ("1h", "1h"), ("30m", "30min"), ("6h", "6h"), ("1w", None), ("1mo", None), ("2d", "2D")]
    for zone in ZONES:
        for pe, fe in every:
            engines = [("polars", lambda xs=xs, zone=zone, pe=pe: pl_epoch(pl_inst(xs, zone).dt.truncate(pe)))]
            if fe:
                engines.append(("pandas", lambda xs=xs, zone=zone, fe=fe: pd_epoch(pd_inst(xs, zone).dt.floor(fe))))
            emit(f"truncate-{zone}-{pe}", "truncate", engines, zone=zone, inst=xs, every=pe)
        emit(f"ceil-{zone}-1d", "ceil", [("pandas", lambda xs=xs, zone=zone: pd_epoch(pd_inst(xs, zone).dt.ceil("1D")))],
             zone=zone, inst=xs, every="1d")


# ── 5. comparing columns of two zones; casting to and from a zoned type ─────

def g_compare():
    a = [utc(2024, 7, 15, 12), utc(2024, 7, 15, 12), utc(2024, 7, 15, 12), None]
    b = [utc(2024, 7, 15, 12), utc(2024, 7, 15, 13), utc(2024, 7, 15, 11), utc(2024, 7, 15, 12)]
    for op, pf in (("eq", lambda x, y: x == y), ("lt", lambda x, y: x < y), ("gt", lambda x, y: x > y)):
        emit(f"compare-{op}", "compare",
             [("polars", lambda pf=pf: cells(pf(pl_inst(a, "Europe/Prague"), pl_inst(b, "America/New_York")).to_list())),
              ("pandas", lambda pf=pf: cells([None if pd.isna(x) else bool(x) for x in pf(pd_inst(a, "Europe/Prague"), pd_inst(b, "America/New_York"))]))],
             op=op, a=a, b=b, zone_a="Europe/Prague", zone_b="America/New_York")
    # a naive column against a zoned one
    emit("compare-naive-zoned", "compare_naive",
         [("polars", lambda: pl_inst(a, None).dt.replace_time_zone(None).eq(pl_inst(b, "UTC")).to_list()),
          ("pandas", lambda: (pd_inst(a, None).dt.tz_localize(None) == pd_inst(b, "UTC")).tolist())],
         a=a, b=b)


def g_cast():
    xs = INSTANTS[:8]
    # naive column of the UTC wall clock cast to a zoned type, and a zoned column cast to naive
    emit("cast-naive-to-zoned", "cast_zoned",
         [("polars", lambda: pl_epoch(pl_inst(xs, None).dt.replace_time_zone(None).cast(pl.Datetime("us", "Europe/Prague")))),
          ("pandas", lambda: pd_epoch(pd_inst(xs, None).dt.tz_localize(None).astype("datetime64[us, Europe/Prague]")))],
         zone="Europe/Prague", inst=xs)
    emit("cast-zoned-to-naive", "cast_naive",
         [("polars", lambda: pl_epoch(pl_inst(xs, "Europe/Prague").cast(pl.Datetime("us")))),
          ("pandas", lambda: pd_epoch(pd_inst(xs, "Europe/Prague").astype("datetime64[us]")))],
         zone_from="Europe/Prague", inst=xs)
    emit("cast-zoned-to-zoned", "cast_zoned",
         [("polars", lambda: pl_epoch(pl_inst(xs, "Europe/Prague").cast(pl.Datetime("us", "America/New_York")))),
          ("pandas", lambda: pd_epoch(pd_inst(xs, "Europe/Prague").astype("datetime64[us, America/New_York]")))],
         zone="America/New_York", inst=xs)


# ── 6. group_by_dynamic / resample on a zoned column ────────────────────────

def hourly(start, hours):
    return [start + h * 3600 * S for h in range(hours)]


def g_dynamic():
    spans = [("Europe/Prague", "spring", hourly(utc(2024, 3, 29, 12), 96)),
             ("Europe/Prague", "autumn", hourly(utc(2024, 10, 25, 12), 96)),
             ("America/New_York", "autumn", hourly(utc(2024, 11, 1, 12), 96)),
             ("Asia/Kolkata", "plain", hourly(utc(2024, 6, 1, 0), 72))]
    for zone, tag, xs in spans:
        def pl_g(xs=xs, zone=zone):
            s = pl_inst(xs, zone)
            df = pl.DataFrame({"ts": s, "v": list(range(len(xs)))})
            out = df.group_by_dynamic("ts", every="1d").agg(pl.col("v").sum().alias("s"), pl.len().alias("n"))
            return {"label": pl_epoch(out["ts"]), "n": cells(out["n"].to_list()), "sum": cells(out["s"].to_list())}

        def pd_g(xs=xs, zone=zone):
            s = pd.Series(range(len(xs)), index=pd.DatetimeIndex(pd_inst(xs, zone)))
            r = s.resample("1D")
            n, sm = r.size(), r.sum()
            return {"label": pd_epoch(pd.Series(n.index)), "n": cells(n.tolist()), "sum": cells(sm.tolist())}

        emit(f"dynamic-1d-{zone}-{tag}", "dynamic", [("polars", pl_g), ("pandas", pd_g)], zone=zone, inst=xs, every="1d")
    # a month window across the spring change (Prague), polars 1mo / pandas MS
    xs = [utc(2024, 3, 1) + d * 86400 * S + 12 * 3600 * S for d in range(80)]

    def pl_m(xs=xs):
        s = pl_inst(xs, "Europe/Prague")
        df = pl.DataFrame({"ts": s, "v": list(range(len(xs)))})
        out = df.group_by_dynamic("ts", every="1mo").agg(pl.col("v").sum().alias("s"), pl.len().alias("n"))
        return {"label": pl_epoch(out["ts"]), "n": cells(out["n"].to_list()), "sum": cells(out["s"].to_list())}

    def pd_m(xs=xs):
        s = pd.Series(range(len(xs)), index=pd.DatetimeIndex(pd_inst(xs, "Europe/Prague")))
        r = s.resample("MS")
        n, sm = r.size(), r.sum()
        return {"label": pd_epoch(pd.Series(n.index)), "n": cells(n.tolist()), "sum": cells(sm.tolist())}

    emit("dynamic-1mo-Europe/Prague", "dynamic", [("polars", pl_m), ("pandas", pd_m)], zone="Europe/Prague", inst=xs, every="1mo")


# ── 7. text I/O ─────────────────────────────────────────────────────────────

def g_io():
    xs = [utc(2024, 7, 15, 10), utc(2024, 1, 15, 11, 30, 5), utc(2024, 3, 31, 1, 0, 0, 500000), None]
    for zone in ("Europe/Prague", "America/New_York", "Asia/Kolkata", "UTC"):
        def pl_w(zone=zone):
            return pl.DataFrame({"ts": pl_inst(xs, zone), "k": [1, 2, 3, 4]}).write_csv()

        def pd_w(zone=zone):
            return pd.DataFrame({"ts": pd_inst(xs, zone), "k": [1, 2, 3, 4]}).to_csv(index=False, lineterminator="\n")

        emit(f"csv-write-{zone}", "csv_write", [("polars", pl_w), ("pandas", pd_w)], zone=zone, inst=xs)

        def pl_j(zone=zone):
            return pl.DataFrame({"ts": pl_inst(xs, zone), "k": [1, 2, 3, 4]}).write_json()

        def pd_j(zone=zone):
            return pd.DataFrame({"ts": pd_inst(xs, zone), "k": [1, 2, 3, 4]}).to_json(orient="records", date_format="iso", date_unit="us")

        emit(f"json-write-{zone}", "json_write", [("polars", pl_j), ("pandas", pd_j)], zone=zone, inst=xs)

        def pl_nd(zone=zone):
            return pl.DataFrame({"ts": pl_inst(xs, zone), "k": [1, 2, 3, 4]}).write_ndjson()

        def pd_nd(zone=zone):
            return pd.DataFrame({"ts": pd_inst(xs, zone), "k": [1, 2, 3, 4]}).to_json(orient="records", lines=True, date_format="iso", date_unit="us")

        emit(f"ndjson-write-{zone}", "ndjson_write", [("polars", pl_nd), ("pandas", pd_nd)], zone=zone, inst=xs)

    # reading text into a declared zoned type
    texts = ["2024-07-15T12:00:00+02:00", "2024-07-15T10:00:00Z", "2024-07-15T10:00:00", "2024-01-15 11:30:05", "2024-01-15T05:30:05-05:00", ""]
    csv = "ts\n" + "\n".join(texts) + "\n"

    def pl_r():
        import io
        df = pl.read_csv(io.StringIO(csv), schema_overrides={"ts": pl.Datetime("us", "Europe/Prague")})
        return {"dtype": str(df.schema["ts"]), "epoch_us": pl_epoch(df["ts"])}

    def pd_r():
        import io
        df = pd.read_csv(io.StringIO(csv), parse_dates=["ts"], date_format="ISO8601")
        s = df["ts"]
        if s.dt.tz is None:
            s = s.dt.tz_localize("Europe/Prague")
        else:
            s = s.dt.tz_convert("Europe/Prague")
        return {"dtype": str(s.dtype), "epoch_us": pd_epoch(s)}

    emit("csv-read-zoned", "csv_read", [("polars", pl_r), ("pandas", pd_r)], zone="Europe/Prague", csv=csv)
    # per-cell parse of each form alone (a mixed column can make an engine drop to text)
    for i, t in enumerate(texts[:5]):
        one = "ts\n" + t + "\n"

        def pl_one(one=one):
            import io
            df = pl.read_csv(io.StringIO(one), schema_overrides={"ts": pl.Datetime("us", "Europe/Prague")})
            return {"dtype": str(df.schema["ts"]), "epoch_us": pl_epoch(df["ts"])}

        def pd_one(one=one):
            import io
            s = pd.read_csv(io.StringIO(one), parse_dates=["ts"], date_format="ISO8601")["ts"]
            s = s.dt.tz_localize("Europe/Prague") if s.dt.tz is None else s.dt.tz_convert("Europe/Prague")
            return {"dtype": str(s.dtype), "epoch_us": pd_epoch(s)}

        emit(f"csv-read-zoned-one{i}", "csv_read", [("polars", pl_one), ("pandas", pd_one)], zone="Europe/Prague", csv=one)

    # JSON Table Schema
    def pd_ts():
        df = pd.DataFrame({"ts": pd_inst(xs[:3], "Europe/Prague")})
        return json.loads(df.to_json(orient="table", index=False))["schema"]["fields"]

    emit("json-table-schema", "table_schema", [("pandas", pd_ts)], zone="Europe/Prague", inst=xs[:3])
    emit("json-table-data", "table_data", [("pandas", lambda: json.loads(pd.DataFrame({"ts": pd_inst(xs[:3], "Europe/Prague")}).to_json(orient="table", index=False))["data"])],
         zone="Europe/Prague", inst=xs[:3])
    # HTML (pandas to_html; polars has none)
    emit("html", "html", [("pandas", lambda: pd.DataFrame({"ts": pd_inst(xs[:3], "Europe/Prague")}).to_html(index=False))],
         zone="Europe/Prague", inst=xs[:3])


for g in (g_fields, g_strftime, g_replace, g_truncate, g_compare, g_cast, g_dynamic, g_io):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        import traceback
        notes.append(f"GENERATOR {g.__name__}: {type(e).__name__}: {e}\n{traceback.format_exc()[-600:]}")

out = sys.argv[1] if len(sys.argv) > 1 else "oracle2g_vectors.json"
with open(out, "w") as fh:
    json.dump(cases, fh, indent=0, ensure_ascii=False)
    fh.write("\n")
sys.stderr.write(f"{len(cases)} cases\n")
for n in notes:
    sys.stderr.write("NOTE " + n + "\n")
