#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for `dataframe`'s input and output (step D3): what pandas and polars
answer to `read_csv`, `to_csv`/`write_csv`, `to_json`/`write_json`/`write_ndjson`, frozen
into src/oracle3_io_vectors.json and replayed by src/oracle3_io_test.zig. No line of
dataframe is consulted here.

    python tools/oracle3_io.py src/oracle3_io_vectors.json      (see tools/README.md)

Three kinds of case, each run on both engines:

* `read`: a CSV text and neutral options -> the columns, a kind per column and the cells.
* `write_csv`: a small table and options -> the text each engine writes.
* `write_json`: a small table -> the JSON value each engine writes (records, columns, ndjson).

Where the engines agree the case says `engine: both`. Where they differ, the case must
carry a `label` and `follow` in LABELS (the engine this module follows), or the run fails:
an unlabelled disagreement is a question nobody has answered. An engine that raises is
recorded (`pandas_error` / `polars_error`); both raising means the case expects an error.
NaN and null are both "missing" in the frozen cells.
"""
import datetime as dt
import io
import json
import math
import re
import sys
import warnings

import numpy as np
import pandas as pd
import polars as pl

warnings.filterwarnings("ignore")

problems = []
stats = {}


def bump(group, key):
    stats.setdefault(group, {}).setdefault(key, 0)
    stats[group][key] += 1


# ── labels: where the engines differ, what this module follows and why ───────

# (regex on the case id, label, follow). "pandas" | "polars" | "ours": the case's `expect`
# is the text/cells of that engine; "ours" means neither: `expect` is set by the case.
LABELS = [
    (r"^read-infer-intna$", "an int column with a missing cell: pandas makes it float64 with NaN, polars keeps Int64 with a null (kept as int, with a null, here)", "polars"),
    (r"^read-infer-(int|intws|intplus|intws2|floatws|floatws2)$", "pandas trims blanks around numbers and reads +3; polars leaves the column text", "pandas"),
    (r"^read-infer-(big|bigneg|u64)", "an integer past int64: pandas uint64 or object, polars Int128; here text (a float would lose digits)", "ours"),
    (r"^read-infer-(infs|inf2|nan1|infinity|infinityneg|infupper)", "pandas reads Infinity/INF/nan as floats; polars only inf and NaN", "pandas"),
    (r"^read-infer-(nulls|nulls_each|nacolumns|quoted_na|allnull)$", "polars' only null marker is the empty field; pandas has a list of 19 (`na_values`), the default here; a quoted NA is missing too in pandas", "pandas"),
    (r"^read-infer-quoted_empty$", "a quoted empty field: pandas missing, polars an empty string; null here (\"\" is in the default markers)", "pandas"),
    (r"^read-infer-boolna$", "bool with a missing cell: pandas makes it object, polars keeps Boolean with a null", "polars"),
        (r"^read-infer-emptyfield$", "a column of nothing but nulls: pandas float64, polars String", "polars"),
    (r"^read-gen-", "an int or bool column with a missing cell: pandas float64 / object, polars keeps the type (and Date for parsed dates)", "polars"),
    (r"^read-struct-bare_quote$", "a quote inside an unquoted field: pandas reads it as a literal, polars refuses the file; literal here (RFC 4180, csvstream)", "pandas"),
    (r"^read-struct-(blank|single_col_blank)$", "blank lines: pandas skips them, polars reads a row of nulls; csvstream skips them", "pandas"),
    (r"^read-struct-dup", "repeated names: pandas a.1, polars a_duplicated_0", "pandas"),
    (r"^read-struct-emptyname$", "an empty name: pandas Unnamed: 1, polars keeps it empty", "pandas"),
    (r"^read-struct-trail", "a trailing delimiter makes an unnamed column: pandas Unnamed: 2 and float64, polars an empty name and String", "pandas"),
    (r"^read-struct-comment$", "a comment line: the engines read it as a row unless asked; with `comment` both skip it", "pandas"),
    (r"^read-struct-(short|ragged_short|comment_plain)", "a short row: pandas pads and turns ints into float64, polars pads and keeps Int64", "polars"),
    (r"^read-opts-nrows0$", "no data row at all: pandas leaves every column text (object), polars infers from the first rows; text here", "pandas"),
    (r"^read-opts-nullvals$", "given null markers replace the defaults: an empty field stays an empty text (pandas, `keep_default_na=False`); polars nulls it", "pandas"),
    (r"^read-opts-nullvals(-empty|2)$", "an int column with a missing cell: pandas float64, polars Int64 with a null", "polars"),
    (r"^read-opts-nohdr", "no header: pandas names the columns 0, 1..., polars column_1...", "polars"),
    (r"^read-opts-usecols", "usecols keeps the file's order in pandas, polars returns the order asked for", "pandas"),
    (r"^read-opts-dates", "pandas has no date type: a date-only column is datetime64 there, Date in polars", "polars"),
    (r"^read-opts-typed", "dtype: a given `int64` over a float or empty cell is an error in pandas; polars strict", "pandas"),
    (r"^read-opts-nullcol", "a column with a given int type and a missing cell: pandas cannot, polars nulls", "polars"),
    (r"^write-csv-floats_sci$", "tiny floats: pandas 1e-05 (Python repr), polars 0.00001", "pandas"),
    (r"^write-csv-float_nan_inf$", "NaN: pandas writes the empty field, polars NaN; this module counts NaN as missing", "pandas"),
    (r"^write-csv-(bools|mixed)", "bools: pandas True/False, polars true/false", "pandas"),
    (r"^write-csv-text_empty", "an empty text: polars writes \"\" (it differs from a null), pandas nothing", "polars"),
    (r"^write-csv-names$", "an empty column name: pandas writes it bare, polars quotes it", "pandas"),
    (r"^write-csv-(single_null|float_null|dates|s2-datefmt|s2-dtfmt)$", "a lone null: pandas writes \"\" so the row survives a read, polars an empty line a reader skips", "pandas"),
    (r"^write-csv-ts", "timestamps: pandas `YYYY-MM-DD HH:MM:SS[.ffffff]` (all cells with a fraction when one has), polars ISO with T and six digits always", "pandas"),
    (r"^write-csv-nonnum", "non-numeric quoting: pandas leaves bools bare, polars quotes true/false", "pandas"),
    (r"^write-csv-nonnum_ts", "non-numeric quoting of dates: both quote; the timestamp spelling differs as in write-csv-ts", "pandas"),
    (r"^write-json-floats", "float digits: pandas rounds to 10 digits (`double_precision`), polars shortest", "polars"),
    (r"^write-json-dates", "dates: pandas epoch milliseconds, polars the ISO text (kept: it reads back as a date)", "polars"),
    (r"^write-json-float_special", "NaN, inf: both null; -0.0: pandas 0.0, polars -0.0", "polars"),
    (r"^read-s2-colnull$", "an int column with a missing cell: pandas float64, polars Int64 with a null", "polars"),
    # dataframe S2 (2026-11-09): options one engine has
    (r"^read-s2-(thousands|decimal-thousands|truev|nafilter|initspace|footer|badlines|datefmt|escape|emptynull)$", "polars has no such option (its answer is the plain read); pandas' answer is followed", "pandas"),
    (r"^write-csv-s2-(sci|sci_prec|sci_off|bom)$", "float_scientific and include_bom are polars options; pandas writes its own repr and no BOM", "polars"),
    (r"^write-csv-s2-esc$", "escapechar/doublequote are pandas options; polars always doubles", "pandas"),
]


def label_for(cid):
    for pat, label, follow in LABELS:
        if re.search(pat, cid):
            return label, follow
    return None


# ── values ──────────────────────────────────────────────────────────────────


def ncell(v):
    """A cell as the vectors keep it: None for missing, ints exact, floats finite."""
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
    if isinstance(v, (dt.date, dt.datetime, pd.Timestamp)):
        return v
    return str(v)


def ts_us(v):
    t = pd.Timestamp(v)
    if t.tzinfo is not None:
        t = t.tz_convert("UTC").tz_localize(None)
    return int(t.as_unit("us").asm8.view("i8"))


def near(a, b):
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    return a == b or abs(a - b) <= 1e-9 * max(abs(a), abs(b), 1e-300)


def kind_pd(s):
    if pd.api.types.is_bool_dtype(s.dtype):
        return "bool"
    if pd.api.types.is_integer_dtype(s.dtype):
        return "int"
    if pd.api.types.is_float_dtype(s.dtype):
        return "float"
    if pd.api.types.is_datetime64_any_dtype(s.dtype):
        return "timestamp"
    return "text"


def norm_read_pd(df):
    cols = [str(c) for c in df.columns]
    kinds, data = [], []
    for j in range(len(cols)):
        s = df.iloc[:, j]
        k = kind_pd(s)
        kinds.append(k)
        if k == "timestamp":
            data.append([None if pd.isna(v) else ts_us(v) for v in s])
        else:
            data.append([ncell(v) for v in s])
        if k == "text" and str(s.dtype) == "object" and all(v is None or (isinstance(v, float) and math.isnan(v)) for v in s):
            kinds[-1] = "text"
    rows = [list(r) for r in zip(*data)] if data else []
    return {"columns": cols, "kinds": kinds, "rows": rows}


def norm_read_pl(df):
    cols = list(df.columns)
    kinds, data = [], []
    for c in cols:
        s = df[c]
        t = s.dtype
        if isinstance(t, pl.Datetime):
            kinds.append("timestamp")
            if t.time_zone:
                s = s.dt.convert_time_zone("UTC").dt.replace_time_zone(None)
            data.append([None if v is None else int(np.datetime64(v, "us").astype("int64")) for v in s.to_list()])
        elif t == pl.Date:
            kinds.append("date")
            data.append([None if v is None else v.isoformat() for v in s.to_list()])
        else:
            kinds.append("int" if t.is_integer() else "float" if t.is_float() else "bool" if t == pl.Boolean else "text")
            data.append([ncell(v) for v in s.to_list()])
    rows = [list(r) for r in zip(*data)] if data else []
    return {"columns": cols, "kinds": kinds, "rows": rows}


def read_same(p, q):
    if p["columns"] != q["columns"] or p["kinds"] != q["kinds"] or len(p["rows"]) != len(q["rows"]):
        return False
    return all(near(u, v) for r, s in zip(p["rows"], q["rows"]) for u, v in zip(r, s))


def enc(v):
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "inf" if v > 0 else "-inf"
    return v


def attempt(fn):
    try:
        return fn(), None
    except Exception as e:  # the engines' own error classes
        return None, f"{type(e).__name__}: {str(e)[:100]}".replace("\n", " ")


# ── read cases ──────────────────────────────────────────────────────────────

read_cases = []


def pd_kwargs(o):
    kw = {}
    if "delimiter" in o:
        kw["sep"] = o["delimiter"]
    if o.get("has_header") is False:
        kw["header"] = None
    if "null_values" in o:
        kw["na_values"] = o["null_values"]
        kw["keep_default_na"] = False
    if "quote" in o:
        kw["quotechar"] = o["quote"]
    if "skip_rows" in o:
        kw["skiprows"] = o["skip_rows"]
    if "n_rows" in o:
        kw["nrows"] = o["n_rows"]
    if "comment" in o:
        kw["comment"] = o["comment"]
    if "columns" in o:
        kw["usecols"] = o["columns"]
    if "types" in o:
        kw["dtype"] = {k: {"int": "int64", "float": "float64", "text": "str", "bool": "bool"}[v] for k, v in o["types"].items()}
    if o.get("infer_types") is False:
        kw["dtype"] = str
    if "date_cols" in o:
        kw["parse_dates"] = o["date_cols"]
    if "names" in o:
        kw["names"] = o["names"]
        kw["header"] = 0 if o.get("has_header", True) else None
    if "thousands" in o:
        kw["thousands"] = o["thousands"]
    if "decimal" in o:
        kw["decimal"] = o["decimal"]
    if "true_values" in o:
        kw["true_values"] = o["true_values"]
        kw["false_values"] = o["false_values"]
    if "column_null_values" in o:
        kw["na_values"] = o["column_null_values"]
    if o.get("na_filter") is False:
        kw["na_filter"] = False
    if o.get("skipinitialspace"):
        kw["skipinitialspace"] = True
    if "skipfooter" in o:
        kw["skipfooter"] = o["skipfooter"]
        kw["engine"] = "python"
    if "skip_rows_after_header" in o:
        kw["skiprows"] = list(range(1, 1 + o["skip_rows_after_header"]))
    if o.get("on_bad_lines") == "skip":
        kw["on_bad_lines"] = "skip"
    if "date_format" in o:
        kw["date_format"] = o["date_format"]
    if "escape_char" in o:
        kw["escapechar"] = o["escape_char"]
    if o.get("double_quote") is False:
        kw["doublequote"] = False
    if o.get("empty_string_is_null") is False:
        kw["na_values"] = ["#N/A", "#N/A N/A", "#NA", "-1.#IND", "-1.#QNAN", "-NaN", "-nan", "1.#IND", "1.#QNAN", "<NA>", "N/A", "NA", "NULL", "NaN", "None", "n/a", "nan", "null"]
        kw["keep_default_na"] = False
    kw["skip_blank_lines"] = True
    return kw


def pd_read(text, o):
    df = pd.read_csv(io.StringIO(text), **pd_kwargs(o))
    if "row_index_name" in o:
        df.insert(0, o["row_index_name"], range(o.get("row_index_offset", 0), o.get("row_index_offset", 0) + len(df)))
    return df


def pl_kwargs(o):
    kw = {}
    if "delimiter" in o:
        kw["separator"] = o["delimiter"]
    if o.get("has_header") is False:
        kw["has_header"] = False
    if "null_values" in o:
        kw["null_values"] = o["null_values"]
    if "quote" in o:
        kw["quote_char"] = o["quote"]
    if "skip_rows" in o:
        kw["skip_rows"] = o["skip_rows"]
    if "n_rows" in o:
        kw["n_rows"] = o["n_rows"]
    if "comment" in o:
        kw["comment_prefix"] = o["comment"]
    if "columns" in o:
        kw["columns"] = o["columns"]
    if "types" in o:
        kw["schema_overrides"] = {k: {"int": pl.Int64, "float": pl.Float64, "text": pl.String, "bool": pl.Boolean}[v] for k, v in o["types"].items()}
    if o.get("infer_types") is False:
        kw["infer_schema"] = False
    if "date_cols" in o:
        kw["try_parse_dates"] = True
    if "names" in o:
        kw["new_columns"] = o["names"]
    if o.get("decimal") == ",":
        kw["decimal_comma"] = True
    if "column_null_values" in o:
        kw["null_values"] = {k: v[0] for k, v in o["column_null_values"].items()}
    if "skip_rows_after_header" in o:
        kw["skip_rows_after_header"] = o["skip_rows_after_header"]
    if "row_index_name" in o:
        kw["row_index_name"] = o["row_index_name"]
        kw["row_index_offset"] = o.get("row_index_offset", 0)
    return kw


def rcase(cid, group, text, opts=None):
    o = opts or {}
    qkw = pl_kwargs(o)
    p, perr = attempt(lambda: norm_read_pd(pd_read(text, o)))
    q, qerr = attempt(lambda: norm_read_pl(pl.read_csv(text.encode("utf-8"), **qkw)))
    if p is not None and o.get("has_header") is False and "names" not in o:
        p["columns"] = [f"column_{i + 1}" for i in range(len(p["columns"]))]  # 0, 1... vs column_1...: renamed, see LABELS
    e = {"id": cid, "group": group, "csv": text, "opts": o}
    if perr:
        e["pandas_error"] = perr
    if qerr:
        e["polars_error"] = qerr
    use = None
    if p is not None and q is not None:
        bump(group, "both")
        raw_p_cols = p["columns"]
        if read_same(p, q):
            bump(group, "agree")
            e["engine"] = "both"
            use = p
        else:
            lab = label_for(cid)
            if not lab:
                problems.append(f"UNLABELLED READ DISAGREEMENT {cid}\n   pandas {p}\n   polars {q}")
                lab = ("UNLABELLED", "pandas")
            bump(group, "labelled")
            e["label"], e["engine"] = lab
            if lab[1] == "ours":
                use = None
                e["engine"] = "ours"
            else:
                use = p if lab[1] == "pandas" else q
                e["other"] = enc_read(q if lab[1] == "pandas" else p)
    elif p is not None or q is not None:
        bump(group, "one")
        lab = label_for(cid)
        if not lab:
            problems.append(f"UNLABELLED ERROR DISAGREEMENT {cid}\n   pandas {perr or p}\n   polars {qerr or q}")
            lab = ("UNLABELLED", "pandas")
        e["label"], e["engine"] = lab
        use = p if p is not None else q
        if lab[1] == "pandas" and p is None or lab[1] == "polars" and q is None:
            e["expect_error"] = True
            use = None
        elif lab[1] == "ours":
            e["engine"] = "ours"
            use = None
        if "other" not in e and (q if lab[1] == "pandas" else p) is not None:
            e["other"] = enc_read(q if lab[1] == "pandas" else p)
    else:
        bump(group, "none")
        e["engine"] = "none"
        e["expect_error"] = True
    if p is not None:
        e["pandas"] = enc_read(p)
    if q is not None:
        e["polars"] = enc_read(q)
    if use is not None:
        e["expect"] = enc_read(use)
    read_cases.append(e)


def enc_read(r):
    return {"columns": r["columns"], "kinds": r["kinds"], "rows": [[enc(v) for v in row] for row in r["rows"]]}


def read_cases_all():
    infer = {
        "int": "1\n-2\n+3\n4\n", "intplus": "+3\n+4\n", "intws": " 4\n5\n", "intws2": "4 \n5 \n", "floatws": " 1.5\n2\n", "floatws2": "1.5 \n2\n",
        "intna": "1\n\n3\n4\n", "intzero": "007\n1\n-0\n", "big": "9223372036854775807\n9223372036854775808\n", "bigneg": "-9223372036854775809\n1\n",
        "u64": "18446744073709551615\n1\n", "maxmin": "9223372036854775807\n-9223372036854775808\n",
        "float": "1.5\n2\n.5\n5.\n", "exp": "1e5\n2E-3\n-1.5e+3\n", "mixed_if": "1\n2.5\n3\n", "expint": "1e3\n5\n",
        "infs": "inf\n-inf\n1.5\n", "inf2": "inf\n+inf\n", "infinity": "Infinity\n1.5\n", "infinityneg": "-Infinity\n1\n", "infupper": "INF\n1\n", "nan1": "nan\n1.5\n", "nan2": "NaN\n2.5\n",
        "boolt": "true\nfalse\n", "boolT": "True\nFalse\n", "boolU": "TRUE\nFALSE\ntRue\n", "bool01": "1\n0\n", "boolna": "True\n\nFalse\n", "boolmix": "true\n1\n",
        "text": "a\nb\n", "textnum": "1\nx\n", "textfloat": "1.5\nx\n", "numbool": "1\ntrue\n",
        "date": "2021-01-02\n2021-03-04\n", "ts": "2021-01-02 03:04:05\n2021-01-02 03:04:06\n", "tsT": "2021-01-02T03:04:05\n2021-01-02T03:04:06.5\n",
        "ws": "a\n b \n", "underscore": "1_000\n2\n", "hex": "0x10\n1\n", "dot": ".\n1\n", "minus": "-\n1\n", "e1": "1e\n1\n", "dotdot": "1.2.3\n1\n", "plusonly": "+\n1\n",
        "nulls": "NA\nnull\nNULL\nN/A\nn/a\nNaN\nnan\nNone\n#N/A\n<NA>\n-nan\n-NaN\n1.#IND\n1.#QNAN\n#NA\nNULL\n",
        "nulls_each": "1\nNA\n2\nnull\n3\nN/A\n4\n",
        "allnull": "NA\nNA\n", "emptyfield": "\n\n", "nacolumns": "NA\n1.5\nN/A\n",
        "quoted_num": '"1"\n"2"\n', "quoted_na": '"NA"\n"1"\n', "quoted_empty": '""\n"1"\n',
        "unicode": "é\n日本\n", "long_int": "123456789012\n-1\n", "float_prec": "0.1\n0.30000000000000004\n1e-320\n", "float_big": "1e308\n1.7976931348623157e308\n1e400\n",
    }
    for k, v in infer.items():
        rcase(f"read-infer-{k}", "infer", "c\n" + v)
    # structure
    struct = {
        "ragged_short": "a,b,c\n1,2,3\n4,5\n6,7,8\n", "ragged_long": "a,b\n1,2\n3,4,5\n", "short_text": "a,b\nx,y\nz\n", "bom": "﻿a,b\n1,2\n", "qnl": 'a,b\n"x\ny",2\n"p""q",3\n',
        "blank": "a,b\n1,2\n\n3,4\n", "blank_lead": "\n\na,b\n1,2\n", "dupnames": "a,a,b\n1,2,3\n", "dup3": "a,a,a,a.1\n1,2,3,4\n", "emptyname": "a,,b\n1,2,3\n",
        "crlf": "a,b\r\n1,2\r\n3,4\r\n", "nonl": "a,b\n1,2", "hdronly": "a,b\n", "empty": "", "onlynl": "\n",
        "comment_plain": "a,b\n#x\n1,2\n", "trailing_delim": "a,b,\n1,2,\n", "quotes_delim": 'a,b\n"x,y",1\n', "esc_quote": 'a\n"he said ""hi"""\n',
        "wide": ",".join(f"c{i}" for i in range(40)) + "\n" + ",".join(str(i) for i in range(40)) + "\n",
        "single_col_blank": "a\n1\n\n2\n", "space_only": "a,b\n , \n1,2\n", "tab_in_field": "a\nx\ty\n", "cr_in_quote": 'a\n"x\ry"\n', "quoted_header": '"a b","c,d"\n1,2\n',
        "bare_quote": 'a\n5" floppy\n',
    }
    for k, v in struct.items():
        rcase(f"read-struct-{k}", "struct", v)
    # options
    rcase("read-opts-semicolon", "opts", "a;b\n1;x\n2;y\n", {"delimiter": ";"})
    rcase("read-opts-tab", "opts", "a\tb\n1\tx\n", {"delimiter": "\t"})
    rcase("read-opts-nohdr", "opts", "1,x\n2,y\n", {"has_header": False})
    rcase("read-opts-skip", "opts", "junk\nmore junk\na,b\n1,2\n", {"skip_rows": 2})
    rcase("read-opts-nrows", "opts", "a,b\n1,2\n3,4\n5,6\n", {"n_rows": 2})
    rcase("read-opts-nrows0", "opts", "a,b\n1,2\n3,4\n", {"n_rows": 0})
    rcase("read-opts-usecols", "opts", "a,b,c\n1,2,3\n4,5,6\n", {"columns": ["c", "a"]})
    rcase("read-opts-usecols1", "opts", "a,b,c\n1,2,3\n4,5,6\n", {"columns": ["b"]})
    rcase("read-opts-typed-str", "opts", "id,v\n001,1\n002,2\n", {"types": {"id": "text"}})
    rcase("read-opts-typed-float", "opts", "a,b\n1,2\n3,4\n", {"types": {"a": "float"}})
    rcase("read-opts-typed-int-bad", "opts", "a\n1.5\n", {"types": {"a": "int"}})
    rcase("read-opts-typed-bool", "opts", "a\ntrue\nFalse\n", {"types": {"a": "bool"}})
    rcase("read-opts-nullcol-int", "opts", "a\n1\n\n3\n", {"types": {"a": "int"}})
    rcase("read-opts-notinfer", "opts", "a,b,c\n1,2.5,true\n", {"infer_types": False})
    rcase("read-opts-nullvals", "opts", "a,b\nNA,1\nx,\n,3\n", {"null_values": ["NA"]})
    rcase("read-opts-nullvals-empty", "opts", "a,b\nNA,1\nx,\n", {"null_values": [""]})
    rcase("read-opts-nullvals2", "opts", "a\n-\n1\n?\n", {"null_values": ["-", "?"]})
    rcase("read-opts-comment", "opts", "a,b\n#x\n1,2\n#y\n3,4\n", {"comment": "#"})
    rcase("read-opts-dates", "opts", "d,t,n\n2021-01-02,2021-01-02 03:04:05,1\n2021-03-04,2021-01-02T03:04:06.5,2\n", {"date_cols": ["d", "t"]})
    rcase("read-opts-dates-z", "opts", "t\n2021-01-02T03:04:05Z\n2021-01-02T03:04:06+02:00\n", {"date_cols": ["t"]})
    rcase("read-opts-dates-mixed", "opts", "t\n2021-01-02\n2021-01-02 03:04:05\n", {"date_cols": ["t"]})
    rcase("read-opts-quote", "opts", "a,b\n'x,y',1\n'it''s',2\n", {"quote": "'"})
    rcase("read-opts-names", "opts", "x,y\n1,2\n", {"names": ["p", "q"]})
    rcase("read-opts-names-nohdr", "opts", "1,2\n3,4\n", {"names": ["p", "q"], "has_header": False})
    # dataframe S2 (2026-11-09)
    rcase("read-s2-thousands", "s2", "a;b\n1,234;5\n-2,000;6\n", {"delimiter": ";", "thousands": ","})
    rcase("read-s2-decimal", "s2", "a;b\n1,5;x\n2,25;y\n", {"delimiter": ";", "decimal": ","})
    rcase("read-s2-decimal-thousands", "s2", "a;b\n1.234,5;x\n2.000,25;y\n", {"delimiter": ";", "decimal": ",", "thousands": "."})
    rcase("read-s2-truev", "s2", "a,b\nyes,1\nno,2\nyes,3\n", {"true_values": ["yes"], "false_values": ["no"]})
    rcase("read-s2-colnull", "s2", "a,b\n1,p\n-,q\n3,r\n", {"column_null_values": {"a": ["-"]}})
    rcase("read-s2-nafilter", "s2", "a,b\n1,NA\n,2\n", {"na_filter": False})
    rcase("read-s2-initspace", "s2", 'a, b\n1, "x,y"\n2,  z\n', {"skipinitialspace": True})
    rcase("read-s2-footer", "s2", "a\n1\n2\n3\n4\n", {"skipfooter": 2})
    rcase("read-s2-skipafter", "s2", "a,b\n1,2\n3,4\n5,6\n", {"skip_rows_after_header": 1})
    rcase("read-s2-rowindex", "s2", "a\nx\ny\n", {"row_index_name": "i", "row_index_offset": 5})
    rcase("read-s2-badlines", "s2", "a,b\n1,2\n3,4,5\n6,7\n", {"on_bad_lines": "skip"})
    rcase("read-s2-datefmt", "s2", "d\n31/12/2021 10:30\n01/02/2022 00:00\n", {"date_cols": ["d"], "date_format": "%d/%m/%Y %H:%M"})
    rcase("read-s2-escape", "s2", 'a\n"x\\"y"\n"p,q"\n', {"escape_char": "\\", "double_quote": False})
    rcase("read-s2-emptynull", "s2", "a,b\nx,p\n,q\n", {"empty_string_is_null": False})


def gen_cases():
    """Random tables of every plain kind, written by Python's csv module, read by both engines."""
    import csv

    alphabet = ["a", "b", "z", " ", ",", '"', "\n", "é", "日", "'", "\\", "-", "1"]
    for seed in range(4):
        r = np.random.RandomState(seed)
        n = 150
        out = io.StringIO()
        w = csv.writer(out, lineterminator="\n")
        w.writerow(["i", "f", "b", "s", "d"])
        for _ in range(n):
            row = []
            row.append("" if r.rand() < 0.1 else int(r.randint(-10**9, 10**9)))
            row.append("" if r.rand() < 0.1 else repr(float(np.round(r.normal(0, 1000), int(r.randint(0, 6))))))
            row.append("" if r.rand() < 0.1 else ("true" if r.rand() < 0.5 else "False"))
            row.append("" if r.rand() < 0.1 else "s" + "".join(r.choice(alphabet, size=int(r.randint(0, 8)))))
            row.append("" if r.rand() < 0.1 else dt.date(2000 + int(r.randint(0, 30)), int(r.randint(1, 13)), int(r.randint(1, 29))).isoformat())
            w.writerow(row)
        rcase(f"read-gen-{seed}", "gen", out.getvalue())
        rcase(f"read-gen-{seed}-dates", "gen", out.getvalue(), {"date_cols": ["d"]})


# ── write cases ─────────────────────────────────────────────────────────────

write_csv_cases = []
write_json_cases = []

EPOCH = dt.datetime(1970, 1, 1)


def to_pd(t):
    d = {}
    for name, ty, vals in t:
        if ty == "text":
            d[name] = pd.Series(vals, dtype="str")
        elif ty == "float":
            d[name] = pd.Series([np.nan if v is None else tofloat(v) for v in vals], dtype="float64")
        elif ty == "int":
            d[name] = pd.Series(pd.array(vals, dtype="Int64")) if any(v is None for v in vals) else pd.Series(np.array(vals, dtype="int64"))
        elif ty == "bool":
            d[name] = pd.Series(pd.array(vals, dtype="boolean")) if any(v is None for v in vals) else pd.Series(np.array(vals, dtype=bool))
        elif ty == "date":
            d[name] = pd.Series(pd.to_datetime([None if v is None else v for v in vals]))
        elif ty == "timestamp":
            d[name] = pd.Series(pd.to_datetime([None if v is None else EPOCH + dt.timedelta(microseconds=v) for v in vals]))
        else:
            raise ValueError(ty)
    return pd.DataFrame(d)


def tofloat(v):
    if v is None:
        return None
    if v == "NaN":
        return float("nan")
    if v == "inf":
        return float("inf")
    if v == "-inf":
        return float("-inf")
    return float(v)


def to_pl(t):
    d = {}
    for name, ty, vals in t:
        if ty == "text":
            d[name] = pl.Series(name, vals, dtype=pl.String)
        elif ty == "float":
            d[name] = pl.Series(name, [tofloat(v) for v in vals], dtype=pl.Float64)
        elif ty == "int":
            d[name] = pl.Series(name, vals, dtype=pl.Int64)
        elif ty == "bool":
            d[name] = pl.Series(name, vals, dtype=pl.Boolean)
        elif ty == "date":
            d[name] = pl.Series(name, [None if v is None else dt.date.fromisoformat(v) for v in vals], dtype=pl.Date)
        elif ty == "timestamp":
            d[name] = pl.Series(name, [None if v is None else EPOCH + dt.timedelta(microseconds=v) for v in vals], dtype=pl.Datetime("us"))
        else:
            raise ValueError(ty)
    return pl.DataFrame(d)


def tbl_json(t):
    n = len(t[0][2]) if t else 0
    return {"columns": [{"name": c, "type": ty} for c, ty, _ in t], "rows": [[enc(t[j][2][i]) if not isinstance(t[j][2][i], str) or t[j][1] != "float" else t[j][2][i] for j in range(len(t))] for i in range(n)]}


def wcase(cid, t, o=None, compare=None):
    """`o`: neutral options: delimiter, header, null_text, quoting (necessary|always|never|non_numeric), crlf, float_precision."""
    o = o or {}
    pdf, plf = to_pd(t), to_pl(t)
    pkw = {"index": False}
    qkw = {}
    if "delimiter" in o:
        pkw["sep"] = o["delimiter"]
        qkw["separator"] = o["delimiter"]
    if o.get("header") is False:
        pkw["header"] = False
        qkw["include_header"] = False
    if "null_text" in o:
        pkw["na_rep"] = o["null_text"]
        qkw["null_value"] = o["null_text"]
    q = o.get("quoting")
    if q:
        import csv
        pkw["quoting"] = {"always": csv.QUOTE_ALL, "never": csv.QUOTE_NONE, "non_numeric": csv.QUOTE_NONNUMERIC}[q]
        qkw["quote_style"] = q
    if o.get("crlf"):
        pkw["lineterminator"] = "\r\n"
        qkw["line_terminator"] = "\r\n"
    if "float_precision" in o:
        pkw["float_format"] = f"%.{o['float_precision']}f"
        qkw["float_precision"] = o["float_precision"]
    if "date_format" in o:
        pkw["date_format"] = qkw["date_format"] = o["date_format"]
    if "datetime_format" in o:
        pkw["date_format"] = qkw["datetime_format"] = o["datetime_format"]
    if "float_scientific" in o:
        qkw["float_scientific"] = o["float_scientific"]
    if "decimal" in o:
        pkw["decimal"] = o["decimal"]
        qkw["decimal_comma"] = o["decimal"] == ","
    if "columns" in o:
        pdf = pdf[o["columns"]]
        plf = plf.select(o["columns"])
    if o.get("include_bom"):
        qkw["include_bom"] = True
    if "escape_char" in o:
        pkw["escapechar"] = o["escape_char"]
        pkw["doublequote"] = False
    p, perr = attempt(lambda: pdf.to_csv(**pkw))
    r, rerr = attempt(lambda: plf.write_csv(**qkw))
    e = {"id": cid, "table": tbl_json(t), "opts": o}
    if perr:
        e["pandas_error"] = perr
    if rerr:
        e["polars_error"] = rerr
    if p is not None:
        e["pandas"] = p
    if r is not None:
        e["polars"] = r
    if p is not None and r is not None:
        bump("write_csv", "both")
        if p == r:
            bump("write_csv", "agree")
            e["engine"] = "both"
            e["expect"] = p
        else:
            lab = label_for(cid)
            if not lab:
                problems.append(f"UNLABELLED WRITE DISAGREEMENT {cid}\n   pandas {p!r}\n   polars {r!r}")
                lab = ("UNLABELLED", "pandas")
            bump("write_csv", "labelled")
            e["label"], e["engine"] = lab
            e["expect"] = p if lab[1] == "pandas" else r
    else:
        e["engine"] = "pandas" if p is not None else "polars" if r is not None else "none"
        bump("write_csv", e["engine"])
        if p is not None or r is not None:
            e["expect"] = p if p is not None else r
        else:
            e["expect_error"] = True
    write_csv_cases.append(e)


def write_csv_cases_all():
    T = lambda *cols: list(cols)
    wcase("write-csv-ints", T(("i", "int", [1, -2, 300, 0])))
    wcase("write-csv-ints_null", T(("i", "int", [1, None, -3]), ("j", "int", [None, None, 5])))
    wcase("write-csv-floats", T(("f", "float", [1.0, 0.1, 100.0, -2.5, 0.30000000000000004, 123456789.12345679, 1234567.0, 0.0001])))
    wcase("write-csv-floats_big", T(("f", "float", [1e15, 9.99e15, 1e16, 1.5e16, 1.2345678901234568e17, 1e22, 1.7976931348623157e308])))
    wcase("write-csv-floats_sci", T(("f", "float", [1e-5, 2.5e-5, 1e-7, 1.5e-7, 1e-10, 5e-324, 1.234e-300])))
    wcase("write-csv-float_nan_inf", T(("f", "float", [float("nan"), float("inf"), float("-inf"), -0.0, 1.5])))
    wcase("write-csv-float_inf", T(("f", "float", [float("inf"), float("-inf"), -0.0, 1.5])))
    wcase("write-csv-float_null", T(("f", "float", [1.5, None, 2.0])))
    wcase("write-csv-bools", T(("b", "bool", [True, False, True])))
    wcase("write-csv-bools_null", T(("b", "bool", [True, None, False])))
    wcase("write-csv-text", T(("s", "text", ["a", "b c", "é€日", "tab\t", "a/b\\c"])))
    wcase("write-csv-text_quotes", T(("s", "text", ["a,b", 'q"x', "line\nbreak", "cr\rcr", " sp ", ";semi"])))
    wcase("write-csv-text_empty", T(("s", "text", ["", "x"]), ("i", "int", [1, 2])))
    wcase("write-csv-text_null", T(("s", "text", ["x", None, "z"]), ("i", "int", [1, 2, 3])))
    wcase("write-csv-single_null", T(("e", "text", ["x", None, "z"])))
    wcase("write-csv-names", T(("a b", "int", [1]), ("c,d", "int", [2]), ('q"', "int", [3]), ("", "int", [4])))
    wcase("write-csv-dates", T(("d", "date", ["2021-01-02", None, "1999-12-31", "2020-02-29"])))
    wcase("write-csv-ts_nofrac", T(("t", "timestamp", [1609556645000000, None, 0])))
    wcase("write-csv-ts_frac", T(("t", "timestamp", [1609556645123456, 1609556645000000, None])))
    wcase("write-csv-ts_ms", T(("t", "timestamp", [1609556645120000, 1609556646000000])))
    wcase("write-csv-mixed", T(("i", "int", [1, 2]), ("f", "float", [1.5, 2.0]), ("b", "bool", [True, False]), ("s", "text", ["x", "y"]), ("d", "date", ["2021-01-02", "2021-01-03"])))
    wcase("write-csv-empty_rows", T(("a", "int", []), ("b", "text", [])))
    wcase("write-csv-opt-semicolon", T(("s", "text", ["a;b", "c,d", "e"]), ("i", "int", [1, 2, 3])), {"delimiter": ";"})
    wcase("write-csv-opt-tab", T(("s", "text", ["a\tb", "c", "e"]), ("i", "int", [1, 2, 3])), {"delimiter": "\t"})
    wcase("write-csv-opt-nohdr", T(("i", "int", [1, 2]), ("s", "text", ["x", "y"])), {"header": False})
    wcase("write-csv-opt-nulltext", T(("i", "int", [1, None]), ("f", "float", [None, 2.5]), ("s", "text", ["x", None])), {"null_text": "NA"})
    wcase("write-csv-opt-always", T(("i", "int", [1, None]), ("f", "float", [1.5, 2.0]), ("s", "text", ["x", None])), {"quoting": "always"})
    wcase("write-csv-opt-never", T(("i", "int", [1, 2]), ("s", "text", ["x", "y z"])), {"quoting": "never"})
    wcase("write-csv-nonnum", T(("i", "int", [1, 2]), ("f", "float", [1.5, 2.0]), ("s", "text", ["x", "y"])), {"quoting": "non_numeric"})
    wcase("write-csv-nonnum_bool", T(("b", "bool", [True, False]), ("s", "text", ["x", "y"])), {"quoting": "non_numeric"})
    wcase("write-csv-nonnum_date", T(("d", "date", ["2021-01-02", "2021-01-03"]), ("s", "text", ["x", "y"])), {"quoting": "non_numeric"})
    wcase("write-csv-opt-crlf", T(("i", "int", [1, 2]), ("s", "text", ["x", "y"])), {"crlf": True})
    wcase("write-csv-opt-prec2", T(("f", "float", [1.0, 0.1, 2.675, 100.0, -3.14159])), {"float_precision": 2})
    wcase("write-csv-opt-prec0", T(("f", "float", [1.5, 2.5, 0.4])), {"float_precision": 0})
    # dataframe S2 (2026-11-09)
    wcase("write-csv-s2-datefmt", T(("d", "date", ["2021-01-02", None, "1999-12-31"])), {"date_format": "%d/%m/%Y"})
    wcase("write-csv-s2-dtfmt", T(("t", "timestamp", [1609556645000000, None, 0])), {"datetime_format": "%Y/%m/%d %H:%M"})
    wcase("write-csv-s2-sci", T(("f", "float", [1234.5, 1e-5, 2.0])), {"float_scientific": True})
    wcase("write-csv-s2-sci_off", T(("f", "float", [1234.5, 1e-5, 2.0, 1e20])), {"float_scientific": False})
    wcase("write-csv-s2-sci_prec", T(("f", "float", [1234.5, 1e-5, 2.0])), {"float_scientific": True, "float_precision": 2})
    wcase("write-csv-s2-decimal", T(("f", "float", [1.5, 0.25, 100.0]), ("i", "int", [1, 2, 3])), {"delimiter": ";", "decimal": ","})
    wcase("write-csv-s2-columns", T(("a", "int", [1, 2]), ("b", "text", ["x", "y"]), ("c", "float", [1.5, 2.5])), {"columns": ["c", "a"]})
    wcase("write-csv-s2-bom", T(("a", "int", [1])), {"include_bom": True})
    wcase("write-csv-s2-esc", T(("s", "text", ['q"x', "plain"])), {"escape_char": "\\", "double_quote": False})


# ── JSON ────────────────────────────────────────────────────────────────────


def jdefault(x):
    if x is None or x is pd.NA or x is pd.NaT:
        return None
    if isinstance(x, pd.Timestamp):
        return str(x.date()) if x == x.normalize() else str(x)
    if isinstance(x, dt.date):
        return x.isoformat()
    return str(x)


def jval(v):
    """Cells of a parsed engine document, normalised."""
    if isinstance(v, float):
        return enc(v) if (math.isnan(v) or math.isinf(v)) else v
    return v


def jcase(cid, t):
    pdf, plf = to_pd(t), to_pl(t)
    e = {"id": cid, "table": tbl_json(t)}
    docs = {}
    # records
    docs["records"] = {
        "pandas": json.loads(pdf.to_json(orient="records")),
        "polars": json.loads(plf.write_json()),
    }
    # columns: a dict of arrays
    docs["columns"] = {
        "pandas": json.loads(json.dumps(pdf.to_dict(orient="list"), default=jdefault, allow_nan=True).replace("NaN", "null")),
        "polars": json.loads(json.dumps(plf.to_dict(as_series=False), default=jdefault, allow_nan=True).replace("NaN", "null")),
    }
    docs["ndjson"] = {
        "pandas": [json.loads(l) for l in pdf.to_json(orient="records", lines=True).splitlines() if l.startswith("{")],
        "polars": [json.loads(l) for l in plf.write_ndjson().splitlines() if l.startswith("{")],
    }
    # the engines' JSON writers print NaN and infinities as null; their dict dumps do not
    def fin(x):
        if isinstance(x, float) and not math.isfinite(x):
            return None
        if isinstance(x, list):
            return [fin(y) for y in x]
        if isinstance(x, dict):
            return {k: fin(y) for k, y in x.items()}
        return x

    docs = {o: {e: fin(v) for e, v in d.items()} for o, d in docs.items()}
    out = {}
    has_date = any(ty == "date" for _, ty, _ in t)
    for orient in ("split", "index", "values", "table"):
        if has_date:
            continue  # pandas writes epoch milliseconds here, the existing label follows polars' ISO text
        out[orient] = {"engine": "pandas", "expect": fin(json.loads(pdf.to_json(orient=orient)))}
    for orient, d in docs.items():
        a, b = d["pandas"], d["polars"]
        bump("write_json", "both")
        if json_same(a, b):
            bump("write_json", "agree")
            out[orient] = {"engine": "both", "expect": a, "pandas": a, "polars": b}
        else:
            lab = label_for(cid)
            if not lab:
                problems.append(f"UNLABELLED JSON DISAGREEMENT {cid}/{orient}\n   pandas {a}\n   polars {b}")
                lab = ("UNLABELLED", "pandas")
            bump("write_json", "labelled")
            out[orient] = {"engine": lab[1], "label": lab[0], "expect": a if lab[1] == "pandas" else b, "pandas": a, "polars": b}
    e["orients"] = out
    write_json_cases.append(e)


json_opts_cases = []
html_cases = []
glimpse_cases = []


def joptcase(cid, t, orient, popts, zopts):
    """Raw text of pandas' `to_json` with options, against `writeJsonOpts`'s."""
    json_opts_cases.append({"id": cid, "table": tbl_json(t), "orient": orient, "opts": zopts, "expect": to_pd(t).to_json(orient=orient, **popts)})


def json_opts_all():
    T = lambda *cols: list(cols)
    txt = T(("s", "text", ["é", "😀z", 'a"b\n', None, "plain"]))
    joptcase("json-opt-ascii", txt, "records", {"force_ascii": True}, {"force_ascii": True})
    joptcase("json-opt-utf8", txt, "records", {"force_ascii": False}, {})
    mix = T(("i", "int", [1, 2]), ("s", "text", ["x", "y"]), ("f", "float", [1.5, 2.5]))
    joptcase("json-opt-indent-records", mix, "records", {"indent": 2}, {"indent": 2})
    joptcase("json-opt-indent-split", mix, "split", {"indent": 4}, {"indent": 4})
    joptcase("json-opt-indent-values", mix, "values", {"indent": 1}, {"indent": 1})
    joptcase("json-opt-indent-index", mix, "index", {"indent": 2}, {"indent": 2})
    joptcase("json-opt-indent-table", mix, "table", {"indent": 2}, {"indent": 2})
    fl = T(("f", "float", [0.30000000000000004, 1.5, 2.0, 1 / 3, 123456.789123, None]))
    joptcase("json-opt-prec3", fl, "records", {"double_precision": 3}, {"double_precision": 3})
    joptcase("json-opt-prec10", fl, "values", {"double_precision": 10}, {"double_precision": 10})
    ts = T(("t", "timestamp", [1609556645678123, None, 0]))
    for unit in ("s", "ms", "us", "ns"):
        joptcase(f"json-opt-epoch-{unit}", ts, "values", {"date_format": "epoch", "date_unit": unit}, {"date_format": "epoch", "date_unit": unit})
    joptcase("json-opt-epoch-date", T(("d", "date", ["2021-01-02", None, "1969-12-31"])), "values", {"date_format": "epoch", "date_unit": "ms"}, {"date_format": "epoch", "date_unit": "ms"})


def htmlcase(cid, t, popts, zopts):
    html_cases.append({"id": cid, "table": tbl_json(t), "opts": zopts, "expect": to_pd(t).to_html(index=False, **popts)})


def glimpsecase(cid, t, zopts=None):
    glimpse_cases.append({"id": cid, "table": tbl_json(t), "opts": zopts or {}, "expect": to_pl(t).glimpse(max_items_per_column=(zopts or {}).get("max_items", 10), return_type="string").rstrip("\n")})


def html_glimpse_all():
    T = lambda *cols: list(cols)
    mixed = T(("a", "int", [1, 2]), ("b", "text", ["x<&>", "y"]), ("f", "float", [1.5, 2.5]), ("t", "bool", [True, False]))
    htmlcase("html-default", mixed, {}, {})
    htmlcase("html-nulls", T(("s", "text", ["x", None]), ("f", "float", [1.5, None])), {}, {})
    htmlcase("html-na_rep", T(("s", "text", ["x", None]), ("f", "float", [1.5, None])), {"na_rep": "-"}, {"null_text": "-"})
    htmlcase("html-float_format", T(("f", "float", [1.23456, 2.5])), {"float_format": "%.2f"}, {"float_precision": 2})
    htmlcase("html-noheader", mixed, {"header": False}, {"header": False})
    htmlcase("html-border", mixed, {"border": 0, "classes": "tbl"}, {"border": 0, "classes": "tbl"})
    htmlcase("html-noescape", mixed, {"escape": False}, {"escape": False})
    htmlcase("html-empty", T(("a", "int", []), ("b", "text", [])), {}, {})
    glimpsecase("glimpse-mixed", T(("a", "int", [1, 2, None]), ("longer", "text", ["x", None, 'z"q']), ("f", "float", [1.5, 2.0, None]), ("b", "bool", [True, False, None]), ("d", "date", ["2021-01-02", None, "2021-01-03"])))
    glimpsecase("glimpse-many", T(("n", "int", list(range(30)))))
    glimpsecase("glimpse-items", T(("n", "int", list(range(30))), ("s", "text", ["w%d" % i for i in range(30)])), {"max_items": 4})


def json_same(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_same(x, y) for x, y in zip(a, b))
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if type(a) != type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        return False
    if isinstance(a, float) != isinstance(b, float):
        return False  # 1 vs 1.0 is a different column type
    return near(a, b)


def write_json_cases_all():
    T = lambda *cols: list(cols)
    jcase("write-json-ints", T(("i", "int", [1, None, -3, 9223372036854775807])))
    jcase("write-json-floats", T(("f", "float", [1.0, 0.1, 1e-5, 0.30000000000000004, 123456789.12345679, 1e16, None])))
    jcase("write-json-float_special", T(("f", "float", [float("nan"), float("inf"), float("-inf"), -0.0, 2.5])))
    jcase("write-json-bools", T(("b", "bool", [True, None, False])))
    jcase("write-json-text", T(("s", "text", ["a,b", 'q"x', "line\nbreak", "tab\t", "a/b\\c", "é€日", "\u0001ctl", None, ""])))
    jcase("write-json-dates", T(("d", "date", ["2021-01-02", None, "1999-12-31"])))
    jcase("write-json-mixed", T(("i", "int", [1, 2]), ("f", "float", [1.5, 2.0]), ("b", "bool", [True, False]), ("s", "text", ["x", None])))
    jcase("write-json-empty", T(("a", "int", []), ("b", "text", [])))
    jcase("write-json-names", T(("a b", "int", [1]), ("c\"d", "int", [2]), ("é", "int", [3])))


def main():
    read_cases_all()
    gen_cases()
    write_csv_cases_all()
    write_json_cases_all()
    json_opts_all()
    html_glimpse_all()
    doc = {
        "engines": {"pandas": pd.__version__, "polars": pl.__version__},
        "read": read_cases,
        "write_csv": write_csv_cases,
        "write_json": write_json_cases,
        "write_json_opts": json_opts_cases,
        "html": html_cases,
        "glimpse": glimpse_cases,
    }
    with open(sys.argv[1], "w") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=True)
    sys.stderr.write(f"pandas {pd.__version__} polars {pl.__version__}: {len(read_cases)} read, {len(write_csv_cases)} write_csv, {len(write_json_cases)} write_json cases\n")
    for g, s in sorted(stats.items()):
        sys.stderr.write(f"  {g}: {s}\n")
    if problems:
        with open(sys.argv[1] + ".report", "w") as f:
            f.write("\n".join(problems))
        sys.stderr.write(f"{len(problems)} UNLABELLED disagreements (see {sys.argv[1]}.report)\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
