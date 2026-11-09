#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the chunked CSV reader of dataframe S2 wave W9: what pandas 3.1
(`read_csv(chunksize=)`) and polars 2.1 (`read_csv` with `infer_schema_length`, with and without
`ignore_errors`) answer, frozen into src/oracle2h_vectors.json and replayed by
src/s2w9_oracle_test.zig. No line of dataframe is consulted here.

    python tools/oracle2h.py src/oracle2h_vectors.json      (see tools/README.md)

A pandas case lists the chunks with each column's kind (`int`, `float`, `bool`, `text`) and cells;
a polars case says whether the read raised, and the cells when it did not. polars' own batched
reader sizes its batches by bytes, so the polars cases ask for the one thing the chunk reader
shares with it: the types are fixed from the first `infer_schema_length` rows.
"""
import io
import json
import math
import sys

import numpy as np
import pandas as pd
import polars as pl

cases = []
problems = []


def kind(dt):
    s = str(dt).lower()
    if s.startswith("int"):
        return "int"
    if s.startswith("float") or s == "f64":
        return "float"
    if s in ("bool", "boolean"):
        return "bool"
    return "text"


def cell(v):
    if v is None or v is pd.NA:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        return None if math.isnan(v) else float(v)
    return str(v)


def pd_case(id, text, **kw):
    try:
        chunk = kw.pop("chunksize")
        out = []
        for df in pd.read_csv(io.StringIO(text), chunksize=chunk, **kw):
            out.append({
                "kinds": [kind(df[c].dtype) for c in df.columns],
                "cols": [[cell(v) for v in df[c]] for c in df.columns],
            })
        cases.append({"id": id, "engine": "pandas", "text": text, "chunk": chunk,
                      "opts": {k: v for k, v in kw.items()}, "chunks": out})
    except Exception as e:  # noqa: BLE001
        problems.append(f"{id}: {type(e).__name__}: {str(e)[:160]}")


def pl_case(id, text, infer, ignore):
    try:
        try:
            df = pl.read_csv(io.BytesIO(text.encode()), infer_schema_length=infer, ignore_errors=ignore)
            res = {"error": False, "cols": [[cell(v) for v in df[c]] for c in df.columns],
                   "kinds": [kind(df[c].dtype) for c in df.columns]}
        except Exception as e:  # noqa: BLE001
            res = {"error": True, "why": type(e).__name__}
        cases.append({"id": id, "engine": "polars", "text": text, "infer_rows": infer,
                      "ignore_errors": ignore, **res})
    except Exception as e:  # noqa: BLE001
        problems.append(f"{id}: {type(e).__name__}: {str(e)[:160]}")


pd_case("pd-int-then-float", "a\n1\n2\n3.5\n4\n", chunksize=2)
pd_case("pd-int-then-text", "a\n1\n2\nx\ny\n", chunksize=2)
pd_case("pd-bool-then-text", "a\ntrue\nfalse\nmaybe\ntrue\n", chunksize=2)
pd_case("pd-int-hole-float", "a,b\n1,x\n,y\n3,z\n4,w\n", chunksize=2)
pd_case("pd-chunk-larger-than-input", "a,b\n1,x\n2,y\n", chunksize=10)
pd_case("pd-nrows-total", "a\n1\n2\n3\n4\n5\n", chunksize=2, nrows=3)
pd_case("pd-bad-lines-skip", "a\n1\n2,9\n3\n4\n5\n", chunksize=2, on_bad_lines="skip")
pd_case("pd-quoted-newline", "a,b\n1,\"x\ny\"\n2,z\n3,w\n", chunksize=2)
pd_case("pd-skiprows", "junk\na\n1\n2\n3\n", chunksize=2, skiprows=1)
pd_case("pd-comment-lines", "a\n1\n#c\n2\n3\n", chunksize=2, comment="#")
pd_case("pd-header-only", "a,b\n", chunksize=2)

pl_case("pl-later-float-in-int", "a\n1\n2\n3.5\n", 2, False)
pl_case("pl-later-float-in-int-ignore", "a\n1\n2\n3.5\n", 2, True)
pl_case("pl-later-text-in-int", "a,b\n1,x\n2,y\nabc,z\n", 2, False)
pl_case("pl-later-text-in-int-ignore", "a,b\n1,x\n2,y\nabc,z\n", 2, True)
pl_case("pl-infer-all-sees-float", "a\n1\n2\n3.5\n", 3, False)
pl_case("pl-later-text-in-float-ignore", "a\n1.5\n2.5\nabc\n4\n", 2, True)

out = sys.argv[1] if len(sys.argv) > 1 else "oracle2h_vectors.json"
with open(out, "w") as fh:
    json.dump(cases, fh, indent=0, ensure_ascii=False)
    fh.write("\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
