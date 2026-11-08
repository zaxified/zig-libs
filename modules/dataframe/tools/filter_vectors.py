#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/oracle_vectors.json`: the cases of `oracle.py`'s pandas and polars
vectors (written for `tabular`, moved here with step R, see `tools/README.md`) for the
verbs `dataframe` has, and the tables they read. Stdlib only, no engine needed: it filters
the oracle's output, it does not re-ask the engines.

    python modules/dataframe/tools/oracle.py \
      | python3 modules/dataframe/tools/filter_vectors.py > modules/dataframe/src/oracle_vectors.json

Add a verb to VERBS when `dataframe` gains it, and rerun.
"""
import json
import sys

VERBS = {
    "aggregate", "sort", "join", "pivot", "melt", "distinct", "dropna", "mutate", "where", "cast",
    "window", "nlargest", "asof", "fillna", "value_counts", "describe", "clip", "replace", "cut",
    "tail", "concat",
}

doc = json.load(sys.stdin)
cases = [c for c in doc["cases"] if c["verb"] in VERBS]
used = set()
for c in cases:
    used.add(c["table"])
    if "right" in c:
        used.add(c["right"])
out = {k: v for k, v in doc.items() if k not in ("tables", "cases")}
out["filtered_by"] = "modules/dataframe/tools/filter_vectors.py"
out["tables"] = {k: v for k, v in doc["tables"].items() if k in used}
out["cases"] = cases
json.dump(out, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
