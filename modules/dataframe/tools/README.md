# `dataframe` verification instruments

Run by hand; no lane needs Python. `CONVENTIONS.md` §9.

| tool | role |
|---|---|
| `oracle.py` + `filter_vectors.py` | Recipe for `src/oracle_vectors.json`: `oracle.py` (written for `tabular`, moved here when step R retired it, 2026-11-08) asks pandas 3.1.0 and polars 2.1.0 over generated tables — every disagreement between the engines carries a label and the engine followed, or the run fails; `filter_vectors.py` (stdlib only) keeps the cases of the verbs this module has and the tables they read. The replay is `src/oracle_test.zig`. |
| `oracle2.py` | `src/oracle2_vectors.json`: what pandas 3.1.0 and polars 2.1.0 answer for the verbs added in D2, over small generated inputs. 311 *scalar* cases run one cell function (`round`, `round_sig_figs`, `is_close`, the `dt` parts, `strptime`/`strftime`, `offset_by`, `truncate`, business days, the string methods) over a list of cells; 344 *frame* cases run one verb (`fill_null`, `qcut`, `factorize`, `interpolate`, `group_by_dynamic`, `pivot_many`, `dummies`, `join_where`, `merge_ordered`, `transpose`, `peaks`, `aggregate` with `ddof`/quantile methods, `horizontal`, `duplicate_mask`, `top_k`, `rle`, frame arithmetic) over a small table. Every disagreement between the engines carries a label in `LABELS` and the engine followed, or the run fails; an engine that raises on a case is recorded and the other one is the oracle. Needs the pinned venv below (pandas, polars, numpy, pyarrow). The replay is `src/oracle2_test.zig`; its `known` list holds the differences kept on purpose. |
| `oracle3_io.py` | `src/oracle3_io_vectors.json`: what pandas 3.1.0 and polars 2.1.0 answer for input and output (D3). 114 *read* cases (`read_csv`/`pl.read_csv` over a CSV text and neutral options: type inference token by token, null markers, blanks, big integers, `inf`/`nan`, ragged rows, BOM, quoted newlines, duplicate and empty names, `usecols`, `dtype`, `skiprows`, `nrows`, comments, dates, four generated 150-row tables), 34 *write_csv* cases (`to_csv`/`write_csv` text byte for byte: floats, bools, quoting styles, nulls, dates, timestamps, separators, precision) and 9 *write_json* tables in `records`, `columns` and ndjson. Every disagreement carries a label and the engine followed (`LABELS`), or the run fails; an engine that raises is recorded. Same pinned venv. The replay is `src/oracle3_io_test.zig`. |
| `bench.zig` + `bench_py.py` | `zig build bench-dataframe`: the verbs against pandas (reference) and polars or DuckDB, one thread each, over the tables `tabular`'s bench used (the same generator and seed). Environment variables: `BENCH_PY`, `BENCH_ALT`, `BENCH_ROUNDS`, `BENCH_RETAIN`, `BENCH_HUGE`; workload names as arguments filter. Rows: the old `f_` set plus CSV/JSON I/O and ten D2 verbs (counts and the cases where the engines' outputs differ are in the `bench.zig` header). |

## The environment

Pinned wheels only, no source builds (`--only-binary`), in the droppable cache (the path keeps
the name it had under `tabular`, which `BENCH_PY` defaults to):

```bash
python3 -m venv .zig-cache/tabular-oracle-venv
.zig-cache/tabular-oracle-venv/bin/pip install --only-binary :all: \
    pandas==3.1.0 polars==2.1.0 duckdb==2.0.0 pyarrow==26.0.0 numpy==2.5.4
```

pandas is BSD-3-Clause, polars and DuckDB MIT, pyarrow Apache-2.0, numpy BSD-3-Clause; none of
their source was read or copied, and no output of theirs other than the vectors is committed.

## Re-taking the vectors

```bash
PY=.zig-cache/tabular-oracle-venv/bin/python
$PY -W ignore modules/dataframe/tools/oracle.py \
  | python3 modules/dataframe/tools/filter_vectors.py > modules/dataframe/src/oracle_vectors.json
$PY modules/dataframe/tools/oracle2.py modules/dataframe/src/oracle2_vectors.json
$PY modules/dataframe/tools/oracle3_io.py modules/dataframe/src/oracle3_io_vectors.json
```

`oracle2b.py` (dataframe S2 wave W3): the same idea for constructors, small Expr functions, name verbs and column functions; `python tools/oracle2b.py src/oracle2b_vectors.json`, replayed by `src/s2w3_oracle_test.zig`.
