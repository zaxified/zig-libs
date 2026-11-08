# `dataframe` verification instruments

Run by hand; no lane needs Python. `CONVENTIONS.md` §9.

| tool | role |
|---|---|
| `filter_vectors.py` | Recipe for `src/oracle_vectors.json`: the cases of `tabular`'s frozen pandas 3.1.0 / polars 2.1.0 vectors for the verbs this module has, and the tables they read. Stdlib only; it filters the frozen file, it does not ask the engines. The engines were asked by `modules/tabular/tools/oracle.py` (its README has the pinned venv). |
| `oracle2.py` | `src/oracle2_vectors.json`: what pandas 3.1.0 and polars 2.1.0 answer for the verbs added in D2, over small generated inputs. 311 *scalar* cases run one cell function (`round`, `round_sig_figs`, `is_close`, the `dt` parts, `strptime`/`strftime`, `offset_by`, `truncate`, business days, the string methods) over a list of cells; 344 *frame* cases run one verb (`fill_null`, `qcut`, `factorize`, `interpolate`, `group_by_dynamic`, `pivot_many`, `dummies`, `join_where`, `merge_ordered`, `transpose`, `peaks`, `aggregate` with `ddof`/quantile methods, `horizontal`, `duplicate_mask`, `top_k`, `rle`, frame arithmetic) over a small table. Every disagreement between the engines carries a label in `LABELS` and the engine followed, or the run fails; an engine that raises on a case is recorded and the other one is the oracle. Needs the pinned venv of `tabular`'s oracle (pandas, polars, numpy, pyarrow). The replay is `src/oracle2_test.zig`; its `known` list holds the differences kept on purpose. |
| `oracle3_io.py` | `src/oracle3_io_vectors.json`: what pandas 3.1.0 and polars 2.1.0 answer for input and output (D3). 114 *read* cases (`read_csv`/`pl.read_csv` over a CSV text and neutral options: type inference token by token, null markers, blanks, big integers, `inf`/`nan`, ragged rows, BOM, quoted newlines, duplicate and empty names, `usecols`, `dtype`, `skiprows`, `nrows`, comments, dates, four generated 150-row tables), 34 *write_csv* cases (`to_csv`/`write_csv` text byte for byte: floats, bools, quoting styles, nulls, dates, timestamps, separators, precision) and 9 *write_json* tables in `records`, `columns` and ndjson. Every disagreement carries a label and the engine followed (`LABELS`), or the run fails; an engine that raises is recorded. Same pinned venv. The replay is `src/oracle3_io_test.zig`. |
| `bench.zig` + `bench_py.py` | `zig build bench-dataframe`: the verbs against pandas (reference) and polars or DuckDB, one thread each, over the tables of `tabular`'s bench (the same generator and seed). The same environment variables as `tabular`'s bench: `BENCH_PY`, `BENCH_ALT`, `BENCH_ROUNDS`, `BENCH_RETAIN`, `BENCH_HUGE`; workload names as arguments filter. Rows: the old `f_` set plus CSV/JSON I/O and ten D2 verbs (counts and the cases where the engines' outputs differ are in the `bench.zig` header). |

```bash
# the venv of tabular's oracle (see modules/tabular/tools/README.md)
python modules/dataframe/tools/oracle2.py modules/dataframe/src/oracle2_vectors.json
python modules/dataframe/tools/oracle3_io.py modules/dataframe/src/oracle3_io_vectors.json
python3 modules/dataframe/tools/filter_vectors.py \
    < modules/tabular/src/oracle_vectors.json > modules/dataframe/src/oracle_vectors.json
```
