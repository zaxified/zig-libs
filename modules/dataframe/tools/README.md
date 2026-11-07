# `dataframe` verification instruments

Run by hand; no lane needs Python. `CONVENTIONS.md` §9.

| tool | role |
|---|---|
| `filter_vectors.py` | Recipe for `src/oracle_vectors.json`: the cases of `tabular`'s frozen pandas 3.1.0 / polars 2.1.0 vectors for the verbs this module has, and the tables they read. Stdlib only; it filters the frozen file, it does not ask the engines. The engines were asked by `modules/tabular/tools/oracle.py` (its README has the pinned venv). |
| `bench.zig` + `bench_py.py` | `zig build bench-dataframe`: the verbs against pandas (reference) and polars or DuckDB, one thread each, over the tables of `tabular`'s bench (the same generator and seed). The same environment variables as `tabular`'s bench: `BENCH_PY`, `BENCH_ALT`, `BENCH_ROUNDS`, `BENCH_RETAIN`, `BENCH_HUGE`; workload names as arguments filter. |

```bash
python3 modules/dataframe/tools/filter_vectors.py \
    < modules/tabular/src/oracle_vectors.json > modules/dataframe/src/oracle_vectors.json
```
