# `tabular` verification instruments

Two instruments (`CONVENTIONS.md` §9), both run by hand. No lane needs Python: the oracle's
answers are frozen and replayed offline.

| tool | role |
|---|---|
| `oracle.py` | Differential oracle: pandas and polars, black box, over generated tables. Writes `src/oracle_vectors.json`, replayed by `src/oracle_test.zig` in the module's own test lane. Every disagreement between the two engines must carry a label and name the engine followed, or the run fails. |
| `bench.zig` + `bench_py.py` | `zig build bench-tabular`: the verbs against pandas (reference) and polars or DuckDB, one thread each, over the same tables. `BENCH_ALT=duckdb` selects DuckDB, `BENCH_ROUNDS=n` the rounds, `BENCH_RETAIN=1` an arena kept across calls. `BENCH_HUGE=1` a fresh arena over `dataset.big_block_allocator`. Workload names as arguments filter. |

## The environment

Pinned wheels only, no source builds (`--only-binary`), in the droppable cache:

```bash
python3 -m venv .zig-cache/tabular-oracle-venv
.zig-cache/tabular-oracle-venv/bin/pip install --only-binary :all: \
    pandas==3.1.0 polars==2.1.0 duckdb==2.0.0 pyarrow==26.0.0 numpy==2.5.4
```

pandas is BSD-3-Clause, polars and DuckDB MIT, pyarrow Apache-2.0, numpy BSD-3-Clause; none of
their source was read or copied, and no output of theirs other than the vectors is committed.
`pyarrow` is there because pandas 3's `str` dtype is at its fastest on it, the fair reference.

## Re-taking the vectors

```bash
.zig-cache/tabular-oracle-venv/bin/python -W ignore modules/tabular/tools/oracle.py \
    > modules/tabular/src/oracle_vectors.json
zig build test-tabular
```

The tables come from a fixed `numpy` seed; the frozen file records the engine versions. The
vectors contain generated numbers and short made-up words only, so no outside data licence
applies. Only columns a verb made or was told about are frozen, plus a row id: the rest is input
passing through and would only make the file bigger.
