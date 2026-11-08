# `dataframe` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — FASTER (no output change): `concatByName` and so `concat(.vertical/.vertical_relaxed/.diagonal)` stack a column whose non-null cells are one kind (or none) straight from the typed arrays and validity bitmaps instead of through boxed cells; a boxed piece or mixed kinds take the cell path as before. `bench-dataframe` `concat` 4.8x to about 2.3x pandas (the rest is first-touch page faults on 150 MB of output). `d4b_test.zig` compares both paths.
- **2026-11-08** — FASTER (no output change): `joinAsof` without `by` over plain int or plain float `on` columns of one kind reads the arrays directly (no boxed key rows) and gallops from the previous position when the left side ascends; `bench-dataframe` `join_asof` 18.0x to 0.92x pandas. Any other storage takes the cell path as before; `d4b_test.zig` compares both.
- **2026-11-08** — FIXED (speed, no API change): `big_block_allocator` no longer stalls. It advised every 2 MiB block `MADV_HUGEPAGE`, which under `transparent_hugepage/defrag` = `always`, `madvise` (the usual default) or `defer+madvise` makes each fault compact memory directly; on a fragmented host 1 GiB took 2.1-5.6 s against 0.54-0.61 s for `page_allocator` (2472 failed compaction stalls). The advice is now given only under `defer` or `never`, read once from sysfs; blocks stay 2 MiB-aligned, so `enabled=always` still gives huge pages. `bench-dataframe` `mutate`/`cumsum`/`filter`: big-block arena now level with `page_allocator`.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: `bench-dataframe` `concat` asks polars for `rechunk=True`, a materialized result like ours and pandas' (without it polars returned two chunks by reference: 1 ms against 230 ms for pandas).
- **2026-11-08** — BENCH: verb rows `fill_null`, `join_asof`, `top_k`, `win_shift`, `win_rank`,
  `value_counts`, `describe`, `concat`, `str_contains`, `strptime` against pandas and polars
  (DuckDB where it has a like-for-like form). Tooling only, no `src/` change.

- **2026-11-08** — BENCH (`tools/bench.zig`, `tools/bench_py.py`): I/O rows over table L
  (`read_csv`, `write_csv`, `write_json` records, `write_ndjson`) against pandas and polars;
  writers count the output byte length. Tooling only, no `src/` change.

- **2026-11-07** — FIXED from the independent D3 review: `readCsv` capped each text
  column's up-front reservation at its share of the input (a wide first row of long cells
  over short rows reserved ~1000x the input); ADDED `CsvReadOptions.max_quoted_lines` (no
  line cap under `strict_quotes`, so a `writeCsv` cell of more than 64 lines reads back);
  `markdownTo` sizes its grid with checked arithmetic; a `format` cut where text stops being
  UTF-8 keeps whole code points; a `.decimal` override takes zeros past 12 fraction digits;
  pass 1 types a float with the same parse as pass 2. SPEC limits/memory claims corrected.
  Tests in `src/io_test.zig`.

- **2026-11-07** — FIXED `format` with `max_rows` or `max_cols` = `maxInt(usize)`
  overflowed computing the head half (`n + 1`); now `n / 2 + n % 2`. Test in `src/io_test.zig`.

- **2026-11-07** — ADDED text rendering (D3, survey row 77): `format` (pandas
  `to_string(index=False)` with polars' `…` elision of rows and columns) and `toMarkdown`
  (a pipe table as `tabulate` lays it out); tests `src/io_test.zig` and the oracle replay
  `src/oracle3_io_test.zig` (114 read, 34 write_csv and 9 JSON cases against pandas 3.1.0
  and polars 2.1.0).

- **2026-11-07** — ADDED JSON output (D3, survey row 74): `writeJson` (`records`, `columns`)
  and `writeNdjson` with `dataset.frameToJson`'s number and string rules (NaN and infinities
  `null`, invalid UTF-8 replaced); floats keep a fractional digit as in both engines.

- **2026-11-07** — ADDED CSV input and output (D3, survey row 73): `readCsv`, `readCsvReader`,
  `writeCsv` over the sibling `csvstream` (new production dependency), `CsvReadOptions`,
  `CsvWriteOptions`, `pandas_na_values`, `polars_na_values`. Types inferred from all cells;
  `max_bytes`, `max_columns`, `max_cell_bytes`, `max_record_bytes`, `max_rows`, `max_cells`
  each answer a dedicated error. Checked against 114 `read_csv` and 34 `to_csv` cases of
  pandas 3.1.0 and polars 2.1.0 (`src/oracle3_io_vectors.json`, `tools/oracle3_io.py`).
- **2026-11-07** — **BEHAVIOURAL, not breaking** (unreleased D2 code, independent review): no consumer-reachable trap or hang in `round` (`decimals` at minInt(i32), decimals below -308, i128 edges), `gatherEvery` (a step near maxInt), `repeat` (empty text, huge count); `qcut` sorts once instead of a selection per edge; `hstack` validates and allocates once; `transpose` refuses more than `max_transpose_width` output columns (`error.TooLarge`); float `round` scales by correctly rounded powers of ten (`round(0.9e308, -308)` is `1e308`, it was `1.0000000000000006e308`).
- **2026-11-07** — **BEHAVIOURAL, not breaking** (unreleased D2 code, found by the new
  pandas/polars vectors `src/oracle2_vectors.json`, `tools/oracle2.py`): `round_sig_figs`
  ties go away from zero; `slice` with a negative offset past the start shortens the
  window; `fillNull(.mean)` of an int column stays int (mean cut toward zero), `.zero`
  fills "" and False, `.one` True; `title` keeps non-ASCII letters inside a word;
  `replace_many` takes the match that ends first, of those the longest; `translateFormat`
  accepts `[` and `]` as literals and writes `%Z` as `UTC`; `truncate` counts weeks from
  Monday 1970-01-05; `peaks` is three-valued (null for a missing cell, unknown next to
  one); `mergeOrdered` with `fill_forward` fills only the cells the join left empty.

- **2026-11-07** — ADDED `arith`, `arithScalar`, `compare`, `dot`, `interpolate`
  (linear/nearest, by position or by a column), `groupByDynamic`, `upsample`,
  `pivotKeys` (survey rows 19, 20, 26, 51, 53); `Expr`'s `binaryValue`.

- **2026-11-07** — ADDED D2 wave W4: `groupFilter`, `ngroup`, `joinWhere`,
  `mergeOrdered`, `mergeSorted`, `pivotMany`, `dummies`, `combineFirst`, `update`,
  `repeatRows`, `scatter`, `dropNans`, `matchToSchema`, `toFloatMatrix`, `hashRows`,
  `betweenTime`; `rle`, `rleId`, `peaks`, `autocorr`, `entropy`, `nanExtreme`,
  `extremeBy`, `nUnique`, `firstValid`, `lastValid`, `argTrue`, `argUnique`,
  `asofIndex`, `extendConstant`; `WinFn` gains `prod`, `sem`, `skew`, `kurt`, `first`,
  `last`, `nunique`, `quantile`, and `Rolling`/`RollingTime`/`expanding` take `q` and
  `ddof`. FIXED (unreleased code): `Binary.tail` with `minInt(i64)` overflowed.

- **2026-11-07** — ADDED the `dt` accessor and temporal parse/format (D2 wave W3, survey
  rows 95, 98, 99): `Expr` gains `dt` (33 `DtPart` components), `strptime` and
  `strftime` with pandas'/polars' `%` directives, `offset_by` and `truncate` with
  polars' duration strings, `add_business_days`; `parseDuration`, `translateFormat`.
  New production dependency: `datefmt`.

- **2026-11-07** — ADDED the survey's frame-structure and analysis rows (D2, waves W1 and
  W2): `clone`, `clear`, `take`, `gatherEvery`, `reverse`, `insertColumn`, `hstack`,
  `replaceColumn`, `popColumn`, `addAffix`, `Selector` with `selectBy`/`selectColumns`,
  `nullCount`, `hasNulls`, `info`, `estimatedSize`, `columnBytes`, `equals`,
  `transpose`, `concat` (vertical, vertical_relaxed, diagonal, horizontal);
  `duplicateMask`, `horizontal`, `fillNull`, `replaceStrict`, `argSort`, `isSorted`,
  `searchSorted`, `indexOf`, `factorize`, `topK`, `qcut`; `AggCol.ddof`,
  `.interpolation`, `.min_count`; `DropNaSpec.thresh`; `Expr` gains `round`,
  `round_sig_figs`, `is_close`, `pad`, `slice`, `strip_chars`, `translate`,
  `to_integer`, `contains_any`, `replace_many`, 45 `Unary` and 18 `Binary` operators
  (math, NaN tests, bitwise, string methods). Additive: every default keeps the old
  behaviour.

- **2026-11-07** — **DOCS:** SPEC Backlog lists the review's remaining LOW nits (L10).
- **2026-11-07** — **BEHAVIOURAL, not breaking:** fixes from the independent review.
  `cumsum` and `rolling` follow pandas and polars (a missing cell is skipped and its row
  is null, a short window is null, an int `cumsum` stays int; both are `window` now and
  return `WindowError`); `distinct(.keep = .last)` keeps rows in input order; a suffixed
  join column that collides with a left name is numbered; a decimal casts to text
  exactly; pivot column keys read numbers as `cast` does; `aggregate` with
  `drop_missing_keys` and no group columns keeps its row; a huge `FrameBuilder` hint is
  clamped to `max_row_hint` instead of overflowing; `big_block_allocator` frees with the
  alignment it allocated with.

- **2026-11-07** — ADDED `resample` (day, week, month, quarter, year) and `reduce` on
  `Frame`, as `tabular`'s row verbs: every verb `tabular` has as a row verb is now here,
  except the compositions listed in SPEC § Backlog.

- **2026-11-07** — ADDED the rest of `tabular`'s verbs on `Frame`: `page`, `tail`, `topN`,
  `nlargest`, `sample`, `concatByName`, `partitionBy`, `valueCounts`, `describe`, `clip`,
  `replace`, `cut`, `joinAsof`. The oracle replays all 1353 pandas/polars cases.

- **2026-11-07** — ADDED `mutate`, `where`, `cast` (the `Expr` tree of `tabular.expr`,
  evaluated over the columns it names) and `window` (every operation of
  `tabular.window`, per group or not) on `Frame`. The oracle replays 1281 pandas/polars
  cases, every one run.

- **2026-11-07** — New module: a columnar dataframe, `Frame`, with `dataset`'s storage
  and `tabular`'s `frame` verbs (`map`, `cumsum`, `rolling`, `filter`, `distinct`,
  `aggregate`, `unpivot`, `join`), plus `sort`, `dropna`, `fillna`, `pivot`, `select`,
  `drop`, `rename` on `Frame`. Verified against `tabular`'s row verbs over generated
  tables and against 570 frozen pandas 3.1.0 / polars 2.1.0 answers.
