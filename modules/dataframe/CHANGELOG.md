# `dataframe` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — ADDED: time zones in `Expr` over the sibling `tz` module — `to_local` (a UTC instant as an IANA zone's wall clock: polars `convert_time_zone`, pandas `tz_convert`) and `from_local` (a wall-clock time read in a zone as its UTC instant: polars `replace_time_zone`, pandas `tz_localize`) with a fold/gap `policy` (`compatible`, `earlier`, `later`, `null`); an unknown zone is `error.BadExpr`. New production dependency: `tz`.
- **2026-11-08** — ADDED: `Selector.matches` (polars `cs.matches`, pandas `filter(regex=)`): columns whose name the pattern matches, compiled once per call; a bad pattern is the new `StructureError.BadPattern` (`BadArgument` through the reshape verbs).
- **2026-11-08** — ADDED: regex string functions in `Expr` — `contains_regex`, `extract` (a group of the first match), `count_regex`, `replace_regex` (first or all, `$1`/`${name}` templates or literal) — over the sibling `regex` module in its Rust grammar (polars' own), linear time for any pattern and text; a pattern it refuses is the new `error.BadPattern`. New production dependency: `regex`.
- **2026-11-08** — FIXED: `arith`/`arithScalar` panicked ("access of union field 'int' while field 'decimal' is active") when a result column mixed int and decimal cells: the int was read after the cell had been retagged decimal. Found by the D5 mutation run (agent MA); the same write shape in `horizontal` was rewritten too (there a by-value call copied first, so it did not misread).
- **2026-11-08** — FIXED (unreleased `readJson`): an integer past i64 makes the column text, as in `readCsv` (it was read as a float); `max_cell_bytes` now caps a string, number or key with no escape too (`std.json` caps only what it copies).
- **2026-11-08** — FIXED: verbs that build a validity bitmap from all-set words (`map`, `take` with nulls, joins' missing rows…) no longer leave bits set past the last row; a consumer counting the public `valid` words saw more rows than the frame has (found as a statistic by the fuzz driver).
- **2026-11-08** — ADDED (test): `src/fuzz.zig`, the module's first fuzz harness and deterministic driver (`DATAFRAME_FUZZ=<runs>[,<seed>]`, `testkit` as a test dependency): the CSV reader on generated and damaged bytes with random options (one-pass against the two-pass reference, `writeCsv` round trip), random frames through 1..4 of 27 verbs with random specs (typed path against its `*Cells` reference, results checked for well-formedness), the writers (JSON and NDJSON parsed back, `format`, Markdown, CSV), and all three again over an allocator that fails from a drawn allocation on. 1.5 M runs in 23 s on 5 jobs, ReleaseSafe: no crash, leak or hang. No production code changed.
- **2026-11-08** — ADDED: `readJson` (`records` and `columns` orients) and `readNdjson`, the reverse of `writeJson`/`writeNdjson`: columns in the order their keys first appear, types by `readCsv`'s rules on the same text (a mix of kinds or a nested value is text from the JSON source), a missing key is null, a repeated key keeps its last value, `columns`/`types`/`parse_dates`/`n_rows` and byte, column, row, cell and cell-size limits; what `writeJson`/`writeNdjson` write reads back equal.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: whole-module mutation run, group MA (`verbs keys core frame value spec frameops structure reshape`): `src/mut_ma_test.zig` adds one test per surviving non-equivalent mutant (names end `(mut <id>)`): boundaries of the `max_*` limits, hand-built frames whose arrays are shorter or longer than `len`, `compare`/`equals`/`interpolate`/`betweenTime` edges, `min_count`, selectors, dummies. One defect found and NOT fixed here (a test would crash the run): `arith` over a result column mixing int and decimal cells panics in `resultType` (`frameops.zig:71`).

- **2026-11-08** — FIXED: the per-name hash lookups added by the S2 sweep are freed after use (they were never released, so a non-arena allocator leaked one table per call); the two sweep branches' lookups are one type, `frame.NameIndex`.
- **2026-11-08** — FIXED: `transpose` of a frame whose number columns hold a text or bool cell (a declared type the builder does not check) panicked in safe builds (`asFloat().?`); the cell now stays as it is.
- **2026-11-08** — FIXED: a `Selector` graph that shares a node deep (any_of/all_of/not through the same pointer) was walked as a tree, 2^depth visits; `selectColumns` now refuses past `max_selector_visits` (4096) nodes per column and for the name check (`error.BadArgument`, as a depth past `max_selector_depth`).
- **2026-11-08** — CHANGED (limit): `pivotMany` and `pivotKeys` cap all value blocks together at `max_pivot_cells`, `dummies` all encoded columns together at `max_aggregate_cells` (`error.TooLarge`); each was capped per block before, so repeating a value or column multiplied the cap. `arith`, `combineFirst` and `concat(.horizontal)` pad a shorter frame to a taller one only up to `max_join_cells` cells beyond the inputs' own (before, 301 columns by 60 000 rows from 60 000 cells in).
- **2026-11-08** — FIXED: `matchToSchema` with `cast` converts each column on its own (it copied the schema and every array of the frame per cast column: O(schema x width) arena memory), and name lookups no longer scan the columns per name in `join`/`joinWhere` suffixes, `arith`, `combineFirst`, `update`, `mergeOrdered(fill_forward)`, `matchToSchema`, `select`, `drop`, `distinct`, `dropna` and the duplicate check of `concat(.vertical)` (a 20 000-column frame took 10 to 76 s per verb; now milliseconds). `sortedRows` checks the `u32` row limit itself.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: the `u32` row-index limit (`TooLarge` for a frame of `maxInt(u32)` rows or more) is one helper, `core.checkRowsU32`, called at the entry of every verb that builds row indexes; `src/sweep_s1_test.zig` calls 47 of them with a hand-built frame of that size and a 64 KiB allocator.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: SPEC records the D5 sweep (S2) limits and closed findings; `readCsvReader` peaks at about 3 x `max_bytes` in an arena (documented, `max_bytes` is the dial); window quantile/median/nunique work is the visit cap times a log factor (documented).
- **2026-11-08** — FIXED: the `is_in` set's key-length prefix is a checked u32 (a canonical key of 4 GiB or more is `error.TooLarge`, it was an unchecked `@intCast`).
- **2026-11-08** — FIXED: resolving a spec's names against a wide frame is one hash lookup each, not a column scan each: `concatByName` (per frame, per output column), `joinAsof` suffix scan and `by` names, `fillNull`/`duplicateMask`/`horizontal`/`factorize`/`topK` subsets and `sort` keys of `argSort`, `window` `partition_by`, `describe`, `partitionBy`, `valueCounts` (all were width x width: minutes at 50 000 columns).
- **2026-11-08** — FIXED: `contains`, `find`, `rfind` and `count_matches` between two text columns search a needle of more than 64 bytes in O(text + needle) (Knuth-Morris-Pratt), they were O(text x needle) with `std.mem.find`: two 1 MiB cells took 2^40 steps.
- **2026-11-08** — FIXED: `mutate` and `where` refuse with `error.TooLarge` once the cells of one assignment have allocated `max_eval_bytes` (2^30) in all (`repeat` of 1 MiB over a thousand rows was a gigabyte-scale allocation); one cell is still bounded by `max_text_result`. Exported as `max_eval_bytes`.
- **2026-11-08** — FIXED: `max_window_work` and `max_rolling_work` bound the whole `rolling`/`expanding`/`rolling_time` call, summed over its partitions (the cap held per partition: 20 partitions each under it ran 20x over); `rolling` and `expanding` are refused before any partition is computed.
- **2026-11-08** — FIXED: `fillNull` clears the validity bits past the last row of its result (it copied the input's last word whole); `readCsv` on blank lines, comments or quoted newlines over a wide header no longer reserves a row per newline for every column (memory proportional to the input: the two-pass reader runs when rows x columns exceeds the input's length), and its second pass falls back to the cell path instead of `unreachable`; the `RecordTooLarge` doc says what the reader answers (`UnterminatedQuote` for a quoted field open at the cap).
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: SPEC records the D3 reader/writer defaults as decided (`parse_dates` off, integers past i64 as text, JSON timestamps as RFC 3339 `…Z`) with the reasons.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: card Performance line measured (33 `bench-dataframe` rows after the D4 typed kernels: 0.11–2.71x pandas, 6 rows over 1.1x, all fresh-page-fault bound; 1.14x worst over `huge_page_allocator`).
- **2026-11-08** — ADDED: `huge_page_allocator`, `big_block_allocator` with `MADV_HUGEPAGE` on every 2 MiB+ block whatever `defrag` says (numpy's, so pandas', policy): faster where huge pages are at hand, the measured stall on a fragmented `defrag=madvise` host otherwise; the caller chooses, the default stays `big_block_allocator`. `bench-dataframe` `BENCH_HUGE=always` runs over it.
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: `src/d4c_test.zig` adds a `fillNull` forward/backward differential over gappy float/int columns with NaN and `limit`s around the word size (typed path against `test_hooks.fillNullCells`). A word-wise fill of mixed validity words was tried and dropped: `fill_null` stays ~6.4 ms because the 8 MB output's first-touch page faults dominate, not the fill.
- **2026-11-08** — FASTER (no output change): `mutate` of `col contains/starts_with/ends_with "literal"` over a plain text column (the whole expression, no `type`) reads the offsets and bytes directly and writes the bool array and validity bits, instead of one boxed evaluation per row; a null cell gives null, an all-null result is `.nulls` typed float, as before. Other expressions and column kinds keep the evaluator. `bench-dataframe` `str_contains` 3.2x to 0.45x pandas. `src/d4c_test.zig` compares it with `expr.test_hooks.mutateCells`.
- **2026-11-08** — FASTER (no output change): `readCsv` without `parse_dates` reads the file once: each inferred column starts as int, widens to float in place, or is text, and stores into typed arrays directly (no boxed cells, no `FrameBuilder`); a column that would turn out text/bool/too-big-int after numbers were stored, or `-0` in an int column, sends the read back to the two-pass way (whose second pass is typed as well). Null-marker check by length and first byte before the 19-way compare, one-pass int parse, and Clinger's fast path for plain decimals (up to 15 digits, bit-identical to `parseFloat`). `bench-dataframe` `read_csv` at 1 M x 8: 4.5x to 1.02x pandas. `src/d4c_test.zig` compares it with `test_hooks.readCsvCells` (1200 random CSVs: options, overrides, ragged rows, quoting, nulls; plus parser-level differentials).
- **2026-11-08** — FASTER (no output change): `join` (`left`/`inner`, probing the left side) on a right side with no repeated key builds the row pairs in one pass over the probe hits, with no member lists, no counting pass and, for `left`, no left row index (the left columns are shared as before). Other joins keep the member-list pairs. `bench-dataframe` `join_left` 1.23x -> 0.89x pandas, `join_inner` 1.13x -> 0.99x. `d4d_test.zig` compares it with `verbs.test_hooks.joinCells`.
- **2026-11-08** — FASTER (no output change): `window` `shift` by one row either way over a plain int or float column with a partition key makes one pass over the rows, each group carrying the cell of its previous (next) row, instead of gathering the partitions and scattering the result; `aggregate` `count` and `size` count from the group ids (and the column's array and validity bits for `count` with `skip_na`) instead of building boxed key rows of the source column. `bench-dataframe` `win_shift` 1.23x -> 0.36x pandas, `group_stats` 1.12x -> 0.53x. `d4d_test.zig` compares both with the cell paths (`window.test_hooks.windowCells`, `verbs.test_hooks.aggregateCells`).
- **2026-11-08** — FASTER (no output change): `sort` builds the key words of a plain int or float column straight from its array, skips the missing-cell pass for a plain column that has nothing to flag (it was a random read of every cell after each key's radix sort), and `take` of a plain typed column prefetches the source 16 rows ahead. `bench-dataframe` `sort_float` 1.23x -> ~1.13x pandas (the rest: output page faults and 8 radix passes). `d4d_test.zig` compares it with `verbs.test_hooks.sortCells`.
- **2026-11-08** — FASTER (no output change): `unpivot` repeats a plain typed id column straight from its array (no 2M-entry row index unless another id column needs it) and weaves melted columns that are all one plain typed kind (int, bool, decimal as float already was) without boxed cells. `bench-dataframe` `melt` 44 -> 36 ms (1.22x to ~1.0x pandas; the rest is first-touch page faults). `d4d_test.zig` compares it with `verbs.test_hooks.unpivotCells`.
- **2026-11-08** — FASTER (no output change): `keys.factorizeInts` presizes its table from a cardinality estimate of 1024 sampled keys (four runs of 256; birthday estimate, capped at `max_presize_slots` = 2^20 slots) instead of growing from 4096 slots, which left up to twice the final table behind as first-touch page faults. Ids, firsts and order are unchanged (`d4d_test.zig` compares both for sorted, reversed, constant, distinct, two-value, random and cyclic keys). `bench-dataframe` `distinct` 43 -> 36 ms, `group_hi` 36 -> 32 ms.
- **2026-11-08** — FASTER (no output change): `pivot` factorizes the row and column key columns on their arrays (`factorColumn`, as `aggregate` does) and reads the value column as numbers for the clean aggregate functions, instead of building three boxed key rows per input row. `bench-dataframe` `pivot` 2.3x to 0.33x pandas. `src/d4d_test.zig` compares it with the cell path (`verbs.test_hooks.pivotCells`).
- **2026-11-08** — NO CONSUMER-VISIBLE CHANGE: `bench-dataframe` sums its check column from the typed int/float array, as the foreign side's vectorized `sum()` does; the boxed per-cell loop cost ~4.5 ms per 1 M rows, twice some verbs (found by the D4-A agent). Same value, counts unchanged.
- **2026-11-08** — FASTER (no output change): `topK` with one int or float key and `n` <= 4096 keeps a bounded heap over the present rows instead of sorting every row (`bench-dataframe` `top_k` 4.7x -> 0.12x pandas); `fillNull` `forward`/`backward` over a plain int or float column works on the array and validity words (a word with nothing missing is copied whole; `fill_null` 9.3x -> ~1.7x, the rest is the bench's own per-cell `get` sum). Other keys, `keep = .all` and the other strategies keep the cell path. `src/d4a_test.zig` covers both against it.

- **2026-11-08** — FASTER (no output change): `window` with `cum_sum`/`cum_prod`/`cum_min`/`cum_max`, `shift` (null fill) and `rolling` over a plain int or float column reads the array and its validity bits directly and builds the result array, instead of going through boxed `Value` cells; the partition key of a plain int column is factorized without materializing key rows. `bench-dataframe` at 1 M rows, ours/pandas: `cumsum` 17.2 -> ~1.1, `rolling` 7.2 -> 0.4 (`sum`/`mean` of rows with a whole window run four rows per vector, each lane adding in the scalar order, so the bits are unchanged), `win_shift` 3.1 -> ~1.0. Other ops, non-plain columns and `shift` with a fill keep the cell path. New `src/d4a_test.zig` checks the typed path against it (storage kind, validity, bits).

- **2026-11-08** — FASTER (no output change): `concatByName` copies a text piece with no null bit and well-formed offsets as one run (offsets rebased) instead of cell by cell. `concat` row: 303 ms before D4, about 96 ms now (pandas 45-63 ms in quiet runs, 229 ms in one noisy run).
- **2026-11-08** — FASTER (no output change): `valueCounts` counts rows per group from the group ids (`verbs.factorKeys`) and no longer builds the boxed cells of the key column that `aggregate`'s `size` ignored; the same steps in the same order (same errors, same column names and storage), then the same sort. `bench-dataframe` `value_counts` 2.4x to 1.03x pandas. `d4b_test.zig` compares both paths.
- **2026-11-08** — FASTER (no output change): `describe` over int, float or decimal columns computes its eight statistics in one pass over the typed array (no boxed key rows for `count`/`min`/`max`, one value array for the rest) and selects the three quantiles nested (median, then the quartiles inside its halves) unless a -0.0 is present, where each quantile keeps its own selection from the input order. Other storage (bool, text, boxed) takes the `aggregate` path as before. `bench-dataframe` `describe` 5.1x to 0.93x pandas. `d4b_test.zig` compares both paths.
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
