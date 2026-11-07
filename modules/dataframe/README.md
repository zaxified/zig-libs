# dataframe

A columnar table, `Frame`, and the verbs of a dataframe library over it, modeled on the
eager API of pandas (the reference) and polars (the fastest). Each column is one typed
array (`int`, `float`, `bool`, `decimal`, `text`, or `boxed` cells of mixed kinds) with a
validity bitmap where it has nulls. Rows have no labels, as in polars: a row is its
position.

- **Verbs:** `aggregate` (23 functions, fx conversion, exact `sum_exact`), `join` (inner,
  left, right, full, semi, anti, cross), `pivot`, `unpivot` (melt), `sort` (multi-key,
  stable, null placement), `filter`, `distinct`, `dropna`, `fillna`, `select`, `drop`,
  `rename`, `map` (column arithmetic), `cumsum`, `rolling`. What is still missing against
  pandas and polars is listed row by row in `SPEC.md` § Backlog.
- **Model after:** pandas 3.1 and polars 2.1, eager DataFrame API.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared state).
  **Deps:** none.

Provenance: original work of the zig-libs authors (MIT); the storage comes from
`dataset`'s `Frame` and the verbs from `tabular`, same authors. Modeled after pandas
(BSD-3-Clause) and polars (MIT): verb names and behaviour from their documentation, no
source consulted or copied. `src/oracle_vectors.json` holds generated tables and what
pandas 3.1.0 and polars 2.1.0 answered over them (`tools/README.md`); no outside data.

## Use

```zig
const df = @import("dataframe");

var arena = std.heap.ArenaAllocator.init(df.big_block_allocator);
defer arena.deinit();
const a = arena.allocator();

const cols = [_]df.Column{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .float } };
var b = try df.FrameBuilder.init(a, &cols, 3);
try b.appendRow(&.{ .{ .text = "x" }, .{ .float = 1 } });
try b.appendRow(&.{ .{ .text = "y" }, .null });
try b.appendRow(&.{ .{ .text = "x" }, .{ .float = 2 } });
const f = try b.toOwned();

const g = try df.aggregate(a, f, .{
    .group_by = &.{"k"},
    .aggs = &.{.{ .src = "v", .out = "total", .func = .sum }},
    .skip_na = true,
});
const s = try df.sort(a, g, .{ .key = "total", .dir = .desc });
_ = s.cell(0, "k"); // .{ .text = "x" }
```

`example/main.zig` runs a longer pipeline (`zig build run-example-dataframe`).

## What results share, and which allocator

Every verb is `verb(allocator, Frame, Spec) -> Frame` and mutates nothing. **A result
borrows:** columns a verb did not touch are shared with its input, a selection of every
row in order shares them all, and the spec's names become column names. Keep the input
and the spec alive as long as the result. Pass an arena: a result has no `deinit`, and a
frame's arrays may be longer than its `len`, so a general-purpose allocator would leak.
For big tables put the arena over `df.big_block_allocator` (2 MiB blocks advised for
transparent huge pages).

Missing is null or a NaN float in every verb, as pandas' `isna`. A frame of 2^32 - 1 rows
or more, and work past the caps in `SPEC.md` § Limits, is `error.TooLarge`.

## Building a frame

`FrameBuilder` copies each row's cells (text included) into per-column arrays; the
storage follows the cells, not the declared `ColumnType`, so a column declared `.float`
that receives ints is an int array, and a mix is `boxed`. A hand-built `Frame`
(`.{ .columns, .data, .len }`) is fine too: arrays shorter than `len` read as null past
their end. `Frame.series(name)` gives one column as a `Series` view.

## Verify

`zig build test-dataframe`. The verbs are checked against `tabular`'s row verbs over
generated tables and against pandas' and polars' frozen answers (`SPEC.md` §
Verification).
