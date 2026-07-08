# dataset

The canonical in-memory **columnar-typed table** — the seam between data
sources (SQL, JSON, synthetic) and consumers (widgets, reports, ETL
transforms). Every origin is normalized to one shape: `{ columns:
[{name,type}], rows: [[Value…]] }`. Consumers never see a source schema —
only a `Dataset`.

- **Status:** `extract` — lifted from the authors' wgs `src/dataset.zig`.
- **Model after:** the Arrow/Polars minimal-columnar-subset shape and the
  pandas DataFrame mental model — but see "Known ceiling" below, this is
  row-major boxed cells, not true columnar storage.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state).

Provenance: extracted from the authors' wgs project (`src/dataset.zig`, MIT,
same authors) — a faithful lift; ownership semantics preserved exactly. No
third-party code (see [NOTICE](../../NOTICE)).

## Memory model — read this before using the module

A `Dataset` is an **immutable view**. Transforms are `dataset → dataset`:
they take an allocator (normally an arena the caller owns for the whole
pipeline) and return a NEW `Dataset`. Structural arrays (`columns`, `rows`,
per-row `Value` slices) are allocated from that allocator; text payloads may
be **borrowed** from the input (shared slices — valid for the arena's
lifetime) or freshly allocated. Nothing is mutated in place, so borrowing is
safe. Free everything at once via the arena — don't try to free a `Dataset`
piecemeal.

## API

```zig
const dataset = @import("dataset");

const ColumnType = dataset.ColumnType; // int, float, text, bool, date
const Column = dataset.Column;         // { name, type }
const Value = dataset.Value;           // tagged union: null/int/float/text/bool
const Dataset = dataset.Dataset;       // { columns, rows }
const Date = dataset.Date;             // { y, m, d }

// Value
fn asFloat(self: Value) ?f64;          // int/float -> f64; else null
fn asInt(self: Value) ?i64;            // int passthrough; float truncates; else null
fn asText(self: Value) ?[]const u8;
fn isNull(self: Value) bool;
fn eql(a, b: Value) bool;              // int/float compare numerically
fn order(a, b: Value) std.math.Order;  // null < bool < numeric < text
fn cast(self: Value, to: ColumnType) ?Value; // best-effort coercion

// Dataset
fn columnIndex(self: Dataset, name: []const u8) ?usize;
fn columnType(self: Dataset, name: []const u8) ?ColumnType;
fn rowCount(self: Dataset) usize;
fn cell(self: Dataset, row: usize, name: []const u8) ?Value;
fn floatColumn(self: Dataset, a: Allocator, name: []const u8) ![]f64;
fn seriesXY(self: Dataset, a: Allocator, x: []const u8, y: []const u8) ![]const [2]f64;
fn concat(self: Dataset, a: Allocator, other: Dataset) !Dataset; // same-schema row append

// binary (compact, exact round-trip) + JSON
fn serialize(a: Allocator, d: Dataset) ![]u8;
fn deserialize(a: Allocator, bytes: []const u8) !Dataset; // error.Corrupt on truncation/bad tag
fn toJson(a: Allocator, d: Dataset) ![]u8; // {"columns":[...],"rows":[...]}; non-finite float -> null

// ISO dates
fn parseIsoDate(s: []const u8) ?Date;  // "YYYY-MM-DD", trailing time ignored
fn Date.ordinal(self: Date) i64;       // see caveat below
```

### `Date.ordinal` — monotonic, not asserted calendar-exact

`ordinal()` uses Howard Hinnant's days-from-civil algorithm to produce a
proleptic-Gregorian day count: equal dates compare equal, later dates compare
greater, and 1970-01-01 lands on ordinal 0. This is enough for range
filtering, sorting and day-difference arithmetic. It is **not independently
verified against every historical calendar reform** — this is the seed's own
hedge, carried forward unchanged: treat it as a monotonic ordering key, not a
certified calendar-math primitive.

## Known ceiling (by design, not a bug)

This is a **row-major, boxed-`Value`** representation (each cell is a tagged
union, each row a slice of them) — simple, allocator-friendly, and exactly
what the seed needed. It is not a typed columnar layout, so it does not get
SIMD-friendly per-column scans or Arrow-style memory density. Fine for
dashboard-sized result sets; not the shape you'd want for a multi-million-row
analytical engine.

## Deferred (backlog, not implemented here)

Flagged by the extraction scope as follow-on work, intentionally out of
scope for this v1 lift:

- **`.decimal` `ColumnType`/`Value` variant** composing the `decimal`
  module — exact money representation; deferred because it is a
  cross-module integration decision (does `dataset` depend on `decimal`,
  or does a consumer layer bridge the two?) rather than a self-contained
  addition.
- **True columnar storage** (typed per-column arrays / SIMD-friendly
  layout) — see "Known ceiling" above; would be a different representation,
  not a faithful extraction of the seed.
- **Streaming / chunked bounded-memory construction** for very large result
  sets — the current model materializes the whole `Dataset` up front; a
  streaming builder is a separate API shape.
- **`distinct`/dedup at the dataset level** — `Value.eql` already gives a
  transform the building block, but the dataset-level operation itself
  (which rows are compared, does the caller pick key columns) needs its own
  design pass.

## Changes vs the seed

Semantics (typed columns, tagged-union cells, serialize/deserialize wire
format, JSON shape, date ordinal) are preserved exactly — this is a faithful
lift. Two additions, both flagged as safe/cheap in the extraction scope:

- `Value.asInt` + `Value.cast(ColumnType)` — the seed only had
  `asFloat`/`asText`; these round out the coercion surface the same way.
- `Dataset.concat` — append the rows of a same-schema `Dataset`, producing a
  new `Dataset` per the transform-algebra memory model; `error.SchemaMismatch`
  on a column-name/type/count mismatch.

## Verify

```
zig build test-dataset
zig build test-dataset -Doptimize=ReleaseFast
zig fmt --check modules/dataset
```
