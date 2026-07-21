# dataset

The canonical in-memory **columnar-typed table** — the seam between data
sources (SQL, JSON, synthetic) and consumers (widgets, reports, ETL
transforms). Every origin is normalized to one shape: `{ columns:
[{name,type}], rows: [[Value…]] }`. Consumers never see a source schema —
only a `Dataset`.

- **Model after:** the Arrow/Polars minimal-columnar-subset shape and the
  pandas DataFrame mental model — but see "Known ceiling" below, this is
  row-major boxed cells, not true columnar storage.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state).

Provenance: original work of the zig-libs authors (MIT). No third-party code.

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

const ColumnType = dataset.ColumnType; // int, float, text, bool, date, decimal
const Column = dataset.Column;         // { name, type }
const Value = dataset.Value;           // tagged union: null/int/float/text/bool/decimal
const Dataset = dataset.Dataset;       // { columns, rows }
const Date = dataset.Date;             // { y, m, d }
const Builder = dataset.Builder;       // incremental row-at-a-time construction

// Value
fn asFloat(self: Value) ?f64;          // int/float/decimal -> f64; else null
fn asInt(self: Value) ?i64;            // int passthrough; float/decimal truncates; else null
fn asText(self: Value) ?[]const u8;
fn isNull(self: Value) bool;
fn eql(a, b: Value) bool;              // int/float/decimal compare numerically; decimal-vs-decimal exact
fn order(a, b: Value) std.math.Order;  // null < bool < numeric(int/float/decimal) < text
fn cast(self: Value, to: ColumnType) ?Value; // best-effort coercion

// Dataset
fn columnIndex(self: Dataset, name: []const u8) ?usize;
fn columnType(self: Dataset, name: []const u8) ?ColumnType;
fn rowCount(self: Dataset) usize;
fn cell(self: Dataset, row: usize, name: []const u8) ?Value;
fn floatColumn(self: Dataset, a: Allocator, name: []const u8) ![]f64;
fn seriesXY(self: Dataset, a: Allocator, x: []const u8, y: []const u8) ![]const [2]f64;
fn concat(self: Dataset, a: Allocator, other: Dataset) !Dataset; // same-schema row append

// Builder — incremental construction (no pre-sizing needed)
fn Builder.init(a: Allocator, columns: []const Column) Builder;
fn Builder.appendRow(self: *Builder, cells: []const Value) !void;
fn Builder.toOwned(self: *Builder) !Dataset;

// binary (compact, exact round-trip) + JSON
fn serialize(a: Allocator, d: Dataset) ![]u8;
fn deserialize(a: Allocator, bytes: []const u8) !Dataset; // error.Corrupt on truncation/bad tag
fn toJson(a: Allocator, d: Dataset) ![]u8; // {"columns":[...],"rows":[...]}; non-finite float -> null

// ISO dates
fn parseIsoDate(s: []const u8) ?Date;  // "YYYY-MM-DD", trailing time ignored
fn Date.ordinal(self: Date) i64;       // see caveat below
```

### `.decimal` — exact fixed-point money/quantity

`Value.decimal: i128` is a RAW fixed-point integer at `decimal_scale =
1_000_000_000_000` (12 fractional digits) — the exact convention of the
sibling `decimal` module's `Decimal{ .raw }`. `dataset` does **not** depend on
`decimal` (it stays a leaf container); to get arithmetic or display
formatting, a consumer wraps the raw value itself:
`decimal.Decimal{ .raw = value.decimal }`.

- `asFloat`/`asInt`/`cast(.float)`/`cast(.int)` go through the (lossy)
  divide-by-scale path, same as everywhere else `Value` coerces to a scalar.
- `eql`/`order` compare two `.decimal`s **exactly** on the raw `i128` — not
  through the lossy `asFloat` fallback used for cross-type numeric
  comparison — so equal money values never spuriously mismatch.
- `cast(.decimal)` widens `int`/`float` (float → `null` on non-finite input);
  `text` → `.decimal` is intentionally not attempted (that needs the
  `decimal` module's parser, which would pull in the dependency this module
  avoids).
- `toJson` emits an **exact** placed-point number literal (integer math, no
  binary-float rounding) — e.g. raw `1_500_000_000_000` → `1.5`.
- The binary wire format gained tag `5` for `.decimal`, **appended** after
  the existing `0..4` tags, so already-serialized data never renumbers.

### `Date.ordinal` — monotonic, not asserted calendar-exact

`ordinal()` uses Howard Hinnant's days-from-civil algorithm to produce a
proleptic-Gregorian day count: equal dates compare equal, later dates compare
greater, and 1970-01-01 lands on ordinal 0. This is enough for range
filtering, sorting and day-difference arithmetic. It is **not independently
verified against every historical calendar reform** — treat it as a monotonic
ordering key, not a certified calendar-math primitive.

## Known ceiling (by design, not a bug)

This is a **row-major, boxed-`Value`** representation (each cell is a tagged
union, each row a slice of them) — simple and allocator-friendly. It is not a
typed columnar layout, so it does not get SIMD-friendly per-column scans or
Arrow-style memory density. Fine for dashboard-sized result sets; not the
shape you'd want for a multi-million-row analytical engine.

## Deferred (backlog, not implemented here)

- **True columnar storage** (typed per-column arrays / SIMD-friendly
  layout) — see "Known ceiling" above; a different representation entirely.
  Deferred per the library's perf-investment policy: no current
  high-throughput product needs it (dashboard-sized result sets are the
  actual workload) — revisit if/when one does.
- **`distinct`/dedup at the dataset level** — NOT duplicated here: covered
  by `tabular.distinct` (group-key + keep-first-or-last), which already owns
  that design.

Resolved this cycle: `.decimal` `ColumnType`/`Value` (raw `i128`, no
`decimal`-module dependency — see above) and `Builder` (streaming/incremental
construction).

## Design notes

Two convenience additions on top of the columnar-table core:

- `Value.asInt` + `Value.cast(ColumnType)` round out the coercion surface
  alongside `asFloat`/`asText`.
- `Dataset.concat` — append the rows of a same-schema `Dataset`, producing a
  new `Dataset` per the transform-algebra memory model; `error.SchemaMismatch`
  on a column-name/type/count mismatch.

## Verify

```
zig build test-dataset
zig build test-dataset -Doptimize=ReleaseFast
zig fmt --check modules/dataset
```
