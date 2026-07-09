# dataset — spec

Canonical in-memory columnar-typed table — the seam between data sources and consumers. Usage: see
./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- Every origin normalizes to one shape: `{ columns: [{name,type}], rows: [[Value…]] }`; consumers
  never see a source schema, only a `Dataset`. `ColumnType`: int/float/text/bool/date. `Value` is a
  tagged union with `asFloat`/`asInt`/`asText`/`isNull`/`eql`/`order`/`cast`.
- **Memory model: a `Dataset` is an immutable view.** Transforms are `dataset → dataset`: take an
  allocator (normally a caller-owned arena for the whole pipeline) and return a **new** `Dataset`.
  Structural arrays (`columns`, `rows`, per-row `Value` slices) are allocated from that allocator;
  text payloads may be borrowed from the input (safe since nothing is ever mutated in place) or
  freshly allocated. Free everything at once via the arena — no piecemeal free.
- `Date.ordinal()` uses Howard Hinnant's days-from-civil algorithm (proleptic Gregorian, 1970-01-01
  = 0): equal dates compare equal, later dates compare greater. It is a monotonic ordering key, **not
  independently verified against every historical calendar reform**.
- Serialize/deserialize is a compact binary wire format with exact round-trip (`error.Corrupt` on
  truncation/bad tag) plus a JSON projection (non-finite float → null).
- **Known ceiling, by design:** row-major, boxed-`Value` representation (each cell a tagged union,
  each row a slice of them) — simple and allocator-friendly, not a typed columnar layout. No
  SIMD-friendly per-column scans or Arrow-style memory density; fine for dashboard-sized result sets,
  not a multi-million-row analytical engine.
- Pure logic, no OS calls, reentrant, no shared state.

## Threat model / out of scope
Not a security boundary — an in-memory data-shape primitive over caller-supplied or caller-parsed
data. `deserialize` treats untrusted bytes defensively (bounds-checked, `error.Corrupt` on
truncation/bad tag/length overflow, never a panic or OOB read) since a wire round-trip may cross a
process or cache boundary. `Date.ordinal` is not a certified calendar-math primitive (see Design
notes) — do not use it for legal/financial date arithmetic requiring exact historical calendar
correctness.

## Verification
`zig build test-dataset` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/dataset`). 7 tests:
`Value` coercion/comparison/ordering (`asFloat`/`asInt`/`cast`/`eql`/`order` incl. null<bool<numeric<
text), `Dataset` accessors (`columnIndex`/`columnType`/`cell`/`floatColumn`/`seriesXY`), `concat`
(same-schema append + `error.SchemaMismatch`), binary serialize/deserialize round-trip + corruption
rejection, `toJson` shape (incl. non-finite float → null), `parseIsoDate` + `Date.ordinal` monotonic
ordering.

## Backlog / deferred
From README "Deferred (backlog, not implemented here)", intentionally v1
out-of-scope: a `.decimal` `ColumnType`/`Value` variant composing the `decimal` module for exact
money (deferred — cross-module dependency-direction decision, not yet made); true columnar storage
(typed per-column arrays, SIMD-friendly layout — a different representation entirely); streaming/
chunked bounded-memory construction for very large result sets
(current model materializes the whole `Dataset` up front); `distinct`/dedup at the dataset level
(needs its own design pass — which rows compared, caller-picked key columns). `dataset`
is the anchor of a sibling family already extracted (`tabular` = dataset algebra, `jsonshape` = JSON→
dataset projection) — those are separate modules, not gaps in this one.

## Status
`extract · any · util · reentrant` + deps: none — canonical source is `pub const meta` in
src/root.zig.
