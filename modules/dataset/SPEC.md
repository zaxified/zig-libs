# dataset — spec

Canonical in-memory columnar-typed table — the seam between data sources and consumers. Usage: see
./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants
- Every origin normalizes to one shape: `{ columns: [{name,type}], rows: [[Value…]] }`; consumers
  never see a source schema, only a `Dataset`. `ColumnType`: int/float/text/bool/date/decimal. `Value`
  is a tagged union with `asFloat`/`asInt`/`asText`/`isNull`/`eql`/`order`/`cast`.
- `.decimal` (`ColumnType`) / `Value.decimal: i128` — exact fixed-point money/quantity type. Stores
  a RAW `i128` at `decimal_scale = 1_000_000_000_000` (12 fractional digits), the exact convention of
  the sibling `decimal` module's `Decimal{ .raw }`. **No dependency on `decimal`** — `dataset` stays a
  leaf container; consumers wrap the raw value themselves as `decimal.Decimal{ .raw = value.decimal }`
  for arithmetic/formatting. `eql`/`order` compare two decimals exactly on the raw `i128` (not the
  lossy `asFloat` path used for cross-type numeric comparison). `cast(.decimal)` handles int/float
  widening (float path returns `null` on non-finite input); text→decimal is NOT attempted (would need
  the `decimal` module's parser). `toJson` emits an exact placed-point number literal (integer math,
  scale-derived decimal point, trailing zeros trimmed) — never the lossy f64 path `.float` uses. The
  binary wire format got a new tag (`5`, appended after the existing `0..4`, not inserted) so
  already-serialized data never renumbers.
- `Builder` — incremental row-at-a-time `Dataset` construction (`init(allocator, columns)` →
  `appendRow(cells)` → `toOwned()`) for sources that don't know their row count up front, without
  pre-sizing an array.
- **Memory model: a `Dataset` is an immutable view.** Transforms are `dataset → dataset`: take an
  allocator (normally a caller-owned arena for the whole pipeline) and return a **new** `Dataset`.
  Structural arrays (`columns`, `rows`, per-row `Value` slices) are allocated from that allocator;
  text payloads may be borrowed from the input (safe since nothing is ever mutated in place) or
  freshly allocated. Free everything at once via the arena — no piecemeal free.
- `Date.ordinal()` uses Howard Hinnant's days-from-civil algorithm (proleptic Gregorian, 1970-01-01
  = 0): equal dates compare equal, later dates compare greater. It is a monotonic ordering key, **not
  independently verified against every historical calendar reform**.
- Serialize/deserialize is a compact binary wire format with exact round-trip (`error.Corrupt` on
  truncation/bad tag) plus a JSON projection (non-finite float → null). **Explicit little-endian on
  the wire, independent of host byte order** — every multi-byte field (`u32` lengths, `i64`/`f64`
  cells, `i128` decimal cells) goes through `std.mem.writeInt`/`readInt(..., .little)`, not
  `std.mem.toBytes`/`bytesToValue` (which write/read the host's *native* representation — silently
  correct on every little-endian CI lane, silently wrong cross-endian). Floats are bit-cast to their
  same-width integer before the explicit-endian write, then bit-cast back on read — the IEEE-754 bit
  *pattern* is host-independent, only its byte order is, so this is correct on a big-endian host too.
  A fixed golden byte vector (computed independently, outside this module, with Python's
  `struct.pack('<...')`) pins the documented little-endian contract; a same-process round-trip cannot
  — encode and decode agree with each other regardless of which byte order either one actually uses.
  Cross-verified by running the suite under `qemu-s390x` against a `-Dtarget=s390x-linux-musl`
  (big-endian) build. On a little-endian host the wire bytes are unchanged by this fix — verified
  byte-for-byte against the golden vector — so no existing little-endian-host payload (e.g. a
  consumer's on-disk cache) is invalidated.
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
`zig build test-dataset` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/dataset`):
`Value` coercion/comparison/ordering (`asFloat`/`asInt`/`cast`/`eql`/`order` incl. null<bool<numeric<
text, and `decimal`'s exact-raw-i128 compare/coercion), `Dataset` accessors (`columnIndex`/
`columnType`/`cell`/`floatColumn`/`seriesXY`), `concat` (same-schema append + `error.SchemaMismatch`),
binary serialize/deserialize round-trip + corruption rejection (incl. the new `decimal` wire tag), a
fixed little-endian golden byte vector asserted byte-for-byte against `serialize`'s output and fed to
`deserialize` (cross-checked live under `qemu-s390x`, `-Dtarget=s390x-linux-musl`), `toJson` shape
(incl. non-finite float → null, exact placed-point `decimal`), `parseIsoDate` +
`Date.ordinal` monotonic ordering, `Builder` incremental construction.

## Backlog / deferred
From README "Deferred (backlog, not implemented here)":
- **True columnar storage** (typed per-column arrays, SIMD-friendly layout) — a different
  representation entirely; big perf-engineering investment with no current high-throughput product
  driving the need (dashboard-sized result sets are the actual workload). Per the library's
  perf-investment policy, deferred until a consumer's throughput actually demands it.
- ~~`.decimal` `ColumnType`/`Value` variant~~ — **done**: raw `i128` inline, no dependency on
  `decimal` (see Design & invariants above).
- ~~Streaming/chunked construction~~ — **done**: `Builder`.
- ~~`distinct`/dedup at the dataset level~~ — **not duplicated here**: covered by
  `tabular.distinct` (added this cycle), which already owns the group-key/keep-first-or-last design.

`dataset` is the anchor of a sibling family already extracted (`tabular` = dataset algebra,
`jsonshape` = JSON→dataset projection) — those are separate modules, not gaps in this one.

## Status
`extract · any · util · reentrant` + deps: none — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** internal tabular Value/Dataset abstraction, plus one wire-format
oracle: the little-endian golden byte vector above. It pins this module's own documented on-wire
contract (there is no external spec/RFC for it), so it does not change the Class C grade — it is a
brute-force reference for our own invariant, not an outside conformance target.
