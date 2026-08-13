# geoindex

Memory-efficient **frozen static spatial index** for bounding-box and
nearest-neighbour queries over a large, fixed set of geo-points. Build an index
from `(lat, lon, value)` triples, **freeze** it to a flat, self-describing,
versioned, little-endian byte buffer, then query that buffer **zero-copy** from
an mmap'd / read-only slice — no per-query allocation.

The driving consumer is a Czech RÚIAN address set: millions of addresses each
carrying a lat/lon, needing "points inside this bbox" and "k nearest to this
point" fast, from a read-only snapshot. The module is general — any static
`(lat, lon) → u32` set that needs bbox + kNN.

- **Model after:** Flatbush (mourner/`flatbush`) — a packed, bulk-loaded Hilbert
  R-tree frozen to a flat array. (See `SPEC.md` for the structure decision vs a
  Z-order/geohash array or a uniform grid.)
- **Platform:** any — pure logic, no OS dependency. **Role:** util.
  **Concurrency:** `reentrant` — a frozen buffer is immutable, so any number of
  threads may query one buffer concurrently with no synchronization.
- **Deps:** none (`std` only).

> **Status: implemented.** Build → freeze → zero-copy load → query is complete
> and tested. A naive linear-scan oracle differential (randomized, over
> adversarial point sets — empty, single, all-identical, collinear, duplicate
> coordinates, pole/antimeridian extremes) pins the bbox membership set and the
> kNN order + distances exactly; a corrupt-buffer fuzz harness pins the
> untrusted-buffer loader + query path; hand-malformed positive controls prove
> the checkers have teeth. See `SPEC.md` for the wire format field-by-field and
> the threat model.

Provenance: original work of the zig-libs authors (MIT) — the spatial index.
Design reference, approach only: Flatbush (mourner/flatbush, **ISC**) — the
packed-Hilbert-R-tree bulk-load idea. No source consulted or copied.

## Contracts

- **Coordinates are WGS84 degrees:** `lat` in `[-90, 90]`, `lon` in
  `[-180, 180]`. `Builder.add` rejects NaN/inf (`error.NotFinite`) and
  out-of-range values (`error.OutOfRange`) — a bad coordinate is never silently
  indexed at a wrong location. Coordinates are stored as **f64** and returned
  **byte-identical** to what was indexed (no quantization).
- **bbox is a CLOSED rectangle.** A point exactly on an edge or corner
  (`lat == min_lat`/`max_lat`, or `lon == min_lon`/`max_lon`) is **included**. A
  zero-area rectangle (`min == max` on both axes) is a valid point query. Pass
  `min <= max` on each axis (an inverted rectangle matches nothing). The
  rectangle **must not cross the antimeridian** in v1 — split a
  ±180-spanning query into two (see `SPEC.md`).
- **kNN distance is an equirectangular approximation** scaled by
  `cos(query latitude)`: `dx = (lon − qlon)·cos(qlat)`, `dy = lat − qlat`,
  `dist2 = dx² + dy²`. This is a monotone proxy for great-circle distance,
  accurate for local/regional queries (the RÚIAN consumer) and degrading at
  continental scale / near the poles. `Neighbor.dist2` is that **squared metric**
  value, **not metres**. **Tie-break** (total order): `dist2` ascending, then
  `value`, then `lat`, then `lon` — so equal-distance results are deterministic.
- **Bounded work / DoS guard:** both queries take `QueryOptions.max_visited` (a
  node-decode budget, default 100 000). `bbox` reports `.truncated_budget` (or
  `.truncated_capacity` if the result buffer fills first) instead of walking the
  whole set. `knn` best-first emits in exact order, so a budget cut returns a
  correct — merely shorter — **prefix** of the true kNN. `max_visited = 0` means
  unbounded; do not use on attacker-influenced queries.

## API

```zig
const geoindex = @import("geoindex");

// Build.
var b = geoindex.Builder.init(gpa);
defer b.deinit();
try b.add(50.08, 14.42, 100); // (lat, lon, value=record id)
try b.add(49.19, 16.61, 200);
const buf = try b.freeze(gpa);   // caller owns `buf`; write it to a file / mmap
defer gpa.free(buf);
// or one-shot: const buf = try geoindex.freezeFromPoints(gpa, gpa, points);

// Query a frozen buffer (zero-copy; `buf` may be a read-only mmap).
const f = try geoindex.Frozen.load(buf);           // fast: header only, O(1)
// const f = try geoindex.Frozen.loadVerified(buf); // untrusted file: + body CRC

// bbox — closed rectangle, into a caller buffer (no allocation).
var hits: [256]geoindex.Match = undefined;
const r = try f.bbox(49.5, 50.5, 13.0, 15.0, &hits, .{});
// r.items: []Match{ value, lat, lon };  r.status: .complete / .truncated_capacity / .truncated_budget

// kNN — k nearest to (lat, lon). `scratch` is the heap workspace.
var near: [10]geoindex.Neighbor = undefined;
var scratch: [4096]geoindex.HeapEntry = undefined; // or size via knnScratchLen(k, fanout, item_count)
const kr = try f.knn(49.2, 16.6, 10, &near, &scratch, .{});
// kr.items ranked nearest-first; kr.status: .complete / .truncated_budget
```

`Match`/`Neighbor` carry the stored `value` and exact `lat`/`lon`; nothing
borrows the frozen buffer, so results outlive it. `loadVerified` adds a one-time
full node-region CRC check for files crossing a trust boundary; queries are
bounds-checked either way.

### Sizing the kNN scratch

`knn` holds its priority queue in the caller-supplied `scratch`. Too small
returns `error.ScratchTooSmall` (never a crash) — enlarge and retry.
`knnScratchLen(k, fanout, item_count)` gives a safe upper bound; a fixed
few-thousand-entry buffer is ample for typical `k`.

### Memory

The frozen buffer is compact (~40 B per point: one leaf per point plus ~1/15 as
many internal nodes, each a 39-byte record). The **query side allocates nothing**
— that is the deployed hot path. The **build** phase keeps everything in a
handful of growable arrays (the point pool + the node pool), so a
millions-of-points build is a handful of allocations, not per-point ones — build
RSS is linear and allocator-insensitive. Freeze is a one-time cost: ship the
frozen buffer and never build in the request path. See `SPEC.md` for the cost
model.

## Verify

```
zig build test-geoindex                        # Debug
zig build test-geoindex -Doptimize=ReleaseFast # ReleaseFast
```
