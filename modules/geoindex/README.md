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
  `min_lat <= max_lat` (an inverted latitude range matches nothing). **`min_lon > max_lon`
  is an antimeridian-wrapping rectangle** (`[min_lon, 180] ∪ [-180, max_lon]`, no
  duplicates, shared buffer/budget/filter); `within`/kNN measure longitude the short way round the antimeridian.
- **kNN and `within` distance.** By default (`QueryOptions.metric = .planar`) an equirectangular
  approximation scaled by `cos(query latitude)`: `dx = wrap(lon − qlon)·cos(qlat)` (the short way round the
  antimeridian), `dy = lat − qlat`, `dist2 = dx² + dy²`: a monotone proxy for great-circle distance, accurate
  for local/regional queries (the RÚIAN consumer) and degrading at continental scale / near the poles;
  `Neighbor.dist2` is that **squared metric** value, **not metres**. `.metric = .great_circle` ranks by
  haversine on a 6371 km sphere and reports **metres** (`radius` in metres, `Neighbor.dist()` the distance),
  correct near the poles and across the dateline. **Tie-break** (total order): `dist2` ascending, then
  `value`, then `lat`, then `lon` — so equal-distance results are deterministic.
- **Rectangles.** `Builder.addBox(min_lat, min_lon, max_lat, max_lon, value)` indexes a rectangle (footprint,
  tile); `bbox` finds it when the query rectangle meets it, `knn`/`within` rank it by its distance to the
  query point (0 inside); `Match`/`Neighbor` carry `max_lat`/`max_lon` (`isPoint()`).
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

// within — everything within `radius` of (lat, lon), unordered, with dist2.
// The radius is in the kNN ranking metric (degrees of latitude, longitude scaled
// by cos(query lat)); pass `.{ .metric = .great_circle }` for a radius in metres.
var around: [256]geoindex.Neighbor = undefined;
const wr = try f.within(49.2, 16.6, 0.05, &around, .{}); // wr.status as for bbox

// filter — a predicate applied during bbox / within / knn; knn still returns
// the k nearest points that PASS. `ctx` is passed back to `func`.
// const flt = geoindex.Filter{ .ctx = &state, .func = myPredicate }; // fn(?*anyopaque, Match) bool
// _ = try f.knn(49.2, 16.6, 10, &near, &scratch, .{ .filter = flt });
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

## Not provided

`u32` payloads only; STR packing, fixed-point storage and an out-of-core build (the reference has none of them). Each is named, with its reason, in `SPEC.md` § What is deliberately not done.

## Verify

```
scripts/modtest geoindex
```
