# geoindex — SPEC

A frozen static spatial index for bbox + nearest-neighbour queries over a large,
fixed set of geo-points. Build from `(lat, lon, value)` triples → freeze to a
flat byte buffer → query that buffer zero-copy from a read-only / mmap'd slice.
See `README.md` for the module purpose and the usage-facing contracts.

## Design decision — packed Hilbert R-tree vs Z-order array vs grid

**Chosen: a packed Hilbert R-tree, bulk-loaded bottom-up and frozen to a flat
array of fixed-size node records (the Flatbush lineage).**

The set is *static*, so there is no insert/rebalance cost to amortize — the whole
tree is bulk-loaded once. Points are sorted along a 16-bit Hilbert space-filling
curve (spatial locality: points close in space are close in the array), then
packed bottom-up: `fanout` consecutive leaves group into one internal node whose
box is their union, repeated level by level up to a single root. Emitting leaves
first and the root last yields the key structural invariant below.

Why this over the two alternatives the brief offered:

- **vs a Z-order / geohash sorted array (range-scan + refine).** A Morton/geohash
  array answers bbox as one or more contiguous index ranges, but a query
  rectangle maps to *many* disjoint Z-ranges (the curve re-enters the rectangle
  repeatedly), so you either over-scan or maintain a range list; kNN needs an
  expanding-ring refinement that is fiddly to bound. An R-tree gives a single
  tree with real per-node bounding boxes → tight bbox pruning and a clean
  best-first kNN, at a modest ~1/15 internal-node overhead.
- **vs a uniform / adaptive grid.** A grid is excellent for uniformly dense data
  but degrades badly on the *clustered* distribution real addresses have (dense
  cities, empty countryside): a fixed cell size is either too coarse for cities
  or explodes cell count for the countryside. The R-tree adapts to density for
  free.

The decisive tie-breaker is the frozen-buffer threat model (below): the R-tree's
bottom-up layout gives a **strictly-decreasing child-index invariant** that makes
traversal termination provable on an untrusted buffer with a single comparison —
the same robustness lever the sibling `trie` module leans on. A Z-order array
would lean on `binary-search + range` bounds instead; workable, but the R-tree's
monotone-index proof is simpler to audit.

Deferred refinements (STR bulk-load bbox tightening, wider fan-out tuning,
great-circle metric) are listed at the end; none change the query API or callers.

### Cost model

- **Memory (frozen):** header 40 B + `node_count` × 39 B. `node_count ≈
  item_count × fanout/(fanout−1) ≈ 1.07 × item_count` at `fanout = 16` → ~42 B
  per point.
- **Build:** O(N log N) — dominated by the Hilbert sort; the pack is O(N). Held in
  a few growable arrays (point pool + node pool), a handful of allocations total.
- **`bbox`:** O(hits + visited internal nodes), bounded by `max_visited`. Zero
  allocation (caller result buffer + a fixed inline DFS stack).
- **`knn`:** O((k + visited) · log(heap)), bounded by `max_visited`. Zero
  allocation (caller-supplied heap scratch).

## Frozen wire format (version 1)

All integers **little-endian**; each `f64` is stored as its IEEE-754 `u64` bit
pattern, also little-endian. The buffer is `header ++ node_region`.

### Header — 40 bytes at offset 0

| off | size | field | meaning |
|----:|-----:|-------|---------|
| 0  | 4 | `magic`         | ASCII `"ZGI1"` |
| 4  | 2 | `version`       | format version = 1 |
| 6  | 2 | `endian_marker` | `0x0102` — detects a wrong-endian / garbage load |
| 8  | 4 | `flags`         | reserved, currently 0 |
| 12 | 4 | `node_count`    | number of node records |
| 16 | 2 | `node_bytes`    | record stride = 39 (validated on load) |
| 18 | 2 | `fanout`        | build-time R-tree fan-out (informational) |
| 20 | 8 | `item_count`    | number of indexed points |
| 28 | 4 | `root_index`    | index of the root node record |
| 32 | 4 | `body_crc`      | CRC-32 of the node region (checked by `loadVerified`) |
| 36 | 4 | `header_crc`    | CRC-32 of bytes `[0..36)` |

`Header.load` validates magic, header CRC, endian marker, version, the record
stride, and the mutual consistency of `item_count` / `node_count` / `root_index`
(including the empty index: `item_count == 0 ⇒ node_count == 0`) — all O(1),
without scanning the body. `loadVerified` additionally checks `body_crc`.

### Node region — starts at offset 40

A contiguous array of `node_count` fixed-size records (stride 39). The tree is
packed **bottom-up**: leaf records first (indices `[0, item_count)`), then each
internal level, and the **root last**. **Invariant:** every child of a node has a
**strictly smaller index** than the node, and a node's children occupy a
contiguous block entirely below it. The decoder enforces `child_index <
parent_index`; because followed indices strictly decrease and are bounded below
by 0, traversal **provably terminates even on a corrupt buffer**.

Each 39-byte record:

| off | size | field | meaning |
|----:|-----:|-------|---------|
| 0  | 1 | `flags`       | bit0 = leaf (record is a single indexed point) |
| 1  | 8 | `min_lat`     | bounding box; for a leaf `min == max == the point` |
| 9  | 8 | `min_lon`     | |
| 17 | 8 | `max_lat`     | |
| 25 | 8 | `max_lon`     | |
| 33 | 4 | `data`        | leaf: stored `value`; internal: `child_start` (index of first child) |
| 37 | 2 | `child_count` | internal: number of contiguous children; leaf: 0 |

## Coordinate & precision decisions

- **f64, not fixed-point.** WGS84 degrees in f64 carry ~15 significant digits
  (sub-millimetre); storing points as-is means the index returns coordinates
  **byte-identical** to the input, so the differential oracle can compare exact
  bit patterns and there is no quantization error to reason about. Fixed-point
  (e.g. int32 micro-degrees) would halve the box storage but reintroduce
  rounding at cell edges and a lossy round-trip; deferred, not needed at RÚIAN
  scale.
- **Ranges:** `lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`, inclusive. Rejected at
  build with `error.OutOfRange`; NaN/inf with `error.NotFinite`.
- **Antimeridian (v1 restriction).** The bbox query treats the rectangle as a
  simple `min ≤ coord ≤ max` interval on each axis, so it **cannot express a
  rectangle that wraps across ±180°**. A caller needing a ±180-spanning window
  splits it into two queries (`[…, 180]` and `[-180, …]`) and unions the results.
  The kNN metric likewise measures raw longitude difference, so a query point and
  a candidate on opposite sides of the antimeridian are treated as far apart even
  if geographically near. Both are documented limitations, not silent wrong
  answers. Full antimeridian handling is deferred.
- **Hilbert grid.** Points are mapped into a 65536×65536 grid spanning the data's
  overall bounding box for the Hilbert sort. A zero-width axis (all points share
  a latitude/longitude) collapses to grid column/row 0 — no divide-by-zero. The
  exact Hilbert mapping affects only query *locality*, never correctness (any
  deterministic order produces a valid packed R-tree), so a clear iterative
  xy→d mapping is used rather than a bit-twiddled one.

## kNN distance metric

Best-first R-tree search over a min-heap: the heap holds pending internal nodes
(keyed by the lower-bound distance from the query point to the node's box) and
pending leaf points (keyed by the exact point distance). Popping the minimum
always yields either the next-nearest point (emit) or the nearest unexplored node
(expand) — a point can never be beaten by anything inside a farther box — so
results come out in exact ascending order and a budget cut returns a correct
prefix.

The metric is an **equirectangular approximation** scaled by the cosine of the
query latitude. With `qk = cos(qlat)`:

```
dx = (lon − qlon) · qk ;  dy = lat − qlat ;  dist2 = dx·dx + dy·dy
```

Because `qk` is a single constant per query, this is an anisotropic linear
scaling of the (lon, lat) plane, so the squared distance from the scaled query
point to a scaled axis-aligned node rectangle is a **true lower bound** on the
distance to any point in that box → pruning never drops a real neighbour, and the
oracle can reproduce the identical f64 arithmetic bit-for-bit. `dist2` is a
ranking key in this metric (degrees²), **not metres**. Ties break by
`(dist2, value, lat, lon)` ascending — a total order (any remaining equal keys
are identical points, so the output is deterministic).

**Great-circle / haversine is deferred.** It would need a haversine box
lower-bound (distance from a point to a lat/lon rectangle on the sphere), which
is more involved and, more importantly, would make oracle/index bit-exact
agreement harder to guarantee. The equirectangular metric matches great-circle
ordering closely for the regional queries this index targets.

## DoS / bounded-work model

Both queries take `QueryOptions.max_visited` (default **100 000**): the maximum
number of node records the query may decode before stopping. A bbox covering
everything, or a kNN over millions of points, cannot walk the whole set — it
stops at the budget. `bbox` reports `.truncated_budget`, or `.truncated_capacity`
if the caller's result buffer fills first (distinguishable so the caller knows
whether to enlarge the buffer or accept a partial answer). `knn` best-first emits
in exact order, so a budget cut yields a correct, merely shorter, prefix. The
inline `bbox` DFS stack is capped at `max_stack` (4096); a buffer that would
overflow it is treated as corrupt (`error.StackOverflow`). `knn`'s heap lives in
caller scratch; overflow is `error.ScratchTooSmall` (never silent dropping, which
would break exactness). `max_visited = 0` disables the budget and must not be
used on attacker-influenced queries.

## Threat model — untrusted frozen buffers

A frozen buffer may come from a file outside the process trust boundary
(truncated, bit-flipped, or hand-crafted). Guarantees:

- **Never panics, never reads out of bounds, never loops forever** on any input
  buffer. Every index the query path follows out of the buffer is bounds-checked
  in `format.zig` (`Nodes.at`, `Nodes.child`); a bad index yields a typed
  `error.Corrupt`. Child-start + child-index arithmetic is overflow-checked.
- **Header validation** rejects short buffers (`Truncated`), wrong magic
  (`BadMagic`), unknown version (`UnsupportedVersion`), wrong record stride
  (`BadNodeBytes`), wrong endian (`BadEndian`), a corrupt header
  (`HeaderCorrupt`), and an inconsistent/out-of-range root (`MalformedRoot`).
  `loadVerified` adds `BodyCorrupt` (node-region CRC).
- **Termination** rests on the strictly-decreasing bounded child-index invariant
  plus the explicit visit budget — not on trusting `child_count` or any length
  field. A corrupt `child_count` can only make individual child follows fail
  bounds/invariant checks; it can never cause an over-read or an unbounded walk.

CRC-32 is an integrity check against accidental corruption / bit-rot, **not** a
security MAC; it does not authenticate a deliberately-forged buffer. A buffer
that survives `loadVerified` is only guaranteed *safe to query* (no crash / OOB /
hang), not *trustworthy in content*. Sign the file at a higher layer if producer
authenticity matters.

## Verification

- **Differential oracle:** a naive linear-scan reference computes the true
  bbox-membership multiset and the true kNN (exact distances, identical metric +
  tie-break) and must agree exactly with the index over randomized point sets and
  queries — bbox set equal, kNN sequence + order + `dist2` equal.
- **Adversarial sets:** empty, single point, all-identical, collinear, duplicate
  coordinates with different values, points on a bbox edge/corner, zero-area
  (point) bbox, `k` > set size, pole/antimeridian extremes, a bbox matching
  everything (budget/capacity paths), NaN/inf rejected at build.
- **Corrupt-buffer fuzz:** `std.testing.fuzz` hammers the loader + query path
  with arbitrary and mutated-valid bytes; only typed errors, never a panic.
- **Positive controls:** a corrupted leaf value makes the index disagree with the
  oracle (and the body CRC catches it); a hand-crafted self-pointing child is
  rejected as `error.Corrupt`, not looped — proving the checkers have teeth.
- **Round-trip:** in-memory answers == answers after build → freeze → load; freeze
  is deterministic (byte-identical on refreeze).
- Green in Debug and `-Doptimize=ReleaseFast`; `zig fmt --check` clean;
  `zig build check-catalog` exit 0.

## Deliberately deferred

- **Great-circle / haversine kNN** with a spherical box lower-bound (see above).
- **Full antimeridian handling** — a ±180-wrapping bbox and a wrap-aware kNN
  metric; today the caller splits such queries.
- **STR (Sort-Tile-Recursive) bulk-load** — tiles the plane before the Hilbert
  pass for slightly tighter leaf boxes; the current single-axis Hilbert order is
  simpler and already gives good locality.
- **Fixed-point coordinate storage** — halves box bytes at the cost of a lossy
  round-trip; unnecessary at RÚIAN scale.
- **Configurable / SIMD node fan-out and a dense root fan-out table** — the
  fan-out is fixed at 16; the decoder already reads `child_count` per node, so a
  build-time change needs no format change.
- **On-disk / larger-than-RAM build** — the pack currently holds the node pool in
  memory before freezing.
- **Payloads wider than `u32`** — callers store a `u32` record id and indirect
  through their own table (same as the sibling `trie`).
