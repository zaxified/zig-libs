// SPDX-License-Identifier: MIT

//! query — the read side: load a frozen buffer and answer spatial queries
//! against it IN PLACE, with no copy of the index and no allocation on the
//! bbox path (a caller-supplied result buffer + a fixed inline DFS stack). The
//! kNN path is also allocation-free: the caller supplies the priority-queue
//! scratch.
//!
//! Two query shapes:
//!   * `bbox(rect, out, opts)` — every indexed point inside an axis-aligned
//!                               lat/lon rectangle (edges INCLUSIVE), with a
//!                               visit budget and a distinguishable truncation.
//!   * `knn(lat, lon, k, out, scratch, opts)` — the k nearest points to a query
//!                               point, ranked ascending, best-first / bounded.
//!
//! Every index followed out of the (possibly untrusted) buffer is bounds- and
//! invariant-checked in `format` (`Nodes.at`, `Nodes.child`); a corrupt buffer
//! yields `error.Corrupt`, never an OOB read, panic, or infinite loop.
//! Traversal termination rests on the strictly-decreasing child-index invariant
//! plus the explicit visit budget.

const std = @import("std");
const format = @import("format.zig");

pub const LoadError = format.LoadError;
pub const QueryError = format.DecodeError || error{ StackOverflow, ScratchTooSmall };

// ── result types ─────────────────────────────────────────────────────────────

/// A point returned by `bbox`. `lat`/`lon` are the exact stored coordinates
/// (f64, byte-identical to what was indexed — no quantization).
pub const Match = struct { value: u32, lat: f64, lon: f64 };

/// A point returned by `knn`, plus its ranking distance. `dist2` is the SQUARED
/// distance in the equirectangular ranking metric (see the ranking contract
/// below), NOT a physical distance in metres — it is a monotone proxy for the
/// great-circle distance suitable for ordering nearest neighbours locally.
pub const Neighbor = struct { value: u32, lat: f64, lon: f64, dist2: f64 };

pub const BboxStatus = enum {
    /// Every point under the query rectangle was reported; `items` is complete.
    complete,
    /// The result buffer filled before the scan finished; `items` is a partial
    /// (arbitrary) subset. Enlarge `out` and retry for the full set.
    truncated_capacity,
    /// The visit budget was hit; `items` is a partial subset.
    truncated_budget,
};

pub const KnnStatus = enum {
    /// `items` holds the true nearest min(k, item_count) points, in order.
    complete,
    /// The visit budget was hit; `items` is a correct PREFIX of the true kNN
    /// (best-first emits in exact order), just shorter than requested.
    truncated_budget,
};

pub const BboxResult = struct { items: []Match, status: BboxStatus };
pub const KnnResult = struct { items: []Neighbor, status: KnnStatus };

/// Options bounding a query's work — the DoS guard. `max_visited` caps the
/// number of node records the query may decode; on reaching it the query stops
/// and reports a truncated result. 0 means "unbounded" — do not use on
/// attacker-influenced queries.
pub const QueryOptions = struct {
    max_visited: usize = 100_000,
};

/// Fixed inline DFS stack cap for `bbox`. A packed R-tree's stack depth is
/// bounded by height × fanout (a few hundred for billions of points); this cap
/// is far above that. A buffer that would overflow it is treated as corrupt.
pub const max_stack: usize = 4096;

// ── Frozen: a loaded, query-ready view over a frozen buffer ──────────────────

pub const Frozen = struct {
    nodes: format.Nodes,
    header: format.Header,

    /// Fast open: validate the header only (O(1)) and keep the buffer by
    /// reference (zero-copy). Per-node bounds-checking during queries keeps
    /// traversal safe even though the body was not scanned here.
    pub fn load(buf: []const u8) LoadError!Frozen {
        const header = try format.Header.load(buf);
        return .{ .nodes = format.Nodes.init(buf, header), .header = header };
    }

    /// Untrusted-file open: `load` plus a full node-region CRC check. Prefer this
    /// for files from outside the process trust boundary; queries remain
    /// bounds-checked regardless, but this rejects silent bit-rot up front.
    pub fn loadVerified(buf: []const u8) LoadError!Frozen {
        const f = try load(buf);
        try f.header.verifyBody(buf);
        return f;
    }

    pub fn itemCount(self: Frozen) u64 {
        return self.header.item_count;
    }

    // ── bbox ───────────────────────────────────────────────────────────────
    //
    // Edge contract: the rectangle is CLOSED — a point exactly on an edge or
    // corner (lat == min_lat/max_lat, or lon == min_lon/max_lon) is INCLUDED.
    // A zero-area rectangle (min == max on both axes) is a valid point query.
    // The caller must pass min <= max on each axis (an inverted rectangle simply
    // matches nothing); the rectangle must not cross the antimeridian in v1
    // (see SPEC.md).

    /// All indexed points inside the closed rectangle
    /// `[min_lat,max_lat] × [min_lon,max_lon]`, written into `out`. No
    /// allocation. Returns the filled prefix of `out` and a status distinguishing
    /// a complete answer from one truncated by buffer capacity or the visit
    /// budget.
    pub fn bbox(
        self: Frozen,
        min_lat: f64,
        max_lat: f64,
        min_lon: f64,
        max_lon: f64,
        out: []Match,
        opts: QueryOptions,
    ) QueryError!BboxResult {
        if (self.header.item_count == 0 or out.len == 0)
            return .{ .items = out[0..0], .status = if (out.len == 0 and self.header.item_count != 0) .truncated_capacity else .complete };

        var stack: [max_stack]u32 = undefined;
        var sp: usize = 0;
        stack[sp] = self.header.root_index;
        sp += 1;

        var n_out: usize = 0;
        var visited: usize = 0;

        while (sp > 0) {
            sp -= 1;
            const node = try self.nodes.at(stack[sp]);

            if (opts.max_visited != 0 and visited >= opts.max_visited)
                return .{ .items = out[0..n_out], .status = .truncated_budget };
            visited += 1;

            // Prune: skip a node whose bbox does not meet the query rectangle.
            if (!boxesIntersect(node.min_lat, node.max_lat, node.min_lon, node.max_lon, min_lat, max_lat, min_lon, max_lon))
                continue;

            if (node.leaf) {
                // A leaf's bbox is its point; intersection above already proved
                // the point is inside the closed rectangle.
                if (n_out >= out.len)
                    return .{ .items = out[0..n_out], .status = .truncated_capacity };
                out[n_out] = .{ .value = node.data, .lat = node.min_lat, .lon = node.min_lon };
                n_out += 1;
            } else {
                var c: u32 = 0;
                while (c < node.child_count) : (c += 1) {
                    const child_index = std.math.add(u32, node.data, c) catch return error.Corrupt;
                    const ch = try self.nodes.child(node, child_index);
                    if (boxesIntersect(ch.min_lat, ch.max_lat, ch.min_lon, ch.max_lon, min_lat, max_lat, min_lon, max_lon)) {
                        if (sp >= stack.len) return error.StackOverflow;
                        stack[sp] = child_index;
                        sp += 1;
                    }
                }
            }
        }
        return .{ .items = out[0..n_out], .status = .complete };
    }

    // ── kNN ──────────────────────────────────────────────────────────────────
    //
    // Best-first R-tree search over a min-heap held in the caller's `scratch`.
    // The heap holds pending internal nodes (keyed by the lower-bound distance
    // from the query point to the node's bbox) and pending leaf points (keyed by
    // the exact point distance). Popping the heap minimum always yields either
    // the next-nearest point (emit it) or the nearest unexplored node (expand
    // it) — a leaf point can never be beaten by anything still inside a node
    // whose bbox is farther away. So results come out in exact ascending order;
    // a budget cut therefore returns a correct, merely shorter, prefix.
    //
    // Ranking metric (documented in README/SPEC): an equirectangular
    // approximation scaled by cos(query latitude). With qk = cos(qlat):
    //   dx = (lon - qlon) * qk ;  dy = lat - qlat ;  dist2 = dx*dx + dy*dy
    // The node bbox lower bound is the squared distance from the (scaled) query
    // point to the (scaled) axis-aligned node rectangle — a true lower bound in
    // that metric, so pruning never drops a real neighbour. Total order used for
    // ties: (dist2 asc, value asc, lat asc, lon asc); equal keys are identical
    // points. See SPEC.md for why great-circle is deferred.

    /// The `k` nearest indexed points to `(lat, lon)`, ascending by distance,
    /// into `out` (need `k` slots). `scratch` is the heap workspace; size it via
    /// `knnScratchLen` — too small yields `error.ScratchTooSmall`. No allocation.
    pub fn knn(
        self: Frozen,
        lat: f64,
        lon: f64,
        k: usize,
        out: []Neighbor,
        scratch: []HeapEntry,
        opts: QueryOptions,
    ) QueryError!KnnResult {
        const want = @min(k, out.len);
        if (want == 0 or self.header.item_count == 0)
            return .{ .items = out[0..0], .status = .complete };

        const qk = std.math.cos(lat * std.math.pi / 180.0);
        var heap = Heap{ .buf = scratch };

        // Seed with the root — as a point if it is itself a leaf, else as a node.
        const root = try self.nodes.at(self.header.root_index);
        try heap.push(seedEntry(root, lat, lon, qk));

        var n_out: usize = 0;
        var visited: usize = 0;

        while (heap.len > 0 and n_out < want) {
            if (opts.max_visited != 0 and visited >= opts.max_visited)
                return .{ .items = out[0..n_out], .status = .truncated_budget };
            visited += 1;

            const e = heap.pop();
            if (e.is_point) {
                out[n_out] = .{ .value = e.value, .lat = e.lat, .lon = e.lon, .dist2 = e.dist2 };
                n_out += 1;
            } else {
                const node = try self.nodes.at(e.node_index);
                var c: u32 = 0;
                while (c < node.child_count) : (c += 1) {
                    const child_index = std.math.add(u32, node.data, c) catch return error.Corrupt;
                    const ch = try self.nodes.child(node, child_index);
                    try heap.push(seedEntry(ch, lat, lon, qk));
                }
            }
        }
        return .{ .items = out[0..n_out], .status = .complete };
    }
};

/// A conservative upper bound on the heap size a `knn(k, …)` needs: the search
/// never holds more than the seeded root plus, per expanded node, its `fanout`
/// children, and it stops after emitting `k`. This bound (k + a generous node
/// allowance) is always safe; a query that would exceed it returns
/// `error.ScratchTooSmall` rather than over-reading.
pub fn knnScratchLen(k: usize, fanout: u16, item_count: u64) usize {
    const cap = @min(item_count, @as(u64, k) + 1) + item_count / @max(@as(u64, 1), fanout - 1) + fanout + 8;
    return @intCast(@min(cap, item_count + fanout + 8));
}

/// Build the heap entry for a node view: a point entry for a leaf (exact point
/// distance), a node entry for an internal node (bbox lower-bound distance).
fn seedEntry(node: format.NodeView, qlat: f64, qlon: f64, qk: f64) HeapEntry {
    if (node.leaf) {
        return .{
            .dist2 = pointDist2(qlat, qlon, node.min_lat, node.min_lon, qk),
            .is_point = true,
            .node_index = 0,
            .value = node.data,
            .lat = node.min_lat,
            .lon = node.min_lon,
        };
    }
    return .{
        .dist2 = boxDist2(qlat, qlon, node.min_lat, node.max_lat, node.min_lon, node.max_lon, qk),
        .is_point = false,
        .node_index = node.index,
        .value = 0,
        .lat = 0,
        .lon = 0,
    };
}

// ── geometry (ranking metric + rectangle predicates) ─────────────────────────

/// Inclusive (closed-rectangle) box/box overlap test: touching edges count as
/// intersecting. Used both for internal-node pruning and (with a degenerate leaf
/// box) for the point-in-rectangle test.
fn boxesIntersect(
    a_min_lat: f64,
    a_max_lat: f64,
    a_min_lon: f64,
    a_max_lon: f64,
    b_min_lat: f64,
    b_max_lat: f64,
    b_min_lon: f64,
    b_max_lon: f64,
) bool {
    return a_max_lat >= b_min_lat and a_min_lat <= b_max_lat and
        a_max_lon >= b_min_lon and a_min_lon <= b_max_lon;
}

fn pointDist2(qlat: f64, qlon: f64, lat: f64, lon: f64, qk: f64) f64 {
    const dy = lat - qlat;
    const dx = (lon - qlon) * qk;
    return dx * dx + dy * dy;
}

/// Squared distance from the (scaled) query point to a (scaled) axis-aligned
/// node rectangle — a lower bound on the distance to any point it contains.
fn boxDist2(qlat: f64, qlon: f64, min_lat: f64, max_lat: f64, min_lon: f64, max_lon: f64, qk: f64) f64 {
    const dy = axisGap(qlat, min_lat, max_lat);
    const dx = axisGap(qlon * qk, min_lon * qk, max_lon * qk);
    return dx * dx + dy * dy;
}

fn axisGap(v: f64, lo: f64, hi: f64) f64 {
    if (v < lo) return lo - v;
    if (v > hi) return v - hi;
    return 0;
}

// ── min-heap over caller scratch (no allocation) ─────────────────────────────

/// One pending item in the kNN priority queue: either a leaf point (emit) or an
/// internal node (expand). Kept as one flat struct so the heap is a plain array.
pub const HeapEntry = struct {
    dist2: f64,
    is_point: bool,
    node_index: u32,
    value: u32,
    lat: f64,
    lon: f64,
};

/// Total order for the heap. Primary key: distance ascending. At an equal
/// distance a NODE sorts before a POINT — so every node that could hide a
/// tied-distance point is expanded before any point at that distance is emitted,
/// keeping the point tie-break exact. Among points: (value, lat, lon) ascending.
fn entryBefore(a: HeapEntry, b: HeapEntry) bool {
    if (a.dist2 != b.dist2) return a.dist2 < b.dist2;
    if (a.is_point != b.is_point) return !a.is_point; // node before point
    if (!a.is_point) return a.node_index < b.node_index; // deterministic node order
    if (a.value != b.value) return a.value < b.value;
    if (a.lat != b.lat) return a.lat < b.lat;
    return a.lon < b.lon;
}

const Heap = struct {
    buf: []HeapEntry,
    len: usize = 0,

    fn push(self: *Heap, e: HeapEntry) QueryError!void {
        if (self.len >= self.buf.len) return error.ScratchTooSmall;
        var i = self.len;
        self.buf[i] = e;
        self.len += 1;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (!entryBefore(self.buf[i], self.buf[parent])) break;
            std.mem.swap(HeapEntry, &self.buf[i], &self.buf[parent]);
            i = parent;
        }
    }

    fn pop(self: *Heap) HeapEntry {
        std.debug.assert(self.len > 0);
        const top = self.buf[0];
        self.len -= 1;
        if (self.len > 0) {
            self.buf[0] = self.buf[self.len];
            var i: usize = 0;
            while (true) {
                const l = 2 * i + 1;
                const r = 2 * i + 2;
                var smallest = i;
                if (l < self.len and entryBefore(self.buf[l], self.buf[smallest])) smallest = l;
                if (r < self.len and entryBefore(self.buf[r], self.buf[smallest])) smallest = r;
                if (smallest == i) break;
                std.mem.swap(HeapEntry, &self.buf[i], &self.buf[smallest]);
                i = smallest;
            }
        }
        return top;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const builder = @import("builder.zig");
const testing = std.testing;

fn build(points: []const builder.Point) ![]u8 {
    return builder.freezeFromPoints(testing.allocator, testing.allocator, points);
}

test "bbox: closed rectangle includes edge and corner points" {
    const buf = try build(&.{
        .{ .lat = 0, .lon = 0, .value = 1 }, // corner
        .{ .lat = 5, .lon = 0, .value = 2 }, // on min_lon edge
        .{ .lat = 10, .lon = 10, .value = 3 }, // opposite corner
        .{ .lat = 20, .lon = 20, .value = 4 }, // outside
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [8]Match = undefined;
    const r = try f.bbox(0, 10, 0, 10, &out, .{});
    try testing.expectEqual(BboxStatus.complete, r.status);
    try testing.expectEqual(@as(usize, 3), r.items.len);
    var mask: u8 = 0;
    for (r.items) |m| mask |= @as(u8, 1) << @intCast(m.value - 1);
    try testing.expectEqual(@as(u8, 0b0111), mask); // values 1,2,3
}

test "bbox: zero-area rectangle is a point query" {
    const buf = try build(&.{
        .{ .lat = 3, .lon = 4, .value = 42 },
        .{ .lat = 3, .lon = 5, .value = 43 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [4]Match = undefined;
    const r = try f.bbox(3, 3, 4, 4, &out, .{});
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expectEqual(@as(u32, 42), r.items[0].value);
}

test "bbox: capacity and budget truncation are distinguishable" {
    var b = builder.Builder.init(testing.allocator);
    defer b.deinit();
    for (0..200) |i| try b.add(@floatFromInt(i % 20), @floatFromInt(i / 20), @intCast(i));
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);

    var small: [3]Match = undefined;
    const r1 = try f.bbox(-1, 100, -1, 100, &small, .{}); // matches all → overflow
    try testing.expectEqual(BboxStatus.truncated_capacity, r1.status);
    try testing.expectEqual(@as(usize, 3), r1.items.len);

    var big: [300]Match = undefined;
    const r2 = try f.bbox(-1, 100, -1, 100, &big, .{ .max_visited = 5 });
    try testing.expectEqual(BboxStatus.truncated_budget, r2.status);
}

test "knn: ranks nearest-first and handles k > item_count" {
    const buf = try build(&.{
        .{ .lat = 0, .lon = 0, .value = 10 },
        .{ .lat = 0, .lon = 1, .value = 11 },
        .{ .lat = 0, .lon = 3, .value = 12 },
        .{ .lat = 0, .lon = 6, .value = 13 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [10]Neighbor = undefined;
    var scratch: [64]HeapEntry = undefined;
    const r = try f.knn(0, 0.4, 10, &out, &scratch, .{});
    try testing.expectEqual(KnnStatus.complete, r.status);
    try testing.expectEqual(@as(usize, 4), r.items.len); // k clamped to set size
    try testing.expectEqual(@as(u32, 10), r.items[0].value); // nearest to lon 0.4
    try testing.expectEqual(@as(u32, 11), r.items[1].value);
    try testing.expectEqual(@as(u32, 12), r.items[2].value);
    try testing.expectEqual(@as(u32, 13), r.items[3].value);
    // Distances ascending.
    for (1..r.items.len) |i| try testing.expect(r.items[i].dist2 >= r.items[i - 1].dist2);
}

test "knn: scratch too small is a typed error, not a crash" {
    var b = builder.Builder.init(testing.allocator);
    defer b.deinit();
    for (0..100) |i| try b.add(@floatFromInt(i % 10), @floatFromInt(i / 10), @intCast(i));
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [50]Neighbor = undefined;
    var tiny: [2]HeapEntry = undefined;
    try testing.expectError(error.ScratchTooSmall, f.knn(5, 5, 50, &out, &tiny, .{}));
}
