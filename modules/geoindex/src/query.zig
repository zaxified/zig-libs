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

/// An item returned by `bbox`: `lat`/`lon` are the exact stored coordinates (f64, byte-identical
/// to what was indexed — no quantization) of a point, or the minimum corner of a rectangle added
/// by `Builder.addBox`; `max_lat`/`max_lon` the maximum corner (equal to `lat`/`lon` for a point).
pub const Match = struct {
    value: u32,
    lat: f64,
    lon: f64,
    max_lat: f64,
    max_lon: f64,

    /// A point (not a rectangle with extent).
    pub fn isPoint(m: Match) bool {
        return m.lat == m.max_lat and m.lon == m.max_lon;
    }
};

/// An item returned by `knn` or `within`, plus its ranking distance. `dist2` is the SQUARED
/// distance in the metric of `QueryOptions.metric`: for `.planar` the equirectangular ranking
/// metric (degrees squared; NOT a physical distance, a monotone proxy for ordering nearest
/// neighbours locally), for `.great_circle` metres squared (`dist()` is the metres). For a
/// rectangle the distance is that to its nearest point, 0 when the query is inside it.
pub const Neighbor = struct {
    value: u32,
    lat: f64,
    lon: f64,
    max_lat: f64,
    max_lon: f64,
    dist2: f64,

    /// The distance itself (`sqrt(dist2)`): metres under `.great_circle`, ranking degrees under `.planar`.
    pub fn dist(n: Neighbor) f64 {
        return @sqrt(n.dist2);
    }
};

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

/// `within` reports the same statuses as `bbox` (complete / capacity / budget).
pub const WithinStatus = BboxStatus;
pub const WithinResult = struct { items: []Neighbor, status: WithinStatus };
pub const BboxResult = struct { items: []Match, status: BboxStatus };
pub const KnnResult = struct { items: []Neighbor, status: KnnStatus };

/// Options bounding a query's work — the DoS guard. `max_visited` caps the
/// number of node records the query may decode; on reaching it the query stops
/// and reports a truncated result. 0 means "unbounded" — do not use on
/// attacker-influenced queries.
pub const QueryOptions = struct {
    max_visited: usize = 100_000,
    /// Optional predicate applied to every candidate point DURING the search
    /// (geoflatbush `filterFn`). A rejected point is neither reported nor counted
    /// against the result capacity / `k`, so `knn` still returns the k nearest
    /// points that pass. Rejecting points does not widen the visit budget.
    filter: ?Filter = null,
    /// How `knn` ranks and `within` measures (`dist2`, `radius`): see `Metric`.
    metric: Metric = .planar,
};

/// The distance `knn` and `within` use.
pub const Metric = enum {
    /// The equirectangular ranking metric: degrees of latitude, with the longitude difference
    /// (taken the short way round the antimeridian) scaled by cos(query latitude). Cheap and
    /// exact enough for ordering locally; it degrades away from the query latitude and near the
    /// poles, and `radius` is in degrees.
    planar,
    /// Great-circle (haversine) distance on a sphere of radius 6371 km (geoflatbush's), in
    /// METRES: `radius` is metres, `dist2` metres squared. Correct near the poles and across
    /// the antimeridian; costs a few trigonometric calls per node.
    great_circle,
};

/// A point predicate with a context pointer (no closures in Zig). `func` is
/// called with `ctx` and the candidate point; return true to keep it. It must
/// not mutate the index buffer.
pub const Filter = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, point: Match) bool,

    fn keep(self: Filter, point: Match) bool {
        return self.func(self.ctx, point);
    }
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
    // An inverted LATITUDE range (min_lat > max_lat) matches nothing.
    //
    // Antimeridian: `min_lon > max_lon` means the rectangle wraps across ±180°
    // and is answered as the union of `[min_lon, 180]` and `[-180, max_lon]`
    // (two disjoint passes, so no point is reported twice). Both passes share
    // `out`, the visit budget (`max_visited` counts both) and the filter; the
    // status is that of the first pass that truncated. Before such a
    // rectangle silently matched nothing. NaN bounds still match nothing.

    /// All indexed points inside the closed rectangle
    /// `[min_lat,max_lat] × [min_lon,max_lon]` (or, if `min_lon > max_lon`, the
    /// antimeridian-wrapping one, see above), written into `out`. No
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

        var visited: usize = 0;
        if (!(min_lon > max_lon)) {
            const r = try self.bboxPass(min_lat, max_lat, min_lon, max_lon, out, opts, &visited);
            return r;
        }
        // Wrapping rectangle: east part, then west part into the rest of `out`.
        const east = try self.bboxPass(min_lat, max_lat, min_lon, 180, out, opts, &visited);
        if (east.status != .complete) return east;
        const n1 = east.items.len;
        const west = try self.bboxPass(min_lat, max_lat, -180, max_lon, out[n1..], opts, &visited);
        return .{ .items = out[0 .. n1 + west.items.len], .status = west.status };
    }

    /// One non-wrapping pass; `visited` accumulates across passes so the budget
    /// is shared. `out` may be empty (a match then reports `truncated_capacity`).
    fn bboxPass(
        self: Frozen,
        min_lat: f64,
        max_lat: f64,
        min_lon: f64,
        max_lon: f64,
        out: []Match,
        opts: QueryOptions,
        visited_total: *usize,
    ) QueryError!BboxResult {
        var stack: [max_stack]u32 = undefined;
        var sp: usize = 0;
        stack[sp] = self.header.root_index;
        sp += 1;

        var n_out: usize = 0;
        var visited: usize = visited_total.*;
        defer visited_total.* = visited;

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
                // A leaf's bbox is its point (or rectangle); intersection above already proved
                // it meets the closed query rectangle.
                const m = Match{ .value = node.data, .lat = node.min_lat, .lon = node.min_lon, .max_lat = node.max_lat, .max_lon = node.max_lon };
                if (opts.filter) |flt| if (!flt.keep(m)) continue;
                if (n_out >= out.len)
                    return .{ .items = out[0..n_out], .status = .truncated_capacity };
                out[n_out] = m;
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

    // ── within (radius) ──────────────────────────────────────────────────────
    //
    // Every item whose distance (`QueryOptions.metric`) to (lat, lon) is <= `radius`: for the default
    // `.planar` metric the equirectangular ranking metric of `knn` (DEGREES of latitude, the
    // longitude difference taken the short way round the antimeridian and scaled by cos(query
    // latitude)), the planar kdbush `within`; for `.great_circle` METRES on a sphere of 6371 km.
    // Each result carries `dist2` (= squared distance, <= radius^2; for a rectangle item that to
    // its nearest point). Order is unspecified (depth-first); sort by `dist2` if needed. A
    // negative or NaN radius, or NaN query coordinates, match nothing; radius 0 matches the
    // items exactly at the query. Subtrees whose bbox lower bound exceeds the radius (padded
    // against rounding) are pruned.

    /// All indexed points within `radius` of `(lat, lon)` (see above), into
    /// `out`. No allocation. Status as for `bbox`.
    pub fn within(
        self: Frozen,
        lat: f64,
        lon: f64,
        radius: f64,
        out: []Neighbor,
        opts: QueryOptions,
    ) QueryError!WithinResult {
        if (self.header.item_count == 0 or !(radius >= 0))
            return .{ .items = out[0..0], .status = .complete };
        if (out.len == 0) return .{ .items = out[0..0], .status = .truncated_capacity };

        const rk = Ranker.init(opts.metric, lat, lon);
        const r2 = radius * radius;
        const r_pad = radius + rk.pad();
        const prune2 = r_pad * r_pad;

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

            if (node.leaf) {
                const d2 = rk.leaf(node);
                if (!(d2 <= r2)) continue;
                if (opts.filter) |flt| {
                    if (!flt.keep(.{ .value = node.data, .lat = node.min_lat, .lon = node.min_lon, .max_lat = node.max_lat, .max_lon = node.max_lon })) continue;
                }
                if (n_out >= out.len)
                    return .{ .items = out[0..n_out], .status = .truncated_capacity };
                out[n_out] = .{ .value = node.data, .lat = node.min_lat, .lon = node.min_lon, .max_lat = node.max_lat, .max_lon = node.max_lon, .dist2 = d2 };
                n_out += 1;
            } else {
                var c: u32 = 0;
                while (c < node.child_count) : (c += 1) {
                    const child_index = std.math.add(u32, node.data, c) catch return error.Corrupt;
                    const ch = try self.nodes.child(node, child_index);
                    const bd2 = if (ch.leaf) rk.leaf(ch) else rk.box(ch.min_lat, ch.max_lat, ch.min_lon, ch.max_lon);
                    // A leaf child is tested exactly when popped; here only prune
                    // internal subtrees (and leaves clearly out of range).
                    if (bd2 <= prune2 or bd2 != bd2) {
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
    // Ranking metric (documented in README/SPEC): by default an equirectangular
    // approximation scaled by cos(query latitude). With qk = cos(qlat):
    //   dx = wrap(lon - qlon) * qk ;  dy = lat - qlat ;  dist2 = dx*dx + dy*dy
    // (`wrap`: the longitude difference the short way round, into [-180, 180]). The node bbox
    // lower bound is the squared distance from the (scaled) query point to the (scaled)
    // axis-aligned node rectangle, over the three copies of the box a turn of longitude apart — a
    // true lower bound in that metric, so pruning never drops a real neighbour. With
    // `QueryOptions.metric = .great_circle` the distance is haversine in metres and the bound
    // the great-circle distance to the rectangle. Total order used for ties: (dist2 asc, value
    // asc, lat asc, lon asc); equal keys are identical items. See SPEC.md.

    /// The `k` nearest indexed items to `(lat, lon)`, ascending by distance,
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

        const rk = Ranker.init(opts.metric, lat, lon);
        var heap = Heap{ .buf = scratch };

        // Seed with the root — as a point if it is itself a leaf, else as a node.
        const root = try self.nodes.at(self.header.root_index);
        try heap.push(seedEntry(root, rk));

        var n_out: usize = 0;
        var visited: usize = 0;

        while (heap.len > 0 and n_out < want) {
            if (opts.max_visited != 0 and visited >= opts.max_visited)
                return .{ .items = out[0..n_out], .status = .truncated_budget };
            visited += 1;

            const e = heap.pop();
            if (e.is_point) {
                if (opts.filter) |flt| {
                    if (!flt.keep(.{ .value = e.value, .lat = e.lat, .lon = e.lon, .max_lat = e.max_lat, .max_lon = e.max_lon })) continue;
                }
                out[n_out] = .{ .value = e.value, .lat = e.lat, .lon = e.lon, .max_lat = e.max_lat, .max_lon = e.max_lon, .dist2 = e.dist2 };
                n_out += 1;
            } else {
                const node = try self.nodes.at(e.node_index);
                var c: u32 = 0;
                while (c < node.child_count) : (c += 1) {
                    const child_index = std.math.add(u32, node.data, c) catch return error.Corrupt;
                    const ch = try self.nodes.child(node, child_index);
                    try heap.push(seedEntry(ch, rk));
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

/// Build the heap entry for a node view: a point entry for a leaf (exact distance to the
/// point or rectangle), a node entry for an internal node (bbox lower-bound distance).
fn seedEntry(node: format.NodeView, rk: Ranker) HeapEntry {
    if (node.leaf) {
        return .{
            .dist2 = rk.leaf(node),
            .is_point = true,
            .node_index = 0,
            .value = node.data,
            .lat = node.min_lat,
            .lon = node.min_lon,
            .max_lat = node.max_lat,
            .max_lon = node.max_lon,
        };
    }
    return .{
        .dist2 = rk.box(node.min_lat, node.max_lat, node.min_lon, node.max_lon),
        .is_point = false,
        .node_index = node.index,
        .value = 0,
        .lat = 0,
        .lon = 0,
        .max_lat = 0,
        .max_lon = 0,
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

/// Mean Earth radius of geoflatbush (6371 km), in metres.
const earth_radius_m: f64 = 6_371_000.0;
const rad: f64 = std.math.pi / 180.0;

/// A longitude difference taken the short way round: into [-180, 180].
fn wrapLon(d: f64) f64 {
    return d - 360.0 * @round(d / 360.0);
}

/// One query point and the metric it is measured in: every distance `within` and `knn` compare
/// comes from here, so the ranking, the pruning lower bounds and the final distances agree.
const Ranker = struct {
    metric: Metric,
    qlat: f64,
    qlon: f64,
    /// `.planar`: cos(query latitude). `.great_circle`: cos of it too (a haversine term).
    qk: f64,

    fn init(metric: Metric, lat: f64, lon: f64) Ranker {
        return .{ .metric = metric, .qlat = lat, .qlon = lon, .qk = std.math.cos(lat * std.math.pi / 180.0) };
    }

    /// Slack added to a radius before pruning against a lower bound, against rounding.
    fn pad(r: Ranker) f64 {
        return switch (r.metric) {
            .planar => 1e-9,
            .great_circle => 1e-3,
        };
    }

    /// Squared distance to a leaf: its point, or the nearest point of its rectangle.
    fn leaf(r: Ranker, n: format.NodeView) f64 {
        if (n.min_lat == n.max_lat and n.min_lon == n.max_lon) return r.point(n.min_lat, n.min_lon);
        return r.box(n.min_lat, n.max_lat, n.min_lon, n.max_lon);
    }

    /// Squared distance to a point.
    fn point(r: Ranker, lat: f64, lon: f64) f64 {
        switch (r.metric) {
            .planar => {
                const dy = lat - r.qlat;
                const dx = wrapLon(lon - r.qlon) * r.qk;
                return dx * dx + dy * dy;
            },
            .great_circle => {
                const d = r.sphere(lat, lon);
                return d * d;
            },
        }
    }

    /// Haversine distance in metres to a point.
    fn sphere(r: Ranker, lat: f64, lon: f64) f64 {
        const sdl = @sin(wrapLon(lon - r.qlon) * rad / 2);
        const sdp = @sin((lat - r.qlat) * rad / 2);
        const h = sdp * sdp + r.qk * std.math.cos(lat * rad) * sdl * sdl;
        return 2 * earth_radius_m * std.math.asin(@sqrt(@min(h, 1.0)));
    }

    /// Squared distance from the query point to a rectangle: a lower bound on the distance to
    /// anything inside it, and the exact distance to a rectangle item.
    fn box(r: Ranker, min_lat: f64, max_lat: f64, min_lon: f64, max_lon: f64) f64 {
        switch (r.metric) {
            .planar => {
                const dy = axisGap(r.qlat, min_lat, max_lat);
                // Across the antimeridian a box may be nearer by a whole turn of longitude.
                var dx = axisGap(r.qlon * r.qk, min_lon * r.qk, max_lon * r.qk);
                dx = @min(dx, axisGap(r.qlon * r.qk, (min_lon - 360.0) * r.qk, (max_lon - 360.0) * r.qk));
                dx = @min(dx, axisGap(r.qlon * r.qk, (min_lon + 360.0) * r.qk, (max_lon + 360.0) * r.qk));
                return dx * dx + dy * dy;
            },
            .great_circle => {
                const d = r.sphereBox(min_lat, max_lat, min_lon, max_lon);
                return d * d;
            },
        }
    }

    /// Great-circle distance in metres to a lat/lon rectangle. Inside its longitudes the nearest
    /// point is on the query's meridian (the latitude gap, or 0); outside them it is on one of
    /// the two edge meridians: the foot of the perpendicular when it falls within the edge, else
    /// an end of it.
    fn sphereBox(r: Ranker, min_lat: f64, max_lat: f64, min_lon: f64, max_lon: f64) f64 {
        const t = @mod(r.qlon - min_lon, 360.0);
        if (max_lon - min_lon >= 360.0 or t <= max_lon - min_lon) {
            const gap = axisGap(r.qlat, min_lat, max_lat);
            return earth_radius_m * gap * rad;
        }
        return @min(r.meridianDist(min_lon, min_lat, max_lat), r.meridianDist(max_lon, min_lat, max_lat));
    }

    /// Distance in metres to the meridian arc at `lon` between two latitudes.
    fn meridianDist(r: Ranker, lon: f64, lo: f64, hi: f64) f64 {
        var best = @min(r.sphere(lo, lon), r.sphere(hi, lon));
        const dl = wrapLon(lon - r.qlon) * rad;
        const c = @cos(dl);
        if (c > 0) {
            // The foot of the perpendicular from the query to the meridian's great circle.
            const foot = std.math.atan(@tan(r.qlat * rad) / c) / rad;
            if (foot >= lo and foot <= hi) {
                const s = std.math.asin(@min(r.qk * @abs(@sin(dl)), 1.0));
                best = @min(best, earth_radius_m * s);
            }
        }
        return best;
    }
};

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
    max_lat: f64,
    max_lon: f64,
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

/// The planar ranking distance, as the tests below state it (`qk` is cos of the query latitude).
fn pointDist2(qlat: f64, qlon: f64, lat: f64, lon: f64, qk: f64) f64 {
    _ = qk;
    return Ranker.init(.planar, qlat, qlon).point(lat, lon);
}

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

fn wrapOracle(pts: []const builder.Point, min_lat: f64, max_lat: f64, min_lon: f64, max_lon: f64, hit: []bool) usize {
    var n: usize = 0;
    for (pts, 0..) |p, i| {
        const lat_ok = p.lat >= min_lat and p.lat <= max_lat;
        const lon_ok = if (min_lon > max_lon) (p.lon >= min_lon or p.lon <= max_lon) else (p.lon >= min_lon and p.lon <= max_lon);
        hit[i] = lat_ok and lon_ok;
        if (hit[i]) n += 1;
    }
    return n;
}

test "bbox: antimeridian-wrapping rectangle equals a brute-force scan (incl. lon = +-180 exactly)" {
    var prng = std.Random.DefaultPrng.init(0x180);
    const rnd = prng.random();
    var pts: [400]builder.Point = undefined;
    for (&pts, 0..) |*p, i| {
        // Quantised longitudes so that +-180 and the query edges are hit exactly.
        const lon_q: i32 = rnd.intRangeAtMost(i32, -36, 36);
        p.* = .{ .lat = @floatFromInt(rnd.intRangeAtMost(i32, -9, 9) * 10), .lon = @as(f64, @floatFromInt(lon_q)) * 5, .value = @intCast(i) };
    }
    pts[0].lon = 180;
    pts[1].lon = -180;
    const buf = try build(&pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [400]Match = undefined;
    var hit: [400]bool = undefined;
    const lons = [_][2]f64{ .{ 170, -170 }, .{ 180, -180 }, .{ 180, 180 }, .{ -180, 180 }, .{ 175, 175 }, .{ 100, -100 }, .{ 0, -5 }, .{ -180, -180 }, .{ 90, 80 } };
    for (lons) |lr| {
        for ([_][2]f64{ .{ -90, 90 }, .{ -30, 30 }, .{ 20, 20 }, .{ 40, -40 } }) |la| {
            const want = wrapOracle(&pts, la[0], la[1], lr[0], lr[1], &hit);
            const r = try f.bbox(la[0], la[1], lr[0], lr[1], &out, .{});
            try testing.expectEqual(BboxStatus.complete, r.status);
            try testing.expectEqual(want, r.items.len);
            var seen: [400]bool = @splat(false);
            for (r.items) |m| {
                try testing.expect(hit[m.value]); // matches the oracle
                try testing.expect(!seen[m.value]); // no duplicate
                seen[m.value] = true;
            }
        }
    }
    // The two extremes are reported by a wrapping query that spans them.
    const r = try f.bbox(-90, 90, 179, -179, &out, .{});
    var got180 = false;
    var got_m180 = false;
    for (r.items) |m| {
        if (m.value == 0) got180 = true;
        if (m.value == 1) got_m180 = true;
    }
    try testing.expect(got180 and got_m180);
}

test "bbox: wrapping rectangle shares capacity, budget and filter across both halves" {
    const buf = try build(&.{
        .{ .lat = 0, .lon = 179, .value = 1 }, // east half
        .{ .lat = 0, .lon = -179, .value = 2 }, // west half
        .{ .lat = 0, .lon = 0, .value = 3 }, // outside the wrap
        .{ .lat = 0, .lon = 178, .value = 4 }, // east half
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [8]Match = undefined;
    const all = try f.bbox(-1, 1, 170, -170, &out, .{});
    try testing.expectEqual(BboxStatus.complete, all.status);
    try testing.expectEqual(@as(usize, 3), all.items.len);
    // Capacity: 3 matches across both halves into 2 slots.
    const cap = try f.bbox(-1, 1, 170, -170, out[0..2], .{});
    try testing.expectEqual(BboxStatus.truncated_capacity, cap.status);
    try testing.expectEqual(@as(usize, 2), cap.items.len);
    // Exactly full, nothing left over: complete (3 slots, 3 matches).
    const exact = try f.bbox(-1, 1, 170, -170, out[0..3], .{});
    try testing.expectEqual(BboxStatus.complete, exact.status);
    try testing.expectEqual(@as(usize, 3), exact.items.len);
    // Only the west half matches, into one slot: fine.
    const west = try f.bbox(-1, 1, 179.5, -170, out[0..1], .{});
    try testing.expectEqual(BboxStatus.complete, west.status);
    try testing.expectEqual(@as(u32, 2), west.items[0].value);
    // Budget is shared: a single visit cannot finish even one pass.
    const bud = try f.bbox(-1, 1, 170, -170, &out, .{ .max_visited = 1 });
    try testing.expectEqual(BboxStatus.truncated_budget, bud.status);
    // ... and a generous budget over a tiny index completes.
    try testing.expectEqual(BboxStatus.complete, (try f.bbox(-1, 1, 170, -170, &out, .{ .max_visited = 1000 })).status);
    // Filter applies to both halves.
    const F = struct {
        fn evenOnly(_: ?*anyopaque, m: Match) bool {
            return m.value % 2 == 0;
        }
    };
    const fl = try f.bbox(-1, 1, 170, -170, &out, .{ .filter = .{ .func = F.evenOnly } });
    try testing.expectEqual(BboxStatus.complete, fl.status);
    try testing.expectEqual(@as(usize, 2), fl.items.len); // values 2 and 4
    // NaN and inverted latitude still match nothing.
    try testing.expectEqual(@as(usize, 0), (try f.bbox(1, -1, 170, -170, &out, .{})).items.len);
    try testing.expectEqual(@as(usize, 0), (try f.bbox(-1, 1, std.math.nan(f64), -170, &out, .{})).items.len);
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

test "bbox: an empty result buffer over a non-empty index is a capacity truncation, not complete" {
    const buf = try build(&.{.{ .lat = 1, .lon = 1, .value = 7 }});
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var none: [0]Match = .{};
    const r = try f.bbox(0, 2, 0, 2, &none, .{});
    try testing.expectEqual(BboxStatus.truncated_capacity, r.status);
}

test "bbox: the visit budget is exact — max_visited nodes are decoded, not one more" {
    // Five leaves under one root: a full scan decodes six records.
    const buf = try build(&.{
        .{ .lat = 0, .lon = 0, .value = 1 }, .{ .lat = 1, .lon = 0, .value = 2 },
        .{ .lat = 2, .lon = 0, .value = 3 }, .{ .lat = 3, .lon = 0, .value = 4 },
        .{ .lat = 4, .lon = 0, .value = 5 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expectEqual(@as(u32, 6), f.header.node_count);
    var out: [8]Match = undefined;
    try testing.expectEqual(BboxStatus.complete, (try f.bbox(-1, 5, -1, 1, &out, .{ .max_visited = 6 })).status);
    try testing.expectEqual(BboxStatus.truncated_budget, (try f.bbox(-1, 5, -1, 1, &out, .{ .max_visited = 5 })).status);
}

test "bbox: a node with more matching children than the DFS stack holds is StackOverflow, not an overrun" {
    // max_stack + 1 leaves at one point, all children of a single root.
    const leaves = max_stack + 1;
    const buf = try testing.allocator.alloc(u8, format.header_size + (leaves + 1) * format.node_size_bytes);
    defer testing.allocator.free(buf);
    for (0..leaves + 1) |i| {
        const base = format.header_size + i * format.node_size_bytes;
        const is_root = i == leaves;
        buf[base + format.off_flags] = if (is_root) 0 else format.leaf_bit;
        format.writeF64(buf, base + format.off_min_lat, 0);
        format.writeF64(buf, base + format.off_min_lon, 0);
        format.writeF64(buf, base + format.off_max_lat, 0);
        format.writeF64(buf, base + format.off_max_lon, 0);
        std.mem.writeInt(u32, buf[base + format.off_data ..][0..4], 0, .little);
        std.mem.writeInt(u16, buf[base + format.off_child_count ..][0..2], if (is_root) @intCast(leaves) else 0, .little);
    }
    const header = format.Header{ .flags = 0, .node_count = leaves + 1, .fanout = leaves, .item_count = leaves, .root_index = leaves };
    header.encode(buf, buf[format.header_size..]);
    const f = try Frozen.load(buf);
    var out: [1]Match = undefined;
    try testing.expectError(error.StackOverflow, f.bbox(0, 0, 0, 0, &out, .{}));
}

test "knn: the visit budget truncates" {
    const buf = try build(&.{
        .{ .lat = 0, .lon = 0, .value = 1 }, .{ .lat = 0, .lon = 1, .value = 2 },
        .{ .lat = 0, .lon = 2, .value = 3 },
    });
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [3]Neighbor = undefined;
    var scratch: [16]HeapEntry = undefined;
    // The root expansion is the one permitted visit; nothing is emitted.
    const r = try f.knn(0, 0, 3, &out, &scratch, .{ .max_visited = 1 });
    try testing.expectEqual(KnnStatus.truncated_budget, r.status);
    try testing.expectEqual(@as(usize, 0), r.items.len);
    const full = try f.knn(0, 0, 3, &out, &scratch, .{ .max_visited = 4 });
    try testing.expectEqual(KnnStatus.complete, full.status);
    try testing.expectEqual(@as(usize, 3), full.items.len);
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

test "knn: tied distance between a direct-child point and a node-wrapped point breaks by value, not discovery order" {
    // Hand-crafted 4-node buffer (bypasses the builder/Hilbert path) to pin an
    // exact heap-ordering scenario that no round-trip through `build` can
    // reliably reach: two points at the IDENTICAL distance from the query,
    // one a direct leaf child of the root, the other wrapped one level down
    // inside its own solo internal node. Expanding the root therefore pushes
    // one "point" heap entry and one "node" heap entry, tied at the same
    // dist2. `entryBefore`'s doc comment requires a node to be expanded
    // before an equal-distance point is emitted, precisely so the wrapped
    // point is discovered in time to compete on the documented value-asc
    // tie-break — if that ordering were wrong, the direct point would be
    // emitted first purely because it started the search already-expanded,
    // regardless of which one the tie-break should actually prefer.
    var buf: [format.header_size + 4 * format.node_size_bytes]u8 = undefined;

    // index0: leaf P (value=1) at (0, -5) — wrapped one level down; must win.
    const base0 = format.header_size + 0 * format.node_size_bytes;
    buf[base0 + format.off_flags] = format.leaf_bit;
    format.writeF64(&buf, base0 + format.off_min_lat, 0);
    format.writeF64(&buf, base0 + format.off_min_lon, -5);
    format.writeF64(&buf, base0 + format.off_max_lat, 0);
    format.writeF64(&buf, base0 + format.off_max_lon, -5);
    std.mem.writeInt(u32, buf[base0 + format.off_data ..][0..4], 1, .little);
    std.mem.writeInt(u16, buf[base0 + format.off_child_count ..][0..2], 0, .little);

    // index1: leaf Q (value=9) at (0, 5) — direct child of root; must lose.
    const base1 = format.header_size + 1 * format.node_size_bytes;
    buf[base1 + format.off_flags] = format.leaf_bit;
    format.writeF64(&buf, base1 + format.off_min_lat, 0);
    format.writeF64(&buf, base1 + format.off_min_lon, 5);
    format.writeF64(&buf, base1 + format.off_max_lat, 0);
    format.writeF64(&buf, base1 + format.off_max_lon, 5);
    std.mem.writeInt(u32, buf[base1 + format.off_data ..][0..4], 9, .little);
    std.mem.writeInt(u16, buf[base1 + format.off_child_count ..][0..2], 0, .little);

    // index2: internal node wrapping only P (index0) — its bbox degenerates to
    // P's point, so its lower-bound distance equals P's exact distance: a tie.
    const base2 = format.header_size + 2 * format.node_size_bytes;
    buf[base2 + format.off_flags] = 0;
    format.writeF64(&buf, base2 + format.off_min_lat, 0);
    format.writeF64(&buf, base2 + format.off_min_lon, -5);
    format.writeF64(&buf, base2 + format.off_max_lat, 0);
    format.writeF64(&buf, base2 + format.off_max_lon, -5);
    std.mem.writeInt(u32, buf[base2 + format.off_data ..][0..4], 0, .little); // child = index0
    std.mem.writeInt(u16, buf[base2 + format.off_child_count ..][0..2], 1, .little);

    // index3: root, children [index1, index2] (data=1, count=2).
    const base3 = format.header_size + 3 * format.node_size_bytes;
    buf[base3 + format.off_flags] = 0;
    format.writeF64(&buf, base3 + format.off_min_lat, 0);
    format.writeF64(&buf, base3 + format.off_min_lon, -5);
    format.writeF64(&buf, base3 + format.off_max_lat, 0);
    format.writeF64(&buf, base3 + format.off_max_lon, 5);
    std.mem.writeInt(u32, buf[base3 + format.off_data ..][0..4], 1, .little); // children start at index1
    std.mem.writeInt(u16, buf[base3 + format.off_child_count ..][0..2], 2, .little);

    const header = format.Header{ .flags = 0, .node_count = 4, .fanout = 16, .item_count = 2, .root_index = 3 };
    header.encode(&buf, buf[format.header_size..]);

    const f = try Frozen.load(&buf);
    var out: [1]Neighbor = undefined;
    var scratch: [8]HeapEntry = undefined;
    const r = try f.knn(0, 0, 1, &out, &scratch, .{});
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expectEqual(@as(f64, 25), r.items[0].dist2); // confirms the tie is real
    try testing.expectEqual(@as(u32, 1), r.items[0].value); // P (wrapped), not Q (direct)
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

// ── radius + filter tests (against a brute-force scan) ───────────────────────

const Rng = std.Random.DefaultPrng;

const Pt = struct { lat: f64, lon: f64 };

fn randomIndex(rng: *Rng, n: usize, pts: []Pt) ![]u8 {
    var b = builder.Builder.init(testing.allocator);
    defer b.deinit();
    for (0..n) |i| {
        const lat = rng.random().float(f64) * 160.0 - 80.0;
        const lon = rng.random().float(f64) * 340.0 - 170.0;
        pts[i] = .{ .lat = lat, .lon = lon };
        try b.add(lat, lon, @intCast(i));
    }
    return b.freeze(testing.allocator);
}

fn modFilter(ctx: ?*anyopaque, p: Match) bool {
    const m: *const u32 = @ptrCast(@alignCast(ctx.?));
    return p.value % m.* == 0;
}

fn rejectAll(_: ?*anyopaque, _: Match) bool {
    return false;
}

test "within: equals a brute-force scan over random points (incl. r = 0, tiny, huge)" {
    var rng = Rng.init(0x6e0_1d3);
    var pts: [600]Pt = undefined;
    const buf = try randomIndex(&rng, pts.len, &pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [600]Neighbor = undefined;
    const radii = [_]f64{ 0, 1e-12, 0.5, 3, 12, 40, 400 };
    for (0..40) |qi| {
        // Half the queries sit exactly on an indexed point.
        const q: Pt = if (qi % 2 == 0) pts[qi * 7 % pts.len] else .{
            .lat = rng.random().float(f64) * 180.0 - 90.0,
            .lon = rng.random().float(f64) * 360.0 - 180.0,
        };
        const qk = std.math.cos(q.lat * std.math.pi / 180.0);
        for (radii) |r| {
            var expect = std.bit_set.IntegerBitSet(600).empty;
            for (pts, 0..) |p, i| if (pointDist2(q.lat, q.lon, p.lat, p.lon, qk) <= r * r) expect.set(i);
            const res = try f.within(q.lat, q.lon, r, &out, .{ .max_visited = 0 });
            try testing.expectEqual(WithinStatus.complete, res.status);
            var got = std.bit_set.IntegerBitSet(600).empty;
            for (res.items) |m| {
                try testing.expect(!got.isSet(m.value)); // no duplicates
                got.set(m.value);
                try testing.expect(m.dist2 <= r * r);
                try testing.expectEqual(pts[m.value].lat, m.lat);
            }
            try testing.expect(expect.eql(got));
            if (r == 0 and qi % 2 == 0) try testing.expect(res.items.len >= 1);
        }
    }
}

test "within: empty results, negative/NaN radius, capacity and budget truncation" {
    var rng = Rng.init(7);
    var pts: [200]Pt = undefined;
    const buf = try randomIndex(&rng, pts.len, &pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var out: [200]Neighbor = undefined;
    // Nothing within r = 0 of a spot that is not a point.
    try testing.expectEqual(@as(usize, 0), (try f.within(89.9, 0, 0, &out, .{})).items.len);
    try testing.expectEqual(@as(usize, 0), (try f.within(0, 0, -1, &out, .{})).items.len);
    try testing.expectEqual(@as(usize, 0), (try f.within(0, 0, std.math.nan(f64), &out, .{})).items.len);
    try testing.expectEqual(@as(usize, 0), (try f.within(std.math.nan(f64), 0, 5, &out, .{})).items.len);
    // Everything, into a small buffer: capacity truncation; empty buffer too.
    const small = try f.within(0, 0, 1e6, out[0..5], .{});
    try testing.expectEqual(WithinStatus.truncated_capacity, small.status);
    try testing.expectEqual(@as(usize, 5), small.items.len);
    try testing.expectEqual(WithinStatus.truncated_capacity, (try f.within(0, 0, 1e6, out[0..0], .{})).status);
    try testing.expectEqual(WithinStatus.truncated_budget, (try f.within(0, 0, 1e6, &out, .{ .max_visited = 3 })).status);
    // Empty index.
    const eb = try build(&.{});
    defer testing.allocator.free(eb);
    const ef = try Frozen.load(eb);
    try testing.expectEqual(@as(usize, 0), (try ef.within(0, 0, 10, &out, .{})).items.len);
}

test "filter: bbox, within and knn equal a filtered brute-force scan" {
    var rng = Rng.init(0xf117e2);
    var pts: [500]Pt = undefined;
    const buf = try randomIndex(&rng, pts.len, &pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    var modulus: u32 = 3;
    const flt = Filter{ .ctx = &modulus, .func = modFilter };
    var m_out: [500]Match = undefined;
    var n_out: [500]Neighbor = undefined;
    var scratch: [1024]HeapEntry = undefined;

    for (0..30) |_| {
        const q: Pt = .{ .lat = rng.random().float(f64) * 160.0 - 80.0, .lon = rng.random().float(f64) * 340.0 - 170.0 };
        const qk = std.math.cos(q.lat * std.math.pi / 180.0);

        // bbox
        var expect = std.bit_set.IntegerBitSet(500).empty;
        for (pts, 0..) |p, i| {
            if (i % 3 == 0 and p.lat >= q.lat - 20 and p.lat <= q.lat + 20 and p.lon >= q.lon - 40 and p.lon <= q.lon + 40) expect.set(i);
        }
        const br = try f.bbox(q.lat - 20, q.lat + 20, q.lon - 40, q.lon + 40, &m_out, .{ .max_visited = 0, .filter = flt });
        try testing.expectEqual(BboxStatus.complete, br.status);
        var got = std.bit_set.IntegerBitSet(500).empty;
        for (br.items) |m| got.set(m.value);
        try testing.expect(expect.eql(got));

        // within
        expect = std.bit_set.IntegerBitSet(500).empty;
        for (pts, 0..) |p, i| if (i % 3 == 0 and pointDist2(q.lat, q.lon, p.lat, p.lon, qk) <= 30 * 30) expect.set(i);
        const wr = try f.within(q.lat, q.lon, 30, &n_out, .{ .max_visited = 0, .filter = flt });
        got = std.bit_set.IntegerBitSet(500).empty;
        for (wr.items) |m| got.set(m.value);
        try testing.expect(expect.eql(got));

        // knn: k nearest among accepted points, in order
        var order: [500]u32 = undefined;
        var cnt: usize = 0;
        for (0..pts.len) |i| {
            if (i % 3 == 0) {
                order[cnt] = @intCast(i);
                cnt += 1;
            }
        }
        const Ctx = struct {
            pts: []const Pt,
            q: Pt,
            qk: f64,
            fn less(c: @This(), a: u32, b: u32) bool {
                const da = pointDist2(c.q.lat, c.q.lon, c.pts[a].lat, c.pts[a].lon, c.qk);
                const db = pointDist2(c.q.lat, c.q.lon, c.pts[b].lat, c.pts[b].lon, c.qk);
                if (da != db) return da < db;
                return a < b;
            }
        };
        std.mem.sort(u32, order[0..cnt], Ctx{ .pts = &pts, .q = q, .qk = qk }, Ctx.less);
        const k = 25;
        const kr = try f.knn(q.lat, q.lon, k, &n_out, &scratch, .{ .max_visited = 0, .filter = flt });
        try testing.expectEqual(KnnStatus.complete, kr.status);
        try testing.expectEqual(@min(@as(usize, k), cnt), kr.items.len);
        for (kr.items, 0..) |m, i| try testing.expectEqual(order[i], m.value);
    }
}

test "filter: rejecting everything yields empty results with complete status" {
    var rng = Rng.init(99);
    var pts: [100]Pt = undefined;
    const buf = try randomIndex(&rng, pts.len, &pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    const flt = Filter{ .func = rejectAll };
    var m_out: [100]Match = undefined;
    var n_out: [100]Neighbor = undefined;
    var scratch: [512]HeapEntry = undefined;
    try testing.expectEqual(@as(usize, 0), (try f.bbox(-90, 90, -180, 180, &m_out, .{ .filter = flt })).items.len);
    try testing.expectEqual(BboxStatus.complete, (try f.bbox(-90, 90, -180, 180, &m_out, .{ .filter = flt })).status);
    try testing.expectEqual(@as(usize, 0), (try f.within(0, 0, 1e6, &n_out, .{ .filter = flt })).items.len);
    const kr = try f.knn(0, 0, 10, &n_out, &scratch, .{ .filter = flt });
    try testing.expectEqual(@as(usize, 0), kr.items.len);
    try testing.expectEqual(KnnStatus.complete, kr.status);
}

test "Ranker.box is a lower bound on the distance to every point inside the box, in both metrics" {
    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    for ([_]Metric{ .planar, .great_circle }) |metric| {
        for (0..400) |_| {
            const lat0 = rnd.float(f64) * 180 - 90;
            const lon0 = rnd.float(f64) * 360 - 180;
            const min_lat = lat0;
            const max_lat = @min(90, lat0 + rnd.float(f64) * 60);
            const min_lon = lon0;
            const max_lon = @min(180, lon0 + rnd.float(f64) * 200);
            const qlat = rnd.float(f64) * 180 - 90;
            const qlon = rnd.float(f64) * 360 - 180;
            const rk = Ranker.init(metric, qlat, qlon);
            const bound = rk.box(min_lat, max_lat, min_lon, max_lon);
            var best: f64 = std.math.inf(f64);
            const steps = 16;
            for (0..steps + 1) |i| {
                for (0..steps + 1) |j| {
                    const lat = min_lat + (max_lat - min_lat) * @as(f64, @floatFromInt(i)) / steps;
                    const lon = min_lon + (max_lon - min_lon) * @as(f64, @floatFromInt(j)) / steps;
                    best = @min(best, rk.point(lat, lon));
                }
            }
            // Never above the nearest sampled point (up to rounding) ...
            try testing.expect(bound <= best * (1 + 1e-9) + 1e-6);
            // ... and the nearest sampled point is not far above it (the bound is the exact distance, not merely valid).
            const tol: f64 = switch (metric) {
                .planar => 4 * 4 * 2, // degrees squared: a sampling cell is at most (200/16)° wide
                .great_circle => 1.2e13, // metres squared: 3.5e6 m
            };
            if (bound == 0) try testing.expect(best <= tol) else try testing.expect(@sqrt(best) - @sqrt(bound) <= @sqrt(tol));
        }
    }
}
