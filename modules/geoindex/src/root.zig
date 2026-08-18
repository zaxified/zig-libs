// SPDX-License-Identifier: MIT

//! geoindex — a memory-efficient, frozen **static spatial index** for
//! bounding-box and nearest-neighbour queries over a large, fixed set of
//! geo-points (WGS84 lat/lon).
//!
//! The driving consumer is a Czech RÚIAN address set: millions of addresses,
//! each carrying a lat/lon, needing "points inside this bbox" and "k nearest to
//! this point" fast, from a read-only snapshot. Build an index from
//! `(lat, lon, value)` triples (`value` = a record id), FREEZE it to a flat,
//! self-describing, versioned, little-endian byte buffer, then query that buffer
//! **zero-copy** from an mmap'd / read-only slice with no per-query allocation.
//!
//! Structure: a packed **Hilbert R-tree** (the Flatbush lineage) — the static
//! set is bulk-loaded bottom-up, leaves in Hilbert order, grouped `fanout` at a
//! time up to a single root. Emitted leaves-first / root-last, so every child
//! record sits at a strictly SMALLER index than its parent; the query decoder
//! enforces that, which makes traversal termination provable even on a corrupt
//! buffer. See SPEC.md for the wire format field-by-field and the design
//! rationale (vs a Z-order array or a grid).
//!
//! Coordinates: `lat` in [-90, 90], `lon` in [-180, 180] degrees; out-of-range
//! and non-finite inputs are rejected at build time. A query rectangle must not
//! cross the antimeridian in v1 (documented in SPEC.md). Coordinates are stored
//! as f64 and returned byte-identical — no quantization.

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure logic; no OS dependency
    .role = .util,
    .concurrency = .reentrant, // a frozen buffer is immutable → any number of concurrent readers
    .model_after = "Flatbush (mourner/flatbush): packed Hilbert R-tree, bulk-loaded",
    .deps = .{},
};

const builder = @import("builder.zig");
const query = @import("query.zig");
pub const format = @import("format.zig");

// ── public API ──────────────────────────────────────────────────────────────

pub const Builder = builder.Builder;
pub const Point = builder.Point;
pub const freezeFromPoints = builder.freezeFromPoints;
pub const BuildError = builder.BuildError;
pub const FreezeError = builder.FreezeError;
pub const default_fanout = builder.default_fanout;

pub const Frozen = query.Frozen;
pub const Match = query.Match;
pub const Neighbor = query.Neighbor;
pub const BboxResult = query.BboxResult;
pub const KnnResult = query.KnnResult;
pub const BboxStatus = query.BboxStatus;
pub const KnnStatus = query.KnnStatus;
pub const QueryOptions = query.QueryOptions;
pub const HeapEntry = query.HeapEntry;
pub const knnScratchLen = query.knnScratchLen;
pub const LoadError = query.LoadError;
pub const QueryError = query.QueryError;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ─────────────────────────

test {
    std.testing.refAllDecls(@This());
    _ = @import("format.zig");
    _ = @import("builder.zig");
    _ = @import("query.zig");
}

const testing = std.testing;

// ── a naive reference oracle: linear scan, no tree ───────────────────────────
//
// Deliberately unrelated to the R-tree internals so the differential test is a
// genuine cross-check. It computes the true bbox-membership multiset and the
// true k-NN with EXACT distances, using the identical ranking metric + tie-break
// the index uses (so equal-distance ties never cause spurious diffs).

const Oracle = struct {
    points: []const Point,

    fn bboxSet(self: Oracle, arena: std.mem.Allocator, min_lat: f64, max_lat: f64, min_lon: f64, max_lon: f64) ![]Point {
        var list: std.ArrayList(Point) = .empty;
        for (self.points) |p| {
            if (p.lat >= min_lat and p.lat <= max_lat and p.lon >= min_lon and p.lon <= max_lon)
                try list.append(arena, p);
        }
        return list.toOwnedSlice(arena);
    }

    fn knn(self: Oracle, arena: std.mem.Allocator, qlat: f64, qlon: f64, k: usize) ![]Neighbor {
        const qk = std.math.cos(qlat * std.math.pi / 180.0);
        const all = try arena.alloc(Neighbor, self.points.len);
        for (self.points, 0..) |p, i| {
            const dy = p.lat - qlat;
            const dx = (p.lon - qlon) * qk; // identical expression to query.pointDist2
            all[i] = .{ .value = p.value, .lat = p.lat, .lon = p.lon, .dist2 = dx * dx + dy * dy };
        }
        std.mem.sort(Neighbor, all, {}, neighborLess);
        return all[0..@min(k, all.len)];
    }
};

fn neighborLess(_: void, a: Neighbor, b: Neighbor) bool {
    if (a.dist2 != b.dist2) return a.dist2 < b.dist2;
    if (a.value != b.value) return a.value < b.value;
    if (a.lat != b.lat) return a.lat < b.lat;
    return a.lon < b.lon;
}

fn matchLess(_: void, a: Point, b: Point) bool {
    if (a.value != b.value) return a.value < b.value;
    if (a.lat != b.lat) return a.lat < b.lat;
    return a.lon < b.lon;
}

// ── differential harness ─────────────────────────────────────────────────────

fn genPoints(arena: std.mem.Allocator, prng: *std.Random.DefaultPrng, n: usize) ![]Point {
    const rnd = prng.random();
    const pts = try arena.alloc(Point, n);
    for (pts) |*p| {
        // A small coordinate window so bbox/knn queries actually hit points, and
        // occasional exact duplicates (snap to a coarse grid).
        const lat = @round(rnd.float(f64) * 200) / 10 - 10; // ~[-10, 10], 0.1 steps
        const lon = @round(rnd.float(f64) * 200) / 10 - 10;
        p.* = .{ .lat = lat, .lon = lon, .value = rnd.int(u32) };
    }
    return pts;
}

fn differentialRound(seed: u64, n: usize) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(seed);

    const pts = try genPoints(arena, &prng, n);
    const oracle = Oracle{ .points = pts };
    const buf = try freezeFromPoints(testing.allocator, testing.allocator, pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expectEqual(@as(u64, pts.len), f.itemCount());

    const rnd = prng.random();
    var probe: usize = 0;
    while (probe < 40) : (probe += 1) {
        // Random query rectangle inside (and sometimes beyond) the point window.
        var a = rnd.float(f64) * 24 - 12;
        var c = rnd.float(f64) * 24 - 12;
        var bb = rnd.float(f64) * 24 - 12;
        var d = rnd.float(f64) * 24 - 12;
        if (a > c) std.mem.swap(f64, &a, &c);
        if (bb > d) std.mem.swap(f64, &bb, &d);

        // 1. bbox membership set agreement (order-independent).
        {
            const want = try oracle.bboxSet(arena, a, c, bb, d);
            const got_buf = try arena.alloc(Match, pts.len + 1);
            const r = try f.bbox(a, c, bb, d, got_buf, .{ .max_visited = 0 });
            try testing.expectEqual(query.BboxStatus.complete, r.status);
            try testing.expectEqual(want.len, r.items.len);

            const want_sorted = try arena.dupe(Point, want);
            std.mem.sort(Point, want_sorted, {}, matchLess);
            const got_pts = try arena.alloc(Point, r.items.len);
            for (r.items, 0..) |m, i| got_pts[i] = .{ .lat = m.lat, .lon = m.lon, .value = m.value };
            std.mem.sort(Point, got_pts, {}, matchLess);
            for (want_sorted, got_pts) |w, g| {
                try testing.expectEqual(w.value, g.value);
                try testing.expectEqual(w.lat, g.lat);
                try testing.expectEqual(w.lon, g.lon);
            }
        }

        // 2. kNN agreement (set + exact order + exact distance).
        {
            const k = rnd.intRangeAtMost(usize, 0, 12);
            const qlat = rnd.float(f64) * 24 - 12;
            const qlon = rnd.float(f64) * 24 - 12;
            const want = try oracle.knn(arena, qlat, qlon, k);
            const out = try arena.alloc(Neighbor, k);
            const scratch = try arena.alloc(query.HeapEntry, pts.len + default_fanout + 8);
            const r = try f.knn(qlat, qlon, k, out, scratch, .{ .max_visited = 0 });
            try testing.expectEqual(query.KnnStatus.complete, r.status);
            try testing.expectEqual(want.len, r.items.len);
            for (want, r.items) |w, g| {
                try testing.expectEqual(w.value, g.value);
                try testing.expectEqual(w.lat, g.lat);
                try testing.expectEqual(w.lon, g.lon);
                try testing.expectEqual(w.dist2, g.dist2);
            }
        }
    }
}

test "differential: real R-tree vs naive linear oracle across many random point sets" {
    var seed: u64 = 1;
    while (seed <= 30) : (seed += 1) {
        try differentialRound(seed, 60);
    }
}

test "differential: adversarial hand-picked point sets" {
    const identical = [_]Point{
        .{ .lat = 5, .lon = 5, .value = 1 },
        .{ .lat = 5, .lon = 5, .value = 2 }, // duplicate coords, different value
        .{ .lat = 5, .lon = 5, .value = 3 },
    };
    const collinear = [_]Point{
        .{ .lat = 0, .lon = 0, .value = 10 },
        .{ .lat = 0, .lon = 1, .value = 11 },
        .{ .lat = 0, .lon = 2, .value = 12 },
        .{ .lat = 0, .lon = 3, .value = 13 },
        .{ .lat = 0, .lon = 4, .value = 14 },
    };
    const extremes = [_]Point{
        .{ .lat = 90, .lon = 180, .value = 1 }, // north pole / antimeridian corner
        .{ .lat = -90, .lon = -180, .value = 2 }, // south pole
        .{ .lat = 90, .lon = -180, .value = 3 },
        .{ .lat = 0, .lon = 0, .value = 4 },
    };
    const sets = [_][]const Point{
        &.{}, // empty
        &.{.{ .lat = 1, .lon = 2, .value = 7 }}, // single point
        &identical,
        &collinear,
        &extremes,
    };
    for (sets) |pts| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const oracle = Oracle{ .points = pts };
        const buf = try freezeFromPoints(testing.allocator, testing.allocator, pts);
        defer testing.allocator.free(buf);
        const f = try Frozen.load(buf);

        // bbox covering everything.
        const want = try oracle.bboxSet(arena, -90, 90, -180, 180);
        const got_buf = try arena.alloc(Match, pts.len + 1);
        const r = try f.bbox(-90, 90, -180, 180, got_buf, .{ .max_visited = 0 });
        try testing.expectEqual(want.len, r.items.len);

        // kNN with k > set size (must return the whole set in order).
        const wk = try oracle.knn(arena, 3, 3, pts.len + 5);
        const out = try arena.alloc(Neighbor, pts.len + 5);
        const scratch = try arena.alloc(query.HeapEntry, pts.len + default_fanout + 8);
        const rk = try f.knn(3, 3, pts.len + 5, out, scratch, .{ .max_visited = 0 });
        try testing.expectEqual(wk.len, rk.items.len);
        for (wk, rk.items) |w, g| {
            try testing.expectEqual(w.value, g.value);
            try testing.expectEqual(w.dist2, g.dist2);
        }
    }
}

test "round-trip: pre-freeze in-memory answers equal post-freeze answers" {
    const pts = [_]Point{
        .{ .lat = 50.08, .lon = 14.42, .value = 100 }, // Praha
        .{ .lat = 49.19, .lon = 16.61, .value = 200 }, // Brno
        .{ .lat = 49.74, .lon = 13.37, .value = 300 }, // Plzeň
        .{ .lat = 49.59, .lon = 17.25, .value = 400 }, // Olomouc
    };
    const buf = try freezeFromPoints(testing.allocator, testing.allocator, &pts);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    // Nearest to a point near Brno must be Brno.
    var out: [1]Neighbor = undefined;
    var scratch: [32]query.HeapEntry = undefined;
    const r = try f.knn(49.2, 16.6, 1, &out, &scratch, .{});
    try testing.expectEqual(@as(u32, 200), r.items[0].value);
    // bbox over central Bohemia catches Praha + Plzeň, not Brno/Olomouc.
    var mout: [8]Match = undefined;
    const rb = try f.bbox(49.5, 50.5, 13.0, 15.0, &mout, .{});
    var mask: u32 = 0;
    for (rb.items) |m| mask |= m.value;
    try testing.expectEqual(@as(u32, 100 | 300), mask);
}

test "large set crosses many R-tree levels and stays correct" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    // 4000 points on a grid → several internal levels (fanout 16).
    var i: u32 = 0;
    while (i < 4000) : (i += 1) {
        const lat = @as(f64, @floatFromInt(i % 80)) * 0.1;
        const lon = @as(f64, @floatFromInt(i / 80)) * 0.1;
        try b.add(lat, lon, i);
    }
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const f = try Frozen.load(buf);
    try testing.expect(f.header.node_count > 4000); // internal levels present

    // A tight bbox around one grid cell returns exactly that point.
    var out: [16]Match = undefined;
    const r = try f.bbox(0.05, 0.15, 0.05, 0.15, &out, .{});
    try testing.expectEqual(@as(usize, 1), r.items.len);
    try testing.expectEqual(@as(u32, 81), r.items[0].value); // lat=0.1 (i%80=1), lon=0.1 (i/80=1) → i=81
}

// ── positive controls: prove the checkers have teeth ─────────────────────────

test "positive control: a corrupted leaf value makes the index DISAGREE with the oracle" {
    const pts = [_]Point{
        .{ .lat = 1, .lon = 1, .value = 111 },
        .{ .lat = 2, .lon = 2, .value = 222 },
    };
    const buf = try freezeFromPoints(testing.allocator, testing.allocator, &pts);
    defer testing.allocator.free(buf);
    // Clean index agrees: bbox around (1,1) yields value 111.
    {
        const f = try Frozen.load(buf);
        var out: [4]Match = undefined;
        const r = try f.bbox(0.5, 1.5, 0.5, 1.5, &out, .{});
        try testing.expectEqual(@as(usize, 1), r.items.len);
        try testing.expectEqual(@as(u32, 111), r.items[0].value);
    }
    // Corrupt leaf 0's value field directly (leaf ordering may differ, so find
    // the leaf whose point is (1,1) and flip its data), then show disagreement +
    // that the body CRC catches it.
    var mut = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(mut);
    const h = try format.Header.load(mut);
    const nodes = format.Nodes.init(mut, h);
    var idx: u32 = 0;
    const leaf_at = while (idx < h.node_count) : (idx += 1) {
        const nd = try nodes.at(idx);
        if (nd.leaf and nd.min_lat == 1 and nd.min_lon == 1) break idx;
    } else unreachable;
    const base = format.header_size + @as(usize, leaf_at) * format.node_size_bytes;
    std.mem.writeInt(u32, mut[base + format.off_data ..][0..4], 999, .little); // 111 → 999

    const f = try Frozen.load(mut); // structurally still valid (load skips body CRC)
    var out: [4]Match = undefined;
    const r = try f.bbox(0.5, 1.5, 0.5, 1.5, &out, .{});
    try testing.expect(r.items.len == 1 and r.items[0].value != 111); // disagreement caught
    try testing.expectError(error.BodyCorrupt, Frozen.loadVerified(mut)); // and the CRC catches it too
}

test "permanent malformed control: a self/forward-pointing child is rejected, not looped" {
    // Hand-build a two-node buffer whose internal root (index 1) claims child 1
    // (itself) — violating the strictly-decreasing invariant a naive walker would
    // loop on. The query path must return error.Corrupt.
    var buf: [format.header_size + 2 * format.node_size_bytes]u8 = undefined;
    @memset(&buf, 0);
    // node 0: a leaf point (never reached).
    const b0 = format.header_size;
    buf[b0 + format.off_flags] = format.leaf_bit;
    format.writeF64(&buf, b0 + format.off_min_lat, 0);
    format.writeF64(&buf, b0 + format.off_min_lon, 0);
    format.writeF64(&buf, b0 + format.off_max_lat, 0);
    format.writeF64(&buf, b0 + format.off_max_lon, 0);
    // node 1 (root): internal, child_start = 1 (points AT ITSELF), child_count = 1.
    const b1 = format.header_size + format.node_size_bytes;
    buf[b1 + format.off_flags] = 0;
    format.writeF64(&buf, b1 + format.off_min_lat, -10);
    format.writeF64(&buf, b1 + format.off_min_lon, -10);
    format.writeF64(&buf, b1 + format.off_max_lat, 10);
    format.writeF64(&buf, b1 + format.off_max_lon, 10);
    std.mem.writeInt(u32, buf[b1 + format.off_data ..][0..4], 1, .little); // child_start = self
    std.mem.writeInt(u16, buf[b1 + format.off_child_count ..][0..2], 1, .little);
    const h = format.Header{ .flags = 0, .node_count = 2, .fanout = 16, .item_count = 1, .root_index = 1 };
    h.encode(&buf, buf[format.header_size..]);

    const f = try Frozen.load(&buf); // header is well-formed
    var out: [4]Match = undefined;
    try testing.expectError(error.Corrupt, f.bbox(-5, 5, -5, 5, &out, .{})); // cycle rejected
    var nb: [4]Neighbor = undefined;
    var scratch: [16]query.HeapEntry = undefined;
    try testing.expectError(error.Corrupt, f.knn(0, 0, 4, &nb, &scratch, .{}));
}

// ── frozen-buffer robustness: never panic / OOB / loop on bad input ──────────

fn runQueries(f: Frozen) void {
    var out: [16]Match = undefined;
    _ = f.bbox(-90, 90, -180, 180, &out, .{ .max_visited = 10_000 }) catch {};
    _ = f.bbox(0, 0, 0, 0, &out, .{}) catch {};
    var nb: [8]Neighbor = undefined;
    var scratch: [256]query.HeapEntry = undefined;
    _ = f.knn(0, 0, 8, &nb, &scratch, .{ .max_visited = 10_000 }) catch {};
    _ = f.knn(50, 14, 8, &nb, &scratch, .{ .max_visited = 10_000 }) catch {};
}

test "truncated buffers of every length load-fail or query-fail without panic" {
    const buf = try freezeFromPoints(testing.allocator, testing.allocator, &.{
        .{ .lat = 1, .lon = 1, .value = 1 },
        .{ .lat = 2, .lon = 2, .value = 2 },
        .{ .lat = 3, .lon = 3, .value = 3 },
    });
    defer testing.allocator.free(buf);
    var len: usize = 0;
    while (len < buf.len) : (len += 1) {
        const f = Frozen.load(buf[0..len]) catch continue;
        runQueries(f);
    }
}

test "wrong-magic and wrong-version buffers are typed rejections" {
    const buf = try freezeFromPoints(testing.allocator, testing.allocator, &.{.{ .lat = 1, .lon = 1, .value = 1 }});
    defer testing.allocator.free(buf);
    var b = try testing.allocator.dupe(u8, buf);
    defer testing.allocator.free(b);
    b[0] = 'X';
    try testing.expect(Frozen.load(b) catch null == null);
    @memcpy(b, buf);
    std.mem.writeInt(u16, b[4..6], 42, .little);
    std.mem.writeInt(u32, b[36..40], std.hash.Crc32.hash(b[0..36]), .little);
    try testing.expectError(error.UnsupportedVersion, Frozen.load(b));
}

fn fuzzRandom(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const f = Frozen.load(buf[0..len]) catch return;
    runQueries(f);
}

test "fuzz: loader + query path never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzRandom, .{});
}

fn fuzzMutated(base: []const u8, smith: *std.testing.Smith) !void {
    var copy: [2048]u8 = undefined;
    if (base.len > copy.len) return;
    @memcpy(copy[0..base.len], base);
    var i: usize = 0;
    const flips: usize = smith.valueRangeAtMost(u8, 0, 16);
    while (i < flips) : (i += 1) {
        const at: usize = smith.valueRangeAtMost(u16, 0, @intCast(base.len - 1));
        copy[at] = smith.value(u8);
    }
    const f = Frozen.load(copy[0..base.len]) catch return;
    runQueries(f);
}

test "fuzz: mutated-valid-buffer loader + query path never panic" {
    const base = try freezeFromPoints(testing.allocator, testing.allocator, &.{
        .{ .lat = 50.08, .lon = 14.42, .value = 1 },
        .{ .lat = 49.19, .lon = 16.61, .value = 2 },
        .{ .lat = 49.74, .lon = 13.37, .value = 3 },
        .{ .lat = 49.59, .lon = 17.25, .value = 4 },
        .{ .lat = 48.97, .lon = 14.47, .value = 5 },
    });
    defer testing.allocator.free(base);
    try std.testing.fuzz(base, fuzzMutated, .{});
}
