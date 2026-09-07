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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Static spatial index for bbox and nearest-neighbour queries over a large fixed geo-point set — DoS-bounded, zero-copy.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
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

/// The corpus-entry format `Smith.slice` reads: a little-endian u32 length,
/// then the frame. See `testkit/src/fuzz.zig` for the hazards it carries.
const testkit = @import("testkit");
const fuzzSeed = testkit.fuzz.seed;

// ⛔ `fuzzRandom` used to fill `buf` with `smith.bytes` and then draw the
// length with `valueRangeAtMost(u16, 0, buf.len)`. A ranged `Smith` draw reads
// EIGHT octets as a little-endian u64 and returns the range MINIMUM when fewer
// remain, so the length was 0 for every input a corpus can carry and
// `Frozen.load` was handed an empty slice — `error.Truncated` before it had
// looked at the magic. With no corpus, that was the only input it ever ran.

/// Whole frozen buffers, in the format the length draw reads. The header is 40
/// octets whose `header_crc` covers `[0..36)`, so a hand-written header needs a
/// correct CRC to get past `Header.load` at all — these were computed with
/// `std.hash.Crc32`, which is what makes the structural refusals below
/// (`BadNodeBytes`, `MalformedRoot`, a lying `node_count`) reachable rather
/// than uniformly masked by `HeaderCorrupt`.
const random_seeds = [_][]const u8{
    fuzzSeed("ZGI1"), // the magic alone: Truncated
    fuzzSeed("ZGI0" ++ "\x00" ** 36), // wrong magic
    fuzzSeed("ZGI1" ++ "\x00" ** 36), // right magic, wrong header CRC
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00'\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcdY\xe3\x12"), // ⭐ the empty index: node_count 0, item_count 0 — legal, and it LOADS
    fuzzSeed("ZGI1\xff\xff\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00'\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf9\x01\xaf\xa7"), // an unsupported version, correctly sealed
    fuzzSeed("ZGI1\x01\x00\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00'\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb9\x17J\xf3"), // the endian marker byte-swapped, correctly sealed
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00(\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xec)|n"), // node_bytes 40, not the 39-octet record stride: BadNodeBytes
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\xff\xff\xff\xff'\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x83\xfd\xb5\xe0"), // node_count 4 Gi records: Truncated
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x01\x00\x00\x00'\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00\x00\x00\x00\x00#\x0a\xcac\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // root_index 99 past node_count 1: MalformedRoot
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00'\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\xc8\x8b\xbc"), // item_count 1 with node_count 0: MalformedRoot
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x01\x00\x00\x00'\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{\xad\xae=\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), // ⭐ one all-zero leaf record: LOADS, and the walk is then bounds-checked
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x01\x00\x00\x00'\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{\xad\xae=\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), // ⭐ one all-ones record: NaN bounding-box corners and a child_count of 65535
    fuzzSeed("ZGI1\x01\x00\x02\x01\x00\x00\x00\x00\x02\x00\x00\x00'\x00\x08\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00?\xb0\xd2\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"), // an internal root claiming 65535 contiguous children: the fan-out bound
    fuzzSeed(""), // the empty buffer: what the collapsed harness ran, every time
};

fn fuzzRandom(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const f = Frozen.load(buf[0..len]) catch return;
    runQueries(f);
}

test "fuzz: loader + query path never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzRandom, .{ .corpus = &random_seeds });
}

/// What one mutation script asked for, so the corpus guard can measure the
/// damage rather than assert that the harness ran.
const Damage = struct {
    changed: usize = 0,
    resealed: bool = false,
};

/// ⛔⛔ Two defects, both measured, both shared with `trie` and `fuzzysearch`.
///
/// 1. `flips` came from `smith.valueRangeAtMost(u8, 0, 16)` as the FIRST draw,
///    which returns the range MINIMUM for all but one input word in 2^64. The
///    flip count was therefore **0**: the harness re-loaded the pristine index
///    on every iteration and never mutated an octet.
///
/// 2. ⭐ Even with the count fixed, a blind byte flip is **CRC-gated**: any
///    octet in `[0..40)` breaks the header CRC over `[0..36)`, so every header
///    mutation comes back as `error.HeaderCorrupt` and the R-tree descent this
///    harness exists for is never entered — the harness would measure the
///    rejection path and nothing else. The script therefore carries a RE-SEAL
///    bit, recomputing `header_crc` (and optionally `body_crc`) after mutating,
///    which is what an attacker shipping a crafted index does. That is what
///    makes a damaged `root_index`, `node_count` or `item_count` reach the
///    bounds-checked walk instead of dying at the checksum.
///
/// Script layout: octet 0 = flags (bit0 re-seal `header_crc`, bit1 also
/// `body_crc`), octet 1 = flip count modulo 17, then per flip an offset (2
/// octets, big-endian, modulo `buf.len`) and a value. A short script CYCLES;
/// the empty script is the collapsed harness exactly.
fn damage(script: []const u8, buf: []u8, out: *Damage) void {
    var s = testkit.fuzz.Cursor{ .bytes = script };
    out.* = .{};
    if (buf.len == 0) return;
    const flags = s.byte();
    const flips: usize = s.byte() % 17;
    var i: usize = 0;
    while (i < flips) : (i += 1) {
        const at: usize = @as(usize, s.word()) % buf.len;
        const v = s.byte();
        if (buf[at] != v) out.changed += 1;
        buf[at] = v;
    }
    if (flags & 1 != 0 and buf.len >= format.header_size) {
        out.resealed = true;
        if (flags & 2 != 0) {
            const count = std.mem.readInt(u32, buf[12..16], .little);
            const end = @min(buf.len, format.header_size + @as(usize, count) * format.node_size_bytes);
            std.mem.writeInt(u32, buf[32..36], std.hash.Crc32.hash(buf[format.header_size..end]), .little);
        }
        std.mem.writeInt(u32, buf[36..40], std.hash.Crc32.hash(buf[0..36]), .little);
    }
}

const mutated_seeds = [_][]const u8{
    fuzzSeed("\x00\x00"), // no flips, no re-seal: the pristine index — what the collapsed harness ran
    fuzzSeed("\x01\x01" ++ "\x00\x1c\xff"), // root_index low byte → 0xff, RE-SEALED: MalformedRoot, not HeaderCorrupt
    fuzzSeed("\x01\x01" ++ "\x00\x0c\xff"), // node_count damaged, re-sealed: the bound the descent trusts
    fuzzSeed("\x01\x01" ++ "\x00\x14\xff"), // item_count damaged, re-sealed
    fuzzSeed("\x01\x01" ++ "\x00\x10\x28"), // node_bytes → 40, re-sealed: BadNodeBytes, not HeaderCorrupt
    fuzzSeed("\x00\x01" ++ "\x00\x1c\xff"), // ⭐ the same root_index flip WITHOUT the re-seal: HeaderCorrupt — all the old harness could ever have measured
    fuzzSeed("\x01\x08" ++ "\x00\x29\xff\x00\x2a\xff\x00\x2b\xff\x00\x2c\xff\x00\x2d\xff\x00\x2e\xff\x00\x2f\xff\x00\x30\xff"), // eight octets of the first record's min_lat/min_lon: NaN corners into the descent
    fuzzSeed("\x01\x02" ++ "\x00\x28\x00\x00\x28\x01"), // the first record's flags octet: a leaf turned internal and back
    fuzzSeed("\x03\x06" ++ "\x00\x30\xff\x00\x34\xff\x00\x38\xff\x00\x3c\xff\x00\x40\xff\x00\x44\xff"), // node region damaged with BOTH CRCs re-sealed: `loadVerified` accepts it too
    fuzzSeed("\x01\x10" ++ "\x00\x28\x01"), // the maximum flip count, cycling over one offset
    fuzzSeed(""), // the empty script: zero flips, no re-seal
};

fn fuzzMutated(base: []const u8, smith: *std.testing.Smith) !void {
    var script: [64]u8 = undefined;
    const n: usize = smith.slice(&script);
    var copy: [2048]u8 = undefined;
    if (base.len > copy.len) return;
    @memcpy(copy[0..base.len], base);
    var d: Damage = .{};
    damage(script[0..n], copy[0..base.len], &d);
    _ = Frozen.loadVerified(copy[0..base.len]) catch {};
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
    try std.testing.fuzz(base, fuzzMutated, .{ .corpus = &mutated_seeds });
}

test "corpus: the random buffers reach the loader, and what they get past is pinned" {
    var nonempty: usize = 0;
    var loaded: usize = 0;
    var header_corrupt: usize = 0;
    for (random_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [1024]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (Frozen.load(buf[0..len])) |f| {
            loaded += 1;
            runQueries(f);
        } else |e| {
            if (e == error.HeaderCorrupt) header_corrupt += 1;
        }
    }
    try testing.expectEqual(random_seeds.len - 1, nonempty);
    // Measured 2026-09-07: both were 0 before the draw was fixed — the loader
    // was handed an empty slice on every iteration.
    try testing.expectEqual(@as(usize, 4), loaded);
    try testing.expectEqual(@as(usize, 1), header_corrupt);
}

test "corpus: the mutation scripts actually damage the index, and reach the descent" {
    // ⭐⭐ Neither "no seed panicked" nor "some seed loaded" is a guard here.
    // The old harness applied ZERO flips, so the pristine index loaded on every
    // iteration and both would have read 100% while nothing was ever mutated.
    // The numbers the empty script cannot produce are the octets actually
    // changed and — the CRC trap — the DAMAGED buffers that still got past
    // `Header.load` into the R-tree descent.
    const base = try freezeFromPoints(testing.allocator, testing.allocator, &.{
        .{ .lat = 50.08, .lon = 14.42, .value = 1 },
        .{ .lat = 49.19, .lon = 16.61, .value = 2 },
        .{ .lat = 49.74, .lon = 13.37, .value = 3 },
        .{ .lat = 49.59, .lon = 17.25, .value = 4 },
        .{ .lat = 48.97, .lon = 14.47, .value = 5 },
    });
    defer testing.allocator.free(base);

    var changed_total: usize = 0;
    var damaged_and_loaded: usize = 0;
    var damaged_and_rejected: usize = 0;
    var damaged_and_verified: usize = 0;
    for (mutated_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [64]u8 = undefined;
        const n: usize = smith.slice(&script);
        var copy: [2048]u8 = undefined;
        @memcpy(copy[0..base.len], base);
        var d: Damage = .{};
        damage(script[0..n], copy[0..base.len], &d);
        changed_total += d.changed;
        if (d.changed == 0) continue;
        if (Frozen.loadVerified(copy[0..base.len])) |_| damaged_and_verified += 1 else |_| {}
        if (Frozen.load(copy[0..base.len])) |f| {
            damaged_and_loaded += 1;
            runQueries(f);
        } else |_| damaged_and_rejected += 1;
    }
    // Measured 2026-09-07: `changed_total` was 0 — the flip count was the first
    // draw and therefore always the range minimum.
    try testing.expectEqual(@as(usize, 25), changed_total);
    // ⭐ The CRC trap as a number: without the re-seal bit every one of these
    // would land in `damaged_and_rejected` and the descent would stay unvisited.
    try testing.expectEqual(@as(usize, 4), damaged_and_loaded);
    try testing.expectEqual(@as(usize, 5), damaged_and_rejected);
    try testing.expectEqual(@as(usize, 2), damaged_and_verified);
}
