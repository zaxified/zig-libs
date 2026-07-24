// SPDX-License-Identifier: MIT

//! builder — the BUILD phase: accumulate `(lat, lon, value)` points, sort them
//! along a Hilbert space-filling curve, pack a bottom-up R-tree over the sorted
//! order, then FREEZE it into the flat `format` byte buffer.
//!
//! This is the Flatbush (mourner/flatbush) recipe: a STATIC set is bulk-loaded
//! into a packed R-tree — leaves in Hilbert order for spatial locality, then
//! each level grouped `fanout` at a time into parent nodes, up to a single root.
//! Because the tree is emitted bottom-up (leaves first, root last), every child
//! record sits at a STRICTLY SMALLER index than its parent, and a node's
//! children form a contiguous block below it. That is exactly the invariant the
//! query decoder leans on for provable traversal termination on a corrupt buffer.
//!
//! Memory: the whole build lives in a handful of growable arrays (the item
//! pool, a scratch permutation, and the node pool), each doubling only O(log N)
//! times over the WHOLE build — so a millions-of-points build is a handful of
//! allocations, not per-point ones. Build RSS is linear and allocator-insensitive.

const std = @import("std");
const Allocator = std.mem.Allocator;
const format = @import("format.zig");

/// Default R-tree fan-out (children per internal node). Flatbush's default; a
/// good bbox/kNN trade-off. Kept internal — the frozen decoder does not depend
/// on it (each node stores its own `child_count`).
pub const default_fanout: u16 = 16;

pub const BuildError = error{
    OutOfMemory,
    /// A coordinate was NaN or infinite.
    NotFinite,
    /// A latitude outside [-90, 90] or longitude outside [-180, 180].
    OutOfRange,
};

pub const FreezeError = error{
    OutOfMemory,
    /// The node region would exceed the u32 index / offset space. Far beyond the
    /// intended workload; reported, never silently truncated.
    TooLarge,
};

pub const Point = struct { lat: f64, lon: f64, value: u32 };

/// One indexed point plus its Hilbert sort key. Stored in a single growable
/// pool; sorting reorders this array in place.
const Item = struct {
    lat: f64,
    lon: f64,
    value: u32,
    hilbert: u32,
};

/// One in-memory node during the bottom-up pack. `data`/`child_count` mean the
/// same as in the frozen record (leaf: value / 0; internal: child_start / count).
const BuildNode = struct {
    leaf: bool,
    min_lat: f64,
    min_lon: f64,
    max_lat: f64,
    max_lon: f64,
    data: u32,
    child_count: u16,
};

/// Incremental builder. Add `(lat, lon, value)` points in any order, then
/// `freeze` once. Reusable after freeze (freeze does not consume it), and
/// deterministic — freezing the same points twice yields byte-identical buffers.
pub const Builder = struct {
    gpa: Allocator,
    items: std.ArrayListUnmanaged(Item),
    fanout: u16,

    pub fn init(gpa: Allocator) Builder {
        return .{ .gpa = gpa, .items = .empty, .fanout = default_fanout };
    }

    pub fn deinit(self: *Builder) void {
        self.items.deinit(self.gpa);
        self.* = undefined;
    }

    /// Add one point. WGS84 degrees: `lat` in [-90, 90], `lon` in [-180, 180].
    /// NaN/inf and out-of-range coordinates are rejected with a typed error —
    /// never silently indexed at a wrong location.
    pub fn add(self: *Builder, lat: f64, lon: f64, value: u32) BuildError!void {
        if (!std.math.isFinite(lat) or !std.math.isFinite(lon)) return error.NotFinite;
        if (lat < -90.0 or lat > 90.0 or lon < -180.0 or lon > 180.0) return error.OutOfRange;
        try self.items.append(self.gpa, .{ .lat = lat, .lon = lon, .value = value, .hilbert = 0 });
    }

    pub fn count(self: *const Builder) usize {
        return self.items.items.len;
    }

    /// Serialize the index into a freshly-allocated frozen buffer (caller owns
    /// and frees it). The builder is left intact and may be frozen again.
    pub fn freeze(self: *Builder, out_gpa: Allocator) FreezeError![]u8 {
        const n = self.items.items.len;
        if (n == 0) return freezeEmpty(out_gpa);

        // 1. Overall bbox of all points → the Hilbert grid frame.
        var min_lat: f64 = self.items.items[0].lat;
        var min_lon: f64 = self.items.items[0].lon;
        var max_lat: f64 = min_lat;
        var max_lon: f64 = min_lon;
        for (self.items.items) |it| {
            min_lat = @min(min_lat, it.lat);
            min_lon = @min(min_lon, it.lon);
            max_lat = @max(max_lat, it.lat);
            max_lon = @max(max_lon, it.lon);
        }

        // 2. Hilbert key per point, then sort. Sorting mutates `self.items`, but
        //    the result is a permutation of the same set, so the builder stays
        //    valid and reusable. A total-order comparator keeps freeze
        //    deterministic even when two points share a Hilbert cell.
        for (self.items.items) |*it| {
            const hx = gridCoord(it.lon, min_lon, max_lon);
            const hy = gridCoord(it.lat, min_lat, max_lat);
            it.hilbert = hilbertXYToIndex(hx, hy);
        }
        std.mem.sort(Item, self.items.items, {}, itemLess);

        // 3. Pack bottom-up into the node pool. Leaves first (one per point, in
        //    Hilbert order), then internal levels, root last.
        var nodes: std.ArrayListUnmanaged(BuildNode) = .empty;
        defer nodes.deinit(out_gpa);
        nodes.ensureTotalCapacity(out_gpa, n + n / (self.fanout - 1) + 1) catch return error.OutOfMemory;

        for (self.items.items) |it| {
            nodes.append(out_gpa, .{
                .leaf = true,
                .min_lat = it.lat,
                .min_lon = it.lon,
                .max_lat = it.lat,
                .max_lon = it.lon,
                .data = it.value,
                .child_count = 0,
            }) catch return error.OutOfMemory;
        }

        // Grouping loop over levels. `level_start`/`level_len` mark the current
        // (already-emitted) level; each pass appends its parent level.
        var level_start: usize = 0;
        var level_len: usize = n;
        while (level_len > 1) {
            const parent_start = nodes.items.len;
            var i: usize = 0;
            while (i < level_len) {
                const chunk = @min(@as(usize, self.fanout), level_len - i);
                const first_child = level_start + i;
                var bb_min_lat: f64 = nodes.items[first_child].min_lat;
                var bb_min_lon: f64 = nodes.items[first_child].min_lon;
                var bb_max_lat: f64 = nodes.items[first_child].max_lat;
                var bb_max_lon: f64 = nodes.items[first_child].max_lon;
                for (1..chunk) |j| {
                    const c = nodes.items[first_child + j];
                    bb_min_lat = @min(bb_min_lat, c.min_lat);
                    bb_min_lon = @min(bb_min_lon, c.min_lon);
                    bb_max_lat = @max(bb_max_lat, c.max_lat);
                    bb_max_lon = @max(bb_max_lon, c.max_lon);
                }
                if (first_child > std.math.maxInt(u32)) return error.TooLarge;
                nodes.append(out_gpa, .{
                    .leaf = false,
                    .min_lat = bb_min_lat,
                    .min_lon = bb_min_lon,
                    .max_lat = bb_max_lat,
                    .max_lon = bb_max_lon,
                    .data = @intCast(first_child),
                    .child_count = @intCast(chunk),
                }) catch return error.OutOfMemory;
                i += chunk;
            }
            level_start = parent_start;
            level_len = nodes.items.len - parent_start;
        }

        const node_count = nodes.items.len;
        if (node_count > std.math.maxInt(u32)) return error.TooLarge;
        const root_index = node_count - 1;

        // 4. Lay down the buffer: header placeholder + node region.
        const total = format.header_size + node_count * format.node_size_bytes;
        const buf = out_gpa.alloc(u8, total) catch return error.OutOfMemory;
        errdefer out_gpa.free(buf);

        var p: usize = format.header_size;
        for (nodes.items) |node| {
            buf[p + format.off_flags] = if (node.leaf) format.leaf_bit else 0;
            format.writeF64(buf, p + format.off_min_lat, node.min_lat);
            format.writeF64(buf, p + format.off_min_lon, node.min_lon);
            format.writeF64(buf, p + format.off_max_lat, node.max_lat);
            format.writeF64(buf, p + format.off_max_lon, node.max_lon);
            std.mem.writeInt(u32, buf[p + format.off_data ..][0..4], node.data, .little);
            std.mem.writeInt(u16, buf[p + format.off_child_count ..][0..2], node.child_count, .little);
            p += format.node_size_bytes;
        }
        std.debug.assert(p == total);

        const header = format.Header{
            .flags = 0,
            .node_count = @intCast(node_count),
            .fanout = self.fanout,
            .item_count = n,
            .root_index = @intCast(root_index),
        };
        header.encode(buf, buf[format.header_size..]);
        return buf;
    }
};

fn freezeEmpty(out_gpa: Allocator) FreezeError![]u8 {
    const buf = out_gpa.alloc(u8, format.header_size) catch return error.OutOfMemory;
    errdefer out_gpa.free(buf);
    const header = format.Header{ .flags = 0, .node_count = 0, .fanout = default_fanout, .item_count = 0, .root_index = 0 };
    header.encode(buf, buf[format.header_size..]); // body is a zero-length slice
    return buf;
}

fn itemLess(_: void, a: Item, b: Item) bool {
    if (a.hilbert != b.hilbert) return a.hilbert < b.hilbert;
    if (a.value != b.value) return a.value < b.value;
    if (a.lat != b.lat) return a.lat < b.lat;
    return a.lon < b.lon;
}

/// Convenience: build + freeze from a slice of points in one call.
pub fn freezeFromPoints(gpa: Allocator, out_gpa: Allocator, points: []const Point) (BuildError || FreezeError)![]u8 {
    var b = Builder.init(gpa);
    defer b.deinit();
    for (points) |pt| try b.add(pt.lat, pt.lon, pt.value);
    return b.freeze(out_gpa);
}

// ── Hilbert curve mapping ────────────────────────────────────────────────────
//
// A 16-bit-per-axis Hilbert index over a 65536×65536 grid. The exact curve is
// irrelevant to CORRECTNESS (any deterministic order produces a valid packed
// R-tree); Hilbert order is chosen only for query LOCALITY. This is the classic
// iterative xy→d mapping (Wikipedia "Hilbert curve"). See SPEC.md.

const hilbert_bits: u5 = 16;
const hilbert_side: u32 = 1 << hilbert_bits; // 65536
const hilbert_max: u32 = hilbert_side - 1; // 65535

/// Map a coordinate to a grid cell in [0, hilbert_max]. A zero-width range
/// (all points share this axis) collapses to cell 0 — no divide-by-zero.
fn gridCoord(v: f64, lo: f64, hi: f64) u32 {
    if (hi <= lo) return 0;
    const t = (v - lo) / (hi - lo); // [0, 1]
    const scaled = t * @as(f64, @floatFromInt(hilbert_max));
    if (scaled <= 0) return 0;
    if (scaled >= @as(f64, @floatFromInt(hilbert_max))) return hilbert_max;
    return @intFromFloat(scaled);
}

/// Iterative Hilbert xy→distance over a `hilbert_side`-wide grid.
fn hilbertXYToIndex(x0: u32, y0: u32) u32 {
    var x = x0;
    var y = y0;
    var d: u32 = 0;
    var s: u32 = hilbert_side / 2;
    while (s > 0) : (s >>= 1) {
        const rx: u32 = if ((x & s) != 0) 1 else 0;
        const ry: u32 = if ((y & s) != 0) 1 else 0;
        d +%= s *% s *% ((3 *% rx) ^ ry);
        // Rotate the quadrant.
        if (ry == 0) {
            if (rx == 1) {
                x = hilbert_max -% x;
                y = hilbert_max -% y;
            }
            const t = x;
            x = y;
            y = t;
        }
    }
    return d;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "add rejects NaN/inf and out-of-range coordinates" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    try testing.expectError(error.NotFinite, b.add(std.math.nan(f64), 0, 1));
    try testing.expectError(error.NotFinite, b.add(0, std.math.inf(f64), 1));
    try testing.expectError(error.OutOfRange, b.add(91.0, 0, 1));
    try testing.expectError(error.OutOfRange, b.add(0, -181.0, 1));
    try b.add(90.0, 180.0, 1); // inclusive bounds accepted
    try b.add(-90.0, -180.0, 2);
    try testing.expectEqual(@as(usize, 2), b.count());
}

test "hilbert mapping is a bijection over a small grid" {
    // 4×4 grid (use the top bits): every distinct cell yields a distinct index,
    // and indices cover [0, 15]. Verifies the mapping is a permutation.
    var seen = [_]bool{false} ** 16;
    const step: u32 = hilbert_side / 4;
    var yi: u32 = 0;
    while (yi < 4) : (yi += 1) {
        var xi: u32 = 0;
        while (xi < 4) : (xi += 1) {
            const d = hilbertXYToIndex(xi * step, yi * step) / (step * step);
            try testing.expect(d < 16);
            try testing.expect(!seen[d]); // no collisions
            seen[d] = true;
        }
    }
    for (seen) |v| try testing.expect(v);
}

test "hilbert order is locality-preserving: consecutive indices are grid-adjacent" {
    // Adjacent Hilbert cells differ by exactly one grid step on one axis — the
    // defining Hilbert property. Walk the 4×4 order and check adjacency.
    const step: u32 = hilbert_side / 4;
    var coords: [16][2]u32 = undefined;
    var yi: u32 = 0;
    while (yi < 4) : (yi += 1) {
        var xi: u32 = 0;
        while (xi < 4) : (xi += 1) {
            const d = hilbertXYToIndex(xi * step, yi * step) / (step * step);
            coords[d] = .{ xi, yi };
        }
    }
    for (1..16) |i| {
        const dx: i64 = @intCast(@abs(@as(i64, coords[i][0]) - @as(i64, coords[i - 1][0])));
        const dy: i64 = @intCast(@abs(@as(i64, coords[i][1]) - @as(i64, coords[i - 1][1])));
        try testing.expectEqual(@as(i64, 1), dx + dy); // exactly one step
    }
}

test "freeze is deterministic and the empty index is a valid header-only buffer" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    // empty
    const e = try b.freeze(testing.allocator);
    defer testing.allocator.free(e);
    const eh = try format.Header.load(e);
    try testing.expectEqual(@as(u64, 0), eh.item_count);
    try testing.expectEqual(@as(u32, 0), eh.node_count);
    try eh.verifyBody(e);

    try b.add(50.0, 14.0, 1);
    try b.add(49.0, 16.0, 2);
    try b.add(48.5, 14.3, 3);
    const buf1 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf1);
    const buf2 = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf2);
    try testing.expectEqualSlices(u8, buf1, buf2);

    const h = try format.Header.load(buf1);
    try testing.expectEqual(@as(u64, 3), h.item_count);
    try h.verifyBody(buf1);
    // Root is the last node and is internal (3 leaves group under one root).
    const nodes = format.Nodes.init(buf1, h);
    const root = try nodes.at(h.root_index);
    try testing.expect(!root.leaf);
    try testing.expectEqual(@as(u16, 3), root.child_count);
}

test "single point freezes to one leaf root" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    try b.add(12.34, 56.78, 999);
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    try testing.expectEqual(@as(u32, 1), h.node_count);
    const nodes = format.Nodes.init(buf, h);
    const root = try nodes.at(h.root_index);
    try testing.expect(root.leaf);
    try testing.expectEqual(@as(u32, 999), root.data);
    try testing.expectEqual(@as(f64, 12.34), root.min_lat);
}

test "every parent bbox encloses its children (packed R-tree invariant)" {
    var b = Builder.init(testing.allocator);
    defer b.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (0..500) |i| {
        try b.add(rnd.float(f64) * 180 - 90, rnd.float(f64) * 360 - 180, @intCast(i));
    }
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    const h = try format.Header.load(buf);
    const nodes = format.Nodes.init(buf, h);
    var idx: u32 = 0;
    while (idx < h.node_count) : (idx += 1) {
        const node = try nodes.at(idx);
        if (node.leaf) continue;
        var c: u32 = 0;
        while (c < node.child_count) : (c += 1) {
            const ch = try nodes.child(node, node.data + c);
            try testing.expect(ch.min_lat >= node.min_lat and ch.max_lat <= node.max_lat);
            try testing.expect(ch.min_lon >= node.min_lon and ch.max_lon <= node.max_lon);
        }
    }
}
