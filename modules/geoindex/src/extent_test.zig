// SPDX-License-Identifier: MIT
//! Rectangle items (`Builder.addBox`), the great-circle metric (`QueryOptions.metric`), the
//! antimeridian-aware planar metric and the build-time fan-out, each against a linear scan
//! that shares no code with the index.

const std = @import("std");
const testing = std.testing;
const gi = @import("root.zig");

const earth_radius_m = 6_371_000.0;

/// Haversine by the textbook formula (radians, `atan2` form), unrelated to `query.zig`'s.
fn havM(lat1: f64, lon1: f64, lat2: f64, lon2: f64) f64 {
    const p1 = lat1 * std.math.pi / 180.0;
    const p2 = lat2 * std.math.pi / 180.0;
    const dp = p2 - p1;
    const dl = (lon2 - lon1) * std.math.pi / 180.0;
    const a = @sin(dp / 2) * @sin(dp / 2) + @cos(p1) * @cos(p2) * @sin(dl / 2) * @sin(dl / 2);
    return 2 * earth_radius_m * std.math.atan2(@sqrt(a), @sqrt(1 - a));
}

const Item = struct { lat: f64, lon: f64, max_lat: f64, max_lon: f64, value: u32 };

fn genItems(a: std.mem.Allocator, rnd: std.Random, n: usize, boxes: bool, world: bool) ![]Item {
    const items = try a.alloc(Item, n);
    for (items, 0..) |*it, i| {
        const lat = if (world) rnd.float(f64) * 180 - 90 else rnd.float(f64) * 20 - 10;
        const lon = if (world) rnd.float(f64) * 360 - 180 else rnd.float(f64) * 20 - 10;
        var h_lat: f64 = 0;
        var h_lon: f64 = 0;
        if (boxes and i % 2 == 0) {
            h_lat = rnd.float(f64) * 4;
            h_lon = rnd.float(f64) * 4;
        }
        it.* = .{ .lat = @max(-90, lat - h_lat), .lon = @max(-180, lon - h_lon), .max_lat = @min(90, lat + h_lat), .max_lon = @min(180, lon + h_lon), .value = @intCast(i) };
    }
    if (world and n > 4) { // the corners of the map
        items[0] = .{ .lat = 90, .lon = 180, .max_lat = 90, .max_lon = 180, .value = 0 };
        items[1] = .{ .lat = -90, .lon = -180, .max_lat = -90, .max_lon = -180, .value = 1 };
        items[2] = .{ .lat = 10, .lon = 179.9, .max_lat = 10, .max_lon = 180, .value = 2 };
        items[3] = .{ .lat = 10, .lon = -180, .max_lat = 12, .max_lon = -179.5, .value = 3 };
    }
    return items;
}

fn freezeItems(items: []const Item, fanout: u16) ![]u8 {
    var b = gi.Builder.init(testing.allocator);
    defer b.deinit();
    b.fanout = fanout;
    for (items) |it| {
        if (it.lat == it.max_lat and it.lon == it.max_lon) try b.add(it.lat, it.lon, it.value) else try b.addBox(it.lat, it.lon, it.max_lat, it.max_lon, it.value);
    }
    return b.freeze(testing.allocator);
}

/// Distance from (qlat, qlon) to a rectangle item by dense sampling of its boundary and interior —
/// an independent upper bound that is exact up to the sampling step.
fn sampledBoxDistM(it: Item, qlat: f64, qlon: f64) f64 {
    var best: f64 = std.math.inf(f64);
    const steps = 24;
    for (0..steps + 1) |i| {
        for (0..steps + 1) |j| {
            const lat = it.lat + (it.max_lat - it.lat) * @as(f64, @floatFromInt(i)) / steps;
            const lon = it.lon + (it.max_lon - it.lon) * @as(f64, @floatFromInt(j)) / steps;
            best = @min(best, havM(qlat, qlon, lat, lon));
        }
    }
    return best;
}

test "rectangles: bbox finds every box that meets the query, with its extent" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    for (0..20) |_| {
        const items = try genItems(a, rnd, 120, true, false);
        const buf = try freezeItems(items, 8);
        defer testing.allocator.free(buf);
        const f = try gi.Frozen.loadVerified(buf);
        try testing.expect(f.header.flags & gi.format.flag_extents != 0);
        var qa = rnd.float(f64) * 24 - 12;
        var qb = rnd.float(f64) * 24 - 12;
        var qc = rnd.float(f64) * 24 - 12;
        var qd = rnd.float(f64) * 24 - 12;
        if (qa > qb) std.mem.swap(f64, &qa, &qb);
        if (qc > qd) std.mem.swap(f64, &qc, &qd);
        var out: [200]gi.Match = undefined;
        const r = try f.bbox(qa, qb, qc, qd, &out, .{ .max_visited = 0 });
        try testing.expectEqual(gi.BboxStatus.complete, r.status);
        var want: usize = 0;
        for (items) |it| {
            if (it.max_lat >= qa and it.lat <= qb and it.max_lon >= qc and it.lon <= qd) {
                want += 1;
                var found = false;
                for (r.items) |m| if (m.value == it.value) {
                    found = true;
                    try testing.expectEqual(it.lat, m.lat);
                    try testing.expectEqual(it.lon, m.lon);
                    try testing.expectEqual(it.max_lat, m.max_lat);
                    try testing.expectEqual(it.max_lon, m.max_lon);
                    try testing.expectEqual(it.lat == it.max_lat and it.lon == it.max_lon, m.isPoint());
                };
                try testing.expect(found);
            }
        }
        try testing.expectEqual(want, r.items.len);
    }
}

test "rectangles: knn and within rank by the distance to the nearest point of the box (0 inside)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(12);
    const rnd = prng.random();
    for (0..20) |_| {
        const items = try genItems(a, rnd, 90, true, false);
        const buf = try freezeItems(items, 4);
        defer testing.allocator.free(buf);
        const f = try gi.Frozen.load(buf);
        const qlat = rnd.float(f64) * 24 - 12;
        const qlon = rnd.float(f64) * 24 - 12;
        const qk = @cos(qlat * std.math.pi / 180.0);
        // The planar distance to a box, by clamping (the textbook form).
        const want = try a.alloc(f64, items.len);
        for (items, want) |it, *w| {
            const dy = @max(@max(it.lat - qlat, qlat - it.max_lat), 0);
            const dx = @max(@max(it.lon - qlon, qlon - it.max_lon), 0) * qk;
            w.* = dx * dx + dy * dy;
        }
        const sorted = try a.dupe(f64, want);
        std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
        const k = 15;
        var out: [k]gi.Neighbor = undefined;
        const scratch = try a.alloc(gi.HeapEntry, items.len + 40);
        const r = try f.knn(qlat, qlon, k, &out, scratch, .{ .max_visited = 0 });
        try testing.expectEqual(@as(usize, k), r.items.len);
        for (r.items, sorted[0..k]) |g, w| try testing.expectApproxEqAbs(w, g.dist2, 1e-9);
        // `within`: the same set as the scan, each with its distance.
        const radius = 3.0;
        var wout: [100]gi.Neighbor = undefined;
        const wr = try f.within(qlat, qlon, radius, &wout, .{ .max_visited = 0 });
        var n_want: usize = 0;
        for (want) |w| {
            if (w <= radius * radius) n_want += 1;
        }
        try testing.expectEqual(n_want, wr.items.len);
        for (wr.items) |m| try testing.expectApproxEqAbs(want[m.value], m.dist2, 1e-9);
    }
}

test "great circle: knn and within agree with a haversine scan over the whole map, poles and antimeridian included" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(13);
    const rnd = prng.random();
    for (0..16) |round| {
        const items = try genItems(a, rnd, 300, round % 2 == 0, true);
        const buf = try freezeItems(items, if (round % 3 == 0) 4 else 16);
        defer testing.allocator.free(buf);
        const f = try gi.Frozen.load(buf);
        for (0..12) |q| {
            // Queries all over the map and on its edges.
            var qlat = rnd.float(f64) * 180 - 90;
            var qlon = rnd.float(f64) * 360 - 180;
            if (q == 0) qlat = 90;
            if (q == 1) qlat = -89.9;
            if (q == 2) qlon = 179.99;
            if (q == 3) qlon = -180;
            const dists = try a.alloc(f64, items.len);
            for (items, dists) |it, *d| d.* = if (it.lat == it.max_lat and it.lon == it.max_lon)
                havM(qlat, qlon, it.lat, it.lon)
            else
                sampledBoxDistM(it, qlat, qlon);
            const sorted = try a.dupe(f64, dists);
            std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
            const k = 10;
            var out: [k]gi.Neighbor = undefined;
            const scratch = try a.alloc(gi.HeapEntry, items.len + 40);
            const r = try f.knn(qlat, qlon, k, &out, scratch, .{ .max_visited = 0, .metric = .great_circle });
            try testing.expectEqual(@as(usize, k), r.items.len);
            for (r.items, sorted[0..k], 0..) |g, w, i| {
                // The scan samples a box (never nearer than the true distance), so: at most the sample, and ascending.
                try testing.expect(g.dist() <= w + 1.0);
                if (i > 0) try testing.expect(g.dist2 >= r.items[i - 1].dist2);
                const it = items[g.value];
                if (it.lat == it.max_lat and it.lon == it.max_lon) try testing.expectApproxEqAbs(w, g.dist(), 1e-3);
            }
            // within: every point item the scan puts inside is found, and nothing found is outside by more than rounding.
            const radius = 1_500_000.0;
            var wout: [400]gi.Neighbor = undefined;
            const wr = try f.within(qlat, qlon, radius, &wout, .{ .max_visited = 0, .metric = .great_circle });
            try testing.expectEqual(gi.WithinStatus.complete, wr.status);
            for (items, dists) |it, d| {
                const is_point = it.lat == it.max_lat and it.lon == it.max_lon;
                var found = false;
                for (wr.items) |m| if (m.value == it.value) {
                    found = true;
                };
                if (is_point and d < radius - 1e-3) try testing.expect(found);
                if (is_point and d > radius + 1e-3) try testing.expect(!found);
                if (!is_point and d < radius - 5000) try testing.expect(found); // sampled bound: within the sampling step
            }
            for (wr.items) |m| try testing.expect(m.dist() <= radius + 1e-3);
        }
    }
}

test "planar metric: across the antimeridian the short way round" {
    const buf = try freezeItems(&.{
        .{ .lat = 0, .lon = 179.9, .max_lat = 0, .max_lon = 179.9, .value = 1 },
        .{ .lat = 0, .lon = -179.9, .max_lat = 0, .max_lon = -179.9, .value = 2 },
        .{ .lat = 0, .lon = 170, .max_lat = 0, .max_lon = 170, .value = 3 },
        .{ .lat = 0, .lon = 0, .max_lat = 0, .max_lon = 0, .value = 4 },
    }, 16);
    defer testing.allocator.free(buf);
    const f = try gi.Frozen.load(buf);
    var out: [4]gi.Neighbor = undefined;
    var scratch: [64]gi.HeapEntry = undefined;
    const r = try f.knn(0, -179.95, 3, &out, &scratch, .{});
    try testing.expectEqual(@as(usize, 3), r.items.len);
    try testing.expectEqual(@as(u32, 2), r.items[0].value); // 0.05 degrees
    try testing.expectEqual(@as(u32, 1), r.items[1].value); // 0.15 degrees, over the dateline
    try testing.expectEqual(@as(u32, 3), r.items[2].value);
    try testing.expectApproxEqAbs(@as(f64, 0.15), r.items[1].dist(), 1e-9);
    var wout: [4]gi.Neighbor = undefined;
    const w = try f.within(0, -179.95, 0.2, &wout, .{});
    try testing.expectEqual(@as(usize, 2), w.items.len);
}

test "fanout: any build-time value (clamped to 2..65535) gives the same answers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(14);
    const items = try genItems(a, prng.random(), 500, true, false);
    var reference: ?[]u32 = null;
    for ([_]u16{ 0, 1, 2, 3, 7, 16, 100, 65535 }) |fan| {
        const buf = try freezeItems(items, fan);
        defer testing.allocator.free(buf);
        const f = try gi.Frozen.loadVerified(buf);
        try testing.expectEqual(std.math.clamp(fan, gi.fanout_min, gi.fanout_max), f.header.fanout);
        var out: [20]gi.Neighbor = undefined;
        const scratch = try a.alloc(gi.HeapEntry, gi.knnScratchLen(20, f.header.fanout, f.itemCount()) + 600);
        const r = try f.knn(1.5, -2.5, 20, &out, scratch, .{ .max_visited = 0 });
        const ids = try a.alloc(u32, r.items.len);
        for (r.items, ids) |m, *i| i.* = m.value;
        if (reference) |ref| try testing.expectEqualSlices(u32, ref, ids) else reference = ids;
    }
}

test "addBox: inverted, out of range, not finite" {
    var b = gi.Builder.init(testing.allocator);
    defer b.deinit();
    try testing.expectError(error.InvertedBox, b.addBox(5, 0, 4, 1, 1));
    try testing.expectError(error.InvertedBox, b.addBox(0, 5, 1, 4, 1));
    try testing.expectError(error.OutOfRange, b.addBox(-91, 0, 0, 1, 1));
    try testing.expectError(error.OutOfRange, b.addBox(0, 0, 1, 181, 1));
    try testing.expectError(error.NotFinite, b.addBox(0, 0, std.math.nan(f64), 1, 1));
    try testing.expectEqual(@as(usize, 0), b.count());
    try b.addBox(3, 3, 3, 3, 9); // a degenerate box is a point and sets no flag
    const buf = try b.freeze(testing.allocator);
    defer testing.allocator.free(buf);
    try testing.expectEqual(@as(u32, 0), (try gi.Frozen.load(buf)).header.flags);
}
