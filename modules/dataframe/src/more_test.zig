// SPDX-License-Identifier: MIT
//! The verbs of `more.zig` against `tabular`'s row verbs of the same names, over the
//! generated tables of `verbs_test.zig`: the same cells, or the same error.

const std = @import("std");
const testing = std.testing;
const tab = @import("tabular");
const ds = @import("dataset");
const vt = @import("verbs_test.zig");
const more = @import("more.zig");
const fm = @import("frame.zig");
const t0 = tab.transforms;
const t1 = tab.series;
const conv = vt.conv;

test "frame verbs agree with the row verbs: page, tail, topN, nlargest, sample" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0x9a9e);
        const r = prng.random();
        const d = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 60));
        const f = try vt.F(a, d);
        const ps: t0.PageSpec = .{ .offset = r.uintLessThan(usize, 70), .limit = if (r.boolean()) r.uintLessThan(usize, 70) else null };
        try vt.agree(t0.page(a, d, ps), more.page(a, f, try conv(more.PageSpec, a, ps)));
        const n = r.uintLessThan(usize, 70);
        try vt.agree(t0.tail(a, d, n), more.tail(a, f, n));
        var tn: t0.TopNSpec = .{ .n = r.uintLessThan(usize, 70) };
        if (r.boolean()) tn.tail = .{ .label_col = vt.pickName(r, d), .label = "other", .value_col = vt.pickName(r, d) };
        try vt.agree(t0.topN(a, d, tn), more.topN(a, f, try conv(more.TopNSpec, a, tn)));
        const ts: t0.TopSpec = .{ .col = vt.pickName(r, d), .n = r.uintLessThan(usize, 20), .dir = r.enumValue(t0.SortDir) };
        try vt.agree(t0.nlargest(a, d, ts), more.nlargest(a, f, try conv(more.TopSpec, a, ts)));
        const ss: t0.SampleSpec = .{ .n = r.uintLessThan(usize, 80), .seed = r.int(u64), .replace = r.boolean() };
        try vt.agree(t0.sample(a, d, ss), more.sample(a, f, try conv(more.SampleSpec, a, ss)));
    }
}

test "frame verbs agree with the row verbs: concatByName, partitionBy, valueCounts, describe" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xc0c0);
        const r = prng.random();
        const d = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 60));
        const e = try vt.table(a, r, if (r.boolean()) "" else "x", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 30));
        const f = try vt.F(a, d);
        const g = try vt.F(a, e);
        try vt.agree(t0.concatByName(a, &.{ d, e, d }), more.concatByName(a, &.{ f, g, f }));

        const by = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (by) |*nm| nm.* = vt.pickName(r, d);
        if (t0.partitionBy(a, d, by)) |want| {
            const got = try more.partitionBy(a, f, by);
            try testing.expectEqual(want.len, got.len);
            for (want, got) |w, p| {
                try testing.expectEqual(w.key.len, p.key.len);
                for (w.key, p.key) |x, y| try testing.expect(@import("storage_test.zig").sameCell(x, y));
                try vt.expectSameTable(w.table, p.frame);
            }
        } else |err| try testing.expectError(err, more.partitionBy(a, f, by));

        var vc: t0.ValueCountsSpec = .{ .cols = by };
        vc.keep_missing = r.boolean();
        try vt.agree(t0.valueCounts(a, d, vc), more.valueCounts(a, f, try conv(more.ValueCountsSpec, a, vc)));
        const dc = try a.alloc([]const u8, r.uintLessThan(usize, 3));
        for (dc) |*nm| nm.* = vt.pickName(r, d);
        try vt.agree(t0.describe(a, d, dc), more.describe(a, f, dc));
    }
}

test "frame verbs agree with the row verbs: clip, replace, cut" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xc1c1);
        const r = prng.random();
        const d = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 60));
        const f = try vt.F(a, d);
        const bound = struct {
            fn of(rr: std.Random) ?f64 {
                return switch (rr.uintLessThan(u8, 4)) {
                    0 => null,
                    1 => std.math.nan(f64),
                    else => vt.randFloat(rr),
                };
            }
        }.of;
        const cs: t0.ClipSpec = .{ .col = vt.pickName(r, d), .lower = bound(r), .upper = bound(r) };
        try vt.agree(t0.clip(a, d, cs), more.clip(a, f, try conv(more.ClipSpec, a, cs)));

        const pairs = try a.alloc(t0.ReplacePair, r.uintLessThan(usize, 4));
        for (pairs) |*p| p.* = .{ .from = try vt.cellOf(r, a, r.enumValue(vt.Shape)), .to = try vt.cellOf(r, a, r.enumValue(vt.Shape)) };
        const rs: t0.ReplaceSpec = .{ .col = vt.pickName(r, d), .pairs = pairs };
        try vt.agree(t0.replace(a, d, rs), more.replace(a, f, try conv(more.ReplaceSpec, a, rs)));

        const edges = try a.alloc(f64, r.uintLessThan(usize, 5));
        for (edges, 0..) |*x, i| x.* = if (r.uintLessThan(u8, 10) == 0) vt.randFloat(r) else @as(f64, @floatFromInt(i)) - 1.5;
        const all_labels = [_][]const u8{ "a", "b", "c", "d" };
        const labels: []const []const u8 = if (r.boolean() and edges.len > 1) try a.dupe([]const u8, all_labels[0 .. edges.len - 1]) else &.{};
        const ct: t0.CutSpec = .{ .col = vt.pickName(r, d), .out = "bin", .edges = edges, .labels = labels, .right = r.boolean(), .include_lowest = r.boolean() };
        try vt.agree(t0.cut(a, d, ct), more.cut(a, f, try conv(more.CutSpec, a, ct)));
    }
}

test "frame verbs agree with the row verbs: joinAsof, every direction and option" {
    for (0..vt.seeds) |seed| {
        errdefer std.debug.print("seed {d}\n", .{seed});
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var prng = std.Random.DefaultPrng.init(seed ^ 0xa50f);
        const r = prng.random();
        const l = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 30));
        var rt = try vt.table(a, r, "", 1 + r.uintLessThan(usize, 4), r.uintLessThan(usize, 30));
        var spec: t1.AsofSpec = .{ .on = vt.pickName(r, l) };
        if (r.boolean()) spec.by = try a.dupe([]const u8, &.{vt.pickName(r, l)});
        spec.direction = switch (r.uintLessThan(u8, 3)) {
            0 => .backward,
            1 => .forward,
            else => .nearest,
        };
        spec.tolerance = if (r.boolean()) @abs(vt.randFloat(r)) else null;
        spec.allow_exact = r.boolean();
        spec.suffix = if (r.boolean()) "_r" else null;
        // Mostly sorted right sides, so the match path runs and not only NotSorted.
        if (r.uintLessThan(u8, 4) != 0) rt = t0.sort(a, rt, .{ .key = spec.on }) catch rt;
        const lf = try vt.F(a, l);
        const rf = try vt.F(a, rt);
        try vt.agree(t1.joinAsof(a, l, rt, spec), more.joinAsof(a, lf, rf, try conv(more.AsofSpec, a, spec)));
    }
}

test "more verbs: a frame past u32 rows is refused, and concat's cell cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]@import("value.zig").Column{.{ .name = "k", .type = .int }};
    const huge: fm.Frame = .{ .columns = &cols, .data = &.{}, .len = 1 << 40 };
    try testing.expectError(error.TooLarge, more.page(a, huge, .{}));
    try testing.expectError(error.TooLarge, more.tail(a, huge, 1));
    try testing.expectError(error.TooLarge, more.sample(a, huge, .{ .n = 1, .seed = 1 }));
    try testing.expectError(error.TooLarge, more.partitionBy(a, huge, &.{}));
    try testing.expectError(error.TooLarge, more.joinAsof(a, huge, huge, .{ .on = "k" }));
    const big: fm.Frame = .{ .columns = &cols, .data = &.{}, .len = 1 << 24 };
    try testing.expectError(error.TooLarge, more.concatByName(a, &.{ big, big }));
}
