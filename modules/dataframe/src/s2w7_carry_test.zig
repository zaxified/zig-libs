// SPDX-License-Identifier: MIT
//! A time zone carried by a column (dataframe S2 wave W7) must survive every verb that passes
//! the column on. ONE table-driven test: each row names a verb and the output column that has
//! to come out with the zone (or, for the casts, without); the table is the list of verbs that
//! carry it, so a new verb that rebuilds its columns from `.type` alone is caught by adding a
//! row. The verbs that cannot carry it are listed in SPEC "Time zones" with the reason.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const st = @import("structure_test.zig");
const Value = df.Value;
const Column = df.Column;
const Frame = df.Frame;

const prague = "Europe/Prague";
const kolkata = "Asia/Kolkata";
const h_us: i64 = 3_600_000_000;
const t0: i64 = 1_700_000_000_000_000;

fn source(a: std.mem.Allocator) !Frame {
    const cols: []const Column = &.{
        .{ .name = "ts", .type = .timestamp, .time_zone = prague },
        .{ .name = "k", .type = .int },
        .{ .name = "v", .type = .float },
        .{ .name = "ts2", .type = .timestamp, .time_zone = "UTC" },
    };
    var rows: [4][4]Value = undefined;
    const ks = [_]i64{ 1, 2, 1, 3 };
    for (&rows, 0..) |*r, i| {
        const us = t0 + @as(i64, @intCast(i)) * h_us;
        r.* = .{ .{ .int = us }, .{ .int = ks[i] }, .{ .float = @floatFromInt(i) }, .{ .int = us } };
    }
    const slices = [_][]const Value{ &rows[0], &rows[1], &rows[2], &rows[3] };
    return st.mk(a, cols, &slices);
}

fn other(a: std.mem.Allocator) !Frame {
    return st.mk(a, &.{
        .{ .name = "k", .type = .int },
        .{ .name = "rts", .type = .timestamp, .time_zone = kolkata },
    }, &.{
        &.{ .{ .int = 1 }, .{ .int = t0 } },
        &.{ .{ .int = 2 }, .{ .int = t0 + h_us } },
        &.{ .{ .int = 3 }, .{ .int = t0 + 2 * h_us } },
    });
}

/// A struct column `s` with one declared zoned field `t`, built by hand.
fn structFrame(a: std.mem.Allocator) !Frame {
    const vals = try a.dupe(i64, &.{ t0, t0 + h_us });
    const children = try a.dupe(df.ColumnData, &.{.{ .int = .{ .values = vals } }});
    const names = try a.dupe([]const u8, &.{"t"});
    const sc = try a.create(df.StructColumn);
    sc.* = .{ .names = names, .children = children, .len = 2 };
    const inner = try a.dupe(Column, &.{.{ .name = "t", .type = .timestamp, .time_zone = prague }});
    const cols = try a.dupe(Column, &.{.{ .name = "s", .type = .@"struct", .inner = inner }});
    const data = try a.dupe(df.ColumnData, &.{.{ .@"struct" = sc }});
    return .{ .columns = cols, .data = data, .len = 2 };
}

const Verb = enum {
    select,
    filter,
    take,
    page,
    tail,
    reverse,
    sort,
    distinct,
    clone,
    rename,
    join_payload,
    join_key,
    asof_payload,
    concat_vertical,
    concat_diagonal,
    group_key,
    agg_min,
    agg_first_ts2,
    implode_explode,
    pivot_row_key,
    unpivot_id,
    unpivot_value,
    window_shift,
    group_by_dynamic,
    mutate_col,
    mutate_if_else,
    cast_to_zone,
    cast_to_naive,
    hstack,
    unnest,
};

const Case = struct { verb: Verb, col: []const u8, zone: ?[]const u8 };

const table = [_]Case{
    .{ .verb = .select, .col = "ts", .zone = prague },
    .{ .verb = .filter, .col = "ts", .zone = prague },
    .{ .verb = .take, .col = "ts", .zone = prague },
    .{ .verb = .page, .col = "ts", .zone = prague },
    .{ .verb = .tail, .col = "ts", .zone = prague },
    .{ .verb = .reverse, .col = "ts", .zone = prague },
    .{ .verb = .sort, .col = "ts", .zone = prague },
    .{ .verb = .distinct, .col = "ts", .zone = prague },
    .{ .verb = .clone, .col = "ts", .zone = prague },
    .{ .verb = .rename, .col = "t2", .zone = prague },
    .{ .verb = .join_payload, .col = "rts", .zone = kolkata },
    .{ .verb = .join_key, .col = "ts", .zone = prague },
    .{ .verb = .asof_payload, .col = "rts", .zone = kolkata },
    .{ .verb = .concat_vertical, .col = "ts", .zone = prague },
    .{ .verb = .concat_diagonal, .col = "ts2", .zone = "UTC" },
    .{ .verb = .group_key, .col = "ts", .zone = prague },
    .{ .verb = .agg_min, .col = "ts_min", .zone = prague },
    .{ .verb = .agg_first_ts2, .col = "ts2_first", .zone = "UTC" },
    .{ .verb = .implode_explode, .col = "ts_list", .zone = prague },
    .{ .verb = .pivot_row_key, .col = "ts", .zone = prague },
    .{ .verb = .unpivot_id, .col = "ts", .zone = prague },
    .{ .verb = .unpivot_value, .col = "value", .zone = prague },
    .{ .verb = .window_shift, .col = "prev", .zone = prague },
    .{ .verb = .group_by_dynamic, .col = "ts", .zone = prague },
    .{ .verb = .mutate_col, .col = "m", .zone = prague },
    .{ .verb = .mutate_if_else, .col = "m", .zone = prague },
    .{ .verb = .cast_to_zone, .col = "k", .zone = "Asia/Tokyo" },
    .{ .verb = .cast_to_naive, .col = "ts", .zone = null },
    .{ .verb = .hstack, .col = "ts_b", .zone = prague },
    .{ .verb = .unnest, .col = "t", .zone = prague },
};

fn apply(a: std.mem.Allocator, verb: Verb) !Frame {
    const f = try source(a);
    const ts: df.Expr = .{ .col = "ts" };
    switch (verb) {
        .select => return df.select(a, f, &.{ "ts", "k" }),
        .filter => return df.filter(a, f, .{ .where = &.{.{ .col = "k", .op = .gt, .value = .{ .int = 0 } }} }),
        .take => return df.take(a, f, &.{ 1, 0 }),
        .page => return df.page(a, f, .{ .limit = 2 }),
        .tail => return df.tail(a, f, 2),
        .reverse => return df.reverse(a, f),
        .sort => return df.sort(a, f, .{ .key = "ts", .dir = .desc }),
        .distinct => return df.distinct(a, f, .{ .keys = &.{"k"} }),
        .clone => return df.clone(a, f),
        .rename => return df.rename(a, f, &.{.{ .from = "ts", .to = "t2" }}),
        .join_payload => return df.join(a, f, try other(a), .{ .on = "k", .how = .left }),
        .join_key => return df.join(a, f, try other(a), .{ .on = "k", .how = .inner }),
        .asof_payload => return df.joinAsof(a, f, try other(a), .{ .on = "k" }),
        .concat_vertical => return df.concat(a, &.{ f, f }, .vertical),
        .concat_diagonal => return df.concat(a, &.{ f, f }, .diagonal),
        .group_key => return df.aggregate(a, f, .{ .group_by = &.{"ts"}, .aggs = &.{.{ .src = "v", .out = "n", .func = .count }} }),
        .agg_min => return df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "ts", .out = "ts_min", .func = .min }} }),
        .agg_first_ts2 => return df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "ts2", .out = "ts2_first", .func = .first }} }),
        .implode_explode => {
            const g = try df.aggregate(a, f, .{ .group_by = &.{"k"}, .aggs = &.{.{ .src = "ts", .out = "ts_list", .func = .implode }} });
            return df.explode(a, g, &.{"ts_list"});
        },
        .pivot_row_key => return df.pivot(a, f, .{ .row_key = "ts", .col_key = "k", .value_col = "v" }),
        .unpivot_id => return df.unpivot(a, f, .{ .id_cols = &.{"ts"}, .value_cols = &.{"v"} }),
        .unpivot_value => return df.unpivot(a, f, .{ .id_cols = &.{"k"}, .value_cols = &.{"ts"} }),
        .window_shift => return df.window(a, f, .{ .value_col = "ts", .out = "prev", .op = .{ .shift = .{ .n = 1 } } }),
        .group_by_dynamic => return df.groupByDynamic(a, f, .{ .index = "ts", .every = "1h", .aggs = &.{.{ .src = "v", .out = "s", .func = .sum }} }),
        .mutate_col => return df.mutate(a, f, &.{.{ .out = "m", .expr = ts }}),
        .mutate_if_else => {
            const c: df.Expr = .{ .binary = .{ .op = .gt, .l = &.{ .col = "k" }, .r = &.{ .lit = .{ .int = 1 } } } };
            return df.mutate(a, f, &.{.{ .out = "m", .expr = .{ .if_else = .{ .cond = &c, .then = &ts, .otherwise = &ts } } }});
        },
        .cast_to_zone => return df.cast(a, f, .{ .col = "k", .to = .timestamp, .zone = "Asia/Tokyo" }),
        .cast_to_naive => return df.cast(a, f, .{ .col = "ts", .to = .timestamp }),
        .hstack => {
            var s = f.series("ts").?;
            s.name = "ts_b";
            return df.hstack(a, f, &.{s});
        },
        .unnest => return df.unnest(a, try structFrame(a), .{ .cols = &.{"s"} }),
    }
}

test "every verb that passes a timestamp column on keeps its zone (table-driven)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var bad: usize = 0;
    for (table) |c| {
        const g = apply(arena.allocator(), c.verb) catch |e| {
            std.debug.print("verb {s} failed: {s}\n", .{ @tagName(c.verb), @errorName(e) });
            bad += 1;
            continue;
        };
        const ci = g.columnIndex(c.col) orelse {
            std.debug.print("verb {s}: no column {s}\n", .{ @tagName(c.verb), c.col });
            bad += 1;
            continue;
        };
        const got = g.columns[ci];
        const ok = got.type == .timestamp and ((got.time_zone == null and c.zone == null) or
            (got.time_zone != null and c.zone != null and std.mem.eql(u8, got.time_zone.?, c.zone.?)));
        if (!ok) {
            std.debug.print("verb {s}: column {s} is {s} zone {?s}, want timestamp zone {?s}\n", .{ @tagName(c.verb), c.col, @tagName(got.type), got.time_zone, c.zone });
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "concat refuses timestamp columns of different zones; a zone and no zone differ too" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try source(a);
    const g = try df.cast(a, f, .{ .col = "ts", .to = .timestamp, .zone = kolkata });
    const n = try df.cast(a, f, .{ .col = "ts", .to = .timestamp });
    for ([_]df.ConcatHow{ .vertical, .vertical_relaxed, .diagonal }) |how| {
        try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ f, g }, how));
        try testing.expectError(error.SchemaMismatch, df.concat(a, &.{ f, n }, how));
    }
}

test "a column's zone is checked where a schema comes in" {
    const ok: Column = .{ .name = "t", .type = .timestamp, .time_zone = prague };
    try ok.checkZone();
    try (Column{ .name = "t", .type = .timestamp }).checkZone();
    try testing.expectError(error.BadArgument, (Column{ .name = "t", .type = .int, .time_zone = prague }).checkZone());
    try testing.expectError(error.BadArgument, (Column{ .name = "t", .type = .timestamp, .time_zone = "Europe/Atlantis" }).checkZone());
    try testing.expectError(error.BadArgument, (Column{ .name = "t", .type = .timestamp, .time_zone = "" }).checkZone());
    const bad_inner: Column = .{ .name = "l", .type = .list, .inner = &.{.{ .name = "", .type = .text, .time_zone = prague }} };
    try testing.expectError(error.BadArgument, bad_inner.checkZone());
}
