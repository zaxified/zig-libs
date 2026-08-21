// SPDX-License-Identifier: MIT

//! What a reporting consumer does with `tabular`: take a raw sales feed
//! (region, day, revenue) shaped as a `dataset.Dataset`, roll it up by
//! region with the T0 verb algebra (`transforms.aggregate` / `sort` /
//! `topN`), then compute a 3-day rolling average for one region with the T1
//! series algebra (`series.rolling`) — the two tiers `tabular`'s own module
//! doc says live in separate namespaces because their spec types collide.
//!
//! Built against the PUBLISHED module (`@import("tabular")`), plus the
//! `dataset` dependency it declares (a real consumer builds the `Dataset`s
//! `tabular` operates on from that same sibling module).

const std = @import("std");
const tabular = @import("tabular");
const dataset = @import("dataset");

const columns = [_]dataset.Column{
    .{ .name = "region", .type = .text },
    .{ .name = "day", .type = .date },
    .{ .name = "revenue", .type = .float },
};

fn row(region: []const u8, day: []const u8, revenue: f64) [3]dataset.Value {
    return .{ .{ .text = region }, .{ .text = day }, .{ .float = revenue } };
}

pub fn main() !void {
    // `dataset`/`tabular` share one memory model (documented in both
    // READMEs): every transform takes a caller-owned allocator, "normally an
    // arena the caller owns for the whole pipeline", and hands back a new
    // `Dataset` whose cells may borrow from earlier stages. Nothing is meant
    // to be freed piecemeal — free the whole arena at the end.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    var b = dataset.Builder.init(gpa, &columns);
    const raw_rows = [_][3]dataset.Value{
        row("east", "2026-08-01", 100),
        row("east", "2026-08-02", 120),
        row("east", "2026-08-03", 90),
        row("east", "2026-08-04", 150),
        row("west", "2026-08-01", 200),
        row("west", "2026-08-02", 210),
        row("west", "2026-08-03", 190),
        row("west", "2026-08-04", 220),
    };
    for (raw_rows) |r| try b.appendRow(&r);
    const sales = try b.toOwned();

    // ── T0: roll up by region, rank, keep the leader ────────────────────────
    const by_region = try tabular.transforms.aggregate(gpa, sales, .{
        .group_by = &.{"region"},
        .aggs = &.{.{ .src = "revenue", .out = "total", .func = .sum }},
    });
    const ranked = try tabular.transforms.sort(gpa, by_region, .{ .key = "total", .dir = .desc });
    const leader = try tabular.transforms.topN(gpa, ranked, .{ .n = 1 });

    const leader_region = leader.cell(0, "region").?.asText().?;
    const leader_total = leader.cell(0, "total").?.asFloat().?;
    std.debug.print("top region: {s} (total revenue {d:.0})\n", .{ leader_region, leader_total });

    // ── T1: a 3-day rolling mean of the east region's daily revenue ────────
    var east_b = dataset.Builder.init(gpa, &columns);
    for (raw_rows) |r| {
        if (std.mem.eql(u8, r[0].asText().?, "east")) try east_b.appendRow(&r);
    }
    const east = try east_b.toOwned();

    const rolled = try tabular.series.rolling(gpa, east, .{
        .value_col = "revenue",
        .out = "revenue_3d_avg",
        .window = 3,
    });
    var i: usize = 0;
    while (i < rolled.rowCount()) : (i += 1) {
        const day = rolled.cell(i, "day").?.asText().?;
        const avg = rolled.cell(i, "revenue_3d_avg").?;
        if (avg.isNull()) {
            std.debug.print("{s}: (insufficient history)\n", .{day});
        } else {
            std.debug.print("{s}: 3-day avg = {d:.1}\n", .{ day, avg.asFloat().? });
        }
    }
}
