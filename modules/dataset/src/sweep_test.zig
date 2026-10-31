// SPDX-License-Identifier: MIT
//! No-panic sweep tests for dataset, wave GW. Findings DS1..DS3, see
//! ~/CML/20261029-panic-sweep/dataset-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const root = @import("root.zig");
const Dataset = root.Dataset;
const Column = root.Column;
const Value = root.Value;

/// Run `body` in a forked child with stderr captured into `buf`.
const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needle in a const, never inline in the call (the child's trace prints the caller's source line).
const needle_builder = "dataset: Builder.appendRow: cells.len != columns.len";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

const cols2 = [_]Column{ .{ .name = "a", .type = .int }, .{ .name = "b", .type = .float } };

test "Dataset.cell: row past the end and a short row are null, not an index panic (sweep DS1)" {
    const full = [_]Value{ .{ .int = 1 }, .{ .float = 2 } };
    const short = [_]Value{.{ .int = 7 }};
    const rows = [_][]const Value{ &full, &short };
    const d: Dataset = .{ .columns = &cols2, .rows = &rows };
    try testing.expectEqual(@as(i64, 1), d.cell(0, "a").?.int);
    try testing.expectEqual(@as(f64, 2), d.cell(0, "b").?.float);
    try testing.expectEqual(@as(i64, 7), d.cell(1, "a").?.int);
    try testing.expect(d.cell(1, "b") == null); // short row
    try testing.expect(d.cell(2, "a") == null); // row past the end
    try testing.expect(d.cell(std.math.maxInt(usize), "a") == null);
}

test "Dataset.floatColumn / seriesXY: a short row reads as a missing cell (sweep DS2)" {
    const full = [_]Value{ .{ .int = 1 }, .{ .float = 2 } };
    const short = [_]Value{.{ .int = 7 }};
    const rows = [_][]const Value{ &short, &full };
    const d: Dataset = .{ .columns = &cols2, .rows = &rows };
    const fc = try d.floatColumn(testing.allocator, "b");
    defer testing.allocator.free(fc);
    try testing.expectEqualSlices(f64, &.{ 0, 2 }, fc);
    const xy = try d.seriesXY(testing.allocator, "b", "a");
    defer testing.allocator.free(xy);
    try testing.expectEqual([2]f64{ 0, 7 }, xy[0]); // x falls back to the row index, y is a real cell
    try testing.expectEqual([2]f64{ 2, 1 }, xy[1]);
    const xy2 = try d.seriesXY(testing.allocator, "a", "b");
    defer testing.allocator.free(xy2);
    try testing.expectEqual([2]f64{ 7, 0 }, xy2[0]); // y of the short row reads 0
}

fn builderShortRow() void {
    var b = root.Builder.init(std.heap.page_allocator, &cols2);
    b.appendRow(&.{.{ .int = 1 }}) catch {};
}
fn builderLongRow() void {
    var b = root.Builder.init(std.heap.page_allocator, &cols2);
    b.appendRow(&.{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } }) catch {};
}

test "Builder.appendRow: a wrong-width row is a checked panic in every mode (sweep DS3)" {
    try expectPanicMessage(builderShortRow, needle_builder);
    try expectPanicMessage(builderLongRow, needle_builder);
    // and a right-width row is still accepted
    var b = root.Builder.init(testing.allocator, &cols2);
    try b.appendRow(&.{ .{ .int = 1 }, .null });
    const d = try b.toOwned();
    defer {
        for (d.rows) |r| testing.allocator.free(r);
        testing.allocator.free(d.rows);
    }
    try testing.expectEqual(@as(usize, 1), d.rows.len);
}

// ── exact numeric order (review round) ───────────────────────────────────────

test "Value.order / eql: ints above 2^53 are told apart, never rounded through f64 (sweep DS5)" {
    const big: i64 = 1 << 53;
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = big }).order(.{ .int = big + 1 }));
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = std.math.maxInt(i64) }).order(.{ .int = std.math.maxInt(i64) - 1 }));
    try testing.expect(!(Value{ .int = big }).eql(.{ .int = big + 1 }));
    try testing.expect((Value{ .int = big + 1 }).eql(.{ .int = big + 1 }));
    // int against float, exactly: 2^53 + 1 is above the float 2^53
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = big + 1 }).order(.{ .float = 9007199254740992.0 }));
    try testing.expectEqual(std.math.Order.eq, (Value{ .int = big }).order(.{ .float = 9007199254740992.0 }));
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = std.math.maxInt(i64) }).order(.{ .float = 9223372036854775808.0 }));
    try testing.expectEqual(std.math.Order.gt, (Value{ .int = std.math.minInt(i64) }).order(.{ .float = -9223372036854777856.0 }));
    // int against decimal, exactly
    try testing.expectEqual(std.math.Order.eq, (Value{ .int = 3 }).order(.{ .decimal = 3 * root.decimal_scale }));
    try testing.expectEqual(std.math.Order.lt, (Value{ .int = 3 }).order(.{ .decimal = 3 * root.decimal_scale + 1 }));
}

test "Value.order: float against decimal is exact on the fraction, down to the subnormals (sweep DS6)" {
    const D = struct {
        fn f(x: f64, raw: i128) std.math.Order {
            return (Value{ .float = x }).order(.{ .decimal = raw });
        }
    };
    try testing.expectEqual(std.math.Order.eq, D.f(0.5, 500_000_000_000));
    try testing.expectEqual(std.math.Order.eq, D.f(0.25, 250_000_000_000));
    // 0.1 as a double is a hair ABOVE 1/10, 0.3 a hair BELOW 3/10
    try testing.expectEqual(std.math.Order.gt, D.f(0.1, 100_000_000_000));
    try testing.expectEqual(std.math.Order.lt, D.f(0.3, 300_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(0.7, 600_000_000_000));
    try testing.expectEqual(std.math.Order.lt, D.f(0.7, 800_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(5e-324, 0));
    try testing.expectEqual(std.math.Order.lt, D.f(5e-324, 1));
    try testing.expectEqual(std.math.Order.lt, D.f(-0.5, 0));
    try testing.expectEqual(std.math.Order.eq, D.f(-0.5, -500_000_000_000));
    try testing.expectEqual(std.math.Order.gt, D.f(1e30, std.math.maxInt(i128)));
    try testing.expectEqual(std.math.Order.lt, D.f(-1e30, std.math.minInt(i128)));
    try testing.expectEqual(std.math.Order.lt, D.f(-std.math.inf(f64), std.math.minInt(i128)));
    try testing.expectEqual(std.math.Order.gt, D.f(std.math.inf(f64), std.math.maxInt(i128)));
}

test "Value.order is a strict weak order over a pool of awkward numbers, null, bool and text (sweep DS7)" {
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);
    const sc = root.decimal_scale;
    const pool = [_]Value{
        .null,                                           .{ .bool = false },                        .{ .bool = true },
        .{ .text = "" },                                 .{ .text = "a" },                          .{ .int = std.math.minInt(i64) },
        .{ .int = -1 },                                  .{ .int = 0 },                             .{ .int = 1 },
        .{ .int = 1 << 53 },                             .{ .int = (1 << 53) + 1 },                 .{ .int = std.math.maxInt(i64) },
        .{ .float = -inf },                              .{ .float = -1.5 },                        .{ .float = 0 },
        .{ .float = 0.1 },                               .{ .float = 0.5 },                         .{ .float = 1 },
        .{ .float = 9007199254740992.0 },                .{ .float = 9007199254740994.0 },          .{ .float = 9223372036854775808.0 },
        .{ .float = 1e30 },                              .{ .float = inf },                         .{ .float = nan },
        .{ .float = 5e-324 },                            .{ .decimal = 0 },                         .{ .decimal = 1 },
        .{ .decimal = sc / 10 },                         .{ .decimal = sc / 2 },                    .{ .decimal = sc },
        .{ .decimal = -sc / 2 },                         .{ .decimal = (@as(i128, 1) << 53) * sc }, .{ .decimal = (@as(i128, 1) << 53) * sc + 1 },
        .{ .decimal = ((@as(i128, 1) << 53) + 1) * sc }, .{ .decimal = std.math.maxInt(i128) },     .{ .decimal = std.math.minInt(i128) },
    };
    const lt = std.math.Order.lt;
    const gt = std.math.Order.gt;
    for (pool) |a| {
        try testing.expectEqual(std.math.Order.eq, a.order(a));
        for (pool) |b| {
            try testing.expectEqual(b.order(a).invert(), a.order(b)); // antisymmetry
            const nan_involved = (a == .float and std.math.isNan(a.float)) or (b == .float and std.math.isNan(b.float));
            if (!nan_involved and a.order(b) == .eq) try testing.expect(a.eql(b));
            for (pool) |c| {
                // transitivity of <= and of equivalence
                if (a.order(b) != gt and b.order(c) != gt) try testing.expect(a.order(c) != gt);
                if (a.order(b) == lt and b.order(c) != gt) try testing.expect(a.order(c) == lt);
                if (a.order(b) == .eq and b.order(c) == .eq) try testing.expect(a.order(c) == .eq);
            }
        }
    }
}
