// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over dataset's `deserialize` harness (added
//! 2026-10-09). The harness body is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`): `std.testing.fuzz` hands it a `*Smith`, the
//! driver a `*Rng`. The first draw is one `slice` of bytes. Mode 0 feeds them
//! to `deserialize` as the image (what the old harness did, and all a corpus
//! seed ever reaches, because a seed ends after the slice); modes 1-3 read
//! them as a script that builds a WELL-FORMED image (so the accepted path and
//! the serialize/deserialize round trip are reachable from random bytes),
//! mode 3 then cuts it short.
//!
//! Driver: `DATASET_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ds = @import("root.zig");

pub const Label = enum { rejected, accepted, round_tripped, truncated };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and the
/// harness reads every choice from them. Past the end a ranged draw answers its
/// minimum (mode 0 = the raw image), so a corpus seed stays a raw image.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        if (self.cur.at >= self.cur.bytes.len) return at_least;
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

/// Build a well-formed image from `script` (a cursor over it cycles; an empty
/// script reads as zeroes). Cells match their column's type.
fn buildImage(a: std.mem.Allocator, script: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    var c: testkit.fuzz.Cursor = .{ .bytes = script };

    const ncol = c.ranged(0, 4);
    const cols = try ar.alloc(ds.Column, ncol);
    for (cols, 0..) |*col, i| {
        col.* = .{
            .name = try std.fmt.allocPrint(ar, "c{d}", .{i}),
            .type = @enumFromInt(c.ranged(0, 6)),
        };
    }
    const nrow = c.ranged(0, 4);
    const rows = try ar.alloc([]const ds.Value, nrow);
    for (rows) |*row| {
        const cells = try ar.alloc(ds.Value, ncol);
        for (cells, cols) |*cell, col| {
            if (c.ranged(0, 7) == 0) {
                cell.* = .null;
                continue;
            }
            cell.* = switch (col.type) {
                .int, .timestamp => .{ .int = @as(i16, @bitCast(c.word())) },
                .float => .{ .float = @as(f64, @floatFromInt(@as(i16, @bitCast(c.word())))) / 8.0 },
                .text, .date => blk: {
                    const t = try ar.alloc(u8, c.ranged(0, 8));
                    for (t) |*b| b.* = c.byte();
                    break :blk .{ .text = t };
                },
                .bool => .{ .bool = c.byte() & 1 == 1 },
                .decimal => .{ .decimal = @as(i128, @as(i16, @bitCast(c.word()))) * 1_000_003 },
            };
        }
        row.* = cells;
    }
    return ds.serialize(a, .{ .columns = cols, .rows = rows });
}

pub fn deserializeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var buf: [256]u8 = @splat(0);
    const len: usize = src.slice(&buf);
    const mode = src.valueRangeAtMost(u8, 0, 3);

    var built: ?[]u8 = null;
    defer if (built) |b| gpa.free(b);
    var image: []const u8 = buf[0..len];
    if (mode != 0) {
        built = try buildImage(gpa, buf[0..len]);
        image = built.?;
        if (mode == 3 and image.len > 0) {
            image = image[0 .. image.len - 1 - @as(usize, buf[0]) % image.len];
            mark(.truncated);
        }
    }

    const d = ds.deserialize(arena.allocator(), image) catch {
        mark(.rejected);
        return;
    };
    mark(.accepted);
    // An image that decodes must also be traversable.
    for (d.rows) |row| for (row) |v| {
        _ = v.asFloat();
    };
    if (mode == 1 or mode == 2) {
        // Well-formed in, so the same bytes must come back out.
        const again = try ds.serialize(gpa, d);
        defer gpa.free(again);
        try testing.expectEqualSlices(u8, image, again);
        mark(.round_tripped);
    }
}

test "fuzz driver: DATASET_FUZZ (deserialize)" {
    try fuzz_driver.run(deserializeHarness, .{ .prefix = "DATASET_FUZZ", .name = "dataset-deserialize" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        deserializeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dataset seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
