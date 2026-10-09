// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over decimal's two existing `testing.fuzz`
//! harnesses (`Decimal.parse`, `BigDecimal.parse`; added 2026-10-09). The
//! bodies live here, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`); the `testing.fuzz` tests in `root.zig` / `big.zig` feed them through
//! the cursor adapter below, the driver feeds them a PRNG.
//!
//! The `--fuzz` wrappers bias raw bytes toward the number alphabet with
//! `Smith.boolWeighted` before handing the literal over; the driver's PRNG
//! source does the same here (three quarters of the bytes: random bytes are almost never numbers), and a corpus replay
//! stays verbatim.
//!
//! Driver: `DECIMAL_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const decimal = @import("root.zig");

pub const Label = enum { parsed, rejected, big_parsed, big_rejected };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

const alphabet = "0123456789+-.eE";

/// The driver's counterpart of the wrappers' `boolWeighted(1, 4)` bias, stronger.
fn bias(comptime S: type, src: *S, text: []u8) void {
    if (S != fuzz_driver.Rng) return;
    for (text) |*c| {
        if (src.index(4) != 0) c.* = alphabet[c.* % alphabet.len];
    }
}

/// `Decimal.parse` never panics on arbitrary text.
pub fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [128]u8 = undefined;
    const len: usize = src.slice(&buf);
    bias(S, src, buf[0..len]);
    _ = decimal.Decimal.parse(buf[0..len]) catch {
        mark(.rejected);
        return;
    };
    mark(.parsed);
}

/// `BigDecimal.parse` never panics or leaks on arbitrary text.
pub fn bigParseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len: usize = src.slice(&buf);
    bias(S, src, buf[0..len]);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    _ = decimal.BigDecimal.parse(arena.allocator(), buf[0..len]) catch {
        mark(.big_rejected);
        return;
    };
    mark(.big_parsed);
}

test "fuzz driver: DECIMAL_FUZZ" {
    try fuzz_driver.run(parseHarness, .{ .prefix = "DECIMAL_FUZZ", .name = "decimal-parse" });
    try fuzz_driver.run(bigParseHarness, .{ .prefix = "DECIMAL_FUZZ", .name = "decimal-big-parse" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        parseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("decimal parse seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        bigParseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("decimal big seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
