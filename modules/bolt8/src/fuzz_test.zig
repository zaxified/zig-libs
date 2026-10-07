// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over bolt8's five existing `testing.fuzz`
//! harnesses (added 2026-10-07): the three act decoders in `act.zig` and the
//! two transport decoders in `transport.zig`. The harness bodies stay where
//! they were, now generic over their source of choices
//! (`fn(comptime S, *S, gpa)`); this file adds the cursor adapter
//! `testing.fuzz` feeds them through, the driver tests, and a 500-seed
//! in-suite run with a reach check.
//!
//! Driver: `BOLT8_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const act = @import("act.zig");
const transport = @import("transport.zig");

pub const Label = enum {
    act1_decoded,
    act1_rejected,
    act2_decoded,
    act2_rejected,
    act3_decoded,
    act3_rejected,
    length_accepted,
    length_refused,
    message_accepted,
    message_refused,
};
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

pub fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input
/// (a ranged `Smith` draw first collapses every seed to one, `check-fuzz-reach`).
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
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

fn driven(comptime harness: anytype, comptime name: []const u8) !void {
    try fuzz_driver.run(harness, .{ .prefix = "BOLT8_FUZZ", .name = "bolt8-" ++ name });
}

test "fuzz driver: BOLT8_FUZZ (act1)" {
    try driven(act.act1Harness, "act1");
}
test "fuzz driver: BOLT8_FUZZ (act2)" {
    try driven(act.act2Harness, "act2");
}
test "fuzz driver: BOLT8_FUZZ (act3)" {
    try driven(act.act3Harness, "act3");
}
test "fuzz driver: BOLT8_FUZZ (recv-length)" {
    try driven(transport.recvLengthHarness, "recv-length");
}
test "fuzz driver: BOLT8_FUZZ (recv-message)" {
    try driven(transport.recvMessageHarness, "recv-message");
}

test "fuzz harnesses: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    const harnesses = .{ act.act1Harness, act.act2Harness, act.act3Harness, transport.recvLengthHarness, transport.recvMessageHarness };
    inline for (harnesses, 0..) |h, which| {
        for (0..500) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("bolt8 harness {d} seed {d}: {t}\n", .{ which, seed, err });
                return err;
            };
        }
    }
    // Reach before verdict: every outcome the harnesses judge was seen.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
