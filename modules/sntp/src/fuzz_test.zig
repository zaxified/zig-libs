// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over sntp's `decodeResponse` harness (added
//! 2026-10-09). The harness body is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`). The first draw is one `slice` of bytes (the
//! datagram, exactly as `std.testing.fuzz` seeds it); a second, ranged draw
//! picks a SHAPE: 0 = the bytes as they are, 1-3 = patch them into a datagram
//! that passes the header checks (mode, version, stratum, leap, timestamps) or
//! into a Kiss-o'-Death, so random bytes reach the accepted paths a raw random
//! 0-64 octets almost never would. Past the end of a corpus seed the ranged
//! draw answers 0, so a seed stays a raw datagram.
//!
//! Driver: `SNTP_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const sntp = @import("root.zig");

pub const Label = enum { rejected, accepted, kiss_of_death, originate_checked };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and the
/// harness reads every choice from them. Past the end a ranged draw answers its
/// minimum (shape 0 = the raw datagram).
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

pub fn decodeResponseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [64]u8 = @splat(0);
    var len: usize = src.slice(&buf);
    const shape = src.valueRangeAtMost(u8, 0, 3);
    if (shape != 0) {
        len = 48;
        // Mode 4 (server), version 1-4; the leap bits stay as drawn.
        buf[0] = (buf[0] & 0xC0) | ((1 + (buf[0] >> 3) % 4) << 3) | 4;
        buf[39] |= 1; // receive timestamp non-zero
        buf[47] |= 1; // transmit timestamp non-zero
        switch (shape) {
            1 => { // accepted, if the draw left it so: no leap alarm, stratum 1..15
                buf[0] &= 0x3F;
                buf[1] = 1 + buf[1] % 15;
            },
            2 => {}, // everything else as drawn: leap, stratum 0 / 16+
            else => { // stratum 0 with an ASCII kiss code in the reference id
                buf[1] = 0;
                const codes = [_]*const [4]u8{ "RATE", "DENY", "RSTR", "ZZZZ" };
                @memcpy(buf[12..16], codes[buf[2] % codes.len]);
            },
        }
    }

    var kod: sntp.KissOfDeath = undefined;
    const reply = sntp.decodeResponse(buf[0..len], &kod) catch |err| {
        if (err == error.KissOfDeath) mark(.kiss_of_death) else mark(.rejected);
        return;
    };
    mark(.accepted);
    try sntp.verifyOriginate(reply, reply.originate);
    mark(.originate_checked);
}

test "fuzz driver: SNTP_FUZZ (decodeResponse)" {
    try fuzz_driver.run(decodeResponseHarness, .{ .prefix = "SNTP_FUZZ", .name = "sntp-decodeResponse" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeResponseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("sntp seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
