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

pub const Label = enum { rejected, accepted, kiss_of_death, originate_checked, sync_ok, sync_refused, mac_ok, mac_refused };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
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
        if (buf[3] & 1 == 0) { // a never-synchronized, near-zero-error server: passes checkSynchronization
            @memset(buf[16..24], 0);
            @memset(buf[4..6], 0);
            @memset(buf[8..10], 0);
        }
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

    // Era-modulo arithmetic and the RFC 5905 suitability checks on whatever
    // was accepted: never a trap, and a refusal is an error value.
    const smp: sntp.Sample = .{ .originate = reply.originate, .receive = reply.receive, .transmit = reply.transmit, .destination = reply.reference };
    _ = smp.offsetNanos();
    _ = smp.roundtripDelayNanos();
    _ = smp.minErrorNanos();
    _ = reply.transmit.toUnixNanosInferEra();
    _ = reply.transmit.toUnixNanosNear(@as(i128, reply.root_delay) << 90);
    if (sntp.checkSynchronization(reply)) |_| mark(.sync_ok) else |_| mark(.sync_refused);

    // The authenticator trailer under a key and algorithm the draw picks:
    // a signed copy must verify, one flipped bit must not, and arbitrary
    // bytes as a trailer get a verdict, never a trap.
    var key: [32]u8 = @splat(0);
    _ = src.slice(&key);
    const alg: sntp.MacAlgorithm = @fromBackingInt(@intCast(src.valueRangeAtMost(u8, 0, 5)));
    const klen: usize = switch (alg) {
        .aes128_cmac => 16,
        .aes256_cmac => 32,
        else => 4 + key[0] % 29,
    };
    const auth: sntp.Auth = .{ .algorithm = alg, .key_id = std.mem.readInt(u32, key[1..5], .big) | 1, .key = key[0..klen] };
    const ver: u3 = @intCast(src.valueRangeAtMost(u8, 3, 4));
    var wire: [sntp.packet_len + sntp.Auth.max_trailer_len]u8 = undefined;
    const n = try auth.sign(ver, &reply.encode(), &wire);
    try auth.verify(ver, wire[0..n]);
    mark(.mac_ok);
    const flip = src.valueRangeAtMost(u8, 0, 255);
    wire[flip % n] ^= @as(u8, 1) << @intCast(flip % 8);
    if (auth.verify(ver, wire[0..n])) |_| return error.FlippedBitAccepted else |_| mark(.mac_refused);
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
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
