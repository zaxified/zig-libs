// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over stun's `decode` + accessors harness (added
//! 2026-10-09). The harness body is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`). The first draw is one `slice` of bytes (the
//! datagram, as `std.testing.fuzz` seeds it); a second, ranged draw picks a
//! SHAPE: 0 = the bytes as they are, 1-3 = patch them into a message with a
//! valid header (type bits, 4-aligned length, magic cookie) and, for 2 / 3, an
//! XOR-MAPPED-ADDRESS / ERROR-CODE attribute first, so random bytes reach the
//! walk and the accessors. Past the end of a corpus seed the ranged draw
//! answers 0, so a seed stays a raw datagram.
//!
//! Driver: `STUN_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const stun = @import("root.zig");

pub const Label = enum { rejected, decoded, attributes_walked, mapped_address, error_code };
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

fn putAttr(packet: []u8, at: usize, typ: u16, value_len: u16) void {
    std.mem.writeInt(u16, packet[at..][0..2], typ, .big);
    std.mem.writeInt(u16, packet[at + 2 ..][0..2], value_len, .big);
}

pub fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var packet: [1024]u8 = @splat(0);
    var len: usize = src.slice(&packet);
    const shape = src.valueRangeAtMost(u8, 0, 3);
    if (shape != 0) {
        // Message length: the drawn bytes, rounded to 4, at least the header
        // (and room for the attribute a shape asks for).
        const want: usize = switch (shape) {
            2 => 20 + 4 + 20, // XOR-MAPPED-ADDRESS, room for an IPv6 value
            3 => 20 + 4 + 8, // ERROR-CODE: 4 octets of class/number + reason
            else => 20 + (len -| 20) / 4 * 4,
        };
        len = @max(want, 20);
        packet[0] &= 0x3F;
        std.mem.writeInt(u16, packet[2..4], @intCast(len - 20), .big);
        std.mem.writeInt(u32, packet[4..8], 0x2112A442, .big);
        switch (shape) {
            2 => {
                const v6 = packet[21] & 1 == 1;
                putAttr(&packet, 20, 0x0020, if (v6) 20 else 8);
                packet[24] = 0;
                packet[25] = if (v6) 2 else 1;
                std.mem.writeInt(u16, packet[2..4], if (v6) 24 else 12, .big);
                len = if (v6) 44 else 32;
            },
            3 => {
                putAttr(&packet, 20, 0x0009, 8);
                packet[24] = 0;
                packet[25] = 0;
                packet[26] = 3 + packet[26] % 3; // class 3..5
            },
            else => {},
        }
    }

    const msg = stun.decode(packet[0..len]) catch {
        mark(.rejected);
        return;
    };
    mark(.decoded);
    // A decoded message must survive every accessor, the attribute walk and
    // both verifiers; decode borrows the input, so nothing to free.
    if (msg.xorMappedAddress()) |o| {
        if (o != null) mark(.mapped_address);
    } else |_| {}
    _ = msg.plainMappedAddress() catch {};
    _ = msg.mappedAddress() catch {};
    if (msg.errorCode()) |o| {
        if (o != null) mark(.error_code);
    } else |_| {}
    _ = msg.verifyFingerprint();
    _ = msg.verifyMessageIntegrity("key");
    var it = msg.attributes();
    var walked = false;
    while (it.next()) |_| walked = true;
    if (walked) mark(.attributes_walked);
}

test "fuzz driver: STUN_FUZZ (decode)" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "STUN_FUZZ", .name = "stun-decode" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("stun seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
