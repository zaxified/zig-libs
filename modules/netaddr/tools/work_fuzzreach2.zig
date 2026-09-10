const std = @import("std");
const na = @import("netaddr.zig");

var rounds: usize = 0;
var nonempty: usize = 0;
var accepted: usize = 0;
var lens: [200]usize = @splat(0);

// EXACT copy of the shipped harness body, plus counters.
fn shipped(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    rounds += 1;
    lens[@min(len, lens.len - 1)] += 1;
    if (len != 0) nonempty += 1;
    if (na.parseIp(buf[0..len]) != null) accepted += 1;
}

var r2_rounds: usize = 0;
var r2_nonempty: usize = 0;
var r2_accepted: usize = 0;

// The `slice`-based shape, for comparison.
fn fixed(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    const len = smith.slice(&buf);
    r2_rounds += 1;
    if (len != 0) r2_nonempty += 1;
    if (na.parseIp(buf[0..len]) != null) r2_accepted += 1;
}

const corpus = [_][]const u8{
    "2001:db8::1",
    "::ffff:192.0.2.1",
    "1:2:3:4:5:6:7:8",
    "192.168.0.1",
    "fe80::1%eth0",
    "::",
    "1::2::3",
    "0001:0002::",
    "010.0.0.1",
    "64:ff9b::192.0.2.33",
    "1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16:17:18:19:20:21:22:23:24:25:26:27:28",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

test "SHIPPED harness, WITH a hand-written corpus of real address literals" {
    try std.testing.fuzz({}, shipped, .{ .corpus = &corpus });
    std.debug.print(
        "\n[SHIPPED+corpus] rounds={d} nonempty={d} accepted_as_ip={d} len0={d}\n",
        .{ rounds, nonempty, accepted, lens[0] },
    );
}

test "slice()-based harness, same corpus" {
    try std.testing.fuzz({}, fixed, .{ .corpus = &corpus });
    std.debug.print(
        "[slice()+corpus] rounds={d} nonempty={d} accepted_as_ip={d}\n",
        .{ r2_rounds, r2_nonempty, r2_accepted },
    );
}
