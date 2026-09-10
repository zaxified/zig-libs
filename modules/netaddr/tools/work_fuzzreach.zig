const std = @import("std");
const na = @import("netaddr.zig");

var seen_len: [128]usize = @splat(0);
var rounds: usize = 0;
var nonempty: usize = 0;
var accepted: usize = 0;

fn fuzzParseIp(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    rounds += 1;
    if (len < seen_len.len) seen_len[len] += 1;
    if (len != 0) nonempty += 1;
    if (na.parseIp(buf[0..len]) != null) accepted += 1;
}

test "fuzz parseIp never panics (INSTRUMENTED)" {
    try std.testing.fuzz({}, fuzzParseIp, .{});
    var distinct: usize = 0;
    for (seen_len) |c| {
        if (c != 0) distinct += 1;
    }
    std.debug.print(
        "\n[REACH] rounds={d} nonempty_len={d} accepted_as_ip={d} distinct_lengths={d} len0={d}\n",
        .{ rounds, nonempty, accepted, distinct, seen_len[0] },
    );
}
