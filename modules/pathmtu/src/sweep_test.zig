// SPDX-License-Identifier: MIT
//! No-panic sweep of the per-hop API: every public input at its extremes.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");
const root = @import("root.zig");

const Answer = struct {
    out: root.HopOutcome,
    calls: usize = 0,
    fn f(ctx: *anyopaque, _: u8, _: u16) root.HopOutcome {
        const self: *Answer = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return self.out;
    }
    fn prober(self: *Answer) root.HopProber {
        return .{ .ctx = self, .probeFn = f };
    }
};

test "hopsWith: extreme floor, ceiling, max_hops and silent counts never panic or hang (sweep PH1)" {
    var out: [255]root.Hop = undefined;
    const outcomes = [_]root.HopOutcome{
        .{ .time_exceeded = null },
        .{ .echo_reply = null },
        .{ .frag_needed = .{ .hint = std.math.maxInt(u32), .from = null } },
        .{ .frag_needed = .{ .hint = 0, .from = null } },
        .{ .frag_needed = .{ .hint = 1, .from = null } },
        .local_reject,
        .send_failed,
        .no_reply,
    };
    const bounds = [_][2]u16{ .{ 0, 1 }, .{ 0, 65535 }, .{ 65534, 65535 }, .{ 68, 69 }, .{ 1280, 9000 } };
    for (outcomes) |o| for (bounds) |b| for ([_]u8{ 0, 1, 255 }) |mh| for ([_]u8{ 0, 1, 255 }) |ms| {
        var a: Answer = .{ .out = o };
        const r = root.hopsWith(a.prober(), .{ .floor = b[0], .ceiling = b[1], .max_hops = mh, .max_silent_hops = ms }, &out) catch |e| {
            try testing.expect(e == error.NoHops and mh == 0);
            continue;
        };
        try testing.expect(r.hops.len >= 1 and r.hops.len <= 255);
        try testing.expect(r.mtu >= b[0] and r.mtu <= b[1]);
        // Work per TTL is bounded whatever the answers.
        try testing.expect(a.calls <= r.hops.len * (root.hops_max_steps + 2));
    };
}

test "hopsWith: floor above ceiling, equal, and an empty output are refusals (sweep PH2)" {
    var out: [4]root.Hop = undefined;
    var a: Answer = .{ .out = .no_reply };
    try testing.expectError(error.CeilingTooLow, root.hopsWith(a.prober(), .{ .floor = 2000, .ceiling = 1500 }, &out));
    try testing.expectError(error.CeilingTooLow, root.hopsWith(a.prober(), .{ .floor = 1500, .ceiling = 1500 }, &out));
    try testing.expectError(error.NoHops, root.hopsWith(a.prober(), .{ .floor = 68, .ceiling = 1500 }, out[0..0]));
    try testing.expectEqual(@as(usize, 0), a.calls);
}

test "probeHops: option extremes are errors or bounded results, never a panic (sweep PH3)" {
    const dest: netaddr.Ip = .{ .v4 = .{ 127, 0, 0, 1 } };
    var out: [2]root.Hop = undefined;
    try testing.expectError(error.NoHops, root.probeHops(dest, .{ .max_hops = 0 }, &out));
    try testing.expectError(error.NoHops, root.probeHops(dest, .{}, out[0..0]));
    try testing.expectError(error.CeilingTooHigh, root.probeHops(dest, .{ .ceiling_mtu = 65535 }, &out));
    try testing.expectError(error.CeilingTooLow, root.probeHops(dest, .{ .ceiling_mtu = 0 }, &out));
    // A spent deadline sends nothing: the walk ends through max_silent_hops, quickly.
    const r = root.probeHops(dest, .{ .deadline_ms = 0, .timeout_ms = 60_000, .retries = 255, .max_hops = 255, .max_silent_hops = 255 }, &out) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    try testing.expect(!r.reached);
    try testing.expectEqual(@as(usize, 2), r.hops.len);
}
