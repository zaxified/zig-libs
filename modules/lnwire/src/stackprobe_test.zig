// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the two codecs that carry a
//! per-commitment secret: residue below each burn. No needles: the decoded
//! message (and the by-value `msg` argument) legitimately holds the secret in
//! the caller's frame, which is the documented caller-owned contract (see the
//! `secret-api-ok` markers in `bolt2.zig`); what the burn must clear is the
//! codec's own frames. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const bolt2 = @import("bolt2.zig");
const sp = @import("testkit").stackprobe;

// Window above the deepest burn (2 KiB, per-message codec).
const P = sp.Probe(.{ .window = 16 * 1024 });

var rev_wire: [2 + 32 + 32 + 33]u8 = undefined;
var re_wire: [2 + 113]u8 = undefined;

fn fill(comptime n: usize, seed: u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return out;
}

test "STACKPROBE: revoke_and_ack / channel_reestablish codecs leave no residue below their burn" {
    try sp.skipUnlessOptimized();
    const a = std.heap.page_allocator;

    const rev: bolt2.RevokeAndAck = .{
        .channel_id = fill(32, 1),
        .per_commitment_secret = fill(32, 0x40),
        .next_per_commitment_point = fill(33, 3),
    };
    const rev_bytes = try bolt2.serializeRevokeAndAck(a, rev);
    @memcpy(&rev_wire, rev_bytes);
    a.free(rev_bytes);
    _ = try P.run("decodeRevokeAndAck", bolt2.decodeRevokeAndAck, .{@as([]const u8, &rev_wire)}, &.{}, .{});
    _ = try P.run("serializeRevokeAndAck", bolt2.serializeRevokeAndAck, .{ a, rev }, &.{}, .{});

    const re: bolt2.ChannelReestablish = .{
        .channel_id = fill(32, 1),
        .next_commitment_number = 42,
        .next_revocation_number = 41,
        .your_last_per_commitment_secret = fill(32, 0x60),
        .my_current_per_commitment_point = fill(33, 3),
    };
    const re_bytes = try bolt2.serializeChannelReestablish(a, re);
    @memcpy(&re_wire, re_bytes);
    a.free(re_bytes);
    _ = try P.run("decodeChannelReestablish", bolt2.decodeChannelReestablish, .{ a, @as([]const u8, &re_wire) }, &.{}, .{});
    _ = try P.run("serializeChannelReestablish", bolt2.serializeChannelReestablish, .{ a, re }, &.{}, .{});
}
