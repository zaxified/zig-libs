// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `age.PayloadStream.sealChunk` /
//! `openChunk`, the streaming payload AEAD the older probe does not call on
//! its own. They carry no burn (chachapoly's AEAD burns below them), so the
//! needle is the check: the stream key, which they hand to the AEAD.
//! ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const age = @import("age.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var st: age.PayloadStream = undefined;
var pt: [100]u8 = undefined;
var sealed: [100 + age.tag_bytes]u8 = undefined;
var back: [100]u8 = undefined;

fn sealW(o: []u8, p: []const u8) void {
    st.counter = 0;
    st.finished = false;
    st.sealChunk(o, p, true);
}
fn openW(o: []u8, s: []const u8) !void {
    st.counter = 0;
    st.finished = false;
    return st.openChunk(o, s, true);
}

test "STACKPROBE: PayloadStream.sealChunk / openChunk leave no stream key on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("tlock probe2 stream key", &key, .{});
    for (&pt, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    age.PayloadStream.init(&st, &key);
    defer st.wipe();
    const no_burn: sp.Expect = .{ .burn = false };
    _ = try P.run("PayloadStream.sealChunk", sealW, .{ @as([]u8, &sealed), @as([]const u8, &pt) }, &.{&key}, no_burn);
    _ = try P.run("PayloadStream.openChunk", openW, .{ @as([]u8, &back), @as([]const u8, &sealed) }, &.{&key}, no_burn);
    try std.testing.expectEqualSlices(u8, &pt, &back);
}
