// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `expandMessageXmd`: hash-to-
//! curve feeds it secret messages (OPAQUE passwords, VOPRF inputs), so neither
//! the message tail its first hasher buffers nor `b_0` may stay on the stack.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). No burn: the function wipes what it holds,
//! so the probe checks the needles (the message, `b_0`) only.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const xmd = @import("xmd.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const P = sp.Probe(.{ .window = 64 * 1024 });
const dst = "QUUX-V01-CS02-with-expander-SHA256-128";

var msg: [40]u8 = undefined;
var b0: [32]u8 = undefined;
/// `b_0` as the first hasher's state words hold it after `final` (native-endian u32).
var b0_words: [32]u8 = undefined;
var out: [128]u8 = undefined;

fn expandWrap(o: *[128]u8, m: *const [40]u8) void {
    o.* = xmd.expandMessageXmd(Sha256, 128, &.{m}, dst);
}

test "STACKPROBE: expandMessageXmd leaves neither the message tail nor b_0 on the dead stack" {
    try sp.skipUnlessOptimized();
    Sha256.hash("sha2 xmd probe message", msg[0..32], .{});
    Sha256.hash("sha2 xmd probe message 2", out[0..32], .{});
    @memcpy(msg[32..40], out[0..8]);
    // b_0 = H(Z_pad || msg || I2OSP(128, 2) || 0x00 || DST_prime), computed here as the needle.
    var h = Sha256.init(.{});
    h.update(&@as([64]u8, @splat(0)));
    h.update(&msg);
    h.update(&[_]u8{ 0, 128, 0 });
    h.update(dst);
    h.update(&[_]u8{dst.len});
    h.final(&b0);
    for (0..8) |w| std.mem.writeInt(u32, b0_words[4 * w ..][0..4], std.mem.readInt(u32, b0[4 * w ..][0..4], .big), .native);
    _ = try P.run("expandMessageXmd(Sha256, 128)", expandWrap, .{ &out, &msg }, &.{ &msg, &b0, &b0_words }, .{ .burn = false, .residue = false });
}
