// SPDX-License-Identifier: MIT

//! `testkit.stackprobe` probe of the burned entry points `open`, `openAlloc`,
//! `publicFromSecret` and `keyPairFromSecretKey`: residue below each burn, and
//! the recipient secret key as a needle in any frame. The older
//! `stackprobe_test.zig` (secret-key codecs, `wipe`) stays as it was.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). `open` is per message (TIGHT burn).

const std = @import("std");
const sb = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var kp: sb.KeyPair = undefined;
var kp_out: sb.KeyPair = undefined;
var pk_out: [sb.public_length]u8 = undefined;
const msg = "dead-stack probe message";
var sealed: [sb.sealedLen(msg.len)]u8 = undefined;
var plain: [msg.len]u8 = undefined;

fn openAllocFree(gpa: std.mem.Allocator, s: []const u8, k: *const sb.KeyPair) !void {
    const out = try sb.openAlloc(gpa, s, k);
    gpa.free(out);
}

fn publicFromSecretStore(sk: *const [sb.secret_length]u8, out: *[sb.public_length]u8) !void {
    out.* = try sb.publicFromSecret(sk);
}

test "STACKPROBE: no recipient secret-key residue after open or the key rebuild" {
    try sp.skipUnlessOptimized();
    const io = std.testing.io;
    kp = sb.KeyPair.generate(io);
    try sb.seal(io, &sealed, msg, kp.public_key);
    const sk = &kp.secret_key;
    const ks = &[_][]const u8{sk};

    _ = try P.run("open", sb.open, .{ &plain, &sealed, &kp }, ks, .{});
    try std.testing.expectEqualStrings(msg, &plain);
    _ = try P.run("openAlloc", openAllocFree, .{ std.heap.page_allocator, &sealed, &kp }, ks, .{});
    _ = try P.run("publicFromSecret", publicFromSecretStore, .{ sk, &pk_out }, ks, .{});
    try std.testing.expectEqualSlices(u8, &kp.public_key, &pk_out);
    _ = try P.run("keyPairFromSecretKey", sb.keyPairFromSecretKey, .{ &kp_out, sk }, &.{ sk, std.mem.asBytes(&kp_out) }, .{});
    try std.testing.expectEqualSlices(u8, &kp.public_key, &kp_out.public_key);
}
