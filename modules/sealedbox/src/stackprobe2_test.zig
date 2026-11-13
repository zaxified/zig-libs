// SPDX-License-Identifier: MIT

//! `testkit.stackprobe` probe of the burned entry points `seal`, `open`,
//! `openAlloc`, `publicFromSecret` and `keyPairFromSecretKey`: residue below each
//! burn, and the recipient secret key as a needle in any frame. `seal` draws its
//! ephemeral key from a fixed-output `io` here, so that key, the X25519 output
//! and the box key are needles too. A long message walks the multi-block cipher
//! path as well. The older
//! `stackprobe_test.zig` (secret-key codecs, `wipe`) stays as it was.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). `open` is per message (TIGHT burn).

const std = @import("std");
const sb = @import("root.zig");
const sp = @import("testkit").stackprobe;

const secretbox = @import("xsalsa20poly1305.zig");
const X25519 = std.crypto.dh.X25519;

const P = sp.Probe(.{ .window = 64 * 1024 });

var ephemeral: [sb.secret_length]u8 = undefined;
var fixed_vtable: std.Io.VTable = undefined;

fn fixedRandom(_: ?*anyopaque, buffer: []u8) void {
    for (buffer, 0..) |*b, i| b.* = ephemeral[i % ephemeral.len];
}

var kp: sb.KeyPair = undefined;
var kp_out: sb.KeyPair = undefined;
var pk_out: [sb.public_length]u8 = undefined;
const msg = "dead-stack probe message";
var sealed: [sb.sealedLen(msg.len)]u8 = undefined;
var plain: [msg.len]u8 = undefined;
const long_len = 4096;
var long_msg: [long_len]u8 = @splat(0x5a);
var long_sealed: [sb.sealedLen(long_len)]u8 = undefined;
var long_plain: [long_len]u8 = undefined;

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

    std.crypto.hash.sha2.Sha256.hash("sealedbox dead-stack probe ephemeral", &ephemeral, .{});
    fixed_vtable = io.vtable.*;
    fixed_vtable.random = fixedRandom;
    const fixed_io: std.Io = .{ .userdata = io.userdata, .vtable = &fixed_vtable };
    const dh = try X25519.scalarmult(ephemeral, kp.public_key);
    const box_key = secretbox.hsalsa20(@splat(0), dh);
    const seal_secrets = &[_][]const u8{ &ephemeral, &dh, &box_key };
    // The residue rule looks only below the longest zero run, and ct25519's inner
    // 16 KiB burn is such a run: with no burn in `seal` the probe stays green while
    // ~2.1 KiB of `seal`'s own frames above it go unwiped (measured 2026-11-02:
    // the run starts 2095..2111 B deep without the burn, 222 B with it). So pin
    // where the run starts.
    const short = try P.run("seal", sb.seal, .{ fixed_io, &sealed, msg, kp.public_key }, seal_secrets, .{});
    try std.testing.expect(short.burn_top < 1024);
    const long = try P.run("seal long", sb.seal, .{ fixed_io, &long_sealed, &long_msg, kp.public_key }, seal_secrets, .{});
    try std.testing.expect(long.burn_top < 1024);
    // Same pin for `open`: its body (box key, subkey, keystream block, tag) runs above
    // ct25519's inner burn, so with no burn in `open` the probe stays green while
    // those frames go unwiped (mutation run 2026-11-13: bypassing `open`'s burn and
    // every wipe in its body survived without this).
    const open_long = try P.run("open long", sb.open, .{ &long_plain, &long_sealed, &kp }, ks, .{});
    try std.testing.expect(open_long.burn_top < 1024);
    try std.testing.expectEqualSlices(u8, &long_msg, &long_plain);
    const open_short = try P.run("open", sb.open, .{ &plain, &sealed, &kp }, ks, .{});
    try std.testing.expect(open_short.burn_top < 1024);
    try std.testing.expectEqualStrings(msg, &plain);
    _ = try P.run("openAlloc", openAllocFree, .{ std.heap.page_allocator, &sealed, &kp }, ks, .{});
    _ = try P.run("publicFromSecret", publicFromSecretStore, .{ sk, &pk_out }, ks, .{});
    try std.testing.expectEqualSlices(u8, &kp.public_key, &pk_out);
    _ = try P.run("keyPairFromSecretKey", sb.keyPairFromSecretKey, .{ &kp_out, sk }, &.{ sk, std.mem.asBytes(&kp_out) }, .{});
    try std.testing.expectEqualSlices(u8, &kp.public_key, &kp_out.public_key);
}
