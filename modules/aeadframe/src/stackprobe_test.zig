// SPDX-License-Identifier: MIT

//! Dead-stack probe for the keyed entry points (`testkit.stackprobe`): residue
//! below each burn, and the channel key as a needle in any frame. ReleaseFast
//! only (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in
//! every mode). Both instantiations (ChaCha20-Poly1305 and std AES-256-GCM).
//!
//! `open` and the rekeys run once per measurement (`repeats = 1`): a second
//! run of the same call is a replay / a non-advancing rekey, which returns
//! before the AEAD and would measure the wrong path. The `…Into` initialisers
//! have no call to burn (a plain struct store) and are probed for needles only.

const std = @import("std");
const root = @import("root.zig");
const channel = @import("channel.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });
const P1 = sp.Probe(.{ .window = 64 * 1024, .repeats = 1 });

var key: [32]u8 = undefined;
var key2: [32]u8 = undefined;
var rec: [4096]u8 = undefined;
var pt_out: [256]u8 = undefined;
const msg: [200]u8 = @splat(0x5a);
const aad = "dead-stack probe";

fn probeChannel(comptime name: []const u8, comptime Ch: type) !void {
    const S = struct {
        var s: Ch.Sealer = undefined;
        var o: Ch.Opener = undefined;
        var peer: Ch.Sealer = undefined;
    };
    const ks = &[_][]const u8{&key};

    _ = try P.run(name ++ " Sealer.initInto", Ch.Sealer.initInto, .{ &S.s, &key, 0 }, &.{ &key, std.mem.asBytes(&S.s) }, .{ .burn = false });
    _ = try P.run(name ++ " Opener.initInto", Ch.Opener.initInto, .{ &S.o, &key, 0 }, &.{ &key, std.mem.asBytes(&S.o) }, .{ .burn = false });
    _ = try P.run(name ++ " Opener.initWindowInto", Ch.Opener.initWindowInto, .{ &S.o, &key, 0, 16 }, &.{ &key, std.mem.asBytes(&S.o) }, .{ .burn = false });

    Ch.Sealer.initInto(&S.s, &key, 0);
    _ = try P.run(name ++ " Sealer.seal", Ch.Sealer.seal, .{ &S.s, &rec, &msg, aad }, ks, .{});

    // A fresh record and a fresh opener for the single measured `open`.
    Ch.Sealer.initInto(&S.peer, &key, 0);
    const n = try S.peer.seal(&rec, &msg, aad);
    Ch.Opener.initInto(&S.o, &key, 0);
    _ = try P1.run(name ++ " Opener.open", Ch.Opener.open, .{ &S.o, &pt_out, rec[0..n], aad }, ks, .{});
    try std.testing.expectEqualSlices(u8, &msg, pt_out[0..msg.len]);

    _ = try P1.run(name ++ " Sealer.rekeyInto", Ch.Sealer.rekeyInto, .{ &S.s, &key2, 1 }, &.{ &key, &key2, std.mem.asBytes(&S.s) }, .{});
    _ = try P1.run(name ++ " Opener.rekeyInto", Ch.Opener.rekeyInto, .{ &S.o, &key2, 1 }, &.{ &key, &key2, std.mem.asBytes(&S.o) }, .{});
}

test "STACKPROBE: no channel key residue after any entry point" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aeadframe probe key", &key, .{});
    std.crypto.hash.sha2.Sha256.hash("aeadframe probe key 2", &key2, .{});
    try probeChannel("ChaCha", channel.ChaChaChannel);
    try probeChannel("AesGcm", channel.AesGcmChannel);
    _ = root;
}
