// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the `io` key generators
//! `stackprobe_test.zig` does not call: `KeyPair.generateInto(out, io)` and
//! the by-value `KeyPair.generate(io)`. They draw the seed into their own
//! frame, above the burn of `generateDeterministicInto`, so they run on a
//! test double of `std.Io` whose `randomSecure` is a fixed SHA-512 stream:
//! the drawn seed is known and is a needle (with the derived secret key for
//! the pointer form; a by-value result lands in the probe's call frame by
//! shape). ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const E = root.EcdsaP384Sha384;
const P = sp.Probe(.{ .window = 64 * 1024 });

fn detFill(buf: []u8) void {
    var off: usize = 0;
    var ctr: u8 = 0;
    while (off < buf.len) : (ctr += 1) {
        var h: [64]u8 = undefined;
        var s = std.crypto.hash.sha2.Sha512.init(.{});
        s.update("p384 stackprobe2 rng");
        s.update(&[1]u8{ctr});
        s.final(&h);
        const n = @min(h.len, buf.len - off);
        @memcpy(buf[off..][0..n], h[0..n]);
        off += n;
    }
}

fn detRandomSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    detFill(buf);
}

var det_vtable: std.Io.VTable = undefined;
var det_io: std.Io = undefined;
var drawn_seed: [E.KeyPair.seed_length]u8 = undefined;
var kp: E.KeyPair = undefined;

test "STACKPROBE: generateInto(io) and generate(io) leave no drawn seed or key on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    det_vtable = base.vtable.*;
    det_vtable.randomSecure = detRandomSecure;
    det_io = .{ .userdata = base.userdata, .vtable = &det_vtable };
    detFill(&drawn_seed);

    _ = try P.run("KeyPair.generateInto(io)", E.KeyPair.generateInto, .{ &kp, det_io }, &.{ &drawn_seed, &kp.secret_key.bytes }, .{});
    var expect: E.KeyPair = undefined;
    try E.KeyPair.generateDeterministicInto(&expect, &drawn_seed);
    try std.testing.expectEqualSlices(u8, &expect.secret_key.bytes, &kp.secret_key.bytes);
    _ = try P.run("KeyPair.generate(io)", E.KeyPair.generate, .{det_io}, &.{&drawn_seed}, .{});
}
