// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the public building blocks
//! `core.deriveX` and `core.deriveRandomizer` burned (the tree and
//! signing entry points are in `stackprobe_test.zig`). Per-chain calls on the
//! signing path: tight burn (`derive_burn`). ReleaseFast only
//! (`skipUnlessOptimized`).

const std = @import("std");
const core = @import("core.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 16 * 1024 });

var id: [16]u8 = undefined;
var seed: [32]u8 = undefined;
var x: [32]u8 = undefined;

test "STACKPROBE: deriveX and deriveRandomizer leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("lms probe2 seed", &seed, .{});
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("lms probe2 id", &h, .{});
    @memcpy(&id, h[0..16]);
    _ = try P.run("core.deriveX", core.deriveX, .{ &x, &id, @as(u32, 3), @as(u16, 5), &seed }, &.{ &seed, &x }, .{});
    const c = try P.run("core.deriveRandomizer", core.deriveRandomizer, .{ &id, @as(u32, 3), &seed }, &.{&seed}, .{});
    _ = c;
}

/// The verify-only stack bound SPEC § Verification-only use documents.
const verify_stack_bound = 4 * 1024;

test "STACKPROBE: hssVerify's stack use stays under the documented bound (verify-only footprint)" {
    try sp.skipUnlessOptimized();
    const kat = @import("kat_vectors.zig");
    const Vec = struct {
        const tc1_pub = kat.bytes(kat.tc1_pub);
        const tc1_msg = kat.bytes(kat.tc1_msg);
        const tc1_sig = kat.bytes(kat.tc1_sig);
        const tc2_pub = kat.bytes(kat.tc2_pub);
        const tc2_msg = kat.bytes(kat.tc2_msg);
        const tc2_sig = kat.bytes(kat.tc2_sig);
    };
    const VP = sp.Probe(.{ .window = 32 * 1024 });
    // Public inputs only: no needles, no burn expected; what is measured is
    // how deep the call reaches.
    const r1 = try VP.run("core.hssVerify (RFC 8554 F.1)", core.hssVerify, .{ &Vec.tc1_pub, &Vec.tc1_msg, &Vec.tc1_sig }, &.{}, .{ .burn = false, .residue = false });
    const r2 = try VP.run("core.hssVerify (RFC 8554 F.2)", core.hssVerify, .{ &Vec.tc2_pub, &Vec.tc2_msg, &Vec.tc2_sig }, &.{}, .{ .burn = false, .residue = false });
    const depth = @max(r1.dirty_depth, r2.dirty_depth);
    if (depth == 0 or depth > verify_stack_bound) {
        std.debug.print("hssVerify reached {d} B of stack (bound {d} B)\n", .{ depth, verify_stack_bound });
        return error.VerifyStackBound;
    }
}
