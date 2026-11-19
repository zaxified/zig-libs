// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned
//! 2026-10-09: `KeyPair.generateInto` and `KeyPair.signerInto` (the rest of the
//! module is in `stackprobe_test.zig`). One-shot calls: `sign_burn`.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const p256 = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Ecdsa = p256.EcdsaP256Sha256;

const P = sp.Probe(.{ .window = 32 * 1024 });

var seed: [32]u8 = undefined;
var kp: Ecdsa.KeyPair = undefined;
var kp2: Ecdsa.KeyPair = undefined;
var signer_out: Ecdsa.Signer = undefined;

test "STACKPROBE: P-256 key generation and signer construction leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("p256 probe2 seed", &seed, .{});
    try Ecdsa.KeyPair.generateDeterministicInto(&kp, &seed);
    _ = try P.run("KeyPair.generateInto", Ecdsa.KeyPair.generateInto, .{ &kp2, std.testing.io }, &.{std.mem.asBytes(&kp2.secret_key)}, .{});
    // `signer` returns the Signer — secret key inside — by value, so its own
    // result slot holds the key (18 windows, 2026-10-09); `signerInto` does not.
    _ = try P.run("KeyPair.signerInto", Ecdsa.KeyPair.signerInto, .{ &signer_out, &kp, null }, &.{std.mem.asBytes(&kp.secret_key)}, .{});
}

// Stack budget (README "Stack use"): the figures the README quotes are pinned here so the
// document cannot drift from the code. Runs in any build mode (it paints a stack window and
// reads how deep each call dirtied it, so Debug's `undefined` fill does not matter).
// Measured 2026-11-19, deepest call of the set, bytes including the burn itself:
//   Debug (modtest default)  ecdhInto 23 488, sign 21 488, verify 19 600, generate 18 784, mul 16 880
//   ReleaseFast              sign 17 928, generate 17 384, ecdhInto 16 936, mul 16 616, verify 9 208
const probe_window: usize = 48 * 1024;
const depth_bound: usize = 32 * 1024; // README: "needs about 24 KiB at most"; the test fails past 32 KiB
var paint_lo: usize = 0;
var paint_hi: usize = 0;

noinline fn paintStack() void {
    var buf: [probe_window]u8 = undefined;
    @memset(&buf, 0x55);
    paint_lo = @intFromPtr(&buf);
    paint_hi = paint_lo + probe_window;
    std.mem.doNotOptimizeAway(&buf);
}

/// Bytes below the painter's frame top that the last call(s) touched.
noinline fn dirtyDepth() usize {
    const p: [*]const volatile u8 = @ptrFromInt(paint_lo);
    var i: usize = 0;
    while (i < probe_window and p[i] == 0x55) i += 1;
    return paint_hi - (paint_lo + i);
}

const P256 = p256.P256;
var s_sk: [32]u8 = undefined;
var s_pt: P256 = undefined;
var s_sec1: [65]u8 = undefined;
var s_out: [32]u8 = undefined;
var s_kp: Ecdsa.KeyPair = undefined;
var s_sig: Ecdsa.Signature = undefined;
var s_ok: bool = true;

fn cMul() void {
    s_pt = P256.basePoint.mul(s_sk, .big) catch return fail();
}
fn cMulPublic() void {
    s_pt = P256.basePoint.mulPublic(s_sk, .big) catch return fail();
}
fn cDouble() void {
    s_pt = P256.basePoint.mulDoubleBasePublic(s_sk, s_pt, s_sk, .big) catch return fail();
}
fn cEcdh() void {
    p256.ecdhInto(&s_out, &s_sk, &s_sec1) catch return fail();
}
fn cSign() void {
    s_sig = s_kp.sign("m", null) catch return fail();
}
fn cVerify() void {
    s_sig.verify("m", s_kp.public_key) catch return fail();
}
fn cGen() void {
    Ecdsa.KeyPair.generateDeterministicInto(&s_kp, &s_sk) catch return fail();
}
fn fail() void {
    s_ok = false;
}

const StackJob = struct {
    max_depth: usize = 0,
    fn run(j: *StackJob) void {
        std.crypto.hash.sha2.Sha256.hash("p256 stack budget seed", &s_sk, .{});
        s_kp = Ecdsa.KeyPair.generateDeterministic(s_sk) catch return fail();
        s_pt = P256.basePoint.mul(s_sk, .big) catch return fail();
        s_sec1 = s_pt.toUncompressedSec1();
        s_sig = s_kp.sign("m", null) catch return fail();
        const calls = [_]*const fn () void{ cMul, cMulPublic, cDouble, cEcdh, cSign, cVerify, cGen };
        for (calls) |f| {
            paintStack();
            f();
            j.max_depth = @max(j.max_depth, dirtyDepth());
        }
    }
};

test "stack use: burn sizes, and every entry point runs in a 64 KiB stack within the documented depth" {
    const burn = @import("burn.zig");
    try std.testing.expectEqual(@as(usize, 16 * 1024), burn.mul_burn);
    try std.testing.expectEqual(@as(usize, 4 * 1024), burn.affine_burn);
    try std.testing.expectEqual(@as(usize, 8 * 1024), burn.sign_burn);
    s_ok = true;
    var job: StackJob = .{};
    const th = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, StackJob.run, .{&job});
    th.join();
    try std.testing.expect(s_ok);
    // Not a vacuous probe: the burns alone dirty 16 KiB.
    try std.testing.expect(job.max_depth >= burn.mul_burn);
    try std.testing.expect(job.max_depth <= depth_bound);
}
