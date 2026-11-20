// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the Ed448 key-generation entry
//! points added 2026-10-09: `KeyPair.createInto`, `KeyPair.generateInto` (the
//! std-shaped by-value `create` / `generate` call these), and for the burn
//! sites no other probe calls directly: `Point.mul`, `Point.mulBasePoint`,
//! `x448.KeyPair.fromEd448` and the seed wipe of `x448.KeyPair.generate`.
//! One-shot calls, so a generous burn (`sign_burn`). ReleaseFast only
//! (`skipUnlessOptimized`).

const std = @import("std");
const ed = @import("ed448.zig");
const x448 = @import("x448.zig");
const scalar = @import("scalar.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 96 * 1024 });

var seed: [57]u8 = undefined;
var kp: ed.KeyPair = undefined;

test "STACKPROBE: Ed448 key generation leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ed448 probe2 seed", seed[0..32], .{});
    var tail: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ed448 probe2 seed tail", &tail, .{});
    @memcpy(seed[32..], tail[0..25]);
    _ = try P.run("KeyPair.createInto", ed.KeyPair.createInto, .{ &kp, &seed }, &.{ &seed, std.mem.asBytes(&kp.secret_key) }, .{});
    _ = try P.run("KeyPair.generateInto", ed.KeyPair.generateInto, .{ &kp, std.testing.io }, &.{std.mem.asBytes(&kp.secret_key)}, .{});
}

var mul_scalar: scalar.CompressedScalar = undefined;
var mul_sink: ed.Point = undefined;

noinline fn mulSink(p: ed.Point, s: scalar.CompressedScalar) void {
    mul_sink = ed.Point.mul(p, s);
}

noinline fn mulBaseSink(s: scalar.CompressedScalar) void {
    mul_sink = ed.Point.mulBasePoint(s);
}

/// `mul` / `mulBasePoint` take the scalar BY VALUE: the copy lives in the
/// caller's argument area, above the burn (known gap, see SPEC Limits). The
/// needle-free probes below check what the module itself controls: a burn
/// exists and no non-paint byte lies below it. The `known gap` tests pin the
/// by-value copy with needles: they expect the hit and go red when the API
/// takes the scalar by pointer (then delete them and pass the scalar as a
/// needle in the first two).
const no_needles: []const []const u8 = &.{};

fn initMulScalar() void {
    var digest: [114]u8 = undefined;
    std.crypto.hash.sha3.Shake256.hash("ed448 probe2 point scalar", &digest, .{});
    mul_scalar = scalar.reduceWide(digest);
}

test "STACKPROBE: Point.mul burns its body (no residue below the burn)" {
    try sp.skipUnlessOptimized();
    initMulScalar();
    _ = try P.run("Point.mul", mulSink, .{ ed.Point.basePoint.dbl(), mul_scalar }, no_needles, .{});
}

test "STACKPROBE: Point.mulBasePoint burns its body (no residue below the burn)" {
    try sp.skipUnlessOptimized();
    initMulScalar();
    _ = try P.run("Point.mulBasePoint", mulBaseSink, .{mul_scalar}, no_needles, .{});
}

test "STACKPROBE: known gap, Point.mul and mulBasePoint leave the by-value scalar copy in the caller frame" {
    try sp.skipUnlessOptimized();
    initMulScalar();
    try std.testing.expectError(error.DeadStackResidue, P.run("Point.mul (needles)", mulSink, .{ ed.Point.basePoint.dbl(), mul_scalar }, &.{&mul_scalar}, .{ .quiet = true }));
    try std.testing.expectError(error.DeadStackResidue, P.run("Point.mulBasePoint (needles)", mulBaseSink, .{mul_scalar}, &.{&mul_scalar}, .{ .quiet = true }));
}

var x_out: x448.KeyPair = undefined;
var ed_kp: ed.KeyPair = undefined;

test "STACKPROBE: x448.KeyPair.fromEd448 leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    var s: [57]u8 = undefined;
    std.crypto.hash.sha3.Shake256.hash("ed448 probe2 x448 conversion", &s, .{});
    ed_kp = ed.KeyPair.create(&s);
    // The converted secret is the first 56 bytes of SHAKE256(seed, 114); the
    // Ed448 seed is the other secret input.
    _ = try P.run("x448.KeyPair.fromEd448", x448.KeyPair.fromEd448, .{ &x_out, &ed_kp }, &.{ &ed_kp.secret_key.bytes, &x_out.secret_key }, .{});
}

test "STACKPROBE: x448.KeyPair.generate leaves no seed on the dead stack" {
    try sp.skipUnlessOptimized();
    // `generate`'s seed is the key itself, so the output is the needle for the
    // seed left in generate's own (unburned) frame by a missing wipe.
    _ = try P.run("x448.KeyPair.generate", x448.KeyPair.generate, .{ &x_out, std.testing.io }, &.{&x_out.secret_key}, .{});
}
