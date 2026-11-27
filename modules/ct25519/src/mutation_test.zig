// SPDX-License-Identifier: MIT

//! Killing tests of the 2026-11-25 delta mutation audit (the burns of the
//! secret-scalar primitives, the Ed25519 signing on the comb). They are
//! dead-stack probes of entry points `stackprobe_test.zig` does not call;
//! ReleaseFast only, as every probe (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Ed = std.crypto.sign.Ed25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

const P = sp.Probe(.{ .window = 64 * 1024 });

var sec: [32]u8 = undefined;
var sec2: [32]u8 = undefined;

fn fill() void {
    std.crypto.hash.sha2.Sha256.hash("ct25519 mutation 2026-11-25 a", &sec, .{});
    std.crypto.hash.sha2.Sha256.hash("ct25519 mutation 2026-11-25 b", &sec2, .{});
}

test "mutation 2026-11-25: mulBaseEncode and mulBaseEncode2 burn their frames (residue rule; the by-value scalar copies sit in the caller's frame, out of any burn's reach)" {
    try sp.skipUnlessOptimized();
    fill();
    _ = try P.run("mulBaseEncode", root.mulBaseEncode, .{sec}, &.{}, .{});
    _ = try P.run("mulBaseEncode2", root.mulBaseEncode2, .{ sec, sec2 }, &.{}, .{});
}

test "mutation 2026-11-25: mul and mulRistretto burn their frames (no burn at all is a failure of the probe)" {
    try sp.skipUnlessOptimized();
    fill();
    const pt = root.mulBase(sec2);
    _ = try P.run("mul", root.mul, .{ pt, sec }, &.{}, .{});
    _ = try P.run("mulRistretto", root.mulRistretto, .{ root.mulRistrettoBase(sec2), sec }, &.{}, .{});
}

var kp: Ed.KeyPair = undefined;
var msg: [100]u8 = undefined;
var sig: Ed.Signature = undefined;

fn signCall(k: *const Ed.KeyPair, m: []const u8) void {
    sig = root.signEd25519(k, m, null) catch unreachable;
}

test "mutation 2026-11-25: signEd25519 wipes its seed, hash halves, clamped scalar and nonce" {
    try sp.skipUnlessOptimized();
    fill();
    kp = try Ed.KeyPair.generateDeterministic(sec);
    @memset(&msg, 0x5a);
    // The same intermediates `signEd25519` derives (RFC 8032 §5.1.6).
    var az: [64]u8 = undefined;
    Sha512.hash(&sec, &az, .{});
    var a: [32]u8 = az[0..32].*;
    root.Edwards25519.scalar.clamp(&a);
    var nh = Sha512.init(.{});
    nh.update(az[32..64]);
    nh.update(&msg);
    var r64: [64]u8 = undefined;
    nh.final(&r64);
    const r = root.Edwards25519.scalar.reduce64(r64);
    _ = try P.run("signEd25519", signCall, .{ &kp, &msg }, &.{ &sec, az[0..32], az[32..64], &a, &r64, &r }, .{});
}

test "mutation 2026-11-25: signEd25519 trusts a consistent key pair (it does not re-derive the public half); signEd25519Checked refuses it" {
    const a = try Ed.KeyPair.generateDeterministic(@splat(0x41));
    const b = try Ed.KeyPair.generateDeterministic(@splat(0x42));
    var wrong = a;
    wrong.public_key = b.public_key;
    wrong.secret_key.bytes[32..64].* = b.public_key.toBytes();
    // The pair agrees with itself, so the comparison signEd25519 makes passes
    // (as std's sign); only the seed-derived check of the Checked form refuses.
    _ = try root.signEd25519(&wrong, "m", null);
    try std.testing.expectError(error.KeyMismatch, root.signEd25519Checked(&wrong.secret_key, "m", null));
}
