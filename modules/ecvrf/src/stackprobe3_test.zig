// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the P-256 suites
//! (`p256vrf.zig`, TAI and SSWU): `KeyPair.init` and `KeyPair.prove`, the
//! two burned entry points. ReleaseFast/ReleaseSmall only
//! (`skipUnlessOptimized`).
//!
//! Needles beyond the engine's residue rule: `SK` (= `x`, both byte orders),
//! the RFC 6979 nonce `k` (both byte orders), `k*B` and `k*H` (each reveals
//! nothing alone, but with `k` known they are the nonce's images; listed in
//! SPEC's backlog) and `c*x = s - k` (with the public `c` it yields `x`).
//! The results land in static memory (`KeyPair.init` takes `out`; `prove`
//! goes through a wrapper), so the caller's own copy is not what is measured.
//! The first run of this probe found `SK` 153..239 B deep, above the burn:
//! `init` returned `KeyError!KeyPair` by value then, and the result
//! temporary sat in its frame — hence the `out` parameter.

const std = @import("std");
const vrf = @import("p256vrf.zig");
const p256 = @import("p256");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

const alpha = "ecvrf p256 dead-stack probe input";

var sk: vrf.SecretKey = undefined;
var proof: vrf.Proof = undefined;

fn Wrappers(comptime S: type) type {
    return struct {
        var kp_out: S.KeyPair = undefined;
        var kp: S.KeyPair = undefined;
        noinline fn prove(out: *vrf.Proof, pair: *const S.KeyPair, a: []const u8) void {
            out.* = pair.prove(a);
        }
    };
}

fn reversed(comptime n: usize, b: [n]u8) [n]u8 {
    var r = b;
    std.mem.reverse(u8, &r);
    return r;
}

fn probeSuite(comptime S: type, comptime name: []const u8) !void {
    const Wr = Wrappers(S);
    for (0..2) |ci| {
        std.crypto.hash.sha2.Sha256.hash(&[_]u8{ 'e', 'c', 'v', 'r', 'f', 'p', @intCast(ci) }, &sk, .{});
        try S.KeyPair.init(&Wr.kp, &sk);
        const sk_le = reversed(32, sk);

        _ = try P.run(name ++ " KeyPair.init", S.KeyPair.init, .{ &Wr.kp_out, &sk }, &.{ &sk, &sk_le, &Wr.kp_out.sk }, .{});

        // Re-derive the prover's intermediates through the public pieces.
        const h_string = S.encodeToCurve(&Wr.kp.pk, alpha);
        const h = try p256.P256.fromSec1(&h_string);
        var hm: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&h_string, &hm, .{});
        const k = p256.sign.rfc6979Nonce(sk, hm);
        const k_be = k.toBytes(.big);
        const k_le = k.toBytes(.little);
        var kb: p256.P256 = undefined;
        var kh: p256.P256 = undefined;
        try p256.P256.basePoint.mulInto(&kb, &k_be, .big);
        try h.mulInto(&kh, &k_be, .big);
        const kb_s = kb.toCompressedSec1();
        const kh_s = kh.toCompressedSec1();
        const pi = Wr.kp.prove(alpha);
        const s = try p256.Scalar.fromBytes(pi[vrf.pt_len + vrf.c_len ..].*, .big);
        const cx = s.sub(k);
        const cx_be = cx.toBytes(.big);
        const cx_le = cx.toBytes(.little);

        _ = try P.run(name ++ " KeyPair.prove", Wr.prove, .{ &proof, &Wr.kp, alpha }, &.{ &sk, &sk_le, &k_be, &k_le, &kb_s, &kh_s, &cx_be, &cx_le }, .{});
        try std.testing.expectEqualSlices(u8, &pi, &proof); // the probed call is the call re-derived above
    }
}

test "STACKPROBE: the P-256 suites' KeyPair.init and KeyPair.prove leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    try probeSuite(vrf.tai, "p256 tai");
    try probeSuite(vrf.sswu, "p256 sswu");
}
