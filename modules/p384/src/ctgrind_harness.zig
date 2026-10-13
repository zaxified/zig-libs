// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for SPEC.md § Constant-time
//! contract, run by `../../../scripts/checks/ctgrind.sh p384`. Not part of
//! `zig build test-p384` (memcheck's context count is valgrind's output);
//! `zig build check-ctgrind` compiles it so it cannot rot.
//!
//! Targets (the secret tainted with `makeMemUndefined`, then reloaded through
//! a volatile pointer so the call reads the tainted memory):
//!
//! * `mul`    — `P384.mulInto` on a non-base point, scalar tainted: the
//!              fixed-window multiply with the masked table scan.
//! * `keygen` — `KeyPair.fromSecretKeyInto`, secret key tainted: range check,
//!              `d·G`, encoding.
//! * `sign`   — `generateDeterministicInto` + `signPrehashedInto` from a
//!              tainted seed: the RFC 6979 HMAC-DRBG, `k·G`, `k⁻¹` (Fermat),
//!              `s = k⁻¹(e + r·d)`. The message is public.
//! * `ecdh`   — `ecdhInto`, secret tainted, peer public.
//! * `vartime` — POSITIVE CONTROL: a tainted scalar into `mulPublic`, which
//!              is documented variable time; it MUST produce in-file
//!              contexts, or the measurement is not seeing this module.
//!
//! The declassified branches (`ct.zig`) are the ones the API reveals: range
//! verdicts on a secret, the identity verdict, r = 0 / s = 0, the RFC 6979
//! retry bit. They show up as zero contexts because they are declassified,
//! not because they are absent — SPEC.md lists each.
//!
//! ReleaseFast only (Debug/ReleaseSafe overflow checks branch on tainted
//! limbs). Results are printed with `std.debug.print`, whose hex formatter
//! branches on the tainted bytes: the propagation witness.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const P384 = root.P384;
const E = root.EcdsaP384Sha384;

fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A scalar inside [1, n): the top byte cleared keeps it below n.
fn secretScalar(comptime domain: []const u8) [48]u8 {
    var s = secretBytes(48, domain);
    s[0] = 0;
    s[47] |= 1;
    return s;
}

const Target = enum { mul, keygen, sign, ecdh, vartime };

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse return error.UnknownTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const tainted = if (std.mem.eql(u8, taint_arg, "yes")) true else if (std.mem.eql(u8, taint_arg, "no")) false else return error.UnknownTaint;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // A public non-base point for `mul` / `ecdh` / `vartime`.
    const peer = P384.basePoint.dbl().add(P384.basePoint);
    const peer_sec1 = peer.toUncompressedSec1();

    switch (target) {
        .mul, .vartime => {
            var k = secretScalar("ctgrind-p384-mul-v1");
            taintIf(tainted, &k);
            const s = reloadVolatile(48, &k);
            var q: P384 = undefined;
            if (target == .mul) {
                try P384.mulInto(&q, peer, &s, .big);
            } else {
                q = try peer.mulPublic(s, .big);
            }
            // Raw projective limbs (no inversion: a separate claim).
            std.debug.print("x={x}\n", .{std.mem.asBytes(&q.x.limbs)});
            std.debug.print("y={x}\n", .{std.mem.asBytes(&q.y.limbs)});
            std.debug.print("z={x}\n", .{std.mem.asBytes(&q.z.limbs)});
        },
        .keygen => {
            var d = secretScalar("ctgrind-p384-keygen-v1");
            taintIf(tainted, &d);
            const sk: E.SecretKey = .{ .bytes = reloadVolatile(48, &d) };
            var kp: E.KeyPair = undefined;
            try E.KeyPair.fromSecretKeyInto(&kp, &sk);
            std.debug.print("pk={x}\n", .{kp.public_key.toUncompressedSec1()});
        },
        .sign => {
            var seed = secretBytes(E.KeyPair.seed_length, "ctgrind-p384-seed-v1");
            taintIf(tainted, &seed);
            const s = reloadVolatile(E.KeyPair.seed_length, &seed);
            var kp: E.KeyPair = undefined;
            try E.KeyPair.generateDeterministicInto(&kp, &s);
            var digest: [48]u8 = undefined;
            std.crypto.hash.sha2.Sha384.hash("ctgrind harness message", &digest, .{});
            var sig: E.Signature = undefined;
            try E.KeyPair.signPrehashedInto(&sig, &kp, &digest, null);
            std.debug.print("pk={x}\n", .{kp.public_key.toUncompressedSec1()});
            std.debug.print("sig={x}\n", .{sig.toBytes()});
        },
        .ecdh => {
            var d = secretScalar("ctgrind-p384-ecdh-v1");
            taintIf(tainted, &d);
            const s = reloadVolatile(48, &d);
            var z: [48]u8 = undefined;
            try root.ecdhInto(&z, &s, &peer_sec1);
            std.debug.print("z={x}\n", .{z});
        },
    }
}
