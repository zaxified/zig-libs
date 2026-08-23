// SPDX-License-Identifier: MIT

//! What a caller with a SECRET scalar does with `ct25519`: multiply it onto
//! the base point and onto an arbitrary point, on both Edwards25519 and
//! Ristretto255, and get exactly what `std.crypto.ecc` would compute for the
//! same inputs — the module's whole claim is "same output as std, minus the
//! secret-dependent branch in std's tail", so std run in the same process is
//! the external judge here.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! `ct25519` allocates nothing and keeps no state, so there is no
//! DebugAllocator to wrap here (see `modules/l2disco/example/main.zig` for
//! the same allocation-free shape).

const std = @import("std");
const ct25519 = @import("ct25519");
const Edwards25519 = ct25519.Edwards25519;
const Ristretto255 = ct25519.Ristretto255;

/// A deterministic "secret" scalar stream — SHA-512 of a counter, reduced mod
/// the group order, exactly the shape a real caller's KDF output takes.
fn nthScalar(n: u32) [32]u8 {
    var seed: [4]u8 = undefined;
    std.mem.writeInt(u32, &seed, n, .little);
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&seed, &wide, .{});
    return Edwards25519.scalar.reduce64(wide);
}

pub fn main() !void {
    // ── external anchor: RFC 8032 §7.1 TEST 1 ──────────────────────────────
    // The published Ed25519 public key is [clamp(SHA-512(sk)[0..32])]B — a
    // value that comes from the RFC, not from std and not from this module.
    {
        const sk_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        var sk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sk, sk_hex);
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, pk_hex);

        var h: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&sk, &h, .{});
        var a: [32]u8 = h[0..32].*;
        Edwards25519.scalar.clamp(&a);

        const pk = ct25519.mulBase(a).toBytes();
        if (!std.mem.eql(u8, &pk, &want)) return error.RfcVectorMismatch;
        std.debug.print("RFC 8032 TEST 1: mulBase(clamp(H(sk))) matches the published public key\n", .{});
    }

    // ── differential vs std, base point, Edwards25519 ──────────────────────
    {
        const s = nthScalar(1);
        const want = try Edwards25519.basePoint.mul(s);
        const got = ct25519.mulBase(s);
        if (!std.mem.eql(u8, &want.toBytes(), &got.toBytes())) return error.DifferentialMismatch;
        std.debug.print("mulBase: bit-exact against std.crypto.ecc.Edwards25519.mul\n", .{});
    }

    // ── differential vs std, arbitrary (non-base) point ────────────────────
    {
        const p = try Edwards25519.basePoint.mul(nthScalar(2));
        const s = nthScalar(3);
        const want = try p.mul(s);
        const got = ct25519.mul(p, s);
        if (!std.mem.eql(u8, &want.toBytes(), &got.toBytes())) return error.DifferentialMismatch;
        std.debug.print("mul: bit-exact against std.crypto.ecc.Edwards25519.mul on a random point\n", .{});
    }

    // ── differential vs std, Ristretto255 ───────────────────────────────────
    {
        const p = try Ristretto255.basePoint.mul(nthScalar(4));
        const s = nthScalar(5);
        const want = try p.mul(s);
        const got = ct25519.mulRistretto(p, s);
        if (!std.mem.eql(u8, &want.toBytes(), &got.toBytes())) return error.DifferentialMismatch;
        std.debug.print("mulRistretto: bit-exact against std.crypto.ecc.Ristretto255.mul\n", .{});
    }

    // ── the module's whole reason to exist: the secret can be zero ─────────
    // std raises error.IdentityElement for s=0; ct25519 returns the neutral
    // element as an ordinary value, so no caller branches on the scalar.
    {
        const zero = [_]u8{0} ** 32;
        std.testing.expectError(error.IdentityElement, Edwards25519.basePoint.mul(zero)) catch return error.StdShapeChanged;
        const got = ct25519.mulBase(zero);
        if (!std.mem.eql(u8, &got.toBytes(), &Edwards25519.identityElement.toBytes())) return error.ZeroScalarMismatch;
        std.debug.print("mulBase(0): neutral element as a VALUE, no error union (std errors here)\n", .{});
    }

    // ── negative case 1: a low-order (order-8 torsion) point, named error ──
    // ct25519.mul performs NO input-point validation (see SPEC.md "Points are
    // the caller's problem") — a caller on raw Edwards25519 (cofactor 8) MUST
    // validate the point itself, with std, before handing it to ct25519. This
    // is that validation step, and the point it rejects: RFC 8032 §5.1.7's
    // canonical small-order example.
    {
        const torsion_bytes = [_]u8{
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
            0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
            0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
        };
        const p = try Edwards25519.fromBytes(torsion_bytes);
        if (p.rejectLowOrder()) |_| {
            return error.ExpectedRejection;
        } else |err| switch (err) {
            error.WeakPublicKey => std.debug.print("order-8 torsion point: rejected by caller-side validation (WeakPublicKey)\n", .{}),
        }
        // Demonstrating why validation matters: ct25519.mul itself answers
        // anyway (deliberately — see SPEC.md), so skipping the check above
        // would silently accept an attacker-supplied low-order point.
        const s = nthScalar(6);
        _ = ct25519.mul(p, s); // does not error; the caller already rejected it above
    }

    // ── negative case 2: a non-canonical field encoding, named error ───────
    // 2^255-1 (all-ones with the sign bit cleared) is well above the field
    // prime p = 2^255-19, so it is a non-canonical encoding of a field
    // element — exactly the RFC 8032 §5.1.3 "reduce mod p" edge case a
    // wire-format decoder must reject rather than silently accept.
    {
        var non_canonical = [_]u8{0xff} ** 32;
        non_canonical[31] = 0x7f;
        if (Edwards25519.rejectNonCanonical(non_canonical)) |_| {
            return error.ExpectedRejection;
        } else |err| switch (err) {
            error.NonCanonical => std.debug.print("2^255-1 encoding: rejected by caller-side validation (NonCanonical)\n", .{}),
        }
    }
}
