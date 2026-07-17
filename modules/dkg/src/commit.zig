// SPDX-License-Identifier: MIT

//! commit — the mechanical cryptographic helpers the GJKR DKG is built
//! from: polynomial evaluation, the nothing-up-my-sleeve second Pedersen
//! generator `h`, the per-coefficient Pedersen (`g^a h^b`) and Feldman
//! (`g^a`) commitment vectors, and the "evaluate a commitment vector at a
//! point" multi-exponentiation (`Π_k C_k^{j^k}`, Horner in the exponent).
//!
//! All REAL and ungated. These are the arithmetic primitives; the PROTOCOL
//! SOUNDNESS — which check runs, over which set, in which order, and how
//! complaints turn into disqualification — lives in `core.zig` and is the
//! Fable-irreducible part. Ported from `threshold_ecdsa`'s own
//! `evalPolynomialAt` / `derivePublicKeyShare` shapes onto the same
//! `std.crypto.ecc.Secp256k1` field/group.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");

pub const Secp256k1 = tecdsa.Secp256k1;
pub const Scalar = tecdsa.Scalar;
pub const Element = tecdsa.Element;

pub const CommitError = error{IdentityElement} || tecdsa.ElementError;

/// The scalar for a public participant index `1 <= index`. Zero-padded
/// 32-byte big-endian; a `u32` is always `< q`, so canonicality never
/// fires (mirrors `threshold_ecdsa`'s own `scalarFromIndex`).
pub fn scalarFromIndex(index: u32) Scalar {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u32, buf[28..32], index, .big);
    return Scalar.fromBytes(buf, .big) catch unreachable;
}

/// `f(x) = coeffs[0] + coeffs[1]·x + … + coeffs[t-1]·x^{t-1}` via Horner
/// (constant term `coeffs[0]` added last). `coeffs` and the output are
/// SECRET; every op goes through `Scalar`'s constant-time arithmetic.
pub fn evalPoly(coeffs: []const Scalar, x: Scalar) Scalar {
    std.debug.assert(coeffs.len >= 1);
    var acc = Scalar.zero;
    var k: usize = coeffs.len;
    while (k > 1) : (k -= 1) acc = acc.mul(x).add(coeffs[k - 1]);
    return acc.mul(x).add(coeffs[0]);
}

/// The domain-separation string hashed to derive the Pedersen generator
/// `h`. Changing it changes `h` (and would invalidate any persisted
/// commitments), so it is frozen here.
pub const pedersen_h_domain = "zig-libs/dkg/pedersen-h/secp256k1/v1";

/// The second Pedersen generator `h`: a nothing-up-my-sleeve secp256k1
/// point with no known discrete-log relative to `g` (the base point) —
/// essential to Pedersen's hiding property (a `g^a h^b` commitment leaks
/// nothing about `a` only because no one knows `log_g h`). Derived by
/// try-and-increment hash-to-curve: SHA-256 over `pedersen_h_domain ||
/// counter` seeds a candidate compressed-`0x02` x-coordinate; increment
/// until a valid curve point appears. Deterministic and reproducible; the
/// unknown-DL property is what a review must (and can) audit by
/// construction. REAL.
pub fn pedersenH() Element {
    var counter: u32 = 0;
    while (true) : (counter += 1) {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(pedersen_h_domain);
        var cbuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &cbuf, counter, .big);
        h.update(&cbuf);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        var sec1: [33]u8 = undefined;
        sec1[0] = 0x02;
        @memcpy(sec1[1..], &digest);
        const p = Secp256k1.fromSec1(&sec1) catch continue;
        return Element.fromPoint(p) catch continue;
    }
}

/// `A_k = g^{a_k}` for each coefficient — the Feldman commitment vector.
/// `commitments[0] = g^{a_0}`. Owned; caller frees. REAL (per-coefficient
/// `basePoint.mul`, the `threshold_ecdsa.splitSecretKey` shape).
pub fn feldmanCommitVector(allocator: std.mem.Allocator, a: []const Scalar) (std.mem.Allocator.Error || CommitError)![]Element {
    const out = try allocator.alloc(Element, a.len);
    errdefer allocator.free(out);
    for (out, a) |*slot, coeff| {
        const p = Secp256k1.basePoint.mul(coeff.toBytes(.big), .big) catch return error.IdentityElement;
        slot.* = try Element.fromPoint(p);
    }
    return out;
}

/// `C_k = g^{a_k} · h^{b_k}` for each coefficient pair — the Pedersen
/// commitment vector. `a.len` must equal `b.len`. Owned; caller frees.
/// REAL.
pub fn pedersenCommitVector(
    allocator: std.mem.Allocator,
    a: []const Scalar,
    b: []const Scalar,
    h: Element,
) (std.mem.Allocator.Error || CommitError)![]Element {
    std.debug.assert(a.len == b.len);
    const h_point = try h.point();
    const out = try allocator.alloc(Element, a.len);
    errdefer allocator.free(out);
    for (out, a, b) |*slot, ak, bk| {
        const g_a = Secp256k1.basePoint.mul(ak.toBytes(.big), .big) catch return error.IdentityElement;
        const h_b = h_point.mul(bk.toBytes(.big), .big) catch return error.IdentityElement;
        slot.* = try Element.fromPoint(g_a.add(h_b));
    }
    return out;
}

/// Evaluate a commitment vector at public index `j`: `Π_k C_k^{j^k}`
/// (Horner in the exponent, identical to
/// `threshold_ecdsa.derivePublicKeyShare`). For a Pedersen vector this
/// yields `g^{f(j)} h^{f'(j)}`; for a Feldman vector, `g^{f(j)}`. This is
/// the right-hand side both verification equations in `core.zig` compare a
/// received share against. REAL.
pub fn evalCommitmentAt(commitments: []const Element, index: u32) CommitError!Element {
    std.debug.assert(commitments.len >= 1);
    const x = scalarFromIndex(index);
    var acc = try commitments[commitments.len - 1].point();
    var k: usize = commitments.len - 1;
    while (k > 0) : (k -= 1) {
        const next = try commitments[k - 1].point();
        acc = acc.mul(x.toBytes(.big), .big) catch return error.IdentityElement;
        acc = acc.add(next);
    }
    return Element.fromPoint(acc);
}

/// `g^a · h^b` for a single share pair — the left-hand side of the
/// Pedersen verification equation (a received share `(s, s')` is valid iff
/// this equals `evalCommitmentAt(C, j)`). REAL; the core decides how the
/// comparison drives complaints/QUAL.
pub fn pedersenEvalShare(s: Scalar, s_prime: Scalar, h: Element) CommitError!Element {
    const g_s = Secp256k1.basePoint.mul(s.toBytes(.big), .big) catch return error.IdentityElement;
    const h_sp = (try h.point()).mul(s_prime.toBytes(.big), .big) catch return error.IdentityElement;
    return Element.fromPoint(g_s.add(h_sp));
}

/// `g^s` for a single share — the left-hand side of the Feldman
/// verification equation. REAL.
pub fn feldmanEvalShare(s: Scalar) CommitError!Element {
    const g_s = Secp256k1.basePoint.mul(s.toBytes(.big), .big) catch return error.IdentityElement;
    return Element.fromPoint(g_s);
}

test "evalPoly matches manual Horner and evalCommitmentAt in the exponent" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // f(x) = 3 + 5x + 2x^2
    const c0 = scalarFromIndex(3);
    const c1 = scalarFromIndex(5);
    const c2 = scalarFromIndex(2);
    const coeffs = [_]Scalar{ c0, c1, c2 };

    // f(4) = 3 + 20 + 32 = 55
    const at4 = evalPoly(&coeffs, scalarFromIndex(4));
    try testing.expectEqualSlices(u8, &scalarFromIndex(55).toBytes(.big), &at4.toBytes(.big));

    // g^{f(4)} must equal evalCommitmentAt(Feldman(coeffs), 4)
    const feld = try feldmanCommitVector(allocator, &coeffs);
    defer allocator.free(feld);
    const lhs = try feldmanEvalShare(at4);
    const rhs = try evalCommitmentAt(feld, 4);
    try testing.expectEqualSlices(u8, &lhs.toBytes(), &rhs.toBytes());
}

test "pedersenH is a valid, stable, non-base point (unknown-DL generator)" {
    const testing = std.testing;
    const h1 = pedersenH();
    const h2 = pedersenH();
    // Deterministic.
    try testing.expectEqualSlices(u8, &h1.toBytes(), &h2.toBytes());
    // Not equal to g (would be a trivially-known DL of 1).
    const g = try Element.fromPoint(Secp256k1.basePoint);
    try testing.expect(!std.mem.eql(u8, &h1.toBytes(), &g.toBytes()));
    // Is a real curve point (round-trips through fromSec1).
    _ = try h1.point();
}

test "pedersen commitment opens consistently at a point" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const h = pedersenH();

    const a = [_]Scalar{ scalarFromIndex(11), scalarFromIndex(7) }; // f
    const b = [_]Scalar{ scalarFromIndex(13), scalarFromIndex(4) }; // f'
    const C = try pedersenCommitVector(allocator, &a, &b, h);
    defer allocator.free(C);

    const j: u32 = 3;
    const s = evalPoly(&a, scalarFromIndex(j));
    const sp = evalPoly(&b, scalarFromIndex(j));
    const lhs = try pedersenEvalShare(s, sp, h);
    const rhs = try evalCommitmentAt(C, j);
    // g^{f(j)} h^{f'(j)} == Π C_k^{j^k}
    try testing.expectEqualSlices(u8, &lhs.toBytes(), &rhs.toBytes());
}
