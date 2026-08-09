// SPDX-License-Identifier: MIT
//! ct25519 — scalar multiplication on Edwards25519 / Ristretto255 that is
//! safe for a **SECRET** scalar, because it does not branch on one.
//!
//! ## Why this module exists
//!
//! `std.crypto.ecc.Edwards25519.mul` (and `Ristretto255.mul`, which is a
//! thin wrapper over it) IS internally constant-time — a 4-bit fixed window
//! over a 16-entry precomputed table selected with `Fe.cMov`, 64
//! unconditional iterations whatever the scalar — EXCEPT for one thing: its
//! `pcMul16` ladder ends with
//!
//! ```zig
//! try q.rejectIdentity();   // std/crypto/25519/edwards25519.zig
//! ```
//!
//! which turns "the product is the neutral element" into
//! `error.IdentityElement`. That is a **branch on a scalar-derived value**
//! — and worse, it is contagious: because the function returns an error
//! union, EVERY caller has to branch again to handle it, and the idioms
//! that fall out (`catch continue`, `catch return error.X`,
//! `catch @panic(...)`) make the two paths take visibly different work.
//!
//! When the scalar is a public one (a signature's `s`, a Fiat-Shamir
//! challenge replayed by a verifier) none of that matters and std's `mul`
//! /`mulPublic` are the right call. When the scalar is a **secret** — an
//! OPRF blind, a private key, a DH ratchet scalar, a proof nonce, a
//! blinding factor — the branch reveals whether that secret was zero, and
//! the caller-side branch that follows it can reveal far more.
//!
//! `mul` below is std's own ladder with the trailing rejection removed: the
//! neutral element is returned as an ordinary **value**. There is no error
//! union, so no call site can branch on the scalar, and the control flow
//! (precompute, then 64 window iterations, each an unconditional 15-entry
//! `cMov` select + add + 4 doublings) is identical for every scalar
//! including zero.
//!
//! Same algorithm, same table size, same iteration count as std — so the
//! same cost. This is not a faster multiply and not a different one; it is
//! the same multiply with a leak taken out of its tail.
//!
//! ## What this module deliberately does NOT do
//!
//! - **No identity rejection on the output.** That is the whole point. If a
//!   protocol genuinely needs "the result must not be the neutral element",
//!   it has to establish that from its inputs (see below) rather than by
//!   branching on the output.
//! - **No `WeakPublicKey` rejection on the input point.** std's `mul`
//!   checks `pc[4]` for a small-order base and errors; that is a branch on
//!   the POINT, which in every caller here is public wire data, but it is
//!   still an error union this module refuses to have. **The caller
//!   validates the point.** For ristretto255 that is free: the group is of
//!   PRIME order `L`, so it has no small-order elements at all, and a
//!   decoded `Ristretto255` that is not the identity generates the whole
//!   group. For raw Edwards25519 (cofactor 8) the caller must apply
//!   `rejectLowOrder`/`rejectIdentity` itself where the point is
//!   attacker-supplied — the callers in this repo multiply the fixed base
//!   point, where the question does not arise.
//!
//! Consequence worth stating once, because three callers rely on it: over
//! a prime-order group with a validated non-identity point `P`, the product
//! `s·P` is the identity **iff `s ≡ 0 (mod L)`** — i.e. iff the caller's
//! own secret scalar is degenerate, never because of anything a peer sent.
//! A protocol's "shared secret MUST NOT be the identity" rule is therefore
//! discharged structurally by validating `P` and generating `s` properly,
//! not by a runtime branch on secret-derived data.
//!
//! ## Verification
//!
//! `mul`/`mulRistretto` are held **bit-exact** against `std`'s own
//! `Edwards25519.mul`/`Ristretto255.mul` wherever std is willing to answer
//! (i.e. every non-degenerate case) over random and edge scalars, on both
//! the base point and random points; RFC 8032 §7.1's published Ed25519
//! public keys are re-derived as `[clamp(H(sk))]B` byte-exactly; and the
//! cases where std refuses (`s = 0`, `s = L`) are pinned to the neutral
//! element as a value. See the tests at the bottom of this file.

const std = @import("std");

/// Re-exported so callers can name the types without a second std path.
pub const Edwards25519 = std.crypto.ecc.Edwards25519;
pub const Ristretto255 = std.crypto.ecc.Ristretto255;

const Fe = Edwards25519.Fe;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "std.crypto.ecc.Edwards25519's own pcMul16 4-bit-window constant-time ladder (std/crypto/25519/edwards25519.zig), with the trailing rejectIdentity removed so the neutral element is a value and the function carries no error union; the ladder itself is the classic fixed-window scalar multiplication of RFC 8032 / Curve25519 implementations",
    .deps = .{},
};

/// `pc[i] = i*p` for `i` in `0..15`, `pc[0]` the neutral element — std's
/// private `Edwards25519.precompute(p, 15)`, which we cannot reach.
fn precompute(p: Edwards25519) [16]Edwards25519 {
    var pc: [16]Edwards25519 = undefined;
    pc[0] = Edwards25519.identityElement;
    pc[1] = p;
    comptime var i: usize = 2;
    inline while (i < 16) : (i += 1) {
        pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
    }
    return pc;
}

/// The base point's table, folded at comptime exactly as std folds its own
/// private `basePointPc` — so `mul(Edwards25519.basePoint, s)` costs the
/// same 64 window iterations and no online precomputation.
const base_pc: [16]Edwards25519 = pc: {
    @setEvalBranchQuota(20_000);
    break :pc precompute(Edwards25519.basePoint);
};

/// Branch-free select of `pc[slot]` (`slot == 0` selects the neutral
/// element), mirroring std's private `Edwards25519.pcSelect`: every entry
/// is touched with a `cMov` whose mask is `1` exactly when `slot ^ i == 0`.
///
/// The mask is `((slot ^ i) -% 1) >> 8`: `slot ^ i` is in `0..15`, so
/// `-% 1` borrows to `~0` only for `slot == i`, and the shift keeps bit 0
/// of that. The `>> 8` is what makes the borrow visible without a compare;
/// `>> 9` and above happen to be equivalent on a 64-bit `usize`, so a
/// mutation there is not a fault injection — mutate the `& 1` or the `-% 1`
/// instead if you want to see this select break.
fn pcSelect(pc: *const [16]Edwards25519, slot: u4) Edwards25519 {
    var t = Edwards25519.identityElement;
    comptime var i: u8 = 1;
    inline while (i < 16) : (i += 1) {
        const c: u64 = ((@as(usize, @as(u8, slot) ^ i) -% 1) >> 8) & 1;
        Fe.cMov(&t.x, pc[i].x, c);
        Fe.cMov(&t.y, pc[i].y, c);
        Fe.cMov(&t.z, pc[i].z, c);
        Fe.cMov(&t.t, pc[i].t, c);
    }
    return t;
}

/// `s * p` on Edwards25519, **constant-time in `s` and total**, with the
/// neutral element returned as an ordinary value rather than raised as
/// `error.IdentityElement`. Safe for a SECRET `s`.
///
/// `s` is used as-is (no clamping, no reduction) — the same contract as
/// std's `Edwards25519.mul`; only the low 253 bits are read, so a scalar
/// that is not already reduced mod `L` must be reduced by the caller
/// (`scalar.reduce`/`reduce64`) exactly as it must be for std.
///
/// The input point is NOT validated: see the module doc comment. Use
/// std's `mulPublic`/`mulDoubleBasePublic` when `s` is public and speed
/// matters — those are variable-time by design and correct there.
pub fn mul(p: Edwards25519, s: [32]u8) Edwards25519 {
    const pc = if (p.is_base) base_pc else precompute(p);
    var q = Edwards25519.identityElement;
    var pos: usize = 252;
    while (true) : (pos -= 4) {
        const slot: u4 = @truncate(s[pos >> 3] >> @as(u3, @truncate(pos)));
        q = q.add(pcSelect(&pc, slot));
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    return q;
}

/// `s * B` on Edwards25519 against the fixed base point — `mul` with the
/// comptime table, spelled out so callers do not have to rely on
/// `basePoint.is_base` being set.
pub fn mulBase(s: [32]u8) Edwards25519 {
    return mul(Edwards25519.basePoint, s);
}

/// `s * p` over Ristretto255 — `mul` on the underlying Edwards25519 point.
/// Constant-time in `s`, no error union, neutral element as a value.
///
/// ristretto255 is a PRIME-ORDER group, so there is no low-order input to
/// reject and the product is the neutral element iff `s ≡ 0 (mod L)` for a
/// non-identity `p`.
pub fn mulRistretto(p: Ristretto255, s: [32]u8) Ristretto255 {
    return .{ .p = mul(p.p, s) };
}

/// `s * B` over Ristretto255 against the ristretto255 base point.
pub fn mulRistrettoBase(s: [32]u8) Ristretto255 {
    return mulRistretto(Ristretto255.basePoint, s);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const scalar = Edwards25519.scalar;

/// Deterministic scalars — this module has no RNG and its tests must be
/// reproducible, so the "random" scalars are a SHA-512 stream reduced mod L.
fn nthScalar(n: u32) [32]u8 {
    var seed: [4]u8 = undefined;
    std.mem.writeInt(u32, &seed, n, .little);
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&seed, &wide, .{});
    return scalar.reduce64(wide);
}

test "mul: bit-exact against std's Edwards25519.mul on the base point" {
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        const s = nthScalar(i);
        const want = try Edwards25519.basePoint.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &mulBase(s).toBytes());
    }
}

test "mul: bit-exact against std's Edwards25519.mul on non-base points" {
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const p = try Edwards25519.basePoint.mul(nthScalar(i +% 1_000));
        const s = nthScalar(i +% 2_000);
        const want = try p.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &mul(p, s).toBytes());
    }
}

test "mulRistretto: bit-exact against std's Ristretto255.mul" {
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const p = try Ristretto255.basePoint.mul(nthScalar(i +% 3_000));
        const s = nthScalar(i +% 4_000);
        const want = try p.mul(s);
        try testing.expect(mulRistretto(p, s).equivalent(want));
        try testing.expectEqualSlices(u8, &want.toBytes(), &mulRistretto(p, s).toBytes());
    }
}

test "mul: the neutral element is a VALUE, where std raises an error" {
    // This is the entire reason the module exists. std refuses both of
    // these; the whole point is that we do not, because refusing means
    // branching on a secret-derived value.
    const zero = [_]u8{0} ** 32;
    try testing.expectError(error.IdentityElement, Edwards25519.basePoint.mul(zero));
    try testing.expectError(error.IdentityElement, Ristretto255.basePoint.mul(zero));

    const id_bytes = Edwards25519.identityElement.toBytes();
    try testing.expectEqualSlices(u8, &id_bytes, &mulBase(zero).toBytes());
    // The ristretto255 identity encodes as 32 zero bytes (RFC 9496 §4.3.2).
    try testing.expectEqualSlices(u8, &zero, &mulRistrettoBase(zero).toBytes());

    // `s = L` (the group order) is the other scalar that lands on the
    // neutral element without being all-zero bytes — the case a "reject an
    // all-zero scalar up front" guard would miss.
    var order: [32]u8 = undefined;
    std.mem.writeInt(u256, &order, scalar.field_order, .little);
    try testing.expectError(error.IdentityElement, Edwards25519.basePoint.mul(order));
    try testing.expectEqualSlices(u8, &id_bytes, &mulBase(order).toBytes());
    try testing.expectEqualSlices(u8, &zero, &mulRistrettoBase(order).toBytes());
}

test "mul: carries no error set, so no call site can branch on the scalar" {
    // The contagious half of the finding: std's `mul` returns an error
    // union, which forces every caller to branch a second time. Pin that
    // these do not, for all four entry points.
    inline for (.{ mul, mulBase, mulRistretto, mulRistrettoBase }) |f| {
        const ret = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
        try testing.expect(@typeInfo(ret) != .error_union);
    }
    // ...and that std really is the shape we are describing.
    const std_ret = @typeInfo(@TypeOf(Edwards25519.mul)).@"fn".return_type.?;
    try testing.expect(@typeInfo(std_ret) == .error_union);
}

test "mulBase: re-derives RFC 8032 §7.1's published Ed25519 public keys" {
    // External anchor: the Ed25519 public key of RFC 8032 §7.1's TEST 1 and
    // TEST 2 is `[clamp(SHA-512(sk)[0..32])]B` encoded — a value published
    // by the RFC, not by us and not by std. A typo in either constant makes
    // this test red immediately.
    const Vector = struct { sk: *const [64]u8, pk: *const [64]u8 };
    const vectors = [_]Vector{
        .{
            .sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            .pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        },
        .{
            .sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            .pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        },
    };
    for (vectors) |v| {
        var sk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sk, v.sk);
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, v.pk);

        var h: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&sk, &h, .{});
        var a: [32]u8 = h[0..32].*;
        scalar.clamp(&a);
        try testing.expectEqualSlices(u8, &want, &mulBase(a).toBytes());
    }
}

test "mul: is additively homomorphic in the scalar (fold-boundary sanity)" {
    // Independent of std: `(a+b)*P == a*P + b*P` exercises the window
    // carry/fold seams that a differential over reduced scalars can miss.
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const a = nthScalar(i +% 5_000);
        const b = nthScalar(i +% 6_000);
        const sum = scalar.add(a, b);
        const lhs = mulBase(sum);
        const rhs = mulBase(a).add(mulBase(b));
        try testing.expectEqualSlices(u8, &lhs.toBytes(), &rhs.toBytes());
    }
}
