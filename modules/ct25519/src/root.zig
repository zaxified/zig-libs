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
//! **The tests below are NOT the constant-time oracle.** They compare
//! outputs, and the defect class this module exists to remove — a branch
//! on a secret that changes no output byte — is invisible to all of them:
//! injecting `if (s == 0) return identityElement;` into `mul` leaves
//! `zig build test-ct25519` green. Constant time is checked with a
//! ctgrind-style valgrind run instead; `SPEC.md` carries the harness, the
//! two flags without which it reports a false clean, and the limits of
//! the claim. What the tests DO establish:
//!
//! `mul`/`mulRistretto` are held **bit-exact** against `std`'s own
//! `Edwards25519.mul`/`Ristretto255.mul` wherever std is willing to answer
//! (i.e. every non-degenerate case) over random and edge scalars, on both
//! the base point and random points; RFC 8032 §7.1's published Ed25519
//! public keys are re-derived as `[clamp(H(sk))]B` byte-exactly; and the
//! cases where std refuses (`s = 0`, `s = L`) are pinned to the neutral
//! element as a value. The inputs std refuses *outright* — the identity
//! and an order-8 torsion point, where this module deliberately answers
//! and std returns `error.WeakPublicKey` — are checked against repeated
//! addition, an oracle independent of both ladders; and scalar bits
//! 250..255 are checked against a doubling chain, because every other
//! test here feeds a reduced or clamped scalar in which the top bits are
//! never set. See the tests at the bottom of this file.

const std = @import("std");

/// Re-exported so callers can name the types without a second std path.
pub const Edwards25519 = std.crypto.ecc.Edwards25519;
pub const Ristretto255 = std.crypto.ecc.Ristretto255;

const Fe = Edwards25519.Fe;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Constant-time-on-secrets scalar multiplication for Edwards25519/Ristretto255 — drops std's secret-dependent `rejectIdentity` branch. Caller must validate points.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
/// std's `Edwards25519.mul`. **All 256 bits are read**: the top window sits
/// at `pos = 252` and covers bits 252..255, so an unreduced `s` yields
/// `s·P` for the full 256-bit integer, NOT for `s mod L`. A protocol that
/// needs the reduced value must reduce first (`scalar.reduce`/`reduce64`),
/// exactly as it must for std. (This comment previously said "only the low
/// 253 bits are read", which was false; the audit's `I2` fault injection —
/// masking bit 255 off inside `mul` — left the whole suite green, because
/// every scalar the tests used was either reduced mod `L` or clamped.)
///
/// The input point is NOT validated: see the module doc comment. Use
/// std's `mulPublic`/`mulDoubleBasePublic` when `s` is public and speed
/// matters — those are variable-time by design and correct there.
pub fn mul(p: Edwards25519, s: [32]u8) Edwards25519 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    const pc = if (p.is_base) base_pc else precompute(p);
    var q = Edwards25519.identityElement;
    var pos: usize = 252;
    while (true) : (pos -= 4) {
        const slot: u4 = @truncate(sc[pos >> 3] >> @as(u3, @truncate(pos)));
        q = q.add(pcSelect(&pc, slot));
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    return q;
}

// ── fixed-base comb (audit C3, a DECISIONS.md P5 algorithm change) ────────
//
// `mul(basePoint, s)` spends 71 % of its time in 252 doublings (audit C3:
// 34.4 of 48.2 µs), because the base point runs the same 16-entry window
// ladder as an arbitrary point. `mulBase`/`mulRistrettoBase` instead use the
// fixed-base comb of Bernstein, Duif, Lange, Schwabe and Yang, "High-speed
// high-security signatures" (CHES 2011, J. Cryptogr. Eng. 2012) §4 — the
// algorithm of ref10's `ge_scalarmult_base`, which libsodium ships as
// `ge25519_scalarmult_base`:
//
//   * recode `s` into signed radix-16 digits `e[0..64]`, each in `[-8, 7]`,
//     so `s = Σ e[i]·16^i + carry·16^64`;
//   * `comb_table[j][k] = (k+1)·16^(2j)·B` for `j < 32`, `k < 8`;
//   * `q = Σ_{i odd} e[i]·16^(i-1)·B`, then `q = 16·q` (4 doublings), then
//     add `Σ_{i even} e[i]·16^i·B` — 64 additions and 4 doublings instead of
//     64 additions and 252 doublings.
//
// ⚠ ONE DELIBERATE DIFFERENCE FROM ref10. ref10 requires `s[31] <= 127` (its
// top digit absorbs the carry and must stay in `[-8, 8]`). This module's
// contract is that **all 256 bits are read** (see `mul`), so the carry out of
// digit 63 is kept as its own secret bit and one extra, always-performed add
// selects between the identity and the constant `2^256·B` (`comb_carry`).
//
// Constant time: the digit loop runs 64 times whatever `s` is; the digit
// recoding is shift/mask arithmetic; each table row is gathered by a
// full-row `cMov` scan (the same mask shape as `pcSelect`) and the sign by a
// `cMov` onto the negated coordinates; the carry add is unconditional.
// Table indices are loop counters only. The source is not the evidence —
// `ctgrind_harness.zig`'s `comb` target is (SPEC.md § "C3").

const comb_rows = 32;
const comb_teeth = 8;
const CombTable = [comb_rows][comb_teeth]Edwards25519;

/// `[j][k] = (k+1)·16^(2j)·B`, extended coordinates, folded at comptime —
/// plus `2^256·B` for the recoding carry. 32·(7 multiples + 8 doublings to
/// the next row) ≈ 480 point operations at comptime, the same shape as
/// `k256`'s and `p256`'s `buildCombTable`.
const comb = blk: {
    @setEvalBranchQuota(100_000_000);
    var tab: CombTable = undefined;
    var row_base = Edwards25519.basePoint;
    row_base.is_base = false;
    for (0..comb_rows) |j| {
        tab[j][0] = row_base;
        for (1..comb_teeth) |k| {
            const m = k + 1; // multiple held in tab[j][k]
            tab[j][k] = if (m % 2 == 0) tab[j][m / 2 - 1].dbl() else tab[j][k - 1].add(row_base);
        }
        // next row: 256·row_base = 32·(8·row_base)
        var nb = tab[j][comb_teeth - 1];
        for (0..5) |_| nb = nb.dbl();
        row_base = nb;
    }
    // After the last row `row_base` is 16^64·B = 2^256·B.
    break :blk .{ .table = tab, .carry = row_base };
};
const comb_table: CombTable = comb.table;
const comb_carry: Edwards25519 = comb.carry;

/// Signed radix-16 recoding of the full 256-bit `s`: `e[i]` in `[-8, 7]`
/// and the returned carry in `{0, 1}`, with `s = Σ e[i]·16^i + carry·16^64`.
/// Branch-free: `x = nibble + carry` is in `0..16`, `(x + 8) >> 4` is 1
/// exactly when `x >= 8`, and subtracting `16·carry` lands `x` in `[-8, 7]`.
fn combRecode(s: *const [32]u8, e: *[64]i8) u8 {
    var carry: u8 = 0;
    for (e, 0..) |*d, i| {
        const nibble: u8 = (s[i >> 1] >> @as(u3, @intCast(4 * (i & 1)))) & 15;
        const x: u8 = nibble + carry; // 0..16
        carry = (x + 8) >> 4;
        d.* = @bitCast(x -% (carry << 4));
    }
    return carry;
}

/// `e·row[0]` for a signed digit `e` in `[-8, 8]`, touching every entry of
/// the row: `|e|` selects by a full `cMov` scan (`|e| == 0` leaves the
/// identity), then the sign selects `-x`/`-t` by `cMov`. ref10's
/// `negative`/`babs`/`equal` shape.
fn combSelect(row: *const [comb_teeth]Edwards25519, e: i8) Edwards25519 {
    const eu: u8 = @bitCast(e);
    const neg: u8 = eu >> 7; // 1 iff e < 0
    const abs: u8 = eu -% ((0 -% neg) & (eu << 1)); // |e|, 0..8
    var t = Edwards25519.identityElement;
    comptime var k: u8 = 1;
    inline while (k <= comb_teeth) : (k += 1) {
        const c: u64 = ((@as(usize, abs ^ k) -% 1) >> 8) & 1;
        const entry = &row[k - 1];
        Fe.cMov(&t.x, entry.x, c);
        Fe.cMov(&t.y, entry.y, c);
        Fe.cMov(&t.z, entry.z, c);
        Fe.cMov(&t.t, entry.t, c);
    }
    const minus_x = t.x.neg();
    const minus_t = t.t.neg();
    Fe.cMov(&t.x, minus_x, neg);
    Fe.cMov(&t.t, minus_t, neg);
    return t;
}

/// `s·B` by the fixed-base comb; see the section comment above. Every
/// secret-derived buffer it owns is wiped before return.
fn combMulBase(s: *const [32]u8) Edwards25519 {
    var e: [64]i8 = undefined;
    defer std.crypto.secureZero(i8, &e);
    var carry = combRecode(s, &e);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&carry));

    var q = Edwards25519.identityElement;
    var i: usize = 1;
    while (i < 64) : (i += 2) q = q.add(combSelect(&comb_table[i >> 1], e[i]));
    q = q.dbl().dbl().dbl().dbl();
    i = 0;
    while (i < 64) : (i += 2) q = q.add(combSelect(&comb_table[i >> 1], e[i]));

    var c = Edwards25519.identityElement;
    const cm: u64 = carry;
    Fe.cMov(&c.x, comb_carry.x, cm);
    Fe.cMov(&c.y, comb_carry.y, cm);
    Fe.cMov(&c.z, comb_carry.z, cm);
    Fe.cMov(&c.t, comb_carry.t, cm);
    return q.add(c);
}

/// `s * B` on Edwards25519 against the fixed base point, **constant-time in
/// `s` and total** — the same result as `mul(Edwards25519.basePoint, s)` for
/// every 256-bit `s` (all bits read, no reduction), computed with the
/// fixed-base comb above instead of the window ladder (audit C3, ~3× faster;
/// SPEC.md § "C3"). `mul(Edwards25519.basePoint, s)` deliberately stays on
/// the ladder: it is the reference the comb is differentially tested against.
pub fn mulBase(s: [32]u8) Edwards25519 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return combMulBase(&sc);
}

/// `s * p` over Ristretto255 — `mul` on the underlying Edwards25519 point.
/// Constant-time in `s`, no error union, neutral element as a value.
///
/// ristretto255 is a PRIME-ORDER group, so there is no low-order input to
/// reject and the product is the neutral element iff `s ≡ 0 (mod L)` for a
/// non-identity `p`.
pub fn mulRistretto(p: Ristretto255, s: [32]u8) Ristretto255 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return .{ .p = mul(p.p, sc) };
}

/// `s * B` over Ristretto255 against the ristretto255 base point — the
/// fixed-base comb of `mulBase` (ristretto255's base point IS Edwards25519's,
/// `Ristretto255.basePoint.p`; pinned by a test below).
pub fn mulRistrettoBase(s: [32]u8) Ristretto255 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return .{ .p = combMulBase(&sc) };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const scalar = Edwards25519.scalar;

test {
    // Opt-in micro-benchmark (audit C9); skips unless CT25519_BENCH is set.
    _ = @import("bench.zig");
}

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

test "mul: reads ALL 256 scalar bits (no silent truncation of the top window)" {
    // Every other test in this file feeds a scalar that is either reduced
    // mod `L` (`nthScalar` ⇒ < 2^253) or clamped (RFC 8032 ⇒ bit 255 forced
    // to 0), so bit 255 is set in NONE of them. Masking it off inside `mul`
    // therefore used to leave the suite green — the audit's `I2` injection.
    // Oracles here are BOTH std's `mul` and a doubling chain, so this pins
    // the value and not merely std's agreement with us.
    var bit: u16 = 250;
    while (bit < 256) : (bit += 1) {
        var s = [_]u8{0} ** 32;
        s[bit >> 3] = @as(u8, 1) << @as(u3, @truncate(bit));
        const ours = mulBase(s).toBytes();
        const want = try Edwards25519.basePoint.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &ours);
        var chain = Edwards25519.basePoint;
        var i: u16 = 0;
        while (i < bit) : (i += 1) chain = chain.dbl();
        try testing.expectEqualSlices(u8, &chain.toBytes(), &ours);
    }
    // 2^256 - 1: an unreduced scalar far above `L`, to pin that nothing
    // silently reduces or rejects it.
    const ones = [_]u8{0xff} ** 32;
    const want_ones = try Edwards25519.basePoint.mul(ones);
    try testing.expectEqualSlices(u8, &want_ones.toBytes(), &mulBase(ones).toBytes());
}

test "mul: degenerate INPUT points, where std refuses to answer at all" {
    // This module deliberately drops std's `WeakPublicKey` check on the
    // point (see the module doc comment), so it answers on inputs std
    // rejects — and those answers were previously untested. The oracle is
    // repeated addition: independent of std's ladder AND of this one.
    const s = nthScalar(9_001);
    try testing.expectEqualSlices(
        u8,
        &Edwards25519.identityElement.toBytes(),
        &mul(Edwards25519.identityElement, s).toBytes(),
    );

    // A point of order exactly 8 (asserted below) — the RFC 8032 §5.1.7
    // "small order" shape. std's `mul` refuses it outright.
    const torsion_bytes = [_]u8{
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
        0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
        0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    };
    const t8 = try Edwards25519.fromBytes(torsion_bytes);
    try testing.expectError(error.WeakPublicKey, t8.mul(s));
    try testing.expectError(error.WeakPublicKey, t8.rejectLowOrder());

    const id_bytes = Edwards25519.identityElement.toBytes();
    var acc = Edwards25519.identityElement; // acc == k*t8
    var k: u8 = 0;
    while (k < 10) : (k += 1) {
        var sk = [_]u8{0} ** 32;
        sk[0] = k;
        try testing.expectEqualSlices(u8, &acc.toBytes(), &mul(t8, sk).toBytes());
        // order exactly 8: identity at k = 0 and k = 8, nowhere between.
        const is_id = std.mem.eql(u8, &acc.toBytes(), &id_bytes);
        try testing.expectEqual(k % 8 == 0, is_id);
        acc = acc.add(t8);
    }
}

test "mulBase/mulRistrettoBase take the comptime base table, and both table paths agree" {
    // The comptime table is reached only while std still marks its own base
    // points `is_base` — a std internal this module cannot enforce. If a std
    // upgrade ever built `Ristretto255.basePoint` from bytes instead, every
    // `mulRistrettoBase` call would quietly start doing an online 15-entry
    // precomputation and no other test would notice. Pin the precondition.
    try testing.expect(Edwards25519.basePoint.is_base);
    try testing.expect(Ristretto255.basePoint.p.is_base);

    // ...and the comptime-folded table must agree with the online one, so a
    // future divergence is a red test rather than only a slowdown.
    const b = try Edwards25519.fromBytes(Edwards25519.basePoint.toBytes());
    try testing.expect(!b.is_base);
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const s = nthScalar(i +% 7_000);
        try testing.expectEqualSlices(u8, &mulBase(s).toBytes(), &mul(b, s).toBytes());
    }
}

// ── C3 comb: P5 evidence 1 + 2 (bit-exact KAT set and randomized
// differential against the pre-C3 algorithm). The reference is
// `mul(Edwards25519.basePoint, s)` / `mulRistretto(Ristretto255.basePoint, s)`:
// that is, byte for byte, the ladder `mulBase`/`mulRistrettoBase` ran before
// C3 (`git show 74645800:modules/ct25519/src/root.zig`), and it stays in the
// module exactly so this comparison never loses its oracle. Every comparison
// is on the canonical 32-byte encoding.

fn expectCombMatchesLadder(s: [32]u8) !void {
    try testing.expectEqualSlices(
        u8,
        &mul(Edwards25519.basePoint, s).toBytes(),
        &mulBase(s).toBytes(),
    );
    try testing.expectEqualSlices(
        u8,
        &mulRistretto(Ristretto255.basePoint, s).toBytes(),
        &mulRistrettoBase(s).toBytes(),
    );
}

test "C3 comb: every nibble value at every position vs the ladder (all 256 table entries, both signs, every carry)" {
    // `v·16^pos` for pos 0..63, v 0..15. v in 1..7 selects `+tab[pos/2][v-1]`;
    // v in 8..15 recodes to `-(16-v)` (magnitudes 8..1, the negative half)
    // with a carry into pos+1 — or, at pos 63, into `comb_carry`. Odd `pos`
    // go through the doubling pass, even ones do not. So this set reaches
    // every entry of `comb_table` with both signs and the carry point.
    var n: usize = 0;
    for (0..64) |pos| {
        for (0..16) |v| {
            var s = [_]u8{0} ** 32;
            s[pos >> 1] = @as(u8, @intCast(v)) << @as(u3, @intCast(4 * (pos & 1)));
            try expectCombMatchesLadder(s);
            n += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1024), n);
}

test "C3 comb: carry-chain and boundary scalars vs the ladder" {
    var order: [32]u8 = undefined;
    std.mem.writeInt(u256, &order, scalar.field_order, .little);
    const L: u256 = scalar.field_order;
    const ints = [_]u256{
        0, 1, 2, 7, 8, 9, 15, 16, 17,
        L - 1,          L,              L + 1,    2 * L,          ~L +% 1, // 2^256 - L
        1 << 252,       (1 << 252) - 1, 1 << 253, (1 << 255) - 1, 1 << 255,
        (1 << 255) + 1,
        ~@as(u256, 0), // 2^256 - 1: all 64 digits carry
        ~@as(u256, 0) - 1,
        0x8888888888888888888888888888888888888888888888888888888888888888, // every digit -8, carry ripples through all 64
        0x7777777777777777777777777777777777777777777777777777777777777777, // every digit +7, no carry
        0x7878787878787878787878787878787878787878787878787878787878787878,
        0x8787878787878787878787878787878787878787878787878787878787878787,
        0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0,
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f,
        0x8000000000000000000000000000000000000000000000000000000000000000,
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0x0000000000000000000000000000000000000000000000000000000000000008,
        0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffffff00000000000000000000000000000000,
    };
    for (ints) |x| {
        var s: [32]u8 = undefined;
        std.mem.writeInt(u256, &s, x, .little);
        try expectCombMatchesLadder(s);
    }
    try testing.expectEqualSlices(u8, &order, &blk: {
        var s: [32]u8 = undefined;
        std.mem.writeInt(u256, &s, ints[10], .little);
        break :blk s;
    });
}

test "C3 comb: randomized differential vs the ladder (full 256-bit and reduced scalars)" {
    // Debug is ~50x slower per multiply; the ReleaseFast lane carries the volume.
    const count: usize = if (@import("builtin").mode == .Debug) 200 else 20_000;
    var prng = std.Random.DefaultPrng.init(0xC3_C0_4B_25_51_9E);
    const random = prng.random();
    for (0..count) |i| {
        var s: [32]u8 = undefined;
        random.bytes(&s); // unreduced, all 256 bits live
        if (i % 2 == 1) s = scalar.reduce(s);
        try expectCombMatchesLadder(s);
    }
}

test "C3 comb: the recoding reconstructs every 256-bit scalar, digits in [-8, 7]" {
    // Isolates `combRecode` from the table: a recoding fault that happens to
    // cancel in the point arithmetic still shows up here as an integer.
    var prng = std.Random.DefaultPrng.init(0x5EC0DE);
    const random = prng.random();
    const fixed = [_]u256{ 0, ~@as(u256, 0), 0x8888888888888888888888888888888888888888888888888888888888888888 };
    for (0..2000 + fixed.len) |i| {
        var s: [32]u8 = undefined;
        if (i < fixed.len) std.mem.writeInt(u256, &s, fixed[i], .little) else random.bytes(&s);
        var e: [64]i8 = undefined;
        const carry = combRecode(&s, &e);
        try testing.expect(carry <= 1);
        var acc: i512 = @as(i512, carry) << 256;
        var k: usize = 64;
        while (k > 0) {
            k -= 1;
            try testing.expect(e[k] >= -8 and e[k] <= 7);
            acc += @as(i512, e[k]) << @as(u9, @intCast(4 * k));
        }
        try testing.expectEqual(@as(i512, std.mem.readInt(u256, &s, .little)), acc);
    }
}

test "C3 comb: the table holds (k+1)·16^(2j)·B and the carry point is 2^256·B" {
    // Independent of the comb's evaluation order: each entry against the
    // ladder on the scalar it claims to be. 2^256·B has no 32-byte scalar, so
    // it is checked as 16·(2^252·B), i.e. four doublings of a ladder result.
    for (0..comb_rows) |j| {
        for (0..comb_teeth) |k| {
            var s = [_]u8{0} ** 32;
            s[j] = @intCast(k + 1); // byte j = 16^(2j)
            try testing.expectEqualSlices(u8, &mul(Edwards25519.basePoint, s).toBytes(), &comb_table[j][k].toBytes());
        }
    }
    var s252 = [_]u8{0} ** 32;
    s252[31] = 0x10;
    const want = mul(Edwards25519.basePoint, s252).dbl().dbl().dbl().dbl();
    try testing.expectEqualSlices(u8, &want.toBytes(), &comb_carry.toBytes());
    // ristretto255's base point is Edwards25519's, which `mulRistrettoBase`
    // relies on when it calls the Edwards comb.
    try testing.expectEqualSlices(u8, &Edwards25519.basePoint.toBytes(), &Ristretto255.basePoint.p.toBytes());
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
