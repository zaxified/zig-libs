// SPDX-License-Identifier: MIT

//! group — the Z_N* wrapper `vdf` computes in: `std.crypto.ff.Modulus`
//! sized for a 2048-bit modulus, plus the canonical **RSA-2048 Factoring
//! Challenge** number as this module's reference hidden-order group (its
//! factorization is, to the best of public knowledge, unknown to anyone —
//! see `root.zig`'s module doc comment for why that property is what makes
//! a VDF's delay real, and why a caller-supplied `N` does not automatically
//! get the same guarantee). No modular-exponentiation primitive is
//! reimplemented here — every operation below is a thin, allocation-free
//! wrapper over `std.crypto.ff.Modulus`/`.Fe`, the exact same constant-time
//! finite-field type the `rsa` module's `Modulus`/`Fe` alias (see that
//! module's `root.zig`). `vdf` does not literally `@import` `rsa` — see
//! `root.zig`'s `meta.deps` note for why — it declares its own alias of the
//! same std type, sized to exactly the bit width this module needs (2048,
//! vs `rsa`'s 4096-bit ceiling).

const std = @import("std");

/// Bit width of the group modulus `N`. Sized exactly to the RSA-2048
/// Factoring Challenge number (`rsa2048ChallengeModulus`, below) — a
/// caller-supplied `N` of up to this many bits is also accepted (`eval`/
/// `hashToPrime`/`prove`/`verify` all take `N` as a `Modulus` *parameter*,
/// nothing in the public API hardcodes the challenge modulus), but nothing
/// in this module has been sized for anything larger. See `root.zig` for
/// the trusted-setup caveat a caller-supplied `N` carries that the
/// challenge modulus does not.
pub const modulus_bits = 2048;

/// `N` (and every element of Z_N*) canonical serialized length, in bytes.
pub const modulus_bytes = modulus_bits / 8;

/// Fixed-capacity big-unsigned-integer type backing `Modulus`/`Fe` below.
pub const Uint = std.crypto.ff.Uint(modulus_bits);

/// Constant-time finite-field modulus type for `N`. Every VDF operation —
/// `eval`'s sequential squarings, the (future) `prove`/`verify` — goes
/// through this; see `std.crypto.ff`'s doc comments for the underlying
/// Montgomery-ladder arithmetic.
pub const Modulus = std.crypto.ff.Modulus(modulus_bits);

/// A field element mod `N` — every group element (`x`, `y`, the proof `π`)
/// is carried as this type.
pub const Fe = Modulus.Fe;

/// `x^2 mod N`. One call of this IS one "tick" of `eval`'s sequential
/// delay — see `vdf.zig`'s module doc comment for why this single
/// operation, repeated `T` times with no shortcut available to someone who
/// does not know `N`'s factorization, is the entire point of the
/// construction.
pub fn square(m: Modulus, x: Fe) Fe {
    return m.sq(x);
}

/// `x * y mod N`.
pub fn mul(m: Modulus, x: Fe, y: Fe) Fe {
    return m.mul(x, y);
}

// ── montint fast-path backend (the hot modular arithmetic) ──────────────────
//
// `std.crypto.ff` is a portable scalar CONSTANT-TIME Montgomery implementation
// (63-bit redundant limbs, 4-way half-limb `mulWide`) — it protects a secret
// exponent at a ~4–8× throughput cost. A VDF has NO secret exponent: `eval`'s
// `T` sequential squarings, `prove`'s streaming quotient, and `verify`'s
// exponentiations all run on the PUBLIC Fiat-Shamir transcript (`N`, `x`, `y`,
// `π`, `l`, `r`). Paying the constant-time tax here buys nothing — worse, it
// slackens the delay calibration: an adversary with a fast (non-CT) squaring
// finishes `~4–8×` sooner than this `eval` predicts, so any `T` calibrated
// against the slow `eval` UNDERSHOOTS the real delay (see `audit/modules/vdf.md`
// F2). We therefore route every squaring/multiply through the sibling `montint`
// module's full-radix-2^64 Montgomery arithmetic — the SAME `MontParams`/limb-
// dispatch pattern `rsa` (`603a493`) and `paillier` (`6b587a5`) already use.
//
// Unlike Paillier (whose `n²` and CRT `p²`/`q²` differ in width, forcing a
// runtime slot dispatch), a VDF operates over a SINGLE modulus `N` of a fixed
// `modulus_bits` (2048) ceiling — so one comptime `Modint(modulus_bits)`
// instantiation covers every case. A caller-supplied `N` of fewer bits simply
// occupies the low limbs with leading zero limbs (correct, marginally slower).
// `montint` exposes a fast (non-CT) Montgomery multiply as its only mul, which
// is exactly what we want here: no slower CT path is introduced on this public
// data — a faster `eval` TIGHTENS the honesty of the delay calibration.
const montint = @import("montint");

/// The montint Montgomery context for `N`: `L = modulus_bits/64` (32) full
/// 2^64 limbs, precomputed constants (`n0inv`, `R mod N`, `R² mod N`). Reused
/// across all `T` squarings of an `eval`/`prove` so the one-time Montgomery
/// setup (`fromBytesBE`'s constant doubling) is paid once, not per squaring.
pub const MontN = montint.Modint(modulus_bits);

/// A Montgomery-domain group element (`L` little-endian 2^64 limbs). Values
/// stay in this domain across a whole squaring loop — convert in once
/// (`toMont`), square/multiply `T` times, convert out once (`fromMont`).
pub const MontFe = MontN.Elem;

/// Precompute the montint Montgomery context for the group modulus `N`.
/// Cheap (a `toBytes` + the `computeConstants` doubling loop, no per-squaring
/// cost) but not free — call once per `eval`/`prove`/`verify`, not per tick.
pub fn montModulus(m: Modulus) MontN {
    var be: [modulus_bytes]u8 = undefined;
    m.toBytes(&be, .big) catch unreachable; // buffer is exactly modulus_bytes
    return MontN.fromBytesBE(&be) catch unreachable; // N is odd, ≥3, ≤ modulus_bits
}

/// Load a validated group element (an `Fe`, value `< N`) into the Montgomery
/// domain: `a → a·R mod N`.
pub fn toMont(mod: *const MontN, x: Fe) MontFe {
    var be: [modulus_bytes]u8 = undefined;
    x.toBytes(&be, .big) catch unreachable; // buffer is exactly modulus_bytes
    const v = mod.elementFromBytesBE(&be) catch unreachable; // x < N (validated upstream)
    return mod.toMontgomery(&v);
}

/// Convert a Montgomery-domain element back to a canonical group `Fe`:
/// `a·R⁻¹ mod N`, re-canonicalized through `Fe`.
pub fn fromMont(m: Modulus, mod: *const MontN, a_mont: MontFe) Fe {
    const v = mod.fromMontgomery(&a_mont);
    var be: [MontN.encoded_bytes]u8 = undefined; // encoded_bytes == modulus_bytes
    mod.toBytesBE(&v, &be);
    return Fe.fromBytes(m, &be, .big) catch unreachable; // v < N
}

/// `1` in the Montgomery domain (`R mod N`) — the accumulator seed for
/// `prove`'s streaming quotient and `verify`'s square-and-multiply.
pub fn montOne(mod: *const MontN) MontFe {
    return mod.one_mont;
}

/// Montgomery-domain squaring — ONE `eval` "tick": `a² · R⁻¹ mod N`, staying
/// resident in the Montgomery domain (no per-call conversion). This is the hot
/// operation the whole rewire exists to speed up.
pub inline fn montSquare(mod: *const MontN, a_mont: MontFe) MontFe {
    return mod.montSqr(&a_mont);
}

/// Montgomery-domain multiply: `a · b · R⁻¹ mod N` (both operands Montgomery-
/// resident). Used for `prove`'s Horner step and `verify`'s combine.
pub inline fn montMulResident(mod: *const MontN, a_mont: MontFe, b_mont: MontFe) MontFe {
    return mod.montMul(&a_mont, &b_mont);
}

/// `base^exp mod N` for a PUBLIC exponent (a Fiat-Shamir transcript value —
/// `l` or `r`; NO secret), via left-to-right square-and-multiply over `exp`'s
/// actual bit length, Montgomery-resident throughout. Variable-time in `exp`
/// is fine (and faster) precisely because `exp` is public — the `montint`
/// analogue of the `ff.powWithEncodedPublicExponent` calls it replaces.
pub fn montPowPublic(m: Modulus, mod: *const MontN, base: Fe, exp_be: []const u8) Fe {
    const base_mont = toMont(mod, base);
    var acc = mod.one_mont;
    var seen = false;
    // Skip leading zero octets (public position — not a value-dependent
    // side-channel concern here); always leave at least one byte.
    var start: usize = 0;
    while (start < exp_be.len - 1 and exp_be[start] == 0) start += 1;
    for (exp_be[start..]) |byte| {
        var mask: u8 = 0x80;
        while (mask != 0) : (mask >>= 1) {
            if (seen) acc = mod.montSqr(&acc);
            if (byte & mask != 0) {
                if (seen) {
                    acc = mod.montMul(&acc, &base_mont);
                } else {
                    acc = base_mont; // first set bit: acc = base^1
                    seen = true;
                }
            }
        }
    }
    // exp == 0 (never happens for l/r, but correct anyway): acc stays R mod N,
    // fromMont → 1 = base^0.
    return fromMont(m, mod, acc);
}

/// Serializes a group element to canonical big-endian bytes
/// (`out.len` must equal `modulus_bytes`; leading zeros included, no
/// compression — this is what `hashToPrime`'s `(N, x, y, T)` binding and
/// `Proof`'s wire codec both hash/carry).
pub fn toBytes(x: Fe, out: []u8) !void {
    return x.toBytes(out, .big);
}

/// Errors `elementFromBytes` rejects an untrusted wire value for.
pub const ElementError = error{
    /// `>= N`, or too many bytes for `Modulus`'s backing `Uint` — the two
    /// cases `std.crypto.ff`'s `FieldElementError.NonCanonical` covers.
    /// This is also what rejects a caller that (mistakenly, or
    /// adversarially) passes `N` itself as an element.
    NonCanonical,
    /// `0` is never a member of Z_N* (no multiplicative inverse) and is a
    /// degenerate VDF input/output/proof value — reject outright rather
    /// than let `mul`/`sq` silently propagate it.
    ZeroElement,
};

/// Decode + validate an untrusted big-endian group element: canonical
/// (`< N`, exactly `Fe.fromBytes`'s own check) and nonzero. This is the
/// "`x`/`y`/`π` outside Z_N* (`0`, `N`, `>= N`) -> reject" gate the module
/// doc comment (`root.zig`) promises for every externally supplied
/// element — `prove`/`verify` run every untrusted element through this
/// before any arithmetic touches it, not re-derive the check ad hoc.
///
/// NOTE: this does NOT check `gcd(v, N) = 1` (full Z_N* membership) —
/// doing so in general requires factoring `N`, exactly the hard problem
/// the hidden-order group relies on staying hard. A non-unit element (a
/// nontrivial factor of `N`) is astronomically unlikely to be hit by
/// chance against the RSA-2048 challenge modulus, and `std.crypto.ff`
/// does not surface non-invertibility as a distinct error class from
/// `mul`/`sq` (those operations are defined over the whole ring Z_N, not
/// just the unit group) — see `root.zig`'s "Caveats" section.
pub fn elementFromBytes(m: Modulus, bytes: []const u8) ElementError!Fe {
    const fe = Fe.fromBytes(m, bytes, .big) catch return error.NonCanonical;
    if (fe.isZero()) return error.ZeroElement;
    return fe;
}

// ── the RSA-2048 Factoring Challenge modulus ────────────────────────────────

/// `N` from the RSA Factoring Challenge (RSA Laboratories, 1991-2007),
/// 2048 bits / 617 decimal digits. Its factorization is, to the best of
/// public knowledge, unknown to anyone — the challenge was discontinued in
/// 2007 with RSA-2048 unclaimed, and no public factorization has surfaced
/// since. See `root.zig`'s module doc comment for why a hidden-order
/// modulus is what makes this VDF's delay unshortcuttable, and why this
/// specific number (rather than an arbitrary caller-supplied `N`) is safe
/// to use as a KAT group with zero trusted-setup caveat.
///
/// Sourced from Wikipedia's "RSA numbers" article, cross-checked
/// byte-for-byte against the article's own raw wikitext (not just its
/// rendered/AI-summarized page — two independent renderings of this page
/// were fetched during development and disagreed with each other in a
/// middle digit run, which is exactly the kind of transcription risk a
/// 617-digit constant invites; the raw wikitext markup, fetched directly,
/// was used to break the tie). See `NOTICE`.
const rsa2048_challenge_hex =
    "c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b" ++
    "7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813" ++
    "a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35" ++
    "b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524a" ++
    "f7e8daefd26c66fc02c479af89d64d373f442709439de66ceb955f3ea37d5159" ++
    "f6135809f85334b5cb1813addc80cd05609f10ac6a95ad65872c909525bdad32" ++
    "bc729592642920f24c61dc5b3c3b7923e56b16a4d9d373d8721f24a3fc0f1b31" ++
    "31f55615172866bccc30f95054c824e733a5eb6817f7bc16399d48c6361cc7e5";

/// The RSA-2048 Factoring Challenge modulus as a `Modulus`. Cheap (no
/// allocation, a hex decode + `Modulus.fromBytes`) but not `comptime` —
/// call once and reuse the result rather than per-iteration in a hot loop.
pub fn rsa2048ChallengeModulus() Modulus {
    var buf: [modulus_bytes]u8 = undefined;
    _ = std.fmt.hexToBytes(&buf, rsa2048_challenge_hex) catch unreachable; // fixed-length, valid-hex literal
    return Modulus.fromBytes(&buf, .big) catch unreachable; // odd, 2048 bits, well within Uint's capacity
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "rsa2048ChallengeModulus: exactly 2048 bits, matches the decimal digit count" {
    const m = rsa2048ChallengeModulus();
    try testing.expectEqual(@as(usize, modulus_bits), m.bits());
}

test "rsa2048ChallengeModulus: round-trips through toBytes" {
    const m = rsa2048ChallengeModulus();
    var buf: [modulus_bytes]u8 = undefined;
    try m.toBytes(&buf, .big);
    const hex = std.fmt.bytesToHex(buf, .lower);
    try testing.expect(std.mem.eql(u8, &hex, rsa2048_challenge_hex));
}

test "square/mul agree with direct std.crypto.ff calls" {
    const m = try Modulus.fromPrimitive(u64, 1_000_003 * 999_983);
    const x = try Fe.fromPrimitive(u64, m, 12345);
    try testing.expect(square(m, x).eql(m.sq(x)));
    const y = try Fe.fromPrimitive(u64, m, 6789);
    try testing.expect(mul(m, x, y).eql(m.mul(x, y)));
}

test "elementFromBytes: rejects 0" {
    const m = rsa2048ChallengeModulus();
    var zero_bytes: [modulus_bytes]u8 = [_]u8{0} ** modulus_bytes;
    try testing.expectError(error.ZeroElement, elementFromBytes(m, &zero_bytes));
}

test "elementFromBytes: rejects N itself and anything >= N (non-canonical)" {
    const m = rsa2048ChallengeModulus();
    var n_bytes: [modulus_bytes]u8 = undefined;
    try m.toBytes(&n_bytes, .big);
    try testing.expectError(error.NonCanonical, elementFromBytes(m, &n_bytes));

    // N + 1: still >= N, still non-canonical.
    var n_plus_1 = n_bytes;
    var i: usize = n_plus_1.len;
    while (i > 0) {
        i -= 1;
        n_plus_1[i] +%= 1;
        if (n_plus_1[i] != 0) break;
    }
    try testing.expectError(error.NonCanonical, elementFromBytes(m, &n_plus_1));
}

test "elementFromBytes: accepts an ordinary small element" {
    const m = rsa2048ChallengeModulus();
    var five: [modulus_bytes]u8 = [_]u8{0} ** modulus_bytes;
    five[modulus_bytes - 1] = 5;
    const fe = try elementFromBytes(m, &five);
    try testing.expect(!fe.isZero());
}

test "toBytes: round trip through elementFromBytes" {
    const m = rsa2048ChallengeModulus();
    var five: [modulus_bytes]u8 = [_]u8{0} ** modulus_bytes;
    five[modulus_bytes - 1] = 5;
    const fe = try elementFromBytes(m, &five);
    var out: [modulus_bytes]u8 = undefined;
    try toBytes(fe, &out);
    try testing.expect(std.mem.eql(u8, &five, &out));
}
