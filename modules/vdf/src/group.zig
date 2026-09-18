// SPDX-License-Identifier: MIT

//! group — the Z_N* wrapper `vdf` computes in: `std.crypto.ff.Modulus`
//! sized for a 2048-bit modulus, plus the canonical **RSA-2048 Factoring
//! Challenge** number as this module's reference hidden-order group (its
//! factorization is, to the best of public knowledge, unknown to anyone —
//! see `root.zig`'s module doc comment for why that property is what makes
//! a VDF's delay real, and why a caller-supplied `N` does not automatically
//! get the same guarantee).
//!
//! **The VDF's group is the quotient Z_N*/{±1}, not Z_N* itself** — see
//! `canonicalize`. `-1 = N-1` has order 2 in Z_N*, and the Fiat-Shamir
//! prime `l` is odd, so `(-π)^l · x^r = -(π^l · x^r)`: in Z_N* a proof for
//! `y` is also a proof for `N-y`, and a prover picks which of the two
//! "outputs" to publish (measured 2026-09-06: 38 of 38 such forgeries
//! accepted). Boneh-Bünz-Fisch §6 and every production RSA-group VDF work
//! in the quotient for exactly this reason: an element is its class
//! `{v, N-v}`, represented by the smaller of the two. `eval`/`prove` emit
//! that representative, `verify` demands it of `y` and `π` and compares in
//! the quotient — one output per `(N, x, T)` again.
//!
//! No modular-exponentiation primitive is
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
// (63-bit redundant limbs, 4-way half-limb `mulWide`) — correct everywhere but
// slow (~8–29× OpenSSL across this repo's bignum-crypto modules; see
// `montint`'s own module doc comment). `montint` is ALSO constant-time — its
// module doc comment says so, and `scripts/checks/ctgrind.sh` runs three harnesses
// over it with zero leaked branches (`ctgrind-expected.tsv`) — but is built on
// full 2^64-bit limbs plus an amd64 `MULX`/`ADCX`/`ADOX` asm core, which is
// where its speed actually comes from: NOT from dropping constant-time
// behavior (a VDF's Fiat-Shamir transcript — `N`, `x`, `y`, `π`, `l`, `r` — is
// all public, so there would be nothing wrong with a non-CT primitive here,
// but `montint` does not offer one and this module does not need one to be
// fast). We therefore route every squaring/multiply through the sibling
// `montint` module's full-radix-2^64 Montgomery arithmetic — the SAME
// `MontParams`/limb-dispatch pattern `rsa` (`603a493`) and `paillier`
// (`6b587a5`) already use, for the same throughput reason.
//
// Unlike Paillier (whose `n²` and CRT `p²`/`q²` differ in width, forcing a
// runtime slot dispatch), a VDF operates over a SINGLE modulus `N` of a fixed
// `modulus_bits` (2048) ceiling — so one comptime `Modint(modulus_bits)`
// instantiation covers every case. A caller-supplied `N` of fewer bits simply
// occupies the low limbs with leading zero limbs (correct, marginally slower).
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
    // A1 F8: `exp_be.len == 0` is unreachable from this module's own two call
    // sites (`l`/`r` are always `prime_bytes`-wide) but `montPowPublic` is
    // `pub` and re-exported via `vdf.group` — an external caller passing an
    // empty slice must get the mathematically correct `base^0 = 1`, not a
    // `usize` underflow on the `exp_be.len - 1` below (which panicked in
    // Debug/ReleaseSafe and produced a mode-divergent result in ReleaseFast;
    // see `A1/vdf.md` F8). Early-return before that subtraction ever runs.
    if (exp_be.len == 0) return fromMont(m, mod, mod.one_mont);
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

// ── the quotient group Z_N*/{±1} ────────────────────────────────────────────

/// `N - v`: the other member of `v`'s class `{v, N-v}` in Z_N*/{±1}.
pub fn negate(m: Modulus, v: Fe) Fe {
    return m.sub(m.zero, v);
}

/// `min(v, N-v)` — the representative this module uses for the class of
/// `v` in Z_N*/{±1}. `N` is odd, so `v` and `N-v` never tie; and `0` (which
/// `elementFromBytes` already refuses) is the only value equal to its own
/// negation. `eval`'s `y` and `prove`'s `π` are always in this form; a
/// consumer that hashes or compares a VDF output byte for byte therefore
/// sees ONE value per `(N, x, T)`, which is the property a randomness
/// beacon or a leader election needs and which Z_N* alone does not give.
pub fn canonicalize(m: Modulus, v: Fe) Fe {
    const neg = negate(m, v);
    return if (v.compare(neg) == .lt) v else neg;
}

/// Whether `v` is already the representative `canonicalize` would return
/// (`v < N - v`). `verify` requires this of `y` and `π` rather than folding
/// them silently: a verifier that accepted both encodings would hand a
/// caller hashing the raw bytes exactly the two-valued output the quotient
/// exists to remove.
pub fn isCanonical(m: Modulus, v: Fe) bool {
    return v.compare(negate(m, v)) == .lt;
}

/// Whether `v` is the identity of Z_N*/{±1}, i.e. `v ∈ {1, N-1}`. As a VDF
/// input `x` that is a degenerate element: `x^(2^T) = 1` for every `T`, so
/// `eval` is constant in `T` and a "proof of `T` sequential squarings" on it
/// costs nothing — `prove`/`verify` refuse it. (`gcd(v, N) ≠ 1`, the other
/// way to fall outside the unit group, is not checked: deciding it in
/// general means factoring `N` — see `elementFromBytes`.)
pub fn isIdentityClass(m: Modulus, v: Fe) bool {
    const one = m.one();
    return v.eql(one) or negate(m, v).eql(one);
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

test "canonicalize/isCanonical/negate: the class {v, N-v} has one representative, the smaller" {
    const m = try Modulus.fromPrimitive(u64, 1_000_003 * 999_983); // N = 999985999949
    const small = try Fe.fromPrimitive(u64, m, 12345);
    const large = negate(m, small); // N - 12345
    try testing.expect(try large.toPrimitive(u64) == 999_985_999_949 - 12345);
    try testing.expect(isCanonical(m, small));
    try testing.expect(!isCanonical(m, large));
    try testing.expect(canonicalize(m, small).eql(small));
    try testing.expect(canonicalize(m, large).eql(small));
    // Right at the middle: (N-1)/2 is canonical, (N+1)/2 is its negation.
    const mid_lo = try Fe.fromPrimitive(u64, m, (999_985_999_949 - 1) / 2);
    const mid_hi = try Fe.fromPrimitive(u64, m, (999_985_999_949 + 1) / 2);
    try testing.expect(isCanonical(m, mid_lo));
    try testing.expect(!isCanonical(m, mid_hi));
    try testing.expect(negate(m, mid_lo).eql(mid_hi));
    // The identity class: 1 and N-1, and nothing else nearby.
    try testing.expect(isIdentityClass(m, m.one()));
    try testing.expect(isIdentityClass(m, negate(m, m.one())));
    try testing.expect(!isIdentityClass(m, try Fe.fromPrimitive(u64, m, 2)));
    try testing.expect(!isIdentityClass(m, negate(m, try Fe.fromPrimitive(u64, m, 2))));
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

// (A1 F8) `montPowPublic` with an empty exponent: `exp_be.len - 1` used to
// underflow before ever entering the loop — a panic in Debug/ReleaseSafe, a
// mode-divergent result in ReleaseFast (see `A1/vdf.md` F8). It is
// unreachable from this module's own two call sites (`l`/`r` are always
// `prime_bytes` wide) but the function is `pub` and re-exported via
// `vdf.group`, so an external caller's empty exponent must get the
// mathematically correct `base^0 = 1` in EVERY build mode, not UB. This test
// is the one place in the suite that reaches `montPowPublic` with a
// zero-length `exp_be` at all.
test "montPowPublic: empty exponent is base^0 = 1, in every build mode (A1 F8)" {
    const m = try Modulus.fromPrimitive(u64, 1_000_003 * 999_983);
    const mod = montModulus(m);
    const base = try Fe.fromPrimitive(u64, m, 12345);
    const result = montPowPublic(m, &mod, base, &.{});
    try testing.expect(result.eql(m.one()));
}
