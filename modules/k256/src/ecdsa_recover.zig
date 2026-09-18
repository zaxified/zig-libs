// SPDX-License-Identifier: MIT
//! Recoverable ECDSA/secp256k1 — deterministic (RFC 6979 §3.2) signing plus
//! standard public-key recovery, the two ECDSA operations `sign.zig`
//! deliberately left out (it ships `bip340Sign`/`bip340Verify` (Schnorr) and
//! `ecdsaVerify`, but no ECDSA **sign** and no public **key recovery** — see
//! its own doc comment: "a verification harness surface, not the module's
//! reason to exist"). This file grows that surface with the two pieces
//! several consumers need without duplicating them: Lightning's BOLT#11
//! invoice signature is exactly a *recoverable* compact ECDSA signature
//! (`r || s || recid`), letting a reader recover the payee's node ID
//! straight from the signature when no explicit signer field is present.
//! Originally implemented inside `lninvoice` (the only consumer at the
//! time); moved here once it became clear the functionality is general
//! secp256k1 machinery, not anything BOLT#11-specific.
//!
//!   * `sign` — RFC 6979 §3.2 deterministic-nonce ECDSA (HMAC-SHA256 DRBG).
//!     BOLT#11's own worked examples are generated this way ("Signatures
//!     are deterministic and generated using RFC6979 (using HMAC-SHA256)"),
//!     which is what lets `lninvoice`'s `bolt11.zig` round-trip test
//!     re-derive an official vector's signature byte-for-byte from its
//!     private key — the strongest form of "the encoder is correct" that
//!     consumer has.
//!   * `recoverPubkey` — standard ECDSA public-key recovery,
//!     `Q = r⁻¹·(s·R − e·G)`, `R` lifted from `r` + the recovery id's parity
//!     bit via `Secp256k1.recoverY`. This is the module's actual security
//!     core: it recovers the right key from a genuine signature, and
//!     recovers a WRONG (or non-recoverable) key from a tampered one.
//!
//! Both curve and hash are secp256k1/SHA-256 throughout, so RFC 6979's
//! `bits2octets` needs no bit-shifting (hash length == group-order byte
//! length == 32); the DRBG below is specialized to that case rather than
//! implemented generically.

const std = @import("std");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");
const fieldmod = @import("field.zig");
const sign_mod = @import("sign.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const Secp256k1 = group.Secp256k1;
const Fe = fieldmod.Fe;
const Scalar = scalarmod.Scalar;

/// `int(bytes32) mod n` — the standard ECDSA/RFC6979 hash-to-scalar
/// reduction (a 32-byte hash can exceed the group order `n`, so a plain
/// `Scalar.fromBytes` would wrongly reject the rare oversized hash).
fn reduceToScalar(bytes32: [32]u8) Scalar {
    var wide: [48]u8 = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

// ── RFC 6979 §3.2 deterministic nonce (HMAC-SHA256 DRBG) ────────────────

fn rfc6979Nonce(privkey: [32]u8, hash32: [32]u8) Scalar {
    // bits2octets(H(m)): for this curve/hash pairing (hash length == order
    // byte length) this is exactly `H(m) mod n`, re-encoded big-endian.
    const h1 = reduceToScalar(hash32).toBytes(.big);

    var v: [32]u8 = [_]u8{0x01} ** 32;
    var k: [32]u8 = [_]u8{0x00} ** 32;
    // A1/k256.md G2: `v`/`k` (the DRBG state) and `buf`/`buf2` (which carry
    // `privkey` and, once the loop finds a candidate, the nonce material
    // itself) used to survive unzeroed on the dead stack after this function
    // returns — measured (`.zig-cache/probe/k256_g2_zeroize.zig`, paint +
    // rescan technique): the RFC 6979 nonce `k` (this function's return
    // value, re-encoded) showed up 2/2/2/2/2 across 5 repeats. A leaked
    // nonce plus its signature yields the private key by elementary algebra
    // (`d = (s·k − e)·r⁻¹ mod n`), so this is zeroed like every other
    // secret-derived buffer in the signing path.
    defer std.crypto.secureZero(u8, &v);
    defer std.crypto.secureZero(u8, &k);

    var buf: [32 + 1 + 32 + 32]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    buf[0..32].* = v;
    buf[32] = 0x00;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    buf[0..32].* = v;
    buf[32] = 0x01;
    buf[33..65].* = privkey;
    buf[65..97].* = h1;
    HmacSha256.create(&k, &buf, &k);
    HmacSha256.create(&v, &v, &k);

    while (true) {
        HmacSha256.create(&v, &v, &k);
        // CONSTANT-TIME NOTE (measured, `scripts/ctgrind.sh --stacks k256`,
        // target `ecdsa`): these two lines are the only branches on this
        // module's path that are neither an input/output validation nor the
        // trailing `rejectIdentity`. `Scalar.fromBytes` branches on the DRBG
        // output being canonical, and `cand.isZero()` on the candidate nonce
        // itself — both SECRET. They are kept, deliberately:
        //
        //   * RFC 6979 §3.2 step h defines the retry as a loop, and there is
        //     no rejection-free variant that still produces the RFC's exact
        //     nonce — and the exact nonce is the whole point (it is what makes
        //     BOLT#11's published invoice strings reproducible, and it is what
        //     the anchor test at the bottom of this file pins byte-exact).
        //   * The branch is taken with probability ≈ 2^-127: the DRBG output
        //     is a uniform 256-bit string and the rejected set is
        //     `[n, 2^256) ∪ {0}`, of size `2^256 − n + 1 < 2^129`. An attacker
        //     who observes one retry has learned that one HMAC output landed
        //     in a set they can already enumerate — and will not observe one.
        //     libsecp256k1's `nonce_function_rfc6979` retries on exactly the
        //     same condition for exactly this reason.
        //
        // So this is documented rather than silenced: it is a real
        // secret-dependent branch, it is expected to appear in the harness's
        // `ecdsa` row, and it is not exploitable. Anything ELSE appearing in
        // that row is not covered by this note.
        if (Scalar.fromBytes(v, .big)) |cand| {
            if (!cand.isZero()) return cand;
        } else |_| {}
        var buf2: [32 + 1]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf2);
        buf2[0..32].* = v;
        buf2[32] = 0x00;
        HmacSha256.create(&k, &buf2, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

// ── sign ─────────────────────────────────────────────────────────────────

pub const SignError = error{ InvalidPrivateKey, InvalidNonce };

pub const Signature = struct { r: [32]u8, s: [32]u8, recid: u2 };

/// RFC 6979 deterministic ECDSA sign over secp256k1/SHA-256, returning a
/// compact recoverable signature. `hash32` is the message hash the caller
/// already computed (e.g. BOLT#11: `SHA256(hrp || data-without-signature)`).
///
/// On return, the stack below this frame that the signing computation used
/// has been overwritten with zeros (see `burnSignStack`).
pub fn sign(privkey: [32]u8, hash32: [32]u8) SignError!Signature {
    const result = signInner(privkey, hash32, Secp256k1.combMulBase);
    burnSignStack();
    return result;
}

/// The nonce commitment `R = k·G`. A parameter of `signInner` only so a test
/// can hand the REAL signing code an `R` whose x-coordinate is ≥ n — the
/// recovery-id bit 1 case (A1/k256.md G7), which a genuine nonce reaches with
/// probability ~2^-128. Production passes `Secp256k1.combMulBase`, and only
/// production calls `sign`.
const CommitFn = fn ([32]u8, std.builtin.Endian) IdentityElementError!Secp256k1;

/// How much stack below `sign`'s frame is zeroed after every signature.
///
/// A1/k256.md G2. Zeroing named locals is not enough and cannot be made
/// enough from this file: after `signInner` returns, its callees' dead frames
/// held the nonce `k` SIX times per signature (measured 2026-09-16 with
/// `stackprobe_test.zig`, ReleaseFast: `k` big-endian ×1 — the ABI copy of
/// the `combMulBase(k_bytes)` argument the 2026-09-11 disassembly found — the
/// std scalar field's Montgomery image of `k` ×3, of `k⁻¹` ×1, and of `d` ×1),
/// every one of them a compiler-made copy inside a by-value callee (`Scalar`'s
/// `invert`/`mul`/`toBytes` are std's and take `Fe` by value) with no name the
/// source could zero. Changing `combMulBase` to take a pointer would have
/// removed one of the six. So the fix is on the region, not on the copies: the
/// whole call tree runs one frame down, in `signInner`, and this many bytes of
/// that region are zeroed before `sign` returns — whatever layout a future
/// compiler picks for the frames in between.
///
/// The number is measured, not guessed: with the burn call removed, the probe
/// reads the call tree dirtying 2 608 B below the call site (ReleaseFast,
/// x86_64, 2026-09-16), and 16 KiB covers that about six times over. The probe
/// asserts ZERO residue in every representation, so a call tree that outgrows
/// the burn goes red there.
const sign_stack_burn = 16 * 1024;

/// Zero `sign_stack_burn` bytes starting at the depth `signInner`'s frame
/// occupied. `noinline` on both functions is load-bearing: inlined, the
/// signing frames would merge into `sign`'s own frame, ABOVE this buffer, and
/// the burn would clear nothing that held a secret. `secureZero` writes
/// through a volatile slice, so the dead store survives optimisation.
noinline fn burnSignStack() void {
    var buf: [sign_stack_burn]u8 = undefined;
    std.crypto.secureZero(u8, &buf);
}

noinline fn signInner(privkey: [32]u8, hash32: [32]u8, comptime commit: CommitFn) SignError!Signature {
    const d = Scalar.fromBytes(privkey, .big) catch return error.InvalidPrivateKey;
    if (d.isZero()) return error.InvalidPrivateKey;
    const e = reduceToScalar(hash32);

    var k = rfc6979Nonce(privkey, hash32);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
    var k_bytes = k.toBytes(.big);
    defer std.crypto.secureZero(u8, &k_bytes);
    const R = commit(k_bytes, .big) catch return error.InvalidNonce;
    const Ra = R.affineCoordinates();
    // ECDSA (SEC 1 §4.1.3) defines r = x(R) mod n, and std's signer and
    // libsecp256k1 both reduce. A1/k256.md G7: this line used to be
    // `Scalar.fromBytes(x(R))`, which REJECTS x ≥ n — so a nonce whose R.x
    // landed in [n, p) made `sign` return error.InvalidNonce instead of a
    // signature, and the recid bit-1 line below could never execute. Measured
    // through the seam test at the bottom of this file before the change:
    // "signInner returned error.InvalidNonce for R.x >= n".
    const r = reduceToScalar(Ra.x.toBytes(.big));
    if (r.isZero()) return error.InvalidNonce;
    const s = k.invert().mul(e.add(r.mul(d)));
    if (s.isZero()) return error.InvalidNonce;

    var recid: u2 = if (Ra.y.isOdd()) 1 else 0;
    // bit 1: whether R.x (a field element, < p) needed reduction mod the
    // (slightly smaller) group order n to produce `r` — probability ~2^-128
    // for a real nonce, and reachable only since `r` is reduced above rather
    // than rejected (G7). Pinned by the seam test at the bottom of this file;
    // mirrors `recoverPubkey`'s handling of the same bit.
    if (Ra.x.toInt() >= scalarmod.field_order) recid |= 2;

    // Low-S canonicalization (BIP-62 style): RFC 6979 alone doesn't decide
    // between (r, s) and the equally-valid (r, n-s) [the latter corresponds
    // to the "other" nonce n-k, whose R has the OPPOSITE y parity] -- most
    // ECDSA-over-secp256k1 consumers (and BOLT#11's own worked examples)
    // always report the low-S form, so the parity bit must flip in
    // lockstep with negating `s` to keep recovery self-consistent.
    var s_final = s;
    if (!isLowS(s.toBytes(.big))) {
        s_final = s.neg();
        recid ^= 1;
    }

    return .{ .r = r.toBytes(.big), .s = s_final.toBytes(.big), .recid = recid };
}

// ── recover ──────────────────────────────────────────────────────────────

pub const RecoverError = error{ InvalidScalar, NotSquare, InvalidPoint, IdentityElement };

/// Standard ECDSA public-key recovery: `Q = r⁻¹·(s·R − e·G)`, with `R`
/// lifted from `r` (as an x-coordinate) and `recid`'s bit 0 (`R.y` parity) —
/// bit 1 (x ≥ n) is honored too, though it is essentially never set in
/// practice. Fails closed on a non-canonical `r`/`s`, an `r` that isn't a
/// valid curve x-coordinate (`error.NotSquare` — this is what makes a
/// tampered signature's recovery fail rather than silently succeed with a
/// wrong key, in the common case), or a recovered point at infinity.
pub fn recoverPubkey(hash32: [32]u8, r: [32]u8, s: [32]u8, recid: u2) RecoverError!Secp256k1 {
    const r_scalar = Scalar.fromBytes(r, .big) catch return error.InvalidScalar;
    if (r_scalar.isZero()) return error.InvalidScalar;
    const s_scalar = Scalar.fromBytes(s, .big) catch return error.InvalidScalar;
    if (s_scalar.isZero()) return error.InvalidScalar;

    // u512 headroom: `r` passed `Scalar.fromBytes`, so it is < n, and the
    // recid-bit-1 case reconstructs `x = r + n`, which can reach 2n − 1 > 2^256.
    // Only `x < p` survives the check below, i.e. `r < p − n` (~2^128.6).
    // Exercised by the G7 tests at the bottom of this file.
    var x_wide: u512 = std.mem.readInt(u256, &r, .big);
    if (recid & 2 != 0) {
        x_wide += scalarmod.field_order;
        if (x_wide >= fieldmod.field_order) return error.InvalidScalar;
    }
    var x_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &x_bytes, @intCast(x_wide), .big);
    const x = Fe.fromBytes(x_bytes, .big) catch return error.InvalidScalar;
    const y = Secp256k1.recoverY(x, (recid & 1) != 0) catch return error.NotSquare;
    const R = Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidPoint;

    const e = reduceToScalar(hash32);
    const r_inv = r_scalar.invert();
    const coeff_g = e.neg().mul(r_inv); // coefficient of G
    const coeff_r = s_scalar.mul(r_inv); // coefficient of R
    return Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, coeff_g.toBytes(.big), R, coeff_r.toBytes(.big), .big) catch
        return error.IdentityElement;
}

/// `true` iff `s` is <= half the group order (the "low-S" / BIP-62 rule
/// several ECDSA-over-secp256k1 consumers require of a signer, e.g. BOLT#11
/// when an `n` field pins the signer — high-S is only tolerated on the
/// recovery path).
pub fn isLowS(s: [32]u8) bool {
    const v = std.mem.readInt(u256, &s, .big);
    return v <= (scalarmod.field_order >> 1);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;

test "sign then recoverPubkey round-trips to the signer's own pubkey" {
    var prng = std.Random.DefaultPrng.init(0x1CE0132E);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var privkey: [32]u8 = undefined;
        rand.bytes(&privkey);
        const d = Scalar.fromBytes(privkey, .big) catch continue;
        if (d.isZero()) continue;

        var msg: [32]u8 = undefined;
        rand.bytes(&msg);
        var hash: [32]u8 = undefined;
        Sha256.hash(&msg, &hash, .{});

        const want_pub = Secp256k1.combMulBase(privkey, .big) catch continue;
        const sig = try sign(privkey, hash);
        const recovered = try recoverPubkey(hash, sig.r, sig.s, sig.recid);
        try testing.expect(want_pub.equivalent(recovered));

        // `sign.ecdsaVerify` (this module's own, independent implementation)
        // agrees too.
        var sig_rs: [64]u8 = undefined;
        sig_rs[0..32].* = sig.r;
        sig_rs[32..64].* = sig.s;
        try testing.expect(sign_mod.ecdsaVerify(&want_pub.toCompressedSec1(), &msg, sig_rs));
    }
}

test "recoverPubkey: a bit-flipped signature recovers a DIFFERENT (or non-recoverable) key" {
    var privkey: [32]u8 = undefined;
    @memset(&privkey, 0);
    privkey[31] = 0x42;
    var hash: [32]u8 = undefined;
    @memset(&hash, 0);
    hash[31] = 0x99;

    const want_pub = try Secp256k1.combMulBase(privkey, .big);
    const sig = try sign(privkey, hash);
    const good = try recoverPubkey(hash, sig.r, sig.s, sig.recid);
    try testing.expect(want_pub.equivalent(good));

    var bad_s = sig.s;
    bad_s[31] ^= 0x01;
    if (recoverPubkey(hash, sig.r, bad_s, sig.recid)) |wrong| {
        try testing.expect(!want_pub.equivalent(wrong));
    } else |_| {} // also acceptable: recovery can fail outright
}

test "recoverPubkey: r=0 and s=0 are rejected (error.InvalidScalar), not silently recovered" {
    // Neither zero-r nor zero-s had ever been fed to recoverPubkey by any
    // test before this one (grep-confirmed). Mutation testing shows they
    // are NOT equally defended: disabling `r_scalar.isZero()` alone still
    // fails closed by accident (`r`'s null coefficient forces `r_inv = 0`
    // — std's documented `invert(0) == 0` — which zeroes BOTH scalar-mult
    // coefficients, hitting the already-checked identity path with
    // `error.IdentityElement` instead of `error.InvalidScalar`: same
    // fail-closed *outcome*, different declared reason). Disabling
    // `s_scalar.isZero()` alone is a REAL divergence: `s=0` makes the `R`
    // coefficient zero but leaves the `G` coefficient (`-e·r⁻¹`, from the
    // hash and `r` alone) nonzero in general, so `recoverPubkey` would
    // return a "recovered" point derived ONLY from the hash and `r` —
    // completely ignoring `s`/`R` — instead of failing. This test pins the
    // real contract: both must error, explicitly.
    var privkey: [32]u8 = undefined;
    @memset(&privkey, 0);
    privkey[31] = 0x42;
    var hash: [32]u8 = undefined;
    @memset(&hash, 0);
    hash[31] = 0x99;
    const sig = try sign(privkey, hash);

    const zero = [_]u8{0} ** 32;
    try testing.expectError(error.InvalidScalar, recoverPubkey(hash, zero, sig.s, sig.recid));
    try testing.expectError(error.InvalidScalar, recoverPubkey(hash, sig.r, zero, sig.recid));
}

// ── the deterministic nonce's external anchor ────────────────────────────
//
// WHY THIS TEST EXISTS. Every other test in this file is self-consistent
// under ANY nonce: the round-trip signs and then recovers with the same
// code, so replacing `rfc6979Nonce` with a constant — catastrophic, since
// two signatures under one key then reveal the private key by elementary
// algebra — left all 34 of k256's tests green (measured 2026-08-13, exit 0).
// The only thing in the repository that went red was a CONSUMER,
// `lninvoice`'s BOLT#11 encode KAT. `ecdsa_recover` was moved here FROM
// `lninvoice`, and its anchor stayed behind; this brings one back.
//
// PROVENANCE, precisely. These four constants are the BOLT#11
// specification's own first worked example ("Please make a donation of any
// amount…"), from `lightning/bolts` — the spec repository, not any
// implementation's test suite. They are ATTRIBUTED, under CC-BY 4.0: see
// `../NOTICE`.
//
// ⛔ CORRECTED 2026-09-09. This comment used to call them "a test oracle under
// NOTICE policy §0". They are not. §0's oracle carve-out is for the observable
// behaviour of a program that was RUN, and it says in as many words that
// "numbers read out of an upstream source file by a script are reproduced data,
// not oracle output". Reading them as oracle output also put this module on the
// opposite side of its own siblings' answer about the identical upstream —
// `lnwire` and `lninvoice` both record `lightning/bolts` as CC-BY 4.0. The
// same correction applies to `kat_vectors.zig`'s BIP340 rows, which are
// BSD-2-Clause and likewise attributed in `../NOTICE`:
//
//   * `spec_privkey` and `spec_node_id` are printed literally in BOLT#11's
//     worked-example preamble.
//   * `spec_hash` is the SHA256 of that example's signing preimage
//     (`hrp || data-without-signature`), which the spec's breakdown prints.
//   * `spec_r`/`spec_s`/`spec_recid` are the 65 signature bytes carried by
//     the `lnbc1pvjluez…` string the spec prints — extracted by bech32
//     decoding, which is mechanical, and which `lninvoice`'s own
//     `bolt11.zig` pins in the other direction by rebuilding that literal
//     published string byte-exact from these same numbers.
//
// This is NOT an RFC 6979 vector: RFC 6979's Appendix A.2 publishes
// deterministic-ECDSA vectors for DSA and the NIST curves only (A.2.5 is
// P-256, which `p256/src/kat_vectors.zig` transcribes) — it has no
// secp256k1 section. BOLT#11 is the published secp256k1 RFC-6979 artifact
// this repository actually has offline, and it pins the nonce just as
// tightly: the signature is a function of it.
fn specHex(comptime n: usize, comptime hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const spec_privkey = specHex(32, "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734");
const spec_node_id = specHex(33, "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad");
const spec_hash = specHex(32, "6daf4d488be41ce7cbb487cab1ef2975e5efcea879b20d421f0ef86b07cbb987");
const spec_r = specHex(32, "8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742");
const spec_s = specHex(32, "5e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1");
const spec_recid: u2 = 1;

test "RFC 6979 nonce anchor: BOLT#11's own worked example signs to its published r/s/recid" {
    // (a) The spec's private key really is the spec's node ID — this ties the
    //     tuple below to a published identity rather than to our own output.
    const pub_point = try Secp256k1.combMulBase(spec_privkey, .big);
    try testing.expectEqualSlices(u8, &spec_node_id, &pub_point.toCompressedSec1());

    // (b) THE anchor. `sign` is deterministic, so this is not "a valid
    //     signature" — it is the literal bytes the specification publishes,
    //     and they exist only if `rfc6979Nonce` produces the RFC's exact
    //     nonce for this (key, hash). Any change to the nonce derivation —
    //     a constant nonce, a different DRBG personalisation, dropping the
    //     `bits2octets` reduction — moves `r` completely.
    const sig = try sign(spec_privkey, spec_hash);
    try testing.expectEqualSlices(u8, &spec_r, &sig.r);
    try testing.expectEqualSlices(u8, &spec_s, &sig.s);
    try testing.expectEqual(spec_recid, sig.recid);

    // (c) And the published signature recovers the published node ID, which
    //     is what makes (b)'s `recid` meaningful. Note this half does NOT
    //     depend on the nonce: it runs on the stored constants, so it stays
    //     green under a nonce mutation. Only (b) has teeth there.
    const recovered = try recoverPubkey(spec_hash, spec_r, spec_s, spec_recid);
    try testing.expectEqualSlices(u8, &spec_node_id, &recovered.toCompressedSec1());
}

// ── A1/k256.md G7: recovery-id bit 1, `R.x ≥ n` ─────────────────────────────
//
// No signer will ever produce this case (a nonce lands `R.x` in `[n, p)` with
// probability ~2^-128), and none is needed to test it. Recovery
// `Q = r⁻¹·(s·R − e·G)` is defined for ANY on-curve `R`, and the `(r, s)` it
// recovers from is then a VALID signature under `Q`: verification computes
// `u1·G + u2·Q = e·s⁻¹·G + r·s⁻¹·r⁻¹·(s·R − e·G) = R`, whose x reduces to `r`.
// So the vectors below are built from public values only, and std's ECDSA
// verifier — code that shares nothing with this file's recovery — is the
// oracle that each one is a genuine signature before k256 is asked about it.

const StdCurve = std.crypto.ecc.Secp256k1;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

/// The first `x = n + t` (`t ≥ 1`) that is a curve x-coordinate, lifted by std.
fn highXPoint() !struct { x: u256, p: StdCurve } {
    var t: u256 = 1;
    while (t < 1024) : (t += 1) {
        const x = scalarmod.field_order + t;
        var xb: [32]u8 = undefined;
        std.mem.writeInt(u256, &xb, x, .big);
        const xf = try StdCurve.Fe.fromBytes(xb, .big);
        const y = StdCurve.recoverY(xf, false) catch continue;
        return .{ .x = x, .p = try StdCurve.fromAffineCoordinates(.{ .x = xf, .y = y }) };
    }
    return error.NoHighX;
}

fn beInt(b: [32]u8) u256 {
    return std.mem.readInt(u256, &b, .big);
}

fn beOf(v: u256) [32]u8 {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, v, .big);
    return b;
}

/// std's `r⁻¹·(s·R − e·G)` — what a correct recovery must return.
fn stdRecover(hash: [32]u8, r: [32]u8, s: [32]u8, R: StdCurve) !StdCurve {
    const r_inv = (try Scalar.fromBytes(r, .big)).invert();
    const e = reduceToScalar(hash);
    const u_r = (try Scalar.fromBytes(s, .big)).mul(r_inv);
    const u_g = e.neg().mul(r_inv);
    return StdCurve.mulDoubleBasePublic(R, u_r.toBytes(.big), StdCurve.basePoint, u_g.toBytes(.big), .big);
}

test "G7: recoverPubkey honours recid bit 1 on a genuine signature whose R.x >= n (std-verified vector)" {
    const n = scalarmod.field_order;
    const hp = try highXPoint();
    const r = beOf(hp.x - n);
    const s = beOf(0x5eed_0f_a1_a1_07_6e_b1_7e_0e);
    const msg = "A1 k256 G7: recovery id bit 1";
    var hash: [32]u8 = undefined;
    Sha256.hash(msg, &hash, .{});
    var sig_rs: [64]u8 = undefined;
    sig_rs[0..32].* = r;
    sig_rs[32..64].* = s;

    // Both parities of R: the lifted point has even y, its negation odd y.
    for ([_]StdCurve{ hp.p, hp.p.neg() }) |R| {
        const parity: u2 = @intFromBool(R.affineCoordinates().y.isOdd());
        const q = try stdRecover(hash, r, s, R);
        const q_sec1 = q.toUncompressedSec1();

        // The oracle: std accepts (r, s) under q as a real ECDSA signature.
        try (StdEcdsa.Signature.fromBytes(sig_rs)).verifyPrehashed(hash, try StdEcdsa.PublicKey.fromSec1(&q_sec1));
        try testing.expect(sign_mod.ecdsaVerify(&q_sec1, msg, sig_rs));

        // k256 recovers exactly q with bit 1 set…
        const got = try recoverPubkey(hash, r, s, 2 | parity);
        try testing.expectEqualSlices(u8, &q_sec1, &got.toUncompressedSec1());

        // …and something else (or nothing) with bit 1 clear: then R would be
        // lifted from x = r, a different point.
        if (recoverPubkey(hash, r, s, parity)) |wrong| {
            try testing.expect(!std.mem.eql(u8, &q_sec1, &wrong.toUncompressedSec1()));
        } else |_| {}
    }

    // The upper bound: r + n must stay below p, so r = p − n is refused.
    const p = fieldmod.field_order;
    try testing.expectError(error.InvalidScalar, recoverPubkey(hash, beOf(p - n), s, 2));
}

test "G7: sign sets recid bit 1 and reduces r when R.x >= n (R injected through the signing seam)" {
    const n = scalarmod.field_order;
    const hp = try highXPoint();
    const enc = hp.p.toUncompressedSec1();
    const Injected = struct {
        var point: Secp256k1 = undefined;
        fn commit(_: [32]u8, _: std.builtin.Endian) IdentityElementError!Secp256k1 {
            return point;
        }
    };
    Injected.point = try Secp256k1.fromSec1(&enc);

    var privkey: [32]u8 = undefined;
    for (&privkey, 0..) |*b, i| b.* = @intCast(0x21 +% i);
    const hash = beOf(0x6b_32_35_36_47_37);

    const sig = signInner(privkey, hash, Injected.commit) catch |err| {
        std.debug.print("G7 sign seam: signInner returned error.{t} for R.x >= n\n", .{err});
        return err;
    };
    try testing.expect(sig.recid & 2 != 0);
    try testing.expectEqual(hp.x - n, beInt(sig.r));

    // The signature is not valid under the key (R is not k·G), but its recid
    // must still name the R it was made with: recovery through k256 lands on
    // std's `r⁻¹·(s·R' − e·G)` for the R' of that parity — which catches a
    // low-S flip that forgets to flip the parity bit along with `s`.
    const R_sel = if ((sig.recid & 1) == @intFromBool(hp.p.affineCoordinates().y.isOdd())) hp.p else hp.p.neg();
    const want = try stdRecover(hash, sig.r, sig.s, R_sel);
    const got = try recoverPubkey(hash, sig.r, sig.s, sig.recid);
    try testing.expectEqualSlices(u8, &want.toUncompressedSec1(), &got.toUncompressedSec1());

    // Positive control on the seam: the production commitment on the same key
    // and hash gives an ordinary signature, recid bit 1 clear.
    const real = try sign(privkey, hash);
    try testing.expect(real.recid & 2 == 0);
}

test "isLowS: half-order boundary" {
    var half: [32]u8 = undefined;
    std.mem.writeInt(u256, &half, scalarmod.field_order >> 1, .big);
    try testing.expect(isLowS(half));
    var high: [32]u8 = undefined;
    std.mem.writeInt(u256, &high, (scalarmod.field_order >> 1) + 1, .big);
    try testing.expect(!isLowS(high));
}
