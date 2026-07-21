// SPDX-License-Identifier: MIT

//! kat_test — the VDF known-answer + property/soundness harness.
//!
//! Two tiers:
//!
//! 1. **REAL, UNGATED** (this file's `1.` section below): `eval` and
//!    `hashToPrime` are exercised against BYTE-EXACT reference vectors
//!    computed independently in Python (a different language, and for
//!    `eval`, also a different algorithm — see each test's comment for
//!    exactly how the vector was produced and how to regenerate it). These
//!    run and PASS today; they do not touch `prove`/`verify`.
//! 2. **GATE-GUARDED** (this file's `2.` section below): completeness
//!    (`verify(prove(...))` accepts an honest proof) and soundness (a
//!    tampered `y`/`π`/`T`, or an out-of-range element, is rejected).
//!    These call `prove`/`verify` and RUN today (`gate.core_implemented`
//!    is `true`). The `if (!gate.core_implemented) return SkipZigTest`
//!    guard remains as the one switch `gate.zig` documents — were the
//!    cores ever regated it would report **SKIP** (`error.SkipZigTest`),
//!    never PASS, since a skip is not a green light.
//!
//! No published third-party (N, x, T) -> (y, π) test vector was found for
//! the RSA-Wesolowski construction (searched: the "VDF Alliance"/Chia-
//! Network `vdf-competition` reference, IOTA's `iotaledger/vdf`, POA
//! Network's `poanetwork/vdf` — all three implement Wesolowski, but over a
//! CLASS group, not RSA `Z_N*`, and none publishes byte-level (N,x,T,y,π)
//! fixtures suitable for cross-language embedding). Section 1's `eval`
//! vectors are instead a genuine cross-LANGUAGE check: Python's built-in
//! arbitrary-precision `pow(x, 2**T, N)` computes the identical
//! mathematical quantity via CPython's own (different) modexp code path —
//! see the vectors' comments for the exact one-line command used.

const std = @import("std");
const vdf = @import("root.zig");
const group = vdf.group;
const gate = vdf.gate;

const testing = std.testing;

// ── 1. REAL, UNGATED ────────────────────────────────────────────────────────

// -- 1a. eval, byte-exact vs. an independent Python oracle, real N --------

/// `x = 5` as a canonical `group.modulus_bytes`-wide big-endian element.
fn fiveElement() [group.modulus_bytes]u8 {
    var buf: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
    buf[group.modulus_bytes - 1] = 5;
    return buf;
}

/// Decode a fixed-length hex literal into an array at comptime-known
/// length — small local helper so the vectors below can be written as
/// plain hex strings.
fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "eval: RSA-2048 challenge modulus, x=5, T=1 (KAT: 5^2 mod N)" {
    const m = group.rsa2048ChallengeModulus();
    const x = try group.elementFromBytes(m, &fiveElement());
    const y = vdf.eval(m, x, 1);

    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    // Computed via: python3 -c "N=...; print(pow(5, 2**1, N))" — 25, i.e.
    // 5^2 exactly (sanity: T=1 is a single squaring, checked independently
    // of `eval`'s own loop by construction of the vector).
    const expected = hexBytes(
        "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000019",
    );
    try testing.expect(std.mem.eql(u8, &y_bytes, &expected));
}

test "eval: RSA-2048 challenge modulus, x=5, T=5 (KAT vs. Python pow(5, 2**5, N))" {
    const m = group.rsa2048ChallengeModulus();
    const x = try group.elementFromBytes(m, &fiveElement());
    const y = vdf.eval(m, x, 5);

    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    const expected = hexBytes(
        "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000004ee2d6d415b85acef81",
    );
    try testing.expect(std.mem.eql(u8, &y_bytes, &expected));
}

test "eval: RSA-2048 challenge modulus, x=5, T=1000 (KAT vs. Python pow(5, 2**1000, N))" {
    const m = group.rsa2048ChallengeModulus();
    const x = try group.elementFromBytes(m, &fiveElement());
    const y = vdf.eval(m, x, 1000);

    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    // python3 -c "N=<the 617-digit challenge number>; \
    //   print(pow(5, 2**1000, N).to_bytes(256,'big').hex())"
    const expected = hexBytes(
        "5fca9f54f089b8529cf0181d8b05aea1b660221be8554839aae1907772034262" ++
            "d8eb12a65045434276ee69bfe77819a18a761ee488854d4b227c95fa6b79776e" ++
            "573b10f2762d14a720e8680ee257921fcf8bbe89550bec7516fe9b754381ad9b" ++
            "854913be9163cb199c2818de99f9e8c723e49db5c4f4fffef0d91d6f19672d25" ++
            "2b40de33d5ee6c6cf6144cac0b93ac8bc5a968a579f606680b223694fd78208a" ++
            "8e74a2c17d277f5cb9b135e78f062418bbb3cf8dfc02aa2a1d498bf182c2df22" ++
            "445b865d4313c07bd68fd8a058594457ec721fb7a8b3155c67ef36d1a580c8ef" ++
            "1114c0feeb0d867bf845146ec1937ca8e196bc55383665becfa3fbecf5691dce",
    );
    try testing.expect(std.mem.eql(u8, &y_bytes, &expected));
}

// -- 1b. eval, independent-FORMULA cross-check via a factorization-known --
// --     toy modulus (demonstrates + exercises the trusted-setup caveat) --

test "eval: toy modulus with known factorization — sequential squaring matches Euler's-theorem shortcut" {
    // p=1000003, q=999983 (both prime; verified independently). Knowing
    // the factorization lets a THIRD party compute the exact shortcut
    // `root.zig`'s "Trusted-setup caveat" warns about: reduce the huge
    // exponent `2^T` mod `lambda(N) = lcm(p-1, q-1)` BEFORE exponentiating,
    // instead of performing `T` sequential squarings. If `eval`'s
    // sequential loop and this shortcut disagree, `eval` has a bug — this
    // is a second, independent verification PATH for the same code under
    // test (Euler's theorem, not "run the same loop twice").
    const p: u64 = 1_000_003;
    const q: u64 = 999_983;
    const n: u64 = p * q; // 999985999949
    const lambda: u64 = 499_991_999_982; // lcm(p-1, q-1); (p-1)*(q-1)/gcd(p-1,q-1)

    const m = try group.Modulus.fromPrimitive(u64, n);
    const x = try group.Fe.fromPrimitive(u64, m, 5);

    const t: u64 = 1000;
    const y_sequential = vdf.eval(m, x, t);

    // e = 2^t mod lambda, via plain (non-constant-time — this is a test
    // oracle over PUBLIC values, not a secret-dependent computation)
    // square-and-multiply on `u128`. NOT `std.crypto.ff.Modulus`: lambda
    // is even by construction (`lcm` of two even numbers, `p-1`/`q-1`),
    // and `ff.Modulus` only accepts odd moduli — this shortcut
    // computation is exactly the reason `ff.Modulus` isn't the right tool
    // for a caller who actually knows a factorization, which is the
    // point being demonstrated.
    var e: u64 = 1;
    {
        var base: u128 = 2 % lambda;
        var exp = t;
        while (exp != 0) : (exp >>= 1) {
            if (exp & 1 != 0) e = @intCast((@as(u128, e) * base) % lambda);
            base = (base * base) % lambda;
        }
    }
    var e_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &e_bytes, e, .big);
    const y_shortcut = try m.powWithEncodedExponent(x, &e_bytes, .big);

    try testing.expect(y_sequential.eql(y_shortcut));

    // And both match a value independently computed in Python:
    // python3 -c "print(pow(5, 2**1000, 999985999949))"  ->  833421283368
    const expected_y = try group.Fe.fromPrimitive(u64, m, 833_421_283_368);
    try testing.expect(y_sequential.eql(expected_y));
}

// -- 1c. hashToPrime — byte-exact vs. an independent Python oracle --------

test "hashToPrime: byte-exact vs. an independent Python (SHAKE256 + Miller-Rabin) oracle" {
    const m = group.rsa2048ChallengeModulus();
    var n_bytes: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_bytes, .big);
    const x_bytes = fiveElement();

    const x = try group.elementFromBytes(m, &x_bytes);
    const y = vdf.eval(m, x, 1000);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);

    const l = vdf.hashToPrime(&n_bytes, &x_bytes, &y_bytes, 1000);

    // Computed via an independent Python re-implementation of
    // `deriveCandidate` + `incrementCandidateByTwo` + a from-scratch
    // 64-round Miller-Rabin (see this repo's development notes — same
    // domain tag "zig-libs/vdf/wesolowski/hash-to-prime/v1", same
    // concatenation order domain||N||x||y||T_be64, same top/bottom-bit
    // forcing, same odd-candidate search). Found after 27 odd-candidate
    // increments from the SHAKE256-derived starting point.
    const expected = hexBytes("d8284ae6b1a9587ca36166fa98626d48e234fedf6267548856b3afa6beca8213");
    try testing.expect(std.mem.eql(u8, &l, &expected));
}

test "hashToPrime: changing T alone changes l (binds the delay parameter, not just N/x/y)" {
    const m = group.rsa2048ChallengeModulus();
    var n_bytes: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_bytes, .big);
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const y = vdf.eval(m, x, 1000);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);

    const l_1000 = vdf.hashToPrime(&n_bytes, &x_bytes, &y_bytes, 1000);
    const l_1001 = vdf.hashToPrime(&n_bytes, &x_bytes, &y_bytes, 1001);
    try testing.expect(!std.mem.eql(u8, &l_1000, &l_1001));
}

// ── 2. GATED — needs prove/verify ───────────────────────────────────────────

// -- 2a. Completeness: an honest prover's proof verifies ------------------

test "completeness: verify(prove(eval(x))) accepts, several small T" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    var n_bytes: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_bytes, .big);

    const ts = [_]u64{ 1, 2, 17, 1000, 10_000 };
    for (ts) |t| {
        const x_bytes = fiveElement();
        const x = try group.elementFromBytes(m, &x_bytes);
        const y = vdf.eval(m, x, t);
        var y_bytes: [group.modulus_bytes]u8 = undefined;
        try group.toBytes(y, &y_bytes);

        const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
        try testing.expect(try vdf.verify(m, &x_bytes, &y_bytes, proof, t));
    }
}

test "completeness: different x values all verify" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const t: u64 = 500;
    const xs = [_]u64{ 2, 3, 5, 7, 11, 13 };
    for (xs) |xv| {
        var x_bytes: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
        x_bytes[group.modulus_bytes - 1] = @intCast(xv);
        const x = try group.elementFromBytes(m, &x_bytes);
        const y = vdf.eval(m, x, t);
        var y_bytes: [group.modulus_bytes]u8 = undefined;
        try group.toBytes(y, &y_bytes);

        const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
        try testing.expect(try vdf.verify(m, &x_bytes, &y_bytes, proof, t));
    }
}

// -- 2b. Soundness: everything that must fail, does -----------------------

test "soundness: y off by one squaring is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const t: u64 = 1000;
    const y = vdf.eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);

    const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);

    // The prover's honest proof, checked against a WRONG y (one extra
    // squaring) — must be rejected.
    const y_wrong = group.square(m, y);
    var y_wrong_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y_wrong, &y_wrong_bytes);
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_wrong_bytes, proof, t)));
}

test "soundness: a tampered proof is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const t: u64 = 1000;
    const y = vdf.eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);

    var proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
    proof.pi[proof.pi.len - 1] ^= 1; // flip one bit of pi
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_bytes, proof, t)));
}

test "soundness: wrong T is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const t: u64 = 1000;
    const y = vdf.eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);

    const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_bytes, proof, t + 1)));
}

test "soundness: x/y/pi outside Z_N* (0, N, >= N) are rejected, not UB" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const t: u64 = 100;
    const y = vdf.eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);

    var zero_bytes: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
    var n_bytes: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_bytes, .big);

    // x = 0
    try testing.expect(!(try vdf.verify(m, &zero_bytes, &y_bytes, proof, t)));
    // y = N (non-canonical)
    try testing.expect(!(try vdf.verify(m, &x_bytes, &n_bytes, proof, t)));
    // pi = 0
    var bad_proof = proof;
    bad_proof.pi = zero_bytes;
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_bytes, bad_proof, t)));
    // pi = N (non-canonical)
    bad_proof.pi = n_bytes;
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_bytes, bad_proof, t)));
}

// -- 2c. y-BINDING teeth: the adaptive false-y forgery --------------------
//
// The soundness tests above reject a tampered y/pi/T, but none of them goes
// RED *specifically* if `hashToPrime` stopped binding `y`: rejecting a
// wrong-y-with-honest-pi only needs the ALGEBRAIC check `pi^l*x^r == y` to
// fail, which it does whether or not `l` depends on `y`. The test below is
// the missing y-binding witness. It forges a `(y', pi')` that a verifier
// binding only `(N, x, T)` — NOT `y` — would ACCEPT for a GENUINELY WRONG
// `y'`, then asserts the real `verify` REJECTS it. The forgery: fix `l` from
// a y-independent binding, pick an arbitrary `pi'`, and DEFINE
// `y' := pi'^l * x^r`. Removing `y` from `hashToPrime` would make `verify`
// identical to the `brokenVerifyUnboundY` control below and ACCEPT this
// forgery — so the final assertion flips to failing. That is the tooth.

/// A deliberately BROKEN verifier that binds the challenge prime to
/// `(N, x, T)` only — `y` is replaced by a fixed placeholder, modelling the
/// exact soundness bug `hashToPrime`'s y-binding exists to prevent. Used as a
/// positive control: it must ACCEPT the forgery the real `verify` rejects,
/// which is what proves the forgery is well-formed (the y-binding test is not
/// passing vacuously) and that the y-binding is the sole thing catching it.
fn brokenVerifyUnboundY(m: group.Modulus, x_bytes: []const u8, y_bytes: []const u8, proof: vdf.Proof, t: u64) bool {
    const x = group.elementFromBytes(m, x_bytes) catch return false;
    const y = group.elementFromBytes(m, y_bytes) catch return false;
    const pi = group.elementFromBytes(m, &proof.pi) catch return false;
    var x_canon: [group.modulus_bytes]u8 = undefined;
    group.toBytes(x, &x_canon) catch unreachable;
    var n_canon: [group.modulus_bytes]u8 = undefined;
    m.toBytes(&n_canon, .big) catch unreachable;
    // y EXCLUDED from the Fiat-Shamir binding (the injected soundness bug):
    const y_placeholder = [_]u8{0} ** group.modulus_bytes;
    const l_bytes = vdf.hashToPrime(&n_canon, &x_canon, &y_placeholder, t);
    const lm = vdf.PrimeModulus.fromBytes(&l_bytes, .big) catch unreachable;
    const r = vdf.pow2Mod(lm, t);
    var r_bytes: [vdf.prime_bytes]u8 = undefined;
    r.toBytes(&r_bytes, .big) catch unreachable;
    const mod = group.montModulus(m);
    const pi_l = group.montPowPublic(m, &mod, pi, &l_bytes);
    const x_r = group.montPowPublic(m, &mod, x, &r_bytes);
    return group.mul(m, pi_l, x_r).eql(y);
}

test "soundness (y-binding): an adaptive false-y forgery is rejected by verify but accepted by a y-unbound verifier" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const t: u64 = 1000;
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const y_true = vdf.eval(m, x, t);

    // Build the y-INDEPENDENT challenge l (the same placeholder the broken
    // control uses), then forge y' = pi'^l * x^r for an arbitrary pi'.
    var x_canon: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(x, &x_canon);
    var n_canon: [group.modulus_bytes]u8 = undefined;
    try m.toBytes(&n_canon, .big);
    const y_placeholder = [_]u8{0} ** group.modulus_bytes;
    const l_bytes = vdf.hashToPrime(&n_canon, &x_canon, &y_placeholder, t);
    const lm = try vdf.PrimeModulus.fromBytes(&l_bytes, .big);
    const r = vdf.pow2Mod(lm, t);
    var r_bytes: [vdf.prime_bytes]u8 = undefined;
    try r.toBytes(&r_bytes, .big);

    // Attacker's arbitrary proof element pi' = 7 (any valid group element).
    var pi_bytes: [group.modulus_bytes]u8 = [_]u8{0} ** group.modulus_bytes;
    pi_bytes[group.modulus_bytes - 1] = 7;
    const pi = try group.elementFromBytes(m, &pi_bytes);

    const mod = group.montModulus(m);
    const pi_l = group.montPowPublic(m, &mod, pi, &l_bytes);
    const x_r = group.montPowPublic(m, &mod, x, &r_bytes);
    const y_forged = group.mul(m, pi_l, x_r);
    var y_forged_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y_forged, &y_forged_bytes);

    const proof = vdf.Proof{ .pi = pi_bytes };

    // (i) The forged y' is a GENUINELY wrong VDF output (not the real one) —
    // so accepting it would be a true soundness break, not a relabelling.
    try testing.expect(!y_forged.eql(y_true));
    // (ii) POSITIVE CONTROL: a y-unbound verifier ACCEPTS the forgery, so the
    // forgery is well-formed and the attack is real (this test is not vacuous).
    try testing.expect(brokenVerifyUnboundY(m, &x_canon, &y_forged_bytes, proof, t));
    // (iii) TEETH: the real verifier folds y into l, so it REJECTS. Any
    // y-independent binding (the mutation `brokenVerifyUnboundY` models) makes
    // this forgery verify — so (iii) flips to accept and goes RED. Confirmed
    // by a mutation check: stripping y from `verify`'s `hashToPrime` call
    // turns this exact assertion red.
    try testing.expect(!(try vdf.verify(m, &x_canon, &y_forged_bytes, proof, t)));
}

test "soundness (y-binding): flipping a single bit of y with the honest pi is rejected" {
    if (!gate.core_implemented) return error.SkipZigTest;

    const m = group.rsa2048ChallengeModulus();
    const x_bytes = fiveElement();
    const x = try group.elementFromBytes(m, &x_bytes);
    const t: u64 = 500;
    const y = vdf.eval(m, x, t);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);

    // Honest proof, but y has its low bit flipped (still a canonical in-range
    // nonzero element) with the SAME pi. Must be rejected.
    var y_tampered = y_bytes;
    y_tampered[group.modulus_bytes - 1] ^= 1;
    try testing.expect(!std.mem.eql(u8, &y_bytes, &y_tampered)); // genuinely different
    try testing.expect(!(try vdf.verify(m, &x_bytes, &y_tampered, proof, t)));
}
