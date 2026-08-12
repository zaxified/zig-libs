// SPDX-License-Identifier: MIT

//! harness_test — the anti-self-consistency verification harness. TFHE gate
//! bootstrapping has NO external byte-exact KAT (TFHE-rs / OpenFHE-binfhe /
//! concrete all differ in encoding and parameters), so a self-consistent-but-
//! wrong core can pass a naive round-trip. This harness defends on three fronts:
//!
//!   1. A NOISELESS cleartext blind-rotation oracle (`clearBootstrap`) that pins
//!      the LUT construction + modulus-switch + rotation indexing WITHOUT the
//!      gated core — the exact place off-by-one/​sign bugs hide.
//!   2. Deliberately-broken POSITIVE CONTROLS that PASS today (teeth before the
//!      core exists): a sign-dropped sample extraction, a dropped-level gadget
//!      decomposition, and a wrong-sign rotation — each is shown to give the
//!      WRONG answer while the real primitive gives the right one.
//!   3. Core-dependent end-to-end anchors (SKIP-gated until the core lands): a
//!      programmable gate (identity refresh / NOT / 2-input AND), an
//!      UNLIMITED-DEPTH bootstrap chain, a corrupted-bootstrap-key control, and
//!      an output-noise-budget assertion.

const std = @import("std");
const testing = std.testing;

const tfhe = @import("tfhe.zig");
const params = @import("params.zig");
const torus = @import("torus.zig");
const gate = @import("gate.zig");

const P = params.toy;
const Toy = tfhe.Tfhe(P);
const T = torus.Torus;

// Identity and NOT LUTs over the 1-bit message space (p=4, Δ=q/4).
fn lutIdentity() Toy.Poly {
    return Toy.testPolynomial(2, .{ Toy.encodeBit(0), Toy.encodeBit(1) });
}
fn lutNot() Toy.Poly {
    return Toy.testPolynomial(2, .{ Toy.encodeBit(1), Toy.encodeBit(0) });
}

// ── 1. Cleartext oracle: the LUT + rotation indexing is correct (no core) ─────

test "clearBootstrap oracle: identity LUT decodes every bit (LUT+modswitch+rotation)" {
    var prng = std.Random.DefaultPrng.init(100);
    const rnd = prng.random();
    const key = Toy.lweKeyGenForTest(64, rnd);
    const lut = lutIdentity();
    for (0..64) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &key, Toy.encodeBit(b), rnd);
        const val = Toy.clearBootstrap(&lut, &ct, &key);
        try testing.expectEqual(b, Toy.decodeBit(val)); // identity: out == in
    }
}

test "clearBootstrap oracle: NOT LUT flips every bit" {
    var prng = std.Random.DefaultPrng.init(101);
    const rnd = prng.random();
    const key = Toy.lweKeyGenForTest(64, rnd);
    const lut = lutNot();
    for (0..64) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &key, Toy.encodeBit(b), rnd);
        try testing.expectEqual(1 - b, Toy.decodeBit(Toy.clearBootstrap(&lut, &ct, &key)));
    }
}

// ── 2a. Positive control: sign-dropped sample extraction is WRONG ─────────────
// Sample extraction of coefficient 0 requires the negacyclic sign flip
// `a_ext[j] = −a(X)_{N−j}`. A version that drops the sign decrypts to a
// different value; the harness proves the correct one is load-bearing.

fn brokenSampleExtract(ct: *const Toy.Glwe) Toy.LweBig {
    const N = P.N;
    var out: Toy.LweBig = undefined;
    out.b = ct.b.c[0];
    out.a[0] = ct.a.c[0];
    var j: usize = 1;
    while (j < N) : (j += 1) out.a[j] = ct.a.c[N - j]; // BUG: missing the `0 -%`
    return out;
}

test "positive control: sign-dropped sample extraction gives the wrong coefficient" {
    var prng = std.Random.DefaultPrng.init(200);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    var wrong_count: usize = 0;
    for (0..40) |_| {
        const b0 = rnd.uintLessThan(u32, 2);
        var msg = Toy.Poly.zero();
        msg.c[0] = Toy.encodeBit(b0);
        for (msg.c[1..]) |*c| c.* = Toy.encodeBit(rnd.uintLessThan(u32, 2));
        const ct = Toy.glweEncryptForTest(&gk, &msg, rnd);
        // real extraction is always correct …
        try testing.expectEqual(b0, Toy.lweDecryptBit(P.N, &big_key, &Toy.sampleExtract(&ct)));
        // … the broken one is wrong on some inputs (the checker bites).
        const broken = brokenSampleExtract(&ct);
        if (Toy.lweDecryptBit(P.N, &big_key, &broken) != b0) wrong_count += 1;
    }
    try testing.expect(wrong_count > 0);
}

// ── 2b. Positive control: dropped-level gadget decomposition exceeds the bound ─
const gadget = @import("gadget.zig");

test "positive control: dropping a gadget level exceeds the decomposition error bound" {
    const b_bits = P.bg_bits;
    const ell = P.ell;
    const bound = gadget.maxError(b_bits, ell);
    // A value whose (ell)-th digit is large: its omission blows the bound.
    // recompose of only the top (ell-1) digits must exceed `bound` somewhere.
    var prng = std.Random.DefaultPrng.init(201);
    const rnd = prng.random();
    var saw_violation = false;
    for (0..4000) |_| {
        const x = rnd.int(T);
        const full = gadget.decompose(b_bits, ell, x);
        // real: within bound.
        const back_full = gadget.recompose(b_bits, ell, full);
        try testing.expect(@min(x -% back_full, back_full -% x) <= bound);
        // broken: drop the least-significant level (zero it out).
        var dropped = full;
        dropped[ell - 1] = 0;
        const back_drop = gadget.recompose(b_bits, ell, dropped);
        if (@min(x -% back_drop, back_drop -% x) > bound) saw_violation = true;
    }
    try testing.expect(saw_violation);
}

// ── 2c. Positive control: wrong-sign rotation exponent breaks the LUT lookup ──
// This directly targets the classic blind-rotation off-by-one/sign bug: the
// accumulator must rotate by `−b̃ + Σ ã_i s_i`. Flipping the sign of the phase
// reads the wrong LUT slot.

fn brokenClearBootstrap(lut: *const Toy.Poly, ct: *const Toy.LweN, key: *const Toy.LweKey(64)) T {
    const two_n = 2 * P.N;
    var rot: usize = Toy.modSwitchScalar(ct.b) % two_n; // BUG: +b̃ instead of −b̃
    for (ct.a, key.s) |ai, si| {
        if (si == 1) rot = (rot + (two_n - Toy.modSwitchScalar(ai))) % two_n; // and −ã
    }
    return lut.mulMonomial(rot).constTerm();
}

test "positive control: wrong-sign rotation exponent misdecodes (checker bites)" {
    var prng = std.Random.DefaultPrng.init(202);
    const rnd = prng.random();
    const key = Toy.lweKeyGenForTest(64, rnd);
    const lut = lutIdentity();
    var real_ok = true;
    var broken_wrong = false;
    for (0..64) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &key, Toy.encodeBit(b), rnd);
        if (Toy.decodeBit(Toy.clearBootstrap(&lut, &ct, &key)) != b) real_ok = false;
        if (Toy.decodeBit(brokenClearBootstrap(&lut, &ct, &key)) != b) broken_wrong = true;
    }
    try testing.expect(real_ok); // the correct rotation is always right …
    try testing.expect(broken_wrong); // … the sign-flipped one is not.
}

// ── 3. End-to-end anchors (SKIP-gated until the Fable core lands) ─────────────

const KeySet = struct {
    small: Toy.LweKey(64),
    glwe: Toy.GlweKey,
    bsk: Toy.BootstrapKey,
    ksk: Toy.KeySwitchKey,
};

fn setupKeys(rnd: std.Random) KeySet {
    const small = Toy.lweKeyGenForTest(64, rnd);
    const glwe = Toy.glweKeyGenForTest(rnd);
    return .{
        .small = small,
        .glwe = glwe,
        .bsk = Toy.bootstrapKeyGenForTest(&small, &glwe, rnd),
        .ksk = Toy.keySwitchKeyGenForTest(&glwe, &small, rnd),
    };
}

test "programmable gate: bootstrap(identity) and bootstrap(NOT) decode correctly" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(300);
    const rnd = prng.random();
    const ks = setupKeys(rnd);
    const id = lutIdentity();
    const not = lutNot();
    for (0..16) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &ks.small, Toy.encodeBit(b), rnd);
        const refreshed = Toy.bootstrap(&ks.bsk, &ks.ksk, &id, &ct);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &ks.small, &refreshed));
        const negated = Toy.bootstrap(&ks.bsk, &ks.ksk, &not, &ct);
        try testing.expectEqual(1 - b, Toy.lweDecryptBit(64, &ks.small, &negated));
    }
}

test "programmable 2-input gate: homomorphic AND via LWE sum + LUT" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(301);
    const rnd = prng.random();
    const ks = setupKeys(rnd);
    // bits at Δ = q/8 so the sum a+b ∈ {0,1,2} stays in the lower half.
    const d8: T = 1 << 29;
    const and_lut = Toy.testPolynomial(3, .{ 0, 0, d8, 0 }); // AND: 1 only when a+b=2
    for (0..4) |it| {
        const a: u32 = @intCast(it & 1);
        const b: u32 = @intCast((it >> 1) & 1);
        var ca = Toy.lweEncryptForTest(64, &ks.small, torus.encode(a, d8), rnd);
        const cb = Toy.lweEncryptForTest(64, &ks.small, torus.encode(b, d8), rnd);
        for (&ca.a, cb.a) |*x, y| x.* +%= y; // homomorphic add of the two bits
        ca.b +%= cb.b;
        const out = Toy.bootstrap(&ks.bsk, &ks.ksk, &and_lut, &ca);
        const got = torus.decode(Toy.lwePhase(64, &ks.small, &out), 29, 1);
        try testing.expectEqual(a & b, got);
    }
}

test "UNLIMITED DEPTH: a long chain of bootstraps preserves the message" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(302);
    const rnd = prng.random();
    const ks = setupKeys(rnd);
    const id = lutIdentity();
    const chain = 16; // a leveled scheme fails long before this; bootstrapping does not.
    for ([_]u32{ 0, 1 }) |b| {
        var ct = Toy.lweEncryptForTest(64, &ks.small, Toy.encodeBit(b), rnd);
        for (0..chain) |_| {
            ct = Toy.bootstrap(&ks.bsk, &ks.ksk, &id, &ct);
            // message survives every single refresh (noise is RESET, not grown).
            try testing.expectEqual(b, Toy.lweDecryptBit(64, &ks.small, &ct));
        }
    }
}

test "positive control: a corrupted bootstrap key must NOT bootstrap correctly" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(303);
    const rnd = prng.random();
    var ks = setupKeys(rnd);
    // Randomise every GGSW row — the bsk no longer encrypts the secret bits, so
    // blind rotation selects garbage and the output must not decode to the input.
    for (&ks.bsk.ggsw) |*g| {
        for (&g.rows) |*row| {
            for (&row.a.c) |*x| x.* = rnd.int(T);
            for (&row.b.c) |*x| x.* = rnd.int(T);
        }
    }
    const id = lutIdentity();
    var mismatches: usize = 0;
    for (0..8) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &ks.small, Toy.encodeBit(b), rnd);
        const out = Toy.bootstrap(&ks.bsk, &ks.ksk, &id, &ct);
        if (Toy.lweDecryptBit(64, &ks.small, &out) != b) mismatches += 1;
    }
    try testing.expect(mismatches > 0); // the key-switch/CMux path is load-bearing
}

test "noise budget: a bootstrapped ciphertext has noise well below Δ/2" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(304);
    const rnd = prng.random();
    const ks = setupKeys(rnd);
    const id = lutIdentity();
    for (0..16) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &ks.small, Toy.encodeBit(b), rnd);
        const out = Toy.bootstrap(&ks.bsk, &ks.ksk, &id, &ct);
        const phase = Toy.lwePhase(64, &ks.small, &out);
        const clean = Toy.encodeBit(b);
        const noise = @min(phase -% clean, clean -% phase); // |centered noise|
        try testing.expect(noise < (Toy.delta / 2)); // decryptable …
        try testing.expect(noise < (Toy.delta / 4)); // … with comfortable margin (reset)
    }
}
