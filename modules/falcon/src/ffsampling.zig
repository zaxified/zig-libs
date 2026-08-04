// SPDX-License-Identifier: MIT
//! ffsampling — Falcon/FN-DSA fast-Fourier trapdoor sampler. Ported from
//! the Round-3 reference `sign.c` (`do_sign_dyn` + `ffSampling_fft_dyntree`)
//! so signatures are BYTE-EXACT against the reference KATs.
//!
//! Design note (why `dyntree`, not the expanded-key tree): the NIST KAT
//! generator signs via `crypto_sign` → `Zf(sign_dyn)`, which builds the
//! ffLDL tree *dynamically* per signature (`ffSampling_fft_dyntree`) rather
//! than from a precomputed `expand_privkey` tree. Both are the same
//! algorithm and yield identical output, but to eliminate ALL byte-exact
//! risk we mirror exactly what generated the vectors. Consequently
//! `Tree(Ring)` just carries the small secret basis (f,g,F,G);
//! `sampleSignature` does the whole Gram-matrix / LDL / nearest-plane walk
//! on each call, exactly as `do_sign_dyn` does.
//!
//! `splitFft`/`mergeFft` here are thin wrappers over `fft.polySplitFft`/
//! `fft.polyMergeFft` (the real work lives in fft.zig on flat buffers).

const std = @import("std");
const fft = @import("fft.zig");
const fpr = @import("fpr.zig");
const gaussian = @import("gaussian.zig");

/// The secret NTRU basis, carried from keygen to signing. (Named `Tree`
/// for API compatibility with the scaffold; it is the basis, not a
/// precomputed tree — see the module doc comment.)
pub fn Tree(comptime Ring: type) type {
    return struct {
        f: [Ring.n]i8 = undefined,
        g: [Ring.n]i8 = undefined,
        big_f: [Ring.n]i8 = undefined,
        big_g: [Ring.n]i8 = undefined,
    };
}

/// splitfft (spec §3.8.3 Alg.7) over a flat FFT-domain buffer.
pub fn splitFft(logn: u5, a: []const f64, f0: []f64, f1: []f64) void {
    fft.polySplitFft(f0, f1, a, logn);
}

/// mergefft (spec §3.8.3 Alg.8), inverse of `splitFft`.
pub fn mergeFft(logn: u5, f0: []const f64, f1: []const f64, out: []f64) void {
    fft.polyMergeFft(out, f0, f1, logn);
}

/// Build the signing "tree" — here, just capture the secret basis. The
/// heavy ffLDL work happens per-signature in `sampleSignature`
/// (`do_sign_dyn` semantics), so this is O(n) copying.
pub fn buildTree(
    comptime Ring: type,
    f: *const [Ring.n]i8,
    g: *const [Ring.n]i8,
    big_f: *const [Ring.n]i8,
    big_g: *const [Ring.n]i8,
) Tree(Ring) {
    return .{ .f = f.*, .g = g.*, .big_f = big_f.*, .big_g = big_g.* };
}

/// One drawn signature candidate (s1, s2) before the norm-bound check.
pub fn SignatureCandidate(comptime Ring: type) type {
    return struct { s1: [Ring.n]i16, s2: [Ring.n]i16 };
}

fn smallToFpr(dst: []f64, src: []const i8) void {
    for (dst, src) |*d, s| d.* = fpr.of(s);
}

/// The fast-Fourier nearest-plane recursion over a dynamically-decomposed
/// Gram matrix (reference `ffSampling_fft_dyntree`). Modifies g00/g01/g11
/// in place; writes the sampled lattice offset over (t0, t1). `tmp` is
/// scratch (>= see S(logn) bound in ffsampling; 4*n suffices for logn<=10).
fn ffSamplingDyntree(
    comptime orig_logn: u5,
    prng: *gaussian.Prng,
    t0: []f64,
    t1: []f64,
    g00: []f64,
    g01: []f64,
    g11: []f64,
    logn: u5,
    tmp: []f64,
) void {
    if (logn == 0) {
        var leaf = g00[0];
        leaf = fpr.mul(fpr.sqrt(leaf), fpr.inv_sigma[orig_logn]);
        t0[0] = fpr.of(gaussian.samplerZ(prng, t0[0], leaf, fpr.sigma_min[orig_logn]));
        t1[0] = fpr.of(gaussian.samplerZ(prng, t1[0], leaf, fpr.sigma_min[orig_logn]));
        return;
    }
    const n: usize = @as(usize, 1) << logn;
    const hn = n >> 1;

    // Decompose G = LDL; d00 stays in g00, d11 -> g11, l10 -> g01.
    fft.polyLdlFft(g00, g01, g11, logn);

    // Split d00 and d11 in place; stash l10 (g01) into tmp[0..n].
    fft.polySplitFft(tmp[0..hn], tmp[hn..n], g00[0..n], logn);
    @memcpy(g00[0..n], tmp[0..n]);
    fft.polySplitFft(tmp[0..hn], tmp[hn..n], g11[0..n], logn);
    @memcpy(g11[0..n], tmp[0..n]);
    @memcpy(tmp[0..n], g01[0..n]); // l10
    @memcpy(g01[0..hn], g00[0..hn]);
    @memcpy(g01[hn..n], g11[0..hn]);

    // Right sub-tree on split(t1); output merged into tmp[2n..3n].
    fft.polySplitFft(tmp[n .. n + hn], tmp[n + hn .. 2 * n], t1[0..n], logn);
    ffSamplingDyntree(orig_logn, prng, tmp[n .. n + hn], tmp[n + hn .. 2 * n], g11[0..hn], g11[hn..n], g01[hn..n], logn - 1, tmp[2 * n ..]);
    fft.polyMergeFft(tmp[2 * n .. 3 * n], tmp[n .. n + hn], tmp[n + hn .. 2 * n], logn);

    // tb0 = t0 + (t1 - z1) * l10 ; z1(final) written over t1.
    @memcpy(tmp[n .. 2 * n], t1[0..n]);
    fft.polySub(tmp[n .. 2 * n], tmp[2 * n .. 3 * n], logn);
    @memcpy(t1[0..n], tmp[2 * n .. 3 * n]);
    fft.polyMulFft(tmp[0..n], tmp[n .. 2 * n], logn);
    fft.polyAdd(t0[0..n], tmp[0..n], logn);

    // Left sub-tree on split(tb0); output merged over t0.
    fft.polySplitFft(tmp[0..hn], tmp[hn..n], t0[0..n], logn);
    ffSamplingDyntree(orig_logn, prng, tmp[0..hn], tmp[hn..n], g00[0..hn], g00[hn..n], g01[0..hn], logn - 1, tmp[n..]);
    fft.polyMergeFft(t0[0..n], tmp[0..hn], tmp[hn..n], logn);
}

/// ffSampling (spec §3.9.1 Alg.11), specialized to Falcon signing: draw one
/// candidate short vector (s1, s2) for hashed target `c`, using `rng` for
/// all internal randomness. `rng` supplies the 48-byte per-signature seed
/// (reference `crypto_sign`: `randombytes(seed,48)` after the nonce), from
/// which the ChaCha20 signer PRNG is initialised via SHAKE256.
///
/// This performs ONE `do_sign_dyn` pass and always returns; the norm-bound
/// accept/reject retry lives in `sign.signWithRng`. (The reference instead
/// re-inits its PRNG from the same SHAKE context on reject; for Falcon-512/
/// 1024 rejection is a ~2^-32 event and never occurs for the embedded KAT
/// vectors, so the two are byte-identical on those. Flag for the owner
/// gate: a rare reject would make `sign.zig`'s fresh-nonce retry diverge
/// from the reference — harmless for correctness, but not KAT-faithful in
/// that measure-zero case.)
pub fn sampleSignature(
    comptime Ring: type,
    tree: *const Tree(Ring),
    c: *const Ring.Poly,
    rng: std.Random,
) SignatureCandidate(Ring) {
    const n = Ring.n;
    const logn = Ring.logn;

    // Per-signature ChaCha PRNG: SHAKE256(seed48) -> 56-byte prng seed.
    // Every buffer below either carries the per-signature RNG seed/state
    // or derives directly from the secret NTRU basis (the Gram matrix and
    // the ffSampling nearest-plane scratch); none of it is the returned
    // signature candidate itself, so it is wiped on return rather than
    // left resident on the stack (see the module's secureZero rationale
    // in `README.md`/`SPEC.md`).
    var seed48: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed48);
    rng.bytes(&seed48);
    var sh = std.crypto.hash.sha3.Shake256.init(.{});
    sh.update(&seed48);
    var pseed: [56]u8 = undefined;
    defer std.crypto.secureZero(u8, &pseed);
    sh.squeeze(&pseed);
    var prng = gaussian.Prng.init(&pseed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&prng));

    var b00: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &b00);
    var b01: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &b01);
    var b10: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &b10);
    var b11: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &b11);
    var g00: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &g00);
    var g01: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &g01);
    var g11: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &g11);
    var t0: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &t0);
    var t1: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &t1);
    var tx: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &tx);
    var ty: [n]f64 = undefined;
    defer std.crypto.secureZero(f64, &ty);
    var scratch: [4 * n]f64 = undefined;
    defer std.crypto.secureZero(f64, &scratch);

    // Basis B = [[g, -f], [G, -F]] in FFT domain.
    smallToFpr(&b01, &tree.f);
    smallToFpr(&b00, &tree.g);
    smallToFpr(&b11, &tree.big_f);
    smallToFpr(&b10, &tree.big_g);
    fft.fftRaw(&b01, logn);
    fft.fftRaw(&b00, logn);
    fft.fftRaw(&b11, logn);
    fft.fftRaw(&b10, logn);
    fft.polyNeg(&b01, logn);
    fft.polyNeg(&b11, logn);

    // Gram matrix G = B*adj(B) (upper triangle g00,g01,g11).
    @memcpy(&t0, &b01);
    fft.polyMulselfadjFft(&t0, logn); // t0 = b01*adj(b01)
    @memcpy(&t1, &b00);
    fft.polyMulAdjFft(&t1, &b10, logn); // t1 = b00*adj(b10)
    fft.polyMulselfadjFft(&b00, logn); // b00 = b00*adj(b00)
    fft.polyAdd(&b00, &t0, logn); // b00 = g00
    @memcpy(&t0, &b01); // save original b01 (= -FFT(f))
    fft.polyMulAdjFft(&b01, &b11, logn); // b01 = b01*adj(b11)
    fft.polyAdd(&b01, &t1, logn); // b01 = g01
    fft.polyMulselfadjFft(&b10, logn); // b10 = b10*adj(b10)
    @memcpy(&t1, &b11);
    fft.polyMulselfadjFft(&t1, logn); // t1 = b11*adj(b11)
    fft.polyAdd(&b10, &t1, logn); // b10 = g11

    @memcpy(&g00, &b00);
    @memcpy(&g01, &b01);
    @memcpy(&g11, &b10);
    // b01 (variable) is now the saved -FFT(f); b11 is still -FFT(F).
    @memcpy(&b01, &t0);

    // Target vector [hm, 0] transformed by the basis.
    for (&t0, c) |*x, hv| x.* = fpr.of(hv);
    fft.fftRaw(&t0, logn);
    const ni = fpr.inverse_of_q;
    @memcpy(&t1, &t0);
    fft.polyMulFft(&t1, &b01, logn);
    fft.polyMulconst(&t1, fpr.neg(ni), logn);
    fft.polyMulFft(&t0, &b11, logn);
    fft.polyMulconst(&t0, ni, logn);

    // Sample; result over (t0, t1).
    ffSamplingDyntree(logn, &prng, &t0, &t1, &g00, &g01, &g11, logn, &scratch);

    // Rebuild the basis (destroyed above) and map the tiny vector back.
    smallToFpr(&b01, &tree.f);
    smallToFpr(&b00, &tree.g);
    smallToFpr(&b11, &tree.big_f);
    smallToFpr(&b10, &tree.big_g);
    fft.fftRaw(&b01, logn);
    fft.fftRaw(&b00, logn);
    fft.fftRaw(&b11, logn);
    fft.fftRaw(&b10, logn);
    fft.polyNeg(&b01, logn);
    fft.polyNeg(&b11, logn);

    @memcpy(&tx, &t0);
    @memcpy(&ty, &t1);
    fft.polyMulFft(&tx, &b00, logn);
    fft.polyMulFft(&ty, &b10, logn);
    fft.polyAdd(&tx, &ty, logn);
    @memcpy(&ty, &t0);
    fft.polyMulFft(&ty, &b01, logn);
    @memcpy(&t0, &tx);
    fft.polyMulFft(&t1, &b11, logn);
    fft.polyAdd(&t1, &ty, logn);
    fft.ifftRaw(&t0, logn);
    fft.ifftRaw(&t1, logn);

    var out: SignatureCandidate(Ring) = undefined;
    for (0..n) |u| {
        const z: i32 = @as(i32, c[u]) - @as(i32, @intCast(fpr.rint(t0[u])));
        out.s1[u] = @intCast(z);
    }
    for (0..n) |u| {
        out.s2[u] = @intCast(-fpr.rint(t1[u]));
    }
    return out;
}

test "Tree(Ring) instantiates for both parameter sets" {
    const poly = @import("poly.zig");
    var t512: Tree(poly.Ring512) = .{};
    var t1024: Tree(poly.Ring1024) = .{};
    _ = &t512;
    _ = &t1024;
}
