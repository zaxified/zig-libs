// SPDX-License-Identifier: MIT
//! prng — HQC's SHAKE256-based PRNG/XOF/hash layer and vector samplers.
//!
//! **This is the byte-exactness-critical module of Part 1.** Every
//! construction here is independently verified against the reference
//! implementation's own intermediate-value dump (kat_vectors.zig), not
//! just transcribed from source — see that file's module doc for exactly
//! which fixtures came from where.
//!
//! Two distinct SHAKE256 instantiations exist (spec Table 1, §3.1) and
//! must not be confused:
//!
//! - `Prng` (domain 0): a plain SHAKE256 squeeze, no quirks. This is what
//!   the reference's `prng_init`/`prng_get_bytes` are, and — surprisingly
//!   useful for a future Part 3 — it is *also* exactly what the NIST KAT
//!   harness (`PQCgenKAT_kem.c`, bundled with the reference) uses as its
//!   `randombytes()`/DRBG: `prng_init(entropy_input, NULL, 48, 0)` then
//!   repeated `prng_get_bytes()`. That means HQC's official KAT does
//!   **not** use NIST's classic AES-256-CTR-DRBG (unlike e.g. this repo's
//!   `falcon`/`slhdsa` KATs) — it's SHAKE256 end to end, confirmed by
//!   reading the reference's `packaging/utils/helpers/main_kat.c`
//!   directly (gitlab.com/pqc-hqc/hqc, tag v5.0.0). Part 3 can reuse
//!   `Prng` verbatim for KAT reproduction; no AES needed.
//! - `Xof` (domain 1): used for h/x/y/r1/r2/e sampling and for expanding
//!   seedKEM/seedPKE. Its `getBytes` has a load-bearing quirk (see that
//!   function's doc) inherited from the reference's `xof_get_bytes`.
//!
//! `hashI`/`hashG`/`hashH`/`hashJ` are the spec's SHA3-512/SHA3-256
//! random oracles I/G/H/J (Table 1); `hashI` and `hashG` are independently
//! KAT-verified here, `hashH`/`hashJ` are transcribed from the reference's
//! `symmetric.c` with the same domain-separator pattern (not yet
//! independently numeric-pinned — see kat_vectors.zig).

const std = @import("std");
const params = @import("params.zig");
const Shake256 = std.crypto.hash.sha3.Shake256;

/// HQC's internal PRNG (domain 0) — a plain SHAKE256(entropy ||
/// personalization || 0x00) squeeze. See module doc: this is also the
/// NIST KAT harness's `randombytes()` in this reference implementation.
pub const Prng = struct {
    st: Shake256,

    /// Mirrors the reference's `prng_init(entropy_input, personalization,
    /// enlen, perlen)`. `personalization` may be empty (KAT usage always
    /// passes an empty/absent one).
    pub fn init(entropy: []const u8, personalization: []const u8) Prng {
        var st = Shake256.init(.{});
        st.update(entropy);
        st.update(personalization);
        st.update(&.{params.domain.prng});
        return .{ .st = st };
    }

    /// Plain squeeze — no alignment quirk (unlike `Xof.getBytes`).
    pub fn getBytes(self: *Prng, out: []u8) void {
        self.st.squeeze(out);
    }
};

/// HQC's XOF (domain 1) — SHAKE256(seed || 0x01), used for every ring
/// vector's randomness (h, x, y, r1, r2, e) and for expanding
/// seedKEM/seedPKE.
pub const Xof = struct {
    st: Shake256,

    pub fn init(seed: []const u8) Xof {
        var st = Shake256.init(.{});
        st.update(seed);
        st.update(&.{params.domain.xof});
        return .{ .st = st };
    }

    /// Squeeze `out.len` bytes — but reproducing the reference's
    /// `xof_get_bytes` quirk: the underlying SHAKE256 stream is always
    /// consumed in whole 8-byte blocks. When `out.len` is not itself a
    /// multiple of 8, the aligned prefix is squeezed directly, then one
    /// *full* extra 8-byte block is squeezed and only its first
    /// `out.len % 8` bytes are kept — silently discarding the rest of
    /// that block from the stream forever.
    ///
    /// This does NOT change the bytes returned by *this* call (they are
    /// still exactly the next `out.len` bytes of the logical XOF output
    /// stream) — it changes how far the stream position advances for the
    /// *next* call on the same context. Missing this quirk desyncs every
    /// subsequent `getBytes` call chained on the same `Xof` (e.g. y then
    /// x in keygen, or r2/e/r1 in encryption) from the reference's
    /// output. Independently verified byte-exact against the reference's
    /// chained y-then-x keygen sampling in kat_vectors.zig — see that
    /// test's comment for how the desync was caught.
    pub fn getBytes(self: *Xof, out: []u8) void {
        const rem = out.len % 8;
        const aligned = out.len - rem;
        self.st.squeeze(out[0..aligned]);
        if (rem != 0) {
            var block: [8]u8 = undefined;
            self.st.squeeze(&block);
            @memcpy(out[aligned..], block[0..rem]);
        }
    }
};

/// I(seed) = SHA3-512(seed || I_DOMAIN=2) — derives (seedPKE.dk,
/// seedPKE.ek) from seedPKE (64-byte output, split by the caller into two
/// 32-byte halves). KAT-verified: kat_vectors.zig's `hqc128_keygen`
/// fixture reproduces `I(seed_pke) == seed_dk || seed_ek` exactly.
pub fn hashI(out: *[64]u8, seed: []const u8) void {
    var st = std.crypto.hash.sha3.Sha3_512.init(.{});
    st.update(seed);
    st.update(&.{params.domain.i});
    st.final(out);
}

/// H(ek_kem) = SHA3-256(ek_kem || H_DOMAIN=1).
pub fn hashH(out: *[32]u8, ek_kem: []const u8) void {
    var st = std.crypto.hash.sha3.Sha3_256.init(.{});
    st.update(ek_kem);
    st.update(&.{params.domain.h});
    st.final(out);
}

/// G(h_ek, m, salt) = SHA3-512(h_ek || m || salt || G_DOMAIN=0) -> (K,
/// theta) as the first/second 32-byte halves of the 64-byte output.
/// KAT-verified: kat_vectors.zig's `hqc128_encaps` fixture reproduces
/// `G(H(ek_kem), m, salt) == K || theta` exactly.
pub fn hashG(out: *[64]u8, h_ek: []const u8, m: []const u8, salt: []const u8) void {
    var st = std.crypto.hash.sha3.Sha3_512.init(.{});
    st.update(h_ek);
    st.update(m);
    st.update(salt);
    st.update(&.{params.domain.g});
    st.final(out);
}

/// J(h_ek, sigma, c_kem_bytes) = SHA3-256(h_ek || sigma || c_kem ||
/// J_DOMAIN=3) — the FO-transform implicit-rejection key. `c_kem_bytes`
/// is the caller's already-serialized ciphertext (u || v || salt); this
/// module doesn't own ciphertext serialization (that's Part 3).
pub fn hashJ(out: *[32]u8, h_ek: []const u8, sigma: []const u8, c_kem_bytes: []const u8) void {
    var st = std.crypto.hash.sha3.Sha3_256.init(.{});
    st.update(h_ek);
    st.update(sigma);
    st.update(c_kem_bytes);
    st.update(&.{params.domain.j});
    st.final(out);
}

/// Barrett reduction of `x` modulo `n`, mirroring the reference's
/// `barrett_reduce` (branch-structured via mask, not an `if`) exactly:
/// `q = (x*mu) >> 32; r = x - q*n; r -= n if r >= n` — the last step done
/// via the reference's own `((r-n)>>31)^1` flag-and-mask idiom rather
/// than a plain comparison, so this module's control flow doesn't branch
/// on `x` (a rejection-sampled candidate — not itself secret data by the
/// time it reaches here, but kept faithful to the reference's posture).
pub fn barrettReduce(x: u32, comptime n: u32, comptime mu: u64) u32 {
    const q: u64 = (@as(u64, x) *% mu) >> 32;
    const prod: u64 = q *% @as(u64, n);
    var r: u32 = x -% @as(u32, @truncate(prod));
    const reduce_flag: u32 = ((r -% n) >> 31) ^ 1;
    const mask: u32 = 0 -% reduce_flag;
    r -%= mask & n;
    return r;
}

/// SampleVect (spec §3.2): fill `out` (n-bit Elem, `out.len` u64 words)
/// with `nBytes` bytes of raw XOF output, LSB-first, then mask the top
/// word to n bits. This is `vect_set_random` in the reference — used for
/// the public generator vector h. KAT-verified: kat_vectors.zig's
/// `hqc128_keygen` fixture reproduces the reference's `h` exactly.
pub fn sampleVect(xof: *Xof, comptime n: u32, out: []u64) void {
    const n_bytes = (n + 7) / 8;
    const bytes = std.mem.sliceAsBytes(out);
    @memset(bytes, 0);
    xof.getBytes(bytes[0..n_bytes]);
    const word_idx = n / 64;
    const bit_in_word: u6 = @intCast(n % 64); // never 0: n is prime for every real param set
    out[word_idx] &= (@as(u64, 1) << bit_in_word) - 1;
}

/// GenerateRandomSupport / SampleFixedWeightVect$ (spec §3.2, "rely on
/// rejection sampling"; reference: `vect_generate_random_support1` +
/// `vect_sample_fixed_weight1`). Used **only** for keygen's (x, y) —
/// unbiased, uniform over all weight-`weight` supports. Draws 24-bit
/// values from the XOF, rejects >= the parameter set's rejection
/// threshold, Barrett-reduces the survivor mod n, and rejects duplicates
/// against the support accumulated so far (full linear rescan every
/// time, no early exit — matches the reference's constant memory-access
/// pattern). `weight` and `n` are comptime so the local scratch buffer
/// (`3*weight` bytes, matching the reference's per-call refill size) is
/// a fixed-size stack array.
///
/// KAT-verified: kat_vectors.zig's `hqc128_keygen` fixture reproduces the
/// reference's chained y-then-x sampling (same Xof context, continuing
/// the stream across both calls) byte-exact.
pub fn sampleFixedWeightRejection(
    xof: *Xof,
    comptime n: u32,
    comptime mu: u64,
    comptime threshold: u32,
    comptime weight: u16,
    support: *[weight]u32,
) void {
    const buf_len = 3 * @as(usize, weight);
    var buf: [buf_len]u8 = undefined;
    var j: usize = buf_len; // force an immediate refill on first draw
    var i: usize = 0;
    while (i < weight) {
        var val: u32 = 0;
        while (true) {
            if (j == buf_len) {
                xof.getBytes(&buf);
                j = 0;
            }
            val = (@as(u32, buf[j]) << 16) | (@as(u32, buf[j + 1]) << 8) | buf[j + 2];
            j += 3;
            if (val < threshold) break;
        }
        val = barrettReduce(val, n, mu);
        var dup = false;
        for (support[0..i]) |s| {
            if (s == val) dup = true;
        }
        if (!dup) {
            support[i] = val;
            i += 1;
        }
    }
}

/// SampleFixedWeightVect (spec §3.2, "Algorithm 5 from [36]" — no
/// rejection sampling, slightly biased; reference:
/// `vect_generate_random_support2` + `vect_sample_fixed_weight2`). Used
/// for encryption's (r1, r2, e). Draws one little-endian u32 per support
/// element from a single `4*weight`-byte XOF pull, maps it into [i, n)
/// via a Lemire-style multiply-shift (`i + (rand * (n-i)) >> 32`), then a
/// constant-access-pattern reverse pass replaces any element that
/// collides with a later one by its own index `i` (this is the source of
/// the "slight bias" the spec's changelog references — see SPEC.md).
///
/// Transcribed directly from the reference's `vect_generate_random_
/// support2` (not independently numeric-KAT-pinned like the rejection
/// variant above — the reference's public intermediates_values dump
/// doesn't expose r1/r2/e directly; see kat_vectors.zig). Self-tested via
/// weight/duplicate-freedom properties in this file's tests.
pub fn sampleFixedWeightBiased(
    xof: *Xof,
    comptime n: u32,
    comptime weight: u16,
    support: *[weight]u32,
) void {
    var raw: [4 * weight]u8 = undefined;
    xof.getBytes(&raw);
    for (support, 0..) |*s, idx| {
        const r = std.mem.readInt(u32, raw[4 * idx ..][0..4], .little);
        const buff: u64 = r;
        s.* = @intCast(idx + ((buff * (n - idx)) >> 32));
    }
    // Reverse pass: for i from weight-2 downto 0, replace support[i] with
    // i itself if it collides with any support[j], j > i. Full scan, no
    // early exit (constant access pattern, mirrors the reference).
    var idx: usize = weight - 1;
    while (idx > 0) {
        idx -= 1;
        var found = false;
        for (support[idx + 1 .. weight]) |s| {
            if (s == support[idx]) found = true;
        }
        if (found) support[idx] = @intCast(idx);
    }
}

/// vect_write_support_to_vector: scatter a support (array of bit
/// positions) into a bit-packed bit vector. Full constant-access-pattern
/// scan (every output word tested against every support entry) matching
/// the reference exactly — this is secret-key/randomness material.
pub fn writeSupportToVector(comptime weight: u16, support: *const [weight]u32, out: []u64) void {
    var index_tab: [weight]u32 = undefined;
    var bit_tab: [weight]u64 = undefined;
    for (support, 0..) |s, idx| {
        index_tab[idx] = s >> 6;
        bit_tab[idx] = @as(u64, 1) << @intCast(s & 0x3f);
    }
    for (out, 0..) |*word, i| {
        var val: u64 = 0;
        for (index_tab, bit_tab) |itab, btab| {
            const tmp = @as(u32, @intCast(i)) -% itab;
            const val1: u32 = 1 ^ ((tmp | (0 -% tmp)) >> 31);
            const mask: u64 = 0 -% @as(u64, val1);
            val |= btab & mask;
        }
        word.* |= val;
    }
}

/// Convenience wrapper: SampleFixedWeightVect$ end to end (support
/// generation + scatter into `out`).
pub fn sampleFixedWeightRejectionVec(
    xof: *Xof,
    comptime n: u32,
    comptime mu: u64,
    comptime threshold: u32,
    comptime weight: u16,
    out: []u64,
) void {
    var support: [weight]u32 = undefined;
    sampleFixedWeightRejection(xof, n, mu, threshold, weight, &support);
    writeSupportToVector(weight, &support, out);
}

/// Convenience wrapper: SampleFixedWeightVect (biased) end to end.
pub fn sampleFixedWeightBiasedVec(
    xof: *Xof,
    comptime n: u32,
    comptime weight: u16,
    out: []u64,
) void {
    var support: [weight]u32 = undefined;
    sampleFixedWeightBiased(xof, n, weight, &support);
    writeSupportToVector(weight, &support, out);
}

// ── self-tests (algebraic/property-based — numeric KAT pins live in
// kat_vectors.zig / kat_test.zig) ─────────────────────────────────────────

test "Xof.getBytes aligned call has no quirk (multiple-of-8 sizes)" {
    // For an 8-byte-aligned request, our getBytes must equal a plain
    // squeeze — this is the "no waste" case, sanity-checked against
    // Zig's own Shake256 used directly.
    const t = std.testing;
    var st_direct = Shake256.init(.{});
    st_direct.update("seed");
    st_direct.update(&.{params.domain.xof});
    var direct: [32]u8 = undefined;
    st_direct.squeeze(&direct);

    var xof = Xof.init("seed");
    var got: [32]u8 = undefined;
    xof.getBytes(&got);
    try t.expectEqualSlices(u8, &direct, &got);
}

test "Xof.getBytes unaligned call: content matches a plain squeeze prefix" {
    // Content correctness (independent of the stream-position quirk):
    // the FIRST call's returned bytes must equal the plain XOF stream's
    // leading bytes, whether or not the size is 8-aligned.
    const t = std.testing;
    var st_direct = Shake256.init(.{});
    st_direct.update("seed");
    st_direct.update(&.{params.domain.xof});
    var direct: [198]u8 = undefined;
    st_direct.squeeze(&direct);

    var xof = Xof.init("seed");
    var got: [198]u8 = undefined;
    xof.getBytes(&got);
    try t.expectEqualSlices(u8, &direct, &got);
}

test "Xof.getBytes unaligned call wastes the tail of the last 8-byte block" {
    // The stream-position-advancement quirk itself: after an unaligned
    // getBytes(198), the NEXT getBytes call must start at stream offset
    // 200 (198 rounded up to a multiple of 8), not 198.
    const t = std.testing;
    var xof = Xof.init("seed");
    var first: [198]u8 = undefined;
    xof.getBytes(&first);
    var next: [8]u8 = undefined;
    xof.getBytes(&next);

    var st_direct = Shake256.init(.{});
    st_direct.update("seed");
    st_direct.update(&.{params.domain.xof});
    var skip: [200]u8 = undefined;
    st_direct.squeeze(&skip);
    var want_next: [8]u8 = undefined;
    st_direct.squeeze(&want_next);

    try t.expectEqualSlices(u8, &want_next, &next);
}

test "barrettReduce matches naive mod for a broad sweep" {
    const t = std.testing;
    const n: u32 = comptime params.hqc128.n;
    const mu: u64 = comptime params.hqc128.nMu();
    var x: u32 = 0;
    while (x < 200_000) : (x += 997) {
        try t.expectEqual(x % n, barrettReduce(x, n, mu));
    }
    // Boundary values near the top of the 24-bit rejection range.
    const threshold: u32 = comptime params.hqc128.rejectionThreshold();
    for ([_]u32{ n - 1, n, n + 1, threshold - 1 }) |val| {
        try t.expectEqual(val % n, barrettReduce(val, n, mu));
    }
}

test "sampleFixedWeightRejection: exact weight, no duplicates, in range" {
    const t = std.testing;
    const P = params.hqc128;
    var xof = Xof.init("some deterministic seed for property testing");
    var support: [P.omega]u32 = undefined;
    sampleFixedWeightRejection(&xof, P.n, P.nMu(), P.rejectionThreshold(), P.omega, &support);
    for (support) |s| try t.expect(s < P.n);
    for (support, 0..) |s, i| {
        for (support[i + 1 ..]) |s2| try t.expect(s != s2);
    }
    var out = [_]u64{0} ** ((P.n + 63) / 64);
    writeSupportToVector(P.omega, &support, &out);
    var w: u32 = 0;
    for (out) |word| w += @popCount(word);
    try t.expectEqual(@as(u32, P.omega), w);
}

test "sampleFixedWeightBiased: exact weight, no duplicates, in range" {
    const t = std.testing;
    const P = params.hqc128;
    var xof = Xof.init("another deterministic seed for property testing");
    var support: [P.omega_r]u32 = undefined;
    sampleFixedWeightBiased(&xof, P.n, P.omega_r, &support);
    for (support) |s| try t.expect(s < P.n);
    for (support, 0..) |s, i| {
        for (support[i + 1 ..]) |s2| try t.expect(s != s2);
    }
    var out = [_]u64{0} ** ((P.n + 63) / 64);
    writeSupportToVector(P.omega_r, &support, &out);
    var w: u32 = 0;
    for (out) |word| w += @popCount(word);
    try t.expectEqual(@as(u32, P.omega_r), w);
}

test "sampleVect masks bits beyond n" {
    const t = std.testing;
    const P = params.hqc128;
    var xof = Xof.init("sample vect seed");
    var out = [_]u64{0} ** P.words();
    sampleVect(&xof, P.n, &out);
    var i: u32 = P.n;
    const top_word = P.n / 64;
    while (i < (top_word + 1) * 64) : (i += 1) {
        try t.expectEqual(@as(u1, 0), @as(u1, @intCast((out[i / 64] >> @intCast(i % 64)) & 1)));
    }
}

test "hashI output length and determinism" {
    const t = std.testing;
    var out1: [64]u8 = undefined;
    var out2: [64]u8 = undefined;
    hashI(&out1, "seed one");
    hashI(&out2, "seed one");
    try t.expectEqualSlices(u8, &out1, &out2);
    hashI(&out2, "seed two");
    try t.expect(!std.mem.eql(u8, &out1, &out2));
}
