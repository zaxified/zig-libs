// SPDX-License-Identifier: MIT
//! code_kat_test — Part 2 (RS/RM concatenated code) test suite: byte-exact
//! encode KATs against `kat_vectors_code.zig` (see that file's module doc
//! for provenance), plus decode-correctness tests gated behind
//! `gate.decoder_core_implemented` (see gate.zig).

const std = @import("std");
const testing = std.testing;

const params = @import("params.zig");
const gf = @import("gf256.zig");
const reedsolomon = @import("reedsolomon.zig");
const reedmuller = @import("reedmuller.zig");
const code = @import("code.zig");
const gate = @import("gate.zig");
const kat = @import("kat_vectors_code.zig");

const RS128 = reedsolomon.RS(params.hqc128, reedsolomon.generator_hqc128);
const RS192 = reedsolomon.RS(params.hqc192, reedsolomon.generator_hqc192);
const RS256 = reedsolomon.RS(params.hqc256, reedsolomon.generator_hqc256);

const RM128 = reedmuller.RM(params.hqc128);
const RM192 = reedmuller.RM(params.hqc192);
const RM256 = reedmuller.RM(params.hqc256);

const Code128 = code.Code(params.hqc128, reedsolomon.generator_hqc128);
const Code192 = code.Code(params.hqc192, reedsolomon.generator_hqc192);
const Code256 = code.Code(params.hqc256, reedsolomon.generator_hqc256);

fn zeroMsg(comptime n: usize) [n]u8 {
    return [_]u8{0} ** n;
}

fn ffMsg(comptime n: usize) [n]u8 {
    return [_]u8{0xff} ** n;
}

fn incrMsg(comptime n: usize) [n]u8 {
    var m: [n]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @intCast(i);
    return m;
}

// ── RS encode: byte-exact against the reference ─────────────────────────

test "RS128.encode byte-exact vs reference (zero/ff/incr/msg0=0x01)" {
    try testing.expectEqualSlices(u8, &kat.hqc128_rs_zero, &RS128.encode(zeroMsg(RS128.k)));
    try testing.expectEqualSlices(u8, &kat.hqc128_rs_ff, &RS128.encode(ffMsg(RS128.k)));
    try testing.expectEqualSlices(u8, &kat.hqc128_rs_incr, &RS128.encode(incrMsg(RS128.k)));

    var msg0_01: RS128.Message = [_]u8{0} ** RS128.k;
    msg0_01[0] = 0x01;
    try testing.expectEqualSlices(u8, &kat.hqc128_rs_msg0_01, &RS128.encode(msg0_01));
}

test "RS192.encode byte-exact vs reference (zero/ff/incr/msg0=0x01)" {
    try testing.expectEqualSlices(u8, &kat.hqc192_rs_zero, &RS192.encode(zeroMsg(RS192.k)));
    try testing.expectEqualSlices(u8, &kat.hqc192_rs_ff, &RS192.encode(ffMsg(RS192.k)));
    try testing.expectEqualSlices(u8, &kat.hqc192_rs_incr, &RS192.encode(incrMsg(RS192.k)));

    var msg0_01: RS192.Message = [_]u8{0} ** RS192.k;
    msg0_01[0] = 0x01;
    try testing.expectEqualSlices(u8, &kat.hqc192_rs_msg0_01, &RS192.encode(msg0_01));
}

test "RS256.encode byte-exact vs reference (zero/ff/incr/msg0=0x01)" {
    try testing.expectEqualSlices(u8, &kat.hqc256_rs_zero, &RS256.encode(zeroMsg(RS256.k)));
    try testing.expectEqualSlices(u8, &kat.hqc256_rs_ff, &RS256.encode(ffMsg(RS256.k)));
    try testing.expectEqualSlices(u8, &kat.hqc256_rs_incr, &RS256.encode(incrMsg(RS256.k)));

    var msg0_01: RS256.Message = [_]u8{0} ** RS256.k;
    msg0_01[0] = 0x01;
    try testing.expectEqualSlices(u8, &kat.hqc256_rs_msg0_01, &RS256.encode(msg0_01));
}

// ── RM encode: byte-exact against the reference (isolated per-byte) ────

fn checkRmByte(comptime RM: type, message: u8, want: []const u8) !void {
    const block = RM.encodeBlock(message);
    var got: [RM.block_bytes]u8 = undefined;
    for (0..RM.multiplicity) |c| @memcpy(got[c * 16 ..][0..16], &block);
    try testing.expectEqualSlices(u8, want, &got);
}

test "RM128.encodeBlock byte-exact vs reference for 8 sample bytes" {
    try checkRmByte(RM128, 0x00, &kat.hqc128_rm_byte_00);
    try checkRmByte(RM128, 0x01, &kat.hqc128_rm_byte_01);
    try checkRmByte(RM128, 0xff, &kat.hqc128_rm_byte_ff);
    try checkRmByte(RM128, 0x55, &kat.hqc128_rm_byte_55);
    try checkRmByte(RM128, 0xaa, &kat.hqc128_rm_byte_aa);
    try checkRmByte(RM128, 0x7f, &kat.hqc128_rm_byte_7f);
    try checkRmByte(RM128, 0x80, &kat.hqc128_rm_byte_80);
    try checkRmByte(RM128, 0x2a, &kat.hqc128_rm_byte_2a);
}

test "RM192.encodeBlock byte-exact vs reference for 8 sample bytes" {
    try checkRmByte(RM192, 0x00, &kat.hqc192_rm_byte_00);
    try checkRmByte(RM192, 0x01, &kat.hqc192_rm_byte_01);
    try checkRmByte(RM192, 0xff, &kat.hqc192_rm_byte_ff);
    try checkRmByte(RM192, 0x55, &kat.hqc192_rm_byte_55);
    try checkRmByte(RM192, 0xaa, &kat.hqc192_rm_byte_aa);
    try checkRmByte(RM192, 0x7f, &kat.hqc192_rm_byte_7f);
    try checkRmByte(RM192, 0x80, &kat.hqc192_rm_byte_80);
    try checkRmByte(RM192, 0x2a, &kat.hqc192_rm_byte_2a);
}

test "RM256.encodeBlock byte-exact vs reference for 8 sample bytes" {
    try checkRmByte(RM256, 0x00, &kat.hqc256_rm_byte_00);
    try checkRmByte(RM256, 0x01, &kat.hqc256_rm_byte_01);
    try checkRmByte(RM256, 0xff, &kat.hqc256_rm_byte_ff);
    try checkRmByte(RM256, 0x55, &kat.hqc256_rm_byte_55);
    try checkRmByte(RM256, 0xaa, &kat.hqc256_rm_byte_aa);
    try checkRmByte(RM256, 0x7f, &kat.hqc256_rm_byte_7f);
    try checkRmByte(RM256, 0x80, &kat.hqc256_rm_byte_80);
    try checkRmByte(RM256, 0x2a, &kat.hqc256_rm_byte_2a);
}

// ── Concatenated code encode: byte-exact against the reference ─────────
// Full-codeword vectors only pinned for hqc128 (see kat_vectors_code.zig's
// module doc for why); hqc192/256 rely on their RS+RM vectors above plus
// code.zig's own offset-math test for concatenation confidence.

test "Code128.encode byte-exact vs reference (zero/ff/incr)" {
    try testing.expectEqualSlices(u8, &kat.hqc128_code_zero, &Code128.encode(zeroMsg(Code128.message_len)));
    try testing.expectEqualSlices(u8, &kat.hqc128_code_ff, &Code128.encode(ffMsg(Code128.message_len)));
    try testing.expectEqualSlices(u8, &kat.hqc128_code_incr, &Code128.encode(incrMsg(Code128.message_len)));
}

test "Code192.encode of the all-zero message matches the reference's all-zero codeword" {
    try testing.expectEqualSlices(u8, &kat.hqc192_code_zero, &Code192.encode(zeroMsg(Code192.message_len)));
}

test "Code256.encode of the all-zero message matches the reference's all-zero codeword" {
    try testing.expectEqualSlices(u8, &kat.hqc256_code_zero, &Code256.encode(zeroMsg(Code256.message_len)));
}

// ── Decode correctness — gated behind gate.decoder_core_implemented ────
// SKIP (not PASS) until a Fable pass fills in RM(p).decodeSymbol and
// RS(p).decode (see gate.zig / those functions' doc comments). Written
// now so the moment the gate flips, this file already has the coverage
// the task's acceptance criteria call for: zero-error round-trip,
// within-capacity error correction, and a documented beyond-capacity
// case — no additional harness work needed at that point.

test "gated: Code128 round-trip decode(encode(m)) == m, zero-error, many random messages" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    var rng = std.Random.DefaultPrng.init(1);
    const random = rng.random();
    for (0..64) |_| {
        var msg: Code128.Message = undefined;
        random.bytes(&msg);
        const cdw = Code128.encode(msg);
        const got = Code128.decode(cdw);
        try testing.expectEqualSlices(u8, &msg, &got);
    }
}

test "gated: Code128 corrects up to RS.delta symbol errors (whole RM blocks flipped)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    var rng = std.Random.DefaultPrng.init(2);
    const random = rng.random();
    for (0..16) |_| {
        var msg: Code128.Message = undefined;
        random.bytes(&msg);
        var cdw = Code128.encode(msg);

        // Corrupt exactly RS128.delta whole RM blocks (the strongest,
        // least-ambiguous kind of symbol error: flip every bit of the
        // block, which under maximum-likelihood RM decoding decodes to
        // some OTHER byte — i.e. this reliably becomes a full symbol
        // error at the RS layer, not a partial/no-op one).
        var corrupted_positions: [RS128.delta]usize = undefined;
        var count: usize = 0;
        while (count < RS128.delta) {
            const pos = random.uintLessThan(usize, RS128.n1);
            if (std.mem.indexOfScalar(usize, corrupted_positions[0..count], pos) != null) continue;
            corrupted_positions[count] = pos;
            count += 1;
            for (cdw[pos * RM128.block_bytes ..][0..RM128.block_bytes]) |*b| b.* = ~b.*;
        }

        const got = Code128.decode(cdw);
        try testing.expectEqualSlices(u8, &msg, &got);
    }
}

test "gated: RM128.decodeSymbol is exhaustively correct on error-free input" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    for (0..256) |m| {
        const message: u8 = @intCast(m);
        const sym = RM128.encodeSymbol(message);
        try testing.expectEqual(message, RM128.decodeSymbol(sym));
    }
}

// `decodeSymbol`'s doc comment calls out a specific documented choice: on a
// genuine tie between two peaks of equal absolute value, `find_peaks` keeps
// the FIRST (smallest-index) one -- strict `>`, not `>=`, in the comparison
// (matching the reference's own comment on the same tie-break). Every OTHER
// test in this suite only ever feeds `decodeSymbol` either a clean,
// error-free codeword (a unique peak, no tie possible) or a within-capacity
// corruption whose nearest codeword is still unique -- none of them can
// exercise this branch. This test builds a genuine two-way tie by hand and
// checks the documented rule holds.
test "gated: RM128.decodeSymbol ties resolve to the smallest index (documented strict `>`)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;

    // encodeBlock(0) is the all-zero block; encodeBlock(1) has weight
    // exactly 64 -- every nonzero RM(1,7) codeword other than the all-ones
    // "DC" row (message bit 7) is exactly balanced (the code's bent-like
    // structure: each of the 7 non-DC generator rows, and every XOR of a
    // nonempty subset of them, has exactly 64 of 128 bits set). So flipping
    // exactly half of those 64 differing bits from the all-zero block lands
    // exactly as close (Hamming distance 32 of 128) to BOTH message 0 and
    // message 1 -- a real tie between two DIFFERENT peak indices, not the
    // separate "transform[i]==0 exact sign ambiguity" case.
    const block0 = RM128.encodeBlock(0);
    const block1 = RM128.encodeBlock(1);
    var diff_bits: [128]usize = undefined;
    var n_diff: usize = 0;
    for (0..128) |bit| {
        const byte = bit / 8;
        const shift: u3 = @intCast(bit % 8);
        if (((block0[byte] >> shift) & 1) != ((block1[byte] >> shift) & 1)) {
            diff_bits[n_diff] = bit;
            n_diff += 1;
        }
    }
    try testing.expectEqual(@as(usize, 64), n_diff); // the balanced-code property this construction relies on

    var corrupted = block0;
    for (diff_bits[0..32]) |bit| {
        const byte = bit / 8;
        const shift: u3 = @intCast(bit % 8);
        corrupted[byte] ^= @as(u8, 1) << shift;
    }

    // Self-validating precondition, independent of the Hadamard-transform
    // implementation under test: brute-force nearest-codeword Hamming
    // distance (minimum-distance decoding is the textbook equivalent of
    // maximum-likelihood decoding over a binary symmetric channel, which is
    // exactly what `decodeSymbol` claims to implement) confirms messages 0
    // and 1 are both tied for closest, at distance 32 -- confirming the
    // tie the mutation targets is real, without assuming they are the
    // ONLY two tied (the code's symmetry in fact ties two more indices at
    // the same distance; that does not weaken the assertion below, since
    // 0 is still the smallest index in the tied set either way).
    var best_dist: u32 = std.math.maxInt(u32);
    var tied_at_0 = false;
    var tied_at_1 = false;
    for (0..256) |m| {
        const cand = RM128.encodeBlock(@intCast(m));
        var dist: u32 = 0;
        for (corrupted, cand) |a, b| dist += @popCount(a ^ b);
        if (dist < best_dist) {
            best_dist = dist;
            tied_at_0 = (m == 0);
            tied_at_1 = (m == 1);
        } else if (dist == best_dist) {
            if (m == 0) tied_at_0 = true;
            if (m == 1) tied_at_1 = true;
        }
    }
    try testing.expectEqual(@as(u32, 32), best_dist);
    try testing.expect(tied_at_0);
    try testing.expect(tied_at_1);

    // Uniform corruption across every duplicated copy keeps the tie exact
    // after expand-and-sum (every copy agrees, so each bit's sum is either
    // 0 or `multiplicity`, just `multiplicity`-scaled from the single-block
    // case above -- scaling by a positive constant preserves which indices
    // are tied for the peak).
    var sym: RM128.Symbol = undefined;
    for (0..RM128.multiplicity) |c| @memcpy(sym[c * 16 ..][0..16], &corrupted);

    // Documented rule: the smaller index (0) wins the tie, not the larger (1).
    try testing.expectEqual(@as(u8, 0), RM128.decodeSymbol(sym));
}

// ── hqc-192/256 decode coverage: the additive-FFT `radixBig` path ──────
// hqc-128 has PARAM_FFT == 4, so its RS root-finding uses only the
// unrolled `radix` small cases (reedsolomon.zig's `radixConv`). hqc-192
// and hqc-256 have PARAM_FFT == 5, which is the ONLY configuration that
// reaches `radixBig` (and the recursive `fftRec` at m_f == 5). The tests
// above never exercise it; these do — property-style random round-trip and
// within-/at-capacity correction at both the concatenated-code and the
// bare Reed-Solomon layer, mirroring the hqc-128 structure above. This
// permanently pins the param_fft=5 path the Fable pass proved works.

/// Zero-error concatenated-code round-trip: decode(encode(m)) == m over
/// many random messages (exercises the full RM→RS decode pipeline with an
/// all-zero error pattern; RS's sigma comes out degree 0).
fn codeRoundTripZeroError(comptime C: type, seed: u64) !void {
    var rng = std.Random.DefaultPrng.init(seed);
    const random = rng.random();
    for (0..32) |_| {
        var msg: C.Message = undefined;
        random.bytes(&msg);
        const cdw = C.encode(msg);
        const got = C.decode(cdw);
        try testing.expectEqualSlices(u8, &msg, &got);
    }
}

/// Concatenated-code correction of exactly RS.delta whole-RM-block errors:
/// flipping every bit of a symbol slot turns it into the codeword of
/// `symbol ^ 0x80` (the RM(1,7) all-ones "DC" row complements the whole
/// block), a guaranteed single RS-symbol error — so this drives exactly
/// delta symbol errors through RS.decode, i.e. the at-capacity boundary.
fn codeCorrectsDeltaBlockErrors(comptime C: type, seed: u64) !void {
    const delta = C.RS.delta;
    const block_bytes = C.RM.block_bytes;
    var rng = std.Random.DefaultPrng.init(seed);
    const random = rng.random();
    for (0..8) |_| {
        var msg: C.Message = undefined;
        random.bytes(&msg);
        var cdw = C.encode(msg);

        var positions: [delta]usize = undefined;
        var count: usize = 0;
        while (count < delta) {
            const pos = random.uintLessThan(usize, C.RS.n1);
            if (std.mem.indexOfScalar(usize, positions[0..count], pos) != null) continue;
            positions[count] = pos;
            count += 1;
            for (cdw[pos * block_bytes ..][0..block_bytes]) |*b| b.* = ~b.*;
        }

        const got = C.decode(cdw);
        try testing.expectEqualSlices(u8, &msg, &got);
    }
}

/// Bare Reed-Solomon correction of exactly delta symbol errors: XOR a
/// random NONZERO value into delta distinct codeword positions (guaranteed
/// symbol errors) and confirm RS.decode recovers the message. This is the
/// most direct exercise of the additive-FFT root-finder with delta real
/// roots (the radixBig path for these parameter sets).
fn rsCorrectsDeltaSymbolErrors(comptime RSt: type, seed: u64) !void {
    const delta = RSt.delta;
    var rng = std.Random.DefaultPrng.init(seed);
    const random = rng.random();
    for (0..16) |_| {
        var msg: RSt.Message = undefined;
        random.bytes(&msg);
        var cdw = RSt.encode(msg);

        var positions: [delta]usize = undefined;
        var count: usize = 0;
        while (count < delta) {
            const pos = random.uintLessThan(usize, RSt.n1);
            if (std.mem.indexOfScalar(usize, positions[0..count], pos) != null) continue;
            positions[count] = pos;
            count += 1;
            var e: u8 = 0;
            while (e == 0) e = random.int(u8);
            cdw[pos] ^= e;
        }

        const got = RSt.decode(cdw);
        try testing.expectEqualSlices(u8, &msg, &got);
    }
}

test "gated: Code192 round-trip decode(encode(m)) == m, zero-error (param_fft=5 radixBig path)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try codeRoundTripZeroError(Code192, 3);
}

test "gated: Code256 round-trip decode(encode(m)) == m, zero-error (param_fft=5 radixBig path)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try codeRoundTripZeroError(Code256, 4);
}

test "gated: Code192 corrects up to RS.delta symbol errors (param_fft=5 radixBig path)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try codeCorrectsDeltaBlockErrors(Code192, 5);
}

test "gated: Code256 corrects up to RS.delta symbol errors (param_fft=5 radixBig path)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try codeCorrectsDeltaBlockErrors(Code256, 6);
}

test "gated: RS192.decode corrects exactly delta random symbol errors (param_fft=5 radixBig root-finding)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try rsCorrectsDeltaSymbolErrors(RS192, 7);
}

test "gated: RS256.decode corrects exactly delta random symbol errors (param_fft=5 radixBig root-finding)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;
    try rsCorrectsDeltaSymbolErrors(RS256, 8);
}

// ── RS corrector EXTERNAL anchor ───────────────────────────────────────
// The gated round-trip tests above validate the decoder self-consistently
// (encode -> corrupt -> decode -> compare). Because `encode` is itself
// byte-exact KAT-pinned against the reference (kat_vectors_code.zig), those
// tests are already strong, but they exercise ONLY the module's own
// corrector against its own encoder, and compare the k-byte MESSAGE alone.
// The tests below add an INDEPENDENT witness for the
// syndrome -> error-locator -> error-value chain: a from-scratch syndrome
// evaluator plus the closed-form SINGLE-error Peterson locator/value
// formulas — a DIFFERENT construction from the shipped constant-time
// Berlekamp-Massey + Gao-Mateer additive-FFT root-finding + Forney, computed
// here over the same KAT-pinned GF(2^8). This is the "known small RS
// instance" external anchor the corrector otherwise lacked: the syndromes
// and the recovered (position, value) are pinned by textbook closed forms,
// not by re-running the decoder under test.
//
// (Note on the NIST HQC KAT: `kem_kat_test.zig`'s `decaps`-agrees vectors DO
// transitively drive this corrector on the real decryption-noise error
// pattern — an external NIST anchor — but bury it inside full KEM
// decapsulation and cannot isolate a corrector-only fault. These tests
// isolate it.)

/// S_i = XOR-sum_{j=0}^{n1-1} c_j * alpha^{(i+1)*j}, i in [0, 2*delta) — the
/// standard RS syndrome definition (alpha = the GF(2^8) generator `gf.exp`
/// tabulates), computed INDEPENDENTLY of `reedsolomon.zig`'s private
/// `computeSyndromes`. Self-validated by the all-zero-on-a-valid-codeword
/// test below (which cross-checks it against the byte-exact-pinned encoder).
fn independentSyndromes(comptime RSt: type, cdw: *const RSt.Codeword) [2 * RSt.delta]u8 {
    var s: [2 * RSt.delta]u8 = [_]u8{0} ** (2 * RSt.delta);
    for (0..2 * RSt.delta) |i| {
        var acc: u8 = 0;
        for (0..RSt.n1) |j| {
            const a: u8 = @intCast(gf.exp[((i + 1) * j) % 255]);
            acc ^= gf.mul(cdw[j], a);
        }
        s[i] = acc;
    }
    return s;
}

test "RS corrector anchor: independent syndromes of every valid codeword are all zero (RS128/192/256)" {
    inline for (.{ RS128, RS192, RS256 }, .{ 0x5311d0, 0x5311d1, 0x5311d2 }) |RSt, seed| {
        var rng = std.Random.DefaultPrng.init(seed);
        const random = rng.random();
        for (0..8) |_| {
            var msg: RSt.Message = undefined;
            random.bytes(&msg);
            const cdw = RSt.encode(msg);
            const s = independentSyndromes(RSt, &cdw);
            for (s) |si| try testing.expectEqual(@as(u8, 0), si);
        }
    }
}

test "RS corrector anchor: single injected error — closed-form Peterson locator/value match, and RS128.decode recovers the message" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;

    // Deterministic valid codeword.
    var msg: RS128.Message = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(0x40 + i);
    const cdw = RS128.encode(msg);

    // Inject ONE known error in the message region [redundancy=30, n1=46),
    // so the uncorrected message suffix visibly differs from `msg` — a no-op
    // corrector would then fail the final recovery check.
    const p: usize = 40; // message byte 40 - 30 = 10
    const v: u8 = 0x9c;
    var recv = cdw;
    recv[p] ^= v;

    // Independent syndromes; single-error closed forms (Peterson):
    //   S_i = v * alpha^{(i+1)p}
    //   => locator alpha^p = S_1 * S_0^{-1},  value v = S_0 * (alpha^p)^{-1}.
    const s = independentSyndromes(RS128, &recv);
    try testing.expect(s[0] != 0); // error is detectable
    const locator = gf.mul(s[1], gf.inverse(s[0])); // = alpha^p
    const p_rec: usize = gf.log[locator];
    const v_rec = gf.mul(s[0], gf.inverse(locator));
    try testing.expectEqual(p, p_rec); // syndrome -> error LOCATOR (external)
    try testing.expectEqual(v, v_rec); // syndrome -> error VALUE  (external)

    // The received (uncorrected) message differs from the original...
    try testing.expect(!std.mem.eql(u8, &msg, recv[RS128.redundancy..]));
    // ...but the module's decoder recovers it exactly (corrected codeword).
    const got = RS128.decode(recv);
    try testing.expectEqualSlices(u8, &msg, &got);
}

test "RS corrector anchor: exactly delta=15 injected errors at fixed positions are all corrected (RS128 at capacity)" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;

    var msg: RS128.Message = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i * 7 + 1);
    const cdw = RS128.encode(msg);

    var recv = cdw;
    // delta distinct positions spanning both parity [0,30) and message
    // [30,46) regions; several land in the message suffix so a no-op / mis-
    // located corrector is caught by the final compare.
    const positions = [_]usize{ 0, 2, 5, 9, 13, 18, 22, 25, 29, 31, 34, 37, 40, 43, 45 };
    const values = [_]u8{ 0x01, 0x9c, 0x3f, 0xaa, 0x55, 0x80, 0x11, 0xf0, 0x7e, 0x22, 0xcd, 0x63, 0x9a, 0x04, 0xe1 };
    comptime std.debug.assert(positions.len == RS128.delta);
    for (positions, values) |pos, val| recv[pos] ^= val;

    // Positive-control preconditions: uncorrected suffix differs, and the
    // error is detectable at the syndrome layer (independent oracle).
    try testing.expect(!std.mem.eql(u8, &msg, recv[RS128.redundancy..]));
    const s = independentSyndromes(RS128, &recv);
    var any_nonzero = false;
    for (s) |si| {
        if (si != 0) any_nonzero = true;
    }
    try testing.expect(any_nonzero);

    // Decoder corrects all delta errors and recovers the message exactly.
    const got = RS128.decode(recv);
    try testing.expectEqualSlices(u8, &msg, &got);
}

test "RS corrector anchor: beyond-capacity (delta+1 errors) is deterministic and does not trap" {
    if (!gate.decoder_core_implemented) return error.SkipZigTest;

    // HONEST NOTE: a bounded-distance RS decoder has NO reliable failure
    // signal past delta errors — like the reference `reed_solomon_decode`,
    // this decoder may SILENTLY return a wrong message (HQC's FO transform
    // catches that one layer up via re-encryption, not here). So this is NOT
    // a "clean reject" negative control; it only pins that a > delta pattern
    // is handled without UB/panic and deterministically (two calls agree).
    var msg: RS128.Message = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i * 3 + 5);
    const cdw = RS128.encode(msg);
    var recv = cdw;
    const positions = [_]usize{ 0, 2, 5, 9, 13, 18, 22, 25, 29, 31, 34, 37, 40, 43, 45, 12 };
    comptime std.debug.assert(positions.len == RS128.delta + 1);
    for (positions, 0..) |pos, i| recv[pos] ^= @as(u8, @intCast(0x80 | (i + 1)));

    const got1 = RS128.decode(recv);
    const got2 = RS128.decode(recv);
    try testing.expectEqualSlices(u8, &got1, &got2); // deterministic, no trap
}
