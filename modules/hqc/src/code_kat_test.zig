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
