// SPDX-License-Identifier: MIT
//! reedmuller — the duplicated first-order Reed-Muller code RM(1,7) that
//! is the INNER code of HQC's Part-2 concatenated code (spec §3.4;
//! reference `src/ref/reed_muller.c` + `src/common/reed_muller.h` +
//! `src/ref/data_structures.h`'s `rm_codeword_t`).
//!
//! Each RS symbol (one GF(2^8) byte) is encoded into a 128-bit RM(1,7)
//! codeword, then that codeword is DUPLICATED `multiplicity` times
//! (`params.zig`'s `rm_multiplicity`: 3 for hqc-128, 5 for hqc-192/256) to
//! fill `n2` bits — the duplication is what buys extra error-correction
//! margin beyond RM(1,7)'s own distance-64 code, since decode sums all
//! `multiplicity` noisy copies before the Hadamard transform (see
//! `decodeSymbol`'s doc comment).
//!
//! **Encode is real (Sonnet)**: `RM(p).encodeBlock`/`encodeSymbol` are a
//! direct, mechanical port of the reference's fixed generator-matrix
//! encode (`encode`) plus duplication (`reed_muller_encode`'s per-symbol
//! loop) — no algorithmic choice, only bit-for-bit transcription,
//! numeric-KAT-pinned byte-exact against the reference (see
//! `kat_vectors_code.zig` / `code_kat_test.zig`).
//!
//! **Decode is the Fable-hard RM half (now implemented)**: `RM(p).decodeSymbol`
//! ports the reference's `reed_muller_decode` exactly — `expand_and_sum`
//! (0/1 accumulation across the duplicated copies), the 7-pass ping-pong
//! fast Hadamard transform (`hadamard`), the `transform[0] -= 64 *
//! MULTIPLICITY` half-transform fixup, and the `find_peaks`
//! maximum-likelihood pick (strict `>` tie-break, sign bit 0x80 from the
//! peak's signed value). See its doc comment for the full algorithm.
//! Exercised by the gated tests in `code_kat_test.zig`
//! (`gate.decoder_core_implemented`, now true).

const std = @import("std");
const params = @import("params.zig");

/// The duplicated RM(1,7) code for one HQC parameter set, specialized at
/// comptime. `p.n2`/`p.rm_multiplicity` come from `params.zig`.
pub fn RM(comptime p: params.Params) type {
    return struct {
        pub const n2 = p.n2;
        /// Number of duplicated 128-bit copies per symbol (reference:
        /// `MULTIPLICITY = CEIL_DIVIDE(PARAM_N2, 128)`). For every real
        /// HQC parameter set `n2` is an exact multiple of 128 (asserted
        /// below), so this is always an exact ratio, never a rounded-up
        /// ceiling in practice.
        pub const multiplicity = p.rm_multiplicity;
        comptime {
            std.debug.assert(multiplicity * 128 == n2);
        }

        /// One un-duplicated RM(1,7) codeword: 128 bits, 16 bytes.
        pub const Block = [16]u8;
        /// A full duplicated symbol slot: `multiplicity` back-to-back
        /// copies of a `Block`, `n2/8` bytes total — this is exactly one
        /// `reed_muller_encode`/`reed_muller_decode` "symbol position" in
        /// the reference (`codeArray[pos .. pos+multiplicity]`).
        pub const block_bytes = n2 / 8;
        pub const Symbol = [block_bytes]u8;

        /// Broadcast bit `n` of `x` to a 32-bit all-ones/all-zeros mask
        /// (reference: `BIT0MASK`, applied to `x >> n` there — folded the
        /// shift into this helper's own `n` parameter here instead).
        fn bitMask(x: u8, n: u3) u32 {
            return 0 -% @as(u32, (x >> n) & 1);
        }

        /// Encode one byte into a single (un-duplicated) RM(1,7) codeword
        /// (reference: `encode`, `reed_muller.c`).
        ///
        /// RM(1,7)'s generator matrix, as the reference's own comment
        /// draws it (8 rows, each a 128-bit pattern, bits numbered big
        /// endian within each 32-bit chunk): row 0 is the constant-1 row
        /// (`aaaaaaaa` repeated — wait, actually row 0 below is `a`'s
        /// row, i.e. message bit 0's contribution — see the per-row XOR
        /// terms below, which is the actual source of truth this
        /// function implements bit-for-bit):
        /// ```
        /// bit 0   aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa   (message bit 0)
        /// bit 1   cccccccc cccccccc cccccccc cccccccc   (message bit 1)
        /// bit 2   f0f0f0f0 f0f0f0f0 f0f0f0f0 f0f0f0f0   (message bit 2)
        /// bit 3   ff00ff00 ff00ff00 ff00ff00 ff00ff00   (message bit 3)
        /// bit 4   ffff0000 ffff0000 ffff0000 ffff0000   (message bit 4)
        /// bit 5   ffffffff 00000000 ffffffff 00000000   (message bit 5)
        /// bit 6   ffffffff ffffffff 00000000 00000000   (message bit 6)
        /// bit 7   ffffffff ffffffff ffffffff ffffffff   (message bit 7,
        ///                                                 the all-ones
        ///                                                 "DC" row)
        /// ```
        /// i.e. `codeword = XOR over set message bits of that bit's row`.
        /// The four 32-bit words are assembled with a running XOR
        /// accumulator exactly as the reference does (cheaper than
        /// re-XORing all 8 rows fresh per word), then packed
        /// little-endian into bytes — confirmed byte-exact against the
        /// reference's own output (`kat_vectors_code.zig`'s `rm_byte_*`
        /// vectors, produced by compiling and running this exact
        /// reference file locally; see SPEC.md's Verification section).
        pub fn encodeBlock(message: u8) Block {
            var w: [4]u32 = undefined;
            var acc: u32 = bitMask(message, 7);
            acc ^= bitMask(message, 0) & 0xaaaaaaaa;
            acc ^= bitMask(message, 1) & 0xcccccccc;
            acc ^= bitMask(message, 2) & 0xf0f0f0f0;
            acc ^= bitMask(message, 3) & 0xff00ff00;
            acc ^= bitMask(message, 4) & 0xffff0000;
            w[0] = acc;
            acc ^= bitMask(message, 5);
            w[1] = acc;
            acc ^= bitMask(message, 6);
            w[3] = acc;
            acc ^= bitMask(message, 5);
            w[2] = acc;

            var out: Block = undefined;
            for (0..4) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], w[i], .little);
            return out;
        }

        /// Encode + duplicate into a full symbol slot (reference:
        /// `reed_muller_encode`'s per-symbol body — this `Symbol` is
        /// exactly one of that function's `multiplicity`-wide slots).
        pub fn encodeSymbol(message: u8) Symbol {
            const block = encodeBlock(message);
            var out: Symbol = undefined;
            for (0..multiplicity) |c| @memcpy(out[c * 16 ..][0..16], &block);
            return out;
        }

        /// THE FABLE CORE (Reed-Muller half). Decodes one symbol slot
        /// (`multiplicity` duplicated, possibly noisy, 128-bit copies)
        /// back to the original message byte via maximum-likelihood
        /// decoding over the duplicated code.
        ///
        /// **Implemented algorithm — three steps, following the reference's
        /// `reed_muller_decode` exactly (spec calls this the "Green
        /// machine", §3.4.3; `macwilliams1977theory` = MacWilliams &
        /// Sloane, *The Theory of Error-Correcting Codes*, the
        /// reference's own cited source for Reed-Muller decoding theory):**
        ///
        ///  1. **Expand and sum** (reference: `expand_and_sum`). View
        ///     `cdw` as `multiplicity` back-to-back 128-bit blocks (each
        ///     `[4]u32`, same little-endian word layout `encodeBlock`
        ///     writes). For each of the 128 bit positions (4 words * 32
        ///     bits, iterated word-major then bit-minor, matching the
        ///     reference's `part`/`bit` nesting), sum that bit (as a
        ///     plain 0/1 integer, NOT a +-1 signed value yet) across all
        ///     `multiplicity` copies into a `[128]i16` (reference:
        ///     `rm_expanded_cdw = int16_t[128]`) accumulator. Output
        ///     range per entry: `[0, multiplicity]`.
        ///
        ///  2. **Fast Hadamard transform** (reference: `hadamard`, 7
        ///     butterfly passes since `128 == 2^7`). Given the 128-entry
        ///     accumulator as `src`, run exactly 7 passes; each pass reads
        ///     64 butterfly pairs from the current buffer and writes both
        ///     `sum` and `difference` into the other buffer, ping-ponging
        ///     between two `[128]i16` buffers each pass:
        ///     ```
        ///     for pass in 0..7:
        ///         for i in 0..64:
        ///             dst[i]      = src[2*i] + src[2*i + 1]
        ///             dst[i + 64] = src[2*i] - src[2*i + 1]
        ///         swap(src, dst)   // (via pointer swap, not a copy)
        ///     ```
        ///     This is the standard in-place (well, ping-pong-buffer)
        ///     radix-2 Hadamard/Walsh transform — NOT a custom variant;
        ///     any correct FHT implementation over 128 entries is
        ///     equivalent, but matching the reference's exact butterfly
        ///     order matters for producing byte-identical intermediate
        ///     values if those ever get KAT-pinned later.
        ///
        ///     After the 7 passes, apply the reference's fixup:
        ///     `transform[0] -= 64 * multiplicity` (this corrects
        ///     `expand_and_sum`'s "0/1 not +-1" shortcut post-hoc — see
        ///     `expand_and_sum`'s own reference comment: "all values are
        ///     halved [and] the first entry is 64 too high" relative to a
        ///     true +-1-input Hadamard transform; this one subtraction is
        ///     the only place that gets corrected, because it's the only
        ///     coefficient `find_peaks` below needs to be exactly right
        ///     relative to the others — the uniform halving of every
        ///     OTHER entry doesn't change which index has the peak
        ///     magnitude).
        ///
        ///  3. **Find the peak** (reference: `find_peaks`). Scan all 128
        ///     transform entries, tracking the one with the largest
        ///     ABSOLUTE value (ties broken by keeping the FIRST (smallest
        ///     index) peak seen, i.e. `>` not `>=` in the comparison —
        ///     the reference's own comment: "if there are two identical
        ///     peaks, the peak with smallest value in the lowest 7 bits is
        ///     taken"). The decoded byte is: bits `[0,7)` = the winning
        ///     index (0-127); bit 7 (0x80) = set if-and-only-if the
        ///     winning entry's SIGNED value was POSITIVE (a negative peak
        ///     means the codeword's complement was closer, which RM(1,7)
        ///     encodes via that eighth "all-ones DC row" in
        ///     `encodeBlock`'s doc comment).
        ///
        /// **KAT strategy once implemented**: `decodeSymbol(encodeSymbol(m))
        /// == m` for all 256 possible `m` (exhaustive, cheap — this is
        /// the zero-error case); then flip up to RM(1,7)'s error-
        /// correction radius worth of bits within one or more of the
        /// `multiplicity` copies and confirm the same `m` still comes
        /// back (the actual error-correction property maximum-likelihood
        /// decoding provides); a beyond-capacity corruption is expected
        /// to decode to a WRONG byte (there's no failure/rejection signal
        /// in this layer — `find_peaks` always returns *some* byte), so
        /// document that as expected behavior rather than an assertion
        /// target.
        pub fn decodeSymbol(cdw: Symbol) u8 {
            // Step 1: expand and sum (reference: `expand_and_sum`). Each
            // 128-bit copy is read as 4 little-endian u32 words (the same
            // layout encodeBlock writes / the reference's `rm_codeword_t.u32`
            // on its little-endian targets); bit `part*32 + bit` of every
            // copy is summed as a plain 0/1 value into a [128]i16
            // accumulator. Starting from zero and summing ALL copies is
            // arithmetically identical to the reference's "assign first
            // copy, += the rest".
            var expanded: [128]i16 = [_]i16{0} ** 128;
            for (0..multiplicity) |copy| {
                for (0..4) |part| {
                    const word = std.mem.readInt(u32, cdw[copy * 16 + part * 4 ..][0..4], .little);
                    for (0..32) |bit| {
                        expanded[part * 32 + bit] +=
                            @intCast((word >> @intCast(bit)) & 1);
                    }
                }
            }

            // Step 2: fast Hadamard transform (reference: `hadamard`) — 7
            // butterfly passes ping-ponging between two [128]i16 buffers
            // via pointer swap. 7 is odd, so the final pass's output lands
            // in `transform` (the reference's `dst`), exactly as
            // `reed_muller_decode` relies on. Data-independent access
            // pattern (no secret-dependent branches or indices).
            var transform: [128]i16 = undefined;
            var p1: *[128]i16 = &expanded;
            var p2: *[128]i16 = &transform;
            for (0..7) |_| {
                for (0..64) |i| {
                    p2[i] = p1[2 * i] + p1[2 * i + 1];
                    p2[i + 64] = p1[2 * i] - p1[2 * i + 1];
                }
                const p3 = p1;
                p1 = p2;
                p2 = p3;
            }
            // p1 now points at the final output buffer (`transform`).
            // Fix the first entry to get the half Hadamard transform: the
            // 0/1 (not +-1) expansion leaves every entry halved and entry 0
            // exactly 64*multiplicity too high; only entry 0's excess
            // changes which index carries the peak magnitude, so it is the
            // only correction needed (reference: `transform[0] -= 64 *
            // MULTIPLICITY`).
            p1[0] -= 64 * @as(i16, multiplicity);

            // Step 3: find the peak (reference: `find_peaks`). Track the
            // entry with the largest ABSOLUTE value; strict `>` keeps the
            // FIRST (smallest-index) peak on ties, matching the reference's
            // tie-break. Branch-free masked selects mirror the reference's
            // constant-time structure (its ternaries over branch-free
            // `pos_mask` arithmetic).
            var peak_abs_value: i32 = 0;
            var peak_value: i32 = 0;
            var peak_pos: i32 = 0;
            for (0..128) |i| {
                const t: i32 = p1[i];
                const pos_mask: i32 = 0 -% @as(i32, @intFromBool(t > 0));
                const absolute: i32 = (pos_mask & t) | (~pos_mask & -t);
                const gt_mask: i32 = 0 -% @as(i32, @intFromBool(absolute > peak_abs_value));
                peak_value = (gt_mask & t) | (~gt_mask & peak_value);
                peak_pos = (gt_mask & @as(i32, @intCast(i))) | (~gt_mask & peak_pos);
                peak_abs_value = (gt_mask & absolute) | (~gt_mask & peak_abs_value);
            }
            // Bit 7 (0x80) = set iff the winning entry's SIGNED value was
            // positive (the all-ones "DC row" / complement bit).
            peak_pos |= 128 * @as(i32, @intFromBool(peak_value > 0));
            return @intCast(peak_pos);
        }
    };
}

// ── tests: encode only (decode is gated, see code_kat_test.zig) ────────

const RM128 = RM(params.hqc128);
const RM192 = RM(params.hqc192);
const RM256 = RM(params.hqc256);

test "RM: block_bytes == multiplicity * 16 for every parameter set" {
    const t = std.testing;
    try t.expectEqual(@as(usize, 3 * 16), RM128.block_bytes);
    try t.expectEqual(@as(usize, 5 * 16), RM192.block_bytes);
    try t.expectEqual(@as(usize, 5 * 16), RM256.block_bytes);
}

test "RM128: encodeSymbol duplicates encodeBlock exactly multiplicity times" {
    const t = std.testing;
    const block = RM128.encodeBlock(0x42);
    const sym = RM128.encodeSymbol(0x42);
    for (0..RM128.multiplicity) |c| {
        try t.expectEqualSlices(u8, &block, sym[c * 16 ..][0..16]);
    }
}

test "RM128: encodeBlock(0) is the all-zero block, encodeBlock(0x80) is the all-ones block" {
    const t = std.testing;
    try t.expectEqualSlices(u8, &([_]u8{0} ** 16), &RM128.encodeBlock(0));
    try t.expectEqualSlices(u8, &([_]u8{0xff} ** 16), &RM128.encodeBlock(0x80));
}
