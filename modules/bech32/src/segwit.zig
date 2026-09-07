// SPDX-License-Identifier: MIT
//! Segwit address encoding (BIP173 "Segwit address format" + BIP350's
//! amendment: v0 stays bech32, v1+ (Taproot and beyond) is bech32m) — the
//! 8-bit witness-program <-> 5-bit bech32-data conversion plus the
//! consensus-rule checks BIP173/§"Decoding" spells out.

const std = @import("std");
const bech32 = @import("bech32.zig");

/// BIP141: witness programs are 2 to 40 bytes.
pub const min_program_len = 2;
pub const max_program_len = 40;
/// BIP141/BIP173: witness version is OP_0..OP_16 (0..16).
pub const max_witver: u5 = 16;

/// Largest byte count `quintetsToProgram` can ever WRITE before its own
/// length-validity check runs (it must not overflow its output buffer even
/// for a checksum-valid but consensus-invalid address): the data part minus
/// one quintet (witness version) is at most `bech32.max_data_len - 1`
/// quintets, i.e. `floor((bech32.max_data_len - 1) * 5 / 8)` bytes.
const max_decode_program_bytes = (bech32.max_data_len - 1) * 5 / 8;

const ConvertError = error{
    /// 5-to-8 conversion: either an entire extra padding quintet (>=5
    /// leftover bits) or a non-zero discarded padding bit (BIP173
    /// "Decoding": the incomplete tail group "MUST be 4 bits or less, MUST
    /// be all zeroes").
    InvalidPadding,
};

/// 8-bit witness-program bytes -> 5-bit bech32 data words, zero-padding the
/// final incomplete group (BIP173 encode direction). `out` must be at least
/// `(program.len * 8 + 4) / 5` long.
fn programToQuintets(program: []const u8, out: []u5) usize {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var n: usize = 0;
    for (program) |byte| {
        acc = ((acc << 8) | byte) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[n] = @intCast((acc >> bits) & 0x1f);
            n += 1;
        }
    }
    if (bits > 0) {
        const shift: u5 = 5 - bits;
        out[n] = @intCast((acc << shift) & 0x1f);
        n += 1;
    }
    return n;
}

/// 5-bit bech32 data words -> witness-program bytes (BIP173 decode
/// direction). Rejects non-canonical padding per the spec's MUST rules.
/// `out` must be at least `max_decode_program_bytes` long (see doc comment).
fn quintetsToProgram(quintets: []const u5, out: []u8) ConvertError!usize {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var n: usize = 0;
    for (quintets) |q| {
        acc = ((acc << 5) | q) & 0xfff;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            std.debug.assert(n < out.len); // see max_decode_program_bytes
            out[n] = @intCast((acc >> bits) & 0xff);
            n += 1;
        }
    }
    if (bits >= 5) return error.InvalidPadding;
    const shift: u5 = 8 - bits;
    if (((acc << shift) & 0xff) != 0) return error.InvalidPadding;
    return n;
}

pub const SegwitError = bech32.DecodeError || ConvertError || error{
    /// Decoded HRP doesn't match the caller's expected chain HRP.
    InvalidHrp,
    /// The data part holds only the checksum — no witness version present.
    EmptyDataSection,
    /// Witness version (first data value) is > 16.
    InvalidWitnessVersion,
    /// Witness version 0 must be bech32, version 1+ must be bech32m
    /// (BIP350) — the decoded string's variant doesn't match its witver.
    InvalidVariant,
    /// Program length outside [2,40], or (for witver 0) not exactly 20/32.
    InvalidProgramLength,
};

/// A decoded segwit address: witness version + program.
pub const SegwitData = struct {
    witver: u5,
    program_buf: [max_decode_program_bytes]u8,
    program_len: u8,

    pub fn program(self: *const SegwitData) []const u8 {
        return self.program_buf[0..self.program_len];
    }
};

/// Decodes and fully validates a segwit address against `expected_hrp`
/// ("bc"/"tb"/... — must already be lowercase canonical). Fail-closed on
/// untrusted input: enforces every MUST in BIP173 "Decoding" + BIP350's
/// variant-match rule before returning.
pub fn decodeSegwit(expected_hrp: []const u8, address: []const u8) SegwitError!SegwitData {
    const decoded = try bech32.decode(address);
    if (!std.mem.eql(u8, decoded.hrp(), expected_hrp)) return error.InvalidHrp;

    const data = decoded.data();
    if (data.len == 0) return error.EmptyDataSection;

    const witver = data[0];
    if (witver > max_witver) return error.InvalidWitnessVersion;

    const expected_encoding: bech32.Encoding = if (witver == 0) .bech32 else .bech32m;
    if (decoded.encoding != expected_encoding) return error.InvalidVariant;

    var result: SegwitData = undefined;
    result.witver = witver;
    result.program_len = @intCast(try quintetsToProgram(data[1..], &result.program_buf));

    if (result.program_len < min_program_len or result.program_len > max_program_len)
        return error.InvalidProgramLength;
    if (witver == 0 and result.program_len != 20 and result.program_len != 32)
        return error.InvalidProgramLength;

    return result;
}

/// Encodes a segwit address: v0 uses bech32, v1+ uses bech32m (BIP350).
pub fn encodeSegwit(hrp: []const u8, witver: u5, program: []const u8) (bech32.EncodeError || SegwitError)!bech32.Bech32String {
    if (witver > max_witver) return error.InvalidWitnessVersion;
    if (program.len < min_program_len or program.len > max_program_len) return error.InvalidProgramLength;
    if (witver == 0 and program.len != 20 and program.len != 32) return error.InvalidProgramLength;

    var data: [1 + ((max_program_len * 8 + 4) / 5)]u5 = undefined;
    data[0] = witver;
    const n = programToQuintets(program, data[1..]);

    const encoding: bech32.Encoding = if (witver == 0) .bech32 else .bech32m;
    return bech32.encode(hrp, data[0 .. 1 + n], encoding);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "programToQuintets/quintetsToProgram round-trip, all program lengths 2..40" {
    var program: [max_program_len]u8 = undefined;
    for (&program, 0..) |*b, i| b.* = @intCast((i * 37 + 11) % 256);

    var len: usize = min_program_len;
    while (len <= max_program_len) : (len += 1) {
        var quintets: [1 + ((max_program_len * 8 + 4) / 5)]u5 = undefined;
        const nq = programToQuintets(program[0..len], &quintets);

        var back: [max_decode_program_bytes]u8 = undefined;
        const nb = try quintetsToProgram(quintets[0..nq], &back);

        try testing.expectEqualSlices(u8, program[0..len], back[0..nb]);
    }
}

test "encodeSegwit v0 then decodeSegwit round-trips" {
    var program: [20]u8 = undefined;
    for (&program, 0..) |*b, i| b.* = @intCast(i);

    const addr = try encodeSegwit("bc", 0, &program);
    const dec = try decodeSegwit("bc", addr.slice());
    try testing.expectEqual(@as(u5, 0), dec.witver);
    try testing.expectEqualSlices(u8, &program, dec.program());
}

test "encodeSegwit v1 (Taproot) then decodeSegwit round-trips, uses bech32m" {
    var program: [32]u8 = undefined;
    for (&program, 0..) |*b, i| b.* = @intCast(i * 3 + 1);

    const addr = try encodeSegwit("bc", 1, &program);
    const dec = try decodeSegwit("bc", addr.slice());
    try testing.expectEqual(@as(u5, 1), dec.witver);
    try testing.expectEqualSlices(u8, &program, dec.program());
}

test "decodeSegwit: wrong HRP rejected" {
    var program: [20]u8 = undefined;
    @memset(&program, 0xAB);
    const addr = try encodeSegwit("bc", 0, &program);
    try testing.expectError(error.InvalidHrp, decodeSegwit("tb", addr.slice()));
}

test "decodeSegwit: the HRP is compared whole — a chain whose HRP extends the expected one is not that chain (A1 M2)" {
    // The corpus's only negative HRP vector differs in its FIRST byte
    // (`tc` vs `bc`), so a compare weakened to a prefix test — or to the
    // first byte alone — stayed green. Regtest is `bcrt`: under a prefix
    // compare a regtest address passes as MAINNET, which is the chain-id
    // confusion the HRP exists to prevent.
    var program: [20]u8 = undefined;
    @memset(&program, 0xAB);
    const regtest = try encodeSegwit("bcrt", 0, &program);
    try testing.expectError(error.InvalidHrp, decodeSegwit("bc", regtest.slice()));
    const mainnet = try encodeSegwit("bc", 0, &program);
    try testing.expectError(error.InvalidHrp, decodeSegwit("bcrt", mainnet.slice()));
    try testing.expectError(error.InvalidHrp, decodeSegwit("b", mainnet.slice()));
    // Same first byte, different chain: testnet `tb` vs a hypothetical `tc`.
    const testnet = try encodeSegwit("tb", 0, &program);
    try testing.expectError(error.InvalidHrp, decodeSegwit("tc", testnet.slice()));
    _ = try decodeSegwit("tb", testnet.slice());
}

test "decodeSegwit: an incomplete tail group of 5 or more bits is InvalidPadding even when the bits are zero (A1 M3)" {
    // BIP173 "Decoding": the incomplete group "MUST be 4 bits or less" AND
    // "MUST be all zeroes". The official invalid vectors only exercise the
    // second half; a check weakened to `bits > 5` accepted a 20-byte
    // program carried in 33 quintets (165 bits: 160 + a whole zero
    // padding quintet), which decodes to the SAME program as the canonical
    // 32-quintet form — a second valid spelling of one address.
    var program: [20]u8 = undefined;
    @memset(&program, 0x42);
    var data: [1 + 33]u5 = undefined;
    data[0] = 0;
    const nq = programToQuintets(&program, data[1..]);
    try testing.expectEqual(@as(usize, 32), nq);
    data[1 + nq] = 0; // one extra all-zero quintet: 5 leftover bits
    const padded = try bech32.encode("bc", &data, .bech32);
    try testing.expectError(error.InvalidPadding, decodeSegwit("bc", padded.slice()));
    // The canonical spelling of the same program still decodes.
    const canonical = try bech32.encode("bc", data[0 .. 1 + nq], .bech32);
    const got = try decodeSegwit("bc", canonical.slice());
    try testing.expectEqualSlices(u8, &program, got.program());
    // And the audit's concrete instance: the BIP173 vector address with a
    // whole zero padding quintet inserted before the checksum.
    try testing.expectError(error.InvalidPadding, decodeSegwit("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kqkhhp9x"));
}

test "decodeSegwit: v0 program length must be 20 or 32" {
    var program21: [21]u8 = undefined;
    @memset(&program21, 1);
    try testing.expectError(error.InvalidProgramLength, encodeSegwit("bc", 0, &program21));
}

test "decodeSegwit: witver > 16 rejected" {
    var program: [20]u8 = undefined;
    @memset(&program, 1);
    try testing.expectError(error.InvalidWitnessVersion, encodeSegwit("bc", 17, &program));
}

test "decodeSegwit: bech32 address with witver 1 rejected (must be bech32m)" {
    // Hand-build a v1 address using the WRONG (bech32) checksum constant.
    var program: [32]u8 = undefined;
    @memset(&program, 0x42);
    var data: [1 + 52]u5 = undefined;
    data[0] = 1;
    const nq = programToQuintets(&program, data[1..]);
    const bad = try bech32.encode("bc", data[0 .. 1 + nq], .bech32); // wrong variant on purpose
    try testing.expectError(error.InvalidVariant, decodeSegwit("bc", bad.slice()));
}

test "decodeSegwit: malicious oversized data section fails closed, no overflow" {
    // A checksum-valid address whose data section (80 program quintets ->
    // 50 bytes, evenly divisible so padding validation trivially passes)
    // is far longer than any real witness program could produce — must be
    // rejected by length validation, not overrun `program_buf`.
    var data: [81]u5 = undefined;
    data[0] = 0; // witver 0 forces the bech32 variant
    @memset(data[1..], 5); // 80 quintets = 400 bits = exactly 50 bytes, zero remainder
    const addr = try bech32.encode("bc", &data, .bech32);
    try testing.expectError(error.InvalidProgramLength, decodeSegwit("bc", addr.slice()));
}

// ── fuzz: segwit address decode, never panics ───────────────────────────────
//
// `decodeSegwit` is the entry point a wallet calls on a raw address string a
// user pasted or a QR code produced — bech32 decode plus the witness-
// version/program-length validation the regression above targets.

/// A corpus entry in the format `Smith.slice` actually reads — a little-endian
/// `u32` length, then the address — followed by one `u64` word per octet the
/// charset knob in `fuzzDecodeSegwit` reads afterwards (`1` bends that octet
/// into the charset, `0` leaves it alone; once the words run out every
/// remaining draw is the weight minimum, i.e. `false`).
///
/// ⛔ Two defects were measured here on 2026-09-08, and both were silent.
/// (1) The corpus was a list of BARE string literals. `Smith.slice` reads a
/// little-endian `u32` length before the bytes, so the P2WPKH vector reached
/// the decoder as `"w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"` — every seed
/// arrived minus its own first four octets, which for a segwit address takes
/// away the `bc1` prefix and the separator. **All three BIP-173/BIP-350
/// vectors were rejected before the witness-version/program-length validation
/// this harness exists to reach**: 0 of 3 accepted.
/// (2) With the seed consumed by the byte draw, `boolWeighted(1, 3)` returned
/// its weight minimum: the loop ran 135 times over the corpus and bent **0**
/// octets, so the charset-bending branch had never executed once.
fn bendSeed(comptime raw: []const u8, comptime bends: []const u64) []const u8 {
    return &struct {
        const words = blk: {
            var w: [bends.len * 8]u8 = undefined;
            for (bends, 0..) |b, i| std.mem.writeInt(u64, w[i * 8 ..][0..8], b, .little);
            break :blk w;
        };
        const bytes = std.mem.toBytes(@as(u32, raw.len)) ++ raw[0..raw.len].* ++ words;
    }.bytes;
}

const decode_seeds = [_][]const u8{
    bendSeed("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", &.{}), // v0 P2WPKH
    bendSeed("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", &.{}), // v1 P2TR
    bendSeed("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kqkhhp9x", &.{}), // the checksum near-miss
    bendSeed("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", &.{}), // HrpMismatch: testnet hrp
    // The charset knob, one word per octet: sixteen octets that are NOT in
    // the charset, every one of them bent into it — the input a tail-less
    // seed cannot produce, and the only one that reaches the loop body.
    bendSeed(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &([_]u64{1} ** 16)),
    bendSeed("", &.{}), // and the input a corpus-less target runs for ever
};

test "fuzz: decodeSegwit never panics on arbitrary text" {
    try testing.fuzz({}, fuzzDecodeSegwit, .{ .corpus = &decode_seeds });
}

const fuzz_alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l1bc";

fn fuzzDecodeSegwit(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    const len = smith.slice(&buf); // not `bytes` + a ranged length: that always yields 0
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 3)) c.* = fuzz_alphabet[c.* % fuzz_alphabet.len];
    }
    _ = decodeSegwit("bc", buf[0..len]) catch return;
}

test "corpus: every segwit seed reaches decodeSegwit, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // ⛔ Not `accepted > 0`. `program_octets` is the number the collapsed
    // corpus cannot move — it only grows when a seed's own octets survive the
    // draw AND clear the checksum and the length validation — and `bent` is
    // the one a tail-less corpus cannot move.
    var nonempty: usize = 0;
    var bent: usize = 0;
    var accepted: usize = 0;
    var program_octets: usize = 0;
    var witver_total: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [128]u8 = undefined;
        const len = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        for (buf[0..len]) |*c| {
            if (smith.boolWeighted(1, 3)) {
                c.* = fuzz_alphabet[c.* % fuzz_alphabet.len];
                bent += 1;
            }
        }
        if (decodeSegwit("bc", buf[0..len])) |d| {
            accepted += 1;
            program_octets += d.program().len;
            witver_total += d.witver;
        } else |_| {}
    }
    try testing.expectEqual(decode_seeds.len - 1, nonempty); // all but the empty string
    // Measured 2026-09-08. Before: every seed arrived four octets short of the
    // address it was written as — 0 accepted, 0 program octets, 0 bent. After:
    try testing.expectEqual(@as(usize, 16), bent);
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 52), program_octets);
    try testing.expectEqual(@as(usize, 1), witver_total);
}
