// SPDX-License-Identifier: MIT
//! Core BIP173 (bech32) + BIP350 (bech32m) codec: the BCH checksum, HRP
//! expansion, charset mapping, and the generic `encode`/`decode` pair over
//! 5-bit-grouped data. `segwit.zig` layers the witness-address consensus
//! rules on top; this file has no notion of witness versions or programs.
//!
//! No allocation: `decode` returns a fixed-size value type sized to the
//! spec's own 90-character total-length ceiling, and `encode` writes into a
//! similarly-sized value type. Both are cheap to return by value (well under
//! 200 bytes).

const std = @import("std");

/// Which BCH constant a string checksums against — BIP173's original
/// `1`, or BIP350's `0x2bc830a3` (segwit v1+/Taproot).
pub const Encoding = enum { bech32, bech32m };

fn encodingConst(e: Encoding) u32 {
    return switch (e) {
        .bech32 => 1,
        .bech32m => 0x2bc830a3,
    };
}

/// The 32-symbol charset (BIP173 "Human-readable part and data part"
/// table), index == 5-bit value.
pub const charset: *const [32]u8 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const charset_rev: [256]i8 = blk: {
    var t: [256]i8 = [_]i8{-1} ** 256;
    for (charset, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

fn charValue(c: u8) ?u5 {
    const v = charset_rev[c];
    if (v < 0) return null;
    return @intCast(v);
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

// ── length limits (BIP173 "human-readable part" + reference-implementation
// 90-char total ceiling) ─────────────────────────────────────────────────

pub const max_hrp_len = 83;
pub const max_len = 90;
pub const checksum_len = 6;
/// Max payload (data-part symbols, excluding the 6-symbol checksum):
/// `max_len - 1 (shortest HRP) - 1 (separator) - checksum_len`.
pub const max_data_len = max_len - 1 - 1 - checksum_len;

/// Largest combined `hrp_expand(hrp) ++ data ++ checksum` vector the
/// checksum math ever needs: `2*max_hrp_len + 1` (hrp expansion) +
/// `max_data_len + checksum_len` (worst-case data-part-including-checksum
/// when hrp is 1 char, i.e. `max_len - 2`).
const max_combined = 2 * max_hrp_len + 1 + (max_len - 2);

// ── BCH checksum (BIP173 "Checksum" §) ──────────────────────────────────

const gen = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

fn polymod(values: []const u5) u32 {
    var chk: u32 = 1;
    for (values) |v| {
        const b: u32 = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ @as(u32, v);
        if (b & 1 != 0) chk ^= gen[0];
        if (b & 2 != 0) chk ^= gen[1];
        if (b & 4 != 0) chk ^= gen[2];
        if (b & 8 != 0) chk ^= gen[3];
        if (b & 16 != 0) chk ^= gen[4];
    }
    return chk;
}

/// `bech32_hrp_expand`: high 3 bits of each HRP byte, then a 0 separator,
/// then the low 5 bits of each HRP byte — case-sensitive (encodes whether
/// each byte was upper/lowercase), which is why checksum verification is
/// always done against the *lowered* string (BIP173 "Uppercase/lowercase").
fn hrpExpandInto(hrp: []const u8, out: []u5) usize {
    for (hrp, 0..) |c, i| out[i] = @intCast(c >> 5);
    out[hrp.len] = 0;
    for (hrp, 0..) |c, i| out[hrp.len + 1 + i] = @intCast(c & 31);
    return 2 * hrp.len + 1;
}

fn createChecksum(hrp: []const u8, data: []const u5, encoding: Encoding) [checksum_len]u5 {
    var buf: [max_combined]u5 = undefined;
    var n = hrpExpandInto(hrp, buf[0..]);
    for (data) |d| {
        buf[n] = d;
        n += 1;
    }
    for (0..checksum_len) |_| {
        buf[n] = 0;
        n += 1;
    }
    const pm = polymod(buf[0..n]) ^ encodingConst(encoding);
    var out: [checksum_len]u5 = undefined;
    for (0..checksum_len) |i| {
        const shift: u5 = @intCast(5 * (5 - i));
        out[i] = @intCast((pm >> shift) & 31);
    }
    return out;
}

/// Returns which encoding (if either) `hrp` + `data_with_checksum` checksums
/// against — `null` if neither BIP173's `1` nor BIP350's `0x2bc830a3` match.
fn detectEncoding(hrp: []const u8, data_with_checksum: []const u5) ?Encoding {
    var buf: [max_combined]u5 = undefined;
    var n = hrpExpandInto(hrp, buf[0..]);
    for (data_with_checksum) |d| {
        buf[n] = d;
        n += 1;
    }
    const pm = polymod(buf[0..n]);
    if (pm == 1) return .bech32;
    if (pm == encodingConst(.bech32m)) return .bech32m;
    return null;
}

// ── decode ───────────────────────────────────────────────────────────────

pub const DecodeError = error{
    /// Total string length exceeds `max_len` (90).
    TooLong,
    /// The string mixes uppercase and lowercase letters.
    MixedCase,
    /// No `1` separator character found.
    NoSeparator,
    /// The human-readable part is empty (separator is the first character).
    EmptyHrp,
    /// The human-readable part exceeds `max_hrp_len` (83).
    HrpTooLong,
    /// An HRP byte is outside the US-ASCII [33,126] range.
    HrpCharOutOfRange,
    /// The data part (including checksum) is shorter than `checksum_len` (6).
    DataTooShort,
    /// A data-part (or checksum) character is not in `charset`.
    InvalidDataChar,
    /// Neither the bech32 nor bech32m checksum constant matches.
    InvalidChecksum,
};

/// A decoded bech32/bech32m string: HRP + payload data (checksum already
/// verified and stripped) + which of the two encodings it checksummed
/// against. Both HRP and data are lowercased, per BIP173 ("the lowercase
/// form is used when determining a character's value").
pub const Decoded = struct {
    hrp_buf: [max_hrp_len]u8,
    hrp_len: u8,
    data_buf: [max_data_len]u5,
    data_len: u8,
    encoding: Encoding,

    pub fn hrp(self: *const Decoded) []const u8 {
        return self.hrp_buf[0..self.hrp_len];
    }

    pub fn data(self: *const Decoded) []const u5 {
        return self.data_buf[0..self.data_len];
    }
};

/// Decodes and checksum-verifies a bech32/bech32m string. Fail-closed on
/// untrusted input: rejects mixed case, out-of-charset characters, a bad
/// checksum, and every length limit from BIP173's "Test vectors" appendix
/// before touching the charset/checksum math.
pub fn decode(s: []const u8) DecodeError!Decoded {
    if (s.len > max_len) return error.TooLong;

    var saw_lower = false;
    var saw_upper = false;
    for (s) |c| {
        if (c >= 'a' and c <= 'z') saw_lower = true;
        if (c >= 'A' and c <= 'Z') saw_upper = true;
    }
    if (saw_lower and saw_upper) return error.MixedCase;

    // The separator is the LAST '1' in the string (data-part charset never
    // contains '1', so any '1' left of the true separator belongs to the HRP).
    const sep = std.mem.lastIndexOfScalar(u8, s, '1') orelse return error.NoSeparator;
    if (sep == 0) return error.EmptyHrp;
    if (sep > max_hrp_len) return error.HrpTooLong;

    for (s[0..sep]) |c| {
        if (c < 33 or c > 126) return error.HrpCharOutOfRange;
    }

    const data_part = s[sep + 1 ..];
    if (data_part.len < checksum_len) return error.DataTooShort;

    var result: Decoded = undefined;
    result.hrp_len = @intCast(sep);
    for (s[0..sep], 0..) |c, i| result.hrp_buf[i] = toLower(c);

    var full: [max_data_len + checksum_len]u5 = undefined;
    for (data_part, 0..) |c, i| {
        full[i] = charValue(toLower(c)) orelse return error.InvalidDataChar;
    }

    const encoding = detectEncoding(result.hrp(), full[0..data_part.len]) orelse
        return error.InvalidChecksum;

    result.data_len = @intCast(data_part.len - checksum_len);
    @memcpy(result.data_buf[0..result.data_len], full[0..result.data_len]);
    result.encoding = encoding;
    return result;
}

// ── encode ───────────────────────────────────────────────────────────────

pub const EncodeError = error{
    EmptyHrp,
    HrpTooLong,
    HrpCharOutOfRange,
    /// `hrp.len + 1 + data.len + checksum_len` would exceed `max_len`.
    TooLong,
};

/// A fixed-buffer encoded string. `encode` always produces the canonical
/// all-lowercase form (BIP173: "Encoders MUST always output an all
/// lowercase Bech32 string").
pub const Bech32String = struct {
    buf: [max_len]u8,
    len: u8,

    pub fn slice(self: *const Bech32String) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Encodes `hrp` + `data` (5-bit values) with a freshly computed checksum
/// for `encoding`. `hrp` is lowercased automatically (case carries no
/// meaning — see `decode`'s doc comment); every resulting byte is validated
/// against the [33,126] HRP range regardless of input case.
pub fn encode(hrp: []const u8, data: []const u5, encoding: Encoding) EncodeError!Bech32String {
    if (hrp.len == 0) return error.EmptyHrp;
    if (hrp.len > max_hrp_len) return error.HrpTooLong;
    if (hrp.len + 1 + data.len + checksum_len > max_len) return error.TooLong;

    var result: Bech32String = undefined;
    var n: usize = 0;
    for (hrp) |c| {
        if (c < 33 or c > 126) return error.HrpCharOutOfRange;
        result.buf[n] = toLower(c);
        n += 1;
    }
    result.buf[n] = '1';
    n += 1;

    const lowered_hrp = result.buf[0..hrp.len];
    for (data) |d| {
        result.buf[n] = charset[d];
        n += 1;
    }
    const cksum = createChecksum(lowered_hrp, data, encoding);
    for (cksum) |d| {
        result.buf[n] = charset[d];
        n += 1;
    }

    result.len = @intCast(n);
    return result;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "polymod of empty values is the multiplicative identity (1)" {
    try testing.expectEqual(@as(u32, 1), polymod(&.{}));
}

test "hrpExpandInto: 'a' -> [3, 0, 1] (0x61 = 0b011_00001)" {
    var out: [3]u5 = undefined;
    const n = hrpExpandInto("a", &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u5, &.{ 3, 0, 1 }, &out);
}

test "encode then decode round-trips (bech32)" {
    const data = [_]u5{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const enc = try encode("test", &data, .bech32);
    const dec = try decode(enc.slice());
    try testing.expectEqualStrings("test", dec.hrp());
    try testing.expectEqualSlices(u5, &data, dec.data());
    try testing.expectEqual(Encoding.bech32, dec.encoding);
}

test "encode then decode round-trips (bech32m)" {
    const data = [_]u5{ 31, 30, 29, 0, 15 };
    const enc = try encode("xyz", &data, .bech32m);
    const dec = try decode(enc.slice());
    try testing.expectEqualStrings("xyz", dec.hrp());
    try testing.expectEqualSlices(u5, &data, dec.data());
    try testing.expectEqual(Encoding.bech32m, dec.encoding);
}

test "encode uppercases nothing: HRP is always lowered in output" {
    const enc = try encode("BC", &.{}, .bech32);
    try testing.expect(std.mem.indexOfAny(u8, enc.slice(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == null);
}

test "decode: empty HRP rejected" {
    try testing.expectError(error.EmptyHrp, decode("1qzzfhee"));
}

test "decode: no separator rejected" {
    try testing.expectError(error.NoSeparator, decode("pzry9x0s0muk"));
}

test "decode: mixed case rejected" {
    try testing.expectError(error.MixedCase, decode("Ab1qqqqqqq"));
}

test "decode: checksum too short rejected" {
    try testing.expectError(error.DataTooShort, decode("li1dgmt3"));
}

test "decode: invalid data character rejected" {
    try testing.expectError(error.InvalidDataChar, decode("x1b4n0q5v"));
}

test "decode: bit-flipped checksum is rejected (positive control)" {
    const data = [_]u5{ 1, 2, 3, 4, 5 };
    const enc = try encode("bc", &data, .bech32);
    var tampered = enc.buf;
    // Flip one bit in the last (checksum) character.
    tampered[enc.len - 1] ^= 0x01;
    try testing.expectError(error.InvalidChecksum, decode(tampered[0..enc.len]));
}

test "encode: TooLong rejected" {
    var hrp_buf: [max_hrp_len]u8 = undefined;
    @memset(&hrp_buf, 'a');
    var data_buf: [max_data_len]u5 = undefined;
    @memset(&data_buf, 0);
    try testing.expectError(error.TooLong, encode(&hrp_buf, &data_buf, .bech32));
}

// ── fuzz: bech32/bech32m string decode, never panics ────────────────────────
//
// `decode` is what runs on an address/invoice a user pastes in, or scans
// from a QR code — attacker/user-controlled text with no structural
// guarantee until the checksum is verified. Bias toward the bech32 charset
// plus the '1' separator so the fuzzer gets past the length gate into the
// charset/checksum math this file's own doc calls out as the real target.

test "fuzz: decode never panics on arbitrary text" {
    try testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l1"; // charset + separator
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    for (buf[0..len]) |*c| {
        if (smith.boolWeighted(1, 3)) c.* = alphabet[c.* % alphabet.len];
    }
    _ = decode(buf[0..len]) catch return;
}
