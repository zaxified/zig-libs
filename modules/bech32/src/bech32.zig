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

// NOTE (load-bearing, do not trim `kat_vectors.zig`): a consistent mutation
// of `0x2bc830a3` here is invisible to every round-trip test in this file —
// `createChecksum` and `detectEncoding` both read the constant from this one
// function, so encode/decode still agree with each other under a wrong
// value. Only the imported BIP-350 vectors in `kat_test.zig` catch it
// (verified by fault injection: 37 pass / 3 fail, all three BIP350 cases).
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
    var t: [256]i8 = @as([256]i8, @splat(-1));
    for (charset, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

/// `charset`'s inverse: the 5-bit value a bech32 data-part byte encodes, or
/// `null` if `c` is not in `charset` at all. Public so a length-uncapped
/// caller (`lninvoice`'s BOLT#11/#12 codec, which cannot reuse `decode`/
/// `encode` because they enforce BIP173's 90-char ceiling via fixed stack
/// buffers) can share this table instead of redeclaring it — see M6 in
/// `A1/bech32.md`.
pub fn charValue(c: u8) ?u5 {
    const v = charset_rev[c];
    if (v < 0) return null;
    return @intCast(v);
}

/// ASCII-lowercases one byte; non-letters pass through unchanged. Public for
/// the same length-uncapped-caller reason as `charValue`.
pub fn toLower(c: u8) u8 {
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

/// The BCH checksum's core recurrence (BIP173 "Checksum"). Already
/// length-generic — `values` is a plain slice, not a fixed-size internal
/// buffer — so it is the one piece of `createChecksum`/`detectEncoding`
/// that a length-uncapped caller genuinely needs verbatim, not just a
/// same-shaped copy of. Public for `lninvoice`'s BOLT#11/#12 codec (M6 in
/// `A1/bech32.md`): the two must never drift against each other on the one
/// piece of math a bech32-family checksum actually is.
pub fn polymod(values: []const u5) u32 {
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
/// Already length-generic (writes into a caller-sized `out`, no internal
/// cap), so it is public for the same length-uncapped-caller reason as
/// `polymod` — see M6 in `A1/bech32.md`.
pub fn hrpExpandInto(hrp: []const u8, out: []u5) usize {
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
    const sep = std.mem.findScalarLast(u8, s, '1') orelse return error.NoSeparator;
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

// ── error location (what Bitcoin Core's `LocateErrors` reports) ───────────

/// Why `locateErrors` has something to say about a string.
pub const Fault = enum {
    /// The string is a valid bech32/bech32m string (`Located.encoding` says which).
    none,
    /// The checksum is valid, but for the other constant than `expected`
    /// (`Located.encoding` is the one it carries); no positions.
    wrong_variant,
    /// Longer than `max_len`; no positions.
    too_long,
    /// Upper- and lowercase letters mixed; `positions` = the first letter whose
    /// case differs from the case of the string's first letter.
    mixed_case,
    /// A byte of the human-readable part outside US-ASCII [33,126]; every such position.
    invalid_character,
    /// No `1` separator; no positions.
    no_separator,
    /// The separator is first (empty HRP), the HRP is longer than `max_hrp_len`, or
    /// fewer than `checksum_len` characters follow it; `positions` = the separator.
    bad_separator,
    /// A data-part character not in `charset`; every such position.
    invalid_data_character,
    /// The checksum fails and one or two substituted data-part characters explain it:
    /// `positions` (ascending, indexes into the input) and `fixes` (the character
    /// that belongs there, lowercase). Errors in the HRP are not located.
    bad_checksum,
    /// The checksum fails and no one- or two-character substitution in the data part
    /// repairs it (three or more errors, an error in the HRP or the separator, an
    /// insertion or a deletion).
    bad_checksum_unlocated,
};

/// The result of `locateErrors`. A decoder that finds errors is a guess beyond two
/// substitutions: a string with three or more wrong characters can be "repaired"
/// into a different valid string, so treat `bad_checksum` as a hint to show the
/// user, never as a correction to apply silently.
pub const Located = struct {
    fault: Fault,
    /// For `.none` the encoding the string checksums against; for `.bad_checksum` the
    /// one the repair was computed for.
    encoding: ?Encoding = null,
    count: u8 = 0,
    pos_buf: [max_len]u8 = undefined,
    fix_buf: [2]u8 = undefined,

    pub fn positions(self: *const Located) []const u8 {
        return self.pos_buf[0..self.count];
    }

    /// For `.bad_checksum`: the character that belongs at `positions()[i]`.
    pub fn fixes(self: *const Located) []const u8 {
        return if (self.fault == .bad_checksum) self.fix_buf[0..self.count] else self.fix_buf[0..0];
    }
};

/// The polymod step for a zero symbol (the linear part of `polymod`).
fn stepZero(chk: u32) u32 {
    const b: u32 = chk >> 25;
    var c = (chk & 0x1ffffff) << 5;
    if (b & 1 != 0) c ^= gen[0];
    if (b & 2 != 0) c ^= gen[1];
    if (b & 4 != 0) c ^= gen[2];
    if (b & 8 != 0) c ^= gen[3];
    if (b & 16 != 0) c ^= gen[4];
    return c;
}

const Atom = struct { key: u32, pos: u8, val: u8 };

fn atomLess(_: void, a: Atom, b: Atom) bool {
    return a.key < b.key;
}

fn atomOrder(key: u32, a: Atom) std.math.Order {
    return std.math.order(key, a.key);
}

const Repair = struct {
    enc: Encoding,
    a: Atom,
    b: ?Atom,

    fn size(r: Repair) u8 {
        return if (r.b == null) 1 else 2;
    }
};

/// The one or two table atoms whose residues XOR to `target`, if any.
fn repair(table: []const Atom, target: u32, enc: Encoding) ?Repair {
    if (std.sort.binarySearch(Atom, table, target, atomOrder)) |i| return .{ .enc = enc, .a = table[i], .b = null };
    for (table) |a| {
        const i = std.sort.binarySearch(Atom, table, target ^ a.key, atomOrder) orelse continue;
        if (table[i].pos > a.pos) return .{ .enc = enc, .a = a, .b = table[i] };
    }
    return null;
}

/// Where the mistyped characters of `s` are, as Bitcoin Core's `bech32.cpp` reports
/// them: the first structural fault with its positions, or, when only the checksum
/// fails, the one or two substituted data-part characters that explain it (the code
/// detects four errors, so such an explanation is unique). `expected` names the
/// checksum constant the string is meant to carry (segwit v0: `.bech32`, v1+:
/// `.bech32m`); null tries both and takes the repair with fewer errors (bech32 on a
/// tie). Never fails and never allocates; the work is one 31-entry table per data
/// character and a binary search per candidate (well under a millisecond).
pub fn locateErrors(s: []const u8, expected: ?Encoding) Located {
    var r: Located = .{ .fault = .none };
    if (s.len > max_len) {
        r.fault = .too_long;
        return r;
    }
    var first_letter: ?bool = null; // true = upper
    for (s, 0..) |c, i| {
        const up = c >= 'A' and c <= 'Z';
        if (!up and !(c >= 'a' and c <= 'z')) continue;
        if (first_letter == null) first_letter = up else if (first_letter.? != up) {
            r.fault = .mixed_case;
            r.pos_buf[0] = @intCast(i);
            r.count = 1;
            return r;
        }
    }
    const sep = std.mem.findScalarLast(u8, s, '1') orelse {
        r.fault = .no_separator;
        return r;
    };
    for (s[0..sep], 0..) |c, i| if (c < 33 or c > 126) {
        r.fault = .invalid_character;
        r.pos_buf[r.count] = @intCast(i);
        r.count += 1;
    };
    if (r.fault != .none) return r;
    if (sep == 0 or sep > max_hrp_len or s.len - sep - 1 < checksum_len) {
        r.fault = .bad_separator;
        r.pos_buf[0] = @intCast(sep);
        r.count = 1;
        return r;
    }
    var hrp_buf: [max_hrp_len]u8 = undefined;
    for (s[0..sep], 0..) |c, i| hrp_buf[i] = toLower(c);
    const hrp = hrp_buf[0..sep];
    const dlen = s.len - sep - 1;
    var vals: [max_len]u5 = undefined;
    for (s[sep + 1 ..], 0..) |c, i| {
        if (charValue(toLower(c))) |v| {
            vals[i] = v;
        } else {
            r.fault = .invalid_data_character;
            r.pos_buf[r.count] = @intCast(sep + 1 + i);
            r.count += 1;
        }
    }
    if (r.fault != .none) return r;

    var buf: [max_combined]u5 = undefined;
    var n = hrpExpandInto(hrp, buf[0..]);
    @memcpy(buf[n..][0..dlen], vals[0..dlen]);
    n += dlen;
    const residue = polymod(buf[0..n]);
    if (residue == 1 or residue == encodingConst(.bech32m)) {
        const enc: Encoding = if (residue == 1) .bech32 else .bech32m;
        r.encoding = enc;
        if (expected != null and expected.? != enc) r.fault = .wrong_variant;
        return r;
    }

    // A substitution of value `v`-delta at data index k changes the residue by
    // step0^(dlen-1-k)(delta): linear, so the residue of a string with two
    // substitutions is the XOR of two table entries.
    var atoms: [max_data_len + checksum_len][31]u32 = undefined; // [k][delta - 1]
    var cur: [31]u32 = undefined;
    for (&cur, 0..) |*c, d| c.* = @intCast(d + 1);
    var k = dlen;
    while (k > 0) {
        k -= 1;
        atoms[k] = cur;
        for (&cur) |*c| c.* = stepZero(c.*);
    }
    var table: [(max_data_len + checksum_len) * 31]Atom = undefined;
    var tn: usize = 0;
    for (0..dlen) |kk| for (0..31) |d| {
        table[tn] = .{ .key = atoms[kk][d], .pos = @intCast(kk), .val = @intCast(d + 1) };
        tn += 1;
    };
    std.mem.sort(Atom, table[0..tn], {}, atomLess);

    var best: ?Repair = null;
    for ([_]Encoding{ .bech32, .bech32m }) |enc| {
        if (expected != null and expected.? != enc) continue;
        const rep = repair(table[0..tn], residue ^ encodingConst(enc), enc) orelse continue;
        if (best == null or rep.size() < best.?.size()) best = rep;
    }
    const found = best orelse {
        r.fault = .bad_checksum_unlocated;
        return r;
    };
    r.fault = .bad_checksum;
    r.encoding = found.enc;
    const items = [2]?Atom{ found.a, found.b };
    for (items) |maybe| {
        const a = maybe orelse continue;
        r.pos_buf[r.count] = @intCast(sep + 1 + a.pos);
        r.fix_buf[r.count] = charset[@as(u5, @intCast(vals[a.pos] ^ a.val))];
        r.count += 1;
    }
    return r;
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
    try testing.expect(std.mem.findAny(u8, enc.slice(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == null);
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

test "decode: HRP longer than 83 is HrpTooLong, ahead of DataTooShort (A1 L2)" {
    // No official BIP173/BIP350 vector exercises this: every published
    // invalid vector with an over-length HRP also has a data part short
    // enough to hit DataTooShort first, so this branch (and its ordering
    // ahead of DataTooShort) can be dropped or reordered without moving the
    // corpus. 84 'a's + an empty data part isolates it: HrpTooLong is the
    // only guard that can fire.
    var s: [max_hrp_len + 2]u8 = undefined; // 84 'a's + '1'
    @memset(s[0 .. max_hrp_len + 1], 'a');
    s[max_hrp_len + 1] = '1';
    try testing.expectError(error.HrpTooLong, decode(&s));
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

test "encode: EmptyHrp rejected (A1 M5)" {
    try testing.expectError(error.EmptyHrp, encode("", &.{}, .bech32));
}

test "encode: HrpTooLong rejected, pinned to hrp.len > 83 rather than the overall length limit (A1 M5)" {
    // A weakened `hrp.len > max_hrp_len` check (or its removal) can hide
    // behind `TooLong` for most data lengths -- an empty data part isolates
    // this specific guard, since HrpTooLong is the only one that can fire.
    var hrp_buf: [max_hrp_len + 1]u8 = undefined;
    @memset(&hrp_buf, 'a');
    try testing.expectError(error.HrpTooLong, encode(&hrp_buf, &.{}, .bech32));
}

test "encode: HrpCharOutOfRange rejected for a byte outside [33,126] (A1 M5)" {
    try testing.expectError(error.HrpCharOutOfRange, encode(&[_]u8{0x20}, &.{}, .bech32));
    try testing.expectError(error.HrpCharOutOfRange, encode(&[_]u8{0x7f}, &.{}, .bech32));
}

test "encode: TooLong is pinned to exactly max_len (90), not a looser bound (A1 M5)" {
    // The test above builds a 172-character total, which stays TooLong under
    // `> 91` or `> 200` alike -- it never exercises the real boundary. 91 is
    // the smallest total that must fail; 90 is the largest that must succeed.
    var data_buf: [max_data_len + 1]u5 = undefined; // 83
    @memset(&data_buf, 0);
    try testing.expectError(error.TooLong, encode("a", data_buf[0..83], .bech32)); // 1+1+83+6 = 91
    _ = try encode("a", data_buf[0..82], .bech32); // 1+1+82+6 = 90, must succeed
}

// ── fuzz: bech32/bech32m string decode, never panics ────────────────────────
//
// `decode` is what runs on an address/invoice a user pastes in, or scans
// from a QR code — attacker/user-controlled text with no structural
// guarantee until the checksum is verified. Bias toward the bech32 charset
// plus the '1' separator so the fuzzer gets past the length gate into the
// charset/checksum math this file's own doc calls out as the real target.

/// A corpus entry in the format `Smith.slice` actually reads — a little-endian
/// `u32` length, then the string — followed by one `u64` word per octet the
/// charset knob in `fuzzDecode` reads afterwards (`1` bends that octet into
/// the charset, `0` leaves it alone; once the words run out every remaining
/// draw is the weight minimum, i.e. `false`).
///
/// ⛔ Two defects were measured here on 2026-09-08, and both were silent.
/// (1) The corpus was a list of BARE string literals. `Smith.slice` reads a
/// little-endian `u32` length before the bytes, so `"a12uel5l"` reached
/// `decode` as `"el5l"` — every seed arrived minus its own first four octets,
/// which for a bech32 string removes the human-readable part and the `1`
/// separator. **Not one of the three published BIP-173 vectors in this corpus
/// was ever decoded**: 0 of 3 accepted, and the checksum arithmetic the
/// harness exists to reach was never entered.
/// (2) With the seed consumed by the byte draw, `boolWeighted(1, 3)` returned
/// its weight minimum: the loop ran 146 times over the corpus and bent **0**
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
    bendSeed("a12uel5l", &.{}), // BIP-173: the shortest valid bech32 string
    bendSeed("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", &.{}),
    bendSeed("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", &.{}),
    bendSeed("Ab1qqqqqqq", &.{}), // MixedCase
    bendSeed("li1dgmt3", &.{}), // DataTooShort
    bendSeed("x1b4n0q5v", &.{}), // InvalidDataChar
    // The charset knob, one word per octet: sixteen octets that are NOT in
    // the charset, every one of them bent into it — the input a tail-less
    // seed cannot produce, and the only one that reaches the loop body.
    bendSeed(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &(@as([16]u64, @splat(1)))),
    bendSeed("", &.{}), // and the input a corpus-less target runs for ever
};

const fz = @import("fuzz_test.zig");
const DecodeMark = fz.Marker(enum { accepted, refused });

test "fuzz: decode never panics on arbitrary text" {
    try testing.fuzz({}, fuzzDecodeSmith, .{ .corpus = &decode_seeds });
}

test "fuzz driver: BECH32_FUZZ (bech32 decode)" {
    try fz.fuzz_driver.run(fuzzDecode, .{ .prefix = "BECH32_FUZZ", .name = "bech32-decode" });
}

test "fuzz harness: bech32 decode, 600 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "bech32-decode", 600);
}

fn fuzzDecodeSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDecode(std.testing.Smith, smith, testing.allocator);
}

const fuzz_alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l1"; // charset + separator

fn fuzzDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [128]u8 = undefined;
    const len = fz.drawInput(S, src, &buf, &decode_seeds); // not `bytes` + a ranged length: that always yields 0
    const bend = fz.bendInput(S, src);
    for (buf[0..len]) |*c| {
        if (bend and fz.weighted(src, 1, 3)) c.* = fuzz_alphabet[c.* % fuzz_alphabet.len];
    }
    _ = decode(buf[0..len]) catch {
        DecodeMark.mark(.refused);
        return;
    };
    DecodeMark.mark(.accepted);
}

test "corpus: every bech32 seed reaches decode, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // ⛔ Not `accepted > 0`. `data_symbols` is the number the collapsed corpus
    // could not move: it only grows when a seed's own octets survive the draw
    // AND clear the checksum, so it notices a seed being shortened as well as
    // dropped. `bent` is the number a tail-less corpus cannot move.
    var nonempty: usize = 0;
    var bent: usize = 0;
    var accepted: usize = 0;
    var data_symbols: usize = 0;
    var hrp_octets: usize = 0;
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
        if (decode(buf[0..len])) |d| {
            accepted += 1;
            data_symbols += d.data().len;
            hrp_octets += d.hrp().len;
        } else |_| {}
    }
    try testing.expectEqual(decode_seeds.len - 1, nonempty); // all but the empty string
    // Measured 2026-09-08. Before: every seed arrived four octets short of the
    // string it was written as — 0 accepted, 0 data symbols, 0 bent. After:
    try testing.expectEqual(@as(usize, 16), bent);
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 48), data_symbols);
    try testing.expectEqual(@as(usize, 89), hrp_octets);
}

// ── locateErrors ─────────────────────────────────────────────────────────

fn randomValid(r: std.Random, buf: *[max_len]u8, enc: Encoding) []const u8 {
    const hrps = [_][]const u8{ "bc", "tb", "a", "bcrt", "lnbc", "split" };
    const hrp = hrps[r.uintLessThan(usize, hrps.len)];
    var data: [max_data_len]u5 = undefined;
    const room = max_len - hrp.len - 1 - checksum_len;
    const n = r.uintLessThan(usize, @min(room, max_data_len) + 1);
    for (data[0..n]) |*d| d.* = r.int(u5);
    const e = encode(hrp, data[0..n], enc) catch unreachable;
    @memcpy(buf[0..e.len], e.slice());
    return buf[0..e.len];
}

test "locateErrors: valid strings are none, and name their encoding" {
    const l = locateErrors("A12UEL5L", null);
    try testing.expectEqual(Fault.none, l.fault);
    try testing.expectEqual(@as(?Encoding, .bech32), l.encoding);
    const m = locateErrors("a1lqfn3a", null);
    try testing.expectEqual(Fault.none, m.fault);
    try testing.expectEqual(@as(?Encoding, .bech32m), m.encoding);
    // valid, but for the other constant than the caller expects
    const w = locateErrors("a1lqfn3a", .bech32);
    try testing.expectEqual(Fault.wrong_variant, w.fault);
    try testing.expectEqual(@as(?Encoding, .bech32m), w.encoding);
    try testing.expectEqual(Fault.none, locateErrors("a1lqfn3a", .bech32m).fault);
}

test "locateErrors: structural faults carry their positions" {
    try testing.expectEqual(Fault.too_long, locateErrors("bc1" ++ @as([90]u8, @splat('q')), null).fault);
    const mixed = locateErrors("bc1qpzRy9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", null);
    try testing.expectEqual(Fault.mixed_case, mixed.fault);
    try testing.expectEqualSlices(u8, &.{6}, mixed.positions());
    try testing.expectEqual(Fault.no_separator, locateErrors("pzry9x0s0muk", null).fault);
    const empty_hrp = locateErrors("1pzry9x0s0muk", null);
    try testing.expectEqual(Fault.bad_separator, empty_hrp.fault);
    try testing.expectEqualSlices(u8, &.{0}, empty_hrp.positions());
    try testing.expectEqual(Fault.bad_separator, locateErrors("li1dgmt3", null).fault); // 5 data characters
    const hrp_bad = locateErrors("x\x7fy1pzry9x0s0muk", null);
    try testing.expectEqual(Fault.invalid_character, hrp_bad.fault);
    try testing.expectEqualSlices(u8, &.{1}, hrp_bad.positions());
    const data_bad = locateErrors("de1lg7wt\xff", null);
    try testing.expectEqual(Fault.invalid_data_character, data_bad.fault);
    try testing.expectEqualSlices(u8, &.{8}, data_bad.positions());
    const two_bad = locateErrors("bc1qbpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", null);
    try testing.expectEqual(Fault.invalid_data_character, two_bad.fault);
    try testing.expectEqualSlices(u8, &.{4}, two_bad.positions());
}

test "locateErrors: one or two substituted characters are found, with their fixes, against a brute force" {
    var prng = std.Random.DefaultPrng.init(0x6c6f6361);
    const r = prng.random();
    var buf: [max_len]u8 = undefined;
    var located: usize = 0;
    for (0..400) |_| {
        const enc: Encoding = if (r.boolean()) .bech32 else .bech32m;
        const good = randomValid(r, &buf, enc);
        const sep = std.mem.findScalarLast(u8, good, '1').?;
        var bad: [max_len]u8 = undefined;
        @memcpy(bad[0..good.len], good);
        const want_n = 1 + r.uintLessThan(usize, 2);
        var at: [2]usize = undefined;
        for (0..want_n) |i| {
            while (true) {
                const p = sep + 1 + r.uintLessThan(usize, good.len - sep - 1);
                if (i == 1 and p == at[0]) continue;
                at[i] = p;
                break;
            }
            const orig = bad[at[i]];
            while (bad[at[i]] == orig) bad[at[i]] = charset[r.uintLessThan(usize, 32)];
        }
        const l = locateErrors(bad[0..good.len], enc);
        try testing.expectEqual(Fault.bad_checksum, l.fault);
        try testing.expectEqual(want_n, l.count);
        // the repaired string is the original, at the located positions
        var fixed: [max_len]u8 = bad;
        for (l.positions(), l.fixes()) |p, f| fixed[p] = f;
        try testing.expectEqualStrings(good, fixed[0..good.len]);
        _ = try decode(fixed[0..good.len]);
        located += 1;
        if (good.len - sep > 14 or located > 40) continue; // the brute force is quadratic in the data length
        // brute force: no other one- or two-character repair exists
        var found: usize = 0;
        for (sep + 1..good.len) |p| for (charset) |c1| {
            var t = bad;
            if (c1 == t[p]) continue;
            t[p] = c1;
            if (decode(t[0..good.len])) |d| {
                if (d.encoding == enc) found += 1;
            } else |_| {}
            for (p + 1..good.len) |q| for (charset) |c2| {
                if (c2 == t[q]) continue;
                var u = t;
                u[q] = c2;
                if (decode(u[0..good.len])) |d| {
                    if (d.encoding == enc) found += 1;
                } else |_| {}
            };
        };
        try testing.expectEqual(@as(usize, 1), found);
    }
}

test "locateErrors: three errors, a bad HRP and a missing character never crash and are not a repair of the original" {
    var prng = std.Random.DefaultPrng.init(0x7468726565);
    const r = prng.random();
    var buf: [max_len]u8 = undefined;
    for (0..300) |_| {
        const good = randomValid(r, &buf, .bech32);
        var bad: [max_len]u8 = undefined;
        @memcpy(bad[0..good.len], good);
        const sep = std.mem.findScalarLast(u8, good, '1').?;
        var len = good.len;
        switch (r.uintLessThan(usize, 3)) {
            0 => for (0..3) |_| {
                const p = sep + 1 + r.uintLessThan(usize, good.len - sep - 1);
                bad[p] = if (bad[p] == 'q') 'p' else 'q';
            },
            1 => bad[0] = if (bad[0] == 'z') 'y' else 'z',
            else => {
                std.mem.copyForwards(u8, bad[sep + 1 ..], bad[sep + 2 .. len]);
                len -= 1;
            },
        }
        const l = locateErrors(bad[0..len], .bech32);
        try testing.expect(l.fault != .none);
        if (l.fault == .bad_checksum) { // a miscorrection is allowed, but it must be a genuine repair
            var fixed: [max_len]u8 = bad;
            for (l.positions(), l.fixes()) |p, f| fixed[p] = f;
            _ = try decode(fixed[0..len]);
        }
    }
}
