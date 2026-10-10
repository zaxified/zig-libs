// SPDX-License-Identifier: MIT
//! base32 — RFC 4648 Base32 (§6) and Base32 with Extended Hex Alphabet (§7).
//!
//! The encoding behind every TOTP/HOTP shared secret (`otpauth://` URIs and
//! authenticator apps), DNSSEC NSEC3 owner names (base32hex) and many
//! human-typed keys. Zig `std` has no base32.
//!
//! Decoding is **strict by default**: bytes outside the alphabet, a wrong
//! padding count, an impossible symbol count and non-zero trailing bits
//! (non-canonical encodings, which would let two different texts decode to
//! the same bytes) each fail with a distinct typed error. Leniency is opt-in
//! through `DecodeOptions`: optional/forbidden padding, case-insensitive
//! input and whitespace skipping (authenticator secrets are often typed in
//! lowercase, unpadded and grouped by spaces).
//!
//! No allocation in the core (`encode`/`decode` write into a caller buffer);
//! `encodeAlloc`/`decodeAlloc` are thin owning wrappers.
//!
//! **Not constant-time**: decoding uses a 256-entry lookup table and branches
//! on the input, so timing and cache behaviour depend on the text. See
//! SPEC.md "Constant-time contract".
//!
//! Provenance: clean-room from RFC 4648 (public IETF specification); vectors
//! are the RFC's §10 table plus values captured from Python's stdlib as a
//! black-box oracle. See `README.md`.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Base32 codec (RFC 4648 §6 + base32hex §7) — strict by default (canonical trailing bits, exact padding), opt-in lenient decode (optional padding, lowercase, whitespace); the encoding of TOTP secrets.",
    // The catalog's Platform cell. Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure computation over caller buffers
    .role = .codec,
    .concurrency = .reentrant, // all functions are pure
    .model_after = "RFC 4648 §6/§7; Python stdlib base64.b32encode/b32decode/b32hexencode",
    .deps = .{},
};

/// Which 32-symbol alphabet.
pub const Alphabet = enum {
    /// RFC 4648 §6: `A-Z` then `2-7`.
    std,
    /// RFC 4648 §7 ("base32hex"): `0-9` then `A-V`. Preserves sort order.
    hex,

    fn symbols(a: Alphabet) *const [32]u8 {
        return switch (a) {
            .std => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            .hex => "0123456789ABCDEFGHIJKLMNOPQRSTUV",
        };
    }
};

/// How `=` padding is treated on decode.
pub const Padding = enum {
    /// RFC 4648 canonical form: the text must be padded to a multiple of 8.
    required,
    /// Either the exact canonical padding or none at all (what
    /// `otpauth://` secrets use). Partial padding is still an error.
    optional,
    /// Any `=` is an error.
    forbidden,
};

/// Letter case accepted on decode. RFC 4648 defines upper case only.
pub const Case = enum {
    upper_only,
    /// Lower-case letters are folded to upper case. Digits are unaffected.
    insensitive,
};

pub const DecodeOptions = struct {
    alphabet: Alphabet = .std,
    padding: Padding = .required,
    case: Case = .upper_only,
    /// Skip ASCII space, `\t`, `\r` and `\n` anywhere in the text (including
    /// between padding characters). Off by default: RFC 4648 §3.3 says
    /// non-alphabet characters must be rejected unless the specification
    /// says otherwise.
    skip_whitespace: bool = false,
};

pub const EncodeOptions = struct {
    alphabet: Alphabet = .std,
    /// Append `=` up to a multiple of 8 characters.
    pad: bool = true,
    /// Emit lower-case letters (the digit symbols are unchanged).
    lowercase: bool = false,
};

pub const EncodeError = error{
    /// `dest` is shorter than `encodedLen`.
    BufferTooSmall,
};

pub const DecodeError = error{
    /// A byte that is not in the alphabet (or not allowed by `case` /
    /// `skip_whitespace`).
    InvalidCharacter,
    /// Padding present when forbidden, missing when required, of the wrong
    /// count, or followed by more data.
    InvalidPadding,
    /// The number of data symbols is impossible (1, 3 or 6 modulo 8): no
    /// byte string encodes to it.
    InvalidLength,
    /// The unused low bits of the last symbol are not zero. Such a text is
    /// not what any encoder produces; accepting it would make decoding
    /// non-injective.
    NonCanonical,
    /// `dest` cannot hold the decoded bytes.
    BufferTooSmall,
};

/// Length of the encoding of `n` bytes.
pub fn encodedLen(n: usize, pad: bool) usize {
    if (pad) return (n + 4) / 5 * 8;
    return (n * 8 + 4) / 5;
}

/// An upper bound on the decoded size of a text of `text_len` bytes (padding
/// and skipped whitespace only make the real size smaller). Size `dest` of
/// `decode` with this.
pub fn decodedLenUpperBound(text_len: usize) usize {
    return text_len / 8 * 5 + (text_len % 8) * 5 / 8;
}

/// Encode `src` into the front of `dest`; returns the written slice.
pub fn encode(dest: []u8, src: []const u8, opts: EncodeOptions) EncodeError![]u8 {
    const n = encodedLen(src.len, opts.pad);
    if (dest.len < n) return error.BufferTooSmall;
    var o: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        const take: usize = @min(5, src.len - i);
        var block: [5]u8 = @splat(0);
        @memcpy(block[0..take], src[i..][0..take]);
        var v: u64 = 0;
        for (block) |b| v = (v << 8) | b;
        const nsym = (take * 8 + 4) / 5; // 2, 4, 5, 7 or 8 symbols carry data
        var k: usize = 0;
        while (k < nsym) : (k += 1) {
            const shift: u6 = @intCast(35 - 5 * k);
            dest[o] = symbolChar(opts.alphabet, opts.lowercase, @intCast((v >> shift) & 31));
            o += 1;
        }
        i += take;
    }
    if (opts.pad) {
        while (o % 8 != 0) : (o += 1) dest[o] = '=';
    }
    std.debug.assert(o == n);
    return dest[0..o];
}

/// Owning variant of `encode`; the caller frees the result.
pub fn encodeAlloc(allocator: std.mem.Allocator, src: []const u8, opts: EncodeOptions) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, encodedLen(src.len, opts.pad));
    // `out` is sized by encodedLen, so encode cannot report BufferTooSmall.
    return encode(out, src, opts) catch unreachable;
}

// ── constant-time symbol mapping ─────────────────────────────────────────────
//
// The octets being encoded or decoded are, for a TOTP secret (`otp`'s
// otpauth.format / uri parse), the secret itself. Indexing an alphabet or a
// 256-entry table by them is a secret-dependent memory address, and a branch
// on a character's class is a secret-dependent branch. Here every symbol is
// computed arithmetically: each range decision is a borrow turned into a mask,
// never a branch or an index (the technique of `sessions/src/idhex.zig`). What
// still branches is public: the options, the lengths, and whether a character
// IS padding or skippable whitespace.

/// 0xFF when `x < n`, else 0 -- a borrow, not a comparison branch.
inline fn below(x: u8, n: u8) u8 {
    return @truncate((@as(u16, x) -% n) >> 8);
}

/// The symbol for a 5-bit value `v` (0..31).
fn symbolChar(alphabet: Alphabet, lowercase: bool, v: u8) u8 {
    switch (alphabet) {
        .std => {
            const letter = below(v, 26); // 'A'..'Z' for 0..25, '2'..'7' for 26..31
            const c = v +% 24 +% (letter & 41);
            return c | (letter & if (lowercase) @as(u8, 0x20) else 0);
        },
        .hex => {
            const digit = below(v, 10); // '0'..'9' for 0..9, 'A'..'V' for 10..31
            const c = v +% '0' +% (~digit & ('A' - '0' - 10));
            return c | (~digit & if (lowercase) @as(u8, 0x20) else 0);
        },
    }
}

/// A symbol's 5-bit value and a 0xFF/0 validity mask (value 0 when invalid).
fn symbolValue(alphabet: Alphabet, case: Case, c: u8) struct { u8, u8 } {
    const fold: u8 = if (case == .insensitive) 0xFF else 0;
    const up = c -% 'A';
    const lo = c -% 'a';
    switch (alphabet) {
        .std => {
            const is_up = below(up, 26);
            const is_lo = below(lo, 26) & fold;
            const dg = c -% '2';
            const is_dg = below(dg, 6);
            const v = (up & is_up) | (lo & is_lo) | ((dg +% 26) & is_dg);
            return .{ v, is_up | is_lo | is_dg };
        },
        .hex => {
            const dg = c -% '0';
            const is_dg = below(dg, 10);
            const is_up = below(up, 22);
            const is_lo = below(lo, 22) & fold;
            const v = (dg & is_dg) | ((up +% 10) & is_up) | ((lo +% 10) & is_lo);
            return .{ v, is_dg | is_up | is_lo };
        },
    }
}

/// `a` where `m` is 0xFF, else `b`.
inline fn pick(m: u8, a: usize, b: usize) usize {
    const w: usize = @as(usize, m & 1) *% std.math.maxInt(usize);
    return (a & w) | (b & ~w);
}

fn isSkippable(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Decode `text` into the front of `dest`; returns the number of bytes
/// written. `dest.len >= decodedLenUpperBound(text.len)` always suffices;
/// a shorter buffer works when the real output fits. On error the contents
/// of `dest` are unspecified.
///
/// Error precedence for a text with several faults: a bad character or
/// misplaced padding is reported where it is met, left to right; then
/// `InvalidLength`, `InvalidPadding` (count), `NonCanonical`.
pub fn decode(dest: []u8, text: []const u8, opts: DecodeOptions) DecodeError!usize {
    var acc: u32 = 0; // holds `nbits` (< 8) pending bits between symbols
    var nbits: u5 = 0;
    var nsym: usize = 0;
    var npad: usize = 0;
    var out: usize = 0;
    // The validity of every character is accumulated as a mask and reported
    // once, after the loop, with the position of the first invalid one (picked
    // arithmetically). The faults that depend only on public things -- padding
    // where forbidden, data after padding, a full buffer -- are recorded with
    // their position, and the earliest fault wins, which is the left-to-right
    // precedence the loop used to get by returning where it met each.
    var bad: u8 = 0;
    var bad_pos: usize = 0;
    var early: ?struct { pos: usize, err: DecodeError } = null;
    for (text, 0..) |c, i| {
        if (opts.skip_whitespace and isSkippable(c)) continue;
        if (c == '=') {
            if (opts.padding == .forbidden) {
                early = .{ .pos = i, .err = error.InvalidPadding };
                break;
            }
            npad += 1;
            continue;
        }
        const sv = symbolValue(opts.alphabet, opts.case, c);
        bad_pos = pick(~sv[1] & ~bad, i, bad_pos);
        bad |= ~sv[1];
        if (npad != 0) { // data after padding
            early = .{ .pos = i, .err = error.InvalidPadding };
            break;
        }
        nsym += 1;
        acc = (acc << 5) | sv[0];
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (out >= dest.len) {
                early = .{ .pos = i, .err = error.BufferTooSmall };
                break;
            }
            dest[out] = @truncate(acc >> nbits);
            out += 1;
            acc &= (@as(u32, 1) << nbits) - 1;
        }
    }
    if (bad != 0) {
        if (early) |e| if (e.pos < bad_pos) return e.err;
        return error.InvalidCharacter;
    }
    if (early) |e| return e.err;
    const rem = nsym % 8;
    switch (rem) {
        0, 2, 4, 5, 7 => {},
        else => return error.InvalidLength,
    }
    const want_pad: usize = (8 - rem) % 8;
    switch (opts.padding) {
        .required => if (npad != want_pad) return error.InvalidPadding,
        .optional => if (npad != 0 and npad != want_pad) return error.InvalidPadding,
        .forbidden => {},
    }
    if (acc != 0) return error.NonCanonical;
    return out;
}

/// Owning variant of `decode`; the caller frees the result.
pub fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8, opts: DecodeOptions) (DecodeError || std.mem.Allocator.Error)![]u8 {
    const buf = try allocator.alloc(u8, decodedLenUpperBound(text.len));
    defer allocator.free(buf);
    const n = try decode(buf, text, opts);
    return allocator.dupe(u8, buf[0..n]);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const Rfc = struct { raw: []const u8, std: []const u8, hex: []const u8 };

// RFC 4648 §10 test vectors, both alphabets.
const rfc_vectors = [_]Rfc{
    .{ .raw = "", .std = "", .hex = "" },
    .{ .raw = "f", .std = "MY======", .hex = "CO======" },
    .{ .raw = "fo", .std = "MZXQ====", .hex = "CPNG====" },
    .{ .raw = "foo", .std = "MZXW6===", .hex = "CPNMU===" },
    .{ .raw = "foob", .std = "MZXW6YQ=", .hex = "CPNMUOG=" },
    .{ .raw = "fooba", .std = "MZXW6YTB", .hex = "CPNMUOJ1" },
    .{ .raw = "foobar", .std = "MZXW6YTBOI======", .hex = "CPNMUOJ1E8======" },
};

test "RFC 4648 section 10 vectors: encode and strict decode, both alphabets" {
    var buf: [32]u8 = undefined;
    for (rfc_vectors) |v| {
        try testing.expectEqualStrings(v.std, try encode(&buf, v.raw, .{}));
        try testing.expectEqualStrings(v.hex, try encode(&buf, v.raw, .{ .alphabet = .hex }));
        var out: [16]u8 = undefined;
        const n = try decode(&out, v.std, .{});
        try testing.expectEqualStrings(v.raw, out[0..n]);
        const m = try decode(&out, v.hex, .{ .alphabet = .hex });
        try testing.expectEqualStrings(v.raw, out[0..m]);
    }
}

test "unpadded and lower-case encoding" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("MZXW6YQ", try encode(&buf, "foob", .{ .pad = false }));
    try testing.expectEqualStrings("mzxw6yq", try encode(&buf, "foob", .{ .pad = false, .lowercase = true }));
    // Digits keep their value under lowercase.
    try testing.expectEqualStrings("cpnmuoj1", try encode(&buf, "fooba", .{ .alphabet = .hex, .lowercase = true }));
}

test "lengths: encodedLen and decodedLenUpperBound" {
    var n: usize = 0;
    while (n < 64) : (n += 1) {
        const padded = encodedLen(n, true);
        const bare = encodedLen(n, false);
        try testing.expect(padded % 8 == 0);
        try testing.expect(bare <= padded and padded - bare < 8);
        try testing.expect(decodedLenUpperBound(padded) >= n);
        try testing.expect(decodedLenUpperBound(bare) >= n);
        // Tight: no more than the true size for exact-8 texts.
        try testing.expectEqual(n, decodedLenUpperBound(bare));
    }
}

test "encode: BufferTooSmall" {
    var small: [7]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encode(&small, "f", .{}));
    var ok: [2]u8 = undefined;
    try testing.expectEqualStrings("MY", try encode(&ok, "f", .{ .pad = false }));
}

test "decode: rejects non-alphabet bytes" {
    var out: [16]u8 = undefined;
    // '1', '0', '8', '9' are not in the std alphabet; '-', '_' neither.
    for ([_][]const u8{ "MY1=====", "MY0=====", "MY8=====", "MY9=====", "M-======", "M_======", "MY\x00=====", "MY\xc3\xa9===" }) |t| {
        try testing.expectError(error.InvalidCharacter, decode(&out, t, .{}));
    }
    // hex alphabet rejects W-Z.
    try testing.expectError(error.InvalidCharacter, decode(&out, "CW======", .{ .alphabet = .hex }));
    // Lower case is rejected unless asked for.
    try testing.expectError(error.InvalidCharacter, decode(&out, "my======", .{}));
    // Whitespace is rejected unless asked for.
    try testing.expectError(error.InvalidCharacter, decode(&out, "MZXW 6===", .{}));
    try testing.expectError(error.InvalidCharacter, decode(&out, "MZXW6===\n", .{}));
}

test "decode: padding classes" {
    var out: [16]u8 = undefined;
    // required: missing, short, long
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6", .{}));
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6==", .{}));
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6====", .{}));
    // padding on a full block, padding-only text
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6YTB=", .{}));
    try testing.expectError(error.InvalidPadding, decode(&out, "========", .{}));
    // data after padding
    try testing.expectError(error.InvalidPadding, decode(&out, "MY==A===", .{}));
    try testing.expectError(error.InvalidPadding, decode(&out, "MY======MY======", .{}));
    // forbidden
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6===", .{ .padding = .forbidden }));
    try testing.expectEqual(@as(usize, 3), try decode(&out, "MZXW6", .{ .padding = .forbidden }));
    // optional: none or exact, never partial
    try testing.expectEqual(@as(usize, 3), try decode(&out, "MZXW6", .{ .padding = .optional }));
    try testing.expectEqual(@as(usize, 3), try decode(&out, "MZXW6===", .{ .padding = .optional }));
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6==", .{ .padding = .optional }));
    try testing.expectError(error.InvalidPadding, decode(&out, "MZXW6YTB=", .{ .padding = .optional }));
}

test "decode: impossible symbol counts" {
    var out: [16]u8 = undefined;
    // 1, 3 and 6 symbols (mod 8) cannot be produced by any encoder.
    for ([_][]const u8{ "M", "MZX", "MZXW6Y", "MZXW6YTBM", "MZXW6YTBMZX", "MZXW6YTBMZXW6Y" }) |t| {
        try testing.expectError(error.InvalidLength, decode(&out, t, .{ .padding = .optional }));
    }
}

test "decode: non-canonical trailing bits" {
    var out: [16]u8 = undefined;
    // "MY" = 'f' with 2 spare bits zero; "MZ" sets one of them.
    try testing.expectEqual(@as(usize, 1), try decode(&out, "MY======", .{}));
    try testing.expectError(error.NonCanonical, decode(&out, "MZ======", .{}));
    try testing.expectError(error.NonCanonical, decode(&out, "M7======", .{}));
    // 4 symbols: 4 spare bits; "MZXR" vs canonical "MZXQ".
    try testing.expectError(error.NonCanonical, decode(&out, "MZXR====", .{}));
    // 5 symbols: 1 spare bit; canonical ends in 6 or Q-class, "MZXW7" is off.
    try testing.expectError(error.NonCanonical, decode(&out, "MZXW7===", .{}));
    // 7 symbols: 3 spare bits.
    try testing.expectError(error.NonCanonical, decode(&out, "MZXW6YR=", .{}));
    // Same for hex.
    try testing.expectError(error.NonCanonical, decode(&out, "CP======", .{ .alphabet = .hex }));
}

test "decode: opt-in leniency (typical authenticator secret text)" {
    var out: [16]u8 = undefined;
    const lenient: DecodeOptions = .{ .padding = .optional, .case = .insensitive, .skip_whitespace = true };
    const n = try decode(&out, "jbsw y3dp ehpk 3pxp\n", lenient);
    try testing.expectEqualSlices(u8, "Hello!\xde\xad\xbe\xef", out[0..n]);
    // whitespace may also sit inside the padding
    try testing.expectEqual(@as(usize, 3), try decode(&out, "MZXW6 = = =", lenient));
    // leniency does not weaken the canonical-bits rule
    try testing.expectError(error.NonCanonical, decode(&out, "mz", lenient));
    // insensitive on hex: digits unaffected, letters folded
    try testing.expectEqual(@as(usize, 6), try decode(&out, "cpnmuoj1e8", .{ .alphabet = .hex, .case = .insensitive, .padding = .optional }));
}

test "decode: BufferTooSmall, and an exact-size buffer works" {
    var out: [2]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, decode(&out, "MZXW6===", .{}));
    var exact: [3]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), try decode(&exact, "MZXW6===", .{}));
    try testing.expectEqualStrings("foo", &exact);
}

test "alloc variants" {
    const a = testing.allocator;
    const enc = try encodeAlloc(a, "foobar", .{});
    defer a.free(enc);
    try testing.expectEqualStrings("MZXW6YTBOI======", enc);
    const dec = try decodeAlloc(a, enc, .{});
    defer a.free(dec);
    try testing.expectEqualStrings("foobar", dec);
    try testing.expectError(error.NonCanonical, decodeAlloc(a, "MZ======", .{}));
}

test "round trip: random lengths 0..300, every option combination" {
    var prng = std.Random.DefaultPrng.init(0x62617365_33322121);
    const rnd = prng.random();
    var raw: [300]u8 = undefined;
    var enc_buf: [encodedLen(300, true)]u8 = undefined;
    var dec_buf: [300]u8 = undefined;
    var len: usize = 0;
    while (len <= 300) : (len += 1) {
        rnd.bytes(raw[0..len]);
        for ([_]Alphabet{ .std, .hex }) |alphabet| for ([_]bool{ true, false }) |pad| for ([_]bool{ false, true }) |lower| {
            const text = try encode(&enc_buf, raw[0..len], .{ .alphabet = alphabet, .pad = pad, .lowercase = lower });
            try testing.expectEqual(encodedLen(len, pad), text.len);
            const n = try decode(&dec_buf, text, .{
                .alphabet = alphabet,
                .padding = if (pad) .required else .forbidden,
                .case = if (lower) .insensitive else .upper_only,
            });
            try testing.expectEqualSlices(u8, raw[0..len], dec_buf[0..n]);
            // optional accepts both forms
            const m = try decode(&dec_buf, text, .{ .alphabet = alphabet, .padding = .optional, .case = .insensitive });
            try testing.expectEqualSlices(u8, raw[0..len], dec_buf[0..m]);
        };
    }
}

test "injective: flipping any spare bit of a canonical text is rejected" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var raw: [40]u8 = undefined;
    var buf: [64]u8 = undefined;
    var out: [40]u8 = undefined;
    for (0..200) |_| {
        const len = rnd.intRangeAtMost(usize, 1, 40);
        rnd.bytes(raw[0..len]);
        const text = try encode(&buf, raw[0..len], .{ .pad = false });
        const spare = (5 - (len * 8) % 5) % 5;
        if (spare == 0) continue;
        // Flip the lowest spare bit in the final symbol.
        const last = &text[text.len - 1];
        const v = std.mem.indexOfScalar(u8, Alphabet.std.symbols(), last.*).?;
        last.* = Alphabet.std.symbols()[v ^ 1];
        try testing.expectError(error.NonCanonical, decode(&out, text, .{ .padding = .forbidden }));
    }
}

test "lower-case encoding folds every letter, including A, and no digit" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("aaaa====", try encode(&buf, "\x00\x00", .{ .lowercase = true }));
    try testing.expectEqualStrings("a0======", try encode(&buf, "\x50", .{ .alphabet = .hex, .lowercase = true }));
    try testing.expectEqualStrings("7777777777777777", try encode(&buf, "\xff" ** 10, .{ .lowercase = true }));
}

test "skip_whitespace skips exactly space, tab, CR and LF" {
    var out: [16]u8 = undefined;
    const opts: DecodeOptions = .{ .skip_whitespace = true };
    // each of the four, alone, between symbols and inside the padding
    for ([_]u8{ ' ', '\t', '\r', '\n' }) |ws| {
        const text = "MZXW6===".*;
        for (0..text.len + 1) |at| {
            var spaced: [9]u8 = undefined;
            @memcpy(spaced[0..at], text[0..at]);
            spaced[at] = ws;
            @memcpy(spaced[at + 1 ..], text[at..]);
            try testing.expectEqual(@as(usize, 3), try decode(&out, &spaced, opts));
        }
    }
    // other control bytes (VT, FF, NUL, NBSP lead byte) stay invalid
    for ([_]u8{ 0x0b, 0x0c, 0x00, 0xa0, 0x1f }) |bad| {
        const text = [_]u8{ 'M', 'Z', 'X', 'W', bad, '6', '=', '=', '=' };
        try testing.expectError(error.InvalidCharacter, decode(&out, &text, opts));
    }
}

test "decodeAlloc sizes its buffer for unpadded text of every length" {
    var prng = std.Random.DefaultPrng.init(0x32);
    var raw: [64]u8 = undefined;
    var enc: [encodedLen(64, false)]u8 = undefined;
    for (0..raw.len + 1) |len| {
        prng.random().bytes(raw[0..len]);
        const text = try encode(&enc, raw[0..len], .{ .pad = false });
        const dec = try decodeAlloc(testing.allocator, text, .{ .padding = .forbidden });
        defer testing.allocator.free(dec);
        try testing.expectEqualSlices(u8, raw[0..len], dec);
    }
}

const kat = @import("kat_vectors.zig");

test "KAT: Python stdlib vectors (padded, unpadded, lowercase)" {
    var raw: [256]u8 = undefined;
    var enc: [encodedLen(256, true)]u8 = undefined;
    var dec: [256]u8 = undefined;
    for (kat.vectors) |v| {
        const n = try std.fmt.hexToBytes(&raw, v.raw_hex);
        try testing.expectEqualStrings(v.std, try encode(&enc, n, .{}));
        try testing.expectEqualStrings(v.hex, try encode(&enc, n, .{ .alphabet = .hex }));
        const d1 = try decode(&dec, v.std, .{});
        try testing.expectEqualSlices(u8, n, dec[0..d1]);
        const d2 = try decode(&dec, v.hex, .{ .alphabet = .hex });
        try testing.expectEqualSlices(u8, n, dec[0..d2]);
        // Unpadded form is Python's output with '=' stripped.
        const bare = std.mem.trimEnd(u8, v.std, "=");
        try testing.expectEqualStrings(bare, try encode(&enc, n, .{ .pad = false }));
        const d3 = try decode(&dec, bare, .{ .padding = .forbidden });
        try testing.expectEqualSlices(u8, n, dec[0..d3]);
        // Lower case is the same text with every letter folded (Python has no
        // lower-case output, so this is checked against the folded oracle text,
        // including the letter `A`, the first one of both alphabets).
        var lower_std: [encodedLen(256, true)]u8 = undefined;
        var lower_hex: [encodedLen(256, true)]u8 = undefined;
        try testing.expectEqualStrings(std.ascii.lowerString(&lower_std, v.std), try encode(&enc, n, .{ .lowercase = true }));
        try testing.expectEqualStrings(std.ascii.lowerString(&lower_hex, v.hex), try encode(&enc, n, .{ .alphabet = .hex, .lowercase = true }));
    }
}

const testkit = @import("testkit");

const fuzz_seeds = [_][]const u8{
    testkit.fuzz.seed("MZXW6YTBOI======"),
    testkit.fuzz.seed("jbsw y3dp ehpk 3pxp"),
    testkit.fuzz.seed("MZ======"), // non-canonical trailing bits
    testkit.fuzz.seed("MY==A==="), // data after padding
    testkit.fuzz.seed("M"), // impossible length
    testkit.fuzz.seed("========"),
    testkit.fuzz.seed(""),
};

const fz = @import("fuzz_test.zig");
const DecodeMark = fz.Marker(enum { accepted, refused, hex_tried, whitespace });

test "fuzz: decode never panics, and every accepted text is canonical" {
    try testing.fuzz({}, fuzzDecodeSmith, .{ .corpus = &fuzz_seeds });
}

test "fuzz driver: BASE32_FUZZ (decode)" {
    try fz.fuzz_driver.run(fuzzDecode, .{ .prefix = "BASE32_FUZZ", .name = "base32-decode" });
}

test "fuzz harness: decode, 600 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "base32-decode", 600);
}

fn fuzzDecodeSmith(_: void, smith: *testing.Smith) !void {
    try fuzzDecode(testing.Smith, smith, testing.allocator);
}

fn fuzzDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var text: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &text, &fuzz_seeds);
    const opts: DecodeOptions = .{
        .alphabet = if (len % 2 == 0) .std else .hex,
        .padding = .optional,
        .case = .insensitive,
        .skip_whitespace = true,
    };
    var out: [decodedLenUpperBound(512)]u8 = undefined;
    if (opts.alphabet == .hex) DecodeMark.mark(.hex_tried);
    for (text[0..len]) |c| if (isSkippable(c)) {
        DecodeMark.mark(.whitespace);
        break;
    };
    const n = decode(&out, text[0..len], opts) catch {
        DecodeMark.mark(.refused);
        return;
    };
    DecodeMark.mark(.accepted);
    // Whatever decode accepts must be the (unique) encoding of what it
    // returned, modulo case, padding and whitespace.
    var again: [encodedLen(out.len, false)]u8 = undefined;
    const re = try encode(&again, out[0..n], .{ .alphabet = opts.alphabet, .pad = false });
    var k: usize = 0;
    for (text[0..len]) |c| {
        if (isSkippable(c) or c == '=') continue;
        try testing.expect(k < re.len);
        try testing.expectEqual(std.ascii.toUpper(c), re[k]);
        k += 1;
    }
    try testing.expectEqual(re.len, k);
}

// ── the table implementation this replaced, kept to cross-check ─────────────

const old_invalid: u8 = 0xff;

fn oldTable(alphabet: Alphabet, case: Case) [256]u8 {
    var t: [256]u8 = @splat(old_invalid);
    for (alphabet.symbols(), 0..) |c, i| {
        t[c] = @intCast(i);
        if (case == .insensitive and c >= 'A') t[c | 0x20] = @intCast(i);
    }
    return t;
}

fn oldDecode(dest: []u8, text: []const u8, opts: DecodeOptions) DecodeError!usize {
    const table = oldTable(opts.alphabet, opts.case);
    var acc: u32 = 0;
    var nbits: u5 = 0;
    var nsym: usize = 0;
    var npad: usize = 0;
    var out: usize = 0;
    for (text) |c| {
        if (opts.skip_whitespace and isSkippable(c)) continue;
        if (c == '=') {
            if (opts.padding == .forbidden) return error.InvalidPadding;
            npad += 1;
            continue;
        }
        const v = table[c];
        if (v == old_invalid) return error.InvalidCharacter;
        if (npad != 0) return error.InvalidPadding;
        nsym += 1;
        acc = (acc << 5) | v;
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (out >= dest.len) return error.BufferTooSmall;
            dest[out] = @truncate(acc >> nbits);
            out += 1;
            acc &= (@as(u32, 1) << nbits) - 1;
        }
    }
    const rem = nsym % 8;
    switch (rem) {
        0, 2, 4, 5, 7 => {},
        else => return error.InvalidLength,
    }
    const want_pad: usize = (8 - rem) % 8;
    switch (opts.padding) {
        .required => if (npad != want_pad) return error.InvalidPadding,
        .optional => if (npad != 0 and npad != want_pad) return error.InvalidPadding,
        .forbidden => {},
    }
    if (acc != 0) return error.NonCanonical;
    return out;
}

test "constant-time symbolChar agrees with the alphabet table for every 5-bit value" {
    for ([_]Alphabet{ .std, .hex }) |a| for ([_]bool{ false, true }) |lower| {
        const syms = a.symbols();
        for (0..32) |v| {
            const c = syms[v];
            const want = if (c >= 'A' and lower) c | 0x20 else c;
            try testing.expectEqual(want, symbolChar(a, lower, @intCast(v)));
        }
    };
}

test "constant-time symbolValue agrees with the lookup table for every byte" {
    for ([_]Alphabet{ .std, .hex }) |a| for ([_]Case{ .upper_only, .insensitive }) |case| {
        const t = oldTable(a, case);
        for (0..256) |c| {
            const got = symbolValue(a, case, @intCast(c));
            if (t[c] == old_invalid) {
                try testing.expectEqual(@as(u8, 0), got[1]);
                try testing.expectEqual(@as(u8, 0), got[0]);
            } else {
                try testing.expectEqual(@as(u8, 0xFF), got[1]);
                try testing.expectEqual(t[c], got[0]);
            }
        }
    };
}

test "decode agrees with the table implementation on random texts, errors and precedence included" {
    var prng = std.Random.DefaultPrng.init(0x32b4);
    const r = prng.random();
    const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz01689=== \t\n!\x00\xff";
    var text: [48]u8 = undefined;
    var got: [64]u8 = undefined;
    var want: [64]u8 = undefined;
    for (0..60_000) |_| {
        const n = r.uintAtMost(usize, text.len);
        for (text[0..n]) |*c| c.* = alpha[r.uintLessThan(usize, alpha.len)];
        // Half the time start from a real encoding so acceptance is covered.
        if (r.boolean()) {
            var raw: [24]u8 = undefined;
            r.bytes(&raw);
            const e = try encode(&text, raw[0..r.uintAtMost(usize, 24)], .{ .alphabet = if (r.boolean()) .std else .hex, .pad = r.boolean() });
            if (e.len > 0 and r.boolean()) text[r.uintLessThan(usize, e.len)] = alpha[r.uintLessThan(usize, alpha.len)];
            const opts: DecodeOptions = .{ .alphabet = if (r.boolean()) .std else .hex, .padding = r.enumValue(Padding), .case = r.enumValue(Case), .skip_whitespace = r.boolean() };
            try compareDecodes(&got, &want, text[0..e.len], opts);
            continue;
        }
        const opts: DecodeOptions = .{ .alphabet = if (r.boolean()) .std else .hex, .padding = r.enumValue(Padding), .case = r.enumValue(Case), .skip_whitespace = r.boolean() };
        try compareDecodes(&got, &want, text[0..n], opts);
        // A destination too small for the real output.
        try compareDecodes(got[0..r.uintAtMost(usize, 6)], want[0..r.uintAtMost(usize, 6)], text[0..n], opts);
    }
}

fn compareDecodes(got: []u8, want: []u8, text: []const u8, opts: DecodeOptions) !void {
    // The two buffers must be the same size for the BufferTooSmall cases.
    const m = @min(got.len, want.len);
    const a = decode(got[0..m], text, opts);
    const b = oldDecode(want[0..m], text, opts);
    if (a) |n| {
        try testing.expectEqual(try b, n);
        try testing.expectEqualSlices(u8, want[0..n], got[0..n]);
    } else |e| {
        try testing.expectEqual(b, @as(DecodeError!usize, e));
    }
}

test {
    _ = @import("kat_vectors.zig");
    _ = @import("fuzz_test.zig");
}
