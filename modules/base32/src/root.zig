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
//! SPEC.md "Threat model".
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
    const syms = opts.alphabet.symbols();
    const case_bit: u8 = if (opts.lowercase) 0x20 else 0;
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
            const c = syms[@intCast((v >> shift) & 31)];
            // Letters get the case bit; digits ('0'..'9', '2'..'7') do not.
            dest[o] = if (c >= 'A') c | case_bit else c;
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

const invalid: u8 = 0xff;

fn buildTable(comptime alphabet: Alphabet, comptime case: Case) [256]u8 {
    var t: [256]u8 = @splat(invalid);
    const syms = alphabet.symbols();
    for (syms, 0..) |c, i| {
        t[c] = @intCast(i);
        if (case == .insensitive and c >= 'A') t[c | 0x20] = @intCast(i);
    }
    return t;
}

const table_std_upper: [256]u8 = buildTable(.std, .upper_only);
const table_std_any: [256]u8 = buildTable(.std, .insensitive);
const table_hex_upper: [256]u8 = buildTable(.hex, .upper_only);
const table_hex_any: [256]u8 = buildTable(.hex, .insensitive);

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
    const table: *const [256]u8 = switch (opts.alphabet) {
        .std => switch (opts.case) {
            .upper_only => &table_std_upper,
            .insensitive => &table_std_any,
        },
        .hex => switch (opts.case) {
            .upper_only => &table_hex_upper,
            .insensitive => &table_hex_any,
        },
    };
    var acc: u32 = 0; // holds `nbits` (< 8) pending bits between symbols
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
        if (v == invalid) return error.InvalidCharacter;
        if (npad != 0) return error.InvalidPadding; // data after padding
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

test "fuzz: decode never panics, and every accepted text is canonical" {
    try testing.fuzz({}, fuzzDecode, .{ .corpus = &fuzz_seeds });
}

fn fuzzDecode(_: void, smith: *testing.Smith) !void {
    var text: [512]u8 = undefined;
    const len: usize = smith.slice(&text);
    const opts: DecodeOptions = .{
        .alphabet = if (len % 2 == 0) .std else .hex,
        .padding = .optional,
        .case = .insensitive,
        .skip_whitespace = true,
    };
    var out: [decodedLenUpperBound(512)]u8 = undefined;
    const n = decode(&out, text[0..len], opts) catch return;
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

test {
    _ = @import("kat_vectors.zig");
}
