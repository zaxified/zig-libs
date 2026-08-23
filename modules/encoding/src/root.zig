// SPDX-License-Identifier: MIT
//! encoding — legacy single-byte code page ↔ UTF-8 conversion
//! (windows-1250/1252, iso-8859-1/2/15). Data-lenient, never traps.
//!
//! The WHATWG "single-byte" decoder/encoder for the European code pages a
//! legacy broker / Excel export is realistically saved in. Internal currency
//! is always UTF-8; this module only runs at the read edge (decode → UTF-8)
//! and the write edge (encode ← UTF-8).
//!
//! Data-lenient: a byte / sequence that cannot be transcoded is emitted
//! verbatim (decode) or replaced with '?' (encode) — never an error, never a
//! crash. Every code page's low half (0x00–0x7F) is ASCII and maps to itself,
//! so structural bytes (delimiters, quotes, CR, LF) survive transcoding and
//! raw byte offsets stay valid.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Legacy single-byte code page ↔ UTF-8 transcoding (5 European code pages: windows-125x, ISO-8859-1/2/15).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "WHATWG Encoding Standard (single-byte subset)",
    .deps = .{},
};

/// Supported text encodings for input / output. `utf8` is the default and a
/// pure pass-through. The rest are the European single-byte code pages.
pub const Encoding = enum {
    utf8,
    windows_1250, // Central European (Czech, Polish, Hungarian, …)
    windows_1252, // Western European
    iso_8859_1, // Latin-1 (Western European)
    iso_8859_2, // Latin-2 (Central European)
    iso_8859_15, // Latin-9 (Latin-1 + €, Š, Ž, Œ, Ÿ)

    /// Parse a config string into an Encoding. Case-insensitive; accepts the
    /// canonical names plus the common aliases. Returns null on no match so
    /// the caller can emit a did-you-mean style warning.
    pub fn parse(s: []const u8) ?Encoding {
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(s, "utf-8") or eq(s, "utf8")) return .utf8;
        if (eq(s, "windows-1250") or eq(s, "windows1250") or eq(s, "cp1250") or eq(s, "win1250")) return .windows_1250;
        if (eq(s, "windows-1252") or eq(s, "windows1252") or eq(s, "cp1252") or eq(s, "win1252")) return .windows_1252;
        if (eq(s, "iso-8859-1") or eq(s, "iso8859-1") or eq(s, "latin-1") or eq(s, "latin1")) return .iso_8859_1;
        if (eq(s, "iso-8859-2") or eq(s, "iso8859-2") or eq(s, "latin-2") or eq(s, "latin2")) return .iso_8859_2;
        if (eq(s, "iso-8859-15") or eq(s, "iso8859-15") or eq(s, "latin-9") or eq(s, "latin9")) return .iso_8859_15;
        return null;
    }

    /// Canonical config string for this encoding.
    pub fn canonicalName(self: Encoding) []const u8 {
        return switch (self) {
            .utf8 => "utf-8",
            .windows_1250 => "windows-1250",
            .windows_1252 => "windows-1252",
            .iso_8859_1 => "iso-8859-1",
            .iso_8859_2 => "iso-8859-2",
            .iso_8859_15 => "iso-8859-15",
        };
    }
};

/// Decode legacy `bytes` in `enc` into a freshly allocated UTF-8 string.
/// For `.utf8` this is a verbatim dupe. ASCII bytes (< 0x80) always pass
/// through unchanged. Caller owns the returned slice.
pub fn decodeToUtf8(alloc: std.mem.Allocator, bytes: []const u8, enc: Encoding) ![]u8 {
    if (enc == .utf8) return alloc.dupe(u8, bytes);
    const table = highTable(enc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    // Worst case is 1 byte → 3 UTF-8 bytes; the common case is ASCII (1:1).
    try out.ensureTotalCapacity(alloc, bytes.len);

    var enc_buf: [4]u8 = undefined;
    for (bytes) |b| {
        if (b < 0x80) {
            try out.append(alloc, b);
            continue;
        }
        const cp = table[b - 0x80];
        const n = std.unicode.utf8Encode(cp, &enc_buf) catch {
            try out.append(alloc, b); // unmappable codepoint → verbatim byte
            continue;
        };
        try out.appendSlice(alloc, enc_buf[0..n]);
    }
    return out.toOwnedSlice(alloc);
}

/// Encode a UTF-8 string into legacy `enc` bytes. For `.utf8` this is a
/// verbatim dupe. A codepoint with no representation in the target code page
/// becomes '?' (single byte); invalid UTF-8 bytes pass through verbatim.
/// Caller owns the returned slice.
pub fn encodeFromUtf8(alloc: std.mem.Allocator, utf8: []const u8, enc: Encoding) ![]u8 {
    if (enc == .utf8) return alloc.dupe(u8, utf8);
    const table = highTable(enc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    // Output is always ≤ the UTF-8 length (multi-byte sequences shrink to one
    // byte), so the input length is a safe upper-bound reservation.
    try out.ensureTotalCapacity(alloc, utf8.len);

    var i: usize = 0;
    while (i < utf8.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(utf8[i]) catch {
            try out.append(alloc, utf8[i]); // invalid leading byte → verbatim
            i += 1;
            continue;
        };
        if (i + seq_len > utf8.len) {
            try out.append(alloc, utf8[i]); // truncated trailing sequence → verbatim
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(utf8[i .. i + seq_len]) catch {
            try out.append(alloc, utf8[i]); // malformed continuation → verbatim
            i += 1;
            continue;
        };
        if (cp < 0x80) {
            try out.append(alloc, @intCast(cp));
        } else if (encodeHigh(table, cp)) |b| {
            try out.append(alloc, b);
        } else {
            try out.append(alloc, '?'); // not representable in the target code page
        }
        i += seq_len;
    }
    return out.toOwnedSlice(alloc);
}

/// Reverse lookup: find the high byte (0x80–0xFF) that maps to `cp` in `table`.
/// Linear scan — the table is 128 entries and the encode path is a rare,
/// non-hot legacy-output feature.
fn encodeHigh(table: *const [128]u21, cp: u21) ?u8 {
    for (table, 0..) |t, i| {
        if (t == cp) return @intCast(0x80 + i);
    }
    return null;
}

// ── 0x80–0xFF code page tables ──────────────────────────────────────────────
//
// Each table maps the 128 high bytes (index 0 = byte 0x80) to a Unicode
// codepoint. Built from an identity base (byte value == codepoint, which is
// exactly Latin-1 and the C1 region) plus the per-code-page overrides where
// the mapping differs. Bytes 0x00–0x7F are ASCII and handled directly by the
// decode loop, never via these tables.

const Ovr = struct { b: u8, cp: u21 };

fn build(comptime ovrs: []const Ovr) [128]u21 {
    var t: [128]u21 = undefined;
    for (&t, 0..) |*e, i| e.* = @intCast(0x80 + i); // identity base (Latin-1 / C1)
    for (ovrs) |o| t[o.b - 0x80] = o.cp;
    return t;
}

fn highTable(enc: Encoding) *const [128]u21 {
    return switch (enc) {
        .utf8 => unreachable, // callers short-circuit utf8 before reaching here
        .windows_1250 => &windows_1250_high,
        .windows_1252 => &windows_1252_high,
        .iso_8859_1 => &iso_8859_1_high,
        .iso_8859_2 => &iso_8859_2_high,
        .iso_8859_15 => &iso_8859_15_high,
    };
}

// ISO-8859-1 (Latin-1): the high half is pure identity (byte == codepoint).
const iso_8859_1_high = build(&.{});

// ISO-8859-15 (Latin-9): Latin-1 with eight substitutions.
const iso_8859_15_high = build(&.{
    .{ .b = 0xA4, .cp = 0x20AC }, // €
    .{ .b = 0xA6, .cp = 0x0160 }, // Š
    .{ .b = 0xA8, .cp = 0x0161 }, // š
    .{ .b = 0xB4, .cp = 0x017D }, // Ž
    .{ .b = 0xB8, .cp = 0x017E }, // ž
    .{ .b = 0xBC, .cp = 0x0152 }, // Œ
    .{ .b = 0xBD, .cp = 0x0153 }, // œ
    .{ .b = 0xBE, .cp = 0x0178 }, // Ÿ
});

// Windows-1252 (Western European): Latin-1 plus the 0x80–0x9F "C1" specials
// (smart quotes, €, dashes, …). The five undefined slots (0x81 0x8D 0x8F 0x90
// 0x9D) keep the identity mapping, matching the WHATWG decoder.
const windows_1252_high = build(&.{
    .{ .b = 0x80, .cp = 0x20AC }, .{ .b = 0x82, .cp = 0x201A }, .{ .b = 0x83, .cp = 0x0192 },
    .{ .b = 0x84, .cp = 0x201E }, .{ .b = 0x85, .cp = 0x2026 }, .{ .b = 0x86, .cp = 0x2020 },
    .{ .b = 0x87, .cp = 0x2021 }, .{ .b = 0x88, .cp = 0x02C6 }, .{ .b = 0x89, .cp = 0x2030 },
    .{ .b = 0x8A, .cp = 0x0160 }, .{ .b = 0x8B, .cp = 0x2039 }, .{ .b = 0x8C, .cp = 0x0152 },
    .{ .b = 0x8E, .cp = 0x017D }, .{ .b = 0x91, .cp = 0x2018 }, .{ .b = 0x92, .cp = 0x2019 },
    .{ .b = 0x93, .cp = 0x201C }, .{ .b = 0x94, .cp = 0x201D }, .{ .b = 0x95, .cp = 0x2022 },
    .{ .b = 0x96, .cp = 0x2013 }, .{ .b = 0x97, .cp = 0x2014 }, .{ .b = 0x98, .cp = 0x02DC },
    .{ .b = 0x99, .cp = 0x2122 }, .{ .b = 0x9A, .cp = 0x0161 }, .{ .b = 0x9B, .cp = 0x203A },
    .{ .b = 0x9C, .cp = 0x0153 }, .{ .b = 0x9E, .cp = 0x017E }, .{ .b = 0x9F, .cp = 0x0178 },
});

// Windows-1250 (Central European). Identity base covers the Latin-1-coincident
// slots; the overrides below are every byte whose codepoint differs (the C1
// specials in 0x80–0x9F and the Central-European letters in 0xA0–0xFF).
const windows_1250_high = build(&.{
    .{ .b = 0x80, .cp = 0x20AC }, .{ .b = 0x82, .cp = 0x201A }, .{ .b = 0x84, .cp = 0x201E },
    .{ .b = 0x85, .cp = 0x2026 }, .{ .b = 0x86, .cp = 0x2020 }, .{ .b = 0x87, .cp = 0x2021 },
    .{ .b = 0x89, .cp = 0x2030 }, .{ .b = 0x8A, .cp = 0x0160 }, .{ .b = 0x8B, .cp = 0x2039 },
    .{ .b = 0x8C, .cp = 0x015A }, .{ .b = 0x8D, .cp = 0x0164 }, .{ .b = 0x8E, .cp = 0x017D },
    .{ .b = 0x8F, .cp = 0x0179 }, .{ .b = 0x91, .cp = 0x2018 }, .{ .b = 0x92, .cp = 0x2019 },
    .{ .b = 0x93, .cp = 0x201C }, .{ .b = 0x94, .cp = 0x201D }, .{ .b = 0x95, .cp = 0x2022 },
    .{ .b = 0x96, .cp = 0x2013 }, .{ .b = 0x97, .cp = 0x2014 }, .{ .b = 0x99, .cp = 0x2122 },
    .{ .b = 0x9A, .cp = 0x0161 }, .{ .b = 0x9B, .cp = 0x203A }, .{ .b = 0x9C, .cp = 0x015B },
    .{ .b = 0x9D, .cp = 0x0165 }, .{ .b = 0x9E, .cp = 0x017E }, .{ .b = 0x9F, .cp = 0x017A },
    .{ .b = 0xA1, .cp = 0x02C7 }, .{ .b = 0xA2, .cp = 0x02D8 }, .{ .b = 0xA3, .cp = 0x0141 },
    .{ .b = 0xA5, .cp = 0x0104 }, .{ .b = 0xAA, .cp = 0x015E }, .{ .b = 0xAF, .cp = 0x017B },
    .{ .b = 0xB2, .cp = 0x02DB }, .{ .b = 0xB3, .cp = 0x0142 }, .{ .b = 0xB9, .cp = 0x0105 },
    .{ .b = 0xBA, .cp = 0x015F }, .{ .b = 0xBC, .cp = 0x013D }, .{ .b = 0xBD, .cp = 0x02DD },
    .{ .b = 0xBE, .cp = 0x013E }, .{ .b = 0xBF, .cp = 0x017C }, .{ .b = 0xC0, .cp = 0x0154 },
    .{ .b = 0xC3, .cp = 0x0102 }, .{ .b = 0xC5, .cp = 0x0139 }, .{ .b = 0xC6, .cp = 0x0106 },
    .{ .b = 0xC8, .cp = 0x010C }, .{ .b = 0xCA, .cp = 0x0118 }, .{ .b = 0xCC, .cp = 0x011A },
    .{ .b = 0xCF, .cp = 0x010E }, .{ .b = 0xD0, .cp = 0x0110 }, .{ .b = 0xD1, .cp = 0x0143 },
    .{ .b = 0xD2, .cp = 0x0147 }, .{ .b = 0xD5, .cp = 0x0150 }, .{ .b = 0xD8, .cp = 0x0158 },
    .{ .b = 0xD9, .cp = 0x016E }, .{ .b = 0xDB, .cp = 0x0170 }, .{ .b = 0xDE, .cp = 0x0162 },
    .{ .b = 0xE0, .cp = 0x0155 }, .{ .b = 0xE3, .cp = 0x0103 }, .{ .b = 0xE5, .cp = 0x013A },
    .{ .b = 0xE6, .cp = 0x0107 }, .{ .b = 0xE8, .cp = 0x010D }, .{ .b = 0xEA, .cp = 0x0119 },
    .{ .b = 0xEC, .cp = 0x011B }, .{ .b = 0xEF, .cp = 0x010F }, .{ .b = 0xF0, .cp = 0x0111 },
    .{ .b = 0xF1, .cp = 0x0144 }, .{ .b = 0xF2, .cp = 0x0148 }, .{ .b = 0xF5, .cp = 0x0151 },
    .{ .b = 0xF8, .cp = 0x0159 }, .{ .b = 0xF9, .cp = 0x016F }, .{ .b = 0xFB, .cp = 0x0171 },
    .{ .b = 0xFE, .cp = 0x0163 }, .{ .b = 0xFF, .cp = 0x02D9 },
});

// ISO-8859-2 (Latin-2). 0x80–0x9F are the C1 controls (identity); 0xA0–0xFF
// are the Central-European letters. Overrides list every 0xA0+ byte whose
// codepoint differs from the identity (Latin-1-coincident) value.
const iso_8859_2_high = build(&.{
    .{ .b = 0xA1, .cp = 0x0104 }, .{ .b = 0xA2, .cp = 0x02D8 }, .{ .b = 0xA3, .cp = 0x0141 },
    .{ .b = 0xA5, .cp = 0x013D }, .{ .b = 0xA6, .cp = 0x015A }, .{ .b = 0xA9, .cp = 0x0160 },
    .{ .b = 0xAA, .cp = 0x015E }, .{ .b = 0xAB, .cp = 0x0164 }, .{ .b = 0xAC, .cp = 0x0179 },
    .{ .b = 0xAE, .cp = 0x017D }, .{ .b = 0xAF, .cp = 0x017B }, .{ .b = 0xB1, .cp = 0x0105 },
    .{ .b = 0xB2, .cp = 0x02DB }, .{ .b = 0xB3, .cp = 0x0142 }, .{ .b = 0xB5, .cp = 0x013E },
    .{ .b = 0xB6, .cp = 0x015B }, .{ .b = 0xB7, .cp = 0x02C7 }, .{ .b = 0xB9, .cp = 0x0161 },
    .{ .b = 0xBA, .cp = 0x015F }, .{ .b = 0xBB, .cp = 0x0165 }, .{ .b = 0xBC, .cp = 0x017A },
    .{ .b = 0xBD, .cp = 0x02DD }, .{ .b = 0xBE, .cp = 0x017E }, .{ .b = 0xBF, .cp = 0x017C },
    .{ .b = 0xC0, .cp = 0x0154 }, .{ .b = 0xC3, .cp = 0x0102 }, .{ .b = 0xC5, .cp = 0x0139 },
    .{ .b = 0xC6, .cp = 0x0106 }, .{ .b = 0xC8, .cp = 0x010C }, .{ .b = 0xCA, .cp = 0x0118 },
    .{ .b = 0xCC, .cp = 0x011A }, .{ .b = 0xCF, .cp = 0x010E }, .{ .b = 0xD0, .cp = 0x0110 },
    .{ .b = 0xD1, .cp = 0x0143 }, .{ .b = 0xD2, .cp = 0x0147 }, .{ .b = 0xD5, .cp = 0x0150 },
    .{ .b = 0xD8, .cp = 0x0158 }, .{ .b = 0xD9, .cp = 0x016E }, .{ .b = 0xDB, .cp = 0x0170 },
    .{ .b = 0xDE, .cp = 0x0162 }, .{ .b = 0xE0, .cp = 0x0155 }, .{ .b = 0xE3, .cp = 0x0103 },
    .{ .b = 0xE5, .cp = 0x013A }, .{ .b = 0xE6, .cp = 0x0107 }, .{ .b = 0xE8, .cp = 0x010D },
    .{ .b = 0xEA, .cp = 0x0119 }, .{ .b = 0xEC, .cp = 0x011B }, .{ .b = 0xEF, .cp = 0x010F },
    .{ .b = 0xF0, .cp = 0x0111 }, .{ .b = 0xF1, .cp = 0x0144 }, .{ .b = 0xF2, .cp = 0x0148 },
    .{ .b = 0xF5, .cp = 0x0151 }, .{ .b = 0xF8, .cp = 0x0159 }, .{ .b = 0xF9, .cp = 0x016F },
    .{ .b = 0xFB, .cp = 0x0171 }, .{ .b = 0xFE, .cp = 0x0163 }, .{ .b = 0xFF, .cp = 0x02D9 },
});

// ── tests ────────────────────────────────────────────────────────────────
const testing = std.testing;

fn expectDecode(enc: Encoding, bytes: []const u8, want: []const u8) !void {
    const got = try decodeToUtf8(testing.allocator, bytes, enc);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectEncode(enc: Encoding, utf8: []const u8, want: []const u8) !void {
    const got = try encodeFromUtf8(testing.allocator, utf8, enc);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "parse: canonical names and aliases" {
    try testing.expectEqual(Encoding.utf8, Encoding.parse("UTF-8").?);
    try testing.expectEqual(Encoding.windows_1250, Encoding.parse("windows-1250").?);
    try testing.expectEqual(Encoding.windows_1250, Encoding.parse("cp1250").?);
    try testing.expectEqual(Encoding.windows_1252, Encoding.parse("Windows-1252").?);
    try testing.expectEqual(Encoding.iso_8859_1, Encoding.parse("latin1").?);
    try testing.expectEqual(Encoding.iso_8859_2, Encoding.parse("ISO-8859-2").?);
    try testing.expectEqual(Encoding.iso_8859_15, Encoding.parse("latin-9").?);
    try testing.expectEqual(@as(?Encoding, null), Encoding.parse("shift-jis"));
}

test "decode: ASCII passes through in every encoding" {
    for ([_]Encoding{ .utf8, .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 }) |enc| {
        try expectDecode(enc, "AAPL,123.45\n", "AAPL,123.45\n");
    }
}

test "decode: Latin-1 high bytes are identity codepoints" {
    try expectDecode(.iso_8859_1, "caf\xe9", "café"); // 0xE9 → é
    try expectDecode(.iso_8859_1, "\xff", "ÿ"); // 0xFF → ÿ
}

test "decode: Windows-1252 smart quotes and euro" {
    try expectDecode(.windows_1252, "\x93Hi\x94", "“Hi”"); // 0x93/0x94 curly quotes
    try expectDecode(.windows_1252, "\x80", "€"); // 0x80 → €
    try expectDecode(.windows_1252, "na\xefve", "naïve"); // 0xEF → ï (Latin-1 region)
}

test "decode: Windows-1250 Czech letters" {
    // "Příliš" — ř=0xF8, í=0xED, š=0x9A in CP1250
    try expectDecode(.windows_1250, "P\xf8\xedli\x9a", "Příliš");
    try expectDecode(.windows_1250, "\xe8", "č"); // 0xE8 → č
    try expectDecode(.windows_1250, "\xb9", "ą"); // 0xB9 → ą (differs from Latin-1 ¹)
}

test "decode: ISO-8859-2 Czech letters" {
    try expectDecode(.iso_8859_2, "\xe8", "č"); // 0xE8 → č
    try expectDecode(.iso_8859_2, "\xf8", "ř"); // 0xF8 → ř
    try expectDecode(.iso_8859_2, "\xb9", "š"); // 0xB9 → š
}

test "decode: ISO-8859-15 euro and Latin-1 divergence" {
    try expectDecode(.iso_8859_15, "\xa4", "€"); // 0xA4 → € (¤ in Latin-1)
    try expectDecode(.iso_8859_15, "\xe9", "é"); // unchanged from Latin-1
}

test "encode: round-trips for representable codepoints" {
    try expectEncode(.iso_8859_1, "café", "caf\xe9");
    try expectEncode(.windows_1250, "Příliš", "P\xf8\xedli\x9a");
    try expectEncode(.iso_8859_2, "č", "\xe8");
    try expectEncode(.windows_1252, "€", "\x80");
    try expectEncode(.iso_8859_15, "€", "\xa4");
}

test "encode: ASCII and utf8 pass-through" {
    try expectEncode(.windows_1250, "AAPL,1.5\n", "AAPL,1.5\n");
    try expectEncode(.utf8, "Příliš", "Příliš");
    try expectDecode(.utf8, "Příliš", "Příliš");
}

test "encode: unrepresentable codepoint becomes '?'" {
    // A CJK character cannot be expressed in any single-byte European code page.
    try expectEncode(.windows_1250, "A日B", "A?B");
    try expectEncode(.iso_8859_1, "€", "?"); // € is not in Latin-1
}

test "decode/encode: empty string" {
    try expectDecode(.windows_1250, "", "");
    try expectEncode(.windows_1250, "", "");
}

test "encode: invalid UTF-8 passes through verbatim" {
    try expectEncode(.iso_8859_1, "ab\xffcd", "ab\xffcd");
}

test "canonicalName: round-trips through parse for every Encoding (audit F2)" {
    // canonicalName() had zero test coverage — a wrong string for one arm
    // (e.g. windows_1250 mislabeled as "windows-1252") stayed green.
    inline for (@typeInfo(Encoding).@"enum".fields) |f| {
        const e: Encoding = @enumFromInt(f.value);
        try testing.expectEqual(e, Encoding.parse(e.canonicalName()).?);
    }
    try testing.expectEqualStrings("windows-1250", Encoding.windows_1250.canonicalName());
}

test "encode: cp U+0080 boundary — ASCII cutoff is strictly '< 0x80' (audit F3)" {
    // 0x80 is the first non-ASCII codepoint. windows_1252 overrides byte 0x80's
    // identity mapping (to €), so no byte maps back to raw cp U+0080 there —
    // it must fall to '?', not be truncated into the ASCII branch.
    try expectEncode(.iso_8859_1, "\u{80}", "\x80"); // identity: still round-trips
    try expectEncode(.windows_1252, "\u{80}", "?"); // 0x80 is remapped to €; no byte left for raw U+0080
}

test "encode: a valid multi-byte lead truncated at buffer end passes through, no OOB (audit F1)" {
    // The invalid-leading-byte case above (0xFF) is caught by utf8ByteSequenceLength;
    // the SEPARATE truncated-trailing-sequence bounds check (a valid lead byte with
    // too few continuation bytes left in the buffer) was load-bearing but untested —
    // disabling it OOB-read past the buffer. These exercise that path directly.
    try expectEncode(.iso_8859_1, "ab\xc2", "ab\xc2"); // 2-byte lead (0xC2), 0 continuation
    try expectEncode(.iso_8859_1, "ab\xe2\x82", "ab\xe2\x82"); // 3-byte lead (0xE2), only 1 continuation
}

test {
    // Exhaustive cross-check of all five high-tables against vendored
    // normative sources (WHATWG index-*.txt / Unicode.org 8859-1.TXT) — see
    // normative_test.zig and ../../NOTICE.
    _ = @import("normative_vectors.zig");
    _ = @import("normative_test.zig");
}

// ── fuzz: decode/encode never panic, OOB or leak on arbitrary bytes ────────
//
// `decodeToUtf8` is the module's decode entry point — legacy code-page bytes
// off the read edge (a broker/Excel export saved in an unknown encoding).
// It is data-lenient by design (never errors on malformed input, an
// unmappable codepoint is emitted verbatim), so unlike a rejecting parser
// there is no structure to bias toward: every byte value takes the same
// bounded per-byte path (ASCII passthrough, table lookup, or the
// `utf8Encode` fallback), so plain arbitrary bytes already reach all of it.
// `encodeFromUtf8` (the write edge) is fuzzed alongside it — the more
// branchy of the two (invalid leading byte / truncated trailing sequence /
// malformed continuation, each with its own audit-found edge case above) —
// over the SAME bytes, since malformed UTF-8 is exactly what a lenient
// encoder must also tolerate. Both allocate, so this runs under
// `std.testing.allocator` with the result freed on every path — a leak here
// is a real finding, not a lenient no-op.
test "fuzz: decodeToUtf8 / encodeFromUtf8 never panic, OOB or leak on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzCodecNeverLeaks, .{});
}

fn fuzzCodecNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];

    const encs = [_]Encoding{ .utf8, .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 };
    const enc = encs[smith.index(encs.len)];

    const a = std.testing.allocator;
    const decoded = try decodeToUtf8(a, input, enc);
    defer a.free(decoded);
    const encoded = try encodeFromUtf8(a, input, enc);
    defer a.free(encoded);
}
