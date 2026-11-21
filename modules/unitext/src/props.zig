// SPDX-License-Identifier: MIT

//! Per-code-point properties and the Python `str` classification methods.
//!
//! The string forms follow CPython's `str.isalpha()` family exactly (each is
//! defined there by General_Category, Numeric_Type, Bidi_Class or the Uppercase /
//! Lowercase properties, which is what the tables hold). Rust's `char::is_alphabetic`
//! is the Alphabetic property (broader: includes Nl and Other_Alphabetic) and
//! `char::is_numeric` is Nd+Nl+No (narrower than Python's `isnumeric`, which
//! includes the CJK ideograph numerals): the per-code-point functions here are
//! Python's, not Rust's, except `isAlphabeticCp` (the Alphabetic property, Rust's and polars').

const std = @import("std");
const ucd = @import("ucd.zig");
const utf8 = @import("utf8.zig");
const common = @import("common.zig");

pub const GeneralCategory = ucd.GeneralCategory;
pub const Options = common.Options;

/// Unicode General_Category of `cp` (`Cn` above U+10FFFF and for unassigned code points).
pub fn generalCategory(cp: u21) GeneralCategory {
    return ucd.category(cp);
}

/// Canonical_Combining_Class of `cp` (0 for a starter and above U+10FFFF); Python
/// `unicodedata.combining`, Go `norm.Properties.CCC`, Rust `unicode_normalization::char::canonical_combining_class`.
pub fn combiningClass(cp: u21) u8 {
    return ucd.ccc(cp);
}

// ── single-property lookups (CPython `unicodedata`) ─────────────────────────

/// `unicodedata.decimal`: the decimal digit value (Numeric_Type=Decimal) or null.
pub fn decimalValue(cp: u21) ?u8 {
    const d = ucd.numrec(cp).decimal;
    return if (d < 0) null else @intCast(d);
}

/// `unicodedata.digit`: the digit value (Numeric_Type Decimal or Digit) or null.
pub fn digitValue(cp: u21) ?u8 {
    const d = ucd.numrec(cp).digit;
    return if (d < 0) null else @intCast(d);
}

/// A Numeric_Value: `num / den` (`den` >= 1; U+0F33 is -1/2, U+5104 is 100000000/1).
pub const Numeric = struct {
    num: i64,
    den: u32,

    /// CPython's `unicodedata.numeric` returns this float.
    pub fn toF64(n: Numeric) f64 {
        return @as(f64, @floatFromInt(n.num)) / @as(f64, @floatFromInt(n.den));
    }
};

/// `unicodedata.numeric`: the Numeric_Value (UnicodeData field 8) or null.
pub fn numericValue(cp: u21) ?Numeric {
    const r = ucd.numrec(cp);
    if (r.den == 0) return null;
    return .{ .num = r.num, .den = r.den };
}

/// Bidi_Class, in the order of UAX #9 Table 4.
pub const BidiClass = enum { l, r, al, en, es, et, an, cs, nsm, bn, b, s, ws, on, lre, lro, rle, rlo, pdf, lri, rli, fsi, pdi };

/// `unicodedata.bidirectional`: the Bidi_Class of UnicodeData.txt, null for a code point it does
/// not list (CPython returns the empty string; the unassigned defaults of DerivedBidiClass.txt are not applied).
pub fn bidiClass(cp: u21) ?BidiClass {
    const v: u16 = ucd.uprops(cp) & 31;
    if (v == 0) return null;
    return @fromBackingInt(@intCast(v - 1));
}

/// `unicodedata.mirrored`: Bidi_Mirrored.
pub fn isMirrored(cp: u21) bool {
    return ucd.uprops(cp) & (1 << 5) != 0;
}

/// East_Asian_Width (UAX #11): neutral, ambiguous, fullwidth, halfwidth, narrow, wide.
pub const EastAsianWidth = enum { n, a, f, h, na, w };

/// `unicodedata.east_asian_width`: the value listed in EastAsianWidth.txt, `.n` for every code
/// point the file does not list (as CPython does).
pub fn eastAsianWidth(cp: u21) EastAsianWidth {
    return @fromBackingInt(@intCast((ucd.uprops(cp) >> 6) & 7));
}

/// The `<tag>` of a compatibility decomposition mapping.
pub const DecompositionTag = enum { font, no_break, initial, medial, final, isolated, circle, super, sub, vertical, wide, narrow, small, square, fraction, compat };

/// One level of the decomposition mapping of UnicodeData.txt field 5.
pub const Decomposition = struct {
    /// Null for a canonical mapping.
    tag: ?DecompositionTag,
    /// The mapped code points, in order (a view into a static table).
    code_points: []const u32,
};

/// `unicodedata.decomposition` as data: the raw one-level mapping of `cp`, null when it has none
/// (Hangul syllables decompose algorithmically and are not listed, as in CPython).
/// `normalize` uses the full recursive tables instead.
pub fn decomposition(cp: u21) ?Decomposition {
    const r = ucd.rawdecomp(cp);
    if (r.len == 0) return null;
    return .{
        .tag = if (r.tag == 0) null else @as(DecompositionTag, @fromBackingInt(@intCast(r.tag - 1))),
        .code_points = ucd.t.rawdecomp_pool[r.off..][0..r.len],
    };
}

/// `unicodedata.decomposition` as text: `"<compat> 0066 0069"`, `"0041 0300"`, or `""` for none.
/// A Hangul syllable gives its jamo (`"110C 1167 11BE"`), as in CPython, though `decomposition` lists none.
/// The longest result is 100 bytes (U+FDFA); a shorter `buf` gets as much as fits, never an error.
pub fn decompositionText(cp: u21, buf: []u8) []const u8 {
    if (ucd.hangul.isSyllable(cp)) { // CPython spells the jamo of a syllable out
        const s = cp - ucd.hangul.s_base;
        const l = ucd.hangul.l_base + s / ucd.hangul.n_count;
        const v = ucd.hangul.v_base + (s % ucd.hangul.n_count) / ucd.hangul.t_count;
        const tj = s % ucd.hangul.t_count;
        const text = (if (tj == 0)
            std.fmt.bufPrint(buf, "{X:0>4} {X:0>4}", .{ l, v })
        else
            std.fmt.bufPrint(buf, "{X:0>4} {X:0>4} {X:0>4}", .{ l, v, ucd.hangul.t_base + tj })) catch return buf[0..0];
        return text;
    }
    const d = decomposition(cp) orelse return buf[0..0];
    var n: usize = 0;
    if (d.tag) |tg| {
        const name = switch (tg) {
            .no_break => "noBreak",
            else => @tagName(tg),
        };
        const s = std.fmt.bufPrint(buf[n..], "<{s}>", .{name}) catch return buf[0..n];
        n += s.len;
    }
    for (d.code_points, 0..) |c, i| {
        const sep: []const u8 = if (i == 0 and d.tag == null) "" else " ";
        const s = std.fmt.bufPrint(buf[n..], "{s}{X:0>4}", .{ sep, c }) catch return buf[0..n];
        n += s.len;
    }
    return buf[0..n];
}

/// Python `str.isalpha` for one code point: category Lm, Lt, Lu, Ll or Lo.
pub fn isAlphaCp(cp: u21) bool {
    return switch (ucd.category(cp)) {
        .Lu, .Ll, .Lt, .Lm, .Lo => true,
        else => false,
    };
}

/// The Alphabetic derived property (`DerivedCoreProperties.txt`: Lu, Ll, Lt, Lm, Lo, Nl and
/// Other_Alphabetic, which includes many combining vowel signs of category Mc / Mn). This is
/// Rust's `char::is_alphabetic` and polars' `cs.alpha()`; `isAlphaCp` is Python's narrower
/// `str.isalpha` (letters only).
pub fn isAlphabeticCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_alphabetic != 0;
}

/// Python `str.isdecimal`: Numeric_Type=Decimal (category Nd).
pub fn isDecimalCp(cp: u21) bool {
    return ucd.numericType(cp) == 3;
}

/// Python `str.isdigit`: Numeric_Type=Decimal or Digit (adds superscripts, circled digits).
pub fn isDigitCp(cp: u21) bool {
    return ucd.numericType(cp) >= 2;
}

/// Python `str.isnumeric`: any Numeric_Type (adds fractions, Roman numerals and the CJK numerals).
pub fn isNumericCp(cp: u21) bool {
    return ucd.numericType(cp) >= 1;
}

/// Python `str.isalnum`: `isAlphaCp or isDecimalCp or isDigitCp or isNumericCp`.
pub fn isAlnumCp(cp: u21) bool {
    return isAlphaCp(cp) or ucd.numericType(cp) >= 1;
}

/// Python `str.isspace`: Bidi_Class WS, B or S, or category Zs.
pub fn isSpaceCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_space != 0;
}

/// Python's uppercase test (`Py_UNICODE_ISUPPER`): the Uppercase property (not Lt).
pub fn isUpperCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_upper != 0;
}

/// Python's lowercase test: the Lowercase property.
pub fn isLowerCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_lower != 0;
}

/// Python's titlecase test: category Lt.
pub fn isTitleCp(cp: u21) bool {
    return ucd.category(cp) == .Lt;
}

/// The Cased property (what Python's `title()` and `istitle()` treat as a letter, and the
/// Final_Sigma rule's "cased").
pub fn isCasedCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_cased != 0;
}

/// The Case_Ignorable property (the Final_Sigma rule skips these).
pub fn isCaseIgnorableCp(cp: u21) bool {
    return ucd.flags(cp) & ucd.f_ignorable != 0;
}

/// Python `str.isprintable` for one code point: not category Cc, Cf, Cs, Co, Cn, Zl, Zp,
/// and of Zs only the ASCII space.
pub fn isPrintableCp(cp: u21) bool {
    return switch (ucd.category(cp)) {
        .Cc, .Cf, .Cs, .Co, .Cn, .Zl, .Zp => false,
        .Zs => cp == ' ',
        else => true,
    };
}

// ── string forms ────────────────────────────────────────────────────────────

/// Every code point passes `pred`, and there is at least one (Python: the empty string is
/// not alpha / decimal / digit / numeric / alnum / space). An ill-formed stretch counts as
/// U+FFFD (category So: none of the above, but printable) under `.replace` and
/// `.pass_through`.
fn allOf(s: []const u8, opts: Options, comptime pred: fn (u21) bool) error{InvalidUtf8}!bool {
    if (s.len == 0) return false;
    var i: usize = 0;
    while (i < s.len) {
        const u = try utf8.unit(s, i, opts.invalid_utf8);
        if (!pred(u.cp)) return false;
        i += u.len;
    }
    return true;
}

/// Python `str.isalpha()`; false for the empty string.
pub fn isAlpha(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isAlphaCp);
}

/// Every code point has the Alphabetic property (`isAlphabeticCp`; Rust `str::chars().all(char::is_alphabetic)`);
/// false for the empty string.
pub fn isAlphabetic(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isAlphabeticCp);
}

/// Python `str.isdecimal()`; false for the empty string.
pub fn isDecimal(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isDecimalCp);
}

/// Python `str.isdigit()` (Numeric_Type Decimal or Digit); false for the empty string.
pub fn isDigit(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isDigitCp);
}

/// Python `str.isnumeric()`; false for the empty string.
pub fn isNumeric(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isNumericCp);
}

/// Python `str.isalnum()`; false for the empty string.
pub fn isAlnum(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isAlnumCp);
}

/// Python `str.isspace()`; false for the empty string.
pub fn isSpace(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    return allOf(s, opts, isSpaceCp);
}

/// Python `str.isprintable()`; TRUE for the empty string (as Python).
pub fn isPrintable(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    if (s.len == 0) return true;
    return allOf(s, opts, isPrintableCp);
}

/// Python `str.isascii()`: every byte below 0x80; true for the empty string. Needs no
/// decoding, so it cannot fail (any byte of an ill-formed string is >= 0x80 or ASCII).
pub fn isAscii(s: []const u8) bool {
    for (s) |b| if (b >= 0x80) return false;
    return true;
}

/// Python `str.isupper()`: at least one cased character and no lowercase or titlecase
/// character (CPython: a character that is Lowercase or Lt makes it false; Uppercase
/// sets "cased"; every other character is ignored).
pub fn isUpper(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    var cased = false;
    var i: usize = 0;
    while (i < s.len) {
        const u = try utf8.unit(s, i, opts.invalid_utf8);
        i += u.len;
        if (isLowerCp(u.cp) or isTitleCp(u.cp)) return false;
        if (isUpperCp(u.cp)) cased = true;
    }
    return cased;
}

/// Python `str.islower()`: at least one cased character and no uppercase or titlecase one.
pub fn isLower(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    var cased = false;
    var i: usize = 0;
    while (i < s.len) {
        const u = try utf8.unit(s, i, opts.invalid_utf8);
        i += u.len;
        if (isUpperCp(u.cp) or isTitleCp(u.cp)) return false;
        if (isLowerCp(u.cp)) cased = true;
    }
    return cased;
}

/// Python `str.istitle()`: uppercase and titlecase characters may only follow uncased
/// ones, lowercase only cased ones, and there is at least one cased character. "Cased"
/// here is Python's: Uppercase, Lowercase or Lt (not the Cased property).
pub fn isTitle(s: []const u8, opts: Options) error{InvalidUtf8}!bool {
    var cased = false;
    var prev_cased = false;
    var i: usize = 0;
    while (i < s.len) {
        const u = try utf8.unit(s, i, opts.invalid_utf8);
        i += u.len;
        if (isUpperCp(u.cp) or isTitleCp(u.cp)) {
            if (prev_cased) return false;
            prev_cased = true;
            cased = true;
        } else if (isLowerCp(u.cp)) {
            if (!prev_cased) return false;
            prev_cased = true;
            cased = true;
        } else {
            prev_cased = false;
        }
    }
    return cased;
}

test "category and classification of representative code points" {
    const e = std.testing;
    try e.expectEqual(GeneralCategory.Lu, generalCategory('A'));
    try e.expectEqual(GeneralCategory.Nd, generalCategory('7'));
    try e.expectEqual(GeneralCategory.Lt, generalCategory(0x01C5));
    try e.expectEqual(GeneralCategory.Cn, generalCategory(0x110000));
    try e.expect(isAlphaCp(0x00E9) and isAlphaCp(0x4E00) and !isAlphaCp('1') and !isAlphaCp(0x0301));
    try e.expect(isDecimalCp(0x0663) and !isDecimalCp(0x00B2) and isDigitCp(0x00B2) and !isDigitCp(0x00BD));
    try e.expect(isNumericCp(0x00BD) and isNumericCp(0x4E09) and isNumericCp(0x2167));
    try e.expect(isSpaceCp(0x00A0) and isSpaceCp(0x2029) and isSpaceCp(0x001C) and isSpaceCp(0x3000) and !isSpaceCp(0x200B));
    try e.expect(isPrintableCp(' ') and !isPrintableCp(0x00A0) and !isPrintableCp(0x0007) and isPrintableCp(0xFFFD) and !isPrintableCp(0x110000));
}

test "string forms: Python semantics on the empty string and mixed text" {
    const e = std.testing;
    const o: Options = .{};
    try e.expect(!(try isAlpha("", o)) and !(try isSpace("", o)) and !(try isUpper("", o)) and !(try isTitle("", o)));
    try e.expect((try isPrintable("", o)) and isAscii(""));
    try e.expect(try isAlpha("Žluťoučký", o));
    try e.expect(!(try isAlpha("a1", o)) and try isAlnum("a1", o) and try isAlnum("½", o));
    try e.expect(try isUpper("ŽLUŤOUČKÝ 1", o) and !(try isUpper("Žlut", o)) and !(try isUpper("1", o)));
    try e.expect(try isLower("žluťoučký!", o) and !(try isLower("a B", o)));
    try e.expect(try isTitle("Hello World", o) and !(try isTitle("Hello world", o)) and try isTitle("Hello 1World", o));
    try e.expect(try isTitle("ǅ", o) and !(try isUpper("ǅ", o)) and !(try isLower("ǅ", o)));
    try e.expectError(error.InvalidUtf8, isAlpha("a\xFF", o));
    try e.expect(!(try isAlpha("a\xFF", .{ .invalid_utf8 = .replace })));
    try e.expect(try isPrintable("a\xFF", .{ .invalid_utf8 = .pass_through }));
    try e.expect(!isAscii("é"));
}

test "decimalValue / digitValue / numericValue: CPython's documented examples" {
    const e = std.testing;
    try e.expectEqual(@as(?u8, 9), decimalValue('9'));
    try e.expectEqual(@as(?u8, 4), decimalValue(0x0664)); // ARABIC-INDIC DIGIT FOUR
    try e.expectEqual(@as(?u8, null), decimalValue(0x00B2)); // SUPERSCRIPT TWO: a digit, not a decimal
    try e.expectEqual(@as(?u8, 2), digitValue(0x00B2));
    try e.expectEqual(@as(?u8, 1), digitValue(0x2460)); // CIRCLED DIGIT ONE
    try e.expectEqual(@as(?u8, null), digitValue(0x00BD));
    try e.expectEqual(@as(f64, 0.5), numericValue(0x00BD).?.toF64()); // VULGAR FRACTION ONE HALF
    try e.expectEqual(Numeric{ .num = -1, .den = 2 }, numericValue(0x0F33).?); // TIBETAN HALF ZERO
    try e.expectEqual(Numeric{ .num = 3, .den = 1 }, numericValue(0x4E09).?); // 三
    try e.expectEqual(Numeric{ .num = 100000000, .den = 1 }, numericValue(0x5104).?); // 億
    try e.expectEqual(Numeric{ .num = 1000, .den = 1 }, numericValue(0x216F).?); // ROMAN NUMERAL ONE THOUSAND
    try e.expectEqual(Numeric{ .num = 0, .den = 1 }, numericValue('0').?);
    try e.expectEqual(Numeric{ .num = 0, .den = 1 }, numericValue(0x2189).?); // VULGAR FRACTION ZERO THIRDS has "0"
    try e.expectEqual(@as(?Numeric, null), numericValue('a'));
    try e.expectEqual(@as(?Numeric, null), numericValue(0x110000));
}

test "the value lookups agree with the Numeric_Type predicates over every code point" {
    var cp: u21 = 0;
    while (cp <= 0x10FFFF) : (cp += 1) {
        try std.testing.expectEqual(isDecimalCp(cp), decimalValue(cp) != null);
        try std.testing.expectEqual(isDigitCp(cp), digitValue(cp) != null);
        try std.testing.expectEqual(isNumericCp(cp), numericValue(cp) != null);
        if (decimalValue(cp)) |d| try std.testing.expectEqual(@as(i64, d), numericValue(cp).?.num);
    }
}

test "bidiClass, isMirrored, eastAsianWidth: representative code points" {
    const e = std.testing;
    try e.expectEqual(BidiClass.l, bidiClass('a').?);
    try e.expectEqual(BidiClass.r, bidiClass(0x05D0).?); // HEBREW ALEF
    try e.expectEqual(BidiClass.al, bidiClass(0x0627).?);
    try e.expectEqual(BidiClass.en, bidiClass('1').?);
    try e.expectEqual(BidiClass.an, bidiClass(0x0663).?);
    try e.expectEqual(BidiClass.ws, bidiClass(' ').?);
    try e.expectEqual(BidiClass.nsm, bidiClass(0x0300).?);
    try e.expectEqual(BidiClass.on, bidiClass('(').?);
    try e.expectEqual(BidiClass.l, bidiClass(0x4E00).?); // inside a First/Last range
    try e.expectEqual(@as(?BidiClass, null), bidiClass(0x0378)); // unassigned
    try e.expect(isMirrored('(') and isMirrored(')') and isMirrored(0x00AB) and !isMirrored('a'));
    try e.expectEqual(EastAsianWidth.na, eastAsianWidth('A'));
    try e.expectEqual(EastAsianWidth.w, eastAsianWidth(0x4E2D)); // 中
    try e.expectEqual(EastAsianWidth.h, eastAsianWidth(0xFF71)); // HALFWIDTH KATAKANA A
    try e.expectEqual(EastAsianWidth.f, eastAsianWidth(0xFF21)); // FULLWIDTH LATIN A
    try e.expectEqual(EastAsianWidth.a, eastAsianWidth(0x03B1)); // GREEK alpha
    try e.expectEqual(EastAsianWidth.n, eastAsianWidth(0x0378));
    try e.expectEqual(EastAsianWidth.n, eastAsianWidth(0x110000));
}

test "decomposition: the raw mapping, canonical and tagged, and its text form" {
    const e = std.testing;
    var buf: [128]u8 = undefined;
    try e.expectEqualStrings("0041 0300", decompositionText(0x00C0, &buf));
    try e.expectEqualStrings("<noBreak> 0020", decompositionText(0x00A0, &buf));
    try e.expectEqualStrings("<compat> 0066 0069", decompositionText(0xFB01, &buf));
    try e.expectEqualStrings("03A9", decompositionText(0x2126, &buf)); // OHM SIGN, a singleton
    try e.expectEqualStrings("1100 1161", decompositionText(0xAC00, &buf)); // Hangul: the jamo, as CPython
    try e.expectEqualStrings("110C 1167 11BE", decompositionText(0xC84F, &buf));
    try e.expectEqual(@as(?Decomposition, null), decomposition(0xAC00)); // not in UnicodeData.txt
    try e.expectEqualStrings("", decompositionText('a', &buf));
    try e.expectEqual(@as(usize, 18), decomposition(0xFDFA).?.code_points.len);
    try e.expectEqual(DecompositionTag.isolated, decomposition(0xFDFA).?.tag.?);
    try e.expectEqual(@as(?DecompositionTag, null), decomposition(0x00C0).?.tag);
    try e.expectEqual(DecompositionTag.super, decomposition(0x00B2).?.tag.?);
    try e.expectEqual(DecompositionTag.fraction, decomposition(0x00BD).?.tag.?);
    try e.expectEqual(@as(?Decomposition, null), decomposition(0x110000));
    var small: [4]u8 = undefined;
    try e.expectEqualStrings("0041", decompositionText(0x00C0, &small)); // as much as fits
    var longest: usize = 0;
    var cp: u21 = 0;
    while (cp <= 0x10FFFF) : (cp += 1) longest = @max(longest, decompositionText(cp, &buf).len);
    try e.expectEqual(@as(usize, 100), longest);
}

test "the raw mappings, expanded, equal the full NFD / NFKD tables over every code point" {
    const e = std.testing;
    const norm_mod = @import("norm.zig");
    const A = e.allocator;
    var cp: u21 = 0;
    while (cp <= 0x10FFFF) : (cp += 1) {
        if (cp >= 0xD800 and cp <= 0xDFFF) continue;
        const d = decomposition(cp) orelse continue;
        for ([_]bool{ false, true }) |compat| {
            if (!compat and d.tag != null) continue;
            var want: std.ArrayList(u21) = .empty;
            defer want.deinit(A);
            try expand(A, &want, cp, compat);
            std.mem.sort(u21, want.items, {}, std.sort.asc(u21));
            var enc: [4]u8 = undefined;
            const n = utf8.encode(cp, &enc);
            const got_s = try norm_mod.normalize(A, enc[0..n], if (compat) .nfkd else .nfd, .{});
            defer A.free(got_s);
            var got: std.ArrayList(u21) = .empty;
            defer got.deinit(A);
            var it = std.unicode.Utf8View.initUnchecked(got_s).iterator();
            while (it.nextCodepoint()) |c| try got.append(A, c);
            std.mem.sort(u21, got.items, {}, std.sort.asc(u21));
            try e.expectEqualSlices(u21, want.items, got.items);
        }
    }
}

fn expand(a: std.mem.Allocator, out: *std.ArrayList(u21), cp: u21, compat: bool) !void {
    const hangul = ucd.hangul;
    if (hangul.isSyllable(cp)) {
        const s = cp - hangul.s_base;
        try out.append(a, @intCast(hangul.l_base + s / hangul.n_count));
        try out.append(a, @intCast(hangul.v_base + (s % hangul.n_count) / hangul.t_count));
        if (s % hangul.t_count != 0) try out.append(a, @intCast(hangul.t_base + s % hangul.t_count));
        return;
    }
    if (decomposition(cp)) |d| if (d.tag == null or compat) {
        for (d.code_points) |c| try expand(a, out, @intCast(c), compat);
        return;
    };
    try out.append(a, cp);
}
