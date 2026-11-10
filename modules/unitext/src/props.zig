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
