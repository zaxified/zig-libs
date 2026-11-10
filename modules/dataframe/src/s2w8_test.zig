// SPDX-License-Identifier: MIT
//! Hand-written tests of dataframe S2 wave W8: Unicode case mapping, `normalize`, `unaccent`
//! and the `is*` classes through `unitext`, in the cell functions, the `Expr` arms, the name
//! verbs and the selectors. The engines' answers are replayed in `s2w8_oracle_test.zig`;
//! these cover what they cannot: exact small cases, the invalid-UTF-8 policy and the cap.
const std = @import("std");
const testing = std.testing;
const vm = @import("value.zig");
const fm = @import("frame.zig");
const ex = @import("expr.zig");
const fnx = @import("exprfn.zig");
const st = @import("structure.zig");
const nm = @import("names.zig");
const Frame = fm.Frame;
const Value = vm.Value;

fn arena() std.heap.ArenaAllocator {
    return .init(testing.allocator);
}

fn expectText(want: []const u8, got: []const u8) !void {
    try testing.expectEqualStrings(want, got);
}

test "w8 case: Czech, German, Greek, Turkish, ligatures" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try expectText("ŽLUŤOUČKÝ KŮŇ", try fnx.upper(a, "Žluťoučký kůň"));
    try expectText("žluťoučký kůň", try fnx.lower(a, "ŽLUŤOUČKÝ KŮŇ"));
    try expectText("STRASSE", try fnx.upper(a, "straße"));
    try expectText("strasse", try fnx.casefold(a, "Straße"));
    try expectText("strasse", try fnx.casefold(a, "STRASSE"));
    // Python and Rust: a sigma that ends a word is final.
    try expectText("σας", try fnx.lower(a, "ΣΑΣ"));
    try expectText("σ", try fnx.lower(a, "Σ"));
    try expectText("σσ", try fnx.casefold(a, "σς"));
    // Turkish capital dotted I has no language rules here: i + combining dot above.
    try expectText("i\u{307}stanbul", try fnx.lower(a, "İstanbul"));
    try expectText("FINE", try fnx.upper(a, "ﬁne"));
    try expectText("ʼN", try fnx.upper(a, "ŉ"));
    // capitalize / title / swapcase
    try expectText("ǅungla", try fnx.capitalize(a, "ǆungla"));
    try expectText("ǅungla", try fnx.capitalize(a, "ǄUNGLA"));
    try expectText("Žluťoučký Kůň", try fnx.title(a, "ŽLUŤOUČKÝ KŮŇ"));
    try expectText("They'Re 3Rd", try fnx.title(a, "they're 3rd"));
    try expectText("Éa", try fnx.capitalize(a, "éA"));
    try expectText("hÉLLO", try fnx.swapcase(a, "Héllo"));
    try expectText("STRASSE", try fnx.swapcase(a, "straße"));
}

test "w8 case: ASCII is unchanged" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try expectText("hello world", try fnx.lower(a, "Hello World"));
    try expectText("HELLO WORLD", try fnx.upper(a, "Hello World"));
    try expectText("Hello World", try fnx.title(a, "hELLO wORLD"));
    try expectText("Hello world", try fnx.capitalize(a, "hELLO wORLD"));
    try expectText("hELLO wORLD", try fnx.swapcase(a, "Hello World"));
    try expectText("", try fnx.lower(a, ""));
}

test "w8 invalid UTF-8 is treated as bytes: ASCII letters change, the rest is kept" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const bad = "\xffAb\xc3";
    try expectText("\xffab\xc3", try fnx.lower(a, bad));
    try expectText("\xffAB\xc3", try fnx.upper(a, bad));
    try expectText("\xffab\xc3", try fnx.casefold(a, bad));
    try expectText(bad, try fnx.normalize(a, bad, .nfc));
    try expectText(bad, try fnx.normalize(a, bad, .nfkd));
    try expectText(bad, try fnx.unaccent(a, bad));
    inline for (.{ .alpha, .digit, .alnum, .space, .lower, .upper, .title, .decimal, .numeric }) |cl| {
        try testing.expect(!fnx.isClass("\xff", cl));
        try testing.expect(!fnx.isClass("a\xc3", cl));
    }
}

test "w8 classes: Arabic-Indic digits, superscripts, fractions, full-width, spaces" {
    // Arabic-Indic digits: decimal, digit, numeric, not alpha.
    try testing.expect(fnx.isClass("٣٤٥", .decimal));
    try testing.expect(fnx.isClass("٣٤٥", .digit));
    try testing.expect(fnx.isClass("٣٤٥", .numeric));
    try testing.expect(fnx.isClass("٣٤٥", .alnum));
    try testing.expect(!fnx.isClass("٣٤٥", .alpha));
    // Devanagari digits.
    try testing.expect(fnx.isClass("१२३", .decimal));
    // Superscript two: a digit and numeric, not decimal.
    try testing.expect(fnx.isClass("²", .digit));
    try testing.expect(!fnx.isClass("²", .decimal));
    try testing.expect(fnx.isClass("²", .numeric));
    // One half and a Roman numeral: numeric only.
    try testing.expect(fnx.isClass("½", .numeric));
    try testing.expect(!fnx.isClass("½", .digit));
    try testing.expect(fnx.isClass("Ⅻ", .numeric));
    try testing.expect(!fnx.isClass("Ⅻ", .alpha));
    // Full-width letters and digits.
    try testing.expect(fnx.isClass("ａｂｃ", .alpha));
    try testing.expect(fnx.isClass("ＡＢ", .upper));
    try testing.expect(fnx.isClass("１２３", .decimal));
    try testing.expect(fnx.isClass("ａ１", .alnum));
    // Letters of other scripts.
    try testing.expect(fnx.isClass("日本語", .alpha));
    try testing.expect(fnx.isClass("Žluťoučký", .alpha));
    try testing.expect(fnx.isClass("žluťoučký", .lower));
    try testing.expect(!fnx.isClass("Žluťoučký", .lower));
    try testing.expect(fnx.isClass("Žluťoučký Kůň", .title));
    try testing.expect(fnx.isClass("Ǆ", .upper));
    try testing.expect(fnx.isClass("ǅ", .title));
    try testing.expect(!fnx.isClass("ǅ", .upper));
    // Spaces: no-break, ideographic, em space.
    try testing.expect(fnx.isClass("\u{a0}", .space));
    try testing.expect(fnx.isClass("\u{3000}\u{2003}", .space));
    try testing.expect(!fnx.isClass("a\u{a0}", .space));
    // The empty text is no class.
    try testing.expect(!fnx.isClass("", .alpha));
    try testing.expect(!fnx.isClass("", .numeric));
    // ASCII, unchanged.
    try testing.expect(fnx.isClass("123", .decimal));
    try testing.expect(fnx.isClass("123", .numeric));
    try testing.expect(fnx.isClass("abc", .alpha));
    try testing.expect(!fnx.isClass("a1", .alpha));
    try testing.expect(fnx.isClass("\x1f", .space));
}

test "w8 normalize and unaccent" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    try expectText("e\u{301}", try fnx.normalize(a, "é", .nfd));
    try expectText("é", try fnx.normalize(a, "e\u{301}", .nfc));
    try expectText("abc123", try fnx.normalize(a, "ａｂｃ１２３", .nfkc));
    try expectText("ａｂｃ１２３", try fnx.normalize(a, "ａｂｃ１２３", .nfc));
    try expectText("fi", try fnx.normalize(a, "ﬁ", .nfkd));
    try expectText("ﬁ", try fnx.normalize(a, "ﬁ", .nfd));
    try expectText("x2", try fnx.normalize(a, "x²", .nfkc));
    try expectText("ZLUTOUCKY KUN", try fnx.unaccent(a, "ŽLUŤOUČKÝ KŮŇ"));
    try expectText("Lodz", try fnx.unaccent(a, "Łódź"));
    try expectText("Strasse", try fnx.unaccent(a, "Straße"));
    try expectText("plain", try fnx.unaccent(a, "plain"));
}

fn textFrame(a: std.mem.Allocator, texts: []const ?[]const u8) !Frame {
    const cs = try a.alloc(Value, texts.len);
    for (cs, texts) |*c, t| c.* = if (t) |s| .{ .text = s } else .null;
    const cols = try a.alloc(vm.Column, 1);
    cols[0] = .{ .name = "x", .type = .text };
    const data = try a.alloc(fm.ColumnData, 1);
    data[0] = try fm.columnFromCells(a, cs);
    return .{ .columns = cols, .data = data, .len = texts.len };
}

test "w8 Expr arms: Unary ops and normalize over a column, null stays null" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const f = try textFrame(a, &.{ "Žluťoučký", null, "straße", "ａｂ" });
    const x = try a.create(ex.Expr);
    x.* = .{ .col = "x" };
    const out = try ex.mutate(a, f, &.{
        .{ .out = "up", .expr = .{ .unary = .{ .op = .upper, .x = x } } },
        .{ .out = "lo", .expr = .{ .unary = .{ .op = .lower, .x = x } } },
        .{ .out = "cf", .expr = .{ .unary = .{ .op = .casefold, .x = x } } },
        .{ .out = "ua", .expr = .{ .unary = .{ .op = .unaccent, .x = x } } },
        .{ .out = "al", .expr = .{ .unary = .{ .op = .is_alpha, .x = x } } },
        .{ .out = "nm", .expr = .{ .unary = .{ .op = .is_numeric, .x = x } } },
        .{ .out = "nf", .expr = .{ .normalize = .{ .x = x, .form = .nfkc } } },
    });
    const up = out.series("up").?;
    try expectText("ŽLUŤOUČKÝ", up.get(0).text);
    try testing.expect(up.get(1) == .null);
    try expectText("STRASSE", up.get(2).text);
    try expectText("žluťoučký", out.series("lo").?.get(0).text);
    try expectText("strasse", out.series("cf").?.get(2).text);
    try expectText("Zlutoucky", out.series("ua").?.get(0).text);
    try testing.expect(out.series("al").?.get(0).bool);
    try testing.expect(out.series("al").?.get(1) == .null);
    try testing.expect(!out.series("nm").?.get(0).bool);
    try expectText("ab", out.series("nf").?.get(3).text);
}

test "w8 a cell that grows past max_text_result is error.TooLarge, not an allocation" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // "İ" lower-cases from 2 to 3 bytes: 6M of them are 12 MB in and 18 MB out.
    const n = 6_000_000;
    const big = try a.alloc(u8, n * 2);
    for (0..n) |i| @memcpy(big[i * 2 ..][0..2], "İ");
    try testing.expectError(error.TooLarge, fnx.lower(a, big));
    try testing.expectError(error.TooLarge, fnx.normalize(a, big, .nfd));
}

test "w8 names: rename lower/upper by the Unicode mapping, selectors by Unicode class" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const names = [_][]const u8{ "Žluťoučký", "straße", "٣٤٥", "abc1", "日本語", "²" };
    const cols = try a.alloc(vm.Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cols, data, names) |*c, *d, n| {
        c.* = .{ .name = n, .type = .int };
        d.* = try fm.columnFromCells(a, &.{.{ .int = 1 }});
    }
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    const lo = try nm.renameLower(a, f, .all);
    try expectText("žluťoučký", lo.columns[0].name);
    const up = try nm.renameUpper(a, f, .all);
    try expectText("ŽLUŤOUČKÝ", up.columns[0].name);
    try expectText("STRASSE", up.columns[1].name);
    const alpha = try st.selectColumns(a, f, .alpha);
    try testing.expectEqual(@as(usize, 3), alpha.len);
    try expectText("Žluťoučký", alpha[0]);
    try expectText("straße", alpha[1]);
    try expectText("日本語", alpha[2]);
    const digit = try st.selectColumns(a, f, .digit);
    try testing.expectEqual(@as(usize, 1), digit.len); // the superscript two is not Nd
    try expectText("٣٤٥", digit[0]);
    const alnum = try st.selectColumns(a, f, .alphanumeric);
    try testing.expectEqual(@as(usize, 6 - 1), alnum.len); // not the superscript two
}

test "w8 strip: Unicode whitespace around valid text, Python str.strip() (U4)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // U+00A0, U+2003, U+3000, U+0085 and U+001C are whitespace to Python's `str.strip()` (isspace);
    // U+200B ZERO WIDTH SPACE and U+FEFF are not.
    try expectText("a", fnx.stripChars("\u{A0}a\u{A0}", null, .both));
    try expectText("a", fnx.stripChars("\u{2003}a\u{3000}", null, .both));
    try expectText("a", fnx.stripChars("\u{85}a\u{85}", null, .both));
    try expectText("a", fnx.stripChars("\x1ca\x1d", null, .both));
    try expectText("a\u{A0}", fnx.stripChars("\u{A0}a\u{A0}", null, .start));
    try expectText("\u{A0}a", fnx.stripChars("\u{A0}a\u{A0}", null, .end));
    try expectText("\u{200B}a\u{200B}", fnx.stripChars("\u{200B}a\u{200B}", null, .both));
    try expectText("a\u{A0}b", fnx.stripChars(" \u{A0}a\u{A0}b\u{2028}\u{2029} ", null, .both));
    try expectText("", fnx.stripChars("\u{A0}\u{3000} \t", null, .both));
    try expectText("\u{200B}", fnx.stripChars("\u{A0}\u{200B}\u{A0}", null, .both));
    // Through the three `Unary` ops and `strip_chars` with null chars.
    const f = try textFrame(a, &.{ "\u{A0}é\u{3000}", null, "\u{2003}x" });
    const x = try a.create(ex.Expr);
    x.* = .{ .col = "x" };
    const out = try ex.mutate(a, f, &.{
        .{ .out = "s", .expr = .{ .unary = .{ .op = .strip, .x = x } } },
        .{ .out = "l", .expr = .{ .unary = .{ .op = .lstrip, .x = x } } },
        .{ .out = "r", .expr = .{ .unary = .{ .op = .rstrip, .x = x } } },
        .{ .out = "c", .expr = .{ .strip_chars = .{ .x = x, .chars = null, .side = .both } } },
    });
    try expectText("é", out.series("s").?.get(0).text);
    try expectText("é\u{3000}", out.series("l").?.get(0).text);
    try expectText("\u{A0}é", out.series("r").?.get(0).text);
    try expectText("é", out.series("c").?.get(0).text);
    try testing.expect(out.series("s").?.get(1) == .null);
    try expectText("x", out.series("s").?.get(2).text);
    // Explicit chars stay exact: U+00A0 is stripped only when it is listed.
    try expectText("\u{A0}a", fnx.stripChars("\u{A0}a\u{A0}", "\u{A0}", .end));
    try expectText("a", fnx.stripChars("\u{A0}a\u{A0}", "\u{A0}", .both));
    try expectText(" a ", fnx.stripChars(" a ", "\u{A0}", .both));
}

test "w8 strip: a cell that is not valid UTF-8 is bytes, ASCII whitespace only (U4)" {
    // The module's policy: no code points, so only the six ASCII whitespace bytes go; 0x85 and 0xA0 as
    // bytes are not whitespace, and neither are 0x1C..0x1F (as before U4).
    try expectText("\xffa\xff", fnx.stripChars(" \t\xffa\xff\n ", null, .both));
    try expectText("\xA0a\xFF", fnx.stripChars("\xA0a\xFF", null, .both));
    try expectText("\xC2\xA0\xFF", fnx.stripChars("\xC2\xA0\xFF", null, .both)); // a would-be U+00A0 next to a stray byte
    try expectText("\x1ca\xff", fnx.stripChars("\x1ca\xff ", null, .both));
}

test "w8 names: alpha / alphanumeric selectors use the Alphabetic property, combining vowel signs count (U3)" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    // Devanagari ि ा, Thai ิ and Devanagari ः are Other_Alphabetic; the virama (U+094D) and a combining
    // acute (U+0301) are not; digits stay Nd (the Devanagari digit one is Nd).
    const names = [_][]const u8{ "किताब", "सः", "กิน", "हिन्दी", "e\u{301}", "किताब१", "१२", "Ⅻ", "x²", "abc" };
    const cols = try a.alloc(vm.Column, names.len);
    const data = try a.alloc(fm.ColumnData, names.len);
    for (cols, data, names) |*c, *d, n| {
        c.* = .{ .name = n, .type = .int };
        d.* = try fm.columnFromCells(a, &.{.{ .int = 1 }});
    }
    const f: Frame = .{ .columns = cols, .data = data, .len = 1 };
    const alpha = try st.selectColumns(a, f, .alpha);
    try testing.expectEqual(@as(usize, 5), alpha.len);
    try expectText("किताब", alpha[0]);
    try expectText("सः", alpha[1]);
    try expectText("กิน", alpha[2]);
    try expectText("Ⅻ", alpha[3]);
    try expectText("abc", alpha[4]);
    const alnum = try st.selectColumns(a, f, .alphanumeric);
    try testing.expectEqual(@as(usize, 7), alnum.len); // the five, plus "किताब१" and "१२"
    try expectText("किताब१", alnum[3]);
    const digit = try st.selectColumns(a, f, .digit);
    try testing.expectEqual(@as(usize, 1), digit.len);
    try expectText("१२", digit[0]);
}
