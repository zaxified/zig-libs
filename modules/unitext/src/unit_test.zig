// SPDX-License-Identifier: MIT

//! Hand-written cases: the examples in the docs, the traps named in the brief, the
//! policies and the caps. The conformance tests (NormalizationTest, CPython) are in
//! `vectors_test.zig`.

const std = @import("std");
const ut = @import("root.zig");
const testing = std.testing;
const a = testing.allocator;

fn expectMapped(comptime f: anytype, in: []const u8, want: []const u8) !void {
    const got = try f(a, in, .{});
    defer a.free(got);
    try testing.expectEqualStrings(want, got);
}

test "lower: full mappings, Final_Sigma, İ" {
    try expectMapped(ut.lower, "ABC", "abc");
    try expectMapped(ut.lower, "ŽLUŤOUČKÝ KŮŇ", "žluťoučký kůň");
    try expectMapped(ut.lower, "İ", "i\u{307}");
    try expectMapped(ut.lower, "ΑΣ", "ας"); // final sigma
    try expectMapped(ut.lower, "ΑΣΑ", "ασα");
    try expectMapped(ut.lower, "Σ", "σ"); // alone: not preceded by a cased letter
    try expectMapped(ut.lower, "ΑΣ.", "ας."); // followed by a case-ignorable only
    try expectMapped(ut.lower, "Α.Σ", "α.ς"); // preceded across a case-ignorable
    try expectMapped(ut.lower, "ΑΣ.Β", "ασ.β"); // followed across a case-ignorable by a cased one
    try expectMapped(ut.lower, "ß", "ß");
    try expectMapped(ut.lower, "ǅ", "ǆ");
}

test "upper: ß, ŉ, ǰ, ligatures, Greek with iota subscript, ΐ" {
    try expectMapped(ut.upper, "straße", "STRASSE");
    try expectMapped(ut.upper, "ŉ", "ʼN");
    try expectMapped(ut.upper, "ǰ", "J\u{30C}");
    try expectMapped(ut.upper, "ﬁ", "FI");
    try expectMapped(ut.upper, "ΐ", "\u{399}\u{308}\u{301}");
    try expectMapped(ut.upper, "ᾳ", "ΑΙ");
    try expectMapped(ut.upper, "ǆ", "Ǆ");
    try expectMapped(ut.upper, "i", "I"); // no Turkish tailoring
}

test "title, capitalize, swapcase, casefold: Python semantics" {
    try expectMapped(ut.title, "hello wORLD", "Hello World");
    try expectMapped(ut.title, "they're", "They'Re"); // Python: an apostrophe ends the run
    try expectMapped(ut.title, "ǆungla", "ǅungla");
    try expectMapped(ut.title, "ß", "Ss");
    try expectMapped(ut.title, "ΑΣ ΑΣ", "Ας Ας");
    try expectMapped(ut.capitalize, "hELLO wORLD", "Hello world");
    try expectMapped(ut.capitalize, "ǆ", "ǅ");
    try expectMapped(ut.capitalize, "ßa", "Ssa");
    try expectMapped(ut.capitalize, "", "");
    try expectMapped(ut.swapcase, "Hello ß", "hELLO SS");
    try expectMapped(ut.swapcase, "ǅ", "ǅ"); // titlecase is neither upper nor lower
    try expectMapped(ut.swapcase, "ΑΣ", "ας");
    try expectMapped(ut.casefold, "Straße ς Σ ﬁ", "strasse σ σ fi");
    try expectMapped(ut.casefold, "İ", "i\u{307}");
}

test "per-code-point simple mappings" {
    try testing.expectEqual(@as(u21, 'a'), ut.toLowerCp('A'));
    try testing.expectEqual(@as(u21, 0x130 - 0x130 + 'i'), ut.toLowerCp(0x130));
    try testing.expectEqual(@as(u21, 0xDF), ut.toUpperCp(0xDF));
    try testing.expectEqual(@as(u21, 0x1C5), ut.toTitleCp(0x1C6));
    try testing.expectEqual(@as(u21, 0x1C5), ut.toTitleCp(0x1C4));
    try testing.expectEqual(@as(u21, 's'), ut.foldCp('S'));
    try testing.expectEqual(@as(u21, 0x3C3), ut.foldCp(0x3C2));
    try testing.expectEqual(@as(u21, 0x1FFFFF), ut.toLowerCp(0x1FFFFF));
    try testing.expectEqual(@as(u21, 0x110000), ut.toUpperCp(0x110000));
}

test "normalization: the standard examples" {
    const cases = [_]struct { in: []const u8, form: ut.Form, want: []const u8 }{
        .{ .in = "e\u{301}", .form = .nfc, .want = "é" },
        .{ .in = "é", .form = .nfd, .want = "e\u{301}" },
        .{ .in = "ﬁ", .form = .nfc, .want = "ﬁ" },
        .{ .in = "ﬁ", .form = .nfkc, .want = "fi" },
        .{ .in = "①²", .form = .nfkd, .want = "12" },
        .{ .in = "Å", .form = .nfc, .want = "Å" }, // U+212B ANGSTROM -> U+00C5
        .{ .in = "가", .form = .nfd, .want = "\u{1100}\u{1161}" },
        .{ .in = "\u{1100}\u{1161}\u{11A8}", .form = .nfc, .want = "각" },
        .{ .in = "a\u{323}\u{307}", .form = .nfc, .want = "ạ\u{307}" }, // ordering: 323 (220) before 307 (230)
        .{ .in = "a\u{307}\u{323}", .form = .nfc, .want = "ạ\u{307}" },
        .{ .in = "\u{FDFA}", .form = .nfkd, .want = "صلى الله عليه وسلم" },
        .{ .in = "\u{0958}", .form = .nfc, .want = "\u{0915}\u{093C}" }, // composition exclusion
        .{ .in = "", .form = .nfc, .want = "" },
        .{ .in = "plain ASCII", .form = .nfkc, .want = "plain ASCII" },
    };
    for (cases) |c| {
        const got = try ut.normalize(a, c.in, c.form, .{});
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "isNormalized and quickCheck" {
    try testing.expect(try ut.isNormalized(a, "é", .nfc, .{}));
    try testing.expect(!(try ut.isNormalized(a, "e\u{301}", .nfc, .{})));
    try testing.expect(try ut.isNormalized(a, "e\u{301}", .nfd, .{}));
    try testing.expect(!(try ut.isNormalized(a, "é", .nfd, .{})));
    try testing.expectEqual(ut.QuickCheck.maybe, try ut.quickCheck("e\u{301}", .nfc));
    try testing.expectEqual(ut.QuickCheck.no, try ut.quickCheck("\u{FB01}", .nfkc));
    try testing.expectEqual(ut.QuickCheck.yes, try ut.quickCheck("abc", .nfd));
    try testing.expectEqual(ut.QuickCheck.no, try ut.quickCheck("a\u{301}\u{323}", .nfd)); // out of order
    try testing.expect(try ut.isNormalized(a, "", .nfd, .{}));
    try testing.expectError(error.InvalidUtf8, ut.isNormalized(a, "\xFF", .nfc, .{}));
    try testing.expect(try ut.isNormalized(a, "a\xFF", .nfc, .{ .invalid_utf8 = .pass_through }));
}

test "unaccent" {
    try expectUnaccent("ŽLUŤOUČKÝ KŮŇ", "ZLUTOUCKY KUN");
    try expectUnaccent("příliš žluťoučký kůň úpěl ďábelské ódy", "prilis zlutoucky kun upel dabelske ody");
    try expectUnaccent("Łódź ø đ ħ ŧ ı ŀ ð Ð", "Lodz o d h t i l d D");
    try expectUnaccent("Straße æ Œ þ ﬁ", "Strasse ae OE th fi");
    try expectUnaccent("ά ё", "α е");
    try expectUnaccent("가", "가");
    const got = try ut.unaccent(a, "Straße æ", .{ .expand_ligatures = false });
    defer a.free(got);
    try testing.expectEqualStrings("Straße æ", got);
}

fn expectUnaccent(in: []const u8, want: []const u8) !void {
    const got = try ut.unaccent(a, in, .{});
    defer a.free(got);
    try testing.expectEqualStrings(want, got);
}

test "invalid UTF-8 under each policy" {
    try testing.expectError(error.InvalidUtf8, ut.lower(a, "A\xFFB", .{}));
    try expectPolicy(ut.lower, "A\xFFB", .replace, "a\u{FFFD}b");
    try expectPolicy(ut.lower, "A\xFFB", .pass_through, "a\xFFb");
    // one U+FFFD per maximal subpart
    try expectPolicy(ut.upper, "a\xE2\x82", .replace, "A\u{FFFD}");
    try expectPolicy(ut.upper, "\xED\xA0\x80", .replace, "\u{FFFD}\u{FFFD}\u{FFFD}");
    try expectPolicy(ut.upper, "\xF0\x9F\x98", .pass_through, "\xF0\x9F\x98");
    // an invalid stretch is neutral to the Final_Sigma context
    try expectPolicy(ut.lower, "Σ\xFFΑ", .pass_through, "σ\xFFα");
    try expectPolicy(ut.lower, "Α\xFFΣ", .pass_through, "α\xFFσ");
    // normalization: invalid bytes break the segment
    const n = try ut.normalize(a, "e\xFF\u{301}", .nfc, .{ .invalid_utf8 = .pass_through });
    defer a.free(n);
    try testing.expectEqualStrings("e\xFF\u{301}", n);
    try testing.expectError(error.InvalidUtf8, ut.normalize(a, "e\xFF", .nfc, .{}));
    const u = try ut.unaccent(a, "é\xFF", .{ .invalid_utf8 = .pass_through });
    defer a.free(u);
    try testing.expectEqualStrings("e\xFF", u);
    const r = try ut.unaccent(a, "é\xFF", .{ .invalid_utf8 = .replace });
    defer a.free(r);
    try testing.expectEqualStrings("e\u{FFFD}", r);
}

fn expectPolicy(comptime f: anytype, in: []const u8, p: ut.InvalidUtf8, want: []const u8) !void {
    const got = try f(a, in, .{ .invalid_utf8 = p });
    defer a.free(got);
    try testing.expectEqualStrings(want, got);
}

test "caps: max_output and max_segment are errors, never a panic" {
    try testing.expectError(error.TooLarge, ut.upper(a, "ßßßß", .{ .max_output = 7 }));
    const ok = try ut.upper(a, "ßßßß", .{ .max_output = 8 });
    a.free(ok);
    try testing.expectError(error.TooLarge, ut.normalize(a, "\u{FDFA}", .nfkd, .{ .max_output = 20 }));
    try testing.expectError(error.TooLarge, ut.normalize(a, "e\u{301}\u{301}\u{301}", .nfc, .{ .max_segment = 3 }));
    const seg = try ut.normalize(a, "e\u{301}\u{301}", .nfc, .{ .max_segment = 3 });
    a.free(seg);
    try testing.expectError(error.TooLarge, ut.unaccent(a, "éééé", .{ .max_output = 3 }));
    try testing.expectError(error.TooLarge, ut.lower(a, "abc", .{ .max_output = 2 }));
    const empty = try ut.lower(a, "", .{ .max_output = 0 });
    a.free(empty);
}

test "writer forms stream the same bytes and report writer failure" {
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try ut.upperTo(&w, "straße", .{});
    try testing.expectEqualStrings("STRASSE", w.buffered());
    var small: [3]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&small);
    try testing.expectError(error.WriteFailed, ut.lowerTo(&w2, "ABCDEFG", .{}));
    var w3 = std.Io.Writer.fixed(&buf);
    try ut.normalizeTo(a, &w3, "e\u{301}", .nfc, .{});
    try testing.expectEqualStrings("é", w3.buffered());
    var w4 = std.Io.Writer.fixed(&buf);
    try ut.unaccentTo(a, &w4, "é", .{});
    try testing.expectEqualStrings("e", w4.buffered());
}

test "long inputs cross the 256-byte emit block and the 64-byte direct-write threshold" {
    const n = 5000;
    const src = try a.alloc(u8, n * 2);
    defer a.free(src);
    for (0..n) |i| {
        src[2 * i] = 0xC3;
        src[2 * i + 1] = 0xA9; // é
    }
    const up = try ut.upper(a, src, .{});
    defer a.free(up);
    try testing.expectEqual(@as(usize, n * 2), up.len);
    try testing.expect(std.mem.startsWith(u8, up, "ÉÉÉ"));
    const dec = try ut.normalize(a, src, .nfd, .{});
    defer a.free(dec);
    try testing.expectEqual(@as(usize, n * 3), dec.len);
    const rec = try ut.normalize(a, dec, .nfc, .{});
    defer a.free(rec);
    try testing.expectEqualSlices(u8, src, rec);
}

test "classification matches the documented Python behaviour" {
    try testing.expect(try ut.isAlpha("Ž", .{}));
    try testing.expect(try ut.isDigit("²", .{}) and !(try ut.isDecimal("²", .{})));
    try testing.expect(try ut.isNumeric("三", .{}));
    try testing.expect(try ut.isSpace(" \t\u{3000}\u{85}", .{}));
    try testing.expect(!(try ut.isPrintable("a\u{A0}", .{})));
    try testing.expectEqual(ut.GeneralCategory.Mn, ut.generalCategory(0x301));
    try testing.expectEqualStrings("17.0.0", ut.unicode_version);
}

test "unaccent: titlecase digraphs keep both letters (UR-1)" {
    // Dž Lj Nj Dz (U+01C5 U+01C8 U+01CB U+01F2) are named "LATIN CAPITAL LETTER D WITH SMALL LETTER Z
    // WITH CARON" and have only a compatibility decomposition; the name rule used to fold them to
    // their first letter (D L N D), silently dropping the second letter. They stay as they are,
    // like their all-capital and all-small siblings.
    const digraphs = "\u{1C5}\u{1C8}\u{1CB}\u{1F2}";
    try expectUnaccent(digraphs, digraphs);
    try expectUnaccent("\u{1C4}\u{1C6}\u{1C7}\u{1C9}", "\u{1C4}\u{1C6}\u{1C7}\u{1C9}");
}

test "sweep: every per-code-point function is total on hostile u21 values (US-0)" {
    const hostile = [_]u21{ 0, 0x7F, 0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFFFD, 0xFFFF, 0x10FFFF, 0x110000, 0x1FFFFF };
    for (hostile) |cp| {
        // none of these may trap; the values are the documented defaults
        _ = ut.generalCategory(cp);
        _ = ut.combiningClass(cp);
        _ = ut.isAlphaCp(cp);
        _ = ut.isDecimalCp(cp);
        _ = ut.isDigitCp(cp);
        _ = ut.isNumericCp(cp);
        _ = ut.isAlnumCp(cp);
        _ = ut.isSpaceCp(cp);
        _ = ut.isUpperCp(cp);
        _ = ut.isLowerCp(cp);
        _ = ut.isTitleCp(cp);
        _ = ut.isCasedCp(cp);
        _ = ut.isCaseIgnorableCp(cp);
        _ = ut.isPrintableCp(cp);
        if (cp > 0x10FFFF) {
            try testing.expectEqual(ut.GeneralCategory.Cn, ut.generalCategory(cp));
            try testing.expectEqual(@as(u8, 0), ut.combiningClass(cp));
            try testing.expect(!ut.isPrintableCp(cp) and !ut.isAlnumCp(cp) and !ut.isSpaceCp(cp));
            try testing.expectEqual(cp, ut.toLowerCp(cp));
            try testing.expectEqual(cp, ut.toUpperCp(cp));
            try testing.expectEqual(cp, ut.toTitleCp(cp));
            try testing.expectEqual(cp, ut.foldCp(cp));
        }
        if (cp >= 0xD800 and cp < 0xE000) {
            try testing.expectEqual(ut.GeneralCategory.Cs, ut.generalCategory(cp));
            try testing.expectEqual(cp, ut.toLowerCp(cp));
            try testing.expectEqual(cp, ut.foldCp(cp));
        }
    }
}

test "sweep: zero caps and empty inputs are errors or empty results, never a trap (US-0)" {
    const o0: ut.Options = .{ .max_output = 0, .max_segment = 0 };
    for ([_][]const u8{ "", "a", "é", "e\u{301}", "\u{FDFA}" }) |s| {
        inline for (.{ ut.lower, ut.upper, ut.title, ut.capitalize, ut.swapcase, ut.casefold }) |f| {
            if (f(a, s, o0)) |r| a.free(r) else |e| try testing.expect(e == error.TooLarge);
        }
        inline for (.{ ut.Form.nfc, ut.Form.nfd, ut.Form.nfkc, ut.Form.nfkd }) |form| {
            if (ut.normalize(a, s, form, o0)) |r| a.free(r) else |e| try testing.expect(e == error.TooLarge);
            _ = ut.isNormalized(a, s, form, o0) catch |e| try testing.expect(e == error.TooLarge);
        }
        if (ut.unaccent(a, s, .{ .max_output = 0, .max_segment = 0 })) |r| a.free(r) else |e| try testing.expect(e == error.TooLarge);
    }
}
