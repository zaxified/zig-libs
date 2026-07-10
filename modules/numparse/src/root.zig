// SPDX-License-Identifier: MIT
//! numparse — locale-aware grouped-number parsing (thousands + decimal
//! separators) into an exact `decimal`, with strict structural validation.
//!
//! v1 handles the western 3-digit grouping subset for two conventions:
//!   American  `thousands_sep = ','`, `decimal_sep = '.'`  → "1,234.56"
//!   European  `thousands_sep = '.'`, `decimal_sep = ','`  → "1.234,56"
//! The grammar is `[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?` with STRICT
//! structural validation (1–3 leading digits, then exact 3-digit groups, no
//! trailing junk). At least one thousands group is required, so plain
//! ungrouped numbers ("123", "1.5", "1,5") deliberately return null — those
//! are the caller's `decimal.Decimal.parse` responsibility. The strictness is
//! what prevents false positives on dates ("2025,06,01") or on American input
//! misread under European separators.
//!
//! Parsing normalizes the grouped string and hands it to
//! `decimal.Decimal.parse`.

const std = @import("std");
const Decimal = @import("decimal").Decimal;

pub const meta = .{
    .platform = .any, // pure logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared state, no allocation
    .model_after = "ICU NumberFormat parse (western 3-digit grouping subset)",
    .deps = .{"decimal"},
};

/// Parses a number in thousands-grouped format, generalised over both
/// American (`thousands_sep=','`, `decimal_sep='.'`) and European
/// (`thousands_sep='.'`, `decimal_sep=','`) conventions. Accepts:
///   `[-]?d{1,3}(<thousands>d{3})+(<decimal>d+)?`
/// Requires at least one thousands group — plain numbers without grouping
/// (`"123"`, `"1,5"`, `"1.5"`) are the caller's `Decimal.parse` responsibility.
/// Returns null if `s` does not match the pattern for the given separators.
///
/// The strict structural validation (1–3 leading digits, exactly 3 digits
/// per group, no trailing non-numeric characters) is intentional. It
/// prevents false positives on strings like `"2025,06,01"` (date
/// components) or American thousands input misread as a European number.
///
/// Examples:
///   parseGroupedNumber("1,234.56", ',', '.') → 1234.56  (American)
///   parseGroupedNumber("1.234,56", '.', ',') → 1234.56  (European)
///   parseGroupedNumber("-1.234.567,89", '.', ',') → -1234567.89
pub fn parseGroupedNumber(s: []const u8, thousands_sep: u8, decimal_sep: u8) ?Decimal {
    var i: usize = 0;
    if (i < s.len and s[i] == '-') i += 1;
    // 1–3 leading digits before the first thousands group
    const leading_start = i;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    const leading = i - leading_start;
    if (leading == 0 or leading > 3) return null;
    // At least one '<thousands>ddd' group required
    var groups: usize = 0;
    while (i < s.len and s[i] == thousands_sep) {
        if (s.len < i + 4) return null;
        if (!std.ascii.isDigit(s[i + 1]) or
            !std.ascii.isDigit(s[i + 2]) or
            !std.ascii.isDigit(s[i + 3])) return null;
        i += 4;
        groups += 1;
        // A digit immediately after the group means >3 digits between separators → invalid
        if (i < s.len and std.ascii.isDigit(s[i])) return null;
    }
    if (groups == 0) return null;
    // Optional decimal part
    if (i < s.len) {
        if (s[i] != decimal_sep) return null;
        i += 1;
        if (i >= s.len or !std.ascii.isDigit(s[i])) return null;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    }
    if (i != s.len) return null;
    // Strip thousands and rewrite the decimal char to '.' into a stack
    // buffer, then re-parse with the fixed-point decimal parser. The 40-byte
    // buffer covers any value the fixed-point range can hold (≈27 integer
    // digits + dot + 12 fractional), far beyond what 3+N*4 digits can express.
    var buf: [40]u8 = undefined;
    var bi: usize = 0;
    for (s) |c| {
        if (c == thousands_sep) continue;
        if (bi >= buf.len) return null;
        buf[bi] = if (c == decimal_sep) '.' else c;
        bi += 1;
    }
    // Seed returned `?Decimal` (Decimal.parse was optional); the extracted
    // `decimal` module returns an error union, so a malformed/out-of-range
    // normalized string maps back to null.
    return Decimal.parse(buf[0..bi]) catch null;
}

// ---------------------------------------------------------------------------
// Tests — `Decimal.parse` returns an error union, so results are unwrapped
// with `try Decimal.parse(...)`.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseGroupedNumber: American format" {
    try testing.expectEqual((try Decimal.parse("1234.56")).raw, parseGroupedNumber("1,234.56", ',', '.').?.raw);
    try testing.expectEqual((try Decimal.parse("-1234567")).raw, parseGroupedNumber("-1,234,567", ',', '.').?.raw);
    try testing.expectEqual((try Decimal.parse("1000")).raw, parseGroupedNumber("1,000", ',', '.').?.raw);
    try testing.expect(parseGroupedNumber("123", ',', '.') == null);
    try testing.expect(parseGroupedNumber("1,5", ',', '.') == null);
    try testing.expect(parseGroupedNumber("1,2345", ',', '.') == null);
}

test "parseGroupedNumber: European format" {
    try testing.expectEqual((try Decimal.parse("1234.56")).raw, parseGroupedNumber("1.234,56", '.', ',').?.raw);
    try testing.expectEqual((try Decimal.parse("-1234567.89")).raw, parseGroupedNumber("-1.234.567,89", '.', ',').?.raw);
    try testing.expectEqual((try Decimal.parse("1234")).raw, parseGroupedNumber("1.234", '.', ',').?.raw);
    try testing.expect(parseGroupedNumber("1.5", '.', ',') == null);
    try testing.expect(parseGroupedNumber("1.234.5", '.', ',') == null);
    try testing.expect(parseGroupedNumber("1,234.56", '.', ',') == null);
}
