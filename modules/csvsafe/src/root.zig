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
    .status = .extract, // seed: bxp-cli/src/pipeline.zig writeSafeValue (injection-guard slice only)
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
        // A '+' / '-' lead is a formula lead ONLY when what follows is not a
        // digit or the decimal separator; otherwise it is a signed number and
        // must pass through unguarded.
        '+', '-' => !nextIsNumeric(value, decimal_sep),
        else => false,
    };
}

fn nextIsNumeric(value: []const u8, decimal_sep: u8) bool {
    return value.len > 1 and (std.ascii.isDigit(value[1]) or value[1] == decimal_sep);
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

// ── Ported from bxp-cli/src/pipeline.zig writeSafeValue tests ──────────────

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
