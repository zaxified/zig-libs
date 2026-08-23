// SPDX-License-Identifier: MIT

//! What a CSV export path does with `csvsafe`: guard the OWASP CSV-formula-
//! injection payload shapes (the ones a real spreadsheet — Excel, LibreOffice
//! Calc, Google Sheets — treats as a formula/DDE command when a cell's first
//! byte is `=`, `+`, `-`, `@`, or a leading tab/CR) before they reach a
//! CSV writer, while letting a legitimate signed number or phone number
//! through unguarded.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const csvsafe = @import("csvsafe");

// The OWASP CSV Injection payload shapes: a formula lead, a DDE-style
// command via '+'/'-'/'@', and the two non-printable leads (tab, CR) a
// spreadsheet also treats as significant.
const formula_payloads = [_][]const u8{
    "=cmd|'/c calc'!A1",
    "+cmd|'/c calc'!A1",
    "-2+3+cmd|'/c calc'!A1",
    "@SUM(1+9)*cmd|'/c calc'!A1",
    "\t=1+1",
    "\r=1+1",
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    for (formula_payloads) |p| {
        const out = try csvsafe.guard(gpa, p);
        defer gpa.free(out);
        std.debug.assert(out[0] == csvsafe.guard_char);
        std.debug.assert(std.mem.eql(u8, out[1..], p));
    }
    std.debug.print("{d} OWASP formula-injection payload shapes: all guarded with a leading '\n", .{formula_payloads.len});

    // The signed-number exception: a leading '+'/'-' followed by digits,
    // separators, or spaces all the way through is provably not a formula
    // (a phone number or a plain signed amount) and must pass unguarded.
    const safe_numbers = [_][]const u8{ "-12.34", "+5", "+420 555 0101" };
    for (safe_numbers) |v| {
        const out = try csvsafe.guard(gpa, v);
        defer gpa.free(out);
        std.debug.assert(std.mem.eql(u8, out, v)); // unguarded, byte-identical
    }
    std.debug.print("signed numbers / phone number: pass unguarded (not treated as formulas)\n", .{});

    // `decimal_sep` only gates the byte immediately AFTER the sign, not the
    // whole tail: the module's rationale (a run of digits/'.'/','/space
    // "cannot contain a formula operator, function name or cell reference,
    // so it is provably not executable") treats both '.' and ',' as
    // numeric punctuation in the tail unconditionally, regardless of which
    // separator the caller passed. So a *digit-led* comma-decimal number
    // like "-12,34" already passes unguarded under the DEFAULT ('.')
    // separator — the `*Sep` variant is not required for this shape:
    std.debug.assert(!csvsafe.needsGuard("-12,34"));
    const digit_led = try csvsafe.guard(gpa, "-12,34");
    defer gpa.free(digit_led);
    std.debug.assert(std.mem.eql(u8, digit_led, "-12,34"));
    std.debug.print("\"-12,34\" passes unguarded even under the DEFAULT '.' separator (tail scan is separator-agnostic)\n", .{});

    // Where `*Sep` actually changes the outcome: a *decimal-led* form with
    // no integer digit before the separator ("-,5" = -0.5 under a
    // comma-decimal locale). Here `decimal_sep` gates the byte right after
    // the sign, so the two variants disagree:
    std.debug.assert(csvsafe.needsGuard("-,5")); // default '.': guarded (',' != '.')
    std.debug.assert(!csvsafe.needsGuardSep("-,5", ',')); // sep=',': recognized as -0.5, unguarded
    std.debug.print("\"-,5\": guarded under default '.', unguarded under guardSep(.., ',') — this is what *Sep is actually for\n", .{});

    // Streaming form: writeSafe into a caller-owned buffer (a CSV writer's
    // real path), no allocation.
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try csvsafe.writeSafe(&w, "=HYPERLINK(\"http://evil\")");
    std.debug.assert(w.buffered()[0] == '\'');
    std.debug.print("writeSafe (allocation-free path): {s}\n", .{w.buffered()});

    // A plain cell needs no guard at all.
    var buf2: [64]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&buf2);
    try csvsafe.writeSafe(&w2, "Alice");
    std.debug.assert(std.mem.eql(u8, w2.buffered(), "Alice"));
    std.debug.print("plain cell \"Alice\": passes through unguarded\n", .{});
}
