// SPDX-License-Identifier: MIT

//! What a consumer of `unitext` does: it builds an accent- and case-insensitive
//! search key for names typed by users (normalize, unaccent, casefold), checks a
//! field with the Python-`str` classification, streams a case mapping into a
//! writer without allocating, and decides what happens to ill-formed bytes.
//! Checks only what the module documents, not table internals.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const ut = @import("unitext");

/// A check that survives every optimize mode (the examples are RUN in the
/// lane's mode; a debug-only assert would vanish in ReleaseFast).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

/// The consumer: a search key under which "Příliš ŽLUŤOUČKÝ" and
/// "prilis zlutoucky" (typed without diacritics) are the same name.
fn searchKey(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    // Text from a form may come decomposed (macOS) or composed: NFC first.
    const nfc = try ut.normalize(gpa, name, .nfc, .{ .invalid_utf8 = .replace });
    defer gpa.free(nfc);
    const plain = try ut.unaccent(gpa, nfc, .{});
    defer gpa.free(plain);
    return ut.casefold(gpa, plain, .{});
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer must(da.deinit() == .ok, @src());
    const gpa = da.allocator();

    // 1. Search keys: composed, decomposed and accent-less spellings meet.
    const a = try searchKey(gpa, "Příliš ŽLUŤOUČKÝ kůň");
    defer gpa.free(a);
    const b = try searchKey(gpa, "Pr\u{030C}i\u{0301}lis\u{030C} z\u{030C}lutoucky KUN");
    defer gpa.free(b);
    const c = try searchKey(gpa, "prilis zlutoucky kun");
    defer gpa.free(c);
    must(std.mem.eql(u8, a, c), @src());
    must(std.mem.eql(u8, b, c), @src());

    // 2. Full case mapping: one letter can become two.
    const up = try ut.upper(gpa, "straße", .{});
    defer gpa.free(up);
    must(std.mem.eql(u8, up, "STRASSE"), @src());

    // 3. Validation of a field: letters of any script, not just ASCII.
    must(try ut.isAlpha("Łódź", .{}), @src());
    must(!try ut.isAlpha("R2-D2", .{}), @src());
    must(try ut.isDecimal("٣٤", .{}), @src()); // Arabic-Indic digits
    must(try ut.isNormalized(gpa, a, .nfc, .{}), @src());

    // 4. Streaming into a fixed buffer: no allocation for the result.
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try ut.lowerTo(&w, "ΟΔΥΣΣΕΥΣ", .{}); // the last sigma is final
    must(std.mem.eql(u8, w.buffered(), "οδυσσευς"), @src());

    // 5. Ill-formed input: refused by default, repaired or copied on request.
    const bad = "ab\xffc";
    must(ut.lower(gpa, bad, .{}) == error.InvalidUtf8, @src());
    const repaired = try ut.lower(gpa, bad, .{ .invalid_utf8 = .replace });
    defer gpa.free(repaired);
    must(std.mem.eql(u8, repaired, "ab\u{FFFD}c"), @src());
}
