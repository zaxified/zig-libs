// SPDX-License-Identifier: MIT
//! Exhaustive cross-check of the five code-page high-tables (0x80-0xFF)
//! against externally-vendored normative sources (see ../../NOTICE for
//! provenance: WHATWG `index-*.txt` for windows-1250/1252, iso-8859-2/15;
//! Unicode.org `8859-1.TXT` for iso-8859-1).
//!
//! Round-tripping our own table against itself proves nothing. This drives
//! `decodeToUtf8`/`encodeFromUtf8` — the PUBLIC API, not the internal table —
//! across every one of the 128 high bytes per page (640 byte/codepoint pairs
//! total), comparing against the independently-sourced table on both sides
//! (decode AND encode), never against our own tables.
//!
//! `normative_vectors.zig`'s parsers reject anything short of exactly 128
//! entries, so a future re-vendor that silently truncates a source file
//! fails loudly here rather than comparing against a quietly-shrunken table.

const std = @import("std");
const testing = std.testing;
const encoding = @import("root.zig");
const Encoding = encoding.Encoding;
const vec = @import("normative_vectors.zig");

const whatwg_1250 = @embedFile("testdata/index-windows-1250.txt");
const whatwg_1252 = @embedFile("testdata/index-windows-1252.txt");
const whatwg_iso2 = @embedFile("testdata/index-iso-8859-2.txt");
const whatwg_iso15 = @embedFile("testdata/index-iso-8859-15.txt");
const unicode_iso1 = @embedFile("testdata/8859-1.TXT");

/// Drive both directions of the public API for every one of the 128 high
/// bytes against `table` (byte `0x80 + i` -> normative codepoint `table[i]`).
fn checkPage(enc: Encoding, table: [128]u21) !void {
    var checked: usize = 0;
    for (table, 0..) |cp, i| {
        const byte: u8 = @intCast(0x80 + i);

        var want_utf8: [4]u8 = undefined;
        const want_len = try std.unicode.utf8Encode(cp, &want_utf8);

        // decode: byte -> the normative codepoint's UTF-8.
        const got = try encoding.decodeToUtf8(testing.allocator, &.{byte}, enc);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, want_utf8[0..want_len], got);

        // encode: the normative codepoint's UTF-8 -> byte (the reverse
        // direction, checked against the SAME external source, not a
        // self-round-trip of our own table).
        const back = try encoding.encodeFromUtf8(testing.allocator, want_utf8[0..want_len], enc);
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, &.{byte}, back);

        checked += 1;
    }
    try testing.expectEqual(@as(usize, 128), checked);
}

test "windows-1252: exhaustive decode+encode vs WHATWG index-windows-1252.txt" {
    const r = try vec.parseWhatwgIndex(whatwg_1252);
    try testing.expectEqual(@as(usize, 128), r.count);
    try checkPage(.windows_1252, r.table);
}

test "windows-1250: exhaustive decode+encode vs WHATWG index-windows-1250.txt" {
    const r = try vec.parseWhatwgIndex(whatwg_1250);
    try testing.expectEqual(@as(usize, 128), r.count);
    try checkPage(.windows_1250, r.table);
}

test "iso-8859-2: exhaustive decode+encode vs WHATWG index-iso-8859-2.txt" {
    const r = try vec.parseWhatwgIndex(whatwg_iso2);
    try testing.expectEqual(@as(usize, 128), r.count);
    try checkPage(.iso_8859_2, r.table);
}

test "iso-8859-15: exhaustive decode+encode vs WHATWG index-iso-8859-15.txt" {
    const r = try vec.parseWhatwgIndex(whatwg_iso15);
    try testing.expectEqual(@as(usize, 128), r.count);
    try checkPage(.iso_8859_15, r.table);
}

test "iso-8859-1: exhaustive decode+encode vs Unicode.org 8859-1.TXT" {
    // WHATWG has no separate index for this page: its label "iso-8859-1" is
    // aliased to the windows-1252 *encoding* in the WHATWG algorithm, but
    // this module's `iso_8859_1` is the true, distinct ISO/IEC 8859-1 code
    // page (pure Latin-1 identity high half), so Unicode.org is the correct
    // normative source here, not WHATWG.
    const r = try vec.parseUnicodeOrgTable(unicode_iso1);
    try testing.expectEqual(@as(usize, 128), r.count);
    try checkPage(.iso_8859_1, r.table);
}

test "normative tables: all five pages define every one of the 128 high bytes (no holes)" {
    // Unlike some WHATWG single-byte pages (e.g. windows-1253/1257 have
    // `null` slots for genuinely undefined bytes), every one of the five
    // European pages this module implements maps all 128 high bytes to
    // *something* in its normative source -- verified here across all five,
    // not assumed. That means there is no "undefined byte" decode path to
    // anchor for these particular pages: `decodeToUtf8`'s "unmappable
    // codepoint -> verbatim byte" fallback (root.zig) and `Encoding.parse`'s
    // rejection of unlisted codepoints are defensive code for a case that,
    // for these five sources, provably never occurs. If a future re-vendor
    // of any of the five ever introduces a real hole, the per-page
    // `count == 128` assertions above -- and this one -- go red immediately.
    const whatwg_pages = [_][]const u8{ whatwg_1250, whatwg_1252, whatwg_iso2, whatwg_iso15 };
    for (whatwg_pages) |p| {
        const r = try vec.parseWhatwgIndex(p);
        try testing.expectEqual(@as(usize, 128), r.count);
    }
    const r1 = try vec.parseUnicodeOrgTable(unicode_iso1);
    try testing.expectEqual(@as(usize, 128), r1.count);
}
