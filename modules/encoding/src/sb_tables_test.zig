// SPDX-License-Identifier: MIT
//! Anchors the generated `sb_tables.zig` to the vendored WHATWG files
//! (src/testdata/index-*.txt, encodings.json): every decode entry equals its
//! index (0xFFFF where the index has no pointer), every encode table is exactly
//! the inverse of its decode table, and every label of encodings.json resolves.

const std = @import("std");
const testing = std.testing;
const sb = @import("sb_tables.zig");
const vectors = @import("normative_vectors.zig");

const encodings_json = @embedFile("testdata/encodings.json");

/// Vendored index per page; `null` = no WHATWG index (iso_8859_1, x_user_defined
/// and the DOS pages, see `otherTable`).
fn indexText(p: sb.Page) ?[]const u8 {
    return switch (p) {
        .ibm866 => @embedFile("testdata/index-ibm866.txt"),
        .iso_8859_2 => @embedFile("testdata/index-iso-8859-2.txt"),
        .iso_8859_3 => @embedFile("testdata/index-iso-8859-3.txt"),
        .iso_8859_4 => @embedFile("testdata/index-iso-8859-4.txt"),
        .iso_8859_5 => @embedFile("testdata/index-iso-8859-5.txt"),
        .iso_8859_6 => @embedFile("testdata/index-iso-8859-6.txt"),
        .iso_8859_7 => @embedFile("testdata/index-iso-8859-7.txt"),
        .iso_8859_8, .iso_8859_8_i => @embedFile("testdata/index-iso-8859-8.txt"),
        .iso_8859_10 => @embedFile("testdata/index-iso-8859-10.txt"),
        .iso_8859_13 => @embedFile("testdata/index-iso-8859-13.txt"),
        .iso_8859_14 => @embedFile("testdata/index-iso-8859-14.txt"),
        .iso_8859_15 => @embedFile("testdata/index-iso-8859-15.txt"),
        .iso_8859_16 => @embedFile("testdata/index-iso-8859-16.txt"),
        .koi8_r => @embedFile("testdata/index-koi8-r.txt"),
        .koi8_u => @embedFile("testdata/index-koi8-u.txt"),
        .macintosh => @embedFile("testdata/index-macintosh.txt"),
        .windows_874 => @embedFile("testdata/index-windows-874.txt"),
        .windows_1250 => @embedFile("testdata/index-windows-1250.txt"),
        .windows_1251 => @embedFile("testdata/index-windows-1251.txt"),
        .windows_1252 => @embedFile("testdata/index-windows-1252.txt"),
        .windows_1253 => @embedFile("testdata/index-windows-1253.txt"),
        .windows_1254 => @embedFile("testdata/index-windows-1254.txt"),
        .windows_1255 => @embedFile("testdata/index-windows-1255.txt"),
        .windows_1256 => @embedFile("testdata/index-windows-1256.txt"),
        .windows_1257 => @embedFile("testdata/index-windows-1257.txt"),
        .windows_1258 => @embedFile("testdata/index-windows-1258.txt"),
        .x_mac_cyrillic => @embedFile("testdata/index-x-mac-cyrillic.txt"),
        .iso_8859_1, .x_user_defined, .cp437, .cp850, .cp852 => null,
    };
}

/// The anchor of a page that has no WHATWG index file: Unicode.org's table
/// (8859-1.TXT, and Microsoft's MICSFT/PC CP437/850/852.TXT), or for
/// `x-user-defined` the Standard's definition (byte 0x80 + i is U+F780 + i).
fn otherTable(p: sb.Page) ![128]?u21 {
    var t: [128]?u21 = undefined;
    if (p == .x_user_defined) {
        for (&t, 0..) |*d, i| d.* = 0xF780 + @as(u21, @intCast(i));
        return t;
    }
    const text = switch (p) {
        .iso_8859_1 => @embedFile("testdata/8859-1.TXT"),
        .cp437 => @embedFile("testdata/CP437.TXT"),
        .cp850 => @embedFile("testdata/CP850.TXT"),
        .cp852 => @embedFile("testdata/CP852.TXT"),
        else => unreachable,
    };
    const r = try vectors.parseUnicodeOrgTable(text);
    for (&t, r.table) |*d, c| d.* = c;
    return t;
}

test "sb_tables: every decode table equals its vendored WHATWG index" {
    for (sb.page_info) |pi| {
        const expect: [128]?u21 = if (indexText(pi.page)) |text|
            (try vectors.parseWhatwgIndexSparse(text)).table
        else
            // iso_8859_1 is not a WHATWG encoding; anchor it to Unicode.org's
            // table (likewise the DOS pages, from Microsoft's files).
            try otherTable(pi.page);
        for (0..128) |i| {
            const want: u16 = if (expect[i]) |c| @intCast(c) else sb.undefined_cp;
            testing.expectEqual(want, pi.decode[i]) catch |e| {
                std.debug.print("page {s} byte 0x{X:0>2}\n", .{ pi.canonical_name, 0x80 + i });
                return e;
            };
        }
    }
}

test "sb_tables: encode table is exactly the inverse of decode" {
    for (sb.page_info, 0..) |pi, k| {
        try testing.expectEqual(k, @backingInt(pi.page));
        // Sorted strictly by cp (=> no duplicate code points).
        for (pi.encode[1..], 0..) |e, i| try testing.expect(pi.encode[i].cp < e.cp);
        // Every decode entry that has a pointer is found at the byte WHATWG's
        // encoder picks: the first pointer for the code point.
        var mapped: usize = 0;
        for (pi.decode, 0..) |cp, i| {
            if (cp == sb.undefined_cp) continue;
            mapped += 1;
            var first: usize = i;
            for (pi.decode[0..i], 0..) |c2, j| {
                if (c2 == cp) {
                    first = j;
                    break;
                }
            }
            var found: ?u8 = null;
            for (pi.encode) |e| {
                if (e.cp == cp) found = e.byte;
            }
            try testing.expectEqual(@as(?u8, @intCast(0x80 + first)), found);
        }
        // ... and nothing else is in it.
        var distinct: usize = 0;
        for (pi.decode, 0..) |cp, i| {
            if (cp == sb.undefined_cp) continue;
            if (std.mem.indexOfScalar(u16, pi.decode[0..i], cp) == null) distinct += 1;
        }
        try testing.expectEqual(distinct, pi.encode.len);
        try testing.expect(mapped >= pi.encode.len);
        for (pi.encode) |e| {
            try testing.expect(e.byte >= 0x80);
            try testing.expectEqual(e.cp, pi.decode[e.byte - 0x80]);
        }
    }
}

test "sb_tables: canonical names, shared 8-I tables, iso_8859_1 identity" {
    try testing.expectEqualStrings("windows-1250", sb.info(.windows_1250).canonical_name);
    try testing.expectEqualStrings("ISO-8859-8-I", sb.info(.iso_8859_8_i).canonical_name);
    try testing.expectEqualStrings("KOI8-R", sb.info(.koi8_r).canonical_name);
    try testing.expectEqualStrings("macintosh", sb.info(.macintosh).canonical_name);
    try testing.expectEqualStrings("x-mac-cyrillic", sb.info(.x_mac_cyrillic).canonical_name);
    try testing.expectEqualSlices(u16, &sb.iso_8859_8_decode, &sb.iso_8859_8_i_decode);
    for (sb.iso_8859_1_decode, 0..) |cp, i| try testing.expectEqual(@as(u16, @intCast(0x80 + i)), cp);
    // The non-WHATWG pages carry their IANA names.
    try testing.expectEqualStrings("IBM437", sb.info(.cp437).canonical_name);
    try testing.expectEqualStrings("IBM850", sb.info(.cp850).canonical_name);
    try testing.expectEqualStrings("IBM852", sb.info(.cp852).canonical_name);
    try testing.expectEqualStrings("x-user-defined", sb.info(.x_user_defined).canonical_name);
}

test "sb_tables: spot checks of the DOS pages and x-user-defined, from the code charts" {
    // CP437: 0x80 Ç, 0xE1 ß, 0xFF NBSP.
    try testing.expectEqual(@as(u16, 0x00C7), sb.cp437_decode[0x00]);
    try testing.expectEqual(@as(u16, 0x00DF), sb.cp437_decode[0xE1 - 0x80]);
    try testing.expectEqual(@as(u16, 0x00A0), sb.cp437_decode[0x7F]);
    // CP850: 0xD5 is dotless i; CP852: Czech letters.
    try testing.expectEqual(@as(u16, 0x0131), sb.cp850_decode[0xD5 - 0x80]);
    try testing.expectEqual(@as(u16, 0x0161), sb.cp852_decode[0xE7 - 0x80]); // š
    try testing.expectEqual(@as(u16, 0x0159), sb.cp852_decode[0xFD - 0x80]); // ř
    try testing.expectEqual(@as(u16, 0x011B), sb.cp852_decode[0xD8 - 0x80]); // ě
    // No byte of a DOS page is undefined, and each decodes to a distinct code point.
    for ([_]*const [128]u16{ &sb.cp437_decode, &sb.cp850_decode, &sb.cp852_decode }) |t| {
        for (t, 0..) |cp, i| {
            try testing.expect(cp != sb.undefined_cp);
            try testing.expect(std.mem.indexOfScalar(u16, t[0..i], cp) == null);
        }
    }
}

const Enc = struct { labels: []const []const u8, name: []const u8 };
const Group = struct { encodings: []const Enc, heading: []const u8 };

fn expectedTarget(name: []const u8, heading: []const u8, label: []const u8) !sb.Target {
    const eql = std.mem.eql;
    if (eql(u8, name, "UTF-8")) return .utf8;
    if (eql(u8, name, "UTF-16LE")) return .utf16le;
    if (eql(u8, name, "UTF-16BE")) return .utf16be;
    if (eql(u8, name, "replacement")) return .replacement;
    if (std.mem.indexOf(u8, heading, "multi-byte") != null) return .{ .unsupported = name };
    for (sb.page_info) |pi| {
        if (eql(u8, pi.canonical_name, name)) {
            // The module's departure: labels of the iso-8859-1 family.
            if (pi.page == .windows_1252) {
                for ([_][]const u8{ "iso-8859-1", "iso8859-1", "iso88591", "iso_8859-1", "iso_8859-1:1987", "iso-ir-100", "latin1", "l1", "csisolatin1", "cp819", "ibm819" }) |l| {
                    if (eql(u8, l, label)) return .{ .page = .iso_8859_1 };
                }
            }
            return .{ .page = pi.page };
        }
    }
    return error.UnknownEncoding;
}

test "sb_tables: every label of encodings.json resolves to its encoding" {
    var parsed = try std.json.parseFromSlice([]const Group, testing.allocator, encodings_json, .{});
    defer parsed.deinit();
    var total: usize = 0;
    for (parsed.value) |g| for (g.encodings) |e| for (e.labels) |l| {
        total += 1;
        const got = sb.lookupLabel(l) orelse {
            std.debug.print("label {s} unresolved\n", .{l});
            return error.LabelMissing;
        };
        try testing.expectEqualDeep(try expectedTarget(e.name, g.heading, l), got);
    };
    // The IANA labels of the (non-WHATWG) DOS pages.
    const dos = [_]struct { []const u8, sb.Page }{
        .{ "cp437", .cp437 }, .{ "ibm437", .cp437 }, .{ "437", .cp437 }, .{ "cspc8codepage437", .cp437 },
        .{ "cp850", .cp850 }, .{ "ibm850", .cp850 }, .{ "850", .cp850 }, .{ "cspc850multilingual", .cp850 },
        .{ "cp852", .cp852 }, .{ "ibm852", .cp852 }, .{ "852", .cp852 }, .{ "cspcp852", .cp852 },
    };
    for (dos) |d| try testing.expectEqualDeep(sb.Target{ .page = d[1] }, sb.lookupLabel(d[0]).?);
    // The table holds exactly the JSON's labels plus those, sorted, no duplicates.
    try testing.expectEqual(total + dos.len, sb.labels.len);
    for (sb.labels[1..], 0..) |l, i| {
        try testing.expect(std.mem.order(u8, sb.labels[i].label, l.label) == .lt);
    }
    try testing.expect(sb.lookupLabel("nonexistent") == null);
    try testing.expect(sb.lookupLabel("") == null);
}
