// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the two parts `normative_test.zig` does
//! not reach: the label table (`Encoding.parse`) and which code points each
//! page encodes rather than turning into '?'. Oracle: golang.org/x/text
//! v0.42.0 (BSD-3-Clause) -- `htmlindex` for the WHATWG label table, `charmap`
//! strict encoders for encodability. The labels are ours
//! (`tools/go_oracle/main.go`); Go's answers are in `go_oracle_vectors.zig`.
//! No Go at test time; only Go's observable verdicts were recorded.
//!
//! Go is an oracle, not an authority: every deliberate difference is listed
//! with the judgement, and an unlisted one fails.

const std = @import("std");
const testing = std.testing;
const encoding = @import("root.zig");
const Encoding = encoding.Encoding;
const vectors = @import("go_oracle_vectors.zig");

/// The WHATWG name htmlindex reports, as this module's member.
fn fromWhatwg(name: []const u8) ?Encoding {
    for (std.enums.values(Encoding)) |e| {
        if (std.mem.eql(u8, e.canonicalName(), name)) return e;
    }
    return null;
}

const LabelDivergence = struct { label: []const u8, ours: ?Encoding, why: []const u8 };

const iso1 = "the iso-8859-1 family selects the true ISO/IEC 8859-1 page here, windows-1252 in WHATWG (the documented departure in `Encoding.parse`)";
const extra = "a spelling WHATWG does not list, accepted here for config files";

const label_divergences = [_]LabelDivergence{
    .{ .label = "cp819", .ours = .iso_8859_1, .why = iso1 ++ "; IANA registers CP819 and IBM819 as ISO_8859-1 aliases" },
    .{ .label = "csisolatin1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "ibm819", .ours = .iso_8859_1, .why = iso1 ++ "; IANA registers CP819 and IBM819 as ISO_8859-1 aliases" },
    .{ .label = "iso-8859-1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "iso-ir-100", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "iso8859-1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "iso88591", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "iso_8859-1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "iso_8859-1:1987", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "l1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "latin1", .ours = .iso_8859_1, .why = iso1 },
    .{ .label = "windows1250", .ours = .windows_1250, .why = extra },
    .{ .label = "win1250", .ours = .windows_1250, .why = extra },
    .{ .label = "windows1252", .ours = .windows_1252, .why = extra },
    .{ .label = "win1252", .ours = .windows_1252, .why = extra },
    .{ .label = "latin-1", .ours = .iso_8859_1, .why = extra },
    .{ .label = "latin-2", .ours = .iso_8859_2, .why = extra },
    .{ .label = "latin-9", .ours = .iso_8859_15, .why = extra },
    .{ .label = "latin9", .ours = .iso_8859_15, .why = extra },
    .{ .label = "iso-ir-203", .ours = .iso_8859_15, .why = extra ++ " (the ISO-IR registration of 8859-15)" },
    .{ .label = "\x0butf-8", .ours = null, .why = "WHATWG strips ASCII whitespace (TAB, LF, FF, CR, SPACE) around a label; VT is not one. Go's htmlindex trims it too" },
};

test "go oracle: Encoding.parse names what WHATWG's label table names" {
    var failed: usize = 0;
    var listed_used: [label_divergences.len]bool = @splat(false);
    for (vectors.labels) |l| {
        const ours = Encoding.parse(l.label);
        const go: ?Encoding = if (l.name) |n| fromWhatwg(n) else null;
        const div_index: ?usize = for (label_divergences, 0..) |d, i| {
            if (std.mem.eql(u8, d.label, l.label)) break i;
        } else null;
        if (div_index) |i| {
            listed_used[i] = true;
            if (ours != label_divergences[i].ours or go == ours) {
                std.debug.print("go oracle: label \"{s}\": listed divergence no longer holds (ours {?t}, go {?s})\n", .{ l.label, ours, l.name });
                failed += 1;
            }
            continue;
        }
        if (ours != go) {
            std.debug.print("go oracle: label \"{f}\": ours {?t}, go {?s}\n", .{ std.zig.fmtString(l.label), ours, l.name });
            failed += 1;
        }
    }
    for (label_divergences, listed_used) |d, used| if (!used) {
        std.debug.print("go oracle: label divergence \"{s}\" names no case\n", .{d.label});
        failed += 1;
    };
    if (failed != 0) return error.GoOracleDisagrees;
}

/// Code points WHATWG's index maps but Go's charmap encoder refuses: the C1
/// controls U+0080..U+009F in iso-8859-2 and iso-8859-15 (WHATWG's index
/// files map pointers 0..31 to them; Go's ISO8859_2 and ISO8859_15 leave them
/// out, though its ISO8859_1 keeps them). This module follows WHATWG
/// (`normative_test.zig` pins all 640 pairs against the WHATWG index files),
/// so encoding those code points gives the byte, not '?'. The windows-125x
/// slots Microsoft leaves undefined (0x81, 0x83, ...) are listed too, for a Go
/// that drops them; x/text v0.42.0 keeps them.
fn whatwgOnly(page: Encoding, cp: u21) bool {
    if (cp < 0x80 or cp > 0x9f) return false;
    const b: u8 = @intCast(cp);
    return switch (page) {
        .iso_8859_2, .iso_8859_15 => true,
        .windows_1250 => switch (b) {
            0x81, 0x83, 0x88, 0x90, 0x98 => true,
            else => false,
        },
        .windows_1252 => switch (b) {
            0x81, 0x8d, 0x8f, 0x90, 0x9d => true,
            else => false,
        },
        else => false,
    };
}

/// Every code point below U+3000 and in U+FFF0..U+FFFF, every 16th up to
/// U+FFF0, every 4096th in the astral planes; Go's pairs are all checked
/// besides, visited or not.
fn step(cp: u21) u21 {
    if (cp < 0x3000 or (cp >= 0xfff0 and cp < 0x10000)) return 1;
    if (cp < 0xfff0) return 0x10;
    return 0x1000;
}

fn visited(cp: u21) bool {
    if (cp < 0x3000 or (cp >= 0xfff0 and cp < 0x10000)) return true;
    if (cp < 0xfff0) return cp % 0x10 == 0;
    return cp % 0x1000 == 0;
}

fn checkPage(page: Encoding, pairs: []const vectors.Pair) !void {
    // ~16 000 one-character encodes per page: a reset fixed buffer, not the
    // leak-tracking testing allocator, or this test alone takes seconds.
    var fixed_buf: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&fixed_buf);
    const a = fixed.allocator();
    var failed: usize = 0;
    var buf: [4]u8 = undefined;
    var next: usize = 0; // pairs are in code point order
    var cp: u21 = 0x80;
    while (cp <= 0x10ffff) : (cp += step(cp)) {
        if (cp >= 0xd800 and cp <= 0xdfff) continue;
        while (next < pairs.len and pairs[next].cp < cp) next += 1;
        const want: u8 = if (next < pairs.len and pairs[next].cp == cp) pairs[next].byte else if (whatwgOnly(page, cp)) @intCast(cp) else '?';
        const n = std.unicode.utf8Encode(cp, &buf) catch unreachable;
        fixed.reset();
        const got = try encoding.encodeFromUtf8(a, buf[0..n], page);
        if (got.len != 1 or got[0] != want) {
            if (failed < 10) std.debug.print("go oracle: {t} U+{X:0>4}: ours {x}, want {x:0>2}\n", .{ page, cp, got, want });
            failed += 1;
        }
    }
    // Every Go pair must have been visited (the stride skips none of them).
    for (pairs) |p| {
        if (!visited(p.cp)) {
            const n = std.unicode.utf8Encode(p.cp, &buf) catch unreachable;
            fixed.reset();
            const got = try encoding.encodeFromUtf8(a, buf[0..n], page);
            if (got.len != 1 or got[0] != p.byte) {
                std.debug.print("go oracle: {t} U+{X:0>4}: ours {x}, want {x:0>2}\n", .{ page, p.cp, got, p.byte });
                failed += 1;
            }
        }
    }
    if (failed != 0) return error.GoOracleDisagrees;
}

test "go oracle: each page encodes exactly the code points charmap encodes, '?' for the rest" {
    try checkPage(.windows_1250, &vectors.encodable_windows_1250);
    try checkPage(.windows_1252, &vectors.encodable_windows_1252);
    try checkPage(.iso_8859_1, &vectors.encodable_iso_8859_1);
    try checkPage(.iso_8859_2, &vectors.encodable_iso_8859_2);
    try checkPage(.iso_8859_15, &vectors.encodable_iso_8859_15);
}
