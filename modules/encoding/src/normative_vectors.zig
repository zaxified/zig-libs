// SPDX-License-Identifier: MIT
//! Parsers for the vendored normative single-byte code-page tables (see
//! ../../NOTICE for provenance). Two source formats are vendored, because the
//! two publishers use different layouts:
//!
//!   - WHATWG `index-*.txt` (windows-1250, windows-1252, iso-8859-2,
//!     iso-8859-15): `<index>\t0x<CP>\t<comment>`, where `<index>` is
//!     byte - 0x80 (0..127).
//!   - Unicode.org `8859-1.TXT` (iso-8859-1 — WHATWG does not publish a
//!     separate index for this page because the "iso-8859-1" *label* is
//!     aliased to the windows-1252 *encoding* in the WHATWG algorithm; the
//!     module's `iso_8859_1` is the true, distinct ISO/IEC 8859-1 code page,
//!     so its normative anchor has to come from Unicode.org instead):
//!     `0x<byte>\t0x<CP>\t#\t<name>`, covering the full 0x00-0xFF range.
//!
//! Both parsers return a `[128]u21` keyed by `byte - 0x80` and the count of
//! data lines actually consumed in that range, so a caller can assert the
//! count is exactly 128 — a re-vendor that silently drops rows (truncated
//! download, a future edition of either table that introduces genuine
//! "undefined" holes) fails a loud, specific assertion instead of comparing
//! against a quietly-shrunken table.

const std = @import("std");

pub const ParseResult = struct {
    table: [128]u21,
    count: usize,
    /// The `# Identifier: <sha256>` the WHATWG file states about itself, when
    /// it carries one. Upstream computes it over the JSON serialisation of
    /// the codepoint list, so it is reproducible from the parsed table alone
    /// — see `identifierMatches`. Null for files that have no such line
    /// (the Unicode.org `8859-*.TXT` tables).
    identifier: ?[64]u8 = null,
};

/// Whether the file's own advertised `Identifier` matches the table that was
/// parsed out of it. Upstream's hash is
/// `sha256(json.dumps(codepoints))` with Python's `", "` separators, e.g.
/// `[8364, 129, 8218, ...]`, and `null` in place of an "undefined" hole.
///
/// This turns the vendored files from "we copied them once" into "this is
/// still upstream's data". Without it a hand-edited table entry paired with a
/// matching change in `root.zig` passes every test — inherent, an oracle
/// cannot catch a co-edited oracle — while leaving the file contradicting the
/// hash printed inside it.
pub fn identifierMatches(r: ParseResult) bool {
    const want = r.identifier orelse return true; // nothing claimed, nothing to check
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [16]u8 = undefined;
    h.update("[");
    for (r.table, 0..) |cp, i| {
        if (i != 0) h.update(", ");
        h.update(std.fmt.bufPrint(&buf, "{d}", .{cp}) catch unreachable);
    }
    h.update("]");
    var digest: [32]u8 = undefined;
    h.final(&digest);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&digest}) catch unreachable;
    return std.mem.eql(u8, &hex, &want);
}

/// Parse a WHATWG `index-*.txt` table. Lines are `<index>\t0x<CP>\t<comment>`;
/// comment-only (`#`) and blank lines are skipped. `<index>` is 0..127 and
/// maps to byte `0x80 + index`.
pub fn parseWhatwgIndex(text: []const u8) !ParseResult {
    var table: [128]u21 = undefined;
    var have: [128]bool = [_]bool{false} ** 128;
    var count: usize = 0;

    var identifier: ?[64]u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') {
            // The file states a hash of its own contents; keep it so the
            // caller can check the table against it.
            const marker = "# Identifier: ";
            if (std.mem.startsWith(u8, line, marker)) {
                const hex = std.mem.trim(u8, line[marker.len..], " \t");
                if (hex.len == 64) identifier = hex[0..64].*;
            }
            continue;
        }

        var fields = std.mem.splitScalar(u8, line, '\t');
        const idx_field = fields.next() orelse return error.MalformedLine;
        const cp_field = fields.next() orelse return error.MalformedLine;

        const idx_s = std.mem.trim(u8, idx_field, " \t");
        const idx = try std.fmt.parseInt(usize, idx_s, 10);
        if (idx >= 128) return error.IndexOutOfRange;

        const cp_s = std.mem.trim(u8, cp_field, " \t");
        if (!std.mem.startsWith(u8, cp_s, "0x")) return error.MalformedCodepoint;
        const cp = try std.fmt.parseInt(u21, cp_s[2..], 16);

        table[idx] = cp;
        have[idx] = true;
        count += 1;
    }
    for (have) |h| {
        if (!h) return error.MissingIndex;
    }
    return .{ .table = table, .count = count, .identifier = identifier };
}

/// Parse a Unicode.org `8859-*.TXT` table. Lines are
/// `0x<byte>\t0x<CP>\t#\t<name>` covering 0x00-0xFF; comment (`#`-leading)
/// and blank lines are skipped. Only rows with byte >= 0x80 are kept (the
/// module's tables never touch the ASCII half); `count` is the number of
/// such rows actually found.
pub fn parseUnicodeOrgTable(text: []const u8) !ParseResult {
    var table: [128]u21 = undefined;
    var have: [128]bool = [_]bool{false} ** 128;
    var count: usize = 0;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var fields = std.mem.splitScalar(u8, line, '\t');
        const byte_field = fields.next() orelse return error.MalformedLine;
        const cp_field = fields.next() orelse return error.MalformedLine;

        const byte_s = std.mem.trim(u8, byte_field, " \t");
        if (!std.mem.startsWith(u8, byte_s, "0x")) return error.MalformedByte;
        const byte = try std.fmt.parseInt(u16, byte_s[2..], 16);
        if (byte < 0x80) continue; // ASCII half — out of scope for the high table
        if (byte > 0xFF) return error.ByteOutOfRange;

        const cp_s = std.mem.trim(u8, cp_field, " \t");
        if (!std.mem.startsWith(u8, cp_s, "0x")) return error.MalformedCodepoint;
        const cp = try std.fmt.parseInt(u21, cp_s[2..], 16);

        const idx = byte - 0x80;
        table[idx] = cp;
        have[idx] = true;
        count += 1;
    }
    for (have) |h| {
        if (!h) return error.MissingIndex;
    }
    return .{ .table = table, .count = count };
}

const testing = std.testing;

test "parseWhatwgIndex: rejects a truncated table (count assertion fires)" {
    // Only 2 of 128 required indices present -> MissingIndex, not a
    // quietly-short table. Raw multiline (`\\`) string literals cannot
    // contain a literal tab byte (Zig source disallows raw tabs), so the
    // field separators are written as an explicit "\t" escape instead.
    const text = "# header comment\n" ++
        "  0\t0x0041\tA (LATIN CAPITAL LETTER A)\n" ++
        "  1\t0x0042\tB (LATIN CAPITAL LETTER B)\n";
    try testing.expectError(error.MissingIndex, parseWhatwgIndex(text));
}

test "parseUnicodeOrgTable: skips ASCII half and rejects truncated table" {
    const text = "# header comment\n" ++
        "0x00\t0x0000\t#\tNULL\n" ++
        "0x80\t0x0080\t#\t<control>\n";
    try testing.expectError(error.MissingIndex, parseUnicodeOrgTable(text));
}
