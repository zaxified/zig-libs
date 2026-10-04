// SPDX-License-Identifier: MIT
//! Deterministic-PRNG corrupt-input harness over `parse` — every doctype
//! policy, every input encoding — and the writer.
//!
//! Each input is a random document written with `Writer` (namespaces,
//! attributes and text full of characters that need escaping, CDATA,
//! comments, PIs), sometimes behind an internal subset declaring entities
//! that the body then references, sometimes transcoded to UTF-16 LE/BE or
//! ISO-8859-1; then damaged with aim at the structure: a byte at a `<`, `&`,
//! quote or `;`, an inserted entity reference, a copied run, truncation,
//! flips, or random bytes. Oracles:
//!
//!   - no crash, no hang, no leak (the driver's DebugAllocator);
//!   - an intact document parses, and its transcoded twin parses to the same
//!     infoset (the dump `core_test.zig` defines);
//!   - every accepted input survives the writer: write it, parse that, and
//!     the infoset is unchanged.
//!
//! Driver: `XML_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver).
//! 300 seeds also run in every ordinary test run.

const std = @import("std");
const testing = std.testing;
const xml = @import("root.zig");
const core = @import("core_test.zig");
const fuzz_driver = @import("testkit").fuzz.driver;
const hit = fuzz_driver.hit;

const texts = [_][]const u8{ "a", "<&>", "\"'", "\t\n", "\r\n", "]]>", "\u{e9}", "\u{6c34}", "\u{10151}", " " };
const names = [_][]const u8{ "a", "b", "p:a", "q:b", "x-y.z", "_" };

fn pick(comptime S: type, src: *S, comptime list: []const []const u8) []const u8 {
    return list[src.index(list.len)];
}

fn genText(comptime S: type, src: *S, buf: []u8) []const u8 {
    var n: usize = 0;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const t = pick(S, src, &texts);
        if (n + t.len > buf.len) break;
        @memcpy(buf[n..][0..t.len], t);
        n += t.len;
    }
    return buf[0..n];
}

fn genElement(comptime S: type, src: *S, w: *xml.Writer, depth: u8, latin1: bool) !void {
    const name = pick(S, src, &names);
    try w.startElement(name);
    // The prefixes the names use are declared on every element that might
    // need them; redeclaring is legal.
    try w.namespace("p", "urn:p");
    try w.namespace("q", if (src.value(bool)) "urn:q" else "urn:p2");
    if (src.value(bool)) try w.namespace("", "urn:d");
    var tb: [64]u8 = undefined;
    const attrs = [_][]const u8{ "x", "y", "p:x" };
    for (attrs[0..src.valueRangeAtMost(u8, 0, 3)]) |an| try w.attribute(an, if (latin1) "v<&\"" else genText(S, src, &tb));
    for (0..src.valueRangeAtMost(u8, 0, if (depth < 4) 4 else 1)) |_| {
        switch (src.valueRangeAtMost(u8, 0, 5)) {
            0, 1 => try w.text(if (latin1) "t&<\u{e9}" else genText(S, src, &tb)),
            2 => try w.cdata(if (latin1) "c]]>" else genText(S, src, &tb)),
            3 => try w.comment("c"),
            4 => try w.pi("t", "d"),
            else => if (depth < 4) try genElement(S, src, w, depth + 1, latin1),
        }
    }
    try w.endElement();
}

/// Offsets of bytes that matter to the grammar.
fn hotSpots(bytes: []const u8, out: []usize) usize {
    var n: usize = 0;
    for (bytes, 0..) |c, i| switch (c) {
        '<', '>', '&', ';', '"', '\'', '[', ']', '=' => {
            if (n == out.len) break;
            out[n] = i;
            n += 1;
        },
        else => {},
    };
    return n;
}

fn damage(comptime S: type, src: *S, base: []const u8, buf: []u8) []const u8 {
    var len = @min(base.len, buf.len);
    @memcpy(buf[0..len], base[0..len]);
    var spots: [512]usize = undefined;
    const ns = hotSpots(buf[0..len], &spots);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0, 1 => hit("intact"),
        2 => if (ns > 0) {
            const at = spots[src.index(ns)];
            buf[at] = "<>&;\"'[]=/!?x \x00"[src.index(15)];
            hit("dmg-syntax");
        },
        3 => if (ns > 0 and len + 8 <= buf.len) { // insert an entity reference
            const at = spots[src.index(ns)] + 1;
            const ref = ([_][]const u8{ "&e;", "&f;", "&lt;", "&#60;", "&#x1F;", "&loop;", "&ext;" })[src.index(7)];
            std.mem.copyBackwards(u8, buf[at + ref.len .. len + ref.len], buf[at..len]);
            @memcpy(buf[at..][0..ref.len], ref);
            len += ref.len;
            hit("dmg-ref");
        },
        4 => if (ns > 1) { // copy a run from one hot spot to another
            const from = spots[src.index(ns)];
            const to = spots[src.index(ns)];
            const n = @min(@as(usize, src.valueRangeAtMost(u8, 1, 32)), len - from, buf.len - to);
            std.mem.copyForwards(u8, buf[to..][0..n], base[from..][0..n]);
            len = @max(len, to + n);
        },
        5 => len = src.index(len + 1),
        6 => for (0..src.valueRangeAtMost(u8, 1, 4)) |_| {
            if (len > 0) buf[src.index(len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        else => {
            len = src.valueRangeAtMost(u8, 0, 128);
            src.bytes(buf[0..len]);
        },
    }
    return buf[0..len];
}

const subset = "<!DOCTYPE a [<!ENTITY e \"E&amp;&#9;\"><!ENTITY f \"&e;&e;\"><!ENTITY loop \"&loop;\">" ++
    "<!ENTITY ext SYSTEM \"x\"><!ATTLIST a x CDATA 'd'><!-- c -->]>";

const utf8_decl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const latin1_decl = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>";

fn transcode(enc: xml.SourceEncoding, utf8: []const u8, out: []u8) ?[]const u8 {
    var n: usize = 0;
    switch (enc) {
        .utf16le, .utf16be => {
            var units: [8192]u16 = undefined;
            const k = std.unicode.utf8ToUtf16Le(&units, utf8) catch return null;
            if (2 + 2 * k > out.len) return null;
            out[0..2].* = if (enc == .utf16le) .{ 0xFF, 0xFE } else .{ 0xFE, 0xFF };
            n = 2;
            for (units[0..k]) |u| {
                const v = std.mem.littleToNative(u16, u);
                std.mem.writeInt(u16, out[n..][0..2], v, if (enc == .utf16le) .little else .big);
                n += 2;
            }
        },
        .latin1 => {
            if (!std.mem.startsWith(u8, utf8, utf8_decl)) return null;
            @memcpy(out[0..latin1_decl.len], latin1_decl);
            n = latin1_decl.len;
            var view = std.unicode.Utf8View.init(utf8[utf8_decl.len..]) catch return null;
            var it = view.iterator();
            while (it.nextCodepoint()) |cp| {
                if (cp > 0xFF or n == out.len) return null;
                out[n] = @intCast(cp);
                n += 1;
            }
        },
        else => return null,
    }
    return out[0..n];
}

/// Parse; on success, the writer must reproduce the infoset.
fn check(gpa: std.mem.Allocator, input: []const u8, opts: xml.Options, must_parse: bool) !?[]u8 {
    var doc = xml.parse(gpa, input, opts) catch |e| {
        switch (e) {
            error.EntityLoop, error.EntityLimit, error.UnsupportedEntity => hit("entity-refused"),
            error.MaxDepthExceeded => hit("depth"),
            else => {},
        }
        if (must_parse) return error.IntactInputRefused;
        return null;
    };
    defer doc.deinit();
    hit("parsed");
    const before = try core.dumpDoc(gpa, &doc);
    errdefer gpa.free(before);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try xml.writeDocument(gpa, &aw.writer, &doc);
    var again = xml.parse(gpa, aw.written(), .{}) catch return error.WriterOutputRefused;
    defer again.deinit();
    const after = try core.dumpDoc(gpa, &again);
    defer gpa.free(after);
    if (!std.mem.eql(u8, before, after)) return error.WriterChangedInfoset;
    return before;
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const with_subset = src.value(bool);
    const enc: xml.SourceEncoding = switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => .utf16le,
        1 => .utf16be,
        2 => .latin1,
        else => .utf8,
    };
    // The UTF-8 original carries a UTF-8 declaration; `transcode` swaps it.
    if (enc == .latin1) try aw.writer.writeAll(utf8_decl);
    if (with_subset) try aw.writer.writeAll(subset);
    {
        var w: xml.Writer = .init(gpa, &aw.writer);
        defer w.deinit();
        try genElement(S, src, &w, 0, enc == .latin1);
        try w.end();
    }
    const base = aw.written();
    var buf: [8192]u8 = undefined;
    const input = damage(S, src, base, &buf);
    const intact = std.mem.eql(u8, input, base);
    const opts: xml.Options = .{
        .doctype = if (with_subset) ([_]xml.DoctypePolicy{ .ignore, .internal_entities })[src.index(2)] else .reject,
        .max_depth = ([_]usize{ 3, 256 })[src.index(2)],
        .max_entity_expansion = 64,
    };
    const ref_dump = try check(gpa, input, opts, intact and opts.max_depth == 256);
    defer if (ref_dump) |d| gpa.free(d);
    if (ref_dump != null and opts.doctype == .internal_entities and
        (std.mem.indexOf(u8, input, "&e;") != null or std.mem.indexOf(u8, input, "&f;") != null))
        hit("entity-expanded");
    // The same document in another encoding reads to the same infoset.
    if (intact and enc != .utf8) {
        var tbuf: [16384]u8 = undefined;
        if (transcode(enc, input, &tbuf)) |t| {
            hit("transcoded");
            const d2 = try check(gpa, t, opts, opts.max_depth == 256);
            defer if (d2) |d| gpa.free(d);
            if (ref_dump != null and d2 != null and !std.mem.eql(u8, ref_dump.?, d2.?)) return error.EncodingChangedInfoset;
        }
    }
}

test "fuzz driver: XML_FUZZ" {
    fuzz_driver.run(harness, .{ .prefix = "XML_FUZZ", .name = "xml" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz harness: 300 seeds in every test run" {
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
}
