// SPDX-License-Identifier: MIT

//! The Public Suffix List algorithm (https://publicsuffix.org/list/): which
//! part of a host name is a "public suffix" (`com`, `co.uk`, `github.io`)
//! under which anyone can register a name. A cookie jar asks it so that
//! `bank.co.uk` cannot set a cookie for all of `co.uk` (RFC 6265 §5.3 step 5).
//!
//! The list itself is NOT here: it is MPL-2.0 data that changes weekly, so
//! the caller loads it (`/usr/share/publicsuffix/public_suffix_list.dat` from
//! the `publicsuffix` package, or a copy it ships) and hands the text to
//! `parse`. ICANN and private sections are both used, as browsers do.
//! Unicode rules are stored punycoded (`公司.cn` → `xn--55qx5d.cn`), because
//! host names reach a client already in ASCII.
//!
//! Held to libpsl (MIT) by `tools/psl_oracle.py`: hermetically over our own
//! mini list (`psl_oracle.zig`), and over the full system list by `zig build
//! interop-cookies`.

const std = @import("std");
const unitext = @import("unitext");

pub const PublicSuffixList = struct {
    arena: std.heap.ArenaAllocator,
    /// Rule text (no `!`, no `*.`) → which kinds of rule name it.
    rules: std.StringHashMapUnmanaged(Kinds) = .empty,

    const Kinds = packed struct(u8) {
        /// `a.b`: `a.b` is a public suffix.
        normal: bool = false,
        /// `*.a.b`: every `x.a.b` is a public suffix.
        wildcard: bool = false,
        /// `!x.a.b`: `x.a.b` is NOT one, though a wildcard says so.
        exception: bool = false,
        _: u5 = 0,
    };

    pub const ParseError = error{OutOfMemory};

    /// Read the list's text (the `.dat` format: one rule per line, `//`
    /// comments, a rule ends at the first whitespace). A rule this parser
    /// cannot represent (invalid UTF-8, a label punycode cannot encode) is
    /// skipped, never guessed at.
    pub fn parse(gpa: std.mem.Allocator, text: []const u8) ParseError!PublicSuffixList {
        var list: PublicSuffixList = .{ .arena = .init(gpa) };
        errdefer list.arena.deinit();
        const a = list.arena.allocator();
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
            var rule = line[0 .. std.mem.findAny(u8, line, " \t") orelse line.len];
            var kind: Kinds = .{ .normal = true };
            if (rule[0] == '!') {
                rule = rule[1..];
                kind = .{ .exception = true };
            } else if (std.mem.startsWith(u8, rule, "*.")) {
                rule = rule[2..];
                kind = .{ .wildcard = true };
            }
            if (rule.len == 0) continue;
            const ascii = toAscii(a, rule) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Unencodable => continue,
            };
            const gop = try list.rules.getOrPut(a, ascii);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            const merged: u8 = @as(u8, @bitCast(gop.value_ptr.*)) | @as(u8, @bitCast(kind));
            gop.value_ptr.* = @bitCast(merged);
        }
        return list;
    }

    pub fn deinit(list: *PublicSuffixList) void {
        list.arena.deinit();
    }

    fn kinds(list: *const PublicSuffixList, name: []const u8) Kinds {
        return list.rules.get(name) orelse .{};
    }

    /// The public suffix of `host` (a slice of it): the labels the prevailing
    /// rule covers, `*` -- the last label -- when no rule matches. `host` must
    /// be lowercase ASCII without a trailing dot; an IP literal has no
    /// meaningful suffix and should not be asked.
    pub fn publicSuffix(list: *const PublicSuffixList, host: []const u8) []const u8 {
        // An exception rule prevails over every other match; the suffix is
        // then the exception minus its leftmost label.
        var start: usize = 0;
        while (true) {
            const s = host[start..];
            if (list.kinds(s).exception) {
                const dot = std.mem.findScalar(u8, s, '.') orelse return s;
                return s[dot + 1 ..];
            }
            start = (std.mem.findScalarPos(u8, host, start, '.') orelse break) + 1;
        }
        // Otherwise the longest match: scanning from the whole host down,
        // the first suffix that a normal rule names, or whose parent a
        // wildcard covers.
        start = 0;
        while (true) {
            const s = host[start..];
            // A wildcard's own base counts as a rule too (`*.kobe.jp` makes
            // `kobe.jp` a suffix): libpsl does so, and it is the stricter
            // reading. The real list names those bases anyway.
            const k = list.kinds(s);
            if (k.normal or k.wildcard) return s;
            if (std.mem.findScalar(u8, s, '.')) |dot| {
                if (list.kinds(s[dot + 1 ..]).wildcard) return s;
            }
            start = (std.mem.findScalarPos(u8, host, start, '.') orelse break) + 1;
        }
        // The implicit `*` rule.
        return host[if (std.mem.findScalarLast(u8, host, '.')) |d| d + 1 else 0..];
    }

    /// Whether `host` is itself a public suffix.
    pub fn isPublicSuffix(list: *const PublicSuffixList, host: []const u8) bool {
        return list.publicSuffix(host).len == host.len;
    }

    /// The public suffix plus one label (`www.bank.co.uk` → `bank.co.uk`),
    /// or null when `host` is a public suffix.
    pub fn registrableDomain(list: *const PublicSuffixList, host: []const u8) ?[]const u8 {
        const ps = list.publicSuffix(host);
        if (ps.len == host.len) return null;
        const head = host[0 .. host.len - ps.len - 1];
        return host[if (std.mem.findScalarLast(u8, head, '.')) |d| d + 1 else 0..];
    }
};

/// A name in the form rules are stored in: lowercase ASCII, each non-ASCII
/// label punycoded (`公司.cn` → `xn--55qx5d.cn`), by UTS #46 processing
/// (`unitext.idna.toAscii`, which maps and validates). A rule it refuses
/// (invalid UTF-8, an invalid label) is `error.Unencodable`.
pub fn toAscii(a: std.mem.Allocator, rule: []const u8) error{ OutOfMemory, Unencodable }![]const u8 {
    return unitext.idna.toAscii(a, rule, .{}) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUtf8, error.TooLarge, error.InvalidDomain => error.Unencodable,
    };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const sample =
    \\// comment
    \\com
    \\uk
    \\co.uk
    \\*.ck
    \\!www.ck
    \\jp
    \\*.kobe.jp
    \\!city.kobe.jp
    \\公司.cn
    \\cn
    \\github.io   trailing words are ignored
    \\
;

test "publicSuffix: normal, wildcard, exception, implicit *, IDN" {
    var list = try PublicSuffixList.parse(testing.allocator, sample);
    defer list.deinit();
    const cases = [_][3][]const u8{
        // host, public suffix, registrable domain ("" = none)
        .{ "example.com", "com", "example.com" },
        .{ "a.b.example.com", "com", "example.com" },
        .{ "com", "com", "" },
        .{ "bank.co.uk", "co.uk", "bank.co.uk" },
        .{ "co.uk", "co.uk", "" },
        .{ "foo.ck", "foo.ck", "" }, // *.ck
        .{ "ck", "ck", "" }, // the wildcard's base
        .{ "a.foo.ck", "foo.ck", "a.foo.ck" },
        .{ "www.ck", "ck", "www.ck" }, // !www.ck
        .{ "a.www.ck", "ck", "www.ck" },
        .{ "x.kobe.jp", "x.kobe.jp", "" },
        .{ "city.kobe.jp", "kobe.jp", "city.kobe.jp" },
        .{ "test", "test", "" }, // implicit *
        .{ "a.b.test", "test", "b.test" },
        .{ "shop.xn--55qx5d.cn", "xn--55qx5d.cn", "shop.xn--55qx5d.cn" },
        .{ "me.github.io", "github.io", "me.github.io" },
    };
    for (cases) |c| {
        try testing.expectEqualStrings(c[1], list.publicSuffix(c[0]));
        const want: ?[]const u8 = if (c[2].len == 0) null else c[2];
        if (want) |w| try testing.expectEqualStrings(w, list.registrableDomain(c[0]).?) else try testing.expect(list.registrableDomain(c[0]) == null);
        try testing.expectEqual(c[2].len == 0, list.isPublicSuffix(c[0]));
    }
}

test "parse: rules are lowercased, so a host asked in lowercase still matches" {
    var list = try PublicSuffixList.parse(testing.allocator, "UK\nCo.Uk\n");
    defer list.deinit();
    try testing.expectEqualStrings("co.uk", list.publicSuffix("bank.co.uk"));
}

test "parse: an empty list is the implicit * rule alone" {
    var list = try PublicSuffixList.parse(testing.allocator, "");
    defer list.deinit();
    try testing.expectEqualStrings("uk", list.publicSuffix("co.uk"));
    try testing.expectEqualStrings("co.uk", list.registrableDomain("a.co.uk").?);
}

test "parse: CRLF lists, a tab ends a rule, one name as normal and wildcard, single-label exception" {
    var crlf = try PublicSuffixList.parse(testing.allocator, "uk\r\nco.uk\r\n");
    defer crlf.deinit();
    try testing.expectEqualStrings("co.uk", crlf.publicSuffix("bank.co.uk"));

    var tab = try PublicSuffixList.parse(testing.allocator, "uk\nco.uk\tnote\n");
    defer tab.deinit();
    try testing.expectEqualStrings("co.uk", tab.publicSuffix("bank.co.uk"));

    // `ck` is a rule in its own right and the base of `*.ck`: both kinds kept.
    var both = try PublicSuffixList.parse(testing.allocator, "*.ck\nck\n");
    defer both.deinit();
    try testing.expectEqualStrings("foo.ck", both.publicSuffix("a.foo.ck"));
    try testing.expectEqualStrings("ck", both.publicSuffix("ck"));

    // An exception without a parent: the suffix is the exception itself, a
    // whole label of the host.
    var exc = try PublicSuffixList.parse(testing.allocator, "!example\n");
    defer exc.deinit();
    try testing.expectEqualStrings("example", exc.publicSuffix("a.example"));
}

test "parse: a rule that cannot be encoded is skipped, never fatal and never guessed; a long label is kept" {
    var long64: [128]u8 = undefined;
    var long65: [130]u8 = undefined;
    for (0..65) |i| {
        if (i < 64) @memcpy(long64[i * 2 ..][0..2], "\u{fc}");
        @memcpy(long65[i * 2 ..][0..2], "\u{fc}");
    }
    const text = try std.fmt.allocPrint(testing.allocator, "uk\n\x80.uk\n{s}.uk\n{s}.uk\ncom\n", .{ long65[0..130], long64[0..128] });
    defer testing.allocator.free(text);
    var list = try PublicSuffixList.parse(testing.allocator, text);
    defer list.deinit();
    // The invalid-UTF-8 rule is not in the list: `x.\x80.uk` is under `uk`.
    try testing.expectEqualStrings("uk", list.publicSuffix("x.\x80.uk"));
    try testing.expectEqualStrings("com", list.publicSuffix("a.com"));
    // 64 and 65 u-umlauts are `xn--tdaaa...` and both rules are there.
    const enc64 = "xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var host: [96]u8 = undefined;
    const h = try std.fmt.bufPrint(&host, "x.{s}.uk", .{enc64});
    try testing.expectEqualStrings(h[2..], list.publicSuffix(h));
    const enc65 = "xn--tdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const h65 = try std.fmt.bufPrint(&host, "x.{s}.uk", .{enc65});
    try testing.expectEqualStrings(h65[2..], list.publicSuffix(h65));
}

test "toAscii: DEL is an ASCII byte (lowercased in place), not a reason for an xn-- form" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("a\x7fb.c", try toAscii(arena.allocator(), "A\x7fB.c"));
}
