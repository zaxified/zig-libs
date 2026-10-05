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
            var rule = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
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
                const dot = std.mem.indexOfScalar(u8, s, '.') orelse return s;
                return s[dot + 1 ..];
            }
            start = (std.mem.indexOfScalarPos(u8, host, start, '.') orelse break) + 1;
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
            if (std.mem.indexOfScalar(u8, s, '.')) |dot| {
                if (list.kinds(s[dot + 1 ..]).wildcard) return s;
            }
            start = (std.mem.indexOfScalarPos(u8, host, start, '.') orelse break) + 1;
        }
        // The implicit `*` rule.
        return host[if (std.mem.lastIndexOfScalar(u8, host, '.')) |d| d + 1 else 0..];
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
        return host[if (std.mem.lastIndexOfScalar(u8, head, '.')) |d| d + 1 else 0..];
    }
};

/// A name in the form rules are stored in: lowercase ASCII, each non-ASCII
/// label punycoded (`公司.cn` → `xn--55qx5d.cn`). NOT full IDNA: no UTS #46
/// mapping or validation -- right for the list's own (already normalized)
/// rules, which is what it is for.
pub fn toAscii(a: std.mem.Allocator, rule: []const u8) error{ OutOfMemory, Unencodable }![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var labels = std.mem.splitScalar(u8, rule, '.');
    var first = true;
    while (labels.next()) |label| {
        if (!first) try out.append(a, '.');
        first = false;
        const ascii = for (label) |c| {
            if (c >= 0x80) break false;
        } else true;
        if (ascii) {
            for (label) |c| try out.append(a, std.ascii.toLower(c));
        } else {
            try out.appendSlice(a, "xn--");
            try punycodeEncode(a, &out, label);
        }
    }
    return out.items;
}

// ── punycode (RFC 3492 §6.3), encoding only ─────────────────────────────────

const base = 36;
const tmin = 1;
const tmax = 26;
const skew = 38;
const damp = 700;

fn adapt(delta_in: u32, numpoints: u32, first: bool) u32 {
    var delta = if (first) delta_in / damp else delta_in / 2;
    delta += delta / numpoints;
    var k: u32 = 0;
    while (delta > ((base - tmin) * tmax) / 2) : (k += base) delta /= base - tmin;
    return k + (base - tmin + 1) * delta / (delta + skew);
}

fn digit(d: u32) u8 {
    return @intCast(if (d < 26) 'a' + d else '0' + (d - 26));
}

/// Append the punycode of the UTF-8 `label` (no `xn--`). Code points are
/// lowercased only when ASCII; the list's own labels are already
/// normalized.
fn punycodeEncode(a: std.mem.Allocator, out: *std.ArrayList(u8), label: []const u8) error{ OutOfMemory, Unencodable }!void {
    var cps_buf: [64]u21 = undefined;
    var n_cps: usize = 0;
    var it = (std.unicode.Utf8View.init(label) catch return error.Unencodable).iterator();
    while (it.nextCodepoint()) |cp| {
        if (n_cps == cps_buf.len) return error.Unencodable;
        cps_buf[n_cps] = if (cp < 0x80) std.ascii.toLower(@intCast(cp)) else cp;
        n_cps += 1;
    }
    const cps = cps_buf[0..n_cps];

    var basic: u32 = 0;
    for (cps) |cp| if (cp < 0x80) {
        try out.append(a, @intCast(cp));
        basic += 1;
    };
    if (basic > 0) try out.append(a, '-');

    var n: u32 = 128;
    var delta: u32 = 0;
    var bias: u32 = 72;
    var h = basic;
    while (h < cps.len) {
        var m: u32 = std.math.maxInt(u32);
        for (cps) |cp| if (cp >= n and cp < m) {
            m = cp;
        };
        delta = std.math.add(u32, delta, std.math.mul(u32, m - n, h + 1) catch return error.Unencodable) catch return error.Unencodable;
        n = m;
        for (cps) |cp| {
            if (cp < n) delta = std.math.add(u32, delta, 1) catch return error.Unencodable;
            if (cp == n) {
                var q = delta;
                var k: u32 = base;
                while (true) : (k += base) {
                    const t: u32 = if (k <= bias) tmin else if (k >= bias + tmax) tmax else k - bias;
                    if (q < t) break;
                    try out.append(a, digit(t + (q - t) % (base - t)));
                    q = (q - t) / (base - t);
                }
                try out.append(a, digit(q));
                bias = adapt(delta, h + 1, h == basic);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "punycode: RFC 3492 §7.1 samples and the IDN TLD forms the list uses" {
    const cases = [_][2][]const u8{
        // RFC 3492 §7.1 (A) Arabic (Egyptian), (B) Chinese (simplified).
        .{ "ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn" },
        .{ "他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye" },
        // (L) mixed ASCII and non-ASCII, lowercased.
        .{ "3年b組金八先生", "3b-ww4c5e180e575a65lsy2b" },
        .{ "公司", "55qx5d" },
        .{ "рф", "p1ai" },
        .{ "bücher", "bcher-kva" },
    };
    for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        try punycodeEncode(testing.allocator, &out, c[0]);
        try testing.expectEqualStrings(c[1], out.items);
    }
}

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
