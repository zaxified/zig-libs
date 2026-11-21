// SPDX-License-Identifier: MIT
//! The `urlize` filter: `jinja2.utils.urlize` of Jinja2 3.1.6 (BSD-3-Clause)
//! ported without a regex engine. The input is the already HTML-escaped text;
//! it is split at whitespace and each word is tested as a URL, an e-mail
//! address or an address of one of `extra_schemes`.

const std = @import("std");
const value = @import("value.zig");

pub const Options = struct {
    trim_url_limit: ?usize = null,
    /// The `rel` attribute value (already sorted and joined), or "".
    rel: []const u8 = "",
    target: []const u8 = "",
    extra_schemes: []const []const u8 = &.{},
};

pub const Error = value.Error;

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c >= 0x80;
}

fn isSpace(c: u8) bool {
    return c == ' ' or (c >= 0x09 and c <= 0x0d) or (c >= 0x1c and c <= 0x1f);
}

fn isHostByte(c: u8) bool {
    return isWordByte(c) or c == '%' or c == '-';
}

/// `(?::[\d]{1,5})?(?:[/?#]\S*)?$` from `i`.
fn tailOk(s: []const u8, start: usize) bool {
    var i = start;
    if (i < s.len and s[i] == ':') {
        var j = i + 1;
        while (j < s.len and std.ascii.isDigit(s[j])) j += 1;
        if (j == i + 1 or j - (i + 1) > 5) return false;
        i = j;
    }
    if (i == s.len) return true;
    if (s[i] != '/' and s[i] != '?' and s[i] != '#') return false;
    for (s[i..]) |c| if (isSpace(c)) return false;
    return true;
}

fn eqlLower(a: []const u8, lower: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, lower);
}

/// The host run starting at `from`: `[\w%.-]+`.
fn hostRun(s: []const u8, from: usize) usize {
    var i = from;
    while (i < s.len and (isHostByte(s[i]) or s[i] == '.')) i += 1;
    return i;
}

fn tldOk(label: []const u8) bool {
    if (label.len >= 2 and label.len <= 63) {
        var all_alpha = true;
        for (label) |c| if (!std.ascii.isAlphabetic(c)) {
            all_alpha = false;
        };
        if (all_alpha) return true;
    }
    if (label.len >= 4 + 2 and label.len <= 4 + 59 and eqlLower(label[0..4], "xn--")) {
        for (label[4..]) |c| if (!isWordByte(c) and c != '%') return false;
        return true;
    }
    return false;
}

/// `(https?://|www\.)(([\w%-]+\.)+)?(tld)` + tail, from `from` (after the scheme).
fn schemeHost(s: []const u8, from: usize) bool {
    const e = hostRun(s, from);
    if (e == from) return false;
    const run = s[from..e];
    if (run[run.len - 1] == '.') return false;
    var it = std.mem.splitScalar(u8, run, '.');
    var last: []const u8 = "";
    while (it.next()) |label| {
        if (label.len == 0) return false;
        last = label;
    }
    return tldOk(last) and tailOk(s, e);
}

fn basicDomain(s: []const u8) bool {
    const e = hostRun(s, 0);
    if (e == 0) return false;
    const run = s[0..e];
    if (run[run.len - 1] == '.') return false;
    var it = std.mem.splitScalar(u8, run, '.');
    var n: usize = 0;
    var last: []const u8 = "";
    while (it.next()) |label| : (n += 1) {
        last = label;
        // Every label but the last: 2..63 host bytes (the last is the tld).
        if (it.peek() != null and (label.len < 2 or label.len > 63)) return false;
    }
    if (n < 2) return false;
    const tlds = [_][]const u8{ "com", "net", "int", "edu", "gov", "org", "info", "mil" };
    for (tlds) |t| if (eqlLower(last, t)) return tailOk(s, e);
    return false;
}

fn ipv4(s: []const u8, from: usize) ?usize {
    var i = from;
    for (0..4) |k| {
        if (k > 0) {
            if (i >= s.len or s[i] != '.') return null;
            i += 1;
        }
        const st = i;
        while (i < s.len and std.ascii.isDigit(s[i]) and i - st < 3) i += 1;
        if (i == st) return null;
    }
    return i;
}

/// `([\da-f]{0,4}:){n}` then `([\da-f]{0,4}:?){1,6}` then `]`, by backtracking.
fn v6Groups(s: []const u8, i: usize, colon_groups: usize, free_groups: usize) ?usize {
    if (colon_groups > 0) {
        var k: usize = 0;
        while (k <= 4 and i + k < s.len and std.ascii.isHex(s[i + k])) k += 1;
        // `{0,4}` hex digits then ':', trying the longest first.
        var h: usize = @min(k, 4) + 1;
        while (h > 0) {
            h -= 1;
            if (i + h < s.len and s[i + h] == ':') {
                if (v6Groups(s, i + h + 1, colon_groups - 1, free_groups)) |r| return r;
            }
        }
        return null;
    }
    // 1..6 free groups: each up to 4 hex and an optional ':'.
    if (free_groups == 0) return if (i < s.len and s[i] == ']') i + 1 else null;
    var k: usize = 0;
    while (k < 4 and i + k < s.len and std.ascii.isHex(s[i + k])) k += 1;
    var h: usize = k + 1;
    while (h > 0) {
        h -= 1;
        for ([_]usize{ 1, 0 }) |colon| {
            if (colon == 1 and !(i + h < s.len and s[i + h] == ':')) continue;
            const ni = i + h + colon;
            if (v6Groups(s, ni, 0, free_groups - 1)) |r| return r;
        }
    }
    return null;
}

fn ipv6(s: []const u8, from: usize) ?usize {
    if (from >= s.len or s[from] != '[') return null;
    // Between 1 and 6 free groups: try each count.
    for (1..7) |n| {
        if (v6Groups(s, from + 1, 2, n)) |r| return r;
    }
    return null;
}

fn startsWithIgnoreCase(s: []const u8, p: []const u8) bool {
    return s.len >= p.len and eqlLower(s[0..p.len], p);
}

/// `_http_re.match(s)` of the reference.
fn httpMatch(s: []const u8) bool {
    var scheme_end: ?usize = null;
    if (startsWithIgnoreCase(s, "https://")) scheme_end = 8 else if (startsWithIgnoreCase(s, "http://")) scheme_end = 7 else if (startsWithIgnoreCase(s, "www.")) scheme_end = 4;
    if (scheme_end) |se| if (schemeHost(s, se)) return true;
    if (basicDomain(s)) return true;
    if (startsWithIgnoreCase(s, "https://") or startsWithIgnoreCase(s, "http://")) {
        const se: usize = if (startsWithIgnoreCase(s, "https://")) 8 else 7;
        if (ipv4(s, se)) |e| if (tailOk(s, e)) return true;
        if (ipv6(s, se)) |e| if (tailOk(s, e)) return true;
    }
    return false;
}

/// `^\S+@\w[\w.-]*\.\w+$`.
fn emailMatch(s: []const u8) bool {
    for (s) |c| if (isSpace(c)) return false;
    var k: usize = 1;
    while (k < s.len) : (k += 1) {
        if (s[k] != '@') continue;
        const a = s[k + 1 ..];
        if (a.len == 0 or !isWordByte(a[0])) continue;
        const d = std.mem.findScalarLast(u8, a, '.') orelse continue;
        if (d < 1 or d + 1 >= a.len) continue;
        var ok = true;
        for (a[1..d]) |c| if (!isWordByte(c) and c != '.' and c != '-') {
            ok = false;
        };
        for (a[d + 1 ..]) |c| if (!isWordByte(c)) {
            ok = false;
        };
        if (ok) return true;
    }
    return false;
}

fn count(s: []const u8, needle: []const u8) usize {
    return std.mem.count(u8, s, needle);
}

fn trimmed(arena: std.mem.Allocator, x: []const u8, limit: ?usize) Error![]const u8 {
    const l = limit orelse return x;
    // The reference counts code points.
    var i: usize = 0;
    var n: usize = 0;
    while (i < x.len) {
        if (n == l) return std.mem.concat(arena, u8, &.{ x[0..i], "..." });
        const len = std.unicode.utf8ByteSequenceLength(x[i]) catch 1;
        i += @min(len, x.len - i);
        n += 1;
    }
    return x;
}

/// `escaped` is the escaped text (`str(escape(text))`).
pub fn urlize(arena: std.mem.Allocator, escaped: []const u8, o: Options) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const rel_attr = if (o.rel.len != 0) try std.fmt.allocPrint(arena, " rel=\"{s}\"", .{try value.escapeAlloc(arena, o.rel)}) else "";
    const target_attr = if (o.target.len != 0) try std.fmt.allocPrint(arena, " target=\"{s}\"", .{try value.escapeAlloc(arena, o.target)}) else "";
    var i: usize = 0;
    while (i < escaped.len) {
        // A run of whitespace, or a word.
        const ws = isSpace(escaped[i]);
        var j = i;
        while (j < escaped.len and isSpace(escaped[j]) == ws) j += 1;
        const word = escaped[i..j];
        i = j;
        if (ws) {
            try out.appendSlice(arena, word);
            continue;
        }
        var head: []const u8 = "";
        var middle: []const u8 = word;
        var tail: []const u8 = "";
        // `^([(<]|&lt;)+`
        var h: usize = 0;
        while (h < middle.len) {
            if (middle[h] == '(' or middle[h] == '<') h += 1 else if (std.mem.startsWith(u8, middle[h..], "&lt;")) h += 4 else break;
        }
        head = middle[0..h];
        middle = middle[h..];
        // `([)>.,\n]|&gt;)+$`
        var t = middle.len;
        while (t > 0) {
            if (middle[t - 1] == ')' or middle[t - 1] == '>' or middle[t - 1] == '.' or middle[t - 1] == ',' or middle[t - 1] == '\n') t -= 1 else if (t >= 4 and std.mem.eql(u8, middle[t - 4 .. t], "&gt;")) t -= 4 else break;
        }
        tail = middle[t..];
        middle = middle[0..t];
        // Balance parentheses and brackets by moving tail pieces back.
        const pairs = [_][2][]const u8{ .{ "(", ")" }, .{ "<", ">" }, .{ "&lt;", "&gt;" } };
        for (pairs) |pr| {
            const start_count = count(middle, pr[0]);
            if (start_count <= count(middle, pr[1])) continue;
            var moves = @min(start_count, count(tail, pr[1]));
            while (moves > 0) : (moves -= 1) {
                const at = std.mem.find(u8, tail, pr[1]).? + pr[1].len;
                middle = try std.mem.concat(arena, u8, &.{ middle, tail[0..at] });
                tail = tail[at..];
            }
        }
        if (httpMatch(middle)) {
            const shown = try trimmed(arena, middle, o.trim_url_limit);
            if (std.mem.startsWith(u8, middle, "https://") or std.mem.startsWith(u8, middle, "http://")) {
                middle = try std.fmt.allocPrint(arena, "<a href=\"{s}\"{s}{s}>{s}</a>", .{ middle, rel_attr, target_attr, shown });
            } else {
                middle = try std.fmt.allocPrint(arena, "<a href=\"https://{s}\"{s}{s}>{s}</a>", .{ middle, rel_attr, target_attr, shown });
            }
        } else if (std.mem.startsWith(u8, middle, "mailto:") and emailMatch(middle[7..])) {
            middle = try std.fmt.allocPrint(arena, "<a href=\"{s}\">{s}</a>", .{ middle, middle[7..] });
        } else if (std.mem.findScalar(u8, middle, '@') != null and !std.mem.startsWith(u8, middle, "www.") and
            !std.mem.startsWith(u8, middle, "@") and std.mem.findScalar(u8, middle, ':') == null and emailMatch(middle))
        {
            middle = try std.fmt.allocPrint(arena, "<a href=\"mailto:{s}\">{s}</a>", .{ middle, middle });
        } else {
            for (o.extra_schemes) |scheme| {
                if (!std.mem.eql(u8, middle, scheme) and std.mem.startsWith(u8, middle, scheme)) {
                    middle = try std.fmt.allocPrint(arena, "<a href=\"{s}\"{s}{s}>{s}</a>", .{ middle, rel_attr, target_attr, middle });
                    break;
                }
            }
        }
        try out.appendSlice(arena, head);
        try out.appendSlice(arena, middle);
        try out.appendSlice(arena, tail);
    }
    return out.items;
}
