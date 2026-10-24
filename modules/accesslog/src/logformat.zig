// SPDX-License-Identifier: MIT

//! logformat.zig -- `LogFormat`, a user-defined line layout in the style of
//! Apache `mod_log_config` (httpd 2.4 documentation).
//!
//! ```zig
//! const clf = comptime accesslog.LogFormat.comptimeParse("%h %l %u %t \"%r\" %>s %b");
//! try clf.write(entry, w); // one LF-terminated line
//! const f = try accesslog.LogFormat.parse(operator_supplied_template);
//! ```
//!
//! Parsed once into a fixed array of items (no allocator, `max_items` = 64);
//! `write` is a loop over them. Literal text is **borrowed from the template**
//! (it must outlive the `LogFormat`; a comptime template always does).
//!
//! ## Directives
//!
//! | directive | prints |
//! |---|---|
//! | `%h` | remote host (`Entry.remote_addr` without its port, IPv6 bare); `-` when null |
//! | `%l` | always `-` (RFC 1413 identity) |
//! | `%u` | `Entry.user`, delimiter-escaped exactly as in Combined; `-` when null |
//! | `%t` | `[` + `Entry.time_formatted` (or the raw `timestamp_ns`) + `]` -- brackets included, as in Apache |
//! | `%r` | request line `METHOD TARGET PROTOCOL` |
//! | `%s`, `%>s` | status (there is only one status, so both are the same) |
//! | `%b` | response bytes; `-` when unknown (`0` prints `0`, as `writeCombined` does -- Apache itself prints `-` for 0) |
//! | `%B` | response bytes; `0` when unknown |
//! | `%D` | latency in microseconds (truncated); `-` when not timed |
//! | `%T` | latency in whole seconds (truncated); `-` when not timed |
//! | `%m` | method |
//! | `%U` | target up to (not including) the first `?` |
//! | `%q` | the rest of the target from the first `?` (query with the `?`), empty when none |
//! | `%H` | protocol |
//! | `%%` | a literal `%` |
//! | `%{Referer}i`, `%{User-Agent}i` | that request header (name case-insensitive); `-` when absent |
//! | `%{key}x` | the `Entry.extra` field `key` (first one with that exact key); `-` when absent |
//!
//! `%{Name}i` is limited to `Referer` and `User-Agent` because `Entry` carries
//! no other request header (`error.UnsupportedHeader`); `%{Name}o` is rejected
//! at parse (`error.ResponseHeadersUnavailable`) because `Entry` carries no
//! response headers. `%<s`, status conditions (`%200h`), `%{format}t` and
//! every other directive are `error.UnknownDirective`.
//!
//! ## Safety
//!
//! The template is trusted configuration; the values are not. Every value goes
//! through the Combined escaper (`root.writeClfEscaped`: `"` and `\` backslash
//! escaped, control bytes and `]` as `\xHH`), so no value can add a line or
//! break out of a quote the template put around it. The template itself may
//! not contain a control byte (`error.ControlByteInLiteral`): the one `\n` of
//! a record is the terminator `write` appends. A template that does not quote
//! a field (`%r` bare) is the operator's choice; the escaper still hex-escapes
//! `"` and `\` there, but cannot protect a delimiter the template invented
//! (a space) -- quote what can hold spaces, as Apache's own formats do.

const std = @import("std");
const root = @import("root.zig");
const Entry = root.Entry;

pub const LogFormat = struct {
    /// Most items (literal runs + directives) one template may have.
    pub const max_items = 64;

    pub const Error = error{
        /// A `%` followed by something that is not a supported directive.
        UnknownDirective,
        /// `%` at the end, `%>` without `s`, or `%{name` without `}x`-style tail.
        UnterminatedDirective,
        /// `%{}i`, `%{}x`.
        EmptyName,
        /// `%{Name}i` for a header `Entry` does not carry.
        UnsupportedHeader,
        /// `%{Name}o`: `Entry` has no response headers.
        ResponseHeadersUnavailable,
        /// `%{key}x` with a key that is not a valid `Entry.extra` key.
        BadExtraKey,
        /// A control byte (0x00-0x1F, 0x7F) in the template's literal text.
        ControlByteInLiteral,
        /// More than `max_items` items.
        TooManyItems,
    };

    const Kind = enum {
        literal,
        host,
        logname,
        user,
        time,
        request_line,
        status,
        bytes_dash,
        bytes_zero,
        micros,
        seconds,
        referer,
        user_agent,
        method,
        path,
        query,
        protocol,
        extra,
    };

    const Item = struct {
        kind: Kind,
        /// `.literal`: the text; `.extra`: the key; unused otherwise.
        text: []const u8 = "",
    };

    items: [max_items]Item = undefined,
    len: usize = 0,

    /// Parse `template`. See the module doc for the directive set.
    pub fn parse(template: []const u8) Error!LogFormat {
        var f: LogFormat = .{};
        var lit_start: usize = 0;
        var i: usize = 0;
        while (i < template.len) {
            if (template[i] != '%') {
                if (template[i] < 0x20 or template[i] == 0x7F) return error.ControlByteInLiteral;
                i += 1;
                continue;
            }
            if (i > lit_start) try f.push(.{ .kind = .literal, .text = template[lit_start..i] });
            i += 1;
            if (i >= template.len) return error.UnterminatedDirective;
            const c = template[i];
            i += 1;
            const item: Item = switch (c) {
                '%' => .{ .kind = .literal, .text = "%" },
                'h' => .{ .kind = .host },
                'l' => .{ .kind = .logname },
                'u' => .{ .kind = .user },
                't' => .{ .kind = .time },
                'r' => .{ .kind = .request_line },
                's' => .{ .kind = .status },
                'b' => .{ .kind = .bytes_dash },
                'B' => .{ .kind = .bytes_zero },
                'D' => .{ .kind = .micros },
                'T' => .{ .kind = .seconds },
                'm' => .{ .kind = .method },
                'U' => .{ .kind = .path },
                'q' => .{ .kind = .query },
                'H' => .{ .kind = .protocol },
                '>' => blk: {
                    if (i >= template.len) return error.UnterminatedDirective;
                    if (template[i] != 's') return error.UnknownDirective;
                    i += 1;
                    break :blk .{ .kind = .status };
                },
                '{' => blk: {
                    const close = std.mem.findScalarPos(u8, template, i, '}') orelse
                        return error.UnterminatedDirective;
                    const name = template[i..close];
                    if (close + 1 >= template.len) return error.UnterminatedDirective;
                    const letter = template[close + 1];
                    i = close + 2;
                    if (name.len == 0) return error.EmptyName;
                    break :blk switch (letter) {
                        'i' => if (std.ascii.eqlIgnoreCase(name, "Referer"))
                            Item{ .kind = .referer }
                        else if (std.ascii.eqlIgnoreCase(name, "User-Agent"))
                            Item{ .kind = .user_agent }
                        else
                            return error.UnsupportedHeader,
                        'o' => return error.ResponseHeadersUnavailable,
                        'x' => if (root.isValidExtraKey(name))
                            Item{ .kind = .extra, .text = name }
                        else
                            return error.BadExtraKey,
                        else => return error.UnknownDirective,
                    };
                },
                else => return error.UnknownDirective,
            };
            try f.push(item);
            lit_start = i;
        }
        if (i > lit_start) try f.push(.{ .kind = .literal, .text = template[lit_start..i] });
        return f;
    }

    /// `parse` at compile time; a bad template is a compile error carrying the
    /// parse error's name.
    pub fn comptimeParse(comptime template: []const u8) LogFormat {
        return comptime parse(template) catch |e| @compileError("accesslog.LogFormat: " ++ @errorName(e) ++ " in template \"" ++ template ++ "\"");
    }

    fn push(f: *LogFormat, item: Item) Error!void {
        if (f.len == max_items) return error.TooManyItems;
        f.items[f.len] = item;
        f.len += 1;
    }

    /// Render `entry` as one line (the template, then `\n`).
    pub fn write(f: *const LogFormat, entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (f.items[0..f.len]) |item| switch (item.kind) {
            .literal => try w.writeAll(item.text),
            .host => if (entry.remote_addr) |a| try root.writeClfEscaped(w, root.hostOnly(a)) else try w.writeByte('-'),
            .logname => try w.writeByte('-'),
            .user => try root.writeClfUser(w, entry.user),
            .time => {
                try w.writeByte('[');
                if (entry.time_formatted) |t| try root.writeClfEscaped(w, t) else try w.print("{d}", .{entry.timestamp_ns});
                try w.writeByte(']');
            },
            .request_line => {
                try root.writeClfEscaped(w, entry.method);
                try w.writeByte(' ');
                try root.writeClfEscaped(w, entry.target);
                try w.writeByte(' ');
                try root.writeClfEscaped(w, entry.protocol);
            },
            .status => try w.print("{d}", .{entry.status}),
            .bytes_dash => if (entry.response_bytes) |b| try w.print("{d}", .{b}) else try w.writeByte('-'),
            .bytes_zero => try w.print("{d}", .{entry.response_bytes orelse 0}),
            .micros => if (entry.latency_ns) |n| try w.print("{d}", .{n / std.time.ns_per_us}) else try w.writeByte('-'),
            .seconds => if (entry.latency_ns) |n| try w.print("{d}", .{n / std.time.ns_per_s}) else try w.writeByte('-'),
            .referer => try writeOpt(w, entry.referer),
            .user_agent => try writeOpt(w, entry.user_agent),
            .method => try root.writeClfEscaped(w, entry.method),
            .path => {
                const q = std.mem.findScalar(u8, entry.target, '?') orelse entry.target.len;
                try root.writeClfEscaped(w, entry.target[0..q]);
            },
            .query => {
                const q = std.mem.findScalar(u8, entry.target, '?') orelse entry.target.len;
                try root.writeClfEscaped(w, entry.target[q..]);
            },
            .protocol => try root.writeClfEscaped(w, entry.protocol),
            .extra => try writeOpt(w, root.extraValue(entry.extra, item.text)),
        };
        try w.writeByte('\n');
    }
};

fn writeOpt(w: *std.Io.Writer, v: ?[]const u8) std.Io.Writer.Error!void {
    if (v) |s| try root.writeClfEscaped(w, s) else try w.writeByte('-');
}

// ── tests: the parser. Equivalence with writeCombined is in root.zig ─────────

const testing = std.testing;

fn render(f: *const LogFormat, e: Entry, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try f.write(e, &w);
    return w.buffered();
}

const sample: Entry = .{
    .timestamp_ns = 7,
    .time_formatted = "22/Jul/2026:10:00:00 +0000",
    .remote_addr = "[2001:db8::1]:443",
    .method = "POST",
    .target = "/a/b?x=1&y=2",
    .protocol = "HTTP/1.0",
    .status = 201,
    .response_bytes = 0,
    .latency_ns = 2_345_678_901,
    .user_agent = "ua",
    .extra = &.{.{ .key = "tenant", .value = "acme" }},
};

test "LogFormat: every directive, exact bytes" {
    var buf: [512]u8 = undefined;
    const all = comptime LogFormat.comptimeParse("h=%h l=%l u=%u t=%t r=%r s=%s S=%>s b=%b B=%B D=%D T=%T m=%m U=%U q=%q H=%H %% UA=%{user-agent}i R=%{REFERER}i x=%{tenant}x n=%{nope}x");
    try testing.expectEqualStrings(
        "h=2001:db8::1 l=- u=- t=[22/Jul/2026:10:00:00 +0000] r=POST /a/b?x=1&y=2 HTTP/1.0 s=201 S=201 b=0 B=0 D=2345678 T=2 m=POST U=/a/b q=?x=1&y=2 H=HTTP/1.0 % UA=ua R=- x=acme n=-\n",
        try render(&all, sample, &buf),
    );
    // Unknown latency / bytes / no query / no time_formatted.
    var e = sample;
    e.latency_ns = null;
    e.response_bytes = null;
    e.target = "/p";
    e.time_formatted = null;
    const f = try LogFormat.parse("%D|%T|%b|%B|%q|%U|%t");
    try testing.expectEqualStrings("-|-|-|0||/p|[7]\n", try render(&f, e, &buf));
}

test "LogFormat: parse errors are typed, one per class" {
    const E = LogFormat.Error;
    try testing.expectError(E.UnknownDirective, LogFormat.parse("%Z"));
    try testing.expectError(E.UnknownDirective, LogFormat.parse("%<s"));
    try testing.expectError(E.UnknownDirective, LogFormat.parse("%200h"));
    try testing.expectError(E.UnknownDirective, LogFormat.parse("%>x"));
    try testing.expectError(E.UnknownDirective, LogFormat.parse("%{%d}t"));
    try testing.expectError(E.UnterminatedDirective, LogFormat.parse("abc%"));
    try testing.expectError(E.UnterminatedDirective, LogFormat.parse("%>"));
    try testing.expectError(E.UnterminatedDirective, LogFormat.parse("%{Referer"));
    try testing.expectError(E.UnterminatedDirective, LogFormat.parse("%{Referer}"));
    try testing.expectError(E.EmptyName, LogFormat.parse("%{}i"));
    try testing.expectError(E.UnsupportedHeader, LogFormat.parse("%{Cookie}i"));
    try testing.expectError(E.ResponseHeadersUnavailable, LogFormat.parse("%{Content-Type}o"));
    try testing.expectError(E.BadExtraKey, LogFormat.parse("%{a b}x"));
    try testing.expectError(E.BadExtraKey, LogFormat.parse("%{a\"b}x"));
    try testing.expectError(E.ControlByteInLiteral, LogFormat.parse("a\nb"));
    try testing.expectError(E.ControlByteInLiteral, LogFormat.parse("a\x7fb"));
    try testing.expectError(E.TooManyItems, LogFormat.parse(strRepeat("%h", LogFormat.max_items + 1)));
    // Exactly max_items is fine (positive control for the bound).
    _ = try LogFormat.parse(strRepeat("%h", LogFormat.max_items));
}

test "LogFormat: a crafted value cannot add a line or leave its quotes" {
    var buf: [512]u8 = undefined;
    const f = comptime LogFormat.comptimeParse("\"%{Referer}i\" \"%{key}x\" \"%U\"");
    var e = sample;
    e.referer = "r\" 200\r\nforged";
    e.target = "/p\n?q";
    e.extra = &.{.{ .key = "key", .value = "v\"\x00" }};
    const out = try render(&f, e, &buf);
    try testing.expectEqualStrings("\"r\\\" 200\\x0d\\x0aforged\" \"v\\\"\\x00\" \"/p\\x0a\"\n", out);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
