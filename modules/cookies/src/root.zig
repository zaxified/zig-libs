// SPDX-License-Identifier: MIT

//! cookies — HTTP cookies (RFC 6265): the `Cookie` request-header parser
//! (`parse`/`find`), the `Set-Cookie` response builder (`SetCookie`, injection-
//! guarded, SameSite=None⇒Secure), and thin `http` helpers (`get`/`set`).
//! Allocation-free; parsed pairs borrow the header.
//!
//! ```zig
//! var it = cookies.parse(req.header("cookie") orelse "");
//! while (it.next()) |c| { … c.name … c.value … }
//! const sid = cookies.find(req.header("cookie") orelse "", "session") orelse return;
//! ```

const std = @import("std");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // no state; results borrow the input header
    .model_after = "RFC 6265 (HTTP State Management Mechanism)",
    .deps = .{"http"},
};

/// One cookie name/value pair from a `Cookie` request header. Both slices
/// borrow the parsed header, so it must outlive the `Cookie`.
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
};

/// Iterates the pairs in a `Cookie` request-header value (RFC 6265 §4.2 /
/// §5.4: `name1=value1; name2=value2`). Allocation-free.
pub const Iterator = struct {
    rest: []const u8,

    pub fn next(it: *Iterator) ?Cookie {
        const ows = " \t";
        while (it.rest.len != 0) {
            // Take up to the next `;` → one segment; advance past it.
            const seg_end = std.mem.indexOfScalar(u8, it.rest, ';') orelse it.rest.len;
            const segment = it.rest[0..seg_end];
            it.rest = if (seg_end == it.rest.len) "" else it.rest[seg_end + 1 ..];

            // Split on the FIRST `=`; no `=` → valueless cookie.
            var name: []const u8 = undefined;
            var value: []const u8 = undefined;
            if (std.mem.indexOfScalar(u8, segment, '=')) |eq| {
                name = std.mem.trim(u8, segment[0..eq], ows);
                value = std.mem.trim(u8, segment[eq + 1 ..], ows);
            } else {
                name = std.mem.trim(u8, segment, ows);
                value = "";
            }

            // Empty name (also covers empty/OWS-only segments) → skip.
            if (name.len == 0) continue;

            // Strip a matching pair of surrounding DQUOTEs (RFC 6265 §4.1.1).
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"')
                value = value[1 .. value.len - 1];

            return .{ .name = name, .value = value };
        }
        return null;
    }
};

/// Start iterating a `Cookie` header value.
pub fn parse(header: []const u8) Iterator {
    return .{ .rest = header };
}

/// The value of the first cookie named `name` (case-sensitive per RFC 6265
/// §5.4), or null. Convenience over `parse`.
pub fn find(header: []const u8, name: []const u8) ?[]const u8 {
    var it = parse(header);
    while (it.next()) |c| {
        if (std.mem.eql(u8, c.name, name)) return c.value;
    }
    return null;
}

// ── P2: Set-Cookie building (RFC 6265 §4.1) ─────────────────────────────────

/// The `SameSite` attribute (RFC 6265bis) controlling cross-site sending.
pub const SameSite = enum {
    /// Sent with same-site requests and top-level cross-site navigations.
    lax,
    /// Sent only with same-site requests (strongest CSRF protection).
    strict,
    /// Sent with all requests — **requires `Secure`** (modern browsers reject
    /// `SameSite=None` without it).
    none,

    fn token(s: SameSite) []const u8 {
        return switch (s) {
            .lax => "Lax",
            .strict => "Strict",
            .none => "None",
        };
    }
};

pub const WriteError = error{
    /// A name/value/attribute byte would break the header (control char, or a
    /// separator like `;`/`,`/`"`/`\`/SP the grammar forbids) — refused so a
    /// reflected value can't inject a Set-Cookie attribute or a second header.
    InvalidCookie,
    /// `same_site == .none` without `secure` — browsers would drop it.
    InsecureSameSiteNone,
    /// The destination buffer is too small (`bufPrint`).
    BufferTooSmall,
};

/// A `Set-Cookie` response header value (RFC 6265 §4.1). Serialize with `write`
/// / `bufPrint`. Attribute fields are omitted when null/false. `expires` is a
/// **pre-formatted** IMF-fixdate string (this module is std-only and dateless —
/// format it with e.g. `http.Server.formatHttpDate`); prefer `max_age`.
pub const SetCookie = struct {
    name: []const u8,
    value: []const u8,
    path: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    /// `Max-Age` in seconds (0 or negative ⇒ expire now). Preferred over
    /// `expires`.
    max_age: ?i64 = null,
    /// Pre-formatted `Expires` date (rfc1123-date / IMF-fixdate); null ⇒ omit.
    expires: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,

    /// Serialize the header VALUE (not the `Set-Cookie:` prefix) into `w`.
    /// Validates everything FIRST — on `WriteError` nothing has been written,
    /// so a rejected cookie never leaves a half-written header. Failures of
    /// the caller's writer propagate as `std.Io.Writer.Error` (WriteFailed).
    pub fn write(sc: SetCookie, w: *std.Io.Writer) (WriteError || std.Io.Writer.Error)!void {
        // 1. Validate before writing any bytes.
        if (sc.name.len == 0) return error.InvalidCookie;
        for (sc.name) |c| if (!isTokenChar(c)) return error.InvalidCookie;
        // Do NOT auto-quote a bad value — reject it (injection guard).
        for (sc.value) |c| if (!isCookieOctet(c)) return error.InvalidCookie;
        if (sc.path) |p| for (p) |c| if (!isAttrOctet(c)) return error.InvalidCookie;
        if (sc.domain) |d| for (d) |c| if (!isAttrOctet(c)) return error.InvalidCookie;
        if (sc.same_site) |ss| {
            if (ss == .none and !sc.secure) return error.InsecureSameSiteNone;
        }

        // 2. Write: name=value, then attributes in RFC 6265 §4.1 order.
        try w.writeAll(sc.name);
        try w.writeByte('=');
        try w.writeAll(sc.value);
        if (sc.path) |p| {
            try w.writeAll("; Path=");
            try w.writeAll(p);
        }
        if (sc.domain) |d| {
            try w.writeAll("; Domain=");
            try w.writeAll(d);
        }
        if (sc.max_age) |a| try w.print("; Max-Age={d}", .{a});
        if (sc.expires) |e| {
            try w.writeAll("; Expires=");
            try w.writeAll(e);
        }
        if (sc.secure) try w.writeAll("; Secure");
        if (sc.http_only) try w.writeAll("; HttpOnly");
        if (sc.same_site) |ss| {
            try w.writeAll("; SameSite=");
            try w.writeAll(ss.token());
        }
    }

    /// Serialize into `buf`, returning the used prefix (BufferTooSmall if it
    /// doesn't fit). Convenience over `write` with a fixed writer.
    pub fn bufPrint(sc: SetCookie, buf: []u8) WriteError![]const u8 {
        var fw = std.Io.Writer.fixed(buf);
        sc.write(&fw) catch |e| switch (e) {
            error.WriteFailed => return error.BufferTooSmall,
            else => |x| return x,
        };
        return fw.buffered();
    }

    /// RFC 6265 §4.1.1 cookie-name token char (RFC 2616 token): no CTL
    /// (0x00-0x1F, 0x7F), no SP/HTAB, no separators.
    fn isTokenChar(c: u8) bool {
        if (c <= 0x20 or c >= 0x7f) return false; // CTL, SP, HTAB, non-ASCII
        return switch (c) {
            '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}' => false,
            else => true,
        };
    }

    /// RFC 6265 §4.1.1 cookie-octet: 0x21-0x7E except `"` `,` `;` `\`.
    fn isCookieOctet(c: u8) bool {
        if (c < 0x21 or c > 0x7e) return false; // CTL, SP, DEL, non-ASCII
        return switch (c) {
            '"', ',', ';', '\\' => false,
            else => true,
        };
    }

    /// Bare Path/Domain attribute-value check: no CTL and no `;` (these feed
    /// the attribute verbatim).
    fn isAttrOctet(c: u8) bool {
        return c >= 0x20 and c != 0x7f and c != ';';
    }
};

// ── P3: http integration ────────────────────────────────────────────────────

pub const SetError = WriteError || http.Server.ResponseWriter.SetHeaderError;

/// Read the value of cookie `name` from a request's `Cookie` header, or null.
/// Convenience for `find(req.header("cookie") orelse "", name)`.
pub fn get(req: *const http.Server.Request, name: []const u8) ?[]const u8 {
    return find(req.header("cookie") orelse "", name);
}

/// Serialize `sc` and set it as the response's `Set-Cookie` header. `buf` holds
/// the header value and **must outlive the response flush** — the response
/// writer stores the header slice without copying, and for a buffered response
/// the head (this value included) is not serialized until the serving loop
/// calls `end()`, **after the handler returns**. A buffer on the handler's own
/// frame is therefore NOT safe (it is popped before the head is written); use
/// storage that outlives the handler dispatch — request-lifetime memory reached
/// via `StreamOptions.context`, or a caller buffer owned by the serving loop.
/// Rejects an invalid cookie (`WriteError`) before touching the response.
///
/// NOTE: the server emits at most **one** `Set-Cookie` per response —
/// `setHeader` replaces by name — so a second `set` overwrites the first.
/// Setting multiple cookies in one response is not supported through this path.
pub fn set(res: *http.Server.ResponseWriter, sc: SetCookie, buf: []u8) SetError!void {
    const value = try sc.bufPrint(buf);
    try res.setHeader("Set-Cookie", value);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectPair(it: *Iterator, name: []const u8, value: []const u8) !void {
    const c = it.next() orelse return error.TestExpectedCookie;
    try testing.expectEqualStrings(name, c.name);
    try testing.expectEqualStrings(value, c.value);
}

test "simple pairs and find" {
    var it = parse("a=1; b=2");
    try expectPair(&it, "a", "1");
    try expectPair(&it, "b", "2");
    try testing.expectEqual(@as(?Cookie, null), it.next());

    try testing.expectEqualStrings("2", find("a=1; b=2", "b").?);
    try testing.expectEqual(@as(?[]const u8, null), find("a=1; b=2", "c"));
}

test "OWS around names and values is trimmed" {
    var it = parse("a = 1 ;  b=2");
    try expectPair(&it, "a", "1");
    try expectPair(&it, "b", "2");
    try testing.expectEqual(@as(?Cookie, null), it.next());
}

test "valueless cookie" {
    var it = parse("flag; a=1");
    try expectPair(&it, "flag", "");
    try expectPair(&it, "a", "1");
    try testing.expectEqual(@as(?Cookie, null), it.next());
}

test "quoted value: matching DQUOTEs stripped, unbalanced kept" {
    var it = parse("s=\"x y\"");
    try expectPair(&it, "s", "x y");
    try testing.expectEqual(@as(?Cookie, null), it.next());

    // Unbalanced leading quote is kept verbatim.
    try testing.expectEqualStrings("\"x", find("s=\"x", "s").?);
    // A lone quote (length 1) is kept verbatim.
    try testing.expectEqualStrings("\"", find("s=\"", "s").?);
}

test "empty-name segments skipped; first '=' splits" {
    var it = parse("=1; a=1");
    try expectPair(&it, "a", "1");
    try testing.expectEqual(@as(?Cookie, null), it.next());

    var it2 = parse("; ;a=1");
    try expectPair(&it2, "a", "1");
    try testing.expectEqual(@as(?Cookie, null), it2.next());

    // Value containing '=' keeps everything after the FIRST '='.
    try testing.expectEqualStrings("b=c", find("a=b=c", "a").?);
}

test "empty and degenerate headers yield no pairs" {
    var it = parse("");
    try testing.expectEqual(@as(?Cookie, null), it.next());

    var it2 = parse("   \t ");
    try testing.expectEqual(@as(?Cookie, null), it2.next());

    var it3 = parse(";;;");
    try testing.expectEqual(@as(?Cookie, null), it3.next());
}

// ── P2: Set-Cookie building ──

test "SetCookie: full attribute set in RFC order" {
    const sc: SetCookie = .{
        .name = "id",
        .value = "abc",
        .path = "/",
        .max_age = 3600,
        .secure = true,
        .http_only = true,
        .same_site = .lax,
    };
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "id=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax",
        try sc.bufPrint(&buf),
    );
}

test "SetCookie: minimal name=value" {
    var buf: [16]u8 = undefined;
    const sc: SetCookie = .{ .name = "n", .value = "v" };
    try testing.expectEqualStrings("n=v", try sc.bufPrint(&buf));
}

test "SetCookie: Domain and pre-formatted Expires" {
    const sc: SetCookie = .{
        .name = "a",
        .value = "1",
        .domain = "example.com",
        .expires = "Wed, 09 Jun 2021 10:18:14 GMT",
    };
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "a=1; Domain=example.com; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        try sc.bufPrint(&buf),
    );
}

test "SetCookie: negative Max-Age (expire now)" {
    var buf: [64]u8 = undefined;
    const sc: SetCookie = .{ .name = "a", .value = "", .max_age = -1 };
    try testing.expectEqualStrings("a=; Max-Age=-1", try sc.bufPrint(&buf));
}

test "SetCookie: SameSite=Strict" {
    var buf: [64]u8 = undefined;
    const sc: SetCookie = .{ .name = "a", .value = "1", .same_site = .strict };
    try testing.expectEqualStrings("a=1; SameSite=Strict", try sc.bufPrint(&buf));
}

test "SetCookie: invalid name rejected" {
    var buf: [64]u8 = undefined;
    const bad_names = [_][]const u8{ "", "a b", "a;b", "a=b", "a,b", "a\"b", "a\\b", "a\x01b", "a\x7fb" };
    for (bad_names) |n| {
        const sc: SetCookie = .{ .name = n, .value = "v" };
        try testing.expectError(error.InvalidCookie, sc.bufPrint(&buf));
    }
}

test "SetCookie: invalid value rejected (no auto-quoting)" {
    var buf: [64]u8 = undefined;
    const bad_values = [_][]const u8{ "a b", "a;b", "a\"b", "a,b", "a\\b", "a\x01b", "a\x7fb" };
    for (bad_values) |v| {
        const sc: SetCookie = .{ .name = "n", .value = v };
        try testing.expectError(error.InvalidCookie, sc.bufPrint(&buf));
    }
}

test "SetCookie: invalid Path/Domain rejected" {
    var buf: [64]u8 = undefined;
    const bad_path: SetCookie = .{ .name = "n", .value = "v", .path = "/a;b" };
    try testing.expectError(error.InvalidCookie, bad_path.bufPrint(&buf));
    const ctl_domain: SetCookie = .{ .name = "n", .value = "v", .domain = "ex\x01.com" };
    try testing.expectError(error.InvalidCookie, ctl_domain.bufPrint(&buf));
}

test "SetCookie: SameSite=None requires Secure" {
    var buf: [64]u8 = undefined;
    const insecure: SetCookie = .{ .name = "n", .value = "v", .same_site = .none };
    try testing.expectError(error.InsecureSameSiteNone, insecure.bufPrint(&buf));

    const ok: SetCookie = .{ .name = "n", .value = "v", .secure = true, .same_site = .none };
    try testing.expectEqualStrings("n=v; Secure; SameSite=None", try ok.bufPrint(&buf));
}

test "SetCookie: bufPrint into too-small buffer" {
    var buf: [4]u8 = undefined;
    const sc: SetCookie = .{ .name = "name", .value = "value" };
    try testing.expectError(error.BufferTooSmall, sc.bufPrint(&buf));
}

// ── P3 tests: http integration (offline, through serveStream) ────────────────

fn cookieHandler(req: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    // Echo the requested "session" cookie back in the body, and set one.
    const sid = get(req, "session") orelse "none";
    // The Set-Cookie value is borrowed by the response until the serving loop
    // flushes the head — which happens AFTER this handler returns — so the
    // buffer must outlive the handler frame. Take it from `context` (here, the
    // caller's frame), not a local array which would be popped first.
    const cbuf: *[128]u8 = @ptrCast(@alignCast(req.context.?));
    try set(res, .{
        .name = "session",
        .value = "s3",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    }, cbuf);
    try res.writeAll(sid);
}

test "get + set over serveStream" {
    const Reader = std.Io.Reader;
    const Writer = std.Io.Writer;
    var in: Reader = .fixed("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "Cookie: a=1; session=abc; b=2\r\nConnection: close\r\n\r\n");
    var out_buf: [2048]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var head_buf: [2048]u8 = undefined;
    var req_body: [256]u8 = undefined;
    var res_body: [512]u8 = undefined;
    var chunk: [128]u8 = undefined;
    // Cookie buffer lives on the test frame → outlives the response flush.
    var cookie_buf: [128]u8 = undefined;
    http.Server.serveStream(.{ .handler = cookieHandler, .server_name = null, .context = &cookie_buf }, &in, &out, .{
        .head = &head_buf,
        .request_body = &req_body,
        .response_body = &res_body,
        .chunk = &chunk,
    });
    const got = out.buffered();
    // get() read the "session" cookie out of the multi-cookie header.
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nabc"));
    // set() emitted the Set-Cookie with attributes.
    try testing.expect(std.mem.indexOf(u8, got, "Set-Cookie: session=s3; Path=/; Secure; HttpOnly; SameSite=Lax\r\n") != null);
}
