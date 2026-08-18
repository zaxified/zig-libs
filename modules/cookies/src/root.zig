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
    .targets = .{.linux64},
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
            // Take up to the next `;` → one segment; advance past it. A `;`
            // inside a DQUOTE-wrapped span does not end the segment — found
            // via python's `http.cookies` oracle (see golden_test.zig):
            // naively splitting first broke `s="x;y"` into `s="x` + `y"`.
            // No backslash-escaping is recognized (RFC 6265's cookie-value
            // grammar has none — that's a Python-only legacy extension), so
            // any `"` simply toggles the span, matching how a properly
            // paired DQUOTE value can appear.
            var seg_end: usize = it.rest.len;
            var in_quotes = false;
            for (it.rest, 0..) |c, i| {
                if (c == '"') in_quotes = !in_quotes;
                if (c == ';' and !in_quotes) {
                    seg_end = i;
                    break;
                }
            }
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
    /// The name uses a reserved prefix (RFC 6265bis §4.1.3) whose constraints
    /// are not met: `__Secure-` requires `secure`; `__Host-` requires `secure`,
    /// `Path=/`, and no `Domain`. Browsers silently reject such a cookie, so it
    /// is refused here loudly rather than sent and dropped.
    CookiePrefixViolation,
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
        // RFC 6265bis §4.1.3 cookie name prefixes (case-sensitive). A browser
        // silently drops a cookie that violates these; reject it here instead.
        if (std.mem.startsWith(u8, sc.name, "__Secure-") and !sc.secure)
            return error.CookiePrefixViolation;
        if (std.mem.startsWith(u8, sc.name, "__Host-")) {
            const path_is_root = sc.path != null and std.mem.eql(u8, sc.path.?, "/");
            if (!sc.secure or sc.domain != null or !path_is_root)
                return error.CookiePrefixViolation;
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

/// Largest `Set-Cookie` header VALUE `set` will serialize — name, value and
/// every attribute together. Longer ⇒ `error.BufferTooSmall`, never a silent
/// truncation (a truncated `Set-Cookie` is worse than a dropped one: it can
/// still parse, so the client stores a cookie nobody wrote).
///
/// WHERE 4096 COMES FROM. RFC 6265 §6.1 requires a user agent to support at
/// least 4096 bytes per cookie, "as measured by the sum of the length of the
/// cookie's name, value, and attributes" — so 4096 is the largest cookie any
/// conforming browser is obliged to keep, and a smaller bound here would
/// refuse cookies that would have worked in practice.
///
/// It is also, deliberately, not a second budget to get wrong. `http`'s
/// per-response copy store is 4096 bytes for ALL header and trailer bytes, so
/// any value this buffer could reject is one `setHeader` would have rejected
/// anyway (`error.HeaderBytesExhausted`, and sooner — the name costs bytes
/// too). This buffer is therefore never the binding constraint: the refusal a
/// caller actually meets comes from the writer's own accounting.
///
/// That last paragraph used to be maintained by comment on both sides —
/// `http`'s `header_copy_bytes` was a private `const`, so this file could not
/// import it and the "same size" property was a duplicated literal. It is
/// imported now, and the relation is asserted at comptime below, so the two
/// cannot drift apart silently in either direction.
pub const max_set_cookie_bytes = 4096;

comptime {
    // FLOOR — RFC 6265 §6.1: a conforming user agent must support at least
    // 4096 bytes per cookie. Refusing below that would reject cookies that
    // work in every real browser. Catches downward drift.
    std.debug.assert(max_set_cookie_bytes >= 4096);
    // CEILING — the doc claim above ("never the binding constraint") is only
    // true while this buffer cannot outgrow the response writer's copy store.
    // Raising this alone would make `set` accept a value `setHeader` must
    // then reject, moving the refusal from a clean `BufferTooSmall` here to a
    // budget error that depends on what else the handler already set.
    // Catches upward drift. Measured before this assertion existed: 4096 →
    // 8192 left 38/38 green in Debug AND ReleaseSafe.
    std.debug.assert(max_set_cookie_bytes <= http.Server.header_copy_bytes);
}

/// Serialize `sc` and set it as the response's `Set-Cookie` header. Rejects an
/// invalid cookie (`WriteError`) before touching the response.
///
/// The value is formatted into a `max_set_cookie_bytes` buffer on THIS frame
/// and handed to `setHeader`, which copies it into the response writer's own
/// storage before returning — which is why no buffer is asked of the caller.
/// It used to take one, because the head (this value included) is not
/// serialized onto the wire until the serving loop calls `end()`, after the
/// handler returns, and the writer borrowed the caller's slices; a value built
/// on the handler's frame was then read after that frame died. The writer
/// copies now, so the parameter bought nothing.
///
/// NOTE: the server emits at most **one** `Set-Cookie` per response —
/// `setHeader` replaces by name — so a second `set` overwrites the first.
/// Setting multiple cookies in one response is not supported through this path.
pub fn set(res: *http.Server.ResponseWriter, sc: SetCookie) SetError!void {
    var buf: [max_set_cookie_bytes]u8 = undefined;
    const value = try sc.bufPrint(&buf);
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

test "quoted value containing a separator is not split mid-value (audit, python-oracle)" {
    // Found via the python http.cookies oracle (golden_test.zig): the naive
    // "split on the next ';'" scan broke a `;` living inside a quoted value
    // into two bogus pairs (`s="x` and orphan `y"`). The scan must not treat
    // a `;` as a segment boundary while inside a DQUOTE-wrapped span.
    var it = parse("s=\"x;y\"; b=2");
    try expectPair(&it, "s", "x;y");
    try expectPair(&it, "b", "2");
    try testing.expectEqual(@as(?Cookie, null), it.next());

    // Two quoted values in the same header, the first containing a `;`.
    var it2 = parse("a=\"p;q\"; b=\"r\"");
    try expectPair(&it2, "a", "p;q");
    try expectPair(&it2, "b", "r");
    try testing.expectEqual(@as(?Cookie, null), it2.next());
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

test "SetCookie: __Host-/__Secure- prefix constraints enforced (audit MED)" {
    var buf: [128]u8 = undefined;
    // __Host- requires Secure + Path=/ + no Domain; a valid one serializes.
    _ = try (SetCookie{ .name = "__Host-sid", .value = "x", .secure = true, .path = "/" }).bufPrint(&buf);
    // ...and each missing/violated constraint is refused, not silently sent-then-dropped.
    try testing.expectError(error.CookiePrefixViolation, (SetCookie{ .name = "__Host-sid", .value = "x", .path = "/" }).bufPrint(&buf));
    try testing.expectError(error.CookiePrefixViolation, (SetCookie{ .name = "__Host-sid", .value = "x", .secure = true }).bufPrint(&buf));
    try testing.expectError(error.CookiePrefixViolation, (SetCookie{ .name = "__Host-sid", .value = "x", .secure = true, .path = "/app" }).bufPrint(&buf));
    try testing.expectError(error.CookiePrefixViolation, (SetCookie{ .name = "__Host-sid", .value = "x", .secure = true, .path = "/", .domain = "example.com" }).bufPrint(&buf));
    // __Secure- requires Secure.
    _ = try (SetCookie{ .name = "__Secure-sid", .value = "x", .secure = true }).bufPrint(&buf);
    try testing.expectError(error.CookiePrefixViolation, (SetCookie{ .name = "__Secure-sid", .value = "x" }).bufPrint(&buf));
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
    // Mutation audit: DEL (0x7f) was never tested for Path/Domain — only the
    // 0x01 control byte and ';' were exercised.
    const del_path: SetCookie = .{ .name = "n", .value = "v", .path = "/a\x7fb" };
    try testing.expectError(error.InvalidCookie, del_path.bufPrint(&buf));
    const del_domain: SetCookie = .{ .name = "n", .value = "v", .domain = "ex\x7f.com" };
    try testing.expectError(error.InvalidCookie, del_domain.bufPrint(&buf));
}

test "SetCookie: SameSite=None requires Secure" {
    var buf: [64]u8 = undefined;
    const insecure: SetCookie = .{ .name = "n", .value = "v", .same_site = .none };
    try testing.expectError(error.InsecureSameSiteNone, insecure.bufPrint(&buf));

    const ok: SetCookie = .{ .name = "n", .value = "v", .secure = true, .same_site = .none };
    try testing.expectEqualStrings("n=v; Secure; SameSite=None", try ok.bufPrint(&buf));

    // Mutation audit: only .strict was ever proven to NOT require Secure;
    // .lax shares that same requirement (only .none needs Secure) but was
    // never exercised insecure, so a regression over-requiring Secure for
    // .lax would pass unnoticed.
    const lax_insecure: SetCookie = .{ .name = "n", .value = "v", .same_site = .lax };
    try testing.expectEqualStrings("n=v; SameSite=Lax", try lax_insecure.bufPrint(&buf));
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
    try set(res, .{
        .name = "session",
        .value = "s3",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    });
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
    http.Server.serveStream(.{ .handler = cookieHandler, .server_name = null }, &in, &out, .{
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

/// The handler half of the dead-frame test below: build a cookie name and
/// value in buffers that die with THIS frame, hand them to `set` — whose own
/// formatting buffer dies with it too — and return.
///
/// A separate `noinline` function, not a block inside the test, and that is
/// the whole point: Zig gives each local its own slot for the enclosing
/// function's entire body in Debug, so a block scope frees nothing and a
/// borrowed-slice bug would stay invisible. Only a returned frame is really
/// reusable. Mirrors `http`'s `setFromDeadFrame`.
noinline fn setFromDeadFrame(res: *http.Server.ResponseWriter) !void {
    var name_buf: [32]u8 = undefined;
    var value_buf: [32]u8 = undefined;
    try set(res, .{
        .name = try std.fmt.bufPrint(&name_buf, "sid{d}", .{9}),
        .value = try std.fmt.bufPrint(&value_buf, "{d}", .{4242}),
        .path = "/",
        .http_only = true,
    });
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. Bigger than that frame PLUS the `set` frame nested
/// under it, so it covers `max_set_cookie_bytes` of formatting buffer as well;
/// `noinline` + `doNotOptimizeAway` so neither the call nor the stores can be
/// optimized out.
noinline fn clobberDeadFrame() void {
    var scratch: [8192]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "set: the cookie outlives the frame it was formatted in" {
    // What this pins: `set` no longer takes a caller buffer because
    // `setHeader` COPIES the value into the response writer's own storage.
    // Nothing else in this module's suite would notice if that copy went
    // away — `writeHead` runs inside `end()`, which the serving loop calls
    // after the handler returns, and `serveStream` offers no seam between the
    // two in which to reuse the dead frame. So the writer is built by hand
    // here and driven in the loop's own order, with the scribble in between.
    const Writer = std.Io.Writer;
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try setFromDeadFrame(&rw);
    clobberDeadFrame();

    try rw.writeAll("ok");
    try rw.end();
    const wire = out.buffered();

    // Read back off the wire after every byte of its source was overwritten.
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: sid9=4242; Path=/; HttpOnly\r\n") != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, wire, "#") == null);
}

test "max_set_cookie_bytes: pinned by value and to http's copy store" {
    // Both directions, because measurement showed neither was covered:
    // 4096 → 8192 left this suite 38/38 green in Debug and ReleaseSafe, and
    // the one test that does spend the buffer is written in terms of
    // `max_set_cookie_bytes ± k`, so it moves with the constant.
    //
    // The floor is RFC 6265 §6.1 (a UA must support ≥ 4096 bytes per cookie,
    // name + value + attributes — i.e. the length of a `Set-Cookie` value).
    try testing.expectEqual(@as(usize, 4096), max_set_cookie_bytes);
    // The ceiling is the coupling itself, read from `http` rather than
    // restated: this is the assertion that would have caught the two
    // constants drifting apart while both files still claimed "same size".
    try testing.expect(max_set_cookie_bytes <= http.Server.header_copy_bytes);
}

test "set: an over-long cookie is refused, not truncated" {
    const Writer = std.Io.Writer;
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // Dropping the caller's buffer moved the size limit inside `set`, so the
    // limit needs its own test: a value past `max_set_cookie_bytes` must fail
    // loudly. A truncated `Set-Cookie` is worse than none — it still parses,
    // so the client would store a silently corrupted value.
    var huge: [max_set_cookie_bytes + 1]u8 = undefined;
    @memset(&huge, 'x');
    try testing.expectError(error.BufferTooSmall, set(&rw, .{ .name = "n", .value = &huge }));
    // Nothing reached the response: no header, and the next `set` still works.
    try set(&rw, .{ .name = "n", .value = "v" });
    try rw.end();
    const wire = out.buffered();
    try testing.expect(std.mem.indexOf(u8, wire, "Set-Cookie: n=v\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, wire, "x") == null);

    // The other refusal a caller can meet is the writer's own copy budget,
    // which bites first (the header name costs bytes too) — also an error,
    // also not a truncation.
    var out2: Writer = .fixed(&out_buf);
    var rw2: http.Server.ResponseWriter = .init(&out2, &body_buf, &chunk_buf, .{});
    var big: [max_set_cookie_bytes - 8]u8 = undefined;
    @memset(&big, 'y');
    try testing.expectError(error.HeaderBytesExhausted, set(&rw2, .{ .name = "n", .value = &big }));
}

// External anchor: python3's `http.cookies` used as a black-box oracle for
// `Cookie`-header parsing (see golden_test.zig's module doc-comment).
test {
    _ = @import("golden_test.zig");
}

// ── fuzz: parse never panics on arbitrary or cookie-shaped bytes ───────────
//
// `parse`/`Iterator.next` are the decode entry point for a `Cookie` request
// header — attacker-controlled bytes off the wire. They are allocation-free
// (results borrow the input), so there is no leak oracle to run here; the
// property under test is "never panics or reads out of bounds", across both
// pure garbage and bytes shaped like the grammar the segment scanner actually
// branches on (`=`, `;`, `"` — the DQUOTE-toggle state machine that a naive
// version of the scanner got wrong, per the python-oracle test above).
test "fuzz: parse never panics, arbitrary or cookie-shaped bytes" {
    try std.testing.fuzz({}, fuzzParseNeverPanics, .{});
}

fn fuzzParseNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const header = buildCookieHeader(smith, &buf);
    var it = parse(header);
    while (it.next()) |c| {
        std.mem.doNotOptimizeAway(c.name);
        std.mem.doNotOptimizeAway(c.value);
    }
}

/// One draw in ten is pure arbitrary bytes; the rest are assembled from the
/// alphabet a real `Cookie:` header uses — `name=value` segments joined by
/// `; `, with the value sometimes DQUOTE-wrapped. Arbitrary bytes almost
/// never spell a quoted value containing a `;`, so without this the quote-
/// toggle branch (in-quotes tracking in `Iterator.next`) would go unexercised
/// for the length of any bounded run.
fn buildCookieHeader(smith: *std.testing.Smith, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (smith.valueRangeAtMost(u8, 0, 9) == 0) {
        var raw: [512]u8 = undefined;
        smith.bytes(&raw);
        const len = smith.valueRangeAtMost(u16, 0, @intCast(raw.len));
        w.writeAll(raw[0..len]) catch {};
        return w.buffered();
    }
    const n_segments = smith.valueRangeAtMost(u8, 0, 6);
    var i: u8 = 0;
    while (i < n_segments) : (i += 1) {
        if (i != 0) w.writeAll("; ") catch {};
        writeSegment(smith, &w);
    }
    return w.buffered();
}

fn writeSegment(smith: *std.testing.Smith, w: *std.Io.Writer) void {
    const alphabet = "abcXYZ019=;\" \t\\,";
    const name_len = smith.valueRangeAtMost(u8, 0, 6);
    var i: u8 = 0;
    while (i < name_len) : (i += 1) {
        w.writeByte(alphabet[smith.index(alphabet.len)]) catch return;
    }
    if (!smith.value(bool)) return;
    w.writeByte('=') catch return;
    const quoted = smith.value(bool);
    if (quoted) w.writeByte('"') catch return;
    const value_len = smith.valueRangeAtMost(u8, 0, 8);
    var j: u8 = 0;
    while (j < value_len) : (j += 1) {
        w.writeByte(alphabet[smith.index(alphabet.len)]) catch return;
    }
    if (quoted) w.writeByte('"') catch return;
}
