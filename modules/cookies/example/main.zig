// SPDX-License-Identifier: MIT

//! What a session-handling REST server does with `cookies`: parse a real
//! multi-cookie `Cookie:` request header (including the awkward RFC 6265
//! edge cases — an empty value, a bare `=` inside a value, a quoted value
//! containing the segment separator `;`), and build a `Set-Cookie` response
//! header with the full RFC 6265bis attribute set, including the two
//! injection/footgun guards the builder exists for: a value that would break
//! the header, and `SameSite=None` sent without `Secure`.
//!
//! `cookies`' parser and builder are allocation-free (only the `get`/`set`
//! `http` helpers touch a live connection, and this example does not open
//! one), so there is no DebugAllocator to wrap here (see
//! `modules/l2disco/example/main.zig` for the same allocation-free shape).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const cookies = @import("cookies");

pub fn main() !void {
    // ── parse: multiple cookies, one header, awkward real-world shapes ─────
    const header = "session=abc123; theme=dark; empty=; jwt=a=b=c; note=\"hi; there\"";
    var it = cookies.parse(header);

    const session = it.next() orelse return error.MissingCookie;
    if (!std.mem.eql(u8, session.name, "session") or !std.mem.eql(u8, session.value, "abc123")) {
        return error.WrongPair;
    }
    const theme = it.next() orelse return error.MissingCookie;
    if (!std.mem.eql(u8, theme.name, "theme") or !std.mem.eql(u8, theme.value, "dark")) {
        return error.WrongPair;
    }
    // Empty value: a valueless "empty=" segment (RFC 6265 §5.4).
    const empty = it.next() orelse return error.MissingCookie;
    if (!std.mem.eql(u8, empty.name, "empty") or empty.value.len != 0) return error.WrongPair;
    // "=" inside the value: split is on the FIRST "=" only, so everything
    // after it is the value verbatim.
    const jwt = it.next() orelse return error.MissingCookie;
    if (!std.mem.eql(u8, jwt.name, "jwt") or !std.mem.eql(u8, jwt.value, "a=b=c")) return error.WrongPair;
    // A quoted value containing the segment separator ";" must not split the
    // segment early — the exact bug the python http.cookies oracle caught
    // (see SPEC.md "External anchor").
    const note = it.next() orelse return error.MissingCookie;
    if (!std.mem.eql(u8, note.name, "note") or !std.mem.eql(u8, note.value, "hi; there")) return error.WrongPair;
    if (it.next() != null) return error.UnexpectedExtraCookie;
    std.debug.print("parsed 5 cookies from one header, incl. empty value / embedded \"=\" / quoted \";\"\n", .{});

    // `find` — case-sensitive per RFC 6265 §5.4.
    const sid = cookies.find(header, "session") orelse return error.MissingCookie;
    if (!std.mem.eql(u8, sid, "abc123")) return error.WrongPair;
    if (cookies.find(header, "Session") != null) return error.FindShouldBeCaseSensitive;
    std.debug.print("find(\"session\")={s}, find(\"Session\") correctly misses (case-sensitive)\n", .{sid});

    // ── build: the full RFC 6265bis attribute set, in RFC 6265 §4.1 order ──
    const sc: cookies.SetCookie = .{
        .name = "session",
        .value = "abc123",
        .path = "/",
        .domain = "example.com",
        .max_age = 3600,
        .expires = "Wed, 21 Oct 2026 07:28:00 GMT", // pre-formatted; module is dateless
        .secure = true,
        .http_only = true,
        .same_site = .strict,
    };
    var buf: [256]u8 = undefined;
    const built = try sc.bufPrint(&buf);
    const want =
        "session=abc123; Path=/; Domain=example.com; Max-Age=3600; " ++
        "Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Strict";
    if (!std.mem.eql(u8, built, want)) return error.UnexpectedBuild;
    std.debug.print("built: {s}\n", .{built});

    // ── negative case 1, named error: SameSite=None without Secure ─────────
    // Browsers silently drop such a cookie; the builder refuses to emit it.
    const insecure_none: cookies.SetCookie = .{
        .name = "tracker",
        .value = "x",
        .same_site = .none,
        .secure = false,
    };
    var buf2: [128]u8 = undefined;
    if (insecure_none.bufPrint(&buf2)) |_| {
        return error.ExpectedRejection;
    } else |err| switch (err) {
        error.InsecureSameSiteNone => std.debug.print("SameSite=None without Secure: InsecureSameSiteNone (expected)\n", .{}),
        else => return err,
    }

    // ── negative case 2, named error: a header-injection attempt in value ──
    // A reflected value containing a control byte / separator could otherwise
    // inject a second Set-Cookie attribute or header; the builder validates
    // BEFORE writing any byte and refuses it outright rather than escaping it.
    const injection_attempt: cookies.SetCookie = .{
        .name = "session",
        .value = "abc\r\nSet-Cookie: admin=true",
    };
    var buf3: [128]u8 = undefined;
    if (injection_attempt.bufPrint(&buf3)) |_| {
        return error.ExpectedRejection;
    } else |err| switch (err) {
        error.InvalidCookie => std.debug.print("value with embedded CRLF (header-injection attempt): InvalidCookie (expected)\n", .{}),
        else => return err,
    }
}
