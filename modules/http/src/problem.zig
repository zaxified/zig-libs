// SPDX-License-Identifier: MIT

//! Problem details for HTTP APIs (RFC 9457, obsoletes RFC 7807) — the
//! `application/problem+json` error body.
//!
//! One writer: the five standard members (`type`, `status`, `title`,
//! `detail`, `instance`) from a `Problem`, followed by the caller's
//! extension members from any struct value, into a `std.Io.Writer`.
//! Allocation-free; the output is one minified JSON object.
//!
//! ```zig
//! var w: std.Io.Writer = .fixed(&buf);
//! try http.problem.write(&w, .{
//!     .type = "https://example.com/probs/out-of-credit",
//!     .status = 403,
//!     .title = "You do not have enough credit.",
//!     .detail = "Your current balance is 30, but that costs 50.",
//!     .instance = "/account/12345/msgs/abc",
//! }, .{ .balance = 30 });
//! // respond with status 403, Content-Type: http.problem.content_type
//! ```
//!
//! ## Policy
//!
//! - **`about:blank` gets its reason phrase.** With the default `type` and
//!   no `title`, the title is the status code's reason phrase (RFC 9457
//!   §4.2.1: "SHOULD be the same as the recommended HTTP status phrase").
//!   A status this module has no phrase for leaves the title out.
//! - **Absent members are omitted**, never written as `null` (§3.1: a
//!   member of the wrong type is ignored by consumers, so `null` would only
//!   add bytes). `type` is always written, `about:blank` included.
//! - **The standard members are always valid JSON text.** `detail` and
//!   `instance` routinely carry request bytes (a path, a header value); a
//!   byte sequence that is not UTF-8 is written as U+FFFD, one per maximal
//!   invalid subpart, so the error body a client receives always parses
//!   (RFC 8259 §8.1 requires UTF-8). Extension members go through
//!   `std.json.Stringify` unchanged — their strings must already be UTF-8.
//! - **An extension may not shadow a standard member** — a field named
//!   `type`, `status`, `title`, `detail` or `instance` is a compile error.
//!   §3.2 also recommends extension names of ≥ 3 characters from ALPHA,
//!   DIGIT and `_`, starting with a letter (for non-JSON formats); that is
//!   left to the caller.
//! - `status` is advisory (§3.1.2): it should equal the response's status
//!   code, and this module does not send the response, so it cannot check.
//!
//! ## Reading one
//!
//! `Problem` doubles as the parse target on the client side — absent `type`
//! defaults to `about:blank` exactly as §3.1.1 says:
//! `std.json.parseFromSlice(Problem, gpa, body, .{ .ignore_unknown_fields = true })`.

const std = @import("std");
const reasonPhrase = @import("Server.zig").reasonPhrase;

/// The media type of a problem details body (RFC 9457 §6.1).
pub const content_type = "application/problem+json";

/// The standard members (RFC 9457 §3.1). Every string is borrowed.
pub const Problem = struct {
    /// URI reference identifying the problem type; §3.1.1.
    type: []const u8 = "about:blank",
    /// The HTTP status code of this occurrence; §3.1.2.
    status: ?u16 = null,
    /// Short summary of the problem type, stable across occurrences; §3.1.3.
    title: ?[]const u8 = null,
    /// Explanation specific to this occurrence; §3.1.4.
    detail: ?[]const u8 = null,
    /// URI reference identifying this occurrence; §3.1.5.
    instance: ?[]const u8 = null,
};

const standard_members = [_][]const u8{ "type", "status", "title", "detail", "instance" };

/// Write `p` and then every field of `extensions` (a struct value; `.{}`
/// for none) as one `application/problem+json` object.
pub fn write(w: *std.Io.Writer, p: Problem, extensions: anytype) std.Io.Writer.Error!void {
    const E = @TypeOf(extensions);
    const fields = switch (@typeInfo(E)) {
        .@"struct" => |s| s.fields,
        else => @compileError("problem.write: extensions must be a struct value, got " ++ @typeName(E)),
    };
    inline for (fields) |f| {
        inline for (standard_members) |m| {
            if (comptime std.mem.eql(u8, f.name, m))
                @compileError("problem.write: extension member '" ++ f.name ++ "' shadows a standard member (RFC 9457 §3.1)");
        }
    }

    var s: std.json.Stringify = .{ .writer = w };
    try s.beginObject();
    try s.objectField("type");
    try writeText(&s, p.type);
    if (p.status) |code| {
        try s.objectField("status");
        try s.write(code);
    }
    const title: ?[]const u8 = p.title orelse if (p.status != null and std.mem.eql(u8, p.type, "about:blank")) blk: {
        const phrase = reasonPhrase(p.status.?);
        break :blk if (phrase.len == 0) null else phrase;
    } else null;
    if (title) |t| {
        try s.objectField("title");
        try writeText(&s, t);
    }
    if (p.detail) |d| {
        try s.objectField("detail");
        try writeText(&s, d);
    }
    if (p.instance) |i| {
        try s.objectField("instance");
        try writeText(&s, i);
    }
    inline for (fields) |f| {
        try s.objectField(f.name);
        try s.write(@field(extensions, f.name));
    }
    try s.endObject();
}

/// A JSON string value that is valid UTF-8 whatever `bytes` holds: each
/// maximal invalid subpart becomes U+FFFD (the Unicode §3.9 "substitution of
/// maximal subparts" practice, as WHATWG `TextDecoder` does it).
fn writeText(s: *std.json.Stringify, bytes: []const u8) std.Io.Writer.Error!void {
    try s.beginWriteRaw();
    defer s.endWriteRaw();
    const w = s.writer;
    try w.writeByte('"');
    var i: usize = 0;
    var run: usize = 0; // start of the pending valid run
    while (i < bytes.len) {
        const n = validSequenceLen(bytes[i..]);
        if (n != 0) {
            i += n;
            continue;
        }
        try std.json.Stringify.encodeJsonStringChars(bytes[run..i], s.options, w);
        try w.writeAll("\u{FFFD}");
        i += maximalSubpartLen(bytes[i..]);
        run = i;
    }
    try std.json.Stringify.encodeJsonStringChars(bytes[run..], s.options, w);
    try w.writeByte('"');
}

/// Length of the well-formed UTF-8 sequence at the start of `b`, or 0.
/// Table 3-7 of the Unicode standard: no overlongs, no surrogates, ≤ U+10FFFF.
fn validSequenceLen(b: []const u8) usize {
    const c0 = b[0];
    if (c0 < 0x80) return 1;
    const len: usize, const lo: u8, const hi: u8 = switch (c0) {
        0xC2...0xDF => .{ 2, 0x80, 0xBF },
        0xE0 => .{ 3, 0xA0, 0xBF },
        0xE1...0xEC, 0xEE...0xEF => .{ 3, 0x80, 0xBF },
        0xED => .{ 3, 0x80, 0x9F },
        0xF0 => .{ 4, 0x90, 0xBF },
        0xF1...0xF3 => .{ 4, 0x80, 0xBF },
        0xF4 => .{ 4, 0x80, 0x8F },
        else => return 0,
    };
    if (b.len < len) return 0;
    if (b[1] < lo or b[1] > hi) return 0;
    for (b[2..len]) |c| if (c < 0x80 or c > 0xBF) return 0;
    return len;
}

/// Length of the maximal subpart at the start of `b` (precondition: the
/// sequence there is not well-formed): the lead byte plus every following
/// byte that could still continue it. At least 1.
fn maximalSubpartLen(b: []const u8) usize {
    const len: usize, const lo: u8, const hi: u8 = switch (b[0]) {
        0xC2...0xDF => .{ 2, 0x80, 0xBF },
        0xE0 => .{ 3, 0xA0, 0xBF },
        0xE1...0xEC, 0xEE...0xEF => .{ 3, 0x80, 0xBF },
        0xED => .{ 3, 0x80, 0x9F },
        0xF0 => .{ 4, 0x90, 0xBF },
        0xF1...0xF3 => .{ 4, 0x80, 0xBF },
        0xF4 => .{ 4, 0x80, 0x8F },
        else => return 1,
    };
    if (b.len < 2 or b[1] < lo or b[1] > hi) return 1;
    var n: usize = 2;
    while (n < len and n < b.len and b[n] >= 0x80 and b[n] <= 0xBF) n += 1;
    return n;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn render(buf: []u8, p: Problem, extensions: anytype) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try write(&w, p, extensions);
    return w.buffered();
}

test "RFC 9457 §3 example: standard members + extensions, in order" {
    var buf: [512]u8 = undefined;
    const out = try render(&buf, .{
        .type = "https://example.com/probs/out-of-credit",
        .title = "You do not have enough credit.",
        .detail = "Your current balance is 30, but that costs 50.",
        .instance = "/account/12345/msgs/abc",
    }, .{
        .balance = 30,
        .accounts = [_][]const u8{ "/account/12345", "/account/67890" },
    });
    try testing.expectEqualStrings(
        \\{"type":"https://example.com/probs/out-of-credit","title":"You do not have enough credit.","detail":"Your current balance is 30, but that costs 50.","instance":"/account/12345/msgs/abc","balance":30,"accounts":["/account/12345","/account/67890"]}
    , out);
}

test "about:blank: title defaults to the reason phrase, absent members omitted" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        \\{"type":"about:blank","status":404,"title":"Not Found"}
    , try render(&buf, .{ .status = 404 }, .{}));
    // An explicit title wins.
    try testing.expectEqualStrings(
        \\{"type":"about:blank","status":404,"title":"Gone fishing"}
    , try render(&buf, .{ .status = 404, .title = "Gone fishing" }, .{}));
    // No phrase for the code → no title, rather than an empty one.
    try testing.expectEqualStrings(
        \\{"type":"about:blank","status":599}
    , try render(&buf, .{ .status = 599 }, .{}));
    // No status → nothing to take a phrase from.
    try testing.expectEqualStrings(
        \\{"type":"about:blank"}
    , try render(&buf, .{}, .{}));
}

test "a non-blank type never borrows the status phrase" {
    // §4.2.1's rule is specific to about:blank; for a defined type the
    // title belongs to that type, and inventing one would mislabel it.
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        \\{"type":"https://e.x/p","status":422}
    , try render(&buf, .{ .type = "https://e.x/p", .status = 422 }, .{}));
}

test "strings are JSON-escaped" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        \\{"type":"about:blank","detail":"a\"b\\c\nd\u0001"}
    , try render(&buf, .{ .detail = "a\"b\\c\nd\x01" }, .{}));
}

test "invalid UTF-8 in a standard member becomes U+FFFD per maximal subpart" {
    var buf: [256]u8 = undefined;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "ok\xffok", .want = "ok\u{FFFD}ok" },
        // Truncated 3-byte sequence: one maximal subpart → one U+FFFD.
        .{ .in = "\xe2\x82", .want = "\u{FFFD}" },
        .{ .in = "\xe2\x82x", .want = "\u{FFFD}x" },
        // Overlong NUL and a surrogate half: the second byte is already
        // out of range, so each byte is its own subpart.
        .{ .in = "\xc0\x80", .want = "\u{FFFD}\u{FFFD}" },
        .{ .in = "\xed\xa0\x80", .want = "\u{FFFD}\u{FFFD}\u{FFFD}" },
        // Above U+10FFFF.
        .{ .in = "\xf4\x90\x80\x80", .want = "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}" },
        // Valid multi-byte text passes through untouched.
        .{ .in = "Žluťoučký kůň €𝄞", .want = "Žluťoučký kůň €𝄞" },
        // A lone continuation byte, then a quote that must still be escaped.
        .{ .in = "\x80\"", .want = "\u{FFFD}\\\"" },
    };
    for (cases) |c| {
        const out = try render(&buf, .{ .type = "t", .instance = c.in }, .{});
        var want_buf: [128]u8 = undefined;
        const want = try std.fmt.bufPrint(&want_buf, "{{\"type\":\"t\",\"instance\":\"{s}\"}}", .{c.want});
        try testing.expectEqualStrings(want, out);
        try testing.expect(std.unicode.utf8ValidateSlice(out));
    }
}

test "the output round-trips through std.json into Problem" {
    var buf: [256]u8 = undefined;
    const out = try render(&buf, .{
        .type = "https://e.x/p",
        .status = 409,
        .title = "Conflict",
        .detail = "d",
        .instance = "/i",
    }, .{ .retry = true });
    const parsed = try std.json.parseFromSlice(Problem, testing.allocator, out, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try testing.expectEqualStrings("https://e.x/p", parsed.value.type);
    try testing.expectEqual(@as(?u16, 409), parsed.value.status);
    try testing.expectEqualStrings("Conflict", parsed.value.title.?);
    try testing.expectEqualStrings("d", parsed.value.detail.?);
    try testing.expectEqualStrings("/i", parsed.value.instance.?);

    // §3.1.1: an absent type means about:blank.
    const bare = try std.json.parseFromSlice(Problem, testing.allocator, "{\"status\":500}", .{ .ignore_unknown_fields = true });
    defer bare.deinit();
    try testing.expectEqualStrings("about:blank", bare.value.type);
}

test "a full writer surfaces WriteFailed" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.WriteFailed, write(&w, .{ .status = 404, .detail = "x" ** 64 }, .{}));
}
