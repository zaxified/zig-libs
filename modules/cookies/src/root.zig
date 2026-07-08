// SPDX-License-Identifier: MIT

//! cookies — HTTP cookies (RFC 6265). **P1**: the `Cookie` request-header
//! parser — iterate the `name=value` pairs a client sends back. Building
//! `Set-Cookie` (attributes: Path/Domain/Max-Age/Expires/Secure/HttpOnly/
//! SameSite) is the next part. Allocation-free; parsed pairs borrow the header.
//!
//! ```zig
//! var it = cookies.parse(req.header("cookie") orelse "");
//! while (it.next()) |c| { … c.name … c.value … }
//! const sid = cookies.find(req.header("cookie") orelse "", "session") orelse return;
//! ```

const std = @import("std");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // no state; results borrow the input header
    .model_after = "RFC 6265 (HTTP State Management Mechanism)",
    .deps = .{},
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
