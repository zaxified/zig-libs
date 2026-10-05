// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: Go's `net/http/cookiejar` (go1.26,
//! BSD-3-Clause), with `resp.Cookies()` parsing the `Set-Cookie` fields, ran
//! our own scenarios (`tools/go_oracle/main.go`); `jar_go_vectors.zig` holds
//! what each request got. Replayed here through `Jar` on the clock the
//! scenarios ran at. Go's public suffix list said "the last label" for every
//! name; ours is the empty list, whose implicit `*` rule says the same. Only
//! Go's observable answers were recorded; no Go source was read.
//!
//! Every step where we send something else is in `divergences` with the RFC
//! rule and what we send; an unlisted difference fails, and so does an
//! entry that agrees again or differs the other way.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const jar = @import("jar.zig");
const PublicSuffixList = @import("psl.zig").PublicSuffixList;
const vectors = @import("jar_go_vectors.zig");

/// A scenario whose requests we answer differently: what OUR requests get,
/// in step order, joined by ` | `, and why.
const Divergence = struct { id: []const u8, ours: []const u8, why: []const u8 };

const divergences = [_]Divergence{
    // ── RFC 6265bis's Secure rules, which Go's jar does not apply ──
    .{ .id = "secure-from-http", .ours = "", .why = "6265bis §5.7: a Secure cookie from a non-secure origin is ignored; Go stores it" },
    .{ .id = "secure-shadow", .ours = "s=1 | ", .why = "6265bis §5.7: a plain origin cannot set a same-name cookie over a Secure one; Go lets it replace the secure cookie" },
    // ── Go off RFC 6265 ──
    .{ .id = "expires-rfc850", .ours = "", .why = "the §5.1.1 cookie-date algorithm reads `Thursday, 01-Jan-70 00:00:00 GMT` as 1970 and the cookie is deleted; Go's Expires parser knows two layouts, ignores the attribute and keeps it" },
    .{ .id = "expires-asctime-past", .ours = "", .why = "as expires-rfc850, the asctime layout" },
    .{ .id = "value-quoted", .ours = "a=\"x y\"", .why = "§5.2 keeps DQUOTEs as part of the value and §5.4 sends it as stored; Go strips them (and re-adds them on the wire only when the value needs them)" },
    .{ .id = "value-quoted-plain", .ours = "a=\"xy\"", .why = "as value-quoted; Go sends `a=xy`, a different value than the server set" },
    .{ .id = "value-ows", .ours = "a=1", .why = "§5.2 step 5 strips WSP around the value; Go keeps the leading spaces" },
    .{ .id = "name-space", .ours = "a b=1", .why = "§5.2's user-agent algorithm takes any name without `=`/`;` (6265bis too); Go requires an RFC 2616 token and drops the cookie" },
};

fn ourAnswers(sc: vectors.Scenario, list: *const PublicSuffixList, buf: []u8) ![]const u8 {
    var j = jar.Jar.init(testing.allocator, undefined, .{ .psl = list });
    defer j.deinit();
    var w: std.Io.Writer = .fixed(buf);
    var first = true;
    for (sc.steps) |st| {
        const url = try http.Url.parse(st.url);
        if (st.fields) |fields| {
            for (fields) |f| try j.setCookieAt(url, f, vectors.now);
            continue;
        }
        if (!first) try w.writeAll(" | ");
        first = false;
        _ = try j.writeCookiesAt(url, vectors.now, &w, "");
    }
    return w.buffered();
}

fn goAnswers(sc: vectors.Scenario, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    var first = true;
    for (sc.steps) |st| {
        if (st.fields != null) continue;
        if (!first) try w.writeAll(" | ");
        first = false;
        try w.writeAll(st.go);
    }
    return w.buffered();
}

test "go oracle jar: every request carries what Go's cookiejar sends, or the difference is judged" {
    var list = try PublicSuffixList.parse(testing.allocator, "");
    defer list.deinit();
    var bad: usize = 0;
    for (vectors.scenarios) |sc| {
        var ob: [1024]u8 = undefined;
        var gb: [1024]u8 = undefined;
        const ours = try ourAnswers(sc, &list, &ob);
        const go = try goAnswers(sc, &gb);
        const agrees = std.mem.eql(u8, ours, go);
        const listed: ?Divergence = for (divergences) |d| {
            if (std.mem.eql(u8, d.id, sc.id)) break d;
        } else null;
        const verdict: ?[]const u8 = if (listed) |d|
            (if (agrees) "agrees now, drop its divergence entry" else if (!std.mem.eql(u8, ours, d.ours)) "diverges, but not the way its entry says" else null)
        else if (agrees) null else "diverges";
        const v = verdict orelse continue;
        bad += 1;
        std.debug.print("jar {s}: {s}\n  go:   {s}\n  ours: {s}\n", .{ sc.id, v, go, ours });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
