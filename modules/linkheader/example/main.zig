// SPDX-License-Identifier: MIT

//! What a REST client does with `linkheader`: parse the exact `Link:` header
//! shape GitHub's REST API sends for paginated collections (`rel="next"`,
//! `rel="last"`, quoted params, several links joined by `,`), follow it with
//! `find`, and build a `Link` header of its own for the reverse direction.
//!
//! `linkheader` allocates nothing and keeps no state, so there is no
//! DebugAllocator to wrap here (see `modules/l2disco/example/main.zig` for
//! the same allocation-free shape).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const linkheader = @import("linkheader");

pub fn main() !void {
    // The GitHub REST API's own documented pagination shape: three links,
    // comma-joined, each `<uri>; rel="..."`.
    const github_header =
        "<https://api.github.com/user/9287/repos?page=3&per_page=100>; rel=\"next\", " ++
        "<https://api.github.com/user/9287/repos?page=1&per_page=100>; rel=\"prev\", " ++
        "<https://api.github.com/user/9287/repos?page=515&per_page=100>; rel=\"last\"";

    var it = linkheader.parse(github_header);
    var seen: usize = 0;
    while (it.next()) |link| : (seen += 1) {
        std.debug.print("link[{d}]: rel={s} uri={s}\n", .{ seen, link.rel, link.uri });
    }
    if (seen != 3) return error.WrongLinkCount;

    // `find` picks the "next" relation out, case-insensitively — the whole
    // point of the module for a pagination-following client.
    const next = linkheader.find(github_header, "NEXT") orelse return error.MissingNext;
    if (!std.mem.eql(u8, next.uri, "https://api.github.com/user/9287/repos?page=3&per_page=100")) {
        return error.WrongNextUri;
    }
    const last = linkheader.find(github_header, "last") orelse return error.MissingLast;
    if (!std.mem.eql(u8, last.uri, "https://api.github.com/user/9287/repos?page=515&per_page=100")) {
        return error.WrongLastUri;
    }
    std.debug.print("find(\"NEXT\")={s} find(\"last\")={s}\n", .{ next.uri, last.uri });

    // RFC 8288 quoted params: a comma AND a semicolon inside a quoted title
    // must not split the link early or desync the following one.
    const quoted_header =
        "<https://api/x>; rel=\"next\"; title=\"Repos, sorted; paginated\", " ++
        "<https://api/y>; rel=\"prev\"";
    var qit = linkheader.parse(quoted_header);
    const first = qit.next() orelse return error.MissingLink;
    if (!std.mem.eql(u8, first.title.?, "Repos, sorted; paginated")) return error.QuoteDesync;
    const second = qit.next() orelse return error.MissingLink;
    if (!std.mem.eql(u8, second.rel, "prev")) return error.QuoteDesync;
    std.debug.print("quoted title survived embedded comma+semicolon: \"{s}\"\n", .{first.title.?});

    // Malformed-segment handling: the module's documented policy is SKIP, not
    // error — a segment with no `<...>` or with no `rel` is dropped and the
    // iterator resynchronizes on the next top-level comma (SPEC.md "Error
    // policy = skip, never panic"). There is no named-error rejection path
    // for a malformed *segment*; the builder is where errors live (below).
    const malformed_header = "garbage-no-brackets, <https://api/no-rel>; title=\"dropped\", <https://api/z>; rel=\"self\"";
    var mit = linkheader.parse(malformed_header);
    const survivor = mit.next() orelse return error.MissingLink;
    if (!std.mem.eql(u8, survivor.uri, "https://api/z") or !std.mem.eql(u8, survivor.rel, "self")) {
        return error.MalformedHandlingChanged;
    }
    if (mit.next() != null) return error.UnexpectedExtraLink;
    std.debug.print("two malformed segments skipped; \"{s}\" (rel={s}) survived\n", .{ survivor.uri, survivor.rel });

    // Build direction: `pagination` + `bufPrint`, the reverse of the GitHub
    // shape above — a server responding to a paginated list.
    var slots: [4]linkheader.Link = undefined;
    const links = linkheader.pagination(&slots, .{
        .first = "/repos?page=1",
        .prev = "/repos?page=2",
        .next = "/repos?page=4",
        .last = "/repos?page=9",
    });
    var out_buf: [256]u8 = undefined;
    const out = try linkheader.bufPrint(&out_buf, links);
    std.debug.print("built: {s}\n", .{out});

    // Negative case, named error: a destination buffer too small to hold
    // the header.
    var tiny: [8]u8 = undefined;
    if (linkheader.bufPrint(&tiny, links)) |_| {
        return error.ExpectedRejection;
    } else |err| switch (err) {
        error.NoSpaceLeft => std.debug.print("bufPrint into an 8-byte buffer: NoSpaceLeft (expected)\n", .{}),
        error.InvalidLink => return error.WrongRejection,
    }

    // Negative case: a title carrying CR LF would split the header and
    // inject a second one. The builder refuses it before writing a byte.
    const evil = [_]linkheader.Link{.{ .uri = "/x", .rel = "next", .title = "hi\r\nSet-Cookie: s=1" }};
    if (linkheader.bufPrint(&out_buf, &evil)) |_| {
        return error.ExpectedRejection;
    } else |err| switch (err) {
        error.InvalidLink => std.debug.print("title with CR LF: InvalidLink (expected)\n", .{}),
        error.NoSpaceLeft => return error.WrongRejection,
    }

    // Every param, RFC 8187 `title*` and a relative target: a preload hint
    // from RFC 8288 §3.5's `title*` shape, resolved against the request URI.
    const hint = "<../s.css>; rel=preload; as=style; title*=UTF-8'de'n%c3%a4chstes%20Kapitel";
    const pre = linkheader.find(hint, "preload") orelse return error.MissingLink;
    const as = pre.param("as") orelse return error.MissingParam;
    var title_buf: [64]u8 = undefined;
    const title = (try pre.preferredTitle(&title_buf)) orelse return error.MissingTitle;
    if (!std.mem.eql(u8, title, "n\u{e4}chstes Kapitel")) return error.WrongTitle;
    var abs_buf: [512]u8 = undefined;
    const abs = try linkheader.resolve(&abs_buf, "https://example.org/app/page/index.html", pre.uri);
    if (!std.mem.eql(u8, abs, "https://example.org/app/s.css")) return error.WrongResolution;
    std.debug.print("preload as={s} title=\"{s}\" -> {s}\n", .{ as.value, title, abs });
}
