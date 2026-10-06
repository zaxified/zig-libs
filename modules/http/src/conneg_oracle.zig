// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for `conneg.zig`: Werkzeug (BSD-3) and
//! python-mimeparse (MIT) answered this module's own case tables
//! (`tools/conneg_oracle/gen.py`); their answers are frozen in
//! `conneg_oracle_vectors.zig` and replayed here through THIS module. No
//! Python at test time. Exempt from a NOTICE entry under §0's black-box-oracle
//! carve-out: both libraries were run, never read.
//!
//! Werkzeug is the primary oracle for `Accept`, `Accept-Language` and
//! `Accept-Encoding`; mimeparse is a second opinion on media types only. Each
//! place we answer differently from Werkzeug is listed in a divergence table
//! with the RFC 9110 rule that decides it — and, for media types, what
//! mimeparse said. A case that diverges without an entry fails, and so does an
//! entry whose case has started to agree.

const std = @import("std");
const testing = std.testing;
const conneg = @import("conneg.zig");
const vectors = @import("conneg_oracle_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

/// `header -> offer,offer,...`: one case's identity in the tables below.
fn caseId(buf: []u8, header: []const u8, offers: []const []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("{s} ->", .{header}) catch unreachable;
    for (offers, 0..) |o, i| w.print("{s}{s}", .{ if (i == 0) " " else ",", o }) catch unreachable;
    return w.buffered();
}

fn findDivergence(table: []const Divergence, id: []const u8) ?Divergence {
    for (table) |d| if (std.mem.eql(u8, d.id, id)) return d;
    return null;
}

fn winner(n: ?conneg.Negotiated) ?[]const u8 {
    return if (n) |x| x.media_type else null;
}

fn eqlOpt(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

/// Replay one table of winners. Every disagreement must be listed; every
/// listing must still disagree.
fn checkWinners(
    comptime what: []const u8,
    cases: anytype,
    divergences: []const Divergence,
    comptime ours: fn ([]const u8, []const []const u8) ?conneg.Negotiated,
) !void {
    var used = [_]bool{false} ** 64;
    std.debug.assert(divergences.len <= used.len);
    var failed = false;
    for (cases) |c| {
        const header = if (@hasField(@TypeOf(c), "accept")) c.accept else c.header;
        var id_buf: [512]u8 = undefined;
        const id = caseId(&id_buf, header, c.offers);
        const n = ours(header, c.offers);
        const got = winner(n);
        var agrees = eqlOpt(got, c.werkzeug);
        // Media cases also carry Werkzeug's weight for its winner.
        const their_q: ?u16 = if (@hasField(@TypeOf(c), "werkzeug_q")) c.werkzeug_q else null;
        if (their_q) |q| if (agrees and n != null and n.?.weight != q) {
            agrees = false;
        };
        var listed: ?usize = null;
        for (divergences, 0..) |d, i| if (std.mem.eql(u8, d.id, id)) {
            listed = i;
        };
        if (listed) |i| used[i] = true;
        if (agrees and listed != null) {
            std.debug.print("{s}: listed divergence now agrees: \"{s}\"\n", .{ what, id });
            failed = true;
        } else if (!agrees and listed == null) {
            std.debug.print("{s}: \"{s}\": ours {?s} q={?d}, Werkzeug {?s} q={?d}\n", .{
                what, id, got, if (n) |x| x.weight else null, c.werkzeug, their_q,
            });
            failed = true;
        }
    }
    for (divergences, 0..) |d, i| if (!used[i]) {
        std.debug.print("{s}: divergence names no case: \"{s}\"\n", .{ what, d.id });
        failed = true;
    };
    if (failed) return error.OracleDisagrees;
}

// ── Accept (media types) ────────────────────────────────────────────────

/// Where `negotiate` picks a different offer than Werkzeug's
/// `MIMEAccept.best_match`, and why ours is right.
const media_divergences = [_]Divergence{
    .{ .id = "text/html;q=0.1234, text/plain;q=0.12 -> text/html,text/plain", .why = "qvalue has at most three decimals (RFC 9110 §12.4.2); the malformed element is skipped, Werkzeug reads 0.1234 (mimeparse sides with Werkzeug)" },
    .{ .id = "text/html;q=, text/plain;q=0.4 -> text/html,text/plain", .why = "an empty qvalue is malformed (§12.4.2) and the element is skipped; Werkzeug defaults it to 1" },
    .{ .id = "text/html;q=0.5;q=0.9, text/plain;q=0.7 -> text/html,text/plain", .why = "the weight is the first `q` (§12.5.1 grammar: one weight per element); Werkzeug takes the last" },
    .{ .id = "text/html;q=0.5;ext=1, text/plain;q=0.4 -> text/html,text/plain", .why = "parameters after the weight are not media-range parameters (§12.5.1 grammar puts the weight last; RFC 7231's accept-ext); Werkzeug makes `ext=1` a range parameter, so the range stops matching" },
    .{ .id = " ,  -> text/html,text/plain", .why = "an Accept field with only empty list elements has no ranges and is treated as absent (any type, §12.5.1; #rule empty elements are ignored, §5.6.1); Werkzeug reports no match" },
    .{ .id = "text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5 -> text/html;level=3", .why = "RFC 9110 §12.5.1's own table gives text/html;level=3 q=0.7 (from `text/html;q=0.7`, which carries no parameter to exclude it); Werkzeug gives 0.3 (`text/*`)" },
};

test "conneg oracle: Accept picks the offer Werkzeug picks, or the difference is judged" {
    try checkWinners("media", vectors.media, &media_divergences, conneg.negotiate);
}

/// One range as `type/subtype;name=value…`, lower-case, the way the
/// generator normalises Werkzeug's.
fn normalRange(buf: []u8, mr: conneg.MediaRange) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("{s}/{s}", .{ mr.type, mr.subtype }) catch unreachable;
    var it = mr.paramsIter();
    while (it.next()) |p| w.print(";{s}={s}", .{ p.name, p.value }) catch unreachable;
    const out = w.buffered();
    for (out) |*ch| ch.* = std.ascii.toLower(ch.*);
    return out;
}

const RangeDivergence = struct { accept: []const u8, why: []const u8 };

/// Headers whose parse (ranges kept, q values) differs from Werkzeug's.
const parse_divergences = [_]RangeDivergence{
    .{ .accept = "text/html;q=0.0001, text/plain;q=0.5", .why = "more than three qvalue decimals: element skipped (§12.4.2); Werkzeug keeps it at q=0" },
    .{ .accept = "text/html;q=0.1234, text/plain;q=0.12", .why = "more than three qvalue decimals: element skipped (§12.4.2)" },
    .{ .accept = "text/html;q=, text/plain;q=0.4", .why = "empty qvalue: element skipped (§12.4.2); Werkzeug q=1" },
    .{ .accept = "text/html;q=0.5;q=0.9, text/plain;q=0.7", .why = "first `q` is the weight; Werkzeug the last" },
    .{ .accept = "text/html;q=0.5;ext=1, text/plain;q=0.4", .why = "a parameter after the weight is not a range parameter; Werkzeug keeps it on the range" },
    .{ .accept = "text, text/plain;q=0.5", .why = "`text` is not a media-range (no `/`): skipped; Werkzeug keeps it" },
    .{ .accept = "*/html, text/plain;q=0.5", .why = "`*/subtype` is not a media-range (§12.5.1): skipped; Werkzeug keeps it (and matches nothing with it)" },
    .{ .accept = "/html, text/plain;q=0.5", .why = "an empty type is not a media-range: skipped; Werkzeug keeps it" },
    .{ .accept = "text/html;foo=\"bar,baz\", text/plain;q=0.5", .why = "same parameter: we report the quoted-string's value unquoted (§5.6.4), Werkzeug its raw form" },
};

const Parsed = struct { range: []const u8, q: u16 };

fn lessParsed(_: void, a: Parsed, b: Parsed) bool {
    const o = std.mem.order(u8, a.range, b.range);
    return o == .lt or (o == .eq and a.q < b.q);
}

test "conneg oracle: Accept parses into the ranges and weights Werkzeug finds, or the difference is judged" {
    var failed = false;
    var used = [_]bool{false} ** parse_divergences.len;
    for (vectors.media) |c| {
        var mr_buf: [32]conneg.MediaRange = undefined;
        const mrs = conneg.parse(c.accept, &mr_buf);
        var text: [32][128]u8 = undefined;
        var ours: [32]Parsed = undefined;
        for (mrs, 0..) |mr, i| ours[i] = .{ .range = normalRange(&text[i], mr), .q = mr.weight };
        var theirs: [32]Parsed = undefined;
        for (c.ranges, 0..) |r, i| theirs[i] = .{ .range = r.range, .q = r.q };
        std.mem.sort(Parsed, ours[0..mrs.len], {}, lessParsed);
        std.mem.sort(Parsed, theirs[0..c.ranges.len], {}, lessParsed);
        var agrees = mrs.len == c.ranges.len;
        if (agrees) for (ours[0..mrs.len], theirs[0..c.ranges.len]) |a, b| {
            if (!std.mem.eql(u8, a.range, b.range) or a.q != b.q) agrees = false;
        };
        var listed = false;
        for (parse_divergences, 0..) |d, i| if (std.mem.eql(u8, d.accept, c.accept)) {
            listed = true;
            used[i] = true;
        };
        if (agrees == listed) {
            failed = true;
            std.debug.print("parse \"{s}\": {s}\n  ours:", .{ c.accept, if (agrees) "listed but agrees" else "differs" });
            for (ours[0..mrs.len]) |p| std.debug.print(" {s}={d}", .{ p.range, p.q });
            std.debug.print("\n  Werkzeug:", .{});
            for (theirs[0..c.ranges.len]) |p| std.debug.print(" {s}={d}", .{ p.range, p.q });
            std.debug.print("\n", .{});
        }
    }
    for (parse_divergences, used) |d, u| if (!u) {
        std.debug.print("parse divergence names no case: \"{s}\"\n", .{d.accept});
        failed = true;
    };
    if (failed) return error.OracleDisagrees;
}

// ── Accept-Language ─────────────────────────────────────────────────────

const language_divergences = [_]Divergence{
    .{ .id = "en-US -> en,de", .why = "basic filtering (RFC 4647 §3.3.1, which §12.5.4 names): range en-US does not match tag en; Werkzeug falls back to the primary subtag" },
    .{ .id = "en-GB;q=0, en -> en-GB,en-US", .why = "the most specific matching range decides a tag (en-GB;q=0 excludes en-GB), so en-US wins; Werkzeug serves the excluded en-GB" },
    .{ .id = "en- -> en,de", .why = "`en-` is not a language-range (empty subtag) and matches nothing; Werkzeug reads it as en" },
};

test "conneg oracle: Accept-Language picks the tag Werkzeug picks, or the difference is judged" {
    try checkWinners("language", vectors.language, &language_divergences, conneg.negotiateLanguage);
}

// ── Accept-Encoding ─────────────────────────────────────────────────────

const encoding_divergences = [_]Divergence{
    .{ .id = "gzip -> br,identity", .why = "identity is acceptable unless excluded (RFC 9110 §12.5.3); Werkzeug has no implicit identity" },
    .{ .id = "gzip;q=0 -> gzip,identity", .why = "implicit identity (§12.5.3); gzip itself is refused by both" },
    .{ .id = "compress, gzip -> identity", .why = "implicit identity (§12.5.3)" },
    .{ .id = "gzip;q=0.001 -> gzip,identity", .why = "implicit identity has q=1 and beats gzip at 0.001 (§12.5.3)" },
};

test "conneg oracle: Accept-Encoding picks the coding Werkzeug picks, or the difference is judged" {
    try checkWinners("encoding", vectors.encoding, &encoding_divergences, conneg.negotiateEncoding);
}
