// SPDX-License-Identifier: MIT

//! Proactive content negotiation (RFC 9110 §12) — **N1: the `Accept`
//! media-range + q-value parser**.
//!
//! This layer parses the `Accept` request header (RFC 9110 §12.5.1) into a list
//! of media-ranges, each with its quality weight `q`. It is pure syntax: it does
//! NOT pick a representation — matching the client's ranges against a server's
//! offers and applying the precedence rules is N2 (`negotiate`), and the sibling
//! `Accept-Language` (RFC 4647) / `Accept-Encoding` headers are N3. Keeping the
//! parse standalone lets a handler inspect what the client asked for before it
//! knows what it can offer.
//!
//! ## Grammar (RFC 9110 §12.5.1)
//!
//! ```
//! Accept      = #( media-range [ weight ] )
//! media-range = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) )
//!               *( OWS ";" OWS parameter )
//! weight      = OWS ";" OWS "q=" qvalue
//! qvalue      = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
//! ```
//!
//! Two parameter zones per element: parameters BEFORE the `;q=` belong to the
//! media-range (they participate in matching — `text/html;level=1`); anything
//! AFTER `q=` is `accept-ext` (extension params, effectively unused) and is
//! ignored here. The weight is kept as an integer in **milli-units** (0..1000,
//! i.e. `q * 1000`) so negotiation is float-free and exactly orderable.
//!
//! ## Usage
//!
//! ```zig
//! var it = http.conneg.accept(req.header("accept") orelse "*/*");
//! while (it.next()) |mr| {
//!     // mr.type / mr.subtype ("*" = wildcard), mr.weight (0..1000)
//!     if (mr.weight != 0 and mr.matches("text", "html")) { … }
//! }
//! ```
//!
//! The iterator is **lenient** (real `Accept` headers are advisory): a malformed
//! element is skipped, not fatal. A missing/empty `Accept` means "anything"
//! (`*/*;q=1`) — that policy is the caller's / N2's; this parser just yields no
//! elements for an empty header.

const std = @import("std");
const body = @import("body.zig");

/// The default quality when an element carries no `;q=` weight: `q=1` (RFC 9110
/// §12.4.2), in milli-units.
pub const q_default: u16 = 1000;

/// The maximum quality, `q=1.000`, in milli-units.
pub const q_max: u16 = 1000;

/// A parsed `Accept` element: a media-range plus its quality weight. Slices
/// point into the header, which must outlive this value.
pub const MediaRange = struct {
    /// The top-level type, or `"*"` for a fully-wildcard range (`*/*`). Compare
    /// case-insensitively (use `matches`).
    type: []const u8,
    /// The subtype, or `"*"` (for `type/*` and `*/*`).
    subtype: []const u8,
    /// Quality in milli-units, 0..1000 (`q_default` when no `;q=` was present).
    /// `q=0` means "not acceptable".
    weight: u16,
    /// The raw media-range parameter section — everything after the media-range
    /// and before the `;q=` weight, `;`-separated (empty when none). Iterate it
    /// with `param` / `params`. Excludes the weight and any `accept-ext`.
    params: []const u8 = "",

    /// Case-insensitive match of this range against a concrete media type
    /// `type/subtype` a server offers. A `*` in this range's type or subtype is
    /// a wildcard (`*/*` matches anything; `text/*` matches any `text/…`). Does
    /// NOT consider parameters or `q` — pure type matching (N2 layers the
    /// precedence + weight rules on top).
    pub fn matches(self: MediaRange, type_: []const u8, subtype_: []const u8) bool {
        const type_ok = std.mem.eql(u8, self.type, "*") or
            std.ascii.eqlIgnoreCase(self.type, type_);
        const subtype_ok = std.mem.eql(u8, self.subtype, "*") or
            std.ascii.eqlIgnoreCase(self.subtype, subtype_);
        return type_ok and subtype_ok;
    }

    /// A specificity rank for RFC 9110 §12.5.1 "most specific wins" ordering,
    /// higher = more specific: `*/*` → 0, `type/*` → 1, `type/subtype` → 2.
    /// (N2 breaks further ties by parameter count, then earlier position.)
    pub fn specificity(self: MediaRange) u2 {
        if (std.mem.eql(u8, self.type, "*")) return 0;
        if (std.mem.eql(u8, self.subtype, "*")) return 1;
        return 2;
    }

    /// The value of media-range parameter `name` (case-insensitive), or null.
    /// Reuses the shared `body` media-type parameter parser over `params`.
    pub fn param(self: MediaRange, name: []const u8) ?[]const u8 {
        var it = self.paramsIter();
        while (it.next()) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) return p.value;
        }
        return null;
    }

    /// Iterate the media-range parameters as `body.Param` (`{ name, value }`).
    pub fn paramsIter(self: MediaRange) body.ParamIterator {
        return .{ .rest = self.params };
    }
};

/// A lenient, allocation-free iterator over an `Accept` header's elements.
/// `next` yields one well-formed `MediaRange` at a time (skipping malformed
/// elements) and null at the end.
pub const Accept = struct {
    /// The remaining header text, advanced by `next`.
    rest: []const u8,

    /// Yield the next well-formed media-range, or null at the end. Malformed
    /// elements (no `/`, empty type/subtype, bad q) are skipped.
    pub fn next(self: *Accept) ?MediaRange {
        while (true) {
            // Skip leading OWS and stray commas (the #rule allows empty
            // elements).
            self.rest = std.mem.trimStart(u8, self.rest, " \t,");
            if (self.rest.len == 0) return null;
            // ',' only ever separates elements — it cannot appear inside a
            // media-range or a qvalue — so a plain scalar scan is safe.
            const end = std.mem.indexOfScalar(u8, self.rest, ',') orelse self.rest.len;
            const elem = std.mem.trim(u8, self.rest[0..end], " \t");
            self.rest = if (end < self.rest.len) self.rest[end + 1 ..] else "";
            if (parseElement(elem)) |mr| return mr;
            // Malformed element — lenient: skip it and try the next one.
        }
    }
};

/// Build an `Accept` iterator over a raw `Accept` header value.
pub fn accept(header: []const u8) Accept {
    return .{ .rest = header };
}

/// Parse a whole `Accept` header into `out`, returning the filled prefix
/// (well-formed elements only, in header order). Stops at `out.len`.
pub fn parse(header: []const u8, out: []MediaRange) []MediaRange {
    var it = accept(header);
    var n: usize = 0;
    while (n < out.len) : (n += 1) {
        out[n] = it.next() orelse break;
    }
    return out[0..n];
}

/// Parse ONE already-comma-split, OWS-trimmed `Accept` element
/// (`text/html;level=1;q=0.8`) into a `MediaRange`, or null if malformed.
/// Exposed for tests; `Accept.next` calls it.
pub fn parseElement(elem: []const u8) ?MediaRange {
    // Split media-range vs params at the first ';' (media types never quote
    // before the first ';', so a plain scalar scan is fine here).
    const semi = std.mem.indexOfScalar(u8, elem, ';');
    const range = std.mem.trim(u8, if (semi) |i| elem[0..i] else elem, " \t");
    const tail = if (semi) |i| elem[i + 1 ..] else "";

    // Parse "type/subtype".
    const slash = std.mem.indexOfScalar(u8, range, '/') orelse return null;
    const type_ = std.mem.trim(u8, range[0..slash], " \t");
    const subtype_ = std.mem.trim(u8, range[slash + 1 ..], " \t");
    if (type_.len == 0 or subtype_.len == 0) return null;

    // Walk the tail as ';'-separated params, tracking byte offsets so the
    // pre-`q` section can be captured as a slice. The first param named "q"
    // (case-insensitive) is the weight boundary; anything after it is
    // accept-ext and ignored.
    var params_: []const u8 = std.mem.trim(u8, tail, " \t;");
    var weight: u16 = q_default;
    var pos: usize = 0;
    while (pos < tail.len) {
        const seg_end = std.mem.indexOfScalarPos(u8, tail, pos, ';') orelse tail.len;
        const seg = tail[pos..seg_end];
        const eq = std.mem.indexOfScalar(u8, seg, '=') orelse seg.len;
        const name = std.mem.trim(u8, seg[0..eq], " \t");
        if (std.ascii.eqlIgnoreCase(name, "q")) {
            const value = if (eq < seg.len) seg[eq + 1 ..] else "";
            weight = parseQvalue(value) orelse return null;
            params_ = std.mem.trim(u8, tail[0..pos], " \t;");
            break;
        }
        pos = seg_end + 1;
    }

    return .{ .type = type_, .subtype = subtype_, .weight = weight, .params = params_ };
}

/// Parse an RFC 9110 §12.4.2 `qvalue` ("0", "0.8", "0.05", "1", "1.000") into
/// milli-units (0..1000). Returns null when malformed or > 1.000.
pub fn parseQvalue(s: []const u8) ?u16 {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return null;
    if (t[0] != '0' and t[0] != '1') return null;
    var milli: u16 = if (t[0] == '1') 1000 else 0;
    if (t.len == 1) return milli;
    if (t[1] != '.') return null;
    const frac = t[2..];
    if (frac.len == 0 or frac.len > 3) return null;
    var scale: u16 = 100;
    for (frac) |c| {
        if (!std.ascii.isDigit(c)) return null;
        milli += @as(u16, c - '0') * scale;
        scale /= 10;
    }
    if (milli > q_max) return null;
    return milli;
}

const testing = std.testing;

test "parseQvalue: well-formed values in milli-units" {
    try testing.expectEqual(@as(u16, 0), parseQvalue("0").?);
    try testing.expectEqual(@as(u16, 1000), parseQvalue("1").?);
    try testing.expectEqual(@as(u16, 800), parseQvalue("0.8").?);
    try testing.expectEqual(@as(u16, 50), parseQvalue("0.05").?);
    try testing.expectEqual(@as(u16, 500), parseQvalue("0.5").?);
    try testing.expectEqual(@as(u16, 333), parseQvalue("0.333").?);
    try testing.expectEqual(@as(u16, 1000), parseQvalue("1.000").?);
    try testing.expectEqual(@as(u16, 1000), parseQvalue("1.0").?);
    try testing.expectEqual(@as(u16, 0), parseQvalue("0.0").?);
    try testing.expectEqual(@as(u16, 0), parseQvalue("0.000").?);
    // OWS around the value is tolerated.
    try testing.expectEqual(@as(u16, 800), parseQvalue(" 0.8 ").?);
}

test "parseQvalue: malformed or out-of-range -> null" {
    try testing.expect(parseQvalue("") == null);
    try testing.expect(parseQvalue("2") == null);
    try testing.expect(parseQvalue("1.5") == null);
    try testing.expect(parseQvalue("1.001") == null);
    try testing.expect(parseQvalue("0.") == null);
    try testing.expect(parseQvalue("0.1234") == null);
    try testing.expect(parseQvalue("abc") == null);
    try testing.expect(parseQvalue("-0.1") == null);
    try testing.expect(parseQvalue(".5") == null);
    try testing.expect(parseQvalue("0,8") == null);
    try testing.expect(parseQvalue("0.8x") == null);
}

test "MediaRange.matches: wildcards and case-insensitivity" {
    const any: MediaRange = .{ .type = "*", .subtype = "*", .weight = q_default };
    try testing.expect(any.matches("text", "html"));
    try testing.expect(any.matches("image", "png"));

    const text_any: MediaRange = .{ .type = "text", .subtype = "*", .weight = q_default };
    try testing.expect(text_any.matches("text", "html"));
    try testing.expect(text_any.matches("text", "plain"));
    try testing.expect(!text_any.matches("image", "png"));

    const text_html: MediaRange = .{ .type = "text", .subtype = "html", .weight = q_default };
    try testing.expect(text_html.matches("text", "html"));
    try testing.expect(text_html.matches("TEXT", "HTML"));
    try testing.expect(!text_html.matches("text", "plain"));
    try testing.expect(!text_html.matches("image", "html"));

    const upper: MediaRange = .{ .type = "Text", .subtype = "Html", .weight = q_default };
    try testing.expect(upper.matches("text", "html"));
}

test "MediaRange.specificity: */* -> 0, type/* -> 1, type/subtype -> 2" {
    const any: MediaRange = .{ .type = "*", .subtype = "*", .weight = q_default };
    const text_any: MediaRange = .{ .type = "text", .subtype = "*", .weight = q_default };
    const text_html: MediaRange = .{ .type = "text", .subtype = "html", .weight = q_default };
    try testing.expectEqual(@as(u2, 0), any.specificity());
    try testing.expectEqual(@as(u2, 1), text_any.specificity());
    try testing.expectEqual(@as(u2, 2), text_html.specificity());
}

test "parseElement: bare media type -> q=1000, no params" {
    const mr = parseElement("text/html").?;
    try testing.expectEqualStrings("text", mr.type);
    try testing.expectEqualStrings("html", mr.subtype);
    try testing.expectEqual(q_default, mr.weight);
    try testing.expectEqualStrings("", mr.params);
}

test "parseElement: weight only" {
    const mr = parseElement("application/json;q=0.9").?;
    try testing.expectEqualStrings("application", mr.type);
    try testing.expectEqualStrings("json", mr.subtype);
    try testing.expectEqual(@as(u16, 900), mr.weight);
    try testing.expectEqualStrings("", mr.params);
}

test "parseElement: media-range params before q" {
    const mr = parseElement("text/html;level=1;q=0.8").?;
    try testing.expectEqualStrings("text", mr.type);
    try testing.expectEqualStrings("html", mr.subtype);
    try testing.expectEqual(@as(u16, 800), mr.weight);
    try testing.expectEqualStrings("level=1", mr.params);
    try testing.expectEqualStrings("1", mr.param("level").?);
    try testing.expect(mr.param("missing") == null);
}

test "parseElement: accept-ext after q is ignored" {
    const mr = parseElement("text/html;level=1;q=0.8;ext=token").?;
    try testing.expectEqual(@as(u16, 800), mr.weight);
    try testing.expectEqualStrings("level=1", mr.params);
    try testing.expect(mr.param("ext") == null);
}

test "parseElement: params without q -> whole tail, q=1000" {
    const mr = parseElement("text/html;level=1;charset=utf-8").?;
    try testing.expectEqual(q_default, mr.weight);
    try testing.expectEqualStrings("level=1;charset=utf-8", mr.params);
    try testing.expectEqualStrings("1", mr.param("level").?);
    try testing.expectEqualStrings("utf-8", mr.param("charset").?);
}

test "parseElement: wildcard with q=0" {
    const mr = parseElement("*/*;q=0").?;
    try testing.expectEqualStrings("*", mr.type);
    try testing.expectEqualStrings("*", mr.subtype);
    try testing.expectEqual(@as(u16, 0), mr.weight);
    try testing.expectEqual(@as(u2, 0), mr.specificity());
}

test "parseElement: OWS around ';' and q name case-insensitive" {
    const mr = parseElement("text/html ; level=1 ; Q=0.5").?;
    try testing.expectEqual(@as(u16, 500), mr.weight);
    try testing.expectEqualStrings("1", mr.param("level").?);
}

test "parseElement: malformed -> null" {
    try testing.expect(parseElement("text") == null);
    try testing.expect(parseElement("/html") == null);
    try testing.expect(parseElement("text/") == null);
    try testing.expect(parseElement("text/html;q=2") == null);
    try testing.expect(parseElement("text/html;q=") == null);
    try testing.expect(parseElement("text/html;q=abc") == null);
}

test "accept: typical browser header" {
    var it = accept("text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8");

    const a = it.next().?;
    try testing.expectEqualStrings("text", a.type);
    try testing.expectEqualStrings("html", a.subtype);
    try testing.expectEqual(q_default, a.weight);

    const b = it.next().?;
    try testing.expectEqualStrings("application", b.type);
    try testing.expectEqualStrings("xhtml+xml", b.subtype);
    try testing.expectEqual(q_default, b.weight);

    const c = it.next().?;
    try testing.expectEqualStrings("application", c.type);
    try testing.expectEqualStrings("xml", c.subtype);
    try testing.expectEqual(@as(u16, 900), c.weight);

    const d = it.next().?;
    try testing.expectEqualStrings("*", d.type);
    try testing.expectEqualStrings("*", d.subtype);
    try testing.expectEqual(@as(u16, 800), d.weight);

    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null); // stays exhausted
}

test "accept: stray commas are skipped" {
    var it = accept("text/html,,application/json");
    try testing.expectEqualStrings("html", it.next().?.subtype);
    try testing.expectEqualStrings("json", it.next().?.subtype);
    try testing.expect(it.next() == null);
}

test "accept: empty header yields no elements" {
    var it = accept("");
    try testing.expect(it.next() == null);

    var ws = accept("  , ,\t");
    try testing.expect(ws.next() == null);
}

test "accept: malformed element in the middle is skipped" {
    var it = accept("text/html, garbage, image/png;q=0.5");
    try testing.expectEqualStrings("html", it.next().?.subtype);
    const png = it.next().?;
    try testing.expectEqualStrings("png", png.subtype);
    try testing.expectEqual(@as(u16, 500), png.weight);
    try testing.expect(it.next() == null);
}

test "parse: fills the prefix in header order" {
    var buf: [8]MediaRange = undefined;
    const list = parse("application/xml;q=0.9, */*;q=0.8, text/html", &buf);
    try testing.expectEqual(@as(usize, 3), list.len);
    try testing.expectEqualStrings("xml", list[0].subtype);
    try testing.expectEqual(@as(u16, 900), list[0].weight);
    try testing.expectEqualStrings("*", list[1].type);
    try testing.expectEqual(@as(u16, 800), list[1].weight);
    try testing.expectEqualStrings("html", list[2].subtype);
    try testing.expectEqual(q_default, list[2].weight);

    // Stops at out.len.
    var small: [2]MediaRange = undefined;
    const capped = parse("a/b, c/d, e/f", &small);
    try testing.expectEqual(@as(usize, 2), capped.len);
    try testing.expectEqualStrings("a", capped[0].type);
    try testing.expectEqualStrings("d", capped[1].subtype);
}
