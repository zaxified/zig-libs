// SPDX-License-Identifier: MIT

//! Proactive content negotiation (RFC 9110 §12) — a full `Accept` /
//! `Accept-Language` / `Accept-Encoding` parser + negotiator.
//!
//! Three layers:
//!  - **N1** — the `Accept` media-range + q-value parser (`MediaRange`,
//!    `accept`/`parse`, `parseQvalue`); pure syntax.
//!  - **N2** — `negotiate(accept, offers)`: match the client's media-ranges
//!    against the server's offered media types and pick the best (most-specific
//!    range → highest weight → server preference), null → 406.
//!    `negotiateContentType(req, offers)` is the request-header convenience.
//!  - **N3** — the sibling `Accept-Language` (RFC 4647 §3.3.1 basic filtering,
//!    `negotiateLanguage`) and `Accept-Encoding` (RFC 9110 §12.5.3,
//!    `encodingQuality`/`negotiateEncoding` with the implicit-`identity` rules),
//!    over a shared `#( token [weight] )` `TokenList`.
//!
//! Everything is allocation-free and float-free (weights are integer
//! milli-units). N1 is documented immediately below; N2 and N3 follow.
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
const Server = @import("Server.zig");

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

// ── N2: negotiate a representation against the client's Accept (RFC 9110 §12.5.1) ──

/// The outcome of `negotiate`: which server offer won, and the quality the
/// client assigned it.
pub const Negotiated = struct {
    /// Index of the winning entry in the `offers` slice passed to `negotiate`.
    index: usize,
    /// The winning media type (aliases `offers[index]`).
    media_type: []const u8,
    /// The `q` weight (milli-units, 1..1000) of the most-specific `Accept`
    /// range that selected this offer. `q_default` when the client sent no
    /// `Accept` (everything is acceptable).
    weight: u16,
};

/// Choose the best representation for the client's `Accept` header from the
/// server's `offers` (concrete `type/subtype` media types, in server-preference
/// order — earlier = preferred on ties). Returns null → the caller responds
/// **406 Not Acceptable** (no offer matched, or every match was `q=0`).
///
/// Per RFC 9110 §12.5.1: an offer's quality is the weight of the **most
/// specific** `Accept` range that matches it (`type/subtype` beats `type/*`
/// beats `*/*`); the winner is the acceptable offer with the highest such
/// weight, ties broken by server preference (offer order). An absent/empty
/// `Accept` (no ranges) means "anything" — the first well-formed offer wins at
/// `q_default`.
pub fn negotiate(accept_header: []const u8, offers: []const []const u8) ?Negotiated {
    // Step A — empty-Accept shortcut: no ranges at all means the client
    // accepts anything → the first well-formed offer wins at q_default.
    var probe = accept(accept_header);
    if (probe.next() == null) {
        for (offers, 0..) |offer, i| {
            if (splitType(offer) == null) continue;
            return .{ .index = i, .media_type = offer, .weight = q_default };
        }
        return null;
    }

    // Step B — score each offer independently by the most specific matching
    // range, then keep the highest-weight acceptable offer (ties → earliest).
    var best: ?Negotiated = null;
    for (offers, 0..) |offer, i| {
        const ot = splitType(offer) orelse continue; // skip malformed offers
        // Find this offer's best-matching range: highest specificity, then
        // (on equal specificity) highest weight, then earliest position.
        var matched = false;
        var best_spec: i8 = -1;
        var best_weight: u16 = 0;
        var it = accept(accept_header);
        while (it.next()) |mr| {
            if (!mr.matches(ot.type, ot.subtype)) continue;
            const spec: i8 = mr.specificity();
            if (!matched or spec > best_spec or (spec == best_spec and mr.weight > best_weight)) {
                matched = true;
                best_spec = spec;
                best_weight = mr.weight;
            }
        }
        if (!matched or best_weight == 0) continue; // unacceptable (no match / q=0)
        // Keep the highest-weight offer; ties → earliest (so strict >).
        if (best == null or best_weight > best.?.weight) {
            best = .{ .index = i, .media_type = offer, .weight = best_weight };
        }
    }
    return best;
}

/// Convenience over `negotiate` reading the request's `Accept` header directly
/// (absent header → treated as "anything", so the first offer wins).
pub fn negotiateContentType(req: *const Server.Request, offers: []const []const u8) ?Negotiated {
    return negotiate(req.header("accept") orelse "", offers);
}

/// A concrete `type/subtype` split of a server offer.
const TypePair = struct { type: []const u8, subtype: []const u8 };

/// Split an offered media type `type/subtype` (OWS-trimmed, both parts
/// non-empty). Returns null for a malformed offer (no `/`, empty half). Any
/// `;`-parameters on the offer are ignored (an offer is matched by type only).
fn splitType(mt: []const u8) ?TypePair {
    const semi = std.mem.indexOfScalar(u8, mt, ';');
    const range = std.mem.trim(u8, if (semi) |i| mt[0..i] else mt, " \t");
    const slash = std.mem.indexOfScalar(u8, range, '/') orelse return null;
    const type_ = std.mem.trim(u8, range[0..slash], " \t");
    const subtype_ = std.mem.trim(u8, range[slash + 1 ..], " \t");
    if (type_.len == 0 or subtype_.len == 0) return null;
    return .{ .type = type_, .subtype = subtype_ };
}

// ── N3: Accept-Language (RFC 4647) + Accept-Encoding (RFC 9110 §12.5.3) ───────
//
// Both headers share the shape `#( token [ weight ] )` — a comma-separated list
// of a bare token (a language-range or a content-coding) with an optional `;q=`
// weight — which is simpler than a media-range (no `/`, no media params). The
// `TokenList` iterator + `parseTokenElement` below parse that shared shape,
// reusing N1's `parseQvalue`; the language and encoding helpers layer their
// matching rules on top.

/// One `#( token [weight] )` element: a bare token with its quality weight.
pub const WeightedToken = struct {
    /// The token as written (a language-range like `en-US` or a content-coding
    /// like `gzip`; may be `*`). Compare case-insensitively.
    token: []const u8,
    /// Quality in milli-units 0..1000 (`q_default` when no `;q=`). `q=0` =
    /// "not acceptable".
    weight: u16,
};

/// A lenient, allocation-free iterator over an `Accept-Language` /
/// `Accept-Encoding` header (a `#( token [weight] )` list). Skips malformed
/// elements, null at the end.
pub const TokenList = struct {
    /// Remaining header text, advanced by `next`.
    rest: []const u8,

    /// Yield the next well-formed weighted token, or null at the end.
    pub fn next(self: *TokenList) ?WeightedToken {
        while (true) {
            // Skip leading OWS and stray commas (the #rule allows empty
            // elements).
            self.rest = std.mem.trimStart(u8, self.rest, " \t,");
            if (self.rest.len == 0) return null;
            const end = std.mem.indexOfScalar(u8, self.rest, ',') orelse self.rest.len;
            const elem = std.mem.trim(u8, self.rest[0..end], " \t");
            self.rest = if (end < self.rest.len) self.rest[end + 1 ..] else "";
            if (parseTokenElement(elem)) |wt| return wt;
            // Malformed element — lenient: skip it and try the next one.
        }
    }
};

/// Build a `TokenList` over a raw `Accept-Language` / `Accept-Encoding` value.
pub fn tokenList(header: []const u8) TokenList {
    return .{ .rest = header };
}

/// Parse ONE already-comma-split, OWS-trimmed element (`gzip;q=0.5`, `en-US`,
/// `*`) into a `WeightedToken`, or null if malformed.
pub fn parseTokenElement(elem: []const u8) ?WeightedToken {
    // Split token vs params at the first ';'.
    const semi = std.mem.indexOfScalar(u8, elem, ';');
    const token = std.mem.trim(u8, if (semi) |i| elem[0..i] else elem, " \t");
    const tail = if (semi) |i| elem[i + 1 ..] else "";
    if (token.len == 0) return null;

    // Walk the tail as ';'-separated params; the first param named "q"
    // (case-insensitive) is the weight. Anything else is ignored.
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
            break;
        }
        pos = seg_end + 1;
    }

    return .{ .token = token, .weight = weight };
}

// ── Accept-Language (RFC 4647 §3.3.1 basic filtering) ────────────────────────

/// RFC 4647 §3.3.1 **basic filtering**: does language-range `range` match
/// language `tag`? Case-insensitive. `*` matches any tag. Otherwise `range`
/// matches iff it equals `tag` OR is a prefix of `tag` at a subtag boundary —
/// i.e. `tag` equals `range` or begins with `range` immediately followed by a
/// `-`. So `en` matches `en`, `en-US`, `en-GB-oxendict`; `en-US` matches `en-US`
/// and `en-US-x-…` but NOT `en` or `en-GB`.
pub fn languageMatches(range: []const u8, tag: []const u8) bool {
    if (std.mem.eql(u8, range, "*")) return true;
    if (std.ascii.eqlIgnoreCase(range, tag)) return true;
    return tag.len > range.len and tag[range.len] == '-' and
        std.ascii.eqlIgnoreCase(range, tag[0..range.len]);
}

/// Pick the best language for an `Accept-Language` header from the server's
/// offered `tags` (concrete language tags, server-preference order). Mirrors
/// `negotiate`: each offer's quality is the weight of the **most specific**
/// matching range (specificity = subtag count of the range, `*` = 0); the winner
/// is the highest-weight acceptable offer, ties → server preference; no-match /
/// `q=0` dropped; null → 406. Empty/absent header → the first offer at
/// `q_default`.
pub fn negotiateLanguage(header: []const u8, tags: []const []const u8) ?Negotiated {
    // Step A — empty-header shortcut: no ranges at all means the client
    // accepts anything → the first tag wins at q_default.
    var probe = tokenList(header);
    if (probe.next() == null) {
        if (tags.len == 0) return null;
        return .{ .index = 0, .media_type = tags[0], .weight = q_default };
    }

    // Step B — score each tag independently by the most specific matching
    // range, then keep the highest-weight acceptable tag (ties → earliest).
    var best: ?Negotiated = null;
    for (tags, 0..) |tag, i| {
        // Find this tag's best-matching range: highest specificity, then
        // (on equal specificity) highest weight, then earliest position.
        var matched = false;
        var best_spec: i16 = -1;
        var best_weight: u16 = 0;
        var it = tokenList(header);
        while (it.next()) |wt| {
            if (!languageMatches(wt.token, tag)) continue;
            const spec: i16 = subtagCount(wt.token);
            if (!matched or spec > best_spec or (spec == best_spec and wt.weight > best_weight)) {
                matched = true;
                best_spec = spec;
                best_weight = wt.weight;
            }
        }
        if (!matched or best_weight == 0) continue; // unacceptable (no match / q=0)
        // Keep the highest-weight tag; ties → earliest (so strict >).
        if (best == null or best_weight > best.?.weight) {
            best = .{ .index = i, .media_type = tag, .weight = best_weight };
        }
    }
    return best;
}

/// Subtag count of a language-range for specificity: `*` → 0, otherwise
/// 1 + the number of `-` separators (`en` → 1, `en-US` → 2).
fn subtagCount(range: []const u8) u8 {
    if (std.mem.eql(u8, range, "*")) return 0;
    const dashes: u8 = @intCast(std.mem.count(u8, range, "-"));
    return 1 + dashes;
}

// ── Accept-Encoding (RFC 9110 §12.5.3) ───────────────────────────────────────

/// The acceptability weight of content-coding `coding` (a concrete token like
/// `gzip`, `br`, `identity`; never `*`) under an `Accept-Encoding` header, or
/// null if `coding` is **not acceptable** (RFC 9110 §12.5.3). Rules:
///   - an explicit (case-insensitive) token entry decides it: its weight, or
///     null when `q=0`;
///   - else a `*` entry decides it: its weight, or null when `q=0`;
///   - else `identity` is implicitly acceptable (`q_default`) — any other
///     unmentioned coding is not acceptable (null);
///   - an absent/empty header accepts anything (`q_default`).
/// (These rules make `identity` acceptable by default unless excluded by
/// `identity;q=0` or a bare `*;q=0` with no identity override.)
pub fn encodingQuality(header: []const u8, coding: []const u8) ?u16 {
    var explicit: ?u16 = null;
    var star: ?u16 = null;
    var any = false;
    var it = tokenList(header);
    while (it.next()) |wt| {
        any = true;
        if (explicit == null and std.ascii.eqlIgnoreCase(wt.token, coding)) {
            explicit = wt.weight;
        } else if (star == null and std.mem.eql(u8, wt.token, "*")) {
            star = wt.weight;
        }
    }
    if (!any) return q_default; // empty/absent header → accept anything
    if (explicit) |w| return if (w > 0) w else null;
    if (star) |w| return if (w > 0) w else null;
    if (std.ascii.eqlIgnoreCase(coding, "identity")) return q_default;
    return null;
}

/// Pick the best content-coding for an `Accept-Encoding` header from the
/// server's offered `codings` (server-preference order). Each offer's quality is
/// `encodingQuality(header, coding)`; the highest-quality acceptable offer wins,
/// ties → server preference; null when none is acceptable (the caller then
/// serves `identity`, which is itself acceptable unless the header forbade it —
/// test with `encodingQuality(header, "identity")`).
pub fn negotiateEncoding(header: []const u8, codings: []const []const u8) ?Negotiated {
    var best: ?Negotiated = null;
    for (codings, 0..) |coding, i| {
        const q = encodingQuality(header, coding) orelse continue;
        if (q == 0) continue; // encodingQuality already nulls q=0, but be safe
        if (best == null or q > best.?.weight) {
            best = .{ .index = i, .media_type = coding, .weight = q };
        }
    }
    return best;
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

test "negotiate: most specific range wins" {
    const offers = [_][]const u8{ "text/html", "text/plain" };
    const n = negotiate("text/*;q=0.5, text/html;q=0.8", &offers).?;
    // text/html gets the specific range's q=0.8 (beats the text/* range);
    // text/plain only matches text/* at q=0.5.
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("text/html", n.media_type);
    try testing.expectEqual(@as(u16, 800), n.weight);
}

test "negotiate: highest weight across offers" {
    const offers = [_][]const u8{ "text/html", "application/json" };
    const n = negotiate("application/json;q=0.9, text/html;q=0.4", &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("application/json", n.media_type);
    try testing.expectEqual(@as(u16, 900), n.weight);
}

test "negotiate: server preference breaks a weight tie" {
    const offers = [_][]const u8{ "application/json", "text/html" };
    const n = negotiate("*/*", &offers).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("application/json", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}

test "negotiate: q=0 excludes an offer" {
    // The only offer's most-specific match is q=0 → nothing acceptable.
    const only = [_][]const u8{"text/html"};
    try testing.expect(negotiate("text/*, text/html;q=0", &only) == null);

    // With a second offer, the excluded one is skipped and text/plain wins
    // via the text/* range at q=1000.
    const offers = [_][]const u8{ "text/html", "text/plain" };
    const n = negotiate("text/*, text/html;q=0", &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("text/plain", n.media_type);
    try testing.expectEqual(@as(u16, 1000), n.weight);
}

test "negotiate: no matching range -> null" {
    const offers = [_][]const u8{"text/html"};
    try testing.expect(negotiate("application/json", &offers) == null);
}

test "negotiate: empty Accept -> first well-formed offer at q_default" {
    const offers = [_][]const u8{ "text/html", "application/json" };
    const n = negotiate("", &offers).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("text/html", n.media_type);
    try testing.expectEqual(q_default, n.weight);

    // Whitespace/comma-only header also counts as "no ranges".
    const ws = negotiate("  , ,\t", &offers).?;
    try testing.expectEqual(@as(usize, 0), ws.index);

    // Malformed leading offer is skipped even on the empty-Accept path.
    const bad_first = [_][]const u8{ "garbage", "application/json" };
    const nb = negotiate("", &bad_first).?;
    try testing.expectEqual(@as(usize, 1), nb.index);
    try testing.expectEqual(q_default, nb.weight);

    // No well-formed offer at all → null.
    const all_bad = [_][]const u8{ "garbage", "/x", "y/" };
    try testing.expect(negotiate("", &all_bad) == null);
}

test "negotiate: malformed offer is skipped" {
    const offers = [_][]const u8{ "garbage", "text/html" };
    const n = negotiate("text/html", &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("text/html", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}

test "negotiate: offer parameters are ignored when matching" {
    const offers = [_][]const u8{"text/html;charset=utf-8"};
    const n = negotiate("text/html", &offers).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    // media_type aliases the offer verbatim, params and all.
    try testing.expectEqualStrings("text/html;charset=utf-8", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}

test "negotiateContentType: reads the request's Accept header" {
    const offers = [_][]const u8{ "text/html", "application/json" };

    var body_none: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = .get,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = "GET",
            .target = "/",
            .http1_0 = false,
            .header_block = "Accept: application/json\r\n",
        },
        .body = &body_none,
        .context = null,
    };
    const n = negotiateContentType(&req, &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("application/json", n.media_type);
    try testing.expectEqual(q_default, n.weight);

    // Absent Accept header → "anything" → the first offer wins.
    var body_none2: Server.RequestBody = .{ .none = .fixed("") };
    const bare: Server.Request = .{
        .method = .get,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = "GET",
            .target = "/",
            .http1_0 = false,
            .header_block = "",
        },
        .body = &body_none2,
        .context = null,
    };
    const nb = negotiateContentType(&bare, &offers).?;
    try testing.expectEqual(@as(usize, 0), nb.index);
    try testing.expectEqualStrings("text/html", nb.media_type);
    try testing.expectEqual(q_default, nb.weight);
}

test "parseTokenElement: bare token -> q=1000" {
    const gz = parseTokenElement("gzip").?;
    try testing.expectEqualStrings("gzip", gz.token);
    try testing.expectEqual(q_default, gz.weight);

    const en = parseTokenElement("en-US").?;
    try testing.expectEqualStrings("en-US", en.token);
    try testing.expectEqual(q_default, en.weight);

    const star = parseTokenElement("*").?;
    try testing.expectEqualStrings("*", star.token);
    try testing.expectEqual(q_default, star.weight);
}

test "parseTokenElement: explicit weight" {
    const gz = parseTokenElement("gzip;q=0.5").?;
    try testing.expectEqualStrings("gzip", gz.token);
    try testing.expectEqual(@as(u16, 500), gz.weight);

    const star = parseTokenElement("*;q=0").?;
    try testing.expectEqualStrings("*", star.token);
    try testing.expectEqual(@as(u16, 0), star.weight);

    // OWS around ';' and case-insensitive q name.
    const ows = parseTokenElement("br ; Q=0.9").?;
    try testing.expectEqualStrings("br", ows.token);
    try testing.expectEqual(@as(u16, 900), ows.weight);
}

test "parseTokenElement: malformed -> null" {
    try testing.expect(parseTokenElement("") == null);
    try testing.expect(parseTokenElement("gzip;q=2") == null);
    try testing.expect(parseTokenElement("gzip;q=") == null);
    try testing.expect(parseTokenElement(";q=0.5") == null);
}

test "tokenList: typical Accept-Encoding header" {
    var it = tokenList("gzip, br;q=0.9, *;q=0");

    const a = it.next().?;
    try testing.expectEqualStrings("gzip", a.token);
    try testing.expectEqual(q_default, a.weight);

    const b = it.next().?;
    try testing.expectEqualStrings("br", b.token);
    try testing.expectEqual(@as(u16, 900), b.weight);

    const c = it.next().?;
    try testing.expectEqualStrings("*", c.token);
    try testing.expectEqual(@as(u16, 0), c.weight);

    try testing.expect(it.next() == null);
    try testing.expect(it.next() == null); // stays exhausted
}

test "tokenList: stray commas are skipped" {
    var it = tokenList("gzip,,br");
    try testing.expectEqualStrings("gzip", it.next().?.token);
    try testing.expectEqualStrings("br", it.next().?.token);
    try testing.expect(it.next() == null);
}

test "tokenList: empty header yields no elements" {
    var it = tokenList("");
    try testing.expect(it.next() == null);

    var ws = tokenList("  , ,\t");
    try testing.expect(ws.next() == null);
}

test "tokenList: malformed element in the middle is skipped" {
    var it = tokenList("gzip, br;q=abc, deflate;q=0.5");
    try testing.expectEqualStrings("gzip", it.next().?.token);
    const d = it.next().?;
    try testing.expectEqualStrings("deflate", d.token);
    try testing.expectEqual(@as(u16, 500), d.weight);
    try testing.expect(it.next() == null);
}

test "languageMatches: wildcard and exact" {
    try testing.expect(languageMatches("*", "en-US"));
    try testing.expect(languageMatches("*", "fr"));
    try testing.expect(languageMatches("en", "en"));
    try testing.expect(languageMatches("en-US", "en-US"));
}

test "languageMatches: prefix at a subtag boundary" {
    try testing.expect(languageMatches("en", "en-US"));
    try testing.expect(languageMatches("en", "en-GB-x-a"));
    try testing.expect(!languageMatches("en", "eng")); // not at a '-' boundary
    try testing.expect(!languageMatches("e", "en")); // ditto
    try testing.expect(languageMatches("en-US", "en-US-x-1"));
    try testing.expect(!languageMatches("en-US", "en"));
    try testing.expect(!languageMatches("en-US", "en-GB"));
}

test "languageMatches: case-insensitive" {
    try testing.expect(languageMatches("EN", "en-us"));
    try testing.expect(languageMatches("en-us", "en-US"));
    try testing.expect(languageMatches("EN-US", "en-us-x-1"));
}

test "subtagCount: * -> 0, en -> 1, en-US -> 2" {
    try testing.expectEqual(@as(u8, 0), subtagCount("*"));
    try testing.expectEqual(@as(u8, 1), subtagCount("en"));
    try testing.expectEqual(@as(u8, 2), subtagCount("en-US"));
    try testing.expectEqual(@as(u8, 3), subtagCount("en-GB-oxendict"));
}

test "negotiateLanguage: most specific range wins" {
    const tags = [_][]const u8{ "en-US", "en-GB" };
    const n = negotiateLanguage("en;q=0.5, en-US;q=0.9", &tags).?;
    // en-US gets the specific range's q=0.9 (beats the bare en range);
    // en-GB only matches en at q=0.5.
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("en-US", n.media_type);
    try testing.expectEqual(@as(u16, 900), n.weight);
}

test "negotiateLanguage: highest weight across tags" {
    const tags = [_][]const u8{ "en", "de" };
    const n = negotiateLanguage("de;q=0.9, en;q=0.4", &tags).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("de", n.media_type);
    try testing.expectEqual(@as(u16, 900), n.weight);
}

test "negotiateLanguage: server preference breaks a weight tie" {
    const tags = [_][]const u8{ "fr", "de" };
    const n = negotiateLanguage("*", &tags).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("fr", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}

test "negotiateLanguage: q=0 excludes a tag" {
    // The only tag's most-specific match is q=0 → nothing acceptable.
    const only = [_][]const u8{"en-US"};
    try testing.expect(negotiateLanguage("en, en-US;q=0", &only) == null);

    // With a second tag, the excluded one is skipped and en-GB wins via the
    // bare en range at q=1000.
    const tags = [_][]const u8{ "en-US", "en-GB" };
    const n = negotiateLanguage("en, en-US;q=0", &tags).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("en-GB", n.media_type);
    try testing.expectEqual(@as(u16, 1000), n.weight);
}

test "negotiateLanguage: no matching range -> null" {
    const tags = [_][]const u8{"en"};
    try testing.expect(negotiateLanguage("fr, de;q=0.5", &tags) == null);
}

test "negotiateLanguage: empty header -> first tag at q_default" {
    const tags = [_][]const u8{ "en", "de" };
    const n = negotiateLanguage("", &tags).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("en", n.media_type);
    try testing.expectEqual(q_default, n.weight);

    // Whitespace/comma-only header also counts as "no ranges".
    const ws = negotiateLanguage("  , ,\t", &tags).?;
    try testing.expectEqual(@as(usize, 0), ws.index);

    // No tags at all → null even on the empty-header path.
    try testing.expect(negotiateLanguage("", &.{}) == null);
}

test "encodingQuality: explicit tokens and implicit identity" {
    const h = "gzip, br;q=0.8";
    try testing.expectEqual(@as(u16, 1000), encodingQuality(h, "gzip").?);
    try testing.expectEqual(@as(u16, 800), encodingQuality(h, "br").?);
    try testing.expectEqual(q_default, encodingQuality(h, "identity").?); // implicit
    try testing.expect(encodingQuality(h, "deflate") == null);
    // Case-insensitive coding match.
    try testing.expectEqual(@as(u16, 1000), encodingQuality(h, "GZIP").?);
}

test "encodingQuality: *;q=0 excludes everything unmentioned" {
    const h = "gzip, *;q=0";
    try testing.expectEqual(@as(u16, 1000), encodingQuality(h, "gzip").?);
    try testing.expect(encodingQuality(h, "br") == null);
    try testing.expect(encodingQuality(h, "identity") == null); // no override
}

test "encodingQuality: explicit identity override beats *;q=0" {
    const h = "*;q=0, identity;q=1";
    try testing.expectEqual(@as(u16, 1000), encodingQuality(h, "identity").?);
    try testing.expect(encodingQuality(h, "gzip") == null);
}

test "encodingQuality: explicit q=0 exclusions" {
    try testing.expect(encodingQuality("identity;q=0", "identity") == null);
    try testing.expect(encodingQuality("gzip;q=0", "gzip") == null);
}

test "encodingQuality: * with a positive weight applies to unmentioned codings" {
    const h = "gzip;q=0.5, *;q=0.3";
    try testing.expectEqual(@as(u16, 500), encodingQuality(h, "gzip").?);
    try testing.expectEqual(@as(u16, 300), encodingQuality(h, "br").?);
    try testing.expectEqual(@as(u16, 300), encodingQuality(h, "identity").?);
}

test "encodingQuality: empty header accepts anything" {
    try testing.expectEqual(q_default, encodingQuality("", "gzip").?);
    try testing.expectEqual(q_default, encodingQuality("", "identity").?);
    try testing.expectEqual(q_default, encodingQuality("  , ,\t", "br").?);
}

test "negotiateEncoding: highest quality wins" {
    const offers = [_][]const u8{ "gzip", "br" };
    const n = negotiateEncoding("br;q=1, gzip;q=0.5", &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("br", n.media_type);
    try testing.expectEqual(@as(u16, 1000), n.weight);
}

test "negotiateEncoding: *;q=0 excludes an offer" {
    const offers = [_][]const u8{ "br", "gzip" };
    const n = negotiateEncoding("gzip, *;q=0", &offers).?;
    try testing.expectEqual(@as(usize, 1), n.index);
    try testing.expectEqualStrings("gzip", n.media_type);
    try testing.expectEqual(@as(u16, 1000), n.weight);
}

test "negotiateEncoding: no acceptable offer -> null" {
    const offers = [_][]const u8{ "gzip", "br" };
    try testing.expect(negotiateEncoding("*;q=0", &offers) == null);
    try testing.expect(negotiateEncoding("deflate", &offers) == null);
}

test "negotiateEncoding: server preference breaks a weight tie" {
    const offers = [_][]const u8{ "br", "gzip" };
    const n = negotiateEncoding("*", &offers).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("br", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}

test "negotiateEncoding: empty header -> first offer at q_default" {
    const offers = [_][]const u8{ "gzip", "br" };
    const n = negotiateEncoding("", &offers).?;
    try testing.expectEqual(@as(usize, 0), n.index);
    try testing.expectEqualStrings("gzip", n.media_type);
    try testing.expectEqual(q_default, n.weight);
}
