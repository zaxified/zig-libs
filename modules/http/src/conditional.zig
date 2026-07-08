// SPDX-License-Identifier: MIT

//! Conditional requests (RFC 9110 §8.8 validators + §13 preconditions):
//! ETag / Last-Modified with `If-Match` / `If-None-Match` /
//! `If-Modified-Since` / `If-Unmodified-Since`, yielding **304 Not Modified**
//! (caches revalidate without re-transferring the body) or **412 Precondition
//! Failed** (optimistic-concurrency guard on unsafe methods — the lost-update
//! defense).
//!
//! The server core already suppresses the body of a 304 (`ResponseWriter`'s
//! `noBody()` treats 304/204/1xx as body-less and omits Content-Length), so
//! this layer is pure decision logic plus header emission: given the
//! representation's current validators (`ETag`, `Last-Modified`), read the
//! request's precondition headers, decide, and either stage the short-circuit
//! response or let the handler proceed.
//!
//! ## Usage
//!
//! ```zig
//! fn handler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) !void {
//!     const etag = "\"a1b2c3\""; // the current representation's entity-tag
//!     if (try http.conditional.apply(req, rw, .{ .etag = etag })) return;
//!     // proceed: ETag (and Last-Modified, if given) are already set on `rw`;
//!     // write the 200 body normally.
//!     rw.setStatus(200);
//!     try rw.writeAll(body);
//! }
//! ```
//!
//! ## Comparison rules (RFC 9110 §8.8.3.2)
//!
//! - `If-None-Match` uses the **weak** comparison (either tag may be weak; the
//!   `W/` flag is ignored, octets compared). It is the cache-revalidation and
//!   "don't overwrite if it exists" header.
//! - `If-Match` uses the **strong** comparison (both tags must be strong and
//!   octet-identical). It is the "only act if unchanged" header for unsafe
//!   methods.
//! - `*` matches any current representation (i.e. "the resource exists"). With
//!   a validator present here, the representation exists, so `*` matches.
//! - Dates (`If-Modified-Since` / `If-Unmodified-Since`) compare at
//!   one-second granularity against `Last-Modified`.

const std = @import("std");
const http = @import("root.zig");
const Server = @import("Server.zig");

/// A parsed entity-tag (RFC 9110 §8.8.3). `value` is the opaque-tag text
/// **including** its surrounding double quotes (as it travels on the wire);
/// `weak` is set when the `W/` prefix was present.
pub const ETag = struct {
    value: []const u8,
    weak: bool,

    /// Parse a single entity-tag: `"xyzzy"` → `.{ .value = "\"xyzzy\"", .weak
    /// = false }`, `W/"xyzzy"` → `.{ ..., .weak = true }`. Surrounding
    /// whitespace is tolerated. Returns null when `raw` is not a well-formed
    /// entity-tag (missing quotes, stray bytes). `*` is NOT an ETag — handle
    /// it at the list level.
    pub fn parse(raw: []const u8) ?ETag {
        var s = std.mem.trim(u8, raw, " \t");
        var weak = false;
        if (std.mem.startsWith(u8, s, "W/")) {
            weak = true;
            s = s[2..];
        }
        if (s.len < 2) return null;
        if (s[0] != '"' or s[s.len - 1] != '"') return null;
        // The inner etagc charset is not validated beyond the quotes — the
        // comparison is octet-exact anyway.
        return .{ .value = s, .weak = weak };
    }

    /// Strong comparison (RFC 9110 §8.8.3.2): true iff both tags are strong
    /// (not weak) and their quoted values are octet-identical.
    pub fn strongEql(a: ETag, b: ETag) bool {
        if (a.weak or b.weak) return false;
        return std.mem.eql(u8, a.value, b.value);
    }

    /// Weak comparison (RFC 9110 §8.8.3.2): true iff the quoted values are
    /// octet-identical, regardless of either tag's weak flag.
    pub fn weakEql(a: ETag, b: ETag) bool {
        return std.mem.eql(u8, a.value, b.value);
    }
};

/// The representation's current validators, supplied by the handler. Both are
/// optional: give whichever the resource can produce (an ETag is preferred;
/// `Last-Modified` is a weaker fallback). `etag` is the full entity-tag text
/// as it should appear on the wire (with quotes, optional `W/`);
/// `last_modified` is epoch seconds.
pub const Validators = struct {
    etag: ?[]const u8 = null,
    last_modified: ?i64 = null,
};

/// The precondition decision (RFC 9110 §13.2.2).
pub const Outcome = enum {
    /// No precondition blocked the request — serve it normally (200/…).
    proceed,
    /// A cache-revalidation precondition matched — respond 304, no body.
    not_modified,
    /// A guard precondition failed — respond 412, no body.
    precondition_failed,
};

/// Evaluate the request's preconditions against `v` in the RFC 9110 §13.2.2
/// order. Pure: reads only request headers, allocates nothing.
///
/// Precedence (first applicable wins):
///  1. `If-Match`            → fails (strong, `*`=exists) ⇒ 412.
///  2. `If-Unmodified-Since` → (only if no `If-Match`) modified since ⇒ 412.
///  3. `If-None-Match`       → matches (weak, `*`=exists) ⇒ 304 for GET/HEAD,
///                             else 412.
///  4. `If-Modified-Since`   → (only if no `If-None-Match`, GET/HEAD only) not
///                             modified since ⇒ 304.
///  5. otherwise             → proceed.
pub fn evaluate(method: http.Method, req: *const Server.Request, v: Validators) Outcome {
    const is_get_head = method == .get or method == .head;

    // Step 1 — If-Match (strong comparison; `*` matches because a validator
    // ⇒ the representation exists). A match falls through WITHOUT running
    // If-Unmodified-Since (§13.1.2/§13.2.2: If-Match takes precedence).
    if (req.header("if-match")) |list| {
        if (!listMatches(list, v.etag, false)) return .precondition_failed;
    }
    // Step 2 — If-Unmodified-Since (only when If-Match is absent). An
    // unparseable date is ignored (RFC 9110 §13.1.4).
    else if (req.header("if-unmodified-since")) |raw| {
        if (parseHttpDate(raw)) |since| {
            if (v.last_modified) |lm| {
                if (lm > since) return .precondition_failed;
            }
        }
    }

    // Step 3 — If-None-Match (weak comparison; `*` matches because the
    // representation exists). Present-but-no-match proceeds and SUPPRESSES
    // If-Modified-Since (§13.2.2).
    if (req.header("if-none-match")) |list| {
        if (listMatches(list, v.etag, true))
            return if (is_get_head) .not_modified else .precondition_failed;
    }
    // Step 4 — If-Modified-Since (GET/HEAD only, only when If-None-Match is
    // absent). An unparseable date is ignored.
    else if (is_get_head) {
        if (req.header("if-modified-since")) |raw| {
            if (parseHttpDate(raw)) |since| {
                if (v.last_modified) |lm| {
                    if (lm <= since) return .not_modified;
                }
            }
        }
    }

    // Step 5.
    return .proceed;
}

/// Evaluate `evaluate`, then stage the response and tell the caller whether to
/// stop. On `.not_modified` sets status 304, emits `ETag` (RFC 9110 §15.4.5)
/// and returns `true`. On `.precondition_failed` sets status 412 and returns
/// `true`. On `.proceed` emits `ETag` so the forthcoming 200 carries it, and
/// returns `false` (the handler writes the body). The server core drops the
/// body of a 304 automatically.
///
/// Only `ETag` is auto-emitted: the response writer stores header value
/// slices without copying, and `v.etag` is caller-owned so it outlives the
/// response. `Last-Modified` fully participates in the request-side
/// evaluation (`If-Modified-Since` / `If-Unmodified-Since`) but is NOT
/// auto-emitted — a formatted date would live in a dangling local buffer.
/// Handlers that want `Last-Modified` on the wire set it themselves from
/// stable memory (`Server.formatHttpDate` into a caller-kept buffer).
///
/// Header emission can only fail if the head was already sent or the table is
/// full (`SetHeaderError`) — call this before writing the body.
pub fn apply(
    req: *const Server.Request,
    rw: *Server.ResponseWriter,
    v: Validators,
) Server.ResponseWriter.SetHeaderError!bool {
    switch (evaluate(req.method, req, v)) {
        .precondition_failed => {
            rw.setStatus(412);
            return true;
        },
        .not_modified => {
            rw.setStatus(304);
            if (v.etag) |e| try rw.setHeader("ETag", e);
            return true;
        },
        .proceed => {
            if (v.etag) |e| try rw.setHeader("ETag", e);
            return false;
        },
    }
}

/// Whether a comma-separated entity-tag list header (`If-Match` /
/// `If-None-Match`) matches the representation's current `etag`. `weak`
/// selects the comparison (true = weak, for If-None-Match; false = strong, for
/// If-Match). A bare `*` element matches iff `current` is non-null (the
/// representation exists). Malformed elements are skipped.
fn listMatches(list: []const u8, current: ?[]const u8, weak: bool) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw| {
        const elem = std.mem.trim(u8, raw, " \t");
        if (elem.len == 0) continue;
        if (std.mem.eql(u8, elem, "*")) {
            if (current != null) return true;
            continue;
        }
        const tag = ETag.parse(elem) orelse continue;
        const cur = ETag.parse(current orelse continue) orelse continue;
        if (if (weak) tag.weakEql(cur) else tag.strongEql(cur)) return true;
    }
    return false;
}

/// Parse an HTTP-date (RFC 9110 §5.6.7) to epoch seconds, or null if invalid.
/// A conformant parser MUST accept all three formats, though only IMF-fixdate
/// is ever generated:
///  - IMF-fixdate:  `Sun, 06 Nov 1994 08:49:37 GMT`
///  - RFC 850 (obs): `Sunday, 06-Nov-94 08:49:37 GMT`
///  - asctime (obs): `Sun Nov  6 08:49:37 1994`
pub fn parseHttpDate(s: []const u8) ?i64 {
    // Dispatch: IMF-fixdate has its comma right after the 3-letter day name;
    // RFC 850 after the full day name; asctime has no comma at all.
    if (std.mem.indexOfScalar(u8, s, ',')) |comma| {
        if (comma == 3) return parseImfFixdate(s);
        return parseRfc850(s, comma);
    }
    return parseAsctime(s);
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` — fixed 29-byte layout.
fn parseImfFixdate(s: []const u8) ?i64 {
    if (s.len != 29) return null;
    if (!isDayName(s[0..3])) return null;
    if (s[3] != ',' or s[4] != ' ') return null;
    const day = parseDigits(s[5..7]) orelse return null;
    if (s[7] != ' ') return null;
    const month = monthFromName(s[8..11]) orelse return null;
    if (s[11] != ' ') return null;
    const year = parseDigits(s[12..16]) orelse return null;
    if (s[16] != ' ') return null;
    if (!std.mem.eql(u8, s[25..29], " GMT")) return null;
    return epochFrom(year, month, day, s[17..25]);
}

/// `Sunday, 06-Nov-94 08:49:37 GMT` — full day name, two-digit year. The
/// two-digit year uses a fixed pivot: 00–69 → 20xx, 70–99 → 19xx (we only
/// ever compare dates and never generate RFC 850, so a sliding window is
/// unnecessary).
fn parseRfc850(s: []const u8, comma: usize) ?i64 {
    if (!isFullDayName(s[0..comma])) return null;
    const rest = s[comma + 1 ..];
    // " 06-Nov-94 08:49:37 GMT"
    if (rest.len != 23 or rest[0] != ' ') return null;
    const day = parseDigits(rest[1..3]) orelse return null;
    if (rest[3] != '-') return null;
    const month = monthFromName(rest[4..7]) orelse return null;
    if (rest[7] != '-') return null;
    const yy = parseDigits(rest[8..10]) orelse return null;
    if (rest[10] != ' ') return null;
    if (!std.mem.eql(u8, rest[19..23], " GMT")) return null;
    const year: i64 = if (yy >= 70) 1900 + @as(i64, yy) else 2000 + @as(i64, yy);
    return epochFrom(year, month, day, rest[11..19]);
}

/// `Sun Nov  6 08:49:37 1994` — fixed 24-byte layout, day space-padded.
fn parseAsctime(s: []const u8) ?i64 {
    if (s.len != 24) return null;
    if (!isDayName(s[0..3]) or s[3] != ' ') return null;
    const month = monthFromName(s[4..7]) orelse return null;
    if (s[7] != ' ') return null;
    const day_text = if (s[8] == ' ') s[9..10] else s[8..10];
    const day = parseDigits(day_text) orelse return null;
    if (s[10] != ' ' or s[19] != ' ') return null;
    const year = parseDigits(s[20..24]) orelse return null;
    return epochFrom(year, month, day, s[11..19]);
}

/// Validate ranges (1..31 day, 0..23 h, 0..59 min, 0..60 s for leap-second
/// tolerance) and convert a broken-down UTC time + `HH:MM:SS` to epoch
/// seconds.
fn epochFrom(year: i64, month: u32, day: u32, tod: []const u8) ?i64 {
    if (day < 1 or day > 31) return null;
    if (tod.len != 8 or tod[2] != ':' or tod[5] != ':') return null;
    const hour = parseDigits(tod[0..2]) orelse return null;
    const min = parseDigits(tod[3..5]) orelse return null;
    const sec = parseDigits(tod[6..8]) orelse return null;
    if (hour > 23 or min > 59 or sec > 60) return null;
    return daysFromCivil(year, month, day) * std.time.s_per_day +
        @as(i64, hour) * 3600 + @as(i64, min) * 60 + sec;
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
/// Hinnant's days-from-civil algorithm). `month` is 1-based.
fn daysFromCivil(year: i64, month: u32, day: u32) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400; // [0, 399]
    const doy = @as(i64, (153 * ((month + 9) % 12) + 2) / 5 + day - 1); // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

/// Strictly numeric, no sign, no whitespace.
fn parseDigits(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var n: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

const day_names = [7][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const full_day_names = [7][]const u8{
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
};
const month_names = [12][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// The weekday name must be well-formed, but is NOT cross-checked against
/// the date (a "wrong" weekday on a valid date is tolerated).
fn isDayName(s: []const u8) bool {
    for (day_names) |n| if (std.mem.eql(u8, s, n)) return true;
    return false;
}

fn isFullDayName(s: []const u8) bool {
    for (full_day_names) |n| if (std.mem.eql(u8, s, n)) return true;
    return false;
}

/// 1-based month from its 3-letter name, or null.
fn monthFromName(s: []const u8) ?u32 {
    for (month_names, 1..) |n, i| if (std.mem.eql(u8, s, n)) return @intCast(i);
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// The RFC 9110 §5.6.7 example instant, in all three accepted formats.
const rfc_epoch: i64 = 784111777;
const rfc_imf = "Sun, 06 Nov 1994 08:49:37 GMT";
const rfc_850 = "Sunday, 06-Nov-94 08:49:37 GMT";
const rfc_asctime = "Sun Nov  6 08:49:37 1994";

test "parseHttpDate: RFC 9110 example in all three formats" {
    try testing.expectEqual(@as(?i64, rfc_epoch), parseHttpDate(rfc_imf));
    try testing.expectEqual(@as(?i64, rfc_epoch), parseHttpDate(rfc_850));
    try testing.expectEqual(@as(?i64, rfc_epoch), parseHttpDate(rfc_asctime));
    // Two-digit-year pivot: 70 → 1970, 69 → 2069.
    try testing.expectEqual(
        @as(?i64, 0),
        parseHttpDate("Thursday, 01-Jan-70 00:00:00 GMT"),
    );
    try testing.expectEqual(
        @as(?i64, 3124137600),
        parseHttpDate("Wednesday, 01-Jan-69 00:00:00 GMT"),
    );
    // asctime with a two-digit day (no padding).
    try testing.expectEqual(
        @as(?i64, rfc_epoch + 10 * std.time.s_per_day),
        parseHttpDate("Wed Nov 16 08:49:37 1994"),
    );
}

test "parseHttpDate: round-trips formatHttpDate" {
    var buf: [Server.http_date_len]u8 = undefined;
    try testing.expectEqualStrings(rfc_imf, Server.formatHttpDate(rfc_epoch, &buf));
    try testing.expectEqual(@as(?i64, rfc_epoch), parseHttpDate(Server.formatHttpDate(rfc_epoch, &buf)));
    try testing.expectEqualStrings(
        "Thu, 01 Jan 1970 00:00:00 GMT",
        Server.formatHttpDate(0, &buf),
    );
    try testing.expectEqual(@as(?i64, 0), parseHttpDate(Server.formatHttpDate(0, &buf)));
    // A modern instant, for good measure.
    try testing.expectEqual(@as(?i64, 1751976000), parseHttpDate(Server.formatHttpDate(1751976000, &buf)));
}

test "parseHttpDate: wrong-but-well-formed weekday is tolerated" {
    // The weekday is not cross-checked against the date (it was a Sunday).
    try testing.expectEqual(@as(?i64, rfc_epoch), parseHttpDate("Mon, 06 Nov 1994 08:49:37 GMT"));
}

test "parseHttpDate: malformed dates → null" {
    const bad = [_][]const u8{
        "", // empty
        "Sun", // short
        "utter garbage, none of this parses", // garbage with a comma
        "Xxx, 06 Nov 1994 08:49:37 GMT", // bad day name
        "Sun, 06 Xxx 1994 08:49:37 GMT", // bad month
        "Sun, 00 Nov 1994 08:49:37 GMT", // day 0
        "Sun, 32 Nov 1994 08:49:37 GMT", // day 32
        "Sun, 06 Nov 1994 24:49:37 GMT", // hour 24
        "Sun, 06 Nov 1994 08:60:37 GMT", // minute 60
        "Sun, 06 Nov 1994 08:49:61 GMT", // second 61 (60 = leap ok)
        "Sun, 06 Nov 1994 08:49:37 UTC", // wrong zone
        "Sun, 6 Nov 1994 08:49:37 GMT", // unpadded IMF day
        "Sun, 06 Nov 1994 08:49:37 GMT ", // trailing byte
        "Sunday, 06 Nov 94 08:49:37 GMT", // RFC 850 with wrong separators
        "Xxxday, 06-Nov-94 08:49:37 GMT", // bad full day name
        "Sun Nov 6 08:49:37 1994", // asctime without day padding
        "Sun Nov  6 08:49:37 94", // asctime with 2-digit year
    };
    for (bad) |s| try testing.expectEqual(@as(?i64, null), parseHttpDate(s));
    // Leap-second tolerance: second 60 parses.
    try testing.expect(parseHttpDate("Sun, 06 Nov 1994 08:49:60 GMT") != null);
}

test "ETag.parse: strong, weak, whitespace, malformed" {
    const strong = ETag.parse("\"xyzzy\"").?;
    try testing.expectEqualStrings("\"xyzzy\"", strong.value);
    try testing.expect(!strong.weak);

    const weak = ETag.parse("W/\"xyzzy\"").?;
    try testing.expectEqualStrings("\"xyzzy\"", weak.value);
    try testing.expect(weak.weak);

    const padded = ETag.parse("  \"x\"\t").?;
    try testing.expectEqualStrings("\"x\"", padded.value);

    // The empty tag `""` is well-formed.
    try testing.expect(ETag.parse("\"\"") != null);

    try testing.expectEqual(@as(?ETag, null), ETag.parse("*")); // list-level token
    try testing.expectEqual(@as(?ETag, null), ETag.parse("xyzzy")); // no quotes
    try testing.expectEqual(@as(?ETag, null), ETag.parse("\"xyzzy")); // no closing quote
    try testing.expectEqual(@as(?ETag, null), ETag.parse("xyzzy\"")); // no opening quote
    try testing.expectEqual(@as(?ETag, null), ETag.parse("\"")); // lone quote
    try testing.expectEqual(@as(?ETag, null), ETag.parse("W/xyzzy")); // weak, no quotes
    try testing.expectEqual(@as(?ETag, null), ETag.parse("w/\"xyzzy\"")); // lower-case w
    try testing.expectEqual(@as(?ETag, null), ETag.parse(""));
}

test "ETag: strong vs weak comparison (RFC 9110 §8.8.3.2 table)" {
    const w1 = ETag.parse("W/\"1\"").?;
    const w1b = ETag.parse("W/\"1\"").?;
    const w2 = ETag.parse("W/\"2\"").?;
    const s1 = ETag.parse("\"1\"").?;
    const s1b = ETag.parse("\"1\"").?;

    // W/"1" vs W/"1": strong no, weak yes.
    try testing.expect(!w1.strongEql(w1b));
    try testing.expect(w1.weakEql(w1b));
    // W/"1" vs W/"2": strong no, weak no.
    try testing.expect(!w1.strongEql(w2));
    try testing.expect(!w1.weakEql(w2));
    // W/"1" vs "1": strong no, weak yes.
    try testing.expect(!w1.strongEql(s1));
    try testing.expect(w1.weakEql(s1));
    // "1" vs "1": strong yes, weak yes.
    try testing.expect(s1.strongEql(s1b));
    try testing.expect(s1.weakEql(s1b));
}

/// Build a socket-free request with canned precondition headers and run
/// `evaluate` on it. `header_block` is raw wire lines ("Name: value\r\n").
fn evalWith(method: http.Method, header_block: []const u8, v: Validators) Outcome {
    var body: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = method,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = method.token(),
            .target = "/",
            .http1_0 = false,
            .header_block = header_block,
        },
        .body = &body,
        .context = null,
    };
    return evaluate(method, &req, v);
}

const v_both: Validators = .{ .etag = "\"v1\"", .last_modified = rfc_epoch };

test "evaluate: no preconditions → proceed" {
    try testing.expectEqual(Outcome.proceed, evalWith(.get, "", v_both));
    try testing.expectEqual(Outcome.proceed, evalWith(.put, "", .{}));
}

test "evaluate: If-Match hit / miss / star / weak-current" {
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-Match: \"v1\"\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-Match: \"stale\"\r\n", v_both),
    );
    // List: match on a later element.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-Match: \"a\", \"b\", \"v1\"\r\n", v_both),
    );
    // `*` matches when a current ETag exists, fails when it does not.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-Match: *\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-Match: *\r\n", .{}),
    );
    // No current validator at all → any If-Match fails.
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-Match: \"v1\"\r\n", .{}),
    );
    // A weak current tag can never strongly match.
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-Match: \"v1\"\r\n", .{ .etag = "W/\"v1\"" }),
    );
}

test "evaluate: If-Unmodified-Since pass / fail / invalid-ignored" {
    // Unmodified since the header date (lm == date) → proceed.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-Unmodified-Since: " ++ rfc_imf ++ "\r\n", v_both),
    );
    // Modified strictly after the header date → 412.
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(
            .put,
            "If-Unmodified-Since: " ++ rfc_imf ++ "\r\n",
            .{ .last_modified = rfc_epoch + 1 },
        ),
    );
    // Invalid date is ignored (RFC 9110 §13.1.4).
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(
            .put,
            "If-Unmodified-Since: not a date\r\n",
            .{ .last_modified = rfc_epoch + 1 },
        ),
    );
    // Unknown Last-Modified → the header cannot fail the request.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-Unmodified-Since: " ++ rfc_imf ++ "\r\n", .{ .etag = "\"v1\"" }),
    );
}

test "evaluate: If-None-Match GET→304, PUT→412, miss→proceed, weak, star" {
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.get, "If-None-Match: \"v1\"\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.head, "If-None-Match: \"v1\"\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-None-Match: \"v1\"\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.get, "If-None-Match: \"other\"\r\n", v_both),
    );
    // Weak comparison: a weak current tag still matches.
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.get, "If-None-Match: \"v1\"\r\n", .{ .etag = "W/\"v1\"" }),
    );
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.get, "If-None-Match: W/\"v1\"\r\n", v_both),
    );
    // `*`: matches an existing representation ("don't overwrite").
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(.put, "If-None-Match: *\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.put, "If-None-Match: *\r\n", .{}),
    );
}

test "evaluate: If-Modified-Since 304 / 200 / invalid-ignored / GET-HEAD only" {
    // Not modified since (lm == date) → 304.
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.get, "If-Modified-Since: " ++ rfc_imf ++ "\r\n", v_both),
    );
    try testing.expectEqual(
        Outcome.not_modified,
        evalWith(.head, "If-Modified-Since: " ++ rfc_imf ++ "\r\n", v_both),
    );
    // Modified after the header date → 200.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(
            .get,
            "If-Modified-Since: " ++ rfc_imf ++ "\r\n",
            .{ .last_modified = rfc_epoch + 1 },
        ),
    );
    // Invalid date is ignored.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.get, "If-Modified-Since: yesterday-ish\r\n", v_both),
    );
    // Not a GET/HEAD → the header does not apply.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.post, "If-Modified-Since: " ++ rfc_imf ++ "\r\n", v_both),
    );
    // No Last-Modified known → cannot 304.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(.get, "If-Modified-Since: " ++ rfc_imf ++ "\r\n", .{ .etag = "\"v1\"" }),
    );
}

test "evaluate: precedence — If-Match beats If-Unmodified-Since" {
    // If-Match matches; If-Unmodified-Since alone would fail (lm > date).
    // §13.2.2: If-Unmodified-Since is only evaluated when If-Match is absent.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(
            .put,
            "If-Match: \"v1\"\r\nIf-Unmodified-Since: " ++ rfc_imf ++ "\r\n",
            .{ .etag = "\"v1\"", .last_modified = rfc_epoch + 1 },
        ),
    );
    // And a failing If-Match still fails regardless of a passing date.
    try testing.expectEqual(
        Outcome.precondition_failed,
        evalWith(
            .put,
            "If-Match: \"stale\"\r\nIf-Unmodified-Since: " ++ rfc_imf ++ "\r\n",
            v_both,
        ),
    );
}

test "evaluate: precedence — If-None-Match suppresses If-Modified-Since" {
    // If-None-Match misses; If-Modified-Since alone would 304.
    try testing.expectEqual(
        Outcome.proceed,
        evalWith(
            .get,
            "If-None-Match: \"other\"\r\nIf-Modified-Since: " ++ rfc_imf ++ "\r\n",
            v_both,
        ),
    );
}

// ── apply end-to-end over the serveStream codec ──────────────────────────

fn condHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    if (try apply(req, rw, .{ .etag = "\"v1\"", .last_modified = rfc_epoch })) return;
    try rw.writeAll("payload");
}

/// Run `Server.serveStream` over canned wire bytes with small test buffers
/// (mirrors the golden-test harness in Server.zig; Date is omitted by
/// leaving `now` null so the goldens stay time-independent).
fn runCondStream(wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    Server.serveStream(.{
        .handler = condHandler,
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "apply: golden 304 on a matching If-None-Match — ETag, no body, no Content-Length" {
    var out_buf: [4096]u8 = undefined;
    const got = runCondStream("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "If-None-Match: \"v1\"\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 304 Not Modified\r\n" ++
        "ETag: \"v1\"\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "\r\n", got);
}

test "apply: golden 200 on a fresh GET — ETag + body" {
    var out_buf: [4096]u8 = undefined;
    const got = runCondStream("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "ETag: \"v1\"\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 7\r\n" ++
        "\r\n" ++
        "payload", got);
}

test "apply: golden 412 on a stale If-Match PUT" {
    var out_buf: [4096]u8 = undefined;
    const got = runCondStream("PUT / HTTP/1.1\r\nHost: t\r\n" ++
        "If-Match: \"stale\"\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 412 Precondition Failed\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", got);
}
