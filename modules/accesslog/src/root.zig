// SPDX-License-Identifier: MIT

//! accesslog — structured HTTP access-log formatter.
//!
//! One record (`Entry`) per request, emitted to a `std.Io.Writer` in any of
//! three formats: **JSON Lines** (one JSON object per line — the modern
//! structured default), **logfmt** (`key=value`, Heroku/Go
//! `kr/logfmt`-style), and the ubiquitous Apache/NGINX **Combined Log
//! Format** (`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`,
//! modeled after `mod_log_config`'s escaping — `ap_escape_logitem`).
//!
//! `Entry` is a plain struct: it carries no reference to a live HTTP
//! request, so it is usable standalone (tests, non-`http` transports,
//! replaying archived data). `entryFromRequest` is the convenience bridge
//! that pulls method/target/protocol/status/headers/peer out of an
//! `http.Server.Request` + `http.Server.ResponseWriter` for the common
//! case of logging one just-served request.
//!
//! ## Log-injection safety (the primary requirement)
//!
//! Every string field may originate from untrusted request data (path,
//! User-Agent, Referer, even the method on a hand-built `Entry`). Each
//! format's writer escapes rigorously so such a field can never: break out
//! of its JSON string / logfmt value / combined quoted field, inject a
//! newline that forges a second record, or emit a raw control byte. See
//! `writeJsonLines` / `writeLogfmt` / `writeCombined` for the per-format
//! escaping rule and the module tests for the adversarial vectors this was
//! verified against.
//!
//! ## The log must always be readable (the second requirement)
//!
//! Log EVASION is the mirror image of log injection and just as bad: a
//! record a pipeline cannot parse is a record the pipeline drops, and a
//! client that can make its OWN record undroppable-into-unparseable has
//! erased itself from the log. RFC 8259 requires a JSON text to be UTF-8,
//! so a request target or User-Agent carrying arbitrary bytes used to be
//! enough. **JSON Lines output is now unconditionally parseable**:
//! `writeJsonString` replaces every ill-formed UTF-8 subsequence with
//! U+FFFD (see its doc for the exact substitution policy). The cost is a
//! documented, deliberate one — the byte-exact round trip this module
//! guarantees now holds for valid-UTF-8 input only. logfmt and Combined are
//! byte-oriented text formats with no encoding requirement of their own and
//! pass such bytes through unchanged; see `SPEC.md` for what that does and
//! does not mean downstream.
//!
//! ## Time contract — no system clock
//!
//! This module never reads the clock. `Entry.timestamp_ns` is a caller-
//! supplied nanosecond Unix timestamp, used verbatim (JSON/logfmt) or as a
//! numeric fallback for Combined's `[%t]` bracket. Combined's real shape
//! (`10/Oct/2000:13:55:36 -0700`) additionally needs a timezone-aware
//! calendar conversion that this module deliberately does not perform
//! (that is a formatting concern, not a logging one, and pulling it in
//! would mean guessing at a timezone policy) — a caller that wants the
//! spec-shaped bracket formats the string itself (e.g. with the `datefmt`
//! module) and passes it as `Entry.time_formatted`.
//!
//! Relationship to `metrics.AccessLog`: the `metrics` module ships a small
//! built-in access-log writer (JSON/Combined, driven off its narrower
//! `AccessEntry` — method/path/status/duration/bytes only, no host/UA/
//! referer/time/request-id). This module is the standalone, fuller-fielded
//! formatter for when those extra fields matter; the two are independent
//! and neither depends on the other.

const std = @import("std");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    // Pure functions over caller-supplied data / a caller-supplied Writer;
    // no shared or internal state.
    .concurrency = .reentrant,
    .model_after = "Apache mod_log_config (Combined Log Format + ap_escape_logitem escaping) + Heroku/kr logfmt + the common JSON-Lines access-log convention (Caddy/nginx json access log)",
    .deps = .{"http"},
};

// ── the record ───────────────────────────────────────────────────────────

/// One access-log record. Plain data — no allocation, no borrowed
/// lifetimes beyond "valid until you're done formatting it". Optional
/// fields render per format: JSON emits an explicit `null`; logfmt omits
/// the key; Combined uses the `-` placeholder (its own convention).
pub const Entry = struct {
    /// Caller-supplied timestamp, nanoseconds since the Unix epoch. This
    /// module never reads the system clock — see the module doc's "Time
    /// contract".
    timestamp_ns: i64,
    /// Preformatted time string for Combined's `[%t]` bracket (e.g.
    /// `"22/Jul/2026:10:00:00 +0000"`). Null falls back to writing the raw
    /// `timestamp_ns` inside the brackets — still one well-formed field,
    /// just not calendar-shaped. Ignored by JSON/logfmt (they use
    /// `timestamp_ns` directly, no ambiguity to resolve).
    time_formatted: ?[]const u8 = null,
    /// Client address (and port, when the caller includes one), e.g.
    /// `"192.0.2.1:54321"`. Null when unknown (no live connection, e.g. a
    /// trusted-proxy deployment with no forwarded-for signal parsed yet).
    remote_addr: ?[]const u8 = null,
    /// Request method token, e.g. `"GET"`.
    method: []const u8,
    /// Raw request-target as sent, e.g. `"/path?q=1"` or `"*"`.
    target: []const u8,
    /// Protocol version string, e.g. `"HTTP/1.1"`.
    protocol: []const u8 = "HTTP/1.1",
    /// Response status code.
    status: u16,
    /// Request body byte count, when known (e.g. the declared
    /// `Content-Length`; null for chunked/unknown).
    request_bytes: ?u64 = null,
    /// Response body byte count, when known (null for streamed responses
    /// with no running total — see `entryFromRequest`'s helper for the
    /// exact contract against `http.Server.ResponseWriter`).
    response_bytes: ?u64 = null,
    /// Request→response latency in nanoseconds, when the caller timed it.
    latency_ns: ?u64 = null,
    /// `User-Agent` header value, if present.
    user_agent: ?[]const u8 = null,
    /// `Referer` header value, if present.
    referer: ?[]const u8 = null,
    /// Correlation / request id (e.g. from the `requestid` module), if any.
    request_id: ?[]const u8 = null,
};

/// Selects which `write*` function `write` dispatches to. Each format is
/// also directly callable (`writeJsonLines`/`writeLogfmt`/`writeCombined`)
/// when the caller already knows which one it wants.
pub const Format = enum { json_lines, logfmt, combined };

/// Emit `entry` in `format` to `w`. See `writeJsonLines`/`writeLogfmt`/
/// `writeCombined` for the exact shape of each.
pub fn write(entry: Entry, format: Format, w: *std.Io.Writer) std.Io.Writer.Error!void {
    switch (format) {
        .json_lines => try writeJsonLines(entry, w),
        .logfmt => try writeLogfmt(entry, w),
        .combined => try writeCombined(entry, w),
    }
}

// ── JSON Lines ───────────────────────────────────────────────────────────

/// One JSON object per line (LF-terminated), fixed key order, every field
/// present (absent optionals as JSON `null`).
///
/// Escaping: every string field goes through `writeJsonString` — RFC 8259
/// `"`/`\`/control-byte escaping (the same rule `std.json` itself expects
/// on the way back in) plus UTF-8 sanitization. A crafted value can
/// therefore never close its string early, inject a sibling key, or emit a
/// raw newline: the whole record — no matter what a field contains — stays
/// exactly one line and one JSON object, provably so by round-tripping it
/// through `std.json.parseFromSlice` (see the tests).
///
/// **Unconditionally parseable, and what that costs.** RFC 8259 requires a
/// JSON text to be UTF-8, so `writeJsonString` replaces each ill-formed
/// UTF-8 subsequence with U+FFFD rather than passing the bytes through. The
/// emitted line therefore parses for ANY input bytes whatsoever — that is
/// the module's guarantee and its fuzz oracle. In exchange the round trip
/// is byte-exact **for valid-UTF-8 input only**: a field carrying arbitrary
/// bytes comes back with U+FFFD where those bytes were, and the originals
/// are not recoverable from the JSON output. See `writeJsonString` for the
/// exact substitution policy, pinned byte-for-byte by its own tests.
pub fn writeJsonLines(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{{\"ts\":{d},\"remote_addr\":", .{entry.timestamp_ns});
    try writeJsonOptString(w, entry.remote_addr);
    try w.writeAll(",\"method\":");
    try writeJsonString(w, entry.method);
    try w.writeAll(",\"target\":");
    try writeJsonString(w, entry.target);
    try w.writeAll(",\"protocol\":");
    try writeJsonString(w, entry.protocol);
    try w.print(",\"status\":{d},\"request_bytes\":", .{entry.status});
    try writeJsonOptU64(w, entry.request_bytes);
    try w.writeAll(",\"response_bytes\":");
    try writeJsonOptU64(w, entry.response_bytes);
    try w.writeAll(",\"latency_ns\":");
    try writeJsonOptU64(w, entry.latency_ns);
    try w.writeAll(",\"user_agent\":");
    try writeJsonOptString(w, entry.user_agent);
    try w.writeAll(",\"referer\":");
    try writeJsonOptString(w, entry.referer);
    try w.writeAll(",\"request_id\":");
    try writeJsonOptString(w, entry.request_id);
    try w.writeAll("}\n");
}

/// U+FFFD REPLACEMENT CHARACTER, UTF-8 encoded (`EF BF BD`). What
/// `writeJsonString` puts in place of an ill-formed UTF-8 subsequence.
const replacement = "\u{fffd}";

/// One step of a UTF-8 scan. `len` is never zero, so a loop over
/// `utf8Step` always terminates.
const Utf8Step = struct {
    /// Number of bytes this step covers.
    len: usize,
    /// True when those bytes are exactly one well-formed UTF-8 sequence;
    /// false when they are a maximal ill-formed subsequence.
    ok: bool,
};

/// Classify the sequence starting at `s[0]` (`s` must be non-empty) against
/// Unicode 16.0 Table 3-7 (*Well-Formed UTF-8 Byte Sequences*) — the same
/// table that rejects surrogates (`ED A0..BF`), overlongs (`C0`/`C1`, `E0
/// 80..9F`, `F0 80..8F`) and anything above U+10FFFF (`F4 90..BF`, `F5..FF`).
///
/// On failure `len` is the **maximal subpart**: the longest prefix of `s` that
/// is still a prefix of some well-formed sequence, or 1 when even the first
/// byte cannot start one. That is Unicode 16.0 §3.9's "U+FFFD Substitution
/// of Maximal Subparts" recommendation — see `writeJsonString` for why this
/// module follows it and where it is observably different from replacing per
/// byte. Running off the end of `s` (a truncated sequence) is a failure with
/// `len` equal to the bytes actually present, which is the same rule.
fn utf8Step(s: []const u8) Utf8Step {
    const b0 = s[0];
    if (b0 < 0x80) return .{ .len = 1, .ok = true };

    // Every non-ASCII lead byte fixes the total length AND the allowed range
    // of the SECOND byte; bytes three and four are always 80..BF. Encoding
    // that second-byte range here is the whole of Table 3-7 — a plain
    // "80..BF times n" check would accept surrogates and overlongs.
    const total: usize, const b1_min: u8, const b1_max: u8 = switch (b0) {
        0xC2...0xDF => .{ 2, 0x80, 0xBF },
        0xE0 => .{ 3, 0xA0, 0xBF }, // E0 80..9F would be an overlong
        0xE1...0xEC => .{ 3, 0x80, 0xBF },
        0xED => .{ 3, 0x80, 0x9F }, // ED A0..BF is a surrogate, D800..DFFF
        0xEE...0xEF => .{ 3, 0x80, 0xBF },
        0xF0 => .{ 4, 0x90, 0xBF }, // F0 80..8F would be an overlong
        0xF1...0xF3 => .{ 4, 0x80, 0xBF },
        0xF4 => .{ 4, 0x80, 0x8F }, // F4 90..BF is past U+10FFFF
        // 0x80..0xC1 (continuation byte on its own, or a 2-byte overlong
        // lead) and 0xF5..0xFF (past U+10FFFF) can never start a sequence.
        else => return .{ .len = 1, .ok = false },
    };
    if (s.len < 2 or s[1] < b1_min or s[1] > b1_max) return .{ .len = 1, .ok = false };
    if (total == 2) return .{ .len = 2, .ok = true };
    if (s.len < 3 or s[2] < 0x80 or s[2] > 0xBF) return .{ .len = 2, .ok = false };
    if (total == 3) return .{ .len = 3, .ok = true };
    if (s.len < 4 or s[3] < 0x80 or s[3] > 0xBF) return .{ .len = 3, .ok = false };
    return .{ .len = 4, .ok = true };
}

/// Write `s` as a double-quoted JSON string (RFC 8259 §7), sanitized so the
/// result is always a valid JSON string for **any** input bytes:
///
///  * `"` and `\` are backslash-escaped, `\b\t\n\f\r` get their named short
///    escapes, every other byte in `0x00-0x1F` becomes `\u00XX`. `0x7F` (DEL)
///    is not a JSON control character per RFC 8259 §7 and passes through.
///  * every **ill-formed UTF-8 subsequence** is replaced by U+FFFD. RFC 8259
///    requires a JSON text to be UTF-8 and conforming parsers enforce it
///    (`std.json` answers `error.SyntaxError`), so passing such bytes through
///    would let a client make its own record unparseable — log evasion. See
///    the module doc.
///
/// **Substitution policy: one U+FFFD per maximal subpart**, i.e. Unicode 16.0
/// §3.9's "U+FFFD Substitution of Maximal Subparts" recommendation, as
/// implemented by `utf8Step`. Chosen over "one U+FFFD per ill-formed byte"
/// (what Go's `encoding/json` does, since its
/// `utf8.DecodeRune` always reports size 1 on error) because it is the Unicode
/// recommendation and the behaviour of the WHATWG Encoding Standard and of
/// Rust's `String::from_utf8_lossy`, so a reader who re-decodes the field with
/// any of those sees the same string this module emitted. The two policies are
/// observably different exactly on a **truncated but otherwise valid prefix**:
/// `E2 82` (the first two bytes of `€`) is one maximal subpart → one U+FFFD
/// here, two per-byte. They agree on `ED A0 80` — three either way, because
/// `ED A0` is not a prefix of anything well-formed, so `ED` alone is the
/// maximal subpart. Both facts are pinned byte-exactly by the tests.
///
/// Cost: the scan copies nothing and allocates nothing. Well-formed bytes are
/// never inspected twice and never written one at a time — they accumulate
/// into a run that is flushed with a single `writeAll` when an escape or a
/// replacement interrupts it, or at the end.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    // Start of the pending verbatim run: everything in `s[run..i]` is passed
    // through untouched and is flushed in one write when something interrupts.
    var run: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        // The whole of the common case, one table lookup per byte: an access
        // log is overwhelmingly printable ASCII, and every such byte only has
        // to advance the cursor.
        if (json_verbatim[c]) {
            i += 1;
            continue;
        }
        if (c < 0x80) {
            try w.writeAll(s[run..i]);
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                0x08 => try w.writeAll("\\b"),
                0x09 => try w.writeAll("\\t"),
                0x0A => try w.writeAll("\\n"),
                0x0C => try w.writeAll("\\f"),
                0x0D => try w.writeAll("\\r"),
                else => try w.print("\\u{x:0>4}", .{c}),
            }
            i += 1;
            run = i;
            continue;
        }
        const step = utf8Step(s[i..]);
        if (step.ok) {
            i += step.len; // well-formed non-ASCII — also stays in the run
            continue;
        }
        try w.writeAll(s[run..i]);
        try w.writeAll(replacement);
        i += step.len;
        run = i;
    }
    try w.writeAll(s[run..]);
    try w.writeByte('"');
}

/// Bytes `writeJsonString` may copy into the output untouched: printable
/// ASCII and DEL (`0x20-0x7F`) except `"` and `\`. Everything else needs a
/// decision — an escape below 0x20, or a UTF-8 scan at or above 0x80 — so one
/// lookup here is the whole per-byte cost of a clean field.
const json_verbatim: [256]bool = blk: {
    var t: [256]bool = @splat(false);
    for (0x20..0x80) |c| t[c] = true;
    t['"'] = false;
    t['\\'] = false;
    break :blk t;
};

fn writeJsonOptString(w: *std.Io.Writer, s: ?[]const u8) std.Io.Writer.Error!void {
    if (s) |v| try writeJsonString(w, v) else try w.writeAll("null");
}

fn writeJsonOptU64(w: *std.Io.Writer, v: ?u64) std.Io.Writer.Error!void {
    if (v) |x| try w.print("{d}", .{x}) else try w.writeAll("null");
}

// ── logfmt ───────────────────────────────────────────────────────────────

/// `key=value` pairs, space-separated, LF-terminated. Fixed key order
/// matching `writeJsonLines`; absent optionals **omit** the key entirely
/// (the logfmt convention — there is no `null`).
///
/// Escaping: a value is quoted only when it needs to be — it contains a
/// space, tab, `"`, `=`, backslash, a control byte, or is empty
/// (`logfmtNeedsQuote`). When quoted, `"`/`\` are backslash-escaped, `\n`/
/// `\r`/`\t` get their short escapes, and any other control byte becomes
/// `\xHH`. Because *every* character that would ever need escaping is also
/// exactly the trigger set for quoting, an unquoted value is guaranteed
/// escape-free passthrough (a benign `GET`, a plain path) while anything
/// containing a quote, an `=` (which could otherwise read as a second
/// key=value pair), or a raw newline (which would otherwise forge a
/// second log line) is always wrapped and neutralized.
pub fn writeLogfmt(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("ts={d}", .{entry.timestamp_ns});
    if (entry.remote_addr) |v| {
        try w.writeAll(" remote_addr=");
        try writeLogfmtValue(w, v);
    }
    try w.writeAll(" method=");
    try writeLogfmtValue(w, entry.method);
    try w.writeAll(" target=");
    try writeLogfmtValue(w, entry.target);
    try w.writeAll(" protocol=");
    try writeLogfmtValue(w, entry.protocol);
    try w.print(" status={d}", .{entry.status});
    if (entry.request_bytes) |v| try w.print(" request_bytes={d}", .{v});
    if (entry.response_bytes) |v| try w.print(" response_bytes={d}", .{v});
    if (entry.latency_ns) |v| try w.print(" latency_ns={d}", .{v});
    if (entry.user_agent) |v| {
        try w.writeAll(" user_agent=");
        try writeLogfmtValue(w, v);
    }
    if (entry.referer) |v| {
        try w.writeAll(" referer=");
        try writeLogfmtValue(w, v);
    }
    if (entry.request_id) |v| {
        try w.writeAll(" request_id=");
        try writeLogfmtValue(w, v);
    }
    try w.writeByte('\n');
}

/// True when `s` must be quoted in a logfmt value: empty, or contains a
/// byte from the trigger set (space/tab/`"`/`=`/backslash/any control
/// byte). Kept in exact lockstep with the escape set in `writeLogfmtValue`
/// — see that function's doc.
fn logfmtNeedsQuote(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |c| switch (c) {
        ' ', '"', '=', '\\', 0x00...0x1F, 0x7F => return true,
        else => {},
    };
    return false;
}

fn writeLogfmtValue(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    if (!logfmtNeedsQuote(s)) {
        // No byte in `s` needs escaping (that's exactly what
        // `logfmtNeedsQuote` just proved) — verbatim passthrough.
        return w.writeAll(s);
    }
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F, 0x7F => try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ── Apache/NGINX Combined Log Format ────────────────────────────────────

/// `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"\n`.
///
/// `%l` (identity) and `%u` (authenticated user) are always `-` — this
/// module tracks neither. `%b` is `-` when `response_bytes` is null, the
/// decimal count otherwise (0 prints as `0`, matching real servers).
/// Referer/User-Agent print the literal `"-"` when absent, matching
/// `mod_log_config`'s own behavior for a missing header on a quoted field.
///
/// Escaping (`ap_escape_logitem` rule, applied to every field — not just
/// the quoted ones, so even `%h`/`%t` can't inject a raw control byte):
/// `"` and `\` are backslash-escaped, every other control byte (0x00–0x1F,
/// 0x7F — this includes `\n`/`\r`) becomes `\xHH`. A quote can therefore
/// never close a quoted field early, and a newline can never start a
/// second line — the record stays exactly one line no matter what the
/// caller's method/target/protocol/referer/user-agent/remote_addr contain.
pub fn writeCombined(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (entry.remote_addr) |a| try writeClfEscaped(w, hostOnly(a)) else try w.writeByte('-');
    try w.writeAll(" - - [");
    if (entry.time_formatted) |t| try writeClfEscaped(w, t) else try w.print("{d}", .{entry.timestamp_ns});
    try w.writeAll("] \"");
    try writeClfEscaped(w, entry.method);
    try w.writeByte(' ');
    try writeClfEscaped(w, entry.target);
    try w.writeByte(' ');
    try writeClfEscaped(w, entry.protocol);
    try w.print("\" {d} ", .{entry.status});
    if (entry.response_bytes) |b| try w.print("{d}", .{b}) else try w.writeByte('-');
    try w.writeAll(" \"");
    if (entry.referer) |r| try writeClfEscaped(w, r) else try w.writeByte('-');
    try w.writeAll("\" \"");
    if (entry.user_agent) |u| try writeClfEscaped(w, u) else try w.writeByte('-');
    try w.writeAll("\"\n");
}

/// Combined's `%h` is the remote *host* — never `host:port`. `remote_addr`
/// carries the full peer address (`entryFromRequest` formats an
/// `IpAddress`, which includes the port), so the port is stripped here and
/// only here: the JSON/logfmt formats keep the address verbatim, where a
/// structured consumer wants the port.
///
/// Real Combined-format consumers reject a port in this slot outright —
/// goaccess 1.10.2 fails the whole line with `Token '192.0.2.1:54321'
/// doesn't match specifier '%h'`. IPv6 is logged bare (`::1`), matching
/// Apache, so the `[…]` brackets go too.
fn hostOnly(addr: []const u8) []const u8 {
    if (addr.len != 0 and addr[0] == '[') {
        // `[::1]:8080` / `[::1]` → `::1`
        if (std.mem.indexOfScalar(u8, addr, ']')) |close| return addr[1..close];
        return addr;
    }
    // A bare IPv6 literal has several colons and no port — leave it alone.
    if (std.mem.count(u8, addr, ":") > 1) return addr;
    if (std.mem.lastIndexOfScalar(u8, addr, ':')) |colon| return addr[0..colon];
    return addr;
}

fn writeClfEscaped(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x00...0x1F, 0x7F => try w.print("\\x{x:0>2}", .{c}),
        else => try w.writeByte(c),
    };
}

// ── http request/response → Entry helper ────────────────────────────────

/// Options for `entryFromRequest` — everything the live `http.Server`
/// types cannot supply themselves (time, latency, correlation id) or that
/// the caller may want to override.
pub const FromRequestOptions = struct {
    /// Caller-supplied timestamp, ns since the Unix epoch — see the
    /// module doc's "Time contract". Required: this module never reads
    /// the clock.
    timestamp_ns: i64,
    /// Preformatted time string for Combined's `[%t]` — see
    /// `Entry.time_formatted`.
    time_formatted: ?[]const u8 = null,
    /// Request→response latency, if the caller timed it.
    latency_ns: ?u64 = null,
    /// Override for the request body byte count. Defaults to the
    /// request's declared `Content-Length` (null when chunked/absent —
    /// this module never drains the body to count it).
    request_bytes: ?u64 = null,
    /// Correlation / request id, e.g. from the `requestid` module.
    request_id: ?[]const u8 = null,
};

/// Build an `Entry` from a served request + its response writer, pulling
/// method/target/protocol/status/User-Agent/Referer/peer address
/// automatically. Zero allocation: `addr_buf` is caller-supplied scratch
/// the peer address is formatted into (the returned `Entry.remote_addr`
/// borrows it) — 64 bytes comfortably covers the longest `IpAddress`
/// textual form (`"[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:65535"`, 47
/// bytes). `addr_buf` must outlive the returned `Entry`.
///
/// `response_bytes` uses the same best-effort contract as
/// `metrics.AccessEntry.bytes`: exact for a buffered or declared-length
/// body, `0` for HEAD/204/304 (`.discard`), `null` for chunked/
/// until-close/compressed streaming responses (no running total is kept).
pub fn entryFromRequest(
    req: *const http.Server.Request,
    res: *const http.Server.ResponseWriter,
    addr_buf: []u8,
    opts: FromRequestOptions,
) Entry {
    var entry: Entry = .{
        .timestamp_ns = opts.timestamp_ns,
        .time_formatted = opts.time_formatted,
        .method = req.method.token(),
        .target = req.target,
        .protocol = if (req.head.http1_0) "HTTP/1.0" else "HTTP/1.1",
        .status = res.status,
        .request_bytes = opts.request_bytes orelse req.head.content_length,
        .response_bytes = responseBytesOf(res),
        .latency_ns = opts.latency_ns,
        .user_agent = req.header("User-Agent"),
        .referer = req.header("Referer"),
        .request_id = opts.request_id,
    };
    if (req.peerAddress()) |p| {
        var w: std.Io.Writer = .fixed(addr_buf);
        w.print("{f}", .{p}) catch {
            // addr_buf too small: leave remote_addr null rather than a
            // truncated/garbage address.
            return entry;
        };
        entry.remote_addr = w.buffered();
    }
    return entry;
}

/// See `entryFromRequest`'s doc for the exact contract.
fn responseBytesOf(res: *const http.Server.ResponseWriter) ?u64 {
    return switch (res.body) {
        .buffering => res.declared_len orelse res.interface.end,
        .identity => res.declared_len.?,
        .discard => 0,
        .chunked, .until_close, .gzip => null,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sampleEntry() Entry {
    return .{
        .timestamp_ns = 1734000000000000000,
        .time_formatted = "22/Jul/2026:10:00:00 +0000",
        .remote_addr = "192.0.2.1:54321",
        .method = "GET",
        .target = "/status?x=1",
        .protocol = "HTTP/1.1",
        .status = 200,
        .request_bytes = 0,
        .response_bytes = 512,
        .latency_ns = 1500000,
        .user_agent = "curl/8.0",
        .referer = "https://example.org/",
        .request_id = "req-abc-123",
    };
}

test "writeJsonLines: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeJsonLines(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "{\"ts\":1734000000000000000,\"remote_addr\":\"192.0.2.1:54321\"," ++
            "\"method\":\"GET\",\"target\":\"/status?x=1\",\"protocol\":\"HTTP/1.1\"," ++
            "\"status\":200,\"request_bytes\":0,\"response_bytes\":512," ++
            "\"latency_ns\":1500000,\"user_agent\":\"curl/8.0\"," ++
            "\"referer\":\"https://example.org/\",\"request_id\":\"req-abc-123\"}\n",
        w.buffered(),
    );
}

test "writeLogfmt: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmt(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "ts=1734000000000000000 remote_addr=192.0.2.1:54321 method=GET " ++
            "target=\"/status?x=1\" protocol=HTTP/1.1 status=200 request_bytes=0 " ++
            "response_bytes=512 latency_ns=1500000 user_agent=curl/8.0 " ++
            "referer=https://example.org/ request_id=req-abc-123\n",
        w.buffered(),
    );
}

test "writeCombined: byte-exact golden for a representative entry" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(sampleEntry(), &w);
    try testing.expectEqualStrings(
        "192.0.2.1 - - [22/Jul/2026:10:00:00 +0000] \"GET /status?x=1 HTTP/1.1\" " ++
            "200 512 \"https://example.org/\" \"curl/8.0\"\n",
        w.buffered(),
    );
}

test "writeCombined: null timestamp fallback prints raw ns inside the brackets" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.time_formatted = null;
    try writeCombined(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "[1734000000000000000]") != null);
}

test "combined: response_bytes of exactly 0 prints the digit '0', not the '-' absent-marker" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.response_bytes = 0;
    try writeCombined(entry, &w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\" 200 0 \"") != null);
}

test "write: enum dispatch matches the dedicated per-format functions" {
    inline for ([_]Format{ .json_lines, .logfmt, .combined }) |fmt| {
        var direct_buf: [512]u8 = undefined;
        var dispatch_buf: [512]u8 = undefined;
        var direct: std.Io.Writer = .fixed(&direct_buf);
        var dispatch: std.Io.Writer = .fixed(&dispatch_buf);
        switch (fmt) {
            .json_lines => try writeJsonLines(sampleEntry(), &direct),
            .logfmt => try writeLogfmt(sampleEntry(), &direct),
            .combined => try writeCombined(sampleEntry(), &direct),
        }
        try write(sampleEntry(), fmt, &dispatch);
        try testing.expectEqualStrings(direct.buffered(), dispatch.buffered());
    }
}

test "missing optional fields: JSON emits null, logfmt omits the key, combined uses '-'" {
    const entry: Entry = .{
        .timestamp_ns = 1,
        .method = "GET",
        .target = "/",
        .status = 204,
        // remote_addr, request_bytes, response_bytes, latency_ns,
        // user_agent, referer, request_id all left null.
    };

    var jbuf: [512]u8 = undefined;
    var jw: std.Io.Writer = .fixed(&jbuf);
    try writeJsonLines(entry, &jw);
    try testing.expectEqualStrings(
        "{\"ts\":1,\"remote_addr\":null,\"method\":\"GET\",\"target\":\"/\"," ++
            "\"protocol\":\"HTTP/1.1\",\"status\":204,\"request_bytes\":null," ++
            "\"response_bytes\":null,\"latency_ns\":null,\"user_agent\":null," ++
            "\"referer\":null,\"request_id\":null}\n",
        jw.buffered(),
    );

    var lbuf: [256]u8 = undefined;
    var lw: std.Io.Writer = .fixed(&lbuf);
    try writeLogfmt(entry, &lw);
    try testing.expectEqualStrings("ts=1 method=GET target=/ protocol=HTTP/1.1 status=204\n", lw.buffered());

    var cbuf: [256]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&cbuf);
    try writeCombined(entry, &cw);
    try testing.expectEqualStrings("- - - [1] \"GET / HTTP/1.1\" 204 - \"-\" \"-\"\n", cw.buffered());
}

// ── log-injection teeth ──────────────────────────────────────────────────
//
// One shared adversarial payload exercised as method/target/user_agent/
// referer across every format: a quote (breakout attempt), CR+LF (line-
// forge attempt), braces (JSON-structure-confusion attempt), a fake
// `logfmt` key=value pair, and a spread of control bytes including DEL.

const evil_payload = "evil\"\r\n{fake}=1 status=200\x01\x1f\x7f";

test "JSON: injection payload stays one record, round-trips byte-exact through std.json" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = evil_payload;
    entry.target = evil_payload;
    entry.method = evil_payload;
    try writeJsonLines(entry, &w);
    const out = w.buffered();

    // Exactly one newline: the record terminator. No forged second line.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    // No raw control byte reached the wire. (0x7F/DEL is not a JSON
    // "control character" per RFC 8259 §7 — 0x00-0x1F only — so it is
    // legitimately allowed to pass through unescaped; it cannot break the
    // string or the line either way.)
    for ([_]u8{ 0x00, 0x01, 0x0D, 0x1F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }

    // Structural validity + exact field round-trip via std.json.
    const without_nl = out[0 .. out.len - 1];
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, without_nl, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings(evil_payload, obj.get("user_agent").?.string);
    try testing.expectEqualStrings(evil_payload, obj.get("target").?.string);
    try testing.expectEqualStrings(evil_payload, obj.get("method").?.string);
}

test "JSON: benign field passes through unchanged (positive control)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = "Mozilla/5.0 (X11; Linux x86_64)";
    try writeJsonLines(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"user_agent\":\"Mozilla/5.0 (X11; Linux x86_64)\"") != null);
}

test "logfmt: injection payload is quoted+escaped, one record, no fake pair, no raw control bytes" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = evil_payload;
    entry.referer = evil_payload;
    try writeLogfmt(entry, &w);
    const out = w.buffered();

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    for ([_]u8{ 0x01, 0x1F, 0x7F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }
    // The embedded quote is backslash-escaped (`\"`, not a bare `"`), so it
    // can never close the quoted value early and let `{fake}=1` or
    // `status=200` read as a sibling top-level key=value pair.
    try testing.expect(std.mem.indexOf(u8, out, "user_agent=\"evil\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "referer=\"evil\\\"") != null);
}

test "logfmt: benign field is unquoted verbatim (positive control)" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    entry.user_agent = "curl/8.0";
    try writeLogfmt(entry, &w);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), " user_agent=curl/8.0 ") != null);
}

test "logfmt: a value containing only '=' is quoted (no ambiguous bare key=value split)" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "a=b");
    try testing.expectEqualStrings("\"a=b\"", w.buffered());
}

test "logfmt: an empty value is quoted (an unquoted empty value would vanish, misreading as an absent key)" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "");
    try testing.expectEqualStrings("\"\"", w.buffered());
}

test "logfmt: control bytes escape to their own exact \\xHH value, not just 'something'" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmtValue(&w, "\x01\x1f\x7f");
    try testing.expectEqualStrings("\"\\x01\\x1f\\x7f\"", w.buffered());
}

test "combined: injection payload cannot forge a second line or break the quoted fields" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    // A payload aiming to close the quoted user-agent field, inject a
    // newline, and prepend what looks like a whole forged combined line.
    const forge = "Mozilla\" \r\n127.0.0.1 - - [x] \"GET / HTTP/1.1\" 200 1 \"-\" \"-";
    entry.user_agent = forge;
    entry.referer = forge;
    entry.method = evil_payload;
    entry.target = evil_payload;
    try writeCombined(entry, &w);
    const out = w.buffered();

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    for ([_]u8{ 0x01, 0x1F, 0x7F }) |b| {
        try testing.expect(std.mem.indexOfScalar(u8, out, b) == null);
    }
    // The line still ends with the real closing `"\n` for user-agent, i.e.
    // it is still exactly the shape %h ... "referer" "user-agent"\n — the
    // embedded quote+newline never closed the field early.
    try testing.expect(std.mem.endsWith(u8, out, "\"\n"));
}

test "combined: benign fields render verbatim (positive control)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(sampleEntry(), &w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"https://example.org/\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"curl/8.0\"") != null);
    try testing.expect(std.mem.startsWith(u8, out, "192.0.2.1 - - ["));
}

// ── entryFromRequest ─────────────────────────────────────────────────────

fn testRequest(head_block: []const u8, target: []const u8, http1_0: bool, body: *http.Server.RequestBody, peer: ?std.Io.net.IpAddress) http.Server.Request {
    return .{
        .method = .get,
        .target = target,
        .path = target,
        .query = "",
        .head = .{
            .method = "GET",
            .target = target,
            .http1_0 = http1_0,
            .header_block = head_block,
            .content_length = 42,
            .has_content_length = true,
        },
        .body = body,
        .context = null,
        .peer = peer,
    };
}

test "entryFromRequest: pulls method/target/protocol/status/UA/referer/peer/content-length" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("192.0.2.9", 5555);
    const req = testRequest(
        "User-Agent: curl/8.0\r\nReferer: https://example.org/\r\n",
        "/status?x=1",
        false,
        &body,
        peer,
    );

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [256]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(201);
    try res.writeAll("hi");

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{
        .timestamp_ns = 99,
        .latency_ns = 12345,
        .request_id = "corr-1",
    });

    try testing.expectEqualStrings("GET", entry.method);
    try testing.expectEqualStrings("/status?x=1", entry.target);
    try testing.expectEqualStrings("HTTP/1.1", entry.protocol);
    try testing.expectEqual(@as(u16, 201), entry.status);
    try testing.expectEqualStrings("curl/8.0", entry.user_agent.?);
    try testing.expectEqualStrings("https://example.org/", entry.referer.?);
    try testing.expectEqualStrings("192.0.2.9:5555", entry.remote_addr.?);
    try testing.expectEqual(@as(?u64, 42), entry.request_bytes);
    try testing.expectEqual(@as(u64, 2), entry.response_bytes.?);
    try testing.expectEqual(@as(i64, 99), entry.timestamp_ns);
    try testing.expectEqual(@as(?u64, 12345), entry.latency_ns);
    try testing.expectEqualStrings("corr-1", entry.request_id.?);
}

test "entryFromRequest: HTTP/1.0 protocol, no peer, no UA/referer, request_bytes override" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", true, &body, null);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(404);

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{
        .timestamp_ns = 1,
        .request_bytes = 7,
    });

    try testing.expectEqualStrings("HTTP/1.0", entry.protocol);
    try testing.expectEqual(@as(?[]const u8, null), entry.remote_addr);
    try testing.expectEqual(@as(?[]const u8, null), entry.user_agent);
    try testing.expectEqual(@as(?[]const u8, null), entry.referer);
    try testing.expectEqual(@as(?u64, 7), entry.request_bytes); // override wins over content_length
}

test "entryFromRequest: addr_buf too small to hold the peer address leaves remote_addr null" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("192.0.2.9", 5555);
    const req = testRequest("", "/", false, &body, peer);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);

    // "192.0.2.9:5555" is 14 bytes; 1 byte is nowhere near enough, forcing
    // the write-failure path instead of the happy path.
    var addr_buf: [1]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });

    try testing.expectEqual(@as(?[]const u8, null), entry.remote_addr);
}

test "entryFromRequest output feeds straight into writeCombined without extra glue" {
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const peer = try std.Io.net.IpAddress.parse("203.0.113.5", 443);
    const req = testRequest("User-Agent: probe\r\n", "/health", false, &body, peer);

    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 5 });

    var line_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line_buf);
    try writeCombined(entry, &w);
    // The Entry still carries the full peer address — JSON/logfmt want the
    // port — but Combined's `%h` slot gets the host alone.
    try testing.expectEqualStrings("203.0.113.5:443", entry.remote_addr.?);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "203.0.113.5 - - "));
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"GET /health HTTP/1.1\" 200") != null);
}

test "entryFromRequest: 204 response streamed through .discard maps response_bytes to 0, not null" {
    // `responseBytesOf` has a 5-way switch over `res.body`; every other
    // test in this file only ever exercises the `.buffering` arm (the
    // default until the body is actually streamed). Force a `.discard`
    // body (HEAD/204/304, per `noBody()`) by flushing before `end()`, and
    // confirm the mapping is the documented `0` — not `null` (that would
    // read as "unknown", which is wrong: a discarded body's length is
    // exactly known to be zero) and not some other constant.
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", false, &body, null);

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(204);
    try res.writeAll("ignored-per-noBody");
    try res.flush();

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });
    try testing.expectEqual(@as(?u64, 0), entry.response_bytes);
}

test "entryFromRequest: identity-framed response maps response_bytes to the declared Content-Length" {
    // The `.identity` arm reads `res.declared_len.?` — the original
    // declared total, not the shrinking remaining-bytes counter in
    // `res.body.identity`. Confirm it reports the full declared length
    // after the whole body has been written (remaining counter at 0).
    var body: http.Server.RequestBody = .{ .none = .fixed("") };
    const req = testRequest("", "/", false, &body, null);

    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var chunk_buf: [16]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var res: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
    res.setStatus(200);
    try res.setHeader("Content-Length", "2");
    try res.writeAll("hi");
    try res.flush();

    var addr_buf: [64]u8 = undefined;
    const entry = entryFromRequest(&req, &res, &addr_buf, .{ .timestamp_ns = 1 });
    try testing.expectEqual(@as(?u64, 2), entry.response_bytes);
}

// ── external anchor: goaccess ────────────────────────────────────────────
//
// Oracle: goaccess 1.10.2 (`GoAccess - version 1.10.2 - Apr  1 2026`), an
// independent Apache/NGINX log analyser. The exact bytes asserted below were
// written to a file and fed to it:
//
//     goaccess -f al.log --log-format=COMBINED --no-global-config -o report.json
//
// and its `general.valid_requests` / `general.failed_requests` counters plus
// the `requests` panel were read back. Verdicts are recorded per test. The
// tool is NOT invoked by the test suite — the bytes are frozen here so the
// gate stays offline; re-run the command above to re-derive.
//
// The finding that justified this anchor: with `remote_addr` emitted verbatim
// (`192.0.2.1:54321`) goaccess failed **every** line —
// `Token '192.0.2.1:54321' doesn't match specifier '%h'`, valid=0 failed=2.
// See `hostOnly`. With the port stripped: valid=3, failed=0.

test "Combined: external anchor — CRLF injection stays one line" {
    // goaccess verdict: valid=1, failed=0, and the requests panel shows a
    // single entry `crlf\x0d\x0ainjection crlf\x0d\x0ainjection HTTP/1.1` —
    // the escaped CRLF did not forge a second record.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const entry: Entry = .{
        .timestamp_ns = 1000000005,
        .time_formatted = "22/Jul/2026:10:00:00 +0000",
        .remote_addr = "192.0.2.1:54321",
        .method = "crlf\r\ninjection",
        .target = "crlf\r\ninjection",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 512,
        .user_agent = "crlf\r\ninjection",
        .referer = "crlf\r\ninjection",
    };
    try writeCombined(entry, &w);
    const out = w.buffered();

    // Exactly one final newline, no carriage returns, no raw LF bytes
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);

    // Ends with the real closing quote-newline
    try testing.expect(std.mem.endsWith(u8, out, "\"\n"));

    // Expected byte-exact output (CRLF escaped as \x0d\x0a per spec)
    try testing.expectEqualStrings(
        "192.0.2.1 - - [22/Jul/2026:10:00:00 +0000] \"crlf\\x0d\\x0ainjection crlf\\x0d\\x0ainjection HTTP/1.1\" 200 512 \"crlf\\x0d\\x0ainjection\" \"crlf\\x0d\\x0ainjection\"\n",
        out,
    );
}

test "Combined: %h carries the host without the port (goaccess rejects a port)" {
    // The regression this pins: `remote_addr` is `host:port`, but Combined's
    // `%h` slot is host-only. Emitting the port made goaccess fail 100% of
    // lines — see the anchor note above.
    try testing.expectEqualStrings("192.0.2.1", hostOnly("192.0.2.1:54321"));
    try testing.expectEqualStrings("192.0.2.1", hostOnly("192.0.2.1"));
    try testing.expectEqualStrings("::1", hostOnly("[::1]:8080"));
    try testing.expectEqualStrings("2001:db8::1", hostOnly("[2001:db8::1]:443"));
    // A bare IPv6 literal has no port to strip.
    try testing.expectEqualStrings("2001:db8::1", hostOnly("2001:db8::1"));
    try testing.expectEqualStrings("", hostOnly(""));

    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(.{
        .timestamp_ns = 1,
        .time_formatted = "22/Jul/2026:10:00:00 +0000",
        .remote_addr = "[2001:db8::1]:443",
        .method = "GET",
        .target = "/a",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 512,
    }, &w);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "2001:db8::1 - - ["));
}

test "Combined: external anchor — quote escape prevents field breakout" {
    // goaccess verdict: valid=1, failed=0; the requests panel shows the whole
    // `quote\"inside quote\"inside HTTP/1.1` as one request field, i.e. the
    // escaped quote did not terminate it early.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const entry: Entry = .{
        .timestamp_ns = 1000000001,
        .time_formatted = "22/Jul/2026:10:00:00 +0000",
        .remote_addr = "192.0.2.1:54321",
        .method = "quote\"inside",
        .target = "quote\"inside",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 512,
        .user_agent = "quote\"inside",
        .referer = "quote\"inside",
    };
    try writeCombined(entry, &w);
    try testing.expectEqualStrings(
        "192.0.2.1 - - [22/Jul/2026:10:00:00 +0000] \"quote\\\"inside quote\\\"inside HTTP/1.1\" 200 512 \"quote\\\"inside\" \"quote\\\"inside\"\n",
        w.buffered(),
    );
}

test "JSON Lines: round-trips through std.json — CRLF stays escaped" {
    // NOT a foreign-ecosystem anchor: the only parser here is `std.json`. That
    // is still an implementation written outside this module (so it catches
    // malformed output and raw control bytes per RFC 8259), but it cannot
    // catch a misreading this module and Zig's std would share. No external
    // JSON tool was run against these bytes.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const entry: Entry = .{
        .timestamp_ns = 1000000005,
        .remote_addr = "192.0.2.1:54321",
        .method = "crlf\r\ninjection",
        .target = "crlf\r\ninjection",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 512,
        .user_agent = "crlf\r\ninjection",
        .referer = "crlf\r\ninjection",
    };
    try writeJsonLines(entry, &w);
    const out = w.buffered();

    // Exactly one line (no raw control bytes)
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);

    // Parse back through std.json to verify round-trip matches original payload
    const without_nl = out[0 .. out.len - 1];
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, without_nl, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try testing.expectEqualStrings("crlf\r\ninjection", obj.get("method").?.string);
    try testing.expectEqualStrings("crlf\r\ninjection", obj.get("target").?.string);
}

test "JSON Lines: round-trips through std.json — null byte escapes" {
    // Same caveat as above: `std.json` only, no external JSON tool.
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const entry: Entry = .{
        .timestamp_ns = 1000000007,
        .remote_addr = "192.0.2.1:54321",
        .method = "null\x00byte",
        .target = "null\x00byte",
        .protocol = "HTTP/1.1",
        .status = 200,
        .response_bytes = 512,
        .user_agent = "null\x00byte",
        .referer = "null\x00byte",
    };
    try writeJsonLines(entry, &w);
    const out = w.buffered();

    // No raw null bytes on wire
    try testing.expect(std.mem.indexOfScalar(u8, out, 0x00) == null);

    // Verify null bytes are escaped as \\u0000
    try testing.expect(std.mem.indexOf(u8, out, "\\u0000") != null);

    // Must round-trip exactly
    const without_nl = out[0 .. out.len - 1];
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, without_nl, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("null\x00byte", parsed.value.object.get("method").?.string);
}

// ── fuzz: arbitrary attacker bytes in every field, one record stays one line ─
//
// The three `write*` functions are the module's whole security surface:
// `method`/`target`/`protocol`/`user_agent`/`referer`/`remote_addr`/
// `request_id` are copied verbatim off the wire by `entryFromRequest`, so a
// log-injection bug here forges log RECORDS, not just ugly output. The
// curated `evil_payload` tests above pin a handful of hand-picked byte
// sequences; this pushes arbitrary bytes — including every control byte, lone
// `\r`, `"`, `\`, `=`, and NUL — through all three escapers at once.
//
// Three invariants, one per format, all of them structural rather than
// cosmetic:
//   * every format: the record is exactly one line — a single trailing `\n`
//     and no other `\n` anywhere. This is the injection property itself.
//   * JSON Lines: the line PARSES. Unconditionally, for any input bytes —
//     the owner's "the log must always be readable" requirement stated as an
//     oracle. Plus: a field that was valid UTF-8 comes back BYTE-EXACT (an
//     escaper that mangled or dropped bytes would still parse), and one that
//     was not comes back valid UTF-8 carrying U+FFFD.
//   * logfmt / Combined: no raw control byte survives into the output, so no
//     field can smuggle a terminal escape or a delimiter past the escaper.
//
// Deliberately not a round trip against our own reader — this module has no
// reader. `std.json` is a foreign parser; for logfmt/Combined the byte-class
// assertions are what stands in for one.

/// The widest field this harness feeds, and the per-field slot in the byte
/// pool below. JSON's `\u00XX` is the worst expansion (6x), so the output
/// buffer is sized for every field being maximum-length control bytes.
const fuzz_field_max = 32;

/// Draw one `Entry` with every attacker-controlled field filled from arbitrary
/// bytes.
///
/// ⚠ **The draw KIND is load-bearing, not taste.** On a plain (non-`-ffuzz`)
/// build `std.testing.fuzz` generates nothing: it runs the declared corpus and
/// then one empty input. A corpus-driven `Smith` reads every *weighted* draw as
/// a little-endian u64 and falls back to `weights[0].min` unless that u64 lands
/// inside the declared range — so `value(bool)` (range 0..1) and
/// `valueRangeAtMost(u8, 0, 32)` are the CONSTANT minimum for any input that is
/// not a hand-placed 8-byte integer. A harness built from those draws is a
/// harness where, off `zig build fuzz`, every optional is absent and every field
/// is empty: half of it does not exist. `Smith.bytes` is the one primitive that
/// copies its input through verbatim under both regimes, so presence flags and
/// field lengths are drawn as single bytes here, and lengths are drawn BEFORE
/// their payloads (`Smith.bytes` consumes `min(out.len, in.len)` and pads the
/// rest, so a length drawn afterwards would be reading padding).
///
/// One corpus input is therefore a plain byte string in exactly this order:
///
///     [flags:1] then, per field, [len:1][len bytes of payload]
///     then the numerics: [ts:8][status:8][request_bytes:8][response_bytes:8][latency_ns:8]
///
/// Trailing draws may be omitted — `Smith` pads a short input with zeroes
/// instead of failing — so a corpus entry only spells out what it cares about.
/// `fuzzCase` writes that encoding and the "corpus really reaches the fields"
/// test below pins the decode, so a change to this order goes red instead of
/// silently degenerating the corpus back to nothing.
fn fuzzEntry(smith: *std.testing.Smith, pool: *[8 * fuzz_field_max]u8) Entry {
    var flags: [1]u8 = undefined;
    smith.bytes(&flags);

    var fields: [8][]const u8 = undefined;
    // `inline` so each field gets its own call site: `Smith` keys the real
    // fuzzer's state on the caller's return address, and a runtime loop would
    // hand all eight fields the same draw.
    inline for (&fields, 0..) |*f, i| {
        var len_byte: [1]u8 = undefined;
        smith.bytes(&len_byte);
        const slot = pool[i * fuzz_field_max ..][0 .. len_byte[0] % (fuzz_field_max + 1)];
        smith.bytes(slot);
        f.* = slot;
    }

    // Numerics never reach an escaper (they render through `{d}`); they are
    // drawn unconditionally so the byte layout above does not depend on flags.
    const timestamp_ns = smith.value(i64);
    const status = smith.value(u16);
    const request_bytes = smith.value(u64);
    const response_bytes = smith.value(u64);
    const latency_ns = smith.value(u64);

    const present = flags[0];
    return .{
        .timestamp_ns = timestamp_ns,
        .time_formatted = if (present & 0x01 != 0) fields[0] else null,
        .remote_addr = if (present & 0x02 != 0) fields[1] else null,
        .method = fields[2],
        .target = fields[3],
        .protocol = fields[4],
        .status = status,
        .request_bytes = if (present & 0x20 != 0) request_bytes else null,
        .response_bytes = if (present & 0x40 != 0) response_bytes else null,
        .latency_ns = if (present & 0x80 != 0) latency_ns else null,
        .user_agent = if (present & 0x04 != 0) fields[5] else null,
        .referer = if (present & 0x08 != 0) fields[6] else null,
        .request_id = if (present & 0x10 != 0) fields[7] else null,
    };
}

/// Encode one corpus input in `fuzzEntry`'s draw order. Field slots, in order:
/// `time_formatted`, `remote_addr`, `method`, `target`, `protocol`,
/// `user_agent`, `referer`, `request_id`.
fn fuzzCase(comptime flags: u8, comptime fields: [8][]const u8) []const u8 {
    comptime {
        var out: []const u8 = &[_]u8{flags};
        for (fields) |f| {
            if (f.len > fuzz_field_max) @compileError("corpus field longer than the harness pool");
            out = out ++ [_]u8{@as(u8, @intCast(f.len))} ++ f;
        }
        return out;
    }
}

/// All eight slots present.
const all_fields: u8 = 0xFF;

/// The written corpus. **A weighted draw is not a random draw and a random
/// corpus is not a corpus** — off `zig build fuzz` these bytes are the only
/// thing that runs (plus one empty input), so every ill-formed UTF-8 shape the
/// policy has to handle is placed here by hand, in the fields that reach an
/// escaper. Under `zig build fuzz` they are the seeds the mutator starts from.
const fuzz_corpus = [_][]const u8{
    // Lone surrogates, truncated leads, bare continuations — one per slot, so
    // no single slot carries the whole burden.
    fuzzCase(all_fields, .{ "\xff", "\x80", "GET", "/\xed\xa0\x80", "HTTP/1.1", "curl\xc3", "\xe2\x82", "\xf0\x9f\x98" }),
    // Overlongs and out-of-range leads, with two realistic fields alongside so
    // the record is not uniformly hostile.
    fuzzCase(all_fields, .{ "22/Jul/2026:10:00:00 +0000", "192.0.2.1:54321", "\xc0\xaf", "\xe0\x80\xaf", "\xf4\x90\x80\x80", "a\xffb", "\x80\x80\x80", "\xf5\xf6\xf7" }),
    // Ill-formed bytes AND the injection payload in the same record: the two
    // defences have to hold at once, not one at a time.
    fuzzCase(all_fields, .{ "\"\r\n", "\\\xff", "\x00\x1f\x7f", "\xff\"\r\n{\"a\":1}", "\xf0", "\xed\xbf\xbf", "\xc2", "\xe2\x82\xac" }),
    // Every field at the pool maximum, all ill-formed: the widest expansion the
    // output buffer has to absorb (3 bytes of U+FFFD per input byte).
    fuzzCase(all_fields, .{ "\xff" ** 32, "\x80" ** 32, "\xed\xa0\x80" ** 10, "\xc0" ** 32, "\xf5" ** 32, "\xfe" ** 32, "\xe2\x82" ** 16, "\xf0\x9f\x98" ** 10 }),
    // Well-formed control: all-valid UTF-8 across the whole of Table 3-7, so a
    // sweep cannot pass by sanitizing everything into U+FFFD.
    fuzzCase(all_fields, .{ "22/Jul/2026:10:00:00 +0000", "[2001:db8::1]:443", "GET", "/\u{00e9}\u{20ac}\u{1f600}", "HTTP/1.1", "curl/8.0 \u{fffd}", "https://example.org/", "req-1" }),
    // No optionals at all: the `null` rendering path, with the three required
    // string fields still ill-formed.
    fuzzCase(0x00, .{ "", "", "\xff", "\xed\xa0\x80", "\xe2\x82", "", "", "" }),
    // Everything empty — the degenerate record, which must still be one line.
    fuzzCase(0x00, .{ "", "", "", "", "", "", "", "" }),
};

/// `out` must end with exactly one `\n` and contain no other one: whatever the
/// fields carried, the reader downstream sees a single record.
fn expectOneLine(out: []const u8) !void {
    try testing.expect(out.len > 0);
    try testing.expectEqual(@as(u8, '\n'), out[out.len - 1]);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, out[0 .. out.len - 1], '\n'));
}

test "fuzz corpus: the written inputs really reach the fields that matter" {
    // Without this, a change to `fuzzEntry`'s draw order turns every corpus
    // entry into padding and all three sweeps below keep passing — on an empty
    // record. Degenerate input is exactly where a fixed and a broken escaper
    // agree, so the corpus being non-degenerate is itself an assertion.
    var pool: [8 * fuzz_field_max]u8 = undefined;

    // The first entry decodes to precisely what `fuzzCase` was handed.
    var smith: std.testing.Smith = .{ .in = fuzz_corpus[0] };
    const first = fuzzEntry(&smith, &pool);
    try testing.expectEqualStrings("\xff", first.time_formatted.?);
    try testing.expectEqualStrings("\x80", first.remote_addr.?);
    try testing.expectEqualStrings("GET", first.method);
    try testing.expectEqualStrings("/\xed\xa0\x80", first.target);
    try testing.expectEqualStrings("HTTP/1.1", first.protocol);
    try testing.expectEqualStrings("curl\xc3", first.user_agent.?);
    try testing.expectEqualStrings("\xe2\x82", first.referer.?);
    try testing.expectEqualStrings("\xf0\x9f\x98", first.request_id.?);

    // …and the absent-optionals entry really leaves them absent.
    var smith2: std.testing.Smith = .{ .in = fuzz_corpus[5] };
    const bare = fuzzEntry(&smith2, &pool);
    try testing.expectEqual(@as(?[]const u8, null), bare.user_agent);
    try testing.expectEqual(@as(?[]const u8, null), bare.remote_addr);
    try testing.expectEqual(@as(?u64, null), bare.latency_ns);
    try testing.expectEqualStrings("\xff", bare.method);

    // Across the corpus, every JSON-visible slot carries ill-formed UTF-8 at
    // least once, and at least one record is entirely well-formed.
    var ill_formed: [7]bool = @splat(false);
    var any_all_valid = false;
    for (fuzz_corpus) |input| {
        var s: std.testing.Smith = .{ .in = input };
        const e = fuzzEntry(&s, &pool);
        const slots = [7]?[]const u8{
            e.method,     e.target,  e.protocol,   e.remote_addr,
            e.user_agent, e.referer, e.request_id,
        };
        var all_valid = true;
        for (slots, 0..) |slot, i| if (slot) |v| {
            if (!std.unicode.utf8ValidateSlice(v)) {
                ill_formed[i] = true;
                all_valid = false;
            }
        };
        any_all_valid = any_all_valid or (all_valid and e.target.len != 0);
    }
    for (ill_formed, 0..) |seen, i| {
        testing.expect(seen) catch |err| {
            std.debug.print("corpus never puts ill-formed UTF-8 in slot {d}\n", .{i});
            return err;
        };
    }
    try testing.expect(any_all_valid);
}

test "fuzz: JSON Lines always parses, whatever bytes the fields carry" {
    try testing.fuzz({}, fuzzJsonLines, .{ .corpus = &fuzz_corpus });
}

fn fuzzJsonLines(_: void, smith: *std.testing.Smith) !void {
    var pool: [8 * fuzz_field_max]u8 = undefined;
    const entry = fuzzEntry(smith, &pool);

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeJsonLines(entry, &w);
    const out = w.buffered();
    try expectOneLine(out);

    // ⭐ ONE-SIDED AND ABSOLUTE. There is no `catch` here and no predicate
    // guarding it: for ANY input bytes the line parses. That single `try` is
    // the direct proof of the module's "the log must always be readable"
    // requirement, and it is a strictly stronger oracle than the two-sided
    // "parses iff the fields were UTF-8" it replaced — that one passed happily
    // on unparseable output as long as it could explain why.
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        out[0 .. out.len - 1],
        .{},
    );
    defer parsed.deinit();
    const obj = parsed.value.object;

    try expectFieldPolicy(entry.method, obj.get("method").?.string);
    try expectFieldPolicy(entry.target, obj.get("target").?.string);
    try expectFieldPolicy(entry.protocol, obj.get("protocol").?.string);
    const opts = [_]struct { k: []const u8, v: ?[]const u8 }{
        .{ .k = "remote_addr", .v = entry.remote_addr },
        .{ .k = "user_agent", .v = entry.user_agent },
        .{ .k = "referer", .v = entry.referer },
        .{ .k = "request_id", .v = entry.request_id },
    };
    for (opts) |o| switch (obj.get(o.k).?) {
        .null => try testing.expectEqual(@as(?[]const u8, null), o.v),
        .string => |s| try expectFieldPolicy(o.v.?, s),
        else => return error.TestUnexpectedResult,
    };
}

/// What the parsed-back field must be, given what went in:
///   * always valid UTF-8 — that is what made the line parseable;
///   * byte-exact when the input was valid UTF-8 (the surviving half of the
///     round-trip guarantee);
///   * otherwise carrying at least one U+FFFD, so the loss is marked rather
///     than silent, and never longer than the 3x worst case.
fn expectFieldPolicy(in: []const u8, got: []const u8) !void {
    try testing.expect(std.unicode.utf8ValidateSlice(got));
    if (std.unicode.utf8ValidateSlice(in)) {
        try testing.expectEqualStrings(in, got);
    } else {
        try testing.expect(std.mem.indexOf(u8, got, replacement) != null);
        try testing.expect(got.len <= in.len * replacement.len);
    }
}

test "fuzz: logfmt stays one line with no raw control byte" {
    try testing.fuzz({}, fuzzLogfmt, .{ .corpus = &fuzz_corpus });
}

fn fuzzLogfmt(_: void, smith: *std.testing.Smith) !void {
    var pool: [8 * fuzz_field_max]u8 = undefined;
    const entry = fuzzEntry(smith, &pool);

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeLogfmt(entry, &w);
    const out = w.buffered();
    try expectOneLine(out);
    for (out[0 .. out.len - 1]) |c| try testing.expect(c >= 0x20);
}

test "fuzz: Combined stays one line with no raw control byte" {
    try testing.fuzz({}, fuzzCombined, .{ .corpus = &fuzz_corpus });
}

fn fuzzCombined(_: void, smith: *std.testing.Smith) !void {
    var pool: [8 * fuzz_field_max]u8 = undefined;
    const entry = fuzzEntry(smith, &pool);

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCombined(entry, &w);
    const out = w.buffered();
    try expectOneLine(out);
    for (out[0 .. out.len - 1]) |c| try testing.expect(c >= 0x20 and c != 0x7F);
}

// ── UTF-8 sanitization: the "always readable" requirement ────────────────
//
// The defect this closes was found by the fuzz harness above on its first
// sweep and was left open as a format-policy decision. The owner's verdict
// (2026-08-11): **the access log must always be readable; a bad byte must
// never break it.** `writeJsonString` therefore substitutes U+FFFD for
// ill-formed UTF-8, and the fuzz oracle above is now one-sided — the line
// parses, full stop.
//
// These tests assert the exact BYTES emitted, not "it parses". A test written
// in terms of the policy ("expect one replacement per maximal subpart") would
// re-assert the policy rather than pin it; only a literal expected string can
// tell maximal-subpart substitution from per-byte substitution.

/// Emit `field` as the `user_agent` of a JSON Lines record and return the
/// value between the quotes, so a test can assert the exact bytes written.
fn jsonUserAgentBody(out: []u8, field: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    var entry = sampleEntry();
    entry.user_agent = field;
    try writeJsonLines(entry, &w);
    const line = w.buffered();
    const key = "\"user_agent\":\"";
    const start = std.mem.indexOf(u8, line, key).? + key.len;
    // Scan to the CLOSING quote, not the first one: `\"` is inside the value.
    var end = start;
    while (line[end] != '"') : (end += 1) {
        if (line[end] == '\\') end += 1;
    }
    return line[start..end];
}

test "JSON: ill-formed UTF-8 becomes U+FFFD, one per MAXIMAL SUBPART, exact bytes" {
    const R = replacement; // "\u{fffd}" = EF BF BD
    const cases = [_]struct { in: []const u8, want: []const u8, why: []const u8 }{
        // ── the discriminating cases: a truncated but otherwise valid prefix
        // is ONE ill-formed subsequence, so it costs ONE U+FFFD. Substituting
        // per byte — Go's `encoding/json`, whose `utf8.DecodeRune` reports
        // size 1 on every error — would emit two here and three below.
        .{ .in = "\xe2\x82", .want = R, .why = "truncated 3-byte lead of U+20AC" },
        .{ .in = "\xf0\x9f\x98", .want = R, .why = "truncated 4-byte lead of U+1F600" },
        .{ .in = "\xc3", .want = R, .why = "truncated 2-byte lead" },
        .{ .in = "\xf0\x9f", .want = R, .why = "4-byte lead truncated after two" },

        // ── lone surrogates: ill-formed in UTF-8 (Table 3-7 caps ED's second
        // byte at 9F). ED A0 is not a prefix of anything well-formed, so the
        // maximal subpart is ED alone and the two continuation bytes are each
        // their own — three U+FFFD, the same as a per-byte policy would give.
        // Enumerated precisely because the two policies AGREE here: this case
        // discriminates a correct table from a lazy "80..BF times n" check,
        // not one policy from the other.
        .{ .in = "\xed\xa0\x80", .want = R ++ R ++ R, .why = "U+D800 high surrogate" },
        .{ .in = "\xed\xbf\xbf", .want = R ++ R ++ R, .why = "U+DFFF low surrogate" },
        .{ .in = "\xed\xa0\xbd\xed\xb8\x80", .want = R ** 6, .why = "CESU-8 surrogate pair" },

        // ── overlong encodings.
        .{ .in = "\xc0\xaf", .want = R ++ R, .why = "overlong '/' (C0 AF)" },
        .{ .in = "\xc1\xbf", .want = R ++ R, .why = "overlong U+007F" },
        .{ .in = "\xe0\x80\xaf", .want = R ** 3, .why = "3-byte overlong '/'" },
        .{ .in = "\xf0\x80\x80\xaf", .want = R ** 4, .why = "4-byte overlong '/'" },

        // ── past U+10FFFF.
        .{ .in = "\xf4\x90\x80\x80", .want = R ** 4, .why = "U+110000" },
        .{ .in = "\xf5\x80\x80\x80", .want = R ** 4, .why = "F5: no such lead byte" },
        .{ .in = "\xff", .want = R, .why = "FF: never appears in UTF-8" },
        .{ .in = "\xfe\xfe\xff\xff", .want = R ** 4, .why = "a BOM-ish byte run" },

        // ── bare continuation bytes.
        .{ .in = "\x80", .want = R, .why = "lone continuation" },
        .{ .in = "\x80\xbf\x80", .want = R ** 3, .why = "run of continuations" },

        // ── interleaving with well-formed text: only the bad part is touched.
        .{ .in = "curl\xffbad", .want = "curl" ++ R ++ "bad", .why = "the finding's own vector" },
        .{ .in = "a\xe2\x82b", .want = "a" ++ R ++ "b", .why = "truncated lead between letters" },
        .{ .in = "\xe2\x82\xac\xff\xe2\x82\xac", .want = "\u{20ac}" ++ R ++ "\u{20ac}", .why = "bad byte between two euros" },

        // ── well-formed input is passed through untouched, every sequence
        // length and every boundary of Table 3-7 (a degenerate all-ASCII
        // sample could not tell a sanitizing writer from a verbatim one).
        .{ .in = "curl/8.0", .want = "curl/8.0", .why = "ASCII" },
        .{ .in = "\xc2\x80", .want = "\u{0080}", .why = "shortest 2-byte" },
        .{ .in = "\xdf\xbf", .want = "\u{07ff}", .why = "longest 2-byte" },
        .{ .in = "\xe0\xa0\x80", .want = "\u{0800}", .why = "shortest 3-byte" },
        .{ .in = "\xed\x9f\xbf", .want = "\u{d7ff}", .why = "last before the surrogates" },
        .{ .in = "\xee\x80\x80", .want = "\u{e000}", .why = "first after the surrogates" },
        .{ .in = "\xef\xbf\xbf", .want = "\u{ffff}", .why = "longest 3-byte" },
        .{ .in = "\xf0\x90\x80\x80", .want = "\u{10000}", .why = "shortest 4-byte" },
        .{ .in = "\xf4\x8f\xbf\xbf", .want = "\u{10ffff}", .why = "the last code point" },
        .{ .in = R, .want = R, .why = "a U+FFFD the CLIENT sent is not touched" },
    };

    var buf: [1024]u8 = undefined;
    for (cases) |c| {
        const got = try jsonUserAgentBody(&buf, c.in);
        testing.expectEqualStrings(c.want, got) catch |err| {
            std.debug.print("case: {s}\n", .{c.why});
            return err;
        };
    }
}

// ── external anchor: CPython's `json`, on these exact vectors ────────────
//
// Oracle: `python3 -c "json.loads(line.decode('utf-8'))"` — a parser from
// another ecosystem that enforces RFC 8259's UTF-8 requirement at the decode
// step, not merely at the grammar. The 16 vectors of the test below were
// written to a file and fed to it. Verdict, captured 2026-08-11:
//
//   * with sanitization: **16/16 lines accepted**, the whole file decodes as
//     UTF-8, 155 U+FFFD emitted across it.
//   * with the pass-through escaper this replaced (the sanitizer's ill-formed
//     branch mutated back to `writeAll(s[i..][0..step.len])`): **14/16 lines
//     REJECTED**, `UnicodeDecodeError`.
//
// So the anchor discriminates — it is not a check that passes either way.
// ⚠ `jq` is NOT a usable oracle here: `jq -e . file` exits 0 on both versions,
// because jq substitutes U+FFFD for ill-formed input bytes itself while
// reading. A consumer that is lenient in exactly the way this module now is
// cannot testify that the module is.
//
// The tool is not invoked by the suite — the bytes are generated by the test
// below and the verdict is frozen here, so the gate stays offline.
test "JSON: every emitted line parses and every field is valid UTF-8, for the same vectors" {
    // The exact-bytes test above pins the policy; this one pins the PROPERTY
    // the policy exists for. Both are needed: exact bytes that nothing parses
    // would be a wrong policy pinned perfectly.
    const vectors = [_][]const u8{
        "\xff",                  "\x80",         "\xc0\xaf",
        "\xe0\x80\xaf",          "\xed\xa0\x80", "\xed\xbf\xbf",
        "\xf4\x90\x80\x80",      "\xe2\x82",     "\xf0\x9f\x98",
        "\xc3",                  "curl\xffbad",  "\xf5\xf6\xf7\xf8",
        "\x80\x80\x80\x80\x80",  evil_payload,   "\xff\"\r\n{\"a\":1}",
        "\u{20ac} ok \u{1f600}",
    };
    var buf: [2048]u8 = undefined;
    for (vectors) |v| {
        var w: std.Io.Writer = .fixed(&buf);
        var entry = sampleEntry();
        entry.user_agent = v;
        entry.target = v;
        entry.method = v;
        entry.remote_addr = v;
        entry.referer = v;
        entry.request_id = v;
        entry.protocol = v;
        try writeJsonLines(entry, &w);
        const out = w.buffered();
        try expectOneLine(out);

        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            testing.allocator,
            out[0 .. out.len - 1],
            .{},
        );
        defer parsed.deinit();
        for ([_][]const u8{ "method", "target", "protocol", "remote_addr", "user_agent", "referer", "request_id" }) |k| {
            try testing.expect(std.unicode.utf8ValidateSlice(parsed.value.object.get(k).?.string));
        }
    }
}

test "JSON: sanitization does not weaken any escape — the C0 controls, quote and backslash" {
    // The sanitizer rewrote the whole loop; this asserts the escaping half of
    // it byte-for-byte, independently of the UTF-8 half. Every byte 0x00-0x1F
    // must leave as an escape and none of them as itself, `"` must never
    // appear bare inside the value, and `\` must always double.
    var buf: [1024]u8 = undefined;
    for (0..0x20) |b| {
        const raw = [_]u8{@intCast(b)};
        const got = try jsonUserAgentBody(&buf, &raw);
        // `\u00XX` in lower-case hex for everything without a short escape.
        var want_buf: [6]u8 = undefined;
        const want: []const u8 = switch (b) {
            0x08 => "\\b",
            0x09 => "\\t",
            0x0A => "\\n",
            0x0C => "\\f",
            0x0D => "\\r",
            else => try std.fmt.bufPrint(&want_buf, "\\u{x:0>4}", .{b}),
        };
        try testing.expectEqualStrings(want, got);
    }
    try testing.expectEqualStrings("\\\"", try jsonUserAgentBody(&buf, "\""));
    try testing.expectEqualStrings("\\\\", try jsonUserAgentBody(&buf, "\\"));
    // 0x7F is not a JSON control character (RFC 8259 §7 stops at 0x1F) and is
    // valid UTF-8, so it still passes through — unchanged by this work.
    try testing.expectEqualStrings("\x7f", try jsonUserAgentBody(&buf, "\x7f"));
}

test "utf8Step: well-formedness agrees with std.unicode over an exhaustive byte sweep" {
    // An independent oracle for the classification half of the policy: std's
    // validator, a different implementation, over every 1- and 2-byte string
    // and every 3-/4-byte string built from the boundary bytes that Table 3-7
    // actually splits on. A hand-written table is exactly the kind of thing
    // that is wrong in one range and right everywhere else.
    const tails = [_]u8{ 0x00, 0x7F, 0x80, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF };
    var b0: usize = 0;
    while (b0 < 0x100) : (b0 += 1) {
        var b1: usize = 0;
        while (b1 < 0x100) : (b1 += 1) {
            for (tails) |t2| for (tails) |t3| {
                const s = [_]u8{ @intCast(b0), @intCast(b1), t2, t3 };
                for (1..5) |n| {
                    const step = utf8Step(s[0..n]);
                    try testing.expect(step.len >= 1 and step.len <= n);
                    if (step.ok) {
                        // A well-formed step must be exactly one code point…
                        try testing.expect(std.unicode.utf8ValidateSlice(s[0..step.len]));
                        try testing.expectEqual(step.len, try std.unicode.utf8ByteSequenceLength(s[0]));
                    } else {
                        // …and an ill-formed one must not be a valid sequence
                        // however far you extend it inside this string.
                        var n2 = step.len;
                        while (n2 <= n) : (n2 += 1) {
                            try testing.expect(!std.unicode.utf8ValidateSlice(s[0..n2]));
                        }
                    }
                }
            };
        }
    }
}

test "utf8Step: the maximal subpart is a prefix of something well-formed, brute-forced" {
    // The subpart LENGTH is the half `utf8ValidateSlice` cannot check. Oracle:
    // a reported ill-formed length L is maximal iff `s[0..L]` can still be
    // completed into a well-formed sequence (or L == 1) and `s[0..L+1]` cannot
    // — brute-forced over the 64 continuation bytes, so the expected value
    // comes from std, not from a second copy of this module's table.
    const S = struct {
        fn completable(prefix: []const u8) bool {
            const want = std.unicode.utf8ByteSequenceLength(prefix[0]) catch return false;
            if (prefix.len > want) return false;
            if (prefix.len == want) return std.unicode.utf8ValidateSlice(prefix);
            var buf: [4]u8 = undefined;
            @memcpy(buf[0..prefix.len], prefix);
            const missing = want - prefix.len;
            var c: usize = 0;
            while (c < (@as(usize, 1) << @intCast(6 * missing))) : (c += 1) {
                for (0..missing) |k| {
                    buf[prefix.len + k] = 0x80 | @as(u8, @intCast((c >> @intCast(6 * k)) & 0x3F));
                }
                if (std.unicode.utf8ValidateSlice(buf[0..want])) return true;
            }
            return false;
        }
    };
    const inputs = [_][]const u8{
        "\xe2\x82",         "\xe2\x82\x28", "\xf0\x9f\x98", "\xf0\x9f",
        "\xc3",             "\xed\xa0\x80", "\xe0\x80\xaf", "\xf0\x80\x80\xaf",
        "\xf4\x90\x80\x80", "\xc0\xaf",     "\x80\xbf",     "\xff\xfe",
        "\xe0\xa0",         "\xed\x9f",     "\xf4\x8f\xbf", "\xf1\x80\x80",
    };
    for (inputs) |s| {
        const step = utf8Step(s);
        if (step.ok) continue;
        try testing.expect(step.len >= 1);
        // Maximal: it is completable (unless it is the unavoidable 1)…
        if (step.len > 1) try testing.expect(S.completable(s[0..step.len]));
        // …and one byte further is not, so nothing longer was available.
        if (step.len < s.len) try testing.expect(!S.completable(s[0 .. step.len + 1]));
    }
}

test "JSON: the byte-exact round trip still holds for every valid-UTF-8 field" {
    // What the module still guarantees after the change, stated as its own
    // test so the guarantee is not merely a sentence in a doc comment.
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var entry = sampleEntry();
    const payload = "GET /π?q=\u{1f600}&x=\"a\\b\"\t\u{00ff}\u{10ffff}";
    entry.method = payload;
    entry.target = payload;
    entry.user_agent = payload;
    entry.referer = payload;
    entry.request_id = payload;
    try writeJsonLines(entry, &w);
    const out = w.buffered();
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        out[0 .. out.len - 1],
        .{},
    );
    defer parsed.deinit();
    for ([_][]const u8{ "method", "target", "user_agent", "referer", "request_id" }) |k| {
        try testing.expectEqualStrings(payload, parsed.value.object.get(k).?.string);
    }
    // …and no replacement character was invented along the way.
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, out, replacement));
}

test "logfmt/Combined pass ill-formed bytes through — byte-oriented formats, deliberately" {
    // Scope statement, pinned: only JSON Lines carries an encoding requirement
    // (RFC 8259), so only JSON Lines sanitizes. logfmt and Combined are
    // byte-oriented text formats and a consumer of theirs (goaccess 1.10.2,
    // measured) reads such a line fine. Changing them would cost the byte-exact
    // round trip they still give. If this ever goes red, SPEC.md's
    // "what is preserved" table is wrong, not this test.
    var buf: [1024]u8 = undefined;
    var entry = sampleEntry();
    entry.user_agent = "curl\xffbad";

    var lw: std.Io.Writer = .fixed(&buf);
    try writeLogfmt(entry, &lw);
    try testing.expect(std.mem.indexOfScalar(u8, lw.buffered(), 0xFF) != null);

    var cbuf: [1024]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&cbuf);
    try writeCombined(entry, &cw);
    try testing.expect(std.mem.indexOfScalar(u8, cw.buffered(), 0xFF) != null);

    // …while the same entry's JSON Lines record carries no such byte.
    var jbuf: [1024]u8 = undefined;
    var jw: std.Io.Writer = .fixed(&jbuf);
    try writeJsonLines(entry, &jw);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, jw.buffered(), 0xFF));
}

test {
    _ = @import("bench.zig");
}
