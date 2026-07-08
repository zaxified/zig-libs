// SPDX-License-Identifier: MIT

//! Range requests (RFC 7233) — **R1: the `Range` request-header parser**.
//!
//! This layer parses the `Range` request header's `byte-ranges-specifier`
//! (RFC 7233 §2.1) into a list of `ByteRangeSpec`s. It is pure syntax: it does
//! NOT resolve the specs against a concrete representation length — clamping to
//! the length, choosing 206 vs 416, and emitting `Content-Range` is the 206
//! response helper's job (R2), and the multi-range `multipart/byteranges` body
//! is R3. Keeping the parse standalone means a caller can accept/reject a range
//! request before it even knows the resource length.
//!
//! ## Grammar (RFC 7233 §2.1)
//!
//! ```
//! Range              = byte-ranges-specifier / other-ranges-specifier
//! byte-ranges-specifier = bytes-unit "=" byte-range-set
//! bytes-unit         = "bytes"
//! byte-range-set     = 1#( byte-range-spec / suffix-byte-range-spec )
//! byte-range-spec    = first-byte-pos "-" [ last-byte-pos ]
//! suffix-byte-range-spec = "-" suffix-length
//! ```
//!
//! Three spec shapes:
//! - `first-last`  (`0-499`)   — an absolute, inclusive `[first, last]`.
//! - `first-`      (`9500-`)   — from `first` to the end of the representation.
//! - `-suffix`     (`-500`)    — the final `suffix` bytes.
//!
//! Only the `bytes` unit is recognized; any other range unit is an extension a
//! recipient MAY ignore, so `parse` reports it as `error.InvalidUnit` and the
//! caller just serves the whole representation (200) as if no `Range` were sent.
//!
//! ## Usage
//!
//! ```zig
//! var buf: [8]http.range.ByteRangeSpec = undefined;
//! const specs = http.range.parse(req.header("range") orelse "", &buf) catch {
//!     // Malformed or unsupported Range -> ignore it, serve 200 (RFC 7233 §2.1,
//!     // §3.1: an invalid Range MUST be ignored, not 416'd).
//!     return serveWhole(rw);
//! };
//! // `specs` are validated byte-range-specs; hand them to the R2 206 helper
//! // together with the representation length.
//! ```
//!
//! ## Validity (RFC 7233 §2.1)
//!
//! - `first-last`: valid iff `last >= first`. A `last < first` spec makes the
//!   whole `Range` header invalid (parse errors), because a recipient that
//!   cannot satisfy *any* sub-range of a syntactically-valid set still must not
//!   act on a malformed one.
//! - `-suffix`: a `suffix` of 0 selects zero bytes; RFC 7233 lets a server
//!   treat it as unsatisfiable, but syntactically `-0` is well-formed, so it is
//!   returned as `.{ .suffix = 0 }` and left for R2 to map to 416.
//! - Positions are `u64`; a value that overflows `u64` errors (`error.Overflow`).
//! - The set is `1#`, so an empty set (`bytes=`) is invalid.
//! - Whitespace: OWS is tolerated around `=`, around the commas, and at the ends
//!   of each spec (RFC 7233 ABNF + RFC 9110 list rule with optional OWS).

const std = @import("std");

/// Refuse a `Range` header that lists more than this many sub-ranges. An
/// unbounded range set is a documented amplification vector (each range can
/// force a separate `multipart/byteranges` part); RFC 7233 §6.1 explicitly
/// permits a server to reject or coalesce excessive ranges. Callers using the
/// fixed-buffer `parse` are additionally bounded by their buffer length.
pub const default_max_ranges: usize = 16;

/// One byte-range-spec from a `Range: bytes=…` set, as written on the wire and
/// **not yet** resolved against a representation length. Tagged per RFC 7233
/// §2.1's three shapes; R2 switches on this to compute the satisfiable byte
/// interval and `Content-Range`.
pub const ByteRangeSpec = union(enum) {
    /// `first-last` — inclusive absolute bounds, `last >= first` guaranteed.
    range: struct { first: u64, last: u64 },
    /// `first-` — from `first` to the last byte of the representation.
    from: u64,
    /// `-suffix` — the final `suffix` bytes (`suffix` may be 0).
    suffix: u64,

    /// True for the `-suffix` form (needs the representation length to resolve
    /// its start). Convenience for R2.
    pub fn isSuffix(self: ByteRangeSpec) bool {
        return self == .suffix;
    }
};

pub const Error = error{
    /// The unit before `=` was absent or not `bytes` (case-insensitive).
    InvalidUnit,
    /// A spec was syntactically malformed (missing `-`, non-digit, empty spec,
    /// `last < first`, or an empty set).
    InvalidRange,
    /// A byte position did not fit in `u64`.
    Overflow,
    /// More sub-ranges than the destination buffer (or `default_max_ranges`
    /// when using `parse`) can hold.
    TooManyRanges,
};

/// Parse a full `Range` header value (e.g. `bytes=0-499, -500, 9500-`) into
/// `out`, returning the filled prefix. Strict: any malformed spec, a bad unit,
/// an empty set, or a `last < first` range fails the whole header (the caller
/// then serves 200). `out.len` bounds the number of ranges (`error.TooManyRanges`
/// beyond it).
pub fn parse(raw: []const u8, out: []ByteRangeSpec) Error![]ByteRangeSpec {
    var it = try iterator(raw);
    var n: usize = 0;
    while (try it.next()) |spec| {
        if (n == out.len) return error.TooManyRanges;
        out[n] = spec;
        n += 1;
    }
    if (n == 0) return error.InvalidRange; // 1#: the set must be non-empty
    return out[0..n];
}

/// A streaming, allocation-free view over a `Range` header's byte-range-set.
/// `iterator` validates the `bytes=` unit up front; `next` then yields one
/// validated `ByteRangeSpec` per comma-separated element (or an error on the
/// first malformed one). Prefer `parse` unless you want to stop early / avoid a
/// buffer.
pub const Iterator = struct {
    /// The remaining byte-range-set text (after `bytes=`), advanced by `next`.
    rest: []const u8,

    /// Yield the next validated spec, `null` at the end, or an `Error` on the
    /// first malformed element. Skips the RFC 9110 list rule's legal empty
    /// elements (`bytes=0-499,,600-699` — a stray comma is not itself an error;
    /// it is elided) but a set that is *only* empty elements yields no specs
    /// (which `parse` then rejects as `InvalidRange`).
    pub fn next(self: *Iterator) Error!?ByteRangeSpec {
        // Skip OWS and empty list elements (stray commas are legal per the
        // RFC 9110 #rule and are elided).
        var i: usize = 0;
        while (i < self.rest.len and
            (self.rest[i] == ' ' or self.rest[i] == '\t' or self.rest[i] == ','))
        {
            i += 1;
        }
        self.rest = self.rest[i..];
        if (self.rest.len == 0) return null;

        // Slice the next element up to the next ',' (none occurs inside a
        // byte-range-spec) and advance past it.
        var tok: []const u8 = undefined;
        if (std.mem.indexOfScalar(u8, self.rest, ',')) |comma| {
            tok = self.rest[0..comma];
            self.rest = self.rest[comma + 1 ..];
        } else {
            tok = self.rest;
            self.rest = self.rest[self.rest.len..];
        }
        tok = std.mem.trim(u8, tok, " \t");
        return try parseSpec(tok);
    }
};

/// Build an `Iterator` over `raw`'s byte-range-set. Validates that `raw` starts
/// with the `bytes` unit (OWS-tolerant, case-insensitive) followed by `=`;
/// returns `error.InvalidUnit` otherwise. Does not yet parse any spec.
pub fn iterator(raw: []const u8) Error!Iterator {
    const trimmed = std.mem.trim(u8, raw, " \t");
    const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidUnit;
    const unit = std.mem.trim(u8, trimmed[0..eq], " \t");
    if (!std.ascii.eqlIgnoreCase(unit, "bytes")) return error.InvalidUnit;
    return .{ .rest = trimmed[eq + 1 ..] };
}

/// Parse a single, already-comma-split and OWS-trimmed byte-range-spec token
/// (`0-499`, `9500-`, or `-500`). Exposed for tests; `Iterator.next` calls it.
pub fn parseSpec(tok: []const u8) Error!ByteRangeSpec {
    // Positions are DIGIT only (no sign), so the first '-' is the separator.
    const dash = std.mem.indexOfScalar(u8, tok, '-') orelse return error.InvalidRange;
    const before = tok[0..dash];
    const after = tok[dash + 1 ..];

    if (before.len == 0) {
        // suffix-byte-range-spec: `-suffix` — the suffix must be present.
        return .{ .suffix = try parsePos(after) };
    }
    const first = try parsePos(before);
    if (after.len == 0) return .{ .from = first };
    const last = try parsePos(after);
    if (last < first) return error.InvalidRange;
    return .{ .range = .{ .first = first, .last = last } };
}

/// Parse a non-empty run of DIGITs into a `u64` byte position.
fn parsePos(s: []const u8) Error!u64 {
    if (s.len == 0) return error.InvalidRange;
    // parseInt would tolerate a '+' sign and '_' separators; RFC 7233 positions
    // are DIGIT-only, so reject anything else up front.
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidRange;
    }
    return std.fmt.parseInt(u64, s, 10) catch |err| switch (err) {
        error.InvalidCharacter => error.InvalidRange,
        error.Overflow => error.Overflow,
    };
}

// ── R2: resolution + 206 / 416 response staging (RFC 7233 §4) ────────────────

const Server = @import("Server.zig");

/// A byte-range-spec resolved against a representation of known length: a
/// concrete, satisfiable, inclusive interval `[start, end]` with `end < total`.
/// This is what a 206 actually serves; its `Content-Range` names it on the wire.
pub const ResolvedRange = struct {
    /// First byte offset served (0-based).
    start: u64,
    /// Last byte offset served, inclusive.
    end: u64,
    /// Total length of the selected representation (the `/total` in
    /// `Content-Range`, and what a `-suffix` / open-ended spec resolves against).
    total: u64,

    /// Number of bytes in `[start, end]` (always ≥ 1 for a satisfiable range).
    pub fn len(self: ResolvedRange) u64 {
        return self.end - self.start + 1;
    }

    /// Write the `Content-Range` header VALUE for a satisfiable range —
    /// `bytes start-end/total` (RFC 7233 §4.2), without the header name.
    pub fn writeContentRange(self: ResolvedRange, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("bytes {d}-{d}/{d}", .{ self.start, self.end, self.total });
    }

    /// `writeContentRange` into `buf`; returns the written slice or
    /// `error.BufferTooSmall`. A 72-byte buffer always suffices (3×u64 + fixed).
    pub fn bufPrintContentRange(self: ResolvedRange, buf: []u8) error{BufferTooSmall}![]const u8 {
        var fw = std.Io.Writer.fixed(buf);
        self.writeContentRange(&fw) catch return error.BufferTooSmall;
        return fw.buffered();
    }
};

/// Resolve one `ByteRangeSpec` against a representation of length `total`.
/// Returns null when the spec is **unsatisfiable** against this length — which,
/// per RFC 7233 §2.1, is:
///   - `range`/`from`: `first >= total` (starts at or past the end); a `range`
///     whose `last` runs past the end is NOT unsatisfiable, it clamps to
///     `total-1`.
///   - `suffix`: a suffix of 0 (selects zero bytes → treated as unsatisfiable,
///     RFC 7233 §4.4 allows the 416).
///   - any spec when `total == 0` (an empty representation satisfies no range).
/// The caller drops unsatisfiable specs; if every spec in the set is
/// unsatisfiable it responds 416.
pub fn resolveSpec(spec: ByteRangeSpec, total: u64) ?ResolvedRange {
    if (total == 0) return null;
    switch (spec) {
        .range => |r| {
            if (r.first >= total) return null;
            const end = if (r.last >= total) total - 1 else r.last;
            return .{ .start = r.first, .end = end, .total = total };
        },
        .from => |first| {
            if (first >= total) return null;
            return .{ .start = first, .end = total - 1, .total = total };
        },
        .suffix => |n| {
            if (n == 0) return null;
            const count = if (n >= total) total else n;
            return .{ .start = total - count, .end = total - 1, .total = total };
        },
    }
}

/// Resolve a whole byte-range-set against `total`, writing the satisfiable
/// ranges into `out` (in request order) and returning that prefix. Unsatisfiable
/// specs are dropped. An **empty** result means the entire set is unsatisfiable
/// → the caller sends 416. Ranges beyond `out.len` are dropped (bound the set
/// with `parse`'s buffer upstream so this cannot silently truncate a wanted
/// range). Overlapping/unsorted ranges are returned as-is — coalescing is the
/// caller's choice (RFC 7233 §6.1 permits, but does not require, it).
pub fn resolve(specs: []const ByteRangeSpec, total: u64, out: []ResolvedRange) []ResolvedRange {
    var n: usize = 0;
    for (specs) |spec| {
        if (n == out.len) break;
        if (resolveSpec(spec, total)) |rr| {
            out[n] = rr;
            n += 1;
        }
    }
    return out[0..n];
}

/// What `apply` decided, so the caller knows how to produce the body.
pub const Outcome = enum {
    /// No usable `Range` header (absent, malformed → ignored, or not `bytes`).
    /// Nothing was staged; serve the whole representation as a normal 200.
    no_range,
    /// The set was valid but no range is satisfiable. `apply` staged **416**
    /// + `Content-Range: bytes */total`; write no body (or a short error one).
    not_satisfiable,
    /// Exactly one satisfiable range. `apply` staged **206** + `Content-Range:
    /// bytes s-e/total`; `out[0]` holds it — write those bytes.
    single,
    /// More than one satisfiable range. `apply` staged **206** only; `out[0..n]`
    /// holds them. The caller emits a `multipart/byteranges` body (R3) and sets
    /// its own `Content-Type` + per-part `Content-Range`.
    multiple,
};

/// The result of `apply`: the `Outcome` plus the satisfiable ranges (valid for
/// `.single` — one — and `.multiple` — the set).
pub const Applied = struct {
    outcome: Outcome,
    ranges: []const ResolvedRange,
};

// Stable backing for the computed `Content-Range` value: `setHeader` stores the
// slice WITHOUT copying, so a computed header needs memory that outlives the
// call. Per-thread, overwritten on the next `apply` on this thread (one request
// is handled to completion per thread, as in `requestid`).
threadlocal var content_range_buf: [72]u8 = undefined;

/// Read the request's `Range` header, resolve it against `total`, and stage the
/// 206 / 416 response line + headers — the one-call server integration.
///
/// Returns an `Applied`: on `.single` / `.not_satisfiable` the status and
/// `Content-Range` header are already set (plus `Accept-Ranges: bytes`), so the
/// caller only writes the body; on `.multiple` the status is 206 and the ranges
/// are handed back for an R3 `multipart/byteranges` body; on `.no_range`
/// nothing is staged. `out` receives the satisfiable ranges (bound it; extra
/// ranges are dropped — see `resolve`). Only `GET`/`HEAD` are range-eligible
/// (RFC 7233 §3.1); any other method yields `.no_range`.
pub fn apply(
    req: *const Server.Request,
    rw: *Server.ResponseWriter,
    total: u64,
    out: []ResolvedRange,
) Server.ResponseWriter.SetHeaderError!Applied {
    if (req.method != .get and req.method != .head) return .{ .outcome = .no_range, .ranges = &.{} };
    const raw = req.header("range") orelse return .{ .outcome = .no_range, .ranges = &.{} };

    var specbuf: [default_max_ranges]ByteRangeSpec = undefined;
    const specs = parse(raw, &specbuf) catch return .{ .outcome = .no_range, .ranges = &.{} };

    const ranges = resolve(specs, total, out);
    if (ranges.len == 0) {
        // Every range unsatisfiable → 416 with the unsatisfied-range Content-Range.
        rw.setStatus(416);
        try rw.setHeader("Accept-Ranges", "bytes");
        var fw = std.Io.Writer.fixed(&content_range_buf);
        fw.print("bytes */{d}", .{total}) catch unreachable; // 72 bytes >> "bytes */" + 20
        try rw.setHeader("Content-Range", fw.buffered());
        return .{ .outcome = .not_satisfiable, .ranges = ranges };
    }

    rw.setStatus(206);
    try rw.setHeader("Accept-Ranges", "bytes");
    if (ranges.len == 1) {
        const cr = ranges[0].bufPrintContentRange(&content_range_buf) catch unreachable;
        try rw.setHeader("Content-Range", cr);
        return .{ .outcome = .single, .ranges = ranges };
    }
    return .{ .outcome = .multiple, .ranges = ranges };
}

const testing = std.testing;

test "single absolute range" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=0-499", &buf);
    try testing.expectEqual(@as(usize, 1), specs.len);
    try testing.expect(specs[0] == .range);
    try testing.expectEqual(@as(u64, 0), specs[0].range.first);
    try testing.expectEqual(@as(u64, 499), specs[0].range.last);
}

test "open-ended range" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=9500-", &buf);
    try testing.expectEqual(@as(usize, 1), specs.len);
    try testing.expect(specs[0] == .from);
    try testing.expectEqual(@as(u64, 9500), specs[0].from);
    try testing.expect(!specs[0].isSuffix());
}

test "suffix range" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=-500", &buf);
    try testing.expectEqual(@as(usize, 1), specs.len);
    try testing.expect(specs[0] == .suffix);
    try testing.expectEqual(@as(u64, 500), specs[0].suffix);
    try testing.expect(specs[0].isSuffix());
}

test "suffix zero is well-formed" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=-0", &buf);
    try testing.expectEqual(@as(usize, 1), specs.len);
    try testing.expect(specs[0] == .suffix);
    try testing.expectEqual(@as(u64, 0), specs[0].suffix);
}

test "multiple ranges with OWS variations" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("  bytes = 0-499, 500-999 ,\t-100  ", &buf);
    try testing.expectEqual(@as(usize, 3), specs.len);
    try testing.expect(specs[0] == .range);
    try testing.expectEqual(@as(u64, 0), specs[0].range.first);
    try testing.expectEqual(@as(u64, 499), specs[0].range.last);
    try testing.expect(specs[1] == .range);
    try testing.expectEqual(@as(u64, 500), specs[1].range.first);
    try testing.expectEqual(@as(u64, 999), specs[1].range.last);
    try testing.expect(specs[2] == .suffix);
    try testing.expectEqual(@as(u64, 100), specs[2].suffix);
}

test "list rule: stray commas are elided" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=0-0,,1-1", &buf);
    try testing.expectEqual(@as(usize, 2), specs.len);
    try testing.expect(specs[0] == .range);
    try testing.expectEqual(@as(u64, 0), specs[0].range.first);
    try testing.expectEqual(@as(u64, 0), specs[0].range.last);
    try testing.expect(specs[1] == .range);
    try testing.expectEqual(@as(u64, 1), specs[1].range.first);
    try testing.expectEqual(@as(u64, 1), specs[1].range.last);

    // Trailing / leading commas too.
    const specs2 = try parse("bytes=, 0-1 ,", &buf);
    try testing.expectEqual(@as(usize, 1), specs2.len);
}

test "unit is case-insensitive" {
    var buf: [4]ByteRangeSpec = undefined;
    const specs = try parse("BYTES=0-1", &buf);
    try testing.expectEqual(@as(usize, 1), specs.len);
}

test "bad unit and missing '=' are InvalidUnit" {
    var buf: [4]ByteRangeSpec = undefined;
    try testing.expectError(error.InvalidUnit, parse("items=0-1", &buf));
    try testing.expectError(error.InvalidUnit, parse("bytes 0-499", &buf));
    try testing.expectError(error.InvalidUnit, parse("", &buf));
    try testing.expectError(error.InvalidUnit, parse("=0-1", &buf));
}

test "inverted range is InvalidRange" {
    var buf: [4]ByteRangeSpec = undefined;
    try testing.expectError(error.InvalidRange, parse("bytes=500-499", &buf));
}

test "garbage sets are InvalidRange" {
    var buf: [4]ByteRangeSpec = undefined;
    const bad = [_][]const u8{
        "bytes=abc",
        "bytes=-",
        "bytes=1-2-3",
        "bytes=",
        "bytes=,,",
        "bytes=1a-2",
        "bytes=0-499, oops",
        "bytes=+1-2",
        "bytes=1_0-20",
    };
    for (bad) |raw| {
        try testing.expectError(error.InvalidRange, parse(raw, &buf));
    }
}

test "position overflow is Overflow" {
    var buf: [4]ByteRangeSpec = undefined;
    try testing.expectError(error.Overflow, parse("bytes=0-99999999999999999999999", &buf));
    try testing.expectError(error.Overflow, parse("bytes=-99999999999999999999999", &buf));
    // Max u64 still fits.
    const specs = try parse("bytes=0-18446744073709551615", &buf);
    try testing.expectEqual(@as(u64, 18446744073709551615), specs[0].range.last);
}

test "TooManyRanges via a small out buffer" {
    var buf: [2]ByteRangeSpec = undefined;
    try testing.expectError(error.TooManyRanges, parse("bytes=0-0,1-1,2-2", &buf));
    // Exactly filling the buffer is fine.
    const specs = try parse("bytes=0-0,1-1", &buf);
    try testing.expectEqual(@as(usize, 2), specs.len);
}

test "iterator streams specs and terminates" {
    var it = try iterator("bytes=0-1, -2, 3-");
    const a = (try it.next()).?;
    try testing.expect(a == .range);
    const b = (try it.next()).?;
    try testing.expect(b == .suffix);
    const c = (try it.next()).?;
    try testing.expect(c == .from);
    try testing.expectEqual(@as(?ByteRangeSpec, null), try it.next());
    try testing.expectEqual(@as(?ByteRangeSpec, null), try it.next());
}

test "parseSpec direct shapes" {
    try testing.expectEqual(ByteRangeSpec{ .from = 7 }, try parseSpec("7-"));
    try testing.expectEqual(ByteRangeSpec{ .suffix = 9 }, try parseSpec("-9"));
    const r = try parseSpec("5-5");
    try testing.expect(r == .range);
    try testing.expectEqual(@as(u64, 5), r.range.first);
    try testing.expectEqual(@as(u64, 5), r.range.last);
    try testing.expectError(error.InvalidRange, parseSpec("5"));
}

// ── R2 tests ─────────────────────────────────────────────────────────────────

test "resolveSpec: absolute range within, clamped, and past end" {
    // within
    try testing.expectEqual(
        ResolvedRange{ .start = 0, .end = 499, .total = 10000 },
        resolveSpec(.{ .range = .{ .first = 0, .last = 499 } }, 10000).?,
    );
    // last past end → clamp to total-1
    try testing.expectEqual(
        ResolvedRange{ .start = 9500, .end = 9999, .total = 10000 },
        resolveSpec(.{ .range = .{ .first = 9500, .last = 100000 } }, 10000).?,
    );
    // first at/after end → unsatisfiable
    try testing.expect(resolveSpec(.{ .range = .{ .first = 10000, .last = 10001 } }, 10000) == null);
}

test "resolveSpec: open-ended and suffix" {
    try testing.expectEqual(
        ResolvedRange{ .start = 9500, .end = 9999, .total = 10000 },
        resolveSpec(.{ .from = 9500 }, 10000).?,
    );
    // suffix within
    try testing.expectEqual(
        ResolvedRange{ .start = 9500, .end = 9999, .total = 10000 },
        resolveSpec(.{ .suffix = 500 }, 10000).?,
    );
    // suffix larger than total → whole representation
    try testing.expectEqual(
        ResolvedRange{ .start = 0, .end = 9999, .total = 10000 },
        resolveSpec(.{ .suffix = 100000 }, 10000).?,
    );
    // suffix 0 → unsatisfiable
    try testing.expect(resolveSpec(.{ .suffix = 0 }, 10000) == null);
    // open-ended past end → unsatisfiable
    try testing.expect(resolveSpec(.{ .from = 10000 }, 10000) == null);
}

test "resolveSpec: empty representation satisfies nothing" {
    try testing.expect(resolveSpec(.{ .range = .{ .first = 0, .last = 0 } }, 0) == null);
    try testing.expect(resolveSpec(.{ .from = 0 }, 0) == null);
    try testing.expect(resolveSpec(.{ .suffix = 5 }, 0) == null);
}

test "resolve: drops unsatisfiable, keeps request order" {
    var specbuf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=0-99, 100000-200000, -50", &specbuf);
    var out: [4]ResolvedRange = undefined;
    const got = resolve(specs, 1000, &out);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqual(ResolvedRange{ .start = 0, .end = 99, .total = 1000 }, got[0]);
    try testing.expectEqual(ResolvedRange{ .start = 950, .end = 999, .total = 1000 }, got[1]);
}

test "resolve: all unsatisfiable → empty (caller sends 416)" {
    var specbuf: [4]ByteRangeSpec = undefined;
    const specs = try parse("bytes=5000-, -0", &specbuf);
    var out: [4]ResolvedRange = undefined;
    try testing.expectEqual(@as(usize, 0), resolve(specs, 1000, &out).len);
}

test "ResolvedRange: len and Content-Range formatting" {
    const rr = ResolvedRange{ .start = 0, .end = 499, .total = 1234 };
    try testing.expectEqual(@as(u64, 500), rr.len());
    var buf: [72]u8 = undefined;
    try testing.expectEqualStrings("bytes 0-499/1234", try rr.bufPrintContentRange(&buf));
}

// Golden apply harness — a range-serving handler over a canned wire request.
const golden_body = "0123456789"; // len 10

fn rangeHandler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    var out: [4]ResolvedRange = undefined;
    const applied = try apply(req, rw, golden_body.len, &out);
    switch (applied.outcome) {
        .no_range => {
            rw.setStatus(200);
            try rw.writeAll(golden_body);
        },
        .not_satisfiable => try rw.writeAll(""),
        .single => {
            const r = applied.ranges[0];
            try rw.writeAll(golden_body[r.start .. r.end + 1]);
        },
        .multiple => try rw.writeAll("MULTI"), // R3 owns the real multipart body
    }
}

fn runRangeStream(wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [64]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    Server.serveStream(.{
        .handler = rangeHandler,
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "apply: golden 206 single range — Content-Range + sliced body" {
    var out_buf: [4096]u8 = undefined;
    const got = runRangeStream("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "Range: bytes=2-5\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 206 Partial Content\r\n" ++
        "Accept-Ranges: bytes\r\n" ++
        "Content-Range: bytes 2-5/10\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "2345", got);
}

test "apply: golden 206 suffix range" {
    var out_buf: [4096]u8 = undefined;
    const got = runRangeStream("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "Range: bytes=-3\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 206 Partial Content\r\n" ++
        "Accept-Ranges: bytes\r\n" ++
        "Content-Range: bytes 7-9/10\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 3\r\n" ++
        "\r\n" ++
        "789", got);
}

test "apply: golden 416 on unsatisfiable range" {
    var out_buf: [4096]u8 = undefined;
    const got = runRangeStream("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "Range: bytes=50-60\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 416 Range Not Satisfiable\r\n" ++
        "Accept-Ranges: bytes\r\n" ++
        "Content-Range: bytes */10\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n", got);
}

test "apply: golden no Range → 200 whole body" {
    var out_buf: [4096]u8 = undefined;
    const got = runRangeStream("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "0123456789", got);
}

test "apply: malformed Range ignored → 200 whole body" {
    var out_buf: [4096]u8 = undefined;
    const got = runRangeStream("GET / HTTP/1.1\r\nHost: t\r\n" ++
        "Range: bytes=abc\r\nConnection: close\r\n\r\n", &out_buf);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Server: test\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "0123456789", got);
}
