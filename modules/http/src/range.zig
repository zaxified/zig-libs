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
