//! gzip — negotiated response compression for `http.Server` (Phase 2.2,
//! SPEC-http-gzip.md). Modeled after the Go net/http gzip-handler /
//! nginx `gzip` semantics: compress only when the request's
//! `Accept-Encoding` admits gzip (a `q=0` is a refusal), only for
//! content-types on a configurable allowlist, and only for bodies worth
//! compressing (`min_size`).
//!
//! This file owns the pure, offline-testable pieces — negotiation,
//! eligibility and configuration; the wire-side integration (routing the
//! response body through `std.compress.flate` into the chunked framing)
//! lives in `Server.zig`'s `ResponseWriter`.

const std = @import("std");
const flate = std.compress.flate;

/// Configuration for negotiated gzip response compression
/// (`Server.Options.compression`; null there = off, `.{}` = these safe
/// defaults). Posture mirrors Go's gzip middleware / nginx `gzip`:
/// min 1 KiB, level 6 (zlib/Go default), textual/structured types only.
pub const Compression = struct {
    /// Plain-body size below which compression is skipped — gzip overhead
    /// loses on tiny bodies (nginx `gzip_min_length` shape). A body whose
    /// size is *unknown* when it starts streaming (no declared
    /// Content-Length, outgrew the response buffer) is compressed
    /// regardless, matching nginx for unknown-length responses.
    min_size: usize = 1024,
    /// flate compression level, 1 (fastest) … 9 (best); 6 = the zlib / Go
    /// `DefaultCompression` trade-off. Out-of-range values clamp to 1…9.
    level: u4 = 6,
    /// Compressible content-type allowlist; see `contentTypeCompressible`
    /// for the entry forms. A response without a Content-Type header is
    /// never compressed.
    content_types: []const []const u8 = &default_content_types,
};

/// Default compressible types: all of `text/*`, JSON/JavaScript/XML, and
/// any structured-syntax `+json` / `+xml` subtype (covers
/// `image/svg+xml`, `application/problem+json`, Atom/RSS, …).
pub const default_content_types = [_][]const u8{
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "+json",
    "+xml",
};

/// Working memory for the gzip encoder: the deflate state plus its 64 KiB
/// sliding window (~290 KiB total — the inherent cost of deflate, cf.
/// zlib's deflate_state). The serving loop allocates one per connection
/// while compression is enabled; the `ResponseWriter` re-initializes it
/// per response, so the owner only provides the memory (no init/deinit).
pub const Scratch = struct {
    compress: flate.Compress,
    window: [flate.max_window_len]u8,
};

/// Whether a request `Accept-Encoding` value admits gzip (RFC 9110
/// §12.5.3): an explicit `gzip` (or its `x-gzip` alias) entry wins over a
/// `*` wildcard; `q=0` on the winning entry is a refusal; an **absent
/// header compresses nothing** (the conservative middleware posture —
/// strictly RFC-absent means "anything goes", but Go's gzip handlers and
/// nginx only compress on an explicit opt-in, and so do we).
pub fn acceptsGzip(accept_encoding: ?[]const u8) bool {
    const value = accept_encoding orelse return false;
    var gzip_ok: ?bool = null;
    var star_ok: ?bool = null;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t");
        if (entry.len == 0) continue;
        const semi = std.mem.indexOfScalar(u8, entry, ';') orelse entry.len;
        const coding = std.mem.trimEnd(u8, entry[0..semi], " \t");
        const ok = qvalueAccepts(entry[semi..]);
        if (std.ascii.eqlIgnoreCase(coding, "gzip") or
            std.ascii.eqlIgnoreCase(coding, "x-gzip"))
        {
            gzip_ok = ok;
        } else if (std.mem.eql(u8, coding, "*")) {
            star_ok = ok;
        }
    }
    return gzip_ok orelse star_ok orelse false;
}

/// Parse the parameter tail of an Accept-Encoding entry (`";q=0.5"`): a
/// qvalue of zero in any decimal form ("0", "0.0", "0.000") refuses;
/// anything else — including no q parameter at all (default q=1) or a
/// malformed value — accepts (lenient, like Go's header parsing).
fn qvalueAccepts(params: []const u8) bool {
    var it = std.mem.splitScalar(u8, params, ';');
    while (it.next()) |raw| {
        const p = std.mem.trim(u8, raw, " \t");
        if (p.len < 2 or (p[0] != 'q' and p[0] != 'Q') or p[1] != '=') continue;
        const q = std.mem.trim(u8, p[2..], " \t");
        if (q.len == 0) return true;
        for (q) |c| {
            if (c != '0' and c != '.') return true; // any nonzero digit (or junk)
        }
        return false; // all zeros → q=0 → refused
    }
    return true;
}

/// Whether `content_type` is on the `allowlist`. The value is compared
/// with its parameters (`; charset=…`) stripped, case-insensitively.
/// Entry forms: exact match ("application/json"); a type prefix ending in
/// '/' ("text/" matches every text subtype); a structured-syntax suffix
/// starting with '+' ("+json" matches "application/problem+json").
pub fn contentTypeCompressible(content_type: []const u8, allowlist: []const []const u8) bool {
    const semi = std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len;
    const ct = std.mem.trim(u8, content_type[0..semi], " \t");
    for (allowlist) |entry| {
        if (entry.len == 0) continue;
        if (entry[0] == '+') {
            if (std.ascii.endsWithIgnoreCase(ct, entry)) return true;
        } else if (entry[entry.len - 1] == '/') {
            if (std.ascii.startsWithIgnoreCase(ct, entry)) return true;
        } else if (std.ascii.eqlIgnoreCase(ct, entry)) return true;
    }
    return false;
}

/// Map a 1…9 compression level to `std.compress.flate` parameters
/// (out-of-range clamps: 0 → 1, >9 → 9).
pub fn levelOptions(level: u4) flate.Compress.Options {
    return switch (level) {
        0, 1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        6 => .level_6,
        7 => .level_7,
        8 => .level_8,
        else => .level_9,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "acceptsGzip: negotiation table" {
    // Accepted.
    try testing.expect(acceptsGzip("gzip"));
    try testing.expect(acceptsGzip("GZIP")); // coding is case-insensitive
    try testing.expect(acceptsGzip("x-gzip")); // RFC 9110 alias
    try testing.expect(acceptsGzip("deflate, gzip;q=0.5"));
    try testing.expect(acceptsGzip("gzip ; q=0.001"));
    try testing.expect(acceptsGzip("gzip;q=1.0"));
    try testing.expect(acceptsGzip("*")); // wildcard admits gzip
    try testing.expect(acceptsGzip("deflate;q=0.9, *;q=0.5"));
    try testing.expect(acceptsGzip("*;q=0, gzip")); // explicit beats wildcard

    // Refused.
    try testing.expect(!acceptsGzip(null)); // absent header → no opt-in
    try testing.expect(!acceptsGzip(""));
    try testing.expect(!acceptsGzip("identity"));
    try testing.expect(!acceptsGzip("deflate, br"));
    try testing.expect(!acceptsGzip("gzip;q=0")); // explicit refusal
    try testing.expect(!acceptsGzip("gzip;q=0.000"));
    try testing.expect(!acceptsGzip("gzip; Q=0"));
    try testing.expect(!acceptsGzip("*;q=0"));
    try testing.expect(!acceptsGzip("*;q=1, gzip;q=0")); // explicit beats wildcard
}

test "contentTypeCompressible: default allowlist" {
    const list: []const []const u8 = &default_content_types;
    try testing.expect(contentTypeCompressible("text/html", list));
    try testing.expect(contentTypeCompressible("text/plain; charset=utf-8", list));
    try testing.expect(contentTypeCompressible("Application/JSON", list));
    try testing.expect(contentTypeCompressible("application/json; charset=utf-8", list));
    try testing.expect(contentTypeCompressible("application/javascript", list));
    try testing.expect(contentTypeCompressible("application/xml", list));
    try testing.expect(contentTypeCompressible("image/svg+xml", list)); // +xml suffix
    try testing.expect(contentTypeCompressible("application/problem+json", list));

    try testing.expect(!contentTypeCompressible("image/png", list));
    try testing.expect(!contentTypeCompressible("application/octet-stream", list));
    try testing.expect(!contentTypeCompressible("video/mp4", list));
    try testing.expect(!contentTypeCompressible("application/gzip", list));
    try testing.expect(!contentTypeCompressible("", list));
}

test "contentTypeCompressible: custom allowlist" {
    const only_csv: []const []const u8 = &.{"text/csv"};
    try testing.expect(contentTypeCompressible("text/csv", only_csv));
    try testing.expect(contentTypeCompressible("text/csv; header=present", only_csv));
    try testing.expect(!contentTypeCompressible("text/html", only_csv));
}

test "levelOptions: clamps into 1…9" {
    try testing.expectEqual(flate.Compress.Options.level_1, levelOptions(0));
    try testing.expectEqual(flate.Compress.Options.level_1, levelOptions(1));
    try testing.expectEqual(flate.Compress.Options.level_6, levelOptions(6));
    try testing.expectEqual(flate.Compress.Options.level_9, levelOptions(9));
    try testing.expectEqual(flate.Compress.Options.level_9, levelOptions(15));
}

test "gzip round-trip through a Scratch (compress, then flate decompress)" {
    const gpa = testing.allocator;
    const scratch = try gpa.create(Scratch);
    defer gpa.destroy(scratch);

    const plain = ("{\"key\":\"value\"," ** 100) ++ "\"end\":true}";

    var aw: std.Io.Writer.Allocating = try .initCapacity(gpa, 64);
    defer aw.deinit();
    scratch.compress = try flate.Compress.init(&aw.writer, &scratch.window, .gzip, levelOptions(6));
    try scratch.compress.writer.writeAll(plain);
    try scratch.compress.finish();
    const compressed = aw.written();
    try testing.expect(compressed.len < plain.len); // repetitive JSON shrinks

    var in: std.Io.Reader = .fixed(compressed);
    var dc: flate.Decompress = .init(&in, .gzip, &.{});
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    _ = try dc.reader.streamRemaining(&out.writer);
    try testing.expectEqualStrings(plain, out.written());
}
