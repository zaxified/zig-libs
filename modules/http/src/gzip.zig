// SPDX-License-Identifier: MIT

//! gzip — negotiated response compression for `http.Server` (Phase 2.2,
//! ../SPEC.md). Modeled after the Go net/http gzip-handler /
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

/// `c.* = try flate.Compress.init(output, buffer, container, opts)`, built in
/// place.
///
/// `Compress` is ~225 KiB and `init` returns it by value inside an error
/// union. The assignment is then a stack temporary of that size in the
/// caller's frame -- 97 KiB of `ResponseWriter.beginGzip`'s frame even in
/// ReleaseFast, and in Debug (several copies) more than a 512 KiB fiber stack
/// holds: an HTTP/2 response reached it through the deeper h2 call chain and
/// segfaulted inside `Compress.init` (an embedder, 2026-09-25). Here each field is
/// set where it lives, and nothing the size of the deflate state is ever on
/// the stack.
///
/// A copy of std 0.16's `Compress.init`, kept honest two ways: the field list
/// is checked at compile time (a field std adds is a compile error here, not a
/// field left undefined), and a test compares the result with std's `init`
/// field by field. The one value std keeps private -- the writer's vtable --
/// is taken from a `Compress.init` evaluated at compile time.
pub fn initCompress(
    c: *flate.Compress,
    output: *std.Io.Writer,
    buffer: []u8,
    container: flate.Container,
    opts: flate.Compress.Options,
) std.Io.Writer.Error!void {
    comptime {
        const expected = [_][]const u8{
            "writer", "history_len", "history_end_unhashed", "bit_writer", "buffered_tokens",
            "lookup", "container",   "hasher",               "opts",
        };
        const fields = std.meta.fields(flate.Compress);
        if (fields.len != expected.len) @compileError("gzip.initCompress: std's flate.Compress changed its fields; update the copy");
        for (fields, expected) |f, e| if (!std.mem.eql(u8, f.name, e))
            @compileError("gzip.initCompress: std's flate.Compress field '" ++ f.name ++ "' is new or moved; update the copy");
    }
    std.debug.assert(output.buffer.len > 8);
    std.debug.assert(buffer.len >= flate.max_window_len);
    try output.writeAll(container.header());
    c.writer = .{ .buffer = buffer, .vtable = compress_vtable };
    c.history_len = 0;
    c.history_end_unhashed = false;
    c.bit_writer = .init(output);
    c.buffered_tokens.pos = 0;
    c.buffered_tokens.n = 0;
    c.buffered_tokens.lit_freqs = @splat(0);
    c.buffered_tokens.dist_freqs = @splat(0);
    c.lookup.head = @splat(.{ .value = std.math.maxInt(u15), .is_null = true });
    c.lookup.chain_pos = std.math.maxInt(u15);
    c.container = container;
    c.opts = opts;
    c.hasher = .init(container);
}

/// `flate.Compress`'s writer vtable -- private in std, so read off a
/// `Compress.init` run at compile time over a fixed buffer.
const compress_vtable: *const std.Io.Writer.VTable = blk: {
    @setEvalBranchQuota(1 << 20);
    var out_buf: [16]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var window: [flate.max_window_len]u8 = undefined;
    const c = flate.Compress.init(&out, &window, .gzip, .default) catch unreachable;
    break :blk c.writer.vtable;
};

/// Handler-facing buffer for the decompressed request-body reader (the cap
/// wrapper's `std.Io.Reader` buffer). Small — the decoder streams straight
/// through, this only backs buffered reads (peek/take) the handler may do.
pub const decode_out_len = 4096;

/// Working memory for the inbound gzip request-body decoder (Task 1): the
/// `std.compress.flate` decoder plus its 64 KiB history window (~64 KiB
/// total). The serving loop allocates one per connection while request
/// decoding is enabled; the loop re-initializes `decompress` per request,
/// so the owner only provides the memory (no init/deinit).
pub const DecodeScratch = struct {
    decompress: flate.Decompress = undefined,
    window: [flate.max_window_len]u8 = undefined,
    out: [decode_out_len]u8 = undefined,
};

/// A request's `Content-Encoding` classified for the inbound-decode path.
pub const RequestEncoding = enum {
    /// Absent, empty, or `identity` — the body is already plaintext.
    identity,
    /// A single `gzip` (or its `x-gzip` alias) coding — decodable.
    gzip,
    /// Anything we do not decode (deflate, br, a multi-coding list, …) →
    /// the server answers 415 rather than hand the handler opaque bytes.
    unsupported,
};

/// Classify a request `Content-Encoding` header for transparent inbound
/// decoding. Only a single `gzip`/`x-gzip` coding is decodable here; a
/// coding list (`gzip, br`) is treated as unsupported (we do not unwrap
/// stacked codings). Absent/empty/`identity` means the body is plaintext.
pub fn requestContentEncoding(content_encoding: ?[]const u8) RequestEncoding {
    const raw = content_encoding orelse return .identity;
    const value = std.mem.trim(u8, raw, " \t");
    if (value.len == 0) return .identity;
    if (std.mem.indexOfScalar(u8, value, ',') != null) return .unsupported;
    if (std.ascii.eqlIgnoreCase(value, "identity")) return .identity;
    if (std.ascii.eqlIgnoreCase(value, "gzip") or std.ascii.eqlIgnoreCase(value, "x-gzip"))
        return .gzip;
    return .unsupported;
}

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

test "requestContentEncoding: classification" {
    try testing.expectEqual(RequestEncoding.identity, requestContentEncoding(null));
    try testing.expectEqual(RequestEncoding.identity, requestContentEncoding(""));
    try testing.expectEqual(RequestEncoding.identity, requestContentEncoding("  "));
    try testing.expectEqual(RequestEncoding.identity, requestContentEncoding("identity"));
    try testing.expectEqual(RequestEncoding.identity, requestContentEncoding("Identity"));

    try testing.expectEqual(RequestEncoding.gzip, requestContentEncoding("gzip"));
    try testing.expectEqual(RequestEncoding.gzip, requestContentEncoding("GZIP"));
    try testing.expectEqual(RequestEncoding.gzip, requestContentEncoding(" gzip "));
    try testing.expectEqual(RequestEncoding.gzip, requestContentEncoding("x-gzip"));

    try testing.expectEqual(RequestEncoding.unsupported, requestContentEncoding("deflate"));
    try testing.expectEqual(RequestEncoding.unsupported, requestContentEncoding("br"));
    try testing.expectEqual(RequestEncoding.unsupported, requestContentEncoding("gzip, br")); // list not unwrapped
    try testing.expectEqual(RequestEncoding.unsupported, requestContentEncoding("gzip, gzip"));
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
    try initCompress(&scratch.compress, &aw.writer, &scratch.window, .gzip, levelOptions(6));
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

test "initCompress: the same state as std's Compress.init, field by field" {
    const gpa = testing.allocator;
    inline for (.{ flate.Container.gzip, flate.Container.zlib, flate.Container.raw }) |container| {
        const a = try gpa.create(Scratch);
        defer gpa.destroy(a);
        const b = try gpa.create(Scratch);
        defer gpa.destroy(b);
        var out_a: std.Io.Writer.Allocating = try .initCapacity(gpa, 64);
        defer out_a.deinit();
        var out_b: std.Io.Writer.Allocating = try .initCapacity(gpa, 64);
        defer out_b.deinit();

        // Both over garbage, so a field the copy forgets shows up as a difference.
        @memset(std.mem.asBytes(&a.compress), 0xa5);
        @memset(std.mem.asBytes(&b.compress), 0x5a);
        a.compress = try flate.Compress.init(&out_a.writer, &a.window, container, levelOptions(4));
        try initCompress(&b.compress, &out_b.writer, &b.window, container, levelOptions(4));

        try testing.expectEqualSlices(u8, out_a.written(), out_b.written());
        const x = &a.compress;
        const y = &b.compress;
        try testing.expectEqual(x.writer.vtable, y.writer.vtable);
        try testing.expectEqual(@intFromPtr(&a.window), @intFromPtr(x.writer.buffer.ptr));
        try testing.expectEqual(@intFromPtr(&b.window), @intFromPtr(y.writer.buffer.ptr));
        try testing.expectEqual(x.writer.buffer.len, y.writer.buffer.len);
        try testing.expectEqual(x.writer.end, y.writer.end);
        try testing.expectEqual(x.history_len, y.history_len);
        try testing.expectEqual(x.history_end_unhashed, y.history_end_unhashed);
        try testing.expectEqual(&out_a.writer, x.bit_writer.output);
        try testing.expectEqual(&out_b.writer, y.bit_writer.output);
        try testing.expectEqual(x.bit_writer.buffered, y.bit_writer.buffered);
        try testing.expectEqual(x.bit_writer.buffered_n, y.bit_writer.buffered_n);
        try testing.expectEqual(x.buffered_tokens.pos, y.buffered_tokens.pos);
        try testing.expectEqual(x.buffered_tokens.n, y.buffered_tokens.n);
        try testing.expectEqualSlices(u16, &x.buffered_tokens.lit_freqs, &y.buffered_tokens.lit_freqs);
        try testing.expectEqualSlices(u16, &x.buffered_tokens.dist_freqs, &y.buffered_tokens.dist_freqs);
        try testing.expectEqualSlices(u8, std.mem.asBytes(&x.lookup.head), std.mem.asBytes(&y.lookup.head));
        try testing.expectEqual(x.lookup.chain_pos, y.lookup.chain_pos);
        try testing.expectEqual(x.container, y.container);
        try testing.expectEqual(x.opts, y.opts);
        try testing.expect(std.meta.eql(x.hasher, y.hasher));

        // And the same bytes out for the same input.
        const plain = ("{\"key\":\"value\"," ** 300) ++ "\"end\":true}";
        try x.writer.writeAll(plain);
        try x.finish();
        try y.writer.writeAll(plain);
        try y.finish();
        try testing.expectEqualSlices(u8, out_a.written(), out_b.written());
    }
}
