// SPDX-License-Identifier: MIT
//! Opt-in cost measurement for the UTF-8 sanitization added to
//! `writeJsonString`: every request served pays this, so "negligible" is not
//! an acceptable answer — a number is.
//!
//! Off by default (`error.SkipZigTest`); run it with:
//!
//!   ACCESSLOG_BENCH=1 scripts/capped zig build test-accesslog -Doptimize=ReleaseFast
//!
//! **The A side is the real code** (`root.writeJsonLines`). The B side,
//! `writeJsonLinesVerbatim` below, is the pre-change implementation kept
//! verbatim as the baseline — the same record writer with the old escaper,
//! which passed every byte >= 0x20 through one `writeByte` at a time and never
//! looked at UTF-8. Comparing against a frozen copy is the only way to measure
//! a change that has already landed, and it is honest as long as the copy is
//! the code that was actually replaced; it is, byte for byte, from
//! `root.zig`'s pre-2026-08-11 revision.
//!
//! Three field shapes, because only one of them is the hot path:
//!   * **ASCII** — a realistic record (`GET /status?x=1`, `curl/8.0`). This is
//!     what a production access log is made of and what the cost has to be
//!     small on.
//!   * **valid UTF-8** — the same record with multi-byte characters, so the
//!     scan's non-ASCII branch is exercised while nothing is replaced.
//!   * **ill-formed** — a record whose fields are mostly bad bytes, i.e. the
//!     path that actually copies work in. The point of "pay only when it is
//!     not clean" is that this row is the expensive one and the first is not.
//!
//! **Sizing.** 200 000 records through one reused 4 KiB fixed buffer: no
//! allocation, nothing retained, ~40 MB of writer traffic total. An over-eager
//! in-memory benchmark has OOM-killed this host before; there is nothing to
//! accumulate here and there must not be.

const std = @import("std");
const root = @import("root.zig");

const Entry = root.Entry;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

// ── the baseline: `root.zig`'s escaper before UTF-8 sanitization ─────────

fn writeJsonStringVerbatim(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0x08 => try w.writeAll("\\b"),
        0x09 => try w.writeAll("\\t"),
        0x0A => try w.writeAll("\\n"),
        0x0C => try w.writeAll("\\f"),
        0x0D => try w.writeAll("\\r"),
        0x00...0x07, 0x0B, 0x0E...0x1F => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

fn writeJsonOptStringVerbatim(w: *std.Io.Writer, s: ?[]const u8) std.Io.Writer.Error!void {
    if (s) |v| try writeJsonStringVerbatim(w, v) else try w.writeAll("null");
}

fn writeJsonOptU64(w: *std.Io.Writer, v: ?u64) std.Io.Writer.Error!void {
    if (v) |x| try w.print("{d}", .{x}) else try w.writeAll("null");
}

fn writeJsonLinesVerbatim(entry: Entry, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("{{\"ts\":{d},\"remote_addr\":", .{entry.timestamp_ns});
    try writeJsonOptStringVerbatim(w, entry.remote_addr);
    try w.writeAll(",\"method\":");
    try writeJsonStringVerbatim(w, entry.method);
    try w.writeAll(",\"target\":");
    try writeJsonStringVerbatim(w, entry.target);
    try w.writeAll(",\"protocol\":");
    try writeJsonStringVerbatim(w, entry.protocol);
    try w.print(",\"status\":{d},\"request_bytes\":", .{entry.status});
    try writeJsonOptU64(w, entry.request_bytes);
    try w.writeAll(",\"response_bytes\":");
    try writeJsonOptU64(w, entry.response_bytes);
    try w.writeAll(",\"latency_ns\":");
    try writeJsonOptU64(w, entry.latency_ns);
    try w.writeAll(",\"user_agent\":");
    try writeJsonOptStringVerbatim(w, entry.user_agent);
    try w.writeAll(",\"referer\":");
    try writeJsonOptStringVerbatim(w, entry.referer);
    try w.writeAll(",\"request_id\":");
    try writeJsonOptStringVerbatim(w, entry.request_id);
    try w.writeAll("}\n");
}

// ── the three records ────────────────────────────────────────────────────

const Shape = struct {
    name: []const u8,
    entry: Entry,
};

fn baseEntry() Entry {
    return .{
        .timestamp_ns = 1734000000000000000,
        .remote_addr = "192.0.2.1:54321",
        .method = "GET",
        .target = "/status?x=1",
        .protocol = "HTTP/1.1",
        .status = 200,
        .request_bytes = 0,
        .response_bytes = 512,
        .latency_ns = 1500000,
        .user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        .referer = "https://example.org/some/path?a=1&b=2",
        .request_id = "req-abc-123",
    };
}

fn shapes() [3]Shape {
    const ascii = baseEntry();

    var utf8 = baseEntry();
    utf8.target = "/caf\u{e9}/\u{4f60}\u{597d}?q=\u{1f600}";
    utf8.user_agent = "Mozilla/5.0 (X11; Linux x86_64) \u{2014} \u{4e2d}\u{6587}\u{7248}";
    utf8.referer = "https://example.org/\u{20ac}/\u{1f4a9}";

    var bad = baseEntry();
    bad.target = "/\xff\xfe\xed\xa0\x80/\xc0\xaf?q=\xe2\x82";
    bad.user_agent = "curl\xff/8.0 \x80\x80\x80 \xf0\x9f\x98";
    bad.referer = "https://example.org/\xed\xbf\xbf\xf4\x90\x80\x80";

    return .{
        .{ .name = "ASCII (the hot path)", .entry = ascii },
        .{ .name = "valid UTF-8", .entry = utf8 },
        .{ .name = "ill-formed UTF-8", .entry = bad },
    };
}

const iters: usize = 200_000;

/// Alternating rounds, minimum taken per side. Running A then B once each
/// measures the order as much as the code — the first pass pays the cold
/// caches and any frequency ramp, which on this host was worth tens of
/// percent, i.e. more than the effect under test.
const rounds: usize = 5;

fn timeWriter(
    comptime writeFn: fn (Entry, *std.Io.Writer) std.Io.Writer.Error!void,
    entry: Entry,
    buf: []u8,
) !u64 {
    const t0 = nowNs();
    for (0..iters) |_| {
        var w: std.Io.Writer = .fixed(buf);
        try writeFn(entry, &w);
        std.mem.doNotOptimizeAway(w.buffered().len);
    }
    return nowNs() - t0;
}

fn nsPerRecord(dt: u64) f64 {
    return @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters));
}

test "bench (opt-in via ACCESSLOG_BENCH): UTF-8 sanitization cost per record" {
    if (std.testing.environ.getPosix("ACCESSLOG_BENCH") == null) return error.SkipZigTest;

    var buf: [4096]u8 = undefined;
    std.debug.print(
        "\naccesslog writeJsonLines — {d} records x {d} rounds (min), one reused " ++
            "4 KiB buffer, {s}\n{s:<22} {s:>8} {s:>12} {s:>12} {s:>9}\n",
        .{
            iters,                             rounds,
            @tagName(@import("builtin").mode), "field shape",
            "out B",                           "verbatim ns",
            "sanitize ns",                     "delta",
        },
    );

    for (shapes()) |s| {
        var w: std.Io.Writer = .fixed(&buf);
        try root.writeJsonLines(s.entry, &w);
        const out_bytes = w.buffered().len;

        var before: u64 = std.math.maxInt(u64);
        var after: u64 = std.math.maxInt(u64);
        for (0..rounds) |_| {
            before = @min(before, try timeWriter(writeJsonLinesVerbatim, s.entry, &buf));
            after = @min(after, try timeWriter(root.writeJsonLines, s.entry, &buf));
        }
        const b = nsPerRecord(before);
        const a = nsPerRecord(after);
        std.debug.print("{s:<22} {d:>8} {d:>12.1} {d:>12.1} {d:>8.1}%\n", .{
            s.name, out_bytes, b, a, (a - b) / b * 100.0,
        });
    }
    std.debug.print(
        "(the sanitizing side also batches its pass-through runs into one " ++
            "writeAll where the old one wrote byte by byte, so a NEGATIVE delta " ++
            "on a clean row is that, not noise)\n",
        .{},
    );
}
