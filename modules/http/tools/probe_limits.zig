// SPDX-License-Identifier: MIT
//
// WHAT THIS ASKS. Four questions about cost and bounds that a pass/fail test
// cannot put a number on:
//
//   1. Do the pure parsers survive arbitrary bytes? A sweep of 16 parsers over
//      structured random input — the point is "no panic", across all of them at
//      once, which is the property the per-parser fuzz harnesses check one at a
//      time.
//   2. What does `conneg.negotiate` cost as the Accept header grows, and does
//      that cost scale with the number of OFFERS? It used to re-parse the whole
//      header once per offer (G7).
//   3. How many response bytes can ONE Range header produce? The interesting
//      number is the multiple of the representation, not of the header.
//   4. Is the CHECKED-OUT set of `bufpool` bounded, as `Client.Options
//      .buffer_pool`'s doc says? `max_idle_slabs` bounds the IDLE list; this
//      measures what happens under 2000 concurrent checkouts.
//
// WHY THIS IS A PROBE AND NOT A UNIT TEST. Every answer here is a measurement,
// and a threshold pinned in a test would be a benchmark pinned to one machine —
// `feedback_rig_is_for_comparisons`. It prints numbers for a human to compare;
// it asserts nothing about them.
//
// WHAT IT NEEDS. Nothing but this module. No network, no threads, no peer.
//
//     zig build-exe -OReleaseSafe --dep http -Mroot=probe_limits.zig \
//       --dep netaddr --dep datefmt -Mhttp=../src/root.zig \
//       -Mnetaddr=../../netaddr/src/root.zig -Mdatefmt=../../datefmt/src/root.zig
//
// ⚠ Run it in a RELEASE mode. In Debug the sweep's numbers say nothing about
// shipped code, and the whole point of items 2–4 is the shape of the curve.
//
// ⚠ This file used to take `gzip` as its own module, because `gzip` was not
// re-exported at the module root — that was the finding. It is re-exported
// since 2026-09-04 (pinned by a test in `root.zig`), and passing `gzip.zig` as a
// separate module now fails to build outright: one file cannot belong to two
// modules. Reaching it through `http` is both correct and the thing the fix was
// for.
const std = @import("std");
const http = @import("http");
const gzip = http.gzip;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

var sink: u64 = 0;

fn sweep(iters: usize, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    // A pool of STRUCTURAL bytes, so the random inputs actually reach parse
    // branches instead of bouncing off the first character.
    const alphabet = "bytes=0-9,-;q\"WGMTSunNov *\r\n\t/+_.abcABC\x00\xff";
    var buf: [512]u8 = undefined;
    var mr: [32]http.conneg.MediaRange = undefined;
    var rr: [32]http.range.ByteRangeSpec = undefined;
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const n = rnd.uintLessThan(usize, buf.len);
        for (buf[0..n]) |*b| b.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
        const s = buf[0..n];

        if (http.range.parse(s, &rr)) |got| sink +%= got.len else |_| {}
        var rit = http.range.iterator(s) catch http.range.Iterator{ .rest = s };
        while (rit.next() catch null) |sp| sink +%= @intFromBool(sp.isSuffix());

        sink +%= http.conneg.parse(s, &mr).len;
        if (http.conneg.parseQvalue(s)) |q| sink +%= q;
        if (http.conneg.negotiate(s, &.{ "text/html", "application/json", "*/*", "a/b" })) |g| sink +%= g.weight;
        if (http.conneg.negotiateLanguage(s, &.{ "en-US", "cs", "de" })) |g| sink +%= g.weight;
        if (http.conneg.negotiateEncoding(s, &.{ "gzip", "br" })) |g| sink +%= g.weight;

        if (http.conditional.parseHttpDate(s)) |d| sink +%= @bitCast(d);
        if (http.conditional.ETag.parse(s)) |e| sink +%= e.value.len;

        if (http.body.ContentType.parse(s)) |ct| {
            sink +%= ct.media_type.len;
            if (ct.param("boundary")) |b| sink +%= b.len;
        }
        sink +%= @intFromBool(gzip.acceptsGzip(s));
        sink +%= @intFromBool(gzip.contentTypeCompressible(s, &gzip.default_content_types));
        sink +%= @intFromEnum(gzip.requestContentEncoding(s));

        // multipart with an ATTACKER-CHOSEN boundary drawn from the same bytes
        const bl = rnd.uintLessThan(usize, 8);
        const bnd = s[0..@min(bl, s.len)];
        var mit = http.multipart.parse(s, bnd, .{});
        var parts: usize = 0;
        while (mit.next() catch null) |pt| {
            parts += 1;
            sink +%= pt.value.len;
            if (parts > 4096) break;
        }

        var ebuf: [2048]u8 = undefined;
        var w = std.Io.Writer.fixed(&ebuf);
        http.sse.writeEvent(&w, .{ .event = s, .id = s, .data = s, .retry = 1 }) catch {};
        w = std.Io.Writer.fixed(&ebuf);
        http.sse.writeComment(&w, s) catch {};
    }
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const gpa = dbg.allocator();
    std.debug.print("optimize mode = {s}\n", .{@tagName(@import("builtin").mode)});

    // ── 1. robustness sweep ─────────────────────────────────────────────────
    const t0 = nowNs();
    const iters: usize = 300_000;
    try sweep(iters, 0xC0FFEE);
    const t1 = nowNs();
    std.debug.print("SWEEP: {d} iterations x 16 parsers, no panic. {d} ms  (sink={d})\n\n", .{ iters, (t1 - t0) / 1_000_000, sink });

    // ── 2. conneg: cost vs. number of Accept media-ranges ───────────────────
    const offers: []const []const u8 = &.{
        "text/html", "application/json", "application/xml", "text/plain",
        "image/png", "application/pdf",  "text/csv",        "a/b",
    };
    std.debug.print("== conneg.negotiate cost vs. Accept range count (8 offers) ==\n", .{});
    for ([_]usize{ 1, 10, 100, 500, 1000, 2000, 4000 }) |nranges| {
        var hdr: std.ArrayList(u8) = .empty;
        defer hdr.deinit(gpa);
        for (0..nranges) |k| {
            if (k != 0) try hdr.append(gpa, ',');
            try hdr.appendSlice(gpa, "zz/qq;q=0.5");
        }
        const reps: usize = if (nranges > 1000) 200 else 2000;
        const a = nowNs();
        for (0..reps) |_| {
            if (http.conneg.negotiate(hdr.items, offers)) |g| sink +%= g.weight;
        }
        const b = nowNs();
        const per = @as(f64, @floatFromInt(b - a)) / @as(f64, @floatFromInt(reps));
        std.debug.print("  ranges={d:>5}  header={d:>6} B   {d:>10.0} ns/call   {d:>8.2} ns/range/offer\n", .{ nranges, hdr.items.len, per, per / @as(f64, @floatFromInt(nranges * offers.len)) });
    }

    // ── 2b. the SAME header against 1 vs 8 offers ───────────────────────────
    // If cost scales with offers, the whole Accept header is being re-walked
    // once per offer (G7). Flat-ish means it is not.
    std.debug.print("\n== conneg.negotiate: same 1000-range header, N offers ==\n", .{});
    {
        var hdr: std.ArrayList(u8) = .empty;
        defer hdr.deinit(gpa);
        for (0..1000) |k| {
            if (k != 0) try hdr.append(gpa, ',');
            try hdr.appendSlice(gpa, "zz/qq;q=0.5");
        }
        for ([_]usize{ 1, 2, 4, 8 }) |noff| {
            const reps: usize = 500;
            const a = nowNs();
            for (0..reps) |_| {
                if (http.conneg.negotiate(hdr.items, offers[0..noff])) |g| sink +%= g.weight;
            }
            const b = nowNs();
            std.debug.print("  offers={d}  {d:>9.0} ns/call\n", .{ noff, @as(f64, @floatFromInt(b - a)) / @as(f64, @floatFromInt(reps)) });
        }
    }

    // ── 3. range: multipart/byteranges amplification ────────────────────────
    std.debug.print("\n== range: response bytes produced by one Range header ==\n", .{});
    const total: u64 = 10 * 1024 * 1024; // a 10 MiB representation
    const mp = http.range.MultipartRanges{ .boundary = "SEP", .content_type = "application/octet-stream" };
    for ([_][]const u8{
        "bytes=0-",
        "bytes=0-,0-",
        "bytes=0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-,0-",
        "bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10,11-11,12-12,13-13,14-14,15-15",
    }) |raw| {
        var sb: [http.range.default_max_ranges]http.range.ByteRangeSpec = undefined;
        const specs = http.range.parse(raw, &sb) catch {
            std.debug.print("  {s}: parse error\n", .{raw});
            continue;
        };
        var ob: [http.range.default_max_ranges]http.range.ResolvedRange = undefined;
        const res = http.range.resolve(specs, total, &ob);
        const bl = mp.bodyLen(res);
        std.debug.print("  header {d:>4} B -> {d:>2} satisfiable range(s) -> body {d:>10} B  ({d:.2}x the representation)\n", .{ raw.len, res.len, bl, @as(f64, @floatFromInt(bl)) / @as(f64, @floatFromInt(total)) });
    }

    // ── 4. bufpool: is the CHECKED-OUT set bounded? ─────────────────────────
    std.debug.print("\n== bufpool: 'a bounded set of slabs' (Client.Options.buffer_pool doc) ==\n", .{});
    var pool = http.bufpool.BufferPool.init(gpa, 4096, 8);
    defer pool.deinit();
    var held: [2000][]u8 = undefined;
    for (&held) |*h| h.* = try pool.acquire();
    std.debug.print("  max_idle_slabs=8, 2000 concurrent checkouts -> allocs={d}, idle={d}, live bytes={d}\n", .{ pool.allocCount(), pool.idleCount(), pool.allocCount() * 4096 });
    for (held) |h| pool.release(h);
    std.debug.print("  after releasing all 2000 -> idle={d} (the other {d} were freed)\n", .{ pool.idleCount(), 2000 - pool.idleCount() });
}
