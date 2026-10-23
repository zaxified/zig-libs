// SPDX-License-Identifier: MIT

//! Fuzz harnesses, generic over their source of choices (`fn(comptime S, *S,
//! gpa)`): `testing.fuzz` feeds them a `Smith`, the deterministic driver
//! (`LZMA_FUZZ=<runs>[,<first seed>]`, testkit's fuzz driver) a PRNG.
//!
//!   decode     arbitrary bytes, valid streams mutated, synthetic streams with
//!              valid framing and random payload (.lzma, raw LZMA1, raw LZMA2,
//!              .xz with a correct header CRC), glued to junk; read whole and
//!              through a chunked, failing reader with a failing allocator.
//!              Invariants: no panic, no leak, no hang; the whole-buffer and
//!              reader verdicts agree; an accepted stream's output re-encodes
//!              and decodes to itself.
//!   roundtrip  random structured input, random options (lc/lp/pb, dictionary,
//!              mode, match finder, nice length, depth), every format, odd
//!              write sizes, failing sinks: decode(encode(x)) == x and every
//!              write pattern gives the same bytes.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const lzma = @import("root.zig");

var reach: [reach_labels.len]usize = @splat(0);

fn labelIndex(comptime label: []const u8) ?usize {
    for (reach_labels, 0..) |l, i| if (std.mem.eql(u8, l, label)) return i;
    return null;
}

fn mark(comptime label: []const u8) void {
    fuzz_driver.hit(label);
    if (comptime labelIndex(label)) |i| reach[i] += 1;
}

fn markError(e: anyerror) void {
    inline for (@typeInfo(lzma.DecodeError).error_set.error_names.?) |n| {
        if (std.mem.eql(u8, n, @errorName(e))) {
            mark("err_" ++ n);
            return;
        }
    }
}

fn rangeU32(src: anytype, lo: u32, hi: u32) u32 {
    return src.valueRangeAtMost(u32, lo, hi);
}

fn drawStructured(comptime S: type, src: *S, buf: []u8) usize {
    const n = buf.len;
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0 => return src.slice(buf),
        1 => {
            var i: usize = 0;
            while (i < n) {
                const r = @min(src.valueRangeAtMost(u16, 1, 600), n - i);
                @memset(buf[i..][0..r], src.value(u8));
                i += r;
            }
            return n;
        },
        2 => {
            const k = src.valueRangeAtMost(u8, 1, 4);
            for (buf) |*c| c.* = 'a' + src.valueRangeAtMost(u8, 0, k);
            return n;
        },
        3 => {
            const p = src.valueRangeAtMost(u16, 1, 300);
            var seed: [300]u8 = undefined;
            src.bytes(&seed);
            for (buf, 0..) |*c, i| c.* = seed[i % p];
            return n;
        },
        4 => {
            // Matches at assorted distances, with small mutations.
            var i: usize = 0;
            src.bytes(buf[0..@min(n, 64)]);
            i = @min(n, 64);
            while (i < n) {
                const dist = 1 + src.valueRangeAtMost(u32, 0, @intCast(i - 1));
                const len = @min(src.valueRangeAtMost(u16, 1, 400), n - i);
                for (0..len) |k| buf[i + k] = buf[i + k - dist];
                i += len;
                if (i < n and src.valueRangeAtMost(u8, 0, 2) == 0) {
                    buf[i] = src.value(u8);
                    i += 1;
                }
            }
            return n;
        },
        5 => {
            @memset(buf, src.value(u8));
            return n;
        },
        else => {
            const words = [_][]const u8{ "range ", "coder ", "lzma ", "the ", "of ", "\n", "xz ", "dictionary " };
            var i: usize = 0;
            while (i < n) {
                const w = words[src.valueRangeAtMost(u8, 0, words.len - 1)];
                const k = @min(w.len, n - i);
                @memcpy(buf[i..][0..k], w[0..k]);
                i += k;
            }
            return n;
        },
    }
}

fn drawOptions(comptime S: type, src: *S) lzma.LzmaOptions {
    var o: lzma.LzmaOptions = .{};
    if (src.valueRangeAtMost(u8, 0, 1) == 0) {
        o = lzma.preset(src.valueRangeAtMost(u4, 0, 6), src.valueRangeAtMost(u8, 0, 7) == 0);
    }
    const dicts = [_]u32{ 4096, 5000, 20_000, 65_536, 100_000, 262_144 };
    o.dict_size = dicts[src.valueRangeAtMost(u8, 0, dicts.len - 1)];
    o.lc = src.valueRangeAtMost(u8, 0, 4);
    o.lp = src.valueRangeAtMost(u8, 0, @intCast(4 - o.lc));
    o.pb = src.valueRangeAtMost(u8, 0, 4);
    o.mode = if (src.valueRangeAtMost(u8, 0, 1) == 0) .fast else .normal;
    o.mf = switch (src.valueRangeAtMost(u8, 0, 4)) {
        0 => .hc3,
        1 => .hc4,
        2 => .bt2,
        3 => .bt3,
        else => .bt4,
    };
    o.nice_len = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => 2,
        1 => src.valueRangeAtMost(u16, 2, 273),
        2 => 273,
        else => 32,
    };
    o.depth = if (src.valueRangeAtMost(u8, 0, 2) == 0) src.valueRangeAtMost(u8, 1, 30) else 0;
    return o;
}

fn formatFor(f: lzma.EncodeFormat, o: lzma.LzmaOptions) lzma.Format {
    return switch (f) {
        .xz => .xz,
        .lzma_alone => .lzma_alone,
        .lzma1 => .{ .lzma1 = .{ .props = .{ .lc = @intCast(o.lc), .lp = @intCast(o.lp), .pb = @intCast(o.pb), .dict_size = o.dict_size } } },
        .lzma2 => .{ .lzma2 = .{ .dict_size = lzma2Dict(o.dict_size) } },
    };
}

/// The dictionary size the LZMA2 properties byte of `dict` stands for.
fn lzma2Dict(dict: u32) u32 {
    var b: u8 = 0;
    while (b < 40) : (b += 1) {
        const d = (@as(u32, 2) | (b & 1)) << @intCast(b / 2 + 11);
        if (d >= dict) return d;
    }
    return 0xFFFF_FFFF;
}

// ── synthetic streams ─────────────────────────────────────────────────────

/// Random bytes that start the way a range coder stream does (a zero byte).
fn payload(comptime S: type, src: *S, gpa: std.mem.Allocator, list: *std.ArrayList(u8), n: usize) !void {
    try list.append(gpa, if (src.valueRangeAtMost(u8, 0, 15) == 0) src.value(u8) else 0);
    var buf: [400]u8 = undefined;
    var left = n -| 1;
    while (left > 0) {
        const k = @min(left, buf.len);
        src.bytes(buf[0..k]);
        // Some structure: runs of zeros and 0xFF make for long matches.
        if (src.valueRangeAtMost(u8, 0, 3) == 0) @memset(buf[0 .. k / 2], if (src.valueRangeAtMost(u8, 0, 1) == 0) 0 else 0xFF);
        try list.appendSlice(gpa, buf[0..k]);
        left -= k;
    }
}

fn synthLzma2(comptime S: type, src: *S, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
    const chunks = src.valueRangeAtMost(u8, 1, 4);
    var first = true;
    for (0..chunks) |_| {
        var ctl: u8 = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0 => 1,
            1 => 2,
            2 => 0xA0 | src.valueRangeAtMost(u8, 0, 0x1F),
            3 => 0x80 | src.valueRangeAtMost(u8, 0, 0x1F),
            4 => 0xC0 | src.valueRangeAtMost(u8, 0, 0x1F),
            else => 0xE0 | src.valueRangeAtMost(u8, 0, 0x1F),
        };
        if (first and src.valueRangeAtMost(u8, 0, 7) != 0) ctl = 0xE0 | (ctl & 0x1F);
        if (first and ctl == 2) ctl = 1;
        first = false;
        if (src.valueRangeAtMost(u8, 0, 40) == 0) ctl = src.value(u8);
        try list.append(gpa, ctl);
        if (ctl >= 0x80) {
            const usz: u32 = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u16, 0, 65535) else src.valueRangeAtMost(u16, 0, 3000);
            const csz: u32 = src.valueRangeAtMost(u16, 4, 400);
            try list.appendSlice(gpa, &.{ @intCast(usz >> 8), @intCast(usz & 0xFF), @intCast((csz - 1) >> 8), @intCast((csz - 1) & 0xFF) });
            if (ctl >= 0xC0) {
                const lc = src.valueRangeAtMost(u8, 0, 4);
                const lp = src.valueRangeAtMost(u8, 0, 4 - lc);
                const pb = src.valueRangeAtMost(u8, 0, 4);
                var pbyte = (c_pb(pb, lp, lc));
                if (src.valueRangeAtMost(u8, 0, 40) == 0) pbyte = src.value(u8);
                try list.append(gpa, pbyte);
            }
            try payload(S, src, gpa, list, csz);
        } else {
            const n: u32 = src.valueRangeAtMost(u16, 1, 300);
            try list.appendSlice(gpa, &.{ @intCast((n - 1) >> 8), @intCast((n - 1) & 0xFF) });
            var buf: [300]u8 = undefined;
            src.bytes(buf[0..n]);
            try list.appendSlice(gpa, buf[0..n]);
        }
    }
    if (src.valueRangeAtMost(u8, 0, 3) != 0) try list.append(gpa, 0);
}

fn c_pb(pb: u8, lp: u8, lc: u8) u8 {
    return (pb * 5 + lp) * 9 + lc;
}

fn vli(list: *std.ArrayList(u8), gpa: std.mem.Allocator, v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) {
        try list.append(gpa, @as(u8, @truncate(v)) | 0x80);
        v >>= 7;
    }
    try list.append(gpa, @truncate(v));
}

/// An .xz stream with correct header CRCs, a random filter chain and a random
/// LZMA2 payload, with the index right, wrong, or missing.
fn synthXz(comptime S: type, src: *S, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
    const check_id: u8 = switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => 0,
        1 => 1,
        2 => 10,
        3 => src.valueRangeAtMost(u8, 0, 15),
        else => 4,
    };
    try list.appendSlice(gpa, &.{ 0xFD, '7', 'z', 'X', 'Z', 0 });
    const flags = [2]u8{ 0, check_id };
    try list.appendSlice(gpa, &flags);
    var crc = std.hash.Crc32.hash(&flags);
    if (src.valueRangeAtMost(u8, 0, 60) == 0) crc ^= 1;
    try list.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, crc)));

    // Block header.
    var h: std.ArrayList(u8) = .empty;
    defer h.deinit(gpa);
    try h.append(gpa, 0); // size, filled in below
    const n_filters = if (src.valueRangeAtMost(u8, 0, 7) == 0) src.valueRangeAtMost(u8, 1, 4) else 1;
    var hflags: u8 = n_filters - 1;
    const sized = src.valueRangeAtMost(u8, 0, 3) == 0;
    if (sized) hflags |= 0xC0;
    if (src.valueRangeAtMost(u8, 0, 60) == 0) hflags |= 0x04;
    try h.append(gpa, hflags);
    if (sized) {
        try vli(&h, gpa, src.valueRangeAtMost(u16, 1, 600));
        try vli(&h, gpa, src.valueRangeAtMost(u16, 0, 3000));
    }
    for (0..n_filters) |i| {
        const id: u64 = if (i + 1 == n_filters and src.valueRangeAtMost(u8, 0, 15) != 0) 0x21 else switch (src.valueRangeAtMost(u8, 0, 5)) {
            0 => 0x03,
            1 => 0x04,
            2 => 0x21,
            3 => 0x0B,
            4 => 0x20,
            else => 0x21,
        };
        try vli(&h, gpa, id);
        if (id == 0x21 and src.valueRangeAtMost(u8, 0, 15) != 0) {
            try h.append(gpa, 1);
            try h.append(gpa, if (src.valueRangeAtMost(u8, 0, 15) == 0) src.valueRangeAtMost(u8, 0, 60) else src.valueRangeAtMost(u8, 0, 18));
        } else {
            const pl = src.valueRangeAtMost(u8, 0, 3);
            try h.append(gpa, pl);
            for (0..pl) |_| try h.append(gpa, src.value(u8));
        }
    }
    while ((h.items.len + 4) % 4 != 0) try h.append(gpa, 0);
    h.items[0] = @intCast((h.items.len + 4) / 4 - 1);
    const hcrc = std.hash.Crc32.hash(h.items);
    try h.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, hcrc)));
    try list.appendSlice(gpa, h.items);

    const start = list.items.len;
    try synthLzma2(S, src, gpa, list);
    const data_len = list.items.len - start;
    while ((list.items.len - start) % 4 != 0) try list.append(gpa, 0);
    const csz: usize = switch (check_id) {
        0 => 0,
        1 => 4,
        4 => 8,
        10 => 32,
        else => 8,
    };
    for (0..csz) |_| try list.append(gpa, src.value(u8));

    // Index.
    var idx: std.ArrayList(u8) = .empty;
    defer idx.deinit(gpa);
    try idx.append(gpa, 0);
    const good = src.valueRangeAtMost(u8, 0, 3) != 0;
    try vli(&idx, gpa, 1);
    try vli(&idx, gpa, if (good) h.items.len + data_len + csz else src.valueRangeAtMost(u16, 5, 800));
    try vli(&idx, gpa, src.valueRangeAtMost(u16, 0, 3000));
    while (idx.items.len % 4 != 0) try idx.append(gpa, 0);
    const icrc = std.hash.Crc32.hash(idx.items);
    try idx.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, icrc)));
    try list.appendSlice(gpa, idx.items);
    var f: [12]u8 = undefined;
    std.mem.writeInt(u32, f[4..8], @intCast(idx.items.len / 4 - 1), .little);
    f[8] = 0;
    f[9] = check_id;
    std.mem.writeInt(u32, f[0..4], std.hash.Crc32.hash(f[4..10]), .little);
    f[10] = 'Y';
    f[11] = 'Z';
    try list.appendSlice(gpa, &f);
}

// ── a pool of valid streams ───────────────────────────────────────────────

/// Compressing a fresh input per run would make the decoder harness spend most
/// of its time in the encoder (the round-trip harness is for that), so the
/// mutated and glued streams are drawn from a fixed pool made once per process.
const Pooled = struct { format: lzma.EncodeFormat, opts: lzma.LzmaOptions, stream: []u8 };
const pool_len = 24;
var pool: [pool_len]Pooled = undefined;
var pool_ready = false;

fn getPool() *const [pool_len]Pooled {
    if (pool_ready) return &pool;
    var prng = std.Random.DefaultPrng.init(0x706f6f6c);
    var rng: fuzz_driver.Rng = .{ .r = prng.random() };
    const gpa = std.heap.page_allocator; // global-alloc-ok: process-lifetime test fixture
    var data: [3000]u8 = undefined;
    for (&pool, 0..) |*p, i| {
        const o = drawOptions(fuzz_driver.Rng, &rng);
        const f: lzma.EncodeFormat = switch (i % 4) {
            0 => .xz,
            1 => .lzma_alone,
            2 => .lzma1,
            else => .lzma2,
        };
        const n = drawStructured(fuzz_driver.Rng, &rng, data[0..rng.valueRangeAtMost(u16, 0, 3000)]);
        const check: lzma.Check = switch (i % 3) {
            0 => .crc64,
            1 => .none,
            else => .sha256,
        };
        p.* = .{ .format = f, .opts = o, .stream = lzma.compress(gpa, data[0..n], f, .{ .lzma = o, .check = check }) catch unreachable };
    }
    pool_ready = true;
    return &pool;
}

// ── decode harness ────────────────────────────────────────────────────────

const cap: u64 = 4 << 20;

fn decodeStream(comptime S: type, src: *S, gpa: std.mem.Allocator, stream: []const u8, format: lzma.Format) !void {
    const opts: lzma.DecodeOptions = .{
        .max_output = if (src.valueRangeAtMost(u8, 0, 15) == 0) src.valueRangeAtMost(u16, 0, 3000) else cap,
        .max_dict = 1 << 20,
        .multi_stream = src.valueRangeAtMost(u8, 0, 7) != 0,
        .ignore_trailing_garbage = src.valueRangeAtMost(u8, 0, 3) == 0,
    };
    const whole = lzma.decompress(gpa, stream, format, opts);

    // The same stream through a reader that breaks it into chunks and may
    // fail, with an allocator that may fail.
    var plan = testkit.fuzz.FaultPlan.draw(src, stream.len);
    if (src.valueRangeAtMost(u8, 0, 1) == 0) plan.fail_at = null;
    var rbuf: [64]u8 = undefined;
    const rb = rbuf[0..if (src.valueRangeAtMost(u8, 0, 1) == 0) 16 else 64];
    var cr = testkit.fuzz.ChunkedReader.init(stream, plan, rb);
    var fa = testkit.fuzz.failingAllocator(src, gpa, 24);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const piece = piece: {
        var dr = lzma.DecompressReader.init(fa.allocator(), &cr.interface, &.{}, format, opts) catch |e| {
            std.debug.assert(e == error.OutOfMemory);
            mark("oom_init");
            break :piece @as(?anyerror, e);
        };
        defer dr.deinit();
        _ = dr.reader.streamRemaining(&out.writer) catch |e| {
            if (e == error.WriteFailed) break :piece @as(?anyerror, error.OutOfMemory);
            break :piece @as(?anyerror, dr.err orelse return error.ReadFailedWithoutCause);
        };
        break :piece null;
    };

    if (piece) |pe| {
        if (pe == error.OutOfMemory) mark("fault_oom");
        if (pe == error.ReadFailed) mark("fault_read");
    }
    if (whole) |w| {
        defer gpa.free(w);
        if (w.len == 0) mark("ok_empty") else mark("ok_data");
        if (piece) |e| {
            if (e != error.ReadFailed and e != error.OutOfMemory) return error.ReaderDisagrees;
            if (plan.fail_at == null and fa.fail_index == std.math.maxInt(usize)) return error.ReaderDisagrees;
            mark("fault_on_good");
        } else try testing.expectEqualSlices(u8, w, out.written());
        // An accepted stream's output re-encodes and decodes to itself.
        if (w.len != 0 and w.len <= 6000 and src.valueRangeAtMost(u8, 0, 3) == 0) {
            var o = lzma.preset(1, false);
            o.dict_size = 8192;
            const z = try lzma.compress(gpa, w, .lzma_alone, .{ .lzma = o });
            defer gpa.free(z);
            const back = try lzma.decompress(gpa, z, .lzma_alone, .{});
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, w, back);
            mark("reencoded");
        }
    } else |e| {
        markError(e);
        if (piece) |pe| {
            if (pe != e and pe != error.ReadFailed and pe != error.OutOfMemory) {
                std.debug.print("whole: {t}, reader: {t}\n", .{ e, pe });
                return error.ReaderDisagrees;
            }
        } else return error.ReaderAcceptedWhatWholeRefused;
    }
}

pub fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);

    // First draw from a full-range u64: a ranged first draw returns its minimum for
    // almost every --fuzz seed (check-fuzz-reach R1), pinning the pool entry to 0.
    const pooled = getPool()[@intCast(src.value(u64) % pool_len)];
    const o = pooled.opts;
    var f = pooled.format;
    var fmt = formatFor(f, o);

    const mode: u8 = @intCast(src.value(u64) % 8); // full range: a switch discriminant (check-fuzz-reach R2)
    switch (mode) {
        0 => {
            mark("mode_raw");
            var raw: [300]u8 = undefined;
            const n = src.slice(&raw);
            if (n >= 6 and f == .xz and src.valueRangeAtMost(u8, 0, 1) == 0) @memcpy(raw[0..6], &[_]u8{ 0xFD, '7', 'z', 'X', 'Z', 0 });
            try stream.appendSlice(gpa, raw[0..n]);
        },
        1, 2, 5 => {
            const z = pooled.stream;
            try stream.appendSlice(gpa, z);
            if (mode == 5) {
                mark("mode_glued");
                switch (src.valueRangeAtMost(u8, 0, 4)) {
                    0 => try stream.appendSlice(gpa, z),
                    1 => try stream.appendSlice(gpa, "junk"),
                    2 => try stream.appendNTimes(gpa, 0, @as(usize, src.valueRangeAtMost(u8, 0, 8))),
                    3 => try stream.appendSlice(gpa, z[0..@min(z.len, @as(usize, src.valueRangeAtMost(u8, 0, 30)))]),
                    else => try stream.appendNTimes(gpa, 0, 8),
                }
            } else {
                const deep = mode == 2;
                if (deep) mark("mode_deep") else mark("mode_mutated");
                const first: usize = if (deep) @min(24, stream.items.len) else 0;
                for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
                    if (stream.items.len <= first) break;
                    const room = stream.items.len - first;
                    const at = first + @as(usize, @intCast(src.value(u64) % room));
                    switch (src.valueRangeAtMost(u8, 0, 3)) {
                        0 => stream.items[at] ^= @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7),
                        1 => stream.items[at] = src.value(u8),
                        2 => stream.shrinkRetainingCapacity(at),
                        else => try stream.insert(gpa, at, src.value(u8)),
                    }
                }
            }
        },
        3, 4 => {
            mark("mode_synth");
            switch (f) {
                .xz => try synthXz(S, src, gpa, &stream),
                .lzma2 => try synthLzma2(S, src, gpa, &stream),
                .lzma_alone => {
                    try stream.append(gpa, c_pb(@intCast(o.pb), @intCast(o.lp), @intCast(o.lc)));
                    try stream.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, o.dict_size)));
                    const known = src.valueRangeAtMost(u8, 0, 2) != 0;
                    const size: u64 = if (known) src.valueRangeAtMost(u16, 0, 6000) else std.math.maxInt(u64);
                    try stream.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u64, size)));
                    try payload(S, src, gpa, &stream, src.valueRangeAtMost(u16, 5, 300));
                },
                .lzma1 => {
                    try payload(S, src, gpa, &stream, src.valueRangeAtMost(u16, 5, 300));
                    if (src.valueRangeAtMost(u8, 0, 1) == 0) {
                        fmt = .{ .lzma1 = .{
                            .props = .{ .lc = @intCast(o.lc), .lp = @intCast(o.lp), .pb = @intCast(o.pb), .dict_size = o.dict_size },
                            .uncompressed_size = src.valueRangeAtMost(u16, 0, 6000),
                            .allow_eopm = src.valueRangeAtMost(u8, 0, 1) == 0,
                        } };
                    }
                },
            }
        },
        else => {
            // Our own raw LZMA2 with the header bytes of a chunk flipped.
            mark("mode_chunks");
            f = .lzma2;
            const l2 = getPool()[3 + 4 * src.valueRangeAtMost(u8, 0, pool_len / 4 - 1)];
            const z = l2.stream;
            fmt = formatFor(f, l2.opts);
            try stream.appendSlice(gpa, z);
            for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
                const at: usize = @intCast(src.value(u64) % @min(stream.items.len, 8));
                stream.items[at] ^= @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7);
            }
        },
    }
    try decodeStream(S, src, gpa, stream.items, fmt);
}

// ── round-trip harness ────────────────────────────────────────────────────

pub fn roundtripHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var data: [40_000]u8 = undefined;
    // Full-range first draw, see decodeHarness (check-fuzz-reach R1).
    const want_len: usize = switch (src.value(u64) % 8) {
        0 => 0,
        1...5 => src.valueRangeAtMost(u16, 1, 3000),
        else => src.valueRangeAtMost(u16, 3000, 40_000),
    };
    const n = drawStructured(S, src, data[0..want_len]);
    const input = data[0..n];
    if (n == 0) mark("rt_empty");
    if (n >= 20_000) mark("rt_big");

    const o = drawOptions(S, src);
    const f: lzma.EncodeFormat = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => .xz,
        1 => .lzma_alone,
        2 => .lzma1,
        else => .lzma2,
    };
    const check: lzma.Check = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => .none,
        1 => .crc32,
        2 => .sha256,
        else => .crc64,
    };
    const opts: lzma.EncodeOptions = .{ .lzma = o, .check = check };
    const z = try lzma.compress(gpa, input, f, opts);
    defer gpa.free(z);
    const back = try lzma.decompress(gpa, z, formatFor(f, o), .{ .max_dict = 1 << 20 });
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    mark("rt_ok");

    // Another write pattern: the same bytes (on half the runs; the others
    // take the failing sink).
    const take_pieces = src.valueRangeAtMost(u8, 0, 1) == 0;
    if (take_pieces) {
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var buf: [64]u8 = undefined;
        var sw = try lzma.StreamWriter.init(gpa, &out.writer, buf[0..src.valueRangeAtMost(u8, 0, 64)], f, opts);
        defer sw.deinit();
        var at: usize = 0;
        while (at < n) {
            const k = @min(@as(usize, src.valueRangeAtMost(u16, 1, 9000)), n - at);
            try sw.writer.writeAll(input[at..][0..k]);
            at += k;
        }
        try sw.finish();
        try testing.expectEqualSlices(u8, z, out.written());
        mark("rt_pieces");
    }

    // A sink that fails: an error, never a panic, never a leak.
    if (!take_pieces) {
        var plan = testkit.fuzz.FaultPlan.draw(src, z.len);
        plan.fail_at = @as(usize, src.valueRangeAtMost(u32, 0, @intCast(z.len)));
        var sink: [60_000]u8 = undefined;
        var cw = testkit.fuzz.ChunkedWriter.init(&sink, plan, &.{});
        var failed = false;
        if (lzma.Encoder.init(gpa, &cw.interface, f, opts)) |enc_| {
            var enc = enc_;
            defer enc.deinit();
            enc.write(input) catch |e| {
                try testing.expect(e == error.WriteFailed);
                failed = true;
            };
            if (!failed) enc.finish() catch |e| {
                try testing.expect(e == error.WriteFailed);
                failed = true;
            };
        } else |e| {
            try testing.expect(e == error.WriteFailed);
            failed = true;
        }
        if (failed) mark("rt_sink_failed");
    }
}

// ── drivers ──────────────────────────────────────────────────────────────

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    try decodeHarness(std.testing.Smith, smith, testing.allocator);
}

fn fuzzRoundtrip(_: void, smith: *std.testing.Smith) !void {
    try roundtripHarness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: the decoders never panic, leak or hang on arbitrary and mutated streams" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

test "fuzz: encode then decode is the identity for every format and option set" {
    try std.testing.fuzz({}, fuzzRoundtrip, .{});
}

test "fuzz driver: LZMA_FUZZ, decoder" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "LZMA_FUZZ", .name = "lzma-decode" });
}

test "fuzz driver: LZMA_FUZZ, round trip" {
    try fuzz_driver.run(roundtripHarness, .{ .prefix = "LZMA_FUZZ", .name = "lzma-roundtrip", .scale = 40 });
}

const reach_labels = [_][]const u8{
    "mode_raw",           "mode_mutated",    "mode_deep",         "mode_synth",            "mode_glued",
    "mode_chunks",        "ok_data",         "ok_empty",          "reencoded",             "err_BadMagic",
    "err_BadHeader",      "err_BadFooter",   "err_BadIndex",      "err_UnsupportedFilter", "err_UnsupportedCheck",
    "err_DictTooLarge",   "err_CorruptData", "err_CheckMismatch", "err_TruncatedInput",    "err_TrailingData",
    "err_OutputTooLarge", "fault_oom",       "fault_read",        "rt_empty",              "rt_big",
    "rt_ok",              "rt_pieces",       "rt_sink_failed",
};

test "fuzz harnesses: 3000 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..3000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("lzma decode seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        if (seed % 8 == 0) roundtripHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("lzma roundtrip seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    var missing = false;
    for (reach_labels, reach) |l, n| {
        if (n == 0) {
            std.debug.print("reach: label {s} never hit in 3000 seeds\n", .{l});
            missing = true;
        }
    }
    if (missing) return error.HarnessDoesNotReach;
}
