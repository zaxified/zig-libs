// SPDX-License-Identifier: MIT
//! Decoding contexts: a caller's workspace (`Decompressor.initStatic`,
//! `DecompressStream.initStatic`, `DDict.initStatic`), the estimates that
//! size it -- exact: a workspace of the estimate decodes what it claims to
//! cover and one byte less is `error.OutOfMemory` --, `max_block_size`
//! (`ZSTD_d_maxBlockSize`) against libzstd's verdicts and buffer sizes
//! (`testdata/mbs_kats.zig`, `tools/gen-mbs-kats.sh`), and `copyFrom`
//! (`ZSTD_copyDCtx`).

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const dict_kats = @import("testdata/dict_kats.zig");
const mbs_kats = @import("testdata/mbs_kats.zig");

const gpa = std.testing.allocator;

fn corpusInput(name: []const u8) ![]u8 {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) {
        const src = try gpa.alloc(u8, c.len);
        corpus.generate(c, src);
        return src;
    };
    unreachable;
}

fn fnv(b: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (b) |x| {
        h ^= x;
        h *%= 0x100000001b3;
    }
    return h;
}

fn workspace(size: usize) !zstd.Workspace {
    return gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), size);
}

/// libzstd's `ZSTD_ErrorCode` for the errors these tests meet (`zdec`'s
/// `ERR <n>`); 0 for success.
fn code(e: anyerror) u8 {
    return switch (e) {
        error.FrameParameterWindowTooLarge => 16,
        error.CorruptionDetected => 20,
        error.ChecksumWrong => 22,
        error.ParameterOutOfBound => 42,
        error.OutOfMemory => 64,
        error.DstSizeTooSmall => 70,
        error.SrcSizeWrong => 72,
        else => 255,
    };
}

const Streamed = struct { verdict: u8, bufs: usize };

/// `zdec` mode 1 (`whole`: all the input at once, 128 KB of output per
/// call) or mode 2 (one more input byte per call, 997 bytes of output), on
/// `s`; the output must be `want`. Returns the verdict and the bytes of the
/// stream's buffers at the end.
fn zdecStream(s: *zstd.DecompressStream, z: []const u8, want: []const u8, whole: bool) !Streamed {
    const ochunk: usize = if (whole) 1 << 17 else 997;
    const obuf = try gpa.alloc(u8, ochunk);
    defer gpa.free(obuf);
    var produced: usize = 0;
    var size: usize = if (whole) z.len else @min(z.len, 1);
    var in: zstd.InBuffer = .{ .src = z[0..size] };
    var r: usize = 1;
    while (true) {
        var o: zstd.OutBuffer = .{ .dst = obuf };
        r = s.decompressStream(&o, &in) catch |e| return .{ .verdict = code(e), .bufs = s.workspaceSize() - zstd.estimateDecompressorSize() };
        try std.testing.expect(produced + o.pos <= want.len);
        try std.testing.expectEqualSlices(u8, want[produced..][0..o.pos], o.dst[0..o.pos]);
        produced += o.pos;
        if (!whole and in.pos == in.src.len and size < z.len) {
            size += 1;
            in.src = z[0..size];
            continue;
        }
        if (in.pos == in.src.len and o.pos < o.dst.len) break;
    }
    const bufs = s.workspaceSize() - zstd.estimateDecompressorSize();
    if (r != 0) return .{ .verdict = 72, .bufs = bufs };
    try std.testing.expectEqual(want.len, produced);
    return .{ .verdict = 0, .bufs = bufs };
}

test "max_block_size refuses frames exactly where libzstd does, and sizes the stream's buffers as libzstd" {
    var src: []u8 = &.{};
    defer gpa.free(src);
    var frame: []u8 = &.{};
    defer gpa.free(frame);
    var key: ?mbs_kats.Kat = null;
    var failures: usize = 0;
    for (mbs_kats.kats) |k| {
        if (key == null or !std.mem.eql(u8, key.?.case, k.case) or key.?.level != k.level or key.?.frame_mbs != k.frame_mbs) {
            if (key == null or !std.mem.eql(u8, key.?.case, k.case)) {
                gpa.free(src);
                src = try corpusInput(k.case);
            }
            gpa.free(frame);
            // libzstd's frame, from this module's compressor
            frame = try zstd.compressAlloc(gpa, src, .{ .level = k.level, .advanced = .{ .max_block_size = if (k.frame_mbs == 0) null else k.frame_mbs } });
            try std.testing.expectEqual(k.len, frame.len);
            try std.testing.expectEqual(k.fnv, fnv(frame));
            key = k;
        }
        // one-shot, into `decompressBound` bytes (as `zdec` mode 0)
        const out = try gpa.alloc(u8, @intCast(try zstd.decompressBound(frame)));
        defer gpa.free(out);
        var d = try zstd.Decompressor.init(gpa, .{ .max_block_size = k.mbs });
        defer d.deinit();
        const oneshot: u8 = if (d.decompress(out, frame)) |n| blk: {
            try std.testing.expectEqualSlices(u8, src, out[0..n]);
            break :blk 0;
        } else |e| code(e);

        const opts: zstd.DecompressStreamOptions = .{ .window_log_max = 31, .max_block_size = k.mbs };
        var s1 = try zstd.DecompressStream.init(gpa, opts);
        defer s1.deinit();
        const whole = try zdecStream(&s1, frame, src, true);
        var s2 = try zstd.DecompressStream.init(gpa, opts);
        defer s2.deinit();
        const bytewise = try zdecStream(&s2, frame, src, false);

        // the same in a workspace of exactly the estimate for the frame;
        // one byte less fails when the buffers are laid out
        const est = try zstd.estimateDecompressStreamSizeFromFrame(frame, opts);
        try std.testing.expectEqual(est, zstd.estimateDecompressorSize() + bytewise.bufs);
        const ws = try workspace(est);
        defer gpa.free(ws);
        var s3 = try zstd.DecompressStream.initStatic(ws, opts);
        defer s3.deinit();
        const static = try zdecStream(&s3, frame, src, false);
        var s4 = try zstd.DecompressStream.initStatic(ws[0 .. est - 1], opts);
        defer s4.deinit();
        const short = try zdecStream(&s4, frame, src, false);

        if (oneshot != k.oneshot or whole.verdict != k.whole or bytewise.verdict != k.bytewise or
            whole.bufs != k.whole_buf or bytewise.bufs != k.bytewise_buf or
            static.verdict != k.bytewise or static.bufs != k.bytewise_buf or short.verdict != 64)
        {
            std.debug.print("{s} l{d} frame {d} mbs {d}: {d} {d} {d} bufs {d} {d}, static {d} {d}, short {d}; libzstd {d} {d} {d} bufs {d} {d}\n", .{ k.case, k.level, k.frame_mbs, k.mbs, oneshot, whole.verdict, bytewise.verdict, whole.bufs, bytewise.bufs, static.verdict, static.bufs, short.verdict, k.oneshot, k.whole, k.bytewise, k.whole_buf, k.bytewise_buf });
            failures += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
    try std.testing.expectEqual(@as(usize, 240), mbs_kats.kats.len);
}

test "max_block_size out of libzstd's bounds is refused" {
    // libzstd refuses 1023 and 131073 when set (`zdec ... mbs:N`:
    // parameter_outOfBound); this port at the first call that decodes
    const z = try zstd.compressAlloc(gpa, "abc", .{});
    defer gpa.free(z);
    var out: [8]u8 = undefined;
    for ([_]u32{ 0, 1023, 131073 }) |m| {
        var d = try zstd.Decompressor.init(gpa, .{ .max_block_size = m });
        defer d.deinit();
        try std.testing.expectError(error.ParameterOutOfBound, d.decompress(&out, z));
        var s = try zstd.DecompressStream.init(gpa, .{ .max_block_size = m });
        defer s.deinit();
        var in: zstd.InBuffer = .{ .src = z };
        var o: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.ParameterOutOfBound, s.decompressStream(&o, &in));
        // the stream's own check, not the one-shot decoder's behind its
        // single-pass shortcut: one byte, no header yet
        var s1 = try zstd.DecompressStream.init(gpa, .{ .max_block_size = m });
        defer s1.deinit();
        var in1: zstd.InBuffer = .{ .src = z[0..1] };
        var o1: zstd.OutBuffer = .{ .dst = &out };
        try std.testing.expectError(error.ParameterOutOfBound, s1.decompressStream(&o1, &in1));
        try std.testing.expectError(error.ParameterOutOfBound, zstd.estimateDecompressStreamSize(1 << 20, .{ .max_block_size = m }));
        try std.testing.expectError(error.ParameterOutOfBound, zstd.estimateDecompressStreamSizeFromFrame(z, .{ .max_block_size = m }));
    }
    for ([_]u32{ 1024, 131072 }) |m| {
        var d = try zstd.Decompressor.init(gpa, .{ .max_block_size = m });
        defer d.deinit();
        try std.testing.expectEqual(@as(usize, 3), try d.decompress(&out, z));
    }
}

test "the piecewise decoder does not apply max_block_size, as ZSTD_decompressContinue does not" {
    const src = try corpusInput("csv-131073");
    defer gpa.free(src);
    const z = try zstd.compressAlloc(gpa, src, .{ .level = 3 });
    defer gpa.free(z);
    var d = try zstd.Decompressor.init(gpa, .{ .max_block_size = 1024 });
    defer d.deinit();
    const out = try gpa.alloc(u8, src.len);
    defer gpa.free(out);
    d.begin();
    var ip: usize = 0;
    var op: usize = 0;
    while (d.nextSrcSizeToDecompress() != 0) {
        const n = d.nextSrcSizeToDecompress();
        op += try d.decompressContinue(out[op..], z[ip..][0..n]);
        ip += n;
    }
    try std.testing.expectEqualSlices(u8, src, out[0..op]);
    // the one-shot decoder refuses the frame (a 128 KB compressed block)
    var d2 = try zstd.Decompressor.init(gpa, .{ .max_block_size = 1024 });
    defer d2.deinit();
    try std.testing.expectError(error.SrcSizeWrong, d2.decompress(out, z));
}

/// A frame of unknown content size with window 2^`log` (mantissa `m`,
/// patched into the header: a larger window only allows more history) and
/// blocks of at most `mbs` bytes.
fn unknownSizeFrame(src: []const u8, log: u5, m: u3, mbs: ?u32) ![]u8 {
    var s = try zstd.Stream.init(gpa, .{ .level = 3, .advanced = .{ .window_log = log, .max_block_size = mbs } });
    defer s.deinit();
    const out = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
    errdefer gpa.free(out);
    var o: zstd.OutBuffer = .{ .dst = out };
    var in: zstd.InBuffer = .{ .src = src };
    while (in.pos < in.src.len) _ = try s.compressStream2(&o, &in, .@"continue");
    while (try s.compressStream2(&o, &in, .end) != 0) {}
    std.debug.assert(out[4] & 0xE0 == 0); // no content size, not single-segment
    out[5] = (@as(u8, log) - 10) << 3 | m;
    return gpa.realloc(out, o.pos);
}

fn headerWindow(log: u6, m: u3) u64 {
    const w = @as(u64, 1) << log;
    return w + (w >> 3) * m;
}

test "estimateDecompressStreamSize: exact for a frame of that window and unknown size, over the window and block grid" {
    const mbss = [_]?u32{ null, 1024, 4096, 65536, 131072 };
    // every window a header can declare: the estimate is what the stream
    // takes for it (the frame's own estimate), without decoding
    var log: u6 = 10;
    while (log <= zstd.limits.window_log_max) : (log += 1) for (0..8) |mi| {
        const m: u3 = @intCast(mi);
        const hdr = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, (@as(u8, log) - 10) << 3 | m };
        const w = headerWindow(log, m);
        for (mbss) |mbs| for ([_]bool{ false, true }) |stable| {
            const opts: zstd.DecompressStreamOptions = .{ .window_log_max = 31, .max_block_size = mbs, .stable_output = stable };
            const est = try zstd.estimateDecompressStreamSize(w, opts);
            if (w > @as(u64, 1) << 31) {
                try std.testing.expectError(error.FrameParameterWindowTooLarge, zstd.estimateDecompressStreamSizeFromFrame(&hdr, opts));
                continue;
            }
            try std.testing.expectEqual(est, try zstd.estimateDecompressStreamSizeFromFrame(&hdr, opts));
            const b: u64 = @min(w, mbs orelse 131072);
            try std.testing.expectEqual(zstd.estimateDecompressorSize() + b + if (stable) 0 else w + 2 * b + 64, est);
            // a frame naming a content size needs no more
            for ([_]u64{ 0, 1, 1000, w - 1, w, w * 3 }) |fcs| {
                var h2: [14]u8 = undefined;
                @memcpy(h2[0..6], &hdr);
                h2[4] = 0xC0; // 8-byte content size
                std.mem.writeInt(u64, h2[6..14], fcs, .little);
                try std.testing.expect(try zstd.estimateDecompressStreamSizeFromFrame(&h2, opts) <= est);
            }
        };
    };
    // a window under 1 KB counts as 1 KB, as the stream counts it
    try std.testing.expectEqual(try zstd.estimateDecompressStreamSize(1024, .{}), try zstd.estimateDecompressStreamSize(0, .{}));
    // a smaller window never needs more
    var prev: usize = 0;
    var w: u64 = 1;
    while (w < 1 << 28) : (w = w * 3 / 2 + 1) {
        const e = try zstd.estimateDecompressStreamSize(w, .{ .max_block_size = 4096 });
        try std.testing.expect(e >= prev);
        prev = e;
    }

    // decoding: the stream allocates exactly the estimate; a workspace of
    // it decodes the frame, one byte less does not
    const src = try corpusInput("csv-600000");
    defer gpa.free(src);
    const input = src[0..300000];
    for ([_]u5{ 10, 11, 14, 17, 18, 20 }) |l| for ([_]u3{ 0, 3, 7 }) |m| for (mbss) |mbs| {
        const z = try unknownSizeFrame(input, l, m, mbs);
        defer gpa.free(z);
        try std.testing.expectEqual(@as(?u64, null), try zstd.getFrameContentSize(z));
        for ([_]bool{ false, true }) |stable| {
            const opts: zstd.DecompressStreamOptions = .{ .max_block_size = mbs, .stable_output = stable };
            const est = try zstd.estimateDecompressStreamSize(headerWindow(l, m), opts);
            try std.testing.expectEqual(est, try zstd.estimateDecompressStreamSizeFromFrame(z, opts));
            var s = try zstd.DecompressStream.init(gpa, opts);
            defer s.deinit();
            try decodeInPieces(&s, z, input, stable);
            try std.testing.expectEqual(est, s.workspaceSize());
            const ws = try workspace(est);
            defer gpa.free(ws);
            var st = try zstd.DecompressStream.initStatic(ws, opts);
            defer st.deinit();
            try decodeInPieces(&st, z, input, stable);
            var short = try zstd.DecompressStream.initStatic(ws[0 .. est - 1], opts);
            defer short.deinit();
            try std.testing.expectError(error.OutOfMemory, decodeInPieces(&short, z, input, stable));
        }
    };
}

/// Decodes `z` through `s` in 1000-byte pieces (no single-pass shortcut)
/// and checks the output is `want`.
fn decodeInPieces(s: *zstd.DecompressStream, z: []const u8, want: []const u8, stable: bool) !void {
    const out = try gpa.alloc(u8, want.len);
    defer gpa.free(out);
    var o: zstd.OutBuffer = .{ .dst = out };
    var ip: usize = 0;
    var r: usize = 1;
    while (true) {
        var in: zstd.InBuffer = .{ .src = z[0..@min(z.len, ip + 1000)], .pos = ip };
        if (!stable) o.dst = out[0..@min(out.len, o.pos + 5000)];
        r = try s.decompressStream(&o, &in);
        ip = in.pos;
        if (r == 0 and ip == z.len) break;
    }
    try std.testing.expectEqualSlices(u8, want, out[0..o.pos]);
}

test "a decoder in a caller's workspace: exactly estimateDecompressorSize, nothing allocated" {
    const est = zstd.estimateDecompressorSize();
    const ws = try workspace(est);
    defer gpa.free(ws);
    try std.testing.expectError(error.OutOfMemory, zstd.Decompressor.initStatic(ws[0 .. est - 1], .{}));
    try std.testing.expectError(error.OutOfMemory, zstd.DecompressStream.initStatic(ws[0 .. est - 1], .{}));
    // libzstd's frames (the goldens' bytes, from this module's compressor)
    var d = try zstd.Decompressor.initStatic(ws, .{});
    defer d.deinit();
    try std.testing.expectEqual(est, d.workspaceSize());
    for ([_][]const u8{ "words-16385", "csv-131073", "zeros-300000", "long-literals", "far-repeat" }) |name| {
        const src = try corpusInput(name);
        defer gpa.free(src);
        for ([_]i32{ -1, 3, 19 }) |level| {
            const z = try zstd.compressAlloc(gpa, src, .{ .level = level, .checksum = true });
            defer gpa.free(z);
            const out = try gpa.alloc(u8, src.len);
            defer gpa.free(out);
            try std.testing.expectEqual(src.len, try d.decompress(out, z));
            try std.testing.expectEqualSlices(u8, src, out);
        }
    }
    // with a dictionary, digested into a workspace too, by copy and by
    // reference; and the raw bytes, which the one-shot decoder reads in place
    for ([_]bool{ true, false }) |copied| {
        const dws = try gpa.alloc(u8, zstd.DDict.estimateSize(dict_kats.full_dict.len, copied));
        defer gpa.free(dws);
        const dd = try zstd.DDict.initStatic(dws, dict_kats.full_dict, .auto, copied);
        try std.testing.expectEqual(dws.len, dd.memorySize());
        var dd_d = try zstd.Decompressor.initStatic(ws, .{ .ddict = &dd });
        var out: [512]u8 = undefined;
        const n = try dd_d.decompress(&out, dict_kats.frame_full_l3);
        try std.testing.expectEqualStrings(dict_kats.in1_content, out[0..n]);
        const ss = try workspace(try zstd.estimateDecompressStreamSizeFromFrame(dict_kats.frame_full_l19, .{}));
        defer gpa.free(ss);
        var s = try zstd.DecompressStream.initStatic(ss, .{ .ddict = &dd });
        defer s.deinit();
        try decodeInPieces(&s, dict_kats.frame_full_l19, dict_kats.in1_content, false);
    }
    var raw_d = try zstd.Decompressor.initStatic(ws, .{ .dictionary = dict_kats.full_dict });
    var out: [512]u8 = undefined;
    const n = try raw_d.decompress(&out, dict_kats.frame_full_l3);
    try std.testing.expectEqualStrings(dict_kats.in1_content, out[0..n]);
    // a stream in a workspace cannot digest raw bytes (it would allocate)
    try std.testing.expectError(error.OutOfMemory, zstd.DecompressStream.initStatic(ws, .{ .dictionary = dict_kats.full_dict }));
}

test "a DDict in a caller's workspace: its content by copy exactly fills the estimate" {
    const dict = dict_kats.full_dict;
    try std.testing.expectEqual(dict.len, zstd.DDict.estimateSize(dict.len, true));
    try std.testing.expectEqual(@as(usize, 0), zstd.DDict.estimateSize(dict.len, false));
    const ws = try gpa.alloc(u8, dict.len);
    defer gpa.free(ws);
    try std.testing.expectError(error.OutOfMemory, zstd.DDict.initStatic(ws[0 .. dict.len - 1], dict, .auto, true));
    var copy = try zstd.DDict.initStatic(ws, dict, .auto, true);
    try std.testing.expect(copy.content.ptr == ws.ptr);
    try std.testing.expectEqual(zstd.getDictId(dict), copy.dictId());
    const by_ref = try zstd.DDict.initStatic(ws[0..0], dict, .auto, false);
    try std.testing.expect(by_ref.content.ptr == dict.ptr);
    try std.testing.expectEqual(@as(usize, 0), by_ref.memorySize());
    var heap = try zstd.DDict.init(gpa, dict, .auto);
    defer heap.deinit(gpa);
    try std.testing.expectEqual(dict.len, heap.memorySize());
    // the copy decodes once the original is gone
    const tmp = try gpa.dupe(u8, dict);
    const from_tmp = try zstd.DDict.initStatic(ws, tmp, .auto, true);
    @memset(tmp, 0);
    gpa.free(tmp);
    var out: [512]u8 = undefined;
    var d = try zstd.Decompressor.init(gpa, .{ .ddict = &from_tmp });
    defer d.deinit();
    const n = try d.decompress(&out, dict_kats.frame_full_l3);
    try std.testing.expectEqualStrings(dict_kats.in1_content, out[0..n]);
    // a content type that does not fit the bytes is refused as by `init`
    try std.testing.expectError(error.DictionaryCorrupted, zstd.DDict.initStatic(ws, dict_kats.raw_dict[0..@min(ws.len, dict_kats.raw_dict.len)], .full, true));
    copy.deinit(gpa); // frees nothing: the workspace is the caller's
}

test "copyFrom (ZSTD_copyDCtx): a prepared context copied before and during a frame" {
    const src = try corpusInput("csv-600000");
    defer gpa.free(src);
    var dd = try zstd.DDict.init(gpa, dict_kats.full_dict, .auto);
    defer dd.deinit(gpa);
    const z = try zstd.compressAlloc(gpa, src, .{ .level = 5, .checksum = true });
    defer gpa.free(z);

    // before decoding: the options travel, max_block_size among them
    var prepared = try zstd.Decompressor.init(gpa, .{ .max_block_size = 1024, .ddict = &dd });
    defer prepared.deinit();
    const ws = try workspace(zstd.estimateDecompressorSize());
    defer gpa.free(ws);
    var c = try zstd.Decompressor.initStatic(ws, .{});
    defer c.deinit();
    c.copyFrom(&prepared);
    try std.testing.expect(c.gpa == null and c.st != prepared.st);
    var out: [512]u8 = undefined;
    const n = try c.decompress(&out, dict_kats.frame_full_l3);
    try std.testing.expectEqualStrings(dict_kats.in1_content, out[0..n]);
    const big = try gpa.alloc(u8, src.len);
    defer gpa.free(big);
    try std.testing.expectError(error.SrcSizeWrong, c.decompress(big, z));
    c.copyFrom(&c); // itself: nothing happens

    // during a frame, piecewise: the copy goes on from where the original
    // was -- stage, frame header, entropy tables, repeat offsets, checksum
    // state -- reaching back into the original's output (shared history)
    var a = try zstd.Decompressor.init(gpa, .{});
    defer a.deinit();
    const out_a = try gpa.alloc(u8, src.len);
    defer gpa.free(out_a);
    const out_b = try gpa.alloc(u8, src.len);
    defer gpa.free(out_b);
    a.begin();
    var ip: usize = 0;
    var op: usize = 0;
    var steps: usize = 0;
    while (a.nextSrcSizeToDecompress() != 0 and op < 300000) : (steps += 1) {
        const k = a.nextSrcSizeToDecompress();
        op += try a.decompressContinue(out_a[op..], z[ip..][0..k]);
        ip += k;
    }
    try std.testing.expect(steps > 4 and op >= 300000);
    var b = try zstd.Decompressor.init(gpa, .{});
    defer b.deinit();
    b.copyFrom(&a);
    for ([_]*zstd.Decompressor{ &a, &b }, [_][]u8{ out_a, out_b }) |x, o| {
        var xi = ip;
        var xo = op;
        while (x.nextSrcSizeToDecompress() != 0) {
            const k = x.nextSrcSizeToDecompress();
            xo += try x.decompressContinue(o[xo..], z[xi..][0..k]);
            xi += k;
        }
        try std.testing.expectEqual(z.len, xi);
        try std.testing.expectEqualSlices(u8, src[op..], o[op..xo]);
    }
    try std.testing.expectEqualSlices(u8, src[0..op], out_a[0..op]);
}

test "copyFrom (ZSTD_copyDCtx) mid-frame with a DDict: the copy reads the same DDict's tables" {
    // A DDict's entropy tables are pointed at, not copied, for a frame
    // (`ZSTD_copyDDictParameters`), so a copy taken inside that frame
    // points at the same DDict, as libzstd's does. lit_repeat_frame's
    // literals reuse the dictionary's Huffman table (`set_repeat`).
    var dd = try zstd.DDict.init(gpa, dict_kats.full_dict, .auto);
    defer dd.deinit(gpa);
    const z = dict_kats.lit_repeat_frame;
    var a = try zstd.Decompressor.init(gpa, .{ .ddict = &dd });
    defer a.deinit();
    a.begin();
    var ip: usize = 0;
    while (a.stage != .decompress_last_block) {
        const k = a.nextSrcSizeToDecompress();
        try std.testing.expectEqual(0, try a.decompressContinue(&.{}, z[ip..][0..k]));
        ip += k;
    }
    try std.testing.expect(a.st.huf_ptr == &dd.entropy.huf and a.st.ll_ptr == &dd.entropy.ll);
    try std.testing.expect(a.st.of_ptr == &dd.entropy.of and a.st.ml_ptr == &dd.entropy.ml);
    var b = try zstd.Decompressor.init(gpa, .{});
    defer b.deinit();
    b.copyFrom(&a);
    try std.testing.expect(b.st.huf_ptr == &dd.entropy.huf and b.st.ll_ptr == &dd.entropy.ll);
    for ([_]*zstd.Decompressor{ &a, &b }) |x| {
        var out: [256]u8 = undefined;
        var xi = ip;
        var xo: usize = 0;
        while (x.nextSrcSizeToDecompress() != 0) {
            const k = x.nextSrcSizeToDecompress();
            xo += try x.decompressContinue(out[xo..], z[xi..][0..k]);
            xi += k;
        }
        try std.testing.expectEqual(z.len, xi);
        try std.testing.expectEqualStrings(dict_kats.lit_repeat_content, out[0..xo]);
    }
}

test "copyFrom (ZSTD_copyDCtx) at every block boundary: each copy goes on as its original would" {
    // 1 KB blocks, so later blocks lean on earlier ones: repeat offsets
    // carried over, Huffman and FSE tables repeated. The copies are decoded
    // only after the original has finished its frame and then decoded
    // another one (other content: every table rebuilt), so a copy sharing
    // the original's tables rather than holding its own, or missing its
    // repeat offsets or their validity, decodes wrongly or refuses.
    const other_src = try corpusInput("mix-10086");
    defer gpa.free(other_src);
    const other = try zstd.compressAlloc(gpa, other_src[0..65536], .{ .level = 3 });
    defer gpa.free(other);
    const other_out = try gpa.alloc(u8, 65536);
    defer gpa.free(other_out);
    const Copy = struct { d: zstd.Decompressor, ip: usize, op: usize };
    var copies: [48]Copy = undefined;
    for ([_][]const u8{ "words-16385", "csv-131073" }) |name| {
        const whole = try corpusInput(name);
        defer gpa.free(whole);
        const src = whole[0..@min(whole.len, 32768)];
        const out = try gpa.alloc(u8, src.len);
        defer gpa.free(out);
        const out2 = try gpa.alloc(u8, src.len);
        defer gpa.free(out2);
        for ([_]i32{ 1, 5, 19 }) |level| {
            const z = try zstd.compressAlloc(gpa, src, .{ .level = level, .checksum = true, .advanced = .{ .max_block_size = 1024 } });
            defer gpa.free(z);
            var n: usize = 0;
            defer for (copies[0..n]) |*c| c.d.deinit();
            var a = try zstd.Decompressor.init(gpa, .{});
            defer a.deinit();
            a.begin();
            var ip: usize = 0;
            var op: usize = 0;
            while (a.nextSrcSizeToDecompress() != 0) {
                if (a.stage == .decode_block_header and n < copies.len) {
                    copies[n] = .{ .d = try zstd.Decompressor.init(gpa, .{}), .ip = ip, .op = op };
                    n += 1;
                    copies[n - 1].d.copyFrom(&a);
                }
                const k = a.nextSrcSizeToDecompress();
                op += try a.decompressContinue(out[op..], z[ip..][0..k]);
                ip += k;
            }
            try std.testing.expectEqualSlices(u8, src, out[0..op]);
            try std.testing.expect(n >= 16);
            try std.testing.expectEqual(other_out.len, try a.decompress(other_out, other));
            for (copies[0..n]) |*c| {
                var xi = c.ip;
                var xo = c.op;
                while (c.d.nextSrcSizeToDecompress() != 0) {
                    const k = c.d.nextSrcSizeToDecompress();
                    xo += try c.d.decompressContinue(out2[xo..], z[xi..][0..k]);
                    xi += k;
                }
                try std.testing.expectEqual(z.len, xi);
                try std.testing.expectEqualSlices(u8, src[c.op..], out2[c.op..xo]);
            }
        }
    }
}

test "copyFrom (ZSTD_copyDCtx) keeps the frame's block bound" {
    // A damaged frame: a 1 KB window, then a 4-byte compressed block of
    // 2000 RLE literals. The literals are bounded by the frame's block size
    // (`ZSTD_decodeLiteralsBlock`: litSize > blockSizeMax is
    // corruption_detected), before the room (1500 bytes here: a decoder
    // bounding them by 128 KB would say dstSize_tooSmall), so the original
    // refuses them as corrupt -- and so must a copy taken after the header.
    const z = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x25, 0x00, 0x00, 0x05, 0x7d, 'x', 0x00 };
    var a = try zstd.Decompressor.init(gpa, .{});
    defer a.deinit();
    var b = try zstd.Decompressor.init(gpa, .{});
    defer b.deinit();
    var out: [4096]u8 = undefined;
    a.begin();
    var ip: usize = 0;
    while (a.stage != .decode_block_header) {
        const k = a.nextSrcSizeToDecompress();
        _ = try a.decompressContinue(&out, z[ip..][0..k]);
        ip += k;
    }
    b.copyFrom(&a);
    for ([_]*zstd.Decompressor{ &a, &b }) |x| {
        _ = try x.decompressContinue(&out, z[ip..][0..3]);
        try std.testing.expectError(error.CorruptionDetected, x.decompressContinue(out[0..1500], z[ip + 3 ..]));
    }
}
