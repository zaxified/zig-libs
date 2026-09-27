// SPDX-License-Identifier: MIT
//! Fuzz: compress arbitrary bytes (one-shot, and streamed), decode them with
//! std and with this module's decoder, demand the input back; and feed the
//! decoder arbitrary bytes, which must never crash it.
//!
//! The compressor's input is caller data, so every byte pattern must yield a
//! valid frame without a panic. The oracle is std's independent decoder: a
//! frame it rejects or decodes to anything else is a finding. (Byte-equality
//! with libzstd is the golden test's job; a fuzz target has no reference to
//! call.)
//!
//! One byte-first draw, then nothing: the level and checksum setting are
//! derived from the input length, so a seed's bytes arrive intact and the
//! corpus below is what the ordinary lane actually runs (see the brotli
//! harness for what a draw before the bytes cost that module).
//!
//! The decoder has three more targets after libzstd's `tests/fuzz/`
//! (`stream_decompress`, `dictionary_decompress`, `dictionary_loader`), in
//! which the first input byte picks the setup (a dictionary, the magicless
//! format, the buffer schedule) and the rest is the frame: arbitrary bytes
//! through `DecompressStream`, through the one-shot decoder with a
//! dictionary, and through `DDict.init` itself. Their seeds are the frames
//! libzstd wrote with `testdata/dict_kats.zig`'s dictionaries, so a mutation
//! starts deep in the entropy and sequence decoding.

const std = @import("std");
const zstd = @import("root.zig");
const kats = @import("testdata/dict_kats.zig");
const fuzzSeed = @import("testkit").fuzz.seed;

const fuzz_buf_len = 1 << 16;
const levels = [_]i32{ -3, 1, 2, 3, -1, 4, 5, 6, 7, 8, 10, 12, 14, 17, 19, 21 };

fn roundTrip(input: []const u8) !void {
    const gpa = std.testing.allocator;
    const level = levels[input.len % levels.len];
    const checksum = input.len & 8 != 0;
    const z = try zstd.compressAlloc(gpa, input, .{ .level = level, .checksum = checksum });
    defer gpa.free(z);
    if (z.len > zstd.compressBound(input.len)) return error.ExceededBound;

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(z);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualSlices(u8, input, out.written());

    try decodeBack(z, input);
}

/// The module's own decoder must agree with std's on the same frame.
fn decodeBack(z: []const u8, input: []const u8) !void {
    const gpa = std.testing.allocator;
    const back = try zstd.decompressAlloc(gpa, z, input.len);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, input, back);
}

/// The same through a `Stream` with a 1 KB window, so the input buffer
/// (window + block) wraps within the harness's 64 KB and the extDict match
/// finders run. The schedule is fixed by the length, like the level: chunks
/// of 1, 7, 1000 and 3000 bytes, every third followed by a flush, into a
/// 64-byte output buffer.
fn streamRoundTrip(input: []const u8) !void {
    const gpa = std.testing.allocator;
    const stream_levels = [_]i32{ -3, 1, 2, 3, 5, 6, 8, 10 };
    var s = try zstd.Stream.init(gpa, .{
        .level = stream_levels[input.len % stream_levels.len],
        .checksum = input.len & 8 != 0,
        .advanced = .{ .window_log = 10 },
    });
    defer s.deinit();
    var z: std.ArrayList(u8) = .empty;
    defer z.deinit(gpa);
    var obuf: [64]u8 = undefined;
    const chunks = [_]usize{ 1, 7, 1000, 3000 };
    var fed: usize = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        const n = @min(chunks[i % chunks.len], input.len - fed);
        const dir: zstd.EndDirective = if (fed + n == input.len) .end else if (i % 3 == 2) .flush else .@"continue";
        var in: zstd.InBuffer = .{ .src = input[fed..][0..n] };
        while (true) {
            var o: zstd.OutBuffer = .{ .dst = &obuf };
            const left = try s.compressStream2(&o, &in, dir);
            try z.appendSlice(gpa, obuf[0..o.pos]);
            if (if (dir == .@"continue") in.pos == in.src.len else left == 0) break;
        }
        fed += n;
        if (dir == .end) break;
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var in: std.Io.Reader = .fixed(z.items);
    var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{ .verify_checksum = false });
    _ = try d.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualSlices(u8, input, out.written());

    try decodeBack(z.items, input);
}

/// Decode arbitrary bytes: any result or error, never a panic, never a
/// write outside the destination (the safe lanes check every index).
fn decodeAnything(input: []const u8) void {
    var d = zstd.Decompressor.init(std.testing.allocator, .{}) catch return;
    defer d.deinit();
    var out: [1 << 17]u8 = undefined;
    _ = d.decompress(&out, input) catch {};
    _ = zstd.decompressBound(input) catch {};
    _ = zstd.findDecompressedSize(input) catch {};
}

/// The setup byte of the decoder targets below: bits 0-1 the dictionary
/// (none; `kats.full_dict`; `kats.raw_dict` as raw content; one from the
/// input itself, its 2-byte length first), bit 2 the magicless format,
/// bits 3-5 the stream's buffer schedule.
const Setup = struct {
    dict: enum { none, full, raw, inline_ } = .none,
    magicless: bool = false,
    schedule: u3 = 0,
    frame: []const u8,
    dict_bytes: ?[]const u8 = null,

    fn parse(input: []const u8) ?Setup {
        if (input.len == 0) return null;
        const b = input[0];
        var su: Setup = .{
            .dict = @enumFromInt(b & 3),
            .magicless = b & 4 != 0,
            .schedule = @truncate(b >> 3),
            .frame = input[1..],
        };
        switch (su.dict) {
            .none => {},
            .full => su.dict_bytes = kats.full_dict,
            .raw => su.dict_bytes = kats.raw_dict,
            .inline_ => {
                if (su.frame.len < 2) return null;
                const n = @min(std.mem.readInt(u16, su.frame[0..2], .little), su.frame.len - 2);
                su.dict_bytes = su.frame[2..][0..n];
                su.frame = su.frame[2 + n ..];
            },
        }
        return su;
    }

    fn format(su: Setup) zstd.Format {
        return if (su.magicless) .magicless else .zstd1;
    }

    fn contentType(su: Setup) zstd.DictContentType {
        return switch (su.dict) {
            .raw => .raw_content,
            .full => .full,
            else => .auto,
        };
    }
};

/// `dictionary_loader`: arbitrary bytes as a dictionary of each content
/// type, digested and by reference -- a result or an error, never a panic.
fn loadAnyDictionary(bytes: []const u8) void {
    const gpa = std.testing.allocator;
    for ([_]zstd.DictContentType{ .auto, .raw_content, .full }) |ct| {
        if (zstd.DDict.init(gpa, bytes, ct)) |dd| {
            var d = dd;
            _ = d.dictId();
            d.deinit(gpa);
        } else |_| {}
        _ = zstd.DDict.initByReference(bytes, ct) catch {};
    }
    _ = zstd.getDictId(bytes);
}

/// `dictionary_decompress`: the frame one-shot with the setup's dictionary,
/// as raw bytes (`dictionary`) and digested (`ddict`), and as a prefix.
fn decodeWithDictionary(input: []const u8) void {
    const gpa = std.testing.allocator;
    const su = Setup.parse(input) orelse return;
    var out: [1 << 17]u8 = undefined;
    if (su.dict == .inline_) loadAnyDictionary(su.dict_bytes.?);
    {
        var d = zstd.Decompressor.init(gpa, .{ .format = su.format(), .dictionary = su.dict_bytes }) catch return;
        defer d.deinit();
        _ = d.decompress(&out, su.frame) catch {};
    }
    const bytes = su.dict_bytes orelse return;
    if (zstd.DDict.init(gpa, bytes, su.contentType())) |dd| {
        var ddict = dd;
        defer ddict.deinit(gpa);
        var d = zstd.Decompressor.init(gpa, .{ .format = su.format(), .ddict = &ddict }) catch return;
        defer d.deinit();
        _ = d.decompress(&out, su.frame) catch {};
    } else |_| {}
    {
        var d = zstd.Decompressor.init(gpa, .{ .format = su.format(), .prefix_once = bytes }) catch return;
        defer d.deinit();
        _ = d.decompress(&out, su.frame) catch {};
    }
}

/// `stream_decompress`: the frame through `DecompressStream` with the
/// setup's dictionary (a `DDict`, or the raw bytes as a prefix), fed and
/// drained by the schedule: input chunks of 1, 13, 4096 bytes or all at
/// once, output through 7, 997 or 16 384 bytes, or one stable 128 KB buffer
/// whose `pos` only grows. A 1 MB window cap (`window_log_max` 20) keeps a
/// header from asking for 128 MB; the whole output is capped at 1 MB.
fn decodeStreamAnything(input: []const u8) void {
    const gpa = std.testing.allocator;
    const su = Setup.parse(input) orelse return;
    const in_chunk = ([_]usize{ 1, 13, 4096, std.math.maxInt(usize) })[su.schedule & 3];
    const stable = su.schedule & 4 != 0;
    const out_len: usize = if (stable) 1 << 17 else ([_]usize{ 7, 997, 1 << 14, 997 })[su.schedule & 3];

    var ddict: ?zstd.DDict = null;
    defer if (ddict) |*dd| dd.deinit(gpa);
    if (su.dict_bytes) |bytes| {
        if (su.dict != .raw) ddict = zstd.DDict.init(gpa, bytes, su.contentType()) catch null;
    }
    var s = zstd.DecompressStream.init(gpa, .{
        .format = su.format(),
        .window_log_max = 20,
        .stable_output = stable,
        .ddict = if (ddict) |*dd| dd else null,
        .prefix = if (su.dict == .raw) su.dict_bytes else null,
    }) catch return;
    defer s.deinit();

    var obuf: [1 << 17]u8 = undefined;
    var stable_out: zstd.OutBuffer = .{ .dst = &obuf };
    var fed: usize = 0;
    var total: usize = 0;
    while (total < 1 << 20) {
        const end = fed + @min(in_chunk, su.frame.len - fed);
        var in: zstd.InBuffer = .{ .src = su.frame[0..end], .pos = fed };
        var ob: zstd.OutBuffer = .{ .dst = obuf[0..out_len] };
        const o = if (stable) &stable_out else &ob;
        const before = o.pos;
        const hint = s.decompressStream(o, &in) catch return;
        const made = o.pos - before;
        total += made;
        const ate = in.pos - fed;
        fed = in.pos;
        if (stable and o.pos == o.dst.len) return;
        if (hint == 0 and fed == su.frame.len) return;
        if (made == 0 and ate == 0 and fed == su.frame.len) return;
    }
}

fn fuzzDecodeStream(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    decodeStreamAnything(buf[0..len]);
}

fn fuzzDecodeDictionary(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    decodeWithDictionary(buf[0..len]);
}

/// A seekable stream from arbitrary bytes (`seekable.Seekable`): the table
/// loaded, then ranges read -- the whole, a middle range, one frame, and a
/// read continuing the last -- any result or error, never a panic or a
/// hang. The ranges come from the input's length, so a seed arrives intact.
fn seekableAnything(input: []const u8) void {
    const gpa = std.testing.allocator;
    var r = zstd.seekable.Seekable.init(gpa, .{ .bytes = input }) catch return;
    defer r.deinit();
    var out: [1 << 16]u8 = undefined;
    const size = r.table.decompressedSize();
    const mid = size / 3;
    _ = r.decompress(&out, 0) catch {};
    _ = r.decompress(out[0..@min(out.len, 1000)], mid) catch {};
    _ = r.decompress(out[0..@min(out.len, 700)], mid + 1000) catch {};
    if (r.numFrames() > 0) _ = r.decompressFrame(&out, (@as(u32, @truncate(input.len)) % r.numFrames())) catch {};
}

fn fuzzSeekable(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    seekableAnything(buf[0..len]);
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    decodeAnything(buf[0..len]);
}

fn fuzzStream(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    try streamRoundTrip(buf[0..len]);
}

fn fuzzCompress(_: void, smith: *std.testing.Smith) !void {
    var buf: [fuzz_buf_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    try roundTrip(buf[0..len]);
}

const seed_words = "the frame of the block of the window, the match of the literal; " ** 40;
const seed_runs = ("a" ** 300) ++ ("b" ** 300) ++ ("a" ** 300);
const seed_noise = blk: {
    @setEvalBranchQuota(10_000);
    var b: [4096]u8 = undefined;
    var x: u32 = 0x12345678;
    for (&b) |*v| {
        x = x *% 1103515245 +% 12345;
        v.* = @truncate(x >> 16);
    }
    break :blk b;
};

const fuzz_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    fuzzSeed("x"),
    fuzzSeed("seven!!"), // the smallest block the matcher sees
    fuzzSeed(seed_words),
    fuzzSeed(seed_runs),
    fuzzSeed(&seed_noise),
    fuzzSeed(seed_words ++ seed_noise ++ seed_words),
    // over 16 KB: the lazy levels switch from the hash chain to the row finder
    // (17 927 bytes -> levels[7], level 6)
    fuzzSeed(seed_words ** 7 ++ "abcdefg"),
};

/// Decoder seeds: hand-built frames (empty; raw block; RLE block;
/// skippable frame followed by a frame; checksummed), so mutations start
/// from something the decoder parses deep into.
const decode_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    fuzzSeed(&.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }),
    fuzzSeed(&.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o' }),
    fuzzSeed(&.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x40, 0x03, 0x02, 0x00, 'z' }),
    fuzzSeed(&.{ 0x50, 0x2a, 0x4d, 0x18, 0x02, 0x00, 0x00, 0x00, 'h', 'i', 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }),
    fuzzSeed(&seed_noise),
};

/// Decoder-target seeds: a setup byte, then a frame libzstd wrote (with and
/// without its magic number), or a dictionary carried inline.
fn setupSeed(comptime setup: u8, comptime frame: []const u8) []const u8 {
    return fuzzSeed(&[_]u8{setup} ++ frame[0..frame.len].*);
}
fn inlineSeed(comptime setup: u8, comptime dict: []const u8, comptime frame: []const u8) []const u8 {
    return fuzzSeed(&[_]u8{ setup | 3, @truncate(dict.len), @truncate(dict.len >> 8) } ++ dict[0..dict.len].* ++ frame[0..frame.len].*);
}
/// `full_dict` with its repeat offsets 50/60/70, and a frame opening on
/// them (`decoder_dict_test.zig`, `tools/crafted-frames.py` `dict_reps`).
const dict_reps = kats.full_dict[0..97].* ++ [_]u8{ 50, 0, 0, 0, 60, 0, 0, 0, 70, 0, 0, 0 } ++ kats.full_dict[109..].*;
const frame_reps = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x83, 0x38, 0xca, 0x6d, 0xe4, 0x27, 0x0c, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x75, 0xbb, 0xc7, 0x03, 0x54, 0x01, 0x01, 0x00, 0x0b };

const decode_dict_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    setupSeed(0, &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o' }),
    setupSeed(1, kats.frame_full_l3),
    setupSeed(1, kats.frame_full_l19),
    setupSeed(1, kats.lit_repeat_frame),
    setupSeed(1 | 4, kats.frame_full_l19[4..]),
    setupSeed(2, kats.frame_raw_l5),
    setupSeed(2 | 4, kats.frame_raw_l5[4..]),
    inlineSeed(0, kats.small_raw_a, kats.small_frame),
    inlineSeed(0, kats.full_dict2, kats.frame2_full_l3),
    inlineSeed(0, &dict_reps, &frame_reps),
};

const decode_stream_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    setupSeed(0 << 3, &.{ 0x50, 0x2a, 0x4d, 0x18, 0x02, 0x00, 0x00, 0x00, 'h', 'i', 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00 }),
    setupSeed(1 | 0 << 3, kats.frame_full_l19),
    setupSeed(1 | 1 << 3, kats.frame_full_l3),
    setupSeed(1 | 2 << 3, kats.lit_repeat_frame),
    setupSeed(1 | 4 | 3 << 3, kats.frame_full_l19[4..]),
    setupSeed(1 | 4 << 3, kats.concat_full_l3_then_frame2),
    setupSeed(2 | 5 << 3, kats.frame_raw_l5),
    setupSeed(2 | 4 | 6 << 3, kats.frame_raw_l5[4..]),
    inlineSeed(7 << 3, kats.full_dict2, kats.frame2_full_l3),
    inlineSeed(1 << 3, &dict_reps, &frame_reps),
};

/// Seekable seeds: libzstd's own seekable streams (tools/zseekable.c), so a
/// mutation starts from a valid table.
const seekable_seed_corpus = [_][]const u8{
    fuzzSeed(""),
    fuzzSeed(&seekable_empty),
    fuzzSeed(&seekable_two),
};
/// "" with frame checksums (`zseekable c 3 1 0 ... e`).
const seekable_empty = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00, 0x5e, 0x2a, 0x4d, 0x18, 0x15, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51, 0x01, 0x00, 0x00, 0x00, 0x80, 0xb1, 0xea, 0x92, 0x8f };
/// "abcdef" in frames of 3 bytes, checksums on (`zseekable c 3 1 3 ... c*,e`).
const seekable_two = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x19, 0x00, 0x00, 0x61, 0x62, 0x63, 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x19, 0x00, 0x00, 0x64, 0x65, 0x66, 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00, 0x5e, 0x2a, 0x4d, 0x18, 0x2d, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x99, 0x09, 0x77, 0xad, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xa8, 0xd5, 0x53, 0xdb, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51, 0x03, 0x00, 0x00, 0x00, 0x80, 0xb1, 0xea, 0x92, 0x8f };

test "seekable fuzz seeds arrive intact and read as libzstd wrote them" {
    for (seekable_seed_corpus[1..]) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        try std.testing.expectEqual(sd.len - 4, len);
        var r = try zstd.seekable.Seekable.init(std.testing.allocator, .{ .bytes = buf[0..len] });
        defer r.deinit();
        var out: [16]u8 = undefined;
        const n = try r.decompress(&out, 0);
        try std.testing.expectEqualStrings(if (len == seekable_two.len) "abcdef" else "", out[0..n]);
        seekableAnything(buf[0..len]);
    }
}

test "fuzz: arbitrary bytes never crash the seekable reader" {
    try std.testing.fuzz({}, fuzzSeekable, .{ .corpus = &seekable_seed_corpus });
}

test "fuzz: arbitrary bytes never crash the stream decoder (with a dictionary, magicless)" {
    try std.testing.fuzz({}, fuzzDecodeStream, .{ .corpus = &decode_stream_seed_corpus });
}

test "fuzz: arbitrary frames and dictionaries never crash dictionary decoding" {
    try std.testing.fuzz({}, fuzzDecodeDictionary, .{ .corpus = &decode_dict_seed_corpus });
}

test "decoder fuzz seeds decode as libzstd wrote them" {
    // The seeds must reach the decoder intact and set it up as meant: each
    // frame decodes through the setup its byte names (none fails for
    // lack of the dictionary, which is not a seed here).
    const gpa = std.testing.allocator;
    const Want = struct { seed: []const u8, content: []const u8 };
    const wants = [_]Want{
        .{ .seed = decode_dict_seed_corpus[2], .content = kats.in1_content },
        .{ .seed = decode_dict_seed_corpus[5], .content = kats.in1_content },
        .{ .seed = decode_dict_seed_corpus[8], .content = kats.small_in_content },
        .{ .seed = decode_dict_seed_corpus[9], .content = kats.in2b_content },
        .{ .seed = decode_stream_seed_corpus[5], .content = kats.in1_content },
        .{ .seed = decode_stream_seed_corpus[9], .content = kats.in2b_content },
    };
    for (wants) |w| {
        var smith: std.testing.Smith = .{ .in = w.seed };
        var buf: [fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        try std.testing.expectEqual(w.seed.len - 4, len);
        const su = Setup.parse(buf[0..len]).?;
        var ddict = try zstd.DDict.init(gpa, su.dict_bytes.?, su.contentType());
        defer ddict.deinit(gpa);
        var d = try zstd.Decompressor.init(gpa, .{ .format = su.format(), .ddict = &ddict });
        defer d.deinit();
        var out: [1024]u8 = undefined;
        const n = try d.decompress(&out, su.frame);
        try std.testing.expectEqualStrings(w.content, out[0..n]);
    }
    for (decode_dict_seed_corpus) |sd| decodeWithDictionary(sd[4..]);
    for (decode_stream_seed_corpus) |sd| decodeStreamAnything(sd[4..]);
}

test "fuzz: every input round-trips through std's decoder" {
    try std.testing.fuzz({}, fuzzCompress, .{ .corpus = &fuzz_seed_corpus });
}

test "fuzz: arbitrary bytes never crash the decoder" {
    try std.testing.fuzz({}, fuzzDecode, .{ .corpus = &decode_seed_corpus });
}

test "fuzz: every input streamed round-trips through std's decoder" {
    try std.testing.fuzz({}, fuzzStream, .{ .corpus = &fuzz_seed_corpus });
}

test "fuzz corpus reaches the compressor intact" {
    // Draws exactly as the harness does: a seed must come back as its own
    // bytes, or the ordinary lane is not running what the corpus says.
    var nonempty: usize = 0;
    for (fuzz_seed_corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        try std.testing.expectEqual(sd.len - 4, len);
        try roundTrip(buf[0..len]);
        try streamRoundTrip(buf[0..len]);
    }
    try std.testing.expectEqual(fuzz_seed_corpus.len - 1, nonempty);
}
