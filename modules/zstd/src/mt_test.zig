// SPDX-License-Identifier: MIT
//! Multithreaded compression against libzstd 1.5.7 (Z9a).
//!
//! Every `corpus.mt_cases` entry is compressed with each worker count of
//! `corpus.mt_test_workers` (1, 2, 4, 8 real threads) -- one-shot through
//! `Compressor.compress`, or through `Stream` with a schedule -- and must
//! give the length and SHA-256 libzstd gave with `corpus.mt_golden_workers`
//! workers (`testdata/mt_goldens.zig`; the recipe checks that libzstd gives
//! the same with one). So the test pins both that the output is libzstd's
//! and that it does not depend on the worker count or on how the threads
//! are scheduled. Each is run once more with the jobs on the calling thread
//! (`run_inline`), and every output is decoded back. The one-shot frames
//! come from one reused `Compressor` and the streamed ones from one reused
//! `Stream`, whose multithreaded context is resized with the worker count.

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/mt_goldens.zig");
const param_test = @import("param_test.zig");
const stream_test = @import("stream_test.zig");
const zstdmt = @import("zstdmt.zig");

const trained_files = .{
    .{ "zd-words", @embedFile("testdata/zd-words.zdict") },
    .{ "zd-csv", @embedFile("testdata/zd-csv.zdict") },
};

fn trained(name: []const u8) []const u8 {
    inline for (trained_files) |t| if (std.mem.eql(u8, t[0], name)) return t[1];
    unreachable;
}

fn find(mc: corpus.MtCase, level: i32, checksum: bool) ?goldens.Golden {
    for (goldens.rows) |g| {
        if (g.level == level and g.checksum == checksum and std.mem.eql(u8, g.case, mc.name)) return g;
    }
    return null;
}

test "every multithreaded case has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.mt_cases) |mc| for (mc.levels) |level| for (mc.checksums) |ck| {
        n += 1;
        if (find(mc, level, ck) == null) {
            std.debug.print("no golden row for {s} level {d} checksum {}\n", .{ mc.name, level, ck });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

/// `mc` at `level` with `workers` workers, into `out` (one-shot) or a new
/// allocation (streamed; the caller frees it).
fn compressCase(gpa: std.mem.Allocator, ctx: *zstd.Compressor, strm: *zstd.Stream, mc: corpus.MtCase, level: i32, ck: bool, workers: u32, dict: []const u8, src: []const u8, out: []u8) ![]const u8 {
    const ctype: zstd.DictContentType = @enumFromInt(mc.content_type);
    var cdict: ?zstd.CDict = null;
    defer if (cdict) |*c| c.deinit();
    const d: zstd.Dictionary = if (mc.dict == null) .none else switch (mc.path) {
        .load => .{ .raw = .{ .bytes = dict, .content_type = ctype } },
        .prefix => .{ .prefix = .{ .bytes = dict, .content_type = ctype } },
        .cdict => blk: {
            cdict = try zstd.CDict.init(gpa, dict, level);
            break :blk .{ .cdict = &cdict.? };
        },
        else => return error.BadCase,
    };
    if (mc.schedule) |sch| {
        var buf: [256]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "nbWorkers={d},{s}", .{ workers, sch });
        const r = try stream_test.runOn(gpa, strm, src, level, ck, s, d);
        return r.out;
    }
    var adv = if (std.mem.eql(u8, mc.params, "-")) zstd.Advanced{} else try param_test.parse(mc.params);
    adv.nb_workers = workers;
    const n = try ctx.compress(out, src, .{ .level = level, .checksum = ck, .advanced = adv, .dictionary = d });
    return out[0..n];
}

fn decodeBack(gpa: std.mem.Allocator, mc: corpus.MtCase, dict: []const u8, frames: []const u8, src: []const u8) !void {
    // (a full dictionary as a prefix made the frame name its ID)
    var dd: ?zstd.DDict = if (mc.dict != null and !(mc.path == .prefix and mc.content_type == 1)) try zstd.DDict.init(gpa, dict, @enumFromInt(mc.content_type)) else null;
    defer if (dd) |*x| x.deinit(gpa);
    var d = try zstd.Decompressor.init(gpa, if (dd) |*x| .{ .ddict = x } else if (mc.dict != null) .{ .prefix_once = dict } else .{});
    defer d.deinit();
    const back = try gpa.alloc(u8, src.len + 1);
    defer gpa.free(back);
    const n = try d.decompress(back, frames);
    if (!std.mem.eql(u8, back[0..n], src)) return error.DecodedOtherBytes;
}

test "multithreaded output is libzstd's for every worker count, and decodes back" {
    // Under qemu-mips this test's pool and buffer churn trips qemu's own
    // page_find_range_empty assertion (SPEC.md, *Portability*); its two
    // axes run in full elsewhere: 32-bit on i386 and ARM, big-endian on
    // s390x.
    if (@import("builtin").cpu.arch.isMIPS32()) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var ctx: zstd.Compressor = .init(gpa);
    defer ctx.deinit();
    var strm = try zstd.Stream.init(gpa, .{});
    defer strm.deinit();
    var inl: zstd.Compressor = .init(gpa);
    defer inl.deinit();
    inl.mt_run_inline = true;
    var inl_strm = try zstd.Stream.init(gpa, .{});
    defer inl_strm.deinit();
    inl_strm.mt_run_inline = true;
    var mismatches: usize = 0;
    var runs: usize = 0;
    for (corpus.mt_cases) |mc| {
        const src = try gpa.alloc(u8, mc.input.len);
        defer gpa.free(src);
        corpus.generate(mc.input, src);
        const dict_buf = try gpa.alloc(u8, if (mc.dict) |name| corpus.dictLen(corpus.findDict(name), &trained) else 0);
        defer gpa.free(dict_buf);
        const dict = if (mc.dict) |name| dict_buf[0..corpus.buildDict(corpus.findDict(name), &trained, dict_buf)] else dict_buf;
        const out = try gpa.alloc(u8, zstd.compressBound(src.len));
        defer gpa.free(out);
        for (mc.levels) |level| for (mc.checksums) |ck| {
            const g = find(mc, level, ck).?;
            for (corpus.mt_test_workers ++ [_]u32{0}) |w| {
                // 0: the jobs on the calling thread, with 3 workers' layout
                const inline_run = w == 0;
                const workers: u32 = if (inline_run) 3 else w;
                const c = if (inline_run) &inl else &ctx;
                const s = if (inline_run) &inl_strm else &strm;
                const z = try compressCase(gpa, c, s, mc, level, ck, workers, dict, src, out);
                defer if (mc.schedule != null) gpa.free(z);
                runs += 1;
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(z, &digest, .{});
                if (z.len != g.len or !std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), g.sha256)) {
                    std.debug.print("MISMATCH {s} level {d} checksum {} workers {d}{s}: {d} bytes, libzstd {d}\n", .{ mc.name, level, ck, workers, if (inline_run) " (inline)" else "", z.len, g.len });
                    mismatches += 1;
                    continue;
                }
                if (w == 1) decodeBack(gpa, mc, dict, z, src) catch |e| {
                    std.debug.print("{s} level {d}: decoding back: {t}\n", .{ mc.name, level, e });
                    return e;
                };
            }
        };
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
    try std.testing.expectEqual(goldens.rows.len * (corpus.mt_test_workers.len + 1), runs);
}

test "rsyncable holds for its frame only" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 3_000_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .mix, .seed = 41 }, src);
    const out = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(out);
    const fresh = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(fresh);
    const adv: zstd.Advanced = .{ .nb_workers = 2, .job_size = 524288 };
    var rs = adv;
    rs.rsyncable = true;
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var f: zstd.Compressor = .init(gpa);
    defer f.deinit();
    const n_rs = try c.compress(out, src, .{ .level = 1, .advanced = rs });
    const n_plain = try f.compress(fresh, src, .{ .level = 1, .advanced = adv });
    // (the input has synchronization points of its own)
    try std.testing.expect(!std.mem.eql(u8, out[0..n_rs], fresh[0..n_plain]));
    const n = try c.compress(out, src, .{ .level = 1, .advanced = adv });
    try std.testing.expectEqualSlices(u8, fresh[0..n_plain], out[0..n]);
}

test "the jobs are threads: one frame is cut into several, posted to the pool" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 1_400_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .far_repeat }, src);
    var s = try zstd.Stream.init(gpa, .{ .level = 1, .advanced = .{ .nb_workers = 4, .job_size = 1 } });
    defer s.deinit();
    const out = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
    defer gpa.free(out);
    var o: zstd.OutBuffer = .{ .dst = out };
    var in: zstd.InBuffer = .{ .src = src };
    while (try s.compressStream2(&o, &in, .end) != 0) {}
    const mt = s.mt.?;
    // 512 KB jobs (a job size under the minimum counts as the minimum)
    try std.testing.expectEqual(zstdmt.job_size_min, mt.target_section_size);
    try std.testing.expectEqual(@as(usize, 4), mt.pool.threads.len);
    try std.testing.expectEqual(@as(u32, 3), mt.pool.posted.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 3), mt.pool.finished.load(.monotonic));
    try std.testing.expect(mt.all_jobs_completed);
    // the next frame starts clean on the same threads
    in = .{ .src = src[0..700_000] };
    o.pos = 0;
    while (try s.compressStream2(&o, &in, .end) != 0) {}
    try std.testing.expectEqual(@as(u32, 5), mt.pool.posted.load(.monotonic));
    const back = try zstd.decompressAlloc(gpa, o.dst[0..o.pos], 700_000);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, src[0..700_000], back);
}

test "up to 512 KB (pledged or ending in the first call) stays on the calling thread" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, zstdmt.job_size_min);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 3 }, src);
    const a = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(a);
    const b = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(b);
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const na = try c.compress(a, src, .{ .level = 3, .advanced = .{ .nb_workers = 2 } });
    try std.testing.expect(c.mt == null);
    const nb = try c.compress(b, src, .{ .level = 3 });
    try std.testing.expectEqualSlices(u8, b[0..nb], a[0..na]);
}

test "the pledged size is enforced across jobs" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 1_200_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 4 }, src);
    const out = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(out);
    for ([_]u64{ 1_000_000, 1_300_000 }) |pledged| {
        var s = try zstd.Stream.init(gpa, .{ .level = 1, .pledged_size = pledged, .advanced = .{ .nb_workers = 2, .job_size = 1 } });
        defer s.deinit();
        var o: zstd.OutBuffer = .{ .dst = out };
        var in: zstd.InBuffer = .{ .src = src };
        // (an end in the first call would pledge its input instead)
        const r = while (true) {
            const op: zstd.EndDirective = if (in.pos < in.src.len) .@"continue" else .end;
            const left = s.compressStream2(&o, &in, op) catch |e| break e;
            if (op == .end and left == 0) break error.NoError;
        };
        try std.testing.expectEqual(error.SrcSizeWrong, r);
    }
}

test "continue while ending a frame is refused; reset abandons it" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 1_200_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .csv, .seed = 5 }, src);
    var s = try zstd.Stream.init(gpa, .{ .level = 3, .advanced = .{ .nb_workers = 2, .job_size = 1 } });
    defer s.deinit();
    var small: [16]u8 = undefined;
    var o: zstd.OutBuffer = .{ .dst = &small };
    var in: zstd.InBuffer = .{ .src = src };
    // (the first call pledges the whole input: MT, frame ended in a job)
    while (in.pos < in.src.len) _ = try s.compressStream2(&o, &in, .end);
    o.pos = 0;
    var none: zstd.InBuffer = .{ .src = &.{} };
    try std.testing.expectError(error.StageWrong, s.compressStream2(&o, &none, .@"continue"));
    try s.reset(.{ .level = 3 });
    // a single-threaded frame on the same stream afterwards
    const out = try gpa.alloc(u8, zstd.compressBound(1000) + 64);
    defer gpa.free(out);
    var o2: zstd.OutBuffer = .{ .dst = out };
    var in2: zstd.InBuffer = .{ .src = src[0..1000] };
    try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o2, &in2, .end));
    const back = try zstd.decompressAlloc(gpa, o2.dst[0..o2.pos], 1000);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, src[0..1000], back);
}

test "worker count and job parameters are bounded as libzstd bounds them" {
    var buf: [64]u8 = undefined;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.ParameterOutOfBound, zstd.compress(gpa, &buf, "x", .{ .advanced = .{ .nb_workers = 257 } }));
    try std.testing.expectError(error.ParameterOutOfBound, zstd.compress(gpa, &buf, "x", .{ .advanced = .{ .overlap_log = 10 } }));
    try std.testing.expectError(error.ParameterOutOfBound, zstd.compress(gpa, &buf, "x", .{ .advanced = .{ .job_size = (1 << 30) + 1 } }));
}

test "a prefix serves one multithreaded frame only" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 700_000);
    defer gpa.free(src);
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 6 }, src);
    const out = try gpa.alloc(u8, 2 * zstd.compressBound(src.len));
    defer gpa.free(out);
    const adv: zstd.Advanced = .{ .nb_workers = 2, .job_size = 1 };
    var s = try zstd.Stream.init(gpa, .{ .level = 3, .advanced = adv, .dictionary = .{ .prefix = .{ .bytes = src[0..20000], .content_type = .raw_content } } });
    defer s.deinit();
    var plain = try zstd.Stream.init(gpa, .{ .level = 3, .advanced = adv });
    defer plain.deinit();
    var frames: [3][]const u8 = undefined;
    var at: usize = 0;
    for ([_]*zstd.Stream{ &s, &s, &plain }, &frames) |st, *f| {
        var o: zstd.OutBuffer = .{ .dst = out[at..] };
        var in: zstd.InBuffer = .{ .src = src };
        while (try st.compressStream2(&o, &in, .end) != 0) {}
        f.* = o.dst[0..o.pos];
        at += o.pos;
    }
    try std.testing.expect(!std.mem.eql(u8, frames[0], frames[1]));
    try std.testing.expectEqualSlices(u8, frames[2], frames[1]);
}
