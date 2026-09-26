// SPDX-License-Identifier: MIT
//! The sequence-level API against libzstd 1.5.7.
//!
//! Every `corpus.seq_cases` entry runs here as `tools/zseq.c` runs it in
//! libzstd -- `generateSequences`, `mergeBlockDelimiters`,
//! `compressSequences`, `compressSequencesAndLiterals`, or compression
//! with the example sequence producer below registered, one-shot or
//! streamed -- and must give the length and SHA-256 libzstd gave, or its
//! error (`testdata/seq_goldens.zig`, from `tools/gen-goldens.sh`). The
//! sequences are `testdata/seqgen.zig`'s, on both sides. All the calls go
//! through ONE reused context. Frames made from valid sequences are decoded
//! back; generated sequences must rebuild their input.

const std = @import("std");
const zstd = @import("root.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/seq_goldens.zig");
const seqgen = corpus.seqgen;
const param_test = @import("param_test.zig");

/// The example producer, identical to `produce` in `tools/zseq.c`: greedy
/// matching within the block over a 4096-entry hash of 4 bytes, and the
/// mode bits that make it fail or misbehave (see there).
pub const ExampleProducer = struct {
    mode: u32,
    calls: u32 = 0,
    table: [4096]u32 = undefined,

    pub fn producer(p: *ExampleProducer) zstd.SequenceProducer {
        return .{ .context = p, .produce = produce };
    }

    fn produce(ctx: ?*anyopaque, out: []zstd.Sequence, src: []const u8, dict: []const u8, level: i32, window_size: usize) zstd.SequenceProducer.ProduceError!usize {
        _ = dict;
        _ = level;
        _ = window_size;
        const p: *ExampleProducer = @ptrCast(@alignCast(ctx.?));
        const period = p.mode & 15;
        p.calls +%= 1;
        if (period != 0 and p.calls % period == 0) return error.SequenceProducerFailed;
        if (p.mode & 32 != 0) return 0;
        if (p.mode & 64 != 0) return out.len + 1;
        @memset(&p.table, 0xFFFFFFFF);
        const mm: usize = if (p.mode & 256 != 0) 3 else 4;
        const n = src.len;
        var i: usize = 0;
        var anchor: usize = 0;
        var ns: usize = 0;
        while (i + 4 <= n) {
            const h = (std.mem.readInt(u32, src[i..][0..4], .little) *% 2654435761) >> 20;
            const cand = p.table[h];
            p.table[h] = @intCast(i);
            if (cand != 0xFFFFFFFF) {
                var len: usize = 0;
                while (i + len < n and src[cand + len] == src[i + len]) len += 1;
                if (p.mode & 2048 != 0) len = @min(len, 3);
                if (len >= mm) {
                    out[ns] = .{ .offset = @intCast(i - cand), .lit_length = @intCast(i - anchor), .match_length = @intCast(len) };
                    if (ns == 0 and p.mode & 1024 != 0) out[ns].offset += 1 << 20;
                    ns += 1;
                    i += len;
                    anchor = i;
                    continue;
                }
            }
            i += 1;
        }
        if (p.mode & 16 == 0) {
            var ll: u32 = @intCast(n - anchor);
            if (p.mode & 128 != 0) ll += 1;
            if (p.mode & 512 != 0 and ll != 0) ll -= 1;
            out[ns] = .{ .offset = 0, .lit_length = ll, .match_length = 0 };
            ns += 1;
        }
        return ns;
    }
};

/// The trained dictionaries of `testdata/`.
fn trained(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "zd-words")) return @embedFile("testdata/zd-words.zdict");
    if (std.mem.eql(u8, name, "zd-csv")) return @embedFile("testdata/zd-csv.zdict");
    std.debug.panic("no trained dictionary {s}", .{name});
}

/// libzstd's error names (`ZSTD_getErrorName`) for this module's errors.
fn libzstdName(e: anyerror) []const u8 {
    return switch (e) {
        error.ExternalSequencesInvalid => "External sequences are not valid",
        error.SequenceProducerFailed => "Block-level external sequence producer returned an error code",
        error.DstSizeTooSmall => "Destination buffer is too small",
        error.ParameterUnsupported => "Unsupported parameter",
        error.FrameParameterUnsupported => "Unsupported frame parameter",
        error.CannotProduceUncompressedBlock => "This mode cannot generate an uncompressed block",
        error.ParameterCombinationUnsupported => "Unsupported combination of parameters",
        error.Generic => "Error (generic)",
        else => @errorName(e),
    };
}

fn findCase(name: []const u8) corpus.Case {
    for (corpus.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    std.debug.panic("no corpus case {s}", .{name});
}

fn find(sc: corpus.SeqCase, level: i32) ?goldens.Golden {
    for (goldens.rows) |g| if (g.level == level and std.mem.eql(u8, g.case, sc.name)) return g;
    return null;
}

fn parse(list: []const u8) !zstd.Advanced {
    if (std.mem.eql(u8, list, "-")) return .{};
    var adv: zstd.Advanced = .{};
    var hint: ?u32 = null;
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |tok| if (!try param_test.applyParam(&adv, &hint, tok)) return error.BadParam;
    return adv;
}

fn sequenceBytes(gpa: std.mem.Allocator, s: []const zstd.Sequence) ![]u8 {
    const b = try gpa.alloc(u8, 16 * s.len);
    for (s, 0..) |q, i| {
        std.mem.writeInt(u32, b[16 * i ..][0..4], q.offset, .little);
        std.mem.writeInt(u32, b[16 * i + 4 ..][0..4], q.lit_length, .little);
        std.mem.writeInt(u32, b[16 * i + 8 ..][0..4], q.match_length, .little);
        std.mem.writeInt(u32, b[16 * i + 12 ..][0..4], q.rep, .little);
    }
    return b;
}

/// What a sequence case gives: the output (owned), or an error.
const Outcome = union(enum) { bytes: []u8, err: anyerror };

/// Runs `sc` at `level` as zseq does. `dict_buf` holds the dictionary's
/// bytes while the call runs.
fn runCase(gpa: std.mem.Allocator, comp: *zstd.Compressor, sc: corpus.SeqCase, level: i32, src: []const u8, seqs: []zstd.Sequence) !Outcome {
    var opts: zstd.Options = .{ .level = level, .checksum = sc.checksum, .advanced = try parse(sc.params) };
    var dict_buf: []u8 = &.{};
    defer gpa.free(dict_buf);
    var cdict: ?zstd.CDict = null;
    defer if (cdict) |*c| c.deinit();
    if (sc.dict) |d| {
        const bytes = if (d.trained) |tn| trained(tn) else blk: {
            dict_buf = try gpa.alloc(u8, findCase(d.input).len);
            corpus.generate(findCase(d.input), dict_buf);
            break :blk dict_buf[0..d.len];
        };
        const ct = std.enums.fromInt(zstd.DictContentType, d.content_type).?;
        if (std.mem.eql(u8, d.mode, "load")) {
            opts.dictionary = .{ .raw = .{ .bytes = bytes, .content_type = ct } };
        } else if (std.mem.eql(u8, d.mode, "cdict")) {
            // ZSTD_createCDict: content type auto
            cdict = try zstd.CDict.init(gpa, bytes, level);
            opts.dictionary = .{ .cdict = &cdict.? };
        } else {
            opts.dictionary = .{ .prefix = .{ .bytes = bytes, .content_type = ct } };
        }
    }
    if (std.mem.eql(u8, sc.cmd, "gen")) {
        const cap = if (sc.capacity != 0) sc.capacity else zstd.sequenceBound(src.len);
        const out = try gpa.alloc(zstd.Sequence, cap);
        defer gpa.free(out);
        @memset(out, .{ .offset = 0, .lit_length = 0, .match_length = 0, .rep = 0 });
        const n = comp.generateSequences(out, src, opts) catch |e| return .{ .err = e };
        return .{ .bytes = try sequenceBytes(gpa, out[0..n]) };
    }
    if (std.mem.eql(u8, sc.cmd, "merge")) {
        const n = zstd.mergeBlockDelimiters(seqs);
        return .{ .bytes = try sequenceBytes(gpa, seqs[0..n]) };
    }
    const cap = if (sc.capacity != 0) sc.capacity else zstd.compressBound(src.len) + 4 * seqs.len + 32;
    const dst = try gpa.alloc(u8, cap);
    errdefer gpa.free(dst);
    const n: usize = if (std.mem.eql(u8, sc.cmd, "cseq"))
        comp.compressSequences(dst, seqs, src, opts) catch |e| {
            gpa.free(dst);
            return .{ .err = e };
        }
    else if (std.mem.eql(u8, sc.cmd, "clit")) blk: {
        const lits = try gpa.alloc(u8, src.len);
        defer gpa.free(lits);
        const nl = seqgen.literals(src, @ptrCast(seqs), lits);
        break :blk comp.compressSequencesAndLiterals(dst, seqs, lits[0..nl], src.len, opts) catch |e| {
            gpa.free(dst);
            return .{ .err = e };
        };
    } else blk: {
        var it = std.mem.splitScalar(u8, sc.cmd, ':');
        const kind = it.next().?;
        var prod: ExampleProducer = .{ .mode = try std.fmt.parseInt(u32, it.next().?, 10) };
        opts.sequence_producer = prod.producer();
        if (std.mem.eql(u8, kind, "prod")) break :blk comp.compress(dst, src, opts) catch |e| {
            gpa.free(dst);
            return .{ .err = e };
        };
        // ZSTD_compressStream2: `chunk` bytes per continue, then end
        const chunk = try std.fmt.parseInt(usize, it.next().?, 10);
        var s = try zstd.Stream.init(gpa, .{ .level = level, .checksum = sc.checksum, .advanced = opts.advanced, .dictionary = opts.dictionary, .sequence_producer = opts.sequence_producer });
        defer s.deinit();
        var out: zstd.OutBuffer = .{ .dst = dst };
        var pos: usize = 0;
        while (true) {
            const take = @min(chunk, src.len - pos);
            var in: zstd.InBuffer = .{ .src = src[pos..][0..take] };
            const end: zstd.EndDirective = if (pos + take == src.len) .end else .@"continue";
            const left = s.compressStream2(&out, &in, end) catch |e| {
                gpa.free(dst);
                return .{ .err = e };
            };
            pos += in.pos;
            if (end == .end and left == 0) break;
        }
        break :blk out.pos;
    };
    return .{ .bytes = try gpa.realloc(dst, n) };
}

/// The sequences a case reads (`seqgen`, as the recipe dumps them).
fn caseSequences(gpa: std.mem.Allocator, sc: corpus.SeqCase, src: []const u8) ![]zstd.Sequence {
    const reads = std.mem.eql(u8, sc.cmd, "merge") or std.mem.eql(u8, sc.cmd, "cseq") or std.mem.eql(u8, sc.cmd, "clit");
    if (!reads) return gpa.alloc(zstd.Sequence, 0);
    const table = try gpa.create([1 << 16]u32);
    defer gpa.destroy(table);
    const buf = try gpa.alloc(seqgen.Seq, seqgen.bound(src.len));
    defer gpa.free(buf);
    const n = seqgen.generate(src, sc.gen, table, buf);
    const out = try gpa.alloc(zstd.Sequence, n);
    for (out, buf[0..n]) |*o, s| o.* = .{ .offset = s.offset, .lit_length = s.lit_length, .match_length = s.match_length, .rep = s.rep };
    return out;
}

/// Rebuild the input from sequences with delimiters (`generateSequences`'
/// output): each sequence's literals, then its match.
fn rebuild(seqs: []const zstd.Sequence, src: []const u8, out: []u8) !usize {
    var op: usize = 0;
    var ip: usize = 0;
    for (seqs) |s| {
        if (op + s.lit_length > out.len) return error.TooLong;
        @memcpy(out[op..][0..s.lit_length], src[ip..][0..s.lit_length]);
        op += s.lit_length;
        ip += s.lit_length;
        if (s.match_length != 0) {
            if (s.offset == 0 or s.offset > op or op + s.match_length > out.len) return error.BadMatch;
            for (0..s.match_length) |k| out[op + k] = out[op + k - s.offset];
            op += s.match_length;
            ip += s.match_length;
        }
    }
    return op;
}

test "every sequence case has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.seq_cases) |sc| for (sc.levels) |level| {
        n += 1;
        if (find(sc, level) == null) {
            std.debug.print("no golden row for {s} level {d}\n", .{ sc.name, level });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

test "the sequence-level API is byte-identical to libzstd 1.5.7, errors included" {
    const gpa = std.testing.allocator;
    var comp: zstd.Compressor = .init(gpa);
    defer comp.deinit();
    var dec = try zstd.Decompressor.init(gpa, .{});
    defer dec.deinit();
    var mismatches: usize = 0;
    for (corpus.seq_cases) |sc| {
        const src = try gpa.alloc(u8, findCase(sc.input).len);
        defer gpa.free(src);
        corpus.generate(findCase(sc.input), src);
        for (sc.levels) |level| {
            const g = find(sc, level).?;
            const seqs = try caseSequences(gpa, sc, src);
            defer gpa.free(seqs);
            const outcome = try runCase(gpa, &comp, sc, level, src, seqs);
            switch (outcome) {
                .err => |e| {
                    if (g.err == null or !std.mem.eql(u8, g.err.?, libzstdName(e))) {
                        std.debug.print("MISMATCH {s} level {d}: error {s}, libzstd {s}\n", .{ sc.name, level, @errorName(e), g.err orelse "none" });
                        mismatches += 1;
                    }
                },
                .bytes => |b| {
                    defer gpa.free(b);
                    var digest: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(b, &digest, .{});
                    const hex = std.fmt.bytesToHex(digest, .lower);
                    if (g.err != null or b.len != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
                        std.debug.print("MISMATCH {s} level {d}: len {d} (libzstd {d}, {s})\n", .{ sc.name, level, b.len, g.len, g.err orelse "ok" });
                        mismatches += 1;
                        continue;
                    }
                    // generated sequences rebuild their input; frames from
                    // valid sequences decode back to it
                    if (std.mem.eql(u8, sc.cmd, "gen") and sc.dict == null) {
                        const back = try gpa.alloc(u8, src.len);
                        defer gpa.free(back);
                        const s: []const zstd.Sequence = @ptrCast(@alignCast(b));
                        try std.testing.expectEqual(src.len, try rebuild(s, src, back));
                        try std.testing.expectEqualSlices(u8, src, back);
                    } else if (!std.mem.eql(u8, sc.cmd, "merge") and sc.gen.damage == .none and sc.gen.list.len == 0 and std.mem.indexOf(u8, sc.params, "format=1") == null and
                        sc.dict == null and !std.mem.eql(u8, sc.name, "cseq-nodelim-explicit-list") and !std.mem.eql(u8, sc.cmd, "prod:1024"))
                    {
                        const back = try gpa.alloc(u8, src.len + 1);
                        defer gpa.free(back);
                        const got = dec.decompress(back, b) catch |e| {
                            std.debug.print("DECODE ERROR {s} level {d}: {s}\n", .{ sc.name, level, @errorName(e) });
                            mismatches += 1;
                            continue;
                        };
                        if (!std.mem.eql(u8, back[0..got], src)) {
                            std.debug.print("DECODE MISMATCH {s} level {d}\n", .{ sc.name, level });
                            mismatches += 1;
                        }
                    }
                },
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

test "compressing generated sequences round-trips, with and without delimiters" {
    const gpa = std.testing.allocator;
    const case = findCase("mix-300000-9");
    const src = try gpa.alloc(u8, case.len);
    defer gpa.free(src);
    corpus.generate(case, src);
    var comp: zstd.Compressor = .init(gpa);
    defer comp.deinit();
    const seqs = try gpa.alloc(zstd.Sequence, zstd.sequenceBound(src.len));
    defer gpa.free(seqs);
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 4 * seqs.len);
    defer gpa.free(dst);
    const back = try gpa.alloc(u8, src.len);
    defer gpa.free(back);
    for ([_]i32{ 1, 5, 19 }) |level| {
        const n = try comp.generateSequences(seqs, src, .{ .level = level });
        // with the delimiters: the blocks libzstd chose, and the frame
        // compress gives (no post-splitter below level 16 here)
        const z = try comp.compressSequences(dst, seqs[0..n], src, .{ .level = level, .advanced = .{ .block_delimiters = .explicit, .repcode_resolution = .enable } });
        try std.testing.expectEqual(src.len, try zstd.decompress(gpa, back, dst[0..z]));
        try std.testing.expectEqualSlices(u8, src, back);
        const m = zstd.mergeBlockDelimiters(seqs[0..n]);
        const z2 = try comp.compressSequences(dst, seqs[0..m], src, .{ .level = level, .advanced = .{ .validate_sequences = true } });
        try std.testing.expectEqual(src.len, try zstd.decompress(gpa, back, dst[0..z2]));
        try std.testing.expectEqualSlices(u8, src, back);
    }
}

test "what libzstd leaves undefined is refused" {
    const gpa = std.testing.allocator;
    var comp: zstd.Compressor = .init(gpa);
    defer comp.deinit();
    const src = "abcdefghabcdefghabcdefgh" ** 4;
    var dst: [256]u8 = undefined;
    const ok = [_]zstd.Sequence{ .{ .offset = 8, .lit_length = 8, .match_length = 88 }, .{ .offset = 0, .lit_length = 0, .match_length = 0 } };
    const explicit: zstd.Options = .{ .advanced = .{ .block_delimiters = .explicit } };
    _ = try comp.compressSequences(&dst, &ok, src, explicit);
    // below 18 bytes of room the header may not fit (libzstd goes on at a
    // wild position)
    try std.testing.expectError(error.DstSizeTooSmall, comp.compressSequences(dst[0..17], &ok, src, explicit));
    // an offset whose code would be highbit32(0)
    const wrap = [_]zstd.Sequence{ .{ .offset = 0xFFFFFFFD, .lit_length = 8, .match_length = 88 }, .{ .offset = 0, .lit_length = 0, .match_length = 0 } };
    try std.testing.expectError(error.ExternalSequencesInvalid, comp.compressSequences(&dst, &wrap, src, explicit));
    // lengths that wrap 32 bits (libzstd copies 4 GB of literals)
    const long = [_]zstd.Sequence{ .{ .offset = 8, .lit_length = 0xFFFFFFFF, .match_length = 97 }, .{ .offset = 0, .lit_length = 0, .match_length = 0 } };
    try std.testing.expectError(error.ExternalSequencesInvalid, comp.compressSequences(&dst, &long, src, explicit));
    try std.testing.expectError(error.ExternalSequencesInvalid, comp.compressSequences(&dst, long[0..1], src, .{}));
    // workers: libzstd hands a large frame to its multithreaded context,
    // which the sequence API bypasses
    const big = try gpa.alloc(u8, 600_000);
    defer gpa.free(big);
    @memset(big, 'x');
    const bigdst = try gpa.alloc(u8, zstd.compressBound(big.len) + 64);
    defer gpa.free(bigdst);
    try std.testing.expectError(error.ParameterUnsupported, comp.compressSequences(bigdst, &.{}, big, .{ .advanced = .{ .nb_workers = 2 } }));
    // ... while a small one runs on the calling thread, as in libzstd
    _ = try comp.compressSequences(&dst, &ok, src, .{ .advanced = .{ .block_delimiters = .explicit, .nb_workers = 2 } });
}

test "a sequence producer's workspace is counted, and a static context has room for it" {
    var prod: ExampleProducer = .{ .mode = 0 };
    const with: zstd.Options = .{ .level = 3, .sequence_producer = prod.producer() };
    const without = try zstd.estimateCompressorSize(100_000, .{ .level = 3 });
    const need = try zstd.estimateCompressorSize(100_000, with);
    // sequenceBound(block) sequences of 16 bytes, and room for a sequence
    // per 3 bytes rather than 4
    try std.testing.expect(need >= without + 16 * zstd.sequenceBound(100_000));
    const gpa = std.testing.allocator;
    const ws = try gpa.alignedAlloc(u8, .fromByteUnits(zstd.workspace_alignment), need);
    defer gpa.free(ws);
    var comp: zstd.Compressor = .initStatic(ws);
    defer comp.deinit();
    const src = try gpa.alloc(u8, 100_000);
    defer gpa.free(src);
    for (src, 0..) |*b, i| b.* = @truncate((i * 7) % 251 + (i / 1000));
    const dst = try gpa.alloc(u8, zstd.compressBound(src.len));
    defer gpa.free(dst);
    const n = try comp.compress(dst, src, with);
    const back = try gpa.alloc(u8, src.len);
    defer gpa.free(back);
    try std.testing.expectEqual(src.len, try zstd.decompress(gpa, back, dst[0..n]));
    try std.testing.expectEqualSlices(u8, src, back);
    try std.testing.expect(prod.calls > 0);
}
