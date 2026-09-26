// SPDX-License-Identifier: MIT
//! Compression with dictionaries against libzstd 1.5.7.
//!
//! Every `corpus.dict_cases` entry -- an input, a dictionary (raw content
//! from the corpus generators, zstd dictionaries trained by libzstd's
//! `ZDICT_trainFromBuffer` and committed as `testdata/*.zdict`, those with
//! other IDs, and a hand-built one whose tables all need checking), the
//! way the dictionary is used (loaded, a `CDict` copied or loaded anew, a
//! prefix, `compressUsingDict` / `compressUsingCDict`), its content type
//! and advanced parameters -- is compressed one-shot, or through `Stream`
//! with a schedule, and must give the length and SHA-256 libzstd gave
//! (`testdata/cdict_goldens.zig`, from `tools/gen-goldens.sh` through
//! `tools/zref.c` and `tools/zstream.c`, which also decode every frame
//! back with the dictionary). As in golden_test.zig, all the one-shot
//! frames come from one reused context and the streamed ones from one
//! reused stream; libzstd gives fresh-context bytes either way with
//! dictionaries too (SPEC.md, *Dictionaries*). Every frame is also
//! decoded back with this module's decoder and the same dictionary.
//!
//! Where libzstd would attach a `CDict` (small inputs, unknown sizes), this
//! port now searches it in place with every strategy's dictMatchState
//! variant: `fast`/`dfast` (D1, `corpus.dict_cases_attach_fast`),
//! `greedy`..`btlazy2` (D2, `corpus.dict_cases_attach_lazy`) and the
//! optimal parsers (D3, `corpus.dict_cases_attach_opt`) -- so
//! `error.DictAttachUnsupported` no longer has a strategy left to name;
//! the last test pins that it is still refused where asked for on
//! purpose (`force_attach_dict = .copy`/`.load`, never `.attach`).

const std = @import("std");
const zstd = @import("root.zig");
const frame = @import("frame.zig");
const match = @import("match.zig");
const corpus = @import("testdata/corpus.zig");
const goldens = @import("testdata/cdict_goldens.zig");
const param_test = @import("param_test.zig");
const stream_test = @import("stream_test.zig");

const trained_files = .{
    .{ "zd-words", @embedFile("testdata/zd-words.zdict") },
    .{ "zd-csv", @embedFile("testdata/zd-csv.zdict") },
};

fn trained(name: []const u8) []const u8 {
    inline for (trained_files) |t| if (std.mem.eql(u8, t[0], name)) return t[1];
    unreachable;
}

fn find(dc: corpus.DictCase, level: i32, checksum: bool) ?goldens.Golden {
    for (goldens.rows) |g| {
        if (g.level == level and g.checksum == checksum and std.mem.eql(u8, g.case, dc.name)) return g;
    }
    return null;
}

test "every dictionary case has a golden row, and nothing else does" {
    var n: usize = 0;
    for (corpus.dict_cases ++ corpus.dict_cases_attach_fast) |dc| for (dc.levels) |level| for (dc.checksums) |ck| {
        n += 1;
        if (find(dc, level, ck) == null) {
            std.debug.print("no golden row for {s} level {d} checksum {}\n", .{ dc.name, level, ck });
            return error.MissingGolden;
        }
    };
    try std.testing.expectEqual(n, goldens.rows.len);
}

test "the trained dictionaries are the ones the goldens were made with" {
    // `sha256sum` of each committed file: a retrained dictionary must come
    // with regenerated goldens.
    const want = .{
        .{ "zd-words", "f9e3b0f77efd66213c36e68d5b34cf2b1eb3d54d577eb64d7bbac6522b1636f2" },
        .{ "zd-csv", "045c94e61c39b29de56722e9bba814a93c2ba902bdec8aac0256a0ccceb486e8" },
    };
    inline for (want) |w| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(trained(w[0]), &digest, .{});
        try std.testing.expectEqualStrings(w[1], &std.fmt.bytesToHex(digest, .lower));
    }
}

/// `dc`'s dictionary bytes, allocated.
fn buildDict(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const d = corpus.findDict(name);
    const buf = try gpa.alloc(u8, corpus.dictLen(d, &trained));
    const n = corpus.buildDict(d, &trained, buf);
    return gpa.realloc(buf, n) catch buf[0..n];
}

const Out = struct { bytes: []u8, owned: bool };

/// One dictionary golden's output: `buf` holds the dictionary and then the
/// input (so a prefix can be adjacent).
fn compressCase(gpa: std.mem.Allocator, ctx: *zstd.Compressor, strm: *zstd.Stream, dc: corpus.DictCase, level: i32, ck: bool, dict: []const u8, src: []const u8, dst: []u8) ![]const u8 {
    const ctype: zstd.DictContentType = @enumFromInt(dc.content_type);
    if (dc.schedule) |sch| {
        // streaming: the advanced parameters are the schedule's
        var cdict: ?zstd.CDict = null;
        defer if (cdict) |*c| c.deinit();
        const d: zstd.Dictionary = switch (dc.path) {
            .load => .{ .raw = .{ .bytes = dict, .content_type = ctype } },
            .prefix => .{ .prefix = .{ .bytes = dict, .content_type = ctype } },
            .cdict => blk: {
                cdict = try zstd.CDict.init(gpa, dict, level);
                break :blk .{ .cdict = &cdict.? };
            },
            .cdictadv => blk: {
                var adv: zstd.Advanced = .{};
                var hint: ?u32 = null;
                var it = std.mem.tokenizeScalar(u8, sch, ',');
                while (it.next()) |tok| {
                    if (try param_test.applyParam(&adv, &hint, tok)) continue;
                    if (tok[0] == 'w') adv.window_log = try std.fmt.parseInt(u32, tok[1..], 10);
                    if (std.mem.eql(u8, tok, "l")) adv.long_distance_matching = .enable;
                }
                cdict = try zstd.CDict.initAdvanced(gpa, dict, .{ .level = level, .content_type = ctype, .advanced = adv, .src_size_hint = hint });
                break :blk .{ .cdict = &cdict.? };
            },
            else => return error.BadCase,
        };
        const r = try stream_test.runOn(gpa, strm, src, level, ck, sch, d);
        const n = r.out.len;
        @memcpy(dst[0..n], r.out);
        gpa.free(r.out);
        return dst[0..n];
    }
    var adv = if (std.mem.eql(u8, dc.params, "-")) zstd.Advanced{} else try param_test.parse(dc.params);
    const opts: zstd.Options = .{ .level = level, .checksum = ck, .advanced = adv };
    if (dc.ocf) {
        // through the frame context, with the frequent-correction seam
        var corrections: [2]u32 = .{ 0, 0 };
        var fo: frame.Options = .{ .level = level, .checksum = ck, .advanced = adv, .overflow_correct_frequently = true, .overflow_corrections = &corrections };
        var cd: ?zstd.CDict = null;
        defer if (cd) |*c| c.deinit();
        fo.dict = switch (dc.path) {
            .load => .{ .raw = .{ .bytes = dict, .content_type = ctype } },
            .prefix => .{ .prefix = .{ .bytes = dict, .content_type = ctype } },
            .cdict => blk: {
                cd = try zstd.CDict.init(gpa, dict, level);
                break :blk .{ .cdict = &cd.? };
            },
            else => return error.BadCase,
        };
        const n = try ctx.ctx.compressFrame(dst, src, fo);
        if (corrections[0] == 0) return error.NoCorrection;
        return dst[0..n];
    }
    const n = switch (dc.path) {
        .load, .loadadj => try ctx.compress(dst, src, withDict(opts, .{ .raw = .{ .bytes = dict, .content_type = ctype } })),
        .prefix, .prefixadj => try ctx.compress(dst, src, withDict(opts, .{ .prefix = .{ .bytes = dict, .content_type = ctype } })),
        .usingdict => try ctx.compressUsingDict(dst, src, dict, level),
        .cdict, .usingcdict => blk: {
            var cd = try zstd.CDict.init(gpa, dict, level);
            defer cd.deinit();
            if (dc.path == .cdict) break :blk try ctx.compress(dst, src, withDict(opts, .{ .cdict = &cd }));
            break :blk try ctx.compressUsingCDict(dst, src, &cd, .{ .content_size = adv.content_size, .checksum = ck, .dict_id = adv.dict_id_flag });
        },
        .cdictadv, .cdictrefadj => blk: {
            const o: zstd.CDict.Options = .{ .level = level, .content_type = ctype, .advanced = adv };
            var cd = try if (dc.path == .cdictadv) zstd.CDict.initAdvanced(gpa, dict, o) else zstd.CDict.initReference(gpa, dict, o);
            defer cd.deinit();
            adv = opts.advanced;
            break :blk try ctx.compress(dst, src, withDict(opts, .{ .cdict = &cd }));
        },
    };
    return dst[0..n];
}

/// Decode `frames` with the dictionary they were made with -- a prefix as
/// `prefix_once`, anything else as a `DDict` of the case's content type --
/// and compare with `src`.
fn decodeBack(gpa: std.mem.Allocator, dc: corpus.DictCase, dict: []const u8, frames: []const u8, src: []const u8) !void {
    const ctype: zstd.DictContentType = @enumFromInt(dc.content_type);
    var dd = try zstd.DDict.init(gpa, dict, ctype);
    defer dd.deinit(gpa);
    const prefix = dc.path == .prefix or dc.path == .prefixadj;
    // magicless frames are read as such (a schedule's own parameters are
    // never the format)
    const format = if (std.mem.eql(u8, dc.params, "-")) zstd.Format.zstd1 else (try param_test.parse(dc.params)).format;
    var d = try zstd.Decompressor.init(gpa, if (prefix) .{ .prefix_once = dict, .format = format } else .{ .ddict = &dd, .format = format });
    defer d.deinit();
    const back = try gpa.alloc(u8, src.len);
    defer gpa.free(back);
    const n = try d.decompress(back, frames);
    if (!std.mem.eql(u8, back[0..n], src)) return error.DecodedOtherBytes;
}

fn withDict(opts: zstd.Options, d: zstd.Dictionary) zstd.Options {
    var o = opts;
    o.dictionary = d;
    return o;
}

test "output with dictionaries is byte-identical to libzstd 1.5.7" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    var ctx: zstd.Compressor = .init(gpa);
    defer ctx.deinit();
    var strm = try zstd.Stream.init(gpa, .{});
    defer strm.deinit();
    for (corpus.dict_cases ++ corpus.dict_cases_attach_fast) |dc| {
        const dict = try buildDict(gpa, dc.dict);
        defer gpa.free(dict);
        // the dictionary and the input in one buffer: adjacent for a
        // `prefixadj` / `loadadj` / `cdictrefadj` case, whose dictionary is
        // the copy right before the input
        const buf = try gpa.alloc(u8, dict.len + dc.input.len);
        defer gpa.free(buf);
        @memcpy(buf[0..dict.len], dict);
        const src = buf[dict.len..];
        corpus.generate(dc.input, src);
        const d = switch (dc.path) {
            .prefixadj, .loadadj, .cdictrefadj => buf[0..dict.len],
            else => dict,
        };
        const dst = try gpa.alloc(u8, zstd.compressBound(src.len) + 64);
        defer gpa.free(dst);
        for (dc.levels) |level| for (dc.checksums) |ck| {
            const g = find(dc, level, ck).?;
            const out = compressCase(gpa, &ctx, &strm, dc, level, ck, d, src, dst) catch |e| {
                std.debug.print("ERROR {s} level {d} checksum {}: {s}\n", .{ dc.name, level, ck, @errorName(e) });
                mismatches += 1;
                continue;
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(out, &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            if (out.len != g.len or !std.mem.eql(u8, &hex, g.sha256)) {
                std.debug.print("MISMATCH {s} level {d} checksum {}: len {d} (libzstd {d})\n", .{ dc.name, level, ck, out.len, g.len });
                mismatches += 1;
            }
            // and this module's decoder gives the input back with the same
            // dictionary
            decodeBack(gpa, dc, d, out, src) catch |e| {
                std.debug.print("DECODE {s} level {d} checksum {}: {s}\n", .{ dc.name, level, ck, @errorName(e) });
                mismatches += 1;
            };
        };
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
    // Both ways into a context ran: tables copied from a CDict, and a
    // dictionary loaded into it.
    try std.testing.expect(ctx.ctx.n_cdict_copies > 0 and ctx.ctx.n_dict_loads > 0);
}

test "every strategy's dictMatchState variant attaches where libzstd would, D1-D3 together" {
    // D1 (fast/dfast), D2 (greedy..btlazy2) and D3 (the optimal parsers)
    // together give every strategy a dictMatchState variant, so
    // `error.DictAttachUnsupported` no longer has a strategy left to name
    // -- this pins that `hasDictMatchStateVariant` is exhaustively `true`
    // and that attaching actually succeeds end to end for each one, below
    // every strategy's cutoff (3000 bytes) and for an unknown-size stream.
    const gpa = std.testing.allocator;
    const dict = trained("zd-words");
    var src: [3000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 13 }, &src);
    var dst: [4096]u8 = undefined;
    var ctx: zstd.Compressor = .init(gpa);
    defer ctx.deinit();
    for ([_]i32{ -3, 1, 3, 5, 9, 13, 16, 19, 22 }) |level| {
        var cd = try zstd.CDict.init(gpa, dict, level);
        defer cd.deinit();
        try std.testing.expect(match.hasDictMatchStateVariant(cd.ms.cp.strategy));
        _ = try ctx.compress(&dst, &src, .{ .level = level, .dictionary = .{ .cdict = &cd } });
        _ = try ctx.compressUsingCDict(&dst, &src, &cd, .{});
        _ = try ctx.compress(&dst, &src, .{ .level = level, .dictionary = .{ .raw = .{ .bytes = dict } } });
        _ = try ctx.compress(&dst, &src, .{ .level = level, .advanced = .{ .force_attach_dict = .attach }, .dictionary = .{ .cdict = &cd } });
        // copying or loading is still available too (byte-identity is
        // `corpus.dict_cases`/`dict_cases_attach_fast`/`_lazy`/`_opt`'s
        // job, not this one's)
        _ = try ctx.compress(&dst, &src, .{ .level = level, .advanced = .{ .force_attach_dict = .copy }, .dictionary = .{ .cdict = &cd } });
        _ = try ctx.compress(&dst, &src, .{ .level = level, .advanced = .{ .force_attach_dict = .load }, .dictionary = .{ .cdict = &cd } });
    }
    // a stream of unknown size attaches too
    var strm = try zstd.Stream.init(gpa, .{ .level = 9, .dictionary = .{ .raw = .{ .bytes = dict } } });
    defer strm.deinit();
    var in: zstd.InBuffer = .{ .src = &src };
    var out: zstd.OutBuffer = .{ .dst = &dst };
    _ = try strm.compressStream2(&out, &in, .@"continue");
    _ = try strm.compressStream2(&out, &in, .end);
}

test "the attach cutoffs are libzstd's, per strategy" {
    const gpa = std.testing.allocator;
    var raw: [5000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = raw.len, .kind = .words, .seed = 1 }, &raw);
    const Want = struct { level: i32, cutoff: u64 };
    // the CDict's own strategy decides: level 1 fast (8 KB), 3 dfast (16
    // KB), 5 greedy .. 16 btopt (32 KB), 19 btultra2 (8 KB) -- for a
    // CDict made for small inputs
    for ([_]Want{ .{ .level = 1, .cutoff = 8 << 10 }, .{ .level = 3, .cutoff = 16 << 10 }, .{ .level = 5, .cutoff = 32 << 10 }, .{ .level = 12, .cutoff = 32 << 10 }, .{ .level = 13, .cutoff = 8 << 10 }, .{ .level = 19, .cutoff = 8 << 10 } }) |w| {
        var cd = try zstd.CDict.init(gpa, &raw, w.level);
        defer cd.deinit();
        try std.testing.expect(frame.shouldAttachDict(&cd, .{}, w.cutoff));
        try std.testing.expect(!frame.shouldAttachDict(&cd, .{}, w.cutoff + 1));
        try std.testing.expect(frame.shouldAttachDict(&cd, .{}, std.math.maxInt(u64)));
        try std.testing.expect(frame.shouldAttachDict(&cd, .{ .force_attach_dict = .attach }, 1 << 30));
        try std.testing.expect(!frame.shouldAttachDict(&cd, .{ .force_attach_dict = .copy }, 1));
        try std.testing.expect(!frame.shouldAttachDict(&cd, .{ .force_max_window = true }, 1));
    }
}

test "a copied CDict's tagged tables lose their tags" {
    const gpa = std.testing.allocator;
    var raw: [6000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = raw.len, .kind = .csv, .seed = 3 }, &raw);
    for ([_]i32{ 1, 3 }) |level| { // fast, dfast: tagged
        var cd = try zstd.CDict.init(gpa, &raw, level);
        defer cd.deinit();
        var comp: frame.Compressor = .initEmpty(gpa);
        defer comp.deinit();
        var local: ?zstd.CDict = null;
        try comp.initStream2(.{ .level = level, .checksum = false, .dict = .{ .cdict = &cd }, .advanced = .{ .force_attach_dict = .copy } }, 50000, null, false, &local);
        try std.testing.expectEqual(@as(u32, 1), comp.n_cdict_copies);
        for (comp.c.ms.hash_table, cd.ms.hash_table) |c, t| try std.testing.expectEqual(t >> 8, c);
        for (comp.c.ms.chain_table, cd.ms.chain_table) |c, t| try std.testing.expectEqual(t >> 8, c);
        try std.testing.expectEqual(cd.ms.loaded_dict_end, comp.c.ms.loaded_dict_end);
    }
}

test "a prefix serves one frame; an empty dictionary is none" {
    const gpa = std.testing.allocator;
    var src: [20000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 30 }, &src);
    // (a separate buffer: a dictionary the input overlaps in memory is
    // dropped, as libzstd presumes it overwritten)
    var dict: [5000]u8 = src[0..5000].*;
    var plain: [21000]u8 = undefined;
    const want = try zstd.compress(gpa, &plain, &src, .{});
    var out: [44000]u8 = undefined;
    var s = try zstd.Stream.init(gpa, .{ .dictionary = .{ .prefix = .{ .bytes = &dict } }, .pledged_size = src.len });
    defer s.deinit();
    var o: zstd.OutBuffer = .{ .dst = &out };
    var in: zstd.InBuffer = .{ .src = &src };
    try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o, &in, .end));
    const first = o.pos;
    try std.testing.expect(first < want); // the prefix served
    in = .{ .src = &src };
    try std.testing.expectEqual(@as(usize, 0), try s.compressStream2(&o, &in, .end));
    // the second frame has no dictionary (and an unknown size): what a
    // stream without one gives
    var s2 = try zstd.Stream.init(gpa, .{});
    defer s2.deinit();
    var o2: zstd.OutBuffer = .{ .dst = out[o.pos..] };
    var in2: zstd.InBuffer = .{ .src = &src };
    _ = try s2.compressStream2(&o2, &in2, .end);
    try std.testing.expectEqualSlices(u8, out[o.pos..][0..o2.pos], out[first..o.pos]);
    // 0 bytes, even "full", are no dictionary
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    var got: [21000]u8 = undefined;
    const n = try c.compress(&got, &src, .{ .dictionary = .{ .raw = .{ .bytes = "", .content_type = .full } } });
    try std.testing.expectEqualSlices(u8, plain[0..want], got[0..n]);
}

test "a dedicated-search CDict: greedy..lazy2 only, bucketed, always attached" {
    const gpa = std.testing.allocator;
    var raw: [30000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = raw.len, .kind = .csv, .seed = 5 }, &raw);
    const dds: zstd.Advanced = .{ .enable_dedicated_dict_search = true };
    // raw-csv-30000's levels: 1 fast, 3 dfast, 5 greedy, 6 lazy, 8 lazy2
    // (rows), 11 btlazy2, 13 btopt
    for ([_]struct { i32, bool }{ .{ 1, false }, .{ 3, false }, .{ 5, true }, .{ 6, true }, .{ 8, true }, .{ 11, false }, .{ 13, false } }) |lw| {
        var cd = try zstd.CDict.initAdvanced(gpa, &raw, .{ .level = lw[0], .advanced = dds });
        defer cd.deinit();
        try std.testing.expectEqual(lw[1], cd.dedicated_dict_search);
        try std.testing.expectEqual(lw[1], cd.ms.dedicated_dict_search);
        if (!lw[1]) continue;
        // sized for the dictionary alone, the hash log 2 larger; the
        // chain table is there even with rows
        try std.testing.expect(cd.ms.chain_table.len != 0);
        try std.testing.expectEqual(@as(usize, 1) << @intCast(cd.ms.cp.hash_log), cd.ms.hash_table.len);
        try std.testing.expectEqual(cd.ms.cp, zstd.CDict.paramsFor(raw.len, .{ .level = lw[0], .advanced = dds }));
        const cp = @import("params.zig").getInternal(lw[0], 0, raw.len, .create_cdict);
        try std.testing.expectEqual(cp.hash_log + 2, cd.ms.cp.hash_log);
        // every bucket: three positions newest first, then (start << 8) | length
        var chained: usize = 0;
        var i: usize = 0;
        while (i < cd.ms.hash_table.len) : (i += 4) {
            const b = cd.ms.hash_table[i..][0..4];
            if (b[1] != 0) try std.testing.expect(b[0] > b[1]);
            if (b[2] != 0) try std.testing.expect(b[1] > b[2]);
            const len = b[3] & 0xff;
            try std.testing.expect((b[3] >> 8) + len <= cd.ms.chain_table.len);
            chained += len;
        }
        try std.testing.expect(chained > 0);
        // always attached: a forced copy, `force_max_window`, a large input
        try std.testing.expect(frame.shouldAttachDict(&cd, .{ .force_attach_dict = .copy }, 1 << 30));
        try std.testing.expect(frame.shouldAttachDict(&cd, .{ .force_max_window = true }, 1));
        var comp: frame.Compressor = .initEmpty(gpa);
        defer comp.deinit();
        var local: ?zstd.CDict = null;
        try comp.initStream2(.{ .level = lw[0], .checksum = false, .dict = .{ .cdict = &cd }, .advanced = .{ .force_attach_dict = .copy } }, 1 << 20, null, false, &local);
        try std.testing.expectEqual(@as(u32, 0), comp.n_cdict_copies);
        try std.testing.expectEqual(@as(?*const match.MatchState, &cd.ms), comp.c.ms.dict_match_state);
        // the context's own tables no larger than the plain size (reverted)
        try std.testing.expect(comp.c.ms.hash_table.len <= @as(usize, 1) << @intCast(cd.ms.cp.hash_log - 2));
    }
    // a hash log not above the chain log falls back to a plain CDict
    var cd = try zstd.CDict.initAdvanced(gpa, &raw, .{ .level = 5, .advanced = .{ .enable_dedicated_dict_search = true, .hash_log = 14, .chain_log = 16 } });
    defer cd.deinit();
    try std.testing.expect(!cd.dedicated_dict_search);
}

/// `src` streamed in 1 KB blocks with `cd` attached (an unknown size),
/// with `prefetch` as the switch; returns the frame's length in `dst`.
fn streamAttached(dst: []u8, src: []const u8, level: i32, cd: *const zstd.CDict, prefetch: zstd.Switch) !usize {
    var s = try zstd.Stream.init(std.testing.allocator, .{ .level = level, .advanced = .{ .prefetch_cdict_tables = prefetch, .max_block_size = 1024 }, .dictionary = .{ .cdict = cd } });
    defer s.deinit();
    var in: zstd.InBuffer = .{ .src = src };
    var out: zstd.OutBuffer = .{ .dst = dst };
    while (in.pos < in.src.len) _ = try s.compressStream2(&out, &in, .@"continue");
    while (try s.compressStream2(&out, &in, .end) != 0) {}
    try std.testing.expect(s.comp.c.ms.dict_match_state != null);
    try std.testing.expectEqual(prefetch == .enable, s.comp.c.ms.prefetch_cdict_tables);
    return out.pos;
}

test "prefetching an attached CDict's tables changes no byte" {
    // `ZSTD_c_prefetchCDictTables` is speed only; the block functions that
    // read it (fast and dfast attached) must still give libzstd's bytes,
    // which the frames without it are pinned to.
    const gpa = std.testing.allocator;
    const dict = trained("zd-words");
    var src: [6000]u8 = undefined;
    corpus.generate(.{ .name = "", .len = src.len, .kind = .words, .seed = 14 }, &src);
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    var ctx: zstd.Compressor = .init(gpa);
    defer ctx.deinit();
    for ([_]i32{ -3, 1, 2, 3, 4, 5 }) |level| {
        var cd = try zstd.CDict.init(gpa, dict, level);
        defer cd.deinit();
        const na = try ctx.compress(&a, &src, .{ .level = level, .advanced = .{ .force_attach_dict = .attach }, .dictionary = .{ .cdict = &cd } });
        try std.testing.expect(!ctx.ctx.c.ms.prefetch_cdict_tables);
        const nb = try ctx.compress(&b, &src, .{ .level = level, .advanced = .{ .force_attach_dict = .attach, .prefetch_cdict_tables = .enable }, .dictionary = .{ .cdict = &cd } });
        try std.testing.expect(ctx.ctx.c.ms.dict_match_state != null and ctx.ctx.c.ms.prefetch_cdict_tables);
        try std.testing.expectEqualSlices(u8, a[0..na], b[0..nb]);
        // and through a stream, block by block
        const sa = try streamAttached(&a, &src, level, &cd, .enable);
        const sb = try streamAttached(&b, &src, level, &cd, .auto);
        try std.testing.expectEqualSlices(u8, b[0..sb], a[0..sa]);
    }
}
