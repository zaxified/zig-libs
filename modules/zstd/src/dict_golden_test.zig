// SPDX-License-Identifier: MIT
//! Dictionary-training content against libzstd 1.5.7.
//!
//! For every run in `testdata/dict_samples.runs`, the content the cover or
//! fastCover trainer here places in the dictionary buffer must have the
//! length and SHA-256 of what libzstd's trainer placed there before
//! finalization (`testdata/dict_goldens.zig`, written by
//! `tools/gen-dict-goldens.sh` through `tools/ztrain.c`), the same
//! small-corpus verdict -- or the run must be refused with the error libzstd
//! refused it with. A run with a split point below 1 goes through the
//! context API on the training share, as the optimizer builds each
//! candidate.
//!
//! For every run in `testdata/dict_samples.final_runs`, the FINISHED
//! dictionary -- `finalizeDictionary`, `addEntropyTablesFromBuffer`,
//! `trainCover` / `trainFastCover`, `optimizeCover` / `optimizeFastCover`
//! (and the k, d they chose), `train`, `selectDict` (and its total) -- must
//! have the length and SHA-256 libzstd's public API gave
//! (`testdata/dict_final_goldens.zig`, through `tools/zfinal.c`), and
//! `getDictHeaderSize` must agree with `ZDICT_getDictHeaderSize` on it.

const std = @import("std");
const db = @import("dict_builder.zig");
const samples = @import("testdata/dict_samples.zig");
const goldens = @import("testdata/dict_goldens.zig");
const final_goldens = @import("testdata/dict_final_goldens.zig");
const ddict = @import("ddict.zig");

/// `ZSTD_ErrorCode` of each refusal.
fn errorCode(e: db.Error) u32 {
    return switch (e) {
        error.ParameterOutOfBound => 42,
        error.DstSizeTooSmall => 70,
        error.SrcSizeWrong => 72,
        error.MemoryLimitExceeded, error.OutOfMemory => 64,
        error.DictionaryCreationFailed => 34,
        error.Generic, error.NoCandidate => 1,
        error.LevelUnsupported => 0xFFFF, // libzstd clamps the level
    };
}

const Outcome = union(enum) { content: []const u8, err: u32 };

/// The run as `ztrain.c` performs it: the trainer's checks in libzstd's
/// order, the context (on the training share for a split below 1), the
/// build. Returns the content, a slice of `dict`.
fn run(gpa: std.mem.Allocator, r: samples.Run, s: db.Samples, dict: []u8) db.Error![]const u8 {
    const split = std.fmt.parseFloat(f64, r.split) catch unreachable;
    switch (r.trainer) {
        .cover => {
            if (split == 1.0) {
                const n = try db.coverContentInto(gpa, dict, s, .{ .k = r.k, .d = r.d });
                return dict[dict.len - n ..];
            }
            if (!db.checkCoverParameters(r.k, r.d, split, dict.len)) return error.ParameterOutOfBound;
            if (s.sizes.len == 0) return error.SrcSizeWrong;
            if (dict.len < db.dict_size_min) return error.DstSizeTooSmall;
            var ctx: db.CoverContext = try .init(gpa, s, r.d, split, db.default_memory_limit);
            defer ctx.deinit(gpa);
            var active: db.ActiveDmers = try .init(gpa, r.k - r.d + 1);
            defer active.deinit(gpa);
            return dict[ctx.buildDictionary(ctx.freqs, &active, dict, r.k, r.d)..];
        },
        .fastcover => {
            if (split == 1.0) {
                const n = try db.fastCoverContentInto(gpa, dict, s, .{ .k = r.k, .d = r.d, .f = r.f, .accel = r.accel });
                return dict[dict.len - n ..];
            }
            const f = if (r.f == 0) db.fastcover_default_f else r.f;
            const accel = if (r.accel == 0) db.fastcover_default_accel else r.accel;
            if (!db.checkFastCoverParameters(r.k, r.d, split, dict.len, f, accel)) return error.ParameterOutOfBound;
            if (s.sizes.len == 0) return error.SrcSizeWrong;
            if (dict.len < db.dict_size_min) return error.DstSizeTooSmall;
            var ctx: db.FastCoverContext = try .init(gpa, s, r.d, split, f, db.accel_table[accel], db.default_memory_limit);
            defer ctx.deinit(gpa);
            const seg = try gpa.alloc(u16, ctx.freqs.len);
            defer gpa.free(seg);
            @memset(seg, 0);
            return dict[ctx.buildDictionary(ctx.freqs, dict, r.k, r.d, seg)..];
        },
    }
}

fn nbDmers(r: samples.Run, s: db.Samples) u64 {
    const split = std.fmt.parseFloat(f64, r.split) catch unreachable;
    const sp: db.Split = db.Split.init(s, r.d, split) catch unreachable;
    return sp.nbDmers(r.d);
}

test "every golden run has a row, and nothing else does" {
    try std.testing.expectEqual(samples.runs.len, goldens.rows.len);
}

test "trained content is byte-identical to libzstd 1.5.7's, refusals too" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    for (samples.runs, goldens.rows) |r, g| {
        const gen = try samples.generate(gpa, samples.find(r.set));
        defer gen.deinit(gpa);
        const s: db.Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
        const dict = try gpa.alloc(u8, r.capacity);
        defer gpa.free(dict);
        const content = run(gpa, r, s, dict) catch |e| {
            if (errorCode(e) != g.err) {
                std.debug.print("MISMATCH {s} {s} cap {d} k {d} d {d}: {s}, libzstd error {d}\n", .{ @tagName(r.trainer), r.set, r.capacity, r.k, r.d, @errorName(e), g.err });
                mismatches += 1;
            }
            continue;
        };
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const small = db.smallCorpus(r.capacity, @intCast(nbDmers(r, s)));
        if (g.err != 0 or content.len != g.len or !std.mem.eql(u8, &hex, g.sha256) or small != g.small) {
            std.debug.print("MISMATCH {s} {s} cap {d} k {d} d {d}: len {d} (libzstd {d}, err {d})\n", .{ @tagName(r.trainer), r.set, r.capacity, r.k, r.d, content.len, g.len, g.err });
            mismatches += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

test "sample sets are the ones the goldens were made from" {
    // Pins the generator: a drift would fail every golden above for a
    // reason unrelated to the trainers. SHA-256 over the recipe's sample
    // files (`<name>.bin`) concatenated in set order.
    const gpa = std.testing.allocator;
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (samples.sets) |set| {
        const gen = try samples.generate(gpa, set);
        defer gen.deinit(gpa);
        const bytes = try samples.serialize(gpa, gen);
        defer gpa.free(bytes);
        h.update(bytes);
    }
    const hex = std.fmt.bytesToHex(h.finalResult(), .lower);
    try std.testing.expectEqualStrings("160d69ccf790560c86382b8e1bca701362d80caa7f862d56e7a86587dbd073c3", &hex);
}

/// No selection from `selectDict` (the oracle's code for it).
const no_selection = 1000;

const FinalOut = struct { size: usize, a: u64 = 0, b: u64 = 0 };

/// The run as `tools/zfinal.c` performs it; the dictionary is `dict[0..size]`.
fn finalRun(gpa: std.mem.Allocator, r: samples.FinalRun, s: db.Samples, dict: []u8) (db.Error || error{NoSelection})!FinalOut {
    const split = std.fmt.parseFloat(f64, r.split) catch unreachable;
    const nb_finalize: usize = r.nb_finalize orelse s.sizes.len;
    switch (r.op) {
        .finalize => {
            const content = s.buffer[r.off..][0..r.len];
            const fs: db.Samples = .{ .buffer = s.buffer, .sizes = s.sizes[0..nb_finalize] };
            return .{ .size = try db.finalizeDictionary(gpa, dict, content, fs, .{ .level = r.level, .dict_id = r.dict_id }) };
        },
        .addentropy => {
            @memset(dict, 0);
            @memcpy(dict[dict.len - r.len ..], s.buffer[r.off..][0..r.len]);
            return .{ .size = try db.addEntropyTablesFromBuffer(gpa, dict, r.len, s, .{}) };
        },
        .cover => return .{ .size = try db.trainCover(gpa, dict, s, .{ .k = r.k, .d = r.d, .level = r.level, .dict_id = r.dict_id }) },
        .fastcover => return .{ .size = try db.trainFastCover(gpa, dict, s, .{ .k = r.k, .d = r.d, .f = r.f, .accel = r.accel, .level = r.level, .dict_id = r.dict_id }) },
        .optcover, .optfast => {
            const p: db.OptimizeParams = .{ .k = r.k, .d = r.d, .steps = r.steps, .split_point = split, .f = r.f, .accel = r.accel, .level = r.level, .dict_id = r.dict_id };
            const o = if (r.op == .optcover) try db.optimizeCover(gpa, dict, s, p) else try db.optimizeFastCover(gpa, dict, s, p);
            return .{ .size = o.size, .a = o.k, .b = o.d };
        },
        .default => return .{ .size = try db.train(gpa, dict, s) },
        .select => {
            const buf = try gpa.dupe(u8, s.buffer[r.off..][0..r.capacity]);
            defer gpa.free(buf);
            const offsets = try gpa.alloc(usize, s.sizes.len + 1);
            defer gpa.free(offsets);
            offsets[0] = 0;
            for (s.sizes, 0..) |n, i| offsets[i + 1] = offsets[i] + n;
            const sel = try db.selectDict(gpa, buf, r.len, s, offsets, nb_finalize, r.nb_train, split, .{
                .level = r.level,
                .dict_id = r.dict_id,
                .shrink = r.shrink,
                .shrink_max_regression = r.max_regression,
            }) orelse return error.NoSelection;
            defer db.freeSelection(gpa, sel);
            @memcpy(dict[0..sel.dict.len], sel.dict);
            return .{ .size = sel.dict.len, .a = sel.total_compressed_size };
        },
    }
}

test "every finished-dictionary run has a row, and nothing else does" {
    try std.testing.expectEqual(samples.final_runs.len, final_goldens.rows.len);
}

test "finished dictionaries are byte-identical to libzstd 1.5.7's" {
    const gpa = std.testing.allocator;
    var mismatches: usize = 0;
    for (samples.final_runs, final_goldens.rows) |r, g| {
        const gen = try samples.generate(gpa, samples.find(r.set));
        defer gen.deinit(gpa);
        const s: db.Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
        const dict = try gpa.alloc(u8, r.capacity);
        defer gpa.free(dict);
        const out = finalRun(gpa, r, s, dict) catch |e| {
            const code: u32 = if (e == error.NoSelection) no_selection else errorCode(@errorCast(e));
            if (code != g.err) {
                std.debug.print("MISMATCH {s} {s} cap {d}: {s}, libzstd error {d}\n", .{ @tagName(r.op), r.set, r.capacity, @errorName(e), g.err });
                mismatches += 1;
            }
            continue;
        };
        const d = dict[0..out.size];
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(d, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const hdr: i64 = if (db.getDictHeaderSize(d)) |h| @intCast(h) else |_| -30;
        if (g.err != 0 or out.size != g.len or !std.mem.eql(u8, &hex, g.sha256) or hdr != g.hdr or out.a != g.a or out.b != g.b) {
            std.debug.print("MISMATCH {s} {s} cap {d}: len {d} hdr {d} a {d} b {d} (libzstd len {d} hdr {d} a {d} b {d} err {d})\n", .{ @tagName(r.op), r.set, r.capacity, out.size, hdr, out.a, out.b, g.len, g.hdr, g.a, g.b, g.err });
            mismatches += 1;
            continue;
        }
        // the decoder takes it as a zstd dictionary with that ID (unless
        // its tables overwrote the content, as addEntropyTablesFromBuffer
        // may)
        if (hdr < 0) continue;
        var dd = try ddict.DDict.init(gpa, d, .full);
        defer dd.deinit(gpa);
        try std.testing.expectEqual(db.getDictId(d), dd.dictId());
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
