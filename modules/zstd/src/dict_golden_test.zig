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

const std = @import("std");
const db = @import("dict_builder.zig");
const samples = @import("testdata/dict_samples.zig");
const goldens = @import("testdata/dict_goldens.zig");

/// `ZSTD_ErrorCode` of each refusal.
fn errorCode(e: db.Error) u32 {
    return switch (e) {
        error.ParameterOutOfBound => 42,
        error.DstSizeTooSmall => 70,
        error.SrcSizeWrong => 72,
        error.MemoryLimitExceeded, error.OutOfMemory => 64,
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
                const n = try db.trainCoverInto(gpa, dict, s, .{ .k = r.k, .d = r.d });
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
                const n = try db.trainFastCoverInto(gpa, dict, s, .{ .k = r.k, .d = r.d, .f = r.f, .accel = r.accel });
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
    try std.testing.expectEqualStrings("1b7d7681f9afed8e997c8bfa21fc03e8c0ff4071404e51e0800a39b6eb066948", &hex);
}
