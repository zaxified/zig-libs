// SPDX-License-Identifier: MIT
//! Deterministic training-sample sets for the dictionary-trainer goldens
//! (`dict_goldens.zig`) and tests.
//!
//! A set is many small samples back to back, with their sizes -- the shape
//! `ZDICT_trainFromBuffer_*` takes. Sample sizes are drawn between `min_len`
//! and `max_len`; the contents come from the golden corpus generators
//! (`corpus.generate`, one seed per sample) or from a record template here
//! (`json`), which is what dictionaries are for: small inputs sharing
//! structure. `tools/dump_samples.zig` writes the same sets to disk for
//! libzstd (`tools/ztrain.c`).

const std = @import("std");
const corpus = @import("corpus.zig");

pub const Kind = enum {
    json, // records from one template: keys shared, values varying
    words, // corpus `words`
    csv, // corpus `csv`
    mix, // corpus `mix`: text, numbers, noise, runs, copies
    random, // incompressible: every score stays low
    zeros, // a single repeated d-mer: one segment and done
    islands, // zeros up to sample `seed`, then text: epochs scoring nothing, then content
    periodic, // zeros, with a text sample every `seed`-th: runs of empty epochs between content
};

pub const Set = struct {
    name: []const u8,
    kind: Kind,
    nb: u32,
    min_len: u32,
    max_len: u32,
    seed: u64 = 0,
};

pub const sets = [_]Set{
    .{ .name = "json-200", .kind = .json, .nb = 200, .min_len = 40, .max_len = 400 },
    .{ .name = "json-2000", .kind = .json, .nb = 2000, .min_len = 20, .max_len = 600, .seed = 1 },
    .{ .name = "words-300", .kind = .words, .nb = 300, .min_len = 8, .max_len = 2000 },
    .{ .name = "csv-100", .kind = .csv, .nb = 100, .min_len = 100, .max_len = 3000 },
    .{ .name = "mix-400", .kind = .mix, .nb = 400, .min_len = 1, .max_len = 1500, .seed = 7 },
    .{ .name = "random-50", .kind = .random, .nb = 50, .min_len = 100, .max_len = 1000 },
    .{ .name = "zeros-20", .kind = .zeros, .nb = 20, .min_len = 10, .max_len = 500 },
    .{ .name = "tiny-6", .kind = .json, .nb = 6, .min_len = 2, .max_len = 12, .seed = 3 },
    .{ .name = "json-40k", .kind = .json, .nb = 400, .min_len = 50, .max_len = 150, .seed = 9 },
    // Built for the empty-epoch stop (`maxZeroScoreRun`), 100-byte samples:
    // with k = 50 and a 64 KiB buffer, epochs are 500 d-mers (5 samples);
    // text first reaches epoch 10 (the last one the stop at 10 lets run),
    // epoch 11 (the first it does not), and with k = 16 and 16 KiB, epochs
    // of 164 among 256, epoch 45 (cover's stop is then 32, not 64).
    .{ .name = "islands-53", .kind = .islands, .nb = 150, .min_len = 100, .max_len = 100, .seed = 53 },
    .{ .name = "islands-58", .kind = .islands, .nb = 150, .min_len = 100, .max_len = 100, .seed = 58 },
    .{ .name = "islands-74", .kind = .islands, .nb = 420, .min_len = 100, .max_len = 100, .seed = 74 },
    // text every 7 epochs: runs of 6 empty epochs, reset by each island
    .{ .name = "periodic-35", .kind = .periodic, .nb = 150, .min_len = 100, .max_len = 100, .seed = 35 },
};

pub const Generated = struct {
    buffer: []u8,
    sizes: []usize,

    pub fn deinit(g: Generated, gpa: std.mem.Allocator) void {
        gpa.free(g.buffer);
        gpa.free(g.sizes);
    }
};

const Rng = struct {
    s: u64,
    fn next(r: *Rng) u64 {
        r.s +%= 0x9E3779B97F4A7C15;
        var z = r.s;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        return z ^ (z >> 31);
    }
    fn below(r: *Rng, n: u64) u64 {
        return r.next() % n;
    }
};

const names = [_][]const u8{ "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "theta", "kappa", "lambda" };
const tags = [_][]const u8{ "red", "green", "blue", "hot", "cold", "new", "old" };

fn json(r: *Rng, out: []u8) void {
    var i: usize = 0;
    var line: [256]u8 = undefined;
    while (i < out.len) {
        const s = std.fmt.bufPrint(&line, "{{\"id\":{d},\"name\":\"{s}\",\"tags\":[\"{s}\",\"{s}\"],\"ts\":{d},\"ok\":{s}}}\n", .{
            r.below(100000),
            names[r.below(names.len)],
            tags[r.below(tags.len)],
            tags[r.below(tags.len)],
            1_700_000_000 + r.below(1_000_000),
            if (r.below(2) == 0) "true" else "false",
        }) catch unreachable;
        const n = @min(s.len, out.len - i);
        @memcpy(out[i..][0..n], s[0..n]);
        i += n;
    }
}

/// Generate `set` (the caller frees with `deinit`).
pub fn generate(gpa: std.mem.Allocator, set: Set) !Generated {
    var r: Rng = .{ .s = @as(u64, set.nb) *% 131 +% @intFromEnum(set.kind) +% set.seed *% 0xD1B54A32D192ED03 };
    const sizes = try gpa.alloc(usize, set.nb);
    errdefer gpa.free(sizes);
    var total: usize = 0;
    for (sizes) |*s| {
        s.* = set.min_len + @as(usize, @intCast(r.below(set.max_len - set.min_len + 1)));
        total += s.*;
    }
    const buffer = try gpa.alloc(u8, total);
    var at: usize = 0;
    for (sizes, 0..) |n, i| {
        const out = buffer[at..][0..n];
        const seed = r.next();
        switch (set.kind) {
            .json => {
                var sr: Rng = .{ .s = seed };
                json(&sr, out);
            },
            .zeros => @memset(out, 0),
            .islands, .periodic => {
                const text = if (set.kind == .islands) i >= set.seed else i % set.seed == set.seed - 1;
                if (text) corpus.generate(.{ .name = "", .len = n, .kind = .words, .seed = seed +% i }, out) else @memset(out, 0);
            },
            inline .words, .csv, .mix, .random => |k| corpus.generate(.{
                .name = "",
                .len = n,
                .kind = @field(corpus.Kind, @tagName(k)),
                .seed = seed +% i,
            }, out),
        }
        at += n;
    }
    return .{ .buffer = buffer, .sizes = sizes };
}

/// The on-disk form `tools/ztrain.c` reads: u32 LE count, u32 LE sizes,
/// the samples.
pub fn serialize(gpa: std.mem.Allocator, g: Generated) ![]u8 {
    const out = try gpa.alloc(u8, 4 + 4 * g.sizes.len + g.buffer.len);
    std.mem.writeInt(u32, out[0..4], @intCast(g.sizes.len), .little);
    for (g.sizes, 0..) |s, i| std.mem.writeInt(u32, out[4 + 4 * i ..][0..4], @intCast(s), .little);
    @memcpy(out[4 + 4 * g.sizes.len ..], g.buffer);
    return out;
}

pub const Trainer = enum { cover, fastcover };

/// One golden training run: `trainer` over `set` into a `capacity`-byte
/// buffer. f and accel of 0 are libzstd's defaults (fastCover only). A
/// `split` below "1" builds the context on the training share, as the
/// optimizer does for each (k, d) it tries.
pub const Run = struct {
    trainer: Trainer,
    set: []const u8,
    capacity: u32,
    k: u32,
    d: u32,
    f: u32 = 0,
    accel: u32 = 0,
    split: []const u8 = "1",
};

pub const runs = [_]Run{
    // cover: d ≤ 8 (masked 64-bit compare) and d > 8 (memcmp), small and
    // large k, capacities from the minimum up to past the corpus
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 50, .d = 6 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 4096, .k = 200, .d = 8 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 256, .k = 16, .d = 3 },
    .{ .trainer = .cover, .set = "json-2000", .capacity = 16384, .k = 1000, .d = 8 },
    .{ .trainer = .cover, .set = "json-2000", .capacity = 8192, .k = 64, .d = 12 },
    .{ .trainer = .cover, .set = "json-2000", .capacity = 2048, .k = 300, .d = 1 },
    .{ .trainer = .cover, .set = "words-300", .capacity = 4096, .k = 100, .d = 6 },
    .{ .trainer = .cover, .set = "words-300", .capacity = 65536, .k = 2000, .d = 8 },
    .{ .trainer = .cover, .set = "csv-100", .capacity = 2000, .k = 77, .d = 7 },
    .{ .trainer = .cover, .set = "csv-100", .capacity = 4096, .k = 150, .d = 16 },
    .{ .trainer = .cover, .set = "mix-400", .capacity = 8192, .k = 250, .d = 8 },
    .{ .trainer = .cover, .set = "mix-400", .capacity = 1000, .k = 1000, .d = 6 },
    .{ .trainer = .cover, .set = "random-50", .capacity = 4096, .k = 100, .d = 8 },
    .{ .trainer = .cover, .set = "zeros-20", .capacity = 1024, .k = 64, .d = 8 },
    .{ .trainer = .cover, .set = "tiny-6", .capacity = 256, .k = 8, .d = 6 },
    .{ .trainer = .cover, .set = "json-40k", .capacity = 300, .k = 40, .d = 5 },
    .{ .trainer = .cover, .set = "json-2000", .capacity = 4096, .k = 200, .d = 8, .split = "0.75" },
    .{ .trainer = .cover, .set = "mix-400", .capacity = 4096, .k = 537, .d = 6, .split = "0.5" },
    // the empty-epoch stop and its reset
    .{ .trainer = .cover, .set = "islands-53", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .cover, .set = "islands-58", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .cover, .set = "islands-74", .capacity = 16384, .k = 16, .d = 8 },
    .{ .trainer = .cover, .set = "periodic-35", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 8, .d = 8 }, // d = k
    // cover refusals, in libzstd's order
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 50, .d = 0 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 0, .d = 6 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 5, .d = 6 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 1024, .k = 1025, .d = 6 },
    .{ .trainer = .cover, .set = "json-200", .capacity = 255, .k = 50, .d = 6 },
    .{ .trainer = .cover, .set = "tiny-6", .capacity = 256, .k = 50, .d = 6, .split = "0.8" },
    // fastCover: both hashes, f from small (collisions) to default, every
    // kind of accel
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 1024, .k = 50, .d = 6 },
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 4096, .k = 200, .d = 8 },
    .{ .trainer = .fastcover, .set = "json-2000", .capacity = 16384, .k = 1000, .d = 8, .f = 20, .accel = 1 },
    .{ .trainer = .fastcover, .set = "json-2000", .capacity = 8192, .k = 64, .d = 6, .f = 8 },
    .{ .trainer = .fastcover, .set = "json-2000", .capacity = 2048, .k = 300, .d = 8, .f = 12, .accel = 4 },
    .{ .trainer = .fastcover, .set = "words-300", .capacity = 4096, .k = 100, .d = 6, .f = 15, .accel = 2 },
    .{ .trainer = .fastcover, .set = "words-300", .capacity = 65536, .k = 2000, .d = 8, .f = 1 },
    .{ .trainer = .fastcover, .set = "csv-100", .capacity = 2000, .k = 77, .d = 6, .accel = 10 },
    .{ .trainer = .fastcover, .set = "mix-400", .capacity = 8192, .k = 250, .d = 8, .f = 18, .accel = 7 },
    .{ .trainer = .fastcover, .set = "mix-400", .capacity = 1000, .k = 1000, .d = 6 },
    .{ .trainer = .fastcover, .set = "random-50", .capacity = 4096, .k = 100, .d = 8 },
    .{ .trainer = .fastcover, .set = "zeros-20", .capacity = 1024, .k = 64, .d = 8 },
    .{ .trainer = .fastcover, .set = "tiny-6", .capacity = 256, .k = 8, .d = 6 },
    .{ .trainer = .fastcover, .set = "json-40k", .capacity = 300, .k = 40, .d = 6, .f = 10 },
    .{ .trainer = .fastcover, .set = "json-2000", .capacity = 4096, .k = 200, .d = 8, .split = "0.75" },
    .{ .trainer = .fastcover, .set = "mix-400", .capacity = 4096, .k = 537, .d = 6, .f = 16, .accel = 3, .split = "0.5" },
    .{ .trainer = .fastcover, .set = "islands-53", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .fastcover, .set = "islands-58", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .fastcover, .set = "periodic-35", .capacity = 65536, .k = 50, .d = 8 },
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 1024, .k = 6, .d = 6 }, // d = k
    // fastCover refusals, in libzstd's order
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 1024, .k = 50, .d = 7 },
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 1024, .k = 50, .d = 6, .f = 32 },
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 1024, .k = 50, .d = 6, .accel = 11 },
    .{ .trainer = .fastcover, .set = "json-200", .capacity = 200, .k = 50, .d = 6 },
    .{ .trainer = .fastcover, .set = "tiny-6", .capacity = 256, .k = 50, .d = 8, .split = "0.9" },
};

pub fn find(name: []const u8) Set {
    for (sets) |s| if (std.mem.eql(u8, s.name, name)) return s;
    unreachable;
}
