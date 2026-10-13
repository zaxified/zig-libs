// SPDX-License-Identifier: MIT

//! Comparative benchmark: `trie` against BurntSushi/fst 0.4.7 (Rust, the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-trie` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cargo` and the
//! `fst` 0.4.7 crate in the local registry (`cargo build --offline`; pinned by
//! `tools/rust_bench/Cargo.toml`/`Cargo.lock`). Run from the repository root.
//!
//! Both sides generate the SAME deterministic data (splitmix64, seed
//! 0x74726965, the draw order mirrored in `tools/rust_bench/src/main.rs`):
//! 1 000 000 keys `w<8 letters>/<0..9999>`, deduplicated and sorted, value =
//! position; then the query sets. One op is the whole row:
//!   build          the index from the sorted pairs: ours `SortedBuilder` into a
//!                  memory writer, fst `MapBuilder::memory()`
//!   lookup_hit     100 000 `get` of present keys
//!   lookup_miss    100 000 `get` of absent keys (a present key, last byte + 1)
//!   prefix_iter    1 000 prefixes (first 3 bytes of a key), every key under
//!                  each: ours `prefixIterator`, fst `search(Str.starts_with())`
//!   range_iter     1 000 ranges [k_i, k_j), j - i <= 1000
//!   search_subseq  100 `Subsequence` searches of 3 letters (both sides must
//!                  visit nearly the whole index)
//!   union_2        union of the even and the odd positions as two indexes
//!   load           open from bytes (O(1) on both sides) -- information only
//!   size           bytes of both indexes -- printed, not a timing row
//! Every row's result is a checksum, (count, sum of values), printed by both
//! sides and compared. Each side times the same way (double the batch until it
//! takes over 100 ms, best of five); the sides alternate for BENCH_ROUNDS
//! (default 3) rounds, each keeping its best. Ratios are ours/fst by wall time;
//! the verdict is the WORST ratio over the timed rows. Arguments filter rows.
//!
//! Not like-for-like, by construction: fst's index is a minimized transducer
//! (smaller, see `size`), ours an un-minimized path-compressed trie; `build`
//! compares a streaming builder on sorted input on both sides; fst `get` and
//! our `lookup` both walk the whole key. Each `next` of ours copies the key
//! into a caller buffer, as fst's streams hand out a borrowed `&[u8]`.

const std = @import("std");
const trie = @import("trie");

const bench_name = "bench-trie";
const cargo_manifest = "modules/trie/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/trie/tools/rust_bench/target/release/trie_bench";
const ref_short = "fst";
const ref_card = "BurntSushi/fst 0.4.7";

const seed: u64 = 0x7472_6965;
const n_keys = 1_000_000;
const n_hit = 100_000;
const n_miss = 100_000;
const n_prefix = 1_000;
const n_range = 1_000;
const n_subseq = 100;

const names = [_][]const u8{ "build", "lookup_hit", "lookup_miss", "prefix_iter", "range_iter", "search_subseq", "union_2", "load" };
const info_only = [_][]const u8{"load"};

const gpa = std.heap.smp_allocator;

const SplitMix = struct {
    s: u64,
    fn next(self: *SplitMix) u64 {
        self.s +%= 0x9E37_79B9_7F4A_7C15;
        var z = self.s;
        z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
        z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
        return z ^ (z >> 31);
    }
};

const Data = struct {
    keys: []const []const u8,
    hits: []const u32,
    misses: []const []const u8,
    prefixes: []const []const u8,
    ranges: []const [2]u32,
    subseqs: []const [3]u8,
    full: []u8,
    full_f: trie.Frozen,
    even: []u8,
    odd: []u8,
    even_f: trie.Frozen,
    odd_f: trie.Frozen,
};

const Result = struct { count: u64, sum: u64 };

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn contains(keys: []const []const u8, key: []const u8) bool {
    var lo: usize = 0;
    var hi: usize = keys.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, keys[mid], key)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return true,
        }
    }
    return false;
}

/// The sorted pairs at positions first, first + step, ... as a v2 index.
fn buildIndex(keys: []const []const u8, first: usize, step: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var sb = try trie.SortedBuilder.init(gpa, &out.writer, .{});
    defer sb.deinit();
    var i = first;
    while (i < keys.len) : (i += step) try sb.insert(keys[i], @intCast(i));
    try sb.finish();
    return out.toOwnedSlice();
}

fn setup(arena: std.mem.Allocator) !Data {
    var rng: SplitMix = .{ .s = seed };
    const raw = try arena.alloc([]const u8, n_keys);
    for (raw) |*slot| {
        const r = rng.next();
        var k: std.ArrayList(u8) = .empty;
        try k.append(arena, 'w');
        for (0..8) |j| try k.append(arena, 'a' + @as(u8, @intCast(((r >> @intCast(8 * j)) & 0xff) % 26)));
        try k.append(arena, '/');
        var nb: [8]u8 = undefined;
        try k.appendSlice(arena, std.fmt.bufPrint(&nb, "{d}", .{rng.next() % 10_000}) catch unreachable);
        slot.* = k.items;
    }
    std.mem.sort([]const u8, raw, {}, lessThan);
    var n: usize = 0;
    for (raw) |k| {
        if (n > 0 and std.mem.eql(u8, raw[n - 1], k)) continue;
        raw[n] = k;
        n += 1;
    }
    const keys = raw[0..n];

    const hits = try arena.alloc(u32, n_hit);
    for (hits) |*h| h.* = @intCast(rng.next() % n);
    const misses = try arena.alloc([]const u8, n_miss);
    for (misses) |*m| {
        while (true) {
            const k = try arena.dupe(u8, keys[rng.next() % n]);
            k[k.len - 1] += 1;
            if (!contains(keys, k)) {
                m.* = k;
                break;
            }
        }
    }
    const prefixes = try arena.alloc([]const u8, n_prefix);
    for (prefixes) |*p| p.* = keys[rng.next() % n][0..3];
    const ranges = try arena.alloc([2]u32, n_range);
    for (ranges) |*r| {
        const i = rng.next() % n;
        const span = rng.next() % 1000 + 1;
        r.* = .{ @intCast(i), @intCast(@min(i + span, n - 1)) };
    }
    const subseqs = try arena.alloc([3]u8, n_subseq);
    for (subseqs) |*q| for (q) |*c| {
        c.* = 'a' + @as(u8, @intCast(rng.next() % 26));
    };

    const full = try buildIndex(keys, 0, 1);
    const even = try buildIndex(keys, 0, 2);
    const odd = try buildIndex(keys, 1, 2);
    return .{
        .keys = keys,
        .hits = hits,
        .misses = misses,
        .prefixes = prefixes,
        .ranges = ranges,
        .subseqs = subseqs,
        .full = full,
        .full_f = try trie.Frozen.load(full),
        .even = even,
        .odd = odd,
        .even_f = try trie.Frozen.load(even),
        .odd_f = try trie.Frozen.load(odd),
    };
}

fn once(d: *const Data, w: usize) Result {
    var kb: [64]u8 = undefined;
    var count: u64 = 0;
    var sum: u64 = 0;
    switch (w) {
        0 => { // build
            const buf = buildIndex(d.keys, 0, 1) catch @panic("build");
            std.mem.doNotOptimizeAway(buf.ptr);
            gpa.free(buf);
            count = d.keys.len;
        },
        1 => for (d.hits) |i| { // lookup_hit
            if (d.full_f.lookup(d.keys[i]) catch @panic("lookup")) |v| {
                count += 1;
                sum += v;
            }
        },
        2 => for (d.misses) |k| { // lookup_miss
            if ((d.full_f.lookup(k) catch @panic("lookup")) == null) count += 1;
        },
        3 => for (d.prefixes) |p| { // prefix_iter
            var it = d.full_f.prefixIterator(gpa, p) catch @panic("prefix");
            defer it.deinit();
            while (it.next(&kb) catch @panic("next")) |c| {
                count += 1;
                sum += c.value;
            }
        },
        4 => for (d.ranges) |r| { // range_iter
            var it = d.full_f.range(gpa, .{ .lo = d.keys[r[0]], .hi = d.keys[r[1]] }, 0) catch @panic("range");
            defer it.deinit();
            while (it.next(&kb) catch @panic("next")) |c| {
                count += 1;
                sum += c.value;
            }
        },
        5 => for (d.subseqs) |q| { // search_subseq
            const aut = trie.automaton.Subsequence{ .subseq = &q };
            var it = d.full_f.search(gpa, trie.automaton.Subsequence, &aut, 0) catch @panic("search");
            defer it.deinit();
            while (it.next(&kb) catch @panic("next")) |c| {
                count += 1;
                sum += c.value;
            }
        },
        6 => { // union_2
            var it = trie.opIterator(gpa, &.{ d.even_f, d.odd_f }, .@"union", 0) catch @panic("op");
            defer it.deinit();
            var vb: [2]trie.IndexedValue = undefined;
            while (it.next(&kb, &vb) catch @panic("next")) |item| {
                count += 1;
                for (item.values) |v| sum += v.value;
            }
        },
        else => { // load
            std.mem.doNotOptimizeAway(d.full.ptr);
            const f = trie.Frozen.load(d.full) catch @panic("load");
            count = f.keyCount();
        },
    }
    return .{ .count = count, .sum = sum };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    try rustBuild(arena, io);
    const d: Data = try setup(arena);

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    // Information: the size of both indexes (no timing).
    const ref_size = try rustRun(arena, io, "size");
    try w.print("size: ours {d} B ({d:.1} B/key), {s} {d} B ({d:.1} B/key), keys {d}\n", .{
        d.full.len,
        @as(f64, @floatFromInt(d.full.len)) / @as(f64, @floatFromInt(d.keys.len)),
        ref_short,
        ref_size.count,
        @as(f64, @floatFromInt(ref_size.count)) / @as(f64, @floatFromInt(d.keys.len)),
        d.keys.len,
    });
    try w.print("{s:<14} {s:>13} {s:>13} {s:>8} {s:>7} {s:>7}  count / sum\n", .{ "row", "ours ns", ref_short ++ " ns", "ratio", "spr us", "spr ref" });
    try w.flush();

    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: Side = .{};
        var ref: Side = .{};
        for (0..rounds) |_| {
            ref.add(try rustRun(arena, io, name));
            ours.add(timeIt(io, &d, wi));
        }
        const ratio = ours.best_ns / ref.best_ns;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(), ref.spread()));
        const same = ours.count == ref.count and ours.sum == ref.sum;
        mismatch = mismatch or !same;
        try w.print("{s:<14} {d:>13.0} {d:>13.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d} / {d}{s}\n", .{
            name,       ours.best_ns,        ref.best_ns,
            ratio,      100 * ours.spread(), 100 * ref.spread(),
            ours.count, ours.sum,            if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " != " ++ ref_short,
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}

// ---- comparison driver (as in every reference-benchmarked module) ----

const Row = struct { ns: f64, count: u64, sum: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    sum: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
        s.sum = r.sum;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, d: *const Data, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| {
            const r = once(d, w);
            std.mem.doNotOptimizeAway(r.count +% r.sum);
        }
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var res: Result = .{ .count = 0, .sum = 0 };
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| res = once(d, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = res.count, .sum = res.sum };
}

/// Build the Rust side once (`cargo build --release --offline`), so the timed
/// runs do not pay for it.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", cargo_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

/// Run the Rust side for one row: `<exe> <name>` prints
/// `name \t ns/op \t count \t sum`.
fn rustRun(arena: std.mem.Allocator, io: std.Io, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ rust_exe, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Rust side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    const sum = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count, .sum = sum };
}
