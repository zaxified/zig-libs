// SPDX-License-Identifier: MIT

//! Comparative benchmark: `kv` against github.com/rosedblabs/rosedb/v2 v2.4.0
//! (the owner's choice of speed reference, 2026-10-14: basho/bitcask, the
//! Scope reference, needs Erlang/OTP), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-kv` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! rosedb with its dependencies in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Data, identical on both sides: N = 100000 keys "k%08d" of a permutation of
//! 0..N-1 (Fisher-Yates driven by splitmix64, seed 0x6b767472), values of 100
//! bytes with byte i = (id + i) % 251, loaded into a fresh store under
//! `.zig-cache/bench-kv/` before each row and deleted after it. One op:
//!   get_hit       20000 point gets, permuted order; the value is copied out
//!                 (ours: `get`, allocate + free; rosedb: a fresh slice)
//!   put_new_1k    1000 puts of NEW keys, no fsync (ours `SyncPolicy.none`,
//!                 rosedb `Options.Sync = false`, both libraries' defaults
//!                 for this shape: Bitcask's and rosedb's)
//!   update_1k     1000 overwrites of existing keys, no fsync
//!   put_sync_100  100 puts of new keys, each fsynced (ours `.always`, rosedb
//!                 `Put` + `DB.Sync`: its `Options.Sync = true` does not
//!                 fsync a `Put` in v2.4.0 — measured 3 us per "synced" put)
//!   scan          every key and value: ours `iterator` (snapshot, key order),
//!                 rosedb `Ascend` (its B-tree index, key order)
//!   open_100k     open + close of the loaded store: replaying the log to
//!                 rebuild the in-memory index, both sides
//!   map_baseline  std.StringHashMap get vs Go map get over the same keys:
//!                 a baseline of the language runtimes, INFO ONLY
//! Storage shape: ours reads values back from the log through mmap
//! (`kv.FsStorage.initMmap`, since 2026-10-25; until then a pread per get, 3
//! per get with `read_verify` -- get_hit 0.92x rosedb then, 0.14x now), rosedb
//! with a pread per get (its WAL, no block cache); both CRC-check what they
//! read (ours `read_verify`, the default).
//!
//! The rest of the field, Bitcask-model stores (keys in RAM, values in the
//! log -- the owner's definition, 2026-10-25), is timed the same way for the
//! card's `fastest` figure: prologic/bitcask v1.0.2 (`tools/bitcask_bench`,
//! mmap reads of sealed files) and nutsdb v1.1.0 in `HintKeyAndRAMIdxMode`
//! (`tools/nutsdb_bench`). Fastest = ours / min(rosedb, bitcask, nutsdb) per
//! row, worst over the timed rows. Their sources were swept before the first
//! build (cgo, unsafe, exec, net, init; recorded in SPEC.md § Performance).
//! `BENCH_FIELD=0` skips them.
//! Result count = hits + value bytes read (gets, scan), puts + value bytes
//! written (write rows), keys indexed (open). Each side times the same way
//! (double the batch until it takes over 100 ms, best of five); the sides
//! alternate for BENCH_ROUNDS (default 3) rounds, each keeping its best. Ratios
//! are ours/rosedb by wall time; the verdict is the WORST ratio over the rows
//! except map_baseline. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const kv = @import("kv");
const fastmem = @import("fastmem");

const bench_name = "bench-kv";
const work_dir = ".zig-cache/bench-kv";
const go_dir = "modules/kv/tools/go_bench";
/// The rest of the field (Bitcask model, owner 2026-10-25): sides timed like
/// the reference, for the card's `fastest` ratio. `BENCH_FIELD=0` skips them.
const field = [_]struct { short: []const u8, dir: []const u8, card: []const u8 }{
    .{ .short = "bitcask", .dir = "modules/kv/tools/bitcask_bench", .card = "prologic/bitcask v1.0.2" },
    .{ .short = "nutsdb", .dir = "modules/kv/tools/nutsdb_bench", .card = "nutsdb v1.1.0" },
};
const ref_short = "rosedb";
const ref_card = "github.com/rosedblabs/rosedb/v2 v2.4.0";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{"map_baseline"};
const names = [_][]const u8{ "get_hit", "put_new_1k", "update_1k", "put_sync_100", "scan", "open_100k", "map_baseline" };

const n_keys = 100_000;
const val_len = 100;
const get_n = 20_000;
const batch_w = 1000;
const sync_w = 100;
const seed = 0x6b767472;

const gpa = std.heap.smp_allocator;

const Data = struct {
    perm: []u32,
    keys: [][]const u8,
    vals: []u8,
    map: std.StringHashMapUnmanaged([]const u8),
};

fn splitmix(s: *u64) u64 {
    s.* +%= 0x9e3779b97f4a7c15;
    var z = s.*;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

fn putKey(b: *[9]u8, id: u32) []const u8 {
    b[0] = 'k';
    var x = id;
    var i: usize = 9;
    while (i > 1) {
        i -= 1;
        b[i] = '0' + @as(u8, @intCast(x % 10));
        x /= 10;
    }
    return b;
}

fn fillVal(v: *[val_len]u8, id: u32) void {
    for (v, 0..) |*c, i| c.* = @intCast((@as(u64, id) + i) % 251);
}

fn setupData(arena: std.mem.Allocator) !Data {
    var d: Data = undefined;
    d.perm = try arena.alloc(u32, n_keys);
    for (d.perm, 0..) |*p, i| p.* = @intCast(i);
    var st: u64 = seed;
    var i: usize = n_keys - 1;
    while (i > 0) : (i -= 1) {
        const j: usize = @intCast(splitmix(&st) % (i + 1));
        std.mem.swap(u32, &d.perm[i], &d.perm[j]);
    }
    d.keys = try arena.alloc([]const u8, n_keys);
    d.vals = try arena.alloc(u8, n_keys * val_len);
    d.map = .empty;
    try d.map.ensureTotalCapacity(arena, n_keys);
    for (0..n_keys) |id| {
        const kb = try arena.create([9]u8);
        d.keys[id] = putKey(kb, @intCast(id));
        const v: *[val_len]u8 = d.vals[id * val_len ..][0..val_len];
        fillVal(v, @intCast(id));
        d.map.putAssumeCapacity(d.keys[id], v);
    }
    return d;
}

/// One store under test and the cursors of the write rows.
const Live = struct {
    d: *const Data,
    db: kv.Db,
    store: kv.Storage,
    file: []const u8,
    options: kv.Options,
    pos: usize = 0,
    gen: u32 = 0,
};

fn preload(l: *Live) !void {
    var v: [val_len]u8 = undefined;
    for (0..n_keys) |i| {
        const id = l.d.perm[i];
        fillVal(&v, id);
        try l.db.put(l.d.keys[id], &v);
    }
    try l.db.sync();
}

fn onceGet(l: *Live) u64 {
    var sum: u64 = 0;
    for (0..get_n) |i| {
        const v = (l.db.get(gpa, l.d.keys[l.d.perm[i]]) catch @panic("get")) orelse continue;
        sum += 1 + v.len;
        gpa.free(v);
    }
    return sum;
}

fn onceScan(l: *Live) u64 {
    var it = l.db.iterator(gpa, "") catch @panic("iterator");
    defer it.deinit();
    var sum: u64 = 0;
    while (it.next() catch @panic("next")) |p| sum += 1 + p.value.len;
    return sum;
}

fn onceWrite(l: *Live, n: usize, update: bool) u64 {
    var kb: [9]u8 = undefined;
    var v: [val_len]u8 = undefined;
    var sum: u64 = 0;
    for (0..n) |j| {
        var id: u32 = undefined;
        var k: []const u8 = undefined;
        if (update) {
            id = l.d.perm[(l.pos + j) % n_keys];
            k = l.d.keys[id];
        } else {
            id = @intCast(n_keys + l.pos + j);
            k = putKey(&kb, id);
        }
        fillVal(&v, id +% l.gen);
        l.db.put(k, &v) catch @panic("put");
        sum += 1 + val_len;
    }
    l.pos += n;
    l.gen +%= 1;
    return sum;
}

fn onceOpen(l: *Live) u64 {
    var db = kv.Db.open(gpa, l.store, l.file, l.options) catch @panic("open");
    defer db.close();
    return db.count();
}

fn onceMap(d: *const Data) u64 {
    var sum: u64 = 0;
    for (0..get_n) |i| {
        if (d.map.get(d.keys[d.perm[i]])) |v| sum += 1 + v.len;
    }
    return sum;
}

fn once(d: *const Data, l: ?*Live, w: usize) u64 {
    return switch (w) {
        0 => onceGet(l.?),
        1 => onceWrite(l.?, batch_w, false),
        2 => onceWrite(l.?, batch_w, true),
        3 => onceWrite(l.?, sync_w, false),
        4 => onceScan(l.?),
        5 => onceOpen(l.?),
        else => onceMap(d),
    };
}

/// One timed row on a freshly loaded store (`map_baseline` needs none).
fn oursRow(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, d: *const Data, w: usize) !bench.Row {
    if (w == 6) return bench.timeIt(io, .{ .fd = null }, once, .{ d, null, w }, true);
    const file = try arena.print("kv-{s}.db", .{names[w]});
    const lock = try arena.print("{s}.lock", .{file});
    dir.deleteFile(io, file) catch {};
    dir.deleteFile(io, lock) catch {};
    const fs = try arena.create(kv.FsStorage);
    fs.* = kv.FsStorage.initMmap(io, dir);
    const options: kv.Options = .{ .sync = .none };
    var l: Live = .{ .d = d, .db = try kv.Db.open(gpa, fs.storage(), file, options), .store = fs.storage(), .file = file, .options = options };
    try preload(&l);
    if (w == 3) {
        // Loaded without fsyncs; the timed writes fsync each.
        l.db.close();
        l.options.sync = .always;
        l.db = try kv.Db.open(gpa, l.store, file, l.options);
    }
    if (w == 5) l.db.close();
    const row = bench.timeIt(io, .{ .fd = null }, once, .{ d, &l, w }, true);
    if (w != 5) l.db.close();
    dir.deleteFile(io, file) catch {};
    dir.deleteFile(io, lock) catch {};
    return row;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    const d: Data = try setupData(arena);
    _ = .{fastmem};

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_field = if (init.environ_map.get("BENCH_FIELD")) |v| !std.mem.eql(u8, v, "0") else true;
    var field_exe: [field.len][]const u8 = undefined;
    if (use_field) for (field, &field_exe) |f, *e| {
        // `goBuild` names its binary `<abs>/go_bench`: one directory each.
        const sub = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work_dir, f.short });
        try cwd.createDirPath(io, sub);
        e.* = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = f.dir, .abs = try cwd.realPathFileAlloc(io, sub, arena) });
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    if (use_field) try w.print("{s:<22} {s:>11} {s:>11} {s:>8}  vs fastest (who)\n", .{ "", field[0].short ++ " ns", field[1].short ++ " ns", "ours/best" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    var worst_fast: f64 = 0;
    var worst_fast_row: []const u8 = "";
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        const info_row = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var others: [field.len]bench.Side = @splat(.{});
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_field and !info_row) for (field_exe, &others) |e, *o| o.add(try bench.foreign(arena, io, bench_name, e, abs, name, null));
            ours.add(try oursRow(arena, io, dir, &d, wi));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name, none here): a cost both sides carry
        // is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = info_row;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        var same = ours.count == go.count;
        if (use_field and !info) for (others) |o| {
            same = same and o.count == ours.count;
        };
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ a foreign side's count" });
        if (use_field and !info) {
            var fastest_ns = go.best_ns;
            var who: []const u8 = ref_short;
            for (field, others) |f, o| {
                max_spread = @max(max_spread, o.spread(false));
                if (o.best_ns < fastest_ns) {
                    fastest_ns = o.best_ns;
                    who = f.short;
                }
            }
            const ratio_fast = ours.best_ns / fastest_ns;
            if (ratio_fast > worst_fast) {
                worst_fast = ratio_fast;
                worst_fast_row = name;
            }
            try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3}  ({s})\n", .{ "", others[0].best_ns, others[1].best_ns, ratio_fast, who });
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_field) try w.print("worst vs fastest = {d:.2} (row {s})\n", .{ worst_fast, worst_fast_row });
    if (filters.len == 0) {
        if (use_field)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} / {s} / rosedb ({s}) (measured <today>)\n", .{ best, worst, ref_card, worst_fast, field[0].card, field[1].card, worst_fast_row })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}
