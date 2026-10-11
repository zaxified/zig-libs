// SPDX-License-Identifier: MIT

//! Comparative benchmark: `kvtree` against go.etcd.io/bbolt v1.5.0 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-kvtree` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! go.etcd.io/bbolt (+ golang.org/x/sys) in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Data, identical on both sides: N = 100000 keys "k%08d" of a permutation of
//! 0..N-1 (Fisher-Yates driven by splitmix64, seed 0x6b767472), values of 100
//! bytes with byte i = (id + i) % 251. Both sides store in a fresh file under
//! `.zig-cache/bench-kvtree/`, deleted after each row. One op:
//!   get_hit        20000 point gets, permuted order, one snapshot / View per
//!                  op; the value is copied out (ours: allocate + free per get;
//!                  bbolt: copy of its mmap slice into a reused buffer)
//!   scan           full ordered scan of the N keys (cursor first/next)
//!   put_txn_1k     one transaction of 1000 puts of NEW keys + commit, store
//!                  holding N keys already (fsync on both sides: kvtree always,
//!                  bbolt NoSync=false)
//!   update_txn_1k  the same, overwriting 1000 existing keys
//!   bucket_get     like get_hit, the N keys living in bucket "b"
//!   map_baseline   std.StringHashMap get vs Go map get over the same keys:
//!                  a baseline of the language runtimes, INFO ONLY
//! bbolt has no keys outside a bucket, so its rows all use bucket "b"; ours
//! use the root tree except bucket_get. Storage shape, the production one on
//! each side: bbolt reads its mmap, resident in the OS page cache after the
//! preload; ours opens the store on a `pagecache.PageCache` in front of
//! `kv.FsStorage` with a budget that holds the whole file
//! (`cache_pages`), so a resident page is lent to the descent with no
//! syscall and no copy (`Storage.preadRef`). Writes go through it too
//! (write-through, same fsyncs). Until 2026-10-11 ours preaded every page
//! through bare `kv.FsStorage`: get_hit 4.67x, scan 3.32x.
//! Result count = hits + value bytes read (gets, scan), puts + value bytes
//! written (write rows); it does not depend on how many ops a side ran.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best, each round on a freshly loaded store. Ratios are
//! ours/bbolt by wall time; the verdict is the WORST ratio over the rows except
//! map_baseline. Arguments filter workloads.

const std = @import("std");
const kvtree = @import("kvtree");
const pagecache = @import("pagecache");

const bench_name = "bench-kvtree";
const work_dir = ".zig-cache/bench-kvtree";
const go_dir = "modules/kvtree/tools/go_bench";
const ref_short = "bbolt";
const ref_card = "go.etcd.io/bbolt v1.5.0";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{"map_baseline"};
const names = [_][]const u8{ "get_hit", "scan", "put_txn_1k", "update_txn_1k", "bucket_get", "map_baseline" };

const n_keys = 100_000;
const val_len = 100;
const get_n = 20_000;
const batch_w = 1000;
const seed = 0x6b767472;
/// 32 MiB of 4 KiB pages: the preloaded store plus every write row's growth
/// over a timed run fit, so no row measures eviction.
const cache_pages = 8192;

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

/// One store under test: a backend over the work directory, a `Db` on it, and
/// the cursors of the write rows.
const Live = struct {
    d: *const Data,
    db: kvtree.Db,
    pos: usize = 0,
    gen: u32 = 0,
};

fn preload(l: *Live, bucket: bool) !void {
    var tx = try l.db.begin();
    var v: [val_len]u8 = undefined;
    if (bucket) {
        const b = try tx.createBucket("b");
        for (0..n_keys) |i| {
            const id = l.d.perm[i];
            fillVal(&v, id);
            try b.put(l.d.keys[id], &v);
        }
    } else {
        for (0..n_keys) |i| {
            const id = l.d.perm[i];
            fillVal(&v, id);
            try tx.put(l.d.keys[id], &v);
        }
    }
    try tx.commit();
}

fn onceGet(l: *Live, bucket: bool) u64 {
    var snap = l.db.snapshot() catch @panic("snapshot");
    defer snap.release();
    var sum: u64 = 0;
    if (bucket) {
        const bk = (snap.bucket("b") catch @panic("bucket")) orelse @panic("no bucket");
        for (0..get_n) |i| {
            const v = (bk.get(gpa, l.d.keys[l.d.perm[i]]) catch @panic("get")) orelse continue;
            sum += 1 + v.len;
            gpa.free(v);
        }
    } else {
        for (0..get_n) |i| {
            const v = (snap.get(gpa, l.d.keys[l.d.perm[i]]) catch @panic("get")) orelse continue;
            sum += 1 + v.len;
            gpa.free(v);
        }
    }
    return sum;
}

fn onceScan(l: *Live) u64 {
    var snap = l.db.snapshot() catch @panic("snapshot");
    defer snap.release();
    var cur = snap.cursor() catch @panic("cursor");
    defer cur.deinit();
    cur.first() catch @panic("first");
    var sum: u64 = 0;
    while (cur.next() catch @panic("next")) |e| {
        if (e.bucket) continue;
        sum += 1 + e.val.len;
    }
    return sum;
}

fn onceWrite(l: *Live, update: bool) u64 {
    var tx = l.db.begin() catch @panic("begin");
    var kb: [9]u8 = undefined;
    var v: [val_len]u8 = undefined;
    var sum: u64 = 0;
    for (0..batch_w) |j| {
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
        tx.put(k, &v) catch @panic("put");
        sum += 1 + val_len;
    }
    tx.commit() catch @panic("commit");
    l.pos += batch_w;
    l.gen +%= 1;
    return sum;
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
        0 => onceGet(l.?, false),
        1 => onceScan(l.?),
        2 => onceWrite(l.?, false),
        3 => onceWrite(l.?, true),
        4 => onceGet(l.?, true),
        else => onceMap(d),
    };
}

/// One timed row on a freshly loaded store (`map_baseline` needs none).
fn oursRow(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, d: *const Data, w: usize) !Row {
    if (w == 5) return timeIt(io, d, null, w);
    const file = try std.fmt.allocPrint(arena, "kvtree-{s}.db", .{names[w]});
    const lock = try std.fmt.allocPrint(arena, "{s}.lock", .{file});
    dir.deleteFile(io, file) catch {};
    dir.deleteFile(io, lock) catch {};
    const fs = try arena.create(kvtree.FsStorage);
    fs.* = kvtree.FsStorage.init(io, dir);
    const pc = try arena.create(pagecache.PageCache);
    pc.* = pagecache.PageCache.init(gpa, fs.storage(), .{ .max_pages = cache_pages });
    defer pc.deinit();
    var l: Live = .{ .d = d, .db = try kvtree.Db.open(gpa, pc.storage(), file, .{}) };
    try preload(&l, w == 4);
    const row = timeIt(io, d, &l, w);
    l.db.close();
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

    const exe = try goBuild(arena, io, init.environ_map, abs);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: Side = .{};
        var go: Side = .{};
        for (0..rounds) |_| {
            go.add(try goRun(arena, io, exe, abs, name));
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
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(), go.spread()));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(), 100 * go.spread(), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}

// ---- comparison driver (the same in every stdlib-Go-referenced bench) ----

const Row = struct { ns: f64, count: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, d: *const Data, l: ?*Live, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(d, l, w));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: u64 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = once(d, l, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

/// Build the Go side once (`go build`), so the timed runs do not pay for it.
fn goBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// Run the Go side for one workload: `<exe> <work dir> <name>` prints
/// `name \t ns/op \t count`.
fn goRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Go side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
