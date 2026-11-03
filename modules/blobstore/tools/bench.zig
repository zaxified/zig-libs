// SPDX-License-Identifier: MIT

//! Comparative benchmark: `blobstore`'s content-addressed put/get/has against
//! Go's `github.com/ipfs/go-ds-flatfs` v0.6.1 (the reference, MIT, `sync=true`)
//! and `github.com/peterbourgon/diskv/v3` v3.0.1 (the candidate for fastest,
//! MIT, `TempDir` + `sync=true`), both driven by `tools/go_bench`. This is the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-blobstore` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and the
//! modules in `tools/go_bench/go.mod` in the module cache (`GOPROXY=off`).
//! Run from the repository root. `BENCH_DIR=/dev/shm/x` moves the work
//! directory off the disk (the default is `.zig-cache/bench-blobstore`, a real
//! filesystem where fsync costs a device flush); `BENCH_ROUNDS=n`.
//!
//! What the sides do, per blob (so the rows are like for like):
//!   put   ours: `putBytes` on a store with `Options.refcount = false`: hash
//!         (SHA-256) while streaming into a temp, fsync, flock the ingest lock,
//!         rename, fsync the directory. flatfs: SHA-256 of the bytes, hex key,
//!         `Put`: temp, write, fsync, rename, fsync the directory. diskv: the
//!         same key, `WriteStream(sync=true)`: temp, write, fsync, rename (no
//!         directory fsync). Both Go sides get the bytes in memory and hash with
//!         crypto/sha256.
//!   get   ours: `casOpen` (lstat, open, fstat) + read to EOF + close. Go:
//!         `Get` / `Read` (open, fstat, read, close).
//!   has   ours: `casHas` (lstat). Go: `Has` (stat).
//! One op = 16 distinct blobs of 4 KiB (a fresh generation each call, so no op
//! is a dedup hit); `put_64k` = one blob of 64 KiB. Count = blobs / bytes, the
//! sides must agree. Ratios are ours/Go by wall time (these ops are
//! syscall-bound, cycles would miss the kernel's share); the verdict is the
//! WORST ratio over the three sides' best of the rounds.
//!
//! What ours does that neither Go side does (so the numbers are fair, not
//! equal): the cross-process flock around the commit, the lstat/fstat
//! regular-file check on every read. What the Go sides do that ours does not:
//! flatfs tracks disk usage and serialises writes to one key; diskv chmods the
//! temp file.
//!
//! WHICH ROW IS WHICH. Every row but `put_rc` uses `Options.refcount = false`:
//! that is what axp runs (it never deletes through the store) and the only
//! configuration whose work equals flatfs's, so those rows make the verdict.
//! `put_rc` is the DEFAULT store (`refcount = true`): each put also writes a
//! `.rc` sidecar through its own temp + fsync + rename + directory fsync, work
//! neither Go side does. It is printed against the same Go `put`, marked info,
//! and kept out of the verdict; read its ratio as the price of refcounting.
//!
//! Rounds: `BENCH_ROUNDS` (default 5) is the number of timed runs of EACH side
//! per row, and each side keeps its best; inside one run both sides double the
//! batch to over 100 ms and keep the best of five batches. So the round counts
//! are equal on both sides.

const std = @import("std");
const bench = @import("testkit").bench;
const blobstore = @import("blobstore");
const Store = blobstore.Store;

const bench_name = "bench-blobstore";
const default_dir = ".zig-cache/bench-blobstore";
const n_blobs = 16;
const small_len = 4096;
const big_len = 64 << 10;

const Op = enum { put, put_rc, put_64k, get, has };

const Ctx = struct {
    io: std.Io = undefined,
    op: Op = .put,
    /// The op `store` was prepared for.
    prepared: ?Op = null,
    root: []const u8 = "",
    store: Store = undefined,
    gen: u64 = 0,
    base_small: [small_len]u8 = undefined,
    base_big: []u8 = &.{},
    buf: []u8 = &.{},
    digests: [n_blobs]blobstore.Digest = undefined,
};

fn fill(c: *Ctx, big: bool, gen: u64, i: usize) []const u8 {
    const len: usize = if (big) big_len else small_len;
    const dst = c.buf[0..len];
    @memcpy(dst, if (big) c.base_big else c.base_small[0..]);
    std.mem.writeInt(u64, dst[0..8], gen, .little);
    std.mem.writeInt(u64, dst[8..16], i, .little);
    return dst;
}

fn prepare(c: *Ctx) void {
    const cwd = std.Io.Dir.cwd();
    cwd.deleteTree(c.io, c.root) catch {};
    cwd.createDirPath(c.io, c.root) catch @panic("bench-blobstore: mkdir");
    var pb: [512]u8 = undefined;
    const base = std.mem.print(&pb, "{s}/s", .{c.root}) catch unreachable;
    // the Store keeps `base` by reference: give it storage that lives on
    const owned = std.heap.page_allocator.dupe(u8, base) catch @panic("oom"); // global-alloc-ok: bench driver, the Store borrows this path for the whole run
    c.store = Store.initOptions(c.io, owned, .{ .refcount = c.op == .put_rc }) catch @panic("bench-blobstore: init");
    c.gen = 0;
    if (c.op == .get or c.op == .has) {
        for (0..n_blobs) |i| c.digests[i] = c.store.putBytes(fill(c, false, 0, i)) catch @panic("bench-blobstore: seed");
    }
    c.prepared = c.op;
}

fn once(c: *Ctx) u64 {
    if (c.prepared == null or c.prepared.? != c.op) prepare(c);
    var t: u64 = 0;
    switch (c.op) {
        .put, .put_rc => {
            c.gen += 1;
            for (0..n_blobs) |i| {
                _ = c.store.putBytes(fill(c, false, c.gen, i)) catch @panic("bench-blobstore: put");
                t += 1;
            }
        },
        .put_64k => {
            c.gen += 1;
            _ = c.store.putBytes(fill(c, true, c.gen, 0)) catch @panic("bench-blobstore: put_64k");
            t = big_len;
        },
        .get => for (c.digests) |d| {
            const f = (c.store.open(d) catch @panic("bench-blobstore: open")) orelse @panic("bench-blobstore: missing");
            defer f.close(c.io);
            var r = f.reader(c.io, &.{});
            const got = r.interface.readSliceShort(c.buf[0..small_len]) catch @panic("bench-blobstore: read");
            t += got;
        },
        .has => for (c.digests) |d| {
            if (c.store.has(d)) t += 1;
        },
    }
    return t;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const dir_path = init.environ_map.get("BENCH_DIR") orelse default_dir;
    try cwd.createDirPath(io, dir_path);
    const abs = try cwd.realPathFileAlloc(io, dir_path, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{ .io = io };
    ctx.root = try std.mem.print(try arena.alloc(u8, 400), "{s}/ours", .{dir_path});
    ctx.base_big = try arena.alloc(u8, big_len);
    ctx.buf = try arena.alloc(u8, big_len);
    for (&ctx.base_small, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    for (ctx.base_big, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = "modules/blobstore/tools/go_bench", .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "put", .op = .put, .ref = "put", .alt = "put_diskv", .wall_only = true },
        // The DEFAULT store (refcount sidecar: a second temp + fsync + rename +
        // directory fsync per put). Paired with the same Go `put`, but flatfs does
        // no bookkeeping of this kind, so it is shown, not in the verdict.
        .{ .name = "put_rc", .op = .put_rc, .ref = "put", .alt = "put_diskv", .wall_only = true, .info = true },
        .{ .name = "put_64k", .op = .put_64k, .ref = "put_64k", .alt = "put_64k_diskv", .wall_only = true },
        .{ .name = "get", .op = .get, .ref = "get", .alt = "get_diskv", .wall_only = true },
        .{ .name = "has", .op = .has, .ref = "has", .alt = "has_diskv", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/flatfs = {d:.2} (best {d:.2}); worst ours/fastest = {d:.2}\n", .{ s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× go-ds-flatfs v0.6.1 · fastest {d:.2}× diskv v3.0.1 (measured <today>)\nref: {s}\nalt: {s}\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0, s.banner, s.alt_banner });

    try w.flush();
    return 0;
}
