// SPDX-License-Identifier: MIT

//! Comparative benchmark: `diskfree` against Go's `github.com/moby/sys/mountinfo`
//! v0.7.3 (the reference: the mountinfo reader Docker/runc use), with
//! `github.com/prometheus/procfs` v0.21.1 as the second reader and
//! `golang.org/x/sys` v0.49.0 `unix.Statfs` for the syscall. The program behind
//! the `**Performance:**` line of the maturity card (CONVENTIONS.md section 9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-diskfree` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and the
//! three modules above in the module cache (`GOPROXY=off`). Run from the
//! repository root. Foreign side: `tools/go_bench`.
//!
//! One op = the whole corpus / one call, as named:
//!   parse_mountinfo  a 120-row mountinfo text of a fixed seed, written by this
//!                    driver into `.zig-cache/bench-diskfree/mountinfo.txt` (the
//!                    Go side reads the same file): realistic rows with 0-2
//!                    optional fields and ~12 % `\040` escapes in the mount
//!                    point. Ours `mountinfo.parseMountinfo` into an arena that
//!                    is reset (capacity kept) per op; Go
//!                    `mountinfo.GetMountsFromReader(bytes.NewReader, nil)`,
//!                    which allocates per row and string (GC). Both unescape
//!                    root, mount point, fs type and source and return the ids
//!                    and device numbers as integers. Count = sum of ids, major,
//!                    minor and the four string lengths over all rows.
//!   live_mountinfo   the whole live path: open and read this process's
//!                    `/proc/.../mountinfo` and parse it. Ours
//!                    `mountinfo.readMountinfo`; ref Go `mountinfo.GetMounts(nil)`
//!                    (reads `/proc/thread-self/mountinfo`, locks the OS thread);
//!                    alt `procfs.GetMounts()` (`/proc/self/mountinfo`; it does NOT
//!                    unescape and builds a map per option field, so it does less
//!                    and more than the others). Count = rows + sum of ids.
//!   statfs           one `statfs("/")`: ours `diskfree.query`; Go
//!                    `unix.Statfs`. Count = blocks + name_max + type magic.
//!   lookup_64        INFORMATIONAL, ours only: `lookup.containing` of 64 paths
//!                    over the corpus table (no reference does this).
//!   table_live       INFORMATIONAL, ours only: `table.readTable` (read the
//!                    mount table, one statfs per distinct mount point, filter).
//!
//! Ratios are ours/Go by wall time; the verdict is the WORST ratio. Arguments
//! filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const diskfree = @import("diskfree");

const bench_name = "bench-diskfree";
const work_dir = ".zig-cache/bench-diskfree";
const go_dir = "modules/diskfree/tools/go_bench";
const rows_n = 120;

const Op = enum { parse_mountinfo, live_mountinfo, statfs, lookup_64, table_live };

const Ctx = struct {
    op: Op = .parse_mountinfo,
    io: std.Io,
    text: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    entries: []diskfree.mountinfo.MountinfoEntry = &.{},
    paths: [64][]const u8 = undefined,
};

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    switch (c.op) {
        .parse_mountinfo => {
            _ = c.arena.reset(.retain_capacity);
            const es = diskfree.mountinfo.parseMountinfo(c.arena.allocator(), c.text) catch @panic("bench-diskfree: parse");
            for (es) |e| {
                t += @as(u64, e.mount_id) + e.parent_id + e.dev_major + e.dev_minor;
                t += e.root.len + e.mount_point.len + e.fs_type.len + e.mount_source.len;
            }
        },
        .live_mountinfo => {
            _ = c.arena.reset(.retain_capacity);
            const es = (diskfree.mountinfo.readMountinfo(c.arena.allocator(), c.io) catch @panic("bench-diskfree: live")) orelse @panic("bench-diskfree: no /proc");
            t = es.len;
            for (es) |e| t += @as(u64, e.mount_id) + e.parent_id;
        },
        .statfs => {
            const u = diskfree.query("/") catch @panic("bench-diskfree: statfs");
            t = u.blocks_total + @as(u64, @intCast(u.name_max)) + u.fs_type_magic;
        },
        .lookup_64 => for (c.paths) |p| {
            t += (diskfree.lookup.containing(c.entries, p) catch @panic("bench-diskfree: lookup") orelse 999) + 1;
        },
        .table_live => {
            _ = c.arena.reset(.retain_capacity);
            const o = (diskfree.table.readTable(c.arena.allocator(), c.io, .{}) catch @panic("bench-diskfree: table")) orelse @panic("bench-diskfree: no /proc");
            t = o.table.rows.len;
        },
    }
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

const fs_types = [_][]const u8{ "ext4", "tmpfs", "proc", "sysfs", "overlay", "cgroup2", "vfat", "squashfs", "devpts", "xfs" };

fn buildCorpus(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (0..rows_n) |i| {
        const ty = fs_types[r.uintLessThan(usize, fs_types.len)];
        const space = r.uintLessThan(u8, 8) == 0;
        try out.print(arena, "{d} {d} {d}:{d} / /mnt/m{d}{s}d{d} rw,nosuid,nodev,relatime", .{
            i + 20, if (i == 0) 20 else r.intRangeAtMost(usize, 20, i + 19), r.uintLessThan(u8, 9), r.uintLessThan(u16, 300), i, if (space) "\\040" else "", i,
        });
        switch (r.uintLessThan(u8, 3)) {
            0 => {},
            1 => try out.print(arena, " shared:{d}", .{r.uintLessThan(u16, 400)}),
            else => try out.print(arena, " shared:{d} master:{d}", .{ r.uintLessThan(u16, 400), r.uintLessThan(u16, 400) }),
        }
        try out.print(arena, " - {s} /dev/src{d} rw,size={d}k,mode=755\n", .{ ty, i, r.uintLessThan(u32, 1 << 20) });
    }
    return out.items;
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var prng = std.Random.DefaultPrng.init(0xd15c_f4ee);
    const text = try buildCorpus(arena, prng.random());
    try dir.writeFile(io, .{ .sub_path = "mountinfo.txt", .data = text });
    std.debug.print("{s}: mountinfo.txt: {d} rows, {d} bytes\n", .{ bench_name, rows_n, text.len });

    // global-alloc-ok: a benchmark program, not module code; the arena's backing store.
    var ctx: Ctx = .{ .io = io, .text = text, .arena = .init(std.heap.page_allocator) };
    defer ctx.arena.deinit();
    ctx.entries = try diskfree.mountinfo.parseMountinfo(arena, text);
    if (ctx.entries.len != rows_n) return error.CorpusRowsLost;
    for (&ctx.paths) |*p| {
        const e = ctx.entries[prng.random().uintLessThan(usize, ctx.entries.len)];
        p.* = try std.fmt.allocPrint(arena, "{s}/sub/{d}/../file", .{ e.mount_point, prng.random().int(u16) });
    }

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "parse_mountinfo", .op = .parse_mountinfo, .ref = "parse_mountinfo", .wall_only = true },
        .{ .name = "live_mountinfo", .op = .live_mountinfo, .ref = "live_moby", .alt = "live_procfs", .wall_only = true },
        .{ .name = "statfs", .op = .statfs, .ref = "statfs", .wall_only = true },
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
    try w.print("\nworst ours/Go moby = {d:.2} (best {d:.2})", .{ s.worst_ref, s.best_ref });
    if (s.worst_fast) |f| try w.print("; worst ours/min(moby, procfs) = {d:.2}", .{f});
    try w.print("\n", .{});
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go moby/sys/mountinfo v0.7.3 · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });

    // Informational rows, ours only.
    const cyc: bench.Cycles = .open();
    defer cyc.close();
    for ([_]Op{ .lookup_64, .table_live }) |op| {
        ctx.op = op;
        var best: f64 = std.math.inf(f64);
        for (0..rounds) |_| best = @min(best, bench.timeIt(io, cyc, once, .{&ctx}, true).ns);
        try w.print("{s:<18} {d:>11.0} ns/op (informational, no reference)\n", .{ @tagName(op), best });
    }
    try w.flush();
    return 0;
}
