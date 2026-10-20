// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tz` against glibc `localtime_r`/`mktime` (the
//! reference), with Go `time` as a second column -- the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tz` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cc` (the system C
//! compiler, linked against the system glibc), `go` 1.26 (standard library only;
//! `tools/go_bench`) and the PINNED tzdata tree
//! `.zig-cache/tz-gen/2026a/zoneinfo` (built by
//! `scripts/gen/tz-gen/fetch-and-build.sh`, SHA-256-pinned release 2026a, `zic -b
//! fat`). The host's /usr/share/zoneinfo is a different release and is never
//! read: glibc is pointed at the pinned tree with TZDIR, Go is handed the zone
//! files through `time.LoadLocationFromTZData`. Run from the repository root.
//!
//! Every workload converts 250 000 deterministic inputs in each of four zones
//! (Europe/Prague, America/New_York, Australia/Sydney, Asia/Kolkata) = 1 000 000
//! per op. The inputs are written to the work directory and read by all three
//! sides. Ours is a lookup of the zone by `find` once, then the call per input;
//! glibc has one active zone at a time (TZ=:<zone>, `tzset` between zones, NOT
//! timed -- the per-call cost is what is measured); Go loads each location once.
//!
//!   utc_to_offset_table   instants 1970..2037 (explicit-transition era):
//!                         `offsetAt` / `localtime_r` -> `tm_gmtoff` / `Zone()` offset
//!   utc_to_offset_footer  instants 2040..2100 (POSIX-rule era), the same calls
//!   local_to_utc          wall-clock times 2000..2037, ~10 % within 2 h of an
//!                         offset change (gaps and folds): `localToUnix(...,
//!                         .compatible)` / `mktime` with tm_isdst = -1 / `time.Date`
//!   abbrev                INFO, not in the verdict: `abbrevAt` / `tm_zone` / the
//!                         Go zone name, each hashed (same function on all sides)
//!
//! Before anything is timed, each foreign side is run in `dump` mode and its
//! value for EVERY input is compared with ours. The offset and abbreviation
//! workloads must agree on all of them. `mktime` and `time.Date` do not promise
//! which instant they pick in a gap or a fold, so for local_to_utc every input
//! on which glibc or Go differs from ours (`compatible`: fold -> earlier, gap ->
//! later) is EXCLUDED from all three sides and counted in the output; the
//! timed workload is the rest. The result count of every workload (the sum of the
//! values, wrapping) must then agree across the sides. The sides alternate for
//! BENCH_ROUNDS (default 3) rounds, each keeping its best; ratios are
//! ours/glibc by wall time; the verdict is the worst. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const datefmt = @import("datefmt");
const tz = @import("tz");

const bench_name = "bench-tz";
const work_dir = ".zig-cache/bench-tz";
const tzdir_rel = ".zig-cache/tz-gen/2026a/zoneinfo";
const release = "2026a";
const c_src = "modules/tz/tools/glibc_bench/driver.c";
const go_dir = "modules/tz/tools/go_bench";
const per_zone = 250_000;
const compared_prefix = 10_000;

const zone_names = [4][]const u8{ "Europe/Prague", "America/New_York", "Australia/Sydney", "Asia/Kolkata" };

const Kind = enum { offset, local, abbrev };
const Work = struct { name: []const u8, kind: Kind, lo: i64 = 0, hi: i64 = 0, info: bool = false };
const works = [_]Work{
    .{ .name = "utc_to_offset_table", .kind = .offset, .lo = 0, .hi = 2145916800 }, // 1970-01-01 .. 2038-01-01
    .{ .name = "utc_to_offset_footer", .kind = .offset, .lo = 2208988800, .hi = 4133980800 }, // 2040-01-01 .. 2101-01-01
    .{ .name = "local_to_utc", .kind = .local, .lo = 946684800, .hi = 2145916800 }, // 2000-01-01 .. 2038-01-01
    .{ .name = "abbrev", .kind = .abbrev, .lo = 0, .hi = 2145916800, .info = true },
};

/// One local wall-clock time; the layout the C and Go sides read (6 x i32).
const Rec = extern struct { y: i32, m: i32, d: i32, hh: i32, mm: i32, ss: i32 };

const Data = struct {
    zones: [4]*const tz.Zone,
    /// Per workload, per zone.
    times: [works.len][4][]const i64,
    recs: [4][]const Rec,
};

fn hashAbbr(s: []const u8) u64 {
    var h: u64 = 0;
    for (s) |c| h = h *% 131 +% c;
    return h;
}

/// Our value for input `i` of zone `z` in workload `wi`: what the other sides
/// print per input in `dump` mode.
inline fn value(d: *const Data, wi: usize, z: usize, i: usize) i64 {
    const zone = d.zones[z];
    switch (works[wi].kind) {
        .offset => return tz.offsetAt(zone, d.times[wi][z][i]).off,
        .abbrev => return @bitCast(hashAbbr(tz.abbrevAt(zone, d.times[wi][z][i]))),
        .local => {
            const r = d.recs[z][i];
            return tz.localToUnix(zone, r.y, @intCast(r.m), @intCast(r.d), @intCast(r.hh), @intCast(r.mm), @intCast(r.ss), .compatible) catch @panic("local_to_utc: unexpected error");
        },
    }
}

const Ctx = struct { d: *const Data, op: usize = 0 };

fn once(c: *Ctx) u64 {
    const d = c.d;
    var sum: u64 = 0;
    switch (works[c.op].kind) {
        .offset => for (0..4) |z| {
            const zone = d.zones[z];
            for (d.times[c.op][z]) |t| sum +%= @bitCast(@as(i64, tz.offsetAt(zone, t).off));
        },
        .abbrev => for (0..4) |z| {
            const zone = d.zones[z];
            for (d.times[c.op][z]) |t| sum +%= hashAbbr(tz.abbrevAt(zone, t));
        },
        .local => for (0..4) |z| {
            const zone = d.zones[z];
            for (d.recs[z]) |r| {
                const v = tz.localToUnix(zone, r.y, @intCast(r.m), @intCast(r.d), @intCast(r.hh), @intCast(r.mm), @intCast(r.ss), .compatible) catch @panic("local_to_utc: unexpected error");
                sum +%= @bitCast(v);
            }
        },
    }
    return sum;
}

// ── inputs ───────────────────────────────────────────────────────────────────

fn genTimes(arena: std.mem.Allocator, r: std.Random, lo: i64, hi: i64) ![]i64 {
    const out = try arena.alloc(i64, per_zone);
    for (out) |*t| t.* = r.intRangeLessThan(i64, lo, hi);
    return out;
}

fn recOf(local: i64) Rec {
    const p = datefmt.unixToParts(local);
    return .{ .y = p.year, .m = @intCast(p.month), .d = @intCast(p.day), .hh = @intCast(p.hour), .mm = @intCast(p.minute), .ss = @intCast(p.second) };
}

/// ~10 % of the wall-clock times lie within 2 h of an explicit offset change of
/// the zone in the range (a gap or a fold when the change is a DST step); the
/// rest are uniform. A zone without a change in the range (Kolkata) gets uniform
/// times only.
fn genLocal(arena: std.mem.Allocator, r: std.Random, zone: *const tz.Zone, lo: i64, hi: i64) ![]Rec {
    const out = try arena.alloc(Rec, per_zone);
    var first: usize = 0;
    while (first < zone.trans.len and zone.trans[first].ts < lo) first += 1;
    var last = first;
    while (last < zone.trans.len and zone.trans[last].ts < hi) last += 1;
    for (out) |*o| {
        var local = r.intRangeLessThan(i64, lo, hi);
        if (last > first and r.uintLessThan(u8, 10) == 0) {
            const k = first + r.uintLessThan(usize, last - first);
            const before: i64 = if (k == 0) zone.init_off else zone.trans[k - 1].off;
            local = zone.trans[k].ts + before + r.intRangeAtMost(i64, -7200, 7200);
        }
        o.* = recOf(local);
    }
    return out;
}

fn writeIn(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, comptime T: type, parts: [4][]const T) !void {
    var buf: std.Io.Writer.Allocating = .init(arena);
    for (parts) |p| try buf.writer.writeInt(u64, p.len, .little);
    for (parts) |p| try buf.writer.writeAll(std.mem.sliceAsBytes(p));
    try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.in", .{name}), .data = buf.written() });
}

/// Run a foreign program in `dump` mode and return its per-input values.
fn dumpSide(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, abs: []const u8, exe: []const u8, side: []const u8, name: []const u8, total: usize) ![]const i64 {
    const outname = try arena.print("{s}.{s}.out", .{ name, side });
    const outpath = try arena.print("{s}/{s}", .{ abs, outname });
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name, "dump", outpath } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} dump of {s} failed:\n{s}\n", .{ bench_name, side, name, res.stderr });
        return error.ForeignFailed;
    }
    const bytes = try dir.readFileAlloc(io, outname, arena, .limited(64 << 20));
    if (bytes.len != total * 8) {
        std.debug.print("{s}: {s} dump of {s} has {d} values, expected {d}\n", .{ bench_name, side, name, bytes.len / 8, total });
        return error.ForeignFailed;
    }
    const out = try arena.alloc(i64, total);
    @memcpy(std.mem.sliceAsBytes(out), bytes);
    return out;
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

    // The pinned tree: a missing one is a hard failure, never a fall back to the
    // host's zoneinfo (a different release).
    const tzdir = cwd.realPathFileAlloc(io, tzdir_rel, arena) catch {
        std.debug.print("{s}: {s} is missing -- run scripts/gen/tz-gen/fetch-and-build.sh first\n", .{ bench_name, tzdir_rel });
        return 1;
    };
    const ver = cwd.readFileAlloc(io, tzdir_rel ++ "/+VERSION", arena, .limited(64)) catch "";
    if (!std.mem.eql(u8, std.mem.trim(u8, ver, " \n"), release)) {
        std.debug.print("{s}: {s}/+VERSION is not {s}\n", .{ bench_name, tzdir_rel, release });
        return 1;
    }
    try dir.writeFile(io, .{ .sub_path = "tzdir.txt", .data = try arena.print("{s}\n", .{tzdir}) });

    var d: Data = undefined;
    for (zone_names, 0..) |n, z| d.zones[z] = tz.find(n) orelse @panic("zone missing");
    var prng = std.Random.DefaultPrng.init(0x747a_6265_6e63);
    const r = prng.random();
    for (works, 0..) |wk, wi| {
        for (0..4) |z| {
            switch (wk.kind) {
                .offset => d.times[wi][z] = try genTimes(arena, r, wk.lo, wk.hi),
                .abbrev => d.times[wi][z] = d.times[0][z], // the table-era instants again
                .local => {
                    d.times[wi][z] = &.{};
                    d.recs[z] = try genLocal(arena, r, d.zones[z], wk.lo, wk.hi);
                },
            }
        }
    }
    const total = 4 * per_zone;

    const cexe = try bench.buildForeign(arena, io, bench_name, &.{"cc"}, abs, c_src, &.{});
    const gexe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("data: tzdata {s} pinned tree {s}; {d} inputs per op ({d} per zone x 4: {s}, {s}, {s}, {s})\n", .{ release, tzdir_rel, total, per_zone, zone_names[0], zone_names[1], zone_names[2], zone_names[3] });

    // ── pre-checks: every foreign value against ours ─────────────────────────
    var excluded_c: usize = 0;
    var excluded_go: usize = 0;
    var excluded_any: usize = 0;
    var gaps: usize = 0;
    var folds: usize = 0;
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        switch (wk.kind) {
            .local => try writeIn(arena, io, dir, wk.name, Rec, d.recs),
            else => try writeIn(arena, io, dir, wk.name, i64, d.times[wi]),
        }
        const cv = try dumpSide(arena, io, dir, abs, cexe, "glibc", wk.name, total);
        const gv = try dumpSide(arena, io, dir, abs, gexe, "go", wk.name, total);
        var bad_c: usize = 0;
        var bad_go: usize = 0;
        var first_bad: ?struct { z: usize, i: usize, ours: i64, c: i64, go: i64 } = null;
        var k: usize = 0;
        var keep: [4]std.ArrayList(Rec) = @splat(.empty);
        for (0..4) |z| for (0..per_zone) |i| {
            const ov = value(&d, wi, z, i);
            const c_ok = cv[k] == ov;
            const g_ok = gv[k] == ov;
            if (!c_ok) bad_c += 1;
            if (!g_ok) bad_go += 1;
            if (!(c_ok and g_ok)) {
                if (first_bad == null) first_bad = .{ .z = z, .i = i, .ours = ov, .c = cv[k], .go = gv[k] };
                if (wk.kind == .local) excluded_any += 1;
            } else if (wk.kind == .local) try keep[z].append(arena, d.recs[z][i]);
            if (wk.kind == .local) switch (tz.resolveLocal(d.zones[z], recSeconds(d.recs[z][i]))) {
                .unique => {},
                .ambiguous => folds += 1,
                .nonexistent => gaps += 1,
            };
            k += 1;
        };
        // The prefix the brief asks for, reported separately so a disagreement
        // right at the start is visible.
        var bad_prefix: usize = 0;
        for (0..compared_prefix) |i| {
            if (cv[i] != value(&d, wi, 0, i) and wk.kind != .local) bad_prefix += 1;
            if (gv[i] != value(&d, wi, 0, i) and wk.kind != .local) bad_prefix += 1;
        }
        try w.print("pre-check {s}: {d} inputs; glibc differs on {d}, go differs on {d}; first {d} (zone 0) differing: {d}\n", .{ wk.name, total, bad_c, bad_go, compared_prefix, bad_prefix });
        if (wk.kind != .local) {
            if (bad_c != 0 or bad_go != 0) {
                const fb = first_bad.?;
                try w.print("{s}: FAILED -- {s} disagrees with the reference (zone {s}, input {d}: ours {d}, glibc {d}, go {d})\n", .{ bench_name, wk.name, zone_names[fb.z], fb.i, fb.ours, fb.c, fb.go });
                try w.flush();
                return 1;
            }
        } else {
            excluded_c = bad_c;
            excluded_go = bad_go;
            var kept: [4][]const Rec = undefined;
            for (0..4) |z| kept[z] = keep[z].items;
            // Replace the inputs by the agreed subset; every side now times that.
            for (0..4) |z| d.recs[z] = kept[z];
            try writeIn(arena, io, dir, wk.name, Rec, d.recs);
        }
    }
    if (bench.selected("local_to_utc", filters)) {
        const kept_n = d.recs[0].len + d.recs[1].len + d.recs[2].len + d.recs[3].len;
        try w.print("local_to_utc inputs: {d} generated ({d} in a gap, {d} in a fold under ours); EXCLUDED where glibc or go differs from `compatible`: {d} (glibc differs on {d}, go on {d}); timed: {d}\n", .{ total, gaps, folds, excluded_any, excluded_c, excluded_go, kept_n });
    }
    try w.flush();

    // ── timing ───────────────────────────────────────────────────────────────
    var ws: [works.len]bench.Work(usize) = undefined;
    for (works, 0..) |wk, wi| ws[wi] = .{ .name = wk.name, .op = wi, .ref = wk.name, .alt = wk.name, .ref_exe = 0, .alt_exe = 1, .info = wk.info };
    var ctx: Ctx = .{ .d = &d };
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ cexe, gexe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, &ws, w);
    try w.print("reference: {s}\nalt: {s}\nworst ours/glibc = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× glibc localtime_r/mktime (tzdata 2026a pinned tree) · fastest {d:.2}× vs Go time (measured 2026-10-20)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}

fn recSeconds(r: Rec) i64 {
    return datefmt.partsToUnix(.{ .year = r.y, .month = @intCast(r.m), .day = @intCast(r.d), .hour = @intCast(r.hh), .minute = @intCast(r.mm), .second = @intCast(r.ss) });
}
