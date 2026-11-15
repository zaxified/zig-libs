// SPDX-License-Identifier: MIT

//! Fuzzing the read side against damaged bytes. The fuzzer builds a valid
//! log — appends, rotations, a compaction, compressed segments — then
//! damages its files: flips
//! bytes, cuts them short, adds junk, in the segments (raw and compressed),
//! the manifest and the
//! index files. Then everything that reads runs over it: a writer's `open`,
//! a reader's, iteration with `resync` past every damage, `verify`, `seek`,
//! `seekTime`. None of it may panic, leak, loop forever or return an error
//! outside its set. Without damage, every record must come back, in order,
//! and `verify` must be clean.

const std = @import("std");
const seglog = @import("root.zig");
const Log = seglog.Log;
const SimStorage = seglog.SimStorage;
const testing = std.testing;
/// `testing.allocator`, except under the driver: there a `SafeAllocator`
/// that still finds leaks but records no stack traces — unwinding the stack
/// at every allocation was most of a run's time.
var gpa: std.mem.Allocator = testing.allocator;

test "fuzz: open, read, resync, verify and seek never misbehave on damaged files" {
    try testing.fuzz({}, fuzzEntry, .{});
}

fn fuzzEntry(_: void, smith: *std.testing.Smith) !void {
    return fuzzOne(std.testing.Smith, smith);
}

/// The driver's source of choices: `Smith`'s methods, from a PRNG. Not
/// `Smith{ .in = random bytes }`: that reads 8 bytes per value and answers
/// the range's minimum for anything outside it — for random bytes almost
/// always, so the harness took the same branch every time (measured: 0 of
/// 20 000 runs ever compressed a segment).
const Rng = struct {
    r: std.Random,
    pub fn valueRangeAtMost(self: *Rng, comptime T: type, lo: T, hi: T) T {
        return self.r.intRangeAtMost(T, lo, hi);
    }
    pub fn value(self: *Rng, comptime T: type) T {
        return self.r.int(T);
    }
    pub fn bytes(self: *Rng, buf: []u8) void {
        self.r.bytes(buf);
    }
    pub fn index(self: *Rng, len: usize) usize {
        return self.r.uintLessThan(usize, len);
    }
};

// ── the deterministic driver ─────────────────────────────────────────────────
//
// `zig build --fuzz` is for exploring; for a verdict it is blind (no progress,
// exit 0 on a crash, no limit per input: a hang looks like a slow run). This
// runs the same harness over inputs from seeds, in the ordinary test binary:
//
//     SEGLOG_FUZZ=<runs>[,<first seed>]  SEGLOG_FUZZ_MS=<limit per input, 2000>
//     SEGLOG_FUZZ_SEEDFILE=<path>        the current seed, for a crash
//
// A hang is `HANG seed=N` and exit 124 within the limit; a failing input is
// `FAIL seed=N`; a panic leaves its seed in the seed file. Any seed replays
// with `SEGLOG_FUZZ=1,N`.

var current_seed = std.atomic.Value(u64).init(0);
var current_start = std.atomic.Value(u64).init(0);

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn watchdog(limit_ns: u64) void {
    while (true) {
        const req: std.os.linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        _ = std.os.linux.nanosleep(&req, null);
        const start = current_start.load(.acquire);
        if (start != 0 and nowNs() -| start > limit_ns) {
            std.debug.print("HANG seed={d} (over {d} ms)\n", .{ current_seed.load(.acquire), limit_ns / std.time.ns_per_ms });
            std.process.exit(124);
        }
    }
}

/// One saved input (e.g. `.zig-cache/f/crash` from `zig build --fuzz`),
/// under the same watchdog.
fn replayFile(path: []const u8) !void {
    var pb: [std.fs.max_path_bytes:0]u8 = undefined;
    @memcpy(pb[0..path.len], path);
    pb[path.len] = 0;
    const rc = std.os.linux.open(pb[0..path.len :0], .{ .ACCMODE = .RDONLY }, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.FileNotFound;
    const fd: i32 = @intCast(rc);
    defer _ = std.os.linux.close(fd);
    var buf: [1 << 16]u8 = undefined;
    const n = std.os.linux.read(fd, &buf, buf.len);
    if (std.os.linux.errno(n) != .SUCCESS) return error.InputOutput;
    const limit_ms = if (std.testing.environ.getPosix("SEGLOG_FUZZ_MS")) |m| try std.fmt.parseInt(u64, m, 10) else 2000;
    const dog = try std.Thread.spawn(.{}, watchdog, .{limit_ms * std.time.ns_per_ms});
    dog.detach();
    current_start.store(nowNs(), .release);
    var smith: std.testing.Smith = .{ .in = buf[0..n] };
    try fuzzOne(std.testing.Smith, &smith);
    current_start.store(0, .release);
    std.debug.print("REPLAY ok ({d} bytes)\n", .{n});
}

test "fuzz driver: deterministic seeds, a limit per input (SEGLOG_FUZZ)" {
    if (std.testing.environ.getPosix("SEGLOG_FUZZ_INPUT")) |path| return replayFile(path);
    const spec = std.testing.environ.getPosix("SEGLOG_FUZZ") orelse return error.SkipZigTest;
    var parts = std.mem.splitScalar(u8, spec, ',');
    const runs = try std.fmt.parseInt(u64, parts.next().?, 10);
    const first = if (parts.next()) |f| try std.fmt.parseInt(u64, f, 10) else 0;
    const limit_ms = if (std.testing.environ.getPosix("SEGLOG_FUZZ_MS")) |m| try std.fmt.parseInt(u64, m, 10) else 2000;
    const seed_fd: ?std.posix.fd_t = if (std.testing.environ.getPosix("SEGLOG_FUZZ_SEEDFILE")) |path| blk: {
        var pb: [std.fs.max_path_bytes:0]u8 = undefined;
        @memcpy(pb[0..path.len], path);
        pb[path.len] = 0;
        const rc = std.os.linux.open(pb[0..path.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        break :blk if (std.os.linux.errno(rc) == .SUCCESS) @intCast(rc) else null;
    } else null;

    const dog = try std.Thread.spawn(.{}, watchdog, .{limit_ms * std.time.ns_per_ms});
    dog.detach();
    var da: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{ .stack_trace_frames = 0 });
    gpa = da.allocator();
    defer {
        gpa = testing.allocator;
        if (da.deinit() != 0) @panic("fuzz driver: leak");
    }

    const t0 = nowNs();
    var last_report = t0;
    var seed = first;
    while (seed < first + runs) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        if (seed_fd) |fd| {
            var sb: [24]u8 = undefined;
            const txt = std.mem.print(&sb, "{d}\n", .{seed}) catch unreachable;
            _ = std.os.linux.pwrite(fd, txt.ptr, txt.len, 0);
        }
        current_seed.store(seed, .release);
        current_start.store(nowNs(), .release);
        fuzzOne(Rng, &rng) catch |e| {
            std.debug.print("FAIL seed={d}: {t}\n", .{ seed, e });
            return e;
        };
        current_start.store(0, .release);
        const now = nowNs();
        if (now - last_report > std.time.ns_per_s) {
            last_report = now;
            const done = seed + 1 - first;
            std.debug.print("runs={d} of {d} ({d}/s)\n", .{ done, runs, done * std.time.ns_per_s / (now - t0) });
        }
    }
    std.debug.print("DONE runs={d} in {d} ms\n", .{ runs, (nowNs() - t0) / std.time.ns_per_ms });
}

fn dropOdd(_: void, r: seglog.Record) bool {
    return r.lsn % 2 == 0;
}

/// Names the fuzzer may damage.
fn fileName(buf: *[40]u8, which: u8, seg: u64) []const u8 {
    return switch (which % 4) {
        0 => std.mem.print(buf, "seg-{d:0>20}.log", .{seg}) catch unreachable,
        1 => std.mem.print(buf, "seg-{d:0>20}.idx", .{seg}) catch unreachable,
        2 => std.mem.print(buf, "seg-{d:0>20}.zst", .{seg}) catch unreachable,
        else => "MANIFEST",
    };
}

/// One case: a quarter of them a migration from the previous format.
fn fuzzOne(comptime S: type, smith: *S) !void {
    // The first draw is a full-width `value(u64)`, not a ranged one: a ranged draw
    // on `Smith` returns its minimum for almost every seed (check-fuzz-reach R1).
    if (smith.value(u64) % 4 == 0) return fuzzMigration(S, smith);
    return fuzzReadDamaged(S, smith);
}

const migrate_test = @import("migrate_test.zig");

/// A version-1 log of random records, maybe damaged, opened with automatic
/// migration. Undamaged: it must migrate and hold every record in order.
/// Refused: not a byte of it may have changed. Otherwise: anything but a
/// panic, a hang or an error outside the set.
fn fuzzMigration(comptime S: type, smith: *S) !void {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const nseg = smith.valueRangeAtMost(u8, 1, 4);
    const segs = try arena.alloc(migrate_test.Seg, nseg);
    var all: std.ArrayList([]const u8) = .empty;
    for (segs, 0..) |*sg, i| {
        const n = smith.valueRangeAtMost(u8, 0, 12);
        const ps = try arena.alloc([]const u8, n);
        for (ps) |*p| {
            const len = smith.valueRangeAtMost(u8, 8, 80);
            const b = try arena.alloc(u8, len);
            smith.bytes(b);
            p.* = b;
            try all.append(arena, b);
        }
        const newest = i + 1 == nseg;
        sg.* = .{ .id = 5 + i * 2, .payloads = ps, .sealed = !newest or smith.valueRangeAtMost(u8, 0, 3) == 0 };
    }
    try migrate_test.writeV1(&sim, segs, &.{}, null);

    // Damage, maybe: a byte anywhere, or a cut.
    var names: [5][40]u8 = undefined;
    var name_list: [5][]const u8 = undefined;
    name_list[0] = "MANIFEST";
    for (segs, 1..) |sg, k| name_list[k] = std.mem.print(&names[k], "seg-{d:0>20}.log", .{sg.id}) catch unreachable;
    const files = name_list[0 .. nseg + 1];
    const damaged = smith.valueRangeAtMost(u8, 0, 2) == 0;
    if (damaged) {
        const f = sim.fileContent(files[smith.index(files.len)]).?;
        if (f.len > 0) {
            if (smith.valueRangeAtMost(u8, 0, 1) == 0) {
                f[smith.index(f.len)] ^= smith.valueRangeAtMost(u8, 1, 255);
            } else {
                const name = files[smith.index(files.len)];
                const g = sim.fileContent(name).?;
                const st = sim.storage();
                const h = try st.open(name, .open_or_create);
                defer st.close(h);
                try st.truncate(h, smith.index(g.len + 1));
                try st.sync(h);
            }
        }
    }
    var before: [5][]u8 = undefined;
    for (files, 0..) |n, k| before[k] = try arena.dupe(u8, sim.fileContent(n) orelse "");

    var rep: seglog.MigrationReport = .{};
    var log = Log.open(gpa, sim.storage(), .{ .legacy_ts = migrate_test.tsOf, .migration_report = &rep }) catch |e| switch (e) {
        error.MigrationFailed => {
            if (!damaged) return error.UndamagedLogRefused;
            try testing.expect(rep.failure != null);
            for (files, 0..) |n, k| try testing.expectEqualSlices(u8, before[k], sim.fileContent(n) orelse "");
            return;
        },
        error.Corrupt, error.NotFound, error.UnsupportedVersion => {
            if (!damaged) return e;
            return;
        },
        else => return e,
    };
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    var k: usize = 0;
    while (try it.next()) |r| : (k += 1) {
        if (!damaged) try testing.expectEqualSlices(u8, all.items[k], r.payload);
        try testing.expectEqual(@as(u64, k + 1), r.lsn);
    }
    if (!damaged) try testing.expectEqual(all.items.len, k);
    var v = try log.verify(gpa);
    defer v.deinit(gpa);
    try testing.expect(v.clean());
}

fn fuzzReadDamaged(comptime S: type, smith: *S) !void {
    var sim = SimStorage.init(gpa);
    defer sim.deinit();
    // Preallocation on or off: its zero tails and the cut at the seal are
    // read paths too (planted mutants there went unfound while it was off).
    const opts: seglog.Options = .{
        .create = true,
        .index_interval = 64,
        .max_record_len = 512,
        .compression = .{ .frame_size = 256 },
        .preallocate = if (smith.valueRangeAtMost(u8, 0, 1) == 1) 512 else 0,
    };

    // 1. A valid log.
    var appended: u64 = 0;
    var segs: u64 = 0;
    {
        var log = try Log.open(gpa, sim.storage(), opts);
        defer log.close();
        var payload: [96]u8 = undefined;
        const steps = smith.valueRangeAtMost(u8, 1, 40);
        for (0..steps) |_| {
            switch (smith.valueRangeAtMost(u8, 0, 9)) {
                0 => {
                    segs += 1;
                    try log.rotate(segs);
                },
                1 => if (segs >= 2) {
                    _ = log.compact(segs - 1, {}, dropOdd) catch |e| switch (e) {
                        error.NotCompactable => {},
                        else => return e,
                    };
                },
                2 => if (segs >= 2) {
                    _ = log.compress(smith.valueRangeAtMost(u64, 1, segs - 1)) catch |e| switch (e) {
                        error.NotCompressible => {},
                        else => return e,
                    };
                },
                else => {
                    if (segs == 0) {
                        segs = 1;
                        try log.rotate(1);
                    }
                    const n = smith.valueRangeAtMost(u8, 0, payload.len);
                    smith.bytes(payload[0..n]);
                    _ = try log.appendAt(smith.value(i16), payload[0..n]);
                    appended += 1;
                },
            }
        }
    }

    // 2. Damage, maybe. Zeros after the newest segment are not damage: they
    // are what a reservation, or a seal whose cut a crash lost, leaves — the
    // log must read as if they were not there.
    if (segs > 0 and smith.valueRangeAtMost(u8, 0, 3) == 0) {
        var nb: [40]u8 = undefined;
        const name = fileName(&nb, 0, segs);
        if (sim.fileContent(name) != null) {
            var zeros: [64]u8 = @splat(0);
            try sim.appendDurable(name, zeros[0..smith.valueRangeAtMost(u8, 1, zeros.len)]);
        }
    }
    const damages = smith.valueRangeAtMost(u8, 0, 3);
    for (0..damages) |_| {
        var nb: [40]u8 = undefined;
        const seg = if (segs == 0) 1 else smith.valueRangeAtMost(u64, 1, segs);
        const name = fileName(&nb, smith.value(u8), seg);
        const content = sim.fileContent(name) orelse continue;
        if (content.len == 0) continue;
        switch (smith.valueRangeAtMost(u8, 0, 3)) {
            0 => content[smith.index(content.len)] ^= smith.valueRangeAtMost(u8, 1, 255),
            // Near the end, where the structure is: a seal, a seek table, a
            // manifest's CRC. Random offsets almost never land there.
            3 => {
                const tail = @min(content.len, 64);
                content[content.len - tail + smith.index(tail)] ^= smith.valueRangeAtMost(u8, 1, 255);
            },
            1 => {
                const st = sim.storage();
                const h = try st.open(name, .open_or_create);
                defer st.close(h);
                try st.truncate(h, smith.index(content.len));
                try st.sync(h);
            },
            else => {
                var junk: [16]u8 = undefined;
                smith.bytes(&junk);
                try sim.appendDurable(name, junk[0..smith.valueRangeAtMost(u8, 1, junk.len)]);
            },
        }
    }

    // 3. Everything that reads.
    try readEverything(&sim, opts, damages == 0, appended);
    // A reader beside nothing: the same files, read-only.
    var r = Log.openReadOnly(gpa, sim.storage(), .{ .max_record_len = opts.max_record_len }) catch |e| switch (e) {
        error.Corrupt, error.NotFound, error.UnsupportedVersion => return,
        else => return e,
    };
    defer r.close();
    try walk(&r, smith);
}

fn readEverything(sim: *SimStorage, opts: seglog.Options, clean: bool, appended: u64) !void {
    var log = Log.open(gpa, sim.storage(), opts) catch |e| switch (e) {
        // L5: a damaged length field in the active segment over
        // `max_record_len` is refused, not cut as a torn tail (root.zig,
        // `scanTail`). The harness missed it from 2026-09-27 until the
        // driver's seed 755 found it (2026-10-19, same on Zig 0.16).
        error.Corrupt, error.NotFound, error.UnsupportedVersion, error.RecordTooLongForOptions => {
            if (clean) return e; // an undamaged log always opens
            return;
        },
        else => return e,
    };
    defer log.close();
    var report = log.verify(gpa) catch |e| switch (e) {
        error.SegmentGone, error.InvalidPosition, error.UnsupportedVersion => {
            if (clean) return e;
            return;
        },
        else => return e,
    };
    defer report.deinit(gpa);
    if (clean) {
        try testing.expect(report.clean());
        // Compaction dropped some; never more than were appended.
        try testing.expect(report.records <= appended);
    }
}

fn walk(log: *Log, smith: anytype) !void {
    var it = log.iterator(null);
    defer it.deinit();
    var steps: usize = 0;
    while (steps < 10_000) : (steps += 1) {
        const rec = it.next() catch |e| switch (e) {
            error.Corrupt => {
                _ = try it.resync();
                continue;
            },
            error.SegmentGone, error.InvalidPosition, error.UnsupportedVersion => break,
            else => return e,
        } orelse break;
        std.mem.doNotOptimizeAway(rec.payload.len);
    }
    try testing.expect(steps < 10_000); // resync always moves forward
    for (0..4) |_| {
        _ = log.seek(smith.valueRangeAtMost(u64, 1, 64)) catch |e| switch (e) {
            error.Corrupt, error.SegmentGone, error.InvalidPosition, error.UnsupportedVersion => {},
            else => return e,
        };
        _ = log.seekTime(smith.value(i16)) catch |e| switch (e) {
            error.Corrupt, error.SegmentGone, error.InvalidPosition, error.UnsupportedVersion => {},
            else => return e,
        };
    }
}
