// SPDX-License-Identifier: MIT

//! M4 behaviour tests: the simulated file system through the public
//! `std.Io.Dir`/`std.Io.File` API, its crash model, and the search finding a
//! classic crash-consistency bug in real code.

const std = @import("std");
const sched = @import("sched.zig");
const search = @import("search.zig");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;

fn newSim(sim: *Sim, seed: u64) void {
    sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
}

fn runTask(seed: u64, comptime task: anytype, args: anytype) !void {
    var sim: Sim = undefined;
    newSim(&sim, seed);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(task, .{h.io()} ++ args);
    try testing.expectEqual(sched.Outcome.quiescent, sim.run().outcome);
    if (h.failure) |err| return err;
}

// ── the API ────────────────────────────────────────────────────────────────

fn basics(io: Io) !void {
    const cwd = Dir.cwd();
    try cwd.createDirPath(io, "data/logs");
    try testing.expectEqual(Dir.CreatePathStatus.existed, try cwd.createDirPathStatus(io, "data/logs", .default_dir));

    var f = try cwd.createFile(io, "data/a.txt", .{ .read = true });
    try f.writePositionalAll(io, "hello, world", 0);
    try f.writePositionalAll(io, "HELLO", 0);
    var buf: [32]u8 = undefined;
    const n = try f.readPositionalAll(io, &buf, 0);
    try testing.expectEqualStrings("HELLO, world", buf[0..n]);
    try testing.expectEqual(@as(u64, 12), (try f.stat(io)).size);
    try f.setLength(io, 5);
    try testing.expectEqual(@as(u64, 5), try f.length(io));
    f.close(io);
    // Creating an existing file truncates it by default.
    {
        var again = try cwd.createFile(io, "data/a.txt", .{});
        defer again.close(io);
        try testing.expectEqual(@as(u64, 0), try again.length(io));
        try again.writePositionalAll(io, "HELLO", 0);
    }
    // ".." walks up.
    {
        var up = try cwd.createFile(io, "data/logs/../up.txt", .{});
        up.close(io);
        try cwd.access(io, "data/up.txt", .{});
        try cwd.deleteFile(io, "data/up.txt");
    }
    // A directory cannot move into its own subtree.
    try testing.expectError(error.FileBusy, cwd.rename("data", cwd, "data/logs/data", io));

    try testing.expectError(error.PathAlreadyExists, cwd.createFile(io, "data/a.txt", .{ .exclusive = true }));
    try testing.expectError(error.FileNotFound, cwd.openFile(io, "data/missing", .{}));
    try testing.expectError(error.NotDir, cwd.openFile(io, "data/a.txt/x", .{}));
    try testing.expectError(error.IsDir, cwd.deleteFile(io, "data/logs"));
    try testing.expectError(error.DirNotEmpty, cwd.deleteDir(io, "data"));

    // Streaming writer and reader.
    {
        var g = try cwd.createFile(io, "data/b.txt", .{});
        defer g.close(io);
        var wbuf: [8]u8 = undefined;
        var w = g.writerStreaming(io, &wbuf);
        try w.interface.print("{d}-{s}", .{ 42, "answer" });
        try w.interface.flush();
    }
    {
        var g = try cwd.openFile(io, "data/b.txt", .{});
        defer g.close(io);
        var rbuf: [4]u8 = undefined;
        var r = g.readerStreaming(io, &rbuf);
        var out: [32]u8 = undefined;
        const k = try r.interface.readSliceShort(&out);
        try testing.expectEqualStrings("42-answer", out[0..k]);
    }

    try cwd.rename("data/b.txt", cwd, "data/logs/c.txt", io);
    try testing.expectError(error.FileNotFound, cwd.access(io, "data/b.txt", .{}));
    try cwd.access(io, "data/logs/c.txt", .{});
    try testing.expectError(error.PathAlreadyExists, cwd.renamePreserve("data/a.txt", cwd, "data/logs/c.txt", io));

    // Iteration, in creation order.
    var d = try cwd.openDir(io, "data", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    var names: [4][]const u8 = undefined;
    var count: usize = 0;
    while (try it.next(io)) |e| : (count += 1) names[count] = e.name;
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("logs", names[0]);
    try testing.expectEqualStrings("a.txt", names[1]);

    var pbuf: [64]u8 = undefined;
    const plen = try d.realPathFile(io, "logs/c.txt", &pbuf);
    try testing.expectEqualStrings("/data/logs/c.txt", pbuf[0..plen]);

    try cwd.deleteFile(io, "data/logs/c.txt");
    try cwd.deleteDir(io, "data/logs");
}

test "directories and files behave as std.Io.Dir/File promise" {
    try runTask(1, basics, .{});
}

fn atomicReplace(io: Io) !void {
    const cwd = Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = "cfg", .data = "old" });
    var af = try cwd.createFileAtomic(io, "cfg", .{ .replace = true });
    defer af.deinit(io);
    try af.file.writePositionalAll(io, "new contents", 0);
    try af.replace(io);
    var buf: [32]u8 = undefined;
    const got = try cwd.readFile(io, "cfg", &buf);
    try testing.expectEqualStrings("new contents", got);
}

test "File.Atomic replaces a file through a temporary name" {
    try runTask(2, atomicReplace, .{});
}

// ── durability ─────────────────────────────────────────────────────────────

fn writeThenMaybeSync(io: Io, sync_dir: bool) !void {
    const cwd = Dir.cwd();
    var f = try cwd.createFile(io, "rec", .{});
    try f.writePositionalAll(io, "durable?", 0);
    try f.sync(io);
    f.close(io);
    if (sync_dir) {
        const d = try cwd.openDir(io, ".", .{});
        defer d.close(io);
        const as_file: File = .{ .handle = d.handle, .flags = .{ .nonblocking = false } };
        try as_file.sync(io);
    }
}

fn survivesCrash(seed: u64, sync_dir: bool) !?[]const u8 {
    var sim: Sim = undefined;
    newSim(&sim, seed);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(writeThenMaybeSync, .{ h.io(), sync_dir });
    _ = sim.run();
    try testing.expect(h.failure == null);
    sim.crash(h);
    sim.restart(h);
    const got = h.readFile("rec") orelse return null;
    try testing.expectEqualStrings("durable?", got);
    return got;
}

test "a synced file's name survives a crash only once its directory is synced" {
    var lost: usize = 0;
    var kept: usize = 0;
    for (0..40) |seed| {
        if (try survivesCrash(seed, false)) |_| kept += 1 else lost += 1;
        try testing.expect(try survivesCrash(seed, true) != null);
    }
    // Without the directory sync the outcome depends on the seed: both
    // happen.
    try testing.expect(lost > 0 and kept > 0);
}

fn writeUnsynced(io: Io) !void {
    var f = try Dir.cwd().createFile(io, "log", .{});
    defer f.close(io);
    try f.writePositionalAll(io, &([_]u8{0xaa} ** 2048), 0);
    try f.sync(io);
    try f.writePositionalAll(io, &([_]u8{0xbb} ** 2048), 0); // never synced
}

test "unsynced writes survive a crash sector by sector: lost, kept or torn" {
    var outcomes: [3]usize = @splat(0); // all old, all new, mixed
    for (0..40) |seed| {
        var sim: Sim = undefined;
        sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024, .fs = .{ .durability = .journal } });
        defer sim.deinit();
        const h = try sim.addHost(.{});
        try h.spawn(writeUnsynced, .{h.io()});
        _ = sim.run();
        sim.crash(h);
        const got = h.readFile("log").?;
        try testing.expectEqual(@as(usize, 2048), got.len);
        var new: usize = 0;
        for (got, 0..) |b, i| {
            try testing.expect(b == 0xaa or b == 0xbb);
            // A sector is all one or all the other.
            try testing.expectEqual(got[i - i % 512], b);
            if (b == 0xbb) new += 1;
        }
        outcomes[if (new == 0) 0 else if (new == got.len) 1 else 2] += 1;
    }
    try testing.expect(outcomes[0] > 0 and outcomes[1] > 0 and outcomes[2] > 0);
}

// ── faults ─────────────────────────────────────────────────────────────────

const FaultLog = struct { write_err: ?anyerror = null, second_ok: bool = false, short: ?anyerror = null };

fn diskFaults(io: Io, log: *FaultLog) !void {
    var f = try Dir.cwd().createFile(io, "x", .{ .read = true });
    defer f.close(io);
    f.writePositionalAll(io, "first", 0) catch |err| {
        log.write_err = err;
    };
    try f.writePositionalAll(io, "second", 0);
    log.second_ok = true;
    // 64 bytes of capacity: a 100-byte write stops at the limit.
    var big: [100]u8 = @splat('z');
    f.writePositionalAll(io, &big, 0) catch |err| {
        log.short = err;
    };
}

test "a one-shot disk error and the capacity limit surface as errors" {
    var sim: Sim = undefined;
    newSim(&sim, 5);
    defer sim.deinit();
    const h = try sim.addHost(.{ .disk_bytes = 64 });
    try sim.scheduleFault(0, .{ .disk_error = .{ .host = h.id, .op = .write } });
    var log: FaultLog = .{};
    try h.spawn(diskFaults, .{ h.io(), &log });
    _ = sim.run();
    try testing.expectEqual(@as(?anyerror, error.InputOutput), log.write_err);
    try testing.expect(log.second_ok);
    try testing.expectEqual(@as(?anyerror, error.NoSpaceLeft), log.short);
    try testing.expectEqual(@as(usize, 64), h.readFile("x").?.len);
}

test "bit rot flips exactly one bit of a stored file" {
    var sim: Sim = undefined;
    newSim(&sim, 6);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    const original = "the quick brown fox";
    try h.putFile("docs/fox.txt", original);
    sim.applyFault(.{ .bit_rot = h.id });
    const rotten = h.readFile("docs/fox.txt").?;
    var bits: u32 = 0;
    for (rotten, original) |x, y| bits += @popCount(x ^ y);
    try testing.expectEqual(@as(u32, 1), bits);
    // The flip is on the disk, not in a cache: it survives a crash.
    sim.crash(h);
    sim.restart(h);
    bits = 0;
    for (h.readFile("docs/fox.txt").?, original) |x, y| bits += @popCount(x ^ y);
    try testing.expectEqual(@as(u32, 1), bits);
}

fn locks(io: Io) !void {
    const cwd = Dir.cwd();
    var a = try cwd.createFile(io, "lock", .{});
    var b = try cwd.openFile(io, "lock", .{});
    defer b.close(io);
    try testing.expect(try a.tryLock(io, .exclusive));
    try testing.expect(!try b.tryLock(io, .shared));
    a.close(io); // closing releases the lock
    try testing.expect(try b.tryLock(io, .shared));
    // A shared lock keeps an exclusive one out.
    var c = try cwd.openFile(io, "lock", .{});
    defer c.close(io);
    try testing.expect(!try c.tryLock(io, .exclusive));
}

test "file locks exclude each other and are released on close" {
    try runTask(7, locks, .{});
}

fn holdLock(io: Io) !void {
    var a = try Dir.cwd().openFile(io, "lock", .{});
    try testing.expect(try a.tryLock(io, .exclusive));
    try io.sleep(.fromSeconds(100), .awake);
}

fn takeLock(io: Io, got: *bool) !void {
    var a = try Dir.cwd().openFile(io, "lock", .{});
    defer a.close(io);
    got.* = try a.tryLock(io, .exclusive);
}

test "a crash releases the locks the host held" {
    var sim: Sim = undefined;
    newSim(&sim, 8);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.putFile("lock", ""); // durable, so it is still there after the crash
    try h.spawn(holdLock, .{h.io()});
    _ = sim.runFor(ns_per_ms);
    sim.crash(h);
    sim.restart(h);
    var got = false;
    try h.spawn(takeLock, .{ h.io(), &got });
    _ = sim.run();
    try testing.expectEqual(@as(?anyerror, null), h.failure);
    try testing.expect(got);
}

fn printer(io: Io) !void {
    var buf: [16]u8 = undefined;
    var w = File.stdout().writerStreaming(io, &buf);
    try w.interface.print("hello from {s}\n", .{"a host"});
    try w.interface.flush();
}

test "stdout of a simulated host is captured, not printed" {
    var sim: Sim = undefined;
    newSim(&sim, 9);
    defer sim.deinit();
    const h = try sim.addHost(.{});
    try h.spawn(printer, .{h.io()});
    _ = sim.run();
    try testing.expectEqualStrings("hello from a host\n", h.console());
}

// ── the search on a crash-consistency bug ──────────────────────────────────

const block = 1024;

const Saver = struct { careful: bool };

/// Replaces `state` with a new version through a temporary file, the classic
/// pattern. The careless variant forgets to sync the temporary file before
/// the rename, so a crash can leave the new name pointing at torn data.
fn saveLoop(io: Io, saver: *const Saver) !void {
    const cwd = Dir.cwd();
    // On (re)boot, whatever is there must be one whole version.
    var buf: [block + 1]u8 = undefined;
    if (cwd.readFile(io, "state", &buf)) |got| {
        if (got.len != block) return error.TornState;
        for (got) |b| if (b != got[0]) return error.TornState;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var version: u8 = 1;
    while (true) : (version +%= 1) {
        var f = try cwd.createFile(io, "state.tmp", .{});
        const data: [block]u8 = @splat(version);
        try f.writePositionalAll(io, &data, 0);
        if (saver.careful) try f.sync(io);
        f.close(io);
        try cwd.rename("state.tmp", cwd, "state", io);
        if (saver.careful) {
            const d = try cwd.openDir(io, ".", .{});
            defer d.close(io);
            try (File{ .handle = d.handle, .flags = .{ .nonblocking = false } }).sync(io);
        }
        try io.sleep(.fromMilliseconds(7), .awake);
    }
}

fn saverSetup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const saver: *const Saver = @ptrCast(@alignCast(ctx.?));
    const h = try sim.addHost(.{});
    try h.spawnBoot(saveLoop, .{ h.io(), saver });
}

fn saverCase(saver: *Saver) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 256 * 1024, .fs = .{ .durability = .journal } },
        .setup = saverSetup,
        .ctx = saver,
        .duration_ns = 2 * std.time.ns_per_s,
    };
}

const crash_faults: search.FaultConfig = .{
    .schedule = .{
        .max_events = 4,
        .horizon = 1500,
        .repair_permille = 1000, // every crash is followed by a restart
        .enable_partition = false,
        .enable_clock_jump = false,
    },
};

test "search finds the torn file left by a rename without fsync" {
    var careless: Saver = .{ .careful = false };
    var failing = (try search.findFailing(testing.allocator, saverCase(&careless), crash_faults, 0, 300)) orelse
        return error.BugNotFound;
    defer failing.deinit();
    try testing.expectEqual(@as(anyerror, error.TornState), failing.violation.err);
    var small = try search.shrink(testing.allocator, &failing);
    defer small.deinit();
    // One crash and its restart are enough.
    try testing.expect(small.after <= 2);
}

test "the careful saver (sync file, rename, sync directory) survives the same search" {
    var careful: Saver = .{ .careful = true };
    const failing = try search.findFailing(testing.allocator, saverCase(&careful), crash_faults, 0, 100);
    try testing.expect(failing == null);
}

// ── the search with disk faults ────────────────────────────────────────────

const Reading = struct { checksum: bool, wrong: bool = false };

/// Reads a stored record every 10 ms and acts on it. Without a checksum, a
/// flipped bit becomes a wrong value nobody notices.
fn readLoop(io: Io, reading: *Reading) !void {
    while (true) {
        try io.sleep(.fromMilliseconds(10), .awake);
        var buf: [16]u8 = undefined;
        const got = try Dir.cwd().readFile(io, "record", &buf);
        if (got.len != 12) continue;
        const value = std.mem.readInt(u64, got[0..8], .little);
        if (reading.checksum) {
            const crc = std.mem.readInt(u32, got[8..12], .little);
            if (crc != std.hash.Crc32.hash(got[0..8])) continue; // detected: ignore it
        }
        if (value != 0x1234_5678_9abc_def0) reading.wrong = true;
    }
}

fn readerSetup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const reading: *Reading = @ptrCast(@alignCast(ctx.?));
    const h = try sim.addHost(.{});
    var rec: [12]u8 = undefined;
    std.mem.writeInt(u64, rec[0..8], 0x1234_5678_9abc_def0, .little);
    std.mem.writeInt(u32, rec[8..12], std.hash.Crc32.hash(rec[0..8]), .little);
    try h.putFile("record", &rec);
    try h.spawn(readLoop, .{ h.io(), reading });
}

fn readerInvariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const reading: *const Reading = @ptrCast(@alignCast(ctx.?));
    if (reading.wrong) return error.SilentCorruption;
}

fn readerReset(ctx: ?*anyopaque) void {
    const reading: *Reading = @ptrCast(@alignCast(ctx.?));
    reading.wrong = false;
}

fn readerCase(reading: *Reading) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 256 * 1024 },
        .setup = readerSetup,
        .invariant = readerInvariant,
        .reset = readerReset,
        .ctx = reading,
        .duration_ns = std.time.ns_per_s,
    };
}

const rot_faults: search.FaultConfig = .{
    .schedule = .{ .max_events = 0, .horizon = 800 },
    .disk = .{ .max_events = 2, .io_errors = false },
};

test "search with disk faults finds silent corruption; a checksum catches it" {
    var plain: Reading = .{ .checksum = false };
    var failing = (try search.findFailing(testing.allocator, readerCase(&plain), rot_faults, 0, 100)) orelse
        return error.BugNotFound;
    defer failing.deinit();
    try testing.expectEqual(@as(anyerror, error.SilentCorruption), failing.violation.err);
    var small = try search.shrink(testing.allocator, &failing);
    defer small.deinit();
    try testing.expectEqual(@as(usize, 1), small.after);
    try testing.expect(small.trace.events[0].kind.disk == .bit_rot);

    var checked: Reading = .{ .checksum = true };
    try testing.expect(try search.findFailing(testing.allocator, readerCase(&checked), rot_faults, 0, 100) == null);
}

// ── crash-model details found by the mutation run ──────────────────────────

fn overwriteTwiceSynced(io: Io) !void {
    var f = try Dir.cwd().openFile(io, "page", .{ .mode = .read_write });
    defer f.close(io);
    try f.writePositionalAll(io, &([_]u8{0x11} ** 512), 0);
    try f.sync(io);
    try f.writePositionalAll(io, &([_]u8{0x22} ** 512), 0);
    try f.sync(io);
}

test "a synced overwrite is final: a crash never brings an older write back" {
    for (0..30) |seed| {
        var sim: Sim = undefined;
        newSim(&sim, seed);
        defer sim.deinit();
        const h = try sim.addHost(.{});
        try h.putFile("page", &([_]u8{0} ** 512));
        try h.spawn(overwriteTwiceSynced, .{h.io()});
        _ = sim.run();
        sim.crash(h);
        for (h.readFile("page").?) |b| try testing.expectEqual(@as(u8, 0x22), b);
    }
}

fn createThenSyncOtherDir(io: Io) !void {
    const cwd = Dir.cwd();
    var f = try cwd.createFile(io, "a/f", .{});
    try f.sync(io);
    f.close(io);
    const other = try cwd.openDir(io, "b", .{});
    defer other.close(io);
    try (File{ .handle = other.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

test "strict durability: syncing another directory does not make a name durable" {
    var lost: usize = 0;
    for (0..30) |seed| {
        var sim: Sim = undefined;
        newSim(&sim, seed);
        defer sim.deinit();
        const h = try sim.addHost(.{});
        try h.putFile("a/.keep", "");
        try h.putFile("b/.keep", "");
        try h.spawn(createThenSyncOtherDir, .{h.io()});
        _ = sim.run();
        sim.crash(h);
        if (h.readFile("a/f") == null) lost += 1;
    }
    try testing.expect(lost > 0);
}

fn renameOnly(io: Io) !void {
    try Dir.cwd().rename("old", Dir.cwd(), "new", io);
}

test "a crash never splits a rename: exactly one of the two names exists" {
    var outcomes: [2]usize = @splat(0);
    for (0..30) |seed| {
        var sim: Sim = undefined;
        newSim(&sim, seed);
        defer sim.deinit();
        const h = try sim.addHost(.{});
        try h.putFile("old", "payload");
        try h.spawn(renameOnly, .{h.io()});
        _ = sim.run();
        sim.crash(h);
        const old = h.readFile("old") != null;
        const new = h.readFile("new") != null;
        try testing.expect(old != new);
        outcomes[@intFromBool(new)] += 1;
    }
    try testing.expect(outcomes[0] > 0 and outcomes[1] > 0);
}

fn shrinkFile(io: Io, sync: bool) !void {
    var f = try Dir.cwd().openFile(io, "big", .{ .mode = .read_write });
    defer f.close(io);
    try f.setLength(io, 10);
    if (sync) try f.sync(io);
}

test "an unsynced truncation may or may not survive a crash; a synced one does" {
    var lengths: [2]usize = @splat(0);
    for (0..30) |seed| {
        for ([_]bool{ false, true }) |sync| {
            var sim: Sim = undefined;
            newSim(&sim, seed);
            defer sim.deinit();
            const h = try sim.addHost(.{});
            try h.putFile("big", &([_]u8{7} ** 1000));
            try h.spawn(shrinkFile, .{ h.io(), sync });
            _ = sim.run();
            sim.crash(h);
            const len = h.readFile("big").?.len;
            if (sync) {
                try testing.expectEqual(@as(usize, 10), len);
            } else {
                try testing.expect(len == 10 or len == 1000);
                lengths[@intFromBool(len == 10)] += 1;
            }
        }
    }
    try testing.expect(lengths[0] > 0 and lengths[1] > 0);
}
