// SPDX-License-Identifier: MIT

//! Pilot: `kv.Db` over the real `kv.FsStorage` (unchanged, `std.Io.Dir`/`File`)
//! on simio's disk, through crashes, I/O errors and bit rot. kv has its own
//! fault simulator (`SimStorage`); this pilot checks the production backend
//! against an independent crash model instead: unsynced data survives per
//! sector, a name change is durable only after the directory is synced.
//!
//! The property, after every reopen: each key holds the version whose write
//! was last acknowledged, or the one in flight when the machine went down.
//! Under bit rot kv's documented policy discards every record after the first
//! bad one, so an older version may come back; what must never come back is a
//! value that was not written. A store whose `sync` does nothing is caught
//! losing acknowledged writes.

const std = @import("std");
const kv = @import("kv");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const Sim = sched.Sim;
const testing = std.testing;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const n_keys = 8;
const n_ops = 300;

const State = struct {
    /// The broken variant: `sync` and `syncDir` do nothing.
    careless: bool = false,
    /// Bit rot is in play: an older version may legitimately come back.
    rot: bool = false,

    /// Per key: the version of the last acknowledged write (0 = absent).
    acked: [n_keys]u32 = @splat(0),
    /// Per key: the version of a write that had not returned yet.
    inflight: [n_keys]?u32 = @splat(null),
    next_op: u32 = 0,
    opens: u32 = 0,
    lost: bool = false,
    garbage: bool = false,
};

fn keyOf(k: usize, buf: *[2]u8) []const u8 {
    buf.* = .{ 'k', '0' + @as(u8, @intCast(k)) };
    return buf;
}

/// A 64-byte value that names its version and can be told from garbage.
fn valueOf(ver: u32, buf: *[64]u8) []const u8 {
    @memset(buf, 'a' + @as(u8, @intCast(ver % 26)));
    _ = std.fmt.bufPrint(buf[0..8], "v{d:0>7}", .{ver}) catch unreachable;
    return buf;
}

fn versionOf(value: []const u8) ?u32 {
    if (value.len != 64 or value[0] != 'v') return null;
    const ver = std.fmt.parseInt(u32, value[1..8], 10) catch return null;
    var want: [64]u8 = undefined;
    return if (std.mem.eql(u8, value, valueOf(ver, &want))) ver else null;
}

/// The key's op sequence: op `i` writes key `i % n_keys` at version `i + 1`;
/// every seventh op deletes it instead.
fn isDelete(op: u32) bool {
    return op % 7 == 6;
}

fn writer(io: Io, gpa: std.mem.Allocator, st: *State) !void {
    while (st.next_op < n_ops) {
        var fs_store = kv.FsStorage.init(io, Io.Dir.cwd());
        var careless_vt = fs_store.storage().vtable.*;
        careless_vt.sync = struct {
            fn f(_: *anyopaque, _: kv.Storage.Handle) kv.Storage.Error!void {}
        }.f;
        careless_vt.syncDir = struct {
            fn f(_: *anyopaque) kv.Storage.Error!void {}
        }.f;
        const store: kv.Storage = if (st.careless) .{ .ctx = &fs_store, .vtable = &careless_vt } else fs_store.storage();

        var db = kv.Db.open(gpa, store, "db", .{}) catch |err| switch (err) {
            // An injected I/O error during replay: try again.
            error.InputOutput => {
                try io.sleep(.fromMilliseconds(5), .awake);
                continue;
            },
            // A store that no longer opens has lost whatever was in it.
            else => {
                for (st.acked) |a| if (a != 0) {
                    st.lost = true;
                };
                return err;
            },
        };
        defer db.close();
        st.opens += 1;
        try verify(&db, gpa, st);
        // A write error poisons the store; reopening is the documented cure.
        work(io, &db, st) catch |err| switch (err) {
            error.Canceled => return err,
            else => {},
        };
    }
}

fn verify(db: *kv.Db, gpa: std.mem.Allocator, st: *State) !void {
    for (0..n_keys) |k| {
        var kb: [2]u8 = undefined;
        const got = db.get(gpa, keyOf(k, &kb)) catch |err| switch (err) {
            error.Corrupt => continue, // detected, nothing served
            else => return err,
        };
        defer if (got) |v| gpa.free(v);
        const ver: u32 = if (got) |v| versionOf(v) orelse {
            st.garbage = true;
            continue;
        } else 0;
        const expected = ver == st.acked[k] or (st.inflight[k] != null and ver == st.inflight[k].?);
        if (!expected) {
            // Under rot an older record may resurface; one never written may not.
            const written_ever = ver == 0 or
                ((ver - 1) % n_keys == k and !isDelete(ver - 1) and ver - 1 <= st.next_op);
            if (!st.rot) st.lost = true else if (!written_ever) st.garbage = true;
        }
        st.acked[k] = ver;
        st.inflight[k] = null;
    }
}

fn work(io: Io, db: *kv.Db, st: *State) !void {
    while (st.next_op < n_ops) {
        const op = st.next_op;
        const k = op % n_keys;
        var kb: [2]u8 = undefined;
        if (isDelete(op)) {
            st.inflight[k] = 0;
            try db.delete(keyOf(k, &kb));
        } else {
            var vb: [64]u8 = undefined;
            st.inflight[k] = op + 1;
            try db.put(keyOf(k, &kb), valueOf(op + 1, &vb));
        }
        st.acked[k] = st.inflight[k].?;
        st.inflight[k] = null;
        st.next_op += 1;
        if (op % 40 == 39) try db.compact();
        try io.sleep(.fromMilliseconds(3), .awake);
    }
}

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const h = try sim.addHost(.{});
    try h.spawnBoot(writer, .{ h.io(), h.allocator(), st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.garbage) return error.Garbage;
    if (st.lost) return error.AckedWriteLost;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    try invariant(sim, ctx);
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.next_op != n_ops) return error.NeverFinished;
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .careless = st.careless, .rot = st.rot };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 512 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 10 * ns_per_s,
    };
}

const crashes: search.FaultConfig = .{
    .schedule = .{
        .max_events = 4,
        .horizon = 1200,
        .repair_permille = 1000, // every crash is followed by a restart
        .enable_partition = false,
        .enable_clock_jump = false,
    },
};

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot kv: every write is acknowledged and readable once the disk behaves" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.opens);
}

test "pilot kv: a crash mid-run loses nothing that was acknowledged" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(400, .{ .net = .{ .crash_node = .{ .node = 0 } } }),
        at(450, .{ .net = .{ .restart_node = .{ .node = 0 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 2), st.opens);
}

test "pilot kv: a store that skips sync loses acknowledged writes, and the search finds it" {
    var st: State = .{ .careless = true };
    var failing = (try search.findFailing(testing.allocator, case(&st), crashes, 0, 50)) orelse
        return error.BugNotFound;
    defer failing.deinit();
    try testing.expectEqual(@as(anyerror, error.AckedWriteLost), failing.violation.err);
}

test "pilot kv: crashes and I/O errors across seeds lose nothing acknowledged" {
    var st: State = .{};
    var faults = crashes;
    faults.disk = .{ .max_events = 3, .bit_rot = false };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 40)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}

test "pilot kv: under bit rot nothing is served that was never written" {
    var st: State = .{ .rot = true };
    var faults = crashes;
    faults.disk = .{ .max_events = 3, .io_errors = false };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 40)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}

fn sharedWriter(io: Io, db: *kv.Db, prefix: u8, done: *u32) Io.Cancelable!void {
    for (0..50) |i| {
        var key: [8]u8 = undefined;
        const k = std.fmt.bufPrint(&key, "{c}-{d}", .{ prefix, i }) catch unreachable;
        var vb: [64]u8 = undefined;
        db.put(k, valueOf(@intCast(i + 1), &vb)) catch return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    done.* += 1;
}

fn twoWriters(io: Io, gpa: std.mem.Allocator, done: *u32) !void {
    var fs_store = kv.FsStorage.init(io, Io.Dir.cwd());
    var db = try kv.Db.open(gpa, fs_store.storage(), "db", .{});
    defer db.close();
    var g: Io.Group = .init;
    g.async(io, sharedWriter, .{ io, &db, 'a', done });
    g.async(io, sharedWriter, .{ io, &db, 'b', done });
    try g.await(io);
    if (db.count() != 100) return error.WrongCount;
}

test "pilot kv: two tasks of one thread share a Db without starving each other" {
    // Before kv waited on its lock through the `Io`, the second task spun
    // forever while the first was suspended in `sync` holding the lock.
    for (0..20) |seed| {
        var sim: Sim = undefined;
        sim.init(testing.allocator, .{ .seed = seed, .stack_size = 512 * 1024 });
        defer sim.deinit();
        const h = try sim.addHost(.{});
        var done: u32 = 0;
        try h.spawn(twoWriters, .{ h.io(), h.allocator(), &done });
        const r = sim.runFor(10 * ns_per_s);
        try testing.expectEqual(sched.Outcome.quiescent, r.outcome);
        try testing.expectEqual(@as(?anyerror, null), h.failure);
        try testing.expectEqual(@as(u32, 2), done);
    }
}
