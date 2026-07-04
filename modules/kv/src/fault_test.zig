// SPDX-License-Identifier: MIT

//! The headline test: a deterministic, bounded fault-injection sweep
//! (mini-VOPR, after the TigerBeetle VOPR approach — deterministic
//! simulation instead of a giant test corpus).
//!
//! A scripted workload (open → puts/overwrites/deletes/compactions → close)
//! is driven through `SimStorage`. A counting run measures how many storage
//! side effects (injection points) the workload performs; the sweep then
//! replays the whole workload once per (injection point × crash mode),
//! crashing the simulated machine at exactly that side effect, "reboots",
//! re-opens the store and asserts the recovery invariants:
//!
//!   1. no acknowledged (fsync-returned) put or delete is lost — the
//!      recovered state must contain every completed step;
//!   2. no torn or corrupt record is served — the recovered state must be
//!      EXACTLY the model state either without or with the single in-flight
//!      step (an unacknowledged op may atomically survive or vanish, but
//!      nothing in between, and nothing else may change);
//!   3. a crash anywhere inside compaction leaves the logical state intact
//!      (compaction changes no logical state, so invariant 2 pins it);
//!   4. the keydir is consistent (count matches, every lookup agrees) and
//!      the recovered store accepts and persists new writes.
//!
//! Everything is in-process and deterministic: no real process kill, no
//! randomness, no clock. The full 1000×-randomized VOPR is a noted phase.

const std = @import("std");
const kv = @import("root.zig");
const Db = kv.Db;
const SimStorage = kv.SimStorage;
const CrashMode = kv.CrashMode;
const testing = std.testing;

const db_name = "sweep.kv";

// ── the scripted workload ────────────────────────────────────────────────────

const Step = union(enum) {
    put: struct { k: []const u8, v: []const u8 },
    del: []const u8,
    compact,
};

const big_value = "B" ** 3000; // multi-chunk on the replay CRC path

const script = [_]Step{
    .{ .put = .{ .k = "alpha", .v = "1" } },
    .{ .put = .{ .k = "beta", .v = "two" } },
    .{ .put = .{ .k = "", .v = "empty-key" } }, // empty key
    .{ .put = .{ .k = "gamma", .v = "" } }, // empty value
    .{ .put = .{ .k = "alpha", .v = "1-overwritten" } },
    .{ .del = "beta" },
    .{ .put = .{ .k = "delta", .v = big_value } },
    .compact, // with dead weight to drop
    .{ .put = .{ .k = "epsilon", .v = "5" } },
    .{ .del = "alpha" },
    .{ .del = "missing" }, // absent → no-op, no I/O
    .{ .put = .{ .k = "beta", .v = "resurrected" } },
    .{ .put = .{ .k = "eta", .v = "7" } },
    .{ .put = .{ .k = "theta", .v = "8888" } },
    .{ .put = .{ .k = "theta", .v = "8" } }, // overwrite again
    .{ .del = "eta" }, // put then delete, both pre-compaction
    .compact, // second cycle, post-compaction writes above
    .{ .put = .{ .k = "zeta", .v = "z" } },
};

/// Apply `steps` to a pure in-memory model of the store's logical state.
/// Values are static script slices — no ownership.
const Model = struct {
    map: std.StringArrayHashMapUnmanaged([]const u8) = .empty,

    fn deinit(m: *Model, gpa: std.mem.Allocator) void {
        m.map.deinit(gpa);
    }

    fn apply(m: *Model, gpa: std.mem.Allocator, steps: []const Step) !void {
        for (steps) |s| switch (s) {
            .put => |p| try m.map.put(gpa, p.k, p.v),
            .del => |k| _ = m.map.swapRemove(k),
            .compact => {},
        };
    }
};

// ── driver ───────────────────────────────────────────────────────────────────

const RunOutcome = struct {
    /// Steps fully acknowledged before the crash (== script.len when the
    /// whole run survived).
    completed: usize,
    /// Whether the crash fired during `Db.open` / a step (vs. not at all).
    crashed: bool,
};

/// Run the whole workload against `sim`. Returns how far it got before the
/// scheduled crash (if any) fired.
fn runScript(sim: *SimStorage) RunOutcome {
    const st = sim.storage();
    var db = Db.open(testing.allocator, st, db_name, .{}) catch |e| switch (e) {
        error.Crashed => return .{ .completed = 0, .crashed = true },
        else => std.debug.panic("workload open failed with {t}, not a crash", .{e}),
    };
    defer db.close();
    for (script, 0..) |step, i| {
        const result: anyerror!void = switch (step) {
            .put => |p| db.put(p.k, p.v),
            .del => |k| db.delete(k),
            .compact => db.compact(),
        };
        result catch |e| switch (e) {
            error.Crashed => return .{ .completed = i, .crashed = true },
            else => std.debug.panic("workload step {d} failed with {t}, not a crash", .{ i, e }),
        };
    }
    return .{ .completed = script.len, .crashed = false };
}

/// Does the recovered store's state equal `model` exactly?
fn matchesModel(db: *Db, model: *const Model) !bool {
    if (db.count() != model.map.count()) return false;
    var it = model.map.iterator();
    while (it.next()) |e| {
        const got = try db.get(testing.allocator, e.key_ptr.*) orelse return false;
        defer testing.allocator.free(got);
        if (!std.mem.eql(u8, got, e.value_ptr.*)) return false;
    }
    return true;
}

/// Reboot after the crash, reopen, and assert the recovery invariants.
fn verifyRecovery(sim: *SimStorage, outcome: RunOutcome) !void {
    sim.reboot();
    var db = try Db.open(testing.allocator, sim.storage(), db_name, .{});
    defer db.close();

    // The recovered state must be the acknowledged model, or (only if a step
    // was in flight) the model with that one step atomically applied.
    var before: Model = .{};
    defer before.deinit(testing.allocator);
    try before.apply(testing.allocator, script[0..outcome.completed]);
    var ok = try matchesModel(&db, &before);
    if (!ok and outcome.crashed and outcome.completed < script.len) {
        var after: Model = .{};
        defer after.deinit(testing.allocator);
        try after.apply(testing.allocator, script[0 .. outcome.completed + 1]);
        ok = try matchesModel(&db, &after);
    }
    try testing.expect(ok);

    // The recovered store must be fully usable and durable again.
    try db.put("post-crash-probe", "alive");
    const got = (try db.get(testing.allocator, "post-crash-probe")).?;
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("alive", got);
}

// ── the sweep ────────────────────────────────────────────────────────────────

test "fault-injection sweep: crash at EVERY storage side effect, all modes" {
    // Counting run: how many injection points does the workload hit?
    var total: usize = 0;
    {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        const out = runScript(&sim);
        try testing.expect(!out.crashed);
        try testing.expectEqual(script.len, out.completed);
        total = sim.ops_seen;
        // The run must also be verifiable as-is (no crash at all).
        try verifyRecovery(&sim, out);
    }
    // The workload must be substantial enough to mean something.
    try testing.expect(total >= 50);

    // Determinism: an identical run hits the identical number of points.
    {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        _ = runScript(&sim);
        try testing.expectEqual(total, sim.ops_seen);
    }

    // The sweep: crash at every point, under every crash model.
    for ([_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail }) |mode| {
        var point: usize = 0;
        while (point < total) : (point += 1) {
            var sim = SimStorage.init(testing.allocator);
            defer sim.deinit();
            sim.crash_mode = mode;
            sim.ops_until_crash = point;
            const out = runScript(&sim);
            try testing.expect(out.crashed);
            verifyRecovery(&sim, out) catch |e| {
                std.debug.print(
                    "fault sweep FAILED: mode={t} crash_point={d}/{d} completed_steps={d}\n",
                    .{ mode, point, total, out.completed },
                );
                return e;
            };
        }
    }
}

test "fault sweep is deterministic across repeats" {
    // Same crash point, same mode, twice → byte-identical surviving file.
    for ([_]usize{ 3, 17, 29 }) |point| {
        var contents: [2][]u8 = undefined;
        for (&contents) |*c| {
            var sim = SimStorage.init(testing.allocator);
            defer sim.deinit();
            sim.crash_mode = .torn_tail;
            sim.ops_until_crash = point;
            _ = runScript(&sim);
            sim.reboot();
            const file = sim.fileContent(db_name) orelse "";
            c.* = try testing.allocator.dupe(u8, file);
        }
        defer for (contents) |c| testing.allocator.free(c);
        try testing.expectEqualSlices(u8, contents[0], contents[1]);
    }
}
