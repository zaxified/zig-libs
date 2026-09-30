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
const lock_name = db_name ++ ".lock";

// ── the scripted workload ────────────────────────────────────────────────────

const Step = union(enum) {
    put: struct { k: []const u8, v: []const u8 },
    del: []const u8,
    compact,
    /// `putExpiring` at `at` against `test_clock` (fixed at `test_now`).
    put_exp: struct { k: []const u8, v: []const u8, at: i64 },
};

/// The sweep's wall clock never moves: an expiry is either past or future
/// for the whole run, so the model knows which without a clock of its own.
const test_now: i64 = 1_000_000;
fn fixedNow(_: ?*anyopaque) i64 {
    return test_now;
}
const test_clock: kv.Clock = .{ .nowFn = fixedNow };
const test_options: kv.Options = .{ .clock = test_clock };

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

/// The expiry workload: a version-1 store with live data takes its first
/// expiring put (the upgrade-by-compaction), then mixes expiring, plain and
/// already-expired puts through an overwrite, a delete and a compaction that
/// must drop the expired key. A crash inside the upgrade must leave either
/// the old version-1 file or the complete version-2 one.
const expiry_script = [_]Step{
    .{ .put = .{ .k = "alpha", .v = "1" } },
    .{ .put = .{ .k = "beta", .v = "two" } },
    .{ .put = .{ .k = "alpha", .v = "1-overwritten" } },
    .{ .put_exp = .{ .k = "sess", .v = "live", .at = test_now + 60_000 } }, // upgrade happens here
    .{ .put_exp = .{ .k = "gone", .v = "stale", .at = test_now - 1 } }, // absent at once
    .{ .put_exp = .{ .k = "beta", .v = "expiring-beta", .at = test_now + 5 } },
    .{ .put = .{ .k = "sess2", .v = big_value } },
    .{ .put_exp = .{ .k = "alpha", .v = "dies", .at = test_now } }, // `at == now` is expired
    .compact, // drops "gone" and "alpha"
    .{ .put = .{ .k = "beta", .v = "plain-again" } }, // overwrite clears the expiry
    .{ .del = "sess" },
    .{ .put_exp = .{ .k = "late", .v = "l", .at = test_now + 1 } },
    .compact,
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
            .put_exp => |p| if (p.at > test_now)
                try m.map.put(gpa, p.k, p.v)
            else {
                _ = m.map.swapRemove(p.k);
            },
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
    return runSteps(sim, &script);
}

fn runSteps(sim: *SimStorage, steps: []const Step) RunOutcome {
    const st = sim.storage();
    var db = Db.open(testing.allocator, st, db_name, test_options) catch |e| switch (e) {
        error.Crashed => return .{ .completed = 0, .crashed = true },
        else => std.debug.panic("workload open failed with {t}, not a crash", .{e}),
    };
    defer db.close();
    for (steps, 0..) |step, i| {
        const result: anyerror!void = switch (step) {
            .put => |p| db.put(p.k, p.v),
            .del => |k| db.delete(k),
            .compact => db.compact(),
            .put_exp => |p| db.putExpiring(p.k, p.v, p.at),
        };
        result catch |e| switch (e) {
            error.Crashed => return .{ .completed = i, .crashed = true },
            else => std.debug.panic("workload step {d} failed with {t}, not a crash", .{ i, e }),
        };
    }
    return .{ .completed = steps.len, .crashed = false };
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
    return verifySteps(sim, &script, outcome);
}

fn verifySteps(sim: *SimStorage, steps: []const Step, outcome: RunOutcome) !void {
    sim.reboot();
    var db = try Db.open(testing.allocator, sim.storage(), db_name, test_options);
    defer db.close();

    // The recovered state must be the acknowledged model, or (only if a step
    // was in flight) the model with that one step atomically applied.
    var before: Model = .{};
    defer before.deinit(testing.allocator);
    try before.apply(testing.allocator, steps[0..outcome.completed]);
    var ok = try matchesModel(&db, &before);
    if (!ok and outcome.crashed and outcome.completed < steps.len) {
        var after: Model = .{};
        defer after.deinit(testing.allocator);
        try after.apply(testing.allocator, steps[0 .. outcome.completed + 1]);
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
        // Teeth: the swept workload must actually exercise the cross-process
        // lock path (`Db.open` takes it by default). If this sidecar is
        // missing, the store opened unlocked and every crash point below
        // stopped covering the lock acquisition.
        try testing.expect(sim.fileContent(lock_name) != null);
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

test "fault-injection sweep: expiring puts, the v1→v2 upgrade and expiry-dropping compaction" {
    var total: usize = 0;
    {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        const out = runSteps(&sim, &expiry_script);
        try testing.expect(!out.crashed);
        total = sim.ops_seen;
        try verifySteps(&sim, &expiry_script, out);
        // Teeth: the run ended on a version-2 file with the expired keys
        // gone from it, not merely hidden.
        const file = sim.fileContent(db_name).?;
        try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, file[4..8], .little));
        try testing.expect(std.mem.indexOf(u8, file, "stale") == null);
        try testing.expect(std.mem.indexOf(u8, file, "dies") == null);
    }
    try testing.expect(total >= 40);

    var holes: usize = 0;
    for ([_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail, .reorder_unsynced }) |mode| {
        for ([_]u64{ 1, 2, 3 }) |seed| {
            if (mode != .reorder_unsynced and seed != 1) continue;
            var point: usize = 0;
            while (point < total) : (point += 1) {
                var sim = SimStorage.init(testing.allocator);
                defer sim.deinit();
                sim.crash_mode = mode;
                sim.reorder_seed = seed;
                sim.ops_until_crash = point;
                const out = runSteps(&sim, &expiry_script);
                try testing.expect(out.crashed);
                holes += sim.holes_punched;
                verifySteps(&sim, &expiry_script, out) catch |e| {
                    std.debug.print(
                        "expiry sweep FAILED: mode={t} seed={d} crash_point={d}/{d} completed_steps={d}\n",
                        .{ mode, seed, point, total, out.completed },
                    );
                    return e;
                };
            }
        }
    }
    try testing.expect(holes > 0);
}

test "fault-injection sweep: non-contiguous (reordered) unsynced persistence" {
    // The scripted workload runs two `compact()`s, each a write-loop-then-
    // single-`sync` window over several live records — exactly the fsync-free
    // multi-write window where out-of-order durability bites. Crash at every
    // side effect under `.reorder_unsynced` for several seeds (each a
    // different keep/drop subset of the un-synced ranges) and assert recovery
    // is still correct: a persisted-but-orphaned record beyond a hole is
    // never served, and no committed record before it is lost.
    var total: usize = 0;
    {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        _ = runScript(&sim);
        total = sim.ops_seen;
    }

    var holes: usize = 0;
    for ([_]u64{ 1, 2, 3, 5, 8, 13, 21, 34 }) |seed| {
        var point: usize = 0;
        while (point < total) : (point += 1) {
            var sim = SimStorage.init(testing.allocator);
            defer sim.deinit();
            sim.crash_mode = .reorder_unsynced;
            sim.reorder_seed = seed;
            sim.ops_until_crash = point;
            const out = runScript(&sim);
            try testing.expect(out.crashed);
            const punched = sim.holes_punched;
            verifyRecovery(&sim, out) catch |e| {
                std.debug.print(
                    "reorder sweep FAILED: seed={d} crash_point={d}/{d} completed_steps={d}\n",
                    .{ seed, point, total, out.completed },
                );
                return e;
            };
            holes += punched;
        }
    }
    // Teeth: the reorder collapse must have punched genuine non-contiguous
    // holes in the compact windows (else this mode tested nothing new).
    try testing.expect(holes > 0);
}

test "fault sweep: a contended lock blocks recovery without touching the crashed store" {
    // The dangerous moment for a store is the one right after a crash: the
    // log has a torn tail, and `open` wants to replay and TRUNCATE it. If a
    // second process is already recovering the same file, both truncating is
    // how a crash-consistent store becomes an inconsistent one.
    //
    // So: crash at every point, then (with another process modeled as holding
    // the lock) assert that recovery is refused and the crashed file is left
    // byte-for-byte alone — and that once the other process is gone, the very
    // same recovery still satisfies the sweep's full invariant set.
    var total: usize = 0;
    {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        _ = runScript(&sim);
        total = sim.ops_seen;
    }

    var contended: usize = 0;
    var point: usize = 0;
    while (point < total) : (point += 1) {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        sim.ops_until_crash = point;
        const out = runScript(&sim);
        try testing.expect(out.crashed);
        sim.reboot();

        // Another process holds the store. (The crash released OUR lock but
        // has no power over theirs — that asymmetry is the model's job.)
        try sim.holdForeignLock(lock_name);
        const before = try testing.allocator.dupe(u8, sim.fileContent(db_name) orelse "");
        defer testing.allocator.free(before);

        try testing.expectError(
            error.Locked,
            Db.open(testing.allocator, sim.storage(), db_name, .{}),
        );
        // A refused open must be a *total* no-op: no replay, no truncation of
        // the torn tail, no stale-temp deletion.
        try testing.expectEqualSlices(u8, before, sim.fileContent(db_name) orelse "");
        contended += 1;

        sim.releaseForeignLock(lock_name);
        verifyRecovery(&sim, out) catch |e| {
            std.debug.print(
                "contended-lock sweep FAILED: crash_point={d}/{d} completed_steps={d}\n",
                .{ point, total, out.completed },
            );
            return e;
        };
    }
    // Teeth: the contention actually happened at every crash point (a sweep
    // where `open` never hit `error.Locked` proves nothing about locking).
    try testing.expectEqual(total, contended);
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
