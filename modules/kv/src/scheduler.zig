// SPDX-License-Identifier: MIT

//! Pluggable fault-injection SCHEDULING policy for the kv VOPR (`vopr.zig`).
//!
//! This module owns exactly one decision per epoch: WHEN a fault fires and
//! WHICH one (crash mode + timing, or transient I/O error + timing, or a
//! clean epoch). It does NOT own the fault *mechanics* — those live in
//! `sim.zig` (`SimStorage`'s crash-collapse models) and `vopr.zig`
//! (`FaultStorage`'s transient-error/short-read injection); this seam only
//! decides the schedule those mechanisms execute.
//!
//! `uniformScheduler` is the module's original policy (flat PRNG draws, no
//! feedback) — it is REAL, fully implemented, and byte-for-byte the same
//! distribution `Vopr.runSeed` used before this seam existed, so switching
//! `Config.scheduler` to it (the default) changes nothing about existing
//! VOPR runs or their determinism.
//!
//! `coverageGuidedScheduler` is the intended upgrade — bias the draw toward
//! (fault-class × timing-bucket) combinations `Coverage` shows as
//! under-exercised, instead of drawing uniformly — and is a documented stub
//! (see its doc comment and the `@panic` in its body). `Coverage` itself
//! (the bookkeeping struct a smarter policy would read) is real and wired:
//! `uniformScheduler` already records into it every epoch, so a
//! coverage-guided policy dropped in later has real data to act on from run
//! one, not a placeholder.

const std = @import("std");
const Prng = @import("prng.zig").Prng;
const kv = @import("root.zig");
const CrashMode = kv.CrashMode;
const Storage = kv.Storage;

/// One epoch's fault decision, as chosen by a `FaultScheduler`. The caller
/// (`Vopr.runSeed`) applies it to `SimStorage`/`FaultStorage` — the
/// scheduler only decides, it never touches storage directly, so it can be
/// unit-tested (and later, coverage-optimized) without a `Db` in the loop.
pub const FaultPlan = union(enum) {
    /// No fault this epoch — the workload must run to completion and the
    /// close+reopen must be byte-exact (no crash/error to explain a delta).
    clean,
    crash: struct {
        mode: CrashMode,
        /// Consumed only by `.reorder_unsynced`; drawn unconditionally by
        /// `uniformScheduler` regardless of mode to keep the PRNG stream
        /// aligned across modes (see its doc comment).
        reorder_seed: u64,
        /// Side-effect countdown until the crash fires (`SimStorage.ops_until_crash`).
        ops_until_crash: usize,
    },
    io_error: struct {
        kind: Storage.Error,
        /// Side-effect countdown until the error fires (`FaultStorage.error_countdown`).
        ops_until_crash: usize,
    },
};

/// Coarse classification of a `FaultPlan`, independent of its exact timing —
/// the axis `Coverage` tallies against a timing bucket. `clean` is included
/// so "did we run enough fault-free epochs" is also visible in the tally.
pub const FaultClass = enum {
    lose_unsynced,
    keep_unsynced,
    torn_tail,
    reorder_unsynced,
    io_no_space,
    io_input_output,
    clean,

    pub const count = @typeInfo(FaultClass).@"enum".fields.len;

    fn ofCrash(mode: CrashMode) FaultClass {
        return switch (mode) {
            .lose_unsynced => .lose_unsynced,
            .keep_unsynced => .keep_unsynced,
            .torn_tail => .torn_tail,
            .reorder_unsynced => .reorder_unsynced,
        };
    }

    fn ofIoError(kind: Storage.Error) FaultClass {
        return if (kind == error.NoSpaceLeft) .io_no_space else .io_input_output;
    }
};

/// Coarse "how soon after open did the fault land" bucket. Two buckets
/// (early/late) are enough to let a future policy tell "we keep re-crashing
/// epoch 0's open/first-write" apart from "we never crash deep into a run".
pub const TimingBucket = enum {
    early, // ops_until_crash < early_threshold (or a clean epoch)
    late,

    pub const count = @typeInfo(TimingBucket).@"enum".fields.len;

    fn of(ops_until_crash: usize, early_threshold: usize) TimingBucket {
        return if (ops_until_crash < early_threshold) .early else .late;
    }
};

/// Per-seed tally of (fault-class × timing-bucket) combinations a scheduler
/// has already produced — the raw material a coverage-guided policy biases
/// against. Real and mechanical: recording is just a counter bump; deciding
/// what to do WITH low counts is the stubbed part (`coverageGuidedScheduler`).
pub const Coverage = struct {
    counts: [FaultClass.count][TimingBucket.count]usize = @splat(@splat(0)),

    pub fn record(self: *Coverage, class: FaultClass, bucket: TimingBucket) void {
        self.counts[@intFromEnum(class)][@intFromEnum(bucket)] += 1;
    }

    pub fn countOf(self: *const Coverage, class: FaultClass, bucket: TimingBucket) usize {
        return self.counts[@intFromEnum(class)][@intFromEnum(bucket)];
    }

    /// Total distinct (class, bucket) combinations that have never been
    /// produced — 0 means every combination has fired at least once. A
    /// coverage-guided policy's whole job is to drive this to 0 faster than
    /// uniform-random sampling does.
    pub fn uncoveredCount(self: *const Coverage) usize {
        var n: usize = 0;
        for (self.counts) |row| {
            for (row) |c| {
                if (c == 0) n += 1;
            }
        }
        return n;
    }

    /// The least-exercised reachable cell (min `countOf` over `reachable_cells`,
    /// random tie-break from `prng`) — the exploit target of a coverage-guided
    /// policy. Ignores the uncoverable `(.clean, .late)` cell.
    pub fn coldestReachableCell(self: *const Coverage, prng: *Prng) Cell {
        var min_count: usize = std.math.maxInt(usize);
        for (reachable_cells) |c| {
            const n = self.countOf(c.class, c.bucket);
            if (n < min_count) min_count = n;
        }
        var ties: [reachable_cells.len]Cell = undefined;
        var k: usize = 0;
        for (reachable_cells) |c| {
            if (self.countOf(c.class, c.bucket) == min_count) {
                ties[k] = c;
                k += 1;
            }
        }
        return ties[prng.below(k)];
    }
};

/// The scheduling seam: a comptime vtable so a policy can carry its own
/// state (a coverage-guided one will want the running `Coverage` — or a
/// cross-run one persisted outside a single seed) without `vopr.zig` caring
/// which policy is installed.
pub const FaultScheduler = struct {
    ctx: *anyopaque,
    planFn: *const fn (ctx: *anyopaque, prng: *Prng, cov: *Coverage) FaultPlan,

    pub fn plan(self: FaultScheduler, prng: *Prng, cov: *Coverage) FaultPlan {
        return self.planFn(self.ctx, prng, cov);
    }
};

/// The module's original policy: flat PRNG draws, no feedback from
/// `Coverage` (it only records into it, never reads it back). Stateless —
/// `ctx` is unused.
///
/// Distribution (unchanged from the pre-`scheduler.zig` inline logic in
/// `Vopr.runSeed`): 60% a crash (uniform over the four `CrashMode`s, timing
/// biased 1-in-3 toward "early" — `below(8)` — else `below(120)`), 20% a
/// transient I/O error (`NoSpaceLeft` or `InputOutput`, same early/late
/// timing split over a `below(100)` late range), 20% a clean epoch.
pub fn uniformScheduler() FaultScheduler {
    return .{ .ctx = undefined, .planFn = uniformPlan };
}

const early_threshold_crash = 8;
const early_threshold_io = 8;

fn uniformPlan(ctx: *anyopaque, prng: *Prng, cov: *Coverage) FaultPlan {
    _ = ctx;
    const roll = prng.below(10);
    if (roll < 6) {
        const modes = [_]CrashMode{ .lose_unsynced, .keep_unsynced, .torn_tail, .reorder_unsynced };
        const mode = modes[prng.below(modes.len)];
        const reorder_seed = prng.next();
        const ops_until_crash = if (prng.chance(1, 3)) prng.below(early_threshold_crash) else prng.below(120);
        cov.record(FaultClass.ofCrash(mode), TimingBucket.of(ops_until_crash, early_threshold_crash));
        return .{ .crash = .{ .mode = mode, .reorder_seed = reorder_seed, .ops_until_crash = ops_until_crash } };
    } else if (roll < 8) {
        const ops_until_crash = if (prng.chance(1, 3)) prng.below(early_threshold_io) else prng.below(100);
        const kind: Storage.Error = if (prng.chance(1, 2)) error.NoSpaceLeft else error.InputOutput;
        cov.record(FaultClass.ofIoError(kind), TimingBucket.of(ops_until_crash, early_threshold_io));
        return .{ .io_error = .{ .kind = kind, .ops_until_crash = ops_until_crash } };
    }
    cov.record(.clean, .early);
    return .clean;
}

/// One (fault-class × timing-bucket) coordinate — the unit a coverage-guided
/// policy scores and selects.
pub const Cell = struct { class: FaultClass, bucket: TimingBucket };

/// The reachable cells: every (class × bucket) EXCEPT `(.clean, .late)`, which
/// is uncoverable by construction (a clean epoch has no fault to be early/late
/// about, so `uniformScheduler` always records `.clean` under `.early`). A
/// coverage-guided policy therefore targets these 13 cells; driving all 13 to
/// non-zero is "full coverage".
pub const reachable_cells = blk: {
    var arr: [FaultClass.count * TimingBucket.count]Cell = undefined;
    var n: usize = 0;
    for (0..FaultClass.count) |ci| {
        for (0..TimingBucket.count) |bi| {
            const class: FaultClass = @enumFromInt(ci);
            const bucket: TimingBucket = @enumFromInt(bi);
            if (class == .clean and bucket == .late) continue;
            arr[n] = .{ .class = class, .bucket = bucket };
            n += 1;
        }
    }
    const final = arr[0..n].*;
    break :blk final;
};

/// Map a bucket back to a concrete `ops_until_crash` offset that falls INSIDE
/// that bucket (`TimingBucket.of` must re-classify it identically): `.early`
/// draws `[0, threshold)`, `.late` draws `[threshold, hi)`. This is the piece
/// the bucket alone can't give (it only says early/late, not an exact offset).
fn bucketOffset(bucket: TimingBucket, prng: *Prng, threshold: usize, hi: usize) usize {
    return switch (bucket) {
        .early => prng.below(threshold),
        .late => threshold + prng.below(hi - threshold),
    };
}

/// Turn a chosen `Cell` into a concrete `FaultPlan` (fault class + timing +,
/// for crashes, a fresh `reorder_seed`). The produced plan re-classifies to
/// EXACTLY `cell` — so recording `cell` after building the plan is faithful.
fn cellToPlan(cell: Cell, prng: *Prng) FaultPlan {
    switch (cell.class) {
        .clean => return .clean,
        .io_no_space, .io_input_output => {
            const kind: Storage.Error = if (cell.class == .io_no_space) error.NoSpaceLeft else error.InputOutput;
            return .{ .io_error = .{
                .kind = kind,
                .ops_until_crash = bucketOffset(cell.bucket, prng, early_threshold_io, 100),
            } };
        },
        else => {
            const mode: CrashMode = switch (cell.class) {
                .lose_unsynced => .lose_unsynced,
                .keep_unsynced => .keep_unsynced,
                .torn_tail => .torn_tail,
                .reorder_unsynced => .reorder_unsynced,
                else => unreachable,
            };
            return .{ .crash = .{
                .mode = mode,
                .reorder_seed = prng.next(),
                .ops_until_crash = bucketOffset(cell.bucket, prng, early_threshold_crash, 120),
            } };
        },
    }
}

/// Coverage-guided fault-scheduling state — the intended upgrade over the
/// stateless `uniformScheduler`. It carries a `session` `Coverage` that
/// PERSISTS across seeds (the two concrete pieces a real policy needs: a
/// selection rule that reads the tally, and a tally that is not reset every
/// seed). Install it via `.scheduler()` and keep the `CoverageGuided` alive
/// for the whole seed loop (see `vopr.zig`'s coverage-guided tests).
///
/// Selection rule: bandit-style **epsilon-greedy over the (class × bucket)
/// cells**. With probability `1/explore_den` it *explores* (draws a uniformly
/// random reachable cell, so a cell the greedy rule keeps mis-scoring can't be
/// permanently starved); otherwise it *exploits* — picks the coldest reachable
/// cell in `session` (least `countOf`, random tie-break). Because exploit
/// deterministically drains the coldest cell, a session converges on full
/// (13-cell) coverage in ~13 exploit draws instead of waiting for uniform
/// sampling to stumble onto the ~1-in-24 rare cells (a late `.reorder_unsynced`
/// crash, a late I/O error). All randomness is from the seeded `prng`, so the
/// policy stays byte-for-byte reproducible.
pub const CoverageGuided = struct {
    /// Cross-seed tally the selection rule reads. NEVER reset within a run.
    session: Coverage = .{},
    /// Explore (draw a uniformly-random cell) 1-in-`explore_den` epochs.
    explore_den: usize = 8,

    pub fn scheduler(self: *CoverageGuided) FaultScheduler {
        return .{ .ctx = self, .planFn = plan };
    }

    fn plan(ctx: *anyopaque, prng: *Prng, cov: *Coverage) FaultPlan {
        const self: *CoverageGuided = @ptrCast(@alignCast(ctx));
        const cell = if (prng.chance(1, self.explore_den))
            randomCell(prng)
        else
            self.session.coldestReachableCell(prng);
        const fp = cellToPlan(cell, prng);
        // Record into BOTH the per-seed `cov` (so per-seed teeth assertions
        // still see every fault) and the cross-seed `session` (what the next
        // epoch's selection reads).
        cov.record(cell.class, cell.bucket);
        self.session.record(cell.class, cell.bucket);
        return fp;
    }

    fn randomCell(prng: *Prng) Cell {
        return reachable_cells[prng.below(reachable_cells.len)];
    }
};

/// Build a coverage-guided scheduler over caller-owned `state` whose `session`
/// tally survives the seed loop. Replaces the former stub — the selection rule
/// now lives in `CoverageGuided.plan`.
pub fn coverageGuidedScheduler(state: *CoverageGuided) FaultScheduler {
    return state.scheduler();
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "uniformScheduler: deterministic for a fixed PRNG state" {
    var cov_a: Coverage = .{};
    var cov_b: Coverage = .{};
    var prng_a = Prng.init(1234);
    var prng_b = Prng.init(1234);
    const sched = uniformScheduler();
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const plan_a = sched.plan(&prng_a, &cov_a);
        const plan_b = sched.plan(&prng_b, &cov_b);
        try testing.expectEqualDeep(plan_a, plan_b);
    }
    try testing.expectEqualDeep(cov_a, cov_b);
}

test "uniformScheduler: over many draws, exercises every FaultClass and both timing buckets" {
    var cov: Coverage = .{};
    var prng = Prng.init(99);
    const sched = uniformScheduler();
    var i: usize = 0;
    while (i < 5000) : (i += 1) _ = sched.plan(&prng, &cov);
    // Teeth: a scheduler that only ever hits one corner of the space
    // (e.g. a bug that always returns .clean) must fail this. `.clean` has
    // no meaningful timing (there is no fault to be early/late about), so
    // it is always recorded under `.early` — `(.clean, .late)` is the one
    // cell that can never be covered by construction, not a coverage gap.
    try testing.expectEqual(@as(usize, 1), cov.uncoveredCount());
    try testing.expectEqual(@as(usize, 0), cov.countOf(.clean, .late));
    inline for (@typeInfo(FaultClass).@"enum".fields) |f| {
        const class: FaultClass = @enumFromInt(f.value);
        if (class == .clean) continue;
        try testing.expect(cov.countOf(class, .early) > 0);
        try testing.expect(cov.countOf(class, .late) > 0);
    }
    try testing.expect(cov.countOf(.clean, .early) > 0);
}

test "Coverage: record/countOf/uncoveredCount agree" {
    var cov: Coverage = .{};
    try testing.expectEqual(FaultClass.count * TimingBucket.count, cov.uncoveredCount());
    cov.record(.torn_tail, .late);
    try testing.expectEqual(@as(usize, 1), cov.countOf(.torn_tail, .late));
    try testing.expectEqual(FaultClass.count * TimingBucket.count - 1, cov.uncoveredCount());
}

test "reachable_cells: 13 cells, excludes exactly the uncoverable (.clean, .late)" {
    try testing.expectEqual(@as(usize, FaultClass.count * TimingBucket.count - 1), reachable_cells.len);
    for (reachable_cells) |c| try testing.expect(!(c.class == .clean and c.bucket == .late));
}

test "cellToPlan: every reachable cell round-trips to a plan that re-classifies to itself" {
    var prng = Prng.init(7);
    for (reachable_cells) |cell| {
        const fp = cellToPlan(cell, &prng);
        const got: Cell = switch (fp) {
            .clean => .{ .class = .clean, .bucket = .early },
            .crash => |c| .{
                .class = FaultClass.ofCrash(c.mode),
                .bucket = TimingBucket.of(c.ops_until_crash, early_threshold_crash),
            },
            .io_error => |e| .{
                .class = FaultClass.ofIoError(e.kind),
                .bucket = TimingBucket.of(e.ops_until_crash, early_threshold_io),
            },
        };
        try testing.expectEqual(cell.class, got.class);
        try testing.expectEqual(cell.bucket, got.bucket);
    }
}

test "coverageGuidedScheduler: deterministic for a fixed PRNG + state" {
    var s_a: CoverageGuided = .{};
    var s_b: CoverageGuided = .{};
    var prng_a = Prng.init(0xABCD);
    var prng_b = Prng.init(0xABCD);
    var cov_a: Coverage = .{};
    var cov_b: Coverage = .{};
    const sched_a = s_a.scheduler();
    const sched_b = s_b.scheduler();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqualDeep(sched_a.plan(&prng_a, &cov_a), sched_b.plan(&prng_b, &cov_b));
    }
    try testing.expectEqualDeep(s_a.session, s_b.session);
}

test "coverageGuidedScheduler: measurably higher cell coverage than uniform on a fixed budget" {
    // The seam's whole point: on the SAME per-run draw budget, the coverage-
    // guided policy covers MORE distinct (class × bucket) cells than uniform
    // sampling. A single run is noisy (uniform can get lucky), so we sum the
    // uncovered-cell count over many independent runs — fewer-uncovered ==
    // more-covered. Each run threads its own cross-run `session` tally.
    const budget = 24; // > 13 reachable cells + slack for epsilon exploration
    const trials = 64;
    var uniform_uncovered: usize = 0;
    var guided_uncovered: usize = 0;
    var s: u64 = 1;
    while (s <= trials) : (s += 1) {
        const seed = s *% 0x9e3779b97f4a7c15 +% 1;

        var u_cov: Coverage = .{};
        var u_prng = Prng.init(seed);
        const u = uniformScheduler();
        for (0..budget) |_| _ = u.plan(&u_prng, &u_cov);
        uniform_uncovered += u_cov.uncoveredCount();

        var cg_state: CoverageGuided = .{};
        var cg_cov: Coverage = .{};
        var cg_prng = Prng.init(seed);
        const cg = cg_state.scheduler();
        for (0..budget) |_| _ = cg.plan(&cg_prng, &cg_cov);
        guided_uncovered += cg_state.session.uncoveredCount();
    }
    // Measurably higher distinct-cell coverage: strictly fewer cells left
    // uncovered, summed over the same budget.
    try testing.expect(guided_uncovered < uniform_uncovered);
    // Guided sits essentially at the coverage floor (1 uncoverable cell per
    // run == `trials`), give or take the odd run where epsilon exploration ate
    // into the exploit budget.
    try testing.expect(guided_uncovered <= trials + trials / 4);
}
