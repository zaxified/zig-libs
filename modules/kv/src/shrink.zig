// SPDX-License-Identifier: MIT

//! Failing-seed search + delta-debugging shrinker for kv's VOPR (`vopr.zig`).
//!
//! `findFailingSeed` sweeps a seed range through `vopr.runSeedTraced`,
//! capturing the first seed whose invariant checker trips (the `Event` trace
//! is kept as a human-readable failure report).
//!
//! `shrink` minimizes a failing run to a small reproducer via delta-debugging
//! (ddmin). The blocker the original scaffold documented — kv's VOPR draws its
//! whole workload+fault schedule LIVE from the seed's `Prng`, so a captured
//! `Event` trace is an observation, not a re-runnable program — is resolved by
//! `vopr.zig`'s **trace-replay mode**: `vopr.generateTrace` re-captures the
//! seed as a `RecordedTrace` (concrete op list with actual value bytes, crash
//! mode/timing/reorder seed, garbage bytes, sabotage), and `vopr.replayTrace`
//! executes any subset of it deterministically WITHOUT a live `Prng`. `shrink`
//! then runs ddmin over that recorded trace: it drops ops, drops whole epochs,
//! and neutralizes faults, re-replaying after every candidate cut and keeping
//! the reduction only when the SAME invariant violation still reproduces.

const std = @import("std");
const vopr = @import("vopr.zig");
const Allocator = std.mem.Allocator;

/// A captured failing run: the seed, the config it failed under, the full
/// op/fault `Event` trace up to the point of failure, the aggregate stats, and
/// the error the invariant checker raised. Owns `trace` — call `deinit`.
pub const FailingRun = struct {
    seed: u64,
    cfg: vopr.Config,
    trace: std.ArrayList(vopr.Event),
    stats: vopr.Stats,
    err: anyerror,

    pub fn deinit(self: *FailingRun, gpa: Allocator) void {
        self.trace.deinit(gpa);
        self.* = undefined;
    }
};

/// Sweep `[start, end]` (inclusive) for the first seed under `cfg` that
/// trips an invariant violation in `vopr.runSeedTraced`. Returns `null` if
/// every seed in the range passes.
pub fn findFailingSeed(gpa: Allocator, start: u64, end: u64, cfg: vopr.Config) !?FailingRun {
    var seed = start;
    while (true) : (seed += 1) {
        var stats: vopr.Stats = .{};
        var trace: std.ArrayList(vopr.Event) = .empty;
        if (vopr.runSeedTraced(gpa, seed, cfg, &stats, &trace)) |_| {
            trace.deinit(gpa);
        } else |e| {
            return FailingRun{ .seed = seed, .cfg = cfg, .trace = trace, .stats = stats, .err = e };
        }
        if (seed == end) break;
    }
    return null;
}

/// A shrunk reproducer: a `RecordedTrace` with fewer ops than the run it was
/// derived from, still reproducing the SAME failure via `vopr.replayTrace`.
/// Owns `trace`.
pub const ShrinkResult = struct {
    seed: u64,
    trace: vopr.RecordedTrace,
    /// Concrete-op count before / after minimization.
    ops_before: usize,
    ops_after: usize,

    pub fn deinit(self: *ShrinkResult) void {
        self.trace.deinit();
        self.* = undefined;
    }
};

pub const ShrinkError = error{
    /// Re-capturing `failing.seed` as a `RecordedTrace` did not reproduce
    /// `failing.err` (the captured trace and the live run diverged — nothing
    /// to minimize). Not expected for the deterministic self-test paths.
    CannotReproduce,
} || Allocator.Error;

/// Delta-debug `failing` down to a smaller reproducer of the SAME failure.
///
/// Re-captures the seed as a replayable `vopr.RecordedTrace`, confirms it still
/// reproduces `failing.err`, then minimizes in three ddmin passes — drop ops,
/// drop whole epochs, neutralize per-epoch faults/garbage — re-verifying the
/// identical `failing.err` (not just *a* failure) after every candidate cut.
pub fn shrink(gpa: Allocator, failing: *const FailingRun) ShrinkError!ShrinkResult {
    var src = try vopr.generateTrace(gpa, failing.seed, failing.cfg);
    defer src.deinit();
    const before = vopr.opCount(src.epochs);

    // The captured full trace must reproduce the SAME failure before we cut.
    if (!failsSame(gpa, failing.err, src.seed, src.epochs)) return error.CannotReproduce;

    // ── flatten every op into one list, tagged with its epoch ────────────────
    const flat = try gpa.alloc(FlatOp, before);
    defer gpa.free(flat);
    {
        var w: usize = 0;
        for (src.epochs, 0..) |ep, ei| {
            for (ep.ops) |op| {
                flat[w] = .{ .epoch = ei, .op = op };
                w += 1;
            }
        }
    }

    // ── Pass A: ddmin over the flat op list ──────────────────────────────────
    var ops_ctx = OpsCtx{ .gpa = gpa, .target = failing.err, .seed = src.seed, .src = src.epochs, .flat = flat };
    const kept_ops = try ddmin(gpa, before, &ops_ctx, OpsCtx.keeps);
    defer gpa.free(kept_ops);

    // Materialize the op-minimized epochs (gpa-owned op arrays).
    const ops_min = try buildEpochsFromSubset(gpa, src.epochs, flat, kept_ops);
    defer freeBuiltEpochs(gpa, ops_min);

    // ── Pass B: ddmin over whole epochs ──────────────────────────────────────
    var ep_ctx = EpochCtx{ .gpa = gpa, .target = failing.err, .seed = src.seed, .src = ops_min };
    const kept_eps = try ddmin(gpa, ops_min.len, &ep_ctx, EpochCtx.keeps);
    defer gpa.free(kept_eps);

    const kept = try gpa.alloc(vopr.RecordedEpoch, kept_eps.len);
    defer gpa.free(kept);
    for (kept_eps, 0..) |ei, i| kept[i] = ops_min[ei]; // shares op arrays with ops_min

    // ── Pass C: neutralize each surviving epoch's fault + garbage tail ───────
    neutralize(gpa, failing.err, src.seed, kept);

    // ── clone the minimized program into a self-owned trace ──────────────────
    var out = try cloneTrace(gpa, src.seed, src.cfg, kept);
    errdefer out.deinit();
    return .{ .seed = failing.seed, .trace = out, .ops_before = before, .ops_after = vopr.opCount(out.epochs) };
}

// ── ddmin machinery ─────────────────────────────────────────────────────────

const FlatOp = struct { epoch: usize, op: vopr.RecordedOp };

/// Does replaying `epochs` reproduce EXACTLY `target` (not merely *some*
/// failure)? The delta-debugging oracle. Any other outcome (pass, or a
/// different error such as an unexpected OOM) counts as "not reproduced".
fn failsSame(gpa: Allocator, target: anyerror, seed: u64, epochs: []const vopr.RecordedEpoch) bool {
    if (vopr.replayTrace(gpa, seed, epochs)) |_| {
        return false;
    } else |e| {
        return e == target;
    }
}

/// Classic Zeller ddmin (complement-removal form) over `n` elements. `keeps`
/// answers "does this subset of indices still reproduce the failure?"; the
/// returned index list is the minimized subset (owned by the caller).
fn ddmin(
    gpa: Allocator,
    n: usize,
    ctx: anytype,
    comptime keeps: fn (@TypeOf(ctx), []const usize) Allocator.Error!bool,
) Allocator.Error![]usize {
    var current = try gpa.alloc(usize, n);
    errdefer gpa.free(current);
    for (0..n) |i| current[i] = i;

    var granularity: usize = 2;
    while (current.len >= 2) {
        const chunk = (current.len + granularity - 1) / granularity;
        var removed = false;
        var start: usize = 0;
        while (start < current.len) : (start += chunk) {
            const end = @min(start + chunk, current.len);
            const comp = try gpa.alloc(usize, current.len - (end - start));
            var w: usize = 0;
            for (current, 0..) |v, i| {
                if (i < start or i >= end) {
                    comp[w] = v;
                    w += 1;
                }
            }
            if (try keeps(ctx, comp)) {
                gpa.free(current);
                current = comp;
                granularity = if (granularity > 2) granularity - 1 else 2;
                removed = true;
                break;
            }
            gpa.free(comp);
        }
        if (!removed) {
            if (granularity >= current.len) break;
            granularity = @min(granularity * 2, current.len);
        }
    }
    return current;
}

const OpsCtx = struct {
    gpa: Allocator,
    target: anyerror,
    seed: u64,
    src: []const vopr.RecordedEpoch,
    flat: []const FlatOp,

    fn keeps(ctx: *OpsCtx, subset: []const usize) Allocator.Error!bool {
        const epochs = try buildEpochsFromSubset(ctx.gpa, ctx.src, ctx.flat, subset);
        defer freeBuiltEpochs(ctx.gpa, epochs);
        return failsSame(ctx.gpa, ctx.target, ctx.seed, epochs);
    }
};

const EpochCtx = struct {
    gpa: Allocator,
    target: anyerror,
    seed: u64,
    src: []const vopr.RecordedEpoch,

    fn keeps(ctx: *EpochCtx, subset: []const usize) Allocator.Error!bool {
        const epochs = try ctx.gpa.alloc(vopr.RecordedEpoch, subset.len);
        defer ctx.gpa.free(epochs); // shares op arrays with ctx.src — not freed here
        for (subset, 0..) |ei, i| epochs[i] = ctx.src[ei];
        return failsSame(ctx.gpa, ctx.target, ctx.seed, epochs);
    }
};

/// Rebuild the full epoch list keeping only the flat-ops named by `subset`
/// (epochs keep their fault/garbage/sabotage; an epoch that loses all its ops
/// still runs). Op arrays are gpa-owned — free with `freeBuiltEpochs`.
fn buildEpochsFromSubset(
    gpa: Allocator,
    src: []const vopr.RecordedEpoch,
    flat: []const FlatOp,
    subset: []const usize,
) Allocator.Error![]vopr.RecordedEpoch {
    const counts = try gpa.alloc(usize, src.len);
    defer gpa.free(counts);
    @memset(counts, 0);
    for (subset) |idx| counts[flat[idx].epoch] += 1;

    const op_arrays = try gpa.alloc([]vopr.RecordedOp, src.len);
    defer gpa.free(op_arrays);
    var made: usize = 0;
    errdefer for (0..made) |e| gpa.free(op_arrays[e]);
    for (0..src.len) |e| {
        op_arrays[e] = try gpa.alloc(vopr.RecordedOp, counts[e]);
        made += 1;
    }

    const cursors = try gpa.alloc(usize, src.len);
    defer gpa.free(cursors);
    @memset(cursors, 0);
    for (subset) |idx| {
        const e = flat[idx].epoch;
        op_arrays[e][cursors[e]] = flat[idx].op;
        cursors[e] += 1;
    }

    const out = try gpa.alloc(vopr.RecordedEpoch, src.len);
    for (out, 0..) |*ep, e| ep.* = .{
        .fault = src[e].fault,
        .short_reads = src[e].short_reads,
        .ops = op_arrays[e],
        .garbage = src[e].garbage,
        .sabotage = src[e].sabotage,
    };
    return out;
}

fn freeBuiltEpochs(gpa: Allocator, epochs: []vopr.RecordedEpoch) void {
    for (epochs) |ep| gpa.free(@constCast(ep.ops));
    gpa.free(epochs);
}

/// Greedily simplify each surviving epoch: try replacing its fault with
/// `.clean` and dropping its garbage tail, keeping the simplification only if
/// the failure still reproduces (so a crash/error/garbage that the failure did
/// not actually need is removed).
fn neutralize(gpa: Allocator, target: anyerror, seed: u64, epochs: []vopr.RecordedEpoch) void {
    for (epochs) |*ep| {
        switch (ep.fault) {
            .clean => {},
            else => {
                const saved = ep.fault;
                ep.fault = .clean;
                if (!failsSame(gpa, target, seed, epochs)) ep.fault = saved;
            },
        }
        if (ep.garbage.len > 0) {
            const saved = ep.garbage;
            ep.garbage = &.{};
            if (!failsSame(gpa, target, seed, epochs)) ep.garbage = saved;
        }
    }
}

/// Deep-copy `epochs` (value bytes + garbage) into a fresh self-owned
/// `RecordedTrace`, so the result outlives the source trace and all scratch.
fn cloneTrace(gpa: Allocator, seed: u64, cfg: vopr.Config, epochs: []const vopr.RecordedEpoch) Allocator.Error!vopr.RecordedTrace {
    var arena_owner = std.heap.ArenaAllocator.init(gpa);
    errdefer arena_owner.deinit();
    const a = arena_owner.allocator();

    const out = try a.alloc(vopr.RecordedEpoch, epochs.len);
    for (epochs, out) |src_ep, *dst| {
        const ops = try a.alloc(vopr.RecordedOp, src_ep.ops.len);
        for (src_ep.ops, ops) |so, *dop| {
            dop.* = switch (so) {
                .put => |p| .{ .put = .{ .key = p.key, .val = try a.dupe(u8, p.val) } },
                else => so,
            };
        }
        var garbage: []const u8 = &.{};
        if (src_ep.garbage.len > 0) garbage = try a.dupe(u8, src_ep.garbage);
        dst.* = .{
            .fault = src_ep.fault,
            .short_reads = src_ep.short_reads,
            .ops = ops,
            .garbage = garbage,
            .sabotage = src_ep.sabotage,
        };
    }
    return .{ .arena = arena_owner, .seed = seed, .cfg = cfg, .epochs = out };
}

// ── CLI-style entry point ───────────────────────────────────────────────────

pub const RunArgs = struct {
    seed: ?u64 = null,
    search: ?struct { start: u64, end: u64 } = null,
    do_shrink: bool = false,
    sabotage: bool = false,
    quiet: bool = false,
};

pub const ParseError = error{ MissingArgument, UnknownArgument, InvalidNumber, NoSeedOrSearchGiven };

/// Parse CLI-style args (e.g. from `std.process.argsAlloc`, minus argv[0]):
///   --seed N              replay exactly seed N
///   --search START END    sweep [START, END] for the first failure
///   --shrink               after a failure is found, delta-debug it to a minimal trace
///   --sabotage              run with Config.sabotage = true (self-test mode)
///   --quiet                 suppress the VOPR's own stderr failure report
pub fn parseArgs(args: []const []const u8) ParseError!RunArgs {
    var out: RunArgs = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--seed")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            out.seed = std.fmt.parseInt(u64, args[i], 10) catch return error.InvalidNumber;
        } else if (std.mem.eql(u8, a, "--search")) {
            if (i + 2 >= args.len) return error.MissingArgument;
            const start = std.fmt.parseInt(u64, args[i + 1], 10) catch return error.InvalidNumber;
            const end = std.fmt.parseInt(u64, args[i + 2], 10) catch return error.InvalidNumber;
            out.search = .{ .start = start, .end = end };
            i += 2;
        } else if (std.mem.eql(u8, a, "--shrink")) {
            out.do_shrink = true;
        } else if (std.mem.eql(u8, a, "--sabotage")) {
            out.sabotage = true;
        } else if (std.mem.eql(u8, a, "--quiet")) {
            out.quiet = true;
        } else {
            return error.UnknownArgument;
        }
    }
    if (out.seed == null and out.search == null) return error.NoSeedOrSearchGiven;
    return out;
}

/// The driver: parse args, run (single seed or a seed-range search), report to
/// `writer`, and — when `--shrink` was passed and a failure was found — minimize
/// it via `shrink` and report the reduction. Returns `true` if no failure was
/// found, `false` if a failure was found and reported.
pub fn run(gpa: Allocator, args: []const []const u8, writer: *std.Io.Writer) !bool {
    const parsed = try parseArgs(args);
    const cfg: vopr.Config = .{ .sabotage = parsed.sabotage, .quiet = parsed.quiet };

    if (parsed.seed) |seed| {
        var stats: vopr.Stats = .{};
        var trace: std.ArrayList(vopr.Event) = .empty;
        defer trace.deinit(gpa);
        if (vopr.runSeedTraced(gpa, seed, cfg, &stats, &trace)) |_| {
            try writer.print("seed {d}: PASS ({d} epochs, {d} acked ops)\n", .{ seed, stats.epochs, stats.acked_ops });
            return true;
        } else |e| {
            try writer.print("seed {d}: FAIL ({t}) — {d} trace events captured\n", .{ seed, e, trace.items.len });
            if (parsed.do_shrink) {
                var captured = FailingRun{ .seed = seed, .cfg = cfg, .trace = trace, .stats = stats, .err = e };
                trace = .empty; // ownership moved into `captured`
                defer captured.deinit(gpa);
                try reportShrink(gpa, &captured, writer);
            }
            return false;
        }
    }

    const s = parsed.search.?; // parseArgs guarantees seed or search is set
    if (try findFailingSeed(gpa, s.start, s.end, cfg)) |found_const| {
        var found = found_const;
        defer found.deinit(gpa);
        try writer.print(
            "search [{d},{d}]: FAIL at seed {d} ({t}), {d} trace events\n",
            .{ s.start, s.end, found.seed, found.err, found.trace.items.len },
        );
        if (parsed.do_shrink) try reportShrink(gpa, &found, writer);
        return false;
    }
    try writer.print("no failure in [{d},{d}]\n", .{ s.start, s.end });
    return true;
}

fn reportShrink(gpa: Allocator, failing: *const FailingRun, writer: *std.Io.Writer) !void {
    var result = shrink(gpa, failing) catch |e| switch (e) {
        error.CannotReproduce => {
            try writer.print("  shrink: could not re-capture seed {d} as a replayable trace\n", .{failing.seed});
            return;
        },
        else => |other| return other,
    };
    defer result.deinit();
    try writer.print(
        "  shrink: {d} ops → {d} ops ({d} epochs) — minimized reproducer\n",
        .{ result.ops_before, result.ops_after, result.trace.epochs.len },
    );
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseArgs: --seed" {
    const a = try parseArgs(&.{ "--seed", "42" });
    try testing.expectEqual(@as(?u64, 42), a.seed);
    try testing.expect(a.search == null);
}

test "parseArgs: --search" {
    const a = try parseArgs(&.{ "--search", "1", "100" });
    try testing.expectEqual(@as(u64, 1), a.search.?.start);
    try testing.expectEqual(@as(u64, 100), a.search.?.end);
}

test "parseArgs: rejects unknown flags" {
    try testing.expectError(error.UnknownArgument, parseArgs(&.{"--bogus"}));
}

test "parseArgs: requires --seed or --search" {
    try testing.expectError(error.NoSeedOrSearchGiven, parseArgs(&.{"--shrink"}));
}

test "parseArgs: rejects a truncated --search" {
    try testing.expectError(error.MissingArgument, parseArgs(&.{ "--search", "1" }));
}

test "run: a passing seed reports PASS and returns true" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const ok = try run(testing.allocator, &.{ "--seed", "1" }, &w);
    try testing.expect(ok);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "PASS") != null);
}

test "run: a failing search (sabotage) reports FAIL without invoking shrink" {
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const ok = try run(testing.allocator, &.{ "--search", "1", "12", "--sabotage", "--quiet" }, &w);
    try testing.expect(!ok);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "FAIL") != null);
}

test "findFailingSeed: the sabotage self-test config reliably yields a failing run with a real trace" {
    const cfg: vopr.Config = .{ .sabotage = true, .quiet = true };
    var found = (try findFailingSeed(testing.allocator, 1, 12, cfg)).?;
    defer found.deinit(testing.allocator);
    try testing.expectEqual(error.InvariantViolation, found.err);
    try testing.expect(found.trace.items.len > 0);
}

test "findFailingSeed: a clean sweep with no faults finds nothing" {
    const NeverFaults = struct {
        fn planFn(ctx: *anyopaque, prng: *@import("prng.zig").Prng, cov: *vopr.Coverage) @import("scheduler.zig").FaultPlan {
            _ = ctx;
            _ = prng;
            cov.record(.clean, .early);
            return .clean;
        }
    };
    const cfg: vopr.Config = .{ .scheduler = .{ .ctx = undefined, .planFn = NeverFaults.planFn } };
    const found = try findFailingSeed(testing.allocator, 1, 5, cfg);
    try testing.expect(found == null);
}

test "shrink: delta-debugs a failing sabotage trace to a strictly smaller reproducer" {
    const cfg: vopr.Config = .{ .sabotage = true, .quiet = true };
    // Find a seed whose RECORDED trace reproduces the invariant failure under
    // replay (the shrinker's world), so the reduction is self-consistent.
    var seed: u64 = 1;
    const failing_seed = while (seed <= 64) : (seed += 1) {
        var tr = try vopr.generateTrace(testing.allocator, seed, cfg);
        defer tr.deinit();
        if (vopr.replayTrace(testing.allocator, tr.seed, tr.epochs)) |_| {} else |e| {
            if (e == error.InvariantViolation) break seed;
        }
    } else return error.NoFailingSeed;

    var fr = FailingRun{
        .seed = failing_seed,
        .cfg = cfg,
        .trace = .empty,
        .stats = .{},
        .err = error.InvariantViolation,
    };
    defer fr.deinit(testing.allocator);

    var result = try shrink(testing.allocator, &fr);
    defer result.deinit();

    // Strictly smaller than the captured run...
    try testing.expect(result.ops_after < result.ops_before);
    try testing.expect(result.ops_after > 0);
    // ...and the minimized trace STILL reproduces the same invariant failure.
    try testing.expectError(
        error.InvariantViolation,
        vopr.replayTrace(testing.allocator, result.trace.seed, result.trace.epochs),
    );
}

test "shrink: the minimized trace is self-contained (survives freeing the source)" {
    const cfg: vopr.Config = .{ .sabotage = true, .quiet = true };
    var seed: u64 = 1;
    const failing_seed = while (seed <= 64) : (seed += 1) {
        var tr = try vopr.generateTrace(testing.allocator, seed, cfg);
        defer tr.deinit();
        if (vopr.replayTrace(testing.allocator, tr.seed, tr.epochs)) |_| {} else |e| {
            if (e == error.InvariantViolation) break seed;
        }
    } else return error.NoFailingSeed;

    var fr = FailingRun{ .seed = failing_seed, .cfg = cfg, .trace = .empty, .stats = .{}, .err = error.InvariantViolation };
    defer fr.deinit(testing.allocator);
    var result = try shrink(testing.allocator, &fr);
    defer result.deinit();
    // Replay twice: the owned trace's value bytes are independent of any freed
    // scratch, so the reproduction is stable.
    try testing.expectError(error.InvariantViolation, vopr.replayTrace(testing.allocator, result.trace.seed, result.trace.epochs));
    try testing.expectError(error.InvariantViolation, vopr.replayTrace(testing.allocator, result.trace.seed, result.trace.epochs));
}
