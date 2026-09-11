// SPDX-License-Identifier: MIT

//! Failing-seed search + delta-debugging shrinker over fault traces.
//!
//! `findFailing` sweeps a seed range, fuzzing a schedule per seed (`sim.run`)
//! until one trips the protocol's invariant — capturing the seed, the concrete
//! `FaultTrace` that broke it, and the exact error.
//!
//! `shrink` minimizes that trace to a small reproducer via classic Zeller ddmin
//! (complement removal): it drops subsets of fault events and re-replays after
//! every cut, keeping a reduction only when the SAME invariant error still
//! reproduces. Because `sim.replay` is a deterministic oracle over a concrete
//! trace, a shrunk subset is directly re-runnable — no live fuzzer in the loop.
//! The result is the minimal set of faults that still provokes the bug (e.g. the
//! single duplicate that starts a forwarding loop), cloned into a self-owned trace.

const std = @import("std");
const sim = @import("sim.zig");
const fault = @import("fault.zig");
const NodeId = @import("types.zig").NodeId;
const Allocator = std.mem.Allocator;

/// A captured failing run: the case (with the failing seed baked in), the fault
/// trace that broke it, and the invariant error. Owns `trace` — call `deinit`.
pub const Failing = struct {
    case: sim.Case,
    trace: fault.FaultTrace,
    err: anyerror,

    pub fn deinit(self: *Failing) void {
        self.trace.deinit();
        self.* = undefined;
    }
};

/// Sweep `[start, end]` (inclusive): for each seed, fuzz a schedule and replay
/// it; return the first that trips an invariant. `null` if every seed passes.
pub fn findFailing(
    gpa: Allocator,
    template: sim.Case,
    fault_cfg: fault.Config,
    start: u64,
    end: u64,
) anyerror!?Failing {
    // audit F7: the loop below has exactly one exit condition, `seed == end`.
    // With `start > end` that never becomes true on the way up — the loop
    // walks off the top of `u64`, wraps to 0, and keeps going until it
    // reaches `end` roughly 2^64 seeds later (measured: ~2296 seeds/s, so
    // ~2.5e8 years). `[start, end]` with `start > end` is documented as an
    // inclusive sweep, which for a reversed range is the empty set, not that.
    if (start > end) return null;
    var seed = start;
    while (true) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try sim.run(gpa, case, fault_cfg);
        if (gr.result.outcome == .violated) {
            return Failing{ .case = case, .trace = gr.trace, .err = gr.result.violation.?.err };
        }
        gr.trace.deinit();
        if (seed == end) break;
    }
    return null;
}

pub const ShrinkResult = struct {
    trace: fault.FaultTrace,
    before: usize,
    after: usize,

    pub fn deinit(self: *ShrinkResult) void {
        self.trace.deinit();
        self.* = undefined;
    }
};

/// Delta-debug `failing` down to a minimal reproducer of the SAME error.
pub fn shrink(gpa: Allocator, failing: *const Failing) Allocator.Error!ShrinkResult {
    const events = failing.trace.events;
    const before = events.len;

    var ctx = Ctx{ .gpa = gpa, .case = failing.case, .target = failing.err, .events = events };
    const kept = try ddmin(gpa, before, &ctx);
    defer gpa.free(kept);

    var out = try cloneSubset(gpa, events, kept);
    errdefer out.deinit();
    return .{ .trace = out, .before = before, .after = kept.len };
}

const Ctx = struct {
    gpa: Allocator,
    case: sim.Case,
    target: anyerror,
    events: []const fault.FaultEvent,

    /// Does replaying just the `subset` (indices into `events`) reproduce the
    /// exact target error? The ddmin oracle.
    fn keeps(self: *Ctx, subset: []const usize) Allocator.Error!bool {
        const sub = try self.gpa.alloc(fault.FaultEvent, subset.len);
        defer self.gpa.free(sub);
        for (subset, 0..) |idx, i| sub[i] = self.events[idx];
        // A real error (e.g. OOM) is "not reproduced"; only the same invariant
        // violation counts.
        const r = sim.replay(self.gpa, self.case, sub, null) catch return false;
        return r.outcome == .violated and r.violation.?.err == self.target;
    }
};

/// Classic Zeller ddmin (complement-removal) over `n` element indices.
fn ddmin(gpa: Allocator, n: usize, ctx: *Ctx) Allocator.Error![]usize {
    // audit F6: the loop below never considers the EMPTY subset — it floors
    // at `current.len == 1` because its only exit test is `current.len >= 2`.
    // For a protocol that's broken regardless of any fault (the checker
    // trips on a clean `replay(case, &.{})`, e.g. `raft`'s `BrokenRaft` and
    // `df-elect`'s `BrokenAlwaysDf` — both documented as firing "on a clean
    // run with no injected faults"), the TRUE minimal reproducer is zero
    // faults, and the floor manufactures a misleading "minimal" counter-
    // example that blames an arbitrary surviving fault for a bug that has
    // nothing to do with any of them. Whether the empty set reproduces
    // depends only on `ctx.case`/`ctx.target`, never on which indices
    // `current` holds, so testing it once up front is exact — no need to
    // retest it after every reduction step below.
    if (try ctx.keeps(&.{})) {
        return try gpa.alloc(usize, 0);
    }

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
            if (try ctx.keeps(comp)) {
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

/// Deep-copy the kept events (including partition cut slices) into a fresh,
/// self-owned trace.
fn cloneSubset(gpa: Allocator, events: []const fault.FaultEvent, kept: []const usize) Allocator.Error!fault.FaultTrace {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const out = try a.alloc(fault.FaultEvent, kept.len);
    for (kept, 0..) |idx, i| {
        var ev = events[idx];
        switch (ev.kind) {
            .partition => |p| ev.kind = .{ .partition = .{ .id = p.id, .cut = try a.dupe(NodeId, p.cut) } },
            else => {},
        }
        out[i] = ev;
    }
    return .{ .arena = arena, .events = out };
}

const testing = std.testing;

fn noopOnMessage(_: *anyopaque, _: *sim.Sim, _: sim.NodeId, _: sim.NodeId, _: []const u8) anyerror!void {}

/// audit F3: `resetFn` is mandatory now; none of the fixtures below have
/// per-node state worth clearing (each builds a fresh ctx per test).
fn noReset(_: *anyopaque) void {}

fn twoNodeScenario(s: *sim.Sim) anyerror!void {
    _ = try s.addNode(.{});
    _ = try s.addNode(.{});
}

test "findFailing: a reversed range [start, end] with start > end is the empty sweep, not ~2^64 seeds (audit F7)" {
    // Before the fix, the loop's only exit condition was `seed == end`; with
    // `start > end` that is never reached on the way up, so it wraps almost
    // the entire u64 space (measured in the audit: forward sweep runs at
    // ~2296 seeds/s, so the wrap is ~2.5e8 years — confirmed here separately
    // via a bounded probe that the pre-fix loop times out rather than
    // returns). `[start, end]` is documented as inclusive, and a reversed
    // range is the empty set, not "every seed".
    const gpa = testing.allocator;
    var unused: usize = 0;
    const template = sim.Case{
        .seed = 0,
        .scenario = twoNodeScenario,
        .protocol = .{ .ctx = &unused, .onMessageFn = noopOnMessage, .resetFn = noReset },
        .until = 100,
    };
    const result = try findFailing(gpa, template, .{}, 100, 50);
    try testing.expect(result == null);
}

fn alwaysViolatingCheck(_: *anyopaque, _: *const sim.Sim) anyerror!void {
    return error.AlwaysBroken;
}

test "findFailing: a forward range still searches and returns a real failure (positive control for F7)" {
    const gpa = testing.allocator;
    var unused: usize = 0;
    const template = sim.Case{
        .seed = 0,
        .scenario = twoNodeScenario,
        .protocol = .{ .ctx = &unused, .onMessageFn = noopOnMessage, .checkFn = alwaysViolatingCheck, .resetFn = noReset },
        .until = 100,
    };
    var failing = (try findFailing(gpa, template, .{}, 1, 10)) orelse return error.ExpectedFailure;
    defer failing.deinit();
    try testing.expectEqual(error.AlwaysBroken, failing.err);
}

test "shrink: a protocol broken regardless of faults shrinks the empty set to zero, not one (audit F6)" {
    // ddmin used to floor at `current.len == 1` (its only loop guard was
    // `while (current.len >= 2)`), so a protocol that fails even with ZERO
    // faults — the checker trips on a clean `replay(case, &.{})` — got
    // handed a misleading "minimal" reproducer that blames an arbitrary
    // single surviving fault for a bug the fault trace never caused. This
    // is exactly the shape of `raft`'s `BrokenRaft` and `df-elect`'s
    // `BrokenAlwaysDf` positive controls (both documented to fire "on a
    // clean run with no injected faults" — see their own modules' shrink
    // tests, updated in this same commit for the same reason).
    const gpa = testing.allocator;
    var unused: usize = 0;
    const template = sim.Case{
        .seed = 0,
        .scenario = twoNodeScenario,
        .protocol = .{ .ctx = &unused, .onMessageFn = noopOnMessage, .checkFn = alwaysViolatingCheck, .resetFn = noReset },
        .until = 100,
    };
    var failing = (try findFailing(gpa, template, .{}, 1, 10)) orelse return error.ExpectedFailure;
    defer failing.deinit();

    var res = try shrink(gpa, &failing);
    defer res.deinit();
    // RED (pre-fix ddmin): this was 1, not 0 — a fault blamed for nothing.
    try testing.expectEqual(@as(usize, 0), res.after);

    // The empty trace genuinely still reproduces — this isn't a floor
    // reported without checking it actually replays.
    const r = try sim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(sim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.AlwaysBroken, r.violation.?.err);
}

// ── audit F8: a hook crash is a reproducer, not a dead sweep ────────────────

fn ringScenario(s: *sim.Sim) anyerror!void {
    _ = try s.addNode(.{});
    _ = try s.addNode(.{});
    try s.addBiLink(0, 1, .{ .latency = 1 });
}

/// Node 0 pings node 1 on a timer forever; node 1 counts receptions and
/// crashes on the third — the audit's own repro shape ("a protocol that
/// returns error.ProtocolBlewUp after its third message"), independent of
/// any injected fault.
const Crashy = struct {
    recv_count: usize = 0,

    fn cast(ctx: *anyopaque) *Crashy {
        return @ptrCast(@alignCast(ctx));
    }

    fn protocol(self: *Crashy) sim.Protocol {
        return .{ .ctx = self, .onStartFn = onStart, .onMessageFn = onMessage, .onTimerFn = onTimer, .resetFn = reset };
    }

    fn reset(ctx: *anyopaque) void {
        cast(ctx).recv_count = 0;
    }

    fn ping(s: *sim.Sim) anyerror!void {
        try s.send(0, 1, "ping");
        try s.setTimer(0, 10, 0);
    }

    fn onStart(_: *anyopaque, s: *sim.Sim, node: sim.NodeId) anyerror!void {
        if (node == 0) try ping(s);
    }

    fn onTimer(_: *anyopaque, s: *sim.Sim, node: sim.NodeId, _: u64) anyerror!void {
        if (node == 0) try ping(s);
    }

    fn onMessage(ctx: *anyopaque, _: *sim.Sim, node: sim.NodeId, _: sim.NodeId, _: []const u8) anyerror!void {
        if (node != 1) return;
        const self = cast(ctx);
        self.recv_count += 1;
        if (self.recv_count == 3) return error.ProtocolBlewUp;
    }
};

test "findFailing: a hook crash produces a reproducer instead of killing the whole sweep (audit F8)" {
    // Before F8, this crash propagated raw out of `sim.run` via `try`
    // inside `findFailing`, which had no `catch` around it — the entire
    // sweep died on whichever seed first reached 3 messages, with no seed,
    // no trace, nothing to reproduce with. The fix lives entirely in
    // sim.zig (`Sim.hookErr`): `sim.run` no longer propagates a hook's own
    // error at all, so this call succeeds and returns a normal `Failing`,
    // with no change needed here in shrink.zig.
    const gpa = testing.allocator;
    var crashy = Crashy{};
    const template = sim.Case{
        .seed = 0,
        .scenario = ringScenario,
        .protocol = crashy.protocol(),
        .until = 500,
    };

    var failing = (try findFailing(gpa, template, .{}, 1, 50)) orelse return error.ExpectedFailure;
    defer failing.deinit();
    try testing.expectEqual(error.ProtocolBlewUp, failing.err);

    // And it shrinks like any other reproducer: `Ctx.keeps` sees the SAME
    // error recur on a subset as `.violated` with a matching `.err` — the
    // same representation `checkFn`-triggered violations already use, so
    // no special-casing was needed in `Ctx.keeps` either.
    var res = try shrink(gpa, &failing);
    defer res.deinit();
    const r = try sim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(sim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.ProtocolBlewUp, r.violation.?.err);
}
