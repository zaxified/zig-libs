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
        .protocol = .{ .ctx = &unused, .onMessageFn = noopOnMessage },
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
        .protocol = .{ .ctx = &unused, .onMessageFn = noopOnMessage, .checkFn = alwaysViolatingCheck },
        .until = 100,
    };
    var failing = (try findFailing(gpa, template, .{}, 1, 10)) orelse return error.ExpectedFailure;
    defer failing.deinit();
    try testing.expectEqual(error.AlwaysBroken, failing.err);
}
