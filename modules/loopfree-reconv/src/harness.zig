// SPDX-License-Identifier: MIT
//! Thin `run`/`findFailing`/`shrink` wrappers around `netsim`'s own
//! (identically-named) top-level drivers.
//!
//! Why not call `netsim.run`/`netsim.findFailing`/`netsim.shrink` directly?
//! Because `Fabric` needs to know the EXACT fault schedule it's about to be
//! replayed against before the run starts (see `fabric.zig`'s module doc,
//! "Topology-change visibility") — `netsim.Protocol` has no hook that would
//! let it discover a fault as the engine applies it. `netsim.run` generates
//! its trace and replays it in one call with no seam in between; these
//! wrappers add exactly that seam (`Fabric.setSchedule`) and are otherwise
//! straight pass-throughs to `netsim.generateFaultTrace` / `netsim.replay`.
//! `shrink`'s ddmin loop is a small reimplementation of the same classic
//! (Zeller) complement-removal algorithm `netsim`'s own shrinker uses,
//! because its oracle also needs the schedule-sync seam on every trial
//! replay.

const std = @import("std");
const netsim = @import("netsim");
const Fabric = @import("fabric.zig").Fabric;
const Allocator = std.mem.Allocator;

/// Fuzz a fault schedule from `case.seed` (via netsim's own seeded fuzzer),
/// sync it into `f` (see the module doc), then replay. Mirrors
/// `netsim.run`'s signature and return shape exactly.
pub fn run(gpa: Allocator, f: *Fabric, case: netsim.Case, fault_cfg: netsim.FaultConfig) anyerror!netsim.GenResult {
    const topo = try netsim.snapshotTopo(gpa, case);
    defer gpa.free(topo.links);
    var trace = try netsim.generateFaultTrace(gpa, case.seed, .{ .node_count = topo.node_count, .links = topo.links }, fault_cfg);
    errdefer trace.deinit();
    f.setSchedule(trace.events);
    const result = try netsim.replay(gpa, case, trace.events, null);
    return .{ .result = result, .trace = trace };
}

/// A captured failing run — same shape as `netsim.shrink_mod.Failing`.
pub const Failing = struct {
    case: netsim.Case,
    trace: netsim.FaultTrace,
    err: anyerror,

    pub fn deinit(self: *Failing) void {
        self.trace.deinit();
        self.* = undefined;
    }
};

/// Sweep `[start, end]` inclusive via `run` above, returning the first seed
/// whose invariant check fails.
pub fn findFailing(
    gpa: Allocator,
    f: *Fabric,
    template: netsim.Case,
    fault_cfg: netsim.FaultConfig,
    start: u64,
    end: u64,
) anyerror!?Failing {
    var seed = start;
    while (true) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try run(gpa, f, case, fault_cfg);
        if (gr.result.outcome == .violated) {
            return Failing{ .case = case, .trace = gr.trace, .err = gr.result.violation.?.err };
        }
        gr.trace.deinit();
        if (seed == end) break;
    }
    return null;
}

pub const ShrinkResult = struct {
    trace: netsim.FaultTrace,
    before: usize,
    after: usize,

    pub fn deinit(self: *ShrinkResult) void {
        self.trace.deinit();
        self.* = undefined;
    }
};

const ShrinkCtx = struct {
    gpa: Allocator,
    f: *Fabric,
    case: netsim.Case,
    target: anyerror,
    events: []const netsim.FaultEvent,

    /// The ddmin oracle: does replaying just `subset` (indices into
    /// `events`), after syncing it into `f`, reproduce the exact target
    /// error?
    fn keeps(self: *ShrinkCtx, subset: []const usize) Allocator.Error!bool {
        const sub = try self.gpa.alloc(netsim.FaultEvent, subset.len);
        defer self.gpa.free(sub);
        for (subset, 0..) |idx, i| sub[i] = self.events[idx];
        self.f.setSchedule(sub);
        const r = netsim.replay(self.gpa, self.case, sub, null) catch return false;
        return r.outcome == .violated and r.violation.?.err == self.target;
    }
};

/// Classic Zeller ddmin (complement-removal) — same algorithm shape as
/// `netsim`'s own shrinker (see the module doc for why it's reimplemented
/// here rather than called directly).
fn ddmin(gpa: Allocator, n: usize, ctx: *ShrinkCtx) Allocator.Error![]usize {
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

/// Deep-copy the kept events (including any partition cut slices) into a
/// fresh, self-owned trace.
fn cloneSubset(gpa: Allocator, events: []const netsim.FaultEvent, kept: []const usize) Allocator.Error!netsim.FaultTrace {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const out = try a.alloc(netsim.FaultEvent, kept.len);
    for (kept, 0..) |idx, i| {
        var ev = events[idx];
        switch (ev.kind) {
            .partition => |p| ev.kind = .{ .partition = .{ .id = p.id, .cut = try a.dupe(netsim.NodeId, p.cut) } },
            else => {},
        }
        out[i] = ev;
    }
    return .{ .arena = arena, .events = out };
}

/// Delta-debug `failing` down to a minimal reproducer of the SAME error,
/// syncing `f`'s schedule to every trial subset along the way.
pub fn shrink(gpa: Allocator, f: *Fabric, failing: *const Failing) Allocator.Error!ShrinkResult {
    const events = failing.trace.events;
    const before = events.len;

    var ctx = ShrinkCtx{ .gpa = gpa, .f = f, .case = failing.case, .target = failing.err, .events = events };
    const kept = try ddmin(gpa, before, &ctx);
    defer gpa.free(kept);

    var out = try cloneSubset(gpa, events, kept);
    errdefer out.deinit();
    return .{ .trace = out, .before = before, .after = kept.len };
}
