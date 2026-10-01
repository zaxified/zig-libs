// SPDX-License-Identifier: MIT

//! Fault search over whole simulations, netsim's method applied to real
//! `std.Io` code: a `Case` builds a world (hosts, links, tasks); `run` draws a
//! fault schedule for a seed with netsim's generator and runs the world under
//! it with an invariant checked after every step; `findFailing` sweeps seeds;
//! `shrink` delta-debugs the schedule (netsim's ddmin) down to the faults that
//! still reproduce the same error; `replay` re-runs a concrete schedule; and
//! `checkDeterminism` runs a seed twice and compares the fingerprints.
//!
//! Schedule times are in ticks of `FaultConfig.tick_ns` (1 ms by default):
//! netsim's generator draws delay spikes and clock jumps in small tick counts,
//! which read as milliseconds here.

const std = @import("std");
const netsim = @import("netsim");
const sched = @import("sched.zig");

const Allocator = std.mem.Allocator;
const Sim = sched.Sim;
const Host = sched.Host;

pub const Case = struct {
    /// Seeds the simulation and the drawn fault schedule.
    seed: u64 = 0,
    /// Simulation options; `seed` inside is replaced by `Case.seed`.
    options: sched.Options = .{ .seed = 0 },
    /// Builds the world: hosts, links, tasks. Use `Host.spawnBoot` for tasks
    /// that must come back when a crashed host restarts.
    setup: *const fn (sim: *Sim, ctx: ?*anyopaque) anyerror!void,
    /// Safety invariant, checked after every task step and every batch of
    /// events (on the scheduler: read state, do not call `std.Io`).
    invariant: ?*const fn (sim: *Sim, ctx: ?*anyopaque) anyerror!void = null,
    /// Checked once after the run (liveness: "everything got through").
    final: ?*const fn (sim: *Sim, ctx: ?*anyopaque) anyerror!void = null,
    /// Resets the state behind `ctx` before every run — a case is run many
    /// times with the same `ctx`, and state left over from the last run
    /// would make the next one depend on it (netsim audit F3).
    reset: ?*const fn (ctx: ?*anyopaque) void = null,
    ctx: ?*anyopaque = null,
    /// Virtual time each run lasts.
    duration_ns: u64 = 60 * std.time.ns_per_s,
    /// A root task that returns an error is a violation.
    task_errors_fail: bool = true,
};

pub const FaultConfig = struct {
    /// netsim's generator settings; `horizon` is in ticks.
    schedule: netsim.FaultConfig = .{ .horizon = 30_000 },
    tick_ns: u64 = std.time.ns_per_ms,
};

pub const Violation = struct {
    err: anyerror,
    at_ns: u64,
    /// Host index whose root task failed, when that is the violation.
    host: ?u32 = null,
};

pub const CaseResult = struct {
    outcome: sched.Outcome,
    violation: ?Violation,
    fingerprint: u64,
    steps: u64,
    now_ns: u64,
};

pub const Generated = struct {
    result: CaseResult,
    trace: netsim.FaultTrace,

    pub fn deinit(g: *Generated) void {
        g.trace.deinit();
    }
};

/// One run under a fault schedule drawn for `case.seed`.
pub fn run(gpa: Allocator, case: Case, cfg: FaultConfig) anyerror!Generated {
    var trace: ?netsim.FaultTrace = null;
    errdefer if (trace) |*t| t.deinit();
    const result = try execute(gpa, case, .{ .generate = .{ .cfg = cfg, .out = &trace } });
    return .{ .result = result, .trace = trace.? };
}

/// Re-runs `case` under exactly `events` (from `run`, `findFailing` or
/// `shrink`). Deterministic: the same events give the same result.
pub fn replay(gpa: Allocator, case: Case, events: []const netsim.FaultEvent, tick_ns: u64) anyerror!CaseResult {
    return execute(gpa, case, .{ .given = .{ .events = events, .tick_ns = tick_ns } });
}

const Mode = union(enum) {
    generate: struct { cfg: FaultConfig, out: *?netsim.FaultTrace },
    given: struct { events: []const netsim.FaultEvent, tick_ns: u64 },
};

fn execute(gpa: Allocator, case: Case, mode: Mode) anyerror!CaseResult {
    if (case.reset) |r| r(case.ctx);
    var opts = case.options;
    opts.seed = case.seed;
    var sim: Sim = undefined;
    sim.init(gpa, opts);
    defer sim.deinit();
    try case.setup(&sim, case.ctx);

    switch (mode) {
        .generate => |g| {
            const links = try topology(gpa, &sim);
            defer gpa.free(links);
            const trace = try netsim.generateFaultTrace(gpa, case.seed, .{
                .node_count = sim.hosts.items.len,
                .links = links,
            }, g.cfg.schedule);
            g.out.* = trace;
            try schedule(&sim, trace.events, g.cfg.tick_ns);
        },
        .given => |g| try schedule(&sim, g.events, g.tick_ns),
    }

    if (case.invariant) |inv| sim.setInvariant(inv, case.ctx);
    const r = sim.runFor(case.duration_ns);
    var result: CaseResult = .{
        .outcome = r.outcome,
        .violation = null,
        .fingerprint = sim.fingerprint(),
        .steps = r.steps,
        .now_ns = r.now_ns,
    };
    if (r.violation) |err| {
        result.violation = .{ .err = err, .at_ns = r.now_ns };
        return result;
    }
    if (case.task_errors_fail) for (sim.hosts.items) |h| if (h.failure) |err| {
        result.violation = .{ .err = err, .at_ns = r.now_ns, .host = h.id };
        return result;
    };
    if (case.final) |final| final(&sim, case.ctx) catch |err| {
        result.violation = .{ .err = err, .at_ns = r.now_ns };
    };
    return result;
}

/// Every link, both directions, for the schedule generator.
fn topology(gpa: Allocator, sim: *Sim) Allocator.Error![]netsim.Link {
    const edges = sim.net.edges.items;
    const links = try gpa.alloc(netsim.Link, edges.len * 2);
    for (edges, 0..) |e, i| {
        links[2 * i] = .{ .a = e.a, .b = e.b };
        links[2 * i + 1] = .{ .a = e.b, .b = e.a };
    }
    return links;
}

fn schedule(sim: *Sim, events: []const netsim.FaultEvent, tick_ns: u64) Allocator.Error!void {
    for (events) |ev| {
        const at = ev.time *| tick_ns;
        const fault: sched.Fault = switch (ev.kind) {
            .link_down => |l| .{ .link_down = .{ .from = l.a, .to = l.b } },
            .link_up => |l| .{ .link_up = .{ .from = l.a, .to = l.b } },
            .partition => |p| .{ .partition = .{ .id = p.id, .cut = p.cut } },
            .heal => |h| .{ .heal = h.id },
            .crash_node => |c| .{ .crash = c.node },
            .restart_node => |c| .{ .restart = c.node },
            .clock_jump => |j| .{ .clock_jump = .{ .host = j.node, .delta_ns = j.delta *| @as(i64, @intCast(@min(tick_ns, std.math.maxInt(i64)))) } },
            .drop_once => |l| .{ .drop_once = .{ .from = l.a, .to = l.b } },
            .dup_once => |l| .{ .dup_once = .{ .from = l.a, .to = l.b } },
            .delay_once => |d| .{ .delay_once = .{ .from = d.a, .to = d.b, .extra_ns = d.extra *| tick_ns } },
        };
        try sim.scheduleFault(at, fault);
    }
}

pub const Failing = struct {
    /// The case with the failing seed filled in.
    case: Case,
    trace: netsim.FaultTrace,
    violation: Violation,
    tick_ns: u64,

    pub fn deinit(f: *Failing) void {
        f.trace.deinit();
    }
};

/// Sweeps seeds `[start, end]` and returns the first run that violates the
/// case (null when every seed holds).
pub fn findFailing(gpa: Allocator, template: Case, cfg: FaultConfig, start: u64, end: u64) anyerror!?Failing {
    if (start > end) return null;
    var seed = start;
    while (true) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var g = try run(gpa, case, cfg);
        if (g.result.violation) |v| return .{ .case = case, .trace = g.trace, .violation = v, .tick_ns = cfg.tick_ns };
        g.deinit();
        if (seed == end) return null;
    }
}

pub const ShrinkResult = struct {
    trace: netsim.FaultTrace,
    before: usize,
    after: usize,

    pub fn deinit(s: *ShrinkResult) void {
        s.trace.deinit();
    }
};

/// Delta-debugs the failing schedule to the fewest faults that still give
/// the same error.
pub fn shrink(gpa: Allocator, failing: *const Failing) Allocator.Error!ShrinkResult {
    const events = failing.trace.events;
    var ctx: ShrinkCtx = .{ .gpa = gpa, .failing = failing };
    const kept = try netsim.ddmin(gpa, events.len, &ctx);
    defer gpa.free(kept);
    return .{
        .trace = try netsim.cloneTraceSubset(gpa, events, kept),
        .before = events.len,
        .after = kept.len,
    };
}

const ShrinkCtx = struct {
    gpa: Allocator,
    failing: *const Failing,

    pub fn keeps(c: *ShrinkCtx, subset: []const usize) Allocator.Error!bool {
        const sub = try c.gpa.alloc(netsim.FaultEvent, subset.len);
        defer c.gpa.free(sub);
        for (subset, 0..) |idx, i| sub[i] = c.failing.trace.events[idx];
        const r = replay(c.gpa, c.failing.case, sub, c.failing.tick_ns) catch return false;
        const v = r.violation orelse return false;
        return v.err == c.failing.violation.err;
    }
};

pub const DeterminismError = error{Nondeterministic};

/// Runs `case` twice under the same drawn schedule and fails when the two
/// runs diverge — the code under test reads something simio does not
/// control (wall clock, threads, addresses, environment).
pub fn checkDeterminism(gpa: Allocator, case: Case, cfg: FaultConfig) anyerror!void {
    var first = try run(gpa, case, cfg);
    defer first.deinit();
    const second = try replay(gpa, case, first.trace.events, cfg.tick_ns);
    if (first.result.fingerprint != second.fingerprint or first.result.now_ns != second.now_ns or
        first.result.outcome != second.outcome) return error.Nondeterministic;
}
