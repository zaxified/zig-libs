// SPDX-License-Identifier: MIT

//! Fault search over whole simulations, netsim's method applied to real
//! `std.Io` code: a `Case` builds a world (hosts, links, tasks); `run` draws a
//! fault schedule for a seed with netsim's generator and runs the world under
//! it with an invariant checked after every step; `findFailing` sweeps seeds;
//! `shrink` delta-debugs the schedule (netsim's ddmin) down to the faults that
//! still reproduce the same error; `replay` re-runs a concrete schedule; and
//! `checkDeterminism` runs a seed twice and compares the schedule fingerprint,
//! the data fingerprint (every byte sent and written) and `Case.digest`.
//!
//! Schedule times are in ticks of `FaultConfig.tick_ns` (1 ms by default):
//! netsim's generator draws delay spikes and clock jumps in small tick counts,
//! which read as milliseconds here. A schedule is netsim's network and host
//! faults plus, when `FaultConfig.disk.max_events > 0`, disk faults (one-shot
//! I/O errors and bit rot) drawn from an independent stream of the same seed.

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
    /// Digest of the application's own state after a run (on the scheduler:
    /// read state, do not call `std.Io`), folded into `checkDeterminism`.
    /// Simio already compares every byte sent and written; this is for state
    /// that never leaves a host.
    digest: ?*const fn (sim: *Sim, ctx: ?*anyopaque) u64 = null,
};

pub const FaultConfig = struct {
    /// netsim's generator settings; `horizon` is in ticks.
    schedule: netsim.FaultConfig = .{ .horizon = 30_000 },
    tick_ns: u64 = std.time.ns_per_ms,
    /// Disk faults, drawn over the same horizon; off by default.
    disk: struct {
        max_events: usize = 0,
        io_errors: bool = true,
        bit_rot: bool = true,
    } = .{},
};

pub const DiskFault = union(enum) {
    /// The next read, write or sync on the host's disk fails.
    io_error: struct { host: u32, op: @FieldType(@FieldType(sched.Fault, "disk_error"), "op") },
    bit_rot: struct { host: u32 },
};

pub const TraceEvent = struct {
    /// In ticks of `FaultConfig.tick_ns`.
    time: u64,
    kind: union(enum) {
        net: netsim.FaultKind,
        disk: DiskFault,
    },
};

/// A concrete, replayable fault schedule. Owns its memory.
pub const Trace = struct {
    arena: std.heap.ArenaAllocator,
    events: []TraceEvent,

    pub fn deinit(t: *Trace) void {
        t.arena.deinit();
    }

    /// Deep copy of `events[kept]` (partition cuts included).
    pub fn subset(gpa: Allocator, events: []const TraceEvent, kept: []const usize) Allocator.Error!Trace {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const out = try a.alloc(TraceEvent, kept.len);
        for (kept, 0..) |idx, i| {
            out[i] = events[idx];
            switch (out[i].kind) {
                .net => |k| switch (k) {
                    .partition => |p| out[i].kind = .{ .net = .{ .partition = .{ .id = p.id, .cut = try a.dupe(netsim.NodeId, p.cut) } } },
                    else => {},
                },
                .disk => {},
            }
        }
        return .{ .arena = arena, .events = out };
    }
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
    /// `Sim.dataFingerprint` at the end of the run.
    data_fingerprint: u64,
    /// `Case.digest` at the end of the run, 0 without one.
    digest: u64 = 0,
    steps: u64,
    now_ns: u64,
};

pub const Generated = struct {
    result: CaseResult,
    trace: Trace,

    pub fn deinit(g: *Generated) void {
        g.trace.deinit();
    }
};

/// One run under a fault schedule drawn for `case.seed`.
pub fn run(gpa: Allocator, case: Case, cfg: FaultConfig) anyerror!Generated {
    var trace: ?Trace = null;
    errdefer if (trace) |*t| t.deinit();
    const result = try execute(gpa, case, .{ .generate = .{ .cfg = cfg, .out = &trace } });
    return .{ .result = result, .trace = trace.? };
}

/// Re-runs `case` under exactly `events` (from `run`, `findFailing` or
/// `shrink`). Deterministic: the same events give the same result.
pub fn replay(gpa: Allocator, case: Case, events: []const TraceEvent, tick_ns: u64) anyerror!CaseResult {
    return execute(gpa, case, .{ .given = .{ .events = events, .tick_ns = tick_ns } });
}

const Mode = union(enum) {
    generate: struct { cfg: FaultConfig, out: *?Trace },
    given: struct { events: []const TraceEvent, tick_ns: u64 },
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
            g.out.* = try generate(gpa, case.seed, &sim, g.cfg);
            try schedule(&sim, g.out.*.?.events, g.cfg.tick_ns);
        },
        .given => |g| try schedule(&sim, g.events, g.tick_ns),
    }

    if (case.invariant) |inv| sim.setInvariant(inv, case.ctx);
    const r = sim.runFor(case.duration_ns);
    var result: CaseResult = .{
        .outcome = r.outcome,
        .violation = null,
        .fingerprint = sim.fingerprint(),
        .data_fingerprint = sim.dataFingerprint(),
        .digest = if (case.digest) |d| d(&sim, case.ctx) else 0,
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

const disk_salt: u64 = 0xd15c_fa17_5eed_0001;

/// netsim's schedule over this world's topology, plus disk faults.
fn generate(gpa: Allocator, seed: u64, sim: *Sim, cfg: FaultConfig) anyerror!Trace {
    const links = try topology(gpa, sim);
    defer gpa.free(links);
    const hosts = sim.hosts.items.len;
    var net_trace = try netsim.generateFaultTrace(gpa, seed, .{ .node_count = hosts, .links = links }, cfg.schedule);
    defer net_trace.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var list: std.ArrayList(TraceEvent) = .empty;
    for (net_trace.events) |ev| {
        var kind = ev.kind;
        switch (kind) {
            .partition => |p| kind = .{ .partition = .{ .id = p.id, .cut = try a.dupe(netsim.NodeId, p.cut) } },
            else => {},
        }
        try list.append(a, .{ .time = ev.time, .kind = .{ .net = kind } });
    }
    const d = cfg.disk;
    if (d.max_events > 0 and hosts > 0 and (d.io_errors or d.bit_rot)) {
        var prng = netsim.Prng.init(seed ^ disk_salt);
        const n = prng.below(d.max_events + 1);
        for (0..n) |_| {
            const t = prng.belowWide(@max(cfg.schedule.horizon, 1));
            const host: u32 = @intCast(prng.below(hosts));
            const rot = if (d.io_errors and d.bit_rot) prng.chance(1, 4) else d.bit_rot;
            const fault: DiskFault = if (rot) .{ .bit_rot = .{ .host = host } } else .{ .io_error = .{
                .host = host,
                .op = switch (prng.below(3)) {
                    0 => .read,
                    1 => .write,
                    else => .sync,
                },
            } };
            try list.append(a, .{ .time = t, .kind = .{ .disk = fault } });
        }
        std.sort.insertion(TraceEvent, list.items, {}, struct {
            fn less(_: void, x: TraceEvent, y: TraceEvent) bool {
                return x.time < y.time;
            }
        }.less);
    }
    return .{ .arena = arena, .events = list.items };
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

fn schedule(sim: *Sim, events: []const TraceEvent, tick_ns: u64) Allocator.Error!void {
    for (events) |ev| {
        const at = ev.time *| tick_ns;
        const net_kind = switch (ev.kind) {
            .net => |k| k,
            .disk => |d| {
                try sim.scheduleFault(at, switch (d) {
                    .io_error => |e| .{ .disk_error = .{ .host = e.host, .op = e.op } },
                    .bit_rot => |r| .{ .bit_rot = r.host },
                });
                continue;
            },
        };
        const fault: sched.Fault = switch (net_kind) {
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
    trace: Trace,
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
    trace: Trace,
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
        .trace = try Trace.subset(gpa, events, kept),
        .before = events.len,
        .after = kept.len,
    };
}

const ShrinkCtx = struct {
    gpa: Allocator,
    failing: *const Failing,

    pub fn keeps(c: *ShrinkCtx, subset: []const usize) Allocator.Error!bool {
        const sub = try c.gpa.alloc(TraceEvent, subset.len);
        defer c.gpa.free(sub);
        for (subset, 0..) |idx, i| sub[i] = c.failing.trace.events[idx];
        const r = replay(c.gpa, c.failing.case, sub, c.failing.tick_ns) catch return false;
        const v = r.violation orelse return false;
        return v.err == c.failing.violation.err;
    }
};

pub const DeterminismError = error{
    /// The runs scheduled or timed differently.
    Nondeterministic,
    /// Same schedule and timing, different bytes sent or written.
    NondeterministicData,
    /// Same bytes, different `Case.digest`.
    NondeterministicState,
};

/// Runs `case` twice under the same drawn schedule and fails when the two
/// runs diverge — the code under test reads something simio does not
/// control (wall clock, threads, addresses, environment).
pub fn checkDeterminism(gpa: Allocator, case: Case, cfg: FaultConfig) anyerror!void {
    var first = try run(gpa, case, cfg);
    defer first.deinit();
    const second = try replay(gpa, case, first.trace.events, cfg.tick_ns);
    if (first.result.fingerprint != second.fingerprint or first.result.now_ns != second.now_ns or
        first.result.outcome != second.outcome) return error.Nondeterministic;
    if (first.result.data_fingerprint != second.data_fingerprint) return error.NondeterministicData;
    if (first.result.digest != second.digest) return error.NondeterministicState;
}
