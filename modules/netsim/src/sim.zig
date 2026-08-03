// SPDX-License-Identifier: MIT

//! The deterministic discrete-event network engine.
//!
//! A `Sim` holds a topology (nodes + directed links with per-link latency /
//! jitter / loss / dup / reorder / bandwidth), a seeded message-mechanics PRNG,
//! and a single event queue ordered by (simulated time, insertion sequence) —
//! so same-time events break ties FIFO and a run replays byte-for-byte. The
//! algorithm under test is a caller-supplied `Protocol` (a small vtable of
//! start / message / timer hooks plus an invariant `check`); the engine never
//! bakes in any fabric specifics. Faults from a `fault.FaultTrace` are injected
//! as ordinary timed events, so connectivity/crash/partition changes interleave
//! with message delivery on the same clock.
//!
//! After EVERY event the engine runs the protocol's invariant `check`; the first
//! violation is captured (error + time) and the run stops with `.violated`,
//! returning the exact fault trace + event log as a reproducer. `replay` re-runs
//! a concrete trace (the deterministic oracle the shrinker calls in a tight
//! loop); `run` fuzzes a trace from the seed first, then replays it.
//!
//! Provenance: the VOPR approach — deterministic simulation, seeded fault
//! injection, invariant model-checking, reproduce-from-seed + delta-debug shrink
//! — is modeled after TigerBeetle's VOPR (design reference only; no code
//! consulted or copied) and generalized here from kv's single-store harness to a
//! message-passing network.

const std = @import("std");
const types = @import("types.zig");
const fault = @import("fault.zig");
const Prng = @import("prng.zig").Prng;
const Allocator = std.mem.Allocator;

pub const NodeId = types.NodeId;
pub const Time = types.Time;

// ── topology configuration ───────────────────────────────────────────────────

pub const LinkConfig = struct {
    /// Base one-way latency in ticks.
    latency: Time = 1,
    /// Uniform extra delay drawn in [0, jitter].
    jitter: Time = 0,
    /// Per-message drop probability, parts per mille.
    loss_permille: u16 = 0,
    /// Per-message duplicate probability, parts per mille.
    dup_permille: u16 = 0,
    /// Probability (parts per mille) a message gets `reorder_extra` extra delay.
    reorder_permille: u16 = 0,
    reorder_extra: Time = 0,
    /// Optional serialization delay: +`payload.len / bandwidth` ticks. null = infinite.
    bandwidth: ?u64 = null,
};

pub const NodeConfig = struct {
    /// Constant offset added to the node's observed clock (see `Sim.clock`).
    clock_skew: i64 = 0,
};

// ── event log (human-readable trace + determinism fingerprint) ───────────────

pub const LogEntry = struct {
    time: Time = 0,
    seq: u64 = 0,
    tag: Tag,
    a: i64 = 0,
    b: i64 = 0,
    c: i64 = 0,

    pub const Tag = enum {
        start,
        deliver,
        drop,
        dup,
        timer,
        fault,
        crash,
        restart,
        violation,
    };
};

/// Ordered record of everything the engine did, plus a rolling fingerprint of
/// it (the determinism witness: identical runs ⇒ identical fingerprint & log).
pub const Log = struct {
    entries: std.ArrayList(LogEntry) = .empty,

    pub fn deinit(self: *Log, gpa: Allocator) void {
        self.entries.deinit(gpa);
        self.* = undefined;
    }

    pub fn copyFrom(self: *Log, gpa: Allocator, other: *const Log) Allocator.Error!void {
        self.entries.clearRetainingCapacity();
        try self.entries.appendSlice(gpa, other.entries.items);
    }

    /// Structural equality — used by determinism tests.
    pub fn eql(x: *const Log, y: *const Log) bool {
        if (x.entries.items.len != y.entries.items.len) return false;
        for (x.entries.items, y.entries.items) |ex, ey| {
            if (!std.meta.eql(ex, ey)) return false;
        }
        return true;
    }
};

const fp_prime: u64 = 0x100000001b3; // FNV-ish odd multiplier

fn foldFingerprint(fp: u64, e: LogEntry) u64 {
    var h = fp;
    h = h *% fp_prime +% @intFromEnum(e.tag);
    h = h *% fp_prime +% e.time;
    h = h *% fp_prime +% e.seq;
    h = h *% fp_prime +% @as(u64, @bitCast(e.a));
    h = h *% fp_prime +% @as(u64, @bitCast(e.b));
    h = h *% fp_prime +% @as(u64, @bitCast(e.c));
    return h;
}

// ── the protocol seam (the algorithm under test) ─────────────────────────────

/// The caller's algorithm, as a small vtable over an opaque context. Every hook
/// receives the live `*Sim` so it can `send`, `setTimer`, and read the topology
/// and clocks. The engine owns topology + scheduling; the protocol owns all of
/// its own per-node state (in `ctx`).
pub const Protocol = struct {
    ctx: *anyopaque,
    /// Called for every non-crashed node at t=0, and again for a node when it
    /// restarts. Optional (a protocol may bootstrap purely reactively).
    onStartFn: ?*const fn (ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void = null,
    /// Called when a message is delivered to `node` from `from`.
    onMessageFn: *const fn (ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void,
    /// Called when a timer fires on a non-crashed node.
    onTimerFn: ?*const fn (ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void = null,
    /// The invariant predicate, checked after EVERY event. Returning an error is
    /// an invariant violation: the engine captures it and stops the run.
    checkFn: ?*const fn (ctx: *anyopaque, sim: *const Sim) anyerror!void = null,
    /// Clear all per-node state to its t=0 baseline. Called at the start of
    /// every drive so a ctx can be reused across many replays (the shrinker
    /// re-runs the same ctx thousands of times). Optional but recommended.
    resetFn: ?*const fn (ctx: *anyopaque) void = null,
};

/// Build a fresh topology and (optionally) any initial state. Called with an
/// empty `*Sim`; must add nodes/links deterministically (no unseeded randomness).
pub const Scenario = *const fn (sim: *Sim) anyerror!void;

/// The invariant-independent inputs of a run: what to build, which algorithm,
/// how long to run. Copyable — the shrinker clones it with a different seed.
pub const Case = struct {
    seed: u64,
    scenario: Scenario,
    protocol: Protocol,
    /// Stop once the earliest queued event is past this time.
    until: Time,
    /// Hard backstop on processed events (guards a mis-specified invariant from
    /// spinning forever on a live-locked protocol).
    max_events_cap: u64 = 5_000_000,
};

pub const RunOutcome = enum { ok, violated };

pub const Violation = struct {
    err: anyerror,
    time: Time,
    events_processed: u64,
};

pub const RunResult = struct {
    outcome: RunOutcome,
    events_processed: u64,
    fingerprint: u64,
    violation: ?Violation = null,
};

pub const TopoOwned = struct {
    node_count: usize,
    /// gpa-owned — free with `gpa.free(links)`.
    links: []fault.Link,
};

pub const GenResult = struct {
    result: RunResult,
    /// The fuzzed schedule the run used — the reproducer. Owned; call `deinit`.
    trace: fault.FaultTrace,
};

// ── internal records ─────────────────────────────────────────────────────────

const NodeRec = struct {
    clock_offset: i64,
    crashed: bool = false,
};

const LinkRec = struct {
    a: NodeId,
    b: NodeId,
    cfg: LinkConfig,
    up: bool = true,
    drop_pending: u32 = 0,
    dup_pending: u32 = 0,
    delay_pending: Time = 0,
};

const ActivePartition = struct {
    id: u32,
    cut: []NodeId, // owned by sim.arena
};

const EKind = union(enum) {
    deliver: struct { from: NodeId, to: NodeId, payload: []const u8 },
    timer: struct { node: NodeId, timer_id: u64 },
    fault: fault.FaultKind,
};

const Event = struct {
    time: Time,
    seq: u64,
    kind: EKind,
};

fn eventLess(x: Event, y: Event) bool {
    if (x.time != y.time) return x.time < y.time;
    return x.seq < y.seq;
}

/// Binary min-heap over (time, seq). Hand-rolled so ordering is fully explicit
/// and deterministic.
const EventHeap = struct {
    items: std.ArrayList(Event) = .empty,

    fn deinit(self: *EventHeap, gpa: Allocator) void {
        self.items.deinit(gpa);
    }

    fn push(self: *EventHeap, gpa: Allocator, ev: Event) Allocator.Error!void {
        try self.items.append(gpa, ev);
        var i = self.items.items.len - 1;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (eventLess(self.items.items[i], self.items.items[parent])) {
                std.mem.swap(Event, &self.items.items[i], &self.items.items[parent]);
                i = parent;
            } else break;
        }
    }

    fn peekTime(self: *const EventHeap) ?Time {
        if (self.items.items.len == 0) return null;
        return self.items.items[0].time;
    }

    fn pop(self: *EventHeap) Event {
        const s = &self.items;
        const root = s.items[0];
        const last = s.items[s.items.len - 1];
        s.items.len -= 1;
        if (s.items.len > 0) {
            s.items[0] = last;
            var i: usize = 0;
            const n = s.items.len;
            while (true) {
                const l = 2 * i + 1;
                const r = 2 * i + 2;
                var smallest = i;
                if (l < n and eventLess(s.items[l], s.items[smallest])) smallest = l;
                if (r < n and eventLess(s.items[r], s.items[smallest])) smallest = r;
                if (smallest == i) break;
                std.mem.swap(Event, &s.items[i], &s.items[smallest]);
                i = smallest;
            }
        }
        return root;
    }
};

// ── the engine ───────────────────────────────────────────────────────────────

pub const Sim = struct {
    gpa: Allocator,
    /// Owns message payloads + partition cuts for the duration of a run.
    arena: std.heap.ArenaAllocator,
    prng: Prng,
    protocol: Protocol,
    nodes: std.ArrayList(NodeRec) = .empty,
    links: std.ArrayList(LinkRec) = .empty,
    /// Per-node out-adjacency: `out_adj.items[a]` holds the indices into
    /// `links` of every link whose `a` is that node.
    ///
    /// Without it both `findLink` and `neighbors` scan EVERY link. `findLink`
    /// runs on every `send`, and consumers call `neighbors` per received
    /// message (`df-elect` does), so a run cost O(messages x links) — the
    /// reason a 1000-node fleet sim was out of reach. Links are append-only,
    /// so keeping this current is one append per `addLink`.
    out_adj: std.ArrayList(std.ArrayList(u32)) = .empty,
    partitions: std.ArrayList(ActivePartition) = .empty,
    queue: EventHeap = .{},
    now: Time = 0,
    seq: u64 = 0,
    events_processed: u64 = 0,
    fingerprint: u64 = 0,
    until: Time,
    max_events_cap: u64,
    log: *Log,
    violation: ?Violation = null,

    pub fn init(gpa: Allocator, seed: u64, protocol: Protocol, log: *Log, until: Time, cap: u64) Sim {
        return .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .prng = Prng.init(seed),
            .protocol = protocol,
            .until = until,
            .max_events_cap = cap,
            .log = log,
        };
    }

    pub fn deinit(self: *Sim) void {
        self.nodes.deinit(self.gpa);
        self.links.deinit(self.gpa);
        for (self.out_adj.items) |*a| a.deinit(self.gpa);
        self.out_adj.deinit(self.gpa);
        self.partitions.deinit(self.gpa);
        self.queue.deinit(self.gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    // ── topology building (called from a Scenario) ───────────────────────────

    pub fn addNode(self: *Sim, cfg: NodeConfig) Allocator.Error!NodeId {
        const id: NodeId = @intCast(self.nodes.items.len);
        try self.nodes.append(self.gpa, .{ .clock_offset = cfg.clock_skew });
        errdefer _ = self.nodes.pop();
        try self.out_adj.append(self.gpa, .empty);
        return id;
    }

    pub fn addLink(self: *Sim, a: NodeId, b: NodeId, cfg: LinkConfig) Allocator.Error!void {
        const idx: u32 = @intCast(self.links.items.len);
        try self.links.append(self.gpa, .{ .a = a, .b = b, .cfg = cfg });
        errdefer _ = self.links.pop();
        try self.out_adj.items[a].append(self.gpa, idx);
    }

    /// Add both directions with the same config.
    pub fn addBiLink(self: *Sim, a: NodeId, b: NodeId, cfg: LinkConfig) Allocator.Error!void {
        try self.addLink(a, b, cfg);
        try self.addLink(b, a, cfg);
    }

    // ── protocol-facing API (used inside hooks) ──────────────────────────────

    pub fn timeNow(self: *const Sim) Time {
        return self.now;
    }

    pub fn nodeCount(self: *const Sim) usize {
        return self.nodes.items.len;
    }

    /// The node's OWN observed clock (global time + its skew/jump offset).
    pub fn clock(self: *const Sim, node: NodeId) i64 {
        return @as(i64, @intCast(self.now)) + self.nodes.items[node].clock_offset;
    }

    /// Fill `out` with `node`'s out-neighbors; returns how many were written.
    pub fn neighbors(self: *const Sim, node: NodeId, out: []NodeId) usize {
        var n: usize = 0;
        for (self.out_adj.items[node].items) |idx| {
            if (n >= out.len) break;
            out[n] = self.links.items[idx].b;
            n += 1;
        }
        return n;
    }

    /// Schedule delivery of `payload` (copied) from `from` to `to`, subject to
    /// the link's latency/jitter/loss/dup/reorder and any one-shot fault armed
    /// on it. Connectivity (link-down / partition / crashed receiver) is checked
    /// at DELIVERY time, so a link that fails after send drops the in-flight message.
    pub fn send(self: *Sim, from: NodeId, to: NodeId, payload: []const u8) Allocator.Error!void {
        const link = self.findLink(from, to) orelse {
            self.append(.{ .tag = .drop, .a = from, .b = to });
            return;
        };
        if (link.drop_pending > 0) {
            link.drop_pending -= 1;
            self.append(.{ .tag = .drop, .a = from, .b = to });
            return;
        }
        if (self.prng.permille(link.cfg.loss_permille)) {
            self.append(.{ .tag = .drop, .a = from, .b = to });
            return;
        }

        var delay: Time = link.cfg.latency;
        if (link.cfg.jitter > 0) delay += self.prng.below(link.cfg.jitter + 1);
        if (link.cfg.bandwidth) |bw| {
            if (bw > 0) delay += payload.len / bw;
        }
        if (link.cfg.reorder_extra > 0 and self.prng.permille(link.cfg.reorder_permille))
            delay += self.prng.below(link.cfg.reorder_extra + 1);
        if (link.delay_pending > 0) {
            delay += link.delay_pending;
            link.delay_pending = 0;
        }

        const buf = try self.arena.allocator().dupe(u8, payload);
        try self.pushDeliver(from, to, buf, self.now + delay);

        const dup_cfg = self.prng.permille(link.cfg.dup_permille);
        if (link.dup_pending > 0 or dup_cfg) {
            if (link.dup_pending > 0) link.dup_pending -= 1;
            const buf2 = try self.arena.allocator().dupe(u8, payload);
            // +1 tick so the copy is distinguishable and ordering stays total.
            try self.pushDeliver(from, to, buf2, self.now + delay + 1);
            self.append(.{ .tag = .dup, .a = from, .b = to });
        }
    }

    pub fn setTimer(self: *Sim, node: NodeId, delay: Time, timer_id: u64) Allocator.Error!void {
        try self.queue.push(self.gpa, .{
            .time = self.now + delay,
            .seq = self.nextSeq(),
            .kind = .{ .timer = .{ .node = node, .timer_id = timer_id } },
        });
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn nextSeq(self: *Sim) u64 {
        const s = self.seq;
        self.seq += 1;
        return s;
    }

    fn findLink(self: *Sim, a: NodeId, b: NodeId) ?*LinkRec {
        if (a >= self.out_adj.items.len) return null;
        for (self.out_adj.items[a].items) |idx| {
            const l = &self.links.items[idx];
            if (l.b == b) return l;
        }
        return null;
    }

    fn pushDeliver(self: *Sim, from: NodeId, to: NodeId, payload: []const u8, at: Time) Allocator.Error!void {
        try self.queue.push(self.gpa, .{
            .time = at,
            .seq = self.nextSeq(),
            .kind = .{ .deliver = .{ .from = from, .to = to, .payload = payload } },
        });
    }

    fn append(self: *Sim, partial: LogEntry) void {
        var e = partial;
        e.time = self.now;
        e.seq = self.nextSeq();
        self.fingerprint = foldFingerprint(self.fingerprint, e);
        // Best-effort: a log OOM must not corrupt the deterministic fingerprint,
        // which is already folded above.
        self.log.entries.append(self.gpa, e) catch {};
    }

    /// Is a → b currently severed (no link, link down, or a partition cuts it)?
    fn severed(self: *Sim, a: NodeId, b: NodeId) bool {
        const link = self.findLink(a, b) orelse return true;
        if (!link.up) return true;
        for (self.partitions.items) |p| {
            const in_a = std.mem.indexOfScalar(NodeId, p.cut, a) != null;
            const in_b = std.mem.indexOfScalar(NodeId, p.cut, b) != null;
            if (in_a != in_b) return true;
        }
        return false;
    }

    fn apply(self: *Sim, ev: Event) anyerror!void {
        switch (ev.kind) {
            .deliver => |d| {
                if (self.nodes.items[d.to].crashed or self.severed(d.from, d.to)) {
                    self.append(.{ .tag = .drop, .a = d.from, .b = d.to });
                    return;
                }
                self.append(.{ .tag = .deliver, .a = d.from, .b = d.to, .c = @intCast(d.payload.len) });
                try self.protocol.onMessageFn(self.protocol.ctx, self, d.to, d.from, d.payload);
            },
            .timer => |t| {
                if (self.nodes.items[t.node].crashed) return;
                // @bitCast, not @intCast: timer ids are arbitrary u64s (the API
                // contract of `setTimer`), including sentinels near maxInt(u64),
                // and the log field only needs a lossless, deterministic image.
                self.append(.{ .tag = .timer, .a = t.node, .b = @bitCast(t.timer_id) });
                if (self.protocol.onTimerFn) |f| try f(self.protocol.ctx, self, t.node, t.timer_id);
            },
            .fault => |fk| try self.applyFault(fk),
        }
    }

    fn applyFault(self: *Sim, fk: fault.FaultKind) anyerror!void {
        switch (fk) {
            .link_down => |l| {
                if (self.findLink(l.a, l.b)) |link| link.up = false;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = l.a, .c = l.b });
            },
            .link_up => |l| {
                if (self.findLink(l.a, l.b)) |link| link.up = true;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = l.a, .c = l.b });
            },
            .partition => |p| {
                const cut = try self.arena.allocator().dupe(NodeId, p.cut);
                try self.partitions.append(self.gpa, .{ .id = p.id, .cut = cut });
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = p.id, .c = @intCast(p.cut.len) });
            },
            .heal => |h| {
                var i: usize = 0;
                while (i < self.partitions.items.len) {
                    if (self.partitions.items[i].id == h.id) {
                        _ = self.partitions.orderedRemove(i);
                    } else i += 1;
                }
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = h.id });
            },
            .crash_node => |c| {
                self.nodes.items[c.node].crashed = true;
                self.append(.{ .tag = .crash, .a = c.node });
            },
            .restart_node => |r| {
                self.nodes.items[r.node].crashed = false;
                self.append(.{ .tag = .restart, .a = r.node });
                if (self.protocol.onStartFn) |f| try f(self.protocol.ctx, self, r.node);
            },
            .clock_jump => |j| {
                self.nodes.items[j.node].clock_offset += j.delta;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = j.node, .c = j.delta });
            },
            .drop_once => |l| {
                if (self.findLink(l.a, l.b)) |link| link.drop_pending += 1;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = l.a, .c = l.b });
            },
            .dup_once => |l| {
                if (self.findLink(l.a, l.b)) |link| link.dup_pending += 1;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = l.a, .c = l.b });
            },
            .delay_once => |d| {
                if (self.findLink(d.a, d.b)) |link| link.delay_pending += d.extra;
                self.append(.{ .tag = .fault, .a = @intFromEnum(std.meta.activeTag(fk)), .b = d.a, .c = d.b });
            },
        }
    }

    fn checkInvariant(self: *Sim) void {
        if (self.violation != null) return;
        const f = self.protocol.checkFn orelse return;
        f(self.protocol.ctx, self) catch |e| {
            self.violation = .{ .err = e, .time = self.now, .events_processed = self.events_processed };
            self.append(.{ .tag = .violation, .a = self.now_as_i64() });
        };
    }

    fn now_as_i64(self: *const Sim) i64 {
        return @intCast(self.now);
    }

    fn injectFaults(self: *Sim, trace: []const fault.FaultEvent) Allocator.Error!void {
        for (trace) |fe| {
            try self.queue.push(self.gpa, .{
                .time = fe.time,
                .seq = self.nextSeq(),
                .kind = .{ .fault = fe.kind },
            });
        }
    }

    fn drive(self: *Sim) anyerror!RunOutcome {
        if (self.protocol.resetFn) |reset| reset(self.protocol.ctx);

        // Bootstrap: start every non-crashed node at t=0.
        if (self.protocol.onStartFn) |f| {
            var i: NodeId = 0;
            while (i < self.nodes.items.len) : (i += 1) {
                if (!self.nodes.items[i].crashed) try f(self.protocol.ctx, self, i);
            }
        }
        self.append(.{ .tag = .start, .a = @intCast(self.nodes.items.len) });
        self.checkInvariant();
        if (self.violation != null) return .violated;

        while (self.queue.peekTime()) |t| {
            if (t > self.until) break;
            if (self.events_processed >= self.max_events_cap) break;
            const ev = self.queue.pop();
            self.now = ev.time;
            try self.apply(ev);
            self.events_processed += 1;
            self.checkInvariant();
            if (self.violation != null) return .violated;
        }
        return .ok;
    }
};

// ── top-level drivers ────────────────────────────────────────────────────────

fn build(gpa: Allocator, case: Case, log: *Log) anyerror!Sim {
    var sim = Sim.init(gpa, case.seed, case.protocol, log, case.until, case.max_events_cap);
    errdefer sim.deinit();
    try case.scenario(&sim);
    return sim;
}

/// Snapshot the topology a `Case` builds (node count + directed links), so the
/// fault fuzzer has valid targets. Caller frees `.links`.
pub fn snapshotTopo(gpa: Allocator, case: Case) anyerror!TopoOwned {
    var log = Log{};
    defer log.deinit(gpa);
    var sim = try build(gpa, case, &log);
    defer sim.deinit();
    const links = try gpa.alloc(fault.Link, sim.links.items.len);
    for (sim.links.items, links) |lr, *l| l.* = .{ .a = lr.a, .b = lr.b };
    return .{ .node_count = sim.nodes.items.len, .links = links };
}

/// Run `case` against a CONCRETE fault trace — the deterministic oracle. If
/// `log_out` is non-null, the full event log is copied into it before teardown.
pub fn replay(gpa: Allocator, case: Case, trace: []const fault.FaultEvent, log_out: ?*Log) anyerror!RunResult {
    var log = Log{};
    defer log.deinit(gpa);
    var sim = try build(gpa, case, &log);
    defer sim.deinit();
    try sim.injectFaults(trace);
    const outcome = try sim.drive();
    if (log_out) |lo| try lo.copyFrom(gpa, &log);
    return .{
        .outcome = outcome,
        .events_processed = sim.events_processed,
        .fingerprint = sim.fingerprint,
        .violation = sim.violation,
    };
}

/// Fuzz a fault schedule from `case.seed`, then replay it. Returns the result
/// AND the schedule it used (the reproducer) — call `.trace.deinit()`.
pub fn run(gpa: Allocator, case: Case, fault_cfg: fault.Config) anyerror!GenResult {
    const topo = try snapshotTopo(gpa, case);
    defer gpa.free(topo.links);
    var trace = try fault.generate(gpa, case.seed, .{ .node_count = topo.node_count, .links = topo.links }, fault_cfg);
    errdefer trace.deinit();
    const result = try replay(gpa, case, trace.events, null);
    return .{ .result = result, .trace = trace };
}

// ── engine smoke tests (protocol-level tests live in root.zig) ───────────────

const testing = std.testing;

test "drive: an event scheduled exactly at `until` is still processed (inclusive boundary)" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var fired: usize = 0;

    const Hooks = struct {
        fn onMessage(ctx: *anyopaque, s: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
            _ = ctx;
            _ = s;
            _ = node;
            _ = from;
            _ = payload;
        }
        fn onTimer(ctx: *anyopaque, s: *Sim, node: NodeId, timer_id: u64) anyerror!void {
            _ = s;
            _ = node;
            _ = timer_id;
            const count: *usize = @ptrCast(@alignCast(ctx));
            count.* += 1;
        }
    };
    const protocol = Protocol{
        .ctx = &fired,
        .onMessageFn = Hooks.onMessage,
        .onTimerFn = Hooks.onTimer,
    };

    var sim = Sim.init(gpa, 1, protocol, &log, 100, 1000);
    defer sim.deinit();
    _ = try sim.addNode(.{});
    try sim.setTimer(0, 100, 0); // fires at exactly `until` == 100
    _ = try sim.drive();

    try testing.expectEqual(@as(usize, 1), fired);
}

test "event heap: pops in (time, seq) order" {
    var h = EventHeap{};
    defer h.deinit(testing.allocator);
    const times = [_]Time{ 5, 1, 3, 1, 4, 1 };
    var seq: u64 = 0;
    for (times) |t| {
        try h.push(testing.allocator, .{ .time = t, .seq = seq, .kind = .{ .timer = .{ .node = 0, .timer_id = 0 } } });
        seq += 1;
    }
    // Expect ascending time, FIFO within equal time (the three t=1 in insert order).
    var prev_time: Time = 0;
    var prev_seq: u64 = 0;
    var first = true;
    while (h.peekTime() != null) {
        const ev = h.pop();
        if (!first) {
            try testing.expect(ev.time > prev_time or (ev.time == prev_time and ev.seq > prev_seq));
        }
        prev_time = ev.time;
        prev_seq = ev.seq;
        first = false;
    }
}

test "adjacency index stays in agreement with the link list" {
    // The index is a second representation of `links`, so the failure mode is
    // that they drift: a link present in one and missing from the other makes
    // `send` silently drop or `neighbors` under-report, and the simulation
    // still "runs". This checks them against each other by brute force —
    // exactly the linear scan the index replaced.
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    const Noop = struct {
        fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
        fn onTimer(_: *anyopaque, _: *Sim, _: NodeId, _: u64) anyerror!void {}
    };
    var unused: usize = 0;
    var sim = Sim.init(gpa, 1, .{
        .ctx = &unused,
        .onMessageFn = Noop.onMessage,
        .onTimerFn = Noop.onTimer,
    }, &log, 100, 1000);
    defer sim.deinit();

    var ids: [6]NodeId = undefined;
    for (&ids) |*id| id.* = try sim.addNode(.{});

    // A deliberately uneven shape: one hub, one isolated node, one self-loop.
    try sim.addBiLink(ids[0], ids[1], .{});
    try sim.addBiLink(ids[0], ids[2], .{});
    try sim.addBiLink(ids[0], ids[3], .{});
    try sim.addLink(ids[4], ids[0], .{}); // one-way
    try sim.addLink(ids[0], ids[0], .{}); // self-loop
    // ids[5] stays isolated.

    for (0..sim.nodes.items.len) |a| {
        // Every link with this source must be in the node's adjacency list.
        var expected: usize = 0;
        for (sim.links.items) |l| {
            if (l.a == a) expected += 1;
        }
        try testing.expectEqual(expected, sim.out_adj.items[a].items.len);

        // And findLink must agree with a brute-force scan for every target.
        for (0..sim.nodes.items.len) |b| {
            var brute: ?*LinkRec = null;
            for (sim.links.items) |*l| {
                if (l.a == a and l.b == b) {
                    brute = l;
                    break;
                }
            }
            const via_index = sim.findLink(@intCast(a), @intCast(b));
            try testing.expectEqual(brute, via_index);
        }

        var out: [8]NodeId = undefined;
        try testing.expectEqual(expected, sim.neighbors(@intCast(a), &out));
    }

    // The isolated node has no out-neighbors and no links.
    var out: [8]NodeId = undefined;
    try testing.expectEqual(@as(usize, 0), sim.neighbors(ids[5], &out));

    // `neighbors` still honors a short output buffer.
    var tiny: [2]NodeId = undefined;
    try testing.expectEqual(@as(usize, 2), sim.neighbors(ids[0], &tiny));
}
