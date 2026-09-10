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

pub const LinkConfigError = error{
    /// A `_permille` field of `LinkConfig` exceeded 1000 (100%) — see
    /// `Sim.addLink` (audit F13).
    InvalidPermille,
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
    /// Optional cap on cumulative delivered-payload bytes for the run — see
    /// `Sim.max_live_bytes` (audit F11). `null` (the default) is today's
    /// behaviour, unbounded; a caller building a `Sim` directly instead of
    /// through `build`/`replay`/`run` sets `sim.max_live_bytes` the same way
    /// `want_log` is set post-init.
    max_live_bytes: ?usize = null,
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
    cut: []NodeId, // owned by sim.arena -- kept for the log's `.c = cut.len`
    /// `cut` as a bitset over node ids, owned by sim.arena (audit F15:
    /// `severed()` used to do two `indexOfScalar` scans of `cut` -- O(|cut|)
    /// each -- for EVERY active partition on EVERY delivery. Membership is
    /// now O(1). `bit_length` is the node count as of this fault's apply time
    /// (topology is always built before any fault, so this equals
    /// `nodes.items.len` for the run's whole remaining lifetime in every
    /// known caller) -- `isNodeInCut` below still checks against it rather
    /// than assuming, so a node id added afterward reads as "not cut" instead
    /// of tripping `DynamicBitSetUnmanaged.isSet`'s bounds assert.
    cut_set: std.DynamicBitSetUnmanaged,
};

fn isNodeInCut(set: *const std.DynamicBitSetUnmanaged, node: NodeId) bool {
    const idx: usize = node;
    return idx < set.bit_length and set.isSet(idx);
}

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
    /// audit F10: `replay` built a full `Log` (including the tight ddmin
    /// shrink loop, which calls it with `log_out = null` thousands of times)
    /// even when nothing ever reads it — measured ~40% of a replay's time.
    /// `log_out` is consulted only AFTER the run finishes, so `replay` now
    /// sets this to `false` up front when it has nowhere to put the log.
    /// Default `true`: every direct `Sim.init` caller (3 in-repo consumers
    /// construct a `Sim` themselves and read `.log` afterward) is unaffected
    /// — only `replay`'s own internal `Sim` ever turns this off. The
    /// fingerprint is unaffected either way: `append` folds it unconditionally.
    want_log: bool = true,
    violation: ?Violation = null,
    /// audit F11: cumulative bytes ever handed to `send`'s payload copies
    /// (the arena that backs them is freed only at `deinit`, not as messages
    /// are delivered) — a running total across the WHOLE run, not a live/
    /// in-flight count. `null` (the default) is today's behaviour, unbounded:
    /// measured at 20 000 sends of 64 KiB, `VmHWM` grows by the full
    /// 1250 MiB, identically in Debug/ReleaseSafe/ReleaseFast/ReleaseSmall.
    /// Set to bound a long or adversarial run instead of discovering the
    /// limit as an OOM kill outside the process's own control.
    max_live_bytes: ?usize = null,
    live_bytes: usize = 0,

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

    pub fn addLink(self: *Sim, a: NodeId, b: NodeId, cfg: LinkConfig) (Allocator.Error || LinkConfigError)!void {
        // audit F13: `Prng.permille(rate)` is `below(1000) < rate`, which for
        // any `rate > 1000` is trivially true every time — a caller who
        // mistypes "5%" as `loss_permille = 5000` (instead of `50`) gets a
        // permanently dead link, not a config error, and the protocol under
        // test then passes trivially because nothing is ever delivered.
        // Rejected at the boundary where the value enters, mirroring
        // `fault.ConfigError.ZeroHorizon`.
        if (cfg.loss_permille > 1000 or cfg.dup_permille > 1000 or cfg.reorder_permille > 1000)
            return error.InvalidPermille;
        const idx: u32 = @intCast(self.links.items.len);
        try self.links.append(self.gpa, .{ .a = a, .b = b, .cfg = cfg });
        errdefer _ = self.links.pop();
        try self.out_adj.items[a].append(self.gpa, idx);
    }

    /// Add both directions with the same config.
    pub fn addBiLink(self: *Sim, a: NodeId, b: NodeId, cfg: LinkConfig) (Allocator.Error || LinkConfigError)!void {
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
    /// Fails closed rather than silently truncating (audit F2): a node with
    /// more out-neighbors than `out` can hold previously dropped the excess
    /// with no signal, which could mask (or fabricate) a protocol bug under
    /// a scenario the caller never sized its buffer for — exactly the class
    /// of failure this simulator exists to catch, not hide.
    pub fn neighbors(self: *const Sim, node: NodeId, out: []NodeId) error{TooManyNeighbors}!usize {
        const adj = self.out_adj.items[node].items;
        if (adj.len > out.len) return error.TooManyNeighbors;
        for (adj, 0..) |idx, n| out[n] = self.links.items[idx].b;
        return adj.len;
    }

    /// Failures `send` can report on top of `Allocator.Error`.
    pub const SendError = Allocator.Error || error{
        /// `max_live_bytes` is set and this payload copy would push the
        /// run's cumulative delivered-byte count over it (audit F11).
        LiveBytesExceeded,
    };

    /// Charge `n` bytes against `max_live_bytes`, loudly, BEFORE the
    /// allocation that would spend them — a caller who set the cap gets
    /// `error.LiveBytesExceeded` instead of an unbounded arena silently
    /// growing past whatever budget they had in mind.
    fn chargeLiveBytes(self: *Sim, n: usize) error{LiveBytesExceeded}!void {
        if (self.max_live_bytes) |max| {
            if (self.live_bytes + n > max) return error.LiveBytesExceeded;
        }
        self.live_bytes += n;
    }

    /// Schedule delivery of `payload` (copied) from `from` to `to`, subject to
    /// the link's latency/jitter/loss/dup/reorder and any one-shot fault armed
    /// on it. Connectivity (link-down / partition / crashed receiver) is checked
    /// at DELIVERY time, so a link that fails after send drops the in-flight message.
    pub fn send(self: *Sim, from: NodeId, to: NodeId, payload: []const u8) SendError!void {
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
        if (link.cfg.jitter > 0) delay += self.prng.belowWide(link.cfg.jitter + 1);
        if (link.cfg.bandwidth) |bw| {
            if (bw > 0) delay += payload.len / bw;
        }
        if (link.cfg.reorder_extra > 0 and self.prng.permille(link.cfg.reorder_permille))
            delay += self.prng.belowWide(link.cfg.reorder_extra + 1);
        if (link.delay_pending > 0) {
            delay += link.delay_pending;
            link.delay_pending = 0;
        }

        try self.chargeLiveBytes(payload.len);
        const buf = try self.arena.allocator().dupe(u8, payload);
        try self.pushDeliver(from, to, buf, self.now + delay);

        const dup_cfg = self.prng.permille(link.cfg.dup_permille);
        if (link.dup_pending > 0 or dup_cfg) {
            if (link.dup_pending > 0) link.dup_pending -= 1;
            try self.chargeLiveBytes(payload.len);
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
        if (!self.want_log) return; // audit F10: nothing will ever read this entry
        // Best-effort: a log OOM must not corrupt the deterministic fingerprint,
        // which is already folded above.
        self.log.entries.append(self.gpa, e) catch {};
    }

    /// Is a → b currently severed (no link, link down, or a partition cuts it)?
    fn severed(self: *Sim, a: NodeId, b: NodeId) bool {
        const link = self.findLink(a, b) orelse return true;
        if (!link.up) return true;
        for (self.partitions.items) |p| {
            const in_a = isNodeInCut(&p.cut_set, a);
            const in_b = isNodeInCut(&p.cut_set, b);
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
                var cut_set = try std.DynamicBitSetUnmanaged.initEmpty(self.arena.allocator(), self.nodes.items.len);
                for (cut) |n| if (n < self.nodes.items.len) cut_set.set(n);
                try self.partitions.append(self.gpa, .{ .id = p.id, .cut = cut, .cut_set = cut_set });
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
                // audit F1: `replay` is public and takes a trace from
                // anywhere (a hand-edited reproducer, a shrunk trace applied
                // to a smaller topology, ...) — unlike `fault.generate`,
                // which only ever draws ids bounded by its own topology. An
                // unchecked index here panicked in Debug and wrote past the
                // array in ReleaseFast while still reporting `outcome = .ok`.
                if (c.node >= self.nodes.items.len) return error.UnknownNode;
                self.nodes.items[c.node].crashed = true;
                self.append(.{ .tag = .crash, .a = c.node });
            },
            .restart_node => |r| {
                if (r.node >= self.nodes.items.len) return error.UnknownNode;
                self.nodes.items[r.node].crashed = false;
                self.append(.{ .tag = .restart, .a = r.node });
                if (self.protocol.onStartFn) |f| try f(self.protocol.ctx, self, r.node);
            },
            .clock_jump => |j| {
                if (j.node >= self.nodes.items.len) return error.UnknownNode;
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
    sim.max_live_bytes = case.max_live_bytes; // audit F11, additive: null preserves today's unbounded behaviour
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
    // audit F10: nothing reads `log` unless the caller asked for it — the
    // ddmin shrink loop calls `replay` with `log_out = null` thousands of
    // times, and building the log was ~40% of that time.
    sim.want_log = (log_out != null);
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
///
/// audit F9: this used to build the topology TWICE — once via `snapshotTopo`
/// (which builds a whole `Sim`, running `case.scenario`, just to copy out the
/// node count and link list before throwing the `Sim` away) and once more
/// inside `replay`, which builds its own fresh `Sim` and runs the SAME
/// `case.scenario` again. Measured (ReleaseFast, ring topology, 200 reps):
/// `snapshotTopo` + `build`'s own topology construction was **~50% of a
/// `run()` call** across every size tried (32/256/2048 nodes, two independent
/// sessions). `Scenario`'s own contract ("add nodes/links deterministically,
/// no unseeded randomness") is exactly what makes the second build
/// redundant: it can only ever reproduce the first one. Now the topology is
/// built ONCE and the same `Sim` both supplies it to `fault.generate` and
/// then drives the trace — the two builds collapse into one without
/// changing what either half sees.
pub fn run(gpa: Allocator, case: Case, fault_cfg: fault.Config) anyerror!GenResult {
    var log = Log{};
    defer log.deinit(gpa);
    var sim = try build(gpa, case, &log);
    defer sim.deinit();
    // `run` never asks `replay` for a log either (it always passed
    // `log_out = null`), so this preserves today's behaviour exactly.
    sim.want_log = false;

    const links = try gpa.alloc(fault.Link, sim.links.items.len);
    defer gpa.free(links);
    for (sim.links.items, links) |lr, *l| l.* = .{ .a = lr.a, .b = lr.b };

    var trace = try fault.generate(gpa, case.seed, .{ .node_count = sim.nodes.items.len, .links = links }, fault_cfg);
    errdefer trace.deinit();
    try sim.injectFaults(trace.events);
    const outcome = try sim.drive();
    const result: RunResult = .{
        .outcome = outcome,
        .events_processed = sim.events_processed,
        .fingerprint = sim.fingerprint,
        .violation = sim.violation,
    };
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

test "drive: an event scheduled AFTER `until` is never processed (audit F4 teeth)" {
    // The companion to the boundary test above: `[0, until]` is inclusive on
    // the near end (pinned above) but must be exclusive past it, or a mutant
    // that deletes `if (t > self.until) break;` sails through unnoticed — the
    // audit's own mutate.sh found exactly that ("mez until smazána" survived
    // the pre-fix suite).
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var fired: usize = 0;

    const Hooks = struct {
        fn onMessage(ctx: *anyopaque, s: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
            _ = .{ ctx, s, node, from, payload };
        }
        fn onTimer(ctx: *anyopaque, s: *Sim, node: NodeId, timer_id: u64) anyerror!void {
            _ = .{ s, node, timer_id };
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
    try sim.setTimer(0, 100, 0); // at `until` — must fire
    try sim.setTimer(0, 101, 1); // past `until` — must NOT fire
    _ = try sim.drive();

    try testing.expectEqual(@as(usize, 1), fired);
}

test "drive: max_events_cap actually backstops a live-locked protocol (audit F4 teeth)" {
    // `Case.max_events_cap` exists specifically to bound a protocol that
    // reschedules itself forever (a live-lock) — the audit's mutate.sh found
    // that deleting `if (self.events_processed >= self.max_events_cap)
    // break;` survives the pre-fix suite untouched.
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var fired: usize = 0;

    const Hooks = struct {
        fn onMessage(ctx: *anyopaque, s: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
            _ = .{ ctx, s, node, from, payload };
        }
        fn onTimer(ctx: *anyopaque, s: *Sim, node: NodeId, timer_id: u64) anyerror!void {
            _ = timer_id;
            const count: *usize = @ptrCast(@alignCast(ctx));
            count.* += 1;
            try s.setTimer(node, 0, 0); // reschedule at the SAME tick: live-lock
        }
    };
    const protocol = Protocol{
        .ctx = &fired,
        .onMessageFn = Hooks.onMessage,
        .onTimerFn = Hooks.onTimer,
    };

    // `until` set absurdly high so only the cap, not the clock, can stop this.
    var sim = Sim.init(gpa, 1, protocol, &log, 1_000_000, 50);
    defer sim.deinit();
    _ = try sim.addNode(.{});
    try sim.setTimer(0, 0, 0);
    const outcome = try sim.drive();

    try testing.expectEqual(RunOutcome.ok, outcome);
    try testing.expectEqual(@as(u64, 50), sim.events_processed);
    try testing.expectEqual(@as(usize, 50), fired);
}

test "applyFault: an out-of-range node id is rejected, not indexed unchecked (audit F1)" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    const Noop = struct {
        fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
    };
    var unused: usize = 0;
    var sim = Sim.init(gpa, 1, .{ .ctx = &unused, .onMessageFn = Noop.onMessage }, &log, 100, 1000);
    defer sim.deinit();
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{});
    _ = try sim.addNode(.{}); // 4 nodes, valid ids 0..3

    try testing.expectError(error.UnknownNode, sim.applyFault(.{ .crash_node = .{ .node = 99 } }));
    try testing.expectError(error.UnknownNode, sim.applyFault(.{ .restart_node = .{ .node = 99 } }));
    try testing.expectError(error.UnknownNode, sim.applyFault(.{ .clock_jump = .{ .node = 99, .delta = 5 } }));

    // Positive control: a valid node id still works exactly as before.
    try sim.applyFault(.{ .crash_node = .{ .node = 2 } });
    try testing.expect(sim.nodes.items[2].crashed);
    try sim.applyFault(.{ .clock_jump = .{ .node = 1, .delta = 7 } });
    try testing.expectEqual(@as(i64, 7), sim.nodes.items[1].clock_offset);
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
        try testing.expectEqual(expected, try sim.neighbors(@intCast(a), &out));
    }

    // The isolated node has no out-neighbors and no links.
    var out: [8]NodeId = undefined;
    try testing.expectEqual(@as(usize, 0), try sim.neighbors(ids[5], &out));

    // audit F2: `neighbors` now fails closed instead of silently truncating.
    // `ids[0]` has 4 real out-neighbors (to ids[1]/ids[2]/ids[3] via the
    // bi-links above, plus the self-loop) — a buffer that can hold only 2
    // must be refused, not quietly handed the first 2 and no signal.
    var tiny: [2]NodeId = undefined;
    try testing.expectError(error.TooManyNeighbors, sim.neighbors(ids[0], &tiny));
    // A buffer sized to fit exactly is fine, and `out` past the written
    // count is untouched (unlike the old always-fill-what-fits behavior,
    // there is no partial write to be careful about on error, but pin it
    // anyway as a contract, not an accident of the current implementation).
    var exact: [4]NodeId = undefined;
    try testing.expectEqual(@as(usize, 4), try sim.neighbors(ids[0], &exact));
}

test "addLink: a _permille field above 1000 is rejected, not silently saturated to certainty (audit F13)" {
    // `Prng.permille(rate)` is `below(1000) < rate`, which for ANY
    // `rate > 1000` is trivially true on every call — a caller who mistypes
    // "5%" as `loss_permille = 5000` gets a permanently dead link with no
    // config error, and the protocol under test then passes trivially
    // because nothing is ever delivered.
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    const Noop = struct {
        fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
    };
    var unused: usize = 0;
    var sim = Sim.init(gpa, 1, .{ .ctx = &unused, .onMessageFn = Noop.onMessage }, &log, 100, 1000);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});

    try testing.expectError(error.InvalidPermille, sim.addLink(a, b, .{ .loss_permille = 5000 }));
    try testing.expectError(error.InvalidPermille, sim.addLink(a, b, .{ .dup_permille = 1001 }));
    try testing.expectError(error.InvalidPermille, sim.addLink(a, b, .{ .reorder_permille = 65535 }));
    try testing.expectEqual(@as(usize, 0), sim.links.items.len); // none of the above were added

    // Positive control: the documented range (0..=1000) still works,
    // INCLUDING the boundary value 1000 itself — fleetsim relies on exactly
    // `reorder_permille = 1000` / `dup_permille = 1000` in its own tests.
    try sim.addLink(a, b, .{ .loss_permille = 1000 });
    try testing.expectEqual(@as(usize, 1), sim.links.items.len);
}

// ── F4 teeth: the five LinkConfig properties `mutate.sh` found untested ──────
//
// `drop_once`/`link_down`/`crash_node`/`restart_node`/`delay_once` (one-shot
// faults, tested above in `root.zig`) and `dup_once` (the one one-shot fault
// that already had teeth, per the audit) all have a single deterministic
// trace to test against. These five are different: `loss_permille`,
// `dup_permille`, `jitter`, `reorder_extra` and `bandwidth` are STATIC
// per-message properties of `LinkConfig` applied by `Sim.send` itself
// (`:420-447`), not one-shot faults from a trace — a mutation that turns any
// one of them into a no-op still produces a legally-shaped run, so the right
// check is "N sends, then a statistical property of the log", not "one trace,
// one exact outcome". A test whose sends land 0% of the time on the
// mutated behaviour would be worthless (indistinguishable from the mutant);
// every test below is sized so it fails hard, not flakily, against a no-op.

fn statNoopSim(gpa: Allocator, log: *Log, seed: u64) Sim {
    const Noop = struct {
        fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
    };
    return Sim.init(gpa, seed, .{ .ctx = undefined, .onMessageFn = Noop.onMessage }, log, 1_000_000, 1_000_000);
}

test "F4 teeth: loss_permille actually drops messages at roughly the configured rate" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 7);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{ .loss_permille = 300 });

    const n = 4000;
    var i: usize = 0;
    while (i < n) : (i += 1) try sim.send(a, b, "x");

    var drops: usize = 0;
    for (log.entries.items) |e| {
        if (e.tag == .drop) drops += 1;
    }
    // Expected ~1200/4000 (30%). A no-op mutation gives 0; a mutation that
    // drops unconditionally gives ~4000. Both are far outside this band.
    try testing.expect(drops > 800 and drops < 1600);
}

test "F4 teeth: dup_permille actually duplicates messages at roughly the configured rate" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 11);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{ .dup_permille = 300 });

    const n = 4000;
    var i: usize = 0;
    while (i < n) : (i += 1) try sim.send(a, b, "x");

    var dups: usize = 0;
    for (log.entries.items) |e| {
        if (e.tag == .dup) dups += 1;
    }
    try testing.expect(dups > 800 and dups < 1600);
}

test "F4 teeth: jitter actually varies the per-message delay, not a fixed offset" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 13);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{ .latency = 10, .jitter = 50 });

    const n = 2000;
    var i: usize = 0;
    while (i < n) : (i += 1) try sim.send(a, b, "x");

    // Nothing drove the queue, so `sim.now` never moved: every queued
    // deliver event's absolute time IS its delay.
    var min_delay: Time = std.math.maxInt(Time);
    var max_delay: Time = 0;
    i = 0;
    while (i < n) : (i += 1) {
        const ev = sim.queue.pop();
        try testing.expect(ev.kind == .deliver);
        try testing.expect(ev.time >= 10 and ev.time <= 60); // latency + [0, jitter]
        min_delay = @min(min_delay, ev.time);
        max_delay = @max(max_delay, ev.time);
    }
    // A no-op mutation collapses every delay to exactly 10 (min == max).
    // Over 2000 draws of `belowWide(51)` the observed range should come
    // close to both ends; this is a loose band, not a distribution check
    // (`prng.zig` already owns the distribution itself).
    try testing.expect(min_delay <= 12);
    try testing.expect(max_delay >= 58);
}

test "F4 teeth: reorder_extra actually delays a fraction of messages further, not just the ones that got it in the trace" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 17);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{ .latency = 10, .reorder_permille = 300, .reorder_extra = 1000 });

    const n = 2000;
    var i: usize = 0;
    while (i < n) : (i += 1) try sim.send(a, b, "x");

    var reordered: usize = 0;
    i = 0;
    while (i < n) : (i += 1) {
        const ev = sim.queue.pop();
        try testing.expect(ev.kind == .deliver);
        try testing.expect(ev.time == 10 or (ev.time > 10 and ev.time <= 1010));
        if (ev.time > 10) reordered += 1;
    }
    // Expected ~600/2000 (30%). A no-op mutation (either the trigger or the
    // extra-delay draw silenced) gives 0.
    try testing.expect(reordered > 350 and reordered < 850);
}

test "F4 teeth: bandwidth actually adds a payload-size-dependent serialization delay" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 19);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{ .latency = 5, .bandwidth = 100 });

    var small_payload: [250]u8 = @splat('x');
    try sim.send(a, b, &small_payload);
    var large_payload: [1000]u8 = @splat('y');
    try sim.send(a, b, &large_payload);

    const ev1 = sim.queue.pop();
    const ev2 = sim.queue.pop();
    // Deterministic (no PRNG involved): latency + payload.len / bandwidth.
    try testing.expectEqual(@as(Time, 5 + 250 / 100), ev1.time); // 7
    try testing.expectEqual(@as(Time, 5 + 1000 / 100), ev2.time); // 15
}

test "send: max_live_bytes bounds cumulative delivered payload bytes (audit F11)" {
    // Unlike the five properties above, this isn't a per-message coin flip —
    // it's a running total, so a single deterministic sequence is enough.
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    var sim = statNoopSim(gpa, &log, 23);
    defer sim.deinit();
    const a = try sim.addNode(.{});
    const b = try sim.addNode(.{});
    try sim.addLink(a, b, .{});

    // Positive control first: the default (null) is genuinely unbounded —
    // many sends that would trip a 100-byte cap must all succeed with it
    // left at its default.
    try testing.expectEqual(@as(?usize, null), sim.max_live_bytes);
    var i: usize = 0;
    while (i < 10) : (i += 1) try sim.send(a, b, "0123456789"); // 100 bytes total
    try testing.expectEqual(@as(usize, 100), sim.live_bytes);

    sim.max_live_bytes = 150;
    i = 0;
    while (i < 4) : (i += 1) try sim.send(a, b, "0123456789"); // +40 -> 140, still under
    try testing.expectEqual(@as(usize, 140), sim.live_bytes);
    // The 5th 10-byte send would land on exactly 150 -- at the cap, not over
    // it, so it must still be accepted (a boundary-off-by-one would refuse
    // this one instead of the next).
    try sim.send(a, b, "0123456789");
    try testing.expectEqual(@as(usize, 150), sim.live_bytes);
    try testing.expectError(error.LiveBytesExceeded, sim.send(a, b, "0123456789"));
    // A refused send must not have charged anything -- the total stays put,
    // not silently grown past the cap it just enforced.
    try testing.expectEqual(@as(usize, 150), sim.live_bytes);
}

test "build: Case.max_live_bytes reaches the Sim it builds (audit F11)" {
    // The Sim-level field is covered above directly; this is the OTHER half
    // -- that `replay`/`run` (the entry points nearly every consumer uses,
    // not raw `Sim.init`) actually plumb `Case.max_live_bytes` through
    // `build` rather than leaving it stranded on the `Case` value.
    const gpa = testing.allocator;
    const OneShotSender = struct {
        fn onStart(_: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
            if (node == 0) try sim.send(0, 1, "hello"); // 5 bytes
        }
        fn onMessage(_: *anyopaque, _: *Sim, _: NodeId, _: NodeId, _: []const u8) anyerror!void {}
    };
    const scenario = struct {
        fn build2(sim: *Sim) anyerror!void {
            _ = try sim.addNode(.{});
            _ = try sim.addNode(.{});
            try sim.addBiLink(0, 1, .{ .latency = 5 });
        }
    }.build2;
    var unused: usize = 0;
    const case = Case{
        .seed = 1,
        .scenario = scenario,
        .protocol = .{ .ctx = &unused, .onStartFn = OneShotSender.onStart, .onMessageFn = OneShotSender.onMessage },
        .until = 100,
        .max_live_bytes = 3, // "hello" is 5 bytes -- too small on purpose
    };
    try testing.expectError(error.LiveBytesExceeded, replay(gpa, case, &.{}, null));

    // Positive control: the same scenario with room to spare succeeds.
    const roomy_case = Case{
        .seed = 1,
        .scenario = scenario,
        .protocol = .{ .ctx = &unused, .onStartFn = OneShotSender.onStart, .onMessageFn = OneShotSender.onMessage },
        .until = 100,
        .max_live_bytes = 1000,
    };
    const result = try replay(gpa, roomy_case, &.{}, null);
    try testing.expectEqual(RunOutcome.ok, result.outcome);
}
