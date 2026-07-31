// SPDX-License-Identifier: MIT

//! The fleet: N simulated devices, one injected clock, one event queue, one
//! seed — and therefore one reproducible trace.
//!
//! Everything that could make two runs differ is either injected or seeded:
//!
//!   - **time** comes only from `advance(to_ms)`; nothing here reads a clock;
//!   - **randomness** comes from two `std.Random.DefaultPrng` streams derived
//!     from `Options.seed` (one for link mechanics, one for signal drivers) so
//!     that adding a signal cannot perturb packet loss, and vice versa;
//!   - **order** is the total order `(time, insertion sequence)`, and the
//!     sequence counter is bumped at insertion, which happens in a fixed order;
//!   - **memory** is a fixed pool, so an allocator that hands back different
//!     addresses cannot change behaviour.
//!
//! There are no threads and no sockets here. A harness feeds frames in with
//! `submit`, advances the clock, and reads the frames the fleet wants to send
//! back out of `outbound()`. The TCP/UDP binding in `tcp.zig` is the only thing
//! in this module that knows what a socket is.

const std = @import("std");
const Allocator = std.mem.Allocator;

const netsim = @import("netsim");
const node_mod = @import("node.zig");
const drivers = @import("drivers.zig");

pub const Node = node_mod.Node;
pub const NodeId = node_mod.NodeId;
pub const Time = node_mod.Time;
pub const Protocol = node_mod.Protocol;
pub const Framing = node_mod.Framing;
pub const Control = node_mod.Control;
pub const Signal = drivers.Signal;

// ── faults ──────────────────────────────────────────────────────────────────

/// Per-node link behaviour. Rates are parts per mille, drawn from the link
/// PRNG once per frame in each direction.
pub const LinkFaults = struct {
    /// Fixed one-way delay applied to every frame in each direction.
    delay_ms: Time = 0,
    /// Uniform extra delay in `[0, jitter_ms]`.
    jitter_ms: Time = 0,
    loss_permille: u16 = 0,
    dup_permille: u16 = 0,
    /// A reordered frame is simply delayed by `reorder_extra_ms`, which is what
    /// reordering *is* on a single link: it arrives after something newer.
    reorder_permille: u16 = 0,
    reorder_extra_ms: Time = 50,
};

/// A scheduled, protocol-level or link-level perturbation of one node.
pub const FaultKind = union(enum) {
    /// Stop answering entirely until `until_ms` (use `std.math.maxInt(u64)` for
    /// "never comes back"). The device is powered but mute — the failure mode a
    /// master's timeout logic exists for.
    silent: struct { until_ms: Time },
    /// Answer, but `extra_ms` late, until `until_ms`.
    slow: struct { extra_ms: Time, until_ms: Time },
    /// Report a device problem in whatever way the protocol has: a Modbus
    /// `SlaveDeviceFailure` exception, DNP3 IIN1.6, an S7 CPU in STOP, IEC 104
    /// `iv` quality.
    trouble: struct { on: bool },
    /// Power-cycle the responder: state returns to as-constructed, so the
    /// master sees the restart indication.
    restart,
    /// Clear every active behaviour fault on the node (not the link rates).
    heal,
    /// Replace the node's link fault rates wholesale.
    link: LinkFaults,
    /// Drop the next `count` inbound frames.
    drop_next: struct { count: u32 },
    /// Duplicate the next `count` inbound frames.
    dup_next: struct { count: u32 },
    /// Delay the next `count` inbound frames by `extra_ms`.
    delay_next: struct { count: u32, extra_ms: Time },
};

pub const Fault = struct {
    at_ms: Time,
    node: NodeId,
    kind: FaultKind,
};

// ── the trace ───────────────────────────────────────────────────────────────

pub const TraceKind = enum {
    /// A frame was handed to the node's responder.
    delivered,
    /// The node answered; the bytes are on their way out.
    replied,
    /// A tick produced unsolicited traffic.
    tick_replied,
    /// A frame reached `outbound()`.
    emitted,
    /// Link loss ate an inbound frame.
    dropped_in,
    /// Link loss ate an outbound frame.
    dropped_out,
    duplicated_in,
    duplicated_out,
    delayed_in,
    /// The node was silent (or slow past its window) and said nothing.
    silent,
    /// The responder returned an error.
    responder_error,
    /// A reply did not fit the fleet's per-frame buffer.
    output_overflow,
    /// The in-flight slot pool or the outbox was full.
    capacity_exhausted,
    /// A responder emitted bytes that do not parse as its own framing.
    bad_framing,
    control_applied,
    control_unsupported,
    signal_fired,
};

pub const TraceEntry = struct {
    time: Time,
    node: NodeId,
    kind: TraceKind,
    /// Offset/length into `traceBytes()`. Zero-length for non-frame entries.
    off: u32 = 0,
    len: u32 = 0,
};

/// A frame the fleet wants transmitted on a node's behalf.
pub const OutFrame = struct {
    node: NodeId,
    time: Time,
    off: u32,
    len: u32,
};

// ── per-node bookkeeping ────────────────────────────────────────────────────

pub const NodeStats = struct {
    delivered: u64 = 0,
    replied: u64 = 0,
    emitted: u64 = 0,
    ticks: u64 = 0,
    dropped_in: u64 = 0,
    dropped_out: u64 = 0,
    duplicated: u64 = 0,
    silent_drops: u64 = 0,
    responder_errors: u64 = 0,
    restarts: u64 = 0,
};

pub const NodeSpec = struct {
    node: Node,
    /// Fire `tick` this often. Zero means "only when `nextDeadline` asks".
    tick_period_ms: Time = 0,
    link: LinkFaults = .{},
    /// Opaque caller tag (a device id, an index into the caller's own table).
    tag: u64 = 0,
};

const Entry = struct {
    node: Node,
    tick_period_ms: Time,
    link: LinkFaults,
    tag: u64,
    stats: NodeStats = .{},
    silent_until: Time = 0,
    slow_until: Time = 0,
    slow_extra: Time = 0,
    trouble: bool = false,
    drop_next: u32 = 0,
    dup_next: u32 = 0,
    delay_next: u32 = 0,
    delay_next_extra: Time = 0,
    tick_pending: bool = false,
};

// ── the event queue ─────────────────────────────────────────────────────────

const EventKind = union(enum) {
    deliver: struct { node: NodeId, slot: u32 },
    emit: struct { node: NodeId, slot: u32 },
    tick: struct { node: NodeId },
    signal: struct { index: u32 },
    fault: struct { index: u32 },
};

const Event = struct {
    time: Time,
    seq: u64,
    kind: EventKind,

    /// The total order that makes the whole thing deterministic: time first,
    /// insertion sequence as the tie-break. No two events compare equal.
    fn before(a: Event, b: Event) bool {
        if (a.time != b.time) return a.time < b.time;
        return a.seq < b.seq;
    }
};

// ── options + errors ────────────────────────────────────────────────────────

pub const Options = struct {
    seed: u64 = 0,
    /// Largest single frame the fleet carries. A reply bigger than this is a
    /// logged `output_overflow`, never a stomp.
    max_frame_len: usize = 1024,
    /// How many frames may be queued (in flight) at once, fleet-wide.
    inflight_capacity: usize = 512,
    /// Trace ring size in entries. The ring may wrap; the fingerprint does not.
    trace_capacity: usize = 4096,
    /// Byte budget for trace frame payloads.
    trace_bytes: usize = 128 * 1024,
    /// Byte budget for one `advance`'s worth of outbound frames.
    outbox_bytes: usize = 128 * 1024,
    /// Record frame payloads in the trace. Off for scale runs, where only the
    /// fingerprint and the counters matter.
    record_frames: bool = true,
};

pub const Error = error{
    /// `submit` named a node that does not exist.
    UnknownNode,
    /// The frame is larger than `max_frame_len`.
    FrameTooLarge,
    /// No free in-flight slot. The fleet stays consistent; the frame is lost
    /// and counted (`capacity_exhausted` in the trace).
    QueueFull,
} || Allocator.Error;

// ── the fleet ───────────────────────────────────────────────────────────────

pub const Fleet = struct {
    gpa: Allocator,
    opts: Options,

    nodes: std.ArrayList(Entry) = .empty,
    signals: std.ArrayList(*Signal) = .empty,
    faults: std.ArrayList(Fault) = .empty,
    partitions: std.ArrayList(Partition) = .empty,

    heap: std.ArrayList(Event) = .empty,
    seq: u64 = 0,

    // Fixed slot pool for in-flight frame bytes.
    slot_bytes: []u8 = &.{},
    slot_len: []u32 = &.{},
    slot_delayed: []bool = &.{},
    free_slots: []u32 = &.{},
    free_count: usize = 0,

    // The trace ring.
    trace_ring: []TraceEntry = &.{},
    trace_head: usize = 0,
    trace_count: usize = 0,
    trace_total: u64 = 0,
    trace_buf: []u8 = &.{},
    trace_used: usize = 0,
    fingerprint: u64 = 0xcbf29ce484222325,

    // This advance's outbound frames.
    out_frames: std.ArrayList(OutFrame) = .empty,
    out_buf: []u8 = &.{},
    out_used: usize = 0,

    scratch: []u8 = &.{},

    link_prng: std.Random.DefaultPrng,
    signal_prng: std.Random.DefaultPrng,

    now: Time = 0,
    /// Events processed over the fleet's whole life.
    events_processed: u64 = 0,
    /// Frames lost because a pool or budget was exhausted.
    capacity_losses: u64 = 0,

    const Partition = struct { id: u32, cut: []const NodeId };

    /// Separate stream constant so the signal PRNG cannot alias the link one.
    const signal_salt: u64 = 0x9E37_79B9_7F4A_7C15;

    pub fn init(gpa: Allocator, opts: Options) Allocator.Error!Fleet {
        var f = Fleet{
            .gpa = gpa,
            .opts = opts,
            .link_prng = std.Random.DefaultPrng.init(opts.seed),
            .signal_prng = std.Random.DefaultPrng.init(opts.seed ^ signal_salt),
        };
        errdefer f.deinit();
        f.slot_bytes = try gpa.alloc(u8, opts.inflight_capacity * opts.max_frame_len);
        f.slot_len = try gpa.alloc(u32, opts.inflight_capacity);
        f.slot_delayed = try gpa.alloc(bool, opts.inflight_capacity);
        f.free_slots = try gpa.alloc(u32, opts.inflight_capacity);
        for (f.free_slots, 0..) |*s, i| s.* = @intCast(i);
        f.free_count = opts.inflight_capacity;
        f.trace_ring = try gpa.alloc(TraceEntry, opts.trace_capacity);
        f.trace_buf = try gpa.alloc(u8, opts.trace_bytes);
        f.out_buf = try gpa.alloc(u8, opts.outbox_bytes);
        f.scratch = try gpa.alloc(u8, opts.max_frame_len);
        return f;
    }

    pub fn deinit(self: *Fleet) void {
        self.nodes.deinit(self.gpa);
        self.signals.deinit(self.gpa);
        self.faults.deinit(self.gpa);
        self.partitions.deinit(self.gpa);
        self.heap.deinit(self.gpa);
        self.out_frames.deinit(self.gpa);
        if (self.slot_bytes.len != 0) self.gpa.free(self.slot_bytes);
        if (self.slot_len.len != 0) self.gpa.free(self.slot_len);
        if (self.slot_delayed.len != 0) self.gpa.free(self.slot_delayed);
        if (self.free_slots.len != 0) self.gpa.free(self.free_slots);
        if (self.trace_ring.len != 0) self.gpa.free(self.trace_ring);
        if (self.trace_buf.len != 0) self.gpa.free(self.trace_buf);
        if (self.out_buf.len != 0) self.gpa.free(self.out_buf);
        if (self.scratch.len != 0) self.gpa.free(self.scratch);
        self.* = undefined;
    }

    // ── building the fleet ──────────────────────────────────────────────────

    pub fn addNode(self: *Fleet, spec: NodeSpec) Allocator.Error!NodeId {
        const id: NodeId = @intCast(self.nodes.items.len);
        try self.nodes.append(self.gpa, .{
            .node = spec.node,
            .tick_period_ms = spec.tick_period_ms,
            .link = spec.link,
            .tag = spec.tag,
        });
        if (spec.tick_period_ms != 0 and spec.node.hasTick()) {
            self.nodes.items[id].tick_pending = true;
            try self.push(self.now + spec.tick_period_ms, .{ .tick = .{ .node = id } });
        }
        return id;
    }

    /// Register a caller-owned signal. It fires at `start_ms`, then every
    /// `period_ms`.
    pub fn addSignal(self: *Fleet, signal: *Signal) Allocator.Error!void {
        const index: u32 = @intCast(self.signals.items.len);
        try self.signals.append(self.gpa, signal);
        try self.push(@max(signal.start_ms, self.now), .{ .signal = .{ .index = index } });
    }

    pub fn addFault(self: *Fleet, fault: Fault) Allocator.Error!void {
        const index: u32 = @intCast(self.faults.items.len);
        try self.faults.append(self.gpa, fault);
        try self.push(@max(fault.at_ms, self.now), .{ .fault = .{ .index = index } });
    }

    /// Translate a `netsim` fault trace into fleet faults. This is the reuse
    /// seam: netsim already owns the seeded churn-and-recover schedule fuzzer,
    /// the replayable trace format and the delta-debugging shrinker, so the
    /// fleet borrows the schedule rather than growing a second one.
    ///
    /// A fleet is a star (every device talks to the outside world, not to its
    /// peers), so the link-scoped kinds are mapped onto the device end of the
    /// link and `clock_jump` has no fleet meaning — the count of unmapped
    /// events is returned so a caller can see what was dropped.
    pub fn applyNetsimTrace(self: *Fleet, events: []const netsim.FaultEvent) Allocator.Error!usize {
        var unmapped: usize = 0;
        for (events) |e| {
            const t: Time = e.time;
            switch (e.kind) {
                .crash_node => |c| try self.addFault(.{ .at_ms = t, .node = idOf(c.node), .kind = .{ .silent = .{ .until_ms = std.math.maxInt(Time) } } }),
                .restart_node => |c| {
                    try self.addFault(.{ .at_ms = t, .node = idOf(c.node), .kind = .heal });
                    try self.addFault(.{ .at_ms = t, .node = idOf(c.node), .kind = .restart });
                },
                .drop_once => |l| try self.addFault(.{ .at_ms = t, .node = idOf(l.b), .kind = .{ .drop_next = .{ .count = 1 } } }),
                .dup_once => |l| try self.addFault(.{ .at_ms = t, .node = idOf(l.b), .kind = .{ .dup_next = .{ .count = 1 } } }),
                .delay_once => |l| try self.addFault(.{ .at_ms = t, .node = idOf(l.b), .kind = .{ .delay_next = .{ .count = 1, .extra_ms = l.extra } } }),
                .link_down => |l| try self.addFault(.{ .at_ms = t, .node = idOf(l.b), .kind = .{ .silent = .{ .until_ms = std.math.maxInt(Time) } } }),
                .link_up => |l| try self.addFault(.{ .at_ms = t, .node = idOf(l.b), .kind = .heal }),
                .partition => |p| {
                    try self.partitions.append(self.gpa, .{ .id = p.id, .cut = p.cut });
                    for (p.cut) |n| try self.addFault(.{ .at_ms = t, .node = idOf(n), .kind = .{ .silent = .{ .until_ms = std.math.maxInt(Time) } } });
                },
                .heal => |h| {
                    for (self.partitions.items) |p| {
                        if (p.id != h.id) continue;
                        for (p.cut) |n| try self.addFault(.{ .at_ms = t, .node = idOf(n), .kind = .heal });
                    }
                },
                .clock_jump => unmapped += 1,
            }
        }
        return unmapped;
    }

    fn idOf(n: netsim.NodeId) NodeId {
        return @intCast(n);
    }

    // ── driving it ──────────────────────────────────────────────────────────

    /// Hand one complete inbound frame to a node. `at_ms` must not be in the
    /// past. Link faults (loss / duplication / delay / reorder) are drawn here,
    /// in submission order, which is what makes them replayable.
    pub fn submit(self: *Fleet, node: NodeId, frame: []const u8, at_ms: Time) Error!void {
        if (node >= self.nodes.items.len) return error.UnknownNode;
        if (frame.len > self.opts.max_frame_len) return error.FrameTooLarge;
        const e = &self.nodes.items[node];
        const at = @max(at_ms, self.now);

        if (e.drop_next > 0) {
            e.drop_next -= 1;
            e.stats.dropped_in += 1;
            self.record(at, node, .dropped_in, frame);
            return;
        }
        const rand = self.link_prng.random();
        if (permille(rand, e.link.loss_permille)) {
            e.stats.dropped_in += 1;
            self.record(at, node, .dropped_in, frame);
            return;
        }

        var delay = e.link.delay_ms + jitter(rand, e.link.jitter_ms);
        if (e.delay_next > 0) {
            e.delay_next -= 1;
            delay += e.delay_next_extra;
            self.record(at, node, .delayed_in, frame);
        } else if (permille(rand, e.link.reorder_permille)) {
            delay += e.link.reorder_extra_ms;
            self.record(at, node, .delayed_in, frame);
        }

        var copies: usize = 1;
        if (e.dup_next > 0) {
            e.dup_next -= 1;
            copies = 2;
            self.record(at, node, .duplicated_in, frame);
        } else if (permille(rand, e.link.dup_permille)) {
            copies = 2;
            e.stats.duplicated += 1;
            self.record(at, node, .duplicated_in, frame);
        }

        for (0..copies) |_| {
            const slot = self.takeSlot(frame) orelse {
                self.noteCapacity(at, node);
                return;
            };
            try self.push(at + delay, .{ .deliver = .{ .node = node, .slot = slot } });
        }
    }

    /// Split `bytes` into frames using the node's framing and submit each. The
    /// return value is how many bytes were consumed — a partial tail is left
    /// for the caller to re-present with more data.
    pub fn submitStream(self: *Fleet, node: NodeId, bytes: []const u8, at_ms: Time) Error!usize {
        if (node >= self.nodes.items.len) return error.UnknownNode;
        const framing = self.nodes.items[node].node.framing;
        var it = node_mod.FrameIterator.init(framing, bytes);
        while (it.next()) |frame| try self.submit(node, frame, at_ms);
        if (it.bad) {
            // Unparseable head: hand the whole thing to the responder anyway
            // and let it produce whatever a real device would (usually
            // silence). Dropping it here would hide the hostile case.
            try self.submit(node, bytes, at_ms);
            return bytes.len;
        }
        return bytes.len - it.rest().len;
    }

    /// Run every event due at or before `to_ms`. Returns how many fired.
    /// Frames the fleet wants transmitted are in `outbound()` afterwards; they
    /// stay valid until the next `advance`.
    pub fn advance(self: *Fleet, to_ms: Time) Error!usize {
        self.out_frames.clearRetainingCapacity();
        self.out_used = 0;
        var fired: usize = 0;
        while (self.heap.items.len != 0 and self.heap.items[0].time <= to_ms) {
            const ev = self.pop().?;
            self.now = ev.time;
            fired += 1;
            self.events_processed += 1;
            try self.run(ev);
        }
        self.now = @max(self.now, to_ms);
        return fired;
    }

    /// Simulated time of the next pending event, if any.
    pub fn nextEventTime(self: *const Fleet) ?Time {
        if (self.heap.items.len == 0) return null;
        return self.heap.items[0].time;
    }

    pub fn outbound(self: *const Fleet) []const OutFrame {
        return self.out_frames.items;
    }

    pub fn frameBytes(self: *const Fleet, f: OutFrame) []const u8 {
        return self.out_buf[f.off..][0..f.len];
    }

    pub fn stats(self: *const Fleet, node: NodeId) NodeStats {
        return self.nodes.items[node].stats;
    }

    pub fn nodeCount(self: *const Fleet) usize {
        return self.nodes.items.len;
    }

    pub fn tagOf(self: *const Fleet, node: NodeId) u64 {
        return self.nodes.items[node].tag;
    }

    pub fn protocolOf(self: *const Fleet, node: NodeId) Protocol {
        return self.nodes.items[node].node.protocol;
    }

    // ── event handling ──────────────────────────────────────────────────────

    fn run(self: *Fleet, ev: Event) Error!void {
        switch (ev.kind) {
            .deliver => |d| try self.onDeliver(ev.time, d.node, d.slot),
            .emit => |d| self.onEmit(ev.time, d.node, d.slot),
            .tick => |d| try self.onTick(ev.time, d.node),
            .signal => |d| try self.onSignal(ev.time, d.index),
            .fault => |d| self.onFault(ev.time, d.index),
        }
    }

    fn onDeliver(self: *Fleet, t: Time, node: NodeId, slot: u32) Error!void {
        const e = &self.nodes.items[node];
        const frame = self.slotBytes(slot);

        if (t < e.silent_until) {
            e.stats.silent_drops += 1;
            self.record(t, node, .silent, frame);
            self.freeSlot(slot);
            return;
        }
        if (t < e.slow_until and !self.slot_delayed[slot]) {
            self.slot_delayed[slot] = true;
            self.record(t, node, .delayed_in, frame);
            try self.push(t + e.slow_extra, .{ .deliver = .{ .node = node, .slot = slot } });
            return;
        }

        e.stats.delivered += 1;
        self.record(t, node, .delivered, frame);

        const reply = e.node.deliver(frame, self.scratch, t) catch |err| {
            e.stats.responder_errors += 1;
            self.record(t, node, switch (err) {
                error.OutputTooSmall => .output_overflow,
                error.ResponderFailed => .responder_error,
            }, &.{});
            self.freeSlot(slot);
            try self.rescheduleTick(node, t);
            return;
        };
        self.freeSlot(slot);
        if (reply) |bytes| {
            e.stats.replied += 1;
            self.record(t, node, .replied, bytes);
            try self.sendOut(t, node, bytes);
        }
        try self.rescheduleTick(node, t);
    }

    fn onTick(self: *Fleet, t: Time, node: NodeId) Error!void {
        const e = &self.nodes.items[node];
        e.tick_pending = false;
        e.stats.ticks += 1;

        if (t >= e.silent_until) {
            const reply = e.node.tick(self.scratch, t) catch |err| {
                e.stats.responder_errors += 1;
                self.record(t, node, switch (err) {
                    error.OutputTooSmall => .output_overflow,
                    error.ResponderFailed => .responder_error,
                }, &.{});
                try self.rescheduleTick(node, t);
                return;
            };
            if (reply) |bytes| {
                e.stats.replied += 1;
                self.record(t, node, .tick_replied, bytes);
                try self.sendOut(t, node, bytes);
            }
        }
        try self.rescheduleTick(node, t);
    }

    /// One outstanding tick per node, at the earliest of the periodic slot and
    /// whatever `nextDeadline` asks for. That bound is what keeps 1000 nodes
    /// from turning into 1000 timers per millisecond.
    fn rescheduleTick(self: *Fleet, node: NodeId, t: Time) Error!void {
        const e = &self.nodes.items[node];
        if (e.tick_pending or !e.node.hasTick()) return;
        var when: ?Time = null;
        if (e.tick_period_ms != 0) when = t + e.tick_period_ms;
        if (e.node.nextDeadline(t)) |d| {
            const clamped = @max(d, t + 1); // never schedule in the past
            when = if (when) |w| @min(w, clamped) else clamped;
        }
        const at = when orelse return;
        e.tick_pending = true;
        try self.push(at, .{ .tick = .{ .node = node } });
    }

    fn onSignal(self: *Fleet, t: Time, index: u32) Error!void {
        const sig = self.signals.items[index];
        sig.fire(t, self.signal_prng.random());
        self.record(t, 0, .signal_fired, &.{});
        if (sig.period_ms != 0) {
            try self.push(t + sig.period_ms, .{ .signal = .{ .index = index } });
        }
    }

    fn onFault(self: *Fleet, t: Time, index: u32) void {
        const f = self.faults.items[index];
        if (f.node >= self.nodes.items.len) return;
        const e = &self.nodes.items[f.node];
        switch (f.kind) {
            .silent => |s| e.silent_until = s.until_ms,
            .slow => |s| {
                e.slow_until = s.until_ms;
                e.slow_extra = s.extra_ms;
            },
            .trouble => |s| {
                e.trouble = s.on;
                const op: Control = if (s.on) .trouble_on else .trouble_off;
                const ok = e.node.control(op, t);
                self.record(t, f.node, if (ok) .control_applied else .control_unsupported, &.{});
            },
            .restart => {
                const ok = e.node.control(.restart, t);
                e.stats.restarts += 1;
                self.record(t, f.node, if (ok) .control_applied else .control_unsupported, &.{});
            },
            .heal => {
                e.silent_until = 0;
                e.slow_until = 0;
                e.slow_extra = 0;
                e.drop_next = 0;
                e.dup_next = 0;
                e.delay_next = 0;
                if (e.trouble) {
                    e.trouble = false;
                    _ = e.node.control(.trouble_off, t);
                }
                self.record(t, f.node, .control_applied, &.{});
            },
            .link => |l| e.link = l,
            .drop_next => |s| e.drop_next += s.count,
            .dup_next => |s| e.dup_next += s.count,
            .delay_next => |s| {
                e.delay_next += s.count;
                e.delay_next_extra = s.extra_ms;
            },
        }
    }

    /// Cut a responder's output back into wire frames, apply the outbound link
    /// faults per frame, and schedule each one's arrival at the far end.
    fn sendOut(self: *Fleet, t: Time, node: NodeId, bytes: []const u8) Error!void {
        const e = &self.nodes.items[node];
        const framing = e.node.framing;
        var it = node_mod.FrameIterator.init(framing, bytes);
        var any = false;
        while (it.next()) |frame| {
            any = true;
            try self.sendFrame(t, node, frame);
        }
        if (it.bad or (!any and bytes.len != 0)) {
            // The responder produced something its own framing cannot describe.
            // Ship it whole rather than silently swallowing it — a fleet that
            // hides a responder bug is worse than useless.
            self.record(t, node, .bad_framing, bytes);
            try self.sendFrame(t, node, bytes);
        } else if (it.rest().len != 0) {
            self.record(t, node, .bad_framing, it.rest());
            try self.sendFrame(t, node, it.rest());
        }
    }

    fn sendFrame(self: *Fleet, t: Time, node: NodeId, frame: []const u8) Error!void {
        const e = &self.nodes.items[node];
        const rand = self.link_prng.random();
        if (permille(rand, e.link.loss_permille)) {
            e.stats.dropped_out += 1;
            self.record(t, node, .dropped_out, frame);
            return;
        }
        var delay = e.link.delay_ms + jitter(rand, e.link.jitter_ms);
        if (permille(rand, e.link.reorder_permille)) delay += e.link.reorder_extra_ms;
        var copies: usize = 1;
        if (permille(rand, e.link.dup_permille)) {
            copies = 2;
            e.stats.duplicated += 1;
            self.record(t, node, .duplicated_out, frame);
        }
        for (0..copies) |_| {
            const slot = self.takeSlot(frame) orelse {
                self.noteCapacity(t, node);
                return;
            };
            try self.push(t + delay, .{ .emit = .{ .node = node, .slot = slot } });
        }
    }

    fn onEmit(self: *Fleet, t: Time, node: NodeId, slot: u32) void {
        const bytes = self.slotBytes(slot);
        const e = &self.nodes.items[node];
        if (self.out_used + bytes.len > self.out_buf.len) {
            self.noteCapacity(t, node);
            self.freeSlot(slot);
            return;
        }
        const off: u32 = @intCast(self.out_used);
        @memcpy(self.out_buf[self.out_used..][0..bytes.len], bytes);
        self.out_used += bytes.len;
        self.out_frames.append(self.gpa, .{
            .node = node,
            .time = t,
            .off = off,
            .len = @intCast(bytes.len),
        }) catch {
            self.out_used = off;
            self.noteCapacity(t, node);
            self.freeSlot(slot);
            return;
        };
        e.stats.emitted += 1;
        self.record(t, node, .emitted, bytes);
        self.freeSlot(slot);
    }

    fn noteCapacity(self: *Fleet, t: Time, node: NodeId) void {
        self.capacity_losses += 1;
        self.record(t, node, .capacity_exhausted, &.{});
    }

    // ── slot pool ───────────────────────────────────────────────────────────

    fn takeSlot(self: *Fleet, bytes: []const u8) ?u32 {
        if (bytes.len > self.opts.max_frame_len) return null;
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const slot = self.free_slots[self.free_count];
        const base = @as(usize, slot) * self.opts.max_frame_len;
        @memcpy(self.slot_bytes[base..][0..bytes.len], bytes);
        self.slot_len[slot] = @intCast(bytes.len);
        self.slot_delayed[slot] = false;
        return slot;
    }

    fn slotBytes(self: *const Fleet, slot: u32) []const u8 {
        const base = @as(usize, slot) * self.opts.max_frame_len;
        return self.slot_bytes[base..][0..self.slot_len[slot]];
    }

    fn freeSlot(self: *Fleet, slot: u32) void {
        self.free_slots[self.free_count] = slot;
        self.free_count += 1;
    }

    // ── the heap ────────────────────────────────────────────────────────────

    fn push(self: *Fleet, at: Time, kind: EventKind) Allocator.Error!void {
        const ev = Event{ .time = at, .seq = self.seq, .kind = kind };
        self.seq += 1;
        try self.heap.append(self.gpa, ev);
        var i = self.heap.items.len - 1;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (!Event.before(self.heap.items[i], self.heap.items[parent])) break;
            std.mem.swap(Event, &self.heap.items[i], &self.heap.items[parent]);
            i = parent;
        }
    }

    fn pop(self: *Fleet) ?Event {
        if (self.heap.items.len == 0) return null;
        const top = self.heap.items[0];
        const last = self.heap.pop().?;
        if (self.heap.items.len == 0) return top;
        self.heap.items[0] = last;
        var i: usize = 0;
        while (true) {
            const l = 2 * i + 1;
            const r = l + 1;
            var best = i;
            if (l < self.heap.items.len and Event.before(self.heap.items[l], self.heap.items[best])) best = l;
            if (r < self.heap.items.len and Event.before(self.heap.items[r], self.heap.items[best])) best = r;
            if (best == i) break;
            std.mem.swap(Event, &self.heap.items[i], &self.heap.items[best]);
            i = best;
        }
        return top;
    }

    // ── the trace ───────────────────────────────────────────────────────────

    fn record(self: *Fleet, t: Time, node: NodeId, kind: TraceKind, bytes: []const u8) void {
        // The fingerprint covers every entry ever produced, including the
        // payload, whether or not the ring kept it. That is what makes "same
        // seed, same trace" checkable on a 1000-node run whose full trace would
        // never fit in memory.
        self.mix(t);
        self.mix(node);
        self.mix(@intFromEnum(kind));
        self.mix(bytes.len);
        for (bytes) |b| self.mix(b);

        if (self.trace_ring.len == 0) return;
        var off: u32 = 0;
        var len: u32 = 0;
        if (self.opts.record_frames and bytes.len != 0 and
            self.trace_used + bytes.len <= self.trace_buf.len)
        {
            off = @intCast(self.trace_used);
            len = @intCast(bytes.len);
            @memcpy(self.trace_buf[self.trace_used..][0..bytes.len], bytes);
            self.trace_used += bytes.len;
        }
        const idx = (self.trace_head + self.trace_count) % self.trace_ring.len;
        if (self.trace_count == self.trace_ring.len) {
            self.trace_head = (self.trace_head + 1) % self.trace_ring.len;
        } else {
            self.trace_count += 1;
        }
        self.trace_ring[idx] = .{ .time = t, .node = node, .kind = kind, .off = off, .len = len };
        self.trace_total += 1;
    }

    fn mix(self: *Fleet, v: anytype) void {
        var x: u64 = @intCast(v);
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            self.fingerprint ^= x & 0xFF;
            self.fingerprint *%= 0x100000001b3;
            x >>= 8;
        }
    }

    /// Trace entries still in the ring, oldest first. `out` must hold
    /// `traceLen()` entries.
    pub fn traceInto(self: *const Fleet, out: []TraceEntry) []TraceEntry {
        const n = @min(out.len, self.trace_count);
        for (0..n) |i| out[i] = self.trace_ring[(self.trace_head + i) % self.trace_ring.len];
        return out[0..n];
    }

    pub fn traceLen(self: *const Fleet) usize {
        return self.trace_count;
    }

    pub fn traceBytes(self: *const Fleet, e: TraceEntry) []const u8 {
        return self.trace_buf[e.off..][0..e.len];
    }
};

// ── PRNG helpers (the ONLY randomness in the module) ────────────────────────

fn permille(rand: std.Random, rate: u16) bool {
    if (rate == 0) return false;
    if (rate >= 1000) return true;
    return rand.uintLessThan(u16, 1000) < rate;
}

fn jitter(rand: std.Random, span: Time) Time {
    if (span == 0) return 0;
    return rand.uintAtMost(u64, span);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A minimal echo responder with a 4-byte length-prefixed framing of its own,
/// so the scheduler can be tested without dragging a real protocol in.
const Echo = struct {
    replies: usize = 0,
    ticks: usize = 0,
    tick_payload: ?[]const u8 = null,
    fail: bool = false,
    restarts: usize = 0,
    trouble: bool = false,

    fn node(self: *Echo) Node {
        return .{
            .ctx = self,
            .protocol = .custom,
            .framing = .opaque_whole,
            .vtable = &.{
                .deliver = deliverFn,
                .tick = tickFn,
                .control = controlFn,
            },
        };
    }

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) node_mod.NodeError!?[]const u8 {
        _ = now_ms;
        const self: *Echo = @ptrCast(@alignCast(ctx));
        if (self.fail) return error.ResponderFailed;
        if (bytes.len > out.len) return error.OutputTooSmall;
        @memcpy(out[0..bytes.len], bytes);
        self.replies += 1;
        return out[0..bytes.len];
    }

    fn tickFn(ctx: *anyopaque, out: []u8, now_ms: Time) node_mod.NodeError!?[]const u8 {
        _ = now_ms;
        const self: *Echo = @ptrCast(@alignCast(ctx));
        self.ticks += 1;
        const p = self.tick_payload orelse return null;
        if (p.len > out.len) return error.OutputTooSmall;
        @memcpy(out[0..p.len], p);
        return out[0..p.len];
    }

    fn controlFn(ctx: *anyopaque, op: node_mod.Control, now_ms: Time) bool {
        _ = now_ms;
        const self: *Echo = @ptrCast(@alignCast(ctx));
        switch (op) {
            .restart => self.restarts += 1,
            .trouble_on => self.trouble = true,
            .trouble_off => self.trouble = false,
        }
        return true;
    }
};

test "scheduler: a submitted frame comes back out after the link delay" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node(), .link = .{ .delay_ms = 10 } });

    try fleet.submit(id, "hello", 0);
    _ = try fleet.advance(5);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len); // still in flight

    _ = try fleet.advance(30);
    try testing.expectEqual(@as(usize, 1), fleet.outbound().len);
    const f = fleet.outbound()[0];
    try testing.expectEqualSlices(u8, "hello", fleet.frameBytes(f));
    try testing.expectEqual(@as(Time, 20), f.time); // 10 in + 10 out
}

test "scheduler: outbound is cleared per advance, not accumulated" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node() });
    try fleet.submit(id, "a", 0);
    _ = try fleet.advance(10);
    try testing.expectEqual(@as(usize, 1), fleet.outbound().len);
    _ = try fleet.advance(20);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len);
}

test "faults: silent, slow, restart and heal are all clock-driven" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node() });

    try fleet.addFault(.{ .at_ms = 100, .node = id, .kind = .{ .silent = .{ .until_ms = 200 } } });
    try fleet.addFault(.{ .at_ms = 300, .node = id, .kind = .{ .slow = .{ .extra_ms = 50, .until_ms = 400 } } });
    try fleet.addFault(.{ .at_ms = 500, .node = id, .kind = .restart });

    try fleet.submit(id, "a", 0);
    _ = try fleet.advance(50);
    try testing.expectEqual(@as(usize, 1), fleet.outbound().len);

    try fleet.submit(id, "b", 150); // inside the silent window
    _ = try fleet.advance(250);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len);
    try testing.expectEqual(@as(u64, 1), fleet.stats(id).silent_drops);

    try fleet.submit(id, "c", 310); // inside the slow window
    _ = try fleet.advance(340);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len); // still late
    _ = try fleet.advance(380);
    try testing.expectEqual(@as(usize, 1), fleet.outbound().len);

    _ = try fleet.advance(600);
    try testing.expectEqual(@as(usize, 1), echo.restarts);
}

test "faults: one-shot drop / dup / delay behave exactly once" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node() });

    try fleet.addFault(.{ .at_ms = 0, .node = id, .kind = .{ .drop_next = .{ .count = 1 } } });
    try fleet.addFault(.{ .at_ms = 0, .node = id, .kind = .{ .dup_next = .{ .count = 1 } } });
    _ = try fleet.advance(1);

    try fleet.submit(id, "x", 1); // dropped
    _ = try fleet.advance(10);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len);

    try fleet.submit(id, "y", 10); // duplicated
    _ = try fleet.advance(20);
    try testing.expectEqual(@as(usize, 2), fleet.outbound().len);

    try fleet.submit(id, "z", 20); // ordinary
    _ = try fleet.advance(30);
    try testing.expectEqual(@as(usize, 1), fleet.outbound().len);
}

test "faults: an explicit delay_next pre-empts the random reorder check, not both" {
    // `submit`'s inbound path checks delay_next first and only falls back to
    // the random reorder roll `else if` it did not fire — an explicit
    // scheduled delay is what "this frame is delayed" already means, so a
    // reorder roll on top would double-count the same event. Set
    // reorder_permille so high (1000 == always) that a version which checks
    // both independently (dropping the "else") stacks reorder_extra_ms on
    // top of delay_next's extra_ms; the exact `.delivered` timestamp is the
    // only way to tell the two apart, since either way *something* is
    // delayed.
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node(), .link = .{
        .reorder_permille = 1000,
        .reorder_extra_ms = 500,
    } });
    try fleet.addFault(.{ .at_ms = 0, .node = id, .kind = .{ .delay_next = .{ .count = 1, .extra_ms = 7 } } });
    _ = try fleet.advance(1);

    try fleet.submit(id, "x", 1);
    _ = try fleet.advance(8); // 1 (submit time) + 7 (delay_next only)

    var buf: [16]TraceEntry = undefined;
    const trace = fleet.traceInto(&buf);
    var delivered_at: ?Time = null;
    for (trace) |e| {
        if (e.kind == .delivered) delivered_at = e.time;
    }
    try testing.expectEqual(@as(?Time, 8), delivered_at);
}

test "faults: an explicit dup_next pre-empts the random dup roll, not both" {
    // Same shape as the delay_next case above, for the dup_next/dup_permille
    // pair. `link.dup_permille` governs BOTH directions independently (the
    // echoed reply gets its own roll going back out), and `stats.duplicated`
    // is shared by both, so neither is a clean signal here. `.duplicated_in`
    // trace entries are recorded only on the inbound path this check lives
    // in: exactly one submitted frame duplicated via `dup_next` alone must
    // produce exactly one such entry. A version that checks `dup_next` and
    // the guaranteed (permille = 1000) random roll independently (dropping
    // the "else") would record it twice — once per branch — even though the
    // frame is still only duplicated into 2 copies either way (`copies = 2`
    // is idempotent), which is why `.delivered`/`outbound()` counts alone
    // can't tell the two apart.
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node(), .link = .{ .dup_permille = 1000 } });
    try fleet.addFault(.{ .at_ms = 0, .node = id, .kind = .{ .dup_next = .{ .count = 1 } } });
    _ = try fleet.advance(1);

    try fleet.submit(id, "x", 1);
    _ = try fleet.advance(10);

    try testing.expectEqual(@as(u64, 2), fleet.stats(id).delivered); // really duplicated

    var buf: [16]TraceEntry = undefined;
    const trace = fleet.traceInto(&buf);
    var duplicated_in_count: usize = 0;
    for (trace) |e| {
        if (e.kind == .duplicated_in) duplicated_in_count += 1;
    }
    try testing.expectEqual(@as(usize, 1), duplicated_in_count);
}

test "faults: trouble is reported unsupported when the protocol has no word for it" {
    const Mute = struct {
        fn deliverFn(_: *anyopaque, _: []const u8, _: []u8, _: Time) node_mod.NodeError!?[]const u8 {
            return null;
        }
    };
    var dummy: u8 = 0;
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = .{
        .ctx = &dummy,
        .vtable = &.{ .deliver = Mute.deliverFn },
    } });
    try fleet.addFault(.{ .at_ms = 5, .node = id, .kind = .{ .trouble = .{ .on = true } } });
    _ = try fleet.advance(10);

    var buf: [16]TraceEntry = undefined;
    const trace = fleet.traceInto(&buf);
    var saw = false;
    for (trace) |e| {
        if (e.kind == .control_unsupported) saw = true;
    }
    try testing.expect(saw);
}

test "hostile: an unknown node and an over-long frame are typed errors" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{ .max_frame_len = 8 });
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node() });
    try testing.expectError(error.UnknownNode, fleet.submit(id + 1, "x", 0));
    try testing.expectError(error.UnknownNode, fleet.submit(99, "x", 0));
    try testing.expectError(error.FrameTooLarge, fleet.submit(id, "123456789", 0));
}

test "hostile: a responder that errors is counted, not propagated" {
    var echo = Echo{ .fail = true };
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node() });
    try fleet.submit(id, "x", 0);
    _ = try fleet.advance(10);
    try testing.expectEqual(@as(u64, 1), fleet.stats(id).responder_errors);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len);
}

test "hostile: a tick that overflows the frame buffer is logged, not a stomp" {
    const big = [_]u8{0xAA} ** 64;
    var echo = Echo{ .tick_payload = &big };
    var fleet = try Fleet.init(testing.allocator, .{ .max_frame_len = 16 });
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node(), .tick_period_ms = 100 });
    _ = try fleet.advance(250);
    try testing.expect(fleet.stats(id).responder_errors >= 2);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len);

    var buf: [64]TraceEntry = undefined;
    var saw = false;
    for (fleet.traceInto(&buf)) |e| {
        if (e.kind == .output_overflow) saw = true;
    }
    try testing.expect(saw);
}

test "hostile: exhausting the in-flight pool loses frames but never corrupts" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{ .inflight_capacity = 4, .max_frame_len = 16 });
    defer fleet.deinit();
    const id = try fleet.addNode(.{ .node = echo.node(), .link = .{ .delay_ms = 100 } });
    for (0..20) |i| try fleet.submit(id, "x", @intCast(i));
    try testing.expect(fleet.capacity_losses > 0);
    _ = try fleet.advance(1000);
    try testing.expectEqual(@as(usize, 4), fleet.outbound().len);
    // Every slot came back to the pool.
    try testing.expectEqual(@as(usize, 4), fleet.free_count);
}

test "determinism: same seed = identical fingerprint; different seed diverges" {
    const run = struct {
        fn go(seed: u64) !u64 {
            var echo = Echo{};
            var fleet = try Fleet.init(testing.allocator, .{
                .seed = seed,
                .max_frame_len = 32,
            });
            defer fleet.deinit();
            const id = try fleet.addNode(.{ .node = echo.node(), .link = .{
                .delay_ms = 5,
                .jitter_ms = 7,
                .loss_permille = 100,
                .dup_permille = 100,
                .reorder_permille = 100,
            } });
            var t: Time = 0;
            while (t < 2000) : (t += 10) {
                try fleet.submit(id, "poll", t);
                _ = try fleet.advance(t);
            }
            _ = try fleet.advance(5000);
            return fleet.fingerprint;
        }
    };
    const a = try run.go(1234);
    const b = try run.go(1234);
    const c = try run.go(4321);
    try testing.expectEqual(a, b);
    try testing.expect(a != c);
}

test "signals fire on their own schedule and land in every sink" {
    var reg: u16 = 0;
    var s_reg = drivers.ScaledRegister{ .cell = &reg };
    const sinks = [_]drivers.Sink{s_reg.sink()};
    var sig = Signal{
        .driver = .{ .ramp = .{ .start = 0, .per_ms = 1, .max = 1000 } },
        .sinks = &sinks,
        .period_ms = 100,
    };
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    try fleet.addSignal(&sig);
    _ = try fleet.advance(1000);
    try testing.expectEqual(@as(u64, 11), sig.fires); // t = 0,100,…,1000
    try testing.expectEqual(@as(u16, 1000), reg);
}

test "netsim trace maps onto fleet faults and reports what it cannot map" {
    var echo = Echo{};
    var fleet = try Fleet.init(testing.allocator, .{});
    defer fleet.deinit();
    _ = try fleet.addNode(.{ .node = echo.node() });
    _ = try fleet.addNode(.{ .node = echo.node() });

    const events = [_]netsim.FaultEvent{
        .{ .time = 10, .kind = .{ .crash_node = .{ .node = 1 } } },
        .{ .time = 20, .kind = .{ .restart_node = .{ .node = 1 } } },
        .{ .time = 30, .kind = .{ .drop_once = .{ .a = 0, .b = 1 } } },
        .{ .time = 40, .kind = .{ .clock_jump = .{ .node = 0, .delta = 5 } } },
    };
    const unmapped = try fleet.applyNetsimTrace(&events);
    try testing.expectEqual(@as(usize, 1), unmapped); // clock_jump has no fleet meaning
    try testing.expectEqual(@as(usize, 4), fleet.faults.items.len);

    try fleet.submit(1, "a", 15);
    _ = try fleet.advance(18);
    try testing.expectEqual(@as(usize, 0), fleet.outbound().len); // crashed
    _ = try fleet.advance(25);
    try testing.expectEqual(@as(usize, 1), echo.restarts);
}
