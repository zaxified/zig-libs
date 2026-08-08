// SPDX-License-Identifier: MIT

//! The fleet as a `netsim` **protocol** — model-checking a device fleet instead
//! of replaying fault schedules written by hand.
//!
//! `Fleet.applyNetsimTrace` already borrows netsim's *schedule fuzzer*: it
//! translates a generated `FaultTrace` into fleet faults and executes it. What
//! it cannot give you is a **search**. Nothing there decides whether a run was
//! good, so nothing can look for a seed that breaks one, and `shrinkTrace` has
//! no oracle to minimise against — a failure could only ever come back as a
//! seed. This file closes that gap: it plugs a `Fleet` into netsim's engine as
//! a `Protocol`, so `run` / `replay` / `findFailing` / `shrinkTrace` work on a
//! fleet exactly as they already do on `raft` or `df-elect`.
//!
//! **The mapping.** A fleet is a star, which is what the SPEC's threat-model
//! section says and what `applyNetsimTrace` assumes. So netsim node 0 is the
//! master (the SCADA poller) and netsim nodes `1..N` are the devices, each with
//! one bidirectional link to the master:
//!
//!   - **netsim owns the network** — link latency and the entire adversary:
//!     drop / duplicate / delay-spike / link down+up / partition+heal /
//!     crash+restart.
//!   - **fleetsim owns the devices** — framing, the seven responders, point
//!     behaviour, the in-flight slot pool, the total event order.
//!
//! The fleet's own link-fault knobs are therefore deliberately left at zero
//! here. Modelling loss at both layers would make a minimised trace a lie: half
//! of what perturbed the run would not be in the trace that is handed back, so
//! replaying it would not reproduce the failure and ddmin would shrink against
//! noise. One adversary, one trace, one reproducer.
//!
//! **The shape follows netsim's existing consumers**, not a second convention:
//! a small vtable over an opaque ctx (`onStart` / `onMessage` / `onTimer` /
//! `check` / `reset`), every scrap of per-node state inside the ctx, and a
//! `resetFn` that returns the ctx to its t=0 baseline — netsim's shrinker
//! re-runs one ctx thousands of times, so a harness that cannot reset is a
//! harness whose counterexamples do not replay. Since a `Fleet`'s state is its
//! whole existence (queue, pools, trace, per-node stats, responder snapshots),
//! `reset` rebuilds it from scratch.
//!
//! **The step function.** `onTimer` on the master is the poll loop: it drains
//! the fleet up to netsim's clock, then sends one request per device. The one
//! and only place the fleet is driven is `onMessage`: a request arriving at a
//! device becomes `Fleet.submit` + `Fleet.advance(sim.timeNow())`, and every
//! frame in `Fleet.outbound()` is handed straight back to netsim as a message
//! from that device to the master. netsim's clock is the authority; the fleet's
//! queue is drained up to it and never past it.
//!
//! **The invariants** are all checked at the master, on the bytes it actually
//! received, and every one of them is immune to the adversary by construction:
//! netsim can lose, duplicate, delay and reorder whole payloads, but it cannot
//! author one. So none of these can fire because a fault fired.
//!
//!   1. `MalformedReply` — a reply is not exactly one complete frame of the
//!      sending device's own `Framing`. (The fleet ships a responder's
//!      undescribable output whole, as `bad_framing`, rather than swallowing
//!      it — so a framing bug reaches the master rather than dying quietly.)
//!   2. `UnitIdMismatch` — a reply does not carry the unit id of the device it
//!      arrived from. This is the cross-routing check: the reply of one device
//!      must never surface as another's.
//!   3. `UnknownTransaction` — a reply echoes a transaction id this master
//!      never issued *to that device*.
//!   4. `ValueOutOfRange` — a register in a reply is outside the band its
//!      `Signal`'s driver can produce.
//!   5. `SlotLeak` — fleet-internal conservation: every in-flight slot is
//!      either free or held by exactly one pending `deliver`/`emit` event, so
//!      `held + free == inflight_capacity` at every instant. The fuzz harness
//!      in `root.zig` asserts the same thing once, after its queue drains; here
//!      it is checked after every single event, under an adversary. Because
//!      the fleet's own link delays are zero here, `held` is in practice always
//!      zero — a submit and its reply both resolve inside the same `advance` —
//!      so the check reduces to "the pool is whole between netsim events".
//!      The `held` term is kept because it is what makes the statement true by
//!      construction rather than true by this configuration: a caller that
//!      gives the fleet a nonzero link delay, or a `slow` fault that
//!      reschedules a delivery, leaves a slot legitimately outstanding.
//!
//! Note what is deliberately **not** an invariant: liveness. An adversary that
//! may cut a link and never heal it, or crash the master and never restart it,
//! can starve any device of any reply. "Every poll is answered" would be a
//! false invariant and would report the adversary as a bug.
//!
//! Two netsim facilities have no meaning on this side of the seam and are
//! honestly no-ops rather than fake couplings: `clock_jump` (a fleet has one
//! clock by construction — the same reason `applyNetsimTrace` reports it as
//! unmapped), and `restart_node` on a device (a netsim node restart re-runs
//! `onStart`, but a device here is purely reactive; power-cycling a *responder*
//! is `Fleet`'s own `Control.restart`, which is a different event).
//!
//! `BrokenDevice` is the positive control this file must ship — netsim's README
//! is explicit that a consumer without a deliberately-broken twin is a harness
//! whose teeth were never checked (see `netsim`'s own `LoopyForward` and
//! `raft`'s `BrokenRaft`). Every one of its four bugs is gated on seeing the
//! same transaction id twice, which **only a duplicated request can cause** —
//! so each one is provably unreachable without the adversary, which is what
//! makes "`findFailing` found it" mean something.

const std = @import("std");
const Allocator = std.mem.Allocator;

const netsim = @import("netsim");
const modbus = @import("modbus");

const node_mod = @import("node.zig");
const fleet_mod = @import("fleet.zig");
const adapters_mod = @import("adapters.zig");
const drivers_mod = @import("drivers.zig");

const Fleet = fleet_mod.Fleet;
const Framing = node_mod.Framing;
const Node = node_mod.Node;
const NodeError = node_mod.NodeError;
const Time = node_mod.Time;
const ScaledRegister = drivers_mod.ScaledRegister;
const Signal = drivers_mod.Signal;
const Sink = drivers_mod.Sink;

/// The invariant violations the harness can report. Each is a genuine
/// contradiction of something the fleet promises, never a restatement of a
/// fault that was injected.
pub const Violation = error{
    MalformedReply,
    UnitIdMismatch,
    UnknownTransaction,
    ValueOutOfRange,
    SlotLeak,
    /// `netsim`'s `resetFn` cannot fail, but rebuilding a `Fleet` allocates.
    /// The failure is latched and reported from `check` rather than silently
    /// running the next replay against a dead fleet.
    FleetRebuildFailed,
};

/// Which deliberate defect a `BrokenDevice` carries. Every one of them behaves
/// correctly until the same transaction id arrives twice.
pub const Bug = enum {
    /// None — a hand-rolled but correct device (used to prove the toy itself is
    /// not what the invariants are catching).
    none,
    /// The MBAP length field double-counts a retransmission, so the frame the
    /// device emits is longer than it says it is. Trips `MalformedReply`.
    length_counts_retransmit,
    /// The reply is built from a scratch header whose unit id was never
    /// refreshed. Trips `UnitIdMismatch`.
    stale_unit_id,
    /// The transaction id is taken from an internal counter rather than echoed
    /// from the request. Trips `UnknownTransaction`.
    invented_transaction,
    /// The register buffer is not re-read on a retransmission and comes back as
    /// the uninitialised sentinel. Trips `ValueOutOfRange`.
    stale_register_buffer,
};

// ── fixed harness geometry ──────────────────────────────────────────────────
//
// netsim's `Scenario` is a bare `fn (*Sim)` with no ctx (see `sim.zig`), so the
// topology's dimensions are constants here exactly as `FLOOD_N` / `LOOPY_N` are
// constants in netsim's own consumers.

/// netsim node id of the master. Devices are `1 + fleet node id`.
pub const master: netsim.NodeId = 0;

/// One-way link latency, in netsim ticks (= fleet milliseconds).
pub const link_latency: netsim.Time = 4;

/// How often the master polls every device.
pub const poll_period: netsim.Time = 20;

/// Holding registers per device, and how many of them a poll reads.
pub const registers: usize = 8;
pub const read_count: u16 = 4;

/// The sine the `Signal` drives every register with: every value a correct
/// device can ever report lies in `[mean - amplitude, mean + amplitude]`.
const sine_mean: f64 = 500;
const sine_amplitude: f64 = 200;
const sine_period_ms: Time = 800;
const sample_period_ms: Time = 50;
/// The band, widened by one count so float rounding is never the finding.
const value_lo: u16 = 299;
const value_hi: u16 = 701;

pub const Options = struct {
    /// The `Fleet`'s own seed. Independent of the netsim seed, which drives the
    /// network and the fault schedule.
    fleet_seed: u64 = 0,
    /// Ship the deliberately-broken device instead of the real `ModbusNode`.
    bug: Bug = .none,
    /// Use the hand-rolled toy device rather than `adapters.Modbus`. Implied by
    /// any `bug` other than `.none`.
    toy: bool = false,
};

/// A fleet of `device_count` Modbus devices polled by one master, wired up as a
/// netsim `Protocol`.
pub fn Vopr(comptime device_count: usize) type {
    std.debug.assert(device_count >= 1);
    return struct {
        const Self = @This();

        gpa: Allocator,
        opts: Options,

        fleet: Fleet = undefined,
        fleet_live: bool = false,
        rebuild_err: ?anyerror = null,

        // Device storage. Held by value in the ctx so every pointer a `Node`
        // vtable closes over stays valid for the life of the harness — the
        // shrinker re-enters this ctx thousands of times.
        real: [device_count]adapters_mod.Modbus = undefined,
        toy: [device_count]BrokenDevice = undefined,
        holdings: [device_count][registers]u16 = undefined,
        regs: [device_count]ScaledRegister = undefined,
        sinks: [device_count][1]Sink = undefined,
        signals: [device_count]Signal = undefined,

        // Master-side bookkeeping.
        /// Highest transaction id issued to each device. Ids are dense and
        /// monotonic per device, so "was issued" is "in `1..issued`".
        issued: [device_count]u16 = @splat(0),
        replies: [device_count]u32 = @splat(0),
        polls: u32 = 0,
        /// Generation of the master's poll-timer chain. A crash swallows the
        /// pending timer; a restart re-runs `onStart`, which starts a new chain
        /// — the generation makes any stale one a no-op instead of doubling the
        /// poll rate.
        gen: u64 = 0,
        violation: ?anyerror = null,

        pub fn init(gpa: Allocator, opts: Options) Self {
            return .{ .gpa = gpa, .opts = opts };
        }

        pub fn deinit(self: *Self) void {
            if (self.fleet_live) self.fleet.deinit();
            self.fleet_live = false;
            self.* = undefined;
        }

        pub fn protocol(self: *Self) netsim.Protocol {
            return .{
                .ctx = self,
                .onStartFn = onStart,
                .onMessageFn = onMessage,
                .onTimerFn = onTimer,
                .checkFn = check,
                .resetFn = reset,
            };
        }

        /// A `netsim.Case` over this harness. `seed` and `until` are netsim's.
        pub fn case(self: *Self, seed: u64, until: netsim.Time) netsim.Case {
            return .{
                .seed = seed,
                .scenario = scenario,
                .protocol = self.protocol(),
                .until = until,
            };
        }

        /// The star: one master, `device_count` devices, one bidirectional link
        /// each. Deterministic and unseeded, as `Scenario` requires.
        pub fn scenario(sim: *netsim.Sim) anyerror!void {
            _ = try sim.addNode(.{}); // the master
            for (0..device_count) |_| _ = try sim.addNode(.{});
            for (0..device_count) |i| {
                try sim.addBiLink(master, devNode(i), .{ .latency = link_latency });
            }
        }

        pub fn devNode(dev: usize) netsim.NodeId {
            return @intCast(dev + 1);
        }

        pub fn unitOf(dev: usize) u8 {
            return @intCast(1 + dev);
        }

        fn cast(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        // ── the netsim protocol vtable ───────────────────────────────────────

        fn reset(ctx: *anyopaque) void {
            const self = cast(ctx);
            self.rebuild() catch |e| {
                self.rebuild_err = e;
                return;
            };
            self.rebuild_err = null;
        }

        fn onStart(ctx: *anyopaque, sim: *netsim.Sim, n: netsim.NodeId) anyerror!void {
            const self = cast(ctx);
            if (n != master) return; // a device is purely reactive
            self.gen += 1;
            try sim.setTimer(master, 0, self.gen);
        }

        fn onTimer(ctx: *anyopaque, sim: *netsim.Sim, n: netsim.NodeId, timer_id: u64) anyerror!void {
            const self = cast(ctx);
            if (n != master or timer_id != self.gen) return; // stale chain
            if (self.rebuild_err != null) return;

            // Let the fleet's own clock catch up even on a silent tick: ticks,
            // signals and any frame the fleet delayed itself are due on time.
            try self.pump(sim);

            var buf: [12]u8 = undefined;
            for (0..device_count) |i| {
                self.issued[i] += 1;
                const req = try encodeRead(&buf, self.issued[i], unitOf(i), 0, read_count);
                try sim.send(master, devNode(i), req);
            }
            self.polls += 1;
            try sim.setTimer(master, poll_period, self.gen);
        }

        fn onMessage(
            ctx: *anyopaque,
            sim: *netsim.Sim,
            n: netsim.NodeId,
            from: netsim.NodeId,
            payload: []const u8,
        ) anyerror!void {
            const self = cast(ctx);
            if (self.rebuild_err != null) return;
            if (n == master) {
                self.onReply(from, payload);
                return;
            }
            // A request has reached a device: the fleet is the device side.
            try self.fleet.submit(@intCast(n - 1), payload, sim.timeNow());
            try self.pump(sim);
        }

        /// Drain the fleet up to netsim's clock and put whatever it wants
        /// transmitted back onto the network as a message to the master.
        fn pump(self: *Self, sim: *netsim.Sim) anyerror!void {
            const now = sim.timeNow();
            _ = try self.fleet.advance(now);
            for (self.fleet.outbound()) |o| {
                try sim.send(devNode(o.node), master, self.fleet.frameBytes(o));
            }
        }

        fn check(ctx: *anyopaque, sim: *const netsim.Sim) anyerror!void {
            _ = sim;
            const self = cast(ctx);
            if (self.rebuild_err != null) return Violation.FleetRebuildFailed;
            if (self.violation) |e| return e;
            if (!self.fleet_live) return Violation.FleetRebuildFailed;
            // Slot conservation, at every instant rather than once at the end.
            if (slotsHeld(&self.fleet) + self.fleet.free_count != self.fleet.opts.inflight_capacity)
                return Violation.SlotLeak;
        }

        // ── the master's oracle ──────────────────────────────────────────────

        fn onReply(self: *Self, from: netsim.NodeId, payload: []const u8) void {
            if (self.violation != null) return;
            if (from == master or from > device_count) {
                // netsim cannot deliver from a node that is not on a link to
                // the master, so this is unreachable rather than adversarial.
                // No test observes this assignment and none can: `scenario`
                // builds only master↔device bi-links, and `pump` sends with
                // `devNode(o.node)` for a fleet id in `0..device_count-1`.
                // It is defence against a future topology change, not an
                // invariant with teeth — verified by deleting it and watching
                // the suite stay green.
                self.violation = Violation.UnitIdMismatch;
                return;
            }
            const dev: usize = from - 1;
            self.replies[dev] += 1;

            // 1. exactly one complete frame of this device's own framing.
            const n = Framing.modbus_tcp.frameLen(payload) catch {
                self.violation = Violation.MalformedReply;
                return;
            } orelse {
                self.violation = Violation.MalformedReply;
                return;
            };
            if (n != payload.len or payload.len < 9) {
                self.violation = Violation.MalformedReply;
                return;
            }

            // 2. the unit id of the device it actually came from.
            if (payload[6] != unitOf(dev)) {
                self.violation = Violation.UnitIdMismatch;
                return;
            }

            // 3. a transaction id this master issued to THIS device.
            const txid = std.mem.readInt(u16, payload[0..2], .big);
            if (txid == 0 or txid > self.issued[dev]) {
                self.violation = Violation.UnknownTransaction;
                return;
            }

            // 4. the values are inside the band the driver can produce.
            const fc = payload[7];
            if (fc == 0x83) return; // a legitimate Modbus exception reply
            if (fc != 0x03) {
                self.violation = Violation.MalformedReply;
                return;
            }
            const byte_count = payload[8];
            if (byte_count != read_count * 2 or payload.len != 9 + @as(usize, byte_count)) {
                self.violation = Violation.MalformedReply;
                return;
            }
            for (0..read_count) |k| {
                const v = std.mem.readInt(u16, payload[9 + 2 * k ..][0..2], .big);
                if (v < value_lo or v > value_hi) {
                    self.violation = Violation.ValueOutOfRange;
                    return;
                }
            }
        }

        // ── (re)building the fleet ───────────────────────────────────────────

        fn rebuild(self: *Self) !void {
            if (self.fleet_live) {
                self.fleet.deinit();
                self.fleet_live = false;
            }
            self.fleet = try Fleet.init(self.gpa, .{
                .seed = self.opts.fleet_seed,
                .max_frame_len = 260,
                .inflight_capacity = 64,
                .trace_capacity = 2048,
                .trace_bytes = 4096,
                .outbox_bytes = 16 * 1024,
                // The shrinker re-runs this thousands of times; trace KINDS are
                // what the tests read, and the payload copies are not free.
                .record_frames = false,
            });
            self.fleet_live = true;

            const toy = self.opts.toy or self.opts.bug != .none;
            for (0..device_count) |i| {
                self.holdings[i] = @splat(@intFromFloat(sine_mean));
                self.regs[i] = .{ .cell = &self.holdings[i][0], .scale = 1 };
                self.sinks[i] = .{self.regs[i].sink()};
                self.signals[i] = .{
                    .driver = .{ .sine = .{
                        .mean = sine_mean,
                        .amplitude = sine_amplitude,
                        .period_ms = sine_period_ms,
                        .phase_ms = @intCast(i * 100),
                    } },
                    .sinks = &self.sinks[i],
                    .period_ms = sample_period_ms,
                };

                const dev_node = if (toy) blk: {
                    self.toy[i] = BrokenDevice.init(unitOf(i), &self.holdings[i], self.opts.bug);
                    break :blk self.toy[i].node();
                } else blk: {
                    self.real[i] = adapters_mod.Modbus.init(
                        .{ .unit_id = unitOf(i), .framing = .tcp },
                        .{ .holding_registers = .{ .base = 0, .values = &self.holdings[i] } },
                    );
                    break :blk self.real[i].node();
                };
                const id = try self.fleet.addNode(.{ .node = dev_node, .tag = i });
                std.debug.assert(id == i);
                try self.fleet.addSignal(&self.signals[i]);
            }

            self.issued = @splat(0);
            self.replies = @splat(0);
            self.polls = 0;
            self.gen = 0;
            self.violation = null;
        }

        /// Total replies the master accepted, across every device.
        pub fn totalReplies(self: *const Self) u32 {
            var n: u32 = 0;
            for (self.replies) |r| n += r;
            return n;
        }

        /// How many trace entries of `kind` the current fleet recorded.
        pub fn traceCount(self: *Self, kind: fleet_mod.TraceKind) !usize {
            const buf = try self.gpa.alloc(fleet_mod.TraceEntry, self.fleet.traceLen());
            defer self.gpa.free(buf);
            var n: usize = 0;
            for (self.fleet.traceInto(buf)) |e| {
                if (e.kind == kind) n += 1;
            }
            return n;
        }
    };
}

/// Slots currently held by a pending event. Every in-flight slot is owned by
/// exactly one `deliver` or `emit` event until it is handed back, so this plus
/// `free_count` must always be the whole pool.
fn slotsHeld(f: *const Fleet) usize {
    var held: usize = 0;
    for (f.heap.items) |ev| {
        switch (ev.kind) {
            .deliver, .emit => held += 1,
            else => {},
        }
    }
    return held;
}

/// Encode a Modbus-TCP `read holding registers` request through the `modbus`
/// module's own encoder, so the master speaks the same dialect the device does.
fn encodeRead(buf: []u8, txid: u16, unit: u8, addr: u16, count: u16) ![]const u8 {
    var pdu: [5]u8 = undefined;
    pdu[0] = 0x03;
    std.mem.writeInt(u16, pdu[1..3], addr, .big);
    std.mem.writeInt(u16, pdu[3..5], count, .big);
    return modbus.tcp.encodeAdu(buf, txid, unit, &pdu);
}

// ── the positive control ────────────────────────────────────────────────────

/// A hand-rolled Modbus-TCP device, correct by default and deliberately broken
/// on demand. Its whole purpose is to prove the invariants above have teeth.
///
/// Every bug is gated on `repeat` — the same transaction id arriving twice.
/// The master issues each id exactly once, so a repeat can only come from the
/// network duplicating a request, which only netsim's adversary can do. That
/// gating is the point: it makes each bug provably unreachable on a clean run,
/// so `findFailing` reporting one is evidence the search explored faults rather
/// than evidence the device was broken from the start.
pub const BrokenDevice = struct {
    unit: u8,
    values: []u16,
    bug: Bug,
    /// Scratch header state — the thing real firmware gets wrong.
    last_txid: u16 = 0,
    seen: bool = false,
    counter: u16 = 0,

    const sentinel: u16 = 0xDEAD;

    pub fn init(unit: u8, values: []u16, bug: Bug) BrokenDevice {
        return .{ .unit = unit, .values = values, .bug = bug };
    }

    pub fn node(self: *BrokenDevice) Node {
        return .{
            .ctx = self,
            .vtable = &vtable,
            .protocol = .modbus,
            .framing = .modbus_tcp,
        };
    }

    const vtable = Node.VTable{ .deliver = deliverFn };

    fn deliverFn(ctx: *anyopaque, bytes: []const u8, out: []u8, now_ms: Time) NodeError!?[]const u8 {
        _ = now_ms;
        const self: *BrokenDevice = @ptrCast(@alignCast(ctx));

        if (bytes.len < 12) return null;
        const txid = std.mem.readInt(u16, bytes[0..2], .big);
        if (std.mem.readInt(u16, bytes[2..4], .big) != 0) return null;
        if (bytes[6] != self.unit) return null;
        if (bytes[7] != 0x03) return null;
        const addr = std.mem.readInt(u16, bytes[8..10], .big);
        const count = std.mem.readInt(u16, bytes[10..12], .big);
        if (count == 0 or @as(usize, addr) + count > self.values.len) return null;

        const repeat = self.seen and txid == self.last_txid;
        self.seen = true;
        self.last_txid = txid;
        self.counter +%= 1;

        const body_len: usize = 2 + 2 * @as(usize, count); // fc + byte count + data
        const total = 7 + body_len;
        if (out.len < total) return NodeError.OutputTooSmall;

        var declared: u16 = @intCast(1 + body_len); // unit id + PDU
        var reply_txid = txid;
        var unit = self.unit;
        var stale_values = false;

        if (repeat) switch (self.bug) {
            .none => {},
            // The length field is accumulated per transaction id rather than
            // computed per response, so a retransmission counts twice and the
            // frame claims more bytes than it carries.
            .length_counts_retransmit => declared += @intCast(body_len),
            // The scratch header's unit id is only written on a first sight.
            .stale_unit_id => unit = self.unit +% 0x40,
            // The transaction id comes from an internal counter, not the
            // request, so it names a transaction that was never issued.
            .invented_transaction => reply_txid = 0xF000 +% self.counter,
            // The register buffer is not re-read, so the response ships the
            // uninitialised scratch contents.
            .stale_register_buffer => stale_values = true,
        };

        std.mem.writeInt(u16, out[0..2], reply_txid, .big);
        std.mem.writeInt(u16, out[2..4], 0, .big);
        std.mem.writeInt(u16, out[4..6], declared, .big);
        out[6] = unit;
        out[7] = 0x03;
        out[8] = @intCast(2 * @as(usize, count));
        for (0..count) |k| {
            const v = if (stale_values) sentinel else self.values[addr + k];
            std.mem.writeInt(u16, out[9 + 2 * k ..][0..2], v, .big);
        }
        return out[0..total];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const Harness = Vopr(2);
/// Every search in this file is bounded, and modestly. A netsim sweep is a
/// replay per seed and ddmin is a replay per candidate cut, so an unbounded
/// budget here would be a runaway, not a better test.
const sweep_start: u64 = 1;
const sweep_end: u64 = 60;
const run_until: netsim.Time = 1200;

test "vopr: the fleet really runs inside netsim — polls, replies, and faults that bite" {
    const gpa = testing.allocator;
    var h = Harness.init(gpa, .{ .fleet_seed = 0xC0FFEE });
    defer h.deinit();

    var gr = try netsim.run(gpa, h.case(0xC0FFEE, run_until), .{});
    defer gr.trace.deinit();

    // Teeth: a harness that silently does nothing passes every invariant.
    try testing.expectEqual(netsim.RunOutcome.ok, gr.result.outcome);
    try testing.expect(h.polls > 20);
    try testing.expect(h.totalReplies() > 20);
    try testing.expect(gr.result.events_processed > 200);
    try testing.expect(gr.trace.events.len > 0); // the adversary was present
    // The fleet, not just netsim, did the work: its own scheduler delivered
    // every request and its responders answered.
    try testing.expect(h.fleet.stats(0).delivered > 20);
    try testing.expect(h.fleet.stats(0).replied > 20);
    try testing.expect(h.fleet.events_processed > 100);
}

test "vopr: a correct fleet survives a bounded netsim seed sweep" {
    const gpa = testing.allocator;
    var h = Harness.init(gpa, .{ .fleet_seed = 7 });
    defer h.deinit();

    // The real `adapters.Modbus`, under netsim's full adversary. Nothing here
    // may fire: every invariant above is a statement about bytes the devices
    // authored, and drop/dup/delay/partition/crash cannot author bytes.
    var failing = try netsim.findFailing(gpa, h.case(0, run_until), .{}, sweep_start, sweep_end);
    if (failing) |*f| {
        defer f.deinit();
        std.debug.print("unexpected violation {any} at seed {d}\n", .{ f.err, f.case.seed });
        return error.CleanFleetViolatedAnInvariant;
    }
}

test "vopr: the toy device is correct too, so the toy is not what is caught" {
    const gpa = testing.allocator;
    var h = Harness.init(gpa, .{ .fleet_seed = 7, .toy = true });
    defer h.deinit();

    var failing = try netsim.findFailing(gpa, h.case(0, run_until), .{}, sweep_start, sweep_end);
    if (failing) |*f| {
        defer f.deinit();
        return error.CorrectToyViolatedAnInvariant;
    }
}

test "vopr: every bug is unreachable without the adversary" {
    const gpa = testing.allocator;
    // With an EMPTY fault trace there is no duplication, so no transaction id
    // is ever seen twice and every one of these devices is indistinguishable
    // from a correct one. This is what makes the searches below evidence.
    for ([_]Bug{
        .length_counts_retransmit,
        .stale_unit_id,
        .invented_transaction,
        .stale_register_buffer,
    }) |bug| {
        var h = Harness.init(gpa, .{ .fleet_seed = 7, .bug = bug });
        defer h.deinit();
        const r = try netsim.replay(gpa, h.case(0, run_until), &.{}, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
        try testing.expect(h.totalReplies() > 20); // and it really answered
    }
}

test "vopr: findFailing catches every planted defect, on the invariant that owns it" {
    const gpa = testing.allocator;
    const cases = [_]struct { bug: Bug, want: anyerror }{
        .{ .bug = .length_counts_retransmit, .want = Violation.MalformedReply },
        .{ .bug = .stale_unit_id, .want = Violation.UnitIdMismatch },
        .{ .bug = .invented_transaction, .want = Violation.UnknownTransaction },
        .{ .bug = .stale_register_buffer, .want = Violation.ValueOutOfRange },
    };
    for (cases) |c| {
        var h = Harness.init(gpa, .{ .fleet_seed = 7, .bug = c.bug });
        defer h.deinit();
        var failing = (try netsim.findFailing(gpa, h.case(0, run_until), .{}, sweep_start, sweep_end)) orelse
            return error.SearchFoundNothing;
        defer failing.deinit();
        try testing.expectEqual(c.want, failing.err);
    }
}

test "vopr: a counterexample comes back minimised, and the minimum still reproduces" {
    const gpa = testing.allocator;
    var h = Harness.init(gpa, .{ .fleet_seed = 7, .bug = .length_counts_retransmit });
    defer h.deinit();

    var failing = (try netsim.findFailing(gpa, h.case(0, run_until), .{}, sweep_start, sweep_end)) orelse
        return error.SearchFoundNothing;
    defer failing.deinit();
    try testing.expectEqual(Violation.MalformedReply, failing.err);

    var res = try netsim.shrinkTrace(gpa, &failing);
    defer res.deinit();
    try testing.expect(res.after >= 1);
    try testing.expect(res.after <= res.before);
    if (res.before > 1) try testing.expect(res.after < res.before); // it shrank

    // The minimised trace is a real reproducer, not a summary of one.
    const r = try netsim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(Violation.MalformedReply, r.violation.?.err);

    // And it keeps the root cause: a duplicate on a master → device link. Any
    // other single fault leaves every transaction id unique, so the bug cannot
    // be expressed at all.
    var dup_to_device = false;
    for (res.trace.events) |e| switch (e.kind) {
        .dup_once => |l| {
            if (l.a == master) dup_to_device = true;
        },
        else => {},
    };
    try testing.expect(dup_to_device);

    // The fleet saw the responder emit bytes its own framing cannot describe,
    // and shipped them whole rather than swallowing them — which is why the
    // master could see the defect at all.
    const bad_framing = try h.traceCount(.bad_framing);
    try testing.expect(bad_framing > 0);
}

test "vopr: the netsim-driven fleet is deterministic across identical seeds" {
    const gpa = testing.allocator;
    var h = Harness.init(gpa, .{ .fleet_seed = 3 });
    defer h.deinit();

    var g1 = try netsim.run(gpa, h.case(11, run_until), .{});
    defer g1.trace.deinit();
    const fleet_fp1 = h.fleet.fingerprint;
    const replies1 = h.totalReplies();

    var g2 = try netsim.run(gpa, h.case(11, run_until), .{});
    defer g2.trace.deinit();

    // netsim's own fingerprint AND the fleet's, so a rebuild that failed to
    // return the devices to their t=0 state cannot hide behind netsim's.
    try testing.expectEqual(g1.result.fingerprint, g2.result.fingerprint);
    try testing.expectEqual(g1.result.events_processed, g2.result.events_processed);
    try testing.expectEqual(fleet_fp1, h.fleet.fingerprint);
    try testing.expectEqual(replies1, h.totalReplies());
    try testing.expect(replies1 > 20);
}
