// SPDX-License-Identifier: MIT

//! protocol — the `netsim.Protocol` consumers that drive real message flow
//! through the stratified mixnet, plus the shared relay plumbing they share.
//!
//!  - `Loopix` is the real thing: clients originate Poisson cover + periodic
//!    real traffic; each mix holds every arrival an INDEPENDENT exponential
//!    delay (the gated `mixing.scheduleRelease`) before forwarding. Its
//!    anonymity test is gated behind `gate.fable_core_implemented` — until the
//!    core is filled in, any run PANICS (the mix's first arrival calls the
//!    stub), so the test SKIPs rather than runs.
//!  - `FifoMix` is the POSITIVE CONTROL: identical topology, routing, and
//!    transcript machinery, but each mix forwards after a CONSTANT delay,
//!    preserving arrival order — the canonical anonymity-breaking mix. It calls
//!    none of the gated core, so it runs today, and the anonymity harness
//!    (`adversary.measure`, scored with the FIFO mix's own constant delay law)
//!    flags it hard: every real target is pinned (link probability 1, effective
//!    set 1). This proves the harness has teeth before the Poisson core exists.
//!
//! Both share `Relay` — the stash/release/forward/transcript mechanics and the
//! traffic originators. The ONLY thing that differs is the per-arrival hold: a
//! constant for `FifoMix`, an exponential for `Loopix`. That is the entire
//! Fable boundary, made concrete: swap the hold and anonymity appears.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");
const routing = @import("routing.zig");
const mixing = @import("mixing.zig");
const adversary = @import("adversary.zig");
const gate = @import("gate.zig");

const Allocator = std.mem.Allocator;
const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Sim = netsim.Sim;
const Protocol = netsim.Protocol;
const LinkConfig = netsim.LinkConfig;

const LoopixConfig = types.LoopixConfig;
const MixHeader = types.MixHeader;
const MsgKind = types.MsgKind;
const Transit = adversary.Transit;

// ── shared topology + config ─────────────────────────────────────────────────

/// The one config both the scenario and the protocols are built from (netsim's
/// `Scenario` is a bare fn pointer, so the topology reads a module constant —
/// same pattern as `df-elect`). 3 layers × 3 mixes + 3 clients = 12 nodes.
pub const DEFAULT_CFG = LoopixConfig{};

const RELEASE_TIMER: u64 = 0;
const REAL_TIMER: u64 = 1;
const COVER_TIMER: u64 = 2;

/// Build the stratified topology for `DEFAULT_CFG`: clients fully connected to
/// layer 0, each adjacent mix layer fully connected, the last layer fully
/// connected back to the clients. Full bipartite layers are what makes it
/// *stratified* — any message may use any mix per layer, so all traffic shares
/// the relay set and is mutually indistinguishable at the link level.
pub fn scenario(sim: *Sim) anyerror!void {
    const cfg = DEFAULT_CFG;
    var i: usize = 0;
    while (i < cfg.nodeCount()) : (i += 1) _ = try sim.addNode(.{});

    const link = LinkConfig{ .latency = 3, .jitter = 2 };
    // clients ↔ layer 0
    var c: u8 = 0;
    while (c < cfg.clients) : (c += 1) {
        var w: u8 = 0;
        while (w < cfg.width) : (w += 1) try sim.addBiLink(cfg.clientNode(c), cfg.mixNode(0, w), link);
    }
    // adjacent mix layers, fully connected
    var l: u8 = 0;
    while (l + 1 < cfg.layers) : (l += 1) {
        var a: u8 = 0;
        while (a < cfg.width) : (a += 1) {
            var b: u8 = 0;
            while (b < cfg.width) : (b += 1) try sim.addBiLink(cfg.mixNode(l, a), cfg.mixNode(l + 1, b), link);
        }
    }
    // last layer ↔ clients
    var w: u8 = 0;
    while (w < cfg.width) : (w += 1) {
        var cc: u8 = 0;
        while (cc < cfg.clients) : (cc += 1) try sim.addBiLink(cfg.mixNode(cfg.layers - 1, w), cfg.clientNode(cc), link);
    }
}

// ── Relay: the mechanics both protocols share ────────────────────────────────

const Stashed = struct { arrival: Time, hdr: MixHeader };

/// The stash/release/forward/transcript machinery + traffic originators. The
/// hold-delay decision is NOT here — each protocol supplies it (constant vs
/// exponential), which is the whole Fable boundary.
const Relay = struct {
    gpa: Allocator,
    cfg: LoopixConfig,
    /// Per-mix FIFO of packets currently being held. Constant/ordered holds
    /// release front-first; the exponential mix reorders via its timers but the
    /// stash is still keyed by release identity (see `release`).
    queues: []std.ArrayListUnmanaged(Stashed),
    transcript: std.ArrayListUnmanaged(Transit) = .empty,
    next_id: u64 = 1,
    real_seq: u64 = 0,
    cover_seq: u64 = 0,

    fn init(gpa: Allocator, cfg: LoopixConfig) Allocator.Error!Relay {
        const queues = try gpa.alloc(std.ArrayListUnmanaged(Stashed), cfg.nodeCount());
        for (queues) |*q| q.* = .empty;
        return .{ .gpa = gpa, .cfg = cfg, .queues = queues };
    }

    fn deinit(self: *Relay, gpa: Allocator) void {
        for (self.queues) |*q| q.deinit(gpa);
        gpa.free(self.queues);
        self.transcript.deinit(gpa);
        self.* = undefined;
    }

    fn reset(self: *Relay) void {
        for (self.queues) |*q| q.clearRetainingCapacity();
        self.transcript.clearRetainingCapacity();
        self.next_id = 1;
        self.real_seq = 0;
        self.cover_seq = 0;
    }

    /// Originate one message from `src_client` toward `dest`, tagged `kind`,
    /// routed by `key`. The client injects it onto its link to the first mix
    /// (route slot 0); the client↔layer-0 links the scenario builds guarantee
    /// that link exists.
    fn originate(self: *Relay, sim: *Sim, src_client: u8, dest: NodeId, kind: MsgKind, key: u64) anyerror!void {
        var hdr = MixHeader{ .kind = kind, .id = self.next_id, .hop = 0, .n_hops = 0, .route = undefined };
        @memset(&hdr.route, 0);
        self.next_id += 1;
        routing.pickRoute(self.cfg, key, dest, &hdr);
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        try sim.send(self.cfg.clientNode(src_client), hdr.route[0], &buf);
    }

    /// A client emits one REAL message to some other client.
    fn originateReal(self: *Relay, sim: *Sim, client: u8) anyerror!void {
        self.real_seq += 1;
        const key = (@as(u64, client) << 40) | (self.real_seq << 1);
        const dest = routing.pickDestClient(self.cfg, key, client);
        try self.originate(sim, client, dest, .real, key);
    }

    /// A client emits one cover message (loop = back to self, drop = elsewhere).
    fn originateCover(self: *Relay, sim: *Sim, client: u8, kind: MsgKind) anyerror!void {
        self.cover_seq += 1;
        const key = (@as(u64, client) << 40) | (self.cover_seq << 1) | 1;
        const dest = if (kind == .loop_cover)
            self.cfg.clientNode(client)
        else
            routing.pickDestClient(self.cfg, key, client);
        try self.originate(sim, client, dest, kind, key);
    }

    /// A mix received a packet: stash it and arm a release timer for `hold`
    /// ticks. On release it is forwarded and a completed transit is logged.
    fn stashAndArm(self: *Relay, sim: *Sim, node: NodeId, payload: []const u8, hold: Time) anyerror!void {
        const hdr = MixHeader.decode(payload);
        try self.queues[node].append(self.gpa, .{ .arrival = sim.timeNow(), .hdr = hdr });
        try sim.setTimer(node, hold, RELEASE_TIMER);
    }

    /// A release timer fired on a mix: forward the front-most held packet
    /// (FIFO by release order) and log its completed transit.
    fn release(self: *Relay, sim: *Sim, node: NodeId) anyerror!void {
        const q = &self.queues[node];
        if (q.items.len == 0) return; // a partition/crash may have voided it
        const s = q.orderedRemove(0);
        var hdr = s.hdr;
        // Record the completed pass through THIS mix (the adversary's raw
        // material — timing only; id/kind are the harness's oracle labels).
        try self.transcript.append(self.gpa, .{
            .mix = node,
            .arrival = s.arrival,
            .departure = sim.timeNow(),
            .kind = hdr.kind,
            .id = hdr.id,
        });
        hdr.hop += 1; // advance to the next relay (route[hop] now the successor)
        const next = hdr.route[hdr.hop];
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        try sim.send(node, next, &buf);
    }
};

// ── FifoMix: the positive control (constant hold, order-preserving) ──────────

/// Deliberately anonymity-BREAKING: every mix forwards after `cfg.fifo_delay`
/// ticks — a constant, so arrival order is preserved through every mix. Emits
/// real traffic but NO cover. Runs today (no gated core) and the anonymity
/// harness flags it: scored with its own constant delay law, every real
/// target's posterior is a spike on its true departure.
pub const FifoMix = struct {
    relay: Relay,

    pub fn init(gpa: Allocator, cfg: LoopixConfig) Allocator.Error!FifoMix {
        return .{ .relay = try Relay.init(gpa, cfg) };
    }
    pub fn deinit(self: *FifoMix, gpa: Allocator) void {
        self.relay.deinit(gpa);
        self.* = undefined;
    }
    pub fn transcript(self: *const FifoMix) []const Transit {
        return self.relay.transcript.items;
    }

    pub fn protocol(self: *FifoMix) Protocol {
        return .{ .ctx = self, .onStartFn = onStart, .onMessageFn = onMessage, .onTimerFn = onTimer, .resetFn = reset };
    }
    fn cast(ctx: *anyopaque) *FifoMix {
        return @ptrCast(@alignCast(ctx));
    }
    fn reset(ctx: *anyopaque) void {
        cast(ctx).relay.reset();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) {
            try sim.setTimer(node, cfg.real_period, REAL_TIMER); // real traffic only — no cover
        }
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        switch (timer_id) {
            REAL_TIMER => {
                try self.relay.originateReal(sim, @intCast(node - cfg.mixCount()));
                try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            },
            RELEASE_TIMER => try self.relay.release(sim, node),
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        _ = from;
        if (self.relay.cfg.isClient(node)) return; // destination: absorb
        try self.relay.stashAndArm(sim, node, payload, self.relay.cfg.fifo_delay); // CONSTANT hold
    }
};

// ── Loopix: the real Poisson mix (calls the gated core) ──────────────────────

/// The real thing: exponential per-hop holds (`mixing.scheduleRelease`) + a
/// Poisson cover process (`mixing.nextCover`). Structurally identical to
/// `FifoMix` — the ONLY difference is the hold law — which is the point: the
/// harness proves anonymity is exactly what that one swap buys.
pub const Loopix = struct {
    relay: Relay,
    prng: mixing.Prng,
    rng_seed: u64,

    pub fn init(gpa: Allocator, cfg: LoopixConfig, rng_seed: u64) Allocator.Error!Loopix {
        return .{ .relay = try Relay.init(gpa, cfg), .prng = mixing.Prng.init(rng_seed), .rng_seed = rng_seed };
    }
    pub fn deinit(self: *Loopix, gpa: Allocator) void {
        self.relay.deinit(gpa);
        self.* = undefined;
    }
    pub fn transcript(self: *const Loopix) []const Transit {
        return self.relay.transcript.items;
    }

    pub fn protocol(self: *Loopix) Protocol {
        return .{ .ctx = self, .onStartFn = onStart, .onMessageFn = onMessage, .onTimerFn = onTimer, .resetFn = reset };
    }
    fn cast(ctx: *anyopaque) *Loopix {
        return @ptrCast(@alignCast(ctx));
    }
    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        self.relay.reset();
        self.prng = mixing.Prng.init(self.rng_seed);
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) {
            try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            // Kick off the (gated) Poisson cover process.
            const ev = mixing.nextCover(&self.prng, cfg);
            try sim.setTimer(node, ev.delay, COVER_TIMER);
        }
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        switch (timer_id) {
            REAL_TIMER => {
                try self.relay.originateReal(sim, @intCast(node - cfg.mixCount()));
                try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            },
            COVER_TIMER => {
                const ev = mixing.nextCover(&self.prng, cfg); // GATED
                try self.relay.originateCover(sim, @intCast(node - cfg.mixCount()), ev.kind);
                try sim.setTimer(node, ev.delay, COVER_TIMER);
            },
            RELEASE_TIMER => try self.relay.release(sim, node),
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        _ = from;
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) return; // destination (or returning loop cover): absorb
        // GATED: the Poisson mix's independent exponential hold.
        const release_at = mixing.scheduleRelease(&self.prng, cfg, sim.timeNow());
        const hold = release_at - sim.timeNow();
        try self.relay.stashAndArm(sim, node, payload, hold);
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const UNTIL: Time = 2000;

test "smoke: the stratified scenario has the expected node/topology shape" {
    const gpa = testing.allocator;
    var fifo = try FifoMix.init(gpa, DEFAULT_CFG);
    defer fifo.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = scenario, .protocol = fifo.protocol(), .until = UNTIL });
    defer gpa.free(topo.links);
    try testing.expectEqual(DEFAULT_CFG.nodeCount(), topo.node_count); // 12 nodes
    try testing.expect(topo.links.len > 0);
}

test "positive control: FifoMix carries real traffic and the anonymity harness flags it" {
    const gpa = testing.allocator;
    var fifo = try FifoMix.init(gpa, DEFAULT_CFG);
    defer fifo.deinit(gpa);
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = fifo.protocol(), .until = UNTIL };

    // Clean run (no faults) for a crisp, deterministic transcript.
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome); // FifoMix has no invariant checkFn

    const transits = fifo.transcript();
    try testing.expect(transits.len > 50); // real traffic actually flowed through the mixes

    // Score with the FIFO mix's OWN delay law (Kerckhoffs): a constant spike.
    const anon = try adversary.measure(gpa, transits, .{ .constant = .{ .delta = DEFAULT_CFG.fifo_delay, .tol = 0 } });
    try testing.expect(anon.targets > 0);
    // The order-preserving mix is caught hard: some target is fully pinned and
    // some target hides among an effective crowd of ~1.
    try testing.expect(anon.max_link_prob > 0.9);
    try testing.expect(anon.min_effective_set < 1.5);
    try testing.expect(!anon.holds(.{})); // FAILS the anonymity invariant
}

test "positive control: FifoMix stays anonymity-broken across a seed sweep (incl. fuzzed faults)" {
    const gpa = testing.allocator;
    var fifo = try FifoMix.init(gpa, DEFAULT_CFG);
    defer fifo.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = fifo.protocol(), .until = UNTIL };
    const model = adversary.DelayModel{ .constant = .{ .delta = DEFAULT_CFG.fifo_delay, .tol = 0 } };

    var flagged: usize = 0;
    var seed: u64 = 1;
    while (seed <= 40) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try netsim.run(gpa, case, .{});
        defer gr.trace.deinit();
        const anon = try adversary.measure(gpa, fifo.transcript(), model);
        if (anon.targets > 0 and !anon.holds(.{})) flagged += 1;
    }
    // A harness that could not catch an order-preserving mix would flag 0 —
    // that would mean the anonymity metric itself is dead.
    try testing.expect(flagged > 0);
}

// ── gated test: the real Poisson mix, behind the Fable stub ──────────────────
//
// See `gate.zig`. `Loopix.onMessage`/`.onTimer` call `mixing.scheduleRelease`/
// `mixing.nextCover`, which `@panic` today — a panic aborts the whole test
// binary (Zig's runner cannot catch it), so this test must never REACH them
// until the core exists. `error.SkipZigTest` keeps `zig build test-loopix`
// green while documenting exactly what will run once the flag flips.

test "real: the Poisson mix holds the anonymity invariant across a seed sweep" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const bound = types.AnonymityBound{};

    var seed: u64 = 1;
    while (seed <= 50) : (seed += 1) {
        var mix = try Loopix.init(gpa, DEFAULT_CFG, seed);
        defer mix.deinit(gpa);
        var gr = try netsim.run(gpa, .{ .seed = seed, .scenario = scenario, .protocol = mix.protocol(), .until = UNTIL }, .{});
        defer gr.trace.deinit();

        const anon = try adversary.measure(gpa, mix.transcript(), .{ .exponential = @floatFromInt(DEFAULT_CFG.mean_delay) });
        if (!anon.holds(bound)) {
            std.debug.print("loopix: seed {} broke anonymity — min_set {d:.2} (>= {d:.2}?), max_link {d:.3} (<= {d:.3}?)\n", .{
                seed, anon.min_effective_set, bound.min_effective_set, anon.max_link_prob, bound.max_link_prob,
            });
            return error.AnonymityInvariantViolated;
        }
    }
}
