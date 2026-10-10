// SPDX-License-Identifier: MIT

//! protocol — the `netsim.Protocol` consumers that drive real message flow
//! through the stratified mixnet, plus the relay plumbing they share.
//!
//!  - `Loopix` is the real thing: clients originate Poisson cover + periodic
//!    real traffic; each mix holds every arrival an INDEPENDENT exponential
//!    delay — drawn by the mix (`mixing.scheduleRelease`) or, as deployed, by
//!    the sender and carried in the header (`LoopixConfig.sender_chosen_delays`)
//!    — before forwarding. In the provider topology clients send through and
//!    receive at a provider that keeps their mailbox; with sender-chosen
//!    delays every client watches its own loop cover come back and raises an
//!    alarm when too many do not (n−1 detection, against `Attack`).
//!  - `FifoMix` is the POSITIVE CONTROL: identical topology, routing, and
//!    transcript machinery, but each mix forwards after a CONSTANT delay,
//!    preserving arrival order — the canonical anonymity-breaking mix. The
//!    anonymity harness (`adversary.measure` / `measureEndToEnd`, scored with
//!    the FIFO mix's own constant delay law) flags it hard: every real target
//!    is pinned.
//!
//! Both share `Relay` — the stash/release/forward/transcript mechanics, the
//! providers and mailboxes, and the traffic originators. The ONLY thing that
//! differs is the per-arrival hold: a constant for `FifoMix`, an exponential
//! for `Loopix`. Swap the hold and anonymity appears.

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

/// The Phase-1 config: clients attached straight to the mixes, mix-chosen
/// holds. 3 layers × 3 mixes + 3 clients = 12 nodes. (netsim's `Scenario` is a
/// bare fn pointer, so each topology reads a module constant — same pattern as
/// `df-elect`.)
pub const DEFAULT_CFG = LoopixConfig{};

/// Loopix as deployed: 8 clients behind 2 providers that keep their
/// mailboxes, sender-chosen holds, loop-based n−1 detection on. 3 layers × 3
/// mixes + 8 clients + 2 providers = 19 nodes.
pub const PROVIDER_CFG = LoopixConfig{ .clients = 8, .providers = 2, .sender_chosen_delays = true };

/// Every link of both topologies. The worst-case latency of one link is what a
/// client adds per leg when it works out when its loop must be back.
pub const LINK = LinkConfig{ .latency = 3, .jitter = 2 };
const max_link_latency: Time = LINK.latency + LINK.jitter;

const RELEASE_TIMER: u64 = 0;
const REAL_TIMER: u64 = 1;
const COVER_TIMER: u64 = 2;
const FETCH_TIMER: u64 = 3;

/// Payload tags outside `MsgKind`'s range: a client asking its provider for
/// its mailbox, and the provider's fixed-size answer.
const FETCH_REQ: u8 = 0xF0;
const FETCH_RESP: u8 = 0xF1;
pub const max_fetch_batch = 16;
const fetch_resp_len = 2 + max_fetch_batch * MixHeader.wire_len;

pub const InitError = Allocator.Error || LoopixConfig.ConfigError;

/// Build the stratified topology for `DEFAULT_CFG`: clients fully connected to
/// layer 0, each adjacent mix layer fully connected, the last layer fully
/// connected back to the clients. Full bipartite layers are what makes it
/// *stratified* — any message may use any mix per layer, so all traffic shares
/// the relay set and is mutually indistinguishable at the link level.
pub fn scenario(sim: *Sim) anyerror!void {
    try buildTopology(sim, DEFAULT_CFG);
}

/// The same for `PROVIDER_CFG`: each client linked to its provider only, every
/// provider to every first-layer and every last-layer mix.
pub fn providerScenario(sim: *Sim) anyerror!void {
    try buildTopology(sim, PROVIDER_CFG);
}

fn buildTopology(sim: *Sim, cfg: LoopixConfig) anyerror!void {
    var i: usize = 0;
    while (i < cfg.nodeCount()) : (i += 1) _ = try sim.addNode(.{});

    // The nodes the first layer receives from and the last layer sends to:
    // the clients themselves, or the providers.
    var edge: [256]NodeId = undefined;
    var edges: usize = 0;
    if (cfg.providers == 0) {
        var c: u8 = 0;
        while (c < cfg.clients) : (c += 1) {
            edge[edges] = cfg.clientNode(c);
            edges += 1;
        }
    } else {
        var p: u8 = 0;
        while (p < cfg.providers) : (p += 1) {
            edge[edges] = cfg.providerNode(p);
            edges += 1;
        }
        var c: u8 = 0;
        while (c < cfg.clients) : (c += 1) try sim.addBiLink(cfg.clientNode(c), cfg.providerOf(c), LINK);
    }
    for (edge[0..edges]) |e| {
        var w: u8 = 0;
        while (w < cfg.width) : (w += 1) try sim.addBiLink(e, cfg.mixNode(0, w), LINK);
    }
    // adjacent mix layers, fully connected
    var l: u8 = 0;
    while (l + 1 < cfg.layers) : (l += 1) {
        var a: u8 = 0;
        while (a < cfg.width) : (a += 1) {
            var b: u8 = 0;
            while (b < cfg.width) : (b += 1) try sim.addBiLink(cfg.mixNode(l, a), cfg.mixNode(l + 1, b), LINK);
        }
    }
    // last layer ↔ the receiving edge (a no-op for a 1-layer net already linked)
    if (cfg.layers > 1) {
        var w: u8 = 0;
        while (w < cfg.width) : (w += 1) {
            for (edge[0..edges]) |e| try sim.addBiLink(cfg.mixNode(cfg.layers - 1, w), e, LINK);
        }
    }
}

// ── Relay: the mechanics both protocols share ────────────────────────────────

const Stashed = struct { arrival: Time, release_at: Time, hdr: MixHeader };

/// A packet that reached its recipient's state machine (ground truth).
pub const Delivery = struct {
    id: u64,
    kind: MsgKind,
    sender: u8,
    recipient: u8,
    sent: Time,
    delivered: Time,
};

/// What the traffic cost, measured off the ground truth.
pub const TrafficStats = struct {
    real_sent: usize = 0,
    real_delivered: usize = 0,
    cover_sent: usize = 0,
    /// Cover packets per real packet — the bandwidth overhead of the cover.
    overhead: f64 = 0,
    mean_latency: f64 = 0,
    max_latency: Time = 0,
};

const Sent = struct { client: u8, at: Time, kind: MsgKind, recipient: NodeId };

/// The stash/release/forward/transcript machinery, the providers and the
/// traffic originators. The hold-delay decision is NOT here — each protocol
/// supplies it (constant vs exponential), which is the whole Fable boundary.
const Relay = struct {
    gpa: Allocator,
    cfg: LoopixConfig,
    /// Per-mix pool of packets currently being held, each stamped with its OWN
    /// scheduled release time. `release` pops BY RELEASE TIME, not front-first:
    /// releasing the front (oldest arrival) on every timer would forward
    /// identities in strict arrival order regardless of the hold law — an
    /// order-preserving mix a Kerckhoffs adversary unlinks with probability 1,
    /// even though the departure TIMES look exponential. (This was a real,
    /// caught defect — see the memoryless property test below.)
    queues: []std.ArrayListUnmanaged(Stashed),
    /// Per-client mailbox, kept by the client's provider.
    mailboxes: []std.ArrayListUnmanaged(MixHeader),
    transcript: std.ArrayListUnmanaged(Transit) = .empty,
    origins: std.ArrayListUnmanaged(adversary.Origin) = .empty,
    sent: std.AutoHashMapUnmanaged(u64, Sent) = .empty,
    deliveries: std.ArrayListUnmanaged(Delivery) = .empty,
    delivered: std.AutoHashMapUnmanaged(u64, Time) = .empty,
    /// Length of every mailbox answer a provider sent (must all be equal).
    fetch_lens: std.ArrayListUnmanaged(usize) = .empty,
    /// Packets dropped as malformed or out of place: undecodable bytes, a
    /// header that does not name this node as its current hop, a mailbox
    /// packet from anything but a last-layer mix. Every byte in the sim comes
    /// from our own encoder, so the tests require 0.
    malformed: u64 = 0,
    /// A packet delivered a second time, or to a client it was not for.
    misdelivered: u64 = 0,
    next_id: u64 = 1,
    real_seq: u64 = 0,
    cover_seq: u64 = 0,

    fn init(gpa: Allocator, cfg: LoopixConfig) InitError!Relay {
        try cfg.validate();
        comptime std.debug.assert(max_fetch_batch == 16); // = LoopixConfig.validate's bound
        const queues = try gpa.alloc(std.ArrayListUnmanaged(Stashed), cfg.nodeCount());
        errdefer gpa.free(queues);
        @memset(queues, .empty);
        const mailboxes = try gpa.alloc(std.ArrayListUnmanaged(MixHeader), cfg.clients);
        @memset(mailboxes, .empty);
        return .{ .gpa = gpa, .cfg = cfg, .queues = queues, .mailboxes = mailboxes };
    }

    fn deinit(self: *Relay, gpa: Allocator) void {
        for (self.queues) |*q| q.deinit(gpa);
        gpa.free(self.queues);
        for (self.mailboxes) |*m| m.deinit(gpa);
        gpa.free(self.mailboxes);
        self.transcript.deinit(gpa);
        self.origins.deinit(gpa);
        self.sent.deinit(gpa);
        self.deliveries.deinit(gpa);
        self.delivered.deinit(gpa);
        self.fetch_lens.deinit(gpa);
        self.* = undefined;
    }

    fn reset(self: *Relay) void {
        for (self.queues) |*q| q.clearRetainingCapacity();
        for (self.mailboxes) |*m| m.clearRetainingCapacity();
        self.transcript.clearRetainingCapacity();
        self.origins.clearRetainingCapacity();
        self.sent.clearRetainingCapacity();
        self.deliveries.clearRetainingCapacity();
        self.delivered.clearRetainingCapacity();
        self.fetch_lens.clearRetainingCapacity();
        self.malformed = 0;
        self.misdelivered = 0;
        self.next_id = 1;
        self.real_seq = 0;
        self.cover_seq = 0;
    }

    /// Originate one message from `src_client` toward `dest`, tagged `kind`,
    /// routed by `key`. With `delays` (and `sender_chosen_delays`) the sender
    /// draws every hop's hold now and writes it into the header. The client
    /// injects it onto its link to its provider, or to the first mix.
    fn originate(self: *Relay, sim: *Sim, src_client: u8, dest: NodeId, kind: MsgKind, key: u64, delays: ?*mixing.Prng) anyerror!MixHeader {
        var hdr = MixHeader{ .kind = kind, .id = self.next_id, .hop = 0, .n_hops = 0, .route = undefined };
        @memset(&hdr.route, 0);
        self.next_id += 1;
        routing.pickRoute(self.cfg, key, dest, &hdr);
        if (self.cfg.sender_chosen_delays) {
            if (delays) |prng| {
                hdr.has_delays = true;
                for (hdr.delays[0..hdr.n_hops]) |*d| d.* = @intCast(mixing.sampleExpDelay(prng, self.cfg.mean_delay));
            }
        }
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        const first = if (self.cfg.providers > 0) self.cfg.providerOf(src_client) else hdr.route[0];
        try sim.send(self.cfg.clientNode(src_client), first, &buf);
        try self.origins.append(self.gpa, .{ .id = hdr.id, .client = src_client });
        try self.sent.put(self.gpa, hdr.id, .{ .client = src_client, .at = sim.timeNow(), .kind = kind, .recipient = hdr.recipient });
        return hdr;
    }

    /// A client emits one REAL message to some other client.
    fn originateReal(self: *Relay, sim: *Sim, client: u8, delays: ?*mixing.Prng) anyerror!void {
        self.real_seq += 1;
        const key = (@as(u64, client) << 40) | (self.real_seq << 1);
        const dest = routing.pickDestClient(self.cfg, key, client);
        _ = try self.originate(sim, client, dest, .real, key, delays);
    }

    /// A client emits one cover message (loop = back to self, drop = elsewhere).
    fn originateCover(self: *Relay, sim: *Sim, client: u8, kind: MsgKind, delays: ?*mixing.Prng) anyerror!MixHeader {
        self.cover_seq += 1;
        const key = (@as(u64, client) << 40) | (self.cover_seq << 1) | 1;
        const dest = if (kind == .loop_cover)
            self.cfg.clientNode(client)
        else
            routing.pickDestClient(self.cfg, key, client);
        return self.originate(sim, client, dest, kind, key, delays);
    }

    /// A mix received a packet: stash it (stamped with its own absolute release
    /// time) and arm a release timer for `hold` ticks. On release THAT packet
    /// is forwarded and its completed transit is logged.
    fn stashAndArm(self: *Relay, sim: *Sim, node: NodeId, hdr: MixHeader, hold: Time) anyerror!void {
        const now = sim.timeNow();
        try self.queues[node].append(self.gpa, .{ .arrival = now, .release_at = now + hold, .hdr = hdr });
        try sim.setTimer(node, hold, RELEASE_TIMER);
    }

    /// A release timer fired on a mix: forward the held packet whose OWN drawn
    /// release time is due, and log its completed transit.
    ///
    /// ANONYMITY-LOAD-BEARING: the packet released must be the one whose timer
    /// this is (matched by its stamped `release_at`), NOT the front of the
    /// queue. Timers fire in release-time order, so popping the front would
    /// re-assign the drawn departure times to identities in arrival order —
    /// the departure timeline would still look exponential, but the identity
    /// permutation would be the identity map (in-order = out-order), which a
    /// Kerckhoffs adversary inverts deterministically. Matching by release
    /// time keeps each identity's departure its own independent memoryless
    /// draw; packets sharing an exact release tick are exchangeable, so
    /// front-first among exact ties leaks nothing.
    fn release(self: *Relay, sim: *Sim, node: NodeId) anyerror!void {
        const q = &self.queues[node];
        const now = sim.timeNow();
        const idx = for (q.items, 0..) |s, i| {
            if (s.release_at == now) break i;
        } else return; // a partition/crash may have voided it
        const s = q.orderedRemove(idx);
        var hdr = s.hdr;
        // Record the completed pass through THIS mix (the adversary's raw
        // material — timing only; id/kind are the harness's oracle labels).
        try self.transcript.append(self.gpa, .{
            .mix = node,
            .arrival = s.arrival,
            .departure = sim.timeNow(),
            .kind = hdr.kind,
            .id = hdr.id,
            .hop = hdr.hop,
        });
        hdr.hop += 1; // advance to the next relay (route[hop] now the successor)
        const next = hdr.route[hdr.hop];
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        try sim.send(node, next, &buf);
    }

    /// The header a MIX may act on: it decodes, and names this node as the
    /// mix of its current hop. Anything else is dropped and counted — a mix
    /// that trusted `hop` would index `route[hop + 1]` past the route on the
    /// way out (review 2026-10-04, L-02: an all-zero header has n_hops 0).
    fn acceptAtMix(self: *Relay, node: NodeId, payload: []const u8) ?MixHeader {
        const hdr = MixHeader.decode(payload) catch {
            self.malformed += 1;
            return null;
        };
        if (hdr.hop >= hdr.n_hops or hdr.route[hdr.hop] != node) {
            self.malformed += 1;
            return null;
        }
        return hdr;
    }

    /// A provider: a client's mailbox pull, a client's packet to forward into
    /// the first layer (at once — the mixes mix), or a packet out of the last
    /// layer to store in its recipient's mailbox.
    fn providerMessage(self: *Relay, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const cfg = self.cfg;
        if (payload.len == 1 and payload[0] == FETCH_REQ) {
            if (!cfg.isClient(from) or cfg.providerOf(cfg.clientIndex(from)) != node) return;
            const mbox = &self.mailboxes[cfg.clientIndex(from)];
            // ALWAYS `fetch_batch` slots: real packets first, dummies after.
            var buf: [fetch_resp_len]u8 = @splat(0);
            const n: usize = @min(mbox.items.len, cfg.fetch_batch);
            buf[0] = FETCH_RESP;
            buf[1] = @intCast(n);
            for (mbox.items[0..n], 0..) |h, i| h.encode(buf[2 + i * MixHeader.wire_len ..][0..MixHeader.wire_len]);
            std.mem.copyForwards(MixHeader, mbox.items[0 .. mbox.items.len - n], mbox.items[n..]);
            mbox.shrinkRetainingCapacity(mbox.items.len - n);
            const len = 2 + @as(usize, cfg.fetch_batch) * MixHeader.wire_len;
            try self.fetch_lens.append(self.gpa, len);
            try sim.send(node, from, buf[0..len]);
            return;
        }
        const hdr = MixHeader.decode(payload) catch {
            self.malformed += 1;
            return;
        };
        if (hdr.hop == 0 and hdr.n_hops > 0 and cfg.isClient(from) and cfg.providerOf(cfg.clientIndex(from)) == node) {
            var buf: [MixHeader.wire_len]u8 = undefined;
            hdr.encode(&buf);
            try sim.send(node, hdr.route[0], &buf);
        } else if (hdr.n_hops > 0 and hdr.hop == hdr.n_hops and hdr.route[hdr.n_hops] == node and
            cfg.layerOf(from) == cfg.layers - 1 and cfg.isClient(hdr.recipient) and
            cfg.providerOf(cfg.clientIndex(hdr.recipient)) == node)
        {
            // Only out of the last layer, only to this provider, only for one
            // of ITS clients (review 2026-10-04, L-10).
            try self.mailboxes[cfg.clientIndex(hdr.recipient)].append(self.gpa, hdr);
        } else self.malformed += 1;
    }

    /// A client: a mailbox answer (provider topology) or a packet straight
    /// from the last layer.
    fn clientMessage(self: *Relay, sim: *Sim, node: NodeId, payload: []const u8) anyerror!void {
        if (payload.len >= 2 and payload[0] == FETCH_RESP) {
            const n = payload[1];
            for (0..n) |i| {
                const off = 2 + i * MixHeader.wire_len;
                if (payload.len < off + MixHeader.wire_len) return;
                const hdr = MixHeader.decode(payload[off..][0..MixHeader.wire_len]) catch {
                    self.malformed += 1;
                    return;
                };
                try self.deliver(sim, node, hdr);
            }
            return;
        }
        const hdr = MixHeader.decode(payload) catch {
            self.malformed += 1;
            return;
        };
        try self.deliver(sim, node, hdr);
    }

    fn deliver(self: *Relay, sim: *Sim, node: NodeId, hdr: MixHeader) anyerror!void {
        const s = self.sent.get(hdr.id) orelse {
            self.malformed += 1;
            return;
        };
        // Exactly once, and only to the client the sender addressed (review
        // 2026-10-04, L-08/L-09: counts alone let a loss and a duplicate
        // cancel out).
        if (node != s.recipient or hdr.hop != hdr.n_hops or self.delivered.contains(hdr.id)) {
            self.misdelivered += 1;
            return;
        }
        const now = sim.timeNow();
        try self.delivered.put(self.gpa, hdr.id, now);
        try self.deliveries.append(self.gpa, .{
            .id = hdr.id,
            .kind = hdr.kind,
            .sender = s.client,
            .recipient = self.cfg.clientIndex(node),
            .sent = s.at,
            .delivered = now,
        });
    }

    fn startClient(self: *Relay, sim: *Sim, node: NodeId) anyerror!void {
        if (self.cfg.providers > 0) try sim.setTimer(node, self.cfg.fetch_period, FETCH_TIMER);
    }

    fn fetch(self: *Relay, sim: *Sim, node: NodeId) anyerror!void {
        try sim.send(node, self.cfg.providerOf(self.cfg.clientIndex(node)), &.{FETCH_REQ});
        try sim.setTimer(node, self.cfg.fetch_period, FETCH_TIMER);
    }

    fn stats(self: *const Relay) TrafficStats {
        var st = TrafficStats{};
        var it = self.sent.valueIterator();
        while (it.next()) |s| {
            if (s.kind == .real) st.real_sent += 1 else st.cover_sent += 1;
        }
        var sum: f64 = 0;
        for (self.deliveries.items) |d| {
            if (d.kind != .real) continue;
            st.real_delivered += 1;
            const lat = d.delivered - d.sent;
            sum += @floatFromInt(lat);
            st.max_latency = @max(st.max_latency, lat);
        }
        if (st.real_delivered > 0) st.mean_latency = sum / @as(f64, @floatFromInt(st.real_delivered));
        if (st.real_sent > 0) st.overhead = @as(f64, @floatFromInt(st.cover_sent)) / @as(f64, @floatFromInt(st.real_sent));
        return st;
    }
};

// ── FifoMix: the positive control (constant hold, order-preserving) ──────────

/// Deliberately anonymity-BREAKING: every mix forwards after `cfg.fifo_delay`
/// ticks — a constant, so arrival order is preserved through every mix. Emits
/// real traffic but NO cover. The anonymity harness flags it: scored with its
/// own constant delay law, every real target's posterior is a spike on its
/// true departure.
pub const FifoMix = struct {
    relay: Relay,

    pub fn init(gpa: Allocator, cfg: LoopixConfig) InitError!FifoMix {
        return .{ .relay = try Relay.init(gpa, cfg) };
    }
    pub fn deinit(self: *FifoMix, gpa: Allocator) void {
        self.relay.deinit(gpa);
        self.* = undefined;
    }
    pub fn transcript(self: *const FifoMix) []const Transit {
        return self.relay.transcript.items;
    }
    pub fn origins(self: *const FifoMix) []const adversary.Origin {
        return self.relay.origins.items;
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
            try self.relay.startClient(sim, node);
        }
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        switch (timer_id) {
            REAL_TIMER => {
                try self.relay.originateReal(sim, cfg.clientIndex(node), null);
                try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            },
            RELEASE_TIMER => try self.relay.release(sim, node),
            FETCH_TIMER => try self.relay.fetch(sim, node),
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) return self.relay.clientMessage(sim, node, payload);
        if (cfg.isProvider(node)) return self.relay.providerMessage(sim, node, from, payload);
        const hdr = self.relay.acceptAtMix(node, payload) orelse return;
        try self.relay.stashAndArm(sim, node, hdr, cfg.fifo_delay); // CONSTANT hold
    }
};

// ── Loopix: the real Poisson mix ─────────────────────────────────────────────

/// An active adversary's n−1 attack on one mix: from `start` until `stop` it
/// blocks every packet entering `mix` (the "flush" phase; letting one target
/// through is what makes it n−1, and changes nothing about detection). What
/// it blocks includes honest clients' loop cover — which is exactly how
/// Loopix notices.
pub const Attack = struct { mix: NodeId, start: Time, stop: Time };

pub const Alarm = struct { client: u8, at: Time };

const LoopWatch = struct { client: u8, deadline: Time };

/// The real thing: exponential per-hop holds + a Poisson cover process.
/// Structurally identical to `FifoMix` — the ONLY difference is the hold law —
/// which is the point: the harness proves anonymity is exactly what that one
/// swap buys.
pub const Loopix = struct {
    relay: Relay,
    prng: mixing.Prng,
    rng_seed: u64,
    /// Whether clients run the Poisson cover process. `true` is the real Loopix
    /// mix; `false` is the NO-COVER positive control — same memoryless holds,
    /// but no chaff to fill the pools, so at the low real-traffic rate a mix
    /// often holds a single packet and the effective anonymity set collapses to
    /// 1 (clause-1 failure).
    cover_enabled: bool = true,
    /// An n−1 attacker, if any.
    attack: ?Attack = null,
    attack_dropped: u64 = 0,
    /// When the attacker last dropped something (0 = never).
    attack_last_drop: Time = 0,
    /// Loop cover in flight, with the time by which each must be back.
    loops: std.AutoHashMapUnmanaged(u64, LoopWatch) = .empty,
    /// Loops each client has given up on.
    lost: []u32,
    /// Loops watched, and loops that came back in time — so a detector that
    /// watches nothing cannot pass the no-false-positive test (L-06).
    loops_watched: u64 = 0,
    loops_returned: u64 = 0,
    alarms: std.ArrayListUnmanaged(Alarm) = .empty,

    pub fn init(gpa: Allocator, cfg: LoopixConfig, rng_seed: u64) InitError!Loopix {
        var relay = try Relay.init(gpa, cfg);
        errdefer relay.deinit(gpa);
        const lost = try gpa.alloc(u32, cfg.clients);
        @memset(lost, 0);
        return .{ .relay = relay, .prng = mixing.Prng.init(rng_seed), .rng_seed = rng_seed, .lost = lost };
    }
    /// The no-cover control (see `cover_enabled`).
    pub fn initNoCover(gpa: Allocator, cfg: LoopixConfig, rng_seed: u64) InitError!Loopix {
        var self = try init(gpa, cfg, rng_seed);
        self.cover_enabled = false;
        return self;
    }
    pub fn deinit(self: *Loopix, gpa: Allocator) void {
        self.loops.deinit(gpa);
        self.alarms.deinit(gpa);
        gpa.free(self.lost);
        self.relay.deinit(gpa);
        self.* = undefined;
    }
    pub fn transcript(self: *const Loopix) []const Transit {
        return self.relay.transcript.items;
    }
    pub fn origins(self: *const Loopix) []const adversary.Origin {
        return self.relay.origins.items;
    }
    pub fn deliveries(self: *const Loopix) []const Delivery {
        return self.relay.deliveries.items;
    }
    pub fn stats(self: *const Loopix) TrafficStats {
        return self.relay.stats();
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
        self.attack_dropped = 0;
        self.attack_last_drop = 0;
        self.loops_watched = 0;
        self.loops_returned = 0;
        self.loops.clearRetainingCapacity();
        @memset(self.lost, 0);
        self.alarms.clearRetainingCapacity();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) {
            try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            try self.relay.startClient(sim, node);
            // Kick off the Poisson cover process — unless this is the no-cover
            // control, which self-starves its mix pools.
            if (self.cover_enabled) {
                const ev = mixing.nextCover(&self.prng, cfg);
                try sim.setTimer(node, ev.delay, COVER_TIMER);
            }
        }
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        switch (timer_id) {
            REAL_TIMER => {
                try self.relay.originateReal(sim, cfg.clientIndex(node), &self.prng);
                try sim.setTimer(node, cfg.real_period, REAL_TIMER);
            },
            COVER_TIMER => {
                const ev = mixing.nextCover(&self.prng, cfg);
                const hdr = try self.relay.originateCover(sim, cfg.clientIndex(node), ev.kind, &self.prng);
                if (ev.kind == .loop_cover and hdr.has_delays) try self.watchLoop(sim, cfg.clientIndex(node), hdr);
                try self.checkLoops(sim, cfg.clientIndex(node));
                try sim.setTimer(node, ev.delay, COVER_TIMER);
            },
            FETCH_TIMER => {
                try self.relay.fetch(sim, node);
                try self.checkLoops(sim, cfg.clientIndex(node));
            },
            RELEASE_TIMER => try self.relay.release(sim, node),
            else => {},
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isClient(node)) return self.relay.clientMessage(sim, node, payload);
        if (cfg.isProvider(node)) return self.relay.providerMessage(sim, node, from, payload);
        const now = sim.timeNow();
        if (self.attack) |a| {
            if (node == a.mix and now >= a.start and now < a.stop) {
                self.attack_dropped += 1;
                self.attack_last_drop = now;
                return;
            }
        }
        const hdr = self.relay.acceptAtMix(node, payload) orelse return;
        // The Poisson mix's independent exponential hold: the sender's draw if
        // the packet carries one, else the mix's own.
        const hold: Time = if (hdr.has_delays)
            hdr.delays[hdr.hop]
        else
            mixing.scheduleRelease(&self.prng, cfg, now) - now;
        try self.relay.stashAndArm(sim, node, hdr, hold);
    }

    /// A sender-chosen-delay loop is fully predictable to its sender: the sum
    /// of its own hop holds, plus every link at its worst, plus (behind a
    /// provider) one fetch period of waiting in the mailbox. Past that plus
    /// `loop_slack`, it is lost.
    fn watchLoop(self: *Loopix, sim: *Sim, client: u8, hdr: MixHeader) anyerror!void {
        const cfg = self.relay.cfg;
        var bound: Time = 0;
        for (hdr.delays[0..hdr.n_hops]) |d| bound += d;
        // Links: client→(provider→)mixes→(provider)→client, plus the fetch
        // request/answer round trip behind a provider.
        const legs: Time = @as(Time, hdr.n_hops) + 1 + if (cfg.providers > 0) @as(Time, 3) else 0;
        bound += legs * max_link_latency;
        if (cfg.providers > 0) bound += cfg.fetch_period;
        try self.loops.put(self.relay.gpa, hdr.id, .{ .client = client, .deadline = sim.timeNow() + bound + cfg.loop_slack });
        self.loops_watched += 1;
    }

    /// Settle `client`'s loops: returned ones are forgotten, overdue ones are
    /// lost, and enough losses raise the client's alarm (once).
    fn checkLoops(self: *Loopix, sim: *Sim, client: u8) anyerror!void {
        const now = sim.timeNow();
        var done: std.ArrayListUnmanaged(u64) = .empty;
        defer done.deinit(self.relay.gpa);
        var it = self.loops.iterator();
        while (it.next()) |kv| {
            const w = kv.value_ptr.*;
            if (w.client != client) continue;
            if (self.relay.delivered.contains(kv.key_ptr.*)) {
                try done.append(self.relay.gpa, kv.key_ptr.*);
                self.loops_returned += 1;
            } else if (now > w.deadline) {
                try done.append(self.relay.gpa, kv.key_ptr.*);
                self.lost[client] += 1;
                if (self.lost[client] == self.relay.cfg.loop_alarm_lost)
                    try self.alarms.append(self.relay.gpa, .{ .client = client, .at = now });
            }
        }
        for (done.items) |id| _ = self.loops.remove(id);
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

// The COOLDOWN a target needs after its arrival for its mix's forward pool to be
// full before the finite horizon `UNTIL` truncates it. In a real mixnet the very
// last packets before the network goes idle are inherently more exposed (there is
// simply no later traffic to hide among); that is a property of the finite
// SIMULATION WINDOW, not of the mixing strategy, so — exactly as anonymity
// analyses drop warm-up/cool-down — we score anonymity over the steady-state
// targets (arrival + COOLDOWN ≤ UNTIL) and let the cool-down tail swell pools
// without being scored. ~7 mean-delays is generous; empirically the correct mix
// has ZERO steady-state targets below effective-set 2 across all 50 seeds, so the
// window is not hiding a genuine mid-run collapse — the two controls collapse
// inside this SAME window (FIFO to 1.00, no-cover to 1.06).
const COOLDOWN: Time = 300;

/// Measure anonymity over the steady-state window WITHOUT touching
/// `adversary.measure` (the metric): a target that arrived too late to clear
/// before `UNTIL` is relabelled to `drop_cover`, so it still swells its mix's
/// departure pool (helping earlier targets hide) but is not itself scored as a
/// linking target. Everything else — the pool indexing, the posterior, the
/// worst-case min/max aggregation — is the real `measure`, unchanged.
fn measureSteadyState(gpa: Allocator, transits: []const Transit, model: adversary.DelayModel) !adversary.AnonymityResult {
    var windowed = try std.ArrayListUnmanaged(Transit).initCapacity(gpa, transits.len);
    defer windowed.deinit(gpa);
    for (transits) |t| {
        var w = t;
        if (t.kind == .real and t.arrival + COOLDOWN > UNTIL) w.kind = .drop_cover;
        windowed.appendAssumeCapacity(w);
    }
    return adversary.measure(gpa, windowed.items, model);
}

// ── the real Poisson mix, now that the core is implemented ───────────────────
//
// Measurement basis (see `AnonymityBound` in `types.zig` + the module SPEC):
//   - CLEAN run (`replay` with an empty fault trace). The Loopix guarantee is
//     against a global PASSIVE adversary on a FUNCTIONING network; the fault
//     fuzzer models an ACTIVE adversary (partition/crash/drop) that can starve a
//     mix's pool — an out-of-Phase-1-scope attack (SPEC "n−1 active attacks").
//     The FIFO anonymity control likewise scores a clean transcript.
//   - Steady-state window (`measureSteadyState`): finite-horizon cool-down only.
//   - Each mix scored with its OWN delay law (Kerckhoffs): exponential for the
//     Poisson mixes, the constant spike for FIFO.

test "real: the Poisson mix holds the anonymity invariant across a seed sweep" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const bound = types.AnonymityBound{};
    const model = adversary.DelayModel{ .exponential = @floatFromInt(DEFAULT_CFG.mean_delay) };

    var worst_set: f64 = std.math.inf(f64);
    var worst_link: f64 = 0;
    var seed: u64 = 1;
    while (seed <= 50) : (seed += 1) {
        var mix = try Loopix.init(gpa, DEFAULT_CFG, seed);
        defer mix.deinit(gpa);
        const case = netsim.Case{ .seed = seed, .scenario = scenario, .protocol = mix.protocol(), .until = UNTIL };
        _ = try netsim.replay(gpa, case, &.{}, null); // clean, deterministic

        const anon = try measureSteadyState(gpa, mix.transcript(), model);
        try testing.expect(anon.targets > 50); // real traffic actually flowed
        worst_set = @min(worst_set, anon.min_effective_set);
        worst_link = @max(worst_link, anon.max_link_prob);
        if (!anon.holds(bound)) {
            std.debug.print("loopix: seed {} broke anonymity — min_set {d:.2} (>= {d:.2}?), max_link {d:.3} (<= {d:.3}?)\n", .{
                seed, anon.min_effective_set, bound.min_effective_set, anon.max_link_prob, bound.max_link_prob,
            });
            return error.AnonymityInvariantViolated;
        }
    }
    // Genuine margin, not tuned-to-pass: the worst target over all 50 seeds sits
    // comfortably inside the bound on BOTH clauses (measured ≈ 3.88 / 0.63 with
    // release-by-own-timer; the pre-fix FIFO-release pairing measured 2.80/0.77
    // because it systematically paired each arrival with its maximum-likelihood
    // departure).
    try testing.expect(worst_set >= bound.min_effective_set + 0.5);
    try testing.expect(worst_link <= bound.max_link_prob - 0.05);
}

test "real: the FIFO and no-cover controls FAIL the invariant under identical measurement" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const bound = types.AnonymityBound{};

    // Same clean run + same steady-state window + each mix's own delay law — the
    // only thing that differs from the passing test is the MIX STRATEGY. Both
    // controls fail the bound on every seed, with the effective set collapsed far
    // below `min_effective_set` (FIFO to ~1.0, no-cover to ~1.06).
    var fifo_worst_set: f64 = std.math.inf(f64);
    var nc_worst_set: f64 = std.math.inf(f64);
    var nc_worst_link: f64 = 0;
    var seed: u64 = 1;
    while (seed <= 50) : (seed += 1) {
        // FIFO, scored with its own constant (spike) law → posterior pins EVERY
        // packet, on every seed: fails the bound deterministically.
        var fifo = try FifoMix.init(gpa, DEFAULT_CFG);
        defer fifo.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenario, .protocol = fifo.protocol(), .until = UNTIL }, &.{}, null);
        const f = try measureSteadyState(gpa, fifo.transcript(), .{ .constant = .{ .delta = DEFAULT_CFG.fifo_delay, .tol = 0 } });
        try testing.expect(f.targets > 50);
        try testing.expect(!f.holds(bound));
        fifo_worst_set = @min(fifo_worst_set, f.min_effective_set);

        // No-cover Poisson mix: memoryless holds, but starved pools. Per seed the
        // worst target's crowd may vary, so we assert the CONTROL (worst over the
        // sweep) fails — the same worst-case footing the passing test uses.
        var nc = try Loopix.initNoCover(gpa, DEFAULT_CFG, seed);
        defer nc.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenario, .protocol = nc.protocol(), .until = UNTIL }, &.{}, null);
        const n = try measureSteadyState(gpa, nc.transcript(), .{ .exponential = @floatFromInt(DEFAULT_CFG.mean_delay) });
        try testing.expect(n.targets > 50);
        nc_worst_set = @min(nc_worst_set, n.min_effective_set);
        nc_worst_link = @max(nc_worst_link, n.max_link_prob);
    }
    // FIFO collapses to a pinned crowd of ~1 on every seed (constant kernel).
    try testing.expect(fifo_worst_set < 1.05);
    // No-cover: the worst-case anonymity set across the sweep collapses far below
    // the bound (cover starvation) — the guarantee the cover process provides.
    try testing.expect(nc_worst_set < 1.5);
    try testing.expect(nc_worst_set < bound.min_effective_set); // fails clause 1
    try testing.expect(nc_worst_link > bound.max_link_prob); // and clause 2
}

// ── the memoryless-mixing property test (audit F1 — the test with teeth) ─────
//
// The kernel-scored invariant above measures the anonymity SET, but it scores
// with a fixed exponential kernel, so it cannot detect the mix's hold law
// silently ceasing to be memoryless (audit F1: a constant-hold injection left
// the whole suite green). This test checks the memoryless property DIRECTLY,
// via its order-statistics consequence (see `adversary.reorderStats`):
//
//   Among co-resident pairs at a mix (the second arrived while the first was
//   still held), a memoryless hold makes the residual of the earlier packet
//   distributed like a fresh draw, so the later arrival departs first with
//   probability ≈ 1/2. ANY order-preserving mix — constant hold, FIFO release
//   discipline, threshold batching in arrival order — scores EXACTLY 0.
//
// The 0.5-vs-0 gap is categorical, so the [0.35, 0.65] band cannot flake on
// the correct mix (thousands of pairs per seed ⇒ sampling error ≈ ±0.01) and
// cannot pass an order-preserving one. Verified to bite: with
// `mixing.sampleExpDelay` forced to `mean/2` (constant hold) this test goes
// RED (fraction 0.00) while the kernel-scored invariant above stays green —
// exactly the F1 regression, now caught. It also caught a REAL defect on first
// run: `Relay.release` used to pop the queue FRONT on every timer (identities
// left in arrival order — fraction 0.00 on every seed) — see `release`.

test "real: the Poisson mix reorders co-resident packets (memoryless); order-preserving mixes score zero" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;

    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        // The real mix: inversion fraction must sit in the memoryless band.
        var mix = try Loopix.init(gpa, DEFAULT_CFG, seed);
        defer mix.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenario, .protocol = mix.protocol(), .until = UNTIL }, &.{}, null);
        const st = adversary.reorderStats(mix.transcript());
        try testing.expect(st.pairs > 500); // dense co-residency (cover keeps pools full)
        const f = st.fraction();
        if (f < 0.35 or f > 0.65) {
            std.debug.print("loopix: seed {} broke memorylessness — inversion fraction {d:.3} over {} pairs (want ~0.5)\n", .{ seed, f, st.pairs });
            return error.MixNotMemoryless;
        }

        // The order-preserving control under the SAME statistic: exactly zero.
        var fifo = try FifoMix.init(gpa, DEFAULT_CFG);
        defer fifo.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenario, .protocol = fifo.protocol(), .until = UNTIL }, &.{}, null);
        const fst = adversary.reorderStats(fifo.transcript());
        try testing.expect(fst.pairs > 50);
        try testing.expectEqual(@as(usize, 0), fst.inversions);
    }
}

// ── the provider topology: Loopix as deployed ───────────────────────────────
//
// 8 clients behind 2 providers that keep their mailboxes, sender-chosen holds,
// loop-based n−1 detection. Same measurement basis as above (clean run,
// steady-state window, each mix scored with its own law).

const P = PROVIDER_CFG;

fn runProviders(gpa: Allocator, mix: *Loopix, seed: u64, faults: []const netsim.FaultEvent) !void {
    _ = gpa;
    _ = try netsim.replay(testing.allocator, .{ .seed = seed, .scenario = providerScenario, .protocol = mix.protocol(), .until = UNTIL }, faults, null);
}

/// End-to-end sender anonymity over the steady-state window: a real packet
/// sent too late to clear before `UNTIL` still swells the pools but is not
/// scored (the same cool-down rule as `measureSteadyState`).
fn senderSteadyState(gpa: Allocator, transits: []const Transit, origins_: []const adversary.Origin, sent: *const std.AutoHashMapUnmanaged(u64, Sent), cfg: LoopixConfig, model: adversary.DelayModel) !adversary.SenderResult {
    var windowed = try std.ArrayListUnmanaged(Transit).initCapacity(gpa, transits.len);
    defer windowed.deinit(gpa);
    for (transits) |t| {
        var w = t;
        if (t.kind == .real) {
            const s = sent.get(t.id).?;
            if (s.at + COOLDOWN > UNTIL) w.kind = .drop_cover;
        }
        windowed.appendAssumeCapacity(w);
    }
    return adversary.measureEndToEnd(gpa, windowed.items, origins_, cfg.clients, cfg.layers - 1, model);
}

test "providers: the topology links each client to its provider only, providers to both edge layers" {
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = providerScenario, .protocol = mix.protocol(), .until = UNTIL });
    defer gpa.free(topo.links);
    try testing.expectEqual(P.nodeCount(), topo.node_count); // 19
    // Directed links: clients↔providers 2·8, providers↔layer0 2·2·3,
    // providers↔last layer 2·2·3, layer↔layer 2·2·9.
    try testing.expectEqual(@as(usize, 16 + 12 + 12 + 36), topo.links.len);
}

test "providers: every packet reaches its recipient through the mailbox, and every answer is the same size" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, P, 3);
    defer mix.deinit(gpa);
    try runProviders(gpa, &mix, 3, &.{});

    const st = mix.stats();
    try testing.expect(st.real_sent > 400);
    // Everything not still in flight at the horizon arrived.
    var due: usize = 0;
    var it = mix.relay.sent.valueIterator();
    while (it.next()) |s| {
        if (s.kind == .real and s.at + COOLDOWN <= UNTIL) due += 1;
    }
    var on_time: usize = 0;
    for (mix.deliveries()) |d| {
        // Loops come home; everything else lands on someone else.
        switch (d.kind) {
            .loop_cover => try testing.expectEqual(d.sender, d.recipient),
            else => try testing.expect(d.sender != d.recipient),
        }
        if (d.kind == .real and d.sent + COOLDOWN <= UNTIL) on_time += 1;
    }
    try testing.expectEqual(due, on_time);
    try testing.expectEqual(@as(u64, 0), mix.relay.malformed);
    try testing.expectEqual(@as(u64, 0), mix.relay.misdelivered);

    // Receiver unobservability: one answer per client per fetch period,
    // every one the same length, whether the mailbox held 0 packets or 8.
    const lens = mix.relay.fetch_lens.items;
    try testing.expect(lens.len >= @as(usize, P.clients) * (UNTIL / P.fetch_period - 2));
    for (lens) |l| try testing.expectEqual(lens[0], l);

    // Latency: three holds of mean 40 plus links plus up to one fetch period.
    try testing.expect(st.mean_latency > 100 and st.mean_latency < 220);
    // Cover dominates the volume, as it must for the sets below.
    try testing.expect(st.overhead > 1.5);
}

test "providers: sender-chosen holds keep the per-mix invariant and stay memoryless" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const model = adversary.DelayModel{ .exponential = @floatFromInt(P.mean_delay) };
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var mix = try Loopix.init(gpa, P, seed);
        defer mix.deinit(gpa);
        try runProviders(gpa, &mix, seed, &.{});
        const anon = try measureSteadyState(gpa, mix.transcript(), model);
        try testing.expect(anon.targets > 200);
        if (!anon.holds(.{})) {
            std.debug.print("loopix providers: seed {} min_set {d:.2} max_link {d:.3}\n", .{ seed, anon.min_effective_set, anon.max_link_prob });
            return error.AnonymityInvariantViolated;
        }
        const f = adversary.reorderStats(mix.transcript()).fraction();
        try testing.expect(f > 0.35 and f < 0.65);
    }
}

test "end-to-end: the sender of every real packet stays hidden through all layers; FIFO and no-cover are traced back" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const bound = types.SenderBound{};
    const exp_model = adversary.DelayModel{ .exponential = @floatFromInt(P.mean_delay) };

    var worst_set: f64 = std.math.inf(f64);
    var worst_link: f64 = 0;
    var fifo_worst_link: f64 = 0;
    var nc_worst_set: f64 = std.math.inf(f64);
    var nc_failed: usize = 0;
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var mix = try Loopix.init(gpa, P, seed);
        defer mix.deinit(gpa);
        try runProviders(gpa, &mix, seed, &.{});
        const r = try senderSteadyState(gpa, mix.transcript(), mix.origins(), &mix.relay.sent, P, exp_model);
        try testing.expect(r.targets > 200);
        try testing.expectEqual(@as(usize, 0), r.fallbacks);
        worst_set = @min(worst_set, r.min_sender_set);
        worst_link = @max(worst_link, r.max_link_prob);
        if (!r.holds(bound)) {
            std.debug.print("loopix e2e: seed {} min_sender_set {d:.2} max_link {d:.3}\n", .{ seed, r.min_sender_set, r.max_link_prob });
            return error.SenderAnonymityViolated;
        }

        var fifo = try FifoMix.init(gpa, P);
        defer fifo.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = providerScenario, .protocol = fifo.protocol(), .until = UNTIL }, &.{}, null);
        const f = try senderSteadyState(gpa, fifo.transcript(), fifo.origins(), &fifo.relay.sent, P, .{ .constant = .{ .delta = P.fifo_delay, .tol = 0 } });
        try testing.expect(f.targets > 100);
        try testing.expect(!f.holds(bound));
        fifo_worst_link = @max(fifo_worst_link, f.max_link_prob);

        var nc = try Loopix.initNoCover(gpa, P, seed);
        defer nc.deinit(gpa);
        try runProviders(gpa, &nc, seed, &.{});
        const n = try senderSteadyState(gpa, nc.transcript(), nc.origins(), &nc.relay.sent, P, exp_model);
        try testing.expect(n.targets > 100);
        nc_worst_set = @min(nc_worst_set, n.min_sender_set);
        if (!n.holds(bound)) nc_failed += 1;
    }
    // Measured 2026-10-04 (see `SenderBound`): real 5.78 / 0.286, FIFO link
    // 1.00, no-cover set 2.00. Genuine margin on the passing side too:
    try testing.expect(worst_set >= bound.min_sender_set + 1.0);
    try testing.expect(worst_link <= bound.max_link_prob - 0.1);
    // FIFO: some packet traced straight back to its sender.
    try testing.expect(fifo_worst_link > 0.99);
    // No cover: some packet's sender set collapses.
    try testing.expect(nc_worst_set < bound.min_sender_set);
    try testing.expect(nc_failed > 0);
}

// ── n−1: the active attack loop cover exists to catch ───────────────────────

/// The middle layer's first mix, blocked for a third of the run.
const ATTACK = Attack{ .mix = P.mixNode(1, 0), .start = 700, .stop = 1400 };

test "n−1: blocking a mix makes clients' loops go missing, and they raise the alarm during the attack" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var seed: u64 = 1;
    while (seed <= 10) : (seed += 1) {
        var mix = try Loopix.init(gpa, P, seed);
        defer mix.deinit(gpa);
        mix.attack = ATTACK;
        try runProviders(gpa, &mix, seed, &.{});
        try testing.expect(mix.attack_dropped > 20);
        // The attack is exactly the window it was given.
        try testing.expect(mix.attack_last_drop >= ATTACK.start and mix.attack_last_drop < ATTACK.stop);
        try testing.expect(mix.alarms.items.len > 0);
        // Every alarm is a reaction to the attack: none before it started,
        // and each client raises its alarm once.
        var seen = [_]bool{false} ** P.clients;
        for (mix.alarms.items) |a| {
            try testing.expect(a.at > ATTACK.start);
            try testing.expect(!seen[a.client]);
            seen[a.client] = true;
        }
        // ...and the first comes while it is still running.
        var first: Time = std.math.maxInt(Time);
        for (mix.alarms.items) |a| first = @min(first, a.at);
        try testing.expect(first < ATTACK.stop);
    }
}

test "n−1: a clean network raises no alarm (no false positives), and without sender-chosen holds nobody is watching" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var mix = try Loopix.init(gpa, P, seed);
        defer mix.deinit(gpa);
        try runProviders(gpa, &mix, seed, &.{});
        for (mix.lost) |l| try testing.expectEqual(@as(u32, 0), l);
        try testing.expectEqual(@as(usize, 0), mix.alarms.items.len);
        // The detector was alive: it watched loops and saw them come back.
        try testing.expect(mix.loops_watched > 100);
        try testing.expect(mix.loops_returned > 90);
    }
    // The same attack against mix-chosen holds: the clients cannot know when a
    // loop is due, so the detector has nothing to go on.
    var cfg = P;
    cfg.sender_chosen_delays = false;
    var blind = try Loopix.init(gpa, cfg, 1);
    defer blind.deinit(gpa);
    blind.attack = ATTACK;
    // (`providerScenario` builds from PROVIDER_CFG; only the delay mode differs,
    // which the topology does not depend on.)
    try runProviders(gpa, &blind, 1, &.{});
    try testing.expect(blind.attack_dropped > 20);
    try testing.expectEqual(@as(usize, 0), blind.alarms.items.len);
}

test "providers: a mailbox answers only its own client, through that client's provider" {
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try providerScenario(&sim);
    const p = mix.protocol();

    // Client 0 is registered with provider 0; client 1 with provider 1.
    try mix.relay.mailboxes[0].append(gpa, .{ .kind = .real, .id = 77, .hop = 3, .n_hops = 3, .route = @splat(0), .recipient = P.clientNode(0) });
    // Asked by the wrong client, by a mix, or at the wrong provider: no answer,
    // and the mailbox keeps its packet.
    try p.onMessageFn(p.ctx, &sim, P.providerNode(0), P.clientNode(2 + 1), &.{FETCH_REQ}); // client 3 → provider 1's client
    try p.onMessageFn(p.ctx, &sim, P.providerNode(0), P.mixNode(0, 0), &.{FETCH_REQ});
    try p.onMessageFn(p.ctx, &sim, P.providerNode(1), P.clientNode(0), &.{FETCH_REQ});
    try testing.expectEqual(@as(usize, 0), mix.relay.fetch_lens.items.len);
    try testing.expectEqual(@as(usize, 1), mix.relay.mailboxes[0].items.len);
    // The right one empties it.
    try p.onMessageFn(p.ctx, &sim, P.providerNode(0), P.clientNode(0), &.{FETCH_REQ});
    try testing.expectEqual(@as(usize, 1), mix.relay.fetch_lens.items.len);
    try testing.expectEqual(@as(usize, 0), mix.relay.mailboxes[0].items.len);
}

test "a mix drops a header that does not name it as the current hop, and an undecodable one" {
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, DEFAULT_CFG, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);
    const p = mix.protocol();
    const m0 = DEFAULT_CFG.mixNode(0, 0);

    // The all-zero header (n_hops 0) used to reach `release` and index
    // `route[hop + 1]` past the route (review L-02); a header for another mix,
    // and plain garbage.
    var zero: [MixHeader.wire_len]u8 = @splat(0);
    var other = MixHeader{ .kind = .real, .id = 1, .hop = 0, .n_hops = 3, .route = .{ DEFAULT_CFG.mixNode(0, 1), 3, 6, 9, 0, 0, 0 } };
    var other_buf: [MixHeader.wire_len]u8 = undefined;
    other.encode(&other_buf);
    for ([_][]const u8{ &zero, &other_buf, &.{ 0x7F, 1, 2 } }) |bytes| try p.onMessageFn(p.ctx, &sim, m0, DEFAULT_CFG.clientNode(0), bytes);
    try testing.expectEqual(@as(u64, 3), mix.relay.malformed);
    try testing.expectEqual(@as(usize, 0), mix.relay.queues[m0].items.len);

    // The same header addressed to m0 is accepted.
    other.route[0] = m0;
    other.encode(&other_buf);
    try p.onMessageFn(p.ctx, &sim, m0, DEFAULT_CFG.clientNode(0), &other_buf);
    try testing.expectEqual(@as(usize, 1), mix.relay.queues[m0].items.len);
}

test "config validation refuses what would overflow the header, the casts or the mailboxes" {
    const gpa = testing.allocator;
    const bad = [_]LoopixConfig{
        .{ .layers = 0 },
        .{ .layers = types.max_layers + 1 },
        .{ .fetch_batch = 0 },
        .{ .fetch_batch = max_fetch_batch + 1 },
        .{ .mean_delay = 1 << 21 },
        .{ .providers = 4, .clients = 3 },
        .{ .loop_alarm_lost = 0 },
    };
    for (bad) |cfg| try testing.expectError(error.InvalidConfig, Loopix.init(gpa, cfg, 1));
    try P.validate();
    try DEFAULT_CFG.validate();
}

test "n−1: a loop's deadline is exactly its own holds + every leg at worst + one fetch + the slack" {
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    var h = MixHeader{ .kind = .loop_cover, .id = 5, .hop = 0, .n_hops = 3, .route = @splat(0), .has_delays = true };
    h.delays = .{ 10, 20, 30, 0, 0, 0, 0 };
    try mix.watchLoop(&sim, 2, h);
    // 60 of holds; 3 mixes + 1 + 3 provider legs (in, out, fetch round trip)
    // at 5 each; one fetch period; the slack.
    const want: Time = 60 + (3 + 1 + 3) * max_link_latency + P.fetch_period + P.loop_slack;
    try testing.expectEqual(want, mix.loops.get(5).?.deadline);
}

test "a client takes a packet once, and only one addressed to it; a provider stores only what leaves the last layer" {
    const gpa = testing.allocator;
    var mix = try Loopix.init(gpa, P, 1);
    defer mix.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try providerScenario(&sim);
    const p = mix.protocol();

    // A packet client 1 sent to client 0, as it leaves the last layer.
    const hdr = MixHeader{ .kind = .real, .id = 42, .hop = 3, .n_hops = 3, .route = .{ 0, 3, 6, P.providerOf(0), 0, 0, 0 }, .recipient = P.clientNode(0) };
    try mix.relay.sent.put(gpa, 42, .{ .client = 1, .at = 0, .kind = .real, .recipient = P.clientNode(0) });
    var buf: [MixHeader.wire_len]u8 = undefined;
    hdr.encode(&buf);

    // At the provider: from a first-layer mix or from a client it is refused;
    // from a last-layer mix it lands in client 0's mailbox.
    try p.onMessageFn(p.ctx, &sim, P.providerOf(0), P.mixNode(0, 0), &buf);
    try p.onMessageFn(p.ctx, &sim, P.providerOf(0), P.clientNode(2), &buf);
    try testing.expectEqual(@as(u64, 2), mix.relay.malformed);
    try testing.expectEqual(@as(usize, 0), mix.relay.mailboxes[0].items.len);
    try p.onMessageFn(p.ctx, &sim, P.providerOf(0), P.mixNode(2, 1), &buf);
    try testing.expectEqual(@as(usize, 1), mix.relay.mailboxes[0].items.len);

    // At the clients: the wrong one refuses it, the right one takes it once.
    try mix.relay.clientMessage(&sim, P.clientNode(2), &buf);
    try mix.relay.clientMessage(&sim, P.clientNode(0), &buf);
    try mix.relay.clientMessage(&sim, P.clientNode(0), &buf);
    try testing.expectEqual(@as(usize, 1), mix.deliveries().len);
    try testing.expectEqual(@as(u8, 0), mix.deliveries()[0].recipient);
    try testing.expectEqual(@as(u64, 2), mix.relay.misdelivered);
}

// ── fuzz: hostile packets into the relay handlers ───────────────────────────
//
// Every handler a node runs on a received payload (`acceptAtMix`,
// `providerMessage`, `clientMessage`, the fetch answer) is fed attacker-shaped
// bytes: wild octets, a well-formed header damaged by 0-3 octets, headers whose
// route names the receiving mix (so the packet is stashed), mailbox fetches and
// fetch answers with a lying count. The registry of sent packets holds a few
// ids so the delivery paths are reachable. Nothing may panic; a delivery names
// an id that was sent; the counters stay consistent.

const fz = @import("fuzz_test.zig");
const testkit = @import("testkit");
const InjectMark = fz.Marker(enum { fifo, poisson, direct, providers, malformed_counted, stashed_at_mix, mailbox_filled, fetch_answered, delivered });

fn hostilePayload(comptime S: type, src: *S, cfg: LoopixConfig, node_ptr: *NodeId, from_ptr: *NodeId, buf: []u8) []const u8 {
    const node = node_ptr.*;
    const kinds = [_]MsgKind{ .real, .loop_cover, .drop_cover };
    switch (src.index(7)) {
        0 => {
            const n = src.slice(buf[0..160]);
            return buf[0..n];
        },
        1, 5 => |which| {
            var hdr = MixHeader{
                .kind = kinds[src.index(3)],
                .id = src.valueRangeAtMost(u64, 0, 6),
                .hop = 0,
                .n_hops = src.valueRangeAtMost(u8, 0, types.max_layers),
                .route = undefined,
            };
            hdr.hop = src.valueRangeAtMost(u8, 0, hdr.n_hops);
            for (&hdr.route) |*r| r.* = @intCast(src.index(cfg.nodeCount()));
            if (which == 5 and hdr.hop < hdr.n_hops) hdr.route[hdr.hop] = node; // names this node: the packet is stashed
            hdr.has_delays = src.value(bool);
            for (&hdr.delays) |*d| d.* = src.valueRangeAtMost(u32, 0, 60);
            hdr.recipient = @intCast(src.index(cfg.nodeCount()));
            var enc: [MixHeader.wire_len]u8 = undefined;
            hdr.encode(&enc);
            const n = fz.damage(src, buf[0..MixHeader.wire_len], &enc);
            return buf[0..n];
        },
        2 => {
            buf[0] = FETCH_REQ;
            return buf[0..1];
        },
        3 => {
            // A fetch answer: a count that may lie about what follows.
            buf[0] = FETCH_RESP;
            buf[1] = src.valueRangeAtMost(u8, 0, 4);
            var enc: [MixHeader.wire_len]u8 = undefined;
            var hdr = MixHeader{ .kind = .real, .id = src.valueRangeAtMost(u64, 0, 6), .hop = 3, .n_hops = 3, .route = @splat(node), .recipient = node };
            hdr.encode(&enc);
            const have = src.valueRangeAtMost(u8, 0, 2);
            var off: usize = 2;
            for (0..have) |_| {
                @memcpy(buf[off..][0..enc.len], &enc);
                off += enc.len;
            }
            return buf[0 .. off - if (src.value(bool) and off > 2) src.index(off - 2) else 0];
        },
        6 => {
            // A last-layer mix handing a packet to its recipient's provider: the
            // one shape that lands in a mailbox (provider topology) or is
            // delivered (direct topology), when the header is intact.
            const c: u8 = @intCast(src.index(cfg.clients));
            const dest: NodeId = if (cfg.providers > 0) cfg.providerOf(c) else cfg.clientNode(c);
            node_ptr.* = dest;
            from_ptr.* = cfg.mixNode(cfg.layers - 1, @intCast(src.index(cfg.width)));
            var hdr = MixHeader{ .kind = .real, .id = src.valueRangeAtMost(u64, 0, 6), .hop = 3, .n_hops = 3, .route = @splat(0), .recipient = cfg.clientNode(c) };
            hdr.route[3] = dest;
            var enc: [MixHeader.wire_len]u8 = undefined;
            hdr.encode(&enc);
            const n = fz.damage(src, buf[0..MixHeader.wire_len], &enc);
            return buf[0..n];
        },
        else => return buf[0..0],
    }
}

fn injectInto(comptime M: type, mix: *M, cfg: LoopixConfig, comptime scen: anytype, comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, mix.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scen(&sim);
    const p = mix.protocol();
    // A few packets "sent", so a hostile header can name a real one.
    for (0..7) |id| try mix.relay.sent.put(gpa, id, .{ .client = @intCast(id % cfg.clients), .at = 0, .kind = .real, .recipient = cfg.clientNode(@intCast((id + 1) % cfg.clients)) });

    var buf: [fetch_resp_len + 8]u8 = undefined;
    for (0..24) |_| {
        var node: NodeId = @intCast(src.index(cfg.nodeCount()));
        var from: NodeId = @intCast(src.index(cfg.nodeCount()));
        const payload = hostilePayload(S, src, cfg, &node, &from, &buf);
        try p.onMessageFn(p.ctx, &sim, node, from, payload);
    }

    const relay = &mix.relay;
    if (relay.malformed > 0) InjectMark.mark(.malformed_counted);
    for (relay.queues) |q| if (q.items.len != 0) {
        InjectMark.mark(.stashed_at_mix);
        break;
    };
    for (relay.mailboxes) |m| if (m.items.len != 0) {
        InjectMark.mark(.mailbox_filled);
        break;
    };
    if (relay.fetch_lens.items.len != 0) InjectMark.mark(.fetch_answered);
    if (relay.deliveries.items.len != 0) InjectMark.mark(.delivered);
    for (relay.deliveries.items) |d| if (!relay.sent.contains(d.id)) return error.DeliveryOfUnsentPacket;
    if (relay.deliveries.items.len > relay.sent.count()) return error.MoreDeliveriesThanPackets;
}

fn fuzzInject(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    const poisson = src.value(bool);
    const providers = src.value(bool);
    if (poisson) InjectMark.mark(.poisson) else InjectMark.mark(.fifo);
    if (providers) InjectMark.mark(.providers) else InjectMark.mark(.direct);
    const seed = src.value(u64);
    if (providers) {
        const cfg = PROVIDER_CFG;
        if (poisson) {
            var mix = try Loopix.init(gpa, cfg, seed);
            defer mix.deinit(gpa);
            try injectInto(Loopix, &mix, cfg, providerScenario, S, src, gpa);
        } else {
            var mix = try FifoMix.init(gpa, cfg);
            defer mix.deinit(gpa);
            try injectInto(FifoMix, &mix, cfg, providerScenario, S, src, gpa);
        }
    } else {
        const cfg = DEFAULT_CFG;
        if (poisson) {
            var mix = try Loopix.init(gpa, cfg, seed);
            defer mix.deinit(gpa);
            try injectInto(Loopix, &mix, cfg, scenario, S, src, gpa);
        } else {
            var mix = try FifoMix.init(gpa, cfg);
            defer mix.deinit(gpa);
            try injectInto(FifoMix, &mix, cfg, scenario, S, src, gpa);
        }
    }
}

fn fuzzInjectSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzInject(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: hostile packets into the relay handlers never panic or mis-deliver" {
    try testing.fuzz({}, fuzzInjectSmith, .{});
}

test "fuzz driver: LOOPIX_FUZZ (inject)" {
    try fz.fuzz_driver.run(fuzzInject, .{ .prefix = "LOOPIX_FUZZ", .name = "loopix-inject" });
}

test "fuzz harness: hostile packets, 300 seeds, reaches every outcome" {
    try InjectMark.reach(fuzzInject, "loopix-inject", 300);
}
