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
const BATCH_TIMER: u64 = 4;
const MIX_LOOP_TIMER: u64 = 5;

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

/// The scenario for any configuration: `Case.scenario` is a bare function
/// pointer, so each configuration gets its own, built at compile time.
pub fn scenarioFor(comptime cfg: LoopixConfig) netsim.Scenario {
    return struct {
        fn build(sim: *Sim) anyerror!void {
            try buildTopology(sim, cfg);
        }
    }.build;
}

/// Adds each directed link once, whichever wiring rule asks for it.
const Wiring = struct {
    sim: *Sim,
    done: std.bit_set.ArrayBitSet(usize, 256 * 256) = .empty,

    fn bi(self: *Wiring, a: NodeId, b: NodeId) anyerror!void {
        if (!self.done.isSet(@as(usize, a) * 256 + b)) {
            self.done.set(@as(usize, a) * 256 + b);
            try self.sim.addLink(a, b, LINK);
        }
        if (!self.done.isSet(@as(usize, b) * 256 + a)) {
            self.done.set(@as(usize, b) * 256 + a);
            try self.sim.addLink(b, a, LINK);
        }
    }
};

fn buildTopology(sim: *Sim, cfg: LoopixConfig) anyerror!void {
    var wire = Wiring{ .sim = sim };
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
        while (c < cfg.clients) : (c += 1) try wire.bi(cfg.clientNode(c), cfg.providerOf(c));
    }
    switch (cfg.topology) {
        .stratified => {
            for (edge[0..edges]) |e| {
                var w: u8 = 0;
                while (w < cfg.width) : (w += 1) try wire.bi(e, cfg.mixNode(0, w));
            }
            // adjacent mix layers, fully connected
            var l: u8 = 0;
            while (l + 1 < cfg.layers) : (l += 1) {
                var a: u8 = 0;
                while (a < cfg.width) : (a += 1) {
                    var b: u8 = 0;
                    while (b < cfg.width) : (b += 1) try wire.bi(cfg.mixNode(l, a), cfg.mixNode(l + 1, b));
                }
            }
            // last layer ↔ the receiving edge (a no-op for a 1-layer net already linked)
            var w: u8 = 0;
            while (w < cfg.width) : (w += 1) {
                for (edge[0..edges]) |e| try wire.bi(cfg.mixNode(cfg.layers - 1, w), e);
            }
        },
        .cascade, .multi_cascade => {
            // `width` chains; a link joins consecutive mixes of ONE chain only.
            var w: u8 = 0;
            while (w < cfg.width) : (w += 1) {
                for (edge[0..edges]) |e| {
                    try wire.bi(e, cfg.mixNode(0, w));
                    try wire.bi(cfg.mixNode(cfg.layers - 1, w), e);
                }
                var l: u8 = 0;
                while (l + 1 < cfg.layers) : (l += 1) try wire.bi(cfg.mixNode(l, w), cfg.mixNode(l + 1, w));
            }
        },
        .free_route => {
            // every mix reaches every other, and the edge reaches every mix
            const m: NodeId = @intCast(cfg.mixCount());
            var a: NodeId = 0;
            while (a < m) : (a += 1) {
                for (edge[0..edges]) |e| try wire.bi(e, a);
                var b: NodeId = a + 1;
                while (b < m) : (b += 1) try wire.bi(a, b);
            }
        },
    }
    if (cfg.mix_loop_interval > 0) {
        // A mix's own loop leaves it for a first-hop mix and returns from a
        // last-hop mix: overlay legs outside the layered wiring.
        var a: NodeId = 0;
        while (a < cfg.mixCount()) : (a += 1) {
            // ...and a mix can be both ends of its own loop's first or last leg.
            try wire.bi(a, a);
            var b: NodeId = 0;
            while (b < cfg.mixCount()) : (b += 1) {
                if (a != b and (cfg.layerOf(b).? == 0 or cfg.isExitMix(a)))
                    try wire.bi(a, b);
            }
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
    /// Loops the MIXES sent to themselves (`LoopixConfig.mix_loop_interval`).
    mix_cover_sent: usize = 0,
    /// Cover packets (clients' and mixes') per real packet — the bandwidth overhead of the cover.
    overhead: f64 = 0,
    mean_latency: f64 = 0,
    max_latency: Time = 0,
    /// Every byte the protocol put on any link: client packets, mix-to-mix
    /// forwards, provider forwards, mailbox requests and the padded mailbox
    /// answers. What the network carries, cover and padding included.
    link_bytes: u64 = 0,
    /// The bytes of mailbox answers alone (`fetch_batch` slots each, padded).
    fetch_bytes: u64 = 0,
    /// `link_bytes` per real packet delivered — the bandwidth cost in bytes of
    /// one application message, everything included (0 if none delivered).
    bytes_per_real: f64 = 0,
};

const Sent = struct { client: u8, at: Time, kind: MsgKind, recipient: NodeId };

/// A loop a mix sent to itself.
const MixSent = struct { mix: NodeId, at: Time };

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
    /// Mixes' own loops in flight or home, and when each came home.
    mix_sent: std.AutoHashMapUnmanaged(u64, MixSent) = .empty,
    mix_returned: std.AutoHashMapUnmanaged(u64, Time) = .empty,
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
    /// Bytes put on links (`send`), and of those the mailbox answers'.
    link_bytes: u64 = 0,
    fetch_bytes: u64 = 0,
    next_id: u64 = 1,
    real_seq: u64 = 0,
    cover_seq: u64 = 0,
    mix_loop_seq: u64 = 0,

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
        self.mix_sent.deinit(gpa);
        self.mix_returned.deinit(gpa);
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
        self.mix_sent.clearRetainingCapacity();
        self.mix_returned.clearRetainingCapacity();
        self.deliveries.clearRetainingCapacity();
        self.delivered.clearRetainingCapacity();
        self.fetch_lens.clearRetainingCapacity();
        self.malformed = 0;
        self.misdelivered = 0;
        self.link_bytes = 0;
        self.fetch_bytes = 0;
        self.next_id = 1;
        self.real_seq = 0;
        self.cover_seq = 0;
        self.mix_loop_seq = 0;
    }

    /// Every send of the protocol goes through here, so the byte count is
    /// exactly what the links were handed.
    fn send(self: *Relay, sim: *Sim, from: NodeId, to: NodeId, bytes: []const u8) anyerror!void {
        self.link_bytes += bytes.len;
        try sim.send(from, to, bytes);
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
        try self.send(sim, self.cfg.clientNode(src_client), first, &buf);
        try self.origins.append(self.gpa, .{
            .id = hdr.id,
            .client = src_client,
            .recipient = if (self.cfg.isClient(hdr.recipient)) self.cfg.clientIndex(hdr.recipient) else null,
        });
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

    /// A MIX sends a loop through the network back to itself. With `delays`
    /// (and `sender_chosen_delays`) it draws every hop's hold, like a client.
    /// It leaves for the first hop directly. Returns the header.
    fn originateMixLoop(self: *Relay, sim: *Sim, mix: NodeId, delays: ?*mixing.Prng) anyerror!MixHeader {
        var hdr = MixHeader{ .kind = .loop_cover, .id = self.next_id, .hop = 0, .n_hops = 0, .route = undefined };
        @memset(&hdr.route, 0);
        self.next_id += 1;
        self.mix_loop_seq += 1;
        routing.pickMixLoopRoute(self.cfg, (@as(u64, mix) << 40) | (self.mix_loop_seq << 1) | 1, mix, &hdr);
        if (self.cfg.sender_chosen_delays) {
            if (delays) |prng| {
                hdr.has_delays = true;
                for (hdr.delays[0..hdr.n_hops]) |*d| d.* = @intCast(mixing.sampleExpDelay(prng, self.cfg.mean_delay));
            }
        }
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        try self.send(sim, mix, hdr.route[0], &buf);
        try self.origins.append(self.gpa, .{ .id = hdr.id, .client = 0, .from_mix = true });
        try self.mix_sent.put(self.gpa, hdr.id, .{ .mix = mix, .at = sim.timeNow() });
        return hdr;
    }

    /// A packet that ends at this mix: one of ITS OWN loops coming home.
    /// True when `payload` was exactly that (and records it).
    fn mixLoopReturn(self: *Relay, node: NodeId, payload: []const u8) bool {
        const hdr = MixHeader.decode(payload) catch return false;
        if (hdr.hop != hdr.n_hops or hdr.route[hdr.n_hops] != node) return false;
        const s = self.mix_sent.get(hdr.id) orelse return false;
        if (s.mix != node) return false;
        if (self.mix_returned.contains(hdr.id)) {
            self.misdelivered += 1;
            return true;
        }
        self.mix_returned.put(self.gpa, hdr.id, 0) catch return false;
        return true;
    }

    /// Batch strategies: hold the packet until the batch is released.
    fn stashBatch(self: *Relay, sim: *Sim, node: NodeId, hdr: MixHeader) anyerror!void {
        const now = sim.timeNow();
        try self.queues[node].append(self.gpa, .{ .arrival = now, .release_at = now, .hdr = hdr });
    }

    /// Release EVERYTHING the mix holds, now, in a random order.
    fn flushBatch(self: *Relay, sim: *Sim, node: NodeId, prng: *mixing.Prng) anyerror!void {
        const q = &self.queues[node];
        mixing.shuffle(Stashed, prng, q.items);
        for (q.items) |s| try self.forward(sim, node, s);
        q.clearRetainingCapacity();
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
        try self.forward(sim, node, s);
    }

    /// Log the completed pass of `s` through `node` and send it on.
    fn forward(self: *Relay, sim: *Sim, node: NodeId, s: Stashed) anyerror!void {
        var hdr = s.hdr;
        // Record the completed pass through THIS mix (the adversary's raw
        // material — timing and the link taken; id/kind are the harness's
        // oracle labels).
        const hop = hdr.hop;
        hdr.hop += 1; // advance to the next relay (route[hop] now the successor)
        const next = hdr.route[hdr.hop];
        try self.transcript.append(self.gpa, .{
            .mix = node,
            .arrival = s.arrival,
            .departure = sim.timeNow(),
            .kind = hdr.kind,
            .id = hdr.id,
            .hop = hop,
            .to = next,
        });
        var buf: [MixHeader.wire_len]u8 = undefined;
        hdr.encode(&buf);
        try self.send(sim, node, next, &buf);
    }

    /// The header a MIX may act on: it decodes, and names this node as the
    /// mix of its current hop. Anything else is dropped and counted — a mix
    /// that trusted `hop` would index `route[hop + 1]` past the route on the
    /// way out (review, L-02: an all-zero header has n_hops 0).
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
            self.fetch_bytes += len;
            try self.send(sim, node, from, buf[0..len]);
            return;
        }
        const hdr = MixHeader.decode(payload) catch {
            self.malformed += 1;
            return;
        };
        if (hdr.hop == 0 and hdr.n_hops > 0 and cfg.isClient(from) and cfg.providerOf(cfg.clientIndex(from)) == node) {
            var buf: [MixHeader.wire_len]u8 = undefined;
            hdr.encode(&buf);
            try self.send(sim, node, hdr.route[0], &buf);
        } else if (hdr.n_hops > 0 and hdr.hop == hdr.n_hops and hdr.route[hdr.n_hops] == node and
            cfg.isExitMix(from) and cfg.isClient(hdr.recipient) and
            cfg.providerOf(cfg.clientIndex(hdr.recipient)) == node)
        {
            // Only out of the last layer, only to this provider, only for one
            // of ITS clients (review, L-10).
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
        // Exactly once, and only to the client the sender addressed (review, L-08/L-09: counts alone let a loss and a duplicate
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
        try self.send(sim, node, self.cfg.providerOf(self.cfg.clientIndex(node)), &.{FETCH_REQ});
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
        if (st.real_sent > 0) st.overhead = @as(f64, @floatFromInt(st.cover_sent + self.mix_sent.count())) / @as(f64, @floatFromInt(st.real_sent));
        st.mix_cover_sent = self.mix_sent.count();
        st.link_bytes = self.link_bytes;
        st.fetch_bytes = self.fetch_bytes;
        if (st.real_delivered > 0) st.bytes_per_real = @as(f64, @floatFromInt(self.link_bytes)) / @as(f64, @floatFromInt(st.real_delivered));
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

/// A mix that gave up on its own loops (`LoopixConfig.mix_loop_alarm_lost`).
pub const MixAlarm = struct { mix: NodeId, at: Time };

const LoopWatch = struct { client: u8, deadline: Time };
const MixLoopWatch = struct { mix: NodeId, deadline: Time };

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
    /// The mixes' own loops in flight (`LoopixConfig.mix_loop_interval`), the
    /// loops each mix has given up on, those watched / that came home, and
    /// the mixes' alarms.
    mix_loops: std.AutoHashMapUnmanaged(u64, MixLoopWatch) = .empty,
    mix_lost: []u32,
    mix_loops_watched: u64 = 0,
    mix_loops_returned: u64 = 0,
    mix_alarms: std.ArrayListUnmanaged(MixAlarm) = .empty,

    pub fn init(gpa: Allocator, cfg: LoopixConfig, rng_seed: u64) InitError!Loopix {
        var relay = try Relay.init(gpa, cfg);
        errdefer relay.deinit(gpa);
        const lost = try gpa.alloc(u32, cfg.clients);
        errdefer gpa.free(lost);
        @memset(lost, 0);
        const mix_lost = try gpa.alloc(u32, cfg.mixCount());
        @memset(mix_lost, 0);
        return .{ .relay = relay, .prng = mixing.Prng.init(rng_seed), .rng_seed = rng_seed, .lost = lost, .mix_lost = mix_lost };
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
        self.mix_loops.deinit(gpa);
        self.mix_alarms.deinit(gpa);
        gpa.free(self.mix_lost);
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
        self.mix_loops.clearRetainingCapacity();
        @memset(self.mix_lost, 0);
        self.mix_loops_watched = 0;
        self.mix_loops_returned = 0;
        self.mix_alarms.clearRetainingCapacity();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const cfg = self.relay.cfg;
        if (cfg.isMix(node)) {
            if (cfg.mix_strategy == .timed) try sim.setTimer(node, cfg.batch_period, BATCH_TIMER);
            if (cfg.mix_loop_interval > 0) try sim.setTimer(node, mixing.nextMixLoop(&self.prng, cfg), MIX_LOOP_TIMER);
        }
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
                if (ev.kind == .loop_cover) try self.watchLoop(sim, cfg.clientIndex(node), hdr);
                try self.checkLoops(sim, cfg.clientIndex(node));
                try sim.setTimer(node, ev.delay, COVER_TIMER);
            },
            FETCH_TIMER => {
                try self.relay.fetch(sim, node);
                try self.checkLoops(sim, cfg.clientIndex(node));
            },
            RELEASE_TIMER => try self.relay.release(sim, node),
            BATCH_TIMER => {
                try self.relay.flushBatch(sim, node, &self.prng);
                try sim.setTimer(node, cfg.batch_period, BATCH_TIMER);
            },
            MIX_LOOP_TIMER => {
                const hdr = try self.relay.originateMixLoop(sim, node, &self.prng);
                try self.watchMixLoop(sim, node, hdr);
                try self.checkMixLoops(sim, node);
                try sim.setTimer(node, mixing.nextMixLoop(&self.prng, cfg), MIX_LOOP_TIMER);
            },
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
        // One of this mix's own loops coming home.
        if (cfg.mix_loop_interval > 0 and self.relay.mixLoopReturn(node, payload)) return;
        const hdr = self.relay.acceptAtMix(node, payload) orelse return;
        switch (cfg.mix_strategy) {
            .poisson => {
                // The Poisson mix's independent exponential hold: the
                // sender's draw if the packet carries one, else the mix's own.
                const hold: Time = if (hdr.has_delays)
                    hdr.delays[hdr.hop]
                else
                    mixing.scheduleRelease(&self.prng, cfg, now) - now;
                try self.relay.stashAndArm(sim, node, hdr, hold);
            },
            .threshold => {
                try self.relay.stashBatch(sim, node, hdr);
                if (self.relay.queues[node].items.len >= cfg.threshold) try self.relay.flushBatch(sim, node, &self.prng);
            },
            .timed => try self.relay.stashBatch(sim, node, hdr), // the batch timer releases it
        }
    }

    /// The latest a packet can be home once its route is fixed, in hold time
    /// alone: the sender's own draws (Poisson with sender-chosen holds), one
    /// full period per hop (timed batches). `null` when the holds cannot be
    /// known (mix-chosen holds; a threshold batch waits for traffic).
    fn holdBound(self: *const Loopix, hdr: MixHeader) ?Time {
        var bound: Time = 0;
        switch (self.relay.cfg.mix_strategy) {
            .poisson => {
                if (!hdr.has_delays) return null;
                for (hdr.delays[0..hdr.n_hops]) |d| bound += d;
            },
            .timed => bound = @as(Time, hdr.n_hops) * self.relay.cfg.batch_period,
            .threshold => return null,
        }
        return bound;
    }

    /// A mix's loop is watched like a client's, minus the provider legs: it
    /// goes mix → first hop → … → last hop → mix, `n_hops + 1` links.
    fn watchMixLoop(self: *Loopix, sim: *Sim, mix: NodeId, hdr: MixHeader) anyerror!void {
        const cfg = self.relay.cfg;
        const hold = self.holdBound(hdr) orelse return;
        const bound = hold + (@as(Time, hdr.n_hops) + 1) * max_link_latency;
        try self.mix_loops.put(self.relay.gpa, hdr.id, .{ .mix = mix, .deadline = sim.timeNow() + bound + cfg.loop_slack });
        self.mix_loops_watched += 1;
    }

    /// Settle `mix`'s loops, as `checkLoops` does for a client.
    fn checkMixLoops(self: *Loopix, sim: *Sim, mix: NodeId) anyerror!void {
        const now = sim.timeNow();
        var done: std.ArrayListUnmanaged(u64) = .empty;
        defer done.deinit(self.relay.gpa);
        var it = self.mix_loops.iterator();
        while (it.next()) |kv| {
            const w = kv.value_ptr.*;
            if (w.mix != mix) continue;
            if (self.relay.mix_returned.contains(kv.key_ptr.*)) {
                try done.append(self.relay.gpa, kv.key_ptr.*);
                self.mix_loops_returned += 1;
            } else if (now > w.deadline) {
                try done.append(self.relay.gpa, kv.key_ptr.*);
                self.mix_lost[mix] += 1;
                if (self.mix_lost[mix] == self.relay.cfg.mix_loop_alarm_lost)
                    try self.mix_alarms.append(self.relay.gpa, .{ .mix = mix, .at = now });
            }
        }
        for (done.items) |id| _ = self.mix_loops.remove(id);
    }

    /// A sender-chosen-delay loop is fully predictable to its sender: the sum
    /// of its own hop holds, plus every link at its worst, plus (behind a
    /// provider) one fetch period of waiting in the mailbox. Past that plus
    /// `loop_slack`, it is lost.
    fn watchLoop(self: *Loopix, sim: *Sim, client: u8, hdr: MixHeader) anyerror!void {
        const cfg = self.relay.cfg;
        var bound: Time = self.holdBound(hdr) orelse return;
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

    // Bytes: every packet the transcript shows leaving a mix, every packet a
    // client sent, and every mailbox answer are on the links, so the total is
    // at least their sum; the answers are exactly the fetch lengths.
    const W = MixHeader.wire_len;
    var fetch_sum: u64 = 0;
    for (lens) |l| fetch_sum += l;
    try testing.expectEqual(fetch_sum, st.fetch_bytes);
    const floor = (mix.transcript().len + st.real_sent + st.cover_sent) * W + fetch_sum;
    try testing.expect(st.link_bytes >= floor);
    // ...and at most each sent packet over every leg (client→provider,
    // provider→layer 0, one per layer, layer→provider) plus the fetch traffic.
    const fetch_reqs = lens.len + P.clients; // at most one unanswered per client
    const ceiling = (st.real_sent + st.cover_sent) * W * (2 + @as(usize, P.layers)) + fetch_sum + fetch_reqs;
    try testing.expect(st.link_bytes <= ceiling);
    try testing.expectEqual(@as(f64, @floatFromInt(st.link_bytes)) / @as(f64, @floatFromInt(st.real_delivered)), st.bytes_per_real);
}

/// A larger network than the anonymity sweeps run: 3 layers × 10 mixes,
/// 120 clients behind 10 providers = 160 nodes.
pub const LARGE_CFG = LoopixConfig{ .width = 10, .clients = 120, .providers = 10, .sender_chosen_delays = true, .real_period = 120 };

pub fn largeScenario(sim: *Sim) anyerror!void {
    try buildTopology(sim, LARGE_CFG);
}

test "scale: 160 nodes deliver every due packet, malformed-free, with per-mix and end-to-end anonymity" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const C = LARGE_CFG;
    var mix = try Loopix.init(gpa, C, 7);
    defer mix.deinit(gpa);
    const until: Time = 1500;
    // Wider than `COOLDOWN`: with ~10x the packets, the tail of three
    // exponential holds past 300 ticks is hit near the horizon.
    const cool: Time = 600;
    _ = try netsim.replay(gpa, .{ .seed = 7, .scenario = largeScenario, .protocol = mix.protocol(), .until = until }, &.{}, null);
    try testing.expectEqual(@as(u64, 0), mix.relay.malformed);
    try testing.expectEqual(@as(u64, 0), mix.relay.misdelivered);
    const st = mix.stats();
    try testing.expect(st.real_sent > 800);
    var due: usize = 0;
    var it = mix.relay.sent.valueIterator();
    while (it.next()) |s| {
        if (s.kind == .real and s.at + cool <= until) due += 1;
    }
    var on_time: usize = 0;
    for (mix.deliveries()) |d| {
        if (d.kind == .real and d.sent + cool <= until) on_time += 1;
    }
    try testing.expectEqual(due, on_time);
    try testing.expect(st.bytes_per_real > @as(f64, @floatFromInt(MixHeader.wire_len * (2 + @as(usize, C.layers)))));
    // Per-mix and end-to-end sender anonymity hold at this size too.
    const exp_model = adversary.DelayModel{ .exponential = @floatFromInt(C.mean_delay) };
    var windowed = try std.ArrayListUnmanaged(Transit).initCapacity(gpa, mix.transcript().len);
    defer windowed.deinit(gpa);
    for (mix.transcript()) |t| {
        var w = t;
        if (t.kind == .real and mix.relay.sent.get(t.id).?.at + cool > until) w.kind = .drop_cover;
        windowed.appendAssumeCapacity(w);
    }
    const r = try adversary.measure(gpa, windowed.items, exp_model);
    try testing.expect(r.holds(types.AnonymityBound{}));
    const e = try adversary.measureEndToEnd(gpa, windowed.items, mix.origins(), C.clients, C.layers - 1, exp_model);
    try testing.expect(e.holds(types.SenderBound{}));
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
    // Measured (see `SenderBound`): real 5.78 / 0.286, FIFO link
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
        var seen = @as([P.clients]bool, @splat(false));
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
const InjectMark = fz.Marker(enum { fifo, poisson, direct, providers, malformed_counted, stashed_at_mix, mailbox_filled, fetch_answered, delivered, free_threshold, multi_timed, batch_flushed });

/// The other topologies, batch strategies and mix loops, for the hostile-packet harness.
const FUZZ_FREE = LoopixConfig{ .topology = .free_route, .mix_strategy = .threshold, .threshold = 3, .mix_loop_interval = 10, .clients = 4, .providers = 2 };
const FUZZ_MULTI = LoopixConfig{ .topology = .multi_cascade, .mix_strategy = .timed, .mix_loop_interval = 10, .clients = 4 };

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
    if (relay.transcript.items.len != 0) InjectMark.mark(.batch_flushed);
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
    const variant = src.index(3); // 0: as before; 1, 2: the other topologies and strategies
    if (poisson and variant != 0) {
        if (variant == 1) {
            InjectMark.mark(.free_threshold);
            var mix = try Loopix.init(gpa, FUZZ_FREE, seed);
            defer mix.deinit(gpa);
            try injectInto(Loopix, &mix, FUZZ_FREE, scenarioFor(FUZZ_FREE), S, src, gpa);
        } else {
            InjectMark.mark(.multi_timed);
            var mix = try Loopix.init(gpa, FUZZ_MULTI, seed);
            defer mix.deinit(gpa);
            try injectInto(Loopix, &mix, FUZZ_MULTI, scenarioFor(FUZZ_MULTI), S, src, gpa);
        }
        return;
    }
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

// ── topologies, batch mixing, mix loops, receiver metrics ────────────────────
//
// Reference: A. Piotrowska, "Studying the anonymity trilemma with a
// discrete-event mix network simulator" (arXiv 2107.12172): cascade,
// multi-cascade, stratified and free-route (P2P) topologies; Poisson and
// batch-and-reorder mixing; cover traffic from clients or mixes; Shannon
// entropy and sender-receiver third-party unlinkability. Same measurement
// basis as above: a clean run, the steady-state window, each mix scored with
// its own law.

const CASCADE = LoopixConfig{ .topology = .cascade, .width = 1, .clients = 8, .providers = 2, .sender_chosen_delays = true };
const MULTI = LoopixConfig{ .topology = .multi_cascade, .clients = 8, .providers = 2, .sender_chosen_delays = true };
const FREE = LoopixConfig{ .topology = .free_route, .clients = 8, .providers = 2, .sender_chosen_delays = true };
const STRAT = PROVIDER_CFG;

/// Run `cfg` clean for `until` ticks (any topology: the scenario is built from
/// `cfg`). The caller owns the result.
fn simulate(gpa: Allocator, comptime cfg: LoopixConfig, seed: u64, until: Time, cover: bool, attack: ?Attack) !Loopix {
    var mix = if (cover) try Loopix.init(gpa, cfg, seed) else try Loopix.initNoCover(gpa, cfg, seed);
    errdefer mix.deinit(gpa);
    mix.attack = attack;
    _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenarioFor(cfg), .protocol = mix.protocol(), .until = until }, &.{}, null);
    return mix;
}

/// The law the adversary links a configuration's mixes with.
fn lawOf(cfg: LoopixConfig) adversary.DelayModel {
    return switch (cfg.mix_strategy) {
        .poisson => .{ .exponential = @floatFromInt(cfg.mean_delay) },
        .threshold, .timed => .batch,
    };
}

/// Relabel real transits that started too late to clear before `until` (see
/// `measureSteadyState`), keeping the caller's order. Caller frees.
fn windowTranscript(gpa: Allocator, mix: *const Loopix, until: Time, cool: Time) ![]Transit {
    const out = try gpa.dupe(Transit, mix.transcript());
    for (out) |*t| {
        if (t.kind == .real and t.arrival + cool > until) t.kind = .drop_cover;
    }
    return out;
}

/// Clients straight on the mixes: a last-hop link names its receiver.
const DIRECT8 = LoopixConfig{ .clients = 8 };

fn withCover(cfg: LoopixConfig, n: Time) LoopixConfig {
    var c = cfg;
    c.cover_mean_interval = n;
    return c;
}

fn withBatch(cfg: LoopixConfig, strategy: types.MixStrategy, threshold: u16, period: Time) LoopixConfig {
    var c = cfg;
    c.mix_strategy = strategy;
    c.threshold = threshold;
    c.batch_period = period;
    return c;
}

fn withLoops(cfg: LoopixConfig, n: Time) LoopixConfig {
    var c = cfg;
    c.mix_loop_interval = n;
    return c;
}

const seeds_per_score = 5;

/// Everything the topology / batch / mix-loop / receiver tests read off a
/// configuration, over `seeds_per_score` clean seeds (worst case of the
/// worst-case measures, mean of the means).
const Score = struct {
    mix_mean_set: f64 = 0,
    mix_min_set: f64 = std.math.inf(f64),
    mix_max_link: f64 = 0,
    recv_min_set: f64 = std.math.inf(f64),
    recv_max_link: f64 = 0,
    e2e_mean_set: f64 = 0,
    e2e_min_set: f64 = std.math.inf(f64),
    e2e_max_link: f64 = 0,
    eps_mean: f64 = 0,
    eps_max: f64 = 0,
    latency: f64 = 0,
    /// Real packets due before the horizon that were not delivered.
    missing: usize = 0,
    /// Packets dropped as malformed + delivered wrongly + e2e fallbacks.
    bad: u64 = 0,
    loops_watched: u64 = 0,
    loops_returned: u64 = 0,
    alarms: usize = 0,
};

fn score(gpa: Allocator, comptime cfg: LoopixConfig, cover: bool, attack: ?Attack) !Score {
    var sc = Score{};
    const k: f64 = seeds_per_score;
    for (1..seeds_per_score + 1) |seed| {
        var mix = try simulate(gpa, cfg, seed, UNTIL, cover, attack);
        defer mix.deinit(gpa);
        const tr = try windowTranscript(gpa, &mix, UNTIL, COOLDOWN);
        defer gpa.free(tr);
        const m = try adversary.measure(gpa, tr, lawOf(cfg));
        const e = try adversary.measureEndToEnd(gpa, tr, mix.origins(), cfg.clients, cfg.layers - 1, lawOf(cfg));
        const rows = try cfg.exitRows(gpa);
        defer gpa.free(rows);
        const r = try adversary.measureReceiver(gpa, tr, mix.origins(), rows, cfg.clients, cfg.layers - 1, lawOf(cfg));
        sc.mix_mean_set += m.mean_effective_set / k;
        sc.mix_min_set = @min(sc.mix_min_set, m.min_effective_set);
        sc.mix_max_link = @max(sc.mix_max_link, m.max_link_prob);
        sc.recv_min_set = @min(sc.recv_min_set, r.min_receiver_set);
        sc.recv_max_link = @max(sc.recv_max_link, r.max_link_prob);
        sc.e2e_mean_set += e.mean_sender_set / k;
        sc.e2e_min_set = @min(sc.e2e_min_set, e.min_sender_set);
        sc.e2e_max_link = @max(sc.e2e_max_link, e.max_link_prob);
        sc.eps_mean += e.mean_epsilon / k;
        sc.eps_max = @max(sc.eps_max, e.max_epsilon);
        sc.latency += mix.stats().mean_latency / k;
        sc.bad += mix.relay.malformed + mix.relay.misdelivered + e.fallbacks;
        sc.loops_watched += mix.mix_loops_watched;
        sc.loops_returned += mix.mix_loops_returned;
        sc.alarms += mix.mix_alarms.items.len;
        var due: usize = 0;
        var it = mix.relay.sent.iterator();
        while (it.next()) |kv| {
            const s = kv.value_ptr.*;
            if (s.kind == .real and s.at + 2 * COOLDOWN <= UNTIL) {
                due += 1;
                if (!mix.relay.delivered.contains(kv.key_ptr.*)) sc.missing += 1;
            }
        }
    }
    return sc;
}

/// The FIFO positive control over `cfg`, scored the same way.
fn scoreFifo(gpa: Allocator, comptime cfg: LoopixConfig) !Score {
    var sc = Score{};
    const k: f64 = seeds_per_score;
    for (1..seeds_per_score + 1) |seed| {
        var mix = try FifoMix.init(gpa, cfg);
        defer mix.deinit(gpa);
        _ = try netsim.replay(gpa, .{ .seed = seed, .scenario = scenarioFor(cfg), .protocol = mix.protocol(), .until = UNTIL }, &.{}, null);
        const tr = try gpa.dupe(Transit, mix.transcript());
        defer gpa.free(tr);
        for (tr) |*t| {
            if (t.kind == .real and t.arrival + COOLDOWN > UNTIL) t.kind = .drop_cover;
        }
        const law = adversary.DelayModel{ .constant = .{ .delta = cfg.fifo_delay, .tol = 0 } };
        const e = try adversary.measureEndToEnd(gpa, tr, mix.origins(), cfg.clients, cfg.layers - 1, law);
        const rows = try cfg.exitRows(gpa);
        defer gpa.free(rows);
        const r = try adversary.measureReceiver(gpa, tr, mix.origins(), rows, cfg.clients, cfg.layers - 1, law);
        sc.recv_min_set = @min(sc.recv_min_set, r.min_receiver_set);
        sc.recv_max_link = @max(sc.recv_max_link, r.max_link_prob);
        sc.eps_mean += e.mean_epsilon / k;
        sc.eps_max = @max(sc.eps_max, e.max_epsilon);
    }
    return sc;
}

// ── item 1: topologies beyond stratified ─────────────────────────────────────

test "topologies: the wiring has exactly the links each one needs" {
    const gpa = testing.allocator;
    // Directed links. Every case: 8 clients ↔ 2 providers = 16.
    //   cascade (3 in a chain):   providers ↔ first, last 4+4, chain 2 pairs · 2 = 4
    //   multi-cascade (3 chains): 12 + 12, chains 3 · 2 pairs · 2 = 12
    //   free route (9 mixes):     providers ↔ every mix 2·9·2 = 36, every mix pair 36 · 2 = 72
    const Case = struct { cfg: LoopixConfig, links: usize };
    inline for ([_]Case{ .{ .cfg = CASCADE, .links = 16 + 8 + 4 }, .{ .cfg = MULTI, .links = 16 + 24 + 12 }, .{ .cfg = FREE, .links = 16 + 36 + 72 } }) |c| {
        var mix = try Loopix.init(gpa, c.cfg, 1);
        defer mix.deinit(gpa);
        const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = scenarioFor(c.cfg), .protocol = mix.protocol(), .until = UNTIL });
        defer gpa.free(topo.links);
        try testing.expectEqual(c.cfg.nodeCount(), topo.node_count);
        try testing.expectEqual(c.links, topo.links.len);
    }
}

test "topologies: a cascade keeps the chain order, a multi-cascade keeps each packet in one chain, a free route repeats no mix" {
    const gpa = testing.allocator;
    inline for (.{ CASCADE, MULTI, FREE }) |cfg| {
        var mix = try simulate(gpa, cfg, 2, UNTIL, true, null);
        defer mix.deinit(gpa);
        var chain_of: std.AutoHashMapUnmanaged(u64, NodeId) = .empty;
        defer chain_of.deinit(gpa);
        var seen_at: std.AutoHashMapUnmanaged(u64, std.StaticBitSet(256)) = .empty;
        defer seen_at.deinit(gpa);
        try testing.expect(mix.transcript().len > 500);
        for (mix.transcript()) |t| {
            switch (cfg.topology) {
                .cascade, .multi_cascade => {
                    try testing.expectEqual(@as(?u8, t.hop), cfg.layerOf(t.mix)); // hop h = layer h
                    const w = t.mix % cfg.width;
                    const gop = try chain_of.getOrPut(gpa, t.id);
                    if (gop.found_existing) try testing.expectEqual(gop.value_ptr.*, w) else gop.value_ptr.* = w;
                },
                else => {
                    const gop = try seen_at.getOrPut(gpa, t.id);
                    if (!gop.found_existing) gop.value_ptr.* = .empty;
                    try testing.expect(!gop.value_ptr.isSet(t.mix)); // never the same mix twice
                    gop.value_ptr.set(t.mix);
                },
            }
        }
    }
}

test "topologies: every due packet is delivered through a cascade, a multi-cascade and a free route" {
    const gpa = testing.allocator;
    inline for (.{ CASCADE, MULTI, FREE }) |cfg| {
        const sc = try score(gpa, cfg, true, null);
        try testing.expectEqual(@as(usize, 0), sc.missing);
        try testing.expectEqual(@as(u64, 0), sc.bad);
        // The per-mix invariant and the receiver bound hold with cover.
        try testing.expect(sc.mix_min_set >= (types.AnonymityBound{}).min_effective_set + 0.5);
        try testing.expect(sc.mix_max_link <= (types.AnonymityBound{}).max_link_prob - 0.05);
        try testing.expect(sc.recv_min_set >= (types.ReceiverBound{}).min_receiver_set + 1);
        try testing.expect(sc.recv_max_link <= (types.ReceiverBound{}).max_link_prob);
    }
}

test "topologies compared (the paper's scalability result): a cascade pools every packet in each mix, multi-cascade and free route spread traffic thin" {
    const gpa = testing.allocator;
    // Light cover (1 per 100 ticks per client) so the topology, not the chaff, decides.
    const cascade = try score(gpa, comptime withCover(CASCADE, 100), true, null);
    const multi = try score(gpa, comptime withCover(MULTI, 100), true, null);
    const free = try score(gpa, comptime withCover(FREE, 100), true, null);
    const strat = try score(gpa, comptime withCover(STRAT, 100), true, null);
    // Measured (5 seeds): mean per-mix set 38.0 / 13.3 / 13.3 / 13.4; mean sender
    // set 7.91 / 7.07 / 7.33 / 7.86 of 8; mean leakage ε 0.00 / 0.50 / 0.27 / 0.02 nats.
    // A cascade's mixes each carry all the traffic, so their sets are ~3x the others'.
    try testing.expect(cascade.mix_mean_set > 2.5 * strat.mix_mean_set);
    try testing.expect(@abs(multi.mix_mean_set - strat.mix_mean_set) < 0.1 * strat.mix_mean_set);
    // Stratified mixes across chains; a multi-cascade's packets only ever meet
    // their own chain's traffic, a free route's mixes see few packets at a time.
    try testing.expect(strat.e2e_mean_set > multi.e2e_mean_set + 0.4);
    try testing.expect(strat.e2e_mean_set > free.e2e_mean_set + 0.3);
    try testing.expect(multi.eps_mean > strat.eps_mean + 0.2);
    try testing.expect(free.eps_mean > strat.eps_mean + 0.1);
    try testing.expect(cascade.e2e_mean_set >= strat.e2e_mean_set);
    // Worst packet's sender set (of 8) 6.97 / 2.00 / 1.66 / 5.01: only the
    // cascade and the stratified net keep every packet in a real crowd.
    try testing.expect(cascade.e2e_min_set > 6 and strat.e2e_min_set > (types.SenderBound{}).min_sender_set);
    try testing.expect(multi.e2e_min_set < 2.5 and free.e2e_min_set < 2.5);
}

// ── item 5: anonymity rises with the cover rate (the paper's cover-traffic result) ──

test "cover: more cover, larger sets and smaller linking probability" {
    const gpa = testing.allocator;
    const low = try score(gpa, comptime withCover(STRAT, 40), true, null);
    const mid = try score(gpa, STRAT, true, null);
    const high = try score(gpa, comptime withCover(STRAT, 6), true, null);
    // Measured: mean per-mix set 17.9 / 30.9 / 66.0; worst link 0.393 / 0.184 / 0.101;
    // worst sender set 6.48 / 6.55 / 7.43.
    try testing.expect(low.mix_mean_set < mid.mix_mean_set and mid.mix_mean_set < high.mix_mean_set);
    try testing.expect(high.mix_mean_set > 3 * low.mix_mean_set);
    try testing.expect(low.mix_max_link > mid.mix_max_link and mid.mix_max_link > high.mix_max_link);
    try testing.expect(low.e2e_min_set < high.e2e_min_set);
}

// ── item 2: batch-and-reorder mixing ────────────────────────────────────────

test "batch: a threshold mix holds every packet in a batch of exactly the threshold; threshold 1 mixes nothing" {
    const gpa = testing.allocator;
    const bound = types.AnonymityBound{};
    // Measured: set = n and linking probability = 1/n on every target.
    const one = try score(gpa, comptime withBatch(STRAT, .threshold, 1, 40), true, null);
    const ten = try score(gpa, comptime withBatch(STRAT, .threshold, 10, 40), true, null);
    try testing.expect(one.mix_min_set < 1.01 and one.mix_max_link > 0.99); // a degenerate batch is pinned
    try testing.expect(one.e2e_min_set < 1.01 and one.eps_max > 20);
    try testing.expect(ten.mix_min_set > 9.99 and ten.mix_max_link < 0.1001);
    try testing.expect(ten.mix_min_set >= bound.min_effective_set and ten.mix_max_link <= bound.max_link_prob);
    try testing.expectEqual(@as(u64, 0), ten.bad);
}

test "batch: the trilemma — a bigger batch buys anonymity and costs latency" {
    const gpa = testing.allocator;
    // Measured: latency 33 / 56 / 83 / 137, set 1 / 5 / 10 / 20 for threshold 1 / 5 / 10 / 20.
    var prev_lat: f64 = 0;
    var prev_set: f64 = 0;
    inline for (.{ 1, 5, 10, 20 }) |n| {
        const sc = try score(gpa, comptime withBatch(STRAT, .threshold, n, 40), true, null);
        try testing.expect(sc.latency > prev_lat + 15);
        try testing.expect(sc.mix_min_set > prev_set);
        prev_lat = sc.latency;
        prev_set = sc.mix_min_set;
    }
    // Same for the timed batch, by its period: set 6.9 / 12.2 / 23.2, latency 71 / 121 / 222.
    prev_lat = 0;
    prev_set = 0;
    inline for (.{ 20, 40, 80 }) |period| {
        const sc = try score(gpa, comptime withBatch(STRAT, .timed, 10, period), true, null);
        try testing.expect(sc.latency > prev_lat + 30);
        try testing.expect(sc.mix_mean_set > prev_set + 4);
        prev_lat = sc.latency;
        prev_set = sc.mix_mean_set;
    }
}

test "batch: a timed batch gives no floor (a quiet round leaves a packet alone); a threshold batch always does" {
    const gpa = testing.allocator;
    const timed = try score(gpa, comptime withBatch(STRAT, .timed, 10, 20), true, null);
    // Measured: a short period has rounds of one packet: set 1.00, link 1.00.
    try testing.expect(timed.mix_min_set < 1.01 and timed.mix_max_link > 0.99);
    try testing.expect(timed.mix_min_set < (types.AnonymityBound{}).min_effective_set);
}

test "batch: without cover a batch waits for traffic (latency), but its set does not shrink" {
    const gpa = testing.allocator;
    const cfg = comptime withBatch(STRAT, .threshold, 10, 40);
    const with = try score(gpa, cfg, true, null);
    const without = try score(gpa, cfg, false, null);
    // Measured latency 83 vs 187; set 10.00 either way.
    try testing.expect(without.latency > 1.5 * with.latency);
    try testing.expect(without.mix_min_set > 9.99);
}

test "batch: a released batch leaves in random order, not arrival order" {
    const gpa = testing.allocator;
    var mix = try simulate(gpa, comptime withBatch(STRAT, .threshold, 10, 40), 3, UNTIL, true, null);
    defer mix.deinit(gpa);
    // Adjacent passes of one release (same mix, same tick) in transcript order:
    // how often is the later one the later ARRIVAL? An order-preserving flush
    // says 1.0.
    var asc: usize = 0;
    var pairs: usize = 0;
    const ts = mix.transcript();
    for (ts[0 .. ts.len - 1], ts[1..]) |a, b| {
        if (a.mix != b.mix or a.departure != b.departure or a.arrival == b.arrival) continue;
        pairs += 1;
        if (a.arrival < b.arrival) asc += 1;
    }
    try testing.expect(pairs > 500);
    const f = @as(f64, @floatFromInt(asc)) / @as(f64, @floatFromInt(pairs));
    try testing.expect(f > 0.4 and f < 0.6);
}

// ── item 3: mix-originated cover ────────────────────────────────────────────

const LOOPS = withLoops(STRAT, 60);

test "mix loops: a clean network gets every loop home, raises no alarm, and the pools fill up" {
    const gpa = testing.allocator;
    const plain = try score(gpa, STRAT, true, null);
    const some = try score(gpa, LOOPS, true, null);
    const more = try score(gpa, comptime withLoops(STRAT, 20), true, null);
    // Measured: 1386 of 1520 watched loops back (the rest still in flight at the
    // horizon), 0 alarms; per-mix mean set 30.9 / 36.2 / 47.6.
    try testing.expect(some.loops_watched > 1000);
    try testing.expect(some.loops_returned * 10 >= some.loops_watched * 8);
    try testing.expectEqual(@as(usize, 0), some.alarms);
    try testing.expectEqual(@as(u64, 0), some.bad);
    try testing.expectEqual(@as(usize, 0), more.alarms);
    try testing.expect(plain.mix_mean_set + 3 < some.mix_mean_set and some.mix_mean_set + 8 < more.mix_mean_set);
    try testing.expect(some.mix_min_set >= (types.AnonymityBound{}).min_effective_set + 0.5);
    // A mix loop names no client: sender and receiver anonymity are unharmed.
    try testing.expect(some.e2e_min_set >= (types.SenderBound{}).min_sender_set);
    try testing.expectEqual(@as(usize, 0), some.missing);
}

test "mix loops: a mix that is blocked loses its own loops and the others' through it, and they alarm during the attack" {
    const gpa = testing.allocator;
    var seed: u64 = 1;
    while (seed <= 5) : (seed += 1) {
        var mix = try simulate(gpa, LOOPS, seed, UNTIL, true, ATTACK);
        defer mix.deinit(gpa);
        try testing.expect(mix.attack_dropped > 20);
        try testing.expect(mix.mix_alarms.items.len > 0);
        var attacked_alarmed = false;
        var seen: [256]bool = @splat(false);
        for (mix.mix_alarms.items) |a| {
            try testing.expect(a.at > ATTACK.start); // none before the attack began
            try testing.expect(!seen[a.mix]); // once per mix
            seen[a.mix] = true;
            if (a.mix == ATTACK.mix) attacked_alarmed = true;
        }
        // The blocked mix cannot get its own loops home.
        try testing.expect(attacked_alarmed);
    }
}

test "mix loops: stats count them as cover, and only a watchable strategy watches" {
    const gpa = testing.allocator;
    var mix = try simulate(gpa, LOOPS, 1, UNTIL, true, null);
    defer mix.deinit(gpa);
    const st = mix.stats();
    try testing.expectEqual(mix.relay.mix_sent.count(), st.mix_cover_sent);
    try testing.expect(st.mix_cover_sent > 250);
    // Timed batches have a known worst hold (one period a hop): watched, none lost.
    const timed = try score(gpa, comptime withLoops(withBatch(STRAT, .timed, 10, 40), 60), true, null);
    try testing.expect(timed.loops_watched > 1000 and timed.alarms == 0);
    // A threshold batch waits for traffic: nothing can be called overdue.
    const thr = try score(gpa, comptime withLoops(withBatch(STRAT, .threshold, 10, 40), 60), true, null);
    try testing.expectEqual(@as(u64, 0), thr.loops_watched);
}

// ── item 4: receiver anonymity and sender–receiver unlinkability ───────────

test "receiver: the Poisson mix hides the recipient; FIFO pins it; a provider hides it down to its own clients" {
    const gpa = testing.allocator;
    const rb = types.ReceiverBound{};
    // Clients straight on the last layer: a link names its receiver.
    const poisson = try score(gpa, DIRECT8, true, null);
    const fifo = try scoreFifo(gpa, DIRECT8);
    // Measured: Poisson worst set 7.47 of 8, worst mass on the recipient 0.221; FIFO 1.00 / 1.00.
    try testing.expect(poisson.recv_min_set >= rb.min_receiver_set + 3 and poisson.recv_max_link <= rb.max_link_prob - 0.2);
    try testing.expect(fifo.recv_min_set < 1.01 and fifo.recv_max_link > 0.99);
    // Behind providers a FIFO mix is traced to the provider and no further: its
    // 4 clients, 1/4 each, whatever the mailbox pulls look like.
    const prov = try scoreFifo(gpa, STRAT);
    try testing.expectApproxEqAbs(@as(f64, 4.0), prov.recv_min_set, 0.01);
    try testing.expectApproxEqAbs(@as(f64, 0.25), prov.recv_max_link, 0.001);
}

test "unlinkability: third-party leakage ε is ~0 for the Poisson mix, large for FIFO and for a cover-starved network's worst packet" {
    const gpa = testing.allocator;
    const ub = types.UnlinkBound{};
    const poisson = try score(gpa, DIRECT8, true, null);
    const nocover = try score(gpa, DIRECT8, false, null);
    const fifo = try scoreFifo(gpa, DIRECT8);
    // Measured (mean ε, worst packet, nats): Poisson 0.001 / 0.86, no cover 0.037 / 23.1, FIFO 18.5 / 27.6.
    try testing.expect(poisson.eps_mean <= ub.max_mean_epsilon / 10 and poisson.eps_max < 2);
    try testing.expect(fifo.eps_mean > 10 * ub.max_mean_epsilon);
    try testing.expect(nocover.eps_max > 20); // some packet's sender is pinned...
    try testing.expect(nocover.e2e_min_set < (types.SenderBound{}).min_sender_set); // ...and the sender-set bound sees it too
    try testing.expect(poisson.e2e_min_set >= (types.SenderBound{}).min_sender_set);
}
