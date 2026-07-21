// SPDX-License-Identifier: MIT

//! types — the Loopix configuration, the message-kind taxonomy, the stratified
//! node-numbering scheme, and the fixed-size in-sim mix header. Pure data +
//! mechanical (de)serialization only — the mixing strategy lives in
//! `mixing.zig` (the gated Fable core) and the anonymity measurement in
//! `adversary.zig`.
//!
//! **Node numbering (stratified topology).** A Loopix mixnet is `layers`
//! cascades of `width` mixes each, plus a handful of client nodes that both
//! originate and receive traffic:
//!
//! ```text
//!   clients        layer 0        layer 1        layer 2      clients
//!   c0 ───┬──────▶ m(0,0) ──┬───▶ m(1,0) ──┬───▶ m(2,0) ──┬──▶ c0
//!   c1 ───┼──────▶ m(0,1) ──┼───▶ m(1,1) ──┼───▶ m(2,1) ──┼──▶ c1
//!   c2 ───┴──────▶ m(0,2) ──┴───▶ m(1,2) ──┴───▶ m(2,2) ──┴──▶ c2
//! ```
//!
//! Mix `(layer, w)` gets node id `layer*width + w`; client `c` gets id
//! `layers*width + c`. Adjacent layers are fully connected (a message may take
//! any mix per layer), which is what a *stratified* mixnet means — every
//! message traverses exactly one mix per layer, so all messages share the same
//! set of relays and are mutually indistinguishable at the link level.

const std = @import("std");
const netsim = @import("netsim");

const NodeId = netsim.NodeId;
const Time = netsim.Time;

/// Hard ceiling on `layers`, so the wire header is a fixed size (a real Sphinx
/// packet is likewise fixed-length regardless of route — see `routing.zig`).
pub const max_layers = 6;
/// Route slots = one mix per layer + the final destination client.
pub const max_hops = max_layers + 1;

/// What a packet actually is — indistinguishable to the adversary (Sphinx
/// bit-unlinkability + constant length hide this), but ground truth to the
/// harness. `real` is application traffic (the only thing anonymity is
/// measured for); the two cover kinds are the Poisson chaff Loopix injects to
/// keep every mix's anonymity set large and to detect active (n−1) attacks.
pub const MsgKind = enum(u8) {
    /// Application payload — the target class the adversary tries to link.
    real,
    /// A message a client routes back to ITSELF through the mixnet; used in
    /// full Loopix to detect n−1 attacks (a dropped loop is evidence of an
    /// active adversary). Here it is Poisson chaff that inflates mix pools.
    loop_cover,
    /// A message routed to a random destination that silently discards it —
    /// pure Poisson chaff, the bulk of the cover volume.
    drop_cover,
};

/// Static parameters of the mixnet + the harness's test-traffic generators.
/// The delay/rate fields drive the (gated) Poisson mixing core; the `_period`
/// fields drive the deterministic test-traffic timers (not part of the mixing
/// strategy itself, exactly like `df-elect`'s `bum_period`).
pub const LoopixConfig = struct {
    /// L — number of stratified mix layers a message traverses.
    layers: u8 = 3,
    /// W — number of mixes per layer.
    width: u8 = 3,
    /// Number of client nodes (each both sends and receives).
    clients: u8 = 3,
    /// 1/μ — the MEAN hold delay (ticks) of the Poisson mix. Each mix holds an
    /// arriving packet an independent Exp(1/mean_delay) time before releasing
    /// it. The memoryless exponential is the whole reason the mix is
    /// unlinkable against a global passive adversary (see `SPEC.md`).
    mean_delay: Time = 40,
    /// Deterministic period at which each client originates a REAL message
    /// (test traffic — a real deployment's send rate is application-driven).
    real_period: Time = 30,
    /// 1/λ — mean inter-arrival time of the Poisson COVER process each node
    /// runs (loop + drop chaff). Lower = more cover = larger anonymity sets.
    cover_mean_interval: Time = 15,
    /// Constant hold used by the `FifoMix` positive control (a mix that does
    /// NOT sample an exponential delay — it forwards after a fixed wait,
    /// preserving arrival order, which is exactly what breaks anonymity).
    fifo_delay: Time = 40,

    pub fn mixCount(self: LoopixConfig) usize {
        return @as(usize, self.layers) * @as(usize, self.width);
    }

    pub fn nodeCount(self: LoopixConfig) usize {
        return self.mixCount() + @as(usize, self.clients);
    }

    /// Node id of mix `(layer, w)`.
    pub fn mixNode(self: LoopixConfig, layer: u8, w: u8) NodeId {
        return @intCast(@as(usize, layer) * @as(usize, self.width) + @as(usize, w));
    }

    /// Node id of client `c`.
    pub fn clientNode(self: LoopixConfig, c: u8) NodeId {
        return @intCast(self.mixCount() + @as(usize, c));
    }

    /// Which layer a mix node sits in, or `null` if `node` is a client.
    pub fn layerOf(self: LoopixConfig, node: NodeId) ?u8 {
        if (node >= self.mixCount()) return null;
        return @intCast(node / self.width);
    }

    /// Is `node` a client (traffic source/sink) rather than a mix?
    pub fn isClient(self: LoopixConfig, node: NodeId) bool {
        return node >= self.mixCount();
    }
};

/// Anonymity invariant the harness enforces (see `adversary.zig` for how each
/// field is measured). Two independent guarantees, both required — this is the
/// Loopix property stated measurably:
///
///  - `min_effective_set` — EVERY real target must, at every mix it transits,
///    hide inside an effective anonymity set (Serjantov–Danezis `2^H`) of at
///    least this size. This is the guarantee COVER TRAFFIC buys: without chaff
///    the pool empties and the set collapses to 1. A FIFO mix also collapses
///    it (the adversary's posterior is a spike). Measured as a WORST-case min
///    over all targets, so a single pinned message fails it.
///  - `max_link_prob` — the adversary's posterior mass on any target's TRUE
///    output must stay below this. This is the guarantee the POISSON MIXING
///    STRATEGY buys: the memoryless hold makes output timing independent of
///    input timing, so the adversary cannot concentrate probability on the
///    real match. A FIFO mix pins it to 1.0.
///
/// Defaults RETUNED against the real Poisson core's measured behaviour (Part 2,
/// like `df-elect`'s `maxBadDfWindow`). Measurement basis: a clean (fault-free,
/// global-PASSIVE-adversary) run of the real `Loopix` mix over 50 seeds, each
/// mix scored with its OWN delay law, over the steady-state window (targets that
/// arrived early enough to clear before the finite horizon — see
/// `protocol.zig`'s cooldown note). On that basis the worst-case measured across
/// all ~24.5k real targets was (re-measured after the release-by-own-timer fix
/// in `protocol.zig` — releasing the queue front on every timer had paired each
/// arrival with its maximum-likelihood departure, inflating link_prob to 0.77):
///
///     correct Poisson mix : min_effective_set 3.88 , max_link_prob 0.63
///     FIFO control        : min_effective_set 1.00 , max_link_prob 1.00
///     no-cover control    : min_effective_set 1.06 , max_link_prob 0.99
///
/// The bound sits with genuine margin below the correct mix and far above both
/// broken controls on BOTH clauses — it is NOT tuned to let the correct mix
/// squeak by. `min_effective_set` (the cover-traffic guarantee) is the binding,
/// robustly-separating clause (2.80 vs 1.00/1.06); `max_link_prob` (the
/// memoryless-hold guarantee) is a second guard both controls also violate.
pub const AnonymityBound = struct {
    min_effective_set: f64 = 2.0,
    max_link_prob: f64 = 0.9,
};

// ── the in-sim mix header ────────────────────────────────────────────────────
//
// In production this is an encrypted, fixed-length Sphinx onion (see
// `routing.zig`, which exercises the REAL `sphinx` packet). In the netsim hot
// loop we carry a modeled, fixed-length header instead: the anonymity property
// is purely about TIMING, and the adversary is denied packet CONTENT by
// construction (it is never handed `id`/`kind`), so modeling the onion's
// observable behaviour — constant length, one-mix-per-layer route, per-hop
// unlinkability — is faithful and keeps runs fast and deterministic.

/// Sentinel next-hop meaning "you are the final mix; deliver to the client in
/// the last route slot" is not needed: `hop == n_hops` is the terminal test.
pub const MixHeader = struct {
    kind: MsgKind,
    /// God's-eye packet identity — the harness label the adversary NEVER sees.
    id: u64,
    /// How many mixes this packet has already cleared (0 at the source).
    hop: u8,
    /// Number of mix hops in the route (`= layers`); `route[n_hops]` is the
    /// destination client.
    n_hops: u8,
    /// `route[0..n_hops]` = the chosen mix per layer; `route[n_hops]` = dest.
    route: [max_hops]NodeId,

    pub const wire_len = 1 + 8 + 1 + 1 + max_hops * 4;

    pub fn encode(self: MixHeader, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(self.kind);
        std.mem.writeInt(u64, buf[1..9], self.id, .little);
        buf[9] = self.hop;
        buf[10] = self.n_hops;
        var off: usize = 11;
        for (self.route) |r| {
            std.mem.writeInt(u32, buf[off..][0..4], r, .little);
            off += 4;
        }
    }

    pub const DecodeError = error{MalformedMixHeader};

    /// Fail-closed decode: validate every length/field against the buffer
    /// BEFORE indexing, so a hostile or truncated payload yields a clean error
    /// instead of an out-of-bounds read / UB. In the sim `decode` only ever
    /// sees self-encoded buffers, but a mixnet header is exactly the kind of
    /// attacker-controlled input that must never be trusted blindly.
    pub fn decode(payload: []const u8) DecodeError!MixHeader {
        if (payload.len < wire_len) return error.MalformedMixHeader;
        const kind: MsgKind = switch (payload[0]) {
            @intFromEnum(MsgKind.real) => .real,
            @intFromEnum(MsgKind.loop_cover) => .loop_cover,
            @intFromEnum(MsgKind.drop_cover) => .drop_cover,
            else => return error.MalformedMixHeader,
        };
        const hop = payload[9];
        const n_hops = payload[10];
        // `route[0..n_hops]` are the mixes and `route[n_hops]` is the
        // destination client, so `n_hops` must leave room for the destination
        // (`n_hops <= max_layers`, i.e. `< max_hops`) and `hop` must not run
        // past the last mix — otherwise `currentMix`/`nextHop` would index the
        // fixed route array out of range.
        if (n_hops > max_layers) return error.MalformedMixHeader;
        if (hop > n_hops) return error.MalformedMixHeader;

        var h = MixHeader{
            .kind = kind,
            .id = std.mem.readInt(u64, payload[1..9], .little),
            .hop = hop,
            .n_hops = n_hops,
            .route = undefined,
        };
        var off: usize = 11;
        for (&h.route) |*r| {
            r.* = std.mem.readInt(u32, payload[off..][0..4], .little);
            off += 4;
        }
        return h;
    }

    /// The mix this packet should be AT right now (valid while `hop < n_hops`).
    pub fn currentMix(self: MixHeader) NodeId {
        return self.route[self.hop];
    }

    /// Where this packet goes next: the next mix, or the destination client
    /// once the last mix has been cleared.
    pub fn nextHop(self: MixHeader) NodeId {
        return self.route[self.hop + 1];
    }

    pub fn atLastMix(self: MixHeader) bool {
        return self.hop + 1 == self.n_hops;
    }
};

const testing = std.testing;

test "LoopixConfig node numbering: mixes then clients, no overlap" {
    const cfg = LoopixConfig{ .layers = 3, .width = 3, .clients = 3 };
    try testing.expectEqual(@as(usize, 9), cfg.mixCount());
    try testing.expectEqual(@as(usize, 12), cfg.nodeCount());
    try testing.expectEqual(@as(NodeId, 0), cfg.mixNode(0, 0));
    try testing.expectEqual(@as(NodeId, 4), cfg.mixNode(1, 1));
    try testing.expectEqual(@as(NodeId, 8), cfg.mixNode(2, 2));
    try testing.expectEqual(@as(NodeId, 9), cfg.clientNode(0));
    try testing.expectEqual(@as(NodeId, 11), cfg.clientNode(2));
    try testing.expectEqual(@as(?u8, 0), cfg.layerOf(0));
    try testing.expectEqual(@as(?u8, 2), cfg.layerOf(8));
    try testing.expectEqual(@as(?u8, null), cfg.layerOf(9));
    try testing.expect(!cfg.isClient(8));
    try testing.expect(cfg.isClient(9));
}

test "MixHeader round-trips through its fixed-size wire encoding" {
    var h = MixHeader{
        .kind = .loop_cover,
        .id = 0xDEADBEEFCAFE,
        .hop = 2, // sitting at the last mix (layer 2 of 3)
        .n_hops = 3,
        .route = undefined,
    };
    @memset(&h.route, 0);
    h.route[0] = 2;
    h.route[1] = 4;
    h.route[2] = 7;
    h.route[3] = 11; // dest client
    var buf: [MixHeader.wire_len]u8 = undefined;
    h.encode(&buf);
    const g = try MixHeader.decode(&buf);
    try testing.expectEqual(MsgKind.loop_cover, g.kind);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFE), g.id);
    try testing.expectEqual(@as(u8, 2), g.hop);
    try testing.expectEqual(@as(u8, 3), g.n_hops);
    try testing.expectEqual(@as(NodeId, 7), g.currentMix()); // route[2]
    try testing.expectEqual(@as(NodeId, 11), g.nextHop()); // route[3] = dest
    try testing.expect(g.atLastMix());
}

test "MixHeader.decode fails closed on truncated / malformed input, never OOB" {
    // Every buffer shorter than the wire size is rejected cleanly — no
    // out-of-bounds read / panic on hostile bytes (checked under ReleaseSafe).
    var full: [MixHeader.wire_len]u8 = undefined;
    @memset(&full, 0);
    full[0] = @intFromEnum(MsgKind.real);
    var i: usize = 0;
    while (i < MixHeader.wire_len) : (i += 1) {
        try testing.expectError(error.MalformedMixHeader, MixHeader.decode(full[0..i]));
    }

    // Full length but an invalid message-kind byte.
    var bad_kind: [MixHeader.wire_len]u8 = undefined;
    @memset(&bad_kind, 0);
    bad_kind[0] = 0x7F; // not a valid MsgKind
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&bad_kind));

    // n_hops past the route capacity would let currentMix/nextHop over-index.
    var bad_nhops: [MixHeader.wire_len]u8 = undefined;
    @memset(&bad_nhops, 0);
    bad_nhops[0] = @intFromEnum(MsgKind.real);
    bad_nhops[10] = max_layers + 1;
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&bad_nhops));

    // hop running past n_hops is likewise rejected.
    var bad_hop: [MixHeader.wire_len]u8 = undefined;
    @memset(&bad_hop, 0);
    bad_hop[0] = @intFromEnum(MsgKind.real);
    bad_hop[10] = 3; // n_hops
    bad_hop[9] = 4; // hop > n_hops
    try testing.expectError(error.MalformedMixHeader, MixHeader.decode(&bad_hop));

    // A well-formed header still decodes at the boundary (n_hops == max_layers).
    var h = MixHeader{ .kind = .real, .id = 42, .hop = max_layers, .n_hops = max_layers, .route = undefined };
    @memset(&h.route, 0);
    var buf: [MixHeader.wire_len]u8 = undefined;
    h.encode(&buf);
    const g = try MixHeader.decode(&buf);
    try testing.expectEqual(MsgKind.real, g.kind);
    try testing.expectEqual(@as(u8, max_layers), g.n_hops);
}
