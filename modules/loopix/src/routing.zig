// SPDX-License-Identifier: MIT

//! routing — stratified route selection + the `sphinx` packet plumbing.
//!
//! **Sphinx reuse (the packet substrate).** Loopix's per-hop unlinkability is
//! NOT its contribution — it reuses Sphinx, exactly the packet this repo's
//! `sphinx` module already ships (BOLT#4). A Sphinx onion is fixed-length,
//! peels one layer per hop, reveals to each hop ONLY its successor + this hop's
//! own opaque payload, and is bit-unlinkable across hops. That is precisely
//! what a mix packet needs. Two reuse notes, both benign for a mixnet:
//!   - `sphinx` is hardwired to secp256k1 + a 1366-byte packet + ≤37 hops
//!     (Lightning's parameters). Loopix/Nym production uses Curve25519 and its
//!     own sizes, but the curve/size choice is immaterial to the anonymity
//!     property — a 3–5 layer stratified mixnet fits inside 37 hops trivially,
//!     and unlinkability is identical across curves.
//!   - BOLT#4's per-hop payload is an OPAQUE byte string, so Loopix's
//!     sender-chosen per-hop metadata — the next mix + the hold delay — rides
//!     inside it with no format change. `sphinxRoundTrip` below builds a real
//!     onion carrying `(next_hop, delay)` per hop and peels it end-to-end,
//!     proving the substrate works as-is.
//!
//! The netsim protocols (`protocol.zig`) carry a MODELED fixed-size header
//! (`types.MixHeader`) rather than a real 1366-byte onion, because the
//! anonymity metric is purely about timing and the adversary is denied packet
//! content by construction — see `types.zig`'s header note. `sphinxRoundTrip`
//! is the standing proof that the modeled header stands in for a real onion.

const std = @import("std");
const netsim = @import("netsim");
const sphinx = @import("sphinx");
const types = @import("types.zig");

const NodeId = netsim.NodeId;
const Time = netsim.Time;
const LoopixConfig = types.LoopixConfig;
const MixHeader = types.MixHeader;

/// splitmix64 finalizer as a PURE hash — deterministic route selection with no
/// per-run state, so a message's route is a fixed function of its identity
/// (source, sequence) and independent of the netsim seed (which still varies
/// message TIMING via jitter — the signal the anonymity metric feeds on).
pub fn mix64(x: u64) u64 {
    var z = x +% 0x9e3779b97f4a7c15;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/// Fill `out.route` with one mix per layer (chosen by hashing `key`) followed
/// by `dest`, and set `hop`/`n_hops`. `key` should be unique per message
/// (e.g. `source*K + seq`) so different messages spread across the mixes.
pub fn pickRoute(cfg: LoopixConfig, key: u64, dest: NodeId, out: *MixHeader) void {
    var h = mix64(key);
    var layer: u8 = 0;
    while (layer < cfg.layers) : (layer += 1) {
        h = mix64(h ^ (@as(u64, layer) +% 1));
        const w: u8 = @intCast(h % cfg.width);
        out.route[layer] = cfg.mixNode(layer, w);
    }
    out.route[cfg.layers] = dest;
    out.n_hops = cfg.layers;
    out.hop = 0;
}

/// Pick a destination client for `key` that is NOT `self` (for real + drop
/// cover, which must land on some other client). Loop cover uses `self`.
pub fn pickDestClient(cfg: LoopixConfig, key: u64, self_client: u8) NodeId {
    if (cfg.clients <= 1) return cfg.clientNode(self_client);
    const r: u8 = @intCast(mix64(key ^ 0xD00D) % (cfg.clients - 1));
    // Map r into [0, clients) skipping self, so every non-self client is reachable.
    const c: u8 = if (r < self_client) r else r + 1;
    return cfg.clientNode(c);
}

// ── the sphinx plumbing proof (real onion, end-to-end) ───────────────────────

const Secp256k1 = std.crypto.ecc.Secp256k1;

/// Per-hop opaque payload carried inside the Sphinx onion: the sender's
/// instruction to hop `i` — forward to `next_hop`, after holding `delay`
/// ticks. This is the production (sender-chosen-delay) Loopix shape; the sim's
/// mix-chosen variant samples its own hold instead (see `mixing.zig`), which
/// is equivalent for anonymity. 8 bytes clears BOLT#4's reserved-length floor.
pub const HopInstruction = struct {
    next_hop: NodeId,
    delay: u32,

    pub const wire_len = 8;

    fn encode(self: HopInstruction, buf: *[wire_len]u8) void {
        std.mem.writeInt(u32, buf[0..4], self.next_hop, .little);
        std.mem.writeInt(u32, buf[4..8], self.delay, .little);
    }

    fn decode(bytes: []const u8) HopInstruction {
        return .{
            .next_hop = std.mem.readInt(u32, bytes[0..4], .little),
            .delay = std.mem.readInt(u32, bytes[4..8], .little),
        };
    }
};

fn pubFromPriv(priv: [32]u8) [sphinx.pubkey_len]u8 {
    const p = Secp256k1.basePoint.mul(priv, .big) catch unreachable;
    return p.toCompressedSec1();
}

const testing = std.testing;

test "sphinx plumbing: a real onion carries (next_hop, delay) per hop and peels end-to-end" {
    // Prove the `sphinx` substrate works as a Loopix mix packet: build a real
    // BOLT#4 onion for a 3-mix stratified route where each hop's OPAQUE payload
    // is a `HopInstruction`, then process it hop-by-hop and recover each hop's
    // next-hop + delay, with the final hop flagged. This is the standing
    // guarantee behind the sim's modeled header.
    const route_mixes = [_]NodeId{ 2, 4, 7 }; // one mix per layer
    const dest: NodeId = 11;
    const delays = [_]u32{ 33, 12, 51 };

    // Distinct valid secp256k1 scalars as the three mixes' node keys.
    var privs: [3][32]u8 = undefined;
    for (&privs, 0..) |*p, i| {
        @memset(p, 0);
        p[31] = @intCast(i + 1); // 1, 2, 3
    }
    var pubs: [3][sphinx.pubkey_len]u8 = undefined;
    for (&pubs, privs) |*pk, sk| pk.* = pubFromPriv(sk);

    // Each hop's payload = where it forwards next + how long it holds.
    var payload_bufs: [3][HopInstruction.wire_len]u8 = undefined;
    for (0..3) |i| {
        const nh: NodeId = if (i + 1 < 3) route_mixes[i + 1] else dest;
        (HopInstruction{ .next_hop = nh, .delay = delays[i] }).encode(&payload_bufs[i]);
    }
    const payloads = [_][]const u8{ &payload_bufs[0], &payload_bufs[1], &payload_bufs[2] };

    const session_key = [_]u8{0x42} ** 32;
    const ad = "loopix-mix";
    var pkt = try sphinx.construct(session_key, &pubs, &payloads, ad);

    // Peel the onion mix by mix; each recovers its own instruction.
    for (0..3) |i| {
        const res = try sphinx.process(privs[i], pkt, ad);
        const inst = HopInstruction.decode(res.payload());
        const expect_next: NodeId = if (i + 1 < 3) route_mixes[i + 1] else dest;
        try testing.expectEqual(expect_next, inst.next_hop);
        try testing.expectEqual(delays[i], inst.delay);
        if (i + 1 < 3) {
            try testing.expect(res.next_packet != null); // more hops to go
            pkt = res.next_packet.?;
        } else {
            try testing.expect(res.next_packet == null); // last mix → deliver to dest
        }
    }
}

test "pickRoute: one mix per layer, all in-range, dest in the final slot" {
    const cfg = LoopixConfig{ .layers = 3, .width = 3, .clients = 3 };
    var h = MixHeader{ .kind = .real, .id = 0, .hop = 9, .n_hops = 0, .route = undefined };
    @memset(&h.route, 0);
    pickRoute(cfg, 12345, cfg.clientNode(1), &h);
    try testing.expectEqual(@as(u8, 0), h.hop);
    try testing.expectEqual(@as(u8, 3), h.n_hops);
    var layer: u8 = 0;
    while (layer < 3) : (layer += 1) {
        try testing.expectEqual(@as(?u8, layer), cfg.layerOf(h.route[layer])); // right layer
    }
    try testing.expectEqual(cfg.clientNode(1), h.route[3]); // dest slot
}

test "pickDestClient: never returns self, always a valid client" {
    const cfg = LoopixConfig{ .layers = 2, .width = 2, .clients = 4 };
    var key: u64 = 0;
    while (key < 200) : (key += 1) {
        const self: u8 = @intCast(key % 4);
        const d = pickDestClient(cfg, key, self);
        try testing.expect(d != cfg.clientNode(self)); // never self
        try testing.expect(cfg.isClient(d)); // a real client node
    }
}
