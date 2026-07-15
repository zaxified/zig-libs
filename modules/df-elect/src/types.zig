// SPDX-License-Identifier: MIT

//! types — edge-segment topology metadata + the two wire messages this
//! module puts on the netsim link (`Hello` for link-state liveness, `BumFrame`
//! for broadcast/unknown-unicast/multicast traffic). Pure data + mechanical
//! (de)serialization only — no election logic lives here, see `election.zig`.

const std = @import("std");
const netsim = @import("netsim");

const NodeId = netsim.NodeId;

pub const SegmentId = u32;

/// A customer site dual-homed to exactly two edge nodes. `priority[i]` is a
/// static, link-state-derived tie-break input to election for `nodes[i]`
/// (lower value wins ties; mirrors an EVPN Ethernet Segment's per-PE ordinal,
/// RFC 7432 §8.5) — carried explicitly here rather than derived from `NodeId`
/// so the election function in `election.zig` never needs a second source of
/// truth for "who wins a tie".
pub const EdgeSegment = struct {
    id: SegmentId,
    nodes: [2]NodeId,
    priority: [2]u32,

    /// Is `node` one of this segment's two members, and if so which slot?
    pub fn indexOf(self: EdgeSegment, node: NodeId) ?u1 {
        if (self.nodes[0] == node) return 0;
        if (self.nodes[1] == node) return 1;
        return null;
    }

    /// The OTHER member of this segment (undefined if `node` is not a
    /// member — callers only call this after `indexOf` succeeded).
    pub fn otherOf(self: EdgeSegment, node: NodeId) NodeId {
        return if (self.nodes[0] == node) self.nodes[1] else self.nodes[0];
    }

    /// `node`'s own election priority, or `null` if it is not a member.
    pub fn priorityOf(self: EdgeSegment, node: NodeId) ?u32 {
        if (self.indexOf(node)) |i| return self.priority[i];
        return null;
    }
};

pub const ElectConfig = struct {
    /// How often an edge node re-floods a Hello for each segment it belongs to.
    hello_period: netsim.Time = 50,
    /// A peer is presumed unreachable once this many ticks pass without a
    /// fresh Hello from it. Must be a small multiple of `hello_period` (a
    /// single dropped Hello must not flip liveness — the classic hold-timer
    /// shape shared by IS-IS/OSPF/BGP).
    stale_after: netsim.Time = 170,
    /// How often a BUM frame is originated (network-side AND per-segment
    /// CE-side), for the scenario/property tests. Not itself part of the
    /// election's own duty — a real deployment's BUM rate is data-plane
    /// driven, not timer driven; this is purely a test-traffic generator.
    /// Kept low enough relative to the sim's `until` that the per-origin
    /// sequence number never reaches `bum_seen`'s 64-bit dedup window (see
    /// that field's doc in `protocol.zig`).
    bum_period: netsim.Time = 40,
};

/// The two message kinds this module puts on the wire, tagged by the first
/// payload byte.
pub const MsgTag = enum(u8) { hello = 0, bum = 1 };

pub fn tagOf(payload: []const u8) MsgTag {
    return @enumFromInt(payload[0]);
}

/// Link-state liveness advertisement: "`origin` is alive and is a member of
/// `segment`". Flooded with monotonic-`seq` supersede semantics (a node
/// forwards it only if `seq` is newer than the highest it has already seen
/// from this `origin` — classic LSA flooding, no separate election protocol).
pub const Hello = struct {
    origin: NodeId,
    seq: u32,
    segment: SegmentId,

    pub const wire_len = 13;

    pub fn encode(self: Hello, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(MsgTag.hello);
        std.mem.writeInt(u32, buf[1..5], self.origin, .little);
        std.mem.writeInt(u32, buf[5..9], self.seq, .little);
        std.mem.writeInt(u32, buf[9..13], self.segment, .little);
    }

    pub fn decode(payload: []const u8) Hello {
        return .{
            .origin = std.mem.readInt(u32, payload[1..5], .little),
            .seq = std.mem.readInt(u32, payload[5..9], .little),
            .segment = std.mem.readInt(u32, payload[9..13], .little),
        };
    }
};

/// Sentinel `ingress_segment` meaning "this frame did not ingress from any
/// customer segment" (network/WAN-side traffic, the common BUM case).
pub const no_ingress: SegmentId = 0xFFFF_FFFF;

/// A broadcast/unknown-unicast/multicast frame, tagged with the segment it
/// entered the fabric from (or `no_ingress`). That ingress tag is this sim's
/// stand-in for EVPN's ESI/split-horizon label — carried in-band here
/// because netsim messages are opaque byte payloads with no separate
/// out-of-band signaling channel, unlike a real MPLS/VXLAN data plane.
pub const BumFrame = struct {
    origin: NodeId,
    seq: u32,
    ingress_segment: SegmentId,

    pub const wire_len = 13;

    pub fn encode(self: BumFrame, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(MsgTag.bum);
        std.mem.writeInt(u32, buf[1..5], self.origin, .little);
        std.mem.writeInt(u32, buf[5..9], self.seq, .little);
        std.mem.writeInt(u32, buf[9..13], self.ingress_segment, .little);
    }

    pub fn decode(payload: []const u8) BumFrame {
        return .{
            .origin = std.mem.readInt(u32, payload[1..5], .little),
            .seq = std.mem.readInt(u32, payload[5..9], .little),
            .ingress_segment = std.mem.readInt(u32, payload[9..13], .little),
        };
    }

    /// A frame's global identity for duplicate-delivery tracking. `origin`
    /// paired with `seq` is unique because each origin's own `seq` counter is
    /// strictly monotonic (see `protocol.zig`'s `originateBum`).
    pub fn id(self: BumFrame) u64 {
        return (@as(u64, self.origin) << 32) | @as(u64, self.seq);
    }
};

const testing = std.testing;

test "Hello round-trips through its wire encoding" {
    var buf: [Hello.wire_len]u8 = undefined;
    const h = Hello{ .origin = 7, .seq = 900, .segment = 3 };
    h.encode(&buf);
    try testing.expectEqual(MsgTag.hello, tagOf(&buf));
    const h2 = Hello.decode(&buf);
    try testing.expectEqual(h.origin, h2.origin);
    try testing.expectEqual(h.seq, h2.seq);
    try testing.expectEqual(h.segment, h2.segment);
}

test "BumFrame round-trips through its wire encoding, including the ingress tag" {
    var buf: [BumFrame.wire_len]u8 = undefined;
    const f = BumFrame{ .origin = 2, .seq = 55, .ingress_segment = no_ingress };
    f.encode(&buf);
    try testing.expectEqual(MsgTag.bum, tagOf(&buf));
    const f2 = BumFrame.decode(&buf);
    try testing.expectEqual(f.origin, f2.origin);
    try testing.expectEqual(f.seq, f2.seq);
    try testing.expectEqual(f.ingress_segment, f2.ingress_segment);
    try testing.expectEqual(@as(u64, (2 << 32) | 55), f.id());

    const g = BumFrame{ .origin = 2, .seq = 55, .ingress_segment = 9 };
    var buf2: [BumFrame.wire_len]u8 = undefined;
    g.encode(&buf2);
    const g2 = BumFrame.decode(&buf2);
    try testing.expectEqual(@as(SegmentId, 9), g2.ingress_segment);
    // Same (origin, seq) as `f` — `id()` collapses ingress tag, by design
    // (duplicate-delivery tracking is keyed separately by segment; see
    // `checks.DeliveryChecker`).
    try testing.expectEqual(f.id(), g.id());
}

test "EdgeSegment.indexOf / otherOf / priorityOf" {
    const seg = EdgeSegment{ .id = 1, .nodes = .{ 4, 9 }, .priority = .{ 10, 20 } };
    try testing.expectEqual(@as(?u1, 0), seg.indexOf(4));
    try testing.expectEqual(@as(?u1, 1), seg.indexOf(9));
    try testing.expectEqual(@as(?u1, null), seg.indexOf(5));
    try testing.expectEqual(@as(NodeId, 9), seg.otherOf(4));
    try testing.expectEqual(@as(NodeId, 4), seg.otherOf(9));
    try testing.expectEqual(@as(?u32, 10), seg.priorityOf(4));
    try testing.expectEqual(@as(?u32, 20), seg.priorityOf(9));
    try testing.expectEqual(@as(?u32, null), seg.priorityOf(5));
}
