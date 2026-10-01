// SPDX-License-Identifier: MIT

//! types — edge-segment topology metadata + the two wire messages this
//! module puts on the netsim link (`Hello` for link-state liveness, `BumFrame`
//! for broadcast/unknown-unicast/multicast traffic). Pure data + mechanical
//! (de)serialization only — no election logic lives here, see `election.zig`.
//!
//! ## Decoding fails closed
//!
//! `tagOf` / `Hello.decode` / `BumFrame.decode` return `DecodeError!T` and
//! bounds-check before indexing. These frames arrive from the fabric, which in
//! a real deployment spans customer-facing edge ports; a one-byte frame used to
//! panic ("index out of bounds: index 5, len 1") and an undefined tag byte used
//! to panic on `@enumFromInt` ("invalid enum value").
//!
//! Length validity is only half of it. `origin` and `seq` are also untrusted
//! *values*: `protocol.zig` uses them as an array index and a shift amount
//! respectively, so the decoders being total is necessary but not sufficient —
//! see `DfElect.handleHello`/`handleBum`, which range-check both against the
//! live topology before use.

const std = @import("std");
const netsim = @import("netsim");

const NodeId = netsim.NodeId;

pub const SegmentId = u32;

/// An Ethernet tag (a VLAN, or the lowest VLAN of a bundle — RFC 7432 §8.5).
/// DF election is per `<segment, tag>`.
pub const Tag = u32;

/// One member of an edge segment: the fabric node and the address the DF
/// algorithms order and hash by (RFC 7432 §8.5's "Originating Router's IP
/// address", an IPv4 address as a host-order `u32`).
pub const Member = struct {
    node: NodeId,
    addr: u32,
    /// DF preference for `Algorithm.preference` (RFC 8584 registry type 2,
    /// "preference-based"; FRRouting's `es-df-pref`). Higher wins. The
    /// default is FRR's (and the preference-based draft's) 32767.
    pref: u16 = 32767,
};

/// Upper bound on members per segment. The election works on stack buffers of
/// this size; a real Ethernet segment is multihomed to a handful of PEs.
pub const max_members = 16;

/// A customer site multihomed to N edge nodes (an EVPN Ethernet Segment).
/// `members` must be sorted by strictly ascending `addr` with distinct nodes —
/// the ordinal list RFC 7432 §8.5 step 3 builds — and at most `max_members`
/// long; `validate` checks both.
pub const EdgeSegment = struct {
    id: SegmentId,
    /// The 10-octet ESI; only HRW (RFC 8584 §3.2) hashes it.
    esi: [10]u8,
    members: []const Member,
    /// The Ethernet tags configured on this segment.
    tags: []const Tag,

    pub const Error = error{ TooManyMembers, NoMembers, MembersNotSorted, DuplicateNode };

    pub fn validate(self: EdgeSegment) Error!void {
        if (self.members.len == 0) return error.NoMembers;
        if (self.members.len > max_members) return error.TooManyMembers;
        for (self.members[1..], 1..) |m, i| {
            if (m.addr <= self.members[i - 1].addr) return error.MembersNotSorted;
        }
        for (self.members, 0..) |m, i| {
            for (self.members[i + 1 ..]) |o| if (o.node == m.node) return error.DuplicateNode;
        }
    }

    /// Is `node` one of this segment's members, and if so at which ordinal?
    pub fn indexOf(self: EdgeSegment, node: NodeId) ?usize {
        for (self.members, 0..) |m, i| if (m.node == node) return i;
        return null;
    }

    /// Position of `tag` in `tags`, or `null` if the segment does not carry it.
    pub fn tagIndex(self: EdgeSegment, tag: Tag) ?usize {
        for (self.tags, 0..) |t, i| if (t == tag) return i;
        return null;
    }
};

/// Which RFC function maps a candidate list and a tag to a DF.
pub const Algorithm = enum {
    /// RFC 7432 §8.5 "service carving": ordinal `tag mod N` over the list
    /// sorted by address.
    modulo,
    /// RFC 8584 §3.2 Highest Random Weight over `(tag, ESI, address)`.
    hrw,
    /// Preference-based (DF Alg 2 in the RFC 8584 registry): the highest
    /// `Member.pref` is DF for every tag of the segment, ties to the least
    /// address. What FRRouting's EVPN multihoming runs; the rule is taken
    /// from FRR's observed behaviour (`tools/frr/`), the preference-based
    /// draft itself was not read.
    preference,
};

pub const ElectConfig = struct {
    /// How often an edge node re-floods a Hello for its segment, and
    /// re-evaluates its DF roles.
    hello_period: netsim.Time = 50,
    /// A member is presumed gone once this many ticks pass without a fresh
    /// Hello from it. A small multiple of `hello_period`, so a single dropped
    /// Hello does not flip liveness (the hold-timer shape of IS-IS/OSPF/BGP).
    stale_after: netsim.Time = 170,
    /// RFC 7432 §8.5 step 2 / RFC 8584 §2.1 DF_Wait: a member takes a DF role
    /// only after its own view has named it DF continuously for this long.
    /// Giving a role up is immediate. Must exceed `hello_period` plus the
    /// fabric's flood delay: that is what keeps a member whose view is still
    /// empty (startup, restart) from taking roles before the Hellos arrive.
    df_wait: netsim.Time = 150,
    algorithm: Algorithm = .modulo,
    /// How often a BUM frame is originated (network-side and per-segment
    /// CE-side), for the scenario/property tests only; kept low enough that
    /// the per-origin sequence number stays inside `bum_seen`'s 64-bit dedup
    /// window (see that field in `protocol.zig`).
    bum_period: netsim.Time = 40,
};

/// The two message kinds this module puts on the wire, tagged by the first
/// payload byte.
pub const MsgTag = enum(u8) { hello = 0, bum = 1 };

/// Why a frame could not be decoded. Same vocabulary as the neighbouring wire
/// decoders (`pbb.DecodeError`, `raft.DecodeError`).
pub const DecodeError = error{
    /// Fewer bytes than the fields being read require.
    Truncated,
    /// Long enough, but the tag byte is not one of the two defined kinds.
    InvalidEncoding,
};

/// Read the message tag off an untrusted frame. This is the first thing done
/// with every inbound payload, so it must be total: an empty frame and an
/// undefined tag byte both used to panic here.
pub fn tagOf(payload: []const u8) DecodeError!MsgTag {
    if (payload.len < 1) return error.Truncated;
    return switch (payload[0]) {
        @intFromEnum(MsgTag.hello) => .hello,
        @intFromEnum(MsgTag.bum) => .bum,
        else => error.InvalidEncoding,
    };
}

/// Link-state liveness advertisement: "`origin` is alive and is a member of
/// `segment`". Flooded with monotonic-`seq` supersede semantics (a node
/// forwards it only if `seq` is newer than the highest it has already seen
/// from this `origin` — classic LSA flooding, no separate election protocol).
pub const Hello = struct {
    origin: NodeId,
    seq: u32,
    /// The segment `origin` is a member of, or `no_segment` for a fabric
    /// node that belongs to none (it floods Hellos too, as every router of a
    /// link-state fabric does; that is what lets a member tell "my peers are
    /// gone" from "I hear nothing at all").
    segment: SegmentId,
    /// The members `origin` currently sees on `segment`, itself included:
    /// bit i = `EdgeSegment.members[i]`. Receivers use it to notice that a
    /// peer does NOT see them (a one-way failure) and yield — see
    /// `protocol.DfElect.refreshRoles`. A view WITHOUT the sender's own bit
    /// declares it isolated (it hears no fabric node): receivers stop
    /// counting it as a member until it advertises itself again.
    view: u32,

    pub const wire_len = 17;

    pub fn encode(self: Hello, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(MsgTag.hello);
        std.mem.writeInt(u32, buf[1..5], self.origin, .little);
        std.mem.writeInt(u32, buf[5..9], self.seq, .little);
        std.mem.writeInt(u32, buf[9..13], self.segment, .little);
        std.mem.writeInt(u32, buf[13..17], self.view, .little);
    }

    pub fn decode(payload: []const u8) DecodeError!Hello {
        if (payload.len < wire_len) return error.Truncated;
        // Check the tag here rather than trusting the caller to have called
        // `tagOf` first. Hello and BumFrame have identical wire lengths and
        // layouts, so a BUM frame decoded as a Hello is silent type confusion:
        // its `ingress_segment` — routinely `no_ingress` (0xFFFFFFFF) — would
        // become a `segment` id. Every dispatch site does check the tag today;
        // this makes that an invariant of the decoder instead of a convention
        // a new call site can forget.
        if (payload[0] != @intFromEnum(MsgTag.hello)) return error.InvalidEncoding;
        return .{
            .origin = std.mem.readInt(u32, payload[1..5], .little),
            .seq = std.mem.readInt(u32, payload[5..9], .little),
            .segment = std.mem.readInt(u32, payload[9..13], .little),
            .view = std.mem.readInt(u32, payload[13..17], .little),
        };
    }
};

/// `Hello.segment` of a fabric node that is a member of no segment.
pub const no_segment: SegmentId = 0xFFFF_FFFF;

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
    /// The frame's Ethernet tag: only a segment carrying it can receive the
    /// frame, and only the DF for `<segment, tag>` delivers it.
    tag: Tag,

    pub const wire_len = 17;

    pub fn encode(self: BumFrame, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(MsgTag.bum);
        std.mem.writeInt(u32, buf[1..5], self.origin, .little);
        std.mem.writeInt(u32, buf[5..9], self.seq, .little);
        std.mem.writeInt(u32, buf[9..13], self.ingress_segment, .little);
        std.mem.writeInt(u32, buf[13..17], self.tag, .little);
    }

    pub fn decode(payload: []const u8) DecodeError!BumFrame {
        if (payload.len < wire_len) return error.Truncated;
        if (payload[0] != @intFromEnum(MsgTag.bum)) return error.InvalidEncoding;
        return .{
            .origin = std.mem.readInt(u32, payload[1..5], .little),
            .seq = std.mem.readInt(u32, payload[5..9], .little),
            .ingress_segment = std.mem.readInt(u32, payload[9..13], .little),
            .tag = std.mem.readInt(u32, payload[13..17], .little),
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
    const h = Hello{ .origin = 7, .seq = 900, .segment = 3, .view = 0b101 };
    h.encode(&buf);
    try testing.expectEqual(MsgTag.hello, try tagOf(&buf));
    const h2 = try Hello.decode(&buf);
    try testing.expectEqual(h.origin, h2.origin);
    try testing.expectEqual(h.seq, h2.seq);
    try testing.expectEqual(h.segment, h2.segment);
    try testing.expectEqual(h.view, h2.view);
}

test "BumFrame round-trips through its wire encoding, including the ingress tag" {
    var buf: [BumFrame.wire_len]u8 = undefined;
    const f = BumFrame{ .origin = 2, .seq = 55, .ingress_segment = no_ingress, .tag = 4094 };
    f.encode(&buf);
    try testing.expectEqual(MsgTag.bum, try tagOf(&buf));
    const f2 = try BumFrame.decode(&buf);
    try testing.expectEqual(f.origin, f2.origin);
    try testing.expectEqual(f.seq, f2.seq);
    try testing.expectEqual(f.ingress_segment, f2.ingress_segment);
    try testing.expectEqual(f.tag, f2.tag);
    try testing.expectEqual(@as(u64, (2 << 32) | 55), f.id());

    const g = BumFrame{ .origin = 2, .seq = 55, .ingress_segment = 9, .tag = 10 };
    var buf2: [BumFrame.wire_len]u8 = undefined;
    g.encode(&buf2);
    const g2 = try BumFrame.decode(&buf2);
    try testing.expectEqual(@as(SegmentId, 9), g2.ingress_segment);
    // Same (origin, seq) as `f` — `id()` collapses ingress tag, by design
    // (duplicate-delivery tracking is keyed separately by segment; see
    // `checks.DeliveryChecker`).
    try testing.expectEqual(f.id(), g.id());
}

test "EdgeSegment: indexOf, tagIndex and validate" {
    const members = [_]Member{ .{ .node = 4, .addr = 0x0a000001 }, .{ .node = 9, .addr = 0x0a000002 }, .{ .node = 2, .addr = 0x0a000003 } };
    const seg = EdgeSegment{ .id = 1, .esi = @splat(0), .members = &members, .tags = &.{ 10, 20 } };
    try seg.validate();
    try testing.expectEqual(@as(?usize, 0), seg.indexOf(4));
    try testing.expectEqual(@as(?usize, 2), seg.indexOf(2));
    try testing.expectEqual(@as(?usize, null), seg.indexOf(5));
    try testing.expectEqual(@as(?usize, 1), seg.tagIndex(20));
    try testing.expectEqual(@as(?usize, null), seg.tagIndex(30));

    const unsorted = [_]Member{ .{ .node = 4, .addr = 2 }, .{ .node = 9, .addr = 1 } };
    try testing.expectError(error.MembersNotSorted, (EdgeSegment{ .id = 1, .esi = @splat(0), .members = &unsorted, .tags = &.{} }).validate());
    const equal_addr = [_]Member{ .{ .node = 4, .addr = 1 }, .{ .node = 9, .addr = 1 } };
    try testing.expectError(error.MembersNotSorted, (EdgeSegment{ .id = 1, .esi = @splat(0), .members = &equal_addr, .tags = &.{} }).validate());
    const dup = [_]Member{ .{ .node = 4, .addr = 1 }, .{ .node = 4, .addr = 2 } };
    try testing.expectError(error.DuplicateNode, (EdgeSegment{ .id = 1, .esi = @splat(0), .members = &dup, .tags = &.{} }).validate());
    try testing.expectError(error.NoMembers, (EdgeSegment{ .id = 1, .esi = @splat(0), .members = &.{}, .tags = &.{} }).validate());
}

// ── rejection tests: both decoders fail closed ──────────────────────────────

test "tagOf and the frame decoders reject short and undefined input" {
    try testing.expectError(error.Truncated, tagOf(&[_]u8{}));
    // The exact reproducer from the bug report.
    try testing.expectError(error.Truncated, Hello.decode(&[_]u8{0}));
    try testing.expectError(error.Truncated, BumFrame.decode(&[_]u8{1}));
    // A BUM frame in the pre-2026-09-30 13-octet layout (no tag) is short.
    try testing.expectError(error.Truncated, BumFrame.decode(&([_]u8{1} ++ [_]u8{0} ** 12)));

    // Every prefix of a valid frame is rejected; the full frame still decodes.
    var buf: [Hello.wire_len]u8 = undefined;
    (Hello{ .origin = 1, .seq = 1, .segment = 1, .view = 1 }).encode(&buf);
    for (0..buf.len) |n| try testing.expectError(error.Truncated, Hello.decode(buf[0..n]));
    _ = try Hello.decode(&buf);

    // Undefined tag bytes: previously "invalid enum value" panics.
    for (2..256) |b| try testing.expectError(error.InvalidEncoding, tagOf(&[_]u8{@intCast(b)}));
    try testing.expectEqual(MsgTag.hello, try tagOf(&[_]u8{0}));
    try testing.expectEqual(MsgTag.bum, try tagOf(&[_]u8{1}));
}

// ── fuzz: both decoders are total over arbitrary bytes ──────────────────────
//
// ⚠ Both targets used to open `smith.bytes(&buf)` and then draw the length
// with `smith.valueRangeAtMost`. `bytes` consumes `@min(buf.len, in.len)`
// octets and a ranged draw then reads EIGHT more as a little-endian `u64`,
// returning the range MINIMUM when fewer remain — so the length was 0 on
// every input a corpus can carry. Neither target had a corpus either, so the
// one input each ever ran was empty and both decoders were handed a
// zero-length slice: `error.Truncated` on the first line, 26 octets of drawn
// frame sitting unread in `buf`. One `slice` draw closes the first half and
// the corpora below close the second.

/// `testkit.fuzz.seedHex`, aliased so the corpora read as the little-endian
/// wire frames they are. A corpus entry is not the frame: `Smith.slice` reads
/// a little-endian `u32` length first, so a raw frame would arrive minus its
/// own tag and three octets of `origin`.
const seedHex = @import("testkit").fuzz.seedHex;

/// Tag octets, in the format the length draw reads. `tagOf` reads exactly one
/// octet, so the interesting seeds are the two defined tags, the boundary
/// above them, and a full frame (the shape every real caller hands it).
const tag_seeds = [_][]const u8{
    seedHex("00"), // MsgTag.hello
    seedHex("01"), // MsgTag.bum
    seedHex("02"), // the first undefined tag: the "invalid enum value" panic this decoder exists to prevent
    seedHex("ff"), // the top of the byte range
    seedHex("0007000000010000000300000001000000"), // a Hello frame: what a dispatch site actually passes
    seedHex("010700000001000000ffffffff0a000000"), // a BUM frame with the `no_ingress` sentinel
    seedHex(""), // zero length → Truncated; the ONLY input this target ran before today
};

test "fuzz: tagOf never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzTagOf, .{ .corpus = &tag_seeds });
}

fn fuzzTagOf(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    var buf: [Hello.wire_len]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = tagOf(buf[0..len]) catch return;
}

test "corpus: every tag seed reaches tagOf, and the tags resolved are pinned" {
    // `hellos` and `bums` are the second numbers: `tagOf("")` returns
    // `error.Truncated`, so an "it did not panic" guard would have been
    // satisfied by the collapsed harness. A resolved tag cannot come from an
    // empty slice at all.
    var nonempty: usize = 0;
    var hellos: usize = 0;
    var bums: usize = 0;
    var invalid: usize = 0;
    for (tag_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Hello.wire_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const t = tagOf(buf[0..len]) catch |e| {
            if (e == error.InvalidEncoding) invalid += 1;
            continue;
        };
        switch (t) {
            .hello => hellos += 1,
            .bum => bums += 1,
        }
    }
    // Measured 2026-09-07. Before: 1 round, 0 non-empty, 0 tags resolved.
    try testing.expectEqual(tag_seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 2), hellos);
    try testing.expectEqual(@as(usize, 2), bums);
    try testing.expectEqual(@as(usize, 2), invalid);
}

/// Whole frames, in the format the length draw reads. The buffer is
/// `Hello.wire_len * 2` = 34 octets and the longest seed here is 34, which is
/// the point: a seed longer than the buffer is not a large seed, it is the
/// EMPTY one.
const frame_seeds = [_][]const u8{
    seedHex("00070000000100000003000000010000"), // Hello, one octet short of `wire_len` → Truncated
    seedHex("0007000000010000000300000005000000"), // Hello{ origin = 7, seq = 1, segment = 3, view = 0b101 }
    seedHex("010700000001000000ffffffff0a000000"), // BumFrame{ origin = 7, seq = 1, ingress = no_ingress, tag = 10 }
    seedHex("010700000001000000030000000b000000"), // BumFrame with a real segment id, tag = 11
    seedHex("010700000001000000ffffffff"), // a BUM frame in the old 13-octet layout, no tag → Truncated
    seedHex("00ffffffffffffffffffffffffffffffff"), // Hello with every field saturated
    seedHex("00070000000100000003000000010000000007000000020000000300000001000000"), // two Hellos back to back: 34 octets, the buffer exactly
    seedHex("7f0700000001000000030000000a000000"), // a tag that is neither: both decoders must refuse
    seedHex("00"), // a lone tag octet
    seedHex(""), // zero length; the collapsed harness's only input
};

test "fuzz: Hello/BumFrame decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzFrames, .{ .corpus = &frame_seeds });
}

fn fuzzFrames(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One byte-first draw. Never `bytes` then a ranged length.
    var buf: [Hello.wire_len * 2]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = Hello.decode(buf[0..len]) catch {};
    if (BumFrame.decode(buf[0..len])) |f| {
        // `id()` is called on every decoded frame by the delivery checker.
        std.mem.doNotOptimizeAway(f.id());
    } else |_| {}
}

test "corpus: every frame seed reaches both decoders, and what decodes is pinned" {
    // `ids` is the second number and it is the load-bearing one: it is a sum
    // over successfully decoded BUM frames, and an empty slice — the single
    // input this target ran for its whole life — produces `error.Truncated`
    // before any field is read, so it cannot contribute to it.
    var nonempty: usize = 0;
    var hellos: usize = 0;
    var bums: usize = 0;
    var ids: u64 = 0;
    for (frame_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Hello.wire_len * 2]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (Hello.decode(buf[0..len])) |_| hellos += 1 else |_| {}
        if (BumFrame.decode(buf[0..len])) |f| {
            bums += 1;
            ids +%= f.id();
        } else |_| {}
    }
    // Measured 2026-09-07. Before: 1 round, 0 non-empty, 0 decoded, id sum 0.
    // Seeds re-cut 2026-09-30 for the 17-octet Hello and BumFrame; same counts.
    try testing.expectEqual(frame_seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 3), hellos);
    try testing.expectEqual(@as(usize, 2), bums);
    try testing.expectEqual(@as(u64, 0x0000_0007_0000_0001 * 2), ids);
}

test "decode refuses the sibling message: identical layouts must not cross-decode" {
    // Hello and BumFrame are both 17 octets with a u32 quadruple, so the tag
    // byte is the ONLY thing separating them. Decoding one as the other used
    // to succeed and silently reinterpret the third field — `no_ingress`
    // (0xFFFFFFFF) arriving as a segment id.
    var hello_buf: [Hello.wire_len]u8 = undefined;
    (Hello{ .origin = 7, .seq = 1, .segment = 3, .view = 1 }).encode(&hello_buf);
    var bum_buf: [BumFrame.wire_len]u8 = undefined;
    (BumFrame{ .origin = 7, .seq = 1, .ingress_segment = no_ingress, .tag = 10 }).encode(&bum_buf);

    try testing.expectError(error.InvalidEncoding, BumFrame.decode(&hello_buf));
    try testing.expectError(error.InvalidEncoding, Hello.decode(&bum_buf));

    // A byte that is neither tag is refused by both, not just by `tagOf`.
    var junk = bum_buf;
    junk[0] = 0x7f;
    try testing.expectError(error.InvalidEncoding, BumFrame.decode(&junk));
    try testing.expectError(error.InvalidEncoding, Hello.decode(&junk));

    // The correct pairing still round-trips.
    try testing.expectEqual(@as(u32, 3), (try Hello.decode(&hello_buf)).segment);
    try testing.expectEqual(no_ingress, (try BumFrame.decode(&bum_buf)).ingress_segment);
}
