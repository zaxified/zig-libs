// SPDX-License-Identifier: MIT

//! **Clause 6 — the network layer (NPDU).** Two fixed octets followed by a
//! layout that **the control octet decides**, which is the part that goes
//! wrong in practice: a decoder that assumes a fixed prefix length will
//! happily read an APDU that starts several octets too early.
//!
//! ```text
//! +---------+---------+ ---- if control bit 5 ---- + ---- if bit 3 ---- + -- if bit 5 -- +
//! | version | control | DNET(2) DLEN(1) DADR(DLEN) | SNET(2) SLEN SADR  |   hop count    | ...
//! +---------+---------+----------------------------+--------------------+----------------+
//! ```
//!
//! The control octet:
//!
//! | bit | meaning |
//! |-----|---------|
//! | 7   | the payload is a **network-layer message**, not an APDU |
//! | 6   | reserved, must be zero |
//! | 5   | destination specifier present (DNET/DLEN/DADR **and the hop count**) |
//! | 4   | reserved, must be zero |
//! | 3   | source specifier present (SNET/SLEN/SADR) |
//! | 2   | expecting reply |
//! | 1-0 | network priority |
//!
//! Three traps live in there:
//!
//! * **The hop count is tied to the destination bit, not to its own bit.** It
//!   appears after the *source* fields, but only when bit 5 is set.
//! * **`DLEN == 0` is legal and means "broadcast on DNET"** — there is no
//!   address, and the entry is not a truncation.
//! * **`SLEN == 0` is not legal**: a source specifier with no address is
//!   meaningless, and a peer that sends one is malformed. (DNET `0xFFFF` is
//!   the global broadcast, which is what pairs with `DLEN == 0`.)
//!
//! Nothing here allocates. The APDU is a slice of the caller's buffer.

const std = @import("std");

pub const Error = error{
    /// Buffer ended in the middle of the NPCI.
    Truncated,
    /// Protocol version is not 1.
    UnsupportedVersion,
    /// A reserved control bit is set, `SLEN` is zero, or an address length
    /// exceeds what the buffer or the standard allows.
    InvalidControl,
    /// A network-layer message type this module does not decode.
    UnknownMessageType,
    /// Output buffer too small.
    NoSpace,
};

/// The only protocol version ASHRAE 135 has ever defined.
pub const version: u8 = 1;

/// The global-broadcast network number (clause 6.2.2). `DNET = 0xFFFF` with
/// `DLEN = 0` means "every network".
pub const global_broadcast_net: u16 = 0xFFFF;

/// Maximum octets a MAC address inside DADR/SADR may take. The standard caps
/// the field at a single length octet; MS/TP uses 1, BACnet/IP uses 6, and
/// nothing real exceeds 7 (ARCNET/Ethernet).
pub const max_mac_len: usize = 255;

/// Network priority (clause 6.2.2, the low two control bits).
pub const Priority = enum(u2) {
    normal = 0,
    urgent = 1,
    critical_equipment = 2,
    life_safety = 3,
};

/// A network address: a network number plus an optional MAC address. `mac_len
/// == 0` means "broadcast on this network", which is only legal for the
/// destination.
pub const NetAddress = struct {
    net: u16,
    /// Storage for the MAC. Fixed-size so an NPCI is a value, never a
    /// borrow — an NPDU header outlives the datagram in a client's state.
    mac: [7]u8 = @splat(0),
    mac_len: u8 = 0,

    pub fn address(self: *const NetAddress) []const u8 {
        return self.mac[0..self.mac_len];
    }

    /// A destination meaning "every device on `net`".
    pub fn broadcast(net: u16) NetAddress {
        return .{ .net = net };
    }

    /// The global broadcast: every device on every network.
    pub const global: NetAddress = .{ .net = global_broadcast_net };

    pub fn fromMac(net: u16, mac: []const u8) Error!NetAddress {
        if (mac.len > 7) return error.InvalidControl;
        var a: NetAddress = .{ .net = net, .mac_len = @intCast(mac.len) };
        @memcpy(a.mac[0..mac.len], mac);
        return a;
    }

    pub fn eql(a: NetAddress, b: NetAddress) bool {
        return a.net == b.net and std.mem.eql(u8, a.address(), b.address());
    }
};

/// Network-layer message types (clause 6.4.1). Values 0x00..0x7F are reserved
/// by ASHRAE; 0x80.. are vendor-proprietary and carry a vendor id.
pub const MessageType = enum(u8) {
    who_is_router_to_network = 0x00,
    i_am_router_to_network = 0x01,
    i_could_be_router_to_network = 0x02,
    reject_message_to_network = 0x03,
    router_busy_to_network = 0x04,
    router_available_to_network = 0x05,
    initialize_routing_table = 0x06,
    initialize_routing_table_ack = 0x07,
    establish_connection_to_network = 0x08,
    disconnect_connection_to_network = 0x09,
    challenge_request = 0x0A,
    security_payload = 0x0B,
    security_response = 0x0C,
    request_key_update = 0x0D,
    update_key_set = 0x0E,
    update_distribution_key = 0x0F,
    request_master_key = 0x10,
    set_master_key = 0x11,
    what_is_network_number = 0x12,
    network_number_is = 0x13,
    _,

    pub fn isProprietary(self: MessageType) bool {
        return @intFromEnum(self) >= 0x80;
    }
};

/// `Reject-Message-To-Network` reasons (clause 6.4.5).
pub const RejectReason = enum(u8) {
    other = 0,
    not_directly_connected = 1,
    router_busy = 2,
    unknown_message_type = 3,
    message_too_long = 4,
    security_error = 5,
    address_error = 6,
    _,
};

/// The network protocol control information — everything before the payload.
pub const Npci = struct {
    /// Destination specifier. Present iff control bit 5 is set; brings the hop
    /// count with it.
    destination: ?NetAddress = null,
    /// Source specifier. Present iff control bit 3 is set. A source with a
    /// zero-length address is malformed and is refused.
    source: ?NetAddress = null,
    /// Only present when `destination` is. Decremented by each router; a
    /// router that reaches zero drops the message.
    hop_count: u8 = 255,
    expecting_reply: bool = false,
    priority: Priority = .normal,
    /// Set when the payload is a network-layer message rather than an APDU.
    network_message: bool = false,

    pub fn controlOctet(self: Npci) u8 {
        var c: u8 = 0;
        if (self.network_message) c |= 0x80;
        if (self.destination != null) c |= 0x20;
        if (self.source != null) c |= 0x08;
        if (self.expecting_reply) c |= 0x04;
        c |= @intFromEnum(self.priority);
        return c;
    }

    /// Octets this NPCI occupies on the wire.
    ///
    /// Each `mac_len` is widened to `usize` **before** any arithmetic. Zig types
    /// `3 + d.mac_len` by its operands, not by where the result lands: written
    /// without the widening it is computed in `u8` and overflows at
    /// `mac_len >= 253`, even though `n` is a `usize`. That is the same shape as
    /// the `u16` length arithmetic in `sc.zig`'s `OptionIter` (audit BD-02).
    /// `decodeHeader` caps DLEN/SLEN at 7 and `NetAddress.fromMac` refuses
    /// longer, so no wire input reaches it today — but `NetAddress.mac_len` is a
    /// public field, so a caller-built NPCI does, and a bounds computation must
    /// not depend on an invariant enforced somewhere else.
    pub fn wireLen(self: Npci) usize {
        var n: usize = 2;
        if (self.destination) |d| n += 3 + @as(usize, d.mac_len);
        if (self.source) |s| n += 3 + @as(usize, s.mac_len);
        if (self.destination != null) n += 1; // hop count
        return n;
    }
};

/// A network-layer message body, decoded to the extent the standard makes it
/// worthwhile. The routing messages are typed; the rest are passed through so
/// a caller can log or forward them without this module pretending to
/// understand BACnet Network Security.
pub const NetworkMessage = union(enum) {
    /// Empty = "which routers exist?"; with a network = "who routes to N?"
    who_is_router_to_network: ?u16,
    /// The networks reachable through the sender. The list is big-endian
    /// `u16`s, which is not the host layout on any machine this runs on, so it
    /// is handed back as an iterator over the borrowed body rather than as a
    /// slice that would need byte-swapping into an allocation.
    i_am_router_to_network: NetworkListIterator,
    i_could_be_router_to_network: struct { net: u16, performance_index: u8 },
    reject_message_to_network: struct { reason: RejectReason, net: u16 },
    router_busy_to_network: NetworkListIterator,
    router_available_to_network: NetworkListIterator,
    /// Recognised, body passed through uninterpreted.
    other: struct { kind: MessageType, vendor_id: ?u16, body: []const u8 },

    pub fn kind(self: NetworkMessage) MessageType {
        return switch (self) {
            .who_is_router_to_network => .who_is_router_to_network,
            .i_am_router_to_network => .i_am_router_to_network,
            .i_could_be_router_to_network => .i_could_be_router_to_network,
            .reject_message_to_network => .reject_message_to_network,
            .router_busy_to_network => .router_busy_to_network,
            .router_available_to_network => .router_available_to_network,
            .other => |o| o.kind,
        };
    }
};

/// A decoded NPDU: the control information plus whatever it wraps.
pub const Npdu = struct {
    npci: Npci,
    payload: Payload,
    /// Octets the NPCI (and, for a network message, its type/vendor octets)
    /// occupied — i.e. where `apdu` starts inside the input.
    header_len: usize,

    pub const Payload = union(enum) {
        /// An application-layer PDU. Borrowed from the input buffer.
        apdu: []const u8,
        /// A network-layer message. Slice-carrying variants borrow too.
        network: NetworkMessage,
    };

    /// The APDU, or null when this NPDU carries a network-layer message.
    pub fn apdu(self: Npdu) ?[]const u8 {
        return switch (self.payload) {
            .apdu => |a| a,
            .network => null,
        };
    }
};

/// Decodes one NPDU. `buf` is the whole NPDU as it came out of a BVLC.
pub fn decode(buf: []const u8) Error!Npdu {
    if (buf.len < 2) return error.Truncated;
    if (buf[0] != version) return error.UnsupportedVersion;
    const control = buf[1];
    // Bits 6 and 4 are reserved and *shall* be zero (clause 6.2.2). A peer
    // that sets one is either broken or probing; refusing beats guessing which
    // optional fields it thinks it sent.
    if (control & 0x50 != 0) return error.InvalidControl;

    var npci: Npci = .{
        .expecting_reply = control & 0x04 != 0,
        .priority = @enumFromInt(@as(u2, @truncate(control & 0x03))),
        .network_message = control & 0x80 != 0,
    };

    var pos: usize = 2;
    if (control & 0x20 != 0) {
        if (pos + 3 > buf.len) return error.Truncated;
        const net = std.mem.readInt(u16, buf[pos..][0..2], .big);
        const dlen = buf[pos + 2];
        pos += 3;
        if (dlen > 7) return error.InvalidControl;
        if (pos + dlen > buf.len) return error.Truncated;
        // DLEN == 0 is legal: "broadcast on DNET".
        npci.destination = try NetAddress.fromMac(net, buf[pos..][0..dlen]);
        pos += dlen;
    }
    if (control & 0x08 != 0) {
        if (pos + 3 > buf.len) return error.Truncated;
        const net = std.mem.readInt(u16, buf[pos..][0..2], .big);
        const slen = buf[pos + 2];
        pos += 3;
        // A source specifier with no address cannot be replied to; the
        // standard forbids it and so does this decoder.
        if (slen == 0 or slen > 7) return error.InvalidControl;
        if (pos + slen > buf.len) return error.Truncated;
        npci.source = try NetAddress.fromMac(net, buf[pos..][0..slen]);
        pos += slen;
    }
    if (npci.destination != null) {
        if (pos + 1 > buf.len) return error.Truncated;
        npci.hop_count = buf[pos];
        pos += 1;
    }

    if (!npci.network_message) {
        return .{ .npci = npci, .payload = .{ .apdu = buf[pos..] }, .header_len = pos };
    }

    if (pos + 1 > buf.len) return error.Truncated;
    const kind: MessageType = @enumFromInt(buf[pos]);
    pos += 1;
    var vendor: ?u16 = null;
    if (kind.isProprietary()) {
        if (pos + 2 > buf.len) return error.Truncated;
        vendor = std.mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
    }
    const body = buf[pos..];
    const msg: NetworkMessage = switch (kind) {
        .who_is_router_to_network => blk: {
            if (body.len == 0) break :blk .{ .who_is_router_to_network = null };
            if (body.len != 2) return error.Truncated;
            break :blk .{ .who_is_router_to_network = std.mem.readInt(u16, body[0..2], .big) };
        },
        .i_am_router_to_network,
        .router_busy_to_network,
        .router_available_to_network,
        => blk: {
            if (body.len % 2 != 0) return error.Truncated;
            const it: NetworkListIterator = .{ .body = body };
            break :blk switch (kind) {
                .i_am_router_to_network => .{ .i_am_router_to_network = it },
                .router_busy_to_network => .{ .router_busy_to_network = it },
                else => .{ .router_available_to_network = it },
            };
        },
        .i_could_be_router_to_network => blk: {
            if (body.len != 3) return error.Truncated;
            break :blk .{ .i_could_be_router_to_network = .{
                .net = std.mem.readInt(u16, body[0..2], .big),
                .performance_index = body[2],
            } };
        },
        .reject_message_to_network => blk: {
            if (body.len != 3) return error.Truncated;
            break :blk .{ .reject_message_to_network = .{
                .reason = @enumFromInt(body[0]),
                .net = std.mem.readInt(u16, body[1..3], .big),
            } };
        },
        else => .{ .other = .{ .kind = kind, .vendor_id = vendor, .body = body } },
    };
    return .{ .npci = npci, .payload = .{ .network = msg }, .header_len = pos };
}

/// Walks the big-endian `u16` network list in an `I-Am-Router-To-Network`
/// (or router-busy/available) body.
pub const NetworkListIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *NetworkListIterator) ?u16 {
        if (self.pos + 2 > self.body.len) return null;
        const v = std.mem.readInt(u16, self.body[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    pub fn count(self: NetworkListIterator) usize {
        return self.body.len / 2;
    }
};

/// Encodes an NPCI followed by `payload` (an APDU, already encoded).
pub fn encode(npci: Npci, payload: []const u8, out: []u8) Error![]u8 {
    var w = HeaderWriter{ .out = out };
    try w.npci(npci);
    try w.raw(payload);
    return out[0..w.pos];
}

/// Encodes an NPCI carrying a network-layer message. `npci.network_message` is
/// forced on, so a caller cannot emit a message the control octet denies.
pub fn encodeNetworkMessage(npci_in: Npci, msg: NetworkMessage, out: []u8) Error![]u8 {
    var npci = npci_in;
    npci.network_message = true;
    var w = HeaderWriter{ .out = out };
    try w.npci(npci);
    switch (msg) {
        .who_is_router_to_network => |maybe_net| {
            try w.byte(@intFromEnum(MessageType.who_is_router_to_network));
            if (maybe_net) |n| try w.u16be(n);
        },
        .i_am_router_to_network,
        .router_busy_to_network,
        .router_available_to_network,
        => |list| {
            try w.byte(@intFromEnum(msg.kind()));
            // Re-emit the borrowed body verbatim: it is already big-endian
            // `u16`s and re-serialising through the iterator would be the same
            // octets with more chances to be wrong.
            try w.raw(list.body);
        },
        .i_could_be_router_to_network => |c| {
            try w.byte(@intFromEnum(MessageType.i_could_be_router_to_network));
            try w.u16be(c.net);
            try w.byte(c.performance_index);
        },
        .reject_message_to_network => |r| {
            try w.byte(@intFromEnum(MessageType.reject_message_to_network));
            try w.byte(@intFromEnum(r.reason));
            try w.u16be(r.net);
        },
        .other => |o| {
            try w.byte(@intFromEnum(o.kind));
            if (o.kind.isProprietary()) try w.u16be(o.vendor_id orelse return error.InvalidControl);
            try w.raw(o.body);
        },
    }
    return out[0..w.pos];
}

/// Encodes one of the list-carrying routing messages
/// (`I-Am-Router-To-Network` and friends).
pub fn encodeNetworkList(
    npci_in: Npci,
    kind: MessageType,
    nets: []const u16,
    out: []u8,
) Error![]u8 {
    switch (kind) {
        .i_am_router_to_network,
        .router_busy_to_network,
        .router_available_to_network,
        => {},
        else => return error.UnknownMessageType,
    }
    var npci = npci_in;
    npci.network_message = true;
    var w = HeaderWriter{ .out = out };
    try w.npci(npci);
    try w.byte(@intFromEnum(kind));
    for (nets) |n| try w.u16be(n);
    return out[0..w.pos];
}

const HeaderWriter = struct {
    out: []u8,
    pos: usize = 0,

    fn byte(self: *HeaderWriter, b: u8) Error!void {
        if (self.pos + 1 > self.out.len) return error.NoSpace;
        self.out[self.pos] = b;
        self.pos += 1;
    }

    fn u16be(self: *HeaderWriter, v: u16) Error!void {
        if (self.pos + 2 > self.out.len) return error.NoSpace;
        std.mem.writeInt(u16, self.out[self.pos..][0..2], v, .big);
        self.pos += 2;
    }

    fn raw(self: *HeaderWriter, bytes: []const u8) Error!void {
        if (self.pos + bytes.len > self.out.len) return error.NoSpace;
        @memcpy(self.out[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn npci(self: *HeaderWriter, n: Npci) Error!void {
        if (n.source) |s| {
            if (s.mac_len == 0) return error.InvalidControl;
        }
        try self.byte(version);
        try self.byte(n.controlOctet());
        if (n.destination) |d| {
            try self.u16be(d.net);
            try self.byte(d.mac_len);
            try self.raw(d.address());
        }
        if (n.source) |s| {
            try self.u16be(s.net);
            try self.byte(s.mac_len);
            try self.raw(s.address());
        }
        if (n.destination != null) try self.byte(n.hop_count);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the plainest NPDU: version, control, APDU" {
    const wire = [_]u8{ 0x01, 0x00, 0x10, 0x08 };
    const n = try decode(&wire);
    try testing.expectEqual(@as(?NetAddress, null), n.npci.destination);
    try testing.expectEqual(@as(?NetAddress, null), n.npci.source);
    try testing.expectEqual(false, n.npci.expecting_reply);
    try testing.expectEqual(Priority.normal, n.npci.priority);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x08 }, n.apdu().?);
    try testing.expectEqual(@as(usize, 2), n.header_len);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(n.npci, n.apdu().?, &out));
}

test "every combination of the four presence/flag bits round-trips" {
    var out: [64]u8 = undefined;
    const apdu_bytes = [_]u8{ 0x10, 0x08, 0xAA };

    // 2 (dest) x 2 (source) x 2 (expecting reply) x 4 (priority) = 32 shapes,
    // and the destination arm is exercised with both a MAC and a broadcast.
    for ([_]bool{ false, true }) |has_dest| {
        for ([_]u8{ 0, 1, 6 }) |dlen| {
            if (!has_dest and dlen != 0) continue;
            for ([_]bool{ false, true }) |has_src| {
                for ([_]u8{ 1, 6 }) |slen| {
                    if (!has_src and slen != 1) continue;
                    for ([_]bool{ false, true }) |reply| {
                        for ([_]Priority{ .normal, .urgent, .critical_equipment, .life_safety }) |prio| {
                            const mac = [_]u8{ 0xC0, 0x00, 0x02, 0x05, 0xBA, 0xC0 };
                            var npci: Npci = .{
                                .expecting_reply = reply,
                                .priority = prio,
                                .hop_count = 250,
                            };
                            if (has_dest) npci.destination = try NetAddress.fromMac(1234, mac[0..dlen]);
                            if (has_src) npci.source = try NetAddress.fromMac(5678, mac[0..slen]);

                            const wire = try encode(npci, &apdu_bytes, &out);
                            try testing.expectEqual(npci.wireLen(), wire.len - apdu_bytes.len);

                            const back = try decode(wire);
                            try testing.expectEqual(has_dest, back.npci.destination != null);
                            try testing.expectEqual(has_src, back.npci.source != null);
                            try testing.expectEqual(reply, back.npci.expecting_reply);
                            try testing.expectEqual(prio, back.npci.priority);
                            if (has_dest) {
                                try testing.expect(back.npci.destination.?.eql(npci.destination.?));
                                try testing.expectEqual(@as(u8, 250), back.npci.hop_count);
                            }
                            if (has_src) try testing.expect(back.npci.source.?.eql(npci.source.?));
                            try testing.expectEqualSlices(u8, &apdu_bytes, back.apdu().?);
                            try testing.expectEqual(npci.wireLen(), back.header_len);
                        }
                    }
                }
            }
        }
    }
}

test "the hop count follows the SOURCE fields but belongs to the DESTINATION bit" {
    // control 0x28 = destination + source. Layout: 01 28 | DNET DLEN DADR |
    // SNET SLEN SADR | hop | APDU.
    const wire = [_]u8{
        0x01, 0x28,
        0x04, 0xD2, 0x01, 0x0A, // DNET 1234, DLEN 1, DADR 0x0A
        0x16, 0x2E, 0x02, 0xAA, 0xBB, // SNET 5678, SLEN 2, SADR aa bb
        0xFE, // hop count 254 — AFTER the source fields
        0x10,
        0x08,
    };
    const n = try decode(&wire);
    try testing.expectEqual(@as(u16, 1234), n.npci.destination.?.net);
    try testing.expectEqualSlices(u8, &.{0x0A}, n.npci.destination.?.address());
    try testing.expectEqual(@as(u16, 5678), n.npci.source.?.net);
    try testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, n.npci.source.?.address());
    try testing.expectEqual(@as(u8, 0xFE), n.npci.hop_count);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x08 }, n.apdu().?);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(n.npci, n.apdu().?, &out));

    // Source only: NO hop count, so the APDU starts one octet earlier than a
    // naive decoder would think.
    const src_only = [_]u8{ 0x01, 0x08, 0x16, 0x2E, 0x01, 0x0B, 0x10, 0x08 };
    const s = try decode(&src_only);
    try testing.expectEqual(@as(?NetAddress, null), s.npci.destination);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x08 }, s.apdu().?);
}

test "DLEN 0 is a broadcast, SLEN 0 is malformed" {
    // Global broadcast: DNET ffff, DLEN 0, hop 255.
    const bcast = [_]u8{ 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    const n = try decode(&bcast);
    try testing.expectEqual(global_broadcast_net, n.npci.destination.?.net);
    try testing.expectEqual(@as(usize, 0), n.npci.destination.?.address().len);
    try testing.expectEqual(@as(u8, 255), n.npci.hop_count);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x08 }, n.apdu().?);

    // A source specifier with SLEN 0 has nothing to reply to.
    try testing.expectError(error.InvalidControl, decode(&.{
        0x01, 0x08, 0x16, 0x2E, 0x00, 0x10, 0x08,
    }));

    // ... and encode refuses to produce one.
    var out: [32]u8 = undefined;
    const bad: Npci = .{ .source = .{ .net = 5, .mac_len = 0 } };
    try testing.expectError(error.InvalidControl, encode(bad, &.{0x10}, &out));
}

test "control bits promising fields the buffer does not contain" {
    // Destination bit set, nothing after the control octet.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x20 }));
    // DNET present, DLEN missing.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x20, 0x04, 0xD2 }));
    // DLEN 6 announced, only 3 octets left.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x20, 0x04, 0xD2, 0x06, 1, 2, 3 }));
    // Everything present but the hop count.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x20, 0x04, 0xD2, 0x01, 0x0A }));
    // Source bit set, nothing follows.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x08 }));
    // Network-message bit set, no message type octet.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x80 }));
    // Truncated before the control octet.
    try testing.expectError(error.Truncated, decode(&.{0x01}));
    // Wrong version.
    try testing.expectError(error.UnsupportedVersion, decode(&.{ 0x02, 0x00, 0x10 }));
    // Reserved bits 6 and 4.
    try testing.expectError(error.InvalidControl, decode(&.{ 0x01, 0x40, 0x10 }));
    try testing.expectError(error.InvalidControl, decode(&.{ 0x01, 0x10, 0x10 }));
    // An address length beyond the 7-octet ceiling.
    try testing.expectError(error.InvalidControl, decode(&.{ 0x01, 0x20, 0x00, 0x01, 0x08 }));
}

test "Who-Is-Router-To-Network, both forms" {
    // Global broadcast, network message, no network number = "list yourselves".
    const all = [_]u8{ 0x01, 0x80, 0x00 };
    const n = try decode(&all);
    try testing.expect(n.npci.network_message);
    try testing.expectEqual(@as(?u16, null), n.payload.network.who_is_router_to_network);
    try testing.expectEqual(@as(?[]const u8, null), n.apdu());

    // With a network number.
    const one = [_]u8{ 0x01, 0x80, 0x00, 0x04, 0xD2 };
    const m = try decode(&one);
    try testing.expectEqual(@as(?u16, 1234), m.payload.network.who_is_router_to_network);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &all, try encodeNetworkMessage(
        .{},
        .{ .who_is_router_to_network = null },
        &out,
    ));
    try testing.expectEqualSlices(u8, &one, try encodeNetworkMessage(
        .{},
        .{ .who_is_router_to_network = 1234 },
        &out,
    ));

    // A body of the wrong size.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x80, 0x00, 0x04 }));
}

test "I-Am-Router-To-Network network list" {
    const wire = [_]u8{ 0x01, 0x80, 0x01, 0x00, 0x01, 0x04, 0xD2, 0xFF, 0xFE };
    const n = try decode(&wire);
    try testing.expectEqual(MessageType.i_am_router_to_network, n.payload.network.kind());

    var it = n.payload.network.i_am_router_to_network;
    try testing.expectEqual(@as(usize, 3), it.count());
    try testing.expectEqual(@as(?u16, 1), it.next());
    try testing.expectEqual(@as(?u16, 1234), it.next());
    try testing.expectEqual(@as(?u16, 0xFFFE), it.next());
    try testing.expectEqual(@as(?u16, null), it.next());

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encodeNetworkList(
        .{},
        .i_am_router_to_network,
        &.{ 1, 1234, 0xFFFE },
        &out,
    ));

    // Re-encoding through the generic path reproduces the same octets.
    try testing.expectEqualSlices(u8, &wire, try encodeNetworkMessage(
        .{},
        n.payload.network,
        &out,
    ));

    // An odd-length list is truncated, not silently rounded down.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x80, 0x01, 0x00 }));
}

test "Reject-Message-To-Network" {
    const wire = [_]u8{ 0x01, 0x80, 0x03, 0x01, 0x04, 0xD2 };
    const n = try decode(&wire);
    const r = n.payload.network.reject_message_to_network;
    try testing.expectEqual(RejectReason.not_directly_connected, r.reason);
    try testing.expectEqual(@as(u16, 1234), r.net);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encodeNetworkMessage(
        .{},
        .{ .reject_message_to_network = .{ .reason = .not_directly_connected, .net = 1234 } },
        &out,
    ));
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x80, 0x03, 0x01, 0x04 }));

    // I-Could-Be-Router-To-Network.
    const icb = [_]u8{ 0x01, 0x80, 0x02, 0x04, 0xD2, 0x07 };
    const m = try decode(&icb);
    try testing.expectEqual(@as(u16, 1234), m.payload.network.i_could_be_router_to_network.net);
    try testing.expectEqual(@as(u8, 7), m.payload.network.i_could_be_router_to_network.performance_index);
    try testing.expectEqualSlices(u8, &icb, try encodeNetworkMessage(
        .{},
        .{ .i_could_be_router_to_network = .{ .net = 1234, .performance_index = 7 } },
        &out,
    ));
}

test "an unmodelled network message is passed through, with its vendor id" {
    // 0x12 What-Is-Network-Number, no body.
    const std_msg = [_]u8{ 0x01, 0x80, 0x12 };
    const n = try decode(&std_msg);
    try testing.expectEqual(MessageType.what_is_network_number, n.payload.network.other.kind);
    try testing.expectEqual(@as(?u16, null), n.payload.network.other.vendor_id);

    // A proprietary type carries a two-octet vendor id before its body.
    const vendor = [_]u8{ 0x01, 0x80, 0x90, 0x01, 0x2C, 0xDE, 0xAD };
    const m = try decode(&vendor);
    try testing.expectEqual(@as(?u16, 300), m.payload.network.other.vendor_id);
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD }, m.payload.network.other.body);

    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &vendor, try encodeNetworkMessage(
        .{},
        .{ .other = .{ .kind = @enumFromInt(0x90), .vendor_id = 300, .body = &.{ 0xDE, 0xAD } } },
        &out,
    ));

    // A proprietary type whose vendor id is truncated.
    try testing.expectError(error.Truncated, decode(&.{ 0x01, 0x80, 0x90, 0x01 }));
}

test "encode refuses to overflow the output buffer at any field" {
    const npci: Npci = .{
        .destination = try NetAddress.fromMac(1, &.{ 1, 2, 3, 4, 5, 6 }),
        .source = try NetAddress.fromMac(2, &.{ 7, 8 }),
    };
    // 2 (version+control) + 9 (DNET/DLEN/6-octet DADR) + 5 (SNET/SLEN/2-octet
    // SADR) + 1 (hop count) + 2 (APDU) = 19. Every buffer short of that must
    // fail at whichever field runs out, never write past the end.
    try testing.expectEqual(@as(usize, 17), npci.wireLen());
    inline for (.{ 0, 1, 2, 4, 6, 9, 11, 13, 16, 17, 18 }) |n| {
        var small: [n]u8 = undefined;
        try testing.expectError(error.NoSpace, encode(npci, &.{ 0x10, 0x08 }, &small));
    }
    var ok: [19]u8 = undefined;
    const wire = try encode(npci, &.{ 0x10, 0x08 }, &ok);
    try testing.expectEqual(@as(usize, 19), wire.len);
}

// ── regression: `wireLen` must not do its arithmetic in `u8` (audit BD-19) ───
//
// `NetAddress.mac_len` is a public field, so an NPCI can be built with any
// length at all without going through `fromMac`. `3 + d.mac_len` written
// unwidened is typed by its operands — `u8` — and panics with "integer
// overflow" from `mac_len == 253` upward, in a function whose whole job is to
// tell the caller how big a buffer to hand `encode`. Same shape as BD-02 in
// `sc.zig`; there it silently wrapped a bounds check, here it traps.
test "wireLen is computed in usize, not in the u8 the operands imply" {
    // 253 is where `3 + mac_len` first leaves the u8 range.
    for ([_]u8{ 252, 253, 254, 255 }) |len| {
        const d: Npci = .{ .destination = .{ .net = 1, .mac_len = len } };
        try testing.expectEqual(@as(usize, 2 + 3 + @as(usize, len) + 1), d.wireLen());
        const s: Npci = .{ .source = .{ .net = 1, .mac_len = len } };
        try testing.expectEqual(@as(usize, 2 + 3 + @as(usize, len)), s.wireLen());
        const both: Npci = .{
            .destination = .{ .net = 1, .mac_len = len },
            .source = .{ .net = 2, .mac_len = len },
        };
        try testing.expectEqual(@as(usize, 2 + 2 * (3 + @as(usize, len)) + 1), both.wireLen());
    }
    // The legal lengths are unchanged.
    try testing.expectEqual(@as(usize, 17), (Npci{
        .destination = try NetAddress.fromMac(1, &.{ 1, 2, 3, 4, 5, 6 }),
        .source = try NetAddress.fromMac(2, &.{ 7, 8 }),
    }).wireLen());
}

test "fuzz: NPDU decode never panics and canonical headers re-encode" {
    try std.testing.fuzz({}, fuzzNpdu, .{});
}

fn fuzzNpdu(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];
    const n = decode(input) catch return;
    switch (n.payload) {
        .apdu => |a| {
            var out: [256]u8 = undefined;
            const again = encode(n.npci, a, &out) catch return;
            try testing.expectEqualSlices(u8, input, again);
        },
        .network => {},
    }
}
