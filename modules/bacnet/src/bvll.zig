// SPDX-License-Identifier: MIT

//! **Annex J — BACnet/IP virtual link layer (BVLL/BVLC).** Four octets in
//! front of every BACnet/IP datagram:
//!
//! ```text
//! +------+----------+----------------+
//! | 0x81 | function |  length (u16)  |   then the function's body
//! +------+----------+----------------+
//! ```
//!
//! Two things about that header are worth stating up front, because both are
//! routine sources of bugs:
//!
//! * **The length counts the whole message including these four octets**, not
//!   the body. A BVLC whose length disagrees with the datagram it arrived in
//!   is a typed error here, never a silently-shortened read — UDP hands you a
//!   datagram with a known size, so the disagreement is always detectable and
//!   always means something is wrong.
//! * **BACnet/IP has no routers in the IP sense.** Broadcasts do not cross
//!   subnets, so a *BBMD* (BACnet Broadcast Management Device) forwards them
//!   for you: `Distribute-Broadcast-To-Network` goes to your BBMD, which
//!   re-emits it locally and as `Forwarded-NPDU` to its peer BBMDs. A device
//!   with no local BBMD registers as a *foreign device* instead. All of that
//!   is codec-level here — the BBMD tables and the registration timer are the
//!   caller's policy.
//!
//! Nothing in this file allocates; NPDU payloads are slices borrowed from the
//! caller's datagram buffer.

const std = @import("std");
const netaddr = @import("netaddr");

pub const Error = error{
    /// Not a BACnet/IP datagram (first octet is not 0x81), or shorter than the
    /// four-octet header.
    NotBvlc,
    /// The length field disagrees with the datagram actually received.
    LengthMismatch,
    /// The datagram ended inside a function body.
    Truncated,
    /// A function code this module does not decode.
    UnknownFunction,
    /// A body that is well formed as octets but impossible for its function —
    /// a BDT entry list whose length is not a multiple of 10, a Result whose
    /// code is not defined for its context.
    InvalidBody,
    /// The output buffer is too small.
    NoSpace,
};

/// The BACnet/IP type octet. Annex J assigns exactly one value.
pub const bvlc_type: u8 = 0x81;

/// The registered BACnet/IP UDP port, 47808 (`0xBAC0`). Annex J also permits
/// 47809..47823 for additional networks on the same subnet, which is what a
/// test device on a high port normally uses.
pub const default_port: u16 = 0xBAC0;

/// The four-octet BVLC header.
pub const header_len: usize = 4;

/// BVLC function codes (Annex J.2.1.1).
pub const Function = enum(u8) {
    result = 0x00,
    write_broadcast_distribution_table = 0x01,
    read_broadcast_distribution_table = 0x02,
    read_broadcast_distribution_table_ack = 0x03,
    forwarded_npdu = 0x04,
    register_foreign_device = 0x05,
    read_foreign_device_table = 0x06,
    read_foreign_device_table_ack = 0x07,
    delete_foreign_device_table_entry = 0x08,
    distribute_broadcast_to_network = 0x09,
    original_unicast_npdu = 0x0A,
    original_broadcast_npdu = 0x0B,
    secure_bvll = 0x0C,
    _,
};

/// `BVLC-Result` codes (Annex J.2.2.1). `success` is only ever sent in
/// response to a Register-Foreign-Device; the others are per-request NAKs.
pub const ResultCode = enum(u16) {
    success = 0x0000,
    write_broadcast_distribution_table_nak = 0x0010,
    read_broadcast_distribution_table_nak = 0x0020,
    register_foreign_device_nak = 0x0030,
    read_foreign_device_table_nak = 0x0040,
    delete_foreign_device_table_entry_nak = 0x0050,
    distribute_broadcast_to_network_nak = 0x0060,
    _,
};

/// A BACnet/IP address: four octets of IPv4 plus a big-endian UDP port. This
/// is the `B/IP address` of Annex J, and it is what appears inside a
/// Forwarded-NPDU and every BDT/FDT entry. Six octets on the wire.
pub const BipAddress = struct {
    ip: [4]u8,
    port: u16 = default_port,

    pub const wire_len: usize = 6;

    pub fn encode(self: BipAddress, out: *[6]u8) void {
        @memcpy(out[0..4], &self.ip);
        std.mem.writeInt(u16, out[4..6], self.port, .big);
    }

    pub fn decode(d: *const [6]u8) BipAddress {
        return .{
            .ip = d[0..4].*,
            .port = std.mem.readInt(u16, d[4..6], .big),
        };
    }

    /// Interop with the sibling `netaddr` module, which is where address
    /// parsing and formatting live for the whole collection.
    pub fn toIp(self: BipAddress) netaddr.Ip {
        return .{ .v4 = self.ip };
    }

    pub fn fromIp(ip: netaddr.Ip, port: u16) ?BipAddress {
        return switch (ip) {
            .v4 => |v| .{ .ip = v, .port = port },
            // BACnet/IP as standardised in Annex J is IPv4 only; IPv6 has its
            // own link layer (Annex U, `BACnet/IPv6`), which this module does
            // not implement.
            .v6 => null,
        };
    }

    pub fn parse(text: []const u8) ?BipAddress {
        const hp = netaddr.parseHostPort(text) orelse {
            const ip = netaddr.parseIp4(text) orelse return null;
            return .{ .ip = ip, .port = default_port };
        };
        const ip = netaddr.parseIp4(hp.host) orelse return null;
        return .{ .ip = ip, .port = hp.port };
    }

    pub fn eql(a: BipAddress, b: BipAddress) bool {
        return std.mem.eql(u8, &a.ip, &b.ip) and a.port == b.port;
    }
};

/// A Broadcast Distribution Table entry (Annex J.4.4.2): a peer BBMD plus the
/// broadcast-distribution mask that says how it should re-emit. A mask of
/// `255.255.255.255` means "direct to that BBMD"; anything else means the BBMD
/// should re-broadcast onto its own subnet.
pub const BdtEntry = struct {
    address: BipAddress,
    mask: [4]u8 = .{ 255, 255, 255, 255 },

    pub const wire_len: usize = 10;
};

/// A Foreign Device Table entry (Annex J.4.5.2): a registered foreign device,
/// the time-to-live it asked for, and the seconds left before it is purged.
pub const FdtEntry = struct {
    address: BipAddress,
    ttl_seconds: u16,
    remaining_seconds: u16,

    pub const wire_len: usize = 10;
};

/// A decoded BVLC message. NPDU payloads borrow from the input datagram.
pub const Message = union(Function) {
    result: ResultCode,
    /// The whole table, as raw octets — decode with `bdtIterator`, which keeps
    /// this union allocation-free.
    write_broadcast_distribution_table: []const u8,
    read_broadcast_distribution_table,
    read_broadcast_distribution_table_ack: []const u8,
    forwarded_npdu: struct {
        /// The originating device, as seen by the forwarding BBMD.
        origin: BipAddress,
        npdu: []const u8,
    },
    register_foreign_device: struct {
        /// How long the BBMD should keep the registration, in seconds. The
        /// BBMD adds a 30-second grace period of its own (J.5.2.3).
        ttl_seconds: u16,
    },
    read_foreign_device_table,
    read_foreign_device_table_ack: []const u8,
    delete_foreign_device_table_entry: BipAddress,
    distribute_broadcast_to_network: []const u8,
    original_unicast_npdu: []const u8,
    original_broadcast_npdu: []const u8,
    /// Annex U security wrapper — recognised, passed through, never
    /// interpreted (see SPEC.md's deferred list).
    secure_bvll: []const u8,

    /// The NPDU inside, for the four functions that carry one. Everything else
    /// is a link-layer management message with no NPDU at all.
    pub fn npdu(self: Message) ?[]const u8 {
        return switch (self) {
            .original_unicast_npdu,
            .original_broadcast_npdu,
            .distribute_broadcast_to_network,
            => |p| p,
            .forwarded_npdu => |f| f.npdu,
            else => null,
        };
    }

    pub fn function(self: Message) Function {
        return std.meta.activeTag(self);
    }
};

/// Decodes one BVLC datagram. `datagram` must be **exactly** what the socket
/// delivered — the length field is checked against `datagram.len`, which is
/// the whole point of doing this over UDP.
pub fn decode(datagram: []const u8) Error!Message {
    if (datagram.len < header_len) return error.NotBvlc;
    if (datagram[0] != bvlc_type) return error.NotBvlc;
    const declared = std.mem.readInt(u16, datagram[2..4], .big);
    if (declared != datagram.len) return error.LengthMismatch;

    const func: Function = @enumFromInt(datagram[1]);
    const body = datagram[header_len..];

    switch (func) {
        .result => {
            if (body.len != 2) return error.Truncated;
            return .{ .result = @enumFromInt(std.mem.readInt(u16, body[0..2], .big)) };
        },
        .write_broadcast_distribution_table => {
            if (body.len % BdtEntry.wire_len != 0) return error.InvalidBody;
            return .{ .write_broadcast_distribution_table = body };
        },
        .read_broadcast_distribution_table => {
            if (body.len != 0) return error.InvalidBody;
            return .read_broadcast_distribution_table;
        },
        .read_broadcast_distribution_table_ack => {
            if (body.len % BdtEntry.wire_len != 0) return error.InvalidBody;
            return .{ .read_broadcast_distribution_table_ack = body };
        },
        .forwarded_npdu => {
            if (body.len < BipAddress.wire_len) return error.Truncated;
            return .{ .forwarded_npdu = .{
                .origin = BipAddress.decode(body[0..6]),
                .npdu = body[BipAddress.wire_len..],
            } };
        },
        .register_foreign_device => {
            if (body.len != 2) return error.Truncated;
            return .{ .register_foreign_device = .{
                .ttl_seconds = std.mem.readInt(u16, body[0..2], .big),
            } };
        },
        .read_foreign_device_table => {
            if (body.len != 0) return error.InvalidBody;
            return .read_foreign_device_table;
        },
        .read_foreign_device_table_ack => {
            if (body.len % FdtEntry.wire_len != 0) return error.InvalidBody;
            return .{ .read_foreign_device_table_ack = body };
        },
        .delete_foreign_device_table_entry => {
            if (body.len != BipAddress.wire_len) return error.Truncated;
            return .{ .delete_foreign_device_table_entry = BipAddress.decode(body[0..6]) };
        },
        .distribute_broadcast_to_network => return .{ .distribute_broadcast_to_network = body },
        .original_unicast_npdu => return .{ .original_unicast_npdu = body },
        .original_broadcast_npdu => return .{ .original_broadcast_npdu = body },
        .secure_bvll => return .{ .secure_bvll = body },
        _ => return error.UnknownFunction,
    }
}

/// Encodes a message into `out`, returning the slice written.
pub fn encode(msg: Message, out: []u8) Error![]u8 {
    var body_len: usize = switch (msg) {
        .result => 2,
        .write_broadcast_distribution_table => |t| t.len,
        .read_broadcast_distribution_table => 0,
        .read_broadcast_distribution_table_ack => |t| t.len,
        .forwarded_npdu => |f| BipAddress.wire_len + f.npdu.len,
        .register_foreign_device => 2,
        .read_foreign_device_table => 0,
        .read_foreign_device_table_ack => |t| t.len,
        .delete_foreign_device_table_entry => BipAddress.wire_len,
        .distribute_broadcast_to_network,
        .original_unicast_npdu,
        .original_broadcast_npdu,
        .secure_bvll,
        => |p| p.len,
    };
    const total = header_len + body_len;
    if (total > std.math.maxInt(u16)) return error.NoSpace;
    if (out.len < total) return error.NoSpace;

    out[0] = bvlc_type;
    out[1] = @intFromEnum(msg.function());
    std.mem.writeInt(u16, out[2..4], @intCast(total), .big);
    const body = out[header_len..total];

    switch (msg) {
        .result => |c| std.mem.writeInt(u16, body[0..2], @intFromEnum(c), .big),
        .write_broadcast_distribution_table,
        .read_broadcast_distribution_table_ack,
        .read_foreign_device_table_ack,
        => |t| @memcpy(body, t),
        .read_broadcast_distribution_table, .read_foreign_device_table => {},
        .forwarded_npdu => |f| {
            f.origin.encode(body[0..6]);
            @memcpy(body[BipAddress.wire_len..], f.npdu);
        },
        .register_foreign_device => |r| std.mem.writeInt(u16, body[0..2], r.ttl_seconds, .big),
        .delete_foreign_device_table_entry => |a| a.encode(body[0..6]),
        .distribute_broadcast_to_network,
        .original_unicast_npdu,
        .original_broadcast_npdu,
        .secure_bvll,
        => |p| @memcpy(body, p),
    }
    body_len = total;
    return out[0..total];
}

/// Wraps an NPDU in the given function. The common path: one call, one
/// datagram, no intermediate copy beyond the NPDU itself.
pub fn wrap(func: Function, npdu_bytes: []const u8, out: []u8) Error![]u8 {
    const msg: Message = switch (func) {
        .original_unicast_npdu => .{ .original_unicast_npdu = npdu_bytes },
        .original_broadcast_npdu => .{ .original_broadcast_npdu = npdu_bytes },
        .distribute_broadcast_to_network => .{ .distribute_broadcast_to_network = npdu_bytes },
        else => return error.UnknownFunction,
    };
    return encode(msg, out);
}

// ── table iterators (allocation-free views over a decoded body) ─────────────

pub const BdtIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *BdtIterator) ?BdtEntry {
        if (self.pos + BdtEntry.wire_len > self.body.len) return null;
        const d = self.body[self.pos..][0..BdtEntry.wire_len];
        self.pos += BdtEntry.wire_len;
        return .{
            .address = BipAddress.decode(d[0..6]),
            .mask = d[6..10].*,
        };
    }
};

pub fn bdtIterator(body: []const u8) BdtIterator {
    return .{ .body = body };
}

pub const FdtIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn next(self: *FdtIterator) ?FdtEntry {
        if (self.pos + FdtEntry.wire_len > self.body.len) return null;
        const d = self.body[self.pos..][0..FdtEntry.wire_len];
        self.pos += FdtEntry.wire_len;
        return .{
            .address = BipAddress.decode(d[0..6]),
            .ttl_seconds = std.mem.readInt(u16, d[6..8], .big),
            .remaining_seconds = std.mem.readInt(u16, d[8..10], .big),
        };
    }
};

pub fn fdtIterator(body: []const u8) FdtIterator {
    return .{ .body = body };
}

/// Serialises BDT entries into `out`, returning the body slice a
/// `write_broadcast_distribution_table` message should carry.
pub fn encodeBdt(entries: []const BdtEntry, out: []u8) Error![]u8 {
    const n = entries.len * BdtEntry.wire_len;
    if (out.len < n) return error.NoSpace;
    for (entries, 0..) |e, i| {
        const d = out[i * BdtEntry.wire_len ..][0..BdtEntry.wire_len];
        e.address.encode(d[0..6]);
        @memcpy(d[6..10], &e.mask);
    }
    return out[0..n];
}

/// Serialises FDT entries into `out` (what a BBMD answers a
/// `read_foreign_device_table` with).
pub fn encodeFdt(entries: []const FdtEntry, out: []u8) Error![]u8 {
    const n = entries.len * FdtEntry.wire_len;
    if (out.len < n) return error.NoSpace;
    for (entries, 0..) |e, i| {
        const d = out[i * FdtEntry.wire_len ..][0..FdtEntry.wire_len];
        e.address.encode(d[0..6]);
        std.mem.writeInt(u16, d[6..8], e.ttl_seconds, .big);
        std.mem.writeInt(u16, d[8..10], e.remaining_seconds, .big);
    }
    return out[0..n];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "original-broadcast NPDU: header layout and length accounting" {
    // 81 0b 00 0c || 01 00 10 08 09 01 19 64  — a Who-Is on a local broadcast.
    const wire = [_]u8{ 0x81, 0x0B, 0x00, 0x0C, 0x01, 0x00, 0x10, 0x08, 0x09, 0x01, 0x19, 0x64 };
    const msg = try decode(&wire);
    try testing.expectEqual(Function.original_broadcast_npdu, msg.function());
    try testing.expectEqualSlices(u8, wire[4..], msg.npdu().?);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(msg, &out));
    try testing.expectEqualSlices(u8, &wire, try wrap(.original_broadcast_npdu, wire[4..], &out));
}

test "the length field must agree with the datagram" {
    // Declares 12 octets, only 11 delivered.
    try testing.expectError(error.LengthMismatch, decode(&.{
        0x81, 0x0B, 0x00, 0x0C, 0x01, 0x00, 0x10, 0x08, 0x09, 0x01, 0x19,
    }));
    // Declares 4, 12 delivered — a trailing-garbage smuggling attempt.
    try testing.expectError(error.LengthMismatch, decode(&.{
        0x81, 0x0B, 0x00, 0x04, 0x01, 0x00, 0x10, 0x08, 0x09, 0x01, 0x19, 0x64,
    }));
    // Declares 0.
    try testing.expectError(error.LengthMismatch, decode(&.{ 0x81, 0x0B, 0x00, 0x00 }));
    // Not BACnet at all.
    try testing.expectError(error.NotBvlc, decode(&.{ 0x82, 0x0B, 0x00, 0x04 }));
    try testing.expectError(error.NotBvlc, decode(&.{ 0x81, 0x0B, 0x00 }));
    try testing.expectError(error.NotBvlc, decode(&.{}));
}

test "forwarded NPDU carries the originating B/IP address" {
    // 81 04 00 12 || c0 00 02 05 ba c0 || 01 00 10 08 09 01 19 64
    const wire = [_]u8{
        0x81, 0x04, 0x00, 0x12,
        0xC0, 0x00, 0x02, 0x05,
        0xBA, 0xC0, 0x01, 0x00,
        0x10, 0x08, 0x09, 0x01,
        0x19, 0x64,
    };
    const msg = try decode(&wire);
    const f = msg.forwarded_npdu;
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 5 }, &f.origin.ip);
    try testing.expectEqual(@as(u16, 47808), f.origin.port);
    try testing.expectEqual(@as(usize, 8), f.npdu.len);

    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(msg, &out));

    // Truncated inside the address.
    try testing.expectError(error.Truncated, decode(&.{
        0x81, 0x04, 0x00, 0x09, 0xC0, 0x00, 0x02, 0x05, 0xBA,
    }));
}

test "register-foreign-device and its result" {
    const reg = [_]u8{ 0x81, 0x05, 0x00, 0x06, 0x00, 0x3C };
    const msg = try decode(&reg);
    try testing.expectEqual(@as(u16, 60), msg.register_foreign_device.ttl_seconds);
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &reg, try encode(msg, &out));

    const ok = [_]u8{ 0x81, 0x00, 0x00, 0x06, 0x00, 0x00 };
    try testing.expectEqual(ResultCode.success, (try decode(&ok)).result);
    const nak = [_]u8{ 0x81, 0x00, 0x00, 0x06, 0x00, 0x30 };
    try testing.expectEqual(ResultCode.register_foreign_device_nak, (try decode(&nak)).result);
    try testing.expectEqualSlices(u8, &nak, try encode(try decode(&nak), &out));

    // A Result with a body that is not two octets.
    try testing.expectError(error.Truncated, decode(&.{ 0x81, 0x00, 0x00, 0x05, 0x00 }));
}

test "BDT and FDT round trip through their iterators" {
    const bdt = [_]BdtEntry{
        .{ .address = .{ .ip = .{ 192, 0, 2, 1 } }, .mask = .{ 255, 255, 255, 255 } },
        .{ .address = .{ .ip = .{ 198, 51, 100, 7 }, .port = 47809 }, .mask = .{ 255, 255, 255, 0 } },
    };
    var body: [64]u8 = undefined;
    const encoded = try encodeBdt(&bdt, &body);
    try testing.expectEqual(@as(usize, 20), encoded.len);

    var dgram: [128]u8 = undefined;
    const wire = try encode(.{ .read_broadcast_distribution_table_ack = encoded }, &dgram);
    const msg = try decode(wire);
    var it = bdtIterator(msg.read_broadcast_distribution_table_ack);
    var seen: usize = 0;
    while (it.next()) |e| : (seen += 1) {
        try testing.expect(e.address.eql(bdt[seen].address));
        try testing.expectEqualSlices(u8, &bdt[seen].mask, &e.mask);
    }
    try testing.expectEqual(@as(usize, 2), seen);

    const fdt = [_]FdtEntry{
        .{ .address = .{ .ip = .{ 203, 0, 113, 9 } }, .ttl_seconds = 60, .remaining_seconds = 45 },
    };
    const fbody = try encodeFdt(&fdt, &body);
    const fwire = try encode(.{ .read_foreign_device_table_ack = fbody }, &dgram);
    var fit = fdtIterator((try decode(fwire)).read_foreign_device_table_ack);
    const e = fit.next().?;
    try testing.expectEqual(@as(u16, 60), e.ttl_seconds);
    try testing.expectEqual(@as(u16, 45), e.remaining_seconds);
    try testing.expectEqual(@as(?FdtEntry, null), fit.next());
}

test "a table body whose length is not a whole number of entries is rejected" {
    // 15 octets is one and a half BDT entries.
    var dgram: [32]u8 = undefined;
    dgram[0] = 0x81;
    dgram[1] = 0x03;
    std.mem.writeInt(u16, dgram[2..4], 19, .big);
    try testing.expectError(error.InvalidBody, decode(dgram[0..19]));

    // Read requests carry no body at all.
    try testing.expectError(error.InvalidBody, decode(&.{ 0x81, 0x02, 0x00, 0x05, 0x00 }));
    try testing.expectEqual(
        Function.read_broadcast_distribution_table,
        (try decode(&.{ 0x81, 0x02, 0x00, 0x04 })).function(),
    );
    try testing.expectEqual(
        Function.read_foreign_device_table,
        (try decode(&.{ 0x81, 0x06, 0x00, 0x04 })).function(),
    );
}

test "unknown function codes are refused, not guessed at" {
    try testing.expectError(error.UnknownFunction, decode(&.{ 0x81, 0x0D, 0x00, 0x04 }));
    try testing.expectError(error.UnknownFunction, decode(&.{ 0x81, 0xFF, 0x00, 0x04 }));
}

test "delete-foreign-device-table-entry" {
    const wire = [_]u8{ 0x81, 0x08, 0x00, 0x0A, 0xCB, 0x00, 0x71, 0x09, 0xBA, 0xC0 };
    const msg = try decode(&wire);
    try testing.expect(msg.delete_foreign_device_table_entry.eql(.{
        .ip = .{ 203, 0, 113, 9 },
        .port = 47808,
    }));
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try encode(msg, &out));
    try testing.expectError(error.Truncated, decode(&.{ 0x81, 0x08, 0x00, 0x08, 0xCB, 0x00, 0x71, 0x09 }));
}

test "B/IP address parsing goes through netaddr" {
    const a = BipAddress.parse("192.0.2.5:47809").?;
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 5 }, &a.ip);
    try testing.expectEqual(@as(u16, 47809), a.port);

    const b = BipAddress.parse("192.0.2.5").?;
    try testing.expectEqual(default_port, b.port);

    try testing.expectEqual(@as(?BipAddress, null), BipAddress.parse("not-an-address"));
    // Annex J is IPv4-only; IPv6 belongs to Annex U, which is deferred.
    try testing.expectEqual(@as(?BipAddress, null), BipAddress.fromIp(.{ .v6 = @splat(0) }, 47808));

    const round = BipAddress.fromIp(.{ .v4 = .{ 10, 0, 0, 1 } }, 47810).?;
    try testing.expectEqual(@as(u16, 47810), round.port);
    switch (round.toIp()) {
        .v4 => |v| try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &v),
        .v6 => return error.WrongFamily,
    }
}

test "encode refuses to overflow the length field or the buffer" {
    var small: [8]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(
        .{ .original_unicast_npdu = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } },
        &small,
    ));
    var bdt_out: [4]u8 = undefined;
    try testing.expectError(error.NoSpace, encodeBdt(
        &.{.{ .address = .{ .ip = .{ 1, 2, 3, 4 } } }},
        &bdt_out,
    ));
}

test "fuzz: BVLC decode never panics and re-encodes identically" {
    try std.testing.fuzz({}, fuzzBvlc, .{});
}

fn fuzzBvlc(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const dgram = buf[0..len];
    const msg = decode(dgram) catch return;
    var out: [512]u8 = undefined;
    const again = try encode(msg, &out);
    try testing.expectEqualSlices(u8, dgram, again);
}
