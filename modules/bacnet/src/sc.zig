// SPDX-License-Identifier: MIT

//! **Annex AB — BACnet Secure Connect (BACnet/SC): the BVLC.**
//!
//! BACnet/SC replaces the Annex J datagram link with a mesh of **WebSocket
//! connections over TLS**. That is not a cosmetic swap, and this file exists
//! because almost none of Annex J's assumptions survive it:
//!
//! * **There is no length field.** Annex J can check its `length` against the
//!   UDP datagram it arrived in; a BACnet/SC message is delimited by the
//!   WebSocket frame, so the *frame* is the length and a message that
//!   disagrees with itself can only be caught by walking it. Every "runs off
//!   the end" is therefore a decode error here, never a short read.
//! * **There are no IP addresses.** A node is a 6-octet **VMAC** plus a
//!   16-octet **device UUID**; the hub keeps the map and is the only thing
//!   that knows a socket.
//! * **The header is variable-length in four independent ways** — an
//!   originating VMAC, a destination VMAC, a destination-option list and a
//!   data-option list, each present or absent by a control bit. The option
//!   lists are self-terminating (a *more-options* bit in every option
//!   marker), so where the payload starts is only knowable by walking them.
//!
//! ```text
//!  0        1        2        4              10             16
//! +--------+--------+--------+--------------+--------------+ ...
//! |function| control| msg id |  orig VMAC?  |  dest VMAC?  | dest opts? | data opts? | payload
//! +--------+--------+--------+--------------+--------------+ ...
//! ```
//!
//! Control octet (AB.2.1.2), MSB first: bits 7..4 reserved and **checked**,
//! bit 3 originating VMAC present, bit 2 destination VMAC present, bit 1
//! destination options present, bit 0 data options present.
//!
//! Header option marker (AB.2.3.1): bit 7 *more options*, bit 6 *must
//! understand*, bit 5 *header data present*, bits 4..0 the option type. When
//! bit 5 is set a 2-octet big-endian length and that many data octets follow.
//! An option whose *must understand* bit is set and whose type we do not know
//! must be answered with a `BVLC-Result` NAK rather than skipped — see
//! `Option.mustReject`.
//!
//! **Byte order: big-endian**, like the rest of BACnet. This is worth stating
//! because two third-party implementations disagree about it; see SPEC.md,
//! which records exactly what was compared and how the tie was broken.
//!
//! Nothing here allocates. Payloads, option lists and detail strings are
//! slices borrowed from the caller's frame buffer.

const std = @import("std");
const types = @import("types.zig");

pub const Error = error{
    /// The frame ended inside a field, an option, or an option's data.
    Truncated,
    /// A reserved control bit (4..7) was set. Refusing beats guessing which
    /// optional fields the peer thinks it sent.
    ReservedControlBits,
    /// A BVLC function this module does not decode.
    UnknownFunction,
    /// Well-formed octets that cannot mean anything for their function — a
    /// Connect-Request that is not exactly 26 octets of body, a `BVLC-Result`
    /// whose code is neither ACK nor NAK, a fixed-size body with trailing
    /// junk.
    InvalidBody,
    /// The output buffer is too small.
    NoSpace,
    /// More than `max_options` options in one list. A bound, not a protocol
    /// rule: an unbounded list is a denial-of-service surface.
    TooManyOptions,
};

// ── constants ──────────────────────────────────────────────────────────────

/// The fixed part of every BACnet/SC BVLC header: function, control, message
/// id (AB.2.1).
pub const header_len: usize = 4;

/// Annex AB requires a node to accept at least this many octets in one BVLC
/// message, so it is the floor for what a peer may negotiate down to.
pub const min_bvlc_length: u16 = 1497;

/// The most options this module will parse in one list. Annex AB sets no
/// limit; an unbounded one is a hostile-input surface, and no real deployment
/// stacks more than a handful.
pub const max_options: usize = 8;

/// The WebSocket subprotocol a node uses to reach a **hub** (AB.7.1).
pub const subprotocol_hub = "hub.bsc.bacnet.org";
/// The WebSocket subprotocol for a **direct** node-to-node connection.
pub const subprotocol_direct = "dc.bsc.bacnet.org";

// ── functions and control bits ─────────────────────────────────────────────

/// BVLC functions for BACnet/SC (AB.2.4). Note these overlap numerically with
/// Annex J's function codes and mean entirely different things — which is why
/// they live in their own enum rather than being bolted onto `bvll.Function`.
pub const Function = enum(u8) {
    result = 0x00,
    encapsulated_npdu = 0x01,
    address_resolution = 0x02,
    address_resolution_ack = 0x03,
    advertisement = 0x04,
    advertisement_solicitation = 0x05,
    connect_request = 0x06,
    connect_accept = 0x07,
    disconnect_request = 0x08,
    disconnect_ack = 0x09,
    heartbeat_request = 0x0A,
    heartbeat_ack = 0x0B,
    proprietary_message = 0x0C,
    _,

    /// True for the functions that set up or tear down the connection itself,
    /// which a node must answer before it is "connected" at all.
    pub fn isConnectionControl(self: Function) bool {
        return switch (self) {
            .connect_request,
            .connect_accept,
            .disconnect_request,
            .disconnect_ack,
            .heartbeat_request,
            .heartbeat_ack,
            => true,
            else => false,
        };
    }
};

/// Control-octet bit masks (AB.2.1.2).
pub const control = struct {
    pub const data_options: u8 = 0x01;
    pub const destination_options: u8 = 0x02;
    pub const destination_vmac: u8 = 0x04;
    pub const originating_vmac: u8 = 0x08;
    /// Bits 4..7 are reserved and shall be zero.
    pub const reserved: u8 = 0xF0;
};

// ── addressing ─────────────────────────────────────────────────────────────

/// A **virtual MAC address**: six octets that name a node inside a BACnet/SC
/// network (AB.1.5.2). Unlike an IP address it means nothing outside the
/// mesh — the hub, not the network, resolves it.
///
/// Two values are reserved: all-zero is "no address" and is never a valid
/// node VMAC, and all-ones is the local broadcast.
pub const Vmac = struct {
    octets: [6]u8,

    pub const wire_len: usize = 6;

    /// The local broadcast VMAC, `FF:FF:FF:FF:FF:FF` — every node on the
    /// network, which is how a Who-Is reaches the mesh.
    pub const broadcast: Vmac = .{ .octets = @splat(0xFF) };
    /// The reserved "no address" value. A node that offers this in a
    /// Connect-Request is malformed.
    pub const unspecified: Vmac = .{ .octets = @splat(0x00) };

    pub fn eql(a: Vmac, b: Vmac) bool {
        return std.mem.eql(u8, &a.octets, &b.octets);
    }

    pub fn isBroadcast(self: Vmac) bool {
        return self.eql(broadcast);
    }

    /// True for the two values a node may not use as its own address.
    pub fn isReserved(self: Vmac) bool {
        return self.eql(broadcast) or self.eql(unspecified);
    }

    /// A fresh VMAC from the caller's PRNG, avoiding the two reserved values.
    /// Randomness is the standard's own recommendation (AB.1.5.2): there is no
    /// central allocator, so collisions are detected rather than prevented —
    /// see `sc_node`'s handling of a `node_duplicate_vmac` NAK.
    pub fn random(rand: std.Random) Vmac {
        while (true) {
            var v: Vmac = .{ .octets = undefined };
            rand.bytes(&v.octets);
            if (!v.isReserved()) return v;
        }
    }

    pub fn format(self: Vmac, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.octets, 0..) |o, i| {
            if (i != 0) try writer.writeByte(':');
            try writer.printInt(o, 16, .lower, .{ .width = 2, .fill = '0' });
        }
    }
};

/// The 16-octet **device UUID** (AB.1.5.1). Where the VMAC is a routing label
/// that may change, the UUID is the device's permanent identity: it is what
/// lets a hub tell "the same node reconnecting" from "a second node that
/// happened to pick the same VMAC".
pub const Uuid = struct {
    octets: [16]u8,

    pub const wire_len: usize = 16;
    pub const nil: Uuid = .{ .octets = @splat(0) };

    pub fn eql(a: Uuid, b: Uuid) bool {
        return std.mem.eql(u8, &a.octets, &b.octets);
    }

    /// An RFC 4122 version-4 UUID from the caller's PRNG. Annex AB does not
    /// require version 4 specifically, only that the value be unique and
    /// stable for the device's lifetime; version 4 is the obvious way to get
    /// there without a registry.
    pub fn random(rand: std.Random) Uuid {
        var u: Uuid = .{ .octets = undefined };
        rand.bytes(&u.octets);
        u.octets[6] = (u.octets[6] & 0x0F) | 0x40; // version 4
        u.octets[8] = (u.octets[8] & 0x3F) | 0x80; // variant 1
        return u;
    }

    /// Parses the canonical `8-4-4-4-12` hyphenated text form. Returns null
    /// for anything else, including the brace and URN spellings — a config
    /// file that spells a UUID unusually is better rejected than guessed.
    pub fn parse(text: []const u8) ?Uuid {
        if (text.len != 36) return null;
        const groups = [_]struct { at: usize, len: usize }{
            .{ .at = 0, .len = 8 },
            .{ .at = 9, .len = 4 },
            .{ .at = 14, .len = 4 },
            .{ .at = 19, .len = 4 },
            .{ .at = 24, .len = 12 },
        };
        for ([_]usize{ 8, 13, 18, 23 }) |i| if (text[i] != '-') return null;
        var out: Uuid = .{ .octets = undefined };
        var w: usize = 0;
        for (groups) |g| {
            var i: usize = 0;
            while (i < g.len) : (i += 2) {
                const hi = std.fmt.charToDigit(text[g.at + i], 16) catch return null;
                const lo = std.fmt.charToDigit(text[g.at + i + 1], 16) catch return null;
                out.octets[w] = @as(u8, hi) << 4 | lo;
                w += 1;
            }
        }
        return out;
    }

    pub fn format(self: Uuid, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.octets, 0..) |o, i| {
            if (i == 4 or i == 6 or i == 8 or i == 10) try writer.writeByte('-');
            try writer.printInt(o, 16, .lower, .{ .width = 2, .fill = '0' });
        }
    }
};

// ── header options ─────────────────────────────────────────────────────────

/// Header option types (AB.2.3). The type is five bits, so the space is tiny
/// and mostly reserved; `_` keeps unknown values decodable, which matters
/// because the *must-understand* bit is what decides whether an unknown option
/// is fatal.
pub const OptionType = enum(u5) {
    /// Type 0 is reserved and must never appear.
    reserved = 0,
    /// "This message travelled a secure path" (AB.2.3.2). No data.
    secure_path = 1,
    /// Vendor extension (AB.2.3.3): vendor id, option type, then data.
    proprietary = 31,
    _,
};

/// Option marker bit masks (AB.2.3.1).
pub const option_flags = struct {
    pub const more: u8 = 0x80;
    pub const must_understand: u8 = 0x40;
    pub const header_data: u8 = 0x20;
    pub const type_mask: u8 = 0x1F;
};

/// One decoded header option. `data` is null when the *header data present*
/// bit is clear — which is a different thing from an empty data block, and the
/// two spell differently on the wire (`41` versus `61 0000`).
pub const Option = struct {
    type: OptionType,
    must_understand: bool,
    data: ?[]const u8 = null,

    /// The vendor-extension payload of a proprietary option (AB.2.3.3).
    pub const Proprietary = struct {
        vendor_id: u16,
        option_type: u8,
        data: []const u8,
    };

    /// A secure-path option. Annex AB defines it with the must-understand bit
    /// **set**, which is what both third-party oracles emit.
    pub const secure_path: Option = .{ .type = .secure_path, .must_understand = true };

    /// Decodes a proprietary option's data block. `error.InvalidBody` when the
    /// option is not proprietary or its data is shorter than the three fixed
    /// octets.
    pub fn asProprietary(self: Option) Error!Proprietary {
        if (self.type != .proprietary) return error.InvalidBody;
        const d = self.data orelse return error.InvalidBody;
        if (d.len < 3) return error.Truncated;
        return .{
            .vendor_id = std.mem.readInt(u16, d[0..2], .big),
            .option_type = d[2],
            .data = d[3..],
        };
    }

    /// True when this option obliges the receiver to refuse the whole message.
    /// The must-understand bit exists exactly so a future option can be added
    /// without silently changing the meaning of a message for an old node: an
    /// option we do not know **and** must understand is a `BVLC-Result` NAK
    /// with `header_not_understood`, not a skip.
    pub fn mustReject(self: Option) bool {
        if (!self.must_understand) return false;
        return switch (self.type) {
            .secure_path, .proprietary => false,
            else => true,
        };
    }

    /// The octets this option occupies on the wire.
    pub fn wireLen(self: Option) usize {
        return 1 + if (self.data) |d| 2 + d.len else 0;
    }
};

/// Walks an option list. Bounded by the slice it was given: `next` can only
/// move forward, and every path either consumes at least one octet or stops.
pub const OptionIter = struct {
    rest: []const u8,
    finished: bool = false,

    pub fn next(self: *OptionIter) Error!?Option {
        if (self.finished or self.rest.len == 0) return null;
        const marker = self.rest[0];
        const has_data = marker & option_flags.header_data != 0;
        var consumed: usize = 1;
        var data: ?[]const u8 = null;
        if (has_data) {
            if (self.rest.len < 3) return error.Truncated;
            const len = std.mem.readInt(u16, self.rest[1..3], .big);
            if (self.rest.len < 3 + len) return error.Truncated;
            data = self.rest[3 .. 3 + len];
            consumed = 3 + len;
        }
        if (marker & option_flags.more == 0) self.finished = true;
        self.rest = self.rest[consumed..];
        return .{
            .type = @enumFromInt(@as(u5, @truncate(marker & option_flags.type_mask))),
            .must_understand = marker & option_flags.must_understand != 0,
            .data = data,
        };
    }
};

/// An iterator over an option list that `decode` has already validated.
pub fn optionIterator(list: []const u8) OptionIter {
    return .{ .rest = list };
}

/// Length of the option list starting at `buf[0]`, in octets.
///
/// This is the function that makes the header parseable at all: an option list
/// has no count and no length, only a *more* bit in each marker, so the only
/// way to find the payload is to walk. A list whose last option still says
/// "more" simply runs off the end of the frame, which is `error.Truncated` —
/// there is no way for it to hang, because every iteration consumes at least
/// one octet of a finite slice.
pub fn scanOptions(buf: []const u8) Error!usize {
    var it: OptionIter = .{ .rest = buf };
    var count: usize = 0;
    while (try it.next()) |_| {
        count += 1;
        if (count > max_options) return error.TooManyOptions;
    }
    if (!it.finished) return error.Truncated;
    return buf.len - it.rest.len;
}

/// Encodes an option list. The *more* bit is this function's business, not the
/// caller's: it is set on every option but the last, so a caller cannot
/// produce a list that terminates in the wrong place.
pub fn encodeOptions(options: []const Option, out: []u8) Error![]u8 {
    if (options.len > max_options) return error.TooManyOptions;
    var at: usize = 0;
    for (options, 0..) |opt, i| {
        const need = opt.wireLen();
        if (out.len < at + need) return error.NoSpace;
        var marker: u8 = @intFromEnum(opt.type);
        if (i + 1 != options.len) marker |= option_flags.more;
        if (opt.must_understand) marker |= option_flags.must_understand;
        if (opt.data) |d| {
            if (d.len > std.math.maxInt(u16)) return error.NoSpace;
            marker |= option_flags.header_data;
            out[at] = marker;
            std.mem.writeInt(u16, out[at + 1 ..][0..2], @intCast(d.len), .big);
            @memcpy(out[at + 3 ..][0..d.len], d);
        } else {
            out[at] = marker;
        }
        at += need;
    }
    return out[0..at];
}

/// Builds a proprietary option's data block into `out`. Kept separate from
/// `encodeOptions` so an `Option` stays a plain borrowing struct.
pub fn encodeProprietaryOptionData(p: Option.Proprietary, out: []u8) Error![]u8 {
    if (out.len < 3 + p.data.len) return error.NoSpace;
    std.mem.writeInt(u16, out[0..2], p.vendor_id, .big);
    out[2] = p.option_type;
    @memcpy(out[3..][0..p.data.len], p.data);
    return out[0 .. 3 + p.data.len];
}

// ── payload bodies ─────────────────────────────────────────────────────────

/// `BVLC-Result` codes (AB.2.4.1). Two values, and only two: this is an
/// acknowledgement channel, not an error taxonomy — the taxonomy is the
/// `BACnetErrorClass`/`BACnetErrorCode` pair inside a NAK.
pub const ResultCode = enum(u8) {
    ack = 0x00,
    nak = 0x01,
    _,
};

/// The error detail carried by a NAK.
pub const ResultError = struct {
    /// The header option marker that caused the rejection, or 0 when the
    /// failure was not about an option. Annex AB calls this the *Error Header
    /// Marker*; it lets a peer see *which* option it got wrong.
    header_marker: u8 = 0,
    class: types.ErrorClass,
    code: types.ErrorCode,
    /// UTF-8, **not** null-terminated, and may be empty. Borrowed.
    details: []const u8 = "",
};

pub const Result = struct {
    /// The function being answered.
    function: Function,
    code: ResultCode,
    /// Present exactly when `code == .nak`.
    err: ?ResultError = null,
};

/// What a node says about its own hub connection in an Advertisement
/// (AB.2.4.2). This is how a peer learns whether it is talking to something
/// that can reach the rest of the network.
pub const HubConnectionStatus = enum(u8) {
    no_hub_connection = 0,
    connected_to_primary = 1,
    connected_to_failover = 2,
    _,
};

/// Whether a node accepts direct (non-hub) connections.
pub const DirectConnectionSupport = enum(u8) {
    unsupported = 0,
    supported = 1,
    _,
};

pub const Advertisement = struct {
    hub_status: HubConnectionStatus,
    direct_connections: DirectConnectionSupport,
    max_bvlc_length: u16,
    max_npdu_length: u16,

    pub const wire_len: usize = 6;
};

/// The body shared by Connect-Request and Connect-Accept (AB.2.4.3/AB.2.4.4).
/// Both directions send the *same* four fields, which is what makes the
/// negotiation symmetric: each side proposes its own maxima and the effective
/// limit is the smaller.
pub const ConnectInfo = struct {
    vmac: Vmac,
    uuid: Uuid,
    max_bvlc_length: u16,
    max_npdu_length: u16,

    pub const wire_len: usize = Vmac.wire_len + Uuid.wire_len + 4;

    /// The limits actually in force once both sides have spoken.
    pub fn negotiate(mine: ConnectInfo, theirs: ConnectInfo) struct { bvlc: u16, npdu: u16 } {
        return .{
            .bvlc = @min(mine.max_bvlc_length, theirs.max_bvlc_length),
            .npdu = @min(mine.max_npdu_length, theirs.max_npdu_length),
        };
    }
};

pub const ProprietaryMessage = struct {
    vendor_id: u16,
    function: u8,
    data: []const u8,
};

/// The decoded body, keyed by function. Slices borrow from the frame.
pub const Payload = union(Function) {
    result: Result,
    encapsulated_npdu: []const u8,
    address_resolution,
    /// A space-separated list of WebSocket URIs, UTF-8, borrowed. Left as text
    /// on purpose: Annex AB gives no length prefix and no escaping, so
    /// splitting is the caller's policy — `uriIterator` does the obvious thing.
    address_resolution_ack: []const u8,
    advertisement: Advertisement,
    advertisement_solicitation,
    connect_request: ConnectInfo,
    connect_accept: ConnectInfo,
    disconnect_request,
    disconnect_ack,
    heartbeat_request,
    heartbeat_ack,
    proprietary_message: ProprietaryMessage,
};

/// Splits an Address-Resolution-ACK's URI list on spaces, skipping runs.
pub fn uriIterator(list: []const u8) std.mem.TokenIterator(u8, .scalar) {
    return std.mem.tokenizeScalar(u8, list, ' ');
}

// ── the message ────────────────────────────────────────────────────────────

/// The variable header (AB.2.1). Option lists are kept as **raw octets**
/// rather than a parsed array so the whole struct stays allocation-free and
/// re-encodes byte-identically; walk them with `optionIterator`.
pub const Header = struct {
    message_id: u16,
    source: ?Vmac = null,
    destination: ?Vmac = null,
    destination_options: []const u8 = &.{},
    data_options: []const u8 = &.{},

    pub fn controlOctet(self: Header) u8 {
        var c: u8 = 0;
        if (self.source != null) c |= control.originating_vmac;
        if (self.destination != null) c |= control.destination_vmac;
        if (self.destination_options.len != 0) c |= control.destination_options;
        if (self.data_options.len != 0) c |= control.data_options;
        return c;
    }

    /// The first option in either list that this module must refuse, if any.
    /// Both lists are checked because Annex AB applies the must-understand
    /// rule to both.
    pub fn unsupportedOption(self: Header) Error!?Option {
        for ([_][]const u8{ self.destination_options, self.data_options }) |list| {
            var it = optionIterator(list);
            while (try it.next()) |opt| if (opt.mustReject()) return opt;
        }
        return null;
    }

    /// True when a secure-path option is present, i.e. the sender claims the
    /// message crossed only TLS-protected hops. This is an *assertion by the
    /// sender*, not proof, and this module never treats it as one.
    pub fn hasSecurePath(self: Header) bool {
        for ([_][]const u8{ self.destination_options, self.data_options }) |list| {
            var it = optionIterator(list);
            while (it.next() catch null) |opt| if (opt.type == .secure_path) return true;
        }
        return false;
    }
};

pub const Message = struct {
    header: Header,
    payload: Payload,

    pub fn function(self: Message) Function {
        return std.meta.activeTag(self.payload);
    }

    /// The NPDU inside, for the one function that carries one.
    pub fn npdu(self: Message) ?[]const u8 {
        return switch (self.payload) {
            .encapsulated_npdu => |p| p,
            else => null,
        };
    }

    /// True when this message is addressed to every node on the network:
    /// Annex AB spells that either as an absent destination VMAC (the hub
    /// distributes it) or as the all-ones broadcast VMAC.
    pub fn isBroadcast(self: Message) bool {
        const d = self.header.destination orelse return true;
        return d.isBroadcast();
    }
};

/// Decodes one BACnet/SC BVLC message. `frame` must be **exactly** one
/// WebSocket binary frame's payload — there is no length field to cross-check
/// against, so anything left over after the payload is by definition part of
/// the payload.
pub fn decode(frame: []const u8) Error!Message {
    if (frame.len < header_len) return error.Truncated;
    const func: Function = @enumFromInt(frame[0]);
    const ctrl = frame[1];
    if (ctrl & control.reserved != 0) return error.ReservedControlBits;

    var at: usize = header_len;
    var hdr: Header = .{ .message_id = std.mem.readInt(u16, frame[2..4], .big) };

    if (ctrl & control.originating_vmac != 0) {
        if (frame.len < at + Vmac.wire_len) return error.Truncated;
        hdr.source = .{ .octets = frame[at..][0..6].* };
        at += Vmac.wire_len;
    }
    if (ctrl & control.destination_vmac != 0) {
        if (frame.len < at + Vmac.wire_len) return error.Truncated;
        hdr.destination = .{ .octets = frame[at..][0..6].* };
        at += Vmac.wire_len;
    }
    if (ctrl & control.destination_options != 0) {
        const n = try scanOptions(frame[at..]);
        hdr.destination_options = frame[at..][0..n];
        at += n;
    }
    if (ctrl & control.data_options != 0) {
        const n = try scanOptions(frame[at..]);
        hdr.data_options = frame[at..][0..n];
        at += n;
    }

    const body = frame[at..];
    const payload: Payload = switch (func) {
        .result => .{ .result = try decodeResult(body) },
        .encapsulated_npdu => .{ .encapsulated_npdu = body },
        .address_resolution => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .address_resolution;
        },
        .address_resolution_ack => .{ .address_resolution_ack = body },
        .advertisement => blk: {
            if (body.len != Advertisement.wire_len) return error.InvalidBody;
            break :blk .{ .advertisement = .{
                .hub_status = @enumFromInt(body[0]),
                .direct_connections = @enumFromInt(body[1]),
                .max_bvlc_length = std.mem.readInt(u16, body[2..4], .big),
                .max_npdu_length = std.mem.readInt(u16, body[4..6], .big),
            } };
        },
        .advertisement_solicitation => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .advertisement_solicitation;
        },
        .connect_request => .{ .connect_request = try decodeConnect(body) },
        .connect_accept => .{ .connect_accept = try decodeConnect(body) },
        .disconnect_request => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .disconnect_request;
        },
        .disconnect_ack => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .disconnect_ack;
        },
        .heartbeat_request => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .heartbeat_request;
        },
        .heartbeat_ack => blk: {
            if (body.len != 0) return error.InvalidBody;
            break :blk .heartbeat_ack;
        },
        .proprietary_message => blk: {
            if (body.len < 3) return error.Truncated;
            break :blk .{ .proprietary_message = .{
                .vendor_id = std.mem.readInt(u16, body[0..2], .big),
                .function = body[2],
                .data = body[3..],
            } };
        },
        _ => return error.UnknownFunction,
    };

    return .{ .header = hdr, .payload = payload };
}

fn decodeResult(body: []const u8) Error!Result {
    if (body.len < 2) return error.Truncated;
    const func: Function = @enumFromInt(body[0]);
    const code: ResultCode = @enumFromInt(body[1]);
    switch (code) {
        .ack => {
            // An ACK carries no error block. Trailing octets would mean the
            // peer thinks it sent one, which is a disagreement worth reporting
            // rather than ignoring.
            if (body.len != 2) return error.InvalidBody;
            return .{ .function = func, .code = code };
        },
        .nak => {
            if (body.len < 7) return error.Truncated;
            return .{ .function = func, .code = code, .err = .{
                .header_marker = body[2],
                .class = @enumFromInt(std.mem.readInt(u16, body[3..5], .big)),
                .code = @enumFromInt(std.mem.readInt(u16, body[5..7], .big)),
                .details = body[7..],
            } };
        },
        // Neither ACK nor NAK: there is no third meaning to guess at.
        _ => return error.InvalidBody,
    }
}

fn decodeConnect(body: []const u8) Error!ConnectInfo {
    if (body.len != ConnectInfo.wire_len) {
        return if (body.len < ConnectInfo.wire_len) error.Truncated else error.InvalidBody;
    }
    return .{
        .vmac = .{ .octets = body[0..6].* },
        .uuid = .{ .octets = body[6..22].* },
        .max_bvlc_length = std.mem.readInt(u16, body[22..24], .big),
        .max_npdu_length = std.mem.readInt(u16, body[24..26], .big),
    };
}

/// The octets `encode` would write for this message.
pub fn encodedLen(msg: Message) usize {
    var n = header_len;
    if (msg.header.source != null) n += Vmac.wire_len;
    if (msg.header.destination != null) n += Vmac.wire_len;
    n += msg.header.destination_options.len;
    n += msg.header.data_options.len;
    n += switch (msg.payload) {
        .result => |r| 2 + if (r.err) |e| 5 + e.details.len else 0,
        .encapsulated_npdu => |p| p.len,
        .address_resolution, .advertisement_solicitation => 0,
        .address_resolution_ack => |u| u.len,
        .advertisement => Advertisement.wire_len,
        .connect_request, .connect_accept => ConnectInfo.wire_len,
        .disconnect_request, .disconnect_ack => 0,
        .heartbeat_request, .heartbeat_ack => 0,
        .proprietary_message => |p| 3 + p.data.len,
    };
    return n;
}

/// Encodes a message into `out`, returning the slice written.
pub fn encode(msg: Message, out: []u8) Error![]u8 {
    const total = encodedLen(msg);
    if (out.len < total) return error.NoSpace;

    out[0] = @intFromEnum(msg.function());
    out[1] = msg.header.controlOctet();
    std.mem.writeInt(u16, out[2..4], msg.header.message_id, .big);

    var at: usize = header_len;
    if (msg.header.source) |v| {
        @memcpy(out[at..][0..6], &v.octets);
        at += Vmac.wire_len;
    }
    if (msg.header.destination) |v| {
        @memcpy(out[at..][0..6], &v.octets);
        at += Vmac.wire_len;
    }
    @memcpy(out[at..][0..msg.header.destination_options.len], msg.header.destination_options);
    at += msg.header.destination_options.len;
    @memcpy(out[at..][0..msg.header.data_options.len], msg.header.data_options);
    at += msg.header.data_options.len;

    const body = out[at..total];
    switch (msg.payload) {
        .result => |r| {
            body[0] = @intFromEnum(r.function);
            body[1] = @intFromEnum(r.code);
            if (r.err) |e| {
                body[2] = e.header_marker;
                std.mem.writeInt(u16, body[3..5], @intFromEnum(e.class), .big);
                std.mem.writeInt(u16, body[5..7], @intFromEnum(e.code), .big);
                @memcpy(body[7..], e.details);
            }
        },
        .encapsulated_npdu, .address_resolution_ack => |p| @memcpy(body, p),
        .address_resolution,
        .advertisement_solicitation,
        .disconnect_request,
        .disconnect_ack,
        .heartbeat_request,
        .heartbeat_ack,
        => {},
        .advertisement => |a| {
            body[0] = @intFromEnum(a.hub_status);
            body[1] = @intFromEnum(a.direct_connections);
            std.mem.writeInt(u16, body[2..4], a.max_bvlc_length, .big);
            std.mem.writeInt(u16, body[4..6], a.max_npdu_length, .big);
        },
        .connect_request, .connect_accept => |c| {
            @memcpy(body[0..6], &c.vmac.octets);
            @memcpy(body[6..22], &c.uuid.octets);
            std.mem.writeInt(u16, body[22..24], c.max_bvlc_length, .big);
            std.mem.writeInt(u16, body[24..26], c.max_npdu_length, .big);
        },
        .proprietary_message => |p| {
            std.mem.writeInt(u16, body[0..2], p.vendor_id, .big);
            body[2] = p.function;
            @memcpy(body[3..], p.data);
        },
    }
    return out[0..total];
}

// ── convenience builders ───────────────────────────────────────────────────

/// A `BVLC-Result` ACK for `func`, echoing the message id being answered.
pub fn ack(func: Function, message_id: u16, source: ?Vmac, dest: ?Vmac) Message {
    return .{
        .header = .{ .message_id = message_id, .source = source, .destination = dest },
        .payload = .{ .result = .{ .function = func, .code = .ack } },
    };
}

/// A `BVLC-Result` NAK. `details` is borrowed and may be empty.
pub fn nak(
    func: Function,
    message_id: u16,
    source: ?Vmac,
    dest: ?Vmac,
    err: ResultError,
) Message {
    return .{
        .header = .{ .message_id = message_id, .source = source, .destination = dest },
        .payload = .{ .result = .{ .function = func, .code = .nak, .err = err } },
    };
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8, buf: []u8) []u8 {
    return std.fmt.hexToBytes(buf, s) catch unreachable;
}

test "isConnectionControl: exactly the six setup/teardown functions" {
    const control_functions = [_]Function{
        .connect_request,
        .connect_accept,
        .disconnect_request,
        .disconnect_ack,
        .heartbeat_request,
        .heartbeat_ack,
    };
    for (control_functions) |f| try testing.expect(f.isConnectionControl());

    const other_functions = [_]Function{
        .result,
        .encapsulated_npdu,
        .address_resolution,
        .address_resolution_ack,
        .advertisement,
        .advertisement_solicitation,
        .proprietary_message,
    };
    for (other_functions) |f| try testing.expect(!f.isConnectionControl());
}

test "the minimal message is four octets and round-trips" {
    var buf: [16]u8 = undefined;
    const frame = hex("0a000001", &buf);
    const m = try decode(frame);
    try testing.expectEqual(Function.heartbeat_request, m.function());
    try testing.expectEqual(@as(u16, 1), m.header.message_id);
    try testing.expectEqual(@as(?Vmac, null), m.header.source);
    try testing.expectEqual(@as(?Vmac, null), m.header.destination);

    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, frame, try encode(m, &out));
}

test "control bits decide the header length, in the standard's order" {
    // Originating VMAC first, then destination — getting that backwards reads
    // the payload from six octets off.
    var buf: [32]u8 = undefined;
    const frame = hex("0a0cffff0102030405060a0b0c0d0e0f", &buf);
    const m = try decode(frame);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, &m.header.source.?.octets);
    try testing.expectEqualSlices(u8, &.{ 10, 11, 12, 13, 14, 15 }, &m.header.destination.?.octets);
    try testing.expectEqual(@as(u16, 0xFFFF), m.header.message_id);
}

test "a reserved control bit is refused, not ignored" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.ReservedControlBits, decode(hex("0a100001", &buf)));
    try testing.expectError(error.ReservedControlBits, decode(hex("0a800001", &buf)));
}

test "a destination VMAC with no source decodes; the policy check is separate" {
    // The codec's job is to say what the octets are. Whether a hub should have
    // attributed the message is `sc_hub`/`sc_node`'s business.
    var buf: [16]u8 = undefined;
    const m = try decode(hex("0a0400030a0b0c0d0e0f", &buf));
    try testing.expectEqual(@as(?Vmac, null), m.header.source);
    try testing.expect(m.header.destination != null);
}

test "a truncated VMAC is an error, never a short read" {
    var buf: [16]u8 = undefined;
    try testing.expectError(error.Truncated, decode(hex("0a08000201020304", &buf)));
    try testing.expectError(error.Truncated, decode(hex("0a0c00020102030405060a0b", &buf)));
}

test "an option list that never terminates runs off the end" {
    var buf: [16]u8 = undefined;
    // Two markers, both with the more bit set, then nothing.
    try testing.expectError(error.Truncated, decode(hex("010200c1c1", &buf)));
    // A single option that claims more and is the last octet.
    try testing.expectError(error.Truncated, decode(hex("010200c1", &buf)));
}

test "an option's header length may not overrun the frame" {
    var buf: [16]u8 = undefined;
    // Marker 0x3f says "header data follows"; the declared length is 0x00ff.
    try testing.expectError(error.Truncated, decode(hex("0102000a3f00ff0102", &buf)));
    // ... and the two length octets themselves must be present.
    try testing.expectError(error.Truncated, decode(hex("0102000a3f00", &buf)));
}

test "a must-understand option we do not know is reported, not skipped" {
    var buf: [16]u8 = undefined;
    // Option type 7 with the must-understand bit set: 0x40 | 7 = 0x47.
    const m = try decode(hex("0102000a470100", &buf));
    const bad = (try m.header.unsupportedOption()).?;
    try testing.expectEqual(@as(u5, 7), @intFromEnum(bad.type));
    try testing.expect(bad.must_understand);

    // The same option without the bit is skipped silently, which is the whole
    // point of the bit existing.
    const ok = try decode(hex("0102000a070100", &buf));
    try testing.expectEqual(@as(?Option, null), try ok.header.unsupportedOption());
}

test "secure path and proprietary are understood, so they never reject" {
    var buf: [24]u8 = undefined;
    const m = try decode(hex("0102000a410100", &buf));
    try testing.expectEqual(@as(?Option, null), try m.header.unsupportedOption());
    try testing.expect(m.header.hasSecurePath());
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, m.payload.encapsulated_npdu);
}

test "a proprietary option's vendor block is decoded, and a short one is caught" {
    var buf: [32]u8 = undefined;
    const m = try decode(hex("010201023f000503e70301020100", &buf));
    var it = optionIterator(m.header.destination_options);
    const opt = (try it.next()).?;
    const p = try opt.asProprietary();
    try testing.expectEqual(@as(u16, 999), p.vendor_id);
    try testing.expectEqual(@as(u8, 3), p.option_type);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, p.data);
    try testing.expectEqual(@as(?Option, null), try it.next());

    // Two octets of vendor block is one short of the fixed three.
    const short = try decode(hex("010201023f000203e70100", &buf));
    var it2 = optionIterator(short.header.destination_options);
    try testing.expectError(error.Truncated, (try it2.next()).?.asProprietary());
}

test "an option with the data flag and zero length differs from no data flag" {
    // `61 0000` and `41` are different octets and must decode differently,
    // because a future option could distinguish them.
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    const with = try decode(hex("010200016100000100", &b1));
    const without = try decode(hex("01020001410100", &b2));
    var with_it = optionIterator(with.header.destination_options);
    var without_it = optionIterator(without.header.destination_options);
    try testing.expectEqual(@as(usize, 0), (try with_it.next()).?.data.?.len);
    try testing.expectEqual(@as(?[]const u8, null), (try without_it.next()).?.data);
}

test "more than max_options in one list is refused" {
    var frame: [4 + max_options + 2]u8 = undefined;
    frame[0] = 0x01;
    frame[1] = 0x02;
    frame[2] = 0;
    frame[3] = 1;
    // max_options + 1 markers all saying "more", then a terminator.
    for (frame[4..][0 .. max_options + 1]) |*b| b.* = option_flags.more | 1;
    frame[frame.len - 1] = 1;
    try testing.expectError(error.TooManyOptions, decode(&frame));
}

test "encodeOptions owns the more bit" {
    var data: [8]u8 = undefined;
    const pd = try encodeProprietaryOptionData(
        .{ .vendor_id = 1, .option_type = 0, .data = &.{} },
        &data,
    );
    var out: [32]u8 = undefined;
    const list = try encodeOptions(&.{
        Option.secure_path,
        .{ .type = .proprietary, .must_understand = false, .data = pd },
    }, &out);
    try testing.expectEqual(@as(u8, 0xC1), list[0]); // more | must_understand | 1
    try testing.expectEqual(@as(u8, 0x3F), list[1]); // last: no more bit
    try testing.expectEqual(list.len, try scanOptions(list));
}

test "BVLC-Result: an ACK has no error block and trailing octets are refused" {
    var buf: [16]u8 = undefined;
    const m = try decode(hex("000000010600", &buf));
    try testing.expectEqual(ResultCode.ack, m.payload.result.code);
    try testing.expectEqual(Function.connect_request, m.payload.result.function);
    try testing.expectEqual(@as(?ResultError, null), m.payload.result.err);

    try testing.expectError(error.InvalidBody, decode(hex("00000001060000", &buf)));
    // A code that is neither ACK nor NAK has no defined meaning.
    try testing.expectError(error.InvalidBody, decode(hex("000000010602", &buf)));
    try testing.expectError(error.Truncated, decode(hex("0000000106", &buf)));
}

test "BVLC-Result: a NAK carries marker, class, code and optional details" {
    var buf: [32]u8 = undefined;
    const m = try decode(hex("00000001060100000700976475706c6963617465", &buf));
    const e = m.payload.result.err.?;
    try testing.expectEqual(@as(u8, 0), e.header_marker);
    try testing.expectEqual(types.ErrorClass.communication, e.class);
    try testing.expectEqual(@as(u16, 151), @intFromEnum(e.code));
    try testing.expectEqualStrings("duplicate", e.details);

    // Seven octets is the minimum: the details string may be empty.
    const bare = try decode(hex("0000020301011f00070092", &buf));
    try testing.expectEqualStrings("", bare.payload.result.err.?.details);
    try testing.expectEqual(@as(u8, 0x1F), bare.payload.result.err.?.header_marker);
    try testing.expectError(error.Truncated, decode(hex("00000001060100000700", &buf)));
}

test "Connect-Request is exactly 26 octets of body, no more and no less" {
    var buf: [40]u8 = undefined;
    const frame = hex("0600000101020304050600112233445566778899aabbccddeeff05780514", &buf);
    const m = try decode(frame);
    const c = m.payload.connect_request;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, &c.vmac.octets);
    try testing.expectEqual(@as(u16, 1400), c.max_bvlc_length);
    try testing.expectEqual(@as(u16, 1300), c.max_npdu_length);

    var short: [4 + ConnectInfo.wire_len - 1]u8 = undefined;
    @memcpy(&short, frame[0 .. frame.len - 1]);
    try testing.expectError(error.Truncated, decode(&short));

    var long: [4 + ConnectInfo.wire_len + 1]u8 = undefined;
    @memcpy(long[0..frame.len], frame);
    long[frame.len] = 0;
    try testing.expectError(error.InvalidBody, decode(&long));
}

test "the negotiated maximum is the smaller of the two proposals" {
    const mine: ConnectInfo = .{
        .vmac = Vmac.unspecified,
        .uuid = Uuid.nil,
        .max_bvlc_length = 1497,
        .max_npdu_length = 1497,
    };
    var theirs = mine;
    theirs.max_bvlc_length = 900;
    theirs.max_npdu_length = 4000;
    const n = mine.negotiate(theirs);
    try testing.expectEqual(@as(u16, 900), n.bvlc);
    try testing.expectEqual(@as(u16, 1497), n.npdu);
}

test "Advertisement is exactly 6 octets of body, no more and no less" {
    var buf: [16]u8 = undefined;
    // function=0x04, control=0, message_id=1, then hub_status=1,
    // direct_connections=1, max_bvlc_length=1400, max_npdu_length=1300.
    const frame = hex("04000001010105780514", &buf);
    const m = try decode(frame);
    const a = m.payload.advertisement;
    try testing.expectEqual(HubConnectionStatus.connected_to_primary, a.hub_status);
    try testing.expectEqual(DirectConnectionSupport.supported, a.direct_connections);
    try testing.expectEqual(@as(u16, 1400), a.max_bvlc_length);
    try testing.expectEqual(@as(u16, 1300), a.max_npdu_length);

    // Unlike Connect-Request/Accept, Advertisement does not distinguish
    // too-short from too-long: any body other than exactly `wire_len` is
    // InvalidBody.
    var short: [4 + Advertisement.wire_len - 1]u8 = undefined;
    @memcpy(&short, frame[0 .. frame.len - 1]);
    try testing.expectError(error.InvalidBody, decode(&short));

    var long: [4 + Advertisement.wire_len + 1]u8 = undefined;
    @memcpy(long[0..frame.len], frame);
    long[frame.len] = 0;
    try testing.expectError(error.InvalidBody, decode(&long));
}

test "the empty-body functions refuse a body" {
    var buf: [16]u8 = undefined;
    for ([_][]const u8{ "02", "05", "08", "09", "0a", "0b" }) |f| {
        var frame: [5]u8 = undefined;
        frame[0] = std.fmt.parseInt(u8, f, 16) catch unreachable;
        frame[1] = 0;
        frame[2] = 0;
        frame[3] = 1;
        frame[4] = 0xAA;
        try testing.expectError(error.InvalidBody, decode(&frame));
        try testing.expect((try decode(frame[0..4])).function() == @as(Function, @enumFromInt(frame[0])));
    }
    _ = &buf;
}

test "an unknown BVLC function is a typed error" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.UnknownFunction, decode(hex("0d000001", &buf)));
    try testing.expectError(error.UnknownFunction, decode(hex("ff000001", &buf)));
}

test "a frame shorter than the fixed header is truncated, not a panic" {
    try testing.expectError(error.Truncated, decode(&.{}));
    try testing.expectError(error.Truncated, decode(&.{0x0A}));
    try testing.expectError(error.Truncated, decode(&.{ 0x0A, 0x00, 0x00 }));
}

test "encode refuses to write past the caller's buffer" {
    const m: Message = .{
        .header = .{ .message_id = 1 },
        .payload = .heartbeat_request,
    };
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpace, encode(m, &small));
}

test "VMAC: the two reserved values, and random avoids both" {
    try testing.expect(Vmac.broadcast.isBroadcast());
    try testing.expect(Vmac.broadcast.isReserved());
    try testing.expect(Vmac.unspecified.isReserved());
    try testing.expect(!(Vmac{ .octets = .{ 1, 0, 0, 0, 0, 0 } }).isReserved());

    var prng = std.Random.DefaultPrng.init(0xBAC0);
    for (0..64) |_| try testing.expect(!Vmac.random(prng.random()).isReserved());
}

test "VMAC formats as colon-separated hex" {
    var buf: [32]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{Vmac{ .octets = .{ 1, 0x0a, 0xff, 0, 0x10, 0x2b } }});
    try testing.expectEqualStrings("01:0a:ff:00:10:2b", s);
}

test "UUID: parse, format and round trip" {
    const text = "00112233-4455-6677-8899-aabbccddeeff";
    const u = Uuid.parse(text).?;
    try testing.expectEqual(@as(u8, 0x00), u.octets[0]);
    try testing.expectEqual(@as(u8, 0xff), u.octets[15]);
    var buf: [40]u8 = undefined;
    try testing.expectEqualStrings(text, try std.fmt.bufPrint(&buf, "{f}", .{u}));

    try testing.expectEqual(@as(?Uuid, null), Uuid.parse("too short"));
    try testing.expectEqual(@as(?Uuid, null), Uuid.parse("00112233x4455-6677-8899-aabbccddeeff"));
    try testing.expectEqual(@as(?Uuid, null), Uuid.parse("g0112233-4455-6677-8899-aabbccddeeff"));
    try testing.expectEqual(@as(?Uuid, null), Uuid.parse("{00112233-4455-6677-8899-aabbccddeeff}"));
}

test "UUID.random sets the version-4 and variant bits" {
    var prng = std.Random.DefaultPrng.init(7);
    for (0..32) |_| {
        const u = Uuid.random(prng.random());
        try testing.expectEqual(@as(u8, 0x40), u.octets[6] & 0xF0);
        try testing.expectEqual(@as(u8, 0x80), u.octets[8] & 0xC0);
    }
}

test "Address-Resolution-ACK's URI list is split on spaces" {
    var buf: [64]u8 = undefined;
    const frame = hex(
        "030c000a0102030405060a0b0c0d0e0f7773733a2f2f3139322e302e322e312f207773733a2f2f3139322e302e322e323a383434332f",
        &buf,
    );
    const m = try decode(frame);
    var it = uriIterator(m.payload.address_resolution_ack);
    try testing.expectEqualStrings("wss://192.0.2.1/", it.next().?);
    try testing.expectEqualStrings("wss://192.0.2.2:8443/", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "an Address-Resolution-ACK with no URIs is legal and empty" {
    var buf: [8]u8 = undefined;
    const m = try decode(hex("03000009", &buf));
    try testing.expectEqual(@as(usize, 0), m.payload.address_resolution_ack.len);
}

test "builders: ack and nak round-trip" {
    var out: [64]u8 = undefined;
    const a = ack(.connect_request, 1, null, null);
    const back = try decode(try encode(a, &out));
    try testing.expectEqual(ResultCode.ack, back.payload.result.code);

    const n = nak(.encapsulated_npdu, 9, Vmac.broadcast, null, .{
        .header_marker = 0x41,
        .class = .communication,
        .code = @enumFromInt(146),
        .details = "no",
    });
    const back2 = try decode(try encode(n, &out));
    try testing.expectEqual(@as(u8, 0x41), back2.payload.result.err.?.header_marker);
    try testing.expectEqualStrings("no", back2.payload.result.err.?.details);
    try testing.expect(back2.header.source.?.isBroadcast());
}

test "a message with no destination is a broadcast, and so is the all-ones VMAC" {
    var out: [64]u8 = undefined;
    const bare: Message = .{ .header = .{ .message_id = 1 }, .payload = .{ .encapsulated_npdu = "" } };
    try testing.expect(bare.isBroadcast());
    var bcast = bare;
    bcast.header.destination = Vmac.broadcast;
    try testing.expect(bcast.isBroadcast());
    var direct = bare;
    direct.header.destination = .{ .octets = .{ 1, 2, 3, 4, 5, 6 } };
    try testing.expect(!direct.isBroadcast());
    _ = try encode(direct, &out);
}

// ── fuzz ───────────────────────────────────────────────────────────────────

test "fuzz: decode never panics, hangs or hands back a slice outside the input" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];
    const m = decode(input) catch return;

    // Everything the decoder handed back must point inside the input.
    const base = @intFromPtr(input.ptr);
    const end = base + input.len;
    const slices = [_][]const u8{
        m.header.destination_options,
        m.header.data_options,
        switch (m.payload) {
            .encapsulated_npdu, .address_resolution_ack => |p| p,
            .proprietary_message => |p| p.data,
            .result => |r| if (r.err) |e| e.details else "",
            else => "",
        },
    };
    for (slices) |sl| {
        if (sl.len == 0) continue;
        const at = @intFromPtr(sl.ptr);
        try testing.expect(at >= base and at + sl.len <= end);
    }

    // Walking the options must terminate and stay in bounds.
    _ = m.header.unsupportedOption() catch {};
    _ = m.header.hasSecurePath();

    // Anything that decodes must re-encode to the very same octets.
    var out: [512]u8 = undefined;
    const again = encode(m, &out) catch return;
    try testing.expectEqualSlices(u8, input, again);
}

test "fuzz: option walking always makes forward progress" {
    try std.testing.fuzz({}, fuzzOptions, .{});
}

fn fuzzOptions(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const input = buf[0..len];

    var it: OptionIter = .{ .rest = input };
    var before = it.rest.len;
    var seen: usize = 0;
    while (it.next() catch return) |opt| {
        // Every step must shrink the remainder, so a hostile list cannot stall.
        try testing.expect(it.rest.len < before);
        before = it.rest.len;
        seen += 1;
        try testing.expect(seen <= input.len + 1);
        if (opt.type == .proprietary) _ = opt.asProprietary() catch {};
    }

    // scanOptions agrees with the walk, or refuses.
    const n = scanOptions(input) catch return;
    try testing.expect(n <= input.len);
}
