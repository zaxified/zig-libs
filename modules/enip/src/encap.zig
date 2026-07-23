// SPDX-License-Identifier: MIT

//! EtherNet/IP **encapsulation** (CIP Volume 2, chapter 2): the 24-octet
//! header every message on TCP 44818 / UDP 2222 and 44818 carries, the command
//! set, and the payloads of the three "tell me about yourself" commands
//! (`ListIdentity`, `ListServices`, `ListInterfaces`).
//!
//! Three things about this header bite implementers:
//!
//! 1. **`length` counts the data *after* the header**, unlike TPKT's, which
//!    counts itself. A framer that adds 24 twice desynchronises the stream.
//! 2. **Everything is little-endian** — except the socket-address fields
//!    inside the identity and sockaddr items, which are `struct sockaddr_in`
//!    in *network* byte order sitting in the middle of a little-endian
//!    message. `cpf.SocketAddress` owns that rule.
//! 3. **`sender_context` is opaque to the receiver and echoed verbatim.** It
//!    is the only request/response correlation this protocol has, so it is
//!    modelled as eight raw octets and never interpreted.
//!
//! Session handles: zero on a `RegisterSession` request, whatever the target
//! answers with on everything afterwards. A target that receives a non-zero
//! handle it did not issue answers `invalid_session_handle` (0x0064).

const std = @import("std");
const netaddr = @import("netaddr");

/// The 24-octet encapsulation header.
pub const header_len: usize = 24;

/// The largest data portion the length field can express while keeping the
/// whole message inside 64 KiB. CIP Vol 2 §2-4.1 caps a target's reply at this
/// value, and it is what this module refuses to exceed on encode.
pub const max_data_len: usize = 65511;

/// The registered EtherNet/IP TCP port for explicit messaging (IANA
/// `EtherNet-IP-2`).
pub const default_tcp_port: u16 = 44818;
/// The registered UDP port for encapsulation commands (`ListIdentity`
/// discovery rides on this one, usually broadcast).
pub const default_udp_port: u16 = 44818;
/// The registered UDP port for **implicit** (Class 0/1 I/O) messaging.
pub const io_udp_port: u16 = 2222;

/// Encapsulation commands (CIP Vol 2 Table 2-3.2). Commands outside this set
/// are refused rather than guessed at, because their payload shape is unknown
/// and a decoder that walks into one produces garbage.
pub const Command = enum(u16) {
    nop = 0x0000,
    list_services = 0x0004,
    list_identity = 0x0063,
    list_interfaces = 0x0064,
    register_session = 0x0065,
    unregister_session = 0x0066,
    send_rr_data = 0x006F,
    send_unit_data = 0x0070,
    /// Legacy, retired in later editions; decoded so a capture containing one
    /// can be walked, never emitted.
    indicate_status = 0x0072,
    cancel = 0x0073,
    _,

    /// True for the commands whose payload this module models in full.
    pub fn isKnown(c: Command) bool {
        return switch (c) {
            .nop,
            .list_services,
            .list_identity,
            .list_interfaces,
            .register_session,
            .unregister_session,
            .send_rr_data,
            .send_unit_data,
            => true,
            else => false,
        };
    }

    /// True for the commands a target answers **without** a session handle.
    /// Sending any other command with a handle of zero is a protocol error.
    pub fn isSessionless(c: Command) bool {
        return switch (c) {
            .nop, .list_services, .list_identity, .list_interfaces, .register_session => true,
            else => false,
        };
    }
};

/// Encapsulation-layer status (CIP Vol 2 Table 2-3.3). Non-exhaustive: real
/// targets emit values outside the table (the simulator used for the goldens
/// answers `0x0008` for a request it cannot parse), and a decoder that refuses
/// them would drop a reply the peer genuinely sent.
pub const Status = enum(u32) {
    success = 0x0000,
    invalid_command = 0x0001,
    insufficient_memory = 0x0002,
    incorrect_data = 0x0003,
    invalid_session_handle = 0x0064,
    invalid_length = 0x0065,
    unsupported_protocol_revision = 0x0069,
    /// "Encapsulated CIP service not allowed on this port".
    unsupported_encapsulated_command = 0x006A,
    _,

    pub fn isSuccess(s: Status) bool {
        return s == .success;
    }
};

/// The protocol version a `RegisterSession` negotiates. Only 1 exists.
pub const protocol_version: u16 = 1;

pub const DecodeError = error{
    /// Fewer than 24 octets, so the header itself is incomplete.
    Truncated,
    /// The length field disagrees with the octets actually present.
    LengthMismatch,
    /// The length field exceeds what encapsulation may carry.
    TooLong,
    /// An options field this module does not understand was set. The spec
    /// requires senders to zero it and receivers to reject anything else.
    BadOptions,
};

pub const EncodeError = error{
    /// The output buffer cannot hold header + data.
    BufferTooSmall,
    /// The data portion exceeds `max_data_len`.
    TooLong,
};

/// One decoded encapsulation message: the header fields plus a slice of the
/// caller's buffer holding the command-specific data.
pub const Message = struct {
    command: Command,
    session_handle: u32,
    status: Status,
    sender_context: [8]u8,
    options: u32,
    /// Command-specific data — a sub-slice of the input, never copied.
    data: []const u8,
    /// Header + data, so a stream reader knows exactly what it consumed.
    total_len: usize,
};

/// Reads the length field out of a 24-octet header without decoding the rest,
/// so a socket adapter can read exactly one message.
pub fn peekTotalLen(head: []const u8) DecodeError!usize {
    if (head.len < header_len) return error.Truncated;
    const data_len = std.mem.readInt(u16, head[2..4], .little);
    return header_len + data_len;
}

/// Decodes exactly one message from the front of `bytes`.
///
/// The length field must account for **exactly** the octets present — this
/// protocol has no checksum, so a length disagreement is the only signal that
/// framing has gone wrong, and neither a short nor a long message is accepted.
/// Trailing octets past the announced data are a `LengthMismatch`, not a
/// silently-ignored tail; use `Framer` for a stream that carries several.
pub fn decode(bytes: []const u8) DecodeError!Message {
    const msg = try decodePrefix(bytes);
    if (msg.total_len != bytes.len) return error.LengthMismatch;
    return msg;
}

/// Like `decode`, but tolerates octets past the end of this message (they
/// belong to the next one). Used by `Framer`.
pub fn decodePrefix(bytes: []const u8) DecodeError!Message {
    if (bytes.len < header_len) return error.Truncated;
    const data_len: usize = std.mem.readInt(u16, bytes[2..4], .little);
    if (data_len > max_data_len) return error.TooLong;
    const total = header_len + data_len;
    if (bytes.len < total) return error.LengthMismatch;
    const options = std.mem.readInt(u32, bytes[20..24], .little);
    // Vol 2 §2-3.6: senders shall set Options to 0 and receivers shall reject
    // anything else. Being strict here is what stops a crafted message from
    // steering a future extension.
    if (options != 0) return error.BadOptions;
    return .{
        .command = @enumFromInt(std.mem.readInt(u16, bytes[0..2], .little)),
        .session_handle = std.mem.readInt(u32, bytes[4..8], .little),
        .status = @enumFromInt(std.mem.readInt(u32, bytes[8..12], .little)),
        .sender_context = bytes[12..20].*,
        .options = options,
        .data = bytes[header_len..total],
        .total_len = total,
    };
}

/// Encodes a message into `out`, returning the written prefix. The length
/// field is derived from `data` and never from a caller-supplied number, so an
/// inconsistent header cannot be produced.
pub fn encode(msg: Message, out: []u8) EncodeError![]u8 {
    if (msg.data.len > max_data_len) return error.TooLong;
    const total = header_len + msg.data.len;
    if (out.len < total) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], @intFromEnum(msg.command), .little);
    std.mem.writeInt(u16, out[2..4], @intCast(msg.data.len), .little);
    std.mem.writeInt(u32, out[4..8], msg.session_handle, .little);
    std.mem.writeInt(u32, out[8..12], @intFromEnum(msg.status), .little);
    @memcpy(out[12..20], &msg.sender_context);
    std.mem.writeInt(u32, out[20..24], msg.options, .little);
    @memcpy(out[header_len..total], msg.data);
    return out[0..total];
}

// ── stream framing ──────────────────────────────────────────────────────────

/// Splits a TCP byte stream into encapsulation messages. TCP gives no message
/// boundaries; this is what supplies them.
///
/// It refuses a message larger than its own storage rather than waiting
/// forever for octets that will never fit, and returns `null` until a whole
/// message is present.
pub const Framer = struct {
    storage: []u8,
    len: usize = 0,

    pub const FeedError = error{Overflow};

    pub fn init(storage: []u8) Framer {
        return .{ .storage = storage };
    }

    pub fn feed(self: *Framer, bytes: []const u8) FeedError!void {
        if (self.len + bytes.len > self.storage.len) return error.Overflow;
        @memcpy(self.storage[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    /// The next complete message, or `null` if more octets are needed.
    /// The returned slices point into the framer's storage and stay valid
    /// until the next `feed`/`next`.
    pub fn next(self: *Framer) (DecodeError || FeedError)!?Message {
        if (self.len < header_len) return null;
        const total = try peekTotalLen(self.storage[0..header_len]);
        if (total - header_len > max_data_len) return error.TooLong;
        // A message that can never fit is a hard error, not a wait forever.
        if (total > self.storage.len) return error.Overflow;
        if (self.len < total) return null;
        const msg = try decodePrefix(self.storage[0..total]);
        std.mem.copyForwards(u8, self.storage[0..], self.storage[total..self.len]);
        self.len -= total;
        return msg;
    }
};

// ── RegisterSession ─────────────────────────────────────────────────────────

/// The four-octet `RegisterSession` payload, identical in request and reply.
pub const RegisterSessionData = struct {
    version: u16 = protocol_version,
    /// Vol 2 §2-4.4: shall be zero; a target rejects anything else.
    options_flags: u16 = 0,

    pub const encoded_len: usize = 4;

    pub fn decode(bytes: []const u8) DecodeError!RegisterSessionData {
        if (bytes.len != encoded_len) return error.LengthMismatch;
        return .{
            .version = std.mem.readInt(u16, bytes[0..2], .little),
            .options_flags = std.mem.readInt(u16, bytes[2..4], .little),
        };
    }

    pub fn encode(self: RegisterSessionData, out: []u8) EncodeError![]u8 {
        if (out.len < encoded_len) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.version, .little);
        std.mem.writeInt(u16, out[2..4], self.options_flags, .little);
        return out[0..encoded_len];
    }
};

// ── ListIdentity / ListServices / ListInterfaces payloads ───────────────────

/// The CIP Identity object's device-type codes, for the handful worth naming.
/// Non-exhaustive — the list is long and vendor-extended.
pub const DeviceType = enum(u16) {
    ac_drive = 0x0002,
    motor_overload = 0x0003,
    limit_switch = 0x0004,
    inductive_proximity_switch = 0x0005,
    photoelectric_sensor = 0x0006,
    general_purpose_discrete_io = 0x0007,
    resolver = 0x0009,
    communications_adapter = 0x000C,
    /// What a controller reports (a "programmable logic controller").
    programmable_logic_controller = 0x000E,
    position_controller = 0x0010,
    dc_drive = 0x0013,
    contactor = 0x0015,
    motor_starter = 0x0016,
    softstart = 0x0017,
    human_machine_interface = 0x0018,
    mass_flow_controller = 0x001A,
    pneumatic_valve = 0x001B,
    vacuum_pressure_gauge = 0x001C,
    _,
};

/// The Identity object's *state* attribute, as reported inside a ListIdentity
/// item. `0xFF` means "the device does not implement this attribute", which is
/// what most controllers answer.
pub const DeviceState = enum(u8) {
    nonexistent = 0,
    self_testing = 1,
    standby = 2,
    operational = 3,
    major_recoverable_fault = 4,
    major_unrecoverable_fault = 5,
    unimplemented = 0xFF,
    _,
};

/// One device's answer to `ListIdentity`: CPF item type `0x000C`.
///
/// `product_name` points into the caller's buffer; nothing is copied.
pub const Identity = struct {
    /// Encapsulation protocol version the device supports (1).
    encapsulation_version: u16 = protocol_version,
    /// `sockaddr_in` in **network** byte order — see `cpf.SocketAddress`.
    socket_address: SocketAddress,
    vendor_id: u16,
    device_type: u16,
    product_code: u16,
    revision_major: u8,
    revision_minor: u8,
    /// Identity object attribute 5, a bit field.
    status: u16,
    serial_number: u32,
    product_name: []const u8,
    state: DeviceState,

    /// Everything but the product name is fixed-width.
    pub const fixed_len: usize = 2 + SocketAddress.encoded_len + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 1 + 1;

    pub fn encodedLen(self: Identity) usize {
        return fixed_len + self.product_name.len;
    }

    pub fn decode(bytes: []const u8) DecodeError!Identity {
        if (bytes.len < fixed_len) return error.Truncated;
        const name_len: usize = bytes[32];
        if (bytes.len < fixed_len + name_len) return error.Truncated;
        // The state octet follows the name; anything past it is not ours.
        if (bytes.len != fixed_len + name_len) return error.LengthMismatch;
        return .{
            .encapsulation_version = std.mem.readInt(u16, bytes[0..2], .little),
            .socket_address = try SocketAddress.decode(bytes[2..18]),
            .vendor_id = std.mem.readInt(u16, bytes[18..20], .little),
            .device_type = std.mem.readInt(u16, bytes[20..22], .little),
            .product_code = std.mem.readInt(u16, bytes[22..24], .little),
            .revision_major = bytes[24],
            .revision_minor = bytes[25],
            .status = std.mem.readInt(u16, bytes[26..28], .little),
            .serial_number = std.mem.readInt(u32, bytes[28..32], .little),
            .product_name = bytes[33 .. 33 + name_len],
            .state = @enumFromInt(bytes[33 + name_len]),
        };
    }

    pub fn encode(self: Identity, out: []u8) EncodeError![]u8 {
        if (self.product_name.len > 255) return error.TooLong;
        const total = self.encodedLen();
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.encapsulation_version, .little);
        _ = try self.socket_address.encode(out[2..18]);
        std.mem.writeInt(u16, out[18..20], self.vendor_id, .little);
        std.mem.writeInt(u16, out[20..22], self.device_type, .little);
        std.mem.writeInt(u16, out[22..24], self.product_code, .little);
        out[24] = self.revision_major;
        out[25] = self.revision_minor;
        std.mem.writeInt(u16, out[26..28], self.status, .little);
        std.mem.writeInt(u32, out[28..32], self.serial_number, .little);
        out[32] = @intCast(self.product_name.len);
        @memcpy(out[33..][0..self.product_name.len], self.product_name);
        out[33 + self.product_name.len] = @intFromEnum(self.state);
        return out[0..total];
    }
};

/// The `sockaddr_in` embedded in identity and sockaddr-info items:
/// **network byte order in the middle of a little-endian message**, which is
/// the single most common decoding mistake in this protocol.
pub const SocketAddress = struct {
    /// `AF_INET` (2) on every device seen.
    family: i16 = 2,
    port: u16,
    /// IPv4 address, most significant octet first (as it appears on the wire).
    addr: [4]u8,
    /// `sin_zero`; senders zero it, and it is kept so a re-encode is exact.
    zero: [8]u8 = @splat(0),

    pub const encoded_len: usize = 16;

    pub fn decode(bytes: []const u8) DecodeError!SocketAddress {
        if (bytes.len < encoded_len) return error.Truncated;
        return .{
            .family = std.mem.readInt(i16, bytes[0..2], .big),
            .port = std.mem.readInt(u16, bytes[2..4], .big),
            .addr = bytes[4..8].*,
            .zero = bytes[8..16].*,
        };
    }

    pub fn encode(self: SocketAddress, out: []u8) EncodeError![]u8 {
        if (out.len < encoded_len) return error.BufferTooSmall;
        std.mem.writeInt(i16, out[0..2], self.family, .big);
        std.mem.writeInt(u16, out[2..4], self.port, .big);
        @memcpy(out[4..8], &self.addr);
        @memcpy(out[8..16], &self.zero);
        return out[0..encoded_len];
    }

    /// The address as a `netaddr.Ip`, which is what a caller wants to
    /// format, compare or feed to a socket. `sockaddr_in` is IPv4-only, so
    /// this is always `.v4`.
    pub fn ip(self: SocketAddress) netaddr.Ip {
        return .{ .v4 = self.addr };
    }

    /// Builds the item from a `netaddr.Ip`. An IPv6 address has no
    /// representation here and is refused rather than truncated.
    pub fn fromIp(addr: netaddr.Ip, port: u16) EncodeError!SocketAddress {
        return switch (addr.unmap()) {
            .v4 => |q| .{ .port = port, .addr = q },
            .v6 => error.TooLong,
        };
    }
};

/// One entry of a `ListServices` reply: CPF item type `0x0100`.
///
/// The spec draws `name_of_service` as a fixed 16-octet field, but the
/// reference target used for the goldens emits `"Communications\x00"` — 15
/// octets — and stops. The name is therefore decoded as "whatever is left in
/// the item", which round-trips both shapes; a spec-literal 16-octet decoder
/// rejects real traffic.
pub const Service = struct {
    version: u16 = protocol_version,
    /// Bit 5 = supports CIP encapsulation over TCP, bit 8 = supports Class 0/1
    /// UDP. `0x0020` is what a TCP-only explicit-messaging target answers.
    capability_flags: u16,
    /// Trailing NUL included exactly as received.
    name: []const u8,

    pub const supports_tcp_encapsulation: u16 = 0x0020;
    pub const supports_class_0_1_udp: u16 = 0x0100;

    pub fn decode(bytes: []const u8) DecodeError!Service {
        if (bytes.len < 4) return error.Truncated;
        return .{
            .version = std.mem.readInt(u16, bytes[0..2], .little),
            .capability_flags = std.mem.readInt(u16, bytes[2..4], .little),
            .name = bytes[4..],
        };
    }

    pub fn encode(self: Service, out: []u8) EncodeError![]u8 {
        const total = 4 + self.name.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.version, .little);
        std.mem.writeInt(u16, out[2..4], self.capability_flags, .little);
        @memcpy(out[4..total], self.name);
        return out[0..total];
    }

    /// The service name without its trailing NUL padding.
    pub fn trimmedName(self: Service) []const u8 {
        return std.mem.sliceTo(self.name, 0);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "header round trips" {
    const msg = Message{
        .command = .register_session,
        .session_handle = 0,
        .status = .success,
        .sender_context = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .options = 0,
        .data = &[_]u8{ 0x01, 0x00, 0x00, 0x00 },
        .total_len = 0,
    };
    var buf: [64]u8 = undefined;
    const wire = try encode(msg, &buf);
    try testing.expectEqual(@as(usize, 28), wire.len);
    const back = try decode(wire);
    try testing.expectEqual(Command.register_session, back.command);
    try testing.expectEqual(@as(usize, 28), back.total_len);
    try testing.expectEqualSlices(u8, msg.data, back.data);
    try testing.expectEqualSlices(u8, &msg.sender_context, &back.sender_context);
}

test "length field counts the data, not the header" {
    // 24-octet header claiming 4 octets of data, with 4 present.
    const wire = [_]u8{ 0x65, 0x00, 0x04, 0x00 } ++ [_]u8{0} ** 20 ++ [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const m = try decode(&wire);
    try testing.expectEqual(@as(usize, 4), m.data.len);
    try testing.expectEqual(@as(usize, 28), m.total_len);
    try testing.expectEqual(@as(usize, 28), try peekTotalLen(wire[0..24]));
}

test "a length that disagrees with the payload is refused in both directions" {
    var wire = [_]u8{ 0x65, 0x00, 0x04, 0x00 } ++ [_]u8{0} ** 20 ++ [_]u8{ 1, 0, 0, 0 };
    try testing.expectError(error.LengthMismatch, decode(wire[0..27])); // short
    // Long: announce 3 but present 4.
    wire[2] = 3;
    try testing.expectError(error.LengthMismatch, decode(&wire));
}

test "a truncated header is not a length problem" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 0x65, 0x00 }));
    try testing.expectError(error.Truncated, peekTotalLen(&[_]u8{0} ** 23));
}

test "non-zero options are refused" {
    var wire = [_]u8{ 0x63, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 20;
    wire[20] = 1;
    try testing.expectError(error.BadOptions, decode(&wire));
}

test "encode refuses more data than encapsulation can carry" {
    var out: [32]u8 = undefined;
    const msg = Message{
        .command = .nop,
        .session_handle = 0,
        .status = .success,
        .sender_context = @splat(0),
        .options = 0,
        .data = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        .total_len = 0,
    };
    try testing.expectError(error.BufferTooSmall, encode(msg, &out));
}

test "commands classify" {
    try testing.expect(Command.list_identity.isSessionless());
    try testing.expect(!Command.send_rr_data.isSessionless());
    try testing.expect(Command.send_unit_data.isKnown());
    try testing.expect(!(@as(Command, @enumFromInt(0x1234))).isKnown());
}

test "framer splits a stream carrying three messages" {
    var one: [64]u8 = undefined;
    const a = try encode(.{
        .command = .nop,
        .session_handle = 0,
        .status = .success,
        .sender_context = @splat(0),
        .options = 0,
        .data = &.{},
        .total_len = 0,
    }, &one);
    var two: [64]u8 = undefined;
    const b = try encode(.{
        .command = .register_session,
        .session_handle = 7,
        .status = .success,
        .sender_context = @splat(0xAB),
        .options = 0,
        .data = &[_]u8{ 1, 0, 0, 0 },
        .total_len = 0,
    }, &two);

    var storage: [256]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(a);
    try f.feed(b);
    try f.feed(a);
    const m1 = (try f.next()).?;
    try testing.expectEqual(Command.nop, m1.command);
    const m2 = (try f.next()).?;
    try testing.expectEqual(Command.register_session, m2.command);
    try testing.expectEqual(@as(u32, 7), m2.session_handle);
    const m3 = (try f.next()).?;
    try testing.expectEqual(Command.nop, m3.command);
    try testing.expectEqual(@as(?Message, null), try f.next());
}

test "framer waits for a partial message and never spins" {
    var storage: [128]u8 = undefined;
    var f = Framer.init(&storage);
    try f.feed(&([_]u8{ 0x65, 0x00, 0x04, 0x00 } ++ [_]u8{0} ** 20));
    try testing.expectEqual(@as(?Message, null), try f.next());
    try f.feed(&[_]u8{ 1, 0 });
    try testing.expectEqual(@as(?Message, null), try f.next());
    try f.feed(&[_]u8{ 0, 0 });
    try testing.expect((try f.next()) != null);
}

test "framer refuses a message larger than its storage instead of waiting forever" {
    var storage: [40]u8 = undefined;
    var f = Framer.init(&storage);
    // Announce 1000 octets of data; storage can never hold it.
    try f.feed(&([_]u8{ 0x6F, 0x00, 0xE8, 0x03 } ++ [_]u8{0} ** 20));
    try testing.expectError(error.Overflow, f.next());
}

test "RegisterSession payload round trips" {
    var buf: [8]u8 = undefined;
    const d = RegisterSessionData{};
    const wire = try d.encode(&buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0 }, wire);
    const back = try RegisterSessionData.decode(wire);
    try testing.expectEqual(@as(u16, 1), back.version);
    try testing.expectError(error.LengthMismatch, RegisterSessionData.decode(wire[0..3]));
}

test "socket address is big-endian inside a little-endian message" {
    const wire = [_]u8{ 0x00, 0x02, 0xAF, 0x12, 192, 168, 1, 5 } ++ [_]u8{0} ** 8;
    const sa = try SocketAddress.decode(&wire);
    try testing.expectEqual(@as(i16, 2), sa.family);
    try testing.expectEqual(@as(u16, 44818), sa.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 5 }, &sa.addr);
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try sa.encode(&out));
    // …and it bridges to netaddr, which is what a caller formats or dials.
    var text: [netaddr.max_ip_text_len]u8 = undefined;
    try testing.expectEqualStrings("192.168.1.5", netaddr.formatIp(sa.ip(), &text));
    const rebuilt = try SocketAddress.fromIp(.{ .v4 = .{ 192, 168, 1, 5 } }, 44818);
    try testing.expectEqualSlices(u8, &wire, try rebuilt.encode(&out));
    try testing.expectError(error.TooLong, SocketAddress.fromIp(.{ .v6 = @splat(1) }, 1));
}

test "identity round trips and rejects a name length that overruns" {
    const ident = Identity{
        .socket_address = .{ .port = 44818, .addr = .{ 10, 0, 0, 3 } },
        .vendor_id = 1,
        .device_type = 14,
        .product_code = 54,
        .revision_major = 20,
        .revision_minor = 11,
        .status = 0x3160,
        .serial_number = 0x00C0FFEE,
        .product_name = "SIMULATED-CIP-DEVICE",
        .state = .unimplemented,
    };
    var buf: [128]u8 = undefined;
    const wire = try ident.encode(&buf);
    try testing.expectEqual(ident.encodedLen(), wire.len);
    const back = try Identity.decode(wire);
    try testing.expectEqualStrings("SIMULATED-CIP-DEVICE", back.product_name);
    try testing.expectEqual(@as(u32, 0x00C0FFEE), back.serial_number);
    try testing.expectEqual(DeviceState.unimplemented, back.state);

    // A name length that runs past the item.
    var bad: [512]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[32] = 200;
    try testing.expectError(error.Truncated, Identity.decode(bad[0..wire.len]));
    // Trailing junk past the state octet.
    var long: [128]u8 = undefined;
    @memcpy(long[0..wire.len], wire);
    long[wire.len] = 0xFF;
    try testing.expectError(error.LengthMismatch, Identity.decode(long[0 .. wire.len + 1]));
}

test "service name is whatever is left in the item, not a fixed 16 octets" {
    // Exactly what the reference target emits: 15 octets of name.
    const wire = [_]u8{ 0x01, 0x00, 0x20, 0x00 } ++ "Communications\x00".*;
    const s = try Service.decode(&wire);
    try testing.expectEqual(@as(u16, 0x0020), s.capability_flags);
    try testing.expectEqualStrings("Communications", s.trimmedName());
    var out: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire, try s.encode(&out));
    // The spec-literal 16-octet shape must also round-trip.
    const padded = [_]u8{ 0x01, 0x00, 0x20, 0x01 } ++ "Communications\x00\x00".*;
    const s2 = try Service.decode(&padded);
    try testing.expectEqualStrings("Communications", s2.trimmedName());
    try testing.expectEqualSlices(u8, &padded, try s2.encode(&out));
}

test "fuzz: encapsulation decode never panics and re-encodes exactly" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const msg = decode(buf[0..len]) catch return;
    try testing.expectEqual(len, msg.total_len);
    var round: [512]u8 = undefined;
    const again = try encode(msg, &round);
    try testing.expectEqualSlices(u8, buf[0..len], again);
}

test "fuzz: framer never panics or hangs" {
    try std.testing.fuzz({}, fuzzFramer, .{});
}

fn fuzzFramer(_: void, smith: *std.testing.Smith) !void {
    var input: [512]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u16, 0, input.len);
    var storage: [1024]u8 = undefined;
    var f = Framer.init(&storage);
    var off: usize = 0;
    var guard: usize = 0;
    while (off < len) {
        const chunk = @min(len - off, @as(usize, 64));
        f.feed(input[off..][0..chunk]) catch return;
        off += chunk;
        while (true) {
            guard += 1;
            // A `next` that returns a message without consuming input is an
            // infinite-loop bug; 4096 rounds over 512 octets cannot happen.
            try testing.expect(guard < 4096);
            const m = f.next() catch return;
            if (m == null) break;
        }
    }
}

test "fuzz: identity and service decoders never panic" {
    try std.testing.fuzz({}, fuzzItems, .{});
}

fn fuzzItems(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    if (Identity.decode(buf[0..len])) |ident| {
        var round: [256]u8 = undefined;
        const again = try ident.encode(&round);
        try testing.expectEqualSlices(u8, buf[0..len], again);
    } else |_| {}
    if (Service.decode(buf[0..len])) |svc| {
        var round: [256]u8 = undefined;
        const again = try svc.encode(&round);
        try testing.expectEqualSlices(u8, buf[0..len], again);
    } else |_| {}
    if (SocketAddress.decode(buf[0..len])) |sa| {
        var round: [16]u8 = undefined;
        const again = try sa.encode(&round);
        try testing.expectEqualSlices(u8, buf[0..16], again);
    } else |_| {}
}
