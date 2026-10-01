// SPDX-License-Identifier: MIT

//! MQTT control-packet codec, versions 3.1.1 and 5.0: encode + decode for all
//! 14 packet types of 3.1.1 (CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC,
//! PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ,
//! PINGRESP, DISCONNECT) plus 5.0's AUTH, its properties and reason codes.
//!
//! Pure wire logic — no I/O, no allocation. Decoding is zero-copy: string
//! and payload fields of a decoded `Packet` are slices into the input
//! buffer. `decode` returns `null` while the buffer does not yet hold a
//! complete packet (stream framing) and a typed error for malformed bytes —
//! it never panics on hostile input. All lengths are bounded: UTF-8 strings
//! by their 2-byte length prefix, the packet body by the remaining-length
//! varint (1–4 bytes, max 268 435 455, overlong encodings rejected).
//!
//! **Versions.** Every packet after CONNECT is laid out differently in 5.0
//! (properties, reason codes), and nothing on the wire says which version a
//! packet is — the CONNECT that opened the connection does. So the version is
//! a parameter: `decodePacket(bytes, version)` / `encodePacket(buf, version,
//! packet)`. One `Packet` type serves both: the 5.0-only fields (`properties`,
//! `reason_code`, the subscription options, AUTH) default to what 3.1.1 means
//! implicitly, and encoding a 3.1.1 packet that sets one is
//! `error.UnsupportedInVersion` rather than a silent drop. A server reads its
//! first packet with `.v5`, under which a CONNECT of either level decodes and
//! reports its level in `Connect.version`; `.v3_1_1` refuses a level-5
//! CONNECT, as this codec always did. `decode` and the `encode<Type>`
//! functions are the 3.1.1 forms they always were.
//!
//! **Properties** (5.0 §2.2.2) decode into the typed `Properties`, validated:
//! an identifier not allowed for the packet type is `MalformedPacket`; a
//! duplicate, a zero where zero is forbidden, or an out-of-range byte is
//! `ProtocolViolation` — the split §2.2.2.2 and the per-property "It is a
//! Protocol Error" sentences make, so a 5.0 peer can answer 0x81 or 0x82 as
//! §4.13 asks (`reasonForDecodeError`). The two properties that may repeat —
//! User Property, and Subscription Identifier in a PUBLISH — are read from
//! the validated block in place (`raw`) and re-encoded verbatim, so a server
//! forwarding a message keeps their order (§3.3.2-18) without copying them.
//!
//! Provenance: clean-room from the OASIS MQTT Version 3.1.1 and Version 5.0
//! specifications.

const std = @import("std");

/// Protocol name carried in the CONNECT variable header (spec 3.1.2.1).
pub const protocol_name = "MQTT";
/// Protocol level for MQTT 3.1.1 (spec 3.1.2.2).
pub const protocol_level: u8 = 4;

/// The protocol version a connection speaks — the CONNECT's protocol level.
pub const Version = enum(u8) {
    v3_1_1 = 4,
    v5 = 5,
};

/// Largest value the remaining-length varint can carry (spec 2.2.3).
pub const max_remaining_length: u32 = 268_435_455;

/// Largest UTF-8 string / binary field (2-byte length prefix, spec 1.5.3).
pub const max_string_len: usize = 65_535;

/// SUBACK per-filter return code for "subscription refused" (spec 3.9.3).
pub const suback_failure: u8 = 0x80;

/// Control-packet type, the high nibble of the fixed header (spec 2.2.1).
/// `auth` exists in 5.0 only; under 3.1.1 type 15 is reserved.
pub const PacketType = enum(u4) {
    connect = 1,
    connack = 2,
    publish = 3,
    puback = 4,
    pubrec = 5,
    pubrel = 6,
    pubcomp = 7,
    subscribe = 8,
    suback = 9,
    unsubscribe = 10,
    unsuback = 11,
    pingreq = 12,
    pingresp = 13,
    disconnect = 14,
    auth = 15,
};

/// Quality-of-service level (spec 4.3).
pub const QoS = enum(u2) {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

/// CONNACK return code (3.1.1 spec 3.2.2.3): 0 accepted, 1–5 refused.
pub const ConnectReturnCode = enum(u8) {
    accepted = 0,
    unacceptable_protocol_version = 1,
    identifier_rejected = 2,
    server_unavailable = 3,
    bad_username_or_password = 4,
    not_authorized = 5,
};

/// MQTT 5.0 Reason Code (spec 2.4, Table 2-6). Below 0x80 is success. One
/// value has several names depending on the packet (0x00 is Success, Normal
/// disconnection and Granted QoS 0) — the aliases are declarations.
/// Which codes a packet may carry is checked by the codec both ways.
pub const ReasonCode = enum(u8) {
    success = 0x00,
    granted_qos_1 = 0x01,
    granted_qos_2 = 0x02,
    disconnect_with_will_message = 0x04,
    no_matching_subscribers = 0x10,
    no_subscription_existed = 0x11,
    continue_authentication = 0x18,
    re_authenticate = 0x19,
    unspecified_error = 0x80,
    malformed_packet = 0x81,
    protocol_error = 0x82,
    implementation_specific_error = 0x83,
    unsupported_protocol_version = 0x84,
    client_identifier_not_valid = 0x85,
    bad_user_name_or_password = 0x86,
    not_authorized = 0x87,
    server_unavailable = 0x88,
    server_busy = 0x89,
    banned = 0x8A,
    server_shutting_down = 0x8B,
    bad_authentication_method = 0x8C,
    keep_alive_timeout = 0x8D,
    session_taken_over = 0x8E,
    topic_filter_invalid = 0x8F,
    topic_name_invalid = 0x90,
    packet_identifier_in_use = 0x91,
    packet_identifier_not_found = 0x92,
    receive_maximum_exceeded = 0x93,
    topic_alias_invalid = 0x94,
    packet_too_large = 0x95,
    message_rate_too_high = 0x96,
    quota_exceeded = 0x97,
    administrative_action = 0x98,
    payload_format_invalid = 0x99,
    retain_not_supported = 0x9A,
    qos_not_supported = 0x9B,
    use_another_server = 0x9C,
    server_moved = 0x9D,
    shared_subscriptions_not_supported = 0x9E,
    connection_rate_exceeded = 0x9F,
    maximum_connect_time = 0xA0,
    subscription_identifiers_not_supported = 0xA1,
    wildcard_subscriptions_not_supported = 0xA2,

    pub const normal_disconnection: ReasonCode = .success;
    pub const granted_qos_0: ReasonCode = .success;

    /// Codes of 0x80 and above report a failure (spec 2.4).
    pub fn isError(rc: ReasonCode) bool {
        return @intFromEnum(rc) >= 0x80;
    }

    /// The SUBACK code granting `qos`.
    pub fn granted(qos: QoS) ReasonCode {
        return @enumFromInt(@intFromEnum(qos));
    }
};

/// The packets that carry a reason code, as far as which codes they may
/// carry is concerned (PUBACK and PUBREC share a set, as do PUBREL and
/// PUBCOMP).
pub const ReasonContext = enum { connack, puback, pubrec, pubrel, pubcomp, suback, unsuback, disconnect, auth };

const connack_reasons = [_]u8{ 0x00, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8C, 0x90, 0x95, 0x97, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9F };
const puback_reasons = [_]u8{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 };
const pubrel_reasons = [_]u8{ 0x00, 0x92 };
const suback_reasons = [_]u8{ 0x00, 0x01, 0x02, 0x80, 0x83, 0x87, 0x8F, 0x91, 0x97, 0x9E, 0xA1, 0xA2 };
const unsuback_reasons = [_]u8{ 0x00, 0x11, 0x80, 0x83, 0x87, 0x8F, 0x91 };
const disconnect_reasons = [_]u8{ 0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2 };
const auth_reasons = [_]u8{ 0x00, 0x18, 0x19 };

/// Whether `code` is one of the reason codes `ctx` may carry (Table 2-6).
pub fn reasonAllowed(ctx: ReasonContext, code: u8) bool {
    const set: []const u8 = switch (ctx) {
        .connack => &connack_reasons,
        .puback, .pubrec => &puback_reasons,
        .pubrel, .pubcomp => &pubrel_reasons,
        .suback => &suback_reasons,
        .unsuback => &unsuback_reasons,
        .disconnect => &disconnect_reasons,
        .auth => &auth_reasons,
    };
    return std.mem.indexOfScalar(u8, set, code) != null;
}

/// The 5.0 reason code a 3.1.1 CONNACK return code corresponds to.
pub fn reasonFromReturnCode(rc: ConnectReturnCode) ReasonCode {
    return switch (rc) {
        .accepted => .success,
        .unacceptable_protocol_version => .unsupported_protocol_version,
        .identifier_rejected => .client_identifier_not_valid,
        .server_unavailable => .server_unavailable,
        .bad_username_or_password => .bad_user_name_or_password,
        .not_authorized => .not_authorized,
    };
}

/// The nearest 3.1.1 CONNACK return code to a 5.0 CONNACK reason code. Lossy:
/// 5.0 has many refusals 3.1.1 cannot name; those become `server_unavailable`
/// (or `not_authorized` for the ones about who the client is).
pub fn returnCodeFromReason(rc: ReasonCode) ConnectReturnCode {
    return switch (rc) {
        .success => .accepted,
        .unsupported_protocol_version => .unacceptable_protocol_version,
        .client_identifier_not_valid => .identifier_rejected,
        .bad_user_name_or_password => .bad_username_or_password,
        .not_authorized, .banned, .bad_authentication_method => .not_authorized,
        else => .server_unavailable,
    };
}

/// The reason code a 5.0 receiver answers a decode failure with (spec 4.13):
/// 0x81 Malformed Packet, 0x82 Protocol Error, 0x84 for an unsupported
/// protocol level in a CONNECT.
pub fn reasonForDecodeError(err: DecodeError) ReasonCode {
    return switch (err) {
        error.ProtocolViolation => .protocol_error,
        error.UnsupportedProtocol => .unsupported_protocol_version,
        else => .malformed_packet,
    };
}

// ── error sets ──────────────────────────────────────────────────────────────

/// Failures while building a packet (all detected locally, before I/O).
pub const EncodeError = error{
    /// Destination buffer too small for the encoded packet.
    BufferTooSmall,
    /// A string / binary field exceeds the 65 535-byte length prefix.
    StringTooLong,
    /// Remaining length would exceed 268 435 455 bytes.
    PacketTooLarge,
    /// A UTF-8 string field is not well-formed UTF-8 (or contains U+0000).
    InvalidUtf8,
    /// CONNECT carries a password without a username (3.1.1 spec 3.1.2.9;
    /// allowed in 5.0).
    PasswordWithoutUsername,
    /// Packet identifier 0 where a nonzero one is required (spec 2.3.1).
    InvalidPacketId,
    /// Empty client id without clean session (3.1.1 spec 3.1.3-7).
    InvalidClientId,
    /// SUBSCRIBE / UNSUBSCRIBE / SUBACK with an empty topic/code list.
    EmptyTopicList,
    /// SUBACK code not allowed for the version (3.1.1: 0, 1, 2 or 0x80).
    InvalidSubackCode,
    /// A field the target version cannot express: properties, a reason code
    /// other than success, subscription options, UNSUBACK codes or AUTH in
    /// 3.1.1.
    UnsupportedInVersion,
    /// A reason code the packet type may not carry (5.0 Table 2-6).
    InvalidReasonCode,
    /// A property the packet type may not carry, or a value the spec forbids
    /// (a zero Receive Maximum, Topic Alias or Subscription Identifier, a
    /// Maximum QoS of 2, wildcards in a Response Topic, a second Subscription
    /// Identifier outside PUBLISH, Authentication Data without a Method).
    InvalidProperty,
    /// PUBLISH with an empty topic name and no Topic Alias to stand for it.
    InvalidTopic,
};

/// Failures while decoding peer bytes. Typed, never a panic.
pub const DecodeError = error{
    /// Remaining-length varint is longer than 4 bytes or overlong-encoded.
    MalformedRemainingLength,
    /// Fixed-header type nibble is 0, or 15 under 3.1.1 (reserved).
    UnknownPacketType,
    /// Fixed-header flag bits differ from the value the spec mandates.
    InvalidFlags,
    /// A QoS field holds the reserved value 3.
    InvalidQos,
    /// Body disagrees with the announced lengths / reserved bits set / a
    /// property not allowed for the packet type / an unknown reason code.
    MalformedPacket,
    /// A UTF-8 string field is not well-formed UTF-8 (or contains U+0000).
    InvalidUtf8,
    /// CONNECT protocol name is not "MQTT" or its level is not one the
    /// decoding version accepts.
    UnsupportedProtocol,
    /// Well-formed bytes that violate the protocol (e.g. wildcard in a
    /// PUBLISH topic name, spec 3.3.2.1; a repeated property; a zero
    /// Receive Maximum).
    ProtocolViolation,
};

// ── properties (5.0 spec 2.2.2) ─────────────────────────────────────────────

/// Property identifier (5.0 Table 2-4).
pub const PropertyId = enum(u8) {
    payload_format_indicator = 0x01,
    message_expiry_interval = 0x02,
    content_type = 0x03,
    response_topic = 0x08,
    correlation_data = 0x09,
    subscription_identifier = 0x0B,
    session_expiry_interval = 0x11,
    assigned_client_identifier = 0x12,
    server_keep_alive = 0x13,
    authentication_method = 0x15,
    authentication_data = 0x16,
    request_problem_information = 0x17,
    will_delay_interval = 0x18,
    request_response_information = 0x19,
    response_information = 0x1A,
    server_reference = 0x1C,
    reason_string = 0x1F,
    receive_maximum = 0x21,
    topic_alias_maximum = 0x22,
    topic_alias = 0x23,
    maximum_qos = 0x24,
    retain_available = 0x25,
    user_property = 0x26,
    maximum_packet_size = 0x27,
    wildcard_subscription_available = 0x28,
    subscription_identifier_available = 0x29,
    shared_subscription_available = 0x2A,
};

/// Where a property block sits — which identifiers it may hold (Table 2-4).
pub const PropertyContext = enum { connect, connack, publish, will, puback, pubrec, pubrel, pubcomp, subscribe, suback, unsubscribe, unsuback, disconnect, auth };

fn idMask(comptime ids: []const PropertyId) u64 {
    var m: u64 = 0;
    for (ids) |id| m |= @as(u64, 1) << @as(u6, @intCast(@intFromEnum(id)));
    return m;
}

fn allowedMask(ctx: PropertyContext) u64 {
    return switch (ctx) {
        .connect => comptime idMask(&.{ .session_expiry_interval, .receive_maximum, .maximum_packet_size, .topic_alias_maximum, .request_response_information, .request_problem_information, .user_property, .authentication_method, .authentication_data }),
        .connack => comptime idMask(&.{ .session_expiry_interval, .receive_maximum, .maximum_qos, .retain_available, .maximum_packet_size, .assigned_client_identifier, .topic_alias_maximum, .reason_string, .user_property, .wildcard_subscription_available, .subscription_identifier_available, .shared_subscription_available, .server_keep_alive, .response_information, .server_reference, .authentication_method, .authentication_data }),
        .publish => comptime idMask(&.{ .payload_format_indicator, .message_expiry_interval, .topic_alias, .response_topic, .correlation_data, .user_property, .subscription_identifier, .content_type }),
        .will => comptime idMask(&.{ .will_delay_interval, .payload_format_indicator, .message_expiry_interval, .content_type, .response_topic, .correlation_data, .user_property }),
        .puback, .pubrec, .pubrel, .pubcomp, .suback, .unsuback => comptime idMask(&.{ .reason_string, .user_property }),
        .subscribe => comptime idMask(&.{ .subscription_identifier, .user_property }),
        .unsubscribe => comptime idMask(&.{.user_property}),
        .disconnect => comptime idMask(&.{ .session_expiry_interval, .reason_string, .user_property, .server_reference }),
        .auth => comptime idMask(&.{ .authentication_method, .authentication_data, .reason_string, .user_property }),
    };
}

fn idAllowed(ctx: PropertyContext, id: PropertyId) bool {
    return allowedMask(ctx) & (@as(u64, 1) << @as(u6, @intCast(@intFromEnum(id)))) != 0;
}

/// Payload Format Indicator values (5.0 spec 3.3.2.3.2).
pub const PayloadFormat = enum(u8) {
    unspecified = 0,
    utf8 = 1,
};

/// One User Property: a name/value pair of UTF-8 strings (5.0 spec 1.5.7).
pub const UserProperty = struct { name: []const u8, value: []const u8 };

/// The User Properties of a packet: those an encoder writes (`items`), or
/// those a decoder found — then `raw` is the packet's whole validated
/// property block, and `iterator` picks the User Properties out of it in
/// wire order. An encoder writes the `raw` ones first, verbatim, then
/// `items`; that is how a server forwards them unaltered and in order
/// (§3.3.2-17/18) without copying them out.
pub const UserProperties = struct {
    items: []const UserProperty = &.{},
    raw: []const u8 = &.{},

    pub fn iterator(u: UserProperties) Iterator {
        return .{ .raw = .{ .rest = u.raw }, .items = u.items };
    }

    pub fn count(u: UserProperties) usize {
        var n: usize = 0;
        var it = u.iterator();
        while (it.next()) |_| n += 1;
        return n;
    }

    pub fn isEmpty(u: UserProperties) bool {
        var it = u.iterator();
        return it.next() == null;
    }

    pub const Iterator = struct {
        raw: RawIterator,
        items: []const UserProperty,
        i: usize = 0,

        pub fn next(it: *Iterator) ?UserProperty {
            while (it.raw.next()) |e| {
                if (e.id == @intFromEnum(PropertyId.user_property)) return .{ .name = e.a, .value = e.b };
            }
            if (it.i >= it.items.len) return null;
            it.i += 1;
            return it.items[it.i - 1];
        }
    };
};

/// The Subscription Identifiers of a packet (5.0 spec 3.3.2.3.8, 3.8.2.1.2):
/// at most one in a SUBSCRIBE, any number in a PUBLISH a server sends. Same
/// two-sided shape as `UserProperties`.
pub const SubscriptionIds = struct {
    items: []const u32 = &.{},
    raw: []const u8 = &.{},

    pub fn iterator(s: SubscriptionIds) Iterator {
        return .{ .raw = .{ .rest = s.raw }, .items = s.items };
    }

    pub fn count(s: SubscriptionIds) usize {
        var n: usize = 0;
        var it = s.iterator();
        while (it.next()) |_| n += 1;
        return n;
    }

    pub fn first(s: SubscriptionIds) ?u32 {
        var it = s.iterator();
        return it.next();
    }

    pub fn isEmpty(s: SubscriptionIds) bool {
        return s.first() == null;
    }

    pub const Iterator = struct {
        raw: RawIterator,
        items: []const u32,
        i: usize = 0,

        pub fn next(it: *Iterator) ?u32 {
            while (it.raw.next()) |e| {
                if (e.id == @intFromEnum(PropertyId.subscription_identifier)) return e.int;
            }
            if (it.i >= it.items.len) return null;
            it.i += 1;
            return it.items[it.i - 1];
        }
    };
};

/// The properties of one 5.0 packet (or Will). Every field is optional;
/// absent means the spec's default. Used both to encode and as decode output
/// (`UserProperties` / `SubscriptionIds` explain their two sides). A 3.1.1
/// packet has none: `isEmpty()`.
pub const Properties = struct {
    payload_format: ?PayloadFormat = null,
    /// Seconds (PUBLISH, Will).
    message_expiry_interval: ?u32 = null,
    content_type: ?[]const u8 = null,
    response_topic: ?[]const u8 = null,
    correlation_data: ?[]const u8 = null,
    subscription_ids: SubscriptionIds = .{},
    /// Seconds; 0xFFFFFFFF = never (CONNECT, CONNACK, DISCONNECT).
    session_expiry_interval: ?u32 = null,
    assigned_client_identifier: ?[]const u8 = null,
    server_keep_alive: ?u16 = null,
    authentication_method: ?[]const u8 = null,
    authentication_data: ?[]const u8 = null,
    request_problem_information: ?bool = null,
    /// Seconds (Will).
    will_delay_interval: ?u32 = null,
    request_response_information: ?bool = null,
    response_information: ?[]const u8 = null,
    server_reference: ?[]const u8 = null,
    reason_string: ?[]const u8 = null,
    receive_maximum: ?u16 = null,
    topic_alias_maximum: ?u16 = null,
    topic_alias: ?u16 = null,
    /// 0 or 1 only (CONNACK; absent = 2).
    maximum_qos: ?QoS = null,
    retain_available: ?bool = null,
    user_properties: UserProperties = .{},
    maximum_packet_size: ?u32 = null,
    wildcard_subscription_available: ?bool = null,
    subscription_identifier_available: ?bool = null,
    shared_subscription_available: ?bool = null,

    pub fn isEmpty(p: Properties) bool {
        inline for (@typeInfo(Properties).@"struct".fields) |f| {
            const v = @field(p, f.name);
            if (@typeInfo(f.type) == .optional) {
                if (v != null) return false;
            } else if (!v.isEmpty()) return false;
        }
        return true;
    }
};

/// One entry of an already-validated property block.
const RawEntry = struct {
    id: u8,
    /// Integer properties (byte / two / four byte / varint).
    int: u32 = 0,
    /// String and binary properties; the name of a User Property.
    a: []const u8 = &.{},
    /// The value of a User Property.
    b: []const u8 = &.{},
};

/// Walks a property block. Defensive like `Subscribe.Iterator`: anything it
/// cannot read ends the walk, so a hand-built `raw` cannot make it misbehave.
const RawIterator = struct {
    rest: []const u8,

    fn next(it: *RawIterator) ?RawEntry {
        var r = BodyReader{ .rest = it.rest };
        const e = readEntry(&r) catch {
            it.rest = &.{};
            return null;
        };
        it.rest = r.rest;
        return e;
    }

    /// One entry, type-checked by identifier but not validated for context.
    fn readEntry(r: *BodyReader) DecodeError!?RawEntry {
        if (r.rest.len == 0) return null;
        const raw_id = try r.varint();
        if (raw_id > 0x7F) return error.MalformedPacket;
        const id = std.enums.fromInt(PropertyId, raw_id) orelse return error.MalformedPacket;
        var e = RawEntry{ .id = @intFromEnum(id) };
        switch (id) {
            .payload_format_indicator, .request_problem_information, .request_response_information, .maximum_qos, .retain_available, .wildcard_subscription_available, .subscription_identifier_available, .shared_subscription_available => e.int = try r.byte(),
            .server_keep_alive, .receive_maximum, .topic_alias_maximum, .topic_alias => e.int = try r.u16be(),
            .message_expiry_interval, .session_expiry_interval, .will_delay_interval, .maximum_packet_size => e.int = try r.u32be(),
            .subscription_identifier => e.int = try r.varint(),
            .content_type, .response_topic, .assigned_client_identifier, .authentication_method, .response_information, .server_reference, .reason_string => e.a = try r.utf8String(),
            .correlation_data, .authentication_data => e.a = try r.lenPrefixed(),
            .user_property => {
                e.a = try r.utf8String();
                e.b = try r.utf8String();
            },
        }
        return e;
    }
};

fn boolByte(v: u32) DecodeError!bool {
    return switch (v) {
        0 => false,
        1 => true,
        else => error.ProtocolViolation,
    };
}

/// Decode and validate one property block (Property Length + properties).
fn decodeProperties(r: *BodyReader, ctx: PropertyContext) DecodeError!Properties {
    const len = try r.varint();
    if (r.rest.len < len) return error.MalformedPacket;
    const block = r.rest[0..len];
    r.rest = r.rest[len..];
    return decodeBlock(block, ctx);
}

/// Validate the entries of one property block and read them into `Properties`.
fn decodeBlock(block: []const u8, ctx: PropertyContext) DecodeError!Properties {
    var p = Properties{ .user_properties = .{ .raw = block }, .subscription_ids = .{ .raw = block } };
    var seen: u64 = 0;
    var br = BodyReader{ .rest = block };
    while (try RawIterator.readEntry(&br)) |e| {
        const id: PropertyId = @enumFromInt(e.id);
        // An identifier the packet type may not carry: Malformed (2.2.2.2).
        if (!idAllowed(ctx, id)) return error.MalformedPacket;
        const bit = @as(u64, 1) << @intCast(e.id);
        const repeatable = id == .user_property or (id == .subscription_identifier and ctx == .publish);
        if (seen & bit != 0 and !repeatable) return error.ProtocolViolation;
        seen |= bit;
        switch (id) {
            .payload_format_indicator => p.payload_format = switch (e.int) {
                0 => .unspecified,
                1 => .utf8,
                else => return error.ProtocolViolation,
            },
            .message_expiry_interval => p.message_expiry_interval = e.int,
            .content_type => p.content_type = e.a,
            .response_topic => {
                if (std.mem.indexOfAny(u8, e.a, "+#") != null) return error.ProtocolViolation; // 3.3.2-14
                p.response_topic = e.a;
            },
            .correlation_data => p.correlation_data = e.a,
            .subscription_identifier => if (e.int == 0) return error.ProtocolViolation, // 3.3.2.3.8
            .session_expiry_interval => p.session_expiry_interval = e.int,
            .assigned_client_identifier => p.assigned_client_identifier = e.a,
            .server_keep_alive => p.server_keep_alive = @intCast(e.int),
            .authentication_method => p.authentication_method = e.a,
            .authentication_data => p.authentication_data = e.a,
            .request_problem_information => p.request_problem_information = try boolByte(e.int),
            .will_delay_interval => p.will_delay_interval = e.int,
            .request_response_information => p.request_response_information = try boolByte(e.int),
            .response_information => p.response_information = e.a,
            .server_reference => p.server_reference = e.a,
            .reason_string => p.reason_string = e.a,
            .receive_maximum => {
                if (e.int == 0) return error.ProtocolViolation;
                p.receive_maximum = @intCast(e.int);
            },
            .topic_alias_maximum => p.topic_alias_maximum = @intCast(e.int),
            .topic_alias => {
                if (e.int == 0) return error.ProtocolViolation; // 3.3.2-8
                p.topic_alias = @intCast(e.int);
            },
            .maximum_qos => p.maximum_qos = switch (e.int) {
                0 => .at_most_once,
                1 => .at_least_once,
                else => return error.ProtocolViolation,
            },
            .retain_available => p.retain_available = try boolByte(e.int),
            .user_property => {},
            .maximum_packet_size => {
                if (e.int == 0) return error.ProtocolViolation;
                p.maximum_packet_size = e.int;
            },
            .wildcard_subscription_available => p.wildcard_subscription_available = try boolByte(e.int),
            .subscription_identifier_available => p.subscription_identifier_available = try boolByte(e.int),
            .shared_subscription_available => p.shared_subscription_available = try boolByte(e.int),
        }
    }
    // Authentication Data without an Authentication Method (3.1.2.11.10).
    if (p.authentication_data != null and p.authentication_method == null) return error.ProtocolViolation;
    return p;
}

/// The bytes `encodePropertyEntries` would write for `p` in `ctx`.
pub fn propertyEntriesLen(p: Properties, ctx: PropertyContext) EncodeError!usize {
    var counter = Cursor{ .buf = &.{}, .counting = true };
    try writePropertyEntries(&counter, p, ctx);
    return counter.pos;
}

/// Encode `p`'s entries for `ctx` without the Property Length in front — a
/// block `decodePropertyEntries` reads back. For keeping properties outside a
/// packet: a server storing a message's properties with it to forward later.
pub fn encodePropertyEntries(buf: []u8, p: Properties, ctx: PropertyContext) EncodeError![]const u8 {
    var cur = Cursor{ .buf = buf };
    try writePropertyEntries(&cur, p, ctx);
    return cur.done();
}

/// Decode and validate a block of property entries (no Property Length in
/// front), as `encodePropertyEntries` writes it. Slices point into `block`.
pub fn decodePropertyEntries(block: []const u8, ctx: PropertyContext) DecodeError!Properties {
    // The one validating decoder: what is stored is held to exactly what
    // arrives on the wire.
    return decodeBlock(block, ctx);
}

/// Write one property block: its length, then the entries.
fn writeProperties(cur: *Cursor, p: Properties, ctx: PropertyContext) EncodeError!void {
    var counter = Cursor{ .buf = &.{}, .counting = true };
    try writePropertyEntries(&counter, p, ctx);
    try cur.varint(try checkedRemaining(counter.pos));
    try writePropertyEntries(cur, p, ctx);
}

fn writePropertyEntries(cur: *Cursor, p: Properties, ctx: PropertyContext) EncodeError!void {
    const W = struct {
        fn head(c: *Cursor, x: PropertyContext, id: PropertyId) EncodeError!void {
            if (!idAllowed(x, id)) return error.InvalidProperty;
            try c.byte(@intFromEnum(id));
        }
    };
    if (p.payload_format) |v| {
        try W.head(cur, ctx, .payload_format_indicator);
        try cur.byte(@intFromEnum(v));
    }
    if (p.message_expiry_interval) |v| {
        try W.head(cur, ctx, .message_expiry_interval);
        try cur.u32be(v);
    }
    if (p.content_type) |v| {
        try W.head(cur, ctx, .content_type);
        try cur.utf8String(v);
    }
    if (p.response_topic) |v| {
        if (std.mem.indexOfAny(u8, v, "+#") != null) return error.InvalidProperty;
        try W.head(cur, ctx, .response_topic);
        try cur.utf8String(v);
    }
    if (p.correlation_data) |v| {
        try W.head(cur, ctx, .correlation_data);
        try cur.lenPrefixed(v);
    }
    {
        var n: usize = 0;
        var it = p.subscription_ids.iterator();
        while (it.next()) |v| {
            n += 1;
            if (n > 1 and ctx != .publish) return error.InvalidProperty;
            if (v == 0 or v > max_remaining_length) return error.InvalidProperty;
            try W.head(cur, ctx, .subscription_identifier);
            try cur.varint(v);
        }
    }
    if (p.session_expiry_interval) |v| {
        try W.head(cur, ctx, .session_expiry_interval);
        try cur.u32be(v);
    }
    if (p.assigned_client_identifier) |v| {
        try W.head(cur, ctx, .assigned_client_identifier);
        try cur.utf8String(v);
    }
    if (p.server_keep_alive) |v| {
        try W.head(cur, ctx, .server_keep_alive);
        try cur.u16be(v);
    }
    if (p.authentication_method) |v| {
        try W.head(cur, ctx, .authentication_method);
        try cur.utf8String(v);
    }
    if (p.authentication_data) |v| {
        if (p.authentication_method == null) return error.InvalidProperty;
        try W.head(cur, ctx, .authentication_data);
        try cur.lenPrefixed(v);
    }
    if (p.request_problem_information) |v| {
        try W.head(cur, ctx, .request_problem_information);
        try cur.byte(@intFromBool(v));
    }
    if (p.will_delay_interval) |v| {
        try W.head(cur, ctx, .will_delay_interval);
        try cur.u32be(v);
    }
    if (p.request_response_information) |v| {
        try W.head(cur, ctx, .request_response_information);
        try cur.byte(@intFromBool(v));
    }
    if (p.response_information) |v| {
        try W.head(cur, ctx, .response_information);
        try cur.utf8String(v);
    }
    if (p.server_reference) |v| {
        try W.head(cur, ctx, .server_reference);
        try cur.utf8String(v);
    }
    if (p.reason_string) |v| {
        try W.head(cur, ctx, .reason_string);
        try cur.utf8String(v);
    }
    if (p.receive_maximum) |v| {
        if (v == 0) return error.InvalidProperty;
        try W.head(cur, ctx, .receive_maximum);
        try cur.u16be(v);
    }
    if (p.topic_alias_maximum) |v| {
        try W.head(cur, ctx, .topic_alias_maximum);
        try cur.u16be(v);
    }
    if (p.topic_alias) |v| {
        if (v == 0) return error.InvalidProperty;
        try W.head(cur, ctx, .topic_alias);
        try cur.u16be(v);
    }
    if (p.maximum_qos) |v| {
        if (v == .exactly_once) return error.InvalidProperty;
        try W.head(cur, ctx, .maximum_qos);
        try cur.byte(@intFromEnum(v));
    }
    if (p.retain_available) |v| {
        try W.head(cur, ctx, .retain_available);
        try cur.byte(@intFromBool(v));
    }
    {
        var it = p.user_properties.iterator();
        while (it.next()) |u| {
            try W.head(cur, ctx, .user_property);
            try cur.utf8String(u.name);
            try cur.utf8String(u.value);
        }
    }
    if (p.maximum_packet_size) |v| {
        if (v == 0) return error.InvalidProperty;
        try W.head(cur, ctx, .maximum_packet_size);
        try cur.u32be(v);
    }
    if (p.wildcard_subscription_available) |v| {
        try W.head(cur, ctx, .wildcard_subscription_available);
        try cur.byte(@intFromBool(v));
    }
    if (p.subscription_identifier_available) |v| {
        try W.head(cur, ctx, .subscription_identifier_available);
        try cur.byte(@intFromBool(v));
    }
    if (p.shared_subscription_available) |v| {
        try W.head(cur, ctx, .shared_subscription_available);
        try cur.byte(@intFromBool(v));
    }
}

// ── packet payload types ────────────────────────────────────────────────────

/// Will message registered at connect time (spec 3.1.2.5–3.1.2.7).
pub const Will = struct {
    topic: []const u8,
    /// Application payload of the will; opaque bytes, not validated UTF-8.
    message: []const u8,
    qos: QoS = .at_most_once,
    retain: bool = false,
    /// Will Properties (5.0 only, spec 3.1.3.2).
    properties: Properties = .{},
};

/// CONNECT fields (spec 3.1). Used both to encode and as decode output.
pub const Connect = struct {
    /// May be empty only together with `clean_session` under 3.1.1 (spec
    /// 3.1.3.1); always may be empty under 5.0 (the server assigns one).
    client_id: []const u8,
    /// Clean Session in 3.1.1, Clean Start in 5.0.
    clean_session: bool = true,
    /// Keep-alive interval in seconds; 0 disables the mechanism.
    keep_alive_s: u16 = 0,
    will: ?Will = null,
    username: ?[]const u8 = null,
    /// Opaque binary data (spec 3.1.3.5), not validated as UTF-8.
    password: ?[]const u8 = null,
    /// The protocol level to send; on decode, the level the client sent.
    version: Version = .v3_1_1,
    /// CONNECT Properties (5.0 only).
    properties: Properties = .{},
};

/// CONNACK fields (spec 3.2). 3.1.1 carries `return_code`, 5.0 `reason_code`;
/// each version encodes its own field, and decoding fills both (the other
/// one by `reasonFromReturnCode` / `returnCodeFromReason`).
pub const Connack = struct {
    session_present: bool,
    return_code: ConnectReturnCode = .accepted,
    reason_code: ReasonCode = .success,
    properties: Properties = .{},
};

/// PUBLISH fields (spec 3.3). `packet_id` is meaningful only for QoS > 0.
pub const Publish = struct {
    /// Empty only in 5.0, with a `properties.topic_alias` standing for it.
    topic: []const u8,
    payload: []const u8 = &.{},
    qos: QoS = .at_most_once,
    retain: bool = false,
    dup: bool = false,
    packet_id: u16 = 0,
    properties: Properties = .{},
};

/// PUBACK / PUBREC / PUBREL / PUBCOMP (spec 3.4–3.7). 3.1.1 carries the
/// packet id only.
pub const Ack = struct {
    packet_id: u16,
    reason_code: ReasonCode = .success,
    properties: Properties = .{},
};

/// The 5.0 Retain Handling subscription option (spec 3.8.3.1).
pub const RetainHandling = enum(u2) {
    /// Send matching retained messages when the subscription is made.
    send_on_subscribe = 0,
    /// Send them only if the subscription did not exist before.
    send_if_new = 1,
    /// Never send them at subscribe time.
    never = 2,
};

/// One SUBSCRIBE entry: topic filter + requested QoS (spec 3.8.3), and in
/// 5.0 the other subscription options.
pub const Subscription = struct {
    filter: []const u8,
    qos: QoS = .at_most_once,
    /// 5.0: never deliver this client's own publishes back to it.
    no_local: bool = false,
    /// 5.0: keep the RETAIN flag a message was published with.
    retain_as_published: bool = false,
    /// 5.0: when to send retained messages at subscribe time.
    retain_handling: RetainHandling = .send_on_subscribe,

    fn optionsByte(s: Subscription) u8 {
        var b: u8 = @intFromEnum(s.qos);
        if (s.no_local) b |= 0x04;
        if (s.retain_as_published) b |= 0x08;
        b |= @as(u8, @intFromEnum(s.retain_handling)) << 4;
        return b;
    }

    fn hasOptions(s: Subscription) bool {
        return s.no_local or s.retain_as_published or s.retain_handling != .send_on_subscribe;
    }
};

/// SUBSCRIBE (spec 3.8). To encode, set `filters`; a decoded one carries the
/// validated `payload` instead. `iterator` walks whichever is set.
pub const Subscribe = struct {
    packet_id: u16,
    filters: []const Subscription = &.{},
    /// Raw validated payload bytes (filter/options pairs) of a decoded packet.
    payload: []const u8 = &.{},
    properties: Properties = .{},

    pub fn iterator(s: Subscribe) Iterator {
        return .{ .rest = s.payload, .filters = if (s.payload.len == 0) s.filters else &.{} };
    }

    pub const Iterator = struct {
        rest: []const u8,
        filters: []const Subscription = &.{},
        i: usize = 0,

        /// Defensive even on hand-built payloads: truncation ends iteration.
        pub fn next(it: *Iterator) ?Subscription {
            if (it.i < it.filters.len) {
                it.i += 1;
                return it.filters[it.i - 1];
            }
            if (it.rest.len < 2) return null;
            const len = std.mem.readInt(u16, it.rest[0..2], .big);
            if (it.rest.len < 3 + @as(usize, len)) {
                it.rest = &.{};
                return null;
            }
            const filter = it.rest[2 .. 2 + @as(usize, len)];
            const opts = it.rest[2 + @as(usize, len)];
            it.rest = it.rest[3 + @as(usize, len) ..];
            // A 3.1.1 payload validated to 0..2 reads as default options.
            const q = opts & 0x03;
            const rh = (opts >> 4) & 0x03;
            if (q > 2 or rh > 2 or opts & 0xC0 != 0) return null;
            return .{
                .filter = filter,
                .qos = @enumFromInt(@as(u2, @intCast(q))),
                .no_local = opts & 0x04 != 0,
                .retain_as_published = opts & 0x08 != 0,
                .retain_handling = @enumFromInt(@as(u2, @intCast(rh))),
            };
        }
    };
};

/// SUBACK (spec 3.9): one code per requested filter — 3.1.1: 0/1/2 granted
/// QoS or `suback_failure` (0x80); 5.0: a SUBACK reason code. Codes are
/// validated during decode.
pub const Suback = struct {
    packet_id: u16,
    codes: []const u8,
    properties: Properties = .{},
};

/// UNSUBSCRIBE (spec 3.10). Set `filters` to encode; a decoded one carries
/// the validated `payload`. `iterator` walks whichever is set.
pub const Unsubscribe = struct {
    packet_id: u16,
    filters: []const []const u8 = &.{},
    /// Raw validated payload bytes (length-prefixed topic filters).
    payload: []const u8 = &.{},
    properties: Properties = .{},

    pub fn iterator(u: Unsubscribe) Iterator {
        return .{ .rest = u.payload, .filters = if (u.payload.len == 0) u.filters else &.{} };
    }

    pub const Iterator = struct {
        rest: []const u8,
        filters: []const []const u8 = &.{},
        i: usize = 0,

        pub fn next(it: *Iterator) ?[]const u8 {
            if (it.i < it.filters.len) {
                it.i += 1;
                return it.filters[it.i - 1];
            }
            if (it.rest.len < 2) return null;
            const len = std.mem.readInt(u16, it.rest[0..2], .big);
            if (it.rest.len < 2 + @as(usize, len)) {
                it.rest = &.{};
                return null;
            }
            const filter = it.rest[2 .. 2 + @as(usize, len)];
            it.rest = it.rest[2 + @as(usize, len) ..];
            return filter;
        }
    };
};

/// UNSUBACK (spec 3.11). 5.0 adds one reason code per filter; 3.1.1 has none
/// (`codes` empty).
pub const Unsuback = struct {
    packet_id: u16,
    codes: []const u8 = &.{},
    properties: Properties = .{},
};

/// DISCONNECT (spec 3.14). 3.1.1 carries nothing.
pub const Disconnect = struct {
    reason_code: ReasonCode = .normal_disconnection,
    properties: Properties = .{},
};

/// AUTH (5.0 spec 3.15), extended authentication.
pub const Auth = struct {
    reason_code: ReasonCode = .success,
    properties: Properties = .{},
};

/// A control packet. Slice fields of a decoded one point into the decode
/// input.
pub const Packet = union(PacketType) {
    connect: Connect,
    connack: Connack,
    publish: Publish,
    puback: Ack,
    pubrec: Ack,
    pubrel: Ack,
    pubcomp: Ack,
    subscribe: Subscribe,
    suback: Suback,
    unsubscribe: Unsubscribe,
    unsuback: Unsuback,
    pingreq,
    pingresp,
    disconnect: Disconnect,
    auth: Auth,
};

// ── remaining-length varint (spec 2.2.3) ────────────────────────────────────

pub const RemainingLength = struct {
    value: u32,
    /// Number of varint bytes consumed (1–4).
    len: usize,
};

/// Encode `value` as a remaining-length varint; returns the byte count (1–4).
/// The same Variable Byte Integer encodes 5.0's property lengths and
/// Subscription Identifiers.
pub fn encodeRemainingLength(buf: *[4]u8, value: u32) error{PacketTooLarge}!usize {
    if (value > max_remaining_length) return error.PacketTooLarge;
    var v = value;
    var i: usize = 0;
    while (true) {
        var b: u8 = @intCast(v & 0x7F);
        v >>= 7;
        if (v != 0) b |= 0x80;
        buf[i] = b;
        i += 1;
        if (v == 0) return i;
    }
}

/// Decode a remaining-length varint. Returns `null` if `bytes` ends before
/// the varint does (need more data). Rejects encodings longer than 4 bytes
/// and overlong encodings (a trailing 0x00 continuation byte).
pub fn decodeRemainingLength(bytes: []const u8) DecodeError!?RemainingLength {
    var value: u32 = 0;
    var i: usize = 0;
    while (i < bytes.len and i < 4) : (i += 1) {
        const b = bytes[i];
        value |= @as(u32, b & 0x7F) << @intCast(7 * i);
        if (b & 0x80 == 0) {
            // Overlong guard: only a 1-byte encoding may end in 0x00.
            if (i > 0 and b == 0) return error.MalformedRemainingLength;
            return .{ .value = value, .len = i + 1 };
        }
    }
    if (i == 4) return error.MalformedRemainingLength;
    return null;
}

// ── shared field validation ─────────────────────────────────────────────────

/// MQTT UTF-8 string rules (spec 1.5.3): well-formed UTF-8 (which excludes
/// surrogate code points) and no U+0000.
pub fn wellFormedString(s: []const u8) bool {
    if (std.mem.indexOfScalar(u8, s, 0) != null) return false;
    return std.unicode.utf8ValidateSlice(s);
}

// ── encoding ────────────────────────────────────────────────────────────────

/// Bounds-checked byte cursor over the caller's output buffer. With
/// `counting` it writes nothing and only measures: the encoder runs every
/// packet body twice — once counting, for the length fields that precede
/// it, once writing — so a length can never disagree with what follows it.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,
    counting: bool = false,

    fn byte(c: *Cursor, b: u8) EncodeError!void {
        if (!c.counting) {
            if (c.pos >= c.buf.len) return error.BufferTooSmall;
            c.buf[c.pos] = b;
        }
        c.pos += 1;
    }

    fn u16be(c: *Cursor, v: u16) EncodeError!void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .big);
        try c.bytes(&tmp);
    }

    fn u32be(c: *Cursor, v: u32) EncodeError!void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, v, .big);
        try c.bytes(&tmp);
    }

    fn varint(c: *Cursor, v: u32) EncodeError!void {
        var tmp: [4]u8 = undefined;
        const n = try encodeRemainingLength(&tmp, v);
        try c.bytes(tmp[0..n]);
    }

    fn bytes(c: *Cursor, s: []const u8) EncodeError!void {
        if (!c.counting) {
            if (c.buf.len - c.pos < s.len) return error.BufferTooSmall;
            @memcpy(c.buf[c.pos..][0..s.len], s);
        }
        c.pos += s.len;
    }

    /// 2-byte length prefix + raw bytes (binary data, spec 1.5.3 framing).
    fn lenPrefixed(c: *Cursor, s: []const u8) EncodeError!void {
        if (s.len > max_string_len) return error.StringTooLong;
        try c.u16be(@intCast(s.len));
        try c.bytes(s);
    }

    /// Length-prefixed field that must also be a valid MQTT UTF-8 string.
    fn utf8String(c: *Cursor, s: []const u8) EncodeError!void {
        if (!wellFormedString(s)) return error.InvalidUtf8;
        try c.lenPrefixed(s);
    }

    fn fixedHeader(c: *Cursor, t: PacketType, flags: u4, remaining: u32) EncodeError!void {
        try c.byte(@as(u8, @intFromEnum(t)) << 4 | flags);
        try c.varint(remaining);
    }

    fn done(c: *const Cursor) []const u8 {
        return c.buf[0..c.pos];
    }
};

fn checkedRemaining(remaining: u64) EncodeError!u32 {
    if (remaining > max_remaining_length) return error.PacketTooLarge;
    return @intCast(remaining);
}

/// Fixed-header flag bits of `p` (spec 2.1.3).
fn fixedFlags(p: Packet) u4 {
    return switch (p) {
        .publish => |x| blk: {
            var flags: u4 = @as(u4, @intFromEnum(x.qos)) << 1;
            if (x.dup and x.qos != .at_most_once) flags |= 0x8;
            if (x.retain) flags |= 0x1;
            break :blk flags;
        },
        .pubrel, .subscribe, .unsubscribe => 0x2,
        else => 0,
    };
}

/// Encode `p` as a `version` packet into `buf`; returns the written slice.
///
/// Refuses (typed `EncodeError`, nothing written that matters) what the
/// version cannot express or the spec forbids a sender to put on the wire:
/// see `EncodeError`. A 5.0 PUBACK/PUBREC/PUBREL/PUBCOMP, DISCONNECT or AUTH
/// with reason success and no properties takes the short form the spec
/// allows (no reason code, no property length).
pub fn encodePacket(buf: []u8, version: Version, p: Packet) EncodeError![]const u8 {
    var counter = Cursor{ .buf = &.{}, .counting = true };
    try writeBody(&counter, version, p);
    const remaining = try checkedRemaining(counter.pos);
    var cur = Cursor{ .buf = buf };
    try cur.fixedHeader(std.meta.activeTag(p), fixedFlags(p), remaining);
    try writeBody(&cur, version, p);
    return cur.done();
}

/// Wire size of the packet `encodePacket` would produce for `p`, without a
/// buffer — so a sender can hold a message to a receiver's limit (5.0's
/// Maximum Packet Size, a broker's `max_packet_size`) before encoding it.
pub fn packetWireLen(version: Version, p: Packet) EncodeError!usize {
    var counter = Cursor{ .buf = &.{}, .counting = true };
    try writeBody(&counter, version, p);
    const rl = try checkedRemaining(counter.pos);
    var tmp: [4]u8 = undefined;
    const n = try encodeRemainingLength(&tmp, rl);
    return 1 + n + rl;
}

fn writeBody(cur: *Cursor, version: Version, p: Packet) EncodeError!void {
    const v5 = version == .v5;
    switch (p) {
        .connect => |c| try writeConnect(cur, c),
        .connack => |c| {
            try cur.byte(if (c.session_present) 1 else 0);
            if (v5) {
                if (!reasonAllowed(.connack, @intFromEnum(c.reason_code))) return error.InvalidReasonCode;
                try cur.byte(@intFromEnum(c.reason_code));
                try writeProperties(cur, c.properties, .connack);
            } else {
                if (!c.properties.isEmpty()) return error.UnsupportedInVersion;
                try cur.byte(@intFromEnum(c.return_code));
            }
        },
        .publish => |x| {
            if (x.qos != .at_most_once and x.packet_id == 0) return error.InvalidPacketId;
            if (!v5 and !x.properties.isEmpty()) return error.UnsupportedInVersion;
            if (x.topic.len == 0 and (!v5 or x.properties.topic_alias == null)) return error.InvalidTopic;
            try cur.utf8String(x.topic);
            if (x.qos != .at_most_once) try cur.u16be(x.packet_id);
            if (v5) try writeProperties(cur, x.properties, .publish);
            try cur.bytes(x.payload);
        },
        .puback => |a| try writeAck(cur, v5, a, .puback),
        .pubrec => |a| try writeAck(cur, v5, a, .pubrec),
        .pubrel => |a| try writeAck(cur, v5, a, .pubrel),
        .pubcomp => |a| try writeAck(cur, v5, a, .pubcomp),
        .subscribe => |s| {
            if (s.packet_id == 0) return error.InvalidPacketId;
            if (s.filters.len == 0) return error.EmptyTopicList;
            try cur.u16be(s.packet_id);
            if (v5) try writeProperties(cur, s.properties, .subscribe) else if (!s.properties.isEmpty()) return error.UnsupportedInVersion;
            for (s.filters) |f| {
                if (!v5 and f.hasOptions()) return error.UnsupportedInVersion;
                try cur.utf8String(f.filter);
                try cur.byte(f.optionsByte());
            }
        },
        .suback => |s| {
            if (s.packet_id == 0) return error.InvalidPacketId;
            if (s.codes.len == 0) return error.EmptyTopicList;
            for (s.codes) |code| {
                const ok = if (v5) reasonAllowed(.suback, code) else code <= 2 or code == suback_failure;
                if (!ok) return error.InvalidSubackCode;
            }
            try cur.u16be(s.packet_id);
            if (v5) try writeProperties(cur, s.properties, .suback) else if (!s.properties.isEmpty()) return error.UnsupportedInVersion;
            try cur.bytes(s.codes);
        },
        .unsubscribe => |u| {
            if (u.packet_id == 0) return error.InvalidPacketId;
            if (u.filters.len == 0) return error.EmptyTopicList;
            try cur.u16be(u.packet_id);
            if (v5) try writeProperties(cur, u.properties, .unsubscribe) else if (!u.properties.isEmpty()) return error.UnsupportedInVersion;
            for (u.filters) |f| try cur.utf8String(f);
        },
        .unsuback => |u| {
            if (u.packet_id == 0) return error.InvalidPacketId;
            try cur.u16be(u.packet_id);
            if (v5) {
                if (u.codes.len == 0) return error.EmptyTopicList;
                for (u.codes) |code| if (!reasonAllowed(.unsuback, code)) return error.InvalidReasonCode;
                try writeProperties(cur, u.properties, .unsuback);
                try cur.bytes(u.codes);
            } else if (u.codes.len != 0 or !u.properties.isEmpty()) return error.UnsupportedInVersion;
        },
        .pingreq, .pingresp => {},
        .disconnect => |d| try writeReasonOnly(cur, v5, d.reason_code, d.properties, .disconnect),
        .auth => |a| {
            if (!v5) return error.UnsupportedInVersion;
            try writeReasonOnly(cur, v5, a.reason_code, a.properties, .auth);
        },
    }
}

fn writeConnect(cur: *Cursor, c: Connect) EncodeError!void {
    const v5 = c.version == .v5;
    if (!v5) {
        if (c.password != null and c.username == null) return error.PasswordWithoutUsername;
        if (c.client_id.len == 0 and !c.clean_session) return error.InvalidClientId;
        if (!c.properties.isEmpty()) return error.UnsupportedInVersion;
        if (c.will) |w| if (!w.properties.isEmpty()) return error.UnsupportedInVersion;
    }
    try cur.lenPrefixed(protocol_name);
    try cur.byte(@intFromEnum(c.version));

    var flags: u8 = 0;
    if (c.clean_session) flags |= 0x02;
    if (c.will) |w| {
        flags |= 0x04 | @as(u8, @intFromEnum(w.qos)) << 3;
        if (w.retain) flags |= 0x20;
    }
    if (c.username != null) flags |= 0x80;
    if (c.password != null) flags |= 0x40;
    try cur.byte(flags);

    try cur.u16be(c.keep_alive_s);
    if (v5) try writeProperties(cur, c.properties, .connect);
    try cur.utf8String(c.client_id);
    if (c.will) |w| {
        if (v5) try writeProperties(cur, w.properties, .will);
        try cur.utf8String(w.topic);
        try cur.lenPrefixed(w.message);
    }
    if (c.username) |u| try cur.utf8String(u);
    if (c.password) |pw| try cur.lenPrefixed(pw);
}

fn writeAck(cur: *Cursor, v5: bool, a: Ack, comptime ctx: PropertyContext) EncodeError!void {
    if (a.packet_id == 0) return error.InvalidPacketId;
    try cur.u16be(a.packet_id);
    if (!v5) {
        if (a.reason_code != .success or !a.properties.isEmpty()) return error.UnsupportedInVersion;
        return;
    }
    const rctx: ReasonContext = @field(ReasonContext, @tagName(ctx));
    if (!reasonAllowed(rctx, @intFromEnum(a.reason_code))) return error.InvalidReasonCode;
    // Short forms (3.4.2.1): reason and property length may be omitted.
    if (a.properties.isEmpty()) {
        if (a.reason_code != .success) try cur.byte(@intFromEnum(a.reason_code));
        return;
    }
    try cur.byte(@intFromEnum(a.reason_code));
    try writeProperties(cur, a.properties, ctx);
}

/// DISCONNECT / AUTH: reason code + properties, both omittable (3.14.2.1,
/// 3.15.2.1). Under 3.1.1 (DISCONNECT only) nothing at all.
fn writeReasonOnly(cur: *Cursor, v5: bool, rc: ReasonCode, props: Properties, comptime ctx: PropertyContext) EncodeError!void {
    if (!v5) {
        if (rc != .success or !props.isEmpty()) return error.UnsupportedInVersion;
        return;
    }
    if (!reasonAllowed(@field(ReasonContext, @tagName(ctx)), @intFromEnum(rc))) return error.InvalidReasonCode;
    if (props.isEmpty()) {
        if (rc != .success) try cur.byte(@intFromEnum(rc));
        return;
    }
    try cur.byte(@intFromEnum(rc));
    try writeProperties(cur, props, ctx);
}

// ── 3.1.1 encoders (the API this codec always had) ──────────────────────────

/// Encode CONNECT at `c.version` (3.1.1 by default). Under 3.1.1 a password
/// without username is rejected (spec 3.1.2.22) and an empty client id
/// requires `clean_session`.
pub fn encodeConnect(buf: []u8, c: Connect) EncodeError![]const u8 {
    return encodePacket(buf, c.version, .{ .connect = c });
}

/// Encode a 3.1.1 CONNACK (spec 3.2) — mostly useful for test fakes and servers.
pub fn encodeConnack(buf: []u8, c: Connack) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .connack = c });
}

/// Wire size of the 3.1.1 PUBLISH `encodePublish` would produce for `p`,
/// without encoding it (and without needing a buffer that size).
///
/// Exists so a SENDER can hold its own message to the same limit a receiver
/// holds an inbound one to, before handing it to a fan-out that has no way to
/// report a per-subscriber encode failure back to it — `broker.zig`'s
/// `Broker.publish` (A1 mqtt M1). `error.PacketTooLarge` if the message
/// cannot be expressed as a PUBLISH at all. `packetWireLen` is the general form.
pub fn publishWireLen(p: Publish) EncodeError!usize {
    // The id's VALUE never changes the size, and a sender measuring before it
    // allocates an id has none yet.
    var sized = p;
    if (sized.qos != .at_most_once and sized.packet_id == 0) sized.packet_id = 1;
    return packetWireLen(.v3_1_1, .{ .publish = sized });
}

/// Encode a 3.1.1 PUBLISH (spec 3.3). QoS > 0 requires a nonzero
/// `packet_id`; the DUP flag is cleared for QoS 0 (spec 3.3.1.1).
pub fn encodePublish(buf: []u8, p: Publish) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .publish = p });
}

/// Encode a 3.1.1 PUBACK (spec 3.4).
pub fn encodePuback(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .puback = .{ .packet_id = packet_id } });
}

/// Encode a 3.1.1 PUBREC (spec 3.5).
pub fn encodePubrec(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .pubrec = .{ .packet_id = packet_id } });
}

/// Encode a 3.1.1 PUBREL (spec 3.6) — fixed-header flags are mandatorily 0b0010.
pub fn encodePubrel(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .pubrel = .{ .packet_id = packet_id } });
}

/// Encode a 3.1.1 PUBCOMP (spec 3.7).
pub fn encodePubcomp(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .pubcomp = .{ .packet_id = packet_id } });
}

/// Encode a 3.1.1 UNSUBACK (spec 3.11) — for test fakes and servers.
pub fn encodeUnsuback(buf: []u8, packet_id: u16) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .unsuback = .{ .packet_id = packet_id } });
}

/// Encode a 3.1.1 SUBSCRIBE (spec 3.8) — at least one filter is required.
pub fn encodeSubscribe(buf: []u8, packet_id: u16, filters: []const Subscription) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .subscribe = .{ .packet_id = packet_id, .filters = filters } });
}

/// Encode a 3.1.1 SUBACK (spec 3.9) — for test fakes and servers. Codes must
/// be 0, 1, 2 or `suback_failure` (0x80).
pub fn encodeSuback(buf: []u8, packet_id: u16, codes: []const u8) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .suback = .{ .packet_id = packet_id, .codes = codes } });
}

/// Encode a 3.1.1 UNSUBSCRIBE (spec 3.10) — at least one filter is required.
pub fn encodeUnsubscribe(buf: []u8, packet_id: u16, filters: []const []const u8) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .unsubscribe = .{ .packet_id = packet_id, .filters = filters } });
}

/// Encode PINGREQ (spec 3.12) — the same in both versions.
pub fn encodePingreq(buf: []u8) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .pingreq);
}

/// Encode PINGRESP (spec 3.13) — for test fakes and servers.
pub fn encodePingresp(buf: []u8) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .pingresp);
}

/// Encode DISCONNECT (spec 3.14) — the 3.1.1 form, which is also 5.0's
/// short form for a normal disconnection.
pub fn encodeDisconnect(buf: []u8) EncodeError![]const u8 {
    return encodePacket(buf, .v3_1_1, .{ .disconnect = .{} });
}

// ── decoding ────────────────────────────────────────────────────────────────

pub const Decoded = struct {
    packet: Packet,
    /// Total bytes consumed from the input (fixed header + body).
    consumed: usize,
};

/// Bounds-checked reader over a packet body.
const BodyReader = struct {
    rest: []const u8,

    fn byte(r: *BodyReader) DecodeError!u8 {
        if (r.rest.len < 1) return error.MalformedPacket;
        const b = r.rest[0];
        r.rest = r.rest[1..];
        return b;
    }

    fn u16be(r: *BodyReader) DecodeError!u16 {
        if (r.rest.len < 2) return error.MalformedPacket;
        const v = std.mem.readInt(u16, r.rest[0..2], .big);
        r.rest = r.rest[2..];
        return v;
    }

    fn u32be(r: *BodyReader) DecodeError!u32 {
        if (r.rest.len < 4) return error.MalformedPacket;
        const v = std.mem.readInt(u32, r.rest[0..4], .big);
        r.rest = r.rest[4..];
        return v;
    }

    /// A Variable Byte Integer inside a body: running out is Malformed, not
    /// "need more" — the body's length is already known.
    fn varint(r: *BodyReader) DecodeError!u32 {
        const v = (decodeRemainingLength(r.rest) catch return error.MalformedPacket) orelse return error.MalformedPacket;
        r.rest = r.rest[v.len..];
        return v.value;
    }

    fn lenPrefixed(r: *BodyReader) DecodeError![]const u8 {
        const len = try r.u16be();
        if (r.rest.len < len) return error.MalformedPacket;
        const s = r.rest[0..len];
        r.rest = r.rest[len..];
        return s;
    }

    fn utf8String(r: *BodyReader) DecodeError![]const u8 {
        const s = try r.lenPrefixed();
        if (!wellFormedString(s)) return error.InvalidUtf8;
        return s;
    }

    fn takeRest(r: *BodyReader) []const u8 {
        const s = r.rest;
        r.rest = &.{};
        return s;
    }

    fn expectEmpty(r: *const BodyReader) DecodeError!void {
        if (r.rest.len != 0) return error.MalformedPacket;
    }
};

fn nonzeroId(id: u16) DecodeError!u16 {
    if (id == 0) return error.MalformedPacket;
    return id;
}

/// Decode one 3.1.1 control packet from the front of `bytes` — the form this
/// codec always had; `decodePacket(bytes, .v3_1_1)`.
///
/// Returns `null` when `bytes` does not yet hold a complete packet (read
/// more from the stream and retry). On success `consumed` is the packet's
/// total wire size; slice fields of the packet point into `bytes`.
pub fn decode(bytes: []const u8) DecodeError!?Decoded {
    return decodePacket(bytes, .v3_1_1);
}

/// Decode one control packet of a `version` connection from the front of
/// `bytes`; `null` = need more bytes.
///
/// A CONNECT is the one packet whose layout its own bytes announce: under
/// `.v5` one of either level decodes (and says which in `Connect.version`),
/// which is how a server reads the first packet of a connection whose version
/// it does not know yet. Under `.v3_1_1` only level 4 does.
pub fn decodePacket(bytes: []const u8, version: Version) DecodeError!?Decoded {
    if (bytes.len < 1) return null;
    const b0 = bytes[0];
    const type_raw: u8 = b0 >> 4;
    const max_type: u8 = if (version == .v5) 15 else 14;
    if (type_raw < 1 or type_raw > max_type) return error.UnknownPacketType;
    const ptype: PacketType = @enumFromInt(type_raw);
    const flags: u4 = @truncate(b0);

    const rl = try decodeRemainingLength(bytes[1..]) orelse return null;
    const total: usize = 1 + rl.len + @as(usize, rl.value);
    if (bytes.len < total) return null;
    const body = bytes[1 + rl.len ..][0..rl.value];

    return .{ .packet = try decodeBody(version, ptype, flags, body), .consumed = total };
}

fn decodeBody(version: Version, ptype: PacketType, flags: u4, body: []const u8) DecodeError!Packet {
    // Fixed-header flag bits are mandated per type (spec 2.2.2, table 2.2).
    switch (ptype) {
        .publish => {},
        .pubrel, .subscribe, .unsubscribe => if (flags != 0x2) return error.InvalidFlags,
        else => if (flags != 0) return error.InvalidFlags,
    }

    const v5 = version == .v5;
    var r = BodyReader{ .rest = body };
    switch (ptype) {
        .connect => return .{ .connect = try decodeConnect(&r, version) },
        .connack => {
            const ack_flags = try r.byte();
            if (ack_flags & 0xFE != 0) return error.MalformedPacket;
            const rc = try r.byte();
            if (v5) {
                if (!reasonAllowed(.connack, rc)) return error.MalformedPacket;
                const reason: ReasonCode = @enumFromInt(rc);
                const props = try decodeProperties(&r, .connack);
                try r.expectEmpty();
                return .{ .connack = .{
                    .session_present = ack_flags & 0x1 != 0,
                    .return_code = returnCodeFromReason(reason),
                    .reason_code = reason,
                    .properties = props,
                } };
            }
            if (rc > 5) return error.MalformedPacket;
            try r.expectEmpty();
            const code: ConnectReturnCode = @enumFromInt(rc);
            return .{ .connack = .{
                .session_present = ack_flags & 0x1 != 0,
                .return_code = code,
                .reason_code = reasonFromReturnCode(code),
            } };
        },
        .publish => return .{ .publish = try decodePublish(&r, flags, v5) },
        .puback => return .{ .puback = try decodeAck(&r, v5, .puback) },
        .pubrec => return .{ .pubrec = try decodeAck(&r, v5, .pubrec) },
        .pubrel => return .{ .pubrel = try decodeAck(&r, v5, .pubrel) },
        .pubcomp => return .{ .pubcomp = try decodeAck(&r, v5, .pubcomp) },
        .subscribe => {
            const id = try nonzeroId(try r.u16be());
            const props: Properties = if (v5) try decodeProperties(&r, .subscribe) else .{};
            const payload = r.takeRest();
            if (payload.len == 0) return error.ProtocolViolation; // spec 3.8.3-3
            var v = BodyReader{ .rest = payload };
            while (v.rest.len > 0) {
                const f = try v.utf8String();
                if (f.len == 0) return error.MalformedPacket;
                const opts = try v.byte();
                if (!v5) {
                    if (opts > 2) return error.InvalidQos;
                    continue;
                }
                if (opts & 0xC0 != 0) return error.MalformedPacket; // 3.8.3-5
                if (opts & 0x03 == 3) return error.ProtocolViolation; // QoS 3
                if ((opts >> 4) & 0x03 == 3) return error.ProtocolViolation; // Retain Handling 3
                // No Local on a Shared Subscription (3.8.3-4).
                if (opts & 0x04 != 0 and std.mem.startsWith(u8, f, "$share/")) return error.ProtocolViolation;
            }
            return .{ .subscribe = .{ .packet_id = id, .payload = payload, .properties = props } };
        },
        .suback => {
            const id = try nonzeroId(try r.u16be());
            const props: Properties = if (v5) try decodeProperties(&r, .suback) else .{};
            const codes = r.takeRest();
            if (codes.len == 0) return error.MalformedPacket;
            for (codes) |code| {
                const ok = if (v5) reasonAllowed(.suback, code) else code <= 2 or code == suback_failure;
                if (!ok) return error.MalformedPacket;
            }
            return .{ .suback = .{ .packet_id = id, .codes = codes, .properties = props } };
        },
        .unsubscribe => {
            const id = try nonzeroId(try r.u16be());
            const props: Properties = if (v5) try decodeProperties(&r, .unsubscribe) else .{};
            const payload = r.takeRest();
            if (payload.len == 0) return error.ProtocolViolation; // spec 3.10.3-2
            var v = BodyReader{ .rest = payload };
            while (v.rest.len > 0) {
                const f = try v.utf8String();
                if (f.len == 0) return error.MalformedPacket;
            }
            return .{ .unsubscribe = .{ .packet_id = id, .payload = payload, .properties = props } };
        },
        .unsuback => {
            const id = try nonzeroId(try r.u16be());
            if (!v5) {
                try r.expectEmpty();
                return .{ .unsuback = .{ .packet_id = id } };
            }
            const props = try decodeProperties(&r, .unsuback);
            const codes = r.takeRest();
            if (codes.len == 0) return error.MalformedPacket;
            for (codes) |code| if (!reasonAllowed(.unsuback, code)) return error.MalformedPacket;
            return .{ .unsuback = .{ .packet_id = id, .codes = codes, .properties = props } };
        },
        .pingreq => {
            try r.expectEmpty();
            return .pingreq;
        },
        .pingresp => {
            try r.expectEmpty();
            return .pingresp;
        },
        .disconnect => {
            if (!v5) {
                try r.expectEmpty();
                return .{ .disconnect = .{} };
            }
            const rr = try decodeReasonOnly(&r, .disconnect);
            return .{ .disconnect = .{ .reason_code = rr.code, .properties = rr.props } };
        },
        .auth => {
            const rr = try decodeReasonOnly(&r, .auth);
            return .{ .auth = .{ .reason_code = rr.code, .properties = rr.props } };
        },
    }
}

fn decodeAck(r: *BodyReader, v5: bool, comptime ctx: PropertyContext) DecodeError!Ack {
    const id = try nonzeroId(try r.u16be());
    if (!v5) {
        try r.expectEmpty();
        return .{ .packet_id = id };
    }
    // Remaining length 2: Success, no properties (3.4.2.1).
    if (r.rest.len == 0) return .{ .packet_id = id };
    const rc = try r.byte();
    if (!reasonAllowed(@field(ReasonContext, @tagName(ctx)), rc)) return error.MalformedPacket;
    // Remaining length 3: no Property Length, none.
    const props: Properties = if (r.rest.len == 0) .{} else try decodeProperties(r, ctx);
    try r.expectEmpty();
    return .{ .packet_id = id, .reason_code = @enumFromInt(rc), .properties = props };
}

fn decodeReasonOnly(r: *BodyReader, comptime ctx: PropertyContext) DecodeError!struct { code: ReasonCode, props: Properties } {
    if (r.rest.len == 0) return .{ .code = .success, .props = .{} };
    const rc = try r.byte();
    if (!reasonAllowed(@field(ReasonContext, @tagName(ctx)), rc)) return error.MalformedPacket;
    const props: Properties = if (r.rest.len == 0) .{} else try decodeProperties(r, ctx);
    try r.expectEmpty();
    return .{ .code = @enumFromInt(rc), .props = props };
}

fn decodeConnect(r: *BodyReader, version: Version) DecodeError!Connect {
    const name = try r.lenPrefixed();
    if (!std.mem.eql(u8, name, protocol_name)) return error.UnsupportedProtocol;
    const level = try r.byte();
    const sent: Version = switch (level) {
        4 => .v3_1_1,
        5 => if (version == .v5) .v5 else return error.UnsupportedProtocol,
        else => return error.UnsupportedProtocol,
    };
    const v5 = sent == .v5;

    const flags = try r.byte();
    if (flags & 0x01 != 0) return error.MalformedPacket; // reserved bit
    const clean_session = flags & 0x02 != 0;
    const will_flag = flags & 0x04 != 0;
    const will_qos_raw: u8 = (flags >> 3) & 0x3;
    const will_retain = flags & 0x20 != 0;
    const password_flag = flags & 0x40 != 0;
    const username_flag = flags & 0x80 != 0;
    if (will_qos_raw == 3) return error.InvalidQos;
    if (!will_flag and (will_qos_raw != 0 or will_retain)) return error.MalformedPacket;
    // 3.1.1 spec 3.1.2-22; 5.0 allows a password alone (3.1.2.9).
    if (!v5 and password_flag and !username_flag) return error.MalformedPacket;

    const keep_alive_s = try r.u16be();
    const props: Properties = if (v5) try decodeProperties(r, .connect) else .{};
    const client_id = try r.utf8String();
    // 3.1.1 spec 3.1.3-7; 5.0 lets the server assign an id either way (3.1.3-6).
    if (!v5 and client_id.len == 0 and !clean_session) return error.MalformedPacket;

    var will: ?Will = null;
    if (will_flag) {
        const will_props: Properties = if (v5) try decodeProperties(r, .will) else .{};
        const topic = try r.utf8String();
        if (topic.len == 0) return error.MalformedPacket;
        will = .{
            .topic = topic,
            .message = try r.lenPrefixed(),
            .qos = @enumFromInt(@as(u2, @intCast(will_qos_raw))),
            .retain = will_retain,
            .properties = will_props,
        };
    }
    const username = if (username_flag) try r.utf8String() else null;
    const password = if (password_flag) try r.lenPrefixed() else null;
    try r.expectEmpty();

    return .{
        .client_id = client_id,
        .clean_session = clean_session,
        .keep_alive_s = keep_alive_s,
        .will = will,
        .username = username,
        .password = password,
        .version = sent,
        .properties = props,
    };
}

fn decodePublish(r: *BodyReader, flags: u4, v5: bool) DecodeError!Publish {
    const qos_raw: u8 = (@as(u8, flags) >> 1) & 0x3;
    if (qos_raw == 3) return error.InvalidQos;
    const qos: QoS = @enumFromInt(@as(u2, @intCast(qos_raw)));
    const dup = flags & 0x8 != 0;
    const retain = flags & 0x1 != 0;
    if (dup and qos == .at_most_once) return error.MalformedPacket; // spec 3.3.1-2

    const topic = try r.utf8String();
    if (std.mem.indexOfAny(u8, topic, "+#") != null) return error.ProtocolViolation; // spec 3.3.2-2

    const packet_id = if (qos != .at_most_once) try nonzeroId(try r.u16be()) else 0;
    const props: Properties = if (v5) try decodeProperties(r, .publish) else .{};
    // An empty topic stands for a Topic Alias (5.0 3.3.2.1); without one, and
    // always in 3.1.1, it is not a topic at all.
    if (topic.len == 0) {
        if (!v5) return error.MalformedPacket;
        if (props.topic_alias == null) return error.ProtocolViolation;
    }
    return .{
        .topic = topic,
        .payload = r.takeRest(),
        .qos = qos,
        .retain = retain,
        .dup = dup,
        .packet_id = packet_id,
        .properties = props,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const testkit = @import("testkit");

test "remaining length: boundary values encode/decode exactly" {
    const cases = [_]struct { value: u32, bytes: []const u8 }{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 127, .bytes = &.{0x7F} },
        .{ .value = 128, .bytes = &.{ 0x80, 0x01 } },
        .{ .value = 16_383, .bytes = &.{ 0xFF, 0x7F } },
        .{ .value = 16_384, .bytes = &.{ 0x80, 0x80, 0x01 } },
        .{ .value = 2_097_151, .bytes = &.{ 0xFF, 0xFF, 0x7F } },
        .{ .value = 2_097_152, .bytes = &.{ 0x80, 0x80, 0x80, 0x01 } },
        .{ .value = 268_435_455, .bytes = &.{ 0xFF, 0xFF, 0xFF, 0x7F } },
    };
    for (cases) |case| {
        var buf: [4]u8 = undefined;
        const n = try encodeRemainingLength(&buf, case.value);
        try testing.expectEqualSlices(u8, case.bytes, buf[0..n]);
        const dec = (try decodeRemainingLength(case.bytes)).?;
        try testing.expectEqual(case.value, dec.value);
        try testing.expectEqual(case.bytes.len, dec.len);
    }
}

test "remaining length: malformed and incomplete" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.PacketTooLarge, encodeRemainingLength(&buf, 268_435_456));

    // 5-byte / 4-continuation-byte encodings are malformed.
    try testing.expectError(
        error.MalformedRemainingLength,
        decodeRemainingLength(&.{ 0x80, 0x80, 0x80, 0x80, 0x01 }),
    );
    try testing.expectError(
        error.MalformedRemainingLength,
        decodeRemainingLength(&.{ 0xFF, 0xFF, 0xFF, 0xFF }),
    );
    // Overlong encodings of small values are malformed.
    try testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0x80, 0x00 }));
    try testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0xFF, 0x80, 0x00 }));
    // Truncated varint: need more bytes.
    try testing.expectEqual(null, try decodeRemainingLength(&.{0x80}));
    try testing.expectEqual(null, try decodeRemainingLength(&.{ 0x80, 0x80, 0x80 }));
}

test "CONNECT: golden bytes with will + credentials (KAT)" {
    var buf: [64]u8 = undefined;
    const got = try encodeConnect(&buf, .{
        .client_id = "zl",
        .clean_session = true,
        .keep_alive_s = 60,
        .will = .{ .topic = "w/t", .message = "gone", .qos = .at_least_once, .retain = true },
        .username = "user",
        .password = "pass",
    });
    const expected = [_]u8{
        0x10, 0x25, // CONNECT, remaining length 37
        0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
        0x04, // protocol level 4
        0xEE, // user+pass+will retain+will qos1+will flag+clean session
        0x00, 0x3C, // keep-alive 60
        0x00, 0x02, 'z', 'l', // client id
        0x00, 0x03, 'w', '/', 't', // will topic
        0x00, 0x04, 'g', 'o', 'n', 'e', // will message
        0x00, 0x04, 'u', 's', 'e', 'r', // username
        0x00, 0x04, 'p', 'a', 's', 's', // password
    };
    try testing.expectEqualSlices(u8, &expected, got);

    // Round-trip: decode gives back every field.
    const dec = (try decode(got)).?;
    try testing.expectEqual(got.len, dec.consumed);
    const c = dec.packet.connect;
    try testing.expectEqualStrings("zl", c.client_id);
    try testing.expect(c.clean_session);
    try testing.expectEqual(@as(u16, 60), c.keep_alive_s);
    try testing.expectEqualStrings("w/t", c.will.?.topic);
    try testing.expectEqualStrings("gone", c.will.?.message);
    try testing.expectEqual(QoS.at_least_once, c.will.?.qos);
    try testing.expect(c.will.?.retain);
    try testing.expectEqualStrings("user", c.username.?);
    try testing.expectEqualSlices(u8, "pass", c.password.?);
}

test "CONNECT: validation" {
    var buf: [64]u8 = undefined;
    try testing.expectError(
        error.PasswordWithoutUsername,
        encodeConnect(&buf, .{ .client_id = "x", .password = "p" }),
    );
    try testing.expectError(
        error.InvalidClientId,
        encodeConnect(&buf, .{ .client_id = "", .clean_session = false }),
    );
    try testing.expectError(
        error.InvalidUtf8,
        encodeConnect(&buf, .{ .client_id = &.{ 0xFF, 0xFE } }),
    );
    try testing.expectError(error.BufferTooSmall, encodeConnect(buf[0..4], .{ .client_id = "x" }));

    // Decoding: wrong protocol name / level.
    var ok_buf: [32]u8 = undefined;
    const ok = try encodeConnect(&ok_buf, .{ .client_id = "x" });
    var bad: [32]u8 = undefined;
    @memcpy(bad[0..ok.len], ok);
    bad[4] = 'X'; // corrupt protocol name
    try testing.expectError(error.UnsupportedProtocol, decode(bad[0..ok.len]));
    @memcpy(bad[0..ok.len], ok);
    bad[8] = 3; // protocol level 3
    try testing.expectError(error.UnsupportedProtocol, decode(bad[0..ok.len]));
    @memcpy(bad[0..ok.len], ok);
    bad[9] |= 0x01; // reserved connect flag set
    try testing.expectError(error.MalformedPacket, decode(bad[0..ok.len]));

    // Password flag set without the username flag (spec 3.1.2-22). The
    // encoder can never produce this combination (it rejects it earlier, at
    // `encodeConnect` — see `PasswordWithoutUsername` above), so the decode
    // guard is only reachable from a hand-crafted wire frame. The frame below
    // is otherwise fully well-formed — a valid client id and a valid,
    // correctly-length-prefixed password with nothing left over — so a
    // missing/inverted guard would decode it successfully instead of
    // rejecting it; the failure can't come from anything else running out of
    // bytes.
    const password_without_username = [_]u8{
        0x10, 16, // CONNECT, remaining length 16
        0x00, 0x04, 'M', 'Q', 'T', 'T', // protocol name
        0x04, // protocol level 4
        0x40, // flags: password flag only (username flag clear)
        0x00, 0x00, // keep-alive 0
        0x00, 0x01, 'x', // client id "x"
        0x00, 0x01, 'p', // password "p"
    };
    try testing.expectError(error.MalformedPacket, decode(&password_without_username));
}

test "CONNACK: decode golden bytes and all return codes" {
    const dec = (try decode(&.{ 0x20, 0x02, 0x01, 0x00 })).?;
    try testing.expectEqual(@as(usize, 4), dec.consumed);
    try testing.expect(dec.packet.connack.session_present);
    try testing.expectEqual(ConnectReturnCode.accepted, dec.packet.connack.return_code);

    const codes = [_]ConnectReturnCode{
        .accepted,           .unacceptable_protocol_version, .identifier_rejected,
        .server_unavailable, .bad_username_or_password,      .not_authorized,
    };
    for (codes, 0..) |rc, i| {
        const d = (try decode(&.{ 0x20, 0x02, 0x00, @intCast(i) })).?;
        try testing.expectEqual(rc, d.packet.connack.return_code);
        try testing.expect(!d.packet.connack.session_present);
    }

    // rc > 5, reserved ack bits, bad fixed flags, wrong length → typed errors.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x02, 0x00, 0x06 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x02, 0x02, 0x00 }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x21, 0x02, 0x00, 0x00 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x20, 0x03, 0x00, 0x00, 0x00 }));

    // encodeConnack round-trips.
    var buf: [4]u8 = undefined;
    const enc = try encodeConnack(&buf, .{ .session_present = true, .return_code = .not_authorized });
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x02, 0x01, 0x05 }, enc);
}

test "PUBLISH: QoS 1 golden bytes + round-trip preserves packet id" {
    var buf: [32]u8 = undefined;
    const original = Publish{
        .topic = "a/b",
        .payload = "hi",
        .qos = .at_least_once,
        .packet_id = 10,
    };
    const got = try encodePublish(&buf, original);
    const expected = [_]u8{
        0x32, 0x09, // PUBLISH qos1, remaining length 9
        0x00, 0x03, 'a', '/', 'b', // topic
        0x00, 0x0A, // packet id 10
        'h', 'i', // payload
    };
    try testing.expectEqualSlices(u8, &expected, got);

    const dec = (try decode(got)).?;
    try testing.expectEqual(got.len, dec.consumed);
    const p = dec.packet.publish;
    try testing.expectEqualStrings(original.topic, p.topic);
    try testing.expectEqualSlices(u8, original.payload, p.payload);
    try testing.expectEqual(original.qos, p.qos);
    try testing.expectEqual(original.packet_id, p.packet_id);
    try testing.expectEqual(original.retain, p.retain);
    try testing.expectEqual(original.dup, p.dup);
}

test "PUBLISH: flags and malformed forms" {
    var buf: [32]u8 = undefined;
    // QoS 0: no packet id on the wire; DUP is normalized away.
    const q0 = try encodePublish(&buf, .{ .topic = "t", .payload = "x", .dup = true, .retain = true });
    try testing.expectEqualSlices(u8, &.{ 0x31, 0x04, 0x00, 0x01, 't', 'x' }, q0);

    // QoS > 0 requires a nonzero id.
    try testing.expectError(
        error.InvalidPacketId,
        encodePublish(&buf, .{ .topic = "t", .qos = .at_least_once }),
    );

    // Decode: QoS 3 is reserved.
    try testing.expectError(error.InvalidQos, decode(&.{ 0x36, 0x03, 0x00, 0x01, 't' }));
    // Decode: DUP with QoS 0 is malformed.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x38, 0x03, 0x00, 0x01, 't' }));
    // Decode: wildcard in a PUBLISH topic name is a protocol violation.
    try testing.expectError(error.ProtocolViolation, decode(&.{ 0x30, 0x03, 0x00, 0x01, '#' }));
    // Decode: zero packet id with QoS 1 is malformed.
    try testing.expectError(
        error.MalformedPacket,
        decode(&.{ 0x32, 0x05, 0x00, 0x01, 't', 0x00, 0x00 }),
    );
    // Decode: topic longer than the body.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x30, 0x02, 0x00, 0x09 }));
    // Decode: invalid UTF-8 topic.
    try testing.expectError(error.InvalidUtf8, decode(&.{ 0x30, 0x03, 0x00, 0x01, 0xFF }));
    // Decode: embedded U+0000 in topic.
    try testing.expectError(error.InvalidUtf8, decode(&.{ 0x30, 0x03, 0x00, 0x01, 0x00 }));
}

test "SUBSCRIBE: golden bytes + iterator round-trip" {
    var buf: [64]u8 = undefined;
    const got = try encodeSubscribe(&buf, 10, &.{
        .{ .filter = "a/b", .qos = .at_least_once },
        .{ .filter = "sport/#", .qos = .exactly_once },
    });
    const expected = [_]u8{
        0x82, 0x12, // SUBSCRIBE (flags 0b0010), remaining length 18
        0x00, 0x0A, // packet id 10
        0x00, 0x03, 'a', '/', 'b', 0x01, // "a/b" qos 1
        0x00, 0x07, 's', 'p', 'o', 'r', 't', '/', '#', 0x02, // "sport/#" qos 2
    };
    try testing.expectEqualSlices(u8, &expected, got);

    const dec = (try decode(got)).?;
    const s = dec.packet.subscribe;
    try testing.expectEqual(@as(u16, 10), s.packet_id);
    var it = s.iterator();
    const first = it.next().?;
    try testing.expectEqualStrings("a/b", first.filter);
    try testing.expectEqual(QoS.at_least_once, first.qos);
    const second = it.next().?;
    try testing.expectEqualStrings("sport/#", second.filter);
    try testing.expectEqual(QoS.exactly_once, second.qos);
    try testing.expectEqual(null, it.next());

    // Empty filter list / bad fixed flags / empty payload → typed errors.
    try testing.expectError(error.EmptyTopicList, encodeSubscribe(&buf, 10, &.{}));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x80, 0x02, 0x00, 0x0A }));
    try testing.expectError(error.ProtocolViolation, decode(&.{ 0x82, 0x02, 0x00, 0x0A }));
    // Requested QoS 3 in the payload.
    try testing.expectError(
        error.InvalidQos,
        decode(&.{ 0x82, 0x06, 0x00, 0x0A, 0x00, 0x01, 'a', 0x03 }),
    );
}

test "SUBACK: mixed granted QoS including 0x80 failure" {
    var buf: [16]u8 = undefined;
    const got = try encodeSuback(&buf, 10, &.{ 0x00, 0x01, 0x02, 0x80 });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x90, 0x06, 0x00, 0x0A, 0x00, 0x01, 0x02, 0x80 },
        got,
    );

    const dec = (try decode(got)).?;
    try testing.expectEqual(@as(u16, 10), dec.packet.suback.packet_id);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x80 }, dec.packet.suback.codes);

    // Invalid code on either side.
    try testing.expectError(error.InvalidSubackCode, encodeSuback(&buf, 10, &.{0x03}));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x90, 0x03, 0x00, 0x0A, 0x03 }));
    // No codes at all.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x90, 0x02, 0x00, 0x0A }));
}

test "UNSUBSCRIBE / UNSUBACK: round-trip" {
    var buf: [32]u8 = undefined;
    const got = try encodeUnsubscribe(&buf, 7, &.{ "a/b", "c" });
    try testing.expectEqualSlices(
        u8,
        &.{ 0xA2, 0x0A, 0x00, 0x07, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x01, 'c' },
        got,
    );
    const dec = (try decode(got)).?;
    var it = dec.packet.unsubscribe.iterator();
    try testing.expectEqualStrings("a/b", it.next().?);
    try testing.expectEqualStrings("c", it.next().?);
    try testing.expectEqual(null, it.next());

    var ubuf: [4]u8 = undefined;
    const ua = try encodeUnsuback(&ubuf, 7);
    try testing.expectEqualSlices(u8, &.{ 0xB0, 0x02, 0x00, 0x07 }, ua);
    try testing.expectEqual(@as(u16, 7), (try decode(ua)).?.packet.unsuback.packet_id);
}

test "PUBACK/PUBREC/PUBREL/PUBCOMP: golden bytes, flags, round-trip" {
    var buf: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x02, 0x00, 0x0A }, try encodePuback(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x50, 0x02, 0x00, 0x0A }, try encodePubrec(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x62, 0x02, 0x00, 0x0A }, try encodePubrel(&buf, 10));
    try testing.expectEqualSlices(u8, &.{ 0x70, 0x02, 0x00, 0x0A }, try encodePubcomp(&buf, 10));

    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x40, 0x02, 0x00, 0x0A })).?.packet.puback.packet_id);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x50, 0x02, 0x00, 0x0A })).?.packet.pubrec.packet_id);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x62, 0x02, 0x00, 0x0A })).?.packet.pubrel.packet_id);
    try testing.expectEqual(@as(u16, 10), (try decode(&.{ 0x70, 0x02, 0x00, 0x0A })).?.packet.pubcomp.packet_id);

    // PUBREL must carry flags 0b0010; PUBACK must carry 0.
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x60, 0x02, 0x00, 0x0A }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0x42, 0x02, 0x00, 0x0A }));
    // Zero packet id / wrong body length.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x40, 0x02, 0x00, 0x00 }));
    try testing.expectError(error.MalformedPacket, decode(&.{ 0x40, 0x03, 0x00, 0x0A, 0x00 }));
    try testing.expectError(error.InvalidPacketId, encodePuback(&buf, 0));
}

test "PINGREQ / PINGRESP / DISCONNECT: empty-body packets" {
    var buf: [2]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0xC0, 0x00 }, try encodePingreq(&buf));
    try testing.expectEqualSlices(u8, &.{ 0xD0, 0x00 }, try encodePingresp(&buf));
    try testing.expectEqualSlices(u8, &.{ 0xE0, 0x00 }, try encodeDisconnect(&buf));

    try testing.expect((try decode(&.{ 0xC0, 0x00 })).?.packet == .pingreq);
    try testing.expect((try decode(&.{ 0xD0, 0x00 })).?.packet == .pingresp);
    try testing.expect((try decode(&.{ 0xE0, 0x00 })).?.packet == .disconnect);

    // Non-empty body / nonzero flags are malformed.
    try testing.expectError(error.MalformedPacket, decode(&.{ 0xD0, 0x01, 0x00 }));
    try testing.expectError(error.InvalidFlags, decode(&.{ 0xC1, 0x00 }));
}

test "decode: unknown packet types and stream framing (null = need more)" {
    try testing.expectError(error.UnknownPacketType, decode(&.{ 0x00, 0x00 }));
    try testing.expectError(error.UnknownPacketType, decode(&.{ 0xF0, 0x00 }));

    try testing.expectEqual(null, try decode(&.{}));
    try testing.expectEqual(null, try decode(&.{0x20}));

    // Every strict prefix of a valid packet decodes to null, never an error.
    var buf: [64]u8 = undefined;
    const full = try encodeConnect(&buf, .{
        .client_id = "abc",
        .will = .{ .topic = "t", .message = "m" },
        .username = "u",
        .password = "p",
    });
    for (0..full.len) |cut| {
        try testing.expectEqual(null, try decode(full[0..cut]));
    }

    // Announced length longer than provided bytes: need more, not an error.
    try testing.expectEqual(null, try decode(&.{ 0x30, 0x7F, 0x00, 0x01 }));
}

test "decode: two packets back to back consume exactly one each" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += (try encodePuback(buf[pos..], 1)).len;
    pos += (try encodePingresp(buf[pos..])).len;
    const first = (try decode(buf[0..pos])).?;
    try testing.expectEqual(@as(u16, 1), first.packet.puback.packet_id);
    try testing.expectEqual(@as(usize, 4), first.consumed);
    const second = (try decode(buf[first.consumed..pos])).?;
    try testing.expect(second.packet == .pingresp);
}

test "decode: 1000-iteration garbage sweep never panics" {
    var prng = std.Random.DefaultPrng.init(0x6d717474); // "mqtt"
    const random = prng.random();
    var buf: [96]u8 = undefined;
    for (0..1000) |_| {
        const len = random.uintAtMost(usize, buf.len);
        random.bytes(buf[0..len]);
        // Any outcome (packet, null, typed error) is fine — just no panic.
        _ = decode(buf[0..len]) catch continue;
    }
    // Same sweep with a plausible fixed header in front.
    for (0..1000) |i| {
        const len = random.uintAtMost(usize, buf.len - 2);
        buf[0] = @as(u8, @intCast((i % 14) + 1)) << 4 | @as(u8, @intCast(i % 16));
        buf[1] = @intCast(len);
        random.bytes(buf[2..][0..len]);
        _ = decode(buf[0 .. 2 + len]) catch continue;
    }
}

// ── fuzz: control-packet decode off the wire, never panics ─────────────────
//
// `decode` is the first thing run on bytes read from a TCP (or WebSocket)
// stream to a broker — fully attacker-controlled, including the
// variable-length "remaining length" varint and every per-packet-type body
// (CONNECT's payload in particular has half a dozen optional, length-
// prefixed sub-fields). The manual PRNG sweep above predates the `Smith`
// harness convention this collection standardises on; this drives the same
// boundary through `std.testing.fuzz`, and advances over a stream the way a
// real reader loop would so back-to-back packets are exercised too.

/// Streams of control packets, in the format `Smith.slice` reads (see
/// `testkit.fuzz`).
///
/// ⭐ Built at run time by this file's own encoders rather than quoted: the
/// comment above says the harness "advances over a stream the way a real reader
/// loop would", and only real back-to-back packets make that true. Uniform
/// random octets are malformed at packet ONE with overwhelming probability —
/// the type nibble, the flags nibble, the remaining-length varint and every
/// length-prefixed sub-field all have to agree — so the multi-packet path had
/// no chance of being reached even by a harness that was fed something.
const StreamCorpus = struct {
    scratch: [512]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [20][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *StreamCorpus, frame: []const u8) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = head;
        self.used += head.len;
        self.n += 1;
    }

    fn pushHex(self: *StreamCorpus, comptime h: []const u8) void {
        var frame: [h.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&frame, h) catch unreachable;
        self.push(&frame);
    }

    fn build(self: *StreamCorpus) ![]const []const u8 {
        // ── streams the reader loop walks ───────────────────────────────────
        // The four-packet stream the aim canary below already uses.
        var n: usize = 0;
        n += (try encodePingreq(self.scratch[n..])).len;
        n += (try encodePublish(self.scratch[n..], .{ .topic = "a/b", .payload = "hi", .qos = .at_most_once })).len;
        n += (try encodeSubscribe(self.scratch[n..], 7, &.{.{ .filter = "a/#", .qos = .at_least_once }})).len;
        n += (try encodePingresp(self.scratch[n..])).len;
        self.push(self.scratch[0..n]);
        // The same stream one octet short: the `need more data` outcome.
        self.push(self.scratch[0 .. n - 1]);

        // The four QoS-2 acknowledgements back to back.
        n = 0;
        n += (try encodePuback(self.scratch[n..], 1)).len;
        n += (try encodePubrec(self.scratch[n..], 2)).len;
        n += (try encodePubrel(self.scratch[n..], 3)).len;
        n += (try encodePubcomp(self.scratch[n..], 4)).len;
        self.push(self.scratch[0..n]);

        n = 0;
        n += (try encodeSuback(self.scratch[n..], 7, &.{ 0, 1, 2, suback_failure })).len;
        n += (try encodeUnsuback(self.scratch[n..], 8)).len;
        n += (try encodeDisconnect(self.scratch[n..])).len;
        self.push(self.scratch[0..n]);

        // ── single packets with the fields a stream of pings never reaches ──
        // CONNECT with every optional sub-field present: will, username and
        // password are three more length-prefixed reads inside the payload.
        self.push(try encodeConnect(&self.scratch, .{
            .client_id = "zig-client",
            .clean_session = true,
            .keep_alive_s = 60,
            .will = .{ .topic = "a/will", .message = "bye", .qos = .at_least_once, .retain = true },
            .username = "user",
            .password = "pw",
        }));
        self.push(try encodeConnack(&self.scratch, .{ .session_present = true, .return_code = .accepted }));
        // PUBLISH at QoS 2, so the packet id is on the wire.
        self.push(try encodePublish(&self.scratch, .{
            .topic = "sensors/temp",
            .payload = "21.5",
            .qos = .exactly_once,
            .retain = true,
            .dup = true,
            .packet_id = 0x1234,
        }));
        self.push(try encodeUnsubscribe(&self.scratch, 9, &.{ "a/#", "b/+" }));

        // ── refusals, each named by the error it raises ─────────────────────
        self.pushHex("0000"); // UnknownPacketType: type 0
        self.pushHex("F000"); // UnknownPacketType: type 15
        self.pushHex("6000"); // InvalidFlags: PUBREL without the mandatory 0x2
        self.pushHex("30FFFFFFFF"); // MalformedRemainingLength: a fifth varint octet
        self.pushHex("2003000000"); // MalformedPacket: CONNACK with a trailing octet
        self.pushHex("20020006"); // MalformedPacket: CONNACK return code 6
        self.pushHex("20020200"); // MalformedPacket: reserved bits in the CONNACK flags
        self.pushHex("82020007"); // ProtocolViolation: SUBSCRIBE with no filters
        self.pushHex("30050002FFFE41"); // InvalidUtf8: a PUBLISH topic that is not UTF-8
        self.pushHex("00" ** 256); // a full buffer of zeroes

        return self.entries[0..self.n];
    }
};

test "fuzz: decode never panics on arbitrary bytes" {
    var corpus: StreamCorpus = .{};
    try testing.fuzz({}, fuzzDecode, .{ .corpus = try corpus.build() });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM.
    // And `len` here is not merely the end of the slice — it is the bound of
    // the loop, so `while (off < len)` never ran a single pass and `decode`
    // was **never called at all**, while the paragraph above promises a reader
    // loop over back-to-back packets. `check-fuzz-reach` only learned to see
    // that shape on 2026-09-07. Measured over the corpus above: **0 of 18
    // seeds reached `decode` and 0 packets were walked before, 18 of 18 and 18
    // packets after.**
    const len: usize = smith.slice(&buf);

    var off: usize = 0;
    var iterations: usize = 0;
    while (off < len and iterations < 64) : (iterations += 1) {
        const decoded = decode(buf[off..len]) catch return;
        const d = decoded orelse return; // need more data
        off += d.consumed;
    }
}

test "corpus: every stream seed reaches decode, and the packets walked are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets — built from the same `build()`, because a
    // guard measuring a different corpus is not a guard. `nonempty` is the
    // reach claim and the only check that catches a seed grown past the
    // 256-octet buffer, which `Smith.slice` reads back as the EMPTY one,
    // silently. `walked` is the number an empty input cannot produce, and it
    // is specifically the multi-packet advance this harness exists for.
    var corpus: StreamCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var walked: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var off: usize = 0;
        var iterations: usize = 0;
        while (off < len and iterations < 64) : (iterations += 1) {
            const decoded = decode(buf[off..len]) catch break;
            const d = decoded orelse break;
            off += d.consumed;
            walked += 1;
        }
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 18), walked);
}

/// Aim canary for `fuzzDecode`, and the reason it needs one: the harness above
/// advertises that it "advances over a stream the way a real reader loop
/// would", but 256 uniform random bytes are malformed at packet one with
/// overwhelming probability, so the multi-packet path was reached essentially
/// never. This drives the same loop over a stream of REAL back-to-back packets
/// and asserts it walked all of them — so if the walk stops working, or stops
/// being reached, a named test says so rather than the fuzzer silently
/// covering one byte.
fn walkStream(bytes: []const u8) !usize {
    var off: usize = 0;
    var count: usize = 0;
    while (off < bytes.len) {
        const decoded = try decode(bytes[off..]);
        const d = decoded orelse break;
        off += d.consumed;
        count += 1;
    }
    return count;
}

test "fuzzDecode's stream walk is reachable and correct on real back-to-back packets" {
    var buf: [512]u8 = undefined;
    var n: usize = 0;
    n += (try encodePingreq(buf[n..])).len;
    n += (try encodePublish(buf[n..], .{
        .topic = "a/b",
        .payload = "hi",
        .qos = .at_most_once,
    })).len;
    n += (try encodeSubscribe(buf[n..], 7, &.{.{ .filter = "a/#", .qos = .at_least_once }})).len;
    n += (try encodePingresp(buf[n..])).len;

    try testing.expectEqual(@as(usize, 4), try walkStream(buf[0..n]));

    // A truncated tail stops the walk cleanly rather than looping or erroring
    // — the `need more data` outcome the real reader loop depends on.
    try testing.expectEqual(@as(usize, 3), try walkStream(buf[0 .. n - 1]));

    // And the fuzz harness's own body over the same bytes reaches every one.
    var off: usize = 0;
    var walked: usize = 0;
    while (off < n) {
        const d = ((try decode(buf[off..n])) orelse break);
        off += d.consumed;
        walked += 1;
    }
    try testing.expectEqual(@as(usize, 4), walked);
}

// ── MQTT 5.0 ────────────────────────────────────────────────────────────────

fn expectRoundTrip5(buf: []u8, p: Packet) !Packet {
    const bytes = try encodePacket(buf, .v5, p);
    try testing.expectEqual(bytes.len, try packetWireLen(.v5, p));
    const dec = (try decodePacket(bytes, .v5)).?;
    try testing.expectEqual(bytes.len, dec.consumed);
    return dec.packet;
}

fn hex(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

test "v5 CONNECT: the variable header is byte-for-byte the spec's own example (Figure 3-6)" {
    // 5.0 §3.1.2.12: protocol name, level 5, flags 0xCE (user name, password,
    // will QoS 1, will, clean start), keep alive 10, properties: Session
    // Expiry Interval 10. Bytes copied from the figure, not from this encoder.
    const figure = hex("00044d51545405ce000a05110000000a");
    var buf: [64]u8 = undefined;
    const c = Connect{
        .client_id = "c",
        .clean_session = true,
        .keep_alive_s = 10,
        .will = .{ .topic = "w", .message = "m", .qos = .at_least_once },
        .username = "u",
        .password = "p",
        .version = .v5,
        .properties = .{ .session_expiry_interval = 10 },
    };
    const got = try encodeConnect(&buf, c);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x20 }, got[0..2]); // CONNECT, remaining 32
    try testing.expectEqualSlices(u8, &figure, got[2..][0..figure.len]);
    // Payload: client id, will properties (empty), will topic, will payload,
    // user name, password (§3.1.3-1 order).
    try testing.expectEqualSlices(u8, &hex("000163" ++ "00" ++ "000177" ++ "00016d" ++ "000175" ++ "000170"), got[2 + figure.len ..]);

    const back = (try decodePacket(got, .v5)).?.packet.connect;
    try testing.expectEqual(Version.v5, back.version);
    try testing.expectEqual(@as(?u32, 10), back.properties.session_expiry_interval);
    try testing.expectEqualStrings("w", back.will.?.topic);
    try testing.expectEqualStrings("p", back.password.?);
}

test "v5 CONNECT: level 5 decodes only under .v5; .v5 also reads a 3.1.1 CONNECT and says so" {
    var buf: [64]u8 = undefined;
    const v5 = try encodeConnect(&buf, .{ .client_id = "x", .version = .v5 });
    try testing.expectError(error.UnsupportedProtocol, decode(v5));
    var buf4: [64]u8 = undefined;
    const v4 = try encodeConnect(&buf4, .{ .client_id = "x" });
    try testing.expectEqual(Version.v3_1_1, (try decodePacket(v4, .v5)).?.packet.connect.version);
    try testing.expectEqual(Version.v5, (try decodePacket(v5, .v5)).?.packet.connect.version);
    // A 3.1.1 CONNECT read under .v5 still follows 3.1.1's rules.
    const bad = hex("10" ++ "10" ++ "00044d51545404" ++ "40" ++ "0000" ++ "000178" ++ "000170");
    try testing.expectError(error.MalformedPacket, decodePacket(&bad, .v5)); // password alone
}

test "v5 CONNECT: password without user name, and an empty client id without clean start, are 5.0-legal" {
    var buf: [64]u8 = undefined;
    const c = Connect{ .client_id = "", .clean_session = false, .password = "tok", .version = .v5 };
    const back = (try expectRoundTrip5(&buf, .{ .connect = c })).connect;
    try testing.expectEqualStrings("", back.client_id);
    try testing.expect(!back.clean_session);
    try testing.expectEqual(@as(?[]const u8, null), back.username);
    try testing.expectEqualStrings("tok", back.password.?);
    // Both still refused at 3.1.1.
    try testing.expectError(error.PasswordWithoutUsername, encodeConnect(&buf, .{ .client_id = "x", .password = "p" }));
    try testing.expectError(error.InvalidClientId, encodeConnect(&buf, .{ .client_id = "", .clean_session = false }));
}

test "v5 CONNECT + Will: every CONNECT and Will property round-trips" {
    var buf: [256]u8 = undefined;
    const c = Connect{
        .client_id = "dev",
        .keep_alive_s = 30,
        .version = .v5,
        .username = "u",
        .properties = .{
            .session_expiry_interval = 0xFFFF_FFFF,
            .receive_maximum = 20,
            .maximum_packet_size = 4096,
            .topic_alias_maximum = 8,
            .request_response_information = true,
            .request_problem_information = false,
            .user_properties = .{ .items = &.{ .{ .name = "site", .value = "A" }, .{ .name = "site", .value = "B" } } },
            .authentication_method = "SCRAM-SHA-256",
            .authentication_data = "client-first",
        },
        .will = .{
            .topic = "dev/status",
            .message = "gone",
            .qos = .exactly_once,
            .retain = true,
            .properties = .{
                .will_delay_interval = 5,
                .payload_format = .utf8,
                .message_expiry_interval = 60,
                .content_type = "text/plain",
                .response_topic = "dev/reply",
                .correlation_data = &.{ 0, 1, 2 },
                .user_properties = .{ .items = &.{.{ .name = "k", .value = "v" }} },
            },
        },
    };
    const back = (try expectRoundTrip5(&buf, .{ .connect = c })).connect;
    const p = back.properties;
    try testing.expectEqual(@as(?u32, 0xFFFF_FFFF), p.session_expiry_interval);
    try testing.expectEqual(@as(?u16, 20), p.receive_maximum);
    try testing.expectEqual(@as(?u32, 4096), p.maximum_packet_size);
    try testing.expectEqual(@as(?u16, 8), p.topic_alias_maximum);
    try testing.expectEqual(@as(?bool, true), p.request_response_information);
    try testing.expectEqual(@as(?bool, false), p.request_problem_information);
    try testing.expectEqualStrings("SCRAM-SHA-256", p.authentication_method.?);
    try testing.expectEqualStrings("client-first", p.authentication_data.?);
    // The same name twice is allowed, in order (§3.1.2.11.8).
    var it = p.user_properties.iterator();
    try testing.expectEqualStrings("A", it.next().?.value);
    try testing.expectEqualStrings("B", it.next().?.value);
    try testing.expectEqual(@as(?UserProperty, null), it.next());

    const w = back.will.?;
    try testing.expectEqual(QoS.exactly_once, w.qos);
    try testing.expect(w.retain);
    try testing.expectEqual(@as(?u32, 5), w.properties.will_delay_interval);
    try testing.expectEqual(@as(?PayloadFormat, .utf8), w.properties.payload_format);
    try testing.expectEqual(@as(?u32, 60), w.properties.message_expiry_interval);
    try testing.expectEqualStrings("text/plain", w.properties.content_type.?);
    try testing.expectEqualStrings("dev/reply", w.properties.response_topic.?);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, w.properties.correlation_data.?);
    try testing.expectEqual(@as(usize, 1), w.properties.user_properties.count());
}

test "v5 CONNACK: golden bytes, and every CONNACK property round-trips" {
    var buf: [256]u8 = undefined;
    const small = try encodePacket(&buf, .v5, .{ .connack = .{
        .session_present = true,
        .properties = .{ .receive_maximum = 20, .topic_alias_maximum = 10, .assigned_client_identifier = "x" },
    } });
    try testing.expectEqualSlices(u8, &hex("200d01000a120001782100142200" ++ "0a"), small);

    const all = Connack{
        .session_present = false,
        .reason_code = .not_authorized,
        .properties = .{
            .session_expiry_interval = 300,
            .receive_maximum = 64,
            .maximum_qos = .at_least_once,
            .retain_available = false,
            .maximum_packet_size = 8192,
            .assigned_client_identifier = "auto-1",
            .topic_alias_maximum = 16,
            .reason_string = "who are you",
            .user_properties = .{ .items = &.{.{ .name = "a", .value = "b" }} },
            .wildcard_subscription_available = true,
            .subscription_identifier_available = false,
            .shared_subscription_available = true,
            .server_keep_alive = 45,
            .response_information = "resp/",
            .server_reference = "other:1883",
            .authentication_method = "M",
            .authentication_data = "D",
        },
    };
    const back = (try expectRoundTrip5(&buf, .{ .connack = all })).connack;
    try testing.expectEqual(ReasonCode.not_authorized, back.reason_code);
    try testing.expectEqual(ConnectReturnCode.not_authorized, back.return_code); // mapped
    const p = back.properties;
    try testing.expectEqual(@as(?u32, 300), p.session_expiry_interval);
    try testing.expectEqual(@as(?u16, 64), p.receive_maximum);
    try testing.expectEqual(@as(?QoS, .at_least_once), p.maximum_qos);
    try testing.expectEqual(@as(?bool, false), p.retain_available);
    try testing.expectEqual(@as(?u32, 8192), p.maximum_packet_size);
    try testing.expectEqualStrings("auto-1", p.assigned_client_identifier.?);
    try testing.expectEqual(@as(?u16, 16), p.topic_alias_maximum);
    try testing.expectEqualStrings("who are you", p.reason_string.?);
    try testing.expectEqual(@as(usize, 1), p.user_properties.count());
    try testing.expectEqual(@as(?bool, true), p.wildcard_subscription_available);
    try testing.expectEqual(@as(?bool, false), p.subscription_identifier_available);
    try testing.expectEqual(@as(?bool, true), p.shared_subscription_available);
    try testing.expectEqual(@as(?u16, 45), p.server_keep_alive);
    try testing.expectEqualStrings("resp/", p.response_information.?);
    try testing.expectEqualStrings("other:1883", p.server_reference.?);
    try testing.expectEqualStrings("M", p.authentication_method.?);
    try testing.expectEqualStrings("D", p.authentication_data.?);

    // A 3.1.1 CONNACK decoded gets the 5.0 code too.
    try testing.expectEqual(ReasonCode.bad_user_name_or_password, (try decode(&.{ 0x20, 0x02, 0x00, 0x04 })).?.packet.connack.reason_code);
}

test "v5 PUBLISH: every PUBLISH property, repeated User Properties and Subscription Identifiers" {
    var buf: [256]u8 = undefined;
    const p = Publish{
        .topic = "a/b",
        .payload = "hi",
        .qos = .at_least_once,
        .packet_id = 9,
        .properties = .{
            .payload_format = .utf8,
            .message_expiry_interval = 120,
            .topic_alias = 4,
            .response_topic = "a/reply",
            .correlation_data = "cid",
            .content_type = "json",
            .subscription_ids = .{ .items = &.{ 1, 268_435_455 } },
            .user_properties = .{ .items = &.{ .{ .name = "x", .value = "1" }, .{ .name = "y", .value = "2" } } },
        },
    };
    const back = (try expectRoundTrip5(&buf, .{ .publish = p })).publish;
    try testing.expectEqualStrings("a/b", back.topic);
    try testing.expectEqualStrings("hi", back.payload);
    try testing.expectEqual(@as(u16, 9), back.packet_id);
    const q = back.properties;
    try testing.expectEqual(@as(?PayloadFormat, .utf8), q.payload_format);
    try testing.expectEqual(@as(?u32, 120), q.message_expiry_interval);
    try testing.expectEqual(@as(?u16, 4), q.topic_alias);
    try testing.expectEqualStrings("a/reply", q.response_topic.?);
    try testing.expectEqualStrings("cid", q.correlation_data.?);
    try testing.expectEqualStrings("json", q.content_type.?);
    var ids = q.subscription_ids.iterator();
    try testing.expectEqual(@as(?u32, 1), ids.next());
    try testing.expectEqual(@as(?u32, 268_435_455), ids.next());
    try testing.expectEqual(@as(?u32, null), ids.next());
    try testing.expectEqual(@as(usize, 2), q.user_properties.count());
}

test "v5 PUBLISH: a Topic Alias stands for an empty topic; nothing else may" {
    var buf: [32]u8 = undefined;
    const aliased = try encodePacket(&buf, .v5, .{ .publish = .{ .topic = "", .payload = "x", .properties = .{ .topic_alias = 3 } } });
    try testing.expectEqualSlices(u8, &hex("3007000003230003" ++ "78"), aliased);
    try testing.expectEqualStrings("", (try decodePacket(aliased, .v5)).?.packet.publish.topic);

    try testing.expectError(error.InvalidTopic, encodePacket(&buf, .v5, .{ .publish = .{ .topic = "" } }));
    try testing.expectError(error.InvalidTopic, encodePublish(&buf, .{ .topic = "" }));
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("300400000078"), .v5));
    try testing.expectError(error.MalformedPacket, decode(&hex("3003000078")));
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .publish = .{ .topic = "t", .properties = .{ .topic_alias = 0 } } }));
}

test "v5 forwarding: decoded User Properties re-encode verbatim and in order, before new ones" {
    var src_buf: [128]u8 = undefined;
    const src = try encodePacket(&src_buf, .v5, .{ .publish = .{
        .topic = "t",
        .payload = "p",
        .properties = .{
            .content_type = "c",
            .topic_alias = 2,
            .user_properties = .{ .items = &.{ .{ .name = "a", .value = "1" }, .{ .name = "b", .value = "2" } } },
        },
    } });
    const in = (try decodePacket(src, .v5)).?.packet.publish;
    // What a server sends on: same User Properties (the block, in place),
    // one more of its own, its own Subscription Identifiers — and NOT the
    // inbound Topic Alias, which belongs to the inbound connection.
    var out_buf: [128]u8 = undefined;
    const out = try encodePacket(&out_buf, .v5, .{ .publish = .{
        .topic = in.topic,
        .payload = in.payload,
        .properties = .{
            .content_type = in.properties.content_type,
            .user_properties = .{ .raw = in.properties.user_properties.raw, .items = &.{.{ .name = "c", .value = "3" }} },
            .subscription_ids = .{ .items = &.{7} },
        },
    } });
    const fwd = (try decodePacket(out, .v5)).?.packet.publish.properties;
    var it = fwd.user_properties.iterator();
    try testing.expectEqualStrings("a", it.next().?.name);
    try testing.expectEqualStrings("b", it.next().?.name);
    try testing.expectEqualStrings("c", it.next().?.name);
    try testing.expectEqual(@as(?UserProperty, null), it.next());
    try testing.expectEqual(@as(?u16, null), fwd.topic_alias);
    try testing.expectEqual(@as(?u32, 7), fwd.subscription_ids.first());
    try testing.expectEqualStrings("c", fwd.content_type.?);
}

test "v5 acks: short forms on the wire, every form decodes, reason codes checked per packet" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("4002000a"), try encodePacket(&buf, .v5, .{ .puback = .{ .packet_id = 10 } }));
    try testing.expectEqualSlices(u8, &hex("4003000a10"), try encodePacket(&buf, .v5, .{ .puback = .{ .packet_id = 10, .reason_code = .no_matching_subscribers } }));
    try testing.expectEqualSlices(u8, &hex("4009000a87051f00026e6f"), try encodePacket(&buf, .v5, .{ .puback = .{
        .packet_id = 10,
        .reason_code = .not_authorized,
        .properties = .{ .reason_string = "no" },
    } }));
    try testing.expectEqualSlices(u8, &hex("6203000a92"), try encodePacket(&buf, .v5, .{ .pubrel = .{ .packet_id = 10, .reason_code = .packet_identifier_not_found } }));

    // Decode: length 2, 3 and 4 (reason + empty property length) all mean what they say.
    try testing.expectEqual(ReasonCode.success, (try decodePacket(&hex("5002000a"), .v5)).?.packet.pubrec.reason_code);
    try testing.expectEqual(ReasonCode.quota_exceeded, (try decodePacket(&hex("5003000a97"), .v5)).?.packet.pubrec.reason_code);
    try testing.expectEqual(ReasonCode.success, (try decodePacket(&hex("7004000a0000"), .v5)).?.packet.pubcomp.reason_code);
    const full = (try decodePacket(&hex("4009000a87051f00026e6f"), .v5)).?.packet.puback;
    try testing.expectEqualStrings("no", full.properties.reason_string.?);

    // A code that packet may not carry: PUBREL "no matching subscribers".
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("6203000a10"), .v5));
    try testing.expectError(error.InvalidReasonCode, encodePacket(&buf, .v5, .{ .pubrel = .{ .packet_id = 1, .reason_code = .no_matching_subscribers } }));
    // A property an ack may not carry.
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("4007000a00030b0101"), .v5));
    // 3.1.1 has no room for any of it.
    try testing.expectError(error.UnsupportedInVersion, encodePacket(&buf, .v3_1_1, .{ .puback = .{ .packet_id = 1, .reason_code = .no_matching_subscribers } }));
    try testing.expectError(error.MalformedPacket, decode(&hex("4003000a10")));
}

test "v5 DISCONNECT and AUTH: every form, and AUTH is not a 3.1.1 packet" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("e000"), try encodePacket(&buf, .v5, .{ .disconnect = .{} }));
    try testing.expectEqualSlices(u8, &hex("e0018e"), try encodePacket(&buf, .v5, .{ .disconnect = .{ .reason_code = .session_taken_over } }));
    try testing.expectEqualSlices(u8, &hex("e00700051100000000"), try encodePacket(&buf, .v5, .{ .disconnect = .{ .properties = .{ .session_expiry_interval = 0 } } }));
    try testing.expectEqual(ReasonCode.keep_alive_timeout, (try decodePacket(&hex("e0018d"), .v5)).?.packet.disconnect.reason_code);
    try testing.expectEqual(ReasonCode.disconnect_with_will_message, (try decodePacket(&hex("e0020400"), .v5)).?.packet.disconnect.reason_code);
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("e00110"), .v5)); // 0x10 is not a DISCONNECT code
    try testing.expectError(error.MalformedPacket, decode(&hex("e0018e"))); // 3.1.1 DISCONNECT is empty

    try testing.expectEqualSlices(u8, &hex("f000"), try encodePacket(&buf, .v5, .{ .auth = .{} }));
    const auth = try encodePacket(&buf, .v5, .{ .auth = .{ .reason_code = .continue_authentication, .properties = .{ .authentication_method = "SCRAM" } } });
    try testing.expectEqualSlices(u8, &hex("f00a1808150005534352414d"), auth);
    try testing.expectEqualStrings("SCRAM", (try decodePacket(auth, .v5)).?.packet.auth.properties.authentication_method.?);
    try testing.expectError(error.UnknownPacketType, decode(&hex("f000")));
    try testing.expectError(error.UnsupportedInVersion, encodePacket(&buf, .v3_1_1, .{ .auth = .{} }));
    try testing.expectError(error.InvalidFlags, decodePacket(&hex("f100"), .v5));
}

test "v5 SUBSCRIBE: subscription options on the wire and every refusal" {
    var buf: [64]u8 = undefined;
    const got = try encodePacket(&buf, .v5, .{ .subscribe = .{
        .packet_id = 10,
        .filters = &.{.{ .filter = "a/b", .qos = .at_least_once, .no_local = true, .retain_as_published = true, .retain_handling = .send_if_new }},
        .properties = .{ .subscription_ids = .{ .items = &.{5} } },
    } });
    try testing.expectEqualSlices(u8, &hex("820b000a020b050003612f621d"), got);
    const s = (try decodePacket(got, .v5)).?.packet.subscribe;
    try testing.expectEqual(@as(?u32, 5), s.properties.subscription_ids.first());
    var it = s.iterator();
    const f = it.next().?;
    try testing.expectEqualStrings("a/b", f.filter);
    try testing.expectEqual(QoS.at_least_once, f.qos);
    try testing.expect(f.no_local and f.retain_as_published);
    try testing.expectEqual(RetainHandling.send_if_new, f.retain_handling);

    try testing.expectError(error.MalformedPacket, decodePacket(&hex("8207000a0000016140"), .v5)); // reserved bit 6
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("8207000a0000016130"), .v5)); // Retain Handling 3
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("8207000a0000016103"), .v5)); // QoS 3
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("8210000a00000a2473686172652f672f7404"), .v5)); // No Local on $share
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("820b000a040b010b0200016100"), .v5)); // two Subscription Identifiers
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("8209000a020b0000016100"), .v5)); // Subscription Identifier 0
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .subscribe = .{
        .packet_id = 1,
        .filters = &.{.{ .filter = "a" }},
        .properties = .{ .subscription_ids = .{ .items = &.{ 1, 2 } } },
    } }));
    try testing.expectError(error.UnsupportedInVersion, encodePacket(&buf, .v3_1_1, .{ .subscribe = .{ .packet_id = 1, .filters = &.{.{ .filter = "a", .no_local = true }} } }));
}

test "v5 SUBACK and UNSUBACK: reason codes per filter" {
    var buf: [32]u8 = undefined;
    const sa = try encodePacket(&buf, .v5, .{ .suback = .{ .packet_id = 10, .codes = &.{ 0x00, 0x01, 0x02, 0x80, 0x8F, 0x9E } } });
    try testing.expectEqualSlices(u8, &hex("9009000a00000102808f9e"), sa);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x80, 0x8F, 0x9E }, (try decodePacket(sa, .v5)).?.packet.suback.codes);
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("9004000a0010"), .v5)); // 0x10 not a SUBACK code
    try testing.expectError(error.InvalidSubackCode, encodePacket(&buf, .v5, .{ .suback = .{ .packet_id = 1, .codes = &.{0x10} } }));
    try testing.expectError(error.InvalidSubackCode, encodeSuback(&buf, 1, &.{0x8F})); // 3.1.1: 0/1/2/0x80 only

    const ua = try encodePacket(&buf, .v5, .{ .unsuback = .{ .packet_id = 7, .codes = &.{ 0x00, 0x11 } } });
    try testing.expectEqualSlices(u8, &hex("b00500070000" ++ "11"), ua);
    const u = (try decodePacket(ua, .v5)).?.packet.unsuback;
    try testing.expectEqual(@as(u16, 7), u.packet_id);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x11 }, u.codes);
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("b003000700"), .v5)); // no codes
    try testing.expectError(error.EmptyTopicList, encodePacket(&buf, .v5, .{ .unsuback = .{ .packet_id = 7 } }));
    try testing.expectError(error.UnsupportedInVersion, encodePacket(&buf, .v3_1_1, .{ .unsuback = .{ .packet_id = 7, .codes = &.{0} } }));
}

test "v5 properties: wrong packet is Malformed, a repeat or a forbidden value is a Protocol Error" {
    // §2.2.2.2: an identifier not valid for the packet type is Malformed.
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("2006000003230001"), .v5)); // Topic Alias in CONNACK
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("20050000027f00"), .v5)); // unknown identifier
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("2006000003800100"), .v5)); // two-byte identifier
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("200400000521"), .v5)); // length past the body
    try testing.expectError(error.MalformedPacket, decodePacket(&hex("200500000221" ++ "00"), .v5)); // value cut short
    // "It is a Protocol Error to include ... more than once" / "... to have the value 0".
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("200900000621000121" ++ "0002"), .v5));
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("2006000003210000"), .v5)); // Receive Maximum 0
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("200800000527" ++ "00000000"), .v5)); // Maximum Packet Size 0
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("20050000022402"), .v5)); // Maximum QoS 2
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("20050000022502"), .v5)); // Retain Available 2
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("200700000416000141"), .v5)); // Data without Method
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("30060001740201" ++ "02"), .v5)); // Payload Format 2
    try testing.expectError(error.ProtocolViolation, decodePacket(&hex("3009000174040800012378"), .v5)); // wildcard Response Topic
    try testing.expectError(error.InvalidUtf8, decodePacket(&hex("20080000051f0002fffe"), .v5)); // Reason String not UTF-8

    // Encoding holds the sender to the same table.
    var buf: [64]u8 = undefined;
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .connack = .{ .session_present = false, .properties = .{ .topic_alias = 1 } } }));
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .connack = .{ .session_present = false, .properties = .{ .receive_maximum = 0 } } }));
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .connack = .{ .session_present = false, .properties = .{ .maximum_qos = .exactly_once } } }));
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .connack = .{ .session_present = false, .properties = .{ .authentication_data = "d" } } }));
    try testing.expectError(error.InvalidProperty, encodePacket(&buf, .v5, .{ .publish = .{ .topic = "t", .properties = .{ .response_topic = "a/#" } } }));
    try testing.expectError(error.InvalidReasonCode, encodePacket(&buf, .v5, .{ .connack = .{ .session_present = false, .reason_code = .granted_qos_1 } }));
    // 3.1.1 cannot carry properties at all.
    try testing.expectError(error.UnsupportedInVersion, encodePacket(&buf, .v3_1_1, .{ .publish = .{ .topic = "t", .properties = .{ .message_expiry_interval = 1 } } }));
    try testing.expectError(error.UnsupportedInVersion, encodeConnack(&buf, .{ .session_present = false, .properties = .{ .receive_maximum = 1 } }));
}

test "v5 decode errors map to the reason code §4.13 answers with" {
    try testing.expectEqual(ReasonCode.malformed_packet, reasonForDecodeError(error.MalformedPacket));
    try testing.expectEqual(ReasonCode.malformed_packet, reasonForDecodeError(error.InvalidUtf8));
    try testing.expectEqual(ReasonCode.protocol_error, reasonForDecodeError(error.ProtocolViolation));
    try testing.expectEqual(ReasonCode.unsupported_protocol_version, reasonForDecodeError(error.UnsupportedProtocol));
    // 3.1.1 return codes and 5.0 reason codes map onto each other where they can.
    inline for (@typeInfo(ConnectReturnCode).@"enum".fields) |f| {
        const rc: ConnectReturnCode = @enumFromInt(f.value);
        try testing.expectEqual(rc, returnCodeFromReason(reasonFromReturnCode(rc)));
    }
    try testing.expectEqual(ConnectReturnCode.server_unavailable, returnCodeFromReason(.quota_exceeded));
    try testing.expect(ReasonCode.packet_too_large.isError());
    try testing.expect(!ReasonCode.no_matching_subscribers.isError());
    try testing.expectEqual(ReasonCode.granted_qos_2, ReasonCode.granted(.exactly_once));
}

test "v5: every strict prefix of a v5 packet is need-more, never an error" {
    var buf: [128]u8 = undefined;
    const full = try encodePacket(&buf, .v5, .{ .publish = .{
        .topic = "a",
        .payload = "xyz",
        .qos = .exactly_once,
        .packet_id = 3,
        .properties = .{ .user_properties = .{ .items = &.{.{ .name = "n", .value = "v" }} }, .message_expiry_interval = 9 },
    } });
    for (0..full.len) |cut| try testing.expectEqual(null, try decodePacket(full[0..cut], .v5));
}

test "v5 decode: 1000-iteration garbage sweep never panics" {
    var prng = std.Random.DefaultPrng.init(0x6d717435); // "mqt5"
    const random = prng.random();
    var buf: [96]u8 = undefined;
    for (0..1000) |i| {
        const len = random.uintAtMost(usize, buf.len - 2);
        buf[0] = @as(u8, @intCast((i % 15) + 1)) << 4 | @as(u8, @intCast(i % 16));
        buf[1] = @intCast(len);
        random.bytes(buf[2..][0..len]);
        const d = (decodePacket(buf[0 .. 2 + len], .v5) catch continue) orelse continue;
        // Whatever decoded walks its repeated properties without trouble.
        switch (d.packet) {
            .publish => |p| {
                _ = p.properties.user_properties.count();
                _ = p.properties.subscription_ids.count();
            },
            else => {},
        }
    }
}

// ── fuzz: v5 decode off the wire ───────────────────────────────────────────

/// 5.0 streams for `fuzzDecodeV5`, built by this file's own encoders for the
/// same reason as `StreamCorpus`: only real back-to-back packets reach the
/// multi-packet walk, and only real property blocks reach `decodeProperties`
/// past its first identifier.
const StreamCorpusV5 = struct {
    scratch: [512]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [16][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *StreamCorpusV5, frame: []const u8) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = head;
        self.used += head.len;
        self.n += 1;
    }

    fn put(self: *StreamCorpusV5, n: *usize, p: Packet) !void {
        n.* += (try encodePacket(self.scratch[n.*..], .v5, p)).len;
    }

    fn build(self: *StreamCorpusV5) ![]const []const u8 {
        var n: usize = 0;
        try self.put(&n, .{ .connack = .{ .session_present = true, .properties = .{ .receive_maximum = 10, .topic_alias_maximum = 4, .assigned_client_identifier = "a1" } } });
        try self.put(&n, .{ .publish = .{ .topic = "t/1", .payload = "v", .qos = .at_least_once, .packet_id = 1, .properties = .{
            .message_expiry_interval = 5,
            .user_properties = .{ .items = &.{.{ .name = "k", .value = "v" }} },
            .subscription_ids = .{ .items = &.{ 1, 300 } },
        } } });
        try self.put(&n, .{ .puback = .{ .packet_id = 1, .reason_code = .no_matching_subscribers } });
        try self.put(&n, .{ .disconnect = .{ .reason_code = .server_shutting_down, .properties = .{ .reason_string = "bye" } } });
        self.push(self.scratch[0..n]);
        self.push(self.scratch[0 .. n - 1]);

        n = 0;
        try self.put(&n, .{ .subscribe = .{ .packet_id = 2, .filters = &.{.{ .filter = "a/#", .qos = .exactly_once, .retain_handling = .never }}, .properties = .{ .subscription_ids = .{ .items = &.{7} } } } });
        try self.put(&n, .{ .suback = .{ .packet_id = 2, .codes = &.{ 0x02, 0x9E } } });
        try self.put(&n, .{ .unsubscribe = .{ .packet_id = 3, .filters = &.{"a/#"} } });
        try self.put(&n, .{ .unsuback = .{ .packet_id = 3, .codes = &.{0x11} } });
        try self.put(&n, .{ .auth = .{ .reason_code = .continue_authentication, .properties = .{ .authentication_method = "M", .authentication_data = "d" } } });
        self.push(self.scratch[0..n]);

        n = 0;
        try self.put(&n, .{ .connect = .{ .client_id = "c", .version = .v5, .password = "p", .properties = .{ .session_expiry_interval = 60, .receive_maximum = 5 }, .will = .{ .topic = "w", .message = "m", .properties = .{ .will_delay_interval = 3, .content_type = "x" } } } });
        self.push(self.scratch[0..n]);
        n = 0;
        try self.put(&n, .{ .publish = .{ .topic = "", .payload = "z", .properties = .{ .topic_alias = 2 } } });
        try self.put(&n, .{ .pubrec = .{ .packet_id = 4 } });
        try self.put(&n, .{ .pubrel = .{ .packet_id = 4, .reason_code = .packet_identifier_not_found } });
        try self.put(&n, .{ .pubcomp = .{ .packet_id = 4, .properties = .{ .reason_string = "r" } } });
        self.push(self.scratch[0..n]);

        // Refusals, one per class decodeProperties tells apart.
        self.push(&hex("2006000003230001")); // Malformed: property not allowed here
        self.push(&hex("200900000621000121" ++ "0002")); // Protocol Error: repeated
        self.push(&hex("2006000003210000")); // Protocol Error: zero Receive Maximum
        self.push(&hex("8207000a0000016140")); // Malformed: reserved option bit
        return self.entries[0..self.n];
    }
};

test "fuzz: v5 decode never panics on arbitrary bytes" {
    var corpus: StreamCorpusV5 = .{};
    try testing.fuzz({}, fuzzDecodeV5, .{ .corpus = try corpus.build() });
}

fn fuzzDecodeV5(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // One `smith.slice` call — see `fuzzDecode` for why never `bytes` + a length.
    const len: usize = smith.slice(&buf);
    var off: usize = 0;
    var iterations: usize = 0;
    while (off < len and iterations < 64) : (iterations += 1) {
        const d = (decodePacket(buf[off..len], .v5) catch return) orelse return;
        switch (d.packet) {
            .publish => |p| {
                _ = p.properties.user_properties.count();
                _ = p.properties.subscription_ids.count();
            },
            else => {},
        }
        off += d.consumed;
    }
}

test "corpus v5: every seed reaches decodePacket, and the packets walked are pinned" {
    var corpus: StreamCorpusV5 = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var walked: usize = 0;
    var refused: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var off: usize = 0;
        while (off < len) {
            const d = (decodePacket(buf[off..len], .v5) catch {
                refused += 1;
                break;
            }) orelse break;
            off += d.consumed;
            walked += 1;
        }
    }
    try testing.expectEqual(entries.len, nonempty);
    // 4 + 3 (the cut copy loses its last packet) + 5 + 1 + 4.
    try testing.expectEqual(@as(usize, 17), walked);
    try testing.expectEqual(@as(usize, 4), refused);
}
