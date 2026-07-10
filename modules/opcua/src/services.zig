// SPDX-License-Identifier: MIT

//! OPC UA service framing (OPC 10000-4) — the `RequestHeader`/`ResponseHeader`
//! envelope every service call rides in, the array-of-struct wire pattern
//! (Int32 count + elements, `-1` = null array — OPC UA Binary's array
//! convention, used throughout Part 4) hand-rolled here since `encoding.zig`
//! only has array support as a `Variant`-array TODO (a different, narrower
//! case), plus the concrete request/response structures F2 needs:
//! OpenSecureChannel, CreateSession, ActivateSession, CloseSession/
//! CloseSecureChannel, and ServiceFault. `Channel` is the low-level
//! send/recv-with-chunking helper `root.zig`'s `SecureChannel`/`Session`
//! build on.
//!
//! Field order for every structure below is ground-truthed against the OPC
//! Foundation's own machine-readable schema — `Schema/Opc.Ua.Types.bsd`
//! (github.com/OPCFoundation/UA-Nodeset, OPC Foundation MIT License 1.00) —
//! fetched directly during implementation rather than inferred from the prose
//! spec or copied from a third party's port of it. The numeric (namespace-0)
//! `..._Encoding_DefaultBinary` NodeIds each request/response is tagged with
//! on the wire come from the same repository's `Schema/NodeIds.csv`.
//!
//! A service message body (§6.7.2/§4.6): unlike a `Variant`'s embedded
//! `ExtensionObject` (which carries an Encoding byte + Int32-length-prefixed
//! ByteString), the *top-level* body of a MSG/OPN/CLO chunk is a bare
//! `NodeId` (the `..._Encoding_DefaultBinary` type id) immediately followed
//! by the structure's fields — no Encoding byte, no length prefix. `Channel.
//! sendService`/`.recvService` build/parse exactly that shape, riding inside
//! the `SecureConversationMessageHeader`/`SequenceHeader` framing `transport.
//! zig` already models, using `transport.Connection.sendChunk`/`.recvChunk`
//! and `MessageChunkAssembler` verbatim (no changes to that file).

const std = @import("std");
const encoding = @import("encoding.zig");
const transport = @import("transport.zig");

pub const ServiceError = encoding.EncodeError || encoding.DecodeError || transport.TransportError || error{
    /// The peer answered with a ServiceFault instead of the expected
    /// response type. `Channel.last_service_result` holds the StatusCode
    /// from the fault's `ResponseHeader.service_result`.
    ServiceFault,
    /// A response's `ResponseHeader.service_result` was itself a Bad status
    /// code (top bit set — OPC 10000-4 §7.34) even though the message wasn't
    /// a ServiceFault. `Channel.last_service_result` holds the code.
    BadServiceResult,
    /// A response's leading type-id NodeId didn't match either the expected
    /// response type or ServiceFault, or its SequenceHeader.RequestId didn't
    /// match the request just sent.
    UnexpectedResponseType,
};

/// `SecurityPolicy#None`'s URI (OPC 10000-7 §6.2.1) — the only SecurityPolicy
/// this module (and this whole `opcua` module: no crypto, see `root.zig`'s
/// doc comment) speaks.
pub const security_policy_none_uri = "http://opcfoundation.org/UA/SecurityPolicy#None";

/// The wire's canonical "null NodeId" (namespace 0, numeric identifier 0,
/// encoded as the compact two-byte form) — used for `RequestHeader.
/// authentication_token` before a session exists.
pub const null_node_id: encoding.NodeId = .{ .numeric = .{ .namespace = 0, .id = 0 } };

fn n0(id: u32) encoding.NodeId {
    return .{ .numeric = .{ .namespace = 0, .id = id } };
}

/// `true` if the top severity bit (Bad) is set (OPC 10000-4 §7.34 Table 166:
/// bits 31:30 are `00` Good, `01` Uncertain, `1x` Bad) — Good/Uncertain both
/// read as "not Bad" here, which is all this module's minimal error-mapping
/// needs.
pub fn isBad(sc: encoding.StatusCode) bool {
    return sc & 0x8000_0000 != 0;
}

fn nodeIdEql(a: encoding.NodeId, b: encoding.NodeId) bool {
    return switch (a) {
        .numeric => |av| switch (b) {
            .numeric => |bv| av.namespace == bv.namespace and av.id == bv.id,
            else => false,
        },
        .string => |av| switch (b) {
            .string => |bv| av.namespace == bv.namespace and std.mem.eql(u8, av.id orelse "", bv.id orelse ""),
            else => false,
        },
        .guid => |av| switch (b) {
            .guid => |bv| av.namespace == bv.namespace and std.meta.eql(av.id, bv.id),
            else => false,
        },
        .byte_string => |av| switch (b) {
            .byte_string => |bv| av.namespace == bv.namespace and std.mem.eql(u8, av.id orelse "", bv.id orelse ""),
            else => false,
        },
    };
}

// ── well-known Encoding_DefaultBinary NodeIds (namespace 0) ─────────────────
// OPC Foundation UA-Nodeset `Schema/NodeIds.csv` (MIT License 1.00).

pub const type_id = struct {
    pub const service_fault = n0(397);
    pub const anonymous_identity_token = n0(321);
    pub const open_secure_channel_request = n0(446);
    pub const open_secure_channel_response = n0(449);
    pub const close_secure_channel_request = n0(452);
    pub const close_secure_channel_response = n0(455);
    pub const create_session_request = n0(461);
    pub const create_session_response = n0(464);
    pub const activate_session_request = n0(467);
    pub const activate_session_response = n0(470);
    pub const close_session_request = n0(473);
    pub const close_session_response = n0(476);
    pub const read_request = n0(631);
    pub const read_response = n0(634);
    pub const write_request = n0(673);
    pub const write_response = n0(676);
    pub const browse_request = n0(527);
    pub const browse_response = n0(530);
    pub const browse_next_request = n0(533);
    pub const browse_next_response = n0(536);
    pub const call_request = n0(712);
    pub const call_response = n0(715);
};

/// `AttributeId` (OPC Foundation UA-Nodeset `Schema/AttributeIds.csv`, MIT
/// License 1.00) — a plain namespace of `u32` constants, not an enum:
/// `ReadValueId.attribute_id`/`WriteValue.attribute_id` carry it as a bare
/// UInt32 on the wire (OPC 10000-4 §7.28/§5.10.2.2), never enum-decoded (a
/// server may in principle reject an attribute id this list doesn't name
/// with a Bad status rather than the wire itself rejecting it).
pub const attribute_id = struct {
    pub const node_id: u32 = 1;
    pub const node_class: u32 = 2;
    pub const browse_name: u32 = 3;
    pub const display_name: u32 = 4;
    pub const description: u32 = 5;
    pub const write_mask: u32 = 6;
    pub const user_write_mask: u32 = 7;
    pub const is_abstract: u32 = 8;
    pub const symmetric: u32 = 9;
    pub const inverse_name: u32 = 10;
    pub const contains_no_loops: u32 = 11;
    pub const event_notifier: u32 = 12;
    /// The common case: the attribute `Session.readAttribute` defaults to.
    pub const value: u32 = 13;
    pub const data_type: u32 = 14;
    pub const value_rank: u32 = 15;
    pub const array_dimensions: u32 = 16;
    pub const access_level: u32 = 17;
    pub const user_access_level: u32 = 18;
    pub const minimum_sampling_interval: u32 = 19;
    pub const historizing: u32 = 20;
    pub const executable: u32 = 21;
    pub const user_executable: u32 = 22;
    pub const data_type_definition: u32 = 23;
    pub const role_permissions: u32 = 24;
    pub const user_role_permissions: u32 = 25;
    pub const access_restrictions: u32 = 26;
    pub const access_level_ex: u32 = 27;
};

// ── enumerations (OPC 10000-4, encoded as OPC 10000-6 §5.1.3 4-byte
// enumerations — this module writes/reads them as plain `u32`s: the bit
// pattern is identical to Int32 for every value these enums actually use) ──

pub const SecurityTokenRequestType = enum(u32) { issue = 0, renew = 1 };
pub const MessageSecurityMode = enum(u32) { invalid = 0, none = 1, sign = 2, sign_and_encrypt = 3 };
pub const ApplicationType = enum(u32) { server = 0, client = 1, client_and_server = 2, discovery_server = 3 };
pub const UserTokenType = enum(u32) { anonymous = 0, user_name = 1, certificate = 2, issued_token = 3 };
/// OPC 10000-4 §7.44 (ground-truthed against the OPC Foundation schema's
/// `TimestampsToReturn` `EnumeratedType`, which also declares `invalid = 4`
/// as an explicit reject-this-request sentinel value some servers echo back).
pub const TimestampsToReturn = enum(u32) { source = 0, server = 1, both = 2, neither = 3, invalid = 4 };
/// OPC 10000-4 §7.6 (`BrowseDescription.browse_direction`).
pub const BrowseDirection = enum(u32) { forward = 0, inverse = 1, both = 2, invalid = 3 };
/// OPC 10000-4 §7.20 (`ReferenceDescription.node_class`) — a bit-flag
/// `EnumeratedType` per the schema (each node has exactly one class in
/// practice; `BrowseDescription.node_class_mask` ORs these together as a
/// plain `u32`, not through this enum).
pub const NodeClass = enum(u32) { unspecified = 0, object = 1, variable = 2, method = 4, object_type = 8, variable_type = 16, reference_type = 32, data_type = 64, view = 128 };

fn encodeEnum(e: *encoding.Encoder, comptime T: type, v: T) encoding.EncodeError!void {
    try e.writer.writeInt(u32, @intFromEnum(v), .little);
}

fn decodeEnum(d: *encoding.Decoder, comptime T: type) encoding.DecodeError!T {
    const raw = try d.reader.takeInt(u32, .little);
    return std.enums.fromInt(T, raw) orelse return error.BadEncodingByte;
}

// ── the array-of-T wire shape (Int32 count, `-1` = null array) ─────────────
// Every `NoOf<Field>`/`<Field>` pair in Part 4 (e.g. `ResponseHeader.
// StringTable`, `CreateSessionResponse.ServerEndpoints`) uses this shape.

fn encodeArray(e: *encoding.Encoder, comptime T: type, items: ?[]const T, comptime encodeItem: fn (*encoding.Encoder, T) encoding.EncodeError!void) encoding.EncodeError!void {
    const arr = items orelse {
        try e.writer.writeInt(i32, -1, .little);
        return;
    };
    if (arr.len > std.math.maxInt(i32)) return error.ValueTooLarge;
    try e.writer.writeInt(i32, @intCast(arr.len), .little);
    for (arr) |item| try encodeItem(e, item);
}

fn decodeArray(d: *encoding.Decoder, comptime T: type, comptime decodeItem: fn (*encoding.Decoder) encoding.DecodeError!T) encoding.DecodeError!?[]T {
    const len = try d.reader.takeInt(i32, .little);
    if (len == -1) return null;
    if (len < -1) return error.BadLength;
    const n: usize = @intCast(len);
    var list = try std.ArrayList(T).initCapacity(d.allocator, n);
    errdefer list.deinit(d.allocator);
    for (0..n) |_| list.appendAssumeCapacity(try decodeItem(d));
    return try list.toOwnedSlice(d.allocator);
}

fn encodeStringItem(e: *encoding.Encoder, s: ?[]const u8) encoding.EncodeError!void {
    try e.encodeString(s);
}
fn decodeStringItem(d: *encoding.Decoder) encoding.DecodeError!?[]const u8 {
    return d.decodeString();
}

fn freeOptStr(a: std.mem.Allocator, s: ?[]const u8) void {
    if (s) |bytes| a.free(bytes);
}

fn freeStringArray(a: std.mem.Allocator, arr: ?[]const ?[]const u8) void {
    if (arr) |items| {
        for (items) |s| freeOptStr(a, s);
        a.free(items);
    }
}

pub fn freeDiagnosticInfo(a: std.mem.Allocator, di: encoding.DiagnosticInfo) void {
    freeOptStr(a, di.additional_info);
    if (di.inner_diagnostic_info) |p| {
        freeDiagnosticInfo(a, p.*);
        a.destroy(p);
    }
}

/// Frees a `?[]const DiagnosticInfo` (the `DiagnosticInfos` sibling array
/// every Part 4 response carries next to its `Results`) — shared by
/// `freeReadResponse`/`freeWriteResponse`/`freeBrowseResponse`/
/// `freeBrowseNextResponse`/`freeCallResponse` below.
fn freeDiagnosticInfoArray(a: std.mem.Allocator, arr: ?[]const encoding.DiagnosticInfo) void {
    if (arr) |infos| {
        for (infos) |di| freeDiagnosticInfo(a, di);
        a.free(infos);
    }
}

// ── RequestHeader / ResponseHeader (OPC 10000-4 §7.33/§7.34) ────────────────

pub const RequestHeader = struct {
    authentication_token: encoding.NodeId,
    timestamp: encoding.DateTime,
    request_handle: u32,
    return_diagnostics: u32,
    audit_entry_id: ?[]const u8,
    timeout_hint: u32,
    additional_header: encoding.ExtensionObject,
};

pub fn encodeRequestHeader(e: *encoding.Encoder, v: RequestHeader) encoding.EncodeError!void {
    try e.encodeNodeId(v.authentication_token);
    try e.encodeDateTime(v.timestamp);
    try e.writer.writeInt(u32, v.request_handle, .little);
    try e.writer.writeInt(u32, v.return_diagnostics, .little);
    try e.encodeString(v.audit_entry_id);
    try e.writer.writeInt(u32, v.timeout_hint, .little);
    try e.encodeExtensionObject(v.additional_header);
}

pub fn decodeRequestHeader(d: *encoding.Decoder) encoding.DecodeError!RequestHeader {
    return .{
        .authentication_token = try d.decodeNodeId(),
        .timestamp = try d.decodeDateTime(),
        .request_handle = try d.decodeUInt32(),
        .return_diagnostics = try d.decodeUInt32(),
        .audit_entry_id = try d.decodeString(),
        .timeout_hint = try d.decodeUInt32(),
        .additional_header = try d.decodeExtensionObject(),
    };
}

pub fn freeRequestHeader(a: std.mem.Allocator, v: RequestHeader) void {
    freeOptStr(a, v.audit_entry_id);
    if (v.additional_header.body.len != 0) a.free(v.additional_header.body);
}

pub const ResponseHeader = struct {
    timestamp: encoding.DateTime,
    request_handle: u32,
    service_result: encoding.StatusCode,
    service_diagnostics: encoding.DiagnosticInfo,
    string_table: ?[]const ?[]const u8,
    additional_header: encoding.ExtensionObject,
};

pub fn encodeResponseHeader(e: *encoding.Encoder, v: ResponseHeader) encoding.EncodeError!void {
    try e.encodeDateTime(v.timestamp);
    try e.writer.writeInt(u32, v.request_handle, .little);
    try e.encodeStatusCode(v.service_result);
    try e.encodeDiagnosticInfo(v.service_diagnostics);
    try encodeArray(e, ?[]const u8, v.string_table, encodeStringItem);
    try e.encodeExtensionObject(v.additional_header);
}

pub fn decodeResponseHeader(d: *encoding.Decoder) encoding.DecodeError!ResponseHeader {
    return .{
        .timestamp = try d.decodeDateTime(),
        .request_handle = try d.decodeUInt32(),
        .service_result = try d.decodeStatusCode(),
        .service_diagnostics = try d.decodeDiagnosticInfo(),
        .string_table = try decodeArray(d, ?[]const u8, decodeStringItem),
        .additional_header = try d.decodeExtensionObject(),
    };
}

pub fn freeResponseHeader(a: std.mem.Allocator, v: ResponseHeader) void {
    freeDiagnosticInfo(a, v.service_diagnostics);
    freeStringArray(a, v.string_table);
    if (v.additional_header.body.len != 0) a.free(v.additional_header.body);
}

/// A "no additional header" `ExtensionObject` — the canonical empty value
/// every `RequestHeader.additional_header`/`ResponseHeader.additional_header`
/// this client sends uses.
pub const no_additional_header: encoding.ExtensionObject = .{ .type_id = null_node_id, .encoding = .no_body };

// ── ApplicationDescription (§7.4) ────────────────────────────────────────────

pub const ApplicationDescription = struct {
    application_uri: ?[]const u8,
    product_uri: ?[]const u8,
    application_name: encoding.LocalizedText,
    application_type: ApplicationType,
    gateway_server_uri: ?[]const u8,
    discovery_profile_uri: ?[]const u8,
    discovery_urls: ?[]const ?[]const u8,
};

pub fn encodeApplicationDescription(e: *encoding.Encoder, v: ApplicationDescription) encoding.EncodeError!void {
    try e.encodeString(v.application_uri);
    try e.encodeString(v.product_uri);
    try e.encodeLocalizedText(v.application_name);
    try encodeEnum(e, ApplicationType, v.application_type);
    try e.encodeString(v.gateway_server_uri);
    try e.encodeString(v.discovery_profile_uri);
    try encodeArray(e, ?[]const u8, v.discovery_urls, encodeStringItem);
}

pub fn decodeApplicationDescription(d: *encoding.Decoder) encoding.DecodeError!ApplicationDescription {
    return .{
        .application_uri = try d.decodeString(),
        .product_uri = try d.decodeString(),
        .application_name = try d.decodeLocalizedText(),
        .application_type = try decodeEnum(d, ApplicationType),
        .gateway_server_uri = try d.decodeString(),
        .discovery_profile_uri = try d.decodeString(),
        .discovery_urls = try decodeArray(d, ?[]const u8, decodeStringItem),
    };
}

pub fn freeApplicationDescription(a: std.mem.Allocator, v: ApplicationDescription) void {
    freeOptStr(a, v.application_uri);
    freeOptStr(a, v.product_uri);
    freeOptStr(a, v.application_name.locale);
    freeOptStr(a, v.application_name.text);
    freeOptStr(a, v.gateway_server_uri);
    freeOptStr(a, v.discovery_profile_uri);
    freeStringArray(a, v.discovery_urls);
}

// ── SignatureData (§7.42), SignedSoftwareCertificate (§7.41) ───────────────

pub const SignatureData = struct {
    algorithm: ?[]const u8,
    signature: ?[]const u8,
};

pub fn encodeSignatureData(e: *encoding.Encoder, v: SignatureData) encoding.EncodeError!void {
    try e.encodeString(v.algorithm);
    try e.encodeByteString(v.signature);
}

pub fn decodeSignatureData(d: *encoding.Decoder) encoding.DecodeError!SignatureData {
    return .{ .algorithm = try d.decodeString(), .signature = try d.decodeByteString() };
}

pub fn freeSignatureData(a: std.mem.Allocator, v: SignatureData) void {
    freeOptStr(a, v.algorithm);
    freeOptStr(a, v.signature);
}

pub const SignedSoftwareCertificate = struct {
    certificate_data: ?[]const u8,
    signature: ?[]const u8,
};

pub fn encodeSignedSoftwareCertificate(e: *encoding.Encoder, v: SignedSoftwareCertificate) encoding.EncodeError!void {
    try e.encodeByteString(v.certificate_data);
    try e.encodeByteString(v.signature);
}

pub fn decodeSignedSoftwareCertificate(d: *encoding.Decoder) encoding.DecodeError!SignedSoftwareCertificate {
    return .{ .certificate_data = try d.decodeByteString(), .signature = try d.decodeByteString() };
}

fn freeSoftwareCertArray(a: std.mem.Allocator, arr: ?[]const SignedSoftwareCertificate) void {
    if (arr) |items| {
        for (items) |c| {
            freeOptStr(a, c.certificate_data);
            freeOptStr(a, c.signature);
        }
        a.free(items);
    }
}

// ── UserTokenPolicy (§7.45), EndpointDescription (§7.14) ────────────────────

pub const UserTokenPolicy = struct {
    policy_id: ?[]const u8,
    token_type: UserTokenType,
    issued_token_type: ?[]const u8,
    issuer_endpoint_url: ?[]const u8,
    security_policy_uri: ?[]const u8,
};

pub fn encodeUserTokenPolicy(e: *encoding.Encoder, v: UserTokenPolicy) encoding.EncodeError!void {
    try e.encodeString(v.policy_id);
    try encodeEnum(e, UserTokenType, v.token_type);
    try e.encodeString(v.issued_token_type);
    try e.encodeString(v.issuer_endpoint_url);
    try e.encodeString(v.security_policy_uri);
}

pub fn decodeUserTokenPolicy(d: *encoding.Decoder) encoding.DecodeError!UserTokenPolicy {
    return .{
        .policy_id = try d.decodeString(),
        .token_type = try decodeEnum(d, UserTokenType),
        .issued_token_type = try d.decodeString(),
        .issuer_endpoint_url = try d.decodeString(),
        .security_policy_uri = try d.decodeString(),
    };
}

fn freeUserTokenPolicy(a: std.mem.Allocator, v: UserTokenPolicy) void {
    freeOptStr(a, v.policy_id);
    freeOptStr(a, v.issued_token_type);
    freeOptStr(a, v.issuer_endpoint_url);
    freeOptStr(a, v.security_policy_uri);
}

fn freeUserTokenPolicyArray(a: std.mem.Allocator, arr: ?[]const UserTokenPolicy) void {
    if (arr) |items| {
        for (items) |t| freeUserTokenPolicy(a, t);
        a.free(items);
    }
}

pub const EndpointDescription = struct {
    endpoint_url: ?[]const u8,
    server: ApplicationDescription,
    server_certificate: ?[]const u8,
    security_mode: MessageSecurityMode,
    security_policy_uri: ?[]const u8,
    user_identity_tokens: ?[]const UserTokenPolicy,
    transport_profile_uri: ?[]const u8,
    security_level: u8,
};

pub fn encodeEndpointDescription(e: *encoding.Encoder, v: EndpointDescription) encoding.EncodeError!void {
    try e.encodeString(v.endpoint_url);
    try encodeApplicationDescription(e, v.server);
    try e.encodeByteString(v.server_certificate);
    try encodeEnum(e, MessageSecurityMode, v.security_mode);
    try e.encodeString(v.security_policy_uri);
    try encodeArray(e, UserTokenPolicy, v.user_identity_tokens, encodeUserTokenPolicy);
    try e.encodeString(v.transport_profile_uri);
    try e.encodeByte(v.security_level);
}

pub fn decodeEndpointDescription(d: *encoding.Decoder) encoding.DecodeError!EndpointDescription {
    return .{
        .endpoint_url = try d.decodeString(),
        .server = try decodeApplicationDescription(d),
        .server_certificate = try d.decodeByteString(),
        .security_mode = try decodeEnum(d, MessageSecurityMode),
        .security_policy_uri = try d.decodeString(),
        .user_identity_tokens = try decodeArray(d, UserTokenPolicy, decodeUserTokenPolicy),
        .transport_profile_uri = try d.decodeString(),
        .security_level = try d.decodeByte(),
    };
}

pub fn freeEndpointDescription(a: std.mem.Allocator, v: EndpointDescription) void {
    freeOptStr(a, v.endpoint_url);
    freeApplicationDescription(a, v.server);
    freeOptStr(a, v.server_certificate);
    freeOptStr(a, v.security_policy_uri);
    freeUserTokenPolicyArray(a, v.user_identity_tokens);
    freeOptStr(a, v.transport_profile_uri);
}

fn freeEndpointArray(a: std.mem.Allocator, arr: ?[]const EndpointDescription) void {
    if (arr) |items| {
        for (items) |ep| freeEndpointDescription(a, ep);
        a.free(items);
    }
}

// ── AnonymousIdentityToken (§7.2) ────────────────────────────────────────────

pub const AnonymousIdentityToken = struct {
    policy_id: ?[]const u8,
};

pub fn encodeAnonymousIdentityToken(e: *encoding.Encoder, v: AnonymousIdentityToken) encoding.EncodeError!void {
    try e.encodeString(v.policy_id);
}

pub fn decodeAnonymousIdentityToken(d: *encoding.Decoder) encoding.DecodeError!AnonymousIdentityToken {
    return .{ .policy_id = try d.decodeString() };
}

// ── OpenSecureChannel (§5.5.2) ───────────────────────────────────────────────

pub const OpenSecureChannelRequest = struct {
    request_header: RequestHeader,
    client_protocol_version: u32,
    request_type: SecurityTokenRequestType,
    security_mode: MessageSecurityMode,
    client_nonce: ?[]const u8,
    requested_lifetime: u32,
};

pub fn encodeOpenSecureChannelRequest(e: *encoding.Encoder, v: OpenSecureChannelRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.writer.writeInt(u32, v.client_protocol_version, .little);
    try encodeEnum(e, SecurityTokenRequestType, v.request_type);
    try encodeEnum(e, MessageSecurityMode, v.security_mode);
    try e.encodeByteString(v.client_nonce);
    try e.writer.writeInt(u32, v.requested_lifetime, .little);
}

pub fn decodeOpenSecureChannelRequest(d: *encoding.Decoder) encoding.DecodeError!OpenSecureChannelRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .client_protocol_version = try d.decodeUInt32(),
        .request_type = try decodeEnum(d, SecurityTokenRequestType),
        .security_mode = try decodeEnum(d, MessageSecurityMode),
        .client_nonce = try d.decodeByteString(),
        .requested_lifetime = try d.decodeUInt32(),
    };
}

pub fn freeOpenSecureChannelRequest(a: std.mem.Allocator, v: OpenSecureChannelRequest) void {
    freeRequestHeader(a, v.request_header);
    freeOptStr(a, v.client_nonce);
}

pub const ChannelSecurityToken = struct {
    channel_id: u32,
    token_id: u32,
    created_at: encoding.DateTime,
    revised_lifetime: u32,
};

pub fn encodeChannelSecurityToken(e: *encoding.Encoder, v: ChannelSecurityToken) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.channel_id, .little);
    try e.writer.writeInt(u32, v.token_id, .little);
    try e.encodeDateTime(v.created_at);
    try e.writer.writeInt(u32, v.revised_lifetime, .little);
}

pub fn decodeChannelSecurityToken(d: *encoding.Decoder) encoding.DecodeError!ChannelSecurityToken {
    return .{
        .channel_id = try d.decodeUInt32(),
        .token_id = try d.decodeUInt32(),
        .created_at = try d.decodeDateTime(),
        .revised_lifetime = try d.decodeUInt32(),
    };
}

pub const OpenSecureChannelResponse = struct {
    response_header: ResponseHeader,
    server_protocol_version: u32,
    security_token: ChannelSecurityToken,
    server_nonce: ?[]const u8,
};

pub fn encodeOpenSecureChannelResponse(e: *encoding.Encoder, v: OpenSecureChannelResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.writer.writeInt(u32, v.server_protocol_version, .little);
    try encodeChannelSecurityToken(e, v.security_token);
    try e.encodeByteString(v.server_nonce);
}

pub fn decodeOpenSecureChannelResponse(d: *encoding.Decoder) encoding.DecodeError!OpenSecureChannelResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .server_protocol_version = try d.decodeUInt32(),
        .security_token = try decodeChannelSecurityToken(d),
        .server_nonce = try d.decodeByteString(),
    };
}

pub fn freeOpenSecureChannelResponse(a: std.mem.Allocator, v: OpenSecureChannelResponse) void {
    freeResponseHeader(a, v.response_header);
    freeOptStr(a, v.server_nonce);
}

// ── CloseSecureChannel (§5.5.3) ──────────────────────────────────────────────

pub const CloseSecureChannelRequest = struct {
    request_header: RequestHeader,
};

pub fn encodeCloseSecureChannelRequest(e: *encoding.Encoder, v: CloseSecureChannelRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
}

pub fn decodeCloseSecureChannelRequest(d: *encoding.Decoder) encoding.DecodeError!CloseSecureChannelRequest {
    return .{ .request_header = try decodeRequestHeader(d) };
}

pub fn freeCloseSecureChannelRequest(a: std.mem.Allocator, v: CloseSecureChannelRequest) void {
    freeRequestHeader(a, v.request_header);
}

/// Modeled for completeness/round-trip testing — per OPC 10000-6 §6.7.2 the
/// server does **not** actually send this in practice (it closes the socket
/// after a CLO instead); `SecureChannel.close` never waits for it.
pub const CloseSecureChannelResponse = struct {
    response_header: ResponseHeader,
};

pub fn encodeCloseSecureChannelResponse(e: *encoding.Encoder, v: CloseSecureChannelResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
}

pub fn decodeCloseSecureChannelResponse(d: *encoding.Decoder) encoding.DecodeError!CloseSecureChannelResponse {
    return .{ .response_header = try decodeResponseHeader(d) };
}

// ── CreateSession (§5.6.2) ───────────────────────────────────────────────────

pub const CreateSessionRequest = struct {
    request_header: RequestHeader,
    client_description: ApplicationDescription,
    server_uri: ?[]const u8,
    endpoint_url: ?[]const u8,
    session_name: ?[]const u8,
    client_nonce: ?[]const u8,
    client_certificate: ?[]const u8,
    requested_session_timeout: f64,
    max_response_message_size: u32,
};

pub fn encodeCreateSessionRequest(e: *encoding.Encoder, v: CreateSessionRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeApplicationDescription(e, v.client_description);
    try e.encodeString(v.server_uri);
    try e.encodeString(v.endpoint_url);
    try e.encodeString(v.session_name);
    try e.encodeByteString(v.client_nonce);
    try e.encodeByteString(v.client_certificate);
    try e.encodeDouble(v.requested_session_timeout);
    try e.writer.writeInt(u32, v.max_response_message_size, .little);
}

pub fn decodeCreateSessionRequest(d: *encoding.Decoder) encoding.DecodeError!CreateSessionRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .client_description = try decodeApplicationDescription(d),
        .server_uri = try d.decodeString(),
        .endpoint_url = try d.decodeString(),
        .session_name = try d.decodeString(),
        .client_nonce = try d.decodeByteString(),
        .client_certificate = try d.decodeByteString(),
        .requested_session_timeout = try d.decodeDouble(),
        .max_response_message_size = try d.decodeUInt32(),
    };
}

pub fn freeCreateSessionRequest(a: std.mem.Allocator, v: CreateSessionRequest) void {
    freeRequestHeader(a, v.request_header);
    freeApplicationDescription(a, v.client_description);
    freeOptStr(a, v.server_uri);
    freeOptStr(a, v.endpoint_url);
    freeOptStr(a, v.session_name);
    freeOptStr(a, v.client_nonce);
    freeOptStr(a, v.client_certificate);
}

/// `ServerSoftwareCertificates`/`ServerSignature`/`MaxRequestMessageSize`
/// (the fields after `ServerEndpoints`) are intentionally not modeled: F2
/// never signs anything (SecurityMode=None) and nothing downstream needs
/// them. `decodeCreateSessionResponse` simply stops reading after
/// `server_endpoints` — harmless, since the reader is a `.fixed` view over
/// an already fully-reassembled message (unread trailing bytes are not a
/// framing bug, just ignored). `encodeCreateSessionResponse` mirrors that
/// same subset for round-trip testing.
pub const CreateSessionResponse = struct {
    response_header: ResponseHeader,
    session_id: encoding.NodeId,
    authentication_token: encoding.NodeId,
    revised_session_timeout: f64,
    server_nonce: ?[]const u8,
    server_certificate: ?[]const u8,
    server_endpoints: ?[]const EndpointDescription,
};

pub fn encodeCreateSessionResponse(e: *encoding.Encoder, v: CreateSessionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.encodeNodeId(v.session_id);
    try e.encodeNodeId(v.authentication_token);
    try e.encodeDouble(v.revised_session_timeout);
    try e.encodeByteString(v.server_nonce);
    try e.encodeByteString(v.server_certificate);
    try encodeArray(e, EndpointDescription, v.server_endpoints, encodeEndpointDescription);
}

pub fn decodeCreateSessionResponse(d: *encoding.Decoder) encoding.DecodeError!CreateSessionResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .session_id = try d.decodeNodeId(),
        .authentication_token = try d.decodeNodeId(),
        .revised_session_timeout = try d.decodeDouble(),
        .server_nonce = try d.decodeByteString(),
        .server_certificate = try d.decodeByteString(),
        .server_endpoints = try decodeArray(d, EndpointDescription, decodeEndpointDescription),
    };
}

pub fn freeCreateSessionResponse(a: std.mem.Allocator, v: CreateSessionResponse) void {
    freeResponseHeader(a, v.response_header);
    freeOptStr(a, v.server_nonce);
    freeOptStr(a, v.server_certificate);
    freeEndpointArray(a, v.server_endpoints);
}

// ── ActivateSession (§5.6.3) ─────────────────────────────────────────────────

pub const ActivateSessionRequest = struct {
    request_header: RequestHeader,
    client_signature: SignatureData,
    client_software_certificates: ?[]const SignedSoftwareCertificate,
    locale_ids: ?[]const ?[]const u8,
    user_identity_token: encoding.ExtensionObject,
    user_token_signature: SignatureData,
};

pub fn encodeActivateSessionRequest(e: *encoding.Encoder, v: ActivateSessionRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeSignatureData(e, v.client_signature);
    try encodeArray(e, SignedSoftwareCertificate, v.client_software_certificates, encodeSignedSoftwareCertificate);
    try encodeArray(e, ?[]const u8, v.locale_ids, encodeStringItem);
    try e.encodeExtensionObject(v.user_identity_token);
    try encodeSignatureData(e, v.user_token_signature);
}

pub fn decodeActivateSessionRequest(d: *encoding.Decoder) encoding.DecodeError!ActivateSessionRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .client_signature = try decodeSignatureData(d),
        .client_software_certificates = try decodeArray(d, SignedSoftwareCertificate, decodeSignedSoftwareCertificate),
        .locale_ids = try decodeArray(d, ?[]const u8, decodeStringItem),
        .user_identity_token = try d.decodeExtensionObject(),
        .user_token_signature = try decodeSignatureData(d),
    };
}

pub fn freeActivateSessionRequest(a: std.mem.Allocator, v: ActivateSessionRequest) void {
    freeRequestHeader(a, v.request_header);
    freeSignatureData(a, v.client_signature);
    freeSoftwareCertArray(a, v.client_software_certificates);
    freeStringArray(a, v.locale_ids);
    if (v.user_identity_token.body.len != 0) a.free(v.user_identity_token.body);
    freeSignatureData(a, v.user_token_signature);
}

pub const ActivateSessionResponse = struct {
    response_header: ResponseHeader,
    server_nonce: ?[]const u8,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeActivateSessionResponse(e: *encoding.Encoder, v: ActivateSessionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.encodeByteString(v.server_nonce);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeActivateSessionResponse(d: *encoding.Decoder) encoding.DecodeError!ActivateSessionResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .server_nonce = try d.decodeByteString(),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeActivateSessionResponse(a: std.mem.Allocator, v: ActivateSessionResponse) void {
    freeResponseHeader(a, v.response_header);
    freeOptStr(a, v.server_nonce);
    if (v.results) |r| a.free(r);
    if (v.diagnostic_infos) |infos| {
        for (infos) |di| freeDiagnosticInfo(a, di);
        a.free(infos);
    }
}

// ── CloseSession (§5.6.4) ────────────────────────────────────────────────────

pub const CloseSessionRequest = struct {
    request_header: RequestHeader,
    delete_subscriptions: bool,
};

pub fn encodeCloseSessionRequest(e: *encoding.Encoder, v: CloseSessionRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeBoolean(v.delete_subscriptions);
}

pub fn decodeCloseSessionRequest(d: *encoding.Decoder) encoding.DecodeError!CloseSessionRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .delete_subscriptions = try d.decodeBoolean(),
    };
}

pub fn freeCloseSessionRequest(a: std.mem.Allocator, v: CloseSessionRequest) void {
    freeRequestHeader(a, v.request_header);
}

pub const CloseSessionResponse = struct {
    response_header: ResponseHeader,
};

pub fn encodeCloseSessionResponse(e: *encoding.Encoder, v: CloseSessionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
}

pub fn decodeCloseSessionResponse(d: *encoding.Decoder) encoding.DecodeError!CloseSessionResponse {
    return .{ .response_header = try decodeResponseHeader(d) };
}

pub fn freeCloseSessionResponse(a: std.mem.Allocator, v: CloseSessionResponse) void {
    freeResponseHeader(a, v.response_header);
}

// ── ServiceFault (§7.38) ─────────────────────────────────────────────────────

pub const ServiceFault = struct {
    response_header: ResponseHeader,
};

pub fn encodeServiceFault(e: *encoding.Encoder, v: ServiceFault) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
}

pub fn decodeServiceFault(d: *encoding.Decoder) encoding.DecodeError!ServiceFault {
    return .{ .response_header = try decodeResponseHeader(d) };
}

pub fn freeServiceFault(a: std.mem.Allocator, v: ServiceFault) void {
    freeResponseHeader(a, v.response_header);
}

// ── Part 4: Read (§5.10.2), Write (§5.10.4), Browse/BrowseNext (§5.8.2/
// §5.8.3), Call (§5.11.2) ────────────────────────────────────────────────────
// Field order for every structure below is ground-truthed the same way F2's
// was: the OPC Foundation's `Schema/Opc.Ua.Types.bsd` (structures) and
// `Schema/AttributeIds.csv`/`Schema/NodeIds.csv` (the `AttributeId` constants
// and each request/response's `..._Encoding_DefaultBinary` numeric NodeId),
// fetched directly rather than inferred from the prose spec.

pub const ReadValueId = struct {
    node_id: encoding.NodeId,
    attribute_id: u32,
    index_range: ?[]const u8,
    data_encoding: encoding.QualifiedName,
};

pub fn encodeReadValueId(e: *encoding.Encoder, v: ReadValueId) encoding.EncodeError!void {
    try e.encodeNodeId(v.node_id);
    try e.writer.writeInt(u32, v.attribute_id, .little);
    try e.encodeString(v.index_range);
    try e.encodeQualifiedName(v.data_encoding);
}

pub fn decodeReadValueId(d: *encoding.Decoder) encoding.DecodeError!ReadValueId {
    return .{
        .node_id = try d.decodeNodeId(),
        .attribute_id = try d.decodeUInt32(),
        .index_range = try d.decodeString(),
        .data_encoding = try d.decodeQualifiedName(),
    };
}

pub fn freeReadValueId(a: std.mem.Allocator, v: ReadValueId) void {
    encoding.freeNodeId(a, v.node_id);
    freeOptStr(a, v.index_range);
    encoding.freeQualifiedName(a, v.data_encoding);
}

fn freeReadValueIdArray(a: std.mem.Allocator, arr: ?[]const ReadValueId) void {
    if (arr) |items| {
        for (items) |it| freeReadValueId(a, it);
        a.free(items);
    }
}

pub const ReadRequest = struct {
    request_header: RequestHeader,
    max_age: f64,
    timestamps_to_return: TimestampsToReturn,
    nodes_to_read: ?[]const ReadValueId,
};

pub fn encodeReadRequest(e: *encoding.Encoder, v: ReadRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeDouble(v.max_age);
    try encodeEnum(e, TimestampsToReturn, v.timestamps_to_return);
    try encodeArray(e, ReadValueId, v.nodes_to_read, encodeReadValueId);
}

pub fn decodeReadRequest(d: *encoding.Decoder) encoding.DecodeError!ReadRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .max_age = try d.decodeDouble(),
        .timestamps_to_return = try decodeEnum(d, TimestampsToReturn),
        .nodes_to_read = try decodeArray(d, ReadValueId, decodeReadValueId),
    };
}

pub fn freeReadRequest(a: std.mem.Allocator, v: ReadRequest) void {
    freeRequestHeader(a, v.request_header);
    freeReadValueIdArray(a, v.nodes_to_read);
}

pub const ReadResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.DataValue,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeReadResponse(e: *encoding.Encoder, v: ReadResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.DataValue, v.results, encoding.Encoder.encodeDataValue);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeReadResponse(d: *encoding.Decoder) encoding.DecodeError!ReadResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.DataValue, encoding.Decoder.decodeDataValue),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeReadResponse(a: std.mem.Allocator, v: ReadResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |items| {
        for (items) |dv| encoding.freeDataValue(a, dv);
        a.free(items);
    }
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const WriteValue = struct {
    node_id: encoding.NodeId,
    attribute_id: u32,
    index_range: ?[]const u8,
    value: encoding.DataValue,
};

pub fn encodeWriteValue(e: *encoding.Encoder, v: WriteValue) encoding.EncodeError!void {
    try e.encodeNodeId(v.node_id);
    try e.writer.writeInt(u32, v.attribute_id, .little);
    try e.encodeString(v.index_range);
    try e.encodeDataValue(v.value);
}

pub fn decodeWriteValue(d: *encoding.Decoder) encoding.DecodeError!WriteValue {
    return .{
        .node_id = try d.decodeNodeId(),
        .attribute_id = try d.decodeUInt32(),
        .index_range = try d.decodeString(),
        .value = try d.decodeDataValue(),
    };
}

pub fn freeWriteValue(a: std.mem.Allocator, v: WriteValue) void {
    encoding.freeNodeId(a, v.node_id);
    freeOptStr(a, v.index_range);
    encoding.freeDataValue(a, v.value);
}

fn freeWriteValueArray(a: std.mem.Allocator, arr: ?[]const WriteValue) void {
    if (arr) |items| {
        for (items) |it| freeWriteValue(a, it);
        a.free(items);
    }
}

pub const WriteRequest = struct {
    request_header: RequestHeader,
    nodes_to_write: ?[]const WriteValue,
};

pub fn encodeWriteRequest(e: *encoding.Encoder, v: WriteRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeArray(e, WriteValue, v.nodes_to_write, encodeWriteValue);
}

pub fn decodeWriteRequest(d: *encoding.Decoder) encoding.DecodeError!WriteRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .nodes_to_write = try decodeArray(d, WriteValue, decodeWriteValue),
    };
}

pub fn freeWriteRequest(a: std.mem.Allocator, v: WriteRequest) void {
    freeRequestHeader(a, v.request_header);
    freeWriteValueArray(a, v.nodes_to_write);
}

pub const WriteResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeWriteResponse(e: *encoding.Encoder, v: WriteResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeWriteResponse(d: *encoding.Decoder) encoding.DecodeError!WriteResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeWriteResponse(a: std.mem.Allocator, v: WriteResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const ViewDescription = struct {
    view_id: encoding.NodeId,
    timestamp: encoding.DateTime,
    view_version: u32,
};

/// The "no view" default (`ViewDescription` with a null `ViewId`) —
/// `BrowseRequest.View` when the caller doesn't want a view-restricted
/// browse (the common case).
pub const no_view: ViewDescription = .{ .view_id = null_node_id, .timestamp = 0, .view_version = 0 };

pub fn encodeViewDescription(e: *encoding.Encoder, v: ViewDescription) encoding.EncodeError!void {
    try e.encodeNodeId(v.view_id);
    try e.encodeDateTime(v.timestamp);
    try e.writer.writeInt(u32, v.view_version, .little);
}

pub fn decodeViewDescription(d: *encoding.Decoder) encoding.DecodeError!ViewDescription {
    return .{
        .view_id = try d.decodeNodeId(),
        .timestamp = try d.decodeDateTime(),
        .view_version = try d.decodeUInt32(),
    };
}

pub fn freeViewDescription(a: std.mem.Allocator, v: ViewDescription) void {
    encoding.freeNodeId(a, v.view_id);
}

pub const BrowseDescription = struct {
    node_id: encoding.NodeId,
    browse_direction: BrowseDirection,
    reference_type_id: encoding.NodeId,
    include_subtypes: bool,
    node_class_mask: u32,
    result_mask: u32,
};

pub fn encodeBrowseDescription(e: *encoding.Encoder, v: BrowseDescription) encoding.EncodeError!void {
    try e.encodeNodeId(v.node_id);
    try encodeEnum(e, BrowseDirection, v.browse_direction);
    try e.encodeNodeId(v.reference_type_id);
    try e.encodeBoolean(v.include_subtypes);
    try e.writer.writeInt(u32, v.node_class_mask, .little);
    try e.writer.writeInt(u32, v.result_mask, .little);
}

pub fn decodeBrowseDescription(d: *encoding.Decoder) encoding.DecodeError!BrowseDescription {
    return .{
        .node_id = try d.decodeNodeId(),
        .browse_direction = try decodeEnum(d, BrowseDirection),
        .reference_type_id = try d.decodeNodeId(),
        .include_subtypes = try d.decodeBoolean(),
        .node_class_mask = try d.decodeUInt32(),
        .result_mask = try d.decodeUInt32(),
    };
}

pub fn freeBrowseDescription(a: std.mem.Allocator, v: BrowseDescription) void {
    encoding.freeNodeId(a, v.node_id);
    encoding.freeNodeId(a, v.reference_type_id);
}

fn freeBrowseDescriptionArray(a: std.mem.Allocator, arr: ?[]const BrowseDescription) void {
    if (arr) |items| {
        for (items) |it| freeBrowseDescription(a, it);
        a.free(items);
    }
}

pub const BrowseRequest = struct {
    request_header: RequestHeader,
    view: ViewDescription,
    requested_max_references_per_node: u32,
    nodes_to_browse: ?[]const BrowseDescription,
};

pub fn encodeBrowseRequest(e: *encoding.Encoder, v: BrowseRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeViewDescription(e, v.view);
    try e.writer.writeInt(u32, v.requested_max_references_per_node, .little);
    try encodeArray(e, BrowseDescription, v.nodes_to_browse, encodeBrowseDescription);
}

pub fn decodeBrowseRequest(d: *encoding.Decoder) encoding.DecodeError!BrowseRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .view = try decodeViewDescription(d),
        .requested_max_references_per_node = try d.decodeUInt32(),
        .nodes_to_browse = try decodeArray(d, BrowseDescription, decodeBrowseDescription),
    };
}

pub fn freeBrowseRequest(a: std.mem.Allocator, v: BrowseRequest) void {
    freeRequestHeader(a, v.request_header);
    freeViewDescription(a, v.view);
    freeBrowseDescriptionArray(a, v.nodes_to_browse);
}

pub const ReferenceDescription = struct {
    reference_type_id: encoding.NodeId,
    is_forward: bool,
    node_id: encoding.ExpandedNodeId,
    browse_name: encoding.QualifiedName,
    display_name: encoding.LocalizedText,
    node_class: NodeClass,
    type_definition: encoding.ExpandedNodeId,
};

pub fn encodeReferenceDescription(e: *encoding.Encoder, v: ReferenceDescription) encoding.EncodeError!void {
    try e.encodeNodeId(v.reference_type_id);
    try e.encodeBoolean(v.is_forward);
    try e.encodeExpandedNodeId(v.node_id);
    try e.encodeQualifiedName(v.browse_name);
    try e.encodeLocalizedText(v.display_name);
    try encodeEnum(e, NodeClass, v.node_class);
    try e.encodeExpandedNodeId(v.type_definition);
}

pub fn decodeReferenceDescription(d: *encoding.Decoder) encoding.DecodeError!ReferenceDescription {
    return .{
        .reference_type_id = try d.decodeNodeId(),
        .is_forward = try d.decodeBoolean(),
        .node_id = try d.decodeExpandedNodeId(),
        .browse_name = try d.decodeQualifiedName(),
        .display_name = try d.decodeLocalizedText(),
        .node_class = try decodeEnum(d, NodeClass),
        .type_definition = try d.decodeExpandedNodeId(),
    };
}

pub fn freeReferenceDescription(a: std.mem.Allocator, v: ReferenceDescription) void {
    encoding.freeNodeId(a, v.reference_type_id);
    encoding.freeExpandedNodeId(a, v.node_id);
    encoding.freeQualifiedName(a, v.browse_name);
    encoding.freeLocalizedText(a, v.display_name);
    encoding.freeExpandedNodeId(a, v.type_definition);
}

pub const BrowseResult = struct {
    status_code: encoding.StatusCode,
    continuation_point: ?[]const u8,
    references: ?[]const ReferenceDescription,
};

pub fn encodeBrowseResult(e: *encoding.Encoder, v: BrowseResult) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status_code);
    try e.encodeByteString(v.continuation_point);
    try encodeArray(e, ReferenceDescription, v.references, encodeReferenceDescription);
}

pub fn decodeBrowseResult(d: *encoding.Decoder) encoding.DecodeError!BrowseResult {
    return .{
        .status_code = try d.decodeStatusCode(),
        .continuation_point = try d.decodeByteString(),
        .references = try decodeArray(d, ReferenceDescription, decodeReferenceDescription),
    };
}

pub fn freeBrowseResult(a: std.mem.Allocator, v: BrowseResult) void {
    freeOptStr(a, v.continuation_point);
    if (v.references) |items| {
        for (items) |r| freeReferenceDescription(a, r);
        a.free(items);
    }
}

fn freeBrowseResultArray(a: std.mem.Allocator, arr: ?[]const BrowseResult) void {
    if (arr) |items| {
        for (items) |it| freeBrowseResult(a, it);
        a.free(items);
    }
}

pub const BrowseResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const BrowseResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeBrowseResponse(e: *encoding.Encoder, v: BrowseResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, BrowseResult, v.results, encodeBrowseResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeBrowseResponse(d: *encoding.Decoder) encoding.DecodeError!BrowseResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, BrowseResult, decodeBrowseResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeBrowseResponse(a: std.mem.Allocator, v: BrowseResponse) void {
    freeResponseHeader(a, v.response_header);
    freeBrowseResultArray(a, v.results);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const BrowseNextRequest = struct {
    request_header: RequestHeader,
    release_continuation_points: bool,
    continuation_points: ?[]const ?[]const u8,
};

pub fn encodeBrowseNextRequest(e: *encoding.Encoder, v: BrowseNextRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeBoolean(v.release_continuation_points);
    try encodeArray(e, ?[]const u8, v.continuation_points, encodeStringItem);
}

pub fn decodeBrowseNextRequest(d: *encoding.Decoder) encoding.DecodeError!BrowseNextRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .release_continuation_points = try d.decodeBoolean(),
        .continuation_points = try decodeArray(d, ?[]const u8, decodeStringItem),
    };
}

pub fn freeBrowseNextRequest(a: std.mem.Allocator, v: BrowseNextRequest) void {
    freeRequestHeader(a, v.request_header);
    freeStringArray(a, v.continuation_points);
}

/// `BrowseNextResponse` is wire-identical in shape to `BrowseResponse` (same
/// `Results: BrowseResult[]` + `DiagnosticInfos` pair — OPC 10000-4 §5.8.3);
/// modeled as its own type (rather than a `const` alias) to keep every Part 4
/// response a distinct type `Channel.call`'s `comptime Response` parameter can
/// key on.
pub const BrowseNextResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const BrowseResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeBrowseNextResponse(e: *encoding.Encoder, v: BrowseNextResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, BrowseResult, v.results, encodeBrowseResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeBrowseNextResponse(d: *encoding.Decoder) encoding.DecodeError!BrowseNextResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, BrowseResult, decodeBrowseResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeBrowseNextResponse(a: std.mem.Allocator, v: BrowseNextResponse) void {
    freeResponseHeader(a, v.response_header);
    freeBrowseResultArray(a, v.results);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const CallMethodRequest = struct {
    object_id: encoding.NodeId,
    method_id: encoding.NodeId,
    input_arguments: ?[]const encoding.Variant,
};

fn freeVariantArray(a: std.mem.Allocator, arr: ?[]const encoding.Variant) void {
    if (arr) |items| {
        for (items) |v| encoding.freeVariant(a, v);
        a.free(items);
    }
}

pub fn encodeCallMethodRequest(e: *encoding.Encoder, v: CallMethodRequest) encoding.EncodeError!void {
    try e.encodeNodeId(v.object_id);
    try e.encodeNodeId(v.method_id);
    try encodeArray(e, encoding.Variant, v.input_arguments, encoding.Encoder.encodeVariant);
}

pub fn decodeCallMethodRequest(d: *encoding.Decoder) encoding.DecodeError!CallMethodRequest {
    return .{
        .object_id = try d.decodeNodeId(),
        .method_id = try d.decodeNodeId(),
        .input_arguments = try decodeArray(d, encoding.Variant, encoding.Decoder.decodeVariant),
    };
}

pub fn freeCallMethodRequest(a: std.mem.Allocator, v: CallMethodRequest) void {
    encoding.freeNodeId(a, v.object_id);
    encoding.freeNodeId(a, v.method_id);
    freeVariantArray(a, v.input_arguments);
}

fn freeCallMethodRequestArray(a: std.mem.Allocator, arr: ?[]const CallMethodRequest) void {
    if (arr) |items| {
        for (items) |it| freeCallMethodRequest(a, it);
        a.free(items);
    }
}

pub const CallRequest = struct {
    request_header: RequestHeader,
    methods_to_call: ?[]const CallMethodRequest,
};

pub fn encodeCallRequest(e: *encoding.Encoder, v: CallRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeArray(e, CallMethodRequest, v.methods_to_call, encodeCallMethodRequest);
}

pub fn decodeCallRequest(d: *encoding.Decoder) encoding.DecodeError!CallRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .methods_to_call = try decodeArray(d, CallMethodRequest, decodeCallMethodRequest),
    };
}

pub fn freeCallRequest(a: std.mem.Allocator, v: CallRequest) void {
    freeRequestHeader(a, v.request_header);
    freeCallMethodRequestArray(a, v.methods_to_call);
}

pub const CallMethodResult = struct {
    status_code: encoding.StatusCode,
    input_argument_results: ?[]const encoding.StatusCode,
    input_argument_diagnostic_infos: ?[]const encoding.DiagnosticInfo,
    output_arguments: ?[]const encoding.Variant,
};

pub fn encodeCallMethodResult(e: *encoding.Encoder, v: CallMethodResult) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status_code);
    try encodeArray(e, encoding.StatusCode, v.input_argument_results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.input_argument_diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
    try encodeArray(e, encoding.Variant, v.output_arguments, encoding.Encoder.encodeVariant);
}

pub fn decodeCallMethodResult(d: *encoding.Decoder) encoding.DecodeError!CallMethodResult {
    return .{
        .status_code = try d.decodeStatusCode(),
        .input_argument_results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .input_argument_diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
        .output_arguments = try decodeArray(d, encoding.Variant, encoding.Decoder.decodeVariant),
    };
}

pub fn freeCallMethodResult(a: std.mem.Allocator, v: CallMethodResult) void {
    if (v.input_argument_results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.input_argument_diagnostic_infos);
    freeVariantArray(a, v.output_arguments);
}

fn freeCallMethodResultArray(a: std.mem.Allocator, arr: ?[]const CallMethodResult) void {
    if (arr) |items| {
        for (items) |it| freeCallMethodResult(a, it);
        a.free(items);
    }
}

pub const CallResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const CallMethodResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeCallResponse(e: *encoding.Encoder, v: CallResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, CallMethodResult, v.results, encodeCallMethodResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeCallResponse(d: *encoding.Decoder) encoding.DecodeError!CallResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, CallMethodResult, decodeCallMethodResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeCallResponse(a: std.mem.Allocator, v: CallResponse) void {
    freeResponseHeader(a, v.response_header);
    freeCallMethodResultArray(a, v.results);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── Channel: chunked send/recv of one service call ──────────────────────────

/// Per-chunk body buffer and reassembly-scratch sizes. Sized comfortably
/// above open62541's (and most servers') default opc.tcp buffer negotiation
/// (64KiB) — F2's requests/responses (no subscriptions, no bulk Browse/Read)
/// never approach that in practice; splitting an outgoing request across
/// multiple chunks is out of scope here (see the module doc comment).
const max_chunk_body: usize = 65536;
const max_message_size: usize = 65536;

/// The low-level "send one service request, receive one service response"
/// helper `root.zig`'s `SecureChannel`/`Session` are built on: owns the
/// per-channel bookkeeping (channel/token ids, sequence/request-id
/// counters) and the OPN-vs-MSG/CLO security-header framing choice: OPN
/// carries the `AsymmetricAlgorithmSecurityHeader` (SecurityPolicyUri +
/// null sender-cert/receiver-thumbprint, SecurityMode=None never signs), MSG
/// and CLO carry the `SymmetricAlgorithmSecurityHeader` (just the u32
/// TokenId) — ground-truthed against open62541 (`UA_SecureChannel_
/// sendAsymmetricOPNMessage`/`sendSymmetricMessage`), OPC 10000-6 §6.7.2/
/// §7.2/§7.3 name the shapes but not which chunk types use which.
pub const Channel = struct {
    conn: *transport.Connection,
    allocator: std.mem.Allocator,
    channel_id: u32 = 0,
    token_id: u32 = 0,
    sequence_number: u32 = 0,
    request_id: u32 = 0,
    /// `ResponseHeader.service_result` (or a ServiceFault's) from the most
    /// recent call that returned `error.ServiceFault`/`error.BadServiceResult`.
    last_service_result: encoding.StatusCode = 0,

    /// Build a `RequestHeader` for the next outgoing call, bumping
    /// `request_handle` — reuses the same monotonic counter as `request_id`/
    /// `sequence_number`; nothing in Part 4 requires these to be tracked
    /// separately, and a single client-owned counter is simplest.
    pub fn nextRequestHeader(ch: *Channel, auth_token: encoding.NodeId, timeout_hint_ms: u32) RequestHeader {
        return .{
            .authentication_token = auth_token,
            // F2 sends a fixed 0 timestamp rather than reaching for a
            // platform clock: RequestHeader.Timestamp is advisory only (no
            // server in practice rejects a stale/zero client timestamp the
            // way TLS would), and `opcua`'s `meta.platform = .any` means
            // this module avoids a posix-only `clock_gettime` dependency.
            .timestamp = 0,
            .request_handle = ch.request_id + 1,
            .return_diagnostics = 0,
            .audit_entry_id = null,
            .timeout_hint = timeout_hint_ms,
            .additional_header = no_additional_header,
        };
    }

    /// Encode `request` behind `request_type_id`, wrap it in the
    /// Secure-Conversation + Sequence framing for `message_type`, and send
    /// it as a single final ('F') chunk (request-side chunk *splitting* for
    /// an oversize body is out of scope — see `max_chunk_body`).
    pub fn sendService(
        ch: *Channel,
        message_type: transport.MessageType,
        request_type_id: encoding.NodeId,
        comptime Request: type,
        request: Request,
        comptime encodeFn: fn (*encoding.Encoder, Request) encoding.EncodeError!void,
    ) ServiceError!void {
        var allocating = std.Io.Writer.Allocating.init(ch.allocator);
        defer allocating.deinit();
        var e = encoding.Encoder.init(&allocating.writer);

        try e.writer.writeInt(u32, ch.channel_id, .little);
        switch (message_type) {
            .open_secure_channel => {
                try e.encodeString(security_policy_none_uri);
                try e.encodeByteString(null); // SenderCertificate — none at SecurityMode=None
                try e.encodeByteString(null); // ReceiverCertificateThumbprint
            },
            .message, .close_secure_channel => {
                try e.writer.writeInt(u32, ch.token_id, .little);
            },
            else => unreachable, // service calls only ever ride OPN/MSG/CLO
        }

        ch.sequence_number += 1;
        ch.request_id += 1;
        try e.writer.writeInt(u32, ch.sequence_number, .little);
        try e.writer.writeInt(u32, ch.request_id, .little);

        try e.encodeNodeId(request_type_id);
        try encodeFn(&e, request);

        const body = allocating.writer.buffered();
        if (body.len > std.math.maxInt(u32) - 8) return error.MessageTooLarge;
        try ch.conn.sendChunk(.{
            .message_type = message_type,
            .chunk_type = .final,
            .message_size = 8 + @as(u32, @intCast(body.len)),
        }, body);
        try ch.conn.writer.flush();
    }

    /// Receive and reassemble one logical response (looping `recvChunk`
    /// through a `MessageChunkAssembler` — reused verbatim from `transport.
    /// zig` — until a final chunk lands), strip the Secure-Conversation +
    /// Sequence framing matching `message_type`, and decode the body. A
    /// `ServiceFault` type-id maps to `error.ServiceFault` (`last_service_
    /// result` carries its StatusCode); a Bad `service_result` on the
    /// expected response type maps to `error.BadServiceResult` (same
    /// field); a request-id mismatch or unexpected type-id is
    /// `error.UnexpectedResponseType`.
    pub fn recvService(
        ch: *Channel,
        message_type: transport.MessageType,
        comptime Response: type,
        response_type_id: encoding.NodeId,
        comptime decodeFn: fn (*encoding.Decoder) encoding.DecodeError!Response,
        comptime responseResult: fn (Response) encoding.StatusCode,
    ) ServiceError!Response {
        var scratch: [max_message_size]u8 = undefined;
        var assembler = transport.MessageChunkAssembler.init(&scratch);

        const full: []const u8 = while (true) {
            var chunk_buf: [max_chunk_body]u8 = undefined;
            const chunk = try ch.conn.recvChunk(&chunk_buf);
            if (chunk.header.message_type == .error_msg) return error.ServerError;
            if (chunk.header.message_type != message_type) return error.BadMessageType;
            if (try assembler.feed(chunk.header.chunk_type, chunk.body)) |msg| break msg;
        };

        var r: std.Io.Reader = .fixed(full);
        _ = try r.takeInt(u32, .little); // SecureChannelId (echoed back)
        switch (message_type) {
            .open_secure_channel => {
                var hd = encoding.Decoder.init(&r, ch.allocator);
                const uri = try hd.decodeString();
                defer freeOptStr(ch.allocator, uri);
                const cert = try hd.decodeByteString();
                defer freeOptStr(ch.allocator, cert);
                const thumb = try hd.decodeByteString();
                defer freeOptStr(ch.allocator, thumb);
            },
            .message, .close_secure_channel => {
                _ = try r.takeInt(u32, .little); // TokenId
            },
            else => unreachable,
        }
        _ = try r.takeInt(u32, .little); // SequenceNumber — not independently validated
        const request_id = try r.takeInt(u32, .little);
        if (request_id != ch.request_id) return error.UnexpectedResponseType;

        var d = encoding.Decoder.init(&r, ch.allocator);
        const resp_type = try d.decodeNodeId();
        if (nodeIdEql(resp_type, type_id.service_fault)) {
            const fault = try decodeServiceFault(&d);
            ch.last_service_result = fault.response_header.service_result;
            return error.ServiceFault;
        }
        if (!nodeIdEql(resp_type, response_type_id)) return error.UnexpectedResponseType;

        const resp = try decodeFn(&d);
        const result = responseResult(resp);
        if (isBad(result)) {
            ch.last_service_result = result;
            return error.BadServiceResult;
        }
        return resp;
    }

    /// `sendService` + `recvService` in one call — the shape every
    /// non-CLO service in this module uses (`SecureChannel.open`,
    /// `Session.create`/`.activate`/`.close`).
    pub fn call(
        ch: *Channel,
        message_type: transport.MessageType,
        request_type_id: encoding.NodeId,
        comptime Request: type,
        request: Request,
        comptime encodeFn: fn (*encoding.Encoder, Request) encoding.EncodeError!void,
        comptime Response: type,
        response_type_id: encoding.NodeId,
        comptime decodeFn: fn (*encoding.Decoder) encoding.DecodeError!Response,
        comptime responseResult: fn (Response) encoding.StatusCode,
    ) ServiceError!Response {
        try ch.sendService(message_type, request_type_id, Request, request, encodeFn);
        return ch.recvService(message_type, Response, response_type_id, decodeFn, responseResult);
    }
};

fn openSecureChannelResult(r: OpenSecureChannelResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn createSessionResult(r: CreateSessionResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn activateSessionResult(r: ActivateSessionResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn closeSessionResult(r: CloseSessionResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn readResult(r: ReadResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn writeResult(r: WriteResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn browseResponseResult(r: BrowseResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn browseNextResult(r: BrowseNextResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn callResult(r: CallResponse) encoding.StatusCode {
    return r.response_header.service_result;
}

pub const result_fns = struct {
    pub const open_secure_channel = openSecureChannelResult;
    pub const create_session = createSessionResult;
    pub const activate_session = activateSessionResult;
    pub const close_session = closeSessionResult;
    pub const read = readResult;
    pub const write = writeResult;
    pub const browse = browseResponseResult;
    pub const browse_next = browseNextResult;
    pub const call = callResult;
};

// ── tests ──

const testing = std.testing;

test "RequestHeader / ResponseHeader round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const rh: RequestHeader = .{
        .authentication_token = null_node_id,
        .timestamp = 0,
        .request_handle = 42,
        .return_diagnostics = 0,
        .audit_entry_id = null,
        .timeout_hint = 5000,
        .additional_header = no_additional_header,
    };
    try encodeRequestHeader(&e, rh);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeRequestHeader(&d);
    defer freeRequestHeader(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 42), decoded.request_handle);
    try testing.expectEqual(@as(u32, 5000), decoded.timeout_hint);
    try testing.expectEqual(@as(?[]const u8, null), decoded.audit_entry_id);
}

test "ResponseHeader: string_table round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const strs = [_]?[]const u8{ "a", "bb" };
    const rh: ResponseHeader = .{
        .timestamp = 7,
        .request_handle = 1,
        .service_result = 0,
        .service_diagnostics = .{},
        .string_table = &strs,
        .additional_header = no_additional_header,
    };
    try encodeResponseHeader(&e, rh);

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeResponseHeader(&d);
    defer freeResponseHeader(testing.allocator, decoded);
    try testing.expectEqual(@as(usize, 2), decoded.string_table.?.len);
    try testing.expectEqualStrings("a", decoded.string_table.?[0].?);
    try testing.expectEqualStrings("bb", decoded.string_table.?[1].?);
}

test "OpenSecureChannelRequest/Response round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const req: OpenSecureChannelRequest = .{
        .request_header = .{
            .authentication_token = null_node_id,
            .timestamp = 0,
            .request_handle = 1,
            .return_diagnostics = 0,
            .audit_entry_id = null,
            .timeout_hint = 0,
            .additional_header = no_additional_header,
        },
        .client_protocol_version = 0,
        .request_type = .issue,
        .security_mode = .none,
        .client_nonce = &.{},
        .requested_lifetime = 3_600_000,
    };
    try encodeOpenSecureChannelRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeOpenSecureChannelRequest(&d);
    defer freeOpenSecureChannelRequest(testing.allocator, decoded);
    try testing.expectEqual(SecurityTokenRequestType.issue, decoded.request_type);
    try testing.expectEqual(MessageSecurityMode.none, decoded.security_mode);
    try testing.expectEqual(@as(u32, 3_600_000), decoded.requested_lifetime);

    var buf2: [512]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const resp: OpenSecureChannelResponse = .{
        .response_header = .{
            .timestamp = 0,
            .request_handle = 1,
            .service_result = 0,
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = no_additional_header,
        },
        .server_protocol_version = 0,
        .security_token = .{ .channel_id = 7, .token_id = 3, .created_at = 0, .revised_lifetime = 3_600_000 },
        .server_nonce = &.{},
    };
    try encodeOpenSecureChannelResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeOpenSecureChannelResponse(&d2);
    defer freeOpenSecureChannelResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(u32, 7), decoded2.security_token.channel_id);
    try testing.expectEqual(@as(u32, 3), decoded2.security_token.token_id);
}

test "CreateSessionRequest/Response round-trip (incl. nested EndpointDescription)" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const req: CreateSessionRequest = .{
        .request_header = .{
            .authentication_token = null_node_id,
            .timestamp = 0,
            .request_handle = 2,
            .return_diagnostics = 0,
            .audit_entry_id = null,
            .timeout_hint = 0,
            .additional_header = no_additional_header,
        },
        .client_description = .{
            .application_uri = "urn:zig-libs:opcua:client",
            .product_uri = "urn:zig-libs:opcua",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua client" },
            .application_type = .client,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .server_uri = null,
        .endpoint_url = "opc.tcp://localhost:4840",
        .session_name = "test-session",
        .client_nonce = &.{},
        .client_certificate = null,
        .requested_session_timeout = 1_200_000.0,
        .max_response_message_size = 0,
    };
    try encodeCreateSessionRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCreateSessionRequest(&d);
    defer freeCreateSessionRequest(testing.allocator, decoded);
    try testing.expectEqualStrings("opc.tcp://localhost:4840", decoded.endpoint_url.?);
    try testing.expectEqual(ApplicationType.client, decoded.client_description.application_type);
    try testing.expectEqual(@as(f64, 1_200_000.0), decoded.requested_session_timeout);

    var buf2: [2048]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const endpoints = [_]EndpointDescription{.{
        .endpoint_url = "opc.tcp://localhost:4840",
        .server = .{
            .application_uri = "urn:open62541.server",
            .product_uri = null,
            .application_name = .{},
            .application_type = .server,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .server_certificate = null,
        .security_mode = .none,
        .security_policy_uri = security_policy_none_uri,
        .user_identity_tokens = &.{.{
            .policy_id = "open62541-anonymous-policy",
            .token_type = .anonymous,
            .issued_token_type = null,
            .issuer_endpoint_url = null,
            .security_policy_uri = null,
        }},
        .transport_profile_uri = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
        .security_level = 0,
    }};
    const resp: CreateSessionResponse = .{
        .response_header = .{
            .timestamp = 0,
            .request_handle = 2,
            .service_result = 0,
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = no_additional_header,
        },
        .session_id = .{ .numeric = .{ .namespace = 1, .id = 100 } },
        .authentication_token = .{ .guid = .{ .namespace = 0, .id = .{ .data1 = 1, .data2 = 2, .data3 = 3, .data4 = .{0} ** 8 } } },
        .revised_session_timeout = 1_200_000.0,
        .server_nonce = &.{ 1, 2, 3 },
        .server_certificate = null,
        .server_endpoints = &endpoints,
    };
    try encodeCreateSessionResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeCreateSessionResponse(&d2);
    defer freeCreateSessionResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(usize, 1), decoded2.server_endpoints.?.len);
    try testing.expectEqualStrings("open62541-anonymous-policy", decoded2.server_endpoints.?[0].user_identity_tokens.?[0].policy_id.?);
    try testing.expectEqual(UserTokenType.anonymous, decoded2.server_endpoints.?[0].user_identity_tokens.?[0].token_type);
}

test "ActivateSessionRequest/Response round-trip" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    var anon_buf: [64]u8 = undefined;
    var anon_w: std.Io.Writer = .fixed(&anon_buf);
    var anon_e = encoding.Encoder.init(&anon_w);
    try encodeAnonymousIdentityToken(&anon_e, .{ .policy_id = "anonymous" });

    const req: ActivateSessionRequest = .{
        .request_header = .{
            .authentication_token = .{ .numeric = .{ .namespace = 1, .id = 55 } },
            .timestamp = 0,
            .request_handle = 3,
            .return_diagnostics = 0,
            .audit_entry_id = null,
            .timeout_hint = 0,
            .additional_header = no_additional_header,
        },
        .client_signature = .{ .algorithm = null, .signature = null },
        .client_software_certificates = null,
        .locale_ids = null,
        .user_identity_token = .{ .type_id = type_id.anonymous_identity_token, .encoding = .byte_string, .body = anon_w.buffered() },
        .user_token_signature = .{ .algorithm = null, .signature = null },
    };
    try encodeActivateSessionRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeActivateSessionRequest(&d);
    defer freeActivateSessionRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(usize, 13), decoded.user_identity_token.body.len); // Int32 length prefix (4) + "anonymous" (9)

    var inner_r: std.Io.Reader = .fixed(decoded.user_identity_token.body);
    var inner_d = encoding.Decoder.init(&inner_r, testing.allocator);
    const anon = try decodeAnonymousIdentityToken(&inner_d);
    defer if (anon.policy_id) |p| testing.allocator.free(p);
    try testing.expectEqualStrings("anonymous", anon.policy_id.?);

    var buf2: [512]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const results = [_]encoding.StatusCode{0};
    const resp: ActivateSessionResponse = .{
        .response_header = .{
            .timestamp = 0,
            .request_handle = 3,
            .service_result = 0,
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = no_additional_header,
        },
        .server_nonce = &.{4},
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeActivateSessionResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeActivateSessionResponse(&d2);
    defer freeActivateSessionResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(usize, 1), decoded2.results.?.len);
    try testing.expectEqual(@as(encoding.StatusCode, 0), decoded2.results.?[0]);
}

test "ServiceFault decode + isBad" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const fault: ServiceFault = .{
        .response_header = .{
            .timestamp = 0,
            .request_handle = 9,
            .service_result = 0x80010000, // BadUnexpectedError-shaped
            .service_diagnostics = .{},
            .string_table = null,
            .additional_header = no_additional_header,
        },
    };
    try encodeServiceFault(&e, fault);
    try testing.expect(isBad(fault.response_header.service_result));

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeServiceFault(&d);
    defer freeServiceFault(testing.allocator, decoded);
    try testing.expectEqual(@as(encoding.StatusCode, 0x80010000), decoded.response_header.service_result);
    try testing.expect(isBad(decoded.response_header.service_result));
}

test "isBad: Good/Uncertain are not Bad" {
    try testing.expect(!isBad(0)); // Good
    try testing.expect(!isBad(0x40000000)); // Uncertain
    try testing.expect(isBad(0x80000000)); // Bad
    try testing.expect(isBad(0x80010000)); // BadUnexpectedError-shaped
}

test "CloseSessionRequest/Response + CloseSecureChannelRequest round-trip" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const req: CloseSessionRequest = .{
        .request_header = .{
            .authentication_token = .{ .numeric = .{ .namespace = 1, .id = 55 } },
            .timestamp = 0,
            .request_handle = 4,
            .return_diagnostics = 0,
            .audit_entry_id = null,
            .timeout_hint = 0,
            .additional_header = no_additional_header,
        },
        .delete_subscriptions = true,
    };
    try encodeCloseSessionRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCloseSessionRequest(&d);
    defer freeCloseSessionRequest(testing.allocator, decoded);
    try testing.expectEqual(true, decoded.delete_subscriptions);

    var buf2: [128]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const clo_req: CloseSecureChannelRequest = .{ .request_header = req.request_header };
    try encodeCloseSecureChannelRequest(&e2, clo_req);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const clo_decoded = try decodeCloseSecureChannelRequest(&d2);
    defer freeCloseSecureChannelRequest(testing.allocator, clo_decoded);
    try testing.expectEqual(@as(u32, 4), clo_decoded.request_header.request_handle);
}

test "sequence/request-id increment across sendService calls" {
    var pipe_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&pipe_buf);
    var r: std.Io.Reader = .fixed(&.{});
    var conn = transport.Connection.init(&r, &w);
    var ch: Channel = .{ .conn = &conn, .allocator = testing.allocator };

    const req1: CloseSecureChannelRequest = .{ .request_header = ch.nextRequestHeader(null_node_id, 0) };
    try ch.sendService(.close_secure_channel, type_id.close_secure_channel_request, CloseSecureChannelRequest, req1, encodeCloseSecureChannelRequest);
    try testing.expectEqual(@as(u32, 1), ch.sequence_number);
    try testing.expectEqual(@as(u32, 1), ch.request_id);

    const req2: CloseSecureChannelRequest = .{ .request_header = ch.nextRequestHeader(null_node_id, 0) };
    try ch.sendService(.close_secure_channel, type_id.close_secure_channel_request, CloseSecureChannelRequest, req2, encodeCloseSecureChannelRequest);
    try testing.expectEqual(@as(u32, 2), ch.sequence_number);
    try testing.expectEqual(@as(u32, 2), ch.request_id);
}

test "Channel.call: full OPN send + recv over an in-memory pipe, ServiceFault mapping" {
    // Simulate the server side by pre-rendering an OpenSecureChannelResponse
    // (or a ServiceFault) into the buffer the client's `Connection` reads
    // from, then drive `Channel.call` as the client would.
    const build_response = struct {
        fn ok(buf: []u8, request_id: u32) []u8 {
            var w: std.Io.Writer = .fixed(buf);
            var e = encoding.Encoder.init(&w);
            e.writer.writeInt(u32, 7, .little) catch unreachable; // SecureChannelId
            e.encodeString(security_policy_none_uri) catch unreachable;
            e.encodeByteString(null) catch unreachable;
            e.encodeByteString(null) catch unreachable;
            e.writer.writeInt(u32, 1, .little) catch unreachable; // SequenceNumber
            e.writer.writeInt(u32, request_id, .little) catch unreachable;
            e.encodeNodeId(type_id.open_secure_channel_response) catch unreachable;
            const resp: OpenSecureChannelResponse = .{
                .response_header = .{
                    .timestamp = 0,
                    .request_handle = 1,
                    .service_result = 0,
                    .service_diagnostics = .{},
                    .string_table = null,
                    .additional_header = no_additional_header,
                },
                .server_protocol_version = 0,
                .security_token = .{ .channel_id = 7, .token_id = 3, .created_at = 0, .revised_lifetime = 3_600_000 },
                .server_nonce = &.{},
            };
            encodeOpenSecureChannelResponse(&e, resp) catch unreachable;
            return w.buffered();
        }

        fn fault(buf: []u8, request_id: u32) []u8 {
            var w: std.Io.Writer = .fixed(buf);
            var e = encoding.Encoder.init(&w);
            e.writer.writeInt(u32, 7, .little) catch unreachable;
            e.encodeString(security_policy_none_uri) catch unreachable;
            e.encodeByteString(null) catch unreachable;
            e.encodeByteString(null) catch unreachable;
            e.writer.writeInt(u32, 1, .little) catch unreachable;
            e.writer.writeInt(u32, request_id, .little) catch unreachable;
            e.encodeNodeId(type_id.service_fault) catch unreachable;
            const sf: ServiceFault = .{ .response_header = .{
                .timestamp = 0,
                .request_handle = 1,
                .service_result = 0x80010000,
                .service_diagnostics = .{},
                .string_table = null,
                .additional_header = no_additional_header,
            } };
            encodeServiceFault(&e, sf) catch unreachable;
            return w.buffered();
        }
    };

    // Happy path.
    {
        var srv_body_buf: [512]u8 = undefined;
        const srv_body = build_response.ok(&srv_body_buf, 1);
        var srv_chunk_buf: [512]u8 = undefined;
        var srv_w: std.Io.Writer = .fixed(&srv_chunk_buf);
        var srv_conn = transport.Connection.init(undefined, &srv_w);
        try srv_conn.sendChunk(.{ .message_type = .open_secure_channel, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(srv_body.len)) }, srv_body);

        var out_buf: [512]u8 = undefined;
        var out_w: std.Io.Writer = .fixed(&out_buf);
        var in_r: std.Io.Reader = .fixed(srv_w.buffered());
        var conn = transport.Connection.init(&in_r, &out_w);
        var ch: Channel = .{ .conn = &conn, .allocator = testing.allocator };

        const req: OpenSecureChannelRequest = .{
            .request_header = ch.nextRequestHeader(null_node_id, 0),
            .client_protocol_version = 0,
            .request_type = .issue,
            .security_mode = .none,
            .client_nonce = &.{},
            .requested_lifetime = 3_600_000,
        };
        const resp = try Channel.call(
            &ch,
            .open_secure_channel,
            type_id.open_secure_channel_request,
            OpenSecureChannelRequest,
            req,
            encodeOpenSecureChannelRequest,
            OpenSecureChannelResponse,
            type_id.open_secure_channel_response,
            decodeOpenSecureChannelResponse,
            result_fns.open_secure_channel,
        );
        defer freeOpenSecureChannelResponse(testing.allocator, resp);
        try testing.expectEqual(@as(u32, 7), resp.security_token.channel_id);
        try testing.expectEqual(@as(u32, 3), resp.security_token.token_id);
    }

    // ServiceFault path.
    {
        var srv_body_buf: [256]u8 = undefined;
        const srv_body = build_response.fault(&srv_body_buf, 1);
        var srv_chunk_buf: [256]u8 = undefined;
        var srv_w: std.Io.Writer = .fixed(&srv_chunk_buf);
        var srv_conn = transport.Connection.init(undefined, &srv_w);
        try srv_conn.sendChunk(.{ .message_type = .open_secure_channel, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(srv_body.len)) }, srv_body);

        var out_buf: [512]u8 = undefined;
        var out_w: std.Io.Writer = .fixed(&out_buf);
        var in_r: std.Io.Reader = .fixed(srv_w.buffered());
        var conn = transport.Connection.init(&in_r, &out_w);
        var ch: Channel = .{ .conn = &conn, .allocator = testing.allocator };

        const req: OpenSecureChannelRequest = .{
            .request_header = ch.nextRequestHeader(null_node_id, 0),
            .client_protocol_version = 0,
            .request_type = .issue,
            .security_mode = .none,
            .client_nonce = &.{},
            .requested_lifetime = 3_600_000,
        };
        try testing.expectError(error.ServiceFault, Channel.call(
            &ch,
            .open_secure_channel,
            type_id.open_secure_channel_request,
            OpenSecureChannelRequest,
            req,
            encodeOpenSecureChannelRequest,
            OpenSecureChannelResponse,
            type_id.open_secure_channel_response,
            decodeOpenSecureChannelResponse,
            result_fns.open_secure_channel,
        ));
        try testing.expectEqual(@as(encoding.StatusCode, 0x80010000), ch.last_service_result);
    }
}

// ── Part 4 (Read/Write/Browse/BrowseNext/Call) tests ────────────────────────

test "AttributeId/TimestampsToReturn/BrowseDirection/NodeClass: ground-truthed constant values" {
    // OPC Foundation UA-Nodeset Schema/AttributeIds.csv + Opc.Ua.Types.bsd,
    // fetched directly during implementation (see the Part 4 section's doc
    // comment) rather than inferred from memory.
    try testing.expectEqual(@as(u32, 13), attribute_id.value);
    try testing.expectEqual(@as(u32, 1), attribute_id.node_id);
    try testing.expectEqual(@as(u32, 27), attribute_id.access_level_ex);
    try testing.expectEqual(@as(u32, 0), @intFromEnum(TimestampsToReturn.source));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(TimestampsToReturn.both));
    try testing.expectEqual(@as(u32, 0), @intFromEnum(BrowseDirection.forward));
    try testing.expectEqual(@as(u32, 1), @intFromEnum(NodeClass.object));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(NodeClass.variable));
}

test "ReadValueId/ReadRequest/ReadResponse round-trip (incl. Variant-array DataValue)" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const nodes = [_]ReadValueId{
        .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2258 } }, .attribute_id = attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
        .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2255 } }, .attribute_id = attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
    };
    const req: ReadRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .max_age = 0,
        .timestamps_to_return = .both,
        .nodes_to_read = &nodes,
    };
    try encodeReadRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeReadRequest(&d);
    defer freeReadRequest(testing.allocator, decoded);
    try testing.expectEqual(TimestampsToReturn.both, decoded.timestamps_to_return);
    try testing.expectEqual(@as(usize, 2), decoded.nodes_to_read.?.len);
    try testing.expectEqual(attribute_id.value, decoded.nodes_to_read.?[0].attribute_id);

    var buf2: [1024]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const ns_array = [_]?[]const u8{ "http://opcfoundation.org/UA/", "urn:example" };
    const results = [_]encoding.DataValue{
        .{ .value = .{ .scalar = .{ .date_time = 132223104000000000 } }, .status = 0 },
        .{ .value = .{ .array = .{ .items = .{ .string = &ns_array } } }, .status = 0 },
    };
    const resp: ReadResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeReadResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeReadResponse(&d2);
    defer freeReadResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(usize, 2), decoded2.results.?.len);
    try testing.expectEqual(@as(encoding.DateTime, 132223104000000000), decoded2.results.?[0].value.?.scalar.date_time);
    const got_ns = decoded2.results.?[1].value.?.array.items.string.?;
    try testing.expectEqualStrings("http://opcfoundation.org/UA/", got_ns[0].?);
    try testing.expectEqualStrings("urn:example", got_ns[1].?);
}

test "WriteValue/WriteRequest/WriteResponse round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const nodes = [_]WriteValue{.{
        .node_id = .{ .numeric = .{ .namespace = 2, .id = 42 } },
        .attribute_id = attribute_id.value,
        .index_range = null,
        .value = .{ .value = .{ .scalar = .{ .double = 3.5 } } },
    }};
    const req: WriteRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .nodes_to_write = &nodes,
    };
    try encodeWriteRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeWriteRequest(&d);
    defer freeWriteRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(f64, 3.5), decoded.nodes_to_write.?[0].value.value.?.scalar.double);

    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const results = [_]encoding.StatusCode{ 0, 0x80740000 }; // BadNotWritable-shaped
    const resp: WriteResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeWriteResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeWriteResponse(&d2);
    defer freeWriteResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(usize, 2), decoded2.results.?.len);
    try testing.expect(isBad(decoded2.results.?[1]));
}

test "ViewDescription/BrowseDescription/BrowseRequest round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const nodes = [_]BrowseDescription{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 85 } }, // Objects folder
        .browse_direction = .forward,
        .reference_type_id = null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = 0x3f,
    }};
    const req: BrowseRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .view = no_view,
        .requested_max_references_per_node = 0,
        .nodes_to_browse = &nodes,
    };
    try encodeBrowseRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeBrowseRequest(&d);
    defer freeBrowseRequest(testing.allocator, decoded);
    try testing.expectEqual(BrowseDirection.forward, decoded.nodes_to_browse.?[0].browse_direction);
    try testing.expectEqual(@as(u32, 0x3f), decoded.nodes_to_browse.?[0].result_mask);
}

test "ReferenceDescription/BrowseResult/BrowseResponse round-trip (nested references)" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const refs = [_]ReferenceDescription{.{
        .reference_type_id = .{ .numeric = .{ .namespace = 0, .id = 35 } }, // Organizes
        .is_forward = true,
        .node_id = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2253 } } }, // Server
        .browse_name = .{ .namespace_index = 0, .name = "Server" },
        .display_name = .{ .locale = "en", .text = "Server" },
        .node_class = .object,
        .type_definition = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2004 } } },
    }};
    const results = [_]BrowseResult{.{
        .status_code = 0,
        .continuation_point = null,
        .references = &refs,
    }};
    const resp: BrowseResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeBrowseResponse(&e, resp);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeBrowseResponse(&d);
    defer freeBrowseResponse(testing.allocator, decoded);
    try testing.expectEqual(@as(usize, 1), decoded.results.?.len);
    const got_refs = decoded.results.?[0].references.?;
    try testing.expectEqual(@as(usize, 1), got_refs.len);
    try testing.expectEqualStrings("Server", got_refs[0].browse_name.name.?);
    try testing.expectEqualStrings("Server", got_refs[0].display_name.text.?);
    try testing.expectEqual(NodeClass.object, got_refs[0].node_class);
    try testing.expectEqualDeep(refs[0].node_id, got_refs[0].node_id);
}

test "BrowseNextRequest/BrowseNextResponse round-trip (paging a continuation point)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const cps = [_]?[]const u8{"\x01\x02\x03"};
    const req: BrowseNextRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .release_continuation_points = false,
        .continuation_points = &cps,
    };
    try encodeBrowseNextRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeBrowseNextRequest(&d);
    defer freeBrowseNextRequest(testing.allocator, decoded);
    try testing.expectEqual(false, decoded.release_continuation_points);
    try testing.expectEqualSlices(u8, "\x01\x02\x03", decoded.continuation_points.?[0].?);

    var buf2: [512]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const results = [_]BrowseResult{.{ .status_code = 0, .continuation_point = null, .references = null }};
    const resp: BrowseNextResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeBrowseNextResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeBrowseNextResponse(&d2);
    defer freeBrowseNextResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(usize, 1), decoded2.results.?.len);
}

test "CallMethodRequest/CallRequest round-trip (Variant input arguments)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const args = [_]encoding.Variant{
        .{ .scalar = .{ .int32 = 42 } },
        .{ .array = .{ .items = .{ .double = &[_]f64{ 1.5, 2.5 } } } },
    };
    const methods = [_]CallMethodRequest{.{
        .object_id = .{ .numeric = .{ .namespace = 1, .id = 100 } },
        .method_id = .{ .numeric = .{ .namespace = 1, .id = 101 } },
        .input_arguments = &args,
    }};
    const req: CallRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .methods_to_call = &methods,
    };
    try encodeCallRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCallRequest(&d);
    defer freeCallRequest(testing.allocator, decoded);
    const got_args = decoded.methods_to_call.?[0].input_arguments.?;
    try testing.expectEqual(@as(i32, 42), got_args[0].scalar.int32);
    try testing.expectEqualSlices(f64, &[_]f64{ 1.5, 2.5 }, got_args[1].array.items.double.?);
}

test "CallMethodResult/CallResponse round-trip (nested StatusCode/Variant arrays)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const input_results = [_]encoding.StatusCode{ 0, 0 };
    const output_args = [_]encoding.Variant{.{ .scalar = .{ .boolean = true } }};
    const results = [_]CallMethodResult{.{
        .status_code = 0,
        .input_argument_results = &input_results,
        .input_argument_diagnostic_infos = null,
        .output_arguments = &output_args,
    }};
    const resp: CallResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeCallResponse(&e, resp);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCallResponse(&d);
    defer freeCallResponse(testing.allocator, decoded);
    try testing.expectEqual(@as(usize, 2), decoded.results.?[0].input_argument_results.?.len);
    try testing.expectEqual(true, decoded.results.?[0].output_arguments.?[0].scalar.boolean);
}

test "ServiceFault-shaped ReadResponse: BadServiceResult surfaces via isBad" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const resp: ReadResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0x80390000, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = null,
        .diagnostic_infos = null,
    };
    try encodeReadResponse(&e, resp);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeReadResponse(&d);
    defer freeReadResponse(testing.allocator, decoded);
    try testing.expect(isBad(decoded.response_header.service_result));
}
