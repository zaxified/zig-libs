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
};

// ── enumerations (OPC 10000-4, encoded as OPC 10000-6 §5.1.3 4-byte
// enumerations — this module writes/reads them as plain `u32`s: the bit
// pattern is identical to Int32 for every value these enums actually use) ──

pub const SecurityTokenRequestType = enum(u32) { issue = 0, renew = 1 };
pub const MessageSecurityMode = enum(u32) { invalid = 0, none = 1, sign = 2, sign_and_encrypt = 3 };
pub const ApplicationType = enum(u32) { server = 0, client = 1, client_and_server = 2, discovery_server = 3 };
pub const UserTokenType = enum(u32) { anonymous = 0, user_name = 1, certificate = 2, issued_token = 3 };

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

fn freeDiagnosticInfo(a: std.mem.Allocator, di: encoding.DiagnosticInfo) void {
    freeOptStr(a, di.additional_info);
    if (di.inner_diagnostic_info) |p| {
        freeDiagnosticInfo(a, p.*);
        a.destroy(p);
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

pub const result_fns = struct {
    pub const open_secure_channel = openSecureChannelResult;
    pub const create_session = createSessionResult;
    pub const activate_session = activateSessionResult;
    pub const close_session = closeSessionResult;
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
