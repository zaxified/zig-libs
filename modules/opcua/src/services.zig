// SPDX-License-Identifier: MIT

//! OPC UA service framing (OPC 10000-4) — the `RequestHeader`/`ResponseHeader`
//! envelope every service call rides in, the array-of-struct wire pattern
//! (Int32 count + elements, `-1` = null array — OPC UA Binary's array
//! convention, used throughout Part 4) hand-rolled here since `encoding.zig`'s
//! array support is scoped to `Variant` elements (a different, narrower case:
//! a homogeneous array of one built-in scalar type, not an arbitrary struct),
//! plus the concrete request/response structures F2 needs:
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
const security = @import("security.zig");

pub const ServiceError = encoding.EncodeError || encoding.DecodeError || transport.TransportError ||
    security.SealAsymmetricError || security.OpenAsymmetricError || security.SymmetricDecryptAndVerifyError || error{
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

/// `SecurityPolicy#None`'s URI (OPC 10000-7 §6.2.1) — the SecurityPolicy the
/// default (SecurityMode=None) code path speaks; the secure policies live in
/// `security.SecurityPolicy.uri()`.
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

/// `NodeId` structural equality — used both by `Channel.recvService` (to
/// match a response's leading type-id) and, from `root.zig`, to classify a
/// `NotificationMessage`'s `NotificationData` `ExtensionObject`s by their
/// `TypeId` (DataChangeNotification/StatusChangeNotification/
/// EventNotificationList — OPC 10000-4 §5.13.5).
pub fn nodeIdEql(a: encoding.NodeId, b: encoding.NodeId) bool {
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

    // ── Part 5: subscriptions / monitored items / Publish (OPC 10000-4 §5.12/
    // §5.13) — same source as the block above, fetched directly from the OPC
    // Foundation `Schema/NodeIds.csv` during implementation.
    pub const create_monitored_items_request = n0(751);
    pub const create_monitored_items_response = n0(754);
    pub const delete_monitored_items_request = n0(781);
    pub const delete_monitored_items_response = n0(784);
    pub const create_subscription_request = n0(787);
    pub const create_subscription_response = n0(790);
    pub const modify_subscription_request = n0(793);
    pub const modify_subscription_response = n0(796);
    pub const set_publishing_mode_request = n0(799);
    pub const set_publishing_mode_response = n0(802);
    /// The `NotificationData` union's concrete members — these ride as the
    /// `TypeId` of an `ExtensionObject` inside `NotificationMessage.
    /// NotificationData`, never as a top-level MSG body, but belong in this
    /// well-known-ids table alongside the others.
    pub const data_change_notification = n0(811);
    pub const status_change_notification = n0(820);
    pub const event_notification_list = n0(916);
    pub const publish_request = n0(826);
    pub const publish_response = n0(829);
    pub const republish_request = n0(832);
    pub const republish_response = n0(835);
    pub const delete_subscriptions_request = n0(847);
    pub const delete_subscriptions_response = n0(850);

    // ── discovery + the services the server side answers that the client
    // half never sends (same `Schema/NodeIds.csv` source as above).
    pub const find_servers_request = n0(422);
    pub const find_servers_response = n0(425);
    pub const get_endpoints_request = n0(428);
    pub const get_endpoints_response = n0(431);
    pub const translate_browse_paths_to_node_ids_request = n0(554);
    pub const translate_browse_paths_to_node_ids_response = n0(557);
    pub const modify_monitored_items_request = n0(763);
    pub const modify_monitored_items_response = n0(766);
    pub const set_monitoring_mode_request = n0(769);
    pub const set_monitoring_mode_response = n0(772);
    /// The identity-token `ExtensionObject` TypeIds an `ActivateSessionRequest.
    /// UserIdentityToken` can carry (§7.36).
    pub const user_name_identity_token = n0(324);
    pub const x509_identity_token = n0(327);
    pub const issued_identity_token = n0(940);
};

/// The StatusCodes this module names (OPC Foundation UA-Nodeset
/// `Schema/StatusCode.csv`, MIT License 1.00 — fetched directly, same
/// provenance as `type_id`). Only the ones the client maps or the server
/// answers with are listed; a code absent here is still a perfectly valid
/// `encoding.StatusCode` on the wire.
pub const status = struct {
    pub const good: encoding.StatusCode = 0;
    pub const bad_internal_error: encoding.StatusCode = 0x8002_0000;
    pub const bad_out_of_memory: encoding.StatusCode = 0x8003_0000;
    pub const bad_encoding_error: encoding.StatusCode = 0x8006_0000;
    pub const bad_decoding_error: encoding.StatusCode = 0x8007_0000;
    pub const bad_encoding_limits_exceeded: encoding.StatusCode = 0x8008_0000;
    pub const bad_service_unsupported: encoding.StatusCode = 0x800B_0000;
    pub const bad_nothing_to_do: encoding.StatusCode = 0x800F_0000;
    pub const bad_too_many_operations: encoding.StatusCode = 0x8010_0000;
    pub const bad_security_checks_failed: encoding.StatusCode = 0x8013_0000;
    pub const bad_certificate_invalid: encoding.StatusCode = 0x8012_0000;
    pub const bad_certificate_time_invalid: encoding.StatusCode = 0x8014_0000;
    pub const bad_certificate_uri_invalid: encoding.StatusCode = 0x8017_0000;
    pub const bad_certificate_use_not_allowed: encoding.StatusCode = 0x8018_0000;
    pub const bad_certificate_untrusted: encoding.StatusCode = 0x801A_0000;
    pub const bad_user_access_denied: encoding.StatusCode = 0x801F_0000;
    pub const bad_identity_token_invalid: encoding.StatusCode = 0x8020_0000;
    pub const bad_identity_token_rejected: encoding.StatusCode = 0x8021_0000;
    pub const bad_secure_channel_id_invalid: encoding.StatusCode = 0x8022_0000;
    pub const bad_nonce_invalid: encoding.StatusCode = 0x8024_0000;
    pub const bad_session_id_invalid: encoding.StatusCode = 0x8025_0000;
    pub const bad_session_closed: encoding.StatusCode = 0x8026_0000;
    pub const bad_session_not_activated: encoding.StatusCode = 0x8027_0000;
    pub const bad_subscription_id_invalid: encoding.StatusCode = 0x8028_0000;
    pub const bad_request_header_invalid: encoding.StatusCode = 0x802A_0000;
    pub const bad_timestamps_to_return_invalid: encoding.StatusCode = 0x802B_0000;
    pub const bad_node_id_invalid: encoding.StatusCode = 0x8033_0000;
    pub const bad_node_id_unknown: encoding.StatusCode = 0x8034_0000;
    pub const bad_attribute_id_invalid: encoding.StatusCode = 0x8035_0000;
    pub const bad_index_range_invalid: encoding.StatusCode = 0x8036_0000;
    pub const bad_data_encoding_invalid: encoding.StatusCode = 0x8038_0000;
    pub const bad_not_readable: encoding.StatusCode = 0x803A_0000;
    pub const bad_not_writable: encoding.StatusCode = 0x803B_0000;
    pub const bad_not_supported: encoding.StatusCode = 0x803D_0000;
    pub const bad_not_implemented: encoding.StatusCode = 0x8040_0000;
    pub const bad_monitoring_mode_invalid: encoding.StatusCode = 0x8041_0000;
    pub const bad_monitored_item_id_invalid: encoding.StatusCode = 0x8042_0000;
    pub const bad_monitored_item_filter_unsupported: encoding.StatusCode = 0x8044_0000;
    pub const bad_continuation_point_invalid: encoding.StatusCode = 0x804A_0000;
    pub const bad_no_continuation_points: encoding.StatusCode = 0x804B_0000;
    pub const bad_reference_type_id_invalid: encoding.StatusCode = 0x804C_0000;
    pub const bad_browse_direction_invalid: encoding.StatusCode = 0x804D_0000;
    pub const bad_view_id_unknown: encoding.StatusCode = 0x806B_0000;
    pub const bad_security_mode_rejected: encoding.StatusCode = 0x8054_0000;
    pub const bad_security_policy_rejected: encoding.StatusCode = 0x8055_0000;
    pub const bad_too_many_sessions: encoding.StatusCode = 0x8056_0000;
    pub const bad_user_signature_invalid: encoding.StatusCode = 0x8057_0000;
    pub const bad_application_signature_invalid: encoding.StatusCode = 0x8058_0000;
    pub const bad_no_match: encoding.StatusCode = 0x806F_0000;
    pub const bad_type_mismatch: encoding.StatusCode = 0x8074_0000;
    pub const bad_method_invalid: encoding.StatusCode = 0x8075_0000;
    pub const bad_arguments_missing: encoding.StatusCode = 0x8076_0000;
    pub const bad_too_many_subscriptions: encoding.StatusCode = 0x8077_0000;
    pub const bad_too_many_publish_requests: encoding.StatusCode = 0x8078_0000;
    pub const bad_no_subscription: encoding.StatusCode = 0x8079_0000;
    pub const bad_sequence_number_unknown: encoding.StatusCode = 0x807A_0000;
    pub const bad_message_not_available: encoding.StatusCode = 0x807B_0000;
    pub const bad_timeout: encoding.StatusCode = 0x800A_0000;
    pub const bad_invalid_argument: encoding.StatusCode = 0x80AB_0000;
    pub const bad_invalid_state: encoding.StatusCode = 0x80AF_0000;
    pub const bad_not_executable: encoding.StatusCode = 0x8111_0000;
    pub const bad_too_many_monitored_items: encoding.StatusCode = 0x80DB_0000;
    pub const bad_too_many_arguments: encoding.StatusCode = 0x80E5_0000;
    pub const bad_protocol_version_unsupported: encoding.StatusCode = 0x80BE_0000;
    // opc.tcp transport-level codes (§7.1.4's `Error` message body).
    pub const bad_tcp_message_type_invalid: encoding.StatusCode = 0x807E_0000;
    pub const bad_tcp_secure_channel_unknown: encoding.StatusCode = 0x807F_0000;
    pub const bad_tcp_message_too_large: encoding.StatusCode = 0x8080_0000;
    pub const bad_tcp_not_enough_resources: encoding.StatusCode = 0x8081_0000;
    pub const bad_tcp_internal_error: encoding.StatusCode = 0x8082_0000;
    pub const bad_tcp_endpoint_url_invalid: encoding.StatusCode = 0x8083_0000;
    pub const bad_secure_channel_closed: encoding.StatusCode = 0x8086_0000;
    pub const bad_secure_channel_token_unknown: encoding.StatusCode = 0x8087_0000;
    pub const bad_sequence_number_invalid: encoding.StatusCode = 0x8088_0000;
};

/// The `SecurityPolicy#Basic256Sha256` URI, spelled once (the enum
/// `security.SecurityPolicy.uri()` returns the same string; this constant
/// exists so `services`/`server` can compare a wire URI without importing
/// the security layer just for a string).
pub const security_policy_basic256sha256_uri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

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
/// OPC 10000-4 §5.12.1.2 (`MonitoredItemCreateRequest.MonitoringMode`) —
/// ground-truthed against the OPC Foundation schema's `MonitoringMode`
/// `EnumeratedType`.
pub const MonitoringMode = enum(u32) { disabled = 0, sampling = 1, reporting = 2 };

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
    // Do NOT `initCapacity(n)` on the raw claimed count: `n` is any i32 up to
    // 0x7FFFFFFF read straight off the wire, so a 5-byte message could force a
    // multi-GiB allocation (OOM DoS). Grow the list element-by-element instead
    // — every element consumes >=1 byte of input, so a hostile huge claim
    // fails on `EndOfStream` reading the first missing element (exactly as
    // `encoding.decodeString` fails on `take`) long before the list grows.
    var list: std.ArrayList(T) = .empty;
    errdefer list.deinit(d.allocator);
    for (0..n) |_| try list.append(d.allocator, try decodeItem(d));
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

/// Skip one Int32-length-prefixed String/ByteString without allocating,
/// returning the bytes it covered (`null` for the wire's `-1` null form) —
/// used by `Channel.recvService` to step over an
/// `AsymmetricAlgorithmSecurityHeader`'s three fields per chunk.
fn skipLengthPrefixed(r: *std.Io.Reader) encoding.DecodeError!?[]const u8 {
    const len = try r.takeInt(i32, .little);
    if (len == -1) return null;
    if (len < -1) return error.BadLength;
    return try r.take(@intCast(len));
}

fn freeStringArray(a: std.mem.Allocator, arr: ?[]const ?[]const u8) void {
    if (arr) |items| {
        for (items) |s| freeOptStr(a, s);
        a.free(items);
    }
}

pub fn freeDiagnosticInfo(a: std.mem.Allocator, di: encoding.DiagnosticInfo) void {
    freeOptStr(a, di.additional_info);
    // Walk the inner-diagnostic chain iteratively rather than recursively:
    // even though the decoder now caps nesting depth (see
    // `encoding.max_diagnostic_depth`), an iterative free is stack-safe no
    // matter how the tree was built, matching the decoder's DoS hardening.
    var next = di.inner_diagnostic_info;
    while (next) |p| {
        freeOptStr(a, p.additional_info);
        next = p.inner_diagnostic_info;
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
    // The AuthenticationToken owns memory whenever the server issued a
    // String/Opaque identifier — which is the normal case (this module's own
    // `server.zig` issues a 32-byte opaque token). Only a *decoded*
    // RequestHeader should be handed here; the ones this module's client
    // builds borrow their fields and are never freed.
    encoding.freeNodeId(a, v.authentication_token);
    encoding.freeNodeId(a, v.additional_header.type_id);
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

/// Public alias of the internal software-certificate array free — a caller
/// that keeps part of a `CreateSessionResponse` (as `root.Session.create`
/// does) needs to free the rest field by field.
pub fn freeSignedSoftwareCertificateArray(a: std.mem.Allocator, arr: ?[]const SignedSoftwareCertificate) void {
    freeSoftwareCertArray(a, arr);
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

/// The trailing three fields (`ServerSoftwareCertificates`,
/// `ServerSignature`, `MaxRequestMessageSize`) carry nothing this module's
/// SecurityMode=None client acts on — but they are *structurally mandatory*
/// on the wire: a third-party client decoding a response that stops after
/// `ServerEndpoints` hits end-of-buffer. They therefore have defaults (a
/// client constructing this struct can keep ignoring them) and are always
/// encoded/decoded (the server side must emit them; the client side must
/// tolerate a real server's).
pub const CreateSessionResponse = struct {
    response_header: ResponseHeader,
    session_id: encoding.NodeId,
    authentication_token: encoding.NodeId,
    revised_session_timeout: f64,
    server_nonce: ?[]const u8,
    server_certificate: ?[]const u8,
    server_endpoints: ?[]const EndpointDescription,
    server_software_certificates: ?[]const SignedSoftwareCertificate = null,
    server_signature: SignatureData = .{ .algorithm = null, .signature = null },
    /// 0 = no limit (OPC 10000-4 §5.6.2.2).
    max_request_message_size: u32 = 0,
};

pub fn encodeCreateSessionResponse(e: *encoding.Encoder, v: CreateSessionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.encodeNodeId(v.session_id);
    try e.encodeNodeId(v.authentication_token);
    try e.encodeDouble(v.revised_session_timeout);
    try e.encodeByteString(v.server_nonce);
    try e.encodeByteString(v.server_certificate);
    try encodeArray(e, EndpointDescription, v.server_endpoints, encodeEndpointDescription);
    try encodeArray(e, SignedSoftwareCertificate, v.server_software_certificates, encodeSignedSoftwareCertificate);
    try encodeSignatureData(e, v.server_signature);
    try e.encodeUInt32(v.max_request_message_size);
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
        .server_software_certificates = try decodeArray(d, SignedSoftwareCertificate, decodeSignedSoftwareCertificate),
        .server_signature = try decodeSignatureData(d),
        .max_request_message_size = try d.decodeUInt32(),
    };
}

pub fn freeCreateSessionResponse(a: std.mem.Allocator, v: CreateSessionResponse) void {
    freeResponseHeader(a, v.response_header);
    freeOptStr(a, v.server_nonce);
    freeOptStr(a, v.server_certificate);
    freeEndpointArray(a, v.server_endpoints);
    freeSoftwareCertArray(a, v.server_software_certificates);
    freeSignatureData(a, v.server_signature);
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

// ── Part 5: subscriptions / monitored items / Publish (OPC 10000-4 §5.12/
// §5.13) ─────────────────────────────────────────────────────────────────────
// Field order for every structure below is ground-truthed the same way Part 4
// was: the OPC Foundation's `Schema/Opc.Ua.Types.bsd`, fetched directly during
// implementation (`CreateSubscriptionRequest`, `MonitoringParameters`,
// `MonitoredItemCreateRequest`/`Result`, `PublishRequest`/`Response`,
// `NotificationMessage`, `DataChangeNotification`/`StatusChangeNotification`/
// `EventNotificationList` all confirmed against that schema's `StructuredType`
// definitions, not inferred from the prose spec).

fn freeU32Array(a: std.mem.Allocator, arr: ?[]const u32) void {
    if (arr) |items| a.free(items);
}

fn encodeU32Item(e: *encoding.Encoder, v: u32) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v, .little);
}
fn decodeU32Item(d: *encoding.Decoder) encoding.DecodeError!u32 {
    return d.decodeUInt32();
}

// ── CreateSubscription (§5.13.2) ─────────────────────────────────────────────

pub const CreateSubscriptionRequest = struct {
    request_header: RequestHeader,
    requested_publishing_interval: f64,
    requested_lifetime_count: u32,
    requested_max_keep_alive_count: u32,
    max_notifications_per_publish: u32,
    publishing_enabled: bool,
    priority: u8,
};

pub fn encodeCreateSubscriptionRequest(e: *encoding.Encoder, v: CreateSubscriptionRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeDouble(v.requested_publishing_interval);
    try e.writer.writeInt(u32, v.requested_lifetime_count, .little);
    try e.writer.writeInt(u32, v.requested_max_keep_alive_count, .little);
    try e.writer.writeInt(u32, v.max_notifications_per_publish, .little);
    try e.encodeBoolean(v.publishing_enabled);
    try e.encodeByte(v.priority);
}

pub fn decodeCreateSubscriptionRequest(d: *encoding.Decoder) encoding.DecodeError!CreateSubscriptionRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .requested_publishing_interval = try d.decodeDouble(),
        .requested_lifetime_count = try d.decodeUInt32(),
        .requested_max_keep_alive_count = try d.decodeUInt32(),
        .max_notifications_per_publish = try d.decodeUInt32(),
        .publishing_enabled = try d.decodeBoolean(),
        .priority = try d.decodeByte(),
    };
}

pub fn freeCreateSubscriptionRequest(a: std.mem.Allocator, v: CreateSubscriptionRequest) void {
    freeRequestHeader(a, v.request_header);
}

pub const CreateSubscriptionResponse = struct {
    response_header: ResponseHeader,
    subscription_id: u32,
    revised_publishing_interval: f64,
    revised_lifetime_count: u32,
    revised_max_keep_alive_count: u32,
};

pub fn encodeCreateSubscriptionResponse(e: *encoding.Encoder, v: CreateSubscriptionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try e.encodeDouble(v.revised_publishing_interval);
    try e.writer.writeInt(u32, v.revised_lifetime_count, .little);
    try e.writer.writeInt(u32, v.revised_max_keep_alive_count, .little);
}

pub fn decodeCreateSubscriptionResponse(d: *encoding.Decoder) encoding.DecodeError!CreateSubscriptionResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .revised_publishing_interval = try d.decodeDouble(),
        .revised_lifetime_count = try d.decodeUInt32(),
        .revised_max_keep_alive_count = try d.decodeUInt32(),
    };
}

pub fn freeCreateSubscriptionResponse(a: std.mem.Allocator, v: CreateSubscriptionResponse) void {
    freeResponseHeader(a, v.response_header);
}

// ── ModifySubscription (§5.13.3) ─────────────────────────────────────────────

pub const ModifySubscriptionRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    requested_publishing_interval: f64,
    requested_lifetime_count: u32,
    requested_max_keep_alive_count: u32,
    max_notifications_per_publish: u32,
    priority: u8,
};

pub fn encodeModifySubscriptionRequest(e: *encoding.Encoder, v: ModifySubscriptionRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try e.encodeDouble(v.requested_publishing_interval);
    try e.writer.writeInt(u32, v.requested_lifetime_count, .little);
    try e.writer.writeInt(u32, v.requested_max_keep_alive_count, .little);
    try e.writer.writeInt(u32, v.max_notifications_per_publish, .little);
    try e.encodeByte(v.priority);
}

pub fn decodeModifySubscriptionRequest(d: *encoding.Decoder) encoding.DecodeError!ModifySubscriptionRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .requested_publishing_interval = try d.decodeDouble(),
        .requested_lifetime_count = try d.decodeUInt32(),
        .requested_max_keep_alive_count = try d.decodeUInt32(),
        .max_notifications_per_publish = try d.decodeUInt32(),
        .priority = try d.decodeByte(),
    };
}

pub fn freeModifySubscriptionRequest(a: std.mem.Allocator, v: ModifySubscriptionRequest) void {
    freeRequestHeader(a, v.request_header);
}

pub const ModifySubscriptionResponse = struct {
    response_header: ResponseHeader,
    revised_publishing_interval: f64,
    revised_lifetime_count: u32,
    revised_max_keep_alive_count: u32,
};

pub fn encodeModifySubscriptionResponse(e: *encoding.Encoder, v: ModifySubscriptionResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.encodeDouble(v.revised_publishing_interval);
    try e.writer.writeInt(u32, v.revised_lifetime_count, .little);
    try e.writer.writeInt(u32, v.revised_max_keep_alive_count, .little);
}

pub fn decodeModifySubscriptionResponse(d: *encoding.Decoder) encoding.DecodeError!ModifySubscriptionResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .revised_publishing_interval = try d.decodeDouble(),
        .revised_lifetime_count = try d.decodeUInt32(),
        .revised_max_keep_alive_count = try d.decodeUInt32(),
    };
}

pub fn freeModifySubscriptionResponse(a: std.mem.Allocator, v: ModifySubscriptionResponse) void {
    freeResponseHeader(a, v.response_header);
}

// ── SetPublishingMode (§5.13.4) ──────────────────────────────────────────────

pub const SetPublishingModeRequest = struct {
    request_header: RequestHeader,
    publishing_enabled: bool,
    subscription_ids: ?[]const u32,
};

pub fn encodeSetPublishingModeRequest(e: *encoding.Encoder, v: SetPublishingModeRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeBoolean(v.publishing_enabled);
    try encodeArray(e, u32, v.subscription_ids, encodeU32Item);
}

pub fn decodeSetPublishingModeRequest(d: *encoding.Decoder) encoding.DecodeError!SetPublishingModeRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .publishing_enabled = try d.decodeBoolean(),
        .subscription_ids = try decodeArray(d, u32, decodeU32Item),
    };
}

pub fn freeSetPublishingModeRequest(a: std.mem.Allocator, v: SetPublishingModeRequest) void {
    freeRequestHeader(a, v.request_header);
    freeU32Array(a, v.subscription_ids);
}

pub const SetPublishingModeResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeSetPublishingModeResponse(e: *encoding.Encoder, v: SetPublishingModeResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeSetPublishingModeResponse(d: *encoding.Decoder) encoding.DecodeError!SetPublishingModeResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeSetPublishingModeResponse(a: std.mem.Allocator, v: SetPublishingModeResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── DeleteSubscriptions (§5.13.8) ────────────────────────────────────────────

pub const DeleteSubscriptionsRequest = struct {
    request_header: RequestHeader,
    subscription_ids: ?[]const u32,
};

pub fn encodeDeleteSubscriptionsRequest(e: *encoding.Encoder, v: DeleteSubscriptionsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeArray(e, u32, v.subscription_ids, encodeU32Item);
}

pub fn decodeDeleteSubscriptionsRequest(d: *encoding.Decoder) encoding.DecodeError!DeleteSubscriptionsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_ids = try decodeArray(d, u32, decodeU32Item),
    };
}

pub fn freeDeleteSubscriptionsRequest(a: std.mem.Allocator, v: DeleteSubscriptionsRequest) void {
    freeRequestHeader(a, v.request_header);
    freeU32Array(a, v.subscription_ids);
}

pub const DeleteSubscriptionsResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeDeleteSubscriptionsResponse(e: *encoding.Encoder, v: DeleteSubscriptionsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeDeleteSubscriptionsResponse(d: *encoding.Decoder) encoding.DecodeError!DeleteSubscriptionsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeDeleteSubscriptionsResponse(a: std.mem.Allocator, v: DeleteSubscriptionsResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── MonitoringParameters (§5.12.1.2), MonitoredItemCreateRequest/Result
// (§5.12.2) ───────────────────────────────────────────────────────────────────

/// The canonical "no filter" `ExtensionObject` (`MonitoringParameters.Filter`
/// left absent) — the basic data-change-monitoring case every `Filter`/
/// `FilterResult` field in this section uses when the caller doesn't supply
/// an event/deadband filter (out of this module's scope: filter *bodies*
/// aren't modeled, only the ExtensionObject envelope carrying one, same as
/// `RequestHeader.additional_header`'s `no_additional_header`).
pub const no_filter: encoding.ExtensionObject = .{ .type_id = null_node_id, .encoding = .no_body };

pub const MonitoringParameters = struct {
    client_handle: u32,
    sampling_interval: f64,
    filter: encoding.ExtensionObject,
    queue_size: u32,
    discard_oldest: bool,
};

pub fn encodeMonitoringParameters(e: *encoding.Encoder, v: MonitoringParameters) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.client_handle, .little);
    try e.encodeDouble(v.sampling_interval);
    try e.encodeExtensionObject(v.filter);
    try e.writer.writeInt(u32, v.queue_size, .little);
    try e.encodeBoolean(v.discard_oldest);
}

pub fn decodeMonitoringParameters(d: *encoding.Decoder) encoding.DecodeError!MonitoringParameters {
    return .{
        .client_handle = try d.decodeUInt32(),
        .sampling_interval = try d.decodeDouble(),
        .filter = try d.decodeExtensionObject(),
        .queue_size = try d.decodeUInt32(),
        .discard_oldest = try d.decodeBoolean(),
    };
}

pub fn freeMonitoringParameters(a: std.mem.Allocator, v: MonitoringParameters) void {
    if (v.filter.body.len != 0) a.free(v.filter.body);
    encoding.freeNodeId(a, v.filter.type_id);
}

pub const MonitoredItemCreateRequest = struct {
    item_to_monitor: ReadValueId,
    monitoring_mode: MonitoringMode,
    requested_parameters: MonitoringParameters,
};

pub fn encodeMonitoredItemCreateRequest(e: *encoding.Encoder, v: MonitoredItemCreateRequest) encoding.EncodeError!void {
    try encodeReadValueId(e, v.item_to_monitor);
    try encodeEnum(e, MonitoringMode, v.monitoring_mode);
    try encodeMonitoringParameters(e, v.requested_parameters);
}

pub fn decodeMonitoredItemCreateRequest(d: *encoding.Decoder) encoding.DecodeError!MonitoredItemCreateRequest {
    return .{
        .item_to_monitor = try decodeReadValueId(d),
        .monitoring_mode = try decodeEnum(d, MonitoringMode),
        .requested_parameters = try decodeMonitoringParameters(d),
    };
}

pub fn freeMonitoredItemCreateRequest(a: std.mem.Allocator, v: MonitoredItemCreateRequest) void {
    freeReadValueId(a, v.item_to_monitor);
    freeMonitoringParameters(a, v.requested_parameters);
}

fn freeMonitoredItemCreateRequestArray(a: std.mem.Allocator, arr: ?[]const MonitoredItemCreateRequest) void {
    if (arr) |items| {
        for (items) |it| freeMonitoredItemCreateRequest(a, it);
        a.free(items);
    }
}

pub const MonitoredItemCreateResult = struct {
    status_code: encoding.StatusCode,
    monitored_item_id: u32,
    revised_sampling_interval: f64,
    revised_queue_size: u32,
    filter_result: encoding.ExtensionObject,
};

pub fn encodeMonitoredItemCreateResult(e: *encoding.Encoder, v: MonitoredItemCreateResult) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status_code);
    try e.writer.writeInt(u32, v.monitored_item_id, .little);
    try e.encodeDouble(v.revised_sampling_interval);
    try e.writer.writeInt(u32, v.revised_queue_size, .little);
    try e.encodeExtensionObject(v.filter_result);
}

pub fn decodeMonitoredItemCreateResult(d: *encoding.Decoder) encoding.DecodeError!MonitoredItemCreateResult {
    return .{
        .status_code = try d.decodeStatusCode(),
        .monitored_item_id = try d.decodeUInt32(),
        .revised_sampling_interval = try d.decodeDouble(),
        .revised_queue_size = try d.decodeUInt32(),
        .filter_result = try d.decodeExtensionObject(),
    };
}

pub fn freeMonitoredItemCreateResult(a: std.mem.Allocator, v: MonitoredItemCreateResult) void {
    if (v.filter_result.body.len != 0) a.free(v.filter_result.body);
    encoding.freeNodeId(a, v.filter_result.type_id);
}

fn freeMonitoredItemCreateResultArray(a: std.mem.Allocator, arr: ?[]const MonitoredItemCreateResult) void {
    if (arr) |items| {
        for (items) |it| freeMonitoredItemCreateResult(a, it);
        a.free(items);
    }
}

// ── CreateMonitoredItems (§5.12.2) ───────────────────────────────────────────

pub const CreateMonitoredItemsRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_create: ?[]const MonitoredItemCreateRequest,
};

pub fn encodeCreateMonitoredItemsRequest(e: *encoding.Encoder, v: CreateMonitoredItemsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try encodeEnum(e, TimestampsToReturn, v.timestamps_to_return);
    try encodeArray(e, MonitoredItemCreateRequest, v.items_to_create, encodeMonitoredItemCreateRequest);
}

pub fn decodeCreateMonitoredItemsRequest(d: *encoding.Decoder) encoding.DecodeError!CreateMonitoredItemsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .timestamps_to_return = try decodeEnum(d, TimestampsToReturn),
        .items_to_create = try decodeArray(d, MonitoredItemCreateRequest, decodeMonitoredItemCreateRequest),
    };
}

pub fn freeCreateMonitoredItemsRequest(a: std.mem.Allocator, v: CreateMonitoredItemsRequest) void {
    freeRequestHeader(a, v.request_header);
    freeMonitoredItemCreateRequestArray(a, v.items_to_create);
}

pub const CreateMonitoredItemsResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const MonitoredItemCreateResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeCreateMonitoredItemsResponse(e: *encoding.Encoder, v: CreateMonitoredItemsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, MonitoredItemCreateResult, v.results, encodeMonitoredItemCreateResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeCreateMonitoredItemsResponse(d: *encoding.Decoder) encoding.DecodeError!CreateMonitoredItemsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, MonitoredItemCreateResult, decodeMonitoredItemCreateResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeCreateMonitoredItemsResponse(a: std.mem.Allocator, v: CreateMonitoredItemsResponse) void {
    freeResponseHeader(a, v.response_header);
    freeMonitoredItemCreateResultArray(a, v.results);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── DeleteMonitoredItems (§5.12.6) ───────────────────────────────────────────

pub const DeleteMonitoredItemsRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    monitored_item_ids: ?[]const u32,
};

pub fn encodeDeleteMonitoredItemsRequest(e: *encoding.Encoder, v: DeleteMonitoredItemsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try encodeArray(e, u32, v.monitored_item_ids, encodeU32Item);
}

pub fn decodeDeleteMonitoredItemsRequest(d: *encoding.Decoder) encoding.DecodeError!DeleteMonitoredItemsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .monitored_item_ids = try decodeArray(d, u32, decodeU32Item),
    };
}

pub fn freeDeleteMonitoredItemsRequest(a: std.mem.Allocator, v: DeleteMonitoredItemsRequest) void {
    freeRequestHeader(a, v.request_header);
    freeU32Array(a, v.monitored_item_ids);
}

pub const DeleteMonitoredItemsResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeDeleteMonitoredItemsResponse(e: *encoding.Encoder, v: DeleteMonitoredItemsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeDeleteMonitoredItemsResponse(d: *encoding.Decoder) encoding.DecodeError!DeleteMonitoredItemsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeDeleteMonitoredItemsResponse(a: std.mem.Allocator, v: DeleteMonitoredItemsResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── NotificationMessage (§5.13.1.2), MonitoredItemNotification (§5.12.1.3),
// DataChangeNotification/StatusChangeNotification/EventNotificationList
// (§5.12.1.4/§5.13.6/§5.12.1.5) ──────────────────────────────────────────────
// `DataChangeNotification`/`StatusChangeNotification`/`EventNotificationList`
// are the concrete members of the `NotificationData` abstract base (itself
// field-less — just an `ExtensionObject` tag) that rides inside
// `NotificationMessage.NotificationData`; `root.zig`'s `Subscription.publish`/
// `.republish` classify each element by its `ExtensionObject.type_id`
// (`type_id.data_change_notification`/`.status_change_notification`/
// `.event_notification_list`) and decode the ones it recognizes.

pub const MonitoredItemNotification = struct {
    client_handle: u32,
    value: encoding.DataValue,
};

pub fn encodeMonitoredItemNotification(e: *encoding.Encoder, v: MonitoredItemNotification) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.client_handle, .little);
    try e.encodeDataValue(v.value);
}

pub fn decodeMonitoredItemNotification(d: *encoding.Decoder) encoding.DecodeError!MonitoredItemNotification {
    return .{
        .client_handle = try d.decodeUInt32(),
        .value = try d.decodeDataValue(),
    };
}

pub fn freeMonitoredItemNotification(a: std.mem.Allocator, v: MonitoredItemNotification) void {
    encoding.freeDataValue(a, v.value);
}

fn freeMonitoredItemNotificationArray(a: std.mem.Allocator, arr: ?[]const MonitoredItemNotification) void {
    if (arr) |items| {
        for (items) |it| freeMonitoredItemNotification(a, it);
        a.free(items);
    }
}

pub const DataChangeNotification = struct {
    monitored_items: ?[]const MonitoredItemNotification,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeDataChangeNotification(e: *encoding.Encoder, v: DataChangeNotification) encoding.EncodeError!void {
    try encodeArray(e, MonitoredItemNotification, v.monitored_items, encodeMonitoredItemNotification);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeDataChangeNotification(d: *encoding.Decoder) encoding.DecodeError!DataChangeNotification {
    return .{
        .monitored_items = try decodeArray(d, MonitoredItemNotification, decodeMonitoredItemNotification),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeDataChangeNotification(a: std.mem.Allocator, v: DataChangeNotification) void {
    freeMonitoredItemNotificationArray(a, v.monitored_items);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const StatusChangeNotification = struct {
    status: encoding.StatusCode,
    diagnostic_info: encoding.DiagnosticInfo,
};

pub fn encodeStatusChangeNotification(e: *encoding.Encoder, v: StatusChangeNotification) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status);
    try e.encodeDiagnosticInfo(v.diagnostic_info);
}

pub fn decodeStatusChangeNotification(d: *encoding.Decoder) encoding.DecodeError!StatusChangeNotification {
    return .{
        .status = try d.decodeStatusCode(),
        .diagnostic_info = try d.decodeDiagnosticInfo(),
    };
}

pub fn freeStatusChangeNotification(a: std.mem.Allocator, v: StatusChangeNotification) void {
    freeDiagnosticInfo(a, v.diagnostic_info);
}

/// §5.12.1.5's `EventFieldList` — one Event occurrence's selected-field
/// values (`Variant[]`, order matching the `EventFilter.SelectClauses` the
/// caller specified when creating the event-monitored item; F1's `no_filter`
/// means this module never actually builds one, but decoding an incoming
/// `EventNotificationList` from a server that has one configured server-side
/// still needs the shape modeled).
pub const EventFieldList = struct {
    client_handle: u32,
    event_fields: ?[]const encoding.Variant,
};

pub fn encodeEventFieldList(e: *encoding.Encoder, v: EventFieldList) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.client_handle, .little);
    try encodeArray(e, encoding.Variant, v.event_fields, encoding.Encoder.encodeVariant);
}

pub fn decodeEventFieldList(d: *encoding.Decoder) encoding.DecodeError!EventFieldList {
    return .{
        .client_handle = try d.decodeUInt32(),
        .event_fields = try decodeArray(d, encoding.Variant, encoding.Decoder.decodeVariant),
    };
}

pub fn freeEventFieldList(a: std.mem.Allocator, v: EventFieldList) void {
    freeVariantArray(a, v.event_fields);
}

fn freeEventFieldListArray(a: std.mem.Allocator, arr: ?[]const EventFieldList) void {
    if (arr) |items| {
        for (items) |it| freeEventFieldList(a, it);
        a.free(items);
    }
}

pub const EventNotificationList = struct {
    events: ?[]const EventFieldList,
};

pub fn encodeEventNotificationList(e: *encoding.Encoder, v: EventNotificationList) encoding.EncodeError!void {
    try encodeArray(e, EventFieldList, v.events, encodeEventFieldList);
}

pub fn decodeEventNotificationList(d: *encoding.Decoder) encoding.DecodeError!EventNotificationList {
    return .{ .events = try decodeArray(d, EventFieldList, decodeEventFieldList) };
}

pub fn freeEventNotificationList(a: std.mem.Allocator, v: EventNotificationList) void {
    freeEventFieldListArray(a, v.events);
}

pub const NotificationMessage = struct {
    sequence_number: u32,
    publish_time: encoding.DateTime,
    notification_data: ?[]const encoding.ExtensionObject,
};

pub fn encodeNotificationMessage(e: *encoding.Encoder, v: NotificationMessage) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.sequence_number, .little);
    try e.encodeDateTime(v.publish_time);
    try encodeArray(e, encoding.ExtensionObject, v.notification_data, encoding.Encoder.encodeExtensionObject);
}

pub fn decodeNotificationMessage(d: *encoding.Decoder) encoding.DecodeError!NotificationMessage {
    return .{
        .sequence_number = try d.decodeUInt32(),
        .publish_time = try d.decodeDateTime(),
        .notification_data = try decodeArray(d, encoding.ExtensionObject, encoding.Decoder.decodeExtensionObject),
    };
}

/// Frees only the raw `ExtensionObject` envelopes (`TypeId` + body bytes) —
/// NOT a decode of their bodies (that's `root.zig`'s `Subscription.publish`/
/// `.republish`'s job, via `decodeDataChangeNotification` & co. on each
/// element's `.body`). Used both when a caller wants a `NotificationMessage`
/// freed without ever decoding its contents (e.g. a round-trip test) and, by
/// `root.zig`, after each `ExtensionObject`'s body has already been decoded
/// into an owned typed value and this raw form is no longer needed.
pub fn freeNotificationMessage(a: std.mem.Allocator, v: NotificationMessage) void {
    if (v.notification_data) |items| {
        for (items) |eo| {
            encoding.freeNodeId(a, eo.type_id);
            if (eo.body.len != 0) a.free(eo.body);
        }
        a.free(items);
    }
}

// ── SubscriptionAcknowledgement (§5.13.5.2) ──────────────────────────────────

pub const SubscriptionAcknowledgement = struct {
    subscription_id: u32,
    sequence_number: u32,
};

pub fn encodeSubscriptionAcknowledgement(e: *encoding.Encoder, v: SubscriptionAcknowledgement) encoding.EncodeError!void {
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try e.writer.writeInt(u32, v.sequence_number, .little);
}

pub fn decodeSubscriptionAcknowledgement(d: *encoding.Decoder) encoding.DecodeError!SubscriptionAcknowledgement {
    return .{
        .subscription_id = try d.decodeUInt32(),
        .sequence_number = try d.decodeUInt32(),
    };
}

fn freeSubscriptionAcknowledgementArray(a: std.mem.Allocator, arr: ?[]const SubscriptionAcknowledgement) void {
    if (arr) |items| a.free(items);
}

// ── Publish (§5.13.5) ────────────────────────────────────────────────────────

pub const PublishRequest = struct {
    request_header: RequestHeader,
    subscription_acknowledgements: ?[]const SubscriptionAcknowledgement,
};

pub fn encodePublishRequest(e: *encoding.Encoder, v: PublishRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeArray(e, SubscriptionAcknowledgement, v.subscription_acknowledgements, encodeSubscriptionAcknowledgement);
}

pub fn decodePublishRequest(d: *encoding.Decoder) encoding.DecodeError!PublishRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_acknowledgements = try decodeArray(d, SubscriptionAcknowledgement, decodeSubscriptionAcknowledgement),
    };
}

pub fn freePublishRequest(a: std.mem.Allocator, v: PublishRequest) void {
    freeRequestHeader(a, v.request_header);
    freeSubscriptionAcknowledgementArray(a, v.subscription_acknowledgements);
}

pub const PublishResponse = struct {
    response_header: ResponseHeader,
    subscription_id: u32,
    available_sequence_numbers: ?[]const u32,
    more_notifications: bool,
    notification_message: NotificationMessage,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodePublishResponse(e: *encoding.Encoder, v: PublishResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try encodeArray(e, u32, v.available_sequence_numbers, encodeU32Item);
    try e.encodeBoolean(v.more_notifications);
    try encodeNotificationMessage(e, v.notification_message);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodePublishResponse(d: *encoding.Decoder) encoding.DecodeError!PublishResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .available_sequence_numbers = try decodeArray(d, u32, decodeU32Item),
        .more_notifications = try d.decodeBoolean(),
        .notification_message = try decodeNotificationMessage(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freePublishResponse(a: std.mem.Allocator, v: PublishResponse) void {
    freeResponseHeader(a, v.response_header);
    freeU32Array(a, v.available_sequence_numbers);
    freeNotificationMessage(a, v.notification_message);
    if (v.results) |r| a.free(r);
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── Republish (§5.13.6) ──────────────────────────────────────────────────────

pub const RepublishRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    retransmit_sequence_number: u32,
};

pub fn encodeRepublishRequest(e: *encoding.Encoder, v: RepublishRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.writer.writeInt(u32, v.subscription_id, .little);
    try e.writer.writeInt(u32, v.retransmit_sequence_number, .little);
}

pub fn decodeRepublishRequest(d: *encoding.Decoder) encoding.DecodeError!RepublishRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .retransmit_sequence_number = try d.decodeUInt32(),
    };
}

pub fn freeRepublishRequest(a: std.mem.Allocator, v: RepublishRequest) void {
    freeRequestHeader(a, v.request_header);
}

pub const RepublishResponse = struct {
    response_header: ResponseHeader,
    notification_message: NotificationMessage,
};

pub fn encodeRepublishResponse(e: *encoding.Encoder, v: RepublishResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeNotificationMessage(e, v.notification_message);
}

pub fn decodeRepublishResponse(d: *encoding.Decoder) encoding.DecodeError!RepublishResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .notification_message = try decodeNotificationMessage(d),
    };
}

pub fn freeRepublishResponse(a: std.mem.Allocator, v: RepublishResponse) void {
    freeResponseHeader(a, v.response_header);
    freeNotificationMessage(a, v.notification_message);
}

// ── Discovery: GetEndpoints (§5.4.4) / FindServers (§5.4.2) ─────────────────
// Answered by the server side from its configured endpoint list, and callable
// from the client side *before* a session exists (both services are explicitly
// session-less — OPC 10000-4 §5.4).

pub const GetEndpointsRequest = struct {
    request_header: RequestHeader,
    endpoint_url: ?[]const u8,
    locale_ids: ?[]const ?[]const u8,
    profile_uris: ?[]const ?[]const u8,
};

pub fn encodeGetEndpointsRequest(e: *encoding.Encoder, v: GetEndpointsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeString(v.endpoint_url);
    try encodeArray(e, ?[]const u8, v.locale_ids, encodeStringItem);
    try encodeArray(e, ?[]const u8, v.profile_uris, encodeStringItem);
}

pub fn decodeGetEndpointsRequest(d: *encoding.Decoder) encoding.DecodeError!GetEndpointsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .endpoint_url = try d.decodeString(),
        .locale_ids = try decodeArray(d, ?[]const u8, decodeStringItem),
        .profile_uris = try decodeArray(d, ?[]const u8, decodeStringItem),
    };
}

pub fn freeGetEndpointsRequest(a: std.mem.Allocator, v: GetEndpointsRequest) void {
    freeRequestHeader(a, v.request_header);
    freeOptStr(a, v.endpoint_url);
    freeStringArray(a, v.locale_ids);
    freeStringArray(a, v.profile_uris);
}

pub const GetEndpointsResponse = struct {
    response_header: ResponseHeader,
    endpoints: ?[]const EndpointDescription,
};

pub fn encodeGetEndpointsResponse(e: *encoding.Encoder, v: GetEndpointsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, EndpointDescription, v.endpoints, encodeEndpointDescription);
}

pub fn decodeGetEndpointsResponse(d: *encoding.Decoder) encoding.DecodeError!GetEndpointsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .endpoints = try decodeArray(d, EndpointDescription, decodeEndpointDescription),
    };
}

pub fn freeGetEndpointsResponse(a: std.mem.Allocator, v: GetEndpointsResponse) void {
    freeResponseHeader(a, v.response_header);
    freeEndpointArray(a, v.endpoints);
}

pub const FindServersRequest = struct {
    request_header: RequestHeader,
    endpoint_url: ?[]const u8,
    locale_ids: ?[]const ?[]const u8,
    server_uris: ?[]const ?[]const u8,
};

pub fn encodeFindServersRequest(e: *encoding.Encoder, v: FindServersRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeString(v.endpoint_url);
    try encodeArray(e, ?[]const u8, v.locale_ids, encodeStringItem);
    try encodeArray(e, ?[]const u8, v.server_uris, encodeStringItem);
}

pub fn decodeFindServersRequest(d: *encoding.Decoder) encoding.DecodeError!FindServersRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .endpoint_url = try d.decodeString(),
        .locale_ids = try decodeArray(d, ?[]const u8, decodeStringItem),
        .server_uris = try decodeArray(d, ?[]const u8, decodeStringItem),
    };
}

pub fn freeFindServersRequest(a: std.mem.Allocator, v: FindServersRequest) void {
    freeRequestHeader(a, v.request_header);
    freeOptStr(a, v.endpoint_url);
    freeStringArray(a, v.locale_ids);
    freeStringArray(a, v.server_uris);
}

pub const FindServersResponse = struct {
    response_header: ResponseHeader,
    servers: ?[]const ApplicationDescription,
};

pub fn encodeFindServersResponse(e: *encoding.Encoder, v: FindServersResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, ApplicationDescription, v.servers, encodeApplicationDescription);
}

pub fn decodeFindServersResponse(d: *encoding.Decoder) encoding.DecodeError!FindServersResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .servers = try decodeArray(d, ApplicationDescription, decodeApplicationDescription),
    };
}

pub fn freeFindServersResponse(a: std.mem.Allocator, v: FindServersResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.servers) |items| {
        for (items) |ad| freeApplicationDescription(a, ad);
        a.free(items);
    }
}

// ── UserNameIdentityToken (§7.36.4) ─────────────────────────────────────────

/// The user-name/password identity token an `ActivateSessionRequest` carries
/// inside its `UserIdentityToken` ExtensionObject. `password` is a ByteString
/// of UTF-8 bytes; at `SecurityPolicy#None` (`encryption_algorithm == null`)
/// it travels **in the clear** — see this module's SPEC threat model.
pub const UserNameIdentityToken = struct {
    policy_id: ?[]const u8,
    user_name: ?[]const u8,
    password: ?[]const u8,
    encryption_algorithm: ?[]const u8,
};

pub fn encodeUserNameIdentityToken(e: *encoding.Encoder, v: UserNameIdentityToken) encoding.EncodeError!void {
    try e.encodeString(v.policy_id);
    try e.encodeString(v.user_name);
    try e.encodeByteString(v.password);
    try e.encodeString(v.encryption_algorithm);
}

pub fn decodeUserNameIdentityToken(d: *encoding.Decoder) encoding.DecodeError!UserNameIdentityToken {
    return .{
        .policy_id = try d.decodeString(),
        .user_name = try d.decodeString(),
        .password = try d.decodeByteString(),
        .encryption_algorithm = try d.decodeString(),
    };
}

pub fn freeUserNameIdentityToken(a: std.mem.Allocator, v: UserNameIdentityToken) void {
    freeOptStr(a, v.policy_id);
    freeOptStr(a, v.user_name);
    freeOptStr(a, v.password);
    freeOptStr(a, v.encryption_algorithm);
}

// ── TranslateBrowsePathsToNodeIds (§5.8.4) ──────────────────────────────────

pub const RelativePathElement = struct {
    reference_type_id: encoding.NodeId,
    is_inverse: bool,
    include_subtypes: bool,
    target_name: encoding.QualifiedName,
};

pub fn encodeRelativePathElement(e: *encoding.Encoder, v: RelativePathElement) encoding.EncodeError!void {
    try e.encodeNodeId(v.reference_type_id);
    try e.encodeBoolean(v.is_inverse);
    try e.encodeBoolean(v.include_subtypes);
    try e.encodeQualifiedName(v.target_name);
}

pub fn decodeRelativePathElement(d: *encoding.Decoder) encoding.DecodeError!RelativePathElement {
    return .{
        .reference_type_id = try d.decodeNodeId(),
        .is_inverse = try d.decodeBoolean(),
        .include_subtypes = try d.decodeBoolean(),
        .target_name = try d.decodeQualifiedName(),
    };
}

pub const RelativePath = struct {
    elements: ?[]const RelativePathElement,
};

pub fn encodeRelativePath(e: *encoding.Encoder, v: RelativePath) encoding.EncodeError!void {
    try encodeArray(e, RelativePathElement, v.elements, encodeRelativePathElement);
}

pub fn decodeRelativePath(d: *encoding.Decoder) encoding.DecodeError!RelativePath {
    return .{ .elements = try decodeArray(d, RelativePathElement, decodeRelativePathElement) };
}

pub const BrowsePath = struct {
    starting_node: encoding.NodeId,
    relative_path: RelativePath,
};

pub fn encodeBrowsePath(e: *encoding.Encoder, v: BrowsePath) encoding.EncodeError!void {
    try e.encodeNodeId(v.starting_node);
    try encodeRelativePath(e, v.relative_path);
}

pub fn decodeBrowsePath(d: *encoding.Decoder) encoding.DecodeError!BrowsePath {
    return .{ .starting_node = try d.decodeNodeId(), .relative_path = try decodeRelativePath(d) };
}

pub const BrowsePathTarget = struct {
    target_id: encoding.ExpandedNodeId,
    /// `0xFFFF_FFFF` = "the whole path was resolved" (OPC 10000-4 §7.7).
    remaining_path_index: u32,
};

pub fn encodeBrowsePathTarget(e: *encoding.Encoder, v: BrowsePathTarget) encoding.EncodeError!void {
    try e.encodeExpandedNodeId(v.target_id);
    try e.encodeUInt32(v.remaining_path_index);
}

pub fn decodeBrowsePathTarget(d: *encoding.Decoder) encoding.DecodeError!BrowsePathTarget {
    return .{ .target_id = try d.decodeExpandedNodeId(), .remaining_path_index = try d.decodeUInt32() };
}

pub const BrowsePathResult = struct {
    status_code: encoding.StatusCode,
    targets: ?[]const BrowsePathTarget,
};

pub fn encodeBrowsePathResult(e: *encoding.Encoder, v: BrowsePathResult) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status_code);
    try encodeArray(e, BrowsePathTarget, v.targets, encodeBrowsePathTarget);
}

pub fn decodeBrowsePathResult(d: *encoding.Decoder) encoding.DecodeError!BrowsePathResult {
    return .{
        .status_code = try d.decodeStatusCode(),
        .targets = try decodeArray(d, BrowsePathTarget, decodeBrowsePathTarget),
    };
}

pub const TranslateBrowsePathsToNodeIdsRequest = struct {
    request_header: RequestHeader,
    browse_paths: ?[]const BrowsePath,
};

pub fn encodeTranslateBrowsePathsToNodeIdsRequest(e: *encoding.Encoder, v: TranslateBrowsePathsToNodeIdsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try encodeArray(e, BrowsePath, v.browse_paths, encodeBrowsePath);
}

pub fn decodeTranslateBrowsePathsToNodeIdsRequest(d: *encoding.Decoder) encoding.DecodeError!TranslateBrowsePathsToNodeIdsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .browse_paths = try decodeArray(d, BrowsePath, decodeBrowsePath),
    };
}

pub const TranslateBrowsePathsToNodeIdsResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const BrowsePathResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeTranslateBrowsePathsToNodeIdsResponse(e: *encoding.Encoder, v: TranslateBrowsePathsToNodeIdsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, BrowsePathResult, v.results, encodeBrowsePathResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeTranslateBrowsePathsToNodeIdsResponse(d: *encoding.Decoder) encoding.DecodeError!TranslateBrowsePathsToNodeIdsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, BrowsePathResult, decodeBrowsePathResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeTranslateBrowsePathsToNodeIdsResponse(a: std.mem.Allocator, v: TranslateBrowsePathsToNodeIdsResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |results| {
        for (results) |r| {
            if (r.targets) |targets| {
                for (targets) |t| encoding.freeExpandedNodeId(a, t.target_id);
                a.free(targets);
            }
        }
        a.free(results);
    }
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

// ── ModifyMonitoredItems (§5.12.3) / SetMonitoringMode (§5.12.4) ────────────

pub const MonitoredItemModifyRequest = struct {
    monitored_item_id: u32,
    requested_parameters: MonitoringParameters,
};

pub fn encodeMonitoredItemModifyRequest(e: *encoding.Encoder, v: MonitoredItemModifyRequest) encoding.EncodeError!void {
    try e.encodeUInt32(v.monitored_item_id);
    try encodeMonitoringParameters(e, v.requested_parameters);
}

pub fn decodeMonitoredItemModifyRequest(d: *encoding.Decoder) encoding.DecodeError!MonitoredItemModifyRequest {
    return .{
        .monitored_item_id = try d.decodeUInt32(),
        .requested_parameters = try decodeMonitoringParameters(d),
    };
}

pub const MonitoredItemModifyResult = struct {
    status_code: encoding.StatusCode,
    revised_sampling_interval: f64,
    revised_queue_size: u32,
    filter_result: encoding.ExtensionObject,
};

pub fn encodeMonitoredItemModifyResult(e: *encoding.Encoder, v: MonitoredItemModifyResult) encoding.EncodeError!void {
    try e.encodeStatusCode(v.status_code);
    try e.encodeDouble(v.revised_sampling_interval);
    try e.encodeUInt32(v.revised_queue_size);
    try e.encodeExtensionObject(v.filter_result);
}

pub fn decodeMonitoredItemModifyResult(d: *encoding.Decoder) encoding.DecodeError!MonitoredItemModifyResult {
    return .{
        .status_code = try d.decodeStatusCode(),
        .revised_sampling_interval = try d.decodeDouble(),
        .revised_queue_size = try d.decodeUInt32(),
        .filter_result = try d.decodeExtensionObject(),
    };
}

pub const ModifyMonitoredItemsRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    timestamps_to_return: TimestampsToReturn,
    items_to_modify: ?[]const MonitoredItemModifyRequest,
};

pub fn encodeModifyMonitoredItemsRequest(e: *encoding.Encoder, v: ModifyMonitoredItemsRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeUInt32(v.subscription_id);
    try encodeEnum(e, TimestampsToReturn, v.timestamps_to_return);
    try encodeArray(e, MonitoredItemModifyRequest, v.items_to_modify, encodeMonitoredItemModifyRequest);
}

pub fn decodeModifyMonitoredItemsRequest(d: *encoding.Decoder) encoding.DecodeError!ModifyMonitoredItemsRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .timestamps_to_return = try decodeEnum(d, TimestampsToReturn),
        .items_to_modify = try decodeArray(d, MonitoredItemModifyRequest, decodeMonitoredItemModifyRequest),
    };
}

pub const ModifyMonitoredItemsResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const MonitoredItemModifyResult,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeModifyMonitoredItemsResponse(e: *encoding.Encoder, v: ModifyMonitoredItemsResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, MonitoredItemModifyResult, v.results, encodeMonitoredItemModifyResult);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeModifyMonitoredItemsResponse(d: *encoding.Decoder) encoding.DecodeError!ModifyMonitoredItemsResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, MonitoredItemModifyResult, decodeMonitoredItemModifyResult),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeModifyMonitoredItemsResponse(a: std.mem.Allocator, v: ModifyMonitoredItemsResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |results| {
        for (results) |r| encoding.freeExtensionObject(a, r.filter_result);
        a.free(results);
    }
    freeDiagnosticInfoArray(a, v.diagnostic_infos);
}

pub const SetMonitoringModeRequest = struct {
    request_header: RequestHeader,
    subscription_id: u32,
    monitoring_mode: MonitoringMode,
    monitored_item_ids: ?[]const u32,
};

pub fn encodeSetMonitoringModeRequest(e: *encoding.Encoder, v: SetMonitoringModeRequest) encoding.EncodeError!void {
    try encodeRequestHeader(e, v.request_header);
    try e.encodeUInt32(v.subscription_id);
    try encodeEnum(e, MonitoringMode, v.monitoring_mode);
    try encodeArray(e, u32, v.monitored_item_ids, encodeU32Item);
}

pub fn decodeSetMonitoringModeRequest(d: *encoding.Decoder) encoding.DecodeError!SetMonitoringModeRequest {
    return .{
        .request_header = try decodeRequestHeader(d),
        .subscription_id = try d.decodeUInt32(),
        .monitoring_mode = try decodeEnum(d, MonitoringMode),
        .monitored_item_ids = try decodeArray(d, u32, decodeU32Item),
    };
}

pub const SetMonitoringModeResponse = struct {
    response_header: ResponseHeader,
    results: ?[]const encoding.StatusCode,
    diagnostic_infos: ?[]const encoding.DiagnosticInfo,
};

pub fn encodeSetMonitoringModeResponse(e: *encoding.Encoder, v: SetMonitoringModeResponse) encoding.EncodeError!void {
    try encodeResponseHeader(e, v.response_header);
    try encodeArray(e, encoding.StatusCode, v.results, encoding.Encoder.encodeStatusCode);
    try encodeArray(e, encoding.DiagnosticInfo, v.diagnostic_infos, encoding.Encoder.encodeDiagnosticInfo);
}

pub fn decodeSetMonitoringModeResponse(d: *encoding.Decoder) encoding.DecodeError!SetMonitoringModeResponse {
    return .{
        .response_header = try decodeResponseHeader(d),
        .results = try decodeArray(d, encoding.StatusCode, encoding.Decoder.decodeStatusCode),
        .diagnostic_infos = try decodeArray(d, encoding.DiagnosticInfo, encoding.Decoder.decodeDiagnosticInfo),
    };
}

pub fn freeSetMonitoringModeResponse(a: std.mem.Allocator, v: SetMonitoringModeResponse) void {
    freeResponseHeader(a, v.response_header);
    if (v.results) |r| a.free(r);
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
/// sender certificate + receiver thumbprint — both null at
/// SecurityMode=None), MSG and CLO carry the
/// `SymmetricAlgorithmSecurityHeader` (just the u32 TokenId) —
/// ground-truthed against open62541 (`UA_SecureChannel_
/// sendAsymmetricOPNMessage`/`sendSymmetricMessage`), OPC 10000-6 §6.7.2/
/// §7.2/§7.3 name the shapes but not which chunk types use which. At
/// SecurityMode Sign/SignAndEncrypt every outgoing/incoming chunk
/// additionally rides through `security.zig`'s seal/open functions (OPN:
/// RSA sign + OAEP encrypt; MSG/CLO: HMAC-SHA256 +, for SignAndEncrypt,
/// AES-256-CBC).
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
    /// `null` (the default) keeps this channel's SecurityMode=None behavior
    /// byte-for-byte unchanged — `sendService`/`recvService` only branch
    /// into `security.zig`'s crypto when this is non-null *and*
    /// `.mode != .none`. See `security.SecurityContext`; `root.
    /// SecureChannel.open` populates `.keys` from the OPN nonce exchange.
    security: ?security.SecurityContext = null,

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
        const sec_mode: security.SecurityMode = if (ch.security) |sec| sec.mode else .none;
        // For a secure OPN: where the encrypted region (the SequenceHeader)
        // starts within the body being built — right after the
        // AsymmetricAlgorithmSecurityHeader (OPC 10000-6 §6.7.2).
        var opn_encrypted_region_offset: usize = 0;
        switch (message_type) {
            .open_secure_channel => {
                if (sec_mode == .none) {
                    // Unchanged from before the security layer landed —
                    // byte-identical to the original SecurityMode=None-only
                    // code path.
                    try e.encodeString(security_policy_none_uri);
                    try e.encodeByteString(null); // SenderCertificate — none at SecurityMode=None
                    try e.encodeByteString(null); // ReceiverCertificateThumbprint
                } else {
                    // Sign/SignAndEncrypt: the real
                    // AsymmetricAlgorithmSecurityHeader, carrying this
                    // client's certificate + the pinned server certificate's
                    // SHA-1 thumbprint.
                    const sec = ch.security.?;
                    const creds = sec.credentials orelse @panic("opcua security: SecurityMode != none requires ClientCredentials");
                    const server_cert = sec.server_certificate orelse @panic("opcua security: SecurityMode != none requires a pinned server certificate");
                    const thumbprint = security.certificateThumbprint(server_cert);
                    try security.encodeAsymmetricAlgorithmSecurityHeader(&e, .{
                        .security_policy_uri = sec.policy.uri(),
                        .sender_certificate = creds.certificate_der,
                        .receiver_certificate_thumbprint = &thumbprint,
                    });
                    opn_encrypted_region_offset = allocating.writer.buffered().len;
                }
            },
            .message, .close_secure_channel => {
                // SymmetricAlgorithmSecurityHeader is just the TokenId at
                // every SecurityMode — Sign/SignAndEncrypt instead change
                // how the *body* is framed below (see the `body` hook after
                // this switch), not this header.
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

        // Sign/SignAndEncrypt: hand the plaintext body to security.zig,
        // which returns the complete wire message (the 8-byte MessageHeader
        // is part of the signed range, so the security layer builds it).
        // `ch.security == null` or `.mode == .none` skips this block
        // entirely — `body` is sent exactly as built above, unchanged.
        if (ch.security) |sec| if (sec.mode != .none) {
            const secured = switch (message_type) {
                .open_secure_channel => blk: {
                    // Presence of credentials/server certificate was already
                    // enforced while encoding the asym header above.
                    const random = sec.random orelse @panic("opcua security: SecurityMode != none requires SecurityContext.random");
                    break :blk try security.sealAsymmetricMessage(
                        ch.allocator,
                        random,
                        message_type.code(),
                        body,
                        opn_encrypted_region_offset,
                        sec.credentials.?,
                        sec.server_certificate.?,
                    );
                },
                .message, .close_secure_channel => blk: {
                    const keys = sec.keys orelse @panic("opcua security: SecurityMode != none requires derived ChannelKeys");
                    break :blk try security.symmetricSignAndEncrypt(ch.allocator, message_type.code(), body, sec.mode, keys, .client_to_server);
                },
                else => unreachable,
            };
            defer ch.allocator.free(secured);
            std.crypto.secureZero(u8, body); // the plaintext request is spent
            try ch.conn.writer.writeAll(secured);
            try ch.conn.writer.flush();
            return;
        };

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

            // Sign/SignAndEncrypt: decrypt + verify each chunk *before*
            // reassembly (every chunk is individually secured — OPC 10000-6
            // §6.7.2). The signature covers the 8-byte MessageHeader the
            // transport already consumed, so it's reconstructed here.
            // `ch.security == null` or `.mode == .none` feeds the chunk
            // body through unchanged.
            var fed: []const u8 = chunk.body;
            var opened: ?[]u8 = null;
            defer if (opened) |o| {
                std.crypto.secureZero(u8, o);
                ch.allocator.free(o);
            };
            if (ch.security) |sec| if (sec.mode != .none) {
                var header_bytes: [8]u8 = undefined;
                header_bytes[0..3].* = chunk.header.message_type.code().*;
                header_bytes[3] = @intFromEnum(chunk.header.chunk_type);
                std.mem.writeInt(u32, header_bytes[4..8], chunk.header.message_size, .little);
                opened = switch (message_type) {
                    .open_secure_channel => blk: {
                        const creds = sec.credentials orelse @panic("opcua security: SecurityMode != none requires ClientCredentials");
                        const server_cert = sec.server_certificate orelse @panic("opcua security: SecurityMode != none requires a pinned server certificate");
                        break :blk try security.openAsymmetricMessage(ch.allocator, &header_bytes, chunk.body, creds.private_key, server_cert);
                    },
                    .message, .close_secure_channel => blk: {
                        const keys = sec.keys orelse @panic("opcua security: SecurityMode != none requires derived ChannelKeys");
                        break :blk try security.symmetricDecryptAndVerify(ch.allocator, &header_bytes, chunk.body, sec.mode, keys, .server_to_client);
                    },
                    else => unreachable,
                };
                fed = opened.?;
            };
            // Strip this chunk's own Secure-Conversation + Sequence headers
            // *before* reassembly. OPC 10000-6 §6.7.2: **every** chunk of a
            // message carries them, not just the first — stripping them only
            // once after reassembly (as this did before a chunked response
            // from the sibling `server.zig` caught it) splices 16 bytes of
            // header into the middle of the message body.
            var hr: std.Io.Reader = .fixed(fed);
            _ = try hr.takeInt(u32, .little); // SecureChannelId (echoed back)
            switch (message_type) {
                .open_secure_channel => {
                    // AsymmetricAlgorithmSecurityHeader: SecurityPolicyUri,
                    // SenderCertificate, ReceiverCertificateThumbprint. At
                    // SecurityMode != None the chunk was already decrypted +
                    // signature-verified above (against the *pinned* server
                    // certificate), so these plaintext fields need no further
                    // checks — skipped without allocating.
                    for (0..3) |_| _ = try skipLengthPrefixed(&hr);
                },
                .message, .close_secure_channel => {
                    _ = try hr.takeInt(u32, .little); // TokenId
                },
                else => unreachable,
            }
            _ = try hr.takeInt(u32, .little); // SequenceNumber — not independently validated
            const chunk_request_id = try hr.takeInt(u32, .little);
            if (chunk_request_id != ch.request_id) return error.UnexpectedResponseType;

            if (try assembler.feed(chunk.header.chunk_type, hr.buffered())) |msg| break msg;
        };

        var r: std.Io.Reader = .fixed(full);
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
fn createSubscriptionResult(r: CreateSubscriptionResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn modifySubscriptionResult(r: ModifySubscriptionResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn setPublishingModeResult(r: SetPublishingModeResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn deleteSubscriptionsResult(r: DeleteSubscriptionsResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn createMonitoredItemsResult(r: CreateMonitoredItemsResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn deleteMonitoredItemsResult(r: DeleteMonitoredItemsResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn publishResult(r: PublishResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn republishResult(r: RepublishResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn getEndpointsResult(r: GetEndpointsResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn findServersResult(r: FindServersResponse) encoding.StatusCode {
    return r.response_header.service_result;
}
fn translateBrowsePathsResult(r: TranslateBrowsePathsToNodeIdsResponse) encoding.StatusCode {
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
    pub const create_subscription = createSubscriptionResult;
    pub const modify_subscription = modifySubscriptionResult;
    pub const set_publishing_mode = setPublishingModeResult;
    pub const delete_subscriptions = deleteSubscriptionsResult;
    pub const create_monitored_items = createMonitoredItemsResult;
    pub const delete_monitored_items = deleteMonitoredItemsResult;
    pub const publish = publishResult;
    pub const republish = republishResult;
    pub const get_endpoints = getEndpointsResult;
    pub const find_servers = findServersResult;
    pub const translate_browse_paths_to_node_ids = translateBrowsePathsResult;
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

// ── Part 5 (Subscriptions/MonitoredItems/Publish) tests ─────────────────────

test "MonitoringMode: ground-truthed constant values" {
    // OPC Foundation UA-Nodeset Schema/Opc.Ua.Types.bsd `MonitoringMode`
    // EnumeratedType, fetched directly during implementation.
    try testing.expectEqual(@as(u32, 0), @intFromEnum(MonitoringMode.disabled));
    try testing.expectEqual(@as(u32, 1), @intFromEnum(MonitoringMode.sampling));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(MonitoringMode.reporting));
}

test "well-known Encoding_DefaultBinary NodeIds: Part 5 constants" {
    try testing.expectEqualDeep(n0(787), type_id.create_subscription_request);
    try testing.expectEqualDeep(n0(790), type_id.create_subscription_response);
    try testing.expectEqualDeep(n0(751), type_id.create_monitored_items_request);
    try testing.expectEqualDeep(n0(754), type_id.create_monitored_items_response);
    try testing.expectEqualDeep(n0(826), type_id.publish_request);
    try testing.expectEqualDeep(n0(829), type_id.publish_response);
    try testing.expectEqualDeep(n0(811), type_id.data_change_notification);
    try testing.expectEqualDeep(n0(820), type_id.status_change_notification);
    try testing.expectEqualDeep(n0(916), type_id.event_notification_list);
    try testing.expectEqualDeep(n0(847), type_id.delete_subscriptions_request);
    try testing.expectEqualDeep(n0(850), type_id.delete_subscriptions_response);
}

test "CreateSubscriptionRequest/Response round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const req: CreateSubscriptionRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .requested_publishing_interval = 250.0,
        .requested_lifetime_count = 10000,
        .requested_max_keep_alive_count = 10,
        .max_notifications_per_publish = 0,
        .publishing_enabled = true,
        .priority = 0,
    };
    try encodeCreateSubscriptionRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCreateSubscriptionRequest(&d);
    defer freeCreateSubscriptionRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(f64, 250.0), decoded.requested_publishing_interval);
    try testing.expectEqual(@as(u32, 10000), decoded.requested_lifetime_count);
    try testing.expectEqual(true, decoded.publishing_enabled);

    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const resp: CreateSubscriptionResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .subscription_id = 42,
        .revised_publishing_interval = 250.0,
        .revised_lifetime_count = 10000,
        .revised_max_keep_alive_count = 10,
    };
    try encodeCreateSubscriptionResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeCreateSubscriptionResponse(&d2);
    defer freeCreateSubscriptionResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(u32, 42), decoded2.subscription_id);
    try testing.expectEqual(@as(u32, 10), decoded2.revised_max_keep_alive_count);
}

test "ModifySubscriptionRequest/Response + SetPublishingMode + DeleteSubscriptions round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const mod_req: ModifySubscriptionRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_id = 42,
        .requested_publishing_interval = 500.0,
        .requested_lifetime_count = 20000,
        .requested_max_keep_alive_count = 20,
        .max_notifications_per_publish = 100,
        .priority = 1,
    };
    try encodeModifySubscriptionRequest(&e, mod_req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const mod_decoded = try decodeModifySubscriptionRequest(&d);
    defer freeModifySubscriptionRequest(testing.allocator, mod_decoded);
    try testing.expectEqual(@as(u32, 42), mod_decoded.subscription_id);
    try testing.expectEqual(@as(f64, 500.0), mod_decoded.requested_publishing_interval);

    var buf1b: [256]u8 = undefined;
    var w1b: std.Io.Writer = .fixed(&buf1b);
    var e1b = encoding.Encoder.init(&w1b);
    const mod_resp: ModifySubscriptionResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .revised_publishing_interval = 500.0,
        .revised_lifetime_count = 20000,
        .revised_max_keep_alive_count = 20,
    };
    try encodeModifySubscriptionResponse(&e1b, mod_resp);
    var r1b: std.Io.Reader = .fixed(w1b.buffered());
    var d1b = encoding.Decoder.init(&r1b, testing.allocator);
    const mod_resp_decoded = try decodeModifySubscriptionResponse(&d1b);
    defer freeModifySubscriptionResponse(testing.allocator, mod_resp_decoded);
    try testing.expectEqual(@as(u32, 20000), mod_resp_decoded.revised_lifetime_count);

    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const sub_ids = [_]u32{ 42, 43 };
    const spm_req: SetPublishingModeRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 2, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .publishing_enabled = false,
        .subscription_ids = &sub_ids,
    };
    try encodeSetPublishingModeRequest(&e2, spm_req);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const spm_decoded = try decodeSetPublishingModeRequest(&d2);
    defer freeSetPublishingModeRequest(testing.allocator, spm_decoded);
    try testing.expectEqual(false, spm_decoded.publishing_enabled);
    try testing.expectEqual(@as(usize, 2), spm_decoded.subscription_ids.?.len);

    var buf3: [256]u8 = undefined;
    var w3: std.Io.Writer = .fixed(&buf3);
    var e3 = encoding.Encoder.init(&w3);
    const spm_results = [_]encoding.StatusCode{ 0, 0x80740000 };
    const spm_resp: SetPublishingModeResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 2, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &spm_results,
        .diagnostic_infos = null,
    };
    try encodeSetPublishingModeResponse(&e3, spm_resp);
    var r3: std.Io.Reader = .fixed(w3.buffered());
    var d3 = encoding.Decoder.init(&r3, testing.allocator);
    const spm_resp_decoded = try decodeSetPublishingModeResponse(&d3);
    defer freeSetPublishingModeResponse(testing.allocator, spm_resp_decoded);
    try testing.expect(isBad(spm_resp_decoded.results.?[1]));

    var buf4: [256]u8 = undefined;
    var w4: std.Io.Writer = .fixed(&buf4);
    var e4 = encoding.Encoder.init(&w4);
    const del_req: DeleteSubscriptionsRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 3, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_ids = &sub_ids,
    };
    try encodeDeleteSubscriptionsRequest(&e4, del_req);
    var r4: std.Io.Reader = .fixed(w4.buffered());
    var d4 = encoding.Decoder.init(&r4, testing.allocator);
    const del_decoded = try decodeDeleteSubscriptionsRequest(&d4);
    defer freeDeleteSubscriptionsRequest(testing.allocator, del_decoded);
    try testing.expectEqual(@as(u32, 43), del_decoded.subscription_ids.?[1]);

    var buf5: [256]u8 = undefined;
    var w5: std.Io.Writer = .fixed(&buf5);
    var e5 = encoding.Encoder.init(&w5);
    const del_results = [_]encoding.StatusCode{ 0, 0 };
    const del_resp: DeleteSubscriptionsResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 3, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &del_results,
        .diagnostic_infos = null,
    };
    try encodeDeleteSubscriptionsResponse(&e5, del_resp);
    var r5: std.Io.Reader = .fixed(w5.buffered());
    var d5 = encoding.Decoder.init(&r5, testing.allocator);
    const del_resp_decoded = try decodeDeleteSubscriptionsResponse(&d5);
    defer freeDeleteSubscriptionsResponse(testing.allocator, del_resp_decoded);
    try testing.expectEqual(@as(usize, 2), del_resp_decoded.results.?.len);
}

test "MonitoringParameters/MonitoredItemCreateRequest/CreateMonitoredItemsRequest round-trip (null filter)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const items = [_]MonitoredItemCreateRequest{.{
        .item_to_monitor = .{
            .node_id = .{ .numeric = .{ .namespace = 0, .id = 2258 } },
            .attribute_id = attribute_id.value,
            .index_range = null,
            .data_encoding = .{ .namespace_index = 0, .name = null },
        },
        .monitoring_mode = .reporting,
        .requested_parameters = .{
            .client_handle = 1,
            .sampling_interval = 250.0,
            .filter = no_filter,
            .queue_size = 1,
            .discard_oldest = true,
        },
    }};
    const req: CreateMonitoredItemsRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_id = 42,
        .timestamps_to_return = .both,
        .items_to_create = &items,
    };
    try encodeCreateMonitoredItemsRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCreateMonitoredItemsRequest(&d);
    defer freeCreateMonitoredItemsRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 42), decoded.subscription_id);
    try testing.expectEqual(@as(usize, 1), decoded.items_to_create.?.len);
    try testing.expectEqual(MonitoringMode.reporting, decoded.items_to_create.?[0].monitoring_mode);
    try testing.expectEqual(@as(u32, 1), decoded.items_to_create.?[0].requested_parameters.client_handle);
    try testing.expectEqual(ExtensionObjectEncodingNoBody, decoded.items_to_create.?[0].requested_parameters.filter.encoding);
}

const ExtensionObjectEncodingNoBody = encoding.ExtensionObjectEncoding.no_body;

test "CreateMonitoredItemsResponse/DeleteMonitoredItems round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const results = [_]MonitoredItemCreateResult{.{
        .status_code = 0,
        .monitored_item_id = 1,
        .revised_sampling_interval = 250.0,
        .revised_queue_size = 1,
        .filter_result = no_filter,
    }};
    const resp: CreateMonitoredItemsResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &results,
        .diagnostic_infos = null,
    };
    try encodeCreateMonitoredItemsResponse(&e, resp);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeCreateMonitoredItemsResponse(&d);
    defer freeCreateMonitoredItemsResponse(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 1), decoded.results.?[0].monitored_item_id);
    try testing.expectEqual(@as(f64, 250.0), decoded.results.?[0].revised_sampling_interval);

    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const item_ids = [_]u32{1};
    const del_req: DeleteMonitoredItemsRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 2, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_id = 42,
        .monitored_item_ids = &item_ids,
    };
    try encodeDeleteMonitoredItemsRequest(&e2, del_req);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const del_decoded = try decodeDeleteMonitoredItemsRequest(&d2);
    defer freeDeleteMonitoredItemsRequest(testing.allocator, del_decoded);
    try testing.expectEqual(@as(u32, 1), del_decoded.monitored_item_ids.?[0]);

    var buf3: [256]u8 = undefined;
    var w3: std.Io.Writer = .fixed(&buf3);
    var e3 = encoding.Encoder.init(&w3);
    const del_results = [_]encoding.StatusCode{0};
    const del_resp: DeleteMonitoredItemsResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 2, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .results = &del_results,
        .diagnostic_infos = null,
    };
    try encodeDeleteMonitoredItemsResponse(&e3, del_resp);
    var r3: std.Io.Reader = .fixed(w3.buffered());
    var d3 = encoding.Decoder.init(&r3, testing.allocator);
    const del_resp_decoded = try decodeDeleteMonitoredItemsResponse(&d3);
    defer freeDeleteMonitoredItemsResponse(testing.allocator, del_resp_decoded);
    try testing.expect(!isBad(del_resp_decoded.results.?[0]));
}

test "NotificationMessage round-trip: DataChangeNotification ExtensionObject decodes back cleanly" {
    // The shape `root.zig`'s `Subscription.publish` actually parses: a
    // `NotificationMessage.NotificationData[0]` whose `TypeId` is
    // `type_id.data_change_notification` and whose body is itself a
    // binary-encoded `DataChangeNotification`.
    var dcn_buf: [256]u8 = undefined;
    var dcn_w: std.Io.Writer = .fixed(&dcn_buf);
    var dcn_e = encoding.Encoder.init(&dcn_w);
    const mi_notifications = [_]MonitoredItemNotification{.{
        .client_handle = 7,
        .value = .{ .value = .{ .scalar = .{ .date_time = 132223104000000000 } }, .status = 0 },
    }};
    try encodeDataChangeNotification(&dcn_e, .{ .monitored_items = &mi_notifications, .diagnostic_infos = null });
    const dcn_body = dcn_w.buffered();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const notif_data = [_]encoding.ExtensionObject{.{
        .type_id = type_id.data_change_notification,
        .encoding = .byte_string,
        .body = dcn_body,
    }};
    const msg: NotificationMessage = .{
        .sequence_number = 1,
        .publish_time = 0,
        .notification_data = &notif_data,
    };
    try encodeNotificationMessage(&e, msg);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeNotificationMessage(&d);
    defer freeNotificationMessage(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 1), decoded.sequence_number);
    try testing.expectEqual(@as(usize, 1), decoded.notification_data.?.len);
    try testing.expect(nodeIdEql(decoded.notification_data.?[0].type_id, type_id.data_change_notification));

    var inner_r: std.Io.Reader = .fixed(decoded.notification_data.?[0].body);
    var inner_d = encoding.Decoder.init(&inner_r, testing.allocator);
    const dcn = try decodeDataChangeNotification(&inner_d);
    defer freeDataChangeNotification(testing.allocator, dcn);
    try testing.expectEqual(@as(usize, 1), dcn.monitored_items.?.len);
    try testing.expectEqual(@as(u32, 7), dcn.monitored_items.?[0].client_handle);
    try testing.expectEqual(@as(encoding.DateTime, 132223104000000000), dcn.monitored_items.?[0].value.value.?.scalar.date_time);
}

test "StatusChangeNotification/EventNotificationList round-trip" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const scn: StatusChangeNotification = .{ .status = 0x80730000, .diagnostic_info = .{} }; // BadTimeout-shaped
    try encodeStatusChangeNotification(&e, scn);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeStatusChangeNotification(&d);
    defer freeStatusChangeNotification(testing.allocator, decoded);
    try testing.expect(isBad(decoded.status));

    var buf2: [256]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const event_fields = [_]encoding.Variant{.{ .scalar = .{ .int32 = 3 } }};
    const events = [_]EventFieldList{.{ .client_handle = 9, .event_fields = &event_fields }};
    const enl: EventNotificationList = .{ .events = &events };
    try encodeEventNotificationList(&e2, enl);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const enl_decoded = try decodeEventNotificationList(&d2);
    defer freeEventNotificationList(testing.allocator, enl_decoded);
    try testing.expectEqual(@as(u32, 9), enl_decoded.events.?[0].client_handle);
    try testing.expectEqual(@as(i32, 3), enl_decoded.events.?[0].event_fields.?[0].scalar.int32);
}

test "PublishRequest/Response round-trip (incl. SubscriptionAcknowledgement + DataChangeNotification)" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const acks = [_]SubscriptionAcknowledgement{.{ .subscription_id = 42, .sequence_number = 1 }};
    const req: PublishRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_acknowledgements = &acks,
    };
    try encodePublishRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodePublishRequest(&d);
    defer freePublishRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 42), decoded.subscription_acknowledgements.?[0].subscription_id);

    var dcn_buf: [256]u8 = undefined;
    var dcn_w: std.Io.Writer = .fixed(&dcn_buf);
    var dcn_e = encoding.Encoder.init(&dcn_w);
    const mi_notifications = [_]MonitoredItemNotification{.{
        .client_handle = 1,
        .value = .{ .value = .{ .scalar = .{ .double = 21.5 } }, .status = 0 },
    }};
    try encodeDataChangeNotification(&dcn_e, .{ .monitored_items = &mi_notifications, .diagnostic_infos = null });

    var buf2: [1024]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    const notif_data = [_]encoding.ExtensionObject{.{ .type_id = type_id.data_change_notification, .encoding = .byte_string, .body = dcn_w.buffered() }};
    const avail_seqs = [_]u32{1};
    const resp: PublishResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .subscription_id = 42,
        .available_sequence_numbers = &avail_seqs,
        .more_notifications = false,
        .notification_message = .{ .sequence_number = 1, .publish_time = 0, .notification_data = &notif_data },
        .results = null,
        .diagnostic_infos = null,
    };
    try encodePublishResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodePublishResponse(&d2);
    defer freePublishResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(u32, 42), decoded2.subscription_id);
    try testing.expectEqual(@as(u32, 1), decoded2.available_sequence_numbers.?[0]);
    try testing.expectEqual(@as(usize, 1), decoded2.notification_message.notification_data.?.len);
    try testing.expect(nodeIdEql(decoded2.notification_message.notification_data.?[0].type_id, type_id.data_change_notification));
}

test "RepublishRequest/Response round-trip" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    const req: RepublishRequest = .{
        .request_header = .{ .authentication_token = null_node_id, .timestamp = 0, .request_handle = 1, .return_diagnostics = 0, .audit_entry_id = null, .timeout_hint = 0, .additional_header = no_additional_header },
        .subscription_id = 42,
        .retransmit_sequence_number = 1,
    };
    try encodeRepublishRequest(&e, req);
    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeRepublishRequest(&d);
    defer freeRepublishRequest(testing.allocator, decoded);
    try testing.expectEqual(@as(u32, 42), decoded.subscription_id);
    try testing.expectEqual(@as(u32, 1), decoded.retransmit_sequence_number);

    var buf2: [512]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&buf2);
    var e2 = encoding.Encoder.init(&w2);
    var dcn_buf: [256]u8 = undefined;
    var dcn_w: std.Io.Writer = .fixed(&dcn_buf);
    var dcn_e = encoding.Encoder.init(&dcn_w);
    const mi_notifications = [_]MonitoredItemNotification{.{
        .client_handle = 1,
        .value = .{ .value = .{ .scalar = .{ .double = 21.5 } }, .status = 0 },
    }};
    try encodeDataChangeNotification(&dcn_e, .{ .monitored_items = &mi_notifications, .diagnostic_infos = null });
    const notif_data = [_]encoding.ExtensionObject{.{ .type_id = type_id.data_change_notification, .encoding = .byte_string, .body = dcn_w.buffered() }};
    const resp: RepublishResponse = .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = no_additional_header },
        .notification_message = .{ .sequence_number = 5, .publish_time = 0, .notification_data = &notif_data },
    };
    try encodeRepublishResponse(&e2, resp);
    var r2: std.Io.Reader = .fixed(w2.buffered());
    var d2 = encoding.Decoder.init(&r2, testing.allocator);
    const decoded2 = try decodeRepublishResponse(&d2);
    defer freeRepublishResponse(testing.allocator, decoded2);
    try testing.expectEqual(@as(u32, 5), decoded2.notification_message.sequence_number);
    try testing.expectEqual(@as(u32, 5), decoded2.notification_message.sequence_number);
}
