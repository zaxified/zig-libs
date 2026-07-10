// SPDX-License-Identifier: MIT

//! opcua — an OPC-UA (IEC 62541 / OPC 10000) binary client: the opc.tcp wire
//! protocol (OPC 10000-6) over `SecurityPolicy#None` (no signing/encryption —
//! that's a separate later module, F9, layered on the `rsa` module).
//!
//! This is F1 "core": the built-in type codec (`encoding`, OPC 10000-6 §5.2)
//! and the opc.tcp transport framing (`transport`, OPC 10000-6 §7) are fully
//! scaffolded (real types, stubbed codec bodies). The service layer riding on
//! top — OpenSecureChannel/CloseSecureChannel (F1-b), CreateSession/
//! ActivateSession/CloseSession (F1-c), and Read/Write/Browse/Call (F1-d) — is
//! reserved here as one-line `@panic` stubs for a later implementing agent.
//!
//! Model: OPC 10000-6 (OPC UA Binary encoding + opc.tcp transport). Structure
//! references open62541 (MPL-2.0) and node-opcua (MIT) — behavioral/API-shape
//! only, no source copied. See `NOTICE` for the full provenance note.

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure codec + a caller-supplied stream; no socket of its own
    .role = .client,
    .concurrency = .reentrant, // no shared state; Connection/Encoder/Decoder are caller-owned
    .model_after = "OPC 10000-6 (OPC UA Binary + opc.tcp); structure ref open62541 (MPL-2.0) / node-opcua (MIT) — behavioral only, no source copied",
    .deps = .{},
};

/// The built-in type codec (OPC 10000-6 §5.2): `Encoder`/`Decoder` over a
/// `std.Io.Writer`/`std.Io.Reader`, plus the `NodeId`/`Variant`/`DataValue`/…
/// types every OPC UA message body is built from.
pub const encoding = @import("encoding.zig");

/// The opc.tcp transport (OPC 10000-6 §7): the Hello/Acknowledge handshake,
/// the 8-byte message-chunk header, and the `Connection` wired over a
/// caller-supplied reader/writer pair (this module never opens a socket).
pub const transport = @import("transport.zig");

/// The service-message framing (OPC 10000-4): `RequestHeader`/
/// `ResponseHeader`, the concrete OpenSecureChannel/CreateSession/
/// ActivateSession/CloseSession/CloseSecureChannel/ServiceFault structures,
/// and `Channel` — the chunked send/recv helper `SecureChannel`/`Session`
/// below are built on.
pub const services = @import("services.zig");

// Pull the submodules' tests into this module's test binary — a bare
// re-export does NOT drag in the imported file's `test` blocks (the
// dark-tests rule; see CONVENTIONS.md §6.3).
test {
    _ = encoding;
    _ = transport;
    _ = services;
}

// ── F2: Secure Channel (SecurityPolicy#None) ────────────────────────────────

/// OpenSecureChannel / CloseSecureChannel (OPC 10000-4 §5.5.2/§5.5.3) over
/// `SecurityPolicy#None`: no signing/encryption (that's SecurityMode=None's
/// entire point) — the OPN request/response still carry the
/// `AsymmetricAlgorithmSecurityHeader` (SecurityPolicyUri + null sender-cert/
/// receiver-thumbprint), and the returned channel/token ids still gate every
/// later MSG/CLO chunk's `SymmetricAlgorithmSecurityHeader` (OPC 10000-6
/// §7.2/§7.3; behavior ground-truthed against open62541's
/// `sendAsymmetricOPNMessage`/`sendSymmetricMessage` split).
pub const SecureChannel = struct {
    io: services.Channel,
    token_created_at: encoding.DateTime = 0,
    token_lifetime_ms: u32 = 0,

    pub const OpenOptions = struct {
        /// `OpenSecureChannelRequest.RequestedLifetime`, milliseconds. The
        /// server may revise this (`OpenSecureChannelResponse.SecurityToken.
        /// RevisedLifetime`, stored on `SecureChannel.token_lifetime_ms`);
        /// 1 hour is open62541/node-opcua's default client ballpark.
        requested_lifetime_ms: u32 = 3_600_000,
        /// `RequestHeader.TimeoutHint`, milliseconds (0 = no timeout).
        timeout_hint_ms: u32 = 10_000,
    };

    /// Perform the OpenSecureChannel request/response (Issue, not Renew —
    /// channel renewal is out of F2's scope) and return the opened channel.
    /// `conn` must already have completed the Hello/Acknowledge handshake
    /// (`transport.connect`/`Connection.hello`).
    pub fn open(conn: *transport.Connection, allocator: std.mem.Allocator, options: OpenOptions) services.ServiceError!SecureChannel {
        var ch: SecureChannel = .{ .io = .{ .conn = conn, .allocator = allocator } };

        const request: services.OpenSecureChannelRequest = .{
            .request_header = ch.io.nextRequestHeader(services.null_node_id, options.timeout_hint_ms),
            .client_protocol_version = 0,
            .request_type = .issue,
            .security_mode = .none,
            .client_nonce = &.{}, // present-but-empty: unused at SecurityMode=None
            .requested_lifetime = options.requested_lifetime_ms,
        };
        const response = try services.Channel.call(
            &ch.io,
            .open_secure_channel,
            services.type_id.open_secure_channel_request,
            services.OpenSecureChannelRequest,
            request,
            services.encodeOpenSecureChannelRequest,
            services.OpenSecureChannelResponse,
            services.type_id.open_secure_channel_response,
            services.decodeOpenSecureChannelResponse,
            services.result_fns.open_secure_channel,
        );
        defer services.freeOpenSecureChannelResponse(allocator, response);

        ch.io.channel_id = response.security_token.channel_id;
        ch.io.token_id = response.security_token.token_id;
        ch.token_created_at = response.security_token.created_at;
        ch.token_lifetime_ms = response.security_token.revised_lifetime;
        return ch;
    }

    /// Send the CloseSecureChannel request in a CLO chunk. Per OPC 10000-6
    /// §6.7.2 (ground-truthed against open62541's `Service_
    /// CloseSecureChannel`: "the server does not send a CloseSecureChannel
    /// response") the server closes its end of the channel without replying
    /// — this does not wait for or expect one; the caller is expected to
    /// close the underlying socket next.
    pub fn close(ch: *SecureChannel) services.ServiceError!void {
        const request: services.CloseSecureChannelRequest = .{
            .request_header = ch.io.nextRequestHeader(services.null_node_id, 0),
        };
        try ch.io.sendService(
            .close_secure_channel,
            services.type_id.close_secure_channel_request,
            services.CloseSecureChannelRequest,
            request,
            services.encodeCloseSecureChannelRequest,
        );
    }
};

// ── F2: Session ──────────────────────────────────────────────────────────────

/// CreateSession / ActivateSession / CloseSession (OPC 10000-4 §5.6),
/// anonymous identity only (no user-name/certificate/issued-token — those
/// need signing machinery this module doesn't have; see the module doc
/// comment's "No crypto" non-goal).
pub const Session = struct {
    channel: *SecureChannel,
    session_id: encoding.NodeId = services.null_node_id,
    authentication_token: encoding.NodeId = services.null_node_id,
    revised_timeout_ms: f64 = 0,
    /// Owned by this `Session` (allocated with `create`'s `allocator`);
    /// `activate` scans it for an Anonymous `UserTokenPolicy` when the
    /// caller doesn't pin one down. Freed by `deinit`.
    server_endpoints: ?[]const services.EndpointDescription = null,
    allocator: std.mem.Allocator = undefined,

    pub const CreateOptions = struct {
        client_description: services.ApplicationDescription,
        server_uri: ?[]const u8 = null,
        endpoint_url: []const u8,
        session_name: ?[]const u8 = null,
        /// Milliseconds; the server may revise this down (see
        /// `Session.revised_timeout_ms`).
        requested_session_timeout_ms: f64 = 1_200_000,
        timeout_hint_ms: u32 = 10_000,
    };

    /// Perform the CreateSession request/response.
    pub fn create(channel: *SecureChannel, allocator: std.mem.Allocator, options: CreateOptions) services.ServiceError!Session {
        var session: Session = .{ .channel = channel, .allocator = allocator };

        const request: services.CreateSessionRequest = .{
            .request_header = channel.io.nextRequestHeader(services.null_node_id, options.timeout_hint_ms),
            .client_description = options.client_description,
            .server_uri = options.server_uri,
            .endpoint_url = options.endpoint_url,
            .session_name = options.session_name,
            .client_nonce = &.{},
            .client_certificate = null,
            .requested_session_timeout = options.requested_session_timeout_ms,
            .max_response_message_size = 0, // 0 = no limit
        };
        const response = try services.Channel.call(
            &channel.io,
            .message,
            services.type_id.create_session_request,
            services.CreateSessionRequest,
            request,
            services.encodeCreateSessionRequest,
            services.CreateSessionResponse,
            services.type_id.create_session_response,
            services.decodeCreateSessionResponse,
            services.result_fns.create_session,
        );
        errdefer services.freeCreateSessionResponse(allocator, response);

        session.session_id = response.session_id;
        session.authentication_token = response.authentication_token;
        session.revised_timeout_ms = response.revised_session_timeout;
        session.server_endpoints = response.server_endpoints;
        // response_header/session_id/authentication_token/server_nonce/
        // server_certificate carry no owned memory we need past this point
        // except server_endpoints (kept above) — free the rest now.
        services.freeResponseHeader(allocator, response.response_header);
        if (response.server_nonce) |n| allocator.free(n);
        if (response.server_certificate) |c| allocator.free(c);
        return session;
    }

    /// Find the first Anonymous `UserTokenPolicy.PolicyId` advertised across
    /// `server_endpoints` (OPC 10000-4 §5.6.3.2: the client is expected to
    /// echo back a policy id the server actually advertised). Returns `null`
    /// if no endpoint advertised one (some servers accept an empty PolicyId
    /// as an Anonymous-token fallback — `activate`'s caller decides).
    pub fn findAnonymousPolicyId(session: *const Session) ?[]const u8 {
        const endpoints = session.server_endpoints orelse return null;
        for (endpoints) |ep| {
            const tokens = ep.user_identity_tokens orelse continue;
            for (tokens) |t| {
                if (t.token_type == .anonymous) return t.policy_id;
            }
        }
        return null;
    }

    /// Perform the ActivateSession request/response with an Anonymous
    /// identity token. `policy_id` overrides `findAnonymousPolicyId`'s
    /// lookup (pass `null` to use it, falling back to `""` if no endpoint
    /// advertised an Anonymous policy — several servers, e.g. open62541,
    /// accept an empty PolicyId for compatibility).
    pub fn activate(session: *Session, policy_id: ?[]const u8) services.ServiceError!void {
        const resolved_policy_id = policy_id orelse (session.findAnonymousPolicyId() orelse "");

        var token_buf = std.Io.Writer.Allocating.init(session.allocator);
        defer token_buf.deinit();
        var token_e = encoding.Encoder.init(&token_buf.writer);
        try services.encodeAnonymousIdentityToken(&token_e, .{ .policy_id = resolved_policy_id });

        const request: services.ActivateSessionRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .client_signature = .{ .algorithm = null, .signature = null },
            .client_software_certificates = null,
            .locale_ids = null,
            .user_identity_token = .{
                .type_id = services.type_id.anonymous_identity_token,
                .encoding = .byte_string,
                .body = token_buf.writer.buffered(),
            },
            .user_token_signature = .{ .algorithm = null, .signature = null },
        };
        const response = try services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.activate_session_request,
            services.ActivateSessionRequest,
            request,
            services.encodeActivateSessionRequest,
            services.ActivateSessionResponse,
            services.type_id.activate_session_response,
            services.decodeActivateSessionResponse,
            services.result_fns.activate_session,
        );
        services.freeActivateSessionResponse(session.allocator, response);
    }

    /// Perform the CloseSession request/response.
    pub fn close(session: *Session, delete_subscriptions: bool) services.ServiceError!void {
        const request: services.CloseSessionRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .delete_subscriptions = delete_subscriptions,
        };
        const response = try services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.close_session_request,
            services.CloseSessionRequest,
            request,
            services.encodeCloseSessionRequest,
            services.CloseSessionResponse,
            services.type_id.close_session_response,
            services.decodeCloseSessionResponse,
            services.result_fns.close_session,
        );
        services.freeCloseSessionResponse(session.allocator, response);
    }

    /// Free `server_endpoints` (owned since `create`). Safe to call even if
    /// `create` failed partway (never populated) or was never called.
    pub fn deinit(session: *Session) void {
        if (session.server_endpoints) |endpoints| {
            for (endpoints) |ep| services.freeEndpointDescription(session.allocator, ep);
            session.allocator.free(endpoints);
            session.server_endpoints = null;
        }
    }

    // ── F1-d: core services ─────────────────────────────────────────────────
    // Read/Write/Browse/BrowseNext/Call, mirroring `create`/`activate`/
    // `close`'s shape: build the request off `session.channel.io.
    // nextRequestHeader`, `services.Channel.call` it, caller frees the
    // response with the matching `services.free*Response`.

    pub const ReadOptions = struct {
        /// OPC 10000-4 §5.10.2.2: 0 = always read a fresh value from the
        /// server (no cached value older than this many milliseconds is
        /// acceptable).
        max_age: f64 = 0,
        timestamps_to_return: services.TimestampsToReturn = .both,
        timeout_hint_ms: u32 = 10_000,
    };

    /// The Read service (OPC 10000-4 §5.10.2): fetch one or more attribute
    /// values by NodeId. See `readAttribute` for the common one-node/one-
    /// attribute case.
    pub fn read(session: *Session, nodes_to_read: []const services.ReadValueId, options: ReadOptions) services.ServiceError!services.ReadResponse {
        const request: services.ReadRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, options.timeout_hint_ms),
            .max_age = options.max_age,
            .timestamps_to_return = options.timestamps_to_return,
            .nodes_to_read = nodes_to_read,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.read_request,
            services.ReadRequest,
            request,
            services.encodeReadRequest,
            services.ReadResponse,
            services.type_id.read_response,
            services.decodeReadResponse,
            services.result_fns.read,
        );
    }

    /// Read a single attribute of a single node and return just its
    /// `DataValue` — the ergonomic common case (`read` proper always takes/
    /// returns arrays, mirroring the wire 1:1). `attribute_id` is typically
    /// `services.attribute_id.value` (13, a Variable node's current value).
    /// Frees everything in the underlying `ReadResponse` except the one
    /// `DataValue` returned (which becomes the caller's to free with
    /// `encoding.freeDataValue`) — the same partial-free technique `create`
    /// uses to keep `server_endpoints` while discarding the rest of
    /// `CreateSessionResponse`.
    pub fn readAttribute(session: *Session, node_id: encoding.NodeId, attribute_id: u32) services.ServiceError!encoding.DataValue {
        const nodes = [_]services.ReadValueId{.{
            .node_id = node_id,
            .attribute_id = attribute_id,
            .index_range = null,
            .data_encoding = .{ .namespace_index = 0, .name = null },
        }};
        const resp = try session.read(&nodes, .{});
        const results = resp.results orelse &.{};
        if (results.len == 0) {
            services.freeReadResponse(session.allocator, resp);
            return error.UnexpectedResponseType;
        }
        const value = results[0];
        services.freeResponseHeader(session.allocator, resp.response_header);
        for (results[1..]) |extra| encoding.freeDataValue(session.allocator, extra);
        session.allocator.free(results);
        if (resp.diagnostic_infos) |infos| {
            for (infos) |di| services.freeDiagnosticInfo(session.allocator, di);
            session.allocator.free(infos);
        }
        return value;
    }

    /// The Write service (OPC 10000-4 §5.10.4): set one or more attribute
    /// values by NodeId.
    pub fn write(session: *Session, nodes_to_write: []const services.WriteValue) services.ServiceError!services.WriteResponse {
        const request: services.WriteRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .nodes_to_write = nodes_to_write,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.write_request,
            services.WriteRequest,
            request,
            services.encodeWriteRequest,
            services.WriteResponse,
            services.type_id.write_response,
            services.decodeWriteResponse,
            services.result_fns.write,
        );
    }

    pub const BrowseOptions = struct {
        view: services.ViewDescription = services.no_view,
        /// 0 = let the server pick a limit (it may still return a
        /// `ContinuationPoint` even so — always check `BrowseResult.
        /// continuation_point` and page with `browseNext` if non-null).
        requested_max_references_per_node: u32 = 0,
        timeout_hint_ms: u32 = 10_000,
    };

    /// The Browse service (OPC 10000-4 §5.8.2): enumerate a node's
    /// references (children/parents/type hierarchy).
    pub fn browse(session: *Session, nodes_to_browse: []const services.BrowseDescription, options: BrowseOptions) services.ServiceError!services.BrowseResponse {
        const request: services.BrowseRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, options.timeout_hint_ms),
            .view = options.view,
            .requested_max_references_per_node = options.requested_max_references_per_node,
            .nodes_to_browse = nodes_to_browse,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.browse_request,
            services.BrowseRequest,
            request,
            services.encodeBrowseRequest,
            services.BrowseResponse,
            services.type_id.browse_response,
            services.decodeBrowseResponse,
            services.result_fns.browse,
        );
    }

    /// Page through a `BrowseResult.continuation_point` the initial `browse`
    /// call returned (OPC 10000-4 §5.8.3). `release = true` tells the server
    /// to discard the continuation points instead of returning more
    /// references (the client-side equivalent of "I'm done paging, free
    /// your cursor").
    pub fn browseNext(session: *Session, continuation_points: []const ?[]const u8, release: bool) services.ServiceError!services.BrowseNextResponse {
        const request: services.BrowseNextRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .release_continuation_points = release,
            .continuation_points = continuation_points,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.browse_next_request,
            services.BrowseNextRequest,
            request,
            services.encodeBrowseNextRequest,
            services.BrowseNextResponse,
            services.type_id.browse_next_response,
            services.decodeBrowseNextResponse,
            services.result_fns.browse_next,
        );
    }

    /// The Call service (OPC 10000-4 §5.11.2): invoke a method node.
    pub fn call(session: *Session, methods_to_call: []const services.CallMethodRequest) services.ServiceError!services.CallResponse {
        const request: services.CallRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .methods_to_call = methods_to_call,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.call_request,
            services.CallRequest,
            request,
            services.encodeCallRequest,
            services.CallResponse,
            services.type_id.call_response,
            services.decodeCallResponse,
            services.result_fns.call,
        );
    }
};

// ── F1-d: top-level convenience wrappers ────────────────────────────────────
// Thin pass-throughs to the `Session` methods above with the most common
// defaults baked in — for callers that don't need `ReadOptions`/
// `BrowseOptions` control.

/// The Read service (OPC 10000-4 §5.10.2): fetch one or more attribute
/// values by NodeId. Equivalent to `session.read(nodes_to_read, .{})`.
pub fn read(session: *Session, nodes_to_read: []const services.ReadValueId) services.ServiceError!services.ReadResponse {
    return session.read(nodes_to_read, .{});
}

/// The Write service (OPC 10000-4 §5.10.4): set one or more attribute values
/// by NodeId. Equivalent to `session.write(nodes_to_write)`.
pub fn write(session: *Session, nodes_to_write: []const services.WriteValue) services.ServiceError!services.WriteResponse {
    return session.write(nodes_to_write);
}

/// The Browse service (OPC 10000-4 §5.8.2): enumerate a node's references
/// (children/parents/type hierarchy). Equivalent to `session.browse(nodes_to_browse, .{})`.
pub fn browse(session: *Session, nodes_to_browse: []const services.BrowseDescription) services.ServiceError!services.BrowseResponse {
    return session.browse(nodes_to_browse, .{});
}

/// The Call service (OPC 10000-4 §5.11.2): invoke a method node. Equivalent
/// to `session.call(methods_to_call)`.
pub fn call(session: *Session, methods_to_call: []const services.CallMethodRequest) services.ServiceError!services.CallResponse {
    return session.call(methods_to_call);
}

// ── tests ──

test "smoke" {
    try std.testing.expect(true);
}

test "full offline flow: OPN -> CreateSession -> ActivateSession -> CloseSession -> CLO" {
    // No real socket / Docker available in this sandbox for a LIVE
    // open62541 interop run (see SPEC/README verification notes) — this
    // drives the exact same client call sequence a live run would, against
    // a hand-rendered "server" byte stream instead of a real one. Response
    // request-ids (1..4) match the order `SecureChannel.open`/`Session.
    // create`/`.activate`/`.close` issue requests in.
    const testing = std.testing;

    const render = struct {
        fn frame(w: *std.Io.Writer, message_type: transport.MessageType, request_id: u32, comptime Body: type, body: Body, comptime encodeFn: fn (*encoding.Encoder, Body) encoding.EncodeError!void, type_id: encoding.NodeId) !void {
            var body_alloc = std.Io.Writer.Allocating.init(testing.allocator);
            defer body_alloc.deinit();
            var e = encoding.Encoder.init(&body_alloc.writer);
            try e.writer.writeInt(u32, 7, .little); // SecureChannelId (0 on the very first OPN response is also acceptable; using the real id throughout is simplest here)
            switch (message_type) {
                .open_secure_channel => {
                    try e.encodeString(services.security_policy_none_uri);
                    try e.encodeByteString(null);
                    try e.encodeByteString(null);
                },
                else => try e.writer.writeInt(u32, 3, .little), // TokenId
            }
            try e.writer.writeInt(u32, request_id, .little); // SequenceNumber
            try e.writer.writeInt(u32, request_id, .little); // RequestId
            try e.encodeNodeId(type_id);
            try encodeFn(&e, body);
            const frame_body = body_alloc.writer.buffered();
            var conn = transport.Connection.init(undefined, w);
            try conn.sendChunk(.{ .message_type = message_type, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(frame_body.len)) }, frame_body);
        }
    }.frame;

    var server_buf: [4096]u8 = undefined;
    var server_w: std.Io.Writer = .fixed(&server_buf);

    try render(&server_w, .open_secure_channel, 1, services.OpenSecureChannelResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .server_protocol_version = 0,
        .security_token = .{ .channel_id = 7, .token_id = 3, .created_at = 0, .revised_lifetime = 3_600_000 },
        .server_nonce = &.{},
    }, services.encodeOpenSecureChannelResponse, services.type_id.open_secure_channel_response);

    const endpoints = [_]services.EndpointDescription{.{
        .endpoint_url = "opc.tcp://localhost:4840",
        .server = .{
            .application_uri = "urn:test:server",
            .product_uri = null,
            .application_name = .{},
            .application_type = .server,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .server_certificate = null,
        .security_mode = .none,
        .security_policy_uri = services.security_policy_none_uri,
        .user_identity_tokens = &.{.{
            .policy_id = "open62541-anonymous-policy",
            .token_type = .anonymous,
            .issued_token_type = null,
            .issuer_endpoint_url = null,
            .security_policy_uri = null,
        }},
        .transport_profile_uri = null,
        .security_level = 0,
    }};
    try render(&server_w, .message, 2, services.CreateSessionResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 2, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .session_id = .{ .numeric = .{ .namespace = 1, .id = 100 } },
        .authentication_token = .{ .numeric = .{ .namespace = 1, .id = 200 } },
        .revised_session_timeout = 1_200_000.0,
        .server_nonce = &.{1},
        .server_certificate = null,
        .server_endpoints = &endpoints,
    }, services.encodeCreateSessionResponse, services.type_id.create_session_response);

    try render(&server_w, .message, 3, services.ActivateSessionResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 3, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .server_nonce = &.{2},
        .results = null,
        .diagnostic_infos = null,
    }, services.encodeActivateSessionResponse, services.type_id.activate_session_response);

    const ns_array = [_]?[]const u8{"http://opcfoundation.org/UA/"};
    const read_results = [_]encoding.DataValue{
        .{ .value = .{ .scalar = .{ .date_time = 132223104000000000 } }, .status = 0 },
        .{ .value = .{ .array = .{ .items = .{ .string = &ns_array } } }, .status = 0 },
    };
    try render(&server_w, .message, 4, services.ReadResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 4, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &read_results,
        .diagnostic_infos = null,
    }, services.encodeReadResponse, services.type_id.read_response);

    const write_results = [_]encoding.StatusCode{0};
    try render(&server_w, .message, 5, services.WriteResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 5, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &write_results,
        .diagnostic_infos = null,
    }, services.encodeWriteResponse, services.type_id.write_response);

    const browse_refs = [_]services.ReferenceDescription{.{
        .reference_type_id = .{ .numeric = .{ .namespace = 0, .id = 35 } },
        .is_forward = true,
        .node_id = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2253 } } },
        .browse_name = .{ .namespace_index = 0, .name = "Server" },
        .display_name = .{ .locale = "en", .text = "Server" },
        .node_class = .object,
        .type_definition = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2004 } } },
    }};
    const browse_results = [_]services.BrowseResult{.{ .status_code = 0, .continuation_point = "\x01", .references = &browse_refs }};
    try render(&server_w, .message, 6, services.BrowseResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 6, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &browse_results,
        .diagnostic_infos = null,
    }, services.encodeBrowseResponse, services.type_id.browse_response);

    const browse_next_refs = [_]services.ReferenceDescription{.{
        .reference_type_id = .{ .numeric = .{ .namespace = 0, .id = 35 } },
        .is_forward = true,
        .node_id = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2254 } } },
        .browse_name = .{ .namespace_index = 0, .name = "Types" },
        .display_name = .{ .locale = "en", .text = "Types" },
        .node_class = .object,
        .type_definition = .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 61 } } },
    }};
    const browse_next_results = [_]services.BrowseResult{.{ .status_code = 0, .continuation_point = null, .references = &browse_next_refs }};
    try render(&server_w, .message, 7, services.BrowseNextResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 7, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &browse_next_results,
        .diagnostic_infos = null,
    }, services.encodeBrowseNextResponse, services.type_id.browse_next_response);

    const call_output_args = [_]encoding.Variant{.{ .scalar = .{ .int32 = 7 } }};
    const call_input_results = [_]encoding.StatusCode{0};
    const call_results = [_]services.CallMethodResult{.{
        .status_code = 0,
        .input_argument_results = &call_input_results,
        .input_argument_diagnostic_infos = null,
        .output_arguments = &call_output_args,
    }};
    try render(&server_w, .message, 8, services.CallResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 8, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &call_results,
        .diagnostic_infos = null,
    }, services.encodeCallResponse, services.type_id.call_response);

    try render(&server_w, .message, 9, services.CloseSessionResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 9, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
    }, services.encodeCloseSessionResponse, services.type_id.close_session_response);

    var client_out_buf: [4096]u8 = undefined;
    var client_out_w: std.Io.Writer = .fixed(&client_out_buf);
    var client_in_r: std.Io.Reader = .fixed(server_w.buffered());
    var conn = transport.Connection.init(&client_in_r, &client_out_w);

    var ch = try SecureChannel.open(&conn, testing.allocator, .{});
    try testing.expectEqual(@as(u32, 7), ch.io.channel_id);
    try testing.expectEqual(@as(u32, 3), ch.io.token_id);

    var session = try Session.create(&ch, testing.allocator, .{
        .client_description = .{
            .application_uri = "urn:zig-libs:opcua:client",
            .product_uri = "urn:zig-libs:opcua",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua client" },
            .application_type = .client,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .endpoint_url = "opc.tcp://localhost:4840",
    });
    defer session.deinit();

    try testing.expectEqualDeep(encoding.NodeId{ .numeric = .{ .namespace = 1, .id = 100 } }, session.session_id);
    try testing.expectEqualDeep(encoding.NodeId{ .numeric = .{ .namespace = 1, .id = 200 } }, session.authentication_token);
    try testing.expectEqualStrings("open62541-anonymous-policy", session.findAnonymousPolicyId().?);

    try session.activate(null);

    // Read: one general `session.read` call covering both a scalar
    // DateTime (i=2258, Value) and a Variant-array String read (i=2255,
    // NamespaceArray) in the same request — exercises `readAttribute`
    // separately isn't needed here since it's just `session.read` with a
    // single-element `nodes_to_read` (see the dedicated unit test in
    // `services.zig` for `ReadResponse`'s Variant-array decode path).
    const read_nodes = [_]services.ReadValueId{
        .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2258 } }, .attribute_id = services.attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
        .{ .node_id = .{ .numeric = .{ .namespace = 0, .id = 2255 } }, .attribute_id = services.attribute_id.value, .index_range = null, .data_encoding = .{ .namespace_index = 0, .name = null } },
    };
    const read_resp = try session.read(&read_nodes, .{});
    defer services.freeReadResponse(testing.allocator, read_resp);
    try testing.expectEqual(@as(encoding.DateTime, 132223104000000000), read_resp.results.?[0].value.?.scalar.date_time);
    try testing.expectEqualStrings("http://opcfoundation.org/UA/", read_resp.results.?[1].value.?.array.items.string.?[0].?);

    // Write: one WriteValue, expect a Good status back.
    const write_nodes = [_]services.WriteValue{.{
        .node_id = .{ .numeric = .{ .namespace = 2, .id = 42 } },
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .value = .{ .value = .{ .scalar = .{ .double = 3.5 } } },
    }};
    const write_resp = try session.write(&write_nodes);
    defer services.freeWriteResponse(testing.allocator, write_resp);
    try testing.expectEqual(@as(usize, 1), write_resp.results.?.len);
    try testing.expect(!services.isBad(write_resp.results.?[0]));

    // Browse: the Objects folder (i=85) — expect "Server" among the
    // references, and a non-empty continuation_point to page with BrowseNext.
    const browse_nodes = [_]services.BrowseDescription{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 85 } },
        .browse_direction = .forward,
        .reference_type_id = services.null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = 0x3f,
    }};
    const browse_resp = try session.browse(&browse_nodes, .{});
    defer services.freeBrowseResponse(testing.allocator, browse_resp);
    try testing.expectEqualStrings("Server", browse_resp.results.?[0].references.?[0].browse_name.name.?);
    const cp = browse_resp.results.?[0].continuation_point.?;

    // BrowseNext: page using the continuation point above.
    const cps = [_]?[]const u8{cp};
    const browse_next_resp = try session.browseNext(&cps, false);
    defer services.freeBrowseNextResponse(testing.allocator, browse_next_resp);
    try testing.expectEqualStrings("Types", browse_next_resp.results.?[0].references.?[0].browse_name.name.?);

    // Call: one method, one output argument.
    const call_args = [_]encoding.Variant{.{ .scalar = .{ .int32 = 3 } }};
    const call_methods = [_]services.CallMethodRequest{.{
        .object_id = .{ .numeric = .{ .namespace = 1, .id = 100 } },
        .method_id = .{ .numeric = .{ .namespace = 1, .id = 101 } },
        .input_arguments = &call_args,
    }};
    const call_resp = try session.call(&call_methods);
    defer services.freeCallResponse(testing.allocator, call_resp);
    try testing.expectEqual(@as(i32, 7), call_resp.results.?[0].output_arguments.?[0].scalar.int32);

    try session.close(false);
    try ch.close(); // CLO: fire-and-forget, no response read
}

test "Session.readAttribute: single-node/single-attribute ergonomic helper" {
    // Isolated from the full OPN/CreateSession/ActivateSession handshake —
    // builds a `SecureChannel`/`Session` directly over a synthetic MSG
    // response, the same way `services.zig`'s own `Channel.call` test
    // constructs a bare `Channel` without going through `SecureChannel.open`.
    const testing = std.testing;

    var srv_body_buf: [256]u8 = undefined;
    var srv_body_w: std.Io.Writer = .fixed(&srv_body_buf);
    var srv_e = encoding.Encoder.init(&srv_body_w);
    try srv_e.writer.writeInt(u32, 7, .little); // SecureChannelId
    try srv_e.writer.writeInt(u32, 3, .little); // TokenId
    try srv_e.writer.writeInt(u32, 1, .little); // SequenceNumber
    try srv_e.writer.writeInt(u32, 1, .little); // RequestId
    try srv_e.encodeNodeId(services.type_id.read_response);
    try services.encodeReadResponse(&srv_e, .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &[_]encoding.DataValue{.{ .value = .{ .scalar = .{ .double = 21.5 } }, .status = 0 }},
        .diagnostic_infos = null,
    });
    const srv_body = srv_body_w.buffered();

    var srv_chunk_buf: [256]u8 = undefined;
    var srv_chunk_w: std.Io.Writer = .fixed(&srv_chunk_buf);
    var srv_conn = transport.Connection.init(undefined, &srv_chunk_w);
    try srv_conn.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(srv_body.len)) }, srv_body);

    var out_buf: [256]u8 = undefined;
    var out_w: std.Io.Writer = .fixed(&out_buf);
    var in_r: std.Io.Reader = .fixed(srv_chunk_w.buffered());
    var conn = transport.Connection.init(&in_r, &out_w);
    var ch: SecureChannel = .{ .io = .{ .conn = &conn, .allocator = testing.allocator, .channel_id = 7, .token_id = 3 } };
    var session: Session = .{ .channel = &ch, .allocator = testing.allocator, .authentication_token = services.null_node_id };

    const dv = try session.readAttribute(.{ .numeric = .{ .namespace = 2, .id = 42 } }, services.attribute_id.value);
    defer encoding.freeDataValue(testing.allocator, dv);
    try testing.expectEqual(@as(f64, 21.5), dv.value.?.scalar.double);
}

// ── LIVE open62541 interop (the real oracle) ────────────────────────────────
// Not gated behind offline-only: this exercises the exact same client code
// path against a real `open62541` server (`docker.io/open62541/open62541`,
// its default `server_ctt` demo binary — `--enableUnencrypted
// --enableAnonymous` already baked into the image's CMD, so SecurityMode#None
// + Anonymous both just work). Skips loudly (`std.debug.print` + `error.
// SkipZigTest`, never silently) when `podman` or the image isn't available —
// see the module's part-3 implementation report for whether this actually
// ran in a given environment.

const live_container_name = "opcua-zig-libs-live-test";
const live_endpoint_url = "opc.tcp://127.0.0.1:4840/";

const PodmanResult = struct {
    exit_code: ?u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: PodmanResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
    }
};

/// Run `podman <args...>`, capturing stdout/stderr. `error.SkipZigTest` if
/// `podman` itself can't be spawned (not installed / not on PATH) — the
/// caller decides whether a non-zero exit code is also skip-worthy.
fn runPodman(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !PodmanResult {
    var argv = try gpa.alloc([]const u8, args.len + 1);
    defer gpa.free(argv);
    argv[0] = "podman";
    @memcpy(argv[1..], args);

    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return error.SkipZigTest;

    var out_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    const stdout = try stdout_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stdout);

    var err_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    return .{
        .exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        },
        .stdout = stdout,
        .stderr = stderr,
    };
}

/// Linux raw syscall (no libc dependency — matches this repo's
/// `std.os.linux.nanosleep` convention, e.g. `ssh/src/transport.zig`,
/// `mqtt/src/broker.zig`) — this test's only Linux-specific bit; podman
/// itself is Linux/macOS(+Podman Desktop) but the container network mode
/// (`--network host`) this test relies on is Linux-only anyway.
fn sleepMs(ms: u64) void {
    var ts: std.os.linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    _ = std.os.linux.nanosleep(&ts, null);
}

/// Best-effort stop+remove of the live-test container — used both as
/// leftover-cleanup before starting and as the `defer`'d teardown after
/// (including on test failure: registered right after the container starts).
fn stopLiveContainer(gpa: std.mem.Allocator, io: std.Io) void {
    var result = runPodman(gpa, io, &.{ "stop", "-t", "1", live_container_name }) catch return;
    result.deinit(gpa);
}

test "LIVE open62541 interop: connect -> OPN(None) -> CreateSession -> ActivateSession -> Read/Browse/Write/Call -> close" {
    const testing = std.testing;
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Leftover cleanup from a previous crashed run, best-effort.
    stopLiveContainer(gpa, io);

    var run_result = runPodman(gpa, io, &.{
        "run",    "--rm",              "-d", "--network", "host",
        "--name", live_container_name,
        "--pull=never", // fail fast (not "hang pulling") if the image is missing
        "docker.io/open62541/open62541:latest",
    }) catch |err| switch (err) {
        error.SkipZigTest => {
            std.debug.print("\nLIVE opcua interop test SKIPPED: `podman` is not available in this environment.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        std.debug.print(
            "\nLIVE opcua interop test SKIPPED: `podman run` failed (image not pulled / podman unusable here).\nstderr: {s}\n",
            .{run_result.stderr},
        );
        return error.SkipZigTest;
    }
    defer stopLiveContainer(gpa, io);

    // Poll for the server's opc.tcp listener to come up (container start is
    // asynchronous; the demo server takes a moment to initialize its address
    // space before `TCP network layer listening` — observed ~0.2-1s locally).
    var stream: std.Io.net.Stream = blk: {
        var attempt: usize = 0;
        while (attempt < 60) : (attempt += 1) {
            const addr = std.Io.net.IpAddress.parse("127.0.0.1", 4840) catch unreachable;
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            sleepMs(250);
        }
        std.debug.print("\nLIVE opcua interop test SKIPPED: could not connect to opc.tcp://127.0.0.1:4840 within 15s.\n", .{});
        return error.SkipZigTest;
    };
    defer stream.close(io);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var conn = transport.Connection.init(&stream_reader.interface, &stream_writer.interface);
    _ = try conn.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = live_endpoint_url,
    });

    var ch = try SecureChannel.open(&conn, gpa, .{});
    defer ch.close() catch {}; // CLO: fire-and-forget, no response read

    var session = try Session.create(&ch, gpa, .{
        .client_description = .{
            .application_uri = "urn:zig-libs:opcua:client",
            .product_uri = "urn:zig-libs:opcua",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua client" },
            .application_type = .client,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .endpoint_url = live_endpoint_url,
    });
    defer session.deinit();
    try session.activate(null);
    defer session.close(false) catch {};

    // ── Read: i=2258 (Server_ServerStatus_CurrentTime) + i=2255
    // (NamespaceArray, a String[] — exercises the new Variant-array decode
    // path against a real server).
    const current_time = try session.readAttribute(.{ .numeric = .{ .namespace = 0, .id = 2258 } }, services.attribute_id.value);
    defer encoding.freeDataValue(gpa, current_time);
    try testing.expect(current_time.value != null);
    try testing.expect(current_time.value.? == .scalar);
    try testing.expect(current_time.value.?.scalar == .date_time);
    try testing.expect(current_time.value.?.scalar.date_time > 0);

    const ns_read_nodes = [_]services.ReadValueId{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 2255 } },
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .data_encoding = .{ .namespace_index = 0, .name = null },
    }};
    const ns_resp = try session.read(&ns_read_nodes, .{});
    defer services.freeReadResponse(gpa, ns_resp);
    const ns_array = ns_resp.results.?[0].value.?.array.items.string.?;
    var found_ua_ns = false;
    for (ns_array) |ns| {
        if (ns) |s| {
            if (std.mem.eql(u8, s, "http://opcfoundation.org/UA/")) found_ua_ns = true;
        }
    }
    try testing.expect(found_ua_ns);

    // ── Browse: the Objects folder (i=85) — expect "Server" among the refs.
    const browse_nodes = [_]services.BrowseDescription{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 85 } },
        .browse_direction = .forward,
        .reference_type_id = services.null_node_id,
        .include_subtypes = true,
        .node_class_mask = 0,
        .result_mask = 0x3f,
    }};
    const browse_resp = try session.browse(&browse_nodes, .{});
    defer services.freeBrowseResponse(gpa, browse_resp);
    try testing.expect(!services.isBad(browse_resp.results.?[0].status_code));
    var found_server_ref = false;
    for (browse_resp.results.?[0].references orelse &.{}) |ref| {
        if (ref.browse_name.name) |name| {
            if (std.mem.eql(u8, name, "Server")) found_server_ref = true;
        }
    }
    try testing.expect(found_server_ref);

    // Page through with BrowseNext if the server handed back a continuation
    // point (harmless either way — just exercises the codepath when present).
    if (browse_resp.results.?[0].continuation_point) |cp| {
        const cps = [_]?[]const u8{cp};
        var next_resp = try session.browseNext(&cps, true); // true: release, we're done
        services.freeBrowseNextResponse(gpa, next_resp);
        _ = &next_resp;
    }

    // ── Write: i=2256 (Server_ServerStatus_State) is read-only — expect a
    // Bad status to decode cleanly, not a crash (server_ctt exposes no
    // reliably-named writable demo node across builds, so this is the
    // documented fallback rather than a genuine write+read-back).
    const write_nodes = [_]services.WriteValue{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 2256 } },
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .value = .{ .value = .{ .scalar = .{ .int32 = 0 } } },
    }};
    const write_resp = try session.write(&write_nodes);
    defer services.freeWriteResponse(gpa, write_resp);
    try testing.expectEqual(@as(usize, 1), write_resp.results.?.len);
    try testing.expect(services.isBad(write_resp.results.?[0]));

    // ── Call: no reliably-named demo method across server_ctt builds either
    // — call a bogus object/method NodeId and just assert the response
    // decodes cleanly (either a ServiceFault, mapped to `error.ServiceFault`,
    // or a `CallResponse` whose `CallMethodResult.status_code` is Bad).
    const call_methods = [_]services.CallMethodRequest{.{
        .object_id = .{ .numeric = .{ .namespace = 0, .id = 85 } }, // Objects (not a method)
        .method_id = .{ .numeric = .{ .namespace = 0, .id = 85 } },
        .input_arguments = null,
    }};
    if (session.call(&call_methods)) |call_resp| {
        defer services.freeCallResponse(gpa, call_resp);
        try testing.expectEqual(@as(usize, 1), call_resp.results.?.len);
        try testing.expect(services.isBad(call_resp.results.?[0].status_code));
    } else |err| {
        // Either a ServiceFault message or a Bad top-level service_result on
        // the response are both "decoded cleanly, didn't crash" outcomes.
        try testing.expect(err == error.ServiceFault or err == error.BadServiceResult);
    }
}
