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
};

// ── F1-d: core services ──────────────────────────────────────────────────────

/// The Read service (OPC 10000-4 §5.10.2): fetch one or more attribute
/// values by NodeId.
pub fn read(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Read service — OPC 10000-4 §5.10.2");
}

/// The Write service (OPC 10000-4 §5.10.4): set one or more attribute values
/// by NodeId.
pub fn write(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Write service — OPC 10000-4 §5.10.4");
}

/// The Browse service (OPC 10000-4 §5.8.2): enumerate a node's references
/// (children/parents/type hierarchy).
pub fn browse(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Browse service — OPC 10000-4 §5.8.2");
}

/// The Call service (OPC 10000-4 §5.11.2): invoke a method node.
pub fn call(session: *Session) noreturn {
    _ = session;
    @panic("TODO(agent): Call service — OPC 10000-4 §5.11.2");
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

    try render(&server_w, .message, 4, services.CloseSessionResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 4, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
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
    try session.close(false);
    try ch.close(); // CLO: fire-and-forget, no response read
}
