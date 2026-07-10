// SPDX-License-Identifier: MIT

//! opcua — an OPC-UA (IEC 62541 / OPC 10000) binary client: the opc.tcp wire
//! protocol (OPC 10000-6) over `SecurityPolicy#None` (the default) or
//! `SecurityPolicy#Basic256Sha256` at SecurityMode Sign/SignAndEncrypt
//! (`security.zig`, layered on the `rsa` module).
//!
//! This is F1 "core": the built-in type codec (`encoding`, OPC 10000-6 §5.2)
//! and the opc.tcp transport framing (`transport`, OPC 10000-6 §7), with the
//! service layer riding on top — OpenSecureChannel/CloseSecureChannel (F1-b),
//! CreateSession/ActivateSession/CloseSession (F1-c), and
//! Read/Write/Browse/Call (F1-d).
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

/// The SecureChannel security layer (OPC 10000-6 §6.7, OPC 10000-7 security
/// profiles) — SecurityMode Sign/SignAndEncrypt over
/// SecurityPolicy#Basic256Sha256: RSA-OAEP/SHA-1 + RSA-PKCS1v1.5/SHA-256 for
/// the OPN handshake (via the `rsa` module), P-SHA256 key derivation, and
/// HMAC-SHA256 + AES-256-CBC for MSG/CLO chunks. `SecureChannel.open`'s
/// SecurityMode=None behavior is unaffected: `OpenOptions.security` defaults
/// to `null`.
pub const security = @import("security.zig");

// Pull the submodules' tests into this module's test binary — a bare
// re-export does NOT drag in the imported file's `test` blocks (the
// dark-tests rule; see CONVENTIONS.md §6.3).
test {
    _ = encoding;
    _ = transport;
    _ = services;
    _ = security;
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
        /// `null` (the default) opens the channel at SecurityMode=None,
        /// byte-for-byte identical to F2's original behavior. Pass a
        /// `security.SecurityContext` (`.policy = .basic256sha256`, `.mode
        /// = .sign`/`.sign_and_encrypt`, `.credentials`, a pinned
        /// `.server_certificate`, and a CSPRNG `.random`) to open a signed/
        /// encrypted channel: the OPN request is RSA-signed + RSA-OAEP-
        /// encrypted to the server certificate, the response verified +
        /// decrypted, and the exchanged nonces run through P-SHA256
        /// (`security.deriveKeys`) to key every subsequent MSG/CLO chunk.
        security: ?security.SecurityContext = null,
    };

    /// Perform the OpenSecureChannel request/response (Issue, not Renew —
    /// channel renewal is out of F2's scope) and return the opened channel.
    /// `conn` must already have completed the Hello/Acknowledge handshake
    /// (`transport.connect`/`Connection.hello`).
    pub fn open(conn: *transport.Connection, allocator: std.mem.Allocator, options: OpenOptions) services.ServiceError!SecureChannel {
        var ch: SecureChannel = .{ .io = .{ .conn = conn, .allocator = allocator, .security = options.security } };

        const security_mode: services.MessageSecurityMode = if (options.security) |sec| sec.mode else .none;
        const secure = security_mode != .none;

        // OPC 10000-6 §6.7.5: the nonce length matches the symmetric key
        // length (32 for the Sha256-keyed profiles). It is key material —
        // wiped once the channel keys are derived.
        var client_nonce: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &client_nonce);
        if (secure) {
            const random = options.security.?.random orelse @panic("opcua security: SecurityMode != none requires SecurityContext.random");
            random.bytes(&client_nonce);
        }

        const request: services.OpenSecureChannelRequest = .{
            .request_header = ch.io.nextRequestHeader(services.null_node_id, options.timeout_hint_ms),
            .client_protocol_version = 0,
            .request_type = .issue,
            .security_mode = security_mode,
            .client_nonce = if (secure) &client_nonce else &.{}, // present-but-empty at SecurityMode=None
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

        if (secure) {
            const server_nonce = response.server_nonce orelse return error.InvalidSecureMessage;
            if (server_nonce.len == 0) return error.InvalidSecureMessage;
            ch.io.security.?.keys = security.deriveKeys(&client_nonce, server_nonce, options.security.?.policy);
            // The server nonce is key material too — wipe the decoded copy
            // before the deferred free above releases it.
            std.crypto.secureZero(u8, @constCast(server_nonce));
        }
        return ch;
    }

    /// Send the CloseSecureChannel request in a CLO chunk. Per OPC 10000-6
    /// §6.7.2 (ground-truthed against open62541's `Service_
    /// CloseSecureChannel`: "the server does not send a CloseSecureChannel
    /// response") the server closes its end of the channel without replying
    /// — this does not wait for or expect one; the caller is expected to
    /// close the underlying socket next.
    pub fn close(ch: *SecureChannel) services.ServiceError!void {
        // The derived channel keys die with the channel — wiped whether or
        // not the CLO send itself succeeds.
        defer if (ch.io.security) |*sec| {
            if (sec.keys) |*keys| {
                keys.wipe();
                sec.keys = null;
            }
        };
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
    /// `CreateSessionResponse.ServerNonce`, kept (owned, freed by `deinit`)
    /// because `activate`'s `clientSignature` over a secure channel signs
    /// serverCertificate ‖ serverNonce (OPC 10000-4 §5.6.3.2).
    server_nonce: ?[]const u8 = null,
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

        // Over a Sign/SignAndEncrypt channel the server validates that
        // ClientCertificate matches the channel's client certificate and
        // signs ClientNonce back (OPC 10000-4 §5.6.2.2) — both must be real.
        const chan_sec = channel.io.security;
        const secure = chan_sec != null and chan_sec.?.mode != .none;
        var session_nonce: [32]u8 = undefined;
        if (secure) chan_sec.?.random.?.bytes(&session_nonce);

        const request: services.CreateSessionRequest = .{
            .request_header = channel.io.nextRequestHeader(services.null_node_id, options.timeout_hint_ms),
            .client_description = options.client_description,
            .server_uri = options.server_uri,
            .endpoint_url = options.endpoint_url,
            .session_name = options.session_name,
            .client_nonce = if (secure) &session_nonce else &.{},
            .client_certificate = if (secure) chan_sec.?.credentials.?.certificate_der else null,
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
        session.server_nonce = response.server_nonce; // kept for `activate`'s clientSignature
        // response_header/session_id/authentication_token/
        // server_certificate carry no owned memory we need past this point
        // except server_endpoints + server_nonce (kept above) — free the
        // rest now.
        services.freeResponseHeader(allocator, response.response_header);
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

        // Over a Sign/SignAndEncrypt channel the server requires a
        // ClientSignature proving possession of the channel certificate's
        // private key: the SecurityPolicy's asymmetric signature
        // (RSA-PKCS1v1.5/SHA-256 for Basic256Sha256) over
        // serverCertificate ‖ serverNonce (OPC 10000-4 §5.6.3.2, "SignedData"
        // — open62541 `checkSignature` verifies exactly this
        // concatenation). Null at SecurityMode=None, as before.
        const chan_sec = session.channel.io.security;
        const secure = chan_sec != null and chan_sec.?.mode != .none;
        var signature_bytes: ?[]u8 = null;
        defer if (signature_bytes) |s| session.allocator.free(s);
        var client_signature: services.SignatureData = .{ .algorithm = null, .signature = null };
        if (secure) {
            const sec = chan_sec.?;
            const server_cert = sec.server_certificate orelse @panic("opcua security: SecurityMode != none requires a pinned server certificate");
            const server_nonce = session.server_nonce orelse &.{};
            const to_sign = try session.allocator.alloc(u8, server_cert.len + server_nonce.len);
            defer session.allocator.free(to_sign);
            @memcpy(to_sign[0..server_cert.len], server_cert);
            @memcpy(to_sign[server_cert.len..], server_nonce);
            signature_bytes = try security.asymmetricSign(session.allocator, to_sign, sec.credentials.?.private_key);
            client_signature = .{
                .algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                .signature = signature_bytes,
            };
        }

        const request: services.ActivateSessionRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .client_signature = client_signature,
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
        if (session.server_nonce) |nonce| {
            session.allocator.free(nonce);
            session.server_nonce = null;
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

    // ── F3: subscription-list services ──────────────────────────────────────
    // SetPublishingMode/DeleteSubscriptions operate on a list of subscription
    // ids (possibly spanning more than one `Subscription` this client is
    // tracking) — the multi-subscription form; `Subscription.
    // setPublishingMode`/`.delete` are single-id convenience wrappers over
    // these two.

    /// SetPublishingMode (OPC 10000-4 §5.13.4) for one or more subscriptions.
    pub fn setPublishingMode(session: *Session, subscription_ids: []const u32, enabled: bool) services.ServiceError!services.SetPublishingModeResponse {
        const request: services.SetPublishingModeRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .publishing_enabled = enabled,
            .subscription_ids = subscription_ids,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.set_publishing_mode_request,
            services.SetPublishingModeRequest,
            request,
            services.encodeSetPublishingModeRequest,
            services.SetPublishingModeResponse,
            services.type_id.set_publishing_mode_response,
            services.decodeSetPublishingModeResponse,
            services.result_fns.set_publishing_mode,
        );
    }

    /// DeleteSubscriptions (OPC 10000-4 §5.13.8) for one or more
    /// subscriptions.
    pub fn deleteSubscriptions(session: *Session, subscription_ids: []const u32) services.ServiceError!services.DeleteSubscriptionsResponse {
        const request: services.DeleteSubscriptionsRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, 10_000),
            .subscription_ids = subscription_ids,
        };
        return services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.delete_subscriptions_request,
            services.DeleteSubscriptionsRequest,
            request,
            services.encodeDeleteSubscriptionsRequest,
            services.DeleteSubscriptionsResponse,
            services.type_id.delete_subscriptions_response,
            services.decodeDeleteSubscriptionsResponse,
            services.result_fns.delete_subscriptions,
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

// ── F3: Subscriptions / MonitoredItems / Publish (OPC 10000-4 §5.12/§5.13) ──
// The last reserved part: CreateSubscription/ModifySubscription/
// SetPublishingMode/DeleteSubscriptions (§5.13.2-4/§5.13.8), CreateMonitoredItems/
// DeleteMonitoredItems (§5.12.2/§5.12.6), and the Publish/Republish long-poll
// loop (§5.13.5/§5.13.6) that delivers `NotificationMessage`s — this module's
// pub-style data-change notification path, the OPC UA feature `read`/`write`
// polling can't replace. Still no crypto (`SecurityMode=None`, the module's
// scope throughout); the wire shapes themselves carry no security-relevant
// content this module would need to sign/encrypt anyway.

/// One decoded `NotificationMessage.NotificationData[i]` — the entry's
/// `ExtensionObject.TypeId` classifies which concrete `NotificationData`
/// member it is (OPC 10000-4 §5.13.1.2); `.unrecognized` surfaces a type this
/// client doesn't decode (e.g. a vendor-specific notification, or one of this
/// module's own gaps) rather than silently dropping it.
pub const Notification = union(enum) {
    /// The common case: one or more monitored items' new values (OPC 10000-4
    /// §5.12.1.4). Correlate `MonitoredItemNotification.client_handle` back to
    /// what was actually monitored via `Subscription.findMonitoredItem`.
    data_change: services.DataChangeNotification,
    /// A subscription-level status change, e.g. the server is about to
    /// delete this subscription (OPC 10000-4 §5.13.1.2 note; the notification
    /// structure itself is §5.13.6's `StatusChangeNotification`).
    status_change: services.StatusChangeNotification,
    /// Event-monitored-item occurrences (OPC 10000-4 §5.12.1.5) — this
    /// module never builds an `EventFilter` (`no_filter` is the only filter
    /// shape F1 constructs), so a real server would only ever send this if
    /// somehow configured out-of-band; modeled for decode-completeness.
    event: services.EventNotificationList,
    /// An `ExtensionObject` whose `TypeId` didn't match any of the three
    /// known `NotificationData` members above — owned dup of the type id
    /// (the original `ExtensionObject` this was read out of is freed once
    /// every entry has been classified).
    unrecognized: encoding.NodeId,
};

/// Frees whichever `Notification` variant is active.
pub fn freeNotification(a: std.mem.Allocator, n: Notification) void {
    switch (n) {
        .data_change => |v| services.freeDataChangeNotification(a, v),
        .status_change => |v| services.freeStatusChangeNotification(a, v),
        .event => |v| services.freeEventNotificationList(a, v),
        .unrecognized => |v| encoding.freeNodeId(a, v),
    }
}

fn freeNotificationSlice(a: std.mem.Allocator, notifications: []const Notification) void {
    for (notifications) |n| freeNotification(a, n);
    a.free(notifications);
}

/// An owned copy of a `NodeId` — used only for `Notification.unrecognized`'s
/// `type_id` (the source `ExtensionObject` it was read from is freed by the
/// time the caller sees this). Not part of the wire codec (that's
/// `encoding.zig`'s job, and it has no dup helper of its own since neither
/// `Encoder`/`Decoder` ever needs one internally) — a small bookkeeping-only
/// utility local to this module's Publish-decode path.
fn dupNodeId(a: std.mem.Allocator, v: encoding.NodeId) std.mem.Allocator.Error!encoding.NodeId {
    return switch (v) {
        .numeric => |n| .{ .numeric = n },
        .guid => |n| .{ .guid = n },
        .string => |n| .{ .string = .{ .namespace = n.namespace, .id = if (n.id) |s| try a.dupe(u8, s) else null } },
        .byte_string => |n| .{ .byte_string = .{ .namespace = n.namespace, .id = if (n.id) |s| try a.dupe(u8, s) else null } },
    };
}

/// Classify and decode each `NotificationMessage.NotificationData[i]`
/// (`ExtensionObject`) by its `TypeId` — shared by `Subscription.publish`/
/// `.republish` (OPC 10000-4 §5.13.5/§5.13.6 both deliver the same
/// `NotificationMessage` shape). Does not touch `notification_data` itself
/// (the caller frees that raw form afterwards via `services.
/// freeNotificationMessage`, once every entry's body has been decoded out of
/// it here).
fn decodeNotifications(allocator: std.mem.Allocator, notification_data: ?[]const encoding.ExtensionObject) services.ServiceError![]const Notification {
    const data = notification_data orelse &.{};
    var list = try std.ArrayList(Notification).initCapacity(allocator, data.len);
    errdefer {
        for (list.items) |n| freeNotification(allocator, n);
        list.deinit(allocator);
    }
    for (data) |eo| {
        if (services.nodeIdEql(eo.type_id, services.type_id.data_change_notification)) {
            var r: std.Io.Reader = .fixed(eo.body);
            var d = encoding.Decoder.init(&r, allocator);
            list.appendAssumeCapacity(.{ .data_change = try services.decodeDataChangeNotification(&d) });
        } else if (services.nodeIdEql(eo.type_id, services.type_id.status_change_notification)) {
            var r: std.Io.Reader = .fixed(eo.body);
            var d = encoding.Decoder.init(&r, allocator);
            list.appendAssumeCapacity(.{ .status_change = try services.decodeStatusChangeNotification(&d) });
        } else if (services.nodeIdEql(eo.type_id, services.type_id.event_notification_list)) {
            var r: std.Io.Reader = .fixed(eo.body);
            var d = encoding.Decoder.init(&r, allocator);
            list.appendAssumeCapacity(.{ .event = try services.decodeEventNotificationList(&d) });
        } else {
            list.appendAssumeCapacity(.{ .unrecognized = try dupNodeId(allocator, eo.type_id) });
        }
    }
    return try list.toOwnedSlice(allocator);
}

/// One `Publish`/`Republish` round trip's decoded payload (OPC 10000-4
/// §5.13.5/§5.13.6) — owned; free with `freePublishResult`.
pub const PublishResult = struct {
    subscription_id: u32,
    sequence_number: u32,
    publish_time: encoding.DateTime,
    /// `true` if the server has more notifications already queued for this
    /// subscription right now — the caller may want to `publish()` again
    /// immediately rather than however it'd normally pace the loop.
    more_notifications: bool,
    /// The decoded `NotificationMessage.NotificationData` — see
    /// `Notification`.
    notifications: []const Notification,
    /// `PublishResponse.AvailableSequenceNumbers` (informational: sequence
    /// numbers this subscription still has queued server-side). `publish`
    /// already handles acknowledging the sequence number *this* result
    /// carries on the *next* `publish()` call — nothing to do with this
    /// field unless the caller wants to reason about backlog itself.
    available_sequence_numbers: ?[]const u32,
    /// `PublishResponse.Results` — the status of each acknowledgement this
    /// call's request piggy-backed (`null` on the first `publish()` call, or
    /// any `republish()`, when there was nothing pending to acknowledge yet).
    ack_results: ?[]const encoding.StatusCode,
};

/// Frees a `PublishResult` returned by `Subscription.publish`/`.republish`.
pub fn freePublishResult(a: std.mem.Allocator, r: PublishResult) void {
    freeNotificationSlice(a, r.notifications);
    if (r.available_sequence_numbers) |s| a.free(s);
    if (r.ack_results) |s| a.free(s);
}

/// CreateSubscription/ModifySubscription/SetPublishingMode/
/// DeleteSubscriptions (OPC 10000-4 §5.13.2-4/§5.13.8), CreateMonitoredItems/
/// DeleteMonitoredItems (§5.12.2/§5.12.6), and the Publish/Republish loop
/// (§5.13.5/§5.13.6) for one subscription on `session`.
pub const Subscription = struct {
    session: *Session,
    allocator: std.mem.Allocator = undefined,
    subscription_id: u32 = 0,
    revised_publishing_interval: f64 = 0,
    revised_lifetime_count: u32 = 0,
    revised_max_keep_alive_count: u32 = 0,
    /// Sequence numbers this client has received (via `publish`/`republish`)
    /// but not yet acknowledged to the server. OPC 10000-4 §5.13.5:
    /// acknowledgement piggy-backs the *next* `PublishRequest` rather than a
    /// separate round trip, so `publish()` drains this into that request's
    /// `SubscriptionAcknowledgements` and clears it at the start of every
    /// call — the one exception being the very first call, which has nothing
    /// to drain yet.
    pending_acks: std.ArrayList(u32) = .empty,
    /// `ClientHandle` -> `MonitoredItemId` correlation, populated by
    /// `createMonitoredItems` for whichever items the server actually
    /// created (a Bad `MonitoredItemCreateResult.StatusCode` is skipped —
    /// nothing to correlate for an item that doesn't exist server-side).
    /// `findMonitoredItem` looks a `MonitoredItemNotification.client_handle`
    /// pulled out of a `publish()` result back up in this table.
    monitored_items: std.ArrayList(MonitoredItemHandle) = .empty,

    pub const MonitoredItemHandle = struct {
        client_handle: u32,
        monitored_item_id: u32,
    };

    pub const CreateOptions = struct {
        /// Milliseconds; the server may revise this (`revised_publishing_
        /// interval`) — 1s is open62541/node-opcua's client-default ballpark.
        requested_publishing_interval_ms: f64 = 1000,
        requested_lifetime_count: u32 = 10_000,
        requested_max_keep_alive_count: u32 = 10,
        /// 0 = no limit.
        max_notifications_per_publish: u32 = 0,
        publishing_enabled: bool = true,
        priority: u8 = 0,
        timeout_hint_ms: u32 = 10_000,
    };

    /// CreateSubscription (OPC 10000-4 §5.13.2).
    pub fn create(session: *Session, allocator: std.mem.Allocator, options: CreateOptions) services.ServiceError!Subscription {
        var sub: Subscription = .{ .session = session, .allocator = allocator };
        const request: services.CreateSubscriptionRequest = .{
            .request_header = session.channel.io.nextRequestHeader(session.authentication_token, options.timeout_hint_ms),
            .requested_publishing_interval = options.requested_publishing_interval_ms,
            .requested_lifetime_count = options.requested_lifetime_count,
            .requested_max_keep_alive_count = options.requested_max_keep_alive_count,
            .max_notifications_per_publish = options.max_notifications_per_publish,
            .publishing_enabled = options.publishing_enabled,
            .priority = options.priority,
        };
        const response = try services.Channel.call(
            &session.channel.io,
            .message,
            services.type_id.create_subscription_request,
            services.CreateSubscriptionRequest,
            request,
            services.encodeCreateSubscriptionRequest,
            services.CreateSubscriptionResponse,
            services.type_id.create_subscription_response,
            services.decodeCreateSubscriptionResponse,
            services.result_fns.create_subscription,
        );
        defer services.freeCreateSubscriptionResponse(allocator, response);
        sub.subscription_id = response.subscription_id;
        sub.revised_publishing_interval = response.revised_publishing_interval;
        sub.revised_lifetime_count = response.revised_lifetime_count;
        sub.revised_max_keep_alive_count = response.revised_max_keep_alive_count;
        return sub;
    }

    pub const ModifyOptions = struct {
        requested_publishing_interval_ms: f64,
        requested_lifetime_count: u32,
        requested_max_keep_alive_count: u32,
        max_notifications_per_publish: u32 = 0,
        priority: u8 = 0,
        timeout_hint_ms: u32 = 10_000,
    };

    /// ModifySubscription (OPC 10000-4 §5.13.3).
    pub fn modify(sub: *Subscription, options: ModifyOptions) services.ServiceError!void {
        const request: services.ModifySubscriptionRequest = .{
            .request_header = sub.session.channel.io.nextRequestHeader(sub.session.authentication_token, options.timeout_hint_ms),
            .subscription_id = sub.subscription_id,
            .requested_publishing_interval = options.requested_publishing_interval_ms,
            .requested_lifetime_count = options.requested_lifetime_count,
            .requested_max_keep_alive_count = options.requested_max_keep_alive_count,
            .max_notifications_per_publish = options.max_notifications_per_publish,
            .priority = options.priority,
        };
        const response = try services.Channel.call(
            &sub.session.channel.io,
            .message,
            services.type_id.modify_subscription_request,
            services.ModifySubscriptionRequest,
            request,
            services.encodeModifySubscriptionRequest,
            services.ModifySubscriptionResponse,
            services.type_id.modify_subscription_response,
            services.decodeModifySubscriptionResponse,
            services.result_fns.modify_subscription,
        );
        defer services.freeModifySubscriptionResponse(sub.allocator, response);
        sub.revised_publishing_interval = response.revised_publishing_interval;
        sub.revised_lifetime_count = response.revised_lifetime_count;
        sub.revised_max_keep_alive_count = response.revised_max_keep_alive_count;
    }

    /// SetPublishingMode (OPC 10000-4 §5.13.4) for just this subscription —
    /// the service itself operates on a list (see `Session.setPublishingMode`
    /// for the multi-subscription form).
    pub fn setPublishingMode(sub: *Subscription, enabled: bool) services.ServiceError!void {
        const response = try sub.session.setPublishingMode(&.{sub.subscription_id}, enabled);
        services.freeSetPublishingModeResponse(sub.allocator, response);
    }

    /// DeleteSubscriptions (OPC 10000-4 §5.13.8) for just this subscription.
    /// After this call `sub` no longer names anything server-side; only
    /// `deinit` (freeing local bookkeeping) is safe to call on it.
    pub fn delete(sub: *Subscription) services.ServiceError!void {
        const response = try sub.session.deleteSubscriptions(&.{sub.subscription_id});
        services.freeDeleteSubscriptionsResponse(sub.allocator, response);
    }

    pub const MonitoredItemSpec = struct {
        node_id: encoding.NodeId,
        attribute_id: u32 = services.attribute_id.value,
        /// Caller-chosen; echoed back on every `MonitoredItemNotification`
        /// for this item (OPC 10000-4 §5.12.1.3) — `findMonitoredItem`
        /// correlates it back to `MonitoredItemCreateResult.
        /// monitored_item_id`. Must be unique within this `Subscription`.
        client_handle: u32,
        /// Milliseconds; `-1` (the OPC UA convention this defaults to) asks
        /// the server for its fastest practical rate — the common "just tell
        /// me when it changes" case. The server may revise this down to the
        /// Subscription's own publishing interval or up to a minimum it
        /// enforces (`MonitoredItemCreateResult.revised_sampling_interval`).
        sampling_interval_ms: f64 = -1,
        queue_size: u32 = 1,
        discard_oldest: bool = true,
        monitoring_mode: services.MonitoringMode = .reporting,
    };

    /// CreateMonitoredItems (OPC 10000-4 §5.12.2), no filter (`services.
    /// no_filter` — deadband/event filters are out of this module's scope,
    /// same as F1's crypto non-goal doc comment). Records a `ClientHandle` ->
    /// `MonitoredItemId` entry in `monitored_items` for every `spec` the
    /// server actually created (skips ones whose `MonitoredItemCreateResult.
    /// status_code` came back Bad). Caller frees the returned response with
    /// `services.freeCreateMonitoredItemsResponse`.
    pub fn createMonitoredItems(sub: *Subscription, specs: []const MonitoredItemSpec, timestamps_to_return: services.TimestampsToReturn) services.ServiceError!services.CreateMonitoredItemsResponse {
        var items = try std.ArrayList(services.MonitoredItemCreateRequest).initCapacity(sub.allocator, specs.len);
        defer items.deinit(sub.allocator);
        for (specs) |spec| {
            items.appendAssumeCapacity(.{
                .item_to_monitor = .{
                    .node_id = spec.node_id,
                    .attribute_id = spec.attribute_id,
                    .index_range = null,
                    .data_encoding = .{ .namespace_index = 0, .name = null },
                },
                .monitoring_mode = spec.monitoring_mode,
                .requested_parameters = .{
                    .client_handle = spec.client_handle,
                    .sampling_interval = spec.sampling_interval_ms,
                    .filter = services.no_filter,
                    .queue_size = spec.queue_size,
                    .discard_oldest = spec.discard_oldest,
                },
            });
        }
        const request: services.CreateMonitoredItemsRequest = .{
            .request_header = sub.session.channel.io.nextRequestHeader(sub.session.authentication_token, 10_000),
            .subscription_id = sub.subscription_id,
            .timestamps_to_return = timestamps_to_return,
            .items_to_create = items.items,
        };
        const response = try services.Channel.call(
            &sub.session.channel.io,
            .message,
            services.type_id.create_monitored_items_request,
            services.CreateMonitoredItemsRequest,
            request,
            services.encodeCreateMonitoredItemsRequest,
            services.CreateMonitoredItemsResponse,
            services.type_id.create_monitored_items_response,
            services.decodeCreateMonitoredItemsResponse,
            services.result_fns.create_monitored_items,
        );
        if (response.results) |results| {
            for (results, 0..) |r, i| {
                if (i >= specs.len) break;
                if (services.isBad(r.status_code)) continue;
                try sub.monitored_items.append(sub.allocator, .{ .client_handle = specs[i].client_handle, .monitored_item_id = r.monitored_item_id });
            }
        }
        return response;
    }

    /// DeleteMonitoredItems (OPC 10000-4 §5.12.6). Drops every matching
    /// `monitored_items` bookkeeping entry regardless of the per-item result
    /// status — a caller asking to delete something this `Subscription` no
    /// longer has a record of is harmless, but keeping a stale entry around
    /// after asking the server to delete it would be worse (a later
    /// notification could never legitimately arrive for it again). Caller
    /// frees the returned response with `services.
    /// freeDeleteMonitoredItemsResponse`.
    pub fn deleteMonitoredItems(sub: *Subscription, monitored_item_ids: []const u32) services.ServiceError!services.DeleteMonitoredItemsResponse {
        const request: services.DeleteMonitoredItemsRequest = .{
            .request_header = sub.session.channel.io.nextRequestHeader(sub.session.authentication_token, 10_000),
            .subscription_id = sub.subscription_id,
            .monitored_item_ids = monitored_item_ids,
        };
        const response = try services.Channel.call(
            &sub.session.channel.io,
            .message,
            services.type_id.delete_monitored_items_request,
            services.DeleteMonitoredItemsRequest,
            request,
            services.encodeDeleteMonitoredItemsRequest,
            services.DeleteMonitoredItemsResponse,
            services.type_id.delete_monitored_items_response,
            services.decodeDeleteMonitoredItemsResponse,
            services.result_fns.delete_monitored_items,
        );
        var i: usize = 0;
        while (i < sub.monitored_items.items.len) {
            var found = false;
            for (monitored_item_ids) |id| {
                if (sub.monitored_items.items[i].monitored_item_id == id) {
                    found = true;
                    break;
                }
            }
            if (found) {
                _ = sub.monitored_items.swapRemove(i);
            } else {
                i += 1;
            }
        }
        return response;
    }

    /// Look up the `MonitoredItemId` a `MonitoredItemNotification.
    /// client_handle` (from a decoded `.data_change` `Notification`)
    /// correlates to — the "which monitored item was this?" ergonomic helper
    /// `createMonitoredItems` populates the bookkeeping for.
    pub fn findMonitoredItem(sub: *const Subscription, client_handle: u32) ?u32 {
        for (sub.monitored_items.items) |mih| {
            if (mih.client_handle == client_handle) return mih.monitored_item_id;
        }
        return null;
    }

    pub const PublishOptions = struct {
        /// `RequestHeader.TimeoutHint`, milliseconds. `0` (the default) means
        /// "no timeout": Publish is meant to long-poll (OPC 10000-4 §5.13.5) —
        /// the server itself bounds how long it holds the request open,
        /// around `revised_max_keep_alive_count * revised_publishing_interval`.
        timeout_hint_ms: u32 = 0,
    };

    /// Publish (OPC 10000-4 §5.13.5): send one `PublishRequest` —
    /// acknowledging whatever sequence number the previous `publish`/
    /// `republish` call on this `Subscription` returned (see `pending_acks`)
    /// — and decode the response's `NotificationMessage`. The caller is
    /// expected to call this in a loop: each call blocks (a normal
    /// request/response over the same `Channel` every other service uses)
    /// until the server has something to report or its keep-alive interval
    /// elapses. Nothing further to do beyond freeing the returned
    /// `PublishResult` with `freePublishResult` — acknowledgement bookkeeping
    /// is handled automatically on the *next* call.
    pub fn publish(sub: *Subscription, options: PublishOptions) services.ServiceError!PublishResult {
        var acks = try std.ArrayList(services.SubscriptionAcknowledgement).initCapacity(sub.allocator, sub.pending_acks.items.len);
        defer acks.deinit(sub.allocator);
        for (sub.pending_acks.items) |seq| acks.appendAssumeCapacity(.{ .subscription_id = sub.subscription_id, .sequence_number = seq });
        sub.pending_acks.clearRetainingCapacity();

        const request: services.PublishRequest = .{
            .request_header = sub.session.channel.io.nextRequestHeader(sub.session.authentication_token, options.timeout_hint_ms),
            .subscription_acknowledgements = if (acks.items.len == 0) null else acks.items,
        };
        const response = try services.Channel.call(
            &sub.session.channel.io,
            .message,
            services.type_id.publish_request,
            services.PublishRequest,
            request,
            services.encodePublishRequest,
            services.PublishResponse,
            services.type_id.publish_response,
            services.decodePublishResponse,
            services.result_fns.publish,
        );
        services.freeResponseHeader(sub.allocator, response.response_header);
        errdefer {
            if (response.available_sequence_numbers) |s| sub.allocator.free(s);
            services.freeNotificationMessage(sub.allocator, response.notification_message);
            if (response.results) |r| sub.allocator.free(r);
            if (response.diagnostic_infos) |infos| {
                for (infos) |di| services.freeDiagnosticInfo(sub.allocator, di);
                sub.allocator.free(infos);
            }
        }

        const notifications = try decodeNotifications(sub.allocator, response.notification_message.notification_data);
        errdefer freeNotificationSlice(sub.allocator, notifications);

        try sub.pending_acks.append(sub.allocator, response.notification_message.sequence_number);

        const sequence_number = response.notification_message.sequence_number;
        const publish_time = response.notification_message.publish_time;
        services.freeNotificationMessage(sub.allocator, response.notification_message);
        if (response.diagnostic_infos) |infos| {
            for (infos) |di| services.freeDiagnosticInfo(sub.allocator, di);
            sub.allocator.free(infos);
        }

        return .{
            .subscription_id = response.subscription_id,
            .sequence_number = sequence_number,
            .publish_time = publish_time,
            .more_notifications = response.more_notifications,
            .notifications = notifications,
            .available_sequence_numbers = response.available_sequence_numbers,
            .ack_results = response.results,
        };
    }

    pub const RepublishOptions = struct {
        timeout_hint_ms: u32 = 10_000,
    };

    /// Republish (OPC 10000-4 §5.13.6): re-request a `NotificationMessage`
    /// the server already sent once but this client never acknowledged (its
    /// sequence number is still in `PublishResponse.AvailableSequenceNumbers`
    /// server-side — e.g. after a dropped/reconnected `Channel`). The
    /// returned message still needs acknowledging like any other `publish()`
    /// result — this queues its sequence number onto `pending_acks` the same
    /// way.
    pub fn republish(sub: *Subscription, retransmit_sequence_number: u32, options: RepublishOptions) services.ServiceError!PublishResult {
        const request: services.RepublishRequest = .{
            .request_header = sub.session.channel.io.nextRequestHeader(sub.session.authentication_token, options.timeout_hint_ms),
            .subscription_id = sub.subscription_id,
            .retransmit_sequence_number = retransmit_sequence_number,
        };
        const response = try services.Channel.call(
            &sub.session.channel.io,
            .message,
            services.type_id.republish_request,
            services.RepublishRequest,
            request,
            services.encodeRepublishRequest,
            services.RepublishResponse,
            services.type_id.republish_response,
            services.decodeRepublishResponse,
            services.result_fns.republish,
        );
        services.freeResponseHeader(sub.allocator, response.response_header);
        errdefer services.freeNotificationMessage(sub.allocator, response.notification_message);

        const notifications = try decodeNotifications(sub.allocator, response.notification_message.notification_data);
        errdefer freeNotificationSlice(sub.allocator, notifications);

        const sequence_number = response.notification_message.sequence_number;
        const publish_time = response.notification_message.publish_time;
        services.freeNotificationMessage(sub.allocator, response.notification_message);

        try sub.pending_acks.append(sub.allocator, sequence_number);

        return .{
            .subscription_id = sub.subscription_id,
            .sequence_number = sequence_number,
            .publish_time = publish_time,
            .more_notifications = false,
            .notifications = notifications,
            .available_sequence_numbers = null,
            .ack_results = null,
        };
    }

    /// Frees local bookkeeping (`pending_acks`/`monitored_items`) — does
    /// *not* call `delete` (this module never does I/O implicitly); safe to
    /// call whether or not `delete`/`Session.deleteSubscriptions` was called
    /// first, or if `create` never succeeded.
    pub fn deinit(sub: *Subscription) void {
        sub.pending_acks.deinit(sub.allocator);
        sub.monitored_items.deinit(sub.allocator);
    }
};

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

test "secure offline self-consistency: sealed OPN handshake (Basic256Sha256/SignAndEncrypt) -> derived keys agree -> symmetric MSG round-trip" {
    // Drives the REAL client code path (`SecureChannel.open` +
    // `Channel.call`) with SecurityMode=SignAndEncrypt against a
    // hand-played "server" that uses this module's own seal/open functions
    // with the roles swapped — proving the two directions of the asymmetric
    // OPN exchange and the P-SHA256-derived symmetric keys are mutually
    // consistent end-to-end. (The LIVE open62541 secure interop test below
    // is the independent oracle; this one runs offline everywhere.)
    const testing = std.testing;
    var prng = std.Random.DefaultCsprng.init([_]u8{42} ** 32);
    const random = prng.random();

    // Small keys keep this fast in Debug; nothing below hardcodes 2048-bit
    // lengths (they're all derived from the certificates' moduli).
    var client_creds = try security.ClientCredentials.generateSelfSigned(testing.allocator, random, .{
        .modulus_bits = 512,
        .common_name = "secure-selftest-client",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
        .application_uri = "urn:zig-libs:opcua:client",
    });
    defer client_creds.deinit(testing.allocator);
    var server_creds = try security.ClientCredentials.generateSelfSigned(testing.allocator, random, .{
        .modulus_bits = 768,
        .common_name = "secure-selftest-server",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
    });
    defer server_creds.deinit(testing.allocator);

    const server_nonce = "server-nonce-abcdefghijklmnopqrs"; // 32 bytes

    // ── Pre-render the sealed OPN response (the server's first reply;
    // request id 1). The seal is deterministic in structure, so it can be
    // rendered before the client's request exists.
    var opn_resp_alloc = std.Io.Writer.Allocating.init(testing.allocator);
    defer opn_resp_alloc.deinit();
    var opn_e = encoding.Encoder.init(&opn_resp_alloc.writer);
    try opn_e.writer.writeInt(u32, 7, .little); // SecureChannelId
    try security.encodeAsymmetricAlgorithmSecurityHeader(&opn_e, .{
        .security_policy_uri = security.SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = server_creds.certificate_der,
        .receiver_certificate_thumbprint = &security.certificateThumbprint(client_creds.certificate_der),
    });
    const opn_resp_enc_offset = opn_resp_alloc.writer.buffered().len;
    try opn_e.writer.writeInt(u32, 1, .little); // SequenceNumber
    try opn_e.writer.writeInt(u32, 1, .little); // RequestId
    try opn_e.encodeNodeId(services.type_id.open_secure_channel_response);
    try services.encodeOpenSecureChannelResponse(&opn_e, .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .server_protocol_version = 0,
        .security_token = .{ .channel_id = 7, .token_id = 3, .created_at = 0, .revised_lifetime = 3_600_000 },
        .server_nonce = server_nonce,
    });
    const sealed_opn_resp = try security.sealAsymmetricMessage(
        testing.allocator,
        random,
        transport.MessageType.open_secure_channel.code(),
        opn_resp_alloc.writer.buffered(),
        opn_resp_enc_offset,
        server_creds, // the server signs with ITS key…
        client_creds.certificate_der, // …and encrypts to the CLIENT's certificate
    );
    defer testing.allocator.free(sealed_opn_resp);

    // ── Client: real SecureChannel.open over the sealed response.
    var client_out_buf: [8192]u8 = undefined;
    var client_out_w: std.Io.Writer = .fixed(&client_out_buf);
    var client_in_r: std.Io.Reader = .fixed(sealed_opn_resp);
    var conn = transport.Connection.init(&client_in_r, &client_out_w);

    var ch = try SecureChannel.open(&conn, testing.allocator, .{
        .security = .{
            .policy = .basic256sha256,
            .mode = .sign_and_encrypt,
            .credentials = client_creds,
            .server_certificate = server_creds.certificate_der,
            .random = random,
        },
    });
    try testing.expectEqual(@as(u32, 7), ch.io.channel_id);
    try testing.expectEqual(@as(u32, 3), ch.io.token_id);
    try testing.expect(ch.io.security.?.keys != null);

    // ── Server side: open the client's sealed OPN request with the server
    // key + the client certificate, and check every security field.
    const opn_req_wire = client_out_w.buffered();
    try testing.expectEqualSlices(u8, "OPN", opn_req_wire[0..3]);
    try testing.expectEqual(opn_req_wire.len, std.mem.readInt(u32, opn_req_wire[4..8], .little));
    const opn_req_plain = try security.openAsymmetricMessage(
        testing.allocator,
        opn_req_wire[0..8],
        opn_req_wire[8..],
        server_creds.private_key,
        client_creds.certificate_der,
    );
    defer testing.allocator.free(opn_req_plain);

    var req_r: std.Io.Reader = .fixed(opn_req_plain);
    try testing.expectEqual(@as(u32, 0), try req_r.takeInt(u32, .little)); // SecureChannelId (0 on the first OPN)
    var req_d = encoding.Decoder.init(&req_r, testing.allocator);
    const req_hdr = try security.decodeAsymmetricAlgorithmSecurityHeader(&req_d);
    defer security.freeAsymmetricAlgorithmSecurityHeader(testing.allocator, req_hdr);
    try testing.expectEqualStrings(security.SecurityPolicy.basic256sha256.uri(), req_hdr.security_policy_uri.?);
    try testing.expectEqualSlices(u8, client_creds.certificate_der, req_hdr.sender_certificate.?);
    try testing.expectEqualSlices(u8, &security.certificateThumbprint(server_creds.certificate_der), req_hdr.receiver_certificate_thumbprint.?);
    try testing.expectEqual(@as(u32, 1), try req_r.takeInt(u32, .little)); // SequenceNumber
    try testing.expectEqual(@as(u32, 1), try req_r.takeInt(u32, .little)); // RequestId
    const req_type = try req_d.decodeNodeId();
    try testing.expectEqualDeep(services.type_id.open_secure_channel_request, req_type);
    const opn_req = try services.decodeOpenSecureChannelRequest(&req_d);
    defer services.freeOpenSecureChannelRequest(testing.allocator, opn_req);
    try testing.expectEqual(services.MessageSecurityMode.sign_and_encrypt, opn_req.security_mode);
    try testing.expectEqual(@as(usize, 32), opn_req.client_nonce.?.len);

    // The server's independent P-SHA256 derivation from the exchanged
    // nonces must agree byte-for-byte with the client's channel keys.
    const server_keys = security.deriveKeys(opn_req.client_nonce.?, server_nonce, .basic256sha256);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&ch.io.security.?.keys.?), std.mem.asBytes(&server_keys));

    // ── Symmetric MSG round-trip through the real Channel.call path:
    // pre-render a sealed CloseSessionResponse (request id 2) with the
    // server-direction keys.
    var msg_resp_alloc = std.Io.Writer.Allocating.init(testing.allocator);
    defer msg_resp_alloc.deinit();
    var msg_e = encoding.Encoder.init(&msg_resp_alloc.writer);
    try msg_e.writer.writeInt(u32, 7, .little); // SecureChannelId
    try msg_e.writer.writeInt(u32, 3, .little); // TokenId
    try msg_e.writer.writeInt(u32, 2, .little); // SequenceNumber
    try msg_e.writer.writeInt(u32, 2, .little); // RequestId
    try msg_e.encodeNodeId(services.type_id.close_session_response);
    try services.encodeCloseSessionResponse(&msg_e, .{
        .response_header = .{ .timestamp = 0, .request_handle = 2, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
    });
    const sealed_msg_resp = try security.symmetricSignAndEncrypt(
        testing.allocator,
        transport.MessageType.message.code(),
        msg_resp_alloc.writer.buffered(),
        .sign_and_encrypt,
        server_keys,
        .server_to_client,
    );
    defer testing.allocator.free(sealed_msg_resp);

    const msg_req_start = client_out_w.buffered().len;
    client_in_r = .fixed(sealed_msg_resp); // conn holds the pointer — swap the stream in place

    const close_resp = try services.Channel.call(
        &ch.io,
        .message,
        services.type_id.close_session_request,
        services.CloseSessionRequest,
        .{ .request_header = ch.io.nextRequestHeader(services.null_node_id, 0), .delete_subscriptions = false },
        services.encodeCloseSessionRequest,
        services.CloseSessionResponse,
        services.type_id.close_session_response,
        services.decodeCloseSessionResponse,
        services.result_fns.close_session,
    );
    services.freeCloseSessionResponse(testing.allocator, close_resp);
    try testing.expectEqual(@as(encoding.StatusCode, 0), close_resp.response_header.service_result);

    // And the client's outgoing MSG chunk opens cleanly with the
    // server-side keys (sender direction = client).
    const msg_req_wire = client_out_w.buffered()[msg_req_start..];
    try testing.expectEqualSlices(u8, "MSG", msg_req_wire[0..3]);
    const msg_req_plain = try security.symmetricDecryptAndVerify(
        testing.allocator,
        msg_req_wire[0..8],
        msg_req_wire[8..],
        .sign_and_encrypt,
        server_keys,
        .client_to_server,
    );
    defer testing.allocator.free(msg_req_plain);
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, msg_req_plain[0..4], .little)); // SecureChannelId
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, msg_req_plain[4..8], .little)); // TokenId
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, msg_req_plain[8..12], .little)); // SequenceNumber
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, msg_req_plain[12..16], .little)); // RequestId
}

test "Subscription offline flow: CreateSubscription -> CreateMonitoredItems -> Publish(DataChangeNotification) -> ack next Publish -> DeleteSubscriptions" {
    // Same technique as the "full offline flow" test above: hand-render a
    // sequence of MSG responses (all ride plain `.message` chunks — none of
    // Part 5's services are OPN/CLO-framed) and drive `Subscription` against
    // them over a bare `SecureChannel`/`Session`, the same way the
    // `Session.readAttribute` test above drives a bare `Channel` without
    // `SecureChannel.open`'s full handshake.
    const testing = std.testing;

    const render = struct {
        fn frame(w: *std.Io.Writer, request_id: u32, comptime Body: type, body: Body, comptime encodeFn: fn (*encoding.Encoder, Body) encoding.EncodeError!void, type_id: encoding.NodeId) !void {
            var body_alloc = std.Io.Writer.Allocating.init(testing.allocator);
            defer body_alloc.deinit();
            var e = encoding.Encoder.init(&body_alloc.writer);
            try e.writer.writeInt(u32, 7, .little); // SecureChannelId
            try e.writer.writeInt(u32, 3, .little); // TokenId
            try e.writer.writeInt(u32, request_id, .little); // SequenceNumber
            try e.writer.writeInt(u32, request_id, .little); // RequestId
            try e.encodeNodeId(type_id);
            try encodeFn(&e, body);
            const frame_body = body_alloc.writer.buffered();
            var conn = transport.Connection.init(undefined, w);
            try conn.sendChunk(.{ .message_type = .message, .chunk_type = .final, .message_size = 8 + @as(u32, @intCast(frame_body.len)) }, frame_body);
        }
    }.frame;

    var server_buf: [8192]u8 = undefined;
    var server_w: std.Io.Writer = .fixed(&server_buf);

    try render(&server_w, 1, services.CreateSubscriptionResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 1, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .subscription_id = 1,
        .revised_publishing_interval = 250.0,
        .revised_lifetime_count = 10000,
        .revised_max_keep_alive_count = 10,
    }, services.encodeCreateSubscriptionResponse, services.type_id.create_subscription_response);

    const cmi_results = [_]services.MonitoredItemCreateResult{.{
        .status_code = 0,
        .monitored_item_id = 1,
        .revised_sampling_interval = 250.0,
        .revised_queue_size = 1,
        .filter_result = services.no_filter,
    }};
    try render(&server_w, 2, services.CreateMonitoredItemsResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 2, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &cmi_results,
        .diagnostic_infos = null,
    }, services.encodeCreateMonitoredItemsResponse, services.type_id.create_monitored_items_response);

    var dcn_buf: [256]u8 = undefined;
    var dcn_w: std.Io.Writer = .fixed(&dcn_buf);
    var dcn_e = encoding.Encoder.init(&dcn_w);
    const mi_notifications = [_]services.MonitoredItemNotification{.{
        .client_handle = 1,
        .value = .{ .value = .{ .scalar = .{ .date_time = 132223104000000000 } }, .status = 0 },
    }};
    try services.encodeDataChangeNotification(&dcn_e, .{ .monitored_items = &mi_notifications, .diagnostic_infos = null });
    const notif_data_1 = [_]encoding.ExtensionObject{.{ .type_id = services.type_id.data_change_notification, .encoding = .byte_string, .body = dcn_w.buffered() }};
    try render(&server_w, 3, services.PublishResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 3, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .subscription_id = 1,
        .available_sequence_numbers = null,
        .more_notifications = false,
        .notification_message = .{ .sequence_number = 1, .publish_time = 0, .notification_data = &notif_data_1 },
        .results = null,
        .diagnostic_infos = null,
    }, services.encodePublishResponse, services.type_id.publish_response);

    const ack_results = [_]encoding.StatusCode{0};
    try render(&server_w, 4, services.PublishResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 4, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .subscription_id = 1,
        .available_sequence_numbers = null,
        .more_notifications = false,
        .notification_message = .{ .sequence_number = 2, .publish_time = 0, .notification_data = null }, // keep-alive
        .results = &ack_results, // ack of sequence 1 succeeded
        .diagnostic_infos = null,
    }, services.encodePublishResponse, services.type_id.publish_response);

    const del_results = [_]encoding.StatusCode{0};
    try render(&server_w, 5, services.DeleteSubscriptionsResponse, .{
        .response_header = .{ .timestamp = 0, .request_handle = 5, .service_result = 0, .service_diagnostics = .{}, .string_table = null, .additional_header = services.no_additional_header },
        .results = &del_results,
        .diagnostic_infos = null,
    }, services.encodeDeleteSubscriptionsResponse, services.type_id.delete_subscriptions_response);

    var client_out_buf: [8192]u8 = undefined;
    var client_out_w: std.Io.Writer = .fixed(&client_out_buf);
    var client_in_r: std.Io.Reader = .fixed(server_w.buffered());
    var conn = transport.Connection.init(&client_in_r, &client_out_w);
    var ch: SecureChannel = .{ .io = .{ .conn = &conn, .allocator = testing.allocator, .channel_id = 7, .token_id = 3 } };
    var session: Session = .{ .channel = &ch, .allocator = testing.allocator, .authentication_token = services.null_node_id };

    var sub = try Subscription.create(&session, testing.allocator, .{ .requested_publishing_interval_ms = 250.0 });
    defer sub.deinit();
    try testing.expectEqual(@as(u32, 1), sub.subscription_id);
    try testing.expectEqual(@as(f64, 250.0), sub.revised_publishing_interval);

    const cmi_specs = [_]Subscription.MonitoredItemSpec{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 2258 } },
        .client_handle = 1,
        .sampling_interval_ms = 250.0,
    }};
    const cmi_resp = try sub.createMonitoredItems(&cmi_specs, .both);
    defer services.freeCreateMonitoredItemsResponse(testing.allocator, cmi_resp);
    try testing.expectEqual(@as(usize, 1), sub.monitored_items.items.len);
    try testing.expectEqual(@as(u32, 1), sub.findMonitoredItem(1).?);

    // First publish: nothing pending to acknowledge yet, returns a
    // DataChangeNotification whose client_handle correlates back to
    // monitored_item_id 1 via `findMonitoredItem`.
    try testing.expectEqual(@as(usize, 0), sub.pending_acks.items.len);
    const pub1 = try sub.publish(.{});
    defer freePublishResult(testing.allocator, pub1);
    try testing.expectEqual(@as(usize, 1), pub1.notifications.len);
    try testing.expect(pub1.notifications[0] == .data_change);
    const dc = pub1.notifications[0].data_change;
    try testing.expectEqual(@as(usize, 1), dc.monitored_items.?.len);
    try testing.expectEqual(@as(u32, 1), dc.monitored_items.?[0].client_handle);
    try testing.expectEqual(@as(u32, 1), sub.findMonitoredItem(dc.monitored_items.?[0].client_handle).?);
    try testing.expectEqual(@as(encoding.DateTime, 132223104000000000), dc.monitored_items.?[0].value.value.?.scalar.date_time);
    // Sequence number 1 is now queued to be acknowledged on the *next* Publish.
    try testing.expectEqual(@as(usize, 1), sub.pending_acks.items.len);
    try testing.expectEqual(@as(u32, 1), sub.pending_acks.items[0]);

    // Second publish: drains+acks seq 1, gets back a keep-alive (empty
    // notification_data) plus that ack's result.
    const pub2 = try sub.publish(.{});
    defer freePublishResult(testing.allocator, pub2);
    try testing.expectEqual(@as(usize, 0), pub2.notifications.len);
    try testing.expectEqual(@as(usize, 1), pub2.ack_results.?.len);
    try testing.expect(!services.isBad(pub2.ack_results.?[0]));
    // This response's own new sequence number (2) is now queued for next time.
    try testing.expectEqual(@as(usize, 1), sub.pending_acks.items.len);
    try testing.expectEqual(@as(u32, 2), sub.pending_acks.items[0]);

    try sub.delete();
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

/// Best-effort stop+remove of a live-test container by name — used both as
/// leftover-cleanup before starting and as the `defer`'d teardown after
/// (including on test failure: registered right after the container starts).
fn stopContainer(gpa: std.mem.Allocator, io: std.Io, name: []const u8) void {
    var result = runPodman(gpa, io, &.{ "stop", "-t", "1", name }) catch return;
    result.deinit(gpa);
}

fn stopLiveContainer(gpa: std.mem.Allocator, io: std.Io) void {
    stopContainer(gpa, io, live_container_name);
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

const live_subs_container_name = "opcua-zig-libs-live-test-subs";

test "LIVE open62541 interop: subscriptions -> CreateSubscription -> CreateMonitoredItems -> Publish -> DataChangeNotification -> ack -> DeleteSubscriptions" {
    // A separate container (own name/port-independent-but-same-host-network,
    // started/torn down within this test) rather than folding this into the
    // Read/Browse/Write/Call LIVE test above — keeps the two independently
    // rerunnable and keeps this test's failure blast radius from taking the
    // other down with it.
    const testing = std.testing;
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    stopContainer(gpa, io, live_subs_container_name); // leftover cleanup, best-effort

    var run_result = runPodman(gpa, io, &.{
        "run",    "--rm",                   "-d",           "--network",                            "host",
        "--name", live_subs_container_name, "--pull=never", "docker.io/open62541/open62541:latest",
    }) catch |err| switch (err) {
        error.SkipZigTest => {
            std.debug.print("\nLIVE opcua subscriptions test SKIPPED: `podman` is not available in this environment.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        std.debug.print(
            "\nLIVE opcua subscriptions test SKIPPED: `podman run` failed (image not pulled / podman unusable here).\nstderr: {s}\n",
            .{run_result.stderr},
        );
        return error.SkipZigTest;
    }
    defer stopContainer(gpa, io, live_subs_container_name);

    var stream: std.Io.net.Stream = blk: {
        var attempt: usize = 0;
        while (attempt < 60) : (attempt += 1) {
            const addr = std.Io.net.IpAddress.parse("127.0.0.1", 4840) catch unreachable;
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            sleepMs(250);
        }
        std.debug.print("\nLIVE opcua subscriptions test SKIPPED: could not connect to opc.tcp://127.0.0.1:4840 within 15s.\n", .{});
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
    defer ch.close() catch {};

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

    // ── CreateSubscription: fast publishing interval so i=2258 (Server
    // CurrentTime, changes every tick) produces a notification quickly.
    var sub = try Subscription.create(&session, gpa, .{
        .requested_publishing_interval_ms = 250.0,
        .requested_max_keep_alive_count = 20,
        .requested_lifetime_count = 200,
    });
    defer sub.deinit();
    try testing.expect(sub.subscription_id != 0);

    // ── CreateMonitoredItems: i=2258 Server_ServerStatus_CurrentTime.
    const monitor_client_handle: u32 = 1;
    const cmi_specs = [_]Subscription.MonitoredItemSpec{.{
        .node_id = .{ .numeric = .{ .namespace = 0, .id = 2258 } },
        .client_handle = monitor_client_handle,
        .sampling_interval_ms = 250.0,
        .queue_size = 10,
    }};
    const cmi_resp = try sub.createMonitoredItems(&cmi_specs, .both);
    defer services.freeCreateMonitoredItemsResponse(gpa, cmi_resp);
    try testing.expectEqual(@as(usize, 1), cmi_resp.results.?.len);
    try testing.expect(!services.isBad(cmi_resp.results.?[0].status_code));
    try testing.expectEqual(@as(usize, 1), sub.monitored_items.items.len);
    const created_monitored_item_id = sub.findMonitoredItem(monitor_client_handle).?;

    // ── Publish loop: keep calling until a DataChangeNotification carrying
    // our monitored item's value shows up (open62541 sends the item's
    // current value on the very first Publish after CreateMonitoredItems in
    // Reporting mode, so this should resolve in one or two iterations —
    // bounded generously to tolerate scheduling jitter under CI/containers).
    var found_data_change = false;
    var found_client_handle_match = false;
    var acked_sequence_number: ?u32 = null;
    var attempt: usize = 0;
    while (attempt < 40 and !found_data_change) : (attempt += 1) {
        const pub_result = try sub.publish(.{ .timeout_hint_ms = 5_000 });
        defer freePublishResult(gpa, pub_result);
        for (pub_result.notifications) |n| {
            switch (n) {
                .data_change => |dcn| {
                    for (dcn.monitored_items orelse &.{}) |mi| {
                        if (mi.client_handle == monitor_client_handle) {
                            found_data_change = true;
                            found_client_handle_match = sub.findMonitoredItem(mi.client_handle) == created_monitored_item_id;
                            try testing.expect(mi.value.value != null);
                            try testing.expect(mi.value.value.? == .scalar);
                            try testing.expect(mi.value.value.?.scalar == .date_time);
                            try testing.expect(mi.value.value.?.scalar.date_time > 0);
                            acked_sequence_number = pub_result.sequence_number;
                        }
                    }
                },
                else => {},
            }
        }
    }
    if (!found_data_change) {
        std.debug.print("\nLIVE opcua subscriptions test: no DataChangeNotification observed after {d} Publish attempts.\n", .{attempt});
    }
    try testing.expect(found_data_change);
    try testing.expect(found_client_handle_match);
    try testing.expect(acked_sequence_number != null);

    // One more Publish call actually sends the acknowledgement (queued in
    // `sub.pending_acks` by the call above) to the server and gets back its
    // result — verifying the ack round-trip, not just the local bookkeeping.
    const ack_pub_result = try sub.publish(.{ .timeout_hint_ms = 5_000 });
    defer freePublishResult(gpa, ack_pub_result);
    if (ack_pub_result.ack_results) |results| {
        for (results) |r| try testing.expect(!services.isBad(r));
    }

    // ── DeleteMonitoredItems + DeleteSubscriptions + session/channel teardown.
    const del_mi_resp = try sub.deleteMonitoredItems(&.{created_monitored_item_id});
    defer services.freeDeleteMonitoredItemsResponse(gpa, del_mi_resp);
    try testing.expectEqual(@as(usize, 0), sub.monitored_items.items.len);

    try sub.delete();
}

const live_secure_container_name = "opcua-zig-libs-live-test-secure";

/// One full secure client sequence against the live server: connect ->
/// Hello -> OpenSecureChannel (Basic256Sha256, `mode`) -> CreateSession ->
/// ActivateSession (clientSignature over serverCertificate ‖ serverNonce)
/// -> Read i=2258 over the signed(-and-encrypted) channel -> teardown.
fn liveSecureSequence(
    gpa: std.mem.Allocator,
    io: std.Io,
    mode: security.SecurityMode,
    credentials: security.ClientCredentials,
    server_certificate: []const u8,
    random: std.Random,
) !void {
    const testing = std.testing;

    const addr = std.Io.net.IpAddress.parse("127.0.0.1", 4840) catch unreachable;
    var stream = try addr.connect(io, .{ .mode = .stream });
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

    var ch = try SecureChannel.open(&conn, gpa, .{
        .security = .{
            .policy = .basic256sha256,
            .mode = mode,
            .credentials = credentials,
            .server_certificate = server_certificate,
            .random = random,
        },
    });
    defer ch.close() catch {};
    try testing.expect(ch.io.security.?.keys != null);

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

    // The proof: a DataValue read over the secured channel decrypts +
    // verifies into a plausible server CurrentTime.
    const current_time = try session.readAttribute(.{ .numeric = .{ .namespace = 0, .id = 2258 } }, services.attribute_id.value);
    defer encoding.freeDataValue(gpa, current_time);
    try testing.expect(current_time.value != null);
    try testing.expect(current_time.value.? == .scalar);
    try testing.expect(current_time.value.?.scalar == .date_time);
    try testing.expect(current_time.value.?.scalar.date_time > 0);
}

test "LIVE open62541 secure interop: Basic256Sha256 SignAndEncrypt + Sign -> OPN -> session -> encrypted Read i=2258" {
    // The real oracle for the whole security layer: a genuine open62541
    // server (`server_ctt` with its baked-in certificate). The image's
    // default CMD carries no trust list and its mbedtls verifier then
    // rejects every client certificate as BadCertificateUntrusted (the
    // startup "Any remote certificate will be accepted" warning
    // notwithstanding — verified empirically), so the container is started
    // with an explicit `--trustlistFolder /trust` and our freshly generated
    // client certificate is copied in (`server_ctt` reloads the folder on
    // every OPN). The server's certificate is pulled out of the container
    // (`podman exec cat`) and pinned — exactly what a deployment would do
    // out-of-band.
    const testing = std.testing;
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    stopContainer(gpa, io, live_secure_container_name); // leftover cleanup, best-effort

    var run_result = runPodman(gpa, io, &.{
        "run",                                  "--rm",                                         "-d",                                         "--network",
        "host",                                 "--name",                                       live_secure_container_name,                   "--pull=never",
        "docker.io/open62541/open62541:latest",
        // The image's CMD, minus its implicit empty trust list:
        "/opt/open62541/build/bin/examples/server_ctt", "/opt/open62541/pki/created/server_cert.der", "/opt/open62541/pki/created/server_key.der",
        "--trustlistFolder",                    "/trust",                                       "--enableUnencrypted",                        "--enableAnonymous",
    }) catch |err| switch (err) {
        error.SkipZigTest => {
            std.debug.print("\nLIVE opcua secure interop test SKIPPED: `podman` is not available in this environment.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        std.debug.print(
            "\nLIVE opcua secure interop test SKIPPED: `podman run` failed (image not pulled / podman unusable here).\nstderr: {s}\n",
            .{run_result.stderr},
        );
        return error.SkipZigTest;
    }
    defer stopContainer(gpa, io, live_secure_container_name);

    // Wait for the listener, then close the probe connection — the secure
    // sequences below open their own.
    {
        var probe: std.Io.net.Stream = blk: {
            var attempt: usize = 0;
            while (attempt < 60) : (attempt += 1) {
                const addr = std.Io.net.IpAddress.parse("127.0.0.1", 4840) catch unreachable;
                if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
                sleepMs(250);
            }
            std.debug.print("\nLIVE opcua secure interop test SKIPPED: could not connect to opc.tcp://127.0.0.1:4840 within 15s.\n", .{});
            return error.SkipZigTest;
        };
        probe.close(io);
    }

    // Pin the server's certificate straight out of the running container.
    var cert_result = try runPodman(gpa, io, &.{
        "exec", live_secure_container_name, "cat", "/opt/open62541/pki/created/server_cert.der",
    });
    defer cert_result.deinit(gpa);
    if (cert_result.exit_code != 0 or cert_result.stdout.len == 0) {
        std.debug.print("\nLIVE opcua secure interop test SKIPPED: could not read the server certificate from the container.\nstderr: {s}\n", .{cert_result.stderr});
        return error.SkipZigTest;
    }
    const server_certificate = cert_result.stdout;
    // Sanity: it must parse as an RSA certificate (same helper the OPN
    // seal/open path uses).
    _ = try security.certificatePublicKey(server_certificate);

    // A real (OS-entropy-seeded) CSPRNG — this handshake leaves the machine.
    var seed: [32]u8 = undefined;
    if (std.os.linux.getrandom(&seed, seed.len, 0) != seed.len) return error.SkipZigTest;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const random = csprng.random();

    // 2048-bit: the conventional Basic256Sha256 application-certificate
    // size (`SecurityLengths.basic256sha256`'s documented shape).
    var credentials = try security.ClientCredentials.generateSelfSigned(gpa, random, .{
        .modulus_bits = 2048,
        .common_name = "zig-libs opcua secure interop test",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
        .application_uri = "urn:zig-libs:opcua:client",
    });
    defer credentials.deinit(gpa);

    // Get the client certificate into the server's trust-list folder:
    // stage it on the host, `podman cp` it in.
    const host_cert_path = "/tmp/opcua-zig-libs-live-secure-client-cert.der";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = host_cert_path, .data = credentials.certificate_der });
    defer std.Io.Dir.cwd().deleteFile(io, host_cert_path) catch {};
    {
        var mkdir_result = try runPodman(gpa, io, &.{ "exec", live_secure_container_name, "mkdir", "-p", "/trust" });
        defer mkdir_result.deinit(gpa);
        if (mkdir_result.exit_code != 0) return error.SkipZigTest;
        var cp_result = try runPodman(gpa, io, &.{ "cp", host_cert_path, live_secure_container_name ++ ":/trust/client_cert.der" });
        defer cp_result.deinit(gpa);
        if (cp_result.exit_code != 0) {
            std.debug.print("\nLIVE opcua secure interop test SKIPPED: `podman cp` into the container failed.\nstderr: {s}\n", .{cp_result.stderr});
            return error.SkipZigTest;
        }
    }

    // SignAndEncrypt is the headline mode; Sign proves the
    // signature-only symmetric framing (no padding, no encryption) against
    // the same server.
    try liveSecureSequence(gpa, io, .sign_and_encrypt, credentials, server_certificate, random);
    try liveSecureSequence(gpa, io, .sign, credentials, server_certificate, random);
}
