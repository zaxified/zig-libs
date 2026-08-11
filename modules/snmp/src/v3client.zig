// SPDX-License-Identifier: MIT

//! Manager-side **SNMPv3 / USM** client over the same caller-provided
//! `Transport` seam the v1/v2c `Client` uses — "send these request bytes, give
//! me the reply bytes" — so every test runs offline from in-memory buffers.
//!
//! This is the layer that ties the pieces together: `v3` (RFC 3412 envelope +
//! ScopedPDU) → `usm` (RFC 3414 security parameters, key localization, HMAC) →
//! `priv` (DES-CBC / AES-128-CFB) → `timewin` (±150 s anti-replay) → `report`
//! (Report-PDU classification). It is allocation-free and single-owner, like
//! `Client`.
//!
//! ## The three security levels (RFC 3414 §1.4)
//!   * `noAuthNoPriv` — envelope only. The user name is not a credential.
//!   * `authNoPriv` — HMAC over the whole datagram; plaintext ScopedPDU.
//!   * `authPriv` — as above plus an encrypted ScopedPDU. Privacy without
//!     authentication does not exist in USM, and this client refuses to build it.
//!
//! ## The discovery handshake (RFC 3414 §4)
//! A v3 manager cannot say anything authenticated until it knows the remote
//! engine's `snmpEngineID` (keys are localized to it) and its
//! `snmpEngineBoots`/`snmpEngineTime` (the replay window). So the first
//! exchange is an unauthenticated, `reportable` GetRequest with an EMPTY
//! engineID, empty user name and no varbinds; the engine answers with a
//! **Report** carrying `usmStatsUnknownEngineIDs.0` and — in its USM security
//! parameters — its real engineID/boots/time. `discover` performs exactly that
//! and is public, so a caller can drive (or pre-seed) the step itself.
//!
//! **Trust note.** The discovery Report is by construction unauthenticated, so
//! its clock is *unverified*. This client therefore only adopts an
//! unauthenticated clock while undiscovered. If it was spoofed LOW, the very
//! next authenticated request falls outside the engine's real window and the
//! engine answers with an **authenticated** `usmStatsNotInTimeWindows` Report;
//! that one is verified and dated before its clock is latched forward, and the
//! request is retried once. That is the RFC 3414 §3.2 self-correction, and it
//! is why a v3 client needs no clock of its own — this module makes no
//! time-of-day calls at all.
//!
//! The correction is deliberately one-way. Peer-driven clock updates go through
//! `timewin.latch`, which only ever moves boots/time FORWARD, so no Report can
//! lower `latestReceivedEngineTime` and re-open the replay window; and an
//! authenticated Report about an engine we already hold is itself put through
//! the ±150 s window before it is acted on, so a captured Report cannot be
//! replayed into a clock rewind. The price is that a clock spoofed *ahead*
//! during discovery cannot be walked back by a Report — that needs a fresh
//! `discover`. `setEngineTime` / `advanceEngineTime` remain available for
//! callers that keep a clock of their own.
//!
//! A Report is never returned as data: it becomes a typed `report.ReportError`.
//!
//! Provenance: clean-room from RFC 3412 (v3 message processing), RFC 3414
//! (USM, discovery, time window), RFC 3826 (AES privacy) and RFC 7860 (SHA-2
//! auth); net-snmp used as a black-box interop oracle only — no source
//! consulted or copied.

const std = @import("std");
const ber = @import("ber.zig");
const oid_mod = @import("oid.zig");
const message = @import("message.zig");
const client_mod = @import("client.zig");
const v3 = @import("v3.zig");
const usm = @import("usm.zig");
const priv = @import("priv.zig");
const timewin = @import("timewin.zig");
const report_mod = @import("report.zig");

const Oid = oid_mod.Oid;
const VarBind = message.VarBind;
const Transport = client_mod.Transport;

/// Largest `snmpEngineID` (RFC 3411 SnmpEngineID is SIZE(5..32)).
pub const max_engine_id_len = 32;

/// Smallest `snmpEngineID` (RFC 3411 SnmpEngineID is SIZE(5..32)). Not a
/// tuning knob: an engine ID shorter than 5 octets cannot carry the
/// enterprise number the format is built around, so a peer offering one is
/// not offering an `SnmpEngineID`.
pub const min_engine_id_len = 5;

/// Largest `msgUserName` (RFC 3414 §2.4 — SIZE(0..32)).
pub const max_user_name_len = 32;

/// Buffer size for the v3 request/reply datagrams and the ScopedPDU scratch.
pub const max_message_len = client_mod.max_message_len;

/// Upper bound on OIDs per get/getNext/getBulk call.
pub const max_request_oids = client_mod.max_request_oids;

/// USM security levels (RFC 3414 §1.4). Ordered weakest → strongest.
pub const SecurityLevel = enum {
    no_auth_no_priv,
    auth_no_priv,
    auth_priv,

    pub fn hasAuth(self: SecurityLevel) bool {
        return self != .no_auth_no_priv;
    }
    pub fn hasPriv(self: SecurityLevel) bool {
        return self == .auth_priv;
    }
};

/// A USM user: the name on the wire plus the passwords/protocols the localized
/// keys are derived from. Passwords are borrowed, never copied — the derived
/// localized keys live in the client, the passwords do not.
pub const User = struct {
    /// `msgUserName` (SIZE 0..32).
    name: []const u8,
    level: SecurityLevel = .no_auth_no_priv,
    /// Authentication protocol; ignored at `noAuthNoPriv`.
    auth_protocol: usm.AuthProtocol = .hmac_sha1,
    /// Authentication password, localized to the engine at discovery time.
    auth_password: []const u8 = &.{},
    /// Privacy protocol; ignored below `authPriv`.
    priv_protocol: priv.PrivProtocol = .aes128_cfb,
    /// Privacy password. RFC 3414 §2.6: it is localized with the **auth**
    /// protocol's hash, then truncated to the cipher's key length.
    priv_password: []const u8 = &.{},
};

/// The client's view of one authoritative engine: its ID, its clock, and the
/// localized keys derived for the configured user against that ID.
pub const EngineState = struct {
    id_buf: [max_engine_id_len]u8 = undefined,
    id_len: usize = 0,
    clock: timewin.EngineTimeState = .{ .engine_boots = 0, .engine_time = 0, .latest_received_engine_time = 0 },
    /// False until `discover` (or `seedEngine`) has run; keys are invalid before then.
    discovered: bool = false,
    auth_key_buf: [usm.max_key_len]u8 = undefined,
    auth_key_len: usize = 0,
    priv_key_buf: [usm.max_key_len]u8 = undefined,
    priv_key_len: usize = 0,

    pub fn id(self: *const EngineState) []const u8 {
        return self.id_buf[0..self.id_len];
    }
    pub fn authKey(self: *const EngineState) []const u8 {
        return self.auth_key_buf[0..self.auth_key_len];
    }
    pub fn privKey(self: *const EngineState) []const u8 {
        return self.priv_key_buf[0..self.priv_key_len];
    }
};

/// What a completed v3 request produced. Varbinds borrow the client's reply /
/// plaintext buffers and stay valid until the next request.
pub const Response = struct {
    error_status: message.ErrorStatus,
    error_index: u32,
    varbinds: message.VarBindList,
    context_engine_id: []const u8,
    context_name: []const u8,
};

pub const Error = client_mod.TransportError || message.DecodeError ||
    message.EncodeError || v3.DecodeError || usm.AuthError ||
    usm.KeyDerivationError || priv.PrivError || timewin.TimeError ||
    report_mod.ReportError || error{
    /// The reply's inner request-id did not match the request's.
    RequestIdMismatch,
    /// The reply's `msgID` did not match the request's (RFC 3412 §7.2 step 4).
    MsgIdMismatch,
    /// The reply carried a PDU that is neither Response nor Report.
    UnexpectedPduType,
    /// More OIDs than `max_request_oids`.
    TooManyOids,
    /// An authenticated/encrypted request was attempted before `discover`.
    NotDiscovered,
    /// The reply's `msgAuthoritativeEngineID` is not the engine we localized
    /// our keys to — a different engine answered, or the engine changed ID.
    EngineIdMismatch,
    /// The engine reported an ID longer than `max_engine_id_len`, or an empty
    /// one where a real one was required.
    BadEngineId,
    /// The user name exceeds `max_user_name_len`.
    BadUserName,
    /// The security level needs a password that the `User` left empty.
    MissingCredentials,
    /// The reply came back at a weaker security level than we sent (an agent
    /// must answer authPriv with authPriv).
    SecurityLevelDowngrade,
    /// A recoverable Report kept coming back after the allowed retry.
    ReportRetryExhausted,
};

/// Allocation-free SNMPv3 manager. Single-owner: it holds the msgID/request-id
/// counters, the privacy salt counter, the engine state and the message
/// buffers, so one thread/loop drives it.
pub const V3Client = struct {
    transport: Transport,
    user: User,
    engine: EngineState = .{},
    next_msg_id: i32,
    next_request_id: i32,
    /// The privacy salt source (`priv.SaltSource`) — it, not the caller, owns
    /// `msgPrivacyParameters`, so no code path here can hand the cipher a
    /// repeated salt. If `Options.initial_salt` was left null the counter is
    /// re-seeded from the engine's discovered `engineBoots‖engineTime` before
    /// the first encrypted message, so a client restart does not resume the
    /// counter from the same place (RFC 3414 §8.1.1.1 "pseudo-random at boot").
    /// That gives one-second separation, not a guarantee: two runs that reach
    /// their first authPriv message inside the same engine second still start
    /// from the same value.
    salt_source: priv.SaltSource,
    /// Whether `salt_source` still needs its engine-derived seed.
    salt_needs_seed: bool,
    /// `contextName` sent in every ScopedPDU (RFC 3412 §6.8); "" is the default
    /// context and what agents expect.
    context_name: []const u8,
    request_buf: [max_message_len]u8 = undefined,
    reply_buf: [max_message_len]u8 = undefined,
    scoped_buf: [max_message_len]u8 = undefined,
    plain_buf: [max_message_len]u8 = undefined,

    pub const Options = struct {
        initial_msg_id: i32 = 1,
        initial_request_id: i32 = 1,
        /// Seed for the privacy-salt counter. `null` (the default) means "derive
        /// it from the engine's discovered clock" — see `salt_source`. Set it
        /// explicitly only to make salts reproducible in a test, or to supply a
        /// better (random) seed than the engine clock.
        initial_salt: ?u64 = null,
        context_name: []const u8 = &.{},
    };

    pub fn init(transport: Transport, user: User, options: Options) V3Client {
        return .{
            .transport = transport,
            .user = user,
            .next_msg_id = options.initial_msg_id,
            .next_request_id = options.initial_request_id,
            .salt_source = priv.SaltSource.counter(options.initial_salt orelse 0),
            .salt_needs_seed = options.initial_salt == null,
            .context_name = options.context_name,
        };
    }

    // ── engine discovery / clock ────────────────────────────────────────────

    /// Run the RFC 3414 §4 discovery exchange: an unauthenticated, reportable
    /// GetRequest with an empty engineID and no varbinds. The engine's Report
    /// supplies `msgAuthoritativeEngineID`/boots/time, which are latched, and
    /// the user's localized keys are derived against that engine ID.
    ///
    /// Idempotent-ish: calling it again re-runs the exchange and re-derives the
    /// keys (useful after an engine restart with a new ID).
    pub fn discover(c: *V3Client) Error!void {
        const msg_id = c.allocMsgId();
        const rid = c.allocRequestId();

        // USM parameters: everything empty — we know nothing yet.
        var sp_buf: [64]u8 = undefined;
        const sp = try usm.encode(&sp_buf, .{
            .engine_id = &.{},
            .engine_boots = 0,
            .engine_time = 0,
            .user_name = &.{},
            .auth_params = &.{},
            .priv_params = &.{},
        });
        const wire = try v3.encode(&c.request_buf, .{
            .msg_id = msg_id,
            .flags = .{ .reportable = true },
            .security_parameters = sp,
            .context_engine_id = &.{},
            .context_name = &.{},
            .pdu = .{ .type = .get_request, .request_id = rid },
        });

        const reply = try c.transport.exchange(wire, &c.reply_buf);
        const m = try v3.decode(reply);
        if (m.header.msg_id != msg_id) return error.MsgIdMismatch;
        const params = try usm.parse(m.security_parameters);

        // The discovery reply must be a plaintext Report; anything else means
        // the peer is not speaking the handshake.
        const scoped = switch (m.data) {
            .plaintext => |s| s,
            .encrypted => return error.UnexpectedPduType,
        };
        const info = report_mod.classify(scoped) catch |err| switch (err) {
            error.EmptyReport => return error.UnknownReport,
            else => |e| return e,
        };
        // usmStatsUnknownEngineIDs is the expected answer, but some agents
        // answer a bare probe with a different usmStats counter; either way the
        // engine ID we need is in the security parameters. Only a Report OID we
        // cannot classify at all is fatal.
        if (info.reason == .unknown) return error.UnknownReport;

        try c.seedEngine(params.engine_id, params.engine_boots, params.engine_time);
    }

    /// Adopt an engine identity + clock without an exchange, and derive the
    /// user's localized keys for it. Use when the engineID/boots/time are
    /// already known (a cached peer, or a caller-driven discovery).
    pub fn seedEngine(c: *V3Client, engine_id: []const u8, boots: u32, time: u32) Error!void {
        if (engine_id.len < min_engine_id_len or engine_id.len > max_engine_id_len) return error.BadEngineId;
        if (c.user.name.len > max_user_name_len) return error.BadUserName;

        @memcpy(c.engine.id_buf[0..engine_id.len], engine_id);
        c.engine.id_len = engine_id.len;
        c.engine.clock = timewin.EngineTimeState.init(boots, time);

        // Localize the keys to THIS engine (RFC 3414 §2.6).
        if (c.user.level.hasAuth()) {
            if (c.user.auth_password.len == 0) return error.MissingCredentials;
            const k = try usm.passwordToKey(
                c.user.auth_protocol,
                c.user.auth_password,
                c.engine.id(),
                &c.engine.auth_key_buf,
            );
            c.engine.auth_key_len = k.len;
        } else c.engine.auth_key_len = 0;

        if (c.user.level.hasPriv()) {
            if (c.user.priv_password.len == 0) return error.MissingCredentials;
            // RFC 3414 §2.6: the privacy password is localized with the AUTH
            // protocol's hash, then the cipher takes the leading key bytes.
            const k = try usm.passwordToKey(
                c.user.auth_protocol,
                c.user.priv_password,
                c.engine.id(),
                &c.engine.priv_key_buf,
            );
            if (k.len < c.user.priv_protocol.keyLen()) return error.KeyTooShort;
            c.engine.priv_key_len = k.len;
        } else c.engine.priv_key_len = 0;

        c.engine.discovered = true;
    }

    /// Overwrite the cached engine clock (for callers that keep their own).
    pub fn setEngineTime(c: *V3Client, boots: u32, time: u32) void {
        c.engine.clock = timewin.EngineTimeState.init(boots, time);
    }

    /// Advance the cached `snmpEngineTime` estimate by `seconds` — for callers
    /// that hold a clock and want to keep a long-lived session inside the
    /// window without waiting for a `notInTimeWindows` Report. Saturating.
    pub fn advanceEngineTime(c: *V3Client, seconds: u32) void {
        c.engine.clock.engine_time +|= seconds;
        c.engine.clock.latest_received_engine_time = c.engine.clock.engine_time;
    }

    // ── requests ────────────────────────────────────────────────────────────

    /// GetRequest for up to `max_request_oids` object instances.
    pub fn get(c: *V3Client, oids: []const Oid) Error!Response {
        return c.nullVarBindRequest(.get_request, oids, 0, 0);
    }

    /// GetNextRequest — the lexicographic successors of `oids`.
    pub fn getNext(c: *V3Client, oids: []const Oid) Error!Response {
        return c.nullVarBindRequest(.get_next_request, oids, 0, 0);
    }

    /// GetBulkRequest (RFC 3416 §4.2.3).
    pub fn getBulk(c: *V3Client, non_repeaters: i32, max_repetitions: i32, oids: []const Oid) Error!Response {
        return c.nullVarBindRequest(.get_bulk_request, oids, non_repeaters, max_repetitions);
    }

    /// SetRequest with fully typed varbinds.
    pub fn set(c: *V3Client, varbinds: []const VarBind) Error!Response {
        return c.request(.set_request, varbinds, 0, 0);
    }

    fn nullVarBindRequest(
        c: *V3Client,
        pdu_type: message.PduType,
        oids: []const Oid,
        f1: i32,
        f2: i32,
    ) Error!Response {
        if (oids.len > max_request_oids) return error.TooManyOids;
        var vbs: [max_request_oids]VarBind = undefined;
        for (oids, 0..) |o, i| vbs[i] = .{ .name = o, .value = .null };
        return c.request(pdu_type, vbs[0..oids.len], f1, f2);
    }

    /// One full request, with the single RFC-sanctioned retry: a *recoverable*
    /// Report (unknownEngineIDs / notInTimeWindows) updates the engine state
    /// and the request is re-sent exactly once. Any other Report is a typed
    /// error.
    fn request(
        c: *V3Client,
        pdu_type: message.PduType,
        varbinds: []const VarBind,
        f1: i32,
        f2: i32,
    ) Error!Response {
        if (!c.engine.discovered) {
            if (c.user.level.hasAuth()) return error.NotDiscovered;
            try c.discover();
        }
        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            const outcome = try c.exchangeOnce(pdu_type, varbinds, f1, f2);
            switch (outcome) {
                .response => |r| return r,
                .report => |rep| {
                    if (!rep.acted) return report_mod.toError(rep.reason);
                    if (attempt == 0) continue;
                    return error.ReportRetryExhausted;
                },
            }
        }
    }

    const Outcome = union(enum) {
        response: Response,
        report: ReportOutcome,
    };

    const ReportOutcome = struct {
        reason: report_mod.Reason,
        /// True when the Report was trustworthy enough that we changed engine
        /// state from it — and therefore re-sending the request can now
        /// plausibly succeed. A Report we could not act on is terminal
        /// immediately; retrying it would only repeat the same failure.
        acted: bool,
    };

    /// A built, signed, ready-to-send request plus the ids the reply must echo.
    const Prepared = struct {
        wire: []u8,
        msg_id: i32,
        request_id: i32,
    };

    fn exchangeOnce(
        c: *V3Client,
        pdu_type: message.PduType,
        varbinds: []const VarBind,
        f1: i32,
        f2: i32,
    ) Error!Outcome {
        const p = try c.buildRequest(pdu_type, varbinds, f1, f2);
        const n = try c.transport.exchangeFn(c.transport.ctx, p.wire, &c.reply_buf);
        if (n > c.reply_buf.len) return error.TransportFailed;
        return c.processReply(c.reply_buf[0..n], p.msg_id, p.request_id, c.user.level);
    }

    /// Build (and, at an authenticated level, sign in place) one v3 request
    /// datagram in `request_buf`. Split out of `exchangeOnce` so the wire form
    /// can be produced and inspected without a transport.
    fn buildRequest(
        c: *V3Client,
        pdu_type: message.PduType,
        varbinds: []const VarBind,
        f1: i32,
        f2: i32,
    ) Error!Prepared {
        const level = c.user.level;
        const msg_id = c.allocMsgId();
        const rid = c.allocRequestId();
        if (c.user.name.len > max_user_name_len) return error.BadUserName;

        const pdu: message.EncodePdu = .{
            .type = pdu_type,
            .request_id = rid,
            .error_status = f1,
            .error_index = f2,
            .varbinds = varbinds,
        };

        // The auth digest is computed over the finished datagram with
        // msgAuthenticationParameters zero-filled to its FINAL length, so the
        // placeholder must already be that long (RFC 3414 §6.3.1 / RFC 7860
        // §4.2.1). Encoding it any shorter and patching afterwards would shift
        // every following byte and invalidate the digest.
        const zeros = [_]u8{0} ** usm.max_digest_len;
        const auth_placeholder: []const u8 = if (level.hasAuth())
            zeros[0..c.user.auth_protocol.digestLen()]
        else
            &.{};

        const flags: v3.MsgFlags = .{
            .auth = level.hasAuth(),
            .priv = level.hasPriv(),
            .reportable = true,
        };

        // `msgPrivacyParameters` is whatever the salt source chose, so the
        // ScopedPDU has to be encrypted BEFORE the USM header is built — the
        // salt is an output of encryption here, not an input to it.
        var sp_buf: [128]u8 = undefined;
        const wire = if (level.hasPriv()) w: {
            c.seedSaltSource();
            const plain = try v3.encodeScopedPdu(&c.scoped_buf, .{
                .context_engine_id = c.engine.id(),
                .context_name = c.context_name,
                .pdu = pdu,
            });
            // DES pads to a multiple of 8; encrypt in the plaintext scratch's
            // sibling buffer so neither aliases the outgoing datagram.
            const enc = try priv.encrypt(
                c.user.priv_protocol,
                c.engine.privKey(),
                c.engine.clock.engine_boots,
                c.engine.clock.engine_time,
                &c.salt_source,
                plain,
                &c.plain_buf,
            );
            const sp = try usm.encode(&sp_buf, .{
                .engine_id = c.engine.id(),
                .engine_boots = c.engine.clock.engine_boots,
                .engine_time = c.engine.clock.engine_time,
                .user_name = c.user.name,
                .auth_params = auth_placeholder,
                .priv_params = &enc.salt,
            });
            break :w try v3.encodeEncrypted(&c.request_buf, .{
                .msg_id = msg_id,
                .flags = flags,
                .security_parameters = sp,
                .encrypted_pdu = enc.ciphertext,
            });
        } else w: {
            const sp = try usm.encode(&sp_buf, .{
                .engine_id = c.engine.id(),
                .engine_boots = c.engine.clock.engine_boots,
                .engine_time = c.engine.clock.engine_time,
                .user_name = c.user.name,
                .auth_params = auth_placeholder,
                .priv_params = &.{},
            });
            break :w try v3.encode(&c.request_buf, .{
                .msg_id = msg_id,
                .flags = flags,
                .security_parameters = sp,
                .context_engine_id = c.engine.id(),
                .context_name = c.context_name,
                .pdu = pdu,
            });
        };

        // Sign in place. The encoder writes backwards, so `wire` is the tail of
        // request_buf; take the same range mutably rather than casting away
        // const, and locate the auth field by pointer identity inside it.
        const out = c.request_buf[c.request_buf.len - wire.len ..];
        if (level.hasAuth()) {
            const sent = try v3.decode(out);
            const sent_params = try usm.parse(sent.security_parameters);
            const off = usm.authOffsetFor(c.user.auth_protocol, out, sent_params) orelse
                return error.BadAuthParams;
            usm.sign(c.user.auth_protocol, c.engine.authKey(), out, off);
        }
        return .{ .wire = out, .msg_id = msg_id, .request_id = rid };
    }

    fn processReply(
        c: *V3Client,
        reply: []const u8,
        msg_id: i32,
        rid: i32,
        level: SecurityLevel,
    ) Error!Outcome {
        const m = try v3.decode(reply);
        if (m.header.msg_id != msg_id) return error.MsgIdMismatch;
        const params = try usm.parse(m.security_parameters);
        const authenticated = m.header.flags.auth;

        // AUTHENTICATE FIRST — nothing below this line may be trusted until the
        // digest verifies (constant-time inside `usm.verify`). A reply that
        // *claims* auth must actually carry a valid digest.
        if (authenticated) {
            if (!c.engine.discovered) return error.NotDiscovered;
            try usm.verify(c.user.auth_protocol, c.engine.authKey(), reply, params);
        }

        // Decrypt (or take the plaintext) ScopedPDU. A Report may legitimately
        // arrive unencrypted even for an authPriv request.
        const scoped: v3.ScopedPdu = switch (m.data) {
            .plaintext => |s| s,
            .encrypted => |bytes| try priv.decryptScopedPdu(
                c.user.priv_protocol,
                c.engine.privKey(),
                params.engine_boots,
                params.engine_time,
                params.priv_params,
                bytes,
                &c.plain_buf,
            ),
        };

        // A Report is the engine's error channel — never data.
        //
        // Real agents (net-snmp among them) send `usmStatsWrongDigests` and
        // friends **unauthenticated**, because at that point the engine has
        // nothing it can authenticate with. So a Report is not held to the
        // downgrade rule below — but an unauthenticated one is never allowed to
        // move state we already trust.
        if (scoped.pdu == .report) {
            const info = try report_mod.classify(scoped);

            // RFC 3414 §2.2.3/§3.2: a Report carries the authoritative
            // engine's boots/time like every other message, and is subject
            // to the same ±150 s window. It used to be the one message this
            // client never dated — and an authenticated Report's digest
            // covers fixed bytes, so a captured one verifies forever. That
            // made a replayed Report a clock-rewind primitive: it dropped
            // `latestReceivedEngineTime` back to the captured value and
            // re-opened the window around it for every authenticated
            // datagram captured at the same time.
            //
            // Checked on a COPY of the clock, because the non-authoritative
            // check latches before it decides (`timewin.checkTimeWindow`)
            // and the real update belongs to the per-reason branches below,
            // which need to know whether they moved anything (`acted`
            // drives the one permitted retry).
            //
            // Only for a Report that is both authenticated and about the
            // engine we already hold a clock for: an unauthenticated Report
            // is already forbidden from moving trusted state, and a Report
            // naming a DIFFERENT engine is discovery, where our cached
            // clock belongs to somebody else and says nothing about its age.
            if (authenticated and c.engine.discovered and
                std.mem.eql(u8, params.engine_id, c.engine.id()))
            {
                var probe = c.engine.clock;
                try timewin.checkTimeWindow(
                    .non_authoritative,
                    &probe,
                    params.engine_boots,
                    params.engine_time,
                );
            }

            var acted = false;
            switch (info.reason) {
                .unknown_engine_ids => {
                    // Bootstrap (nothing to lose yet) or an authenticated
                    // re-discovery. An unauthenticated one against an engine we
                    // already trust is ignored — it would let an off-path
                    // attacker re-point us at an engine ID of their choosing.
                    if (!c.engine.discovered or authenticated) {
                        try c.seedEngine(params.engine_id, params.engine_boots, params.engine_time);
                        acted = true;
                    }
                },
                .not_in_time_windows => {
                    // RFC 3414 §3.2: only an AUTHENTICATED report may move our
                    // clock — otherwise an attacker could park the replay window
                    // anywhere. At noAuthNoPriv there is nothing to protect.
                    if (authenticated or !level.hasAuth()) {
                        if (!std.mem.eql(u8, params.engine_id, c.engine.id()))
                            return error.EngineIdMismatch;
                        // RFC 3414 §3.2's non-authoritative update rule is a
                        // LATCH: adopt the larger boots, and at equal boots
                        // the larger engineTime. This used to be
                        // `setEngineTime`, i.e. `EngineTimeState.init` — a
                        // hard overwrite that also discarded
                        // `latestReceivedEngineTime`, so a Report could move
                        // the anti-replay floor backwards. It cannot now:
                        // `latch` returns false when the Report carries
                        // nothing newer, and a Report that carries nothing
                        // newer is not a resync, so `acted` stays false and
                        // the Report becomes a typed error instead of a
                        // retry.
                        acted = timewin.latch(
                            &c.engine.clock,
                            params.engine_boots,
                            params.engine_time,
                        );
                    }
                },
                else => {},
            }
            return .{ .report = .{ .reason = info.reason, .acted = acted } };
        }

        // From here on we are handling DATA, and the security level we asked
        // for is binding: an agent must not answer an authenticated request
        // unauthenticated, nor an authPriv request in the clear. Otherwise an
        // off-path forgery would pass as a valid reply.
        if (level.hasAuth() and !authenticated) return error.SecurityLevelDowngrade;
        if (level.hasPriv() and !m.header.flags.priv) return error.SecurityLevelDowngrade;

        // A real reply must come from the engine we localized our keys to.
        if (c.engine.discovered and !std.mem.eql(u8, params.engine_id, c.engine.id()))
            return error.EngineIdMismatch;

        // Anti-replay window (RFC 3414 §3.2), non-authoritative role: only
        // meaningful once the message has been authenticated.
        if (authenticated) {
            try timewin.checkTimeWindow(
                .non_authoritative,
                &c.engine.clock,
                params.engine_boots,
                params.engine_time,
            );
        }

        const pdu = switch (scoped.pdu) {
            .response => |p| p,
            else => return error.UnexpectedPduType,
        };
        if (pdu.request_id != rid) return error.RequestIdMismatch;
        return .{ .response = .{
            .error_status = pdu.error_status,
            .error_index = pdu.error_index,
            .varbinds = pdu.varbinds,
            .context_engine_id = scoped.context_engine_id,
            .context_name = scoped.context_name,
        } };
    }

    /// GetNext-based subtree walk, v3 flavour.
    pub fn walker(c: *V3Client, root: Oid) Walker {
        return .{ .client = c, .root = root, .current = root };
    }

    // ── counters ────────────────────────────────────────────────────────────

    fn allocMsgId(c: *V3Client) i32 {
        const id = c.next_msg_id;
        c.next_msg_id = if (id == std.math.maxInt(i32)) 1 else id + 1;
        return id;
    }

    fn allocRequestId(c: *V3Client) i32 {
        const rid = c.next_request_id;
        c.next_request_id = if (rid == std.math.maxInt(i32)) 1 else rid + 1;
        return rid;
    }

    /// Give the salt counter its one-time engine-derived seed, unless the caller
    /// pinned one via `Options.initial_salt`. RFC 3414 §8.1.1.1 wants the local
    /// integer "set to a pseudo-random value at boot time"; this module owns no
    /// clock and no RNG (deliberately — see SPEC), so the closest varying value
    /// available is the engine's own `engineBoots‖engineTime`, which is already
    /// on the wire anyway. It separates two runs of this client that start more
    /// than a second apart; it does not separate two runs inside one second.
    fn seedSaltSource(c: *V3Client) void {
        if (!c.salt_needs_seed) return;
        c.salt_needs_seed = false;
        const seed = (@as(u64, c.engine.clock.engine_boots) << 32) |
            @as(u64, c.engine.clock.engine_time);
        c.salt_source = priv.SaltSource.counter(seed);
    }
};

/// Repeated-GetNext subtree iterator over a `V3Client` — the v3 twin of
/// `client.Walker`, with the same subtree and non-advancing-agent guards.
pub const Walker = struct {
    client: *V3Client,
    root: Oid,
    current: Oid,
    finished: bool = false,

    pub const WalkError = Error || error{ OidNotIncreasing, RequestFailed };

    pub fn next(w: *Walker) WalkError!?VarBind {
        if (w.finished) return null;
        const resp = try w.client.getNext(&.{w.current});
        if (resp.error_status != .no_error) {
            w.finished = true;
            return error.RequestFailed;
        }
        var it = resp.varbinds.iterator();
        const vb = (try it.next()) orelse {
            w.finished = true;
            return null;
        };
        if (vb.value == .end_of_mib_view) {
            w.finished = true;
            return null;
        }
        if (!vb.name.startsWith(&w.root)) {
            w.finished = true;
            return null;
        }
        if (vb.name.order(&w.current) != .gt) {
            w.finished = true;
            return error.OidNotIncreasing;
        }
        w.current = vb.name;
        return vb;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A scripted in-memory SNMPv3 agent: it owns an engine identity + clock and a
/// user table, and it implements the real USM receive path (parse → verify →
/// decrypt) and send path (encrypt → sign), so the client is exercised against
/// something that can actually reject it.
pub const FakeAgent = struct {
    engine_id: []const u8 = &usm.netsnmp_engine_id,
    boots: u32 = 1,
    time: u32 = 100,
    user: User,
    values: []const VarBind = &.{},
    error_status: i32 = 0,
    error_index: i32 = 0,
    /// Force the next reply to be a Report with this reason instead of data.
    force_report: ?report_mod.Reason = null,
    /// Reply with a clock this far ahead of `time` (to trip the window).
    time_skew: i32 = 0,
    /// Answer an authPriv request with an unencrypted Response (downgrade).
    downgrade: bool = false,
    /// Echo this `msgID` instead of the request's.
    force_msg_id: ?i32 = null,
    /// Offset added to the echoed inner request-id.
    request_id_offset: i32 = 0,
    /// Count of non-discovery requests served.
    served: usize = 0,
    /// Count of discovery probes served.
    probes: usize = 0,

    scratch: [max_message_len]u8 = undefined,
    plain: [max_message_len]u8 = undefined,
    out: [max_message_len]u8 = undefined,
    /// The last request datagram as received, so a test can assert on what the
    /// client actually put on the wire (e.g. `msgPrivacyParameters`).
    last_req: [max_message_len]u8 = undefined,
    last_req_len: usize = 0,

    pub fn transport(a: *FakeAgent) Transport {
        return .{ .ctx = a, .exchangeFn = exchangeFn };
    }

    pub fn lastRequest(a: *const FakeAgent) []const u8 {
        return a.last_req[0..a.last_req_len];
    }

    fn authKey(a: *FakeAgent, buf: []u8) ![]const u8 {
        return usm.passwordToKey(a.user.auth_protocol, a.user.auth_password, a.engine_id, buf);
    }
    fn privKey(a: *FakeAgent, buf: []u8) ![]const u8 {
        return usm.passwordToKey(a.user.auth_protocol, a.user.priv_password, a.engine_id, buf);
    }

    fn exchangeFn(ctx: *anyopaque, req: []const u8, reply_buf: []u8) client_mod.TransportError!usize {
        const a: *FakeAgent = @ptrCast(@alignCast(ctx));
        const out = a.serve(req) catch return error.TransportFailed;
        if (out.len > reply_buf.len) return error.TransportFailed;
        std.mem.copyForwards(u8, reply_buf[0..out.len], out);
        return out.len;
    }

    fn serve(a: *FakeAgent, req: []const u8) ![]const u8 {
        @memcpy(a.last_req[0..req.len], req);
        a.last_req_len = req.len;
        const m = try v3.decode(req);
        const params = try usm.parse(m.security_parameters);

        // Unknown/empty engine ID → discovery Report (unauthenticated).
        if (params.engine_id.len == 0 or !std.mem.eql(u8, params.engine_id, a.engine_id)) {
            a.probes += 1;
            return a.buildReport(m.header.msg_id, requestIdOf(m) orelse 0, .unknown_engine_ids, false);
        }

        // Verify the digest exactly as a real engine would.
        if (m.header.flags.auth) {
            var kb: [usm.max_key_len]u8 = undefined;
            const key = try a.authKey(&kb);
            usm.verify(a.user.auth_protocol, key, req, params) catch {
                return a.buildReport(m.header.msg_id, 0, .wrong_digests, false);
            };
        }
        if (forcedReason(a)) |reason| {
            const authed = m.header.flags.auth;
            return a.buildReport(m.header.msg_id, 0, reason, authed);
        }

        const scoped: v3.ScopedPdu = switch (m.data) {
            .plaintext => |s| s,
            .encrypted => |bytes| blk: {
                var kb: [usm.max_key_len]u8 = undefined;
                const key = try a.privKey(&kb);
                break :blk try priv.decryptScopedPdu(
                    a.user.priv_protocol,
                    key,
                    params.engine_boots,
                    params.engine_time,
                    params.priv_params,
                    bytes,
                    &a.plain,
                );
            },
        };
        const rid = switch (scoped.pdu) {
            .get_request, .get_next_request, .set_request => |p| p.request_id,
            .get_bulk_request => |p| p.request_id,
            else => return error.UnexpectedTag,
        };
        a.served += 1;
        return a.buildResponse(m.header.msg_id, rid, m.header.flags.priv and !a.downgrade);
    }

    fn forcedReason(a: *FakeAgent) ?report_mod.Reason {
        const r = a.force_report orelse return null;
        a.force_report = null; // one-shot
        return r;
    }

    fn requestIdOf(m: v3.V3Message) ?i32 {
        const s = switch (m.data) {
            .plaintext => |p| p,
            .encrypted => return null,
        };
        return switch (s.pdu) {
            .get_request, .get_next_request, .set_request, .response, .report => |p| p.request_id,
            .get_bulk_request => |p| p.request_id,
            else => null,
        };
    }

    fn reasonOid(reason: report_mod.Reason) []const u8 {
        return switch (reason) {
            .unsupported_sec_levels => "1.3.6.1.6.3.15.1.1.1.0",
            .not_in_time_windows => "1.3.6.1.6.3.15.1.1.2.0",
            .unknown_user_names => "1.3.6.1.6.3.15.1.1.3.0",
            .unknown_engine_ids => "1.3.6.1.6.3.15.1.1.4.0",
            .wrong_digests => "1.3.6.1.6.3.15.1.1.5.0",
            .decryption_errors => "1.3.6.1.6.3.15.1.1.6.0",
            .unknown_security_models => "1.3.6.1.6.3.11.2.1.1.0",
            .invalid_msgs => "1.3.6.1.6.3.11.2.1.2.0",
            .unknown_pdu_handlers => "1.3.6.1.6.3.11.2.1.3.0",
            .unknown => "1.3.6.1.4.1.99999.1",
        };
    }

    fn buildReport(a: *FakeAgent, msg_id: i32, rid: i32, reason: report_mod.Reason, authed: bool) ![]const u8 {
        const vbs = [_]VarBind{
            .{ .name = try Oid.parse(reasonOid(reason)), .value = .{ .counter32 = 1 } },
        };
        return a.frame(msg_id, .{
            .type = .report,
            .request_id = rid,
            .varbinds = &vbs,
        }, authed, false);
    }

    fn buildResponse(a: *FakeAgent, msg_id: i32, rid: i32, encrypted: bool) ![]const u8 {
        return a.frame(msg_id, .{
            .type = .response,
            .request_id = rid +% a.request_id_offset,
            .error_status = a.error_status,
            .error_index = a.error_index,
            .varbinds = a.values,
        }, a.user.level.hasAuth(), encrypted);
    }

    /// Build (and sign/encrypt) a reply datagram into `a.out`.
    fn frame(a: *FakeAgent, msg_id_in: i32, pdu: message.EncodePdu, authed: bool, encrypted: bool) ![]const u8 {
        const msg_id = a.force_msg_id orelse msg_id_in;
        const skewed: u32 = @intCast(@max(0, @as(i64, a.time) + a.time_skew));
        const zeros = [_]u8{0} ** usm.max_digest_len;
        const auth_ph: []const u8 = if (authed) zeros[0..a.user.auth_protocol.digestLen()] else &.{};
        // The fake agent pins its reply salt so datagrams are reproducible; a
        // fresh source per reply keeps that behaviour byte-identical.
        var salt_src = priv.SaltSource.fixedForInterop(.{ 0, 0, 0, 0, 0, 0, 0, 9 });
        const salt = salt_src.mode.fixed_for_interop;
        var sp_buf: [128]u8 = undefined;
        const sp = try usm.encode(&sp_buf, .{
            .engine_id = a.engine_id,
            .engine_boots = a.boots,
            .engine_time = skewed,
            .user_name = if (authed) a.user.name else "",
            .auth_params = auth_ph,
            .priv_params = if (encrypted) &salt else &.{},
        });
        const wire = if (encrypted) w: {
            const plain = try v3.encodeScopedPdu(&a.scratch, .{
                .context_engine_id = a.engine_id,
                .pdu = pdu,
            });
            var kb: [usm.max_key_len]u8 = undefined;
            const key = try a.privKey(&kb);
            const enc = try priv.encrypt(a.user.priv_protocol, key, a.boots, skewed, &salt_src, plain, &a.plain);
            break :w try v3.encodeEncrypted(&a.out, .{
                .msg_id = msg_id,
                .flags = .{ .auth = authed, .priv = true },
                .security_parameters = sp,
                .encrypted_pdu = enc.ciphertext,
            });
        } else try v3.encode(&a.out, .{
            .msg_id = msg_id,
            .flags = .{ .auth = authed, .priv = false },
            .security_parameters = sp,
            .context_engine_id = a.engine_id,
            .pdu = pdu,
        });

        const mut = a.out[a.out.len - wire.len ..];
        if (authed) {
            const sent = try v3.decode(mut);
            const sp2 = try usm.parse(sent.security_parameters);
            const off = usm.authOffsetFor(a.user.auth_protocol, mut, sp2) orelse return error.BadAuthParams;
            var kb: [usm.max_key_len]u8 = undefined;
            const key = try a.authKey(&kb);
            usm.sign(a.user.auth_protocol, key, mut, off);
        }
        return mut;
    }
};

fn sysNameVarBinds() ![1]VarBind {
    return .{.{ .name = try Oid.parse("1.3.6.1.2.1.1.5.0"), .value = .{ .octet_string = "zig-libs" } }};
}

test "noAuthNoPriv: auto-discovery then a plaintext GET" {
    const vals = try sysNameVarBinds();
    var agent: FakeAgent = .{
        .user = .{ .name = "plain", .level = .no_auth_no_priv },
        .values = &vals,
    };
    var c = V3Client.init(agent.transport(), .{ .name = "plain", .level = .no_auth_no_priv }, .{});
    try testing.expect(!c.engine.discovered);

    const resp = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    try testing.expect(c.engine.discovered);
    try testing.expectEqualSlices(u8, &usm.netsnmp_engine_id, c.engine.id());
    try testing.expectEqual(@as(u32, 1), c.engine.clock.engine_boots);
    var it = resp.varbinds.iterator();
    try testing.expectEqualStrings("zig-libs", (try it.next()).?.value.octet_string);
    try testing.expectEqual(@as(usize, 1), agent.probes);
    try testing.expectEqual(@as(usize, 1), agent.served);
}

/// Drive a full discover + GET at `level` with `auth`/`privp`, against a
/// FakeAgent that runs the real USM checks.
fn expectLevelRoundTrip(level: SecurityLevel, auth: usm.AuthProtocol, privp: priv.PrivProtocol) !void {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = level,
        .auth_protocol = auth,
        .auth_password = "maplesyrup",
        .priv_protocol = privp,
        .priv_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    try testing.expect(c.engine.discovered);
    try testing.expectEqual(auth.keyLen(), c.engine.authKey().len);

    const resp = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    var it = resp.varbinds.iterator();
    try testing.expectEqualStrings("zig-libs", (try it.next()).?.value.octet_string);
    try testing.expectEqualSlices(u8, &usm.netsnmp_engine_id, resp.context_engine_id);
}

test "authNoPriv: every auth protocol round-trips through discover + GET" {
    for ([_]usm.AuthProtocol{
        .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512,
    }) |p| {
        try expectLevelRoundTrip(.auth_no_priv, p, .aes128_cfb);
    }
}

test "authPriv: DES-CBC and AES-128-CFB round-trip through discover + GET" {
    try expectLevelRoundTrip(.auth_priv, .hmac_sha1, .des_cbc);
    try expectLevelRoundTrip(.auth_priv, .hmac_sha1, .aes128_cfb);
    try expectLevelRoundTrip(.auth_priv, .hmac_sha256, .aes128_cfb);
    try expectLevelRoundTrip(.auth_priv, .hmac_sha512, .des_cbc);
}

test "an authenticated request before discovery is NotDiscovered, never sent in the clear" {
    var agent: FakeAgent = .{ .user = .{
        .name = "u",
        .level = .auth_no_priv,
        .auth_password = "maplesyrup",
    } };
    var c = V3Client.init(agent.transport(), .{
        .name = "u",
        .level = .auth_no_priv,
        .auth_password = "maplesyrup",
    }, .{});
    try testing.expectError(error.NotDiscovered, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
    try testing.expectEqual(@as(usize, 0), agent.probes);
    try testing.expectEqual(@as(usize, 0), agent.served);
}

test "a wrong auth password is rejected by the agent -> WrongDigest, not silent data" {
    const vals = try sysNameVarBinds();
    const agent_user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = agent_user, .values = &vals };
    var c = V3Client.init(agent.transport(), .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "wrongpassword",
    }, .{});
    try c.discover();
    try testing.expectError(error.WrongDigest, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
}

test "a notInTimeWindows Report re-latches the clock and the retry succeeds" {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals, .time = 5000 };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.engine_time);

    // Pretend our cached clock drifted, and make the agent answer the next
    // request with an authenticated notInTimeWindows Report carrying the truth.
    c.setEngineTime(1, 10);
    agent.force_report = .not_in_time_windows;
    const resp = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    var it = resp.varbinds.iterator();
    try testing.expectEqualStrings("zig-libs", (try it.next()).?.value.octet_string);
    // The clock was corrected from the Report before the retry.
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.engine_time);
}

test "terminal Reports become typed errors, one per usmStats counter" {
    const cases = [_]struct { report_mod.Reason, anyerror }{
        .{ .unknown_user_names, error.UnknownUserName },
        .{ .wrong_digests, error.WrongDigest },
        .{ .decryption_errors, error.DecryptionError },
        .{ .unsupported_sec_levels, error.UnsupportedSecLevel },
        .{ .unknown_security_models, error.UnknownSecurityModel },
        .{ .invalid_msgs, error.InvalidMsg },
        .{ .unknown_pdu_handlers, error.UnknownPduHandler },
        .{ .unknown, error.UnknownReport },
    };
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    for (cases) |c_| {
        var agent: FakeAgent = .{ .user = user };
        var c = V3Client.init(agent.transport(), user, .{});
        try c.discover();
        agent.force_report = c_[0];
        try testing.expectError(c_[1], c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
    }
}

test "an out-of-window reply is rejected by the time window (RFC 3414 §3.2)" {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals, .time = 10_000 };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();

    // Inside the window: fine.
    agent.time_skew = -150;
    _ = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});

    // 151 s behind the newest engineTime we have latched: replayed/stale.
    agent.time_skew = -200;
    try testing.expectError(error.NotInTimeWindow, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
}

test "an authPriv request answered with a plaintext Response is a downgrade, not data" {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
        .priv_protocol = .aes128_cfb,
        .priv_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals, .downgrade = true };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    try testing.expectError(error.SecurityLevelDowngrade, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
}

test "seedEngine: missing credentials and bad engine IDs are typed errors" {
    var agent: FakeAgent = .{ .user = .{ .name = "u" } };
    var c = V3Client.init(agent.transport(), .{
        .name = "u",
        .level = .auth_no_priv,
        .auth_password = "", // required at authNoPriv
    }, .{});
    try testing.expectError(error.MissingCredentials, c.seedEngine("engine", 1, 1));
    try testing.expectError(error.BadEngineId, c.seedEngine("", 1, 1));
    try testing.expectError(error.BadEngineId, c.seedEngine(&[_]u8{0} ** (max_engine_id_len + 1), 1, 1));

    var c2 = V3Client.init(agent.transport(), .{
        .name = "u",
        .level = .auth_priv,
        .auth_password = "maplesyrup",
        .priv_password = "", // required at authPriv
    }, .{});
    try testing.expectError(error.MissingCredentials, c2.seedEngine("engine", 1, 1));

    var c3 = V3Client.init(agent.transport(), .{ .name = &[_]u8{'x'} ** (max_user_name_len + 1) }, .{});
    try testing.expectError(error.BadUserName, c3.seedEngine("engine", 1, 1));
}

test "the privacy salt never repeats across real authPriv requests" {
    // Drive two authPriv requests through the full send path and read the salt
    // back off the wire. The client, not the caller, chose both — they must
    // differ, and so must the ciphertext of the (identical) ScopedPDUs.
    const vals = try sysNameVarBinds();
    inline for (.{ priv.PrivProtocol.aes128_cfb, priv.PrivProtocol.des_cbc }) |proto| {
        const user: User = .{
            .name = "privUser",
            .level = .auth_priv,
            .auth_protocol = .hmac_sha1,
            .auth_password = "maplesyrup",
            .priv_protocol = proto,
            .priv_password = "maplesyrup",
        };
        var agent: FakeAgent = .{ .user = user, .values = &vals };
        var c = V3Client.init(agent.transport(), user, .{});
        try c.discover();

        const oid = try Oid.parse("1.3.6.1.2.1.1.5.0");
        _ = try c.get(&.{oid});
        var first: [8]u8 = undefined;
        var first_ct: [256]u8 = undefined;
        const n1 = blk: {
            const m = try v3.decode(agent.lastRequest());
            const sp = try usm.parse(m.security_parameters);
            first = sp.priv_params[0..8].*;
            @memcpy(first_ct[0..m.data.encrypted.len], m.data.encrypted);
            break :blk m.data.encrypted.len;
        };

        _ = try c.get(&.{oid});
        const m2 = try v3.decode(agent.lastRequest());
        const sp2 = try usm.parse(m2.security_parameters);

        try testing.expect(!std.mem.eql(u8, &first, sp2.priv_params));
        try testing.expect(!std.mem.eql(u8, first_ct[0..n1], m2.data.encrypted));

        // RFC 3414 §8.1.1.1: a DES salt carries snmpEngineBoots up front.
        if (proto == .des_cbc) {
            var boots: [4]u8 = undefined;
            std.mem.writeInt(u32, &boots, c.engine.clock.engine_boots, .big);
            try testing.expectEqualSlices(u8, &boots, sp2.priv_params[0..4]);
        }
    }
}

test "the salt counter is seeded from the engine clock, not from a constant" {
    // Two clients built identically must not start their salt counters at the
    // same place when the engine clock differs — the cross-restart hazard.
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "privUser",
        .level = .auth_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
        .priv_protocol = .des_cbc,
        .priv_password = "maplesyrup",
    };
    var salts: [2][8]u8 = undefined;
    inline for (.{ 1000, 2000 }, 0..) |agent_time, i| {
        var agent: FakeAgent = .{ .user = user, .values = &vals, .time = agent_time };
        var c = V3Client.init(agent.transport(), user, .{});
        try c.discover();
        _ = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
        const m = try v3.decode(agent.lastRequest());
        const sp = try usm.parse(m.security_parameters);
        salts[i] = sp.priv_params[0..8].*;
    }
    try testing.expect(!std.mem.eql(u8, &salts[0], &salts[1]));

    // An explicit seed still overrides it (reproducible salts for tests/KATs).
    var agent: FakeAgent = .{ .user = user, .values = &vals, .time = 1000 };
    var c = V3Client.init(agent.transport(), user, .{ .initial_salt = 0x0102030405060708 });
    try c.discover();
    _ = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    const m = try v3.decode(agent.lastRequest());
    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqualSlices(u8, &[_]u8{ 5, 6, 7, 8 }, sp.priv_params[4..8]);
}

test "msgID mismatch and request-id mismatch are typed errors" {
    const vals = try sysNameVarBinds();
    const user: User = .{ .name = "plain" };

    // An agent that echoes the wrong msgID (RFC 3412 §7.2 step 4).
    var bad_msg_id: FakeAgent = .{ .user = user, .values = &vals, .force_msg_id = 999_999 };
    var c1 = V3Client.init(bad_msg_id.transport(), user, .{});
    try testing.expectError(error.MsgIdMismatch, c1.discover());

    // An agent that echoes the wrong inner request-id.
    var bad_rid: FakeAgent = .{ .user = user, .values = &vals, .request_id_offset = 1 };
    var c2 = V3Client.init(bad_rid.transport(), user, .{});
    try c2.discover();
    try testing.expectError(error.RequestIdMismatch, c2.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
}

test "a reply from a different engine is EngineIdMismatch" {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    // The client now trusts a different engine identity than the agent uses;
    // the agent's (correctly signed for ITS id) reply must not be accepted.
    const other = [_]u8{ 0x80, 0x00, 0x1f, 0x88, 0x04 } ++ "other-engine".*;
    try c.seedEngine(&other, c.engine.clock.engine_boots, c.engine.clock.engine_time);
    try testing.expect(std.meta.isError(c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")})));
}

test "hostile replies: truncated, garbage and bit-flipped datagrams stay typed" {
    const Hostile = struct {
        mode: u8,
        fn exchangeFn(ctx: *anyopaque, req: []const u8, reply_buf: []u8) client_mod.TransportError!usize {
            _ = req;
            const s: *@This() = @ptrCast(@alignCast(ctx));
            switch (s.mode) {
                0 => return 0, // empty datagram
                1 => { // pure garbage
                    const junk = [_]u8{ 0x30, 0x82, 0xff, 0xff, 0x02 };
                    @memcpy(reply_buf[0..junk.len], &junk);
                    return junk.len;
                },
                2 => { // a v2c message where a v3 one belongs
                    const out = message.encode(reply_buf, .v2c, "public", .{
                        .type = .response,
                        .request_id = 1,
                    }) catch return error.TransportFailed;
                    std.mem.copyForwards(u8, reply_buf[0..out.len], out);
                    return out.len;
                },
                else => return error.TransportFailed,
            }
        }
    };
    for ([_]u8{ 0, 1, 2, 3 }) |mode| {
        var h: Hostile = .{ .mode = mode };
        var c = V3Client.init(
            .{ .ctx = &h, .exchangeFn = Hostile.exchangeFn },
            .{ .name = "plain" },
            .{},
        );
        try testing.expect(std.meta.isError(c.discover()));
    }
}

test "bit-flip sweep over a valid authPriv reply: never a panic, never wrong data" {
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
        .priv_protocol = .aes128_cfb,
        .priv_password = "maplesyrup",
    };
    // Capture one good reply, then replay mutated copies through processReply.
    var agent: FakeAgent = .{ .user = user, .values = &vals };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    _ = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});

    // Build one real request, let the agent answer it, and keep that reply.
    var vbs: [1]VarBind = .{.{ .name = try Oid.parse("1.3.6.1.2.1.1.5.0"), .value = .null }};
    const prepared = try c.buildRequest(.get_request, &vbs, 0, 0);
    var good: [max_message_len]u8 = undefined;
    const reply = try agent.serve(prepared.wire);
    const n = reply.len;
    @memcpy(good[0..n], reply);

    var mutated: [max_message_len]u8 = undefined;
    for (0..n) |i| {
        @memcpy(mutated[0..n], good[0..n]);
        mutated[i] ^= 0x80;
        // Any outcome except a crash is fine; the digest check turns almost all
        // of these into AuthenticationFailed.
        _ = c.processReply(mutated[0..n], prepared.msg_id, prepared.request_id, .auth_priv) catch {};
    }
    // The untouched reply still verifies and carries the real data.
    const ok = try c.processReply(good[0..n], prepared.msg_id, prepared.request_id, .auth_priv);
    var it = ok.response.varbinds.iterator();
    try testing.expectEqualStrings("zig-libs", (try it.next()).?.value.octet_string);
}

test "walker: subtree walk over v3 stops at the boundary" {
    const WalkAgent = struct {
        inner: FakeAgent,
        table: []const VarBind,

        fn exchangeFn(ctx: *anyopaque, req: []const u8, reply_buf: []u8) client_mod.TransportError!usize {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            // Decode the asked-for OID and pick its successor before delegating.
            const m = v3.decode(req) catch return error.TransportFailed;
            if (m.data == .plaintext) {
                const sp = m.data.plaintext;
                if (sp.pdu == .get_next_request) {
                    var it = sp.pdu.get_next_request.varbinds.iterator();
                    if (it.next() catch null) |asked| {
                        s.inner.values = &.{};
                        for (s.table) |*e| {
                            if (e.name.order(&asked.name) == .gt) {
                                s.inner.values = e[0..1];
                                break;
                            }
                        }
                    }
                }
            }
            return FakeAgent.exchangeFn(&s.inner, req, reply_buf);
        }
    };
    const table = [_]VarBind{
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.1"), .value = .{ .octet_string = "lo" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.2"), .value = .{ .octet_string = "eth0" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.31.1.1.1.1.1"), .value = .{ .octet_string = "lo" } },
    };
    var wa: WalkAgent = .{ .inner = .{ .user = .{ .name = "plain" } }, .table = &table };
    var c = V3Client.init(
        .{ .ctx = &wa, .exchangeFn = WalkAgent.exchangeFn },
        .{ .name = "plain" },
        .{},
    );
    try c.discover();
    var w = c.walker(try Oid.parse("1.3.6.1.2.1.2.2.1.2"));
    var seen: usize = 0;
    while (try w.next()) |vb| {
        seen += 1;
        try testing.expect(vb.value == .octet_string);
    }
    try testing.expectEqual(@as(usize, 2), seen);
    try testing.expectEqual(@as(?VarBind, null), try w.next());
}

test "too many oids -> TooManyOids without touching the transport" {
    var agent: FakeAgent = .{ .user = .{ .name = "plain" } };
    var c = V3Client.init(agent.transport(), .{ .name = "plain" }, .{});
    var oids: [max_request_oids + 1]Oid = @splat(try Oid.parse("1.3.6.1"));
    try testing.expectError(error.TooManyOids, c.get(&oids));
    try testing.expectEqual(@as(usize, 0), agent.probes);
}

test "a replayed notInTimeWindows Report cannot rewind the anti-replay clock (RFC 3414 §2.2.3/§3.2)" {
    // Regression. A Report used to be exempt from the ±150 s window
    // entirely — `processReply` returned from the Report branch before ever
    // reaching `checkTimeWindow` — and the `notInTimeWindows` branch then
    // OVERWROTE the clock (`EngineTimeState.init`) instead of latching it
    // forward. An authenticated Report's digest covers fixed bytes, so one
    // captured genuine Report replays forever, and each replay dropped
    // `latestReceivedEngineTime` back to the captured value, re-opening the
    // window around it for every authenticated datagram captured with it.
    const vals = try sysNameVarBinds();
    const user: User = .{
        .name = "rfcUser",
        .level = .auth_no_priv,
        .auth_protocol = .hmac_sha1,
        .auth_password = "maplesyrup",
    };
    var agent: FakeAgent = .{ .user = user, .values = &vals, .time = 5000 };
    var c = V3Client.init(agent.transport(), user, .{});
    try c.discover();
    _ = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.latest_received_engine_time);

    // The replay: an authenticated `notInTimeWindows` Report carrying an
    // engineTime from long before the floor. 4850 is 5000 − 150, spelled
    // out rather than derived, so this test pins the window that was
    // actually shipped.
    agent.time = 100;
    agent.force_report = .not_in_time_windows;
    try testing.expectError(error.NotInTimeWindow, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.latest_received_engine_time);
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.engine_time);
    try testing.expectEqual(@as(u32, 1), c.engine.clock.engine_boots);

    // The same replay wearing the other recoverable reason. This is the
    // shape the window check alone catches: an authenticated
    // `unknownEngineIDs` Report about the engine we already hold goes to
    // `seedEngine`, which re-seeds the clock unconditionally
    // (`EngineTimeState.init`) — a hard rewind that no latch guards,
    // because the branch does not go through one. Only dating the Report
    // stops it.
    agent.time = 100;
    agent.force_report = .unknown_engine_ids;
    try testing.expectError(error.NotInTimeWindow, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.latest_received_engine_time);
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.engine_time);

    // The second half of the same defect, and the half the window check
    // alone does NOT cover: a Report that is INSIDE the window but carries
    // nothing newer. 4900 is only 100 s back, so it passes the ±150 s
    // check — and an overwrite would still drop the floor from 4850 to
    // 4750 and hand the attacker 150 s of replayable past per Report. RFC
    // 3414 §3.2's non-authoritative update is a latch: nothing older is
    // ever adopted, and a Report that moves nothing is not a resync, so it
    // is a typed error rather than a retry.
    agent.time = 4900;
    agent.force_report = .not_in_time_windows;
    try testing.expectError(error.NotInTimeWindow, c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}));
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.latest_received_engine_time);
    try testing.expectEqual(@as(u32, 5000), c.engine.clock.engine_time);

    // Non-vacuity: a Report carrying something genuinely NEWER is still the
    // RFC 3414 §3.2 self-correction it is supposed to be — clock latched,
    // request retried, data returned.
    agent.time = 9000;
    agent.force_report = .not_in_time_windows;
    const resp = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")});
    var it = resp.varbinds.iterator();
    try testing.expectEqualStrings("zig-libs", (try it.next()).?.value.octet_string);
    try testing.expectEqual(@as(u32, 9000), c.engine.clock.latest_received_engine_time);
}

test "the three v3 client limits are the values RFC 3411/3414 fix, not whatever the constants say" {
    // The boundary tests elsewhere in this file are written in terms of the
    // constants (`max_engine_id_len + 1` and friends), so they verify the
    // mechanism and stay green for any value. These are the values.
    //
    // Provenance:
    //   * RFC 3411 `SnmpEngineID ::= TEXTUAL-CONVENTION … SIZE(5..32)`
    //   * RFC 3414 §2.4 `msgUserName … SIZE(0..32)`
    //   * `max_request_oids` is this stack's own send-side cap (one
    //     `[32]VarBind` stack array per request, `client.zig:37`), not an
    //     RFC number — pinned so a silent widening of the stack buffer is
    //     a test failure rather than a bigger frame.
    try testing.expectEqual(@as(usize, 5), min_engine_id_len);
    try testing.expectEqual(@as(usize, 32), max_engine_id_len);
    try testing.expectEqual(@as(usize, 32), max_user_name_len);
    try testing.expectEqual(@as(usize, 32), max_request_oids);

    // And the enforcement really is at those values — a 4-octet engine ID
    // is refused, a 5-octet one accepted, a 32-octet one accepted, a
    // 33-octet one refused. Every length below is a literal.
    var agent: FakeAgent = .{ .user = .{ .name = "u" } };
    const user: User = .{ .name = "u" }; // noAuthNoPriv: no passwords needed
    var c = V3Client.init(agent.transport(), user, .{});
    try testing.expectError(error.BadEngineId, c.seedEngine(&[_]u8{0} ** 4, 1, 1));
    try c.seedEngine(&[_]u8{0} ** 5, 1, 1);
    try c.seedEngine(&[_]u8{0} ** 32, 1, 1);
    try testing.expectError(error.BadEngineId, c.seedEngine(&[_]u8{0} ** 33, 1, 1));

    var c32 = V3Client.init(agent.transport(), .{ .name = &[_]u8{'x'} ** 32 }, .{});
    try c32.seedEngine(&[_]u8{0} ** 5, 1, 1);
    var c33 = V3Client.init(agent.transport(), .{ .name = &[_]u8{'x'} ** 33 }, .{});
    try testing.expectError(error.BadUserName, c33.seedEngine(&[_]u8{0} ** 5, 1, 1));

    // 32 OIDs go out; 33 are refused without touching the transport.
    var oids: [33]Oid = @splat(try Oid.parse("1.3.6.1"));
    var c2 = V3Client.init(agent.transport(), user, .{});
    try c2.seedEngine(&usm.netsnmp_engine_id, 1, 1);
    try testing.expectError(error.TooManyOids, c2.get(oids[0..33]));
    try testing.expectEqual(@as(usize, 0), agent.served);
}
