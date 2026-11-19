// SPDX-License-Identifier: MIT

//! dnp3.secure_auth — Secure Authentication (IEEE 1815-2012 §7, SAv5
//! symmetric procedures) for the outstation, over the g120 codecs in `sa.zig`.
//!
//! Opt-in: an `Outstation` without a `SecureAuth` attached
//! (`Outstation.setSecureAuth`) never reaches this file and behaves exactly
//! as before. With one attached, every request fragment is screened here
//! before the outstation acts on it:
//!
//! - A **critical** request (function code in `Config.critical`) is not
//!   executed. It is stored, and the outstation answers AUTHENTICATE_RESPONSE
//!   (0x83) carrying a g120v1 Challenge with a fresh challenge sequence number
//!   (CSQ) and fresh challenge data. The master's AUTHENTICATE_REQUEST (0x20)
//!   carrying a g120v2 Reply is verified — CSQ, peer, user, then the MAC in
//!   constant time over `challenge message ‖ critical request` with that
//!   user's control-direction session key — and only then is the stored
//!   request executed. Any failure discards the stored request.
//! - **Aggressive mode**: a request whose first object is g120v3 and whose
//!   last object is g120v9 is verified in one step: CSQ = last CSQ + 1, user
//!   with valid session keys, MAC over `last challenge message ‖ request up to
//!   the g120v9 object` in constant time. Success executes the objects in
//!   between and advances the CSQ, so the same message cannot pass twice.
//! - **Session keys**: g120v4 (status request) is answered with g120v5
//!   carrying a new key-change sequence number (KSQ) and fresh challenge data,
//!   and opens a single key-change window for that user and KSQ; g120v6
//!   (key change) is accepted only inside that window, unwrapped with the
//!   user's update key (`sa.unwrapSessionKeys`, AES-KW) and confirmed by a
//!   g120v5 with status OK whose MAC is computed under the new
//!   monitoring-direction key over the received g120v6 object.
//! - **Errors**: a failed authentication is answered with a g120v7 Error
//!   (code 1, authentication failed) until `Config.max_error_messages` have
//!   been sent; after that the outstation stays silent until the next
//!   successful key change. `Statistics` counts every event.
//!
//! Bounded state: one outstanding challenge, one key-change window, one
//! stored critical request (in caller-owned storage). Clock-injected (`now_ms`
//! from the outstation), randomness injected (`RandomSource`), no I/O, no
//! allocation.
//!
//! Anchoring: no live peer with Secure Authentication was available (modern
//! opendnp3 dropped SA), so the tests anchor on vectors derived by hand from
//! the `sa.zig` primitives (which are KAT-exact), not on a foreign MAC.

const std = @import("std");
const sa = @import("sa.zig");
const application = @import("application.zig");

const FunctionCode = application.FunctionCode;
const Iin = application.Iin;

pub const Error = error{BufferTooSmall};

// ── critical function codes ─────────────────────────────────────────────────

/// A set of application function codes (256 bits).
pub const FunctionSet = struct {
    bits: [4]u64 = .{ 0, 0, 0, 0 },

    pub fn contains(self: FunctionSet, f: FunctionCode) bool {
        const v: u8 = @backingInt(f);
        return (self.bits[v >> 6] >> @intCast(v & 63)) & 1 == 1;
    }

    pub fn with(self: FunctionSet, f: FunctionCode) FunctionSet {
        var s = self;
        const v: u8 = @backingInt(f);
        s.bits[v >> 6] |= @as(u64, 1) << @intCast(v & 63);
        return s;
    }

    pub fn without(self: FunctionSet, f: FunctionCode) FunctionSet {
        var s = self;
        const v: u8 = @backingInt(f);
        s.bits[v >> 6] &= ~(@as(u64, 1) << @intCast(v & 63));
        return s;
    }

    pub fn of(fs: []const FunctionCode) FunctionSet {
        var s = FunctionSet{};
        for (fs) |f| s = s.with(f);
        return s;
    }

    /// The function codes this module treats as critical by default: every
    /// request that changes the outstation's outputs, configuration or
    /// running state (IEEE 1815-2012 §7, the "mandatory critical" rows as
    /// read for this module — see SPEC "Secure Authentication integration").
    /// READ, CONFIRM, the freezes, DELAY_MEASURE and RECORD_CURRENT_TIME are
    /// optional-critical in the standard and left out; add them with `with`.
    pub const default_critical: FunctionSet = of(&.{
        .write,              .select,                .operate,
        .direct_operate,     .direct_operate_no_ack, .cold_restart,
        .warm_restart,       .initialize_data,       .initialize_application,
        .start_application,  .stop_application,      .save_configuration,
        .enable_unsolicited, .disable_unsolicited,   .assign_class,
        .open_file,          .close_file,            .delete_file,
        .activate_config,
    });
};

/// Function codes that ask for no response. A challenge cannot be answered
/// to them (the master is not listening for one), so a critical no-ack
/// request is accepted only in aggressive mode and otherwise discarded.
fn isNoAck(f: FunctionCode) bool {
    return switch (f) {
        .direct_operate_no_ack, .immediate_freeze_no_ack, .freeze_clear_no_ack, .freeze_at_time_no_ack => true,
        else => false,
    };
}

// ── configuration and state ─────────────────────────────────────────────────

pub const Config = struct {
    /// MAC algorithm the outstation challenges with (HMAC only; AES-GMAC's IV
    /// derivation is out of scope, see `sa.zig`). The standard's default for
    /// networked links is HMAC-SHA-256 truncated to 16 octets.
    mac_algorithm: sa.HmacAlgorithm = .hmac_sha256_trunc_16,
    /// Key-wrap algorithm reported in g120v5; it fixes the update-key length
    /// (AES-128 → 16 octets, AES-256 → 32).
    key_wrap_algorithm: sa.KeyWrapAlgorithm = .aes_128,
    /// Which function codes are challenged.
    critical: FunctionSet = FunctionSet.default_critical,
    /// Accept aggressive-mode requests (g120v3 … g120v9).
    allow_aggressive_mode: bool = true,
    /// Octets of random challenge data per challenge / key status (4..64;
    /// 4 is the standard's minimum).
    challenge_len: u8 = 4,
    /// How long an outstanding challenge waits for its reply.
    reply_timeout_ms: u64 = 2_000,
    /// Session keys are invalidated after this long without a key change
    /// (twice the standard's 15-minute expected interval).
    session_key_timeout_ms: u64 = 2 * 15 * 60 * 1000,
    /// … or after this many authenticated messages (twice the expected
    /// count of 1000). 0 disables either axis.
    session_key_max_messages: u32 = 2 * 1000,
    /// g120v7 Error messages sent before the outstation falls silent (reset
    /// by a successful key change).
    max_error_messages: u32 = 2,
    /// User number written into outstation-issued challenges.
    challenge_user: u16 = 1,
    /// Association id written into g120v7.
    association_id: u16 = 0,
};

/// One user of the association: its long-lived update key (caller-owned)
/// and the session keys the master installed.
pub const User = struct {
    number: u16,
    update_key: []const u8,
    control_key: [32]u8 = @splat(0),
    monitoring_key: [32]u8 = @splat(0),
    key_len: u8 = 0,
    status: sa.KeyStatus = .not_init,
    keys_set_at_ms: u64 = 0,
    messages: u32 = 0,

    fn invalidate(self: *User, status: sa.KeyStatus) void {
        std.crypto.secureZero(u8, &self.control_key);
        std.crypto.secureZero(u8, &self.monitoring_key);
        self.key_len = 0;
        self.status = status;
        self.messages = 0;
    }
};

/// Caller-injected randomness for challenge data.
pub const RandomSource = struct {
    ctx: *anyopaque,
    fill: *const fn (ctx: *anyopaque, buf: []u8) void,
};

/// Security statistics (in memory; the g121/g122 wire objects are not
/// served, see SPEC Backlog).
pub const Statistics = struct {
    unexpected_messages: u32 = 0,
    authentication_failures: u32 = 0,
    reply_timeouts: u32 = 0,
    challenges_sent: u32 = 0,
    successful_authentications: u32 = 0,
    aggressive_mode_accepted: u32 = 0,
    discarded_messages: u32 = 0,
    error_messages_sent: u32 = 0,
    error_messages_received: u32 = 0,
    session_key_changes: u32 = 0,
    failed_session_key_changes: u32 = 0,
    session_key_status_requests: u32 = 0,
    session_keys_expired: u32 = 0,
};

/// What the outstation should do with a screened request.
pub const Decision = union(enum) {
    /// Not an SA matter: process the request as usual.
    pass,
    /// Send nothing.
    silent,
    /// Send this AUTHENTICATE_RESPONSE fragment (written into `out`).
    reply: []u8,
    /// Authenticated: execute `function` with `body`, answering with `seq`.
    execute: struct { function: FunctionCode, seq: u4, body: []const u8 },
};

pub const max_challenge_data = 64;
/// Response header + g120v1 object header + Challenge fixed part + data.
const max_challenge_message = application.response_header_len + sa.object_header_len + sa.Challenge.min_len + max_challenge_data;

pub const SecureAuth = struct {
    config: Config,
    users: []User,
    random: RandomSource,
    /// Holds the critical request awaiting its reply. A request longer than
    /// this is discarded rather than challenged.
    pending_storage: []u8,
    stats: Statistics = .{},

    /// Last CSQ sent in a challenge or accepted in aggressive mode.
    csq: u32 = 0,
    /// Last KSQ sent in a key status.
    ksq: u32 = 0,
    /// The last challenge message sent (whole application fragment); empty
    /// before the first challenge.
    challenge_buf: [max_challenge_message]u8 = undefined,
    challenge_len: usize = 0,
    pending: ?Pending = null,
    key_change: ?KeyChangeWindow = null,
    errors_sent: u32 = 0,

    pub const Pending = struct {
        csq: u32,
        request_len: usize,
        issued_at_ms: u64,
        peer: ?u16,
    };

    pub const KeyChangeWindow = struct {
        user: u16,
        ksq: u32,
        /// The g120v5 body that opened this window, exactly as sent. A key
        /// change must carry it inside its wrapped data
        /// (`sa.unwrapSessionKeysWithStatus`), which binds the change to
        /// this status's fresh challenge data.
        status: [max_status_body]u8,
        status_len: usize,
    };

    const max_status_body = sa.SessionKeyStatus.fixed_len + max_challenge_data + sa.mac.max_len;

    /// The key-status message a key change must wrap now (empty when no
    /// window is open). For a master-side caller and for tests.
    pub fn lastStatus(self: *const SecureAuth) []const u8 {
        const w = &(self.key_change orelse return &.{});
        return w.status[0..w.status_len];
    }

    pub fn init(config: Config, users: []User, random: RandomSource, pending_storage: []u8) SecureAuth {
        return .{ .config = config, .users = users, .random = random, .pending_storage = pending_storage };
    }

    /// `Config.challenge_len` clamped to 4..64 where it is used, so a
    /// config changed after `init` cannot index past the scratch.
    fn challengeLen(self: *const SecureAuth) usize {
        return std.math.clamp(self.config.challenge_len, 4, max_challenge_data);
    }

    fn macLen(self: *const SecureAuth) usize {
        return sa.mac.length(self.config.mac_algorithm);
    }

    fn findUser(self: *SecureAuth, number: u16) ?*User {
        for (self.users) |*u| {
            if (u.number == number) return u;
        }
        return null;
    }

    /// The user, if its session keys are installed and not expired. Expiry
    /// invalidates the keys on the spot (status COMM_FAIL).
    fn keyedUser(self: *SecureAuth, number: u16, now_ms: u64) ?*User {
        const u = self.findUser(number) orelse return null;
        self.expire(u, now_ms);
        if (u.status != .ok) return null;
        return u;
    }

    fn expire(self: *SecureAuth, u: *User, now_ms: u64) void {
        if (u.status != .ok) return;
        const by_time = self.config.session_key_timeout_ms != 0 and
            now_ms -% u.keys_set_at_ms >= self.config.session_key_timeout_ms;
        const by_count = self.config.session_key_max_messages != 0 and
            u.messages >= self.config.session_key_max_messages;
        if (by_time or by_count) {
            u.invalidate(.comm_fail);
            self.stats.session_keys_expired += 1;
        }
    }

    /// Screens one request fragment. `request` is the whole fragment,
    /// `function`/`seq`/`body` its decoded header and the bytes after it.
    pub fn screen(
        self: *SecureAuth,
        request: []const u8,
        function: FunctionCode,
        seq: u4,
        body: []const u8,
        peer: ?u16,
        now_ms: u64,
        iin: Iin,
        out: []u8,
    ) Error!Decision {
        if (self.pending) |p| {
            if (now_ms -% p.issued_at_ms >= self.config.reply_timeout_ms) {
                self.pending = null;
                self.stats.reply_timeouts += 1;
            }
        }
        switch (function) {
            .auth_request => return try self.onAuthRequest(seq, body, peer, now_ms, iin, out),
            .auth_request_no_ack => {
                const obj = sa.decodeObject(body) catch {
                    self.stats.unexpected_messages += 1;
                    return .silent;
                };
                if (obj.variation == .sa_error) {
                    self.stats.error_messages_received += 1;
                } else {
                    self.stats.unexpected_messages += 1;
                }
                return .silent;
            },
            else => {},
        }
        if (body.len >= 2 and body[0] == 120 and body[1] == @backingInt(sa.ObjectVariation.aggressive_mode_request)) {
            return try self.onAggressive(request, function, seq, body, now_ms, iin, out);
        }
        if (!self.config.critical.contains(function)) return .pass;
        return try self.challenge(request, function, seq, peer, now_ms, iin, out);
    }

    // ── challenge of a critical request ─────────────────────────────────────

    fn challenge(
        self: *SecureAuth,
        request: []const u8,
        function: FunctionCode,
        seq: u4,
        peer: ?u16,
        now_ms: u64,
        iin: Iin,
        out: []u8,
    ) Error!Decision {
        if (isNoAck(function) or request.len > self.pending_storage.len) {
            self.stats.discarded_messages += 1;
            return .silent;
        }
        // A new critical request replaces any outstanding challenge: there
        // is never more than one, and the old CSQ can no longer be answered.
        self.pending = null;
        var data: [max_challenge_data]u8 = undefined;
        const cd = data[0..self.challengeLen()];
        self.random.fill(self.random.ctx, cd);
        const csq = self.csq +% 1;
        var body: [sa.Challenge.min_len + max_challenge_data]u8 = undefined;
        const ch = (sa.Challenge{
            .challenge_seq_num = csq,
            .user_number = self.config.challenge_user,
            .mac_algorithm = self.config.mac_algorithm,
            .reason = .critical,
            .challenge_data = cd,
        }).encode(&body) catch unreachable;
        const frag = try authResponse(seq, iin, .challenge, ch, out);
        self.csq = csq;
        @memcpy(self.challenge_buf[0..frag.len], frag);
        self.challenge_len = frag.len;
        @memcpy(self.pending_storage[0..request.len], request);
        self.pending = .{ .csq = csq, .request_len = request.len, .issued_at_ms = now_ms, .peer = peer };
        self.stats.challenges_sent += 1;
        return .{ .reply = frag };
    }

    // ── AUTHENTICATE_REQUEST ────────────────────────────────────────────────

    fn onAuthRequest(self: *SecureAuth, seq: u4, body: []const u8, peer: ?u16, now_ms: u64, iin: Iin, out: []u8) Error!Decision {
        const obj = sa.decodeObject(body) catch {
            self.stats.unexpected_messages += 1;
            return .silent;
        };
        return switch (obj.variation) {
            .reply => try self.onReply(seq, obj.data, peer, now_ms, iin, out),
            .session_key_status_request => try self.onStatusRequest(seq, obj.data, now_ms, iin, out),
            .session_key_change => try self.onKeyChange(seq, obj.data, now_ms, iin, out),
            else => blk: {
                self.stats.unexpected_messages += 1;
                break :blk .silent;
            },
        };
    }

    fn onReply(self: *SecureAuth, seq: u4, data: []const u8, peer: ?u16, now_ms: u64, iin: Iin, out: []u8) Error!Decision {
        const p = self.pending orelse {
            self.stats.unexpected_messages += 1;
            return .silent;
        };
        const stored = self.pending_storage[0..p.request_len];
        const hdr = application.decodeRequestHeader(stored) catch unreachable; // validated when stored
        // A reply that does not name the outstanding exchange — another CSQ,
        // another application sequence number (the challenge, the reply and
        // the final response all carry the critical request's own, so a
        // SELECT authenticated this way is still followed by an OPERATE with
        // sequence + 1), another peer, or no decodable reply at all — is
        // ignored and leaves the challenge in place: it is not an answer to
        // it, and letting it cancel the exchange would hand any station a
        // one-message veto (review MEDIUM-2). It cannot pass either, so no
        // replay opens.
        const reply = sa.Reply.decode(data) catch {
            self.stats.unexpected_messages += 1;
            return .silent;
        };
        if (reply.challenge_seq_num != p.csq or seq != hdr.header.control.seq or !samePeer(peer, p.peer)) {
            self.stats.unexpected_messages += 1;
            return .silent;
        }
        // A reply that does name it consumes it, good or bad: a failed MAC
        // leaves nothing a second attempt could ride on.
        self.pending = null;
        const user = self.keyedUser(reply.user_number, now_ms) orelse
            return try self.fail(seq, reply.user_number, now_ms, iin, out);
        if (!sa.verifyReplyMac(
            self.config.mac_algorithm,
            user.control_key[0..user.key_len],
            self.challenge_buf[0..self.challenge_len],
            stored,
            reply.mac_value,
        )) return try self.fail(seq, reply.user_number, now_ms, iin, out);
        user.messages +|= 1;
        self.stats.successful_authentications += 1;
        return .{ .execute = .{ .function = hdr.header.function, .seq = seq, .body = hdr.rest } };
    }

    // ── aggressive mode ─────────────────────────────────────────────────────

    fn onAggressive(
        self: *SecureAuth,
        request: []const u8,
        function: FunctionCode,
        seq: u4,
        body: []const u8,
        now_ms: u64,
        iin: Iin,
        out: []u8,
    ) Error!Decision {
        const first = sa.decodeObject(body) catch return try self.fail(seq, 0, now_ms, iin, out);
        const amr = sa.AggressiveModeRequest.decode(first.data) catch return try self.fail(seq, 0, now_ms, iin, out);
        if (!self.config.allow_aggressive_mode or self.challenge_len == 0)
            return try self.fail(seq, amr.user_number, now_ms, iin, out);
        // The g120v9 object is the last one; its size is fixed by the MAC
        // algorithm, so its position is known without scanning the objects
        // in between.
        const mac_len = self.macLen();
        const tail = sa.object_header_len + mac_len;
        if (body.len < first.consumed + tail) return try self.fail(seq, amr.user_number, now_ms, iin, out);
        const mac_obj = sa.decodeObject(body[body.len - tail ..]) catch
            return try self.fail(seq, amr.user_number, now_ms, iin, out);
        if (mac_obj.variation != .aggregate_mac or mac_obj.consumed != tail)
            return try self.fail(seq, amr.user_number, now_ms, iin, out);
        if (amr.challenge_seq_num != self.csq +% 1)
            return try self.fail(seq, amr.user_number, now_ms, iin, out);
        const user = self.keyedUser(amr.user_number, now_ms) orelse
            return try self.fail(seq, amr.user_number, now_ms, iin, out);
        const covered = request[0 .. request.len - tail];
        if (!sa.mac.verifyTwo(
            self.config.mac_algorithm,
            user.control_key[0..user.key_len],
            self.challenge_buf[0..self.challenge_len],
            covered,
            mac_obj.data,
        )) return try self.fail(seq, amr.user_number, now_ms, iin, out);
        self.csq = amr.challenge_seq_num;
        self.pending = null;
        user.messages +|= 1;
        self.stats.aggressive_mode_accepted += 1;
        self.stats.successful_authentications += 1;
        return .{ .execute = .{ .function = function, .seq = seq, .body = body[first.consumed .. body.len - tail] } };
    }

    // ── session keys ────────────────────────────────────────────────────────

    fn onStatusRequest(self: *SecureAuth, seq: u4, data: []const u8, now_ms: u64, iin: Iin, out: []u8) Error!Decision {
        const req = sa.SessionKeyStatusRequest.decode(data) catch return try self.fail(seq, 0, now_ms, iin, out);
        self.stats.session_key_status_requests += 1;
        // An unknown user is answered like a known one without keys
        // (NOT_INIT, a window that no key change can pass), so the status
        // request does not tell an unauthenticated peer which users exist.
        const user = self.findUser(req.user_number) orelse
            return try self.keyStatus(seq, req.user_number, .not_init, &.{}, iin, out);
        self.expire(user, now_ms);
        return try self.keyStatus(seq, user.number, user.status, &.{}, iin, out);
    }

    fn onKeyChange(self: *SecureAuth, seq: u4, data: []const u8, now_ms: u64, iin: Iin, out: []u8) Error!Decision {
        // One window per key status sent; consumed by any key change.
        const w = self.key_change orelse {
            self.stats.unexpected_messages += 1;
            return .silent;
        };
        self.key_change = null;
        const kc = sa.SessionKeyChange.decode(data) catch return try self.fail(seq, 0, now_ms, iin, out);
        const user = self.findUser(w.user) orelse {
            self.stats.failed_session_key_changes += 1;
            return try self.keyStatus(seq, w.user, .auth_fail, &.{}, iin, out);
        };
        if (kc.key_change_seq_num != w.ksq or kc.user_number != w.user) {
            self.stats.failed_session_key_changes += 1;
            return try self.keyStatus(seq, w.user, .auth_fail, &.{}, iin, out);
        }
        const update_len: usize = switch (self.config.key_wrap_algorithm) {
            .aes_128 => 16,
            .aes_256 => 32,
            else => 0,
        };
        // The wrapped data must carry the very status that opened this window
        // (review MEDIUM-1): the KSQ alone restarts at 0 with the outstation
        // and any peer can step it with g120v4, so without the status's fresh
        // challenge data a recorded g120v6 would replay after a restart.
        var plain: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        const keys = if (user.update_key.len != update_len)
            null
        else
            sa.unwrapSessionKeysWithStatus(user.update_key, kc.wrapped_key_data, w.status[0..w.status_len], &plain) catch null;
        const k = keys orelse {
            self.stats.failed_session_key_changes += 1;
            return try self.keyStatus(seq, w.user, .auth_fail, &.{}, iin, out);
        };
        // The confirmation MAC (under the new monitoring key, over the
        // received g120v6) is computed BEFORE anything is installed: an
        // algorithm that cannot produce it refuses the change instead of
        // confirming it with an empty MAC.
        var mac_buf: [sa.mac.max_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &mac_buf);
        const confirm_mac = sa.mac.compute(self.config.mac_algorithm, k.monitoring_key, data, null, &mac_buf) catch {
            self.stats.failed_session_key_changes += 1;
            return try self.fail(seq, w.user, now_ms, iin, out);
        };
        const key_len = k.control_key.len;
        user.invalidate(.not_init);
        @memcpy(user.control_key[0..key_len], k.control_key);
        @memcpy(user.monitoring_key[0..key_len], k.monitoring_key);
        user.key_len = @intCast(key_len);
        user.status = .ok;
        user.keys_set_at_ms = now_ms;
        self.stats.session_key_changes += 1;
        self.errors_sent = 0;
        return try self.keyStatus(seq, w.user, .ok, confirm_mac, iin, out);
    }

    /// Sends a g120v5 with a new KSQ and fresh challenge data, and opens the
    /// key-change window for it. `mac_value` is the confirmation MAC of an
    /// accepted key change, empty otherwise.
    fn keyStatus(self: *SecureAuth, seq: u4, user: u16, status: sa.KeyStatus, mac_value: []const u8, iin: Iin, out: []u8) Error!Decision {
        var data: [max_challenge_data]u8 = undefined;
        const cd = data[0..self.challengeLen()];
        self.random.fill(self.random.ctx, cd);
        const ksq = self.ksq +% 1;
        var body: [max_status_body]u8 = undefined;
        const st = (sa.SessionKeyStatus{
            .key_change_seq_num = ksq,
            .user_number = user,
            .key_wrap_algorithm = self.config.key_wrap_algorithm,
            .key_status = status,
            .mac_algorithm = self.config.mac_algorithm,
            .challenge_data = cd,
            .mac_value = mac_value,
        }).encode(&body) catch unreachable;
        const frag = try authResponse(seq, iin, .session_key_status, st, out);
        self.ksq = ksq;
        var w: KeyChangeWindow = .{ .user = user, .ksq = ksq, .status = undefined, .status_len = st.len };
        @memcpy(w.status[0..st.len], st);
        self.key_change = w;
        return .{ .reply = frag };
    }

    // ── failure ─────────────────────────────────────────────────────────────

    /// A failed authentication: nothing executes; a g120v7 Error goes out
    /// while the error budget lasts.
    fn fail(self: *SecureAuth, seq: u4, user: u16, now_ms: u64, iin: Iin, out: []u8) Error!Decision {
        self.stats.authentication_failures += 1;
        if (self.errors_sent >= self.config.max_error_messages) return .silent;
        var body: [sa.SaError.min_len]u8 = undefined;
        const e = (sa.SaError{
            .sequence_number = self.csq,
            .user_number = user,
            .association_id = self.config.association_id,
            .error_code = .authentication_failed,
            .time_of_error = @truncate(now_ms),
            .error_text = &.{},
        }).encode(&body) catch unreachable;
        const frag = try authResponse(seq, iin, .sa_error, e, out);
        self.errors_sent += 1;
        self.stats.error_messages_sent += 1;
        return .{ .reply = frag };
    }
};

/// `null` (no peer named) equals only `null`, as for the outstation's
/// select-before-operate arm.
fn samePeer(a: ?u16, b: ?u16) bool {
    if (a) |x| return if (b) |y| x == y else false;
    return b == null;
}

/// Writes an AUTHENTICATE_RESPONSE (FIR+FIN, no CON) with one g120 object.
fn authResponse(seq: u4, iin: Iin, variation: sa.ObjectVariation, data: []const u8, out: []u8) Error![]u8 {
    const hdr = application.encodeResponseHeader(.{
        .control = .{ .fir = true, .fin = true, .seq = seq },
        .function = .auth_response,
        .iin = iin,
    }, out) catch return error.BufferTooSmall;
    const obj = sa.encodeObject(variation, data, out[hdr.len..]) catch return error.BufferTooSmall;
    return out[0 .. hdr.len + obj.len];
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Recipe: tools/sa_outstation_kat.py. No live peer with Secure Authentication exists (modern opendnp3 dropped
// SA), so the first test pins a whole exchange against vectors derived by
// hand OUTSIDE this module: Python's `hmac`/`hashlib` for every MAC and the
// `cryptography` package's RFC 3394 key wrap for the g120v6 payload, over the
// byte layouts IEEE 1815-2012 §7 gives. The rest exercise each decision with
// MACs computed through `sa.zig`.

const testing = std.testing;
const outstation = @import("outstation.zig");
const hex = @import("testkit").hex.literal;

const kat_update_key = hex("000102030405060708090a0b0c0d0e0f");
const kat_control_key = hex("404142434445464748494a4b4c4d4e4f");
const kat_monitoring_key = hex("606162636465666768696a6b6c6d6e6f");
/// DIRECT_OPERATE body: g12v1, qualifier 0x17, one CROB for index 0,
/// LATCH_ON, count 1, 100/100 ms.
const kat_crob_index0 = hex("0c011701000301640000006400000000");

const Rig = struct {
    bouts: [2]outstation.BinaryOutputStatus = .{ .{}, .{} },
    event_storage: [4]outstation.Event = undefined,
    users: [2]User = .{
        .{ .number = 1, .update_key = &kat_update_key },
        .{ .number = 7, .update_key = &kat_update_key },
    },
    pending: [256]u8 = undefined,
    counter: u8 = 0,
    auth: SecureAuth = undefined,
    station: outstation.Outstation = undefined,
    out: [512]u8 = undefined,

    fn fill(ctx: *anyopaque, buf: []u8) void {
        const c: *u8 = @ptrCast(ctx);
        for (buf) |*b| {
            c.* +%= 1;
            b.* = c.*;
        }
    }

    /// Builds the outstation in place (it points into the rig).
    fn setup(self: *Rig, config: Config, with_sa: bool) void {
        self.station = outstation.Outstation.init(
            .{ .need_time_at_start = false },
            .{ .binary_outputs = &self.bouts },
            outstation.EventBuffer.init(&self.event_storage),
        );
        self.auth = SecureAuth.init(config, &self.users, .{ .ctx = &self.counter, .fill = fill }, &self.pending);
        if (with_sa) self.station.setSecureAuth(&self.auth);
    }

    fn send(self: *Rig, request: []const u8, now_ms: u64) !?[]u8 {
        const r = (try self.station.handleFrom(request, 1, now_ms, &self.out)) orelse return null;
        return r.fragment;
    }

    fn sendFrom(self: *Rig, request: []const u8, peer: ?u16, now_ms: u64) !?[]u8 {
        const r = (try self.station.handleFrom(request, peer, now_ms, &self.out)) orelse return null;
        return r.fragment;
    }

    /// Wraps the keys the SAv5 way, around the status that opened the
    /// current key-change window.
    fn wrap(self: *Rig, update_key: []const u8, control_key: []const u8, monitoring_key: []const u8, buf: []u8) ![]u8 {
        return sa.wrapSessionKeysWithStatus(update_key, control_key, monitoring_key, self.auth.lastStatus(), buf);
    }

    /// Installs session keys for `user` through the real status-request /
    /// key-change exchange.
    fn installKeys(self: *Rig, user: u16, now_ms: u64) !void {
        var req: [256]u8 = undefined;
        _ = (try self.send(try authRequest(&req, 0, .session_key_status_request, &.{ @truncate(user), @truncate(user >> 8) }), now_ms)).?;
        var wrapped: [192]u8 = undefined;
        const w = try self.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped);
        var body: [200]u8 = undefined;
        const kc = try (sa.SessionKeyChange{ .key_change_seq_num = self.auth.ksq, .user_number = user, .wrapped_key_data = w }).encode(&body);
        const st = (try self.send(try authRequest(&req, 1, .session_key_change, kc), now_ms)).?;
        const status = try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data);
        try testing.expectEqual(sa.KeyStatus.ok, status.key_status);
    }

    /// Answers the outstation's last challenge for `user`, MAC'd with `key`
    /// over the stored critical request.
    fn reply(self: *Rig, buf: []u8, seq: u4, csq: u32, user: u16, key: []const u8) ![]u8 {
        var m: [16]u8 = undefined;
        const mac_value = try sa.computeReplyMac(
            .hmac_sha256_trunc_16,
            key,
            self.auth.challenge_buf[0..self.auth.challenge_len],
            self.auth.pending_storage[0..if (self.auth.pending) |p| p.request_len else 0],
            &m,
        );
        var body: [32]u8 = undefined;
        const r = try (sa.Reply{ .challenge_seq_num = csq, .user_number = user, .mac_value = mac_value }).encode(&body);
        return try authRequest(buf, seq, .reply, r);
    }
};

fn authRequest(buf: []u8, seq: u4, variation: sa.ObjectVariation, data: []const u8) ![]u8 {
    buf[0] = (application.AppControl{ .fir = true, .fin = true, .seq = seq }).toByte();
    buf[1] = @backingInt(FunctionCode.auth_request);
    const o = try sa.encodeObject(variation, data, buf[2..]);
    return buf[0 .. 2 + o.len];
}

fn crobRequest(buf: []u8, seq: u4, function: FunctionCode, index: u8) []u8 {
    buf[0] = (application.AppControl{ .fir = true, .fin = true, .seq = seq }).toByte();
    buf[1] = @backingInt(function);
    @memcpy(buf[2..18], &kat_crob_index0);
    buf[6] = index;
    return buf[0..18];
}

fn isSaError(fragment: []const u8) bool {
    if (fragment.len < 4 or fragment[1] != @backingInt(FunctionCode.auth_response)) return false;
    const obj = sa.decodeObject(fragment[4..]) catch return false;
    if (obj.variation != .sa_error) return false;
    const e = sa.SaError.decode(obj.data) catch return false;
    return e.error_code == .authentication_failed;
}

fn challengeCsq(fragment: []const u8) !u32 {
    try testing.expectEqual(@as(u8, 0x83), fragment[1]);
    const obj = try sa.decodeObject(fragment[4..]);
    try testing.expectEqual(sa.ObjectVariation.challenge, obj.variation);
    return (try sa.Challenge.decode(obj.data)).challenge_seq_num;
}

test "SA: key change, challenge, reply and aggressive mode match hand-derived vectors" {
    var rig: Rig = .{};
    rig.setup(.{}, true);

    // Key status for user 1 (NOT_INIT), KSQ 1, challenge data 01..04.
    try testing.expectEqualSlices(u8, &hex("c083800078055b010f00010000000100010204040001020304"), (try rig.send(&hex("c02078045b0102000100"), 0)).?);
    // Key change wrapping (SAv5 layout) key length 16, control 40..4f,
    // monitoring 60..6f and the status above under update key 00..0f; the confirmation carries KSQ 2, OK, fresh data 05..08 and
    // HMAC-SHA-256/16 of the g120v6 object under the monitoring key.
    try testing.expectEqualSlices(u8, &hex("c183800078055b011f000200000001000101040400050607084bb1a3193de25290dc40b2e67d311ffb"), (try rig.send(&hex("c12078065b014600010000000100edddc550b51738bf1313e1a468c058816cbcbd43f1797572396cffe9ad5f7ea5d35c3ef0608455b72d3d56b77a2a661881d2f9cd995baaddce5142fe5013f2a1"), 0)).?);
    try testing.expectEqualSlices(u8, &kat_control_key, rig.users[0].control_key[0..16]);
    // The same wrapped data from this module's own SAv5 wrap: the layout
    // (length field, keys, status, ZERO padding) byte for byte.
    var wbuf: [96]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("edddc550b51738bf1313e1a468c058816cbcbd43f1797572396cffe9ad5f7ea5d35c3ef0608455b72d3d56b77a2a661881d2f9cd995baaddce5142fe5013f2a1"), try sa.wrapSessionKeysWithStatus(&kat_update_key, &kat_control_key, &kat_monitoring_key, &hex("010000000100010204040001020304"), &wbuf));

    // DIRECT_OPERATE is critical: challenged (CSQ 1, data 09..0c), not run.
    var req: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("c383800078015b010c000100000001000401090a0b0c"), (try rig.send(crobRequest(&req, 3, .direct_operate, 0), 10)).?);
    try testing.expect(!rig.bouts[0].value);

    // The reply's MAC covers challenge ‖ request; it runs the request once,
    // answered with the request's own sequence number.
    const reply_bytes = hex("c32078025b011600010000000100235abad130e837442bec066c3ccab4b0");
    const resp = (try rig.send(&reply_bytes, 20)).?;
    try testing.expectEqual(@as(u8, 0xC3), resp[0]);
    try testing.expectEqual(@as(u8, 0x81), resp[1]);
    try testing.expectEqual(@as(u8, 0), resp[resp.len - 1]); // CROB status SUCCESS
    try testing.expect(rig.bouts[0].value);

    // Replaying the reply finds no outstanding challenge: silent, not run.
    rig.bouts[0].value = false;
    try testing.expectEqual(@as(?[]u8, null), try rig.send(&reply_bytes, 30));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.unexpected_messages);

    // Aggressive mode: CSQ 2 = last + 1, MAC over the last challenge ‖ the
    // request up to the g120v9 object.
    const aggressive = hex("c40578035b0106000200000001000c01170100030164000000640000000078095b0110009f6b59d0cef544190d09ec964f196360");
    const agg_resp = (try rig.send(&aggressive, 40)).?;
    try testing.expectEqual(@as(u8, 0x81), agg_resp[1]);
    try testing.expectEqual(@as(u8, 0), agg_resp[agg_resp.len - 1]);
    try testing.expect(rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 2), rig.auth.csq);
    try testing.expectEqual(@as(u32, 2), rig.users[0].messages);

    // The same aggressive message again carries a CSQ already used.
    rig.bouts[0].value = false;
    try testing.expect(isSaError((try rig.send(&aggressive, 50)).?));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 2), rig.auth.stats.successful_authentications);
}

test "SA: a bad reply MAC is refused with g120v7, and the challenge cannot be retried" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    const csq = try challengeCsq((try rig.send(crobRequest(&req, 5, .direct_operate, 0), 0)).?);
    var good_buf: [64]u8 = undefined;
    const good = try rig.reply(&good_buf, 5, csq, 1, &kat_control_key);
    var bad: [64]u8 = undefined;
    @memcpy(bad[0..good.len], good);
    bad[good.len - 1] ^= 0x80;
    try testing.expect(isSaError((try rig.send(bad[0..good.len], 1)).?));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.authentication_failures);
    // The correct reply now finds nothing outstanding.
    try testing.expectEqual(@as(?[]u8, null), try rig.send(good, 2));
    try testing.expect(!rig.bouts[0].value);
}

test "SA: a reply with the wrong CSQ, sequence, peer, user or key never executes" {
    const Case = enum { csq, seq, peer, no_peer, unknown_user, no_keys, empty_key, wrong_key };
    for (std.enums.values(Case)) |case| {
        var rig: Rig = .{};
        rig.setup(.{}, true);
        try rig.installKeys(1, 0);
        var req: [32]u8 = undefined;
        const csq = try challengeCsq((try rig.send(crobRequest(&req, 5, .direct_operate, 0), 0)).?);
        var buf: [64]u8 = undefined;
        const r = switch (case) {
            .csq => try rig.reply(&buf, 5, csq +% 1, 1, &kat_control_key),
            .seq => try rig.reply(&buf, 6, csq, 1, &kat_control_key),
            .peer, .no_peer, .wrong_key => try rig.reply(&buf, 5, csq, 1, if (case == .wrong_key) &kat_monitoring_key else &kat_control_key),
            // A user without session keys must not authenticate with the
            // empty key its zeroed slot would give.
            .empty_key => try rig.reply(&buf, 5, csq, 7, &.{}),
            .unknown_user => try rig.reply(&buf, 5, csq, 9, &kat_control_key),
            .no_keys => try rig.reply(&buf, 5, csq, 7, &kat_control_key),
        };
        const peer: ?u16 = switch (case) {
            .peer => 2,
            .no_peer => null,
            else => 1,
        };
        const answers = switch (case) {
            .csq, .seq, .peer, .no_peer => false,
            else => true,
        };
        const resp = try rig.sendFrom(r, peer, 1);
        try testing.expect(!rig.bouts[0].value);
        if (answers) {
            // It answers the outstanding challenge and fails: consumed.
            try testing.expect(isSaError(resp.?));
            try testing.expectEqual(@as(?SecureAuth.Pending, null), rig.auth.pending);
        } else {
            // It does not answer it: ignored, and the master's genuine
            // reply still goes through.
            try testing.expectEqual(@as(?[]u8, null), resp);
            try testing.expect(rig.auth.pending != null);
            try testing.expectEqual(@as(u32, 1), rig.auth.stats.unexpected_messages);
            // An undecodable reply is ignored the same way.
            var short: [16]u8 = undefined;
            try testing.expectEqual(@as(?[]u8, null), try rig.send(try authRequest(&short, 5, .reply, &.{ 1, 2, 3 }), 1));
            try testing.expect(rig.auth.pending != null);
            try testing.expectEqual(@as(u32, 2), rig.auth.stats.unexpected_messages);
            var good: [64]u8 = undefined;
            _ = (try rig.send(try rig.reply(&good, 5, csq, 1, &kat_control_key), 2)).?;
            try testing.expect(rig.bouts[0].value);
        }
    }
}

test "SA: a reply after the timeout, or to a replaced challenge, does not execute" {
    var rig: Rig = .{};
    rig.setup(.{ .reply_timeout_ms = 1000 }, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    var csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 0), 0)).?);
    var r = try rig.reply(&buf, 1, csq, 1, &kat_control_key);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(r, 1000));
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.reply_timeouts);
    try testing.expect(!rig.bouts[0].value);
    // One millisecond inside the window still works.
    csq = try challengeCsq((try rig.send(crobRequest(&req, 2, .direct_operate, 0), 2000)).?);
    r = try rig.reply(&buf, 2, csq, 1, &kat_control_key);
    _ = (try rig.send(r, 2999)).?;
    try testing.expect(rig.bouts[0].value);

    // A second critical request replaces the first challenge.
    rig.bouts[0].value = false;
    const first = try challengeCsq((try rig.send(crobRequest(&req, 3, .direct_operate, 0), 3000)).?);
    var old_buf: [64]u8 = undefined;
    const old = try rig.reply(&old_buf, 3, first, 1, &kat_control_key);
    var req2: [32]u8 = undefined;
    const second = try challengeCsq((try rig.send(crobRequest(&req2, 4, .direct_operate, 1), 3001)).?);
    try testing.expectEqual(first +% 1, second);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(old, 3002));
    try testing.expect(!rig.bouts[0].value and !rig.bouts[1].value);
}

test "SA: SELECT and OPERATE each authenticated keep select-before-operate working" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    var csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .select, 0), 0)).?);
    var resp = (try rig.send(try rig.reply(&buf, 1, csq, 1, &kat_control_key), 1)).?;
    try testing.expectEqual(@as(u8, 0), resp[resp.len - 1]);
    try testing.expect(!rig.bouts[0].value);
    csq = try challengeCsq((try rig.send(crobRequest(&req, 2, .operate, 0), 2)).?);
    resp = (try rig.send(try rig.reply(&buf, 2, csq, 1, &kat_control_key), 3)).?;
    try testing.expectEqual(@as(u8, 0), resp[resp.len - 1]);
    try testing.expect(rig.bouts[0].value);
}

test "SA: non-critical requests are answered byte-identically, and no SA means no AUTH function" {
    var plain: Rig = .{};
    plain.setup(.{}, false);
    var secured: Rig = .{};
    secured.setup(.{}, true);
    const read = hex("c1013c0106"); // READ class 0
    try testing.expectEqualSlices(u8, (try plain.send(&read, 0)).?, (try secured.send(&read, 0)).?);
    // Without SA attached, AUTHENTICATE_REQUEST is FUNC_NOT_SUPPORTED as
    // before, and a critical request runs unchallenged.
    const r = (try plain.send(&hex("c22078045b0102000100"), 0)).?;
    try testing.expectEqual(@as(u8, 0x81), r[1]);
    try testing.expect(r[3] & 0x01 != 0);
    var req: [32]u8 = undefined;
    _ = (try plain.send(crobRequest(&req, 3, .direct_operate, 0), 0)).?;
    try testing.expect(plain.bouts[0].value);
}

test "SA: the critical set is the caller's to override" {
    var rig: Rig = .{};
    rig.setup(.{ .critical = FunctionSet.default_critical.without(.direct_operate).with(.read) }, true);
    var req: [32]u8 = undefined;
    const resp = (try rig.send(crobRequest(&req, 1, .direct_operate, 0), 0)).?;
    try testing.expectEqual(@as(u8, 0x81), resp[1]);
    try testing.expect(rig.bouts[0].value);
    _ = try challengeCsq((try rig.send(&hex("c2013c0106"), 1)).?);
    try testing.expect(FunctionSet.default_critical.contains(.operate));
    try testing.expect(!FunctionSet.default_critical.contains(.read));
    try testing.expect(!FunctionSet.default_critical.contains(.confirm));
}

test "SA: a critical no-ack request runs only in aggressive mode" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    try testing.expectEqual(@as(?[]u8, null), try rig.send(crobRequest(&req, 1, .direct_operate_no_ack, 0), 0));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.discarded_messages);
    try testing.expectEqual(@as(usize, 0), rig.auth.challenge_len);

    // Aggressive mode needs a challenge to chain from first.
    _ = try challengeCsq((try rig.send(crobRequest(&req, 2, .direct_operate, 1), 1)).?);
    var agg: [96]u8 = undefined;
    const msg = try aggressiveRequest(&rig, &agg, 3, .direct_operate_no_ack, rig.auth.csq +% 1, 1, &kat_control_key);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(msg, 2));
    try testing.expect(rig.bouts[0].value);
    try testing.expect(!rig.bouts[1].value);
}

fn aggressiveRequest(rig: *Rig, buf: []u8, seq: u4, function: FunctionCode, csq: u32, user: u16, key: []const u8) ![]u8 {
    buf[0] = (application.AppControl{ .fir = true, .fin = true, .seq = seq }).toByte();
    buf[1] = @backingInt(function);
    var amr: [6]u8 = undefined;
    var pos: usize = 2;
    pos += (try sa.encodeObject(.aggressive_mode_request, try (sa.AggressiveModeRequest{ .challenge_seq_num = csq, .user_number = user }).encode(&amr), buf[pos..])).len;
    @memcpy(buf[pos..][0..16], &kat_crob_index0);
    pos += 16;
    var m: [16]u8 = undefined;
    const mac_value = try sa.mac.computeTwo(.hmac_sha256_trunc_16, key, rig.auth.challenge_buf[0..rig.auth.challenge_len], buf[0..pos], &m);
    pos += (try sa.encodeObject(.aggregate_mac, mac_value, buf[pos..])).len;
    return buf[0..pos];
}

test "SA: aggressive mode refused without a challenge, when disabled, or with a bad MAC or object" {
    const Case = enum { no_challenge, disabled, bad_mac, wrong_user_key, truncated, not_v9 };
    for (std.enums.values(Case)) |case| {
        var rig: Rig = .{};
        rig.setup(.{ .allow_aggressive_mode = case != .disabled }, true);
        try rig.installKeys(1, 0);
        var req: [32]u8 = undefined;
        if (case != .no_challenge) _ = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 1), 0)).?);
        var agg: [96]u8 = undefined;
        var msg = try aggressiveRequest(&rig, &agg, 2, .direct_operate, rig.auth.csq +% 1, 1, if (case == .wrong_user_key) &kat_monitoring_key else &kat_control_key);
        switch (case) {
            .bad_mac => msg[msg.len - 1] ^= 1,
            .truncated => msg = msg[0..20],
            .not_v9 => msg[msg.len - 21] = 8,
            else => {},
        }
        try testing.expect(isSaError((try rig.send(msg, 1)).?));
        try testing.expect(!rig.bouts[0].value);
    }
}

test "SA: key change refused for a wrong KSQ, a wrong update key, or without a status request" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    var req: [256]u8 = undefined;
    // No status request yet: there is no window.
    var wrapped: [192]u8 = undefined;
    const w = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped);
    var body: [200]u8 = undefined;
    try testing.expectEqual(@as(?[]u8, null), try rig.send(try authRequest(&req, 0, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = 1, .user_number = 1, .wrapped_key_data = w }).encode(&body)), 0));

    // Status request, then a key change one KSQ off.
    _ = (try rig.send(try authRequest(&req, 1, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    var st = (try rig.send(try authRequest(&req, 2, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq +% 1, .user_number = 1, .wrapped_key_data = w }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    // Wrapped under another update key.
    const other = hex("ff0102030405060708090a0b0c0d0e0f");
    const w2 = try rig.wrap(&other, &kat_control_key, &kat_monitoring_key, &wrapped);
    st = (try rig.send(try authRequest(&req, 3, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = w2 }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.not_init, rig.users[0].status);
    // Another user's number inside the window.
    st = (try rig.send(try authRequest(&req, 4, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 7, .wrapped_key_data = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped) }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(@as(u32, 3), rig.auth.stats.failed_session_key_changes);

    // A key change too short to decode closes the window it used.
    _ = (try rig.send(try authRequest(&req, 6, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    try testing.expect(isSaError((try rig.send(try authRequest(&req, 7, .session_key_change, &.{ 1, 2, 3 }), 0)).?));
    try testing.expectEqual(@as(?[]u8, null), try rig.send(try authRequest(&req, 8, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped) }).encode(&body)), 0));
    // Wrapped data shorter than one AES-KW block.
    _ = (try rig.send(try authRequest(&req, 9, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    st = (try rig.send(try authRequest(&req, 10, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = &.{ 1, 2, 3 } }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.not_init, rig.users[0].status);

    // A good change, then its replay: refused, keys kept.
    try rig.installKeys(1, 0);
    st = (try rig.send(try authRequest(&req, 5, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq -% 1, .user_number = 1, .wrapped_key_data = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped) }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.ok, rig.users[0].status);
}

test "SA: a key change wipes the previous keys, including a longer pair" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    var req: [256]u8 = undefined;
    var wrapped: [192]u8 = undefined;
    var body: [200]u8 = undefined;
    const long_c: [32]u8 = @splat(0xA5);
    const long_m: [32]u8 = @splat(0x5A);
    _ = (try rig.send(try authRequest(&req, 0, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    const w = try rig.wrap(&kat_update_key, &long_c, &long_m, &wrapped);
    _ = (try rig.send(try authRequest(&req, 1, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = w }).encode(&body)), 0)).?;
    try testing.expectEqual(@as(u8, 32), rig.users[0].key_len);
    try rig.installKeys(1, 0);
    try testing.expectEqual(@as(u8, 16), rig.users[0].key_len);
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0))), rig.users[0].control_key[16..]);
    try testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0))), rig.users[0].monitoring_key[16..]);
}

test "SA: session keys expire by time and by message count" {
    var rig: Rig = .{};
    rig.setup(.{ .session_key_timeout_ms = 1000, .session_key_max_messages = 1 }, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    var csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 0), 10)).?);
    _ = (try rig.send(try rig.reply(&buf, 1, csq, 1, &kat_control_key), 11)).?;
    try testing.expect(rig.bouts[0].value);
    // One message used up the count.
    rig.bouts[0].value = false;
    csq = try challengeCsq((try rig.send(crobRequest(&req, 2, .direct_operate, 0), 12)).?);
    try testing.expect(isSaError((try rig.send(try rig.reply(&buf, 2, csq, 1, &kat_control_key), 13)).?));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(sa.KeyStatus.comm_fail, rig.users[0].status);
    try testing.expectEqual(@as(u8, 0), rig.users[0].control_key[0] | rig.users[0].key_len);

    // Fresh keys, then time runs out exactly at the limit.
    rig.auth.config.session_key_max_messages = 0;
    try rig.installKeys(1, 100);
    csq = try challengeCsq((try rig.send(crobRequest(&req, 3, .direct_operate, 0), 1099)).?);
    _ = (try rig.send(try rig.reply(&buf, 3, csq, 1, &kat_control_key), 1099)).?;
    try testing.expect(rig.bouts[0].value);
    rig.bouts[0].value = false;
    csq = try challengeCsq((try rig.send(crobRequest(&req, 4, .direct_operate, 0), 1100)).?);
    try testing.expect(isSaError((try rig.send(try rig.reply(&buf, 4, csq, 1, &kat_control_key), 1100)).?));
    try testing.expect(!rig.bouts[0].value);
    try testing.expectEqual(@as(u32, 2), rig.auth.stats.session_keys_expired);
    // A status request reports the expiry, and finds nothing more to expire.
    var st = (try rig.send(try authRequest(&req, 5, .session_key_status_request, &.{ 1, 0 }), 1101)).?;
    try testing.expectEqual(sa.KeyStatus.comm_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(@as(u32, 2), rig.auth.stats.session_keys_expired);

    // A status request alone notices that the keys ran out of time.
    try rig.installKeys(1, 5000);
    st = (try rig.send(try authRequest(&req, 6, .session_key_status_request, &.{ 1, 0 }), 6000)).?;
    try testing.expectEqual(sa.KeyStatus.comm_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.comm_fail, rig.users[0].status);
}

test "SA: a zero limit disables that expiry axis" {
    var rig: Rig = .{};
    rig.setup(.{ .session_key_timeout_ms = 0, .session_key_max_messages = 0 }, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    const csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 0), std.math.maxInt(u32))).?);
    _ = (try rig.send(try rig.reply(&buf, 1, csq, 1, &kat_control_key), std.math.maxInt(u32))).?;
    try testing.expect(rig.bouts[0].value);
}

test "SA: error messages stop after the budget, and a key change restores it" {
    var rig: Rig = .{};
    rig.setup(.{ .max_error_messages = 1 }, true);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    var csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 0), 0)).?);
    try testing.expect(isSaError((try rig.send(try rig.reply(&buf, 1, csq, 1, &kat_control_key), 0)).?));
    csq = try challengeCsq((try rig.send(crobRequest(&req, 2, .direct_operate, 0), 0)).?);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(try rig.reply(&buf, 2, csq, 1, &kat_control_key), 0));
    try testing.expectEqual(@as(u32, 2), rig.auth.stats.authentication_failures);
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.error_messages_sent);
    try rig.installKeys(1, 0);
    csq = try challengeCsq((try rig.send(crobRequest(&req, 3, .direct_operate, 0), 0)).?);
    try testing.expect(isSaError((try rig.send(try rig.reply(&buf, 3, csq, 1, &kat_monitoring_key), 0)).?));
}

test "SA: unexpected or malformed AUTH requests are counted and ignored" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    var req: [64]u8 = undefined;
    // A reply with nothing outstanding, garbage, an unknown g120 variation.
    try testing.expectEqual(@as(?[]u8, null), try rig.send(try authRequest(&req, 0, .reply, &.{ 1, 0, 0, 0, 1, 0 }), 0));
    try testing.expectEqual(@as(?[]u8, null), try rig.send(&hex("c120ffff"), 0));
    try testing.expectEqual(@as(?[]u8, null), try rig.send(try authRequest(&req, 1, .challenge, &.{ 0, 0, 0, 0, 0, 0, 0, 0 }), 0));
    try testing.expectEqual(@as(u32, 3), rig.auth.stats.unexpected_messages);
    // The master's own g120v7 (AUTH_REQUEST_NO_ACK) is counted, not answered.
    var e: [32]u8 = undefined;
    const err = try (sa.SaError{ .sequence_number = 1, .user_number = 1, .association_id = 0, .error_code = .authentication_failed, .time_of_error = 0, .error_text = &.{} }).encode(&e);
    const no_ack = try authRequest(&req, 2, .sa_error, err);
    no_ack[1] = @backingInt(FunctionCode.auth_request_no_ack);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(no_ack, 0));
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.error_messages_received);
    // A status request for an unknown user looks like one for a known user
    // without keys, and no key change can pass its window.
    var known: Rig = .{};
    known.setup(.{}, true);
    const st_known = (try known.send(try authRequest(&req, 3, .session_key_status_request, &.{ 7, 0 }), 0)).?;
    var known_copy: [64]u8 = undefined;
    @memcpy(known_copy[0..st_known.len], st_known);
    const st_unknown = (try rig.send(try authRequest(&req, 3, .session_key_status_request, &.{ 9, 0 }), 0)).?;
    try testing.expectEqual(st_known.len, st_unknown.len);
    try testing.expectEqualSlices(u8, known_copy[0..6], st_unknown[0..6]); // header + object header
    const unknown_status = try sa.SessionKeyStatus.decode((try sa.decodeObject(st_unknown[4..])).data);
    try testing.expectEqual(sa.KeyStatus.not_init, unknown_status.key_status);
    try testing.expectEqual(@as(u16, 9), unknown_status.user_number);
    var wrapped: [192]u8 = undefined;
    var kc_body: [200]u8 = undefined;
    var kc_req: [256]u8 = undefined;
    const kc = try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 9, .wrapped_key_data = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped) }).encode(&kc_body);
    const refused = (try rig.send(try authRequest(&kc_req, 4, .session_key_change, kc), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(refused[4..])).data)).key_status);
    // A critical request too large to store is discarded, not challenged.
    var big: [300]u8 = undefined;
    @memset(&big, 0);
    big[0] = 0xC4;
    big[1] = @backingInt(FunctionCode.write);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(&big, 0));
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.discarded_messages);
}

test "SA: an update key that does not fit the key-wrap algorithm is refused" {
    var rig: Rig = .{};
    rig.setup(.{ .key_wrap_algorithm = .aes_256 }, true); // needs a 32-octet update key
    var req: [256]u8 = undefined;
    var wrapped: [192]u8 = undefined;
    var body: [200]u8 = undefined;
    _ = (try rig.send(try authRequest(&req, 0, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    const w = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped);
    const st = (try rig.send(try authRequest(&req, 1, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = w }).encode(&body)), 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.not_init, rig.users[0].status);
}

test "SA: challenge shapes: empty body, a leading g120 that is not v3, the storage boundary, clamped data" {
    var rig: Rig = .{};
    rig.setup(.{ .challenge_len = 0 }, true);
    // COLD_RESTART has no objects at all; it is still challenged.
    var csq = try challengeCsq((try rig.send(&hex("c00d"), 0)).?);
    try testing.expectEqual(@as(u32, 1), csq);
    // Challenge data is never shorter than the standard's 4 octets.
    const ch = try sa.Challenge.decode((try sa.decodeObject(rig.auth.challenge_buf[4..rig.auth.challenge_len])).data);
    try testing.expectEqual(@as(usize, 4), ch.challenge_data.len);
    // A WRITE whose first object is g120v1 is challenged, not taken for
    // aggressive mode.
    csq = try challengeCsq((try rig.send(&hex("c10278015b0100000000"), 0)).?);
    try testing.expectEqual(@as(u32, 2), csq);
    // A request exactly as long as the storage is still stored.
    var big: [256]u8 = undefined;
    @memset(&big, 0);
    big[0] = 0xC2;
    big[1] = @backingInt(FunctionCode.write);
    _ = try challengeCsq((try rig.send(&big, 0)).?);
    try testing.expectEqual(@as(usize, 256), rig.auth.pending.?.request_len);

    var wide: Rig = .{};
    wide.setup(.{ .challenge_len = 255 }, true);
    _ = try challengeCsq((try wide.send(&hex("c00d"), 0)).?);
    try testing.expectEqual(@as(usize, max_challenge_data), (try sa.Challenge.decode((try sa.decodeObject(wide.auth.challenge_buf[4..wide.auth.challenge_len])).data)).challenge_data.len);
    // The clamp holds for a config changed after `init`, key status included.
    wide.auth.config.challenge_len = 200;
    _ = try challengeCsq((try wide.send(&hex("c10d"), 0)).?);
    const st = (try wide.send(&hex("c22078045b0102000100"), 0)).?;
    try testing.expectEqual(@as(usize, max_challenge_data), (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).challenge_data.len);
}

test "SA: a challenge that could not be sent leaves no older challenge answerable" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    const csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 0), 0)).?);
    const old = try rig.reply(&buf, 1, csq, 1, &kat_control_key);
    var req2: [32]u8 = undefined;
    var tiny: [12]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, rig.station.handleFrom(crobRequest(&req2, 2, .direct_operate, 1), 1, 1, &tiny));
    try testing.expectEqual(@as(?[]u8, null), try rig.send(old, 2));
    try testing.expect(!rig.bouts[0].value);
}

test "SA: an accepted aggressive-mode request cancels the outstanding challenge" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    try rig.installKeys(1, 0);
    var req: [32]u8 = undefined;
    var buf: [64]u8 = undefined;
    const csq = try challengeCsq((try rig.send(crobRequest(&req, 1, .direct_operate, 1), 0)).?);
    const pending_reply = try rig.reply(&buf, 1, csq, 1, &kat_control_key);
    var agg: [96]u8 = undefined;
    _ = (try rig.send(try aggressiveRequest(&rig, &agg, 2, .direct_operate, csq +% 1, 1, &kat_control_key), 1)).?;
    try testing.expect(rig.bouts[0].value);
    try testing.expectEqual(@as(?[]u8, null), try rig.send(pending_reply, 2));
    try testing.expect(!rig.bouts[1].value);
}

test "SA: a MAC algorithm that cannot confirm a key change refuses it" {
    var rig: Rig = .{};
    rig.setup(.{ .mac_algorithm = .aes_gmac_trunc_12 }, true); // needs an IV this module does not derive
    var req: [256]u8 = undefined;
    var wrapped: [192]u8 = undefined;
    var body: [200]u8 = undefined;
    _ = (try rig.send(try authRequest(&req, 0, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    const w = try rig.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped);
    const r = (try rig.send(try authRequest(&req, 1, .session_key_change, try (sa.SessionKeyChange{ .key_change_seq_num = rig.auth.ksq, .user_number = 1, .wrapped_key_data = w }).encode(&body)), 0)).?;
    try testing.expect(isSaError(r));
    try testing.expectEqual(sa.KeyStatus.not_init, rig.users[0].status);
    try testing.expectEqual(@as(u8, 0), rig.users[0].key_len);
    try testing.expectEqual(@as(u32, 1), rig.auth.stats.failed_session_key_changes);
}

test "SA: a challenged request does not abandon the response awaiting its confirm" {
    var rig: Rig = .{};
    rig.setup(.{}, true);
    rig.bouts[0].class = .class1;
    rig.station.update(.binary_output_status, 0, .{ .binary = true }, 0);
    const events = (try rig.send(&hex("c1013c0206"), 0)).?; // READ class 1
    try testing.expect(events[0] & 0x20 != 0); // CON
    try testing.expect(rig.station.awaiting_confirm);
    var req: [32]u8 = undefined;
    _ = try challengeCsq((try rig.send(crobRequest(&req, 2, .direct_operate, 1), 1)).?);
    try testing.expect(rig.station.awaiting_confirm);
    try testing.expectEqual(@as(?u4, 1), rig.station.last_request_seq);
    // SA's own exchanges do not either; an authenticated request does.
    try rig.installKeys(1, 2);
    try testing.expect(rig.station.awaiting_confirm);
    const csq = try challengeCsq((try rig.send(crobRequest(&req, 3, .direct_operate, 1), 3)).?);
    var buf: [64]u8 = undefined;
    _ = (try rig.send(try rig.reply(&buf, 3, csq, 1, &kat_control_key), 4)).?;
    try testing.expect(!rig.station.awaiting_confirm);
    try testing.expectEqual(@as(?u4, 3), rig.station.last_request_seq);
}

test "SA: a recorded key change replayed after a restart is refused, however the KSQ is stepped" {
    // Boot 1: a genuine key change, recorded.
    var first: Rig = .{};
    first.setup(.{}, true);
    var req: [256]u8 = undefined;
    _ = (try first.send(try authRequest(&req, 0, .session_key_status_request, &.{ 1, 0 }), 0)).?;
    var wrapped: [192]u8 = undefined;
    const w = try first.wrap(&kat_update_key, &kat_control_key, &kat_monitoring_key, &wrapped);
    var body: [200]u8 = undefined;
    const recorded_ksq = first.auth.ksq;
    const recorded = try (sa.SessionKeyChange{ .key_change_seq_num = recorded_ksq, .user_number = 1, .wrapped_key_data = w }).encode(&body);
    var recorded_req: [256]u8 = undefined;
    const replay = try authRequest(&recorded_req, 1, .session_key_change, recorded);
    _ = (try first.send(replay, 0)).?;
    try testing.expectEqual(sa.KeyStatus.ok, first.users[0].status);

    // Boot 2: the KSQ starts again at 0; an attacker steps it with g120v4
    // until the window carries the recorded KSQ, then replays.
    var second: Rig = .{};
    second.setup(.{}, true);
    second.counter = 100; // a real random source does not repeat after a restart
    var i: u32 = 0;
    while (second.auth.ksq != recorded_ksq) : (i += 1) {
        _ = (try second.send(try authRequest(&req, @truncate(i), .session_key_status_request, &.{ 1, 0 }), 0)).?;
    }
    const st = (try second.send(replay, 0)).?;
    try testing.expectEqual(sa.KeyStatus.auth_fail, (try sa.SessionKeyStatus.decode((try sa.decodeObject(st[4..])).data)).key_status);
    try testing.expectEqual(sa.KeyStatus.not_init, second.users[0].status);
    try testing.expectEqual(@as(u8, 0), second.users[0].key_len);
}
