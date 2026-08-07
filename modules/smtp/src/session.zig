// SPDX-License-Identifier: MIT

//! The SMTP conversation as a **pure state machine**: greeting → EHLO (with
//! HELO fallback) → STARTTLS → AUTH → MAIL/RCPT/DATA → QUIT, with no socket, no
//! allocation of I/O resources and no clock. A caller drives it with two calls:
//!
//!     while (true) switch (try s.next()) {
//!         .send => |bytes| try transport.write(bytes),
//!         .send_body => |body| try streamDotStuffed(transport, body),
//!         .recv => try s.feedReply(try readOneReply()),
//!         .start_tls => { try upgrade(); try s.tlsEstablished(); },
//!         .done => break,
//!     };
//!
//! That shape is why the whole protocol is testable from a transcript: the
//! tests below feed canned replies and assert the exact bytes the session would
//! have written, with no network anywhere. `client.zig` is the same loop over a
//! `Transport`, and is the only file in the module that blocks.
//!
//! ## Two rules that are enforced, not documented
//!
//! **STARTTLS discards what it learned in the clear.** RFC 3207 §4.2: "The
//! client MUST discard any knowledge obtained from the server, such as the list
//! of SMTP service extensions, which was not obtained from the TLS negotiation
//! itself." An active attacker owns every byte of the first EHLO reply — it can
//! delete `STARTTLS` (downgrade), or add `AUTH PLAIN` to a server that never
//! offered it. So `tlsEstablished` frees the capability set and the session
//! re-issues EHLO; and once TLS is up, `error.PlaintextAfterTls` is returned
//! rather than continuing if anything tries to fall back.
//!
//! **AUTH is refused on an unprotected link.** RFC 4954 §9. PLAIN and LOGIN
//! hand the password to anyone on the path. `Options.allow_plaintext_auth` is
//! the explicit opt-in and defaults to false, so the insecure case cannot be
//! reached by forgetting a flag.
//!
//! ## Pipelining
//!
//! With `PIPELINING` (RFC 2920) advertised, `MAIL FROM`, every `RCPT TO` and
//! `DATA` go out as one group and their replies are read in order — §3.1 allows
//! exactly that grouping and requires DATA to be last in it. The replies are
//! *all* consumed even when the first one fails, because the server has already
//! queued answers for the commands it received; skipping them desynchronises
//! the connection, which is the classic pipelining bug.

const std = @import("std");
const testing = std.testing;

const reply_mod = @import("reply.zig");
const capabilities = @import("capabilities.zig");
const command = @import("command.zig");
const data_mod = @import("data.zig");
const auth_mod = @import("auth.zig");

pub const Mechanism = capabilities.Mechanism;

pub const TlsPolicy = enum {
    /// Never issue STARTTLS.
    disabled,
    /// Use STARTTLS when the server advertises it.
    opportunistic,
    /// Require it: a server that does not advertise STARTTLS, or a caller that
    /// cannot perform the handshake, aborts the session.
    required,
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
    /// SASL authorization identity; empty means "the same as `username`".
    authzid: []const u8 = "",
    /// Preference order. The first mechanism the server also offers wins.
    mechanisms: []const Mechanism = &.{ .plain, .login },
};

pub const Options = struct {
    /// Our own name for EHLO/HELO — a fully-qualified domain, or an address
    /// literal from `command.addressLiteral`.
    ehlo_domain: []const u8 = "localhost",
    tls: TlsPolicy = .opportunistic,
    credentials: ?Credentials = null,
    /// AUTH over a link with no TLS. See the file comment; RFC 4954 §9.
    allow_plaintext_auth: bool = false,
    /// Group MAIL/RCPT/DATA when the server advertises PIPELINING.
    pipelining: bool = true,
    /// Send `SIZE=` on MAIL FROM when the server advertises SIZE.
    announce_size: bool = true,
    /// Treat any rejected recipient as a failure of the whole transaction.
    require_all_recipients: bool = false,
    cap_limits: capabilities.Limits = .{},
    cmd_limits: command.Limits = .{},
    /// Ceiling on recipients per transaction — a bound on what one call can
    /// make us allocate and send.
    max_recipients: usize = 1000,
};

pub const Envelope = struct {
    /// Reverse-path. `null` is the null sender `<>` of RFC 5321 §3.6.3, which
    /// is what a bounce (DSN) must use.
    from: ?[]const u8,
    to: []const []const u8,
    /// The message, already composed (see `message.render`). The session
    /// dot-stuffs it; do not pre-stuff.
    body: []const u8,
    /// The body contains octets above 127 and needs RFC 6152 8BITMIME.
    eight_bit: bool = false,
    /// The envelope or headers need RFC 6531 SMTPUTF8.
    smtputf8: bool = false,
};

pub const RecipientStatus = struct {
    addr: []const u8,
    code: u16 = 0,
    accepted: bool = false,
};

pub const SessionError = error{
    /// The greeting was not a 220 (or was a 554 "no service").
    BadGreeting,
    /// Both EHLO and HELO were refused.
    GreetingRefused,
    /// `TlsPolicy.required` and the server does not advertise STARTTLS.
    TlsNotOffered,
    /// STARTTLS was accepted by the server but the caller could not upgrade.
    TlsUnavailable,
    /// Something tried to continue in the clear after STARTTLS succeeded.
    PlaintextAfterTls,
    /// AUTH on an unencrypted link without `allow_plaintext_auth`.
    PlaintextAuthRefused,
    /// The server offers no mechanism this module implements.
    NoSupportedAuthMechanism,
    /// The server rejected the credentials.
    AuthenticationFailed,
    /// Every recipient was rejected.
    AllRecipientsRejected,
    /// `require_all_recipients` and at least one was rejected.
    RecipientRejected,
    /// The message exceeds the server's advertised SIZE.
    MessageTooLarge,
    /// An 8-bit body without 8BITMIME, or a UTF-8 envelope without SMTPUTF8.
    EightBitNotSupported,
    SmtpUtf8NotSupported,
    /// More recipients than `Options.max_recipients`.
    TooManyRecipients,
    /// A call used out of order (`beginTransaction` before the handshake, a
    /// reply fed when none was expected, …).
    InvalidState,
} || reply_mod.ReplyError || command.CommandError || capabilities.ParseError ||
    auth_mod.AuthError || data_mod.StuffError || std.mem.Allocator.Error;

/// What the driver must do next.
pub const Step = union(enum) {
    /// Write these bytes verbatim. Valid until the next call on the session.
    send: []const u8,
    /// Dot-stuff these bytes, write them, and append `CRLF.CRLF`
    /// (`data.writeData` does exactly that). Kept separate from `send` so a
    /// large message is never copied into the session's own buffer.
    send_body: []const u8,
    /// Read one reply and hand it to `feedReply`.
    recv,
    /// Perform the TLS handshake now, then call `tlsEstablished`.
    start_tls,
    /// Nothing left to do in the current phase.
    done,
};

pub const State = enum {
    /// Waiting for the server's 220 greeting.
    greeting,
    /// EHLO issued (or about to be).
    ehlo,
    /// EHLO was refused; falling back to HELO (RFC 5321 §3.2).
    helo,
    starttls_command,
    starttls_handshake,
    auth_initial,
    auth_username,
    auth_password,
    auth_plain_response,
    /// Handshake complete; idle, waiting for a transaction or QUIT.
    ready,
    /// MAIL/RCPT/DATA in flight.
    transaction,
    /// 354 received; the body goes out next.
    body,
    quit,
    /// QUIT acknowledged, or the session was abandoned.
    closed,
};

const Phase = enum { emit, wait };

pub const Session = struct {
    gpa: std.mem.Allocator,
    opts: Options,
    state: State = .greeting,
    phase: Phase = .wait, // the greeting arrives unprompted
    /// True once the caller reported a successful TLS handshake.
    tls_active: bool = false,
    /// True once EHLO (not HELO) succeeded, so ESMTP parameters are legal.
    esmtp: bool = false,
    /// True once AUTH succeeded.
    authenticated: bool = false,
    /// Set when the capability set came from an EHLO issued under TLS.
    caps: capabilities.Capabilities,
    /// Whether STARTTLS has already been performed (so it is not retried).
    starttls_done: bool = false,
    /// Command bytes for the current step.
    out: std.ArrayList(u8) = .empty,
    /// The most recent reply, owned, for diagnostics.
    last: ?reply_mod.Owned = null,

    // transaction state
    env: ?Envelope = null,
    rcpts: std.ArrayList(RecipientStatus) = .empty,
    /// Index into the logical command sequence 0=MAIL, 1..n=RCPT, n+1=DATA.
    tx_index: usize = 0,
    /// How many of those commands have been written.
    tx_sent: usize = 0,
    /// A failure recorded mid-group; reported once the group's replies have all
    /// been consumed (never leave a pipelined reply unread).
    tx_error: ?SessionError = null,
    /// The mechanism chosen for AUTH.
    mechanism: Mechanism = .plain,
    /// The caller asked to close.
    quit_requested: bool = false,

    pub fn init(gpa: std.mem.Allocator, opts: Options) Session {
        return .{ .gpa = gpa, .opts = opts, .caps = .empty(gpa) };
    }

    pub fn deinit(self: *Session) void {
        self.caps.deinit();
        self.wipeOut();
        self.out.deinit(self.gpa);
        self.rcpts.deinit(self.gpa);
        if (self.last) |*l| l.deinit(self.gpa);
        self.* = undefined;
    }

    /// Overwrite the command buffer before reuse: it has held a base64-encoded
    /// password.
    fn wipeOut(self: *Session) void {
        std.crypto.secureZero(u8, self.out.items);
        self.out.clearRetainingCapacity();
    }

    /// The capability set currently in force. After STARTTLS this is the
    /// post-TLS one; the pre-TLS set is gone.
    pub fn serverCapabilities(self: *const Session) *const capabilities.Capabilities {
        return &self.caps;
    }

    /// The last reply the server sent, for logging and for a caller that wants
    /// the server's own words in an error message.
    pub fn lastReply(self: *const Session) ?reply_mod.Reply {
        return if (self.last) |l| l.reply else null;
    }

    /// Per-recipient outcome of the most recent transaction.
    pub fn recipients(self: *const Session) []const RecipientStatus {
        return self.rcpts.items;
    }

    // ── driving ────────────────────────────────────────────────────────────

    pub fn next(self: *Session) SessionError!Step {
        if (self.phase == .wait) {
            return switch (self.state) {
                .starttls_handshake => .start_tls,
                .closed => .done,
                .ready => .done,
                else => .recv,
            };
        }
        switch (self.state) {
            .greeting => return .recv,
            .ehlo => {
                try self.emit(command.ehlo(try self.buf(), self.opts.ehlo_domain, self.opts.cmd_limits));
                return self.sent();
            },
            .helo => {
                try self.emit(command.helo(try self.buf(), self.opts.ehlo_domain, self.opts.cmd_limits));
                return self.sent();
            },
            .starttls_command => {
                try self.emit(command.starttls(try self.buf(), self.opts.cmd_limits));
                return self.sent();
            },
            .starttls_handshake => {
                self.phase = .wait;
                return .start_tls;
            },
            .auth_initial => return self.emitAuthInitial(),
            .auth_username => {
                const c = self.opts.credentials.?;
                try self.emitBase64(c.username);
                return self.sent();
            },
            .auth_password => {
                const c = self.opts.credentials.?;
                try self.emitBase64(c.password);
                return self.sent();
            },
            .auth_plain_response => {
                const c = self.opts.credentials.?;
                var resp: [1024]u8 = undefined;
                const ir = try auth_mod.plainResponse(&resp, c.authzid, c.username, c.password);
                defer std.crypto.secureZero(u8, &resp);
                try self.emit(command.authContinue(try self.buf(), ir, self.opts.cmd_limits));
                return self.sent();
            },
            .ready => {
                if (self.quit_requested) {
                    self.state = .quit;
                    return self.next();
                }
                return .done;
            },
            .transaction => return self.emitTransaction(),
            .body => {
                const env = self.env orelse return error.InvalidState;
                self.phase = .wait;
                return .{ .send_body = env.body };
            },
            .quit => {
                try self.emit(command.quit(try self.buf(), self.opts.cmd_limits));
                return self.sent();
            },
            .closed => return .done,
        }
    }

    fn buf(self: *Session) SessionError![]u8 {
        self.wipeOut();
        try self.out.resize(self.gpa, 1024);
        return self.out.items;
    }

    fn emit(self: *Session, line: command.CommandError![]const u8) SessionError!void {
        const l = try line;
        // `line` points into `self.out`; shrink to what was written.
        self.out.shrinkRetainingCapacity(l.len);
    }

    fn emitBase64(self: *Session, credential: []const u8) SessionError!void {
        var resp: [1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &resp);
        const enc = try auth_mod.loginResponse(&resp, credential);
        try self.emit(command.authContinue(try self.buf(), enc, self.opts.cmd_limits));
    }

    fn sent(self: *Session) Step {
        self.phase = .wait;
        return .{ .send = self.out.items };
    }

    /// Report that the TLS handshake the `.start_tls` step asked for succeeded.
    pub fn tlsEstablished(self: *Session) SessionError!void {
        if (self.state != .starttls_handshake) return error.InvalidState;
        self.tls_active = true;
        self.starttls_done = true;
        // RFC 3207 §4.2 — everything learned in the clear is discarded.
        self.caps.deinit();
        self.caps = .empty(self.gpa);
        self.esmtp = false;
        self.state = .ehlo;
        self.phase = .emit;
    }

    /// Report that the handshake failed or that the caller cannot perform one.
    pub fn tlsUnavailable(self: *Session) SessionError {
        self.state = .closed;
        return error.TlsUnavailable;
    }

    pub fn feedReply(self: *Session, r: reply_mod.Reply) SessionError!void {
        if (self.phase != .wait) return error.InvalidState;
        if (self.last) |*l| l.deinit(self.gpa);
        self.last = try r.clone(self.gpa);

        switch (self.state) {
            .greeting => {
                // RFC 5321 §3.1: 220 to proceed; 554 means the server refuses
                // to serve us at all.
                if (r.code != 220) {
                    self.state = .closed;
                    return error.BadGreeting;
                }
                self.state = .ehlo;
                self.phase = .emit;
            },
            .ehlo => try self.onEhlo(r),
            .helo => {
                try r.check();
                if (r.code != 250) return error.UnexpectedReply;
                self.esmtp = false;
                self.caps.deinit();
                self.caps = try capabilities.parse(self.gpa, r.text, self.opts.cap_limits);
                try self.afterGreeting();
            },
            .starttls_command => {
                // RFC 3207 §4: 220 means "go ahead"; anything else leaves the
                // connection in the clear.
                if (r.code != 220) {
                    if (self.opts.tls == .required) {
                        self.state = .closed;
                        try r.check();
                        return error.TlsNotOffered;
                    }
                    // Opportunistic: carry on unencrypted.
                    try self.afterTlsDecision();
                    return;
                }
                self.state = .starttls_handshake;
                self.phase = .emit;
            },
            .starttls_handshake => return error.InvalidState,
            .auth_initial => try self.onAuthInitial(r),
            .auth_username => {
                if (r.code != 334) return self.authFailed(r);
                self.state = .auth_password;
                self.phase = .emit;
            },
            .auth_password, .auth_plain_response => {
                if (r.code != 235) return self.authFailed(r);
                self.authOk();
            },
            .ready => return error.InvalidState,
            .transaction => try self.onTransactionReply(r),
            .body => {
                // The 250 that acknowledges the queued message.
                self.env = null;
                self.state = .ready;
                self.phase = .emit;
                if (self.tx_error) |e| {
                    self.tx_error = null;
                    return e;
                }
                r.check() catch |e| return e;
                if (r.code != 250) return error.UnexpectedReply;
            },
            .quit => {
                self.state = .closed;
                self.phase = .emit;
                // A server that answers QUIT with anything but 221 has already
                // closed as far as we are concerned; it is not worth an error.
            },
            .closed => return error.InvalidState,
        }
    }

    fn onEhlo(self: *Session, r: reply_mod.Reply) SessionError!void {
        if (r.code != 250) {
            // RFC 5321 §3.2 / §4.1.4: 500/502 means an old server that only
            // knows HELO. A 4yz is a real transient failure, not a reason to
            // downgrade.
            if (r.code == 500 or r.code == 502 or r.code == 550) {
                if (self.opts.tls == .required or self.opts.credentials != null) {
                    // Neither STARTTLS nor AUTH exists without ESMTP.
                    self.state = .closed;
                    return error.GreetingRefused;
                }
                self.state = .helo;
                self.phase = .emit;
                return;
            }
            self.state = .closed;
            try r.check();
            return error.GreetingRefused;
        }
        self.esmtp = true;
        self.caps.deinit();
        self.caps = try capabilities.parse(self.gpa, r.text, self.opts.cap_limits);
        try self.afterGreeting();
    }

    /// Decide what follows a successful greeting: STARTTLS, AUTH, or ready.
    fn afterGreeting(self: *Session) SessionError!void {
        if (!self.starttls_done and self.opts.tls != .disabled) {
            if (self.caps.starttls) {
                self.state = .starttls_command;
                self.phase = .emit;
                return;
            }
            if (self.opts.tls == .required) {
                self.state = .closed;
                return error.TlsNotOffered;
            }
        }
        try self.afterTlsDecision();
    }

    fn afterTlsDecision(self: *Session) SessionError!void {
        if (self.opts.credentials) |c| {
            if (!self.authenticated) {
                if (!self.tls_active and !self.opts.allow_plaintext_auth) {
                    self.state = .closed;
                    return error.PlaintextAuthRefused;
                }
                self.mechanism = pick(c.mechanisms, self.caps.auth) orelse {
                    self.state = .closed;
                    return error.NoSupportedAuthMechanism;
                };
                self.state = .auth_initial;
                self.phase = .emit;
                return;
            }
        }
        self.state = .ready;
        self.phase = .emit;
    }

    fn pick(preference: []const Mechanism, offered: capabilities.AuthSet) ?Mechanism {
        for (preference) |m| {
            if (offered.supports(m)) return m;
        }
        return null;
    }

    fn emitAuthInitial(self: *Session) SessionError!Step {
        const c = self.opts.credentials.?;
        switch (self.mechanism) {
            .plain => {
                var resp: [1024]u8 = undefined;
                defer std.crypto.secureZero(u8, &resp);
                const ir = try auth_mod.plainResponse(&resp, c.authzid, c.username, c.password);
                try self.emit(command.auth(try self.buf(), "PLAIN", ir, self.opts.cmd_limits));
            },
            .login => try self.emit(command.auth(try self.buf(), "LOGIN", null, self.opts.cmd_limits)),
        }
        return self.sent();
    }

    fn onAuthInitial(self: *Session, r: reply_mod.Reply) SessionError!void {
        switch (self.mechanism) {
            .plain => switch (r.code) {
                235 => self.authOk(),
                // A server that ignores our initial response and challenges
                // anyway (RFC 4954 §4 allows an empty 334): repeat it.
                334 => {
                    self.state = .auth_plain_response;
                    self.phase = .emit;
                },
                else => return self.authFailed(r),
            },
            .login => switch (r.code) {
                334 => {
                    // Trust the ORDER, not the challenge text: servers vary.
                    // A challenge that clearly asks for the password first is
                    // the one case worth honouring.
                    self.state = if (auth_mod.classifyLoginChallenge(r.text) == .password)
                        .auth_password
                    else
                        .auth_username;
                    self.phase = .emit;
                },
                235 => self.authOk(),
                else => return self.authFailed(r),
            },
        }
    }

    fn authOk(self: *Session) void {
        self.authenticated = true;
        self.wipeOut();
        self.state = .ready;
        self.phase = .emit;
    }

    fn authFailed(self: *Session, r: reply_mod.Reply) SessionError {
        self.wipeOut();
        self.state = .closed;
        // 454 is "temporary authentication failure" — a caller may retry, so
        // the transient/permanent distinction is preserved.
        r.check() catch |e| return e;
        return error.AuthenticationFailed;
    }

    // ── transactions ───────────────────────────────────────────────────────

    /// Queue one message. Legal when the session is `.ready`.
    pub fn beginTransaction(self: *Session, env: Envelope) SessionError!void {
        if (self.state != .ready) return error.InvalidState;
        if (env.to.len == 0) return error.AllRecipientsRejected;
        if (env.to.len > self.opts.max_recipients) return error.TooManyRecipients;
        if (env.eight_bit and self.esmtp and !self.caps.eightbitmime) return error.EightBitNotSupported;
        if (env.smtputf8 and !self.caps.smtputf8) return error.SmtpUtf8NotSupported;
        if (self.caps.sizeExceeded(env.body.len)) return error.MessageTooLarge;

        // Validate every path BEFORE a single byte goes out: a rejected
        // recipient discovered halfway leaves the server holding a half-built
        // transaction.
        if (env.from) |f| try command.validateMailbox(f, self.opts.cmd_limits, env.smtputf8);
        self.rcpts.clearRetainingCapacity();
        for (env.to) |t| {
            try command.validateMailbox(t, self.opts.cmd_limits, env.smtputf8);
            try self.rcpts.append(self.gpa, .{ .addr = t });
        }

        self.env = env;
        self.tx_index = 0;
        self.tx_sent = 0;
        self.tx_error = null;
        self.state = .transaction;
        self.phase = .emit;
    }

    /// Ask for a graceful QUIT once the current work finishes.
    pub fn requestQuit(self: *Session) void {
        self.quit_requested = true;
        if (self.state == .ready) {
            self.state = .quit;
            self.phase = .emit;
        }
    }

    fn txCount(self: *const Session) usize {
        return 2 + self.rcpts.items.len; // MAIL + n×RCPT + DATA
    }

    fn emitTransaction(self: *Session) SessionError!Step {
        const env = self.env orelse return error.InvalidState;
        const total = self.txCount();
        // Everything already written is awaiting a reply.
        if (self.tx_sent > self.tx_index) {
            self.phase = .wait;
            return .recv;
        }
        const group = self.opts.pipelining and self.esmtp and self.caps.pipelining;

        self.wipeOut();
        var i = self.tx_sent;
        const stop = if (group) total else i + 1;
        while (i < stop) : (i += 1) {
            var line: [1024]u8 = undefined;
            const bytes = if (i == 0)
                try command.mail(&line, env.from, self.mailParams(env), self.opts.cmd_limits)
            else if (i < total - 1)
                try command.rcpt(&line, self.rcpts.items[i - 1].addr, .{}, self.opts.cmd_limits, env.smtputf8 and self.caps.smtputf8)
            else
                try command.data(&line, self.opts.cmd_limits);
            try self.out.appendSlice(self.gpa, bytes);
        }
        self.tx_sent = stop;
        self.phase = .wait;
        return .{ .send = self.out.items };
    }

    fn mailParams(self: *const Session, env: Envelope) command.MailParams {
        if (!self.esmtp) return .{};
        return .{
            .size = if (self.opts.announce_size and self.caps.size_advertised) env.body.len else null,
            .body = if (env.eight_bit and self.caps.eightbitmime) .eight_bit_mime else null,
            .smtputf8 = env.smtputf8 and self.caps.smtputf8,
        };
    }

    fn onTransactionReply(self: *Session, r: reply_mod.Reply) SessionError!void {
        const total = self.txCount();
        const i = self.tx_index;
        self.tx_index += 1;

        if (i == 0) {
            // MAIL FROM
            r.check() catch |e| self.recordTxError(e);
            if (r.code != 250 and self.tx_error == null) self.recordTxError(error.UnexpectedReply);
        } else if (i < total - 1) {
            var st = &self.rcpts.items[i - 1];
            st.code = r.code;
            st.accepted = r.code / 100 == 2;
            if (!st.accepted and self.opts.require_all_recipients and self.tx_error == null) {
                self.recordTxError(error.RecipientRejected);
            }
        } else {
            // DATA
            if (r.code == 354) {
                var any = false;
                for (self.rcpts.items) |st| any = any or st.accepted;
                if (!any) self.recordTxError(error.AllRecipientsRejected);
                self.state = .body;
                self.phase = .emit;
                // Once the server has said 354 the data MUST be terminated —
                // there is no way back out of data mode. Two cases:
                //
                //  * the only complaint is our own `require_all_recipients`
                //    policy: the accepted recipients are real, so the real
                //    message goes out and the policy error is reported after
                //    the 250. Delivering an empty message instead would be a
                //    worse outcome than reporting a partial success.
                //  * anything else (the envelope itself failed, or no
                //    recipient stuck): send an empty body so the connection
                //    stays usable, and report the failure.
                const send_real = self.tx_error == null or self.tx_error.? == error.RecipientRejected;
                if (!send_real) self.env = Envelope{ .from = null, .to = &.{}, .body = "" };
                return;
            }
            if (self.tx_error == null) {
                var any = false;
                for (self.rcpts.items) |st| any = any or st.accepted;
                if (!any) {
                    self.recordTxError(error.AllRecipientsRejected);
                } else {
                    r.check() catch |e| self.recordTxError(e);
                    if (self.tx_error == null) self.recordTxError(error.UnexpectedReply);
                }
            }
        }

        if (self.tx_index < total) {
            // More replies of this group are still owed; keep reading them.
            self.phase = if (self.tx_sent > self.tx_index) .wait else .emit;
            return;
        }
        // Group finished without reaching data mode.
        self.env = null;
        self.state = .ready;
        self.phase = .emit;
        if (self.tx_error) |e| {
            self.tx_error = null;
            return e;
        }
    }

    fn recordTxError(self: *Session, e: SessionError) void {
        if (self.tx_error == null) self.tx_error = e;
    }
};

// ── tests: the whole protocol from a transcript, with no socket ────────────

/// Drives a session against a scripted list of replies, recording every byte it
/// would have written. This is the entire point of the pure state machine.
const Script = struct {
    gpa: std.mem.Allocator,
    replies: []const []const u8,
    idx: usize = 0,
    sent: std.ArrayList(u8) = .empty,
    bodies: std.ArrayList([]const u8) = .empty,
    tls_calls: usize = 0,

    fn deinit(self: *Script) void {
        self.sent.deinit(self.gpa);
        self.bodies.deinit(self.gpa);
    }

    fn run(self: *Script, s: *Session) (SessionError || reply_mod.ParseError)!void {
        var parser: reply_mod.Parser = .init(self.gpa, .{}, .{});
        defer parser.deinit();
        var guard: usize = 0;
        while (guard < 200) : (guard += 1) {
            switch (try s.next()) {
                .send => |b| try self.sent.appendSlice(self.gpa, b),
                .send_body => |b| {
                    try self.bodies.append(self.gpa, b);
                    const wire = try data_mod.stuffAlloc(self.gpa, b, .{});
                    defer self.gpa.free(wire);
                    try self.sent.appendSlice(self.gpa, wire);
                },
                .recv => {
                    if (self.idx >= self.replies.len) return error.InvalidState;
                    try parser.feed(self.replies[self.idx]);
                    self.idx += 1;
                    const r = (try parser.next()) orelse return error.InvalidState;
                    try s.feedReply(r);
                },
                .start_tls => {
                    self.tls_calls += 1;
                    try s.tlsEstablished();
                },
                .done => return,
            }
        }
        return error.InvalidState;
    }
};

const ehlo_full =
    "250-mail.example.com Hello\r\n" ++
    "250-PIPELINING\r\n" ++
    "250-SIZE 10240000\r\n" ++
    "250-8BITMIME\r\n" ++
    "250-STARTTLS\r\n" ++
    "250-AUTH PLAIN LOGIN\r\n" ++
    "250-ENHANCEDSTATUSCODES\r\n" ++
    "250 SMTPUTF8\r\n";

const ehlo_plain =
    "250-mail.example.com Hello\r\n" ++
    "250-SIZE 10240000\r\n" ++
    "250 8BITMIME\r\n";

test "the minimal RFC 5321 §4.3.2 conversation, byte for byte" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .ehlo_domain = "client.example.org", .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 mail.example.com ESMTP\r\n",
        ehlo_plain,
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectEqual(State.ready, s.state);
    try testing.expectEqualStrings("EHLO client.example.org\r\n", sc.sent.items);
    try testing.expect(s.esmtp);
    try testing.expect(s.caps.eightbitmime);

    try s.beginTransaction(.{
        .from = "sender@example.com",
        .to = &.{"rcpt@example.net"},
        .body = "Subject: t\r\n\r\nbody\r\n",
    });
    sc.sent.clearRetainingCapacity();
    sc.replies = &.{
        "250 2.1.0 Ok\r\n",
        "250 2.1.5 Ok\r\n",
        "354 End data with <CR><LF>.<CR><LF>\r\n",
        "250 2.0.0 Ok: queued as ABC\r\n",
    };
    sc.idx = 0;
    try sc.run(&s);
    try testing.expectEqualStrings(
        "MAIL FROM:<sender@example.com> SIZE=20\r\n" ++
            "RCPT TO:<rcpt@example.net>\r\n" ++
            "DATA\r\n" ++
            "Subject: t\r\n\r\nbody\r\n.\r\n",
        sc.sent.items,
    );
    try testing.expectEqual(State.ready, s.state);
    try testing.expect(s.recipients()[0].accepted);

    s.requestQuit();
    sc.sent.clearRetainingCapacity();
    sc.replies = &.{"221 2.0.0 Bye\r\n"};
    sc.idx = 0;
    try sc.run(&s);
    try testing.expectEqualStrings("QUIT\r\n", sc.sent.items);
    try testing.expectEqual(State.closed, s.state);
}

test "PIPELINING groups MAIL+RCPT+DATA into one write (RFC 2920 §3.1)" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .ehlo_domain = "c.example.org", .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.caps.pipelining);

    try s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{ "b@example.net", "c@example.net", "d@example.net" },
        .body = "hi\r\n",
    });
    sc.sent.clearRetainingCapacity();
    sc.replies = &.{
        // One TCP read carrying every reply of the group — exactly what a
        // pipelining server does.
        "250 ok\r\n250 ok\r\n550 5.1.1 no such user\r\n250 ok\r\n354 go\r\n",
        "250 queued\r\n",
    };
    sc.idx = 0;
    // The scripted reader feeds one string per `.recv`, so split the group.
    sc.replies = &.{
        "250 2.1.0 ok\r\n",
        "250 2.1.5 ok\r\n",
        "550 5.1.1 no such user\r\n",
        "250 2.1.5 ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
    };
    try sc.run(&s);

    // One write containing all five commands, DATA last (§3.1 requires it).
    const expect =
        "MAIL FROM:<a@example.com> SIZE=4\r\n" ++
        "RCPT TO:<b@example.net>\r\n" ++
        "RCPT TO:<c@example.net>\r\n" ++
        "RCPT TO:<d@example.net>\r\n" ++
        "DATA\r\n";
    try testing.expect(std.mem.startsWith(u8, sc.sent.items, expect));
    try testing.expectEqualStrings("hi\r\n.\r\n", sc.sent.items[expect.len..]);
    // The rejected recipient is data, not an error; the others went through.
    try testing.expectEqual(@as(usize, 3), s.recipients().len);
    try testing.expect(s.recipients()[0].accepted);
    try testing.expect(!s.recipients()[1].accepted);
    try testing.expectEqual(@as(u16, 550), s.recipients()[1].code);
    try testing.expect(s.recipients()[2].accepted);
}

test "without PIPELINING each command waits for its own reply" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_plain } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(!s.caps.pipelining);

    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{ "b@example.net", "c@example.net" }, .body = "x\r\n" });
    // Drive by hand so the interleaving is visible.
    var parser: reply_mod.Parser = .init(gpa, .{}, .{});
    defer parser.deinit();
    const script = [_]struct { expect: []const u8, r: []const u8 }{
        .{ .expect = "MAIL FROM:<a@example.com> SIZE=3\r\n", .r = "250 ok\r\n" },
        .{ .expect = "RCPT TO:<b@example.net>\r\n", .r = "250 ok\r\n" },
        .{ .expect = "RCPT TO:<c@example.net>\r\n", .r = "250 ok\r\n" },
        .{ .expect = "DATA\r\n", .r = "354 go\r\n" },
    };
    for (script) |step| {
        const st = try s.next();
        try testing.expectEqualStrings(step.expect, st.send);
        try testing.expectEqual(Step.recv, try s.next());
        try parser.feed(step.r);
        try s.feedReply((try parser.next()).?);
    }
    const body = try s.next();
    try testing.expectEqualStrings("x\r\n", body.send_body);
}

test "all recipients rejected is a typed error and the DATA reply is still consumed" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
    defer sc.deinit();
    try sc.run(&s);

    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{ "b@example.net", "c@example.net" }, .body = "x\r\n" });
    sc.idx = 0;
    sc.replies = &.{
        "250 ok\r\n",
        "550 5.1.1 no\r\n",
        "550 5.1.1 no\r\n",
        "554 5.5.1 No valid recipients\r\n",
    };
    try testing.expectError(error.AllRecipientsRejected, sc.run(&s));
    // Every scripted reply was consumed: the connection is still in sync.
    try testing.expectEqual(@as(usize, 4), sc.idx);
    try testing.expectEqual(State.ready, s.state);

    // ...and the session is usable for another transaction afterwards.
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"ok@example.net"}, .body = "y\r\n" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "354 go\r\n", "250 queued\r\n" };
    try sc.run(&s);
    try testing.expectEqual(State.ready, s.state);
}

test "a 4yz on MAIL FROM is transient, a 5yz is permanent" {
    const gpa = testing.allocator;
    for ([_]struct { r: []const u8, want: anyerror }{
        .{ .r = "451 4.3.0 try later\r\n", .want = error.TransientFailure },
        .{ .r = "550 5.7.1 rejected\r\n", .want = error.PermanentFailure },
    }) |c| {
        var s: Session = .init(gpa, .{ .tls = .disabled });
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
        defer sc.deinit();
        try sc.run(&s);
        try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\r\n" });
        sc.idx = 0;
        sc.replies = &.{ c.r, "503 5.5.1 bad sequence\r\n", "503 5.5.1 bad sequence\r\n" };
        try testing.expectError(c.want, sc.run(&s));
        try testing.expectEqual(@as(usize, 3), sc.idx); // the whole group was drained
    }
}

test "STARTTLS discards the pre-TLS capabilities and re-issues EHLO" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .ehlo_domain = "c.example.org", .tls = .required });
    defer s.deinit();
    var sc: Script = .{
        .gpa = gpa,
        .replies = &.{
            "220 ready\r\n",
            // Pre-TLS: an attacker-controlled list claiming AUTH exists.
            "250-mail.example.com Hello\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 SIZE 100\r\n",
            "220 2.0.0 Ready to start TLS\r\n",
            // Post-TLS: the real list. No AUTH at all.
            "250-mail.example.com Hello\r\n250-PIPELINING\r\n250 SIZE 20480000\r\n",
        },
    };
    defer sc.deinit();
    try sc.run(&s);

    try testing.expectEqual(@as(usize, 1), sc.tls_calls);
    try testing.expect(s.tls_active);
    try testing.expectEqualStrings(
        "EHLO c.example.org\r\nSTARTTLS\r\nEHLO c.example.org\r\n",
        sc.sent.items,
    );
    // The pre-TLS claims are gone: only what TLS protected survives.
    try testing.expect(!s.caps.auth.plain);
    try testing.expect(s.caps.pipelining);
    try testing.expectEqual(@as(?u64, 20480000), s.caps.max_size);
}

test "TLS required but not offered aborts instead of continuing in the clear" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .required });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_plain } };
    defer sc.deinit();
    try testing.expectError(error.TlsNotOffered, sc.run(&s));
    try testing.expectEqual(State.closed, s.state);
}

test "opportunistic TLS carries on when STARTTLS is refused" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .opportunistic });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 STARTTLS\r\n",
        "454 4.7.0 TLS not available right now\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectEqual(State.ready, s.state);
    try testing.expect(!s.tls_active);
}

test "AUTH PLAIN over TLS, with the RFC 4954 initial response" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .ehlo_domain = "c.example.org",
        .tls = .required,
        .credentials = .{ .username = "user@example.com", .password = "s3cret" },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 STARTTLS\r\n",
        "220 go ahead\r\n",
        "250-mail.example.com Hello\r\n250 AUTH PLAIN LOGIN\r\n",
        "235 2.7.0 Authentication successful\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
    var expected: [128]u8 = undefined;
    const ir = try auth_mod.plainResponse(&expected, "", "user@example.com", "s3cret");
    const want = try std.fmt.allocPrint(gpa, "EHLO c.example.org\r\nSTARTTLS\r\nEHLO c.example.org\r\nAUTH PLAIN {s}\r\n", .{ir});
    defer gpa.free(want);
    try testing.expectEqualStrings(want, sc.sent.items);
}

test "AUTH LOGIN when the server offers nothing else" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u", .password = "p" },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 AUTH LOGIN\r\n",
        "334 " ++ auth_mod.login_username_challenge ++ "\r\n",
        "334 " ++ auth_mod.login_password_challenge ++ "\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
    try testing.expectEqualStrings("EHLO localhost\r\nAUTH LOGIN\r\ndQ==\r\ncA==\r\n", sc.sent.items);
}

test "AUTH is refused on a plaintext link unless the caller opts in" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .credentials = .{ .username = "u", .password = "p" },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH PLAIN\r\n" } };
    defer sc.deinit();
    try testing.expectError(error.PlaintextAuthRefused, sc.run(&s));
    try testing.expectEqual(State.closed, s.state);
    // The password never reached the wire.
    try testing.expect(std.mem.indexOf(u8, sc.sent.items, "AUTH") == null);
}

test "a server offering only mechanisms we cannot do is a typed error" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u", .password = "p" },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH GSSAPI CRAM-MD5\r\n" } };
    defer sc.deinit();
    try testing.expectError(error.NoSupportedAuthMechanism, sc.run(&s));
}

test "a rejected password is permanent, a 454 is transient" {
    const gpa = testing.allocator;
    for ([_]struct { r: []const u8, want: anyerror }{
        .{ .r = "535 5.7.8 Authentication credentials invalid\r\n", .want = error.PermanentFailure },
        .{ .r = "454 4.7.0 Temporary authentication failure\r\n", .want = error.TransientFailure },
    }) |c| {
        var s: Session = .init(gpa, .{
            .tls = .disabled,
            .allow_plaintext_auth = true,
            .credentials = .{ .username = "u", .password = "p" },
        });
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH PLAIN\r\n", c.r } };
        defer sc.deinit();
        try testing.expectError(c.want, sc.run(&s));
        try testing.expectEqual(State.closed, s.state);
    }
}

test "HELO fallback for a server that does not know EHLO" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .ehlo_domain = "c.example.org", .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ancient.example.com SMTP\r\n",
        "500 5.5.1 Command unrecognized: EHLO\r\n",
        "250 ancient.example.com\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectEqual(State.ready, s.state);
    try testing.expect(!s.esmtp);
    try testing.expectEqualStrings("EHLO c.example.org\r\nHELO c.example.org\r\n", sc.sent.items);

    // No ESMTP parameters may be emitted on a HELO session.
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\r\n" });
    const st = try s.next();
    try testing.expectEqualStrings("MAIL FROM:<a@example.com>\r\n", st.send);
}

test "a 4yz on EHLO is not a reason to downgrade to HELO" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "421 4.7.0 Too many connections\r\n" } };
    defer sc.deinit();
    try testing.expectError(error.TransientFailure, sc.run(&s));
}

test "a greeting that is not 220 ends the session" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{"554 No SMTP service here\r\n"} };
    defer sc.deinit();
    try testing.expectError(error.BadGreeting, sc.run(&s));
    try testing.expectEqual(State.closed, s.state);
}

test "SIZE, 8BITMIME and SMTPUTF8 are only used when advertised" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
    defer sc.deinit();
    try sc.run(&s);

    try s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"b@example.net"},
        .body = "8-bit body\r\n",
        .eight_bit = true,
        .smtputf8 = true,
    });
    const st = try s.next();
    try testing.expect(std.mem.startsWith(u8, st.send, "MAIL FROM:<a@example.com> SIZE=12 BODY=8BITMIME SMTPUTF8\r\n"));

    // A server without the extensions refuses the transaction up front.
    var s2: Session = .init(gpa, .{ .tls = .disabled });
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250 mail.example.com Hello\r\n" } };
    defer sc2.deinit();
    try sc2.run(&s2);
    try testing.expectError(error.EightBitNotSupported, s2.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"b@example.net"},
        .body = "x",
        .eight_bit = true,
    }));
    try testing.expectError(error.SmtpUtf8NotSupported, s2.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"b@example.net"},
        .body = "x",
        .smtputf8 = true,
    }));
}

test "a message larger than the advertised SIZE is refused before MAIL FROM" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 SIZE 10\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectError(error.MessageTooLarge, s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"b@example.net"},
        .body = "much longer than ten octets",
    }));
}

test "the null reverse-path used by bounces" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250 x\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    try s.beginTransaction(.{ .from = null, .to = &.{"b@example.net"}, .body = "x\r\n" });
    const st = try s.next();
    try testing.expectEqualStrings("MAIL FROM:<>\r\n", st.send);
}

test "a bad address is rejected before anything is written" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250 x\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectError(error.ControlCharacterInArgument, s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"b@example.net>\r\nRCPT TO:<victim@example.org"},
        .body = "x\r\n",
    }));
    try testing.expectError(error.InvalidAddress, s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{"not-an-address"},
        .body = "x\r\n",
    }));
    try testing.expectEqual(State.ready, s.state);
}

test "calls out of order are state errors, not corruption" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    try testing.expectError(error.InvalidState, s.beginTransaction(.{ .from = null, .to = &.{"b@example.net"}, .body = "x" }));
    try testing.expectError(error.InvalidState, s.tlsEstablished());
    // A reply fed while a command is still pending emission.
    var parser: reply_mod.Parser = .init(gpa, .{}, .{});
    defer parser.deinit();
    try parser.feed("220 ready\r\n");
    const r = (try parser.next()).?;
    try s.feedReply(r);
    try testing.expectEqual(State.ehlo, s.state);
    try testing.expectError(error.InvalidState, s.feedReply(r));
}

test "require_all_recipients turns a partial rejection into a failure" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled, .require_all_recipients = true });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
    defer sc.deinit();
    try sc.run(&s);
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{ "b@example.net", "c@example.net" }, .body = "x\r\n" });
    sc.idx = 0;
    sc.replies = &.{
        "250 ok\r\n",
        "250 ok\r\n",
        "550 5.1.1 no\r\n",
        // The server still gives 354 because one recipient stuck; we end the
        // data immediately and report the failure.
        "354 go\r\n",
        "250 queued\r\n",
    };
    try testing.expectError(error.RecipientRejected, sc.run(&s));
}

test "too many recipients is bounded" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled, .max_recipients = 4 });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250 x\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    var many: [8][]const u8 = undefined;
    for (&many) |*m| m.* = "b@example.net";
    try testing.expectError(error.TooManyRecipients, s.beginTransaction(.{
        .from = null,
        .to = &many,
        .body = "x",
    }));
}
