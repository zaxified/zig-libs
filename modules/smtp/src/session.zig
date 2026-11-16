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
    /// The login name; for XOAUTH2/OAUTHBEARER the account (`user=` / `a=`).
    username: []const u8,
    /// PLAIN/LOGIN password. Unused by the OAuth mechanisms.
    password: []const u8 = "",
    /// XOAUTH2/OAUTHBEARER bearer token, as obtained by the caller (acquiring
    /// and refreshing it is not this module's job). A secret: every buffer
    /// that held it is wiped. Visible ASCII only, no spaces.
    token: []const u8 = "",
    /// SASL authorization identity; empty means "the same as `username`".
    authzid: []const u8 = "",
    /// Preference order. The first mechanism the server also offers wins.
    /// `.xoauth2` and `.oauthbearer` are opt-in: list them (and set `token`).
    /// `.scram_sha_256` is opt-in too: list it and set `Options.scram_random`.
    /// It needs a printable-ASCII `username` and `password` (no SASLprep:
    /// anything else is `error.NonAsciiCredential`) and an empty `authzid`.
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
    /// How the body's line endings are sent (`data.Options`). The default
    /// rewrites a lone LF or CR to CRLF — RFC 5321 §2.3.8 forbids sending
    /// them bare. `.newline = .strict` refuses such a body instead, for bytes
    /// that must reach the server unchanged (a message signed elsewhere).
    data: data_mod.Options = .{},
    /// Randomness for the SCRAM client nonce (RFC 5802 §5.1: unpredictable).
    /// Required when `Credentials.mechanisms` lists `.scram_sha_256` and the
    /// server offers it: without it the AUTH fails with
    /// `error.ScramNoRandomSource` before any byte is sent. Pass a CSPRNG
    /// (`std.Random` over the OS entropy source), never a seeded PRNG.
    scram_random: ?std.Random = null,
    /// TEST SEAM: use exactly this client nonce instead of `scram_random`.
    /// A fixed nonce voids SCRAM's replay protection; production leaves it
    /// null. Printable ASCII, no ','.
    scram_nonce: ?[]const u8 = null,
    /// Send the message with BDAT (RFC 3030) instead of DATA when the server
    /// advertises CHUNKING: no dot-stuffing, each chunk acknowledged. Off by
    /// default (it changes the wire format of every message to such servers);
    /// a server without CHUNKING still gets DATA.
    bdat: bool = false,
    /// Target BDAT chunk size in octets of the normalised message (a chunk may
    /// run up to one CRLF over). The last chunk is `BDAT n LAST`. Minimum 1.
    bdat_chunk: usize = 64 * 1024,
};

pub const Envelope = struct {
    /// Reverse-path. `null` is the null sender `<>` of RFC 5321 §3.6.3, which
    /// is what a bounce (DSN) must use.
    from: ?[]const u8,
    to: []const []const u8,
    /// The message, already composed (see `message.render`). The session
    /// dot-stuffs it; do not pre-stuff. Lone LF/CR line endings are rewritten
    /// to CRLF unless `Options.data.newline = .strict`, which refuses them —
    /// use that for bytes that must not change (A1 F6: a DKIM signature over
    /// LF endings silently broke). `SIZE=` announces the size after that
    /// handling (RFC 1870 §3), not `body.len`.
    body: []const u8,
    /// The body contains octets above 127 and needs RFC 6152 8BITMIME.
    eight_bit: bool = false,
    /// The envelope or headers need RFC 6531 SMTPUTF8.
    smtputf8: bool = false,
    /// RFC 3461 DSN parameters; null = none.
    dsn: ?Dsn = null,
};

/// RFC 3461 delivery status notification request. Sent only when the server
/// advertised DSN; otherwise `beginTransaction` fails with
/// `error.DsnNotSupported` before any byte goes out.
pub const Dsn = struct {
    /// `RET=` on MAIL FROM.
    ret: ?command.DsnRet = null,
    /// `ENVID=` on MAIL FROM (raw bytes; xtext-encoded on the wire).
    envid: ?[]const u8 = null,
    /// `NOTIFY=` on every RCPT TO.
    notify: command.DsnNotify = .{},
    /// `ORCPT=` per recipient, parallel to `Envelope.to`; empty for none,
    /// otherwise exactly `to.len` entries (null = no ORCPT for that one).
    orcpt: []const ?command.DsnOrcpt = &.{},

    fn requested(self: Dsn) bool {
        return self.ret != null or self.envid != null or !self.notify.isEmpty() or self.orcpt.len != 0;
    }
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
    /// DSN parameters requested but the server did not advertise DSN.
    DsnNotSupported,
    /// SCRAM chosen but neither `Options.scram_random` nor `scram_nonce` set.
    ScramNoRandomSource,
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
    /// XOAUTH2/OAUTHBEARER: the server answered with a 334 error challenge;
    /// the empty acknowledgement goes out next, then the failure reply.
    auth_oauth_error,
    /// SCRAM: client-first sent, the server-first (334) arrived; the
    /// client-final goes out next.
    auth_scram_final,
    /// SCRAM: the server signature verified; the empty response that
    /// completes the exchange goes out next, then the 235.
    auth_scram_ack,
    /// Handshake complete; idle, waiting for a transaction or QUIT.
    ready,
    /// MAIL/RCPT/DATA in flight.
    transaction,
    /// 354 received; the body goes out next.
    body,
    /// RFC 3030: the next BDAT command line and its chunk go out.
    bdat,
    /// A BDAT chunk failed: RSET goes out, its reply is consumed, then the
    /// recorded error is returned.
    bdat_rset,
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
    /// The JSON error document of a failed XOAUTH2/OAUTHBEARER exchange
    /// (decoded from the server's 334 challenge), owned.
    auth_error: ?[]u8 = null,
    /// SCRAM exchange state, alive from client-first to the final reply.
    scram: ?auth_mod.ScramClient = null,

    // BDAT state (valid while `tx_bdat`)
    /// This transaction uses BDAT (CHUNKING advertised and `Options.bdat`).
    tx_bdat: bool = false,
    bdat_stuffer: data_mod.Stuffer = .init(.{}),
    /// Offset into `env.body` already consumed by the stuffer.
    bdat_off: usize = 0,
    /// The chunk in flight, owned.
    bdat_chunk_buf: []u8 = &.{},
    bdat_last: bool = false,
    /// The BDAT line of the current chunk has been handed out; its octets follow.
    bdat_line_sent: bool = false,
    bdat_error: ?SessionError = null,

    pub fn init(gpa: std.mem.Allocator, opts: Options) Session {
        return .{ .gpa = gpa, .opts = opts, .caps = .empty(gpa) };
    }

    pub fn deinit(self: *Session) void {
        self.caps.deinit();
        self.wipeOut();
        self.out.deinit(self.gpa);
        self.rcpts.deinit(self.gpa);
        if (self.auth_error) |e| self.gpa.free(e);
        self.scramDone();
        self.gpa.free(self.bdat_chunk_buf);
        if (self.last) |*l| l.deinit(self.gpa);
        self.* = undefined;
    }

    /// After a failed XOAUTH2/OAUTHBEARER login: the server's JSON error
    /// document (RFC 7628 §3.2.2, e.g. `{"status":"invalid_token",...}`), valid
    /// until `deinit`. Null when there was none or it was not valid base64.
    pub fn authErrorJson(self: *const Session) ?[]const u8 {
        return self.auth_error;
    }

    fn storeAuthError(self: *Session, challenge: []const u8) SessionError!void {
        if (self.auth_error) |e| self.gpa.free(e);
        self.auth_error = null;
        const trimmed = std.mem.trim(u8, challenge, " \t");
        const n = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return;
        const out = try self.gpa.alloc(u8, n);
        std.base64.standard.Decoder.decode(out, trimmed) catch {
            self.gpa.free(out);
            return;
        };
        self.auth_error = out;
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
            .auth_oauth_error => {
                // RFC 7628 §3.2.3 / the XOAUTH2 convention: acknowledge the
                // error challenge so the server can send its final failure.
                const ack: []const u8 = if (self.mechanism == .oauthbearer) auth_mod.oauthbearer_error_ack else "";
                try self.emit(command.authContinue(try self.buf(), ack, self.opts.cmd_limits));
                return self.sent();
            },
            .auth_scram_final => return self.emitScramFinal() catch |e| {
                self.scramAbort();
                return e;
            },
            .auth_scram_ack => {
                try self.emit(command.authContinue(try self.buf(), "", self.opts.cmd_limits));
                return self.sent();
            },
            .bdat => return self.emitBdat(),
            .bdat_rset => {
                try self.emit(command.rset(try self.buf(), self.opts.cmd_limits));
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
            // Whatever follows our acknowledgement is the end: even a 235
            // here is not a login we asked for.
            .auth_oauth_error => return self.authFailed(r),
            .auth_scram_final => try self.onScramFinal(r),
            .auth_scram_ack => {
                if (r.code != 235) return self.authFailed(r);
                self.authOk();
            },
            .bdat => try self.onBdatReply(r),
            .bdat_rset => {
                // Whatever RSET answers, the chunk's failure is what we report.
                self.state = .ready;
                self.phase = .emit;
                self.env = null;
                const e = self.bdat_error orelse error.UnexpectedReply;
                self.bdat_error = null;
                return e;
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
            .xoauth2, .oauthbearer => try self.emitOauthInitial(c),
            .scram_sha_256 => self.emitScramInitial(c) catch |e| {
                self.scramAbort();
                return e;
            },
        }
        return self.sent();
    }

    /// SCRAM client-first as the AUTH initial response (RFC 4954 §4).
    fn emitScramInitial(self: *Session, c: Credentials) SessionError!void {
        if (c.authzid.len != 0) return error.InvalidCredential; // GS2 header is `n,,`
        var nonce_buf: [24]u8 = undefined;
        const nonce: []const u8 = if (self.opts.scram_nonce) |n| n else blk: {
            const rnd = self.opts.scram_random orelse return error.ScramNoRandomSource;
            var raw: [18]u8 = undefined;
            rnd.bytes(&raw);
            break :blk std.base64.standard.Encoder.encode(&nonce_buf, &raw);
        };
        self.scramDone();
        self.scram = try auth_mod.ScramClient.init(self.gpa, c.username, nonce);
        var raw: [1024]u8 = undefined;
        const first = try self.scram.?.clientFirst(&raw);
        var enc: [1400]u8 = undefined;
        const ir = try auth_mod.loginResponse(&enc, first);
        try self.emit(command.auth(try self.buf(), "SCRAM-SHA-256", ir, self.opts.cmd_limits));
    }

    /// client-final from the server-first the last 334 carried.
    fn emitScramFinal(self: *Session) SessionError!Step {
        const c = self.opts.credentials.?;
        const sc = &self.scram.?;
        const text = (self.last orelse return error.InvalidState).reply.text;
        var sf_buf: [4096]u8 = undefined;
        const sf = try auth_mod.decodeChallenge(&sf_buf, text);
        var raw: [4608]u8 = undefined;
        defer std.crypto.secureZero(u8, &raw);
        const fin = try sc.clientFinal(&raw, sf, c.password);
        var enc: [6200]u8 = undefined;
        defer std.crypto.secureZero(u8, &enc);
        const ir = try auth_mod.loginResponse(&enc, fin);
        var lim = self.opts.cmd_limits;
        lim.max_command_line = @max(lim.max_command_line, 12288);
        self.wipeOut();
        try self.out.resize(self.gpa, ir.len + 64);
        try self.emit(command.authContinue(self.out.items, ir, lim));
        return self.sent();
    }

    /// The server's final message, in the 334 (normal) or in the 235 (RFC 4954
    /// §4 additional data). A signature that does not verify fails the AUTH.
    fn onScramFinal(self: *Session, r: reply_mod.Reply) SessionError!void {
        if (r.code != 334 and r.code != 235) return self.authFailed(r);
        self.verifyScramFinal(r.text) catch |e| {
            self.scramAbort();
            // A 235 whose text is not a signature (the usual "2.7.0 ok") is a
            // server that never proved itself, not a malformed challenge.
            return if (r.code == 235) error.ServerSignatureMismatch else e;
        };
        if (r.code == 235) return self.authOk();
        self.state = .auth_scram_ack;
        self.phase = .emit;
    }

    fn verifyScramFinal(self: *Session, text: []const u8) SessionError!void {
        var buf_: [512]u8 = undefined;
        const dec = try auth_mod.decodeChallenge(&buf_, text);
        try self.scram.?.verifyServerFinal(dec);
    }

    fn scramDone(self: *Session) void {
        if (self.scram) |*sc| sc.deinit();
        self.scram = null;
    }

    /// A SCRAM exchange that cannot continue: the session is over.
    fn scramAbort(self: *Session) void {
        self.scramDone();
        self.wipeOut();
        self.state = .closed;
    }

    /// The OAuth initial response. Bearer tokens routinely exceed the 512-octet
    /// default line, so the line ceiling is RFC 4954 §4's 12288 for AUTH, and
    /// the buffers are sized to the token. Every buffer that held it is wiped.
    fn emitOauthInitial(self: *Session, c: Credentials) SessionError!void {
        const raw_len = if (self.mechanism == .xoauth2)
            auth_mod.xoauth2RawLen(c.username, c.token)
        else
            auth_mod.oauthbearerRawLen(c.username, c.token);
        const enc_len = auth_mod.encodedLen(raw_len);
        if (enc_len > 12288) return error.NoSpaceLeft;
        const scratch = try self.gpa.alloc(u8, raw_len);
        defer self.gpa.free(scratch);
        const enc = try self.gpa.alloc(u8, enc_len);
        defer self.gpa.free(enc);
        defer std.crypto.secureZero(u8, enc);
        defer std.crypto.secureZero(u8, scratch);
        const ir = if (self.mechanism == .xoauth2)
            try auth_mod.xoauth2Response(enc, scratch, c.username, c.token)
        else
            try auth_mod.oauthbearerResponse(enc, scratch, c.username, c.token);
        var lim = self.opts.cmd_limits;
        lim.max_command_line = @max(lim.max_command_line, 12288);
        self.wipeOut();
        try self.out.resize(self.gpa, enc_len + 64);
        try self.emit(command.auth(self.out.items, self.mechanism.name(), ir, lim));
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
            .xoauth2, .oauthbearer => switch (r.code) {
                235 => self.authOk(),
                334 => {
                    // The error document, base64 JSON. Keep it for the caller
                    // and acknowledge it (`.auth_oauth_error`).
                    try self.storeAuthError(r.text);
                    self.state = .auth_oauth_error;
                    self.phase = .emit;
                },
                else => return self.authFailed(r),
            },
            .scram_sha_256 => switch (r.code) {
                334 => {
                    self.state = .auth_scram_final;
                    self.phase = .emit;
                },
                // Success before any proof was exchanged: nothing verified the
                // server, so it is not a login we asked for.
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
        self.scramDone();
        self.authenticated = true;
        self.wipeOut();
        self.state = .ready;
        self.phase = .emit;
    }

    fn authFailed(self: *Session, r: reply_mod.Reply) SessionError {
        self.scramDone();
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
        if (env.dsn) |d| {
            if (d.requested()) {
                // RFC 3461 §4: the parameters exist only when DSN was offered.
                if (!self.esmtp or !self.caps.dsn) return error.DsnNotSupported;
                if (d.orcpt.len != 0 and d.orcpt.len != env.to.len) return error.InvalidDsnParameter;
            }
        }
        // The size of what goes on the wire, not of the slice handed in: LF
        // endings grow to CRLF (A1 F6 — 100 000 B of LF text was announced
        // as SIZE=100000 and sent as 102 000, past a 100 000 limit). Also the
        // point where `.strict` refuses a bare LF/CR, before MAIL FROM.
        const size = try data_mod.messageSize(env.body, self.opts.data);
        if (self.caps.sizeExceeded(size)) return error.MessageTooLarge;
        const use_bdat = self.opts.bdat and self.esmtp and self.caps.chunking;
        if (use_bdat) {
            // BDAT cannot be abandoned half way the way a refused body can be
            // replaced by an empty one, so everything the stuffer would refuse
            // (an over-long line) is found now, before MAIL FROM.
            var sink_buf: [64]u8 = undefined;
            var sink: std.Io.Writer.Discarding = .init(&sink_buf);
            var st: data_mod.Stuffer = .initChunked(self.opts.data);
            st.write(&sink.writer, env.body) catch |e| switch (e) {
                error.WriteFailed => unreachable, // Discarding never fails
                else => |x| return x,
            };
            st.finishChunked(&sink.writer) catch |e| switch (e) {
                error.WriteFailed => unreachable,
                else => |x| return x,
            };
        }

        // Validate every path BEFORE a single byte goes out: a rejected
        // recipient discovered halfway leaves the server holding a half-built
        // transaction.
        if (env.from) |f| try command.validateMailbox(f, self.opts.cmd_limits, env.smtputf8);
        self.rcpts.clearRetainingCapacity();
        for (env.to) |t| {
            try command.validateMailbox(t, self.opts.cmd_limits, env.smtputf8);
            try self.rcpts.append(self.gpa, .{ .addr = t });
        }
        if (env.dsn != null) {
            // Dry-run the lines so a bad DSN parameter is refused before MAIL
            // FROM goes out, not halfway through the transaction.
            var line: [1024]u8 = undefined;
            _ = try command.mail(&line, env.from, self.mailParams(env), self.opts.cmd_limits);
            for (env.to, 0..) |t, i| {
                _ = try command.rcpt(&line, t, self.rcptParams(env, i), self.opts.cmd_limits, env.smtputf8 and self.caps.smtputf8);
            }
        }

        self.env = env;
        self.tx_index = 0;
        self.tx_sent = 0;
        self.tx_error = null;
        self.tx_bdat = use_bdat;
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
        // MAIL + n×RCPT + DATA (BDAT has no DATA command to wait on)
        return (if (self.tx_bdat) @as(usize, 1) else 2) + self.rcpts.items.len;
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
            else if (i < self.rcptEnd())
                try command.rcpt(&line, self.rcpts.items[i - 1].addr, self.rcptParams(env, i - 1), self.opts.cmd_limits, env.smtputf8 and self.caps.smtputf8)
            else
                try command.data(&line, self.opts.cmd_limits);
            try self.out.appendSlice(self.gpa, bytes);
        }
        self.tx_sent = stop;
        self.phase = .wait;
        return .{ .send = self.out.items };
    }

    /// Index one past the last RCPT in the command sequence.
    fn rcptEnd(self: *const Session) usize {
        return if (self.tx_bdat) self.txCount() else self.txCount() - 1;
    }

    fn mailParams(self: *const Session, env: Envelope) command.MailParams {
        if (!self.esmtp) return .{};
        return .{
            // `beginTransaction` already ran `messageSize` on this body with
            // these options, so it cannot fail here.
            .size = if (self.opts.announce_size and self.caps.size_advertised)
                data_mod.messageSize(env.body, self.opts.data) catch unreachable
            else
                null,
            .body = if (env.eight_bit and self.caps.eightbitmime) .eight_bit_mime else null,
            .smtputf8 = env.smtputf8 and self.caps.smtputf8,
            .ret = if (env.dsn) |d| d.ret else null,
            .envid = if (env.dsn) |d| d.envid else null,
        };
    }

    fn rcptParams(self: *const Session, env: Envelope, i: usize) command.RcptParams {
        _ = self;
        const d = env.dsn orelse return .{};
        return .{
            .notify = d.notify,
            .orcpt = if (i < d.orcpt.len) d.orcpt[i] else null,
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
        } else if (i < self.rcptEnd()) {
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
        if (self.tx_bdat) {
            var any = false;
            for (self.rcpts.items) |st| any = any or st.accepted;
            if (!any) self.recordTxError(error.AllRecipientsRejected);
            // As for DATA: a lone `require_all_recipients` complaint still
            // delivers to the recipients that were accepted.
            if (any and (self.tx_error == null or self.tx_error.? == error.RecipientRejected)) {
                self.bdat_stuffer = .initChunked(self.opts.data);
                self.bdat_off = 0;
                self.bdat_last = false;
                self.bdat_line_sent = false;
                self.state = .bdat;
                self.phase = .emit;
                return;
            }
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

    /// Cut the next chunk out of the body (normalised, not dot-stuffed).
    fn nextChunk(self: *Session) SessionError!void {
        const body = (self.env orelse return error.InvalidState).body;
        const want = @max(self.opts.bdat_chunk, 1);
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        errdefer aw.deinit();
        const st = &self.bdat_stuffer;
        while (aw.written().len < want and self.bdat_off < body.len) {
            st.write(&aw.writer, body[self.bdat_off..][0..1]) catch |e| switch (e) {
                error.WriteFailed => return error.OutOfMemory,
                else => |x| return x,
            };
            self.bdat_off += 1;
        }
        self.bdat_last = self.bdat_off >= body.len;
        if (self.bdat_last) st.finishChunked(&aw.writer) catch |e| switch (e) {
            error.WriteFailed => return error.OutOfMemory,
            else => |x| return x,
        };
        self.gpa.free(self.bdat_chunk_buf);
        self.bdat_chunk_buf = &.{};
        self.bdat_chunk_buf = try aw.toOwnedSlice();
    }

    /// `BDAT n [LAST]` first, then the chunk's octets as a second `send`.
    fn emitBdat(self: *Session) SessionError!Step {
        if (self.bdat_line_sent) {
            self.bdat_line_sent = false;
            self.phase = .wait;
            return .{ .send = self.bdat_chunk_buf };
        }
        try self.nextChunk();
        try self.emit(command.bdat(try self.buf(), self.bdat_chunk_buf.len, self.bdat_last, self.opts.cmd_limits));
        self.bdat_line_sent = true;
        return .{ .send = self.out.items }; // phase stays `.emit`: the chunk follows
    }

    /// The reply to one chunk (RFC 3030 §3, §4.3). Nothing is pipelined past a
    /// chunk, so a failure here means no later chunk was sent; RSET then clears
    /// the server's BDAT state before the error is reported.
    fn onBdatReply(self: *Session, r: reply_mod.Reply) SessionError!void {
        if (r.code == 250) {
            if (!self.bdat_last) {
                self.phase = .emit;
                return;
            }
            self.env = null;
            self.state = .ready;
            self.phase = .emit;
            if (self.tx_error) |e| {
                self.tx_error = null;
                return e;
            }
            return;
        }
        const err: SessionError = if (r.check()) |_| error.UnexpectedReply else |e| e;
        self.bdat_error = err;
        self.state = .bdat_rset;
        self.phase = .emit;
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

test "F9: capabilities are cleared the instant tlsEstablished() returns, before the post-TLS EHLO reply arrives" {
    // The audit worried that a caller driving `Session` itself (rather than
    // through the full happy-path flow) could call `serverCapabilities()` in
    // the window between `tlsEstablished()` and the post-TLS EHLO reply and
    // see the attacker's pre-TLS list — and that the existing regression
    // test ("STARTTLS discards the pre-TLS capabilities...", above) does not
    // actually prove the discard, because `onEhlo` re-clears `caps` anyway
    // once the real reply lands. This test inspects state right INSIDE that
    // window, before any post-TLS reply is fed, which the other test cannot.
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .ehlo_domain = "c.example.org", .tls = .required });
    defer s.deinit();
    var parser: reply_mod.Parser = .init(gpa, .{}, .{});
    defer parser.deinit();
    const replies = [_][]const u8{
        "220 ready\r\n",
        // Pre-TLS, attacker-shaped: claims AUTH exists.
        "250-mail.example.com Hello\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 SIZE 100\r\n",
        "220 2.0.0 Ready to start TLS\r\n",
    };
    var idx: usize = 0;
    var guard: usize = 0;
    while (guard < 200) : (guard += 1) {
        switch (try s.next()) {
            .send => {},
            .send_body => return error.TestUnexpectedResult,
            .recv => {
                try parser.feed(replies[idx]);
                idx += 1;
                const r = (try parser.next()).?;
                try s.feedReply(r);
            },
            .start_tls => {
                try s.tlsEstablished();
                // No post-TLS EHLO reply has been fed yet -- this IS the window.
                try testing.expect(!s.esmtp);
                try testing.expect(!s.caps.auth.plain);
                try testing.expectEqual(@as(?u64, null), s.caps.max_size);
                return;
            },
            .done => return error.TestUnexpectedResult,
        }
    }
    return error.TestUnexpectedResult;
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
    const want = try gpa.print("EHLO c.example.org\r\nSTARTTLS\r\nEHLO c.example.org\r\nAUTH PLAIN {s}\r\n", .{ir});
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
    try testing.expect(std.mem.find(u8, sc.sent.items, "AUTH") == null);
}

test "the command buffer's spare capacity holds no AUTH line once AUTH succeeds (A1 F14)" {
    // `wipeOut` zeroes `self.out` before clearing it; in ReleaseFast
    // `clearRetainingCapacity` alone keeps every byte, so the base64
    // credentials would sit in the buffer until a longer command happened to
    // overwrite them. The F5 probe below watches the stack, not this heap
    // buffer. Debug and ReleaseSafe poison the cleared bytes (`@memset` to
    // `undefined`) and hide the leak, so the test skips wherever its own
    // control cannot see one.
    const gpa = testing.allocator;
    {
        var control: std.ArrayList(u8) = .empty;
        defer control.deinit(gpa);
        try control.appendSlice(gpa, "AUTH PLAIN control\r\n");
        control.clearRetainingCapacity();
        if (std.mem.find(u8, control.allocatedSlice(), "AUTH") == null) return error.SkipZigTest;
    }

    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "user@example.com", .password = "s3cret-F14" },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 AUTH PLAIN\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);

    var ir_buf: [128]u8 = undefined;
    const ir = try auth_mod.plainResponse(&ir_buf, "", "user@example.com", "s3cret-F14");
    // Control: the credentials did go through this buffer.
    try testing.expect(std.mem.find(u8, sc.sent.items, ir) != null);
    try testing.expectEqual(@as(usize, 0), s.out.items.len);
    const spare = s.out.allocatedSlice();
    try testing.expect(spare.len >= ir.len);
    try testing.expect(std.mem.find(u8, spare, ir) == null);
    try testing.expect(std.mem.find(u8, spare, "AUTH") == null);
}

// ── F5: credential zeroization, verified on the artifact ────────────────────
//
// `secureZero` calls exist (`auth.plainResponse` `defer`s one over its base64
// staging buffer; `wipeOut` above zeroizes `self.out`), but nothing in the
// suite read memory back before this test: deleting either call left the
// whole suite green (F5, the A1 audit report for `smtp`). Method:
// scrub a stack region with 0xAA, call the function under test AT THE SAME
// CALL DEPTH so its frame lands inside that region, then re-enter a frame of
// the same size and count occurrences of the plaintext password. A positive
// control that deliberately leaves the needle behind proves the scan can see
// a leak at all -- Debug and ReleaseSafe fill `undefined` with a poison
// pattern and would make even that positive control read 0, so this only
// runs in ReleaseFast.

const f5_pass = "Q7x-N33dl3-P4ssw0rd-Zx9";
const f5_user = "U5r-N33dl3-Zx9";
const f5_region = 256 * 1024;

fn f5Count(hay: []const u8, needle: []const u8) usize {
    if (needle.len == 0 or needle.len > hay.len) return 0;
    var n: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.mem.eql(u8, hay[i..][0..needle.len], needle)) n += 1;
    }
    return n;
}

noinline fn f5Scrub() void {
    var b: [f5_region]u8 = undefined;
    @memset(&b, 0xAA);
    std.mem.doNotOptimizeAway(&b);
}

noinline fn f5Scan() usize {
    var b: [f5_region]u8 = undefined;
    std.mem.doNotOptimizeAway(&b);
    return f5Count(&b, f5_pass);
}

noinline fn f5LeakControl() void {
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..f5_pass.len], f5_pass);
    std.mem.doNotOptimizeAway(&buf);
}

noinline fn f5CallPlainResponse() void {
    var out: [256]u8 = undefined;
    const r = auth_mod.plainResponse(&out, "", f5_user, f5_pass) catch return;
    std.mem.doNotOptimizeAway(r.ptr);
    std.crypto.secureZero(u8, &out); // the caller's own copy is the caller's job
}

noinline fn f5DriveSessionAuth(gpa: std.mem.Allocator) void {
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = f5_user, .password = f5_pass },
    });
    defer s.deinit();
    var p: reply_mod.Parser = .init(gpa, .{}, .{});
    defer p.deinit();
    const script = [_][]const u8{ "220 ready\r\n", "250-x\r\n250 AUTH PLAIN\r\n", "235 ok\r\n" };
    var idx: usize = 0;
    var guard: usize = 0;
    while (guard < 20) : (guard += 1) {
        const step = s.next() catch return;
        switch (step) {
            .send => |b| std.mem.doNotOptimizeAway(b.ptr),
            .recv => {
                if (idx >= script.len) return;
                p.feed(script[idx]) catch return;
                idx += 1;
                const r = (p.next() catch return) orelse return;
                s.feedReply(r) catch return;
            },
            .done => return,
            else => return,
        }
    }
}

test "F5 (ReleaseFast only): plaintext password does not survive on the dead stack after AUTH" {
    if (@import("builtin").mode != .fast) return error.SkipZigTest;
    const gpa = testing.allocator;

    f5Scrub();
    f5LeakControl();
    const positive = f5Scan();
    try testing.expect(positive > 0); // the scan itself must be able to see a leak

    f5Scrub();
    f5CallPlainResponse();
    try testing.expectEqual(@as(usize, 0), f5Scan());

    f5Scrub();
    f5DriveSessionAuth(gpa);
    try testing.expectEqual(@as(usize, 0), f5Scan());
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

test "SIZE counts the body as sent, not as given; strict refuses a bare LF up front (A1 F6)" {
    const gpa = testing.allocator;
    {
        // 10 bytes of LF text is 15 on the wire: over a SIZE 10 server.
        var s: Session = .init(gpa, .{ .tls = .disabled });
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 SIZE 10\r\n" } };
        defer sc.deinit();
        try sc.run(&s);
        try testing.expectError(error.MessageTooLarge, s.beginTransaction(.{
            .from = "a@example.com",
            .to = &.{"b@example.net"},
            .body = "a\nb\nc\nd\ne\n",
        }));
    }
    {
        // SIZE= announces the CRLF size.
        var s: Session = .init(gpa, .{ .tls = .disabled });
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_plain } };
        defer sc.deinit();
        try sc.run(&s);
        try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\ny\n" });
        const st = try s.next();
        try testing.expectEqualStrings("MAIL FROM:<a@example.com> SIZE=6\r\n", st.send);
    }
    {
        var s: Session = .init(gpa, .{ .tls = .disabled, .data = .{ .newline = .strict } });
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_plain } };
        defer sc.deinit();
        try sc.run(&s);
        try testing.expectError(error.BareLineFeed, s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\ny\n" }));
    }
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

// ── OAuth bearer mechanisms and DSN parameters (2026-11-16) ────────────────

test "XOAUTH2 login with a token past the 512-octet default line" {
    const gpa = testing.allocator;
    // A Microsoft-sized JWT-ish token: 1500 visible octets.
    const tok = try gpa.alloc(u8, 1500);
    defer gpa.free(tok);
    for (tok, 0..) |*c, i| c.* = "abcdefghijklmnopqrstuvwxyz0123456789.-_"[i % 39];
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u@example.com", .token = tok, .mechanisms = &.{ .xoauth2, .plain } },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 AUTH PLAIN XOAUTH2\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
    const scratch = try gpa.alloc(u8, auth_mod.xoauth2RawLen("u@example.com", tok));
    defer gpa.free(scratch);
    const enc = try gpa.alloc(u8, auth_mod.encodedLen(scratch.len));
    defer gpa.free(enc);
    const ir = try auth_mod.xoauth2Response(enc, scratch, "u@example.com", tok);
    const want = try gpa.print("EHLO localhost\r\nAUTH XOAUTH2 {s}\r\n", .{ir});
    defer gpa.free(want);
    try testing.expectEqualStrings(want, sc.sent.items);
    // The command buffer that held the encoded token is wiped and emptied
    // after login (the spare-capacity scan is the ReleaseFast F13 test).
    try testing.expectEqual(@as(usize, 0), s.out.items.len);
    try testing.expect(s.authErrorJson() == null);
}

test "OAUTHBEARER login, and it is only used when the server offers it" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u@example.com", .token = "tok", .mechanisms = &.{.oauthbearer} },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-mail.example.com Hello\r\n250 AUTH PLAIN OAUTHBEARER\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
    // base64("n,a=u@example.com,\x01auth=Bearer tok\x01\x01")
    var scratch: [64]u8 = undefined;
    var enc: [128]u8 = undefined;
    const ir = try auth_mod.oauthbearerResponse(&enc, &scratch, "u@example.com", "tok");
    const want = try gpa.print("EHLO localhost\r\nAUTH OAUTHBEARER {s}\r\n", .{ir});
    defer gpa.free(want);
    try testing.expectEqualStrings(want, sc.sent.items);

    // The server does not list OAUTHBEARER: nothing is sent, typed error.
    var s2: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u", .token = "tok", .mechanisms = &.{ .oauthbearer, .xoauth2 } },
    });
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH PLAIN LOGIN\r\n" } };
    defer sc2.deinit();
    try testing.expectError(error.NoSupportedAuthMechanism, sc2.run(&s2));
    try testing.expectEqualStrings("EHLO localhost\r\n", sc2.sent.items);

    // An invalid token (a space) is refused locally, nothing leaves.
    var s3: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u", .token = "bad token", .mechanisms = &.{.xoauth2} },
    });
    defer s3.deinit();
    var sc3: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH XOAUTH2\r\n" } };
    defer sc3.deinit();
    try testing.expectError(error.InvalidCredential, sc3.run(&s3));
    try testing.expectEqualStrings("EHLO localhost\r\n", sc3.sent.items);
}

test "OAuth mechanisms are refused on a plaintext link like PLAIN" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .credentials = .{ .username = "u", .token = "tok", .mechanisms = &.{.xoauth2} },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH XOAUTH2\r\n" } };
    defer sc.deinit();
    try testing.expectError(error.PlaintextAuthRefused, sc.run(&s));
}

test "XOAUTH2 error challenge: empty response sent, JSON surfaced" {
    const gpa = testing.allocator;
    const json = "{\"status\":\"401\",\"schemes\":\"Bearer\",\"scope\":\"https://mail.google.com/\"}";
    var jb: [200]u8 = undefined;
    const json_b64 = std.base64.standard.Encoder.encode(&jb, json);
    const challenge = try gpa.print("334 {s}\r\n", .{json_b64});
    defer gpa.free(challenge);
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u@example.com", .token = "tok", .mechanisms = &.{.xoauth2} },
    });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        "250-x\r\n250 AUTH XOAUTH2\r\n",
        challenge,
        "535 5.7.8 Username and Password not accepted\r\n",
    } };
    defer sc.deinit();
    try testing.expectError(error.PermanentFailure, sc.run(&s));
    try testing.expectEqualStrings(json, s.authErrorJson().?);
    try testing.expect(!s.authenticated);
    try testing.expectEqual(State.closed, s.state);
    // EHLO, AUTH XOAUTH2 <ir>, then the EMPTY response line.
    try testing.expect(std.mem.endsWith(u8, sc.sent.items, "\r\n\r\n"));
    try testing.expectEqual(@as(usize, 0), s.out.items.len);
}

test "OAUTHBEARER error challenge is acknowledged with a single \\x01" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "", .token = "tok", .mechanisms = &.{.oauthbearer} },
    });
    defer s.deinit();
    var sc: Script = .{
        .gpa = gpa,
        .replies = &.{
            "220 ready\r\n",
            "250-x\r\n250 AUTH OAUTHBEARER\r\n",
            "334 eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=\r\n", // {"status":"invalid_token"}
            "535 5.7.8 bad\r\n",
        },
    };
    defer sc.deinit();
    try testing.expectError(error.PermanentFailure, sc.run(&s));
    try testing.expectEqualStrings("{\"status\":\"invalid_token\"}", s.authErrorJson().?);
    try testing.expect(std.mem.endsWith(u8, sc.sent.items, "\r\nAQ==\r\n"));

    // A 334 that is not base64 is still acknowledged; no JSON is kept.
    var s2: Session = .init(gpa, .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "u", .token = "tok", .mechanisms = &.{.oauthbearer} },
    });
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 AUTH OAUTHBEARER\r\n", "334 !!!\r\n", "535 no\r\n" } };
    defer sc2.deinit();
    try testing.expectError(error.PermanentFailure, sc2.run(&s2));
    try testing.expect(s2.authErrorJson() == null);
    try testing.expect(std.mem.endsWith(u8, sc2.sent.items, "\r\nAQ==\r\n"));
}

test "DSN parameters go out when DSN is advertised" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-mail.example.com Hello\r\n250-PIPELINING\r\n250 DSN\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    try s.beginTransaction(.{
        .from = "a@example.com",
        .to = &.{ "b@example.net", "c@example.net" },
        .body = "x\r\n",
        .dsn = .{
            .ret = .hdrs,
            .envid = "id=1+2",
            .notify = .{ .success = true, .failure = true },
            .orcpt = &.{ .{ .address = "b+x@example.net" }, null },
        },
    });
    const st = try s.next();
    try testing.expectEqualStrings(
        "MAIL FROM:<a@example.com> RET=HDRS ENVID=id+3D1+2B2\r\n" ++
            "RCPT TO:<b@example.net> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;b+2Bx@example.net\r\n" ++
            "RCPT TO:<c@example.net> NOTIFY=SUCCESS,FAILURE\r\n" ++
            "DATA\r\n",
        st.send,
    );
}

test "DSN parameters are refused locally without the DSN capability, and bad ones before MAIL" {
    const gpa = testing.allocator;
    // No DSN advertised.
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_plain } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expectError(error.DsnNotSupported, s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x", .dsn = .{ .ret = .full } }));
    try testing.expectError(error.DsnNotSupported, s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x", .dsn = .{ .notify = .{ .never = true } } }));
    // An all-default Dsn requests nothing and is accepted.
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x", .dsn = .{} });

    // HELO-only server: ESMTP parameters do not exist.
    var h: Session = .init(gpa, .{ .tls = .disabled });
    defer h.deinit();
    var sch: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "502 no\r\n", "250 hi\r\n" } };
    defer sch.deinit();
    try sch.run(&h);
    try testing.expectError(error.DsnNotSupported, h.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x", .dsn = .{ .ret = .full } }));

    // DSN advertised: invalid parameters are errors up front, state intact.
    var d: Session = .init(gpa, .{ .tls = .disabled });
    defer d.deinit();
    var scd: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", "250-x\r\n250 DSN\r\n" } };
    defer scd.deinit();
    try scd.run(&d);
    const to = &[_][]const u8{"b@example.net"};
    try testing.expectError(error.InvalidDsnParameter, d.beginTransaction(.{ .from = "a@example.com", .to = to, .body = "x", .dsn = .{ .notify = .{ .never = true, .failure = true } } }));
    try testing.expectError(error.InvalidDsnParameter, d.beginTransaction(.{ .from = "a@example.com", .to = to, .body = "x", .dsn = .{ .envid = "" } }));
    try testing.expectError(error.InvalidDsnParameter, d.beginTransaction(.{ .from = "a@example.com", .to = to, .body = "x", .dsn = .{ .orcpt = &.{ null, null } } }));
    try testing.expectEqual(State.ready, d.state);
}

// ── SCRAM-SHA-256 (RFC 5802/7677) ──────────────────────────────────────────

fn b64lit(comptime s: []const u8) *const [std.base64.standard.Encoder.calcSize(s.len)]u8 {
    const r = comptime blk: {
        var out: [std.base64.standard.Encoder.calcSize(s.len)]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&out, s);
        break :blk out;
    };
    return &r;
}

const scram_ehlo = "250-mail.example.com\r\n250 AUTH SCRAM-SHA-256 PLAIN\r\n";
const scram_sf = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const scram_cf = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const scram_sv = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

fn scramOpts(password: []const u8) Options {
    return .{
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "user", .password = password, .mechanisms = &.{ .scram_sha_256, .plain } },
        .scram_nonce = "rOprNGfwEbeRWgbNEkqO", // test seam
    };
}

test "SCRAM-SHA-256 login: the RFC 7677 §3 exchange on the wire" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, scramOpts("pencil"));
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        scram_ehlo,
        "334 " ++ b64lit(scram_sf) ++ "\r\n",
        "334 " ++ b64lit(scram_sv) ++ "\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
    try testing.expectEqual(State.ready, s.state);
    try testing.expect(s.scram == null);
    try testing.expectEqualStrings(
        "EHLO localhost\r\nAUTH SCRAM-SHA-256 " ++ b64lit("n,,n=user,r=rOprNGfwEbeRWgbNEkqO") ++ "\r\n" ++
            b64lit(scram_cf) ++ "\r\n" ++ "\r\n",
        sc.sent.items,
    );
}

test "SCRAM-SHA-256: a wrong server signature fails the AUTH and closes the session" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, scramOpts("pencil"));
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{
        "220 ready\r\n",
        scram_ehlo,
        "334 " ++ b64lit(scram_sf) ++ "\r\n",
        "334 " ++ b64lit("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95H4=") ++ "\r\n",
        "235 2.7.0 ok\r\n",
    } };
    defer sc.deinit();
    try testing.expectError(error.ServerSignatureMismatch, sc.run(&s));
    try testing.expect(!s.authenticated);
    try testing.expectEqual(State.closed, s.state);
    // the completing empty line was never sent
    try testing.expect(!std.mem.endsWith(u8, sc.sent.items, "\r\n\r\n"));
    // a server that skips the proof and says 235 at once is no better
    var s2: Session = .init(gpa, scramOpts("pencil"));
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "334 " ++ b64lit(scram_sf) ++ "\r\n", "235 2.7.0 ok\r\n" } };
    defer sc2.deinit();
    try testing.expectError(error.ServerSignatureMismatch, sc2.run(&s2));
    try testing.expect(!s2.authenticated);
    var s3: Session = .init(gpa, scramOpts("pencil"));
    defer s3.deinit();
    var sc3: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "235 2.7.0 ok\r\n" } };
    defer sc3.deinit();
    try testing.expectError(error.AuthenticationFailed, sc3.run(&s3));
    try testing.expect(!s3.authenticated);
}

test "SCRAM-SHA-256: the signature in the 235 additional data is verified too" {
    const gpa = testing.allocator;
    var s: Session = .init(gpa, scramOpts("pencil"));
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "334 " ++ b64lit(scram_sf) ++ "\r\n", "235 " ++ b64lit(scram_sv) ++ "\r\n" } };
    defer sc.deinit();
    try sc.run(&s);
    try testing.expect(s.authenticated);
}

test "SCRAM-SHA-256: rejected proof, bad iteration count, non-ASCII password" {
    const gpa = testing.allocator;
    {
        var s: Session = .init(gpa, scramOpts("wrong"));
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "334 " ++ b64lit(scram_sf) ++ "\r\n", "535 5.7.8 Authentication failed\r\n" } };
        defer sc.deinit();
        try testing.expectError(error.PermanentFailure, sc.run(&s));
        try testing.expect(!s.authenticated);
        try testing.expectEqual(State.closed, s.state);
    }
    {
        var s: Session = .init(gpa, scramOpts("pencil"));
        defer s.deinit();
        const low = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=100";
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "334 " ++ b64lit(low) ++ "\r\n" } };
        defer sc.deinit();
        try testing.expectError(error.ScramIterationsOutOfRange, sc.run(&s));
        try testing.expectEqual(State.closed, s.state);
    }
    {
        var s: Session = .init(gpa, scramOpts("p\xc3\xa9ncil"));
        defer s.deinit();
        var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo, "334 " ++ b64lit(scram_sf) ++ "\r\n" } };
        defer sc.deinit();
        try testing.expectError(error.NonAsciiCredential, sc.run(&s));
        try testing.expectEqual(State.closed, s.state);
    }
}

test "SCRAM-SHA-256: the nonce comes from scram_random, and without a source nothing is sent" {
    const gpa = testing.allocator;
    var o = scramOpts("pencil");
    o.scram_nonce = null;
    var s: Session = .init(gpa, o);
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo } };
    defer sc.deinit();
    try testing.expectError(error.ScramNoRandomSource, sc.run(&s));
    try testing.expectEqualStrings("EHLO localhost\r\n", sc.sent.items);

    var prng = std.Random.DefaultPrng.init(7);
    o.scram_random = prng.random();
    var s2: Session = .init(gpa, o);
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", scram_ehlo } };
    defer sc2.deinit();
    // runs out of scripted replies after the AUTH line: that is the point we stop
    try testing.expectError(error.InvalidState, sc2.run(&s2));
    const line = std.mem.trimEnd(u8, sc2.sent.items["EHLO localhost\r\n".len..], "\r\n");
    try testing.expect(std.mem.startsWith(u8, line, "AUTH SCRAM-SHA-256 "));
    var dec: [128]u8 = undefined;
    const raw = try auth_mod.decodeChallenge(&dec, line["AUTH SCRAM-SHA-256 ".len..]);
    try testing.expect(std.mem.startsWith(u8, raw, "n,,n=user,r="));
    try testing.expectEqual(@as(usize, "n,,n=user,r=".len + 24), raw.len);
}

// ── BDAT / CHUNKING (RFC 3030) ─────────────────────────────────────────────

const ehlo_chunking =
    "250-mail.example.com Hello\r\n" ++
    "250-PIPELINING\r\n" ++
    "250-CHUNKING\r\n" ++
    "250 SIZE 10240000\r\n";

fn bdatSession(gpa: std.mem.Allocator, chunk: usize, sc: *Script) !Session {
    var s: Session = .init(gpa, .{ .tls = .disabled, .bdat = true, .bdat_chunk = chunk });
    errdefer s.deinit();
    sc.replies = &.{ "220 ready\r\n", ehlo_chunking };
    try sc.run(&s);
    return s;
}

test "BDAT: chunks of the normalised message, no dot-stuffing, the last one is LAST" {
    const gpa = testing.allocator;
    var sc: Script = .{ .gpa = gpa, .replies = &.{} };
    defer sc.deinit();
    var s = try bdatSession(gpa, 8, &sc);
    defer s.deinit();
    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "Subject: x\n.dot\nend" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "250 c1\r\n", "250 c2\r\n", "250 queued\r\n" };
    try sc.run(&s);
    try testing.expectEqual(@as(usize, 5), sc.idx);
    try testing.expectEqual(State.ready, s.state);
    try testing.expectEqualStrings(
        "MAIL FROM:<a@example.com> SIZE=23\r\nRCPT TO:<b@example.net>\r\n" ++
            "BDAT 8\r\nSubject:" ++ "BDAT 8\r\n x\r\n.dot" ++ "BDAT 7 LAST\r\n\r\nend\r\n",
        sc.sent.items,
    );
    try testing.expectEqual(@as(usize, 0), sc.bodies.items.len); // DATA was never used
}

test "BDAT: an empty body is one BDAT 0 LAST, and a big chunk sends the message at once" {
    const gpa = testing.allocator;
    var sc: Script = .{ .gpa = gpa, .replies = &.{} };
    defer sc.deinit();
    var s = try bdatSession(gpa, 64 * 1024, &sc);
    defer s.deinit();
    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = null, .to = &.{"b@example.net"}, .body = "" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "250 queued\r\n" };
    try sc.run(&s);
    try testing.expectEqualStrings("MAIL FROM:<> SIZE=0\r\nRCPT TO:<b@example.net>\r\nBDAT 0 LAST\r\n", sc.sent.items);

    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "a\r\n.b\r\n" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "250 queued\r\n" };
    try sc.run(&s);
    try testing.expect(std.mem.endsWith(u8, sc.sent.items, "BDAT 7 LAST\r\na\r\n.b\r\n"));
}

test "BDAT: a refused chunk stops the stream, RSET follows, the error is the server's" {
    const gpa = testing.allocator;
    var sc: Script = .{ .gpa = gpa, .replies = &.{} };
    defer sc.deinit();
    var s = try bdatSession(gpa, 8, &sc);
    defer s.deinit();
    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "Subject: x\n.dot\nend" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "250 c1\r\n", "552 5.3.4 too big\r\n", "250 reset\r\n" };
    try testing.expectError(error.PermanentFailure, sc.run(&s));
    try testing.expectEqual(@as(usize, 5), sc.idx); // every reply consumed
    try testing.expectEqual(State.ready, s.state);
    try testing.expect(std.mem.endsWith(u8, sc.sent.items, "BDAT 8\r\n x\r\n.dotRSET\r\n"));
    try testing.expect(std.mem.find(u8, sc.sent.items, "LAST") == null); // chunk 3 never sent

    // usable again afterwards
    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "ok" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "250 queued\r\n" };
    try sc.run(&s);
    try testing.expect(std.mem.endsWith(u8, sc.sent.items, "BDAT 4 LAST\r\nok\r\n"));

    // a transient refusal of the LAST chunk keeps its class
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "ok" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "451 4.3.0 later\r\n", "250 reset\r\n" };
    try testing.expectError(error.TransientFailure, sc.run(&s));
}

test "BDAT: all recipients rejected sends no chunk; a lone-policy rejection still delivers" {
    const gpa = testing.allocator;
    var sc: Script = .{ .gpa = gpa, .replies = &.{} };
    defer sc.deinit();
    var s = try bdatSession(gpa, 64, &sc);
    defer s.deinit();
    sc.sent.clearRetainingCapacity();
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "550 5.1.1 no\r\n" };
    try testing.expectError(error.AllRecipientsRejected, sc.run(&s));
    try testing.expect(std.mem.find(u8, sc.sent.items, "BDAT") == null);
    try testing.expectEqual(State.ready, s.state);
}

test "BDAT: used only when asked for and advertised; an over-long line is refused before MAIL" {
    const gpa = testing.allocator;
    // advertised but not requested: DATA
    var s: Session = .init(gpa, .{ .tls = .disabled });
    defer s.deinit();
    var sc: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_chunking } };
    defer sc.deinit();
    try sc.run(&s);
    try s.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\r\n" });
    sc.idx = 0;
    sc.replies = &.{ "250 ok\r\n", "250 ok\r\n", "354 go\r\n", "250 q\r\n" };
    try sc.run(&s);
    try testing.expect(std.mem.find(u8, sc.sent.items, "BDAT") == null);
    try testing.expect(std.mem.find(u8, sc.sent.items, "DATA\r\n") != null);

    // requested but not advertised: DATA
    var s2: Session = .init(gpa, .{ .tls = .disabled, .bdat = true });
    defer s2.deinit();
    var sc2: Script = .{ .gpa = gpa, .replies = &.{ "220 ready\r\n", ehlo_full } };
    defer sc2.deinit();
    try sc2.run(&s2);
    try s2.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = "x\r\n" });
    sc2.idx = 0;
    sc2.replies = &.{ "250 ok\r\n", "250 ok\r\n", "354 go\r\n", "250 q\r\n" };
    try sc2.run(&s2);
    try testing.expect(std.mem.find(u8, sc2.sent.items, "BDAT") == null);

    // both: the line that cannot be sent is found before any command goes out
    var sc3: Script = .{ .gpa = gpa, .replies = &.{} };
    defer sc3.deinit();
    var s3 = try bdatSession(gpa, 64, &sc3);
    defer s3.deinit();
    const long = try gpa.alloc(u8, 1500);
    defer gpa.free(long);
    @memset(long, 'a');
    try testing.expectError(error.LineTooLong, s3.beginTransaction(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = long }));
    try testing.expectEqual(State.ready, s3.state);
}
