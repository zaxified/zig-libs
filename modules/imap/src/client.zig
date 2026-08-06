// SPDX-License-Identifier: MIT

//! The client session: it writes commands, reads until the matching tagged
//! completion arrives, and keeps the connection state the protocol requires a
//! client to track (RFC 9051 §3).
//!
//! Ported from `emersion/go-imap` v2 `imapclient` (MIT — see
//! `modules/imap/NOTICE`), reshaped from its goroutine-per-connection model
//! into a synchronous one — see the divergence note at the bottom.
//!
//! ## What makes this layer necessary
//!
//! Three things none of the layers below can own:
//!
//! **Untagged data arrives unsolicited.** `* 23 EXISTS` can land between any
//! two responses, including in the middle of an unrelated command, because it
//! reports a change the server just learned about. So "read the reply" is
//! really "read until the tag I sent comes back, handling everything else on
//! the way".
//!
//! **The synchronising literal is a three-step handshake.** Write `{n}`, wait
//! for `+`, then write the payload — and untagged data may arrive before the
//! `+`. `command.Encoder` deliberately refuses to fake this; the session is
//! where the read and the write interleave.
//!
//! **State gates commands.** `SELECT` is meaningless before authentication and
//! `LOGIN` is an error after it. Tracking that here turns a class of protocol
//! error into a local one.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const command = @import("command.zig");
const fetchmod = @import("fetch.zig");
const searchmod = @import("search.zig");
const response = @import("response.zig");
const wire = @import("wire.zig");

pub const Error = response.Error || command.Error || error{
    /// A command that only makes sense with a mailbox selected.
    NoMailbox,
    /// `idlePoll` was called outside an IDLE, or a command was sent inside one.
    NotIdle,
    /// The command is not legal in the current connection state.
    BadState,
    /// A tagged response arrived carrying a tag we never sent.
    UnknownTag,
    /// The server answered the command with NO or BAD.
    CommandFailed,
    /// The server ended the session with an untagged BYE.
    ServerClosed,
    /// A continuation request was expected and something else came back.
    NoContinuation,
    /// The server advertised `LOGINDISABLED`, so RFC 9051 §6.2.3 forbids
    /// issuing `LOGIN` at all. Run `startTls` first (the capability is
    /// normally withdrawn once the link is encrypted).
    LoginDisabled,
    /// `login` was called on a link this client has not seen encrypted and
    /// `Options.allow_plaintext_auth` is false. See that option.
    PlaintextAuth,
    /// Bytes were already buffered from the server when the STARTTLS
    /// handshake was about to start — they arrived in the clear, before any
    /// peer was authenticated, so they are treated as injected and the
    /// upgrade is refused. Same posture and same spelling as the sibling
    /// `smtp` module's guard.
    PlaintextInjection,
};

/// RFC 9051 §3.
pub const State = enum {
    /// Before the greeting, or after a greeting that was not PREAUTH.
    not_authenticated,
    authenticated,
    selected,
    logout,
};

/// What a completed command reported.
pub const Completion = struct {
    status: response.StatusType,
    code: response.Code,
    text: ?[]const u8,
};

/// The subset of `SELECT`'s untagged data a client is expected to keep.
pub const Mailbox = struct {
    name: []const u8 = "",
    exists: u32 = 0,
    flags: []const []const u8 = &.{},
    permanent_flags: []const []const u8 = &.{},
    uid_validity: u32 = 0,
    uid_next: u32 = 0,
    read_only: bool = false,
};

/// Called for untagged data the session does not consume itself. Returning an
/// error aborts the command.
pub const UnilateralFn = *const fn (ctx: ?*anyopaque, data: response.Data) anyerror!void;

pub const Options = struct {
    wire: wire.Options = .{},
    /// Observer for untagged data the session does not consume (EXPUNGE, an
    /// unsolicited EXISTS, anything unparsed).
    on_unilateral: ?UnilateralFn = null,
    unilateral_ctx: ?*anyopaque = null,
    /// Permit `login` on a link this client has not seen encrypted.
    ///
    /// `LOGIN` transmits the password as a plain astring, so on a cleartext
    /// link it is handed to anyone on the path. Default **false**: `login`
    /// refuses with `error.PlaintextAuth` unless `startTls`/`tlsEstablished`
    /// has run or the caller opts in here. The opt-in is for the cases where
    /// the transport is already trusted and this client cannot know it — a
    /// unix socket, a loopback test server, a tunnel the caller established.
    /// Mirrors `smtp`'s `Session.Options.allow_plaintext_auth`, including the
    /// default.
    allow_plaintext_auth: bool = false,
};

pub const Client = struct {
    gpa: Allocator,
    /// Reset after every response line; everything the session keeps is duped
    /// into `gpa` first.
    arena: std.heap.ArenaAllocator,
    rd: response.Reader,
    enc: command.Encoder,
    tagger: command.Tagger = .{},
    opts: Options,

    state: State = .not_authenticated,
    caps: std.StringHashMapUnmanaged(void) = .empty,
    mailbox: Mailbox = .{},
    /// Non-null while an IDLE is running; owns the tag.
    idle_tag: ?[]u8 = null,
    /// The real error behind `command.Error.SyncFailed`, which cannot travel
    /// through the encoder's callback signature.
    sync_err: ?Error = null,
    /// The server answered `STARTTLS` with OK and nothing was buffered
    /// across the boundary — `tlsEstablished` may be called.
    tls_negotiated: bool = false,
    /// `tlsEstablished` has run: the streams this client writes to and reads
    /// from are the caller's encrypted ones. Gates `login`.
    tls_active: bool = false,

    pub fn init(
        gpa: Allocator,
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        opts: Options,
    ) Client {
        return .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .rd = response.Reader.init(undefined, r, opts.wire),
            .enc = command.Encoder.init(gpa, w, .{}),
            .sync_err = null,
            .opts = opts,
        };
    }

    pub fn deinit(c: *Client) void {
        if (c.idle_tag) |t| c.gpa.free(t);
        c.freeCaps();
        c.freeMailbox();
        c.arena.deinit();
    }

    fn freeCaps(c: *Client) void {
        var it = c.caps.keyIterator();
        while (it.next()) |k| c.gpa.free(k.*);
        c.caps.deinit(c.gpa);
        c.caps = .empty;
    }

    fn freeMailbox(c: *Client) void {
        if (c.mailbox.name.len > 0) c.gpa.free(c.mailbox.name);
        freeList(c.gpa, c.mailbox.flags);
        freeList(c.gpa, c.mailbox.permanent_flags);
        c.mailbox = .{};
    }

    /// True when the server advertised `name` (case-insensitive).
    pub fn hasCap(c: *Client, name: []const u8) bool {
        var buf: [64]u8 = undefined;
        if (name.len > buf.len) return false;
        const upper = std.ascii.upperString(buf[0..name.len], name);
        if (c.caps.contains(upper)) return true;
        // The two mixed-case names are stored as spelled.
        for ([_][]const u8{ "IMAP4rev1", "IMAP4rev2" }) |exact| {
            if (std.ascii.eqlIgnoreCase(name, exact)) return c.caps.contains(exact);
        }
        return false;
    }

    // ── reading ─────────────────────────────────────────────────────────────

    /// Install the encoder's continuation seam. `init` cannot do it — it does
    /// not know the final address of the value it returns — and leaving it to
    /// the caller means a forgotten call silently loses the handshake, which
    /// is the bug this seam exists to fix. So every command arms it, and
    /// arming is idempotent.
    fn arm(c: *Client) void {
        c.enc.opts.on_sync = syncThunk;
        c.enc.opts.sync_ctx = c;
    }

    fn syncThunk(ctx: ?*anyopaque) anyerror!void {
        const c: *Client = @ptrCast(@alignCast(ctx.?));
        c.awaitContinuation() catch |e| {
            c.sync_err = e;
            return error.ContinuationFailed;
        };
    }

    /// Translate the encoder's opaque `SyncFailed` back into what actually
    /// went wrong while waiting.
    fn unmask(c: *Client, e: Error) Error {
        if (e != error.SyncFailed) return e;
        const real = c.sync_err orelse return e;
        c.sync_err = null;
        return real;
    }

    /// Read one response line into the arena, which is reset first — so the
    /// returned value is valid only until the next call.
    fn readLine(c: *Client) Error!response.Response {
        _ = c.arena.reset(.retain_capacity);
        c.rd.d.gpa = c.arena.allocator();
        return c.rd.next();
    }

    /// Read the server's opening greeting. `PREAUTH` means the connection is
    /// already authenticated (a pre-authenticated transport, e.g. a local
    /// socket), `BYE` means the server refused it outright.
    pub fn greet(c: *Client) Error!Completion {
        c.arm();
        const resp = try c.readLine();
        const st = switch (resp) {
            .data => |d| switch (d) {
                .status => |s| s,
                else => return error.UnexpectedByte,
            },
            else => return error.UnexpectedByte,
        };

        try c.absorbCode(st.code);
        switch (st.type) {
            .ok => c.state = .not_authenticated,
            .preauth => c.state = .authenticated,
            .bye => {
                c.state = .logout;
                return error.ServerClosed;
            },
            .no, .bad => return error.CommandFailed,
        }
        return .{ .status = st.type, .code = st.code, .text = null };
    }

    /// Read responses until the tagged completion for `tag`, dispatching
    /// everything else on the way.
    fn awaitCompletion(c: *Client, tag: []const u8) Error!Completion {
        while (true) {
            const resp = try c.readLine();
            switch (resp) {
                .continuation => return error.NoContinuation,
                .data => |d| try c.handleData(d),
                .tagged => |t| {
                    if (!std.mem.eql(u8, t.tag, tag)) return error.UnknownTag;
                    try c.absorbCode(t.status.code);
                    return .{
                        .status = t.status.type,
                        .code = t.status.code,
                        .text = null,
                    };
                },
            }
        }
    }

    /// Read responses until the server's `+` continuation, dispatching any
    /// untagged data that arrives first.
    fn awaitContinuation(c: *Client) Error!void {
        while (true) {
            const resp = try c.readLine();
            switch (resp) {
                .continuation => return,
                .data => |d| try c.handleData(d),
                // A tagged response here means the server rejected the command
                // outright instead of asking for the literal.
                .tagged => return error.NoContinuation,
            }
        }
    }

    fn handleData(c: *Client, d: response.Data) Error!void {
        switch (d) {
            .capability => |caps| try c.setCaps(caps),
            .status => |s| {
                try c.absorbCode(s.code);
                if (s.type == .bye) {
                    c.state = .logout;
                    return error.ServerClosed;
                }
            },
            .exists => |n| c.mailbox.exists = n,
            .flags => |f| {
                freeList(c.gpa, c.mailbox.flags);
                c.mailbox.flags = try dupeList(c.gpa, f);
            },
            else => {},
        }
        if (c.opts.on_unilateral) |f| {
            f(c.opts.unilateral_ctx, d) catch return error.CommandFailed;
        }
    }

    /// Pick up the pieces of a response code the session keeps.
    fn absorbCode(c: *Client, code: response.Code) Error!void {
        switch (code) {
            .capability => |caps| try c.setCaps(caps),
            .permanent_flags => |f| {
                freeList(c.gpa, c.mailbox.permanent_flags);
                c.mailbox.permanent_flags = try dupeList(c.gpa, f);
            },
            .uid_validity => |v| c.mailbox.uid_validity = v,
            .uid_next => |v| c.mailbox.uid_next = v,
            .read_only => c.mailbox.read_only = true,
            .read_write => c.mailbox.read_only = false,
            else => {},
        }
    }

    fn setCaps(c: *Client, caps: []const []const u8) Error!void {
        c.freeCaps();
        for (caps) |cap| {
            const owned = c.gpa.dupe(u8, cap) catch return error.OutOfMemory;
            c.caps.put(c.gpa, owned, {}) catch {
                c.gpa.free(owned);
                return error.OutOfMemory;
            };
        }
        // Non-synchronising literals are a capability, so the encoder's policy
        // is decided by what the server just said it supports.
        c.enc.opts.literal_plus = c.hasCap("LITERAL+");
        c.enc.opts.literal_minus = c.hasCap("LITERAL-") or c.hasCap("IMAP4rev2");
        c.enc.opts.quoted_utf8 = c.hasCap("IMAP4rev2") or c.hasCap("UTF8=ACCEPT");
    }

    // ── writing ─────────────────────────────────────────────────────────────

    fn finish(c: *Client) Error!void {
        try c.enc.crlf();
        c.enc.w.flush() catch return error.WriteFailed;
    }

    // ── commands ────────────────────────────────────────────────────────────

    /// `CAPABILITY`. Also runs implicitly whenever the server volunteers a
    /// capability list, so calling it is only necessary after a state change
    /// the server did not annotate.
    pub fn capability(c: *Client) Error!Completion {
        c.arm();
        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.capability(tag);
        c.enc.w.flush() catch return error.WriteFailed;
        return c.expectOk(tag);
    }

    pub fn noop(c: *Client) Error!Completion {
        c.arm();
        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.noop(tag);
        c.enc.w.flush() catch return error.WriteFailed;
        return c.expectOk(tag);
    }

    /// `STARTTLS` (RFC 9051 §6.2.1), step 1 of 2: send the command and read
    /// its completion. On success the caller performs the TLS handshake on
    /// its own transport and then calls `tlsEstablished` with the upgraded
    /// streams — this client owns no socket, so it cannot do the handshake
    /// itself (divergence D6).
    ///
    /// Two things this does that a bare `enc.startTls` would not:
    ///
    /// **It refuses buffered plaintext.** Once the server has said OK it must
    /// send nothing further until the TLS handshake; anything already in the
    /// reader arrived in the clear from an unauthenticated peer and would be
    /// replayed as if it had come from inside the tunnel. That is the 2011
    /// STARTTLS command/response-injection class (CVE-2011-0411 and
    /// relatives), and it is refused with `error.PlaintextInjection` —
    /// the same guard, and the same spelling, as `smtp/src/client.zig`.
    /// The check is exactly as strong as the reader's buffer: bytes still in
    /// the kernel socket queue are not visible here, so a caller reading
    /// through an unbuffered stream gets no protection from it. That is the
    /// same ceiling `smtp`'s `parser.atBoundary()` has.
    ///
    /// **It does not upgrade anything by itself.** `tls_active` stays false
    /// until `tlsEstablished` runs, so `login` keeps refusing in between.
    pub fn startTls(c: *Client) Error!Completion {
        c.arm();
        if (c.tls_active or c.tls_negotiated) return error.BadState;
        // §6.2.1: only valid in the not-authenticated state.
        if (c.state != .not_authenticated) return error.BadState;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.startTls(tag);
        c.enc.w.flush() catch return error.WriteFailed;
        const done = try c.expectOk(tag);

        if (c.rd.d.r.bufferedLen() != 0) return error.PlaintextInjection;
        c.tls_negotiated = true;
        return done;
    }

    /// `STARTTLS` step 2 of 2: adopt the caller's upgraded streams and redo
    /// capability discovery.
    ///
    /// RFC 9051 §6.2.1 requires the client to **discard** the capability list
    /// it learned before the handshake — it came from an unauthenticated peer
    /// and a downgrade attacker could have written it. This drops the whole
    /// set *and* the encoder policy derived from it (`literal_plus`,
    /// `literal_minus`, `quoted_utf8` — `setCaps` derives all three), then
    /// re-issues `CAPABILITY` over the encrypted link and takes the answer
    /// from there. Returns that command's completion.
    pub fn tlsEstablished(c: *Client, r: *std.Io.Reader, w: *std.Io.Writer) Error!Completion {
        if (!c.tls_negotiated) return error.BadState;
        c.rd.d.r = r;
        c.enc.w = w;
        // §6.2.1 discard: the pre-TLS list and everything derived from it.
        c.freeCaps();
        c.enc.opts.literal_plus = false;
        c.enc.opts.literal_minus = false;
        c.enc.opts.quoted_utf8 = false;
        c.tls_active = true;
        c.tls_negotiated = false;
        return c.capability();
    }

    /// `LOGIN`. Only legal before authentication — after it, the server is
    /// required to reject it, so this refuses locally rather than sending a
    /// command that leaks a password into a session that cannot use it.
    ///
    /// Two more refusals, both about not handing the password to the wrong
    /// party. `LOGINDISABLED` (RFC 9051 §6.2.3) is the server stating that
    /// `LOGIN` is not permitted on this link — a client MUST NOT issue it,
    /// and the module already parsed the capability, it simply never
    /// consulted it. And an unencrypted link needs
    /// `Options.allow_plaintext_auth`, because `LOGIN` puts the password on
    /// the wire in the clear.
    pub fn login(c: *Client, user: []const u8, pass: []const u8) Error!Completion {
        c.arm();
        if (c.state != .not_authenticated) return error.BadState;
        if (c.hasCap("LOGINDISABLED")) return error.LoginDisabled;
        if (!c.tls_active and !c.opts.allow_plaintext_auth) return error.PlaintextAuth;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);

        try c.enc.atom(tag);
        try c.enc.sp();
        try c.enc.atom("LOGIN");
        try c.enc.sp();
        c.enc.string(user) catch |e| return c.unmask(e);
        try c.enc.sp();
        c.enc.string(pass) catch |e| return c.unmask(e);
        try c.finish();

        const done = try c.expectOk(tag);
        c.state = .authenticated;
        return done;
    }

    /// `SELECT` (or `EXAMINE` when `read_only`). Replaces whatever mailbox
    /// state was there: RFC 9051 §6.3.2 requires a client to discard the old
    /// mailbox's state before the new one, since a failed SELECT leaves the
    /// connection with NO selected mailbox at all.
    pub fn select(c: *Client, name: []const u8, read_only: bool) Error!Completion {
        c.arm();
        if (c.state != .authenticated and c.state != .selected) return error.BadState;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);

        c.freeMailbox();
        c.state = .authenticated;

        try c.enc.atom(tag);
        try c.enc.sp();
        try c.enc.atom(if (read_only) "EXAMINE" else "SELECT");
        try c.enc.sp();
        c.enc.mailbox(name) catch |e| return c.unmask(e);
        try c.finish();

        const done = c.expectOk(tag) catch |e| {
            // A failed SELECT is not "the old mailbox is still open".
            c.freeMailbox();
            return e;
        };

        c.mailbox.name = c.gpa.dupe(u8, name) catch return error.OutOfMemory;
        c.mailbox.read_only = read_only or c.mailbox.read_only;
        c.state = .selected;
        return done;
    }

    /// `LOGOUT`. The server answers with an untagged `BYE` and then the tagged
    /// completion, so `ServerClosed` from the BYE is the expected path here
    /// rather than a failure.
    pub fn logout(c: *Client) Error!void {
        c.arm();
        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.logout(tag);
        c.enc.w.flush() catch return error.WriteFailed;

        _ = c.awaitCompletion(tag) catch |e| switch (e) {
            error.ServerClosed => {},
            else => return e,
        };
        c.state = .logout;
    }

    // ── FETCH / SEARCH / IDLE ───────────────────────────────────────────────

    /// `FETCH`, collecting every `* n FETCH` into `out_gpa`.
    ///
    /// Results are allocated from `out_gpa` rather than the session's arena
    /// because a FETCH spans many response lines and the arena is reset on
    /// each one. Hand it an arena of your own and free it when done with the
    /// messages.
    pub fn fetchMessages(
        c: *Client,
        out_gpa: Allocator,
        seq_set: []const u8,
        by_uid: bool,
        req: fetchmod.Request,
    ) Error![]const fetchmod.Message {
        c.arm();
        if (c.state != .selected) return error.NoMailbox;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try fetchmod.encode(&c.enc, tag, seq_set, by_uid, req);
        c.enc.w.flush() catch return error.WriteFailed;

        var out: std.ArrayList(fetchmod.Message) = .empty;
        errdefer out.deinit(out_gpa);

        while (true) {
            // Collected data must outlive the line it arrived on.
            c.rd.d.gpa = out_gpa;
            const resp = c.rd.next() catch |e| return e;
            switch (resp) {
                .continuation => return error.NoContinuation,
                .tagged => |t| {
                    if (!std.mem.eql(u8, t.tag, tag)) return error.UnknownTag;
                    try c.absorbCode(t.status.code);
                    if (t.status.type != .ok) return error.CommandFailed;
                    return out.toOwnedSlice(out_gpa);
                },
                .data => |d| switch (d) {
                    .fetch => |m| try out.append(out_gpa, m),
                    else => try c.handleData(d),
                },
            }
        }
    }

    /// `SEARCH`. Accepts either reply shape; `Result.tag` is null for the
    /// IMAP4rev1 form, which carries no correlator.
    pub fn searchMessages(
        c: *Client,
        out_gpa: Allocator,
        by_uid: bool,
        ret: searchmod.Return,
        crit: *const searchmod.Criteria,
    ) Error!searchmod.Result {
        c.arm();
        if (c.state != .selected) return error.NoMailbox;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        searchmod.encode(&c.enc, tag, by_uid, ret, crit) catch |e| return c.unmask(e);
        c.enc.w.flush() catch return error.WriteFailed;

        var result: searchmod.Result = .{};
        while (true) {
            c.rd.d.gpa = out_gpa;
            const resp = try c.rd.next();
            switch (resp) {
                .continuation => return error.NoContinuation,
                .tagged => |t| {
                    if (!std.mem.eql(u8, t.tag, tag)) return error.UnknownTag;
                    try c.absorbCode(t.status.code);
                    if (t.status.type != .ok) return error.CommandFailed;
                    return result;
                },
                .data => |d| switch (d) {
                    .search, .esearch => |r| result = r,
                    else => try c.handleData(d),
                },
            }
        }
    }

    /// Begin `IDLE` (RFC 2177 / RFC 9051 §6.3.13): send the command and wait
    /// for the server's continuation. Until `idleDone`, **no other command may
    /// be sent** — that is the protocol's rule, not this client's.
    ///
    /// The caller owns the timing. RFC 2177 requires re-issuing IDLE at least
    /// every 29 minutes or servers may drop the connection; this client does
    /// not run a timer, because it owns no thread.
    pub fn idleBegin(c: *Client) Error!void {
        c.arm();
        if (c.state != .selected and c.state != .authenticated) return error.BadState;
        if (c.idle_tag != null) return error.NotIdle;

        const tag = try c.tagger.next(c.gpa);
        errdefer c.gpa.free(tag);
        try c.enc.atom(tag);
        try c.enc.sp();
        try c.enc.atom("IDLE");
        try c.finish();

        try c.awaitContinuation();
        c.idle_tag = tag;
    }

    /// Read one piece of unsolicited data while idling. Blocks on the
    /// underlying reader, so the caller decides what "waiting" costs.
    pub fn idlePoll(c: *Client) Error!response.Data {
        if (c.idle_tag == null) return error.NotIdle;
        const resp = try c.readLine();
        return switch (resp) {
            .data => |d| blk: {
                try c.handleData(d);
                break :blk d;
            },
            // A tagged response during IDLE means the server ended it itself.
            .tagged, .continuation => error.NotIdle,
        };
    }

    /// End `IDLE`: send `DONE` and read to the completion.
    pub fn idleDone(c: *Client) Error!Completion {
        const tag = c.idle_tag orelse return error.NotIdle;
        defer {
            c.gpa.free(tag);
            c.idle_tag = null;
        }
        try c.enc.atom("DONE");
        try c.finish();
        return c.awaitCompletion(tag);
    }

    fn expectOk(c: *Client, tag: []const u8) Error!Completion {
        const done = try c.awaitCompletion(tag);
        if (done.status != .ok) return error.CommandFailed;
        return done;
    }
};

fn dupeList(gpa: Allocator, list: []const []const u8) Error![]const []const u8 {
    const out = gpa.alloc([]const u8, list.len) catch return error.OutOfMemory;
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |s| gpa.free(s);
        gpa.free(out);
    }
    for (list) |s| {
        out[n] = gpa.dupe(u8, s) catch return error.OutOfMemory;
        n += 1;
    }
    return out;
}

fn freeList(gpa: Allocator, list: []const []const u8) void {
    for (list) |s| gpa.free(s);
    if (list.len > 0) gpa.free(list);
}

// ── tests ───────────────────────────────────────────────────────────────────

/// A scripted peer: `script` is what the server says, and everything the
/// client writes is captured for byte-exact assertions.
const Peer = struct {
    r: std.Io.Reader,
    w: std.Io.Writer,
    buf: [8192]u8 = undefined,

    fn init(p: *Peer, script: []const u8) void {
        p.r = std.Io.Reader.fixed(script);
        p.w = std.Io.Writer.fixed(&p.buf);
    }
    fn sent(p: *Peer) []const u8 {
        return p.w.buffered();
    }
    fn client(p: *Peer, opts: Options) Client {
        return Client.init(testing.allocator, &p.r, &p.w, opts);
    }
};

test "RFC 9051 §6.1.1 + §6.2.3 + §6.3.2: greet, capability, login, select" {
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 STARTTLS] Service Ready\r\n" ++
        "* CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN\r\n" ++
        "T1 OK CAPABILITY completed\r\n" ++
        "T2 OK LOGIN completed\r\n" ++
        "* 172 EXISTS\r\n" ++
        "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
        "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
        "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n" ++
        "T3 OK [READ-WRITE] SELECT completed\r\n");

    // The link is a scripted in-memory pipe, not a socket, so the plaintext
    // gate is opted out of explicitly -- exactly as the sibling `smtp`'s tests
    // do. FIXTURE CORRECTION: this script used to advertise LOGINDISABLED on
    // the CAPABILITY line and then log in successfully, i.e. it encoded the
    // very defect W2-57 names, in the test whose own title cites §6.2.3. The
    // capability moved to the dedicated refusal test below.
    var c = p.client(.{ .allow_plaintext_auth = true });
    defer c.deinit();

    _ = try c.greet();
    try testing.expectEqual(State.not_authenticated, c.state);
    // The greeting's own response code carries capabilities -- that is how a
    // client avoids a round trip before STARTTLS.
    try testing.expect(c.hasCap("STARTTLS"));
    try testing.expect(c.hasCap("IMAP4rev2"));

    _ = try c.capability();
    try testing.expect(c.hasCap("AUTH=PLAIN"));
    try testing.expect(!c.hasCap("LOGINDISABLED"));

    _ = try c.login("SMITH", "SESAME");
    try testing.expectEqual(State.authenticated, c.state);

    _ = try c.select("INBOX", false);
    try testing.expectEqual(State.selected, c.state);
    try testing.expectEqual(@as(u32, 172), c.mailbox.exists);
    try testing.expectEqual(@as(u32, 3857529045), c.mailbox.uid_validity);
    try testing.expectEqual(@as(u32, 4392), c.mailbox.uid_next);
    try testing.expectEqual(@as(usize, 5), c.mailbox.flags.len);
    try testing.expectEqualStrings("\\*", c.mailbox.permanent_flags[2]);
    try testing.expect(!c.mailbox.read_only);

    try testing.expectEqualStrings(
        "T1 CAPABILITY\r\n" ++
            "T2 LOGIN \"SMITH\" \"SESAME\"\r\n" ++
            "T3 SELECT INBOX\r\n",
        p.sent(),
    );
}

test "RFC 9051 §6.2.3: LOGINDISABLED refuses LOGIN instead of sending the password" {
    // The capability the module has always parsed and never consulted. This
    // assertion used to live in the test above, one line before a successful
    // `login` on the very same connection.
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED] Service Ready\r\n");

    // Note: even with the plaintext gate opted out, LOGINDISABLED still wins —
    // it is the server's own statement that LOGIN is not permitted here.
    var c = p.client(.{ .allow_plaintext_auth = true });
    defer c.deinit();
    _ = try c.greet();
    try testing.expect(c.hasCap("LOGINDISABLED"));

    try testing.expectError(error.LoginDisabled, c.login("SMITH", "SESAME"));
    // Nothing at all went onto the wire -- in particular not the password.
    try testing.expectEqualStrings("", p.sent());
    try testing.expectEqual(State.not_authenticated, c.state);
}

test "LOGIN on an unencrypted link is refused without an explicit opt-in" {
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 STARTTLS] Service Ready\r\n");

    var c = p.client(.{}); // default: allow_plaintext_auth = false
    defer c.deinit();
    _ = try c.greet();

    try testing.expectError(error.PlaintextAuth, c.login("SMITH", "SESAME"));
    try testing.expectEqualStrings("", p.sent());
    try testing.expectEqual(State.not_authenticated, c.state);
}

test "STARTTLS: §6.2.1 capability discard, and LOGIN opens up once TLS is active" {
    // Step 1 runs over the cleartext peer and must consume it exactly: the
    // server may not send a byte after the OK until the handshake.
    var p1: Peer = undefined;
    p1.init("* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED LITERAL+] Ready\r\n" ++
        "T1 OK Begin TLS negotiation now\r\n");

    var c = p1.client(.{});
    defer c.deinit();
    _ = try c.greet();
    try testing.expect(c.hasCap("LOGINDISABLED"));
    try testing.expect(c.enc.opts.literal_plus); // derived from the PRE-TLS list

    _ = try c.startTls();
    try testing.expect(c.tls_negotiated);
    try testing.expect(!c.tls_active); // not until the caller has handshaked
    try testing.expectEqualStrings("T1 STARTTLS\r\n", p1.sent());

    // Step 2: the caller hands over the upgraded streams. Everything the
    // cleartext peer claimed must be gone -- including the encoder policy
    // `setCaps` derived from it, which is the half that is easy to forget.
    //
    // The scripted server deliberately answers CAPABILITY with NO untagged
    // list. That is what makes this test bite: `setCaps` starts with a
    // `freeCaps`, so when the server does re-announce, the discard is
    // invisible -- the re-announcement overwrites the stale set either way.
    // A server that stays silent (broken, or an attacker who suppressed the
    // line) is the case where the pre-TLS list would otherwise survive the
    // handshake intact. Fail-closed means it must not.
    var p2: Peer = undefined;
    p2.init("T2 OK CAPABILITY completed\r\n" ++
        "T3 OK LOGIN completed\r\n");

    _ = try c.tlsEstablished(&p2.r, &p2.w);
    try testing.expect(c.tls_active);
    try testing.expect(!c.hasCap("LOGINDISABLED")); // discarded, not carried over
    try testing.expect(!c.hasCap("STARTTLS"));
    try testing.expect(!c.hasCap("IMAP4rev2"));
    try testing.expectEqual(@as(usize, 0), c.caps.count());
    try testing.expect(!c.enc.opts.literal_plus); // and so is what it implied
    try testing.expect(!c.enc.opts.literal_minus);
    try testing.expect(!c.enc.opts.quoted_utf8);

    // ...and now LOGIN is allowed with no `allow_plaintext_auth` anywhere.
    _ = try c.login("SMITH", "SESAME");
    try testing.expectEqual(State.authenticated, c.state);
    try testing.expectEqualStrings(
        "T2 CAPABILITY\r\n" ++ "T3 LOGIN \"SMITH\" \"SESAME\"\r\n",
        p2.sent(),
    );
}

test "STARTTLS: the post-handshake CAPABILITY answer is what the session keeps" {
    var p1: Peer = undefined;
    p1.init("* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED] Ready\r\n" ++
        "T1 OK Begin TLS negotiation now\r\n");

    var c = p1.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.startTls();

    var p2: Peer = undefined;
    p2.init("* CAPABILITY IMAP4rev2 LITERAL+ AUTH=PLAIN\r\n" ++
        "T2 OK CAPABILITY completed\r\n");
    _ = try c.tlsEstablished(&p2.r, &p2.w);

    try testing.expect(c.hasCap("AUTH=PLAIN"));
    try testing.expect(!c.hasCap("LOGINDISABLED"));
    try testing.expect(c.enc.opts.literal_plus); // re-derived from the NEW list
}

test "STARTTLS: data buffered across the handshake boundary is refused" {
    // The 2011 STARTTLS injection class: the attacker appends a command (or a
    // response) to the OK, in the clear, and it is replayed as if it had come
    // from inside the tunnel. `smtp` refuses this; `imap` had no such path.
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 STARTTLS] Ready\r\n" ++
        "T1 OK Begin TLS negotiation now\r\n" ++
        "* 1 EXISTS\r\n"); // <- injected before the handshake

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();

    try testing.expectError(error.PlaintextInjection, c.startTls());
    try testing.expect(!c.tls_negotiated);
    // And the upgrade cannot be forced through afterwards.
    var p2: Peer = undefined;
    p2.init("T2 OK CAPABILITY completed\r\n");
    try testing.expectError(error.BadState, c.tlsEstablished(&p2.r, &p2.w));
    try testing.expect(!c.tls_active);
}

test "a synchronising literal: write {n}, wait for '+', then the payload" {
    // No LITERAL+ or LITERAL- advertised, and the password holds a CRLF, so it
    // cannot be quoted. This is the handshake the encoder refuses to fake.
    var p: Peer = undefined;
    p.init("* OK ready\r\n" ++
        "+ Ready for additional command text\r\n" ++
        "T1 OK LOGIN completed\r\n");

    var c = p.client(.{ .allow_plaintext_auth = true });
    defer c.deinit();
    _ = try c.greet();
    _ = try c.login("u", "pa\r\nss");

    try testing.expectEqualStrings("T1 LOGIN \"u\" {6}\r\npa\r\nss\r\n", p.sent());
}

test "untagged data arriving before the continuation is handled, not dropped" {
    // RFC 9051 permits it, and a client that treats the first line after {n}
    // as the continuation would misread this entirely.
    var p: Peer = undefined;
    p.init("* OK ready\r\n" ++
        "* 5 EXISTS\r\n" ++
        "+ go ahead\r\n" ++
        "T1 OK LOGIN completed\r\n");

    var c = p.client(.{ .allow_plaintext_auth = true });
    defer c.deinit();
    _ = try c.greet();
    _ = try c.login("u", "pa\r\nss");

    try testing.expectEqual(@as(u32, 5), c.mailbox.exists);
    try testing.expectEqualStrings("T1 LOGIN \"u\" {6}\r\npa\r\nss\r\n", p.sent());
}

test "LITERAL+ removes the handshake entirely" {
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 LITERAL+] ready\r\n" ++
        "T1 OK LOGIN completed\r\n");

    var c = p.client(.{ .allow_plaintext_auth = true });
    defer c.deinit();
    _ = try c.greet();
    _ = try c.login("u", "pa\r\nss");

    // {6+} and the payload go out together; no '+' is read.
    try testing.expectEqualStrings("T1 LOGIN \"u\" {6+}\r\npa\r\nss\r\n", p.sent());
}

test "unsolicited untagged data mid-command reaches the observer" {
    const Seen = struct {
        var expunges: std.ArrayList(u32) = .empty;
        fn cb(ctx: ?*anyopaque, d: response.Data) anyerror!void {
            _ = ctx;
            if (d == .expunge) try expunges.append(testing.allocator, d.expunge);
        }
    };
    Seen.expunges = .empty;
    defer Seen.expunges.deinit(testing.allocator);

    var p: Peer = undefined;
    p.init("* OK ready\r\n" ++
        "* 44 EXPUNGE\r\n" ++
        "* 3 EXPUNGE\r\n" ++
        "T1 OK NOOP completed\r\n");

    var c = p.client(.{ .on_unilateral = Seen.cb });
    defer c.deinit();
    _ = try c.greet();
    _ = try c.noop();

    try testing.expectEqual(@as(usize, 2), Seen.expunges.items.len);
    try testing.expectEqual(@as(u32, 44), Seen.expunges.items[0]);
}

test "PREAUTH means the connection is already authenticated" {
    var p: Peer = undefined;
    p.init("* PREAUTH [CAPABILITY IMAP4rev2] Logged in as smith\r\n");
    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    try testing.expectEqual(State.authenticated, c.state);
    // ...and LOGIN is then a local error, not a password sent into a session
    // that cannot use it.
    try testing.expectError(error.BadState, c.login("u", "p"));
}

test "a greeting of BYE is a refused connection" {
    var p: Peer = undefined;
    p.init("* BYE Try again later\r\n");
    var c = p.client(.{});
    defer c.deinit();
    try testing.expectError(error.ServerClosed, c.greet());
    try testing.expectEqual(State.logout, c.state);
}

test "a failed SELECT leaves NO mailbox selected" {
    // RFC 9051 §6.3.2 is explicit: a failed SELECT does not leave the previous
    // mailbox open. Keeping stale state here would have the client operating
    // on a mailbox the server no longer has selected.
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "* 172 EXISTS\r\n" ++
        "T1 OK [READ-WRITE] SELECT completed\r\n" ++
        // A server may emit untagged data for a SELECT it then refuses --
        // which is exactly what makes clearing state on FAILURE load-bearing
        // rather than redundant with clearing it on entry.
        "* 9 EXISTS\r\n" ++
        "* OK [UIDVALIDITY 1] partial\r\n" ++
        "T2 NO [NONEXISTENT] Mailbox does not exist\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("INBOX", false);
    try testing.expectEqual(@as(u32, 172), c.mailbox.exists);

    try testing.expectError(error.CommandFailed, c.select("Nope", false));
    // Not 9, and not 172: the half-built state from the refused command is
    // gone, and so is the previous mailbox's.
    try testing.expectEqual(@as(u32, 0), c.mailbox.exists);
    try testing.expectEqual(@as(u32, 0), c.mailbox.uid_validity);
    try testing.expectEqualStrings("", c.mailbox.name);
    try testing.expectEqual(State.authenticated, c.state);
}

test "EXAMINE is the read-only spelling, and the state says so" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "* 3 EXISTS\r\n" ++
        "T1 OK [READ-ONLY] EXAMINE completed\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("Archive", true);
    try testing.expect(c.mailbox.read_only);
    try testing.expectEqualStrings("T1 EXAMINE \"Archive\"\r\n", p.sent());
}

test "a tagged response with the wrong tag is an error" {
    // Mismatched tags mean the stream is not what we think it is; continuing
    // would attribute one command's result to another.
    var p: Peer = undefined;
    p.init("* OK ready\r\nT99 OK CAPABILITY completed\r\n");
    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    try testing.expectError(error.UnknownTag, c.capability());
}

test "capabilities decide the encoder's literal policy" {
    var p: Peer = undefined;
    p.init("* OK [CAPABILITY IMAP4rev2 LITERAL+ UTF8=ACCEPT] ready\r\n");
    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();

    try testing.expect(c.enc.opts.literal_plus);
    try testing.expect(c.enc.opts.literal_minus); // implied by IMAP4rev2
    try testing.expect(c.enc.opts.quoted_utf8);
}

test "LOGOUT: the untagged BYE is the expected path, not a failure" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "* BYE IMAP4rev2 Server logging out\r\n" ++
        "T1 OK LOGOUT completed\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    try c.logout();
    try testing.expectEqual(State.logout, c.state);
}

test "a non-ASCII mailbox name goes out as modified UTF-7 unless UTF-8 is on" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\nT1 OK SELECT completed\r\n");
    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("\u{53f0}\u{5317}", false);
    try testing.expectEqualStrings("T1 SELECT \"&U,BTFw-\"\r\n", p.sent());
}

test "FETCH collects across lines, into an allocator that outlives them" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "T1 OK [READ-WRITE] SELECT completed\r\n" ++
        "* 12 FETCH (UID 4827313 FLAGS (\\Seen) RFC822.SIZE 4286)\r\n" ++
        "* 13 FETCH (UID 4827314 FLAGS (\\Seen \\Answered) RFC822.SIZE 512)\r\n" ++
        "T2 OK FETCH completed\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("INBOX", false);

    // The session arena is reset per line, so results go somewhere that is not.
    var out = std.heap.ArenaAllocator.init(testing.allocator);
    defer out.deinit();

    const msgs = try c.fetchMessages(out.allocator(), "12:13", false, .{
        .uid = true,
        .flags = true,
        .rfc822_size = true,
    });
    try testing.expectEqual(@as(usize, 2), msgs.len);
    // The FIRST message must still be readable after the second line was read
    // -- that is the whole point of not using the per-line arena.
    try testing.expectEqual(@as(u32, 4827313), msgs[0].uid().?);
    try testing.expectEqualStrings("\\Seen", msgs[0].items[1].flags[0]);
    try testing.expectEqual(@as(u32, 4827314), msgs[1].uid().?);
    try testing.expectEqual(@as(usize, 2), msgs[1].items[1].flags.len);

    try testing.expectEqualStrings(
        "T1 SELECT INBOX\r\n" ++
            "T2 FETCH 12:13 (UID FLAGS RFC822.SIZE)\r\n",
        p.sent(),
    );
}

test "FETCH is refused without a selected mailbox" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n");
    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();

    var out = std.heap.ArenaAllocator.init(testing.allocator);
    defer out.deinit();
    try testing.expectError(
        error.NoMailbox,
        c.fetchMessages(out.allocator(), "1", false, .{ .uid = true }),
    );
}

test "SEARCH accepts both reply shapes" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "T1 OK [READ-WRITE] SELECT completed\r\n" ++
        "* SEARCH 2 84 882\r\n" ++
        "T2 OK SEARCH completed\r\n" ++
        "* ESEARCH (TAG \"T3\") UID COUNT 3\r\n" ++
        "T3 OK SEARCH completed\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("INBOX", false);

    var out = std.heap.ArenaAllocator.init(testing.allocator);
    defer out.deinit();

    const rev1 = try c.searchMessages(out.allocator(), false, .{}, &.{ .flag = &.{"\\Flagged"} });
    try testing.expectEqual(@as(usize, 3), rev1.numbers.len);
    try testing.expect(rev1.tag == null);

    const rev2 = try c.searchMessages(out.allocator(), true, .{ .count = true }, &.{ .larger = 1000 });
    try testing.expectEqual(@as(u32, 3), rev2.count.?);
    try testing.expect(rev2.uid);

    try testing.expectEqualStrings(
        "T1 SELECT INBOX\r\n" ++
            "T2 SEARCH FLAGGED\r\n" ++
            "T3 UID SEARCH RETURN (COUNT) LARGER 1000\r\n",
        p.sent(),
    );
}

test "IDLE: wait for the continuation, take data, then DONE" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "T1 OK [READ-WRITE] SELECT completed\r\n" ++
        "+ idling\r\n" ++
        "* 4 EXISTS\r\n" ++
        "* 3 EXPUNGE\r\n" ++
        "T2 OK IDLE terminated\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("INBOX", false);

    try c.idleBegin();
    // The command is only "running" once the server has agreed to it.
    try testing.expectEqual(@as(u32, 4), (try c.idlePoll()).exists);
    try testing.expectEqual(@as(u32, 3), (try c.idlePoll()).expunge);

    const done = try c.idleDone();
    try testing.expectEqual(response.StatusType.ok, done.status);
    try testing.expectEqualStrings(
        "T1 SELECT INBOX\r\n" ++ "T2 IDLE\r\n" ++ "DONE\r\n",
        p.sent(),
    );
}

test "IDLE: polling outside an IDLE, and nesting one, are both refused" {
    var p: Peer = undefined;
    p.init("* PREAUTH ok\r\n" ++
        "T1 OK [READ-WRITE] SELECT completed\r\n" ++
        "+ idling\r\n");

    var c = p.client(.{});
    defer c.deinit();
    _ = try c.greet();
    _ = try c.select("INBOX", false);

    try testing.expectError(error.NotIdle, c.idlePoll());
    try c.idleBegin();
    // No command may be sent while IDLE runs -- including another IDLE.
    try testing.expectError(error.NotIdle, c.idleBegin());
}

// ── divergence from the Go original ─────────────────────────────────────────
//
// D5. go-imap runs a reader goroutine and returns command handles that are
//     awaited later, so commands may be pipelined. This client is synchronous:
//     one command is written, then read to completion. Untagged data is still
//     handled wherever it arrives, which is the part that matters for
//     correctness; pipelining is a throughput feature and can be added over
//     this without changing the layers below.
//
// D6. go-imap reconnects and upgrades in place for STARTTLS. Here the
//     transport is the caller's, so the upgrade is split in two:
//     `Client.startTls` writes the command, reads its completion and refuses
//     the upgrade if anything was buffered across the boundary
//     (`error.PlaintextInjection`); the caller then performs the handshake on
//     its own transport and hands the upgraded streams to
//     `Client.tlsEstablished`, which discards the pre-TLS capability list per
//     §6.2.1 and re-runs CAPABILITY. Consistent with owning no socket.
//
//     Until 2026-08-07 this note claimed "`startTls` writes the command and
//     the caller swaps the streams" for a `Client` method that did not exist:
//     only the unused `command.Encoder.startTls` did, nothing called it, and
//     there was no capability discard, no buffered-plaintext refusal and no
//     gate on `LOGINDISABLED`. An integrator reading the note was told a
//     safety property the code did not have. Recorded here rather than
//     deleted, because the shape of that mistake — a divergence note
//     describing the design intent instead of the code — is the thing to
//     watch for.
