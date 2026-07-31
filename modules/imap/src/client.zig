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

    /// Write an astring, running the continuation handshake when the value can
    /// only travel as a synchronising literal.
    fn writeString(c: *Client, s: []const u8) Error!void {
        if (c.enc.quotable(s)) return c.enc.quoted(s);
        c.enc.literal(s) catch |e| switch (e) {
            error.SyncLiteralRequired => {
                // {n} CRLF, flush, wait for '+', then the payload.
                try c.enc.special('{');
                try c.enc.number(@intCast(s.len));
                try c.enc.special('}');
                try c.enc.crlf();
                c.enc.w.flush() catch return error.WriteFailed;
                try c.awaitContinuation();
                c.enc.w.writeAll(s) catch return error.WriteFailed;
            },
            else => return e,
        };
    }

    fn finish(c: *Client) Error!void {
        try c.enc.crlf();
        c.enc.w.flush() catch return error.WriteFailed;
    }

    // ── commands ────────────────────────────────────────────────────────────

    /// `CAPABILITY`. Also runs implicitly whenever the server volunteers a
    /// capability list, so calling it is only necessary after a state change
    /// the server did not annotate.
    pub fn capability(c: *Client) Error!Completion {
        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.capability(tag);
        c.enc.w.flush() catch return error.WriteFailed;
        return c.expectOk(tag);
    }

    pub fn noop(c: *Client) Error!Completion {
        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try c.enc.noop(tag);
        c.enc.w.flush() catch return error.WriteFailed;
        return c.expectOk(tag);
    }

    /// `LOGIN`. Only legal before authentication — after it, the server is
    /// required to reject it, so this refuses locally rather than sending a
    /// command that leaks a password into a session that cannot use it.
    pub fn login(c: *Client, user: []const u8, pass: []const u8) Error!Completion {
        if (c.state != .not_authenticated) return error.BadState;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);

        try c.enc.atom(tag);
        try c.enc.sp();
        try c.enc.atom("LOGIN");
        try c.enc.sp();
        try c.writeString(user);
        try c.enc.sp();
        try c.writeString(pass);
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
        if (c.state != .authenticated and c.state != .selected) return error.BadState;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);

        c.freeMailbox();
        c.state = .authenticated;

        try c.enc.atom(tag);
        try c.enc.sp();
        try c.enc.atom(if (read_only) "EXAMINE" else "SELECT");
        try c.enc.sp();
        try c.enc.mailbox(name);
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
        if (c.state != .selected) return error.NoMailbox;

        const tag = try c.tagger.next(c.gpa);
        defer c.gpa.free(tag);
        try searchmod.encode(&c.enc, tag, by_uid, ret, crit);
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
        "* CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED\r\n" ++
        "T1 OK CAPABILITY completed\r\n" ++
        "T2 OK LOGIN completed\r\n" ++
        "* 172 EXISTS\r\n" ++
        "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
        "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
        "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n" ++
        "T3 OK [READ-WRITE] SELECT completed\r\n");

    var c = p.client(.{});
    defer c.deinit();

    _ = try c.greet();
    try testing.expectEqual(State.not_authenticated, c.state);
    // The greeting's own response code carries capabilities -- that is how a
    // client avoids a round trip before STARTTLS.
    try testing.expect(c.hasCap("STARTTLS"));
    try testing.expect(c.hasCap("IMAP4rev2"));

    _ = try c.capability();
    try testing.expect(c.hasCap("LOGINDISABLED"));

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

test "a synchronising literal: write {n}, wait for '+', then the payload" {
    // No LITERAL+ or LITERAL- advertised, and the password holds a CRLF, so it
    // cannot be quoted. This is the handshake the encoder refuses to fake.
    var p: Peer = undefined;
    p.init("* OK ready\r\n" ++
        "+ Ready for additional command text\r\n" ++
        "T1 OK LOGIN completed\r\n");

    var c = p.client(.{});
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

    var c = p.client(.{});
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

    var c = p.client(.{});
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
//     transport is the caller's, so `startTls` writes the command and the
//     caller swaps the streams — consistent with owning no socket.
