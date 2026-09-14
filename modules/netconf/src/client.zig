// SPDX-License-Identifier: MIT

//! The NETCONF session: hello exchange, dialect switch, message-id allocation,
//! request/reply correlation and notification queueing.
//!
//! ## The read seam (no threading policy in this module)
//!
//! Exactly one call in this file blocks: `Client.pumpOnce`, which performs ONE
//! read on the caller-supplied `Transport` and feeds whatever came back into
//! the framer. Everything above it (`receive`, `call`, `hello`) is a loop over
//! `pumpOnce`, and everything below it (`framing.Framer`) is a pure state
//! machine that can be fed from any source.
//!
//! That is deliberate: this module does not own a timer thread, an event loop
//! or a deadline. A caller that needs a bounded wait implements it in its own
//! `Transport.read` — for an SSH channel, `poll()`/`std.Io` on the underlying
//! socket fd before calling `ssh.Session.pumpOnce`, returning 0 bytes on
//! timeout (0 means "nothing this round", not EOF, so the client keeps its
//! partial message intact and the caller decides whether to wait again or give
//! up). See README.md "Read timeouts".
//!
//! ## Correlation
//!
//! `message-id` is allocated here, monotonically, and every reply is checked
//! against the request that is outstanding. A reply whose id does not match is
//! `error.MessageIdMismatch`, never a shrug: on a NETCONF session the id is
//! the only thing tying an answer to a question.
//!
//! Notifications (RFC 5277) may arrive interleaved with replies; they are
//! queued rather than mistaken for one, and drained with `nextNotification`.

const std = @import("std");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const testing = std.testing;
const builtin = @import("builtin");

const framing = @import("framing.zig");
const capabilities = @import("capabilities.zig");
const rpc_mod = @import("rpc.zig");
const reply_mod = @import("reply.zig");
const ssh = @import("ssh");

pub const TransportError = error{
    /// The underlying byte stream failed while reading.
    ReadFailed,
    /// The underlying byte stream failed while writing.
    WriteFailed,
    /// The peer closed the stream.
    EndOfStream,
    /// The blocking operation was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `ReadFailed`/
    /// `WriteFailed` so a caller can tell a canceled wait from a real
    /// transport failure. Part of the vtable contract for a `Transport` that
    /// *does* own a socket; `SshTransport` below owns none and never
    /// produces it — see its doc comment.
    Canceled,
};

/// The byte-stream seam. One blocking `read`, one `write`; no timeouts, no
/// threads, no ownership. `read` returning 0 means "no data this round" and is
/// NOT end of stream — that is `error.EndOfStream`.
pub const Transport = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, buf: []u8) TransportError!usize,
        write: *const fn (ctx: *anyopaque, bytes: []const u8) TransportError!void,
    };

    pub fn read(self: Transport, buf: []u8) TransportError!usize {
        return self.vtable.read(self.ctx, buf);
    }

    pub fn write(self: Transport, bytes: []const u8) TransportError!void {
        return self.vtable.write(self.ctx, bytes);
    }
};

pub const Options = struct {
    /// Framing ceilings (hostile-input guards).
    limits: framing.Limits = .{},
    /// What we advertise in our `<hello>`.
    capabilities: []const []const u8 = &capabilities.default_client_capabilities,
    /// Refuse, locally and before sending anything, an operation whose RFC
    /// requires a capability the peer never advertised in its `<hello>`:
    /// `lock`/`unlock`/`getConfig`/`copyConfig`/`deleteConfig`/`editConfig`
    /// against `.candidate` need `:candidate` (§8.3), the same group against
    /// `.startup` need `:startup` (§8.7), `.url` needs `:url` (§8.8),
    /// `commit(.{.confirmed = true})` needs `:confirmed-commit` (§8.4),
    /// `validate` needs `:validate` (§8.6), and `createSubscription` needs
    /// RFC 5277 §3.1's `:notification`. Before this existed, the ten
    /// booleans `capabilities.Capabilities` parses out of the peer's
    /// `<hello>` were read by nothing in this module: they were "parsed,
    /// stored, never compared" (2026-09-10 audit, `A1/netconf.md` N8) — a
    /// server that never advertised `:candidate` still got a
    /// `lock(.candidate)` sent at it, and the only sign anything was wrong
    /// was whatever `<rpc-error>` it chose to send back over the wire.
    ///
    /// Default `true`: RFC 6241 doesn't forbid trying anyway (§7.1 leaves
    /// "what the server does with an unadvertised operation" to the
    /// server), so this is a design choice between two legitimate
    /// behaviours, not a normative requirement — but some NETCONF servers
    /// are known to implement an operation without advertising the
    /// capability that is supposed to announce it, so the check is a
    /// switch, not a hardcoded refusal: set `check_capabilities = false` to
    /// fall back to "try it, let the peer's `<rpc-error>` say no".
    check_capabilities: bool = true,
    /// Bytes per `pumpOnce` read.
    read_buffer_size: usize = 64 * 1024,
    /// Refuse to queue more than this many unread notifications; beyond it a
    /// `call` fails rather than growing without bound. Bounds ITEM COUNT, not
    /// bytes: each queued notification is a raw copy of the message, up to
    /// `Limits.max_message` in size, so the worst-case queue footprint is
    /// `max_queued_notifications * Limits.max_message` (16 GiB at both
    /// defaults). Lower `Limits.max_message` if a tighter byte bound matters
    /// more than queue depth (2026-09-10 audit, `A1/netconf.md` N7).
    max_queued_notifications: usize = 1024,
    /// Refuse to buffer more than this many out-of-order replies (see
    /// `Client.receiveReply`'s reply queue); beyond it a `receiveReply` call
    /// fails rather than growing without bound.
    max_queued_replies: usize = 1024,
    /// Consecutive `Transport.read` calls that returned 0 ("nothing this
    /// round") before `receive` gives up with `error.IdleTimeout`, instead of
    /// spinning forever.
    ///
    /// README's own "Read timeouts" recipe tells a caller to implement
    /// `Transport.read` as one bounded wait (`poll`/`std.Io`) followed by a
    /// read that returns 0 on timeout -- but nothing between that seam and
    /// `Client.receive`'s loop ever stopped calling it again. A `Transport`
    /// that follows the recipe literally, with a socket that never becomes
    /// readable, measured 116,275,395 reads/second at ReleaseFast: not a
    /// blocked wait, a 100%-CPU spin, because every "nothing this round"
    /// answer costs a full loop iteration and nothing bounds how many of
    /// those a session may see (2026-09-10 audit, `A1/netconf.md` N2).
    ///
    /// A correctly implemented `Transport.read` returns 0 only after actually
    /// waiting some nonzero wall-clock time per call, so a legitimate stall
    /// would need thousands of consecutive rounds to hit this cap -- at any
    /// realistic wait granularity, far longer than a real timeout policy
    /// would tolerate anyway. A `Transport.read` that returns 0 WITHOUT
    /// waiting (the shape the spin above measured) turns an unbounded spin
    /// into a typed error in a few milliseconds instead. 0 disables the cap
    /// (the historical, unbounded behaviour).
    max_idle_reads: usize = 300_000,
};

pub const SessionError = error{
    /// A message arrived that is not legal in this state (e.g. an `<rpc>` from
    /// a server, or a second `<hello>`).
    UnexpectedMessage,
    /// `hello`/`call` used out of order.
    InvalidState,
    /// More notifications queued than `Options.max_queued_notifications`.
    NotificationQueueFull,
    /// More out-of-order replies buffered than `Options.max_queued_replies`.
    ReplyQueueFull,
    /// `Transport.read` returned 0 ("nothing this round") for
    /// `Options.max_idle_reads` consecutive calls without ever completing a
    /// message. See `Options.max_idle_reads`.
    IdleTimeout,
    /// `Options.check_capabilities` is `true` (the default) and the peer's
    /// `<hello>` never advertised the capability an operation requires. See
    /// `Options.check_capabilities`.
    CapabilityNotAdvertised,
} || TransportError || framing.FramerError || framing.WriteError ||
    capabilities.HelloError || reply_mod.ParseError || reply_mod.CheckError ||
    reply_mod.NotificationError ||
    error{ MidMessage, NoCommonBaseVersion } || std.mem.Allocator.Error;

pub const State = enum {
    /// Before the hello exchange.
    new,
    /// Hello exchanged; dialect fixed; RPCs may flow.
    established,
    /// `close-session` acknowledged, or the peer went away.
    closed,
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    transport: Transport,
    opts: Options,
    framer: framing.Framer,
    state: State = .new,
    /// What we advertised, resolved (so `negotiate` compares like with like).
    ours: capabilities.Capabilities,
    /// The peer's `<hello>`; null until `hello()` returns.
    server: ?capabilities.Hello = null,
    /// Next `message-id`. RFC 6241 only requires uniqueness within a session;
    /// monotonic from 1 is the convention every implementation uses.
    next_id: u64 = 1,
    read_buf: []u8,
    /// The message most recently handed out by `receive`, owned here.
    current: std.ArrayList(u8) = .empty,
    /// Notifications received while waiting for a reply, in arrival order.
    notifications: std.ArrayList([]u8) = .empty,
    /// Replies received while waiting for a *different* `message-id` — a
    /// pipelining caller may have several requests outstanding at once, and
    /// RFC 6241 does not require the server to answer them in request order.
    /// Buffered here (already parsed and owned) until the matching
    /// `receiveReply(id)` call claims them.
    pending_replies: std.ArrayList(reply_mod.Reply) = .empty,
    /// ids `send` has handed out that no `receiveReply` has yet returned or
    /// buffered — the set a reply's id is checked against before it is
    /// trusted enough to buffer. Without this, a reply carrying an id nobody
    /// asked for (forged, or a stale reply from a previous session) would be
    /// indistinguishable from a legitimately out-of-order pipelined one and
    /// would sit buffered forever instead of failing loudly.
    outstanding_ids: std.ArrayList(u64) = .empty,

    pub fn init(gpa: std.mem.Allocator, transport: Transport, opts: Options) std.mem.Allocator.Error!Client {
        const buf = try gpa.alloc(u8, opts.read_buffer_size);
        errdefer gpa.free(buf);
        var ours = try capabilities.Capabilities.fromSlice(gpa, opts.capabilities);
        errdefer ours.deinit();
        return .{
            .gpa = gpa,
            .transport = transport,
            .opts = opts,
            // The hello exchange is ALWAYS end-of-message framed (RFC 6242
            // §4.1); chunked framing starts only after it.
            .framer = .init(gpa, .end_of_message, opts.limits),
            .ours = ours,
            .read_buf = buf,
        };
    }

    pub fn deinit(self: *Client) void {
        for (self.notifications.items) |n| self.gpa.free(n);
        self.notifications.deinit(self.gpa);
        for (self.pending_replies.items) |*r| r.deinit();
        self.pending_replies.deinit(self.gpa);
        self.outstanding_ids.deinit(self.gpa);
        self.current.deinit(self.gpa);
        if (self.server) |*s| s.deinit();
        self.ours.deinit();
        self.framer.deinit();
        self.gpa.free(self.read_buf);
        self.* = undefined;
    }

    /// The framing currently in force.
    pub fn dialect(self: *const Client) framing.Dialect {
        return self.framer.dialect;
    }

    /// The peer's session id (RFC 6241 §8.1), available after `hello`.
    pub fn sessionId(self: *const Client) ?u32 {
        return if (self.server) |s| s.session_id else null;
    }

    /// The peer's capability set, available after `hello`.
    pub fn serverCapabilities(self: *const Client) ?*const capabilities.Capabilities {
        return if (self.server) |*s| &s.capabilities else null;
    }

    // ── the one blocking call ──────────────────────────────────────────────

    /// Perform ONE read on the transport and feed the result to the framer.
    /// Returns the number of bytes read (0 = the transport had nothing this
    /// round). This is the only place in the module that blocks; layer a
    /// timeout on it by implementing `Transport.read` with one.
    pub fn pumpOnce(self: *Client) SessionError!usize {
        const n = try self.transport.read(self.read_buf);
        if (n != 0) try self.framer.feed(self.read_buf[0..n]);
        return n;
    }

    /// Return the next complete message, reading as many times as it takes.
    /// The slice is owned by the client and is valid until the next `receive`
    /// / `call` / `deinit`.
    pub fn receive(self: *Client) SessionError![]const u8 {
        var idle_reads: usize = 0;
        while (true) {
            if (try self.framer.next()) |m| {
                self.current.clearRetainingCapacity();
                try self.current.appendSlice(self.gpa, m);
                return self.current.items;
            }
            const n = try self.pumpOnce();
            if (n == 0) {
                idle_reads += 1;
                if (self.opts.max_idle_reads != 0 and idle_reads >= self.opts.max_idle_reads)
                    return error.IdleTimeout;
            } else {
                idle_reads = 0;
            }
        }
    }

    /// Send a pre-framed-and-serialised message.
    fn sendRaw(self: *Client, payload: []const u8) SessionError!void {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        framing.writeMessage(&aw.writer, self.framer.dialect, payload) catch |e| switch (e) {
            error.WriteFailed => return error.OutOfMemory,
            else => |other| return other,
        };
        try self.transport.write(aw.written());
    }

    // ── §8.1 hello exchange ────────────────────────────────────────────────

    /// Send our `<hello>`, read the peer's, verify a common base version and
    /// switch the framer to the negotiated dialect. RFC 6242 §4.1: the switch
    /// happens here and nowhere else.
    pub fn hello(self: *Client) SessionError!void {
        if (self.state != .new) return error.InvalidState;

        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        capabilities.writeHello(&aw.writer, self.opts.capabilities, null) catch return error.OutOfMemory;
        try self.sendRaw(aw.written());

        const msg = try self.receive();
        if (reply_mod.classify(msg) != .hello) return error.UnexpectedMessage;
        var h = try capabilities.parseHello(self.gpa, msg, .server);
        errdefer h.deinit();

        const d = try capabilities.negotiate(&self.ours, &h.capabilities);
        try self.framer.setDialect(d);
        self.server = h;
        self.state = .established;
    }

    // ── requests ───────────────────────────────────────────────────────────

    /// The capability (if any) `Datastore` requires as a `<source>`/`<target>`.
    fn datastoreCapability(d: rpc_mod.Datastore) ?[]const u8 {
        return switch (d) {
            .running => null,
            .candidate => capabilities.cap_candidate,
            .startup => capabilities.cap_startup,
            .url => capabilities.cap_url,
        };
    }

    /// The capability (if any) a `ConfigSource` requires. `.config` (an
    /// inline body) needs nothing beyond the operation's own capability, if
    /// it has one.
    fn configSourceCapability(s: rpc_mod.ConfigSource) ?[]const u8 {
        return switch (s) {
            .running, .config => null,
            .candidate => capabilities.cap_candidate,
            .startup => capabilities.cap_startup,
            .url => capabilities.cap_url,
        };
    }

    /// `Options.check_capabilities`'s enforcement point: called once per
    /// `send`, before anything goes on the wire. See the option's doc
    /// comment for the RFC citations behind each case. Checks up to two
    /// capabilities per call (an operation naming both a target/source
    /// datastore AND having its own gating capability, e.g. `validate`
    /// against `.candidate`) and fails closed on the first one missing.
    fn checkCapability(self: *Client, rpc: rpc_mod.Rpc) SessionError!void {
        if (!self.opts.check_capabilities) return;
        // `send` only runs in `.established`, which is only reached after
        // `hello()` has stored the server's hello -- this is never null in
        // practice, not a silent fallthrough.
        const server = self.serverCapabilities() orelse return;
        var needed: [2]?[]const u8 = .{ null, null };
        switch (rpc) {
            .get_config => |g| needed[0] = datastoreCapability(g.source),
            .edit_config => |e| {
                needed[0] = datastoreCapability(e.target);
                needed[1] = switch (e.payload) {
                    .config => null,
                    .url => capabilities.cap_url,
                };
            },
            .copy_config => |c| {
                needed[0] = datastoreCapability(c.target);
                needed[1] = configSourceCapability(c.source);
            },
            .delete_config => |d| needed[0] = datastoreCapability(d),
            .lock => |d| needed[0] = datastoreCapability(d),
            .unlock => |d| needed[0] = datastoreCapability(d),
            .commit => |c| if (c.confirmed) {
                needed[0] = capabilities.cap_confirmed_commit;
            },
            .validate => |s| {
                needed[0] = capabilities.cap_validate;
                needed[1] = configSourceCapability(s);
            },
            .create_subscription => needed[0] = capabilities.cap_notification,
            .get, .discard_changes, .close_session, .kill_session, .raw => {},
        }
        for (needed) |maybe_cap| {
            const cap = maybe_cap orelse continue;
            if (!server.has(cap)) return error.CapabilityNotAdvertised;
        }
    }

    /// Serialise and send `rpc` with a freshly allocated `message-id`, which is
    /// returned so a pipelining caller can correlate later.
    pub fn send(self: *Client, rpc: rpc_mod.Rpc) SessionError!u64 {
        if (self.state != .established) return error.InvalidState;
        try self.checkCapability(rpc);
        const id = self.next_id;
        self.next_id += 1;
        const payload = try rpc_mod.buildRpc(self.gpa, id, rpc);
        defer self.gpa.free(payload);
        try self.sendRaw(payload);
        try self.outstanding_ids.append(self.gpa, id);
        return id;
    }

    /// Wait for the `<rpc-reply>` carrying `id`, queueing any notification that
    /// arrives first and buffering (not discarding) any reply that carries a
    /// *different* id — a pipelining caller may have several `send`s
    /// outstanding, and RFC 6241 does not require the server to answer them
    /// in request order, so a mismatched id here is not necessarily an error;
    /// it may just belong to a `receiveReply(other_id)` call the caller
    /// hasn't made yet. The reply is returned parsed and owned by the caller,
    /// **including** when it carries `<rpc-error>` — inspect `Reply.errors`, or
    /// call `Reply.expectOk`/`expectData` for the typed error.
    pub fn receiveReply(self: *Client, id: u64) SessionError!reply_mod.Reply {
        // Already buffered by an earlier receiveReply(other_id) call.
        for (self.pending_replies.items, 0..) |*r, i| {
            if (matchesId(r, id)) return self.pending_replies.orderedRemove(i);
        }
        while (true) {
            const msg = try self.receive();
            switch (reply_mod.classify(msg)) {
                .notification => {
                    // `classify` only sniffs the root element's LOCAL NAME
                    // (it does not resolve namespaces at all), while
                    // `reply_mod.parseNotification` requires the RFC 5277 §4
                    // namespace too. A `<notification>` in a foreign or
                    // absent namespace used to queue here regardless, taking
                    // up queue slots and memory, only to fail with
                    // `error.NotANotification` much later -- at whatever
                    // unrelated `nextNotification`/`awaitNotification` call
                    // happened to dequeue it (2026-09-10 audit,
                    // `A1/netconf.md` N10). Validating before queueing makes
                    // this fail at the point the bad message actually
                    // arrived, the same way `.hello`/`.rpc`/`.unknown` below
                    // already do.
                    var probe = try reply_mod.parseNotification(self.gpa, msg);
                    probe.deinit();
                    if (self.notifications.items.len >= self.opts.max_queued_notifications)
                        return error.NotificationQueueFull;
                    const copy = try self.gpa.dupe(u8, msg);
                    errdefer self.gpa.free(copy);
                    try self.notifications.append(self.gpa, copy);
                },
                .rpc_reply => {
                    var r = try reply_mod.parseReply(self.gpa, msg);
                    errdefer r.deinit();
                    if (matchesId(&r, id)) {
                        self.removeOutstanding(id);
                        return r;
                    }
                    // Only buffer a reply for an id THIS client actually has
                    // outstanding — otherwise a forged or stale id would sit
                    // buffered forever instead of failing loudly, exactly
                    // like a real correlation failure should.
                    // `errdefer r.deinit()` above covers both error returns
                    // below — do not also deinit by hand, or it double-frees.
                    const other_id = self.findOutstanding(&r) orelse return error.MessageIdMismatch;
                    self.removeOutstanding(other_id);
                    if (self.pending_replies.items.len >= self.opts.max_queued_replies)
                        return error.ReplyQueueFull;
                    try self.pending_replies.append(self.gpa, r);
                },
                // A client never receives <hello> twice or an <rpc>.
                .hello, .rpc, .unknown => return error.UnexpectedMessage,
            }
        }
    }

    fn matchesId(r: *const reply_mod.Reply, id: u64) bool {
        r.expectMessageId(id) catch return false;
        return true;
    }

    /// Which of `self.outstanding_ids` (if any) `r` carries.
    fn findOutstanding(self: *const Client, r: *const reply_mod.Reply) ?u64 {
        for (self.outstanding_ids.items) |oid| {
            if (matchesId(r, oid)) return oid;
        }
        return null;
    }

    fn removeOutstanding(self: *Client, id: u64) void {
        for (self.outstanding_ids.items, 0..) |oid, i| {
            if (oid == id) {
                _ = self.outstanding_ids.orderedRemove(i);
                return;
            }
        }
    }

    /// `send` + `receiveReply`: the ordinary synchronous request.
    pub fn call(self: *Client, rpc: rpc_mod.Rpc) SessionError!reply_mod.Reply {
        const id = try self.send(rpc);
        return self.receiveReply(id);
    }

    /// `call` + `expectOk` — for the operations whose success is `<ok/>`.
    /// On `error.RpcError` the reply is placed in `err_out` (when non-null) so
    /// the caller keeps the structured reason; otherwise it is freed.
    pub fn callOk(self: *Client, rpc: rpc_mod.Rpc, err_out: ?*?reply_mod.Reply) SessionError!void {
        var r = try self.call(rpc);
        r.expectOk() catch |e| {
            if (err_out) |slot| {
                slot.* = r;
            } else {
                r.deinit();
            }
            return e;
        };
        r.deinit();
    }

    // ── notifications ──────────────────────────────────────────────────────

    /// Pop the oldest queued notification, or null. Caller owns the result.
    pub fn nextNotification(self: *Client) SessionError!?reply_mod.Notification {
        if (self.notifications.items.len == 0) return null;
        const queued = self.notifications.orderedRemove(0);
        defer self.gpa.free(queued);
        return try reply_mod.parseNotification(self.gpa, queued);
    }

    /// Block until a notification arrives (queueing nothing else — a reply
    /// arriving here is `error.UnexpectedMessage`, since no request is
    /// outstanding).
    pub fn awaitNotification(self: *Client) SessionError!reply_mod.Notification {
        if (try self.nextNotification()) |n| return n;
        while (true) {
            const msg = try self.receive();
            if (reply_mod.classify(msg) != .notification) return error.UnexpectedMessage;
            return try reply_mod.parseNotification(self.gpa, msg);
        }
    }

    // ── convenience wrappers (RFC 6241 §7) ─────────────────────────────────

    pub fn get(self: *Client, filter: rpc_mod.Filter) SessionError!reply_mod.Reply {
        return self.call(.{ .get = .{ .filter = filter } });
    }

    pub fn getConfig(self: *Client, source: rpc_mod.Datastore, filter: rpc_mod.Filter) SessionError!reply_mod.Reply {
        return self.call(.{ .get_config = .{ .source = source, .filter = filter } });
    }

    pub fn editConfig(self: *Client, e: rpc_mod.EditConfig) SessionError!reply_mod.Reply {
        return self.call(.{ .edit_config = e });
    }

    pub fn copyConfig(self: *Client, c: rpc_mod.CopyConfig) SessionError!reply_mod.Reply {
        return self.call(.{ .copy_config = c });
    }

    pub fn deleteConfig(self: *Client, target: rpc_mod.Datastore) SessionError!reply_mod.Reply {
        return self.call(.{ .delete_config = target });
    }

    pub fn lock(self: *Client, target: rpc_mod.Datastore) SessionError!reply_mod.Reply {
        return self.call(.{ .lock = target });
    }

    pub fn unlock(self: *Client, target: rpc_mod.Datastore) SessionError!reply_mod.Reply {
        return self.call(.{ .unlock = target });
    }

    pub fn commit(self: *Client, c: rpc_mod.Commit) SessionError!reply_mod.Reply {
        return self.call(.{ .commit = c });
    }

    pub fn discardChanges(self: *Client) SessionError!reply_mod.Reply {
        return self.call(.discard_changes);
    }

    pub fn validate(self: *Client, source: rpc_mod.ConfigSource) SessionError!reply_mod.Reply {
        return self.call(.{ .validate = source });
    }

    pub fn killSession(self: *Client, session_id: u32) SessionError!reply_mod.Reply {
        return self.call(.{ .kill_session = session_id });
    }

    pub fn createSubscription(self: *Client, s: rpc_mod.CreateSubscription) SessionError!reply_mod.Reply {
        return self.call(.{ .create_subscription = s });
    }

    /// Caller-supplied operation XML inside our correlated `<rpc>` envelope.
    pub fn raw(self: *Client, operation_xml: []const u8) SessionError!reply_mod.Reply {
        return self.call(.{ .raw = operation_xml });
    }

    /// §7.8 `<close-session>`: request a graceful close and consume the `<ok/>`.
    /// The session is `.closed` afterwards even if the peer answered with an
    /// error (it is not going to serve us either way).
    pub fn closeSession(self: *Client) SessionError!void {
        var r = try self.call(.close_session);
        defer r.deinit();
        self.state = .closed;
        try r.expectOk();
    }
};

// ── SSH transport adapter (RFC 6242 §4) ────────────────────────────────────

/// Drives a `ssh.connection.Session` that has had `subsystem("netconf")`
/// requested on it. Owns nothing: the SSH session's lifetime is the caller's.
///
///     var s = try ssh.openSession(&t, gpa, .{});
///     defer s.deinit();
///     try s.subsystem("netconf");
///     var adapter: netconf.SshTransport = .init(&s);
///     var c = try netconf.Client.init(gpa, adapter.transport(), .{});
///
/// `read` consumes whatever the SSH session has already buffered before
/// pumping for more, and clears the session's `stdout` as it goes so a long
/// session cannot grow it without bound.
///
/// This adapter never produces `error.Canceled`. It owns no file descriptor
/// to recover a cancellation from: `pumpOnce` below folds a failure from
/// `ssh.connection.Session` into `ReadFailed` already, and by the time it
/// gets there the real socket is two layers further down, behind
/// `ssh.transport.Transport`'s type-erased `*std.Io.Reader` — the concrete
/// reader whose out-of-band `err` field would carry `Canceled` belongs to
/// whoever built that `std.Io.Reader` in the first place, not to this module.
/// A caller that needs to tell a cancel from a dead SSH connection has to
/// inspect that reader itself (see `ssh`'s own transport doc comment).
pub const SshTransport = struct {
    session: *ssh.connection.Session,
    /// True once the channel reported EOF/close.
    eof: bool = false,

    pub fn init(session: *ssh.connection.Session) SshTransport {
        return .{ .session = session };
    }

    pub fn transport(self: *SshTransport) Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: Transport.VTable = .{ .read = readFn, .write = writeFn };

    fn take(self: *SshTransport, buf: []u8) usize {
        const have = self.session.stdout.items;
        if (have.len == 0) return 0;
        const n = @min(buf.len, have.len);
        @memcpy(buf[0..n], have[0..n]);
        if (n == have.len) {
            self.session.stdout.clearRetainingCapacity();
        } else {
            std.mem.copyForwards(u8, self.session.stdout.items[0 .. have.len - n], have[n..]);
            self.session.stdout.shrinkRetainingCapacity(have.len - n);
        }
        return n;
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *SshTransport = @ptrCast(@alignCast(ctx));
        const buffered = self.take(buf);
        if (buffered != 0) return buffered;
        if (self.eof) return error.EndOfStream;
        // Exactly one blocking SSH message read.
        const ev = self.session.pumpOnce() catch return error.ReadFailed;
        switch (ev) {
            .eof, .closed => {
                self.eof = true;
                const n = self.take(buf);
                if (n != 0) return n;
                return error.EndOfStream;
            },
            else => return self.take(buf),
        }
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *SshTransport = @ptrCast(@alignCast(ctx));
        self.session.writeData(bytes) catch return error.WriteFailed;
    }
};

// ── tests: a fake NETCONF peer over an in-memory pipe ──────────────────────
//
// The peer speaks the real framing in both dialects and answers real RPCs, so
// the client's state machine (hello → dialect switch → correlated calls) is
// exercised end to end without a network. Cross-implementation validation is
// the job of the live test at the bottom of this file.

/// A `Transport` whose `read` always returns 0 ("nothing this round") and
/// never delivers a byte -- the shape README's "Read timeouts" recipe
/// produces from a socket that never becomes readable. Used only to prove
/// `Options.max_idle_reads` bounds `Client.receive`'s loop (N2); everything
/// else in this file uses `FakePeer`, which speaks real NETCONF.
const AlwaysIdleTransport = struct {
    fn readFn(_: *anyopaque, _: []u8) TransportError!usize {
        return 0;
    }
    fn writeFn(_: *anyopaque, _: []const u8) TransportError!void {}
    const vtable: Transport.VTable = .{ .read = readFn, .write = writeFn };
    fn transport(self: *AlwaysIdleTransport) Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

const FakePeer = struct {
    gpa: std.mem.Allocator,
    /// Bytes the client has written and the peer has not yet consumed.
    inbox: std.ArrayList(u8) = .empty,
    /// Bytes the peer has produced for the client to read.
    outbox: std.ArrayList(u8) = .empty,
    decoder: framing.Framer,
    dialect: framing.Dialect = .end_of_message,
    session_id: u32 = 4,
    caps: []const []const u8,
    /// Feed the client at most this many bytes per read — set to 1 to prove
    /// the client survives one-byte-at-a-time delivery.
    drip: usize = 0,
    /// Push a notification before the next reply.
    notify_before_reply: bool = false,
    /// Answer the next request with this message-id instead of the real one.
    forge_message_id: ?u64 = null,
    hello_sent: bool = false,
    /// Hold the next reply back instead of putting it in `outbox` — released
    /// later with `releaseHeld`, so a test can make a *later* request's
    /// reply arrive on the wire first (out-of-order pipelined replies).
    hold_next_reply: bool = false,
    held: std.ArrayList(u8) = .empty,

    fn init(gpa: std.mem.Allocator, caps: []const []const u8) FakePeer {
        return .{ .gpa = gpa, .caps = caps, .decoder = .init(gpa, .end_of_message, .{}) };
    }

    fn deinit(self: *FakePeer) void {
        self.inbox.deinit(self.gpa);
        self.outbox.deinit(self.gpa);
        self.held.deinit(self.gpa);
        self.decoder.deinit();
        self.* = undefined;
    }

    /// Put a previously-held reply onto the wire now, after whatever is
    /// already queued in `outbox` — so it is read by the client second.
    fn releaseHeld(self: *FakePeer) !void {
        try self.outbox.appendSlice(self.gpa, self.held.items);
        self.held.clearRetainingCapacity();
    }

    fn transport(self: *FakePeer) Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: Transport.VTable = .{ .read = readFn, .write = writeFn };

    fn emit(self: *FakePeer, payload: []const u8) !void {
        try self.emitTo(&self.outbox, payload);
    }

    fn emitTo(self: *FakePeer, dest: *std.ArrayList(u8), payload: []const u8) !void {
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        try framing.writeMessage(&aw.writer, self.dialect, payload);
        try dest.appendSlice(self.gpa, aw.written());
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *FakePeer = @ptrCast(@alignCast(ctx));
        if (self.outbox.items.len == 0) return error.EndOfStream;
        var n = @min(buf.len, self.outbox.items.len);
        if (self.drip != 0) n = @min(n, self.drip);
        @memcpy(buf[0..n], self.outbox.items[0..n]);
        std.mem.copyForwards(u8, self.outbox.items[0 .. self.outbox.items.len - n], self.outbox.items[n..]);
        self.outbox.shrinkRetainingCapacity(self.outbox.items.len - n);
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *FakePeer = @ptrCast(@alignCast(ctx));
        self.decoder.feed(bytes) catch return error.WriteFailed;
        while (self.decoder.next() catch return error.WriteFailed) |msg| {
            self.handle(msg) catch return error.WriteFailed;
        }
    }

    fn handle(self: *FakePeer, msg: []const u8) !void {
        switch (reply_mod.classify(msg)) {
            .hello => {
                var aw: std.Io.Writer.Allocating = .init(self.gpa);
                defer aw.deinit();
                try capabilities.writeHello(&aw.writer, self.caps, self.session_id);
                try self.emit(aw.written());
                self.hello_sent = true;
                // Both peers switch after the hello exchange.
                var client_caps = try capabilities.parseHello(self.gpa, msg, .client);
                defer client_caps.deinit();
                var mine = try capabilities.Capabilities.fromSlice(self.gpa, self.caps);
                defer mine.deinit();
                // A peer with no common base version keeps end-of-message
                // framing and lets the client be the one to give up — which is
                // exactly what the "no common base version" test asserts.
                const d = capabilities.negotiate(&mine, &client_caps.capabilities) catch return;
                self.dialect = d;
                try self.decoder.setDialect(d);
            },
            .rpc => try self.answer(msg),
            else => return error.UnexpectedMessage,
        }
    }

    fn answer(self: *FakePeer, msg: []const u8) !void {
        var doc = try @import("xml").parse(self.gpa, msg, .{ .doctype = .reject });
        defer doc.deinit();
        const id_text = doc.root.attr("", "message-id") orelse return error.MalformedReply;
        const op = doc.root.firstElementChild() orelse return error.MalformedReply;

        if (self.notify_before_reply) {
            self.notify_before_reply = false;
            try self.emit(
                \\<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
                \\  <eventTime>2026-07-22T10:00:00Z</eventTime>
                \\  <event xmlns="http://example.com/event/1.0"><severity>major</severity></event>
                \\</notification>
            );
        }

        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        if (self.forge_message_id) |forged| {
            self.forge_message_id = null;
            try w.print("<rpc-reply message-id=\"{d}\" xmlns=\"{s}\"><ok/></rpc-reply>", .{ forged, capabilities.base_ns });
        } else if (std.mem.eql(u8, op.local, "get-config") or std.mem.eql(u8, op.local, "get")) {
            try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\">\n", .{ id_text, capabilities.base_ns });
            try w.writeAll(
                \\  <data>
                \\    <top xmlns="http://example.com/schema/1.2/config">
                \\      <users><user><name>root</name></user></users>
                \\    </top>
                \\  </data>
                \\
            );
            try w.writeAll("</rpc-reply>");
        } else if (std.mem.eql(u8, op.local, "lock")) {
            // The RFC 6241 §7.5 failure case, verbatim apart from the id.
            try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\">\n", .{ id_text, capabilities.base_ns });
            try w.writeAll(
                \\  <rpc-error>
                \\    <error-type>protocol</error-type>
                \\    <error-tag>lock-denied</error-tag>
                \\    <error-severity>error</error-severity>
                \\    <error-message>
                \\      Lock failed, lock is already held
                \\    </error-message>
                \\    <error-info>
                \\      <session-id>454</session-id>
                \\    </error-info>
                \\  </rpc-error>
                \\
            );
            try w.writeAll("</rpc-reply>");
        } else {
            try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\"><ok/></rpc-reply>", .{ id_text, capabilities.base_ns });
        }
        if (self.hold_next_reply) {
            self.hold_next_reply = false;
            try self.emitTo(&self.held, aw.written());
        } else {
            try self.emit(aw.written());
        }
    }
};

const PeerAndClient = struct { peer: *FakePeer, client: *Client };

fn helloWith(gpa: std.mem.Allocator, peer_caps: []const []const u8, drip: usize) !PeerAndClient {
    return helloWithOpts(gpa, peer_caps, drip, .{});
}

fn helloWithOpts(
    gpa: std.mem.Allocator,
    peer_caps: []const []const u8,
    drip: usize,
    opts: Options,
) !PeerAndClient {
    const peer = try gpa.create(FakePeer);
    peer.* = FakePeer.init(gpa, peer_caps);
    peer.drip = drip;
    const client = try gpa.create(Client);
    client.* = try Client.init(gpa, peer.transport(), opts);
    return .{ .peer = peer, .client = client };
}

fn destroy(gpa: std.mem.Allocator, peer: *FakePeer, client: *Client) void {
    client.deinit();
    gpa.destroy(client);
    peer.deinit();
    gpa.destroy(peer);
}

test "hello exchange switches to chunked when both advertise :base:1.1" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1, capabilities.cap_candidate }, 0);
    defer destroy(gpa, h.peer, h.client);

    try testing.expectEqual(framing.Dialect.end_of_message, h.client.dialect());
    try h.client.hello();
    try testing.expectEqual(framing.Dialect.chunked, h.client.dialect());
    try testing.expectEqual(@as(?u32, 4), h.client.sessionId());
    try testing.expect(h.client.serverCapabilities().?.candidate);
    try testing.expectEqual(State.established, h.client.state);
}

test "hello exchange stays end-of-message against a :base:1.0-only peer" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{capabilities.cap_base_1_0}, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();
    try testing.expectEqual(framing.Dialect.end_of_message, h.client.dialect());

    // ...and a real RPC still round-trips in that dialect.
    var r = try h.client.getConfig(.running, .none);
    defer r.deinit();
    const data = try r.expectData();
    try testing.expect(std.mem.indexOf(u8, data, "<name>root</name>") != null);
}

test "no common base version is a typed error, not a guess" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{"http://example.com/only-vendor-stuff"}, 0);
    defer destroy(gpa, h.peer, h.client);
    try testing.expectError(error.NoCommonBaseVersion, h.client.hello());
}

test "message-ids are monotonic and every reply is correlated" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    var seen: [4]u64 = undefined;
    for (&seen, 0..) |*s, i| {
        _ = i;
        var r = try h.client.call(.discard_changes);
        defer r.deinit();
        try r.expectOk();
        s.* = try std.fmt.parseInt(u64, r.message_id.?, 10);
    }
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, &seen);
}

test "a forged message-id is rejected" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();
    h.peer.forge_message_id = 9999;
    try testing.expectError(error.MessageIdMismatch, h.client.call(.discard_changes));
}

// W2-B/netconf-F3: `receiveReply(id)` used to fail the whole call with
// `error.MessageIdMismatch` the instant it read a reply for any OTHER id —
// which broke a pipelining caller (the exact use `send`'s own doc comment
// advertises: "returned so a pipelining caller can correlate later") the
// moment the server answered two outstanding requests out of order, which
// RFC 6241 never promises not to do. The fix buffers a reply that belongs to
// a *known-outstanding* id and keeps reading for the one actually awaited.
test "receiveReply survives a pipelined reply arriving out of order" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    // Two requests outstanding; the peer answers the SECOND one first.
    h.peer.hold_next_reply = true;
    const id_a = try h.client.send(.discard_changes);
    const id_b = try h.client.send(.discard_changes);
    try h.peer.releaseHeld(); // id_a's reply now lands on the wire AFTER id_b's

    var r_a = try h.client.receiveReply(id_a);
    defer r_a.deinit();
    try r_a.expectOk();
    try testing.expectEqualStrings("1", r_a.message_id.?);

    var r_b = try h.client.receiveReply(id_b);
    defer r_b.deinit();
    try r_b.expectOk();
    try testing.expectEqualStrings("2", r_b.message_id.?);
}

test "one byte at a time: the whole session works with a 1-byte transport" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 1);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();
    try testing.expectEqual(framing.Dialect.chunked, h.client.dialect());
    var r = try h.client.getConfig(.running, .{ .subtree = "<top xmlns=\"http://example.com/schema/1.2/config\"><users/></top>" });
    defer r.deinit();
    _ = try r.expectData();
}

test "rpc-error surfaces as a typed error with the structured detail retained" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    var r = try h.client.lock(.running);
    defer r.deinit();
    try testing.expectError(error.RpcError, r.expectOk());
    const e = r.firstError().?;
    try testing.expectEqual(reply_mod.ErrorTag.lock_denied, e.tag);
    try testing.expectEqual(@as(?u32, 454), e.info_session_id);

    // callOk hands the reply back rather than dropping it.
    var kept: ?reply_mod.Reply = null;
    try testing.expectError(error.RpcError, h.client.callOk(.{ .lock = .running }, &kept));
    var k = kept.?;
    defer k.deinit();
    try testing.expectEqual(reply_mod.ErrorTag.lock_denied, k.firstError().?.tag);
}

test "an interleaved notification is queued, not mistaken for the reply" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1, capabilities.cap_notification }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    h.peer.notify_before_reply = true;
    var r = try h.client.call(.discard_changes);
    defer r.deinit();
    try r.expectOk();

    var n = (try h.client.nextNotification()).?;
    defer n.deinit();
    try testing.expectEqualStrings("2026-07-22T10:00:00Z", n.event_time);
    try testing.expect((try h.client.nextNotification()) == null);
}

test "nextNotification drains in arrival order (FIFO), not LIFO" {
    // N14 regression: `Client.notifications`'s own doc comment (line 146)
    // promises "in arrival order". Swapping `orderedRemove(0)` for `pop()` in
    // `nextNotification` used to survive the suite green because nothing
    // checked the ORDER of more than one queued notification, only that they
    // came back at all.
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    const template =
        \\<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><eventTime>{s}</eventTime></notification>
    ;
    // Pushed directly onto the queue, oldest first -- this is exactly what
    // `receiveReply`'s `.notification` branch does, one message at a time.
    inline for (.{ "A", "B", "C" }) |tag| {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try aw.writer.print(template, .{tag});
        try h.client.notifications.append(gpa, try gpa.dupe(u8, aw.written()));
    }

    var na = (try h.client.nextNotification()).?;
    defer na.deinit();
    var nb = (try h.client.nextNotification()).?;
    defer nb.deinit();
    var nc = (try h.client.nextNotification()).?;
    defer nc.deinit();
    // Arrival order was A, B, C. A `pop()` instead of `orderedRemove(0)`
    // would hand these back C, B, A.
    try testing.expectEqualStrings("A", na.event_time);
    try testing.expectEqualStrings("B", nb.event_time);
    try testing.expectEqualStrings("C", nc.event_time);
}

test "receiveReply rejects an interleaved <notification> in a foreign namespace instead of queueing it" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1, capabilities.cap_notification }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    // N10 regression: `classify` only looks at the root element's LOCAL
    // NAME, not its namespace, so this used to queue -- and only fail much
    // later, whenever some unrelated `nextNotification`/`awaitNotification`
    // call happened to dequeue it.
    try h.peer.emit("<notification xmlns=\"urn:evil\"><eventTime>2026-01-01T00:00:00Z</eventTime></notification>");
    try testing.expectError(error.NotANotification, h.client.call(.discard_changes));
    // And nothing was buffered before the error fired.
    try testing.expectEqual(@as(usize, 0), h.client.notifications.items.len);
}

test "receiveReply enforces max_queued_notifications rather than growing without bound" {
    const gpa = testing.allocator;
    const peer = try gpa.create(FakePeer);
    peer.* = FakePeer.init(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1, capabilities.cap_notification });
    defer {
        peer.deinit();
        gpa.destroy(peer);
    }
    var client = try Client.init(gpa, peer.transport(), .{ .max_queued_notifications = 1 });
    defer client.deinit();
    try client.hello();

    // Hold the real reply back so it does not land on the wire (and get
    // read) before the two notifications queued below.
    peer.hold_next_reply = true;
    const id = try client.send(.discard_changes);
    const notif =
        \\<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><eventTime>2026-01-01T00:00:00Z</eventTime></notification>
    ;
    // Two notifications ahead of the reply against a cap of 1: the FIRST
    // fills the queue (0 -> 1), the SECOND must be refused rather than
    // growing the queue further. Before this had a test, `C-NOTIFQ-DEL`
    // (deleting the check entirely) survived the suite green.
    try peer.emit(notif);
    try peer.emit(notif);
    try testing.expectError(error.NotificationQueueFull, client.receiveReply(id));
}

test "receiveReply enforces max_queued_replies rather than growing without bound" {
    const gpa = testing.allocator;
    const peer = try gpa.create(FakePeer);
    peer.* = FakePeer.init(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 });
    defer {
        peer.deinit();
        gpa.destroy(peer);
    }
    var client = try Client.init(gpa, peer.transport(), .{ .max_queued_replies = 1 });
    defer client.deinit();
    try client.hello();

    // Three requests outstanding, all three replies held back so they can be
    // released onto the wire in send order.
    peer.hold_next_reply = true;
    _ = try client.send(.discard_changes); // reply A -- held
    peer.hold_next_reply = true;
    _ = try client.send(.discard_changes); // reply B -- held
    peer.hold_next_reply = true;
    const id_c = try client.send(.discard_changes); // reply C -- held
    try peer.releaseHeld(); // A, B, C now on the wire, in that order

    // receiveReply(id_c) reads A first (mismatch, buffered: queue 0 -> 1),
    // then B (mismatch, queue already at the cap of 1) before it would ever
    // reach C. Before this had a test, `C-REPLYQ-DEL` survived the suite
    // green.
    try testing.expectError(error.ReplyQueueFull, client.receiveReply(id_c));
}

test "receive gives up with IdleTimeout instead of spinning forever on a Transport that always returns 0" {
    // N2 regression: README's "Read timeouts" recipe has a caller implement
    // `Transport.read` as one bounded wait followed by a read that returns 0
    // on timeout. A transport that returns 0 without ever completing a
    // message used to make `receive`'s loop spin at 116,275,395 reads/second
    // (ReleaseFast) with nothing to stop it -- not a blocked wait, live CPU.
    const gpa = testing.allocator;
    var t: AlwaysIdleTransport = .{};
    var client = try Client.init(gpa, t.transport(), .{ .max_idle_reads = 1000 });
    defer client.deinit();
    try testing.expectError(error.IdleTimeout, client.hello());
}

test "calls before hello, and hello twice, are state errors" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try testing.expectError(error.InvalidState, h.client.call(.discard_changes));
    try h.client.hello();
    try testing.expectError(error.InvalidState, h.client.hello());
}

test "hello exchange rejects a first message that is not classified as hello" {
    // N15 regression: `hello()`'s own `classify(msg) != .hello` check
    // (client.zig, right after `self.receive()` in `hello`) is the ONLY
    // guard against a peer that answers the hello exchange with something
    // else -- nothing upstream of it does. It had no dedicated test: a peer
    // that answered with, say, an `<rpc-reply>` was never exercised.
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    // Queued before the client sends anything, so it is the first (and, for
    // this test, only) message `receive()` decodes -- framed
    // `.end_of_message`, exactly like a real hello reply always is.
    try h.peer.emit("<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>");
    try testing.expectError(error.UnexpectedMessage, h.client.hello());
}

test "close-session ends the session" {
    const gpa = testing.allocator;
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();
    try h.client.closeSession();
    try testing.expectEqual(State.closed, h.client.state);
    try testing.expectError(error.InvalidState, h.client.call(.discard_changes));
}

test "the full operation surface round-trips against the fake peer" {
    const gpa = testing.allocator;
    // This test is about the wire encoding of every `Rpc` variant, not about
    // `Options.check_capabilities` -- the peer advertises every capability
    // the operation list below needs so the two concerns stay separate (see
    // the dedicated "check_capabilities" tests further down for the gating
    // behaviour itself).
    const h = try helloWith(gpa, &.{
        capabilities.cap_base_1_0,
        capabilities.cap_base_1_1,
        capabilities.cap_candidate,
        capabilities.cap_startup,
        capabilities.cap_confirmed_commit,
        capabilities.cap_validate,
        capabilities.cap_notification,
    }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    const ops = [_]rpc_mod.Rpc{
        .{ .get = .{} },
        .{ .get_config = .{ .source = .candidate } },
        .{ .edit_config = .{ .target = .candidate, .payload = .{ .config = "<top xmlns=\"urn:x\"/>" } } },
        .{ .copy_config = .{ .target = .startup, .source = .running } },
        .{ .delete_config = .startup },
        .{ .unlock = .candidate },
        .{ .commit = .{ .confirmed = true, .confirm_timeout = 120 } },
        .discard_changes,
        .{ .validate = .candidate },
        .{ .kill_session = 4 },
        .{ .create_subscription = .{ .stream = "NETCONF" } },
        .{ .raw = "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\"/>" },
    };
    for (ops) |op| {
        var r = try h.client.call(op);
        defer r.deinit();
        try testing.expect(!r.hasErrors());
    }
}

test "check_capabilities (default true) refuses locally an operation the peer never advertised" {
    const gpa = testing.allocator;
    // Only the two base versions -- none of :candidate, :startup, :url,
    // :confirmed-commit, :validate, :notification.
    const h = try helloWith(gpa, &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 }, 0);
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    // One representative per RFC 6241/5277 clause named in
    // `Options.check_capabilities`'s doc comment (§8.3, §8.7, §8.8, §8.4,
    // §8.6, RFC 5277 §3.1). None of these ever reach the fake peer: the
    // refusal is local, so `FakePeer.answer` (which does not itself check
    // capabilities -- see `handle`/`answer` above) never gets a chance to
    // answer wrong.
    const cases = [_]rpc_mod.Rpc{
        .{ .get_config = .{ .source = .candidate } }, // :candidate via source
        .{ .edit_config = .{ .target = .startup, .payload = .{ .config = "<x/>" } } }, // :startup via target
        .{ .edit_config = .{ .target = .running, .payload = .{ .url = "file:///x" } } }, // :url via payload
        .{ .copy_config = .{ .target = .running, .source = .startup } }, // :startup via source
        .{ .delete_config = .candidate }, // :candidate via Datastore
        .{ .lock = .candidate },
        .{ .unlock = .candidate },
        .{ .commit = .{ .confirmed = true } }, // :confirmed-commit
        .{ .validate = .running }, // :validate, unconditional on the op itself
        .{ .create_subscription = .{} }, // RFC 5277 §3.1 :notification
    };
    for (cases) |op| {
        try testing.expectError(error.CapabilityNotAdvertised, h.client.call(op));
    }
    // The control: an operation naming no gated datastore/feature at all
    // must NOT be refused by the same client/peer pair.
    var r = try h.client.call(.{ .get = .{} });
    r.deinit();
}

test "check_capabilities = false falls back to letting the peer answer" {
    const gpa = testing.allocator;
    // Same bare peer as above (no :candidate/:startup/:confirmed-commit/
    // :validate/:notification advertised), but the client opts out of the
    // local check.
    const h = try helloWithOpts(
        gpa,
        &.{ capabilities.cap_base_1_0, capabilities.cap_base_1_1 },
        0,
        .{ .check_capabilities = false },
    );
    defer destroy(gpa, h.peer, h.client);
    try h.client.hello();

    const cases = [_]rpc_mod.Rpc{
        .{ .get_config = .{ .source = .candidate } },
        .{ .commit = .{ .confirmed = true } },
        .{ .validate = .running },
        .{ .create_subscription = .{} },
    };
    for (cases) |op| {
        // FakePeer.answer does not implement its own capability policing --
        // it answers <ok/> (or <data/> for get-config) unconditionally, so
        // with the check off the request reaches it and succeeds, exactly
        // the RFC 6241 §7.1 "try it, let the peer decide" behaviour the
        // switch restores.
        var r = try h.client.call(op);
        defer r.deinit();
        try testing.expect(!r.hasErrors());
    }
}

// ── live interop against a real NETCONF server (gated) ──────────────────────
//
// Set NETCONF_TEST_SERVER=host:port (plus NETCONF_TEST_USER /
// NETCONF_TEST_PASSWORD) to run the real thing: our SSH client authenticates,
// requests the `netconf` subsystem, and this module performs a full
// hello → get-config → close-session round trip. Without the variable the test
// prints SKIPPED and passes, exactly like the live tests in `ssh` and `tc`.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

/// The live test dials a server the operator named in the environment, so
/// there is no known-hosts database to check against — host-key policy is
/// explicitly the caller's job (see `ssh.transport.HostKeyVerifier`).
const accept_any_host_key: ssh.transport.HostKeyVerifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict {
        return .accept;
    }
}.f };

fn liveRoundTrip(advertise: []const []const u8, want: framing.Dialect) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    const endpoint = envVar("NETCONF_TEST_SERVER") orelse {
        if (verboseSkip()) std.debug.print(
            "SKIPPED: live NETCONF interop (set NETCONF_TEST_SERVER=host:port" ++
                " NETCONF_TEST_USER=… NETCONF_TEST_PASSWORD=…)\n",
            .{},
        );
        return error.SkipZigTest;
    };
    const user = envVar("NETCONF_TEST_USER") orelse return error.SkipZigTest;
    const password = envVar("NETCONF_TEST_PASSWORD") orelse return error.SkipZigTest;

    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.SkipZigTest;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch return error.SkipZigTest;
    var stream = addr.connect(io, .{ .mode = .stream }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live NETCONF interop (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer stream.close(io);

    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    // Real SSH: transport handshake, RFC 4252 password auth, RFC 4254
    // "subsystem" request — the exact stack RFC 6242 §2 mandates.
    var t = try ssh.transport.connect(&sr.interface, &sw.interface, gpa, .{
        .verifier = accept_any_host_key,
        .host = host,
        .port = port,
    });
    var scratch: [4096]u8 = undefined;
    try t.requestService("ssh-userauth", &scratch);
    // `.{}` = no `BannerHandler`: this is a test harness, and a NETCONF
    // server's RFC 4252 §5.4 banner has nowhere to go here.
    try ssh.userauth.authenticatePassword(&t, gpa, user, password, .{});

    var session = try ssh.openSession(&t, gpa, .{});
    defer session.deinit();
    try session.subsystem("netconf");

    var adapter: SshTransport = .init(&session);
    var client = try Client.init(gpa, adapter.transport(), .{ .capabilities = advertise });
    defer client.deinit();

    // hello → the dialect must be the capability intersection, live.
    try client.hello();
    std.debug.print(
        "live NETCONF: session-id={?d} dialect={s} peer-capabilities={d}\n",
        .{ client.sessionId(), @tagName(client.dialect()), client.serverCapabilities().?.list.len },
    );
    try testing.expect(client.sessionId() != null);
    try testing.expectEqual(want, client.dialect());

    // get-config over the negotiated framing.
    {
        var r = try client.getConfig(.running, .none);
        defer r.deinit();
        try r.expectMessageId(1);
        const data = try r.expectData();
        try testing.expect(data.len != 0);
        std.debug.print("live NETCONF: get-config returned {d} bytes\n", .{data.len});
    }

    // get, i.e. a second correlated request on the same session.
    {
        var r = try client.get(.none);
        defer r.deinit();
        try r.expectMessageId(2);
        _ = try r.expectData();
    }

    // An operation the server does not implement must come back as a real
    // <rpc-error>, parsed, not as a dropped message.
    {
        var r = try client.raw("<no-such-operation xmlns=\"urn:example:test\"/>");
        defer r.deinit();
        try r.expectMessageId(3);
        try testing.expectError(error.RpcError, r.expectOk());
        const e = r.firstError().?;
        std.debug.print(
            "live NETCONF: unsupported op → error-tag={s} type={s}\n",
            .{ e.tag_text, e.type_text },
        );
        try testing.expect(e.tag_text.len != 0);
    }

    try client.closeSession();
    try testing.expectEqual(State.closed, client.state);
}

test "live interop: chunked framing (:base:1.1) against a real NETCONF server" {
    try liveRoundTrip(&capabilities.default_client_capabilities, .chunked);
}

test "live interop: end-of-message framing (:base:1.0 only) against a real NETCONF server" {
    // Advertising only :base:1.0 must drive the SAME server into the legacy
    // framing — the dialect decision proven against a third-party peer.
    try liveRoundTrip(&.{capabilities.cap_base_1_0}, .end_of_message);
}
