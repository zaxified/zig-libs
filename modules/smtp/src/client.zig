// SPDX-License-Identifier: MIT

//! The SMTP client: `session.Session` driven over a caller-supplied byte
//! stream.
//!
//! ## The read seam (no threading policy in this module)
//!
//! Exactly one call in this file blocks: `Client.pumpOnce`, which performs ONE
//! read on the `Transport` and feeds the bytes to the reply parser. Everything
//! above it (`receiveReply`, `connect`, `send`, `quit`) is a loop over that
//! call, and everything below it is a pure state machine. A caller that needs a
//! bounded wait implements it inside its own `Transport.read`, returning 0 for
//! "nothing this round" (0 is NOT end of stream — that is `error.EndOfStream`).
//! There is no timer thread here.
//!
//! ## STARTTLS is a seam
//!
//! When the session asks for `.start_tls`, this client calls the caller's
//! `TlsUpgrade`, which performs the handshake and returns the `Transport` for
//! the encrypted stream. Two things happen at that boundary, and both are
//! security properties rather than housekeeping:
//!
//! 1. **Buffered plaintext is refused.** If the reply parser holds any byte
//!    that arrived before the handshake, that is a server (or an attacker)
//!    pushing commands that would be replayed as though they had come over TLS
//!    — the plaintext-command-injection flaw that hit essentially every MTA in
//!    2011. It is `error.PlaintextInjection`, never "just leftover data".
//! 2. **The capability set is discarded** and EHLO re-issued, by
//!    `Session.tlsEstablished` (RFC 3207 §4.2).

const std = @import("std");
const builtin = @import("builtin");

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

const reply_mod = @import("reply.zig");
const session_mod = @import("session.zig");
const data_mod = @import("data.zig");
const message_mod = @import("message.zig");
const mime = @import("mime.zig");

pub const TransportError = error{
    /// The underlying byte stream failed while reading.
    ReadFailed,
    /// The underlying byte stream failed while writing.
    WriteFailed,
    /// The peer closed the stream.
    EndOfStream,
};

/// The byte-stream seam. One blocking `read`, one `write`; no timeouts, no
/// threads, no ownership.
///
/// `TransportError` has no room for `Canceled` — same shape as
/// `std.Io.Reader.Error`/`std.Io.Writer.Error`, and for the same reason: an
/// implementation of `read`/`write` that blocks inside `std.Io` (a
/// `std.Io.net.Stream.Reader`/`Writer`, or a plain `std.Io.Reader` handed
/// down from somewhere else) sees any `std.Io` cancellation collapse to a
/// generic failure at that boundary. If a caller of `Client` needs to tell a
/// canceled wait from a dead connection, the implementation of this vtable
/// is where that has to happen — inspect the concrete reader's/writer's
/// out-of-band `err` field before mapping to `error.ReadFailed`/
/// `error.WriteFailed`, the way `TcpTransport` in `modbus` does it.
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

/// The STARTTLS hook: perform the handshake on the current stream and return
/// the transport that speaks TLS. No TLS is implemented in this repo
/// (CONVENTIONS.md §2) — this is where a caller plugs one in.
pub const TlsUpgrade = struct {
    ctx: *anyopaque,
    upgrade: *const fn (ctx: *anyopaque) TransportError!Transport,
};

pub const Options = struct {
    session: session_mod.Options = .{},
    reply_limits: reply_mod.Limits = .{},
    reply_opts: reply_mod.Options = .{},
    /// Bytes per `pumpOnce` read.
    read_buffer_size: usize = 16 * 1024,
    /// Working buffer for streaming the dot-stuffed body.
    body_chunk: usize = 8 * 1024,
    /// Absent means "this caller cannot do TLS": a session that reaches
    /// `.start_tls` then fails with `error.TlsUnavailable` rather than
    /// continuing in the clear.
    tls: ?TlsUpgrade = null,
};

pub const ClientError = error{
    /// Bytes were buffered before the TLS handshake completed. See the file
    /// comment: this is command injection, not leftover data.
    PlaintextInjection,
} || TransportError || reply_mod.ParseError || session_mod.SessionError;

pub const Client = struct {
    gpa: std.mem.Allocator,
    transport: Transport,
    opts: Options,
    parser: reply_mod.Parser,
    sess: session_mod.Session,
    read_buf: []u8,
    body_buf: []u8,

    /// `writeBody`'s worst case leaves up to `body_chunk*2 - 1` bytes
    /// buffered going into `Stuffer.finish`, which itself writes up to 5
    /// bytes (a line-ending completion plus the `.CRLF` terminator) — both
    /// must fit in `body_buf` (`body_chunk*4`): `body_chunk*2 - 1 + 5 <=
    /// body_chunk*4`, i.e. `body_chunk >= 3`. Below that, `finish` can
    /// overflow the fixed buffer and fail with a generic `error.WriteFailed`
    /// that gives no hint the real problem is the configured chunk size.
    pub const min_body_chunk = 3;

    pub fn init(gpa: std.mem.Allocator, transport: Transport, opts: Options) (std.mem.Allocator.Error || error{BodyChunkTooSmall})!Client {
        if (opts.body_chunk < min_body_chunk) return error.BodyChunkTooSmall;
        const rbuf = try gpa.alloc(u8, opts.read_buffer_size);
        errdefer gpa.free(rbuf);
        const bbuf = try gpa.alloc(u8, opts.body_chunk * 4);
        errdefer gpa.free(bbuf);
        return .{
            .gpa = gpa,
            .transport = transport,
            .opts = opts,
            .parser = .init(gpa, opts.reply_limits, opts.reply_opts),
            .sess = .init(gpa, opts.session),
            .read_buf = rbuf,
            .body_buf = bbuf,
        };
    }

    pub fn deinit(self: *Client) void {
        self.sess.deinit();
        self.parser.deinit();
        self.gpa.free(self.read_buf);
        self.gpa.free(self.body_buf);
        self.* = undefined;
    }

    pub fn state(self: *const Client) session_mod.State {
        return self.sess.state;
    }

    pub fn serverCapabilities(self: *const Client) *const @import("capabilities.zig").Capabilities {
        return self.sess.serverCapabilities();
    }

    pub fn lastReply(self: *const Client) ?reply_mod.Reply {
        return self.sess.lastReply();
    }

    pub fn recipients(self: *const Client) []const session_mod.RecipientStatus {
        return self.sess.recipients();
    }

    // ── the one blocking call ──────────────────────────────────────────────

    /// Perform ONE read on the transport and feed the result to the reply
    /// parser. Returns the number of bytes read (0 = nothing this round).
    pub fn pumpOnce(self: *Client) ClientError!usize {
        const n = try self.transport.read(self.read_buf);
        if (n != 0) try self.parser.feed(self.read_buf[0..n]);
        return n;
    }

    /// The next complete reply, reading as many times as it takes. The slice
    /// inside is valid until the next call.
    pub fn receiveReply(self: *Client) ClientError!reply_mod.Reply {
        while (true) {
            if (try self.parser.next()) |r| return r;
            _ = try self.pumpOnce();
        }
    }

    /// Run the session until it has nothing more to do.
    pub fn drive(self: *Client) ClientError!void {
        while (true) switch (try self.sess.next()) {
            .send => |bytes| try self.transport.write(bytes),
            .send_body => |body| try self.writeBody(body),
            .recv => {
                const r = try self.receiveReply();
                try self.sess.feedReply(r);
            },
            .start_tls => {
                const up = self.opts.tls orelse return self.sess.tlsUnavailable();
                // Nothing may be buffered across the handshake.
                if (!self.parser.atBoundary()) return error.PlaintextInjection;
                self.transport = try up.upgrade(up.ctx);
                self.parser.deinit();
                self.parser = .init(self.gpa, self.opts.reply_limits, self.opts.reply_opts);
                try self.sess.tlsEstablished();
            },
            .done => return,
        };
    }

    /// Greeting → EHLO → STARTTLS → AUTH, leaving the session ready to send.
    pub fn connect(self: *Client) ClientError!void {
        try self.drive();
    }

    /// One transaction: MAIL/RCPT/DATA plus the body.
    pub fn sendEnvelope(self: *Client, env: session_mod.Envelope) ClientError!void {
        try self.sess.beginTransaction(env);
        try self.drive();
    }

    /// Compose and send in one call. `random` supplies MIME boundaries and, if
    /// the message has none, its `Message-ID`.
    pub fn sendMessage(
        self: *Client,
        msg: message_mod.Message,
        random: std.Random,
        render_opts: message_mod.RenderOptions,
        env_extra: struct { from: ?[]const u8 = null, to: []const []const u8 = &.{} },
    ) (ClientError || message_mod.RenderError)![]u8 {
        const doc = try message_mod.render(self.gpa, msg, random, render_opts);
        errdefer self.gpa.free(doc);
        const from = env_extra.from orelse msg.from.addr;
        try self.sendEnvelope(.{
            .from = from,
            .to = env_extra.to,
            .body = doc,
            .eight_bit = !mime.isAscii(doc),
        });
        // The caller gets the exact octets that went out — that is what a
        // golden, a log or a Sent folder needs.
        return doc;
    }

    /// QUIT and wait for the acknowledgement.
    pub fn quit(self: *Client) ClientError!void {
        self.sess.requestQuit();
        try self.drive();
    }

    /// Stream the message dot-stuffed, in bounded pieces, so a large message is
    /// never copied whole into another buffer.
    fn writeBody(self: *Client, body: []const u8) ClientError!void {
        var w: std.Io.Writer = .fixed(self.body_buf);
        var st: data_mod.Stuffer = .init(.{});
        const chunk = self.opts.body_chunk;
        var i: usize = 0;
        while (i < body.len) : (i += chunk) {
            try st.write(&w, body[i..@min(i + chunk, body.len)]);
            if (w.buffered().len >= self.body_buf.len / 2) {
                try self.transport.write(w.buffered());
                w = .fixed(self.body_buf);
            }
        }
        try st.finish(&w);
        if (w.buffered().len != 0) try self.transport.write(w.buffered());
    }
};

// ── tests: a scripted in-memory peer ───────────────────────────────────────

/// An SMTP server made of canned replies. It records everything the client
/// wrote and un-stuffs the DATA stream, so a test can assert on the message the
/// "server" received — the same assertion the live test makes, minus the third
/// party.
const FakeServer = struct {
    gpa: std.mem.Allocator,
    replies: []const []const u8,
    idx: usize = 0,
    outbox: std.ArrayList(u8) = .empty,
    received: std.ArrayList(u8) = .empty,
    /// Set while the client is inside DATA.
    in_data: bool = false,
    unstuffer: ?data_mod.Unstuffer = null,
    messages: std.ArrayList([]u8) = .empty,
    /// Hand the client at most this many bytes per read (1 proves the client
    /// survives one-byte-at-a-time delivery).
    drip: usize = 0,
    tls_upgrades: usize = 0,

    fn init(gpa: std.mem.Allocator, replies: []const []const u8) FakeServer {
        return .{ .gpa = gpa, .replies = replies };
    }

    fn deinit(self: *FakeServer) void {
        self.outbox.deinit(self.gpa);
        self.received.deinit(self.gpa);
        if (self.unstuffer) |*u| u.deinit();
        for (self.messages.items) |m| self.gpa.free(m);
        self.messages.deinit(self.gpa);
        self.* = undefined;
    }

    fn transport(self: *FakeServer) Transport {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: Transport.VTable = .{ .read = readFn, .write = writeFn };

    fn pushNextReply(self: *FakeServer) !void {
        if (self.idx >= self.replies.len) return;
        try self.outbox.appendSlice(self.gpa, self.replies[self.idx]);
        self.idx += 1;
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *FakeServer = @ptrCast(@alignCast(ctx));
        if (self.outbox.items.len == 0) return error.EndOfStream;
        var n = @min(buf.len, self.outbox.items.len);
        if (self.drip != 0) n = @min(n, self.drip);
        @memcpy(buf[0..n], self.outbox.items[0..n]);
        std.mem.copyForwards(u8, self.outbox.items[0 .. self.outbox.items.len - n], self.outbox.items[n..]);
        self.outbox.shrinkRetainingCapacity(self.outbox.items.len - n);
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *FakeServer = @ptrCast(@alignCast(ctx));
        self.handle(bytes) catch return error.WriteFailed;
    }

    fn handle(self: *FakeServer, bytes: []const u8) !void {
        try self.received.appendSlice(self.gpa, bytes);
        var rest = bytes;
        while (rest.len != 0) {
            if (self.in_data) {
                const u = &self.unstuffer.?;
                // Feed byte-wise so the terminator is found exactly.
                var i: usize = 0;
                while (i < rest.len) : (i += 1) {
                    if (try u.feed(rest[i .. i + 1])) {
                        try self.messages.append(self.gpa, try self.gpa.dupe(u8, u.bytes()));
                        u.deinit();
                        self.unstuffer = null;
                        self.in_data = false;
                        try self.pushNextReply();
                        rest = rest[i + 1 ..];
                        break;
                    }
                } else return;
                continue;
            }
            const nl = std.mem.indexOf(u8, rest, "\r\n") orelse return;
            const line = rest[0..nl];
            rest = rest[nl + 2 ..];
            try self.pushNextReply();
            if (std.ascii.startsWithIgnoreCase(line, "DATA")) {
                self.in_data = true;
                self.unstuffer = data_mod.Unstuffer.init(self.gpa, .{});
            }
        }
    }
};

fn upgradeStub(ctx: *anyopaque) TransportError!Transport {
    const self: *FakeServer = @ptrCast(@alignCast(ctx));
    self.tls_upgrades += 1;
    return self.transport();
}

test "a whole conversation over the fake server, and the received message matches" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 1000000\r\n250 8BITMIME\r\n", // EHLO
        "250 2.1.0 Ok\r\n", // MAIL
        "250 2.1.5 Ok\r\n", // RCPT
        "354 End data\r\n", // DATA
        "250 2.0.0 Ok: queued\r\n", // body
        "221 2.0.0 Bye\r\n", // QUIT
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 mail.example.com ESMTP\r\n");

    var c = try Client.init(gpa, srv.transport(), .{ .session = .{ .tls = .disabled, .ehlo_domain = "client.example.org" } });
    defer c.deinit();
    try c.connect();
    try testing.expectEqual(session_mod.State.ready, c.state());

    // A body with a line that is exactly "." — the canonical transparency case.
    const body = "Subject: test\r\n\r\nbefore\r\n.\r\nafter\r\n";
    try c.sendEnvelope(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = body });
    try c.quit();

    try testing.expectEqual(@as(usize, 1), srv.messages.items.len);
    try testing.expectEqualStrings(body, srv.messages.items[0]);
    // ...and the wire really did carry the doubled period.
    try testing.expect(std.mem.indexOf(u8, srv.received.items, "before\r\n..\r\nafter") != null);
}

test "the same conversation with a one-byte-at-a-time transport" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250 PIPELINING\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
        "221 bye\r\n",
    });
    defer srv.deinit();
    srv.drip = 1;
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");

    var c = try Client.init(gpa, srv.transport(), .{ .session = .{ .tls = .disabled } });
    defer c.deinit();
    try c.connect();
    try c.sendEnvelope(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = ".\r\n..\r\n" });
    try c.quit();
    try testing.expectEqualStrings(".\r\n..\r\n", srv.messages.items[0]);
}

test "sendMessage composes and delivers, and returns the exact octets sent" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250 SIZE 1000000\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");

    var c = try Client.init(gpa, srv.transport(), .{ .session = .{ .tls = .disabled } });
    defer c.deinit();
    try c.connect();

    var prng = std.Random.DefaultPrng.init(99);
    const doc = try c.sendMessage(.{
        .from = .{ .name = "Alice", .addr = "alice@example.com" },
        .to = &.{.{ .addr = "bob@example.net" }},
        .subject = "Multipart with a dot line",
        .date = .{ .unix = 1784714400 },
        .body = .{ .multipart = .{ .parts = &.{
            .{ .text = .{ .body = "one\r\n.\r\ntwo\r\n" } },
            .{ .attachment = .{ .filename = "a.txt", .content_type = "text/plain", .data = "attached\n" } },
        } } },
    }, prng.random(), .{}, .{ .to = &.{"bob@example.net"} });
    defer gpa.free(doc);

    try testing.expectEqual(@as(usize, 1), srv.messages.items.len);
    try testing.expectEqualStrings(doc, srv.messages.items[0]);
    try testing.expect(std.mem.indexOf(u8, doc, "\r\n.\r\n") != null);
}

test "STARTTLS: buffered plaintext across the handshake is refused" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250 STARTTLS\r\n",
        // The 220 for STARTTLS, immediately followed by an injected reply that
        // the client would otherwise read as though it had arrived over TLS.
        "220 Ready to start TLS\r\n250 injected\r\n",
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");

    var c = try Client.init(gpa, srv.transport(), .{
        .session = .{ .tls = .required },
        .tls = .{ .ctx = &srv, .upgrade = upgradeStub },
    });
    defer c.deinit();
    try testing.expectError(error.PlaintextInjection, c.connect());
    try testing.expectEqual(@as(usize, 0), srv.tls_upgrades);
}

test "STARTTLS: a clean handshake upgrades and re-issues EHLO" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
        "220 Ready to start TLS\r\n",
        "250-mail.example.com Hello\r\n250 PIPELINING\r\n",
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");

    var c = try Client.init(gpa, srv.transport(), .{
        .session = .{ .tls = .required, .ehlo_domain = "c.example.org" },
        .tls = .{ .ctx = &srv, .upgrade = upgradeStub },
    });
    defer c.deinit();
    try c.connect();
    try testing.expectEqual(@as(usize, 1), srv.tls_upgrades);
    try testing.expectEqualStrings("EHLO c.example.org\r\nSTARTTLS\r\nEHLO c.example.org\r\n", srv.received.items);
    // The pre-TLS AUTH claim did not survive.
    try testing.expect(!c.serverCapabilities().auth.plain);
}

test "a caller with no TLS hook fails instead of continuing in the clear" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250-mail.example.com Hello\r\n250 STARTTLS\r\n",
        "220 Ready to start TLS\r\n",
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");
    var c = try Client.init(gpa, srv.transport(), .{ .session = .{ .tls = .required } });
    defer c.deinit();
    try testing.expectError(error.TlsUnavailable, c.connect());
}

test "a large body streams through bounded buffers" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{
        "250 mail.example.com\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
    });
    defer srv.deinit();
    try srv.outbox.appendSlice(gpa, "220 ready\r\n");

    // Every line is a single '.', so stuffing doubles the payload — the worst
    // case for the streaming buffer.
    const body = try gpa.alloc(u8, 3 * 20000);
    defer gpa.free(body);
    var i: usize = 0;
    while (i < body.len) : (i += 3) {
        body[i] = '.';
        body[i + 1] = '\r';
        body[i + 2] = '\n';
    }

    var c = try Client.init(gpa, srv.transport(), .{ .session = .{ .tls = .disabled }, .body_chunk = 1024 });
    defer c.deinit();
    try c.connect();
    try c.sendEnvelope(.{ .from = "a@example.com", .to = &.{"b@example.net"}, .body = body });
    try testing.expectEqualStrings(body, srv.messages.items[0]);
}

// W2-B/smtp-F5: `writeBody`'s fixed `body_buf` (`body_chunk*4`) is exactly
// tight against `Stuffer.finish`'s worst-case 5-byte trailer for
// `body_chunk < min_body_chunk` (3) — below that, `finish` can overflow the
// buffer and the caller sees a generic `error.WriteFailed` that gives no
// hint the real problem is its own `Options.body_chunk`. `init` now rejects
// it up front with a named error instead.
test "Client.init rejects a body_chunk too small for Stuffer.finish's worst case" {
    const gpa = testing.allocator;
    var srv = FakeServer.init(gpa, &.{});
    defer srv.deinit();

    try testing.expectError(error.BodyChunkTooSmall, Client.init(gpa, srv.transport(), .{ .body_chunk = 0 }));
    try testing.expectError(error.BodyChunkTooSmall, Client.init(gpa, srv.transport(), .{ .body_chunk = 2 }));

    var c = try Client.init(gpa, srv.transport(), .{ .body_chunk = Client.min_body_chunk });
    c.deinit();
}

// ── live interop against a real third-party SMTP server (gated) ─────────────
//
// Set SMTP_TEST_SERVER=host:port to run the real thing against, e.g., Python's
// `aiosmtpd`. SMTP_TEST_USER / SMTP_TEST_PASSWORD enable the AUTH leg, and
// SMTP_TEST_CAPTURE names a file the server writes the received message to, so
// the test can assert on what the server ACTUALLY got rather than on what we
// think we sent. Without SMTP_TEST_SERVER the test prints SKIPPED and passes,
// exactly like the live tests in `netconf`, `ssh` and `tc`.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

/// The reference `Transport` over a real socket: exactly one read per call
/// (`fillMore` performs one `readVec` and returns whatever arrived), no
/// timeout, no thread. Constructed in place because the reader/writer hold
/// pointers into its own buffers.
const NetTransport = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    rbuf: [8192]u8 = undefined,
    wbuf: [8192]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,

    fn setUp(self: *NetTransport) void {
        self.reader = self.stream.reader(self.io, &self.rbuf);
        self.writer = self.stream.writer(self.io, &self.wbuf);
    }

    fn transport(self: *NetTransport) Transport {
        return .{ .ctx = self, .vtable = &vt };
    }
    const vt: Transport.VTable = .{ .read = rd, .write = wr };

    fn rd(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *NetTransport = @ptrCast(@alignCast(ctx));
        const r = &self.reader.interface;
        if (r.buffered().len == 0) r.fillMore() catch return error.EndOfStream;
        const avail = r.buffered();
        if (avail.len == 0) return error.EndOfStream;
        const n = @min(buf.len, avail.len);
        @memcpy(buf[0..n], avail[0..n]);
        r.toss(n);
        return n;
    }

    fn wr(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *NetTransport = @ptrCast(@alignCast(ctx));
        const w = &self.writer.interface;
        w.writeAll(bytes) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
    }
};

test "live interop: a full session against a real SMTP server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    const endpoint = envVar("SMTP_TEST_SERVER") orelse {
        if (verboseSkip()) std.debug.print(
            "SKIPPED: live SMTP interop (set SMTP_TEST_SERVER=host:port," ++
                " optionally SMTP_TEST_USER/SMTP_TEST_PASSWORD/SMTP_TEST_CAPTURE)\n",
            .{},
        );
        return error.SkipZigTest;
    };
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.SkipZigTest;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch return error.SkipZigTest;
    var stream = addr.connect(io, .{ .mode = .stream }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live SMTP interop (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer stream.close(io);

    const nt = try gpa.create(NetTransport);
    defer gpa.destroy(nt);
    nt.* = .{ .io = io, .stream = stream };
    nt.setUp();

    const user = envVar("SMTP_TEST_USER");
    const pass = envVar("SMTP_TEST_PASSWORD");
    var opts: Options = .{ .session = .{
        .ehlo_domain = "client.example.org",
        .tls = .disabled,
        .allow_plaintext_auth = true,
    } };
    if (user != null and pass != null) {
        opts.session.credentials = .{ .username = user.?, .password = pass.? };
    }

    var c = try Client.init(gpa, nt.transport(), opts);
    defer c.deinit();
    try c.connect();

    const caps = c.serverCapabilities();
    std.debug.print(
        "live SMTP: greeting={s} pipelining={} size={?d} auth(plain={} login={}) 8bitmime={} smtputf8={} enhanced={}\n",
        .{ caps.domain, caps.pipelining, caps.max_size, caps.auth.plain, caps.auth.login, caps.eightbitmime, caps.smtputf8, caps.enhanced_status_codes },
    );
    if (user != null) try testing.expect(c.sess.authenticated);

    // A multipart message whose text part contains a line that is exactly ".".
    var prng = std.Random.DefaultPrng.init(0x5A17);
    const doc = try c.sendMessage(.{
        .from = .{ .name = "Zig Tester", .addr = "sender@example.com" },
        .to = &.{.{ .name = "Recipient Ř", .addr = "rcpt@example.net" }},
        .subject = "Živá zkouška — live interop",
        .date = .{ .unix = 1784714400, .offset_minutes = 120 },
        .message_id = "live-test@example.com",
        .body = .{ .multipart = .{ .subtype = .mixed, .parts = &.{
            .{ .multipart = .{ .subtype = .alternative, .parts = &.{
                .{ .text = .{ .body = "první\r\n.\r\ntřetí\r\n" } },
                .{ .text = .{ .subtype = "html", .body = "<p>první</p>\r\n<p>.</p>\r\n" } },
            } } },
            .{ .attachment = .{
                .filename = "účtenka.txt",
                .content_type = "text/plain",
                .data = "attachment line 1\n.\nattachment line 3\n",
            } },
        } } },
    }, prng.random(), .{}, .{ .to = &.{"rcpt@example.net"} });
    defer gpa.free(doc);
    std.debug.print("live SMTP: sent {d} octets, recipients accepted: {d}\n", .{ doc.len, c.recipients().len });
    try testing.expect(c.recipients()[0].accepted);

    try c.quit();
    try testing.expectEqual(session_mod.State.closed, c.state());

    // The real assertion: what the SERVER received, byte for byte.
    if (envVar("SMTP_TEST_CAPTURE")) |path| {
        const got = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 * 1024 * 1024)) catch |e| {
            std.debug.print("live SMTP: capture file {s} unreadable: {s}\n", .{ path, @errorName(e) });
            return e;
        };
        defer gpa.free(got);
        try testing.expectEqualStrings(doc, got);
        std.debug.print("live SMTP: server received {d} octets, byte-identical to what we sent\n", .{got.len});
    }
}
