// SPDX-License-Identifier: MIT

//! SSH-2.0 connection protocol (RFC 4254) — part 3 of this module: session
//! channels, window/flow control, and the `exec` request that turns the
//! part-1 transport + part-2 userauth into "run a command on the far end".
//!
//! Layering: everything here is an ordinary encrypted binary packet through
//! `transport.Transport.sendPacket`/`recvPacket` (part 1), and none of it is
//! reachable before `userauth.serveUserauth` has succeeded (part 2) — the
//! server side of userauth treats a channel message as a protocol error.
//!
//! Implemented, both roles:
//!   - §5.1 SSH_MSG_CHANNEL_OPEN `"session"` / _OPEN_CONFIRMATION /
//!     _OPEN_FAILURE,
//!   - §5.2 SSH_MSG_CHANNEL_DATA / _EXTENDED_DATA (stderr,
//!     `data_type_code == 1`) with real §5.2 window accounting:
//!     SSH_MSG_CHANNEL_WINDOW_ADJUST both ways, a sender that never exceeds
//!     the peer's window or `maximum packet size`, and a receiver that
//!     rejects an overrun instead of growing a buffer for it,
//!   - §5.3 SSH_MSG_CHANNEL_EOF / _CLOSE,
//!   - §6.5 `"exec"` and §6.5 `"subsystem"` channel requests with
//!     `want_reply` → SSH_MSG_CHANNEL_SUCCESS/_FAILURE, and §6.10
//!     `"exit-status"`.
//!
//! Deferred (documented in SPEC.md, not stubbed): `"pty-req"`, `"shell"`,
//! `"env"`, `"signal"`, `"exit-signal"`, `"window-change"` (§6.2-§6.10 apart
//! from exec/subsystem/exit-status), X11 and agent forwarding, TCP/IP port
//! forwarding and the associated global requests (§7), and more than one
//! channel per connection.

const std = @import("std");
const transport = @import("transport.zig");
const messages = @import("messages.zig");

const Cursor = messages.Cursor;

/// Default initial window we advertise (RFC 4254 §5.1 "initial window size":
/// how many bytes the peer may send before we adjust). 2 MiB, matching
/// OpenSSH's channel window order of magnitude.
pub const default_window_size: u32 = 2 * 1024 * 1024;

/// Default `maximum packet size` we advertise — the largest CHANNEL_DATA
/// payload the peer may put in one packet.
pub const default_max_packet_size: u32 = 32 * 1024;

/// The largest channel-data chunk this module will *send* in one packet,
/// whatever the peer advertises. Bounded by `transport.writePacket`'s
/// internal packet buffer (8 KiB) minus the CHANNEL_DATA header, padding and
/// MAC; the peer's `maximum packet size` is honoured on top of this
/// (`@min` of the two).
pub const max_send_chunk: u32 = 4096;

/// Cap on collected stdout/stderr in the one-shot `exec` helper.
pub const default_max_output: usize = 8 * 1024 * 1024;

pub const ChannelError = transport.TransportError || error{
    /// The peer answered SSH_MSG_CHANNEL_OPEN_FAILURE (or something that was
    /// not a confirmation).
    ChannelOpenFailed,
    /// A `want_reply` channel request was answered SSH_MSG_CHANNEL_FAILURE.
    ChannelRequestFailed,
    /// Operation attempted on a channel that is closed (or was never open),
    /// including a peer sending a message for a channel id we do not have.
    ChannelClosed,
    /// The peer sent more channel data than the window we advertised — a
    /// flow-control violation (RFC 4254 §5.2). We refuse it instead of
    /// buffering it.
    WindowOverrun,
    /// Collected output exceeded the caller's `max_output` bound.
    OutputTooLarge,
    /// A server-side command handler failed.
    CommandFailed,
};

fn msgType(p: transport.Packet) u8 {
    return if (p.payload.len == 0) 0 else p.payload[0];
}

/// How many bytes of scratch a channel reads one packet into. Must exceed
/// the `maximum packet size` we advertise plus framing.
const scratch_len = 128 * 1024;

// ── channel bookkeeping ────────────────────────────────────────────────────

/// One channel's RFC 4254 §5 state: the id pair and the two windows. Shared
/// by the client (`Session`) and the server (`serveSession`) so the flow
/// control is implemented exactly once.
pub const ChannelState = struct {
    local_id: u32,
    remote_id: u32 = 0,
    /// Bytes the peer may still send us before we adjust (§5.2).
    local_window: u32,
    /// What `local_window` was set to; we top it back up once it has been
    /// half consumed.
    local_window_initial: u32,
    /// Largest CHANNEL_DATA payload we let the peer send in one packet.
    local_max_packet: u32,
    /// Bytes we may still send (the peer's advertised window).
    remote_window: u32 = 0,
    /// Largest CHANNEL_DATA payload the peer accepts in one packet.
    remote_max_packet: u32 = 0,
    open: bool = false,
    sent_eof: bool = false,
    sent_close: bool = false,
    got_eof: bool = false,
    got_close: bool = false,
    /// §6.10 `exit-status`, once the peer has reported it.
    exit_status: ?u32 = null,

    /// Account for `n` received data bytes. Both RFC 4254 §5.2 limits are
    /// enforced on receipt: a chunk larger than the `maximum packet size` we
    /// advertised, and data beyond the window we granted, are violations —
    /// not something to make room for.
    fn acceptData(self: *ChannelState, n: usize) ChannelError!void {
        if (n > self.local_max_packet) return error.PacketTooLarge;
        return self.consumeLocalWindow(n);
    }

    fn consumeLocalWindow(self: *ChannelState, n: usize) ChannelError!void {
        if (n > self.local_window) return error.WindowOverrun;
        self.local_window -= @intCast(n);
    }
};

fn writeChannelHeader(w: *std.Io.Writer, msg: messages.MessageType, recipient: u32) std.Io.Writer.Error!void {
    try w.writeByte(@intFromEnum(msg));
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, recipient, .big);
    try w.writeAll(&b);
}

fn writeU32(w: *std.Io.Writer, v: u32) std.Io.Writer.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try w.writeAll(&b);
}

/// SSH_MSG_CHANNEL_WINDOW_ADJUST (§5.2).
fn sendWindowAdjust(t: *transport.Transport, recipient: u32, add: u32) ChannelError!void {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_WINDOW_ADJUST, recipient);
    try writeU32(&w, add);
    return t.sendPacket(w.buffered());
}

/// Top the peer's send allowance back up once we have consumed half of what
/// we advertised (the same hysteresis OpenSSH uses — one adjust per half
/// window rather than one per packet).
fn maybeAdjustWindow(t: *transport.Transport, ch: *ChannelState) ChannelError!void {
    if (ch.local_window * 2 > ch.local_window_initial) return;
    const add = ch.local_window_initial - ch.local_window;
    if (add == 0) return;
    try sendWindowAdjust(t, ch.remote_id, add);
    ch.local_window += add;
}

fn sendEofMsg(t: *transport.Transport, ch: *ChannelState) ChannelError!void {
    if (ch.sent_eof or ch.sent_close) return;
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_EOF, ch.remote_id);
    try t.sendPacket(w.buffered());
    ch.sent_eof = true;
}

fn sendCloseMsg(t: *transport.Transport, ch: *ChannelState) ChannelError!void {
    if (ch.sent_close) return;
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_CLOSE, ch.remote_id);
    try t.sendPacket(w.buffered());
    ch.sent_close = true;
}

/// §6.10 SSH_MSG_CHANNEL_REQUEST `"exit-status"` (never `want_reply`).
fn sendExitStatus(t: *transport.Transport, ch: *ChannelState, status: u32) ChannelError!void {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_REQUEST, ch.remote_id);
    try messages.writeString(&w, "exit-status");
    try w.writeByte(0); // want_reply = FALSE (§6.10)
    try writeU32(&w, status);
    return t.sendPacket(w.buffered());
}

// ── client: a session channel ──────────────────────────────────────────────

pub const SessionOptions = struct {
    /// Our channel number (§5.1 "sender channel"). Any value; only one
    /// channel per connection is supported, so the default is fine.
    local_channel_id: u32 = 0,
    window_size: u32 = default_window_size,
    max_packet_size: u32 = default_max_packet_size,
    /// Refuse to buffer more than this much stdout/stderr.
    max_output: usize = default_max_output,
};

/// A client-side RFC 4254 §6.1 `"session"` channel.
///
/// Owns the collected `stdout`/`stderr` and the packet scratch; `deinit`
/// frees them. Message handling funnels through `pumpOnce`, so a streaming
/// caller (NETCONF over `subsystem`, say) can interleave `writeData` and
/// `pumpOnce` and drain `stdout` itself, while the one-shot `exec` helper
/// below just pumps to EOF.
pub const Session = struct {
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    scratch: []u8,
    ch: ChannelState,
    stdout: std.ArrayList(u8) = .empty,
    stderr: std.ArrayList(u8) = .empty,
    max_output: usize,

    /// RFC 4254 §5.1: send SSH_MSG_CHANNEL_OPEN `"session"` and wait for the
    /// confirmation. Requires a transport that has completed userauth.
    pub fn open(
        t: *transport.Transport,
        gpa: std.mem.Allocator,
        opts: SessionOptions,
    ) ChannelError!Session {
        const scratch = try gpa.alloc(u8, scratch_len);
        errdefer gpa.free(scratch);

        var self = Session{
            .t = t,
            .gpa = gpa,
            .scratch = scratch,
            .max_output = opts.max_output,
            .ch = .{
                .local_id = opts.local_channel_id,
                .local_window = opts.window_size,
                .local_window_initial = opts.window_size,
                .local_max_packet = opts.max_packet_size,
            },
        };

        var buf: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
        try messages.writeString(&w, "session");
        try writeU32(&w, self.ch.local_id);
        try writeU32(&w, self.ch.local_window);
        try writeU32(&w, self.ch.local_max_packet);
        try t.sendPacket(w.buffered());

        while (true) {
            const pkt = try t.recvPacket(scratch);
            switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
                .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
                // OpenSSH sends `hostkeys-00@openssh.com` right after
                // userauth, i.e. exactly here.
                .SSH_MSG_GLOBAL_REQUEST => {
                    var c = Cursor{ .b = pkt.payload[1..] };
                    _ = try c.string();
                    if (try c.boolean())
                        try t.sendPacket(&[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_REQUEST_FAILURE)});
                    continue;
                },
                .SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                    var c = Cursor{ .b = pkt.payload[1..] };
                    const recipient = try c.uint32();
                    if (recipient != self.ch.local_id) return error.ChannelOpenFailed;
                    self.ch.remote_id = try c.uint32();
                    self.ch.remote_window = try c.uint32();
                    self.ch.remote_max_packet = try c.uint32();
                    if (self.ch.remote_max_packet == 0) return error.ChannelOpenFailed;
                    self.ch.open = true;
                    return self;
                },
                .SSH_MSG_CHANNEL_OPEN_FAILURE => return error.ChannelOpenFailed,
                else => return error.ProtocolError,
            }
        }
    }

    pub fn deinit(self: *Session) void {
        self.stdout.deinit(self.gpa);
        self.stderr.deinit(self.gpa);
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    /// §6.5: SSH_MSG_CHANNEL_REQUEST `"exec"` with `want_reply = TRUE`,
    /// waiting for SSH_MSG_CHANNEL_SUCCESS/_FAILURE.
    pub fn exec(self: *Session, command: []const u8) ChannelError!void {
        return self.request("exec", command);
    }

    /// §6.5: the `"subsystem"` request — same shape as `exec` with a
    /// subsystem name instead of a command line. This is the entry point a
    /// NETCONF-over-SSH (RFC 6242) caller wants (`subsystem("netconf")`),
    /// after which the channel is a bidirectional byte stream driven with
    /// `writeData`/`pumpOnce`.
    pub fn subsystem(self: *Session, name: []const u8) ChannelError!void {
        return self.request("subsystem", name);
    }

    /// Generic §5.4 channel request carrying a single `string` argument,
    /// with `want_reply = TRUE`.
    pub fn request(self: *Session, request_type: []const u8, argument: []const u8) ChannelError!void {
        if (!self.ch.open or self.ch.sent_close or self.ch.got_close) return error.ChannelClosed;

        const buf = try self.gpa.alloc(u8, 64 + request_type.len + argument.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try writeChannelHeader(&w, .SSH_MSG_CHANNEL_REQUEST, self.ch.remote_id);
        try messages.writeString(&w, request_type);
        try w.writeByte(1); // want_reply
        try messages.writeString(&w, argument);
        try self.t.sendPacket(w.buffered());

        // The reply may be preceded by data/window messages; `pumpOnce`
        // handles those and reports the verdict when it arrives.
        while (true) {
            switch (try self.pumpOnce()) {
                .request_success => return,
                .request_failure => return error.ChannelRequestFailed,
                .closed => return error.ChannelClosed,
                else => continue,
            }
        }
    }

    /// Send channel data (stdin), honouring the peer's window and maximum
    /// packet size (§5.2): never more than `remote_window` bytes in flight,
    /// never more than `min(remote_max_packet, max_send_chunk)` per packet.
    /// Blocks pumping incoming messages while the window is closed.
    pub fn writeData(self: *Session, data: []const u8) ChannelError!void {
        if (!self.ch.open or self.ch.sent_eof or self.ch.sent_close or self.ch.got_close)
            return error.ChannelClosed;
        var rest = data;
        while (rest.len > 0) {
            while (self.ch.remote_window == 0) {
                if (self.ch.got_close) return error.ChannelClosed;
                _ = try self.pumpOnce();
            }
            const limit = @min(@min(self.ch.remote_max_packet, max_send_chunk), self.ch.remote_window);
            const n = @min(@as(usize, limit), rest.len);
            var buf: [max_send_chunk + 64]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            try writeChannelHeader(&w, .SSH_MSG_CHANNEL_DATA, self.ch.remote_id);
            try messages.writeString(&w, rest[0..n]);
            try self.t.sendPacket(w.buffered());
            self.ch.remote_window -= @intCast(n);
            rest = rest[n..];
        }
    }

    /// §5.3 SSH_MSG_CHANNEL_EOF — "no more data from me".
    pub fn sendEof(self: *Session) ChannelError!void {
        return sendEofMsg(self.t, &self.ch);
    }

    /// §5.3 SSH_MSG_CHANNEL_CLOSE. After sending, only the peer's own CLOSE
    /// is still expected.
    pub fn close(self: *Session) ChannelError!void {
        return sendCloseMsg(self.t, &self.ch);
    }

    /// Pump until the peer closes the channel, collecting stdout/stderr and
    /// the §6.10 exit status. Answers the peer's CLOSE with our own.
    pub fn drain(self: *Session) ChannelError!void {
        while (!self.ch.got_close) {
            switch (try self.pumpOnce()) {
                .closed => break,
                else => continue,
            }
        }
        try sendCloseMsg(self.t, &self.ch);
    }

    pub fn exitStatus(self: *const Session) ?u32 {
        return self.ch.exit_status;
    }

    pub const Event = enum {
        data,
        extended_data,
        eof,
        closed,
        window_adjust,
        request_success,
        request_failure,
        /// A peer request we answered but that carried no payload of
        /// interest (e.g. `exit-status`), or an ignorable message.
        other,
    };

    /// Read and process exactly one incoming message. The streaming seam:
    /// data lands in `stdout`/`stderr`, windows are accounted for and topped
    /// up, `exit-status` is recorded.
    pub fn pumpOnce(self: *Session) ChannelError!Event {
        const pkt = try self.t.recvPacket(self.scratch);
        const mt: messages.MessageType = @enumFromInt(msgType(pkt));
        switch (mt) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => return .other,
            .SSH_MSG_DISCONNECT => return error.ChannelClosed,
            .SSH_MSG_GLOBAL_REQUEST => {
                // §4: answer any global request we do not implement.
                var c = Cursor{ .b = pkt.payload[1..] };
                _ = try c.string();
                if (try c.boolean())
                    try self.t.sendPacket(&[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_REQUEST_FAILURE)});
                return .other;
            },
            .SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                const add = try c.uint32();
                // §5.2 windows are 32-bit; saturate rather than wrap.
                self.ch.remote_window +|= add;
                return .window_adjust;
            },
            .SSH_MSG_CHANNEL_DATA => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                const data = try c.string();
                try self.ch.acceptData(data.len);
                if (self.stdout.items.len + data.len > self.max_output) return error.OutputTooLarge;
                try self.stdout.appendSlice(self.gpa, data);
                try maybeAdjustWindow(self.t, &self.ch);
                return .data;
            },
            .SSH_MSG_CHANNEL_EXTENDED_DATA => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                const code = try c.uint32();
                const data = try c.string();
                try self.ch.acceptData(data.len);
                if (code == messages.extended_data_stderr) {
                    if (self.stderr.items.len + data.len > self.max_output) return error.OutputTooLarge;
                    try self.stderr.appendSlice(self.gpa, data);
                }
                // An unknown data_type_code is counted against the window
                // (it consumed it) and dropped.
                try maybeAdjustWindow(self.t, &self.ch);
                return .extended_data;
            },
            .SSH_MSG_CHANNEL_EOF => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                self.ch.got_eof = true;
                return .eof;
            },
            .SSH_MSG_CHANNEL_CLOSE => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                self.ch.got_close = true;
                return .closed;
            },
            .SSH_MSG_CHANNEL_REQUEST => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                const req = try c.string();
                const want_reply = try c.boolean();
                if (std.mem.eql(u8, req, "exit-status")) {
                    self.ch.exit_status = try c.uint32();
                } else if (want_reply) {
                    var buf: [8]u8 = undefined;
                    var w: std.Io.Writer = .fixed(&buf);
                    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_FAILURE, self.ch.remote_id);
                    try self.t.sendPacket(w.buffered());
                }
                return .other;
            },
            .SSH_MSG_CHANNEL_SUCCESS => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                return .request_success;
            },
            .SSH_MSG_CHANNEL_FAILURE => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try self.expectOurChannel(&c);
                return .request_failure;
            },
            else => return error.ProtocolError,
        }
    }

    /// Every channel message starts with the *recipient* channel — ours. A
    /// message addressed to a channel we do not have is not something to
    /// silently apply to the one we do.
    fn expectOurChannel(self: *Session, c: *Cursor) ChannelError!void {
        const recipient = try c.uint32();
        if (recipient != self.ch.local_id) return error.ChannelClosed;
        if (!self.ch.open) return error.ChannelClosed;
    }
};

/// Result of the one-shot `exec` helper. `stdout`/`stderr` are owned by the
/// caller.
pub const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    /// §6.10 exit status, if the peer reported one (OpenSSH always does for
    /// a command that ran; `null` typically means the command died on a
    /// signal, which is reported by `exit-signal` — deferred).
    exit_status: ?u32,

    pub fn deinit(self: *ExecResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
        self.* = undefined;
    }
};

pub const ExecOptions = struct {
    session: SessionOptions = .{},
    /// Bytes to feed the remote command's stdin before signalling EOF.
    stdin: []const u8 = "",
};

/// Run `command` on the far end and collect its output — the ergonomic
/// entry point: open a session channel, `exec`, write stdin (if any) + EOF,
/// drain stdout/stderr until the peer closes, and return with the §6.10
/// exit status.
///
/// `t` must be a transport that has completed userauth
/// (`userauth.authenticate`).
pub fn exec(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    command: []const u8,
    opts: ExecOptions,
) ChannelError!ExecResult {
    var session = try Session.open(t, gpa, opts.session);
    defer session.deinit();

    try session.exec(command);
    if (opts.stdin.len > 0) try session.writeData(opts.stdin);
    try session.sendEof();
    try session.drain();

    return .{
        .stdout = try session.stdout.toOwnedSlice(gpa),
        .stderr = try session.stderr.toOwnedSlice(gpa),
        .exit_status = session.ch.exit_status,
    };
}

// ── server: serve one session channel ──────────────────────────────────────

pub const CommandError = std.mem.Allocator.Error || error{CommandFailed};

/// Server policy hook: run `command` for `user`, appending output to
/// `stdout`/`stderr`, and return the exit status the client will see in the
/// §6.10 `exit-status` request. `stdin` is whatever the client sent before
/// EOF. What "run" means (a real process, a routing table, a NETCONF
/// session) is entirely the caller's business — this module never spawns
/// anything.
pub const CommandHandler = *const fn (
    gpa: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) CommandError!u32;

pub const ServeConfig = struct {
    /// The authenticated identity (`userauth.AuthResult.user()`), passed
    /// through to the handlers.
    user: []const u8 = "",
    /// Handler for §6.5 `"exec"`. `null` → every exec request is answered
    /// SSH_MSG_CHANNEL_FAILURE.
    exec: ?CommandHandler = null,
    /// Handler for §6.5 `"subsystem"` (`command` is the subsystem name).
    subsystem: ?CommandHandler = null,
    window_size: u32 = default_window_size,
    max_packet_size: u32 = default_max_packet_size,
    /// Cap on buffered client stdin.
    max_input: usize = default_max_output,
    /// When the handler runs. `CommandHandler` is a one-shot function, not a
    /// pipe, so it cannot consume stdin *while* it runs the way a real
    /// process would:
    ///   - `.collect_until_eof` (default) — reply to the request
    ///     immediately, then buffer CHANNEL_DATA until the client sends
    ///     SSH_MSG_CHANNEL_EOF, and only then run the handler with the
    ///     complete stdin. Correct for batch use, but a client that never
    ///     sends EOF never gets output.
    ///   - `.ignore` — run the handler as soon as the request arrives, with
    ///     empty stdin. Right for commands that take no input, and immune to
    ///     a client that holds its stdin open.
    stdin_mode: enum { collect_until_eof, ignore } = .collect_until_eof,
};

/// Server: accept and serve exactly one `"session"` channel, then return.
///
/// Handles §5.1 open (rejecting any channel type other than `"session"`,
/// and any second channel, with SSH_MSG_CHANNEL_OPEN_FAILURE), buffers the
/// client's stdin with full window accounting, runs `config.exec` /
/// `config.subsystem` on the matching request, streams the result back as
/// CHANNEL_DATA / CHANNEL_EXTENDED_DATA (respecting the client's window and
/// maximum packet size), then sends `exit-status`, EOF and CLOSE.
///
/// Returns when the channel is closed both ways, or on SSH_MSG_DISCONNECT.
pub fn serveSession(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    config: ServeConfig,
) ChannelError!void {
    const scratch = try gpa.alloc(u8, scratch_len);
    defer gpa.free(scratch);

    var ch = ChannelState{
        .local_id = 0,
        .local_window = config.window_size,
        .local_window_initial = config.window_size,
        .local_max_packet = config.max_packet_size,
    };
    var stdin: std.ArrayList(u8) = .empty;
    defer stdin.deinit(gpa);
    var ran = false;
    // A request accepted but not yet run (waiting for the client's EOF, see
    // `ServeConfig.stdin_mode`). The command is copied out of the packet
    // scratch, which the next `recvPacket` overwrites.
    var pending: ?struct { handler: CommandHandler, command: []u8 } = null;
    defer if (pending) |p| gpa.free(p.command);

    while (true) {
        const pkt = try t.recvPacket(scratch);
        const mt: messages.MessageType = @enumFromInt(msgType(pkt));
        switch (mt) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
            .SSH_MSG_DISCONNECT => return,
            .SSH_MSG_GLOBAL_REQUEST => {
                var c = Cursor{ .b = pkt.payload[1..] };
                _ = try c.string();
                if (try c.boolean())
                    try t.sendPacket(&[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_REQUEST_FAILURE)});
            },
            .SSH_MSG_CHANNEL_OPEN => {
                var c = Cursor{ .b = pkt.payload[1..] };
                const kind = try c.string();
                const sender = try c.uint32();
                const window = try c.uint32();
                const max_packet = try c.uint32();
                if (ch.open or ch.got_close) {
                    try sendOpenFailure(t, sender, .resource_shortage, "only one session channel is supported");
                    continue;
                }
                if (!std.mem.eql(u8, kind, "session")) {
                    try sendOpenFailure(t, sender, .unknown_channel_type, "only \"session\" channels are supported");
                    continue;
                }
                if (max_packet == 0) {
                    try sendOpenFailure(t, sender, .connect_failed, "zero maximum packet size");
                    continue;
                }
                ch.remote_id = sender;
                ch.remote_window = window;
                ch.remote_max_packet = max_packet;
                ch.open = true;

                var buf: [32]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                try writeChannelHeader(&w, .SSH_MSG_CHANNEL_OPEN_CONFIRMATION, ch.remote_id);
                try writeU32(&w, ch.local_id);
                try writeU32(&w, ch.local_window);
                try writeU32(&w, ch.local_max_packet);
                try t.sendPacket(w.buffered());
            },
            .SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                ch.remote_window +|= try c.uint32();
            },
            .SSH_MSG_CHANNEL_DATA => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                const data = try c.string();
                try ch.acceptData(data.len);
                if (stdin.items.len + data.len > config.max_input) return error.OutputTooLarge;
                try stdin.appendSlice(gpa, data);
                try maybeAdjustWindow(t, &ch);
            },
            .SSH_MSG_CHANNEL_EXTENDED_DATA => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                _ = try c.uint32();
                const data = try c.string();
                try ch.acceptData(data.len);
                try maybeAdjustWindow(t, &ch);
            },
            .SSH_MSG_CHANNEL_EOF => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                ch.got_eof = true;
                // stdin is complete — now the handler can see all of it.
                if (pending) |p| {
                    defer gpa.free(p.command);
                    pending = null;
                    try runCommand(t, gpa, &ch, config, p.handler, p.command, stdin.items, scratch);
                }
            },
            .SSH_MSG_CHANNEL_CLOSE => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                ch.got_close = true;
                try sendCloseMsg(t, &ch);
                return;
            },
            .SSH_MSG_CHANNEL_REQUEST => {
                var c = Cursor{ .b = pkt.payload[1..] };
                try expectChannel(&ch, &c);
                // We have already torn our side down: a request now cannot
                // be served (RFC 4254 §5.3 — after CLOSE only the peer's
                // CLOSE is still expected).
                if (ch.sent_close) return error.ChannelClosed;
                const req = try c.string();
                const want_reply = try c.boolean();

                const handler: ?CommandHandler = if (std.mem.eql(u8, req, "exec"))
                    config.exec
                else if (std.mem.eql(u8, req, "subsystem"))
                    config.subsystem
                else
                    null;

                if (handler == null or ran) {
                    // pty-req / shell / env / signal / window-change and a
                    // second exec on the same channel all land here.
                    if (want_reply) try sendChannelReply(t, &ch, false);
                    continue;
                }
                const command = try c.string();
                if (want_reply) try sendChannelReply(t, &ch, true);
                ran = true;
                switch (config.stdin_mode) {
                    .ignore => try runCommand(t, gpa, &ch, config, handler.?, command, &.{}, scratch),
                    .collect_until_eof => {
                        if (ch.got_eof) {
                            try runCommand(t, gpa, &ch, config, handler.?, command, stdin.items, scratch);
                        } else {
                            pending = .{ .handler = handler.?, .command = try gpa.dupe(u8, command) };
                        }
                    },
                }
            },
            else => return error.ProtocolError,
        }
    }
}

/// Every channel message starts with the recipient channel — ours. A message
/// for a channel we never opened, or one the peer has already closed, is a
/// typed error rather than something applied to whatever channel we do have.
/// (`sent_close` is deliberately NOT checked here: the peer's own CLOSE in
/// answer to ours is the normal way §5.3 ends.)
fn expectChannel(ch: *ChannelState, c: *Cursor) ChannelError!void {
    const recipient = try c.uint32();
    if (!ch.open or ch.got_close) return error.ChannelClosed;
    if (recipient != ch.local_id) return error.ChannelClosed;
}

fn sendOpenFailure(
    t: *transport.Transport,
    sender: u32,
    reason: messages.ChannelOpenFailureReason,
    description: []const u8,
) ChannelError!void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_OPEN_FAILURE, sender);
    try writeU32(&w, @intFromEnum(reason));
    try messages.writeString(&w, description[0..@min(description.len, 128)]);
    try messages.writeString(&w, ""); // language tag
    return t.sendPacket(w.buffered());
}

fn sendChannelReply(t: *transport.Transport, ch: *ChannelState, ok: bool) ChannelError!void {
    var buf: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeChannelHeader(
        &w,
        if (ok) .SSH_MSG_CHANNEL_SUCCESS else .SSH_MSG_CHANNEL_FAILURE,
        ch.remote_id,
    );
    return t.sendPacket(w.buffered());
}

/// Run the handler and stream its result back, then close the channel down
/// the RFC 4254 §5.3 way: data → `exit-status` → EOF → CLOSE.
fn runCommand(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    ch: *ChannelState,
    config: ServeConfig,
    handler: CommandHandler,
    command: []const u8,
    stdin: []const u8,
    scratch: []u8,
) ChannelError!void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var err_out: std.ArrayList(u8) = .empty;
    defer err_out.deinit(gpa);

    const status = handler(gpa, config.user, command, stdin, &out, &err_out) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.CommandFailed => return error.CommandFailed,
    };

    try sendChannelData(t, ch, out.items, null, scratch);
    try sendChannelData(t, ch, err_out.items, messages.extended_data_stderr, scratch);
    try sendExitStatus(t, ch, status);
    try sendEofMsg(t, ch);
    try sendCloseMsg(t, ch);
}

/// Send `data` as CHANNEL_DATA (`data_type == null`) or CHANNEL_EXTENDED_DATA,
/// chunked to respect the peer's window and maximum packet size (§5.2).
/// Waits for SSH_MSG_CHANNEL_WINDOW_ADJUST when the window is exhausted.
fn sendChannelData(
    t: *transport.Transport,
    ch: *ChannelState,
    data: []const u8,
    data_type: ?u32,
    scratch: []u8,
) ChannelError!void {
    if (data.len == 0) return;
    var rest = data;
    while (rest.len > 0) {
        while (ch.remote_window == 0) {
            // The only message that can unblock us is a window adjust; any
            // other channel traffic is processed minimally.
            const pkt = try t.recvPacket(scratch);
            const mt: messages.MessageType = @enumFromInt(msgType(pkt));
            switch (mt) {
                .SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    var c = Cursor{ .b = pkt.payload[1..] };
                    _ = try c.uint32();
                    ch.remote_window +|= try c.uint32();
                },
                .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => {},
                .SSH_MSG_CHANNEL_EOF => ch.got_eof = true,
                .SSH_MSG_CHANNEL_CLOSE => {
                    ch.got_close = true;
                    return error.ChannelClosed;
                },
                else => return error.ProtocolError,
            }
        }
        const limit = @min(@min(ch.remote_max_packet, max_send_chunk), ch.remote_window);
        const n = @min(@as(usize, limit), rest.len);
        var buf: [max_send_chunk + 64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        if (data_type) |code| {
            try writeChannelHeader(&w, .SSH_MSG_CHANNEL_EXTENDED_DATA, ch.remote_id);
            try writeU32(&w, code);
        } else {
            try writeChannelHeader(&w, .SSH_MSG_CHANNEL_DATA, ch.remote_id);
        }
        try messages.writeString(&w, rest[0..n]);
        try t.sendPacket(w.buffered());
        ch.remote_window -= @intCast(n);
        rest = rest[n..];
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

test "ChannelState: a peer that exceeds the advertised window is rejected" {
    const t = std.testing;
    var ch = ChannelState{
        .local_id = 0,
        .local_window = 16,
        .local_window_initial = 16,
        .local_max_packet = 1024,
    };
    try ch.consumeLocalWindow(10);
    try t.expectEqual(@as(u32, 6), ch.local_window);
    // 7 > 6 remaining: a flow-control violation, not a buffer to grow.
    try t.expectError(error.WindowOverrun, ch.consumeLocalWindow(7));
    try ch.consumeLocalWindow(6);
    try t.expectEqual(@as(u32, 0), ch.local_window);
    try t.expectError(error.WindowOverrun, ch.consumeLocalWindow(1));
}

test "ChannelState: a chunk over the advertised maximum packet size is refused" {
    const t = std.testing;
    var ch = ChannelState{
        .local_id = 0,
        .local_window = 1 << 20,
        .local_window_initial = 1 << 20,
        .local_max_packet = 1024,
    };
    try ch.acceptData(1024);
    // Window is ample; it is the per-packet limit that bites (RFC 4254 §5.2).
    try t.expectError(error.PacketTooLarge, ch.acceptData(1025));
}

test "max_send_chunk fits in one binary packet" {
    // `transport.writePacket` encodes into an 8 KiB stack buffer; a full
    // chunk plus CHANNEL_EXTENDED_DATA header, padding and a 32-byte MAC
    // must stay under it or `exec` would fail on large output.
    try std.testing.expect(max_send_chunk + 13 + 16 + 32 + 4 < 8192);
}

// ── full-stack loopback self-interop: our client ↔ our server ──────────────
//
// The headline test of parts 2+3: a real TCP connection carrying transport
// KEX → publickey userauth → session channel → exec → stdout/stderr +
// exit-status → close, plus the reject cases (each with the positive control
// running through the same harness, so a "rejection" cannot be an artefact
// of the harness never working in the first place).

const userauth = @import("userauth.zig");
const server_mod = @import("server.zig");
const Ed25519 = std.crypto.sign.Ed25519;

/// Test-only mirrors of `server.zig`'s private loopback helpers (both files
/// need them; neither belongs in the public API).
fn testFillRandom(buf: []u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) @panic("getrandom failed");
        off += @intCast(signed);
    }
}

fn testListenLoopback(io: std.Io, port_out: *u16) !std.Io.net.Server {
    var tries: usize = 0;
    while (tries < 32) : (tries += 1) {
        var pb: [2]u8 = undefined;
        testFillRandom(&pb);
        const port: u16 = 20000 + (std.mem.readInt(u16, &pb, .big) % 20000);
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const s = addr.listen(io, .{ .reuse_address = true }) catch continue;
        port_out.* = port;
        return s;
    }
    return error.SkipZigTest;
}

fn acceptAnyHostKey(key_type: []const u8, key_blob: []const u8) bool {
    _ = key_type;
    _ = key_blob;
    return true;
}

fn testKey(seed_byte: u8) userauth.AuthKey {
    const seed: [32]u8 = [_]u8{seed_byte} ** 32;
    return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable };
}

/// The single authorized key of the test server, as a wire blob. Set by the
/// harness before each run (tests are sequential within a process).
const Authorized = struct {
    var blob: []const u8 = &.{};

    fn check(user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        return std.mem.eql(u8, user, "alice") and
            std.mem.eql(u8, algorithm, "ssh-ed25519") and
            std.mem.eql(u8, key_blob, blob);
    }
};

fn checkPassword(user: []const u8, password: []const u8) bool {
    return std.mem.eql(u8, user, "alice") and std.mem.eql(u8, password, "correct horse");
}

/// Test command handler: echoes identity/stdin, writes to stderr, and exits
/// with a distinctive non-zero status so `exit-status` cannot be faked by a
/// default.
fn testExecHandler(
    gpa: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) CommandError!u32 {
    if (std.mem.eql(u8, command, "big")) {
        // Larger than the tiny window the `big` case advertises, so the
        // send path must actually block on SSH_MSG_CHANNEL_WINDOW_ADJUST.
        try stdout.appendNTimes(gpa, 'x', 100_000);
        return 0;
    }
    try stdout.print(gpa, "ran '{s}' as {s}", .{ command, user });
    if (stdin.len > 0) try stdout.print(gpa, " stdin='{s}'", .{stdin});
    try stderr.appendSlice(gpa, "diagnostic");
    return 7;
}

const Case = enum {
    /// publickey (two-phase) → exec → stdout/stderr/exit-status.
    happy,
    /// Same, but the client skips the query phase (§7 allows both).
    happy_no_probe,
    /// password method.
    password,
    /// exec with stdin and 100 KB of output through a 16 KB window.
    big_output,
    /// Signature computed over a session id that is not this connection's.
    wrong_session_id,
    /// A key the server does not authorize.
    unauthorized_key,
    /// SSH_MSG_CHANNEL_OPEN before authenticating.
    exec_before_auth,
    /// A second `exec` after the channel has been closed.
    request_after_close,
};

const ClientCtx = struct {
    port: u16,
    case: Case,
    err: ?anyerror = null,
    stdout: []u8 = &.{},
    stderr: []u8 = &.{},
    exit_status: ?u32 = null,

    fn run(self: *ClientCtx) void {
        self.inner() catch |e| {
            self.err = e;
        };
    }

    fn inner(self: *ClientCtx) !void {
        const gpa = std.testing.allocator;
        var threaded = std.Io.Threaded.init(gpa, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", self.port);
        var stream: std.Io.net.Stream = blk: {
            var tries: usize = 0;
            while (tries < 60) : (tries += 1) {
                if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
                var ts = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
                _ = std.os.linux.nanosleep(&ts, null);
            }
            return error.ConnectionRefused;
        };
        defer stream.close(io);

        var rbuf: [32 * 1024]u8 = undefined;
        var wbuf: [32 * 1024]u8 = undefined;
        var sr = stream.reader(io, &rbuf);
        var sw = stream.writer(io, &wbuf);
        var t = try transport.connect(&sr.interface, &sw.interface, gpa, acceptAnyHostKey);

        var pbuf: [16 * 1024]u8 = undefined;
        try t.requestService("ssh-userauth", &pbuf);

        const key = testKey(0x11);
        switch (self.case) {
            .exec_before_auth => {
                // Skip userauth entirely and try to open a channel. The
                // server must refuse and disconnect.
                var buf: [64]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
                try messages.writeString(&w, "session");
                try writeU32(&w, 0);
                try writeU32(&w, default_window_size);
                try writeU32(&w, default_max_packet_size);
                try t.sendPacket(w.buffered());
                const pkt = try t.recvPacket(&pbuf);
                if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_DISCONNECT))
                    return error.ExpectedDisconnect;
                return;
            },
            .wrong_session_id => {
                const bogus = "not this connection's session id";
                const e = userauth.authenticatePublickeyBoundTo(&t, gpa, "alice", key, .{}, bogus);
                try std.testing.expectError(error.AuthenticationFailed, e);
                try t.sendDisconnect(.no_more_auth_methods_available, "give up");
                return;
            },
            .unauthorized_key => {
                const other = testKey(0x22);
                const e = userauth.authenticatePublickey(&t, gpa, "alice", other, .{});
                try std.testing.expectError(error.AuthenticationFailed, e);
                try t.sendDisconnect(.no_more_auth_methods_available, "give up");
                return;
            },
            .password => try userauth.authenticatePassword(&t, gpa, "alice", "correct horse"),
            .happy_no_probe => try userauth.authenticatePublickey(&t, gpa, "alice", key, .{ .probe_first = false }),
            else => try userauth.authenticatePublickey(&t, gpa, "alice", key, .{}),
        }

        if (self.case == .request_after_close) {
            var session = try Session.open(&t, gpa, .{});
            defer session.deinit();
            try session.exec("whoami");
            try session.sendEof();
            try session.drain(); // server closed; our CLOSE sent
            const e = session.exec("again");
            try std.testing.expectError(error.ChannelClosed, e);
            return;
        }

        const opts: ExecOptions = switch (self.case) {
            .big_output => .{ .session = .{ .window_size = 16 * 1024, .max_packet_size = 8 * 1024 } },
            else => .{ .stdin = "from-the-client" },
        };
        const command = if (self.case == .big_output) "big" else "whoami";
        const res = try exec(&t, gpa, command, opts);
        self.stdout = res.stdout;
        self.stderr = res.stderr;
        self.exit_status = res.exit_status;
    }
};

fn runCase(case: Case) !ClientCtx {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const host_key: server_mod.HostKey = testKey(0x33);
    const client_blob = try testKey(0x11).publicBlob(gpa);
    defer gpa.free(client_blob);
    Authorized.blob = client_blob;

    var port: u16 = 0;
    var listener = try testListenLoopback(io, &port);
    defer listener.deinit(io);

    var ctx = ClientCtx{ .port = port, .case = case };
    const th = try std.Thread.spawn(.{}, ClientCtx.run, .{&ctx});

    var server_err: ?anyerror = null;
    serverSide(io, &listener, gpa, host_key, case) catch |e| {
        server_err = e;
    };
    // Always join before reporting: the client thread owns allocations the
    // testing allocator will otherwise flag as leaked, and its error is
    // usually the root cause of a server-side EndOfStream.
    th.join();
    if (ctx.err) |e| {
        if (ctx.stdout.len > 0) gpa.free(ctx.stdout);
        if (ctx.stderr.len > 0) gpa.free(ctx.stderr);
        std.debug.print("client side of case .{t} failed: {t}\n", .{ case, e });
        return e;
    }
    if (server_err) |e| {
        if (ctx.stdout.len > 0) gpa.free(ctx.stdout);
        if (ctx.stderr.len > 0) gpa.free(ctx.stderr);
        return e;
    }
    return ctx;
}

fn serverSide(
    io: std.Io,
    listener: *std.Io.net.Server,
    gpa: std.mem.Allocator,
    host_key: server_mod.HostKey,
    case: Case,
) !void {
    var stream = try listener.accept(io);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const keys = [_]server_mod.HostKey{host_key};
    var t = try server_mod.accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });

    const auth_config = userauth.AuthConfig{
        .authorized_key = Authorized.check,
        .password = checkPassword,
        .banner = "zig-libs ssh test server\n",
        .max_attempts = 4,
    };

    switch (case) {
        // The server must refuse to leave the authentication protocol.
        .exec_before_auth => return std.testing.expectError(
            error.ProtocolError,
            userauth.serveUserauth(&t, gpa, auth_config),
        ),
        .wrong_session_id, .unauthorized_key => return std.testing.expectError(
            error.AuthenticationFailed,
            userauth.serveUserauth(&t, gpa, auth_config),
        ),
        else => {},
    }

    const auth = try userauth.serveUserauth(&t, gpa, auth_config);
    try std.testing.expectEqualStrings("alice", auth.user());
    try std.testing.expectEqual(
        @as(userauth.AuthMethod, if (case == .password) .password else .publickey),
        auth.method,
    );

    try serveSession(&t, gpa, .{
        .user = auth.user(),
        .exec = testExecHandler,
        .window_size = 16 * 1024,
        .max_packet_size = 8 * 1024,
    });
}

fn expectClientOk(ctx: *ClientCtx) !void {
    if (ctx.err) |e| return e;
}

test "loopback: publickey auth → session channel → exec → stdout/stderr/exit-status" {
    const t = std.testing;
    var ctx = try runCase(.happy);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
    try t.expectEqualStrings("ran 'whoami' as alice stdin='from-the-client'", ctx.stdout);
    try t.expectEqualStrings("diagnostic", ctx.stderr);
    try t.expectEqual(@as(?u32, 7), ctx.exit_status);
}

test "loopback: publickey without the query phase (RFC 4252 §7 direct signature)" {
    const t = std.testing;
    var ctx = try runCase(.happy_no_probe);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
    try t.expectEqual(@as(?u32, 7), ctx.exit_status);
}

test "loopback: password auth (RFC 4252 §8) → exec" {
    const t = std.testing;
    var ctx = try runCase(.password);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
    try t.expectEqualStrings("ran 'whoami' as alice stdin='from-the-client'", ctx.stdout);
}

test "loopback: 100 KB of output through a 16 KB window (flow control actually runs)" {
    const t = std.testing;
    var ctx = try runCase(.big_output);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
    try t.expectEqual(@as(usize, 100_000), ctx.stdout.len);
    for (ctx.stdout) |b| try t.expectEqual(@as(u8, 'x'), b);
    try t.expectEqual(@as(?u32, 0), ctx.exit_status);
}

test "loopback REJECT: a signature bound to a different session id is refused" {
    const t = std.testing;
    var ctx = try runCase(.wrong_session_id);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    // The client asserted internally that it got USERAUTH_FAILURE; the
    // server asserted it never authenticated anyone. Same key, same user,
    // same everything else as the passing `happy` case — only the session-id
    // binding differs.
    try expectClientOk(&ctx);
}

test "loopback REJECT: an unauthorized public key gets USERAUTH_FAILURE" {
    const t = std.testing;
    var ctx = try runCase(.unauthorized_key);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
}

test "loopback REJECT: opening a channel before userauth is a protocol error" {
    const t = std.testing;
    var ctx = try runCase(.exec_before_auth);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
}

test "loopback REJECT: a channel request after CLOSE is error.ChannelClosed" {
    const t = std.testing;
    var ctx = try runCase(.request_after_close);
    defer t.allocator.free(ctx.stdout);
    defer t.allocator.free(ctx.stderr);
    try expectClientOk(&ctx);
}

// ── live interop against real OpenSSH (gated; both directions) ─────────────
//
// The loopback tests above validate this module against itself, which is
// weaker than an external reference. These two do the real thing: our client
// authenticates to a real `sshd` with a public key and runs a command, and a
// real `ssh` client authenticates to our server and runs one. Each is skipped
// (`error.SkipZigTest`) if the OpenSSH binaries are absent.

/// Current user name, for `sshd` (which, when not running as root, can only
/// authenticate the user it runs as). Read from the environment at runtime —
/// never hardcoded.
fn currentUser() ?[]const u8 {
    const v = std.process.Environ.getPosix(std.testing.environ, "USER") orelse
        std.process.Environ.getPosix(std.testing.environ, "LOGNAME") orelse return null;
    if (v.len == 0 or v.len > 64) return null;
    return v;
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var f = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var fw = f.writer(io, &buf);
    try fw.interface.writeAll(contents);
    try fw.interface.flush();
}

test "live interop: our client → real OpenSSH sshd — publickey auth + exec + exit-status" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();

    const sshd_path = "/usr/sbin/sshd";
    cwd.access(io, sshd_path, .{}) catch return error.SkipZigTest;
    const user = currentUser() orelse return error.SkipZigTest;

    var rnd: [8]u8 = undefined;
    testFillRandom(&rnd);
    const hex = std.fmt.bytesToHex(&rnd, .lower);
    const dir_path = try std.fmt.allocPrint(gpa, "/tmp/zig_ssh_exec_{s}", .{&hex});
    defer gpa.free(dir_path);
    var work = cwd.createDirPathOpen(io, dir_path, .{}) catch return error.SkipZigTest;
    defer {
        work.close(io);
        cwd.deleteTree(io, dir_path) catch {};
    }

    // Host key + client key, both from the real ssh-keygen.
    const hk_path = try std.fmt.allocPrint(gpa, "{s}/hk", .{dir_path});
    defer gpa.free(hk_path);
    const ck_path = try std.fmt.allocPrint(gpa, "{s}/ck", .{dir_path});
    defer gpa.free(ck_path);
    for ([_][]const u8{ hk_path, ck_path }) |p| {
        var child = std.process.spawn(io, .{
            .argv = &.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "zig-ssh-exec-test", "-f", p },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        switch (child.wait(io) catch return error.SkipZigTest) {
            .exited => |c| if (c != 0) return error.SkipZigTest,
            else => return error.SkipZigTest,
        }
    }

    // authorized_keys = the client key's public half.
    const ck_pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{ck_path});
    defer gpa.free(ck_pub_path);
    const ck_pub = cwd.readFileAlloc(io, ck_pub_path, gpa, .limited(4096)) catch return error.SkipZigTest;
    defer gpa.free(ck_pub);
    const ak_path = try std.fmt.allocPrint(gpa, "{s}/authorized_keys", .{dir_path});
    defer gpa.free(ak_path);
    writeFile(io, ak_path, ck_pub) catch return error.SkipZigTest;

    // Our client-side key, loaded from the openssh-key-v1 private file.
    const ck_text = cwd.readFileAlloc(io, ck_path, gpa, .limited(16384)) catch return error.SkipZigTest;
    defer gpa.free(ck_text);
    const client_key = userauth.AuthKey.fromOpenSSH(ck_text, null) catch return error.SkipZigTest;

    var portbuf: [2]u8 = undefined;
    testFillRandom(&portbuf);
    const port: u16 = 20000 + (std.mem.readInt(u16, &portbuf, .big) % 20000);
    const port_opt = try std.fmt.allocPrint(gpa, "Port={d}", .{port});
    defer gpa.free(port_opt);
    const ak_opt = try std.fmt.allocPrint(gpa, "AuthorizedKeysFile={s}", .{ak_path});
    defer gpa.free(ak_opt);

    var sshd = std.process.spawn(io, .{
        .argv = &.{
            sshd_path,                         "-D",
            "-e",                              "-f",
            "/dev/null",                       "-h",
            hk_path,                           "-o",
            port_opt,                          "-o",
            "ListenAddress=127.0.0.1",         "-o",
            "UsePAM=no",                       "-o",
            "StrictModes=no",                  "-o",
            "PidFile=none",                    "-o",
            "LogLevel=QUIET",                  "-o",
            "PubkeyAuthentication=yes",        "-o",
            "PasswordAuthentication=no",       "-o",
            "KbdInteractiveAuthentication=no", "-o",
            ak_opt,
        },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    defer sshd.kill(io);

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var stream: std.Io.net.Stream = blk: {
        var tries: usize = 0;
        while (tries < 60) : (tries += 1) {
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            var ts = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&ts, null);
        }
        return error.SkipZigTest; // sshd never came up here
    };
    defer stream.close(io);

    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var t = try transport.connect(&sr.interface, &sw.interface, gpa, acceptAnyHostKey);
    // RFC 4252 publickey against a real sshd — the session-id binding has to
    // be byte-exact or OpenSSH rejects the signature.
    try userauth.authenticate(&t, gpa, user, client_key);

    // RFC 4254 §6.5 exec + §6.10 exit-status against a real sshd. `sh -c` so
    // the command text is shell-independent (sshd runs it through the
    // account's login shell, whatever that is).
    var res = try exec(&t, gpa, "/bin/sh -c 'printf hello; printf oops >&2; exit 7'", .{});
    defer res.deinit(gpa);

    try std.testing.expectEqualStrings("hello", res.stdout);
    try std.testing.expectEqualStrings("oops", res.stderr);
    try std.testing.expectEqual(@as(?u32, 7), res.exit_status);
}

/// Our server's authorized key for the live `ssh`-client test.
const LiveAuthorized = struct {
    var blob: [512]u8 = undefined;
    var blob_len: usize = 0;

    fn check(user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        _ = user;
        _ = algorithm;
        return std.mem.eql(u8, key_blob, blob[0..blob_len]);
    }
};

fn liveExecHandler(
    gpa: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) CommandError!u32 {
    _ = stdin;
    _ = user;
    try stdout.print(gpa, "zig-libs ran: {s}\n", .{command});
    try stderr.appendSlice(gpa, "note\n");
    return 3;
}

test "live interop: real OpenSSH ssh client → our server — publickey auth + exec + exit-status" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();

    cwd.access(io, "/usr/bin/ssh", .{}) catch return error.SkipZigTest;

    var rnd: [8]u8 = undefined;
    testFillRandom(&rnd);
    const hex = std.fmt.bytesToHex(&rnd, .lower);
    const dir_path = try std.fmt.allocPrint(gpa, "/tmp/zig_ssh_srvexec_{s}", .{&hex});
    defer gpa.free(dir_path);
    var work = cwd.createDirPathOpen(io, dir_path, .{}) catch return error.SkipZigTest;
    defer {
        work.close(io);
        cwd.deleteTree(io, dir_path) catch {};
    }

    // The client key the real `ssh` will authenticate with.
    const ck_path = try std.fmt.allocPrint(gpa, "{s}/ck", .{dir_path});
    defer gpa.free(ck_path);
    {
        var child = std.process.spawn(io, .{
            .argv = &.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "zig-ssh-srvexec", "-f", ck_path },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        switch (child.wait(io) catch return error.SkipZigTest) {
            .exited => |c| if (c != 0) return error.SkipZigTest,
            else => return error.SkipZigTest,
        }
    }
    // Authorize exactly that key: parse its wire blob out of the .pub line.
    {
        const pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{ck_path});
        defer gpa.free(pub_path);
        const text = cwd.readFileAlloc(io, pub_path, gpa, .limited(4096)) catch return error.SkipZigTest;
        defer gpa.free(text);
        var it = std.mem.tokenizeScalar(u8, text, ' ');
        _ = it.next() orelse return error.SkipZigTest; // "ssh-ed25519"
        const b64 = it.next() orelse return error.SkipZigTest;
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(b64) catch return error.SkipZigTest;
        if (n > LiveAuthorized.blob.len) return error.SkipZigTest;
        dec.decode(LiveAuthorized.blob[0..n], b64) catch return error.SkipZigTest;
        LiveAuthorized.blob_len = n;
    }

    var port: u16 = 0;
    var listener = try testListenLoopback(io, &port);
    defer listener.deinit(io);

    const port_str = try std.fmt.allocPrint(gpa, "{d}", .{port});
    defer gpa.free(port_str);
    const out_path = try std.fmt.allocPrint(gpa, "{s}/out", .{dir_path});
    defer gpa.free(out_path);

    // Run the real client through `sh` so its stdout lands in a file we can
    // check (and its stdin is /dev/null, so it sends CHANNEL_EOF promptly).
    const cmdline = try std.fmt.allocPrint(gpa,
        \\/usr/bin/ssh -p {s} -F /dev/null -i {s} -o IdentitiesOnly=yes \
        \\ -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        \\ -o GlobalKnownHostsFile=/dev/null -o PreferredAuthentications=publickey \
        \\ -o BatchMode=yes -o ConnectTimeout=10 -n \
        \\ alice@127.0.0.1 'uname -a' > {s} 2>/dev/null; echo $? >> {s}
    , .{ port_str, ck_path, out_path, out_path });
    defer gpa.free(cmdline);

    var ssh_child = std.process.spawn(io, .{
        .argv = &.{ "/bin/sh", "-c", cmdline },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    defer ssh_child.kill(io);

    var stream = try listener.accept(io);
    defer stream.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const host_key: server_mod.HostKey = testKey(0x44);
    const keys = [_]server_mod.HostKey{host_key};
    var t = try server_mod.accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });

    // Real OpenSSH client, our RFC 4252 verifier: it must produce a
    // session-id-bound signature our `serveUserauth` accepts.
    const auth = try userauth.serveUserauth(&t, gpa, .{ .authorized_key = LiveAuthorized.check });
    try std.testing.expectEqualStrings("alice", auth.user());

    // …and our RFC 4254 server must give it output + an exit status. The
    // real client holds stdin open in some configurations, so run the
    // handler as soon as the request arrives.
    try serveSession(&t, gpa, .{
        .user = auth.user(),
        .exec = liveExecHandler,
        .stdin_mode = .ignore,
    });

    _ = ssh_child.wait(io) catch {};
    const out = try cwd.readFileAlloc(io, out_path, gpa, .limited(4096));
    defer gpa.free(out);
    try std.testing.expectEqualStrings("zig-libs ran: uname -a\n3\n", out);
}

// ── offline reject tests (crafted wire input, no socket, no threads) ───────

/// Frame `payloads` as plaintext binary packets (the `.none` cipher state),
/// so a crafted message stream can be fed straight into `serveSession`.
fn framePackets(out: []u8, payloads: []const []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    var cipher: transport.CipherState = .none;
    for (payloads) |p| try transport.writePacket(&w, &cipher, p);
    return w.buffered();
}

fn channelOpenPayload(buf: []u8, sender: u32, window: u32, max_packet: u32) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
    try messages.writeString(&w, "session");
    try writeU32(&w, sender);
    try writeU32(&w, window);
    try writeU32(&w, max_packet);
    return w.buffered();
}

// ── fuzz: the CHANNEL-layer decode entry (RFC 4254), not the transport ─────
//
// The module's other four fuzz targets all sit at or below the Binary Packet
// Protocol (`messages.readString`/`readMpint`, `KexInit.decode`,
// `transport.readPacket`). None of them reach this file: `serveSession` and
// `Session.pumpOnce` decode their fields with `messages.Cursor`, a different
// decoder from the allocating `readString`/`readMpint` pair that is fuzzed —
// so before this harness the entire §5/§6 message layer had zero fuzz
// coverage. This drives arbitrary *well-framed* channel messages (the packet
// layer is already trusted by the time they arrive) into the server loop,
// which is where a peer's bytes are turned into channel ids, window
// arithmetic and length-prefixed payloads.
test "fuzz: serveSession never panics on an arbitrary channel message stream" {
    try std.testing.fuzz({}, fuzzServeSession, .{});
}

fn fuzzServeSession(_: void, smith: *std.testing.Smith) !void {
    var payload_store: [6][192]u8 = undefined;
    var payloads: [6][]const u8 = undefined;
    const n: usize = smith.valueRangeAtMost(u8, 1, @intCast(payloads.len));
    for (0..n) |i| {
        var w: std.Io.Writer = .fixed(&payload_store[i]);
        // Bias the message type into the channel range (90..100) so the
        // budget is spent inside RFC 4254 handling rather than bouncing off
        // the `else => ProtocolError` arm.
        const mt: u8 = if (smith.boolWeighted(4, 1))
            smith.valueRangeAtMost(u8, 90, 100)
        else
            smith.valueRangeAtMost(u8, 0, 255);
        w.writeByte(mt) catch return;
        var body: [160]u8 = undefined;
        const present: usize = smith.valueRangeAtMost(u8, 0, @intCast(body.len));
        smith.bytes(body[0..present]);
        w.writeAll(body[0..present]) catch return;
        payloads[i] = w.buffered();
    }

    var wire: [4096]u8 = undefined;
    const framed = framePackets(&wire, payloads[0..n]) catch return;

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [8192]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    // Small window/packet bounds so the flow-control arithmetic is exercised
    // near its edges rather than under a 2 MiB default that never closes.
    serveSession(&tr, std.testing.allocator, .{
        .exec = testExecHandler,
        .window_size = 64,
        .max_packet_size = 128,
        .max_input = 4096,
    }) catch return;
}

test "serveSession REJECT: a peer that overruns the advertised window" {
    const t = std.testing;

    var open_buf: [64]u8 = undefined;
    const open = try channelOpenPayload(&open_buf, 7, 4096, 4096);

    // 64 bytes of CHANNEL_DATA when only a 16-byte window was granted.
    var data_buf: [256]u8 = undefined;
    var dw: std.Io.Writer = .fixed(&data_buf);
    try writeChannelHeader(&dw, .SSH_MSG_CHANNEL_DATA, 0);
    try messages.writeString(&dw, &[_]u8{'z'} ** 64);

    var wire: [1024]u8 = undefined;
    const framed = try framePackets(&wire, &.{ open, dw.buffered() });

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    try t.expectError(error.WindowOverrun, serveSession(&tr, t.allocator, .{
        .exec = testExecHandler,
        .window_size = 16,
        .max_packet_size = 4096,
    }));
}

test "serveSession REJECT: a channel request for a channel that is not open" {
    const t = std.testing;

    var req_buf: [64]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&req_buf);
    try writeChannelHeader(&rw, .SSH_MSG_CHANNEL_REQUEST, 0);
    try messages.writeString(&rw, "exec");
    try rw.writeByte(1);
    try messages.writeString(&rw, "id");

    var wire: [512]u8 = undefined;
    const framed = try framePackets(&wire, &.{rw.buffered()});

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [512]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    try t.expectError(error.ChannelClosed, serveSession(&tr, t.allocator, .{
        .exec = testExecHandler,
    }));
}

test "serveSession REJECT: a non-session channel type gets OPEN_FAILURE, not a channel" {
    const t = std.testing;

    var open_buf: [96]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&open_buf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
    try messages.writeString(&ow, "direct-tcpip"); // port forwarding: not offered
    try writeU32(&ow, 5);
    try writeU32(&ow, 4096);
    try writeU32(&ow, 4096);

    // …then a request on the channel the peer hoped it got.
    var req_buf: [64]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&req_buf);
    try writeChannelHeader(&rw, .SSH_MSG_CHANNEL_REQUEST, 0);
    try messages.writeString(&rw, "exec");
    try rw.writeByte(0);
    try messages.writeString(&rw, "id");

    var wire: [1024]u8 = undefined;
    const framed = try framePackets(&wire, &.{ ow.buffered(), rw.buffered() });

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    try t.expectError(error.ChannelClosed, serveSession(&tr, t.allocator, .{
        .exec = testExecHandler,
    }));

    // The reply we did send must be an OPEN_FAILURE for channel 5.
    var reply = messages.Cursor{ .b = sink_buf[0..] };
    _ = try reply.uint32(); // packet_length
    _ = try reply.byte(); // padding_length
    try t.expectEqual(
        @as(u8, @intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN_FAILURE)),
        try reply.byte(),
    );
    try t.expectEqual(@as(u32, 5), try reply.uint32());
    try t.expectEqual(
        @as(u32, @intFromEnum(messages.ChannelOpenFailureReason.unknown_channel_type)),
        try reply.uint32(),
    );
}
