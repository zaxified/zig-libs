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
/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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
    // audit `ssh` F4: `local_window * 2` overflows u32 (ReleaseSafe panic)
    // once a caller configures a window above 0x7FFF_FFFF via
    // `SessionOptions.window_size`/`ServeConfig.window_size`. The
    // non-overflowing equivalent of "consumed at least half" avoids the
    // multiply entirely.
    if (ch.local_window >= ch.local_window_initial / 2) return;
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

// ── client: channels ───────────────────────────────────────────────────────

pub const SessionOptions = struct {
    /// Our channel number (§5.1 "sender channel") for a standalone
    /// `Session.open`. A `Connection` numbers its channels itself.
    local_channel_id: u32 = 0,
    window_size: u32 = default_window_size,
    max_packet_size: u32 = default_max_packet_size,
    /// Refuse to buffer more than this much stdout/stderr.
    max_output: usize = default_max_output,
};

/// RFC 4254 §6.2 `pty-req`. `modes` is the encoded terminal-modes string
/// (§8: opcode/uint32 pairs ending in TTY_OP_END = 0); the default asks for
/// nothing beyond the server's defaults.
pub const PtyOptions = struct {
    term: []const u8 = "xterm",
    cols: u32 = 80,
    rows: u32 = 24,
    width_px: u32 = 0,
    height_px: u32 = 0,
    modes: []const u8 = &.{0},
};

/// RFC 4254 §6.10 `exit-signal`: the remote command died on a signal.
/// `name` is the signal without the "SIG" prefix ("TERM", "KILL", …).
pub const ExitSignal = struct {
    name_buf: [32]u8 = undefined,
    name_len: u8 = 0,
    core_dumped: bool = false,

    pub fn name(self: *const ExitSignal) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// A client-side channel: an RFC 4254 §6.1 `"session"`, or a TCP/IP
/// forwarding channel (§7.2 `direct-tcpip`, `forwarded-tcpip`) opened through
/// a `Connection` — the same byte-stream API either way.
///
/// Owns the collected `stdout`/`stderr`. Message handling funnels through
/// `pumpOnce`, so a streaming caller (NETCONF over `subsystem`, an
/// interactive shell, a forwarded TCP stream) can interleave `writeData` and
/// `pumpOnce` and drain `stdout` itself, while the one-shot `exec` helper
/// below just pumps to EOF. For a forwarding channel `stdout` is simply the
/// bytes that came from the far end.
pub const Session = struct {
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    /// Packet scratch: owned by a standalone session, borrowed from the
    /// `Connection` otherwise.
    scratch: []u8,
    ch: ChannelState,
    stdout: std.ArrayList(u8) = .empty,
    stderr: std.ArrayList(u8) = .empty,
    max_output: usize,
    /// The multiplexer this channel belongs to, or `null` for a standalone
    /// `Session.open` (one channel on the transport, as before).
    conn: ?*Connection = null,
    /// §6.10 `exit-signal`, once the peer has reported one.
    exit_signal: ?ExitSignal = null,
    open_failed: bool = false,

    /// RFC 4254 §5.1: send SSH_MSG_CHANNEL_OPEN `"session"` and wait for the
    /// confirmation. Requires a transport that has completed userauth. The
    /// channel is then the only one on `t`; to run several at once use a
    /// `Connection`.
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
        try self.sendOpen("session", &.{});
        while (!self.ch.open) {
            switch (try self.pumpOnce()) {
                .open_failed => return error.ChannelOpenFailed,
                else => {},
            }
        }
        return self;
    }

    /// Free what the session holds. For a channel of a `Connection` this
    /// also unregisters it and frees the `Session` itself (it was allocated
    /// by the `Connection`); close it first if the peer is still talking.
    pub fn deinit(self: *Session) void {
        self.stdout.deinit(self.gpa);
        self.stderr.deinit(self.gpa);
        if (self.conn) |c| {
            c.unregister(self);
            const gpa = self.gpa;
            self.* = undefined;
            gpa.destroy(self);
            return;
        }
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    fn sendOpen(self: *Session, kind: []const u8, extra: []const u8) ChannelError!void {
        const buf = try self.gpa.alloc(u8, 64 + kind.len + extra.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
        try messages.writeString(&w, kind);
        try writeU32(&w, self.ch.local_id);
        try writeU32(&w, self.ch.local_window);
        try writeU32(&w, self.ch.local_max_packet);
        try w.writeAll(extra);
        try self.t.sendPacket(w.buffered());
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

    /// §6.5 `"shell"`: the user's login shell on this channel. Usually after
    /// `requestPty`; then the channel is an interactive byte stream.
    pub fn shell(self: *Session) ChannelError!void {
        return self.requestRaw("shell", true, &.{});
    }

    /// §6.2 `"pty-req"`: a pseudo-terminal for this channel.
    pub fn requestPty(self: *Session, opts: PtyOptions) ChannelError!void {
        const buf = try self.gpa.alloc(u8, 32 + opts.term.len + opts.modes.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try messages.writeString(&w, opts.term);
        try writeU32(&w, opts.cols);
        try writeU32(&w, opts.rows);
        try writeU32(&w, opts.width_px);
        try writeU32(&w, opts.height_px);
        try messages.writeString(&w, opts.modes);
        return self.requestRaw("pty-req", true, w.buffered());
    }

    /// §6.4 `"env"`: one environment variable for the command or shell to
    /// come. Servers refuse names they were not told to accept (OpenSSH's
    /// `AcceptEnv`), which arrives as `error.ChannelRequestFailed`.
    pub fn setEnv(self: *Session, name: []const u8, value: []const u8) ChannelError!void {
        const buf = try self.gpa.alloc(u8, 16 + name.len + value.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try messages.writeString(&w, name);
        try messages.writeString(&w, value);
        return self.requestRaw("env", true, w.buffered());
    }

    /// §6.7 `"window-change"`: the terminal was resized (no reply).
    pub fn windowChange(self: *Session, cols: u32, rows: u32, width_px: u32, height_px: u32) ChannelError!void {
        var buf: [16]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeU32(&w, cols);
        try writeU32(&w, rows);
        try writeU32(&w, width_px);
        try writeU32(&w, height_px);
        return self.requestRaw("window-change", false, w.buffered());
    }

    /// §6.9 `"signal"`: deliver signal `name` (without "SIG": "TERM",
    /// "INT", "KILL", …) to the remote command (no reply).
    pub fn signal(self: *Session, name: []const u8) ChannelError!void {
        var buf: [40]u8 = undefined;
        if (name.len > 32) return error.ProtocolError;
        var w: std.Io.Writer = .fixed(&buf);
        try messages.writeString(&w, name);
        return self.requestRaw("signal", false, w.buffered());
    }

    /// Generic §5.4 channel request carrying a single `string` argument,
    /// with `want_reply = TRUE`.
    pub fn request(self: *Session, request_type: []const u8, argument: []const u8) ChannelError!void {
        const buf = try self.gpa.alloc(u8, 8 + argument.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try messages.writeString(&w, argument);
        return self.requestRaw(request_type, true, w.buffered());
    }

    /// §5.4 channel request with a caller-encoded type-specific payload.
    /// With `want_reply` it waits for SSH_MSG_CHANNEL_SUCCESS (or returns
    /// `error.ChannelRequestFailed`); without, it returns once sent.
    pub fn requestRaw(self: *Session, request_type: []const u8, want_reply: bool, payload: []const u8) ChannelError!void {
        if (!self.ch.open or self.ch.sent_close or self.ch.got_close) return error.ChannelClosed;

        const buf = try self.gpa.alloc(u8, 64 + request_type.len + payload.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try writeChannelHeader(&w, .SSH_MSG_CHANNEL_REQUEST, self.ch.remote_id);
        try messages.writeString(&w, request_type);
        try w.writeByte(@intFromBool(want_reply));
        try w.writeAll(payload);
        try self.t.sendPacket(w.buffered());
        if (!want_reply) return;

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
    // secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
    pub fn sendEof(self: *Session) ChannelError!void {
        return sendEofMsg(self.t, &self.ch);
    }

    /// §5.3 SSH_MSG_CHANNEL_CLOSE. After sending, only the peer's own CLOSE
    /// is still expected.
    // secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
    pub fn close(self: *Session) ChannelError!void {
        return sendCloseMsg(self.t, &self.ch);
    }

    /// Pump until the peer closes the channel, collecting stdout/stderr and
    /// the §6.10 exit status. Answers the peer's CLOSE with our own — unless
    /// the peer has hung up by then (Go's x/crypto/ssh server closes the
    /// connection right after its CLOSE): everything was delivered.
    // secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
    pub fn drain(self: *Session) ChannelError!void {
        while (!self.ch.got_close) {
            switch (try self.pumpOnce()) {
                .closed => break,
                else => continue,
            }
        }
        sendCloseMsg(self.t, &self.ch) catch |e| if (!hungUp(e)) return e;
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
        open_confirmed,
        open_failed,
        /// A peer request we answered but that carried no payload of
        /// interest (e.g. `exit-status`), a message for another channel of
        /// the same `Connection`, or an ignorable message.
        other,
    };

    /// Read and process exactly one incoming message. The streaming seam:
    /// data lands in `stdout`/`stderr`, windows are accounted for and topped
    /// up, `exit-status` / `exit-signal` are recorded. On a `Connection`, the
    /// message may belong to another of its channels: it is applied there and
    /// this returns `.other`.
    // secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
    pub fn pumpOnce(self: *Session) ChannelError!Event {
        if (self.conn) |c| return c.pumpFor(self);
        const pkt = try self.t.recvPacket(self.scratch);
        const mt: messages.MessageType = @enumFromInt(msgType(pkt));
        switch (mt) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => return .other,
            .SSH_MSG_DISCONNECT => return error.ChannelClosed,
            .SSH_MSG_GLOBAL_REQUEST => {
                try refuseGlobalRequest(self.t, pkt.payload);
                return .other;
            },
            .SSH_MSG_CHANNEL_OPEN => {
                try refuseChannelOpen(self.t, pkt.payload);
                return .other;
            },
            else => return self.handleChannelPacket(pkt.payload),
        }
    }

    /// Apply one channel message (types 91-100) addressed to this channel.
    fn handleChannelPacket(self: *Session, payload: []const u8) ChannelError!Event {
        const mt: messages.MessageType = @enumFromInt(if (payload.len == 0) 0 else payload[0]);
        var c = Cursor{ .b = payload[1..] };
        switch (mt) {
            .SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                const recipient = try c.uint32();
                if (recipient != self.ch.local_id or self.ch.open) return error.ProtocolError;
                self.ch.remote_id = try c.uint32();
                self.ch.remote_window = try c.uint32();
                self.ch.remote_max_packet = try c.uint32();
                if (self.ch.remote_max_packet == 0) return error.ChannelOpenFailed;
                self.ch.open = true;
                return .open_confirmed;
            },
            .SSH_MSG_CHANNEL_OPEN_FAILURE => {
                const recipient = try c.uint32();
                if (recipient != self.ch.local_id or self.ch.open) return error.ProtocolError;
                self.open_failed = true;
                return .open_failed;
            },
            .SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                try self.expectOurChannel(&c);
                const add = try c.uint32();
                // §5.2 windows are 32-bit; saturate rather than wrap.
                self.ch.remote_window +|= add;
                return .window_adjust;
            },
            .SSH_MSG_CHANNEL_DATA => {
                try self.expectOurChannel(&c);
                const data = try c.string();
                try self.ch.acceptData(data.len);
                if (self.stdout.items.len + data.len > self.max_output) return error.OutputTooLarge;
                try self.stdout.appendSlice(self.gpa, data);
                try maybeAdjustWindow(self.t, &self.ch);
                return .data;
            },
            .SSH_MSG_CHANNEL_EXTENDED_DATA => {
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
                try self.expectOurChannel(&c);
                self.ch.got_eof = true;
                return .eof;
            },
            .SSH_MSG_CHANNEL_CLOSE => {
                try self.expectOurChannel(&c);
                self.ch.got_close = true;
                return .closed;
            },
            .SSH_MSG_CHANNEL_REQUEST => {
                try self.expectOurChannel(&c);
                const req = try c.string();
                const want_reply = try c.boolean();
                if (std.mem.eql(u8, req, "exit-status")) {
                    self.ch.exit_status = try c.uint32();
                } else if (std.mem.eql(u8, req, "exit-signal")) {
                    // §6.10: string signal name, boolean core dumped,
                    // string error message, string language tag.
                    const sig = try c.string();
                    var es: ExitSignal = .{ .core_dumped = try c.boolean() };
                    const n = @min(sig.len, es.name_buf.len);
                    @memcpy(es.name_buf[0..n], sig[0..n]);
                    es.name_len = @intCast(n);
                    self.exit_signal = es;
                } else if (want_reply) {
                    var buf: [8]u8 = undefined;
                    var w: std.Io.Writer = .fixed(&buf);
                    try writeChannelHeader(&w, .SSH_MSG_CHANNEL_FAILURE, self.ch.remote_id);
                    try self.t.sendPacket(w.buffered());
                }
                return .other;
            },
            .SSH_MSG_CHANNEL_SUCCESS => {
                try self.expectOurChannel(&c);
                return .request_success;
            },
            .SSH_MSG_CHANNEL_FAILURE => {
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

/// §4: answer a global request we do not implement (`want_reply` only).
fn refuseGlobalRequest(t: *transport.Transport, payload: []const u8) ChannelError!void {
    var c = Cursor{ .b = payload[1..] };
    _ = try c.string();
    if (try c.boolean())
        try t.sendPacket(&[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_REQUEST_FAILURE)});
}

/// §5.1: refuse a channel the peer opens towards us (an X11, agent or
/// forwarded-tcpip channel we never asked for).
fn refuseChannelOpen(t: *transport.Transport, payload: []const u8) ChannelError!void {
    var c = Cursor{ .b = payload[1..] };
    _ = try c.string();
    const sender = try c.uint32();
    try sendOpenFailure(t, sender, .administratively_prohibited, "not accepted by this client");
}

/// `direct-tcpip` (RFC 4254 §7.2): ask the server to connect to
/// `host:port` and relay that TCP stream over a channel. `originator_*`
/// tell it who asked (informational).
pub const DirectTcpipOptions = struct {
    host: []const u8,
    port: u32,
    originator_host: []const u8 = "127.0.0.1",
    originator_port: u32 = 0,
    session: SessionOptions = .{},
};

/// `forwarded-tcpip` channels a `Connection` holds before `acceptForwarded`
/// takes them; further opens are refused with `resource_shortage`.
pub const max_unaccepted_forwards = 16;

/// The remote address a `forwarded-tcpip` channel (RFC 4254 §7.2) arrived
/// for, and who connected to it.
pub const ForwardedOrigin = struct {
    connected_port: u32,
    originator_port: u32,
};

/// A client-side channel multiplexer (RFC 4254 §5): several channels on one
/// authenticated transport — sessions run side by side, TCP/IP forwarding
/// in both directions. Every packet is read through the `Connection` and
/// applied to the channel it names, whichever channel's call is pumping.
///
///     var conn = try ssh.connection.Connection.init(&t, gpa);
///     defer conn.deinit();
///     const a = try conn.openSession(.{});
///     defer a.deinit();
///     const b = try conn.openSession(.{});
///     defer b.deinit();
///     try a.exec("make"); try b.exec("tail -f log");
///
/// Channels it opens are heap-allocated `Session`s; `Session.deinit` frees
/// one. Single-owner like the transport under it.
pub const Connection = struct {
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    scratch: []u8,
    channels: std.ArrayList(*Session) = .empty,
    next_id: u32 = 0,
    /// `forwarded-tcpip` channels the server opened for a remote forward we
    /// requested, waiting for `acceptForwarded`.
    forwarded: std.ArrayList(*Session) = .empty,
    forwarded_origin: std.ArrayList(ForwardedOrigin) = .empty,
    /// Remote forwards granted and not cancelled (incoming
    /// `forwarded-tcpip` is accepted only while this is non-zero).
    remote_forwards: u32 = 0,
    /// Replies to our global requests (§4), in order.
    global_reply: ?GlobalReply = null,
    /// Local ids of channels freed by `Session.deinit` before the peer's
    /// CLOSE arrived (or before an open was answered): their late messages
    /// are dropped instead of failing whichever channel is pumping.
    zombies: std.ArrayList(u32) = .empty,
    window_size: u32 = default_window_size,
    max_packet_size: u32 = default_max_packet_size,

    const GlobalReply = struct { ok: bool, port: ?u32 };

    pub fn init(t: *transport.Transport, gpa: std.mem.Allocator) std.mem.Allocator.Error!Connection {
        return .{ .t = t, .gpa = gpa, .scratch = try gpa.alloc(u8, scratch_len) };
    }

    /// Frees the multiplexer. Channels still registered are freed too
    /// (without telling the peer); deinit them first to close them properly.
    pub fn deinit(self: *Connection) void {
        while (self.channels.items.len > 0) self.channels.items[self.channels.items.len - 1].deinit();
        self.channels.deinit(self.gpa);
        self.zombies.deinit(self.gpa);
        self.forwarded.deinit(self.gpa);
        self.forwarded_origin.deinit(self.gpa);
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    fn newChannel(self: *Connection, opts: SessionOptions) ChannelError!*Session {
        const s = try self.gpa.create(Session);
        errdefer self.gpa.destroy(s);
        s.* = .{
            .t = self.t,
            .gpa = self.gpa,
            .scratch = self.scratch,
            .max_output = opts.max_output,
            .conn = self,
            .ch = .{
                .local_id = self.next_id,
                .local_window = opts.window_size,
                .local_window_initial = opts.window_size,
                .local_max_packet = opts.max_packet_size,
            },
        };
        self.next_id +%= 1;
        try self.channels.append(self.gpa, s);
        return s;
    }

    fn unregister(self: *Connection, s: *Session) void {
        // Not closed both ways yet: send our CLOSE (best effort — deinit
        // cannot fail) and remember the id until the peer's CLOSE, so its
        // late traffic is dropped (review 2026-10-06 M2).
        if (!s.ch.got_close) {
            if (s.ch.open) sendCloseMsg(self.t, &s.ch) catch {};
            self.zombies.append(self.gpa, s.ch.local_id) catch {};
        }
        for (self.channels.items, 0..) |x, i| if (x == s) {
            _ = self.channels.swapRemove(i);
            break;
        };
        for (self.forwarded.items, 0..) |x, i| if (x == s) {
            _ = self.forwarded.orderedRemove(i);
            _ = self.forwarded_origin.orderedRemove(i);
            break;
        };
    }

    fn openChannel(self: *Connection, kind: []const u8, extra: []const u8, opts: SessionOptions) ChannelError!*Session {
        const s = try self.newChannel(opts);
        errdefer s.deinit();
        try s.sendOpen(kind, extra);
        while (!s.ch.open) {
            if (s.open_failed) return error.ChannelOpenFailed;
            _ = try self.pumpFor(s);
        }
        return s;
    }

    /// RFC 4254 §6.1: open another `"session"` channel.
    pub fn openSession(self: *Connection, opts: SessionOptions) ChannelError!*Session {
        return self.openChannel("session", &.{}, opts);
    }

    /// RFC 4254 §7.2 `direct-tcpip` ("local forwarding", `ssh -L`): the
    /// server connects to `opts.host:opts.port`; the returned channel carries
    /// that TCP stream (`writeData` / `stdout`, EOF both ways).
    pub fn openDirectTcpip(self: *Connection, opts: DirectTcpipOptions) ChannelError!*Session {
        const buf = try self.gpa.alloc(u8, 32 + opts.host.len + opts.originator_host.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try messages.writeString(&w, opts.host);
        try writeU32(&w, opts.port);
        try messages.writeString(&w, opts.originator_host);
        try writeU32(&w, opts.originator_port);
        return self.openChannel("direct-tcpip", w.buffered(), opts.session);
    }

    /// RFC 4254 §7.1 `tcpip-forward` ("remote forwarding", `ssh -R`): ask
    /// the server to listen on `bind_address:port` and open a
    /// `forwarded-tcpip` channel to us for every connection
    /// (`acceptForwarded`). `port` 0 lets the server pick; the port actually
    /// bound is returned.
    pub fn requestRemoteForward(self: *Connection, bind_address: []const u8, port: u32) ChannelError!u32 {
        const reply = try self.globalRequest("tcpip-forward", bind_address, port);
        if (!reply.ok) return error.ChannelRequestFailed;
        self.remote_forwards += 1;
        return reply.port orelse port;
    }

    /// RFC 4254 §7.1 `cancel-tcpip-forward`.
    pub fn cancelRemoteForward(self: *Connection, bind_address: []const u8, port: u32) ChannelError!void {
        const reply = try self.globalRequest("cancel-tcpip-forward", bind_address, port);
        if (!reply.ok) return error.ChannelRequestFailed;
        self.remote_forwards -|= 1;
    }

    fn globalRequest(self: *Connection, name: []const u8, address: []const u8, port: u32) ChannelError!GlobalReply {
        const buf = try self.gpa.alloc(u8, 32 + name.len + address.len);
        defer self.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_GLOBAL_REQUEST));
        try messages.writeString(&w, name);
        try w.writeByte(1); // want_reply
        try messages.writeString(&w, address);
        try writeU32(&w, port);
        self.global_reply = null;
        try self.t.sendPacket(w.buffered());
        while (self.global_reply == null) _ = try self.pumpFor(null);
        const r = self.global_reply.?;
        self.global_reply = null;
        return r;
    }

    /// The next `forwarded-tcpip` channel the server opened for a remote
    /// forward (pumping until one arrives), with where it came from.
    // secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
    pub fn acceptForwarded(self: *Connection) ChannelError!struct { session: *Session, origin: ForwardedOrigin } {
        while (self.forwarded.items.len == 0) _ = try self.pumpFor(null);
        const s = self.forwarded.orderedRemove(0);
        const o = self.forwarded_origin.orderedRemove(0);
        return .{ .session = s, .origin = o };
    }

    /// Read and apply one message; the event is reported only if it
    /// concerns `target` (`.other` otherwise).
    fn pumpFor(self: *Connection, target: ?*Session) ChannelError!Session.Event {
        const pkt = try self.t.recvPacket(self.scratch);
        const mt: messages.MessageType = @enumFromInt(msgType(pkt));
        switch (mt) {
            .SSH_MSG_DISCONNECT => return error.ChannelClosed,
            .SSH_MSG_GLOBAL_REQUEST => {
                try refuseGlobalRequest(self.t, pkt.payload);
                return .other;
            },
            .SSH_MSG_REQUEST_SUCCESS => {
                var c = Cursor{ .b = pkt.payload[1..] };
                // §7.1: a `tcpip-forward` for port 0 answers the port bound.
                self.global_reply = .{ .ok = true, .port = c.uint32() catch null };
                return .other;
            },
            .SSH_MSG_REQUEST_FAILURE => {
                self.global_reply = .{ .ok = false, .port = null };
                return .other;
            },
            .SSH_MSG_CHANNEL_OPEN => {
                try self.peerOpen(pkt.payload);
                return .other;
            },
            .SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
            .SSH_MSG_CHANNEL_OPEN_FAILURE,
            .SSH_MSG_CHANNEL_WINDOW_ADJUST,
            .SSH_MSG_CHANNEL_DATA,
            .SSH_MSG_CHANNEL_EXTENDED_DATA,
            .SSH_MSG_CHANNEL_EOF,
            .SSH_MSG_CHANNEL_CLOSE,
            .SSH_MSG_CHANNEL_REQUEST,
            .SSH_MSG_CHANNEL_SUCCESS,
            .SSH_MSG_CHANNEL_FAILURE,
            => {
                var c = Cursor{ .b = pkt.payload[1..] };
                const recipient = try c.uint32();
                const s = self.find(recipient) orelse {
                    try self.zombieMessage(mt, recipient, &c);
                    return .other;
                };
                const ev = try s.handleChannelPacket(pkt.payload);
                return if (target == s) ev else .other;
            },
            else => return error.ProtocolError,
        }
    }

    /// A message for a channel no `Session` owns any more: dropped if the id
    /// is a zombie (an abandoned open that is confirmed now gets our CLOSE;
    /// the peer's CLOSE retires the id), a protocol violation otherwise.
    fn zombieMessage(self: *Connection, mt: messages.MessageType, recipient: u32, c: *Cursor) ChannelError!void {
        const i = std.mem.indexOfScalar(u32, self.zombies.items, recipient) orelse return error.ChannelClosed;
        switch (mt) {
            .SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                var ch: ChannelState = .{ .local_id = recipient, .local_window = 0, .local_window_initial = 0, .local_max_packet = 0 };
                ch.remote_id = try c.uint32();
                try sendCloseMsg(self.t, &ch);
            },
            .SSH_MSG_CHANNEL_OPEN_FAILURE, .SSH_MSG_CHANNEL_CLOSE => _ = self.zombies.swapRemove(i),
            else => {},
        }
    }

    fn find(self: *Connection, local_id: u32) ?*Session {
        for (self.channels.items) |s| if (s.ch.local_id == local_id) return s;
        return null;
    }

    /// The server opens a channel towards us: `forwarded-tcpip` for a remote
    /// forward we hold is accepted and queued; anything else is refused.
    fn peerOpen(self: *Connection, payload: []const u8) ChannelError!void {
        var c = Cursor{ .b = payload[1..] };
        const kind = try c.string();
        const sender = try c.uint32();
        const window = try c.uint32();
        const max_packet = try c.uint32();
        if (!std.mem.eql(u8, kind, "forwarded-tcpip") or self.remote_forwards == 0) {
            return sendOpenFailure(self.t, sender, .administratively_prohibited, "not accepted by this client");
        }
        if (max_packet == 0) return sendOpenFailure(self.t, sender, .connect_failed, "zero maximum packet size");
        _ = try c.string(); // address that was connected
        const connected_port = try c.uint32();
        _ = try c.string(); // originator address
        const originator_port = try c.uint32();

        // A server may open forwarded channels faster than the caller accepts
        // them; each would buffer up to `max_output` (review 2026-10-06 M4).
        if (self.forwarded.items.len >= max_unaccepted_forwards) {
            return sendOpenFailure(self.t, sender, .resource_shortage, "too many unaccepted forwarded channels");
        }
        try self.forwarded.ensureUnusedCapacity(self.gpa, 1);
        try self.forwarded_origin.ensureUnusedCapacity(self.gpa, 1);
        const s = try self.newChannel(.{ .window_size = self.window_size, .max_packet_size = self.max_packet_size });
        errdefer s.deinit();
        s.ch.remote_id = sender;
        s.ch.remote_window = window;
        s.ch.remote_max_packet = max_packet;
        s.ch.open = true;
        self.forwarded.appendAssumeCapacity(s);
        self.forwarded_origin.appendAssumeCapacity(.{ .connected_port = connected_port, .originator_port = originator_port });

        var buf: [32]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeChannelHeader(&w, .SSH_MSG_CHANNEL_OPEN_CONFIRMATION, sender);
        try writeU32(&w, s.ch.local_id);
        try writeU32(&w, s.ch.local_window);
        try writeU32(&w, s.ch.local_max_packet);
        try self.t.sendPacket(w.buffered());
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
// secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
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

// ── server: session channels ───────────────────────────────────────────────

pub const CommandError = std.mem.Allocator.Error || error{CommandFailed};

/// §6.2 `pty-req` as the client sent it.
pub const PtyInfo = struct {
    term_buf: [64]u8 = undefined,
    term_len: u8 = 0,
    cols: u32 = 0,
    rows: u32 = 0,
    width_px: u32 = 0,
    height_px: u32 = 0,

    pub fn term(self: *const PtyInfo) []const u8 {
        return self.term_buf[0..self.term_len];
    }
};

/// One §6.4 `env` variable a client set and `ServeConfig.accept_env` let
/// through.
pub const EnvVar = struct { name: []const u8, value: []const u8 };

/// Everything a handler may want to know about the request it serves —
/// what `CommandHandler.runInfoFn` receives. Borrowed for the call.
pub const RequestInfo = struct {
    user: []const u8,
    kind: enum { exec, subsystem, shell },
    /// The command line (`exec`), the subsystem name, or empty (`shell`).
    command: []const u8,
    /// The pseudo-terminal the client asked for on this channel, if any.
    pty: ?PtyInfo,
    env: []const EnvVar,
    /// Our number for the channel (distinct per concurrent channel).
    channel: u32,
};

/// Server policy hook: run `command` for `user`, appending output to
/// `stdout`/`stderr`, and return the exit status the client will see in the
/// §6.10 `exit-status` request. `stdin` is whatever the client sent before
/// EOF. What "run" means (a real process, a routing table, a NETCONF
/// session) is entirely the caller's business — this module never spawns
/// anything.
/// ⚠ `user`, `command` and `stdin` are borrowed for the duration of the call
/// (`command` and `stdin` point into `serveSession`'s own buffers); copy
/// anything kept. `stdout`/`stderr` are appended to with `gpa` and owned by
/// `serveSession`.
///
/// `ctx` is the caller's own state, handed back untouched — same idiom as
/// `transport.HostKeyVerifier`. Without it a server handling two connections
/// (or two virtual hosts) has nowhere but a global to keep what the handler
/// dispatches on. Leave it at `transport.no_context` for a stateless handler.
///
/// Set `runFn` (user and command only) or `runInfoFn` (the whole
/// `RequestInfo`: request kind, pty, accepted environment, channel); with
/// both set, `runInfoFn` wins.
///
/// A reason for refusing is already expressible here and needs no separate
/// channel: that is exactly what the returned exit status and `stderr` are,
/// and RFC 4254 §6.10 delivers both to the client.
pub const CommandHandler = struct {
    ctx: *anyopaque = transport.no_context,
    runFn: ?*const fn (
        ctx: *anyopaque,
        gpa: std.mem.Allocator,
        user: []const u8,
        command: []const u8,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) CommandError!u32 = null,
    runInfoFn: ?*const fn (
        ctx: *anyopaque,
        gpa: std.mem.Allocator,
        info: *const RequestInfo,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) CommandError!u32 = null,

    pub fn run(
        self: CommandHandler,
        gpa: std.mem.Allocator,
        user: []const u8,
        command: []const u8,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) CommandError!u32 {
        const info: RequestInfo = .{ .user = user, .kind = .exec, .command = command, .pty = null, .env = &.{}, .channel = 0 };
        return self.runInfo(gpa, &info, stdin, stdout, stderr);
    }

    pub fn runInfo(
        self: CommandHandler,
        gpa: std.mem.Allocator,
        info: *const RequestInfo,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) CommandError!u32 {
        if (self.runInfoFn) |f| return f(self.ctx, gpa, info, stdin, stdout, stderr);
        if (self.runFn) |f| return f(self.ctx, gpa, info.user, info.command, stdin, stdout, stderr);
        return error.CommandFailed;
    }
};

/// Called whenever `serveSession` answers a `SSH_MSG_CHANNEL_OPEN` with
/// `SSH_MSG_CHANNEL_OPEN_FAILURE` — a concurrent second channel, a
/// non-`"session"` type, or a zero max-packet-size peer value (RFC 4254
/// §5.1). Optional (`ServeConfig.on_channel_open_refused`, default `null`):
/// today's behavior is already correct on the wire (the client gets the
/// failure message either way), but with no hook the server side has no way
/// to know it happened — `SPEC.md` documents one session channel per
/// connection as this module's deliberate scope, but not that refusing a
/// second one is otherwise silent server-side (A1/examples/ssh.md S3a).
/// `ctx` is the caller's own state, same idiom as `CommandHandler` above.
///
/// ⚠ `kind` and `description` are borrowed for the duration of the call —
/// same warning as `CommandHandler`'s `command`/`stdin` — they point into
/// `serveSession`'s own scratch buffer; copy anything kept past the call.
pub const ChannelOpenRejectedHandler = struct {
    ctx: *anyopaque = transport.no_context,
    onFn: *const fn (
        ctx: *anyopaque,
        kind: []const u8,
        reason: messages.ChannelOpenFailureReason,
        description: []const u8,
    ) void,

    pub fn call(
        self: ChannelOpenRejectedHandler,
        kind: []const u8,
        reason: messages.ChannelOpenFailureReason,
        description: []const u8,
    ) void {
        self.onFn(self.ctx, kind, reason, description);
    }
};

pub const ServeConfig = struct {
    /// The authenticated identity (`userauth.AuthResult.user()`), passed
    /// through to the handlers.
    user: []const u8 = "",
    /// Handler for §6.5 `"exec"`. `null` → every exec request is answered
    /// SSH_MSG_CHANNEL_FAILURE.
    exec: ?CommandHandler = null,
    /// Handler for §6.5 `"subsystem"` (`command` is the subsystem name).
    subsystem: ?CommandHandler = null,
    /// Handler for §6.5 `"shell"` (`command` is empty). `null` → refused.
    /// The handler is one-shot like the others, so a "shell" here is batch:
    /// with the default `stdin_mode` it sees everything the client typed
    /// once the client sends EOF.
    shell: ?CommandHandler = null,
    /// Accept §6.2 `"pty-req"` (recorded and handed to the handler in
    /// `RequestInfo.pty`; nothing here allocates a terminal). Without it a
    /// `ssh -t` client is told SSH_MSG_CHANNEL_FAILURE and goes on without one.
    allow_pty: bool = true,
    /// §6.4 `"env"` names to accept (exact, or a prefix ending in `*`, like
    /// OpenSSH's `AcceptEnv`); everything else is refused, the OpenSSH
    /// default. Accepted variables reach the handler in `RequestInfo.env`.
    accept_env: []const []const u8 = &.{},
    /// Concurrent session channels `serveConnection` serves (§5.1); one more
    /// is refused with `resource_shortage`. `serveSession` serves one.
    max_sessions: u32 = 8,
    /// Restricts which subsystem NAMES `subsystem` is offered for
    /// (A1/examples/ssh.md S3b). Today's request dispatch below only looks
    /// at the request TYPE ("exec" vs "subsystem") — once `subsystem` is
    /// set at all, ANY name gets SSH_MSG_CHANNEL_SUCCESS and then runs the
    /// same handler, because there was nowhere to check the name before
    /// replying. A client waiting for its own subsystem's init packet
    /// (`sftp`'s SSH_FXP_INIT, say) against a server that only implements
    /// some other one hangs instead of getting SSH_MSG_CHANNEL_FAILURE and
    /// trying something else.
    ///
    /// Empty (the default) preserves today's behavior byte-for-byte: any
    /// name is accepted, and it is `subsystem`'s own job to recognize or
    /// ignore names it does not implement. A non-empty list makes a name
    /// NOT on it fail on the wire — SSH_MSG_CHANNEL_FAILURE, handler never
    /// invoked — the same way an unset `subsystem` already does for every
    /// name. This does not give different names different handlers (that
    /// needs `subsystem`'s type to become a list of `{name, handler}`
    /// pairs, a breaking change to the existing field — see
    /// `A1/examples/ssh.md`'s Dispozice for that variant and its cost); it
    /// only lets a single-subsystem server reject names it was never going
    /// to serve, before pretending otherwise.
    subsystem_names: []const []const u8 = &.{},
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
    /// See `ChannelOpenRejectedHandler` above. `null` (default) keeps
    /// today's behavior exactly: `serveSession` refuses on the wire either
    /// way, this only adds an optional server-side observability seam.
    on_channel_open_refused: ?ChannelOpenRejectedHandler = null,
};

/// Server: accept and serve exactly one `"session"` channel, then return.
///
/// `serveConnection` with `max_sessions = 1` that returns once that channel
/// is closed both ways: §5.1 open (rejecting any channel type other than
/// `"session"`, and any second concurrent channel, with
/// SSH_MSG_CHANNEL_OPEN_FAILURE), stdin buffered with full window
/// accounting, `config.exec` / `config.subsystem` / `config.shell` run on the
/// matching request, the result streamed back as CHANNEL_DATA /
/// CHANNEL_EXTENDED_DATA (respecting the client's window and maximum packet
/// size), then `exit-status`, EOF and CLOSE.
///
/// Returns when the channel is closed both ways, or on SSH_MSG_DISCONNECT.
// secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
pub fn serveSession(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    config: ServeConfig,
) ChannelError!void {
    var cfg = config;
    cfg.max_sessions = 1;
    var srv = try Server.init(t, gpa, cfg, .first_channel);
    defer srv.deinit();
    return srv.run();
}

/// Server: serve session channels (RFC 4254 §6) until the client
/// disconnects — up to `config.max_sessions` at once, each running its
/// handler on its own request. While one channel's output waits for window
/// space, the others' messages are still read and applied; a handler that
/// becomes runnable meanwhile runs next.
///
/// Returns on SSH_MSG_DISCONNECT, or when the client hangs up with no
/// channel left open.
// secret-api-ok: channel layer; it reaches the Transport only through sendPacket/recvPacket, which run under record_burn (writePacket/readPacket), and holds no key material itself.
pub fn serveConnection(
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    config: ServeConfig,
) ChannelError!void {
    var srv = try Server.init(t, gpa, config, .until_disconnect);
    defer srv.deinit();
    return srv.run();
}

/// One server-side channel's state beyond the §5 flow control.
const ServerChannel = struct {
    ch: ChannelState,
    stdin: std.ArrayList(u8) = .empty,
    /// A request was accepted on this channel (only one per channel, §6.5).
    ran: bool = false,
    /// Accepted request waiting to run (see `ServeConfig.stdin_mode`), or
    /// ready to run now.
    pending: ?Pending = null,
    pty: ?PtyInfo = null,
    env: std.ArrayList(EnvVar) = .empty,

    const Pending = struct {
        handler: CommandHandler,
        kind: @FieldType(RequestInfo, "kind"),
        command: []u8,
        ready: bool,
    };

    fn deinit(sc: *ServerChannel, gpa: std.mem.Allocator) void {
        sc.stdin.deinit(gpa);
        if (sc.pending) |p| gpa.free(p.command);
        for (sc.env.items) |e| {
            gpa.free(e.name);
            gpa.free(e.value);
        }
        sc.env.deinit(gpa);
    }

    fn done(sc: *const ServerChannel) bool {
        return sc.ch.got_close and sc.ch.sent_close;
    }
};

const Server = struct {
    t: *transport.Transport,
    gpa: std.mem.Allocator,
    config: ServeConfig,
    mode: enum { first_channel, until_disconnect },
    scratch: []u8,
    channels: std.ArrayList(*ServerChannel) = .empty,
    next_id: u32 = 0,
    /// `serveSession`: the one channel has been opened (and maybe finished).
    served_one: bool = false,
    disconnected: bool = false,

    fn init(t: *transport.Transport, gpa: std.mem.Allocator, config: ServeConfig, mode: @FieldType(Server, "mode")) ChannelError!Server {
        return .{ .t = t, .gpa = gpa, .config = config, .mode = mode, .scratch = try gpa.alloc(u8, scratch_len) };
    }

    fn deinit(srv: *Server) void {
        for (srv.channels.items) |sc| {
            sc.deinit(srv.gpa);
            srv.gpa.destroy(sc);
        }
        srv.channels.deinit(srv.gpa);
        srv.gpa.free(srv.scratch);
    }

    fn run(srv: *Server) ChannelError!void {
        while (true) {
            if (srv.nextReady()) |sc| {
                try srv.runPending(sc);
                continue;
            }
            srv.sweep();
            if (srv.disconnected) return;
            if (srv.mode == .first_channel and srv.served_one and srv.channels.items.len == 0) return;

            const pkt = srv.t.recvPacket(srv.scratch) catch |e| {
                // The client may hang up instead of answering our CLOSE —
                // OpenSSH does when a re-exchange it started is still
                // pending at that point (it queues its CLOSE behind the
                // exchange and exits).
                if (hungUp(e) and srv.allClosedByUs()) return;
                return e;
            };
            try srv.dispatch(pkt.payload);
        }
    }

    /// Every open channel has had our CLOSE (nothing left to deliver).
    fn allClosedByUs(srv: *const Server) bool {
        if (srv.mode == .first_channel and !srv.served_one) return false;
        for (srv.channels.items) |sc| if (!sc.ch.sent_close) return false;
        return true;
    }

    fn nextReady(srv: *Server) ?*ServerChannel {
        for (srv.channels.items) |sc| {
            if (sc.pending) |p| if (p.ready and !sc.ch.sent_close) return sc;
        }
        return null;
    }

    /// Free channels closed both ways.
    fn sweep(srv: *Server) void {
        var i: usize = 0;
        while (i < srv.channels.items.len) {
            const sc = srv.channels.items[i];
            if (sc.done()) {
                sc.deinit(srv.gpa);
                srv.gpa.destroy(sc);
                _ = srv.channels.orderedRemove(i);
            } else i += 1;
        }
    }

    fn find(srv: *Server, c: *Cursor) ChannelError!*ServerChannel {
        const recipient = try c.uint32();
        for (srv.channels.items) |sc| {
            if (sc.ch.local_id == recipient) {
                if (!sc.ch.open or sc.ch.got_close) return error.ChannelClosed;
                return sc;
            }
        }
        return error.ChannelClosed;
    }

    /// RFC 4254 §5.3: once our CLOSE is out, the peer may still send for
    /// the channel until it has seen it (a `window-change`, trailing data).
    /// Those are dropped — we may send nothing more on it — and only its
    /// CLOSE still counts (review 2026-10-06 M1: they used to end the whole
    /// connection with `error.ChannelClosed`).
    fn closingByUs(sc: *const ServerChannel) bool {
        return sc.ch.sent_close and !sc.ch.got_close;
    }

    fn activeSessions(srv: *const Server) usize {
        var n: usize = 0;
        for (srv.channels.items) |sc| {
            if (!sc.done()) n += 1;
        }
        return n;
    }

    fn refuseOpen(srv: *Server, kind: []const u8, sender: u32, reason: messages.ChannelOpenFailureReason, desc: []const u8) ChannelError!void {
        try sendOpenFailure(srv.t, sender, reason, desc);
        if (srv.config.on_channel_open_refused) |hook| hook.call(kind, reason, desc);
    }

    /// Apply one packet from the client. Never runs a handler (that is
    /// `run`'s job), so it is safe to call while another channel's output
    /// is waiting for window space.
    fn dispatch(srv: *Server, payload: []const u8) ChannelError!void {
        const mt: messages.MessageType = @enumFromInt(if (payload.len == 0) 0 else payload[0]);
        var c = Cursor{ .b = payload[1..] };
        switch (mt) {
            .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => {},
            .SSH_MSG_DISCONNECT => srv.disconnected = true,
            .SSH_MSG_GLOBAL_REQUEST => try refuseGlobalRequest(srv.t, payload),
            .SSH_MSG_CHANNEL_OPEN => {
                const kind = try c.string();
                const sender = try c.uint32();
                const window = try c.uint32();
                const max_packet = try c.uint32();
                if (srv.activeSessions() >= srv.config.max_sessions or
                    (srv.mode == .first_channel and srv.served_one))
                {
                    return srv.refuseOpen(kind, sender, .resource_shortage, if (srv.config.max_sessions == 1)
                        "only one session channel is supported"
                    else
                        "too many session channels");
                }
                if (!std.mem.eql(u8, kind, "session")) {
                    return srv.refuseOpen(kind, sender, .unknown_channel_type, "only \"session\" channels are supported");
                }
                if (max_packet == 0) {
                    return srv.refuseOpen(kind, sender, .connect_failed, "zero maximum packet size");
                }
                try srv.channels.ensureUnusedCapacity(srv.gpa, 1);
                const sc = try srv.gpa.create(ServerChannel);
                sc.* = .{ .ch = .{
                    .local_id = srv.next_id,
                    .local_window = srv.config.window_size,
                    .local_window_initial = srv.config.window_size,
                    .local_max_packet = srv.config.max_packet_size,
                    .remote_id = sender,
                    .remote_window = window,
                    .remote_max_packet = max_packet,
                    .open = true,
                } };
                // Owned by `channels` from here on (`deinit` frees it): no
                // errdefer past this line, or a failed send below would
                // free it twice (review 2026-10-06 H1).
                srv.channels.appendAssumeCapacity(sc);
                srv.next_id +%= 1;
                srv.served_one = true;

                var buf: [32]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                try writeChannelHeader(&w, .SSH_MSG_CHANNEL_OPEN_CONFIRMATION, sc.ch.remote_id);
                try writeU32(&w, sc.ch.local_id);
                try writeU32(&w, sc.ch.local_window);
                try writeU32(&w, sc.ch.local_max_packet);
                try srv.t.sendPacket(w.buffered());
            },
            .SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                const sc = try srv.find(&c);
                if (closingByUs(sc)) return;
                sc.ch.remote_window +|= try c.uint32();
            },
            .SSH_MSG_CHANNEL_DATA => {
                const sc = try srv.find(&c);
                if (closingByUs(sc)) return;
                const data = try c.string();
                try sc.ch.acceptData(data.len);
                // `.ignore`: the handler never sees stdin, so none is kept
                // (review 2026-10-06 L3); the window is still accounted.
                if (srv.config.stdin_mode == .collect_until_eof) {
                    if (sc.stdin.items.len + data.len > srv.config.max_input) return error.OutputTooLarge;
                    try sc.stdin.appendSlice(srv.gpa, data);
                }
                try maybeAdjustWindow(srv.t, &sc.ch);
            },
            .SSH_MSG_CHANNEL_EXTENDED_DATA => {
                const sc = try srv.find(&c);
                if (closingByUs(sc)) return;
                _ = try c.uint32();
                const data = try c.string();
                try sc.ch.acceptData(data.len);
                try maybeAdjustWindow(srv.t, &sc.ch);
            },
            .SSH_MSG_CHANNEL_EOF => {
                const sc = try srv.find(&c);
                if (closingByUs(sc)) return;
                sc.ch.got_eof = true;
                // stdin is complete — now the handler can see all of it.
                if (sc.pending) |*p| p.ready = true;
            },
            .SSH_MSG_CHANNEL_CLOSE => {
                const sc = try srv.find(&c);
                sc.ch.got_close = true;
                try sendCloseMsg(srv.t, &sc.ch);
            },
            .SSH_MSG_CHANNEL_REQUEST => {
                const sc = try srv.find(&c);
                if (closingByUs(sc)) return;
                const req = try c.string();
                const want_reply = try c.boolean();
                try srv.channelRequest(sc, req, want_reply, &c);
            },
            else => return error.ProtocolError,
        }
    }

    fn channelRequest(srv: *Server, sc: *ServerChannel, req: []const u8, want_reply: bool, c: *Cursor) ChannelError!void {
        const gpa = srv.gpa;
        if (std.mem.eql(u8, req, "pty-req")) {
            if (!srv.config.allow_pty or sc.ran) {
                if (want_reply) try sendChannelReply(srv.t, &sc.ch, false);
                return;
            }
            const term = try c.string();
            var pty: PtyInfo = .{
                .cols = try c.uint32(),
                .rows = try c.uint32(),
                .width_px = try c.uint32(),
                .height_px = try c.uint32(),
            };
            _ = try c.string(); // encoded terminal modes (§8): nothing here to apply them to
            const n = @min(term.len, pty.term_buf.len);
            @memcpy(pty.term_buf[0..n], term[0..n]);
            pty.term_len = @intCast(n);
            sc.pty = pty;
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, true);
            return;
        }
        if (std.mem.eql(u8, req, "env")) {
            const name = try c.string();
            const value = try c.string();
            const ok = !sc.ran and sc.env.items.len < max_env_vars and envAccepted(srv.config.accept_env, name);
            if (ok) {
                const n = try gpa.dupe(u8, name);
                errdefer gpa.free(n);
                const v = try gpa.dupe(u8, value);
                errdefer gpa.free(v);
                try sc.env.append(gpa, .{ .name = n, .value = v });
            }
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, ok);
            return;
        }
        if (std.mem.eql(u8, req, "window-change")) {
            // §6.7: never `want_reply`; the new size is recorded for a
            // handler that has not run yet.
            if (sc.pty) |*pty| {
                pty.cols = try c.uint32();
                pty.rows = try c.uint32();
                pty.width_px = try c.uint32();
                pty.height_px = try c.uint32();
            }
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, sc.pty != null);
            return;
        }

        const kind: @FieldType(RequestInfo, "kind") = if (std.mem.eql(u8, req, "exec"))
            .exec
        else if (std.mem.eql(u8, req, "subsystem"))
            .subsystem
        else if (std.mem.eql(u8, req, "shell"))
            .shell
        else {
            // signal / xon-xoff / x11-req / auth-agent-req / keepalive and
            // anything else: a one-shot handler has nothing to deliver a
            // signal to, and the rest are not implemented.
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, false);
            return;
        };
        const handler: ?CommandHandler = switch (kind) {
            .exec => srv.config.exec,
            .subsystem => srv.config.subsystem,
            .shell => srv.config.shell,
        };
        if (handler == null or sc.ran) {
            // A second exec/shell on the same channel lands here too.
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, false);
            return;
        }
        const command: []const u8 = if (kind == .shell) "" else try c.string();
        // S3b: for "subsystem", `command` is the requested NAME, not a
        // command line. An empty `subsystem_names` (the default) accepts any
        // name; a non-empty one rejects a name not on it right here, before
        // SSH_MSG_CHANNEL_SUCCESS ever goes out.
        if (kind == .subsystem and srv.config.subsystem_names.len > 0 and
            !nameInList(srv.config.subsystem_names, command))
        {
            if (want_reply) try sendChannelReply(srv.t, &sc.ch, false);
            return;
        }
        if (want_reply) try sendChannelReply(srv.t, &sc.ch, true);
        sc.ran = true;
        const ready = switch (srv.config.stdin_mode) {
            .ignore => true,
            .collect_until_eof => sc.ch.got_eof,
        };
        if (srv.config.stdin_mode == .ignore) sc.stdin.clearRetainingCapacity();
        sc.pending = .{ .handler = handler.?, .kind = kind, .command = try gpa.dupe(u8, command), .ready = ready };
    }

    /// Run a ready handler and stream its result back, then close the
    /// channel down the RFC 4254 §5.3 way: data → `exit-status` → EOF → CLOSE.
    fn runPending(srv: *Server, sc: *ServerChannel) ChannelError!void {
        const p = sc.pending.?;
        sc.pending = null;
        defer srv.gpa.free(p.command);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(srv.gpa);
        var err_out: std.ArrayList(u8) = .empty;
        defer err_out.deinit(srv.gpa);

        const stdin: []const u8 = if (srv.config.stdin_mode == .ignore) &.{} else sc.stdin.items;
        const info: RequestInfo = .{
            .user = srv.config.user,
            .kind = p.kind,
            .command = p.command,
            .pty = sc.pty,
            .env = sc.env.items,
            .channel = sc.ch.local_id,
        };
        const status = p.handler.runInfo(srv.gpa, &info, stdin, &out, &err_out) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.CommandFailed => return error.CommandFailed,
        };

        if (!try srv.sendData(sc, out.items, null)) return;
        if (!try srv.sendData(sc, err_out.items, messages.extended_data_stderr)) return;
        try sendExitStatus(srv.t, &sc.ch, status);
        try sendEofMsg(srv.t, &sc.ch);
        try sendCloseMsg(srv.t, &sc.ch);
    }

    /// `data` as CHANNEL_DATA (`data_type == null`) or CHANNEL_EXTENDED_DATA,
    /// chunked to the client's window and maximum packet size (§5.2). While
    /// the window is shut, every incoming packet is applied (to any channel)
    /// via `dispatch`. False when the client closed this channel meanwhile.
    fn sendData(srv: *Server, sc: *ServerChannel, data: []const u8, data_type: ?u32) ChannelError!bool {
        var rest = data;
        while (rest.len > 0) {
            while (sc.ch.remote_window == 0) {
                if (sc.ch.got_close) return false;
                if (srv.disconnected) return error.ChannelClosed;
                const pkt = try srv.t.recvPacket(srv.scratch);
                try srv.dispatch(pkt.payload);
            }
            if (sc.ch.got_close) return false;
            const limit = @min(@min(sc.ch.remote_max_packet, max_send_chunk), sc.ch.remote_window);
            const n = @min(@as(usize, limit), rest.len);
            var buf: [max_send_chunk + 64]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            if (data_type) |code| {
                try writeChannelHeader(&w, .SSH_MSG_CHANNEL_EXTENDED_DATA, sc.ch.remote_id);
                try writeU32(&w, code);
            } else {
                try writeChannelHeader(&w, .SSH_MSG_CHANNEL_DATA, sc.ch.remote_id);
            }
            try messages.writeString(&w, rest[0..n]);
            try srv.t.sendPacket(w.buffered());
            sc.ch.remote_window -= @intCast(n);
            rest = rest[n..];
        }
        return true;
    }
};

/// Cap on accepted `env` variables per channel.
const max_env_vars = 64;

/// Test seam for `interop_test.zig` (the patterns are not attacker data,
/// the name is).
pub const envAcceptedForTest = if (@import("builtin").is_test) envAccepted else {};

/// `ServeConfig.accept_env` membership: an exact name, or a pattern ending
/// in `*` that matches by prefix.
fn envAccepted(patterns: []const []const u8, name: []const u8) bool {
    for (patterns) |p| {
        if (p.len > 0 and p[p.len - 1] == '*') {
            if (std.mem.startsWith(u8, name, p[0 .. p.len - 1])) return true;
        } else if (std.mem.eql(u8, p, name)) return true;
    }
    return false;
}

/// The peer went away (end of stream, reset, or a write into a closed
/// socket).
fn hungUp(e: ChannelError) bool {
    return e == error.EndOfStream or e == error.ReadFailed or e == error.WriteFailed or
        e == error.PeerDisconnected;
}

/// `ServeConfig.subsystem_names` membership test — linear scan, since the
/// list is a handful of static names a caller wrote out, not attacker data.
fn nameInList(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
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

test "maybeAdjustWindow does not overflow u32 on a large configured window" {
    // audit `ssh` F4: `local_window * 2` used to overflow (ReleaseSafe panic)
    // once a caller passed `window_size` above 0x7FFF_FFFF via
    // `SessionOptions`/`ServeConfig`. Not peer-reachable, but the caller-
    // config path itself must not panic.
    const t = std.testing;
    var sink_buf: [64]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var r: std.Io.Reader = .fixed(&.{});
    var tr = transport.Transport.init(&r, &sink);

    // `local_window` alone is > 0x7FFF_FFFF, so `local_window * 2` (the old
    // formula) overflows u32 regardless of which branch is taken — the
    // multiply itself panics under ReleaseSafe before the comparison runs.
    var ch = ChannelState{
        .local_id = 0,
        .remote_id = 3,
        .local_window = 0x9000_0000, // still > half of initial: no top-up due
        .local_window_initial = 0xF000_0000,
        .local_max_packet = 1024,
    };
    try maybeAdjustWindow(&tr, &ch);
    try t.expectEqual(@as(u32, 0x9000_0000), ch.local_window); // unchanged
}

test "Server.sendData rejects a WINDOW_ADJUST addressed to another channel" {
    // audit `ssh` F5: the wait loop used to discard `recipient_channel`
    // (`_ = try c.uint32()`) instead of checking it against `expectChannel`
    // like every other channel-message site. Latent while the module is
    // single-channel, but this proves the guard now rejects a mismatched id
    // rather than silently crediting our window with someone else's grant.
    const t = std.testing;

    // WINDOW_ADJUST addressed to channel 99, while our local id is 5.
    var wa_buf: [16]u8 = undefined;
    var ww: std.Io.Writer = .fixed(&wa_buf);
    try writeChannelHeader(&ww, .SSH_MSG_CHANNEL_WINDOW_ADJUST, 99);
    try writeU32(&ww, 1000);

    var wire: [256]u8 = undefined;
    const framed = try framePackets(&wire, &.{ww.buffered()});

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [64]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    var srv = try Server.init(&tr, t.allocator, .{}, .until_disconnect);
    defer srv.deinit();
    const sc = try t.allocator.create(ServerChannel);
    sc.* = .{
        .ch = .{
            .local_id = 5,
            .remote_id = 7,
            .local_window = 1 << 20,
            .local_window_initial = 1 << 20,
            .local_max_packet = 1024,
            .remote_window = 0, // forces the wait loop to run
            .remote_max_packet = 1024,
            .open = true,
        },
    };
    try srv.channels.append(t.allocator, sc);
    try t.expectError(error.ChannelClosed, srv.sendData(sc, "hello", null));
    // The mismatched grant must not have been credited.
    try t.expectEqual(@as(u32, 0), sc.ch.remote_window);
}

test "max_send_chunk fits in one binary packet" {
    // `transport.writePacket` encodes into an 8 KiB stack buffer; a full
    // chunk plus CHANNEL_EXTENDED_DATA header, padding and a 32-byte MAC
    // must stay under it or `exec` would fail on large output.
    try std.testing.expect(max_send_chunk + 13 + 16 + 32 + 4 < 8192);
}

test "delivered flow-control and output-cap defaults are pinned to their documented values" {
    // audit `ssh` F3: `default_window_size`/`default_max_packet_size` guard
    // RFC 4254 §5.2 accounting (:114-122) and `default_max_output` bounds
    // the one-shot `exec` collector — none of the three had a test pinning
    // the literal, only the inequality on `max_send_chunk` above did.
    const t = std.testing;
    try t.expectEqual(@as(u32, 2 * 1024 * 1024), default_window_size);
    try t.expectEqual(@as(u32, 32 * 1024), default_max_packet_size);
    try t.expectEqual(@as(usize, 8 * 1024 * 1024), default_max_output);
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

/// ⭐ `accept` that cannot wait forever — see the twin in `server.zig` for the
/// full account. Short version: the live tests spawn a real `/usr/bin/ssh` and
/// then block waiting for it to connect, and a client that exits first leaves
/// the accept blocked for the life of the process. That is what wedged every
/// CI lane on 2026-08-15 into the six-hour job limit.
///
/// ⛔ Not `SO_RCVTIMEO`: `std.Io.Threaded` panics on the `EAGAIN` it produces
/// ("programmer bug caused syscall error: AGAIN"). `poll(2)` on the raw handle
/// sidesteps `std.Io` and is what `opcua`'s driver uses for the same reason.
///
/// That same sidestep means `std.posix.poll` is not a cancellation point: it
/// retries on `EINTR`, and a thread parked in it is never signalled by
/// `Threaded` at all, so the wait runs to its full `timeout_ms` regardless of
/// a pending `Future.cancel` — which would otherwise surface as an ordinary
/// `error.AcceptPollFailed` or as `error.PeerNeverConnected`, indistinguishable
/// from a peer that genuinely never showed up. `checkCanceled` recovers it
/// once the wait ends, on both exit paths.
fn checkCanceled(io: std.Io) error{Canceled}!void {
    // `Io.checkCancel` acknowledges the request and reports it exactly once;
    // the answer has to be converted into an error right here, not asked for
    // again.
    io.checkCancel() catch return error.Canceled;
}

fn acceptBounded(io: std.Io, listener: *std.Io.net.Server, timeout_ms: i32) !std.Io.net.Stream {
    var fds = [_]std.posix.pollfd{.{
        .fd = listener.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, timeout_ms) catch {
        try checkCanceled(io);
        return error.AcceptPollFailed;
    };
    if (n == 0) {
        try checkCanceled(io);
        // A peer this test started itself and that never arrived is a
        // FINDING, not a reason to skip.
        return error.PeerNeverConnected;
    }
    return listener.accept(io);
}

test "acceptBounded: a canceled wait surfaces Canceled, not an idle poll timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var port: u16 = 0;
    var listener = try testListenLoopback(io, &port);
    defer listener.deinit(io);

    // Nobody connects: the poll inside `acceptBounded` is genuinely parked
    // for the whole of this timeout, exactly like the accept wait a real
    // caller would cancel on shutdown.
    var fut = try io.concurrent(acceptBounded, .{ io, &listener, @as(i32, 5000) });
    try io.sleep(.fromMilliseconds(100), .awake);
    try std.testing.expectError(error.Canceled, fut.cancel(io));
}

/// How long any test here waits for a peer it has already started.
const accept_timeout_ms: i32 = 30_000;

/// Loopback tests dial an in-process server whose host key the test itself
/// generated, so there is nothing to look up — the trust decision is already
/// discharged by construction. Never a template for real code.
const accept_any_host_key: transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: transport.HostKeyInfo) transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "127.0.0.1" };

fn testKey(seed_byte: u8) userauth.AuthKey {
    const seed: [32]u8 = [_]u8{seed_byte} ** 32;
    return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable };
}

/// The single authorized key of the test server, as a wire blob. Lives on
/// the stack of the harness that built the key and reaches the hook through
/// `AuthorizedKeyCheck.ctx` — it used to be a file-scope `var` set before
/// each run, which is exactly the workaround the context pointer removes.
const Authorized = struct {
    blob: []const u8,

    fn check(ctx: *anyopaque, user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        const self: *Authorized = @ptrCast(@alignCast(ctx));
        return std.mem.eql(u8, user, "alice") and
            std.mem.eql(u8, algorithm, "ssh-ed25519") and
            std.mem.eql(u8, key_blob, self.blob);
    }

    fn hook(self: *Authorized) userauth.AuthorizedKeyCheck {
        return .{ .ctx = self, .checkFn = check };
    }
};

const check_password: userauth.PasswordCheck = .{ .checkFn = struct {
    fn f(_: *anyopaque, user: []const u8, password: []const u8) bool {
        return std.mem.eql(u8, user, "alice") and std.mem.eql(u8, password, "correct horse");
    }
}.f };

/// Test command handler: echoes identity/stdin, writes to stderr, and exits
/// with a distinctive non-zero status so `exit-status` cannot be faked by a
/// default.
///
/// It also opens its reply with a label taken from `CommandHandler.ctx`, and
/// every loopback case uses its OWN label — so the asserted stdout is only
/// right if `serveSession` really handed this handler the context THIS
/// connection was configured with, rather than some other connection's or
/// none.
const ExecLabel = struct {
    label: []const u8,

    fn handler(self: *ExecLabel) CommandHandler {
        return .{ .ctx = self, .runFn = testExecHandler };
    }
};

/// The label the fuzz/reject tests use — they assert nothing about stdout,
/// so one shared instance is honest here.
var fuzz_label: ExecLabel = .{ .label = "fuzz" };

fn testExecHandler(
    ctx: *anyopaque,
    gpa: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) CommandError!u32 {
    const self: *ExecLabel = @ptrCast(@alignCast(ctx));
    if (std.mem.eql(u8, command, "big")) {
        // Larger than the tiny window the `big` case advertises, so the
        // send path must actually block on SSH_MSG_CHANNEL_WINDOW_ADJUST.
        try stdout.appendNTimes(gpa, 'x', 100_000);
        return 0;
    }
    try stdout.print(gpa, "[{s}] ran '{s}' as {s}", .{ self.label, command, user });
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
    /// What `userauth.BannerHandler` delivered, copied out of the packet
    /// scratch (the seam borrows). `banner_len == 0` means the handler was
    /// never called — which is the whole assertion: the server below always
    /// sets `AuthConfig.banner`.
    banner_buf: [128]u8 = undefined,
    banner_len: usize = 0,
    banner_calls: usize = 0,

    fn banner(self: *const ClientCtx) []const u8 {
        return self.banner_buf[0..self.banner_len];
    }

    fn showBanner(ctx: *anyopaque, message: []const u8, language: []const u8) void {
        const self: *ClientCtx = @ptrCast(@alignCast(ctx));
        self.banner_calls += 1;
        // RFC 4252 §5.4 sends a language tag alongside; the test server sends
        // it empty, and capturing it is how we notice if the seam ever hands
        // the handler the wrong string.
        if (language.len != 0) return;
        const n = @min(message.len, self.banner_buf.len);
        @memcpy(self.banner_buf[0..n], message[0..n]);
        self.banner_len = n;
    }

    fn bannerHandler(self: *ClientCtx) userauth.BannerHandler {
        return .{ .ctx = self, .showFn = showBanner };
    }

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
        var t = try transport.connect(&sr.interface, &sw.interface, gpa, accept_any_host_key);

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
                const e = userauth.authenticatePublickeyBoundTo(&t, gpa, "alice", &key, .{}, bogus);
                try std.testing.expectError(error.AuthenticationFailed, e);
                try t.sendDisconnect(.no_more_auth_methods_available, "give up");
                return;
            },
            .unauthorized_key => {
                const other = testKey(0x22);
                const e = userauth.authenticatePublickey(&t, gpa, "alice", &other, .{});
                try std.testing.expectError(error.AuthenticationFailed, e);
                try t.sendDisconnect(.no_more_auth_methods_available, "give up");
                return;
            },
            .password => try userauth.authenticatePassword(&t, gpa, "alice", "correct horse", .{ .banner = self.bannerHandler() }),
            .happy_no_probe => try userauth.authenticatePublickey(&t, gpa, "alice", &key, .{ .probe_first = false }),
            else => try userauth.authenticatePublickey(&t, gpa, "alice", &key, .{ .banner = self.bannerHandler() }),
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
    var authorized: Authorized = .{ .blob = client_blob };
    // One label per case, ALL alive at once — a server handling several
    // connections holds several of these, which is the whole reason the
    // handler needs a context pointer at all. Keeping the others alive rather
    // than using a single local is also what gives the assertions teeth: a
    // handler that reads anything other than the pointer it was handed picks
    // up a neighbouring case's label, and the expected stdout no longer
    // matches. (A single local would be reused at the same stack address
    // every run and the substitution would be invisible.)
    var exec_labels: [std.meta.fields(Case).len]ExecLabel = undefined;
    inline for (std.meta.fields(Case), 0..) |f, i| exec_labels[i] = .{ .label = f.name };
    const exec_label = &exec_labels[@intFromEnum(case)];

    var port: u16 = 0;
    var listener = try testListenLoopback(io, &port);
    defer listener.deinit(io);

    var ctx = ClientCtx{ .port = port, .case = case };
    const th = try std.Thread.spawn(.{}, ClientCtx.run, .{&ctx});

    var server_err: ?anyerror = null;
    serverSide(io, &listener, gpa, host_key, case, &authorized, exec_label) catch |e| {
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
    authorized: *Authorized,
    exec_label: *ExecLabel,
) !void {
    var stream = try acceptBounded(io, listener, accept_timeout_ms);
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const keys = [_]server_mod.HostKey{host_key};
    var t = try server_mod.accept(&sr.interface, &sw.interface, gpa, .{ .host_keys = &keys });

    const auth_config = userauth.AuthConfig{
        .authorized_key = authorized.hook(),
        .password = check_password,
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
        .exec = exec_label.handler(),
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
    // The `[happy]` prefix comes from THIS case's own `CommandHandler.ctx`.
    try t.expectEqualStrings("[happy] ran 'whoami' as alice stdin='from-the-client'", ctx.stdout);
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
    // A DIFFERENT label from the `.happy` case above, in the same process:
    // the two connections' handler contexts must not be the same one.
    try t.expectEqualStrings("[password] ran 'whoami' as alice stdin='from-the-client'", ctx.stdout);
}

test "loopback: the server's USERAUTH_BANNER reaches the client's seam (RFC 4252 §5.4)" {
    const t = std.testing;
    // Both methods, because the banner is not tied to one: `serveUserauth`
    // sends `AuthConfig.banner` once before the first verdict whichever
    // method the client picked, and the seam lives in the reply loop both
    // share.
    for ([_]Case{ .happy, .password }) |case| {
        var ctx = try runCase(case);
        defer t.allocator.free(ctx.stdout);
        defer t.allocator.free(ctx.stderr);
        try expectClientOk(&ctx);
        // Before this seam existed the banner was parsed, length-checked and
        // dropped — a caller could not observe it at all, so this assertion
        // could not have been written.
        try t.expectEqualStrings("zig-libs ssh test server\n", ctx.banner());
        // Exactly once: §5.4 allows a banner at any point, and `serveUserauth`
        // guards with `banner_sent`. A second delivery would mean the guard
        // stopped working.
        try t.expectEqual(@as(usize, 1), ctx.banner_calls);
    }
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

/// Drive our whole client stack — `transport.connect` →
/// `userauth.authenticate` → `exec` — against a real `sshd`.
///
/// `client_key_type` is what `ssh-keygen` mints for the user key, and
/// `sshd_pubkey_algorithms` (when non-empty) is passed as
/// `PubkeyAcceptedAlgorithms`, which is BOTH what `sshd` puts in its RFC 8308
/// `server-sig-algs` and what it will actually verify. Setting it to a single
/// `rsa-sha2-512` is therefore a real oracle for the client half of RFC 8308:
/// `AuthKey.fromOpenSSH` pins an RSA key to `rsa-sha2-256`, so a client that
/// does not read `server-sig-algs` signs with SHA-256 and this `sshd` refuses
/// it.
fn liveOurClientExec(client_key_type: []const u8, sshd_pubkey_algorithms: []const u8) !void {
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

    // Host key + client key, both from the real ssh-keygen. The HOST key stays
    // ed25519 in every case: `PubkeyAcceptedAlgorithms` below constrains the
    // USER key, and mixing the two would make a failure ambiguous.
    const hk_path = try std.fmt.allocPrint(gpa, "{s}/hk", .{dir_path});
    defer gpa.free(hk_path);
    const ck_path = try std.fmt.allocPrint(gpa, "{s}/ck", .{dir_path});
    defer gpa.free(ck_path);
    for ([_][]const u8{ hk_path, ck_path }, [_][]const u8{ "ed25519", client_key_type }) |p, kt| {
        var child = std.process.spawn(io, .{
            .argv = &.{ "ssh-keygen", "-q", "-t", kt, "-N", "", "-C", "zig-ssh-exec-test", "-f", p },
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
    var client_key: userauth.AuthKey = undefined;
    userauth.AuthKey.fromOpenSSH(&client_key, ck_text, null) catch return error.SkipZigTest;

    var portbuf: [2]u8 = undefined;
    testFillRandom(&portbuf);
    const port: u16 = 20000 + (std.mem.readInt(u16, &portbuf, .big) % 20000);
    const port_opt = try std.fmt.allocPrint(gpa, "Port={d}", .{port});
    defer gpa.free(port_opt);
    const ak_opt = try std.fmt.allocPrint(gpa, "AuthorizedKeysFile={s}", .{ak_path});
    defer gpa.free(ak_opt);
    // `PubkeyAcceptedAlgorithms` is what `sshd` advertises in `server-sig-algs`
    // AND what it enforces, so it is a real oracle rather than a hint. Passing
    // the default (an empty extra option) leaves the case unconstrained.
    const alg_opt = if (sshd_pubkey_algorithms.len == 0)
        try gpa.dupe(u8, "PubkeyAuthentication=yes")
    else
        try std.fmt.allocPrint(gpa, "PubkeyAcceptedAlgorithms={s}", .{sshd_pubkey_algorithms});
    defer gpa.free(alg_opt);

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
            alg_opt,                           "-o",
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

    var t = try transport.connect(&sr.interface, &sw.interface, gpa, accept_any_host_key);
    // RFC 4252 publickey against a real sshd — the session-id binding has to
    // be byte-exact or OpenSSH rejects the signature.
    try userauth.authenticate(&t, gpa, user, &client_key);

    // RFC 4254 §6.5 exec + §6.10 exit-status against a real sshd. `sh -c` so
    // the command text is shell-independent (sshd runs it through the
    // account's login shell, whatever that is).
    var res = try exec(&t, gpa, "/bin/sh -c 'printf hello; printf oops >&2; exit 7'", .{});
    defer res.deinit(gpa);

    try std.testing.expectEqualStrings("hello", res.stdout);
    try std.testing.expectEqualStrings("oops", res.stderr);
    try std.testing.expectEqual(@as(?u32, 7), res.exit_status);
}

test "live interop: our client → real OpenSSH sshd — publickey auth + exec + exit-status" {
    try liveOurClientExec("ed25519", "");
}

// The client half of RFC 8308, and the mirror of the server-side RSA lane
// below. `sshd` here accepts `rsa-sha2-512` and nothing else, and says so in
// `server-sig-algs`; `AuthKey.fromOpenSSH` hands us the key pinned to
// `rsa-sha2-256`. A client that signs with the name its own key carries is
// refused — `error.AuthenticationFailed` — so passing proves the client
// actually read the extension and re-chose, rather than being lucky.
test "live interop: our client → real OpenSSH sshd — RSA user key the server only accepts as rsa-sha2-512" {
    try liveOurClientExec("rsa", "rsa-sha2-512");
}

/// Our server's authorized key for the live `ssh`-client test. The buffer is
/// sized for the largest blob the cases below can produce (an rsa-4096 blob
/// is ~535 bytes, over the 512 this held while only ed25519 was exercised).
const LiveAuthorized = struct {
    blob: [1024]u8 = undefined,
    blob_len: usize = 0,

    fn check(ctx: *anyopaque, user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        const self: *LiveAuthorized = @ptrCast(@alignCast(ctx));
        _ = user;
        _ = algorithm;
        return std.mem.eql(u8, key_blob, self.blob[0..self.blob_len]);
    }

    fn hook(self: *LiveAuthorized) userauth.AuthorizedKeyCheck {
        return .{ .ctx = self, .checkFn = check };
    }
};

const live_exec_handler: CommandHandler = .{ .runFn = liveExecHandler };

fn liveExecHandler(
    _: *anyopaque,
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

/// Drive a real OpenSSH `ssh` client, authenticating with a `user_key_type`
/// user key, through our whole server stack: `server.accept` →
/// `userauth.serveUserauth` → `serveSession`.
///
/// `user_key_type` is the only knob because it is the only thing that has
/// ever made this differ: an `ed25519` (or `ecdsa`) user key has exactly one
/// signature algorithm, so a client can offer it with no information from the
/// server, whereas an `rsa` key's blob type (`ssh-rsa`) names no hash and the
/// client will not guess one — it needs the server's RFC 8308
/// `server-sig-algs`. That is why the `rsa` case below is the regression test
/// for EXT_INFO and the `ed25519` case is not: with EXT_INFO removed the
/// `ed25519` case still passes.
fn liveSshClientExec(user_key_type: []const u8) !void {
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
            .argv = &.{ "ssh-keygen", "-q", "-t", user_key_type, "-N", "", "-C", "zig-ssh-srvexec", "-f", ck_path },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        switch (child.wait(io) catch return error.SkipZigTest) {
            .exited => |c| if (c != 0) return error.SkipZigTest,
            else => return error.SkipZigTest,
        }
    }
    // Authorize exactly that key: parse its wire blob out of the .pub line.
    var live_authorized: LiveAuthorized = .{};
    {
        const pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{ck_path});
        defer gpa.free(pub_path);
        const text = cwd.readFileAlloc(io, pub_path, gpa, .limited(4096)) catch return error.SkipZigTest;
        defer gpa.free(text);
        var it = std.mem.tokenizeScalar(u8, text, ' ');
        _ = it.next() orelse return error.SkipZigTest; // key type, e.g. "ssh-ed25519"
        const b64 = it.next() orelse return error.SkipZigTest;
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(b64) catch return error.SkipZigTest;
        if (n > live_authorized.blob.len) return error.SkipZigTest;
        dec.decode(live_authorized.blob[0..n], b64) catch return error.SkipZigTest;
        live_authorized.blob_len = n;
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

    var stream = try acceptBounded(io, &listener, accept_timeout_ms);
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
    const auth = try userauth.serveUserauth(&t, gpa, .{ .authorized_key = live_authorized.hook() });
    try std.testing.expectEqualStrings("alice", auth.user());

    // …and our RFC 4254 server must give it output + an exit status. The
    // real client holds stdin open in some configurations, so run the
    // handler as soon as the request arrives.
    try serveSession(&t, gpa, .{
        .user = auth.user(),
        .exec = live_exec_handler,
        .stdin_mode = .ignore,
    });

    _ = ssh_child.wait(io) catch {};
    const out = try cwd.readFileAlloc(io, out_path, gpa, .limited(4096));
    defer gpa.free(out);
    try std.testing.expectEqualStrings("zig-libs ran: uname -a\n3\n", out);
}

test "live interop: real OpenSSH ssh client → our server — publickey auth + exec + exit-status" {
    try liveSshClientExec("ed25519");
}

// The RFC 8308 regression test. A real `ssh` will not offer an RSA user key
// to a server that never sent `server-sig-algs` — it logs `send_pubkey_test:
// no mutual signature algorithm` and never sends the request at all, so this
// fails at `serveUserauth` with `error.AuthenticationFailed`. It is the only
// test in this module that a foreign client's *algorithm* selection can
// break: our own client names an RSA signature algorithm itself, so every
// loopback test is blind to it.
test "live interop: real OpenSSH ssh client → our server — RSA user key (RFC 8308 server-sig-algs)" {
    try liveSshClientExec("rsa");
}

// ── offline reject tests (crafted wire input, no socket, no threads) ───────

/// Frame `payloads` as plaintext binary packets (the `.none` cipher state),
/// so a crafted message stream can be fed straight into `serveSession`.
fn framePackets(out: []u8, payloads: []const []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    var cipher: transport.CipherState = .plaintext;
    for (payloads) |p| try transport.writePacket(&w, &cipher, .os, p);
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
/// ⛔ What this harness used to do, and why none of it happened. Its first draw
/// was `valueRangeAtMost(u8, 1, 6)` — the range minimum, **1** — so it built one
/// message; the type came from `boolWeighted(4, 1)`, false at the minimum, so
/// the `else` arm's `valueRangeAtMost(u8, 0, 255)` gave **0**; and the body
/// length was 0 too. With no corpus the target therefore replayed exactly one
/// input for ever: a single packet whose whole payload is the octet `0x00`.
/// Message type 0 is not in 90..100, so it fell straight through to
/// `else => ProtocolError` — and the comment above, which says this harness
/// exists because "the entire §5/§6 message layer had zero fuzz coverage",
/// was describing the state it left behind rather than the one it created.
///
/// ⭐ The seed is now a LIST of channel-message payloads, each a
/// `testkit.fuzz` slice seed, terminated by a zero-length one. The first draw
/// is bytes, so the reach gate is satisfied honestly; the number of messages
/// and their contents both come out of the seed; and the positive entries are
/// built by this file's own `channelOpenPayload` and the RFC 4254 writers,
/// because a channel message is a type octet plus length-prefixed fields and
/// arbitrary bytes are not one.
const SessionCorpus = struct {
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [7][]const u8 = undefined,
    counts: [7]usize = undefined,
    n: usize = 0,

    fn push(self: *SessionCorpus, payloads: []const []const u8) void {
        const start = self.used;
        var at = start;
        for (payloads) |p| at += testkit.fuzz.seedInto(self.store[at..], p).len;
        at += testkit.fuzz.seedInto(self.store[at..], "").len; // the terminator
        self.entries[self.n] = self.store[start..at];
        self.counts[self.n] = payloads.len;
        self.used = at;
        self.n += 1;
    }

    fn dataPayload(buf: []u8, recipient: u32, body: []const u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_DATA)) catch unreachable;
        writeU32(&w, recipient) catch unreachable;
        messages.writeString(&w, body) catch unreachable;
        return w.buffered();
    }

    fn execPayload(buf: []u8, recipient: u32, command: []const u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_REQUEST)) catch unreachable;
        writeU32(&w, recipient) catch unreachable;
        messages.writeString(&w, "exec") catch unreachable;
        w.writeByte(1) catch unreachable; // want_reply
        messages.writeString(&w, command) catch unreachable;
        return w.buffered();
    }

    fn onePayload(buf: []u8, mt: messages.MessageType, recipient: u32) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.writeByte(@intFromEnum(mt)) catch unreachable;
        writeU32(&w, recipient) catch unreachable;
        return w.buffered();
    }

    fn build(self: *SessionCorpus) []const []const u8 {
        var b1: [64]u8 = undefined;
        const open = channelOpenPayload(&b1, 7, 64, 128) catch unreachable;
        var b2: [128]u8 = undefined;
        const exec_req = execPayload(&b2, 0, "hello");
        var b3: [64]u8 = undefined;
        const eof = onePayload(&b3, .SSH_MSG_CHANNEL_EOF, 0);
        var b4: [64]u8 = undefined;
        const close = onePayload(&b4, .SSH_MSG_CHANNEL_CLOSE, 0);
        var b5: [128]u8 = undefined;
        const data = dataPayload(&b5, 0, "stdin bytes");
        var b6: [128]u8 = undefined;
        const overrun = dataPayload(&b6, 0, &([_]u8{0x41} ** 100));

        // A complete, well-formed session: open, stdin, exec, eof, close.
        self.push(&.{ open, data, exec_req, eof, close });
        // Open and nothing else: the server must confirm and then meet EOF.
        self.push(&.{open});
        // ⭐ 100 octets of CHANNEL_DATA against the 64-octet window this
        // harness advertises — the flow-control arithmetic the old draws could
        // not reach, since they never produced a CHANNEL_DATA at all.
        self.push(&.{ open, overrun });
        // Channel messages for a channel that was never opened.
        self.push(&.{ data, close });
        // A CHANNEL_OPEN truncated to its type octet.
        self.push(&.{open[0..1]});
        // The single `0x00` payload the target replayed on every round.
        self.push(&.{&[_]u8{0}});
        self.push(&.{});
        return self.entries[0..self.n];
    }
};

test "fuzz: serveSession never panics on an arbitrary channel message stream" {
    var corpus: SessionCorpus = .{};
    try std.testing.fuzz({}, fuzzServeSession, .{ .corpus = corpus.build() });
}

fn fuzzServeSession(_: void, smith: *std.testing.Smith) !void {
    // The first draw is taken here, byte-first; the harness reads it back.
    var first: [192]u8 = undefined;
    const n = smith.slice(&first);
    var src: fuzz_test.Primed(std.testing.Smith) = .{ .inner = smith, .first = first[0..n] };
    return serveSessionHarness(@TypeOf(src), &src, std.testing.allocator);
}

const fuzz_test = @import("fuzz_test.zig");
const SessionLabel = enum { failed, served, replied };
const session_reach = fuzz_test.Reach(SessionLabel);

/// The harness body, generic over its source (`testing.fuzz` hands it a
/// `Smith`, testkit's driver a corpus-replaying PRNG).
fn serveSessionHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var payload_store: [6][192]u8 = undefined;
    var payloads: [6][]const u8 = undefined;
    // ⚠ Bytes first, and the message COUNT out of the bytes: a zero-length
    // payload ends the list. See `SessionCorpus` for what the ranged draws
    // this replaced were actually producing.
    var n: usize = 0;
    while (n < payloads.len) : (n += 1) {
        const len: usize = src.slice(&payload_store[n]);
        if (len == 0) break;
        payloads[n] = payload_store[n][0..len];
    }

    var wire: [4096]u8 = undefined;
    const framed = framePackets(&wire, payloads[0..n]) catch return;

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [8192]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    // Small window/packet bounds so the flow-control arithmetic is exercised
    // near its edges rather than under a 2 MiB default that never closes.
    const res = serveSession(&tr, gpa, .{
        .exec = fuzz_label.handler(),
        .window_size = 64,
        .max_packet_size = 128,
        .max_input = 4096,
    });
    if (res) |_| session_reach.mark(.served) else |_| session_reach.mark(.failed);
    if (sink.buffered().len > 0) session_reach.mark(.replied);
}

fn driveSession(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var corpus: SessionCorpus = .{};
    return fuzz_test.corpusDrive(S, src, gpa, corpus.build(), serveSessionHarness);
}

test "fuzz driver: SSH_FUZZ (ssh-session)" {
    try fuzz_test.fuzz_driver.run(driveSession, .{ .prefix = "SSH_FUZZ", .name = "ssh-session", .scale = 10 });
}

test "fuzz harness: 300 serveSession seeds in every test run, and they get everywhere" {
    try fuzz_test.reachSeeds(session_reach, "ssh-session", driveSession, 300);
}

test "corpus: the serveSession seeds deliver real channel messages, counts pinned" {
    // ⛔ Two numbers, neither of which the collapsed input could move.
    // `delivered` is how many messages the seeds actually carried — it was 1
    // on every round before, and one that never reached the channel layer.
    // `reply_octets` is what the server WROTE back: a stream the server
    // answers produces packets, and an unparseable one produces none, so it
    // is the number that says the RFC 4254 handling ran at all.
    var corpus: SessionCorpus = .{};
    const entries = corpus.build();
    var delivered: usize = 0;
    var reply_octets: usize = 0;
    for (entries, corpus.counts[0..corpus.n]) |sd, want| {
        var smith: std.testing.Smith = .{ .in = sd };
        var payload_store: [6][192]u8 = undefined;
        var payloads: [6][]const u8 = undefined;
        var n: usize = 0;
        while (n < payloads.len) : (n += 1) {
            const len: usize = smith.slice(&payload_store[n]);
            if (len == 0) break;
            payloads[n] = payload_store[n][0..len];
        }
        try std.testing.expectEqual(want, n);
        delivered += n;
        var wire: [4096]u8 = undefined;
        const framed = framePackets(&wire, payloads[0..n]) catch continue;
        var r: std.Io.Reader = .fixed(framed);
        var sink_buf: [8192]u8 = undefined;
        var sink: std.Io.Writer = .fixed(&sink_buf);
        var tr = transport.Transport.init(&r, &sink);
        serveSession(&tr, std.testing.allocator, .{
            .exec = fuzz_label.handler(),
            .window_size = 64,
            .max_packet_size = 128,
            .max_input = 4096,
        }) catch {};
        reply_octets += sink.buffered().len;
    }
    try std.testing.expectEqual(@as(usize, 12), delivered);
    // +16 since the transport answers an unrecognized message number with
    // SSH_MSG_UNIMPLEMENTED (RFC 4253 §11.4) instead of the layer above
    // failing on it.
    try std.testing.expectEqual(@as(usize, 296), reply_octets);
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
        .exec = fuzz_label.handler(),
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
        .exec = fuzz_label.handler(),
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
        .exec = fuzz_label.handler(),
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

/// A1/examples/ssh.md S3a: `serveSession` used to refuse a second/wrong-type
/// channel with no server-side seam at all — only the wire-level
/// OPEN_FAILURE the test above already checks. Records what
/// `on_channel_open_refused` was called with, for the regression test below.
const RefusalRecorder = struct {
    calls: usize = 0,
    kind_buf: [64]u8 = undefined,
    last_kind: []const u8 = "",
    last_reason: ?messages.ChannelOpenFailureReason = null,
    desc_buf: [128]u8 = undefined,
    last_description: []const u8 = "",

    // `kind`/`description` are borrowed for the duration of the call (same
    // idiom as `CommandHandler`'s `command`/`stdin` — they point into
    // `serveSession`'s own scratch buffer, freed when it returns), so this
    // copies them out rather than storing the slices themselves.
    fn onRefused(
        ctx: *anyopaque,
        kind: []const u8,
        reason: messages.ChannelOpenFailureReason,
        description: []const u8,
    ) void {
        const self: *RefusalRecorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        const kn = @min(kind.len, self.kind_buf.len);
        @memcpy(self.kind_buf[0..kn], kind[0..kn]);
        self.last_kind = self.kind_buf[0..kn];
        self.last_reason = reason;
        const dn = @min(description.len, self.desc_buf.len);
        @memcpy(self.desc_buf[0..dn], description[0..dn]);
        self.last_description = self.desc_buf[0..dn];
    }

    fn handler(self: *RefusalRecorder) ChannelOpenRejectedHandler {
        return .{ .ctx = self, .onFn = onRefused };
    }
};

test "serveSession: on_channel_open_refused fires on a non-session channel type (A1/examples/ssh.md S3a)" {
    // Same wire scenario as "a non-session channel type gets OPEN_FAILURE,
    // not a channel" above, plus the new optional hook. `null` (the default,
    // exercised by every other REJECT test in this file) must keep behaving
    // exactly as before -- this test only adds an assertion, it does not
    // change what's on the wire.
    const t = std.testing;

    var open_buf: [96]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&open_buf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
    try messages.writeString(&ow, "direct-tcpip");
    try writeU32(&ow, 5);
    try writeU32(&ow, 4096);
    try writeU32(&ow, 4096);

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

    var rec: RefusalRecorder = .{};
    try t.expectError(error.ChannelClosed, serveSession(&tr, t.allocator, .{
        .exec = fuzz_label.handler(),
        .on_channel_open_refused = rec.handler(),
    }));

    try t.expectEqual(@as(usize, 1), rec.calls);
    try t.expectEqualStrings("direct-tcpip", rec.last_kind);
    try t.expectEqual(messages.ChannelOpenFailureReason.unknown_channel_type, rec.last_reason.?);
    try t.expectEqualStrings("only \"session\" channels are supported", rec.last_description);
}

/// A `CommandHandler` that records the subsystem name it was called with,
/// for the `subsystem_names` regression test below.
const SubsystemRecorder = struct {
    calls: usize = 0,
    name_buf: [64]u8 = undefined,
    last_name: []const u8 = "",

    fn run(
        ctx: *anyopaque,
        gpa: std.mem.Allocator,
        user: []const u8,
        command: []const u8,
        stdin: []const u8,
        stdout: *std.ArrayList(u8),
        stderr: *std.ArrayList(u8),
    ) CommandError!u32 {
        _ = gpa;
        _ = user;
        _ = stdin;
        _ = stdout;
        _ = stderr;
        const self: *SubsystemRecorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        const n = @min(command.len, self.name_buf.len);
        @memcpy(self.name_buf[0..n], command[0..n]);
        self.last_name = self.name_buf[0..n];
        return 0;
    }

    fn handler(self: *SubsystemRecorder) CommandHandler {
        return .{ .ctx = self, .runFn = run };
    }
};

test "serveSession: subsystem_names rejects a name not on the list before CHANNEL_SUCCESS (A1/examples/ssh.md S3b)" {
    // Before this field existed, ANY subsystem name got SSH_MSG_CHANNEL_SUCCESS
    // and then ran `config.subsystem`, once `config.subsystem` was set at
    // all -- there was nowhere to check the NAME before replying. A real
    // client waiting for its own subsystem's init packet against a server
    // that only implements a different one would hang. This test opens a
    // channel, requests an unrecognized subsystem name, then a recognized
    // one, and inspects the actual wire replies (decoded through a second
    // `Transport`, the same framing the peer itself would use) rather than
    // just the handler's own call count -- the bug was specifically about
    // what goes out BEFORE the handler runs.
    const t = std.testing;

    var open_buf: [32]u8 = undefined;
    var ow: std.Io.Writer = .fixed(&open_buf);
    try ow.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN));
    try messages.writeString(&ow, "session");
    try writeU32(&ow, 5);
    try writeU32(&ow, 4096);
    try writeU32(&ow, 4096);

    var bad_req_buf: [64]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&bad_req_buf);
    try writeChannelHeader(&bw, .SSH_MSG_CHANNEL_REQUEST, 0);
    try messages.writeString(&bw, "subsystem");
    try bw.writeByte(1); // want_reply
    try messages.writeString(&bw, "unknown-name");

    var good_req_buf: [64]u8 = undefined;
    var gw: std.Io.Writer = .fixed(&good_req_buf);
    try writeChannelHeader(&gw, .SSH_MSG_CHANNEL_REQUEST, 0);
    try messages.writeString(&gw, "subsystem");
    try gw.writeByte(1); // want_reply
    try messages.writeString(&gw, "netconf");

    var close_buf: [16]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&close_buf);
    try writeChannelHeader(&cw, .SSH_MSG_CHANNEL_CLOSE, 0);

    var wire: [1024]u8 = undefined;
    const framed = try framePackets(&wire, &.{ ow.buffered(), bw.buffered(), cw.buffered() });

    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);

    var rec: SubsystemRecorder = .{};
    try serveSession(&tr, t.allocator, .{
        .subsystem = rec.handler(),
        .subsystem_names = &.{"netconf"},
    });

    // The handler must never have run for the unrecognized name.
    try t.expectEqual(@as(usize, 0), rec.calls);

    // Decode the server's own replies through a second Transport -- the same
    // framing a real peer would use to read them.
    var reply_r: std.Io.Reader = .fixed(sink.buffered());
    var reply_sink_buf: [16]u8 = undefined;
    var reply_sink: std.Io.Writer = .fixed(&reply_sink_buf);
    var reply_t = transport.Transport.init(&reply_r, &reply_sink);
    var scratch: [256]u8 = undefined;

    const open_reply = try reply_t.recvPacket(&scratch);
    try t.expectEqual(
        @as(u8, @intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION)),
        open_reply.payload[0],
    );
    const subsystem_reply = try reply_t.recvPacket(&scratch);
    try t.expectEqual(
        @as(u8, @intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_FAILURE)),
        subsystem_reply.payload[0],
    );

    // Positive control, same channel: a name ON the list still succeeds and
    // the handler still runs, with the right name -- the list restricts,
    // it does not just refuse everything.
    var wire2: [1024]u8 = undefined;
    const framed2 = try framePackets(&wire2, &.{ ow.buffered(), gw.buffered(), cw.buffered() });
    var r2: std.Io.Reader = .fixed(framed2);
    var sink_buf2: [1024]u8 = undefined;
    var sink2: std.Io.Writer = .fixed(&sink_buf2);
    var tr2 = transport.Transport.init(&r2, &sink2);
    var rec2: SubsystemRecorder = .{};
    try serveSession(&tr2, t.allocator, .{
        .subsystem = rec2.handler(),
        .subsystem_names = &.{"netconf"},
        // `.ignore` runs the handler immediately, not after CHANNEL_EOF (the
        // default `.collect_until_eof`) -- this synthetic stream never sends
        // one, and the point of this half of the test is the handler DOES
        // run for a name on the list.
        .stdin_mode = .ignore,
    });
    try t.expectEqual(@as(usize, 1), rec2.calls);
    try t.expectEqualStrings("netconf", rec2.last_name);

    var reply_r2: std.Io.Reader = .fixed(sink2.buffered());
    var reply_sink_buf2: [16]u8 = undefined;
    var reply_sink2: std.Io.Writer = .fixed(&reply_sink_buf2);
    var reply_t2 = transport.Transport.init(&reply_r2, &reply_sink2);
    _ = try reply_t2.recvPacket(&scratch); // OPEN_CONFIRMATION
    const subsystem_reply2 = try reply_t2.recvPacket(&scratch);
    try t.expectEqual(
        @as(u8, @intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_SUCCESS)),
        subsystem_reply2.payload[0],
    );
}

test "serveSession: messages the client sends after our CLOSE are dropped, not a connection error (RFC 4254 §5.3)" {
    // Review 2026-10-06 M1. The handler runs at once (`.ignore`), so our
    // exit-status/EOF/CLOSE go out right after the exec; the client — which
    // has not seen them yet — still sends a window-change, data and EOF,
    // then its CLOSE. All but the CLOSE must be dropped silently.
    const t = std.testing;
    var b0: [64]u8 = undefined;
    const open = try channelOpenPayload(&b0, 7, 1 << 20, 1 << 15);
    var b1: [64]u8 = undefined;
    const exec_req = SessionCorpus.execPayload(&b1, 0, "id");
    var b2: [64]u8 = undefined;
    var ww: std.Io.Writer = .fixed(&b2);
    try writeChannelHeader(&ww, .SSH_MSG_CHANNEL_REQUEST, 0);
    try messages.writeString(&ww, "window-change");
    try ww.writeByte(0);
    for (0..4) |_| try writeU32(&ww, 80);
    var b3: [64]u8 = undefined;
    const data = SessionCorpus.dataPayload(&b3, 0, "late");
    var b4: [16]u8 = undefined;
    const eof = SessionCorpus.onePayload(&b4, .SSH_MSG_CHANNEL_EOF, 0);
    var b5: [16]u8 = undefined;
    const close = SessionCorpus.onePayload(&b5, .SSH_MSG_CHANNEL_CLOSE, 0);

    var wire: [1024]u8 = undefined;
    const framed = try framePackets(&wire, &.{ open, exec_req, ww.buffered(), data, eof, close });
    var r: std.Io.Reader = .fixed(framed);
    var sink_buf: [4096]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var tr = transport.Transport.init(&r, &sink);
    try serveSession(&tr, t.allocator, .{ .exec = fuzz_label.handler(), .stdin_mode = .ignore });

    // Nothing after our CLOSE: the last packet we wrote is that CLOSE.
    var rr: std.Io.Reader = .fixed(sink.buffered());
    var c: transport.CipherState = .plaintext;
    var pbuf: [512]u8 = undefined;
    var last: u8 = 0;
    while (transport.readPacket(&rr, &c, &pbuf)) |pkt| last = pkt.payload[0] else |_| {}
    try t.expectEqual(@as(u8, @intFromEnum(messages.MessageType.SSH_MSG_CHANNEL_CLOSE)), last);
}
