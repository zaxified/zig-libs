// SPDX-License-Identifier: MIT

//! The IEC 60870-5-104 flow-control state machine (§5.4–§5.6, §9.6) — the part
//! of the protocol that is actually hard.
//!
//! Two counters and four timers govern every connection:
//!
//! * **k** — the sender may have at most `k` I-frames outstanding (sent but
//!   not yet acknowledged). At `k` it must stop sending and wait.
//! * **w** — the receiver must acknowledge at the latest after `w` received
//!   I-frames. `w` should not exceed two thirds of `k`, otherwise the sender
//!   stalls before the receiver has any reason to acknowledge.
//! * **t0** — connection establishment timeout.
//! * **t1** — timeout on a sent I-frame or a sent U-format *act*: if no
//!   acknowledgement/confirmation arrives, the connection must be closed.
//! * **t2** — acknowledge-when-idle: `w` may not be reached for a long time,
//!   so a receiver holding unacknowledged I-frames sends a supervisory frame
//!   after t2. **t2 must be shorter than t1**, or the sender times out before
//!   the receiver ever acknowledges.
//! * **t3** — idle test: after t3 with nothing received, send `TESTFR act`.
//!
//! Sequence numbers are **15 bits and wrap at 32768**. An implementation that
//! treats them as plain 16-bit counters, or that compares them with `<`,
//! stalls forever the first time N(S) rolls over — hence `apci.Seq` is a `u15`
//! and every comparison here goes through modulo-2^15 distance.
//!
//! **This is a pure, time-injected state machine.** It owns no clock, no
//! socket and no thread: the caller passes `now_ms` into every entry point and
//! performs the I/O that `tick` asks for. The timers are therefore policy the
//! caller applies at whatever granularity it likes — the same seam discipline
//! as the sibling `netconf`, `nl80211` and `ebpf` modules — and the whole
//! machine is testable with a fake clock and no network.

const std = @import("std");
const apci = @import("apci.zig");

const Seq = apci.Seq;
const UFunction = apci.UFunction;

// ── configuration ───────────────────────────────────────────────────────────

pub const ConfigError = error{
    /// k or w is zero, or above the 32767 ceiling a 15-bit sequence allows.
    WindowOutOfRange,
    /// w > k: the receiver would never acknowledge before the sender stalls.
    ReceiveWindowTooLarge,
    /// t2 >= t1: the sender's timeout would fire before the receiver's
    /// idle acknowledgement (§5.5 requires t2 < t1).
    T2NotLessThanT1,
    /// A timeout of zero.
    ZeroTimeout,
};

/// The six protocol parameters of IEC 60870-5-104 §9.6. The defaults are the
/// standard's own recommended values.
pub const Config = struct {
    /// Maximum outstanding (unacknowledged) I-frames. Standard default 12.
    k: u16 = 12,
    /// Acknowledge at the latest after this many received I-frames.
    /// Standard default 8, i.e. two thirds of k.
    w: u16 = 8,
    /// Connection establishment timeout, milliseconds. Standard default 30 s.
    t0_ms: u64 = 30_000,
    /// Send-or-test timeout, milliseconds. Standard default 15 s.
    t1_ms: u64 = 15_000,
    /// Acknowledge-when-idle timeout, milliseconds. Standard default 10 s.
    t2_ms: u64 = 10_000,
    /// Idle test-frame timeout, milliseconds. Standard default 20 s.
    t3_ms: u64 = 20_000,

    pub fn validate(self: Config) ConfigError!void {
        if (self.k == 0 or self.w == 0) return error.WindowOutOfRange;
        if (self.k > 32767 or self.w > 32767) return error.WindowOutOfRange;
        if (self.w > self.k) return error.ReceiveWindowTooLarge;
        if (self.t0_ms == 0 or self.t1_ms == 0 or self.t2_ms == 0 or self.t3_ms == 0) return error.ZeroTimeout;
        if (self.t2_ms >= self.t1_ms) return error.T2NotLessThanT1;
    }
};

/// Which end of the connection this is. A controlling station (master,
/// typically a control centre) initiates the TCP connection and owns
/// STARTDT/STOPDT; a controlled station (outstation/RTU) answers them.
pub const Role = enum { controlling, controlled };

pub const State = enum {
    /// No TCP connection.
    closed,
    /// TCP connect in flight; t0 is running.
    connecting,
    /// TCP is up but data transfer is stopped — only U- and S-format frames
    /// may cross. This is where a connection sits before STARTDT and after
    /// STOPDT.
    stopped,
    /// STARTDT act sent, waiting for the confirmation.
    starting,
    /// Data transfer active: I-frames may flow.
    started,
    /// STOPDT act sent, waiting for the confirmation.
    stopping,
};

pub const Error = error{
    /// The operation needs a TCP connection and there is none.
    NotConnected,
    /// An I-frame was sent or received while data transfer is stopped.
    NotStarted,
    /// k I-frames are already outstanding — the sender must wait.
    SendWindowFull,
    /// A received I-frame's N(S) is not the next one expected. §5.5 requires
    /// strictly sequential numbering; the connection must be closed.
    UnexpectedSequence,
    /// A received N(R) acknowledges a frame that was never sent, or one that
    /// was already acknowledged — i.e. it falls outside the send window.
    InvalidAcknowledgement,
    /// A frame that this role may never receive (e.g. `STARTDT act` at a
    /// controlling station), or a confirmation nobody asked for.
    UnexpectedFrame,
    /// A second U-format *act* while one is still awaiting confirmation.
    ConfirmationPending,
} || ConfigError;

/// What `onFrame` observed.
pub const Event = union(enum) {
    /// Nothing the caller needs to act on (an S-frame, a TESTFR con, …).
    none,
    /// An in-window I-frame; the slice aliases the caller's receive buffer.
    asdu: []const u8,
    /// Data transfer is now active. At a controlling station this is the
    /// `STARTDT con`; at a controlled station it is the `STARTDT act` that
    /// `tick` will confirm.
    started,
    /// Data transfer has stopped (STOPDT act or con).
    stopped,
    /// A `TESTFR act` arrived; `tick` will ask for the confirmation.
    test_requested,
    /// Our `TESTFR act` was confirmed — the link is alive.
    test_confirmed,
};

pub const CloseReason = enum {
    /// t0 expired: the TCP connection never came up.
    connect_timeout,
    /// t1 expired on an outstanding I-frame: the peer never acknowledged.
    ack_timeout,
    /// t1 expired on an outstanding U-format act: no confirmation.
    confirm_timeout,
};

/// What the caller must do now. `tick` has already accounted for it in the
/// state machine, so the caller performs the I/O and nothing else; on a write
/// failure the connection is dead anyway and the caller closes it.
pub const Action = union(enum) {
    /// Nothing to do; see `nextDeadline` for when to look again.
    none,
    /// Send a supervisory frame acknowledging up to this N(R).
    send_s_frame: Seq,
    /// Send this U-format frame.
    send_u: UFunction,
    /// Close the connection; the protocol has failed.
    close: CloseReason,
};

// ── the state machine ───────────────────────────────────────────────────────

pub const Connection = struct {
    cfg: Config,
    role: Role,
    state: State = .closed,

    /// N(S) of the next I-frame this end will send.
    send_seq: Seq = 0,
    /// Oldest I-frame this end sent that the peer has not acknowledged.
    ack_seq: Seq = 0,
    /// N(R) this end advertises: the next N(S) it expects from the peer.
    recv_seq: Seq = 0,
    /// The N(R) this end last actually put on the wire.
    last_sent_ack: Seq = 0,
    /// I-frames received since the last acknowledgement this end sent.
    unacked_rx: u16 = 0,

    t0_deadline: ?u64 = null,
    /// t1 for the oldest outstanding I-frame.
    t1_i_deadline: ?u64 = null,
    /// t1 for an outstanding U-format act.
    t1_u_deadline: ?u64 = null,
    t2_deadline: ?u64 = null,
    t3_deadline: ?u64 = null,

    /// The U-format act awaiting confirmation, if any.
    pending_act: ?UFunction = null,
    /// A U-format confirmation this end owes the peer.
    owed_confirmation: ?UFunction = null,

    pub fn init(cfg: Config, role: Role) Error!Connection {
        try cfg.validate();
        return .{ .cfg = cfg, .role = role };
    }

    // ── connection lifecycle ────────────────────────────────────────────────

    /// The caller has started a TCP connect; t0 now runs.
    pub fn beginConnect(self: *Connection, now: u64) void {
        self.resetLink();
        self.state = .connecting;
        self.t0_deadline = now + self.cfg.t0_ms;
    }

    /// The TCP connection is up. Data transfer is still stopped.
    pub fn onTcpConnected(self: *Connection, now: u64) void {
        self.state = .stopped;
        self.t0_deadline = null;
        self.t3_deadline = now + self.cfg.t3_ms;
    }

    /// The TCP connection went away; everything resets. Sequence numbers are
    /// per-connection (§5.5), so a reconnect starts again at zero.
    pub fn onTcpClosed(self: *Connection) void {
        self.resetLink();
        self.state = .closed;
    }

    fn resetLink(self: *Connection) void {
        self.send_seq = 0;
        self.ack_seq = 0;
        self.recv_seq = 0;
        self.last_sent_ack = 0;
        self.unacked_rx = 0;
        self.t0_deadline = null;
        self.t1_i_deadline = null;
        self.t1_u_deadline = null;
        self.t2_deadline = null;
        self.t3_deadline = null;
        self.pending_act = null;
        self.owed_confirmation = null;
    }

    /// True while I-frames may flow.
    pub fn isStarted(self: *const Connection) bool {
        return self.state == .started;
    }

    // ── send side ───────────────────────────────────────────────────────────

    /// Number of I-frames sent but not yet acknowledged.
    pub fn outstanding(self: *const Connection) u16 {
        return apci.seqDistance(self.ack_seq, self.send_seq);
    }

    /// True when `k` is reached and no further I-frame may be sent.
    pub fn sendWindowFull(self: *const Connection) bool {
        return self.outstanding() >= self.cfg.k;
    }

    /// Reserves the next I-format control field. Call it immediately before
    /// writing the frame: it advances N(S), clears the pending acknowledgement
    /// (the I-frame carries N(R) itself) and arms t1.
    pub fn prepareI(self: *Connection, now: u64) Error!apci.Control {
        if (self.state == .closed or self.state == .connecting) return error.NotConnected;
        if (self.state != .started) return error.NotStarted;
        if (self.sendWindowFull()) return error.SendWindowFull;

        const ctl = apci.Control{ .i = .{ .send_seq = self.send_seq, .recv_seq = self.recv_seq } };
        if (self.outstanding() == 0) self.t1_i_deadline = now + self.cfg.t1_ms;
        self.send_seq +%= 1;
        // An I-frame carries N(R), so it is itself an acknowledgement.
        self.noteAckSent();
        return ctl;
    }

    /// Sends `STARTDT act` (controlling stations only).
    pub fn startDataTransfer(self: *Connection, now: u64) Error!UFunction {
        if (self.role != .controlling) return error.UnexpectedFrame;
        if (self.state == .closed or self.state == .connecting) return error.NotConnected;
        if (self.pending_act != null) return error.ConfirmationPending;
        self.state = .starting;
        return self.armAct(.startdt_act, now);
    }

    /// Sends `STOPDT act` (controlling stations only).
    pub fn stopDataTransfer(self: *Connection, now: u64) Error!UFunction {
        if (self.role != .controlling) return error.UnexpectedFrame;
        if (self.state == .closed or self.state == .connecting) return error.NotConnected;
        if (self.pending_act != null) return error.ConfirmationPending;
        self.state = .stopping;
        return self.armAct(.stopdt_act, now);
    }

    /// Sends `TESTFR act`. Either role may test the link, in any connected
    /// state — a stopped connection is still kept alive this way.
    pub fn sendTestFrame(self: *Connection, now: u64) Error!UFunction {
        if (self.state == .closed or self.state == .connecting) return error.NotConnected;
        if (self.pending_act != null) return error.ConfirmationPending;
        return self.armAct(.testfr_act, now);
    }

    fn armAct(self: *Connection, func: UFunction, now: u64) UFunction {
        self.pending_act = func;
        self.t1_u_deadline = now + self.cfg.t1_ms;
        return func;
    }

    fn noteAckSent(self: *Connection) void {
        self.last_sent_ack = self.recv_seq;
        self.unacked_rx = 0;
        self.t2_deadline = null;
    }

    // ── receive side ────────────────────────────────────────────────────────

    /// Feeds one decoded APDU. Returns what it meant; the state machine has
    /// already updated its counters and timers.
    pub fn onFrame(self: *Connection, apdu: apci.Apdu, now: u64) Error!Event {
        if (self.state == .closed or self.state == .connecting) return error.NotConnected;
        // Any frame from the peer proves the link is alive: restart t3.
        self.t3_deadline = now + self.cfg.t3_ms;

        switch (apdu.control) {
            .i => |f| {
                if (self.state != .started) return error.NotStarted;
                if (f.send_seq != self.recv_seq) return error.UnexpectedSequence;
                try self.applyAck(f.recv_seq, now);
                self.recv_seq +%= 1;
                self.unacked_rx += 1;
                if (self.unacked_rx < self.cfg.w and self.t2_deadline == null) {
                    self.t2_deadline = now + self.cfg.t2_ms;
                }
                return .{ .asdu = apdu.asdu };
            },
            .s => |f| {
                try self.applyAck(f.recv_seq, now);
                return .none;
            },
            .u => |func| return self.onUFrame(func, now),
        }
    }

    fn onUFrame(self: *Connection, func: UFunction, now: u64) Error!Event {
        switch (func) {
            .startdt_act => {
                if (self.role != .controlled) return error.UnexpectedFrame;
                self.state = .started;
                self.owed_confirmation = .startdt_con;
                return .started;
            },
            .stopdt_act => {
                if (self.role != .controlled) return error.UnexpectedFrame;
                self.state = .stopped;
                self.owed_confirmation = .stopdt_con;
                return .stopped;
            },
            .testfr_act => {
                self.owed_confirmation = .testfr_con;
                return .test_requested;
            },
            .startdt_con, .stopdt_con, .testfr_con => {
                const expect_act: UFunction = switch (func) {
                    .startdt_con => .startdt_act,
                    .stopdt_con => .stopdt_act,
                    else => .testfr_act,
                };
                if (self.pending_act != expect_act) return error.UnexpectedFrame;
                self.pending_act = null;
                self.t1_u_deadline = null;
                _ = now;
                return switch (func) {
                    .startdt_con => blk: {
                        self.state = .started;
                        break :blk Event.started;
                    },
                    .stopdt_con => blk: {
                        self.state = .stopped;
                        break :blk Event.stopped;
                    },
                    else => Event.test_confirmed,
                };
            },
        }
    }

    /// Applies a received N(R): everything up to it is acknowledged.
    fn applyAck(self: *Connection, nr: Seq, now: u64) Error!void {
        const advance = apci.seqDistance(self.ack_seq, nr);
        if (advance > self.outstanding()) return error.InvalidAcknowledgement;
        if (advance == 0) return; // a repeat of the last acknowledgement
        self.ack_seq = nr;
        if (self.outstanding() == 0) {
            self.t1_i_deadline = null;
        } else {
            // Frames are still in flight; restart t1 for the new oldest one.
            self.t1_i_deadline = now + self.cfg.t1_ms;
        }
    }

    // ── timers ──────────────────────────────────────────────────────────────

    /// The single action the caller must perform now, if any. Priority: fatal
    /// timeouts first, then owed confirmations, then acknowledgements, then
    /// the idle test frame. Loop until it returns `.none`.
    pub fn tick(self: *Connection, now: u64) Action {
        if (self.state == .closed) return .none;

        if (self.t0_deadline) |d| if (now >= d) {
            self.t0_deadline = null;
            return .{ .close = .connect_timeout };
        };
        if (self.t1_i_deadline) |d| if (now >= d) {
            self.t1_i_deadline = null;
            return .{ .close = .ack_timeout };
        };
        if (self.t1_u_deadline) |d| if (now >= d) {
            self.t1_u_deadline = null;
            self.pending_act = null;
            return .{ .close = .confirm_timeout };
        };

        if (self.owed_confirmation) |func| {
            self.owed_confirmation = null;
            return .{ .send_u = func };
        }

        // The w counter and t2 are two routes to the same acknowledgement.
        const w_reached = self.unacked_rx >= self.cfg.w;
        const t2_fired = if (self.t2_deadline) |d| now >= d else false;
        if (self.unacked_rx > 0 and (w_reached or t2_fired)) {
            const nr = self.recv_seq;
            self.noteAckSent();
            return .{ .send_s_frame = nr };
        }

        if (self.t3_deadline) |d| if (now >= d) {
            self.t3_deadline = now + self.cfg.t3_ms;
            if (self.pending_act == null) {
                return .{ .send_u = self.armAct(.testfr_act, now) };
            }
        };

        return .none;
    }

    /// The earliest instant at which `tick` could return something other than
    /// `.none`, or null when no timer is armed. A caller with an event loop
    /// uses it as the poll timeout.
    pub fn nextDeadline(self: *const Connection) ?u64 {
        var best: ?u64 = null;
        const candidates = [_]?u64{
            self.t0_deadline,
            self.t1_i_deadline,
            self.t1_u_deadline,
            self.t2_deadline,
            self.t3_deadline,
        };
        for (candidates) |c| {
            if (c) |v| {
                if (best == null or v < best.?) best = v;
            }
        }
        // An owed confirmation or a reached w is due immediately.
        if (self.owed_confirmation != null or self.unacked_rx >= self.cfg.w) return 0;
        return best;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const fast = Config{ .k = 3, .w = 2, .t0_ms = 100, .t1_ms = 50, .t2_ms = 20, .t3_ms = 30 };
/// Same, but with t3 far out of the way so a test can exercise t1/t2 alone.
const no_t3 = Config{ .k = 3, .w = 2, .t0_ms = 100, .t1_ms = 50, .t2_ms = 20, .t3_ms = 100_000 };

fn started(role: Role, cfg: Config) !Connection {
    return startedAt(role, cfg, 0);
}

/// Brings a connection to `.started` with every timer armed relative to `now`,
/// so a test that then jumps the clock does not trip t3 by accident.
fn startedAt(role: Role, cfg: Config, now: u64) !Connection {
    var c = try Connection.init(cfg, role);
    c.beginConnect(now);
    c.onTcpConnected(now);
    switch (role) {
        .controlling => {
            _ = try c.startDataTransfer(now);
            _ = try c.onFrame(.{ .control = .{ .u = .startdt_con }, .asdu = &.{}, .len = 6 }, now);
        },
        .controlled => {
            _ = try c.onFrame(.{ .control = .{ .u = .startdt_act }, .asdu = &.{}, .len = 6 }, now);
            _ = c.tick(now); // consume the owed STARTDT con
        },
    }
    try testing.expectEqual(State.started, c.state);
    return c;
}

fn iframe(ns: Seq, nr: Seq, body: []const u8) apci.Apdu {
    return .{ .control = .{ .i = .{ .send_seq = ns, .recv_seq = nr } }, .asdu = body, .len = 6 + body.len };
}

fn sframe(nr: Seq) apci.Apdu {
    return .{ .control = .{ .s = .{ .recv_seq = nr } }, .asdu = &.{}, .len = 6 };
}

test "config validation enforces the standard's relationships" {
    try (Config{}).validate();
    try testing.expectError(error.WindowOutOfRange, (Config{ .k = 0 }).validate());
    try testing.expectError(error.WindowOutOfRange, (Config{ .w = 0 }).validate());
    try testing.expectError(error.WindowOutOfRange, (Config{ .k = 40000 }).validate());
    try testing.expectError(error.ReceiveWindowTooLarge, (Config{ .k = 4, .w = 5 }).validate());
    try testing.expectError(error.T2NotLessThanT1, (Config{ .t1_ms = 10, .t2_ms = 10 }).validate());
    try testing.expectError(error.T2NotLessThanT1, (Config{ .t1_ms = 10, .t2_ms = 11 }).validate());
    try testing.expectError(error.ZeroTimeout, (Config{ .t3_ms = 0 }).validate());
    try testing.expectError(error.T2NotLessThanT1, Connection.init(.{ .t1_ms = 1, .t2_ms = 2 }, .controlling));
}

test "STARTDT/STOPDT transitions at a controlling station" {
    var c = try Connection.init(fast, .controlling);
    try testing.expectEqual(State.closed, c.state);
    // No I-frames before there is a connection.
    try testing.expectError(error.NotConnected, c.prepareI(0));

    c.beginConnect(0);
    try testing.expectEqual(State.connecting, c.state);
    c.onTcpConnected(1);
    try testing.expectEqual(State.stopped, c.state);
    // Still no I-frames: data transfer has not started.
    try testing.expectError(error.NotStarted, c.prepareI(1));

    try testing.expectEqual(UFunction.startdt_act, try c.startDataTransfer(1));
    try testing.expectEqual(State.starting, c.state);
    // A second act while one is pending is refused.
    try testing.expectError(error.ConfirmationPending, c.sendTestFrame(1));

    try testing.expectEqual(Event.started, try c.onFrame(.{ .control = .{ .u = .startdt_con }, .asdu = &.{}, .len = 6 }, 2));
    try testing.expectEqual(State.started, c.state);
    try testing.expect(c.isStarted());
    _ = try c.prepareI(2);

    try testing.expectEqual(UFunction.stopdt_act, try c.stopDataTransfer(3));
    try testing.expectEqual(State.stopping, c.state);
    try testing.expectEqual(Event.stopped, try c.onFrame(.{ .control = .{ .u = .stopdt_con }, .asdu = &.{}, .len = 6 }, 4));
    try testing.expectEqual(State.stopped, c.state);
    try testing.expectError(error.NotStarted, c.prepareI(4));
}

test "a controlled station answers STARTDT/STOPDT and never issues them" {
    var c = try Connection.init(fast, .controlled);
    c.beginConnect(0);
    c.onTcpConnected(0);
    try testing.expectError(error.UnexpectedFrame, c.startDataTransfer(0));
    try testing.expectError(error.UnexpectedFrame, c.stopDataTransfer(0));

    try testing.expectEqual(Event.started, try c.onFrame(.{ .control = .{ .u = .startdt_act }, .asdu = &.{}, .len = 6 }, 0));
    try testing.expectEqual(State.started, c.state);
    try testing.expectEqual(Action{ .send_u = .startdt_con }, c.tick(0));
    try testing.expectEqual(Action.none, c.tick(0));

    try testing.expectEqual(Event.stopped, try c.onFrame(.{ .control = .{ .u = .stopdt_act }, .asdu = &.{}, .len = 6 }, 1));
    try testing.expectEqual(Action{ .send_u = .stopdt_con }, c.tick(1));
    try testing.expectEqual(State.stopped, c.state);

    // A controlling station must never receive an act.
    var m = try started(.controlling, fast);
    try testing.expectError(error.UnexpectedFrame, m.onFrame(.{ .control = .{ .u = .startdt_act }, .asdu = &.{}, .len = 6 }, 0));
    // ... nor a confirmation it never asked for.
    try testing.expectError(error.UnexpectedFrame, m.onFrame(.{ .control = .{ .u = .stopdt_con }, .asdu = &.{}, .len = 6 }, 0));
}

test "k exhaustion blocks sending and an acknowledgement releases it" {
    var c = try started(.controlling, fast); // k = 3
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const ctl = try c.prepareI(10);
        try testing.expectEqual(@as(Seq, @intCast(i)), ctl.i.send_seq);
    }
    try testing.expectEqual(@as(u16, 3), c.outstanding());
    try testing.expect(c.sendWindowFull());
    try testing.expectError(error.SendWindowFull, c.prepareI(10));

    // The peer acknowledges the first two: two slots free up.
    _ = try c.onFrame(sframe(2), 11);
    try testing.expectEqual(@as(u16, 1), c.outstanding());
    try testing.expect(!c.sendWindowFull());
    _ = try c.prepareI(11);
    _ = try c.prepareI(11);
    try testing.expectError(error.SendWindowFull, c.prepareI(11));

    // Acknowledging everything stops t1.
    _ = try c.onFrame(sframe(5), 12);
    try testing.expectEqual(@as(u16, 0), c.outstanding());
    try testing.expect(c.t1_i_deadline == null);
}

test "an out-of-window acknowledgement is rejected" {
    var c = try started(.controlling, fast);
    _ = try c.prepareI(0);
    _ = try c.prepareI(0); // outstanding 0 and 1, next N(S) is 2
    // N(R) = 3 acknowledges a frame that was never sent.
    try testing.expectError(error.InvalidAcknowledgement, c.onFrame(sframe(3), 1));
    // A wildly wrong one, on the far side of the wrap.
    try testing.expectError(error.InvalidAcknowledgement, c.onFrame(sframe(32000), 1));
    // A repeat of the current position is harmless.
    try testing.expectEqual(Event.none, try c.onFrame(sframe(0), 1));
    try testing.expectEqual(@as(u16, 2), c.outstanding());
    // The exact boundary is accepted.
    try testing.expectEqual(Event.none, try c.onFrame(sframe(2), 1));
    try testing.expectEqual(@as(u16, 0), c.outstanding());
}

test "an out-of-order I-frame is rejected" {
    var c = try started(.controlled, fast);
    _ = try c.onFrame(iframe(0, 0, "a"), 0);
    // The next N(S) must be 1.
    try testing.expectError(error.UnexpectedSequence, c.onFrame(iframe(2, 0, "b"), 0));
    try testing.expectError(error.UnexpectedSequence, c.onFrame(iframe(0, 0, "b"), 0));
    const e = try c.onFrame(iframe(1, 0, "b"), 0);
    try testing.expectEqualStrings("b", e.asdu);
}

test "the 15-bit sequence number wraps at 32768 in both directions" {
    var c = try started(.controlling, fast);
    // Fast-forward both counters to just below the wrap.
    c.send_seq = 32766;
    c.ack_seq = 32766;
    c.recv_seq = 32766;
    c.last_sent_ack = 32766;

    // Send across the boundary: 32766, 32767, 0.
    try testing.expectEqual(@as(Seq, 32766), (try c.prepareI(0)).i.send_seq);
    try testing.expectEqual(@as(Seq, 32767), (try c.prepareI(0)).i.send_seq);
    try testing.expectEqual(@as(Seq, 0), (try c.prepareI(0)).i.send_seq);
    try testing.expectEqual(@as(u16, 3), c.outstanding());
    // An acknowledgement on the far side of the wrap is in-window.
    _ = try c.onFrame(sframe(1), 1);
    try testing.expectEqual(@as(u16, 0), c.outstanding());

    // Receive across the boundary too.
    _ = try c.onFrame(iframe(32766, 1, "x"), 1);
    _ = try c.onFrame(iframe(32767, 1, "y"), 1);
    _ = try c.onFrame(iframe(0, 1, "z"), 1);
    try testing.expectEqual(@as(Seq, 1), c.recv_seq);
    // And an I-frame beyond it is still out of order.
    try testing.expectError(error.UnexpectedSequence, c.onFrame(iframe(32767, 1, "w"), 1));

    // A client that mishandled the wrap would stall here; this one does not.
    try testing.expect(!c.sendWindowFull());
    _ = try c.prepareI(1);
}

test "w reached forces an immediate supervisory acknowledgement" {
    var c = try started(.controlled, fast); // w = 2
    _ = try c.onFrame(iframe(0, 0, "a"), 0);
    try testing.expectEqual(@as(u16, 1), c.unacked_rx);
    try testing.expectEqual(Action.none, c.tick(0)); // below w, t2 not yet due
    _ = try c.onFrame(iframe(1, 0, "b"), 0);
    try testing.expectEqual(@as(u16, 0), c.nextDeadline().?); // due now
    try testing.expectEqual(Action{ .send_s_frame = 2 }, c.tick(0));
    try testing.expectEqual(@as(u16, 0), c.unacked_rx);
    try testing.expectEqual(@as(Seq, 2), c.last_sent_ack);
    try testing.expectEqual(Action.none, c.tick(0));
}

test "t2 acknowledges when w is never reached" {
    var c = try startedAt(.controlled, no_t3, 100); // w = 2, t2 = 20 ms
    _ = try c.onFrame(iframe(0, 0, "a"), 100);
    try testing.expectEqual(@as(u64, 120), c.t2_deadline.?);
    try testing.expectEqual(Action.none, c.tick(119));
    try testing.expectEqual(Action{ .send_s_frame = 1 }, c.tick(120));
    try testing.expect(c.t2_deadline == null);
    try testing.expectEqual(Action.none, c.tick(200));
}

test "sending an I-frame is itself an acknowledgement, so t2 is cancelled" {
    var c = try startedAt(.controlling, fast, 100);
    _ = try c.onFrame(iframe(0, 0, "a"), 100);
    try testing.expect(c.t2_deadline != null);
    const ctl = try c.prepareI(100);
    try testing.expectEqual(@as(Seq, 1), ctl.i.recv_seq); // carries the ack
    try testing.expect(c.t2_deadline == null);
    try testing.expectEqual(@as(u16, 0), c.unacked_rx);
    // Nothing is owed at 125: t1 (150) and t3 (130) are both still ahead.
    try testing.expectEqual(Action.none, c.tick(125));
}

test "t3 sends a test frame when the link goes quiet" {
    var c = try started(.controlling, fast); // t3 = 30 ms
    try testing.expectEqual(Action.none, c.tick(29));
    try testing.expectEqual(Action{ .send_u = .testfr_act }, c.tick(30));
    try testing.expectEqual(UFunction.testfr_act, c.pending_act.?);
    // The confirmation clears it and restarts t3.
    try testing.expectEqual(Event.test_confirmed, try c.onFrame(.{ .control = .{ .u = .testfr_con }, .asdu = &.{}, .len = 6 }, 35));
    try testing.expect(c.pending_act == null);
    try testing.expectEqual(@as(u64, 65), c.t3_deadline.?);

    // A TESTFR act from the peer is answered.
    try testing.expectEqual(Event.test_requested, try c.onFrame(.{ .control = .{ .u = .testfr_act }, .asdu = &.{}, .len = 6 }, 40));
    try testing.expectEqual(Action{ .send_u = .testfr_con }, c.tick(40));
}

test "t1 expiry on an unacknowledged I-frame closes the connection" {
    var c = try startedAt(.controlling, no_t3, 100); // t1 = 50 ms
    _ = try c.prepareI(100);
    try testing.expectEqual(@as(u64, 150), c.t1_i_deadline.?);
    try testing.expectEqual(Action.none, c.tick(149));
    try testing.expectEqual(Action{ .close = .ack_timeout }, c.tick(150));
}

test "t1 expiry on an unconfirmed U-format act closes the connection" {
    var c = try Connection.init(fast, .controlling);
    c.beginConnect(100);
    c.onTcpConnected(100);
    _ = try c.startDataTransfer(100);
    try testing.expectEqual(Action.none, c.tick(149));
    try testing.expectEqual(Action{ .close = .confirm_timeout }, c.tick(150));
}

test "t0 expiry closes a connection that never came up" {
    var c = try Connection.init(fast, .controlling); // t0 = 100 ms
    c.beginConnect(0);
    try testing.expectEqual(Action.none, c.tick(99));
    try testing.expectEqual(Action{ .close = .connect_timeout }, c.tick(100));
    // A closed connection produces no actions at all.
    c.onTcpClosed();
    try testing.expectEqual(Action.none, c.tick(1_000_000));
    try testing.expect(c.nextDeadline() == null);
}

test "a partial acknowledgement restarts t1 for the frames still in flight" {
    var c = try startedAt(.controlling, no_t3, 100);
    _ = try c.prepareI(100);
    _ = try c.prepareI(101);
    try testing.expectEqual(@as(u64, 150), c.t1_i_deadline.?);
    _ = try c.onFrame(sframe(1), 120);
    try testing.expectEqual(@as(u16, 1), c.outstanding());
    try testing.expectEqual(@as(u64, 170), c.t1_i_deadline.?);
    try testing.expectEqual(Action.none, c.tick(169));
    try testing.expectEqual(Action{ .close = .ack_timeout }, c.tick(170));
}

test "reconnecting resets the sequence numbers to zero" {
    var c = try started(.controlling, fast);
    _ = try c.prepareI(0);
    _ = try c.onFrame(iframe(0, 1, "a"), 0);
    try testing.expect(c.send_seq != 0 or c.recv_seq != 0);
    c.onTcpClosed();
    try testing.expectEqual(State.closed, c.state);
    try testing.expectEqual(@as(Seq, 0), c.send_seq);
    try testing.expectEqual(@as(Seq, 0), c.recv_seq);
    try testing.expectEqual(@as(Seq, 0), c.ack_seq);
    try testing.expectError(error.NotConnected, c.onFrame(sframe(0), 0));
}

test "I-frames are refused in the stopped state, in both directions" {
    var c = try Connection.init(fast, .controlled);
    c.beginConnect(0);
    c.onTcpConnected(0);
    try testing.expectError(error.NotStarted, c.onFrame(iframe(0, 0, "a"), 0));
    try testing.expectError(error.NotStarted, c.prepareI(0));
    // S- and U-format frames are fine while stopped.
    try testing.expectEqual(Event.none, try c.onFrame(sframe(0), 0));
    try testing.expectEqual(Event.test_requested, try c.onFrame(.{ .control = .{ .u = .testfr_act }, .asdu = &.{}, .len = 6 }, 0));
}

test "a full 32768-frame cycle keeps flowing (the wrap is not a stall)" {
    // The failure mode this guards against: a 16-bit or signed comparison
    // makes the connection wedge after 32767 frames. Drive a whole cycle.
    const cfg = Config{ .k = 12, .w = 8, .t0_ms = 30000, .t1_ms = 15000, .t2_ms = 10000, .t3_ms = 20000 };
    var m = try started(.controlling, cfg);
    var o = try started(.controlled, cfg);
    var n: u32 = 0;
    while (n < apci.seq_modulus + 100) : (n += 1) {
        const ctl = try m.prepareI(0);
        const e = try o.onFrame(iframe(ctl.i.send_seq, ctl.i.recv_seq, "p"), 0);
        try testing.expectEqualStrings("p", e.asdu);
        // The outstation acknowledges whenever its state machine says to.
        while (true) {
            switch (o.tick(0)) {
                .send_s_frame => |nr| _ = try m.onFrame(sframe(nr), 0),
                .none => break,
                else => unreachable,
            }
        }
    }
    // Drain the last partial window: the outstation acknowledges on t2.
    switch (o.tick(cfg.t2_ms)) {
        .send_s_frame => |nr| _ = try m.onFrame(sframe(nr), 0),
        else => {},
    }
    try testing.expectEqual(@as(u16, 0), m.outstanding());
    try testing.expectEqual(@as(Seq, @intCast((apci.seq_modulus + 100) % apci.seq_modulus)), m.send_seq);
}

test "nextDeadline reports the earliest armed timer" {
    var c = try started(.controlling, fast);
    // Only t3 is armed after starting.
    try testing.expectEqual(@as(u64, 30), c.nextDeadline().?);
    _ = try c.prepareI(0); // arms t1 at 50
    try testing.expectEqual(@as(u64, 30), c.nextDeadline().?);
    _ = try c.onFrame(iframe(0, 1, "a"), 5); // arms t2 at 25, restarts t3 at 35
    try testing.expectEqual(@as(u64, 25), c.nextDeadline().?);
}
