// SPDX-License-Identifier: MIT
//! dnp3.link_session — the data-link layer's confirmed-delivery services
//! (IEEE 1815-2012 §9.2.6 / §9.3, the two-state frame-count-bit scheme of
//! IEC 60870-5-2): `Secondary`, which decides what a station does with each
//! primary-station frame it receives, and `Primary`, the stop-and-wait sender
//! of RESET_LINK_STATES and CONFIRMED_USER_DATA with retries. Both are pure
//! state machines over `link.Control`: no I/O, no allocation, no timers (the
//! caller injects `now_ms` and calls `poll`). The outstation `Session` and the
//! `master` use the same pair, so each side's duplicate suppression and
//! retransmission are the same code.
//!
//! The frame-count bit works like this. After RESET_LINK_STATES (answered ACK)
//! the secondary expects FCB = 1; each CONFIRMED_USER_DATA with FCV = 1 and the
//! expected FCB is delivered, ACKed and flips the expectation; one with the
//! other FCB is a retransmission of a frame already delivered (the ACK was
//! lost) and is ACKed again without being delivered a second time. A confirmed
//! frame before any reset, or without FCV, is answered NACK.
//! Unconfirmed user data is delivered with no reply.

const std = @import("std");
const link = @import("link.zig");

/// What a secondary station does with one primary-station frame.
pub const Verdict = enum {
    /// Nothing to answer, nothing to deliver (a function this layer does not own).
    none,
    /// Deliver the user data; send no link reply (unconfirmed user data).
    deliver,
    /// Deliver the user data and answer ACK.
    ack_deliver,
    /// Answer ACK; the user data is a duplicate (or there is none): do not deliver.
    ack_discard,
    /// Answer NACK (link not reset, or a confirmed frame without FCV).
    nack,
};

/// Receive side: one per association.
pub const Secondary = struct {
    /// A RESET_LINK_STATES has been accepted.
    reset: bool = false,
    /// The FCB the next new confirmed frame must carry.
    expected_fcb: bool = true,

    /// `c` is the control octet of a frame with `prm = true`.
    pub fn onPrimary(self: *Secondary, c: link.Control) Verdict {
        switch (c.primaryFunction()) {
            .reset_link_states => {
                self.reset = true;
                self.expected_fcb = true;
                return .ack_discard;
            },
            .test_link_states => {
                if (!self.reset or !c.fcv_or_dfc) return .nack;
                if (c.fcb != self.expected_fcb) return .ack_discard;
                self.expected_fcb = !self.expected_fcb;
                return .ack_discard;
            },
            .confirmed_user_data => {
                if (!self.reset or !c.fcv_or_dfc) return .nack;
                if (c.fcb != self.expected_fcb) return .ack_discard;
                self.expected_fcb = !self.expected_fcb;
                return .ack_deliver;
            },
            .unconfirmed_user_data => return .deliver,
            .request_link_status => return .none,
            _ => return .none,
        }
    }
};

pub const PrimaryConfig = struct {
    /// How long to wait for the ACK of a RESET_LINK_STATES or a confirmed data
    /// frame before retransmitting (opendnp3 `LinkConfig.Timeout`, default 1 s).
    response_timeout_ms: u32 = 1000,
    /// Retransmissions after the first attempt before the link is given up
    /// (opendnp3 `NumRetry`, default 0; 3 here, the usual SCADA setting).
    retries: u8 = 3,
};

/// What the caller does next.
pub const Action = enum {
    /// Nothing.
    none,
    /// Send RESET_LINK_STATES (`resetControl`).
    send_reset,
    /// Send the frame as CONFIRMED_USER_DATA (`dataControl`), first attempt.
    send_data,
    /// Send the same RESET_LINK_STATES again.
    retransmit_reset,
    /// Send the same CONFIRMED_USER_DATA again (same FCB).
    retransmit_data,
    /// The frame was ACKed: the next one may start.
    acked,
    /// Retries exhausted or the secondary refused: the link is un-reset, the
    /// frame was not delivered.
    failed,
};

/// Send side: stop-and-wait, one frame outstanding.
pub const Primary = struct {
    cfg: PrimaryConfig = .{},
    /// DIR bit of every frame we send: true for a master, false for an outstation.
    dir: bool,
    reset: bool = false,
    fcb: bool = true,
    phase: Phase = .idle,
    deadline_ms: u64 = 0,
    attempts: u8 = 0,

    pub const Phase = enum { idle, wait_reset_ack, wait_data_ack };

    pub fn init(dir: bool, cfg: PrimaryConfig) Primary {
        return .{ .dir = dir, .cfg = cfg };
    }

    pub fn resetControl(self: *const Primary) link.Control {
        return .{ .dir = self.dir, .prm = true, .fcb = false, .fcv_or_dfc = false, .function = @backingInt(link.PrimaryFunction.reset_link_states) };
    }

    pub fn dataControl(self: *const Primary) link.Control {
        return .{ .dir = self.dir, .prm = true, .fcb = self.fcb, .fcv_or_dfc = true, .function = @backingInt(link.PrimaryFunction.confirmed_user_data) };
    }

    /// Begin delivering one frame (precondition: nothing outstanding; an
    /// outstanding one is abandoned). `send_reset` first when the link is not
    /// reset, then `onSecondary` returns `send_data` once the reset is ACKed.
    pub fn start(self: *Primary, now_ms: u64) Action {
        self.attempts = 0;
        self.deadline_ms = now_ms + self.cfg.response_timeout_ms;
        if (!self.reset) {
            self.phase = .wait_reset_ack;
            return .send_reset;
        }
        self.phase = .wait_data_ack;
        return .send_data;
    }

    /// A secondary-station frame (`prm = false`) arrived.
    pub fn onSecondary(self: *Primary, c: link.Control, now_ms: u64) Action {
        const f = c.secondaryFunction();
        switch (self.phase) {
            .idle => return .none,
            .wait_reset_ack => switch (f) {
                .ack => {
                    self.reset = true;
                    self.fcb = true;
                    self.phase = .wait_data_ack;
                    self.attempts = 0;
                    self.deadline_ms = now_ms + self.cfg.response_timeout_ms;
                    return .send_data;
                },
                .nack => return self.fail(),
                else => return .none,
            },
            .wait_data_ack => switch (f) {
                .ack => {
                    self.fcb = !self.fcb;
                    self.phase = .idle;
                    return .acked;
                },
                .nack => return self.fail(),
                else => return .none,
            },
        }
    }

    /// Retransmit on timeout; give up after `retries`.
    pub fn poll(self: *Primary, now_ms: u64) Action {
        if (self.phase == .idle or now_ms < self.deadline_ms) return .none;
        if (self.attempts >= self.cfg.retries) return self.fail();
        self.attempts += 1;
        self.deadline_ms = now_ms + self.cfg.response_timeout_ms;
        return if (self.phase == .wait_reset_ack) .retransmit_reset else .retransmit_data;
    }

    /// When `poll` next has something to do, or null when idle.
    pub fn nextDeadline(self: *const Primary) ?u64 {
        return if (self.phase == .idle) null else self.deadline_ms;
    }

    fn fail(self: *Primary) Action {
        self.phase = .idle;
        self.reset = false;
        return .failed;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn pc(f: link.PrimaryFunction, fcb: bool, fcv: bool) link.Control {
    return .{ .dir = true, .prm = true, .fcb = fcb, .fcv_or_dfc = fcv, .function = @backingInt(f) };
}

fn sc(f: link.SecondaryFunction) link.Control {
    return .{ .dir = false, .prm = false, .function = @backingInt(f) };
}

test "secondary: reset, then alternating FCB delivers once each; a repeated FCB is ACKed and not delivered again" {
    var s: Secondary = .{};
    try testing.expectEqual(Verdict.ack_discard, s.onPrimary(pc(.reset_link_states, false, false)));
    try testing.expectEqual(Verdict.ack_deliver, s.onPrimary(pc(.confirmed_user_data, true, true)));
    // The ACK was lost: the primary repeats FCB=1. Acknowledge, do not deliver.
    try testing.expectEqual(Verdict.ack_discard, s.onPrimary(pc(.confirmed_user_data, true, true)));
    try testing.expectEqual(Verdict.ack_deliver, s.onPrimary(pc(.confirmed_user_data, false, true)));
    try testing.expectEqual(Verdict.ack_deliver, s.onPrimary(pc(.confirmed_user_data, true, true)));
    try testing.expectEqual(Verdict.ack_discard, s.onPrimary(pc(.confirmed_user_data, true, true)));
}

test "secondary: confirmed data before a reset, or without FCV, is NACKed; unconfirmed is delivered; a reset restarts the count" {
    var s: Secondary = .{};
    try testing.expectEqual(Verdict.nack, s.onPrimary(pc(.confirmed_user_data, true, true)));
    try testing.expectEqual(Verdict.nack, s.onPrimary(pc(.test_link_states, true, true)));
    try testing.expectEqual(Verdict.deliver, s.onPrimary(pc(.unconfirmed_user_data, false, false)));
    _ = s.onPrimary(pc(.reset_link_states, false, false));
    try testing.expectEqual(Verdict.nack, s.onPrimary(pc(.confirmed_user_data, true, false)));
    try testing.expectEqual(Verdict.ack_deliver, s.onPrimary(pc(.confirmed_user_data, true, true)));
    // A second reset puts the expectation back to FCB=1.
    _ = s.onPrimary(pc(.reset_link_states, false, false));
    try testing.expectEqual(Verdict.ack_deliver, s.onPrimary(pc(.confirmed_user_data, true, true)));
    // TEST_LINK_STATES follows the same count.
    try testing.expectEqual(Verdict.ack_discard, s.onPrimary(pc(.test_link_states, false, true)));
    try testing.expectEqual(Verdict.ack_discard, s.onPrimary(pc(.test_link_states, false, true)));
    try testing.expectEqual(Verdict.none, s.onPrimary(pc(.request_link_status, false, false)));
}

test "primary: reset first, data after the ACK, FCB toggles per delivered frame" {
    var p = Primary.init(true, .{ .response_timeout_ms = 100, .retries = 2 });
    try testing.expectEqual(Action.send_reset, p.start(0));
    try testing.expectEqual(false, p.resetControl().fcv_or_dfc);
    try testing.expectEqual(Action.send_data, p.onSecondary(sc(.ack), 10));
    try testing.expect(p.dataControl().fcb and p.dataControl().fcv_or_dfc);
    try testing.expectEqual(Action.acked, p.onSecondary(sc(.ack), 20));
    // Next frame: no reset again, FCB flipped.
    try testing.expectEqual(Action.send_data, p.start(30));
    try testing.expect(!p.dataControl().fcb);
    try testing.expectEqual(Action.acked, p.onSecondary(sc(.ack), 31));
    try testing.expectEqual(Action.send_data, p.start(40));
    try testing.expect(p.dataControl().fcb);
    try testing.expectEqual(Action.none, p.onSecondary(sc(.link_status), 41));
}

test "primary: timeout retransmits the same frame (same FCB), then gives up and un-resets" {
    var p = Primary.init(false, .{ .response_timeout_ms = 100, .retries = 2 });
    _ = p.start(0);
    _ = p.onSecondary(sc(.ack), 1); // reset acked, data out at t=1, deadline 101
    try testing.expectEqual(Action.none, p.poll(100));
    try testing.expectEqual(@as(?u64, 101), p.nextDeadline());
    const fcb = p.dataControl().fcb;
    try testing.expectEqual(Action.retransmit_data, p.poll(101));
    try testing.expectEqual(fcb, p.dataControl().fcb);
    try testing.expectEqual(Action.retransmit_data, p.poll(202));
    try testing.expectEqual(Action.failed, p.poll(303));
    try testing.expectEqual(@as(?u64, null), p.nextDeadline());
    try testing.expect(!p.dataControl().dir);
    // The link is un-reset: the next start resets again.
    try testing.expectEqual(Action.send_reset, p.start(400));
    try testing.expectEqual(Action.retransmit_reset, p.poll(500));
}

test "primary: a NACK fails the frame and forces a reset next time; ACK while idle is ignored" {
    var p = Primary.init(true, .{});
    try testing.expectEqual(Action.none, p.onSecondary(sc(.ack), 0));
    _ = p.start(0);
    _ = p.onSecondary(sc(.ack), 0);
    try testing.expectEqual(Action.failed, p.onSecondary(sc(.nack), 1));
    try testing.expectEqual(Action.send_reset, p.start(2));
    try testing.expectEqual(Action.failed, p.onSecondary(sc(.nack), 3));
}
