// SPDX-License-Identifier: MIT

//! The GOOSE **subscriber** as a pure, time-injected state machine.
//!
//! A subscriber's whole job is to turn a stream of unacknowledged multicast
//! frames into typed events, and there are exactly four conditions worth
//! distinguishing — conflating any two of them is how a GOOSE consumer ends up
//! either flapping or silently blind:
//!
//! * **`stNum` jump** — the publisher's data changed. This is the event a
//!   protection scheme acts on.
//! * **`sqNum` gap** — frames were lost. The data is still current (the newest
//!   frame won), but the link is degraded and a burst may have been missed.
//! * **`timeAllowedtoLive` expiry** — nothing arrived within the window the
//!   publisher itself promised. The publisher, its link or the switch is gone,
//!   and whatever the last frame said must stop being trusted.
//! * **`confRev` mismatch** — the publisher's *dataset definition* changed. The
//!   values still decode, but they no longer mean what the subscriber's
//!   configuration says they mean. Treating this as ordinary data is the
//!   dangerous case, because nothing looks wrong.
//!
//! Several of these can be true of one frame (a `confRev` change usually comes
//! with a `stNum` jump), so `onFrame` returns a small **set** of events rather
//! than one.
//!
//! There is no clock and no socket here: `onFrame` and `tick` both take
//! `now_ms`. Every test below runs the whole machine with no network at all.

const std = @import("std");
const goose = @import("goose.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = goose.Error;

pub const Event = union(enum) {
    /// The first frame accepted from this publisher.
    first: struct { st_num: u32, sq_num: u32 },
    /// An in-sequence retransmission; nothing changed.
    refresh,
    /// `stNum` advanced: the data set changed.
    state_change: struct { st_num: u32, previous: u32 },
    /// `sqNum` skipped: frames were lost.
    sequence_gap: struct { expected: u32, got: u32 },
    /// Nothing arrived inside the last advertised `timeAllowedtoLive`.
    tal_expired: struct { last_seen_ms: u64, tal_ms: u32 },
    /// The publisher's dataset revision is not the configured one.
    conf_rev_mismatch: struct { expected: u32, got: u32 },
    /// `stNum` or `sqNum` went backwards — a duplicate, a reordered frame or a
    /// publisher that restarted.
    out_of_order: struct { st_num: u32, sq_num: u32 },
    /// The publisher marked the frame `test`; nothing downstream may act on it.
    test_frame,
    /// The publisher set `ndsCom`: its configuration is incomplete.
    needs_commissioning,
    /// A frame arrived after the subscriber had declared the publisher dead.
    recovered: struct { down_for_ms: u64 },
};

pub const max_events: usize = 6;

/// The events one frame (or one `tick`) produced.
pub const Events = struct {
    items: [max_events]Event = undefined,
    len: u8 = 0,

    pub fn slice(self: *const Events) []const Event {
        return self.items[0..self.len];
    }

    fn push(self: *Events, e: Event) void {
        if (self.len == max_events) return;
        self.items[self.len] = e;
        self.len += 1;
    }

    pub fn has(self: *const Events, comptime name: std.meta.Tag(Event)) bool {
        for (self.slice()) |e| if (e == name) return true;
        return false;
    }
};

pub const Config = struct {
    /// The `gocbRef` this subscriber is bound to. A frame from any other
    /// control block is not this subscriber's business and is rejected.
    gocb_ref: []const u8,
    /// The dataset revision the subscriber was configured against. Null
    /// disables the check (a discovery tool, not a protection scheme).
    expected_conf_rev: ?u32 = null,
    /// A frame whose `test` flag is set is reported but, by default, still
    /// updates the sequence state so a test burst does not later look like
    /// loss. Set false to ignore test frames entirely.
    accept_test_frames: bool = true,
    /// Extra slack added to the publisher's advertised TAL before declaring it
    /// dead, to absorb switch jitter. IEC 61850-5 leaves this to the
    /// implementation; zero is the strict reading.
    tal_slack_ms: u32 = 0,
};

pub const Subscriber = struct {
    config: Config,

    /// Null until the first accepted frame.
    st_num: ?u32 = null,
    sq_num: u32 = 0,
    conf_rev: u32 = 0,
    last_rx_ms: u64 = 0,
    /// The TAL the last accepted frame advertised.
    tal_ms: u32 = 0,
    /// False once TAL has expired, until a frame arrives again.
    alive: bool = false,
    /// Counters a diagnostic caller wants.
    frames: u64 = 0,
    losses: u64 = 0,
    state_changes: u64 = 0,

    pub fn init(config: Config) Subscriber {
        return .{ .config = config };
    }

    /// Does this frame belong to this subscriber?
    pub fn matches(self: *const Subscriber, pdu: goose.Pdu) bool {
        return std.mem.eql(u8, pdu.gocb_ref, self.config.gocb_ref);
    }

    /// Feeds one decoded GOOSE PDU. Returns every condition it implies.
    ///
    /// The frame is applied to the sequence state **after** the events are
    /// derived, so a caller sees "expected 4, got 7" rather than a state that
    /// has already absorbed the gap.
    pub fn onFrame(self: *Subscriber, pdu: goose.Pdu, now_ms: u64) Events {
        var ev = Events{};
        if (pdu.test_mode) {
            ev.push(.test_frame);
            if (!self.config.accept_test_frames) return ev;
        }
        if (pdu.nds_com) ev.push(.needs_commissioning);

        if (self.config.expected_conf_rev) |want| {
            if (pdu.conf_rev != want) {
                ev.push(.{ .conf_rev_mismatch = .{ .expected = want, .got = pdu.conf_rev } });
            }
        }

        if (self.st_num) |prev_st| {
            if (!self.alive) {
                ev.push(.{ .recovered = .{ .down_for_ms = now_ms -| self.last_rx_ms } });
            }
            if (pdu.st_num > prev_st) {
                ev.push(.{ .state_change = .{ .st_num = pdu.st_num, .previous = prev_st } });
                self.state_changes += 1;
                // A state change resets sqNum, so no gap is implied even though
                // the number went backwards.
            } else if (pdu.st_num < prev_st) {
                ev.push(.{ .out_of_order = .{ .st_num = pdu.st_num, .sq_num = pdu.sq_num } });
            } else {
                // Same stNum: sqNum must be exactly one more.
                const expected = self.sq_num +% 1;
                if (pdu.sq_num == expected) {
                    ev.push(.refresh);
                } else if (seqAfter(pdu.sq_num, expected)) {
                    ev.push(.{ .sequence_gap = .{ .expected = expected, .got = pdu.sq_num } });
                    self.losses += 1;
                } else {
                    ev.push(.{ .out_of_order = .{ .st_num = pdu.st_num, .sq_num = pdu.sq_num } });
                    // A duplicate or reordered frame must not rewind the state.
                    self.frames += 1;
                    self.last_rx_ms = now_ms;
                    self.tal_ms = pdu.time_allowed_to_live_ms;
                    self.alive = true;
                    return ev;
                }
            }
        } else {
            ev.push(.{ .first = .{ .st_num = pdu.st_num, .sq_num = pdu.sq_num } });
        }

        self.st_num = pdu.st_num;
        self.sq_num = pdu.sq_num;
        self.conf_rev = pdu.conf_rev;
        self.last_rx_ms = now_ms;
        self.tal_ms = pdu.time_allowed_to_live_ms;
        self.alive = true;
        self.frames += 1;
        return ev;
    }

    /// Checks liveness. Returns `tal_expired` exactly once per outage.
    pub fn tick(self: *Subscriber, now_ms: u64) ?Event {
        if (!self.alive) return null;
        if (self.st_num == null) return null;
        const window = @as(u64, self.tal_ms) + self.config.tal_slack_ms;
        if (now_ms -| self.last_rx_ms <= window) return null;
        self.alive = false;
        return .{ .tal_expired = .{ .last_seen_ms = self.last_rx_ms, .tal_ms = self.tal_ms } };
    }

    /// When liveness must next be checked, or null when nothing is armed.
    pub fn nextDeadline(self: *const Subscriber) ?u64 {
        if (!self.alive or self.st_num == null) return null;
        return self.last_rx_ms + self.tal_ms + self.config.tal_slack_ms + 1;
    }

    /// Whether the last accepted data may still be acted on.
    pub fn dataUsable(self: *const Subscriber) bool {
        return self.alive and self.st_num != null;
    }
};

/// `a` is after `b` in a wrapping 32-bit sequence space. `sqNum` is a `u32`
/// that a fast publisher genuinely wraps (at 1 kHz it takes 50 days, at 4 ms
/// bursts far less), so ordinal comparison is not enough.
fn seqAfter(a: u32, b: u32) bool {
    return a != b and (a -% b) < (1 << 31);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const publisher = @import("publisher.zig");
const ber = @import("ber.zig");

const gocb = "TESTLD/LLN0$GO$gcbTest";

fn makePdu(st: u32, sq: u32, conf_rev: u32, tal: u32) goose.Pdu {
    return .{
        .gocb_ref = gocb,
        .time_allowed_to_live_ms = tal,
        .dat_set = "TESTLD/LLN0$dsTest",
        .go_id = gocb,
        .t = mmsdata.UtcTime.fromMillis(0, 10),
        .st_num = st,
        .sq_num = sq,
        .test_mode = false,
        .conf_rev = conf_rev,
        .nds_com = false,
        .num_dat_set_entries = 0,
        .all_data = &.{},
    };
}

test "the first frame is reported as first, then refreshes" {
    var s = Subscriber.init(.{ .gocb_ref = gocb, .expected_conf_rev = 3 });
    var ev = s.onFrame(makePdu(1, 0, 3, 2000), 1000);
    try testing.expectEqual(@as(usize, 1), ev.slice().len);
    try testing.expectEqual(@as(u32, 1), ev.slice()[0].first.st_num);
    try testing.expect(s.dataUsable());

    ev = s.onFrame(makePdu(1, 1, 3, 2000), 3000);
    try testing.expect(ev.has(.refresh));
    ev = s.onFrame(makePdu(1, 2, 3, 2000), 5000);
    try testing.expect(ev.has(.refresh));
    try testing.expectEqual(@as(u64, 0), s.losses);
}

test "a stNum jump is a state change and resets the sequence expectation" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, 5, 1, 2000), 0);
    const ev = s.onFrame(makePdu(2, 0, 1, 10), 100);
    try testing.expect(ev.has(.state_change));
    try testing.expectEqual(@as(u32, 1), ev.slice()[0].state_change.previous);
    try testing.expectEqual(@as(u32, 2), ev.slice()[0].state_change.st_num);
    // sqNum went 5 -> 0 but that is not a gap.
    try testing.expect(!ev.has(.sequence_gap));
    try testing.expectEqual(@as(u64, 0), s.losses);
    // And the next in-sequence frame is an ordinary refresh.
    try testing.expect(s.onFrame(makePdu(2, 1, 1, 10), 110).has(.refresh));
}

test "an sqNum gap is reported as loss without discarding the newer frame" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, 0, 1, 2000), 0);
    _ = s.onFrame(makePdu(1, 1, 1, 2000), 10);
    const ev = s.onFrame(makePdu(1, 5, 1, 2000), 20);
    try testing.expect(ev.has(.sequence_gap));
    try testing.expectEqual(@as(u32, 2), ev.slice()[0].sequence_gap.expected);
    try testing.expectEqual(@as(u32, 5), ev.slice()[0].sequence_gap.got);
    try testing.expectEqual(@as(u64, 1), s.losses);
    // The newer frame won: the next expected number follows it.
    try testing.expect(s.onFrame(makePdu(1, 6, 1, 2000), 30).has(.refresh));
}

test "a duplicate or reordered frame does not rewind the state" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, 0, 1, 2000), 0);
    _ = s.onFrame(makePdu(1, 1, 1, 2000), 10);
    _ = s.onFrame(makePdu(1, 2, 1, 2000), 20);
    const dup = s.onFrame(makePdu(1, 1, 1, 2000), 25);
    try testing.expect(dup.has(.out_of_order));
    try testing.expectEqual(@as(u32, 2), s.sq_num);
    // A publisher that restarted with a lower stNum is also out of order.
    const restart = s.onFrame(makePdu(0, 0, 1, 2000), 30);
    try testing.expect(restart.has(.out_of_order));
}

test "TAL expiry fires exactly once and clears data usability" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, 0, 1, 500), 1000);
    try testing.expect(s.tick(1400) == null);
    try testing.expect(s.tick(1500) == null); // exactly at the window: still alive
    const ev = s.tick(1501).?;
    try testing.expectEqual(@as(u32, 500), ev.tal_expired.tal_ms);
    try testing.expectEqual(@as(u64, 1000), ev.tal_expired.last_seen_ms);
    try testing.expect(!s.dataUsable());
    // And it does not fire again for the same outage.
    try testing.expect(s.tick(9000) == null);
    try testing.expect(s.nextDeadline() == null);
}

test "a frame after an outage reports recovery" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, 0, 1, 500), 1000);
    _ = s.tick(2000);
    try testing.expect(!s.alive);
    const ev = s.onFrame(makePdu(1, 1, 1, 500), 5000);
    try testing.expect(ev.has(.recovered));
    try testing.expectEqual(@as(u64, 4000), ev.slice()[0].recovered.down_for_ms);
    try testing.expect(s.dataUsable());
}

test "TAL slack absorbs jitter without hiding a real outage" {
    var s = Subscriber.init(.{ .gocb_ref = gocb, .tal_slack_ms = 200 });
    _ = s.onFrame(makePdu(1, 0, 1, 500), 0);
    try testing.expect(s.tick(700) == null);
    try testing.expect(s.tick(701) != null);
}

test "a confRev mismatch is reported alongside whatever else the frame implies" {
    var s = Subscriber.init(.{ .gocb_ref = gocb, .expected_conf_rev = 3 });
    var ev = s.onFrame(makePdu(1, 0, 3, 2000), 0);
    try testing.expect(!ev.has(.conf_rev_mismatch));
    // The publisher's dataset was re-engineered.
    ev = s.onFrame(makePdu(2, 0, 4, 2000), 10);
    try testing.expect(ev.has(.conf_rev_mismatch));
    try testing.expect(ev.has(.state_change));
    try testing.expectEqual(@as(u32, 3), ev.slice()[0].conf_rev_mismatch.expected);
    try testing.expectEqual(@as(u32, 4), ev.slice()[0].conf_rev_mismatch.got);
    // With no configured revision the check is off.
    var s2 = Subscriber.init(.{ .gocb_ref = gocb });
    try testing.expect(!s2.onFrame(makePdu(1, 0, 99, 2000), 0).has(.conf_rev_mismatch));
}

test "a test frame is flagged, and can be ignored entirely" {
    var pdu = makePdu(1, 0, 1, 2000);
    pdu.test_mode = true;
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    try testing.expect(s.onFrame(pdu, 0).has(.test_frame));
    try testing.expect(s.st_num != null);

    var strict = Subscriber.init(.{ .gocb_ref = gocb, .accept_test_frames = false });
    const ev = strict.onFrame(pdu, 0);
    try testing.expect(ev.has(.test_frame));
    try testing.expectEqual(@as(usize, 1), ev.slice().len);
    try testing.expect(strict.st_num == null);
    try testing.expect(!strict.dataUsable());
}

test "ndsCom is surfaced" {
    var pdu = makePdu(1, 0, 1, 2000);
    pdu.nds_com = true;
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    try testing.expect(s.onFrame(pdu, 0).has(.needs_commissioning));
}

test "a frame from a different control block is not this subscriber's" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    var other = makePdu(1, 0, 1, 2000);
    other.gocb_ref = "OTHERLD/LLN0$GO$gcbX";
    try testing.expect(!s.matches(other));
    try testing.expect(s.matches(makePdu(1, 0, 1, 2000)));
}

test "sqNum wrapping is not mistaken for a gap" {
    var s = Subscriber.init(.{ .gocb_ref = gocb });
    _ = s.onFrame(makePdu(1, std.math.maxInt(u32) - 1, 1, 2000), 0);
    try testing.expect(s.onFrame(makePdu(1, std.math.maxInt(u32), 1, 2000), 10).has(.refresh));
    try testing.expect(s.onFrame(makePdu(1, 0, 1, 2000), 20).has(.refresh));
    try testing.expect(s.onFrame(makePdu(1, 1, 1, 2000), 30).has(.refresh));
    try testing.expectEqual(@as(u64, 0), s.losses);
}

test "publisher and subscriber run a whole event over an in-memory wire" {
    var vbuf: [16]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.boolean(&vw, false);
    const val = vw.done();

    var pub_ = try publisher.Publisher.init(.{
        .gocb_ref = gocb,
        .dat_set = "TESTLD/LLN0$dsTest",
        .conf_rev = 3,
        .vlan = null,
    }, .{});
    var sub = Subscriber.init(.{ .gocb_ref = gocb, .expected_conf_rev = 3 });

    var out: [1024]u8 = undefined;
    var now: u64 = 0;
    pub_.start(now);

    // Steady state for a while.
    var i: usize = 0;
    var state_changes: usize = 0;
    var gaps: usize = 0;
    var drop_next = false;
    while (i < 30) : (i += 1) {
        now = pub_.nextDeadline().?;
        const frame = (try pub_.tick(now, &[_][]const u8{val}, &out)).?;
        // Drop one frame to prove the gap detector sees it.
        if (drop_next) {
            drop_next = false;
            continue;
        }
        const f = try goose.Frame.decode(frame);
        const pdu = try goose.Pdu.decode(f.pdu);
        try testing.expect(sub.matches(pdu));
        const ev = sub.onFrame(pdu, now);
        if (ev.has(.state_change)) state_changes += 1;
        if (ev.has(.sequence_gap)) gaps += 1;
        // TAL must always be ahead of the next transmission, so a subscriber
        // polled right before the next frame never declares the publisher dead.
        try testing.expect(sub.tick(pub_.nextDeadline().?) == null);
        if (i == 10) drop_next = true;
        if (i == 20) pub_.stateChange(now + 1);
    }
    try testing.expectEqual(@as(usize, 1), state_changes);
    try testing.expectEqual(@as(usize, 1), gaps);
    try testing.expectEqual(@as(u64, 1), sub.losses);

    // The publisher stops; the subscriber notices within TAL.
    const last = now;
    try testing.expect(sub.tick(last + sub.tal_ms) == null);
    try testing.expect(sub.tick(last + sub.tal_ms + 1) != null);
    try testing.expect(!sub.dataUsable());
}
