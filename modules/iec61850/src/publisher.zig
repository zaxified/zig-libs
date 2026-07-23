// SPDX-License-Identifier: MIT

//! The GOOSE **publisher** as a pure, time-injected state machine.
//!
//! GOOSE has no acknowledgement and no retransmission request, so reliability
//! is bought entirely with repetition. IEC 61850-5 §13.7.6 describes the
//! pattern every implementation follows:
//!
//! * in steady state the publisher repeats the same frame at a slow
//!   **heartbeat** (typically 1–5 s), incrementing `sqNum` each time;
//! * on a **state change** it increments `stNum`, resets `sqNum` to 0 and
//!   re-sends immediately, then again after a very short interval, then at a
//!   **backoff ladder** of growing intervals until the heartbeat is reached
//!   again — so a change is delivered several times within a few milliseconds
//!   even across a lossy link;
//! * **`timeAllowedtoLive` must always exceed the next expected
//!   retransmission**, because a subscriber treats its expiry as "the publisher
//!   is gone". Deriving TAL from the ladder rather than fixing it is the whole
//!   point: a constant TAL is either too short during the fast burst (spurious
//!   failure reports) or too long in steady state (a dead publisher goes
//!   unnoticed for seconds).
//!
//! There is **no clock and no thread here**. The caller passes `now_ms` into
//! every entry point and performs the I/O `tick` returns; `nextDeadline` says
//! when to come back. That is what makes the whole thing testable with no
//! network at all — which is exactly what the tests below do.

const std = @import("std");
const ber = @import("ber.zig");
const goose = @import("goose.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = goose.Error || error{
    /// `tick` was called before `start`.
    NotStarted,
    /// The ladder is empty, or an interval is zero (which would busy-loop).
    BadProfile,
};

/// The retransmission ladder. Entry `i` is the delay from transmission `i` to
/// transmission `i + 1`; the **last entry repeats forever** and is therefore
/// the steady-state heartbeat.
pub const Profile = struct {
    ladder: []const u32 = &default_ladder,
    /// `timeAllowedtoLive = tal_multiplier * next_interval`. Two is the common
    /// choice: it tolerates exactly one lost frame before a subscriber declares
    /// the publisher dead.
    tal_multiplier: u32 = 2,
    /// Floor for TAL, so the first few millisecond-scale steps do not produce a
    /// TAL a subscriber cannot realistically meet.
    min_tal_ms: u32 = 10,
    /// Ceiling for TAL; a `u32` field on the wire, but keep it sane.
    max_tal_ms: u32 = 60_000,

    pub fn validate(self: Profile) Error!void {
        if (self.ladder.len == 0) return error.BadProfile;
        for (self.ladder) |v| if (v == 0) return error.BadProfile;
    }

    /// The interval that follows transmission number `step`.
    pub fn interval(self: Profile, step: usize) u32 {
        return self.ladder[@min(step, self.ladder.len - 1)];
    }

    /// TAL to advertise on the transmission at `step`.
    pub fn tal(self: Profile, step: usize) u32 {
        const next = self.interval(step);
        const v = @as(u64, next) * self.tal_multiplier;
        return @intCast(std.math.clamp(v, self.min_tal_ms, self.max_tal_ms));
    }
};

/// 4 ms up to a 1 s heartbeat — the shape libiec61850 and every vendor stack
/// use, and the one whose first three steps land inside a protection-class
/// budget.
pub const default_ladder = [_]u32{ 4, 8, 16, 32, 64, 128, 256, 512, 1000 };

pub const Config = struct {
    /// `gocbRef`, e.g. `"LD/LLN0$GO$gcbEvents"`.
    gocb_ref: []const u8,
    /// `datSet`, e.g. `"LD/LLN0$Events"`.
    dat_set: []const u8,
    /// `goID`. Defaults to `gocb_ref` when empty.
    go_id: []const u8 = &.{},
    conf_rev: u32 = 1,
    /// A test publisher's frames must not operate anything downstream.
    test_mode: bool = false,
    /// "Needs commissioning".
    nds_com: bool = false,

    dst: [6]u8 = .{ 0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01 },
    src: [6]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    appid: u16 = 0x0001,
    vlan: ?goose.Vlan = .{ .priority = 4, .id = 0 },
    /// Quality reported in the `t` field.
    time_accuracy: ?u5 = 10,
};

pub const Publisher = struct {
    config: Config,
    profile: Profile = .{},

    st_num: u32 = 1,
    sq_num: u32 = 0,
    /// Index into the ladder: how many transmissions since the last state
    /// change.
    step: usize = 0,
    next_due_ms: u64 = 0,
    started: bool = false,
    /// Timestamp put in `t`: the instant of the last **state change**, not of
    /// the transmission. A retransmission carries the original event time,
    /// which is what makes `t` usable as an event timestamp.
    event_time_ms: u64 = 0,

    pub fn init(config: Config, profile: Profile) Error!Publisher {
        try profile.validate();
        return .{ .config = config, .profile = profile };
    }

    /// Arms the first transmission, due immediately.
    pub fn start(self: *Publisher, now_ms: u64) void {
        self.started = true;
        self.st_num = 1;
        self.sq_num = 0;
        self.step = 0;
        self.next_due_ms = now_ms;
        self.event_time_ms = now_ms;
    }

    /// A value in the data set changed: bump `stNum`, reset `sqNum`, restart
    /// the ladder and make the next transmission due immediately.
    pub fn stateChange(self: *Publisher, now_ms: u64) void {
        self.st_num +%= 1;
        if (self.st_num == 0) self.st_num = 1; // stNum 0 is reserved
        self.sq_num = 0;
        self.step = 0;
        self.next_due_ms = now_ms;
        self.event_time_ms = now_ms;
    }

    pub fn due(self: *const Publisher, now_ms: u64) bool {
        return self.started and now_ms >= self.next_due_ms;
    }

    pub fn nextDeadline(self: *const Publisher) ?u64 {
        return if (self.started) self.next_due_ms else null;
    }

    /// The TAL the *next* frame will advertise.
    pub fn timeAllowedToLive(self: *const Publisher) u32 {
        return self.profile.tal(self.step);
    }

    /// Emits the next frame if one is due, else null. **Mutating**: on success
    /// the transmission has already been accounted for (`sqNum` advanced, the
    /// ladder stepped, the next deadline armed), so the caller must actually
    /// send what it gets back.
    pub fn tick(
        self: *Publisher,
        now_ms: u64,
        data_values: []const []const u8,
        out: []u8,
    ) Error!?[]const u8 {
        if (!self.started) return error.NotStarted;
        if (now_ms < self.next_due_ms) return null;
        const frame = try self.build(data_values, out);
        // Schedule from the deadline, not from `now`, so a late caller does not
        // drift the whole ladder.
        self.next_due_ms = self.next_due_ms + self.profile.interval(self.step);
        // A caller that was very late must not then burst: never schedule into
        // the past.
        if (self.next_due_ms <= now_ms) self.next_due_ms = now_ms + self.profile.interval(self.step);
        self.step += 1;
        self.sq_num +%= 1;
        return frame;
    }

    /// Builds the current frame without advancing anything — for a caller that
    /// wants to inspect or re-send the last frame.
    pub fn build(self: *const Publisher, data_values: []const []const u8, out: []u8) Error![]const u8 {
        const pdu_out = out[out.len / 2 ..];
        const pdu = try (goose.Pdu{
            .gocb_ref = self.config.gocb_ref,
            .time_allowed_to_live_ms = self.profile.tal(self.step),
            .dat_set = self.config.dat_set,
            .go_id = if (self.config.go_id.len == 0) self.config.gocb_ref else self.config.go_id,
            .t = mmsdata.UtcTime.fromMillis(self.event_time_ms, self.config.time_accuracy),
            .st_num = self.st_num,
            .sq_num = self.sq_num,
            .test_mode = self.config.test_mode,
            .conf_rev = self.config.conf_rev,
            .nds_com = self.config.nds_com,
            .num_dat_set_entries = @intCast(data_values.len),
            .all_data = &.{},
        }).encode(data_values, pdu_out);
        const frame = goose.Frame{
            .dst = self.config.dst,
            .src = self.config.src,
            .vlan = self.config.vlan,
            .appid = self.config.appid,
            .pdu = &.{},
            .total_len = 0,
        };
        return frame.encode(pdu, out[0 .. out.len / 2]);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn oneBoolean(v: bool, buf: []u8) ![]const u8 {
    var w = ber.Writer.init(buf);
    try mmsdata.Emit.boolean(&w, v);
    return w.done();
}

fn testConfig() Config {
    return .{
        .gocb_ref = "TESTLD/LLN0$GO$gcbTest",
        .dat_set = "TESTLD/LLN0$dsTest",
        .conf_rev = 3,
        .src = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .appid = 0x1000,
        .vlan = null,
    };
}

test "the ladder runs from the fast burst up to the heartbeat and stays there" {
    var vbuf: [16]u8 = undefined;
    const val = try oneBoolean(true, &vbuf);
    var p = try Publisher.init(testConfig(), .{});
    p.start(1000);

    var out: [1024]u8 = undefined;
    var now: u64 = 1000;
    var sent: usize = 0;
    var intervals: [12]u64 = undefined;
    var last: u64 = 0;
    while (sent < 12) {
        if (p.due(now)) {
            _ = (try p.tick(now, &[_][]const u8{val}, &out)).?;
            if (sent > 0) intervals[sent] = now - last;
            last = now;
            sent += 1;
        } else {
            now = p.nextDeadline().?;
        }
    }
    // 4, 8, 16, 32, 64, 128, 256, 512, then 1000 forever.
    try testing.expectEqualSlices(
        u64,
        &[_]u64{ 4, 8, 16, 32, 64, 128, 256, 512, 1000, 1000, 1000 },
        intervals[1..12],
    );
}

test "a state change bumps stNum, resets sqNum and restarts the ladder" {
    var vbuf: [16]u8 = undefined;
    const val = try oneBoolean(true, &vbuf);
    var p = try Publisher.init(testConfig(), .{});
    p.start(0);
    var out: [1024]u8 = undefined;

    // Run out to the heartbeat.
    var now: u64 = 0;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        now = p.nextDeadline().?;
        _ = (try p.tick(now, &[_][]const u8{val}, &out)).?;
    }
    var f = try goose.Frame.decode((try p.build(&[_][]const u8{val}, &out)));
    var pdu = try goose.Pdu.decode(f.pdu);
    try testing.expectEqual(@as(u32, 1), pdu.st_num);
    try testing.expectEqual(@as(u32, 10), pdu.sq_num);
    try testing.expectEqual(@as(u32, 2000), pdu.time_allowed_to_live_ms); // heartbeat * 2

    // A state change: due immediately, sqNum 0, stNum 2, TAL back to the floor.
    p.stateChange(now + 5);
    try testing.expect(p.due(now + 5));
    const frame = (try p.tick(now + 5, &[_][]const u8{val}, &out)).?;
    f = try goose.Frame.decode(frame);
    pdu = try goose.Pdu.decode(f.pdu);
    try testing.expectEqual(@as(u32, 2), pdu.st_num);
    try testing.expectEqual(@as(u32, 0), pdu.sq_num);
    try testing.expectEqual(@as(u32, 10), pdu.time_allowed_to_live_ms); // min_tal_ms floor
    try testing.expectEqual(now + 5 + 4, p.nextDeadline().?);
}

test "timeAllowedtoLive always exceeds the next retransmission interval" {
    const p = try Publisher.init(testConfig(), .{});
    var step: usize = 0;
    while (step < 20) : (step += 1) {
        const tal = p.profile.tal(step);
        const next = p.profile.interval(step);
        try testing.expect(tal > next);
    }
    // And with a multiplier of exactly 1 the invariant would break, which is
    // why the floor exists: check the shipped default holds it.
    try testing.expect(p.profile.tal_multiplier >= 2);
}

test "a retransmission carries the event time, not the transmission time" {
    var vbuf: [16]u8 = undefined;
    const val = try oneBoolean(true, &vbuf);
    var p = try Publisher.init(testConfig(), .{});
    p.start(1_700_000_000_000);
    var out: [1024]u8 = undefined;
    const first = try goose.Pdu.decode((try goose.Frame.decode((try p.tick(1_700_000_000_000, &[_][]const u8{val}, &out)).?)).pdu);
    var buf2: [1024]u8 = undefined;
    const second = try goose.Pdu.decode((try goose.Frame.decode((try p.tick(1_700_000_000_004, &[_][]const u8{val}, &buf2)).?)).pdu);
    try testing.expectEqual(first.t.seconds, second.t.seconds);
    try testing.expectEqual(first.t.fraction, second.t.fraction);
    try testing.expectEqual(@as(u32, 1), second.sq_num);
}

test "tick returns null until the deadline and refuses before start" {
    var vbuf: [16]u8 = undefined;
    const val = try oneBoolean(true, &vbuf);
    var p = try Publisher.init(testConfig(), .{});
    var out: [1024]u8 = undefined;
    try testing.expectError(error.NotStarted, p.tick(0, &[_][]const u8{val}, &out));
    p.start(100);
    try testing.expect((try p.tick(99, &[_][]const u8{val}, &out)) == null);
    try testing.expect((try p.tick(100, &[_][]const u8{val}, &out)) != null);
    try testing.expect((try p.tick(101, &[_][]const u8{val}, &out)) == null);
    try testing.expect((try p.tick(104, &[_][]const u8{val}, &out)) != null);
}

test "a very late caller does not burst to catch up" {
    var vbuf: [16]u8 = undefined;
    const val = try oneBoolean(true, &vbuf);
    var p = try Publisher.init(testConfig(), .{});
    p.start(0);
    var out: [1024]u8 = undefined;
    _ = try p.tick(0, &[_][]const u8{val}, &out);
    // The caller vanishes for ten seconds.
    _ = try p.tick(10_000, &[_][]const u8{val}, &out);
    // The next deadline is in the future, not ten thousand missed slots ago.
    try testing.expect(p.nextDeadline().? > 10_000);
}

test "stNum never wraps to the reserved value 0" {
    var p = try Publisher.init(testConfig(), .{});
    p.start(0);
    p.st_num = std.math.maxInt(u32);
    p.stateChange(1);
    try testing.expectEqual(@as(u32, 1), p.st_num);
}

test "a bad profile is refused rather than busy-looping" {
    try testing.expectError(error.BadProfile, Publisher.init(testConfig(), .{ .ladder = &[_]u32{} }));
    try testing.expectError(error.BadProfile, Publisher.init(testConfig(), .{ .ladder = &[_]u32{ 4, 0, 16 } }));
}

test "the published frame decodes as a well-formed GOOSE frame" {
    var vbuf: [64]u8 = undefined;
    var w = ber.Writer.init(&vbuf);
    try mmsdata.Emit.integer(&w, -7);
    const int_val = w.done();
    var vbuf2: [16]u8 = undefined;
    const bool_val = try oneBoolean(false, &vbuf2);

    var cfg = testConfig();
    cfg.vlan = .{ .priority = 4, .id = 42 };
    cfg.test_mode = true;
    cfg.nds_com = true;
    var p = try Publisher.init(cfg, .{});
    p.start(1_700_000_000_500);
    var out: [1024]u8 = undefined;
    const frame = (try p.tick(1_700_000_000_500, &[_][]const u8{ bool_val, int_val }, &out)).?;

    const f = try goose.Frame.decode(frame);
    try testing.expectEqual(@as(u16, 0x1000), f.appid);
    try testing.expectEqual(@as(u12, 42), f.vlan.?.id);
    try testing.expectEqual(@as(u3, 4), f.vlan.?.priority);
    try testing.expect(goose.isGooseMulticast(f.dst));
    const pdu = try goose.Pdu.decode(f.pdu);
    try testing.expectEqualStrings("TESTLD/LLN0$GO$gcbTest", pdu.gocb_ref);
    try testing.expectEqualStrings("TESTLD/LLN0$dsTest", pdu.dat_set);
    try testing.expectEqualStrings(pdu.gocb_ref, pdu.go_id);
    try testing.expect(pdu.test_mode);
    try testing.expect(pdu.nds_com);
    try testing.expectEqual(@as(u32, 3), pdu.conf_rev);
    try testing.expectEqual(@as(u32, 2), pdu.num_dat_set_entries);
    var it = pdu.values();
    try testing.expectEqual(false, try (try it.next()).?.boolean());
    try testing.expectEqual(@as(i32, -7), try (try it.next()).?.integer(i32));
}
