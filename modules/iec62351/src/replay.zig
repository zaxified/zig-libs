// SPDX-License-Identifier: MIT

//! IEC 62351-6 clause 6.2 — replay protection for GOOSE and Sampled Values.
//!
//! Authentication alone does not stop a replay: a captured frame carries a
//! valid tag forever. The 2020 edition therefore adds a **state machine over
//! the PDU's own sequencing fields** — `stNum`/`sqNum`/`t` for GOOSE (clause
//! 6.2.1, Figure 2) and `smpCnt` for Sampled Values (clause 6.2.2, Figure 3).
//! This file is that state machine.
//!
//! ## Pure, time-injected, no clock of its own
//!
//! Every entry point takes `now_ns` from the caller. There is no thread, no
//! timer and no clock read anywhere in this file — matching the rest of the
//! repository, and making the whole thing testable by advancing a `u64`.
//! `check` is a pure function of (state, input, now) and mutates nothing;
//! `accept` is `check` plus a commit on success. Callers that need to decide
//! before committing (e.g. to run the tag check first) use `check`.
//!
//! ## Two facts about GOOSE sequencing that decide the design
//!
//! 1. **`t` is the time of the last state change, not of this frame.** A GOOSE
//!    publisher retransmits the same state with an increasing `sqNum` and an
//!    unchanged `t`; on a slow-changing signal `t` is legitimately minutes or
//!    hours old. Applying a freshness window to `t` on every frame therefore
//!    rejects healthy traffic. This guard checks `t`'s age **only when
//!    `stNum` advances**, and separately enforces that `t` does *not* move
//!    within a state (`require_stable_timestamp`) — a changed `t` under an
//!    unchanged `stNum` is a fabricated frame.
//! 2. **Both counters wrap.** IEC 61850-8-1 wraps `sqNum` and `stNum` from
//!    the maximum back to 1 rather than to 0. Comparing them with `>` makes a
//!    publisher restart look like a permanent replay and wedges the
//!    subscriber. The guard uses RFC 1982 serial-number arithmetic (a value is
//!    "newer" if it is within half the counter space ahead), which handles the
//!    wrap and still rejects a rewind — at the documented cost that an
//!    attacker who can jump the counter by more than 2^31 gets a fresh start.
//!    Set `allow_stnum_wrap`/`allow_sqnum_wrap` to `false` for strict `>`
//!    ordering in a deployment that never wraps in practice.
//!
//! ## What this does not do
//!
//! It has no memory of *which* publisher a frame came from. One guard tracks
//! one stream (one GoCB reference / one `svID`); the caller keys guards by
//! publisher identity. That is deliberate: keying is an application concern
//! and a map here would need an allocator and a lifetime policy.

const std = @import("std");

pub const ns_per_us: u64 = 1_000;
pub const ns_per_ms: u64 = 1_000_000;
pub const ns_per_s: u64 = 1_000_000_000;

/// RFC 1982 serial-number comparison over an unsigned counter: is `a` ahead of
/// `b` within half the counter space?
fn serialNewer(comptime T: type, a: T, b: T) bool {
    const half = @as(T, 1) << (@bitSizeOf(T) - 1);
    const delta = a -% b;
    return delta != 0 and delta < half;
}

/// Why a frame was accepted or rejected. Every rejection names the specific
/// rule, so a subscriber can log which one fired instead of "bad frame".
pub const Verdict = enum {
    /// No prior state: this frame establishes it.
    accept_first,
    /// `stNum` advanced — a new state (a real event).
    accept_new_state,
    /// Same state, `sqNum` advanced — a heartbeat retransmission.
    accept_in_sequence,

    /// `stNum` went backwards: a replayed older state.
    reject_replay_state,
    /// Same `stNum` and `sqNum` did not advance: a replayed retransmission
    /// (including an exact duplicate).
    reject_replay_sequence,
    /// `stNum` advanced but `sqNum` did not restart at 0.
    reject_sqnum_not_reset,
    /// `t` changed without `stNum` changing.
    reject_timestamp_changed,
    /// `t` is older than the configured window on a state change.
    reject_stale_timestamp,
    /// `t` is ahead of local time by more than the configured skew.
    reject_future_timestamp,
    /// Nothing was accepted within the previous frame's `timeAllowedtoLive`
    /// (plus `tal_slack_ms`), or for longer than `max_idle_ns`; the stream
    /// must be re-established (`reset`) rather than silently resumed.
    reject_idle_gap,
    /// Sampled Values only: `smpCnt` did not advance within the forward window.
    reject_sample_out_of_window,
    /// Sampled Values only: the publisher's configuration revision changed.
    reject_config_revision,
    /// Sampled Values only: the publisher reports an unsynchronised clock and
    /// the profile requires synchronisation.
    reject_not_synchronised,

    pub fn accepted(v: Verdict) bool {
        return switch (v) {
            .accept_first, .accept_new_state, .accept_in_sequence => true,
            else => false,
        };
    }
};

// ── GOOSE ───────────────────────────────────────────────────────────────────

/// The three `goosePdu` fields the replay state machine reads. The caller
/// extracts them from its own decoder — this module never parses a PDU.
pub const GooseIdentity = struct {
    /// `stNum` — incremented on every state change.
    st_num: u32,
    /// `sqNum` — incremented on every retransmission, restarted at 0 on a
    /// state change.
    sq_num: u32,
    /// `t` — the entry time of the last state change, in nanoseconds since
    /// the UTC epoch (IEC 61850's `UtcTime` converted by the caller).
    t_ns: u64,
    /// `timeAllowedtoLive` — the publisher's promise that the next frame
    /// follows within this many milliseconds. Required, not defaulted: it is
    /// the only thing that bounds the heartbeat path, where `t` legitimately
    /// stays old (A1 finding N3 — with nothing bounding it, 500 of 500
    /// day-old captured heartbeats were accepted under default options).
    time_allowed_to_live_ms: u32,
    /// `t`'s quality bits, straight off `UtcTime` (IEC 61850-7-2 §6.2.2.4):
    /// `clockFailure` / `clockNotSynchronized`. Default false (healthy) so a
    /// caller that does not populate them sees the exact same behavior as
    /// before these fields existed. Audit finding N4: the entire freshness
    /// argument in this file rests on `t`, and until this field existed there
    /// was nowhere to say "the publisher's clock is the reason `t` cannot be
    /// trusted" — `SvIdentity.smp_synch` had a symmetric signal for Sampled
    /// Values, GOOSE had none.
    clock_failure: bool = false,
    /// See `clock_failure`.
    clock_not_synchronized: bool = false,
};

pub const GooseOptions = struct {
    /// How old `t` may be when `stNum` advances. Generous by default: a
    /// state change that took a while to reach us is normal on a congested
    /// segment, and this is the one window whose tightening trades
    /// availability for replay resistance.
    max_state_age_ns: u64 = 10 * ns_per_s,
    /// How far `t` may lead local time before the frame is rejected.
    /// Non-zero because subscriber and publisher clocks differ.
    max_skew_ns: u64 = 500 * ns_per_ms,
    /// An additional, fixed cap on silence, on top of `timeAllowedtoLive`.
    /// 0 disables this cap (not the TAL check).
    max_idle_ns: u64 = 0,
    /// Reject a frame arriving later than the previous accepted frame's
    /// `timeAllowedtoLive` plus `tal_slack_ms` (`reject_idle_gap`). On by
    /// default: the publisher promised the next frame by then, so a later one
    /// means the stream was lost — the same rule `iec61850.subscriber` applies.
    /// Turning it off leaves heartbeats bounded only by `max_idle_ns`.
    enforce_time_allowed_to_live: bool = true,
    /// Jitter allowance added to `timeAllowedtoLive`, in milliseconds.
    tal_slack_ms: u32 = 0,
    /// Require `sqNum == 0` on a state change (IEC 61850-8-1's rule).
    require_sqnum_reset: bool = true,
    /// Require `t` to be unchanged while `stNum` is unchanged.
    require_stable_timestamp: bool = true,
    /// Use RFC 1982 serial arithmetic for `stNum` (tolerates the wrap) rather
    /// than strict `>`.
    allow_stnum_wrap: bool = true,
    /// Likewise for `sqNum`.
    allow_sqnum_wrap: bool = true,
    /// Reject when `clock_failure` or `clock_not_synchronized` is set,
    /// symmetric to `SvOptions.require_synchronised`. Off by default: turning
    /// this on changes accept/reject behavior for every caller, and not every
    /// GOOSE decoder surfaces `UtcTime`'s quality bits today (audit finding N4).
    require_synchronised: bool = false,
};

/// Replay guard for one GOOSE stream (one GoCB reference).
pub const GooseGuard = struct {
    options: GooseOptions = .{},
    state: ?State = null,

    pub const State = struct {
        st_num: u32,
        sq_num: u32,
        t_ns: u64,
        /// Local time at which the last accepted frame arrived.
        last_seen_ns: u64,
        /// The `timeAllowedtoLive` that frame promised.
        tal_ms: u32,
    };

    pub fn init(options: GooseOptions) GooseGuard {
        return .{ .options = options };
    }

    /// Forget the stream. The next frame is treated as the first one, so the
    /// caller must have another reason to trust it (a fresh key, an operator
    /// action) before calling this.
    pub fn reset(g: *GooseGuard) void {
        g.state = null;
    }

    /// Decide, without changing anything.
    pub fn check(g: *const GooseGuard, id: GooseIdentity, now_ns: u64) Verdict {
        const o = g.options;

        // Checked before anything else, same as the future-timestamp check
        // below: an unsynchronised/failed clock undermines every later
        // decision that reads `t`, including the very first frame.
        if (o.require_synchronised and (id.clock_failure or id.clock_not_synchronized))
            return .reject_not_synchronised;

        // A timestamp in the future is wrong in every state, including the
        // first frame, so it is checked before anything else.
        if (id.t_ns > now_ns +| o.max_skew_ns) return .reject_future_timestamp;

        const prev = g.state orelse {
            if (now_ns -| id.t_ns > o.max_state_age_ns) return .reject_stale_timestamp;
            return .accept_first;
        };

        // The PREVIOUS frame's promise decides, not this one's: a replayed or
        // forged frame must not be able to excuse its own lateness.
        if (o.enforce_time_allowed_to_live and
            now_ns -| prev.last_seen_ns > (@as(u64, prev.tal_ms) + o.tal_slack_ms) * ns_per_ms)
        {
            return .reject_idle_gap;
        }
        if (o.max_idle_ns != 0 and now_ns -| prev.last_seen_ns > o.max_idle_ns) {
            return .reject_idle_gap;
        }

        if (id.st_num == prev.st_num) {
            const forward = if (o.allow_sqnum_wrap)
                serialNewer(u32, id.sq_num, prev.sq_num)
            else
                id.sq_num > prev.sq_num;
            if (!forward) return .reject_replay_sequence;
            if (o.require_stable_timestamp and id.t_ns != prev.t_ns) return .reject_timestamp_changed;
            return .accept_in_sequence;
        }

        const newer_state = if (o.allow_stnum_wrap)
            serialNewer(u32, id.st_num, prev.st_num)
        else
            id.st_num > prev.st_num;
        if (!newer_state) return .reject_replay_state;

        if (o.require_sqnum_reset and id.sq_num != 0) return .reject_sqnum_not_reset;
        if (now_ns -| id.t_ns > o.max_state_age_ns) return .reject_stale_timestamp;
        return .accept_new_state;
    }

    /// `check`, committing the new state when (and only when) it accepts.
    pub fn accept(g: *GooseGuard, id: GooseIdentity, now_ns: u64) Verdict {
        const v = g.check(id, now_ns);
        if (v.accepted()) {
            g.state = .{
                .st_num = id.st_num,
                .sq_num = id.sq_num,
                .t_ns = id.t_ns,
                .last_seen_ns = now_ns,
                .tal_ms = id.time_allowed_to_live_ms,
            };
        }
        return v;
    }
};

// ── Sampled Values ──────────────────────────────────────────────────────────

/// The Sampled Value fields the replay state machine reads.
pub const SvIdentity = struct {
    /// `smpCnt` — the sample counter, restarted every second (or every
    /// `smp_rate` samples).
    smp_cnt: u16,
    /// `smpSynch` — 0 = not synchronised, 1 = local clock, 2 = global clock.
    smp_synch: u8 = 0,
    /// `confRev` — the publisher's configuration revision.
    conf_rev: u32 = 0,
};

pub const SvOptions = struct {
    /// Samples per second; `smpCnt` counts 0..`smp_rate`-1 and wraps.
    /// 0 means "the counter wraps at 2^16", i.e. do not model the wrap point.
    smp_rate: u16 = 0,
    /// How far ahead of the last accepted sample a new one may jump before it
    /// is treated as out of window. Bounds how much an attacker can advance
    /// the counter in one step to invalidate the genuine publisher's frames.
    max_forward_gap: u16 = 100,
    /// Reject when the publisher reports `smpSynch == 0`.
    require_synchronised: bool = false,
    /// Longest silence after which the guard demands an explicit `reset`.
    /// 0 disables the check.
    max_idle_ns: u64 = 0,
};

/// Replay guard for one Sampled Value stream (one `svID`).
///
/// Sampled Values carry no timestamp of their own, so freshness cannot be
/// derived from the PDU: all this guard can enforce is that the counter moves
/// forward, by a bounded amount, and that the stream has not gone silent.
/// A subscriber that needs real freshness must bound the arrival interval
/// itself and pass `max_idle_ns`.
pub const SvGuard = struct {
    options: SvOptions = .{},
    state: ?State = null,

    pub const State = struct {
        smp_cnt: u16,
        conf_rev: u32,
        last_seen_ns: u64,
    };

    pub fn init(options: SvOptions) SvGuard {
        return .{ .options = options };
    }

    pub fn reset(g: *SvGuard) void {
        g.state = null;
    }

    pub fn check(g: *const SvGuard, id: SvIdentity, now_ns: u64) Verdict {
        const o = g.options;
        if (o.require_synchronised and id.smp_synch == 0) return .reject_not_synchronised;

        const prev = g.state orelse return .accept_first;
        if (o.max_idle_ns != 0 and now_ns -| prev.last_seen_ns > o.max_idle_ns) {
            return .reject_idle_gap;
        }
        if (id.conf_rev != prev.conf_rev) return .reject_config_revision;

        const modulus: u32 = if (o.smp_rate == 0) 1 << 16 else o.smp_rate;
        if (o.smp_rate != 0 and id.smp_cnt >= o.smp_rate) return .reject_sample_out_of_window;

        const delta: u32 = (@as(u32, id.smp_cnt) +% modulus - @as(u32, prev.smp_cnt)) % modulus;
        if (delta == 0) return .reject_replay_sequence;
        if (delta > o.max_forward_gap) return .reject_sample_out_of_window;
        return .accept_in_sequence;
    }

    pub fn accept(g: *SvGuard, id: SvIdentity, now_ns: u64) Verdict {
        const v = g.check(id, now_ns);
        if (v.accepted()) {
            g.state = .{ .smp_cnt = id.smp_cnt, .conf_rev = id.conf_rev, .last_seen_ns = now_ns };
        }
        return v;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const t0: u64 = 1_600_000_000 * ns_per_s;
/// An hour: out of the way of every test that is not about `timeAllowedtoLive`.
const test_tal_ms: u32 = 3_600_000;

test "GOOSE: a healthy stream — one event then heartbeats" {
    var g: GooseGuard = .init(.{});
    try testing.expectEqual(Verdict.accept_first, g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0));
    var i: u32 = 1;
    var now = t0;
    while (i < 20) : (i += 1) {
        now += ns_per_s;
        try testing.expectEqual(
            Verdict.accept_in_sequence,
            g.accept(.{ .st_num = 5, .sq_num = i, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, now),
        );
    }
    // A new event: stNum up, sqNum back to 0, fresh t.
    now += ns_per_s;
    try testing.expectEqual(
        Verdict.accept_new_state,
        g.accept(.{ .st_num = 6, .sq_num = 0, .t_ns = now, .time_allowed_to_live_ms = test_tal_ms }, now),
    );
}

test "GOOSE: a replayed frame is rejected" {
    var g: GooseGuard = .init(.{});
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    _ = g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_s);
    _ = g.accept(.{ .st_num = 5, .sq_num = 2, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 2 * ns_per_s);

    // Exact duplicate of the frame just accepted.
    try testing.expectEqual(
        Verdict.reject_replay_sequence,
        g.accept(.{ .st_num = 5, .sq_num = 2, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 3 * ns_per_s),
    );
    // An older retransmission of the same state.
    try testing.expectEqual(
        Verdict.reject_replay_sequence,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 3 * ns_per_s),
    );
    // An older state entirely.
    try testing.expectEqual(
        Verdict.reject_replay_state,
        g.accept(.{ .st_num = 4, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 3 * ns_per_s),
    );
    // ...and the guard's state was not disturbed by any of the rejections.
    try testing.expectEqual(@as(u32, 2), g.state.?.sq_num);
    try testing.expectEqual(
        Verdict.accept_in_sequence,
        g.accept(.{ .st_num = 5, .sq_num = 3, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 4 * ns_per_s),
    );
}

test "GOOSE: the status-number flooding attack is rejected once it rewinds" {
    // The documented attack: inject frames with a far-future stNum so the
    // subscriber will not accept the genuine publisher again. The guard
    // cannot stop the first (authenticated) jump — only the tag can — but it
    // must not let the attacker rewind afterwards, and must keep rejecting
    // the genuine stream's now-stale numbers so the operator sees the fault
    // rather than a silent switchover.
    var g: GooseGuard = .init(.{});
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.accept_new_state,
        g.accept(.{ .st_num = 1000, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
    try testing.expectEqual(
        Verdict.reject_replay_state,
        g.accept(.{ .st_num = 6, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 2 * ns_per_ms),
    );
}

test "GOOSE: a state change must restart sqNum" {
    var g: GooseGuard = .init(.{});
    _ = g.accept(.{ .st_num = 5, .sq_num = 7, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.reject_sqnum_not_reset,
        g.accept(.{ .st_num = 6, .sq_num = 8, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
    // The same frame is accepted when the rule is switched off.
    var lax: GooseGuard = .init(.{ .require_sqnum_reset = false });
    _ = lax.accept(.{ .st_num = 5, .sq_num = 7, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.accept_new_state,
        lax.accept(.{ .st_num = 6, .sq_num = 8, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
}

test "GOOSE: t may not move while stNum stands still" {
    var g: GooseGuard = .init(.{});
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.reject_timestamp_changed,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0 + ns_per_s, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_s),
    );
}

test "GOOSE: heartbeats with an old t are accepted; a stale state change is not" {
    var g: GooseGuard = .init(.{ .max_state_age_ns = 2 * ns_per_s });
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);

    // An hour of heartbeats carrying the original (now very old) t: healthy.
    const much_later = t0 + 3600 * ns_per_s;
    try testing.expectEqual(
        Verdict.accept_in_sequence,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, much_later),
    );
    // A *state change* carrying that same old t is stale.
    try testing.expectEqual(
        Verdict.reject_stale_timestamp,
        g.accept(.{ .st_num = 6, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, much_later + ns_per_ms),
    );
}

test "GOOSE: a timestamp from the future is rejected, including on the first frame" {
    var g: GooseGuard = .init(.{ .max_skew_ns = 100 * ns_per_ms });
    try testing.expectEqual(
        Verdict.reject_future_timestamp,
        g.accept(.{ .st_num = 1, .sq_num = 0, .t_ns = t0 + ns_per_s, .time_allowed_to_live_ms = test_tal_ms }, t0),
    );
    try testing.expect(g.state == null);
    // Inside the skew allowance it is fine.
    try testing.expectEqual(
        Verdict.accept_first,
        g.accept(.{ .st_num = 1, .sq_num = 0, .t_ns = t0 + 50 * ns_per_ms, .time_allowed_to_live_ms = test_tal_ms }, t0),
    );
}

test "GOOSE: the first frame must itself be fresh" {
    var g: GooseGuard = .init(.{ .max_state_age_ns = ns_per_s });
    try testing.expectEqual(
        Verdict.reject_stale_timestamp,
        g.accept(.{ .st_num = 1, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + 10 * ns_per_s),
    );
}

test "GOOSE: counter wrap is accepted, a rewind is not" {
    var g: GooseGuard = .init(.{});
    const max = std.math.maxInt(u32);
    _ = g.accept(.{ .st_num = 5, .sq_num = max, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    // IEC 61850-8-1 wraps sqNum to 1, not 0.
    try testing.expectEqual(
        Verdict.accept_in_sequence,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
    // Strict ordering refuses the same wrap.
    var strict: GooseGuard = .init(.{ .allow_sqnum_wrap = false });
    _ = strict.accept(.{ .st_num = 5, .sq_num = max, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.reject_replay_sequence,
        strict.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
    // A rewind past the halfway point is a replay under both settings.
    var g2: GooseGuard = .init(.{});
    _ = g2.accept(.{ .st_num = 5, .sq_num = 100, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    try testing.expectEqual(
        Verdict.reject_replay_sequence,
        g2.accept(.{ .st_num = 5, .sq_num = 99, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0 + ns_per_ms),
    );
}

test "GOOSE: default options refuse day-old captured heartbeats — timeAllowedtoLive bounds the heartbeat path (A1 N3)" {
    // The audit's scenario: the subscriber saw stNum 5 and its heartbeats with
    // TAL 2 s, the publisher vanished, and a day later the capture is replayed
    // bit for bit, so every tag still verifies. Before, all 500 were
    // `accept_in_sequence` under default options.
    var g: GooseGuard = .init(.{});
    const tal: u32 = 2000;
    try testing.expectEqual(Verdict.accept_first, g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = tal }, t0));
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = tal }, t0 + ns_per_s));

    const day_later = t0 + 86_400 * ns_per_s;
    var accepted: usize = 0;
    var sq: u32 = 2;
    while (sq < 502) : (sq += 1) {
        // A replayed or forged frame may promise any TAL; the previous frame's promise decides.
        const late: GooseIdentity = .{ .st_num = 5, .sq_num = sq, .t_ns = t0, .time_allowed_to_live_ms = std.math.maxInt(u32) };
        if (g.accept(late, day_later + sq).accepted()) accepted += 1;
    }
    try testing.expectEqual(@as(usize, 0), accepted);
    try testing.expectEqual(Verdict.reject_idle_gap, g.check(.{ .st_num = 5, .sq_num = 2, .t_ns = t0, .time_allowed_to_live_ms = tal }, day_later));
}

test "GOOSE: the TAL boundary, the slack, and the switch that turns the check off" {
    const tal: u32 = 2000;
    const first: GooseIdentity = .{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = tal };
    const next: GooseIdentity = .{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = tal };

    var g: GooseGuard = .init(.{});
    _ = g.accept(first, t0);
    try testing.expectEqual(Verdict.accept_in_sequence, g.check(next, t0 + 2000 * ns_per_ms)); // exactly TAL
    try testing.expectEqual(Verdict.reject_idle_gap, g.check(next, t0 + 2000 * ns_per_ms + 1));

    var s: GooseGuard = .init(.{ .tal_slack_ms = 500 });
    _ = s.accept(first, t0);
    try testing.expectEqual(Verdict.accept_in_sequence, s.check(next, t0 + 2500 * ns_per_ms));
    try testing.expectEqual(Verdict.reject_idle_gap, s.check(next, t0 + 2500 * ns_per_ms + 1));

    // Off: the day-old heartbeat is accepted again — the pre-N3 behaviour.
    var off: GooseGuard = .init(.{ .enforce_time_allowed_to_live = false });
    _ = off.accept(first, t0);
    try testing.expectEqual(Verdict.accept_in_sequence, off.check(next, t0 + 86_400 * ns_per_s));
}

test "GOOSE: a silent gap forces an explicit resynchronisation" {
    var g: GooseGuard = .init(.{ .max_idle_ns = 5 * ns_per_s });
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    const later = t0 + 60 * ns_per_s;
    try testing.expectEqual(
        Verdict.reject_idle_gap,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, later),
    );
    g.reset();
    try testing.expectEqual(
        Verdict.accept_first,
        g.accept(.{ .st_num = 5, .sq_num = 1, .t_ns = later, .time_allowed_to_live_ms = test_tal_ms }, later),
    );
}

test "GOOSE: clock-quality bits are ignored by default, matching pre-N4 behavior" {
    var g: GooseGuard = .init(.{});
    try testing.expectEqual(
        Verdict.accept_first,
        g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms, .clock_failure = true, .clock_not_synchronized = true }, t0),
    );
}

test "GOOSE: require_synchronised rejects a publisher reporting clock trouble, symmetric to SV" {
    var g: GooseGuard = .init(.{ .require_synchronised = true });
    // Audit finding N4: before this option existed there was no way to say
    // "the publisher itself says its clock is bad" for GOOSE, even though
    // the entire freshness argument in this file rests on `t`.
    try testing.expectEqual(
        Verdict.reject_not_synchronised,
        g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms, .clock_failure = true }, t0),
    );
    try testing.expectEqual(
        Verdict.reject_not_synchronised,
        g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms, .clock_not_synchronized = true }, t0),
    );
    // A healthy clock still gets through.
    try testing.expectEqual(
        Verdict.accept_first,
        g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0),
    );
}

test "GOOSE: check is pure — repeated calls never change the verdict" {
    var g: GooseGuard = .init(.{});
    _ = g.accept(.{ .st_num = 5, .sq_num = 0, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms }, t0);
    const id: GooseIdentity = .{ .st_num = 5, .sq_num = 1, .t_ns = t0, .time_allowed_to_live_ms = test_tal_ms };
    for (0..5) |_| try testing.expectEqual(Verdict.accept_in_sequence, g.check(id, t0 + ns_per_s));
    try testing.expectEqual(@as(u32, 0), g.state.?.sq_num);
    _ = g.accept(id, t0 + ns_per_s);
    try testing.expectEqual(Verdict.reject_replay_sequence, g.check(id, t0 + ns_per_s));
}

test "SV: samples advance, an exact repeat is a replay" {
    var g: SvGuard = .init(.{ .smp_rate = 4000, .max_forward_gap = 10 });
    try testing.expectEqual(Verdict.accept_first, g.accept(.{ .smp_cnt = 0 }, t0));
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .smp_cnt = 1 }, t0 + 250 * ns_per_us));
    try testing.expectEqual(Verdict.reject_replay_sequence, g.accept(.{ .smp_cnt = 1 }, t0 + 500 * ns_per_us));
    try testing.expectEqual(Verdict.reject_sample_out_of_window, g.accept(.{ .smp_cnt = 0 }, t0 + 500 * ns_per_us));
}

test "SV: the counter wraps at smpRate" {
    var g: SvGuard = .init(.{ .smp_rate = 80, .max_forward_gap = 5 });
    _ = g.accept(.{ .smp_cnt = 78 }, t0);
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .smp_cnt = 79 }, t0 + 1));
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .smp_cnt = 0 }, t0 + 2));
    // A counter at or above smpRate cannot be genuine.
    try testing.expectEqual(Verdict.reject_sample_out_of_window, g.accept(.{ .smp_cnt = 80 }, t0 + 3));
}

test "SV: a jump beyond the forward window is refused" {
    var g: SvGuard = .init(.{ .smp_rate = 4000, .max_forward_gap = 10 });
    _ = g.accept(.{ .smp_cnt = 100 }, t0);
    try testing.expectEqual(Verdict.reject_sample_out_of_window, g.accept(.{ .smp_cnt = 500 }, t0 + 1));
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .smp_cnt = 108 }, t0 + 1));
}

test "SV: the forward-gap window is closed, not open — exactly max_forward_gap is still in" {
    // A delta strictly greater than max_forward_gap is refused, but a delta
    // of EXACTLY max_forward_gap must still be accepted (`>`, not `>=`) — the
    // gap test above only exercised deltas well inside (8) and well outside
    // (400) the window, leaving the boundary itself unchecked.
    var g: SvGuard = .init(.{ .smp_rate = 4000, .max_forward_gap = 10 });
    _ = g.accept(.{ .smp_cnt = 100 }, t0);
    try testing.expectEqual(Verdict.accept_in_sequence, g.accept(.{ .smp_cnt = 110 }, t0 + 1)); // delta 10: in
    var g2: SvGuard = .init(.{ .smp_rate = 4000, .max_forward_gap = 10 });
    _ = g2.accept(.{ .smp_cnt = 100 }, t0);
    try testing.expectEqual(Verdict.reject_sample_out_of_window, g2.accept(.{ .smp_cnt = 111 }, t0 + 1)); // delta 11: out
}

test "SV: configuration revision changes and lost synchronisation are refused" {
    var g: SvGuard = .init(.{ .smp_rate = 4000, .require_synchronised = true });
    try testing.expectEqual(Verdict.reject_not_synchronised, g.accept(.{ .smp_cnt = 0, .smp_synch = 0 }, t0));
    try testing.expectEqual(Verdict.accept_first, g.accept(.{ .smp_cnt = 0, .smp_synch = 2, .conf_rev = 1 }, t0));
    try testing.expectEqual(
        Verdict.reject_config_revision,
        g.accept(.{ .smp_cnt = 1, .smp_synch = 2, .conf_rev = 2 }, t0 + 1),
    );
}

test "SV: a silent gap forces a resynchronisation" {
    var g: SvGuard = .init(.{ .smp_rate = 4000, .max_idle_ns = ns_per_s });
    _ = g.accept(.{ .smp_cnt = 0 }, t0);
    try testing.expectEqual(Verdict.reject_idle_gap, g.accept(.{ .smp_cnt = 1 }, t0 + 5 * ns_per_s));
}

test "serialNewer: forward within half the space, backward otherwise" {
    try testing.expect(serialNewer(u32, 2, 1));
    try testing.expect(!serialNewer(u32, 1, 1));
    try testing.expect(!serialNewer(u32, 1, 2));
    try testing.expect(serialNewer(u32, 1, std.math.maxInt(u32)));
    try testing.expect(!serialNewer(u32, std.math.maxInt(u32), 1));
    try testing.expect(serialNewer(u16, 0, 65535));
}

/// A knob draw this harness's SEED can steer.
///
/// `smith.valueRangeAtMost` reads EIGHT octets as a little-endian u64 and
/// returns the range MINIMUM unless that word already lies inside the range.
/// All three draws below were ranged, so `st_num`, `sq_num` and the clock skew
/// were 0 on every step of every run: this harness offered the guard the SAME
/// identity thirty-two times, and neither the "accepting must mean the pair
/// moved strictly forward" branch nor the rejection branch below could see a
/// pair that had moved. `value(u64)` has full-range weights, so every input
/// word survives; the reduction is ours.
///
/// ⛔ This target is not a `STRUCTURED` fuzz-reach exemption candidate even
/// though it draws a shape rather than a byte string: the gate's own second
/// remedy — draw with `value(u64)` and reduce — is this one line.
fn drawBelow(smith: *std.testing.Smith, bound: u64) u32 {
    return @intCast(smith.value(u64) % bound);
}

test "fuzz: a GOOSE guard never accepts a strictly older (stNum, sqNum) pair" {
    // 32 steps x 3 draws x 8 octets = 768 octets per seed. A fixed PRNG seed
    // keeps the corpus identical on every run.
    var prng = std.Random.DefaultPrng.init(0x600_5e00_0000_0001);
    var bufs: [8][768]u8 = undefined;
    var seeds: [8][]const u8 = undefined;
    for (&bufs, &seeds) |*b, *s| {
        prng.random().bytes(b);
        s.* = b;
    }
    try testing.fuzz({}, fuzzGoose, .{ .corpus = &seeds });
}

fn fuzzGoose(_: void, smith: *std.testing.Smith) !void {
    var g: GooseGuard = .init(.{ .max_state_age_ns = std.math.maxInt(u64) / 4, .max_skew_ns = ns_per_s });
    var now = t0;
    var steps: usize = 0;
    // Measured on 2026-09-06 over the corpus above (8 seeds x 32 steps):
    // **1 distinct identity offered across all 256 steps and 8 acceptances
    // before; 256 distinct identities and 15 acceptances after.** The 8
    // acceptances before were the eight first steps — one per seed, the guard
    // having no state yet — after which the same identity was refused 31 times
    // in a row, which is the whole of what this harness used to test.
    while (steps < 32) : (steps += 1) {
        const id: GooseIdentity = .{
            .st_num = drawBelow(smith, 9),
            .sq_num = drawBelow(smith, 9),
            .t_ns = now -| drawBelow(smith, 1001),
            .time_allowed_to_live_ms = test_tal_ms,
        };
        const before = g.state;
        const v = g.accept(id, now);
        if (v.accepted()) {
            if (before) |b| {
                // Accepting must mean the pair moved strictly forward.
                const advanced = id.st_num != b.st_num or id.sq_num != b.sq_num;
                try testing.expect(advanced);
                if (id.st_num == b.st_num) try testing.expect(id.sq_num > b.sq_num);
            }
        } else {
            // A rejection must leave the state untouched.
            try testing.expectEqual(before != null, g.state != null);
            if (before) |b| try testing.expectEqual(b.sq_num, g.state.?.sq_num);
        }
        now += ns_per_ms;
    }
}
