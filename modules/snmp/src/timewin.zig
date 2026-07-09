// SPDX-License-Identifier: MIT

//! USM time-window anti-replay — **T-H** (RFC 3414 §3.2 / §2.2.3). Pure integer
//! logic: given a received `msgAuthoritativeEngineBoots` / `...EngineTime` and
//! the locally held notion of the authoritative engine's boots/time, decide
//! whether the message falls inside the ±150-second replay window.
//!
//! Two roles (RFC 3414 §3.2):
//!   * **Authoritative** — the message is addressed to this engine, which owns
//!     the clock. The received boots/time are validated against our own
//!     `snmpEngineBoots` / `snmpEngineTime`; nothing is latched.
//!   * **Non-authoritative** — we hold a cached copy of a *remote* authoritative
//!     engine's boots/time. Before deciding, we latch forward: adopt the larger
//!     boots, and (at the current boots) the larger engineTime — so the window
//!     tracks the newest evidence we have seen.
//!
//! This module makes no time-of-day calls; the caller supplies both the local
//! and message clock values, keeping it deterministic and unit-testable.
//!
//! Provenance: clean-room from RFC 3414 §3.2 (Timeliness) and §2.2.3
//! (snmpEngineTime). No source consulted.

const std = @import("std");

/// The largest legal `snmpEngineBoots` (2^31 − 1). Once an engine reaches it,
/// USM treats every message as out-of-window (the engine must re-key), so a
/// local boots at this value fails authoritatively (RFC 3414 §3.2 step 1).
pub const max_boots: u32 = std.math.maxInt(i32); // 2147483647

/// The USM time window, in seconds (RFC 3414 §3.2: 150 s each side).
pub const time_window_secs: u32 = 150;

pub const TimeError = error{
    /// The message's engine boots/time fell outside the authenticated time
    /// window (a stale or replayed message), or the local boots hit `max_boots`.
    NotInTimeWindow,
};

/// The locally held view of an authoritative engine's clock. For the
/// authoritative role these are this engine's own `snmpEngineBoots` /
/// `snmpEngineTime`; for the non-authoritative role they are the cached values
/// for a specific remote engine (key them per `engineID` in the caller).
pub const EngineTimeState = struct {
    /// Cached `snmpEngineBoots`.
    engine_boots: u32,
    /// Cached `snmpEngineTime` (the notional current time at that engine).
    engine_time: u32,
    /// `latestReceivedEngineTime` (RFC 3414 §3.2): the highest engineTime seen
    /// at `engine_boots`. Only meaningful non-authoritatively.
    latest_received_engine_time: u32,

    /// A fresh state seeded from an engine's boots/time (e.g. a discovery Report).
    pub fn init(boots: u32, time: u32) EngineTimeState {
        return .{ .engine_boots = boots, .engine_time = time, .latest_received_engine_time = time };
    }
};

/// Which side of the exchange is evaluating the window.
pub const Role = enum { authoritative, non_authoritative };

/// The RFC 3414 §3.2 non-authoritative latch: adopt the larger boots, and — when
/// boots are equal — the larger engineTime. Returns `true` if anything advanced.
/// Exposed so callers can update their cache even outside a full window check.
pub fn latch(state: *EngineTimeState, msg_boots: u32, msg_time: u32) bool {
    if (msg_boots > state.engine_boots or
        (msg_boots == state.engine_boots and msg_time > state.latest_received_engine_time))
    {
        state.engine_boots = msg_boots;
        state.engine_time = msg_time;
        state.latest_received_engine_time = msg_time;
        return true;
    }
    return false;
}

/// Decide whether a received `(msg_boots, msg_time)` is inside the USM time
/// window (RFC 3414 §3.2). For `.non_authoritative` the cache is latched forward
/// first (so `state` may be mutated); for `.authoritative` `state` is read-only
/// and holds this engine's own boots/time.
///
/// Authoritative rejects when: local boots == `max_boots`; `msg_boots` != local
/// boots; or |`msg_time` − local time| > 150 s.
///
/// Non-authoritative (after latching) rejects when: cached boots == `max_boots`;
/// `msg_boots` < cached boots; or (`msg_boots` == cached boots and `msg_time` is
/// more than 150 s behind `latestReceivedEngineTime`).
pub fn checkTimeWindow(
    role: Role,
    state: *EngineTimeState,
    msg_boots: u32,
    msg_time: u32,
) TimeError!void {
    switch (role) {
        .authoritative => {
            if (state.engine_boots == max_boots) return error.NotInTimeWindow;
            if (msg_boots != state.engine_boots) return error.NotInTimeWindow;
            const diff = if (msg_time > state.engine_time)
                msg_time - state.engine_time
            else
                state.engine_time - msg_time;
            if (diff > time_window_secs) return error.NotInTimeWindow;
        },
        .non_authoritative => {
            _ = latch(state, msg_boots, msg_time);
            if (state.engine_boots == max_boots) return error.NotInTimeWindow;
            if (msg_boots < state.engine_boots) return error.NotInTimeWindow;
            if (msg_boots == state.engine_boots) {
                // msg_time more than 150 s behind the newest time we've seen.
                const floor: i64 = @as(i64, state.latest_received_engine_time) - time_window_secs;
                if (@as(i64, msg_time) < floor) return error.NotInTimeWindow;
            }
        },
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "authoritative: in-window accepts, boots mismatch and skew reject" {
    var st = EngineTimeState.init(3, 1000);
    // Same boots, within ±150 s: OK.
    try checkTimeWindow(.authoritative, &st, 3, 1000);
    try checkTimeWindow(.authoritative, &st, 3, 1150);
    try checkTimeWindow(.authoritative, &st, 3, 850);
    // Boots mismatch → reject.
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.authoritative, &st, 2, 1000));
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.authoritative, &st, 4, 1000));
    // Just outside the window (±151 s) → reject.
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.authoritative, &st, 3, 1151));
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.authoritative, &st, 3, 849));
    // Authoritative role never mutates the state.
    try testing.expectEqual(@as(u32, 3), st.engine_boots);
    try testing.expectEqual(@as(u32, 1000), st.engine_time);
}

test "authoritative: boots at max is always out of window" {
    var st = EngineTimeState.init(max_boots, 1000);
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.authoritative, &st, max_boots, 1000));
}

test "authoritative: exact window edge (±150 s) accepts" {
    var st = EngineTimeState.init(7, 5000);
    try checkTimeWindow(.authoritative, &st, 7, 5150);
    try checkTimeWindow(.authoritative, &st, 7, 4850);
}

test "non-authoritative: monotonic latch of boots and time" {
    var st = EngineTimeState.init(1, 100);
    // A newer time at the same boots advances the cache.
    try testing.expect(latch(&st, 1, 200));
    try testing.expectEqual(@as(u32, 200), st.latest_received_engine_time);
    try testing.expectEqual(@as(u32, 200), st.engine_time);
    // An older time does not.
    try testing.expect(!latch(&st, 1, 150));
    try testing.expectEqual(@as(u32, 200), st.latest_received_engine_time);
    // A reboot (higher boots) always wins, even with a lower time.
    try testing.expect(latch(&st, 2, 5));
    try testing.expectEqual(@as(u32, 2), st.engine_boots);
    try testing.expectEqual(@as(u32, 5), st.latest_received_engine_time);
    // A lower boots is ignored.
    try testing.expect(!latch(&st, 1, 999));
    try testing.expectEqual(@as(u32, 2), st.engine_boots);
}

test "non-authoritative: check latches then validates" {
    var st = EngineTimeState.init(5, 1000);
    // Fresh, newer message: accepted and latched forward.
    try checkTimeWindow(.non_authoritative, &st, 5, 1000);
    try checkTimeWindow(.non_authoritative, &st, 5, 1200);
    try testing.expectEqual(@as(u32, 1200), st.latest_received_engine_time);

    // A replay > 150 s behind the newest seen time → reject.
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.non_authoritative, &st, 5, 1049));
    // Within 150 s behind → accepted (and does not lower the cache).
    try checkTimeWindow(.non_authoritative, &st, 5, 1051);
    try testing.expectEqual(@as(u32, 1200), st.latest_received_engine_time);

    // An old-boots message → reject.
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.non_authoritative, &st, 4, 9999));

    // A reboot (higher boots) is adopted and accepted.
    try checkTimeWindow(.non_authoritative, &st, 6, 3);
    try testing.expectEqual(@as(u32, 6), st.engine_boots);
    try testing.expectEqual(@as(u32, 3), st.latest_received_engine_time);
}

test "non-authoritative: cached boots at max rejects" {
    var st = EngineTimeState.init(max_boots, 1000);
    try testing.expectError(error.NotInTimeWindow, checkTimeWindow(.non_authoritative, &st, max_boots, 1000));
}

test "non-authoritative: no underflow when times are small" {
    var st = EngineTimeState.init(1, 10);
    // latest_received=10; floor = 10-150 = -140; any small msg_time >= -140 is OK.
    try checkTimeWindow(.non_authoritative, &st, 1, 0);
    try checkTimeWindow(.non_authoritative, &st, 1, 5);
}
