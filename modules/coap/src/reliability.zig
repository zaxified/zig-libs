// SPDX-License-Identifier: MIT

//! coap reliability (C3) — the CoAP message layer (RFC 7252 §4): Confirmable
//! retransmission with exponential backoff (§4.2), message-ID deduplication
//! (§4.5), and the empty-ACK / Reset helpers. Transport- and clock-agnostic:
//! the caller drives everything with an absolute millisecond time (`now_ms`)
//! and its own UDP socket, so this is fully offline-testable and imposes no
//! timer/thread model.
//!
//! ```zig
//! // Sending a CON and retransmitting until ACKed:
//! var rt = coap.reliability.Retransmit.init(.{}, now_ms, jitter_permille);
//! send(datagram);
//! // …each time the clock advances or a packet arrives…
//! switch (rt.poll(now_ms)) {
//!     .waiting => {},
//!     .retransmit => send(datagram),   // re-send the same bytes
//!     .timed_out => giveUp(),          // no ACK after MAX_RETRANSMIT
//! }
//! // on receiving the ACK/RST for this message id:
//! rt.ack();
//! ```
//!
//! **Transport security.** This layer is transport-agnostic — it never touches
//! a socket, so it runs unchanged over plain UDP or over a caller-terminated
//! DTLS session. `Dedup` (below) is a reliability mechanism, not a security
//! one; see its doc comment and `SPEC.md` "Threat model" for what that does
//! and doesn't protect against on an unauthenticated (plain UDP) transport.

const std = @import("std");
const coap = @import("root.zig");

// ── transmission parameters (RFC 7252 §4.8) ─────────────────────────────────

/// The RFC 7252 §4.8 transmission parameters, integer-scaled. Defaults are the
/// spec base values; tune per deployment.
pub const Params = struct {
    /// ACK_TIMEOUT — the base timeout before the first retransmission (ms).
    ack_timeout_ms: u32 = 2000,
    /// ACK_RANDOM_FACTOR as permille (1500 = 1.5). The initial timeout is
    /// chosen uniformly in `[ack_timeout, ack_timeout × factor]`.
    ///
    /// RFC 7252 §4.8 requires this to be greater than 1. Nothing here can
    /// enforce that — `Params` is a plain struct — so `Retransmit.init` clamps
    /// anything below `1000` UP to `1000`, which means "no jitter". Without the
    /// clamp the `factor - 1000` underflows and the process dies.
    ack_random_factor_permille: u32 = 1500,
    /// MAX_RETRANSMIT — retransmissions before giving up (4 ⇒ 5 sends total).
    max_retransmit: u8 = 4,
};

/// EXCHANGE_LIFETIME (§4.8.2), the default deduplication window (ms): the time a
/// message ID must be remembered so a retransmitted request is recognized.
pub const exchange_lifetime_ms: u64 = 247_000;

// ── empty-ACK / Reset helpers (RFC 7252 §4.2) ───────────────────────────────

/// An empty Acknowledgement for message `mid` — acknowledges a Confirmable
/// message without a piggybacked response (the response follows separately).
pub fn emptyAck(mid: u16) coap.Message {
    return .{ .type = .ack, .code = .empty, .message_id = mid };
}

/// A Reset for message `mid` — the recipient could not process the message (or
/// is not interested in a Non-confirmable one).
pub fn reset(mid: u16) coap.Message {
    return .{ .type = .reset, .code = .empty, .message_id = mid };
}

// ── Confirmable retransmission (RFC 7252 §4.2) ──────────────────────────────

/// Tracks the retransmission schedule of one just-sent Confirmable message.
/// Clock-agnostic: the caller passes an absolute `now_ms` to `init` and each
/// `poll`. A CON is retransmitted with an exponentially doubling timeout up to
/// `max_retransmit` times; a further timeout with no ACK is a transmission
/// failure. `ack()`/`reset()` stop the schedule when the peer responds.
pub const Retransmit = struct {
    params: Params,
    /// The current timeout window length (ms) — doubles each retransmit.
    timeout_ms: u32,
    /// Absolute time the current window expires (ms).
    deadline_ms: u64,
    /// Retransmissions sent so far (0..max_retransmit).
    retransmits: u8 = 0,
    /// Set once ACKed/RST or failed — `poll` then always returns `.waiting`.
    done: bool = false,

    pub const Action = enum {
        /// The window has not elapsed; keep waiting for an ACK.
        waiting,
        /// Retransmit the same datagram now (the next window is armed).
        retransmit,
        /// MAX_RETRANSMIT exhausted with no ACK — give up on this message.
        timed_out,
    };

    /// Begin tracking a CON just sent at `now_ms`. `jitter_permille` ∈ [0,1000]
    /// selects the initial timeout deterministically within the §4.2 range:
    /// 0 → `ack_timeout`, 1000 → `ack_timeout × factor`. Pass a random value in
    /// production (so peers don't sync retransmits), a fixed one in tests.
    pub fn init(params: Params, now_ms: u64, jitter_permille: u32) Retransmit {
        const base: u64 = params.ack_timeout_ms;
        // RFC 7252 §4.8 requires ACK_RANDOM_FACTOR > 1, and nothing validates
        // `Params` — it is a plain public struct a deployment fills in by hand.
        // The obvious spellings of "no jitter" (0, or 1 meaning 1.0) are both
        // below 1000, and `factor - 1000` on a `u32` then underflows to ~4.29e9,
        // which the `@intCast` below turns into a panic in Debug and UB in
        // ReleaseFast. Clamping is the right answer rather than rejecting: the
        // clamped value IS "no jitter", which is what such a caller meant, and
        // it keeps `init` infallible for the many callers that pass the spec
        // defaults. See CHANGELOG 2026-09-03.
        const factor: u64 = @max(params.ack_random_factor_permille, 1000);
        const span_ms: u64 = base * (factor - 1000) / 1000;
        const initial: u64 = base + span_ms * @min(jitter_permille, 1000) / 1000;
        return .{
            .params = params,
            // Saturating, for the same reason `poll` doubles saturatingly: an
            // `ack_timeout_ms` near `maxInt(u32)` with a large factor overflows
            // the window type, and a wrapped window is worse than a long one.
            .timeout_ms = std.math.lossyCast(u32, initial),
            .deadline_ms = now_ms + initial,
        };
    }

    /// Advance the schedule to `now_ms` (call when time passes or a packet
    /// arrives). Returns whether to retransmit, keep waiting, or give up. On
    /// `.retransmit` the window is doubled and re-armed; on `.timed_out` the
    /// schedule is marked done.
    pub fn poll(self: *Retransmit, now_ms: u64) Action {
        if (self.done) return .waiting;
        if (now_ms < self.deadline_ms) return .waiting;
        if (self.retransmits >= self.params.max_retransmit) {
            self.done = true;
            return .timed_out;
        }
        self.retransmits += 1;
        // Saturating. `max_retransmit` is a `u8`, so a deployment on a lossy
        // link may legitimately set it to ~30; with the 2000 ms base the window
        // leaves `u32` at retransmit #22. A wrapping `*=` does not merely
        // mis-time the next send — it eventually reaches ZERO, and a zero-length
        // window makes `poll` return `.retransmit` on every call, i.e. a
        // self-inflicted packet storm at the moment the network is worst. RFC
        // 7252 §4.2's backoff is monotone by design; saturating keeps it so.
        self.timeout_ms *|= 2;
        self.deadline_ms = now_ms + self.timeout_ms;
        return .retransmit;
    }

    /// The peer acknowledged (ACK) or rejected (RST) — stop retransmitting.
    pub fn ack(self: *Retransmit) void {
        self.done = true;
    }

    /// Alias for `ack` — an RST also ends the exchange.
    pub fn onReset(self: *Retransmit) void {
        self.done = true;
    }

    pub fn isDone(self: *const Retransmit) bool {
        return self.done;
    }
};

// ── message-ID deduplication (RFC 7252 §4.5) ────────────────────────────────

/// A bounded, time-windowed set of recently-seen message IDs — recognizes a
/// retransmitted (duplicate) message so the handler processes each exchange
/// once. Caller-provided storage (`[]Entry`), zero-allocation. Use one per
/// remote endpoint (message IDs are only unique within a source).
///
/// **This is a RELIABILITY control (§4.5 duplicate suppression), not a
/// replay-security control.** Both the table size (the caller's `storage`
/// slice — size it for how many in-flight exchanges you expect per source) and
/// the remembered-duration (`lifetime_ms`, passed to `init`) are already
/// caller-configurable, so a deployment can size the window for its expected
/// number of authenticated peers / concurrent exchanges. But sizing alone does
/// not make it a security boundary: on plain UDP, an unauthenticated attacker
/// who can inject packets can flood a peer's window with distinct message IDs
/// (however large) to evict a legitimate in-flight exchange's entry before its
/// own retransmission window elapses, after which a subsequently
/// replayed/retransmitted datagram with that ID is no longer recognized as a
/// duplicate and is reprocessed. `Dedup` only becomes a *security* boundary
/// once the transport authenticates the source — i.e. run over a
/// caller-terminated DTLS session per remote peer (RFC 7252 §9) — so that
/// "flood one peer's dedup table" requires being that authenticated peer.
pub const Dedup = struct {
    /// Ring storage of live entries; when full, an expired or the oldest slot
    /// is reused.
    entries: []Entry,
    len: usize = 0,
    /// How long a message ID is remembered (ms). Default EXCHANGE_LIFETIME.
    lifetime_ms: u64 = exchange_lifetime_ms,

    pub const Entry = struct { mid: u16, expiry_ms: u64 };

    pub const Verdict = enum {
        /// Not seen (recently) — a new exchange; now recorded.
        fresh,
        /// Seen within the window — a retransmission; the handler should reply
        /// from cache / drop rather than re-process.
        duplicate,
    };

    /// Initialize over caller storage.
    pub fn init(storage: []Entry, lifetime_ms: u64) Dedup {
        return .{ .entries = storage, .lifetime_ms = lifetime_ms };
    }

    /// Record message id `mid` seen at `now_ms`; return whether it is a
    /// duplicate (already live in the window). Expired entries are reclaimed on
    /// the way.
    pub fn check(self: *Dedup, mid: u16, now_ms: u64) Verdict {
        // Defensive: zero-length caller storage means dedup is impossible —
        // treat everything as fresh rather than indexing an empty slice below
        // (the eviction path would otherwise panic/UB on `entries[min_idx]`).
        if (self.entries.len == 0) return .fresh;

        // Single pass: compact live entries down (dropping expired ones),
        // noting a duplicate and the soonest-to-expire live slot as we go.
        var keep: usize = 0;
        var found = false;
        var min_idx: usize = 0;
        for (self.entries[0..self.len]) |entry| {
            if (entry.expiry_ms <= now_ms) continue; // expired — reclaim
            if (entry.mid == mid) found = true;
            self.entries[keep] = entry;
            if (keep == 0 or entry.expiry_ms < self.entries[min_idx].expiry_ms)
                min_idx = keep;
            keep += 1;
        }
        self.len = keep;
        if (found) return .duplicate;
        const fresh_entry: Entry = .{ .mid = mid, .expiry_ms = now_ms + self.lifetime_ms };
        if (self.len == self.entries.len) {
            // Full even after compaction: evict the soonest-to-expire entry.
            self.entries[min_idx] = fresh_entry;
        } else {
            self.entries[self.len] = fresh_entry;
            self.len += 1;
        }
        return .fresh;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Retransmit.init: jitter selects within [ack_timeout, ack_timeout×factor]" {
    const j0 = Retransmit.init(.{}, 100, 0);
    try testing.expectEqual(@as(u32, 2000), j0.timeout_ms);
    try testing.expectEqual(@as(u64, 2100), j0.deadline_ms);
    try testing.expectEqual(@as(u8, 0), j0.retransmits);
    try testing.expect(!j0.done);

    const j1000 = Retransmit.init(.{}, 100, 1000);
    try testing.expectEqual(@as(u32, 3000), j1000.timeout_ms);
    try testing.expectEqual(@as(u64, 3100), j1000.deadline_ms);

    const j500 = Retransmit.init(.{}, 100, 500);
    try testing.expectEqual(@as(u32, 2500), j500.timeout_ms);
    try testing.expectEqual(@as(u64, 2600), j500.deadline_ms);

    // Jitter is clamped to 1000.
    const j_over = Retransmit.init(.{}, 100, 9999);
    try testing.expectEqual(@as(u32, 3000), j_over.timeout_ms);
}

test "Retransmit.poll: default schedule — 4 retransmits, then timed_out" {
    var rt = Retransmit.init(.{}, 0, 0); // timeout 2000, deadline 2000

    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(0));
    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(1999));

    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(2000));
    try testing.expectEqual(@as(u32, 4000), rt.timeout_ms);
    try testing.expectEqual(@as(u64, 6000), rt.deadline_ms);

    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(5999));
    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(6000));
    try testing.expectEqual(@as(u32, 8000), rt.timeout_ms);
    try testing.expectEqual(@as(u64, 14000), rt.deadline_ms);

    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(14000));
    try testing.expectEqual(@as(u32, 16000), rt.timeout_ms);
    try testing.expectEqual(@as(u64, 30000), rt.deadline_ms);

    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(30000));
    try testing.expectEqual(@as(u8, 4), rt.retransmits);
    try testing.expectEqual(@as(u32, 32000), rt.timeout_ms);
    try testing.expectEqual(@as(u64, 62000), rt.deadline_ms);

    // Final window: one more wait, then the exchange times out.
    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(61999));
    try testing.expect(!rt.isDone());
    try testing.expectEqual(Retransmit.Action.timed_out, rt.poll(62000));
    try testing.expect(rt.isDone());

    // After timed_out, poll stays .waiting forever.
    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(999_999));
}

test "Retransmit: ack/onReset stop the schedule" {
    var rt = Retransmit.init(.{}, 0, 0);
    rt.ack();
    try testing.expect(rt.isDone());
    // Even far past the deadline, no retransmit is asked for.
    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(100_000));
    try testing.expectEqual(@as(u8, 0), rt.retransmits);

    var rt2 = Retransmit.init(.{}, 0, 0);
    rt2.onReset();
    try testing.expect(rt2.isDone());
    try testing.expectEqual(Retransmit.Action.waiting, rt2.poll(100_000));
}

test "Retransmit: custom max_retransmit gives exactly that many retransmits" {
    const params: Params = .{ .max_retransmit = 2 };
    var rt = Retransmit.init(params, 0, 0); // 2000, deadline 2000
    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(2000)); // #1
    try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(6000)); // #2
    try testing.expectEqual(@as(u8, 2), rt.retransmits);
    // deadline is now 6000 + 8000 = 14000; the next elapse is failure.
    try testing.expectEqual(Retransmit.Action.waiting, rt.poll(13999));
    try testing.expectEqual(Retransmit.Action.timed_out, rt.poll(14000));
    try testing.expect(rt.isDone());
}

test "Retransmit: the backoff is MONOTONE to the end of a long schedule, never wrapping" {
    // `max_retransmit` is a u8 and documented as tunable; a lossy link raising
    // it to ~30 is ordinary. With the 2000 ms base the window leaves u32 at
    // retransmit #22, and a wrapping double reaches ZERO by #28 — after which
    // `poll` answers `.retransmit` on every call, a packet storm. The default
    // schedule (4) is three orders of magnitude short of the boundary, so
    // nothing in the suite used to go anywhere near it.
    var rt = Retransmit.init(.{ .max_retransmit = 40 }, 0, 0);
    var now: u64 = 0;
    var prev: u32 = rt.timeout_ms;
    try testing.expectEqual(@as(u32, 2000), prev);
    var n: usize = 0;
    while (n < 40) : (n += 1) {
        now = rt.deadline_ms;
        try testing.expectEqual(Retransmit.Action.retransmit, rt.poll(now));
        // The window never shrinks, and in particular never falls back under
        // the base — the shape a wrap produces.
        try testing.expect(rt.timeout_ms >= prev);
        try testing.expect(rt.timeout_ms >= 2000);
        prev = rt.timeout_ms;
    }
    // Saturated rather than wrapped: 2000 · 2^40 is far past u32.
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rt.timeout_ms);
    try testing.expectEqual(Retransmit.Action.timed_out, rt.poll(rt.deadline_ms));
}

test "Retransmit.init: an ACK_RANDOM_FACTOR below 1 is clamped, not an underflow" {
    // RFC 7252 §4.8 requires ACK_RANDOM_FACTOR > 1 and nothing validates
    // `Params`. Both obvious spellings of "no jitter" are below 1000 and used
    // to underflow `factor - 1000` on a u32 — a panic in Debug, UB in
    // ReleaseFast (observed as both a SIGSEGV and a runaway, which is what UB
    // looks like). The clamped result is exactly "no jitter": the base timeout.
    for ([_]u32{ 0, 1, 999, 1000 }) |bad| {
        const rt = Retransmit.init(.{ .ack_random_factor_permille = bad }, 0, 1000);
        try testing.expectEqual(@as(u32, 2000), rt.timeout_ms);
        try testing.expectEqual(@as(u64, 2000), rt.deadline_ms);
    }
    // A legal factor still jitters, so the clamp did not flatten the feature.
    const ok = Retransmit.init(.{ .ack_random_factor_permille = 1500 }, 0, 1000);
    try testing.expectEqual(@as(u32, 3000), ok.timeout_ms);
}

test "Dedup: fresh, duplicate, and expiry from first sight" {
    var storage: [4]Dedup.Entry = undefined;
    var dd = Dedup.init(&storage, 1000);

    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 0));
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(1, 10));
    // Duplicate does NOT refresh: window runs from first sight (expiry 1000).
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(1, 999));
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 1000));
}

test "Dedup: distinct mids are independent" {
    var storage: [4]Dedup.Entry = undefined;
    var dd = Dedup.init(&storage, 1000);

    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(7, 0));
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(8, 0));
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(7, 100));
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(8, 100));
    try testing.expectEqual(@as(usize, 2), dd.len);
}

test "Dedup: full storage evicts the soonest-to-expire entry" {
    var storage: [2]Dedup.Entry = undefined;
    var dd = Dedup.init(&storage, 1000);

    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 0)); // expiry 1000
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(2, 100)); // expiry 1100
    // Third fresh mid: full, evicts mid 1 (smallest expiry).
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(3, 200)); // expiry 1200
    try testing.expectEqual(@as(usize, 2), dd.len);
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(2, 300));
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(3, 300));
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 300)); // was evicted
}

test "Dedup: zero-length storage never panics and always reports fresh" {
    var storage: [0]Dedup.Entry = undefined;
    var dd = Dedup.init(&storage, 1000);
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 0));
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 1)); // no storage ⇒ can't remember it either
    try testing.expectEqual(@as(usize, 0), dd.len);
}

test "Dedup: expired entries are reclaimed on check" {
    var storage: [2]Dedup.Entry = undefined;
    var dd = Dedup.init(&storage, 1000);

    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(1, 0)); // expiry 1000
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(2, 900)); // expiry 1900
    // At 1500, mid 1 is expired: it is compacted away, so mid 3 fits without
    // evicting mid 2.
    try testing.expectEqual(Dedup.Verdict.fresh, dd.check(3, 1500));
    try testing.expectEqual(@as(usize, 2), dd.len);
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(2, 1600));
    try testing.expectEqual(Dedup.Verdict.duplicate, dd.check(3, 1600));
}

test "emptyAck/reset build the right type and code" {
    const a = emptyAck(0xBEEF);
    try testing.expectEqual(coap.Type.ack, a.type);
    try testing.expectEqual(coap.Code.empty, a.code);
    try testing.expectEqual(@as(u16, 0xBEEF), a.message_id);

    const r = reset(0x1234);
    try testing.expectEqual(coap.Type.reset, r.type);
    try testing.expectEqual(coap.Code.empty, r.code);
    try testing.expectEqual(@as(u16, 0x1234), r.message_id);
}
