// SPDX-License-Identifier: MIT

//! coap Observe (C7) — RFC 7641: a client registers interest in a resource with
//! an **Observe** option (number 6, value 0 = register) on a GET; the server
//! then pushes a **notification** — a fresh response carrying the current
//! representation and an Observe option holding a monotonically increasing 24-bit
//! sequence number — every time the resource changes, until the client
//! deregisters (Observe value 1) or the server drops the subscription.
//!
//! Two caller-driven, zero-allocation pieces, in the same style as the rest of
//! the module:
//!
//! - **`Registry`** — the server's subscription table over caller storage
//!   (`[]Entry`), structurally like `reliability.Dedup`: a bounded array keyed by
//!   `(token, resource)` with FIFO eviction when full. `notify` applies the RFC
//!   7641 §3.4 freshness test so an out-of-order/replayed notification is
//!   rejected.
//! - **`Sequence`** — the monotonic 24-bit generator for the notification
//!   sequence numbers, plus `isNewer`, the RFC 1982-style "lollipop" comparison.
//!
//! **Server push reuses `server.Server.separate` unchanged**: a notification is
//! just a separate response (echoing the observed request's token) with an
//! Observe option added — no fresh request is involved. Build the option value
//! with `encodeValue(seq)` and put option `options.number.observe` on the
//! response; sort the options ascending as usual.
//!
//! **Reliability interaction (caller glue, no change to `reliability.zig`).** A
//! CON notification is driven by a `reliability.Retransmit` like any other CON.
//! If it exhausts retransmission (`.timed_out`) or the peer answers with a Reset,
//! the subscription is dead: the caller calls `Registry.cancel(token, resource)`.
//! Which type a notification goes out as is not the caller's free choice:
//! RFC 7641 §7 requires non-confirmable notifications to be interspersed with
//! confirmable ones, and §4.5 a confirmable one at least every 24 hours. The
//! push path asks `Registry.notificationType` before each notification and
//! reports each ACK with `Registry.acknowledged`.
//! (An RST correlates by message id, so the caller maps the notification's id
//! back to its `(token, resource)` — a few lines in its own loop.)
//!
//! **Transport security / admission (see also `SPEC.md` "Threat model").** CoAP
//! over plain UDP is unauthenticated: anyone who can send a datagram to the
//! server can send an Observe registration. `register` (below) is the raw,
//! unconditional primitive — same FIFO-eviction-when-full behavior as always,
//! used internally and by callers that already gate admission themselves.
//! `tryRegister` is the admission-checked entry point a caller wired to an
//! untrusted transport should use instead: it consults an optional `admit_fn`
//! hook and an optional per-`source_id` cap *before* touching the table, so a
//! rejected request never evicts an existing subscription. `source_id` is
//! whatever opaque peer identity the caller's transport can vouch for — in
//! production that identity should come from a **caller-terminated DTLS**
//! session (RFC 7252 §9 / RFC 7641 §8 both call out DTLS as the CoAP transport
//! security mechanism), not from the UDP source address alone (trivially
//! spoofed). This module stays transport-agnostic — it never touches a socket
//! — so DTLS termination, like the rest of the transport, is the caller's BYO
//! seam (mirroring this repo's BYO-TLS stance for TCP transports). Without
//! *both* a real `admit_fn` policy and an authenticated `source_id`, the
//! eviction attack described in `SPEC.md` remains possible — a hook that
//! trusts an unauthenticated source is not a mitigation.

const std = @import("std");
const coap = @import("root.zig");

/// The Observe sequence number space is 24-bit (RFC 7641 §2).
pub const max_sequence: u24 = std.math.maxInt(u24);

/// Observe option values used in a *request* (RFC 7641 §2). In a *response* the
/// value is instead the notification sequence number.
pub const request = struct {
    /// Register — start observing.
    pub const register: u24 = 0;
    /// Deregister — stop observing.
    pub const deregister: u24 = 1;
};

/// The monotonic 24-bit sequence generator a server stamps onto notifications.
/// `next()` returns the current value and advances (wrapping at 2^24); the
/// wrap-around is handled by `isNewer` on the receiving side.
pub const Sequence = struct {
    value: u24 = 0,

    pub fn next(self: *Sequence) u24 {
        const v = self.value;
        self.value +%= 1;
        return v;
    }
};

/// The **first two** of RFC 7641 §3.4's three freshness conditions: RFC 1982
/// serial-number arithmetic over the 24-bit space — is `new` ahead of `old`
/// within half the space (directly, or across the wrap)?
///
/// ⚠ This is deliberately NOT the whole test, and on its own it is not safe on
/// an unauthenticated transport. §3.4 reads
///
/// > (V1 < V2 and V2 - V1 < 2^23) or (V1 > V2 and V1 - V2 > 2^23) or
/// > (T2 > T1 + 128 seconds)
///
/// and the third condition is the recovery path — "after 128 seconds have
/// elapsed without any notification, a client does not need to check the
/// sequence numbers". Without it the comparison can WEDGE: one notification
/// carrying `2^23 - 1` is "newer" than every value in `[0, 2^23)`, so a single
/// spoofed datagram makes every genuine notification that follows read as
/// stale, permanently. Use `isNewerAt`, or `Registry.notify`, which does.
pub fn isNewer(old: u24, new: u24) bool {
    const half: u24 = 1 << 23;
    return (old < new and new - old < half) or (old > new and old - new > half);
}

/// RFC 7641 §3.4's freshness test, complete: `isNewer`, **or** more than
/// `reordering_window_ms` of client-local time has passed since the freshest
/// notification so far, in which case the sequence numbers are not consulted at
/// all. `old_ms` and `now_ms` are the caller's own clock (any monotonic
/// millisecond source); a caller that has no clock and passes a constant gets
/// the two-condition behaviour and the wedge that comes with it.
pub fn isNewerAt(old: u24, old_ms: u64, new: u24, now_ms: u64) bool {
    if (isNewer(old, new)) return true;
    return now_ms -| old_ms > reordering_window_ms;
}

/// RFC 7641 §3.4's 128 seconds: the age past which an incoming notification is
/// fresh regardless of its sequence number. The RFC picks it as "a nice round
/// number greater than MAX_LATENCY" (RFC 7252 §4.8.2).
pub const reordering_window_ms: u64 = 128_000;

/// RFC 7641 §4.5: "A server that transmits notifications mostly in
/// non-confirmable messages MUST send a notification in a confirmable message
/// instead of a non-confirmable message at least every 24 hours."
pub const max_con_interval_ms: u64 = 24 * 60 * 60 * 1000;

/// How many notifications `Registry.notificationType` lets go out
/// non-confirmable before it demands a confirmable one, by default. RFC 7641
/// §7 requires the limit ("Without client authentication, a server therefore
/// MUST strictly limit the number of notifications that it sends between
/// receiving acknowledgements … any notifications sent in non-confirmable
/// messages MUST be interspersed with confirmable messages") but names no
/// number; 5 is libcoap's `COAP_OBS_MAX_NON`.
pub const default_max_non_between_acks: u32 = 5;

/// Encode an Observe sequence as its option value: a 0..3-byte minimal
/// big-endian uint (0 → empty), like the CoAP uint format (RFC 7641 §2 uses the
/// §3.2 uint representation).
pub fn encodeValue(seq: u24, buf: *[3]u8) []const u8 {
    buf.* = .{ @truncate(seq >> 16), @truncate(seq >> 8), @truncate(seq) };
    var start: usize = 0;
    while (start < 3 and buf[start] == 0) start += 1;
    return buf[start..];
}

pub const DecodeError = error{
    /// The option value was longer than RFC 7641 §2's three bytes.
    OptionValueTooLong,
};

/// Decode an Observe option value (0..3 bytes) back to a sequence number.
///
/// An over-long value is REJECTED, not folded. It used to take the last three
/// bytes, which is worse than truncating: the attacker keeps the bytes that
/// decide the outcome and chooses it with padding — `{0,0,0,1}` decoded as
/// `deregister` and `{1,0,0,0}` as `register`, from the same four bytes in the
/// other order, while a conformant peer rejects both. `coap.parse` puts no
/// length limit on an option value, so this is straight off the wire. The
/// sibling decoders agree: `block.Block.decode` returns `error.TooLong` and
/// `options.contentFormat`/`accept` return `FormatError.OptionValueTooLong` —
/// the latter added in this same drift window, with the reason written into
/// its source ("rejecting is safer than silently `@truncate`-ing an
/// attacker-supplied over-long value to a plausible-looking identifier"). That
/// argument was applied to the two options it was found on rather than to the
/// rule; this is the third.
pub fn decodeValue(bytes: []const u8) DecodeError!u24 {
    if (bytes.len > 3) return error.OptionValueTooLong;
    var v: u32 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return @truncate(v);
}

/// An admission hook consulted by `Registry.tryRegister` before a *new*
/// subscription is added (not on a refresh of an existing one). `source_id` is
/// the caller's opaque peer identity (e.g. derived from an authenticated DTLS
/// session — see the module doc comment); `token`/`resource` identify the
/// subscription being requested. Return `false` to reject the registration
/// outright — rejection never touches the table, so it cannot evict an
/// existing entry. No allocation, no closures: a plain function pointer plus
/// an opaque context, in the same style as `aaa-gate.ApiKeyVerifyFn`.
pub const AdmitFn = *const fn (ctx: ?*anyopaque, source_id: u64, token: []const u8, resource: u64) bool;

/// A server-side table of active observations over caller storage — a bounded
/// array of `(token, resource) → last sequence` entries with FIFO eviction when
/// full, the same zero-allocation pattern as `reliability.Dedup`. The `resource`
/// key is a caller-chosen identifier (e.g. a hash of the Uri-Path) so the table
/// stays fixed-size.
///
/// `admit_fn`/`admit_ctx` and `max_per_source` are optional admission policy
/// consulted only by `tryRegister` (see its doc comment); `register` ignores
/// them and always succeeds/evicts as before. Both default to "off" (null /
/// 0), so a `Registry` that never sets them or only ever calls `register`
/// behaves exactly as before this policy was added.
pub const Registry = struct {
    entries: []Entry,
    len: usize = 0,
    /// Optional admission hook for `tryRegister`. `null` (default) = admit-all,
    /// matching the pre-existing `register` behavior.
    admit_fn: ?AdmitFn = null,
    /// Opaque context handed verbatim to every `admit_fn` call.
    admit_ctx: ?*anyopaque = null,
    /// Optional per-`source_id` cap on live subscriptions, enforced only by
    /// `tryRegister`. `0` (default) = unlimited. Bounds how much of the table
    /// one admitted peer can occupy, so it can't monopolize (and thereby evict)
    /// the shared FIFO even once admitted.
    max_per_source: usize = 0,
    /// RFC 7641 §7's notification budget, consulted by `notificationType`: how
    /// many notifications may go out non-confirmable between two
    /// acknowledgements from the client. On by default
    /// (`default_max_non_between_acks`); `0` makes every notification
    /// confirmable. `null` switches the budget off — §7 scopes the MUST to a
    /// server "without client authentication", so only do that for clients the
    /// caller has authenticated (DTLS). The 24-hour rule applies either way.
    max_non_between_acks: ?u32 = default_max_non_between_acks,

    pub const Entry = struct {
        token_buf: [coap.max_token_len]u8 = undefined,
        token_len: u8 = 0,
        resource: u64 = 0,
        /// The sequence number stamped on the last notification for this entry.
        last_seq: u24 = 0,
        /// Client-local time (ms) at which `last_seq` was accepted — T1 in RFC
        /// 7641 §3.4. Stamped by `register`/`tryRegister` and advanced by
        /// `notify`; it is what makes §3.4's third condition expressible at all.
        last_ms: u64 = 0,
        /// The caller-supplied peer identity that registered this entry (`0`
        /// when registered via the plain `register` primitive, which does not
        /// take one). Used only by `tryRegister`'s per-source cap.
        source_id: u64 = 0,
        /// Notifications `notificationType` has let go out non-confirmable
        /// since the client last acknowledged one (`acknowledged`).
        non_since_ack: u32 = 0,
        /// When the client last confirmed its interest: the registration, or
        /// the last `acknowledged` call. Drives §4.5's 24-hour rule.
        last_ack_ms: u64 = 0,

        pub fn token(e: *const Entry) []const u8 {
            return e.token_buf[0..e.token_len];
        }
    };

    /// The result of feeding an arriving notification's sequence to `notify`.
    pub const Update = enum {
        /// Fresh — newer than the last seen; `last_seq` advanced.
        accepted,
        /// Stale or out-of-order — rejected (RFC 7641 §3.4); `last_seq` unchanged.
        stale,
    };

    /// Initialize over caller storage.
    pub fn init(storage: []Entry) Registry {
        return .{ .entries = storage };
    }

    fn find(self: *Registry, tok: []const u8, resource: u64) ?*Entry {
        for (self.entries[0..self.len]) |*e| {
            if (e.resource == resource and std.mem.eql(u8, e.token(), tok)) return e;
        }
        return null;
    }

    /// Register (or refresh) a subscription for `(tok, resource)` with the
    /// initial notification's `seq`. On a full registry the oldest entry is
    /// evicted (FIFO). Returns the live entry.
    ///
    /// Unconditional: ignores `admit_fn`/`max_per_source` entirely. This is
    /// the right primitive when the caller has already gated admission itself
    /// (or trusts its transport, e.g. a private link). On an untrusted
    /// transport, prefer `tryRegister`, which checks that policy first — see
    /// the module doc comment.
    pub fn register(self: *Registry, tok: []const u8, resource: u64, seq: u24, now_ms: u64) *Entry {
        return self.registerRaw(0, tok, resource, seq, now_ms);
    }

    /// Admission-checked registration: the entry point to use on an untrusted
    /// (plain UDP) transport. `source_id` is the caller's opaque, ideally
    /// DTLS-authenticated peer identity (module doc comment).
    ///
    /// Returns `null` — and leaves the table completely untouched, so no
    /// existing subscription is evicted — when either:
    /// - `admit_fn` is set and returns `false` for this `(source_id, tok,
    ///   resource)`, or
    /// - `max_per_source` is set (nonzero) and `source_id` already holds that
    ///   many *distinct* subscriptions (a refresh of an existing one never
    ///   counts against the cap).
    ///
    /// Otherwise behaves like `register` (including FIFO eviction of some
    /// *other* source's oldest entry if the table is full — the cap bounds one
    /// source's share, it does not reserve table space).
    pub fn tryRegister(self: *Registry, source_id: u64, tok: []const u8, resource: u64, seq: u24, now_ms: u64) ?*Entry {
        if (self.admit_fn) |admit| {
            if (!admit(self.admit_ctx, source_id, tok, resource)) return null;
        }
        if (self.max_per_source > 0 and self.find(tok, resource) == null) {
            var live: usize = 0;
            for (self.entries[0..self.len]) |e| {
                if (e.source_id == source_id) live += 1;
            }
            if (live >= self.max_per_source) return null;
        }
        return self.registerRaw(source_id, tok, resource, seq, now_ms);
    }

    fn registerRaw(self: *Registry, source_id: u64, tok: []const u8, resource: u64, seq: u24, now_ms: u64) *Entry {
        if (self.find(tok, resource)) |e| {
            e.last_seq = seq;
            e.last_ms = now_ms;
            return e;
        }
        const slot = if (self.len < self.entries.len) blk: {
            const e = &self.entries[self.len];
            self.len += 1;
            break :blk e;
        } else blk: {
            // Full: evict the oldest (index 0), shift the rest down.
            std.mem.copyForwards(Entry, self.entries[0 .. self.len - 1], self.entries[1..self.len]);
            break :blk &self.entries[self.len - 1];
        };
        slot.* = .{};
        slot.token_len = @intCast(@min(tok.len, coap.max_token_len));
        @memcpy(slot.token_buf[0..slot.token_len], tok[0..slot.token_len]);
        slot.resource = resource;
        slot.last_seq = seq;
        slot.last_ms = now_ms;
        slot.source_id = source_id;
        slot.last_ack_ms = now_ms;
        return slot;
    }

    /// A notification carrying `seq` arrived for `(tok, resource)`. Returns null
    /// when there is no such subscription, else whether it is fresh (`accepted`,
    /// `last_seq` advanced) or stale/out-of-order (`stale`, rejected).
    pub fn notify(self: *Registry, tok: []const u8, resource: u64, seq: u24, now_ms: u64) ?Update {
        const e = self.find(tok, resource) orelse return null;
        if (isNewerAt(e.last_seq, e.last_ms, seq, now_ms)) {
            e.last_seq = seq;
            e.last_ms = now_ms;
            return .accepted;
        }
        return .stale;
    }

    /// The message type the server's push path MUST use for the next
    /// notification on `(tok, resource)` — RFC 7641 §7 and §4.5. Returns null
    /// when there is no such subscription.
    ///
    /// `.confirmable` once `max_non_between_acks` notifications have gone out
    /// non-confirmable since the client last acknowledged one, or once
    /// `max_con_interval_ms` has passed since it last did; it keeps returning
    /// `.confirmable` until the caller reports an ACK via `acknowledged`.
    /// Otherwise `.non_confirmable`, and the call counts that notification
    /// against the budget — so call it once per notification actually sent.
    /// A CON notification that times out or draws a Reset still ends the
    /// subscription through `cancel` (module doc comment).
    pub fn notificationType(self: *Registry, tok: []const u8, resource: u64, now_ms: u64) ?coap.Type {
        const e = self.find(tok, resource) orelse return null;
        if (now_ms -| e.last_ack_ms >= max_con_interval_ms) return .confirmable;
        if (self.max_non_between_acks) |max| {
            if (e.non_since_ack >= max) return .confirmable;
        }
        e.non_since_ack +|= 1;
        return .non_confirmable;
    }

    /// The client acknowledged a confirmable notification on `(tok, resource)`
    /// — its interest is confirmed, so the §7 budget and the §4.5 clock start
    /// over. Returns whether such a subscription exists.
    pub fn acknowledged(self: *Registry, tok: []const u8, resource: u64, now_ms: u64) bool {
        const e = self.find(tok, resource) orelse return false;
        e.non_since_ack = 0;
        e.last_ack_ms = now_ms;
        return true;
    }

    /// Cancel a subscription — a client Observe:1 (deregister) GET, or a
    /// RST/timeout on a CON notification. Returns whether an entry was removed.
    pub fn cancel(self: *Registry, tok: []const u8, resource: u64) bool {
        for (self.entries[0..self.len], 0..) |*e, i| {
            if (e.resource == resource and std.mem.eql(u8, e.token(), tok)) {
                std.mem.copyForwards(Entry, self.entries[i .. self.len - 1], self.entries[i + 1 .. self.len]);
                self.len -= 1;
                return true;
            }
        }
        return false;
    }

    /// Number of active subscriptions.
    pub fn count(self: *const Registry) usize {
        return self.len;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A fixed client-local "now" for the tests that do not care about time. It is
/// deliberately NOT zero: `notify`'s §3.4 third condition compares against the
/// entry's `last_ms`, and starting the clock at 0 would make every first
/// notification older than the 128 s window and so trivially fresh — the tests
/// would then pass without the sequence comparison running at all.
const t0: u64 = 1_000_000;

/// Serialize `note`, parse it back (a real in-memory round-trip), assert its
/// payload, and return the Observe sequence it carried.
fn roundTripNotificationSeq(note: coap.Message, expect_payload: []const u8) !u24 {
    var wire: [128]u8 = undefined;
    const n = try coap.serialize(note, &wire);
    var opts: [8]coap.Option = undefined;
    const parsed = try coap.parse(wire[0..n], &opts);
    try testing.expectEqualStrings(expect_payload, parsed.payload);
    var seq: ?u24 = null;
    for (parsed.options) |o| {
        if (o.number == coap.options.number.observe) seq = try decodeValue(o.value);
    }
    return seq orelse error.MissingObserveOption;
}

test "Sequence: monotonic, wraps at 24 bits" {
    var s = Sequence{};
    try testing.expectEqual(@as(u24, 0), s.next());
    try testing.expectEqual(@as(u24, 1), s.next());
    try testing.expectEqual(@as(u24, 2), s.next());

    var w = Sequence{ .value = max_sequence };
    try testing.expectEqual(max_sequence, w.next());
    try testing.expectEqual(@as(u24, 0), w.next()); // wrapped
}

test "isNewer: forward, stale, and wrap-around" {
    try testing.expect(isNewer(0, 1));
    try testing.expect(isNewer(1, 2));
    try testing.expect(!isNewer(2, 1)); // out of order
    try testing.expect(!isNewer(5, 5)); // equal is not newer
    // Wrap: a small value just past the top is newer than a value near the top.
    try testing.expect(isNewer(max_sequence, 0));
    try testing.expect(!isNewer(0, max_sequence));
}

test "encodeValue/decodeValue round-trip (minimal, no leading zeros)" {
    var buf: [3]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{}, encodeValue(0, &buf));
    try testing.expectEqualSlices(u8, &.{60}, encodeValue(60, &buf));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, encodeValue(256, &buf));
    for ([_]u24{ 0, 1, 255, 256, 65535, 65536, max_sequence }) |v| {
        const enc = encodeValue(v, &buf);
        if (enc.len > 0) try testing.expect(enc[0] != 0);
        try testing.expectEqual(v, try decodeValue(enc));
    }
}

test "Registry: register, freshness-checked notify, cancel" {
    var storage: [4]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    const tok = "\x01\x02\x03\x04";
    _ = reg.register(tok, 42, 0, t0); // initial notification seq 0
    try testing.expectEqual(@as(usize, 1), reg.count());

    // In-order notifications are accepted and advance last_seq.
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 1, t0).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 2, t0).?);
    // A replayed/out-of-order seq is rejected.
    try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, 1, t0).?);
    try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, 2, t0).?);

    // Unknown (token, resource) → null.
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify(tok, 99, 3, t0));
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("zzzz", 42, 3, t0));

    // Cancel removes exactly the one entry.
    try testing.expect(reg.cancel(tok, 42));
    try testing.expectEqual(@as(usize, 0), reg.count());
    try testing.expect(!reg.cancel(tok, 42)); // already gone
}

test "TEETH: one forged notification cannot blind a subscription for good (RFC 7641 §3.4)" {
    // §3.4's freshness test has THREE conditions; only the first two are about
    // sequence numbers. Without the third, a single spoofed datagram carrying
    // 2^23 - 1 — "newer" than every value in [0, 2^23) and so needing no
    // knowledge of the current sequence at all — makes every genuine
    // notification that follows read as stale, permanently. On plain UDP the
    // attacker needs only the token and the resource, and `find` keys on those
    // two alone; it never sees a source address.
    var storage: [2]Registry.Entry = undefined;
    var reg = Registry.init(&storage);
    const tok = "\x01\x02";

    _ = reg.register(tok, 42, 0, t0);
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 1, t0).?);

    // The forged notification is accepted — it IS "newer" in serial arithmetic,
    // and nothing here can tell it from a legitimate jump.
    const forged: u24 = (1 << 23) - 1;
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, forged, t0).?);

    // Within the reordering window the genuine stream now reads as stale. That
    // is correct behaviour for a reorder and is exactly the wedge for a spoof.
    var seq: u24 = 2;
    while (seq < 200) : (seq += 1) {
        try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, seq, t0 + 1000).?);
    }

    // The recovery: past 128 s with nothing accepted, the sequence numbers are
    // not consulted at all and the subscription un-wedges. This is the arm the
    // module used to be structurally unable to express — `Entry` had no
    // timestamp, so no caller could have implemented it either.
    // 128 s is the RFC's number, not ours, so it is written here as a LITERAL.
    // Expressed as `t0 + reordering_window_ms + 1` this test scales with the
    // constant it is supposed to pin and stays green however far the window is
    // moved — checked, and it did (widening it to ~4 years left the suite green).
    const later = t0 + 128_001;
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 2, later).?);
    // …and normal service resumes from there.
    try testing.expectEqual(Registry.Update.accepted, reg.notify(tok, 42, 3, later).?);
    try testing.expectEqual(Registry.Update.stale, reg.notify(tok, 42, 2, later).?);
}

test "TEETH: the reordering window is a boundary, not a door left open" {
    // Anything at or below 128 s must still go through the sequence comparison —
    // otherwise the recovery path would swallow the reorder rejection whole.
    var storage: [1]Registry.Entry = undefined;
    var reg = Registry.init(&storage);
    _ = reg.register("t", 1, 100, t0);

    try testing.expectEqual(Registry.Update.stale, reg.notify("t", 1, 50, t0).?);
    // Literals again, for the same reason: RFC 7641 §3.4 says 128 seconds.
    try testing.expectEqual(Registry.Update.stale, reg.notify("t", 1, 50, t0 + 128_000).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify("t", 1, 50, t0 + 128_001).?);
    // And the constant itself is the RFC's value, so a future edit to it is a
    // spec change and must be argued as one.
    try testing.expectEqual(@as(u64, 128_000), reordering_window_ms);

    // `isNewerAt` agrees with `isNewer` whenever the clock has not moved, so the
    // new condition is strictly additive.
    try testing.expect(isNewerAt(100, t0, 101, t0) == isNewer(100, 101));
    try testing.expect(isNewerAt(100, t0, 50, t0) == isNewer(100, 50));
}

test "TEETH: an over-long Observe option value is refused, not folded to a chosen outcome" {
    // Taking the last three bytes let the attacker pick register-vs-deregister
    // by choosing the padding: the same four bytes in two orders decoded to the
    // two opposite requests, while a conformant peer rejects both. `coap.parse`
    // puts no length limit on an option value, so these arrive straight off the
    // wire.
    try testing.expectError(error.OptionValueTooLong, decodeValue(&[_]u8{ 0, 0, 0, 1 }));
    try testing.expectError(error.OptionValueTooLong, decodeValue(&[_]u8{ 1, 0, 0, 0 }));
    try testing.expectError(error.OptionValueTooLong, decodeValue(&[_]u8{ 9, 9, 9, 9, 9, 0, 0, 0 }));

    // The legal lengths are untouched, including the empty value (= 0 = register).
    try testing.expectEqual(@as(u24, 0), try decodeValue(&[_]u8{}));
    try testing.expectEqual(@as(u24, 1), try decodeValue(&[_]u8{1}));
    try testing.expectEqual(@as(u24, 0x0102), try decodeValue(&[_]u8{ 1, 2 }));
    try testing.expectEqual(@as(u24, 0x010203), try decodeValue(&[_]u8{ 1, 2, 3 }));
}

test "Registry: FIFO eviction when full, re-register refreshes" {
    var storage: [2]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    _ = reg.register("a", 1, 0, t0);
    _ = reg.register("b", 2, 0, t0);
    _ = reg.register("c", 3, 0, t0); // full → evicts the oldest ("a",1)
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("a", 1, 5, t0)); // evicted
    try testing.expectEqual(Registry.Update.accepted, reg.notify("b", 2, 5, t0).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify("c", 3, 5, t0).?);

    // Re-registering an existing key updates in place (no growth).
    _ = reg.register("b", 2, 10, t0);
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expectEqual(Registry.Update.stale, reg.notify("b", 2, 9, t0).?); // 9 < 10
    try testing.expectEqual(Registry.Update.accepted, reg.notify("b", 2, 11, t0).?);
}

fn denyAll(_: ?*anyopaque, _: u64, _: []const u8, _: u64) bool {
    return false;
}

fn admitSourceOne(_: ?*anyopaque, source_id: u64, _: []const u8, _: u64) bool {
    return source_id == 1;
}

test "Registry.tryRegister: default (no hook, no cap) matches register" {
    var storage: [2]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    try testing.expect(reg.tryRegister(1, "a", 1, 0, t0) != null);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expectEqual(Registry.Update.accepted, reg.notify("a", 1, 1, t0).?);
}

test "Registry.tryRegister: rejected admission does not register and does not evict" {
    var storage: [2]Registry.Entry = undefined;
    var reg = Registry.init(&storage);

    // A legitimate subscription is already in place.
    _ = reg.register("a", 1, 0, t0);
    try testing.expectEqual(@as(usize, 1), reg.count());

    reg.admit_fn = denyAll;
    try testing.expectEqual(@as(?*Registry.Entry, null), reg.tryRegister(2, "b", 2, 0, t0));
    // Rejected: nothing new registered, and the existing entry survives untouched.
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expectEqual(Registry.Update.accepted, reg.notify("a", 1, 1, t0).?);
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("b", 2, 0, t0));
}

test "Registry.tryRegister: admitted source registers normally, even when the table is full" {
    var storage: [1]Registry.Entry = undefined;
    var reg = Registry.init(&storage);
    reg.admit_fn = admitSourceOne;

    // source_id 2 is not admitted.
    try testing.expectEqual(@as(?*Registry.Entry, null), reg.tryRegister(2, "x", 1, 0, t0));
    try testing.expectEqual(@as(usize, 0), reg.count());

    // source_id 1 is admitted and registers (and may still FIFO-evict another
    // *admitted* source's entry once the table is full — the hook gates
    // whether an entry is added at all, not the table's eviction policy).
    try testing.expect(reg.tryRegister(1, "y", 2, 0, t0) != null);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expectEqual(Registry.Update.accepted, reg.notify("y", 2, 1, t0).?);
}

test "Registry.tryRegister: per-source cap bounds one source's share without evicting" {
    var storage: [4]Registry.Entry = undefined;
    var reg = Registry.init(&storage);
    reg.max_per_source = 2;

    try testing.expect(reg.tryRegister(1, "a", 1, 0, t0) != null);
    try testing.expect(reg.tryRegister(1, "b", 2, 0, t0) != null);
    try testing.expectEqual(@as(usize, 2), reg.count());

    // A third distinct subscription from the same source hits the cap and is
    // rejected — the two existing entries for source 1 are untouched.
    try testing.expectEqual(@as(?*Registry.Entry, null), reg.tryRegister(1, "c", 3, 0, t0));
    try testing.expectEqual(@as(usize, 2), reg.count());
    try testing.expectEqual(Registry.Update.accepted, reg.notify("a", 1, 1, t0).?);
    try testing.expectEqual(Registry.Update.accepted, reg.notify("b", 2, 1, t0).?);
    try testing.expectEqual(@as(?Registry.Update, null), reg.notify("c", 3, 0, t0));

    // A refresh of an already-held subscription is not new share and is not
    // capped.
    try testing.expect(reg.tryRegister(1, "a", 1, 5, t0) != null);
    try testing.expectEqual(@as(usize, 2), reg.count());

    // A different, uncapped source can still register freely.
    try testing.expect(reg.tryRegister(2, "d", 4, 0, t0) != null);
    try testing.expectEqual(@as(usize, 3), reg.count());
}

test "TEETH: RFC 7641 §7 — non-confirmable notifications are interspersed with confirmable ones" {
    var store: [2]Registry.Entry = undefined;
    var reg = Registry.init(&store);
    try testing.expectEqual(@as(?u32, 5), reg.max_non_between_acks); // on by default
    _ = reg.register("t", 1, 0, t0);

    for (0..5) |_| try testing.expectEqual(coap.Type.non_confirmable, reg.notificationType("t", 1, t0).?);
    // Budget spent: confirmable, and it STAYS confirmable until an ACK arrives.
    try testing.expectEqual(coap.Type.confirmable, reg.notificationType("t", 1, t0).?);
    try testing.expectEqual(coap.Type.confirmable, reg.notificationType("t", 1, t0).?);

    try testing.expect(reg.acknowledged("t", 1, t0));
    try testing.expectEqual(coap.Type.non_confirmable, reg.notificationType("t", 1, t0).?);

    // Zero means every notification is confirmable.
    reg.max_non_between_acks = 0;
    try testing.expect(reg.acknowledged("t", 1, t0));
    try testing.expectEqual(coap.Type.confirmable, reg.notificationType("t", 1, t0).?);

    try testing.expect(reg.notificationType("absent", 1, t0) == null);
    try testing.expect(!reg.acknowledged("absent", 1, t0));
}

test "TEETH: RFC 7641 §4.5 — a confirmable notification at least every 24 hours, budget off or not" {
    var store: [1]Registry.Entry = undefined;
    var reg = Registry.init(&store);
    reg.max_non_between_acks = null; // an authenticated client: no §7 budget
    // Not zero: an entry whose registration time was never stamped would read
    // as more than a day old and fail the first assertion.
    const start: u64 = 25 * 60 * 60 * 1000;
    _ = reg.register("t", 1, 0, start);

    for (0..1000) |_| {
        try testing.expectEqual(coap.Type.non_confirmable, reg.notificationType("t", 1, start + max_con_interval_ms - 1).?);
    }
    try testing.expectEqual(coap.Type.confirmable, reg.notificationType("t", 1, start + max_con_interval_ms).?);
    try testing.expect(reg.acknowledged("t", 1, start + max_con_interval_ms));
    try testing.expectEqual(coap.Type.non_confirmable, reg.notificationType("t", 1, start + max_con_interval_ms + 1).?);
}

test "C7 end-to-end: observe register → notifications → freshness → cancel" {
    const num = coap.options.number;

    const token = "\x0A\x0B\x0C\x0D";
    const resource: u64 = 0x57A7; // stand-in for a Uri-Path hash

    var srv = coap.server.Server.init(0xC000);
    var seq = Sequence{};

    var sub_store: [4]Registry.Entry = undefined;
    var reg = Registry.init(&sub_store); // server subscription table
    var view_store: [4]Registry.Entry = undefined;
    var view = Registry.init(&view_store); // the client's freshness view

    // 1. client → GET /status with Observe: register (value 0 → empty).
    var obuf: [3]u8 = undefined;
    const get: coap.Message = .{
        .type = .confirmable,
        .code = .get,
        .message_id = 0x01,
        .token = token,
        .options = &.{
            .{ .number = num.observe, .value = encodeValue(request.register, &obuf) },
            .{ .number = num.uri_path, .value = "status" },
        },
    };
    var gwire: [64]u8 = undefined;
    const glen = try coap.serialize(get, &gwire);

    // 2. server parses, confirms it is a register, and registers + notifies.
    var sopts: [8]coap.Option = undefined;
    const sget = try coap.parse(gwire[0..glen], &sopts);
    var registering = false;
    for (sget.options) |o| {
        if (o.number == num.observe) registering = (try decodeValue(o.value)) == request.register;
    }
    try testing.expect(registering);

    const s0 = seq.next(); // 0
    _ = reg.register(sget.token, resource, s0, t0);
    try testing.expectEqual(@as(usize, 1), reg.count());
    {
        var nbuf: [3]u8 = undefined;
        const note = srv.separate(sget, .content, &.{
            .{ .number = num.observe, .value = encodeValue(s0, &nbuf) },
        }, "v0", false);
        const cs = try roundTripNotificationSeq(note, "v0");
        _ = view.register(sget.token, resource, cs, t0); // client records the initial seq
    }

    // 3. two resource changes → two notifications with increasing seq, accepted.
    inline for (.{ "v1", "v2" }) |p| {
        const s = seq.next();
        var nbuf: [3]u8 = undefined;
        const note = srv.separate(sget, .content, &.{
            .{ .number = num.observe, .value = encodeValue(s, &nbuf) },
        }, p, false);
        const cs = try roundTripNotificationSeq(note, p);
        try testing.expectEqual(Registry.Update.accepted, view.notify(token, resource, cs, t0).?);
    }

    // 4. an out-of-order (stale) notification is rejected by the client.
    try testing.expectEqual(Registry.Update.stale, view.notify(token, resource, 1, t0).?);

    // 5. cancellation (an Observe:1 deregister GET, or a RST) removes the entry.
    try testing.expect(reg.cancel(sget.token, resource));
    try testing.expectEqual(@as(usize, 0), reg.count());
}

test "C7 reliability glue: a dead CON notification cancels the subscription" {
    const reliability = coap.reliability;

    var sub_store: [2]Registry.Entry = undefined;
    var reg = Registry.init(&sub_store);
    const token = "\x01";
    const resource: u64 = 7;

    // A CON notification whose Retransmit exhausts (.timed_out) → cancel.
    _ = reg.register(token, resource, 0, t0);
    var rt = reliability.Retransmit.init(.{ .max_retransmit = 0 }, 0, 0);
    try testing.expectEqual(reliability.Retransmit.Action.timed_out, rt.poll(2000));
    if (rt.isDone()) _ = reg.cancel(token, resource);
    try testing.expectEqual(@as(usize, 0), reg.count());

    // A CON notification answered with a Reset (.reset) → cancel.
    _ = reg.register(token, resource, 0, t0);
    var rt2 = reliability.Retransmit.init(.{}, 0, 0);
    rt2.onReset();
    if (rt2.isDone()) _ = reg.cancel(token, resource);
    try testing.expectEqual(@as(usize, 0), reg.count());
}
