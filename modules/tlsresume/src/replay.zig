// SPDX-License-Identifier: MIT

//! tlsresume.replay — ticket-age obfuscation/freshness (RFC 8446 §4.2.11.1)
//! and anti-replay (RFC 8446 §8, §8.1/§8.2).
//!
//! **`obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow` are REAL** —
//! pure `wrapping` arithmetic and a comparison, no key material and no
//! crypto judgment call, so (unlike `psk.zig`) they are implemented here
//! rather than left for the crypto-implementation pass. Byte-exact against
//! an RFC 8448 §4 vector (see tests).
//!
//! **`StrikeRegister` is REAL.** RFC 8446 §8 gives three non-exclusive
//! anti-replay strategies for accepting 0-RTT (or, per §8.2 more broadly,
//! any single-use PSK): (1) single-use tickets — track a strike register of
//! already-seen ticket identifiers/PSK binders and reject a repeat; (2)
//! client-hello recording — record enough of the full ClientHello to detect
//! an exact replay within a window; (3) freshness checks alone (§4.2.11.1)
//! as a best-effort, weaker mitigation. This module implements shape (1):
//! a bounded single-use strike register with the following fail-SAFE
//! policy (all failure modes reject resumption, which merely forces a full
//! handshake — never a false accept):
//!
//! - An identifier seen within the last `window_ms` is a replay: reject.
//! - An identifier whose record has aged past `window_ms` is treated as
//!   fresh again (its slot is reusable) — safe because entries older than
//!   the freshness window are exactly the ones `withinFreshnessWindow`
//!   already rejects upstream (a replayed ClientHello carries the ORIGINAL
//!   `obfuscated_ticket_age`, so its reported age falls ever further behind
//!   the server-measured age as time passes).
//! - Memory is hard-bounded at `capacity` entries (RFC 8446 §8 warns that
//!   anti-replay state must not itself become a DoS vector): when full,
//!   expired entries are evicted; if none are expired, the NEW identifier
//!   is rejected (fail-closed) rather than evicting a live entry (which
//!   would re-open the replay window for that live ticket).

const std = @import("std");

/// RFC 8446 §4.2.11.1: `obfuscated_ticket_age = (age_ms + ticket_age_add)
/// mod 2^32`, computed as a client preparing `PskIdentity.obfuscated_ticket_age`.
/// `age_ms` is milliseconds since the ticket was issued; wraparound is the
/// point (RFC 8446 deliberately specifies `mod 2^32`, i.e. Zig's `+%`), not
/// an error condition.
pub fn obfuscateAge(age_ms: u32, ticket_age_add: u32) u32 {
    return age_ms +% ticket_age_add;
}

/// The server-side inverse: recovers `age_ms` from a received
/// `obfuscated_ticket_age` and the `ticket_age_add` this server itself
/// stamped into the ticket at issuance time (RFC 8446 §4.2.11.1).
pub fn deobfuscateAge(obfuscated_ticket_age: u32, ticket_age_add: u32) u32 {
    return obfuscated_ticket_age -% ticket_age_add;
}

/// RFC 8446 §4.2.11.1: the server SHOULD reject 0-RTT if the client's
/// reported age deviates from the server's own measured elapsed time by
/// more than a small window (this bounds replay-via-slow-network-retry, not
/// just clock skew — a large positive deviation means the ticket has aged
/// past what a live client's clock could produce). `window_ms` is the
/// caller's configured tolerance (e.g. a few RTTs); this function makes no
/// clock calls (`actual_age_ms` is caller-measured, per this repo's
/// no-wall-clock-inside-a-module convention — see `dtls.flight`'s
/// caller-clocked timer for the same pattern).
pub fn withinFreshnessWindow(client_reported_age_ms: u32, actual_age_ms: u32, window_ms: u32) bool {
    const diff = if (client_reported_age_ms > actual_age_ms)
        client_reported_age_ms - actual_age_ms
    else
        actual_age_ms - client_reported_age_ms;
    return diff <= window_ms;
}

pub const StrikeRegisterError = error{OutOfMemory};

/// A bounded, single-use strike register (RFC 8446 §8.1's "single-use
/// tickets" anti-replay strategy): `checkAndMark` records a ticket/PSK-binder
/// identifier the first time it is seen and rejects any repeat within
/// `window_ms`. Bounded by `capacity` so a flood of distinct identifiers
/// cannot grow this unboundedly (RFC 8446 §8 warns servers must not let
/// anti-replay state become a DoS vector itself) — see the module doc
/// comment for the full accept/reject/eviction policy and why every failure
/// mode is fail-safe (rejects resumption, never falsely accepts).
pub const StrikeRegister = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    /// How long a seen identifier stays "hot" (rejected as a replay).
    /// Should be >= the freshness window the caller passes to
    /// `withinFreshnessWindow`/`selectPsk` — entries older than that are
    /// already unusable via the freshness check, so evicting them is safe.
    window_ms: i64,
    /// Seen identifiers (keys are owned copies, freed on eviction/deinit)
    /// -> the `now_ms` at which each was first seen.
    seen: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn init(allocator: std.mem.Allocator, capacity: usize, window_ms: i64) StrikeRegister {
        return .{ .allocator = allocator, .capacity = capacity, .window_ms = window_ms };
    }

    pub fn deinit(self: *StrikeRegister) void {
        var it = self.seen.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.seen.deinit(self.allocator);
        self.* = undefined;
    }

    /// Returns `true` if `ticket_id` has NOT been seen before within the
    /// freshness window (accept — and the identifier is now marked seen),
    /// `false` if this is a replay (reject) or if the register is full of
    /// still-live entries (fail-closed; the engine falls back to a full
    /// handshake). `now_ms` is the caller's clock reading, monotone
    /// non-decreasing across calls.
    pub fn checkAndMark(self: *StrikeRegister, ticket_id: []const u8, now_ms: i64) StrikeRegisterError!bool {
        if (self.seen.getPtr(ticket_id)) |first_seen_ms| {
            if (now_ms - first_seen_ms.* <= self.window_ms) return false; // replay
            // Aged out: the freshness check upstream already rejects a
            // ClientHello this old, so re-arming the slot is safe.
            first_seen_ms.* = now_ms;
            return true;
        }

        if (self.seen.count() >= self.capacity) {
            try self.evictExpired(now_ms);
            // Still full of live entries -> fail-closed: reject the NEW
            // identifier rather than evict a live one (which would re-open
            // the replay window for a ticket already accepted once).
            if (self.seen.count() >= self.capacity) return false;
        }

        const owned = try self.allocator.dupe(u8, ticket_id);
        errdefer self.allocator.free(owned);
        try self.seen.put(self.allocator, owned, now_ms);
        return true;
    }

    fn evictExpired(self: *StrikeRegister, now_ms: i64) StrikeRegisterError!void {
        // Collect-then-remove: mutating the map invalidates its iterators.
        // Bounded by `capacity`, so this scratch list is bounded too.
        var expired: std.ArrayList([]const u8) = .empty;
        defer expired.deinit(self.allocator);
        var it = self.seen.iterator();
        while (it.next()) |entry| {
            if (now_ms - entry.value_ptr.* > self.window_ms) {
                try expired.append(self.allocator, entry.key_ptr.*);
            }
        }
        for (expired.items) |key| {
            const removed = self.seen.fetchRemove(key).?;
            self.allocator.free(removed.key);
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 8448 §4 "Resumed 0-RTT Handshake": the resumed ClientHello's
// pre_shared_key extension carries obfuscated_ticket_age = 0xfad6aacb,
// against a ticket_age_add of 0xfad6aac5 (from the §3 NewSessionTicket —
// see ticket.zig's decode test against the same trace). Fetched from
// https://www.rfc-editor.org/rfc/rfc8448 §3/§4.
const rfc8448_ticket_age_add: u32 = 0xfad6aac5;
const rfc8448_obfuscated_ticket_age: u32 = 0xfad6aacb;
// (obfuscated - ticket_age_add) mod 2^32 = 6 — RFC 8448's synthetic trace
// has essentially no elapsed time between issuance and resumption.
const rfc8448_age_ms: u32 = 6;

test "RFC 8448 §3/§4: obfuscateAge/deobfuscateAge round-trip the real vector" {
    try testing.expectEqual(rfc8448_obfuscated_ticket_age, obfuscateAge(rfc8448_age_ms, rfc8448_ticket_age_add));
    try testing.expectEqual(rfc8448_age_ms, deobfuscateAge(rfc8448_obfuscated_ticket_age, rfc8448_ticket_age_add));
}

test "obfuscateAge: wraps mod 2^32 rather than overflowing (RFC 8446 §4.2.11.1)" {
    const age: u32 = 0xFFFF_FFFF;
    const add: u32 = 2;
    try testing.expectEqual(@as(u32, 1), obfuscateAge(age, add));
    try testing.expectEqual(age, deobfuscateAge(1, add));
}

test "withinFreshnessWindow: accepts small deviation, rejects large, either direction" {
    try testing.expect(withinFreshnessWindow(1000, 1010, 50));
    try testing.expect(withinFreshnessWindow(1010, 1000, 50));
    try testing.expect(!withinFreshnessWindow(1000, 2000, 50));
    try testing.expect(withinFreshnessWindow(500, 500, 0)); // exact match, zero window
}

test "StrikeRegister: rejects a replayed identifier, accepts distinct ones" {
    var reg = StrikeRegister.init(testing.allocator, 8, 10_000);
    defer reg.deinit();

    try testing.expect(try reg.checkAndMark("ticket-a", 0)); // first sight: accept
    try testing.expect(!try reg.checkAndMark("ticket-a", 5)); // replay: reject
    try testing.expect(try reg.checkAndMark("ticket-b", 10)); // distinct: accept
    try testing.expect(!try reg.checkAndMark("ticket-b", 15)); // and single-use too
    try testing.expect(!try reg.checkAndMark("ticket-a", 9_999)); // still hot at window edge
}

test "StrikeRegister: capacity is honored — full of live entries fail-closes on new ids" {
    var reg = StrikeRegister.init(testing.allocator, 2, 10_000);
    defer reg.deinit();

    try testing.expect(try reg.checkAndMark("ticket-a", 0));
    try testing.expect(try reg.checkAndMark("ticket-b", 1));
    // Full, nothing expired: a NEW id is rejected (fail-closed), and the
    // live entries keep their replay protection.
    try testing.expect(!try reg.checkAndMark("ticket-c", 2));
    try testing.expect(!try reg.checkAndMark("ticket-a", 3));
    try testing.expectEqual(@as(usize, 2), reg.seen.count());
}

test "StrikeRegister: expired entries are evicted, memory stays bounded" {
    var reg = StrikeRegister.init(testing.allocator, 2, 1_000);
    defer reg.deinit();

    try testing.expect(try reg.checkAndMark("ticket-a", 0));
    try testing.expect(try reg.checkAndMark("ticket-b", 100));
    // Past the window: a & b are stale; the full register evicts them to
    // admit c instead of rejecting or growing.
    try testing.expect(try reg.checkAndMark("ticket-c", 2_000));
    try testing.expect(reg.seen.count() <= 2);
    // A stale id re-presented after its record aged out is accepted again
    // (safe: withinFreshnessWindow rejects such a ClientHello upstream) and
    // is single-use from its new first-seen time.
    try testing.expect(try reg.checkAndMark("ticket-a", 2_100));
    try testing.expect(!try reg.checkAndMark("ticket-a", 2_200));
    try testing.expect(reg.seen.count() <= 2);
}
