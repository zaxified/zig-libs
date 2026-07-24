// SPDX-License-Identifier: MIT

//! Bounded sliding-window anti-replay filter for `aeadframe`.
//!
//! The classic IPsec-ESP / DTLS 1.3 (RFC 6479 / RFC 9147 §5) sequence-number
//! window: a high-water mark plus a fixed-width bitmap of which of the recent
//! `size` sequence numbers below it have already been accepted. `size` is
//! bounded to 64 by the `u64` bitmap backing — a conscious ceiling, not a bug.
//!
//! The filter is **advisory until an AEAD tag has verified**: `accepts` is a
//! read-only pre-check, and `commit` records a sequence number. A caller MUST
//! `accepts` → verify the AEAD → `commit`, and never `commit` a sequence
//! number whose record failed authentication. Committing an unverified number
//! would let an on-path attacker "burn" a future window slot with a forged
//! record and get the legitimate one rejected as a replay it never was.
//!
//! Implemented independently for this module (no dependency on the sibling
//! replay windows in `oscore` / `snmp` / `iec62351`); it re-derives the same
//! well-known algorithm.

const std = @import("std");

/// Default and maximum trackable window width.
pub const default_window: u7 = 64;

pub const ReplayWindow = struct {
    /// Highest sequence number ever committed.
    highest: u64 = 0,
    /// Bit `i` set ⇒ `highest - (i + 1)` has been committed. Only the low
    /// `eff()` bits are meaningful.
    bitmap: u64 = 0,
    /// False until the first `commit`; before that the window has no
    /// high-water mark and `accepts` admits any sequence number.
    started: bool = false,
    /// Configured width. Clamped to 64 (the bitmap's capacity) by `eff`.
    size: u7 = default_window,

    /// Effective width: `size` capped at 64 so a `diff`/`shift` in 64..127
    /// never `@intCast`es to `u6` and panics on a hostile sequence number.
    fn eff(self: ReplayWindow) u7 {
        return @min(self.size, 64);
    }

    /// Would `seq` be accepted right now? Read-only. `true` iff `seq` is a new
    /// high, or within the window and not yet committed. A caller MUST still
    /// verify the record's AEAD tag before trusting/committing it.
    pub fn accepts(self: ReplayWindow, seq: u64) bool {
        if (!self.started) return true;
        if (seq > self.highest) return true; // ahead of the window: fresh
        const diff = self.highest - seq;
        if (diff == 0) return false; // exact duplicate of the high-water mark
        if (diff > self.eff()) return false; // fell off the trailing edge
        const bit = @as(u64, 1) << @intCast(diff - 1);
        return (self.bitmap & bit) == 0;
    }

    /// Record `seq` as accepted, sliding the window forward if it is a new
    /// high. MUST only be called after the record's AEAD tag has verified.
    /// Idempotent for an already-recorded `seq`; a no-op for one that has
    /// fallen out of the window.
    pub fn commit(self: *ReplayWindow, seq: u64) void {
        if (!self.started) {
            self.highest = seq;
            self.bitmap = 0;
            self.started = true;
            return;
        }
        if (seq > self.highest) {
            const shift = seq - self.highest;
            if (shift >= self.eff()) {
                self.bitmap = 0; // window jumped clear of every old bit
            } else {
                const amt: u6 = @intCast(shift);
                // The old high-water mark now sits at bit (shift - 1); the rest
                // of the old bitmap shifts up alongside it.
                self.bitmap = (self.bitmap << amt) | (@as(u64, 1) << @intCast(shift - 1));
            }
            self.highest = seq;
        } else if (seq < self.highest) {
            const diff = self.highest - seq;
            if (diff <= self.eff()) {
                self.bitmap |= @as(u64, 1) << @intCast(diff - 1);
            }
        }
        // seq == highest: already implicitly recorded; nothing to do.
    }

    /// Drop all history (used on an epoch change — the nonce space is fresh,
    /// so the old sequence numbers are meaningless). Preserves `size`.
    pub fn reset(self: *ReplayWindow) void {
        self.* = .{ .size = self.size };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "fresh window accepts anything; first commit sets the mark" {
    var w = ReplayWindow{};
    try testing.expect(w.accepts(0));
    try testing.expect(w.accepts(1_000_000));
    w.commit(10);
    try testing.expect(!w.accepts(10)); // now a duplicate
    try testing.expect(w.accepts(11));
}

test "in-window replay rejected, reordered-but-fresh accepted, window advances" {
    var w = ReplayWindow{};
    w.commit(100);
    // Reordered-but-fresh below the mark:
    try testing.expect(w.accepts(98));
    w.commit(98);
    try testing.expect(!w.accepts(98)); // now a replay
    try testing.expect(!w.accepts(100)); // the mark itself is a replay
    // A jump forward advances the window; old committed bits ride along.
    w.commit(130);
    try testing.expect(!w.accepts(100)); // still remembered (diff 30 <= 64)
    try testing.expect(w.accepts(129)); // fresh, within window
}

test "too-old (out of window) rejected" {
    var w = ReplayWindow{ .size = 8 };
    w.commit(100);
    try testing.expect(!w.accepts(91)); // diff 9 > 8
    try testing.expect(w.accepts(92)); // diff 8 == window edge, unseen
    try testing.expect(w.accepts(100 - 8));
}

// A brute-force reference oracle: a plain set of committed sequence numbers,
// with the same "older than window ⇒ dropped" rule. The bitmap window must
// agree with it on `accepts` for every step of a randomised trace.
const RefOracle = struct {
    seen: std.AutoHashMap(u64, void),
    highest: u64 = 0,
    started: bool = false,
    size: u64,

    fn accepts(self: *RefOracle, seq: u64) bool {
        if (!self.started) return true;
        if (seq > self.highest) return true;
        if (self.highest - seq > self.size) return false;
        return self.seen.get(seq) == null;
    }
    fn commit(self: *RefOracle, seq: u64) void {
        self.seen.put(seq, {}) catch unreachable;
        if (!self.started or seq > self.highest) {
            self.highest = seq;
            self.started = true;
        }
    }
};

test "bitmap window agrees with a reference set over a randomised trace" {
    inline for (.{ 8, 32, 64 }) |sz| {
        var w = ReplayWindow{ .size = sz };
        var ref = RefOracle{ .seen = std.AutoHashMap(u64, void).init(testing.allocator), .size = sz };
        defer ref.seen.deinit();

        var prng = std.Random.DefaultPrng.init(0xA11CE + sz);
        const rnd = prng.random();
        var base: u64 = 0;
        for (0..4000) |_| {
            // Draw a sequence number near the moving frontier: mostly ahead,
            // sometimes within/behind the window, occasionally far behind.
            const roll = rnd.intRangeAtMost(u8, 0, 99);
            const seq: u64 = if (roll < 55)
                base + rnd.intRangeAtMost(u64, 1, 3) // advance
            else if (roll < 90)
                base -| rnd.intRangeAtMost(u64, 0, sz + 4) // in/near window
            else
                base -| rnd.intRangeAtMost(u64, 0, 500); // far behind

            try testing.expectEqual(ref.accepts(seq), w.accepts(seq));
            if (w.accepts(seq)) {
                w.commit(seq);
                ref.commit(seq);
                if (seq > base) base = seq;
            }
        }
    }
}

test "boundary sweep at exactly the window edge" {
    var w = ReplayWindow{ .size = 64 };
    w.commit(1000);
    // diff == 64 is the last in-window slot; diff == 65 is out.
    try testing.expect(w.accepts(1000 - 64));
    try testing.expect(!w.accepts(1000 - 65));
    w.commit(1000 - 64);
    try testing.expect(!w.accepts(1000 - 64)); // now recorded
    try testing.expect(!w.accepts(1000 - 65)); // still out of window
}

test "oversized size (>64) + hostile diff/shift never panics" {
    var w = ReplayWindow{ .size = 100 };
    w.commit(200);
    try testing.expect(!w.accepts(130)); // diff 70 > eff(64)
    w.commit(130); // diff 70 > eff -> skipped, no panic
    w.commit(270); // shift 70 >= eff -> bitmap reset, no panic
    try testing.expectEqual(@as(u64, 270), w.highest);
}

test "reset drops history but keeps size" {
    var w = ReplayWindow{ .size = 16 };
    w.commit(500);
    w.reset();
    try testing.expect(!w.started);
    try testing.expect(w.accepts(1)); // fresh again
    try testing.expectEqual(@as(u7, 16), w.size);
}
