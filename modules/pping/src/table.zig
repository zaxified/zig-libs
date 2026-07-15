// SPDX-License-Identifier: MIT

//! table — the bounded, allocator-backed store mapping distinct TCP TSvals to
//! the time they were first observed in one (flow, direction). Purely
//! mechanical: `TsTable` has NO opinion about eviction policy, first-echo
//! semantics, or aging cutoffs — those decisions belong entirely to
//! `match.matchEcho` (the Fable core), which is `TsTable`'s only intended
//! caller from within this module. `TsTable` itself guarantees only:
//!
//!   - **Fixed capacity, decided once at `init`.** No reallocation, ever —
//!     the storage is one `gpa.alloc` call sized to the requested capacity;
//!     `insert` fails cleanly with `error.Full` instead of growing. This is
//!     the mechanism `Estimator`'s "no allocator growth tied to stream
//!     length" guarantee rests on (see `root.zig`).
//!   - **Linear-scan lookup/insert/remove.** O(n) in the table's current
//!     occupancy, which is itself bounded by `capacity` — so cost never
//!     grows with how many packets a caller has fed the flow, only with how
//!     many *distinct unmatched* TSvals are outstanding at once (small in
//!     practice: bounded by the flow's bandwidth-delay product in in-flight
//!     segments). A hash map would be the obvious upgrade if profiling ever
//!     shows this matters; nothing above `TsTable` depends on the linear
//!     implementation.
//!   - **No policy.** `insert` never overwrites an existing entry for the
//!     same `tsval` and never evicts on its own to make room — both of those
//!     are algorithmic judgment calls `match.matchEcho` must make explicitly
//!     (see that function's doc contract).

const std = @import("std");
const Allocator = std.mem.Allocator;

/// One stored (tsval, first-seen-time) fact.
pub const Entry = struct {
    tsval: u32,
    first_seen: u64,
};

/// A fixed-capacity, allocator-backed table of `Entry`. See the module doc
/// for what it does and, just as importantly, what it deliberately does not
/// decide.
pub const TsTable = struct {
    /// Backing storage, `capacity` long, allocated once at `init`. Only the
    /// first `len` slots are meaningful.
    entries: []Entry,
    len: usize = 0,

    pub const InitError = Allocator.Error;

    /// Allocate a table that can hold up to `capacity` entries. `capacity`
    /// may be 0 (a table that never accepts an insert) — callers that pass a
    /// nonsensical `Config.capacity` get a table that always reports
    /// `error.Full`, not a crash.
    pub fn init(gpa: Allocator, cap: usize) InitError!TsTable {
        const entries = try gpa.alloc(Entry, cap);
        return .{ .entries = entries, .len = 0 };
    }

    /// Free the backing storage. `self` must not be used afterward.
    pub fn deinit(self: *TsTable, gpa: Allocator) void {
        gpa.free(self.entries);
        self.* = undefined;
    }

    /// The fixed capacity this table was allocated with.
    pub fn capacity(self: *const TsTable) usize {
        return self.entries.len;
    }

    /// Number of entries currently stored (`<= capacity`).
    pub fn count(self: *const TsTable) usize {
        return self.len;
    }

    pub fn isFull(self: *const TsTable) bool {
        return self.len >= self.entries.len;
    }

    /// All live entries, in unspecified order (see `removeAt`'s swap-remove
    /// note). Valid until the next mutating call.
    pub fn items(self: *const TsTable) []const Entry {
        return self.entries[0..self.len];
    }

    /// Index of the (at most one) live entry with this `tsval`, or `null`.
    /// Linear scan — see the module doc for why that is fine here.
    pub fn indexOf(self: *const TsTable, tsval: u32) ?usize {
        for (self.entries[0..self.len], 0..) |e, i| {
            if (e.tsval == tsval) return i;
        }
        return null;
    }

    /// The `first_seen` time recorded for `tsval`, or `null` if not present.
    pub fn get(self: *const TsTable, tsval: u32) ?u64 {
        const idx = self.indexOf(tsval) orelse return null;
        return self.entries[idx].first_seen;
    }

    /// Insert a NEW entry unconditionally. The caller (`match.matchEcho`) is
    /// responsible for having already decided this is correct — i.e. that no
    /// live entry for `tsval` exists yet (see `indexOf`) and that there is
    /// room (see `isFull`) or that making room by eviction is not this
    /// table's job. `error.Full` if `count() == capacity()`; this table never
    /// silently overwrites or grows to make an insert succeed.
    pub fn insert(self: *TsTable, tsval: u32, first_seen: u64) error{Full}!void {
        if (self.len >= self.entries.len) return error.Full;
        self.entries[self.len] = .{ .tsval = tsval, .first_seen = first_seen };
        self.len += 1;
    }

    /// Remove the live entry at `idx` (as returned by `indexOf`). O(1)
    /// swap-remove: the last live entry moves into `idx`, so `items()`'s
    /// order is NOT preserved across a `removeAt` call — callers that need
    /// to keep iterating after a removal must account for that (see
    /// `evictOlderThan`'s "do not advance the cursor" note).
    pub fn removeAt(self: *TsTable, idx: usize) void {
        std.debug.assert(idx < self.len);
        self.len -= 1;
        self.entries[idx] = self.entries[self.len];
    }

    /// Evict every entry whose age (`now -| first_seen`, saturating so a
    /// caller-supplied `now` that is not >= every stored `first_seen` never
    /// underflows into a huge age) exceeds `max_age`. Pure mechanical
    /// sweep — no notion of which entry "matched" anything, just an age
    /// cutoff; `match.matchEcho`'s aging policy is expected to call this
    /// before making any capacity-eviction decision (see that function's
    /// doc). Returns the number of entries evicted.
    pub fn evictOlderThan(self: *TsTable, now: u64, max_age: u64) usize {
        var evicted: usize = 0;
        var i: usize = 0;
        while (i < self.len) {
            const age = now -| self.entries[i].first_seen;
            if (age > max_age) {
                self.removeAt(i);
                evicted += 1;
                // Do not advance `i`: removeAt swapped a fresh (unexamined)
                // entry into this slot.
            } else {
                i += 1;
            }
        }
        return evicted;
    }

    /// Index of the entry with the smallest `first_seen` ("oldest"), or
    /// `null` if empty. A mechanical scan `match.matchEcho` can use to
    /// implement its documented capacity-eviction policy without this table
    /// having to know or care that "evict the oldest" is that policy.
    pub fn oldestIndex(self: *const TsTable) ?usize {
        if (self.len == 0) return null;
        var best: usize = 0;
        var i: usize = 1;
        while (i < self.len) : (i += 1) {
            if (self.entries[i].first_seen < self.entries[best].first_seen) best = i;
        }
        return best;
    }

    /// Empty the table; capacity/allocation is kept.
    pub fn reset(self: *TsTable) void {
        self.len = 0;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "TsTable: empty table has zero count, isFull only at capacity 0" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), t.capacity());
    try testing.expectEqual(@as(usize, 0), t.count());
    try testing.expect(!t.isFull());
    try testing.expectEqual(@as(?usize, null), t.indexOf(42));
    try testing.expectEqual(@as(?u64, null), t.get(42));
    try testing.expectEqual(@as(?usize, null), t.oldestIndex());
}

test "TsTable: capacity 0 always reports Full, never crashes" {
    var t = try TsTable.init(testing.allocator, 0);
    defer t.deinit(testing.allocator);
    try testing.expect(t.isFull());
    try testing.expectError(error.Full, t.insert(1, 100));
}

test "TsTable: insert then get/indexOf round-trip" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(10, 1000);
    try t.insert(20, 2000);
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(@as(?u64, 1000), t.get(10));
    try testing.expectEqual(@as(?u64, 2000), t.get(20));
    try testing.expectEqual(@as(?u64, null), t.get(30));
    try testing.expectEqual(@as(usize, 0), t.indexOf(10).?);
    try testing.expectEqual(@as(usize, 1), t.indexOf(20).?);
}

test "TsTable: insert does not overwrite an existing tsval's first_seen (caller's job to check first)" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(10, 1000);
    // TsTable itself does not forbid a second insert of the same tsval — it
    // is documented as the CALLER's responsibility to check `indexOf` first.
    // Demonstrate that inserting again simply appends a second raw entry
    // (this is why match.matchEcho, not TsTable, owns the "first-seen only"
    // rule): count grows, but `get` (which returns the FIRST match found by
    // `indexOf`'s forward scan) still reports the original entry.
    try t.insert(10, 2000);
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(@as(?u64, 1000), t.get(10));
}

test "TsTable: insert past capacity fails with error.Full and does not corrupt state" {
    var t = try TsTable.init(testing.allocator, 2);
    defer t.deinit(testing.allocator);
    try t.insert(1, 10);
    try t.insert(2, 20);
    try testing.expect(t.isFull());
    try testing.expectError(error.Full, t.insert(3, 30));
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(@as(?u64, 10), t.get(1));
    try testing.expectEqual(@as(?u64, 20), t.get(2));
}

test "TsTable: removeAt swap-removes and keeps remaining entries reachable" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 10);
    try t.insert(2, 20);
    try t.insert(3, 30);
    t.removeAt(t.indexOf(2).?);
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(@as(?u64, null), t.get(2));
    try testing.expectEqual(@as(?u64, 10), t.get(1));
    try testing.expectEqual(@as(?u64, 30), t.get(3));
}

test "TsTable: removeAt on the last live entry just shrinks length" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 10);
    t.removeAt(0);
    try testing.expectEqual(@as(usize, 0), t.count());
    try testing.expectEqual(@as(?u64, null), t.get(1));
}

test "TsTable: evictOlderThan removes only entries past the age cutoff" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 0); // age at now=1000 -> 1000
    try t.insert(2, 500); // age -> 500
    try t.insert(3, 900); // age -> 100
    const evicted = t.evictOlderThan(1000, 500);
    try testing.expectEqual(@as(usize, 1), evicted); // only tsval=1 (age 1000 > 500)
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expectEqual(@as(?u64, null), t.get(1));
    try testing.expectEqual(@as(?u64, 500), t.get(2));
    try testing.expectEqual(@as(?u64, 900), t.get(3));
}

test "TsTable: evictOlderThan with now before some first_seen values never underflows or misclassifies (saturating age)" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 5000); // "first seen" in the future relative to `now` below
    // now (100) < first_seen (5000): a naive `now - first_seen` would wrap to
    // a huge u64 and get evicted; the saturating form must NOT do that.
    const evicted = t.evictOlderThan(100, 10);
    try testing.expectEqual(@as(usize, 0), evicted);
    try testing.expectEqual(@as(usize, 1), t.count());
}

test "TsTable: evictOlderThan can empty the whole table" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 0);
    try t.insert(2, 0);
    try t.insert(3, 0);
    const evicted = t.evictOlderThan(1000, 1);
    try testing.expectEqual(@as(usize, 3), evicted);
    try testing.expectEqual(@as(usize, 0), t.count());
    try testing.expectEqual(@as(?usize, null), t.oldestIndex());
}

test "TsTable: oldestIndex finds the smallest first_seen regardless of insertion order" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 500);
    try t.insert(2, 100); // oldest
    try t.insert(3, 900);
    try testing.expectEqual(@as(usize, 1), t.oldestIndex().?);
    try testing.expectEqual(@as(u32, 2), t.entries[t.oldestIndex().?].tsval);
}

test "TsTable: reset empties without freeing, and the table is reusable" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try t.insert(1, 10);
    try t.insert(2, 20);
    t.reset();
    try testing.expectEqual(@as(usize, 0), t.count());
    try testing.expectEqual(@as(usize, 4), t.capacity()); // capacity untouched
    try t.insert(3, 30);
    try testing.expectEqual(@as(usize, 1), t.count());
    try testing.expectEqual(@as(?u64, 30), t.get(3));
}

test "TsTable: items() reflects only live entries" {
    var t = try TsTable.init(testing.allocator, 4);
    defer t.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), t.items().len);
    try t.insert(1, 10);
    try t.insert(2, 20);
    try testing.expectEqual(@as(usize, 2), t.items().len);
}

test "TsTable: bounded-memory property — capacity is never exceeded across a long insert/evict stream" {
    var t = try TsTable.init(testing.allocator, 8);
    defer t.deinit(testing.allocator);
    var state: u64 = 0x2545F4914F6CDD1D;
    var i: u64 = 0;
    while (i < 5000) : (i += 1) {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const tsval: u32 = @truncate(state >> 32);
        const now = i;
        if (t.indexOf(tsval) == null) {
            if (t.isFull()) {
                // Mimic a bounded eviction policy: drop the oldest to make
                // room, proving capacity can be held across an unbounded
                // stream without ever growing the backing allocation.
                t.removeAt(t.oldestIndex().?);
            }
            try t.insert(tsval, now);
        }
        try testing.expect(t.count() <= t.capacity());
    }
    try testing.expectEqual(@as(usize, 8), t.entries.len); // allocation never grew
}
