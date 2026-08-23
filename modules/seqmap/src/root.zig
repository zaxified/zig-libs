// SPDX-License-Identifier: MIT

//! seqmap (clean-room) — fixed-size correlation table from a 16-bit sequence
//! id to per-probe state, for protocols that match a reply to its request by
//! that id (ICMP echo being the motivating case: the kernel hands back
//! whatever id was in the echo request, and the sender has to remember what
//! it meant).
//!
//! The id space is only 65536 values, so the whole thing is a single
//! `capacity`-sized array indexed directly by the id — no hashing, no
//! tree, no per-entry allocation. `add` hands out ids in round-robin order
//! (0, 1, 2, … wrapping back to 0) rather than searching for the lowest free
//! slot: an outstanding probe's TTL is normally far shorter than the time it
//! takes to cycle through 65536 ids, so in the common case the slot `add`
//! lands on is free, and the O(1) property survives even when the table is
//! nearly full (a linear "find a free slot" scan would degrade exactly when
//! it matters most — deep into a large, mostly-outstanding probe run).
//!
//! **Not a source of unguessable ids.** Ids are sequential and therefore
//! trivially predictable — that predictability is the whole basis for the
//! O(1), allocation-free design (no need to hash, no need to search). Do
//! **not** reach for this where an id must be unguessable to an attacker.
//! DNS transaction ids are the canonical trap: a guessable transaction id
//! lets an off-path attacker forge a matching reply before the real one
//! arrives (cache-poisoning-style response spoofing). Use a CSPRNG-sourced
//! id for that class of problem; this module is for correlation against a
//! cooperative peer (or an unspoofable transport) where the only threats are
//! ordinary loss, reordering, and duplication.
//!
//! Ownership: `init`/`deinit` are the only calls that touch the allocator —
//! everything else is array indexing over the table `init` already
//! allocated, so `add`/`fetch`/`fetchPtr`/`release`/`clear` are all O(1) and
//! allocation-free by construction.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Fixed 65,536-slot 16-bit request/reply correlation map, O(1)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared/global state; don't share one instance
    // Written clean-room from a functional specification (2026-07-29): the
    // author of this file never read the previous implementation, which was
    // recorded in NOTICE as fping-derived. See SPEC.md for the process.
    .model_after = null,
    .deps = .{}, // std only
};

/// The whole 16-bit id space. One slot per possible sequence id.
pub const capacity: usize = 65536;

/// Per-probe state held for one outstanding (or answered-but-not-yet-released)
/// sequence id.
pub const Entry = struct {
    /// Caller-defined handle — e.g. an index into the caller's own target
    /// table. Opaque to this module: never read, never compared, never
    /// interpreted, just carried and handed back on `fetch`/`fetchPtr`.
    target: u32,
    /// 0-based probe index within `target` (this module doesn't count probes
    /// itself — the caller does, and stores the result here).
    probe: u16,
    /// Transmit timestamp on the caller's clock. Kept only so the caller can
    /// compute RTT when a reply lands (`reply_ns - sent_ns`); this module
    /// never reads or compares it.
    sent_ns: i64,
    /// Set by the caller (via `fetchPtr`) when the first reply for this id
    /// arrives. The slot is deliberately *not* released on that reply: a
    /// second (duplicate) reply for the same id can still be looked up and
    /// recognised as a duplicate — via this flag — right up until the
    /// caller explicitly `release`s the slot.
    answered: bool = false,
};

/// A `capacity`-entry table indexed directly by sequence id, plus one
/// round-robin cursor. See the module doc for why ids are handed out in
/// order rather than by scanning for the lowest free slot, and why that
/// makes ids predictable (not to be used where that predictability is a
/// vulnerability).
pub const SeqMap = struct {
    /// `slots[seq]` is `null` iff id `seq` is not currently outstanding.
    slots: []?Entry,
    /// Next id `add` will attempt. A `u16` rather than a wider counter with
    /// an explicit modulo: the id space is exactly 2^16, so incrementing
    /// with wrapping arithmetic (`+%`) *is* "advance and wrap at 65536" —
    /// there is no separate wraparound case to get wrong. Deliberately not
    /// reset by `clear`: a fresh probing round keeps handing out the next
    /// ids in the same sequence, not id 0 again, so two different rounds
    /// essentially never reuse the same id back-to-back.
    ///
    /// Only moves on a *successful* `add`. A failed `add` (the id it landed
    /// on is still occupied) leaves the cursor exactly where it was, so the
    /// very next `add` retries that same id — which is what makes
    /// `release`ing that specific id immediately unblock the next `add`,
    /// with no wrap-around needed.
    cursor: u16 = 0,

    /// Allocate the table (the only allocation this type ever makes) and
    /// mark every slot empty. Free with `deinit`.
    pub fn init(gpa: std.mem.Allocator) !SeqMap {
        const slots = try gpa.alloc(?Entry, capacity);
        @memset(slots, null);
        return .{ .slots = slots };
    }

    /// Free the table. `self` must not be used afterward.
    pub fn deinit(self: *SeqMap, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
        self.* = undefined;
    }

    /// Reserve the next id in round-robin order for one outstanding probe of
    /// `target`/`probe`, sent at `sent_ns`. The cursor only advances on
    /// success. On `error.Exhausted` (the id the cursor is sitting on is
    /// still occupied — a previous probe using that same id hasn't been
    /// `release`d yet) the cursor does **not** move, so the next call to
    /// `add` retries that exact same id rather than skipping ahead. This
    /// module never searches for a free slot; a caller that keeps calling
    /// `add` after an `Exhausted` is, deliberately, hammering on the same
    /// id until either it is `release`d or the caller gives up. That is
    /// also why releasing that specific id is what unblocks the next `add`
    /// — there is no wrap-around involved, because the cursor never left.
    pub fn add(self: *SeqMap, target: u32, probe: u16, sent_ns: i64) error{Exhausted}!u16 {
        const seq = self.cursor;
        if (self.slots[seq] != null) return error.Exhausted;
        self.slots[seq] = .{ .target = target, .probe = probe, .sent_ns = sent_ns };
        self.cursor +%= 1;
        return seq;
    }

    /// The entry for `seq`, or `null` if that id is not currently
    /// outstanding — either it was never handed out, or it was and has
    /// since been `release`d. A `null` here is the normal, expected shape of
    /// a stale reply or a packet that was never ours; it is not an error.
    pub fn fetch(self: *const SeqMap, seq: u16) ?Entry {
        return self.slots[seq];
    }

    /// Same lookup as `fetch`, but mutable — the caller uses this to flip
    /// `answered` in place the moment the first reply for `seq` arrives,
    /// without a separate write call.
    pub fn fetchPtr(self: *SeqMap, seq: u16) ?*Entry {
        if (self.slots[seq]) |*e| return e;
        return null;
    }

    /// Free the slot for `seq` so that id can be reserved again once the
    /// cursor cycles back to it. Idempotent: releasing an id that is already
    /// free (never reserved, or already released) is a silent no-op, not an
    /// error — a caller that releases on both "answered" and "gave up
    /// waiting" paths doesn't have to track which one already fired.
    pub fn release(self: *SeqMap, seq: u16) void {
        self.slots[seq] = null;
    }

    /// Free every slot at once — the start of a new probing round. Leaves
    /// `cursor` untouched: see the field doc for why ids keep advancing
    /// across rounds instead of restarting at 0.
    pub fn clear(self: *SeqMap) void {
        @memset(self.slots, null);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "add hands out ids 0, 1, 2, ... in order from a fresh map" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0), try m.add(1, 0, 100));
    try testing.expectEqual(@as(u16, 1), try m.add(1, 1, 101));
    try testing.expectEqual(@as(u16, 2), try m.add(2, 0, 102));
}

test "clear frees every slot but does not reset the round-robin cursor" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 0), try m.add(1, 0, 0));
    try testing.expectEqual(@as(u16, 1), try m.add(1, 1, 0));
    try testing.expectEqual(@as(u16, 2), try m.add(1, 2, 0));

    m.clear();
    // Every entry from before the clear is gone...
    try testing.expect(m.fetch(0) == null);
    try testing.expect(m.fetch(1) == null);
    try testing.expect(m.fetch(2) == null);
    // ...but the next id handed out is 3, not 0 again: a new probing round
    // continues the same sequence rather than colliding with the last one.
    try testing.expectEqual(@as(u16, 3), try m.add(2, 0, 0));
}

test "filling all 65536 ids then add fails; the cursor is parked on 0, not advancing" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    var i: usize = 0;
    while (i < capacity) : (i += 1) {
        const seq = try m.add(@intCast(i), 0, 0);
        try testing.expectEqual(@as(u16, @intCast(i)), seq);
    }
    // Every one of the 65536 ids is now occupied — no free slot exists.
    // A failed add does not move the cursor, so repeated attempts keep
    // failing on the exact same id (0) rather than working through others.
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));
}

test "releasing the id the cursor is parked on immediately unblocks the next add — no wrap-around" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    // Fill the entire space: ids 0..65535 in order, cursor lands back on 0.
    var i: usize = 0;
    while (i < capacity) : (i += 1) _ = try m.add(0, 0, 0);

    // Full table: add keeps failing, parked on id 0 (never moves on failure).
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));

    // Releasing a *different* id changes nothing for add: the cursor is
    // still sitting on 0, which is still occupied.
    m.release(500);
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));

    // Releasing id 0 specifically — the one the cursor is parked on — makes
    // the very next add succeed and return exactly 0. No cycling through
    // the other 65535 ids is involved.
    m.release(0);
    try testing.expectEqual(@as(u16, 0), try m.add(9, 3, 555));

    const e = m.fetch(0).?;
    try testing.expectEqual(@as(u32, 9), e.target);
    try testing.expectEqual(@as(u16, 3), e.probe);
    try testing.expectEqual(@as(i64, 555), e.sent_ns);

    // Cursor has now advanced past 0 (that add succeeded), to id 1 — still
    // occupied from the original fill, so the next add fails again.
    try testing.expectError(error.Exhausted, m.add(0, 0, 0));
}

test "fetch/fetchPtr return null for an id that was never reserved" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    // A stale reply, or a packet that was never ours: not an error, just
    // "nothing to correlate against".
    try testing.expect(m.fetch(999) == null);
    try testing.expect(m.fetchPtr(999) == null);
}

test "fetch returns the fields exactly as stored by add" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    const seq = try m.add(42, 7, -1234);
    const e = m.fetch(seq).?;
    try testing.expectEqual(@as(u32, 42), e.target);
    try testing.expectEqual(@as(u16, 7), e.probe);
    try testing.expectEqual(@as(i64, -1234), e.sent_ns);
    try testing.expect(!e.answered); // default: no reply seen yet
}

test "fetchPtr lets the caller flip answered in place, visible on the next fetch" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    const seq = try m.add(1, 0, 0);
    try testing.expect(!m.fetch(seq).?.answered);

    const ptr = m.fetchPtr(seq).?;
    ptr.answered = true;

    try testing.expect(m.fetch(seq).?.answered);
}

test "a slot stays reserved (and answered) after the first reply, so a duplicate is still recognised" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    const seq = try m.add(1, 0, 0);
    m.fetchPtr(seq).?.answered = true; // first reply arrives

    // A second (duplicate) reply for the same id: still found, still
    // carries the same target/probe, and `answered` shows it is a repeat.
    const e = m.fetch(seq).?;
    try testing.expectEqual(@as(u32, 1), e.target);
    try testing.expect(e.answered);

    // Only an explicit release actually frees the slot.
    m.release(seq);
    try testing.expect(m.fetch(seq) == null);
}

test "release is idempotent" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    const seq = try m.add(1, 0, 0);
    m.release(seq);
    m.release(seq); // must not error or crash
    try testing.expect(m.fetch(seq) == null);

    // Releasing an id that was never reserved at all is equally harmless.
    m.release(500);
    try testing.expect(m.fetch(500) == null);
}

test "releasing an id the cursor has already passed does not rewind the cursor" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    const a = try m.add(1, 0, 0);
    const b = try m.add(2, 0, 0);
    try testing.expectEqual(@as(u16, 0), a);
    try testing.expectEqual(@as(u16, 1), b);

    m.release(a);
    // The cursor is at 2, not back at 0 — releasing does not rewind it.
    try testing.expect(m.fetch(a) == null); // freed
    try testing.expectEqual(@as(u16, 2), try m.add(3, 0, 0)); // cursor keeps going forward
}

test "no allocation after init: tens of thousands of add/fetch/fetchPtr/release/clear cycles" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    const gpa = failing.allocator();

    // fail_index = 1: the 0th allocation (init's table) succeeds; anything
    // after that fails immediately. If any of the operations below ever
    // allocated, they would surface that failure.
    var m = try SeqMap.init(gpa);
    defer m.deinit(gpa);

    var round: usize = 0;
    while (round < 40_000) : (round += 1) {
        const target: u32 = @intCast(round);
        const seq = m.add(target, 0, @intCast(round)) catch |err| {
            try testing.expectEqual(error.Exhausted, err);
            continue;
        };
        const e = m.fetch(seq).?;
        try testing.expectEqual(target, e.target);
        const ptr = m.fetchPtr(seq).?;
        ptr.answered = true;
        m.release(seq);
        try testing.expect(m.fetch(seq) == null);
    }
    m.clear(); // also allocation-free
}

test "clear frees slots across the whole id space, not just the low end" {
    var m = try SeqMap.init(testing.allocator);
    defer m.deinit(testing.allocator);

    // Drive the cursor past the halfway point so the reserved slot lives in
    // the upper half of the table, then confirm clear() reaches it too.
    var i: usize = 0;
    while (i < capacity / 2 + 100) : (i += 1) _ = try m.add(1, 0, 0);
    const seq: u16 = @intCast(capacity / 2 + 99);
    try testing.expect(m.fetch(seq) != null);

    m.clear();
    try testing.expect(m.fetch(seq) == null);
    try testing.expect(m.fetch(capacity - 1) == null);
}

test "capacity is the full 16-bit id space" {
    try testing.expectEqual(@as(usize, 65536), capacity);
}

// ── regression: the previous implementation's own tests ─────────────────────
//
// These are the authors' tests, not fping's, and they pin the behavioural
// contract this clean-room rewrite had to reproduce. Kept verbatim (only the
// cursor field's NAME adapted — expression, not behaviour) so the swap is
// provably behaviour-preserving rather than merely believed to be.

test "round-robin add/fetch/release" {
    var map = try SeqMap.init(std.testing.allocator);
    defer map.deinit(std.testing.allocator);

    const s0 = try map.add(10, 0, 1111);
    const s1 = try map.add(11, 3, 2222);
    try std.testing.expectEqual(@as(u16, 0), s0);
    try std.testing.expectEqual(@as(u16, 1), s1);

    const e = map.fetch(s1).?;
    try std.testing.expectEqual(@as(u32, 11), e.target);
    try std.testing.expectEqual(@as(u16, 3), e.probe);
    try std.testing.expectEqual(@as(i64, 2222), e.sent_ns);

    map.release(s0);
    try std.testing.expectEqual(@as(?Entry, null), map.fetch(s0));
    map.release(s0); // idempotent
}

test "exhaustion when slot still occupied after wrap" {
    var map = try SeqMap.init(std.testing.allocator);
    defer map.deinit(std.testing.allocator);

    var i: u32 = 0;
    while (i < capacity) : (i += 1) {
        _ = try map.add(i, 0, 1);
    }
    try std.testing.expectError(error.Exhausted, map.add(99, 0, 2));
    map.release(0);
    const seq = try map.add(99, 0, 3);
    try std.testing.expectEqual(@as(u16, 0), seq);
}

test "sequence numbers wrap around at 65536" {
    var map = try SeqMap.init(std.testing.allocator);
    defer map.deinit(std.testing.allocator);

    var i: usize = 0;
    while (i < capacity + 5) : (i += 1) {
        const seq = try map.add(@intCast(i % 1000), 0, 1);
        try std.testing.expectEqual(@as(u16, @intCast(i % capacity)), seq);
        map.release(seq);
    }
    try std.testing.expectEqual(@as(u16, 5), map.cursor);
}

test "fetchPtr mutates in place; clear frees every slot" {
    var map = try SeqMap.init(std.testing.allocator);
    defer map.deinit(std.testing.allocator);

    const seq = try map.add(7, 2, 42);
    map.fetchPtr(seq).?.answered = true;
    try std.testing.expect(map.fetch(seq).?.answered);
    try std.testing.expectEqual(@as(?*Entry, null), map.fetchPtr(seq +% 1));

    map.clear();
    try std.testing.expectEqual(@as(?Entry, null), map.fetch(seq));
    // The round-robin cursor is not reset by clear (fresh ids keep advancing).
    const seq2 = try map.add(8, 0, 43);
    try std.testing.expectEqual(seq +% 1, seq2);
}

test "no allocation after init" {
    // Allow exactly the one init-time table allocation; any per-op
    // allocation would trip the failing allocator.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const gpa = failing.allocator();
    var map = try SeqMap.init(gpa);
    defer map.deinit(gpa);

    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        const seq = try map.add(i, 0, 1);
        _ = map.fetch(seq);
        map.release(seq);
    }
}
