// SPDX-License-Identifier: MIT
//! seqmap — O(1) correlation map for request/reply protocols keyed by a
//! 16-bit sequence number.
//!
//! Maps the 16-bit sequence id of an in-flight probe to the (target, probe)
//! pair it was sent for, plus the transmit timestamp used for RTT. Sequence
//! numbers are handed out round-robin from a fixed table of 65536 slots (same
//! approach as fping's `seqmap.c`). A slot is freed explicitly by the engine
//! on reply, timeout, or send error, so exhaustion can only occur when more
//! than 65535 probes are genuinely outstanding — the engine's in-flight cap
//! must stay below that.
//!
//! One allocation at `init` (the slot table); `add`/`fetch`/`release` never
//! allocate. Pure logic, portable — usable by any protocol that correlates
//! replies via a 16-bit id (ICMP echo, DNS ids, …).

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared/global state; don't share one instance
    .model_after = "fping seqmap.c",
    .deps = .{}, // std only
};

// ── public API ──────────────────────────────────────────────────────────────

/// Size of the sequence space (16-bit ids).
pub const capacity = 65536;

/// In-flight probe state stored per sequence number.
pub const Entry = struct {
    /// Caller-defined target handle (e.g. an index into a target table).
    target: u32,
    /// 0-based probe index within the target.
    probe: u16,
    /// Transmit timestamp, caller's clock (used for RTT on reply).
    sent_ns: i64,
    /// Set when the first reply arrives; the slot stays reserved until its
    /// timeout event fires so further replies can be counted as duplicates.
    answered: bool = false,
};

/// Fixed 65536-slot round-robin sequence map.
pub const SeqMap = struct {
    slots: []?Entry,
    next: u16 = 0,

    pub fn init(gpa: std.mem.Allocator) !SeqMap {
        const slots = try gpa.alloc(?Entry, capacity);
        @memset(slots, null);
        return .{ .slots = slots };
    }

    pub fn deinit(self: *SeqMap, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
        self.* = undefined;
    }

    /// Reserve the next sequence number for a probe. O(1), no allocation.
    pub fn add(self: *SeqMap, target: u32, probe: u16, sent_ns: i64) error{Exhausted}!u16 {
        const seq = self.next;
        if (self.slots[seq] != null) return error.Exhausted;
        self.slots[seq] = .{ .target = target, .probe = probe, .sent_ns = sent_ns };
        self.next = seq +% 1;
        return seq;
    }

    /// Look up a sequence number from a received reply. Returns null for
    /// sequence numbers we do not currently have outstanding (stale replies
    /// or packets that are not ours).
    pub fn fetch(self: *const SeqMap, seq: u16) ?Entry {
        return self.slots[seq];
    }

    /// Mutable lookup (for marking a slot answered).
    pub fn fetchPtr(self: *SeqMap, seq: u16) ?*Entry {
        return if (self.slots[seq]) |*e| e else null;
    }

    /// Release a slot. Idempotent.
    pub fn release(self: *SeqMap, seq: u16) void {
        self.slots[seq] = null;
    }

    /// Release every slot (start of a new probing round).
    pub fn clear(self: *SeqMap) void {
        @memset(self.slots, null);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

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
    try std.testing.expectEqual(@as(u16, 5), map.next);
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
