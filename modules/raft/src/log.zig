// SPDX-License-Identifier: MIT

//! log — the replicated-log storage container. MECHANICAL (no consensus-safety
//! logic): a growable 1-based array of `LogEntry` with the accessors Raft's
//! algorithm needs — append, the conflict-truncation primitive, random access,
//! and the last-index/last-term summary that feeds the election restriction.
//!
//! The DECISIONS about *when* to truncate/append/commit live in `safety.zig`
//! (the Fable core); this file only performs the mutations that core selects,
//! and only that. Indices are 1-based to match the paper: `lastIndex() == 0`
//! and `lastTerm() == 0` for an empty log (there is no entry 0).

const std = @import("std");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;

const Term = types.Term;
const LogIndex = types.LogIndex;
const LogEntry = types.LogEntry;

/// A candidate/log summary — the `(lastLogTerm, lastLogIndex)` pair the §5.4.1
/// up-to-date comparison operates on. Named here (not in safety.zig) because it
/// is a plain projection of the log, computed mechanically.
pub const LogInfo = struct {
    last_index: LogIndex = 0,
    last_term: Term = 0,
};

pub const Log = struct {
    /// Entries `snap_index + 1 ..`, in order.
    entries: std.ArrayList(LogEntry) = .empty,
    /// The last index a snapshot covers (§7): entries up to it are compacted
    /// away and only its term is kept. 0 = no snapshot (the log is dense from
    /// index 1).
    snap_index: LogIndex = 0,
    snap_term: Term = 0,

    pub fn deinit(self: *Log, gpa: Allocator) void {
        self.entries.deinit(gpa);
        self.* = undefined;
    }

    pub fn reset(self: *Log) void {
        self.entries.clearRetainingCapacity();
        self.snap_index = 0;
        self.snap_term = 0;
    }

    /// Index of the last entry (1-based), or the snapshot's last index when
    /// no entry follows it.
    pub fn lastIndex(self: *const Log) LogIndex {
        return self.snap_index + @as(LogIndex, @intCast(self.entries.items.len));
    }

    /// Term of the last entry, the snapshot's term when no entry follows it,
    /// or 0 for an empty log.
    pub fn lastTerm(self: *const Log) Term {
        if (self.entries.items.len == 0) return self.snap_term;
        return self.entries.items[self.entries.items.len - 1].term;
    }

    pub fn info(self: *const Log) LogInfo {
        return .{ .last_index = self.lastIndex(), .last_term = self.lastTerm() };
    }

    /// The entry at 1-based `index`, or null if out of range (including
    /// `index == 0` and an index a snapshot compacted away).
    pub fn get(self: *const Log, index: LogIndex) ?LogEntry {
        if (index <= self.snap_index or index > self.lastIndex()) return null;
        return self.entries.items[@intCast(index - self.snap_index - 1)];
    }

    /// Term at 1-based `index`; `index == 0` yields 0 (the "before the first
    /// entry" sentinel term — this is what makes a `prevLogIndex == 0`
    /// consistency check trivially pass), and the snapshot's last index its
    /// term. Null if `index` is past the end or compacted away (below the
    /// snapshot's last index).
    pub fn termAt(self: *const Log, index: LogIndex) ?Term {
        if (index == self.snap_index) return self.snap_term;
        if (index < self.snap_index or index > self.lastIndex()) return null;
        return self.entries.items[@intCast(index - self.snap_index - 1)].term;
    }

    pub fn append(self: *Log, gpa: Allocator, entry: LogEntry) Allocator.Error!void {
        try self.entries.append(gpa, entry);
    }

    pub fn appendSlice(self: *Log, gpa: Allocator, slice: []const LogEntry) Allocator.Error!void {
        try self.entries.appendSlice(gpa, slice);
    }

    /// Delete every entry with index > `index`, keeping `[1..index]`.
    /// `truncateAfter(0)` empties the log. Truncating at or past the current
    /// end is a no-op. THIS IS A RAW PRIMITIVE — deleting entries that still
    /// match a leader can drop committed state; the conflict rule that decides
    /// a SAFE truncation point is `safety.handleAppendEntries` (the Fable core),
    /// never this function. A snapshot's entries are committed and never
    /// truncated: `index` below `snap_index` keeps the snapshot.
    pub fn truncateAfter(self: *Log, index: LogIndex) void {
        if (index >= self.lastIndex()) return;
        const keep = @max(index, self.snap_index) - self.snap_index;
        self.entries.shrinkRetainingCapacity(@intCast(keep));
    }

    /// Compact the log up to `index` (§7): entries `<= index` are dropped and
    /// `index` becomes the snapshot's last index. `index` must be in
    /// `(snap_index, lastIndex()]`.
    pub fn compactTo(self: *Log, index: LogIndex) void {
        std.debug.assert(index > self.snap_index and index <= self.lastIndex());
        const t = self.termAt(index).?;
        const drop: usize = @intCast(index - self.snap_index);
        const rest = self.entries.items.len - drop;
        std.mem.copyForwards(LogEntry, self.entries.items[0..rest], self.entries.items[drop..]);
        self.entries.shrinkRetainingCapacity(rest);
        self.snap_index = index;
        self.snap_term = t;
    }

    /// Replace the whole log by a snapshot ending at `index` / `term` (an
    /// installed snapshot, §7): no entry is kept.
    pub fn restoreSnapshot(self: *Log, index: LogIndex, term: Term) void {
        self.entries.clearRetainingCapacity();
        self.snap_index = index;
        self.snap_term = term;
    }
};

// ── tests (all mechanical) ──────────────────────────────────────────────────

const testing = std.testing;

test "empty log reports the 0/0 sentinels" {
    var log = Log{};
    defer log.deinit(testing.allocator);
    try testing.expectEqual(@as(LogIndex, 0), log.lastIndex());
    try testing.expectEqual(@as(Term, 0), log.lastTerm());
    try testing.expectEqual(@as(?LogEntry, null), log.get(0));
    try testing.expectEqual(@as(?LogEntry, null), log.get(1));
    try testing.expectEqual(@as(?Term, 0), log.termAt(0)); // the prevLogIndex==0 base case
    try testing.expectEqual(@as(?Term, null), log.termAt(1));
}

test "append then random-access by 1-based index" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    try log.append(gpa, .{ .term = 1, .command = 10 });
    try log.append(gpa, .{ .term = 1, .command = 11 });
    try log.append(gpa, .{ .term = 2, .command = 12 });
    try testing.expectEqual(@as(LogIndex, 3), log.lastIndex());
    try testing.expectEqual(@as(Term, 2), log.lastTerm());
    try testing.expectEqual(@as(Command, 10), log.get(1).?.command);
    try testing.expectEqual(@as(Command, 12), log.get(3).?.command);
    try testing.expectEqual(@as(?Term, 1), log.termAt(2));
    try testing.expectEqual(@as(?Term, 2), log.termAt(3));
    try testing.expectEqual(@as(?LogEntry, null), log.get(4));
}

const Command = types.Command;

test "truncateAfter keeps the prefix and drops the tail; boundaries are no-ops" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    try log.appendSlice(gpa, &.{
        .{ .term = 1, .command = 1 },
        .{ .term = 1, .command = 2 },
        .{ .term = 2, .command = 3 },
        .{ .term = 2, .command = 4 },
    });

    log.truncateAfter(2); // keep [1..2]
    try testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try testing.expectEqual(@as(Command, 2), log.get(2).?.command);
    try testing.expectEqual(@as(?LogEntry, null), log.get(3));

    log.truncateAfter(5); // past end → no-op
    try testing.expectEqual(@as(LogIndex, 2), log.lastIndex());

    log.truncateAfter(0); // empty it
    try testing.expectEqual(@as(LogIndex, 0), log.lastIndex());
    try testing.expectEqual(@as(Term, 0), log.lastTerm());
}

test "info projects (lastTerm, lastIndex) for the up-to-date comparison" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    try log.appendSlice(gpa, &.{ .{ .term = 1, .command = 1 }, .{ .term = 4, .command = 2 } });
    const i = log.info();
    try testing.expectEqual(@as(LogIndex, 2), i.last_index);
    try testing.expectEqual(@as(Term, 4), i.last_term);
}

test "a compacted log keeps its snapshot's last index and term, and nothing below" {
    const gpa = testing.allocator;
    var log = Log{};
    defer log.deinit(gpa);
    try log.appendSlice(gpa, &.{
        .{ .term = 1, .command = 1 },
        .{ .term = 2, .command = 2 },
        .{ .term = 2, .command = 3 },
        .{ .term = 3, .command = 4 },
    });
    log.compactTo(2);
    try testing.expectEqual(@as(LogIndex, 4), log.lastIndex());
    try testing.expectEqual(@as(Term, 3), log.lastTerm());
    try testing.expectEqual(@as(?Term, 2), log.termAt(2)); // the snapshot's last index
    try testing.expectEqual(@as(?Term, null), log.termAt(1)); // compacted
    try testing.expectEqual(@as(?Term, null), log.termAt(0));
    try testing.expectEqual(@as(?LogEntry, null), log.get(2));
    try testing.expectEqual(@as(Command, 3), log.get(3).?.command);
    // Truncation never reaches into the snapshot.
    log.truncateAfter(1);
    try testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try testing.expectEqual(@as(Term, 2), log.lastTerm());
    try log.append(gpa, .{ .term = 5, .command = 9 });
    try testing.expectEqual(@as(Command, 9), log.get(3).?.command);
    log.compactTo(3);
    try testing.expectEqual(@as(LogIndex, 3), log.lastIndex());
    try testing.expectEqual(@as(Term, 5), log.lastTerm());
    log.restoreSnapshot(10, 7);
    try testing.expectEqual(@as(LogIndex, 10), log.lastIndex());
    try testing.expectEqual(@as(?Term, 7), log.termAt(10));
    try testing.expectEqual(@as(?Term, null), log.termAt(11));
}
