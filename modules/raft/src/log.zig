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
    entries: std.ArrayList(LogEntry) = .empty,

    pub fn deinit(self: *Log, gpa: Allocator) void {
        self.entries.deinit(gpa);
        self.* = undefined;
    }

    pub fn reset(self: *Log) void {
        self.entries.clearRetainingCapacity();
    }

    /// Number of entries == index of the last entry (1-based).
    pub fn lastIndex(self: *const Log) LogIndex {
        return @intCast(self.entries.items.len);
    }

    /// Term of the last entry, or 0 for an empty log.
    pub fn lastTerm(self: *const Log) Term {
        if (self.entries.items.len == 0) return 0;
        return self.entries.items[self.entries.items.len - 1].term;
    }

    pub fn info(self: *const Log) LogInfo {
        return .{ .last_index = self.lastIndex(), .last_term = self.lastTerm() };
    }

    /// The entry at 1-based `index`, or null if out of range (including
    /// `index == 0`).
    pub fn get(self: *const Log, index: LogIndex) ?LogEntry {
        if (index == 0 or index > self.entries.items.len) return null;
        return self.entries.items[@intCast(index - 1)];
    }

    /// Term at 1-based `index`; `index == 0` yields 0 (the "before the first
    /// entry" sentinel term — this is what makes a `prevLogIndex == 0`
    /// consistency check trivially pass). Null if `index` is past the end.
    pub fn termAt(self: *const Log, index: LogIndex) ?Term {
        if (index == 0) return 0;
        if (index > self.entries.items.len) return null;
        return self.entries.items[@intCast(index - 1)].term;
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
    /// never this function.
    pub fn truncateAfter(self: *Log, index: LogIndex) void {
        if (index >= self.entries.items.len) return;
        self.entries.shrinkRetainingCapacity(@intCast(index));
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
