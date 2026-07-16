// SPDX-License-Identifier: MIT

//! checks — the invariant proof: Raft's five formal safety properties (Ongaro &
//! Ousterhout §5.4.3, Figure 3), as continuously-checkable predicates with
//! independent teeth. Two shapes:
//!
//!  1. **Live incremental** (`SafetyChecker`) — a single shared observer the
//!     protocol feeds as events happen: leadership announcements (Election
//!     Safety), state-machine applies (State Machine Safety), and committed
//!     entries. A violation is captured stickily and surfaced by `check()`,
//!     which `netsim.Protocol.checkFn` returns — halting the run with the exact
//!     reproducer (mirrors netsim's own `LoopyForward` accumulate-then-assert).
//!  2. **Pure snapshot predicates** — Log Matching / Leader Append-Only / Leader
//!     Completeness are properties OVER logs, so they are stateless functions of
//!     log snapshots. The gated `RaftServer.check` runs them across the live
//!     per-node logs; today they are proven by the synthetic teeth tests below
//!     (hand-built states that violate each property, asserted to be caught).
//!
//! The five (Figure 3):
//!   - **Election Safety**  — at most one leader per term.
//!   - **Leader Append-Only** — a leader never overwrites or deletes entries in
//!     its own log; it only appends.
//!   - **Log Matching** — if two logs contain an entry with the same index and
//!     term, the logs are identical in all entries up through that index.
//!   - **Leader Completeness** — an entry committed in a term is present in the
//!     logs of the leaders of all higher terms.
//!   - **State Machine Safety** — if a server has applied an entry at an index,
//!     no other server ever applies a different entry for that index.

const std = @import("std");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;

const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const Command = types.Command;
const LogEntry = types.LogEntry;

/// A committed log entry's identity — used by the Leader Completeness predicate
/// and the live checker's committed-set bookkeeping.
pub const CommitRec = struct {
    index: LogIndex,
    term: Term,
    command: Command,
};

// ── 1. live incremental checker ─────────────────────────────────────────────

pub const SafetyChecker = struct {
    /// term → the (unique) leader observed for it. A second, DIFFERENT leader
    /// for the same term is an Election Safety violation.
    leaders: std.AutoHashMapUnmanaged(Term, NodeId) = .empty,
    /// log index → the command a server applied there. A different command
    /// applied at the same index by any server is a State Machine Safety
    /// violation.
    applied: std.AutoHashMapUnmanaged(LogIndex, Command) = .empty,
    /// log index → the (term, command) known committed there. A committed index
    /// taking a second, different value is the deepest safety failure.
    committed: std.AutoHashMapUnmanaged(LogIndex, CommitRec) = .empty,
    /// Sticky first violation (netsim stops at the first `check()` failure).
    violation: ?anyerror = null,

    pub fn deinit(self: *SafetyChecker, gpa: Allocator) void {
        self.leaders.deinit(gpa);
        self.applied.deinit(gpa);
        self.committed.deinit(gpa);
        self.* = undefined;
    }

    pub fn reset(self: *SafetyChecker) void {
        self.leaders.clearRetainingCapacity();
        self.applied.clearRetainingCapacity();
        self.committed.clearRetainingCapacity();
        self.violation = null;
    }

    /// Election Safety: record that `node` believes itself leader for `term`.
    /// Re-recording the SAME leader is idempotent; a different one trips
    /// `error.ElectionSafety`.
    pub fn recordLeader(self: *SafetyChecker, gpa: Allocator, term: Term, node: NodeId) Allocator.Error!void {
        if (self.violation != null) return;
        const gop = try self.leaders.getOrPut(gpa, term);
        if (gop.found_existing) {
            if (gop.value_ptr.* != node) self.violation = error.ElectionSafety;
        } else {
            gop.value_ptr.* = node;
        }
    }

    /// State Machine Safety: record that some server applied `command` at
    /// `index`. A different command already applied there trips
    /// `error.StateMachineSafety`.
    pub fn recordApply(self: *SafetyChecker, gpa: Allocator, index: LogIndex, command: Command) Allocator.Error!void {
        if (self.violation != null) return;
        const gop = try self.applied.getOrPut(gpa, index);
        if (gop.found_existing) {
            if (gop.value_ptr.* != command) self.violation = error.StateMachineSafety;
        } else {
            gop.value_ptr.* = command;
        }
    }

    /// Record a committed entry. A committed index that changes (term or
    /// command) is a State Machine Safety violation (a committed entry was
    /// lost/overwritten — what Figure 8 is about).
    pub fn recordCommitted(self: *SafetyChecker, gpa: Allocator, rec: CommitRec) Allocator.Error!void {
        if (self.violation != null) return;
        const gop = try self.committed.getOrPut(gpa, rec.index);
        if (gop.found_existing) {
            if (gop.value_ptr.*.term != rec.term or gop.value_ptr.*.command != rec.command)
                self.violation = error.StateMachineSafety;
        } else {
            gop.value_ptr.* = rec;
        }
    }

    /// `netsim.Protocol.checkFn` body.
    pub fn check(self: *const SafetyChecker) anyerror!void {
        if (self.violation) |e| return e;
    }
};

// ── 2. pure snapshot predicates ─────────────────────────────────────────────

/// **Log Matching.** Given every server's full log (`logs[i]` = node i's
/// entries, `logs[i][0]` = its index-1 entry), return the 1-based index at which
/// the property is violated, or null if it holds. Property: whenever two logs
/// have an entry at the same index with the same term, every entry up to and
/// including that index is identical between them.
pub fn logMatchingViolation(logs: []const []const LogEntry) ?LogIndex {
    var a: usize = 0;
    while (a < logs.len) : (a += 1) {
        var b: usize = a + 1;
        while (b < logs.len) : (b += 1) {
            const la = logs[a];
            const lb = logs[b];
            const common = @min(la.len, lb.len);
            // The strongest constraint is the HIGHEST common index whose terms
            // match: an identical prefix through it implies identity through
            // every earlier index. Find it, then verify the whole prefix.
            var k = common;
            while (k > 0) : (k -= 1) {
                if (la[k - 1].term == lb[k - 1].term) {
                    var j: usize = 0;
                    while (j < k) : (j += 1) {
                        if (la[j].term != lb[j].term or la[j].command != lb[j].command or la[j].kind != lb[j].kind)
                            return @intCast(j + 1);
                    }
                    break; // prefix verified up to k; earlier equal-term points are subsumed
                }
            }
        }
    }
    return null;
}

/// **Leader Append-Only.** Given a leader's log `before` and `after` some
/// interval during which it remained leader, holds iff `after` only grew:
/// length did not shrink and every index present in `before` is unchanged.
pub fn appendOnlyHolds(before: []const LogEntry, after: []const LogEntry) bool {
    if (after.len < before.len) return false;
    for (before, 0..) |e, i| {
        if (after[i].term != e.term or after[i].command != e.command or after[i].kind != e.kind) return false;
    }
    return true;
}

/// **Leader Completeness.** Every committed entry appears — at its index, with
/// its term and command — in `leader_log`. Checked when a server becomes leader
/// of a term higher than every entry in `committed`.
pub fn leaderCompletenessHolds(leader_log: []const LogEntry, committed: []const CommitRec) bool {
    for (committed) |c| {
        if (c.index == 0 or c.index > leader_log.len) return false;
        const e = leader_log[@intCast(c.index - 1)];
        if (e.term != c.term or e.command != c.command) return false;
    }
    return true;
}

// ── tests: teeth for each of the five, plus clean negatives ─────────────────

const testing = std.testing;

test "Election Safety: a second distinct leader for one term is caught; re-recording the same is idempotent" {
    const gpa = testing.allocator;
    var c = SafetyChecker{};
    defer c.deinit(gpa);
    try c.recordLeader(gpa, 1, 0);
    try c.recordLeader(gpa, 1, 0); // same leader again — fine
    try c.recordLeader(gpa, 2, 1); // different term — fine
    try c.check();
    try c.recordLeader(gpa, 1, 3); // SECOND leader for term 1 — violation
    try testing.expectError(error.ElectionSafety, c.check());
}

test "State Machine Safety: a divergent apply at the same index is caught" {
    const gpa = testing.allocator;
    var c = SafetyChecker{};
    defer c.deinit(gpa);
    try c.recordApply(gpa, 1, 100);
    try c.recordApply(gpa, 2, 101);
    try c.recordApply(gpa, 1, 100); // same command, same index — fine
    try c.check();
    try c.recordApply(gpa, 1, 999); // DIFFERENT command at index 1 — violation
    try testing.expectError(error.StateMachineSafety, c.check());
}

test "State Machine Safety: a committed index that changes value is caught" {
    const gpa = testing.allocator;
    var c = SafetyChecker{};
    defer c.deinit(gpa);
    try c.recordCommitted(gpa, .{ .index = 3, .term = 2, .command = 7 });
    try c.recordCommitted(gpa, .{ .index = 3, .term = 2, .command = 7 }); // idempotent
    try c.check();
    try c.recordCommitted(gpa, .{ .index = 3, .term = 4, .command = 8 }); // committed entry overwritten
    try testing.expectError(error.StateMachineSafety, c.check());
}

test "checker reset clears violations and all tables" {
    const gpa = testing.allocator;
    var c = SafetyChecker{};
    defer c.deinit(gpa);
    try c.recordLeader(gpa, 1, 0);
    try c.recordLeader(gpa, 1, 1);
    try testing.expectError(error.ElectionSafety, c.check());
    c.reset();
    try c.check();
    try c.recordLeader(gpa, 1, 5); // fresh table, no ghost
    try c.check();
}

test "Log Matching: identical logs and a shared prefix hold" {
    const a = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 2 }, .{ .term = 2, .command = 3 } };
    const b = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 2 } }; // proper prefix of a
    const logs = [_][]const LogEntry{ &a, &b };
    try testing.expectEqual(@as(?LogIndex, null), logMatchingViolation(&logs));
}

test "Log Matching: teeth — same (index,term) but a divergent earlier entry is caught" {
    // Both have term=2 at index 3, but their index-2 commands differ — that is
    // exactly the state Log Matching forbids.
    const a = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 2 }, .{ .term = 2, .command = 9 } };
    const b = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 7 }, .{ .term = 2, .command = 9 } };
    const logs = [_][]const LogEntry{ &a, &b };
    try testing.expectEqual(@as(?LogIndex, 2), logMatchingViolation(&logs));
}

test "Log Matching: different terms at the shared index impose no constraint" {
    // Index 2 has different terms → no requirement on the prefix; must NOT flag.
    const a = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 2, .command = 5 } };
    const b = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 3, .command = 6 } };
    const logs = [_][]const LogEntry{ &a, &b };
    try testing.expectEqual(@as(?LogIndex, null), logMatchingViolation(&logs));
}

test "Leader Append-Only: growth holds; a shrink or an overwrite is caught (teeth)" {
    const before = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 2 } };
    const grown = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 1, .command = 2 }, .{ .term = 2, .command = 3 } };
    try testing.expect(appendOnlyHolds(&before, &grown));

    const shrunk = [_]LogEntry{.{ .term = 1, .command = 1 }};
    try testing.expect(!appendOnlyHolds(&before, &shrunk)); // deleted an entry

    const overwritten = [_]LogEntry{ .{ .term = 1, .command = 1 }, .{ .term = 2, .command = 99 }, .{ .term = 2, .command = 3 } };
    try testing.expect(!appendOnlyHolds(&before, &overwritten)); // rewrote index 2
}

test "Leader Completeness: a leader containing every committed entry holds; a gap is caught (teeth)" {
    const committed = [_]CommitRec{
        .{ .index = 1, .term = 1, .command = 10 },
        .{ .index = 2, .term = 1, .command = 11 },
    };
    const good_leader = [_]LogEntry{ .{ .term = 1, .command = 10 }, .{ .term = 1, .command = 11 }, .{ .term = 3, .command = 12 } };
    try testing.expect(leaderCompletenessHolds(&good_leader, &committed));

    const missing = [_]LogEntry{ .{ .term = 1, .command = 10 }, .{ .term = 3, .command = 99 } }; // index 2 committed=11, here=99
    try testing.expect(!leaderCompletenessHolds(&missing, &committed));

    const too_short = [_]LogEntry{.{ .term = 1, .command = 10 }}; // missing index 2 entirely
    try testing.expect(!leaderCompletenessHolds(&too_short, &committed));
}
