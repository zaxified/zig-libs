// SPDX-License-Identifier: MIT

//! raft — the Raft consensus algorithm (leader election + log replication),
//! model-checked in `netsim` against Raft's five formal safety properties under
//! fuzzed crash / partition / message-reorder / clock-skew schedules.
//!
//! Modeled after Ongaro & Ousterhout, "In Search of an Understandable Consensus
//! Algorithm" (extended version) — Figure 2 (state + RPCs), Figure 3 (safety
//! properties), §5.2–§5.4 (election, replication, the election restriction and
//! the Figure-8 commit rule). It runs INSIDE `netsim` exactly like this
//! collection's other fabric protocols: a `netsim.Protocol` consumer, a live invariant checker, a
//! deliberately-broken positive control, and a property/shrink/teeth harness.
//!
//! **Status: consensus-safety core IMPLEMENTED; gate flipped; full suite runs.**
//! The mechanical scaffold: wire codecs + persistent-state serialization
//! (`types.zig`), the log container (`log.zig`), all five safety checkers with
//! synthetic teeth tests (`checks.zig`), the protocol plumbing and the
//! `BrokenRaft` positive control with its property/shrink/teeth tests
//! (`server.zig`). The irreducible consensus-safety kernel (`safety.zig`) — the
//! up-to-date election restriction, the RequestVote grant, the AppendEntries
//! conflict-only truncation rule, and the Figure-8 leader-commit rule — is real
//! and unit-tested, and the formerly gated model-check tests now drive the real
//! `RaftServer` through the fuzzed crash/partition/reorder/clock-skew sweep with
//! all five safety invariants enforced live. Membership changes (§6) remain
//! design-only (`jointMajority` implemented, not yet wired into the protocol).
//!
//! **What the LIVE sweep actually catches** — stated explicitly, because a
//! checker that cannot fail is worse than no checker:
//!   - leaders propose DISTINCT client commands, one per heartbeat, identified
//!     `(term, index)` (`server.commandFor`), so the apply-keyed State Machine
//!     Safety check and the command-comparing Log Matching / Leader
//!     Completeness predicates all have a value that VARIES. Before this, every
//!     replicated entry was the leader's own `command = 0` no-op and State
//!     Machine Safety compared zero against zero at every index.
//!   - `BrokenRaft` (leadership declared with no election at all) trips
//!     **Election Safety** live, on a clean run and across a seed sweep;
//!   - the `index_only_up_to_date` injection — §5.4.1 with the term-first clause
//!     dropped — trips **Leader Completeness** live on a directed
//!     partition/crash schedule;
//!   - the `naive_truncation` injection — §5.3 without the conflict-only
//!     qualifier — is NOT caught by the sweep even so: an entry's identity is
//!     `(creating term, index)`, so the same leader re-replicating a rolled-back
//!     index restores a byte-identical entry. It is covered by `safety.zig`'s
//!     `§5.3 the trap` unit test and by `server.zig`'s rollback regression test,
//!     which is where that rule's teeth live.

const std = @import("std");
const netsim = @import("netsim");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Raft consensus (Ongaro & Ousterhout) — leader election + log replication, model-checked in netsim against all five formal safety properties; membership changes are design-only",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure simulation-verified logic, no OS/network I/O
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "Raft (Ongaro & Ousterhout, extended paper) — leader election + log replication",
    .deps = .{"netsim"},
};

// ── public API ──────────────────────────────────────────────────────────────

const types = @import("types.zig");
pub const Term = types.Term;
pub const LogIndex = types.LogIndex;
pub const NodeId = types.NodeId;
pub const Command = types.Command;
pub const no_vote = types.no_vote;
pub const EntryKind = types.EntryKind;
/// Every wire decoder here fails closed — see `types.zig`'s module doc.
pub const DecodeError = types.DecodeError;
pub const LogEntry = types.LogEntry;
pub const RpcTag = types.RpcTag;
pub const RequestVoteReq = types.RequestVoteReq;
pub const RequestVoteResp = types.RequestVoteResp;
pub const AppendEntriesReq = types.AppendEntriesReq;
pub const AppendEntriesResp = types.AppendEntriesResp;
pub const PersistentState = types.PersistentState;

const log_mod = @import("log.zig");
pub const Log = log_mod.Log;
pub const LogInfo = log_mod.LogInfo;

/// FABLE tier — see `safety.zig`. These are the irreducible consensus-safety
/// decisions; everything else in this module is mechanical scaffold.
const safety = @import("safety.zig");
pub const VoteDecision = safety.VoteDecision;
pub const AppendOutcome = safety.AppendOutcome;
pub const TermObservation = safety.TermObservation;
pub const logIsAtLeastAsUpToDate = safety.logIsAtLeastAsUpToDate;
pub const handleRequestVote = safety.handleRequestVote;
pub const handleAppendEntries = safety.handleAppendEntries;
pub const leaderCommitIndex = safety.leaderCommitIndex;
pub const jointMajority = safety.jointMajority;
pub const observeTerm = safety.observeTerm;

const checks = @import("checks.zig");
pub const SafetyChecker = checks.SafetyChecker;
pub const CommitRec = checks.CommitRec;
pub const logMatchingViolation = checks.logMatchingViolation;
pub const appendOnlyHolds = checks.appendOnlyHolds;
pub const leaderCompletenessHolds = checks.leaderCompletenessHolds;

const server = @import("server.zig");
pub const RaftServer = server.RaftServer;
pub const RaftConfig = server.RaftConfig;
pub const CLUSTER_N = server.CLUSTER_N;
pub const scenario = server.scenario;
/// Positive control — proves `SafetyChecker` has teeth (see `server.zig`).
pub const BrokenRaft = server.BrokenRaft;

const gate = @import("gate.zig");
/// Flip once `safety.zig`'s decision functions are real — see `gate.zig`.
pub const fable_core_implemented = gate.fable_core_implemented;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// refAllDecls walks every pub declaration reachable from this file (including
// the sub-module re-exports above), which is what pulls types.zig / log.zig /
// safety.zig / checks.zig / server.zig / gate.zig's own `test` blocks into
// `zig build test-raft` — a bare `pub const x = @import("x.zig")` re-export
// alone does NOT do this (the dark-tests rule).

test {
    std.testing.refAllDecls(@This());
    _ = @import("types.zig");
    _ = @import("log.zig");
    _ = @import("safety.zig");
    _ = @import("checks.zig");
    _ = @import("server.zig");
    _ = @import("gate.zig");
}

test "smoke: module imports and re-exports resolve" {
    _ = netsim;
    _ = fable_core_implemented; // resolved regardless of its value
    try std.testing.expectEqual(@as(usize, 5), CLUSTER_N);
}
