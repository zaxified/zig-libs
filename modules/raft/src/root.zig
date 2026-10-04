// SPDX-License-Identifier: MIT

//! raft — the Raft consensus algorithm (leader election + log replication) as
//! a runnable server, `Node` — a pure state machine over caller-owned
//! transport, storage and clock — model-checked in `netsim` against Raft's
//! five formal safety properties under fuzzed crash / partition /
//! message-reorder / clock-skew schedules.
//!
//! Modeled after Ongaro & Ousterhout, "In Search of an Understandable Consensus
//! Algorithm" (extended version) — Figure 2 (state + RPCs), Figure 3 (safety
//! properties), §5.2–§5.4 (election, replication, the election restriction and
//! the Figure-8 commit rule). The decision kernel (`safety.zig`) makes every
//! consensus decision; `node.zig` is the plumbing around it; `server.zig`'s
//! `RaftServer` runs N `Node`s inside `netsim` with a disk per server, a live
//! invariant checker, a deliberately-broken positive control and a
//! property/shrink/teeth harness.
//!
//! **Status: mvp.** Not yet: snapshots / log compaction, membership changes
//! (`jointMajority` implemented, not wired), pre-vote / leadership transfer,
//! linearizable reads — see SPEC.md § Backlog.
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
//!     `§5.3 the trap` unit test and by `node.zig`'s duplicated-AppendEntries test,
//!     which is where that rule's teeth live.

const std = @import("std");
const netsim = @import("netsim");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Raft consensus (Ongaro & Ousterhout) — a runnable server (`Node`: tick/step/propose → ready/advance over your transport and disk), model-checked in netsim against all five formal safety properties; no snapshots or membership changes yet",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure state machine, no OS/network I/O (the caller owns it)
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
pub const tagOf = types.tagOf;
pub const max_entries_per_msg = types.max_entries_per_msg;
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

/// A runnable server: the plumbing around the kernel as a pure state machine
/// (tick / step / propose → ready / advance) over caller-owned transport,
/// storage and clock — see `node.zig`.
const node_mod = @import("node.zig");
pub const Node = node_mod.Node;
pub const NodeConfig = node_mod.Config;
pub const Role = node_mod.Role;
pub const HardState = node_mod.HardState;
pub const Restore = node_mod.Restore;
pub const Ready = node_mod.Ready;
pub const InjectedBug = node_mod.InjectedBug;
pub const InitError = node_mod.InitError;
pub const ProposeError = node_mod.ProposeError;
pub const fingerprint = node_mod.fingerprint;

/// What `Node`s exchange: entries carrying the caller's bytes, and the codec.
const message = @import("message.zig");
pub const Entry = message.Entry;
pub const Message = message.Message;
pub const MessageBody = message.Body;
pub const MessageTag = message.Tag;
pub const VoteReq = message.VoteReq;
pub const VoteResp = message.VoteResp;
pub const AppendReq = message.AppendReq;
pub const AppendResp = message.AppendResp;

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
    _ = @import("node.zig");
    _ = @import("message.zig");
}

test "smoke: module imports and re-exports resolve" {
    _ = netsim;
    _ = fable_core_implemented; // resolved regardless of its value
    try std.testing.expectEqual(@as(usize, 5), CLUSTER_N);
}
