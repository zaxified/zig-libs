// SPDX-License-Identifier: MIT

//! safety — THE FABLE CORE: the consensus-safety decision logic where Raft's
//! subtle bugs hide, isolated as PURE functions so it is model-checkable in
//! `netsim` and unit-testable in isolation. Every function here is a `@panic`
//! stub gated by `gate.fable_core_implemented`; a later Fable pass fills the
//! bodies. `server.zig` (the mechanical protocol) calls these to make every
//! safety-relevant decision and then MECHANICALLY executes the returned verdict
//! (send a vote, truncate+append the log, advance commitIndex) — the *judgement*
//! is here, the *plumbing* is there.
//!
//! Reference: Ongaro & Ousterhout, "In Search of an Understandable Consensus
//! Algorithm" (extended version), §5.2 (election), §5.3 (log replication),
//! §5.4.1 (election restriction), §5.4.2 (committing entries from previous
//! terms — the Figure 8 crux). Section numbers below cite it.
//!
//! ── HONEST TIERING (Fable-irreducible vs mechanical) ────────────────────────
//!
//! Not everything a naive reading calls "safety logic" is genuinely irreducible.
//! The four functions below marked **[FABLE-CORE]** are the real kernel — each
//! has a documented subtle failure mode (a wrong-but-plausible implementation
//! that silently breaks a formal safety property). The one marked **[mechanical,
//! implemented]** (`observeTerm`) is a near-trivial term comparison; it is
//! implemented here, in the clear, precisely so this file does not inflate its
//! Fable surface — it belongs in this file for cohesion (it is a term/role
//! safety rule), not because it is hard.

const std = @import("std");
const types = @import("types.zig");
const log_mod = @import("log.zig");
const gate = @import("gate.zig");

const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const RequestVoteReq = types.RequestVoteReq;
const AppendEntriesReq = types.AppendEntriesReq;
const Log = log_mod.Log;
const LogInfo = log_mod.LogInfo;

// ── [FABLE-CORE] the election restriction (§5.4.1) ──────────────────────────

/// Is the candidate's log at least as up-to-date as `mine`? (§5.4.1) — the
/// restriction that guarantees **Leader Completeness**: a server grants its
/// vote only to a candidate whose log is "at least as up-to-date", defined as
/// higher `lastLogTerm`, or equal `lastLogTerm` and `lastLogIndex >= mine`.
///
/// **Why Fable, not mechanical:** the comparison ORDER is the whole game.
/// Comparing index before term (or using only index) is a plausible-looking
/// implementation that elects a leader missing committed entries — the exact
/// scenario §5.4.1 exists to forbid. This three-line function is where Leader
/// Completeness is won or lost.
pub fn logIsAtLeastAsUpToDate(cand: LogInfo, mine: LogInfo) bool {
    if (!gate.fable_core_implemented) @panic("TODO(fable/core): §5.4.1 up-to-date comparison — term first, then index");
    _ = cand;
    _ = mine;
    unreachable;
}

// ── [FABLE-CORE] RequestVote receiver (§5.2, §5.4.1) ────────────────────────

pub const VoteDecision = struct {
    /// Grant the vote?
    grant: bool,
    /// Did this RPC carry a higher term, forcing a step-down to follower?
    term_advanced: bool,
    /// The server's term after processing (== req.term if it stepped up).
    new_term: Term,
    /// If `grant`, the candidate the server must record as `votedFor`.
    voted_for: NodeId = types.no_vote,
};

/// Decide RequestVote for a server at `current_term` / `voted_for` with log
/// summary `my_log`. **[FABLE-CORE]** — grant IFF, after any term step-up
/// (§5.1): `req.term >= current_term` AND (`voted_for` is unset OR already this
/// candidate) AND the candidate's log is at least as up-to-date (§5.4.1).
///
/// **Why Fable:** every clause is a real safety gate. Drop the "already voted"
/// check and one term elects two leaders (breaks **Election Safety**). Drop the
/// up-to-date check and you elect a leader missing committed entries (breaks
/// **Leader Completeness**). Grant on a STALE term and a deposed leader's
/// candidate wins. The conjunction — and the term step-down that must precede
/// it — is irreducible.
pub fn handleRequestVote(current_term: Term, voted_for: NodeId, my_log: LogInfo, req: RequestVoteReq) VoteDecision {
    if (!gate.fable_core_implemented) @panic("TODO(fable/core): §5.2/§5.4.1 RequestVote grant — term step-up, single-vote-per-term, up-to-date restriction");
    _ = current_term;
    _ = voted_for;
    _ = my_log;
    _ = req;
    unreachable;
}

// ── [FABLE-CORE] AppendEntries receiver (§5.3) ──────────────────────────────

pub const AppendOutcome = struct {
    /// Did this RPC carry a higher term (step-down)?
    term_advanced: bool,
    /// The server's term after processing.
    new_term: Term,
    /// Did the consistency check pass? (false ⇒ leave the log untouched and
    /// answer failure so the leader decrements nextIndex and retries.)
    success: bool,
    /// On success: keep local entries `[1..truncate_to]` then append
    /// `req.entries[append_from..]`. The subtle contract: `truncate_to` must
    /// NOT cut below any already-matching entry (see below). Meaningless if
    /// `!success`.
    truncate_to: LogIndex = 0,
    /// On success: index into `req.entries` of the first entry to actually
    /// append (leading entries already present and matching are skipped, not
    /// re-truncated). Meaningless if `!success`.
    append_from: usize = 0,
    /// On success: the follower's new commitIndex —
    /// `min(leaderCommit, index of last new entry)` (§5.3). Meaningless if
    /// `!success`.
    new_commit_index: LogIndex = 0,
};

/// AppendEntries receiver for a follower at `current_term` / `commit_index`
/// with `log`. **[FABLE-CORE]** — the log-consistency check
/// (`prevLogIndex`/`prevLogTerm` must match) plus the conflict rule plus
/// follower commit advancement (§5.3).
///
/// **Why Fable — the conflict rule is a trap:** the naive "truncate everything
/// after prevLogIndex, then append all entries" DELETES committed entries when a
/// delayed or duplicated AppendEntries arrives — the follower had already
/// appended those entries from a later RPC, and blindly truncating rolls them
/// back, which can lose a committed entry and violate **State Machine Safety**.
/// The correct rule (§5.3) only deletes an existing entry when it *conflicts*
/// (same index, different term) with an incoming one, and must skip
/// already-present matching entries rather than re-truncate them. Getting the
/// "only on conflict" qualifier and the last-new-entry commit cap right is the
/// irreducible part.
pub fn handleAppendEntries(current_term: Term, log: *const Log, commit_index: LogIndex, req: AppendEntriesReq) AppendOutcome {
    if (!gate.fable_core_implemented) @panic("TODO(fable/core): §5.3 AppendEntries — consistency check, conflict-only truncation, min(leaderCommit,lastNew) commit");
    _ = current_term;
    _ = log;
    _ = commit_index;
    _ = req;
    unreachable;
}

// ── [FABLE-CORE] the leader commit rule — Figure 8 (§5.4.2) ─────────────────

/// The highest index a leader may advance `commitIndex` to. **[FABLE-CORE — the
/// marquee subtlety]** — a leader may only mark an entry committed when it is
/// replicated on a majority AND `log[N].term == current_term` (its OWN term).
/// `match_index[i]` is server `i`'s highest replicated index (self included);
/// `node_count` gives the majority threshold. Returns the new commitIndex
/// (`>= commit_index`).
///
/// **Why Fable — this is Figure 8:** the intuitive rule "commit any entry on a
/// majority" is WRONG. An entry from an OLDER term sitting on a majority can
/// still be overwritten by a future leader whose log did not contain it — so
/// committing it, then having it disappear, breaks **State Machine Safety**. A
/// leader may only *directly* commit entries from its current term; older-term
/// entries become committed only *indirectly*, once a current-term entry above
/// them is committed. This one predicate is the reason Raft needed a formal
/// proof — the counterexample is literally Figure 8 of the paper.
pub fn leaderCommitIndex(current_term: Term, commit_index: LogIndex, match_index: []const LogIndex, node_count: usize, log: *const Log) LogIndex {
    if (!gate.fable_core_implemented) @panic("TODO(fable/core): §5.4.2 Figure-8 commit rule — majority AND entry.term == current_term");
    _ = current_term;
    _ = commit_index;
    _ = match_index;
    _ = node_count;
    _ = log;
    unreachable;
}

// ── [FABLE-CORE, design-only] membership changes (§6) ───────────────────────

/// Joint-consensus safety check (§6): during a `C_old → C_old,new → C_new`
/// transition, an election or commit counts only if it wins majorities in BOTH
/// the old and new configurations. **[FABLE-CORE, DESIGN-ONLY in Phase 1]** —
/// full membership change (joint consensus, the config-entry-takes-effect-on-
/// append rule, the no-op-in-current-term leader precondition) is designed in
/// SPEC.md §Membership but scaffolded only: this predicate is stubbed, `config`
/// log entries carry no payload yet, and the harness does not fuzz membership.
/// Left as the natural next Fable increment after the core five properties hold.
pub fn jointMajority(old_ids: []const NodeId, new_ids: []const NodeId, granted: []const NodeId) bool {
    if (!gate.fable_core_implemented) @panic("TODO(fable/core): §6 joint-consensus majority over C_old AND C_new (design-only in Phase 1)");
    _ = old_ids;
    _ = new_ids;
    _ = granted;
    unreachable;
}

// ── [mechanical, implemented] term observation (§5.1) ───────────────────────

pub const TermObservation = struct {
    /// The incoming term was strictly higher — the server must adopt it and
    /// revert to follower (clearing its vote for the new term).
    term_advanced: bool,
    /// The server's term after observing the message.
    new_term: Term,
};

/// Apply §5.1's universal rule to any incoming RPC/response term: "if the
/// message's term > currentTerm, set currentTerm = term and convert to
/// follower." **[mechanical, implemented]** — a single comparison. It lives in
/// this file because it IS a term/role safety rule, but it is not Fable-hard, so
/// it is implemented in the clear (honest tiering — see the file header). Used
/// on the RESPONSE and heartbeat paths; the request handlers above fold their
/// own term step-up into their verdict.
pub fn observeTerm(current_term: Term, msg_term: Term) TermObservation {
    if (msg_term > current_term) return .{ .term_advanced = true, .new_term = msg_term };
    return .{ .term_advanced = false, .new_term = current_term };
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// The FABLE-CORE decision types are plain data — constructing them exercises
// their shapes at the type level without entering any panicking body (mirrors
// df-elect's "SegmentView/Decision are plain data" test). `observeTerm` is
// implemented, so it is tested for real.

const testing = std.testing;

test "decision result types are plain data (compile-only, no stub call)" {
    const v = VoteDecision{ .grant = true, .term_advanced = false, .new_term = 3, .voted_for = 2 };
    try testing.expect(v.grant and v.new_term == 3);

    const a = AppendOutcome{
        .term_advanced = true,
        .new_term = 5,
        .success = true,
        .truncate_to = 4,
        .append_from = 1,
        .new_commit_index = 4,
    };
    try testing.expect(a.success and a.truncate_to == 4);

    const info = LogInfo{ .last_index = 9, .last_term = 2 };
    try testing.expectEqual(@as(LogIndex, 9), info.last_index);
}

test "observeTerm: adopts a strictly higher term, holds otherwise (mechanical rule, real test)" {
    try testing.expectEqual(TermObservation{ .term_advanced = true, .new_term = 7 }, observeTerm(3, 7));
    try testing.expectEqual(TermObservation{ .term_advanced = false, .new_term = 5 }, observeTerm(5, 5));
    try testing.expectEqual(TermObservation{ .term_advanced = false, .new_term = 5 }, observeTerm(5, 2));
}
