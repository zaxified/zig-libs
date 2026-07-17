// SPDX-License-Identifier: MIT

//! safety — THE FABLE CORE: the consensus-safety decision logic where Raft's
//! subtle bugs hide, isolated as PURE functions so it is model-checkable in
//! `netsim` and unit-testable in isolation. The bodies are IMPLEMENTED (the
//! Fable pass landed; `gate.fable_core_implemented == true`). `server.zig` (the
//! mechanical protocol) calls these to make every safety-relevant decision and
//! then MECHANICALLY executes the returned verdict (send a vote, truncate+append
//! the log, advance commitIndex) — the *judgement* is here, the *plumbing* is
//! there.
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
///
/// TERM FIRST, index only as the tie-break. The wrong-but-plausible orders
/// (index first, or index only) let an old partitioned leader that kept
/// appending a LONG tail of stale-term entries outrank a short log that
/// contains newly committed entries — electing a leader that then overwrites
/// them. Term-first is what makes "your log ends in a newer term" always beat
/// "your log is longer".
pub fn logIsAtLeastAsUpToDate(cand: LogInfo, mine: LogInfo) bool {
    if (cand.last_term != mine.last_term) return cand.last_term > mine.last_term;
    return cand.last_index >= mine.last_index;
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
///
/// Clause order matters: the stale-term rejection comes first (a deposed
/// leader's candidate must not extract votes); the step-up to a strictly higher
/// term clears the CURRENT vote (a vote binds to a term — a new term is a new
/// ballot); only then are the single-vote and up-to-date gates evaluated
/// against the post-step-up state.
pub fn handleRequestVote(current_term: Term, voted_for: NodeId, my_log: LogInfo, req: RequestVoteReq) VoteDecision {
    // §5.1: a request from a STALE term is refused outright — no state change.
    if (req.term < current_term)
        return .{ .grant = false, .term_advanced = false, .new_term = current_term };

    // §5.1: a strictly higher term forces adoption + step-down; the vote slot
    // resets with the new term (one ballot per term, and this is a new ballot).
    const term_advanced = req.term > current_term;
    const effective_vote: NodeId = if (term_advanced) types.no_vote else voted_for;

    // §5.2: at most one vote per term — re-granting to the SAME candidate is
    // allowed (idempotent, so a duplicated/retried RequestVote is harmless).
    const may_vote = effective_vote == types.no_vote or effective_vote == req.candidate_id;

    // §5.4.1: the election restriction — only a candidate whose log is at least
    // as up-to-date may receive the vote (Leader Completeness hinges here).
    const cand = LogInfo{ .last_index = req.last_log_index, .last_term = req.last_log_term };
    const grant = may_vote and logIsAtLeastAsUpToDate(cand, my_log);

    return .{
        .grant = grant,
        .term_advanced = term_advanced,
        .new_term = req.term,
        .voted_for = if (grant) req.candidate_id else types.no_vote,
    };
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
    /// `max(commitIndex, min(leaderCommit, index of last new entry))` (§5.3;
    /// the outer max keeps a delayed/duplicated RPC from REGRESSING an already
    /// advanced commitIndex). Meaningless if `!success`.
    new_commit_index: LogIndex = 0,
    /// On success: the highest log index the follower now KNOWS matches the
    /// leader — `prevLogIndex + entries.len` — which is what the reply must
    /// advertise for the leader's `matchIndex[i]`. NOT the follower's raw last
    /// index: the log may extend past the verified region with a stale tail
    /// from an older leader that this RPC neither checked nor truncated (no
    /// conflict inside the batch window), and advertising that tail would let
    /// the leader count unverified — possibly divergent — entries toward a
    /// majority and commit an entry a "replica" does not actually hold.
    /// Meaningless if `!success`.
    match_index: LogIndex = 0,
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
    // §5.1: refuse a STALE leader outright (it will observe our term and step down).
    if (req.term < current_term)
        return .{ .term_advanced = false, .new_term = current_term, .success = false };
    const term_advanced = req.term > current_term;
    const new_term = req.term;

    // §5.3 consistency check: our log must contain an entry at prevLogIndex
    // whose term is prevLogTerm (index 0 carries the sentinel term 0, so an
    // empty-prefix check trivially passes). Failure leaves the log untouched;
    // the leader decrements nextIndex and retries lower.
    const prev_term = log.termAt(req.prev_log_index) orelse
        return .{ .term_advanced = term_advanced, .new_term = new_term, .success = false };
    if (prev_term != req.prev_log_term)
        return .{ .term_advanced = term_advanced, .new_term = new_term, .success = false };

    // §5.3 conflict rule — CONFLICT-ONLY truncation. Walk the incoming batch:
    //   - an existing entry with the SAME term at that index is the same entry
    //     (Log Matching) — keep it, skip the incoming copy;
    //   - the first existing entry with a DIFFERENT term is a conflict — delete
    //     it and everything after, then append from here;
    //   - if our log ends first, nothing conflicts — just append the remainder.
    // The naive "truncate everything after prevLogIndex, then append" is the
    // trap: a delayed or duplicated AppendEntries would roll back entries the
    // follower already accepted from a LATER RPC — entries that may already be
    // committed and applied — losing committed state (see the regression test).
    var truncate_to: LogIndex = log.lastIndex(); // default: keep everything
    var append_from: usize = req.entries.len; // default: nothing left to append
    for (req.entries, 0..) |e, i| {
        const idx: LogIndex = req.prev_log_index + 1 + @as(LogIndex, @intCast(i));
        const existing = log.termAt(idx) orelse {
            append_from = i; // log ends before idx — append from here, no cut
            break;
        };
        if (existing != e.term) {
            truncate_to = idx - 1; // conflict — cut it and everything after
            append_from = i;
            break;
        }
        // same index + same term ⇒ identical entry — skip, never re-truncate
    }

    // §5.3 follower commit: cap at the LAST NEW ENTRY (prev + batch len), not
    // at our raw last index — any tail beyond the verified region is unverified
    // and must not be committed on this leader's word. The outer max keeps a
    // stale leaderCommit (delayed/duplicated RPC) from regressing commitIndex.
    const last_new: LogIndex = req.prev_log_index + @as(LogIndex, @intCast(req.entries.len));
    const new_commit = @max(commit_index, @min(req.leader_commit, last_new));

    return .{
        .term_advanced = term_advanced,
        .new_term = new_term,
        .success = true,
        .truncate_to = truncate_to,
        .append_from = append_from,
        .new_commit_index = new_commit,
        .match_index = last_new,
    };
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
///
/// Implementation note: log terms are non-decreasing, so the scan walks DOWN
/// from lastIndex and stops at the first entry older than `current_term` —
/// everything below is older still and can only commit indirectly. Returning
/// the highest qualifying N commits every entry ≤ N at once (the indirect
/// mechanism): Log Matching guarantees anyone holding the current-term entry
/// at N holds the identical prefix below it, so the old-term entries ride
/// along under the protection the current-term entry earned.
pub fn leaderCommitIndex(current_term: Term, commit_index: LogIndex, match_index: []const LogIndex, node_count: usize, log: *const Log) LogIndex {
    const needed = node_count / 2 + 1;
    var n: LogIndex = log.lastIndex();
    while (n > commit_index) : (n -= 1) {
        // n ∈ (commit_index, lastIndex] is always in range.
        const t = log.termAt(n).?;
        // Figure 8, the crux: NEVER directly commit an entry from another term.
        // An older-term entry on a majority can still be overwritten by a
        // future leader that never saw it (its electorate needs no overlap with
        // holders of a mere old-term entry) — only a CURRENT-term entry on a
        // majority forces every future electorate to intersect voters whose
        // last term blocks such a rival (§5.4.1 up-to-date check).
        if (t < current_term) break; // non-decreasing terms: nothing lower qualifies
        if (t > current_term) continue; // defensive; a leader's log cannot exceed its term
        var replicas: usize = 0;
        for (match_index) |m| {
            if (m >= n) replicas += 1;
        }
        if (replicas >= needed) return n;
    }
    return commit_index;
}

// ── [FABLE-CORE, design-only] membership changes (§6) ───────────────────────

/// Joint-consensus safety check (§6): during a `C_old → C_old,new → C_new`
/// transition, an election or commit counts only if it wins majorities in BOTH
/// the old and new configurations. **[FABLE-CORE, DESIGN-ONLY in Phase 1]** —
/// full membership change (joint consensus, the config-entry-takes-effect-on-
/// append rule, the no-op-in-current-term leader precondition) is designed in
/// SPEC.md §Membership but scaffolded only: this predicate is implemented and
/// unit-tested, but `config` log entries carry no payload yet and the harness
/// does not fuzz membership. Wiring it into elections/commits is the natural
/// next Fable increment now that the core five properties hold.
///
/// Implemented (correct §6 predicate) even though Phase 1's harness does not
/// yet fuzz membership — the gate must not leave any reachable `@panic`. The
/// subtlety it encodes: a SINGLE combined majority over `C_old ∪ C_new` is the
/// wrong-but-plausible rule — it can be satisfied entirely by new-config nodes
/// while a disjoint old-config majority elects a second leader (or vice versa);
/// only the conjunction of INDEPENDENT majorities makes the two configurations'
/// quorums always intersect. An empty configuration has no majority
/// (conservative: the predicate returns false rather than vacuous truth).
/// Configuration member lists are assumed duplicate-free (they are node sets);
/// duplicates in `granted` cannot double-count (membership is tested per id).
pub fn jointMajority(old_ids: []const NodeId, new_ids: []const NodeId, granted: []const NodeId) bool {
    return hasMajority(old_ids, granted) and hasMajority(new_ids, granted);
}

fn hasMajority(config: []const NodeId, granted: []const NodeId) bool {
    var count: usize = 0;
    for (config) |id| {
        if (std.mem.indexOfScalar(NodeId, granted, id) != null) count += 1;
    }
    return count >= config.len / 2 + 1;
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
// Unit tests for the pure decision kernel, one block per documented failure
// mode (the wrong-but-plausible implementations each function's doc names).
// The end-to-end proof — the real `RaftServer` under the fuzzed fault sweep,
// all five invariants live — is the gated model-check pair in `server.zig`.

const testing = std.testing;

test "decision result types are plain data" {
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

test "§5.4.1 up-to-date: term dominates index; index breaks term ties" {
    const short_new = LogInfo{ .last_index = 2, .last_term = 5 };
    const long_old = LogInfo{ .last_index = 100, .last_term = 4 };
    // The whole game: a short log ending in a newer term BEATS a long stale log.
    try testing.expect(logIsAtLeastAsUpToDate(short_new, long_old));
    try testing.expect(!logIsAtLeastAsUpToDate(long_old, short_new));
    // Equal terms: longer (or equal) index wins.
    const a = LogInfo{ .last_index = 7, .last_term = 3 };
    const b = LogInfo{ .last_index = 9, .last_term = 3 };
    try testing.expect(logIsAtLeastAsUpToDate(b, a));
    try testing.expect(!logIsAtLeastAsUpToDate(a, b));
    try testing.expect(logIsAtLeastAsUpToDate(a, a)); // "at least as" — equality grants
    // Empty logs (0/0 sentinels) are mutually up-to-date.
    try testing.expect(logIsAtLeastAsUpToDate(.{}, .{}));
}

test "§5.2 RequestVote: stale term refused, no state change" {
    const req = RequestVoteReq{ .term = 2, .candidate_id = 1, .last_log_index = 99, .last_log_term = 99 };
    const d = handleRequestVote(5, types.no_vote, .{}, req);
    try testing.expect(!d.grant);
    try testing.expect(!d.term_advanced);
    try testing.expectEqual(@as(Term, 5), d.new_term);
}

test "§5.2 RequestVote: single vote per term — second candidate refused, same candidate re-granted" {
    const my_log = LogInfo{ .last_index = 3, .last_term = 1 };
    const c1 = RequestVoteReq{ .term = 2, .candidate_id = 1, .last_log_index = 3, .last_log_term = 1 };
    const c2 = RequestVoteReq{ .term = 2, .candidate_id = 4, .last_log_index = 9, .last_log_term = 1 };

    // First ask (term steps up 1→2, vote slot fresh): grant to candidate 1.
    const d1 = handleRequestVote(1, types.no_vote, my_log, c1);
    try testing.expect(d1.grant and d1.term_advanced);
    try testing.expectEqual(@as(Term, 2), d1.new_term);
    try testing.expectEqual(@as(NodeId, 1), d1.voted_for);

    // Same term, already voted for 1: candidate 4 is refused even with a better log.
    const d2 = handleRequestVote(2, 1, my_log, c2);
    try testing.expect(!d2.grant);
    try testing.expect(!d2.term_advanced);

    // Duplicate ask from candidate 1: idempotent re-grant.
    const d3 = handleRequestVote(2, 1, my_log, c1);
    try testing.expect(d3.grant);
    try testing.expectEqual(@as(NodeId, 1), d3.voted_for);
}

test "§5.4.1 RequestVote: a higher term does NOT excuse an out-of-date log; refusal still adopts the term" {
    const my_log = LogInfo{ .last_index = 5, .last_term = 3 };
    const behind = RequestVoteReq{ .term = 9, .candidate_id = 2, .last_log_index = 4, .last_log_term = 3 };
    const d = handleRequestVote(3, types.no_vote, my_log, behind);
    try testing.expect(!d.grant); // log not up-to-date — no vote…
    try testing.expect(d.term_advanced); // …but the higher term is still adopted (§5.1)
    try testing.expectEqual(@as(Term, 9), d.new_term);
}

test "§5.2 RequestVote: a fresh (higher) term clears an old vote — new ballot, new grant" {
    // Voted for 1 in term 2; candidate 4 asks in term 3: the step-up resets the
    // slot, so 4 can be granted.
    const my_log = LogInfo{ .last_index = 3, .last_term = 1 };
    const c4 = RequestVoteReq{ .term = 3, .candidate_id = 4, .last_log_index = 3, .last_log_term = 1 };
    const d = handleRequestVote(2, 1, my_log, c4);
    try testing.expect(d.grant and d.term_advanced);
    try testing.expectEqual(@as(NodeId, 4), d.voted_for);
}

// Helper: build a log from (term) slices, command = 100 + position.
fn buildLog(gpa: std.mem.Allocator, terms: []const Term) !Log {
    var l = Log{};
    errdefer l.deinit(gpa);
    for (terms, 0..) |t, i| try l.append(gpa, .{ .term = t, .command = 100 + @as(u64, @intCast(i)) });
    return l;
}

test "§5.3 AppendEntries: stale leader refused; consistency check gates missing/mismatched prev" {
    const gpa = testing.allocator;
    var l = try buildLog(gpa, &.{ 1, 1, 2 });
    defer l.deinit(gpa);

    // Stale term → refused, term untouched.
    const stale = AppendEntriesReq{ .term = 1, .leader_id = 0, .prev_log_index = 3, .prev_log_term = 2, .entries = &.{}, .leader_commit = 0 };
    const o1 = handleAppendEntries(2, &l, 0, stale);
    try testing.expect(!o1.success and !o1.term_advanced);
    try testing.expectEqual(@as(Term, 2), o1.new_term);

    // prev past the end → fail (but the higher term IS adopted).
    const hole = AppendEntriesReq{ .term = 3, .leader_id = 0, .prev_log_index = 5, .prev_log_term = 2, .entries = &.{}, .leader_commit = 0 };
    const o2 = handleAppendEntries(2, &l, 0, hole);
    try testing.expect(!o2.success and o2.term_advanced);
    try testing.expectEqual(@as(Term, 3), o2.new_term);

    // prev in range but wrong term → fail.
    const mismatch = AppendEntriesReq{ .term = 3, .leader_id = 0, .prev_log_index = 3, .prev_log_term = 1, .entries = &.{}, .leader_commit = 0 };
    try testing.expect(!handleAppendEntries(2, &l, 0, mismatch).success);

    // prev == 0 (sentinel) always passes the check.
    const base = AppendEntriesReq{ .term = 3, .leader_id = 0, .prev_log_index = 0, .prev_log_term = 0, .entries = &.{}, .leader_commit = 0 };
    try testing.expect(handleAppendEntries(2, &l, 0, base).success);
}

test "§5.3 conflict rule: matching entries are skipped, first conflict truncates, fresh tail appends" {
    const gpa = testing.allocator;
    var l = try buildLog(gpa, &.{ 1, 1, 2, 2 });
    defer l.deinit(gpa);

    // Batch over indices 2..5: index 2 and 3 match (terms 1,2), index 4
    // CONFLICTS (ours term 2, incoming term 3) → keep [1..3], append from the
    // conflicting element on.
    const entries = [_]types.LogEntry{
        .{ .term = 1, .command = 101 }, // idx 2 — matches, skip
        .{ .term = 2, .command = 102 }, // idx 3 — matches, skip
        .{ .term = 3, .command = 900 }, // idx 4 — conflict (ours: term 2)
        .{ .term = 3, .command = 901 }, // idx 5 — new
    };
    const req = AppendEntriesReq{ .term = 3, .leader_id = 0, .prev_log_index = 1, .prev_log_term = 1, .entries = &entries, .leader_commit = 0 };
    const o = handleAppendEntries(3, &l, 0, req);
    try testing.expect(o.success);
    try testing.expectEqual(@as(LogIndex, 3), o.truncate_to);
    try testing.expectEqual(@as(usize, 2), o.append_from);
    try testing.expectEqual(@as(LogIndex, 5), o.match_index);

    // Log ends mid-batch, no conflict: nothing truncated, append the remainder.
    const tail = [_]types.LogEntry{
        .{ .term = 2, .command = 103 }, // idx 4 — matches our last entry
        .{ .term = 2, .command = 104 }, // idx 5 — past our end, append
    };
    const req2 = AppendEntriesReq{ .term = 2, .leader_id = 0, .prev_log_index = 3, .prev_log_term = 2, .entries = &tail, .leader_commit = 0 };
    const o2 = handleAppendEntries(2, &l, 0, req2);
    try testing.expect(o2.success);
    try testing.expectEqual(l.lastIndex(), o2.truncate_to); // no cut
    try testing.expectEqual(@as(usize, 1), o2.append_from);
}

test "§5.3 the trap: a duplicated old AppendEntries must NOT roll back later entries (conflict-only truncation)" {
    const gpa = testing.allocator;
    // Follower already accepted entries 1..4 from the leader (all term 1) via
    // two RPCs; entries 1..4 are committed and applied. Now the FIRST RPC
    // (prev=0, entries 1..3) is delivered AGAIN (dup_once / retransmit).
    var l = try buildLog(gpa, &.{ 1, 1, 1, 1 });
    defer l.deinit(gpa);
    const dup_entries = [_]types.LogEntry{
        .{ .term = 1, .command = 100 },
        .{ .term = 1, .command = 101 },
        .{ .term = 1, .command = 102 },
    };
    const dup = AppendEntriesReq{ .term = 1, .leader_id = 0, .prev_log_index = 0, .prev_log_term = 0, .entries = &dup_entries, .leader_commit = 2 };
    const o = handleAppendEntries(1, &l, 4, dup);
    try testing.expect(o.success);
    // The naive rule would truncate to 0 and re-append 3 entries — deleting the
    // COMMITTED entry 4. Conflict-only keeps the whole log and appends nothing.
    try testing.expectEqual(@as(LogIndex, 4), o.truncate_to);
    try testing.expectEqual(@as(usize, 3), o.append_from);
    // And the stale leaderCommit=2 must not REGRESS our commitIndex=4.
    try testing.expectEqual(@as(LogIndex, 4), o.new_commit_index);
    // The reply advertises only the verified region (prev+len=3), never the raw
    // last index.
    try testing.expectEqual(@as(LogIndex, 3), o.match_index);
}

test "§5.3 follower commit: capped at the last NEW entry, not at leaderCommit or our stale tail" {
    const gpa = testing.allocator;
    // Our log: 1..2 match the leader (term 1); 3..5 are a STALE tail (term 2
    // from a deposed leader). New leader (term 3) sends prev=2 with one entry.
    var l = try buildLog(gpa, &.{ 1, 1, 2, 2, 2 });
    defer l.deinit(gpa);
    const entries = [_]types.LogEntry{.{ .term = 3, .command = 300 }}; // idx 3 — conflicts
    const req = AppendEntriesReq{ .term = 3, .leader_id = 0, .prev_log_index = 2, .prev_log_term = 1, .entries = &entries, .leader_commit = 9 };
    const o = handleAppendEntries(2, &l, 1, req);
    try testing.expect(o.success and o.term_advanced);
    try testing.expectEqual(@as(LogIndex, 2), o.truncate_to); // cut the stale tail
    // leaderCommit=9 but only 3 entries are verified after this RPC → commit 3,
    // never 5 (which would commit the stale tail) and never 9.
    try testing.expectEqual(@as(LogIndex, 3), o.new_commit_index);
    try testing.expectEqual(@as(LogIndex, 3), o.match_index);
}

test "§5.4.2 Figure 8: an old-term entry on a majority must NOT commit; a current-term entry commits it indirectly" {
    const gpa = testing.allocator;
    // Leader of term 4. Its log: idx1 term1, idx2 term2 (the Figure-8 entry),
    // idx3 term4 (its own no-op).
    var l = try buildLog(gpa, &.{ 1, 2, 4 });
    defer l.deinit(gpa);

    // idx2 (term 2) is on a majority (3 of 5) — but it is NOT from term 4:
    // committing it here is the canonical bug (S5 could still win term 5 with
    // its term-3 log and overwrite idx2 everywhere).
    const match_old = [_]LogIndex{ 2, 2, 2, 0, 0 };
    try testing.expectEqual(@as(LogIndex, 0), leaderCommitIndex(4, 0, &match_old, 5, &l));

    // Once the CURRENT-term entry idx3 reaches a majority, it commits — and
    // idx2 rides along (indirect commit): return jumps straight to 3.
    const match_cur = [_]LogIndex{ 3, 3, 3, 0, 0 };
    try testing.expectEqual(@as(LogIndex, 3), leaderCommitIndex(4, 0, &match_cur, 5, &l));

    // Sub-majority current-term replication commits nothing.
    const match_minor = [_]LogIndex{ 3, 3, 0, 0, 0 };
    try testing.expectEqual(@as(LogIndex, 0), leaderCommitIndex(4, 0, &match_minor, 5, &l));

    // commitIndex never regresses and never passes lastIndex.
    try testing.expectEqual(@as(LogIndex, 3), leaderCommitIndex(4, 3, &match_cur, 5, &l));
}

test "§6 joint majority: needs INDEPENDENT majorities in both configs, not one combined pool" {
    const c_old = [_]NodeId{ 0, 1, 2 };
    const c_new = [_]NodeId{ 2, 3, 4 };

    // Majority of old (0,1) + majority of new (3,4) — 2 also helps neither side here.
    try testing.expect(jointMajority(&c_old, &c_new, &.{ 0, 1, 3, 4 }));

    // Four grants, but ALL from the new side: old config has only 1 of 3 → no.
    // (A combined-pool rule would wrongly accept this.)
    try testing.expect(!jointMajority(&c_old, &c_new, &.{ 2, 3, 4, 4 }));

    // Old-only majority without a new majority → no.
    try testing.expect(!jointMajority(&c_old, &c_new, &.{ 0, 1 }));

    // The shared node counts toward BOTH sides.
    try testing.expect(jointMajority(&c_old, &c_new, &.{ 0, 2, 3 }));

    // Empty configuration: conservative false, never vacuous truth.
    try testing.expect(!jointMajority(&.{}, &c_new, &.{ 2, 3, 4 }));
}

test "observeTerm: adopts a strictly higher term, holds otherwise (mechanical rule, real test)" {
    try testing.expectEqual(TermObservation{ .term_advanced = true, .new_term = 7 }, observeTerm(3, 7));
    try testing.expectEqual(TermObservation{ .term_advanced = false, .new_term = 5 }, observeTerm(5, 5));
    try testing.expectEqual(TermObservation{ .term_advanced = false, .new_term = 5 }, observeTerm(5, 2));
}
