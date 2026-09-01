// SPDX-License-Identifier: MIT

//! server — the `netsim.Protocol` consumer(s).
//!
//!  - `RaftServer` is the real thing: election timers + heartbeats, RequestVote
//!    and AppendEntries RPC exchange, the leader-commit loop — making every
//!    safety-relevant decision through `safety.zig` (the Fable core, now
//!    implemented) and MECHANICALLY executing the verdict (truncate/append the
//!    log, advance commitIndex, apply). Its model-checking tests run for real
//!    now that `gate.fable_core_implemented` is `true`.
//!  - `BrokenRaft` is the POSITIVE CONTROL: a deliberately-wrong election that
//!    declares leadership WITHOUT collecting a majority and never calls
//!    `safety.zig`, so it runs today. Its job is to prove `checks.SafetyChecker`
//!    has teeth — it reuses that EXACT type, so the `error.ElectionSafety` it
//!    trips is provably the same check the real protocol will be held to.
//!
//! Cluster topology (`scenario`): a 5-node full mesh, so a partition can carve
//! the cluster into a majority and a minority side (the case leader election and
//! the commit rule must survive) and heal.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");
const log_mod = @import("log.zig");
const safety = @import("safety.zig");
const checks = @import("checks.zig");
const gate = @import("gate.zig");

const Allocator = std.mem.Allocator;
const NodeId = netsim.NodeId;
const Time = netsim.Time;
const Sim = netsim.Sim;
const Protocol = netsim.Protocol;
const LinkConfig = netsim.LinkConfig;

const Term = types.Term;
const LogIndex = types.LogIndex;
const Command = types.Command;
const LogEntry = types.LogEntry;
const Log = log_mod.Log;
const no_vote = types.no_vote;

// ── shared topology + config ────────────────────────────────────────────────

pub const CLUSTER_N = 5;

pub const RaftConfig = struct {
    /// Base ticks a follower waits without hearing from a leader before starting
    /// an election.
    election_timeout: Time = 100,
    /// Per-node deterministic offset added to `election_timeout` (`node *
    /// election_spread`) — Raft's randomized timeout, made deterministic for the
    /// sim so it still de-synchronizes candidates and avoids perpetual split
    /// votes.
    election_spread: Time = 15,
    /// How often a leader emits heartbeats. Must be well under
    /// `election_timeout` so a live leader keeps followers from timing out.
    heartbeat_period: Time = 30,
    /// Propose one DISTINCT client command per heartbeat while leader.
    ///
    /// This is what gives the live State-Machine-Safety and Log-Matching
    /// checkers teeth. With it off, every replicated entry is the leader's own
    /// `command = 0` no-op, so `SafetyChecker.recordApply` — which keys on the
    /// command VALUE — compares zero against zero at every index and can never
    /// observe a divergent apply: the deepest invariant certifies instead of
    /// checking. See `commandFor` and the `bug:` positive controls.
    propose_client_commands: bool = true,
};

/// The command payload for the entry a leader creates at `index` while serving
/// `term`: the pair packed into the sim's `u64` command word.
///
/// Distinctness is the whole point. Two servers may legally hold DIFFERENT
/// entries at the same index (an uncommitted tail from a deposed leader), and
/// State Machine Safety is the claim that they never *apply* different ones
/// there. That claim is only observable if entries created by different terms
/// at the same index carry different commands — Election Safety already gives
/// at most one leader per term, so `(term, index)` uniquely names an entry's
/// creator, and equal commands at an index now mean "the same entry" rather
/// than "both were zero".
pub fn commandFor(term: Term, index: LogIndex) Command {
    return (@as(Command, @truncate(term)) << 32) | @as(Command, @truncate(index));
}

/// A deliberately-wrong Raft rule, injectable into the REAL `RaftServer` so the
/// live model-check can be shown to catch it. Distinct from `BrokenRaft`, which
/// is a separate protocol that never calls `safety.zig` at all: these mutate
/// one clause of the real algorithm, which is the shape a regression actually
/// takes. Both were injected by hand during the audit, and both PASSED the
/// 300-seed sweep back when every entry was a `command = 0` no-op — they are
/// the exact reason `propose_client_commands` exists.
pub const InjectedBug = enum {
    /// The real algorithm.
    none,
    /// §5.3 conflict rule replaced by the naive "truncate everything after
    /// prevLogIndex, then append the whole batch" — a delayed or duplicated
    /// AppendEntries rolls back entries the follower already accepted (and may
    /// already have applied) from a later RPC.
    naive_truncation,
    /// §5.4.1 election restriction with the TERM-first clause dropped: a
    /// candidate is up-to-date iff its log is at least as LONG. A partitioned
    /// ex-leader with a long stale-term tail can then win and overwrite
    /// committed entries.
    index_only_up_to_date,
};

pub fn scenario(sim: *Sim) anyerror!void {
    var i: usize = 0;
    while (i < CLUSTER_N) : (i += 1) _ = try sim.addNode(.{});
    const cfg = LinkConfig{ .latency = 5, .jitter = 2 };
    var a: NodeId = 0;
    while (a < CLUSTER_N) : (a += 1) {
        var b: NodeId = a + 1;
        while (b < CLUSTER_N) : (b += 1) try sim.addBiLink(a, b, cfg);
    }
}

fn majority(node_count: usize) u32 {
    return @intCast(node_count / 2 + 1);
}

// Timer id space: heartbeat uses a fixed sentinel; election timers carry a
// per-node epoch (< sentinel) so a stale election timer that fires after the
// node re-armed can be recognized and ignored (netsim timers cannot be
// cancelled).
const HEARTBEAT_TIMER: u64 = std.math.maxInt(u64);

const Role = enum { follower, candidate, leader };

// ── RaftServer: the real protocol (calls the Fable stub) ────────────────────

const NodeState = struct {
    // persistent (Figure 2)
    current_term: Term = 0,
    voted_for: NodeId = no_vote,
    log: Log = .{},
    // volatile (all servers)
    role: Role = .follower,
    commit_index: LogIndex = 0,
    last_applied: LogIndex = 0,
    election_epoch: u64 = 0,
    // Candidate vote tally, per GRANTING PEER (self included) — a set, not a
    // counter: the network duplicates messages (dup faults), and counting the
    // same voter's duplicated grant twice would manufacture a fake majority —
    // two leaders in one term (Election Safety gone) from one dup_once fault.
    votes_from: []bool,
    // volatile (leaders) — per-peer, indexed by NodeId; self slot tracks own log
    next_index: []LogIndex,
    match_index: []LogIndex,
    // Leader Append-Only witness: the leader's log as of the previous `check`.
    prev_log: std.ArrayList(LogEntry) = .empty,

    fn init(gpa: Allocator, node_count: usize) Allocator.Error!NodeState {
        const vf = try gpa.alloc(bool, node_count);
        errdefer gpa.free(vf);
        @memset(vf, false);
        const ni = try gpa.alloc(LogIndex, node_count);
        errdefer gpa.free(ni);
        @memset(ni, 0);
        const mi = try gpa.alloc(LogIndex, node_count);
        @memset(mi, 0);
        return .{ .votes_from = vf, .next_index = ni, .match_index = mi };
    }

    fn deinit(self: *NodeState, gpa: Allocator) void {
        self.log.deinit(gpa);
        gpa.free(self.votes_from);
        gpa.free(self.next_index);
        gpa.free(self.match_index);
        self.prev_log.deinit(gpa);
    }

    fn resetAll(self: *NodeState) void {
        self.current_term = 0;
        self.voted_for = no_vote;
        self.log.reset();
        self.role = .follower;
        self.commit_index = 0;
        self.last_applied = 0;
        self.election_epoch = 0;
        @memset(self.votes_from, false);
        @memset(self.next_index, 0);
        @memset(self.match_index, 0);
        self.prev_log.clearRetainingCapacity();
    }

    fn voteCount(self: *const NodeState) u32 {
        var n: u32 = 0;
        for (self.votes_from) |g| {
            if (g) n += 1;
        }
        return n;
    }
};

pub const RaftServer = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: RaftConfig,
    nodes: []NodeState,
    checker: checks.SafetyChecker = .{},
    /// index → the term in which that index was FIRST committed (the committing
    /// leader's term). Raft's Leader Completeness (Figure 3) constrains "the
    /// leaders of all HIGHER-numbered terms" than the commit — a deposed leader
    /// still holding `.leader` inside a minority partition legally misses
    /// entries committed in LATER terms, so `check` must scope the predicate by
    /// this term or it flags legal executions. The first `recordCommitted` for
    /// an index is always by the committing leader itself (commitIndex advances
    /// on the leader synchronously in `handleAppendResp`, before any follower
    /// can observe the new leaderCommit), so first-record term == commit term.
    commit_terms: std.AutoHashMapUnmanaged(LogIndex, Term) = .empty,

    /// Inbound messages dropped because they did not decode (see
    /// `dropMalformed`). Raft has no "your message was garbage" reply in
    /// Figure 2, so a malformed datagram is DROPPED — but it is counted, not
    /// silently swallowed, because a drop is otherwise invisible.
    ///
    /// In this harness the only sender is our own `encode`, so a non-zero
    /// count means a codec bug on our side, and the model-check asserts it
    /// stays 0 (`expectNoMalformed`). That is what makes the counter load-
    /// bearing rather than decorative.
    malformed_dropped: u64 = 0,

    /// Deliberate defect to run instead of the real rule. `.none` in every
    /// production path; the positive-control tests set it and REQUIRE the live
    /// checker to trip. See `InjectedBug`.
    bug: InjectedBug = .none,

    pub fn init(gpa: Allocator, node_count: usize, cfg: RaftConfig) Allocator.Error!RaftServer {
        const nodes = try gpa.alloc(NodeState, node_count);
        var made: usize = 0;
        errdefer {
            for (nodes[0..made]) |*n| n.deinit(gpa);
            gpa.free(nodes);
        }
        for (nodes) |*n| {
            n.* = try NodeState.init(gpa, node_count);
            made += 1;
        }
        return .{ .gpa = gpa, .node_count = node_count, .cfg = cfg, .nodes = nodes };
    }

    pub fn deinit(self: *RaftServer, gpa: Allocator) void {
        for (self.nodes) |*n| n.deinit(gpa);
        gpa.free(self.nodes);
        self.checker.deinit(gpa);
        self.commit_terms.deinit(gpa);
        self.* = undefined;
    }

    pub fn protocol(self: *RaftServer) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *RaftServer {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        for (self.nodes) |*n| n.resetAll();
        self.checker.reset();
        self.commit_terms.clearRetainingCapacity();
        self.malformed_dropped = 0;
    }

    // ── timers ──────────────────────────────────────────────────────────────

    fn resetElectionTimer(self: *RaftServer, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        ns.election_epoch += 1;
        const delay = self.cfg.election_timeout + @as(Time, node) * self.cfg.election_spread;
        try sim.setTimer(node, delay, ns.election_epoch);
    }

    /// Adopt `new_term`, revert to follower (§5.1) and RE-ARM the election
    /// timer.
    ///
    /// The re-arm is the part that is easy to lose, and losing it is a silent
    /// liveness bug rather than a crash. A leader holds NO live election timer:
    /// `onTimer` swallows the one it armed as a candidate (`role == .leader` →
    /// return) without re-arming, because a leader must not campaign against
    /// itself. So from one timeout after its election, a leader's only way back
    /// to an armed timer is a step-down that re-arms. A step-down that does not
    /// leaves a node that answers every RPC correctly and is never electable
    /// again — see the `demoted by a RESPONSE` regression test, which asserts an
    /// election actually STARTS, since asserting `role == .follower` passes
    /// either way.
    fn stepDown(self: *RaftServer, sim: *Sim, node: NodeId, new_term: Term) anyerror!void {
        const ns = &self.nodes[node];
        ns.current_term = new_term;
        ns.role = .follower;
        ns.voted_for = no_vote;
        try self.resetElectionTimer(sim, node);
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        self.nodes[node].role = .follower;
        try self.resetElectionTimer(sim, node);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        if (timer_id == HEARTBEAT_TIMER) {
            if (self.nodes[node].role == .leader) {
                if (self.cfg.propose_client_commands) try self.proposeClientCommand(node);
                try self.broadcastAppendEntries(sim, node);
                try sim.setTimer(node, self.cfg.heartbeat_period, HEARTBEAT_TIMER);
            }
            return;
        }
        // Election timer — ignore if superseded by a newer epoch.
        if (timer_id != self.nodes[node].election_epoch) return;
        // A leader does not campaign, so its election timer is dropped here
        // WITHOUT being re-armed — which is precisely why every step-down must
        // re-arm it (`stepDown`). Do not "simplify" this by re-arming here: the
        // node would then campaign on the remainder of a stale timeout instead
        // of a fresh one.
        if (self.nodes[node].role == .leader) return;
        try self.startElection(sim, node);
    }

    // ── elections ─────────────────────────────────────────────────────────────

    fn startElection(self: *RaftServer, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        ns.current_term += 1;
        ns.role = .candidate;
        ns.voted_for = node;
        @memset(ns.votes_from, false);
        ns.votes_from[node] = true; // votes for itself
        const info = ns.log.info();
        var buf: [types.RequestVoteReq.wire_len]u8 = undefined;
        (types.RequestVoteReq{
            .term = ns.current_term,
            .candidate_id = node,
            .last_log_index = info.last_index,
            .last_log_term = info.last_term,
        }).encode(&buf);
        try self.broadcast(sim, node, &buf);
        try self.resetElectionTimer(sim, node);
    }

    fn becomeLeader(self: *RaftServer, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        ns.role = .leader;
        // Election Safety witness: assert exactly one leader per term.
        try self.checker.recordLeader(self.gpa, ns.current_term, node);
        // A fresh leader appends a no-op in its own term so prior-term entries
        // can commit indirectly (the Figure-8 mechanism, §5.4.2). It carries a
        // `(term, index)` command like every other entry: a real no-op has no
        // payload, but two DIFFERENT no-ops (different terms, same index) that
        // both encode `command = 0` are invisible to the apply-keyed State
        // Machine Safety check — see `commandFor`.
        const noop_index = ns.log.lastIndex() + 1;
        try ns.log.append(self.gpa, .{
            .term = ns.current_term,
            .kind = .noop,
            .command = commandFor(ns.current_term, noop_index),
        });
        const last = ns.log.lastIndex();
        for (ns.next_index, ns.match_index) |*ni, *mi| {
            ni.* = last + 1;
            mi.* = 0;
        }
        ns.match_index[node] = last;
        try self.broadcastAppendEntries(sim, node);
        try sim.setTimer(node, self.cfg.heartbeat_period, HEARTBEAT_TIMER);
    }

    /// Send `payload` to every other node. (The scaffold referenced this helper
    /// from `startElection` but never defined it — scaffold defect, added
    /// during the core pass.)
    fn broadcast(self: *RaftServer, sim: *Sim, node: NodeId, payload: []const u8) anyerror!void {
        var peer: NodeId = 0;
        while (peer < self.node_count) : (peer += 1) {
            if (peer == node) continue;
            try sim.send(node, peer, payload);
        }
    }

    // ── replication ────────────────────────────────────────────────────────────

    /// Append one distinct client command to the leader's own log. Stands in
    /// for a client request arriving at the leader; the sim has no clients, so
    /// the heartbeat tick drives it.
    fn proposeClientCommand(self: *RaftServer, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        const idx = ns.log.lastIndex() + 1;
        try ns.log.append(self.gpa, .{
            .term = ns.current_term,
            .kind = .command,
            .command = commandFor(ns.current_term, idx),
        });
        // The leader replicates to itself synchronously (Figure 2: a leader
        // counts its own log toward the majority).
        ns.match_index[node] = ns.log.lastIndex();
    }

    fn broadcastAppendEntries(self: *RaftServer, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        var peer: NodeId = 0;
        while (peer < self.node_count) : (peer += 1) {
            if (peer == node) continue;
            const next = ns.next_index[peer];
            const prev_index = next - 1;
            const prev_term = ns.log.termAt(prev_index) orelse 0;
            // Send up to one batch of entries starting at `next`.
            var scratch: [types.max_entries_per_msg]LogEntry = undefined;
            var count: usize = 0;
            var idx = next;
            while (idx <= ns.log.lastIndex() and count < types.max_entries_per_msg) : (idx += 1) {
                scratch[count] = ns.log.get(idx).?;
                count += 1;
            }
            var buf: [types.AppendEntriesReq.max_wire]u8 = undefined;
            const n = (types.AppendEntriesReq{
                .term = ns.current_term,
                .leader_id = node,
                .prev_log_index = prev_index,
                .prev_log_term = prev_term,
                .entries = scratch[0..count],
                .leader_commit = ns.commit_index,
            }).encode(&buf);
            try sim.send(node, peer, buf[0..n]);
        }
    }

    /// A message that did not decode is dropped and counted.
    ///
    /// Why drop: Figure 2 defines no negative acknowledgement, so there is
    /// nothing legal to reply. Inventing one would add a protocol message AND
    /// an amplification vector (an attacker sending 1-byte datagrams would get
    /// full-size replies). Dropping is also exactly what the network already
    /// does to a corrupted packet, and Raft's liveness argument is built on
    /// tolerating loss: a dropped RequestVote is retried by the next election
    /// timeout, a dropped AppendEntries by the next heartbeat. So a drop costs
    /// no more liveness than the packet loss Raft already assumes.
    ///
    /// Why count: a peer that emits ONLY malformed messages is, to this node,
    /// indistinguishable from a dead link — and if enough peers do it, the
    /// cluster loses quorum while every node looks healthy. That is a real
    /// liveness concern, but it is not one a decoder can fix: the correct
    /// response (evict the peer? alarm? refuse to count it toward quorum?) is
    /// an operational policy decision above this layer. The counter is
    /// deliberately the whole mechanism here — it makes the condition
    /// observable and leaves the policy to the caller. See SPEC.md
    /// §"Malformed messages".
    fn dropMalformed(self: *RaftServer, err: types.DecodeError) void {
        // Both variants are dropped identically today; the switch exists so
        // that a future policy split (e.g. alarm only on InvalidEncoding, which
        // cannot be caused by truncation in transit) has an obvious home.
        switch (err) {
            error.Truncated, error.InvalidEncoding => self.malformed_dropped += 1,
        }
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const tag = types.tagOf(payload) catch |e| return self.dropMalformed(e);
        switch (tag) {
            .request_vote_req => try self.handleVoteReq(sim, node, from, payload),
            .request_vote_resp => try self.handleVoteResp(sim, node, from, payload),
            .append_entries_req => try self.handleAppendReq(sim, node, from, payload),
            .append_entries_resp => try self.handleAppendResp(sim, node, from, payload),
        }
    }

    fn handleVoteReq(self: *RaftServer, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const ns = &self.nodes[node];
        const req = types.RequestVoteReq.decode(payload) catch |e| return self.dropMalformed(e);
        // THE FABLE CORE: the grant decision (term step-up + single-vote +
        // up-to-date restriction).
        var d = safety.handleRequestVote(ns.current_term, ns.voted_for, ns.log.info(), req);
        if (self.bug == .index_only_up_to_date and !d.grant) {
            // INJECTED DEFECT (§5.4.1 with the term-first clause dropped): keep
            // every other clause of the real decision and widen the up-to-date
            // test to "at least as long". Only ever ADDS grants, so a refusal
            // for any other reason (stale term, already voted) still stands.
            const effective_vote: NodeId = if (d.term_advanced) no_vote else ns.voted_for;
            const may_vote = effective_vote == no_vote or effective_vote == req.candidate_id;
            if (req.term >= ns.current_term and may_vote and req.last_log_index >= ns.log.lastIndex()) {
                d.grant = true;
                d.voted_for = req.candidate_id;
            }
        }
        // Step down BEFORE the grant branch: a refused vote (the candidate's
        // log is not up to date) still adopts the term and still demotes, and
        // then only `stepDown`'s re-arm keeps this node electable.
        if (d.term_advanced) try self.stepDown(sim, node, d.new_term);
        if (d.grant) {
            ns.voted_for = d.voted_for;
            try self.resetElectionTimer(sim, node);
        }
        var buf: [types.RequestVoteResp.wire_len]u8 = undefined;
        (types.RequestVoteResp{ .term = ns.current_term, .vote_granted = d.grant }).encode(&buf);
        try sim.send(node, from, &buf);
    }

    fn handleVoteResp(self: *RaftServer, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const ns = &self.nodes[node];
        const resp = types.RequestVoteResp.decode(payload) catch |e| return self.dropMalformed(e);
        const obs = safety.observeTerm(ns.current_term, resp.term);
        if (obs.term_advanced) {
            try self.stepDown(sim, node, obs.new_term);
            return;
        }
        if (ns.role != .candidate or resp.term != ns.current_term) return;
        if (resp.vote_granted) {
            // Set semantics — a duplicated grant from the same voter must not
            // count twice (see `votes_from`).
            ns.votes_from[from] = true;
            if (ns.voteCount() >= majority(self.node_count)) try self.becomeLeader(sim, node);
        }
    }

    fn handleAppendReq(self: *RaftServer, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const ns = &self.nodes[node];
        var scratch: [types.max_entries_per_msg]LogEntry = undefined;
        const req = types.AppendEntriesReq.decode(payload, &scratch) catch |e| return self.dropMalformed(e);
        // THE FABLE CORE: consistency check + conflict-only truncation +
        // follower commit advancement.
        var out = safety.handleAppendEntries(ns.current_term, &ns.log, ns.commit_index, req);
        if (self.bug == .naive_truncation and out.success) {
            // INJECTED DEFECT (§5.3 conflict rule → naive rule): cut everything
            // after prevLogIndex and re-append the whole batch, instead of
            // cutting only at the first genuine term conflict.
            out.truncate_to = req.prev_log_index;
            out.append_from = 0;
        }
        if (out.term_advanced) {
            ns.current_term = out.new_term;
            ns.voted_for = no_vote;
        }
        if (req.term >= ns.current_term) {
            ns.role = .follower;
            try self.resetElectionTimer(sim, node);
        }
        if (out.success) {
            ns.log.truncateAfter(out.truncate_to);
            try ns.log.appendSlice(self.gpa, req.entries[out.append_from..]);
            ns.commit_index = out.new_commit_index;
            try self.applyCommitted(node);
        }
        var buf: [types.AppendEntriesResp.wire_len]u8 = undefined;
        (types.AppendEntriesResp{
            .term = ns.current_term,
            .success = out.success,
            // The core's verdict (prev + entries.len — the VERIFIED region),
            // never the raw last index: a stale unverified tail past the batch
            // window must not be advertised as replicated (see AppendOutcome).
            .match_index = if (out.success) out.match_index else 0,
        }).encode(&buf);
        try sim.send(node, from, &buf);
    }

    fn handleAppendResp(self: *RaftServer, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const ns = &self.nodes[node];
        const resp = types.AppendEntriesResp.decode(payload) catch |e| return self.dropMalformed(e);
        const obs = safety.observeTerm(ns.current_term, resp.term);
        if (obs.term_advanced) {
            try self.stepDown(sim, node, obs.new_term);
            return;
        }
        if (ns.role != .leader or resp.term != ns.current_term) return;
        if (resp.success) {
            // `match_index` is an unconstrained wire `u64` — `decode` bounds
            // the term and nothing else — and the line below is an
            // unconditional `+ 1` on it. That is the exact shape `max_term`
            // exists to rule out for `current_term` (see types.zig): a panic
            // under Debug/ReleaseSafe, and under ReleaseFast a wrap to 0
            // whose `prev_index = next - 1` underflows straight into
            // `log.get(0).?`, which is `null` by contract.
            //
            // Rejected, not clamped. Clamping to `lastIndex()` would be the
            // worse bug: it would record that this follower has matched the
            // WHOLE log, and `leaderCommitIndex` counts exactly those
            // match_index values for its majority — so one forged response
            // could commit entries no majority ever replicated. A crash is
            // an availability problem; that would be a safety violation.
            // An honest follower can never match more than the leader holds,
            // so a larger value is corruption or hostility either way.
            if (resp.match_index > ns.log.lastIndex()) {
                self.malformed_dropped += 1;
                return;
            }
            ns.match_index[from] = resp.match_index;
            ns.next_index[from] = resp.match_index + 1;
            ns.match_index[node] = ns.log.lastIndex();
            // THE FABLE CORE: the Figure-8 commit rule.
            const nc = safety.leaderCommitIndex(ns.current_term, ns.commit_index, ns.match_index, self.node_count, &ns.log);
            if (nc > ns.commit_index) {
                ns.commit_index = nc;
                try self.applyCommitted(node);
            }
        } else if (ns.next_index[from] > 1) {
            ns.next_index[from] -= 1; // decrement and retry (§5.3)
        }
    }

    fn applyCommitted(self: *RaftServer, node: NodeId) anyerror!void {
        const ns = &self.nodes[node];
        while (ns.last_applied < ns.commit_index) {
            ns.last_applied += 1;
            const e = ns.log.get(ns.last_applied).?;
            try self.checker.recordApply(self.gpa, ns.last_applied, e.command);
            try self.checker.recordCommitted(self.gpa, .{ .index = ns.last_applied, .term = e.term, .command = e.command });
            // First recorder == committing leader (see `commit_terms`); later
            // (follower/indirect) records must not overwrite the commit term.
            const gop = try self.commit_terms.getOrPut(self.gpa, ns.last_applied);
            if (!gop.found_existing) gop.value_ptr.* = ns.current_term;
        }
    }

    // ── the live safety check (all five properties over global state) ─────────

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        // Election Safety + State Machine Safety (incremental, already recorded).
        try self.checker.check();

        // Log Matching — across every node's current log.
        const logs = try self.gpa.alloc([]const LogEntry, self.node_count);
        defer self.gpa.free(logs);
        for (self.nodes, logs) |*n, *slot| slot.* = n.log.entries.items;
        if (checks.logMatchingViolation(logs) != null) return error.LogMatching;

        // Committed-set workspace for Leader Completeness, re-filtered per leader.
        var committed: std.ArrayList(checks.CommitRec) = .empty;
        defer committed.deinit(self.gpa);

        for (self.nodes) |*n| {
            if (n.role != .leader) continue;
            // Leader Append-Only — never shrinks/overwrites its own log.
            if (!checks.appendOnlyHolds(n.prev_log.items, n.log.entries.items)) return error.LeaderAppendOnly;
            // Leader Completeness — Figure 3 scopes it to "the leaders of all
            // HIGHER-numbered terms" than the commit, so a stale leader (deposed
            // but unaware inside a minority partition) is only held to entries
            // committed in terms ≤ its own; requiring more flags legal runs.
            // (`<=` keeps the committing leader itself checked — strictly
            // stronger, and it trivially holds its own commits.) The predicate
            // in checks.zig is unchanged; only its input set is scoped. A real
            // Figure-8 loss is still caught twice over: any FUTURE leader
            // missing the entry trips this check, and an overwritten committed
            // entry trips recordCommitted/recordApply (State Machine Safety).
            committed.clearRetainingCapacity();
            var it = self.checker.committed.iterator();
            while (it.next()) |kv| {
                const commit_term = self.commit_terms.get(kv.key_ptr.*) orelse 0;
                if (commit_term <= n.current_term) try committed.append(self.gpa, kv.value_ptr.*);
            }
            if (!checks.leaderCompletenessHolds(n.log.entries.items, committed.items)) return error.LeaderCompleteness;
        }
        // Refresh the append-only witnesses AFTER the check.
        for (self.nodes) |*n| {
            n.prev_log.clearRetainingCapacity();
            try n.prev_log.appendSlice(self.gpa, n.log.entries.items);
        }
    }
};

// ── BrokenRaft: the positive control ────────────────────────────────────────

/// Deliberately WRONG: on its election timeout a node increments its term and
/// IMMEDIATELY declares itself leader — no votes collected, no majority, no
/// up-to-date check. Does NOT call `safety.zig`. With a fixed (un-spread)
/// election timeout every node's timer fires on the same tick and every node
/// self-promotes into the SAME term, so two distinct leaders for one term are
/// recorded — tripping `checks.SafetyChecker`'s **Election Safety** invariant
/// (the exact checker the real `RaftServer` is held to). Fires on a clean run
/// with no injected faults; faults only perturb the timing.
pub const BrokenRaft = struct {
    gpa: Allocator,
    node_count: usize,
    /// Fixed timeout (NO per-node spread) — guarantees synchronized self-promotion.
    timeout: Time,
    current_term: []Term,
    checker: checks.SafetyChecker = .{},

    pub fn init(gpa: Allocator, node_count: usize, timeout: Time) Allocator.Error!BrokenRaft {
        const t = try gpa.alloc(Term, node_count);
        @memset(t, 0);
        return .{ .gpa = gpa, .node_count = node_count, .timeout = timeout, .current_term = t };
    }

    pub fn deinit(self: *BrokenRaft, gpa: Allocator) void {
        gpa.free(self.current_term);
        self.checker.deinit(gpa);
        self.* = undefined;
    }

    pub fn protocol(self: *BrokenRaft) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *BrokenRaft {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        @memset(self.current_term, 0);
        self.checker.reset();
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        try sim.setTimer(node, self.timeout, 0);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        _ = timer_id;
        const self = cast(ctx);
        self.current_term[node] += 1;
        // THE BUG: declare leadership with no election at all.
        try self.checker.recordLeader(self.gpa, self.current_term[node], node);
        // Exercise the wire too: broadcast a heartbeat to every neighbor.
        var buf: [types.AppendEntriesResp.wire_len]u8 = undefined;
        (types.AppendEntriesResp{ .term = self.current_term[node], .success = true, .match_index = 0 }).encode(&buf);
        var nb: [CLUSTER_N]NodeId = undefined;
        const n = try sim.neighbors(node, &nb);
        for (nb[0..n]) |peer| try sim.send(node, peer, &buf);
        try sim.setTimer(node, self.timeout, 0);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        _ = ctx;
        _ = sim;
        _ = node;
        _ = from;
        _ = payload; // the broken control ignores inbound messages
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        _ = sim;
        const self = cast(ctx);
        try self.checker.check();
    }
};

// ── unguarded tests: the positive control proves the harness has teeth ──────

const testing = std.testing;

const DEFAULT_CFG = RaftConfig{};
const UNTIL: Time = 2000;

test "positive control: BrokenRaft trips Election Safety on a clean run" {
    const gpa = testing.allocator;
    var broken = try BrokenRaft.init(gpa, CLUSTER_N, DEFAULT_CFG.election_timeout);
    defer broken.deinit(gpa);
    const case = netsim.Case{ .seed = 1, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(error.ElectionSafety, r.violation.?.err);
}

test "teeth: BrokenRaft trips the checker across a seed sweep, including under fault fuzzing" {
    const gpa = testing.allocator;
    var broken = try BrokenRaft.init(gpa, CLUSTER_N, DEFAULT_CFG.election_timeout);
    defer broken.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    var caught: usize = 0;
    var seed: u64 = 1;
    while (seed <= 100) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try netsim.run(gpa, case, .{});
        defer gr.trace.deinit();
        if (gr.result.outcome == .violated) caught += 1;
    }
    // A dead checker would report 0 across the whole sweep.
    try testing.expect(caught > 0);
}

test "shrink: a fuzzed failing schedule against BrokenRaft minimizes to a still-reproducing core" {
    const gpa = testing.allocator;
    var broken = try BrokenRaft.init(gpa, CLUSTER_N, DEFAULT_CFG.election_timeout);
    defer broken.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL };

    var failing = (try netsim.findFailing(gpa, template, .{}, 1, 200)) orelse return error.NoFailingSeed;
    defer failing.deinit();
    try testing.expectEqual(error.ElectionSafety, failing.err);

    var res = try netsim.shrinkTrace(gpa, &failing);
    defer res.deinit();
    try testing.expect(res.after <= res.before);
    if (res.before >= 1) try testing.expect(res.after >= 1);

    const r = try netsim.replay(gpa, failing.case, res.trace.events, null);
    try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
    try testing.expectEqual(failing.err, r.violation.?.err);
}

test "smoke: the cluster scenario builds the expected full mesh" {
    const gpa = testing.allocator;
    var broken = try BrokenRaft.init(gpa, CLUSTER_N, DEFAULT_CFG.election_timeout);
    defer broken.deinit(gpa);
    const topo = try netsim.snapshotTopo(gpa, .{ .seed = 0, .scenario = scenario, .protocol = broken.protocol(), .until = UNTIL });
    defer gpa.free(topo.links);
    try testing.expectEqual(@as(usize, CLUSTER_N), topo.node_count);
    // full mesh: N*(N-1) directed links
    try testing.expectEqual(@as(usize, CLUSTER_N * (CLUSTER_N - 1)), topo.links.len);
}

// ── the real-RaftServer model-check tests (formerly gated) ──────────────────
//
// See `gate.zig`. With the Fable core implemented and the gate flipped, these
// drive the real cluster through netsim's crash/partition/reorder/clock-skew
// fuzzer, enforcing all five safety properties continuously. (While the core
// was a `@panic` stub they reported SKIP — a panic would have aborted the whole
// test binary, so they could not run at all.)

test "real: RaftServer upholds all five safety invariants across a fuzzed fault sweep" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };

    const failing = try netsim.findFailing(gpa, template, .{}, 1, 300);
    if (failing) |*f| {
        var mf = f.*;
        defer mf.deinit();
        std.debug.print("raft: real cluster tripped {} at seed {}\n", .{ mf.err, mf.case.seed });
        return error.HardInvariantViolated;
    }
}

test "real: a leader is eventually elected on a quiet network (liveness sanity)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    var leaders: usize = 0;
    for (srv.nodes) |*n| {
        if (n.role == .leader) leaders += 1;
    }
    try testing.expect(leaders >= 1);
}

// ── the live State-Machine-Safety key actually varies ───────────────────────
//
// The audit's F1: `becomeLeader` appended only `.{ .kind = .noop, .command = 0 }`
// and nothing else was ever proposed, so every replicated entry in the whole
// run carried the SAME command. `SafetyChecker.recordApply` keys on the command
// value, so it compared 0 against 0 at every index — State Machine Safety, the
// deepest of the five, could not fail no matter what the algorithm did. The two
// tests below are the ones that go RED if that returns: the first fails on the
// distinctness itself, the second and third fail because the injected defects
// stop being visible.

/// How many DIFFERENT command values the run applied, and whether any two
/// indices were applied the same command (which would mean the key does not
/// separate entries).
fn appliedCommandStats(gpa: Allocator, c: *const checks.SafetyChecker) !struct { total: usize, distinct: usize } {
    var seen: std.AutoHashMapUnmanaged(Command, void) = .empty;
    defer seen.deinit(gpa);
    var it = c.applied.iterator();
    var total: usize = 0;
    while (it.next()) |kv| {
        total += 1;
        try seen.put(gpa, kv.value_ptr.*, {});
    }
    return .{ .total = total, .distinct = seen.count() };
}

test "real: every applied index carries a DISTINCT command (State Machine Safety has a key that varies)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

    const stats = try appliedCommandStats(gpa, &srv.checker);
    // Several entries were committed and applied…
    try testing.expect(stats.total >= 3);
    // …and no two indices shared a command value. With the pre-fix harness
    // (`propose_client_commands = false` and a zero no-op payload) this is
    // `distinct == 1` for any `total`, and the assert fires.
    try testing.expectEqual(stats.total, stats.distinct);

    // Each applied command names the (term, index) of the leader that created
    // it — mutate `commandFor` to a constant and this pins it.
    var it = srv.checker.applied.iterator();
    while (it.next()) |kv| {
        const rec = srv.checker.committed.get(kv.key_ptr.*).?;
        try testing.expectEqual(commandFor(rec.term, kv.key_ptr.*), kv.value_ptr.*);
    }
}

/// The minority side of the directed schedule below: node 0 alone.
const CUT0 = [_]NodeId{0};

/// The interleaving §5.4.1 exists to forbid, as a hand-built fault schedule —
/// no seed search, no luck. Four beats:
///
///  1. `partition` node 0 away. It is the term-1 leader and stays leader inside
///     its minority (Raft has no lease), so it keeps proposing — accumulating a
///     LONG tail of STALE-term entries. This is the shape that could not exist
///     before F1 was fixed: with no client commands proposed, a partitioned
///     leader's log grew by exactly one no-op per term and could never outgrow
///     the majority's.
///  2. `crash` the majority's term-2 leader, so the term-3 leader elected in its
///     place has never spoken to node 0 — its `nextIndex[0]` starts at its own
///     log end, so re-syncing node 0 needs a long walk-back rather than one
///     matching batch.
///  3. `heal`. Node 0 hears the term-3 leader, steps down and re-arms its
///     election timer, but the walk-back has not yet cut its stale tail.
///  4. `crash` the term-3 leader before the walk-back finishes. Node 0 times out
///     first (lowest `election_spread` offset) and campaigns while still holding
///     the long stale tail.
///
/// A term-first §5.4.1 refuses it (last term 1 < 3). An index-only §5.4.1 sees
/// only "longer" and elects it — and it then overwrites entries the majority
/// had already committed.
fn directedStaleTailSchedule(partition_at: Time, crash1_at: Time, heal_after: Time, crash2_after: Time) [4]netsim.FaultEvent {
    return .{
        .{ .time = partition_at, .kind = .{ .partition = .{ .id = 1, .cut = &CUT0 } } },
        .{ .time = crash1_at, .kind = .{ .crash_node = .{ .node = 1 } } },
        .{ .time = crash1_at + heal_after, .kind = .{ .heal = .{ .id = 1 } } },
        .{ .time = crash1_at + heal_after + crash2_after, .kind = .{ .crash_node = .{ .node = 2 } } },
    };
}

const DIRECTED_UNTIL: Time = 3000;

test "positive control: the index-only §5.4.1 election restriction is caught LIVE (directed stale-tail schedule)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    const trace = directedStaleTailSchedule(200, 700, 100, 40);

    // (a) The real algorithm survives the schedule — no false positive.
    {
        var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
        defer srv.deinit(gpa);
        const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = srv.protocol(), .until = DIRECTED_UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    }

    // (b) Drop the term-first clause and the LIVE check bites. During the audit
    // this exact injection PASSED the whole 300-seed sweep and was caught only
    // by `safety.zig`'s unit test — that is audit finding F1.
    {
        var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
        defer srv.deinit(gpa);
        srv.bug = .index_only_up_to_date;
        const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = srv.protocol(), .until = DIRECTED_UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.violated, r.outcome);
        try testing.expectEqual(error.LeaderCompleteness, r.violation.?.err);
    }

    // (c) …and this is WHY it used to pass: with no client commands proposed
    // (the pre-fix harness) the same defect, the same schedule and the same
    // checkers see nothing at all, because a partitioned leader's log cannot
    // grow and the index-only comparison never has anything to be wrong about.
    // Set `propose_client_commands = false` and (b) above stops failing.
    {
        var cfg = DEFAULT_CFG;
        cfg.propose_client_commands = false;
        var srv = try RaftServer.init(gpa, CLUSTER_N, cfg);
        defer srv.deinit(gpa);
        srv.bug = .index_only_up_to_date;
        const case = netsim.Case{ .seed = 3, .scenario = scenario, .protocol = srv.protocol(), .until = DIRECTED_UNTIL };
        const r = try netsim.replay(gpa, case, &trace, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    }
}

// ── stepping down must RE-ARM the election timer (a liveness regression) ────
//
// A leader has NO live election timer: `onTimer` sees `role == .leader` and
// swallows the fired timer without re-arming it (a leader does not campaign
// against itself), and `resetElectionTimer` is what re-arms. So from one full
// timeout after it was elected, a leader's only route back to an armed timer is
// a step-down that calls `resetElectionTimer`.
//
// `handleAppendReq` does that. Every OTHER step-down path did not: a higher term
// observed on an AppendEntries RESPONSE, on a RequestVote response, or on a
// RequestVote request that is refused (candidate's log not up to date) demoted
// the node to `.follower` and left it with no timer at all. Such a node is not
// wedged in any way a crash test can see — it answers every RPC correctly — it
// has simply stopped being electable, forever, unless some other leader happens
// to talk to it. If the rest of the cluster is gone, the cluster is dead with a
// perfectly healthy-looking node in it.
//
// Hence the assertion below is on LIVENESS, not on state: a test that checked
// `role == .follower` after the step-down passes against the bug — that part was
// always right. What fails is that the timeout never comes.

const StepDownVia = enum {
    /// `handleAppendResp` — a follower/candidate replies with a higher term.
    append_resp,
    /// `handleVoteResp` — a peer's vote reply carries a higher term.
    vote_resp,
    /// `handleVoteReq` — a candidate at a higher term whose log is NOT up to
    /// date: the vote is REFUSED (so the grant branch's re-arm never runs) but
    /// the term is still adopted and the role still drops to follower. Not
    /// named in the finding; found by sweeping every `role = .follower` site.
    vote_req_refused,
};

/// Wraps `RaftServer`'s vtable and, at a chosen time, hand-delivers ONE forged
/// higher-term message to `target` — the step-down trigger — through the real
/// `onMessageFn`. Everything else is forwarded untouched, so the cluster,
/// timers and safety checks are the real ones.
const StepDownProbe = struct {
    srv: *RaftServer,
    via: StepDownVia,
    target: NodeId,
    inject_at: Time,
    /// If set, deliver a SECOND message this many ticks after the step-down: a
    /// legitimate RequestVote at the term the node has just adopted, from a
    /// candidate whose log is exactly as up-to-date. Nothing about that message
    /// carries a term bump, so `handleRequestVote`'s own step-up compensation
    /// does not apply and the grant depends purely on `votedFor` having been
    /// cleared by the step-down.
    follow_up_after: ?Time = null,
    /// Observed at injection time — the preconditions the test asserts, so a
    /// scheduling change that stops producing the situation FAILS rather than
    /// silently testing nothing.
    injected: bool = false,
    was_leader: bool = false,
    term_before: Term = 0,
    voted_for_before: NodeId = no_vote,
    role_after: Role = .follower,
    term_after: Term = 0,
    follow_up_done: bool = false,
    follow_up_term: Term = 0,
    voted_for_after_follow_up: NodeId = no_vote,

    const INJECT_TIMER: u64 = std.math.maxInt(u64) - 1;
    const FOLLOWUP_TIMER: u64 = std.math.maxInt(u64) - 2;

    fn protocol(self: *StepDownProbe) Protocol {
        return .{
            .ctx = self,
            .onStartFn = onStart,
            .onMessageFn = onMessage,
            .onTimerFn = onTimer,
            .checkFn = check,
            .resetFn = reset,
        };
    }

    fn cast(ctx: *anyopaque) *StepDownProbe {
        return @ptrCast(@alignCast(ctx));
    }

    fn reset(ctx: *anyopaque) void {
        const self = cast(ctx);
        const inner = self.srv.protocol();
        inner.resetFn.?(inner.ctx);
        self.injected = false;
        self.was_leader = false;
        self.term_before = 0;
        self.voted_for_before = no_vote;
        self.role_after = .follower;
        self.term_after = 0;
        self.follow_up_done = false;
        self.follow_up_term = 0;
        self.voted_for_after_follow_up = no_vote;
    }

    fn onStart(ctx: *anyopaque, sim: *Sim, node: NodeId) anyerror!void {
        const self = cast(ctx);
        const inner = self.srv.protocol();
        try inner.onStartFn.?(inner.ctx, sim, node);
        if (node == self.target) try sim.setTimer(node, self.inject_at, INJECT_TIMER);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, node: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        const inner = self.srv.protocol();
        try inner.onMessageFn(inner.ctx, sim, node, from, payload);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, node: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const inner = self.srv.protocol();
        switch (timer_id) {
            INJECT_TIMER => try self.stepDownInjection(inner, sim, node),
            FOLLOWUP_TIMER => try self.voteReqInjection(inner, sim, node),
            else => try inner.onTimerFn.?(inner.ctx, sim, node, timer_id),
        }
    }

    fn stepDownInjection(self: *StepDownProbe, inner: Protocol, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.srv.nodes[node];
        self.injected = true;
        self.was_leader = ns.role == .leader;
        self.term_before = ns.current_term;
        self.voted_for_before = ns.voted_for;
        const higher = ns.current_term + 1;
        const peer: NodeId = if (node == 0) 1 else 0;
        switch (self.via) {
            .append_resp => {
                var buf: [types.AppendEntriesResp.wire_len]u8 = undefined;
                (types.AppendEntriesResp{ .term = higher, .success = false, .match_index = 0 }).encode(&buf);
                try inner.onMessageFn(inner.ctx, sim, node, peer, &buf);
            },
            .vote_resp => {
                var buf: [types.RequestVoteResp.wire_len]u8 = undefined;
                (types.RequestVoteResp{ .term = higher, .vote_granted = false }).encode(&buf);
                try inner.onMessageFn(inner.ctx, sim, node, peer, &buf);
            },
            .vote_req_refused => {
                var buf: [types.RequestVoteReq.wire_len]u8 = undefined;
                // An EMPTY log at a higher term: §5.4.1 refuses the vote (the
                // leader's own log is long), so only the term step-down runs.
                (types.RequestVoteReq{
                    .term = higher,
                    .candidate_id = peer,
                    .last_log_index = 0,
                    .last_log_term = 0,
                }).encode(&buf);
                try inner.onMessageFn(inner.ctx, sim, node, peer, &buf);
            },
        }
        self.role_after = ns.role;
        self.term_after = ns.current_term;
        if (self.follow_up_after) |d| try sim.setTimer(node, d, FOLLOWUP_TIMER);
    }

    /// The second message: a legitimate RequestVote at the node's CURRENT term
    /// (no step-up), from a candidate claiming this node's own log summary — so
    /// §5.4.1 is satisfied exactly, and the only remaining gate is `votedFor`.
    fn voteReqInjection(self: *StepDownProbe, inner: Protocol, sim: *Sim, node: NodeId) anyerror!void {
        const ns = &self.srv.nodes[node];
        const peer: NodeId = if (node == 0) 1 else 0;
        const info = ns.log.info();
        self.follow_up_term = ns.current_term;
        var buf: [types.RequestVoteReq.wire_len]u8 = undefined;
        (types.RequestVoteReq{
            .term = ns.current_term,
            .candidate_id = peer,
            .last_log_index = info.last_index,
            .last_log_term = info.last_term,
        }).encode(&buf);
        try inner.onMessageFn(inner.ctx, sim, node, peer, &buf);
        self.follow_up_done = true;
        self.voted_for_after_follow_up = ns.voted_for;
    }

    fn check(ctx: *anyopaque, sim: *const Sim) anyerror!void {
        const self = cast(ctx);
        const inner = self.srv.protocol();
        try inner.checkFn.?(inner.ctx, sim);
    }
};

/// Node 0 is the only candidate at t=100 and wins term 1 uncontested: the next
/// node's first timeout is 40 ticks later, far past the ~12 ticks the election
/// takes on a 5±2-tick link. Its own election timer then fires at t=200 and is
/// swallowed by the `role == .leader` branch of `onTimer`, which is the state
/// the regression needs.
const LIVENESS_CFG = RaftConfig{ .election_timeout = 100, .election_spread = 40, .heartbeat_period = 30 };
const INJECT_AT: Time = 600;
const LIVENESS_UNTIL: Time = 1400;

/// Isolate the target by crashing every peer one tick before the step-down, so
/// that after it nothing can re-arm its timer FOR it. Without this the bug is
/// masked: a surviving leader's next heartbeat lands in `handleAppendReq`, which
/// re-arms — the one step-down path that was already correct.
const CRASH_PEERS = [_]netsim.FaultEvent{
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 1 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 2 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 3 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 4 } } },
};

test "real: a leader demoted by a RESPONSE re-arms its election timer and stands for election again" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;

    for ([_]StepDownVia{ .append_resp, .vote_resp, .vote_req_refused }) |via| {
        var srv = try RaftServer.init(gpa, CLUSTER_N, LIVENESS_CFG);
        defer srv.deinit(gpa);
        var probe = StepDownProbe{ .srv = &srv, .via = via, .target = 0, .inject_at = INJECT_AT };
        const case = netsim.Case{
            .seed = 5,
            .scenario = scenario,
            .protocol = probe.protocol(),
            .until = LIVENESS_UNTIL,
        };
        const r = try netsim.replay(gpa, case, &CRASH_PEERS, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

        // Preconditions — the situation the regression is about actually arose.
        try testing.expect(probe.injected);
        try testing.expect(probe.was_leader);
        // The step-down itself. THIS is the assertion that passes against the
        // bug, which is exactly why it cannot be the whole test.
        try testing.expectEqual(Role.follower, probe.role_after);
        try testing.expectEqual(probe.term_before + 1, probe.term_after);

        // Liveness: 800 ticks — eight election timeouts — after the step-down,
        // the node must have STOOD FOR ELECTION. With the timer left unarmed it
        // sits at exactly `term_after` in `.follower` forever, answering RPCs.
        try testing.expect(srv.nodes[0].current_term > probe.term_after);
        try testing.expectEqual(Role.candidate, srv.nodes[0].role);
        try testing.expectEqual(@as(NodeId, 0), srv.nodes[0].voted_for);
    }
}

/// Ten ticks after the step-down — well inside the fresh election timeout, so
/// the node is still sitting at the term it just adopted and has not yet
/// campaigned (which would set `votedFor` to itself and destroy the observable).
const FOLLOW_UP_AFTER: Time = 10;

test "real: a step-down CLEARS votedFor, so the node can still vote in the term it just adopted" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;

    // Two messages, because one cannot see this. `handleRequestVote` computes
    // `effective_vote = if (term_advanced) no_vote else voted_for`, so the
    // message that CARRIES the higher term is decided as if the vote were
    // already cleared — a single-message test is green either way. The stale
    // `votedFor` only bites the NEXT request, which arrives at a term that is no
    // longer new: `term_advanced` is false, the compensation does not fire, and
    // the node refuses a vote it must grant. §5.1 requires `votedFor` to reset
    // whenever `currentTerm` changes, and that reset is `stepDown`'s job.
    //
    // The consequence is liveness again, and again invisible to a state-based
    // `checkFn`: the refusal is a perfectly well-formed reply, and every node
    // involved looks healthy. The cluster just fails to elect for another term.
    for ([_]StepDownVia{ .append_resp, .vote_resp, .vote_req_refused }) |via| {
        var srv = try RaftServer.init(gpa, CLUSTER_N, LIVENESS_CFG);
        defer srv.deinit(gpa);
        var probe = StepDownProbe{
            .srv = &srv,
            .via = via,
            .target = 0,
            .inject_at = INJECT_AT,
            .follow_up_after = FOLLOW_UP_AFTER,
        };
        const case = netsim.Case{
            .seed = 5,
            .scenario = scenario,
            .protocol = probe.protocol(),
            .until = LIVENESS_UNTIL,
        };
        const r = try netsim.replay(gpa, case, &CRASH_PEERS, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

        // Preconditions: it was the leader of `term_before`, which means it had
        // voted for ITSELF in that term — the stale value that must not survive
        // into the next one.
        try testing.expect(probe.injected);
        try testing.expect(probe.was_leader);
        try testing.expectEqual(@as(NodeId, 0), probe.voted_for_before);
        try testing.expectEqual(probe.term_before + 1, probe.term_after);

        // The second message arrived at the SAME term the step-down adopted —
        // the condition under which `handleRequestVote`'s step-up compensation
        // cannot help.
        try testing.expect(probe.follow_up_done);
        try testing.expectEqual(probe.term_after, probe.follow_up_term);

        // …and the vote was GRANTED. With `votedFor` left naming node 0 itself,
        // `may_vote` is false and this stays 0 (the stale self-vote).
        try testing.expectEqual(@as(NodeId, 1), probe.voted_for_after_follow_up);
    }
}

/// Drive raw payloads into `node` as if they arrived from `from`, through the
/// real `Protocol` vtable.
fn feedFrom(srv: *RaftServer, node: NodeId, from: NodeId, payloads: []const []const u8) !void {
    const gpa = testing.allocator;
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, srv.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);
    const p = srv.protocol();
    for (payloads) |payload| try p.onMessageFn(p.ctx, &sim, node, from, payload);
}

/// AppendEntries wire bytes, written into `buf`.
fn encodeAppend(buf: *[types.AppendEntriesReq.max_wire]u8, prev_index: LogIndex, prev_term: Term, entries: []const LogEntry, leader_commit: LogIndex) []const u8 {
    const n = (types.AppendEntriesReq{
        .term = 1,
        .leader_id = 1,
        .prev_log_index = prev_index,
        .prev_log_term = prev_term,
        .entries = entries,
        .leader_commit = leader_commit,
    }).encode(buf);
    return buf[0..n];
}

test "the naive §5.3 truncation rule rolls back COMMITTED entries; the conflict-only rule keeps them" {
    const gpa = testing.allocator;
    const e = [_]LogEntry{
        .{ .term = 1, .command = commandFor(1, 1) },
        .{ .term = 1, .command = commandFor(1, 2) },
        .{ .term = 1, .command = commandFor(1, 3) },
        .{ .term = 1, .command = commandFor(1, 4) },
        .{ .term = 1, .command = commandFor(1, 5) },
    };
    var b1: [types.AppendEntriesReq.max_wire]u8 = undefined;
    var b2: [types.AppendEntriesReq.max_wire]u8 = undefined;
    const ae1 = encodeAppend(&b1, 0, 0, e[0..3], 0);
    const ae2 = encodeAppend(&b2, 3, 1, e[3..5], 5);
    // AE#1, then AE#2, then a DUPLICATE of AE#1 arriving late (netsim's
    // `dup_once` / `delay_once` produce exactly this).
    const stream = [_][]const u8{ ae1, ae2, ae1 };

    // Conflict-only (§5.3): the duplicate matches entry-for-entry, so nothing
    // is cut and nothing is re-appended.
    {
        var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
        defer srv.deinit(gpa);
        try feedFrom(&srv, 0, 1, &stream);
        try testing.expectEqual(@as(LogIndex, 5), srv.nodes[0].log.lastIndex());
        try testing.expectEqual(@as(LogIndex, 5), srv.nodes[0].commit_index);
        try testing.expectEqual(@as(LogIndex, 5), srv.nodes[0].last_applied);
    }

    // Naive ("cut everything after prevLogIndex, re-append the batch"): the
    // duplicate deletes indices 4 and 5 — which this follower had already
    // COMMITTED and APPLIED. The state machine is now ahead of the log.
    {
        var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
        defer srv.deinit(gpa);
        srv.bug = .naive_truncation;
        try feedFrom(&srv, 0, 1, &stream);
        try testing.expectEqual(@as(LogIndex, 3), srv.nodes[0].log.lastIndex());
        try testing.expect(srv.nodes[0].last_applied > srv.nodes[0].log.lastIndex());
    }

    // NOTE (beyond the finding): this rollback is still INVISIBLE to the live
    // model-check, distinct commands or not. An entry's identity is
    // `(creating term, index)` — Election Safety makes that unique — so when the
    // same leader re-replicates indices 4 and 5 it restores byte-identical
    // entries, and `recordApply` sees the value it already has. The §5.3
    // conflict-rule trap therefore remains covered by `safety.zig`'s unit test
    // (`§5.3 the trap`) and by this test, NOT by the fuzzed sweep. F1's other
    // half — the §5.4.1 election restriction — is the one the sweep now catches.
}

// ── malformed inbound messages: dropped, counted, never fatal ───────────────
//
// Every payload below used to PANIC inside `onMessage` (out-of-bounds index,
// "invalid enum value", or — with safety off — an out-of-bounds write past
// `handleAppendReq`'s 8-element `scratch`). Driving them through the real
// `Protocol` vtable is what proves the fix reaches the actual entry point and
// not just the codec: `tagOf` runs before any decoder, so a fail-closed
// decoder behind a panicking tag read would never have been reached.

fn feedMalformed(srv: *RaftServer, payloads: []const []const u8) !void {
    const gpa = testing.allocator;
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, srv.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);
    const p = srv.protocol();
    for (payloads) |payload| try p.onMessageFn(p.ctx, &sim, 0, 1, payload);
}

test "malformed inbound messages are dropped and counted, and never crash the node" {
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);

    // A header claiming 65535 entries — the out-of-bounds WRITE.
    var lying_count = [_]u8{0} ** types.AppendEntriesReq.header_len;
    lying_count[0] = @intFromEnum(types.RpcTag.append_entries_req);
    std.mem.writeInt(u16, lying_count[37..39], 0xFFFF, .little);

    // A well-formed tag whose entry count exceeds the bytes present.
    var short_batch = [_]u8{0} ** types.AppendEntriesReq.header_len;
    short_batch[0] = @intFromEnum(types.RpcTag.append_entries_req);
    std.mem.writeInt(u16, short_batch[37..39], 4, .little);

    const cases = [_][]const u8{
        &.{}, // empty: tagOf out of bounds
        &.{99}, // undefined RPC tag: "invalid enum value"
        &.{@intFromEnum(types.RpcTag.request_vote_req)}, // the reported reproducer
        &.{@intFromEnum(types.RpcTag.request_vote_resp)},
        &.{@intFromEnum(types.RpcTag.append_entries_req)},
        &.{@intFromEnum(types.RpcTag.append_entries_resp)},
        &lying_count,
        &short_batch,
    };
    try feedMalformed(&srv, &cases);

    // Every one was dropped — counted, not silently swallowed.
    try testing.expectEqual(@as(u64, cases.len), srv.malformed_dropped);
    // …and none of them moved the consensus state.
    for (srv.nodes) |*n| {
        try testing.expectEqual(@as(Term, 0), n.current_term);
        try testing.expectEqual(no_vote, n.voted_for);
        try testing.expectEqual(@as(LogIndex, 0), n.log.lastIndex());
    }
}

test "a well-formed message is still accepted (the guard is not over-tight)" {
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);

    var rq: [types.RequestVoteReq.wire_len]u8 = undefined;
    (types.RequestVoteReq{ .term = 5, .candidate_id = 1, .last_log_index = 0, .last_log_term = 0 }).encode(&rq);
    try feedMalformed(&srv, &.{&rq});

    try testing.expectEqual(@as(u64, 0), srv.malformed_dropped);
    // The vote request was acted on: node 0 stepped up to term 5 and voted.
    try testing.expectEqual(@as(Term, 5), srv.nodes[0].current_term);
    try testing.expectEqual(@as(NodeId, 1), srv.nodes[0].voted_for);
}

test "real: the model-checked cluster never drops a message of its own making" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };

    // Every byte on this wire came from our own `encode`, so a single drop
    // would mean an encoder/decoder disagreement — the fail-closed decoders
    // turn what used to be a panic into a silent drop, and this is what keeps
    // that from hiding a real codec bug.
    var seed: u64 = 1;
    while (seed <= 25) : (seed += 1) {
        var case = template;
        case.seed = seed;
        var gr = try netsim.run(gpa, case, .{});
        defer gr.trace.deinit();
        try testing.expectEqual(@as(u64, 0), srv.malformed_dropped);
    }
}

test "a leader rejects an AppendEntriesResp claiming more log than it has" {
    // `match_index` is an unconstrained wire u64 and `decode` bounds only the
    // term, so `next_index = match_index + 1` was an unconditional increment
    // on peer-controlled input -- the shape `max_term` exists to rule out for
    // `current_term`. Rejected rather than clamped: clamping would record the
    // follower as having matched the WHOLE log, and `leaderCommitIndex`
    // counts exactly those values for its majority, so a forged response
    // could commit entries no majority ever replicated.
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);

    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = netsim.Sim.init(gpa, 0, srv.protocol(), &log, UNTIL, 10_000);
    defer sim.deinit();
    try scenario(&sim);

    // Put node 0 in the one state that reaches the arithmetic.
    const ns = &srv.nodes[0];
    ns.role = .leader;
    ns.current_term = 1;

    var payload = [_]u8{0} ** 18;
    payload[0] = @intFromEnum(types.RpcTag.append_entries_resp);
    std.mem.writeInt(u64, payload[1..9], 1, .little); // term == leader's
    payload[9] = 1; // success
    std.mem.writeInt(u64, payload[10..18], std.math.maxInt(u64), .little);

    const before = srv.malformed_dropped;
    const p = srv.protocol();
    try p.onMessageFn(p.ctx, &sim, 0, 1, &payload);

    // Dropped and counted, and nothing about the peer's replication state moved.
    try testing.expectEqual(before + 1, srv.malformed_dropped);
    try testing.expectEqual(@as(LogIndex, 0), ns.match_index[1]);
    try testing.expect(ns.commit_index == 0);
}
