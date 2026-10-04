// SPDX-License-Identifier: MIT

//! server — the `netsim.Protocol` consumer(s).
//!
//!  - `RaftServer` runs one `node.Node` per simulated server — the same state
//!    machine a deployment drives — and plays every role the deployment
//!    plays around it: the clock (a `Node.tick` every `RaftConfig.tick`), the
//!    transport (`Message.encode` → `sim.send` → `Node.stepBytes`), the disk
//!    (each `Ready`'s hard state, truncation and entries, kept per server) and
//!    the state machine (each `Ready.committed`, fed to the invariant
//!    checkers). A restart after a crash rebuilds the node from its disk ALONE,
//!    so commit index, applied index, role and the leader's bookkeeping are
//!    lost exactly as Figure 2 says volatile state is. The fuzzed fault sweep
//!    therefore checks the code a consumer runs, not a copy of it.
//!  - `BrokenRaft` is the POSITIVE CONTROL: a deliberately-wrong election that
//!    declares leadership WITHOUT collecting a majority and never calls
//!    `safety.zig`. Its job is to prove `checks.SafetyChecker` has teeth — it
//!    reuses that EXACT type, so the `error.ElectionSafety` it trips is
//!    provably the same check the real protocol is held to.
//!
//! Cluster topology (`scenario`): a 5-node full mesh, so a partition can carve
//! the cluster into a majority and a minority side (the case leader election and
//! the commit rule must survive) and heal.
//!
//! History: until 2026-10-04 this file held its own copy of the Raft plumbing
//! around the kernel (timers, vote tally, nextIndex/matchIndex, the apply
//! loop), and `example-apps/raft-kv` held a second one. The model-check
//! verified the first; nothing verified the second, and it had drifted (no
//! bound on a peer's claimed match index). `node.zig` is now the only copy.

const std = @import("std");
const netsim = @import("netsim");
const types = @import("types.zig");
const checks = @import("checks.zig");
const node_mod = @import("node.zig");
const message = @import("message.zig");

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
const Node = node_mod.Node;
const Entry = node_mod.Entry;
const Message = node_mod.Message;
const Role = node_mod.Role;
const no_vote = types.no_vote;

/// Moved to `node.zig`, where the rules it breaks now live.
pub const InjectedBug = node_mod.InjectedBug;

// ── shared topology + config ────────────────────────────────────────────────

pub const CLUSTER_N = 5;

pub const RaftConfig = struct {
    /// Base time a follower waits without hearing from a leader before starting
    /// an election.
    election_timeout: Time = 100,
    /// Per-node deterministic offset added to `election_timeout` (`node *
    /// election_spread`) — Raft's randomized timeout, made deterministic for the
    /// sim (`Node`'s jitter is off here) so it still de-synchronizes candidates
    /// and avoids perpetual split votes.
    election_spread: Time = 15,
    /// How often a leader emits heartbeats. Must be well under
    /// `election_timeout` so a live leader keeps followers from timing out.
    heartbeat_period: Time = 30,
    /// Simulated time per `Node.tick`. The three periods above are rounded
    /// down to whole ticks.
    tick: Time = 10,
    /// Propose one DISTINCT client command per heartbeat while leader.
    ///
    /// This is what gives the live State-Machine-Safety and Log-Matching
    /// checkers teeth. With it off, the only entries are leader no-ops, and a
    /// partitioned leader's log cannot outgrow the majority's — the shape the
    /// §5.4.1 positive control needs. See `commandFor`.
    propose_client_commands: bool = true,
    /// Drain each node's `Ready` after EVERY event (true) or only on its tick
    /// (false). The second batches every message a node receives between two
    /// ticks into one `ready` — legal under the contract, and the only way
    /// the sweep can reach a bug that needs two inputs before a `ready`. Each
    /// event's Ready used to be persisted, sent and applied atomically, which
    /// hid every bug of that shape. (Measured: it does NOT catch the review's
    /// H1 re-introduced — that bug's damage needs a peer to accept the stale
    /// broadcast while holding committed entries to lose; `node.zig`'s H1
    /// test is what pins it.)
    drain_every_event: bool = true,
};

/// The command a leader proposes when its next entry will be `index` while
/// serving `term`: the pair packed into a `u64`, carried as the entry's 8 bytes.
///
/// Distinctness is the whole point. Two servers may legally hold DIFFERENT
/// entries at the same index (an uncommitted tail from a deposed leader), and
/// State Machine Safety is the claim that they never *apply* different ones
/// there. That claim is only observable if entries created by different terms
/// at the same index differ — Election Safety already gives at most one leader
/// per term, so `(term, index)` uniquely names an entry's creator.
pub fn commandFor(term: Term, index: LogIndex) Command {
    return (@as(Command, @truncate(term)) << 32) | @as(Command, @truncate(index));
}

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

// ── RaftServer: N real `Node`s inside netsim ────────────────────────────────

/// One simulated server: its node (null before the first start) and what
/// survives a crash — its disk.
const Slot = struct {
    node: ?Node = null,
    disk_hs: node_mod.HardState = .{},
    /// Persisted entries; `data` owned.
    disk: std.ArrayList(Entry) = .empty,
    /// Tick-timer generation. netsim timers cannot be cancelled, so a restart
    /// starts a new chain and a timer from an older one is ignored.
    epoch: u64 = 0,
    ticks: u64 = 0,
    /// `malformed_dropped` of node incarnations before this one.
    dropped_before: u64 = 0,
    /// The term this server was last recorded leader of (Election Safety).
    leader_recorded: Term = 0,
    /// Leader Append-Only witness: the log as of the previous `check`.
    prev_log: std.ArrayList(LogEntry) = .empty,

    fn wipe(s: *Slot, gpa: Allocator) void {
        if (s.node) |*n| n.deinit();
        s.node = null;
        for (s.disk.items) |e| gpa.free(e.data);
        s.disk.clearRetainingCapacity();
        s.disk_hs = .{};
        s.epoch = 0;
        s.ticks = 0;
        s.dropped_before = 0;
        s.leader_recorded = 0;
        s.prev_log.clearRetainingCapacity();
    }

    fn deinit(s: *Slot, gpa: Allocator) void {
        s.wipe(gpa);
        s.disk.deinit(gpa);
        s.prev_log.deinit(gpa);
    }
};

pub const RaftServer = struct {
    gpa: Allocator,
    node_count: usize,
    cfg: RaftConfig,
    slots: []Slot,
    checker: checks.SafetyChecker = .{},
    /// index → the term in which that index was FIRST committed (the committing
    /// leader's term). Raft's Leader Completeness (Figure 3) constrains "the
    /// leaders of all HIGHER-numbered terms" than the commit — a deposed leader
    /// still holding `.leader` inside a minority partition legally misses
    /// entries committed in LATER terms, so `check` must scope the predicate by
    /// this term or it flags legal executions. The first record for an index is
    /// always the committing leader's own: it applies the entry in the same
    /// event in which its commit index passes it, and a follower can only learn
    /// that commit index from a message sent in that event.
    commit_terms: std.AutoHashMapUnmanaged(LogIndex, Term) = .empty,
    /// index → the `commandFor` value applied there (command entries only).
    applied_commands: std.AutoHashMapUnmanaged(LogIndex, Command) = .empty,
    wire: std.ArrayList(u8) = .empty,

    /// Deliberate defect to run instead of the real rule, installed into every
    /// node. `.none` in every production path; the positive-control tests set
    /// it and REQUIRE the live checker to trip. See `InjectedBug`.
    bug: InjectedBug = .none,

    pub fn init(gpa: Allocator, node_count: usize, cfg: RaftConfig) Allocator.Error!RaftServer {
        const slots = try gpa.alloc(Slot, node_count);
        @memset(slots, .{});
        return .{ .gpa = gpa, .node_count = node_count, .cfg = cfg, .slots = slots };
    }

    pub fn deinit(self: *RaftServer, gpa: Allocator) void {
        for (self.slots) |*s| s.deinit(gpa);
        gpa.free(self.slots);
        self.checker.deinit(gpa);
        self.commit_terms.deinit(gpa);
        self.applied_commands.deinit(gpa);
        self.wire.deinit(gpa);
        self.* = undefined;
    }

    /// Server `i`'s current node incarnation (it must have started).
    pub fn node(self: *RaftServer, i: NodeId) *Node {
        return &self.slots[i].node.?;
    }

    /// Inbound messages dropped as malformed, across every node and every
    /// incarnation of it, in this run. In this harness every byte on the wire
    /// came from our own `encode`, so the model-check requires 0: a fail-closed
    /// decoder must not be allowed to quietly hide a codec bug.
    pub fn malformedDropped(self: *const RaftServer) u64 {
        var n: u64 = 0;
        for (self.slots) |s| {
            n += s.dropped_before;
            if (s.node) |x| n += x.malformed_dropped;
        }
        return n;
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
        for (self.slots) |*s| s.wipe(self.gpa);
        self.checker.reset();
        self.commit_terms.clearRetainingCapacity();
        self.applied_commands.clearRetainingCapacity();
    }

    fn ticksOf(self: *const RaftServer, t: Time) u32 {
        return @intCast(@max(1, t / self.cfg.tick));
    }

    fn nodeConfig(self: *const RaftServer, i: NodeId) node_mod.Config {
        const hb = self.ticksOf(self.cfg.heartbeat_period);
        return .{
            .id = i,
            .cluster_size = @intCast(self.node_count),
            .election_ticks = @max(hb + 1, self.ticksOf(self.cfg.election_timeout + @as(Time, i) * self.cfg.election_spread)),
            .election_jitter_ticks = 0,
            .heartbeat_ticks = hb,
            .max_append_entries = types.max_entries_per_msg,
            .seed = i,
        };
    }

    /// First start and every restart: a node built from this server's disk.
    fn onStart(ctx: *anyopaque, sim: *Sim, i: NodeId) anyerror!void {
        const self = cast(ctx);
        const s = &self.slots[i];
        if (s.node) |*old| {
            s.dropped_before += old.malformed_dropped;
            old.deinit();
            s.node = null;
        }
        s.node = try Node.init(self.gpa, self.nodeConfig(i), .{ .hard_state = s.disk_hs, .entries = s.disk.items });
        s.node.?.injected_bug = self.bug;
        s.epoch += 1;
        s.ticks = 0;
        try sim.setTimer(i, self.cfg.tick, s.epoch);
    }

    fn onTimer(ctx: *anyopaque, sim: *Sim, i: NodeId, timer_id: u64) anyerror!void {
        const self = cast(ctx);
        const s = &self.slots[i];
        if (timer_id != s.epoch) return;
        const n = &s.node.?;
        s.ticks += 1;
        // A client request arriving at the leader, once per heartbeat period
        // (the sim has no clients). Proposed BEFORE the tick, so the heartbeat
        // it triggers carries it.
        if (self.cfg.propose_client_commands and n.role == .leader and s.ticks % n.cfg.heartbeat_ticks == 0) {
            var b: [8]u8 = undefined;
            std.mem.writeInt(Command, &b, commandFor(n.term, n.lastIndex() + 1), .little);
            _ = try n.propose(&b);
        }
        try n.tick();
        try self.drain(sim, i);
        try sim.setTimer(i, self.cfg.tick, s.epoch);
    }

    fn onMessage(ctx: *anyopaque, sim: *Sim, i: NodeId, from: NodeId, payload: []const u8) anyerror!void {
        const self = cast(ctx);
        try self.node(i).stepBytes(from, payload);
        if (self.cfg.drain_every_event) try self.drain(sim, i);
    }

    /// The deployment's half of the contract, in its order: persist, send,
    /// apply, advance.
    fn drain(self: *RaftServer, sim: *Sim, i: NodeId) anyerror!void {
        const gpa = self.gpa;
        const s = &self.slots[i];
        const n = &s.node.?;
        while (n.hasReady()) {
            const rd = try n.ready();

            if (rd.hard_state) |hs| s.disk_hs = hs;
            if (rd.truncate_after) |t| {
                while (s.disk.items.len > t) gpa.free(s.disk.pop().?.data);
            }
            for (rd.entries) |e| {
                if (e.index != s.disk.items.len + 1) return error.ReadyEntriesNotContiguous;
                var owned = e;
                owned.data = try gpa.dupe(u8, e.data);
                errdefer gpa.free(owned.data);
                try s.disk.append(gpa, owned);
            }

            for (rd.messages) |m| {
                try self.wire.resize(gpa, m.encodedLen());
                _ = m.encode(self.wire.items);
                try sim.send(m.from, m.to, self.wire.items);
            }

            for (rd.committed) |e| {
                const fp = node_mod.fingerprint(e);
                try self.checker.recordApply(gpa, e.index, fp);
                try self.checker.recordCommitted(gpa, .{ .index = e.index, .term = e.term, .command = fp });
                const gop = try self.commit_terms.getOrPut(gpa, e.index);
                if (!gop.found_existing) gop.value_ptr.* = n.term;
                if (e.kind == .command and e.data.len == 8)
                    try self.applied_commands.put(gpa, e.index, std.mem.readInt(Command, e.data[0..8], .little));
            }

            try n.advance();
        }
        // The disk now holds exactly the node's log — a Ready that missed an
        // overwrite of equal length would leave them differing in content.
        if (s.disk.items.len != n.lastIndex()) return error.DiskDiverged;
        for (s.disk.items) |e| {
            if (n.log.get(e.index).?.command != node_mod.fingerprint(e)) return error.DiskDiverged;
        }
        // Election Safety witness: at most one leader per term.
        if (n.role == .leader and s.leader_recorded != n.term) {
            try self.checker.recordLeader(gpa, n.term, i);
            s.leader_recorded = n.term;
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
        for (self.slots, logs) |*s, *slot| slot.* = if (s.node) |*n| n.log.entries.items else &.{};
        if (checks.logMatchingViolation(logs) != null) return error.LogMatching;

        // Committed-set workspace for Leader Completeness, re-filtered per leader.
        var committed: std.ArrayList(checks.CommitRec) = .empty;
        defer committed.deinit(self.gpa);

        for (self.slots) |*s| {
            const n = if (s.node) |*x| x else continue;
            if (n.role != .leader) continue;
            // Leader Append-Only — never shrinks/overwrites its own log.
            if (!checks.appendOnlyHolds(s.prev_log.items, n.log.entries.items)) return error.LeaderAppendOnly;
            // Leader Completeness — Figure 3 scopes it to "the leaders of all
            // HIGHER-numbered terms" than the commit, so a stale leader (deposed
            // but unaware inside a minority partition) is only held to entries
            // committed in terms ≤ its own; requiring more flags legal runs.
            // (`<=` keeps the committing leader itself checked — strictly
            // stronger, and it trivially holds its own commits.) A real
            // Figure-8 loss is still caught twice over: any FUTURE leader
            // missing the entry trips this check, and an overwritten committed
            // entry trips recordCommitted/recordApply (State Machine Safety).
            committed.clearRetainingCapacity();
            var it = self.checker.committed.iterator();
            while (it.next()) |kv| {
                const commit_term = self.commit_terms.get(kv.key_ptr.*) orelse 0;
                if (commit_term <= n.term) try committed.append(self.gpa, kv.value_ptr.*);
            }
            if (!checks.leaderCompletenessHolds(n.log.entries.items, committed.items)) return error.LeaderCompleteness;
        }
        // Refresh the append-only witnesses AFTER the check.
        for (self.slots) |*s| {
            s.prev_log.clearRetainingCapacity();
            if (s.node) |*n| try s.prev_log.appendSlice(self.gpa, n.log.entries.items);
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
const gate = @import("gate.zig");

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
    // netsim audit F6: `BrokenRaft` fires "on a clean run with no injected
    // faults" (see its own doc comment above) — the true minimal reproducer
    // is the EMPTY fault set, and netsim's shrinker finds exactly that.
    try testing.expectEqual(@as(usize, 0), res.after);

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

// ── the real model-check: N `Node`s under fuzzed faults ─────────────────────

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

test "real: a 150-seed sweep with Readys batched per tick (several inputs before one ready)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var cfg = DEFAULT_CFG;
    cfg.drain_every_event = false;
    var srv = try RaftServer.init(gpa, CLUSTER_N, cfg);
    defer srv.deinit(gpa);
    const template = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };

    const failing = try netsim.findFailing(gpa, template, .{}, 1, 150);
    if (failing) |*f| {
        var mf = f.*;
        defer mf.deinit();
        std.debug.print("raft: batched cluster tripped {} at seed {}\n", .{ mf.err, mf.case.seed });
        return error.HardInvariantViolated;
    }
    // …and it still makes progress.
    const r = try netsim.replay(gpa, .{ .seed = 7, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL }, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    try testing.expect(srv.applied_commands.count() >= 20);
}

test "real: a leader is eventually elected on a quiet network, and commits" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    var leaders: usize = 0;
    for (0..CLUSTER_N) |i| {
        if (srv.node(@intCast(i)).role == .leader) leaders += 1;
    }
    try testing.expectEqual(@as(usize, 1), leaders);
    // Liveness, not just election: on a quiet network the leader keeps
    // committing a command per heartbeat for the whole run.
    try testing.expect(srv.applied_commands.count() >= 30);
}

// ── the live State-Machine-Safety key actually varies ───────────────────────
//
// The audit's F1: once every replicated entry carried the SAME command, so
// `SafetyChecker.recordApply`, which keys on the command value, compared 0
// against 0 at every index — State Machine Safety, the deepest of the five,
// could not fail no matter what the algorithm did. The key is now the entry's
// fingerprint (index, term, kind, bytes), and the bytes are `commandFor`.

test "real: every applied command is DISTINCT and names the (term, index) that created it" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    const case = netsim.Case{ .seed = 7, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &.{}, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

    var seen: std.AutoHashMapUnmanaged(Command, void) = .empty;
    defer seen.deinit(gpa);
    var it = srv.applied_commands.iterator();
    while (it.next()) |kv| {
        try seen.put(gpa, kv.value_ptr.*, {});
        // Mutate `commandFor` to a constant and this pins it.
        const rec = srv.checker.committed.get(kv.key_ptr.*).?;
        try testing.expectEqual(commandFor(rec.term, kv.key_ptr.*), kv.value_ptr.*);
    }
    try testing.expect(srv.applied_commands.count() >= 3);
    try testing.expectEqual(srv.applied_commands.count(), seen.count());
}

/// The minority side of the directed schedule below: node 0 alone.
const CUT0 = [_]NodeId{0};

/// The interleaving §5.4.1 exists to forbid, as a hand-built fault schedule —
/// no seed search, no luck. Four beats:
///
///  1. `partition` node 0 away. It is the term-1 leader and stays leader inside
///     its minority (Raft has no lease), so it keeps proposing — accumulating a
///     LONG tail of STALE-term entries.
///  2. `crash` the majority's term-2 leader, so the term-3 leader elected in its
///     place has never spoken to node 0 — its `nextIndex[0]` starts at its own
///     log end, so re-syncing node 0 needs a walk-back rather than one
///     matching batch.
///  3. `heal`. Node 0 hears the term-3 leader and steps down, but the walk-back
///     has not yet cut its stale tail.
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
    // the same defect, the same schedule and the same checkers see nothing at
    // all, because a partitioned leader's log cannot grow and the index-only
    // comparison never has anything to be wrong about.
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

// ── a step-down must leave the node electable and able to vote ──────────────
//
// Two liveness regressions the pre-`Node` plumbing had, kept as tests because
// a state-based `checkFn` cannot see either: (1) a leader demoted by anything
// but an AppendEntries REQUEST was left with no armed election timer — it
// answered every RPC correctly and was never electable again; (2) a step-down
// left `votedFor` naming last term's candidate, so the node refused a vote it
// had to grant in the term it had just adopted. With tick-driven elections (1)
// has no place to live any more — but the test is what proves it.

const StepDownVia = enum {
    /// A follower/candidate replies to an AppendEntries with a higher term.
    append_resp,
    /// A peer's vote reply carries a higher term.
    vote_resp,
    /// A candidate at a higher term whose log is NOT up to date: the vote is
    /// REFUSED but the term is still adopted and the role still drops.
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
    /// candidate whose log is exactly as up-to-date. Nothing about it carries a
    /// term bump, so the grant depends purely on `votedFor` having been cleared.
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
        inner.resetFn(inner.ctx);
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

    fn deliver(inner: Protocol, sim: *Sim, node: NodeId, from: NodeId, body: message.Body) anyerror!void {
        var buf: [Message.append_header_len]u8 = undefined;
        const m: Message = .{ .from = from, .to = node, .body = body };
        const n = m.encode(&buf);
        try inner.onMessageFn(inner.ctx, sim, node, from, buf[0..n]);
    }

    fn stepDownInjection(self: *StepDownProbe, inner: Protocol, sim: *Sim, node: NodeId) anyerror!void {
        const ns = self.srv.node(node);
        self.injected = true;
        self.was_leader = ns.role == .leader;
        self.term_before = ns.term;
        self.voted_for_before = ns.voted_for;
        const higher = ns.term + 1;
        const peer: NodeId = if (node == 0) 1 else 0;
        switch (self.via) {
            .append_resp => try deliver(inner, sim, node, peer, .{ .append_resp = .{ .term = higher, .success = false, .index = 0 } }),
            .vote_resp => try deliver(inner, sim, node, peer, .{ .vote_resp = .{ .term = higher, .granted = false } }),
            // An EMPTY log at a higher term: §5.4.1 refuses the vote (the
            // leader's own log is long), so only the term step-down runs.
            .vote_req_refused => try deliver(inner, sim, node, peer, .{ .vote_req = .{ .term = higher, .last_log_index = 0, .last_log_term = 0 } }),
        }
        self.role_after = ns.role;
        self.term_after = ns.term;
        if (self.follow_up_after) |d| try sim.setTimer(node, d, FOLLOWUP_TIMER);
    }

    /// The second message: a legitimate RequestVote at the node's CURRENT term
    /// (no step-up), from a candidate claiming this node's own log summary — so
    /// §5.4.1 is satisfied exactly, and the only remaining gate is `votedFor`.
    fn voteReqInjection(self: *StepDownProbe, inner: Protocol, sim: *Sim, node: NodeId) anyerror!void {
        const ns = self.srv.node(node);
        const peer: NodeId = if (node == 0) 1 else 0;
        const info = ns.log.info();
        self.follow_up_term = ns.term;
        try deliver(inner, sim, node, peer, .{ .vote_req = .{ .term = ns.term, .last_log_index = info.last_index, .last_log_term = info.last_term } });
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
/// takes on a 5±2-tick link.
const LIVENESS_CFG = RaftConfig{ .election_timeout = 100, .election_spread = 40, .heartbeat_period = 30 };
const INJECT_AT: Time = 603;
const LIVENESS_UNTIL: Time = 1400;

/// Isolate the target by crashing every peer just before the step-down, so
/// that after it nothing can reset its timer FOR it: a surviving leader's next
/// heartbeat would.
const CRASH_PEERS = [_]netsim.FaultEvent{
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 1 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 2 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 3 } } },
    .{ .time = INJECT_AT - 1, .kind = .{ .crash_node = .{ .node = 4 } } },
};

test "real: a leader demoted by a RESPONSE or a refused vote stands for election again" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;

    for ([_]StepDownVia{ .append_resp, .vote_resp, .vote_req_refused }) |via| {
        var srv = try RaftServer.init(gpa, CLUSTER_N, LIVENESS_CFG);
        defer srv.deinit(gpa);
        var probe = StepDownProbe{ .srv = &srv, .via = via, .target = 0, .inject_at = INJECT_AT };
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = probe.protocol(), .until = LIVENESS_UNTIL };
        const r = try netsim.replay(gpa, case, &CRASH_PEERS, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

        // Preconditions — the situation the regression is about actually arose.
        try testing.expect(probe.injected);
        try testing.expect(probe.was_leader);
        // The step-down itself. THIS is the assertion that passes against the
        // bug, which is exactly why it cannot be the whole test.
        try testing.expectEqual(Role.follower, probe.role_after);
        try testing.expectEqual(probe.term_before + 1, probe.term_after);

        // Liveness: 800 time units — eight election timeouts — after the
        // step-down, the node must have STOOD FOR ELECTION.
        const n0 = srv.node(0);
        try testing.expect(n0.term > probe.term_after);
        try testing.expectEqual(Role.candidate, n0.role);
        try testing.expectEqual(@as(NodeId, 0), n0.voted_for);
    }
}

/// Ten time units after the step-down — well inside the fresh election
/// timeout, so the node is still at the term it just adopted and has not yet
/// campaigned (which would set `votedFor` to itself and destroy the observable).
const FOLLOW_UP_AFTER: Time = 10;

test "real: a step-down CLEARS votedFor, so the node can still vote in the term it just adopted" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;

    // Two messages, because one cannot see this. `handleRequestVote` treats the
    // message that CARRIES the higher term as if the vote were already cleared,
    // so a single-message test is green either way. The stale `votedFor` only
    // bites the NEXT request, at a term that is no longer new.
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
        const case = netsim.Case{ .seed = 5, .scenario = scenario, .protocol = probe.protocol(), .until = LIVENESS_UNTIL };
        const r = try netsim.replay(gpa, case, &CRASH_PEERS, null);
        try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);

        // Preconditions: it was the leader of `term_before`, which means it had
        // voted for ITSELF in that term — the stale value that must not survive.
        try testing.expect(probe.injected);
        try testing.expect(probe.was_leader);
        try testing.expectEqual(@as(NodeId, 0), probe.voted_for_before);
        try testing.expectEqual(probe.term_before + 1, probe.term_after);

        // The second message arrived at the SAME term the step-down adopted.
        try testing.expect(probe.follow_up_done);
        try testing.expectEqual(probe.term_after, probe.follow_up_term);

        // …and the vote was GRANTED.
        try testing.expectEqual(@as(NodeId, 1), probe.voted_for_after_follow_up);
    }
}

// ── malformed inbound messages, through the real Protocol entry point ───────
//
// `node.zig` pins the node-level rules; this proves the drops reach the
// harness's counter, which is what the sweep below holds at 0.

fn startedSim(gpa: Allocator, srv: *RaftServer, log: *netsim.Log) !netsim.Sim {
    var sim = netsim.Sim.init(gpa, 0, srv.protocol(), log, UNTIL, 10_000);
    errdefer sim.deinit();
    try scenario(&sim);
    const p = srv.protocol();
    for (0..CLUSTER_N) |i| try p.onStartFn.?(p.ctx, &sim, @intCast(i));
    return sim;
}

test "malformed inbound messages are dropped and counted, and never crash the node" {
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    var log: netsim.Log = .{};
    defer log.deinit(gpa);
    var sim = try startedSim(gpa, &srv, &log);
    defer sim.deinit();

    // The old format's frames are garbage to a `Node` too.
    var old: [types.RequestVoteReq.wire_len]u8 = undefined;
    (types.RequestVoteReq{ .term = 5, .candidate_id = 1, .last_log_index = 0, .last_log_term = 0 }).encode(&old);
    const cases = [_][]const u8{ &.{}, &.{99}, &.{0x10}, &.{0x12}, &.{0x13}, &old };
    const p = srv.protocol();
    for (cases) |c| try p.onMessageFn(p.ctx, &sim, 0, 1, c);

    try testing.expectEqual(@as(u64, cases.len), srv.malformedDropped());
    const n0 = srv.node(0);
    try testing.expectEqual(@as(Term, 0), n0.term);
    try testing.expectEqual(no_vote, n0.voted_for);
    try testing.expectEqual(@as(LogIndex, 0), n0.lastIndex());

    // The guard is not over-tight: a well-formed RequestVote is acted on.
    var buf: [Message.vote_req_len]u8 = undefined;
    _ = (Message{ .from = 1, .to = 0, .body = .{ .vote_req = .{ .term = 5, .last_log_index = 0, .last_log_term = 0 } } }).encode(&buf);
    try p.onMessageFn(p.ctx, &sim, 0, 1, &buf);
    try testing.expectEqual(@as(u64, cases.len), srv.malformedDropped());
    try testing.expectEqual(@as(Term, 5), n0.term);
    try testing.expectEqual(@as(NodeId, 1), n0.voted_for);
    // …and the vote reached the server's disk before the reply left.
    try testing.expectEqual(@as(NodeId, 1), srv.slots[0].disk_hs.voted_for);
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
        try testing.expectEqual(@as(u64, 0), srv.malformedDropped());
    }
}

test "real: a crashed server restarts from its disk alone and the cluster stays safe" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const gpa = testing.allocator;
    var srv = try RaftServer.init(gpa, CLUSTER_N, DEFAULT_CFG);
    defer srv.deinit(gpa);
    // Crash the first leader mid-run and bring it back much later.
    const trace = [_]netsim.FaultEvent{
        .{ .time = 600, .kind = .{ .crash_node = .{ .node = 0 } } },
        .{ .time = 1200, .kind = .{ .restart_node = .{ .node = 0 } } },
    };
    const case = netsim.Case{ .seed = 11, .scenario = scenario, .protocol = srv.protocol(), .until = UNTIL };
    const r = try netsim.replay(gpa, case, &trace, null);
    try testing.expectEqual(netsim.RunOutcome.ok, r.outcome);
    // The restarted incarnation came back from the disk (epoch 2), lost its
    // volatile state, and caught up with the new leader's log.
    try testing.expectEqual(@as(u64, 2), srv.slots[0].epoch);
    var leader: ?NodeId = null;
    for (1..CLUSTER_N) |i| {
        if (srv.node(@intCast(i)).role == .leader) leader = @intCast(i);
    }
    const l = leader orelse return error.NoLeader;
    try testing.expect(srv.node(0).term >= 2);
    try testing.expect(srv.node(0).lastIndex() + types.max_entries_per_msg >= srv.node(l).lastIndex());
    try testing.expect(srv.node(0).applied > 0);
}
