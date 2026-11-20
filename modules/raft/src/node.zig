// SPDX-License-Identifier: MIT

//! node — one Raft server as a pure state machine: no sockets, no clock, no
//! threads, no disk. The caller owns all four and drives the node with three
//! inputs and one output:
//!
//!   tick()            one unit of the caller's clock (elections, heartbeats)
//!   step(message)     a message from a peer (or `stepBytes` for raw frames)
//!   propose(bytes)    a client command, on the leader
//!   ready() / advance()   what to persist, send and apply — in that order
//!
//! ```
//! while (node.hasReady()) {
//!     const rd = node.ready();
//!     // 1. make rd.hard_state, rd.truncate_after and rd.entries DURABLE
//!     // 2. send rd.messages
//!     // 3. apply rd.committed to the state machine, in order
//!     node.advance();
//! }
//! ```
//!
//! The order is the one Figure 2 requires ("respond to RPCs only after
//! updating stable storage"): a vote or an acknowledgement that leaves the
//! machine before the state it promises is on disk can elect two leaders or
//! lose a committed entry after a crash. The node enforces the half it can see:
//! the leader counts its OWN log toward a commit majority only up to what an
//! `advance` has confirmed persisted, never up to what it merely appended.
//!
//! Every consensus DECISION is the kernel's (`safety.zig`): the vote grant, the
//! AppendEntries consistency check and conflict-only truncation, the Figure-8
//! commit rule, term observation. This file is the plumbing the model-check
//! used to own moved to where a deployment can reach it: `server.RaftServer`
//! now runs N of these inside `netsim`, so the fuzzed fault sweep checks
//! exactly the code a consumer runs.
//!
//! Structural fixes that came with the move. Elections are tick-driven: every
//! non-leader counts toward its timeout on every tick, so "a step-down forgot
//! to re-arm the election timer" — the liveness bug the netsim plumbing had
//! twice — has no place to live. A term never passes `types.max_term`: the
//! decoders refuse anything above it and a node at it stops campaigning instead
//! of incrementing into an overflow. An AppendEntries response claiming more
//! log than the leader has is dropped and counted, never clamped (`server.zig`
//! has the reasoning).
//!
//! Opt-in election hardening (both off by default, as in etcd/raft):
//! `Config.pre_vote` (Raft thesis §9.6 — a node asks whether it COULD win
//! before it bumps its term) and `Config.check_quorum` (a leader that has not
//! heard from a quorum for an election timeout steps down, and a follower
//! that heard from a leader within one ignores higher-term vote requests).
//!
//! Leadership transfer (Raft thesis §3.10; etcd/raft `MsgTransferLeader` /
//! `MsgTimeoutNow`): `transferLeadership(target)` on the leader stops new
//! proposals, brings the target's log up to date and tells it to campaign at
//! once; abandoned after one election timeout.
//!
//! Not here yet (see SPEC.md § Backlog / deferred): snapshots / log compaction, membership
//! change, linearizable reads. The whole log
//! lives in memory, and so does every entry's data.

const std = @import("std");
const types = @import("types.zig");
const log_mod = @import("log.zig");
const safety = @import("safety.zig");
const message = @import("message.zig");

const Allocator = std.mem.Allocator;
const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const EntryKind = types.EntryKind;
const LogEntry = types.LogEntry;
const Log = log_mod.Log;
const no_vote = types.no_vote;

pub const Entry = message.Entry;
pub const Message = message.Message;

/// `pre_candidate`: polling peers with PreVote before an election
/// (`Config.pre_vote`; etcd/raft's `StatePreCandidate`) — its term and vote
/// are still those of the follower it was.
pub const Role = enum { follower, pre_candidate, candidate, leader };

pub const Config = struct {
    /// This server. Voters are `0 .. cluster_size - 1`; every server in the
    /// cluster must be given the same `cluster_size`.
    id: NodeId,
    cluster_size: u32,
    /// A follower or candidate that hears nothing for this many ticks starts
    /// an election. The actual timeout is redrawn on every reset, uniformly
    /// from `[election_ticks, election_ticks + election_jitter_ticks)`.
    election_ticks: u32 = 10,
    /// Randomization against split votes (§5.2). 0 makes the timeout exact —
    /// for a deterministic simulation that de-synchronizes servers some other
    /// way; a deployment wants it near `election_ticks`.
    election_jitter_ticks: u32 = 10,
    /// A leader sends AppendEntries (a heartbeat if it has nothing new) at
    /// least this often. Must be well under `election_ticks`.
    heartbeat_ticks: u32 = 1,
    /// Entries per AppendEntries, and the most `stepBytes` will decode — so
    /// every server must agree on it.
    max_append_entries: u32 = 64,
    /// Byte cap per AppendEntries: the sum over its entries of
    /// `message.Message.entry_header_len + data.len` (the frame minus its
    /// fixed header — `maxFrameLen` is the whole frame). The leader batches up
    /// to it (and to `max_append_entries`); a follower drops and counts an
    /// AppendEntries above it before allocating anything for its entries;
    /// `propose` refuses an entry that could not fit in one. Every server must
    /// agree on it. etcd/raft's `MaxSizePerMsg`; the default is the etcd
    /// server's (1 MiB). A log holding an entry larger than this (restored
    /// from a node with a larger cap) cannot be replicated until it is raised.
    max_append_bytes: u32 = 1 << 20,
    /// Unacknowledged AppendEntries that carry entries, per follower (empty
    /// ones — heartbeats — are not counted). When a follower's window is full
    /// the leader sends it heartbeats only, until an acknowledgement frees a
    /// slot: a success frees every message it covers, a success that covers
    /// none of them frees the oldest (a lost message must not wedge the
    /// window — etcd frees one on a heartbeat response), a rejection empties
    /// it. Bounds what a slow or dead follower can pile up in the transport.
    /// etcd/raft's `MaxInflightMsgs`; the default is the etcd server's
    /// (4096 / 8 = 512). Must be > 0.
    max_inflight_msgs: u32 = 512,
    /// The same window in bytes (entry bytes as in `max_append_bytes`); 0 =
    /// no byte bound (etcd/raft's `MaxInflightBytes`, also 0 by default).
    /// When non-zero it must be >= `max_append_bytes`.
    max_inflight_bytes: u64 = 0,
    /// PreVote (Raft thesis §9.6; etcd/raft `Config.PreVote`, hashicorp/raft
    /// on unless `PreVoteDisabled`). On an election timeout the node first
    /// becomes a `pre_candidate` and asks every peer whether it WOULD vote for
    /// it in term + 1, without changing its own term or vote; only a majority
    /// of yeses starts the real election. A peer says yes only if the
    /// candidate's log is up to date (§5.4.1) and the peer has not heard from
    /// a live leader within its own `election_ticks`. So a node cut off from
    /// the cluster cannot inflate its term, and on rejoining cannot depose a
    /// healthy leader. Off by default (etcd/raft's default; existing clusters
    /// behave as before). Every server answers pre-votes whatever its own
    /// setting, but servers whose decoder predates the PreVote tags drop
    /// them — upgrade every server before switching it on.
    pre_vote: bool = false,
    /// CheckQuorum (etcd/raft `Config.CheckQuorum`; hashicorp/raft's leader
    /// lease, always on there). A leader that has not had an AppendEntries
    /// response from a majority (itself included) during the last
    /// `election_ticks` ticks steps down to follower in the same term — so a
    /// leader cut off into a minority stops acting as one. And a follower
    /// that heard from a leader within `election_ticks` (the "lease") ignores
    /// a RequestVote or PreVote carrying a higher term, without adopting that
    /// term or replying. Off by default (etcd/raft's default).
    check_quorum: bool = false,
    /// Seeds the election-timeout jitter. Give every server a different one
    /// (two servers with the same seed time out in lockstep).
    seed: u64,
};

/// The durable part of Figure 2's state besides the log.
pub const HardState = struct {
    term: Term = 0,
    voted_for: NodeId = no_vote,
};

/// What `init` restarts from: what the caller persisted out of earlier
/// `Ready`s.
pub const Restore = struct {
    hard_state: HardState = .{},
    /// The persisted log, dense from index 1. Copied.
    entries: []const Entry = &.{},
    /// Entries the caller's state machine already holds durably (0 when it
    /// is rebuilt from the log on every start). They are known committed —
    /// they were only ever handed out as committed — and are not re-delivered.
    applied: LogIndex = 0,
};

/// One batch of work. Everything it points to is owned by the node and stays
/// valid until `advance`; the caller must not call `tick`, `step`,
/// `stepBytes` or `propose` in between.
///
/// Persist in field order — `hard_state`, then `truncate_after`, then
/// `entries` — and make all three durable before sending a message. The order
/// matters for a crash in the middle: an entry is never newer than the term on
/// disk, which `init` checks (`error.InvalidRestore`); entries written before
/// the term that admitted them would leave a disk `init` refuses.
pub const Ready = struct {
    /// Non-null when term or vote changed: persist it.
    hard_state: ?HardState,
    /// Non-null when entries the caller may already have persisted were
    /// overwritten by a new leader: delete every persisted entry with an index
    /// above this, BEFORE writing `entries`.
    truncate_after: ?LogIndex,
    /// New log entries to persist, contiguous, starting right after the
    /// persisted log (after truncation).
    entries: []const Entry,
    /// To send once the above is durable. `data` slices are node-owned copies.
    messages: []const Message,
    /// Committed entries to apply, in index order, each exactly once (per
    /// `init`). May include entries from `entries` above, which is why those
    /// must be persisted first.
    committed: []const Entry,
};

/// A deliberately wrong rule, for the positive-control tests only: the
/// model-check must catch each one. `.none` everywhere else.
pub const InjectedBug = enum {
    none,
    /// §5.3's conflict rule replaced by "truncate everything after
    /// prevLogIndex, then append the whole batch".
    naive_truncation,
    /// §5.4.1 with the term-first clause dropped: "up to date" iff at least
    /// as long.
    index_only_up_to_date,
};

pub const InitError = error{ InvalidConfig, InvalidRestore } || Allocator.Error;
/// `ProposalDropped`: a leadership transfer is under way (etcd/raft's
/// `ErrProposalDropped`; hashicorp/raft's `ErrLeadershipTransferInProgress`).
pub const ProposeError = error{ NotLeader, EntryTooLarge, ProposalDropped } || Allocator.Error;
/// `InvalidTarget`: the target is not a server of this cluster.
pub const TransferError = error{ NotLeader, InvalidTarget } || Allocator.Error;

/// Upper bound on any `propose` payload: the wire carries an entry's length
/// as a `u32`. The effective bound is lower — `Config.max_append_bytes` minus
/// `message.Message.entry_header_len`.
pub const max_entry_len: usize = std.math.maxInt(u32);

/// A 64-bit fingerprint of an entry — its position, term, kind and bytes.
/// Stored as each entry's `LogEntry.command`, so the log the kernel and the
/// invariant checkers see compares CONTENT, not just terms: two entries at one
/// index with different bytes have different fingerprints. Not cryptographic;
/// it is a checker key, not an integrity check against a hostile leader.
pub fn fingerprint(e: Entry) u64 {
    var h = std.hash.Wyhash.init(0x7261_6674); // "raft"
    var hdr: [17]u8 = undefined;
    std.mem.writeInt(u64, hdr[0..8], e.index, .little);
    std.mem.writeInt(u64, hdr[8..16], e.term, .little);
    hdr[16] = @backingInt(e.kind);
    h.update(&hdr);
    h.update(e.data);
    return h.final();
}

pub const Node = struct {
    gpa: Allocator,
    cfg: Config,

    // persistent (Figure 2) — durable once an `advance` confirms it
    term: Term = 0,
    voted_for: NodeId = no_vote,
    /// Terms, kinds and fingerprints; `data[i - 1]` is index i's bytes.
    log: Log = .{},
    data: std.ArrayList([]u8) = .empty,

    // volatile
    role: Role = .follower,
    /// The server last seen acting as leader in this term, or `no_vote` —
    /// where to redirect a client.
    leader: NodeId = no_vote,
    commit: LogIndex = 0,
    /// Highest index handed out in `Ready.committed` and confirmed by `advance`.
    applied: LogIndex = 0,
    /// Highest index confirmed persisted (by `advance`, or by `init`).
    stable: LogIndex = 0,

    // leader / candidate bookkeeping, indexed by NodeId
    votes: []bool,
    next: []LogIndex,
    match: []LogIndex,
    /// Per-follower in-flight window (`Config.max_inflight_msgs`): follower
    /// p's ring is `infl_last/infl_size[p * cap ..][0..cap]`, oldest at
    /// `infl_head[p]`. Each slot is one unacknowledged AppendEntries with
    /// entries: the last index it carried and its entry bytes. Between two
    /// resets the last indices never decrease (nextIndex only rises without a
    /// rejection, and a leader's log only grows), so freeing "every message
    /// an ack covers" pops from the front.
    infl_last: []LogIndex,
    infl_size: []u32,
    infl_head: []u32,
    infl_count: []u32,
    infl_bytes: []u64,
    /// CheckQuorum: which followers sent an AppendEntries response since the
    /// leader's last quorum check (etcd/raft `Progress.RecentActive`).
    recent_active: []bool,
    /// The server a leadership transfer is handing over to, or `no_vote`
    /// (etcd/raft's `leadTransferee`). While set, `propose` refuses.
    transferee: NodeId = no_vote,

    /// Ticks since this node last heard from a leader or granted a vote; on a
    /// leader, ticks into the current election-timeout period (the quorum
    /// check and the transfer deadline fall at its end).
    election_elapsed: u32 = 0,
    election_timeout: u32 = 0,
    heartbeat_elapsed: u32 = 0,
    prng: std.Random.DefaultPrng,

    // pending output
    hs_dirty: bool = false,
    /// Lowest index truncated away since the last `advance` that the caller
    /// may already have persisted; null if none.
    truncated: ?LogIndex = null,
    bcast_pending: bool = false,
    msgs: std.ArrayList(Message) = .empty,
    /// Owns the entry arrays and data copies inside `msgs`, and the arrays a
    /// `ready` builds. Reset by `advance`.
    out_arena: std.heap.ArenaAllocator,
    in_ready: bool = false,
    ready_last: LogIndex = 0,
    ready_commit: LogIndex = 0,

    decode_buf: []Entry,
    kernel_buf: std.ArrayList(LogEntry) = .empty,

    /// Inbound messages dropped as malformed or impossible: undecodable
    /// bytes, a sender outside the cluster, an AppendEntries response claiming
    /// more log than this leader has. Raft has no negative acknowledgement, so
    /// a drop is all there is to do — and counting it is what keeps a peer that
    /// only sends garbage (a dead link, as far as quorum goes) visible.
    malformed_dropped: u64 = 0,
    /// Testing only — see `InjectedBug`.
    injected_bug: InjectedBug = .none,

    pub fn init(gpa: Allocator, cfg: Config, restore: Restore) InitError!Node {
        if (cfg.cluster_size == 0 or cfg.id >= cfg.cluster_size) return error.InvalidConfig;
        if (cfg.election_ticks == 0 or cfg.heartbeat_ticks == 0 or cfg.max_append_entries == 0) return error.InvalidConfig;
        if (cfg.heartbeat_ticks >= cfg.election_ticks) return error.InvalidConfig;
        if (cfg.election_jitter_ticks > std.math.maxInt(u32) - cfg.election_ticks) return error.InvalidConfig;
        // A no-op (an empty entry) must fit in one AppendEntries.
        if (cfg.max_append_bytes < message.Message.entry_header_len) return error.InvalidConfig;
        if (cfg.max_inflight_msgs == 0) return error.InvalidConfig;
        if (cfg.max_inflight_bytes != 0 and cfg.max_inflight_bytes < cfg.max_append_bytes) return error.InvalidConfig;
        try validateRestore(cfg, restore);

        const n = cfg.cluster_size;
        var self: Node = .{
            .gpa = gpa,
            .cfg = cfg,
            .term = restore.hard_state.term,
            .voted_for = restore.hard_state.voted_for,
            .commit = restore.applied,
            .applied = restore.applied,
            .stable = restore.entries.len,
            .votes = &.{},
            .next = &.{},
            .match = &.{},
            .infl_last = &.{},
            .infl_size = &.{},
            .infl_head = &.{},
            .infl_count = &.{},
            .infl_bytes = &.{},
            .recent_active = &.{},
            .prng = .init(cfg.seed),
            .out_arena = .init(gpa),
            .decode_buf = &.{},
        };
        errdefer self.deinit();
        self.votes = try gpa.alloc(bool, n);
        self.next = try gpa.alloc(LogIndex, n);
        self.match = try gpa.alloc(LogIndex, n);
        self.decode_buf = try gpa.alloc(Entry, cfg.max_append_entries);
        const ring = std.math.mul(usize, n, cfg.max_inflight_msgs) catch return error.OutOfMemory;
        self.infl_last = try gpa.alloc(LogIndex, ring);
        self.infl_size = try gpa.alloc(u32, ring);
        self.infl_head = try gpa.alloc(u32, n);
        self.infl_count = try gpa.alloc(u32, n);
        self.infl_bytes = try gpa.alloc(u64, n);
        self.recent_active = try gpa.alloc(bool, n);
        @memset(self.recent_active, false);
        @memset(self.infl_head, 0);
        @memset(self.infl_count, 0);
        @memset(self.infl_bytes, 0);
        @memset(self.votes, false);
        @memset(self.next, 1);
        @memset(self.match, 0);
        try self.log.entries.ensureTotalCapacity(gpa, restore.entries.len);
        try self.data.ensureTotalCapacity(gpa, restore.entries.len);
        for (restore.entries) |e| {
            const owned = try gpa.dupe(u8, e.data);
            self.log.entries.appendAssumeCapacity(.{ .term = e.term, .kind = e.kind, .command = fingerprint(e) });
            self.data.appendAssumeCapacity(owned);
        }
        self.resetElectionTimer();
        return self;
    }

    fn validateRestore(cfg: Config, r: Restore) InitError!void {
        const hs = r.hard_state;
        if (hs.term > types.max_term) return error.InvalidRestore;
        if (hs.voted_for != no_vote and hs.voted_for >= cfg.cluster_size) return error.InvalidRestore;
        if (r.applied > r.entries.len) return error.InvalidRestore;
        var last_term: Term = 0;
        for (r.entries, 1..) |e, i| {
            if (e.index != i) return error.InvalidRestore;
            if (e.term < last_term or e.term > hs.term) return error.InvalidRestore;
            last_term = e.term;
        }
    }

    pub fn deinit(self: *Node) void {
        const gpa = self.gpa;
        for (self.data.items) |d| gpa.free(d);
        self.data.deinit(gpa);
        self.log.deinit(gpa);
        self.msgs.deinit(gpa);
        self.out_arena.deinit();
        self.kernel_buf.deinit(gpa);
        gpa.free(self.decode_buf);
        gpa.free(self.votes);
        gpa.free(self.next);
        gpa.free(self.match);
        gpa.free(self.infl_last);
        gpa.free(self.infl_size);
        gpa.free(self.infl_head);
        gpa.free(self.infl_count);
        gpa.free(self.infl_bytes);
        gpa.free(self.recent_active);
        self.* = undefined;
    }

    pub fn lastIndex(self: *const Node) LogIndex {
        return self.log.lastIndex();
    }

    /// Index `i`'s entry (borrowing node memory until the next mutation), or
    /// null past the end.
    pub fn entryAt(self: *const Node, i: LogIndex) ?Entry {
        const e = self.log.get(i) orelse return null;
        return .{ .index = i, .term = e.term, .kind = e.kind, .data = self.data.items[@intCast(i - 1)] };
    }

    /// The largest AppendEntries frame this node accepts (`max_append_bytes`
    /// of entries plus the fixed header) — and so the largest frame of any
    /// kind. A transport can refuse a longer frame before reading it.
    pub fn maxFrameLen(self: *const Node) usize {
        return message.Message.append_header_len + @as(usize, self.cfg.max_append_bytes);
    }

    fn majority(self: *const Node) usize {
        return self.cfg.cluster_size / 2 + 1;
    }

    fn resetElectionTimer(self: *Node) void {
        self.election_elapsed = 0;
        const j = self.cfg.election_jitter_ticks;
        self.election_timeout = self.cfg.election_ticks + if (j == 0) 0 else self.prng.random().uintLessThan(u32, j);
    }

    // ── inputs ──────────────────────────────────────────────────────────────

    pub fn tick(self: *Node) Allocator.Error!void {
        std.debug.assert(!self.in_ready);
        if (self.role == .leader) {
            // etcd's `tickHeartbeat`: once per (un-jittered) election timeout,
            // the quorum check and the transfer deadline.
            self.election_elapsed += 1;
            if (self.election_elapsed >= self.cfg.election_ticks) {
                self.election_elapsed = 0;
                if (self.cfg.check_quorum) {
                    if (!self.quorumActive()) {
                        self.becomeFollower(self.term);
                        self.leader = no_vote;
                        return;
                    }
                    @memset(self.recent_active, false);
                    self.recent_active[self.cfg.id] = true;
                }
                // A transfer not finished within one election timeout is
                // abandoned and this leader takes proposals again (etcd's
                // `abortLeaderTransfer`, hashicorp's ElectionTimeout).
                self.transferee = no_vote;
            }
            self.heartbeat_elapsed += 1;
            if (self.heartbeat_elapsed >= self.cfg.heartbeat_ticks) try self.bcastAppend();
            return;
        }
        self.election_elapsed += 1;
        if (self.election_elapsed >= self.election_timeout) {
            if (self.cfg.pre_vote) try self.preCampaign() else try self.campaign(false);
        }
    }

    /// Append `bytes` as a command entry; returns its index. It is committed
    /// when a `Ready.committed` delivers it — or never, if leadership is lost
    /// first (watch `entryAt(index).term`: a different term means it was
    /// overwritten). The bytes are copied.
    pub fn propose(self: *Node, bytes: []const u8) ProposeError!LogIndex {
        std.debug.assert(!self.in_ready);
        if (self.role != .leader) return error.NotLeader;
        if (self.transferee != no_vote) return error.ProposalDropped;
        // Bounded by the per-message byte cap, not only by the wire's u32
        // length: an entry no AppendEntries can carry would wedge replication.
        if (bytes.len > self.cfg.max_append_bytes - message.Message.entry_header_len) return error.EntryTooLarge;
        const idx = try self.appendLocal(.command, bytes);
        self.bcast_pending = true;
        return idx;
    }

    /// Hand leadership to `target` (Raft thesis §3.10; etcd/raft
    /// `TransferLeadership`). From now on `propose` refuses
    /// (`error.ProposalDropped`); the target is sent what it is missing and,
    /// once its log matches this leader's, a `timeout_now`, on which it starts
    /// an election at once — no PreVote, and its RequestVote is honoured
    /// inside a CheckQuorum lease. Done when the target wins (this node then
    /// steps down on its RequestVote); abandoned, with proposals accepted
    /// again, if this node is still leader one election timeout later. A
    /// second call for the same target is a no-op; for another target it
    /// restarts the transfer toward that one; for this node itself it cancels
    /// a transfer under way (all as etcd/raft).
    pub fn transferLeadership(self: *Node, target: NodeId) TransferError!void {
        std.debug.assert(!self.in_ready);
        if (target >= self.cfg.cluster_size) return error.InvalidTarget;
        if (self.role != .leader) return error.NotLeader;
        if (self.transferee != no_vote) {
            if (self.transferee == target) return;
            self.transferee = no_vote;
        }
        if (target == self.cfg.id) return;
        // The transfer gets one full election timeout from now (etcd).
        self.election_elapsed = 0;
        self.transferee = target;
        if (self.match[target] == self.lastIndex()) try self.sendTimeoutNow(target) else try self.sendAppend(target);
    }

    /// Decode a frame from peer `from` and step it. A frame that does not
    /// decode is dropped and counted (`malformed_dropped`).
    pub fn stepBytes(self: *Node, from: NodeId, bytes: []const u8) Allocator.Error!void {
        const m = Message.decode(bytes, from, self.cfg.id, self.decode_buf) catch {
            self.malformed_dropped += 1;
            return;
        };
        try self.step(m);
    }

    pub fn step(self: *Node, m: Message) Allocator.Error!void {
        std.debug.assert(!self.in_ready);
        if (m.to != self.cfg.id or m.from >= self.cfg.cluster_size or m.from == self.cfg.id) {
            self.malformed_dropped += 1;
            return;
        }
        if (m.body == .append_req and appendBytes(m.body.append_req.entries) > self.cfg.max_append_bytes) {
            // A hostile or misconfigured leader: refused before anything is
            // allocated for its entries. No reply (a drop is what Raft
            // tolerates; see `malformed_dropped`).
            self.malformed_dropped += 1;
            return;
        }
        switch (m.body) {
            .vote_req => |v| try self.onVoteReq(m.from, v),
            .vote_resp => |v| try self.onVoteResp(m.from, v),
            .append_req => |a| try self.onAppendReq(m.from, a),
            .append_resp => |a| try self.onAppendResp(m.from, a),
            .pre_vote_req => |v| try self.onPreVoteReq(m.from, v),
            .pre_vote_resp => |v| try self.onPreVoteResp(m.from, v),
            .timeout_now => |t| try self.onTimeoutNow(t),
        }
    }

    // ── output ──────────────────────────────────────────────────────────────

    pub fn hasReady(self: *const Node) bool {
        return self.hs_dirty or self.truncated != null or self.bcast_pending or
            self.msgs.items.len > 0 or self.lastIndex() > self.stable or self.commit > self.applied;
    }

    pub fn ready(self: *Node) Allocator.Error!Ready {
        std.debug.assert(!self.in_ready);
        if (self.bcast_pending) {
            // Belt and braces for H1: only a leader broadcasts.
            if (self.role == .leader) try self.bcastAppend() else self.bcast_pending = false;
        }
        const a = self.out_arena.allocator();
        const last = self.lastIndex();

        const first_new: usize = @intCast(self.stable + 1);
        const entries = try a.alloc(Entry, @as(usize, @intCast(last + 1)) - first_new);
        for (entries, first_new..) |*e, i| e.* = self.entryAt(i).?;

        // `commit <= lastIndex()` always holds for the real rules; the
        // `naive_truncation` positive control is what breaks it, and it must
        // be observable rather than crash the run.
        const hi = @max(self.applied, @min(self.commit, last));
        const committed = try a.alloc(Entry, @intCast(hi - self.applied));
        for (committed, @as(usize, @intCast(self.applied + 1))..) |*e, i| e.* = self.entryAt(i).?;

        self.in_ready = true;
        self.ready_last = last;
        self.ready_commit = hi;
        return .{
            .hard_state = if (self.hs_dirty) .{ .term = self.term, .voted_for = self.voted_for } else null,
            .truncate_after = self.truncated,
            .entries = entries,
            .messages = self.msgs.items,
            .committed = committed,
        };
    }

    /// Everything the last `ready` returned is persisted, sent and applied.
    pub fn advance(self: *Node) Allocator.Error!void {
        std.debug.assert(self.in_ready);
        std.debug.assert(self.ready_last == self.lastIndex());
        self.in_ready = false;
        self.hs_dirty = false;
        self.truncated = null;
        self.stable = self.ready_last;
        self.applied = self.ready_commit;
        self.msgs.clearRetainingCapacity();
        _ = self.out_arena.reset(.retain_capacity);
        if (self.role == .leader) {
            // Only now is the leader's own log durable up to `stable`, so only
            // now may it count toward a majority.
            self.match[self.cfg.id] = self.stable;
            self.maybeCommit();
        }
    }

    // ── elections ───────────────────────────────────────────────────────────

    /// `transfer`: this election was asked for by the leader
    /// (`timeout_now`); its RequestVotes say so, which lifts the
    /// CheckQuorum lease on the receivers (etcd's `campaignTransfer`).
    fn campaign(self: *Node, transfer: bool) Allocator.Error!void {
        // A term at the ceiling cannot be followed by a new one. Staying a
        // follower here is the whole defence against `term += 1` overflowing
        // (a panic) or wrapping to 0 (a term regression) — see `types.max_term`.
        if (self.term >= types.max_term) {
            self.resetElectionTimer();
            return;
        }
        self.term += 1;
        self.voted_for = self.cfg.id;
        self.hs_dirty = true;
        self.role = .candidate;
        self.leader = no_vote;
        self.resetElectionTimer();
        // A set, not a counter: a duplicated grant must not count twice.
        @memset(self.votes, false);
        self.votes[self.cfg.id] = true;
        if (self.voteCount() >= self.majority()) return self.becomeLeader();
        const li = self.log.info();
        for (0..self.cfg.cluster_size) |p| {
            if (p == self.cfg.id) continue;
            try self.send(@intCast(p), .{ .vote_req = .{
                .term = self.term,
                .last_log_index = li.last_index,
                .last_log_term = li.last_term,
                .transfer = transfer,
            } });
        }
    }

    /// PreVote (thesis §9.6): ask for votes in term + 1 without taking it.
    /// Term, vote and hard state stay as they are; a majority of grants
    /// (`onPreVoteResp`) starts the real `campaign`.
    fn preCampaign(self: *Node) Allocator.Error!void {
        // The real election would need term + 1; at the ceiling there is none.
        if (self.term >= types.max_term) {
            self.resetElectionTimer();
            return;
        }
        self.role = .pre_candidate;
        self.leader = no_vote;
        self.resetElectionTimer();
        @memset(self.votes, false);
        self.votes[self.cfg.id] = true;
        if (self.voteCount() >= self.majority()) return self.campaign(false);
        const li = self.log.info();
        for (0..self.cfg.cluster_size) |p| {
            if (p == self.cfg.id) continue;
            try self.send(@intCast(p), .{ .pre_vote_req = .{
                .term = self.term + 1,
                .last_log_index = li.last_index,
                .last_log_term = li.last_term,
            } });
        }
    }

    /// Heard from a leader (or is one) within the last `election_ticks`
    /// ticks. etcd/raft's `inLease` without the `checkQuorum` conjunct: a
    /// PreVote is refused on it always (thesis §9.6, hashicorp/raft's "we
    /// have a leader"); a RequestVote only under `check_quorum` (etcd/raft).
    fn leaderLive(self: *const Node) bool {
        return self.leader != no_vote and self.election_elapsed < self.cfg.election_ticks;
    }

    fn onPreVoteReq(self: *Node, from: NodeId, v: message.VoteReq) Allocator.Error!void {
        // Never adopts `v.term` and never records a vote: a pre-vote moves no
        // state on the receiver, only a reply leaves.
        if (v.term > self.term and self.cfg.check_quorum and self.leaderLive()) return; // inside the lease: ignored (etcd)
        // etcd's `canVote` for a pre-vote: a repeat of our vote, or no vote and
        // no leader in this term, or a future term.
        const can_vote = v.term > self.term or
            (v.term == self.term and (self.voted_for == from or (self.voted_for == no_vote and self.leader == no_vote)));
        const up_to_date = safety.logIsAtLeastAsUpToDate(.{ .last_index = v.last_log_index, .last_term = v.last_log_term }, self.log.info());
        const grant = can_vote and up_to_date and !self.leaderLive();
        // A grant carries the request's term (the asker ignores replies older
        // than its own term), a refusal ours (so a stale asker catches up).
        try self.send(from, .{ .pre_vote_resp = .{ .term = if (grant) v.term else self.term, .granted = grant } });
    }

    fn onPreVoteResp(self: *Node, from: NodeId, v: message.VoteResp) Allocator.Error!void {
        // A refusal from a higher term: that term exists, adopt it (etcd).
        // A grant carries OUR prospective term and is not adopted.
        if (!v.granted and v.term > self.term) return self.becomeFollower(v.term);
        if (self.role != .pre_candidate or !v.granted or v.term != self.term + 1) return;
        self.votes[from] = true;
        if (self.voteCount() >= self.majority()) try self.campaign(false);
    }

    /// The leader asks this node to campaign now (leadership transfer). As
    /// etcd/raft's `stepFollower` → `hup(campaignTransfer)`: a higher term is
    /// adopted first; only a follower of the message's term acts (a
    /// candidate or pre-candidate ignores it, etcd's `stepCandidate`), and
    /// never through PreVote.
    fn onTimeoutNow(self: *Node, t: message.TimeoutNow) Allocator.Error!void {
        const obs = safety.observeTerm(self.term, t.term);
        if (obs.term_advanced) self.becomeFollower(obs.new_term);
        if (t.term != self.term or self.role != .follower) return;
        try self.campaign(true);
    }

    fn sendTimeoutNow(self: *Node, to: NodeId) Allocator.Error!void {
        try self.send(to, .{ .timeout_now = .{ .term = self.term } });
    }

    fn quorumActive(self: *const Node) bool {
        var n: usize = 0;
        for (self.recent_active) |a| n += @intFromBool(a);
        return n >= self.majority();
    }

    fn voteCount(self: *const Node) usize {
        var n: usize = 0;
        for (self.votes) |v| n += @intFromBool(v);
        return n;
    }

    fn becomeLeader(self: *Node) Allocator.Error!void {
        self.role = .leader;
        self.leader = self.cfg.id;
        // nextIndex starts AT the no-op below, so the first AppendEntries
        // carries it instead of failing one consistency check per follower.
        @memset(self.next, self.lastIndex() + 1);
        @memset(self.match, 0);
        self.match[self.cfg.id] = self.stable;
        @memset(self.infl_count, 0);
        @memset(self.infl_bytes, 0);
        // CheckQuorum: the leader is always active (etcd); the first check
        // comes one election timeout from now.
        @memset(self.recent_active, false);
        self.recent_active[self.cfg.id] = true;
        self.election_elapsed = 0;
        self.transferee = no_vote;
        // §8: a fresh leader commits a no-op of its own term, which is what
        // lets the Figure-8 rule pull earlier-term entries in behind it.
        _ = try self.appendLocal(.noop, "");
        try self.bcastAppend();
    }

    /// Adopt a higher term (clearing the vote: one ballot per term, §5.1) or
    /// stay in the current one, and become a follower with a fresh timeout.
    fn becomeFollower(self: *Node, term: Term) void {
        if (term > self.term) {
            self.term = term;
            self.voted_for = no_vote;
            self.hs_dirty = true;
            self.leader = no_vote;
        }
        self.role = .follower;
        // Only a leader transfers (etcd: `reset` aborts it).
        self.transferee = no_vote;
        // A broadcast scheduled while leader must not go out after the step
        // down: `ready` would send the stale tail under the NEW term, as a
        // leader of a term this node never won (review, H1).
        self.bcast_pending = false;
        self.resetElectionTimer();
    }

    fn onVoteReq(self: *Node, from: NodeId, v: message.VoteReq) Allocator.Error!void {
        // CheckQuorum lease (etcd/raft `Step`, thesis §4.2.3): a node that
        // heard from a leader within an election timeout neither adopts a
        // higher term from a RequestVote nor answers it — unless the
        // election was asked for by the leader (a transfer, etcd's `force`).
        if (v.term > self.term and self.cfg.check_quorum and self.leaderLive() and !v.transfer) return;
        const req: types.RequestVoteReq = .{
            .term = v.term,
            .candidate_id = from,
            .last_log_index = v.last_log_index,
            .last_log_term = v.last_log_term,
        };
        // THE KERNEL: term step-up + one vote per term + §5.4.1.
        var d = safety.handleRequestVote(self.term, self.voted_for, self.log.info(), req);
        if (self.injected_bug == .index_only_up_to_date and !d.grant) {
            const effective: NodeId = if (d.term_advanced) no_vote else self.voted_for;
            const may_vote = effective == no_vote or effective == from;
            if (v.term >= self.term and may_vote and v.last_log_index >= self.lastIndex()) {
                d.grant = true;
                d.voted_for = from;
            }
        }
        // Step down before the grant: a refused vote still adopts the term.
        if (d.term_advanced) self.becomeFollower(d.new_term);
        if (d.grant) {
            if (self.voted_for != d.voted_for) {
                self.voted_for = d.voted_for;
                self.hs_dirty = true;
            }
            // Someone may become leader now; do not campaign against them.
            self.resetElectionTimer();
        }
        try self.send(from, .{ .vote_resp = .{ .term = self.term, .granted = d.grant } });
    }

    fn onVoteResp(self: *Node, from: NodeId, v: message.VoteResp) Allocator.Error!void {
        const obs = safety.observeTerm(self.term, v.term);
        if (obs.term_advanced) return self.becomeFollower(obs.new_term);
        if (self.role != .candidate or v.term != self.term or !v.granted) return;
        self.votes[from] = true;
        if (self.voteCount() >= self.majority()) try self.becomeLeader();
    }

    // ── replication ─────────────────────────────────────────────────────────

    fn appendLocal(self: *Node, kind: EntryKind, bytes: []const u8) Allocator.Error!LogIndex {
        const idx = self.lastIndex() + 1;
        const owned = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(owned);
        try self.data.ensureUnusedCapacity(self.gpa, 1);
        try self.log.append(self.gpa, .{
            .term = self.term,
            .kind = kind,
            .command = fingerprint(.{ .index = idx, .term = self.term, .kind = kind, .data = bytes }),
        });
        self.data.appendAssumeCapacity(owned);
        return idx;
    }

    fn truncateAfter(self: *Node, keep: LogIndex) void {
        if (keep >= self.lastIndex()) return;
        for (self.data.items[@intCast(keep)..]) |d| self.gpa.free(d);
        self.data.shrinkRetainingCapacity(@intCast(keep));
        self.log.truncateAfter(keep);
        if (keep < self.stable) {
            self.stable = keep;
            self.truncated = if (self.truncated) |t| @min(t, keep) else keep;
        }
    }

    fn bcastAppend(self: *Node) Allocator.Error!void {
        self.bcast_pending = false;
        self.heartbeat_elapsed = 0;
        for (0..self.cfg.cluster_size) |p| {
            if (p == self.cfg.id) continue;
            try self.sendAppend(@intCast(p));
        }
    }

    fn sendAppend(self: *Node, to: NodeId) Allocator.Error!void {
        const a = self.out_arena.allocator();
        const last = self.lastIndex();
        const prev = self.next[to] - 1;
        // A full window sends a heartbeat (no entries): it still carries the
        // commit index and holds elections off, and its ack frees a slot.
        const room: u64 = if (self.inflFull(to)) 0 else @min(last - prev, self.cfg.max_append_entries);
        // etcd's `limitSize`: the longest prefix within the byte cap, but
        // never empty — an entry above the cap goes alone (only a restored
        // log can hold one: `propose` refuses it).
        var count: usize = 0;
        var size: u64 = 0;
        while (count < room) : (count += 1) {
            const es = message.Message.entry_header_len + self.data.items[@intCast(prev + count)].len;
            if (count > 0 and size + es > self.cfg.max_append_bytes) break;
            size += es;
        }
        const entries = try a.alloc(Entry, count);
        for (entries, @as(usize, @intCast(prev + 1))..) |*e, i| {
            const src = self.entryAt(i).?;
            // Copies: a later truncation in this same batch frees the
            // originals, and the message must outlive it until `advance`.
            e.* = src;
            e.data = try a.dupe(u8, src.data);
        }
        if (count > 0) self.inflAdd(to, prev + count, @intCast(@min(size, std.math.maxInt(u32))));
        try self.send(to, .{ .append_req = .{
            .term = self.term,
            .prev_log_index = prev,
            .prev_log_term = self.log.termAt(prev).?,
            .leader_commit = self.commit,
            .entries = entries,
        } });
    }

    fn onAppendReq(self: *Node, from: NodeId, a: message.AppendReq) Allocator.Error!void {
        self.kernel_buf.clearRetainingCapacity();
        try self.kernel_buf.ensureTotalCapacity(self.gpa, a.entries.len);
        for (a.entries) |e| self.kernel_buf.appendAssumeCapacity(.{ .term = e.term, .kind = e.kind, .command = fingerprint(e) });
        const req: types.AppendEntriesReq = .{
            .term = a.term,
            .leader_id = from,
            .prev_log_index = a.prev_log_index,
            .prev_log_term = a.prev_log_term,
            .entries = self.kernel_buf.items,
            .leader_commit = a.leader_commit,
        };
        const term_before = self.term;
        // THE KERNEL: consistency check + conflict-only truncation + commit.
        var out = safety.handleAppendEntries(self.term, &self.log, self.commit, req);
        if (self.injected_bug == .naive_truncation and out.success) {
            out.truncate_to = a.prev_log_index;
            out.append_from = 0;
        }
        if (a.term >= self.term) {
            // A current leader exists: stand down (a candidate of this term
            // lost) and let its heartbeat hold elections off.
            self.becomeFollower(a.term);
            self.leader = from;
        }
        if (out.success) {
            self.truncateAfter(out.truncate_to);
            for (a.entries[out.append_from..]) |e| {
                const owned = try self.gpa.dupe(u8, e.data);
                errdefer self.gpa.free(owned);
                try self.data.ensureUnusedCapacity(self.gpa, 1);
                try self.log.append(self.gpa, .{ .term = e.term, .kind = e.kind, .command = fingerprint(e) });
                self.data.appendAssumeCapacity(owned);
            }
            if (out.new_commit_index > self.commit) self.commit = out.new_commit_index;
        }
        var resp: message.AppendResp = .{
            .term = self.term,
            .success = out.success,
            .index = if (out.success) out.match_index else self.lastIndex(),
        };
        // §5.3 conflict-term hint on a log mismatch (not on a stale-term refusal).
        if (!out.success and a.term >= term_before) {
            if (self.log.termAt(a.prev_log_index)) |ct| {
                resp.conflict_term = ct;
                resp.conflict_index = self.firstIndexOfTerm(a.prev_log_index, ct);
            } else {
                resp.conflict_index = self.lastIndex() + 1;
            }
        }
        try self.send(from, .{ .append_resp = resp });
    }

    /// The first index of term `t` in this log, given that `hi` holds term
    /// `t` (terms never decrease along the log: binary search, O(log n)).
    fn firstIndexOfTerm(self: *const Node, hi_index: LogIndex, t: Term) LogIndex {
        var lo: LogIndex = 1; // answer in [lo, hi]
        var hi: LogIndex = hi_index;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.log.termAt(mid).? < t) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// The last index holding term `t`, or null if this log has no entry of
    /// that term (same monotonicity; O(log n)).
    fn lastIndexOfTerm(self: *const Node, t: Term) ?LogIndex {
        var lo: LogIndex = 1; // first index whose term is > t, in [1, last+1]
        var hi: LogIndex = self.lastIndex() + 1;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.log.termAt(mid).? <= t) lo = mid + 1 else hi = mid;
        }
        const last = lo - 1; // last index with term <= t
        if (last == 0 or self.log.termAt(last).? != t) return null;
        return last;
    }

    fn onAppendResp(self: *Node, from: NodeId, a: message.AppendResp) Allocator.Error!void {
        const obs = safety.observeTerm(self.term, a.term);
        if (obs.term_advanced) return self.becomeFollower(obs.new_term);
        if (self.role != .leader or a.term != self.term) return;
        self.recent_active[from] = true;
        if (a.success) {
            // Rejected, not clamped: a clamp would record the follower as
            // holding the WHOLE log, and `leaderCommitIndex` counts exactly
            // that — one forged response could commit what no majority holds.
            if (a.index > self.lastIndex()) {
                self.malformed_dropped += 1;
                return;
            }
            const progressed = a.index > self.match[from];
            if (progressed) self.match[from] = a.index;
            // Everything this ack covers has arrived. If it covered nothing
            // and the window is still full, the oldest message is presumed
            // lost (etcd: `FreeFirstOne` on a heartbeat response).
            self.inflFreeLE(from, a.index);
            if (!progressed and self.inflFull(from)) self.inflFreeFirst(from);
            self.next[from] = @max(self.next[from], self.match[from] + 1);
            self.maybeCommit();
            // A transfer waits for the target to hold the whole log (etcd:
            // on the ack that brings `Match` to `lastIndex`).
            if (progressed and from == self.transferee and self.match[from] == self.lastIndex()) try self.sendTimeoutNow(from);
            // Keep streaming only on PROGRESS: a duplicated or stale ack must
            // not fork a second stream; the heartbeat covers the rest.
            if (progressed and self.next[from] <= self.lastIndex()) try self.sendAppend(from);
        } else {
            // Walk back — straight past the follower's end if its hint says
            // so — but never below what it has already confirmed (a stale
            // rejection arriving after a success).
            // With a conflict-term hint (§5.3) it skips a whole term at once:
            // past our last entry of the follower's conflicting term if we
            // have that term, else to the first index of it on the follower.
            const resume_at: LogIndex = if (a.conflict_index == 0)
                a.index +| 1
            else if (a.conflict_term != 0)
                (if (self.lastIndexOfTerm(a.conflict_term)) |li| li + 1 else a.conflict_index)
            else
                a.conflict_index;
            const lowered = @min(self.next[from] -| 1, resume_at);
            const next = @max(self.match[from] + 1, lowered);
            // Retry at once only if the rejection moved us: a follower that
            // keeps rejecting at `match + 1` (it cannot, honestly) would
            // otherwise get the same batch back every round trip.
            const moved = next < self.next[from];
            self.next[from] = next;
            // etcd: a rejection sends the follower back to probing and empties
            // its window — the messages after the gap are useless.
            self.infl_count[from] = 0;
            self.infl_bytes[from] = 0;
            if (moved) try self.sendAppend(from);
        }
    }

    // ── the in-flight window (etcd/raft `tracker.Inflights`) ─────────────────

    fn inflFull(self: *const Node, p: NodeId) bool {
        if (self.infl_count[p] >= self.cfg.max_inflight_msgs) return true;
        const cap = self.cfg.max_inflight_bytes;
        return cap != 0 and self.infl_bytes[p] >= cap;
    }

    fn inflSlot(self: *const Node, p: NodeId, k: u32) usize {
        const cap = self.cfg.max_inflight_msgs;
        return @as(usize, p) * cap + (self.infl_head[p] + k) % cap;
    }

    fn inflAdd(self: *Node, p: NodeId, last: LogIndex, size: u32) void {
        std.debug.assert(!self.inflFull(p));
        const slot = self.inflSlot(p, self.infl_count[p]);
        self.infl_last[slot] = last;
        self.infl_size[slot] = size;
        self.infl_count[p] += 1;
        self.infl_bytes[p] += size;
    }

    fn inflFreeFirst(self: *Node, p: NodeId) void {
        const slot = self.inflSlot(p, 0);
        self.infl_bytes[p] -= self.infl_size[slot];
        self.infl_head[p] = (self.infl_head[p] + 1) % self.cfg.max_inflight_msgs;
        self.infl_count[p] -= 1;
    }

    fn inflFreeLE(self: *Node, p: NodeId, index: LogIndex) void {
        while (self.infl_count[p] > 0 and self.infl_last[self.inflSlot(p, 0)] <= index) self.inflFreeFirst(p);
    }

    fn maybeCommit(self: *Node) void {
        // THE KERNEL: the Figure-8 rule.
        const nc = safety.leaderCommitIndex(self.term, self.commit, self.match, self.cfg.cluster_size, &self.log);
        if (nc > self.commit) {
            self.commit = nc;
            // Followers learn it with the next AppendEntries.
            self.bcast_pending = true;
        }
    }

    /// An AppendEntries' entry bytes as `max_append_bytes` counts them.
    fn appendBytes(entries: []const Entry) u64 {
        var n: u64 = 0;
        for (entries) |e| n += message.Message.entry_header_len + e.data.len;
        return n;
    }

    fn send(self: *Node, to: NodeId, body: message.Body) Allocator.Error!void {
        try self.msgs.append(self.gpa, .{ .from = self.cfg.id, .to = to, .body = body });
    }
};

// ── tests ───────────────────────────────────────────────────────────────────
//
// An in-memory cluster: each node's "disk" is what it persisted out of its
// Readys, the "network" a FIFO of encoded frames. Crashing a node throws away
// everything but its disk. The model-check proper is `server.zig` (netsim,
// fuzzed faults, all five invariants); these pin the API contract and the
// cases a sweep reaches only by luck.

const testing = std.testing;

const Disk = struct {
    hs: HardState = .{},
    entries: std.ArrayList(Entry) = .empty,

    fn deinit(d: *Disk, gpa: Allocator) void {
        for (d.entries.items) |e| gpa.free(e.data);
        d.entries.deinit(gpa);
    }

    fn persist(d: *Disk, gpa: Allocator, rd: Ready) !void {
        if (rd.hard_state) |hs| d.hs = hs;
        if (rd.truncate_after) |t| {
            while (d.entries.items.len > t) gpa.free(d.entries.pop().?.data);
        }
        for (rd.entries) |e| {
            try testing.expectEqual(@as(LogIndex, d.entries.items.len + 1), e.index);
            var c = e;
            c.data = try gpa.dupe(u8, e.data);
            try d.entries.append(gpa, c);
        }
    }
};

const Frame = struct { from: NodeId, to: NodeId, bytes: []u8 };

fn Cluster(comptime n: u32) type {
    return struct {
        const Self = @This();
        gpa: Allocator,
        nodes: [n]?Node = @splat(null),
        disks: [n]Disk = @splat(.{}),
        net: std.ArrayList(Frame) = .empty,
        /// What each node's state machine applied, in order.
        applied: [n]std.ArrayList([]u8) = @splat(.empty),
        cut: [n]bool = @splat(false),

        fn init(gpa: Allocator) !Self {
            var c: Self = .{ .gpa = gpa };
            for (0..n) |i| try c.start(@intCast(i));
            return c;
        }

        fn cfg(i: NodeId) Config {
            // Deterministic and staggered: node 0 always times out first.
            return .{ .id = i, .cluster_size = n, .election_ticks = 10 + 5 * i, .election_jitter_ticks = 0, .heartbeat_ticks = 2, .max_append_entries = 4, .seed = i };
        }

        fn start(c: *Self, i: NodeId) !void {
            c.nodes[i] = try Node.init(c.gpa, cfg(i), .{ .hard_state = c.disks[i].hs, .entries = c.disks[i].entries.items });
            for (c.applied[i].items) |b| c.gpa.free(b);
            c.applied[i].clearRetainingCapacity();
        }

        fn crash(c: *Self, i: NodeId) void {
            c.nodes[i].?.deinit();
            c.nodes[i] = null;
        }

        fn deinit(c: *Self) void {
            for (&c.nodes) |*m| if (m.*) |*x| x.deinit();
            for (&c.disks) |*d| d.deinit(c.gpa);
            for (c.net.items) |f| c.gpa.free(f.bytes);
            c.net.deinit(c.gpa);
            for (&c.applied) |*a| {
                for (a.items) |b| c.gpa.free(b);
                a.deinit(c.gpa);
            }
        }

        fn drain(c: *Self, i: NodeId) !void {
            const node = if (c.nodes[i]) |*x| x else return;
            while (node.hasReady()) {
                const rd = try node.ready();
                try c.disks[i].persist(c.gpa, rd);
                for (rd.messages) |m| {
                    try c.net.append(c.gpa, .{ .from = m.from, .to = m.to, .bytes = try m.encodeAlloc(c.gpa) });
                }
                for (rd.committed) |e| {
                    if (e.kind == .command) try c.applied[i].append(c.gpa, try c.gpa.dupe(u8, e.data));
                }
                try node.advance();
            }
        }

        /// Deliver every frame in flight (and what they cause) until quiet.
        fn deliver(c: *Self) !void {
            while (c.net.items.len > 0) {
                const f = c.net.orderedRemove(0);
                defer c.gpa.free(f.bytes);
                if (c.cut[f.from] or c.cut[f.to]) continue;
                const node = if (c.nodes[f.to]) |*x| x else continue;
                try node.stepBytes(f.from, f.bytes);
                try c.drain(f.to);
            }
        }

        fn tickAll(c: *Self, times: usize) !void {
            for (0..times) |_| {
                for (0..n) |i| {
                    const node = if (c.nodes[i]) |*x| x else continue;
                    try node.tick();
                    try c.drain(@intCast(i));
                }
                try c.deliver();
            }
        }

        fn leaderId(c: *const Self) ?NodeId {
            var found: ?NodeId = null;
            for (c.nodes, 0..) |m, i| {
                const x = m orelse continue;
                if (x.role == .leader and !c.cut[i]) found = @intCast(i);
            }
            return found;
        }
    };
}

test "a three-node cluster elects, replicates and applies on every node" {
    var c = try Cluster(3).init(testing.allocator);
    defer c.deinit();
    try c.tickAll(12);
    const l = c.leaderId() orelse return error.NoLeader;
    try testing.expectEqual(@as(NodeId, 0), l);

    _ = try c.nodes[l].?.propose("a=1");
    _ = try c.nodes[l].?.propose("b=2");
    try c.drain(l);
    try c.deliver();
    // No tick: the commit advance is broadcast at once, not left for the
    // next heartbeat.
    for (c.nodes) |m| try testing.expectEqual(c.nodes[l].?.commit, m.?.commit);
    try c.tickAll(3);

    for (c.applied) |a| {
        try testing.expectEqual(@as(usize, 2), a.items.len);
        try testing.expectEqualStrings("a=1", a.items[0]);
        try testing.expectEqualStrings("b=2", a.items[1]);
    }
    // Every node persisted exactly its log.
    for (c.nodes, c.disks) |m, d| try testing.expectEqual(m.?.lastIndex(), d.entries.items.len);
}

test "a single-node cluster elects itself and commits only after advance" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 1, .election_ticks = 3, .election_jitter_ticks = 0, .seed = 1 }, .{});
    defer node.deinit();
    for (0..3) |_| try node.tick();
    try testing.expectEqual(Role.leader, node.role);
    const idx = try node.propose("x");

    // The first Ready asks for the no-op and "x" to be persisted, and commits
    // NOTHING: the leader's own copies are not durable yet.
    var rd = try node.ready();
    try testing.expectEqual(@as(usize, 2), rd.entries.len);
    try testing.expectEqual(@as(usize, 0), rd.committed.len);
    try testing.expectEqual(@as(Term, 1), rd.hard_state.?.term);
    try node.advance();

    // Now they are, and a majority of one holds them.
    rd = try node.ready();
    try testing.expectEqual(@as(usize, 2), rd.committed.len);
    try testing.expectEqual(idx, rd.committed[1].index);
    try testing.expectEqualStrings("x", rd.committed[1].data);
    try node.advance();
    try testing.expect(!node.hasReady());
}

test "the leader counts its own entry toward a majority only once advance confirms it durable" {
    const gpa = testing.allocator;
    var c = try Cluster(3).init(gpa);
    defer c.deinit();
    try c.tickAll(12);
    const l = c.leaderId().?;
    const leader = &c.nodes[l].?;
    const idx = try leader.propose("p");
    // Appended, not persisted: the leader's own slot does not move...
    try testing.expect(leader.match[l] < idx);
    const rd = try leader.ready();
    try testing.expectEqual(idx, rd.entries[rd.entries.len - 1].index);
    // ...nor while the caller is still writing it...
    try testing.expect(leader.match[l] < idx);
    try c.disks[l].persist(gpa, rd);
    try leader.advance();
    // ...only now.
    try testing.expectEqual(idx, leader.match[l]);
}

test "a crashed follower restarts from its disk alone and catches up" {
    var c = try Cluster(3).init(testing.allocator);
    defer c.deinit();
    try c.tickAll(12);
    const l = c.leaderId().?;
    _ = try c.nodes[l].?.propose("one");
    try c.drain(l);
    try c.deliver();
    try c.tickAll(3);

    c.crash(2);
    _ = try c.nodes[l].?.propose("two");
    _ = try c.nodes[l].?.propose("three");
    try c.drain(l);
    try c.deliver();
    try c.tickAll(3);

    try c.start(2);
    try testing.expectEqual(@as(LogIndex, 2), c.nodes[2].?.lastIndex()); // no-op + "one", from disk
    try testing.expectEqual(@as(LogIndex, 0), c.nodes[2].?.commit); // commit is volatile
    try c.tickAll(4);
    // The state machine was rebuilt from the log as the commit index came back.
    try testing.expectEqual(@as(usize, 3), c.applied[2].items.len);
    try testing.expectEqualStrings("three", c.applied[2].items[2]);
}

test "a deposed leader's uncommitted tail is truncated, and the truncation reaches the disk" {
    var c = try Cluster(3).init(testing.allocator);
    defer c.deinit();
    try c.tickAll(12);
    try testing.expectEqual(@as(?NodeId, 0), c.leaderId());

    // Partition the leader away; it keeps accepting proposals nobody gets.
    c.cut[0] = true;
    _ = try c.nodes[0].?.propose("lost-1");
    _ = try c.nodes[0].?.propose("lost-2");
    try c.drain(0);
    try c.deliver();
    try testing.expectEqual(@as(usize, 3), c.disks[0].entries.items.len); // no-op + the two lost ones

    try c.tickAll(30);
    const l = c.leaderId().?;
    try testing.expect(l != 0);
    _ = try c.nodes[l].?.propose("kept");
    try c.drain(l);
    try c.deliver();

    c.cut[0] = false;
    try c.tickAll(10);
    try testing.expectEqual(Role.follower, c.nodes[0].?.role);
    // Node 0's disk lost the stale tail and holds the new leader's log.
    for (c.disks[0].entries.items) |e| {
        try testing.expect(!std.mem.eql(u8, e.data, "lost-1") and !std.mem.eql(u8, e.data, "lost-2"));
    }
    try testing.expectEqual(c.nodes[l].?.lastIndex(), c.disks[0].entries.items.len);
    try testing.expectEqualStrings("kept", c.applied[0].items[c.applied[0].items.len - 1]);
}

/// A node 0 that has won term 1 in a three-node cluster, with `extra`
/// command entries persisted after its no-op.
fn testLeader(gpa: Allocator, extra: usize) !Node {
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0 }, .{});
    errdefer node.deinit();
    for (0..2) |_| try node.tick();
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = 1, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
    // Its own no-op is appended, not yet durable: it must not count yet.
    try testing.expect(node.match[0] < node.lastIndex());
    for (0..extra) |_| _ = try node.propose("x");
    _ = try node.ready();
    try node.advance();
    return node;
}

// ── hostile-peer limits: byte cap and in-flight window (SPEC Backlog 10) ────

/// `testLeader` with a caller's config (id 0 of 3, term 1; `extra` one-byte
/// commands after the no-op, all persisted).
fn testLeaderCfg(gpa: Allocator, cfg: Config, extra: usize) !Node {
    var node = try Node.init(gpa, cfg, .{});
    errdefer node.deinit();
    while (node.role != .candidate) try node.tick();
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = node.term, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
    for (0..extra) |_| _ = try node.propose("x");
    _ = try node.ready();
    try node.advance();
    return node;
}

fn limitCfg() Config {
    return .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0 };
}

/// Entry counts of the AppendEntries queued for `to` since `from_msg`.
fn batchesTo(node: *const Node, to: NodeId, from_msg: usize, out: []usize) []usize {
    var n: usize = 0;
    for (node.msgs.items[from_msg..]) |m| {
        if (m.to != to or m.body != .append_req) continue;
        out[n] = m.body.append_req.entries.len;
        n += 1;
    }
    return out[0..n];
}

test "byte cap, follower: an AppendEntries AT the cap is applied, one byte over is dropped before any state moves" {
    const gpa = testing.allocator;
    const H = Message.entry_header_len;
    var cfg: Config = .{ .id = 1, .cluster_size = 3, .seed = 1, .max_append_bytes = 2 * H + 10 };
    var node = try Node.init(gpa, cfg, .{});
    defer node.deinit();
    try testing.expectEqual(Message.append_header_len + 2 * H + 10, node.maxFrameLen());

    const over = [_]Entry{ .{ .index = 1, .term = 1, .data = "abcdef" }, .{ .index = 2, .term = 1, .data = "fghij" } };
    const at = [_]Entry{ .{ .index = 1, .term = 1, .data = "abcde" }, .{ .index = 2, .term = 1, .data = "fghij" } };
    var buf: [128]u8 = undefined;
    // cap + 1, through the wire (the frame is maxFrameLen() + 1 and decodes fine).
    const m_over: Message = .{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 1, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &over } } };
    try testing.expectEqual(node.maxFrameLen() + 1, m_over.encodedLen());
    try node.stepBytes(0, buf[0..m_over.encode(&buf)]);
    try testing.expectEqual(@as(u64, 1), node.malformed_dropped);
    try testing.expectEqual(@as(LogIndex, 0), node.lastIndex());
    try testing.expectEqual(@as(Term, 0), node.term); // not even the term moved
    try testing.expect(!node.hasReady()); // and no reply
    // At the cap: accepted and acknowledged.
    const m_at: Message = .{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 1, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &at } } };
    try testing.expectEqual(node.maxFrameLen(), m_at.encodedLen());
    try node.stepBytes(0, buf[0..m_at.encode(&buf)]);
    try testing.expectEqual(@as(u64, 1), node.malformed_dropped);
    try testing.expectEqual(@as(LogIndex, 2), node.lastIndex());
    try testing.expect(node.msgs.items[0].body.append_resp.success);

    // The default is etcd's server value.
    cfg = .{ .id = 0, .cluster_size = 1, .seed = 0 };
    try testing.expectEqual(@as(u32, 1 << 20), cfg.max_append_bytes);
    try testing.expectEqual(@as(u32, 512), cfg.max_inflight_msgs);
    try testing.expectEqual(@as(u64, 0), cfg.max_inflight_bytes);
}

test "byte cap, leader: batches stop at the cap, and an entry above it goes alone" {
    const gpa = testing.allocator;
    const H = Message.entry_header_len;
    // Log: no-op (H bytes), then one-byte commands (H + 1 each).
    for ([_]struct { cap: u32, want: usize }{
        .{ .cap = 3 * H + 2, .want = 3 }, // exactly no-op + two commands
        .{ .cap = 3 * H + 1, .want = 2 }, // one byte short of the third
    }) |c| {
        var cfg = limitCfg();
        cfg.max_append_bytes = c.cap;
        var node = try testLeaderCfg(gpa, cfg, 9);
        defer node.deinit();
        node.next[1] = 1;
        node.infl_count[1] = 0;
        node.infl_bytes[1] = 0;
        const from = node.msgs.items.len;
        try node.sendAppend(1);
        var out: [4]usize = undefined;
        try testing.expectEqualSlices(usize, &.{c.want}, batchesTo(&node, 1, from, &out));
    }
    // A restored entry larger than the cap is still sent, alone (etcd's
    // `limitSize`), rather than never.
    const big = "012345678901234567890123456789";
    const ents = [_]Entry{ .{ .index = 1, .term = 1, .data = big }, .{ .index = 2, .term = 1, .data = "y" } };
    var cfg = limitCfg();
    cfg.max_append_bytes = H + 2;
    var node = try Node.init(gpa, cfg, .{ .hard_state = .{ .term = 1 }, .entries = &ents });
    defer node.deinit();
    while (node.role != .candidate) try node.tick();
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = node.term, .granted = true } } });
    node.next[1] = 1;
    const from = node.msgs.items.len;
    try node.sendAppend(1);
    var out: [4]usize = undefined;
    try testing.expectEqualSlices(usize, &.{1}, batchesTo(&node, 1, from, &out));
}

test "byte cap, propose: the largest entry one AppendEntries can carry is accepted, one byte more refused" {
    const gpa = testing.allocator;
    var cfg = limitCfg();
    cfg.max_append_bytes = Message.entry_header_len + 8;
    var node = try testLeaderCfg(gpa, cfg, 0);
    defer node.deinit();
    _ = try node.propose("12345678");
    try testing.expectError(error.EntryTooLarge, node.propose("123456789"));
}

test "limits: init refuses a cap no no-op fits in, an empty window, a byte window below one message" {
    const gpa = testing.allocator;
    const H = Message.entry_header_len;
    var cfg = limitCfg();
    cfg.max_append_bytes = H - 1;
    try testing.expectError(error.InvalidConfig, Node.init(gpa, cfg, .{}));
    cfg.max_append_bytes = H;
    var ok = try Node.init(gpa, cfg, .{});
    ok.deinit();
    cfg = limitCfg();
    cfg.max_inflight_msgs = 0;
    try testing.expectError(error.InvalidConfig, Node.init(gpa, cfg, .{}));
    cfg = limitCfg();
    cfg.max_append_bytes = 100;
    cfg.max_inflight_bytes = 99;
    try testing.expectError(error.InvalidConfig, Node.init(gpa, cfg, .{}));
    cfg.max_inflight_bytes = 100;
    ok = try Node.init(gpa, cfg, .{});
    ok.deinit();
}

test "in-flight window: at the cap the leader sends heartbeats only; acks free it, a rejection empties it" {
    const gpa = testing.allocator;
    var cfg = limitCfg();
    cfg.max_inflight_msgs = 2;
    cfg.max_append_entries = 4;
    var node = try testLeaderCfg(gpa, cfg, 19); // log 1..20
    defer node.deinit();
    node.next[1] = 1;
    node.infl_count[1] = 0;
    node.infl_bytes[1] = 0;
    var out: [8]usize = undefined;

    // Two unacknowledged batches fill the window; the third send is a heartbeat.
    var from = node.msgs.items.len;
    for (0..3) |_| try node.sendAppend(1);
    try testing.expectEqualSlices(usize, &.{ 4, 4, 0 }, batchesTo(&node, 1, from, &out));
    // Heartbeats do not count: still exactly two in flight.
    try testing.expectEqual(@as(u32, 2), node.infl_count[1]);

    // An ack covering both (they carried 1..4) frees both, and the stream
    // moves on with a full batch.
    from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 4 } } });
    try testing.expectEqualSlices(usize, &.{4}, batchesTo(&node, 1, from, &out));
    try testing.expectEqual(@as(u32, 1), node.infl_count[1]);

    // Fill it again; an ack that covers NOTHING in flight (a heartbeat's)
    // frees the oldest — a lost batch must not wedge the window — and sends
    // nothing by itself.
    try node.sendAppend(1);
    try testing.expectEqual(@as(u32, 2), node.infl_count[1]);
    from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 4 } } });
    try testing.expectEqual(@as(u32, 1), node.infl_count[1]);
    try testing.expectEqual(@as(usize, 0), batchesTo(&node, 1, from, &out).len);
    try node.sendAppend(1);
    try testing.expectEqual(@as(u32, 2), node.infl_count[1]);

    // An ack that PROGRESSES but covers none of the in-flight batches (they
    // carry 5..8; it confirms 6) frees nothing: the window stays full and the
    // stream continues with a heartbeat (etcd frees one slot only on a
    // heartbeat response, never on an append progress).
    from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 6 } } });
    try testing.expectEqual(@as(LogIndex, 6), node.match[1]);
    try testing.expectEqual(@as(u32, 2), node.infl_count[1]);
    try testing.expectEqualSlices(usize, &.{0}, batchesTo(&node, 1, from, &out));

    // A rejection empties it (the follower goes back to probing).
    node.next[1] = 9;
    from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 6 } } });
    try testing.expectEqualSlices(usize, &.{4}, batchesTo(&node, 1, from, &out)); // the retry
    try testing.expectEqual(@as(u32, 1), node.infl_count[1]);
}

test "in-flight window in bytes: acks and a rejection give the bytes back, not only the slots" {
    const gpa = testing.allocator;
    const H = Message.entry_header_len;
    const batch: u64 = 2 * H + 1; // no-op + one command
    var cfg = limitCfg();
    cfg.max_append_bytes = 2 * H + 1;
    cfg.max_inflight_bytes = 2 * batch;
    var node = try testLeaderCfg(gpa, cfg, 9);
    defer node.deinit();
    var out: [4]usize = undefined;
    const reset = struct {
        fn f(nd: *Node) void {
            nd.next[1] = 1;
            nd.match[1] = 0;
            nd.infl_count[1] = 0;
            nd.infl_bytes[1] = 0;
        }
    }.f;

    // Full by bytes; an ack covering both frees their bytes, so the stream
    // goes on with a batch (one command: two would be over the cap), not a
    // heartbeat.
    reset(&node);
    for (0..2) |_| try node.sendAppend(1);
    try testing.expect(node.inflFull(1));
    var from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 2 } } });
    try testing.expectEqualSlices(usize, &.{1}, batchesTo(&node, 1, from, &out));
    try testing.expectEqual(@as(u64, H + 1), node.infl_bytes[1]);

    // Full by bytes; a rejection empties the bytes too, so the retry carries entries.
    reset(&node);
    for (0..2) |_| try node.sendAppend(1);
    node.next[1] = 3;
    from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 0 } } });
    try testing.expectEqualSlices(usize, &.{2}, batchesTo(&node, 1, from, &out));
}

test "in-flight window in bytes: full at the cap, not one byte below it" {
    const gpa = testing.allocator;
    const H = Message.entry_header_len;
    // Batch from index 1: the no-op and one command, 2H + 1 bytes.
    const batch: u64 = 2 * H + 1;
    for ([_]struct { cap: u64, third: usize }{
        .{ .cap = 2 * batch, .third = 0 }, // two batches reach the cap: heartbeat
        .{ .cap = 2 * batch + 1, .third = 2 }, // one byte of room left: a batch
    }) |c| {
        var cfg = limitCfg();
        cfg.max_append_bytes = 2 * H + 1;
        cfg.max_inflight_bytes = c.cap;
        var node = try testLeaderCfg(gpa, cfg, 9);
        defer node.deinit();
        node.next[1] = 1;
        node.infl_count[1] = 0;
        node.infl_bytes[1] = 0;
        const from = node.msgs.items.len;
        for (0..3) |_| try node.sendAppend(1);
        var out: [4]usize = undefined;
        try testing.expectEqualSlices(usize, &.{ 2, 2, c.third }, batchesTo(&node, 1, from, &out));
    }
}

test "a new leader starts every follower's window empty" {
    const gpa = testing.allocator;
    var cfg = limitCfg();
    cfg.max_inflight_msgs = 1;
    var node = try testLeaderCfg(gpa, cfg, 3);
    defer node.deinit();
    try testing.expectEqual(@as(u32, 1), node.infl_count[1]); // the election's first batch
    // Deposed, then elected again in a later term.
    try node.step(.{ .from = 2, .to = 0, .body = .{ .vote_resp = .{ .term = 5, .granted = false } } });
    while (node.role != .candidate) try node.tick();
    node.infl_count[1] = 1; // a stale count from the earlier term must not survive
    node.infl_bytes[1] = 77;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = node.term, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
    // becomeLeader's broadcast found the window empty: it carried entries.
    const last = node.msgs.items[node.msgs.items.len - 2]; // to 1, then to 2
    try testing.expectEqual(@as(NodeId, 1), last.to);
    try testing.expect(last.body.append_req.entries.len > 0);

    // The same for the byte window: stale bytes alone would keep it full.
    cfg = limitCfg();
    cfg.max_append_bytes = 64;
    cfg.max_inflight_bytes = 64;
    var b = try testLeaderCfg(gpa, cfg, 0);
    defer b.deinit();
    try b.step(.{ .from = 2, .to = 0, .body = .{ .vote_resp = .{ .term = 5, .granted = false } } });
    while (b.role != .candidate) try b.tick();
    b.infl_count[1] = 0;
    b.infl_bytes[1] = 64;
    try b.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = b.term, .granted = true } } });
    const first = b.msgs.items[b.msgs.items.len - 2];
    try testing.expectEqual(@as(NodeId, 1), first.to);
    try testing.expect(first.body.append_req.entries.len > 0);
}

// ── PreVote and CheckQuorum (SPEC Backlog 7) ────────────────────────────────

fn pvCfg(id: NodeId) Config {
    return .{ .id = id, .cluster_size = 3, .election_ticks = 4, .election_jitter_ticks = 0, .seed = id, .pre_vote = true };
}

/// The messages `node` queued since `from` with body tag `tag`.
fn countTag(node: *const Node, from: usize, tag: message.Tag) usize {
    var n: usize = 0;
    for (node.msgs.items[from..]) |m| n += @intFromBool(m.body == tag);
    return n;
}

test "PreVote: a timeout makes a pre-candidate — term, vote and hard state do not move" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, pvCfg(0), .{ .hard_state = .{ .term = 3, .voted_for = 2 } });
    defer node.deinit();
    for (0..3) |_| try node.tick();
    try testing.expectEqual(Role.follower, node.role);
    try node.tick();
    try testing.expectEqual(Role.pre_candidate, node.role);
    try testing.expectEqual(@as(Term, 3), node.term);
    try testing.expectEqual(@as(NodeId, 2), node.voted_for);
    const rd = try node.ready();
    try testing.expect(rd.hard_state == null); // nothing to persist
    try testing.expectEqual(@as(usize, 2), rd.messages.len);
    for (rd.messages) |m| {
        try testing.expectEqual(message.Tag.pre_vote_req, std.meta.activeTag(m.body));
        try testing.expectEqual(@as(Term, 4), m.body.pre_vote_req.term); // the term it WOULD take
    }
    try node.advance();
    // Without a majority it times out again — still a pre-candidate, still term 3.
    for (0..4) |_| try node.tick();
    try testing.expectEqual(Role.pre_candidate, node.role);
    try testing.expectEqual(@as(Term, 3), node.term);

    // Off (the default): the same timeout is a real election.
    var plain = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 4, .election_jitter_ticks = 0, .seed = 0 }, .{ .hard_state = .{ .term = 3 } });
    defer plain.deinit();
    try testing.expect(!plain.cfg.pre_vote and !plain.cfg.check_quorum);
    for (0..4) |_| try plain.tick();
    try testing.expectEqual(Role.candidate, plain.role);
    try testing.expectEqual(@as(Term, 4), plain.term);
}

test "PreVote: a majority of grants starts the real election; stale grants and same-term refusals do not" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, pvCfg(0), .{ .hard_state = .{ .term = 3 } });
    defer node.deinit();
    for (0..4) |_| try node.tick();
    try testing.expectEqual(Role.pre_candidate, node.role);
    // A grant for another prospective term (an older pre-campaign's) counts nothing.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 3, .granted = true } } });
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 5, .granted = true } } });
    // A refusal at our own term moves nothing either.
    try node.step(.{ .from = 2, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 3, .granted = false } } });
    try testing.expectEqual(Role.pre_candidate, node.role);
    try testing.expectEqual(@as(Term, 3), node.term);
    // A real grant from node 1: two of three — the election proper starts.
    const from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 4, .granted = true } } });
    try testing.expectEqual(Role.candidate, node.role);
    try testing.expectEqual(@as(Term, 4), node.term);
    try testing.expectEqual(@as(NodeId, 0), node.voted_for);
    try testing.expectEqual(@as(usize, 2), countTag(&node, from, .vote_req));
    // A pre-vote grant reaching a node that is no longer a pre-candidate is ignored.
    try node.step(.{ .from = 2, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 5, .granted = true } } });
    try testing.expectEqual(Role.candidate, node.role);
    try testing.expectEqual(@as(Term, 4), node.term);
}

test "PreVote: a refusal from a higher term is adopted; a single-node cluster elects itself" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, pvCfg(0), .{ .hard_state = .{ .term = 3 } });
    defer node.deinit();
    for (0..4) |_| try node.tick();
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 9, .granted = false } } });
    try testing.expectEqual(Role.follower, node.role);
    try testing.expectEqual(@as(Term, 9), node.term);

    var solo = try Node.init(gpa, .{ .id = 0, .cluster_size = 1, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0, .pre_vote = true }, .{});
    defer solo.deinit();
    for (0..2) |_| try solo.tick();
    try testing.expectEqual(Role.leader, solo.role);
    try testing.expectEqual(@as(Term, 1), solo.term);

    // At max_term there is no term + 1 to ask for.
    var top = try Node.init(gpa, pvCfg(0), .{ .hard_state = .{ .term = types.max_term } });
    defer top.deinit();
    for (0..8) |_| try top.tick();
    try testing.expectEqual(Role.follower, top.role);
    try testing.expect(!top.hasReady());
}

/// The single `pre_vote_resp` `node` queued since `from`.
fn lastPreVoteResp(node: *const Node, from: usize) !message.VoteResp {
    try testing.expectEqual(from + 1, node.msgs.items.len);
    return node.msgs.items[from].body.pre_vote_resp;
}

test "PreVote receiver: grants only an up-to-date log with no live leader, and never moves its term, vote or timer" {
    const gpa = testing.allocator;
    const ents = [_]Entry{ .{ .index = 1, .term = 1 }, .{ .index = 2, .term = 2 } };
    var f = try Node.init(gpa, pvCfg(1), .{ .hard_state = .{ .term = 2, .voted_for = 2 }, .entries = &ents });
    defer f.deinit();
    try f.tick();
    try testing.expectEqual(@as(u32, 1), f.election_elapsed);

    // Up to date (same last entry), future term: granted, with the request's term.
    var from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 2, .last_log_term = 2 } } });
    var r = try lastPreVoteResp(&f, from);
    try testing.expect(r.granted);
    try testing.expectEqual(@as(Term, 3), r.term);
    try testing.expectEqual(@as(Term, 2), f.term); // not adopted
    try testing.expectEqual(@as(NodeId, 2), f.voted_for); // not recorded
    try testing.expectEqual(@as(u32, 1), f.election_elapsed); // timer not reset
    try testing.expect(!f.hs_dirty);

    // One entry short: refused, with our term.
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 1, .last_log_term = 1 } } });
    r = try lastPreVoteResp(&f, from);
    try testing.expect(!r.granted);
    try testing.expectEqual(@as(Term, 2), r.term);
    // Longer but older last term: refused (§5.4.1, term first).
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 9, .last_log_term = 1 } } });
    try testing.expect(!(try lastPreVoteResp(&f, from)).granted);
    // Same term as ours, and we already voted for someone else: refused.
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 2, .last_log_index = 2, .last_log_term = 2 } } });
    try testing.expect(!(try lastPreVoteResp(&f, from)).granted);
    // …but a repeat from the node we voted for is granted (etcd's canVote).
    from = f.msgs.items.len;
    try f.step(.{ .from = 2, .to = 1, .body = .{ .pre_vote_req = .{ .term = 2, .last_log_index = 2, .last_log_term = 2 } } });
    try testing.expect((try lastPreVoteResp(&f, from)).granted);
    // An older term: refused.
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 1, .last_log_index = 2, .last_log_term = 2 } } });
    try testing.expect(!(try lastPreVoteResp(&f, from)).granted);

    // A leader of term 2 is heard from: it is live, so an up-to-date
    // pre-vote is refused — until a full election_ticks pass without it.
    try f.step(.{ .from = 2, .to = 1, .body = .{ .append_req = .{ .term = 2, .prev_log_index = 2, .prev_log_term = 2, .leader_commit = 0, .entries = &.{} } } });
    try testing.expectEqual(@as(NodeId, 2), f.leader);
    for (0..3) |_| try f.tick(); // 3 < election_ticks (4)
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 2, .last_log_term = 2 } } });
    try testing.expect(!(try lastPreVoteResp(&f, from)).granted);
    try testing.expectEqual(@as(Term, 2), f.term);
    var off = f.cfg; // a node of a cluster without pre_vote answers the same way
    off.pre_vote = false;
    f.cfg = off;
    f.election_elapsed = f.cfg.election_ticks; // the leader went quiet for a full timeout
    from = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 2, .last_log_term = 2 } } });
    try testing.expect((try lastPreVoteResp(&f, from)).granted);
}

test "PreVote receiver: a live leader refuses a pre-vote" {
    const gpa = testing.allocator;
    // (A pre-vote is answered the same whatever the receiver's own `pre_vote`.)
    var node = try testLeaderCfg(gpa, limitCfg(), 0);
    defer node.deinit();
    for (0..10) |_| try node.tick(); // no CheckQuorum: leadership never lapses
    const from = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_req = .{ .term = node.term + 1, .last_log_index = 99, .last_log_term = node.term } } });
    const r = node.msgs.items[node.msgs.items.len - 1].body.pre_vote_resp;
    try testing.expect(node.msgs.items.len == from + 1);
    try testing.expect(!r.granted);
    try testing.expectEqual(Role.leader, node.role);
}

fn cqCfg() Config {
    var c = limitCfg();
    c.election_ticks = 4;
    c.check_quorum = true;
    return c;
}

test "CheckQuorum: a leader with no acks steps down at election_ticks, not one tick before" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, cqCfg(), 0);
    defer node.deinit();
    const term = node.term;
    for (0..3) |_| try node.tick();
    try testing.expectEqual(Role.leader, node.role);
    try node.tick();
    try testing.expectEqual(Role.follower, node.role);
    try testing.expectEqual(term, node.term); // same term, nothing to persist
    try testing.expectEqual(no_vote, node.leader);

    // Off: the same silence never deposes it.
    var plain = try testLeaderCfg(gpa, limitCfg(), 0);
    defer plain.deinit();
    for (0..40) |_| try plain.tick();
    try testing.expectEqual(Role.leader, plain.role);
}

test "CheckQuorum: one ack per period keeps a 3-node leader; the activity is reset every period" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, cqCfg(), 0);
    defer node.deinit();
    const ack: Message = .{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = node.term, .success = true, .index = 1 } } };
    for (0..5) |_| {
        try node.step(ack); // node 1 + the leader = a majority of 3
        for (0..4) |_| try node.tick();
        try testing.expectEqual(Role.leader, node.role);
    }
    // A refusal is activity too (etcd: any MsgAppResp).
    try node.step(.{ .from = 2, .to = 0, .body = .{ .append_resp = .{ .term = node.term, .success = false, .index = 0 } } });
    for (0..4) |_| try node.tick();
    try testing.expectEqual(Role.leader, node.role);
    // An ack from an older term is not.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = node.term - 1, .success = true, .index = 1 } } });
    // A period with no ack: the previous period's activity does not carry over.
    for (0..3) |_| try node.tick();
    try testing.expectEqual(Role.leader, node.role);
    try node.tick();
    try testing.expectEqual(Role.follower, node.role);
}

test "CheckQuorum lease: inside it a higher-term RequestVote or PreVote is ignored outright; after it, it is answered" {
    const gpa = testing.allocator;
    for ([_]bool{ true, false }) |cq| {
        var cfg = limitCfg();
        cfg.id = 1;
        cfg.election_ticks = 4;
        cfg.check_quorum = cq;
        var f = try Node.init(gpa, cfg, .{ .hard_state = .{ .term = 2 } });
        defer f.deinit();
        try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 2, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &.{} } } });
        _ = try f.ready();
        try f.advance();
        for (0..3) |_| try f.tick();
        try f.step(.{ .from = 2, .to = 1, .body = .{ .vote_req = .{ .term = 7, .last_log_index = 5, .last_log_term = 2 } } });
        if (cq) {
            try testing.expectEqual(@as(Term, 2), f.term);
            try testing.expectEqual(no_vote, f.voted_for);
            try testing.expectEqual(@as(usize, 0), f.msgs.items.len); // no reply at all
            try f.step(.{ .from = 2, .to = 1, .body = .{ .pre_vote_req = .{ .term = 7, .last_log_index = 5, .last_log_term = 2 } } });
            try testing.expectEqual(@as(usize, 0), f.msgs.items.len);
            // The lease ends with the election timeout: then the vote is granted.
            f.election_elapsed = f.cfg.election_ticks;
            try f.step(.{ .from = 2, .to = 1, .body = .{ .vote_req = .{ .term = 7, .last_log_index = 5, .last_log_term = 2 } } });
            try testing.expectEqual(@as(Term, 7), f.term);
            try testing.expectEqual(@as(NodeId, 2), f.voted_for);
        } else {
            // Without CheckQuorum (the default) Raft as before: adopted and granted.
            try testing.expectEqual(@as(Term, 7), f.term);
            try testing.expectEqual(@as(NodeId, 2), f.voted_for);
        }
    }
    // A leader with CheckQuorum is inside its own lease.
    var l = try testLeaderCfg(gpa, cqCfg(), 0);
    defer l.deinit();
    const before = l.msgs.items.len;
    try l.step(.{ .from = 1, .to = 0, .body = .{ .vote_req = .{ .term = l.term + 5, .last_log_index = 99, .last_log_term = l.term } } });
    try testing.expectEqual(Role.leader, l.role);
    try testing.expectEqual(before, l.msgs.items.len);
}

test "a rejection's hint skips the follower's gap in one round trip, but never below its match" {
    const gpa = testing.allocator;
    var node = try testLeader(gpa, 19);
    defer node.deinit();
    try testing.expectEqual(@as(LogIndex, 20), node.lastIndex());

    // The leader believes node 1 is caught up; node 1 holds two entries.
    node.next[1] = 21;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 2 } } });
    try testing.expectEqual(@as(LogIndex, 3), node.next[1]); // one round trip, not eighteen
    // The retry went out at once, from the new nextIndex.
    const retry = node.msgs.items[node.msgs.items.len - 1].body.append_req;
    try testing.expectEqual(@as(LogIndex, 2), retry.prev_log_index);

    // A stale rejection arriving after node 1 confirmed index 10 cannot pull
    // nextIndex below 11.
    node.match[1] = 10;
    node.next[1] = 15;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 2 } } });
    try testing.expectEqual(@as(LogIndex, 11), node.next[1]);
    // Without a useful hint it walks back by one.
    node.next[1] = 15;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 20 } } });
    try testing.expectEqual(@as(LogIndex, 14), node.next[1]);
    // A rejection that cannot move it (already at match + 1) sends nothing:
    // the heartbeat retries, not a reply-driven loop.
    node.next[1] = 11;
    const before = node.msgs.items.len;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 2 } } });
    try testing.expectEqual(@as(LogIndex, 11), node.next[1]);
    try testing.expectEqual(before, node.msgs.items.len);
}

/// Drive a leader (term 201, log of 8 terms x 25 entries) against one
/// follower holding a 300-entry divergent tail, delivering frames directly;
/// returns the rejections the follower sent before the logs matched.
/// `strip_hint` removes the conflict-term hint, i.e. a legacy follower.
fn divergentRoundTrips(gpa: Allocator, strip_hint: bool) !usize {
    var lent: [200]Entry = undefined;
    for (&lent, 0..) |*e, i| e.* = .{ .index = i + 1, .term = 1 + i / 25 };
    var fent: [350]Entry = undefined;
    // Shares indices 1..50 (terms 1, 2) with the leader, then 10 own terms.
    for (&fent, 0..) |*e, i| e.* = .{ .index = i + 1, .term = if (i < 50) 1 + i / 25 else 90 + (i - 50) / 30 };
    var leader = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0, .max_append_entries = 8 }, .{ .hard_state = .{ .term = 200 }, .entries = &lent });
    defer leader.deinit();
    var follower = try Node.init(gpa, .{ .id = 1, .cluster_size = 3, .election_ticks = 1000, .election_jitter_ticks = 0, .seed = 1 }, .{ .hard_state = .{ .term = 99 }, .entries = &fent });
    defer follower.deinit();
    for (0..2) |_| try leader.tick();
    try leader.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = 201, .granted = true } } });
    try testing.expectEqual(Role.leader, leader.role);

    var rejections: usize = 0;
    var rounds: usize = 0;
    while (leader.match[1] < leader.lastIndex()) : (rounds += 1) {
        try testing.expect(rounds < 1000);
        var frames: std.ArrayList([]u8) = .empty;
        defer {
            for (frames.items) |f| gpa.free(f);
            frames.deinit(gpa);
        }
        const rd = try leader.ready();
        for (rd.messages) |m| if (m.to == 1 and m.body == .append_req) try frames.append(gpa, try m.encodeAlloc(gpa));
        try leader.advance();
        for (frames.items) |f| {
            try follower.stepBytes(0, f);
            const frd = try follower.ready();
            for (frd.messages) |m| {
                if (m.body != .append_resp) continue;
                if (!m.body.append_resp.success) rejections += 1;
                var reply = m;
                if (strip_hint) {
                    reply.body.append_resp.conflict_index = 0;
                    reply.body.append_resp.conflict_term = 0;
                }
                const bytes = try reply.encodeAlloc(gpa);
                defer gpa.free(bytes);
                try leader.stepBytes(1, bytes);
            }
            try follower.advance();
        }
    }
    try testing.expectEqual(leader.lastIndex(), follower.lastIndex());
    for (1..leader.lastIndex() + 1) |i| try testing.expectEqual(leader.log.termAt(i), follower.log.termAt(i));
    return rejections;
}

test "conflict-term hint: a long divergent tail converges in O(terms) round trips, not O(tail)" {
    const with_hint = try divergentRoundTrips(testing.allocator, false);
    const legacy = try divergentRoundTrips(testing.allocator, true);
    // 10 follower terms to skip, plus the probe that finds the shared prefix.
    try testing.expect(with_hint <= 12);
    // A follower without the hint (index-gap hint only) walks back one entry
    // per round trip, past the leader's whole divergent tail.
    try testing.expect(legacy > 100);
}

test "conflict-term hint: leader uses its own last entry of the conflicting term" {
    const gpa = testing.allocator;
    var node = try testLeader(gpa, 19); // 20 entries, all term 1
    defer node.deinit();
    node.next[1] = 21;
    // The follower says its entry at the probe has term 1, first at index 4:
    // the leader has term 1 through index 20, so it resumes at 21... which
    // cannot be higher than next - 1, so it steps back by one.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 50, .conflict_term = 1, .conflict_index = 4 } } });
    try testing.expectEqual(@as(LogIndex, 20), node.next[1]);
    // A conflict term the leader lacks: resume at the follower's first index of it.
    node.next[1] = 20;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 50, .conflict_term = 7, .conflict_index = 6 } } });
    try testing.expectEqual(@as(LogIndex, 6), node.next[1]);
    // Past the follower's end (term 0): its length + 1.
    node.next[1] = 20;
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = false, .index = 3, .conflict_term = 0, .conflict_index = 4 } } });
    try testing.expectEqual(@as(LogIndex, 4), node.next[1]);
}

test "conflict-term hint: the follower reports term and first index, or its end" {
    const gpa = testing.allocator;
    const ents = [_]Entry{
        .{ .index = 1, .term = 1 }, .{ .index = 2, .term = 2 }, .{ .index = 3, .term = 2 }, .{ .index = 4, .term = 2 },
    };
    var f = try Node.init(gpa, .{ .id = 1, .cluster_size = 3, .election_ticks = 1000, .election_jitter_ticks = 0, .seed = 1 }, .{ .hard_state = .{ .term = 2 }, .entries = &ents });
    defer f.deinit();
    // prev (4, term 3) mismatches the follower's term 2 at 4: hint = (2, first index of 2 = 2).
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 3, .prev_log_index = 4, .prev_log_term = 3, .leader_commit = 0, .entries = &.{} } } });
    var rd = try f.ready();
    var r = rd.messages[rd.messages.len - 1].body.append_resp;
    try testing.expect(!r.success);
    try testing.expectEqual(@as(Term, 2), r.conflict_term);
    try testing.expectEqual(@as(LogIndex, 2), r.conflict_index);
    try f.advance();
    // prev past the end: no term, one past the last index.
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 3, .prev_log_index = 9, .prev_log_term = 3, .leader_commit = 0, .entries = &.{} } } });
    rd = try f.ready();
    r = rd.messages[rd.messages.len - 1].body.append_resp;
    try testing.expectEqual(@as(Term, 0), r.conflict_term);
    try testing.expectEqual(@as(LogIndex, 5), r.conflict_index);
    try f.advance();
    // A stale leader gets no hint.
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 1, .prev_log_index = 9, .prev_log_term = 1, .leader_commit = 0, .entries = &.{} } } });
    rd = try f.ready();
    r = rd.messages[rd.messages.len - 1].body.append_resp;
    try testing.expectEqual(@as(LogIndex, 0), r.conflict_index);
}

test "H1: a leader deposed before its next ready sends no AppendEntries under the new term" {
    const gpa = testing.allocator;
    // Three ways to step down between `propose` (which schedules a broadcast)
    // and the `ready` that would send it.
    for (0..3) |way| {
        var node = try testLeader(gpa, 3);
        defer node.deinit();
        _ = try node.propose("y");
        switch (way) {
            0 => try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_req = .{ .term = 2, .last_log_index = 0, .last_log_term = 0 } } }),
            1 => try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 2, .success = false, .index = 0 } } }),
            // A new leader's AppendEntries that TRUNCATES this node's own
            // tail — the stale `next[]` would then point past the log.
            else => try node.step(.{ .from = 1, .to = 0, .body = .{ .append_req = .{
                .term = 2,
                .prev_log_index = 1,
                .prev_log_term = 1,
                .leader_commit = 0,
                .entries = &.{.{ .index = 2, .term = 2, .data = "z" }},
            } } }),
        }
        try testing.expectEqual(Role.follower, node.role);
        const rd = try node.ready();
        for (rd.messages) |m| try testing.expect(m.body != .append_req);
        try node.advance();
    }
}

test "a duplicated success ack does not fork a second replication stream" {
    const gpa = testing.allocator;
    var node = try testLeader(gpa, 20);
    defer node.deinit();
    node.msgs.clearRetainingCapacity();
    const ack: Message = .{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 8 } } };
    try node.step(ack);
    try testing.expectEqual(@as(usize, 1), node.msgs.items.len); // progress: stream on
    try node.step(ack);
    try testing.expectEqual(@as(usize, 1), node.msgs.items.len); // duplicate: nothing
    // A stale, smaller ack (reordered) never lowers what node 1 confirmed.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = 3 } } });
    try testing.expectEqual(@as(LogIndex, 8), node.match[1]);
}

test "a candidate counts only grants for ITS term (a late grant from an older candidacy is ignored)" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0 }, .{});
    defer node.deinit();
    for (0..4) |_| try node.tick(); // two elections: now a candidate of term 2
    try testing.expectEqual(@as(Term, 2), node.term);
    try testing.expectEqual(Role.candidate, node.role);
    // Node 1's grant from term 1 arrives late. Counting it would make this a
    // term-2 leader on a ballot nobody cast in term 2.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = 1, .granted = true } } });
    try testing.expectEqual(Role.candidate, node.role);
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = 2, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
}

test "a success reply advertises the VERIFIED prefix, never an unchecked stale tail" {
    const gpa = testing.allocator;
    const tail = [_]Entry{ .{ .index = 1, .term = 1 }, .{ .index = 2, .term = 1 }, .{ .index = 3, .term = 1 } };
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1 }, .entries = &tail });
    defer node.deinit();
    // A term-2 leader checks only index 1..2; index 3 is neither verified nor
    // in conflict, so it stays — and must not be claimed as replicated.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_req = .{
        .term = 2,
        .prev_log_index = 1,
        .prev_log_term = 1,
        .leader_commit = 0,
        .entries = &.{.{ .index = 2, .term = 1 }},
    } } });
    try testing.expectEqual(@as(LogIndex, 3), node.lastIndex());
    const r = node.msgs.items[0].body.append_resp;
    try testing.expect(r.success);
    try testing.expectEqual(@as(LogIndex, 2), r.index);
}

test "granting a vote in the CURRENT term resets the election timer" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1 } });
    defer node.deinit();
    for (0..3) |_| try node.tick();
    try testing.expectEqual(@as(u32, 3), node.election_elapsed);
    // Same term: no step-down resets the timer for us; only the grant does.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_req = .{ .term = 1, .last_log_index = 0, .last_log_term = 0 } } });
    try testing.expectEqual(@as(NodeId, 1), node.voted_for);
    try testing.expectEqual(@as(u32, 0), node.election_elapsed);
}

test "only a leader accepts a proposal" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{});
    defer node.deinit();
    try testing.expectError(error.NotLeader, node.propose("x"));
    try testing.expect(!node.hasReady());
}

test "a node at max_term never starts another term (no overflow, no wrap)" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 0 }, .{
        .hard_state = .{ .term = types.max_term },
    });
    defer node.deinit();
    for (0..10) |_| try node.tick();
    try testing.expectEqual(types.max_term, node.term);
    try testing.expectEqual(Role.follower, node.role);
    try testing.expect(!node.hasReady());
}

test "§5.3: a duplicated AppendEntries never rolls back an applied entry; the naive rule does" {
    const gpa = testing.allocator;
    const es = [_]Entry{
        .{ .index = 1, .term = 1, .data = "1" }, .{ .index = 2, .term = 1, .data = "2" },
        .{ .index = 3, .term = 1, .data = "3" }, .{ .index = 4, .term = 1, .data = "4" },
        .{ .index = 5, .term = 1, .data = "5" },
    };
    const ae1: Message = .{ .from = 1, .to = 0, .body = .{ .append_req = .{ .term = 1, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = es[0..3] } } };
    const ae2: Message = .{ .from = 1, .to = 0, .body = .{ .append_req = .{ .term = 1, .prev_log_index = 3, .prev_log_term = 1, .leader_commit = 5, .entries = es[3..5] } } };

    for ([_]InjectedBug{ .none, .naive_truncation }) |bug| {
        var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{});
        defer node.deinit();
        node.injected_bug = bug;
        // AE#1, AE#2, then AE#1 again, late — netsim's dup/delay faults.
        for ([_]Message{ ae1, ae2, ae1 }) |m| {
            try node.step(m);
            _ = try node.ready();
            try node.advance();
        }
        switch (bug) {
            .none => {
                try testing.expectEqual(@as(LogIndex, 5), node.lastIndex());
                try testing.expectEqual(@as(LogIndex, 5), node.applied);
            },
            // Index 4 and 5 were applied and are gone from the log.
            else => try testing.expect(node.applied > node.lastIndex()),
        }
    }
}

test "malformed and impossible input is dropped, counted, and moves no state" {
    const gpa = testing.allocator;
    var node = try Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{});
    defer node.deinit();
    const garbage = [_][]const u8{ "", &.{0x99}, &.{0x10}, &.{ 0x12, 0, 0 }, &.{0x02} };
    for (garbage) |g| try node.stepBytes(1, g);
    // A sender outside the cluster, and one claiming to be ourselves.
    var buf: [64]u8 = undefined;
    const vr: Message = .{ .from = 7, .to = 0, .body = .{ .vote_req = .{ .term = 9, .last_log_index = 0, .last_log_term = 0 } } };
    const n = vr.encode(&buf);
    try node.stepBytes(7, buf[0..n]);
    try node.stepBytes(0, buf[0..n]);
    try testing.expectEqual(@as(u64, garbage.len + 2), node.malformed_dropped);
    try testing.expectEqual(@as(Term, 0), node.term);
    try testing.expect(!node.hasReady());

    // The guard is not over-tight: the same frame from a real peer is acted on.
    try node.stepBytes(1, buf[0..n]);
    try testing.expectEqual(@as(Term, 9), node.term);
    try testing.expectEqual(@as(NodeId, 1), node.voted_for);
    const rd = try node.ready();
    try testing.expectEqual(@as(NodeId, 1), rd.hard_state.?.voted_for); // persisted before the grant leaves
    try testing.expect(rd.messages[0].body.vote_resp.granted);
    try node.advance();
}

test "a leader drops an AppendEntries response claiming more log than it has" {
    const gpa = testing.allocator;
    var node = try testLeader(gpa, 0);
    defer node.deinit();
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = 1, .success = true, .index = std.math.maxInt(u64) } } });
    try testing.expectEqual(@as(u64, 1), node.malformed_dropped);
    try testing.expectEqual(@as(LogIndex, 0), node.match[1]);
    try testing.expectEqual(@as(LogIndex, 0), node.commit);
}

test "init refuses an inconsistent config or restore" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, Node.init(gpa, .{ .id = 3, .cluster_size = 3, .seed = 0 }, .{}));
    try testing.expectError(error.InvalidConfig, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 2, .heartbeat_ticks = 2, .seed = 0 }, .{}));
    try testing.expectError(error.InvalidConfig, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .election_ticks = 10, .election_jitter_ticks = std.math.maxInt(u32), .seed = 0 }, .{}));
    const gap = [_]Entry{ .{ .index = 1, .term = 1 }, .{ .index = 3, .term = 1 } };
    try testing.expectError(error.InvalidRestore, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1 }, .entries = &gap }));
    const future = [_]Entry{.{ .index = 1, .term = 2 }};
    try testing.expectError(error.InvalidRestore, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1 }, .entries = &future }));
    try testing.expectError(error.InvalidRestore, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1, .voted_for = 5 } }));
    // More applied than there are entries to have applied.
    try testing.expectError(error.InvalidRestore, Node.init(gpa, .{ .id = 0, .cluster_size = 3, .seed = 0 }, .{ .hard_state = .{ .term = 1 }, .applied = 1 }));
}

// ── PreVote / CheckQuorum: the bookkeeping the delta mutation run found unpinned ──

test "CheckQuorum: the stepping-down tick sends no AppendEntries" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, cqCfg(), 0);
    defer node.deinit();
    for (0..3) |_| try node.tick();
    const from = node.msgs.items.len;
    try node.tick();
    try testing.expectEqual(Role.follower, node.role);
    try testing.expectEqual(@as(usize, 0), countTag(&node, from, .append_req));
}

test "CheckQuorum: a re-elected leader's first check counts only this term's acks, a full election_ticks after winning" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, cqCfg(), 0);
    defer node.deinit();
    // Node 1 acked in the first leadership…
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = node.term, .success = true, .index = 1 } } });
    // …which ends; node 0 becomes a candidate and ticks twice more before winning.
    try node.step(.{ .from = 2, .to = 0, .body = .{ .vote_resp = .{ .term = node.term + 1, .granted = false } } });
    while (node.role != .candidate) try node.tick();
    for (0..2) |_| try node.tick();
    try testing.expectEqual(Role.candidate, node.role);
    try node.step(.{ .from = 1, .to = 0, .body = .{ .vote_resp = .{ .term = node.term, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
    // The check is election_ticks after the win, not after the candidacy began…
    for (0..3) |_| try node.tick();
    try testing.expectEqual(Role.leader, node.role);
    // …and the old term's ack does not count: no ack this term, so it steps down.
    try node.tick();
    try testing.expectEqual(Role.follower, node.role);
}

test "PreVote: a pre-candidate forgets its leader, so it grants a peer's pre-vote at once" {
    const gpa = testing.allocator;
    var f = try Node.init(gpa, pvCfg(1), .{ .hard_state = .{ .term = 2 } });
    defer f.deinit();
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 2, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &.{} } } });
    try testing.expectEqual(@as(NodeId, 0), f.leader);
    for (0..4) |_| try f.tick();
    try testing.expectEqual(Role.pre_candidate, f.role);
    try testing.expectEqual(no_vote, f.leader); // etcd: `r.lead = None`
    // Its timer restarted, so the leader would count as live again were it remembered.
    try testing.expectEqual(@as(u32, 0), f.election_elapsed);
    const from = f.msgs.items.len;
    try f.step(.{ .from = 2, .to = 1, .body = .{ .pre_vote_req = .{ .term = 3, .last_log_index = 0, .last_log_term = 0 } } });
    try testing.expect((try lastPreVoteResp(&f, from)).granted);
}

test "PreVote: the next pre-campaign waits a full timeout, and starts from a fresh tally" {
    const gpa = testing.allocator;
    var cfg = pvCfg(0);
    cfg.cluster_size = 5; // a majority is 3
    var node = try Node.init(gpa, cfg, .{ .hard_state = .{ .term = 3 } });
    defer node.deinit();
    for (0..4) |_| try node.tick();
    try testing.expectEqual(Role.pre_candidate, node.role);
    // One grant: 2 of 5.
    try node.step(.{ .from = 1, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 4, .granted = true } } });
    _ = try node.ready();
    try node.advance();
    for (0..3) |_| try node.tick();
    try testing.expect(!node.hasReady()); // no new pre-campaign before the timeout
    try node.tick();
    try testing.expectEqual(@as(usize, 4), countTag(&node, 0, .pre_vote_req));
    // A new round: one grant is 2 of 5 again — node 1's grant from the last
    // round must not be counted.
    try node.step(.{ .from = 2, .to = 0, .body = .{ .pre_vote_resp = .{ .term = 4, .granted = true } } });
    try testing.expectEqual(Role.pre_candidate, node.role);
    try testing.expectEqual(@as(Term, 3), node.term);
}

test "PreVote receiver: same term with a known (lapsed) leader, or an older term from its own candidate, is refused" {
    const gpa = testing.allocator;
    var f = try Node.init(gpa, pvCfg(1), .{ .hard_state = .{ .term = 2 } });
    defer f.deinit();
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 2, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &.{} } } });
    f.election_elapsed = f.cfg.election_ticks; // not live any more, but still known
    var from = f.msgs.items.len;
    try f.step(.{ .from = 2, .to = 1, .body = .{ .pre_vote_req = .{ .term = 2, .last_log_index = 0, .last_log_term = 0 } } });
    try testing.expect(!(try lastPreVoteResp(&f, from)).granted); // etcd's canVote: r.lead != None

    var g = try Node.init(gpa, pvCfg(1), .{ .hard_state = .{ .term = 2, .voted_for = 2 } });
    defer g.deinit();
    from = g.msgs.items.len;
    try g.step(.{ .from = 2, .to = 1, .body = .{ .pre_vote_req = .{ .term = 1, .last_log_index = 0, .last_log_term = 0 } } });
    try testing.expect(!(try lastPreVoteResp(&g, from)).granted);
}

// ── leadership transfer (SPEC Backlog 7) ────────────────────────────────────

/// `testLeaderCfg` with node `p`'s log acknowledged up to the leader's last index.
fn ackAll(node: *Node, p: NodeId) !void {
    try node.step(.{ .from = p, .to = 0, .body = .{ .append_resp = .{ .term = node.term, .success = true, .index = node.lastIndex() } } });
}

fn trCfg() Config {
    var c = limitCfg();
    c.election_ticks = 4;
    return c;
}

test "transfer: a caught-up target gets timeout_now at once; proposals are dropped while it runs" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, trCfg(), 2);
    defer node.deinit();
    try testing.expectError(error.InvalidTarget, node.transferLeadership(3));
    try ackAll(&node, 2);
    try testing.expectEqual(no_vote, node.transferee);
    // No transfer yet: a progressing ack from the would-be target sends nothing of the kind.
    try testing.expectEqual(@as(usize, 0), countTag(&node, 0, .timeout_now));

    var from = node.msgs.items.len;
    try node.transferLeadership(2);
    try testing.expectEqual(@as(NodeId, 2), node.transferee);
    try testing.expectEqual(@as(usize, 1), node.msgs.items.len - from);
    const m = node.msgs.items[from];
    try testing.expectEqual(@as(NodeId, 2), m.to);
    try testing.expectEqual(node.term, m.body.timeout_now.term);
    try testing.expectError(error.ProposalDropped, node.propose("x"));
    try testing.expectEqual(Role.leader, node.role);
    // The same target again: nothing new is sent.
    from = node.msgs.items.len;
    try node.transferLeadership(2);
    try testing.expectEqual(from, node.msgs.items.len);
    // To itself: cancels (etcd), proposals are taken again.
    try node.transferLeadership(0);
    try testing.expectEqual(no_vote, node.transferee);
    _ = try node.propose("y");
    try testing.expectEqual(from, node.msgs.items.len);

    // A follower cannot transfer.
    var f = try Node.init(gpa, .{ .id = 1, .cluster_size = 3, .seed = 1 }, .{});
    defer f.deinit();
    try testing.expectError(error.NotLeader, f.transferLeadership(2));
}

test "transfer: a lagging target is caught up first; timeout_now follows the ack that reaches the leader's last index" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, trCfg(), 3); // last index 4
    defer node.deinit();
    node.next[2] = 2; // the target holds only the no-op
    node.match[2] = 1;
    var from = node.msgs.items.len;
    try node.transferLeadership(2);
    try testing.expectEqual(@as(usize, 0), countTag(&node, from, .timeout_now));
    try testing.expectEqual(@as(usize, 1), countTag(&node, from, .append_req));
    try testing.expectEqual(@as(usize, 3), node.msgs.items[from].body.append_req.entries.len);
    // A partial ack: not yet.
    from = node.msgs.items.len;
    try node.step(.{ .from = 2, .to = 0, .body = .{ .append_resp = .{ .term = node.term, .success = true, .index = 3 } } });
    try testing.expectEqual(@as(usize, 0), countTag(&node, from, .timeout_now));
    // Another follower reaching the end: not it.
    try ackAll(&node, 1);
    try testing.expectEqual(@as(usize, 0), countTag(&node, from, .timeout_now));
    // The target reaching the end: now, once.
    try ackAll(&node, 2);
    try testing.expectEqual(@as(usize, 1), countTag(&node, from, .timeout_now));
    // A duplicate of that ack (no progress) does not repeat it.
    try ackAll(&node, 2);
    try testing.expectEqual(@as(usize, 1), countTag(&node, from, .timeout_now));
}

test "transfer: abandoned one election timeout after it started, not one tick before" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, trCfg(), 0);
    defer node.deinit();
    try node.tick();
    try node.tick(); // mid-period: the transfer still gets a full timeout
    try node.transferLeadership(1);
    for (0..3) |_| try node.tick();
    try testing.expectEqual(@as(NodeId, 1), node.transferee);
    try testing.expectError(error.ProposalDropped, node.propose("x"));
    try node.tick();
    try testing.expectEqual(no_vote, node.transferee);
    try testing.expectEqual(Role.leader, node.role);
    _ = try node.propose("x");
    // Another target restarts it toward that one (etcd).
    try node.transferLeadership(1);
    try node.transferLeadership(2);
    try testing.expectEqual(@as(NodeId, 2), node.transferee);
}

test "transfer: stepping down ends it, and a new term's leader starts with none" {
    const gpa = testing.allocator;
    var node = try testLeaderCfg(gpa, trCfg(), 0);
    defer node.deinit();
    try node.transferLeadership(1);
    try node.step(.{ .from = 1, .to = 0, .body = .{ .append_resp = .{ .term = node.term + 1, .success = false, .index = 0 } } });
    try testing.expectEqual(Role.follower, node.role);
    try testing.expectEqual(no_vote, node.transferee);
    // Re-elected leader with a stale transferee forced in: becomeLeader clears it.
    while (node.role != .candidate) try node.tick();
    node.transferee = 1;
    try node.step(.{ .from = 2, .to = 0, .body = .{ .vote_resp = .{ .term = node.term, .granted = true } } });
    try testing.expectEqual(Role.leader, node.role);
    try testing.expectEqual(no_vote, node.transferee);
    _ = try node.propose("x");
}

test "timeout_now: a follower campaigns at once, flagged, without PreVote; stale or non-follower ignores it" {
    const gpa = testing.allocator;
    var cfg = pvCfg(1); // pre_vote on: the transfer must bypass it
    cfg.election_ticks = 50;
    var f = try Node.init(gpa, cfg, .{ .hard_state = .{ .term = 3 } });
    defer f.deinit();
    // An older term: ignored.
    try f.step(.{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 2 } } });
    try testing.expectEqual(Role.follower, f.role);
    try testing.expectEqual(@as(usize, 0), f.msgs.items.len);
    // Its own term: a real election now, term + 1, RequestVotes carrying the flag.
    try f.step(.{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 3 } } });
    try testing.expectEqual(Role.candidate, f.role);
    try testing.expectEqual(@as(Term, 4), f.term);
    try testing.expectEqual(@as(usize, 0), countTag(&f, 0, .pre_vote_req));
    try testing.expectEqual(@as(usize, 2), countTag(&f, 0, .vote_req));
    for (f.msgs.items) |m| try testing.expect(m.body.vote_req.transfer);
    // A candidate ignores one (etcd's stepCandidate).
    const n = f.msgs.items.len;
    try f.step(.{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 4 } } });
    try testing.expectEqual(@as(Term, 4), f.term);
    try testing.expectEqual(n, f.msgs.items.len);
    // A higher term is adopted first, then the follower campaigns.
    try f.step(.{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 8 } } });
    try testing.expectEqual(Role.candidate, f.role);
    try testing.expectEqual(@as(Term, 9), f.term);

    // A pre-candidate ignores one too, and an ordinary election is unflagged.
    var p = try Node.init(gpa, pvCfg(1), .{ .hard_state = .{ .term = 3 } });
    defer p.deinit();
    for (0..4) |_| try p.tick();
    try testing.expectEqual(Role.pre_candidate, p.role);
    try p.step(.{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 3 } } });
    try testing.expectEqual(Role.pre_candidate, p.role);
    try testing.expectEqual(@as(Term, 3), p.term);
    var q = try Node.init(gpa, .{ .id = 1, .cluster_size = 3, .election_ticks = 2, .election_jitter_ticks = 0, .seed = 1 }, .{});
    defer q.deinit();
    for (0..2) |_| try q.tick();
    try testing.expectEqual(Role.candidate, q.role);
    for (q.msgs.items) |m| try testing.expect(!m.body.vote_req.transfer);
}

test "transfer vote: honoured inside a CheckQuorum lease, by a follower and by the old leader" {
    const gpa = testing.allocator;
    var cfg = cqCfg();
    cfg.id = 1;
    var f = try Node.init(gpa, cfg, .{ .hard_state = .{ .term = 2 } });
    defer f.deinit();
    try f.step(.{ .from = 0, .to = 1, .body = .{ .append_req = .{ .term = 2, .prev_log_index = 0, .prev_log_term = 0, .leader_commit = 0, .entries = &.{} } } });
    _ = try f.ready();
    try f.advance();
    try testing.expect(f.leaderLive());
    // Unflagged: ignored (the lease). Flagged: adopted and granted.
    try f.step(.{ .from = 2, .to = 1, .body = .{ .vote_req = .{ .term = 3, .last_log_index = 0, .last_log_term = 0 } } });
    try testing.expectEqual(@as(Term, 2), f.term);
    try f.step(.{ .from = 2, .to = 1, .body = .{ .vote_req = .{ .term = 3, .last_log_index = 0, .last_log_term = 0, .transfer = true } } });
    try testing.expectEqual(@as(Term, 3), f.term);
    try testing.expectEqual(@as(NodeId, 2), f.voted_for);
    try testing.expect(f.msgs.items[f.msgs.items.len - 1].body.vote_resp.granted);

    var l = try testLeaderCfg(gpa, cqCfg(), 0);
    defer l.deinit();
    try l.transferLeadership(1);
    try l.step(.{ .from = 1, .to = 0, .body = .{ .vote_req = .{ .term = l.term + 1, .last_log_index = l.lastIndex(), .last_log_term = l.term, .transfer = true } } });
    try testing.expectEqual(Role.follower, l.role);
    try testing.expectEqual(@as(NodeId, 1), l.voted_for);
    try testing.expectEqual(no_vote, l.transferee);
}

test "transfer, end to end: a three-node cluster hands leadership to node 2 in the next term, then commits under it" {
    var c = try Cluster(3).init(testing.allocator);
    defer c.deinit();
    try c.tickAll(12);
    try testing.expectEqual(@as(?NodeId, 0), c.leaderId());
    _ = try c.nodes[0].?.propose("before");
    try c.drain(0);
    try c.deliver();
    try c.nodes[0].?.transferLeadership(2);
    try c.drain(0);
    try c.deliver();
    try testing.expectEqual(@as(?NodeId, 2), c.leaderId());
    try testing.expectEqual(@as(Term, 2), c.nodes[2].?.term);
    for (c.nodes) |m| try testing.expectEqual(@as(Term, 2), m.?.term);
    _ = try c.nodes[2].?.propose("after");
    try c.drain(2);
    try c.deliver();
    try c.tickAll(3);
    for (c.applied) |a| {
        try testing.expectEqual(@as(usize, 2), a.items.len);
        try testing.expectEqualStrings("after", a.items[1]);
    }
}
