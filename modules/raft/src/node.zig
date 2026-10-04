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
//! used to own (`server.zig` before 2026-10-04) moved to where a deployment can
//! reach it: `server.RaftServer` now runs N of these inside `netsim`, so the
//! fuzzed fault sweep checks exactly the code a consumer runs.
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
//! Not here yet (see SPEC.md § Backlog): snapshots / log compaction, membership
//! change, pre-vote and leadership transfer, linearizable reads. The whole log
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

pub const Role = enum { follower, candidate, leader };

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
pub const ProposeError = error{ NotLeader, EntryTooLarge } || Allocator.Error;

/// Largest `propose` payload: the wire carries an entry's length as a `u32`.
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
    hdr[16] = @intFromEnum(e.kind);
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
            .prng = .init(cfg.seed),
            .out_arena = .init(gpa),
            .decode_buf = &.{},
        };
        errdefer self.deinit();
        self.votes = try gpa.alloc(bool, n);
        self.next = try gpa.alloc(LogIndex, n);
        self.match = try gpa.alloc(LogIndex, n);
        self.decode_buf = try gpa.alloc(Entry, cfg.max_append_entries);
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
            self.heartbeat_elapsed += 1;
            if (self.heartbeat_elapsed >= self.cfg.heartbeat_ticks) try self.bcastAppend();
            return;
        }
        self.election_elapsed += 1;
        if (self.election_elapsed >= self.election_timeout) try self.campaign();
    }

    /// Append `bytes` as a command entry; returns its index. It is committed
    /// when a `Ready.committed` delivers it — or never, if leadership is lost
    /// first (watch `entryAt(index).term`: a different term means it was
    /// overwritten). The bytes are copied.
    pub fn propose(self: *Node, bytes: []const u8) ProposeError!LogIndex {
        std.debug.assert(!self.in_ready);
        if (self.role != .leader) return error.NotLeader;
        if (bytes.len > max_entry_len) return error.EntryTooLarge;
        const idx = try self.appendLocal(.command, bytes);
        self.bcast_pending = true;
        return idx;
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
        switch (m.body) {
            .vote_req => |v| try self.onVoteReq(m.from, v),
            .vote_resp => |v| try self.onVoteResp(m.from, v),
            .append_req => |a| try self.onAppendReq(m.from, a),
            .append_resp => |a| try self.onAppendResp(m.from, a),
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

    fn campaign(self: *Node) Allocator.Error!void {
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
            } });
        }
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
        // A broadcast scheduled while leader must not go out after the step
        // down: `ready` would send the stale tail under the NEW term, as a
        // leader of a term this node never won (review 2026-10-04, H1).
        self.bcast_pending = false;
        self.resetElectionTimer();
    }

    fn onVoteReq(self: *Node, from: NodeId, v: message.VoteReq) Allocator.Error!void {
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
        const count: usize = @intCast(@min(last - prev, self.cfg.max_append_entries));
        const entries = try a.alloc(Entry, count);
        for (entries, @as(usize, @intCast(prev + 1))..) |*e, i| {
            const src = self.entryAt(i).?;
            // Copies: a later truncation in this same batch frees the
            // originals, and the message must outlive it until `advance`.
            e.* = src;
            e.data = try a.dupe(u8, src.data);
        }
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
        try self.send(from, .{ .append_resp = .{
            .term = self.term,
            .success = out.success,
            .index = if (out.success) out.match_index else self.lastIndex(),
        } });
    }

    fn onAppendResp(self: *Node, from: NodeId, a: message.AppendResp) Allocator.Error!void {
        const obs = safety.observeTerm(self.term, a.term);
        if (obs.term_advanced) return self.becomeFollower(obs.new_term);
        if (self.role != .leader or a.term != self.term) return;
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
            self.next[from] = @max(self.next[from], self.match[from] + 1);
            self.maybeCommit();
            // Keep streaming only on PROGRESS: a duplicated or stale ack must
            // not fork a second stream; the heartbeat covers the rest.
            if (progressed and self.next[from] <= self.lastIndex()) try self.sendAppend(from);
        } else {
            // Walk back — straight past the follower's end if its hint says
            // so — but never below what it has already confirmed (a stale
            // rejection arriving after a success).
            const lowered = @min(self.next[from] -| 1, a.index +| 1);
            const next = @max(self.match[from] + 1, lowered);
            // Retry at once only if the rejection moved us: a follower that
            // keeps rejecting at `match + 1` (it cannot, honestly) would
            // otherwise get the same batch back every round trip.
            const moved = next < self.next[from];
            self.next[from] = next;
            if (moved) try self.sendAppend(from);
        }
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
