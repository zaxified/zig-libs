// SPDX-License-Identifier: MIT

//! One Raft server: real TCP, real timers, real disk — everything `netsim`
//! abstracts away when the `raft` module's kernel is model-checked, supplied
//! here for real. Every consensus DECISION is the module's:
//! `handleRequestVote`, `handleAppendEntries`, `leaderCommitIndex`,
//! `observeTerm` — this file only carries their verdicts to sockets, to the
//! `kv` store, and to the applied state machine, in the order Figure 2
//! requires (persist, THEN answer).
//!
//! Threading model, deliberately coarse: one `SpinLock` over all Raft state.
//! Frames are built and verdicts applied UNDER the lock (pure memory work);
//! network I/O happens outside it. Threads: the accept loop (main), one
//! ticker (election timeouts), one replication loop per peer, one thread per
//! accepted connection, and a stop watcher. RPCs are one-shot: connect, one
//! request frame, one response frame, close — the listener only ever sees
//! requests, so responses never need routing.

const std = @import("std");
const raft = @import("raft");
const lockfree = @import("lockfree");
const wire = @import("wire.zig");
const store_mod = @import("store.zig");

const heartbeat_ms = 50;
const tick_ms = 20;
const election_base_ms = 300;
const election_jitter_ms = 300;
/// How long a `put`/`del` connection waits for its entry to commit+apply
/// before answering failure — generous against a 50 ms heartbeat, and short
/// enough that a majority-less cluster answers "no" while a client budget is
/// still running.
const commit_wait_ms = 2000;

pub const Options = struct {
    id: u32,
    peers: []const []const u8,
    data: []const u8,
};

const Role = enum { follower, candidate, leader };

pub fn serve(gpa: std.mem.Allocator, io: std.Io, opts: Options) !void {
    var node: Node = undefined;
    try node.init(gpa, io, opts);
    defer node.deinit();
    try node.run();
}

const Node = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    id: u32,
    n: usize,
    addrs: []std.Io.net.IpAddress,

    lock: lockfree.SpinLock = .{},
    // ── guarded by `lock` ───────────────────────────────────────────────────
    term: raft.Term = 0,
    vote: raft.NodeId = raft.no_vote,
    role: Role = .follower,
    /// Last node observed acting as leader — the redirect hint for clients.
    leader_hint: raft.NodeId = raft.no_vote,
    log: raft.Log = .{},
    /// blobs[i-1] is log index i's payload; always in lockstep with `log`.
    blobs: std.ArrayList([]u8) = .empty,
    commit: raft.LogIndex = 0,
    applied_idx: raft.LogIndex = 0,
    applied: std.StringHashMapUnmanaged([]u8) = .empty,
    next: []raft.LogIndex,
    match: []raft.LogIndex,
    election_deadline: u64 = 0,
    prng: std.Random.DefaultPrng,
    store: store_mod.Store,
    // ────────────────────────────────────────────────────────────────────────

    stop: std.atomic.Value(bool) = .init(false),
    /// Every DETACHED thread that touches `*Node` — accepted connections and
    /// vote RPCs — is counted here so shutdown can wait for all of them before
    /// `deinit` frees the state they hold. Missing this on vote threads was a
    /// real use-after-free: they were detached and untracked.
    live_threads: std.atomic.Value(usize) = .init(0),
    listen_addr: std.Io.net.IpAddress,

    fn init(self: *Node, gpa: std.mem.Allocator, io: std.Io, opts: Options) !void {
        const n = opts.peers.len;
        self.* = .{
            .gpa = gpa,
            .io = io,
            .id = opts.id,
            .n = n,
            .addrs = try gpa.alloc(std.Io.net.IpAddress, n),
            .next = try gpa.alloc(raft.LogIndex, n),
            .match = try gpa.alloc(raft.LogIndex, n),
            .prng = undefined,
            .store = undefined,
            .listen_addr = undefined,
        };
        var seed: [8]u8 = undefined;
        try io.randomSecure(&seed);
        self.prng = .init(std.mem.readInt(u64, &seed, .little));

        for (opts.peers, 0..) |p, i| {
            const colon = std.mem.lastIndexOfScalar(u8, p, ':') orelse return error.BadPeerAddress;
            const port = std.fmt.parseInt(u16, p[colon + 1 ..], 10) catch return error.BadPeerAddress;
            self.addrs[i] = std.Io.net.IpAddress.parse(p[0..colon], port) catch return error.BadPeerAddress;
        }
        self.listen_addr = self.addrs[self.id];

        try self.store.open(gpa, io, opts.data);
        errdefer self.store.close();

        // Recover: persistent state, then the log (dense from 1). The applied
        // state machine is NOT recovered — it re-materializes as commitIndex
        // re-advances, which is Figure 2's contract for volatile state.
        const meta = self.store.loadMeta();
        self.term = meta.term;
        self.vote = meta.vote;
        var idx: raft.LogIndex = 1;
        while (try self.store.getEntry(gpa, idx)) |le| : (idx += 1) {
            try self.log.append(gpa, le.entry);
            try self.blobs.append(gpa, le.blob);
        }
        self.resetElectionDeadline();
        std.debug.print("raft-kv[{d}]: recovered term={d} log={d} entries\n", .{ self.id, self.term, self.log.lastIndex() });
    }

    fn deinit(self: *Node) void {
        const gpa = self.gpa;
        for (self.blobs.items) |b| gpa.free(b);
        self.blobs.deinit(gpa);
        self.log.deinit(gpa);
        var it = self.applied.iterator();
        while (it.next()) |e| {
            gpa.free(e.key_ptr.*);
            gpa.free(e.value_ptr.*);
        }
        self.applied.deinit(gpa);
        self.store.close();
        gpa.free(self.addrs);
        gpa.free(self.next);
        gpa.free(self.match);
    }

    // ── time ────────────────────────────────────────────────────────────────

    fn nowMs() u64 {
        var ts: std.posix.timespec = undefined;
        if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
    }

    fn resetElectionDeadline(self: *Node) void {
        const jitter = self.prng.random().uintLessThan(u64, election_jitter_ms);
        self.election_deadline = nowMs() + election_base_ms + jitter;
    }

    // ── main loop ───────────────────────────────────────────────────────────

    fn run(self: *Node) !void {
        // reuse_address: a node that crashed and restarted must be able to
        // rebind its own port while old connections sit in TIME_WAIT —
        // restart-on-the-same-address is the whole demo.
        var listener = self.listen_addr.listen(self.io, .{ .reuse_address = true }) catch |err| {
            std.debug.print("raft-kv[{d}]: cannot listen: {t}\n", .{ self.id, err });
            return err;
        };
        defer listener.deinit(self.io);

        installStopHandlers();

        const ticker = try std.Thread.spawn(.{}, tickerLoop, .{self});
        defer ticker.join();
        var repl_threads = try self.gpa.alloc(std.Thread, self.n);
        defer self.gpa.free(repl_threads);
        var spawned: usize = 0;
        defer for (repl_threads[0..spawned]) |t| t.join();
        for (0..self.n) |i| {
            if (i == self.id) continue;
            repl_threads[spawned] = try std.Thread.spawn(.{}, replicationLoop, .{ self, @as(u32, @intCast(i)) });
            spawned += 1;
        }
        const watcher = try std.Thread.spawn(.{}, stopWatcher, .{self});
        defer watcher.join();

        std.debug.print("raft-kv[{d}]: listening on {f}\n", .{ self.id, self.listen_addr });

        while (!self.stop.load(.acquire)) {
            const stream = listener.accept(self.io) catch |err| {
                if (self.stop.load(.acquire)) break;
                std.debug.print("raft-kv[{d}]: accept: {t}\n", .{ self.id, err });
                break;
            };
            // In-flight connections are all request/response with bounded
            // waits, so shutdown joins them implicitly: the stop watcher's
            // self-connect below is the LAST accepted connection.
            _ = self.live_threads.rmw(.Add, 1, .acq_rel);
            const t = std.Thread.spawn(.{}, connectionThread, .{ self, stream }) catch {
                var s = stream;
                s.close(self.io);
                _ = self.live_threads.rmw(.Sub, 1, .acq_rel);
                continue;
            };
            t.detach();
        }
        // Wait UNCONDITIONALLY for every detached thread (connections AND vote
        // RPCs) to release `*Node` before returning — `serve` runs `deinit`
        // the moment we return, and a straggler still inside `self.lock`/
        // `self.log` would then touch freed state. The earlier soft deadline
        // here would elapse and let `deinit` proceed under a live thread; that
        // was the use-after-free. Every counted thread finishes on its own
        // (request/response is bounded by commit_wait_ms; a vote/replication
        // RPC returns when its peer answers or the connection drops), so this
        // terminates in every case the demo produces. The one thing that could
        // stall it — a peer that accepts and then never answers — already
        // stalls the replication-thread joins above, so this widens no window
        // that was not already open, and it trades a definite UAF for it.
        while (self.live_threads.load(.acquire) != 0)
            self.io.sleep(.fromMilliseconds(10), .awake) catch break;
        std.debug.print("raft-kv[{d}]: stopped cleanly\n", .{self.id});
    }

    fn stopWatcher(self: *Node) void {
        while (!stop_requested.load(.acquire) and !self.stop.load(.acquire))
            self.io.sleep(.fromMilliseconds(50), .awake) catch break;
        self.stop.store(true, .release);
        // Wake the accept loop with a throwaway connection.
        var s = self.listen_addr.connect(self.io, .{ .mode = .stream }) catch return;
        s.close(self.io);
    }

    // ── ticker: elections ───────────────────────────────────────────────────

    fn tickerLoop(self: *Node) void {
        while (!self.stop.load(.acquire)) {
            self.io.sleep(.fromMilliseconds(tick_ms), .awake) catch return;
            self.lock.lock();
            if (self.role != .leader and nowMs() >= self.election_deadline) {
                self.startElectionLocked() catch |err| {
                    std.debug.print("raft-kv[{d}]: election start failed: {t}\n", .{ self.id, err });
                };
            }
            self.lock.unlock();
        }
    }

    /// §5.2: term += 1, vote for self (PERSISTED before any ballot leaves
    /// this machine), then ask every peer in parallel.
    fn startElectionLocked(self: *Node) !void {
        self.term += 1;
        self.vote = self.id;
        self.role = .candidate;
        // Reset the deadline BEFORE the fallible persist. If saveMeta fails
        // (a broken disk), the `try` returns and tickerLoop only logs it — but
        // with the deadline already advanced, the next tick backs off instead
        // of re-firing 20 ms later and hammering the disk while inflating the
        // term every cycle.
        self.resetElectionDeadline();
        try self.store.saveMeta(self.term, self.vote);
        std.debug.print("raft-kv[{d}]: term={d} standing for election\n", .{ self.id, self.term });

        const li = self.log.info();
        const req: raft.RequestVoteReq = .{
            .term = self.term,
            .candidate_id = self.id,
            .last_log_index = li.last_index,
            .last_log_term = li.last_term,
        };
        const tally = try self.gpa.create(Tally);
        tally.* = .{ .granted = .init(1), .refs = .init(1) }; // self vote counted
        for (0..self.n) |i| {
            if (i == self.id) continue;
            _ = tally.refs.rmw(.Add, 1, .acq_rel);
            _ = self.live_threads.rmw(.Add, 1, .acq_rel);
            const t = std.Thread.spawn(.{}, voteThread, .{ self, @as(u32, @intCast(i)), req, tally }) catch {
                _ = self.live_threads.rmw(.Sub, 1, .acq_rel);
                _ = tally.refs.rmw(.Sub, 1, .acq_rel);
                continue;
            };
            t.detach();
        }
        tally.release(self.gpa);
    }

    const Tally = struct {
        granted: std.atomic.Value(usize),
        refs: std.atomic.Value(usize),

        fn release(t: *Tally, gpa: std.mem.Allocator) void {
            if (t.refs.rmw(.Sub, 1, .acq_rel) == 1) gpa.destroy(t);
        }
    };

    fn voteThread(self: *Node, peer: u32, req: raft.RequestVoteReq, tally: *Tally) void {
        defer _ = self.live_threads.rmw(.Sub, 1, .acq_rel);
        defer tally.release(self.gpa);
        var buf: [raft.RequestVoteReq.wire_len + 1]u8 = undefined;
        buf[0] = @intFromEnum(wire.Kind.rpc);
        req.encode(buf[1..]);
        var resp_buf: [64]u8 = undefined;
        const resp_frame = self.exchange(peer, &buf, &resp_buf) catch return;
        if (resp_frame.len < 1 or resp_frame[0] != @intFromEnum(wire.Kind.rpc)) return;
        const resp = raft.RequestVoteResp.decode(resp_frame[1..]) catch return;

        self.lock.lock();
        defer self.lock.unlock();
        const obs = raft.observeTerm(self.term, resp.term);
        if (obs.term_advanced) {
            self.stepDownLocked(obs.new_term);
            return;
        }
        // Count only ballots from THIS candidacy: same term, still a candidate.
        if (self.role != .candidate or resp.term != self.term or req.term != self.term) return;
        if (!resp.vote_granted) return;
        const got = tally.granted.rmw(.Add, 1, .acq_rel) + 1;
        if (got >= self.n / 2 + 1) self.becomeLeaderLocked();
    }

    fn stepDownLocked(self: *Node, new_term: raft.Term) void {
        self.term = new_term;
        self.role = .follower;
        self.vote = raft.no_vote;
        self.store.saveMeta(self.term, self.vote) catch |err| {
            std.debug.print("raft-kv[{d}]: persist failed: {t}\n", .{ self.id, err });
        };
        self.resetElectionDeadline();
    }

    fn becomeLeaderLocked(self: *Node) void {
        self.role = .leader;
        self.leader_hint = self.id;
        const last = self.log.lastIndex();
        for (0..self.n) |i| {
            self.next[i] = last + 1;
            self.match[i] = 0;
        }
        std.debug.print("raft-kv[{d}]: term={d} LEADER\n", .{ self.id, self.term });
        // §8: commit a no-op from the new term so leaderCommitIndex's
        // Figure-8 rule can pull every earlier entry in behind it without
        // waiting for client traffic.
        _ = self.appendLocked(.{ .term = self.term, .kind = .noop, .command = 0 }, "") catch |err| blk: {
            std.debug.print("raft-kv[{d}]: no-op append failed: {t}\n", .{ self.id, err });
            break :blk 0;
        };
    }

    /// Persist first, then mirror in memory, then count ourselves replicated.
    fn appendLocked(self: *Node, entry: raft.LogEntry, blob: []const u8) !raft.LogIndex {
        const idx = self.log.lastIndex() + 1;
        try self.store.putEntry(self.gpa, idx, entry, blob);
        const owned = try self.gpa.dupe(u8, blob);
        errdefer self.gpa.free(owned);
        try self.log.append(self.gpa, entry);
        try self.blobs.append(self.gpa, owned);
        self.match[self.id] = idx;
        return idx;
    }

    // ── replication (leader → one peer) ─────────────────────────────────────

    fn replicationLoop(self: *Node, peer: u32) void {
        while (!self.stop.load(.acquire)) {
            self.io.sleep(.fromMilliseconds(heartbeat_ms), .awake) catch return;

            self.lock.lock();
            if (self.role != .leader) {
                self.lock.unlock();
                continue;
            }
            const sent_term = self.term;
            const frame = self.buildAppendLocked(peer) catch |err| {
                self.lock.unlock();
                std.debug.print("raft-kv[{d}]: build append: {t}\n", .{ self.id, err });
                continue;
            };
            self.lock.unlock();
            defer self.gpa.free(frame);

            var resp_buf: [64]u8 = undefined;
            const resp_frame = self.exchange(peer, frame, &resp_buf) catch continue;
            if (resp_frame.len < 1 or resp_frame[0] != @intFromEnum(wire.Kind.rpc)) continue;
            const resp = raft.AppendEntriesResp.decode(resp_frame[1..]) catch continue;

            self.lock.lock();
            const obs = raft.observeTerm(self.term, resp.term);
            if (obs.term_advanced) {
                self.stepDownLocked(obs.new_term);
            } else if (self.role == .leader and self.term == sent_term) {
                if (resp.success) {
                    if (resp.match_index > self.match[peer]) self.match[peer] = resp.match_index;
                    self.next[peer] = self.match[peer] + 1;
                    const nc = raft.leaderCommitIndex(self.term, self.commit, self.match, self.n, &self.log);
                    if (nc > self.commit) {
                        self.commit = nc;
                        self.applyCommittedLocked();
                    }
                } else if (self.next[peer] > 1) {
                    self.next[peer] -= 1;
                }
            }
            self.lock.unlock();
        }
    }

    fn buildAppendLocked(self: *Node, peer: u32) ![]u8 {
        const next_i = self.next[peer];
        const prev = next_i - 1;
        const last = self.log.lastIndex();
        const count: usize = @min(last -| prev, raft.max_entries_per_msg);
        var entries: [raft.max_entries_per_msg]raft.LogEntry = undefined;
        var payloads: [raft.max_entries_per_msg][]const u8 = undefined;
        for (0..count) |j| {
            const idx = prev + 1 + j;
            entries[j] = self.log.get(idx).?;
            payloads[j] = self.blobs.items[idx - 1];
        }
        const req: raft.AppendEntriesReq = .{
            .term = self.term,
            .leader_id = self.id,
            .prev_log_index = prev,
            .prev_log_term = if (prev == 0) 0 else self.log.termAt(prev).?,
            .entries = entries[0..count],
            .leader_commit = self.commit,
        };
        return wire.encodeAppendWithPayloads(self.gpa, req, payloads[0..count]);
    }

    // ── one-shot RPC exchange ───────────────────────────────────────────────

    fn exchange(self: *Node, peer: u32, frame: []const u8, resp_buf: []u8) ![]u8 {
        var stream = try self.addrs[peer].connect(self.io, .{ .mode = .stream });
        defer stream.close(self.io);
        var wbuf: [1024]u8 = undefined;
        var rbuf: [1024]u8 = undefined;
        var w = stream.writer(self.io, &wbuf);
        var r = stream.reader(self.io, &rbuf);
        try wire.writeFrame(&w.interface, frame);
        return wire.readFrame(&r.interface, resp_buf);
    }

    // ── the state machine ───────────────────────────────────────────────────

    fn applyCommittedLocked(self: *Node) void {
        while (self.applied_idx < self.commit) {
            const idx = self.applied_idx + 1;
            const entry = self.log.get(idx) orelse break;
            const blob = self.blobs.items[idx - 1];
            self.applied_idx = idx;
            if (entry.kind != .command) continue;
            // The binding check: consensus agreed on `command`; refuse a blob
            // that does not hash to it rather than apply unagreed bytes.
            if (wire.commandHash(blob) != entry.command) {
                std.debug.print("raft-kv[{d}]: index {d}: payload does not hash to the committed command — NOT applied\n", .{ self.id, idx });
                continue;
            }
            const op = wire.decodeOp(blob) orelse continue;
            self.applyOp(op) catch |err| {
                std.debug.print("raft-kv[{d}]: apply {d}: {t}\n", .{ self.id, idx, err });
            };
        }
    }

    fn applyOp(self: *Node, op: wire.DecodedOp) !void {
        switch (op.op) {
            .set => {
                const gop = try self.applied.getOrPut(self.gpa, op.key);
                if (gop.found_existing) {
                    self.gpa.free(gop.value_ptr.*);
                } else {
                    gop.key_ptr.* = try self.gpa.dupe(u8, op.key);
                }
                gop.value_ptr.* = try self.gpa.dupe(u8, op.value);
            },
            .del => {
                if (self.applied.fetchRemove(op.key)) |kvp| {
                    self.gpa.free(kvp.key);
                    self.gpa.free(kvp.value);
                }
            },
        }
    }

    // ── inbound connections ─────────────────────────────────────────────────

    fn connectionThread(self: *Node, stream_in: std.Io.net.Stream) void {
        var stream = stream_in;
        defer {
            stream.close(self.io);
            _ = self.live_threads.rmw(.Sub, 1, .acq_rel);
        }
        const frame_buf = self.gpa.alloc(u8, wire.limits.max_frame) catch return;
        defer self.gpa.free(frame_buf);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var r = stream.reader(self.io, &rbuf);
        var w = stream.writer(self.io, &wbuf);

        const frame = wire.readFrame(&r.interface, frame_buf) catch return;
        if (frame.len < 1) return;

        if (frame[0] == @intFromEnum(wire.Kind.rpc)) {
            self.handleRpc(frame[1..], &w.interface) catch return;
            return;
        }
        const cmd = wire.decodeClient(frame) orelse return;
        self.handleClient(cmd, &w.interface) catch return;
    }

    fn reply(self: *Node, w: *std.Io.Writer, kind: wire.Resp, body: []const u8) !void {
        const out = try self.gpa.alloc(u8, 1 + body.len);
        defer self.gpa.free(out);
        out[0] = @intFromEnum(kind);
        @memcpy(out[1..], body);
        try wire.writeFrame(w, out);
    }

    // ── peer RPC handlers: the kernel decides, this code obeys ──────────────

    fn handleRpc(self: *Node, body: []const u8, w: *std.Io.Writer) !void {
        const tag = raft.tagOf(body) catch return;
        switch (tag) {
            .request_vote_req => {
                const req = raft.RequestVoteReq.decode(body) catch return;
                var out: [raft.RequestVoteResp.wire_len + 1]u8 = undefined;
                out[0] = @intFromEnum(wire.Kind.rpc);
                {
                    self.lock.lock();
                    defer self.lock.unlock();
                    const d = raft.handleRequestVote(self.term, self.vote, self.log.info(), req);
                    const changed = d.new_term != self.term or (d.grant and d.voted_for != self.vote);
                    if (d.term_advanced) self.role = .follower;
                    self.term = d.new_term;
                    if (d.term_advanced) self.vote = raft.no_vote;
                    if (d.grant) {
                        self.vote = d.voted_for;
                        // A granted vote is a statement that someone MAY become
                        // leader — do not immediately campaign against them.
                        self.resetElectionDeadline();
                    }
                    // Persist BEFORE the ballot leaves this machine (§5.1's
                    // "before responding to RPCs").
                    if (changed) try self.store.saveMeta(self.term, self.vote);
                    const resp: raft.RequestVoteResp = .{ .term = self.term, .vote_granted = d.grant };
                    resp.encode(out[1..]);
                }
                try wire.writeFrame(w, &out);
            },
            .append_entries_req => {
                var entries_buf: [raft.max_entries_per_msg]raft.LogEntry = undefined;
                const dec = wire.decodeAppendWithPayloads(body, &entries_buf) catch return;
                const req = dec.req;
                var out: [raft.AppendEntriesResp.wire_len + 1]u8 = undefined;
                out[0] = @intFromEnum(wire.Kind.rpc);
                {
                    self.lock.lock();
                    defer self.lock.unlock();
                    const o = raft.handleAppendEntries(self.term, &self.log, self.commit, req);
                    if (o.new_term != self.term) {
                        self.term = o.new_term;
                        self.vote = raft.no_vote;
                        try self.store.saveMeta(self.term, self.vote);
                    }
                    if (req.term >= self.term) {
                        // A current leader exists: a candidate stands down, and
                        // the heartbeat holds elections at bay.
                        self.role = .follower;
                        self.leader_hint = req.leader_id;
                        self.resetElectionDeadline();
                    }
                    if (o.success) {
                        // Conflict truncation (the kernel's verdict, never more).
                        var last = self.log.lastIndex();
                        if (o.truncate_to < last) {
                            var i = last;
                            while (i > o.truncate_to) : (i -= 1) {
                                try self.store.delEntry(i);
                                self.gpa.free(self.blobs.pop().?);
                            }
                            self.log.truncateAfter(o.truncate_to);
                            if (self.applied_idx > o.truncate_to) {
                                // Cannot happen for committed entries (the
                                // kernel never truncates below commit), but
                                // stay honest if it ever did.
                                std.debug.print("raft-kv[{d}]: truncated below applied — state diverged\n", .{self.id});
                            }
                            last = o.truncate_to;
                        }
                        for (o.append_from..req.entries.len) |j| {
                            const idx = req.prev_log_index + 1 + j;
                            if (idx <= last) continue; // already present + matching
                            try self.store.putEntry(self.gpa, idx, req.entries[j], dec.blobs[j]);
                            const owned = try self.gpa.dupe(u8, dec.blobs[j]);
                            errdefer self.gpa.free(owned);
                            try self.log.append(self.gpa, req.entries[j]);
                            try self.blobs.append(self.gpa, owned);
                        }
                        if (o.new_commit_index > self.commit) {
                            self.commit = o.new_commit_index;
                            self.applyCommittedLocked();
                        }
                    }
                    const resp: raft.AppendEntriesResp = .{
                        .term = self.term,
                        .success = o.success,
                        .match_index = if (o.success) o.match_index else 0,
                    };
                    resp.encode(out[1..]);
                }
                try wire.writeFrame(w, &out);
            },
            else => return,
        }
    }

    // ── client handlers ─────────────────────────────────────────────────────

    fn handleClient(self: *Node, cmd: wire.ClientCmd, w: *std.Io.Writer) !void {
        switch (cmd.kind) {
            .c_put, .c_del => try self.clientWrite(cmd, w),
            .c_get => {
                self.lock.lock();
                if (self.role != .leader) {
                    const hint = self.leader_hint;
                    self.lock.unlock();
                    try self.redirect(w, hint);
                    return;
                }
                const held = self.applied.get(cmd.key);
                // Copy under the lock; the map can change the moment we drop it.
                const copy: ?[]u8 = if (held) |v| try self.gpa.dupe(u8, v) else null;
                self.lock.unlock();
                if (copy) |v| {
                    defer self.gpa.free(v);
                    try self.reply(w, .ok, v);
                } else try self.reply(w, .notfound, "");
            },
            .c_dump => try self.dump(w),
            else => try self.reply(w, .err, "unknown command"),
        }
    }

    fn redirect(self: *Node, w: *std.Io.Writer, hint: raft.NodeId) !void {
        var body: [4]u8 = undefined;
        std.mem.writeInt(u32, &body, hint, .little);
        try self.reply(w, .redirect, &body);
    }

    fn clientWrite(self: *Node, cmd: wire.ClientCmd, w: *std.Io.Writer) !void {
        const op: wire.Op = if (cmd.kind == .c_put) .set else .del;
        const blob = try wire.encodeOp(self.gpa, op, cmd.key, cmd.value);
        defer self.gpa.free(blob);

        self.lock.lock();
        if (self.role != .leader) {
            const hint = self.leader_hint;
            self.lock.unlock();
            try self.redirect(w, hint);
            return;
        }
        const entry_term = self.term;
        const idx = self.appendLocked(
            .{ .term = entry_term, .kind = .command, .command = wire.commandHash(blob) },
            blob,
        ) catch |err| {
            self.lock.unlock();
            std.debug.print("raft-kv[{d}]: append failed: {t}\n", .{ self.id, err });
            try self.reply(w, .err, "append failed");
            return;
        };
        self.lock.unlock();

        // Wait for commit + apply. The entry is ours only while
        // log[idx].term == entry_term — a truncation by a new leader replaces
        // it, and success then would be a lie.
        const deadline = nowMs() + commit_wait_ms;
        while (nowMs() < deadline) {
            self.io.sleep(.fromMilliseconds(10), .awake) catch break;
            self.lock.lock();
            const t = self.log.termAt(idx);
            if (t == null or t.? != entry_term) {
                self.lock.unlock();
                try self.reply(w, .err, "lost leadership before commit");
                return;
            }
            if (self.applied_idx >= idx) {
                self.lock.unlock();
                try self.reply(w, .ok, "");
                return;
            }
            self.lock.unlock();
        }
        try self.reply(w, .err, "commit timed out (no majority?)");
    }

    fn dump(self: *Node, w: *std.Io.Writer) !void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        self.lock.lock();
        {
            errdefer self.lock.unlock();
            try body.append(self.gpa, switch (self.role) {
                .follower => 'f',
                .candidate => 'c',
                .leader => 'l',
            });
            var num: [8]u8 = undefined;
            std.mem.writeInt(u64, &num, self.term, .little);
            try body.appendSlice(self.gpa, &num);
            var cnt: [4]u8 = undefined;
            std.mem.writeInt(u32, &cnt, self.applied.count(), .little);
            try body.appendSlice(self.gpa, &cnt);
            var it = self.applied.iterator();
            while (it.next()) |e| {
                var klen: [2]u8 = undefined;
                std.mem.writeInt(u16, &klen, @intCast(e.key_ptr.*.len), .little);
                try body.appendSlice(self.gpa, &klen);
                try body.appendSlice(self.gpa, e.key_ptr.*);
                var vlen: [4]u8 = undefined;
                std.mem.writeInt(u32, &vlen, @intCast(e.value_ptr.*.len), .little);
                try body.appendSlice(self.gpa, &vlen);
                try body.appendSlice(self.gpa, e.value_ptr.*);
            }
        }
        self.lock.unlock();
        try self.reply(w, .dump, body.items);
    }
};

// ── SIGTERM/SIGINT → clean exit, so the leak check actually runs ────────────

var stop_requested: std.atomic.Value(bool) = .init(false);

fn onStopSignal(_: std.posix.SIG) callconv(.c) void {
    stop_requested.store(true, .release);
}

fn installStopHandlers() void {
    var act: std.posix.Sigaction = .{
        .handler = .{ .handler = onStopSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
}
