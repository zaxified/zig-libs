// SPDX-License-Identifier: MIT

//! One Raft server: real TCP, real timers, real disk around the `raft`
//! module's `raft.Node` state machine. Every consensus STEP — elections,
//! replication, commit, truncation — is `raft.Node`'s (`tick`, `stepBytes`,
//! `propose`, then `ready`/`advance`); this file only supplies what the node
//! does not own: the transport, the disk (`kv`, via `store.zig`), the clock,
//! the threads, the KV state machine and the client protocol.
//!
//! The loop around every input is `drainLocked`, in the order Figure 2
//! requires: persist what `ready` says, collect its messages, apply its
//! committed entries, `advance`. The collected frames are handed to the
//! per-peer sender threads only AFTER the lock is dropped, so no vote or
//! acknowledgement leaves this machine before the state it promises is on disk.
//!
//! Threading model, deliberately coarse: one `SpinLock` over the node, the
//! store and the applied map. Network I/O never happens under it. Threads:
//! the accept loop (main), one ticker, one sender per peer (a small drop-oldest
//! queue; Raft tolerates loss), one thread per accepted connection, and a stop
//! watcher. Peer traffic is one-way: a message is one frame on a fresh
//! connection to its destination; responses are ordinary messages.

const std = @import("std");
const raft = @import("raft");
const lockfree = @import("lockfree");
const wire = @import("wire.zig");
const store_mod = @import("store.zig");

/// One tick of the node's clock. Heartbeat 50 ms, election 300-600 ms.
const tick_ms = 10;
const heartbeat_ticks = 5;
const election_ticks = 30;
const election_jitter_ticks = 30;
/// Entries per AppendEntries. Bounded so a full message of maximal operations
/// (about 65 KiB each) stays under `wire.limits.max_frame`.
const max_append_entries = 8;
/// Frames queued per peer before the oldest is dropped.
const max_queue = 256;
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

pub fn serve(gpa: std.mem.Allocator, io: std.Io, opts: Options) !void {
    var node: Node = undefined;
    try node.init(gpa, io, opts);
    defer node.deinit();
    try node.run();
}

/// An encoded peer frame (kind ++ from ++ message) and where it goes.
const Out = struct { to: u32, bytes: []u8 };

/// Outbound queue of one peer. Its own lock: pushing never waits for the
/// node lock's holder's I/O (there is none), but keeps senders independent.
const Peer = struct {
    lock: lockfree.SpinLock = .{},
    q: std.ArrayList([]u8) = .empty,
};

const Node = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    id: u32,
    n: usize,
    addrs: []std.Io.net.IpAddress,
    peers: []Peer,

    lock: lockfree.SpinLock = .{},
    // ── guarded by `lock` ───────────────────────────────────────────────────
    node: raft.Node,
    store: store_mod.Store,
    /// Highest log index the store holds.
    stored_last: raft.LogIndex = 0,
    applied: std.StringHashMapUnmanaged([]u8) = .empty,
    /// For the role-change log lines only.
    seen_role: raft.Role = .follower,
    seen_term: raft.Term = 0,
    // ────────────────────────────────────────────────────────────────────────

    stop: std.atomic.Value(bool) = .init(false),
    /// Every DETACHED thread that touches `*Node` (accepted connections) is
    /// counted here so shutdown can wait for all of them before `deinit` frees
    /// the state they hold. Missing this on detached threads was a real
    /// use-after-free.
    live_threads: std.atomic.Value(usize) = .init(0),
    listen_addr: std.Io.net.IpAddress,

    fn init(self: *Node, gpa: std.mem.Allocator, io: std.Io, opts: Options) !void {
        const n = opts.peers.len;
        const addrs = try gpa.alloc(std.Io.net.IpAddress, n);
        errdefer gpa.free(addrs);
        const peers = try gpa.alloc(Peer, n);
        errdefer gpa.free(peers);
        for (peers) |*p| p.* = .{};

        for (opts.peers, 0..) |p, i| {
            const colon = std.mem.lastIndexOfScalar(u8, p, ':') orelse return error.BadPeerAddress;
            const port = std.fmt.parseInt(u16, p[colon + 1 ..], 10) catch return error.BadPeerAddress;
            addrs[i] = std.Io.net.IpAddress.parse(p[0..colon], port) catch return error.BadPeerAddress;
        }

        self.* = .{
            .gpa = gpa,
            .io = io,
            .id = opts.id,
            .n = n,
            .addrs = addrs,
            .peers = peers,
            .node = undefined,
            .store = undefined,
            .listen_addr = addrs[opts.id],
        };
        try self.store.open(gpa, io, opts.data);
        errdefer self.store.close();

        // Recover: persistent state, then the log (dense from 1). The applied
        // state machine is NOT recovered — `Restore.applied = 0` makes the
        // node re-deliver committed entries as it re-learns the commit index,
        // which is Figure 2's contract for volatile state.
        const meta = self.store.loadMeta();
        var entries: std.ArrayList(raft.Entry) = .empty;
        defer {
            for (entries.items) |e| gpa.free(e.data);
            entries.deinit(gpa);
        }
        var idx: raft.LogIndex = 1;
        while (try self.store.getEntry(gpa, idx)) |e| : (idx += 1) {
            errdefer gpa.free(e.data);
            try entries.append(gpa, e);
        }

        var seed: [8]u8 = undefined;
        try io.randomSecure(&seed);
        self.node = try raft.Node.init(gpa, .{
            .id = opts.id,
            .cluster_size = @intCast(n),
            .election_ticks = election_ticks,
            .election_jitter_ticks = election_jitter_ticks,
            .heartbeat_ticks = heartbeat_ticks,
            .max_append_entries = max_append_entries,
            .seed = std.mem.readInt(u64, &seed, .little),
        }, .{
            .hard_state = .{ .term = meta.term, .voted_for = meta.vote },
            .entries = entries.items,
        });
        self.stored_last = entries.items.len;
        self.seen_term = self.node.term;
        std.debug.print("raft-kv[{d}]: recovered term={d} log={d} entries\n", .{ self.id, self.node.term, self.node.lastIndex() });
    }

    fn deinit(self: *Node) void {
        const gpa = self.gpa;
        self.node.deinit();
        var it = self.applied.iterator();
        while (it.next()) |e| {
            gpa.free(e.key_ptr.*);
            gpa.free(e.value_ptr.*);
        }
        self.applied.deinit(gpa);
        self.store.close();
        for (self.peers) |*p| {
            for (p.q.items) |f| gpa.free(f);
            p.q.deinit(gpa);
        }
        gpa.free(self.peers);
        gpa.free(self.addrs);
    }

    fn nowMs() u64 {
        var ts: std.posix.timespec = undefined;
        if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
    }

    /// A failed disk or allocation mid-`ready` leaves the node between
    /// `ready` and `advance`; the only safe continuation is Raft's own failure
    /// model — crash, and recover from what is durable.
    fn fatal(self: *Node, what: []const u8, err: anyerror) noreturn {
        std.debug.print("raft-kv[{d}]: FATAL {s}: {t} — exiting, state recovers from disk\n", .{ self.id, what, err });
        std.process.exit(1);
    }

    // ── the drain loop ──────────────────────────────────────────────────────

    /// Call with the lock held after every `tick`/`stepBytes`/`propose`:
    /// persist, collect the frames to send, apply, advance. Frames go to `out`;
    /// the caller sends them via `dispatch` once the lock is released.
    fn drainLocked(self: *Node, out: *std.ArrayList(Out)) void {
        while (self.node.hasReady()) {
            const rd = self.node.ready() catch |err| self.fatal("ready", err);
            // 1. persist
            if (rd.hard_state) |hs| self.store.saveMeta(hs.term, hs.voted_for) catch |err| self.fatal("saveMeta", err);
            if (rd.truncate_after) |t| {
                while (self.stored_last > t) : (self.stored_last -= 1)
                    self.store.delEntry(self.stored_last) catch |err| self.fatal("delEntry", err);
            }
            for (rd.entries) |e| {
                self.store.putEntry(self.gpa, e) catch |err| self.fatal("putEntry", err);
                self.stored_last = e.index;
            }
            // 2. collect messages (sent by the caller, after the lock)
            for (rd.messages) |m| {
                const need = 5 + m.encodedLen();
                const buf = self.gpa.alloc(u8, need) catch |err| self.fatal("encode", err);
                buf[0] = @intFromEnum(wire.Kind.rpc);
                std.mem.writeInt(u32, buf[1..5], m.from, .little);
                _ = m.encode(buf[5..]);
                out.append(self.gpa, .{ .to = m.to, .bytes = buf }) catch |err| self.fatal("queue", err);
            }
            // 3. apply
            for (rd.committed) |e| {
                if (e.kind != .command) continue;
                const op = wire.decodeOp(e.data) orelse continue;
                self.applyOp(op) catch |err| {
                    std.debug.print("raft-kv[{d}]: apply {d}: {t}\n", .{ self.id, e.index, err });
                };
            }
            self.node.advance() catch |err| self.fatal("advance", err);
        }
        if (self.node.role != self.seen_role or self.node.term != self.seen_term) {
            self.seen_role = self.node.role;
            self.seen_term = self.node.term;
            switch (self.node.role) {
                .candidate => std.debug.print("raft-kv[{d}]: term={d} standing for election\n", .{ self.id, self.node.term }),
                .leader => std.debug.print("raft-kv[{d}]: term={d} LEADER\n", .{ self.id, self.node.term }),
                .follower => {},
            }
        }
    }

    /// Hand collected frames to the per-peer queues. No lock needed beyond the
    /// queues' own; never blocks on the network.
    fn dispatch(self: *Node, out: *std.ArrayList(Out)) void {
        defer out.deinit(self.gpa);
        for (out.items) |f| {
            if (f.to >= self.n or f.to == self.id) {
                self.gpa.free(f.bytes);
                continue;
            }
            const p = &self.peers[f.to];
            p.lock.lock();
            defer p.lock.unlock();
            if (p.q.items.len >= max_queue) self.gpa.free(p.q.orderedRemove(0));
            p.q.append(self.gpa, f.bytes) catch self.gpa.free(f.bytes);
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
        var sender_threads = try self.gpa.alloc(std.Thread, self.n);
        defer self.gpa.free(sender_threads);
        var spawned: usize = 0;
        defer for (sender_threads[0..spawned]) |t| t.join();
        for (0..self.n) |i| {
            if (i == self.id) continue;
            sender_threads[spawned] = try std.Thread.spawn(.{}, senderLoop, .{ self, @as(u32, @intCast(i)) });
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
            // In-flight connections are all one frame with bounded
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
        // Wait UNCONDITIONALLY for every detached thread (connections) to
        // release `*Node` before returning — `serve` runs `deinit` the moment
        // we return, and a straggler still inside `self.lock`/`self.node`
        // would then touch freed state. The earlier soft deadline
        // here would elapse and let `deinit` proceed under a live thread; that
        // was the use-after-free. Every counted thread finishes on its own
        // (a client request is bounded by commit_wait_ms; a peer frame is one
        // read), so this terminates in every case the demo produces.
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

    // ── ticker ──────────────────────────────────────────────────────────────

    fn tickerLoop(self: *Node) void {
        while (!self.stop.load(.acquire)) {
            self.io.sleep(.fromMilliseconds(tick_ms), .awake) catch return;
            var out: std.ArrayList(Out) = .empty;
            self.lock.lock();
            self.node.tick() catch |err| self.fatal("tick", err);
            self.drainLocked(&out);
            self.lock.unlock();
            self.dispatch(&out);
        }
    }

    // ── senders: one per peer, one frame per fresh connection ───────────────

    fn senderLoop(self: *Node, peer: u32) void {
        const p = &self.peers[peer];
        while (!self.stop.load(.acquire)) {
            p.lock.lock();
            const f: ?[]u8 = if (p.q.items.len > 0) p.q.orderedRemove(0) else null;
            p.lock.unlock();
            const frame = f orelse {
                self.io.sleep(.fromMilliseconds(2), .awake) catch return;
                continue;
            };
            defer self.gpa.free(frame);
            self.sendFrame(peer, frame) catch {}; // loss is fine; Raft retries
        }
    }

    fn sendFrame(self: *Node, peer: u32, frame: []const u8) !void {
        var stream = try self.addrs[peer].connect(self.io, .{ .mode = .stream });
        defer stream.close(self.io);
        var wbuf: [1024]u8 = undefined;
        var w = stream.writer(self.io, &wbuf);
        try wire.writeFrame(&w.interface, frame);
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
            if (frame.len < 5) return;
            const from = std.mem.readInt(u32, frame[1..5], .little);
            var out: std.ArrayList(Out) = .empty;
            self.lock.lock();
            // Undecodable or impossible messages are dropped and counted inside.
            self.node.stepBytes(from, frame[5..]) catch |err| self.fatal("step", err);
            self.drainLocked(&out);
            self.lock.unlock();
            self.dispatch(&out);
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

    // ── client handlers ─────────────────────────────────────────────────────

    fn handleClient(self: *Node, cmd: wire.ClientCmd, w: *std.Io.Writer) !void {
        switch (cmd.kind) {
            .c_put, .c_del => try self.clientWrite(cmd, w),
            .c_get => {
                self.lock.lock();
                if (self.node.role != .leader) {
                    const hint = self.node.leader;
                    self.lock.unlock();
                    try self.redirect(w, hint);
                    return;
                }
                const held = self.applied.get(cmd.key);
                // Copy under the lock; the map can change the moment we drop it.
                const copy: ?[]u8 = if (held) |v| self.gpa.dupe(u8, v) catch |err| {
                    self.lock.unlock();
                    return err;
                } else null;
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

        var out: std.ArrayList(Out) = .empty;
        self.lock.lock();
        const entry_term = self.node.term;
        const idx = self.node.propose(blob) catch |err| {
            const hint = self.node.leader;
            self.lock.unlock();
            switch (err) {
                error.NotLeader => try self.redirect(w, hint),
                error.OutOfMemory => try self.reply(w, .err, "append failed"),
                // Unreachable through wire.limits (1 MiB frames), kept honest.
                error.EntryTooLarge => try self.reply(w, .err, "command too large"),
            }
            return;
        };
        self.drainLocked(&out);
        self.lock.unlock();
        self.dispatch(&out);

        // Wait for commit + apply. The entry is ours only while
        // log[idx].term == entry_term — a truncation by a new leader replaces
        // it, and success then would be a lie.
        const deadline = nowMs() + commit_wait_ms;
        while (nowMs() < deadline) {
            self.io.sleep(.fromMilliseconds(10), .awake) catch break;
            self.lock.lock();
            const e = self.node.entryAt(idx);
            if (e == null or e.?.term != entry_term) {
                self.lock.unlock();
                try self.reply(w, .err, "lost leadership before commit");
                return;
            }
            if (self.node.applied >= idx) {
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
            try body.append(self.gpa, switch (self.node.role) {
                .follower => 'f',
                .candidate => 'c',
                .leader => 'l',
            });
            var num: [8]u8 = undefined;
            std.mem.writeInt(u64, &num, self.node.term, .little);
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
