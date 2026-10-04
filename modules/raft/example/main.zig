// SPDX-License-Identifier: MIT

//! What a consumer builds `raft` INTO: three `raft.Node`s replicating a tiny
//! key-value log, with the caller supplying everything a node does not own —
//! the clock (`tick`), the transport (here a FIFO of encoded frames; in a
//! deployment, TCP or QUIC), the disk (here a slice per node; in a deployment,
//! fsync) and the state machine (here a list of applied commands).
//!
//! The loop every server runs is the one in `drain`: persist what `ready`
//! says, THEN send its messages, THEN apply its committed entries, then
//! `advance`. Crashing a node below throws away everything but its disk, and
//! the restarted node catches up from the leader.
//!
//! Built against the PUBLISHED module (`@import("raft")`) only.

const std = @import("std");
const raft = @import("raft");

const N = 3;

const Server = struct {
    node: ?raft.Node = null,
    // "Disk": what survives a crash.
    hs: raft.HardState = .{},
    log: std.ArrayList(raft.Entry) = .empty,
    // State machine: rebuilt from the log on every start.
    applied: std.ArrayList([]const u8) = .empty,
};

const Frame = struct { from: raft.NodeId, to: raft.NodeId, bytes: []u8 };

const Cluster = struct {
    gpa: std.mem.Allocator,
    servers: [N]Server = @splat(.{}),
    wire: std.ArrayList(Frame) = .empty,

    fn start(c: *Cluster, id: raft.NodeId) !void {
        const s = &c.servers[id];
        s.node = try raft.Node.init(c.gpa, .{
            .id = id,
            .cluster_size = N,
            .election_ticks = 10,
            .election_jitter_ticks = 10,
            .heartbeat_ticks = 2,
            .seed = 0x5eed + id, // distinct per server: no lockstep timeouts
        }, .{ .hard_state = s.hs, .entries = s.log.items });
        s.applied.clearRetainingCapacity();
    }

    fn crash(c: *Cluster, id: raft.NodeId) void {
        c.servers[id].node.?.deinit();
        c.servers[id].node = null;
    }

    /// The contract, in its order: persist, send, apply, advance.
    fn drain(c: *Cluster, id: raft.NodeId) !void {
        const s = &c.servers[id];
        const node = &s.node.?;
        while (node.hasReady()) {
            const rd = try node.ready();
            // 1. persist
            if (rd.hard_state) |hs| s.hs = hs;
            if (rd.truncate_after) |t| {
                while (s.log.items.len > t) c.gpa.free(s.log.pop().?.data);
            }
            for (rd.entries) |e| {
                var owned = e;
                owned.data = try c.gpa.dupe(u8, e.data);
                try s.log.append(c.gpa, owned);
            }
            // 2. send
            for (rd.messages) |m| try c.wire.append(c.gpa, .{ .from = m.from, .to = m.to, .bytes = try m.encodeAlloc(c.gpa) });
            // 3. apply (the bytes stay valid: they live on this server's disk)
            for (rd.committed) |e| {
                if (e.kind == .command) try s.applied.append(c.gpa, s.log.items[@intCast(e.index - 1)].data);
            }
            try node.advance();
        }
    }

    fn deliverAll(c: *Cluster) !void {
        while (c.wire.items.len > 0) {
            const f = c.wire.orderedRemove(0);
            defer c.gpa.free(f.bytes);
            if (c.servers[f.to].node) |*node| {
                // A frame that does not decode is dropped and counted inside.
                try node.stepBytes(f.from, f.bytes);
                try c.drain(f.to);
            }
        }
    }

    fn tick(c: *Cluster, times: usize) !void {
        for (0..times) |_| {
            for (&c.servers, 0..) |*s, id| {
                if (s.node) |*node| {
                    try node.tick();
                    try c.drain(@intCast(id));
                }
            }
            try c.deliverAll();
        }
    }

    fn leader(c: *Cluster) ?raft.NodeId {
        for (c.servers, 0..) |s, id| {
            if (s.node) |node| if (node.role == .leader) return @intCast(id);
        }
        return null;
    }

    fn deinit(c: *Cluster) void {
        for (&c.servers) |*s| {
            if (s.node) |*node| node.deinit();
            for (s.log.items) |e| c.gpa.free(e.data);
            s.log.deinit(c.gpa);
            s.applied.deinit(c.gpa);
        }
        for (c.wire.items) |f| c.gpa.free(f.bytes);
        c.wire.deinit(c.gpa);
    }
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var c: Cluster = .{ .gpa = gpa };
    defer c.deinit();
    for (0..N) |id| try c.start(@intCast(id));

    try c.tick(40);
    const l = c.leader() orelse return error.NoLeaderElected;
    std.debug.print("node {d} is leader of term {d}\n", .{ l, c.servers[l].node.?.term });

    for ([_][]const u8{ "city=Brno", "river=Svratka" }) |cmd| _ = try c.servers[l].node.?.propose(cmd);
    try c.drain(l);
    try c.tick(5);

    // Crash a follower, keep writing, bring it back from its disk alone.
    const f: raft.NodeId = (l + 1) % N;
    c.crash(f);
    _ = try c.servers[l].node.?.propose("hill=Spilberk");
    try c.drain(l);
    try c.tick(5);
    try c.start(f);
    std.debug.print("node {d} restarted with {d} entries on disk, commit index {d}\n", .{
        f, c.servers[f].log.items.len, c.servers[f].node.?.commit,
    });
    try c.tick(10);

    for (c.servers, 0..) |s, id| {
        std.debug.print("node {d} applied:", .{id});
        for (s.applied.items) |a| std.debug.print(" {s}", .{a});
        std.debug.print("\n", .{});
        if (s.applied.items.len != 3) return error.NotReplicated;
    }
}
