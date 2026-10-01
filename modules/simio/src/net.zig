// SPDX-License-Identifier: MIT

//! The simulated network behind `std.Io.net`: hosts with addresses, links
//! between them, routed paths, and three kinds of socket.
//!
//! - **Datagrams** (`bind` with `.dgram`): each packet travels the path on its
//!   own, so it can be lost, duplicated, reordered or corrupted per link.
//! - **ICMP echo** (`.dgram` + `protocol = .icmp`/`.icmpv6`, a Linux ping
//!   socket): the destination host's simulated stack answers echo requests.
//! - **Streams** (`listen`/`connect`): reliable and in order, like TCP. A
//!   connection is a SYN/SYN-ACK handshake (SYN retried with backoff, RST when
//!   nothing listens); each direction is a FIFO pipe whose head is the only
//!   segment in flight, so order holds while loss shows up as retransmission
//!   delay, a partition as no progress (backoff, then the user timeout), and a
//!   closed peer as a reset. Flow control: a writer may have at most
//!   `tcp_window` bytes the peer application has not read yet; window updates
//!   travel back over the network. Reads return a seeded, sometimes short
//!   prefix of what is buffered, so framing bugs surface.
//!
//! Paths: the shortest path over the links that are up (Dijkstra by latency,
//! ties broken by host id), latency summed and faults drawn per link — the
//! generalization of axp-sim's tree model. Reachability is checked again on
//! arrival, so a link that fails while a packet is in flight drops it.
//!
//! Every draw comes from the network's own seeded stream, so changing a link
//! does not perturb the scheduler's choices.

const std = @import("std");
const netsim = @import("netsim");
const sched = @import("sched.zig");

const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Prng = netsim.Prng;
const Sim = sched.Sim;
const Host = sched.Host;
const Fiber = sched.Fiber;
const Handle = net.Socket.Handle;

const ns_per_us = std.time.ns_per_us;
const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

pub const LinkConfig = struct {
    /// One-way latency of this link.
    latency_ns: u64 = ns_per_ms,
    /// Extra latency drawn uniformly from `[0, jitter_ns]` per packet.
    jitter_ns: u64 = 0,
    loss_permille: u16 = 0,
    /// Datagrams only (a stream never delivers a byte twice).
    dup_permille: u16 = 0,
    /// Datagrams only: with this probability a packet is held back by up to
    /// `reorder_ns` more, so later packets can overtake it.
    reorder_permille: u16 = 0,
    reorder_ns: u64 = 0,
    /// Datagrams only: flip one bit of the payload (a stream's checksum would
    /// catch it, a datagram codec has to).
    corrupt_permille: u16 = 0,
};

pub const NetOptions = struct {
    /// Latency of a host talking to itself (loopback or its own address).
    loopback_latency_ns: u64 = 10 * ns_per_us,
    /// Probability that a stream read returns fewer bytes than are buffered.
    short_read_permille: u16 = 250,
    /// Bytes a stream writer may have outstanding (unread by the peer).
    tcp_window: usize = 256 * 1024,
    /// Largest stream segment.
    tcp_mss: usize = 1460,
    tcp_rto_min_ns: u64 = 200 * ns_per_ms,
    tcp_rto_max_ns: u64 = 60 * ns_per_s,
    /// How long `connect` keeps retrying SYN (Linux: ~127 s).
    tcp_syn_timeout_ns: u64 = 127 * ns_per_s,
    /// How long a stream keeps retransmitting into a dead path before the
    /// connection fails with `Timeout` (Linux `tcp_retries2`: ~15 min).
    tcp_user_timeout_ns: u64 = 900 * ns_per_s,
    /// Datagram receive buffer per socket; packets beyond it are dropped.
    udp_rcvbuf: usize = 256 * 1024,
};

/// One direction of a link: whether it carries traffic, and the one-shot
/// faults armed on it (from a fault schedule).
const Dir = struct { up: bool = true, drop: u32 = 0, dup: u32 = 0, delay_ns: u64 = 0 };

/// A link; `dir[0]` is a → b, `dir[1]` is b → a.
const Edge = struct {
    a: u32,
    b: u32,
    cfg: LinkConfig,
    dir: [2]Dir = .{ .{}, .{} },

    fn from(e: *const Edge, u: u32) ?u1 {
        if (e.a == u) return 0;
        if (e.b == u) return 1;
        return null;
    }

    fn other(e: *const Edge, d: u1) u32 {
        return if (d == 0) e.b else e.a;
    }
};

const Hop = struct { edge: u32, dir: u1 };

const Partition = struct { id: u32, cut: []u32 };

/// What the scheduler's event queue carries for the network.
pub const Event = union(enum) {
    packet: *Packet,
    pipe: *Pipe,
    syn_retry: u64,
};

const Packet = struct {
    kind: enum { udp, icmp, syn, synack, rst },
    src_host: u32,
    dst_host: u32,
    src: net.IpAddress,
    dst: net.IpAddress,
    data: []u8 = &.{},
    from_sid: u64 = 0,
    to_sid: u64 = 0,
};

const Seg = struct {
    at: u64,
    kind: enum { data, fin, rst, window },
    data: []u8 = &.{},
    n: usize = 0,
};

/// One direction of a stream connection. Owned by `Net`; outlives the
/// sending socket so bytes and the FIN already sent still arrive.
pub const Pipe = struct {
    from_host: u32,
    to_host: u32,
    from_sid: u64,
    to_sid: u64,
    segs: std.ArrayList(Seg) = .empty,
    head: usize = 0,
    last_at: u64 = 0,
    scheduled: bool = false,
    backoff: u64 = 0,
    failing_since: ?u64 = null,
    sender_open: bool = true,
};

const Dgram = struct { from: net.IpAddress, data: []u8 };

const StreamError = enum { reset, timeout, refused };

pub const Sock = struct {
    sid: u64,
    host: *Host,
    handle: Handle = -1,
    kind: enum { udp, icmp, listener, stream },
    local: net.IpAddress,
    waiters: std.ArrayList(*Fiber) = .empty,

    // datagram sockets
    dgrams: std.ArrayList(Dgram) = .empty,
    dgram_bytes: usize = 0,
    peer: ?net.IpAddress = null,

    // listeners
    accept_q: std.ArrayList(*Sock) = .empty,
    backlog: usize = 0,
    shut: bool = false,

    // streams
    state: enum { connecting, established } = .connecting,
    err: ?StreamError = null,
    remote: net.IpAddress = undefined,
    peer_host: u32 = 0,
    peer_sid: u64 = 0,
    rx: std.ArrayList(u8) = .empty,
    rx_head: usize = 0,
    rx_fin: bool = false,
    rx_shut: bool = false,
    tx_shut: bool = false,
    inflight: usize = 0,
    tx: ?*Pipe = null,
    syn_rto: u64 = 0,
    syn_deadline: u64 = 0,
    /// Server side: the client socket id this connection answered.
    syn_key: ?u64 = null,

    fn removeWaiter(s: *Sock, f: *Fiber) void {
        for (s.waiters.items, 0..) |w, i| if (w == f) {
            _ = s.waiters.orderedRemove(i);
            return;
        };
    }

    fn buffered(s: *const Sock) usize {
        return s.rx.items.len - s.rx_head;
    }
};

pub const Net = struct {
    sim: *Sim,
    prng: Prng,
    edges: std.ArrayList(Edge) = .empty,
    partitions: std.ArrayList(Partition) = .empty,
    socks: std.AutoHashMapUnmanaged(u64, *Sock) = .empty,
    pipes: std.AutoArrayHashMapUnmanaged(*Pipe, void) = .empty,
    syn_seen: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    next_sid: u64 = 1,
    // Dijkstra scratch, reused.
    dist: std.ArrayList(u64) = .empty,
    via: std.ArrayList(Hop) = .empty,
    done: std.ArrayList(bool) = .empty,
    path: std.ArrayList(Hop) = .empty,

    pub fn init(sim: *Sim, seed: u64) Net {
        return .{ .sim = sim, .prng = .init(seed ^ 0x6e65745f73696d21) };
    }

    pub fn deinit(n: *Net) void {
        const gpa = n.sim.gpa;
        var it = n.socks.valueIterator();
        while (it.next()) |s| freeSock(gpa, s.*);
        n.socks.deinit(gpa);
        for (n.pipes.keys()) |p| freePipe(gpa, p);
        n.pipes.deinit(gpa);
        n.syn_seen.deinit(gpa);
        n.edges.deinit(gpa);
        for (n.partitions.items) |p| gpa.free(p.cut);
        n.partitions.deinit(gpa);
        n.dist.deinit(gpa);
        n.via.deinit(gpa);
        n.done.deinit(gpa);
        n.path.deinit(gpa);
    }

    /// Releases what a pending event owns (called for events never fired).
    pub fn dropEvent(n: *Net, ev: Event) void {
        switch (ev) {
            .packet => |p| freePacket(n.sim.gpa, p),
            .pipe, .syn_retry => {},
        }
    }

    // ── topology ────────────────────────────────────────────────────────────

    fn findEdge(n: *Net, a: u32, b: u32) ?*Edge {
        for (n.edges.items) |*e| if ((e.a == a and e.b == b) or (e.a == b and e.b == a)) return e;
        return null;
    }

    /// The direction `from → to` of an existing link.
    fn dirOf(n: *Net, from: u32, to: u32) ?*Dir {
        const e = n.findEdge(from, to) orelse return null;
        return &e.dir[e.from(from).?];
    }

    pub fn link(n: *Net, a: u32, b: u32, cfg: LinkConfig) Allocator.Error!void {
        if (n.findEdge(a, b)) |e| {
            e.cfg = cfg;
            e.dir = .{ .{}, .{} };
            return;
        }
        try n.edges.append(n.sim.gpa, .{ .a = a, .b = b, .cfg = cfg });
    }

    pub fn setLinkUp(n: *Net, a: u32, b: u32, up: bool) error{NoSuchLink}!void {
        const e = n.findEdge(a, b) orelse return error.NoSuchLink;
        e.dir[0].up = up;
        e.dir[1].up = up;
    }

    /// One direction only: `from → to` stops (or resumes) carrying traffic
    /// while the reverse keeps working — a one-way failure.
    pub fn setDirUp(n: *Net, from: u32, to: u32, up: bool) error{NoSuchLink}!void {
        const d = n.dirOf(from, to) orelse return error.NoSuchLink;
        d.up = up;
    }

    /// Hosts in `cut` can no longer reach hosts outside it (and the other
    /// way round) until `heal(id)`.
    pub fn partition(n: *Net, id: u32, cut: []const u32) Allocator.Error!void {
        const gpa = n.sim.gpa;
        try n.partitions.ensureUnusedCapacity(gpa, 1);
        n.partitions.appendAssumeCapacity(.{ .id = id, .cut = try gpa.dupe(u32, cut) });
    }

    pub fn heal(n: *Net, id: u32) void {
        var i: usize = 0;
        while (i < n.partitions.items.len) {
            if (n.partitions.items[i].id == id) {
                n.sim.gpa.free(n.partitions.items[i].cut);
                _ = n.partitions.orderedRemove(i);
            } else i += 1;
        }
    }

    /// One-shot faults on the next packet crossing `from → to`: lost,
    /// duplicated (datagrams; a stream sees nothing), or held back.
    pub fn armDrop(n: *Net, from: u32, to: u32) void {
        const d = n.dirOf(from, to) orelse return;
        d.drop += 1;
    }

    pub fn armDup(n: *Net, from: u32, to: u32) void {
        const d = n.dirOf(from, to) orelse return;
        d.dup += 1;
    }

    pub fn armDelay(n: *Net, from: u32, to: u32, delay_ns: u64) void {
        const d = n.dirOf(from, to) orelse return;
        d.delay_ns += delay_ns;
    }

    fn inCut(cut: []const u32, h: u32) bool {
        return std.mem.indexOfScalar(u32, cut, h) != null;
    }

    fn partitioned(n: *const Net, u: u32, v: u32) bool {
        for (n.partitions.items) |p| if (inCut(p.cut, u) != inCut(p.cut, v)) return true;
        return false;
    }

    /// Shortest path from `src` to `dst` over link directions that are up,
    /// not cut by a partition and not through a down host, as hops from
    /// `dst` back to `src`; null when unreachable.
    fn route(n: *Net, src: u32, dst: u32) ?[]const Hop {
        const gpa = n.sim.gpa;
        const count = n.sim.hosts.items.len;
        n.dist.resize(gpa, count) catch return null;
        n.via.resize(gpa, count) catch return null;
        n.done.resize(gpa, count) catch return null;
        @memset(n.dist.items, std.math.maxInt(u64));
        @memset(n.done.items, false);
        n.dist.items[src] = 0;
        while (true) {
            var best: ?u32 = null;
            for (n.dist.items, n.done.items, 0..) |d, done, i| {
                if (done or d == std.math.maxInt(u64)) continue;
                if (best == null or d < n.dist.items[best.?]) best = @intCast(i);
            }
            const u = best orelse break;
            if (u == dst) break;
            n.done.items[u] = true;
            for (n.edges.items, 0..) |*e, ei| {
                const d = e.from(u) orelse continue;
                if (!e.dir[d].up) continue;
                const v = e.other(d);
                if (n.done.items[v] or !n.sim.hosts.items[v].up or n.partitioned(u, v)) continue;
                const nd = n.dist.items[u] + e.cfg.latency_ns + 1;
                if (nd < n.dist.items[v]) {
                    n.dist.items[v] = nd;
                    n.via.items[v] = .{ .edge = @intCast(ei), .dir = d };
                }
            }
        }
        if (n.dist.items[dst] == std.math.maxInt(u64)) return null;
        n.path.clearRetainingCapacity();
        var at = dst;
        while (at != src) {
            const hop = n.via.items[at];
            n.path.append(gpa, hop) catch return null;
            const e = n.edges.items[hop.edge];
            at = if (hop.dir == 0) e.a else e.b;
        }
        return n.path.items;
    }

    const Transit = struct { delay: u64, lost: bool, dup: bool, corrupt: bool };

    /// Draws one packet's fate on the current path (consuming one-shot
    /// faults armed on it); null when unreachable.
    fn transit(n: *Net, src: u32, dst: u32) ?Transit {
        const hosts = n.sim.hosts.items;
        if (!hosts[src].up or !hosts[dst].up) return null;
        if (src == dst) return .{ .delay = n.sim.opts.net.loopback_latency_ns, .lost = false, .dup = false, .corrupt = false };
        const path = n.route(src, dst) orelse return null;
        var t: Transit = .{ .delay = 0, .lost = false, .dup = false, .corrupt = false };
        for (path) |hop| {
            const e = &n.edges.items[hop.edge];
            const d = &e.dir[hop.dir];
            if (d.drop > 0) {
                d.drop -= 1;
                t.lost = true;
            }
            if (d.dup > 0) {
                d.dup -= 1;
                t.dup = true;
            }
            t.delay += d.delay_ns;
            d.delay_ns = 0;
            const c = e.cfg;
            t.delay += c.latency_ns + n.prng.belowWide(c.jitter_ns +| 1);
            if (n.prng.permille(c.loss_permille)) t.lost = true;
            if (n.prng.permille(c.dup_permille)) t.dup = true;
            if (n.prng.permille(c.corrupt_permille)) t.corrupt = true;
            if (n.prng.permille(c.reorder_permille)) t.delay += n.prng.belowWide(c.reorder_ns +| 1);
        }
        return t;
    }

    /// Can a packet already on its way from `src` still arrive at `dst`? The
    /// sender may have crashed since; the receiver must be up and the path
    /// open.
    fn reachable(n: *Net, src: u32, dst: u32) bool {
        if (!n.sim.hosts.items[dst].up) return false;
        return src == dst or n.route(src, dst) != null;
    }

    /// A crash: every socket of `h` vanishes without a FIN or a reset.
    /// Segments it already sent are still on the wire and arrive; what peers
    /// send to it later meets a dead host (and, after a restart, a reset).
    /// Waiters must already be detached (the host's tasks are gone).
    pub fn crashHost(n: *Net, h: *Host) void {
        var doomed: std.ArrayList(*Sock) = .empty;
        defer doomed.deinit(n.sim.gpa);
        var it = n.socks.valueIterator();
        while (it.next()) |s| if (s.*.host == h) {
            doomed.append(n.sim.gpa, s.*) catch {
                // No memory for the list: destroy in place, then rescan.
                s.*.waiters.clearRetainingCapacity();
                n.destroySock(s.*);
                it = n.socks.valueIterator();
            };
        };
        for (doomed.items) |s| {
            s.waiters.clearRetainingCapacity();
            n.destroySock(s);
        }
    }

    // ── addresses and ports ─────────────────────────────────────────────────

    /// The host an address names, as seen from `from`.
    fn hostOf(n: *Net, from: *Host, a: net.IpAddress) ?*Host {
        switch (a) {
            .ip4 => |v4| {
                if (v4.bytes[0] == 127 or std.mem.allEqual(u8, &v4.bytes, 0)) return from;
                for (n.sim.hosts.items) |h| if (std.mem.eql(u8, &h.ip4, &v4.bytes)) return h;
            },
            .ip6 => |v6| {
                if (isLoopback6(v6.bytes) or std.mem.allEqual(u8, &v6.bytes, 0)) return from;
                if (mapped4(v6.bytes)) |b4| {
                    if (b4[0] == 127) return from;
                    for (n.sim.hosts.items) |h| if (std.mem.eql(u8, &h.ip4, &b4)) return h;
                    return null;
                }
                for (n.sim.hosts.items) |h| if (std.mem.eql(u8, &h.ip6, &v6.bytes)) return h;
            },
        }
        return null;
    }

    fn newSid(n: *Net) u64 {
        defer n.next_sid += 1;
        return n.next_sid;
    }

    fn portTaken(h: *Host, kind: @FieldType(Sock, "kind"), port: u16) bool {
        var it = h.handles.valueIterator();
        while (it.next()) |s| {
            const same = switch (kind) {
                .udp => s.*.kind == .udp,
                .icmp => s.*.kind == .icmp,
                .listener, .stream => s.*.kind == .listener or s.*.kind == .stream,
            };
            if (same and s.*.local.getPort() == port) return true;
        }
        return false;
    }

    fn ephemeralPort(h: *Host, kind: @FieldType(Sock, "kind")) ?u16 {
        for (0..16384) |_| {
            const p = h.next_port;
            h.next_port = if (p == 65535) 49152 else p + 1;
            if (!portTaken(h, kind, p)) return p;
        }
        return null;
    }

    /// `h`'s own address in `family`, with `port`.
    fn ownAddress(h: *Host, family: net.IpAddress.Family, port: u16) net.IpAddress {
        return switch (family) {
            .ip4 => .{ .ip4 = .{ .bytes = h.ip4, .port = port } },
            .ip6 => .{ .ip6 = .{ .bytes = h.ip6, .port = port } },
        };
    }

    /// The address a packet leaving through `s` carries as its source.
    fn sourceOf(s: *const Sock) net.IpAddress {
        if (isUnspecified(s.local)) return ownAddress(s.host, s.local, s.local.getPort());
        return s.local;
    }

    fn newSock(n: *Net, h: *Host, kind: @FieldType(Sock, "kind"), local: net.IpAddress) Allocator.Error!*Sock {
        const gpa = n.sim.gpa;
        const s = try gpa.create(Sock);
        errdefer gpa.destroy(s);
        s.* = .{ .sid = n.newSid(), .host = h, .kind = kind, .local = local };
        try n.socks.put(gpa, s.sid, s);
        return s;
    }

    fn giveHandle(n: *Net, s: *Sock) Allocator.Error!Handle {
        const h = s.host;
        try h.handles.ensureUnusedCapacity(n.sim.gpa, 1);
        s.handle = h.next_handle;
        h.next_handle += 1;
        h.handles.putAssumeCapacity(s.handle, s);
        return s.handle;
    }

    /// Wakes every task waiting on `s`; each re-checks what it waits for.
    fn notify(n: *Net, s: *Sock) void {
        while (s.waiters.items.len > 0) n.sim.wake(s.waiters.items[0], .normal);
    }

    /// Removes the socket from every table and frees it; tasks waiting on it
    /// wake and find their handle gone.
    fn destroySock(n: *Net, s: *Sock) void {
        n.notify(s);
        if (s.handle >= 0) _ = s.host.handles.remove(s.handle);
        _ = n.socks.remove(s.sid);
        if (s.syn_key) |k| _ = n.syn_seen.remove(k);
        if (s.tx) |p| {
            p.sender_open = false;
            n.maybeFreePipe(p);
        }
        freeSock(n.sim.gpa, s);
    }

    fn freeSock(gpa: Allocator, s: *Sock) void {
        for (s.dgrams.items) |d| gpa.free(d.data);
        s.dgrams.deinit(gpa);
        s.accept_q.deinit(gpa);
        s.rx.deinit(gpa);
        s.waiters.deinit(gpa);
        gpa.destroy(s);
    }

    fn freePacket(gpa: Allocator, p: *Packet) void {
        gpa.free(p.data);
        gpa.destroy(p);
    }

    fn freePipe(gpa: Allocator, p: *Pipe) void {
        for (p.segs.items[p.head..]) |s| gpa.free(s.data);
        p.segs.deinit(gpa);
        gpa.destroy(p);
    }

    fn maybeFreePipe(n: *Net, p: *Pipe) void {
        if (p.sender_open or p.scheduled or p.head < p.segs.items.len) return;
        _ = n.pipes.swapRemove(p);
        freePipe(n.sim.gpa, p);
    }

    // ── packets ─────────────────────────────────────────────────────────────

    /// Sends a packet now. It may be dropped, delayed, duplicated or damaged
    /// on the way; reachability is checked again on arrival.
    fn transmit(n: *Net, p: *Packet) void {
        const gpa = n.sim.gpa;
        const t = n.transit(p.src_host, p.dst_host) orelse return freePacket(gpa, p);
        if (t.lost) return freePacket(gpa, p);
        const datagram = p.kind == .udp or p.kind == .icmp;
        if (datagram and t.corrupt and p.data.len > 0) {
            const bit = n.prng.below(p.data.len * 8);
            p.data[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        }
        if (datagram and t.dup) dup: {
            const copy = gpa.create(Packet) catch break :dup;
            copy.* = p.*;
            copy.data = gpa.dupe(u8, p.data) catch {
                gpa.destroy(copy);
                break :dup;
            };
            n.sim.scheduleNet(n.sim.now + t.delay + 1, .{ .packet = copy }) catch freePacket(gpa, copy);
        }
        n.sim.scheduleNet(n.sim.now + t.delay, .{ .packet = p }) catch freePacket(gpa, p);
    }

    fn control(n: *Net, kind: @FieldType(Packet, "kind"), src_host: u32, dst_host: u32, src: net.IpAddress, dst: net.IpAddress, from_sid: u64, to_sid: u64) void {
        const p = n.sim.gpa.create(Packet) catch return; // a lost control packet is a legal outcome
        p.* = .{ .kind = kind, .src_host = src_host, .dst_host = dst_host, .src = src, .dst = dst, .from_sid = from_sid, .to_sid = to_sid };
        n.transmit(p);
    }

    pub fn fire(n: *Net, ev: Event) void {
        switch (ev) {
            .packet => |p| {
                defer freePacket(n.sim.gpa, p);
                if (!n.reachable(p.src_host, p.dst_host)) return;
                switch (p.kind) {
                    .udp => n.arriveDatagram(p),
                    .icmp => n.arriveIcmp(p),
                    .syn => n.arriveSyn(p),
                    .synack => n.arriveSynAck(p),
                    .rst => if (n.socks.get(p.to_sid)) |s| {
                        s.err = if (s.state == .connecting) .refused else .reset;
                        n.notify(s);
                    },
                }
            },
            .pipe => |p| n.firePipe(p),
            .syn_retry => |sid| n.synRetry(sid),
        }
    }

    fn arriveDatagram(n: *Net, p: *Packet) void {
        const h = n.sim.hosts.items[p.dst_host];
        var it = h.handles.valueIterator();
        const s = while (it.next()) |c| {
            const cand = c.*;
            if (cand.kind != .udp or cand.local.getPort() != p.dst.getPort()) continue;
            if (!isUnspecified(cand.local) and !sameIp(cand.local, p.dst)) continue;
            if (cand.peer) |peer| if (!peer.eql(&p.src)) continue;
            break cand;
        } else return; // nobody listening: dropped (no ICMP port-unreachable yet)
        n.queueDatagram(s, p.src, p);
    }

    fn queueDatagram(n: *Net, s: *Sock, from: net.IpAddress, p: *Packet) void {
        if (s.dgram_bytes + p.data.len > n.sim.opts.net.udp_rcvbuf) return;
        s.dgrams.append(n.sim.gpa, .{ .from = from, .data = p.data }) catch return;
        s.dgram_bytes += p.data.len;
        p.data = &.{}; // ownership moved to the queue
        n.notify(s);
    }

    fn arriveIcmp(n: *Net, p: *Packet) void {
        if (p.data.len < 8) return;
        const v6 = p.dst == .ip6;
        const request: u8 = if (v6) 128 else 8;
        const reply: u8 = if (v6) 129 else 0;
        if (p.data[0] == request) {
            // The destination's stack answers; no socket involved.
            const r = n.sim.gpa.create(Packet) catch return;
            r.* = .{
                .kind = .icmp,
                .src_host = p.dst_host,
                .dst_host = p.src_host,
                .src = withPort(p.dst, 0),
                .dst = p.src,
                .data = p.data,
            };
            p.data = &.{};
            r.data[0] = reply;
            if (!v6) setIcmp4Checksum(r.data);
            n.transmit(r);
            return;
        }
        if (p.data[0] != reply) return;
        const h = n.sim.hosts.items[p.dst_host];
        var it = h.handles.valueIterator();
        while (it.next()) |c| {
            const s = c.*;
            if (s.kind == .icmp and s.local.getPort() == p.dst.getPort()) return n.queueDatagram(s, p.src, p);
        }
    }

    fn arriveSyn(n: *Net, p: *Packet) void {
        const gpa = n.sim.gpa;
        const h = n.sim.hosts.items[p.dst_host];
        if (n.syn_seen.get(p.from_sid)) |server_sid| {
            // Our SYN-ACK was lost and the client retried: answer again.
            if (n.socks.get(server_sid)) |c|
                n.control(.synack, p.dst_host, p.src_host, c.local, p.src, c.sid, p.from_sid);
            return;
        }
        var it = h.handles.valueIterator();
        const listener = while (it.next()) |c| {
            const cand = c.*;
            if (cand.kind != .listener or cand.shut or cand.local.getPort() != p.dst.getPort()) continue;
            if (!isUnspecified(cand.local) and !sameIp(cand.local, p.dst)) continue;
            break cand;
        } else {
            n.control(.rst, p.dst_host, p.src_host, p.dst, p.src, 0, p.from_sid);
            return;
        };
        if (listener.accept_q.items.len >= listener.backlog) return; // the client retries
        listener.accept_q.ensureUnusedCapacity(gpa, 1) catch return;
        n.syn_seen.ensureUnusedCapacity(gpa, 1) catch return;
        n.pipes.ensureUnusedCapacity(gpa, 1) catch return;
        const pipe = gpa.create(Pipe) catch return;
        const c = n.newSock(h, .stream, p.dst) catch {
            gpa.destroy(pipe);
            return;
        };
        pipe.* = .{ .from_host = p.dst_host, .to_host = p.src_host, .from_sid = c.sid, .to_sid = p.from_sid };
        n.pipes.putAssumeCapacity(pipe, {});
        c.* = .{
            .sid = c.sid,
            .host = h,
            .kind = .stream,
            .local = p.dst,
            .state = .established,
            .remote = p.src,
            .peer_host = p.src_host,
            .peer_sid = p.from_sid,
            .tx = pipe,
            .syn_key = p.from_sid,
        };
        n.syn_seen.putAssumeCapacity(p.from_sid, c.sid);
        listener.accept_q.appendAssumeCapacity(c);
        n.notify(listener);
        n.control(.synack, p.dst_host, p.src_host, p.dst, p.src, c.sid, p.from_sid);
    }

    fn arriveSynAck(n: *Net, p: *Packet) void {
        const gpa = n.sim.gpa;
        const s = n.socks.get(p.to_sid) orelse {
            n.control(.rst, p.dst_host, p.src_host, p.dst, p.src, 0, p.from_sid);
            return;
        };
        if (s.state == .established) return; // a duplicate answer
        if (s.err != null) return;
        n.pipes.ensureUnusedCapacity(gpa, 1) catch return; // the SYN retry will try again
        const pipe = gpa.create(Pipe) catch return;
        pipe.* = .{ .from_host = s.host.id, .to_host = p.src_host, .from_sid = s.sid, .to_sid = p.from_sid };
        n.pipes.putAssumeCapacity(pipe, {});
        s.peer_sid = p.from_sid;
        s.tx = pipe;
        s.state = .established;
        n.notify(s);
    }

    fn sendSyn(n: *Net, s: *Sock) void {
        n.control(.syn, s.host.id, s.peer_host, sourceOf(s), s.remote, s.sid, 0);
        n.sim.scheduleNet(n.sim.now + s.syn_rto, .{ .syn_retry = s.sid }) catch {};
    }

    fn synRetry(n: *Net, sid: u64) void {
        const s = n.socks.get(sid) orelse return;
        if (s.state != .connecting or s.err != null) return;
        if (n.sim.now >= s.syn_deadline) {
            s.err = .timeout;
            n.notify(s);
            return;
        }
        s.syn_rto = @min(s.syn_rto * 2, n.sim.opts.net.tcp_rto_max_ns);
        n.sendSyn(s);
    }

    // ── stream pipes ────────────────────────────────────────────────────────

    fn pushSeg(n: *Net, p: *Pipe, seg_in: Seg) Allocator.Error!void {
        const o = n.sim.opts.net;
        var seg = seg_in;
        var at = n.sim.now;
        if (n.transit(p.from_host, p.to_host)) |first| {
            var t = first;
            var rto = o.tcp_rto_min_ns;
            // A lost segment arrives one retransmission timeout later, then
            // the next copy takes its own chances.
            while (t.lost) {
                at += rto;
                rto = @min(rto * 2, o.tcp_rto_max_ns);
                t = n.transit(p.from_host, p.to_host) orelse break;
            } else at += t.delay;
        }
        seg.at = @max(at, p.last_at);
        p.last_at = seg.at;
        try p.segs.append(n.sim.gpa, seg);
        if (!p.scheduled) {
            try n.sim.scheduleNet(@max(p.segs.items[p.head].at, n.sim.now), .{ .pipe = p });
            p.scheduled = true;
        }
    }

    fn firePipe(n: *Net, p: *Pipe) void {
        const gpa = n.sim.gpa;
        const o = n.sim.opts.net;
        p.scheduled = false;
        if (p.head >= p.segs.items.len) return n.maybeFreePipe(p);
        if (!n.reachable(p.from_host, p.to_host)) {
            const since = p.failing_since orelse blk: {
                p.failing_since = n.sim.now;
                p.backoff = o.tcp_rto_min_ns;
                break :blk n.sim.now;
            };
            if (n.sim.now - since >= o.tcp_user_timeout_ns) {
                if (n.socks.get(p.from_sid)) |sender| {
                    sender.err = .timeout;
                    n.notify(sender);
                }
                for (p.segs.items[p.head..]) |s| gpa.free(s.data);
                p.segs.clearRetainingCapacity();
                p.head = 0;
                return n.maybeFreePipe(p);
            }
            n.sim.scheduleNet(n.sim.now + p.backoff, .{ .pipe = p }) catch return;
            p.scheduled = true;
            p.backoff = @min(p.backoff * 2, o.tcp_rto_max_ns);
            return;
        }
        p.failing_since = null;
        const seg = p.segs.items[p.head];
        p.head += 1;
        if (p.head == p.segs.items.len) {
            p.segs.clearRetainingCapacity();
            p.head = 0;
        }
        n.deliverSeg(p, seg);
        gpa.free(seg.data);
        if (p.head < p.segs.items.len) {
            n.sim.scheduleNet(@max(p.segs.items[p.head].at, n.sim.now), .{ .pipe = p }) catch return;
            p.scheduled = true;
        } else n.maybeFreePipe(p);
    }

    fn deliverSeg(n: *Net, p: *Pipe, seg: Seg) void {
        const r = n.socks.get(p.to_sid) orelse {
            // The receiver is gone: data or a FIN for a closed socket is
            // answered with a reset; a bare window update (an ACK) is not.
            if (seg.kind == .data or seg.kind == .fin) {
                const hosts = n.sim.hosts.items;
                n.control(.rst, p.to_host, p.from_host, ownAddress(hosts[p.to_host], .ip4, 0), ownAddress(hosts[p.from_host], .ip4, 0), 0, p.from_sid);
            }
            return;
        };
        switch (seg.kind) {
            .data => if (!r.rx_shut) r.rx.appendSlice(n.sim.gpa, seg.data) catch {},
            .fin => r.rx_fin = true,
            .rst => r.err = .reset,
            .window => r.inflight -= @min(seg.n, r.inflight),
        }
        n.notify(r);
    }

    // ── the vtable's network entries ────────────────────────────────────────

    pub fn listen(n: *Net, h: *Host, address: *const net.IpAddress, options: net.IpAddress.ListenOptions) net.IpAddress.ListenError!net.Socket {
        if (options.mode != .stream) return error.SocketModeUnsupported;
        if (options.protocol != .tcp) return error.ProtocolUnsupportedBySystem;
        if (!n.isLocal(h, address.*)) return error.AddressUnavailable;
        var local = address.*;
        if (local.getPort() == 0) {
            local.setPort(ephemeralPort(h, .listener) orelse return error.AddressInUse);
        } else if (portTaken(h, .listener, local.getPort())) return error.AddressInUse;
        const s = n.newSock(h, .listener, local) catch return error.SystemResources;
        s.backlog = @max(options.kernel_backlog, 1);
        _ = n.giveHandle(s) catch {
            n.destroySock(s);
            return error.SystemResources;
        };
        return .{ .handle = s.handle, .address = local };
    }

    pub fn bind(n: *Net, h: *Host, address: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
        if (options.mode != .dgram) return error.SocketModeUnsupported;
        const kind: @FieldType(Sock, "kind") = if (options.protocol) |p| switch (p) {
            .udp => .udp,
            .icmp, .icmpv6 => .icmp,
            else => return error.ProtocolUnsupportedBySystem,
        } else .udp;
        if (!n.isLocal(h, address.*)) return error.AddressUnavailable;
        var local = address.*;
        if (local.getPort() == 0) {
            local.setPort(ephemeralPort(h, kind) orelse return error.AddressInUse);
        } else if (portTaken(h, kind, local.getPort())) return error.AddressInUse;
        const s = n.newSock(h, kind, local) catch return error.SystemResources;
        _ = n.giveHandle(s) catch {
            n.destroySock(s);
            return error.SystemResources;
        };
        return .{ .handle = s.handle, .address = local };
    }

    pub fn connect(n: *Net, h: *Host, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
        const sim = n.sim;
        const me = sim.running();
        try sim.cancelPoint(me);
        const dst = n.hostOf(h, address.*) orelse return error.NetworkUnreachable;
        const family: net.IpAddress.Family = address.*;
        if (options.mode == .dgram) {
            const local = ownAddress(h, family, ephemeralPort(h, .udp) orelse return error.AddressUnavailable);
            const s = n.newSock(h, .udp, local) catch return error.SystemResources;
            s.peer = address.*;
            _ = n.giveHandle(s) catch {
                n.destroySock(s);
                return error.SystemResources;
            };
            return .{ .handle = s.handle, .address = local };
        }
        if (options.mode != .stream) return error.SocketModeUnsupported;
        const local = ownAddress(h, family, ephemeralPort(h, .stream) orelse return error.AddressUnavailable);
        const s = n.newSock(h, .stream, local) catch return error.SystemResources;
        const handle = n.giveHandle(s) catch {
            n.destroySock(s);
            return error.SystemResources;
        };
        s.remote = address.*;
        s.peer_host = dst.id;
        s.syn_rto = ns_per_s;
        s.syn_deadline = sim.now + sim.opts.net.tcp_syn_timeout_ns;
        n.sendSyn(s);
        const deadline = sim.deadlineOf(h, options.timeout);
        while (true) {
            const cur = h.handles.get(handle) orelse return error.ConnectionResetByPeer;
            if (cur.state == .established) return .{ .handle = handle, .address = local };
            if (cur.err) |e| {
                n.destroySock(cur);
                return switch (e) {
                    .refused => error.ConnectionRefused,
                    .reset => error.ConnectionResetByPeer,
                    .timeout => error.Timeout,
                };
            }
            const reason = n.waitOn(me, cur, deadline) catch {
                n.destroySock(cur);
                return error.SystemResources;
            };
            switch (reason) {
                .canceled => {
                    if (h.handles.get(handle)) |c| n.destroySock(c);
                    me.acknowledgeCancel();
                    return error.Canceled;
                },
                .timeout => {
                    if (h.handles.get(handle)) |c| n.destroySock(c);
                    return error.Timeout;
                },
                .normal => {},
            }
        }
    }

    pub fn accept(n: *Net, h: *Host, handle: Handle) net.Server.AcceptError!net.Socket {
        const me = n.sim.running();
        try n.sim.cancelPoint(me);
        while (true) {
            const s = h.handles.get(handle) orelse return error.SocketNotListening;
            if (s.kind != .listener or s.shut) return error.SocketNotListening;
            if (s.accept_q.items.len > 0) {
                const c = s.accept_q.orderedRemove(0);
                _ = n.giveHandle(c) catch {
                    n.destroySock(c);
                    return error.SystemResources;
                };
                return .{ .handle = c.handle, .address = c.remote };
            }
            switch (n.waitOn(me, s, null) catch return error.SystemResources) {
                .canceled => {
                    me.acknowledgeCancel();
                    return error.Canceled;
                },
                .timeout, .normal => {},
            }
        }
    }

    pub fn read(n: *Net, h: *Host, handle: Handle, data: [][]u8) net.Stream.Reader.Error!usize {
        const me = n.sim.running();
        try n.sim.cancelPoint(me);
        while (true) {
            const s = h.handles.get(handle) orelse return error.SocketUnconnected;
            if (s.kind != .stream) return error.SocketUnconnected;
            if (s.err) |e| return switch (e) {
                .reset, .refused => error.ConnectionResetByPeer,
                .timeout => error.Timeout,
            };
            const avail = s.buffered();
            if (avail > 0 and !s.rx_shut) {
                var cap: usize = 0;
                for (data) |d| cap += d.len;
                var want = @min(avail, cap);
                if (want > 1 and n.prng.permille(n.sim.opts.net.short_read_permille)) want = 1 + n.prng.below(want);
                var copied: usize = 0;
                for (data) |d| {
                    if (copied == want) break;
                    const k = @min(d.len, want - copied);
                    @memcpy(d[0..k], s.rx.items[s.rx_head + copied ..][0..k]);
                    copied += k;
                }
                s.rx_head += copied;
                if (s.rx_head == s.rx.items.len) {
                    s.rx.clearRetainingCapacity();
                    s.rx_head = 0;
                }
                if (s.tx) |p| n.pushSeg(p, .{ .at = 0, .kind = .window, .n = copied }) catch {};
                return copied;
            }
            if (s.rx_fin or s.rx_shut) return 0;
            if (s.state != .established) return error.SocketUnconnected;
            switch (n.waitOn(me, s, null) catch return error.SystemResources) {
                .canceled => {
                    me.acknowledgeCancel();
                    return error.Canceled;
                },
                .timeout, .normal => {},
            }
        }
    }

    pub fn write(n: *Net, h: *Host, handle: Handle, header: []const u8, data: []const []const u8, splat: usize) net.Stream.Writer.Error!usize {
        const me = n.sim.running();
        try n.sim.cancelPoint(me);
        var total = header.len;
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |d| total += d.len;
            total += data[data.len - 1].len * splat;
        }
        if (total == 0) return 0;
        while (true) {
            const s = h.handles.get(handle) orelse return error.SocketUnconnected;
            if (s.kind != .stream) return error.SocketUnconnected;
            if (s.err != null) return error.ConnectionResetByPeer;
            if (s.tx_shut or s.state != .established) return error.SocketUnconnected;
            const window = n.sim.opts.net.tcp_window;
            const space = window -| s.inflight;
            if (space > 0) {
                const amount = @min(space, total);
                var cursor: Gather = .{ .header = header, .data = data, .splat = splat };
                var left = amount;
                while (left > 0) {
                    const k = @min(left, n.sim.opts.net.tcp_mss);
                    const chunk = n.sim.gpa.alloc(u8, k) catch
                        return if (amount == left) error.SystemResources else amount - left;
                    cursor.copy(chunk);
                    n.sim.mixData(h, chunk);
                    n.pushSeg(s.tx.?, .{ .at = 0, .kind = .data, .data = chunk }) catch {
                        n.sim.gpa.free(chunk);
                        return if (amount == left) error.SystemResources else amount - left;
                    };
                    s.inflight += k;
                    left -= k;
                }
                return amount;
            }
            switch (n.waitOn(me, s, null) catch return error.SystemResources) {
                .canceled => {
                    me.acknowledgeCancel();
                    return error.Canceled;
                },
                .timeout, .normal => {},
            }
        }
    }

    pub fn close(n: *Net, h: *Host, handles: []const Handle) void {
        for (handles) |handle| {
            const s = h.handles.get(handle) orelse continue;
            n.closeSock(s);
        }
    }

    fn closeSock(n: *Net, s: *Sock) void {
        switch (s.kind) {
            .stream => if (s.state == .established and s.err == null) {
                // Unread data turns a close into a reset, as on Linux.
                const kind: @FieldType(Seg, "kind") = if (s.buffered() > 0) .rst else .fin;
                if (kind == .rst or !s.tx_shut) n.pushSeg(s.tx.?, .{ .at = 0, .kind = kind }) catch {};
            },
            .listener => for (s.accept_q.items) |c| {
                n.pushSeg(c.tx.?, .{ .at = 0, .kind = .rst }) catch {};
                n.destroySock(c);
            },
            .udp, .icmp => {},
        }
        n.destroySock(s);
    }

    pub fn shutdown(n: *Net, h: *Host, handle: Handle, how: net.ShutdownHow) net.ShutdownError!void {
        const s = h.handles.get(handle) orelse return error.SocketUnconnected;
        switch (s.kind) {
            .listener => {
                s.shut = true;
                n.notify(s);
                return;
            },
            .stream => {},
            .udp, .icmp => return error.SocketUnconnected,
        }
        if (s.state != .established) return error.SocketUnconnected;
        if (s.err != null) return error.ConnectionResetByPeer;
        if (how != .recv and !s.tx_shut) {
            s.tx_shut = true;
            n.pushSeg(s.tx.?, .{ .at = 0, .kind = .fin }) catch return error.SystemResources;
        }
        if (how != .send) s.rx_shut = true;
        n.notify(s);
    }

    pub fn send(n: *Net, h: *Host, handle: Handle, messages: []net.OutgoingMessage) struct { ?net.Socket.SendError, usize } {
        const s = h.handles.get(handle) orelse return .{ error.SocketUnconnected, 0 };
        for (messages, 0..) |*m, i| {
            n.sendOne(h, s, m) catch |err| return .{ err, i };
        }
        if (n.sim.current) |me| n.sim.maybeYield(me);
        return .{ null, messages.len };
    }

    fn sendOne(n: *Net, h: *Host, s: *Sock, m: *net.OutgoingMessage) net.Socket.SendError!void {
        const gpa = n.sim.gpa;
        if (s.kind != .udp and s.kind != .icmp) return error.SocketUnconnected;
        const dest = m.address.*;
        if (@as(net.IpAddress.Family, dest) != @as(net.IpAddress.Family, s.local)) return error.AddressFamilyUnsupported;
        const max: usize = if (dest == .ip4) 65507 else 65527;
        if (m.data_len > max) return error.MessageOversize;
        const dst = n.hostOf(h, dest) orelse return error.NetworkUnreachable;
        const data = gpa.dupe(u8, m.data_ptr[0..m.data_len]) catch return error.SystemResources;
        errdefer gpa.free(data);
        n.sim.mixData(h, data);
        if (s.kind == .icmp) {
            const request: u8 = if (dest == .ip6) 128 else 8;
            if (data.len < 8 or data[0] != request) return error.Unexpected; // Linux: EINVAL
            // A ping socket owns the echo identifier: it is the socket's port.
            std.mem.writeInt(u16, data[4..6], s.local.getPort(), .big);
            if (dest == .ip4) setIcmp4Checksum(data);
        }
        const p = gpa.create(Packet) catch return error.SystemResources;
        p.* = .{
            .kind = if (s.kind == .icmp) .icmp else .udp,
            .src_host = h.id,
            .dst_host = dst.id,
            .src = sourceOf(s),
            .dst = if (s.kind == .icmp) withPort(dest, 0) else dest,
            .data = data,
        };
        n.transmit(p);
    }

    /// Fills `op` from the queue without blocking; null when nothing is
    /// queued.
    pub fn tryReceive(n: *Net, h: *Host, op: Io.Operation.NetReceive) ?Io.Operation.NetReceive.Result {
        const gpa = n.sim.gpa;
        const s = h.handles.get(op.socket_handle) orelse return .{ error.SocketUnconnected, 0 };
        if (s.kind != .udp and s.kind != .icmp) return .{ error.SocketUnconnected, 0 };
        if (s.dgrams.items.len == 0) return null;
        var count: usize = 0;
        var used: usize = 0;
        for (op.message_buffer) |*msg| {
            if (s.dgrams.items.len == 0 or used == op.data_buffer.len) break;
            const d = s.dgrams.orderedRemove(0);
            defer gpa.free(d.data);
            s.dgram_bytes -= d.data.len;
            const room = op.data_buffer[used..];
            const k = @min(room.len, d.data.len);
            @memcpy(room[0..k], d.data[0..k]);
            msg.from = d.from;
            msg.data = room[0..k];
            msg.control = msg.control[0..0];
            msg.flags = .{ .eor = false, .trunc = k < d.data.len, .ctrunc = false, .oob = false, .errqueue = false };
            used += k;
            count += 1;
        }
        return .{ null, count };
    }

    pub fn receive(n: *Net, h: *Host, op: Io.Operation.NetReceive) Io.Cancelable!Io.Operation.NetReceive.Result {
        const me = n.sim.running();
        try n.sim.cancelPoint(me);
        while (true) {
            if (n.tryReceive(h, op)) |r| return r;
            const s = h.handles.get(op.socket_handle).?; // tryReceive checked it
            switch (n.waitOn(me, s, null) catch return .{ error.SystemResources, 0 }) {
                .canceled => {
                    me.acknowledgeCancel();
                    return error.Canceled;
                },
                .timeout, .normal => {},
            }
        }
    }

    fn waitOn(n: *Net, me: *Fiber, s: *Sock, deadline: ?u64) Allocator.Error!sched.WakeReason {
        try s.waiters.append(n.sim.gpa, me);
        return n.sim.block(me, .{ .sock = s }, true, deadline) catch |err| {
            s.removeWaiter(me);
            return err;
        };
    }

    /// Registers `me` on every socket `batch` waits on, then parks it.
    pub fn waitBatch(n: *Net, h: *Host, me: *Fiber, batch: *Io.Batch, deadline: ?u64) Allocator.Error!sched.WakeReason {
        var idx = batch.submitted.head;
        errdefer n.unwaitAll(h, me);
        while (idx != .none) {
            const st = &batch.storage[idx.toIndex()].submission;
            switch (st.operation) {
                .net_receive => |op| if (h.handles.get(op.socket_handle)) |s| try s.waiters.append(n.sim.gpa, me),
                else => {},
            }
            idx = st.node.next;
        }
        return n.sim.block(me, .batch, true, deadline);
    }

    /// Takes `f` off every socket of `h` it waits on.
    pub fn unwaitAll(n: *Net, h: *Host, f: *Fiber) void {
        _ = n;
        var it = h.handles.valueIterator();
        while (it.next()) |s| s.*.removeWaiter(f);
    }

    fn isLocal(n: *Net, h: *Host, a: net.IpAddress) bool {
        if (isUnspecified(a)) return true;
        const owner = n.hostOf(h, a) orelse return false;
        return owner == h;
    }
};

/// Copies successive bytes of `header ++ data[0..len-1] ++ data[len-1] * splat`.
const Gather = struct {
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    part: usize = 0,
    off: usize = 0,
    rep: usize = 0,

    fn copy(g: *Gather, out: []u8) void {
        var o: usize = 0;
        while (o < out.len) {
            const src = g.current();
            if (g.off == src.len) {
                g.advance();
                continue;
            }
            const k = @min(src.len - g.off, out.len - o);
            @memcpy(out[o..][0..k], src[g.off..][0..k]);
            o += k;
            g.off += k;
        }
    }

    /// Part 0 is the header, part i the slice `data[i - 1]`; the last data
    /// slice is visited `splat` times (zero times when `splat == 0`).
    fn current(g: *const Gather) []const u8 {
        if (g.part == 0) return g.header;
        assert(g.part <= g.data.len); // callers never ask past the total
        if (g.part == g.data.len and g.splat == 0) return &.{};
        return g.data[g.part - 1];
    }

    fn advance(g: *Gather) void {
        g.off = 0;
        if (g.part == g.data.len and g.rep + 1 < g.splat) {
            g.rep += 1;
            return;
        }
        g.part += 1;
    }
};

fn isUnspecified(a: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |v| std.mem.allEqual(u8, &v.bytes, 0),
        .ip6 => |v| std.mem.allEqual(u8, &v.bytes, 0),
    };
}

fn sameIp(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

fn withPort(a: net.IpAddress, port: u16) net.IpAddress {
    var r = a;
    r.setPort(port);
    return r;
}

fn isLoopback6(b: [16]u8) bool {
    return std.mem.allEqual(u8, b[0..15], 0) and b[15] == 1;
}

fn mapped4(b: [16]u8) ?[4]u8 {
    if (!std.mem.allEqual(u8, b[0..10], 0) or b[10] != 0xff or b[11] != 0xff) return null;
    return b[12..16].*;
}

/// RFC 1071 checksum over an ICMPv4 message, written into bytes 2..4.
fn setIcmp4Checksum(msg: []u8) void {
    msg[2] = 0;
    msg[3] = 0;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < msg.len) : (i += 2) sum += std.mem.readInt(u16, msg[i..][0..2], .big);
    if (i < msg.len) sum += @as(u32, msg[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    std.mem.writeInt(u16, msg[2..4], ~@as(u16, @truncate(sum)), .big);
}

test "Gather walks header, data and the splatted tail in order" {
    var g: Gather = .{ .header = "ab", .data = &.{ "cd", "", "e" }, .splat = 3 };
    var out: [7]u8 = undefined;
    g.copy(out[0..3]);
    g.copy(out[3..]);
    try std.testing.expectEqualStrings("abcdeee", &out);
}

test "the ICMPv4 checksum verifies to zero" {
    var msg = [_]u8{ 8, 0, 0, 0, 0x12, 0x34, 0, 1, 'h', 'i', '!' };
    setIcmp4Checksum(&msg);
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < msg.len) : (i += 2) sum += std.mem.readInt(u16, msg[i..][0..2], .big);
    sum += @as(u32, msg[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    try std.testing.expectEqual(@as(u32, 0xffff), sum);
}
