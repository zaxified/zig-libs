//! The ping engine: schedules probes across many targets with global and
//! per-subnet pacing, tracks timeouts and statistics.
//!
//! Design follows fping's main_loop (two time-ordered event queues plus a
//! global minimum send interval), with additions aimed at large monitoring
//! deployments (10k+ targets per cycle):
//!
//!  * binary heaps instead of linked lists for O(log n) scheduling,
//!  * a hard cap on in-flight probes,
//!  * optional per-subnet send spacing (/24 for IPv4, /64 for IPv6) so a
//!    cycle does not burst into one branch of the network,
//!  * optional random jitter on each target's first probe to decorrelate
//!    consecutive monitoring cycles.
//!
//! Concurrency lives in the 16-bit ICMP sequence space (single socket per
//! address family), not in file descriptors — so the loop waits with ppoll
//! on at most two sockets.
//!
//! Sequence slots are released when the probe resolves (reply or timeout);
//! fping instead keeps seqmap entries for --seqmap-timeout but discards
//! late replies anyway (fping issue #32), so observable behaviour matches.
//! Duplicate replies are counted while the answered slot is still queued
//! (i.e. until its timeout event is lazily purged).

const std = @import("std");
const linux = std.os.linux;
const netaddr = @import("netaddr");
const seqmap = @import("seqmap");
const echo = @import("echo.zig");
const SeqMap = seqmap.SeqMap;
const Socket = @import("Socket.zig");

pub const TargetId = u32;

pub const Mode = enum {
    /// Stop probing a target after its first reply; retry on timeout up to
    /// `retries` times with timeout backoff (fping default mode).
    alive,
    /// Send exactly `count` probes per target for full RTT/loss statistics
    /// (fping -c/-C).
    count,
    /// Send probes forever until `stop()` is called (fping -l).
    loop,
};

pub const Config = struct {
    mode: Mode = .alive,
    /// Probes per target in .count mode.
    count: u16 = 1,
    /// Extra attempts after a timeout in .alive mode (fping -r, default 3).
    retries: u16 = 3,
    /// Minimum gap between any two transmitted packets (fping -i, global
    /// pacing — the primary anti-netstorm control).
    interval_ns: u64 = 10 * std.time.ns_per_ms,
    /// Minimum gap between two probes to the same target (fping -p).
    perhost_interval_ns: u64 = 1000 * std.time.ns_per_ms,
    /// Reply timeout for a single probe (fping -t).
    timeout_ns: u64 = 500 * std.time.ns_per_ms,
    /// Timeout multiplier applied on each retry in .alive mode (fping -B).
    backoff_factor: f32 = 1.5,
    /// Random extra delay in [0, jitter_ns) added to each target's first
    /// probe, spreading load across the cycle. 0 = off.
    jitter_ns: u64 = 0,
    /// Hard cap on outstanding probes. Must be < 65536 (sequence space).
    max_inflight: u32 = 4096,
    /// Minimum gap between sends into the same subnet (/24 IPv4, /64 IPv6).
    /// 0 = off.
    subnet_gap_ns: u64 = 0,
    /// ICMP payload bytes (fping -b). On-wire size adds 8B ICMP + IP header.
    payload_size: u16 = 56,
    /// Randomize payload on every send to defeat link compression (fping -R).
    random_payload: bool = false,
    /// Send ICMP Timestamp requests instead of Echo (fping --icmp-timestamp).
    /// IPv4 only; run() fails with IcmpTimestampRequiresIpv4 on v6 targets.
    icmp_timestamp: bool = false,
    /// Discard replies whose source address differs from the target
    /// (fping --check-source).
    check_source: bool = false,
    socket_mode: Socket.Mode = .auto,
    /// SO_RCVBUF for the ICMP sockets.
    recv_buf_size: u32 = 1 << 20,
    /// IP TTL / IPv6 unicast hops (fping -H).
    ttl: ?u8 = null,
    /// IP TOS / IPv6 traffic class (fping -O).
    tos: ?u8 = null,
    /// Set the Don't Fragment flag (fping -M).
    dont_fragment: bool = false,
    /// Routing mark (fping -k/--fwmark); requires CAP_NET_ADMIN.
    fwmark: ?u32 = null,
    /// Bind sockets to an interface (fping -I); requires CAP_NET_RAW.
    iface: ?[]const u8 = null,
    /// Send probes via a specific outgoing interface, receive from any
    /// (fping --oiface). No capability required.
    oiface: ?[]const u8 = null,
    /// Source address for IPv4 probes (fping -S).
    source4: ?Addr = null,
    /// Source address for IPv6 probes (fping -S).
    source6: ?Addr = null,
};

/// Reply details delivered with a successful probe.
pub const ReplyInfo = struct {
    rtt_ns: u64,
    /// Length of the received ICMP message (fping prints it as "N bytes").
    size: u16 = 0,
    /// Received TTL (v4) / hop limit (v6), when the kernel provided it.
    ttl: ?u8 = null,
    /// Received TOS (v4) / traffic class (v6).
    tos: ?u8 = null,
    /// ICMP Timestamp payload (icmp_timestamp mode only).
    ts: ?echo.TsData = null,
};

pub const Outcome = union(enum) {
    reply: ReplyInfo,
    /// A further reply for an already-answered probe.
    duplicate: ReplyInfo,
    timeout,
    send_error: Socket.SendError,
};

/// Per-probe callback. `probe` is the 0-based probe index within the target
/// (wraps at 65536 in loop mode).
pub const ResultFn = *const fn (ctx: ?*anyopaque, id: TargetId, probe: u16, outcome: Outcome) void;

pub const Stats = struct {
    sent: u32 = 0,
    recv: u32 = 0,
    send_errors: u32 = 0,
    /// Extra replies for probes that were already answered.
    duplicates: u32 = 0,
    /// Replies discarded because the source address did not match
    /// (check_source mode).
    source_mismatches: u32 = 0,
    /// ICMP errors (unreachable etc.) received for our probes. The probe
    /// itself still resolves via timeout, mirroring fping.
    icmp_errors: u32 = 0,
    min_ns: u64 = 0,
    max_ns: u64 = 0,
    total_ns: u64 = 0,
    last_ns: u64 = 0,

    pub fn alive(s: Stats) bool {
        return s.recv > 0;
    }

    pub fn lost(s: Stats) u32 {
        return s.sent - s.recv;
    }

    pub fn lossPermille(s: Stats) u32 {
        if (s.sent == 0) return 0;
        return @intCast((@as(u64, s.lost()) * 1000) / s.sent);
    }

    pub fn avgNs(s: Stats) ?u64 {
        if (s.recv == 0) return null;
        return s.total_ns / s.recv;
    }
};

/// A probe destination: family-tagged sockaddr, built from a `netaddr.Ip`
/// or parsed from a numeric literal.
pub const Addr = union(echo.Family) {
    v4: linux.sockaddr.in,
    v6: linux.sockaddr.in6,

    pub const ParseError = error{InvalidAddress};

    /// Parse a numeric IPv4/IPv6 address (no DNS; `netaddr.parseIp`). IPv6
    /// addresses may carry a scope id suffix — numeric ("%2") or an
    /// interface name ("%eth0"), resolved via ioctl(SIOCGIFINDEX) like
    /// getaddrinfo does.
    pub fn parse(text: []const u8) ParseError!Addr {
        if (std.mem.indexOfScalar(u8, text, '%')) |percent| {
            const scope_text = text[percent + 1 ..];
            const scope = std.fmt.parseInt(u32, scope_text, 10) catch
                ifNameToIndex(scope_text) orelse return error.InvalidAddress;
            const ip = netaddr.parseIp(text[0..percent]) orelse return error.InvalidAddress;
            var addr = fromIp(ip);
            switch (addr) {
                .v6 => |*sa| sa.scope_id = scope,
                .v4 => return error.InvalidAddress, // scopes are IPv6-only
            }
            return addr;
        }
        const ip = netaddr.parseIp(text) orelse return error.InvalidAddress;
        return fromIp(ip);
    }

    pub fn fromIp(ip: netaddr.Ip) Addr {
        return switch (ip) {
            .v4 => |q| .{ .v4 = .{
                .port = 0,
                .addr = @bitCast(q),
            } },
            .v6 => |b| .{ .v6 = .{
                .port = 0,
                .flowinfo = 0,
                .addr = b,
                .scope_id = 0,
            } },
        };
    }

    /// The address bytes as a `netaddr.Ip` (scope id is not representable
    /// there and is dropped).
    pub fn toIp(self: Addr) netaddr.Ip {
        return switch (self) {
            .v4 => |sa| .{ .v4 = @bitCast(sa.addr) },
            .v6 => |sa| .{ .v6 = sa.addr },
        };
    }

    pub fn family(self: Addr) echo.Family {
        return @as(echo.Family, self);
    }

    fn sockaddrPtr(self: *const Addr) *const linux.sockaddr {
        return switch (self.*) {
            .v4 => |*sa| @ptrCast(sa),
            .v6 => |*sa| @ptrCast(sa),
        };
    }

    fn sockaddrLen(self: *const Addr) linux.socklen_t {
        return switch (self.*) {
            .v4 => @sizeOf(linux.sockaddr.in),
            .v6 => @sizeOf(linux.sockaddr.in6),
        };
    }

    /// Address bytes equal (ports/scope ignored).
    pub fn sameHost(self: Addr, other: Addr) bool {
        return switch (self) {
            .v4 => |a| switch (other) {
                .v4 => |b| a.addr == b.addr,
                .v6 => false,
            },
            .v6 => |a| switch (other) {
                .v6 => |b| std.mem.eql(u8, &a.addr, &b.addr),
                .v4 => false,
            },
        };
    }

    /// Bucket key for subnet pacing: /24 for IPv4, /64 for IPv6.
    fn subnetKey(self: Addr) u64 {
        switch (self) {
            .v4 => |sa| {
                const bytes: [4]u8 = @bitCast(sa.addr);
                const prefix = std.mem.readInt(u32, &bytes, .big) >> 8;
                return (1 << 32) | @as(u64, prefix);
            },
            .v6 => |sa| {
                return std.mem.readInt(u64, sa.addr[0..8], .big);
            },
        }
    }

    pub fn format(self: Addr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [netaddr.max_ip_text_len]u8 = undefined;
        try w.writeAll(netaddr.formatIp(self.toIp(), &buf));
    }
};

const Target = struct {
    addr: Addr,
    stats: Stats = .{},
    /// Probes handed to sendto (including failed sends).
    attempts: u16 = 0,
    /// Probes currently awaiting reply or timeout.
    pending: u16 = 0,
    /// Current probe timeout (grows with backoff in .alive mode).
    timeout_ns: u64,
    done: bool = false,
};

const Event = struct {
    time: i64,
    target: TargetId,
    probe: u16,
    /// Sequence number, used by timeout events to validate against seqmap.
    seq: u16 = 0,
};

fn eventBefore(_: void, a: Event, b: Event) std.math.Order {
    return std.math.order(a.time, b.time);
}

const EventQueue = std.PriorityQueue(Event, void, eventBefore);

pub const RunError = error{
    OutOfMemory,
    /// More probes outstanding than the sequence space allows.
    SequenceSpaceExhausted,
    /// icmp_timestamp is set but a target is IPv6 (RFC 792 is IPv4 only).
    IcmpTimestampRequiresIpv4,
    /// Config.oiface does not name an existing interface.
    UnknownInterface,
} || Socket.OpenError;

pub const Pinger = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    targets: std.ArrayList(Target) = .empty,
    ping_q: EventQueue = .{ .items = &.{}, .cap = 0, .context = {} },
    timeout_q: EventQueue = .{ .items = &.{}, .cap = 0, .context = {} },
    seqmap: SeqMap,
    sock4: ?Socket = null,
    sock6: ?Socket = null,
    /// Monotonic time of the last transmitted packet; 0 = nothing sent yet
    /// (CLOCK_MONOTONIC is always far past any pacing interval at startup).
    last_send_ns: i64 = 0,
    inflight: u32 = 0,
    subnet_last: std.AutoHashMapUnmanaged(u64, i64) = .empty,
    prng: std.Random.DefaultPrng,
    /// Socket.batch_max packet slots for batched sends (slot 0 doubles as
    /// the single-send buffer).
    send_slab: []u8,
    /// Bytes per send_slab slot (= wire size of one probe).
    pkt_len: usize,
    recv_batch: Socket.RecvBatch,
    result_fn: ?ResultFn = null,
    result_ctx: ?*anyopaque = null,
    /// Set asynchronously (e.g. from a signal handler) to end run().
    stop_requested: std.atomic.Value(bool) = .init(false),

    pub fn init(gpa: std.mem.Allocator, cfg: Config) !Pinger {
        std.debug.assert(cfg.max_inflight < seqmap.capacity);
        const pkt_len = if (cfg.icmp_timestamp)
            echo.timestamp_msg_len
        else
            echo.echo_header_len + @as(usize, cfg.payload_size);
        const send_slab = try gpa.alloc(u8, Socket.batch_max * pkt_len);
        errdefer gpa.free(send_slab);
        @memset(send_slab, 0);
        const recv_slot = @max(4096, pkt_len + 128);
        const recv_slab = try gpa.alloc(u8, Socket.batch_max * recv_slot);
        errdefer gpa.free(recv_slab);

        // Jitter only needs decorrelation, not cryptographic randomness.
        const seed: u64 = @bitCast(monoNow() ^ (@as(i64, linux.getpid()) << 32));

        return .{
            .gpa = gpa,
            .cfg = cfg,
            .seqmap = try SeqMap.init(gpa),
            .prng = .init(seed),
            .send_slab = send_slab,
            .pkt_len = pkt_len,
            .recv_batch = .{ .slab = recv_slab, .slot_size = recv_slot },
        };
    }

    pub fn deinit(self: *Pinger) void {
        if (self.sock4) |*s| s.close();
        if (self.sock6) |*s| s.close();
        self.targets.deinit(self.gpa);
        self.ping_q.deinit(self.gpa);
        self.timeout_q.deinit(self.gpa);
        self.seqmap.deinit(self.gpa);
        self.subnet_last.deinit(self.gpa);
        self.gpa.free(self.send_slab);
        self.gpa.free(self.recv_batch.slab);
        self.* = undefined;
    }

    pub fn setResultCallback(self: *Pinger, ctx: ?*anyopaque, f: ResultFn) void {
        self.result_fn = f;
        self.result_ctx = ctx;
    }

    /// Request run() to return as soon as possible. Async-signal-safe.
    pub fn stop(self: *Pinger) void {
        self.stop_requested.store(true, .monotonic);
    }

    /// Add a target by numeric address string.
    pub fn addTarget(self: *Pinger, text: []const u8) (Addr.ParseError || error{OutOfMemory})!TargetId {
        return self.addTargetAddr(try Addr.parse(text));
    }

    pub fn addTargetAddr(self: *Pinger, addr: Addr) error{OutOfMemory}!TargetId {
        const id: TargetId = @intCast(self.targets.items.len);
        try self.targets.append(self.gpa, .{ .addr = addr, .timeout_ns = self.cfg.timeout_ns });
        return id;
    }

    /// Add a target from a `netaddr.Ip` (e.g. straight out of `dns`).
    pub fn addTargetIp(self: *Pinger, ip: netaddr.Ip) error{OutOfMemory}!TargetId {
        return self.addTargetAddr(Addr.fromIp(ip));
    }

    pub fn targetCount(self: *const Pinger) usize {
        return self.targets.items.len;
    }

    pub fn stats(self: *const Pinger, id: TargetId) Stats {
        return self.targets.items[id].stats;
    }

    pub fn targetAddr(self: *const Pinger, id: TargetId) Addr {
        return self.targets.items[id].addr;
    }

    fn ensureSockets(self: *Pinger) RunError!void {
        var need4 = false;
        var need6 = false;
        for (self.targets.items) |*t| switch (t.addr) {
            .v4 => need4 = true,
            .v6 => need6 = true,
        };
        const oiface_index: ?u32 = if (self.cfg.oiface) |name|
            ifNameToIndex(name) orelse return error.UnknownInterface
        else
            null;
        const base: Socket.Options = .{
            .recv_buf_size = self.cfg.recv_buf_size,
            .ttl = self.cfg.ttl,
            .tos = self.cfg.tos,
            .dont_fragment = self.cfg.dont_fragment,
            .fwmark = self.cfg.fwmark,
            .iface = self.cfg.iface,
            .oiface_index = oiface_index,
        };
        if (need4 and self.sock4 == null) {
            var opts = base;
            if (self.cfg.source4) |src| opts.source = .{ .v4 = src.v4 };
            self.sock4 = try Socket.open(.v4, self.cfg.socket_mode, opts);
        }
        if (need6 and self.sock6 == null) {
            var opts = base;
            if (self.cfg.source6) |src| opts.source = .{ .v6 = src.v6 };
            self.sock6 = try Socket.open(.v6, self.cfg.socket_mode, opts);
        }
    }

    fn socketFor(self: *Pinger, fam: echo.Family) *Socket {
        return switch (fam) {
            .v4 => &self.sock4.?,
            .v6 => &self.sock6.?,
        };
    }

    fn emit(self: *Pinger, id: TargetId, probe: u16, outcome: Outcome) void {
        if (self.result_fn) |f| f(self.result_ctx, id, probe, outcome);
    }

    /// Prepare a probing round: open sockets, reset statistics from any
    /// previous round and schedule every target's first probe. Called by
    /// run(); use it directly together with step()/pollFds() when embedding
    /// the engine into an external event loop.
    pub fn prepare(self: *Pinger) RunError!void {
        if (self.cfg.icmp_timestamp) {
            for (self.targets.items) |*t| {
                if (t.addr.family() == .v6) return error.IcmpTimestampRequiresIpv4;
            }
        }
        try self.ensureSockets();

        self.ping_q.items.len = 0;
        self.timeout_q.items.len = 0;
        self.inflight = 0;
        // Slots may still be occupied when the previous round ended early
        // (stop(), or answered slots whose events were never purged).
        self.seqmap.clear();
        self.subnet_last.clearRetainingCapacity();
        self.stop_requested.store(false, .monotonic);
        for (self.targets.items) |*t| {
            t.stats = .{};
            t.attempts = 0;
            t.pending = 0;
            t.timeout_ns = self.cfg.timeout_ns;
            t.done = false;
        }

        const start = monoNow();
        const rng = self.prng.random();
        for (self.targets.items, 0..) |_, idx| {
            const jitter: i64 = if (self.cfg.jitter_ns > 0)
                @intCast(rng.uintLessThan(u64, self.cfg.jitter_ns))
            else
                0;
            try self.ping_q.push(self.gpa, .{
                .time = start + jitter,
                .target = @intCast(idx),
                .probe = 0,
            });
        }
    }

    /// Advance the engine without blocking: fire due timeouts, transmit
    /// whatever pacing allows right now and drain already-received replies.
    ///
    /// Returns the absolute CLOCK_MONOTONIC deadline (ns) of the next
    /// scheduled event — wait until the sockets from pollFds() become
    /// readable or the deadline passes, then call step() again. Returns
    /// null when the round is complete (or stop() was called).
    pub fn step(self: *Pinger) RunError!?i64 {
        if (self.stop_requested.load(.monotonic)) return null;
        var now = monoNow();

        // Timeout events never need to wait on pacing; drain due ones first.
        // Events whose probe was already answered are purged lazily
        // regardless of their time, so they neither extend the next wait
        // nor keep the round alive (fping removes them eagerly on reply,
        // which a binary heap cannot do cheaply). Duplicate replies are
        // therefore only counted while the answered slot is still queued.
        while (self.timeout_q.peek()) |ev| {
            if (self.seqmap.fetch(ev.seq)) |entry| {
                if (entry.target == ev.target and entry.probe == ev.probe) {
                    if (!entry.answered) {
                        if (ev.time > now) break;
                        _ = self.timeout_q.pop();
                        try self.handleTimeout(ev, now);
                        continue;
                    }
                    // Answered: this event owns the slot — release it.
                    self.seqmap.release(ev.seq);
                }
            }
            // Released, reused or just-released slot: drop the stale event.
            _ = self.timeout_q.pop();
        }

        // Transmit while the global gap, the in-flight cap and the subnet
        // buckets allow it; consecutive due sends (only possible with a
        // zero interval) go out as one sendmmsg batch.
        try self.dispatchDue();
        now = monoNow();

        self.drainReplies();

        // All probes resolved and nothing left to send: the remaining
        // timeout events only guarded duplicate detection — like fping,
        // do not wait them out.
        if (self.ping_q.items.len == 0 and self.inflight == 0) return null;

        const wait = self.nextWaitNs(now) orelse return null;
        return now + wait;
    }

    /// Fill `buf` with the sockets to poll for readability between step()
    /// calls (POLLIN; at most one per address family).
    pub fn pollFds(self: *const Pinger, buf: *[2]linux.pollfd) []linux.pollfd {
        var n: usize = 0;
        if (self.sock4) |s| {
            buf[n] = .{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 };
            n += 1;
        }
        if (self.sock6) |s| {
            buf[n] = .{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 };
            n += 1;
        }
        return buf[0..n];
    }

    /// Run all probes to completion (or until stop() in loop mode).
    /// Repeated runs reset statistics.
    pub fn run(self: *Pinger) RunError!void {
        try self.prepare();
        while (try self.step()) |deadline| {
            self.waitReadable(deadline - monoNow());
        }
    }

    /// Transmit every probe the pacing gates allow right now. With a
    /// non-zero global interval at most one packet may leave per gap, so
    /// batches only form when interval_ns == 0 — then consecutive due
    /// sends to the same address family share one sendmmsg syscall.
    fn dispatchDue(self: *Pinger) RunError!void {
        var now = monoNow();
        while (true) {
            // Collect a same-family batch of events allowed to send now.
            var events: [Socket.batch_max]Event = undefined;
            var seqs: [Socket.batch_max]u16 = undefined;
            var family: echo.Family = undefined;
            var n: usize = 0;
            collect: while (n < Socket.batch_max) {
                const ev = self.ping_q.peek() orelse break :collect;
                if (ev.time > now) break :collect;
                if (self.inflight + n >= self.cfg.max_inflight) break :collect;
                if (n == 0) {
                    if (now - self.last_send_ns < @as(i64, @intCast(self.cfg.interval_ns)))
                        break :collect;
                } else if (self.cfg.interval_ns != 0) break :collect;
                const fam = self.targets.items[ev.target].addr.family();
                if (n == 0) family = fam else if (fam != family) break :collect;
                if (self.subnetReadyAt(ev, now)) |ready_at| {
                    // Subnet busy: push the event back to when its bucket
                    // frees up, then keep collecting other targets.
                    var deferred = self.ping_q.pop().?;
                    deferred.time = ready_at;
                    try self.ping_q.push(self.gpa, deferred);
                    continue :collect;
                }
                _ = self.ping_q.pop();
                seqs[n] = try self.prepareProbe(ev, now, self.sendSlot(n));
                events[n] = ev;
                n += 1;
            }
            if (n == 0) return;

            const sock = self.socketFor(family);
            const t0 = &self.targets.items[events[0].target];
            var accepted: usize = 0;
            if (n > 1) {
                var addrs: [Socket.batch_max]*const linux.sockaddr = undefined;
                var packets: [Socket.batch_max][]const u8 = undefined;
                for (events[0..n], 0..) |ev, i| {
                    addrs[i] = self.targets.items[ev.target].addr.sockaddrPtr();
                    packets[i] = self.sendSlot(i);
                }
                accepted = sock.sendMany(addrs[0..n], t0.addr.sockaddrLen(), packets[0..n]);
            }
            for (events[0..n], seqs[0..n], 0..) |ev, seq, i| {
                if (i < accepted) {
                    try self.commitProbe(ev, seq, now);
                    continue;
                }
                // Single send, or the remainder of a short sendmmsg batch
                // (retried individually for an accurate per-packet errno).
                const t = &self.targets.items[ev.target];
                if (sock.sendTo(t.addr.sockaddrPtr(), t.addr.sockaddrLen(), self.sendSlot(i))) {
                    try self.commitProbe(ev, seq, now);
                } else |err| {
                    self.failProbe(ev, seq, err);
                }
            }
            now = monoNow();
        }
    }

    fn sendSlot(self: *Pinger, i: usize) []u8 {
        return self.send_slab[i * self.pkt_len ..][0..self.pkt_len];
    }

    /// Returns when the subnet bucket of `ev`'s target allows sending, or
    /// null if it may send now.
    fn subnetReadyAt(self: *Pinger, ev: Event, now: i64) ?i64 {
        if (self.cfg.subnet_gap_ns == 0) return null;
        const key = self.targets.items[ev.target].addr.subnetKey();
        const last = self.subnet_last.get(key) orelse return null;
        const ready = last + @as(i64, @intCast(self.cfg.subnet_gap_ns));
        return if (ready > now) ready else null;
    }

    fn nextWaitNs(self: *Pinger, now: i64) ?i64 {
        var wait: ?i64 = null;
        if (self.ping_q.peek()) |ev| {
            var t = ev.time;
            const pace = self.last_send_ns + @as(i64, @intCast(self.cfg.interval_ns));
            if (pace > t) t = pace;
            wait = t - now;
        }
        if (self.timeout_q.peek()) |ev| {
            const t = ev.time - now;
            if (wait == null or t < wait.?) wait = t;
        }
        const w = wait orelse return null;
        return @max(w, 0);
    }

    /// Write the wire packet for `ev` into `buf` and do all pre-send
    /// bookkeeping: seqmap slot, pacing stamps, statistics and the next
    /// probe of this target (fping cadence: scheduled relative to this
    /// event's nominal time, not the actual send time).
    fn prepareProbe(self: *Pinger, ev: Event, now: i64, buf: []u8) RunError!u16 {
        const t = &self.targets.items[ev.target];
        const sock = self.socketFor(t.addr.family());

        const seq = self.seqmap.add(ev.target, ev.probe, now) catch
            return error.SequenceSpaceExhausted;

        if (self.cfg.icmp_timestamp) {
            echo.writeTimestampRequest(buf, sock.ident, seq, originateMs());
        } else {
            if (self.cfg.random_payload)
                self.prng.random().bytes(buf[echo.echo_header_len..]);
            echo.writeEchoRequest(t.addr.family(), buf, sock.ident, seq);
        }

        t.attempts +%= 1;
        self.last_send_ns = now;
        if (self.cfg.subnet_gap_ns > 0)
            try self.subnet_last.put(self.gpa, t.addr.subnetKey(), now);
        t.stats.sent += 1;

        const more = switch (self.cfg.mode) {
            .count => ev.probe + 1 < self.cfg.count,
            .loop => true,
            .alive => false,
        };
        if (more) {
            try self.ping_q.push(self.gpa, .{
                .time = ev.time + @as(i64, @intCast(self.cfg.perhost_interval_ns)),
                .target = ev.target,
                .probe = ev.probe +% 1,
            });
        }
        return seq;
    }

    /// Post-send bookkeeping for a probe the kernel accepted.
    fn commitProbe(self: *Pinger, ev: Event, seq: u16, now: i64) RunError!void {
        const t = &self.targets.items[ev.target];
        t.pending += 1;
        self.inflight += 1;
        try self.timeout_q.push(self.gpa, .{
            .time = now + @as(i64, @intCast(t.timeout_ns)),
            .target = ev.target,
            .probe = ev.probe,
            .seq = seq,
        });
    }

    /// Bookkeeping for a probe the kernel rejected.
    fn failProbe(self: *Pinger, ev: Event, seq: u16, err: Socket.SendError) void {
        const t = &self.targets.items[ev.target];
        self.seqmap.release(seq);
        t.stats.send_errors += 1;
        self.emit(ev.target, ev.probe, .{ .send_error = err });
        self.checkDone(t);
    }

    fn handleTimeout(self: *Pinger, ev: Event, now: i64) RunError!void {
        // The slot may have been reused; only a live entry that still
        // matches this event belongs to it.
        const entry = self.seqmap.fetch(ev.seq) orelse return;
        if (entry.target != ev.target or entry.probe != ev.probe) return;
        self.seqmap.release(ev.seq);

        // Probe already resolved by a reply; the slot was only kept for
        // duplicate detection.
        if (entry.answered) return;

        const t = &self.targets.items[ev.target];
        t.pending -= 1;
        self.inflight -= 1;
        self.emit(ev.target, ev.probe, .timeout);

        if (self.cfg.mode == .alive and !t.done and t.attempts < 1 + self.cfg.retries) {
            t.timeout_ns = backoff(t.timeout_ns, self.cfg.backoff_factor);
            try self.ping_q.push(self.gpa, .{
                .time = now,
                .target = ev.target,
                .probe = ev.probe + 1,
            });
        } else {
            self.checkDone(t);
        }
    }

    fn handleReply(self: *Pinger, fam: echo.Family, info: Socket.RecvInfo, recv_mono_ns: i64) void {
        const sock = self.socketFor(fam);
        const parsed = switch (fam) {
            .v4 => echo.parseV4(info.packet, sock.kind == .raw),
            .v6 => echo.parseV6(info.packet),
        };
        switch (parsed) {
            .echo_reply => |r| {
                // RAW sockets see every echo reply on the host; DGRAM sockets
                // are already filtered by the kernel.
                if (sock.kind == .raw and r.ident != sock.ident) return;
                const entry = self.seqmap.fetchPtr(r.seq) orelse return;
                const t = &self.targets.items[entry.target];
                if (t.addr.family() != fam) return;

                if (self.cfg.check_source and !sourceMatches(info.src, t.addr)) {
                    t.stats.source_mismatches += 1;
                    return;
                }

                const rtt: u64 = @intCast(@max(recv_mono_ns - entry.sent_ns, 0));
                // Report the ICMP message length; RAW v4 sockets deliver the
                // IP header too, so strip its length.
                var icmp_len = info.packet.len;
                if (fam == .v4 and sock.kind == .raw and info.packet.len >= 20)
                    icmp_len -= @as(usize, info.packet[0] & 0x0f) * 4;
                const reply_info: ReplyInfo = .{
                    .rtt_ns = rtt,
                    .size = @intCast(@min(icmp_len, std.math.maxInt(u16))),
                    .ttl = info.ttl,
                    .tos = info.tos,
                    .ts = r.ts,
                };

                if (entry.answered) {
                    t.stats.duplicates += 1;
                    self.emit(entry.target, entry.probe, .{ .duplicate = reply_info });
                    return;
                }
                entry.answered = true;

                t.pending -= 1;
                self.inflight -= 1;

                const s = &t.stats;
                s.recv += 1;
                s.last_ns = rtt;
                s.total_ns += rtt;
                if (s.min_ns == 0 or rtt < s.min_ns) s.min_ns = rtt;
                if (rtt > s.max_ns) s.max_ns = rtt;

                self.emit(entry.target, entry.probe, .{ .reply = reply_info });

                if (self.cfg.mode == .alive) t.done = true else self.checkDone(t);
            },
            .icmp_error => |e| {
                if (e.orig_ident != sock.ident) return;
                const entry = self.seqmap.fetch(e.orig_seq) orelse return;
                // Informational only; the probe is resolved by its timeout
                // (fping semantics).
                self.targets.items[entry.target].stats.icmp_errors += 1;
            },
            .ignored => {},
        }
    }

    fn checkDone(self: *Pinger, t: *Target) void {
        if (self.cfg.mode == .loop) return;
        if (t.pending > 0) return;
        t.done = true;
    }

    /// Block until a socket is readable or `wait_ns` elapses. EINTR (e.g.
    /// SIGINT setting stop_requested) ends the wait early so the run loop
    /// can observe it.
    fn waitReadable(self: *Pinger, wait_ns: i64) void {
        var buf: [2]linux.pollfd = undefined;
        const fds = self.pollFds(&buf);
        const clamped = @max(wait_ns, 0);
        var ts: linux.timespec = .{
            .sec = @intCast(@divTrunc(clamped, std.time.ns_per_s)),
            .nsec = @intCast(@mod(clamped, std.time.ns_per_s)),
        };
        _ = linux.ppoll(fds.ptr, fds.len, &ts, null);
    }

    /// Read and process every already-received reply (non-blocking).
    fn drainReplies(self: *Pinger) void {
        // One realtime/monotonic pair converts kernel receive timestamps
        // (CLOCK_REALTIME) to the engine's monotonic clock.
        const mono_now = monoNow();
        const real_now = realNow();

        inline for (.{ .v4, .v6 }) |fam| {
            const maybe_sock = switch (@as(echo.Family, fam)) {
                .v4 => self.sock4,
                .v6 => self.sock6,
            };
            if (maybe_sock != null) {
                const sock = self.socketFor(fam);
                while (true) {
                    const infos = sock.recvBatch(&self.recv_batch);
                    if (infos.len == 0) break;
                    for (infos) |info| {
                        const recv_mono = if (info.timestamp_real_ns) |ts_real|
                            mono_now - @max(real_now - ts_real, 0)
                        else
                            mono_now;
                        self.handleReply(fam, info, recv_mono);
                    }
                    // A short batch means the socket is drained.
                    if (infos.len < Socket.batch_max) break;
                }
            }
        }
    }
};

fn sourceMatches(src: Socket.RecvInfo.SrcAddr, target: Addr) bool {
    return switch (src) {
        .none => true, // no source info available; cannot verify
        .v4 => |sa| switch (target) {
            .v4 => |ta| sa.addr == ta.addr,
            .v6 => false,
        },
        .v6 => |sa| switch (target) {
            .v6 => |ta| std.mem.eql(u8, &sa.addr, &ta.addr),
            .v4 => false,
        },
    };
}

fn backoff(timeout_ns: u64, factor: f32) u64 {
    const scaled = @as(f64, @floatFromInt(timeout_ns)) * factor;
    return @intFromFloat(scaled);
}

/// Resolve an interface name to its index via ioctl(SIOCGIFINDEX), like
/// if_nametoindex(3). Returns null for unknown names.
fn ifNameToIndex(name: []const u8) ?u32 {
    if (name.len == 0 or name.len >= linux.IFNAMESIZE) return null;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var req: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(req.ifrn.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&req))) != .SUCCESS)
        return null;
    return @intCast(req.ifru.ivalue);
}

pub fn monoNow() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn realNow() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Milliseconds since midnight UT, as required by RFC 792 timestamps.
fn originateMs() u32 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const ms_in_day = @mod(ts.sec, std.time.s_per_day) * std.time.ms_per_s +
        @divTrunc(ts.nsec, std.time.ns_per_ms);
    return @intCast(ms_in_day);
}

// ── tests: offline ──────────────────────────────────────────────────────────

test "addr parse and subnet keys" {
    const a = try Addr.parse("192.168.1.17");
    const b = try Addr.parse("192.168.1.200");
    const c = try Addr.parse("192.168.2.1");
    try std.testing.expectEqual(a.subnetKey(), b.subnetKey());
    try std.testing.expect(a.subnetKey() != c.subnetKey());

    const x = try Addr.parse("2001:db8::1");
    const y = try Addr.parse("2001:db8::ffff");
    const z = try Addr.parse("2001:db8:1::1");
    try std.testing.expectEqual(x.subnetKey(), y.subnetKey());
    try std.testing.expect(x.subnetKey() != z.subnetKey());

    try std.testing.expectError(error.InvalidAddress, Addr.parse("not-an-ip"));
    try std.testing.expectError(error.InvalidAddress, Addr.parse("10.0.0.1%1")); // scopes are v6-only
}

test "addr format and sameHost" {
    const a = try Addr.parse("10.0.0.1");
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try a.format(&w);
    try std.testing.expectEqualStrings("10.0.0.1", w.buffered());

    const b = try Addr.parse("2001:db8::1");
    var w6: std.Io.Writer = .fixed(&buf);
    try b.format(&w6);
    try std.testing.expectEqualStrings("2001:db8::1", w6.buffered());

    try std.testing.expect(a.sameHost(try Addr.parse("10.0.0.1")));
    try std.testing.expect(!a.sameHost(try Addr.parse("10.0.0.2")));
    try std.testing.expect(!a.sameHost(try Addr.parse("::1")));
}

test "addr round-trips through netaddr.Ip" {
    const ip = netaddr.parseIp("192.0.2.7").?;
    const addr = Addr.fromIp(ip);
    try std.testing.expect(addr.toIp().eql(ip));
    const ip6 = netaddr.parseIp("2001:db8::42").?;
    try std.testing.expect(Addr.fromIp(ip6).toIp().eql(ip6));
}

test "stats helpers" {
    var s: Stats = .{ .sent = 4, .recv = 3, .total_ns = 3_000_000 };
    try std.testing.expect(s.alive());
    try std.testing.expectEqual(@as(u32, 1), s.lost());
    try std.testing.expectEqual(@as(u32, 250), s.lossPermille());
    try std.testing.expectEqual(@as(u64, 1_000_000), s.avgNs().?);
}

test "pinger init/deinit and target bookkeeping" {
    var p = try Pinger.init(std.testing.allocator, .{});
    defer p.deinit();
    const id = try p.addTarget("127.0.0.1");
    try std.testing.expectEqual(@as(TargetId, 0), id);
    try std.testing.expectEqual(@as(usize, 1), p.targetCount());
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).sent);
}

test "icmp_timestamp rejects ipv6 targets" {
    var p = try Pinger.init(std.testing.allocator, .{ .icmp_timestamp = true });
    defer p.deinit();
    _ = try p.addTarget("::1");
    try std.testing.expectError(error.IcmpTimestampRequiresIpv4, p.run());
}

test "scheduling: global pacing shapes the next deadline" {
    // The scheduler is unit-testable without touching the network — the
    // C original's main_loop can only be exercised end-to-end.
    var p = try Pinger.init(std.testing.allocator, .{
        .interval_ns = 10 * std.time.ns_per_ms,
    });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");

    const now = monoNow();
    try p.ping_q.push(p.gpa, .{ .time = now, .target = 0, .probe = 0 });

    // Nothing sent yet: the event is due immediately.
    try std.testing.expectEqual(@as(?i64, 0), p.nextWaitNs(now));

    // A packet just left: the same event must wait out the global gap.
    p.last_send_ns = now;
    try std.testing.expectEqual(@as(?i64, 10 * std.time.ns_per_ms), p.nextWaitNs(now));

    // A timeout due sooner takes precedence.
    try p.timeout_q.push(p.gpa, .{ .time = now + 3 * std.time.ns_per_ms, .target = 0, .probe = 0 });
    try std.testing.expectEqual(@as(?i64, 3 * std.time.ns_per_ms), p.nextWaitNs(now));
}

test "scheduling: subnet gap defers same-/24 sends" {
    var p = try Pinger.init(std.testing.allocator, .{
        .subnet_gap_ns = 5 * std.time.ns_per_ms,
    });
    defer p.deinit();
    const a = try p.addTarget("192.0.2.10");
    const b = try p.addTarget("192.0.2.20"); // same /24
    const c = try p.addTarget("192.0.3.10"); // different /24

    const now = monoNow();
    try p.subnet_last.put(p.gpa, p.targets.items[a].addr.subnetKey(), now);

    const ev_same: Event = .{ .time = now, .target = b, .probe = 0 };
    const ev_other: Event = .{ .time = now, .target = c, .probe = 0 };
    try std.testing.expectEqual(@as(?i64, now + 5 * std.time.ns_per_ms), p.subnetReadyAt(ev_same, now));
    try std.testing.expectEqual(@as(?i64, null), p.subnetReadyAt(ev_other, now));
}

test "seqmap correlation: a parsed reply resolves to its probe" {
    var sm = try SeqMap.init(std.testing.allocator);
    defer sm.deinit(std.testing.allocator);

    const seq = try sm.add(42, 3, 123_456);
    var pkt: [echo.echo_header_len]u8 = @splat(0);
    echo.writeEchoRequest(.v4, &pkt, 0xcafe, seq);
    pkt[0] = echo.v4.echo_reply; // kernel echoes the id/seq back
    const parsed = echo.parseV4(&pkt, false);
    const entry = sm.fetch(parsed.echo_reply.seq).?;
    try std.testing.expectEqual(@as(u32, 42), entry.target);
    try std.testing.expectEqual(@as(u16, 3), entry.probe);
    try std.testing.expectEqual(@as(i64, 123_456), entry.sent_ns);
    sm.release(seq);
    try std.testing.expectEqual(@as(?seqmap.Entry, null), sm.fetch(seq));
}

// ── tests: integration (loopback; skipped without ICMP socket access) ───────

/// Captures per-probe outcomes for the loopback integration tests.
const Capture = struct {
    replies: u32 = 0,
    others: u32 = 0,
    last_id: TargetId = 0,
    last_probe: u16 = 0,
    last_rtt_ns: u64 = 0,

    fn cb(ctx: ?*anyopaque, id: TargetId, probe: u16, outcome: Outcome) void {
        const self: *Capture = @ptrCast(@alignCast(ctx.?));
        switch (outcome) {
            .reply => |r| {
                self.replies += 1;
                self.last_id = id;
                self.last_probe = probe;
                self.last_rtt_ns = r.rtt_ns;
            },
            else => self.others += 1,
        }
    }
};

fn pingLoopback(target: []const u8) !void {
    var p = try Pinger.init(std.testing.allocator, .{
        .retries = 0,
        .timeout_ns = 2 * std.time.ns_per_s,
        .interval_ns = 0,
    });
    defer p.deinit();
    const id = try p.addTarget(target);
    var cap: Capture = .{};
    p.setResultCallback(&cap, Capture.cb);

    p.run() catch |e| switch (e) {
        // No ICMP socket in this environment: no CAP_NET_RAW and a
        // restrictive net.ipv4.ping_group_range (or the address family is
        // unavailable, e.g. IPv6 disabled).
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return e,
    };

    // Exactly one probe, answered by a correlated echo reply.
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).sent);
    try std.testing.expect(p.stats(id).alive());
    try std.testing.expectEqual(@as(u32, 1), cap.replies);
    try std.testing.expectEqual(@as(u32, 0), cap.others);
    try std.testing.expectEqual(id, cap.last_id);
    try std.testing.expectEqual(@as(u16, 0), cap.last_probe);
    // Plausible loopback RTT: below a second (and equal to the recorded stat).
    try std.testing.expect(cap.last_rtt_ns < std.time.ns_per_s);
    try std.testing.expectEqual(cap.last_rtt_ns, p.stats(id).last_ns);
}

test "integration: ping 127.0.0.1 replies with a plausible RTT" {
    try pingLoopback("127.0.0.1");
}

test "integration: ping ::1 replies with a plausible RTT" {
    try pingLoopback("::1");
}

test "integration: embed API prepare/step/pollFds round against loopback" {
    var p = try Pinger.init(std.testing.allocator, .{
        .retries = 0,
        .timeout_ns = 300 * std.time.ns_per_ms,
        .interval_ns = 0,
    });
    defer p.deinit();
    const id = try p.addTarget("127.0.0.1");

    p.prepare() catch |e| switch (e) {
        // No ICMP socket privileges in this environment (CI sandbox).
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };

    var iterations: u32 = 0;
    while (try p.step()) |deadline| : (iterations += 1) {
        try std.testing.expect(iterations < 1000);
        var buf: [2]linux.pollfd = undefined;
        const fds = p.pollFds(&buf);
        try std.testing.expect(fds.len == 1);
        const wait = @max(deadline - monoNow(), 0);
        var ts: linux.timespec = .{
            .sec = @intCast(@divTrunc(wait, std.time.ns_per_s)),
            .nsec = @intCast(@mod(wait, std.time.ns_per_s)),
        };
        _ = linux.ppoll(fds.ptr, fds.len, &ts, null);
    }

    try std.testing.expect(p.stats(id).alive());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).sent);
}
