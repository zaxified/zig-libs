// SPDX-License-Identifier: MIT

//! The ping engine: schedules probes across many targets with global and
//! per-subnet pacing, tracks timeouts and statistics.
//!
//! The scheduling design references fping's main loop (two time-ordered event
//! queues plus a global minimum send interval) — behavior only, no source
//! consulted at the statement level; see this module's own NOTICE. The
//! expression here is independent, with additions aimed at large monitoring
//! deployments (10k+
//! targets per cycle):
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
    ///
    /// A1 F10: this is per-*retry*, not per-target-total. Against a silent
    /// target, `.alive` mode's worst case is `timeout_ns * (backoff_factor
    /// ^ (retries + 1) - 1) / (backoff_factor - 1)` (a geometric series --
    /// each retry's own timeout is the previous one times `backoff_factor`).
    /// Measured 2026-09-05: the *default* `Config{}` (`retries=3,
    /// timeout_ns=500ms, backoff_factor=1.5`) already blocks 4067ms, 8.1x
    /// `timeout_ns` alone; `retries=10` at the same timeout reaches 85579ms.
    /// This is deliberate backoff, entirely determined by values the caller
    /// chose (unlike A1 F3, nothing external can make it worse), so it is
    /// documented here rather than capped: capping it would silently
    /// override a `retries`/`backoff_factor` combination the caller set on
    /// purpose. `run()` still has no deadline/cancel of its own beyond
    /// `stop()` — budget for the worst case above, or call `stop()` from
    /// another thread/signal handler.
    retries: u16 = 3,
    /// Minimum gap between any two transmitted packets (fping -i, global
    /// pacing — the primary anti-netstorm control).
    interval_ns: u64 = 10 * std.time.ns_per_ms,
    /// Minimum gap between two probes to the same target (fping -p).
    perhost_interval_ns: u64 = 1000 * std.time.ns_per_ms,
    /// Reply timeout for a single probe (fping -t). See `retries`' doc
    /// comment (A1 F10) for the worst-case total across retries.
    timeout_ns: u64 = 500 * std.time.ns_per_ms,
    /// Timeout multiplier applied on each retry in .alive mode (fping -B).
    /// See `retries`' doc comment (A1 F10).
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
    /// (fping --check-source). Also discards an ICMP error whose quoted
    /// destination differs from the target (A1 F2) -- ident+seq alone name
    /// a *slot*, not which target the error is actually about.
    ///
    /// A1 F8: default changed from `false` to `true`. `ident`+`seq` are the
    /// only correlation key otherwise, and neither is a secret an attacker
    /// needs to guess right: `seq` is a plain per-target counter by design
    /// (`seqmap`'s own doc comment), and even a *random* `ident` (A1 F6) is
    /// just 16 bits with no rate limit on wrong guesses. Measured live
    /// 2026-09-05 with the guard off: a single reply forged with a
    /// neighboring target's ident/seq marked that OTHER target alive
    /// (`te_wrongdst_raw`-style cross-target confusion) -- exactly the
    /// failure mode a monitoring tool watching many targets can least
    /// afford, since one compromised/spoofable host then vouches for every
    /// other host in the same run. Set `false` explicitly to restore the
    /// old fping-compatible default.
    check_source: bool = true,
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
    /// A send slot is shorter than the ICMP header. `init` sizes the slab so
    /// this cannot happen; it is reported rather than asserted because an
    /// assert here compiles out of exactly the modes that would suffer from
    /// being wrong.
    SendBufferTooSmall,
    /// A receive slot is shorter than the batch slab it indexes. `init` sizes
    /// the slab so this cannot happen; reported for the same reason as
    /// `SendBufferTooSmall` — an assert compiles out of the release modes.
    RecvSlabTooSmall,
    /// A1 F1/m30: `sendMany` was handed more packets than `Socket.batch_max`
    /// (or a mismatched addrs/packets length). `dispatchDue`'s own collect
    /// loop never builds a batch bigger than `Socket.batch_max`, so this
    /// cannot actually happen through the public `Pinger` API today — it is
    /// propagated rather than asserted for the same reason every other
    /// caller-controlled-length guard in this module is: an assert is the
    /// one guard that disappears in the build mode that ships.
    TooManyPackets,
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
        // A1 F4: this was `std.debug.assert`, which compiles out of
        // ReleaseFast/ReleaseSmall -- the modes an integrator ships. A
        // caller-configured `max_inflight` at or past `seqmap.capacity`
        // then reached `seqmap.add` at runtime with no guard at all.
        if (cfg.max_inflight >= seqmap.capacity) return error.MaxInflightTooLarge;
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

        try self.drainReplies();

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
                accepted = try sock.sendMany(addrs[0..n], t0.addr.sockaddrLen(), packets[0..n]);
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
            // `init` sizes `pkt_len` to exactly `timestamp_msg_len` on this
            // branch, so the slice is the whole buffer; the reslice is what
            // hands the writer the fixed-size type it now asks for.
            echo.writeTimestampRequest(buf[0..echo.timestamp_msg_len], sock.ident, seq, originateMs());
        } else {
            if (self.cfg.random_payload)
                self.prng.random().bytes(buf[echo.echo_header_len..]);
            // `init` sizes every send slot to `echo_header_len` plus the
            // configured payload, so this cannot be short. Propagated rather
            // than swallowed anyway: the point of the writer returning an
            // error instead of asserting is that no caller decides the check
            // is unnecessary and puts the fail-open guard back.
            echo.writeEchoRequest(t.addr.family(), buf, sock.ident, seq) catch
                return error.SendBufferTooSmall;
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

        // A1 F4: was `t.attempts < 1 + self.cfg.retries`. `1 + retries` is
        // u16 arithmetic that overflows when `retries == 65535`: a panic in
        // Debug/ReleaseSafe, and in ReleaseFast the optimizer may assume
        // the overflow it is UB not to happen and fold the comparison away
        // (measured 2026-09-05: the run never returned). `attempts <=
        // retries` is arithmetically identical for every retries value
        // that does not overflow, and adds no operation that can.
        if (self.cfg.mode == .alive and !t.done and t.attempts <= self.cfg.retries) {
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
                const t = &self.targets.items[entry.target];
                // A1 F2: `check_source` used to sit only in the `.echo_reply`
                // branch above -- an ICMP error correlated by (guessable)
                // ident+seq alone counted toward `icmp_errors` even when its
                // quoted destination named a DIFFERENT target than the one
                // it resolved to (measured live 2026-09-05: a Time Exceeded
                // quoting 8.8.8.8, forged with the right ident/seq for a
                // 10.9.9.77 probe, still incremented that probe's
                // icmp_errors with check_source = true). The quoted
                // destination is the only part of the error that actually
                // names which probe it is about; ident/seq only says which
                // *slot*.
                if (self.cfg.check_source) {
                    const dest_matches = switch (t.addr) {
                        .v4 => |ta| std.mem.eql(u8, e.quoted_dst[0..4], std.mem.asBytes(&ta.addr)),
                        .v6 => |ta| std.mem.eql(u8, &e.quoted_dst, &ta.addr),
                    };
                    if (!dest_matches) return;
                }
                // Informational only; the probe is resolved by its timeout
                // (fping semantics).
                t.stats.icmp_errors += 1;
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

    /// A1 F3/F10: upper bound on `recvBatch` calls per family, per
    /// `drainReplies` call (i.e. per `step()`). Without this, a socket kept
    /// full by a sustained inbound flood makes `recvBatch` keep returning
    /// full batches forever, and the `while (true)` loop below never
    /// reaches its "short batch => drained" exit -- so `step()` never
    /// returns, and every OTHER thing it is responsible for (sending due
    /// probes, firing timeouts, letting `run()`'s caller observe `stop()`)
    /// stops happening too. Measured 2026-09-05 (`perf flood2`, six
    /// concurrent flooders on the loopback RAW socket): `run()` budgeted at
    /// 200ms took 1500.9-9046.5ms across six runs (7.5x-45x), while a quiet
    /// run and a post-flood recovery run both held at 200.7-200.9ms.
    /// `batch_max` (16) * this is the worst case packets handled inline per
    /// family per `step()`; nothing is dropped by hitting the cap, only
    /// deferred to the very next `drainReplies` call -- the kernel socket
    /// buffer (`Options.recv_buf_size`, 1 MiB default) holds the rest, and
    /// `pollFds`/`waitReadable` will report the socket readable again
    /// immediately since it is still full.
    const max_batches_per_drain = 64;

    /// Read and process every already-received reply (non-blocking), up to
    /// the per-family budget above.
    fn drainReplies(self: *Pinger) RunError!void {
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
                var batches: usize = 0;
                while (true) {
                    const infos = sock.recvBatch(&self.recv_batch) catch
                        return error.RecvSlabTooSmall;
                    if (infos.len == 0) break;
                    for (infos) |info| {
                        const recv_mono = if (info.timestamp_real_ns) |ts_real|
                            mono_now - @max(real_now - ts_real, 0)
                        else
                            mono_now;
                        self.handleReply(fam, info, recv_mono);
                    }
                    batches += 1;
                    // A short batch means the socket is drained; hitting the
                    // budget means it probably is not, but step() must
                    // return control anyway (see doc comment above).
                    if (infos.len < Socket.batch_max or batches >= max_batches_per_drain) break;
                }
                self.drainErrQueue(fam, sock);
            }
        }
    }

    /// A1 F5: read the socket error queue (`IP_RECVERR`/`IPV6_RECVERR`,
    /// which `Socket.open` now always sets) for ICMP errors about our own
    /// probes -- on the DGRAM path this is the ONLY way they are ever
    /// delivered (verified live: `errq2.py` under `unshare`, a forged Time
    /// Exceeded produced nothing on a normal `recvmsg` but appeared on
    /// `MSG_ERRQUEUE` immediately, with the quoted echo header as payload
    /// and the quoted destination as the reported address). Correlates the
    /// same way the RAW path's `.icmp_error` branch in `handleReply` does:
    /// by the quoted ident against this socket's own, then by `seq` against
    /// `seqmap`, then (if `check_source`) by the reported address against
    /// the resolved target. Bounded by the same per-`step()` budget as
    /// `drainReplies`, for the same reason.
    fn drainErrQueue(self: *Pinger, fam: echo.Family, sock: *const Socket) void {
        var n: usize = 0;
        while (n < Socket.batch_max * max_batches_per_drain) : (n += 1) {
            var one: [512]u8 = undefined;
            const info = sock.recvErr(&one) orelse break;
            if (info.packet.len < echo.echo_header_len) continue;
            const ident = std.mem.readInt(u16, info.packet[4..6], .big);
            const seq = std.mem.readInt(u16, info.packet[6..8], .big);
            if (ident != sock.ident) continue;
            const entry = self.seqmap.fetch(seq) orelse continue;
            const t = &self.targets.items[entry.target];
            if (t.addr.family() != fam) continue;
            if (self.cfg.check_source and !sourceMatches(info.src, t.addr)) continue;
            t.stats.icmp_errors += 1;
        }
    }
};

fn sourceMatches(src: Socket.RecvInfo.SrcAddr, target: Addr) bool {
    return switch (src) {
        // A1 F13: "cannot verify" is not "verified" -- this returned `true`,
        // turning `check_source`, a fail-closed guard everywhere else, into
        // fail-open for the one case it could not judge. Not reachable on
        // Linux today: `recvmsg`/`recvmmsg` fill `msg_name` for both socket
        // kinds and both families, so `parseSrc` never actually returns
        // `.none` (see A1 audit record `icmp.md` F13). Fail closed anyway,
        // defensively, since nothing guarantees that stays true.
        .none => false,
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
    const scaled = @as(f64, @floatFromInt(timeout_ns)) * @as(f64, factor);
    // A1 F4: `@intFromFloat` of a value that does not fit `u64` (NaN,
    // infinity, negative, or simply too large) is UB -- a panic in
    // Debug/ReleaseSafe, and in ReleaseFast (measured 2026-09-05: factors
    // 1e30 / -1.0 / NaN each ran unbounded, never returning). None of these
    // is a valid timeout multiplier's result, so none of them changes the
    // timeout: NaN/±infinity/negative keep the previous timeout, and an
    // overflowing product clamps to `cap`, a power of two (so it round-trips
    // through f64 exactly) far past any real-world timeout.
    if (!std.math.isFinite(scaled) or scaled < 0) return timeout_ns;
    const cap: f64 = @as(f64, 1 << 62); // ~146 years
    if (scaled > cap) return @intFromFloat(cap);
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

test "stats helpers: no probes sent yet" {
    // Zero-sent must not be treated as 100% loss (or any other non-zero
    // permille) just because `lost() == 0 - 0 == 0` happens to also be 0;
    // this pins the early-return guard, not the arithmetic.
    const s: Stats = .{};
    try std.testing.expect(!s.alive());
    try std.testing.expectEqual(@as(u32, 0), s.lost());
    try std.testing.expectEqual(@as(u32, 0), s.lossPermille());
    try std.testing.expectEqual(@as(?u64, null), s.avgNs());
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
    try echo.writeEchoRequest(.v4, &pkt, 0xcafe, seq);
    pkt[0] = echo.v4.echo_reply; // kernel echoes the id/seq back
    // A1 F7: the checksum covers the type byte -- a real reply carries its
    // own valid checksum, not the request's.
    std.mem.writeInt(u16, pkt[2..4], 0, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    const parsed = echo.parseV4(&pkt, false);
    const entry = sm.fetch(parsed.echo_reply.seq).?;
    try std.testing.expectEqual(@as(u32, 42), entry.target);
    try std.testing.expectEqual(@as(u16, 3), entry.probe);
    try std.testing.expectEqual(@as(i64, 123_456), entry.sent_ns);
    sm.release(seq);
    try std.testing.expectEqual(@as(?seqmap.Entry, null), sm.fetch(seq));
}

test "A1 F4: retries = 65535 does not overflow the retry-count comparison" {
    // Before the fix, `t.attempts < 1 + self.cfg.retries` computed
    // `1 + 65535` in u16 arithmetic: Debug/ReleaseSafe panicked with
    // "integer overflow" (measured @ pinger.zig:766), ReleaseFast never
    // returned. `retries = 65535` is an extreme but legitimate
    // configuration choice, not a caller bug -- there was nothing to
    // reject, only arithmetic to fix. `attempts` starts at 0 (no
    // `prepareProbe` call happened here), so a retry must be scheduled.
    var p = try Pinger.init(std.testing.allocator, .{ .mode = .alive, .retries = 65535 });
    defer p.deinit();
    _ = try p.addTarget("192.0.2.1");
    const seq = try p.seqmap.add(0, 0, monoNow());
    p.targets.items[0].pending = 1;
    p.inflight = 1;
    const ev: Event = .{ .time = monoNow(), .target = 0, .probe = 0, .seq = seq };
    try p.handleTimeout(ev, monoNow());
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len);
    try std.testing.expect(!p.targets.items[0].done);
}

test "A1 F4: backoff() never produces UB for non-finite, negative, or overflowing factors" {
    // Measured 2026-09-05: backoff_factor = 1e30 / -1.0 / NaN each panicked
    // in Debug/ReleaseSafe (`@intFromFloat` of a value that does not fit
    // u64) and ran unbounded in ReleaseFast.
    try std.testing.expectEqual(@as(u64, 1) << 62, backoff(500_000_000, 1e30));
    try std.testing.expectEqual(@as(u64, 500_000_000), backoff(500_000_000, -1.0));
    try std.testing.expectEqual(@as(u64, 500_000_000), backoff(500_000_000, std.math.nan(f32)));
    // The ordinary case is unaffected.
    try std.testing.expectEqual(@as(u64, 750_000_000), backoff(500_000_000, 1.5));
}

test "A1 F4: max_inflight >= seqmap.capacity is reported, not asserted" {
    // Was `std.debug.assert(cfg.max_inflight < seqmap.capacity)`, compiled
    // out of ReleaseFast/ReleaseSmall.
    try std.testing.expectError(
        error.MaxInflightTooLarge,
        Pinger.init(std.testing.allocator, .{ .max_inflight = seqmap.capacity }),
    );
    // Positive control: a legal value still initializes.
    var p = try Pinger.init(std.testing.allocator, .{ .max_inflight = seqmap.capacity - 1 });
    p.deinit();
}

test "A1 F13: no source information never counts as a source match" {
    // `.none` used to return true ("cannot verify" read as "verified"), a
    // fail-open reading of a guard that is fail-closed everywhere else.
    const target = try Addr.parse("192.0.2.1");
    try std.testing.expect(!sourceMatches(.none, target));
    const target6 = try Addr.parse("2001:db8::1");
    try std.testing.expect(!sourceMatches(.none, target6));
}

test "A1 F8: sourceMatches compares every octet, not just the first" {
    // No test previously distinguished a comparison that only checked a
    // subset of the address (A1 F12 mutation table, m7: "source compared by
    // only its first octet") from the real one -- both left the suite
    // green.
    const target = try Addr.parse("192.0.2.1");
    const wrong = [_][]const u8{ "10.0.2.1", "192.10.2.1", "192.0.10.1", "192.0.2.10" };
    for (wrong) |w| {
        const addr = try Addr.parse(w);
        const sa: linux.sockaddr.in = switch (addr) {
            .v4 => |a| a,
            .v6 => unreachable,
        };
        try std.testing.expect(!sourceMatches(.{ .v4 = sa }, target));
    }
    const good: linux.sockaddr.in = switch (target) {
        .v4 => |a| a,
        .v6 => unreachable,
    };
    try std.testing.expect(sourceMatches(.{ .v4 = good }, target));

    const target6 = try Addr.parse("2001:db8::1");
    const wrong6 = [_][]const u8{ "2001:db9::1", "2001:db8::2" };
    for (wrong6) |w| {
        const addr = try Addr.parse(w);
        const sa: linux.sockaddr.in6 = switch (addr) {
            .v6 => |a| a,
            .v4 => unreachable,
        };
        try std.testing.expect(!sourceMatches(.{ .v6 = sa }, target6));
    }
}

test "A1 F2: check_source now validates the quoted destination inside an ICMP error too" {
    // Before this fix, `check_source` sat only in the `.echo_reply` branch
    // of handleReply. Measured live 2026-09-05 (`te_wrongdst_cs_raw`): a
    // Time Exceeded quoting the WRONG destination but carrying the right
    // (guessable) ident/seq still incremented that target's icmp_errors
    // even with check_source = true.
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = true });
    defer p.deinit();
    const id = try p.addTarget("10.9.9.77");
    // .dgram: no raw IP header to strip, so `pkt` below is the ICMP message
    // as-is (recvmsg on a DGRAM ping socket never sees the IP header).
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };

    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt: [echo.echo_header_len + 20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.time_exceeded;
    pkt[8] = 0x45; // quoted IHL = 5
    const orig = pkt[8 + 20 ..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0x1234, .big);
    std.mem.writeInt(u16, orig[6..8], seq, .big);
    // Quoted destination = 8.8.8.8, NOT the real target 10.9.9.77.
    pkt[8 + 16] = 8;
    pkt[8 + 17] = 8;
    pkt[8 + 18] = 8;
    pkt[8 + 19] = 8;
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big); // A1 F7

    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).icmp_errors);

    // Positive control: same packet, quoted destination corrected to the
    // real target -- must be counted.
    const target_bytes: [4]u8 = switch (p.targetAddr(id)) {
        .v4 => |a| @bitCast(a.addr),
        .v6 => unreachable,
    };
    @memcpy(pkt[8 + 16 ..][0..4], &target_bytes);
    pkt[2] = 0;
    pkt[3] = 0;
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).icmp_errors);
}

// ── A1 F12: mutation-table gaps in the correlation/scheduling layer ─────────
//
// icmp.md audit F12: 22 mutations across the correlation and scheduling
// layer left the whole suite green. Unlike the boundary-check gaps in
// echo.zig/Socket.zig above, these are not "unreachable without a specific
// input shape" -- they are simply guards nothing ever exercised through
// `handleReply`/`dispatchDue`/`handleTimeout`/`step` with a case built to
// depend on them.

test "A1 F12 m2/m3/m31: a RAW socket's ident check compares the WHOLE 16 bits, not part of it" {
    // `if (sock.kind == .raw and r.ident != sock.ident) return;` -- m2
    // deletes it outright, m3 weakens it to the high byte only, m31 to a
    // single bit. A single test that flips every bit position one at a time
    // (all other bits matching) catches all three: whichever subset of bits
    // a weakened comparison actually checks, at least one of the 16 flips
    // touches a bit outside that subset and would wrongly be accepted.
    // check_source: false -- this test isolates the ident check; the
    // crafted RecvInfo below carries no source address (A1 F8 changed the
    // default to true, which would otherwise reject every reply here on
    // the unrelated source-address guard before the ident check is even
    // reached).
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .raw, .ident = 0x1234 };
    p.targets.items[id].pending = 1;
    p.inflight = 1;
    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt: [20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = 0x45; // IP header, IHL = 5 -> 20 bytes, stripped by the .raw path
    const icmp = pkt[20..];
    icmp[0] = echo.v4.echo_reply;
    std.mem.writeInt(u16, icmp[6..8], seq, .big);

    var bit: u4 = 0;
    while (true) : (bit += 1) {
        const wrong_ident = p.sock4.?.ident ^ (@as(u16, 1) << bit);
        std.mem.writeInt(u16, icmp[4..6], wrong_ident, .big);
        icmp[2] = 0;
        icmp[3] = 0;
        std.mem.writeInt(u16, icmp[2..4], echo.checksum(icmp), .big);
        p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
        if (bit == 15) break;
    }
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).recv);

    // Positive control: the correct ident resolves the probe.
    std.mem.writeInt(u16, icmp[4..6], p.sock4.?.ident, .big);
    icmp[2] = 0;
    icmp[3] = 0;
    std.mem.writeInt(u16, icmp[2..4], echo.checksum(icmp), .big);
    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).recv);
}

test "A1 F12 m4/m32: an ICMP error's orig_ident check compares the WHOLE 16 bits, not part of it" {
    // `if (e.orig_ident != sock.ident) return;` -- same bit-flip technique
    // as m2/m3/m31 above, applied to the ICMP-error correlation path.
    var p = try Pinger.init(std.testing.allocator, .{});
    defer p.deinit();
    const id = try p.addTarget("10.9.9.77");
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };
    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt: [echo.echo_header_len + 20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.time_exceeded;
    pkt[8] = 0x45; // quoted IHL = 5
    const orig = pkt[8 + 20 ..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[6..8], seq, .big);
    const target_bytes: [4]u8 = switch (p.targetAddr(id)) {
        .v4 => |a| @bitCast(a.addr),
        .v6 => unreachable,
    };
    @memcpy(pkt[8 + 16 ..][0..4], &target_bytes); // correct quoted dest -- isolate the ident check

    var bit: u4 = 0;
    while (true) : (bit += 1) {
        const wrong_ident = p.sock4.?.ident ^ (@as(u16, 1) << bit);
        std.mem.writeInt(u16, orig[4..6], wrong_ident, .big);
        pkt[2] = 0;
        pkt[3] = 0;
        std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big); // A1 F7
        p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
        if (bit == 15) break;
    }
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).icmp_errors);

    // Positive control: the correct ident counts the error.
    std.mem.writeInt(u16, orig[4..6], p.sock4.?.ident, .big);
    pkt[2] = 0;
    pkt[3] = 0;
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);
    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).icmp_errors);
}

test "A1 F12 m5: a reply arriving on the wrong address family's socket does not resolve a probe" {
    // `if (t.addr.family() != fam) return;` -- a seq number is a 16-bit
    // space SHARED across both sockets (comment above `SeqMap`), so nothing
    // else stops an event on the wrong family's socket from matching a
    // live entry by seq number alone.
    // check_source: false -- isolates the family check (A1 F8 changed the
    // default; see the m2/m3/m31 test above for why).
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1"); // a v4 target
    p.sock6 = .{ .fd = -1, .family = .v6, .kind = .dgram, .ident = 0x1234 };
    p.targets.items[id].pending = 1;
    p.inflight = 1;
    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt6: [echo.echo_header_len]u8 = @splat(0);
    pkt6[0] = echo.v6.echo_reply;
    std.mem.writeInt(u16, pkt6[4..6], 0x1234, .big);
    std.mem.writeInt(u16, pkt6[6..8], seq, .big);
    p.handleReply(.v6, .{ .packet = &pkt6 }, monoNow());
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).recv);

    // Positive control: the SAME seq, delivered on the matching (v4) family.
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };
    var pkt4: [echo.echo_header_len]u8 = @splat(0);
    pkt4[0] = echo.v4.echo_reply;
    std.mem.writeInt(u16, pkt4[4..6], 0x1234, .big);
    std.mem.writeInt(u16, pkt4[6..8], seq, .big);
    std.mem.writeInt(u16, pkt4[2..4], echo.checksum(&pkt4), .big);
    p.handleReply(.v4, .{ .packet = &pkt4 }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).recv);
}

test "A1 F12 m6: check_source, when enabled, is actually enforced on echo replies (not just ICMP errors)" {
    // `if (self.cfg.check_source and !sourceMatches(info.src, t.addr)) {`
    // in the `.echo_reply` arm -- the F2 fix added the equivalent gate to
    // the `.icmp_error` arm (see the F2 test above) but nothing exercised
    // THIS one with an actual mismatched source.
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = true });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };
    p.targets.items[id].pending = 1;
    p.inflight = 1;
    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt: [echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.echo_reply;
    std.mem.writeInt(u16, pkt[4..6], 0x1234, .big);
    std.mem.writeInt(u16, pkt[6..8], seq, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);

    const wrong = try Addr.parse("10.0.0.9");
    const wrong_sa: linux.sockaddr.in = switch (wrong) {
        .v4 => |a| a,
        .v6 => unreachable,
    };
    p.handleReply(.v4, .{ .packet = &pkt, .src = .{ .v4 = wrong_sa } }, monoNow());
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).recv);
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).source_mismatches);

    // Positive control: the correct source resolves the (still-live) probe.
    const good = try Addr.parse("192.0.2.1");
    const good_sa: linux.sockaddr.in = switch (good) {
        .v4 => |a| a,
        .v6 => unreachable,
    };
    p.handleReply(.v4, .{ .packet = &pkt, .src = .{ .v4 = good_sa } }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).recv);
}

test "A1 F12 m17: a second reply to an already-answered probe counts as a duplicate, not a second reply" {
    // `if (entry.answered) { t.stats.duplicates += 1; ...; return; }` --
    // without it a replayed/duplicated reply on the wire would resolve the
    // probe (and decrement pending/inflight) a second time.
    // check_source: false -- isolates duplicate detection (A1 F8 changed
    // the default; see the m2/m3/m31 test above for why).
    var p = try Pinger.init(std.testing.allocator, .{ .check_source = false });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    p.sock4 = .{ .fd = -1, .family = .v4, .kind = .dgram, .ident = 0x1234 };
    p.targets.items[id].pending = 1;
    p.inflight = 1;
    const seq = try p.seqmap.add(id, 0, monoNow());

    var pkt: [echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.echo_reply;
    std.mem.writeInt(u16, pkt[4..6], 0x1234, .big);
    std.mem.writeInt(u16, pkt[6..8], seq, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);

    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).recv);
    try std.testing.expectEqual(@as(u32, 0), p.stats(id).duplicates);

    p.handleReply(.v4, .{ .packet = &pkt }, monoNow());
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).recv); // unchanged
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).duplicates);
}

test "A1 F12 m19: dispatchDue never sends past max_inflight" {
    // `if (self.inflight + n >= self.cfg.max_inflight) break :collect;`
    var p = try Pinger.init(std.testing.allocator, .{ .max_inflight = 4 });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    p.inflight = 4; // already at the cap
    const now = monoNow();
    try p.ping_q.push(p.gpa, .{ .time = now, .target = id, .probe = 0 });
    try p.dispatchDue();
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len); // still queued, not sent
    try std.testing.expectEqual(@as(u32, 4), p.inflight); // unchanged
}

test "A1 F12 m20: dispatchDue waits out the global pacing gap before sending" {
    // `if (now - self.last_send_ns < interval_ns) break :collect;` (the
    // n == 0 branch of the collect loop's pacing gate).
    var p = try Pinger.init(std.testing.allocator, .{ .interval_ns = 10 * std.time.ns_per_ms });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    const now = monoNow();
    p.last_send_ns = now; // a packet just left
    try p.ping_q.push(p.gpa, .{ .time = now, .target = id, .probe = 0 });
    try p.dispatchDue();
    try std.testing.expectEqual(@as(usize, 1), p.ping_q.items.len); // still queued, gap not elapsed
    try std.testing.expectEqual(@as(u32, 0), p.inflight);
}

test "A1 F12 m23: a stale timeout event for a reused slot is dropped, not misattributed" {
    // `if (entry.target != ev.target or entry.probe != ev.probe) return;`
    // inside `handleTimeout` -- a second line of defense past `step`'s own
    // owner check, for a slot that was released and reused between when a
    // timeout event was scheduled and when it fires.
    var p = try Pinger.init(std.testing.allocator, .{ .mode = .alive, .retries = 3 });
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    const seq = try p.seqmap.add(id, 5, monoNow()); // the slot now belongs to probe 5
    p.targets.items[id].pending = 1;
    p.inflight = 1;

    // A stale event for the SAME seq but a DIFFERENT probe, as if the slot
    // had been released and reused since the event was scheduled.
    const stale: Event = .{ .time = monoNow(), .target = id, .probe = 999, .seq = seq };
    try p.handleTimeout(stale, monoNow());

    try std.testing.expectEqual(@as(u32, 1), p.inflight); // untouched
    try std.testing.expectEqual(@as(u32, 1), p.targets.items[id].pending); // untouched
    try std.testing.expectEqual(@as(usize, 0), p.ping_q.items.len); // no bogus retry scheduled
}

test "A1 F12 m24: a timeout scheduled in the future does not fire early" {
    // `if (ev.time > now) break;` in `step`'s timeout-draining loop.
    var p = try Pinger.init(std.testing.allocator, .{});
    defer p.deinit();
    const id = try p.addTarget("192.0.2.1");
    const seq = try p.seqmap.add(id, 0, monoNow());
    p.targets.items[id].pending = 1;
    p.inflight = 1;
    const now = monoNow();
    try p.timeout_q.push(p.gpa, .{
        .time = now + 60 * std.time.ns_per_s, // far in the future
        .target = id,
        .probe = 0,
        .seq = seq,
    });
    _ = try p.step();
    try std.testing.expectEqual(@as(u32, 1), p.inflight);
    try std.testing.expectEqual(@as(u32, 1), p.targets.items[id].pending);
    try std.testing.expect(p.seqmap.fetch(seq) != null);
}

/// `std.Thread.sleep` does not exist in 0.16; a direct `nanosleep(2)` is the
/// dependency-free replacement, matching this file's existing raw-syscall
/// style (`monoNow`/`realNow` above).
fn sleepMs(ms: u64) void {
    var ts: linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = linux.nanosleep(&ts, null);
}

// ── tests: A1 F3/F5 (need a real ICMP socket; skip without access) ──────────

test "A1 F3: step() returns promptly even while its socket is being flooded" {
    // `drainReplies`'s per-family loop used to have no cap on how many
    // `recvBatch` calls it would make -- under a sustained flood it never
    // reached the "short batch => drained" exit, so `step()` (and therefore
    // `run()`'s own timing loop) never got control back. Measured live
    // 2026-09-05 (`perf flood2`, six concurrent flooders on the loopback RAW
    // socket): a 200ms-budget `run()` took 1500.9-9046.5ms (7.5x-45x) across
    // six runs, while a quiet run and a post-flood recovery run both held
    // 200.7-200.9ms.
    var p = try Pinger.init(std.testing.allocator, .{ .socket_mode = .raw });
    defer p.deinit();
    _ = try p.addTarget("127.0.0.1");
    p.prepare() catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };

    // Several RAW sockets flood loopback as fast as the kernel accepts
    // sends, each batching Socket.batch_max packets per sendmmsg call
    // (single-packet sendto() per iteration turned out far too slow to
    // outrun recvmmsg's own drain rate and never reproduced the bug this
    // guards). RAW sockets see every ICMP packet on the host (Socket.zig's
    // own doc comment on the .raw branch of handleReply), so this reaches
    // `p.sock4` without needing an actual round trip through anything.
    const flood_threads = 4;
    var flood_socks: [flood_threads]Socket = undefined;
    var opened: usize = 0;
    defer for (flood_socks[0..opened]) |*s| s.close();
    for (0..flood_threads) |i| {
        flood_socks[i] = Socket.open(.v4, .raw, .{}) catch |err| switch (err) {
            error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
            else => return err,
        };
        opened += 1;
    }

    var stop = std.atomic.Value(bool).init(false);
    const Flooder = struct {
        fn run(s: *const Socket, halt: *std.atomic.Value(bool)) void {
            var dst: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
            const dst_ptr: *const linux.sockaddr = @ptrCast(&dst);
            var pkt: [echo.echo_header_len]u8 = @splat(0);
            pkt[0] = echo.v4.echo_request;
            var addrs: [Socket.batch_max]*const linux.sockaddr = undefined;
            var pkts: [Socket.batch_max][]const u8 = undefined;
            for (0..Socket.batch_max) |i| {
                addrs[i] = dst_ptr;
                pkts[i] = &pkt;
            }
            while (!halt.load(.monotonic)) {
                _ = s.sendMany(&addrs, @sizeOf(linux.sockaddr.in), &pkts) catch 0;
            }
        }
    };
    var threads: [flood_threads]std.Thread = undefined;
    for (0..flood_threads) |i|
        threads[i] = try std.Thread.spawn(.{}, Flooder.run, .{ &flood_socks[i], &stop });
    defer {
        stop.store(true, .monotonic);
        for (threads) |t| t.join();
    }
    // Let the flood actually build up a backlog in the socket buffer before
    // measuring -- otherwise step() might race ahead of it.
    sleepMs(100);

    const t0 = monoNow();
    _ = try p.step();
    const elapsed_ms = @divTrunc(monoNow() - t0, std.time.ns_per_ms);

    // Budget: max_batches_per_drain (64) * Socket.batch_max (16) packets
    // handled inline per family, plus the error-queue drain -- thousands of
    // packets of local CPU work, comfortably under a second, and nowhere
    // near the flood's measured RED range (1500-9046ms).
    try std.testing.expect(elapsed_ms < 1000);
}

test "A1 F5: the socket error queue delivers ICMP errors for a DGRAM ping socket's own probes" {
    // On the (default, preferred) DGRAM path the kernel never puts an ICMP
    // error about our own probe on the normal receive queue -- it can only
    // be read back via IP_RECVERR + MSG_ERRQUEUE. Verified live under
    // `unshare` (`errq2.py`): a forged Time Exceeded quoting a DGRAM
    // socket's own ident/seq produced NOTHING on a normal recvmsg, but
    // appeared on the error queue immediately once IP_RECVERR was set --
    // with the quoted echo header as payload and the quoted destination as
    // the reported address.
    var p = try Pinger.init(std.testing.allocator, .{});
    defer p.deinit();
    const id = try p.addTarget("10.9.9.77");
    p.prepare() catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    const sock4 = &(p.sock4.?);
    // This test is specifically about the DGRAM path (A1 F5's "always 0"
    // claim does not apply to RAW, which already saw ICMP errors before
    // this fix). Environments where .auto fell back to RAW skip it.
    if (sock4.kind != .dgram) return error.SkipZigTest;

    var injector = Socket.open(.v4, .raw, .{}) catch |err| switch (err) {
        error.PermissionDenied, error.AddressFamilyUnsupported => return error.SkipZigTest,
        else => return err,
    };
    defer injector.close();

    const seq = try p.seqmap.add(id, 0, monoNow());

    // A forged ICMP Time Exceeded, quoting our own DGRAM socket's ident and
    // this probe's seq, with the quoted destination set to the real target
    // -- exactly what a real router's reply to this probe would carry.
    var pkt: [echo.echo_header_len + 20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.time_exceeded;
    pkt[8] = 0x45; // quoted IHL = 5
    pkt[8 + 8] = 64; // quoted TTL
    pkt[8 + 9] = 1; // quoted protocol = IPPROTO_ICMP -- required for the
    // kernel to match this quoted packet back to an ICMP (ping) socket at
    // all; without it the error queue never sees it, regardless of ident.
    pkt[8 + 12] = 127; // quoted source = 127.0.0.1 (our own local address)
    pkt[8 + 13] = 0;
    pkt[8 + 14] = 0;
    pkt[8 + 15] = 1;
    const target_bytes: [4]u8 = switch (p.targetAddr(id)) {
        .v4 => |a| @bitCast(a.addr),
        .v6 => unreachable,
    };
    @memcpy(pkt[8 + 16 ..][0..4], &target_bytes); // quoted destination
    const orig = pkt[8 + 20 ..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], sock4.ident, .big);
    std.mem.writeInt(u16, orig[6..8], seq, .big);
    std.mem.writeInt(u16, pkt[2..4], echo.checksum(&pkt), .big);

    var dst_sa: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    try injector.sendTo(@ptrCast(&dst_sa), @sizeOf(linux.sockaddr.in), &pkt);

    // Give the kernel a moment to route the injected packet and queue the
    // error before draining.
    sleepMs(50);

    try p.drainReplies(); // exercises drainErrQueue (A1 F5) internally
    try std.testing.expectEqual(@as(u32, 1), p.stats(id).icmp_errors);
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
