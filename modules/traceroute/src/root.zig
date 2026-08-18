// SPDX-License-Identifier: MIT

//! traceroute — ICMP-echo path discovery (TTL-stepped probes → per-hop
//! addresses + RTTs), built on the sibling `icmp` module's wire codec.
//!
//! The classic method: send ICMP Echo Requests with increasing IP TTL
//! (1, 2, 3, …). Each intermediate router that decrements the TTL to zero
//! answers with ICMP Time Exceeded — its source address is that hop. The
//! destination answers with an Echo Reply (path complete); an ICMP
//! Destination Unreachable also terminates the trace (the code is
//! recorded). Responses are correlated to the probe that triggered them via
//! the echo ident + sequence quoted inside the ICMP error (parsed by
//! `icmp.echo.parseV4`/`parseV6`), so even a response that arrives after
//! its probe already timed out is attributed to the right hop slot.
//!
//! Layers:
//!
//!  * `traceWith` — the hop state machine behind an injectable `Transport`
//!    seam (send probe with TTL / receive bytes + source / clock), fully
//!    offline-testable from canned packet bytes.
//!  * `LinuxTransport` + `trace` — the live path: a raw ICMP socket via
//!    `icmp.Socket` (requires CAP_NET_RAW), per-probe TTL via
//!    setsockopt IP_TTL / IPV6_UNICAST_HOPS, ppoll for the probe timeout.
//!
//! Probes are sequential (one in flight), like traceroute(8)'s default —
//! the state machine stays simple and every RTT is unambiguous. Malformed
//! or hostile ICMP bytes never panic: `icmp.echo` parsing is bounds-checked
//! and anything unrecognized is ignored while the probe's timeout keeps
//! counting; a probe that never gets an answer becomes a `.timeout` entry
//! (traceroute's `*`). Hop count and probes per hop are bounded
//! (`Options.validate`).
//!
//! **Real-capture anchor.** The canned-bytes tests below are hand-built RFC
//! 792 shapes, never checked against a real kernel. A separate "real-capture
//! goldens" section near the end of this file freezes bytes captured from an
//! ACTUAL Linux network stack: a genuine Time Exceeded from a real forwarding
//! router, a genuine Destination Host Unreachable from a real routing-table
//! miss, and a genuine Echo Reply — all captured inside a throwaway,
//! unprivileged `unshare --user --net` sandbox (two nested `unshare --net`
//! namespaces joined by a veth pair, one of them doing real IPv4 forwarding
//! with `net.ipv4.ip_forward=1`, entirely inside the sandbox's own user
//! namespace). No sudo, no setcap, nothing on the host changed — every
//! namespace and interface vanished when the capturing shell exited. This is
//! the traceroute equivalent of the sibling `icmp` module's own real-capture
//! section (see `../../icmp/src/echo.zig`), but goes one step further: that
//! module's notes say time_exceeded needs "CAP_NET_RAW on the host itself"
//! and calls it out of scope — a plain loopback send genuinely cannot
//! produce it (loopback delivery never enters the kernel's *forwarding*
//! path, so no TTL is ever decremented against a router). A second veth-
//! connected namespace acting as a real one-hop router sidesteps that
//! entirely: it is a real Linux router, forwarding real packets, decrementing
//! a real TTL to zero — no elevated host privilege needed, only two more
//! disposable namespaces. What is still NOT captured this way, and why: a
//! load-balanced hop (would need >= 2 real parallel routers on the same TTL,
//! not attempted), IPv6 (the topology above was only built for v4), and a
//! path longer than one real hop (this module's per-hop classification logic
//! is exercised identically regardless of hop count once one real hop is
//! proven, so a longer chain would add sandbox complexity without covering
//! any new code path). The existing loopback-gated live test below (`trace
//! to 127.0.0.1`) remains a real-CAP_NET_RAW reachability smoke test on
//! whatever host runs it, but by itself could only ever prove Echo Reply —
//! never Time Exceeded or Destination Unreachable, which is exactly the gap
//! the real-capture section closes offline.
//!
//! Basic usage (live; needs CAP_NET_RAW):
//!
//! ```zig
//! const traceroute = @import("traceroute");
//! const netaddr = @import("netaddr");
//!
//! const dest = netaddr.parseIp("192.0.2.1").?;
//! var tr = try traceroute.trace(gpa, dest, .{});
//! defer tr.deinit(gpa);
//! for (tr.hops) |hop| {
//!     const st = hop.stats(); // per-hop min/avg/max via latency-stats
//!     _ = st;
//! }
//! ```
//!
//! Provenance: clean-room — models the classic traceroute(8) / mtr ICMP
//! method (a public technique: Van Jacobson's TTL-stepping applied to ICMP
//! Echo) and RFC 792 (ICMP message formats, via the sibling `icmp` codec).
//! No traceroute, mtr or other third-party source consulted or copied —
//! behavior only. See ../../NOTICE.

const std = @import("std");
const builtin = @import("builtin");
const icmp = @import("icmp");
const echo = icmp.echo;
const netaddr = @import("netaddr");
const latency = @import("latency-stats");

const linux = std.os.linux;

pub const meta = .{
    .targets = .{ .linux64, .linux32 },
    .platform = .linux, // live path = raw ICMP socket (icmp.Socket); engine is pure
    .role = .client,
    .concurrency = .single_owner, // one trace run owns its transport + buffers
    .model_after = "traceroute(8) / mtr ICMP method",
    .deps = .{ "icmp", "netaddr", "latency-stats" },
};

// ── result model ────────────────────────────────────────────────────────────

/// One probe's outcome at a hop.
pub const Probe = struct {
    kind: Kind = .timeout,
    /// Source address of the response (the router / destination); null for
    /// `.timeout` (and for responses whose transport gave no source).
    address: ?netaddr.Ip = null,
    /// Round-trip time, send → matching response. Null for `.timeout`.
    rtt_ns: ?u64 = null,
    /// ICMP code for `.dest_unreachable` (RFC 792: 0 net, 1 host, 3 port,
    /// 13 administratively prohibited, …).
    code: ?u8 = null,

    /// `reply` = Echo Reply from the destination; `time_exceeded` = an
    /// intermediate router; `dest_unreachable` = terminal ICMP error;
    /// `timeout` = no answer (traceroute's `*`).
    pub const Kind = enum { reply, time_exceeded, dest_unreachable, timeout };
};

/// One TTL step: `probes.len == Options.probes_per_hop`.
pub const Hop = struct {
    ttl: u8,
    /// Slice into `Trace.probes`; owned by the `Trace`.
    probes: []const Probe,

    /// Per-hop RTT statistics (min/avg/max/stddev/loss) over the hop's
    /// probes, via `latency-stats` — timeouts count as losses.
    pub fn stats(hop: Hop) latency.Stats {
        var samples: [max_probes_per_hop]?u64 = undefined;
        for (hop.probes, samples[0..hop.probes.len]) |p, *s| s.* = p.rtt_ns;
        return latency.compute(samples[0..hop.probes.len]);
    }

    /// The distinct responder addresses seen at this hop, in order of first
    /// appearance — more than one means a load-balanced path. Asserts
    /// `buf.len >= probes.len`.
    pub fn distinctAddresses(hop: Hop, buf: []netaddr.Ip) []const netaddr.Ip {
        std.debug.assert(buf.len >= hop.probes.len);
        var n: usize = 0;
        for (hop.probes) |p| {
            const a = p.address orelse continue;
            const seen = for (buf[0..n]) |b| {
                if (b.eql(a)) break true;
            } else false;
            if (!seen) {
                buf[n] = a;
                n += 1;
            }
        }
        return buf[0..n];
    }

    /// First responder address at this hop, if any probe was answered.
    pub fn address(hop: Hop) ?netaddr.Ip {
        for (hop.probes) |p| {
            if (p.address) |a| return a;
        }
        return null;
    }
};

/// A completed (or partial) trace. Free with `deinit`.
pub const Trace = struct {
    dest: netaddr.Ip,
    /// True when the destination sent an Echo Reply.
    reached: bool,
    /// Set when the trace terminated on ICMP Destination Unreachable.
    unreachable_code: ?u8,
    /// Set when the trace stopped early because the transport itself failed
    /// — `sendFn`/`recvFn` returning an error, not a per-probe timeout (a
    /// normal outcome, recorded on the `Probe` instead). `hops`/`probes`
    /// still hold whatever was collected before the failure: eight good hops
    /// then a send failure is a useful partial path, not nothing, and this
    /// is how a caller tells "stopped early, here is what I have" apart from
    /// "reached the destination" or "hit Destination Unreachable" — the
    /// same way those two are already told apart from each other.
    transport_err: ?TransportError = null,
    /// The probed hops, first_ttl first. Ends at the hop that reached the
    /// destination, terminated the trace (`unreachable_code`,
    /// `transport_err`), or at max_hops.
    hops: []Hop,
    /// Backing storage for every hop's probes.
    probes: []Probe,

    pub fn deinit(tr: *Trace, gpa: std.mem.Allocator) void {
        gpa.free(tr.hops);
        gpa.free(tr.probes);
        tr.* = undefined;
    }
};

// ── options ─────────────────────────────────────────────────────────────────

/// Upper bound on `Options.probes_per_hop` (keeps per-hop scratch fixed).
pub const max_probes_per_hop = 16;

/// Upper bound on `Options.payload_size` (bytes after the 8-byte header).
pub const max_payload = 1024;

pub const Options = struct {
    /// Highest TTL probed (inclusive). Bounded by the u8 TTL itself.
    max_hops: u8 = 30,
    /// Probes sent at each TTL (traceroute's default 3).
    probes_per_hop: u8 = 3,
    /// Per-probe reply timeout.
    timeout_ms: u32 = 1000,
    first_ttl: u8 = 1,
    /// ICMP echo payload bytes (zero-filled) after the 8-byte header.
    payload_size: u16 = 24,
    /// Echo identifier stamped on every probe. The live `trace` fills it
    /// from the socket; only responses quoting it are considered.
    ident: u16 = 0x7472, // "tr"
    /// First sequence number; probe #k is sent as `seq_base +% k`.
    seq_base: u16 = 1,

    pub fn validate(o: Options) error{InvalidOptions}!void {
        if (o.first_ttl == 0 or o.max_hops < o.first_ttl) return error.InvalidOptions;
        if (o.probes_per_hop == 0 or o.probes_per_hop > max_probes_per_hop) return error.InvalidOptions;
        if (o.timeout_ms == 0) return error.InvalidOptions;
        if (o.payload_size > max_payload) return error.InvalidOptions;
    }
};

// ── transport seam ──────────────────────────────────────────────────────────

pub const TransportError = error{ SendFailed, RecvFailed };

/// One received packet, as the engine sees it.
pub const Packet = struct {
    /// Bytes written into the buffer passed to `recvFn`.
    len: usize,
    /// Source address of the packet, when the transport knows it.
    from: ?netaddr.Ip = null,
};

/// The socket seam: everything the hop state machine needs from the outside
/// world, injectable so the engine is offline-testable from canned bytes.
pub const Transport = struct {
    ctx: *anyopaque,
    /// True when received IPv4 packets start with the IP header (raw
    /// sockets do that; ICMPv6 sockets never deliver the IPv6 header).
    strip_ip_header: bool = false,
    /// Send one echo-request probe with the given IP TTL / hop limit.
    sendFn: *const fn (ctx: *anyopaque, ttl: u8, packet: []const u8) TransportError!void,
    /// Receive one packet into `buf` within `timeout_ns`; null on timeout.
    recvFn: *const fn (ctx: *anyopaque, buf: []u8, timeout_ns: u64) TransportError!?Packet,
    /// Monotonic clock, nanoseconds.
    nowFn: *const fn (ctx: *anyopaque) u64,
};

// ── the hop state machine ───────────────────────────────────────────────────

/// What has no partial `Trace` to show for it: neither happens after any
/// probe has been sent, so there is nothing yet to return alongside the
/// error. A transport failure mid-trace is different — see `Trace.transport_err`.
pub const TraceError = error{ InvalidOptions, OutOfMemory };

/// Trace the path to `dest` through an injected transport. Sequential:
/// one probe in flight; each TTL gets `probes_per_hop` probes; the trace
/// stops after the hop where the destination replied (`reached`), a
/// Destination Unreachable arrived (`unreachable_code`), the transport
/// itself failed (`transport_err` — the returned `Trace` still holds
/// whatever hops were collected before that), or at `max_hops`.
pub fn traceWith(
    gpa: std.mem.Allocator,
    t: Transport,
    dest: netaddr.Ip,
    opts: Options,
) TraceError!Trace {
    try opts.validate();

    const family: echo.Family = switch (dest) {
        .v4 => .v4,
        .v6 => .v6,
    };
    const ppn: usize = opts.probes_per_hop;
    const hop_capacity: usize = @as(usize, opts.max_hops - opts.first_ttl) + 1;
    const total = hop_capacity * ppn; // <= 255 * 16, always fits the u16 seq space

    // Flat probe slots: slot k = hop (k / ppn), probe (k % ppn). The wire
    // sequence number is `seq_base +% k`, so any response — even a late one
    // — maps back to its slot via the quoted ident/seq.
    const probes = try gpa.alloc(Probe, total);
    defer gpa.free(probes);
    @memset(probes, .{});
    const send_times = try gpa.alloc(?u64, total);
    defer gpa.free(send_times);
    @memset(send_times, null);

    var pkt_buf: [echo.echo_header_len + max_payload]u8 = undefined;
    var rbuf: [2048]u8 = undefined;
    const timeout_ns = @as(u64, opts.timeout_ms) * std.time.ns_per_ms;

    var reached = false;
    var unreachable_code: ?u8 = null;
    var transport_err: ?TransportError = null;
    var hops_used: usize = 0;

    outer: for (0..hop_capacity) |hi| {
        const ttl: u8 = opts.first_ttl + @as(u8, @intCast(hi));
        hops_used = hi + 1;

        for (0..ppn) |pi| {
            const slot = hi * ppn + pi;
            const seq = opts.seq_base +% @as(u16, @intCast(slot));

            const packet = pkt_buf[0 .. echo.echo_header_len + opts.payload_size];
            @memset(packet, 0);
            echo.writeEchoRequest(family, packet, opts.ident, seq);

            // A transport failure stops the trace here, but — unlike
            // InvalidOptions/OutOfMemory above, which happen before any probe
            // is sent — hops already collected are real data. `break :outer`
            // rather than `try`/`return`, so the packing below still runs and
            // hands back a partial `Trace` with `transport_err` set.
            t.sendFn(t.ctx, ttl, packet) catch |err| {
                transport_err = err;
                // If this was the hop's very first probe, nothing about this
                // hop was ever attempted — exclude it, matching what
                // `hops_used` means everywhere else here (a hop with at
                // least one attempted probe). A failure on a LATER probe of
                // the same hop leaves `hops_used` as already set: that hop
                // did get at least one real attempt, the same way an
                // `unreachable_code` stop mid-hop keeps the hop it stopped in.
                if (pi == 0) hops_used = hi;
                break :outer;
            };
            const sent_at = t.nowFn(t.ctx);
            send_times[slot] = sent_at;
            const deadline = sent_at + timeout_ns;

            recv: while (true) {
                const now = t.nowFn(t.ctx);
                if (now >= deadline) break :recv; // timeout → the slot stays `*`
                const resp = (t.recvFn(t.ctx, &rbuf, deadline - now) catch |err| {
                    transport_err = err;
                    break :outer;
                }) orelse break :recv;
                if (resp.len > rbuf.len) {
                    transport_err = error.RecvFailed;
                    break :outer;
                }
                const rcv_at = t.nowFn(t.ctx);

                // Reuse the icmp codec: bounds-checked, never panics;
                // anything malformed / not ours comes back `.ignored`.
                const reply = switch (family) {
                    .v4 => echo.parseV4(rbuf[0..resp.len], t.strip_ip_header),
                    .v6 => echo.parseV6(rbuf[0..resp.len]),
                };
                switch (reply) {
                    .ignored => continue :recv,
                    .echo_reply => |er| {
                        if (er.ident != opts.ident) continue :recv;
                        const j = slotOf(er.seq, opts.seq_base, total) orelse continue :recv;
                        const st = send_times[j] orelse continue :recv; // not sent yet: spoof
                        probes[j] = .{
                            .kind = .reply,
                            .address = resp.from orelse dest,
                            .rtt_ns = rcv_at -| st,
                        };
                        reached = true;
                        if (j == slot) break :recv;
                    },
                    .icmp_error => |ie| {
                        if (ie.orig_ident != opts.ident) continue :recv;
                        const j = slotOf(ie.orig_seq, opts.seq_base, total) orelse continue :recv;
                        const st = send_times[j] orelse continue :recv;
                        switch (ie.kind) {
                            .time_exceeded => probes[j] = .{
                                .kind = .time_exceeded,
                                .address = resp.from,
                                .rtt_ns = rcv_at -| st,
                            },
                            .dest_unreachable => {
                                probes[j] = .{
                                    .kind = .dest_unreachable,
                                    .address = resp.from,
                                    .rtt_ns = rcv_at -| st,
                                    .code = ie.code,
                                };
                                unreachable_code = ie.code;
                            },
                            // Redirect / param problem / packet too big:
                            // not a hop answer, keep waiting.
                            else => continue :recv,
                        }
                        if (j == slot) break :recv;
                    },
                }
            }

            // A terminal error stops the hop early; a destination reply
            // still gets the hop's full probe count (per-hop RTT stats).
            if (unreachable_code != null) break;
        }

        if (reached or unreachable_code != null) break :outer;
    }

    // Exact-size result: copy the used prefix so Trace frees whole slices.
    const out_probes = try gpa.dupe(Probe, probes[0 .. hops_used * ppn]);
    errdefer gpa.free(out_probes);
    const out_hops = try gpa.alloc(Hop, hops_used);
    for (out_hops, 0..) |*h, i| {
        h.* = .{
            .ttl = opts.first_ttl + @as(u8, @intCast(i)),
            .probes = out_probes[i * ppn ..][0..ppn],
        };
    }
    return .{
        .dest = dest,
        .reached = reached,
        .unreachable_code = unreachable_code,
        .transport_err = transport_err,
        .hops = out_hops,
        .probes = out_probes,
    };
}

/// Map a wire sequence number back to its flat probe slot (bounded scheme:
/// wraparound-safe subtraction, then a range check).
fn slotOf(seq: u16, base: u16, total: usize) ?usize {
    const idx: usize = seq -% base;
    return if (idx < total) idx else null;
}

// ── live path: raw ICMP socket (Linux, CAP_NET_RAW) ─────────────────────────

/// Live transport over `icmp.Socket` in raw mode. Raw is required: DGRAM
/// ("ping") sockets deliver ICMP errors on the error queue, not as packets.
/// Per-probe TTL via setsockopt IP_TTL (v4) / IPV6_UNICAST_HOPS (v6).
pub const LinuxTransport = struct {
    sock: icmp.Socket,
    dest: DestAddr,

    const DestAddr = union(enum) {
        v4: linux.sockaddr.in,
        v6: linux.sockaddr.in6,
    };

    pub const OpenError = icmp.Socket.OpenError;

    pub fn open(dest_ip: netaddr.Ip) OpenError!LinuxTransport {
        if (comptime builtin.os.tag != .linux)
            @compileError("traceroute.LinuxTransport is Linux-only (raw ICMP sockets)");
        const family: icmp.Socket.Family = switch (dest_ip) {
            .v4 => .v4,
            .v6 => .v6,
        };
        const sock = try icmp.Socket.open(family, .raw, .{});
        return .{
            .sock = sock,
            .dest = switch (dest_ip) {
                .v4 => |q| .{ .v4 = .{ .port = 0, .addr = @bitCast(q) } },
                .v6 => |b| .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = b, .scope_id = 0 } },
            },
        };
    }

    pub fn close(lt: *LinuxTransport) void {
        lt.sock.close();
        lt.* = undefined;
    }

    /// The socket's echo identifier — pass it as `Options.ident`.
    pub fn ident(lt: *const LinuxTransport) u16 {
        return lt.sock.ident;
    }

    pub fn transport(lt: *LinuxTransport) Transport {
        return .{
            .ctx = lt,
            // Raw v4 sockets deliver the IP header; ICMPv6 never does.
            .strip_ip_header = lt.sock.family == .v4,
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .nowFn = nowImpl,
        };
    }

    fn sendImpl(ctx: *anyopaque, ttl: u8, packet: []const u8) TransportError!void {
        const lt: *LinuxTransport = @ptrCast(@alignCast(ctx));
        const v: u32 = ttl;
        const rc = switch (lt.sock.family) {
            .v4 => linux.setsockopt(lt.sock.fd, linux.SOL.IP, linux.IP.TTL, @ptrCast(&v), @sizeOf(u32)),
            .v6 => linux.setsockopt(lt.sock.fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS, @ptrCast(&v), @sizeOf(u32)),
        };
        if (linux.errno(rc) != .SUCCESS) return error.SendFailed;

        var attempts: u8 = 0;
        while (true) {
            const res = switch (lt.dest) {
                .v4 => |*sa| lt.sock.sendTo(@ptrCast(sa), @sizeOf(linux.sockaddr.in), packet),
                .v6 => |*sa| lt.sock.sendTo(@ptrCast(sa), @sizeOf(linux.sockaddr.in6), packet),
            };
            res catch |err| switch (err) {
                error.WouldBlock => {
                    // Rare for one in-flight probe; wait for writability once.
                    attempts += 1;
                    if (attempts > 1) return error.SendFailed;
                    pollOnce(lt.sock.fd, linux.POLL.OUT, std.time.ns_per_ms * 100);
                    continue;
                },
                else => return error.SendFailed,
            };
            return;
        }
    }

    fn recvImpl(ctx: *anyopaque, buf: []u8, timeout_ns: u64) TransportError!?Packet {
        const lt: *LinuxTransport = @ptrCast(@alignCast(ctx));
        const deadline = monoNow() + timeout_ns;
        while (true) {
            if (lt.sock.recvMsg(buf)) |info| {
                return .{
                    .len = info.packet.len,
                    .from = switch (info.src) {
                        .none => null,
                        .v4 => |sa| .{ .v4 = @bitCast(sa.addr) },
                        .v6 => |sa| .{ .v6 = sa.addr },
                    },
                };
            }
            const now = monoNow();
            if (now >= deadline) return null;
            pollOnce(lt.sock.fd, linux.POLL.IN, deadline - now);
        }
    }

    fn nowImpl(_: *anyopaque) u64 {
        return monoNow();
    }

    fn pollOnce(fd: i32, events: i16, wait_ns: u64) void {
        var pfd = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        var ts: linux.timespec = .{
            .sec = @intCast(wait_ns / std.time.ns_per_s),
            .nsec = @intCast(wait_ns % std.time.ns_per_s),
        };
        _ = linux.ppoll(&pfd, pfd.len, &ts, null);
    }

    fn monoNow() u64 {
        // Same clock the sibling icmp engine uses (icmp.monoNow), as u64.
        return @intCast(icmp.monoNow());
    }
};

pub const LiveTraceError = TraceError || LinuxTransport.OpenError;

/// Trace the path to `dest` over a fresh raw ICMP socket (CAP_NET_RAW).
/// `opts.ident` is overwritten with the socket's identifier.
pub fn trace(gpa: std.mem.Allocator, dest: netaddr.Ip, opts: Options) LiveTraceError!Trace {
    var lt = try LinuxTransport.open(dest);
    defer lt.close();
    var o = opts;
    o.ident = lt.ident();
    return traceWith(gpa, lt.transport(), dest, o);
}

// ── tests: canned-bytes fake transport ──────────────────────────────────────

const testing = std.testing;

fn ip4(a: u8, b: u8, c: u8, d: u8) netaddr.Ip {
    return .{ .v4 = .{ a, b, c, d } };
}

const test_dest = ip4(192, 0, 2, 99);
const router_a = ip4(10, 0, 0, 1);
const router_b = ip4(10, 0, 1, 1);
const router_c = ip4(10, 0, 2, 1);

/// What the fake network does with a probe at a given TTL.
const Behavior = union(enum) {
    /// Router replies ICMP Time Exceeded.
    time_exceeded: netaddr.Ip,
    /// Alternating routers per probe (a load-balanced hop).
    time_exceeded_multi: []const netaddr.Ip,
    /// Like `time_exceeded`, but the answer arrives only after the probe's
    /// own window expired (a late reply, delivered during the next window).
    time_exceeded_late: netaddr.Ip,
    /// The destination replies ICMP Echo Reply.
    reply,
    /// The destination (or a filter) replies Destination Unreachable.
    unreach: struct { from: netaddr.Ip, code: u8 },
    /// Probe vanishes.
    drop,
    /// Raw bytes come back verbatim (malformed / hostile input).
    garbage: []const u8,
};

/// Offline transport: builds canned ICMP response bytes for every probe
/// sent, with a deterministic virtual clock (RTT = (n+1) ms for the n-th
/// send; a recv timeout advances the clock by the full timeout).
const FakeTransport = struct {
    /// behaviors[ttl - 1]; TTLs beyond the list drop.
    behaviors: []const Behavior,
    dest: netaddr.Ip = test_dest,
    family: echo.Family = .v4,
    /// Prepend a 20-byte IPv4 header to responses (raw-socket shape).
    with_ip_header: bool = false,

    clock: u64 = 1_000_000, // arbitrary epoch
    sends: u64 = 0,
    sent: std.ArrayList(Sent) = .empty,
    queue: std.ArrayList(Canned) = .empty,
    gpa: std.mem.Allocator = testing.allocator,
    /// If set, `sendFn` fails with `error.SendFailed` the first time a probe
    /// at this TTL is sent — never recorded into `sent`. Models the
    /// transport itself breaking mid-trace (a socket error, not a missing
    /// reply), which is otherwise unreachable from the canned-bytes fixtures
    /// below: every `Behavior` controls how the fake network answers, none
    /// of them controls whether the send call itself succeeds.
    fail_send_at_ttl: ?u8 = null,

    const Sent = struct { ttl: u8, ident: u16, seq: u16, len: usize };
    const Canned = struct { arrival: u64, from: ?netaddr.Ip, bytes: []u8 };

    fn deinit(f: *FakeTransport) void {
        f.sent.deinit(f.gpa);
        for (f.queue.items) |c| f.gpa.free(c.bytes);
        f.queue.deinit(f.gpa);
    }

    fn transport(f: *FakeTransport) Transport {
        return .{
            .ctx = f,
            .strip_ip_header = f.with_ip_header,
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .nowFn = nowImpl,
        };
    }

    fn nowImpl(ctx: *anyopaque) u64 {
        const f: *FakeTransport = @ptrCast(@alignCast(ctx));
        return f.clock;
    }

    fn sendImpl(ctx: *anyopaque, ttl: u8, packet: []const u8) TransportError!void {
        const f: *FakeTransport = @ptrCast(@alignCast(ctx));
        if (f.fail_send_at_ttl) |bad_ttl| if (ttl == bad_ttl) return error.SendFailed;
        const ident = std.mem.readInt(u16, packet[4..6][0..2], .big);
        const seq = std.mem.readInt(u16, packet[6..8][0..2], .big);
        f.sent.append(f.gpa, .{ .ttl = ttl, .ident = ident, .seq = seq, .len = packet.len }) catch return error.SendFailed;

        const rtt = (f.sends + 1) * std.time.ns_per_ms;
        f.sends += 1;

        const behavior: Behavior = if (ttl == 0 or ttl > f.behaviors.len)
            .drop
        else
            f.behaviors[ttl - 1];

        const probe_index = (f.sends - 1) % 16; // varies within a hop

        var bytes: []u8 = undefined;
        var from: ?netaddr.Ip = null;
        var arrival = f.clock + rtt;
        switch (behavior) {
            .drop => return,
            .reply => {
                bytes = f.buildEchoReply(packet) catch return error.SendFailed;
                from = f.dest;
            },
            .time_exceeded => |r| {
                bytes = f.buildError(echoErrType(f.family, .time_exceeded), 0, packet) catch return error.SendFailed;
                from = r;
            },
            .time_exceeded_multi => |routers| {
                bytes = f.buildError(echoErrType(f.family, .time_exceeded), 0, packet) catch return error.SendFailed;
                from = routers[probe_index % routers.len];
            },
            .time_exceeded_late => |r| {
                bytes = f.buildError(echoErrType(f.family, .time_exceeded), 0, packet) catch return error.SendFailed;
                from = r;
                arrival = f.clock + 1_500 * std.time.ns_per_ms; // > the probe's window
            },
            .unreach => |u| {
                bytes = f.buildError(echoErrType(f.family, .dest_unreachable), u.code, packet) catch return error.SendFailed;
                from = u.from;
            },
            .garbage => |g| {
                bytes = f.gpa.dupe(u8, g) catch return error.SendFailed;
                from = router_a;
            },
        }
        f.queue.append(f.gpa, .{ .arrival = arrival, .from = from, .bytes = bytes }) catch {
            f.gpa.free(bytes);
            return error.SendFailed;
        };
    }

    fn recvImpl(ctx: *anyopaque, buf: []u8, timeout_ns: u64) TransportError!?Packet {
        const f: *FakeTransport = @ptrCast(@alignCast(ctx));
        // Deliver the earliest queued response that arrives in the window.
        var best: ?usize = null;
        for (f.queue.items, 0..) |c, i| {
            if (c.arrival > f.clock + timeout_ns) continue;
            if (best == null or c.arrival < f.queue.items[best.?].arrival) best = i;
        }
        const i = best orelse {
            f.clock += timeout_ns; // window expires
            return null;
        };
        const c = f.queue.orderedRemove(i);
        defer f.gpa.free(c.bytes);
        if (c.bytes.len > buf.len) return error.RecvFailed;
        @memcpy(buf[0..c.bytes.len], c.bytes);
        f.clock = @max(f.clock, c.arrival);
        return .{ .len = c.bytes.len, .from = c.from };
    }

    // ── canned wire bytes (RFC 792 shapes, built by hand) ──

    fn prefixLen(f: *const FakeTransport) usize {
        return if (f.with_ip_header) 20 else 0;
    }

    /// Echo Reply: the request with the type flipped (checksum refreshed).
    fn buildEchoReply(f: *FakeTransport, request: []const u8) ![]u8 {
        const p = f.prefixLen();
        const out = try f.gpa.alloc(u8, p + request.len);
        f.writeIpHeader(out);
        const body = out[p..];
        @memcpy(body, request);
        body[0] = switch (f.family) {
            .v4 => echo.v4.echo_reply,
            .v6 => echo.v6.echo_reply,
        };
        writeChecksum(body);
        return out;
    }

    /// ICMP error quoting the original request: type/code + 4 unused bytes,
    /// then the quoted IP header (20B v4 / 40B v6) + the original echo
    /// header (8 bytes) — exactly what parseV4/parseV6 expect.
    fn buildError(f: *FakeTransport, err_type: u8, code: u8, orig: []const u8) ![]u8 {
        const p = f.prefixLen();
        const quoted_hdr: usize = switch (f.family) {
            .v4 => 20,
            .v6 => 40,
        };
        const out = try f.gpa.alloc(u8, p + echo.echo_header_len + quoted_hdr + echo.echo_header_len);
        @memset(out, 0);
        f.writeIpHeader(out);
        const body = out[p..];
        body[0] = err_type;
        body[1] = code;
        switch (f.family) {
            .v4 => body[echo.echo_header_len] = 0x45, // quoted IPv4 header, ihl=5
            .v6 => body[echo.echo_header_len + 6] = 58, // quoted next header = ICMPv6
        }
        @memcpy(
            body[echo.echo_header_len + quoted_hdr ..],
            orig[0..echo.echo_header_len],
        );
        writeChecksum(body);
        return out;
    }

    fn writeIpHeader(f: *const FakeTransport, out: []u8) void {
        if (!f.with_ip_header) return;
        @memset(out[0..20], 0);
        out[0] = 0x45; // IPv4, ihl = 5
    }

    fn writeChecksum(body: []u8) void {
        body[2] = 0;
        body[3] = 0;
        std.mem.writeInt(u16, body[2..4][0..2], echo.checksum(body), .big);
    }

    fn echoErrType(family: echo.Family, kind: enum { time_exceeded, dest_unreachable }) u8 {
        return switch (family) {
            .v4 => switch (kind) {
                .time_exceeded => echo.v4.time_exceeded,
                .dest_unreachable => echo.v4.dest_unreachable,
            },
            .v6 => switch (kind) {
                .time_exceeded => echo.v6.time_exceeded,
                .dest_unreachable => echo.v6.dest_unreachable,
            },
        };
    }
};

fn runFake(f: *FakeTransport, opts: Options) TraceError!Trace {
    return traceWith(testing.allocator, f.transport(), f.dest, opts);
}

test "probes carry the right TTL, ident and seq" {
    var f: FakeTransport = .{ .behaviors = &.{ .{ .time_exceeded = router_a }, .{ .time_exceeded = router_b }, .reply } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 3, .ident = 0xabcd, .seq_base = 100, .payload_size = 16 });
    defer tr.deinit(testing.allocator);

    // 3 hops * 3 probes: TTL steps 1,1,1,2,2,2,3,3,3; seq increments from 100.
    try testing.expectEqual(@as(usize, 9), f.sent.items.len);
    for (f.sent.items, 0..) |s, k| {
        try testing.expectEqual(@as(u8, @intCast(k / 3 + 1)), s.ttl);
        try testing.expectEqual(@as(u16, 0xabcd), s.ident);
        try testing.expectEqual(@as(u16, 100 + @as(u16, @intCast(k))), s.seq);
        try testing.expectEqual(@as(usize, echo.echo_header_len + 16), s.len);
    }
}

test "time exceeded maps routers to hops; echo reply reaches and stops" {
    var f: FakeTransport = .{ .behaviors = &.{
        .{ .time_exceeded = router_a },
        .{ .time_exceeded = router_b },
        .reply,
    } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .max_hops = 30 });
    defer tr.deinit(testing.allocator);

    try testing.expect(tr.reached);
    try testing.expectEqual(@as(?u8, null), tr.unreachable_code);
    try testing.expectEqual(@as(usize, 3), tr.hops.len); // stopped, not 30

    try testing.expectEqual(@as(u8, 1), tr.hops[0].ttl);
    for (tr.hops[0].probes) |p| {
        try testing.expectEqual(Probe.Kind.time_exceeded, p.kind);
        try testing.expect(p.address.?.eql(router_a));
        try testing.expect(p.rtt_ns.? > 0);
    }
    try testing.expect(tr.hops[1].address().?.eql(router_b));

    // The destination hop: full probe count, all echo replies from dest.
    for (tr.hops[2].probes) |p| {
        try testing.expectEqual(Probe.Kind.reply, p.kind);
        try testing.expect(p.address.?.eql(test_dest));
    }
}

test "destination unreachable terminates and records the code" {
    var f: FakeTransport = .{
        .behaviors = &.{
            .{ .time_exceeded = router_a },
            .{ .unreach = .{ .from = router_b, .code = 13 } }, // admin prohibited
            .reply, // never reached
        },
    };
    defer f.deinit();
    var tr = try runFake(&f, .{});
    defer tr.deinit(testing.allocator);

    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(?u8, 13), tr.unreachable_code);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    const p = tr.hops[1].probes[0];
    try testing.expectEqual(Probe.Kind.dest_unreachable, p.kind);
    try testing.expectEqual(@as(?u8, 13), p.code);
    try testing.expect(p.address.?.eql(router_b));
    // The error stops the hop: probes 2 and 3 were never sent.
    try testing.expectEqual(@as(usize, 4), f.sent.items.len);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[1].probes[1].kind);
}

test "a silent hop times out as * and the trace continues" {
    var f: FakeTransport = .{ .behaviors = &.{
        .{ .time_exceeded = router_a },
        .drop,
        .reply,
    } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .timeout_ms = 500 });
    defer tr.deinit(testing.allocator);

    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 3), tr.hops.len);
    for (tr.hops[1].probes) |p| {
        try testing.expectEqual(Probe.Kind.timeout, p.kind);
        try testing.expectEqual(@as(?netaddr.Ip, null), p.address);
        try testing.expectEqual(@as(?u64, null), p.rtt_ns);
    }
    const st = tr.hops[1].stats();
    try testing.expectEqual(@as(u64, 3), st.sent);
    try testing.expectEqual(@as(u64, 0), st.received);
    try testing.expectApproxEqAbs(@as(f64, 100), st.lossPct(), 1e-9);
}

test "load-balanced hop: two distinct router addresses across 3 probes" {
    var f: FakeTransport = .{ .behaviors = &.{
        .{ .time_exceeded_multi = &.{ router_a, router_b } },
        .reply,
    } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 3 });
    defer tr.deinit(testing.allocator);

    var buf: [max_probes_per_hop]netaddr.Ip = undefined;
    const distinct = tr.hops[0].distinctAddresses(&buf);
    try testing.expectEqual(@as(usize, 2), distinct.len);
    try testing.expect(distinct[0].eql(router_a));
    try testing.expect(distinct[1].eql(router_b));
    // Single-address hop for contrast.
    const d2 = tr.hops[1].distinctAddresses(&buf);
    try testing.expectEqual(@as(usize, 1), d2.len);
}

test "late reply is attributed to the probe that triggered it" {
    var f: FakeTransport = .{
        .behaviors = &.{
            .{ .time_exceeded_late = router_c }, // arrives during hop 2's window
            .drop,
            .reply,
        },
    };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .timeout_ms = 1000 });
    defer tr.deinit(testing.allocator);

    // Hop 1's probe timed out first; its Time Exceeded arrived while hop 2
    // was waiting — the quoted ident/seq routes it back to hop 1 and the
    // RTT is measured against hop 1's own send time.
    const p1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.time_exceeded, p1.kind);
    try testing.expect(p1.address.?.eql(router_c));
    try testing.expectEqual(@as(u64, 1_500 * std.time.ns_per_ms), p1.rtt_ns.?);
    // Hop 2 itself stayed silent, hop 3 reached the destination.
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[1].probes[0].kind);
    try testing.expectEqual(Probe.Kind.reply, tr.hops[2].probes[0].kind);
    try testing.expect(tr.reached);
}

test "per-hop RTT stats via latency-stats" {
    var f: FakeTransport = .{ .behaviors = &.{.reply} };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 3 });
    defer tr.deinit(testing.allocator);

    // Fake RTTs are 1, 2, 3 ms for the three probes.
    const st = tr.hops[0].stats();
    try testing.expectEqual(@as(u64, 3), st.received);
    try testing.expectEqual(@as(u64, 1 * std.time.ns_per_ms), st.min_ns);
    try testing.expectEqual(@as(u64, 3 * std.time.ns_per_ms), st.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 2 * std.time.ns_per_ms), st.mean_ns, 1e-6);
}

test "raw-socket shape: v4 responses with a leading IP header" {
    var f: FakeTransport = .{
        .behaviors = &.{ .{ .time_exceeded = router_a }, .reply },
        .with_ip_header = true,
    };
    defer f.deinit();
    var tr = try runFake(&f, .{});
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expect(tr.hops[0].address().?.eql(router_a));
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
}

test "IPv6: time exceeded + echo reply" {
    var f: FakeTransport = .{
        .behaviors = &.{ .{ .time_exceeded = netaddr.parseIp("2001:db8::1").? }, .reply },
        .dest = netaddr.parseIp("2001:db8::99").?,
        .family = .v6,
    };
    defer f.deinit();
    var tr = try runFake(&f, .{});
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(Probe.Kind.time_exceeded, tr.hops[0].probes[0].kind);
    try testing.expectEqual(Probe.Kind.reply, tr.hops[1].probes[0].kind);
    try testing.expect(tr.dest.eql(tr.hops[1].probes[0].address.?));
}

test "malformed and hostile bytes are ignored, never panic" {
    // Truncated time-exceeded (quote too short for parseV4), a short blob,
    // and an empty packet: all must parse to .ignored and the probe must
    // fall through to a clean timeout.
    const truncated_te = [_]u8{ echo.v4.time_exceeded, 0, 0, 0, 0, 0, 0, 0, 0x45, 1, 2 };
    for ([_][]const u8{ &truncated_te, &.{ 0xff, 0x00, 0x01 }, &.{} }) |g| {
        var f: FakeTransport = .{ .behaviors = &.{ .{ .garbage = g }, .reply } };
        defer f.deinit();
        var tr = try runFake(&f, .{ .probes_per_hop = 1 });
        defer tr.deinit(testing.allocator);
        try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
        try testing.expect(tr.reached);
    }
}

test "responses with a foreign ident are ignored" {
    // A garbage packet that IS a well-formed echo reply, but for someone
    // else's ident — must not resolve any probe.
    var alien: [echo.echo_header_len]u8 = @splat(0);
    echo.writeEchoRequest(.v4, &alien, 0x1111, 7);
    alien[0] = echo.v4.echo_reply;
    var f: FakeTransport = .{ .behaviors = &.{ .{ .garbage = &alien }, .reply } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .ident = 0x2222 });
    defer tr.deinit(testing.allocator);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
}

test "responses with an out-of-range seq (matching ident) are ignored" {
    // `slotOf` maps seq -> flat slot via wraparound subtraction then a
    // range check against `total`; a reply whose seq lands exactly one
    // past the last valid slot (idx == total) must be rejected just like
    // a wildly out-of-range one — pin both, not just the "foreign ident"
    // case above.
    const ident: u16 = 0x2222;
    const seq_base: u16 = 5;
    // probes_per_hop=1, max_hops=1 -> total = 1; only seq 5 (idx 0) is valid.
    const bad_seqs = [_]u16{ 6, 9999 };
    for (bad_seqs) |bad_seq| {
        var alien: [echo.echo_header_len]u8 = @splat(0);
        echo.writeEchoRequest(.v4, &alien, ident, bad_seq);
        alien[0] = echo.v4.echo_reply;
        var f: FakeTransport = .{ .behaviors = &.{.{ .garbage = &alien }} };
        defer f.deinit();
        var tr = try runFake(&f, .{
            .probes_per_hop = 1,
            .max_hops = 1,
            .ident = ident,
            .seq_base = seq_base,
        });
        defer tr.deinit(testing.allocator);
        try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    }
}

test "ICMP redirect is not treated as a hop answer (keeps waiting, then times out)" {
    // Every canned Behavior in this file is either time_exceeded or
    // dest_unreachable — the `else => continue :recv` arm for redirect /
    // param-problem / packet-too-big has no coverage at all. Hand-build a
    // well-formed ICMP Redirect quoting probe #0 (default ident 0x7472,
    // seq_base 1) and confirm it is swallowed rather than resolving the
    // probe as a hop answer.
    var redirect_pkt: [8 + 20 + echo.echo_header_len]u8 = @splat(0);
    redirect_pkt[0] = echo.v4.redirect;
    redirect_pkt[8] = 0x45; // quoted IPv4 header, ihl=5
    const orig = redirect_pkt[8 + 20 ..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0x7472, .big); // default Options.ident
    std.mem.writeInt(u16, orig[6..8], 1, .big); // seq_base=1 -> probe #0

    var f: FakeTransport = .{ .behaviors = &.{ .{ .garbage = &redirect_pkt }, .reply } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .timeout_ms = 50 });
    defer tr.deinit(testing.allocator);

    // The redirect must not resolve hop 1's probe as any kind of answer —
    // it keeps waiting and eventually times out; hop 2 still reaches dest.
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    try testing.expect(tr.reached);
    try testing.expectEqual(Probe.Kind.reply, tr.hops[1].probes[0].kind);
}

test "options are validated" {
    var f: FakeTransport = .{ .behaviors = &.{.reply} };
    defer f.deinit();
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .probes_per_hop = 0 }));
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .probes_per_hop = max_probes_per_hop + 1 }));
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .first_ttl = 0 }));
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .first_ttl = 5, .max_hops = 4 }));
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .timeout_ms = 0 }));
    try testing.expectError(error.InvalidOptions, traceWith(gpa, f.transport(), test_dest, .{ .payload_size = max_payload + 1 }));
}

test "unanswered trace runs to max_hops" {
    var f: FakeTransport = .{ .behaviors = &.{.drop} };
    defer f.deinit();
    var tr = try runFake(&f, .{ .max_hops = 5, .probes_per_hop = 1, .timeout_ms = 100 });
    defer tr.deinit(testing.allocator);
    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(usize, 5), tr.hops.len);
    try testing.expectEqual(@as(u8, 5), tr.hops[4].ttl);
    for (tr.hops) |h| try testing.expectEqual(@as(?netaddr.Ip, null), h.address());
}

test "first_ttl offsets the hop window" {
    var f: FakeTransport = .{ .behaviors = &.{
        .{ .time_exceeded = router_a },
        .{ .time_exceeded = router_b },
        .reply,
    } };
    defer f.deinit();
    var tr = try runFake(&f, .{ .first_ttl = 2, .probes_per_hop = 1 });
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(@as(u8, 2), tr.hops[0].ttl);
    try testing.expect(tr.hops[0].address().?.eql(router_b));
    try testing.expectEqual(@as(u8, 2), f.sent.items[0].ttl);
}

// ── SendFailed/RecvFailed: the partial Trace survives a transport error ────

test "a send failure after two good hops returns the partial Trace, not nothing" {
    // Before this, traceWith propagated a transport error with `try`/`return`,
    // discarding hops[0]/hops[1] entirely — an eight-good-hops-then-a-failure
    // trace is most of a traceroute's value, not a failure to report as
    // opaquely as InvalidOptions/OutOfMemory (which really do have nothing to
    // show, because they happen before any probe is sent).
    var f: FakeTransport = .{
        .behaviors = &.{
            .{ .time_exceeded = router_a },
            .{ .time_exceeded = router_b },
            .reply, // never reached: TTL 3 never gets to send
        },
        .fail_send_at_ttl = 3,
    };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1 });
    defer tr.deinit(testing.allocator);

    // The failure is reported, distinctly from "reached"/"unreachable"...
    try testing.expectEqual(@as(?TransportError, error.SendFailed), tr.transport_err);
    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(?u8, null), tr.unreachable_code);
    // ...and the two good hops collected before it are still there, correct.
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(Probe.Kind.time_exceeded, tr.hops[0].probes[0].kind);
    try testing.expect(tr.hops[0].probes[0].address.?.eql(router_a));
    try testing.expectEqual(Probe.Kind.time_exceeded, tr.hops[1].probes[0].kind);
    try testing.expect(tr.hops[1].probes[0].address.?.eql(router_b));
    // The failed TTL's probe was never recorded as sent.
    try testing.expectEqual(@as(usize, 2), f.sent.items.len);
}

test "a recv-layer failure also returns the partial Trace, not nothing" {
    // Symmetric with the send-failure case above: `recvFn` returning an
    // error mid-trace must not discard what came before it either. A reply
    // larger than traceWith's internal receive buffer (2048 B) makes
    // FakeTransport's own `recvImpl` report `error.RecvFailed`, exercising
    // the same `catch` path a real socket's read error would.
    var big: [3000]u8 = undefined;
    var f: FakeTransport = .{
        .behaviors = &.{
            .{ .time_exceeded = router_a },
            .{ .garbage = &big },
            .reply, // never reached
        },
    };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .timeout_ms = 500 });
    defer tr.deinit(testing.allocator);

    try testing.expectEqual(@as(?TransportError, error.RecvFailed), tr.transport_err);
    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(Probe.Kind.time_exceeded, tr.hops[0].probes[0].kind);
    try testing.expect(tr.hops[0].probes[0].address.?.eql(router_a));
    // Hop 2's probe: the send succeeded (it is what triggered the failing
    // recv), so it still counts as a "used" hop, same as an unreachable_code
    // stop mid-hop does — but with no answer, its slot stays the default `*`.
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[1].probes[0].kind);
}

// ── real-capture goldens (veth 2-hop router sandbox, 2026-08-02) ───────────
//
// See this file's module doc comment ("Real-capture anchor") for the full
// methodology and honest limitations. Summary: inside a throwaway, fully
// unprivileged `unshare --user --net` sandbox, two more `unshare --net`
// namespaces were joined by veth pairs into client -> router -> server, with
// `net.ipv4.ip_forward=1` set in the router namespace (a real Linux router,
// just confined to disposable interfaces). A raw ICMP socket in the client
// namespace sent real echo-request probes (ident 0x7472 — this module's
// `Options` default) and the bytes below are the UNMODIFIED replies a real
// kernel sent back, IP header included (raw ICMP sockets deliver it, hence
// `strip_ip_header = true` below, matching `LinuxTransport`'s own v4 setting).
// No sudo, no setcap, no host-visible state: every interface and namespace
// existed only for the life of the capturing shell.
//
//   - `real_time_exceeded_icmp`: probe sent with TTL=1 (seq=1) toward the
//     server — the ROUTER's real forwarding code decremented TTL to zero and
//     replied Time Exceeded from its own address (10.0.0.2). This is the
//     genuine kernel forwarding path; a loopback send can never produce it
//     (see the module doc comment).
//   - `real_dest_unreachable_icmp`: probe sent (seq=2) to an address the
//     router has an explicit `ip route add unreachable 10.0.2.0/24` for — a
//     real routing-table miss, synthesized by the real Linux IP stack as
//     Destination Host Unreachable (code 1), not by iptables/nftables.
//   - `real_echo_reply_icmp`: probe sent (seq=3) straight to the server
//     (10.0.1.2), which really answered with Echo Reply.
//
// All three verify byte-for-byte under this module's own `echo.checksum`
// (see the count-canary test below) — the checksum is the KERNEL's, this
// only confirms `checksum()` agrees it's zero, same cross-check style as the
// sibling `icmp` module's real-capture section.

const real_time_exceeded_icmp = [_]u8{
    0x45, 0xc0, 0x00, 0x50, 0x0c, 0x10, 0x00, 0x00, 0x40, 0x01, 0x59, 0xdb, 0x0a, 0x00, 0x00, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x0b, 0x00, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x34,
    0x4a, 0x59, 0x40, 0x00, 0x01, 0x01, 0x1a, 0x6e, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01, 0x02,
    0x08, 0x00, 0x83, 0x8c, 0x74, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const real_dest_unreachable_icmp = [_]u8{
    0x45, 0xc0, 0x00, 0x50, 0x0c, 0xaa, 0x00, 0x00, 0x40, 0x01, 0x59, 0x41, 0x0a, 0x00, 0x00, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x03, 0x01, 0xfc, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x34,
    0x27, 0x9d, 0x40, 0x00, 0x40, 0x01, 0xfd, 0x26, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x02, 0x05,
    0x08, 0x00, 0x83, 0x8b, 0x74, 0x72, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const real_echo_reply_icmp = [_]u8{
    0x45, 0x00, 0x00, 0x34, 0x6d, 0x9e, 0x00, 0x00, 0x3f, 0x01, 0xf9, 0x28, 0x0a, 0x00, 0x01, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x8a, 0x74, 0x72, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

const real_router_addr = ip4(10, 0, 0, 2);
const real_server_addr = ip4(10, 0, 1, 2);

/// Minimal transport for the real-capture goldens: on each recv, hands back
/// the NEXT captured packet verbatim — no synthesis, no recomputed checksum,
/// nothing derived from this module's own encoder. `sendFn` is a no-op: the
/// golden's whole value is the kernel's real reply, and the canned-bytes
/// tests above already anchor this module's own request encoding.
const ReplayTransport = struct {
    packets: []const struct { bytes: []const u8, from: netaddr.Ip },
    i: usize = 0,
    clock: u64 = 0,

    fn transport(r: *ReplayTransport) Transport {
        return .{
            .ctx = r,
            .strip_ip_header = true, // real raw-socket capture includes the IP header
            .sendFn = sendImpl,
            .recvFn = recvImpl,
            .nowFn = nowImpl,
        };
    }

    fn sendImpl(_: *anyopaque, _: u8, _: []const u8) TransportError!void {}

    fn nowImpl(ctx: *anyopaque) u64 {
        const r: *ReplayTransport = @ptrCast(@alignCast(ctx));
        r.clock += std.time.ns_per_ms;
        return r.clock;
    }

    fn recvImpl(ctx: *anyopaque, buf: []u8, _: u64) TransportError!?Packet {
        const r: *ReplayTransport = @ptrCast(@alignCast(ctx));
        if (r.i >= r.packets.len) return null; // exhausted -> the caller times out
        const p = r.packets[r.i];
        r.i += 1;
        if (p.bytes.len > buf.len) return error.RecvFailed;
        @memcpy(buf[0..p.bytes.len], p.bytes);
        return .{ .len = p.bytes.len, .from = p.from };
    }
};

test "REAL CAPTURE: genuine kernel Time Exceeded, then genuine Destination Host Unreachable, from a live 2-hop router" {
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_time_exceeded_icmp[20..]));
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_dest_unreachable_icmp[20..]));

    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_time_exceeded_icmp, .from = real_router_addr },
        .{ .bytes = &real_dest_unreachable_icmp, .from = real_router_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, .{
        .max_hops = 2,
        .probes_per_hop = 1,
        .ident = 0x7472,
        .seq_base = 1,
        .timeout_ms = 500,
    });
    defer tr.deinit(testing.allocator);

    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(@as(?u8, 1), tr.unreachable_code); // real Host Unreachable

    const hop1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.time_exceeded, hop1.kind);
    try testing.expect(hop1.address.?.eql(real_router_addr));

    const hop2 = tr.hops[1].probes[0];
    try testing.expectEqual(Probe.Kind.dest_unreachable, hop2.kind);
    try testing.expectEqual(@as(?u8, 1), hop2.code);
    try testing.expect(hop2.address.?.eql(real_router_addr));
}

test "REAL CAPTURE: genuine kernel Echo Reply reaches the destination" {
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_echo_reply_icmp[20..]));

    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_echo_reply_icmp, .from = real_server_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, .{
        .max_hops = 1,
        .probes_per_hop = 1,
        .ident = 0x7472,
        .seq_base = 3,
        .timeout_ms = 500,
    });
    defer tr.deinit(testing.allocator);

    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 1), tr.hops.len);
    const hop1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.reply, hop1.kind);
    try testing.expect(hop1.address.?.eql(real_server_addr));
}

test "REAL CAPTURE: fixture count + size canary — 3 real veth-router captures" {
    // Pins fixture shapes so a future re-capture silently changing sizes
    // (e.g. a kernel quoting more/less of the original datagram) doesn't
    // slip by unnoticed.
    try testing.expectEqual(@as(usize, 80), real_time_exceeded_icmp.len);
    try testing.expectEqual(@as(usize, 80), real_dest_unreachable_icmp.len);
    try testing.expectEqual(@as(usize, 52), real_echo_reply_icmp.len);
}

test "live: trace to 127.0.0.1 (skipped without CAP_NET_RAW)" {
    const dest = netaddr.parseIp("127.0.0.1").?;
    var lt = LinuxTransport.open(dest) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer lt.close();
    var opts: Options = .{ .max_hops = 3, .timeout_ms = 2000 };
    opts.ident = lt.ident();
    var tr = try traceWith(testing.allocator, lt.transport(), dest, opts);
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 1), tr.hops.len);
    const p = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.reply, p.kind);
    try testing.expect(p.address.?.eql(dest));
}
