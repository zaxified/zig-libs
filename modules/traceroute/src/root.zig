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
//! behavior only. See ../../../NOTICE.

const std = @import("std");
const builtin = @import("builtin");
const icmp = @import("icmp");
const echo = icmp.echo;
const netaddr = @import("netaddr");
const latency = @import("latency-stats");

const linux = std.os.linux;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "ICMP-echo path discovery — TTL-stepped probes, per-hop address + RTT stats, load-balanced-path aware",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{ .linux64, .linux32 },
    .platform = .linux, // live path = raw ICMP socket (icmp.Socket); engine is pure
    .role = .client,
    .concurrency = .single_owner, // one trace run owns its transport + buffers
    .model_after = "traceroute(8) / mtr (ICMP and UDP methods)",
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
    /// 13 administratively prohibited, …), and for a UDP-method `.reply`
    /// (the destination's own Port Unreachable: 3 on IPv4, 4 on IPv6).
    code: ?u8 = null,
    /// MPLS label stack the router quoted in an RFC 4950 extension of its
    /// ICMP error (RFC 4884 multi-part message) — what `traceroute -e`
    /// prints as `<MPLS:L=…>`. Empty when there was none.
    mpls: MplsStack = .{},

    /// `reply` = the destination answered (Echo Reply for the ICMP method,
    /// its own Port Unreachable for the UDP method); `time_exceeded` = an
    /// intermediate router; `dest_unreachable` = terminal ICMP error;
    /// `timeout` = no answer (traceroute's `*`).
    pub const Kind = enum { reply, time_exceeded, dest_unreachable, timeout };
};

/// One MPLS label stack entry (RFC 3032 §2.1), as quoted by RFC 4950.
pub const MplsEntry = struct {
    label: u20,
    /// Traffic class (the former EXP bits, RFC 5462).
    tc: u3,
    /// S: bottom of the stack.
    bottom: bool,
    ttl: u8,
};

/// A bounded MPLS label stack (plain data, so `Probe` stays copyable).
pub const MplsStack = struct {
    entries: [max_mpls_labels]MplsEntry = undefined,
    len: u8 = 0,

    pub fn slice(m: *const MplsStack) []const MplsEntry {
        return m.entries[0..m.len];
    }
};

/// Labels kept per probe; deeper stacks are truncated (real ones are 1-3).
pub const max_mpls_labels = 8;

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

/// Upper bound on an `Options`'s worst-case wall-clock run time (probe count
/// times `timeout_ms`; every probe timing out is the worst case). A1 F6/F8:
/// `max_hops`, `probes_per_hop` and `timeout_ms` are each bounded on their
/// own, but nothing bounded their PRODUCT — the worst individually-legal
/// combination (255 hops x 16 probes x a u32-max timeout) is 4080 probes
/// worth ~202,817 days, and those same 4080 probes at `max_payload` also put
/// ~4.2 MB on the wire toward one address with no rate limit. 30 minutes is
/// far past any legitimate interactive or scripted use of this module and
/// comfortably clears realistic large scans (e.g. 64 hops x 5 probes x 3 s
/// = 16 min); `Options.validate` rejects anything past it.
pub const max_run_ms: u64 = 30 * 60 * 1000;

/// How probes are sent. traceroute(8) defaults to `.udp`; mtr and
/// `traceroute -I` use `.icmp`. A network that drops ICMP echo shows a wall
/// of `*` with `.icmp` and usually not with `.udp`, and vice versa.
pub const Method = enum {
    /// ICMP Echo Request; the destination answers Echo Reply.
    icmp,
    /// UDP datagrams to `udp_port_base + k`; the destination answers ICMP
    /// Port Unreachable (nothing should listen on those ports).
    udp,
};

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
    method: Method = .icmp,
    /// UDP method: probe #k goes to destination port `udp_port_base + k`
    /// (traceroute(8)'s classic 33434 upwards); a reply is matched by the
    /// quoted destination port. The source port is the correlation token
    /// (`ident`): the live `trace` uses the socket's bound port.
    udp_port_base: u16 = 33434,

    // Live path only (`trace`); `traceWith` ignores them — the injected
    // transport decides where packets go.
    /// Bind to this interface (SO_BINDTODEVICE) — pick the egress on a
    /// multi-homed host.
    iface: ?[]const u8 = null,
    /// Source address to send from.
    source: ?netaddr.Ip = null,
    /// IP TOS / IPv6 traffic class of the probes.
    tos: ?u8 = null,
    /// Routing mark (SO_MARK, policy routing); needs CAP_NET_ADMIN.
    fwmark: ?u32 = null,

    pub fn validate(o: Options) error{InvalidOptions}!void {
        if (o.first_ttl == 0 or o.max_hops < o.first_ttl) return error.InvalidOptions;
        if (o.probes_per_hop == 0 or o.probes_per_hop > max_probes_per_hop) return error.InvalidOptions;
        if (o.timeout_ms == 0) return error.InvalidOptions;
        if (o.payload_size > max_payload) return error.InvalidOptions;
        if (o.method == .udp) {
            // Every probe needs its own, non-zero destination port.
            const probes_total: u32 = (@as(u32, o.max_hops) - o.first_ttl + 1) * o.probes_per_hop;
            if (o.udp_port_base == 0 or @as(u32, o.udp_port_base) + probes_total - 1 > std.math.maxInt(u16))
                return error.InvalidOptions;
        }
        // A1 F6/F8: bound the PRODUCT, not just each field — see max_run_ms.
        const hop_count: u64 = @as(u64, o.max_hops - o.first_ttl) + 1;
        const total_probes: u64 = hop_count * @as(u64, o.probes_per_hop);
        const worst_case_ms: u64 = total_probes * @as(u64, o.timeout_ms);
        if (worst_case_ms > max_run_ms) return error.InvalidOptions;
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
    /// UDP method: send `payload` to the destination's `dst_port` with this
    /// TTL. Null for a transport that cannot (`traceWith` then refuses
    /// `Method.udp` with `error.InvalidOptions`).
    sendUdpFn: ?*const fn (ctx: *anyopaque, ttl: u8, dst_port: u16, payload: []const u8) TransportError!void = null,
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
    if (opts.method == .udp and t.sendUdpFn == null) return error.InvalidOptions;

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

            // A transport failure stops the trace here, but — unlike
            // InvalidOptions/OutOfMemory above, which happen before any probe
            // is sent — hops already collected are real data. `break :outer`
            // rather than `try`/`return`, so the packing below still runs and
            // hands back a partial `Trace` with `transport_err` set.
            const sent: TransportError!void = switch (opts.method) {
                .icmp => blk: {
                    const packet = pkt_buf[0 .. echo.echo_header_len + opts.payload_size];
                    @memset(packet, 0);
                    // `packet` is sliced to `echo_header_len + payload_size`
                    // just above, so it cannot be short. A panic rather than
                    // `unreachable`: `unreachable` is undefined behaviour in
                    // the release modes, which is the fail-open shape this
                    // writer's new signature exists to remove.
                    echo.writeEchoRequest(family, packet, opts.ident, seq) catch
                        @panic("traceroute: probe buffer smaller than the ICMP header");
                    break :blk t.sendFn(t.ctx, ttl, packet);
                },
                .udp => blk: {
                    const payload = pkt_buf[0..opts.payload_size];
                    @memset(payload, 0);
                    // validate() proved base + slot never passes 65535.
                    const port: u16 = opts.udp_port_base + @as(u16, @intCast(slot));
                    break :blk t.sendUdpFn.?(t.ctx, ttl, port, payload);
                },
            };
            sent catch |err| {
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

                const icmp_msg = icmpMessage(family, rbuf[0..resp.len], t.strip_ip_header) orelse continue :recv;

                if (opts.method == .udp) {
                    const ue = parseUdpError(family, icmp_msg) orelse continue :recv;
                    if (ue.sport != opts.ident) continue :recv;
                    const j = slotOf(ue.dport, opts.udp_port_base, total) orelse continue :recv;
                    const st = send_times[j] orelse continue :recv; // not sent yet: spoof
                    if (probes[j].kind != .timeout) continue :recv; // A1 F12, see below
                    if (!quotedDestIs(dest, ue.quoted_dst)) continue :recv; // A1 F3, see below
                    const rtt = rcv_at -| st;
                    switch (ue.kind) {
                        .time_exceeded => probes[j] = .{
                            .kind = .time_exceeded,
                            .address = resp.from,
                            .rtt_ns = rtt,
                            .mpls = mplsOf(family, icmp_msg),
                        },
                        .dest_unreachable => {
                            // The destination's own Port Unreachable is the
                            // UDP method's "reply" — the counterpart of the
                            // ICMP method's Echo Reply, held to the same
                            // source check (A1 F1). Anything else, or from
                            // anyone else, is a terminal error.
                            const port_unreach: u8 = if (family == .v4) 3 else 4;
                            const from_dest = if (resp.from) |from| from.eql(dest) else true;
                            if (ue.code == port_unreach and from_dest) {
                                probes[j] = .{ .kind = .reply, .address = resp.from orelse dest, .rtt_ns = rtt, .code = ue.code };
                                reached = true;
                            } else {
                                probes[j] = .{
                                    .kind = .dest_unreachable,
                                    .address = resp.from,
                                    .rtt_ns = rtt,
                                    .code = ue.code,
                                    .mpls = mplsOf(family, icmp_msg),
                                };
                                unreachable_code = ue.code;
                            }
                        },
                    }
                    if (j == slot) break :recv;
                    continue :recv;
                }

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
                        // A1 F12: a slot that already has a real answer keeps
                        // it — the first non-timeout write wins, not the
                        // last. Otherwise a duplicate or spoofed packet for
                        // an already-resolved slot silently overwrites its
                        // address/RTT (and, for `.icmp_error` below, could
                        // re-trigger `unreachable_code`/terminate the trace)
                        // with no test able to see it happen.
                        if (probes[j].kind != .timeout) continue :recv;
                        // A1 F1: `reached` (and the address it records) is
                        // documented as "the destination sent an Echo
                        // Reply" — the only signal this engine has for that
                        // claim is the reply's own source address, so
                        // require it to match `dest` when the transport
                        // reports one. Without this, a single Echo Reply
                        // from ANY address carrying the right ident/seq set
                        // `reached = true` and truncated the whole trace to
                        // one hop attributed to the spoofer. Routers
                        // answering Time Exceeded / Destination Unreachable
                        // from their own address (below) are unaffected —
                        // that is the whole point of path measurement.
                        if (resp.from) |from| {
                            if (!from.eql(dest)) continue :recv;
                        }
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
                        if (probes[j].kind != .timeout) continue :recv; // A1 F12, see above
                        // A1 F3 (closed at its source, `icmp` module F2):
                        // every probe this function sends targets `dest`
                        // (TTL is the only thing that changes hop to hop),
                        // so a genuine router's Time Exceeded / Destination
                        // Unreachable always quotes `dest` back. Before
                        // `icmp.echo.Reply.icmp_error` carried the quoted
                        // header at all, this correlated on ident+seq
                        // alone — the audit's own passing test proved it:
                        // a fixture quoting dst = 10.0.2.5 (not the actual
                        // `real_server_addr` probed) still resolved a hop.
                        const quoted_dest_matches = switch (dest) {
                            .v4 => |q| std.mem.eql(u8, ie.quoted_dst[0..4], &q),
                            .v6 => |b| std.mem.eql(u8, &ie.quoted_dst, &b),
                        };
                        if (!quoted_dest_matches) continue :recv;
                        switch (ie.kind) {
                            .time_exceeded => probes[j] = .{
                                .kind = .time_exceeded,
                                .address = resp.from,
                                .rtt_ns = rcv_at -| st,
                                .mpls = mplsOf(family, icmp_msg),
                            },
                            .dest_unreachable => {
                                probes[j] = .{
                                    .kind = .dest_unreachable,
                                    .address = resp.from,
                                    .rtt_ns = rcv_at -| st,
                                    .code = ie.code,
                                    .mpls = mplsOf(family, icmp_msg),
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

fn quotedDestIs(dest: netaddr.Ip, quoted: [16]u8) bool {
    return switch (dest) {
        .v4 => |q| std.mem.eql(u8, quoted[0..4], &q),
        .v6 => |b| std.mem.eql(u8, &quoted, &b),
    };
}

/// The ICMP message inside a received packet: past the IPv4 header when the
/// transport delivers it (raw IPv4 sockets do), and with a valid ICMPv4
/// checksum (RFC 792) — the same gate `icmp.echo.parseV4` applies. ICMPv6's
/// checksum needs the pseudo-header, which only the kernel has; it verifies
/// it before delivery to an ICMPv6 socket.
fn icmpMessage(family: echo.Family, buf: []const u8, strip_ip_header: bool) ?[]const u8 {
    var b = buf;
    if (family == .v4 and strip_ip_header) {
        if (b.len < 20) return null;
        const ihl: usize = @as(usize, b[0] & 0x0f) * 4;
        if (ihl < 20 or b.len < ihl) return null;
        b = b[ihl..];
    }
    if (b.len < echo.echo_header_len) return null;
    if (family == .v4 and echo.checksum(b) != 0) return null;
    return b;
}

/// An ICMP Time Exceeded / Destination Unreachable that quotes a UDP probe.
const UdpError = struct {
    kind: enum { time_exceeded, dest_unreachable },
    code: u8,
    quoted_dst: [16]u8,
    sport: u16,
    dport: u16,
};

/// Parse an ICMP error quoting an IPv4/IPv6 header + the first 8 bytes of a
/// UDP datagram (RFC 792 / RFC 4443 §3.1 guarantee at least those). Null for
/// anything else — other ICMP types, a quoted protocol other than UDP, a
/// quote too short to hold the ports.
fn parseUdpError(family: echo.Family, msg: []const u8) ?UdpError {
    const kind: @FieldType(UdpError, "kind") = switch (family) {
        .v4 => switch (msg[0]) {
            echo.v4.time_exceeded => .time_exceeded,
            echo.v4.dest_unreachable => .dest_unreachable,
            else => return null,
        },
        .v6 => switch (msg[0]) {
            echo.v6.time_exceeded => .time_exceeded,
            echo.v6.dest_unreachable => .dest_unreachable,
            else => return null,
        },
    };
    const quoted = msg[echo.echo_header_len..];
    var out: UdpError = .{ .kind = kind, .code = msg[1], .quoted_dst = @splat(0), .sport = 0, .dport = 0 };
    const udp: []const u8 = switch (family) {
        .v4 => blk: {
            if (quoted.len < 20) return null;
            const qihl: usize = @as(usize, quoted[0] & 0x0f) * 4;
            if (qihl < 20 or quoted.len < qihl + 8) return null;
            if (quoted[9] != 17) return null; // quoted protocol must be UDP
            @memcpy(out.quoted_dst[0..4], quoted[16..20]);
            break :blk quoted[qihl..];
        },
        .v6 => blk: {
            if (quoted.len < 40 + 8) return null;
            if (quoted[6] != 17) return null; // next header must be UDP
            @memcpy(&out.quoted_dst, quoted[24..40]);
            break :blk quoted[40..];
        },
    };
    out.sport = std.mem.readInt(u16, udp[0..2], .big);
    out.dport = std.mem.readInt(u16, udp[2..4], .big);
    return out;
}

/// The RFC 4884 extension structure's objects of an ICMP Time Exceeded /
/// Destination Unreachable, or null when it carries none (or a damaged one).
///
/// RFC 4884 §4/§5: the ICMP header's length field (IPv4: byte 5, 32-bit
/// words; IPv6: byte 4, 64-bit words) gives the size of the quoted original
/// datagram, which is then at least 128 bytes, and the extension structure
/// follows it. Routers that predate RFC 4884 append it at a fixed 128 bytes
/// with the length field left 0 ("compatibility", §5): that case is accepted
/// only when a version-2 header with a verified checksum sits right there.
pub fn extensionObjects(family: echo.Family, msg: []const u8) ?[]const u8 {
    if (msg.len < echo.echo_header_len) return null;
    const is_error = switch (family) {
        .v4 => msg[0] == echo.v4.time_exceeded or msg[0] == echo.v4.dest_unreachable,
        .v6 => msg[0] == echo.v6.time_exceeded or msg[0] == echo.v6.dest_unreachable,
    };
    if (!is_error) return null;
    const words: usize = if (family == .v4) msg[5] else msg[4];
    const unit: usize = if (family == .v4) 4 else 8;
    const compat = words == 0;
    const orig_len: usize = if (compat) 128 else words * unit;
    if (orig_len < 128) return null;
    const off = echo.echo_header_len + orig_len;
    if (msg.len < off + 4) return null;
    const ext = msg[off..];
    if (ext[0] >> 4 != 2) return null; // extension structure version 2
    const cks = std.mem.readInt(u16, ext[2..4], .big);
    // The checksum is mandatory for a compatibility-mode guess (it is the
    // only evidence the bytes are an extension at all); otherwise a zero
    // field means "not computed".
    if (cks != 0 or compat) {
        if (cks == 0 or echo.checksum(ext) != 0) return null;
    }
    return ext[4..];
}

/// The MPLS label stack (RFC 4950: class 1, c-type 1) among an ICMP error's
/// extension objects; empty when there is none.
pub fn mplsOf(family: echo.Family, msg: []const u8) MplsStack {
    var out: MplsStack = .{};
    var objs = extensionObjects(family, msg) orelse return out;
    while (objs.len >= 4) {
        const len = std.mem.readInt(u16, objs[0..2], .big);
        if (len < 4 or len > objs.len) break;
        if (objs[2] == 1 and objs[3] == 1) {
            var e = objs[4..len];
            while (e.len >= 4 and out.len < max_mpls_labels) : (e = e[4..]) {
                const v = std.mem.readInt(u32, e[0..4], .big);
                out.entries[out.len] = .{
                    .label = @intCast(v >> 12),
                    .tc = @intCast((v >> 9) & 0x7),
                    .bottom = v & 0x100 != 0,
                    .ttl = @intCast(v & 0xff),
                };
                out.len += 1;
            }
            return out;
        }
        objs = objs[len..];
    }
    return out;
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
    /// UDP method: the send socket, and its bound source port (the probes'
    /// correlation token, `Options.ident`).
    udp_fd: ?i32 = null,
    udp_port: u16 = 0,

    const DestAddr = union(enum) {
        v4: linux.sockaddr.in,
        v6: linux.sockaddr.in6,
    };

    pub const OpenError = icmp.Socket.OpenError || error{UdpSocketFailed};

    pub fn open(dest_ip: netaddr.Ip) OpenError!LinuxTransport {
        return openWith(dest_ip, .{});
    }

    /// `open` honouring `opts.method`, `.iface`, `.source`, `.tos` and
    /// `.fwmark`. The raw ICMP socket receives every reply (for both
    /// methods: Time Exceeded / Port Unreachable for a UDP probe arrive as
    /// ICMP); the UDP method adds a datagram socket to send from.
    pub fn openWith(dest_ip: netaddr.Ip, opts: Options) OpenError!LinuxTransport {
        if (comptime builtin.os.tag != .linux)
            @compileError("traceroute.LinuxTransport is Linux-only (raw ICMP sockets)");
        const family: icmp.Socket.Family = switch (dest_ip) {
            .v4 => .v4,
            .v6 => .v6,
        };
        const src_sa: ?SockAddr = if (opts.source) |src| sockAddr(src, 0) else null;
        var sock = try icmp.Socket.open(family, .raw, .{
            .iface = opts.iface,
            .tos = if (opts.method == .icmp) opts.tos else null,
            .fwmark = opts.fwmark,
            .source = if (src_sa) |sa| switch (sa) {
                .v4 => |v| .{ .v4 = v },
                .v6 => |v| .{ .v6 = v },
            } else null,
        });
        errdefer sock.close();
        var lt: LinuxTransport = .{
            .sock = sock,
            .dest = switch (dest_ip) {
                .v4 => |q| .{ .v4 = .{ .port = 0, .addr = @bitCast(q) } },
                .v6 => |b| .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = b, .scope_id = 0 } },
            },
        };
        if (opts.method == .udp) {
            const fd = try openUdp(family, opts, src_sa);
            lt.udp_fd = fd;
            lt.udp_port = boundPort(fd) catch {
                _ = linux.close(fd);
                return error.UdpSocketFailed;
            };
        }
        return lt;
    }

    const SockAddr = union(enum) { v4: linux.sockaddr.in, v6: linux.sockaddr.in6 };

    fn sockAddr(ip: netaddr.Ip, port: u16) SockAddr {
        return switch (ip) {
            .v4 => |q| .{ .v4 = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(q) } },
            .v6 => |b| .{ .v6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = b, .scope_id = 0 } },
        };
    }

    fn openUdp(family: icmp.Socket.Family, opts: Options, src: ?SockAddr) OpenError!i32 {
        const af: u32 = if (family == .v4) linux.AF.INET else linux.AF.INET6;
        const rc = linux.socket(af, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.UdpSocketFailed;
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);
        if (opts.iface) |name| {
            if (linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, name.ptr, @intCast(name.len))) != .SUCCESS)
                return error.UdpSocketFailed;
        }
        if (opts.tos) |tos| {
            const v: u32 = tos;
            const r = switch (family) {
                .v4 => linux.setsockopt(fd, linux.SOL.IP, linux.IP.TOS, @ptrCast(&v), @sizeOf(u32)),
                .v6 => linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.TCLASS, @ptrCast(&v), @sizeOf(u32)),
            };
            if (linux.errno(r) != .SUCCESS) return error.UdpSocketFailed;
        }
        if (opts.fwmark) |mark| {
            if (linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.MARK, @ptrCast(&mark), @sizeOf(u32))) != .SUCCESS)
                return error.UdpSocketFailed;
        }
        // Bind (to the source address, or any) with port 0: the kernel picks
        // an ephemeral source port, which becomes the correlation token.
        const any: SockAddr = if (family == .v4)
            .{ .v4 = .{ .port = 0, .addr = 0 } }
        else
            .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = @splat(0), .scope_id = 0 } };
        const sa = src orelse any;
        const brc = switch (sa) {
            .v4 => |*v| linux.bind(fd, @ptrCast(v), @sizeOf(linux.sockaddr.in)),
            .v6 => |*v| linux.bind(fd, @ptrCast(v), @sizeOf(linux.sockaddr.in6)),
        };
        if (linux.errno(brc) != .SUCCESS) return error.UdpSocketFailed;
        return fd;
    }

    fn boundPort(fd: i32) error{UdpSocketFailed}!u16 {
        var ss: linux.sockaddr.in6 = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        if (linux.errno(linux.getsockname(fd, @ptrCast(&ss), &len)) != .SUCCESS) return error.UdpSocketFailed;
        // sin_port and sin6_port sit at the same offset.
        return std.mem.bigToNative(u16, ss.port);
    }

    pub fn close(lt: *LinuxTransport) void {
        if (lt.udp_fd) |fd| _ = linux.close(fd);
        lt.sock.close();
        lt.* = undefined;
    }

    /// The probes' correlation token — pass it as `Options.ident`: the UDP
    /// socket's source port for the UDP method, else the ICMP socket's echo
    /// identifier.
    pub fn ident(lt: *const LinuxTransport) u16 {
        return if (lt.udp_fd != null) lt.udp_port else lt.sock.ident;
    }

    pub fn transport(lt: *LinuxTransport) Transport {
        return .{
            .ctx = lt,
            // Raw v4 sockets deliver the IP header; ICMPv6 never does.
            .strip_ip_header = lt.sock.family == .v4,
            .sendFn = sendImpl,
            .sendUdpFn = if (lt.udp_fd != null) sendUdpImpl else null,
            .recvFn = recvImpl,
            .nowFn = nowImpl,
        };
    }

    fn sendUdpImpl(ctx: *anyopaque, ttl: u8, dst_port: u16, payload: []const u8) TransportError!void {
        const lt: *LinuxTransport = @ptrCast(@alignCast(ctx));
        const fd = lt.udp_fd orelse return error.SendFailed;
        const v: u32 = ttl;
        const rc = switch (lt.sock.family) {
            .v4 => linux.setsockopt(fd, linux.SOL.IP, linux.IP.TTL, @ptrCast(&v), @sizeOf(u32)),
            .v6 => linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS, @ptrCast(&v), @sizeOf(u32)),
        };
        if (linux.errno(rc) != .SUCCESS) return error.SendFailed;
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const port = std.mem.nativeToBig(u16, dst_port);
            const sent = switch (lt.dest) {
                .v4 => |sa| blk: {
                    var d = sa;
                    d.port = port;
                    break :blk linux.sendto(fd, payload.ptr, payload.len, 0, @ptrCast(&d), @sizeOf(linux.sockaddr.in));
                },
                .v6 => |sa| blk: {
                    var d = sa;
                    d.port = port;
                    break :blk linux.sendto(fd, payload.ptr, payload.len, 0, @ptrCast(&d), @sizeOf(linux.sockaddr.in6));
                },
            };
            switch (linux.errno(sent)) {
                .SUCCESS => return,
                // A previous probe's ICMP error can surface as a pending
                // socket error on this send (ECONNREFUSED for a Port
                // Unreachable, EHOSTUNREACH, …). The raw socket already
                // delivered that ICMP message; the error is not this send's
                // — clear it by retrying once.
                .CONNREFUSED, .HOSTUNREACH, .NETUNREACH => if (attempt > 0) return error.SendFailed,
                else => return error.SendFailed,
            }
        }
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

/// A1 F2: best-effort per-trace ident and starting sequence, drawn from
/// `getrandom(2)` rather than the raw ICMP socket's PID-derived identifier
/// (`icmp.Socket` stamps `.raw` sockets with `getpid() & 0xffff` — that
/// value is never used by the kernel to demux a raw socket's traffic, it is
/// purely this module's own correlation token, so this module is free to
/// pick a better one) and the fixed `Options{}.seq_base = 1` default.
/// Measured on this host: PID-derived idents differ from a neighboring
/// process's by exactly 1 in ~99.8% of cases, and `seq` was always exactly
/// 1, 2, 3, … — together a ~2-guess off-path correlation window. Raises the
/// bar against a *blind* off-path spoofer to a full unknown 16+16 bits;
/// does nothing against an on-path attacker who reads the real values off
/// the wire (see SPEC.md "Threat model"). Same posture as the sibling
/// `pathmtu.randomStartSeq` (CONVENTIONS.md §2.2): not a secret, so a
/// syscall failure falls back to the old fixed values rather than aborting.
fn randomIdentAndSeq() struct { ident: u16, seq_base: u16 } {
    var buf: [4]u8 = undefined;
    while (true) {
        const rc = linux.getrandom(&buf, buf.len, 0);
        const signed: isize = @bitCast(rc);
        if (signed == buf.len) return .{
            .ident = std.mem.readInt(u16, buf[0..2], .little),
            .seq_base = std.mem.readInt(u16, buf[2..4], .little),
        };
        if (signed == -@as(isize, @intFromEnum(linux.E.INTR))) continue;
        return .{ .ident = 0x7472, .seq_base = 1 }; // getrandom unavailable: old fixed values
    }
}

/// Trace the path to `dest` over a fresh raw ICMP socket (CAP_NET_RAW).
/// `opts.ident` and `opts.seq_base` are overwritten with fresh random
/// values for this trace (A1 F2) — the socket's own PID-derived identifier
/// is never used for probes sent by this function.
pub fn trace(gpa: std.mem.Allocator, dest: netaddr.Ip, opts: Options) LiveTraceError!Trace {
    try opts.validate();
    var lt = try LinuxTransport.openWith(dest, opts);
    defer lt.close();
    var o = opts;
    const r = randomIdentAndSeq();
    // UDP: the kernel-chosen ephemeral source port is the token — it is what
    // the replies quote back.
    o.ident = if (opts.method == .udp) lt.ident() else r.ident;
    o.seq_base = r.seq_base;
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

        // Bounded to [0, 16) by construction (`% 16`), so the narrowing to
        // `usize` below is provably in range on every host width this
        // collection targets, not a truncation of `f.sends` (which is not
        // itself bounded -- a trace can run arbitrarily many probes).
        const probe_index: usize = @intCast((f.sends - 1) % 16); // varies within a hop

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
        // A1 F3 (closed at its source, `icmp` module F2): the quoted IP
        // header's destination must be `f.dest` -- every probe this fake
        // network answers was addressed there, so a genuine router's error
        // always quotes it back. Before `icmp.echo.Reply.icmp_error` carried
        // the quoted destination at all, this canned-bytes builder never
        // needed to fill it in either.
        switch (f.family) {
            .v4 => {
                body[echo.echo_header_len] = 0x45; // quoted IPv4 header, ihl=5
                const dst4 = switch (f.dest) {
                    .v4 => |q| q,
                    .v6 => unreachable,
                };
                @memcpy(body[echo.echo_header_len + 16 ..][0..4], &dst4);
            },
            .v6 => {
                body[echo.echo_header_len + 6] = 58; // quoted next header = ICMPv6
                const dst6 = switch (f.dest) {
                    .v6 => |b| b,
                    .v4 => unreachable,
                };
                @memcpy(body[echo.echo_header_len + 24 ..][0..16], &dst6);
            },
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
    try echo.writeEchoRequest(.v4, &alien, 0x1111, 7);
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
        try echo.writeEchoRequest(.v4, &alien, ident, bad_seq);
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

// ── A1 fix-campaign regression tests ────────────────────────────────────────

test "F1: an echo reply spoofed from a foreign source address does not resolve the trace" {
    // Before this fix, `traceWith` accepted an Echo Reply carrying the
    // right ident+seq from ANY source address, not just `dest` -- a single
    // off-path spoofed packet set `reached = true` and truncated the whole
    // trace to one hop, attributed to the spoofer's own address.
    var alien: [echo.echo_header_len]u8 = @splat(0);
    try echo.writeEchoRequest(.v4, &alien, 0x7472, 1); // default ident, seq_base 1 -> slot 0
    alien[0] = echo.v4.echo_reply;
    // `.garbage` behavior stamps `from = router_a` (NOT `test_dest`).
    var f: FakeTransport = .{ .behaviors = &.{.{ .garbage = &alien }} };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .max_hops = 1, .timeout_ms = 50 });
    defer tr.deinit(testing.allocator);
    try testing.expect(!tr.reached);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
}

test "F1: a genuine echo reply from the destination itself still resolves the trace" {
    // Positive control for the check above: nothing about the fix should
    // reject the ordinary case.
    var f: FakeTransport = .{ .behaviors = &.{.reply} };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .max_hops = 1 });
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(Probe.Kind.reply, tr.hops[0].probes[0].kind);
    try testing.expect(tr.hops[0].probes[0].address.?.eql(test_dest));
}

test "F5: a reply with the right ident but a not-yet-sent slot is rejected" {
    // Isolates the `send_times[j] orelse continue` guard from the ident
    // check next to it. The audit's original "foreign ident" test used a
    // WRONG ident whose seq also happened to land on an unsent slot, so a
    // mutation deleting the ident check alone still passed (caught by this
    // other guard instead) -- it never actually exercised the ident branch
    // in isolation. Here the ident is correct (default 0x7472) and only the
    // slot is wrong: seq_base 1, probe_per_hop 1 means seq 2 is hop 2's
    // slot, which has not been sent while hop 1 is still waiting.
    // `.garbage` always stamps `from = router_a`, and the A1 F1 fix now
    // requires an echo reply's source to match `dest` -- so `dest` is set
    // to `router_a` here too, or F1's check would reject this packet on
    // its own and this test would stop isolating anything.
    var alien: [echo.echo_header_len]u8 = @splat(0);
    try echo.writeEchoRequest(.v4, &alien, 0x7472, 2); // right ident, hop 2's (unsent) slot
    alien[0] = echo.v4.echo_reply;
    var f: FakeTransport = .{ .behaviors = &.{ .{ .garbage = &alien }, .drop }, .dest = router_a };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .max_hops = 2, .timeout_ms = 50 });
    defer tr.deinit(testing.allocator);
    try testing.expect(!tr.reached);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[1].probes[0].kind);
}

test "F5: a reply with a wrong ident for an already-sent slot is rejected" {
    // Isolates the ident check from the "not sent yet" guard, the other
    // direction: the slot IS already sent (so the unsent-slot guard would
    // NOT reject it on its own), and only the ident is wrong.
    // Same reason as the test above: `dest = router_a` so the A1 F1 source
    // check does not independently reject this packet and mask what this
    // test is actually meant to isolate.
    var alien: [echo.echo_header_len]u8 = @splat(0);
    try echo.writeEchoRequest(.v4, &alien, 0x1111, 1); // wrong ident, hop 1's already-sent slot
    alien[0] = echo.v4.echo_reply;
    var f: FakeTransport = .{ .behaviors = &.{.{ .garbage = &alien }}, .dest = router_a };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .max_hops = 1, .ident = 0x7472, .timeout_ms = 50 });
    defer tr.deinit(testing.allocator);
    try testing.expect(!tr.reached);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
}

test "F12: a slot that already has a real answer keeps it; a duplicate for it is ignored" {
    // "Eviction": hop 1 is genuinely answered by router_a inside its own
    // window. A duplicate/spoofed Time Exceeded for the SAME slot (hop 1's
    // seq) then arrives during hop 2's window -- exactly how a legitimate
    // LATE reply is meant to land (see "late reply is attributed to the
    // probe that triggered it" above), except this one targets a slot that
    // is already resolved. Before this fix the duplicate silently
    // overwrote hop 1's address/RTT with no test able to see it happen.
    // A well-formed ICMP Time Exceeded, quoting hop 1's probe (seq 1, NOT
    // hop 2's seq 2) -- same wire shape as the "ICMP redirect" test above.
    var dup: [8 + 20 + echo.echo_header_len]u8 = @splat(0);
    dup[0] = echo.v4.time_exceeded;
    dup[8] = 0x45; // quoted IPv4 header, ihl=5
    const dup_orig = dup[8 + 20 ..];
    dup_orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, dup_orig[4..6], 0x7472, .big); // default Options.ident
    std.mem.writeInt(u16, dup_orig[6..8], 1, .big); // hop 1's slot
    var f: FakeTransport = .{
        .behaviors = &.{
            .{ .time_exceeded = router_a }, // hop 1: genuine answer, resolved on time
            .{ .garbage = &dup }, // hop 2: a duplicate answer for hop 1's slot arrives instead
            .reply, // hop 3: destination, still reachable
        },
    };
    defer f.deinit();
    var tr = try runFake(&f, .{ .probes_per_hop = 1, .max_hops = 3, .timeout_ms = 500 });
    defer tr.deinit(testing.allocator);

    const hop1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.time_exceeded, hop1.kind);
    try testing.expect(hop1.address.?.eql(router_a));
    // The RTT recorded is hop 1's OWN round trip (1st send -> 1ms in
    // FakeTransport's deterministic clock), not hop 2's (2nd send -> 2ms) --
    // if the guard were missing, the duplicate delivered in hop 2's window
    // would have overwritten it.
    try testing.expectEqual(@as(u64, 1 * std.time.ns_per_ms), hop1.rtt_ns.?);
    // Hop 2 itself never got a real answer for ITS OWN slot: the duplicate
    // consumed its window without resolving it.
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[1].probes[0].kind);
    try testing.expect(tr.reached);
}

test "F2: randomIdentAndSeq draws fresh values, not the old fixed ident/seq_base=1" {
    var idents = std.AutoHashMap(u16, void).init(testing.allocator);
    defer idents.deinit();
    var seqs = std.AutoHashMap(u16, void).init(testing.allocator);
    defer seqs.deinit();
    for (0..64) |_| {
        const r = randomIdentAndSeq();
        try idents.put(r.ident, {});
        try seqs.put(r.seq_base, {});
    }
    // 64 draws from a 65536-value space landing on < 32 distinct values in
    // either column would be an astronomically unlikely coincidence if the
    // draws were actually random; the old code returned exactly ONE value
    // (the fixed 0x7472 ident / seq_base 1) every single time.
    try testing.expect(idents.count() > 32);
    try testing.expect(seqs.count() > 32);
}

test "F6/F8: a run whose worst-case wall time is absurd is rejected up front" {
    // The audit's worst individually-legal case: 255 hops x 16 probes x a
    // u32-max timeout ~ 202,817 days, and the same 4080 probes at
    // max_payload also amplify ~4.2 MB onto one address with no rate limit.
    try testing.expectError(error.InvalidOptions, (Options{
        .max_hops = 255,
        .first_ttl = 1,
        .probes_per_hop = max_probes_per_hop,
        .timeout_ms = std.math.maxInt(u32),
    }).validate());
    // A legitimately large but sane scan (64 hops x 5 probes x 3s = 16 min)
    // is nowhere near the ceiling and still validates.
    try (Options{
        .max_hops = 64,
        .probes_per_hop = 5,
        .timeout_ms = 3000,
    }).validate();
    // The default Options{} (90s worst case) is nowhere near it either.
    try (Options{}).validate();
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
// A1 F3 (closed at its source, `icmp` module F2): `real_dest_unreachable_icmp`
// quotes 10.0.2.5, the routed-unreachable prefix it was actually captured
// against -- a DIFFERENT trace session than the one toward `real_server_addr`
// that produced `real_time_exceeded_icmp`. Decoded from the fixture bytes,
// quoted IP header at offset 28: `0a 00 02 05`. Before `icmp.echo.Reply`
// carried the quoted destination, splicing both genuine captures into one
// `traceWith` call toward `real_server_addr` and asserting both hops
// resolved was the audit's own proof of F3: it passed *only* because the
// quoted destination went unchecked. Named here instead of repeating the
// literal.
const real_unreachable_dest = ip4(10, 0, 2, 5);

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
            .sendUdpFn = sendUdpImpl,
            .recvFn = recvImpl,
            .nowFn = nowImpl,
        };
    }

    fn sendImpl(_: *anyopaque, _: u8, _: []const u8) TransportError!void {}

    fn sendUdpImpl(_: *anyopaque, _: u8, _: u16, _: []const u8) TransportError!void {}

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

test "REAL CAPTURE: genuine kernel Time Exceeded from a live router" {
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_time_exceeded_icmp[20..]));

    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_time_exceeded_icmp, .from = real_router_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, .{
        .max_hops = 1,
        .probes_per_hop = 1,
        .ident = 0x7472,
        .seq_base = 1,
        .timeout_ms = 500,
    });
    defer tr.deinit(testing.allocator);

    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(usize, 1), tr.hops.len);
    const hop1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.time_exceeded, hop1.kind);
    try testing.expect(hop1.address.?.eql(real_router_addr));
}

test "REAL CAPTURE: genuine kernel Destination Host Unreachable for a routed-unreachable target" {
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_dest_unreachable_icmp[20..]));

    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_dest_unreachable_icmp, .from = real_router_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_unreachable_dest, .{
        .max_hops = 1,
        .probes_per_hop = 1,
        .ident = 0x7472,
        .seq_base = 2,
        .timeout_ms = 500,
    });
    defer tr.deinit(testing.allocator);

    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(usize, 1), tr.hops.len);
    try testing.expectEqual(@as(?u8, 1), tr.unreachable_code); // real Host Unreachable

    const hop1 = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.dest_unreachable, hop1.kind);
    try testing.expectEqual(@as(?u8, 1), hop1.code);
    try testing.expect(hop1.address.?.eql(real_router_addr));
}

test "A1 F3: an ICMP error quoting a DIFFERENT destination than the one being traced is ignored, not attributed" {
    // Same real `real_dest_unreachable_icmp` capture as above, replayed
    // against `real_server_addr` instead of the destination it actually
    // quotes (`real_unreachable_dest`) -- this is exactly the audit's own
    // proof of F3: before the quoted destination was checked, this passed
    // and resolved the hop anyway.
    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_dest_unreachable_icmp, .from = real_router_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, .{
        .max_hops = 1,
        .probes_per_hop = 1,
        .ident = 0x7472,
        .seq_base = 2,
        .timeout_ms = 5,
    });
    defer tr.deinit(testing.allocator);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    try testing.expectEqual(@as(?u8, null), tr.unreachable_code);
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
    // A fresh `unshare -rn` namespace starts with `lo` down; this test used
    // to fail there (not skip) whenever it ran before anything brought it up.
    bringLoopbackUp();
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

// ── 2026-10-04: UDP method, MPLS extensions, live options ───────────────────

// Real kernel replies to UDP probes, captured with tcpdump in the same kind of
// throwaway veth sandbox as the captures above (client 10.0.0.1 → router
// 10.0.0.2/10.0.1.1 → server 10.0.1.2, `ip_forward=1` in the router netns,
// all inside `unshare -rnm`, 2026-10-04). The client sent UDP from port 40000
// to 10.0.1.2: TTL 1 to port 33434 (the router's Time Exceeded) and TTL 2 to
// port 33435 (the server's Port Unreachable — nothing listens there).
// `tcpdump -vv` decoded them as "ICMP time exceeded in-transit … 10.0.0.1.40000
// > 10.0.1.2.33434" and "ICMP 10.0.1.2 udp port 33435 unreachable".
const real_udp_time_exceeded = [_]u8{
    0x45, 0xc0, 0x00, 0x44, 0x0b, 0xb0, 0x00, 0x00, 0x40, 0x01, 0x5a, 0x47, 0x0a, 0x00, 0x00, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x0b, 0x00, 0xc0, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x28,
    0x76, 0xa9, 0x40, 0x00, 0x01, 0x11, 0xee, 0x19, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01, 0x02,
    0x9c, 0x40, 0x82, 0x9a, 0x00, 0x14, 0x15, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
const real_udp_port_unreachable = [_]u8{
    0x45, 0xc0, 0x00, 0x44, 0xad, 0xe8, 0x00, 0x00, 0x3f, 0x01, 0xb8, 0x0e, 0x0a, 0x00, 0x01, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x03, 0x03, 0xc8, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x28,
    0x76, 0xaa, 0x40, 0x00, 0x01, 0x11, 0xee, 0x18, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01, 0x02,
    0x9c, 0x40, 0x82, 0x9b, 0x00, 0x14, 0x15, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

const udp_trace_opts: Options = .{
    .method = .udp,
    .max_hops = 2,
    .probes_per_hop = 1,
    .ident = 40000, // the captured probes' source port
    .udp_port_base = 33434,
    .timeout_ms = 500,
};

test "REAL CAPTURE: a UDP trace — router Time Exceeded, then the server's Port Unreachable" {
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_udp_time_exceeded[20..]));
    try testing.expectEqual(@as(u16, 0), echo.checksum(real_udp_port_unreachable[20..]));
    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_udp_time_exceeded, .from = real_router_addr },
        .{ .bytes = &real_udp_port_unreachable, .from = real_server_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, udp_trace_opts);
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(?u8, null), tr.unreachable_code);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(Probe.Kind.time_exceeded, tr.hops[0].probes[0].kind);
    try testing.expect(tr.hops[0].probes[0].address.?.eql(real_router_addr));
    const last = tr.hops[1].probes[0];
    try testing.expectEqual(Probe.Kind.reply, last.kind);
    try testing.expectEqual(@as(?u8, 3), last.code); // RFC 792: port unreachable
    try testing.expect(last.address.?.eql(real_server_addr));
    // No RFC 4884 extension in a plain kernel reply.
    try testing.expectEqual(@as(usize, 0), tr.hops[0].probes[0].mpls.slice().len);
}

test "UDP replies are matched on the quoted source AND destination port and the quoted destination" {
    // Same real bytes, three ways to not match: another source port (another
    // traceroute's probes), a port base that puts 33434 outside this trace's
    // window, and a destination the probes did not go to.
    for ([_]struct { Options, netaddr.Ip }{
        .{ blk: {
            var o = udp_trace_opts;
            o.ident = 40001;
            break :blk o;
        }, real_server_addr },
        .{ blk: {
            var o = udp_trace_opts;
            o.udp_port_base = 33500;
            break :blk o;
        }, real_server_addr },
        .{ udp_trace_opts, real_unreachable_dest },
    }) |c| {
        var r: ReplayTransport = .{ .packets = &.{
            .{ .bytes = &real_udp_time_exceeded, .from = real_router_addr },
        } };
        var tr = try traceWith(testing.allocator, r.transport(), c[1], c[0]);
        defer tr.deinit(testing.allocator);
        try testing.expect(!tr.reached);
        for (tr.hops) |h| try testing.expectEqual(Probe.Kind.timeout, h.probes[0].kind);
    }
}

test "UDP: a Port Unreachable from someone other than the destination is terminal, not 'reached'" {
    // The server's real Port Unreachable, delivered as if it came from the
    // router: A1 F1's rule (the destination's answer must come from the
    // destination) applies to the UDP method's "reply" too.
    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_udp_time_exceeded, .from = real_router_addr },
        .{ .bytes = &real_udp_port_unreachable, .from = real_router_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, udp_trace_opts);
    defer tr.deinit(testing.allocator);
    try testing.expect(!tr.reached);
    try testing.expectEqual(@as(?u8, 3), tr.unreachable_code);
    try testing.expectEqual(Probe.Kind.dest_unreachable, tr.hops[1].probes[0].kind);
}

test "UDP: an ICMP-method trace ignores UDP errors and vice versa" {
    // An echo-method trace (ident 40000 as the echo id) must not take a
    // quoted UDP header for its own probe…
    var r: ReplayTransport = .{ .packets = &.{.{ .bytes = &real_udp_time_exceeded, .from = real_router_addr }} };
    var o = udp_trace_opts;
    o.method = .icmp;
    o.max_hops = 1;
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, o);
    defer tr.deinit(testing.allocator);
    try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    // …and a UDP trace must not take a quoted echo request (the ICMP-method
    // real capture, ident 0x7472 seq 1) for one of its probes.
    var r2: ReplayTransport = .{ .packets = &.{.{ .bytes = &real_time_exceeded_icmp, .from = real_router_addr }} };
    var o2 = udp_trace_opts;
    o2.ident = 0x7472;
    o2.max_hops = 1;
    var tr2 = try traceWith(testing.allocator, r2.transport(), real_server_addr, o2);
    defer tr2.deinit(testing.allocator);
    try testing.expectEqual(Probe.Kind.timeout, tr2.hops[0].probes[0].kind);
}

test "UDP options: port window must fit, and the transport must be able to send UDP" {
    var o = udp_trace_opts;
    o.udp_port_base = 0;
    try testing.expectError(error.InvalidOptions, o.validate());
    // 2 probes from 65535 would need port 65536.
    o.udp_port_base = 65535;
    try testing.expectError(error.InvalidOptions, o.validate());
    o.udp_port_base = 65534;
    try o.validate();
    // A transport without `sendUdpFn` (the ICMP-only fake) refuses the method.
    var f: FakeTransport = .{ .behaviors = &.{.reply} };
    defer f.deinit();
    try testing.expectError(error.InvalidOptions, runFake(&f, udp_trace_opts));
}

// An ICMP Time Exceeded quoting a UDP probe (10.0.0.1.40000 → 10.0.1.2.33434)
// padded to 128 bytes, with an RFC 4884 length field (32 words) and an RFC 4950
// MPLS object of two entries — built for this test and decoded by tcpdump
// 4.99.6: "ICMP Multi-Part extension v2, checksum 0xc2f0 (correct), length 16",
// "MPLS Stack Entry Object (1), Class-Type: 1, length 12", "label 16, tc 0,
// ttl 1". (tcpdump prints only the first entry; the second — label 17, TC 5,
// bottom of stack, TTL 255 — is read off RFC 3032 §2.1's layout.)
const mpls_time_exceeded = blk: {
    const h =
        "450000ac00070000400166480a0000020a0000010b00d5f0002000004500002800074000011164bc0a0000010a000102" ++
        "9c40829a0014000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000002000c2f0000c01010001000100011bff";
    @setEvalBranchQuota(10000);
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    break :blk out;
};

test "MPLS label stack (RFC 4950) is read from an RFC 4884 extension and attached to the hop" {
    var r: ReplayTransport = .{ .packets = &.{.{ .bytes = &mpls_time_exceeded, .from = real_router_addr }} };
    var o = udp_trace_opts;
    o.max_hops = 1;
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, o);
    defer tr.deinit(testing.allocator);
    const p = tr.hops[0].probes[0];
    try testing.expectEqual(Probe.Kind.time_exceeded, p.kind);
    const labels = p.mpls.slice();
    try testing.expectEqual(@as(usize, 2), labels.len);
    try testing.expectEqualDeep(MplsEntry{ .label = 16, .tc = 0, .bottom = false, .ttl = 1 }, labels[0]);
    try testing.expectEqualDeep(MplsEntry{ .label = 17, .tc = 5, .bottom = true, .ttl = 255 }, labels[1]);
}

test "extensionObjects: length field, compatibility mode, version and checksum gates" {
    const msg = mpls_time_exceeded[20..]; // past the outer IPv4 header
    try testing.expect(extensionObjects(.v4, msg) != null);
    // RFC 4884 §5 compatibility: length field 0, extension at 128 bytes —
    // accepted because a version-2 header with a valid checksum sits there.
    var compat = mpls_time_exceeded;
    compat[20 + 5] = 0;
    try testing.expectEqual(@as(usize, 2), mplsOf(.v4, compat[20..]).len);
    // …but not when the checksum is zero (nothing proves it is an extension).
    var compat0 = compat;
    compat0[20 + 8 + 128 + 2] = 0;
    compat0[20 + 8 + 128 + 3] = 0;
    try testing.expect(extensionObjects(.v4, compat0[20..]) == null);
    // A length field below 128 bytes (31 words) is not RFC 4884.
    var short = mpls_time_exceeded;
    short[20 + 5] = 31;
    try testing.expect(extensionObjects(.v4, short[20..]) == null);
    // Version 1, or a damaged checksum, is not an extension.
    var v1 = mpls_time_exceeded;
    v1[20 + 8 + 128] = 0x10;
    try testing.expect(extensionObjects(.v4, v1[20..]) == null);
    var bad = mpls_time_exceeded;
    bad[bad.len - 1] ^= 1;
    try testing.expect(extensionObjects(.v4, bad[20..]) == null);
    // A zero checksum with an explicit length field means "not computed".
    var nock = mpls_time_exceeded;
    nock[20 + 8 + 128 + 2] = 0;
    nock[20 + 8 + 128 + 3] = 0;
    try testing.expect(extensionObjects(.v4, nock[20..]) != null);
    // Not an error message at all.
    try testing.expect(extensionObjects(.v4, real_echo_reply_icmp[20..]) == null);
    // An object whose length runs past the data stops the walk, empty-handed.
    var long_obj = mpls_time_exceeded;
    long_obj[20 + 8 + 128 + 4 + 1] = 0x40; // object length 64 > remaining
    long_obj[20 + 8 + 128 + 2] = 0;
    long_obj[20 + 8 + 128 + 3] = 0;
    try testing.expectEqual(@as(usize, 0), mplsOf(.v4, long_obj[20..]).len);
}

test "MPLS: a stack deeper than max_mpls_labels is truncated, never overflows" {
    var buf: [8 + 128 + 4 + 4 + 4 * 12]u8 = @splat(0);
    buf[0] = echo.v4.time_exceeded;
    buf[5] = 32; // 128 bytes of original datagram
    const ext = buf[8 + 128 ..];
    ext[0] = 0x20;
    std.mem.writeInt(u16, ext[4..6], 4 + 4 * 12, .big);
    ext[6] = 1;
    ext[7] = 1;
    for (0..12) |i| std.mem.writeInt(u32, ext[8 + 4 * i ..][0..4], @as(u32, @intCast(100 + i)) << 12, .big);
    const st = mplsOf(.v4, &buf);
    try testing.expectEqual(@as(usize, max_mpls_labels), st.slice().len);
    try testing.expectEqual(@as(u20, 100 + max_mpls_labels - 1), st.slice()[max_mpls_labels - 1].label);
}

test "IPv6 UDP: Port Unreachable is code 4 and quotes a 40-byte header" {
    const dest6 = netaddr.parseIp("2001:db8::2").?;
    const router6 = netaddr.parseIp("2001:db8::1").?;
    // RFC 4443 §3.3 / §3.1: type 3 (Time Exceeded) / type 1 code 4 (port
    // unreachable), 4 unused bytes, then the invoking packet: a 40-byte IPv6
    // header (next header 17 at offset 6, destination at 24) + the UDP header.
    var te: [8 + 40 + 8]u8 = @splat(0);
    te[0] = echo.v6.time_exceeded;
    te[8 + 6] = 17;
    @memcpy(te[8 + 24 ..][0..16], &dest6.v6);
    std.mem.writeInt(u16, te[48..50], 40000, .big);
    std.mem.writeInt(u16, te[50..52], 33434, .big);
    var pu = te;
    pu[0] = echo.v6.dest_unreachable;
    pu[1] = 4;
    std.mem.writeInt(u16, pu[50..52], 33435, .big);
    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &te, .from = router6 },
        .{ .bytes = &pu, .from = dest6 },
    } };
    var t = r.transport();
    t.strip_ip_header = false; // ICMPv6 sockets never deliver the IPv6 header
    var tr = try traceWith(testing.allocator, t, dest6, udp_trace_opts);
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(?u8, 4), tr.hops[1].probes[0].code);
    // IPv4's port-unreachable code (3) from the destination is NOT the IPv6
    // "reached" signal (that is 3 = address unreachable there).
    var pu3 = pu;
    pu3[1] = 3;
    var r3: ReplayTransport = .{ .packets = &.{ .{ .bytes = &te, .from = router6 }, .{ .bytes = &pu3, .from = dest6 } } };
    var t3 = r3.transport();
    t3.strip_ip_header = false;
    var tr3 = try traceWith(testing.allocator, t3, dest6, udp_trace_opts);
    defer tr3.deinit(testing.allocator);
    try testing.expect(!tr3.reached);
    try testing.expectEqual(@as(?u8, 3), tr3.unreachable_code);
}

/// An ICMPv4 Time Exceeded with `orig_len` bytes of quoted datagram (a UDP
/// probe 10.0.0.1.40000 → 10.0.1.2.33434 at its start), the RFC 4884 length
/// field set to `words`, and `ext` appended — every checksum computed, so a
/// test can switch exactly one rule off.
fn buildExtTe(buf: []u8, words: u8, orig_len: usize, ext: []const u8) []u8 {
    const msg = buf[0 .. 8 + orig_len + ext.len];
    @memset(msg, 0);
    msg[0] = echo.v4.time_exceeded;
    msg[5] = words;
    const q = msg[8..];
    q[0] = 0x45;
    q[9] = 17;
    @memcpy(q[16..20], &[_]u8{ 10, 0, 1, 2 });
    std.mem.writeInt(u16, q[20..22], 40000, .big);
    std.mem.writeInt(u16, q[22..24], 33434, .big);
    @memcpy(msg[8 + orig_len ..], ext);
    std.mem.writeInt(u16, msg[2..4], echo.checksum(msg), .big);
    return msg;
}

/// An extension structure (version `ver`) holding one object of `class`/
/// `ctype` with `entries`, its checksum computed.
fn buildExt(buf: []u8, ver: u4, class: u8, ctype: u8, entries: []const u32) []u8 {
    const len = 4 + 4 + 4 * entries.len;
    const e = buf[0..len];
    @memset(e, 0);
    e[0] = @as(u8, ver) << 4;
    std.mem.writeInt(u16, e[4..6], @intCast(4 + 4 * entries.len), .big);
    e[6] = class;
    e[7] = ctype;
    for (entries, 0..) |v, i| std.mem.writeInt(u32, e[8 + 4 * i ..][0..4], v, .big);
    std.mem.writeInt(u16, e[2..4], echo.checksum(e), .big);
    return e;
}

test "extensions: each RFC 4884/4950 rule rejects on its own (every checksum valid)" {
    var eb: [64]u8 = undefined;
    var mb: [300]u8 = undefined;
    const lse = (@as(u32, 300) << 12) | (1 << 9) | 64; // label 300, TC 1, S = 0, TTL 64
    // Baseline: a well-formed one decodes — TC 1 sets bit 9 and S (bit 8)
    // stays clear, so the two fields cannot be confused.
    const good = buildExtTe(&mb, 32, 128, buildExt(&eb, 2, 1, 1, &.{lse}));
    const st = mplsOf(.v4, good);
    try testing.expectEqual(@as(usize, 1), st.slice().len);
    try testing.expectEqualDeep(MplsEntry{ .label = 300, .tc = 1, .bottom = false, .ttl = 64 }, st.slice()[0]);
    // A length field of 31 words (124 bytes) with a valid extension right
    // after: RFC 4884 §4.1 requires the original datagram field to be at
    // least 128 bytes when an extension follows — not an extension.
    try testing.expect(extensionObjects(.v4, buildExtTe(&mb, 31, 124, buildExt(&eb, 2, 1, 1, &.{lse}))) == null);
    // Version 1 with a correct checksum: only version 2 is defined.
    try testing.expect(extensionObjects(.v4, buildExtTe(&mb, 32, 128, buildExt(&eb, 1, 1, 1, &.{lse}))) == null);
    // Class 1 but C-Type 2: not the MPLS label stack object.
    try testing.expectEqual(@as(usize, 0), mplsOf(.v4, buildExtTe(&mb, 32, 128, buildExt(&eb, 2, 1, 2, &.{lse}))).slice().len);
    // Compatibility mode (length 0) whose extension checksums to exactly
    // 0x0000 — a real one's-complement sum can, so pick the TTL that makes
    // it so: still refused, since a zero field means "not computed" and a
    // guessed extension needs a checksum to be believed.
    // Words: 0x2000 (version) + 0x0008 + 0x0101 (object header) + 0x0012 +
    // 0xdee4 (the entry) = 0xffff, so the computed checksum is 0x0000.
    const zero_ck = buildExt(&eb, 2, 1, 1, &.{0x0012dee4});
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, zero_ck[2..4], .big));
    try testing.expectEqual(@as(u16, 0), echo.checksum(zero_ck));
    try testing.expect(extensionObjects(.v4, buildExtTe(&mb, 0, 128, zero_ck)) == null);
    // The same bytes with an explicit length field are accepted ("not
    // computed" is allowed there).
    try testing.expect(extensionObjects(.v4, buildExtTe(&mb, 32, 128, zero_ck)) != null);
}

test "UDP: a quoted datagram that is not UDP, or a damaged ICMPv4 checksum, is ignored" {
    // The real Time Exceeded, re-labelled as quoting TCP (protocol 6) with the
    // same ports in place — then its ICMP checksum fixed up so only the
    // protocol rule can reject it.
    var tcp = real_udp_time_exceeded;
    tcp[20 + 8 + 9] = 6;
    tcp[22] = 0;
    tcp[23] = 0;
    std.mem.writeInt(u16, tcp[22..24], echo.checksum(tcp[20..]), .big);
    var broken = real_udp_time_exceeded;
    broken[broken.len - 1] ^= 0x01; // payload bit flip, checksum now wrong
    for ([_][]const u8{ &tcp, &broken }) |bytes| {
        var r: ReplayTransport = .{ .packets = &.{.{ .bytes = bytes, .from = real_router_addr }} };
        var o = udp_trace_opts;
        o.max_hops = 1;
        var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, o);
        defer tr.deinit(testing.allocator);
        try testing.expectEqual(Probe.Kind.timeout, tr.hops[0].probes[0].kind);
    }
    // IPv6: a quoted next header of 6 (TCP) is not a UDP probe either.
    const dest6 = netaddr.parseIp("2001:db8::2").?;
    var te: [8 + 40 + 8]u8 = @splat(0);
    te[0] = echo.v6.time_exceeded;
    te[8 + 6] = 6;
    @memcpy(te[8 + 24 ..][0..16], &dest6.v6);
    std.mem.writeInt(u16, te[48..50], 40000, .big);
    std.mem.writeInt(u16, te[50..52], 33434, .big);
    var r6: ReplayTransport = .{ .packets = &.{.{ .bytes = &te, .from = netaddr.parseIp("2001:db8::1").? }} };
    var t6 = r6.transport();
    t6.strip_ip_header = false;
    var o6 = udp_trace_opts;
    o6.max_hops = 1;
    var tr6 = try traceWith(testing.allocator, t6, dest6, o6);
    defer tr6.deinit(testing.allocator);
    try testing.expectEqual(Probe.Kind.timeout, tr6.hops[0].probes[0].kind);
}

test "UDP: a late duplicate for an answered probe does not overwrite it (A1 F12)" {
    // Probe 1 answered by the router; while probe 2 waits, a second Time
    // Exceeded for probe 1 arrives from somewhere else; then probe 2's own
    // Port Unreachable. The first answer for a slot wins.
    var dup = real_udp_time_exceeded;
    _ = &dup;
    var r: ReplayTransport = .{ .packets = &.{
        .{ .bytes = &real_udp_time_exceeded, .from = real_router_addr },
        .{ .bytes = &dup, .from = test_dest },
        .{ .bytes = &real_udp_port_unreachable, .from = real_server_addr },
    } };
    var tr = try traceWith(testing.allocator, r.transport(), real_server_addr, udp_trace_opts);
    defer tr.deinit(testing.allocator);
    try testing.expect(tr.hops[0].probes[0].address.?.eql(real_router_addr));
    try testing.expect(tr.reached);
}

test "live: iface/source/tos land on the sockets themselves (skipped without CAP_NET_RAW)" {
    bringLoopbackUp();
    const dest = netaddr.parseIp("127.0.0.1").?;
    for ([_]Method{ .icmp, .udp }) |method| {
        var lt = LinuxTransport.openWith(dest, .{ .method = method, .iface = "lo", .source = dest, .tos = 0x10 }) catch |err| switch (err) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        };
        defer lt.close();
        // The socket that SENDS carries TOS and the interface binding.
        const send_fd = lt.udp_fd orelse lt.sock.fd;
        var tos: u32 = 0;
        var tl: linux.socklen_t = @sizeOf(u32);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockopt(send_fd, linux.SOL.IP, linux.IP.TOS, @ptrCast(&tos), &tl)));
        try testing.expectEqual(@as(u32, 0x10), tos);
        var dev: [16]u8 = @splat(0);
        var dl: linux.socklen_t = dev.len;
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockopt(send_fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, &dev, &dl)));
        try testing.expectEqualStrings("lo", std.mem.sliceTo(&dev, 0));
        // The receiving raw socket is bound to the interface as well.
        dl = dev.len;
        @memset(&dev, 0);
        try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.getsockopt(lt.sock.fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, &dev, &dl)));
        try testing.expectEqualStrings("lo", std.mem.sliceTo(&dev, 0));
        // UDP: the token is the bound source port, not the ICMP ident.
        if (method == .udp) try testing.expectEqual(lt.udp_port, lt.ident());
    }
}

fn bringLoopbackUp() void {
    const fd_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var ifr: extern struct { name: [16]u8, flags: i16, pad: [22]u8 } = .{ .name = @splat(0), .flags = 0, .pad = @splat(0) };
    @memcpy(ifr.name[0..2], "lo");
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS) return;
    ifr.flags |= 1; // IFF_UP
    _ = linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&ifr));
}

test "live: UDP trace to 127.0.0.1 ends on the loopback's own Port Unreachable (skipped without CAP_NET_RAW)" {
    bringLoopbackUp();
    const dest = netaddr.parseIp("127.0.0.1").?;
    var tr = trace(testing.allocator, dest, .{ .method = .udp, .max_hops = 3, .probes_per_hop = 2, .timeout_ms = 2000 }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer tr.deinit(testing.allocator);
    if (tr.transport_err != null and tr.hops.len == 0) return error.SkipZigTest; // no usable loopback
    try testing.expect(tr.reached);
    try testing.expectEqual(@as(usize, 1), tr.hops.len);
    for (tr.hops[0].probes) |p| {
        try testing.expectEqual(Probe.Kind.reply, p.kind);
        try testing.expectEqual(@as(?u8, 3), p.code);
        try testing.expect(p.address.?.eql(dest));
    }
}

test "live: source/interface/tos options reach the sockets (skipped without CAP_NET_RAW)" {
    bringLoopbackUp();
    const dest = netaddr.parseIp("127.0.0.1").?;
    // Bound to `lo`, from 127.0.0.1, TOS 0x10: still reaches the destination.
    var tr = trace(testing.allocator, dest, .{
        .max_hops = 2,
        .probes_per_hop = 1,
        .timeout_ms = 2000,
        .iface = "lo",
        .source = dest,
        .tos = 0x10,
    }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer tr.deinit(testing.allocator);
    if (tr.transport_err != null and tr.hops.len == 0) return error.SkipZigTest;
    try testing.expect(tr.reached);
    // A source address this host does not own cannot be bound: the open fails.
    try testing.expectError(error.SourceAddressBind, trace(testing.allocator, dest, .{ .source = netaddr.parseIp("192.0.2.77").? }));
    // An interface that does not exist cannot be bound either.
    if (trace(testing.allocator, dest, .{ .method = .udp, .iface = "nonexistent0" })) |t_ok| {
        var t2 = t_ok;
        t2.deinit(testing.allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

// ── A1 F9: fuzz — arbitrary ICMP bytes through the full hop state machine ──
//
// The audit found zero fuzz harnesses (`grep -c testing.fuzz` -> 0) and
// wrote one externally (CONVENTIONS.md §9: an instrument parked outside its
// module's gates is never built again by anything). Ported in here instead
// of rebuilt: same `FuzzTransport` (hands the fuzzer's bytes back as if a
// router had sent them, then goes silent; a length-prefix byte carves the
// input into several packets so a run can model a flood, not just one
// packet), same corpus, same anti-vacuity check.

const FuzzTransport = struct {
    input: []const u8,
    off: usize = 0,
    clock: u64 = 1_000_000,
    strip: bool,

    fn transport(s: *FuzzTransport) Transport {
        return .{ .ctx = s, .strip_ip_header = s.strip, .sendFn = fuzzSend, .recvFn = fuzzRecv, .nowFn = fuzzNow };
    }
    fn fuzzNow(ctx: *anyopaque) u64 {
        return @as(*FuzzTransport, @ptrCast(@alignCast(ctx))).clock;
    }
    fn fuzzSend(_: *anyopaque, _: u8, _: []const u8) TransportError!void {}
    fn fuzzRecv(ctx: *anyopaque, buf: []u8, timeout_ns: u64) TransportError!?Packet {
        const s: *FuzzTransport = @ptrCast(@alignCast(ctx));
        if (s.off >= s.input.len) {
            s.clock += timeout_ns;
            return null;
        }
        const want: usize = s.input[s.off];
        s.off += 1;
        const n = @min(@min(want, s.input.len -| s.off), buf.len);
        @memcpy(buf[0..n], s.input[s.off..][0..n]);
        s.off += n;
        s.clock += std.time.ns_per_ms;
        return .{ .len = n, .from = ip4(198, 51, 100, 66) };
    }
};

fn fuzzOneRun(input: []const u8) anyerror!void {
    const gpa = testing.allocator;
    for ([_]bool{ true, false }) |strip| {
        for ([_]netaddr.Ip{ test_dest, netaddr.parseIp("2001:db8::99").? }) |d| {
            var f: FuzzTransport = .{ .input = input, .strip = strip };
            var tr = traceWith(gpa, f.transport(), d, .{
                .max_hops = 6,
                .probes_per_hop = 2,
                .timeout_ms = 5,
            }) catch |e| switch (e) {
                error.OutOfMemory => return,
                error.InvalidOptions => unreachable,
            };
            defer tr.deinit(gpa);
            // Touch every derived value: stats() and distinctAddresses() both
            // index fixed stack scratch off attacker-influenced probe counts.
            var buf: [max_probes_per_hop]netaddr.Ip = undefined;
            for (tr.hops) |h| {
                const st = h.stats();
                std.mem.doNotOptimizeAway(st.mean_ns);
                std.mem.doNotOptimizeAway(st.jitter_ns);
                std.mem.doNotOptimizeAway(h.distinctAddresses(&buf).len);
                std.mem.doNotOptimizeAway(h.address());
            }
        }
    }
}

/// Corpus encoding: `[len:1][len bytes of packet] ...` repeated. Smith.bytes
/// only -- the one primitive that copies its input through verbatim both
/// under `zig build fuzz` and off it; a weighted/range draw collapses to its
/// lower bound outside `--fuzz` (the repository-wide `Smith` trap recorded
/// in `feedback_my_own_lint_measured_a_smaller_world` / accesslog's notes),
/// which would leave this harness half-dead.
fn fuzzTraceroute(_: void, smith: *testing.Smith) anyerror!void {
    var pool: [1024]u8 = undefined;
    var n: usize = 0;
    inline for (0..4) |_| {
        var lb: [1]u8 = undefined;
        smith.bytes(&lb);
        const want = @min(@as(usize, lb[0]), pool.len - n - 1);
        pool[n] = @intCast(want);
        n += 1;
        smith.bytes(pool[n..][0..want]);
        n += want;
    }
    try fuzzOneRun(pool[0..n]);
}

fn fuzzSeedTimeExceeded() [1 + 56]u8 {
    var b: [1 + 56]u8 = @splat(0);
    b[0] = 56; // length prefix
    const p = b[1..];
    p[0] = 0x45; // outer IPv4, ihl 5
    p[20] = 11; // ICMP time exceeded
    p[28] = 0x45; // quoted IPv4 header, ihl 5
    // A1 F3 (closed at its source, `icmp` module F2): the quoted
    // destination must be `test_dest` (192.0.2.99, the only v4 dest
    // `fuzzOneRun` traces to) -- every probe traced here was addressed
    // there, so a genuine router's error always quotes it back.
    p[44] = 192;
    p[45] = 0;
    p[46] = 2;
    p[47] = 99;
    p[48] = 8; // quoted echo request
    p[52] = 0x74;
    p[53] = 0x72; // ident 0x7472
    p[55] = 1; // seq 1
    // A1 (icmp F7): icmp.echo.parseV4 now verifies the receive-side ICMP
    // checksum, so this seed needs a real one -- an all-zero checksum field
    // made it `.ignored` before it ever reached the quoted-header logic
    // this seed exists to exercise.
    std.mem.writeInt(u16, p[22..24], echo.checksum(p[20..56]), .big);
    return b;
}
fn fuzzSeedEchoReply() [1 + 28]u8 {
    var b: [1 + 28]u8 = @splat(0);
    b[0] = 28;
    const p = b[1..];
    p[0] = 0x45;
    p[20] = 0; // echo reply
    p[24] = 0x74;
    p[25] = 0x72;
    p[27] = 1;
    std.mem.writeInt(u16, p[22..24], echo.checksum(p[20..28]), .big); // A1 (icmp F7)
    return b;
}
const fuzz_seed_te = fuzzSeedTimeExceeded();
const fuzz_seed_er = fuzzSeedEchoReply();

const fuzz_corpus = [_][]const u8{
    "",
    &.{0},
    &.{ 3, 0xff, 0x00, 0x01 },
    &fuzz_seed_te,
    &fuzz_seed_er,
    // an IHL that lies (0x4f = 60 bytes claimed) plus filler
    &(.{ 200, 0x4f } ++ .{0xaa} ** 199),
};

test "fuzz: arbitrary ICMP bytes through the full hop state machine never panic" {
    try testing.fuzz({}, fuzzTraceroute, .{ .corpus = &fuzz_corpus });
}

test "fuzz corpus really reaches the classifier (a green fuzz run is not vacuous)" {
    // Drive the same seeds directly, bypassing Smith, and prove at least one
    // of them resolves a hop -- otherwise the fuzz test above would be
    // exercising nothing but the timeout path.
    const gpa = testing.allocator;
    var resolved: usize = 0;
    for (fuzz_corpus) |c| {
        var f: FuzzTransport = .{ .input = c, .strip = true };
        var tr = try traceWith(gpa, f.transport(), test_dest, .{
            .max_hops = 6,
            .probes_per_hop = 2,
            .timeout_ms = 5,
        });
        defer tr.deinit(gpa);
        for (tr.hops) |h| for (h.probes) |p| {
            if (p.kind != .timeout) resolved += 1;
        };
    }
    try testing.expect(resolved > 0);
}
