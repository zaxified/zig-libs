// SPDX-License-Identifier: MIT

//! What this module's own doc comment says about its live path is checked
//! here, not just quoted: `LinuxTransport.open` hard-codes `icmp.Socket
//! .open(family, .raw, .{})` -- RAW mode specifically, never `.auto` or
//! `.dgram` -- because "DGRAM (\"ping\") sockets deliver ICMP errors on the
//! error queue, not as packets" (root.zig). That means there is NO
//! unprivileged live path in this module at all: unlike `syslog` or
//! `traceroute`'s sibling network modules, an unprivileged datagram mode
//! exists at the OS level (measured below) but this module deliberately does
//! not use it, because it cannot see the Time Exceeded/Destination
//! Unreachable replies that are the entire point of a traceroute.
//!
//! ⚠ WHAT COULD NOT BE EXERCISED UNPRIVILEGED, AND WHY: `traceroute.trace` /
//! `LinuxTransport.open` (the real raw-ICMP-socket live path) need
//! CAP_NET_RAW. This example still calls them for real, over loopback, and
//! asserts the exact outcome instead of skipping silently:
//!   - unprivileged (the common case, including this repo's own CI): a
//!     `SOCK_RAW` open fails at the kernel with EACCES/EPERM, which
//!     `icmp.Socket.open` maps to the named `error.PermissionDenied` --
//!     asserted below, not assumed. (Measured separately, outside Zig, while
//!     writing this: on this host `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
//!     is refused while `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`
//!     succeeds -- `net.ipv4.ping_group_range` covers this process's group
//!     -- which is exactly the OS-level capability this module's design
//!     doc says it deliberately does not fall back to.)
//!   - privileged (CAP_NET_RAW present, e.g. root): the open succeeds and
//!     this example runs a real trace to `127.0.0.1` instead, so the check
//!     is never vacuous either way.
//!
//! What IS fully exercised unprivileged, for real, is `traceWith` -- the
//! entire hop state machine (probe construction, per-hop TTL sequencing,
//! ident/seq correlation, reply classification) -- driven through the
//! injectable `Transport` seam this module ships specifically so the engine
//! never needs a socket at all. The canned response bytes below are built
//! from the sibling `icmp` module's own PUBLIC wire encoder/constants
//! (`icmp.echo.checksum`/`v4.*`/`echo_header_len`), the same public surface
//! `LinuxTransport` itself is built on -- not private test helpers reached
//! into, and not hand-waved "should look like this" bytes.
//!
//! Built against the PUBLISHED module (`@import("traceroute")` plus its
//! three declared deps `icmp`/`netaddr`/`latency-stats`) -- no `test_deps`,
//! no reaching into `src/`. `zig build check-examples` builds this against
//! exactly that surface.

const std = @import("std");
const traceroute = @import("traceroute");
const icmp = @import("icmp");
const netaddr = @import("netaddr");

// ── documented fixture: Options.validate's own named error ────────────────

fn checkOptionsValidation() !void {
    if ((traceroute.Options{ .probes_per_hop = 0 }).validate()) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidOptions => std.debug.print("Options{{ .probes_per_hop = 0 }}.validate(): InvalidOptions (expected)\n", .{}),
    }
}

// ── a real allocating failure path in traceWith itself ─────────────────────

/// `traceWith` allocates its scratch arrays with the caller's allocator
/// before sending a single probe (root.zig: `probes = try gpa.alloc(...)`).
/// A `FixedBufferAllocator` backed by a real (too-small) `gpa` allocation
/// forces that first allocation to fail -- proving the whole init path
/// returns `error.OutOfMemory` cleanly, and that this example's own backing
/// buffer is freed by `defer` regardless.
fn checkAllocFailureReturnsEarly(gpa: std.mem.Allocator) !void {
    const backing = try gpa.alloc(u8, 4); // far too small for any real scratch array
    defer gpa.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);

    var dummy: DummyTransport = .{};
    const dest = netaddr.parseIp("192.0.2.99").?;
    if (traceroute.traceWith(fba.allocator(), dummy.transport(), dest, .{})) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.OutOfMemory => std.debug.print(
            "traceWith with a 4-byte allocator: OutOfMemory (expected), before any probe would have been sent\n",
            .{},
        ),
        else => return err,
    }
}

/// Never actually called -- `traceWith`'s allocation failure above happens
/// before the send loop starts. Exists only so `Transport`'s function
/// pointers have somewhere to point.
const DummyTransport = struct {
    fn transport(d: *DummyTransport) traceroute.Transport {
        return .{ .ctx = d, .sendFn = send, .recvFn = recv, .nowFn = now };
    }
    fn send(_: *anyopaque, _: u8, _: []const u8) traceroute.TransportError!void {
        unreachable;
    }
    fn recv(_: *anyopaque, _: []u8, _: u64) traceroute.TransportError!?traceroute.Packet {
        unreachable;
    }
    fn now(_: *anyopaque) u64 {
        unreachable;
    }
};

// ── the unprivileged engine, driven by a fixture Transport ────────────────

/// Builds canned ICMP response bytes from the `icmp.echo` module's own
/// PUBLIC encoder/constants -- the same public surface `LinuxTransport`
/// itself is built from, not a private test helper.
const FixtureTransport = struct {
    gpa: std.mem.Allocator,
    dest: netaddr.Ip,
    router_ttl1: netaddr.Ip,
    /// If set, the probe at this TTL gets malformed bytes back instead of a
    /// well-formed ICMP message -- proves reply classification never panics
    /// on hostile/truncated input, using the real `traceWith` parse path.
    garbage_at_ttl: ?u8 = null,
    clock: u64 = 1_000_000,
    sent: std.ArrayList(struct { ttl: u8, seq: u16 }) = .empty,
    pending: ?[]u8 = null,
    pending_from: ?netaddr.Ip = null,

    fn deinit(f: *FixtureTransport) void {
        f.sent.deinit(f.gpa);
        if (f.pending) |p| f.gpa.free(p);
    }

    fn transport(f: *FixtureTransport) traceroute.Transport {
        return .{ .ctx = f, .sendFn = sendImpl, .recvFn = recvImpl, .nowFn = nowImpl };
    }

    fn nowImpl(ctx: *anyopaque) u64 {
        const f: *FixtureTransport = @ptrCast(@alignCast(ctx));
        return f.clock;
    }

    fn sendImpl(ctx: *anyopaque, ttl: u8, packet: []const u8) traceroute.TransportError!void {
        const f: *FixtureTransport = @ptrCast(@alignCast(ctx));
        const seq = std.mem.readInt(u16, packet[6..8][0..2], .big);
        f.sent.append(f.gpa, .{ .ttl = ttl, .seq = seq }) catch return error.SendFailed;

        if (f.garbage_at_ttl) |g| if (g == ttl) {
            f.pending = f.gpa.dupe(u8, &[_]u8{ 0xff, 0x00, 0x01 }) catch return error.SendFailed;
            f.pending_from = f.router_ttl1;
            return;
        };

        if (ttl == 1) {
            f.pending = buildTimeExceeded(f.gpa, packet) catch return error.SendFailed;
            f.pending_from = f.router_ttl1;
        } else {
            f.pending = buildEchoReply(f.gpa, packet) catch return error.SendFailed;
            f.pending_from = f.dest;
        }
    }

    fn recvImpl(ctx: *anyopaque, buf: []u8, timeout_ns: u64) traceroute.TransportError!?traceroute.Packet {
        const f: *FixtureTransport = @ptrCast(@alignCast(ctx));
        if (f.pending) |p| {
            defer {
                f.gpa.free(p);
                f.pending = null;
            }
            @memcpy(buf[0..p.len], p);
            f.clock += 1 * std.time.ns_per_ms; // a plausible small RTT
            return .{ .len = p.len, .from = f.pending_from };
        }
        f.clock += timeout_ns; // no (more) responses: the probe's window expires
        return null;
    }

    /// Echo Reply: the request with the type byte flipped and the checksum
    /// refreshed -- exactly what a real destination host echoes back.
    fn buildEchoReply(gpa: std.mem.Allocator, request: []const u8) ![]u8 {
        const out = try gpa.dupe(u8, request);
        out[0] = icmp.echo.v4.echo_reply;
        out[2] = 0;
        out[3] = 0;
        std.mem.writeInt(u16, out[2..4][0..2], icmp.echo.checksum(out), .big);
        return out;
    }

    /// ICMP Time Exceeded quoting the original request: type/code + 4
    /// unused bytes, a minimal quoted IPv4 header (ihl=5), then the quoted
    /// 8-byte echo header -- exactly the shape `icmp.echo.parseV4` expects
    /// for an ICMP error (echo.zig: quoted IP header + >= 8 bytes payload).
    fn buildTimeExceeded(gpa: std.mem.Allocator, orig_request: []const u8) ![]u8 {
        const quoted_ip_hdr_len = 20;
        const out = try gpa.alloc(u8, icmp.echo.echo_header_len + quoted_ip_hdr_len + icmp.echo.echo_header_len);
        @memset(out, 0);
        out[0] = icmp.echo.v4.time_exceeded;
        out[1] = 0; // code
        out[icmp.echo.echo_header_len] = 0x45; // quoted IPv4 header: version 4, ihl 5
        @memcpy(
            out[icmp.echo.echo_header_len + quoted_ip_hdr_len ..],
            orig_request[0..icmp.echo.echo_header_len],
        );
        std.mem.writeInt(u16, out[2..4][0..2], icmp.echo.checksum(out), .big);
        return out;
    }
};

fn checkEngineWithFixtureBytes(gpa: std.mem.Allocator) !void {
    const dest = netaddr.parseIp("192.0.2.99").?;
    const router1 = netaddr.parseIp("10.0.0.1").?;

    var f: FixtureTransport = .{ .gpa = gpa, .dest = dest, .router_ttl1 = router1 };
    defer f.deinit();

    var tr = try traceroute.traceWith(gpa, f.transport(), dest, .{
        .max_hops = 2,
        .probes_per_hop = 2,
        .timeout_ms = 200,
    });
    defer tr.deinit(gpa);

    // Probe construction + TTL sequencing: 2 hops * 2 probes, TTL 1,1,2,2.
    if (f.sent.items.len != 4) return error.WrongProbeCount;
    for (f.sent.items, 0..) |s, i| {
        const want_ttl: u8 = if (i < 2) 1 else 2;
        if (s.ttl != want_ttl) return error.WrongTtlSequencing;
    }

    // Reply classification: hop 1 = time_exceeded from router1, hop 2 =
    // reply from dest; both real conclusions of `traceWith`'s own parsing
    // of the fixture bytes above, not restated by hand.
    if (!tr.reached) return error.ExpectedReached;
    if (tr.hops.len != 2) return error.WrongHopCount;
    for (tr.hops[0].probes) |p| {
        if (p.kind != .time_exceeded) return error.WrongKindHop1;
        if (!(p.address orelse return error.MissingAddress).eql(router1)) return error.WrongAddressHop1;
        if (p.rtt_ns == null or p.rtt_ns.? == 0) return error.MissingRtt;
    }
    for (tr.hops[1].probes) |p| {
        if (p.kind != .reply) return error.WrongKindHop2;
        if (!(p.address orelse return error.MissingAddress).eql(dest)) return error.WrongAddressHop2;
    }
    var router1_buf: [netaddr.max_ip_text_len]u8 = undefined;
    var dest_buf: [netaddr.max_ip_text_len]u8 = undefined;
    std.debug.print(
        "traceWith over fixture bytes: 2 hops, TTL 1,1,2,2, hop1=time_exceeded@{s}, hop2=reply@{s}, reached\n",
        .{ netaddr.formatIp(router1, &router1_buf), netaddr.formatIp(dest, &dest_buf) },
    );
}

fn checkMalformedBytesNeverPanic(gpa: std.mem.Allocator) !void {
    const dest = netaddr.parseIp("192.0.2.99").?;
    const router1 = netaddr.parseIp("10.0.0.1").?;

    var f: FixtureTransport = .{ .gpa = gpa, .dest = dest, .router_ttl1 = router1, .garbage_at_ttl = 1 };
    defer f.deinit();

    var tr = try traceroute.traceWith(gpa, f.transport(), dest, .{
        .max_hops = 2,
        .probes_per_hop = 1,
        .timeout_ms = 50,
    });
    defer tr.deinit(gpa);

    // 3 hostile bytes at hop 1 must parse to `.ignored` inside traceWith
    // (never panic) and fall through to a clean timeout; hop 2 still
    // reaches the destination normally.
    if (tr.hops[0].probes[0].kind != .timeout) return error.GarbageShouldTimeout;
    if (tr.hops[1].probes[0].kind != .reply) return error.Hop2ShouldReply;
    std.debug.print("malformed bytes (3 hostile bytes) at hop 1: classified as timeout, never panicked; hop 2 still reached\n", .{});
}

// ── the genuinely-privileged live path: attempted for real, not assumed ───

fn checkLiveRawSocketPrivilegeBoundary(gpa: std.mem.Allocator) !void {
    const dest = netaddr.parseIp("127.0.0.1").?;
    if (traceroute.LinuxTransport.open(dest)) |lt_const| {
        // CAP_NET_RAW is actually available on this host (e.g. root) --
        // run a real trace instead of asserting a failure that would be
        // false here.
        var lt = lt_const;
        defer lt.close();
        var o = traceroute.Options{ .max_hops = 3, .timeout_ms = 500 };
        o.ident = lt.ident();
        var tr = try traceroute.traceWith(gpa, lt.transport(), dest, o);
        defer tr.deinit(gpa);
        std.debug.print(
            "CAP_NET_RAW IS available on this host: real raw-socket trace to 127.0.0.1 ran, reached={}\n",
            .{tr.reached},
        );
    } else |err| switch (err) {
        error.PermissionDenied => std.debug.print(
            "traceroute.LinuxTransport.open (SOCK_RAW): PermissionDenied (expected -- no CAP_NET_RAW on this host, " ++
                "and this module has no unprivileged fallback by design; see the file header)\n",
            .{},
        ),
        else => return err,
    }
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    try checkOptionsValidation();
    try checkAllocFailureReturnsEarly(gpa);
    try checkEngineWithFixtureBytes(gpa);
    try checkMalformedBytesNeverPanic(gpa);
    try checkLiveRawSocketPrivilegeBoundary(gpa);

    std.debug.print("OK: all traceroute example checks passed\n", .{});
}
