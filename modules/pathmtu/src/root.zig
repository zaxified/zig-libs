// SPDX-License-Identifier: MIT

//! pathmtu — Path MTU discovery for IPv4/IPv6 on Linux: the kernel's cached
//! view (`query`) and an authoritative DF-bit binary search (`probe`) that
//! catches what the cache structurally cannot.
//!
//! Fourth member of the `icmp` / `probe` / `traceroute` family — "how big a
//! packet survives this path" is the question none of them answers, and the
//! one behind a PPPoE or WireGuard link whose real MTU is below 1500: small
//! requests work, large ones just hang, with nothing in a packet capture to
//! say why.
//!
//! ## Two answers, and why both exist
//!
//! `query` is the ~25-line, unprivileged, kernel-assisted approach: set
//! `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` to `PMTUDISC_DO` on a connected UDP
//! socket, nudge it with one oversized datagram, read `IP_MTU`/`IPV6_MTU`
//! back. Fast, needs no capability, and correct exactly when the kernel's
//! destination cache has been populated by a genuine ICMP Fragmentation
//! Needed (v4) / Packet Too Big (v6) message.
//!
//! `probe` exists because that populating step is not guaranteed. A
//! middlebox that drops an oversized DF packet WITHOUT sending the ICMP
//! back — a firewall rule that eats "destination unreachable", a tunnel
//! endpoint that never generates it — leaves the kernel with nothing to
//! learn from; `query` then reports the outgoing interface's own MTU
//! (1500), silently wrong, because the cache has no way to distinguish "no
//! problem" from "no answer". This is the actual failure mode behind most
//! reports of "TCP handshakes fine, then hangs on real traffic": the SYN/ACK
//! exchange is small, the data segments are not. `probe` finds the true
//! ceiling itself — binary-search candidate wire sizes with the DF bit set,
//! using the sibling `icmp` module's echo codec and DF-capable socket — and
//! tells the two failure shapes apart: a size that fails because a router
//! sends a real ICMP Fragmentation-Needed/Packet-Too-Big (well-behaved path,
//! `blackhole = false`) versus a size that fails because nothing ever comes
//! back after retries rule out ordinary packet loss (`blackhole = true`).
//! `query` can never set `blackhole` — the cache has no signal to report it
//! from — and always reports `.cached`.
//!
//! **Measured, live, on this host (see SPEC.md for the full method): a
//! router forwarding onto a real 1300-byte-MTU link, ICMP Frag-Needed
//! reaching the client, `query` reports 1300 — correct. The same topology
//! with that ICMP message dropped by the router's own firewall: `query`
//! reports 1500 — the interface's own MTU, silently wrong; `probe` still
//! finds 1300, and marks it `blackhole = true`.**
//!
//! ## Surface, and what the original proposal's shape did not survive
//!
//! `query`/`probe` and `Result{ mtu, source, blackhole, iface_mtu }` are
//! close to the proposal's suggested surface, with three changes. `probe`
//! does not take a `std.Io` — the sibling `icmp`/`traceroute` family this
//! module extends is raw-syscall (`std.os.linux` + `ppoll`), not
//! `std.Io`-based, and splitting that convention within one family would
//! cost more than the `Io` parameter buys here (`probe` is a single
//! blocking call, not a streamed or cancellable one). `query`/`probe` share
//! one `Options` (with a `timeout_ms` field matching `sntp.QueryOptions`/
//! `stun.QueryOptions`, per this repo's "don't invent a third options
//! shape" rule) rather than being told apart by signature — `query` simply
//! doesn't use the probe-only fields (`retries`, `ceiling_mtu`). And
//! `Source` drops the proposal's third `.interface` variant: that would
//! mean a `Result` whose `mtu` is just the raw interface MTU handed back as
//! if it were an answer about the path — precisely the failure mode this
//! module exists to name and avoid (see `query`'s doc comment). The
//! interface MTU is still available, but only ever as the separate
//! `iface_mtu` field, never disguised as a discovered or cached path MTU.
//!
//! ## Layers
//!
//!  * `searchWith` — the pure DF-probe binary search over an injectable
//!    `Prober` seam. No sockets, no clock, no allocation; this is what the
//!    offline tests exercise directly (`FakeProber`), including the
//!    black-hole/well-behaved distinction, without a network or CAP_NET_RAW.
//!  * `classify` / `mtuHintV4` / `mtuHintV6` — turn one received ICMP/ICMPv6
//!    message into a `ProbeOutcome`, reading RFC 1191's next-hop-MTU hint
//!    (v4: 2 bytes at ICMP header offset 6) / RFC 4443 §3.2's MTU field (v6:
//!    4 bytes at offset 4) when a router supplies one. `searchWith` trusts a
//!    valid hint the same way a real kernel PMTUD implementation does —
//!    converging on it directly rather than re-probing that exact size.
//!  * `probe` — the live path: opens an `icmp.Socket` (DGRAM if unprivileged
//!    ping is permitted, RAW otherwise — CAP_NET_RAW), wires it into
//!    `searchWith` via `Prober`.
//!  * `query` — the kernel-cache path: raw `std.os.linux` socket calls only
//!    (no `icmp` dependency needed — no ICMP is sent or parsed).
//!  * `ifaceMtu` — `SIOCGIFMTU` by interface name, for `Options.iface` /
//!    `Result.iface_mtu`. This module does **no** automatic egress-interface
//!    resolution (no route lookup) — see SPEC.md "What is deliberately not
//!    done".
//!
//! Provenance: clean-room from RFC 1191 (IPv4 PMTUD) / RFC 8201 (IPv6 PMTUD)
//! / RFC 4443 §3.2 (Packet Too Big) and `ip(7)`/`ipv6(7)`'s
//! `IP_MTU_DISCOVER`/`IP_MTU` documentation. A prior in-house ~25-line
//! implementation (our own code, not a third-party project) was read
//! as the starting point for `query` and is superseded by this module — see
//! this file's own NOTICE-equivalent note in SPEC.md; no root `NOTICE` entry
//! applies (no third-party source studied or ported). Design method for
//! `probe` (DF-bit binary search) follows the public technique used by
//! Linux `tracepath(8)` — behavior only, no source consulted.

const std = @import("std");
const linux = std.os.linux;
const icmp = @import("icmp");
const echo = icmp.echo;
const netaddr = @import("netaddr");

pub const meta = .{
    .targets = .{ .linux64, .linux32 },
    .platform = .linux, // raw syscalls (IP_MTU_DISCOVER) + the sibling icmp module's raw/dgram ICMP sockets; no portable fallback
    .role = .client,
    .concurrency = .reentrant, // no shared state; each call opens its own socket
    .model_after = "RFC 1191/8201 Path MTU Discovery; RFC 4443 §3.2 Packet Too Big; ip(7)/ipv6(7) IP_MTU_DISCOVER; Linux tracepath(8)'s DF-probe binary search method",
    .deps = .{ "icmp", "netaddr" },
};

// ── result model ────────────────────────────────────────────────────────────

/// Where `Result.mtu` came from.
pub const Source = enum {
    /// `query`: whatever the kernel's PMTU destination cache already held.
    cached,
    /// `probe`: converged by an active DF-bit binary search.
    probed,
};

pub const Result = struct {
    mtu: u32,
    source: Source,
    /// Only ever set by `probe`. True when the search's upper bound was
    /// narrowed purely by timeouts — no explicit ICMP Fragmentation Needed
    /// (v4) / Packet Too Big (v6) was seen anywhere in the whole search —
    /// after retries ruled out ordinary single-packet loss. This is the
    /// signature `query`'s kernel-cache read cannot produce at all: the
    /// cache has no "I asked and got silence" state, only "I don't know
    /// yet" (which reads identically to "no problem"). See the module doc
    /// comment for a measured example (1300 real vs. 1500 reported).
    blackhole: bool = false,
    /// Set when `Options.iface` was supplied and `SIOCGIFMTU` resolved it.
    iface_mtu: ?u32 = null,
};

/// Shared by `query` and `probe` (this repo avoids a third `*Options` shape
/// alongside `sntp.QueryOptions`/`stun.QueryOptions`). `query` only reads
/// `iface`; `retries`/`ceiling_mtu`/`timeout_ms` are `probe`-only.
pub const Options = struct {
    /// `probe`: receive timeout per candidate-size attempt, matching
    /// `sntp.QueryOptions`/`stun.QueryOptions`'s field. Unused by `query` —
    /// the kernel-cache read is one synchronous `getsockopt`, it never waits
    /// on the network.
    timeout_ms: u32 = 1000,
    /// `probe`: additional attempts at one candidate size before concluding
    /// no reply arrived at all (vs. ordinary single-packet loss).
    retries: u8 = 2,
    /// `probe`: upper bound to start the search from. Defaults to
    /// `default_ceiling_mtu` (1500) unless `iface` resolves a different
    /// configured MTU.
    ceiling_mtu: ?u16 = null,
    /// Interface name (e.g. `"eth0"`) read via `SIOCGIFMTU` into
    /// `Result.iface_mtu`, and used as `probe`'s starting upper bound when
    /// `ceiling_mtu` is unset. Optional and never auto-detected — see
    /// SPEC.md "What is deliberately not done".
    iface: ?[]const u8 = null,
};

// ── protocol floors / defaults ─────────────────────────────────────────────

/// RFC 791: every IPv4 router must be able to forward a datagram of at
/// least this size without fragmenting. The practical floor `probe` treats
/// as "definitely gets through, or the destination is unreachable".
pub const min_mtu_v4: u16 = 68;

/// RFC 8200 §5: the minimum link MTU every IPv6 link must support.
pub const min_mtu_v6: u16 = 1280;

/// Starting upper bound for `probe` when neither `Options.ceiling_mtu` nor
/// `Options.iface` supplies one — plain Ethernet.
pub const default_ceiling_mtu: u16 = 1500;

/// Largest wire size `probe` will ever build a request for (covers common
/// jumbo-frame ceilings). Also the fixed stack buffer size `probe` uses —
/// no allocator required.
pub const max_probe_mtu: u16 = 9000;

const ipv4_header_len: u16 = 20;
const ipv6_header_len: u16 = 40;

/// RFC 792: ICMPv4 Destination Unreachable code for "fragmentation needed
/// and DF set".
const v4_frag_needed_code: u8 = 4;

/// RFC 863 discard port — matches the prior in-house approach: nothing needs to be
/// listening, the datagram only exists to nudge PMTUD and is never expected
/// to be delivered to an application.
const control_port: u16 = 9;

// ── query: kernel PMTU cache ────────────────────────────────────────────────

pub const QueryError = error{
    SocketFailed,
    ConnectFailed,
    Unexpected,
};

/// Read the kernel's cached path MTU to `dest`: `IP_MTU_DISCOVER`/
/// `IPV6_MTU_DISCOVER` = `PMTUDISC_DO` on a connected UDP socket, one
/// oversized nudge datagram (`EMSGSIZE` is an expected, ignored outcome),
/// then `getsockopt(IP_MTU`/`IPV6_MTU)`. Unprivileged — no `CAP_NET_RAW`.
///
/// **This can be wrong.** If nothing has ever populated the kernel's PMTU
/// exception for `dest` — either because no oversized packet has been sent
/// yet, or because one was sent and the resulting ICMP feedback was dropped
/// somewhere on the path — this returns the outgoing interface's own MTU,
/// which reads as "no problem" whether or not there is one. `probe` is the
/// only way to tell those apart; see the module doc comment.
pub fn query(dest: netaddr.Ip, opts: Options) QueryError!Result {
    const family = toSocketFamily(dest);
    const domain: u32 = switch (family) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };

    const rc = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    switch (family) {
        .v4 => setOptInt(fd, linux.SOL.IP, linux.IP.MTU_DISCOVER, linux.IP.PMTUDISC_DO),
        .v6 => setOptInt(fd, linux.SOL.IPV6, linux.IPV6.MTU_DISCOVER, linux.IPV6.PMTUDISC_DO),
    }

    switch (dest) {
        .v4 => |q| {
            const sa: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, control_port), .addr = @bitCast(q) };
            if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
                return error.ConnectFailed;
        },
        .v6 => |b| {
            const sa: linux.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, control_port), .flowinfo = 0, .addr = b, .scope_id = 0 };
            if (linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
                return error.ConnectFailed;
        },
    }

    // Oversized nudge -- EMSGSIZE is the expected outcome once the kernel
    // already knows the path can't take this size; ignored either way, the
    // getsockopt below is the actual read.
    var big: [1472]u8 = @splat(0);
    _ = linux.sendto(fd, &big, big.len, 0, null, 0);

    var mtu: u32 = 0;
    var optlen: linux.socklen_t = @sizeOf(u32);
    const grc = switch (family) {
        .v4 => linux.getsockopt(fd, linux.SOL.IP, linux.IP.MTU, @ptrCast(&mtu), &optlen),
        .v6 => linux.getsockopt(fd, linux.SOL.IPV6, linux.IPV6.MTU, @ptrCast(&mtu), &optlen),
    };
    if (linux.errno(grc) != .SUCCESS) return error.Unexpected;

    var result: Result = .{ .mtu = mtu, .source = .cached };
    if (opts.iface) |name| result.iface_mtu = ifaceMtu(name) catch null;
    return result;
}

// ── probe: DF-bit binary search ─────────────────────────────────────────────

/// One candidate size's outcome, decoupled from any real socket. This is
/// the seam `searchWith` is tested against offline; `probe`'s live path
/// (`LiveProber`) is the only thing that produces one from real ICMP bytes.
pub const ProbeOutcome = union(enum) {
    /// A reply came back addressed to this exact probe: the size gets
    /// through.
    ok,
    /// An explicit ICMP Fragmentation Needed (v4) / Packet Too Big (v6) was
    /// seen for this size, optionally carrying the next-hop MTU it reported
    /// (RFC 1191 / RFC 4443 §3.2). A real signal from the path: this size
    /// does NOT count toward `blackhole`.
    frag_needed: ?u32,
    /// The local kernel refused to even hand the packet to the wire
    /// (`EMSGSIZE` against the outgoing interface's own configured MTU).
    /// Definitive, but purely local — it says nothing about the remote
    /// path, so it must not feed the black-hole signal either way.
    local_reject,
    /// No reply of any kind arrived before the attempt budget was spent.
    no_reply,
};

pub const Prober = struct {
    ctx: *anyopaque,
    probeFn: *const fn (ctx: *anyopaque, wire_size: u16) ProbeOutcome,

    pub fn probe(self: Prober, wire_size: u16) ProbeOutcome {
        return self.probeFn(self.ctx, wire_size);
    }
};

pub const SearchError = error{
    /// The floor MTU (68 v4 / 1280 v6) itself never got a reply -- this
    /// isn't a PMTU question, the destination is unreachable outright.
    Unreachable,
    /// `ceiling` was at or below `floor` -- nothing to search. `searchWith`
    /// is `pub` and its own doc comment recommends it directly to a
    /// consumer substituting their own transport, so this precondition is
    /// enforced here as a checked error rather than relying on `probe()`'s
    /// own `CeilingTooLow` guard (see "probe: live path" below) -- a caller
    /// reaching `searchWith` directly gets none of that guard's protection.
    /// Previously a bare `std.debug.assert`: compiled out entirely in
    /// ReleaseFast/ReleaseSmall, so a violated precondition made `hi - lo`
    /// underflow on unsigned `u16` arithmetic in the loop below and hang
    /// rather than panic (found by audit, 2026-08-18; see CHANGELOG.md).
    CeilingTooLow,
};

/// One probe outcome's effect on the search state: narrows `(lo, hi)`
/// toward the true boundary and updates the two flags `searchWith` derives
/// `blackhole` from. `size` is always the wire size that produced
/// `outcome`, and is always strictly between the caller's current `lo` and
/// `hi` (or equal to `hi` on the very first call).
fn applyOutcome(size: u16, outcome: ProbeOutcome, lo: *u16, hi: *u16, saw_frag_needed: *bool, saw_timeout_boundary: *bool) void {
    switch (outcome) {
        .ok => lo.* = size,
        .frag_needed => |hint| {
            saw_frag_needed.* = true;
            // RFC 1191/4443: the next-hop MTU a router reports is a size
            // that DOES fit (not a size that failed) -- the same trust a
            // real kernel PMTUD implementation places in it, without
            // re-probing that exact size. So a valid hint raises `lo` to
            // the hint itself and drops `hi` to one past it, converging
            // immediately rather than merely narrowing.
            if (hint) |h| {
                if (h > lo.* and h < size and h < std.math.maxInt(u16)) {
                    const h16: u16 = @intCast(h);
                    lo.* = h16;
                    hi.* = h16 + 1;
                    return;
                }
            }
            hi.* = size;
        },
        .local_reject => hi.* = size,
        .no_reply => {
            saw_timeout_boundary.* = true;
            hi.* = size;
        },
    }
}

/// The pure DF-probe binary search (RFC 1191 method): converge on the
/// largest wire size in `[floor, ceiling]` that `prober` reports `.ok` for.
/// No sockets, no clock, no allocation. `probe` is the live wrapper that
/// supplies a real ICMP-backed `Prober`; this function is what the offline
/// `FakeProber` tests exercise directly.
pub fn searchWith(prober: Prober, floor: u16, ceiling: u16, iface_mtu: ?u32) SearchError!Result {
    if (ceiling <= floor) return error.CeilingTooLow;

    if (prober.probe(floor) != .ok) return error.Unreachable;

    var lo: u16 = floor;
    var hi: u16 = ceiling;
    var saw_frag_needed = false;
    var saw_timeout_boundary = false;

    applyOutcome(hi, prober.probe(hi), &lo, &hi, &saw_frag_needed, &saw_timeout_boundary);
    while (hi - lo > 1) {
        const mid = lo + (hi - lo) / 2;
        applyOutcome(mid, prober.probe(mid), &lo, &hi, &saw_frag_needed, &saw_timeout_boundary);
    }

    return .{
        .mtu = lo,
        .source = .probed,
        .blackhole = saw_timeout_boundary and !saw_frag_needed,
        .iface_mtu = iface_mtu,
    };
}

// ── probe: wire classification ──────────────────────────────────────────────

const Classified = union(enum) { ok, frag_needed: ?u32 };

/// Turn one received packet into a `Classified` outcome, or `null` if it's
/// unrelated to our probe (wrong ident/seq, or not a message we care about)
/// and the caller should keep waiting. `strip_ip_header` matches raw v4
/// ICMP sockets, which deliver the IP header (the sibling `icmp`/
/// `traceroute` modules' convention); DGRAM sockets and all v6 sockets
/// never do.
fn classify(family: icmp.Socket.Family, strip_ip_header: bool, packet: []const u8, ident: u16, seq: u16) ?Classified {
    const icmp_bytes = if (strip_ip_header) (stripIpv4(packet) orelse return null) else packet;

    switch (family) {
        .v4 => {
            switch (echo.parseV4(icmp_bytes, false)) {
                .echo_reply => |er| return if (er.ident == ident and er.seq == seq) .ok else null,
                .icmp_error => |e| {
                    if (e.orig_ident != ident or e.orig_seq != seq) return null;
                    if (e.kind == .dest_unreachable and e.code == v4_frag_needed_code)
                        return .{ .frag_needed = mtuHintV4(icmp_bytes) };
                    return null;
                },
                .ignored => return null,
            }
        },
        .v6 => {
            switch (echo.parseV6(icmp_bytes)) {
                .echo_reply => |er| return if (er.ident == ident and er.seq == seq) .ok else null,
                .icmp_error => |e| {
                    if (e.orig_ident != ident or e.orig_seq != seq) return null;
                    if (e.kind == .packet_too_big) return .{ .frag_needed = mtuHintV6(icmp_bytes) };
                    return null;
                },
                .ignored => return null,
            }
        },
    }
}

fn stripIpv4(packet: []const u8) ?[]const u8 {
    if (packet.len < 20) return null;
    const ihl: usize = @as(usize, packet[0] & 0x0f) * 4;
    if (ihl < 20 or packet.len < ihl) return null;
    return packet[ihl..];
}

/// RFC 1191: for ICMPv4 Destination Unreachable / code 4, the 2 bytes at
/// ICMP header offset 6 (the low half of the "unused" field, repurposed)
/// carry the next-hop MTU. Zero means a pre-RFC-1191 router left it unset
/// -- treated as "no hint", falling back to plain bisection.
fn mtuHintV4(icmp_bytes: []const u8) ?u32 {
    if (icmp_bytes.len < 8) return null;
    const v = std.mem.readInt(u16, icmp_bytes[6..8], .big);
    return if (v == 0) null else v;
}

/// RFC 4443 §3.2: for ICMPv6 Packet Too Big, the 4 bytes at offset 4 carry
/// the next-hop MTU -- always meaningful (no ICMPv6 equivalent of v4's
/// unfilled-field history).
fn mtuHintV6(icmp_bytes: []const u8) ?u32 {
    if (icmp_bytes.len < 8) return null;
    const v = std.mem.readInt(u32, icmp_bytes[4..8], .big);
    return if (v == 0) null else v;
}

// ── probe: live path ─────────────────────────────────────────────────────────

pub const ProbeError = error{
    PermissionDenied,
    AddressFamilyUnsupported,
    /// See `SearchError.Unreachable`.
    Unreachable,
    /// `Options.ceiling_mtu` (or the interface MTU it fell back to) was at
    /// or below the protocol floor -- nothing to search.
    CeilingTooLow,
    /// `Options.ceiling_mtu` was set above `max_probe_mtu` (9000) --
    /// refused, not silently capped. A caller who names a ceiling this
    /// module can never probe is stating an expectation the module cannot
    /// meet; answering with a `Result` bounded by a smaller, unrequested
    /// ceiling would quietly answer a different question than the one
    /// asked, the same failure shape `CeilingTooLow` above already refuses
    /// rather than commits. `Options.iface`'s auto-*derived* ceiling is
    /// unaffected by this error and still clamps silently -- see
    /// SPEC.md "Limits and refusals" for why the two cases are handled
    /// differently.
    CeilingTooHigh,
    Unexpected,
};

const DestAddr = union(enum) {
    v4: linux.sockaddr.in,
    v6: linux.sockaddr.in6,
};

/// The live `Prober`: owns a real `icmp.Socket` and turns each
/// `searchWith` call into a send + receive-with-timeout-and-retries cycle.
const LiveProber = struct {
    sock: *icmp.Socket,
    family: icmp.Socket.Family,
    ip_header_len: u16,
    strip_ip_header: bool,
    dest: DestAddr,
    retries: u8,
    timeout_ms: u32,
    seq: u16 = 1,
    // Zero-filled, not `undefined`: `writeEchoRequest` only touches the
    // 8-byte echo header (see its own doc comment -- "payload bytes beyond
    // the header are expected to be pre-filled ... by the caller"), and a
    // probe wire size larger than the header leaves the rest of this
    // buffer as whatever was last in it. `undefined` on a stack field means
    // that remainder is stale stack content, echoed onto the wire as ICMP
    // payload on every single probe, not only the out-of-bounds case fixed
    // alongside this (found while fixing that; same root cause, smaller
    // blast radius -- in-bounds, but still someone else's stack bytes on
    // the wire).
    buf: [max_probe_mtu]u8 = @splat(0),

    fn prober(self: *LiveProber) Prober {
        return .{ .ctx = self, .probeFn = probeFn };
    }

    fn probeFn(ctx: *anyopaque, wire_size: u16) ProbeOutcome {
        const self: *LiveProber = @ptrCast(@alignCast(ctx));
        return self.attempt(wire_size);
    }

    fn attempt(self: *LiveProber, wire_size: u16) ProbeOutcome {
        // Defense in depth for the exact invariant an audit found broken
        // (2026-08-18; see CHANGELOG.md): `probe()` refuses any
        // `ceiling_mtu` above `max_probe_mtu` before this prober is ever
        // built (`ProbeError.CeilingTooHigh`), and `searchWith` never
        // probes a size above its own `ceiling` argument, so this can
        // never trip in practice. Deliberately **not** a
        // `std.debug.assert` -- that check, and Zig's own slice-bounds
        // check on `self.buf[0..payload_len]` below, both compile out
        // entirely in ReleaseFast/ReleaseSmall, which is exactly how the
        // original bug read past the end of this buffer and handed the
        // over-length slice to `sendTo`. `@panic` does not compile out in
        // any mode.
        if (wire_size < self.ip_header_len or wire_size - self.ip_header_len > self.buf.len)
            @panic("pathmtu: LiveProber.attempt: wire_size exceeds probe buffer capacity");

        const payload_len = wire_size - self.ip_header_len;
        const efamily: echo.Family = switch (self.family) {
            .v4 => .v4,
            .v6 => .v6,
        };

        var tries: u8 = 0;
        while (tries <= self.retries) : (tries += 1) {
            const seq = self.seq;
            self.seq +%= 1;
            // `attempt` already panics above when `wire_size` overruns the
            // buffer; this is the same caller error at the other end -- a
            // probe smaller than the ICMP header itself. A panic holds in
            // every optimize mode, which is the whole reason the writer
            // stopped using `std.debug.assert` for it.
            echo.writeEchoRequest(efamily, self.buf[0..payload_len], self.sock.ident, seq) catch
                @panic("pathmtu: LiveProber.attempt: wire_size smaller than the ICMP header");

            const send_result = switch (self.dest) {
                .v4 => |*sa| self.sock.sendTo(@ptrCast(sa), @sizeOf(linux.sockaddr.in), self.buf[0..payload_len]),
                .v6 => |*sa| self.sock.sendTo(@ptrCast(sa), @sizeOf(linux.sockaddr.in6), self.buf[0..payload_len]),
            };
            send_result catch |err| switch (err) {
                error.MessageTooLong => return .local_reject,
                else => continue, // WouldBlock / transient failure: this attempt produced no signal, retry
            };

            const deadline: u64 = @as(u64, @intCast(icmp.monoNow())) + @as(u64, self.timeout_ms) * std.time.ns_per_ms;
            var recv_buf: [max_probe_mtu + 128]u8 = undefined;
            while (true) {
                if (self.sock.recvMsg(&recv_buf)) |info| {
                    if (classify(self.family, self.strip_ip_header, info.packet, self.sock.ident, seq)) |c| {
                        switch (c) {
                            .ok => return .ok,
                            .frag_needed => |hint| return .{ .frag_needed = hint },
                        }
                    }
                    continue;
                }
                const now: u64 = @intCast(icmp.monoNow());
                if (now >= deadline) break;
                pollOnce(self.sock.fd, linux.POLL.IN, deadline - now);
            }
        }
        return .no_reply;
    }
};

/// Best-effort per-session starting `seq`, drawn from `getrandom(2)` rather
/// than the previous fixed value 1 -- raises the bar against a *blind*
/// off-path spoofer, who must now guess a full 16-bit unknown instead of
/// spraying the first ~20 sequential values; does nothing against an
/// on-path attacker, who reads the real value off the wire. See SPEC.md
/// "Threat model" for the full reasoning and honest scope. Linux-only
/// direct syscall, matching the `getrandom`-direct, panic-avoided-here
/// posture `ssh`/`bulletproofs` use elsewhere in this repo
/// (CONVENTIONS.md §2.2) -- except this value is not a secret (it only
/// needs to be hard to *blindly guess*, never to stay confidential), so
/// unlike a key draw, a syscall failure falls back to the old fixed value
/// rather than aborting the process: that only returns this session to the
/// pre-existing, already-documented baseline exposure, never to something
/// worse or silently misrepresented as safe.
fn randomStartSeq() u16 {
    var buf: [2]u8 = undefined;
    while (true) {
        const rc = linux.getrandom(&buf, buf.len, 0);
        const signed: isize = @bitCast(rc);
        if (signed == buf.len) return std.mem.readInt(u16, &buf, .little);
        if (signed == -@as(isize, @intFromEnum(linux.E.INTR))) continue;
        return 1; // getrandom unavailable: fall back to the old fixed start
    }
}

fn pollOnce(fd: i32, events: i16, wait_ns: u64) void {
    var pfd = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    var ts: linux.timespec = .{
        .sec = @intCast(wait_ns / std.time.ns_per_s),
        .nsec = @intCast(wait_ns % std.time.ns_per_s),
    };
    _ = linux.ppoll(&pfd, pfd.len, &ts, null);
}

/// Authoritative Path MTU to `dest`: binary-search wire sizes with the DF
/// bit set over a real ICMP socket (unprivileged DGRAM if the host permits
/// it via `net.ipv4.ping_group_range`, RAW otherwise -- `CAP_NET_RAW`).
/// Distinguishes a well-behaved path (an explicit ICMP Fragmentation
/// Needed/Packet Too Big shrinks the search) from a black hole (the same
/// boundary found only because nothing ever answered) -- see the module doc
/// comment and `Result.blackhole`.
pub fn probe(dest: netaddr.Ip, opts: Options) ProbeError!Result {
    const family = toSocketFamily(dest);
    const ip_header_len: u16 = switch (family) {
        .v4 => ipv4_header_len,
        .v6 => ipv6_header_len,
    };
    const floor: u16 = switch (family) {
        .v4 => min_mtu_v4,
        .v6 => min_mtu_v6,
    };

    // Refused, not clamped: an explicit `ceiling_mtu` above what this
    // module can ever probe is a caller stating an expectation the module
    // cannot meet (see `ProbeError.CeilingTooHigh`'s doc comment). This is
    // the one value on this path that used to flow unchecked into
    // `LiveProber`'s fixed `max_probe_mtu`-sized stack buffer (audit,
    // 2026-08-18; see CHANGELOG.md) -- checked here, before anything is
    // built from it, so the buffer invariant holds by construction for
    // every caller, not only a polite one.
    if (opts.ceiling_mtu) |c| {
        if (c > max_probe_mtu) return error.CeilingTooHigh;
    }

    var iface_mtu: ?u32 = null;
    if (opts.iface) |name| iface_mtu = ifaceMtu(name) catch null;

    const ceiling_from_iface: ?u16 = if (iface_mtu) |m| @intCast(@min(m, max_probe_mtu)) else null;
    const ceiling: u16 = opts.ceiling_mtu orelse ceiling_from_iface orelse default_ceiling_mtu;
    if (ceiling <= floor) return error.CeilingTooLow;

    var sock = icmp.Socket.open(family, .auto, .{ .dont_fragment = true }) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        error.AddressFamilyUnsupported => return error.AddressFamilyUnsupported,
        else => return error.Unexpected,
    };
    defer sock.close();

    var lp: LiveProber = .{
        .sock = &sock,
        .family = family,
        .ip_header_len = ip_header_len,
        .strip_ip_header = sock.kind == .raw and family == .v4,
        .dest = switch (dest) {
            .v4 => |q| .{ .v4 = .{ .port = 0, .addr = @bitCast(q) } },
            .v6 => |b| .{ .v6 = .{ .port = 0, .flowinfo = 0, .addr = b, .scope_id = 0 } },
        },
        .retries = opts.retries,
        .timeout_ms = opts.timeout_ms,
        // Off-path-blind-spoofing hardening (audit finding #3, 2026-08-18;
        // see SPEC.md "Threat model" for exactly which attacker this does
        // and does not raise the bar against). Was a fixed 1.
        .seq = randomStartSeq(),
    };

    return searchWith(lp.prober(), floor, ceiling, iface_mtu);
}

fn toSocketFamily(dest: netaddr.Ip) icmp.Socket.Family {
    return switch (dest) {
        .v4 => .v4,
        .v6 => .v6,
    };
}

fn setOptInt(fd: i32, level: i32, opt: u32, value: u32) void {
    const v: u32 = value;
    _ = linux.setsockopt(fd, level, opt, @ptrCast(&v), @sizeOf(u32));
}

// ── interface MTU ────────────────────────────────────────────────────────────

pub const IfaceError = error{ NoSuchInterface, SocketFailed };

/// Read an interface's configured MTU by name (`SIOCGIFMTU`) -- unprivileged,
/// a throwaway datagram socket for the ioctl. Mirrors the sibling `rawsock`
/// module's `ifaceByName`/`hwaddr`/`ipv4Addr` ioctl pattern, duplicated
/// locally rather than taking a dependency on `rawsock`: this module needs
/// one ioctl, not `rawsock`'s AF_PACKET raw-frame machinery.
pub fn ifaceMtu(name: []const u8) IfaceError!u32 {
    if (name.len == 0 or name.len > 15) return error.NoSuchInterface;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var req: Ifreq = .{};
    @memcpy(req.name[0..name.len], name);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFMTU, @intFromPtr(&req))) != .SUCCESS)
        return error.NoSuchInterface;
    return @bitCast(req.un[0..4].*);
}

/// `struct ifreq`: 16-byte name + 24-byte union. `SIOCGIFMTU` writes
/// `ifr_mtu` as a native-endian `int` at union offset 0.
const Ifreq = extern struct {
    name: [16]u8 = @splat(0),
    un: [24]u8 = @splat(0),
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// -- mtuHintV4 / mtuHintV6 ----------------------------------------------------

test "mtuHintV4: reads the next-hop MTU field, treats zero as absent" {
    var bytes: [8]u8 = .{ 3, 4, 0, 0, 0, 0, 0x05, 0x14 }; // hint = 0x0514 = 1300
    try testing.expectEqual(@as(?u32, 1300), mtuHintV4(&bytes));
    bytes[6] = 0;
    bytes[7] = 0;
    try testing.expectEqual(@as(?u32, null), mtuHintV4(&bytes));
    try testing.expectEqual(@as(?u32, null), mtuHintV4(bytes[0..7])); // too short
}

test "mtuHintV6: reads the 4-byte MTU field, treats zero as absent" {
    var bytes: [8]u8 = .{ 2, 0, 0, 0, 0, 0, 0x05, 0x14 }; // hint = 1300
    try testing.expectEqual(@as(?u32, 1300), mtuHintV6(&bytes));
    @memset(bytes[4..8], 0);
    try testing.expectEqual(@as(?u32, null), mtuHintV6(&bytes));
    try testing.expectEqual(@as(?u32, null), mtuHintV6(bytes[0..7]));
}

// -- classify: hand-built bytes -----------------------------------------------

test "classify v4: matching echo reply is ok, mismatched ident/seq is ignored" {
    var buf: [echo.echo_header_len]u8 = @splat(0);
    try echo.writeEchoRequest(.v4, &buf, 0x1234, 7);
    buf[0] = echo.v4.echo_reply;
    try testing.expectEqual(Classified.ok, classify(.v4, false, &buf, 0x1234, 7).?);
    try testing.expectEqual(@as(?Classified, null), classify(.v4, false, &buf, 0x1234, 8));
    try testing.expectEqual(@as(?Classified, null), classify(.v4, false, &buf, 0x9999, 7));
}

test "classify v4: dest-unreachable/code 4 is frag_needed with the MTU hint; other codes are ignored" {
    var pkt: [echo.echo_header_len + 20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v4.dest_unreachable;
    pkt[1] = v4_frag_needed_code;
    std.mem.writeInt(u16, pkt[6..8], 1300, .big); // next-hop MTU
    pkt[8] = 0x45; // quoted IP header, ihl=5
    const orig = pkt[8 + 20 ..];
    orig[0] = echo.v4.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0xabcd, .big);
    std.mem.writeInt(u16, orig[6..8], 3, .big);

    const c = classify(.v4, false, &pkt, 0xabcd, 3);
    try testing.expectEqual(@as(?u32, 1300), c.?.frag_needed);

    // A mutation that ignores the code (accepts ANY dest-unreachable as
    // frag_needed) must be caught here: code 1 (host unreachable) is a
    // different, unrelated ICMP error and must be ignored, not classified.
    pkt[1] = 1;
    try testing.expectEqual(@as(?Classified, null), classify(.v4, false, &pkt, 0xabcd, 3));
}

test "classify v6: packet_too_big is frag_needed with the MTU hint; other errors are ignored" {
    var pkt: [echo.echo_header_len + 40 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = echo.v6.packet_too_big;
    std.mem.writeInt(u32, pkt[4..8], 1300, .big);
    const quoted = pkt[echo.echo_header_len..];
    quoted[6] = 58; // next header = ICMPv6
    const orig = quoted[40..];
    orig[0] = echo.v6.echo_request;
    std.mem.writeInt(u16, orig[4..6], 0xbeef, .big);
    std.mem.writeInt(u16, orig[6..8], 9, .big);

    const c = classify(.v6, false, &pkt, 0xbeef, 9);
    try testing.expectEqual(@as(?u32, 1300), c.?.frag_needed);

    // dest_unreachable (not packet_too_big) must be ignored, not conflated.
    pkt[0] = echo.v6.dest_unreachable;
    try testing.expectEqual(@as(?Classified, null), classify(.v6, false, &pkt, 0xbeef, 9));
}

test "classify: ip-header stripping is exact at the IHL boundary" {
    var pkt: [20 + echo.echo_header_len]u8 = @splat(0);
    pkt[0] = 0x45; // ihl = 5 -> 20 bytes
    pkt[20] = echo.v4.echo_reply;
    std.mem.writeInt(u16, pkt[24..26], 1, .big);
    std.mem.writeInt(u16, pkt[26..28], 1, .big);
    try testing.expectEqual(Classified.ok, classify(.v4, true, &pkt, 1, 1).?);
    // A packet shorter than its own claimed IHL must be rejected, not read
    // out of bounds.
    try testing.expectEqual(@as(?Classified, null), classify(.v4, true, pkt[0..19], 1, 1));
}

// -- searchWith: pure binary search over a fake Prober ------------------------

const FakeProber = struct {
    /// Largest wire size that actually "fits" -- sizes <= this are `.ok`.
    real_mtu: u16,
    /// Sizes above `real_mtu` get an explicit ICMP signal when true, or
    /// silence (`.no_reply`) when false -- the well-behaved-path vs.
    /// black-hole distinction this module exists to draw.
    explicit_icmp: bool,
    hint: ?u32 = null,

    fn prober(self: *FakeProber) Prober {
        return .{ .ctx = self, .probeFn = probeFn };
    }

    fn probeFn(ctx: *anyopaque, wire_size: u16) ProbeOutcome {
        const self: *FakeProber = @ptrCast(@alignCast(ctx));
        if (wire_size <= self.real_mtu) return .ok;
        return if (self.explicit_icmp) .{ .frag_needed = self.hint } else .no_reply;
    }
};

test "searchWith: well-behaved path converges exactly, via the ICMP hint, blackhole = false" {
    var fp: FakeProber = .{ .real_mtu = 1300, .explicit_icmp = true, .hint = 1300 };
    const r = try searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, null);
    try testing.expectEqual(@as(u32, 1300), r.mtu);
    try testing.expectEqual(Source.probed, r.source);
    try testing.expect(!r.blackhole);
}

test "searchWith: well-behaved path converges exactly WITHOUT a hint (plain bisection), blackhole = false" {
    var fp: FakeProber = .{ .real_mtu = 1300, .explicit_icmp = true, .hint = null };
    const r = try searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, null);
    try testing.expectEqual(@as(u32, 1300), r.mtu);
    try testing.expect(!r.blackhole);
}

test "searchWith: black-holed path converges to the SAME mtu, but blackhole = true" {
    // Same real bottleneck as the test above, but nothing ever answers for
    // an oversized probe -- the exact scenario a router's firewall eating
    // its own Frag-Needed reply produces. The kernel-cache `query` path has
    // no way to see this at all; this is the property that justifies
    // `probe` existing.
    var fp: FakeProber = .{ .real_mtu = 1300, .explicit_icmp = false };
    const r = try searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, null);
    try testing.expectEqual(@as(u32, 1300), r.mtu);
    try testing.expect(r.blackhole);
}

test "searchWith: property -- exact convergence across a range of true bottlenecks" {
    // A mutation in the bisection arithmetic (off-by-one in `mid`, wrong
    // branch on `.ok` vs the failure arms) would miss the exact boundary
    // for at least one of these -- mutating the constant, not the guard
    // (feedback_mutate_the_constant).
    const bottlenecks = [_]u16{ 100, 296, 999, 1279, 1300, 1499 };
    for (bottlenecks) |b| {
        var fp: FakeProber = .{ .real_mtu = b, .explicit_icmp = true, .hint = null };
        const r = try searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, null);
        try testing.expectEqual(@as(u32, b), r.mtu);
    }
}

test "searchWith: even the floor MTU never answering is Unreachable, not blackhole" {
    var fp: FakeProber = .{ .real_mtu = 10, .explicit_icmp = false }; // below min_mtu_v4
    try testing.expectError(error.Unreachable, searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, null));
}

test "searchWith: one explicit Frag-Needed anywhere clears blackhole, even if another size timed out" {
    // Models a path with one well-behaved hop and one silent one: whichever
    // boundary wins the search, ANY genuine ICMP feedback during the whole
    // run is enough to call it not-a-blackhole -- documented as a known
    // limitation in SPEC.md (a single search can't separate two distinct
    // hops' behavior), not a bug.
    const Mixed = struct {
        fn probeFn(_: *anyopaque, wire_size: u16) ProbeOutcome {
            if (wire_size <= 1300) return .ok;
            if (wire_size == default_ceiling_mtu) return .{ .frag_needed = null }; // one real signal, at the ceiling probe
            return .no_reply; // every interior failing probe times out
        }
    };
    var dummy: u8 = 0;
    const p: Prober = .{ .ctx = &dummy, .probeFn = Mixed.probeFn };
    const r = try searchWith(p, min_mtu_v4, default_ceiling_mtu, null);
    try testing.expectEqual(@as(u32, 1300), r.mtu);
    try testing.expect(!r.blackhole);
}

test "searchWith: local_reject narrows the bound without affecting blackhole either way" {
    const LocalRejectAtCeiling = struct {
        fn probeFn(_: *anyopaque, wire_size: u16) ProbeOutcome {
            if (wire_size == default_ceiling_mtu) return .local_reject; // only at the very first probe
            if (wire_size <= 1300) return .ok;
            return .{ .frag_needed = 1300 };
        }
    };
    var dummy: u8 = 0;
    const p: Prober = .{ .ctx = &dummy, .probeFn = LocalRejectAtCeiling.probeFn };
    const r = try searchWith(p, min_mtu_v4, default_ceiling_mtu, null);
    try testing.expectEqual(@as(u32, 1300), r.mtu);
    try testing.expect(!r.blackhole);
}

test "searchWith: iface_mtu passes through unchanged" {
    var fp: FakeProber = .{ .real_mtu = 1300, .explicit_icmp = true };
    const r = try searchWith(fp.prober(), min_mtu_v4, default_ceiling_mtu, 9000);
    try testing.expectEqual(@as(?u32, 9000), r.iface_mtu);
}

// -- regression: audit findings, 2026-08-18 -----------------------------------
//
// Three confirmed defects: (1) an unclamped `Options.ceiling_mtu` overran
// `LiveProber`'s fixed 9000-byte stack buffer -- Debug/ReleaseSafe panicked,
// ReleaseFast read/sent adjacent stack memory as ICMP payload and returned a
// fabricated `Result`. (2) `searchWith`'s `ceiling > floor` precondition was
// a bare `std.debug.assert` -- compiled out in ReleaseFast, where a violated
// precondition underflowed `hi - lo` on `u16` and hung. (3) the threat model
// didn't name the "forged reply converges instantly to a falsely LARGE MTU"
// direction of its own already-documented lack of authentication. See
// SPEC.md "Threat model" and "Limits and refusals" for the full writeup.
//
// (1) and (2) were confirmed against the unfixed code with out-of-tree
// repros before this fix (index-out-of-bounds panic in Debug matching the
// audit's exact `root.zig:480`/`index 19980, len 9000`; a fabricated
// `mtu=20000 blackhole=false` plus SIGSEGV-on-return in ReleaseFast for (1);
// a 15s-plus hang in ReleaseFast for (2)) -- and re-confirmed red against
// `git show HEAD:modules/pathmtu/src/root.zig` for the two tests below (see
// this task's final report for the exact transcript).

test "regression (finding #1): probe() refuses ceiling_mtu above max_probe_mtu instead of overrunning the buffer" {
    // No live socket/privilege needed: `probe()` checks `ceiling_mtu`
    // before ever opening one, so this runs unconditionally (not
    // live-gated) and exercises the exact `.{ .ceiling_mtu = 20000 }` shape
    // the audit's out-of-tree repro used.
    const dest = netaddr.parseIp("127.0.0.1").?;
    const r = probe(dest, .{ .timeout_ms = 200, .retries = 0, .ceiling_mtu = 20000 });
    try testing.expectError(error.CeilingTooHigh, r);
}

test "regression (finding #1): max_probe_mtu itself is still accepted (refusal is > max_probe_mtu, not >=)" {
    // A boundary check on the fix itself: 9000 is a valid ceiling (it's the
    // buffer size, a probe AT that size fits exactly), only something
    // larger is refused.
    const dest = netaddr.parseIp("127.0.0.1").?;
    const r = probe(dest, .{ .timeout_ms = 200, .retries = 0, .ceiling_mtu = max_probe_mtu }) catch |err| switch (err) {
        // Environment-dependent (no CAP_NET_RAW / ping_group_range): the
        // point of this test is that the ceiling itself wasn't refused, so
        // any error other than CeilingTooHigh proves that.
        error.CeilingTooHigh => return error.TestUnexpectedResult,
        else => return, // any other outcome (including success) is fine
    };
    _ = r;
}

test "regression (finding #2): searchWith(ceiling <= floor) is a checked error, not a hang or a panic" {
    const Always = struct {
        fn probeFn(_: *anyopaque, _: u16) ProbeOutcome {
            return .ok;
        }
    };
    var dummy: u8 = 0;
    const p: Prober = .{ .ctx = &dummy, .probeFn = Always.probeFn };
    // ceiling == floor: violates the documented precondition. Before the
    // fix this was a bare `std.debug.assert` -- panicked in Debug, and in
    // ReleaseFast fell through into `hi - lo` underflowing on `u16` and
    // looping until killed (confirmed: 15s+ hang against the unfixed code,
    // see the comment above this section).
    try testing.expectError(error.CeilingTooLow, searchWith(p, 1500, 1500, null));
    // ceiling < floor: same guard, other side.
    try testing.expectError(error.CeilingTooLow, searchWith(p, 1500, 1499, null));
}

test "regression (finding #3): probe's live path no longer starts seq at the fixed, predictable value 1" {
    // Not a full anti-spoofing proof (impossible to test the absence of a
    // successful blind forgery from inside a unit test) -- just confirms
    // the mechanism this mitigation actually depends on: `randomStartSeq`
    // is not a constant. A mutation that hardcoded it back to `1` would
    // pass every other test in this file (the live/loopback tests never
    // observe `seq` at all) and only fail here.
    var seen_nonzero = false;
    var seen_distinct = false;
    var first: ?u16 = null;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const s = randomStartSeq();
        if (s != 0) seen_nonzero = true;
        if (first) |f| {
            if (f != s) seen_distinct = true;
        } else first = s;
    }
    // getrandom(2) is effectively always available on this host; a fixed
    // fallback of 1 for all 32 draws would be indistinguishable from
    // "never randomized" and is the exact regression this guards against.
    try testing.expect(seen_nonzero);
    try testing.expect(seen_distinct);
}

// -- real-capture goldens (client--router--server veth sandbox, 2026-08-18) --
//
// See SPEC.md "Anchoring" for the full topology and method. Summary: inside
// a throwaway, fully unprivileged `unshare --user --net` sandbox, three more
// `unshare --net` namespaces were joined client -> router -> server by veth
// pairs, with the router's server-facing link MTU set to 1300 and real
// kernel forwarding (`net.ipv4.conf.all.forwarding=1`,
// `net.ipv6.conf.all.forwarding=1`). A DF, oversized `ping` from the client
// through the real forwarding router produced the bytes below -- the
// UNMODIFIED replies a real Linux kernel sent back. No sudo, no setcap, no
// host-visible state: every interface and namespace existed only for the
// life of the capturing shell. Also verified live in that sandbox (not
// re-run in this test binary -- it needs the netns, nftables and root the
// CI sandbox doesn't have; see SPEC.md): `query()`'s kernel-cache blind
// spot, by adding an nftables rule dropping the router's own outgoing
// Frag-Needed and comparing `IP_MTU` for a destination with a prior learned
// exception (1300, correct) against a destination that never got one
// (1500, the interface MTU -- silently wrong).

const real_v4_frag_needed = [_]u8{
    0x45, 0xc0, 0x02, 0x40, 0x1f, 0x0e, 0x00, 0x00, 0x40, 0x01, 0x44, 0xed, 0x0a, 0x00, 0x00, 0x02,
    0x0a, 0x00, 0x00, 0x01, 0x03, 0x04, 0x0e, 0xb5, 0x00, 0x00, 0x05, 0x14, 0x45, 0x00, 0x05, 0x94,
    0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x20, 0x67, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01, 0x02,
    0x08, 0x00, 0x87, 0xd6, 0x3d, 0x92, 0x00, 0x01,
};

// Truncated real capture, with the outer IPv6 header (40 bytes) already
// stripped: ICMPv6 sockets never deliver it (`icmp/src/Socket.zig`'s own
// doc comment), so `classify(.v6, ...)` -- like the real live path -- never
// sees it either. The full ICMPv6 Packet Too Big reply runs to 1280 bytes
// (RFC 4443 quotes the original up to the IPv6 minimum link MTU); only the
// ICMPv6 header (8 bytes) and the quoted inner IPv6 + ICMPv6-echo header
// (48 bytes, enough for `orig_ident`/`orig_seq`) are kept.
const real_v6_packet_too_big = [_]u8{
    0x02, 0x00, 0x70, 0xd1, 0x00, 0x00, 0x05, 0x14, 0x60, 0x01, 0xc8, 0x40, 0x05, 0x80, 0x3a, 0x40,
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x80, 0x00, 0x0b, 0x7c, 0x3d, 0x9c, 0x00, 0x01,
};

test "golden: real capture -- v4 Fragmentation Needed from a genuine forwarding router, mtu hint 1300" {
    // strip_ip_header = true: this is a raw-socket-shaped capture (real
    // client sockets deliver the IP header for v4), IP header included.
    const c = classify(.v4, true, &real_v4_frag_needed, 0x3d92, 1);
    try testing.expectEqual(@as(?u32, 1300), c.?.frag_needed);
    // Wrong ident/seq must not match this real packet either.
    try testing.expectEqual(@as(?Classified, null), classify(.v4, true, &real_v4_frag_needed, 0x3d92, 2));
    try testing.expectEqual(@as(?Classified, null), classify(.v4, true, &real_v4_frag_needed, 0x0000, 1));
}

test "golden: real capture -- v6 Packet Too Big from a genuine forwarding router, mtu hint 1300" {
    const c = classify(.v6, false, &real_v6_packet_too_big, 15772, 1);
    try testing.expectEqual(@as(?u32, 1300), c.?.frag_needed);
    try testing.expectEqual(@as(?Classified, null), classify(.v6, false, &real_v6_packet_too_big, 15772, 2));
}

test "golden: real-capture fixture size canary" {
    try testing.expectEqual(@as(usize, 56), real_v4_frag_needed.len);
    try testing.expectEqual(@as(usize, 56), real_v6_packet_too_big.len);
}

// -- fuzz: classify never panics on arbitrary bytes --------------------------

test "fuzz: classify never panics on arbitrary packets" {
    try testing.fuzz({}, fuzzClassify, .{});
}

fn fuzzClassify(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const ident = smith.value(u16);
    const seq = smith.value(u16);
    _ = classify(.v4, false, buf[0..len], ident, seq);
    _ = classify(.v4, true, buf[0..len], ident, seq);
    _ = classify(.v6, false, buf[0..len], ident, seq);
}

// -- live (gated where privilege is genuinely required) ----------------------

test "live: ifaceMtu(\"lo\") reads a real loopback MTU, unprivileged" {
    const mtu = try ifaceMtu("lo");
    try testing.expect(mtu > 0);
}

test "live: query() against loopback, unprivileged (no CAP_NET_RAW needed)" {
    const dest = netaddr.parseIp("127.0.0.1").?;
    const r = query(dest, .{}) catch |err| switch (err) {
        // Some sandboxes disallow even unprivileged UDP sockets entirely;
        // that's an environment limit, not a claim this module doesn't
        // hold, so it's an explicit skip rather than a silent pass.
        error.SocketFailed, error.ConnectFailed => return error.SkipZigTest,
        else => return err,
    };
    try testing.expectEqual(Source.cached, r.source);
    try testing.expect(r.mtu > 0);
}

test "live: probe() against loopback (skipped without CAP_NET_RAW / ping_group_range)" {
    const dest = netaddr.parseIp("127.0.0.1").?;
    const r = probe(dest, .{ .timeout_ms = 500 }) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    // Loopback MTU is far above the default 1500 ceiling, so this only
    // proves the live plumbing (real socket, real send/recv, real
    // searchWith wiring) works end-to-end -- it can never observe a real
    // bottleneck. The netns goldens above are what anchor the
    // fragmentation-needed / black-hole classification itself.
    try testing.expectEqual(@as(u32, default_ceiling_mtu), r.mtu);
    try testing.expect(!r.blackhole);
}
