// SPDX-License-Identifier: MIT

//! What a Path-MTU consumer does with `pathmtu`: read the kernel's cached
//! view (`query`, unprivileged), drive the authoritative DF-bit binary
//! search engine (`searchWith`) offline through its public `Prober` seam to
//! see the well-behaved-path/black-hole distinction this module exists for,
//! and attempt the live probe path (`probe`) for real.
//!
//! ⚠ WHAT RAN LIVE VS. WHAT DID NOT, AND WHY:
//!
//!  - **LIVE, unprivileged**: `query()` against `127.0.0.1` (a real
//!    connected UDP socket + `IP_MTU_DISCOVER`/`getsockopt(IP_MTU)`, no
//!    CAP_NET_RAW) and `ifaceMtu("lo")` (a real `SIOCGIFMTU`). Both need no
//!    capability at all — the module's own doc comment is explicit about
//!    this.
//!  - **LIVE, gated on privilege**: `probe()` opens a real `icmp.Socket`
//!    (DGRAM if `net.ipv4.ping_group_range` covers this process, RAW
//!    otherwise — CAP_NET_RAW). This example calls it for real against
//!    `127.0.0.1` and asserts the named `error.PermissionDenied` it gets on
//!    an unprivileged host, following the `traceroute` example's pattern —
//!    it does not assume the failure, it observes it.
//!  - **NOT live, by public-seam fixture**: the actual DF-bit binary search
//!    and its well-behaved-vs-black-hole classification — the module's
//!    central claim, and the one thing `query()` structurally cannot show
//!    (see the module doc comment: the kernel cache has no "I asked and got
//!    silence" state). Reproducing a genuine ICMP black hole needs a
//!    forwarding router with a firewall rule dropping its own
//!    Fragmentation-Needed replies — exactly the `unshare --net` veth
//!    topology `root.zig`'s own "real-capture goldens" section documents
//!    building, which needs kernel namespace/forwarding setup this example
//!    does not attempt to reproduce. Instead this example scripts
//!    `pathmtu.Prober` — the SAME public seam `probe()`'s real
//!    `LiveProber` implements — so `searchWith`'s real bisection and
//!    black-hole bookkeeping run for real, just fed controlled outcomes.
//!    This is exactly the technique `root.zig`'s own offline `FakeProber`
//!    tests use, reimplemented here against the public API only (no
//!    `test_deps`, no private declarations).
//!
//! This module allocates nowhere in its public API (`std.mem.Allocator`
//! does not appear in its signatures) — there is no OutOfMemory path to
//! exercise and no `std.heap.DebugAllocator` gate to wrap this example in.

const std = @import("std");
const pathmtu = @import("pathmtu");
const netaddr = @import("netaddr");

// ── fixture prober: the module's own public `Prober` seam ─────────────────

const ScriptedProber = struct {
    /// Largest wire size that "fits".
    real_mtu: u16,
    /// Above `real_mtu`: an explicit ICMP signal (well-behaved path) when
    /// true, or silence (black hole) when false.
    explicit_icmp: bool,

    fn prober(self: *ScriptedProber) pathmtu.Prober {
        return .{ .ctx = self, .probeFn = probeFn };
    }

    fn probeFn(ctx: *anyopaque, wire_size: u16) pathmtu.ProbeOutcome {
        const self: *ScriptedProber = @ptrCast(@alignCast(ctx));
        if (wire_size <= self.real_mtu) return .ok;
        return if (self.explicit_icmp) .{ .frag_needed = self.real_mtu } else .no_reply;
    }
};

pub fn main() !void {
    // ── 1. LIVE, unprivileged: kernel cache + interface MTU ───────────────

    const iface_mtu = try pathmtu.ifaceMtu("lo");
    if (iface_mtu == 0) return error.UnexpectedZeroMtu;
    std.debug.print("ifaceMtu(\"lo\") = {d}\n", .{iface_mtu});

    const dest = netaddr.parseIp("127.0.0.1").?;
    const cached = try pathmtu.query(dest, .{ .iface = "lo" });
    if (cached.source != .cached) return error.WrongSource;
    if (cached.mtu == 0) return error.UnexpectedZeroMtu;
    // `query` can never set `blackhole` -- see the module doc comment.
    if (cached.blackhole) return error.QueryShouldNeverSeeBlackhole;
    std.debug.print("query(127.0.0.1) = {{ .mtu = {d}, .iface_mtu = {?} }}\n", .{ cached.mtu, cached.iface_mtu });

    // A second live call: a destination with no prior PMTU exception at all
    // still resolves through the SAME kernel-cache path (no crash, no
    // special-case), just reporting the outgoing interface's own MTU --
    // which is precisely `query`'s documented blind spot when nothing has
    // ever populated the cache for that destination.
    const dest2 = netaddr.parseIp("127.0.0.2").?;
    const cached2 = try pathmtu.query(dest2, .{});
    std.debug.print("query(127.0.0.2) = {{ .mtu = {d} }} (no iface requested this time)\n", .{cached2.mtu});

    // ── 2. LIVE, gated on privilege: the authoritative probe path ─────────

    if (pathmtu.probe(dest, .{ .timeout_ms = 300, .retries = 0 })) |r| {
        std.debug.print(
            "CAP_NET_RAW / ping_group_range IS available: real probe() ran, mtu={d} blackhole={}\n",
            .{ r.mtu, r.blackhole },
        );
    } else |err| switch (err) {
        error.PermissionDenied => std.debug.print(
            "probe(127.0.0.1): PermissionDenied (expected -- no CAP_NET_RAW/ping_group_range on this host)\n",
            .{},
        ),
        else => return err,
    }

    // `probe`'s ceiling_mtu refusal needs no socket at all -- checked before
    // one is ever opened -- so this named error runs unconditionally,
    // privilege or not.
    if (pathmtu.probe(dest, .{ .ceiling_mtu = pathmtu.max_probe_mtu + 1 })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.CeilingTooHigh => std.debug.print(
            "probe(ceiling_mtu = max_probe_mtu + 1): CeilingTooHigh (expected, no socket opened)\n",
            .{},
        ),
        else => return err,
    }

    // ── 3. FIXTURE: the DF-bit binary search engine, both signatures ──────

    var well_behaved: ScriptedProber = .{ .real_mtu = 1300, .explicit_icmp = true };
    const wb = try pathmtu.searchWith(well_behaved.prober(), pathmtu.min_mtu_v4, pathmtu.default_ceiling_mtu, iface_mtu);
    if (wb.mtu != 1300) return error.WrongMtu;
    if (wb.blackhole) return error.ShouldNotBeBlackhole;
    std.debug.print("searchWith (well-behaved fixture, explicit Frag-Needed): mtu={d} blackhole={}\n", .{ wb.mtu, wb.blackhole });

    // A second target through the SAME engine: the real black hole this
    // module exists to detect -- identical true bottleneck, but nothing
    // ever answers past it.
    var blackholed: ScriptedProber = .{ .real_mtu = 1300, .explicit_icmp = false };
    const bh = try pathmtu.searchWith(blackholed.prober(), pathmtu.min_mtu_v4, pathmtu.default_ceiling_mtu, null);
    if (bh.mtu != 1300) return error.WrongMtu;
    if (!bh.blackhole) return error.ShouldBeBlackhole;
    std.debug.print("searchWith (black-holed fixture, silence past 1300): mtu={d} blackhole={} <- query() could never see this\n", .{ bh.mtu, bh.blackhole });

    // ── 4. named negative case, pure ───────────────────────────────────────

    const Always = struct {
        fn probeFn(_: *anyopaque, _: u16) pathmtu.ProbeOutcome {
            return .ok;
        }
    };
    var dummy: u8 = 0;
    const p: pathmtu.Prober = .{ .ctx = &dummy, .probeFn = Always.probeFn };
    if (pathmtu.searchWith(p, 1500, 1500, null)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.CeilingTooLow => std.debug.print("searchWith(ceiling == floor): CeilingTooLow (expected)\n", .{}),
        error.Unreachable => return err,
    }

    std.debug.print("OK: all pathmtu example checks passed\n", .{});
}
