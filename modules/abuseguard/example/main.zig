// SPDX-License-Identifier: MIT

//! What an internet-facing `http.Server` operator does with `abuseguard`:
//! drive a `Guard` through a realistic mix of well-behaved clients and one
//! abusive client that escalates strikes -> greylist -> permanent ban, retry
//! a blocked client to show denial is stable across repeats, let a greylist
//! expire through an injected clock (a ban never does -- confirmed against
//! src/root.zig's own integration test), unban and confirm recovery, hold
//! per-IP and global connection caps at their exact boundary, wire the real
//! `on_connect`/`on_conn_state` hook pair a server uses, force genuine
//! LRU eviction at a small `max_tracked_ips`, and force the fail-closed OOM
//! path with a `FailingAllocator`. Everything runs under a leak-checking
//! allocator.
//!
//! This is an example in the gate sense -- it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only:
//! `http`, `netaddr`, `router`; no `test_deps`, no private declarations).

const std = @import("std");
const abuseguard = @import("abuseguard");
const netaddr = @import("netaddr");
const net = std.Io.net;

/// A fake, caller-controlled clock -- same `.ctx`/`.nowFn` shape the module
/// documents (`abuseguard.Clock`). `Guard` never reads a wall clock on its
/// own, so every greylist/decay/expiry step below is deterministic and
/// offline.
const FakeClock = struct {
    ns: u64 = 0,

    fn clock(fc: *FakeClock) abuseguard.Clock {
        return .{ .ctx = fc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) u64 {
        const fc: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return fc.ns;
    }
    fn advanceMs(fc: *FakeClock, ms: u64) void {
        fc.ns += ms * std.time.ns_per_ms;
    }
};

fn ip(text: []const u8) netaddr.Ip {
    return netaddr.parseIp(text).?;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var fc: FakeClock = .{};
    var g = abuseguard.Guard.init(gpa, .{
        .max_conns_per_ip = 3,
        .max_conns_total = 8,
        .ban_threshold = 3,
        .ban_after_offenses = 2,
        .greylist_ttl_ms = 60_000,
        .strike_decay_ms = 0, // exact arithmetic for this walkthrough
        .clock = fc.clock(),
    });
    defer g.deinit();

    // 1. A pool of well-behaved clients: each opens two connections and
    // closes them again. Every round targets a fresh IP, so on the next
    // round's insert the store's tail-sweep reclaims the previous round's
    // now-empty entry -- idle memory does not accumulate under ordinary
    // churn even with no eviction pressure yet.
    {
        var round: usize = 0;
        while (round < 12) : (round += 1) {
            var buf: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "10.0.0.{d}", .{round + 1}) catch unreachable;
            const client = ip(text);
            std.debug.assert(g.admit(client) == .admitted);
            std.debug.assert(g.admit(client) == .admitted);
            g.connClosed(client);
            g.connClosed(client);
            std.debug.assert(g.connCount(client) == 0);
        }
    }
    std.debug.print("12 benign clients cycled connections; tracked={d}\n", .{g.trackedCount()});

    // 2. One abusive client: strikes accumulate to `ban_threshold`. Offense
    // #1 greylists (not bans). While greylisted, repeated retries are all
    // denied the same way -- a scanner hammering the same door.
    const attacker = ip("198.51.100.7");
    g.record(attacker, 1);
    g.record(attacker, 1);
    std.debug.assert(!g.isGreylisted(attacker)); // 2 strikes < threshold 3
    g.record(attacker, 1); // 3rd strike: offense #1
    std.debug.assert(g.isGreylisted(attacker));
    std.debug.assert(!g.isBanned(attacker));
    var retry: usize = 0;
    while (retry < 3) : (retry += 1) {
        std.debug.assert(g.admit(attacker) == .greylisted); // retried, still denied
    }

    // 3. The greylist TTL expires (clock advanced, never slept): the client
    // is readmitted and its slot closes normally.
    fc.advanceMs(60_001);
    std.debug.assert(!g.isGreylisted(attacker));
    std.debug.assert(g.admit(attacker) == .admitted);
    g.connClosed(attacker);
    std.debug.print("attacker's greylist expired through the injected clock; readmitted\n", .{});

    // 4. The client offends again: the strike balance was reset at offense
    // #1, so a fresh run at the threshold is needed. Offense #2 crosses
    // `ban_after_offenses` and escalates to a *permanent* ban -- unlike the
    // greylist, a ban carries no TTL and time alone never lifts it.
    g.record(attacker, 3); // straight to the threshold
    std.debug.assert(g.isBanned(attacker));
    retry = 0;
    while (retry < 3) : (retry += 1) {
        std.debug.assert(g.admit(attacker) == .banned); // retried denial, stable
    }
    fc.advanceMs(10 * std.time.ms_per_min); // a ban never expires on its own
    std.debug.assert(g.admit(attacker) == .banned);
    std.debug.print("attacker escalated to a permanent ban; still denied after 10 min\n", .{});

    // 5. Only an explicit `unban` lifts a permanent ban -- full forgiveness:
    // clears the ban, the greylist, all strikes and the offense history.
    g.unban(attacker);
    std.debug.assert(!g.isBanned(attacker));
    std.debug.assert(g.admit(attacker) == .admitted);
    g.connClosed(attacker);
    std.debug.print("unban restored the attacker to a clean slate\n", .{});

    // 6. The per-IP cap held at its exact boundary, then recovers once a
    // slot is released. A cap rejection must not corrupt bookkeeping.
    {
        const busy = ip("203.0.113.50");
        std.debug.assert(g.admit(busy) == .admitted);
        std.debug.assert(g.admit(busy) == .admitted);
        std.debug.assert(g.admit(busy) == .admitted);
        std.debug.assert(g.admit(busy) == .per_ip_cap); // 4th over max_conns_per_ip=3
        g.connClosed(busy);
        std.debug.assert(g.admit(busy) == .admitted); // one freed slot -> readmitted
        std.debug.assert(g.connCount(busy) == 3);
        g.connClosed(busy);
        g.connClosed(busy);
        g.connClosed(busy);
        std.debug.assert(g.connCount(busy) == 0);
    }
    std.debug.print("per-IP cap held exactly at the boundary and recovered after release\n", .{});

    // 7. The global cap, kept distinct from the per-IP cap: two IPs each
    // fill their own per-IP allowance (3 + 3 = 6 of the total 8), then a
    // third IP is admitted twice more (8) before its third attempt is
    // rejected by `total_cap` specifically -- it is still well under its
    // own per-IP cap of 3.
    {
        const d = ip("203.0.113.51");
        const e = ip("203.0.113.52");
        const f = ip("203.0.113.53");
        var i: usize = 0;
        while (i < 3) : (i += 1) std.debug.assert(g.admit(d) == .admitted);
        i = 0;
        while (i < 3) : (i += 1) std.debug.assert(g.admit(e) == .admitted);
        std.debug.assert(g.totalConns() == 6);
        std.debug.assert(g.admit(f) == .admitted); // total 7
        std.debug.assert(g.admit(f) == .admitted); // total 8: exactly at max_conns_total
        std.debug.assert(g.admit(f) == .total_cap); // f itself is nowhere near its own cap
        std.debug.assert(g.connCount(f) == 2);

        g.connClosed(f); // total 7: one slot freed
        std.debug.assert(g.admit(f) == .admitted); // retried, admitted this time: total 8
        std.debug.assert(g.totalConns() == 8);

        i = 0;
        while (i < 3) : (i += 1) g.connClosed(d);
        i = 0;
        while (i < 3) : (i += 1) g.connClosed(e);
        i = 0;
        while (i < 2) : (i += 1) g.connClosed(f);
        std.debug.assert(g.totalConns() == 0);
    }
    std.debug.print("global cap held exactly at max_conns_total, independent of any single IP's own cap\n", .{});

    // 8. The `on_connect`/`on_conn_state` hook pair -- the actual shape a
    // real `http.Server` wires up. Same IP, two source ports: one entry,
    // one budget (the key is the IP alone, not the 4-tuple). Non-`.closed`
    // lifecycle states must never release a slot. Once both slots are
    // released, a further duplicate `.closed` (a retried/redelivered event)
    // is a no-op -- it must not underflow the counter.
    {
        const peer_a = try net.IpAddress.parseIp4("203.0.113.60", 1111);
        const peer_a2 = try net.IpAddress.parseIp4("203.0.113.60", 2222);
        const client_a = ip("203.0.113.60");

        std.debug.assert(g.onConnect()(g.onConnectCtx(), peer_a) == .accept);
        std.debug.assert(g.onConnect()(g.onConnectCtx(), peer_a2) == .accept);
        std.debug.assert(g.connCount(client_a) == 2);

        g.onConnState()(g.onConnStateCtx(), peer_a, .active);
        g.onConnState()(g.onConnStateCtx(), peer_a, .idle);
        std.debug.assert(g.connCount(client_a) == 2); // non-.closed states never release

        g.onConnState()(g.onConnStateCtx(), peer_a, .closed);
        std.debug.assert(g.connCount(client_a) == 1);
        g.onConnState()(g.onConnStateCtx(), peer_a2, .closed);
        std.debug.assert(g.connCount(client_a) == 0);
        g.onConnState()(g.onConnStateCtx(), peer_a, .closed); // duplicate/retried close
        std.debug.assert(g.connCount(client_a) == 0); // ignored, no underflow
    }
    std.debug.print("hook pair: same IP two ports share one budget; a duplicate close is a no-op\n", .{});

    // 9. A malformed peer literal, handled by name -- `net.IpAddress`'s own
    // parser is the fallible piece an on-the-wire peer address goes through
    // before it ever reaches the guard. `Guard`'s own admission surface has
    // no Zig error union to catch (allocator failure surfaces as the
    // `.store_full` verdict below, not an error -- see step 11), so this is
    // where "handle at least one error by name" has a real error to name.
    if (net.IpAddress.parseIp4("not-an-ip", 80)) |_| {
        return error.UnexpectedParseSuccess;
    } else |err| switch (err) {
        error.InvalidCharacter => std.debug.print(
            "malformed peer literal \"not-an-ip\" rejected: InvalidCharacter (expected)\n",
            .{},
        ),
        else => return err,
    }

    // 10. Genuine LRU eviction at a small `max_tracked_ips` (a dedicated,
    // tightly-bounded store -- distinct from step 1's tail-sweep of merely
    // *empty* entries). Strikes are given a nonzero, non-decaying balance
    // so entries stay non-empty and must be evicted by the real cap path
    // (`findEvictable`), not swept for being empty.
    {
        var g_bounded = abuseguard.Guard.init(gpa, .{
            .max_tracked_ips = 3,
            .ban_threshold = 100, // strikes only; never crosses into an offense here
            .strike_decay_ms = 0, // strikes persist -> entries stay non-empty
            .clock = fc.clock(),
        });
        defer g_bounded.deinit();

        g_bounded.record(ip("10.2.0.1"), 1);
        g_bounded.record(ip("10.2.0.2"), 1);
        g_bounded.record(ip("10.2.0.3"), 1);
        std.debug.assert(g_bounded.trackedCount() == 3);

        g_bounded.record(ip("10.2.0.1"), 1); // touch .1 -> .2 becomes the LRU tail
        g_bounded.record(ip("10.2.0.4"), 1); // at cap -> evicts .2, not the touched .1
        std.debug.assert(g_bounded.trackedCount() == 3);

        // .1 kept its accumulated strikes across the eviction pressure...
        g_bounded.record(ip("10.2.0.1"), 98); // 2 + 98 = 100 -> crosses ban_threshold
        std.debug.assert(g_bounded.isGreylisted(ip("10.2.0.1")));
        // ...while the evicted .2 starts over from zero (the price of eviction).
        g_bounded.record(ip("10.2.0.2"), 98);
        std.debug.assert(!g_bounded.isGreylisted(ip("10.2.0.2")));
    }
    std.debug.print("bounded store: LRU eviction at max_tracked_ips kept the touched entry, dropped the stale one\n", .{});

    // 11. The fail-closed OOM path: when the allocator backing new entry
    // tracking fails, `admit` returns `.store_full` instead of trapping --
    // an untrackable connection is refused, never admitted uncounted. This
    // is the module's error-partway-through-allocation contract; it
    // surfaces as a verdict, not a catchable error, which is why step 9
    // is where the "handle an error by name" convention is met instead.
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        var fc2: FakeClock = .{};
        var g2 = abuseguard.Guard.init(failing.allocator(), .{ .clock = fc2.clock() });
        defer g2.deinit();
        switch (g2.admit(ip("192.0.2.99"))) {
            .store_full => std.debug.print("OOM on entry tracking: store_full (fail-closed, as documented)\n", .{}),
            else => return error.UnexpectedVerdict,
        }
        std.debug.assert(g2.trackedCount() == 0);
        std.debug.assert(g2.totalConns() == 0);
    }

    std.debug.print("abuseguard example done; tracked={d} total_conns={d}\n", .{ g.trackedCount(), g.totalConns() });
}
