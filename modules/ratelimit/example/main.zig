// SPDX-License-Identifier: MIT

//! What an API-gateway consumer does with `ratelimit`: run the per-key
//! request `Limiter` and the per-user `ConnectionLimiter` through a
//! realistic multi-client lifecycle, under `std.heap.DebugAllocator` so any
//! leak in eviction, TTL expiry, capacity-bound insertion or the documented
//! fail-open OOM path shows up here — the class of defect this repo has
//! actually hit (`cbor.encodeMap` leaked on every canonical encode while its
//! own arena-backed test suite stayed green).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const ratelimit = @import("ratelimit");
const netaddr = @import("netaddr");
const http = @import("http");

/// A deterministic clock a caller controls — the module never reads the wall
/// clock on its own, it only offers `Clock.monotonic` as a default. Mirrors
/// the `TestClock` idiom the module's own tests use, built here from public
/// surface only (`Clock{ .ctx, .nowFn }`).
const FakeClock = struct {
    ns: u64 = 0,

    fn clock(fc: *FakeClock) ratelimit.Clock {
        return .{ .ctx = fc, .nowFn = nowFn };
    }
    fn nowFn(ctx: ?*anyopaque) u64 {
        const fc: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return fc.ns;
    }
    fn advanceMs(fc: *FakeClock, ms: u64) void {
        fc.ns += ms * std.time.ns_per_ms;
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── Part 1: the request Limiter — many distinct clients, a small
    // capacity bound, and idle expiry all in play at once ──────────────────
    {
        var fc: FakeClock = .{};
        var limiter = ratelimit.Limiter.init(gpa, .{
            .rate_per_s = 1,
            .burst = 3,
            .max_keys = 4, // tight cap: forces LRU eviction below
            .ttl_ms = 5_000,
            .clock = fc.clock(),
            .key = .forwarded_ip,
        });
        defer limiter.deinit();

        // Realistic traffic: eight distinct clients, several requests each —
        // not one call per key.
        const clients = [_][]const u8{
            "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
            "203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8",
        };
        var total_allowed: u32 = 0;
        for (clients) |c| {
            for (0..2) |_| {
                if (limiter.allowAt(c, fc.ns).allowed) total_allowed += 1;
            }
        }
        std.debug.assert(total_allowed > 0);
        // Eight distinct keys hit a 4-key cap: the table never grows past it.
        std.debug.assert(limiter.keyCount() <= 4);
        std.debug.print("part1: {d} distinct clients, table capped at {d} keys\n", .{ clients.len, limiter.keyCount() });

        // One client exhausts its own burst and is denied — draining a fresh
        // key with more requests than its burst allows.
        const heavy = "198.51.100.9";
        var allowed_for_heavy: u32 = 0;
        var denied_for_heavy = false;
        for (0..5) |_| {
            const d = limiter.allowAt(heavy, fc.ns);
            if (d.allowed) allowed_for_heavy += 1 else denied_for_heavy = true;
        }
        std.debug.assert(allowed_for_heavy == 3); // exactly the burst
        std.debug.assert(denied_for_heavy);
        std.debug.print("part1: heavy client got {d}/5, denied past burst\n", .{allowed_for_heavy});

        // A retried/duplicate request while still denied: the retry itself
        // must not further drain or otherwise corrupt the bucket.
        const retry1 = limiter.allowAt(heavy, fc.ns);
        const retry2 = limiter.allowAt(heavy, fc.ns);
        std.debug.assert(!retry1.allowed and !retry2.allowed);
        std.debug.assert(retry1.retry_after_ms == retry2.retry_after_ms);

        // Time advances by exactly the reported wait: the window refills and
        // the next attempt is admitted, per the module's documented
        // "waiting retry_after_ms guarantees the next attempt passes".
        fc.advanceMs(retry2.retry_after_ms);
        const after_wait = limiter.allowAt(heavy, fc.ns);
        std.debug.assert(after_wait.allowed);
        std.debug.print("part1: after waiting retry_after_ms, heavy client passes again\n", .{});

        // Idle-expiry pressure: let every currently-tracked key sit past the
        // TTL, then confirm a hit on an expired key resets it to a full
        // bucket rather than staying (incorrectly) exhausted or erroring.
        fc.advanceMs(6_000); // > ttl_ms
        const revived = limiter.allowAt(heavy, fc.ns);
        std.debug.assert(revived.allowed);
        std.debug.assert(revived.remaining == 2); // full burst (3) minus this one
        std.debug.print("part1: idle key past TTL resets to a full bucket\n", .{});
    }

    // ── Part 2: fail-open under allocator exhaustion — an error return
    // partway through tracking a new key must not become a denial ─────────
    {
        var fc: FakeClock = .{};
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        var limiter = ratelimit.Limiter.init(failing.allocator(), .{
            .rate_per_s = 1,
            .burst = 1,
            .clock = fc.clock(),
            .key = .forwarded_ip,
        });
        defer limiter.deinit();

        // The very first insert fails allocation; the module's documented
        // policy is fail-open (never turn OOM into an outage), not a crash
        // and not a silent leak of a half-built entry.
        const d = limiter.allowAt("192.0.2.50", fc.ns);
        std.debug.assert(d.allowed);
        std.debug.assert(limiter.keyCount() == 0); // never got tracked
        std.debug.print("part2: allocator exhaustion on a new key still admits (fail-open)\n", .{});
    }

    // ── Part 3: the per-user ConnectionLimiter — configured users share one
    // bucket across their prefixes, unlisted addresses hit a bounded table ─
    {
        var fc: FakeClock = .{};
        const users = [_]ratelimit.ConnUser{
            .{
                .name = "acme",
                .prefixes = &.{netaddr.parsePrefix("192.0.2.0/24").?},
                .rate_per_s = 4,
                .burst = 4,
            },
        };
        var cl = try ratelimit.ConnectionLimiter.init(gpa, .{
            .users = &users,
            .rate_per_s = 1,
            .burst = 2,
            .max_unlisted_keys = 3, // tight cap: forces unlisted eviction
            .unlisted_ttl_ms = 0,
            .clock = fc.clock(),
        });
        defer cl.deinit();

        // The configured user's whole burst, spread across two addresses of
        // its prefix (both share one bucket) — then denied past it.
        var user_allowed: u32 = 0;
        var user_denied = false;
        for ([_][]const u8{ "192.0.2.7", "192.0.2.200", "192.0.2.7", "192.0.2.9", "192.0.2.7" }) |txt| {
            const d = cl.allowPeerAt(netaddr.parseIp(txt).?, fc.ns);
            if (d.allowed) user_allowed += 1 else user_denied = true;
        }
        std.debug.assert(user_allowed == 4);
        std.debug.assert(user_denied);
        std.debug.print("part3: configured user got {d}/5 across two addresses, denied past burst\n", .{user_allowed});

        // A dual-stack listener's mapped spelling of the SAME address must
        // land on the SAME (already-drained) bucket — bucket identity, not
        // `.allowed` alone (a fresh bucket would allow a stranger too).
        const mapped = cl.allowPeerAt(netaddr.parseIp("::ffff:192.0.2.7").?, fc.ns);
        std.debug.assert(!mapped.allowed);

        // Unlisted-table pressure: more distinct strangers than
        // `max_unlisted_keys` — the table must stay bounded via LRU
        // eviction, exactly the pressure path `ConnectionLimiter` exists to
        // survive without unbounded memory growth.
        const strangers = [_][]const u8{ "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5" };
        for (strangers) |txt| _ = cl.allowPeerAt(netaddr.parseIp(txt).?, fc.ns);
        std.debug.assert(cl.unlistedKeyCount() <= 3);
        std.debug.print("part3: {d} distinct unlisted strangers, table capped at {d}\n", .{ strangers.len, cl.unlistedKeyCount() });

        // Time advances: the configured user's bucket refills and passes
        // again (default fake clock never touches the real one).
        fc.advanceMs(1_000);
        std.debug.assert(cl.allowPeerAt(netaddr.parseIp("192.0.2.7").?, fc.ns).allowed);

        // The `on_connect` hook shape itself: assignable to the http.Server
        // seam without a shim, and returns the accept/reject enum it wraps.
        const hook: http.Server.OnConnectFn = ratelimit.ConnectionLimiter.onConnect;
        const peer: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 1234 } };
        const decision = hook(&cl, peer);
        std.debug.assert(decision == .accept or decision == .reject);
        std.debug.print("part3: on_connect hook wired to http.Server.OnConnectFn, decision={s}\n", .{@tagName(decision)});
    }

    // ── Part 4: ConnectionLimiter.init itself can fail allocation — handle
    // the error by name rather than let it propagate unnamed ──────────────
    {
        var fc: FakeClock = .{};
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        const users = [_]ratelimit.ConnUser{
            .{ .name = "acme", .prefixes = &.{netaddr.parsePrefix("192.0.2.0/24").?} },
        };
        const result = ratelimit.ConnectionLimiter.init(failing.allocator(), .{
            .users = &users,
            .clock = fc.clock(),
        });
        if (result) |_| {
            unreachable; // the first allocation (user_buckets) was made to fail
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("part4: ConnectionLimiter.init under OOM: error.OutOfMemory (expected)\n", .{}),
        }
    }
}
