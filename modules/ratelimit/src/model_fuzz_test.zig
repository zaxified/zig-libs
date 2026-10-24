// SPDX-License-Identifier: MIT

//! Model-fuzz for `Limiter`: seeded random operation sequences (weighted
//! `allowNAt` on a handful of keys, `setConfigAt` mid-flight, time jumps
//! from 0 to past the refill time) against an EXACT integer model of a
//! keyed token bucket store, compared after every operation:
//!  - the decision (`allowed`) exactly; `remaining`, `retry_after_ms` and
//!    `reset_after_ms` exactly too, except one step of float rounding where
//!    the exact value sits on an integer boundary (see `near`);
//!  - `keyCount()` exactly — so second-chance eviction at `max_keys` and
//!    the idle-TTL sweep are held to the documented policy: a hit only marks
//!    the key used; the hand at the queue's end evicts the first key not
//!    used since it last passed (a used one is rotated to the front,
//!    unmarked); a key expires only when it has been idle longer than BOTH
//!    `ttl_ms` and its refill time (`burst / rate`), i.e. only when its
//!    bucket is full anyway, and the sweep stops at a live unused key.
//!    Decisions (which key kept its drained bucket) catch a wrong victim.
//! The model shares no code with the module: balances are integers in
//! 1/8000-token units, rates are `num/den` with `den` a power of two up to
//! 8 and times whole milliseconds, so every refill is exact. The float
//! implementation can only disagree on an exact tie (balance == n after an
//! inexact refill); the generator steps the clock 1 ms past such a tie
//! instead of guessing a side. Reservations and cancels are held to the
//! reference itself by the replayed x/time/rate traces (xrate_ops_vectors).

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

const unit: i64 = 8000; // model units per token
const ns_per_ms = std.time.ns_per_ms;

const Rate = struct {
    num: u32,
    den: u32, // 1, 2, 4 or 8

    fn f(r: Rate) f64 {
        return @as(f64, @floatFromInt(r.num)) / @as(f64, @floatFromInt(r.den));
    }
    /// Model units gained per millisecond: num/den tokens/s * 8000 / 1000.
    fn perMs(r: Rate) i64 {
        return @divExact(@as(i64, r.num) * 8, @as(i64, r.den));
    }
};

const MKey = struct {
    name: u8,
    bal: i64, // model units
    last_ms: u64,
    /// The implementation's float balance equals `bal` exactly (fresh, full
    /// or capped since its last inexact refill).
    exact: bool,
    referenced: bool = false,
};

const Model = struct {
    rate: Rate,
    burst: u32,
    ttl_ms: u64,
    max_keys: usize,
    /// The eviction queue: index 0 is the front, the hand at the end.
    keys: std.ArrayList(MKey) = .empty,

    fn cap(m: *const Model) i64 {
        return @as(i64, m.burst) * unit;
    }

    /// Advance a key to `t` at the current rate; cap at the current burst.
    fn advance(m: *const Model, k: *MKey, t: u64) void {
        if (t > k.last_ms) {
            const gained = @as(i64, @intCast(t - k.last_ms)) * m.rate.perMs();
            k.bal += gained;
            k.last_ms = t;
            if (gained > 0) k.exact = false;
        }
        if (k.bal >= m.cap()) {
            k.bal = m.cap();
            k.exact = true;
        }
    }

    fn expired(m: *const Model, k: MKey, t: u64) bool {
        if (m.ttl_ms == 0) return false;
        const idle = t -| k.last_ms;
        return idle > m.ttl_ms and @as(i64, @intCast(idle)) * m.rate.perMs() > m.cap();
    }

    fn find(m: *Model, name: u8) ?usize {
        for (m.keys.items, 0..) |k, i| if (k.name == name) return i;
        return null;
    }

    /// Pass the hand over the last key: unmark it, move it to the front.
    fn rotate(m: *Model, gpa: std.mem.Allocator) !void {
        var k = m.keys.pop().?;
        k.referenced = false;
        try m.keys.insert(gpa, 0, k);
    }

    /// The key's index after the store's lookup at `t` (marked used; created
    /// full at the front, after the sweep and the cap, when new).
    fn lookup(m: *Model, gpa: std.mem.Allocator, name: u8, t: u64, reach: *Reach) !usize {
        if (m.find(name)) |i| {
            m.keys.items[i].referenced = true;
            return i;
        }
        if (m.ttl_ms != 0) {
            var budget = m.keys.items.len;
            while (budget > 0 and m.keys.items.len > 0) : (budget -= 1) {
                const tail = m.keys.items[m.keys.items.len - 1];
                if (m.expired(tail, t)) {
                    _ = m.keys.pop();
                    reach.swept += 1;
                } else if (tail.referenced) {
                    try m.rotate(gpa);
                    reach.rotated += 1;
                } else break;
            }
        }
        if (m.keys.items.len >= m.max_keys) {
            while (m.keys.items[m.keys.items.len - 1].referenced) {
                try m.rotate(gpa);
                reach.rotated += 1;
            }
            _ = m.keys.pop();
            reach.evicted += 1;
        }
        try m.keys.insert(gpa, 0, .{ .name = name, .bal = m.cap(), .last_ms = t, .exact = true });
        return 0;
    }
};

/// Whole milliseconds for `units` to accrue at `per_ms`, rounded up; `ok`
/// also accepts one more when the exact value is a whole number (the float
/// path may land a hair above it and round up).
fn ceilDiv(units: i64, per_ms: i64) u64 {
    return @intCast(@divFloor(units + per_ms - 1, per_ms));
}

fn near(got: u64, want: u64, tie: bool) bool {
    return got == want or (tie and got == want + 1);
}

fn nearDown(got: u32, want: u32, tie: bool) bool {
    return got == want or (tie and want > 0 and got == want - 1);
}

const Reach = struct {
    allowed: usize = 0,
    denied: usize = 0,
    over_burst: usize = 0,
    evicted: usize = 0,
    swept: usize = 0,
    rotated: usize = 0,
    ttl_held: usize = 0, // idle past ttl_ms, but not past the refill time
    reconfig: usize = 0,
    ties: usize = 0,
};

test "model-fuzz: Limiter decisions, LRU and idle TTL vs an exact integer model" {
    const seed: u64 = 0x726174656c6d3031;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const gpa = testing.allocator;
    const dens = [_]u32{ 1, 2, 4, 8 };
    var reach: Reach = .{};

    var case: usize = 0;
    while (case < 300) : (case += 1) {
        var m: Model = .{
            .rate = .{ .num = 1 + rnd.uintLessThan(u32, 40), .den = dens[rnd.uintLessThan(usize, dens.len)] },
            .burst = 1 + rnd.uintLessThan(u32, 8),
            .ttl_ms = switch (rnd.uintLessThan(u8, 4)) {
                0 => 0,
                1 => 1 + rnd.uintLessThan(u64, 50),
                else => 1 + rnd.uintLessThan(u64, 5000),
            },
            .max_keys = 1 + rnd.uintLessThan(usize, 6),
        };
        defer m.keys.deinit(gpa);
        var l = root.Limiter.init(gpa, .{
            .rate_per_s = m.rate.f(),
            .burst = m.burst,
            .ttl_ms = m.ttl_ms,
            .max_keys = m.max_keys,
            .key = .forwarded_ip,
        });
        defer l.deinit();

        var t: u64 = 0;
        var op: usize = 0;
        while (op < 150) : (op += 1) {
            t += switch (rnd.uintLessThan(u8, 8)) {
                0, 1 => 0,
                2, 3, 4 => rnd.uintLessThan(u64, 200),
                5, 6 => rnd.uintLessThan(u64, 3000),
                // Past any refill time here: burst 8 at 1/8 per s is 64 s.
                else => rnd.uintLessThan(u64, 70_000),
            };
            if (rnd.uintLessThan(u8, 25) == 0) {
                // Reconfigure: the model advances every key at the old
                // config first, exactly what setConfigAt promises.
                const new_rate: ?Rate = if (rnd.boolean()) .{ .num = 1 + rnd.uintLessThan(u32, 40), .den = dens[rnd.uintLessThan(usize, dens.len)] } else null;
                const new_burst: ?u32 = if (new_rate == null or rnd.boolean()) 1 + rnd.uintLessThan(u32, 8) else null;
                for (m.keys.items) |*k| m.advance(k, t);
                if (new_rate) |r| m.rate = r;
                if (new_burst) |b| m.burst = b;
                l.setConfigAt(if (new_rate) |r| r.f() else null, new_burst, t * ns_per_ms);
                reach.reconfig += 1;
                continue;
            }

            const name: u8 = 'a' + rnd.uintLessThan(u8, 8);
            const n: u32 = rnd.uintLessThan(u32, m.burst + 2);
            const need = @as(i64, n) * unit;

            // Step past an exact tie the float path could see either side of.
            if (m.find(name)) |i| {
                var probe = m.keys.items[i];
                while (true) {
                    if (m.expired(probe, t)) break;
                    var p = probe;
                    m.advance(&p, t);
                    if (p.exact or p.bal != need) break;
                    t += 1;
                    reach.ties += 1;
                    probe = m.keys.items[i];
                }
            }

            for (m.keys.items) |k| {
                if (m.ttl_ms != 0 and t -| k.last_ms > m.ttl_ms and !m.expired(k, t)) reach.ttl_held += 1;
            }
            const idx = try m.lookup(gpa, name, t, &reach);
            const k = &m.keys.items[idx];
            m.advance(k, t);
            const allowed = n <= m.burst and k.bal >= need;
            if (allowed) k.bal -= need;
            // Exactness after the decision: subtracting a whole token count
            // is exact in f64; the flag carries over.
            const tie_floor = !k.exact and @mod(k.bal, unit) == 0;
            const want_remaining: u32 = if (k.bal <= 0) 0 else @intCast(@divFloor(k.bal, unit));

            const d = l.allowNAt(&.{name}, n, t * ns_per_ms);
            var bad = d.allowed != allowed or !nearDown(d.remaining, want_remaining, tie_floor);
            if (!allowed) {
                if (n > m.burst) {
                    bad = bad or d.retry_after_ms != std.math.maxInt(u64);
                    reach.over_burst += 1;
                } else {
                    const short = need - k.bal;
                    const per = m.rate.perMs();
                    bad = bad or !near(d.retry_after_ms, ceilDiv(short, per), @mod(short, per) == 0);
                }
                reach.denied += 1;
            } else reach.allowed += 1;
            const to_full = m.cap() - k.bal;
            const per = m.rate.perMs();
            bad = bad or !near(d.reset_after_ms, ceilDiv(to_full, per), @mod(to_full, per) == 0);
            bad = bad or l.keyCount() != m.keys.items.len;
            if (bad) {
                std.debug.print(
                    "ratelimit model-fuzz mismatch: seed=0x{x} case={d} op={d} t={d}ms key={c} n={d} rate={d}/{d} burst={d} ttl={d} max_keys={d}\n" ++
                        "  got  allowed={} remaining={d} retry={d} reset={d} keys={d}\n" ++
                        "  want allowed={} remaining={d} bal={d}/8000 keys={d}\n",
                    .{ seed, case, op, t, name, n, m.rate.num, m.rate.den, m.burst, m.ttl_ms, m.max_keys, d.allowed, d.remaining, d.retry_after_ms, d.reset_after_ms, l.keyCount(), allowed, want_remaining, k.bal, m.keys.items.len },
                );
                return error.TestUnexpectedResult;
            }
        }
    }
    // Every rule the model holds was exercised.
    try testing.expect(reach.allowed > 1000 and reach.denied > 1000 and reach.over_burst > 100);
    try testing.expect(reach.evicted > 100 and reach.swept > 100 and reach.rotated > 100 and reach.ttl_held > 100);
    try testing.expect(reach.reconfig > 500);
}
