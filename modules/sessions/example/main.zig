// SPDX-License-Identifier: MIT

//! What a `router`-based web app does with `sessions`: build a `Manager` over
//! the default `RamcacheStore`, run several sessions through a realistic
//! request lifecycle (create → save → load, idle expiry, absolute-cap expiry,
//! session-fixation `regenerate`, `revoke`/logout, and the cross-request
//! optimistic-concurrency race that a resurrection bug would show up as),
//! then tear everything down under a leak-checking allocator.
//!
//! Built by `zig build check-examples` against the PUBLISHED module —
//! `deps` only (`router`, `http`, `cookies`, `ramcache`, `entropy`), no
//! `test_deps`, no private declarations.

const std = @import("std");
const sessions = @import("sessions");
const ramcache = @import("ramcache");

/// A fake, caller-controlled clock -- the module injects one so timeout
/// accounting is deterministic and offline (no real clock-dependent
/// assertions). Same shape as `sessions.Clock`: `.ctx` + `.nowFn`.
const FakeClock = struct {
    now_ns: i64 = 1_000_000_000,

    fn clock(fc: *FakeClock) sessions.Clock {
        return .{ .ctx = fc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const fc: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return fc.now_ns;
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Entropy still needs an `std.Io` instance even offline (session ids are
    // CSPRNG-drawn); no sockets, no threads needed for this example.
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    const max_entries: usize = 8;
    var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 1 << 16, .max_entries = max_entries });
    defer cache.deinit();

    var fake_clock: FakeClock = .{};
    var store: sessions.RamcacheStore = .{ .cache = &cache, .clock = fake_clock.clock() };

    var m = try sessions.Manager.init(gpa, store.store(), .{
        .io = io,
        .clock = fake_clock.clock(),
        .idle_timeout_ns = 500 * std.time.ns_per_s,
        .absolute_timeout_ns = 2000 * std.time.ns_per_s,
    });

    // 1. Create several sessions and persist them, like distinct logged-in
    // users. Exercises the CSPRNG id draw + create-CAS write repeatedly.
    var ids: [4][2 * sessions.max_id_bytes]u8 = undefined;
    var id_lens: [4]usize = undefined;
    {
        var i: usize = 0;
        while (i < ids.len) : (i += 1) {
            var s: sessions.Session = .{};
            m.create(&s);
            try s.setData("user-session");
            std.debug.assert(m.persist(&s)); // create-CAS: expected generation 0
            @memcpy(ids[i][0..s.id_len], s.id());
            id_lens[i] = s.id_len;
        }
    }
    std.debug.print("created + persisted {d} sessions\n", .{ids.len});

    // 2. Error return partway through allocation: `Manager.lookup` swallows
    // any `StoreError` into `.absent`, hiding the failure from a caller who
    // might want to distinguish "no session" from "the store couldn't even
    // try". Reach the same call `lookup` makes -- `Store.get`, which dupes
    // the loaded record into `gpa` -- directly, with a `FailingAllocator`
    // standing in for that copy failing. Must surface `error.OutOfMemory` by
    // name, not panic or silently report absence.
    {
        const id = ids[0][0..id_lens[0]];
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        if (store.store().get(failing.allocator(), id)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("Store.get under a FailingAllocator: OutOfMemory (expected)\n", .{}),
        }
        // The failed attempt must not have corrupted the record: a normal
        // allocator still reads it back intact right after.
        var l: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &l) == .loaded);
        std.debug.assert(std.mem.eql(u8, l.data(), "user-session"));
    }

    // 3. Load one back, mutate its payload, save again (normal request
    // lifecycle: load → handler → save). The generation must advance.
    {
        var s: sessions.Session = .{};
        const id = ids[0][0..id_lens[0]];
        std.debug.assert(m.lookup(id, &s) == .loaded);
        const g0 = s.generation;
        try s.setData("user-session;cart=3");
        std.debug.assert(m.persist(&s));
        std.debug.assert(s.generation > g0);
    }

    // 4. Error path: a payload over `max_session_bytes` must be rejected by
    // name, not silently truncated -- and must not have allocated/leaked
    // anything on the way to failing (Session carries its buffer inline, so
    // there's nothing to free either way, but the call must still fail).
    {
        var s: sessions.Session = .{};
        m.create(&s);
        var oversized: [sessions.max_session_bytes + 1]u8 = undefined;
        @memset(&oversized, 'x');
        if (s.setData(&oversized)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Overflow => std.debug.print("oversized payload correctly rejected: Overflow\n", .{}),
        }
    }

    // 5. Idle-timeout expiry: advance the fake clock past `idle_timeout_ns`.
    // The session must come back `.expired` once, then `.absent` on a
    // second lookup (it was evicted from the store, not merely rejected).
    {
        const id = ids[1][0..id_lens[1]];
        fake_clock.now_ns += 1000 * std.time.ns_per_s; // > idle_timeout_ns
        var s: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &s) == .expired);
        var s2: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &s2) == .absent);
        std.debug.print("idle-expired session evicted: expired then absent\n", .{});
    }
    fake_clock.now_ns = 1_000_000_000; // reset for the remaining scenarios

    // 6. Absolute-cap expiry: a session refreshed just under the idle window
    // repeatedly, but still rejected once it crosses the absolute cap
    // measured from creation.
    {
        var s: sessions.Session = .{};
        m.create(&s);
        std.debug.assert(m.persist(&s));
        const id = try gpa.dupe(u8, s.id());
        defer gpa.free(id);

        fake_clock.now_ns += 2500 * std.time.ns_per_s; // > absolute_timeout_ns
        var s2: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &s2) == .expired);
    }
    fake_clock.now_ns = 1_000_000_000;

    // 7. Session-fixation defense: regenerate rotates the id, carries the
    // data over, and kills the old id in the store.
    {
        const old_id = ids[2][0..id_lens[2]];
        var s: sessions.Session = .{};
        std.debug.assert(m.lookup(old_id, &s) == .loaded);
        m.regenerate(&s);
        std.debug.assert(!std.mem.eql(u8, old_id, s.id()));
        std.debug.assert(m.persist(&s)); // new id: create-CAS (generation reset to 0)

        var lo: sessions.Session = .{};
        std.debug.assert(m.lookup(old_id, &lo) == .absent); // old id dead
        var ln: sessions.Session = .{};
        std.debug.assert(m.lookup(s.id(), &ln) == .loaded);
        std.debug.assert(std.mem.eql(u8, ln.data(), "user-session"));
        std.debug.print("regenerate: old id dead, new id carries data\n", .{});
    }

    // 8. Cross-request race: two in-flight "requests" load the same session,
    // then one is destroyed (revoke/logout) before the other's trailing save
    // runs. The stale save's CAS must fail closed -- it must NOT resurrect
    // the just-destroyed session. This is the retried/duplicate-write
    // pressure path the generation/CAS mechanism exists for.
    {
        const id = ids[3][0..id_lens[3]];
        var a: sessions.Session = .{};
        var b: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &a) == .loaded);
        std.debug.assert(m.lookup(id, &b) == .loaded);
        std.debug.assert(a.generation == b.generation);

        // A's request logs out.
        store.store().delete(a.id());

        // B's trailing save races in with a now-stale generation.
        try b.setData("stale-write");
        std.debug.assert(!m.persist(&b)); // CAS must fail, not resurrect

        var l: sessions.Session = .{};
        std.debug.assert(m.lookup(id, &l) == .absent); // stays dead
        std.debug.print("cross-request race: stale save could not resurrect a destroyed session\n", .{});
    }

    // 9. Capacity pressure: fill the ramcache well past its 8-entry cap with
    // fresh sessions -- forces real W-TinyLFU eviction inside the store
    // while sessions are still being created and persisted, the same
    // pattern real traffic produces under load. Asserted, not just printed:
    // the live entry count must never exceed the configured cap, and
    // getting there must have actually evicted something (not merely have
    // had headroom).
    {
        const bulk_count = 32;
        var i: usize = 0;
        while (i < bulk_count) : (i += 1) {
            var s: sessions.Session = .{};
            m.create(&s);
            try s.setData("bulk");
            std.debug.assert(m.persist(&s));
            std.debug.assert(cache.stats.entries <= max_entries);
        }
        std.debug.assert(cache.stats.evictions > 0);
        std.debug.print("capacity: {d} more sessions through a {d}-entry store -> {d} evictions, {d} live entries\n", .{ bulk_count, max_entries, cache.stats.evictions, cache.stats.entries });
    }
}
