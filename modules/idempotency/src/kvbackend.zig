// SPDX-License-Identifier: MIT

//! `KvBackend` — a durable `Backend` for `Store` over a caller-owned
//! `kv.Db`. Records are written with `kv.Db.putTtl` (fsync'd before `put`
//! returns, expiry on kv's wall clock, so a record keeps its deadline across
//! a restart); a retry that arrives after the process crashed or restarted
//! is still answered from the record instead of running the side effect
//! again — the gap an in-process `ramcache` store leaves.
//!
//! Reservations stay in memory: they protect one process's concurrent
//! first-flights, and a process that dies takes its handlers with it. The
//! `kv` file is single-process (its own exclusive lock), so this backend is
//! durable, not shared; a store shared by several processes is a backend of
//! the same interface over a shared database.
//!
//! ```zig
//! var db = try kv.Db.open(gpa, fs.storage(), "idempotency.kv", .{});
//! defer db.close();
//! var kb = idempotency.KvBackend{ .db = &db, .gpa = gpa };
//! defer kb.deinit();
//! var store = idempotency.Store{ .backend = kb.backend(), .ttl_ns = 24 * std.time.ns_per_hour };
//! defer store.deinit();
//! ```
//!
//! A record lives while its age is under the TTL (kv's `now < expires_at`,
//! whole ms rounded up); the `ramcache` store keeps it through age == TTL.
//!
//! No lock is held across `kv` I/O: the reservation is taken first (under a
//! short spinlock), then the record is read. A same-key request that arrives
//! during that read sees the reservation and gets 409 rather than the
//! replay — a retry later replays. A `kv` read error answers `.in_flight`
//! (fail closed: never a second run); a failed `putTtl` (kv poisoned, disk
//! full) loses the record, which only means a later retry runs again — the
//! same best-effort contract as `Store.record`.

const std = @import("std");
const kv = @import("kv");
const root = @import("root.zig");
const Backend = root.Backend;
const Allocator = std.mem.Allocator;

pub const KvBackend = struct {
    db: *kv.Db,
    /// Owns the reservation keys and is `Backend.gpa` for the `Store`.
    gpa: Allocator,
    lock: std.atomic.Mutex = .unlocked,
    /// Reserved key -> the `now` it was reserved at (for `lease_ns`).
    in_flight: std.StringHashMapUnmanaged(i64) = .empty,
    /// Counters for tests and monitoring (read without the lock: advisory).
    read_errors: u64 = 0,
    write_errors: u64 = 0,

    pub fn backend(self: *KvBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable, .gpa = self.gpa };
    }

    pub fn deinit(self: *KvBackend) void {
        var it = self.in_flight.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.in_flight.deinit(self.gpa);
        self.* = undefined;
    }

    const vtable: Backend.VTable = .{
        .lookupOrReserve = lookupOrReserve,
        .put = put,
        .release = release,
    };

    fn cast(ptr: *anyopaque) *KvBackend {
        return @ptrCast(@alignCast(ptr));
    }

    fn acquire(self: *KvBackend) void {
        while (!self.lock.tryLock()) std.atomic.spinLoopHint();
    }

    fn lookupOrReserve(ptr: *anyopaque, key: []const u8, now: i64, lease_ns: i64, gpa: Allocator) Allocator.Error!Backend.Lookup {
        const self = cast(ptr);
        {
            self.acquire();
            defer self.lock.unlock();
            if (self.in_flight.getPtr(key)) |since| {
                // A lease that ran out hands the key to this request; the
                // stale holder's `release` then frees it early, which the
                // lease already allowed.
                if (lease_ns <= 0 or now - since.* < lease_ns) return .in_flight;
                since.* = now;
            } else {
                const owned = try self.gpa.dupe(u8, key);
                errdefer self.gpa.free(owned);
                try self.in_flight.put(self.gpa, owned, now);
            }
        }
        const value = self.db.get(gpa, key) catch |err| switch (err) {
            error.OutOfMemory => {
                release(ptr, key);
                return error.OutOfMemory;
            },
            else => {
                // Fail closed: an unreadable record must not become a run.
                _ = @atomicRmw(u64, &self.read_errors, .Add, 1, .monotonic);
                release(ptr, key);
                return .in_flight;
            },
        };
        if (value) |v| {
            release(ptr, key);
            return .{ .found = v };
        }
        return .reserved;
    }

    fn put(ptr: *anyopaque, key: []const u8, blob: []const u8, now: i64, ttl_ns: i64) void {
        _ = now;
        const self = cast(ptr);
        // kv's expiry is in whole milliseconds on its wall clock; round up so
        // a record never expires before `ttl_ns`.
        // `ttl_ns <= 0` = no expiry, as for the `ramcache` store.
        const result = if (ttl_ns <= 0)
            self.db.put(key, blob)
        else
            self.db.putTtl(key, blob, @intCast(@divFloor(ttl_ns - 1, std.time.ns_per_ms) + 1));
        result catch {
            _ = @atomicRmw(u64, &self.write_errors, .Add, 1, .monotonic);
        };
    }

    fn release(ptr: *anyopaque, key: []const u8) void {
        const self = cast(ptr);
        self.acquire();
        defer self.lock.unlock();
        if (self.in_flight.fetchRemove(key)) |e| self.gpa.free(e.key);
    }
};
