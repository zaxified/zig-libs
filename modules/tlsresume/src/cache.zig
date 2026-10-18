// SPDX-License-Identifier: MIT

//! tlsresume.cache — a bounded stateful session cache, the OpenSSL server
//! session-cache shape (`SSL_CTX_sess_set_cache_size`, session timeout) for
//! TLS 1.2 session-ID resumption and for stateful TLS 1.3 PSK identities
//! (identity = cache id, state kept server-side instead of in a STEK blob).
//!
//! Fixed-size entries (`max_id_len` + `max_state_len` bytes), one allocation
//! at `init`, none per entry. **Single owner, no internal locking** (like
//! `StekRing`): wrap in the caller's lock to share it.
//!
//! Complexity: lookup, `put` and `remove` are O(capacity) linear scans; the
//! simplest correct design, and the id compare is constant-time per slot
//! (session ids are bearer secrets) which a hash map would not give for free.
//! Eviction at capacity drops the OLDEST entry by insertion order (a replace
//! counts as a fresh insertion). No clock inside: callers pass `now_s`.

const std = @import("std");

/// A session cache holding ids up to `max_id_len` bytes and state blobs up to
/// `max_state_len` bytes.
pub fn SessionCache(comptime max_id_len: usize, comptime max_state_len: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            used: bool = false,
            /// Monotonic insertion sequence; the smallest used one is the oldest.
            seq: u64 = 0,
            stored_at_s: i64 = 0,
            id_len: usize = 0,
            state_len: usize = 0,
            id: [max_id_len]u8 = undefined,
            state: [max_state_len]u8 = undefined,
        };

        entries: []Entry,
        gpa: std.mem.Allocator,
        timeout_s: i64,
        next_seq: u64 = 0,
        used_count: usize = 0,

        /// Allocate `capacity` (>= 1) entries. An entry is valid while
        /// `now_s - stored_at_s < timeout_s`.
        pub fn init(gpa: std.mem.Allocator, capacity: usize, timeout_s: i64) !Self {
            std.debug.assert(capacity >= 1);
            const entries = try gpa.alloc(Entry, capacity);
            for (entries) |*e| e.* = .{};
            return .{ .entries = entries, .gpa = gpa, .timeout_s = timeout_s };
        }

        /// Wipe all state and ids with `secureZero` and free the storage.
        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.entries));
            self.gpa.free(self.entries);
            self.* = undefined;
        }

        fn wipe(e: *Entry) void {
            std.crypto.secureZero(u8, std.mem.asBytes(e));
            e.* = .{};
        }

        fn find(self: *Self, id: []const u8) ?*Entry {
            var hit: ?*Entry = null;
            // Scan every slot (no early exit on a match): constant-time per
            // compare, and equal-length ids only.
            for (self.entries) |*e| {
                if (!e.used or e.id_len != id.len) continue;
                if (std.crypto.timing_safe.eql([max_id_len]u8, padded(e.id[0..e.id_len]), padded(id))) hit = e;
            }
            return hit;
        }

        fn padded(id: []const u8) [max_id_len]u8 {
            var p = @as([max_id_len]u8, @splat(0));
            @memcpy(p[0..id.len], id);
            return p;
        }

        fn expired(self: *const Self, e: *const Entry, now_s: i64) bool {
            return now_s - e.stored_at_s >= self.timeout_s;
        }

        /// Store `state` under `id`, replacing an existing entry with that id
        /// (the replacement becomes the newest). When full, the oldest entry
        /// (insertion order) is evicted and wiped; capacity never fails.
        pub fn put(self: *Self, id: []const u8, state: []const u8, now_s: i64) error{ IdTooLong, StateTooLarge }!void {
            if (id.len > max_id_len) return error.IdTooLong;
            if (state.len > max_state_len) return error.StateTooLarge;
            var slot: ?*Entry = self.find(id);
            if (slot == null) {
                var oldest: ?*Entry = null;
                for (self.entries) |*e| {
                    if (!e.used) {
                        slot = e;
                        break;
                    }
                    if (oldest == null or e.seq < oldest.?.seq) oldest = e;
                }
                if (slot == null) slot = oldest;
                if (!slot.?.used) self.used_count += 1;
            }
            const e = slot.?;
            wipe(e);
            e.used = true;
            e.seq = self.next_seq;
            self.next_seq += 1;
            e.stored_at_s = now_s;
            e.id_len = id.len;
            e.state_len = state.len;
            @memcpy(e.id[0..id.len], id);
            @memcpy(e.state[0..state.len], state);
        }

        /// Copy the state stored under `id` into `out` and return the filled
        /// slice. `null` if absent, expired (an expired entry is removed and
        /// wiped), or `out` is shorter than the state (the entry is kept).
        /// Not single-use: for TLS 1.3 0-RTT use `take`.
        pub fn get(self: *Self, id: []const u8, now_s: i64, out: []u8) ?[]u8 {
            return self.lookup(id, now_s, out, false);
        }

        /// Like `get` but removes (and wipes) the entry on success: single-use
        /// redemption, as TLS 1.3 0-RTT / anti-replay requires (RFC 8446
        /// §8.1: a PSK accepted for early data must be usable once). If `out`
        /// is too small the entry is kept.
        pub fn take(self: *Self, id: []const u8, now_s: i64, out: []u8) ?[]u8 {
            return self.lookup(id, now_s, out, true);
        }

        fn lookup(self: *Self, id: []const u8, now_s: i64, out: []u8, consume: bool) ?[]u8 {
            if (id.len > max_id_len) return null;
            const e = self.find(id) orelse return null;
            if (self.expired(e, now_s)) {
                wipe(e);
                self.used_count -= 1;
                return null;
            }
            if (out.len < e.state_len) return null;
            const n = e.state_len;
            @memcpy(out[0..n], e.state[0..n]);
            if (consume) {
                wipe(e);
                self.used_count -= 1;
            }
            return out[0..n];
        }

        /// Remove and wipe the entry for `id`, if any.
        pub fn remove(self: *Self, id: []const u8) void {
            if (id.len > max_id_len) return;
            if (self.find(id)) |e| {
                wipe(e);
                self.used_count -= 1;
            }
        }

        /// Number of stored entries (expired ones count until touched).
        pub fn count(self: *const Self) usize {
            return self.used_count;
        }
    };
}

const testing = std.testing;
const C = SessionCache(8, 16);

test "put/get round trip, replace keeps one entry" {
    var c = try C.init(testing.allocator, 4, 100);
    defer c.deinit();
    var out: [16]u8 = undefined;
    try c.put("id1", "state-a", 0);
    try testing.expectEqualSlices(u8, "state-a", c.get("id1", 1, &out).?);
    try c.put("id1", "state-b", 2);
    try testing.expectEqual(@as(usize, 1), c.count());
    try testing.expectEqualSlices(u8, "state-b", c.get("id1", 3, &out).?);
    try testing.expect(c.get("id2", 3, &out) == null);
    try testing.expect(c.get("id", 3, &out) == null); // prefix is not a match
}

test "timeout boundary, expired entry is removed" {
    var c = try C.init(testing.allocator, 4, 100);
    defer c.deinit();
    var out: [16]u8 = undefined;
    try c.put("a", "s", 10);
    try testing.expect(c.get("a", 10 + 99, &out) != null);
    try testing.expect(c.get("a", 10 + 100, &out) == null);
    try testing.expectEqual(@as(usize, 0), c.count());
}

test "eviction of the oldest at capacity" {
    var c = try C.init(testing.allocator, 2, 1000);
    defer c.deinit();
    var out: [16]u8 = undefined;
    try c.put("a", "1", 0);
    try c.put("b", "2", 1);
    try c.put("a", "1x", 2); // replace: a is now the newest, b the oldest
    try c.put("c", "3", 3); // full -> evicts b
    try testing.expectEqual(@as(usize, 2), c.count());
    try testing.expect(c.get("b", 4, &out) == null);
    try testing.expect(c.get("a", 4, &out) != null);
    try testing.expect(c.get("c", 4, &out) != null);
}

test "take is single-use; get is not" {
    var c = try C.init(testing.allocator, 2, 1000);
    defer c.deinit();
    var out: [16]u8 = undefined;
    try c.put("a", "xyz", 0);
    try testing.expect(c.get("a", 1, &out) != null);
    try testing.expect(c.get("a", 1, &out) != null);
    try testing.expectEqualSlices(u8, "xyz", c.take("a", 1, &out).?);
    try testing.expect(c.take("a", 1, &out) == null);
    try testing.expectEqual(@as(usize, 0), c.count());
}

test "IdTooLong / StateTooLarge / out too small / remove" {
    var c = try C.init(testing.allocator, 2, 1000);
    defer c.deinit();
    try testing.expectError(error.IdTooLong, c.put("123456789", "s", 0));
    try testing.expectError(error.StateTooLarge, c.put("a", "01234567890123456", 0));
    try c.put("a", "0123456789", 0);
    var tiny: [4]u8 = undefined;
    try testing.expect(c.get("a", 1, &tiny) == null);
    try testing.expect(c.take("a", 1, &tiny) == null);
    try testing.expectEqual(@as(usize, 1), c.count()); // kept
    c.remove("a");
    c.remove("zz");
    try testing.expectEqual(@as(usize, 0), c.count());
}

test "ids of different length with equal prefix do not collide; empty id works" {
    var c = try C.init(testing.allocator, 4, 1000);
    defer c.deinit();
    var out: [16]u8 = undefined;
    try c.put("ab", "1", 0);
    try c.put("ab\x00", "2", 0);
    try c.put("", "3", 0);
    try testing.expectEqual(@as(usize, 3), c.count());
    try testing.expectEqualSlices(u8, "1", c.get("ab", 1, &out).?);
    try testing.expectEqualSlices(u8, "2", c.get("ab\x00", 1, &out).?);
    try testing.expectEqualSlices(u8, "3", c.get("", 1, &out).?);
}
