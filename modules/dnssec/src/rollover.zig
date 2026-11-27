// SPDX-License-Identifier: MIT
//! RFC 5011 automated trust-anchor rollover: the state machine a validating resolver runs over a zone's
//! secure-entry-point DNSKEYs to add a new anchor after a hold-down and to retire a revoked one.
//!
//! Pure state: no clock, no I/O, no persistence. The caller fetches the zone's apex DNSKEY RRset, validates it
//! (`chain.validateDnskeySet` against `Tracker.isTrusted` keys, which is what makes the observation
//! trustworthy), and hands the SEP keys it holds to `observe` together with `now`. The tracker answers which keys
//! are trust anchors (`isTrusted`, `trustedKeys`). Saving its state between runs is the caller's (`keys` is a plain
//! list of `TrackedKey`; `restore` puts one back).
//!
//! Rules implemented (RFC 5011 §2):
//!   * a SEP key not yet tracked and not revoked enters `add_pend` (§2.2); seen continuously for `add_hold_down`
//!     it becomes `valid` (§2.4.1); missing from the RRset while `add_pend` it is forgotten (the clock restarts if
//!     it reappears);
//!   * a `valid` key missing from the RRset becomes `missing` and stays trusted (§2.4.2), and is `valid` again when
//!     seen;
//!   * a key with the REVOKE bit set whose RRset also carries a signature by that key (`self_signed`) becomes
//!     `revoked` (§2.1) and is dropped after `remove_hold_down` (§2.4.3); a revoked `add_pend` key is dropped at
//!     once; a revoked key is never trusted again;
//!   * keys are identified by `(algorithm, public key)`, not by key tag (setting REVOKE changes the tag).
//!
//! RFC 5011 §2.4.1 sets the add hold-down to 30 days or the DNSKEY RRset's TTL if longer ("the longest of
//! 30 days ..."): pass the larger in `Options.add_hold_down`.

const std = @import("std");
const rdata = @import("rdata.zig");

pub const flag_revoke: u16 = 0x0080;

pub const State = enum { add_pend, valid, missing, revoked };

pub const Options = struct {
    /// Seconds a new key must be seen continuously before it is trusted (RFC 5011 §2.4.1: 30 days minimum).
    add_hold_down: u32 = 30 * 86400,
    /// Seconds a revoked key is remembered before it is dropped (§2.4.3).
    remove_hold_down: u32 = 30 * 86400,
};

/// One secure-entry-point key of a validated DNSKEY RRset, as `observe` takes it.
pub const Observed = struct {
    algorithm: u8,
    public_key: []const u8,
    /// The REVOKE bit (RFC 5011 §2.1) is set in this key's flags.
    revoked: bool = false,
    /// The RRset carries an RRSIG made by this very key (required for a revocation to count).
    self_signed: bool = false,

    /// From a parsed DNSKEY (`rdata.parseDnskey`); `self_signed` the caller's.
    pub fn fromDnskey(k: rdata.Dnskey, self_signed: bool) Observed {
        return .{ .algorithm = k.algorithm, .public_key = k.public_key, .revoked = k.flags & flag_revoke != 0, .self_signed = self_signed };
    }
};

pub const TrackedKey = struct {
    algorithm: u8,
    /// Owned by the tracker's allocator.
    public_key: []u8,
    state: State,
    /// When `state` was entered (`now` of the observation).
    since: u32,
};

pub const Tracker = struct {
    gpa: std.mem.Allocator,
    options: Options,
    keys: std.ArrayList(TrackedKey) = .empty,

    pub fn init(gpa: std.mem.Allocator, options: Options) Tracker {
        return .{ .gpa = gpa, .options = options };
    }

    pub fn deinit(self: *Tracker) void {
        for (self.keys.items) |k| self.gpa.free(k.public_key);
        self.keys.deinit(self.gpa);
    }

    /// Put a configured trust anchor (or one saved by an earlier run) in place, already `valid`.
    pub fn restore(self: *Tracker, algorithm: u8, public_key: []const u8, state: State, since: u32) std.mem.Allocator.Error!void {
        const pk = try self.gpa.dupe(u8, public_key);
        errdefer self.gpa.free(pk);
        try self.keys.append(self.gpa, .{ .algorithm = algorithm, .public_key = pk, .state = state, .since = since });
    }

    fn find(self: *const Tracker, algorithm: u8, public_key: []const u8) ?*TrackedKey {
        for (self.keys.items) |*k| {
            if (k.algorithm == algorithm and std.mem.eql(u8, k.public_key, public_key)) return k;
        }
        return null;
    }

    /// Whether the key is a trust anchor now: `valid`, or `missing` (a once-valid key that is absent from the
    /// current RRset stays trusted until it is revoked, RFC 5011 §2.4.2).
    pub fn isTrusted(self: *const Tracker, algorithm: u8, public_key: []const u8) bool {
        const k = self.find(algorithm, public_key) orelse return false;
        return k.state == .valid or k.state == .missing;
    }

    /// The state of a tracked key, or null.
    pub fn stateOf(self: *const Tracker, algorithm: u8, public_key: []const u8) ?State {
        return if (self.find(algorithm, public_key)) |k| k.state else null;
    }

    /// Number of keys currently trusted.
    pub fn trustedCount(self: *const Tracker) usize {
        var n: usize = 0;
        for (self.keys.items) |k| n += @intFromBool(k.state == .valid or k.state == .missing);
        return n;
    }

    /// Advance the state machine with the SEP keys of a DNSKEY RRset that the caller validated against
    /// `isTrusted` keys, as of `now` (seconds, monotone across calls). Keys not in `observed` are treated as
    /// absent from the RRset.
    pub fn observe(self: *Tracker, now: u32, observed: []const Observed) std.mem.Allocator.Error!void {
        // Existing keys.
        var i: usize = 0;
        while (i < self.keys.items.len) {
            const k = &self.keys.items[i];
            const o: ?Observed = for (observed) |c| {
                if (c.algorithm == k.algorithm and std.mem.eql(u8, c.public_key, k.public_key)) break c;
            } else null;
            var drop = false;
            if (o) |seen| {
                if (seen.revoked) {
                    if (seen.self_signed and k.state != .revoked) {
                        if (k.state == .add_pend) {
                            drop = true;
                        } else {
                            k.state = .revoked;
                            k.since = now;
                        }
                    }
                } else switch (k.state) {
                    .add_pend => if (elapsed(now, k.since) >= self.options.add_hold_down) {
                        k.state = .valid;
                        k.since = now;
                    },
                    .missing => {
                        k.state = .valid;
                        k.since = now;
                    },
                    .valid, .revoked => {},
                }
            } else switch (k.state) {
                .add_pend => drop = true,
                .valid => {
                    k.state = .missing;
                    k.since = now;
                },
                .missing, .revoked => {},
            }
            if (k.state == .revoked and elapsed(now, k.since) >= self.options.remove_hold_down) drop = true;
            if (drop) {
                self.gpa.free(k.public_key);
                _ = self.keys.orderedRemove(i);
            } else i += 1;
        }
        // New keys.
        for (observed) |c| {
            if (c.revoked or self.find(c.algorithm, c.public_key) != null) continue;
            try self.restore(c.algorithm, c.public_key, .add_pend, now);
        }
    }
};

fn elapsed(now: u32, since: u32) u32 {
    return if (now >= since) now - since else 0;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const day: u32 = 86400;

fn key(pk: []const u8) Observed {
    return .{ .algorithm = 13, .public_key = pk };
}

test "a new SEP key is trusted only after the add hold-down, seen continuously" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "old", .valid, 0);
    try t.observe(100 * day, &.{ key("old"), key("new") });
    try testing.expectEqual(State.add_pend, t.stateOf(13, "new").?);
    try testing.expect(!t.isTrusted(13, "new"));
    try t.observe(129 * day, &.{ key("old"), key("new") });
    try testing.expect(!t.isTrusted(13, "new"));
    try t.observe(130 * day, &.{ key("old"), key("new") });
    try testing.expectEqual(State.valid, t.stateOf(13, "new").?);
    try testing.expect(t.isTrusted(13, "new"));
    try testing.expectEqual(@as(usize, 2), t.trustedCount());
}

test "an add_pend key that disappears is forgotten and its hold-down restarts" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "old", .valid, 0);
    try t.observe(100 * day, &.{ key("old"), key("new") });
    try t.observe(115 * day, &.{key("old")});
    try testing.expectEqual(@as(?State, null), t.stateOf(13, "new"));
    try t.observe(120 * day, &.{ key("old"), key("new") });
    try t.observe(149 * day, &.{ key("old"), key("new") });
    try testing.expect(!t.isTrusted(13, "new"));
    try t.observe(150 * day, &.{ key("old"), key("new") });
    try testing.expect(t.isTrusted(13, "new"));
}

test "a valid key missing from the RRset stays trusted and is valid again when seen" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "a", .valid, 0);
    try t.observe(10 * day, &.{key("b")});
    try testing.expectEqual(State.missing, t.stateOf(13, "a").?);
    try testing.expect(t.isTrusted(13, "a"));
    try t.observe(20 * day, &.{ key("a"), key("b") });
    try testing.expectEqual(State.valid, t.stateOf(13, "a").?);
}

test "a self-signed revocation retires the key after the remove hold-down; an unsigned one does nothing" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "a", .valid, 0);
    try t.restore(13, "b", .valid, 0);
    try t.observe(10 * day, &.{
        .{ .algorithm = 13, .public_key = "a", .revoked = true, .self_signed = false },
        .{ .algorithm = 13, .public_key = "b", .revoked = true, .self_signed = true },
    });
    try testing.expectEqual(State.valid, t.stateOf(13, "a").?);
    try testing.expectEqual(State.revoked, t.stateOf(13, "b").?);
    try testing.expect(!t.isTrusted(13, "b"));
    // A revoked key cannot be un-revoked by a later unrevoked sighting.
    try t.observe(20 * day, &.{ key("a"), key("b") });
    try testing.expectEqual(State.revoked, t.stateOf(13, "b").?);
    try t.observe(40 * day, &.{key("a")});
    try testing.expectEqual(@as(?State, null), t.stateOf(13, "b"));
}

test "a revoked add_pend key is dropped at once, a revoked unknown key is ignored, keys are identified by algorithm and key" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.observe(0, &.{key("x")});
    try t.observe(day, &.{.{ .algorithm = 13, .public_key = "x", .revoked = true, .self_signed = true }});
    try testing.expectEqual(@as(?State, null), t.stateOf(13, "x"));
    try t.observe(2 * day, &.{.{ .algorithm = 13, .public_key = "never", .revoked = true, .self_signed = true }});
    try testing.expectEqual(@as(usize, 0), t.keys.items.len);
    try t.observe(3 * day, &.{.{ .algorithm = 8, .public_key = "k" }});
    try testing.expectEqual(@as(?State, null), t.stateOf(13, "k"));
    try testing.expectEqual(State.add_pend, t.stateOf(8, "k").?);
}

test "mutation 2026-11-25: fromDnskey reads the REVOKE bit and keeps self_signed" {
    const k: rdata.Dnskey = .{ .flags = 0x0181, .protocol = 3, .algorithm = 13, .public_key = "k" };
    const o = Observed.fromDnskey(k, true);
    try testing.expect(o.revoked and o.self_signed);
    const o2 = Observed.fromDnskey(.{ .flags = 0x0101, .protocol = 3, .algorithm = 13, .public_key = "k" }, false);
    try testing.expect(!o2.revoked and !o2.self_signed);
}

test "mutation 2026-11-25: restore frees its copy when the append fails" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    var t = Tracker.init(fa.allocator(), .{});
    defer t.deinit();
    try testing.expectError(error.OutOfMemory, t.restore(13, "key", .valid, 0));
}

test "mutation 2026-11-25: since is stamped at every transition; a valid key is never aged out; missing keys count as trusted" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "old", .valid, 0);
    // 100 days in: `old` (valid since day 0, far past the remove hold-down) stays trusted.
    try t.observe(100 * day, &.{ key("old"), key("new") });
    try testing.expect(t.isTrusted(13, "old"));
    try testing.expectEqual(State.add_pend, t.stateOf(13, "new").?);
    // add_pend -> valid stamps the promotion time.
    try t.observe(130 * day, &.{ key("old"), key("new") });
    try testing.expectEqual(State.valid, t.stateOf(13, "new").?);
    try testing.expectEqual(130 * day, t.find(13, "new").?.since);
    // valid -> missing stamps; a missing key is trusted and counted.
    try t.observe(140 * day, &.{key("old")});
    try testing.expectEqual(State.missing, t.stateOf(13, "new").?);
    try testing.expectEqual(140 * day, t.find(13, "new").?.since);
    try testing.expectEqual(@as(usize, 2), t.trustedCount());
    // missing -> valid stamps.
    try t.observe(150 * day, &.{ key("old"), key("new") });
    try testing.expectEqual(State.valid, t.stateOf(13, "new").?);
    try testing.expectEqual(150 * day, t.find(13, "new").?.since);
}

test "mutation 2026-11-25: a key is identified by algorithm AND bytes" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "k", .valid, 0);
    // Same bytes under another algorithm is another key: the algorithm-13 key is absent from the RRset.
    try t.observe(5 * day, &.{.{ .algorithm = 14, .public_key = "k" }});
    try testing.expectEqual(State.missing, t.stateOf(13, "k").?);
    try testing.expectEqual(State.add_pend, t.stateOf(14, "k").?);
}

test "mutation 2026-11-25: a revoked key's hold-down runs from the first revocation, the state is kept, order survives the drop, a backwards clock never promotes" {
    var t = Tracker.init(testing.allocator, .{});
    defer t.deinit();
    try t.restore(13, "a", .valid, 0);
    try t.restore(13, "b", .valid, 0);
    try t.restore(13, "c", .valid, 0);
    const revoked_a: Observed = .{ .algorithm = 13, .public_key = "a", .revoked = true, .self_signed = true };
    try t.observe(100 * day, &.{ revoked_a, key("b"), key("c") });
    // Revoked, stamped now, not dropped at once although it is valid since day 0.
    try testing.expectEqual(State.revoked, t.stateOf(13, "a").?);
    try testing.expectEqual(100 * day, t.find(13, "a").?.since);
    // A second sighting of the revocation does not restart the hold-down.
    try t.observe(110 * day, &.{ revoked_a, key("b"), key("c") });
    try testing.expectEqual(100 * day, t.find(13, "a").?.since);
    try t.observe(129 * day, &.{ revoked_a, key("b"), key("c") });
    try testing.expect(t.stateOf(13, "a") != null);
    try t.observe(130 * day, &.{ revoked_a, key("b"), key("c") });
    try testing.expect(t.stateOf(13, "a") == null);
    // The drop keeps the order of the others.
    try testing.expectEqual(@as(usize, 2), t.keys.items.len);
    try testing.expectEqualStrings("b", t.keys.items[0].public_key);
    try testing.expectEqualStrings("c", t.keys.items[1].public_key);

    // A clock that went backwards (now < since) counts as no time elapsed, not as 2^32 seconds.
    try t.observe(200 * day, &.{ key("b"), key("c"), key("n") });
    try t.observe(50 * day, &.{ key("b"), key("c"), key("n") });
    try testing.expectEqual(State.add_pend, t.stateOf(13, "n").?);
}
