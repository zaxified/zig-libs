// SPDX-License-Identifier: MIT
//! Netdev feature flags: `FEATURES_GET` and `FEATURES_SET` — the one place in
//! this family where "the request succeeded" and "the change happened" are
//! genuinely different things, so this module refuses to conflate them.
//!
//! ## The four bitsets of a GET reply
//!
//! | bitset | meaning |
//! |---|---|
//! | `hw` | what the device can do at all (value = capable, mask = known) |
//! | `wanted` | what userspace has asked for |
//! | `active` | what is actually in effect right now |
//! | `nochange` | bits that cannot be changed on this device |
//!
//! `wanted` and `active` differ whenever a feature was requested but the stack
//! could not turn it on — e.g. TSO asked for while checksum offload is off. The
//! kernel does not report that as an error; it silently keeps `active` clear.
//!
//! ## Why a SET needs its reply read
//!
//! `FEATURES_SET` **always ACKs**, whether or not the requested bits took
//! effect. The truth is in the `FEATURES_SET_REPLY` message, which carries two
//! *diff* bitsets. Both are (value, mask) pairs and the **mask is the
//! interesting half**:
//!
//! | reply attribute | mask means | value means |
//! |---|---|---|
//! | `ETHTOOL_A_FEATURES_WANTED` | this bit's result differs from what was requested | what was requested |
//! | `ETHTOOL_A_FEATURES_ACTIVE` | this bit's active state actually changed | its new state |
//!
//! So a non-empty `WANTED` mask is the "you did not get what you asked for"
//! signal, and the `ACTIVE` mask is "here is what really moved". That mapping
//! is not guesswork: `goldens.zig` carries two real `FEATURES_SET_REPLY`
//! messages captured with CAP_NET_ADMIN inside `unshare -rn` — one fully
//! honoured (empty `WANTED` mask) and one where four of five requested bits
//! were refused (`WANTED` mask = exactly those four, `ACTIVE` mask = the one
//! that did move).
//!
//! Counting *set value bits* would be the wrong test — a feature requested
//! **off** and refused has a clear value bit and a set mask bit — which is why
//! `SetResult` uses `Bitset.maskCount`, not `Bitset.count`.
//!
//! `ethtool -K` prints exactly this under "Actual changes:".
//!
//! Note the interaction with `ETHTOOL_FLAG_OMIT_REPLY`: setting it suppresses
//! the reply entirely, and with it any chance of knowing what stuck. This
//! module never sets that flag behind a caller's back.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = bitset.Error;

/// `ETHTOOL_MSG_FEATURES_GET` reply. Owns its bitsets — free with `deinit`.
pub const Features = struct {
    device: header.Device = .{},
    hw: ?bitset.Bitset = null,
    wanted: ?bitset.Bitset = null,
    active: ?bitset.Bitset = null,
    nochange: ?bitset.Bitset = null,

    pub fn deinit(f: *Features, gpa: std.mem.Allocator) void {
        inline for (.{ "hw", "wanted", "active", "nochange" }) |name| {
            if (@field(f, name)) |*b| b.deinit(gpa);
        }
        f.* = .{};
    }

    /// Is the named feature in effect? Null when this reply's bitsets carry no
    /// names — i.e. when the request asked for compact bitsets. With compact
    /// bitsets, resolve names once via `stringSet(.features)` and use
    /// `isActiveAt`.
    pub fn isActive(f: Features, name: []const u8) ?bool {
        const a = f.active orelse return null;
        return a.isSetByName(name);
    }

    pub fn isActiveAt(f: Features, index: u32) bool {
        const a = f.active orelse return false;
        return a.isSet(index);
    }

    /// Can this device do the feature at all?
    pub fn isSupportedAt(f: Features, index: u32) bool {
        const h = f.hw orelse return false;
        return h.isSet(index);
    }

    /// Is the feature pinned — asked for but impossible to change?
    pub fn isFixedAt(f: Features, index: u32) bool {
        const n = f.nochange orelse return false;
        return n.isSet(index);
    }
};

pub fn parse(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Features {
    var out: Features = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.FEATURES.HEADER => out.device = try header.parse(a.data),
        uapi.FEATURES.HW => {
            if (out.hw != null) return error.BadLength;
            out.hw = try bitset.parse(gpa, a.data);
        },
        uapi.FEATURES.WANTED => {
            if (out.wanted != null) return error.BadLength;
            out.wanted = try bitset.parse(gpa, a.data);
        },
        uapi.FEATURES.ACTIVE => {
            if (out.active != null) return error.BadLength;
            out.active = try bitset.parse(gpa, a.data);
        },
        uapi.FEATURES.NOCHANGE => {
            if (out.nochange != null) return error.BadLength;
            out.nochange = try bitset.parse(gpa, a.data);
        },
        else => {},
    };
    return out;
}

/// Append the `ETHTOOL_A_FEATURES_WANTED` bitset of a `FEATURES_SET` request,
/// keyed by the kernel's feature names ("tx-tcp-segmentation", "rx-checksum",
/// …). Name-keyed because that is what `ethtool -K` does and because feature
/// bit numbers are not a stable ABI — they shift as `netdev_features_t` grows.
pub fn appendSetByName(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    entries: []const bitset.NamedValue,
) Error!void {
    try bitset.appendNamedValues(gpa, list, uapi.FEATURES.WANTED, entries);
}

/// Same, keyed by bit index — for a caller that already read indices out of a
/// GET reply on this same kernel.
pub fn appendSetByIndex(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    entries: []const bitset.IndexedValue,
) Error!void {
    try bitset.appendIndexedValues(gpa, list, uapi.FEATURES.WANTED, entries);
}

/// The decoded `FEATURES_SET_REPLY`. Both bitsets are *diffs* whose mask half
/// carries the meaning — see the file header. Owns its allocations.
pub const SetResult = struct {
    device: header.Device = .{},
    /// Requested changes the kernel did **not** honour. `inMask(i)` = bit `i`'s
    /// resulting state differs from what was requested; `isSet(i)` = what was
    /// requested for it.
    unhonoured: ?bitset.Bitset = null,
    /// Features whose active state actually **changed**. `inMask(i)` = it
    /// changed; `isSet(i)` = its new state.
    changed: ?bitset.Bitset = null,

    pub fn deinit(r: *SetResult, gpa: std.mem.Allocator) void {
        if (r.unhonoured) |*b| b.deinit(gpa);
        if (r.changed) |*b| b.deinit(gpa);
        r.* = .{};
    }

    /// True when the kernel did exactly what was asked. A `FEATURES_SET` that
    /// ACKs but returns false here changed less than the caller requested.
    pub fn fullyHonoured(r: SetResult) bool {
        return r.unhonouredCount() == 0;
    }

    /// How many requested bits were not honoured.
    pub fn unhonouredCount(r: SetResult) u32 {
        const b = r.unhonoured orelse return 0;
        return b.maskCount();
    }

    /// How many features actually changed state.
    pub fn changedCount(r: SetResult) u32 {
        const b = r.changed orelse return 0;
        return b.maskCount();
    }

    /// Was this specific feature bit honoured?
    pub fn honouredAt(r: SetResult, index: u32) bool {
        const b = r.unhonoured orelse return true;
        return !b.inMask(index);
    }

    /// The feature's new active state, or null when it did not change.
    pub fn newStateAt(r: SetResult, index: u32) ?bool {
        const b = r.changed orelse return null;
        if (!b.inMask(index)) return null;
        return b.isSet(index);
    }

    /// Same as `honouredAt`, by name. Only answerable when the reply used
    /// verbose bitsets — `ethtool` itself asks for compact ones here, so a
    /// caller that wants names must not set `compact_bitsets` on the SET.
    pub fn honouredByName(r: SetResult, name: []const u8) bool {
        const b = r.unhonoured orelse return true;
        const bits = b.bits orelse return true;
        for (bits) |bit| {
            if (bit.name) |n| {
                if (std.mem.eql(u8, n, name)) return false;
            }
        }
        return true;
    }
};

/// Decode a `FEATURES_SET_REPLY`. Deliberately a different type from
/// `Features`: the attributes are the same numbers but mean diffs, and reusing
/// `Features` here would invite reading `active` as "what is on now".
pub fn parseSetResult(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!SetResult {
    var out: SetResult = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.FEATURES.HEADER => out.device = try header.parse(a.data),
        uapi.FEATURES.WANTED => {
            if (out.unhonoured != null) return error.BadLength;
            out.unhonoured = try bitset.parse(gpa, a.data);
        },
        uapi.FEATURES.ACTIVE => {
            if (out.changed != null) return error.BadLength;
            out.changed = try bitset.parse(gpa, a.data);
        },
        else => {},
    };
    return out;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "GET reply: the four bitsets keep their separate meanings" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.FEATURES.HEADER, .{ .target = .byIndex(2) });
    // hw: bits 0..3 known, 0/1/3 capable. wanted: 0 and 3. active: only 0.
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.HW, 32, &.{0b1011}, &.{0b1111});
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.WANTED, 32, &.{0b1001}, null);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{0b0001}, null);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.NOCHANGE, 32, &.{0b0100}, null);

    var f = try parse(gpa, list.items);
    defer f.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), f.device.index);
    try testing.expect(f.isSupportedAt(1));
    try testing.expect(!f.isSupportedAt(2));
    // Bit 3 was wanted but is not active — the silent-failure case.
    try testing.expect(f.wanted.?.isSet(3));
    try testing.expect(!f.isActiveAt(3));
    try testing.expect(f.isActiveAt(0));
    try testing.expect(f.isFixedAt(2));
    // No names in a compact reply.
    try testing.expect(f.isActive("rx-checksum") == null);
}

test "GET reply: verbose bitsets answer by name" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendNamedValues(gpa, &list, uapi.FEATURES.ACTIVE, &.{
        .{ .name = "rx-checksum", .on = true },
        .{ .name = "tx-tcp-segmentation", .on = false },
    });
    var f = try parse(gpa, list.items);
    defer f.deinit(gpa);
    try testing.expectEqual(@as(?bool, true), f.isActive("rx-checksum"));
    try testing.expectEqual(@as(?bool, false), f.isActive("tx-tcp-segmentation"));
    try testing.expect(f.isActive("no-such-feature") == null);
}

test "SET reply: an empty unhonoured mask means fully honoured" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.FEATURES.HEADER, .{ .target = .byIndex(2) });
    // Nothing refused; one bit (3) changed, to off.
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.WANTED, 32, &.{0}, &.{0});
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{0}, &.{0b1000});

    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(r.fullyHonoured());
    try testing.expectEqual(@as(u32, 0), r.unhonouredCount());
    try testing.expectEqual(@as(u32, 1), r.changedCount());
    try testing.expectEqual(@as(?bool, false), r.newStateAt(3));
    try testing.expect(r.newStateAt(4) == null); // untouched
    try testing.expect(r.honouredAt(3));
}

test "SET reply: a refused change is reported even though its value bit is 0" {
    // The trap `Bitset.count` would fall into: a feature requested **off** and
    // refused has a clear *value* bit and a set *mask* bit. Counting set values
    // would call that a success.
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.WANTED, 32, &.{0}, &.{0b0100});
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{0}, &.{0});

    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(!r.fullyHonoured());
    try testing.expectEqual(@as(u32, 1), r.unhonouredCount());
    try testing.expectEqual(@as(u32, 0), r.changedCount());
    try testing.expect(!r.honouredAt(2));
    try testing.expect(r.honouredAt(3));
}

test "SET reply: a partially honoured change is reported, not swallowed" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Requested bits 1 and 2 on; only 2 took effect.
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.WANTED, 32, &.{0b0010}, &.{0b0010});
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{0b0100}, &.{0b0100});

    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(!r.fullyHonoured());
    try testing.expectEqual(@as(u32, 1), r.unhonouredCount());
    try testing.expect(!r.honouredAt(1));
    try testing.expect(r.honouredAt(2));
    try testing.expectEqual(@as(?bool, true), r.newStateAt(2));
    try testing.expect(r.newStateAt(1) == null); // asked for, never moved
}

test "SET reply: a verbose reply answers by name" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendNamedValues(gpa, &list, uapi.FEATURES.WANTED, &.{
        .{ .name = "tx-tcp-segmentation", .on = true },
    });
    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(!r.honouredByName("tx-tcp-segmentation"));
    try testing.expect(r.honouredByName("rx-gro")); // never mentioned
}

test "SET request encodes the -K shape: named bits, no NOMASK" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSetByName(gpa, &list, &.{.{ .name = "tx-tcp-segmentation", .on = false }});

    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(uapi.FEATURES.WANTED, a.type);
    var bs = try bitset.parse(gpa, a.data);
    defer bs.deinit(gpa);
    // Masked, not a list: bits nobody named must stay untouched.
    try testing.expect(!bs.nomask);
    try testing.expect(!bs.byName("tx-tcp-segmentation").?.value);
}

test "duplicate feature bitsets are a malformed reply, not a leak" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.HW, 32, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.HW, 32, &.{1}, null);
    try testing.expectError(error.BadLength, parse(gpa, list.items));

    list.clearRetainingCapacity();
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{1}, null);
    try testing.expectError(error.BadLength, parseSetResult(gpa, list.items));
}

test "a truncated feature reply is a typed error" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, parse(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    try testing.expectError(error.Truncated, parseSetResult(gpa, &.{ 0x40, 0x00, 0x03, 0x00, 1 }));
}
