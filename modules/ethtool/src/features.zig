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
//! *diff* bitsets, both masked by the request's own mask:
//!
//! * `wanted` — bits that were requested **on** but are not active afterwards;
//! * `active` — bits that are active afterwards despite being requested **off**.
//!
//! A bit set in either one is a change the kernel did not honour — the same
//! thing `ethtool -K` prints under "Actual changes:". `SetResult.fullyHonoured`
//! is that test; `SetResult` keeps both diffs so a caller can say *which* bits.
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
        const b = a.byName(name) orelse return null;
        return b.value;
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

/// The decoded `FEATURES_SET_REPLY`. Both bitsets are *diffs* — see the file
/// header. Owns its allocations.
pub const SetResult = struct {
    device: header.Device = .{},
    /// Requested **on**, not active afterwards.
    wanted_diff: ?bitset.Bitset = null,
    /// Active afterwards despite being requested **off**.
    active_diff: ?bitset.Bitset = null,

    pub fn deinit(r: *SetResult, gpa: std.mem.Allocator) void {
        if (r.wanted_diff) |*b| b.deinit(gpa);
        if (r.active_diff) |*b| b.deinit(gpa);
        r.* = .{};
    }

    /// True when the kernel did exactly what was asked. A `FEATURES_SET` that
    /// ACKs but returns false here changed less than the caller requested.
    pub fn fullyHonoured(r: SetResult) bool {
        const w = if (r.wanted_diff) |b| b.count() else 0;
        const a = if (r.active_diff) |b| b.count() else 0;
        return w == 0 and a == 0;
    }

    /// How many requested bits were not honoured (both directions summed).
    pub fn unhonouredCount(r: SetResult) u32 {
        const w = if (r.wanted_diff) |b| b.count() else 0;
        const a = if (r.active_diff) |b| b.count() else 0;
        return w + a;
    }

    /// Was this specific feature honoured? Only answerable by name when the
    /// reply used verbose bitsets (the default — do not set
    /// `compact_bitsets` on a SET if you want names back).
    pub fn honouredByName(r: SetResult, name: []const u8) bool {
        if (r.wanted_diff) |b| {
            if (b.byName(name)) |bit| {
                if (bit.value) return false;
            }
        }
        if (r.active_diff) |b| {
            if (b.byName(name)) |bit| {
                if (bit.value) return false;
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
            if (out.wanted_diff != null) return error.BadLength;
            out.wanted_diff = try bitset.parse(gpa, a.data);
        },
        uapi.FEATURES.ACTIVE => {
            if (out.active_diff != null) return error.BadLength;
            out.active_diff = try bitset.parse(gpa, a.data);
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

test "SET reply: an empty diff means fully honoured" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.FEATURES.HEADER, .{ .target = .byIndex(2) });
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.WANTED, 32, &.{0}, &.{0b1000});
    try bitset.appendCompact(gpa, &list, uapi.FEATURES.ACTIVE, 32, &.{0}, &.{0b1000});

    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(r.fullyHonoured());
    try testing.expectEqual(@as(u32, 0), r.unhonouredCount());
}

test "SET reply: a partially honoured change is reported, not swallowed" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // The caller asked for tso on and rx-checksum off; the kernel kept tso off
    // (it appears in the `wanted` diff) and rx-checksum on (`active` diff).
    try bitset.appendNamedValues(gpa, &list, uapi.FEATURES.WANTED, &.{
        .{ .name = "tx-tcp-segmentation", .on = true },
    });
    try bitset.appendNamedValues(gpa, &list, uapi.FEATURES.ACTIVE, &.{
        .{ .name = "rx-checksum", .on = true },
    });

    var r = try parseSetResult(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(!r.fullyHonoured());
    try testing.expectEqual(@as(u32, 2), r.unhonouredCount());
    try testing.expect(!r.honouredByName("tx-tcp-segmentation"));
    try testing.expect(!r.honouredByName("rx-checksum"));
    try testing.expect(r.honouredByName("tx-scatter-gather")); // never mentioned
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
