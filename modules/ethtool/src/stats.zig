// SPDX-License-Identifier: MIT
//! Statistics: `STATS_GET` (the standardised, grouped counters) and
//! `STRSET_GET` (the kernel's string tables, which is how those counters — and
//! feature and link-mode bits — get names).
//!
//! ## `STATS_GET` is not `ethtool -S`
//!
//! Plain `ethtool -S <dev>` prints the driver's *own* counter array, which has
//! no netlink message at all — it still goes through the legacy
//! `SIOCETHTOOL`/`ETHTOOL_GSTATS` ioctl, and this module does not implement it
//! (see SPEC.md's deferred list). What `STATS_GET` returns is the newer,
//! standardised set: IEEE 802.3 `eth-mac`/`eth-ctrl`, RFC 2819 `rmon` and
//! `eth-phy`, which is what `ethtool -S <dev> --groups eth-mac …` asks for and
//! what a monitoring consumer actually wants, because the names are the
//! standard's rather than each driver's invention.
//!
//! A driver that implements none of these answers with a reply whose groups are
//! *present but empty* — that is exactly what the committed golden shows for an
//! `e1000e`. Empty is not an error.
//!
//! ## Group layout
//!
//! ```text
//! ETHTOOL_A_STATS_GRP (nest, one per group)
//!   GRP_ID     u32     which group (eth-mac, rmon, …)
//!   GRP_SS_ID  u32     the ETH_SS_* string set that names this group's stats
//!   GRP_STAT   nest    one per counter: a single u64 whose *attribute type*
//!                      is the counter's index in that string set
//!   GRP_HIST_RX/TX nest   one per histogram bucket: BKT_LOW, BKT_HI, VAL
//! ```
//!
//! The counter index doubling as the attribute type is the part that surprises:
//! there is no `ETHTOOL_A_STATS_GRP_STAT_VALUE`. Fetch the group's
//! `ETH_SS_STATS_ETH_MAC` (etc.) string set once and index it to get names.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const header = @import("header.zig");
const bitset = @import("bitset.zig");
const params = @import("params.zig");

pub const Error = codec.Error || error{OutOfMemory};

/// Refuse to allocate unboundedly for a corrupt reply. The biggest standard
/// group has a few dozen counters.
pub const max_stats_per_group: usize = 4096;
pub const max_groups: usize = 64;
pub const max_strings: usize = 1 << 16;

/// One counter. `id` is its index in the group's string set — the wire carries
/// it as the attribute type, not as a value.
pub const Stat = struct {
    id: u16,
    value: u64,
};

/// One histogram bucket. `hi == 0` marks the open-ended last bucket, which is
/// the kernel's convention (`ETHTOOL_RMON_HIST_MAX`).
pub const HistBucket = struct {
    low: u32 = 0,
    hi: u32 = 0,
    value: u64 = 0,
};

/// One statistics group of a `STATS_GET` reply. Owns its slices.
pub const Group = struct {
    id: ?uapi.StatsGroup = null,
    /// The `ETH_SS_*` string set that names this group's counters.
    ss_id: ?uapi.StringSetId = null,
    stats: []Stat = &.{},
    hist_rx: []HistBucket = &.{},
    hist_tx: []HistBucket = &.{},

    pub fn deinit(g: *Group, gpa: std.mem.Allocator) void {
        gpa.free(g.stats);
        gpa.free(g.hist_rx);
        gpa.free(g.hist_tx);
        g.* = .{};
    }

    /// Look a counter up by its index in the group's string set.
    pub fn value(g: Group, id: u16) ?u64 {
        for (g.stats) |s| {
            if (s.id == id) return s.value;
        }
        return null;
    }
};

/// A decoded `STATS_GET` reply. Owns everything — free with `deinit`.
pub const Stats = struct {
    device: header.Device = .{},
    src: ?uapi.StatsSrc = null,
    groups: []Group = &.{},

    pub fn deinit(s: *Stats, gpa: std.mem.Allocator) void {
        for (s.groups) |*g| g.deinit(gpa);
        gpa.free(s.groups);
        s.* = .{};
    }

    pub fn group(s: Stats, id: uapi.StatsGroup) ?Group {
        for (s.groups) |g| {
            if (g.id) |i| {
                if (i == id) return g;
            }
        }
        return null;
    }
};

pub fn parse(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Stats {
    var out: Stats = .{};
    var groups: std.ArrayList(Group) = .empty;
    errdefer {
        for (groups.items) |*g| g.deinit(gpa);
        groups.deinit(gpa);
    }

    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.STATS.HEADER => out.device = try header.parse(a.data),
        uapi.STATS.SRC => out.src = @enumFromInt(try a.asU32()),
        uapi.STATS.GRP => {
            if (groups.items.len >= max_groups) return error.BadLength;
            var g = try parseGroup(gpa, a.data);
            errdefer g.deinit(gpa);
            try groups.append(gpa, g);
        },
        else => {},
    };
    out.groups = try groups.toOwnedSlice(gpa);
    return out;
}

fn parseGroup(gpa: std.mem.Allocator, nest_bytes: []const u8) Error!Group {
    var g: Group = .{};
    var stats: std.ArrayList(Stat) = .empty;
    var hist_rx: std.ArrayList(HistBucket) = .empty;
    var hist_tx: std.ArrayList(HistBucket) = .empty;
    errdefer {
        stats.deinit(gpa);
        hist_rx.deinit(gpa);
        hist_tx.deinit(gpa);
    }

    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.STATS_GRP.ID => g.id = @enumFromInt(try a.asU32()),
        uapi.STATS_GRP.SS_ID => g.ss_id = @enumFromInt(try a.asU32()),
        uapi.STATS_GRP.PAD => {},
        uapi.STATS_GRP.STAT => {
            // The nest holds exactly one u64 whose attribute type is the
            // counter's string-set index.
            var inner: codec.AttrIterator = .{ .buf = a.data };
            while (try inner.next()) |x| {
                if (x.data.len == 0) continue; // padding attribute
                if (stats.items.len >= max_stats_per_group) return error.BadLength;
                try stats.append(gpa, .{ .id = x.type, .value = try params.readU64(x) });
            }
        },
        uapi.STATS_GRP.HIST_RX, uapi.STATS_GRP.HIST_TX => {
            const bucket = try parseHistBucket(a.data);
            const target = if (a.type == uapi.STATS_GRP.HIST_RX) &hist_rx else &hist_tx;
            if (target.items.len >= max_stats_per_group) return error.BadLength;
            try target.append(gpa, bucket);
        },
        else => {},
    };
    g.stats = try stats.toOwnedSlice(gpa);
    errdefer gpa.free(g.stats);
    g.hist_rx = try hist_rx.toOwnedSlice(gpa);
    errdefer gpa.free(g.hist_rx);
    g.hist_tx = try hist_tx.toOwnedSlice(gpa);
    return g;
}

fn parseHistBucket(nest_bytes: []const u8) codec.Error!HistBucket {
    var b: HistBucket = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |x| switch (x.type) {
        uapi.STATS_GRP.HIST_BKT_LOW => b.low = try x.asU32(),
        uapi.STATS_GRP.HIST_BKT_HI => b.hi = try x.asU32(),
        uapi.STATS_GRP.HIST_VAL => b.value = try params.readU64(x),
        else => {},
    };
    return b;
}

/// Append the `ETHTOOL_A_STATS_GROUPS` bitset that selects which groups to
/// return, keyed by the kernel's own group names ("eth-mac", "eth-ctrl",
/// "rmon", "eth-phy"). This is byte-for-byte the shape
/// `ethtool -S <dev> --groups …` puts on the wire.
pub fn appendGroupSelector(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    names: []const []const u8,
) bitset.BuildError!void {
    try bitset.appendNameList(gpa, list, uapi.STATS.GROUPS, names);
}

/// What the `build*` encoders can fail with.
pub const BuildError = bitset.BuildError || header.Error;

/// Encode a complete `ETHTOOL_MSG_STATS_GET` request — `nlmsghdr`,
/// `genlmsghdr`, header nest and group selector, owned by the caller and freed
/// with `gpa`. An empty `groups` omits the selector entirely, which is what
/// asks for the driver's default set. `Ethtool.stats` sends exactly this.
pub fn buildStats(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    groups: []const []const u8,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.STATS_GET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.STATS.HEADER, .{ .target = target });
    if (groups.len != 0) try appendGroupSelector(gpa, &msg, groups);
    return header.finishRequest(gpa, &msg, h);
}

/// The standard group names, in `ETHTOOL_A_STATS_GROUPS` bit order. Asserted
/// against a captured `ETH_SS_STATS_STD` reply in `goldens.zig`, so this table
/// cannot drift from the kernel silently.
pub const group_names = [_][]const u8{ "eth-phy", "eth-mac", "eth-ctrl", "rmon" };

pub fn groupName(g: uapi.StatsGroup) ?[]const u8 {
    const i = @intFromEnum(g);
    return if (i < group_names.len) group_names[i] else null;
}

// ── STRSET ─────────────────────────────────────────────────────────────────

/// One string of a set, with the index the kernel gave it.
pub const StringEntry = struct {
    index: u32,
    /// Owned.
    value: []const u8,
};

/// One decoded string set. Owns its strings.
pub const StringSet = struct {
    id: ?uapi.StringSetId = null,
    /// The kernel's declared length, which may exceed `entries.len` when the
    /// request asked for counts only.
    count: ?u32 = null,
    entries: []StringEntry = &.{},

    pub fn deinit(s: *StringSet, gpa: std.mem.Allocator) void {
        for (s.entries) |e| gpa.free(e.value);
        gpa.free(s.entries);
        s.* = .{};
    }

    pub fn get(s: StringSet, index: u32) ?[]const u8 {
        for (s.entries) |e| {
            if (e.index == index) return e.value;
        }
        return null;
    }

    pub fn indexOf(s: StringSet, name: []const u8) ?u32 {
        for (s.entries) |e| {
            if (std.mem.eql(u8, e.value, name)) return e.index;
        }
        return null;
    }
};

/// A `STRSET_GET` reply: the sets that were asked for. Owns everything.
pub const StringSets = struct {
    device: header.Device = .{},
    sets: []StringSet = &.{},

    pub fn deinit(s: *StringSets, gpa: std.mem.Allocator) void {
        for (s.sets) |*one| one.deinit(gpa);
        gpa.free(s.sets);
        s.* = .{};
    }

    pub fn byId(s: StringSets, id: uapi.StringSetId) ?StringSet {
        for (s.sets) |one| {
            if (one.id) |i| {
                if (i == id) return one;
            }
        }
        return null;
    }
};

pub fn parseStringSets(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!StringSets {
    var out: StringSets = .{};
    var sets: std.ArrayList(StringSet) = .empty;
    errdefer {
        for (sets.items) |*s| s.deinit(gpa);
        sets.deinit(gpa);
    }

    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.STRSET.HEADER => out.device = try header.parse(a.data),
        uapi.STRSET.STRINGSETS => {
            var outer: codec.AttrIterator = .{ .buf = a.data };
            while (try outer.next()) |s| {
                if (s.type != uapi.STRINGSETS.STRINGSET) continue;
                if (sets.items.len >= max_groups) return error.BadLength;
                var one = try parseStringSet(gpa, s.data);
                errdefer one.deinit(gpa);
                try sets.append(gpa, one);
            }
        },
        else => {},
    };
    out.sets = try sets.toOwnedSlice(gpa);
    return out;
}

fn parseStringSet(gpa: std.mem.Allocator, nest_bytes: []const u8) Error!StringSet {
    var out: StringSet = .{};
    var entries: std.ArrayList(StringEntry) = .empty;
    errdefer {
        for (entries.items) |e| gpa.free(e.value);
        entries.deinit(gpa);
    }

    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.STRINGSET.ID => out.id = @enumFromInt(try a.asU32()),
        uapi.STRINGSET.COUNT => {
            const n = try a.asU32();
            if (n > max_strings) return error.BadLength;
            out.count = n;
        },
        uapi.STRINGSET.STRINGS => {
            var strings: codec.AttrIterator = .{ .buf = a.data };
            while (try strings.next()) |s| {
                if (s.type != uapi.STRINGS.STRING) continue;
                if (entries.items.len >= max_strings) return error.BadLength;
                var index: ?u32 = null;
                var value: ?[]const u8 = null;
                var inner: codec.AttrIterator = .{ .buf = s.data };
                while (try inner.next()) |x| switch (x.type) {
                    uapi.STRING.INDEX => index = try x.asU32(),
                    uapi.STRING.VALUE => value = x.asString(),
                    else => {},
                };
                // A string with no index or no value is not usable; a kernel
                // never sends one, and guessing would put entries out of step.
                const i = index orelse return error.BadLength;
                const v = value orelse return error.BadLength;
                const owned = try gpa.dupe(u8, v);
                errdefer gpa.free(owned);
                try entries.append(gpa, .{ .index = i, .value = owned });
            }
        },
        else => {},
    };
    out.entries = try entries.toOwnedSlice(gpa);
    return out;
}

/// Append the `ETHTOOL_A_STRSET_STRINGSETS` nest selecting which string sets to
/// fetch — the exact shape `ethtool` sends before printing feature or statistic
/// names.
pub fn appendStringSetSelector(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ids: []const uapi.StringSetId,
    // `InvalidRequest` because `ids` is caller-supplied and unbounded: past
    // ~8000 string-set ids the nest exceeds what an `nlattr` length can
    // express. Refusing beats the silent truncation that was here until
    // 2026-09-02 (see `codec.nestEnd`).
) error{ OutOfMemory, InvalidRequest }!void {
    const sets = try codec.nestBegin(gpa, list, uapi.STRSET.STRINGSETS | codec.NLA_F_NESTED);
    for (ids) |id| {
        const one = try codec.nestBegin(gpa, list, uapi.STRINGSETS.STRINGSET | codec.NLA_F_NESTED);
        try codec.appendAttrU32(gpa, list, uapi.STRINGSET.ID, @intFromEnum(id));
        codec.nestEnd(list, one) catch return error.InvalidRequest;
    }
    codec.nestEnd(list, sets) catch return error.InvalidRequest;
}

/// Encode a complete `ETHTOOL_MSG_STRSET_GET` request. A null `target` sends
/// the **empty** header nest the device-independent sets are asked for with —
/// not an omitted header, which the kernel's policy rejects. `Ethtool.stringSet`
/// sends exactly this.
pub fn buildStringSet(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: ?header.Target,
    ids: []const uapi.StringSetId,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.STRSET_GET,
        .seq = seq,
    });
    if (target) |t| {
        try header.append(gpa, &msg, uapi.STRSET.HEADER, .{ .target = t });
    } else {
        try header.appendGlobal(gpa, &msg, uapi.STRSET.HEADER, 0);
    }
    try appendStringSetSelector(gpa, &msg, ids);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

fn appendU64(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    v: u64,
) !void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, v, native_endian);
    try codec.appendAttr(gpa, list, attr_type, &raw);
}

test "STATS: a group's counters are keyed by attribute type, not by a value attr" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.STATS.HEADER, .{ .target = .byIndex(2) });
    try codec.appendAttrU32(gpa, &list, uapi.STATS.SRC, @intFromEnum(uapi.StatsSrc.aggregate));
    const grp = try codec.nestBegin(gpa, &list, uapi.STATS.GRP);
    try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.eth_mac));
    try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.SS_ID, @intFromEnum(uapi.StringSetId.stats_eth_mac));
    for ([_]struct { id: u16, v: u64 }{
        .{ .id = 0, .v = 1234 }, // FramesTransmittedOK
        .{ .id = 3, .v = 5678 }, // FramesReceivedOK
    }) |s| {
        const one = try codec.nestBegin(gpa, &list, uapi.STATS_GRP.STAT);
        try appendU64(gpa, &list, s.id, s.v);
        codec.nestEnd(&list, one) catch return error.InvalidRequest;
    }
    codec.nestEnd(&list, grp) catch return error.InvalidRequest;

    var st = try parse(gpa, list.items);
    defer st.deinit(gpa);
    try testing.expectEqual(uapi.StatsSrc.aggregate, st.src.?);
    try testing.expectEqual(@as(usize, 1), st.groups.len);
    const g = st.group(.eth_mac).?;
    try testing.expectEqual(uapi.StringSetId.stats_eth_mac, g.ss_id.?);
    try testing.expectEqual(@as(?u64, 1234), g.value(0));
    try testing.expectEqual(@as(?u64, 5678), g.value(3));
    try testing.expect(g.value(1) == null); // counter the driver does not keep
    try testing.expect(st.group(.rmon) == null);
}

test "STATS: rmon histograms decode into rx/tx buckets" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const grp = try codec.nestBegin(gpa, &list, uapi.STATS.GRP);
    try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.rmon));
    for ([_]HistBucket{
        .{ .low = 64, .hi = 64, .value = 10 },
        .{ .low = 65, .hi = 127, .value = 20 },
        .{ .low = 1024, .hi = 0, .value = 30 }, // open-ended last bucket
    }) |b| {
        const one = try codec.nestBegin(gpa, &list, uapi.STATS_GRP.HIST_RX);
        try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.HIST_BKT_LOW, b.low);
        try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.HIST_BKT_HI, b.hi);
        try appendU64(gpa, &list, uapi.STATS_GRP.HIST_VAL, b.value);
        codec.nestEnd(&list, one) catch return error.InvalidRequest;
    }
    {
        const one = try codec.nestBegin(gpa, &list, uapi.STATS_GRP.HIST_TX);
        try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.HIST_BKT_LOW, 64);
        try appendU64(gpa, &list, uapi.STATS_GRP.HIST_VAL, 7);
        codec.nestEnd(&list, one) catch return error.InvalidRequest;
    }
    codec.nestEnd(&list, grp) catch return error.InvalidRequest;

    var st = try parse(gpa, list.items);
    defer st.deinit(gpa);
    const g = st.group(.rmon).?;
    try testing.expectEqual(@as(usize, 3), g.hist_rx.len);
    try testing.expectEqual(@as(u32, 127), g.hist_rx[1].hi);
    try testing.expectEqual(@as(u64, 30), g.hist_rx[2].value);
    try testing.expectEqual(@as(u32, 0), g.hist_rx[2].hi); // open-ended
    try testing.expectEqual(@as(usize, 1), g.hist_tx.len);
    try testing.expectEqual(@as(u64, 7), g.hist_tx[0].value);
}

test "STATS: an empty group is a normal reply, not an error" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const grp = try codec.nestBegin(gpa, &list, uapi.STATS.GRP);
    try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.eth_ctrl));
    try codec.appendAttrU32(gpa, &list, uapi.STATS_GRP.SS_ID, 19);
    codec.nestEnd(&list, grp) catch return error.InvalidRequest;

    var st = try parse(gpa, list.items);
    defer st.deinit(gpa);
    const g = st.group(.eth_ctrl).?;
    try testing.expectEqual(@as(usize, 0), g.stats.len);
    try testing.expect(g.value(0) == null);
}

test "STATS: a counter that is not 8 bytes is a malformed reply" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const grp = try codec.nestBegin(gpa, &list, uapi.STATS.GRP);
    const one = try codec.nestBegin(gpa, &list, uapi.STATS_GRP.STAT);
    try codec.appendAttrU32(gpa, &list, 0, 5);
    codec.nestEnd(&list, one) catch return error.InvalidRequest;
    codec.nestEnd(&list, grp) catch return error.InvalidRequest;
    try testing.expectError(error.BadLength, parse(gpa, list.items));
}

test "group_names matches the StatsGroup enum ordering" {
    try testing.expectEqualStrings("eth-mac", groupName(.eth_mac).?);
    try testing.expectEqualStrings("rmon", groupName(.rmon).?);
    try testing.expect(groupName(@enumFromInt(99)) == null);
}

test "STRSET: strings decode with their kernel indices" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const sets = try codec.nestBegin(gpa, &list, uapi.STRSET.STRINGSETS);
    const one = try codec.nestBegin(gpa, &list, uapi.STRINGSETS.STRINGSET);
    try codec.appendAttrU32(gpa, &list, uapi.STRINGSET.ID, @intFromEnum(uapi.StringSetId.stats_std));
    try codec.appendAttrU32(gpa, &list, uapi.STRINGSET.COUNT, 2);
    const strings = try codec.nestBegin(gpa, &list, uapi.STRINGSET.STRINGS);
    for ([_][]const u8{ "eth-phy", "eth-mac" }, 0..) |s, i| {
        const str = try codec.nestBegin(gpa, &list, uapi.STRINGS.STRING);
        try codec.appendAttrU32(gpa, &list, uapi.STRING.INDEX, @intCast(i));
        try codec.appendAttrString(gpa, &list, uapi.STRING.VALUE, s);
        codec.nestEnd(&list, str) catch return error.InvalidRequest;
    }
    codec.nestEnd(&list, strings) catch return error.InvalidRequest;
    codec.nestEnd(&list, one) catch return error.InvalidRequest;
    codec.nestEnd(&list, sets) catch return error.InvalidRequest;

    var ss = try parseStringSets(gpa, list.items);
    defer ss.deinit(gpa);
    const std_set = ss.byId(.stats_std).?;
    try testing.expectEqual(@as(?u32, 2), std_set.count);
    try testing.expectEqualStrings("eth-phy", std_set.get(0).?);
    try testing.expectEqualStrings("eth-mac", std_set.get(1).?);
    try testing.expectEqual(@as(?u32, 1), std_set.indexOf("eth-mac"));
    try testing.expect(std_set.get(2) == null);
    try testing.expect(ss.byId(.features) == null);
}

test "STRSET: a string without an index or a value is refused, never mis-aligned" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const sets = try codec.nestBegin(gpa, &list, uapi.STRSET.STRINGSETS);
    const one = try codec.nestBegin(gpa, &list, uapi.STRINGSETS.STRINGSET);
    const strings = try codec.nestBegin(gpa, &list, uapi.STRINGSET.STRINGS);
    const str = try codec.nestBegin(gpa, &list, uapi.STRINGS.STRING);
    try codec.appendAttrString(gpa, &list, uapi.STRING.VALUE, "no-index");
    codec.nestEnd(&list, str) catch return error.InvalidRequest;
    codec.nestEnd(&list, strings) catch return error.InvalidRequest;
    codec.nestEnd(&list, one) catch return error.InvalidRequest;
    codec.nestEnd(&list, sets) catch return error.InvalidRequest;
    try testing.expectError(error.BadLength, parseStringSets(gpa, list.items));
}

test "STRSET: an absurd COUNT does not become an allocation" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const sets = try codec.nestBegin(gpa, &list, uapi.STRSET.STRINGSETS);
    const one = try codec.nestBegin(gpa, &list, uapi.STRINGSETS.STRINGSET);
    try codec.appendAttrU32(gpa, &list, uapi.STRINGSET.COUNT, 0xffff_ffff);
    codec.nestEnd(&list, one) catch return error.InvalidRequest;
    codec.nestEnd(&list, sets) catch return error.InvalidRequest;
    try testing.expectError(error.BadLength, parseStringSets(gpa, list.items));
}

test "STRSET selector encodes one nest per requested set" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendStringSetSelector(gpa, &list, &.{ .features, .link_modes });
    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(uapi.STRSET.STRINGSETS, a.type);
    var inner = a.nested();
    var n: usize = 0;
    while (try inner.next()) |s| : (n += 1) {
        var deep = s.nested();
        const id = (try deep.next()).?;
        try testing.expectEqual(uapi.STRINGSET.ID, id.type);
        try testing.expectEqual(@as(u32, if (n == 0) 4 else 9), try id.asU32());
    }
    try testing.expectEqual(@as(usize, 2), n);
}

/// STATS_GET and STRSET_GET reply attribute lists for `fuzzStats`, in the
/// format `Smith.slice` reads (see `testkit.fuzz`).
///
/// ⭐ Built at run time by this file's own encoders rather than quoted as hex:
/// these are trees of netlink TLVs, whose lengths and scalars are HOST byte
/// order, so a hex corpus would be a little-endian one and the counts pinned
/// below would be false on a big-endian target instead of failing there.
const Corpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // One eth-mac group with two counters, keyed by attribute type.
        var eth_mac: std.ArrayList(u8) = .empty;
        {
            const grp = try codec.nestBegin(gpa, &eth_mac, uapi.STATS.GRP);
            try codec.appendAttrU32(gpa, &eth_mac, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.eth_mac));
            try codec.appendAttrU32(gpa, &eth_mac, uapi.STATS_GRP.SS_ID, @intFromEnum(uapi.StringSetId.stats_eth_mac));
            for ([_]struct { id: u16, v: u64 }{ .{ .id = 0, .v = 1234 }, .{ .id = 3, .v = 5678 } }) |s| {
                const one = try codec.nestBegin(gpa, &eth_mac, uapi.STATS_GRP.STAT);
                try appendU64(gpa, &eth_mac, s.id, s.v);
                try codec.nestEnd(&eth_mac, one);
            }
            try codec.nestEnd(&eth_mac, grp);
        }
        self.push(eth_mac.items);

        // The rmon histograms, rx and tx, including an open-ended bucket.
        var rmon: std.ArrayList(u8) = .empty;
        {
            const grp = try codec.nestBegin(gpa, &rmon, uapi.STATS.GRP);
            try codec.appendAttrU32(gpa, &rmon, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.rmon));
            for ([_]HistBucket{
                .{ .low = 64, .hi = 64, .value = 10 },
                .{ .low = 65, .hi = 127, .value = 20 },
                .{ .low = 1024, .hi = 0, .value = 30 },
            }) |b| {
                const one = try codec.nestBegin(gpa, &rmon, uapi.STATS_GRP.HIST_RX);
                try codec.appendAttrU32(gpa, &rmon, uapi.STATS_GRP.HIST_BKT_LOW, b.low);
                try codec.appendAttrU32(gpa, &rmon, uapi.STATS_GRP.HIST_BKT_HI, b.hi);
                try appendU64(gpa, &rmon, uapi.STATS_GRP.HIST_VAL, b.value);
                try codec.nestEnd(&rmon, one);
            }
            {
                const one = try codec.nestBegin(gpa, &rmon, uapi.STATS_GRP.HIST_TX);
                try codec.appendAttrU32(gpa, &rmon, uapi.STATS_GRP.HIST_BKT_LOW, 64);
                try appendU64(gpa, &rmon, uapi.STATS_GRP.HIST_VAL, 7);
                try codec.nestEnd(&rmon, one);
            }
            try codec.nestEnd(&rmon, grp);
        }
        self.push(rmon.items);

        // A group with no counters: a normal reply, not an error.
        var empty_group: std.ArrayList(u8) = .empty;
        {
            const grp = try codec.nestBegin(gpa, &empty_group, uapi.STATS.GRP);
            try codec.appendAttrU32(gpa, &empty_group, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.eth_ctrl));
            try codec.appendAttrU32(gpa, &empty_group, uapi.STATS_GRP.SS_ID, 19);
            try codec.nestEnd(&empty_group, grp);
        }
        self.push(empty_group.items);

        // A string set with two indexed strings.
        var strset: std.ArrayList(u8) = .empty;
        {
            const sets = try codec.nestBegin(gpa, &strset, uapi.STRSET.STRINGSETS);
            const one = try codec.nestBegin(gpa, &strset, uapi.STRINGSETS.STRINGSET);
            try codec.appendAttrU32(gpa, &strset, uapi.STRINGSET.ID, @intFromEnum(uapi.StringSetId.stats_std));
            try codec.appendAttrU32(gpa, &strset, uapi.STRINGSET.COUNT, 2);
            const strings = try codec.nestBegin(gpa, &strset, uapi.STRINGSET.STRINGS);
            for ([_][]const u8{ "eth-phy", "eth-mac" }, 0..) |s, i| {
                const str = try codec.nestBegin(gpa, &strset, uapi.STRINGS.STRING);
                try codec.appendAttrU32(gpa, &strset, uapi.STRING.INDEX, @intCast(i));
                try codec.appendAttrString(gpa, &strset, uapi.STRING.VALUE, s);
                try codec.nestEnd(&strset, str);
            }
            try codec.nestEnd(&strset, strings);
            try codec.nestEnd(&strset, one);
            try codec.nestEnd(&strset, sets);
        }
        self.push(strset.items);

        // ── the refusals ───────────────────────────────────────────────────
        // A string with a value but no index: refused, never mis-aligned.
        var no_index: std.ArrayList(u8) = .empty;
        {
            const sets = try codec.nestBegin(gpa, &no_index, uapi.STRSET.STRINGSETS);
            const one = try codec.nestBegin(gpa, &no_index, uapi.STRINGSETS.STRINGSET);
            const strings = try codec.nestBegin(gpa, &no_index, uapi.STRINGSET.STRINGS);
            const str = try codec.nestBegin(gpa, &no_index, uapi.STRINGS.STRING);
            try codec.appendAttrString(gpa, &no_index, uapi.STRING.VALUE, "no-index");
            try codec.nestEnd(&no_index, str);
            try codec.nestEnd(&no_index, strings);
            try codec.nestEnd(&no_index, one);
            try codec.nestEnd(&no_index, sets);
        }
        self.push(no_index.items);

        // An absurd COUNT that must not become an allocation.
        var absurd: std.ArrayList(u8) = .empty;
        {
            const sets = try codec.nestBegin(gpa, &absurd, uapi.STRSET.STRINGSETS);
            const one = try codec.nestBegin(gpa, &absurd, uapi.STRINGSETS.STRINGSET);
            try codec.appendAttrU32(gpa, &absurd, uapi.STRINGSET.COUNT, 0xffff_ffff);
            try codec.nestEnd(&absurd, one);
            try codec.nestEnd(&absurd, sets);
        }
        self.push(absurd.items);

        // A counter that is not eight octets, and a truncated TLV.
        var narrow: std.ArrayList(u8) = .empty;
        {
            const grp = try codec.nestBegin(gpa, &narrow, uapi.STATS.GRP);
            try codec.appendAttrU32(gpa, &narrow, uapi.STATS_GRP.ID, @intFromEnum(uapi.StatsGroup.eth_mac));
            const one = try codec.nestBegin(gpa, &narrow, uapi.STATS_GRP.STAT);
            try codec.appendAttrU32(gpa, &narrow, 0, 1234);
            try codec.nestEnd(&narrow, one);
            try codec.nestEnd(&narrow, grp);
        }
        self.push(narrow.items);
        self.push(&[_]u8{ 0x40, 0x00, 0x02, 0x00 });

        return self.entries[0..self.n];
    }
};

test "fuzz: statistics and string-set decoding never crash or leak" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzStats, .{ .corpus = try corpus.build() });
}

fn fuzzStats(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and both decoders were handed an empty
    // attribute list with the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: a reply with no groups and no
    // string sets is a legal one, so both decoders SUCCEEDED on the empty
    // slice every round while allocating nothing and walking nothing.
    // Measured 2026-09-07 over the corpus above: **0 of 8 seeds non-empty, 8
    // of 8 stats replies and 8 of 8 string-set replies "decoded", 0 groups and
    // 0 strings recovered before; 8 of 8 non-empty, 3 and 5 decoded, 3 groups
    // and 2 strings after.**
    const len: usize = smith.slice(&raw);
    const buf = raw[0..len];
    if (parse(testing.allocator, buf)) |s| {
        var v = s;
        v.deinit(testing.allocator);
    } else |_| {}
    if (parseStringSets(testing.allocator, buf)) |s| {
        var v = s;
        v.deinit(testing.allocator);
    } else |_| {}
}

test "corpus: every stats seed reaches both decoders, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here — this file has a test called "empty bitset decodes to an empty
    // set, not an error" — so "parsed" alone counts a harness that walks
    // nothing as a complete success.
    //
    // `groups` and `strings` are those second numbers: both are 0 for the
    // empty reply the two decoders accept.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var stats_ok: usize = 0;
    var strset_ok: usize = 0;
    var groups: usize = 0;
    var strings: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const buf = raw[0..len];
        if (parse(testing.allocator, buf)) |s| {
            stats_ok += 1;
            var v = s;
            groups += v.groups.len;
            v.deinit(testing.allocator);
        } else |_| {}
        if (parseStringSets(testing.allocator, buf)) |s| {
            strset_ok += 1;
            var v = s;
            for (v.sets) |one| strings += one.entries.len;
            v.deinit(testing.allocator);
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), stats_ok);
    try testing.expectEqual(@as(usize, 5), strset_ok);
    try testing.expectEqual(@as(usize, 3), groups);
    try testing.expectEqual(@as(usize, 2), strings);
}
