// SPDX-License-Identifier: MIT
//! `PRIVFLAGS_GET`/`SET` — the driver's private on/off switches
//! (`ethtool --show-priv-flags`, `ethtool --set-priv-flags <dev> <flag> on`).
//!
//! The flag names are the **driver's own** (`ETH_SS_PRIV_FLAGS`, e.g.
//! `"legacy-rx"` on i40e) and differ per driver, so a verbose reply is the
//! useful form: the bitset then carries a name per bit. With a compact reply
//! the names come from `Ethtool.stringSet(dev, &.{.priv_flags})`.
//!
//! Unprivileged to read; a SET needs **CAP_NET_ADMIN**. A SET names the flags
//! to change; the rest are left alone.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};
pub const BuildError = bitset.BuildError || header.Error;

/// `ETHTOOL_MSG_PRIVFLAGS_GET` reply. Owns its bitset — free with `deinit`.
pub const Privflags = struct {
    device: header.Device = .{},
    /// One bit per private flag. A driver with no private flags answers with
    /// an empty set, which is not an error.
    flags: ?bitset.Bitset = null,

    pub fn deinit(p: *Privflags, gpa: std.mem.Allocator) void {
        if (p.flags) |*b| b.deinit(gpa);
        p.* = .{};
    }

    /// Is the driver flag called `name` on? Null when the reply carries no
    /// names (compact) or does not mention it.
    pub fn isOn(p: Privflags, name: []const u8) ?bool {
        const f = p.flags orelse return null;
        return f.isSetByName(name);
    }
};

pub fn parsePrivflags(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Privflags {
    var out: Privflags = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PRIVFLAGS.HEADER => out.device = try header.parse(a.data),
        uapi.PRIVFLAGS.FLAGS => {
            if (out.flags != null) return error.BadLength;
            out.flags = try bitset.parse(gpa, a.data);
        },
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_PRIVFLAGS_SET` parameters: the flags to switch, by name
/// **or** by index (not both: `InvalidRequest`). Empty = a legal no-op.
pub const PrivflagsSet = struct {
    flags: []const bitset.NamedValue = &.{},
    flags_by_index: []const bitset.IndexedValue = &.{},
};

/// Encode a complete `ETHTOOL_MSG_PRIVFLAGS_GET` request. `form` picks the
/// bitset encoding of the reply. `Ethtool.privflags` sends exactly this.
pub fn buildPrivflags(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.PRIVFLAGS_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.PRIVFLAGS.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

/// Encode a complete `ETHTOOL_MSG_PRIVFLAGS_SET` request. `Ethtool.setPrivflags`
/// sends exactly this.
pub fn buildSetPrivflags(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: PrivflagsSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.PRIVFLAGS_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.PRIVFLAGS.HEADER, .{ .target = target });
    try bitset.appendMasked(gpa, &msg, uapi.PRIVFLAGS.FLAGS, set.flags_by_index, set.flags);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "PRIVFLAGS reply: names resolve, absent names are null" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.PRIVFLAGS.HEADER, .{ .target = .byIndex(2) });
    try bitset.appendNamedValues(gpa, &list, uapi.PRIVFLAGS.FLAGS, &.{
        .{ .name = "legacy-rx", .on = true },
        .{ .name = "link-down-on-close", .on = false },
    });
    var p = try parsePrivflags(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), p.device.index);
    try testing.expectEqual(@as(?bool, true), p.isOn("legacy-rx"));
    try testing.expectEqual(@as(?bool, false), p.isOn("link-down-on-close"));
    try testing.expectEqual(@as(?bool, null), p.isOn("no-such-flag"));
}

test "PRIVFLAGS reply: compact set has no names; empty reply is legal" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.PRIVFLAGS.FLAGS, 3, &.{0b101}, &.{0b111});
    var p = try parsePrivflags(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(?bool, null), p.isOn("legacy-rx"));
    try testing.expect(p.flags.?.isSet(0) and !p.flags.?.isSet(1) and p.flags.?.isSet(2));

    var e = try parsePrivflags(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expect(e.flags == null);
    try testing.expectEqual(@as(?bool, null), e.isOn("x"));
}

test "PRIVFLAGS reply: malformed input is a typed error" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, parsePrivflags(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.PRIVFLAGS.FLAGS, 3, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.PRIVFLAGS.FLAGS, 3, &.{1}, null);
    try testing.expectError(error.BadLength, parsePrivflags(gpa, list.items));
}

test "PRIVFLAGS_GET request" {
    const gpa = testing.allocator;
    const msg = try buildPrivflags(gpa, 23, 2, .byName("eth0"), .verbose);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.PRIVFLAGS_GET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.PRIVFLAGS.HEADER, h.type & codec.NLA_TYPE_MASK);
    var hit: codec.AttrIterator = .{ .buf = h.data };
    try testing.expectEqualStrings("eth0", (try hit.next()).?.asString());
    try testing.expect((try hit.next()) == null); // verbose = no flag word
}

test "PRIVFLAGS_SET request: by name, by index, and empty" {
    const gpa = testing.allocator;
    const by_name = try buildSetPrivflags(gpa, 23, 2, .byIndex(2), .{
        .flags = &.{.{ .name = "legacy-rx", .on = true }},
    });
    defer gpa.free(by_name);
    try testing.expectEqual(uapi.MSG.PRIVFLAGS_SET, by_name[16]);
    var it: codec.AttrIterator = .{ .buf = by_name[20..] };
    _ = (try it.next()).?;
    const f = (try it.next()).?;
    try testing.expectEqual(uapi.PRIVFLAGS.FLAGS, f.type & codec.NLA_TYPE_MASK);
    var bs = try bitset.parse(gpa, f.data);
    defer bs.deinit(gpa);
    try testing.expectEqual(true, bs.isSetByName("legacy-rx").?);

    const by_idx = try buildSetPrivflags(gpa, 23, 2, .byIndex(2), .{
        .flags_by_index = &.{.{ .index = 1, .on = false }},
    });
    defer gpa.free(by_idx);
    var iit: codec.AttrIterator = .{ .buf = by_idx[20..] };
    _ = (try iit.next()).?;
    var bs2 = try bitset.parse(gpa, (try iit.next()).?.data);
    defer bs2.deinit(gpa);
    try testing.expect(bs2.inMask(1) and !bs2.isSet(1));

    const empty = try buildSetPrivflags(gpa, 23, 2, .byIndex(2), .{});
    defer gpa.free(empty);
    var eit: codec.AttrIterator = .{ .buf = empty[20..] };
    _ = (try eit.next()).?;
    try testing.expect((try eit.next()) == null);
}

test "PRIVFLAGS_SET request: invalid arguments are InvalidRequest" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, buildSetPrivflags(gpa, 23, 1, .byIndex(2), .{
        .flags = &.{.{ .name = "a", .on = true }},
        .flags_by_index = &.{.{ .index = 0, .on = true }},
    }));
    try testing.expectError(error.InvalidRequest, buildSetPrivflags(gpa, 23, 1, .byName(""), .{}));
    try testing.expectError(error.InvalidRequest, buildSetPrivflags(gpa, 23, 1, .byIndex(2), .{
        .flags_by_index = &.{.{ .index = bitset.max_bits, .on = true }},
    }));
}
