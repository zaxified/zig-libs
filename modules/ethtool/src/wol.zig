// SPDX-License-Identifier: MIT
//! `WOL_GET`/`SET` — Wake-on-LAN (`ethtool <dev>` "Wake-on", `ethtool -s <dev>
//! wol g`).
//!
//! `WOL_GET` needs **CAP_NET_ADMIN even to read** (the reply may carry the
//! SecureOn password); `WOL_SET` needs it too.
//!
//! ## `SOPASS` is a secret
//!
//! The 6-byte SecureOn password (`ethtool -s <dev> wol s sopass 00:11:…`)
//! authenticates the magic packet. This module wipes every buffer *it* owns
//! that held one, with `std.crypto.secureZero`:
//!
//! * **GET**: the copy of the reply, and the socket's receive buffer, are
//!   zeroed as soon as the reply is decoded (also on every error path).
//!   `Wol.deinit` zeroes the `sopass` it handed to the caller; a caller that
//!   keeps `Wol.sopass` past `deinit` owns that copy.
//! * **SET**: the request is built in a buffer reserved up front (so no growth
//!   leaves a stale copy behind), copied once into the returned datagram, and
//!   the builder buffer is zeroed. `Ethtool.setWol` zeroes the datagram after
//!   sending it. A caller of the offline `buildSetWol` owns the datagram and
//!   must `wipe` it.
//!
//! The caller's own `WolSet.sopass` value is the caller's to wipe.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};
pub const BuildError = bitset.BuildError || header.Error;

/// Zero a buffer that held a secret, in a way the optimizer may not drop.
pub fn wipe(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

/// `ETHTOOL_MSG_WOL_GET` reply. Owns its bitset — free with `deinit`.
pub const Wol = struct {
    device: header.Device = .{},
    /// Value = wake-up modes enabled, mask = modes the device supports. Bit
    /// indices are `uapi.wake_bit`; a verbose reply names them (`"magic"`, …).
    modes: ?bitset.Bitset = null,
    /// The SecureOn password, when the driver reports one. **A secret.**
    sopass: ?[uapi.sopass_len]u8 = null,

    pub fn deinit(w: *Wol, gpa: std.mem.Allocator) void {
        if (w.modes) |*b| b.deinit(gpa);
        if (w.sopass) |*s| wipe(s);
        w.* = .{};
    }

    /// Is wake-up mode `wake_bit` (`uapi.wake_bit.*`) enabled?
    pub fn enabled(w: Wol, wake_bit: u32) bool {
        const m = w.modes orelse return false;
        return m.isSet(wake_bit);
    }

    /// Does the device support wake-up mode `wake_bit`?
    pub fn supports(w: Wol, wake_bit: u32) bool {
        const m = w.modes orelse return false;
        return m.inMask(wake_bit);
    }
};

pub fn parseWol(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Wol {
    var out: Wol = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.WOL.HEADER => out.device = try header.parse(a.data),
        uapi.WOL.MODES => {
            if (out.modes != null) return error.BadLength;
            out.modes = try bitset.parse(gpa, a.data);
        },
        uapi.WOL.SOPASS => {
            if (a.data.len != uapi.sopass_len) return error.BadLength;
            out.sopass = a.data[0..uapi.sopass_len].*;
        },
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_WOL_SET` parameters.
pub const WolSet = struct {
    /// Wake-up modes to switch on or off (a delta), by index (`uapi.wake_bit.*`)
    /// **or** by name (`"magic"`, …), not both (`InvalidRequest`).
    modes: []const bitset.IndexedValue = &.{},
    mode_names: []const bitset.NamedValue = &.{},
    /// The SecureOn password. A secret: see the file header.
    sopass: ?[uapi.sopass_len]u8 = null,
};

/// Encode a complete `ETHTOOL_MSG_WOL_GET` request. `form` picks the bitset
/// encoding of the reply. `Ethtool.wol` sends exactly this.
pub fn buildWol(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.WOL_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.WOL.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

/// Upper bound of the bytes `buildSetWol` writes: both frame headers, a header
/// nest with an interface name, the bitset entries and the SOPASS attribute.
/// Deliberately generous — it only has to never be too small.
fn setBound(target: header.Target, set: WolSet) usize {
    var n: usize = 20 + 8 + 8 + 4; // nlmsghdr+genlmsghdr, header nest, modes nest + BITS
    switch (target) {
        .index => n += 8,
        .name => |name| n += 4 + codec.alignUp(name.len + 1),
    }
    n += set.modes.len * 16;
    for (set.mode_names) |e| n += 16 + codec.alignUp(e.name.len + 1);
    if (set.sopass != null) n += 4 + codec.alignUp(uapi.sopass_len);
    return n;
}

/// Encode a complete `ETHTOOL_MSG_WOL_SET` request. `Ethtool.setWol` sends
/// exactly this. **The result may contain the SOPASS: `wipe` it** before
/// freeing it (the file header says what else is zeroed here).
pub fn buildSetWol(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: WolSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    // Reserved up front, so appending the secret never reallocates (a realloc
    // would leave an unwiped copy in the freed block). `finishRequest`'s
    // `toOwnedSlice` may shrink-and-move too, so it is not used: the datagram
    // is copied out once and the builder buffer is zeroed here.
    try msg.ensureTotalCapacityPrecise(gpa, setBound(target, set));
    defer {
        wipe(msg.allocatedSlice());
        msg.deinit(gpa);
    }
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.WOL_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.WOL.HEADER, .{ .target = target });
    try bitset.appendMasked(gpa, &msg, uapi.WOL.MODES, set.modes, set.mode_names);
    if (set.sopass) |*secret| codec.appendAttr(gpa, &msg, uapi.WOL.SOPASS, secret) catch |e| switch (e) {
        error.AttrTooLong => unreachable, // six bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.finishHeader(&msg, h);
    return gpa.dupe(u8, msg.items);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const pw = [uapi.sopass_len]u8{ 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34 };

test "WOL reply: modes as (enabled, supported), SOPASS decoded" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.WOL.HEADER, .{ .target = .byIndex(2) });
    // supported: phy, ucast, bcast, magic, magicsecure; enabled: magic.
    const sup: u32 = (1 << uapi.wake_bit.phy) | (1 << uapi.wake_bit.ucast) | (1 << uapi.wake_bit.bcast) |
        (1 << uapi.wake_bit.magic) | (1 << uapi.wake_bit.magicsecure);
    try bitset.appendCompact(gpa, &list, uapi.WOL.MODES, 8, &.{1 << uapi.wake_bit.magic}, &.{sup});
    try codec.appendAttr(gpa, &list, uapi.WOL.SOPASS, &pw);

    var w = try parseWol(gpa, list.items);
    defer w.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), w.device.index);
    try testing.expect(w.enabled(uapi.wake_bit.magic));
    try testing.expect(!w.enabled(uapi.wake_bit.phy));
    try testing.expect(w.supports(uapi.wake_bit.phy));
    try testing.expect(!w.supports(uapi.wake_bit.arp));
    try testing.expectEqualSlices(u8, &pw, &w.sopass.?);
}

test "WOL reply: deinit wipes the SOPASS it handed out" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttr(gpa, &list, uapi.WOL.SOPASS, &pw);
    var w = try parseWol(gpa, list.items);
    const copy_ptr: *[uapi.sopass_len]u8 = &w.sopass.?;
    try testing.expectEqualSlices(u8, &pw, copy_ptr);
    w.deinit(gpa);
    // `deinit` resets the struct; the secret bytes are gone from its storage.
    try testing.expect(w.sopass == null);
    try testing.expectEqual(@as([uapi.sopass_len]u8, @splat(0)), copy_ptr.*);
}

test "WOL reply: absent attributes stay null; wrong SOPASS length is an error" {
    const gpa = testing.allocator;
    var w = try parseWol(gpa, &.{});
    defer w.deinit(gpa);
    try testing.expect(w.modes == null and w.sopass == null);
    try testing.expect(!w.enabled(uapi.wake_bit.magic) and !w.supports(uapi.wake_bit.magic));

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttr(gpa, &list, uapi.WOL.SOPASS, pw[0..5]);
    try testing.expectError(error.BadLength, parseWol(gpa, list.items));
    list.clearRetainingCapacity();
    try codec.appendAttr(gpa, &list, uapi.WOL.SOPASS, &(pw ++ [_]u8{0}));
    try testing.expectError(error.BadLength, parseWol(gpa, list.items));
    try testing.expectError(error.Truncated, parseWol(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    // A duplicated modes bitset.
    list.clearRetainingCapacity();
    try bitset.appendCompact(gpa, &list, uapi.WOL.MODES, 8, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.WOL.MODES, 8, &.{1}, null);
    try testing.expectError(error.BadLength, parseWol(gpa, list.items));
}

test "WOL_GET request: command, device, compact flag" {
    const gpa = testing.allocator;
    const msg = try buildWol(gpa, 23, 4, .byName("eth0"), .compact);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.WOL_GET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.WOL.HEADER, h.type & codec.NLA_TYPE_MASK);
    var hit: codec.AttrIterator = .{ .buf = h.data };
    try testing.expectEqualStrings("eth0", (try hit.next()).?.asString());
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS, try (try hit.next()).?.asU32());
}

test "WOL_SET request: modes by index and the SOPASS, in a well-formed frame" {
    const gpa = testing.allocator;
    const msg = try buildSetWol(gpa, 23, 5, .byName("enp0s31f6"), .{
        .modes = &.{ .{ .index = uapi.wake_bit.magic, .on = true }, .{ .index = uapi.wake_bit.arp, .on = false } },
        .sopass = pw,
    });
    defer {
        wipe(msg);
        gpa.free(msg);
    }
    // nlmsg_len covers exactly the datagram.
    try testing.expectEqual(@as(u32, @intCast(msg.len)), std.mem.readInt(u32, msg[0..4], @import("builtin").cpu.arch.endian()));
    try testing.expectEqual(uapi.MSG.WOL_SET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    _ = (try it.next()).?;
    const modes = (try it.next()).?;
    try testing.expectEqual(uapi.WOL.MODES, modes.type & codec.NLA_TYPE_MASK);
    var bs = try bitset.parse(gpa, modes.data);
    defer bs.deinit(gpa);
    try testing.expect(bs.isSet(uapi.wake_bit.magic));
    try testing.expect(!bs.isSet(uapi.wake_bit.arp));
    try testing.expect(bs.inMask(uapi.wake_bit.arp));
    const sp = (try it.next()).?;
    try testing.expectEqual(uapi.WOL.SOPASS, sp.type);
    try testing.expectEqualSlices(u8, &pw, sp.data);
    try testing.expect((try it.next()) == null);
}

test "WOL_SET request: by name, no SOPASS, and the empty no-op" {
    const gpa = testing.allocator;
    const msg = try buildSetWol(gpa, 23, 5, .byIndex(2), .{ .mode_names = &.{.{ .name = "magic", .on = true }} });
    defer gpa.free(msg);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    _ = (try it.next()).?;
    var bs = try bitset.parse(gpa, (try it.next()).?.data);
    defer bs.deinit(gpa);
    try testing.expectEqual(true, bs.isSetByName("magic").?);
    try testing.expect((try it.next()) == null);

    const empty = try buildSetWol(gpa, 23, 5, .byIndex(2), .{});
    defer gpa.free(empty);
    var eit: codec.AttrIterator = .{ .buf = empty[20..] };
    _ = (try eit.next()).?;
    try testing.expect((try eit.next()) == null);
}

test "WOL_SET request: invalid arguments are InvalidRequest, nothing leaks" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, buildSetWol(gpa, 23, 1, .byIndex(2), .{
        .modes = &.{.{ .index = 5, .on = true }},
        .mode_names = &.{.{ .name = "magic", .on = true }},
        .sopass = pw,
    }));
    try testing.expectError(error.InvalidRequest, buildSetWol(gpa, 23, 1, .byName(""), .{ .sopass = pw }));
    try testing.expectError(error.InvalidRequest, buildSetWol(gpa, 23, 1, .byIndex(2), .{
        .modes = &.{.{ .index = bitset.max_bits, .on = true }},
        .sopass = pw,
    }));
}

test "WOL_SET request: the capacity bound is never too small" {
    const gpa = testing.allocator;
    // A max-length name and many named modes; `ensureTotalCapacityPrecise` +
    // no-growth is what keeps stale SOPASS copies out of freed memory, so a
    // too-small bound would show as a different capacity than the reservation.
    const long = "enp0s31f6xxxxx"; // 14 chars: the longest legal IFNAMSIZ-1 is 15
    var entries: [20]bitset.NamedValue = undefined;
    for (&entries) |*e| e.* = .{ .name = "magicsecure", .on = true };
    const target: header.Target = .byName(long);
    const set: WolSet = .{ .mode_names = &entries, .sopass = pw };
    const bound = setBound(target, set);
    const msg = try buildSetWol(gpa, 23, 1, target, set);
    defer {
        wipe(msg);
        gpa.free(msg);
    }
    try testing.expect(msg.len <= bound);
    var by_index: [40]bitset.IndexedValue = @splat(.{ .index = 3, .on = true });
    const set2: WolSet = .{ .modes = &by_index, .sopass = pw };
    const msg2 = try buildSetWol(gpa, 23, 1, .byIndex(70000), set2);
    defer {
        wipe(msg2);
        gpa.free(msg2);
    }
    try testing.expect(msg2.len <= setBound(.byIndex(70000), set2));
}
