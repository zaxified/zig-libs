// SPDX-License-Identifier: MIT
//! `RSS_GET` — receive-side scaling: the hash function, the hash key and the
//! indirection table (`ethtool --show-rxfh`, `ethtool -x <dev>`). Read-only.
//!
//! * `hfunc` — the hash function as the kernel's bit mask (`rss_hfunc`:
//!   toeplitz = 1, xor = 2, crc32 = 4; the names are the `ETH_SS_RSS_HASH_FUNCS`
//!   string set). Zero when the driver does not report one.
//! * `key` — the hash key, raw bytes (often 40 or 52). Empty when the driver
//!   reports none. **The key is not a secret in the cryptographic sense but it
//!   steers traffic distribution**, so `deinit` does not wipe it; treat it as
//!   configuration.
//! * `indir` — the indirection table, one u32 receive-queue number per slot.
//! * `context` — the RSS context id of the reply, when the kernel sends one
//!   (context 0 is the default context and is a real value, hence optional).
//! * `input_xfrm` — the input transformation mask (`RXH_XFRM_*`), when present.
//!
//! The per-flow-type hash field selection (`ETHTOOL_A_RSS_FLOW_HASH`, newer
//! kernels) is not decoded; it stays reachable through `Ethtool.raw`.
//!
//! Unprivileged. A device that does not implement RSS answers `NotSupported`
//! (`EOPNOTSUPP`), which is the normal outcome for virtual interfaces.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");

const native_endian = @import("builtin").cpu.arch.endian();

pub const Error = codec.Error || error{OutOfMemory};

/// `ETHTOOL_A_RSS_HFUNC` bit masks (`ETH_RSS_HASH_*`); the order matches the
/// `ETH_SS_RSS_HASH_FUNCS` string set (toeplitz, xor, crc32).
pub const rss_hfunc = struct {
    pub const toeplitz: u32 = 1 << 0;
    pub const xor: u32 = 1 << 1;
    pub const crc32: u32 = 1 << 2;
};

/// `ETHTOOL_MSG_RSS_GET` reply. Owns `key` and `indir` — free with `deinit`.
pub const Rss = struct {
    device: header.Device = .{},
    /// RSS context id as sent by the kernel; null when the reply has none.
    context: ?u32 = null,
    /// Hash-function mask (see `rss_hfunc`); null when absent.
    hfunc: ?u32 = null,
    /// One receive-queue number per slot; empty when absent.
    indir: []u32 = &.{},
    /// Hash key bytes; empty when absent.
    key: []u8 = &.{},
    /// `RXH_XFRM_*` input transformation; null when absent.
    input_xfrm: ?u32 = null,

    pub fn deinit(r: *Rss, gpa: std.mem.Allocator) void {
        if (r.indir.len != 0) gpa.free(r.indir);
        if (r.key.len != 0) gpa.free(r.key);
        r.* = .{};
    }

    /// Is the named hash function (a single `rss_hfunc` mask) the one in use?
    pub fn usesHfunc(r: Rss, mask: u32) bool {
        return if (r.hfunc) |h| h == mask else false;
    }
};

pub fn parseRss(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Rss {
    var out: Rss = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.RSS.HEADER => out.device = try header.parse(a.data),
        uapi.RSS.CONTEXT => out.context = try a.asU32(),
        uapi.RSS.HFUNC => out.hfunc = try a.asU32(),
        uapi.RSS.INPUT_XFRM => out.input_xfrm = try a.asU32(),
        uapi.RSS.INDIR => {
            if (out.indir.len != 0) return error.BadLength;
            // The table is an array of u32; a length that is not a multiple of
            // four is a malformed reply, never a partial last entry.
            if (a.data.len % 4 != 0) return error.BadLength;
            const n = a.data.len / 4;
            if (n == 0) continue;
            const t = try gpa.alloc(u32, n);
            for (t, 0..) |*e, i| e.* = std.mem.readInt(u32, a.data[i * 4 ..][0..4], native_endian);
            out.indir = t;
        },
        uapi.RSS.HKEY => {
            if (out.key.len != 0) return error.BadLength;
            if (a.data.len == 0) continue;
            out.key = try gpa.dupe(u8, a.data);
        },
        else => {},
    };
    return out;
}

/// Encode a complete `ETHTOOL_MSG_RSS_GET` request. `context` selects a
/// non-default RSS context (`ethtool -x <dev> context N`); null asks for the
/// default. `Ethtool.rss` sends exactly this.
pub fn buildRss(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    context: ?u32,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.RSS_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.RSS.HEADER, .{ .target = target });
    if (context) |c| try codec.appendAttrU32(gpa, &msg, uapi.RSS.CONTEXT, c);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn appendIndir(gpa: std.mem.Allocator, list: *std.ArrayList(u8), entries: []const u32) !void {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    for (entries) |e| {
        var w: [4]u8 = undefined;
        std.mem.writeInt(u32, &w, e, native_endian);
        try raw.appendSlice(gpa, &w);
    }
    try codec.appendAttr(gpa, list, uapi.RSS.INDIR, raw.items);
}

test "RSS reply: every attribute decodes" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.RSS.HEADER, .{ .target = .byIndex(2) });
    try codec.appendAttrU32(gpa, &list, uapi.RSS.CONTEXT, 0);
    try codec.appendAttrU32(gpa, &list, uapi.RSS.HFUNC, rss_hfunc.toeplitz);
    try appendIndir(gpa, &list, &.{ 0, 1, 2, 3, 0, 1, 2, 3 });
    try codec.appendAttr(gpa, &list, uapi.RSS.HKEY, &.{ 0x6d, 0x5a, 0x56, 0xda, 0x25 });
    try codec.appendAttrU32(gpa, &list, uapi.RSS.INPUT_XFRM, 1);
    var r = try parseRss(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), r.device.index);
    try testing.expectEqual(@as(?u32, 0), r.context);
    try testing.expect(r.usesHfunc(rss_hfunc.toeplitz) and !r.usesHfunc(rss_hfunc.xor));
    try testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 0, 1, 2, 3 }, r.indir);
    try testing.expectEqualSlices(u8, &.{ 0x6d, 0x5a, 0x56, 0xda, 0x25 }, r.key);
    try testing.expectEqual(@as(?u32, 1), r.input_xfrm);
}

test "RSS reply: optional attributes may be missing; empty reply is legal" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.RSS.HEADER, .{ .target = .byIndex(3) });
    try codec.appendAttrU32(gpa, &list, uapi.RSS.HFUNC, rss_hfunc.crc32);
    var r = try parseRss(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expectEqual(@as(?u32, null), r.context);
    try testing.expectEqual(@as(?u32, rss_hfunc.crc32), r.hfunc);
    try testing.expectEqual(@as(usize, 0), r.indir.len);
    try testing.expectEqual(@as(usize, 0), r.key.len);
    try testing.expectEqual(@as(?u32, null), r.input_xfrm);

    var e = try parseRss(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expectEqual(@as(?u32, null), e.hfunc);
    try testing.expect(!e.usesHfunc(1));
}

test "RSS reply: malformed attributes are typed errors" {
    const gpa = testing.allocator;
    // Truncated TLV (claims 8 bytes, has 5).
    try testing.expectError(error.Truncated, parseRss(gpa, &.{ 0x08, 0x00, 0x03, 0x00, 1 }));
    // HFUNC / CONTEXT of the wrong size.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttr(gpa, &list, uapi.RSS.HFUNC, &.{ 1, 0 });
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
    list.clearRetainingCapacity();
    try codec.appendAttr(gpa, &list, uapi.RSS.CONTEXT, &.{ 1, 0, 0, 0, 0, 0, 0, 0 });
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
    // INDIR not a multiple of four (truncated last entry).
    list.clearRetainingCapacity();
    try codec.appendAttr(gpa, &list, uapi.RSS.INDIR, &.{ 1, 0, 0, 0, 2, 0 });
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
    // Duplicate INDIR / HKEY must not leak the first copy (testing.allocator checks).
    list.clearRetainingCapacity();
    try appendIndir(gpa, &list, &.{ 0, 1 });
    try appendIndir(gpa, &list, &.{ 0, 1 });
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
    list.clearRetainingCapacity();
    try codec.appendAttr(gpa, &list, uapi.RSS.HKEY, &.{ 1, 2 });
    try codec.appendAttr(gpa, &list, uapi.RSS.HKEY, &.{ 1, 2 });
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
    // Header nest with a bad device-index length.
    list.clearRetainingCapacity();
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    try codec.appendAttr(gpa, &nest, uapi.HEADER.DEV_INDEX, &.{ 1, 2 });
    try codec.appendAttr(gpa, &list, uapi.RSS.HEADER | codec.NLA_F_NESTED, nest.items);
    try testing.expectError(error.BadLength, parseRss(gpa, list.items));
}

test "RSS reply: oversized table (max attribute) decodes without panic" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const big = try gpa.alloc(u8, 65528); // largest u32-multiple that fits one TLV
    defer gpa.free(big);
    @memset(big, 0x01);
    try codec.appendAttr(gpa, &list, uapi.RSS.INDIR, big);
    var r = try parseRss(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expectEqual(@as(usize, 16382), r.indir.len);
    try testing.expectEqual(@as(u32, 0x01010101), r.indir[16381]);
}

test "RSS_GET request: default and explicit context" {
    const gpa = testing.allocator;
    const msg = try buildRss(gpa, 23, 4, .byName("eth0"), null);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.RSS_GET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.RSS.HEADER, h.type & codec.NLA_TYPE_MASK);
    try testing.expect((try it.next()) == null);

    const m2 = try buildRss(gpa, 23, 5, .byIndex(2), 7);
    defer gpa.free(m2);
    var it2: codec.AttrIterator = .{ .buf = m2[20..] };
    _ = (try it2.next()).?;
    const c = (try it2.next()).?;
    try testing.expectEqual(uapi.RSS.CONTEXT, c.type);
    try testing.expectEqual(@as(u32, 7), try c.asU32());
    try testing.expectError(error.InvalidRequest, buildRss(gpa, 23, 1, .byName(""), null));
}
