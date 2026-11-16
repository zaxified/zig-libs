// SPDX-License-Identifier: MIT
//! `TSINFO_GET` — timestamping capabilities (`ethtool -T <dev>`), the first
//! stop when setting up PTP.
//!
//! The reply carries three capability bitsets and the PTP hardware clock:
//!
//! * `timestamping` — `SOF_TIMESTAMPING_*` flags (`ETH_SS_SOF_TIMESTAMPING`:
//!   `"hardware-transmit"`, `"software-receive"`, `"hardware-raw-clock"`, …).
//! * `tx_types` — hardware transmit timestamp modes (`off`, `on`, `onestep-sync`, …).
//! * `rx_filters` — hardware receive filters (`none`, `all`, `ptpv2-event`, …).
//! * `phc_index` — `/dev/ptp<N>`; **absent** when the device has no PTP clock,
//!   which `ethtool -T` prints as "none". That is why it is optional here and
//!   not defaulted to 0 (clock 0 is a real clock).
//!
//! All three bitsets are plain capability lists. With a verbose reply they
//! carry the kernel's names; with a compact one, bare bit numbers, resolved
//! through `Ethtool.stringSet` (`.sof_timestamping`, `.ts_tx_types`,
//! `.ts_rx_filters`). Unprivileged. Newer kernels add per-device statistics
//! and a hardware-timestamp-provider nest; those are not decoded here and
//! stay reachable through `Ethtool.raw`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};

/// `ETHTOOL_MSG_TSINFO_GET` reply. Owns its bitsets — free with `deinit`.
pub const TsInfo = struct {
    device: header.Device = .{},
    timestamping: ?bitset.Bitset = null,
    tx_types: ?bitset.Bitset = null,
    rx_filters: ?bitset.Bitset = null,
    /// PTP hardware clock index; null = the device has none.
    phc_index: ?u32 = null,

    pub fn deinit(t: *TsInfo, gpa: std.mem.Allocator) void {
        inline for (.{ "timestamping", "tx_types", "rx_filters" }) |name| {
            if (@field(t, name)) |*b| b.deinit(gpa);
        }
        t.* = .{};
    }

    /// Does the device have a PTP hardware clock?
    pub fn hasPhc(t: TsInfo) bool {
        return t.phc_index != null;
    }
};

pub fn parseTsInfo(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!TsInfo {
    var out: TsInfo = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TSINFO.HEADER => out.device = try header.parse(a.data),
        uapi.TSINFO.TIMESTAMPING => try parseOnce(gpa, &out.timestamping, a.data),
        uapi.TSINFO.TX_TYPES => try parseOnce(gpa, &out.tx_types, a.data),
        uapi.TSINFO.RX_FILTERS => try parseOnce(gpa, &out.rx_filters, a.data),
        uapi.TSINFO.PHC_INDEX => out.phc_index = try a.asU32(),
        else => {},
    };
    return out;
}

/// A bitset attribute may appear once; a second one is a malformed reply (and
/// must not leak the first).
fn parseOnce(gpa: std.mem.Allocator, slot: *?bitset.Bitset, data: []const u8) Error!void {
    if (slot.* != null) return error.BadLength;
    slot.* = try bitset.parse(gpa, data);
}

/// Encode a complete `ETHTOOL_MSG_TSINFO_GET` request. `form` picks the bitset
/// encoding of the reply. `Ethtool.tsInfo` sends exactly this.
pub fn buildTsInfo(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.TSINFO_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.TSINFO.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "TSINFO reply: the three capability sets and the PHC index" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.TSINFO.HEADER, .{ .target = .byIndex(2) });
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.TIMESTAMPING, 32, &.{0b1_0101}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.TX_TYPES, 4, &.{0b0011}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 16, &.{0b1}, null);
    try codec.appendAttrU32(gpa, &list, uapi.TSINFO.PHC_INDEX, 0);

    var t = try parseTsInfo(gpa, list.items);
    defer t.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), t.device.index);
    try testing.expect(t.hasPhc());
    try testing.expectEqual(@as(?u32, 0), t.phc_index); // clock 0 is a clock
    try testing.expect(t.timestamping.?.isSet(0) and !t.timestamping.?.isSet(1) and t.timestamping.?.isSet(2));
    try testing.expectEqual(@as(u32, 3), t.timestamping.?.count());
    try testing.expectEqual(@as(u32, 2), t.tx_types.?.count());
    try testing.expect(t.rx_filters.?.isSet(0));
}

test "TSINFO reply: no PHC is null; a verbose reply keeps its names" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendNameList(gpa, &list, uapi.TSINFO.TIMESTAMPING, &.{ "software-transmit", "software-receive" });
    var t = try parseTsInfo(gpa, list.items);
    defer t.deinit(gpa);
    try testing.expect(!t.hasPhc());
    try testing.expect(t.tx_types == null and t.rx_filters == null);
    try testing.expectEqual(@as(?bool, true), t.timestamping.?.isSetByName("software-receive"));
    try testing.expectEqual(@as(?bool, false), t.timestamping.?.isSetByName("hardware-transmit"));

    var e = try parseTsInfo(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expect(e.timestamping == null and !e.hasPhc());
}

test "TSINFO reply: malformed input is a typed error and leaks nothing" {
    const gpa = testing.allocator;
    // PHC_INDEX with one byte.
    try testing.expectError(error.BadLength, parseTsInfo(gpa, &.{ 0x05, 0x00, 0x05, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseTsInfo(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 8, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 8, &.{1}, null);
    try testing.expectError(error.BadLength, parseTsInfo(gpa, list.items));
}

test "TSINFO_GET request: command, device, compact flag" {
    const gpa = testing.allocator;
    const msg = try buildTsInfo(gpa, 23, 8, .byName("eth0"), .compact);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.TSINFO_GET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.TSINFO.HEADER, h.type & codec.NLA_TYPE_MASK);
    var hit: codec.AttrIterator = .{ .buf = h.data };
    try testing.expectEqualStrings("eth0", (try hit.next()).?.asString());
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS, try (try hit.next()).?.asU32());
    try testing.expect((try it.next()) == null);
    try testing.expectError(error.InvalidRequest, buildTsInfo(gpa, 23, 8, .byName(""), .verbose));
}
