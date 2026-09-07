// SPDX-License-Identifier: MIT
//! `NL80211_CMD_GET_INTERFACE` decoding — one `Interface` per wireless netdev
//! or wdev the kernel reports.
//!
//! Everything an `Interface` holds is fixed-size (names ≤ `IFNAMSIZ`, SSIDs ≤
//! 32 bytes by the standard), so decoding one allocates nothing; only the
//! *list* returned by a dump is allocated. That matters because a caller
//! polling interface state should not churn the allocator.
//!
//! An nl80211 interface may have **no ifindex at all**: a P2P device
//! (`NL80211_IFTYPE_P2P_DEVICE`) exists only as a wdev id. Both identifiers
//! are therefore optional and `wdev` is the one that is always present.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const Error = codec.Error;

/// Build a `NL80211_CMD_GET_INTERFACE` request: a dump of every interface when
/// `ifindex` is null (`iw dev`), or one interface's state otherwise
/// (`iw dev <dev> info`).
pub fn buildGetInterface(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    ifindex: ?u32,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
    if (ifindex == null) flags |= codec.NLM_F_DUMP;
    const hdr = try codec.appendHeader(gpa, &list, family_id, flags, seq, 0);
    try genl.appendHeader(gpa, &list, uapi.CMD.GET_INTERFACE, uapi.family_version);
    if (ifindex) |i| try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, i);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// One wireless interface as reported by `NL80211_CMD_NEW_INTERFACE`.
pub const Interface = struct {
    /// Netdev index, or null for an interface that has none (P2P device).
    ifindex: ?u32 = null,
    /// The wireless device id — always present, unlike `ifindex`.
    wdev: ?u64 = null,
    /// Index of the wiphy (physical radio) this interface belongs to.
    wiphy: ?u32 = null,
    iftype: uapi.Iftype = .unspecified,
    mac: ?uapi.Mac = null,
    /// Dump generation counter — a changed value between messages of one dump
    /// means the kernel's list mutated mid-walk.
    generation: ?u32 = null,
    /// Operating frequency of the interface's current channel, MHz.
    freq_mhz: ?u32 = null,
    chan_width: ?uapi.ChanWidth = null,
    center_freq1_mhz: ?u32 = null,
    center_freq2_mhz: ?u32 = null,
    /// Transmit power in mBm (100 · dBm).
    tx_power_mbm: ?i32 = null,
    /// True when the interface is in 4-address (WDS) mode.
    use_4addr: ?bool = null,

    name_buf: [uapi.ifnamsiz]u8 = @splat(0),
    name_len: u8 = 0,
    ssid_buf: [uapi.max_ssid_len]u8 = @splat(0),
    ssid_len: u8 = 0,
    ssid_present: bool = false,

    /// Interface name (`wlan0`); empty for an interface with no netdev.
    pub fn name(i: *const Interface) []const u8 {
        return i.name_buf[0..i.name_len];
    }

    /// The SSID the interface is currently associated with, or null when it is
    /// not associated. Verbatim bytes — see `ie.Summary.ssid`.
    pub fn ssid(i: *const Interface) ?[]const u8 {
        return if (i.ssid_present) i.ssid_buf[0..i.ssid_len] else null;
    }

    /// Channel bandwidth in MHz, when the kernel reported a width this module
    /// can map to one.
    pub fn widthMhz(i: *const Interface) ?u16 {
        return (i.chan_width orelse return null).megahertz();
    }
};

/// Decode one `NL80211_CMD_NEW_INTERFACE` message's attribute bytes (i.e. the
/// genl payload past the 4-byte `genlmsghdr`).
pub fn parse(attr_bytes: []const u8) Error!Interface {
    var out: Interface = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.IFINDEX => out.ifindex = try a.asU32(),
        uapi.ATTR.WIPHY => out.wiphy = try a.asU32(),
        uapi.ATTR.IFTYPE => out.iftype = @enumFromInt(try a.asU32()),
        uapi.ATTR.GENERATION => out.generation = try a.asU32(),
        uapi.ATTR.WIPHY_FREQ => out.freq_mhz = try a.asU32(),
        uapi.ATTR.CENTER_FREQ1 => out.center_freq1_mhz = try a.asU32(),
        uapi.ATTR.CENTER_FREQ2 => out.center_freq2_mhz = try a.asU32(),
        uapi.ATTR.CHANNEL_WIDTH => out.chan_width = @enumFromInt(try a.asU32()),
        uapi.ATTR.WIPHY_TX_POWER_LEVEL => out.tx_power_mbm = try a.asI32(),
        uapi.ATTR.WDEV => {
            if (a.data.len != 8) return error.BadLength;
            out.wdev = std.mem.readInt(u64, a.data[0..8], .little);
        },
        uapi.ATTR.MAC => {
            if (a.data.len != 6) return error.BadLength;
            out.mac = a.data[0..6].*;
        },
        uapi.ATTR.IFNAME => {
            const s = a.asString();
            // A name longer than IFNAMSIZ cannot come from the kernel; treat it
            // as a bad reply rather than silently truncating an identifier.
            if (s.len >= uapi.ifnamsiz) return error.BadLength;
            @memcpy(out.name_buf[0..s.len], s);
            out.name_len = @intCast(s.len);
        },
        uapi.ATTR.SSID => {
            // SSIDs are raw bytes with no terminator; the 802.11 ceiling is 32.
            if (a.data.len > uapi.max_ssid_len) return error.BadLength;
            @memcpy(out.ssid_buf[0..a.data.len], a.data);
            out.ssid_len = @intCast(a.data.len);
            out.ssid_present = true;
        },
        // NL80211_ATTR_4ADDR is a u8 boolean.
        uapi.ATTR.@"4ADDR" => out.use_4addr = (try a.asU8()) != 0,
        else => {},
    };
    return out;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parse: a station interface with an association" {
    // Hand-built in the shape the kernel emits (the real capture is exercised
    // byte-for-byte in goldens.zig).
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const gpa = testing.allocator;
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.IFINDEX, 3);
    try codec.appendAttrString(gpa, &buf, uapi.ATTR.IFNAME, "wlan0");
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.WIPHY, 0);
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.IFTYPE, 2); // station
    try codec.appendAttr(gpa, &buf, uapi.ATTR.WDEV, &.{ 1, 0, 0, 0, 0, 0, 0, 0 });
    try codec.appendAttr(gpa, &buf, uapi.ATTR.MAC, &.{ 0x02, 0, 0, 0x11, 0x22, 0x33 });
    try codec.appendAttr(gpa, &buf, uapi.ATTR.SSID, "example-net");
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.WIPHY_FREQ, 5500);
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.CHANNEL_WIDTH, 3); // 80 MHz
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.CENTER_FREQ1, 5530);

    const i = try parse(buf.items);
    try testing.expectEqual(@as(?u32, 3), i.ifindex);
    try testing.expectEqualStrings("wlan0", i.name());
    try testing.expectEqual(uapi.Iftype.station, i.iftype);
    try testing.expectEqual(@as(?u64, 1), i.wdev);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0x11, 0x22, 0x33 }, &i.mac.?);
    try testing.expectEqualStrings("example-net", i.ssid().?);
    try testing.expectEqual(@as(?u32, 5500), i.freq_mhz);
    try testing.expectEqual(@as(?u16, 80), i.widthMhz());
    try testing.expectEqual(@as(?u32, 5530), i.center_freq1_mhz);
}

test "parse: a P2P device has a wdev but no ifindex or name" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const gpa = testing.allocator;
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.WIPHY, 0);
    try codec.appendAttrU32(gpa, &buf, uapi.ATTR.IFTYPE, 10); // p2p_device
    try codec.appendAttr(gpa, &buf, uapi.ATTR.WDEV, &.{ 2, 0, 0, 0, 0, 0, 0, 0 });

    const i = try parse(buf.items);
    try testing.expectEqual(@as(?u32, null), i.ifindex);
    try testing.expectEqual(@as(usize, 0), i.name().len);
    try testing.expectEqual(@as(?u64, 2), i.wdev);
    try testing.expectEqual(uapi.Iftype.p2p_device, i.iftype);
    try testing.expectEqual(@as(?[]const u8, null), i.ssid());
}

test "parse: malformed attributes yield typed errors, never a panic" {
    // Truncated TLV.
    try testing.expectError(error.Truncated, parse(&.{ 0x08, 0x00 }));
    // IFINDEX with a 2-byte payload.
    try testing.expectError(error.BadLength, parse(&.{ 0x06, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00 }));
    // WDEV with 4 bytes instead of 8.
    try testing.expectError(error.BadLength, parse(&.{ 0x08, 0x00, 0x99, 0x00, 1, 0, 0, 0 }));
    // MAC with 5 bytes.
    try testing.expectError(error.BadLength, parse(&.{ 0x09, 0x00, 0x06, 0x00, 1, 2, 3, 4, 5, 0, 0, 0 }));
    // SSID longer than the 802.11 ceiling.
    var too_long: [4 + 40]u8 = @splat(0x41);
    std.mem.writeInt(u16, too_long[0..2], 44, .little);
    std.mem.writeInt(u16, too_long[2..4], uapi.ATTR.SSID, .little);
    try testing.expectError(error.BadLength, parse(&too_long));
}

test "parse: an empty attribute list is a valid, empty interface" {
    const i = try parse(&.{});
    try testing.expectEqual(@as(?u32, null), i.ifindex);
    try testing.expectEqual(uapi.Iftype.unspecified, i.iftype);
}

/// GET_INTERFACE reply attribute lists for `fuzzParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by `codec`'s own encoders, the way the value tests
/// above build theirs, rather than quoted as hex: an nl80211 attribute is a
/// netlink TLV, whose length and scalars are HOST byte order, so a hex corpus
/// would be a little-endian one and the counts pinned below would be false on
/// a big-endian target instead of failing there.
const Corpus = struct {
    scratch: [4096]u8 = undefined,
    store: [4096]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
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

        // A station interface with an association, in the shape the kernel
        // emits (the real capture is exercised byte-for-byte in goldens.zig).
        var sta: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.IFINDEX, 3);
        try codec.appendAttrString(gpa, &sta, uapi.ATTR.IFNAME, "wlan0");
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.IFTYPE, 2);
        try codec.appendAttr(gpa, &sta, uapi.ATTR.WDEV, &.{ 1, 0, 0, 0, 0, 0, 0, 0 });
        try codec.appendAttr(gpa, &sta, uapi.ATTR.MAC, &.{ 0x02, 0, 0, 0x11, 0x22, 0x33 });
        try codec.appendAttr(gpa, &sta, uapi.ATTR.SSID, "example-net");
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.WIPHY_FREQ, 5500);
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.CHANNEL_WIDTH, 3);
        try codec.appendAttrU32(gpa, &sta, uapi.ATTR.CENTER_FREQ1, 5530);
        self.push(sta.items);

        // A P2P device: a wdev, no ifindex and no name.
        var p2p: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &p2p, uapi.ATTR.WIPHY, 0);
        try codec.appendAttrU32(gpa, &p2p, uapi.ATTR.IFTYPE, 10);
        try codec.appendAttr(gpa, &p2p, uapi.ATTR.WDEV, &.{ 2, 0, 0, 0, 0, 0, 0, 0 });
        self.push(p2p.items);

        // An AP with a name and nothing else.
        var ap: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &ap, uapi.ATTR.IFINDEX, 4);
        try codec.appendAttrString(gpa, &ap, uapi.ATTR.IFNAME, "wlan1");
        try codec.appendAttrU32(gpa, &ap, uapi.ATTR.IFTYPE, 3);
        self.push(ap.items);

        // ── the refusals ───────────────────────────────────────────────────
        // A TLV header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 });
        // MAC of the wrong width, and a WDEV that is not eight octets.
        var bad_mac: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &bad_mac, uapi.ATTR.MAC, &.{ 1, 2, 3 });
        self.push(bad_mac.items);
        var bad_wdev: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &bad_wdev, uapi.ATTR.WDEV, 1);
        self.push(bad_wdev.items);

        return self.entries[0..self.n];
    }
};

test "fuzz: interface parse never crashes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzParse, .{ .corpus = try corpus.build() });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an empty attribute list, with
    // the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: an interface with no
    // attributes at all is a legal reply — every field is optional — so
    // `parse("")` succeeds. Measured 2026-09-07 over the corpus above: **0 of
    // 6 seeds non-empty and 6 of 6 "parsed" before; 6 of 6 non-empty, 3 parsed
    // and 3 of them carrying an iftype after.**
    const len: usize = smith.slice(&raw);
    if (parse(raw[0..len])) |i| std.mem.doNotOptimizeAway(&i) else |_| {}
}

test "corpus: every interface seed reaches the parser, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here, so "parsed" alone counts a harness that walks nothing as a
    // success.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var typed: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [256]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        if (parse(raw[0..len])) |i| {
            parsed += 1;
            if (i.iftype != .unspecified) typed += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), parsed);
    try testing.expectEqual(@as(usize, 3), typed);
}
