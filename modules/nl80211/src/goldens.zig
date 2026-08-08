// SPDX-License-Identifier: MIT
//! Byte-exact goldens captured from a real `iw` (v6.17) on Linux 7.0, plus the
//! kernel replies it received, decoded back through this module.
//!
//! ## How the request goldens were captured
//!
//! ```sh
//! strace -f -e trace=sendmsg -e write=all -xx -s 8192 -e abbrev=none \
//!     iw dev <dev> scan trigger
//! ```
//!
//! `-e write=all` dumps the exact `sendmsg` payload with no re-encoding step
//! in between, so what is asserted here is literally the bytes `iw` handed the
//! kernel. The exact command line sits next to every golden below. (This is
//! the harness the sibling `tc` module proved out — same flags, different
//! tool.)
//!
//! Two fields of a captured request are runtime values rather than encoding:
//!
//! * **`nlmsg_pid`** — the sender's netlink port id, assigned by the kernel at
//!   `bind` time. This module always writes 0 there (the kernel fills it in),
//!   so `expectSameRequest` zeroes it in the captured bytes too.
//! * **`nlmsg_seq`** — per-socket. Each test simply builds with the sequence
//!   number the capture happened to use.
//!
//! Everything else — length, message type, flags, the `genlmsghdr`, and every
//! attribute with its exact type, length, order and padding — is compared byte
//! for byte.
//!
//! The nl80211 family id in every capture is **41 (0x29)**. That is *not* a
//! constant: it is whatever nlctrl assigned on that boot, which is exactly why
//! `client.zig` resolves it at runtime. The goldens simply pass 41 in.
//!
//! ## What could not be captured from `iw`
//!
//! `iw connect` supports only open and **WEP** networks — it has no WPA mode,
//! because on ordinary mac80211 hardware WPA needs a userspace supplicant (see
//! `connect.zig`'s header). So the WPA2 attributes (`WPA_VERSIONS`,
//! `CIPHER_SUITES_PAIRWISE`, `CIPHER_SUITE_GROUP`, `AKM_SUITES`, `PMK`,
//! `USE_MFP`, `WANT_1X_4WAY_HS`) have **no `iw` golden**; they are derived
//! from `linux/nl80211.h` and covered by the round-trip tests in
//! `connect.zig`. Everything else below came off the wire.
//!
//! **UNANCHORED (wave-2 F7, 2026-08-08):** a real `wpa_supplicant` WPA2-PSK
//! `CONNECT` capture (the fix this finding names — `strace` the same way
//! the three goldens above it were captured) was attempted and found
//! impractical in this environment: no root/`CAP_NET_ADMIN` to bring up
//! `mac80211_hwsim` (`modprobe` refused: "Operation not permitted"), and the
//! one real WPA2-associated interface on this host is live infrastructure a
//! test run must not touch. What *is* verified: `scripts/check-uapi-consts.py
//! nl80211` (the standing check `nl80211` F3 added) diffs every constant in
//! `uapi.zig`, WPA attributes included, against this host's
//! `/usr/include/linux/nl80211.h` on every run — `WPA_VERSIONS`=75,
//! `CIPHER_SUITES_PAIRWISE`=73, `CIPHER_SUITE_GROUP`=74, `AKM_SUITES`=76,
//! `PREV_BSSID`=79, `SOCKET_OWNER`=204, `PMK`=254, `WANT_1X_4WAY_HS`=257,
//! `USE_MFP`=66 all currently MATCHED. So the attribute *numbers* are
//! standing-checked; what remains unverified is the *set, order and payload
//! shape* of a real WPA2-PSK `CONNECT` message — genuinely different from
//! "nothing was checked."
//!
//! ## How the reply goldens were captured
//!
//! ```sh
//! strace -f -e trace=recvmsg -e read=all -xx -s 16384 -e abbrev=none \
//!     iw dev <dev> station dump
//! ```
//!
//! …with the duplicate that `MSG_PEEK` produces dropped. These are real kernel
//! replies for a real associated link, so they exercise attribute combinations
//! no hand-written fixture would think of: u64 counters beside their u32
//! twins, a 2100-byte `TID_STATS` nest, a 484-byte IE stream off the air, and
//! a single wiphy split across 75 messages.
//!
//! ## Anonymisation
//!
//! The captures came from a machine with a real Wi-Fi link, so before being
//! committed every reply had these **length-preserving** substitutions
//! applied:
//!
//! | captured | replaced with |
//! |---|---|
//! | the AP's BSSID | `02:00:00:aa:bb:cc` |
//! | the radio's four local MACs | `02:00:00:11:22:33` … `:36` |
//! | the 18-byte SSID | `ZIGLIBS-TEST-AP-01` |
//! | the regulatory alpha2 (`GET_REG` reply + the beacon's Country IE) | `DE` |
//!
//! Every replacement MAC is locally administered (bit 1 of the first octet)
//! and so cannot collide with a real vendor address. The interface name
//! `wlp2s0` was deliberately kept: it is a udev bus-path name (PCI 02:00.0),
//! carries no identity, and keeping it makes the capture commands in the
//! comments reproducible. Nothing else was touched:
//! lengths, offsets, padding, counters and all other attributes are exactly as
//! the kernel sent them, which is what makes the decode assertions meaningful.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");

const uapi = @import("uapi.zig");
const ie = @import("ie.zig");
const iface = @import("iface.zig");
const station = @import("station.zig");
const wiphy = @import("wiphy.zig");
const scan = @import("scan.zig");
const connect = @import("connect.zig");
const reg = @import("reg.zig");
const client = @import("client.zig");

/// The family id nlctrl handed out on the machine the captures came from.
/// Dynamic in reality — see the file header.
const fam: u16 = 41;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(20 * s.len + 1000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Compare a request this module built against bytes captured from `iw`,
/// ignoring only `nlmsg_pid` (a runtime port id — see the file header).
fn expectSameRequest(captured: []const u8, ours: []const u8) !void {
    try testing.expectEqual(captured.len, ours.len);
    const buf = try testing.allocator.dupe(u8, captured);
    defer testing.allocator.free(buf);
    @memset(buf[12..16], 0); // nlmsg_pid
    try testing.expectEqualSlices(u8, buf, ours);
}

/// Netlink is host-endian, so these little-endian goldens only mean anything
/// on a little-endian host.
fn skipUnlessLittleEndian() !void {
    if (native_endian != .little) return error.SkipZigTest;
}

// ── request goldens (byte-exact vs `iw`) ───────────────────────────────────

test "golden: nlctrl CTRL_CMD_GETFAMILY for \"nl80211\"" {
    // strace -f -e trace=sendmsg -e write=all -xx -s 8192 -e abbrev=none \
    //     iw dev wlp2s0 scan trigger          [message 1 of 2]
    try skipUnlessLittleEndian();
    const captured = hex(
        "2000000010000500522d9f9546b5dc75" ++
            "030100000c0002006e6c383032313100",
    );
    const req = try genl.buildGetFamilyRequest(testing.allocator, 0x959f_2d52, uapi.family_name);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_WIPHY split dump" {
    // strace … iw list                        [the GET_WIPHY message]
    try skipUnlessLittleEndian();
    const captured = hex(
        "1800000029000503292d9f9580b71c8b" ++
            "01000000" ++ // genlmsghdr: cmd 1 (GET_WIPHY), version 0
            "0400ae00", // NL80211_ATTR_SPLIT_WIPHY_DUMP, zero-length flag
    );
    const req = try wiphy.buildGetWiphy(testing.allocator, fam, 0x959f_2d29, true);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_INTERFACE dump" {
    // strace … iw dev
    try skipUnlessLittleEndian();
    const captured = hex(
        "1400000029000503282d9f958ab71c8b" ++
            "05000000",
    );
    const req = try iface.buildGetInterface(testing.allocator, fam, 0x959f_2d28, null);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_INTERFACE for one interface" {
    // strace … iw dev wlp2s0 info
    try skipUnlessLittleEndian();
    const captured = hex(
        "1c00000029000500282d9f959eb71c8b" ++
            "05000000" ++
            "0800030003000000", // NL80211_ATTR_IFINDEX = 3
    );
    const req = try iface.buildGetInterface(testing.allocator, fam, 0x959f_2d28, 3);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_STATION dump" {
    // strace … iw dev wlp2s0 station dump
    try skipUnlessLittleEndian();
    const captured = hex(
        "1c00000029000503282d9f9594b71c8b" ++
            "11000000" ++
            "0800030003000000",
    );
    const req = try station.buildGetStation(testing.allocator, fam, 0x959f_2d28, 3, null);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_STATION for one peer (the second half of `iw link`)" {
    // strace … iw dev wlp2s0 link             [message 3 of 3]
    // The MAC is the associated AP's BSSID — anonymised, see the file header.
    try skipUnlessLittleEndian();
    const captured = hex(
        "2800000029000500292d9f958fb71c8b" ++
            "11000000" ++
            "0800030003000000" ++ // IFINDEX = 3
            "0a000600020000aabbcc0000", // MAC, 6 bytes + 2 pad
    );
    const req = try station.buildGetStation(
        testing.allocator,
        fam,
        0x959f_2d29,
        3,
        .{ 0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc },
    );
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_SCAN dump (the first half of `iw link`)" {
    // strace … iw dev wlp2s0 scan dump
    try skipUnlessLittleEndian();
    const captured = hex(
        "1c00000029000503282d9f9599b71c8b" ++
            "20000000" ++
            "0800030003000000",
    );
    const req = try scan.buildGetScan(testing.allocator, fam, 0x959f_2d28, 3);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: TRIGGER_SCAN, plain (wildcard SSID + colocated-6GHz flag)" {
    // strace … iw dev wlp2s0 scan trigger     [message 2 of 2]
    try skipUnlessLittleEndian();
    const captured = hex(
        "2c00000029000500532d9f9546b5dc75" ++
            "21000000" ++ // cmd 33 = TRIGGER_SCAN
            "0800030003000000" ++ // IFINDEX = 3
            "08002d00" ++ "04000100" ++ // SCAN_SSIDS { [1] = "" }
            "08009e00" ++ "00400000", // SCAN_FLAGS = COLOCATED_6GHZ
    );
    const req = try scan.buildTriggerScan(testing.allocator, fam, 0x959f_2d53, .{
        .ifindex = 3,
        .ssids = scan.wildcard_ssids,
        .flags = uapi.SCAN_FLAG.COLOCATED_6GHZ,
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: TRIGGER_SCAN restricted to two channels" {
    // strace … iw dev wlp2s0 scan trigger freq 2412 2437
    // Note `iw` omits SCAN_FLAGS once the frequency list restricts the scan.
    try skipUnlessLittleEndian();
    const captured = hex(
        "3800000029000500c72c9f956dbbdc92" ++
            "21000000" ++
            "0800030003000000" ++
            "08002d00" ++ "04000100" ++ // SCAN_SSIDS { [1] = "" }
            "14002c00" ++ // SCAN_FREQUENCIES nest, 20 bytes
            "080001006c090000" ++ // [1] = 2412
            "0800020085090000", // [2] = 2437
    );
    const req = try scan.buildTriggerScan(testing.allocator, fam, 0x959f_2cc7, .{
        .ifindex = 3,
        .ssids = scan.wildcard_ssids,
        .freqs_mhz = &.{ 2412, 2437 },
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: TRIGGER_SCAN with flush + low priority" {
    // strace … iw dev wlp2s0 scan trigger flush lowpri
    try skipUnlessLittleEndian();
    const captured = hex(
        "2c00000029000500c72c9f9571bbdc92" ++
            "21000000" ++
            "0800030003000000" ++
            "08002d00" ++ "04000100" ++
            "08009e00" ++ "03400000", // FLUSH | LOW_PRIORITY | COLOCATED_6GHZ
    );
    const req = try scan.buildTriggerScan(testing.allocator, fam, 0x959f_2cc7, .{
        .ifindex = 3,
        .ssids = scan.wildcard_ssids,
        .flags = uapi.SCAN_FLAG.COLOCATED_6GHZ |
            uapi.SCAN_FLAG.FLUSH |
            uapi.SCAN_FLAG.LOW_PRIORITY,
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: TRIGGER_SCAN with a named SSID (raw bytes, not a C string)" {
    // strace … iw dev wlp2s0 scan trigger ssid TestNet
    // nla_len is 11 = 4 + 7: the trailing 0x00 is alignment padding, NOT a
    // terminator. Getting this wrong sends an 8-byte SSID.
    try skipUnlessLittleEndian();
    const captured = hex(
        "3400000029000500c72c9f9575bbdc92" ++
            "21000000" ++
            "0800030003000000" ++
            "10002d00" ++ // SCAN_SSIDS nest, 16 bytes
            "0b000100" ++ "546573744e657400" ++ // [1] = "TestNet" + pad
            "08009e00" ++ "00400000",
    );
    const req = try scan.buildTriggerScan(testing.allocator, fam, 0x959f_2cc7, .{
        .ifindex = 3,
        .ssids = &.{"TestNet"},
        .flags = uapi.SCAN_FLAG.COLOCATED_6GHZ,
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: CONNECT to an open network" {
    // strace … iw dev wlp2s0 connect TestNet
    try skipUnlessLittleEndian();
    const captured = hex(
        "28000000290005000c2d9f95a8b91c9d" ++
            "2e000000" ++ // cmd 46 = CONNECT
            "0800030003000000" ++ // IFINDEX = 3
            "0b003400" ++ "546573744e657400", // SSID = "TestNet"
    );
    const req = try connect.buildConnect(testing.allocator, fam, 0x959f_2d0c, .{
        .ifindex = 3,
        .ssid = "TestNet",
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: CONNECT pinned to a frequency" {
    // strace … iw dev wlp2s0 connect TestNet 2412
    try skipUnlessLittleEndian();
    const captured = hex(
        "30000000290005000c2d9f95afb91c9d" ++
            "2e000000" ++
            "0800030003000000" ++
            "0b003400" ++ "546573744e657400" ++
            "08002600" ++ "6c090000", // WIPHY_FREQ = 2412
    );
    const req = try connect.buildConnect(testing.allocator, fam, 0x959f_2d0c, .{
        .ifindex = 3,
        .ssid = "TestNet",
        .freq_mhz = 2412,
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: CONNECT with a WEP key (the nested ATTR_KEYS shape)" {
    // strace … iw dev wlp2s0 connect TestNet 2412 key 0:abcde
    // The only capture that exercises a doubly-nested request attribute, and
    // the only evidence for NLA_F_NESTED being set on both levels.
    try skipUnlessLittleEndian();
    const captured = hex(
        "5c000000290005000c2d9f95b6b91c9d" ++
            "2e000000" ++
            "0800030003000000" ++
            "0b003400" ++ "546573744e657400" ++
            "08002600" ++ "6c090000" ++
            "04004600" ++ // NL80211_ATTR_PRIVACY, zero-length flag
            "28005180" ++ // ATTR_KEYS (0x51) | NLA_F_NESTED, 40 bytes
            "24000180" ++ //   key [1] | NLA_F_NESTED, 36 bytes
            "0500020000000000" ++ //     NL80211_KEY_IDX = 0 (u8, padded)
            "0800030001ac0f00" ++ //     NL80211_KEY_CIPHER = 00-0F-AC:1 (WEP-40)
            "090001006162636465000000" ++ //  NL80211_KEY_DATA = "abcde"
            "04000500", //     NL80211_KEY_DEFAULT flag
    );
    const req = try connect.buildConnect(testing.allocator, fam, 0x959f_2d0c, .{
        .ifindex = 3,
        .ssid = "TestNet",
        .freq_mhz = 2412,
        .privacy = true,
        .wep_keys = &.{.{ .index = 0, .data = "abcde", .default = true }},
    });
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: DISCONNECT" {
    // strace … iw dev wlp2s0 disconnect
    try skipUnlessLittleEndian();
    const captured = hex(
        "1c00000029000500002d9f95bdb91c9d" ++
            "30000000" ++ // cmd 48 = DISCONNECT
            "0800030003000000",
    );
    const req = try connect.buildDisconnect(testing.allocator, fam, 0x959f_2d00, 3, null);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: GET_REG dump" {
    // strace … iw reg get
    try skipUnlessLittleEndian();
    const captured = hex(
        "1400000029000503282d9f9585b71c8b" ++
            "1f000000", // cmd 31 = GET_REG
    );
    const req = try reg.buildGetReg(testing.allocator, fam, 0x959f_2d28);
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

test "golden: REQ_SET_REG (alpha2 IS NUL-terminated, unlike the SSID)" {
    // strace … iw reg set US
    // nla_len is 7 = 4 + 3: "US" plus a terminator, then one pad byte. The
    // contrast with the SSID attribute above is the whole point of this test.
    try skipUnlessLittleEndian();
    const captured = hex(
        "1c00000029000500d72c9f95f9badc96" ++
            "1b000000" ++ // cmd 27 = REQ_SET_REG
            "07002100" ++ "55530000", // REG_ALPHA2 = "US\0" + pad
    );
    const req = try reg.buildReqSetReg(testing.allocator, fam, 0x959f_2cd7, "US");
    defer testing.allocator.free(req);
    try expectSameRequest(&captured, req);
}

// ── reply goldens (real kernel bytes, decoded) ─────────────────────────────

/// Walk a captured reply datagram and hand each nl80211 family message's
/// command byte + attribute bytes to `f`.
fn eachFamilyMessage(
    dgram: []const u8,
    ctx: anytype,
    comptime f: fn (@TypeOf(ctx), u8, []const u8) anyerror!void,
) !void {
    var it: codec.MessageIterator = .{ .buf = dgram };
    while (try it.next()) |m| {
        if (m.type != fam) continue;
        const p = try genl.splitPayload(m.payload);
        try f(ctx, p.cmd, p.attrs);
    }
}

test "golden reply: the nlctrl family reply carries the id and the mcast groups" {
    try skipUnlessLittleEndian();
    var it: codec.MessageIterator = .{ .buf = &nlctrl_getfamily_reply };
    const m = (try it.next()).?;
    try testing.expectEqual(genl.GENL_ID_CTRL, m.type);
    const p = try genl.splitPayload(m.payload);

    // Family id — 41 on this boot, which is exactly why it is resolved.
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    var family_id: ?u16 = null;
    while (try attrs.next()) |a| {
        if (a.type == uapi.CTRL_ATTR.FAMILY_ID) family_id = try a.asU16();
    }
    try testing.expectEqual(@as(?u16, fam), family_id);

    // The six groups this kernel publishes for nl80211, with the ids it
    // happened to assign.
    try testing.expectEqual(@as(?u32, 22), try client.findMcastGroupId(p.attrs, "config"));
    try testing.expectEqual(@as(?u32, 23), try client.findMcastGroupId(p.attrs, uapi.mcast_group.scan));
    try testing.expectEqual(@as(?u32, 24), try client.findMcastGroupId(p.attrs, "regulatory"));
    try testing.expectEqual(@as(?u32, 25), try client.findMcastGroupId(p.attrs, "mlme"));
    try testing.expectEqual(@as(?u32, 26), try client.findMcastGroupId(p.attrs, "vendor"));
    try testing.expectEqual(@as(?u32, 27), try client.findMcastGroupId(p.attrs, "nan"));
    try testing.expectEqual(@as(?u32, null), try client.findMcastGroupId(p.attrs, "no-such-group"));
}

test "golden reply: GET_INTERFACE dump — a P2P device and an associated station" {
    try skipUnlessLittleEndian();
    var list: std.ArrayList(iface.Interface) = .empty;
    defer list.deinit(testing.allocator);
    const Ctx = struct {
        out: *std.ArrayList(iface.Interface),
        fn on(c: @This(), cmd: u8, attrs: []const u8) anyerror!void {
            try testing.expectEqual(@as(u8, uapi.CMD.NEW_INTERFACE), cmd);
            try c.out.append(testing.allocator, try iface.parse(attrs));
        }
    };
    try eachFamilyMessage(&get_interface_dump_reply, Ctx{ .out = &list }, Ctx.on);
    try testing.expectEqual(@as(usize, 2), list.items.len);

    // A P2P device: wdev only, no ifindex and no name.
    const p2p = &list.items[0];
    try testing.expectEqual(@as(?u32, null), p2p.ifindex);
    try testing.expectEqual(@as(usize, 0), p2p.name().len);
    try testing.expectEqual(uapi.Iftype.p2p_device, p2p.iftype);
    try testing.expectEqual(@as(?u64, 2), p2p.wdev);
    try testing.expectEqual(@as(?u32, 0), p2p.wiphy);
    try testing.expectEqual(@as(?[]const u8, null), p2p.ssid());

    // The managed station, associated on a 80 MHz channel at 5500 MHz.
    const sta = &list.items[1];
    try testing.expectEqual(@as(?u32, 3), sta.ifindex);
    try testing.expectEqualStrings("wlp2s0", sta.name());
    try testing.expectEqual(uapi.Iftype.station, sta.iftype);
    try testing.expectEqual(@as(?u64, 1), sta.wdev);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0x11, 0x22, 0x33 }, &sta.mac.?);
    try testing.expectEqualStrings("ZIGLIBS-TEST-AP-01", sta.ssid().?);
    try testing.expectEqual(@as(?u32, 5500), sta.freq_mhz);
    try testing.expectEqual(uapi.ChanWidth.@"80", sta.chan_width.?);
    try testing.expectEqual(@as(?u16, 80), sta.widthMhz());
    try testing.expectEqual(@as(?u32, 5530), sta.center_freq1_mhz);
    try testing.expectEqual(@as(?i32, 2200), sta.tx_power_mbm); // 22 dBm
    try testing.expectEqual(@as(?bool, false), sta.use_4addr);
}

test "golden reply: GET_STATION dump — 64-bit counters, signed signal, VHT rates" {
    try skipUnlessLittleEndian();
    var found: ?station.Station = null;
    const Ctx = struct {
        out: *?station.Station,
        fn on(c: @This(), cmd: u8, attrs: []const u8) anyerror!void {
            try testing.expectEqual(@as(u8, uapi.CMD.NEW_STATION), cmd);
            c.out.* = try station.parse(attrs);
        }
    };
    try eachFamilyMessage(&get_station_dump_reply, Ctx{ .out = &found }, Ctx.on);
    const s = found.?;

    try testing.expectEqual(@as(?u32, 3), s.ifindex);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc }, &s.mac.?);

    // The 64-bit counters won over the 32-bit ones that arrived first: the
    // u32 RX_BYTES here had already wrapped four times.
    try testing.expectEqual(@as(?u64, 33_915_461_682), s.rx_bytes);
    try testing.expectEqual(@as(?u64, 7_390_653_409), s.tx_bytes);
    try testing.expect(s.rx_bytes.? > std.math.maxInt(u32));
    try testing.expectEqual(@as(?u32, 22_251_405), s.rx_packets);
    try testing.expectEqual(@as(?u32, 19_162_683), s.tx_packets);
    try testing.expectEqual(@as(?u32, 726_147), s.tx_retries);
    try testing.expectEqual(@as(?u32, 66), s.tx_failed);
    try testing.expectEqual(@as(?u32, 6), s.beacon_loss);
    try testing.expectEqual(@as(?u64, 2_062_752), s.beacon_rx);

    // 0xaf / 0xb0 read as signed bytes, not 175 / 176.
    try testing.expectEqual(@as(?i8, -81), s.signal_dbm);
    try testing.expectEqual(@as(?i8, -80), s.signal_avg_dbm);
    try testing.expectEqual(@as(?i8, -81), s.beacon_signal_avg_dbm);

    try testing.expectEqual(@as(?u32, 218_126), s.connected_time_s);
    try testing.expectEqual(@as(?u32, 10), s.inactive_time_ms);

    // The doubly-nested RATE_INFO blocks: VHT-MCS 1/2, NSS 1, 80 MHz, short GI.
    const tx = s.tx_bitrate.?;
    try testing.expectEqual(@as(?u32, 65_000), tx.kilobitsPerSecond()); // 65.0 Mbit/s
    try testing.expectEqual(@as(?u8, 1), tx.vht_mcs);
    try testing.expectEqual(@as(?u8, 1), tx.vht_nss);
    try testing.expect(tx.short_gi);
    try testing.expectEqual(station.RateWidth.mhz_80, tx.width);

    const rx = s.rx_bitrate.?;
    try testing.expectEqual(@as(?u32, 97_600), rx.kilobitsPerSecond()); // 97.6 Mbit/s
    try testing.expectEqual(@as(?u8, 2), rx.vht_mcs);
    try testing.expectEqual(station.RateWidth.mhz_80, rx.width);
}

test "golden reply: GET_SCAN — a BSS and its 484 bytes of real information elements" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var found: ?scan.Bss = null;
    defer if (found) |*b| b.deinit(gpa);
    const Ctx = struct {
        out: *?scan.Bss,
        fn on(c: @This(), cmd: u8, attrs: []const u8) anyerror!void {
            try testing.expectEqual(@as(u8, uapi.CMD.NEW_SCAN_RESULTS), cmd);
            c.out.* = (try scan.parseBss(testing.allocator, attrs)).?;
        }
    };
    try eachFamilyMessage(&get_scan_reply, Ctx{ .out = &found }, Ctx.on);
    const b = found.?;

    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc }, &b.bssid.?);
    try testing.expectEqual(@as(?u32, 5500), b.freq_mhz);
    try testing.expectEqual(@as(?i32, -8100), b.signal_mbm);
    try testing.expectEqual(@as(?i32, -81), b.signalDbm());
    try testing.expectEqual(@as(?u16, 0x1111), b.capability);
    try testing.expectEqual(@as(?u16, 100), b.beacon_interval_tu);
    try testing.expectEqual(uapi.BssStatus.associated, b.status.?);
    try testing.expectEqual(@as(?u32, 10_264), b.seen_ms_ago);
    // The kernel supplied both probe-response and beacon IE streams.
    try testing.expect(b.presp_data);
    try testing.expectEqual(@as(usize, 484), b.ies.len);
    try testing.expectEqual(@as(usize, 382), b.beacon_ies.len);

    // …and the information elements decode.
    const s = b.elements();
    try testing.expect(!s.truncated);
    try testing.expectEqualStrings("ZIGLIBS-TEST-AP-01", s.ssid);
    try testing.expect(!s.hidden_ssid);
    try testing.expectEqualStrings("DE ", s.country.?);
    try testing.expect(s.ht);
    try testing.expect(s.vht);
    try testing.expect(s.he);

    // The rates element: 6, 9, 12, 18, 24, 36, 48, 54 Mbit/s, the first four
    // in the basic set.
    var rates: station.RateInfo = undefined;
    _ = &rates;
    var rit: ie.RateIterator = .{ .body = s.supported_rates };
    const first = rit.next().?;
    try testing.expect(first.basic);
    try testing.expectEqual(@as(u32, 6000), first.kilobitsPerSecond());
    var n: usize = 1;
    while (rit.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 8), n);

    // The RSN element: WPA2-PSK with CCMP everywhere.
    const rsn = s.rsn.?;
    try testing.expectEqual(@as(u16, 1), rsn.version);
    try testing.expectEqual(uapi.CIPHER.CCMP, rsn.group_cipher);
    try testing.expectEqualSlices(u32, &.{uapi.CIPHER.CCMP}, rsn.pairwise.slice());
    try testing.expectEqualSlices(u32, &.{uapi.AKM.PSK}, rsn.akm.slice());
    try testing.expect(rsn.offersPsk());
    try testing.expect(!rsn.offersSae());
    try testing.expectEqual(ie.Security.wpa2_psk, s.security(b.capability));

    // This AP is RSN-only: no pre-standard WPA1 vendor element. It does carry
    // Microsoft vendor elements — WPS (type 4) and WMM (type 2) — which is
    // exactly the case `findVendor` has to tell apart from WPA1 (type 1).
    try testing.expectEqual(@as(?ie.Rsn, null), s.wpa1);
    try testing.expectEqual(
        @as(?[]const u8, null),
        ie.findVendor(b.ies, ie.oui_microsoft, ie.vendor_type_wpa),
    );
    try testing.expect(ie.findVendor(b.ies, ie.oui_microsoft, 4) != null); // WPS
    try testing.expect(ie.findVendor(b.ies, ie.oui_microsoft, 2) != null); // WMM
}

test "golden reply: GET_REG — the world domain plus this radio's country domain" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var list: std.ArrayList(reg.RegDomain) = .empty;
    defer {
        for (list.items) |*d| d.deinit(gpa);
        list.deinit(gpa);
    }
    const Ctx = struct {
        out: *std.ArrayList(reg.RegDomain),
        fn on(c: @This(), cmd: u8, attrs: []const u8) anyerror!void {
            try testing.expectEqual(@as(u8, uapi.CMD.GET_REG), cmd);
            try c.out.append(testing.allocator, try reg.parse(testing.allocator, attrs));
        }
    };
    try eachFamilyMessage(&get_reg_reply, Ctx{ .out = &list }, Ctx.on);
    try testing.expectEqual(@as(usize, 2), list.items.len);

    const world = list.items[0];
    try testing.expect(world.isWorld());
    try testing.expectEqualStrings("00", &world.alpha2);
    try testing.expectEqual(@as(?u32, null), world.wiphy);
    try testing.expectEqual(@as(usize, 9), world.rules.len);
    // The 2.4 GHz rule: 2402–2472 MHz, 40 MHz wide, 20 dBm, no flags.
    const g = world.ruleFor(2412).?;
    try testing.expectEqual(@as(u32, 2402), g.startMhz());
    try testing.expectEqual(@as(u32, 2472), g.endMhz());
    try testing.expectEqual(@as(u32, 40), g.maxBandwidthMhz());
    try testing.expectEqual(@as(u32, 20), g.maxEirpDbm());
    try testing.expectEqual(@as(u32, 2_402_000), g.start_khz); // kHz, not MHz

    // The per-wiphy country domain, tagged with the radio it belongs to.
    const country = list.items[1];
    try testing.expectEqualStrings("DE", &country.alpha2);
    try testing.expect(!country.isWorld());
    try testing.expectEqual(@as(?u32, 0), country.wiphy);
    try testing.expectEqual(@as(usize, 28), country.rules.len);
    const c = country.ruleFor(2412).?;
    try testing.expectEqual(@as(u32, 22), c.maxEirpDbm());
    try testing.expectEqual(@as(u32, 600), c.max_antenna_gain_mbi);
}

test "golden reply: GET_WIPHY — one radio reassembled from 75 split messages" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var parser: wiphy.Parser = .init(gpa);
    defer parser.deinit();

    var msg_count: usize = 0;
    var it: codec.MessageIterator = .{ .buf = &get_wiphy_split_dump };
    while (try it.next()) |m| {
        if (m.type != fam) continue;
        const p = try genl.splitPayload(m.payload);
        try testing.expectEqual(@as(u8, uapi.CMD.NEW_WIPHY), p.cmd);
        try parser.feed(p.attrs);
        msg_count += 1;
    }
    // The single defining fact about a split dump: many messages, one radio.
    try testing.expectEqual(@as(usize, 75), msg_count);

    const list = try parser.finish();
    defer wiphy.freeAll(gpa, list);
    try testing.expectEqual(@as(usize, 1), list.len);

    const w = &list[0];
    try testing.expectEqual(@as(u32, 0), w.index);
    try testing.expectEqualStrings("phy0", w.name());
    try testing.expectEqual(@as(?u8, 20), w.max_num_scan_ssids);
    try testing.expectEqual(@as(?u8, 20), w.max_num_sched_scan_ssids);
    try testing.expectEqual(@as(?u16, 413), w.max_scan_ie_len);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0x11, 0x22, 0x33 }, &w.mac.?);

    // Ciphers, in the order the kernel listed them.
    try testing.expectEqualSlices(u32, &.{
        uapi.CIPHER.WEP40,
        uapi.CIPHER.WEP104,
        uapi.CIPHER.TKIP,
        uapi.CIPHER.CCMP,
        uapi.CIPHER.AES_CMAC,
    }, w.ciphers);
    try testing.expect(w.supportsCipher(uapi.CIPHER.CCMP));
    try testing.expect(!w.supportsCipher(uapi.CIPHER.GCMP_256));

    // Interface types.
    try testing.expect(w.supportsIftype(.station));
    try testing.expect(w.supportsIftype(.ap));
    try testing.expect(w.supportsIftype(.monitor));
    try testing.expect(w.supportsIftype(.p2p_device));
    try testing.expect(!w.supportsIftype(.mesh_point));
    // AP_VLAN and monitor are the software-only ones on this radio.
    try testing.expectEqual(
        (@as(u32, 1) << @intFromEnum(uapi.Iftype.ap_vlan)) |
            (@as(u32, 1) << @intFromEnum(uapi.Iftype.monitor)),
        w.software_iftypes,
    );

    // NL80211_ATTR_SUPPORTED_COMMANDS is a *partial* advertisement — the
    // kernel lists the MLME-ish commands a driver opted into, and notably does
    // NOT list TRIGGER_SCAN even on a radio that scans perfectly well. So
    // `supportsCommand` answers "is it advertised", not "is it possible"; scan
    // capability is inferred from `max_num_scan_ssids` instead. Pinned here so
    // the caveat cannot quietly stop being true.
    try testing.expectEqual(@as(usize, 33), w.commands.len);
    try testing.expect(w.supportsCommand(uapi.CMD.CONNECT));
    try testing.expect(w.supportsCommand(uapi.CMD.AUTHENTICATE));
    try testing.expect(w.supportsCommand(uapi.CMD.ASSOCIATE));
    try testing.expect(!w.supportsCommand(uapi.CMD.TRIGGER_SCAN));
    try testing.expect(w.max_num_scan_ssids.? > 0);

    // Two bands, merged out of the dribble of one-channel-per-message.
    try testing.expectEqual(@as(usize, 2), w.bands.len);
    try testing.expectEqual(@as(usize, 51), w.channelCount());

    const b24 = w.band(0).?;
    try testing.expectEqual(@as(usize, 14), b24.freqs.len);
    try testing.expect(b24.ht);
    try testing.expect(!b24.vht);
    // 802.11b/g legacy rates, in 100 kbit/s units.
    try testing.expectEqualSlices(u32, &.{ 10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540 }, b24.rates);
    try testing.expectEqual(@as(u32, 2412), b24.freqs[0].freq_mhz);
    try testing.expectEqual(@as(?u32, 2200), b24.freqs[0].max_tx_power_mbm);
    try testing.expect(b24.freqs[0].usable());
    // Channel 14 (2484 MHz) is Japan-only and disabled in this regdomain.
    try testing.expectEqual(@as(u32, 2484), b24.freqs[13].freq_mhz);
    try testing.expect(b24.freqs[13].disabled);
    try testing.expect(!b24.freqs[13].usable());

    const b5 = w.band(1).?;
    try testing.expectEqual(@as(usize, 37), b5.freqs.len);
    try testing.expect(b5.vht);
    // 5180 MHz: usable but passive-only (NO_IR) under this regdomain.
    const ch36 = w.frequency(5180).?;
    try testing.expect(ch36.no_ir);
    try testing.expect(!ch36.disabled);
    // The 6 GHz band is absent on this radio.
    try testing.expectEqual(@as(?*const wiphy.Band, null), w.band(3));
    try testing.expectEqual(@as(?*const wiphy.Frequency, null), w.frequency(6115));
}

test "golden reply: the captured beacon's IE stream survives hostile truncation" {
    // Every prefix of a real 484-byte IE stream must either decode or report a
    // typed error — never read out of bounds, never loop.
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var found: ?scan.Bss = null;
    defer if (found) |*b| b.deinit(gpa);
    const Ctx = struct {
        out: *?scan.Bss,
        fn on(c: @This(), _: u8, attrs: []const u8) anyerror!void {
            c.out.* = (try scan.parseBss(testing.allocator, attrs)).?;
        }
    };
    try eachFamilyMessage(&get_scan_reply, Ctx{ .out = &found }, Ctx.on);
    const ies = found.?.ies;

    var cut: usize = 0;
    while (cut <= ies.len) : (cut += 1) {
        const s = ie.summarize(ies[0..cut]);
        std.mem.doNotOptimizeAway(&s);
        var it: ie.Iterator = .{ .buf = ies[0..cut] };
        var steps: usize = 0;
        while (it.next() catch null) |_| {
            steps += 1;
            try testing.expect(steps <= cut / 2 + 1); // the ≥2-byte advance rule
        }
    }
    // Also: every single-byte corruption must be survivable.
    var i: usize = 0;
    while (i < ies.len) : (i += 7) {
        const orig = ies[i];
        ies[i] = 0xff;
        const s = ie.summarize(ies);
        std.mem.doNotOptimizeAway(&s);
        ies[i] = orig;
    }
}

// ── captured bytes ─────────────────────────────────────────────────────────
// See the file header for the capture commands and the anonymisation table.

/// Reply to `CTRL_CMD_GETFAMILY("nl80211")` — family id + the six multicast
/// groups. Captured from `iw reg get` (every `iw` invocation starts with it).
const nlctrl_getfamily_reply = hex("fc09000010000000b72c9f95d6bb1caf010200000c0002006e6c383032313100" ++
    "060001002900000008000300010000000800040000000000080005005c010000" ++
    "28090600140001000800010001000000080002000e0000001400020008000100" ++
    "02000000080002001a000000140003000800010005000000080002000e000000" ++
    "140004000800010006000000080002001a000000140005000800010007000000" ++
    "080002001a000000140006000800010008000000080002001a00000014000700" ++
    "0800010009000000080002001a00000014000800080001000a00000008000200" ++
    "1a00000014000900080001000b000000080002001a00000014000a0008000100" ++
    "0c000000080002001a00000014000b00080001000e000000080002001a000000" ++
    "14000c00080001000f000000080002001a00000014000d000800010010000000" ++
    "080002001a00000014000e000800010011000000080002000e00000014000f00" ++
    "0800010012000000080002001a00000014001000080001001300000008000200" ++
    "1a000000140011000800010014000000080002001a0000001400120008000100" ++
    "15000000080002001e00000014001300080001006b000000080002001e000000" ++
    "140014000800010016000000080002001a000000140015000800010017000000" ++
    "080002001a000000140016000800010018000000080002001a00000014001700" ++
    "0800010019000000080002001a00000014001800080001001f00000008000200" ++
    "0e00000014001900080001001a000000080002000b00000014001a0008000100" ++
    "1b000000080002000b00000014001b00080001007e000000080002000b000000" ++
    "14001c00080001001c000000080002000a00000014001d00080001001d000000" ++
    "080002001a00000014001e000800010021000000080002001a00000014001f00" ++
    "0800010072000000080002001a00000014002000080001002000000008000200" ++
    "0400000014002100080001004b000000080002001a0000001400220008000100" ++
    "4c000000080002001a000000140023000800010025000000080002001a000000" ++
    "140024000800010026000000080002001a000000140025000800010027000000" ++
    "080002001a000000140026000800010028000000080002001a00000014002700" ++
    "080001002b000000080002001a00000014002800080001002c00000008000200" ++
    "1a00000014002900080001002e000000080002001a00000014002a0008000100" ++
    "7a000000080002000b00000014002b000800010030000000080002001a000000" ++
    "14002c000800010031000000080002001a00000014002d000800010032000000" ++
    "080002000400000014002e000800010034000000080002001a00000014002f00" ++
    "0800010035000000080002001a00000014003000080001003600000008000200" ++
    "1a000000140031000800010037000000080002001a0000001400320008000100" ++
    "38000000080002001a000000140033000800010039000000080002001a000000" ++
    "14003400080001003a000000080002001a00000014003500080001003b000000" ++
    "080002001a000000140036000800010043000000080002001a00000014003700" ++
    "080001003d000000080002001a00000014003800080001003e00000008000200" ++
    "0a00000014003900080001003f000000080002001a00000014003a0008000100" ++
    "41000000080002001a00000014003b000800010044000000080002001a000000" ++
    "14003c000800010045000000080002001a00000014003d00080001006c000000" ++
    "080002001a00000014003e00080001006d000000080002001a00000014003f00" ++
    "0800010049000000080002000a00000014004000080001004a00000008000200" ++
    "1a00000014004100080001004f000000080002001a0000001400420008000100" ++
    "52000000080002001a000000140043000800010051000000080002001a000000" ++
    "140044000800010053000000080002001a000000140045000800010054000000" ++
    "080002001a000000140046000800010055000000080002001a00000014004700" ++
    "0800010057000000080002001a00000014004800080001005900000008000200" ++
    "1a00000014004900080001005a000000080002001a00000014004a0008000100" ++
    "73000000080002000b00000014004b000800010074000000080002000b000000" ++
    "14004c000800010075000000080002000b00000014004d000800010076000000" ++
    "080002000b00000014004e000800010077000000080002000b00000014004f00" ++
    "080001005c000000080002001a00000014005000080001005d00000008000200" ++
    "1a00000014005100080001005e000000080002001a0000001400520008000100" ++
    "5f000000080002000a000000140053000800010060000000080002001a000000" ++
    "140054000800010062000000080002001a000000140055000800010063000000" ++
    "080002001a000000140056000800010064000000080002000a00000014005700" ++
    "0800010065000000080002001a00000014005800080001006600000008000200" ++
    "1a000000140059000800010067000000080002001e00000014005a0008000100" ++
    "68000000080002001a00000014005b000800010069000000080002001a000000" ++
    "14005c00080001006a000000080002001a00000014005d00080001006f000000" ++
    "080002001a00000014005e000800010070000000080002001a00000014005f00" ++
    "0800010079000000080002001a00000014006000080001007b00000008000200" ++
    "0a00000014006100080001007c000000080002000a0000001400620008000100" ++
    "7f000000080002000b000000140063000800010081000000080002001a000000" ++
    "140064000800010082000000080002000a000000140065000800010083000000" ++
    "080002001a000000140066000800010086000000080002001a00000014006700" ++
    "0800010087000000080002000b00000014006800080001008800000008000200" ++
    "1a000000140069000800010089000000080002001a00000014006a0008000100" ++
    "8c000000080002001a00000014006b00080001008e000000080002001a000000" ++
    "14006c000800010092000000080002001a00000014006d000800010094000000" ++
    "080002001a00000014006e000800010095000000080002001a00000014006f00" ++
    "0800010096000000080002001a00000014007000080001009700000008000200" ++
    "1a000000140071000800010098000000080002001a0000001400720008000100" ++
    "99000000080002001a00000014007300080001009b000000080002001a000000" ++
    "14007400080001009c000000080002001a00000014007500080001009d000000" ++
    "080002001a000000940007001800010008000200160000000b000100636f6e66" ++
    "69670000180002000800020017000000090001007363616e000000001c000300" ++
    "08000200180000000f000100726567756c61746f727900001800040008000200" ++
    "19000000090001006d6c6d650000000018000500080002001a0000000b000100" ++
    "76656e646f72000014000600080002001b000000080001006e616e00");

/// `iw dev` — the `NL80211_CMD_NEW_INTERFACE` dump reply: two interfaces.
const get_interface_dump_reply = hex("5400000029000200b82c9f95dbbb1caf07010000080001000000000008000500" ++
    "0a0000000c00990002000000000000000a000600020000112234000008002e00" ++
    "06000000050053000000000008004d0100000000f400000029000200b82c9f95" ++
    "dbbb1caf0701000008000300030000000b000400776c70327330000008000100" ++
    "0000000008000500020000000c00990001000000000000000a00060002000011" ++
    "2233000008002e0006000000050053000000000008004d010000000008002600" ++
    "7c150000080022010000000008009f00030000000800a0009a15000008006200" ++
    "98080000160034005a49474c4942532d544553542d41502d303100004c000901" ++
    "0800010000000000080002000000000008000300000000000800040000000000" ++
    "0800050000000000080006000000000008000800000000000800090000000000" ++
    "08000a0000000000");

/// `iw dev wlp2s0 station dump` — one associated AP, 2500 bytes, including a
/// 2100-byte `STA_INFO_TID_STATS` nest this module deliberately skips.
const get_station_dump_reply = hex("c409000029000200b82c9f95e5bb1caf1301000008000300030000000a000600" ++
    "020000aabbcc000008002e005f00000094091500080010000e54030008000100" ++
    "0a0000000c002a0013b6b7df03c600000800020032e084e508000300e16b84b8" ++
    "0c00170032e084e5070000000c001800e16b84b8010000000c00200000000000" ++
    "000000000c002700000000000000000005000700af00000005000d00b0000000" ++
    "1400190005000000ae00000005000100af00000014001a0005000000af000000" ++
    "05000100b00000002c000800080005008a020000060001008a02000004000800" ++
    "05000600010000000500070001000000040004002c000e0008000500d0030000" ++
    "06000100d0030000040008000500060002000000050007000100000004000400" ++
    "080009008d87530108000a003b66240108000b0083140b0008000c0042000000" ++
    "080012000600000018000f000400030005000400030000000600050064000000" ++
    "0c001100fe000000aa0000000c001c0015950200000000000c001d00a0791f00" ++
    "0000000005001e00af00000038081f00800001000c00010004520e0200000000" ++
    "0c0002001f582401000000000c00030032130b00000000000c00040042000000" ++
    "000000004c00060008000100000000000800020000000000080003001d582401" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "08000900f40576b808000a001f582401800002000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800003000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800004000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800005000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800006000c0001000200000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800007000c0001001a04000000000000" ++
    "0c0002006b000000000000000c00030002000000000000000c00040000000000" ++
    "000000004c00060008000100000000000800020000000000080003006b000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009005231000008000a006b000000800008000c000100162b000000000000" ++
    "0c000200680d0000000000000c0003000a010000000000000c00040000000000" ++
    "000000004c0006000800010000000000080002000000000008000300680d0000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "08000900b32d0e0008000a00680d0000800009000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000a000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000b000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000c000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000d000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000e000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a000000000080000f000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000800010000c0001000000000000000000" ++
    "0c00020000000000000000000c00030000000000000000000c00040000000000" ++
    "000000004c000600080001000000000008000200000000000800030000000000" ++
    "0800040000000000080005000000000008000600000000000800080000000000" ++
    "080009000000000008000a0000000000340011000c00010081b2000000000000" ++
    "0c00020007000000000000000c00030000000000000000000c00040000000000" ++
    "00000000");

/// `iw dev wlp2s0 scan dump` — one BSS with 484 bytes of probe-response IEs
/// and 382 bytes of beacon IEs, straight off the air.
const get_scan_reply = hex("1404000029000200b82c9f95eabb1caf2201000008002e0030ed010008000300" ++
    "030000000c0099000100000000000000e4032f000a000100020000aabbcc0000" ++
    "04000e000c000300be6afa5a40010000e801060000125a49474c4942532d5445" ++
    "53542d41502d303101088c121824b048606c073c4445202401172801172c0117" ++
    "3001173401173801173c011740011764011e68011e6c011e70011e74011e7801" ++
    "1e7c011e80011e84011e88011e8c011e2001002302160030140100000fac0401" ++
    "00000fac040100000fac020c000b0501002d00004605334f0000002d1aef0117" ++
    "ffffffff000000000000000000000000000000000000003d1664050400000000" ++
    "0000000000000000000000000000007f0904000880000000c001bf0cf5698b0f" ++
    "aaff0000aaff0020c005016a720000c3050330303030ff27230100081200104c" ++
    "2002c06f5b9518000c00aaffaaffaaffaaff7b1cc7711cc7711cc7711cc771ff" ++
    "07240400010dfcffff0e260000a40820a408404308603208dd8e0050f204104a" ++
    "00011010440001021057000101103b00010310470010a5371d7be53547ba8319" ++
    "58b769991a6e102100044b616f6e1023000b4f32534d415254424f5832102400" ++
    "03312e311042000e4942534f343232313030323231391054000800060050f204" ++
    "00011011000d4b616f6e204447323330304352100800020004103c0001031049" ++
    "000600372a000120dd0500904c0417dd090010180201009c0000dd180050f202" ++
    "0101000003a4000027a4000042435e0062322f006c027f000c000d0047c01526" ++
    "4901000082010b0000125a49474c4942532d544553542d41502d303101088c12" ++
    "1824b048606c050400030000073c4445202401172801172c0117300117340117" ++
    "3801173c011740011764011e68011e6c011e70011e74011e78011e7c011e8001" ++
    "1e84011e88011e8c011e2001002302160030140100000fac040100000fac0401" ++
    "00000fac020c000b0501001e00004605334f0000002d1aef0117ffffffff0000" ++
    "00000000000000000000000000000000003d1664050400000000000000000000" ++
    "0000000000000000007f0904000880000000c001bf0cf5698b0faaff0000aaff" ++
    "0020c005016a720000c3050330303030ff27230100081200104c2002c06f5b95" ++
    "18000c00aaffaaffaaffaaff7b1cc7711cc7711cc7711cc771ff07240400010d" ++
    "fcffff0e260000a40820a408404308603208dd220050f204104a000110104400" ++
    "01021057000101103c0001031049000600372a000120dd0500904c0417dd0900" ++
    "10180201009c0000dd180050f2020101000003a4000027a4000042435e006232" ++
    "2f006c027f00000006000400640000000600050011110000080002007c150000" ++
    "080014000000000008000a00182800000c000f0070fb9fe8638c010008000700" ++
    "5ce0ffff08000900010000000800170003000000");

/// `iw reg get` — the world regdomain followed by this radio's country one.
const get_reg_reply = hex("3c02000029000200b82c9f95d6bb1caf1f010000070021003030000020022200" ++
    "3c00000008000100800000000800020038850b000800030000290e0008000400" ++
    "d0070000080005000000000008000600d007000008000700000000003c000100" ++
    "080001000000000008000200d0a624000800030040b8250008000400409c0000" ++
    "080005000000000008000600d007000008000700000000003c00020008000100" ++
    "8008000008000200a87d25000800030050df250008000400204e000008000500" ++
    "0000000008000600d007000008000700000000003c0003000800010081000000" ++
    "0800020010c0250008000300300e260008000400204e00000800050000000000" ++
    "08000600d007000008000700000000003c000400080001008008000008000200" ++
    "50e34e0008000300d01b50000800040080380100080005000000000008000600" ++
    "d007000008000700000000003c000500080001009008000008000200d01b5000" ++
    "08000300505451000800040080380100080005000000000008000600d0070000" ++
    "08000700000000003c00060008000100900000000800020050c5530008000300" ++
    "d06e57000800040000710200080005000000000008000600d007000008000700" ++
    "000000003c0007000800010080000000080002005882570008000300f8085900" ++
    "0800040080380100080005000000000008000600d00700000800070000000000" ++
    "3c000800080001000000000008000200c069690308000300404acc0308000400" ++
    "80f52000080005000000000008000600000000000800070000000000bc060000" ++
    "29000200b82c9f95d6bb1caf1f0100000700210044450000940622003c000000" ++
    "0800010000a8410008000200d0a6240008000300882f250008000400409c0000" ++
    "0800050058020000080006009808000008000700000000003c00010008000100" ++
    "0088410008000200f0f42400080003003091250008000400409c000008000500" ++
    "58020000080006009808000008000700000000003c0002000800010000c84100" ++
    "08000200985625000800030050df250008000400409c00000800050058020000" ++
    "080006009808000008000700000000003c000300080001008838450008000200" ++
    "50e34e000800030070314f000800040080380100080005005802000008000600" ++
    "9808000008000700000000003c00040008000100885845000800020070314f00" ++
    "08000300907f4f00080004008038010008000500580200000800060098080000" ++
    "08000700000000003c000500080001008838450008000200907f4f0008000300" ++
    "b0cd4f0008000400803801000800050058020000080006009808000008000700" ++
    "000000003c000600080001008858450008000200b0cd4f0008000300d01b5000" ++
    "0800040080380100080005005802000008000600980800000800070000000000" ++
    "3c000700080001009028450008000200d01b500008000300f069500008000400" ++
    "803801000800050058020000080006009808000008000700000000003c000800" ++
    "080001009048450008000200f06950000800030010b850000800040080380100" ++
    "0800050058020000080006009808000008000700000000003c00090008000100" ++
    "902845000800020010b850000800030030065100080004008038010008000500" ++
    "58020000080006009808000008000700000000003c000a000800010090484500" ++
    "0800020030065100080003005054510008000400803801000800050058020000" ++
    "080006009808000008000700000000003c000b00080001009028450008000200" ++
    "50c5530008000300701354000800040080380100080005005802000008000600" ++
    "9808000008000700000000003c000c0008000100904845000800020070135400" ++
    "0800030090615400080004008038010008000500580200000800060098080000" ++
    "08000700000000003c000d000800010090284500080002009061540008000300" ++
    "b0af540008000400803801000800050058020000080006009808000008000700" ++
    "000000003c000e00080001009048450008000200b0af540008000300d0fd5400" ++
    "0800040080380100080005005802000008000600980800000800070000000000" ++
    "3c000f00080001009028450008000200d0fd540008000300f04b550008000400" ++
    "803801000800050058020000080006009808000008000700000000003c001000" ++
    "080001009048450008000200f04b550008000300109a55000800040080380100" ++
    "0800050058020000080006009808000008000700000000003c00110008000100" ++
    "9028450008000200109a55000800030030e85500080004008038010008000500" ++
    "58020000080006009808000008000700000000003c0012000800010090484500" ++
    "0800020030e85500080003005036560008000400803801000800050058020000" ++
    "080006009808000008000700000000003c001300080001009028450008000200" ++
    "5036560008000300708456000800040080380100080005005802000008000600" ++
    "9808000008000700000000003c00140008000100904845000800020070845600" ++
    "0800030090d25600080004008038010008000500580200000800060098080000" ++
    "08000700000000003c00150008000100902845000800020090d2560008000300" ++
    "b020570008000400803801000800050058020000080006009808000008000700" ++
    "000000003c001600080001009048450008000200b020570008000300d06e5700" ++
    "0800040080380100080005005802000008000600980800000800070000000000" ++
    "3c001700080001000028050108000200588257000800030078d0570008000400" ++
    "803801000800050058020000080006009808000008000700000000003c001800" ++
    "08000100004805010800020078d0570008000300981e58000800040080380100" ++
    "0800050058020000080006009808000008000700000000003c00190008000100" ++
    "0028050108000200981e580008000300b86c5800080004008038010008000500" ++
    "58020000080006009808000008000700000000003c001a000800010000480501" ++
    "08000200b86c580008000300d8ba580008000400803801000800050058020000" ++
    "080006009808000008000700000000003c001b000800010000e8050108000200" ++
    "d8ba580008000300f808590008000400204e0000080005005802000008000600" ++
    "98080000080007000000000008000100000000000400d800");

/// `iw list` — ONE radio spread across 75 `NL80211_CMD_NEW_WIPHY` messages in
/// a single 13204-byte datagram. The split-dump merge test feeds this whole.
const get_wiphy_split_dump = hex("8800000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e000100000005003d000700000005003e0004000000" ++
    "08003f00ffffffff08004000ffffffff050059000000000005002b0014000000" ++
    "05007b0014000000060038009d01000006007c00e6010000050085000b000000" ++
    "04006800040082007400000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000001800390001ac0f00" ++
    "05ac0f0002ac0f0004ac0f0006ac0f0005005600000000000400660008007100" ++
    "030000000800720003000000080069000300000008006a000300000054000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e00010000002400200004000100040002000400030004000400" ++
    "04000600040008000400090004000a000401000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "d4001600d000000014000300ffff00000000000000002c010100000006000400" ++
    "ef11000005000500030000000500060005000000a00002000c00000008000100" ++
    "0a00000010000100080001001400000004000200100002000800010037000000" ++
    "0400020010000300080001006e000000040002000c000400080001003c000000" ++
    "0c000500080001005a0000000c00060008000100780000000c00070008000100" ++
    "b40000000c00080008000100f00000000c00090008000100680100000c000a00" ++
    "08000100e00100000c000b00080001001c0200006c00000029000200fb2b9f95" ++
    "d1c09ce303010000080001000000000009000200706879300000000008002e00" ++
    "010000003c001600380000003400010030000000080001006c09000008001400" ++
    "000000000400090004000b0004000c0004001a0004001e000800060098080000" ++
    "6c00000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e00010000003c001600380000003400010030000100" ++
    "080001007109000008001400000000000400090004000b0004000c0004001a00" ++
    "04001e0008000600980800006c00000029000200fb2b9f95d1c09ce303010000" ++
    "080001000000000009000200706879300000000008002e00010000003c001600" ++
    "3800000034000100300002000800010076090000080014000000000004000900" ++
    "04000b0004000c0004001a0004001e0008000600980800006c00000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000003c001600380000003400010030000300080001007b090000" ++
    "08001400000000000400090004000b0004000c0004001a0004001e0008000600" ++
    "980800006800000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e0001000000380016003400000030000100" ++
    "2c0004000800010080090000080014000000000004000b0004000c0004001a00" ++
    "04001e0008000600980800006800000029000200fb2b9f95d1c09ce303010000" ++
    "080001000000000009000200706879300000000008002e000100000038001600" ++
    "34000000300001002c0005000800010085090000080014000000000004000b00" ++
    "04000c0004001a0004001e0008000600980800006800000029000200fb2b9f95" ++
    "d1c09ce303010000080001000000000009000200706879300000000008002e00" ++
    "010000003800160034000000300001002c000600080001008a09000008001400" ++
    "0000000004000b0004000c0004001a0004001e00080006009808000068000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e00010000003800160034000000300001002c00070008000100" ++
    "8f090000080014000000000004000b0004000c0004001a0004001e0008000600" ++
    "980800006800000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e0001000000380016003400000030000100" ++
    "2c0008000800010094090000080014000000000004000b0004000c0004001a00" ++
    "04001e0008000600980800006c00000029000200fb2b9f95d1c09ce303010000" ++
    "080001000000000009000200706879300000000008002e00010000003c001600" ++
    "3800000034000100300009000800010099090000080014000000000004000a00" ++
    "04000b0004000c0004001a0004001e0008000600980800006c00000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000003c001600380000003400010030000a00080001009e090000" ++
    "080014000000000004000a0004000b0004000c0004001a0004001e0008000600" ++
    "980800006c00000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e00010000003c0016003800000034000100" ++
    "30000b0008000100a3090000080014000000000004000a0004000b0004000c00" ++
    "04001a0004001e0008000600980800006c00000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "3c001600380000003400010030000c0008000100a80900000800140000000000" ++
    "04000a0004000b0004000c0004001a0004001e00080006009808000064000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e000100000034001600300000002c00010028000d0008000100" ++
    "b40900000800140000000000040002000400090004000a000800060098080000" ++
    "3c00000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e00010000000c0016000800000004000100dc000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e0001000000ac001600a800010014000300ffff000000000000" ++
    "00002c010100000006000400ef11000005000500030000000500060005000000" ++
    "0c000700faff0000faff002008000800b0719003640002000c00000008000100" ++
    "3c0000000c000100080001005a0000000c00020008000100780000000c000300" ++
    "08000100b40000000c00040008000100f00000000c0005000800010068010000" ++
    "0c00060008000100e00100000c000700080001001c0200000c01000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e0001000000dc001600d8000100d4000100d0000000080001003c140000" ++
    "080014000000000004000300040004000400090004000c0004000e0004000f00" ++
    "04001a0004001e00080006009808000094001200240000000600010003000000" ++
    "0600020007000000050003000200000006000400d00700002400010006000100" ++
    "07000000060002000f000000050003000200000006000400a00f000024000200" ++
    "060001000f00000006000200ff03000005000300030000000600040070170000" ++
    "24000300060001000f00000006000200ff030000050003000700000006000400" ++
    "701700000c01000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e0001000000dc001600d8000100d4000100" ++
    "d000010008000100501400000800140000000000040003000400040004000a00" ++
    "04000c0004000e0004000f0004001a0004001e00080006009808000094001200" ++
    "2400000006000100030000000600020007000000050003000200000006000400" ++
    "d0070000240001000600010007000000060002000f0000000500030002000000" ++
    "06000400a00f000024000200060001000f00000006000200ff03000005000300" ++
    "03000000060004007017000024000300060001000f00000006000200ff030000" ++
    "050003000700000006000400701700000c01000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "dc001600d8000100d4000100d000020008000100641400000800140000000000" ++
    "04000300040004000400090004000c0004000e0004000f0004001a0004001e00" ++
    "0800060098080000940012002400000006000100030000000600020007000000" ++
    "050003000200000006000400d007000024000100060001000700000006000200" ++
    "0f000000050003000200000006000400a00f000024000200060001000f000000" ++
    "06000200ff030000050003000300000006000400701700002400030006000100" ++
    "0f00000006000200ff030000050003000700000006000400701700000c010000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e0001000000dc001600d8000100d4000100d000030008000100" ++
    "781400000800140000000000040003000400040004000a0004000c0004000e00" ++
    "04000f0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4000400080001008c14000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400050008000100a014000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400060008000100b414000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400070008000100c814000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700006400000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000003400160030000100" ++
    "2c0001002800080008000100dc14000008001400000000000400020004000900" ++
    "04000a0008000600980800006400000029000200fb2b9f95d1c09ce303010000" ++
    "080001000000000009000200706879300000000008002e000100000034001600" ++
    "300001002c0001002800090008000100f0140000080014000000000004000200" ++
    "0400090004000a0008000600980800006400000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "34001600300001002c00010028000a0008000100041500000800140000000000" ++
    "040002000400090004000a0008000600980800006400000029000200fb2b9f95" ++
    "d1c09ce303010000080001000000000009000200706879300000000008002e00" ++
    "0100000034001600300001002c00010028000b00080001001815000008001400" ++
    "00000000040002000400090004000a0008000600980800006400000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e000100000034001600300001002c00010028000c00080001002c150000" ++
    "0800140000000000040002000400090004000a00080006009808000064000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e000100000034001600300001002c00010028000d0008000100" ++
    "401500000800140000000000040002000400090004000a000800060098080000" ++
    "6400000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e000100000034001600300001002c00010028000e00" ++
    "08000100541500000800140000000000040002000400090004000a0008000600" ++
    "980800006400000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e000100000034001600300001002c000100" ++
    "28000f0008000100681500000800140000000000040002000400090004000a00" ++
    "08000600980800002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001000080001007c15000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001100080001009015000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400120008000100a415000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400130008000100b815000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400140008000100cc15000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400150008000100e015000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e400160008000100f415000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001700080001000816000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001800080001001c16000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001900080001003016000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001a00080001004416000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000900" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700002001000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000f0001600ec000100" ++
    "e8000100e4001b00080001005816000008001400000000000400030004000400" ++
    "040005000800070000000000080008009162431408000d0060ea000004000a00" ++
    "04000c0004001a0004001e000800060098080000940012002400000006000100" ++
    "030000000600020007000000050003000200000006000400d007000024000100" ++
    "0600010007000000060002000f000000050003000200000006000400a00f0000" ++
    "24000200060001000f00000006000200ff030000050003000300000006000400" ++
    "7017000024000300060001000f00000006000200ff0300000500030007000000" ++
    "06000400701700006800000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000003800160034000100" ++
    "300001002c001c00080001007116000008001400000000000400090004000c00" ++
    "04001a000400210008000600980800006800000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "3800160034000100300001002c001d0008000100851600000800140000000000" ++
    "04000a0004000c0004001a000400210008000600980800006800000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000003800160034000100300001002c001e000800010099160000" ++
    "08001400000000000400090004000c0004001a00040021000800060098080000" ++
    "6800000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e00010000003800160034000100300001002c001f00" ++
    "08000100ad160000080014000000000004000a0004000c0004001a0004002100" ++
    "08000600980800007000000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000400016003c000100" ++
    "380001003400200008000100c116000008001400000000000400090004000a00" ++
    "04000b0004000c0004001a000400210008000600980800006400000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e000100000034001600300001002c0001002800210008000100d5160000" ++
    "0800140000000000040002000400090004000a00080006009808000064000000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e000100000034001600300001002c0001002800220008000100" ++
    "e91600000800140000000000040002000400090004000a000800060098080000" ++
    "6400000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e000100000034001600300001002c00010028002300" ++
    "08000100fd1600000800140000000000040002000400090004000a0008000600" ++
    "980800006400000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e000100000034001600300001002c000100" ++
    "2800240008000100111700000800140000000000040002000400090004000a00" ++
    "08000600980800003c00000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000000c00160008000100" ++
    "040001003400000029000200fb2b9f95d1c09ce3030100000800010000000000" ++
    "09000200706879300000000008002e0001000000040016003c01000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000000c0132000800010007000000080002000600000008000300" ++
    "0b000000080004000f0000000800050013000000080006001700000008000700" ++
    "1d0000000800080019000000080009002500000008000a002600000008000b00" ++
    "2700000008000c002800000008000d002b00000008000e004400000008000f00" ++
    "370000000800100039000000080011003b000000080012004300000008001300" ++
    "310000000800140041000000080015004b000000080016005400000008001700" ++
    "570000000800180055000000080019005900000008001a005c00000008001b00" ++
    "2e00000008001c003000000008001d006600000008001e006800000008001f00" ++
    "690000000800200079000000080021009c0000003c00000029000200fb2b9f95" ++
    "d1c09ce303010000080001000000000009000200706879300000000008002e00" ++
    "0100000008006f001027000004006c006c00000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "3c00760004000200040003000400050004000600040007000400080004000900" ++
    "1400040014000000100000008000000000000000080012000b00000014010000" ++
    "29000200fb2b9f95d1c09ce30301000008000100000000000900020070687930" ++
    "0000000008002e00010000000c0079000400040004000600d800780068000100" ++
    "4400010014000100080001000100000008000200040002001800020008000100" ++
    "010000000c000200040008000400090014000300080001000100000008000200" ++
    "04000a0008000400020000000800020003000000080005000000000008000600" ++
    "000000006c000200480001001400010008000100010000000800020004000200" ++
    "1c00020008000100010000001000020004000300040008000400090014000300" ++
    "08000100010000000800020004000a0008000400010000000800020003000000" ++
    "080005000000000008000600000000005800000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "08008f00e3da4def1e009400e34b1fffffffffffffffffffff00000000000000" ++
    "0000000000000000d006000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e0001000000b804630004000000" ++
    "8400010006006500000000000600650010000000060065002000000006006500" ++
    "3000000006006500400000000600650050000000060065006000000006006500" ++
    "700000000600650080000000060065009000000006006500a000000006006500" ++
    "b000000006006500c000000006006500d000000006006500e000000006006500" ++
    "f000000084000200060065000000000006006500100000000600650020000000" ++
    "0600650030000000060065004000000006006500500000000600650060000000" ++
    "06006500700000000600650080000000060065009000000006006500a0000000" ++
    "06006500b000000006006500c000000006006500d000000006006500e0000000" ++
    "06006500f0000000840003000600650000000000060065001000000006006500" ++
    "2000000006006500300000000600650040000000060065005000000006006500" ++
    "6000000006006500700000000600650080000000060065009000000006006500" ++
    "a000000006006500b000000006006500c000000006006500d000000006006500" ++
    "e000000006006500f00000008400040006006500000000000600650010000000" ++
    "0600650020000000060065003000000006006500400000000600650050000000" ++
    "0600650060000000060065007000000006006500800000000600650090000000" ++
    "06006500a000000006006500b000000006006500c000000006006500d0000000" ++
    "06006500e000000006006500f000000004000500040006008400070006006500" ++
    "0000000006006500100000000600650020000000060065003000000006006500" ++
    "4000000006006500500000000600650060000000060065007000000006006500" ++
    "80000000060065009000000006006500a000000006006500b000000006006500" ++
    "c000000006006500d000000006006500e000000006006500f000000084000800" ++
    "0600650000000000060065001000000006006500200000000600650030000000" ++
    "0600650040000000060065005000000006006500600000000600650070000000" ++
    "0600650080000000060065009000000006006500a000000006006500b0000000" ++
    "06006500c000000006006500d000000006006500e000000006006500f0000000" ++
    "8400090006006500000000000600650010000000060065002000000006006500" ++
    "3000000006006500400000000600650050000000060065006000000006006500" ++
    "700000000600650080000000060065009000000006006500a000000006006500" ++
    "b000000006006500c000000006006500d000000006006500e000000006006500" ++
    "f000000084000a00060065000000000006006500100000000600650020000000" ++
    "0600650030000000060065004000000006006500500000000600650060000000" ++
    "06006500700000000600650080000000060065009000000006006500a0000000" ++
    "06006500b000000006006500c000000006006500d000000006006500e0000000" ++
    "06006500f000000004000b0084000c0006006500000000000600650010000000" ++
    "0600650020000000060065003000000006006500400000000600650050000000" ++
    "0600650060000000060065007000000006006500800000000600650090000000" ++
    "06006500a000000006006500b000000006006500c000000006006500d0000000" ++
    "06006500e000000006006500f000000068016400040000002400010006006500" ++
    "4000000006006500b000000006006500c000000006006500d00000001c000200" ++
    "060065004000000006006500b000000006006500d00000003c00030006006500" ++
    "000000000600650020000000060065004000000006006500a000000006006500" ++
    "b000000006006500c000000006006500d00000003c0004000600650000000000" ++
    "0600650020000000060065004000000006006500a000000006006500b0000000" ++
    "06006500c000000006006500d000000004000500040006001c00070006006500" ++
    "b000000006006500c000000006006500d0000000140008000600650040000000" ++
    "06006500d00000003c0009000600650000000000060065002000000006006500" ++
    "4000000006006500a000000006006500b000000006006500c000000006006500" ++
    "d00000001c000a00060065004000000006006500b000000006006500d0000000" ++
    "04000b0014000c0006006500b000000006006500d00000000800de0002000000" ++
    "0800df00ffff00000800e000fe0000000c00a90004000000000000400c00aa00" ++
    "04000000000000401000b000f01f8033ffff0000ffff00000a00060002000011" ++
    "223300003400a6800a00010002000011223300000a0002000200001122340000" ++
    "0a00030002000011223500000a00040002000011223600003000000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000003000000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000007800000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000000500ce00020000000400d80008000001010000000d00d900" ++
    "5f021e5410940122000000002400558104001c0004001d0004001e0004002400" ++
    "0400600004006d000400a2000400a3006000000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "3000e6002c00000008000500020000000e00a9000400c000000000c001200000" ++
    "0e00aa000400c000000000c0012000008800000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "0400e6000800ef00000000003400090108000100000000000800020000000000" ++
    "08000600000000000800070000000000080008000000000008000b0000100000" ++
    "08000a010020000008000b010000000108000c012c0100003000000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e00010000003000000029000200fb2b9f95d1c09ce30301000008000100" ++
    "0000000009000200706879300000000008002e00010000003800000029000200" ++
    "fb2b9f95d1c09ce3030100000800010000000000090002007068793000000000" ++
    "08002e000100000006003c01020000003000000029000200fb2b9f95d1c09ce3" ++
    "03010000080001000000000009000200706879300000000008002e0001000000" ++
    "5400000029000200fb2b9f95d1c09ce303010000080001000000000009000200" ++
    "706879300000000008002e000100000024005881050003000000000005000400" ++
    "0000000006000500000000000500060000000000");
