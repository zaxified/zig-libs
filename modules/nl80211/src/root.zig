// SPDX-License-Identifier: MIT
//! nl80211 — pure-Zig **Wi-Fi control** over the `nl80211` generic-netlink
//! family: radio and interface enumeration, scanning with information-element
//! decoding, station/link statistics, connect/disconnect and the regulatory
//! domain — with no `iw` shell-out, no `wpa_supplicant` linkage and no libc.
//!
//! ```zig
//! const nl80211 = @import("nl80211");
//!
//! var wifi = try nl80211.Nl80211.open(gpa);
//! defer wifi.close();
//!
//! const ifaces = try wifi.interfaces();
//! defer gpa.free(ifaces);
//! const wlan = ifaces[0].ifindex.?;
//!
//! // Subscribe BEFORE triggering: the completion event can fire in the gap.
//! var events = try nl80211.EventSocket.openWith(&wifi, &.{nl80211.mcast_group.scan});
//! defer events.close();
//! try wifi.triggerScan(.{ .ifindex = wlan, .ssids = nl80211.wildcard_ssids });
//! while (!(try events.waitForEvent()).endsScan()) {}   // the ONE blocking call
//!
//! const bsses = try wifi.scanResults(wlan);
//! defer nl80211.scan.freeAll(gpa, bsses);
//! for (bsses) |bss| {
//!     const elems = bss.elements();          // SSID, rates, channel, RSN
//!     std.debug.print("{s} {s} {?d} dBm {s}\n", .{
//!         &nl80211.formatMac(bss.bssid.?),
//!         elems.ssid,                        // raw bytes — never print unescaped
//!         bss.signalDbm(),
//!         @tagName(elems.security(bss.capability)),
//!     });
//! }
//! ```
//!
//! ## What this module is, and is not
//!
//! nl80211 is enormous — 100+ commands, 350+ attributes. This is a **v1 with a
//! stated ceiling**, not a complete client:
//!
//! * **Implemented:** `GET_WIPHY` (split dump, merged), `GET_INTERFACE`,
//!   `TRIGGER_SCAN` + `GET_SCAN` + the `scan` multicast event, `GET_STATION`,
//!   `CONNECT`/`DISCONNECT`, `GET_REG`/`REQ_SET_REG`, plus a **`raw` escape
//!   hatch** (`Nl80211.raw`) that reaches every command not modelled here.
//! * **Not implemented:** AP mode, mesh, IBSS, P2P, monitor configuration,
//!   survey, TDLS, WoWLAN, scheduled scan, key management, vendor commands,
//!   and **the supplicant** — see `connect.zig`'s header for exactly which
//!   association path works without one, and SPEC.md for the full deferred
//!   list.
//!
//! Read `connect.zig`'s file header before using `connect`:
//! `NL80211_CMD_CONNECT` delegates the 4-way handshake to the driver only on
//! hardware with an internal SME. On ordinary mac80211 chips you still need
//! `wpa_supplicant`, and this module is then an enumeration/scan/statistics
//! library — which is most of what a fleet-management or monitoring consumer
//! wants anyway.
//!
//! **Platform:** linux (raw `std.os.linux` syscalls over `AF_NETLINK` — a
//! conscious ceiling). **Privileges:** the dumps (`wiphys`, `interfaces`,
//! `stations`, `scanResults`, `regDomains`) and multicast subscription need
//! none; `triggerScan`, `connect`, `disconnect` and `requestRegDomain` need
//! **CAP_NET_ADMIN**.
//!
//! Verification: `goldens.zig` asserts the encoders reproduce, byte for byte,
//! requests captured from a real `iw` under `strace`, and decodes real kernel
//! replies (including a wiphy split across 75 messages and 484 bytes of
//! information elements straight off the air). The tests at the bottom of this
//! file run against the live kernel and skip cleanly when there is no Wi-Fi
//! device or no privilege.
//!
//! Provenance: clean-room from the kernel UAPI (`linux/nl80211.h`, GPL-2.0
//! WITH Linux-syscall-note — the command/attribute constants and their layouts
//! are the kernel's OS ABI, not copyrightable interface code) and the IEEE
//! 802.11 information-element formats. `iw` was used only as a black-box
//! capture oracle under `strace`; no `iw` or `wpa_supplicant` source was read
//! or ported. See `NOTICE`.

const std = @import("std");
const builtin = @import("builtin");
const netlink = @import("netlink");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

pub const meta = .{
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Nl80211/EventSocket per thread
    .model_after = "kernel UAPI linux/nl80211.h + IEEE 802.11 information elements; `iw` used only as a black-box strace capture oracle",
    .deps = .{ "genetlink", "netlink" },
};

// ── submodules ─────────────────────────────────────────────────────────────

/// Kernel UAPI constants and enums (`CMD`, `ATTR`, `Iftype`, cipher/AKM …).
pub const uapi = @import("uapi.zig");
/// IEEE 802.11 information-element parsing — the hostile-input surface.
pub const ie = @import("ie.zig");
/// `GET_WIPHY` decoding, including the split-dump merge.
pub const wiphy = @import("wiphy.zig");
/// `GET_INTERFACE` decoding.
pub const iface = @import("iface.zig");
/// `GET_STATION` decoding.
pub const station = @import("station.zig");
/// `TRIGGER_SCAN` building + BSS decoding.
pub const scan = @import("scan.zig");
/// `CONNECT`/`DISCONNECT` building. **Read its header before using it.**
pub const connect = @import("connect.zig");
/// Regulatory domain decoding + `REQ_SET_REG`.
pub const reg = @import("reg.zig");
/// The socket client and the multicast event socket.
pub const client = @import("client.zig");

/// The generic-netlink transport this family rides on, re-exported so a caller
/// does not need a second import to drive the raw escape hatch.
pub const genl = @import("genetlink");
/// The netlink wire codec, for building `raw` request attributes.
pub const codec = netlink.codec;

// ── flat re-exports (the API most callers touch) ───────────────────────────

pub const Nl80211 = client.Nl80211;
pub const EventSocket = client.EventSocket;
pub const Event = client.Event;
pub const RequestError = client.RequestError;
pub const OpenError = client.OpenError;
pub const SubscribeError = client.SubscribeError;

pub const Wiphy = wiphy.Wiphy;
pub const Band = wiphy.Band;
pub const Frequency = wiphy.Frequency;
pub const Interface = iface.Interface;
pub const Station = station.Station;
pub const RateInfo = station.RateInfo;
pub const Bss = scan.Bss;
pub const TriggerOptions = scan.TriggerOptions;
pub const ConnectOptions = connect.ConnectOptions;
pub const RegDomain = reg.RegDomain;
pub const RegRule = reg.RegRule;
pub const Security = ie.Security;

pub const Iftype = uapi.Iftype;
pub const AuthType = uapi.AuthType;
pub const ChanWidth = uapi.ChanWidth;
pub const BssStatus = uapi.BssStatus;
pub const DfsRegion = uapi.DfsRegion;
pub const Mfp = uapi.Mfp;
pub const Mac = uapi.Mac;
pub const CIPHER = uapi.CIPHER;
pub const AKM = uapi.AKM;
pub const SCAN_FLAG = uapi.SCAN_FLAG;
pub const WPA_VERSION = uapi.WPA_VERSION;
pub const RRF = uapi.RRF;
pub const mcast_group = uapi.mcast_group;
pub const family_name = uapi.family_name;
pub const max_ssid_len = uapi.max_ssid_len;

/// The SSID list an ordinary active scan sends (one wildcard entry).
pub const wildcard_ssids = scan.wildcard_ssids;
/// Format a MAC/BSSID the way `iw` prints it.
pub const formatMac = uapi.formatMac;

// ── live tests (real kernel; skip cleanly without a radio or privileges) ────
//
// Every unprivileged dump below runs for real when this machine has a Wi-Fi
// device. Nothing here changes system state: no association is made and the
// regulatory domain is only read. Without a device, or in a network namespace
// with no wiphy in it, each test prints `SKIPPED: …` and passes — the repo's
// env-gated pattern (see `tc`/`netlink`/`ebpf`).

const testing = std.testing;

fn skip(comptime what: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: {s} (no nl80211 Wi-Fi device visible here)\n", .{what});
    return error.SkipZigTest;
}

fn openOrSkip() !Nl80211 {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Nl80211.open(testing.allocator) catch |e| switch (e) {
        error.FamilyNotFound => skip("nl80211 family not registered (no cfg80211)"),
        else => skip("nl80211 socket open"),
    };
}

test "live: the nl80211 family id resolves and is genuinely dynamic" {
    var wifi = try openOrSkip();
    defer wifi.close();
    // Whatever it is, it is a real dynamic genl id: above nlctrl's fixed 0x10.
    try testing.expect(wifi.family_id > genl.GENL_ID_CTRL);
}

test "live: GET_WIPHY split dump (unprivileged)" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.wiphys() catch |e| switch (e) {
        error.AccessDenied => return skip("GET_WIPHY dump"),
        else => return e,
    };
    defer wiphy.freeAll(testing.allocator, list);
    if (list.len == 0) return skip("no wiphy on this machine");

    for (list) |*w| {
        // A radio always has a name and at least one band with channels.
        try testing.expect(w.name().len > 0);
        try testing.expect(w.channelCount() > 0);
        for (w.bands) |b| for (b.freqs) |f| {
            try testing.expect(f.freq_mhz > 700 and f.freq_mhz < 8000);
        };
        // Scan capability is advertised through the SSID ceiling, not through
        // SUPPORTED_COMMANDS — see `Wiphy.supportsCommand`.
        if (w.max_num_scan_ssids) |n| try testing.expect(n > 0);
    }
}

test "live: GET_INTERFACE dump, then GET_INTERFACE for one of them" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.interfaces() catch |e| switch (e) {
        error.AccessDenied => return skip("GET_INTERFACE dump"),
        else => return e,
    };
    defer testing.allocator.free(list);
    if (list.len == 0) return skip("no wireless interface on this machine");

    var checked: usize = 0;
    for (list) |i| {
        // Every nl80211 interface has a wdev id, even one with no netdev.
        try testing.expect(i.wdev != null);
        const idx = i.ifindex orelse continue; // a P2P device has none
        try testing.expect(i.name().len > 0);
        const one = try wifi.interfaceByIndex(idx);
        try testing.expectEqual(i.ifindex, one.ifindex);
        try testing.expectEqualStrings(i.name(), one.name());
        try testing.expectEqual(i.iftype, one.iftype);
        checked += 1;
    }
    if (checked == 0) return skip("no interface with an ifindex");
}

test "live: GET_STATION dump on every interface (unprivileged)" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.interfaces() catch return skip("GET_INTERFACE dump");
    defer testing.allocator.free(list);

    var any = false;
    for (list) |i| {
        const idx = i.ifindex orelse continue;
        const peers = wifi.stations(idx) catch |e| switch (e) {
            // An interface type that has no station table at all.
            error.NotSupported, error.NoSuchDevice, error.AccessDenied => continue,
            else => return e,
        };
        defer testing.allocator.free(peers);
        any = true;
        for (peers) |s| {
            try testing.expect(s.mac != null);
            // dBm is signed, and Wi-Fi signals are negative in practice.
            if (s.signal_dbm) |sig| try testing.expect(sig < 0 and sig > -128);
            if (s.tx_bitrate) |r| {
                if (r.kilobitsPerSecond()) |kbps| try testing.expect(kbps > 0);
            }
        }
    }
    if (!any) return skip("no interface accepted a station dump");
}

test "live: GET_SCAN dump of the kernel's BSS table (unprivileged)" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.interfaces() catch return skip("GET_INTERFACE dump");
    defer testing.allocator.free(list);

    var any = false;
    for (list) |i| {
        const idx = i.ifindex orelse continue;
        const bsses = wifi.scanResults(idx) catch |e| switch (e) {
            error.NotSupported, error.NoSuchDevice, error.AccessDenied => continue,
            else => return e,
        };
        defer scan.freeAll(testing.allocator, bsses);
        any = true;
        for (bsses) |b| {
            try testing.expect(b.bssid != null);
            if (b.freq_mhz) |f| try testing.expect(f > 700 and f < 8000);
            // Whatever is on the air, the IE walk must not blow up.
            const s = b.elements();
            try testing.expect(s.ssid.len <= max_ssid_len);
            if (s.rsn) |r| try testing.expect(r.pairwise.len <= ie.max_suites);
        }
    }
    if (!any) return skip("no interface accepted a scan dump");
}

test "live: GET_REG (unprivileged; reads only, never sets)" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.regDomains() catch |e| switch (e) {
        error.AccessDenied => return skip("GET_REG dump"),
        else => return e,
    };
    defer reg.freeAll(testing.allocator, list);
    if (list.len == 0) return skip("kernel reported no regulatory domain");

    for (list) |d| {
        // alpha2 is always two ASCII characters ("00" for the world domain).
        for (d.alpha2) |c| try testing.expect(std.ascii.isAlphanumeric(c));
        for (d.rules) |r| try testing.expect(r.end_khz >= r.start_khz);
    }
}

test "live: the `scan` multicast group resolves and can be joined" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const id = wifi.resolveMulticastGroup(mcast_group.scan) catch |e| switch (e) {
        error.GroupNotFound => return skip("nl80211 publishes no `scan` group"),
        error.AccessDenied => return skip("multicast group resolution"),
        else => return e,
    };
    try testing.expect(id != 0);

    var events = EventSocket.openWith(&wifi, &.{ mcast_group.scan, mcast_group.mlme }) catch |e| switch (e) {
        error.AccessDenied => return skip("joining the scan multicast group"),
        else => return e,
    };
    defer events.close();
    try testing.expect(events.fd() >= 0);
    // No blocking read here on purpose: a scan may never happen during a test
    // run, and this module owns no timer to bound the wait with. The live
    // trigger→wait path is exercised by the privileged test below.
}

test "live (root): trigger a scan and wait for its completion event" {
    var wifi = try openOrSkip();
    defer wifi.close();
    const list = wifi.interfaces() catch return skip("GET_INTERFACE dump");
    defer testing.allocator.free(list);

    var target: ?u32 = null;
    for (list) |i| {
        if (i.iftype != .station) continue;
        target = i.ifindex orelse continue;
        break;
    }
    const idx = target orelse return skip("no managed-mode interface to scan with");

    // Subscribe first — see scan.zig's header for why the order matters.
    var events = EventSocket.openWith(&wifi, &.{mcast_group.scan}) catch
        return skip("joining the scan multicast group");
    defer events.close();

    wifi.triggerScan(.{ .ifindex = idx, .ssids = wildcard_ssids }) catch |e| switch (e) {
        error.AccessDenied => return skip("TRIGGER_SCAN (needs CAP_NET_ADMIN)"),
        error.Busy => return skip("TRIGGER_SCAN (a scan is already running)"),
        error.NotSupported, error.NoSuchDevice => return skip("TRIGGER_SCAN on this device"),
        else => return e,
    };

    // The one blocking call, driven by this caller's own loop. A scan takes a
    // few seconds; a bounded wait would poll `events.fd()` first.
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const ev = try events.waitForEvent();
        if (!ev.endsScan()) continue;
        if (ev.isScanAborted()) return skip("the scan was aborted by the driver");
        const bsses = try wifi.scanResults(idx);
        defer scan.freeAll(testing.allocator, bsses);
        for (bsses) |b| try testing.expect(b.bssid != null);
        return;
    }
    return error.TestUnexpectedResult;
}

test "live: the raw escape hatch reaches a command the typed API does not model" {
    var wifi = try openOrSkip();
    defer wifi.close();
    // NL80211_CMD_GET_PROTOCOL_FEATURES — deliberately not in the typed API,
    // and the very first thing `iw list` asks for.
    const replies = wifi.raw(.{ .cmd = uapi.CMD.GET_PROTOCOL_FEATURES }) catch |e| switch (e) {
        error.NotSupported, error.InvalidRequest => return skip("GET_PROTOCOL_FEATURES"),
        error.AccessDenied => return skip("raw GET_PROTOCOL_FEATURES"),
        else => return e,
    };
    defer Nl80211.freeRawReplies(testing.allocator, replies);
    if (replies.len == 0) return skip("kernel returned no protocol features");

    // NL80211_ATTR_PROTOCOL_FEATURES = 173; bit 0 = SPLIT_WIPHY_DUMP.
    var it: codec.AttrIterator = .{ .buf = replies[0].attrs };
    var features: ?u32 = null;
    while (try it.next()) |a| {
        if (a.type == 173) features = try a.asU32();
    }
    try testing.expect(features != null);
    try testing.expect(features.? & 1 != 0); // this module relies on it
}

// ── dark-tests aggregator ──────────────────────────────────────────────────
// A bare `pub const x = @import(…)` re-export does NOT pull x's tests into the
// test binary (CONVENTIONS §6.3).

test {
    _ = uapi;
    _ = ie;
    _ = wiphy;
    _ = iface;
    _ = station;
    _ = scan;
    _ = connect;
    _ = reg;
    _ = client;
    _ = @import("goldens.zig");
}
