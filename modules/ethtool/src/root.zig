// SPDX-License-Identifier: MIT
//! ethtool — pure-Zig **Ethernet device control** over the kernel's modern
//! `ethtool` generic-netlink family: link settings and state, ring / coalesce /
//! pause / channel parameters, netdev feature flags, the standardised
//! statistics groups, the kernel's own string tables and pluggable-module
//! access — with no `ethtool` shell-out, no ioctl and no libc.
//!
//! ```zig
//! const ethtool = @import("ethtool");
//!
//! var et = try ethtool.Ethtool.open(gpa);   // resolves the family id at runtime
//! defer et.close();
//! const dev = ethtool.Target.byName("eth0");
//!
//! const state = try et.linkState(dev);
//! var modes = try et.linkModes(dev, .verbose);   // .verbose = bitsets carry names
//! defer modes.deinit(gpa);
//! std.debug.print("link={?} {?d}Mb/s {s}\n", .{
//!     state.link, modes.speedMbps(), @tagName(modes.duplex orelse .unknown),
//! });
//!
//! const r = try et.rings(dev);              // every field optional = "n/a"
//! _ = .{ r.rx, r.rx_max, r.tx, r.tx_max };
//!
//! // A SET's ACK is not proof the change happened — read the result.
//! var res = try et.setFeaturesByName(dev, &.{.{ .name = "rx-gro", .on = false }});
//! defer res.deinit(gpa);
//! if (!res.fullyHonoured()) { /* the kernel kept something it would not change */ }
//! ```
//!
//! ## What this module is, and is not
//!
//! * **This is the netlink API, not the ioctl one.** Everything here rides
//!   `ETHTOOL_MSG_*` over generic netlink. The legacy `SIOCETHTOOL` path is
//!   **not** implemented, which has one visible consequence: `ethtool -i`
//!   (driver/firmware/bus info) and plain `ethtool -S` (the driver's private
//!   counter array) have *no netlink message at all* and are therefore not
//!   here. See SPEC.md for the honest deferred list.
//! * **Implemented:** `LINKINFO_GET`/`SET`, `LINKMODES_GET`/`SET`,
//!   `LINKSTATE_GET`, `RINGS_GET`/`SET`, `COALESCE_GET`/`SET`,
//!   `PAUSE_GET`/`SET`, `CHANNELS_GET`/`SET`, `FEATURES_GET`/`SET`,
//!   `STATS_GET`, `STRSET_GET`, `MODULE_GET`/`SET`, `MODULE_EEPROM_GET`, the
//!   `monitor` multicast group, and a **`raw` escape hatch** that reaches every
//!   remaining command (WOL, EEE, FEC, PRIVFLAGS, TSINFO, cable test, RSS, …).
//!
//! ## Bitsets are the part that bites
//!
//! Half of this family's interesting attributes are *bitsets*, and they arrive
//! in two entirely different encodings depending on one flag in the request —
//! compact word arrays, or a verbose per-bit nest carrying the kernel's names.
//! `bitset.zig`'s header explains which is which and when; both are pinned by
//! real captures.
//!
//! **Platform:** linux (raw `std.os.linux` syscalls over `AF_NETLINK` — a
//! conscious ceiling). **Privileges:** every GET here is unprivileged (except
//! `WOL_GET`, reachable through `raw`); every SET needs **CAP_NET_ADMIN**.
//!
//! Verification: `goldens.zig` asserts the encoders reproduce, byte for byte,
//! requests captured from a real `ethtool` under `strace`, and decodes the
//! kernel replies those requests received — including the same link-mode
//! bitset in both encodings, so the two decoders are checked against each
//! other. The tests at the bottom of this file run against the live kernel and
//! skip cleanly when a device does not implement an operation.
//!
//! Provenance: clean-room from the kernel UAPI
//! (`linux/ethtool_netlink_generated.h`, `linux/ethtool.h`, GPL-2.0 WITH
//! Linux-syscall-note — the message/attribute constants and their layouts are
//! the kernel's OS ABI, not copyrightable interface code). The `ethtool`
//! binary was used **only as a black-box capture oracle** under `strace`; no
//! `ethtool` source was read or ported. See `NOTICE`.

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
    .targets = .{.linux64},
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Ethtool/EventSocket per thread
    .model_after = "kernel UAPI linux/ethtool_netlink_generated.h + linux/ethtool.h; the `ethtool` binary used only as a black-box strace capture oracle",
    .deps = .{ "genetlink", "netlink" },
};

// ── submodules ─────────────────────────────────────────────────────────────

/// Kernel UAPI constants and enums (`MSG`, `REPLY`, every attribute set, the
/// `Port`/`Duplex`/`LinkExtState`/… enums).
pub const uapi = @import("uapi.zig");
/// The two bitset encodings — **read this before touching a bitset**.
pub const bitset = @import("bitset.zig");
/// The `ETHTOOL_A_*_HEADER` nest every message carries, and its flags.
pub const header = @import("header.zig");
/// `LINKINFO` / `LINKMODES` / `LINKSTATE`.
pub const link = @import("link.zig");
/// `RINGS` / `COALESCE` / `PAUSE` / `CHANNELS`.
pub const params = @import("params.zig");
/// `FEATURES_GET`/`SET`, including the partially-honoured-SET result.
pub const features = @import("features.zig");
/// `STATS_GET` and `STRSET_GET`.
pub const stats = @import("stats.zig");
/// `MODULE_GET`/`SET` and `MODULE_EEPROM_GET`.
pub const moduleinfo = @import("moduleinfo.zig");
/// The socket client and the `monitor` notification socket.
pub const client = @import("client.zig");

/// The generic-netlink transport this family rides on, re-exported so a caller
/// does not need a second import to drive the raw escape hatch.
pub const genl = @import("genetlink");
/// The netlink wire codec, for building `raw` request attributes.
pub const codec = netlink.codec;

// ── flat re-exports (the API most callers touch) ───────────────────────────

pub const Ethtool = client.Ethtool;
pub const EventSocket = client.EventSocket;
pub const Notification = client.Notification;
pub const BitsetForm = client.BitsetForm;
pub const RequestError = client.RequestError;
pub const OpenError = client.OpenError;
pub const SubscribeError = client.SubscribeError;

pub const Target = header.Target;
pub const Device = header.Device;
pub const Bitset = bitset.Bitset;
pub const LinkInfo = link.LinkInfo;
pub const LinkModes = link.LinkModes;
pub const LinkModesSet = link.LinkModesSet;
pub const LinkState = link.LinkState;
pub const Rings = params.Rings;
pub const RingsSet = params.RingsSet;
pub const Coalesce = params.Coalesce;
pub const CoalesceSet = params.CoalesceSet;
pub const Pause = params.Pause;
pub const PauseSet = params.PauseSet;
pub const Channels = params.Channels;
pub const ChannelsSet = params.ChannelsSet;
pub const Features = features.Features;
pub const FeatureSetResult = features.SetResult;
pub const Stats = stats.Stats;
pub const StringSets = stats.StringSets;
pub const ModuleInfo = moduleinfo.ModuleInfo;
pub const Eeprom = moduleinfo.Eeprom;

pub const Port = uapi.Port;
pub const Duplex = uapi.Duplex;
pub const MdiX = uapi.MdiX;
pub const Transceiver = uapi.Transceiver;
pub const LinkExtState = uapi.LinkExtState;
pub const StatsGroup = uapi.StatsGroup;
pub const StringSetId = uapi.StringSetId;
pub const mcast_group = uapi.mcast_group;
pub const family_name = uapi.family_name;
/// The standard statistics group names, in bit order.
pub const stats_group_names = stats.group_names;

// ── live tests (real kernel; skip cleanly, never fail) ─────────────────────
//
// Every GET below runs for real against a network interface on this machine.
// Nothing here changes system state: no SET is issued except in the explicitly
// privileged test at the end, which skips without CAP_NET_ADMIN. When a driver
// does not implement an operation — which is normal and common — the test
// prints `SKIPPED: …` and passes.

const testing = std.testing;

fn skip(comptime what: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: {s}\n", .{what});
    return error.SkipZigTest;
}

fn openOrSkip() !Ethtool {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Ethtool.open(testing.allocator) catch |e| switch (e) {
        error.FamilyNotFound => skip("the ethtool netlink family is not registered in this kernel"),
        else => skip("opening a NETLINK_GENERIC socket"),
    };
}

/// `ARPHRD_ETHER` — the link type an ethtool-capable NIC has.
const arphrd_ether: u16 = 1;

/// Interface-name prefixes that are most likely to be a physical NIC, best
/// first. Anything else that is Ethernet-typed is taken as a fallback.
const candidate_prefixes = [_][]const u8{ "en", "eth", "wl" };

/// Pick one interface to test against, using the sibling `netlink` module's
/// `RTM_GETLINK` dump rather than `/sys` — same no-libc discipline, and it
/// yields the link type so a loopback or tunnel is not mistaken for a NIC.
/// Returns null when this namespace has no Ethernet interface at all.
fn findInterface(buf: *[uapi.ifnamesize]u8) !?[]const u8 {
    var sock = netlink.Socket.open(testing.allocator) catch return null;
    defer sock.close();
    const links = sock.links() catch return null;
    defer testing.allocator.free(links);

    var best_len: ?usize = null;
    var best_rank: usize = candidate_prefixes.len + 1;
    for (links) |l| {
        if (l.hw_type != arphrd_ether) continue;
        const n = l.name();
        if (n.len == 0 or n.len >= uapi.ifnamesize) continue;
        var rank: usize = candidate_prefixes.len;
        for (candidate_prefixes, 0..) |p, i| {
            if (std.mem.startsWith(u8, n, p)) {
                rank = i;
                break;
            }
        }
        if (rank < best_rank) {
            best_rank = rank;
            @memcpy(buf[0..n.len], n);
            best_len = n.len;
        }
    }
    return if (best_len) |n| buf[0..n] else null;
}

fn targetOrSkip(buf: *[uapi.ifnamesize]u8) !Target {
    const name = (try findInterface(buf)) orelse
        return skip("no Ethernet-type interface in this network namespace");
    return Target.byName(name);
}

test "live: the ethtool family id resolves and is genuinely dynamic" {
    var et = try openOrSkip();
    defer et.close();
    // Whatever it is, it is a real dynamic genl id: above nlctrl's fixed 0x10.
    try testing.expect(et.family_id > genl.GENL_ID_CTRL);
}

test "live: LINKSTATE_GET on a real interface (unprivileged)" {
    var et = try openOrSkip();
    defer et.close();
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    const st = et.linkState(dev) catch |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.InvalidRequest => return skip("LINKSTATE_GET on this device"),
        error.AccessDenied => return skip("LINKSTATE_GET (needs privilege here)"),
        else => return e,
    };
    // The kernel always answers with the device it was asked about.
    try testing.expectEqualStrings(dev.name, st.device.name());
    try testing.expect(st.device.index != null);
    try testing.expect(st.device.index.? > 0);
    if (st.sqi) |q| {
        if (st.sqi_max) |m| try testing.expect(q <= m);
    }
    if (st.link) |up| {
        // ext_state only means anything on a link that is down.
        if (up) try testing.expect(st.ext_state == null);
    }
}

test "live: LINKMODES_GET decodes in BOTH bitset encodings, and they agree" {
    // The strongest live assertion in this module: ask the same kernel for the
    // same data twice, once verbose and once compact, and require every bit to
    // match. A decoder bug in either form shows up here on any machine.
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    var verbose = et.linkModes(dev, .verbose) catch |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.InvalidRequest => {
            // A Wi-Fi or virtual interface has no ethtool link settings; the
            // kernel usually says so in words.
            if (verboseSkip()) if (et.lastErrorMessage()) |m| std.debug.print("  (kernel said: {s})\n", .{m});
            return skip("LINKMODES_GET on this device");
        },
        error.AccessDenied => return skip("LINKMODES_GET"),
        else => return e,
    };
    defer verbose.deinit(gpa);
    var compact = try et.linkModes(dev, .compact);
    defer compact.deinit(gpa);

    const v_ours = verbose.ours orelse return skip("the kernel sent no link-mode bitset");
    const c_ours = compact.ours orelse return skip("the kernel sent no link-mode bitset");
    try testing.expectEqual(bitset.Bitset.Encoding.verbose, v_ours.encoding());
    try testing.expectEqual(bitset.Bitset.Encoding.compact, c_ours.encoding());
    const size = c_ours.size orelse return skip("the kernel sent a bitset with no SIZE");
    try testing.expectEqual(@as(?u32, size), v_ours.size);
    // ceil(size/32) words, exactly.
    try testing.expectEqual(@as(usize, (size + 31) / 32), c_ours.value_words.?.len);

    var i: u32 = 0;
    while (i < size) : (i += 1) {
        try testing.expectEqual(verbose.supports(i), compact.supports(i));
        try testing.expectEqual(verbose.advertises(i), compact.advertises(i));
        // Advertising a mode you do not support is impossible.
        if (compact.advertises(i)) try testing.expect(compact.supports(i));
        // Only the verbose form has names, and it has one for every bit it
        // mentions.
        if (verbose.supports(i)) try testing.expect(v_ours.nameOf(i) != null);
    }
    try testing.expectEqual(verbose.autoneg, compact.autoneg);
    try testing.expectEqual(verbose.duplex, compact.duplex);
}

test "live: LINKINFO_GET (unprivileged)" {
    var et = try openOrSkip();
    defer et.close();
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);
    const li = et.linkInfo(dev) catch |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.InvalidRequest => return skip("LINKINFO_GET on this device"),
        error.AccessDenied => return skip("LINKINFO_GET"),
        else => return e,
    };
    try testing.expectEqualStrings(dev.name, li.device.name());
    if (li.port) |p| {
        // Every value the kernel can send is representable, including the two
        // sentinels at the top of the range.
        const raw: u8 = @intFromEnum(p);
        try testing.expect(raw <= 5 or raw == 0xef or raw == 0xff);
    }
}

test "live: RINGS / COALESCE / PAUSE / CHANNELS gets (unprivileged)" {
    var et = try openOrSkip();
    defer et.close();
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    var answered: usize = 0;

    if (et.rings(dev)) |r| {
        answered += 1;
        try testing.expectEqualStrings(dev.name, r.device.name());
        // A current setting never exceeds its own maximum.
        if (r.rx) |v| if (r.rx_max) |m| try testing.expect(v <= m);
        if (r.tx) |v| if (r.tx_max) |m| try testing.expect(v <= m);
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied, error.InvalidRequest => {},
        else => return e,
    }

    if (et.coalesce(dev)) |c| {
        answered += 1;
        try testing.expectEqualStrings(dev.name, c.device.name());
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied, error.InvalidRequest => {},
        else => return e,
    }

    if (et.pauseParams(dev, true)) |p| {
        answered += 1;
        try testing.expectEqualStrings(dev.name, p.device.name());
        // Asking with ETHTOOL_FLAG_STATS is allowed to yield no stats at all.
        if (p.stats) |s| {
            if (s.tx_frames) |v| std.mem.doNotOptimizeAway(v);
        }
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied, error.InvalidRequest => {},
        else => return e,
    }

    if (et.channels(dev)) |ch| {
        answered += 1;
        try testing.expectEqualStrings(dev.name, ch.device.name());
        if (ch.rx_count) |v| if (ch.rx_max) |m| try testing.expect(v <= m);
        if (ch.combined_count) |v| if (ch.combined_max) |m| try testing.expect(v <= m);
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied, error.InvalidRequest => {},
        else => return e,
    }

    if (answered == 0) return skip("this device implements none of RINGS/COALESCE/PAUSE/CHANNELS");
}

test "live: FEATURES_GET, cross-checked against the kernel's own name table" {
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    var f = et.features(dev, .compact) catch |e| switch (e) {
        error.NotSupported,
        error.NoSuchDevice,
        error.AccessDenied,
        error.InvalidRequest,
        => return skip("FEATURES_GET on this device"),
        else => return e,
    };
    defer f.deinit(gpa);
    const hw = f.hw orelse return skip("the kernel sent no `hw` feature bitset");
    const size = hw.size orelse return skip("feature bitset with no SIZE");

    // The names come from a separate, device-independent request.
    var sets = et.stringSet(null, &.{.features}) catch |e| switch (e) {
        error.NotSupported, error.AccessDenied => return skip("STRSET_GET of ETH_SS_FEATURES"),
        else => return e,
    };
    defer sets.deinit(gpa);
    const names = sets.byId(.features) orelse return skip("kernel returned no feature name set");
    // The table describes exactly the bitset the same kernel just sent.
    try testing.expectEqual(@as(?u32, size), names.count);
    try testing.expectEqual(@as(usize, size), names.entries.len);
    for (names.entries) |e| {
        try testing.expect(e.index < size);
        // Reserved bits are named with an *empty* string, so emptiness is not
        // an error — but every index the kernel declares must be present.
        try testing.expect(names.get(e.index) != null);
    }
    // All four bitsets describe the same bit space.
    for ([_]?bitset.Bitset{ f.wanted, f.active, f.nochange }) |maybe| {
        if (maybe) |b| try testing.expectEqual(@as(?u32, size), b.size);
    }

    var active_count: u32 = 0;
    var i: u32 = 0;
    while (i < size) : (i += 1) {
        if (f.isActiveAt(i)) {
            active_count += 1;
            try testing.expect(names.get(i) != null);
        }
    }
    // Every netdev has *some* feature on. Note what is deliberately NOT
    // asserted: that an active bit is also in `hw`. "highdma" is active on
    // real hardware without appearing in `hw` at all (see goldens.zig), so
    // that implication is simply false.
    try testing.expect(active_count > 0);

    // And the verbose form of the same request names them inline. Note the
    // comparison uses `isSet`, not the raw `Bit.value`: `active` is a NOMASK
    // list, where the kernel omits the VALUE flag and presence *is* the value.
    var verbose = try et.features(dev, .verbose);
    defer verbose.deinit(gpa);
    if (verbose.active) |a| {
        if (a.bits) |bits| {
            for (bits) |b| {
                const idx = b.index orelse continue;
                try testing.expect(f.isActiveAt(idx));
                try testing.expect(a.isSet(idx));
                if (b.name) |n| try testing.expectEqualStrings(names.get(idx).?, n);
            }
            // Both encodings must agree on the count of active features.
            try testing.expectEqual(active_count, a.count());
        }
    }
    // The same question by name, answered off the verbose reply alone.
    if (names.get(0)) |first| {
        if (first.len > 0) try testing.expectEqual(
            @as(?bool, f.isActiveAt(0)),
            verbose.isActive(first),
        );
    }
}

test "live: STATS_GET of the standard groups (unprivileged)" {
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    var st = et.stats(dev, &.{ "eth-mac", "eth-ctrl", "rmon" }) catch |e| switch (e) {
        error.NotSupported,
        error.NoSuchDevice,
        error.AccessDenied,
        error.InvalidRequest,
        => return skip("STATS_GET on this device"),
        else => return e,
    };
    defer st.deinit(gpa);
    try testing.expectEqualStrings(dev.name, st.device.name());

    // Most drivers implement none of the standardised groups and answer with
    // empty ones — that is a valid reply, and asserting otherwise would make
    // this test machine-dependent.
    for (st.groups) |g| {
        const id = g.id orelse continue;
        try testing.expect(stats.groupName(id) != null);
        try testing.expect(g.ss_id != null);
        for (g.hist_rx) |b| {
            if (b.hi != 0) try testing.expect(b.hi >= b.low);
        }
    }

    // Whatever the groups contain, their counter names are fetchable.
    var sets = try et.stringSet(null, &.{.stats_std});
    defer sets.deinit(gpa);
    const std_set = sets.byId(.stats_std) orelse return skip("kernel returned no ETH_SS_STATS_STD");
    // The module's hardcoded group-name table must match this kernel's.
    for (stats.group_names, 0..) |name, i| {
        const kernel_name = std_set.get(@intCast(i)) orelse continue;
        try testing.expectEqualStrings(name, kernel_name);
    }
}

test "live: an unimplemented operation is a typed error, often with the kernel's words" {
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;

    // `lo` exists on every Linux system and implements essentially none of
    // this family — a reliable way to exercise the refusal path.
    if (et.rings(Target.byName("lo"))) |_| {
        // A kernel where loopback grew ring parameters: fine, nothing to test.
    } else |e| switch (e) {
        error.NotSupported, error.InvalidRequest => {
            if (et.lastErrorMessage()) |m| try testing.expect(m.len > 0);
        },
        error.NoSuchDevice => {},
        else => return e,
    }

    // A device that does not exist is ENODEV/ENOENT, not a malformed reply.
    var modes = et.linkModes(Target.byName("zig-libs-nope"), .verbose) catch |e| switch (e) {
        error.NoSuchDevice, error.NotSupported, error.InvalidRequest => return,
        else => return e,
    };
    modes.deinit(gpa);
    return error.TestUnexpectedResult;
}

test "live: MODULE_GET / MODULE_EEPROM_GET (skips without a pluggable module)" {
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    const info = et.moduleInfo(dev) catch |e| switch (e) {
        error.NotSupported,
        error.NoSuchDevice,
        error.AccessDenied,
        error.InvalidRequest,
        => return skip("MODULE_GET (no pluggable transceiver on this device)"),
        else => return e,
    };
    if (info.power_mode_policy) |p| try testing.expect(@intFromEnum(p) != 0);

    var eeprom = et.moduleEeprom(dev, .{ .length = 1, .offset = 0 }) catch |e| switch (e) {
        error.NotSupported, error.AccessDenied, error.InvalidRequest => return skip("MODULE_EEPROM_GET"),
        else => return e,
    };
    defer eeprom.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), eeprom.data.len);
}

test "live: the `monitor` multicast group resolves and can be joined" {
    var et = try openOrSkip();
    defer et.close();
    const id = et.resolveMulticastGroup(mcast_group.monitor) catch |e| switch (e) {
        error.GroupNotFound => return skip("this kernel's ethtool family publishes no `monitor` group"),
        error.AccessDenied => return skip("multicast group resolution"),
        else => return e,
    };
    try testing.expect(id != 0);

    var events = EventSocket.openWith(&et, &.{mcast_group.monitor}) catch |e| switch (e) {
        error.AccessDenied => return skip("joining the monitor multicast group"),
        else => return e,
    };
    defer events.close();
    try testing.expect(events.fd() >= 0);
    // No blocking read here on purpose: nothing may change any device's
    // settings during a test run, and this module owns no timer to bound the
    // wait with. A caller that needs one polls `events.fd()` — see the README.
}

test "live: the raw escape hatch reaches a command the typed API does not model" {
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    // ETHTOOL_MSG_TSINFO_GET — deliberately not in the typed API.
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try header.append(gpa, &attrs, 1, .{ .target = dev, .compact_bitsets = true });

    const replies = et.raw(.{ .cmd = uapi.MSG.TSINFO_GET, .attrs = attrs.items }) catch |e| switch (e) {
        error.NotSupported, error.InvalidRequest, error.NoSuchDevice => return skip("raw TSINFO_GET"),
        error.AccessDenied => return skip("raw TSINFO_GET (needs privilege)"),
        else => return e,
    };
    defer Ethtool.freeRawReplies(gpa, replies);
    if (replies.len == 0) return skip("kernel answered TSINFO_GET with a bare ACK");
    try testing.expectEqual(uapi.REPLY.TSINFO_GET, replies[0].cmd);
    // The reply's leading attribute is a header nest naming the same device.
    const d = (try header.parseLeading(replies[0].attrs)) orelse return skip("TSINFO reply carried no header");
    try testing.expectEqualStrings(dev.name, d.name());
}

test "live (root): a SET round-trip that puts the value back" {
    // Needs CAP_NET_ADMIN. It writes the ring's *current* rx size back
    // unchanged, so even when it does run it changes nothing.
    var et = try openOrSkip();
    defer et.close();
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    const before = et.rings(dev) catch return skip("RINGS_GET (needed by the SET test)");
    const rx = before.rx orelse return skip("this device reports no current rx ring size");

    et.setRings(dev, .{ .rx = rx }) catch |e| switch (e) {
        error.AccessDenied => return skip("RINGS_SET (needs CAP_NET_ADMIN)"),
        error.NotSupported, error.InvalidRequest, error.Busy => return skip("RINGS_SET on this device"),
        else => return e,
    };
    const after = try et.rings(dev);
    try testing.expectEqual(before.rx, after.rx);
    try testing.expectEqual(before.tx, after.tx);
}

test "live (root): FEATURES_SET is judged by its reply, not by its ACK" {
    // Needs CAP_NET_ADMIN. It re-requests a feature's *current* state, so it
    // is a no-op even when it runs — the point is to exercise the SET path and
    // prove the reply says "nothing changed, nothing refused".
    var et = try openOrSkip();
    defer et.close();
    const gpa = testing.allocator;
    var buf: [uapi.ifnamesize]u8 = undefined;
    const dev = try targetOrSkip(&buf);

    var f = et.features(dev, .verbose) catch return skip("FEATURES_GET (needed by the SET test)");
    defer f.deinit(gpa);
    const active = f.active orelse return skip("no `active` feature bitset");
    const bits = active.bits orelse return skip("kernel answered with a compact bitset");

    // Something that is on now and that the device can genuinely do.
    var chosen: ?[]const u8 = null;
    for (bits) |b| {
        const idx = b.index orelse continue;
        if (!f.isSupportedAt(idx) or f.isFixedAt(idx)) continue;
        chosen = b.name orelse continue;
        break;
    }
    const name = chosen orelse return skip("no changeable active feature on this device");

    var res = et.setFeaturesByName(dev, &.{.{ .name = name, .on = true }}) catch |e| switch (e) {
        error.AccessDenied => return skip("FEATURES_SET (needs CAP_NET_ADMIN)"),
        error.NotSupported, error.InvalidRequest, error.Busy => return skip("FEATURES_SET on this device"),
        else => return e,
    };
    defer res.deinit(gpa);
    // Asking for what is already true must be honoured and must change nothing.
    try testing.expect(res.fullyHonoured());
    try testing.expectEqual(@as(u32, 0), res.unhonouredCount());
    try testing.expectEqual(@as(u32, 0), res.changedCount());

    // …and the device really is unchanged.
    var after = try et.features(dev, .verbose);
    defer after.deinit(gpa);
    try testing.expectEqual(@as(?bool, true), after.isActive(name));
}

// ── dark-tests aggregator ──────────────────────────────────────────────────
// A bare `pub const x = @import(…)` re-export does NOT pull x's tests into the
// test binary (CONVENTIONS §6.3).

test {
    _ = uapi;
    _ = bitset;
    _ = header;
    _ = link;
    _ = params;
    _ = features;
    _ = stats;
    _ = moduleinfo;
    _ = client;
    _ = @import("goldens.zig");
}
