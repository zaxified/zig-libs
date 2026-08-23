// SPDX-License-Identifier: MIT
//! devlink — pure-Zig **device management** over the kernel's `devlink`
//! generic-netlink family: enumerating devlink instances and their ports,
//! reading and writing driver parameters, walking the recursive hardware
//! resource tree, taking and reading region snapshots, watching health
//! reporters and switching the embedded switch's mode — with no `devlink`
//! shell-out, no `/sys` parsing and no libc.
//!
//! ```zig
//! const devlink = @import("devlink");
//!
//! var dl = try devlink.Devlink.open(gpa);   // resolves the family id at runtime
//! defer dl.close();
//!
//! const devices = try dl.devices();          // empty on a machine with no SmartNIC
//! defer gpa.free(devices);
//! for (devices) |d| std.debug.print("{f}\n", .{d.handle});
//!
//! const h = devlink.Handle.pci("0000:65:00.0");
//!
//! const ports = try dl.ports(h);
//! defer gpa.free(ports);
//!
//! var info = try dl.info(h);
//! defer info.deinit(gpa);
//! if (info.hasPendingUpdate()) { /* firmware flashed, waiting for a reset */ }
//!
//! var res = try dl.resources(h);             // recursive; bounded depth
//! defer res.deinit(gpa);
//! if (res.find("linear")) |r| _ = r.size;
//! ```
//!
//! ## What this module is, and is not
//!
//! * **Implemented:** `GET` (device enumeration), `PORT_GET`/`PORT_SET`/
//!   `PORT_SPLIT`/`PORT_UNSPLIT`, `PARAM_GET`/`PARAM_SET`,
//!   `RESOURCE_DUMP`/`RESOURCE_SET`, `REGION_GET`/`REGION_NEW`/`REGION_DEL`/
//!   `REGION_READ`, `HEALTH_REPORTER_GET`/`HEALTH_REPORTER_RECOVER`,
//!   `ESWITCH_GET`/`ESWITCH_SET`, `INFO_GET`, the `config` multicast group, and
//!   a **`raw` escape hatch** that reaches every remaining command.
//! * **Deliberately not modelled in v1:** rate objects, traps and trap
//!   groups/policers, DPIPE, shared buffers (`SB_*`), flash update, selftests,
//!   linecards, `RELOAD`, port functions and `PORT_NEW`/`PORT_DEL`. devlink is
//!   large; the ceiling is documented, and everything above the line is
//!   reachable through `raw`. See SPEC.md for the full list and the reasoning.
//!
//! ## Three things about this family that bite
//!
//! 1. **The handle is two strings, not an ifindex.** A devlink instance is
//!    `bus_name` + `dev_name` (`pci/0000:65:00.0`), it may have no netdev at
//!    all, and a devlink *port* is a switch object rather than an interface.
//!    See `handle.zig`.
//! 2. **A parameter's value type is carried in the message.**
//!    `DEVLINK_ATTR_PARAM_VALUE_DATA` is `dynamic`; its width comes from
//!    `PARAM_TYPE` in the same nest, so the decoder dispatches rather than
//!    tabulates. See `param.zig`.
//! 3. **The resource list is recursive and unbounded on the wire.** The
//!    decoder carries an explicit depth and node budget, and a hostile deeply
//!    nested stream is a typed error rather than a stack overflow. See
//!    `resource.zig`.
//!
//! **Platform:** linux (raw `std.os.linux` syscalls over `AF_NETLINK` — a
//! conscious ceiling). **Privileges:** the enumeration and read commands are
//! unprivileged, with two exceptions the kernel marks `GENL_ADMIN_PERM` —
//! `ESWITCH_GET` and `REGION_READ`. Every write needs **CAP_NET_ADMIN**.
//!
//! **Most machines have no devlink device.** The family is registered by any
//! kernel built with `CONFIG_NET_DEVLINK`, but instances are created only by
//! SmartNIC and switch-ASIC drivers (mlx4, mlx5, ice, bnxt, nfp, mlxsw,
//! prestera, …) and by `netdevsim`. An ordinary NIC registers none, and
//! `devices()` correctly returns an empty slice. The live tests below treat
//! that as the expected case.
//!
//! Verification: `goldens.zig` asserts the encoders reproduce, byte for byte,
//! requests captured from a real `devlink` (iproute2 6.19) under `strace`, and
//! decodes the kernel replies that were reachable without devlink hardware —
//! the nlctrl family reply, an empty dump's `NLMSG_DONE`, and the `ENODEV` and
//! `EPERM` errors. The object-reply goldens are UAPI-derived and say so. The
//! tests at the bottom of this file run against the live kernel and skip
//! cleanly when there is nothing to talk to.
//!
//! Provenance: clean-room from the kernel UAPI (`linux/devlink.h`, GPL-2.0+
//! WITH Linux-syscall-note — the command/attribute constants and their layouts
//! are the kernel's OS ABI, not copyrightable interface code). The `devlink`
//! binary from iproute2 was used **only as a black-box capture oracle** under
//! `strace`; no iproute2 source was read or ported. See `NOTICE`.

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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Linux devlink over genetlink — device/port enumeration, port split/unsplit, parameter/resource inspection, region snapshots, health reporters, eswitch mode",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Devlink/EventSocket per thread
    .model_after = "kernel UAPI linux/devlink.h; the iproute2 `devlink` binary used only as a black-box strace capture oracle",
    .deps = .{ "genetlink", "netlink" },
};

// ── submodules ─────────────────────────────────────────────────────────────

/// Kernel UAPI constants and enums (`CMD`, the flat `ATTR` space, the
/// `PortType`/`PortFlavour`/`ParamType`/`ParamCmode`/… enums).
pub const uapi = @import("uapi.zig");
/// The `bus_name`/`dev_name` handle every message carries — **read this
/// first**.
pub const handle = @import("handle.zig");
/// `DEVLINK_CMD_GET` and `INFO_GET`.
pub const dev = @import("dev.zig");
/// `PORT_GET` / `PORT_SET` / `PORT_SPLIT` / `PORT_UNSPLIT`.
pub const port = @import("port.zig");
/// `PARAM_GET` / `PARAM_SET`, including the type-dispatched value.
pub const param = @import("param.zig");
/// `RESOURCE_DUMP` / `RESOURCE_SET` — the recursive one.
pub const resource = @import("resource.zig");
/// `REGION_GET` / `REGION_NEW` / `REGION_DEL` / `REGION_READ`, with the
/// chunk reassembler.
pub const region = @import("region.zig");
/// `HEALTH_REPORTER_GET` / `HEALTH_REPORTER_RECOVER`.
pub const health = @import("health.zig");
/// `ESWITCH_GET` / `ESWITCH_SET`.
pub const eswitch = @import("eswitch.zig");
/// The socket client and the `config` notification socket.
pub const client = @import("client.zig");

/// The generic-netlink transport this family rides on, re-exported so a caller
/// does not need a second import to drive the raw escape hatch.
pub const genl = @import("genetlink");
/// The netlink wire codec, for building `raw` request attributes.
pub const codec = netlink.codec;

// ── flat re-exports (the API most callers touch) ───────────────────────────

pub const Devlink = client.Devlink;
pub const EventSocket = client.EventSocket;
pub const Notification = client.Notification;
pub const Reply = client.Reply;
pub const RequestError = client.RequestError;
pub const OpenError = client.OpenError;
pub const SubscribeError = client.SubscribeError;

pub const Handle = handle.Handle;
pub const PortHandle = handle.PortHandle;
pub const OwnedHandle = handle.Owned;

pub const Device = dev.Device;
pub const Info = dev.Info;
pub const Version = dev.Version;
pub const VersionKind = dev.VersionKind;
pub const Port = port.Port;
pub const Param = param.Param;
pub const ParamValue = param.ParamValue;
pub const Value = param.Value;
pub const Resource = resource.Resource;
pub const Resources = resource.Resources;
pub const Region = region.Region;
pub const RegionData = region.Data;
pub const RegionRead = region.ReadRequest;
pub const Reporter = health.Reporter;
pub const Eswitch = eswitch.Eswitch;
pub const EswitchSet = eswitch.Set;

pub const PortType = uapi.PortType;
pub const PortFlavour = uapi.PortFlavour;
pub const ParamType = uapi.ParamType;
pub const ParamCmode = uapi.ParamCmode;
pub const EswitchMode = uapi.EswitchMode;
pub const InlineMode = uapi.InlineMode;
pub const EncapMode = uapi.EncapMode;
pub const HealthState = uapi.HealthState;
pub const mcast_group = uapi.mcast_group;
pub const family_name = uapi.family_name;

/// Free a slice of parameters and everything they own.
pub const freeParams = param.freeAll;

// ── live tests (real kernel; skip cleanly, never fail) ─────────────────────
//
// Every request below runs for real against this machine's kernel. Nothing
// here changes system state: no SET, SPLIT, SNAPSHOT or RECOVER is ever
// issued, not even under privilege — devlink writes reset hardware, and a
// test suite has no business doing that to a machine it did not provision.
//
// **A machine with no devlink-capable device is the expected case**, and every
// test below passes on one: the family still resolves, the dumps still run,
// and they come back empty. When there is nothing further to assert the test
// prints `SKIPPED: …` and passes.

const testing = std.testing;

fn skip(comptime what: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: {s}\n", .{what});
    return error.SkipZigTest;
}

fn openOrSkip() !Devlink {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Devlink.open(testing.allocator) catch |e| switch (e) {
        error.FamilyNotFound => skip("this kernel has no devlink family (CONFIG_NET_DEVLINK off)"),
        else => skip("opening a NETLINK_GENERIC socket"),
    };
}

/// The first devlink instance on this machine, or null. Almost every test
/// below needs one and almost every machine has none.
fn firstDevice(dl: *Devlink) !?Device {
    const list = dl.devices() catch |e| switch (e) {
        error.AccessDenied, error.NotSupported => return null,
        else => return e,
    };
    defer testing.allocator.free(list);
    return if (list.len == 0) null else list[0];
}

test "live: the devlink family id resolves and is genuinely dynamic" {
    var dl = try openOrSkip();
    defer dl.close();
    // Whatever it is, it is a real dynamic genl id: above nlctrl's fixed 0x10.
    try testing.expect(dl.family_id > genl.GENL_ID_CTRL);
}

test "live: DEVLINK_CMD_GET dump (an empty result is the normal answer)" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    const list = try dl.devices();
    defer gpa.free(list);

    for (list) |d| {
        // Whatever the kernel sent, it named the instance properly.
        try testing.expect(d.handle.isComplete());
        try testing.expect(d.handle.bus().len > 0);
        try testing.expect(d.handle.dev().len > 0);
        // And the handle round-trips through the CLI's textual form.
        var buf: [128]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "{f}", .{d.handle});
        const parsed = try Handle.parse(s);
        try testing.expect(d.handle.eql(parsed));
    }
    if (list.len == 0)
        return skip("no devlink instance on this machine (no SmartNIC/switch ASIC; e1000e and iwlwifi register none)");
    // Success-path diagnostic: gated because scripts/test-lib.sh treats any
    // stderr from a passing step as a failure — a rule that only holds if
    // passing tests stay silent.
    if (verboseSkip()) std.debug.print("  (found {d} devlink instance(s))\n", .{list.len});
}

test "live: PORT_GET dump, and the ports belong to devices that exist" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    const ports = try dl.ports(null);
    defer gpa.free(ports);

    if (ports.len == 0) return skip("no devlink ports on this machine");

    const devices = try dl.devices();
    defer gpa.free(devices);
    for (ports) |p| {
        try testing.expect(p.handle.isComplete());
        try testing.expect(p.index != null);
        // Every port's handle must name an instance the device dump listed.
        var matched = false;
        for (devices) |d| {
            if (std.mem.eql(u8, d.handle.bus(), p.handle.bus()) and
                std.mem.eql(u8, d.handle.dev(), p.handle.dev())) matched = true;
        }
        try testing.expect(matched);
        // A split lane always belongs to a front-panel port.
        if (p.isSplit()) try testing.expect(p.number != null);
    }

    // Filtering by the first device's handle must be a subset of the whole.
    const filtered = try dl.ports(devices[0].handle.borrow());
    defer gpa.free(filtered);
    try testing.expect(filtered.len <= ports.len);
    for (filtered) |p| try testing.expect(p.handle.eql(devices[0].handle.borrow()));
}

test "live: PARAM_GET / REGION_GET / HEALTH_REPORTER_GET dumps" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    const params = try dl.params(null);
    defer freeParams(gpa, params);
    for (params) |p| {
        try testing.expect(p.name_len > 0);
        // A parameter always declares its type; without one its values could
        // not be decoded at all.
        try testing.expect(p.type != null);
        for (p.values) |v| try testing.expect(v.cmode != null);
    }

    const regions = try dl.regions(null);
    defer gpa.free(regions);
    for (regions) |r| {
        try testing.expect(r.name_len > 0);
        if (r.max_snapshots_allowed) |m| try testing.expect(r.snapshot_count <= m);
    }

    const reporters = try dl.healthReporters(null);
    defer gpa.free(reporters);
    for (reporters) |r| {
        try testing.expect(r.name_len > 0);
        if (r.unrecoveredCount()) |n| try testing.expect(n <= r.err_count.?);
    }

    if (params.len == 0 and regions.len == 0 and reporters.len == 0)
        return skip("no devlink parameters, regions or health reporters on this machine");
    // Behind `verboseSkip()` like the inventory line at the top of this file.
    // An informational print on a PASSING test is not free: the gate driver
    // treats any stderr from a step that exited 0 as a failure, so this line
    // turned a green CI lane red on a runner that happens to have a devlink
    // instance. This host has none, so the path never ran here — which is why
    // it took CI to find it and why it cannot be reproduced by dropping
    // `unshare` locally.
    if (verboseSkip()) std.debug.print(
        "  ({d} param(s), {d} region(s), {d} reporter(s))\n",
        .{ params.len, regions.len, reporters.len },
    );
}

test "live: INFO_GET and RESOURCE_DUMP on a real instance" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    const d = (try firstDevice(&dl)) orelse return skip("INFO_GET (no devlink instance here)");
    const h = d.handle.borrow();

    if (dl.info(h)) |got| {
        var i = got;
        defer i.deinit(gpa);
        try testing.expect(i.handle.eql(h));
        for (i.versions) |*v| try testing.expect(v.name_len > 0);
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied => {
            if (verboseSkip()) std.debug.print("  (INFO_GET refused: {s})\n", .{@errorName(e)});
        },
        else => return e,
    }

    if (dl.resources(h)) |got| {
        var rs = got;
        defer rs.deinit(gpa);
        // Whatever the tree is, it stayed within the decoder's bounds and
        // every reported size respects its own maximum.
        try testing.expect(rs.count() <= resource.max_nodes);
        for (rs.roots) |r| {
            if (r.size) |s| {
                if (r.size_max) |m| try testing.expect(s <= m);
            }
        }
    } else |e| switch (e) {
        error.NotSupported, error.NoSuchDevice, error.AccessDenied => {
            if (verboseSkip()) std.debug.print("  (RESOURCE_DUMP refused: {s})\n", .{@errorName(e)});
        },
        else => return e,
    }
}

test "live: a handle no driver registered is a typed error, not a hang" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    // The x86 host bridge: a real PCI address, never a devlink instance.
    const nowhere: Handle = .pci("0000:00:00.0");
    if (dl.info(nowhere)) |got| {
        var i = got;
        i.deinit(gpa);
        return error.TestUnexpectedResult;
    } else |e| switch (e) {
        error.NoSuchDevice, error.NotSupported, error.InvalidRequest, error.AccessDenied => {},
        else => return e,
    }

    // ESWITCH_GET is GENL_ADMIN_PERM: unprivileged it is EPERM, and that is a
    // different answer from "no such device" — both are acceptable here.
    if (dl.eswitch(nowhere)) |_| {
        return error.TestUnexpectedResult;
    } else |e| switch (e) {
        error.AccessDenied, error.NoSuchDevice, error.NotSupported, error.InvalidRequest => {},
        else => return e,
    }

    // A request this module knows the kernel would reject never reaches it.
    try testing.expectError(error.InvalidRequest, dl.info(.{ .bus = "", .dev = "x" }));
    try testing.expectError(error.InvalidRequest, dl.param(nowhere, ""));
    try testing.expectError(error.InvalidRequest, dl.readRegion(nowhere, .{
        .region = "cr-space",
        .length = 0,
    }));
}

test "live: the `config` multicast group resolves and can be joined" {
    var dl = try openOrSkip();
    defer dl.close();
    const id = dl.resolveMulticastGroup(mcast_group.config) catch |e| switch (e) {
        error.GroupNotFound => return skip("this kernel's devlink family publishes no `config` group"),
        error.AccessDenied => return skip("multicast group resolution"),
        else => return e,
    };
    try testing.expect(id != 0);
    // devlink publishes exactly one group; anything else is not there.
    try testing.expectError(error.GroupNotFound, dl.resolveMulticastGroup("zig-libs-nope"));

    var events = EventSocket.openWith(&dl, &.{mcast_group.config}) catch |e| switch (e) {
        error.AccessDenied => return skip("joining the config multicast group"),
        else => return e,
    };
    defer events.close();
    try testing.expect(events.fd() >= 0);
    // No blocking read here on purpose: nothing may change any device's
    // configuration during a test run, and this module owns no timer to bound
    // the wait with. A caller that needs one polls `events.fd()` — see the
    // README.
}

test "live: the raw escape hatch reaches a command the typed API does not model" {
    var dl = try openOrSkip();
    defer dl.close();
    const gpa = testing.allocator;

    // DEVLINK_CMD_RATE_GET — deliberately not in the typed API. Dumping it
    // needs no handle, and on a machine with no devlink instance it answers
    // with an empty dump rather than an error, which is itself the assertion.
    const replies = dl.raw(.{ .cmd = uapi.CMD.RATE_GET, .dump = true }) catch |e| switch (e) {
        error.NotSupported, error.InvalidRequest, error.NoSuchDevice => return skip("raw RATE_GET"),
        error.AccessDenied => return skip("raw RATE_GET (needs privilege)"),
        else => return e,
    };
    defer Devlink.freeRawReplies(gpa, replies);

    for (replies) |r| {
        try testing.expectEqual(uapi.CMD.RATE_NEW, r.cmd);
        // Every devlink message carries the handle, whatever the command.
        const h = try handle.parse(r.attrs);
        try testing.expect(h.isComplete());
    }
    if (replies.len == 0) return skip("no devlink rate objects on this machine (empty RATE_GET dump)");
}

test "live: the shared transport seam is reachable on a devlink socket" {
    var dl = try openOrSkip();
    defer dl.close();

    try testing.expect(dl.sock.handle() >= 0);
    try testing.expect(dl.sock.portid != 0);
    // No request has failed yet, so there is no extended-ACK message to read.
    try testing.expectEqual(@as(?[]const u8, null), dl.lastErrorMessage());

    // A bounded receive on an idle socket must time out rather than hang.
    try dl.sock.setRecvTimeout(50);
    try testing.expectError(error.WouldBlock, dl.sock.recvDatagramStrict());
    try dl.sock.setRecvTimeout(0);

    // …and the socket still works afterwards.
    const list = try dl.devices();
    testing.allocator.free(list);
}

// ── dark-tests aggregator ──────────────────────────────────────────────────
// A bare `pub const x = @import(…)` re-export does NOT pull x's tests into the
// test binary (CONVENTIONS §6.3).

test {
    _ = uapi;
    _ = handle;
    _ = dev;
    _ = port;
    _ = param;
    _ = resource;
    _ = region;
    _ = health;
    _ = eswitch;
    _ = client;
    _ = @import("goldens.zig");
}
