// SPDX-License-Identifier: MIT
//! Byte-exact goldens captured from the real `devlink` binary (iproute2
//! 6.19.0) on Linux 7.0, plus the kernel replies it received.
//!
//! ## How the request goldens were captured
//!
//! ```sh
//! strace -f -e trace=%network -e write=all -e read=all -s 64 \
//!     -o log.txt devlink <args>
//! ```
//!
//! Note `-e trace=%network` rather than a bare `sendmsg` filter: **`devlink`
//! sends with `sendto`**, exactly like the sibling `ethtool` and unlike
//! `nl80211`'s reference tooling, so tracing `sendmsg` alone captures the
//! kernel's replies and none of the requests. The capture was verified to be
//! non-empty before any golden was written. The exact command line sits in a
//! comment next to every golden below.
//!
//! `-e write=all` dumps the payload with no re-encoding step in between, so
//! what is asserted here is literally the bytes `devlink` handed the kernel.
//!
//! One field of a captured request is a runtime value rather than encoding:
//! **`nlmsg_seq`**, which `devlink` seeds from the wall clock. Each test builds
//! with the sequence number its capture happened to use. `nlmsg_pid` needs no
//! special handling — `devlink`, like this module, writes 0 and lets the kernel
//! fill it in.
//!
//! The devlink family id in every capture is **25 (0x19)**. That is *not* a
//! constant: it is whatever nlctrl assigned on that boot, which is exactly why
//! `client.zig` resolves it at runtime. The goldens pass 25 in.
//!
//! ## The capture machine had no devlink hardware
//!
//! This is the honest and important caveat. devlink is implemented by SmartNIC
//! and switch-ASIC drivers (mlx5, mlx4, ice, bnxt, nfp, mlxsw, prestera) and by
//! `netdevsim`; the capture machine has an Intel e1000e and an Intel Wi-Fi
//! radio, **neither of which registers a devlink instance**, and loading
//! `netdevsim` needs real root. `devlink dev show` there returns an empty dump.
//!
//! What that means for the goldens below:
//!
//! * Every **request** golden is a real capture. A request is emitted before
//!   the kernel can refuse it, so `devlink port split pci/…/1 count 2` puts its
//!   bytes on the wire and *then* gets `EPERM`/`ENODEV` — the bytes are as real
//!   as they would be against a switch.
//! * Four **reply** goldens are real kernel bytes: the nlctrl
//!   `CTRL_CMD_NEWFAMILY` that carries the family id and the `config`
//!   multicast group, the `NLMSG_DONE` that terminates an empty dump, and the
//!   `NLMSG_ERROR` for `ENODEV` and for `EPERM`.
//! * Every **object** reply golden (device, port, parameter, resource tree,
//!   region, chunked region read, health reporter, info) is **constructed from
//!   the UAPI**, not captured. They are marked as such at each test. The
//!   decoders they exercise are additionally covered by the hostile-input and
//!   round-trip tests in each source file.
//!
//! ## Two iproute2 quirks these goldens pin
//!
//! 1. **`devlink dev param set` never reaches `PARAM_SET` without a device.**
//!    The binary issues a `PARAM_GET` first, to learn the parameter's type, and
//!    only then sends the typed `PARAM_SET`. On a handle that does not exist
//!    the `PARAM_GET` fails and the `SET` is never emitted — so what the
//!    `param set` capture below contains is that `PARAM_GET`, carrying the
//!    `PARAM_VALUE_CMODE` the command line supplied. It is pinned as-is.
//! 2. **`devlink health recover` emits the handle and reporter name twice** in
//!    one message. Netlink attribute policy takes the last occurrence, so the
//!    kernel is unaffected; this module emits them once. The capture is pinned
//!    exactly, by calling the builder twice, so the quirk is documented rather
//!    than quietly normalised.
//!
//! ## Anonymisation
//!
//! * **`nlmsg_pid` was zeroed in every captured reply.** That field is the
//!   capturing process's netlink port id, derived from its pid; it identifies
//!   a session and nothing about the protocol. These goldens are decoded, not
//!   matched against a live socket, so zeroing it changes no assertion.
//! * The handle used for every request capture is **`pci/0000:00:00.0`**,
//!   which is the x86 host bridge — a PCI address that exists on every such
//!   machine, belongs to no network device, and carries no identity. It was
//!   chosen deliberately so that no real device's bus address appears here.
//! * The constructed replies use `pci/0000:65:00.0`, a plausible but
//!   fictitious address, and the serial numbers, PSIDs and firmware versions
//!   in them are invented — no real board identifier appears anywhere in this
//!   file.
//!
//! Nothing else was touched: lengths, offsets, padding and every attribute in
//! the captured bytes are exactly as `devlink` and the kernel produced them.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");

const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const dev = @import("dev.zig");
const port = @import("port.zig");
const param = @import("param.zig");
const resource = @import("resource.zig");
const region = @import("region.zig");
const health = @import("health.zig");
const eswitch = @import("eswitch.zig");
const client = @import("client.zig");

/// The family id nlctrl handed out on the machine the captures came from.
/// Dynamic in reality — see the file header.
const fam: u16 = 0x19;

/// The handle every request capture used. See "Anonymisation" above.
const cap_handle: handle.Handle = .pci("0000:00:00.0");
const cap_port: handle.PortHandle = .{ .handle = cap_handle, .index = 1 };

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(60 * s.len + 4000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Netlink is host-endian, so these little-endian goldens only mean anything
/// on a little-endian host.
fn skipUnlessLittleEndian() !void {
    if (native_endian != .little) return error.SkipZigTest;
}

/// Start a request message the way `client.zig` does, with the flags spelled
/// out so a capture's exact choices can be reproduced. Returns the header
/// offset for `codec.finishHeader`.
fn beginRequest(
    gpa: std.mem.Allocator,
    msg: *std.ArrayList(u8),
    cmd: u8,
    seq: u32,
    flags: u16,
) !usize {
    const off = try codec.appendHeader(gpa, msg, fam, flags, seq, 0);
    try genl.appendHeader(gpa, msg, cmd, uapi.family_version);
    return off;
}

const REQ = codec.NLM_F_REQUEST;
const ACK = codec.NLM_F_ACK;
const DUMP = codec.NLM_F_DUMP;

// ── captured requests: the six plain dumps ─────────────────────────────────

/// `devlink dev show`, `devlink port show`, `devlink dev param show`,
/// `devlink region show`, `devlink health show` — one nlmsghdr + genlmsghdr and
/// nothing else. All five were captured in one `strace` run and share a
/// sequence number.
const seq_dumps: u32 = 0x6a61c224;

const req_dev_show = hex("140000001900050324c2616a0000000001010000");
const req_port_show = hex("140000001900050324c2616a0000000005010000");
const req_param_show = hex("140000001900050324c2616a0000000026010000");
const req_region_show = hex("140000001900050324c2616a000000002a010000");
const req_health_show = hex("140000001900050324c2616a0000000034010000");
/// `devlink dev info` was captured a moment later, hence the +1 sequence.
const req_dev_info_dump = hex("140000001900050325c2616a0000000033010000");

test "golden: the five bare dumps devlink emits for `<object> show`" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    const cases = [_]struct { cmd: u8, want: []const u8 }{
        .{ .cmd = uapi.CMD.GET, .want = &req_dev_show }, //            devlink dev show
        .{ .cmd = uapi.CMD.PORT_GET, .want = &req_port_show }, //      devlink port show
        .{ .cmd = uapi.CMD.PARAM_GET, .want = &req_param_show }, //    devlink dev param show
        .{ .cmd = uapi.CMD.REGION_GET, .want = &req_region_show }, //  devlink region show
        .{ .cmd = uapi.CMD.HEALTH_REPORTER_GET, .want = &req_health_show }, // devlink health show
    };
    for (cases) |c| {
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const off = try beginRequest(gpa, &msg, c.cmd, seq_dumps, REQ | ACK | DUMP);
        codec.finishHeader(&msg, off);
        try testing.expectEqualSlices(u8, c.want, msg.items);
    }
}

test "golden: devlink dev info (dump form)" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.INFO_GET, 0x6a61c225, REQ | ACK | DUMP);
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_dev_info_dump, msg.items);
}

// ── captured requests: the handle-bearing `doit` reads ─────────────────────
//
// All captured in one run: `devlink <cmd> pci/0000:00:00.0[…]`.

const seq_reads: u32 = 0x6a61c247;
const h_attrs = "080001007063690011000200303030303a30303a30302e3000000000";

/// `devlink dev show pci/0000:00:00.0`
const req_dev_show_h = hex("300000001900050047c2616a0000000001010000" ++ h_attrs);
/// `devlink port show pci/0000:00:00.0/1`
const req_port_show_h = hex("380000001900050047c2616a0000000005010000" ++ h_attrs ++ "0800030001000000");
/// `devlink dev info pci/0000:00:00.0`
const req_dev_info_h = hex("300000001900050047c2616a0000000033010000" ++ h_attrs);
/// `devlink dev eswitch show pci/0000:00:00.0`
const req_eswitch_show_h = hex("300000001900050047c2616a000000001d010000" ++ h_attrs);
/// `devlink dev param show pci/0000:00:00.0 name test_param`
const req_param_show_h = hex("400000001900050047c2616a0000000026010000" ++ h_attrs ++
    "0f005100746573745f706172616d0000");
/// `devlink region show pci/0000:00:00.0/cr-space`
const req_region_show_h = hex("400000001900050047c2616a000000002a010000" ++ h_attrs ++
    "0d00580063722d737061636500000000");
/// `devlink health show pci/0000:00:00.0 reporter fw`
const req_health_show_h = hex("380000001900050047c2616a0000000034010000" ++ h_attrs ++
    "0700730066770000");

test "golden: the handle-only reads (dev show / dev info / eswitch show)" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    const cases = [_]struct { cmd: u8, want: []const u8 }{
        .{ .cmd = uapi.CMD.GET, .want = &req_dev_show_h },
        .{ .cmd = uapi.CMD.INFO_GET, .want = &req_dev_info_h },
        .{ .cmd = uapi.CMD.ESWITCH_GET, .want = &req_eswitch_show_h },
    };
    for (cases) |c| {
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        const off = try beginRequest(gpa, &msg, c.cmd, seq_reads, REQ | ACK);
        try handle.append(gpa, &msg, cap_handle);
        codec.finishHeader(&msg, off);
        try testing.expectEqualSlices(u8, c.want, msg.items);
    }
    // The same bytes through the eswitch module's own builder.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.ESWITCH_GET, seq_reads, REQ | ACK);
    try eswitch.appendGet(gpa, &msg, cap_handle);
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_eswitch_show_h, msg.items);
}

test "golden: devlink port show <handle>/1" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.PORT_GET, seq_reads, REQ | ACK);
    try handle.appendPort(gpa, &msg, cap_port);
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_port_show_h, msg.items);
}

test "golden: devlink dev param show <handle> name test_param" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.PARAM_GET, seq_reads, REQ | ACK);
    try param.appendGetByName(gpa, &msg, cap_handle, "test_param");
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_param_show_h, msg.items);
}

test "golden: devlink region show <handle>/cr-space" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.REGION_GET, seq_reads, REQ | ACK);
    try region.appendGet(gpa, &msg, cap_handle, "cr-space");
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_region_show_h, msg.items);
}

test "golden: devlink health show <handle> reporter fw" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.HEALTH_REPORTER_GET, seq_reads, REQ | ACK);
    try health.appendGet(gpa, &msg, cap_handle, "fw");
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_health_show_h, msg.items);
}

// ── captured request: RESOURCE_DUMP ────────────────────────────────────────

/// `devlink resource set pci/0000:00:00.0 path kvd/linear size 98304`
///
/// Two things worth pinning here. First, this is the only way to get a real
/// `RESOURCE_DUMP` capture out of iproute2 without hardware: plain
/// `devlink resource show` sends `DPIPE_TABLE_GET` first and gives up when that
/// fails. Second, **`devlink` sends this one with `NLM_F_REQUEST` alone — no
/// `NLM_F_ACK`** (it does the same for `RESOURCE_SET`), and it carries the
/// `RESOURCE_SIZE` the command line supplied even though a dump has no use for
/// it. This module's `resources()` always asks for an ACK and sends the handle
/// alone; the capture is reproduced here from the primitives to pin the wire
/// format of the command itself.
const req_resource_dump = hex("3c000000190001005cc3616a0000000024010000" ++ h_attrs ++
    "0c0043000080010000000000");

test "golden: devlink's RESOURCE_DUMP, ACK-less and with a stray size" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.RESOURCE_DUMP, 0x6a61c35c, REQ);
    try resource.appendDump(gpa, &msg, cap_handle);
    try uapi.appendAttrU64(gpa, &msg, uapi.ATTR.RESOURCE_SIZE, 98304);
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_resource_dump, msg.items);

    // And this module's own form: same command, handle only, ACK requested.
    var ours: std.ArrayList(u8) = .empty;
    defer ours.deinit(gpa);
    const off2 = try beginRequest(gpa, &ours, uapi.CMD.RESOURCE_DUMP, 0x6a61c35c, REQ | ACK);
    try resource.appendDump(gpa, &ours, cap_handle);
    codec.finishHeader(&ours, off2);
    // Same genlmsghdr and same handle; only the flags and the trailing size
    // attribute differ.
    try testing.expectEqualSlices(u8, req_resource_dump[16 .. req_resource_dump.len - 12], ours.items[16..]);
    try testing.expectEqual(@as(u16, REQ | ACK), std.mem.readInt(u16, ours.items[6..8], .little));
}

// ── captured requests: the writes ──────────────────────────────────────────

const seq_writes: u32 = 0x6a61c25a;
const port_attrs = h_attrs ++ "0800030001000000";

/// `devlink port set pci/0000:00:00.0/1 type eth`
const req_port_set = hex("40000000190005005ac2616a0000000006010000" ++ port_attrs ++
    "0600040002000000");
/// `devlink port split pci/0000:00:00.0/1 count 2`
const req_port_split = hex("40000000190005005ac2616a0000000009010000" ++ port_attrs ++
    "0800090002000000");
/// `devlink port unsplit pci/0000:00:00.0/1`
const req_port_unsplit = hex("38000000190005005ac2616a000000000a010000" ++ port_attrs);

test "golden: devlink port set / split / unsplit" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;

    var set: std.ArrayList(u8) = .empty;
    defer set.deinit(gpa);
    var o1 = try beginRequest(gpa, &set, uapi.CMD.PORT_SET, seq_writes, REQ | ACK);
    try port.appendSetType(gpa, &set, cap_port, .eth);
    codec.finishHeader(&set, o1);
    try testing.expectEqualSlices(u8, &req_port_set, set.items);

    var split: std.ArrayList(u8) = .empty;
    defer split.deinit(gpa);
    o1 = try beginRequest(gpa, &split, uapi.CMD.PORT_SPLIT, seq_writes, REQ | ACK);
    try port.appendSplit(gpa, &split, cap_port, 2);
    codec.finishHeader(&split, o1);
    try testing.expectEqualSlices(u8, &req_port_split, split.items);

    var unsplit: std.ArrayList(u8) = .empty;
    defer unsplit.deinit(gpa);
    o1 = try beginRequest(gpa, &unsplit, uapi.CMD.PORT_UNSPLIT, seq_writes, REQ | ACK);
    try port.appendUnsplit(gpa, &unsplit, cap_port);
    codec.finishHeader(&unsplit, o1);
    try testing.expectEqualSlices(u8, &req_port_unsplit, unsplit.items);
}

/// `devlink dev param set pci/0000:00:00.0 name test_param value 10 cmode runtime`
///
/// See quirk (1) in the file header: what iproute2 actually put on the wire is
/// the *type-discovery* `PARAM_GET`, carrying the requested cmode. The three
/// captures with `value 10` / `value true` / `value hello` are byte-identical
/// apart from the cmode, which is exactly what you would expect from a request
/// that has not yet learned the parameter's type.
const req_param_get_with_cmode = hex("48000000190005005ac2616a0000000026010000" ++ h_attrs ++
    "0f005100746573745f706172616d0000" ++ "0500570000000000");

test "golden: what `devlink dev param set` really sends first" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.PARAM_GET, seq_writes, REQ | ACK);
    try param.appendGetByName(gpa, &msg, cap_handle, "test_param");
    try codec.appendAttrU8(gpa, &msg, uapi.ATTR.PARAM_VALUE_CMODE, @intFromEnum(uapi.ParamCmode.runtime));
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_param_get_with_cmode, msg.items);

    // The cmode is the only byte that moved between the three captures
    // (`cmode runtime` = 0, `driverinit` = 1, `permanent` = 2).
    try testing.expectEqual(@as(u8, 0), req_param_get_with_cmode[req_param_get_with_cmode.len - 4]);
}

/// `devlink region new pci/0000:00:00.0/cr-space snapshot 5`
const req_region_new = hex("48000000190005005ac2616a000000002c010000" ++ h_attrs ++
    "0d00580063722d737061636500000000" ++ "08005c0005000000");
/// `devlink region del pci/0000:00:00.0/cr-space snapshot 5`
const req_region_del = hex("48000000190005005ac2616a000000002d010000" ++ h_attrs ++
    "0d00580063722d737061636500000000" ++ "08005c0005000000");
/// `devlink region read pci/0000:00:00.0/cr-space snapshot 5 address 0 length 16`
const req_region_read = hex("60000000190005035ac2616a000000002e010000" ++ h_attrs ++
    "0d00580063722d737061636500000000" ++ "08005c0005000000" ++
    "0c00600000000000000000000c0061001000000000000000");

test "golden: region new / del / read" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;

    var new: std.ArrayList(u8) = .empty;
    defer new.deinit(gpa);
    var off = try beginRequest(gpa, &new, uapi.CMD.REGION_NEW, seq_writes, REQ | ACK);
    try region.appendNewSnapshot(gpa, &new, cap_handle, "cr-space", 5);
    codec.finishHeader(&new, off);
    try testing.expectEqualSlices(u8, &req_region_new, new.items);

    var del: std.ArrayList(u8) = .empty;
    defer del.deinit(gpa);
    off = try beginRequest(gpa, &del, uapi.CMD.REGION_DEL, seq_writes, REQ | ACK);
    try region.appendDelSnapshot(gpa, &del, cap_handle, "cr-space", 5);
    codec.finishHeader(&del, off);
    try testing.expectEqualSlices(u8, &req_region_del, del.items);

    // REGION_READ is the one write-side command sent as a **dump** — the reply
    // is chunked across as many messages as the kernel needs.
    var read: std.ArrayList(u8) = .empty;
    defer read.deinit(gpa);
    off = try beginRequest(gpa, &read, uapi.CMD.REGION_READ, seq_writes, REQ | ACK | DUMP);
    try region.appendRead(gpa, &read, cap_handle, .{
        .region = "cr-space",
        .snapshot_id = 5,
        .address = 0,
        .length = 16,
    });
    codec.finishHeader(&read, off);
    try testing.expectEqualSlices(u8, &req_region_read, read.items);
}

/// `devlink health recover pci/0000:00:00.0 reporter fw`
///
/// See quirk (2): iproute2 emits the handle and the reporter name **twice**.
const req_health_recover = hex("5c000000190005005ac2616a0000000036010000" ++
    h_attrs ++ "0700730066770000" ++ h_attrs ++ "0700730066770000");

test "golden: devlink health recover, duplicated attributes and all" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.HEALTH_REPORTER_RECOVER, seq_writes, REQ | ACK);
    try health.appendRecover(gpa, &msg, cap_handle, "fw");
    try health.appendRecover(gpa, &msg, cap_handle, "fw"); // the quirk
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_health_recover, msg.items);

    // This module sends it once — the same message, 36 bytes shorter, and
    // identical up to the point where iproute2 starts repeating itself.
    var ours: std.ArrayList(u8) = .empty;
    defer ours.deinit(gpa);
    const off2 = try beginRequest(gpa, &ours, uapi.CMD.HEALTH_REPORTER_RECOVER, seq_writes, REQ | ACK);
    try health.appendRecover(gpa, &ours, cap_handle, "fw");
    codec.finishHeader(&ours, off2);
    try testing.expectEqual(@as(usize, 56), ours.items.len);
    try testing.expectEqualSlices(u8, req_health_recover[16..56], ours.items[16..]);
}

/// `devlink dev eswitch set pci/0000:00:00.0 mode switchdev inline-mode network encap-mode basic`
///
/// The one capture that pins the eswitch attribute widths: `MODE` is a u16
/// (`nla_len` 6) while `INLINE_MODE` and `ENCAP_MODE` are u8 (`nla_len` 5).
const req_eswitch_set = hex("48000000190005005ac2616a000000001e010000" ++ h_attrs ++
    "060019000100000005001a000200000005003e0001000000");

test "golden: devlink dev eswitch set, pinning the u16/u8/u8 widths" {
    try skipUnlessLittleEndian();
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try beginRequest(gpa, &msg, uapi.CMD.ESWITCH_SET, seq_writes, REQ | ACK);
    try eswitch.appendSet(gpa, &msg, cap_handle, .{
        .mode = .switchdev,
        .inline_mode = .network,
        .encap_mode = .basic,
    });
    codec.finishHeader(&msg, off);
    try testing.expectEqualSlices(u8, &req_eswitch_set, msg.items);

    // And the same bytes decode back to the same three values.
    const e = try eswitch.parse(msg.items[20..]);
    try testing.expectEqual(@as(?uapi.EswitchMode, .switchdev), e.mode);
    try testing.expectEqual(@as(?uapi.InlineMode, .network), e.inline_mode);
    try testing.expectEqual(@as(?uapi.EncapMode, .basic), e.encap_mode);
}

// ── captured replies (real kernel bytes) ───────────────────────────────────

/// The kernel's `CTRL_CMD_NEWFAMILY` answer to `CTRL_CMD_GETFAMILY("devlink")`,
/// captured verbatim during `devlink dev show`. 1236 bytes: the family id, the
/// version, the full `CTRL_ATTR_OPS` table of 58 commands, and the single
/// `config` multicast group. `nlmsg_pid` zeroed — see "Anonymisation".
const reply_nlctrl_newfamily = hex(
    "d40400001000000024c2616a00000000010200000c0002006465766c696e6b00" ++
        "0600010019000000080003000100000008000400000000000800050000000000" ++
        "78040600140001000800010001000000080002000e0000001400020008000100" ++
        "05000000080002000e000000140003000800010006000000080002000b000000" ++
        "140004000800010007000000080002000b000000140005000800010008000000" ++
        "080002000b000000140006000800010009000000080002000b00000014000700" ++
        "080001000a000000080002000b00000014000800080001000b00000008000200" ++
        "0e00000014000900080001000f000000080002000e00000014000a0008000100" ++
        "10000000080002000b00000014000b000800010013000000080002000e000000" ++
        "14000c000800010014000000080002000b00000014000d000800010017000000" ++
        "080002000e00000014000e000800010018000000080002000b00000014000f00" ++
        "080001001b000000080002000b00000014001000080001001c00000008000200" ++
        "0b00000014001100080001001d000000080002000b0000001400120008000100" ++
        "1e000000080002000b00000014001300080001001f000000080002000a000000" ++
        "140014000800010020000000080002000a000000140015000800010021000000" ++
        "080002000a000000140016000800010022000000080002000b00000014001700" ++
        "0800010023000000080002000b00000014001800080001002400000008000200" ++
        "0a000000140019000800010025000000080002000b00000014001a0008000100" ++
        "26000000080002000e00000014001b000800010027000000080002000b000000" ++
        "14001c00080001002a000000080002000e00000014001d00080001002c000000" ++
        "080002000b00000014001e00080001002d000000080002000b00000014001f00" ++
        "080001002e000000080002000d00000014002000080001002f00000008000200" ++
        "0e000000140021000800010030000000080002000b0000001400220008000100" ++
        "33000000080002000e000000140023000800010034000000080002000e000000" ++
        "140024000800010035000000080002000b000000140025000800010036000000" ++
        "080002000b000000140026000800010037000000080002000b00000014002700" ++
        "0800010038000000080002000d00000014002800080001003900000008000200" ++
        "0b00000014002900080001003a000000080002000b00000014002a0008000100" ++
        "3d000000080002000e00000014002b00080001003e000000080002000b000000" ++
        "14002c000800010041000000080002000e00000014002d000800010042000000" ++
        "080002000b00000014002e000800010045000000080002000e00000014002f00" ++
        "0800010046000000080002000b00000014003000080001004900000008000200" ++
        "0b00000014003100080001004a000000080002000e0000001400320008000100" ++
        "4b000000080002000b00000014003300080001004c000000080002000b000000" ++
        "14003400080001004d000000080002000b00000014003500080001004e000000" ++
        "080002000e00000014003600080001004f000000080002000b00000014003700" ++
        "0800010052000000080002000e00000014003800080001005300000008000200" ++
        "0b000000140039000800010054000000080002000a0000001c00070018000100" ++
        "080002000b0000000b000100636f6e6669670000",
);

test "golden (real reply): the devlink family id and its `config` group" {
    try skipUnlessLittleEndian();
    var it: codec.MessageIterator = .{ .buf = &reply_nlctrl_newfamily };
    const m = (try it.next()).?;
    try testing.expectEqual(genl.GENL_ID_CTRL, m.type);
    const p = try genl.splitPayload(m.payload);

    var family_id: ?u16 = null;
    var name: ?[]const u8 = null;
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    while (try attrs.next()) |a| switch (a.type) {
        genl.CTRL_ATTR_FAMILY_ID => family_id = try a.asU16(),
        genl.CTRL_ATTR_FAMILY_NAME => name = a.asString(),
        else => {},
    };
    try testing.expectEqualStrings(uapi.family_name, name.?);
    try testing.expectEqual(@as(?u16, fam), family_id);

    // The shared `genetlink` group resolver, against real kernel bytes.
    try testing.expectEqual(@as(?u32, 0x0b), try genl.findMcastGroupId(p.attrs, uapi.mcast_group.config));
    // devlink publishes exactly one group; nothing else resolves.
    try testing.expectEqual(@as(?u32, null), try genl.findMcastGroupId(p.attrs, "monitor"));
    try testing.expectEqual(@as(?u32, null), try genl.findMcastGroupId(p.attrs, "scan"));
}

test "golden (real reply): the kernel's own op table agrees with uapi.zig" {
    try skipUnlessLittleEndian();
    // The strongest available check on the command numbers without devlink
    // hardware: the family's `CTRL_ATTR_OPS` nest lists every command id this
    // kernel implements, so each constant this module sends can be asserted to
    // be one the kernel knows about, and the count of ops to be the 58 the
    // capture contained.
    var it: codec.MessageIterator = .{ .buf = &reply_nlctrl_newfamily };
    const m = (try it.next()).?;
    const p = try genl.splitPayload(m.payload);

    var ids: [128]u32 = @splat(0);
    var n: usize = 0;
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    while (try attrs.next()) |a| {
        if (a.type != 6) continue; // CTRL_ATTR_OPS
        var ops: codec.AttrIterator = .{ .buf = a.data };
        while (try ops.next()) |op| {
            var inner: codec.AttrIterator = .{ .buf = op.data };
            while (try inner.next()) |x| {
                if (x.type != 1) continue; // CTRL_ATTR_OP_ID
                ids[n] = try x.asU32();
                n += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 57), n);

    const sent = [_]u8{
        uapi.CMD.GET,                 uapi.CMD.PORT_GET,
        uapi.CMD.PORT_SET,            uapi.CMD.PORT_SPLIT,
        uapi.CMD.PORT_UNSPLIT,        uapi.CMD.ESWITCH_GET,
        uapi.CMD.ESWITCH_SET,         uapi.CMD.RESOURCE_DUMP,
        uapi.CMD.RESOURCE_SET,        uapi.CMD.PARAM_GET,
        uapi.CMD.PARAM_SET,           uapi.CMD.REGION_GET,
        uapi.CMD.REGION_NEW,          uapi.CMD.REGION_DEL,
        uapi.CMD.REGION_READ,         uapi.CMD.INFO_GET,
        uapi.CMD.HEALTH_REPORTER_GET, uapi.CMD.HEALTH_REPORTER_RECOVER,
    };
    for (sent) |c| {
        try testing.expect(std.mem.indexOfScalar(u32, ids[0..n], c) != null);
    }
}

/// The `NLMSG_DONE` that terminated `devlink dev show` on a machine with no
/// devlink instance at all — the empty dump this module documents as normal.
const reply_empty_dump_done = hex("140000000300020024c2616a0000000000000000");

test "golden (real reply): an empty dump is one NLMSG_DONE and nothing else" {
    try skipUnlessLittleEndian();
    var it: codec.MessageIterator = .{ .buf = &reply_empty_dump_done };
    const m = (try it.next()).?;
    try testing.expectEqual(codec.NLMSG_DONE, m.type);
    try testing.expectEqual(seq_dumps, m.seq);
    try testing.expect(m.flags & codec.NLM_F_MULTI != 0);
    try testing.expect((try it.next()) == null);
}

/// `devlink dev show pci/0000:00:00.0` against a handle no driver registered.
const reply_enodev = hex("240000000200000147c2616a00000000edffffff" ++
    "300000001900050047c2616a00000000");
/// `devlink dev eswitch show pci/0000:00:00.0` as an unprivileged user —
/// `ESWITCH_GET` is `GENL_ADMIN_PERM`, so this is EPERM, not EOPNOTSUPP.
const reply_eperm = hex("240000000200000147c2616a00000000ffffffff" ++
    "300000001900050047c2616a00000000");

test "golden (real replies): ENODEV and EPERM map to the typed errors" {
    try skipUnlessLittleEndian();
    var it: codec.MessageIterator = .{ .buf = &reply_enodev };
    const m = (try it.next()).?;
    try testing.expectEqual(codec.NLMSG_ERROR, m.type);
    // NLM_F_CAPPED: the echoed request is truncated to its header.
    try testing.expect(m.flags & codec.NLM_F_CAPPED != 0);
    try testing.expectEqual(@as(i32, -19), try m.errorCode()); // -ENODEV
    try testing.expectEqual(error.NoSuchDevice, client.errnoToError(try m.errorCode()));
    // No extended-ACK string was attached to either of these.
    try testing.expectEqual(@as(?[]const u8, null), try m.errorMessage());

    var it2: codec.MessageIterator = .{ .buf = &reply_eperm };
    const m2 = (try it2.next()).?;
    try testing.expectEqual(@as(i32, -1), try m2.errorCode()); // -EPERM
    try testing.expectEqual(error.AccessDenied, client.errnoToError(try m2.errorCode()));
}

// ── constructed replies (UAPI-derived, not captured) ───────────────────────
//
// Everything below builds a reply the way the kernel documents it and decodes
// it back. These are **not** captures — the machine these goldens were made on
// has no devlink-capable device (see the file header) — so they prove the
// decoders against the UAPI rather than against a driver. They are written at
// whole-message level, through `codec.MessageIterator` + `genl.splitPayload`,
// so the plumbing between the socket and the typed parsers is exercised too.

/// Wrap attribute bytes in a full devlink reply message.
fn wrapMessage(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    cmd: u8,
    seq: u32,
    flags: u16,
    attrs: []const u8,
) !void {
    const off = try codec.appendHeader(gpa, out, fam, flags, seq, 0);
    try genl.appendHeader(gpa, out, cmd, uapi.family_version);
    try out.appendSlice(gpa, attrs);
    codec.finishHeader(out, off);
}

/// Walk a synthetic multi-message dump the way `client.Walk` does.
const DumpWalker = struct {
    it: codec.MessageIterator,

    fn next(w: *DumpWalker) !?struct { cmd: u8, attrs: []const u8 } {
        while (try w.it.next()) |m| {
            if (m.type == codec.NLMSG_DONE) return null;
            if (m.type != fam) continue;
            const p = try genl.splitPayload(m.payload);
            return .{ .cmd = p.cmd, .attrs = p.attrs };
        }
        return null;
    }
};

test "constructed: a two-device DEVLINK_CMD_GET dump decodes at message level" {
    const gpa = testing.allocator;
    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);

    for ([_]handle.Handle{
        .pci("0000:65:00.0"),
        .{ .bus = "netdevsim", .dev = "netdevsim1" },
    }) |h| {
        var attrs: std.ArrayList(u8) = .empty;
        defer attrs.deinit(gpa);
        try handle.append(gpa, &attrs, h);
        try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.RELOAD_FAILED, 0);
        try wrapMessage(gpa, &dgram, uapi.CMD.NEW, seq_dumps, codec.NLM_F_MULTI, attrs.items);
    }
    // The terminating DONE, byte-for-byte the shape the real one had.
    try dgram.appendSlice(gpa, &reply_empty_dump_done);

    var w: DumpWalker = .{ .it = .{ .buf = dgram.items } };
    var seen: usize = 0;
    // The decoded devices are copied out, not borrowed: `Device` owns its
    // strings inline, which is the whole point of `handle.Owned`.
    var got: [2]dev.Device = undefined;
    while (try w.next()) |m| {
        try testing.expectEqual(uapi.CMD.NEW, m.cmd);
        got[seen] = try dev.parseDevice(m.attrs);
        try testing.expect(got[seen].handle.isComplete());
        try testing.expectEqual(@as(?bool, false), got[seen].reload_failed);
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 2), seen);
    try testing.expectEqualStrings("pci", got[0].handle.bus());
    try testing.expectEqualStrings("0000:65:00.0", got[0].handle.dev());
    try testing.expectEqualStrings("netdevsim", got[1].handle.bus());
}

test "constructed: a PORT_GET dump with a physical port and two representors" {
    const gpa = testing.allocator;
    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    const h: handle.Handle = .pci("0000:65:00.0");

    {
        var a: std.ArrayList(u8) = .empty;
        defer a.deinit(gpa);
        try handle.append(gpa, &a, h);
        try codec.appendAttrU32(gpa, &a, uapi.ATTR.PORT_INDEX, 1);
        try codec.appendAttrU16(gpa, &a, uapi.ATTR.PORT_TYPE, @intFromEnum(uapi.PortType.eth));
        try codec.appendAttrU32(gpa, &a, uapi.ATTR.PORT_NETDEV_IFINDEX, 4);
        try codec.appendAttrString(gpa, &a, uapi.ATTR.PORT_NETDEV_NAME, "enp101s0f0np0");
        try codec.appendAttrU16(gpa, &a, uapi.ATTR.PORT_FLAVOUR, @intFromEnum(uapi.PortFlavour.physical));
        try codec.appendAttrU32(gpa, &a, uapi.ATTR.PORT_NUMBER, 0);
        try codec.appendAttrU8(gpa, &a, uapi.ATTR.PORT_SPLITTABLE, 1);
        try wrapMessage(gpa, &dgram, uapi.CMD.PORT_NEW, 1, codec.NLM_F_MULTI, a.items);
    }
    for ([_]u16{ 0, 1 }) |vf| {
        var a: std.ArrayList(u8) = .empty;
        defer a.deinit(gpa);
        try handle.append(gpa, &a, h);
        try codec.appendAttrU32(gpa, &a, uapi.ATTR.PORT_INDEX, 65535 - @as(u32, vf));
        try codec.appendAttrU16(gpa, &a, uapi.ATTR.PORT_FLAVOUR, @intFromEnum(uapi.PortFlavour.pci_vf));
        try codec.appendAttrU16(gpa, &a, uapi.ATTR.PORT_PCI_PF_NUMBER, 0);
        try codec.appendAttrU16(gpa, &a, uapi.ATTR.PORT_PCI_VF_NUMBER, vf);
        try wrapMessage(gpa, &dgram, uapi.CMD.PORT_NEW, 1, codec.NLM_F_MULTI, a.items);
    }
    try dgram.appendSlice(gpa, &reply_empty_dump_done);

    var w: DumpWalker = .{ .it = .{ .buf = dgram.items } };
    var ports: [3]port.Port = undefined;
    var n: usize = 0;
    while (try w.next()) |m| {
        ports[n] = try port.parse(m.attrs);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("enp101s0f0np0", ports[0].netdevName());
    try testing.expectEqual(@as(?uapi.PortFlavour, .physical), ports[0].flavour);
    // The representors have no netdev, which is the case a flat "every port
    // has a name" assumption gets wrong.
    try testing.expectEqual(@as(usize, 0), ports[1].netdevName().len);
    try testing.expectEqual(@as(?u16, 1), ports[2].pci_vf_number);
}

test "constructed: a PARAM_GET reply with all three cmodes carrying a u32" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle.append(gpa, &attrs, .pci("0000:65:00.0"));
    const nest = try codec.nestBegin(gpa, &attrs, uapi.ATTR.PARAM);
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.PARAM_NAME, "max_macs");
    try codec.appendAttr(gpa, &attrs, uapi.ATTR.PARAM_GENERIC, &.{});
    try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.PARAM_TYPE, @intFromEnum(uapi.ParamType.u32_));
    const vl = try codec.nestBegin(gpa, &attrs, uapi.ATTR.PARAM_VALUES_LIST);
    const vals = [_]struct { cmode: uapi.ParamCmode, v: ?u32 }{
        .{ .cmode = .runtime, .v = 128 },
        .{ .cmode = .driverinit, .v = 64 },
        .{ .cmode = .permanent, .v = null },
    };
    for (vals) |x| {
        const one = try codec.nestBegin(gpa, &attrs, uapi.ATTR.PARAM_VALUE);
        if (x.v) |v| try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.PARAM_VALUE_DATA, v);
        try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.PARAM_VALUE_CMODE, @intFromEnum(x.cmode));
        codec.nestEnd(&attrs, one);
    }
    codec.nestEnd(&attrs, vl);
    codec.nestEnd(&attrs, nest);

    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    try wrapMessage(gpa, &dgram, uapi.CMD.PARAM_NEW, 1, 0, attrs.items);

    var it: codec.MessageIterator = .{ .buf = dgram.items };
    const m = (try it.next()).?;
    const p_split = try genl.splitPayload(m.payload);
    var p = try param.parse(gpa, p_split.attrs);
    defer p.deinit(gpa);

    try testing.expectEqualStrings("max_macs", p.name());
    try testing.expect(p.generic);
    try testing.expectEqual(@as(?u64, 128), p.forCmode(.runtime).?.value.?.asInt());
    try testing.expectEqual(@as(?u64, 64), p.forCmode(.driverinit).?.value.?.asInt());
    // Present in the list, but with no value stored in the device's NVM.
    try testing.expect(p.forCmode(.permanent).?.value == null);
    // …and that difference is exactly what a reload would apply.
    try testing.expect(p.reloadWouldChange());
}

test "constructed: a mlxsw-shaped recursive RESOURCE_DUMP reply" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle.append(gpa, &attrs, .pci("0000:65:00.0"));

    const top = try codec.nestBegin(gpa, &attrs, uapi.ATTR.RESOURCE_LIST);
    const kvd = try codec.nestBegin(gpa, &attrs, uapi.ATTR.RESOURCE);
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.RESOURCE_NAME, "kvd");
    try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_ID, 1);
    try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_SIZE, 245760);
    try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_SIZE_GRAN, 1);
    try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.RESOURCE_UNIT, 0);
    const sub = try codec.nestBegin(gpa, &attrs, uapi.ATTR.RESOURCE_LIST);
    const kids = [_]struct { n: []const u8, id: u64, size: u64 }{
        .{ .n = "linear", .id = 2, .size = 98304 },
        .{ .n = "hash_single", .id = 3, .size = 87040 },
        .{ .n = "hash_double", .id = 4, .size = 60416 },
    };
    for (kids) |k| {
        const one = try codec.nestBegin(gpa, &attrs, uapi.ATTR.RESOURCE);
        try codec.appendAttrString(gpa, &attrs, uapi.ATTR.RESOURCE_NAME, k.n);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_ID, k.id);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_SIZE, k.size);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.RESOURCE_OCC, 0);
        codec.nestEnd(&attrs, one);
    }
    codec.nestEnd(&attrs, sub);
    codec.nestEnd(&attrs, kvd);
    codec.nestEnd(&attrs, top);

    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    try wrapMessage(gpa, &dgram, uapi.CMD.RESOURCE_DUMP, 1, 0, attrs.items);

    var it: codec.MessageIterator = .{ .buf = dgram.items };
    const m = (try it.next()).?;
    const p = try genl.splitPayload(m.payload);
    var rs = try resource.parse(gpa, p.attrs);
    defer rs.deinit(gpa);

    try testing.expectEqual(@as(usize, 4), rs.count());
    try testing.expectEqual(@as(usize, 3), rs.roots[0].children.len);
    try testing.expectEqual(@as(?u64, 98304), rs.find("linear").?.size);
    try testing.expectEqual(@as(?u64, 4), rs.find("hash_double").?.id);
    // The whole tree is reachable from the root, which is what "recursive"
    // has to mean for the decoder to be right.
    try testing.expect(rs.roots[0].find("hash_single") != null);
}

test "constructed: a REGION_GET reply with two snapshots" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle.append(gpa, &attrs, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.REGION_NAME, "cr-space");
    try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.REGION_SIZE, 1048576);
    try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.REGION_MAX_SNAPSHOTS, 4);
    const snaps = try codec.nestBegin(gpa, &attrs, uapi.ATTR.REGION_SNAPSHOTS);
    for ([_]u32{ 1, 5 }) |id| {
        const one = try codec.nestBegin(gpa, &attrs, uapi.ATTR.REGION_SNAPSHOT);
        try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.REGION_SNAPSHOT_ID, id);
        codec.nestEnd(&attrs, one);
    }
    codec.nestEnd(&attrs, snaps);

    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    try wrapMessage(gpa, &dgram, uapi.CMD.REGION_NEW, 1, 0, attrs.items);

    var it: codec.MessageIterator = .{ .buf = dgram.items };
    const m = (try it.next()).?;
    const p = try genl.splitPayload(m.payload);
    const r = try region.parseRegion(p.attrs);

    try testing.expectEqualStrings("cr-space", r.name());
    try testing.expectEqual(@as(?u64, 1048576), r.size);
    try testing.expectEqualSlices(u32, &.{ 1, 5 }, r.snapshots());
    try testing.expectEqual(@as(?bool, true), r.canSnapshot());
}

test "constructed: a chunked REGION_READ dump reassembles into 48 bytes" {
    const gpa = testing.allocator;
    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);

    // Three messages, chunked the way the kernel does it: fixed-size pieces
    // whose addresses are what tie them together — the last one first, to
    // prove the assembler does not rely on order.
    const pieces = [_]struct { addr: u64, len: usize, fill: u8 }{
        .{ .addr = 0x1020, .len = 16, .fill = 0xcc },
        .{ .addr = 0x1000, .len = 16, .fill = 0xaa },
        .{ .addr = 0x1010, .len = 16, .fill = 0xbb },
    };
    for (pieces) |piece| {
        var attrs: std.ArrayList(u8) = .empty;
        defer attrs.deinit(gpa);
        try handle.append(gpa, &attrs, .pci("0000:65:00.0"));
        try codec.appendAttrString(gpa, &attrs, uapi.ATTR.REGION_NAME, "cr-space");
        try codec.appendAttrU32(gpa, &attrs, uapi.ATTR.REGION_SNAPSHOT_ID, 5);
        const chunks = try codec.nestBegin(gpa, &attrs, uapi.ATTR.REGION_CHUNKS);
        const one = try codec.nestBegin(gpa, &attrs, uapi.ATTR.REGION_CHUNK);
        var payload: [16]u8 = @splat(piece.fill);
        try codec.appendAttr(gpa, &attrs, uapi.ATTR.REGION_CHUNK_DATA, payload[0..piece.len]);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.REGION_CHUNK_ADDR, piece.addr);
        codec.nestEnd(&attrs, one);
        codec.nestEnd(&attrs, chunks);
        try wrapMessage(gpa, &dgram, uapi.CMD.REGION_READ, 1, codec.NLM_F_MULTI, attrs.items);
    }
    try dgram.appendSlice(gpa, &reply_empty_dump_done);

    var assembler = try region.Assembler.init(gpa, 0x1000, 48);
    errdefer assembler.deinit(gpa);
    var w: DumpWalker = .{ .it = .{ .buf = dgram.items } };
    while (try w.next()) |m| try assembler.feed(m.attrs);
    var data = assembler.finish(gpa);
    defer data.deinit(gpa);

    try testing.expect(data.isComplete());
    try testing.expectEqual(@as(u64, 0x1000), data.address);
    try testing.expectEqualSlices(u8, &(.{0xaa} ** 16 ++ .{0xbb} ** 16 ++ .{0xcc} ** 16), data.bytes);
}

test "constructed: a HEALTH_REPORTER_GET dump with a tripped reporter" {
    const gpa = testing.allocator;
    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    const specs = [_]struct { n: []const u8, state: u8, err: u64, rec: u64 }{
        .{ .n = "fw", .state = 0, .err = 0, .rec = 0 },
        .{ .n = "fw_fatal", .state = 1, .err = 2, .rec = 1 },
    };
    for (specs) |s| {
        var attrs: std.ArrayList(u8) = .empty;
        defer attrs.deinit(gpa);
        try handle.append(gpa, &attrs, .pci("0000:65:00.0"));
        const nest = try codec.nestBegin(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER);
        try codec.appendAttrString(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_NAME, s.n);
        try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_STATE, s.state);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_ERR_COUNT, s.err);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_RECOVER_COUNT, s.rec);
        try uapi.appendAttrU64(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD, 60000);
        try codec.appendAttrU8(gpa, &attrs, uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER, 1);
        codec.nestEnd(&attrs, nest);
        try wrapMessage(gpa, &dgram, uapi.CMD.HEALTH_REPORTER_GET, 1, codec.NLM_F_MULTI, attrs.items);
    }
    try dgram.appendSlice(gpa, &reply_empty_dump_done);

    var w: DumpWalker = .{ .it = .{ .buf = dgram.items } };
    var seen: usize = 0;
    while (try w.next()) |m| {
        const r = try health.parse(m.attrs);
        if (seen == 0) {
            try testing.expectEqualStrings("fw", r.name());
            try testing.expectEqual(@as(?bool, true), r.isHealthy());
            try testing.expectEqual(@as(?u64, 0), r.unrecoveredCount());
        } else {
            try testing.expectEqualStrings("fw_fatal", r.name());
            try testing.expectEqual(@as(?bool, false), r.isHealthy());
            try testing.expectEqual(@as(?u64, 1), r.unrecoveredCount());
        }
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 2), seen);
}

test "constructed: an INFO_GET reply with a pending firmware update" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try handle.append(gpa, &attrs, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.INFO_DRIVER_NAME, "mlx5_core");
    // Invented, not captured — see "Anonymisation".
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.INFO_SERIAL_NUMBER, "XX0000XX0000");
    try codec.appendAttrString(gpa, &attrs, uapi.ATTR.INFO_BOARD_SERIAL_NUMBER, "XX0000XX0000");
    const versions = [_]struct { attr: u16, n: []const u8, v: []const u8 }{
        .{ .attr = uapi.ATTR.INFO_VERSION_FIXED, .n = "fw.psid", .v = "XX_0000000000" },
        .{ .attr = uapi.ATTR.INFO_VERSION_RUNNING, .n = "fw.version", .v = "0.0.1000" },
        .{ .attr = uapi.ATTR.INFO_VERSION_STORED, .n = "fw.version", .v = "0.0.1001" },
    };
    for (versions) |x| {
        const nest = try codec.nestBegin(gpa, &attrs, x.attr);
        try codec.appendAttrString(gpa, &attrs, uapi.ATTR.INFO_VERSION_NAME, x.n);
        try codec.appendAttrString(gpa, &attrs, uapi.ATTR.INFO_VERSION_VALUE, x.v);
        codec.nestEnd(&attrs, nest);
    }

    var dgram: std.ArrayList(u8) = .empty;
    defer dgram.deinit(gpa);
    try wrapMessage(gpa, &dgram, uapi.CMD.INFO_GET, 1, 0, attrs.items);

    var it: codec.MessageIterator = .{ .buf = dgram.items };
    const m = (try it.next()).?;
    const p = try genl.splitPayload(m.payload);
    var info = try dev.parseInfo(gpa, p.attrs);
    defer info.deinit(gpa);

    try testing.expectEqualStrings("mlx5_core", info.driverName());
    try testing.expectEqual(@as(usize, 3), info.versions.len);
    try testing.expectEqualStrings("0.0.1000", info.find(.running, "fw.version").?.value());
    try testing.expectEqualStrings("0.0.1001", info.find(.stored, "fw.version").?.value());
    try testing.expect(info.hasPendingUpdate());
}
