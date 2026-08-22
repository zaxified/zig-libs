// SPDX-License-Identifier: MIT

//! What a network-inventory tool does with `netlink`: open an
//! `NETLINK_ROUTE` socket (no root needed for the read-only dumps), list
//! every interface, then list the IPv4 addresses bound to the loopback
//! device specifically — the same unprivileged path `ip link`/`ip addr`
//! use, without shelling out to either.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `netlink` does not export.

const std = @import("std");
const netlink = @import("netlink");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Opening the socket can fail by name — e.g. a sandboxed environment
    // that denies AF_NETLINK entirely — which a monitoring tool wants to
    // report distinctly from "the kernel returned nothing".
    var nl = netlink.Socket.open(gpa) catch |err| switch (err) {
        error.AccessDenied => {
            std.debug.print("no permission to open an AF_NETLINK socket\n", .{});
            return;
        },
        error.ProtocolNotSupported => {
            std.debug.print("kernel has no NETLINK_ROUTE support\n", .{});
            return;
        },
        else => return err,
    };
    defer nl.close();

    const links = try nl.links();
    defer gpa.free(links);
    std.debug.print("{d} interface(s):\n", .{links.len});

    var loopback_index: ?u32 = null;
    for (links) |l| {
        std.debug.print("  {d}: {s} mtu={d} up={}\n", .{
            l.index,
            l.name(),
            l.mtu,
            l.flags & netlink.IFF.UP != 0,
        });
        if (l.flags & netlink.IFF.LOOPBACK != 0) loopback_index = l.index;
    }

    const lo_index = loopback_index orelse {
        std.debug.print("no loopback interface found\n", .{});
        return;
    };

    // Scope the address dump to loopback + IPv4 only, entirely client-side
    // (the kernel-side family filter is applied too where supported).
    const addrs = try nl.addresses(.{ .family = netlink.AF.INET, .ifindex = lo_index });
    defer gpa.free(addrs);
    std.debug.print("IPv4 addresses on interface {d}:\n", .{lo_index});
    for (addrs) |a| {
        const b = a.bytes();
        std.debug.print("  {d}.{d}.{d}.{d}/{d}\n", .{ b[0], b[1], b[2], b[3], a.prefixlen });
    }
}
