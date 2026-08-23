// SPDX-License-Identifier: MIT

//! What a firewall config compiler does with `netaddr`: take the CIDR blocks
//! an operator typed, mask them to their canonical network form, summarize a
//! DHCP pool range into the minimal covering block list, and order a set of
//! resolved destinations the way a client would actually try to connect.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const netaddr = @import("netaddr");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A config line an operator typed, host bits and all.
    const raw = netaddr.parsePrefix("192.0.2.130/24") orelse return error.BadPrefix;
    const net = raw.masked();
    var buf: [netaddr.max_prefix_text_len]u8 = undefined;
    std.debug.print("declared {s} -> canonical {s}\n", .{
        "192.0.2.130/24",
        netaddr.formatPrefix(net, &buf),
    });

    // A malformed line, handled by name so the caller can report it distinctly
    // from a network error rather than just falling through.
    const bad = netaddr.parsePrefix("192.0.2.0/99");
    if (bad == null) std.debug.print("rejected out-of-range prefix length\n", .{});

    // Summarize a DHCP pool (a raw address range) into the minimal CIDR block
    // list a router's ACL table can hold. This allocates, so it is the part of
    // the module a leak-checked example actually exercises.
    const pool_start = netaddr.parseIp("203.0.113.10") orelse return error.BadIp;
    const pool_end = netaddr.parseIp("203.0.113.19") orelse return error.BadIp;
    const blocks = netaddr.summarize(gpa, .{ .from = pool_start, .to = pool_end }) catch |err| switch (err) {
        error.InvalidRange => {
            std.debug.print("pool range was inverted or mixed-family\n", .{});
            return;
        },
        error.OutOfMemory => return err,
    };
    defer gpa.free(blocks);

    std.debug.print("pool 203.0.113.10-19 summarizes to {d} block(s):\n", .{blocks.len});
    for (blocks) |p| {
        var pbuf: [netaddr.max_prefix_text_len]u8 = undefined;
        std.debug.print("  {s}\n", .{netaddr.formatPrefix(p, &pbuf)});
    }

    // A resolver handed back three candidate destinations for one name; order
    // them the way a dialer should actually try them (RFC 6724), given the
    // source address the OS would pick for each.
    var dsts = [_]netaddr.Ip{
        netaddr.parseIp("198.51.100.7").?,
        netaddr.parseIp("::1").?,
        netaddr.parseIp("2001:db8::7").?,
    };
    var srcs = [_]?netaddr.Ip{
        netaddr.parseIp("198.51.100.1"),
        netaddr.parseIp("::1"),
        netaddr.parseIp("2001:db8::1"),
    };
    try netaddr.sortDestinationsWithSources(&dsts, &srcs);
    std.debug.print("connect order:\n", .{});
    for (dsts) |d| {
        var ibuf: [netaddr.max_ip_text_len]u8 = undefined;
        std.debug.print("  {s}\n", .{netaddr.formatIp(d, &ibuf)});
    }
}
