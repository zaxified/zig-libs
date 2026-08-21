// SPDX-License-Identifier: MIT

//! What a consumer does with `tc` without a kernel: build the exact request
//! bytes `Socket.qdiscAdd`/`classAdd`/`filterAdd` would send over rtnetlink —
//! an htb root qdisc, a rate-limited class under it, and a u32 filter that
//! runs a mirred+police action list on match — never opening a socket. Every
//! write op needs `CAP_NET_ADMIN`, which this example does not assume; the
//! module's message builders are public precisely so a caller can construct
//! (and inspect, log, or replay) these requests offline.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only —
//! `netlink`, whose codec `tc` builds requests on top of — no `test_deps`,
//! no access to anything the module does not export). If a type needed to
//! call the API is not public, or an error cannot be named from outside,
//! this file stops compiling.

const std = @import("std");
const tc = @import("tc");
const netlink = @import("netlink");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const ifindex: u32 = 2; // e.g. eth0
    const root: tc.Handle = .root;
    const qdisc_handle: tc.Handle = try tc.Handle.parse("1:"); // named error below
    const class_handle: tc.Handle = .init(1, 0x10);

    // ── htb root qdisc: `tc qdisc add dev eth0 root handle 1: htb default 10`
    const qdisc_req = try tc.message.buildQdiscSet(
        gpa,
        1, // seq
        .add,
        .{ .ifindex = ifindex, .handle = qdisc_handle, .parent = root },
        .{ .htb = .{ .defcls = 0x10 } },
        tc.Psched.fallback,
    );
    defer gpa.free(qdisc_req);
    std.debug.print("qdisc add: {d} bytes total, {d}-byte nlmsghdr + {d}-byte tcmsg/attrs\n", .{
        qdisc_req.len,
        netlink.codec.header_len,
        qdisc_req.len - netlink.codec.header_len,
    });

    // ── htb class: `tc class add dev eth0 parent 1: classid 1:10 htb rate 12500000 ceil 25000000`
    const class_req = try tc.message.buildClassSet(
        gpa,
        2,
        .add,
        .{ .ifindex = ifindex, .handle = class_handle, .parent = qdisc_handle },
        .{ .htb = .{ .rate = 12_500_000, .ceil = 25_000_000 } },
        tc.Psched.fallback,
    );
    defer gpa.free(class_req);
    std.debug.print("class add: {d} bytes\n", .{class_req.len});

    // ── u32 filter: mark matching traffic, then rate-limit it, mirroring the
    //    module's own README example.
    const filter_req = try tc.message.buildFilterSet(
        gpa,
        3,
        .add,
        .{ .ifindex = ifindex, .parent = qdisc_handle, .prio = 1, .eth_type = tc.ETH_P.IP },
        .{
            .u32 = .{
                .keys = &.{tc.U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32)},
                .actions = &.{
                    .{ .skbedit = .{ .mark = 7 } }, // pipe: fall through to police
                    .{ .police = .{ .rate = 125_000, .burst = 10 * 1024, .exceed = .shot } },
                },
            },
        },
    );
    defer gpa.free(filter_req);
    std.debug.print("filter add: {d} bytes\n", .{filter_req.len});

    // ── a malformed handle string is rejected by name, not silently zeroed.
    _ = tc.Handle.parse("not-a-handle") catch |err| switch (err) {
        error.InvalidHandle => std.debug.print("rejected malformed handle syntax\n", .{}),
        error.HandleOverflow => return err,
    };

    // ── a u32 filter with more keys than the wire format can carry
    //    (`sel.nkeys` is a u8) is rejected before any bytes are built.
    var too_many: [200]tc.U32Key = undefined;
    for (&too_many) |*k| k.* = tc.U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32);
    _ = tc.message.buildFilterSet(
        gpa,
        4,
        .add,
        .{ .ifindex = ifindex, .parent = qdisc_handle, .prio = 2, .eth_type = tc.ETH_P.IP },
        .{ .u32 = .{ .keys = &too_many } },
    ) catch |err| switch (err) {
        error.TooManyKeys => std.debug.print("rejected a u32 filter with too many keys ({d})\n", .{too_many.len}),
        else => return err,
    };
}
