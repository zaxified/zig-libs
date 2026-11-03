// SPDX-License-Identifier: MIT

//! The Linux kernel's ARP as a live foreign peer for this module's socket
//! wrappers and ARP builder, and the recorder that freezes the exchange into
//! `src/testdata/kernel_arp.zig`, replayed by `src/root.zig`'s "kernel ARP"
//! test with no privileges.
//!
//!     unshare -rn zig build interop-rawsock                # check
//!     unshare -rn zig build interop-rawsock -- --capture   # ...and rewrite the transcript
//!
//! In a fresh user + network namespace: a veth pair with fixed MACs, the
//! kernel owning 10.88.0.2 on one end. Through THIS module only -- `open` a
//! capture socket on the other end, `arp.buildRequest` "who-has 10.88.0.2",
//! `sendRaw` it, `recv` until `arp.parseReply` accepts an answer -- the
//! kernel is asked, and must answer. The module's own loopback tests inject
//! and capture their own frames; here the other side is not ours.

const std = @import("std");
const rawsock = @import("rawsock");
const linux = std.os.linux;

const transcript_path = "modules/rawsock/src/testdata/kernel_arp.zig";
const mac_a = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0xaa, 0x01 };
const mac_b = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0xaa, 0x02 };
const ip_a = [4]u8{ 10, 88, 0, 1 };
const ip_b = [4]u8{ 10, 88, 0, 2 };

fn run(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !void {
    const r = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    switch (r.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("`{s}` failed: {s}\n", .{ argv[0], r.stderr });
    return error.CommandFailed;
}

/// The interface index from `ip -o link show` ("N: name@peer: ..."): /sys in
/// a fresh network namespace still shows the host's interfaces.
fn ifindex(gpa: std.mem.Allocator, io: std.Io, name: []const u8) !i32 {
    const r = try std.process.run(gpa, io, .{ .argv = &.{ "ip", "-o", "link", "show", name } });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    const colon = std.mem.findScalar(u8, r.stdout, ':') orelse return error.NoSuchInterface;
    return std.fmt.parseInt(i32, r.stdout[0..colon], 10);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else {
            std.debug.print("usage: unshare -rn zig build interop-rawsock [-- --capture]\n", .{});
            return 2;
        }
    }
    if (linux.geteuid() != 0) {
        std.debug.print("interop-rawsock: needs euid 0 -- run it under `unshare -rn`\n", .{});
        return 2;
    }

    try run(gpa, io, &.{ "ip", "link", "add", "rsa", "address", "02:00:00:00:aa:01", "type", "veth", "peer", "name", "rsb", "address", "02:00:00:00:aa:02" });
    defer run(gpa, io, &.{ "ip", "link", "del", "rsa" }) catch {};
    try run(gpa, io, &.{ "ip", "addr", "add", "10.88.0.2/24", "dev", "rsb" });
    try run(gpa, io, &.{ "ip", "link", "set", "rsb", "up" });
    try run(gpa, io, &.{ "ip", "link", "set", "rsa", "up" });

    const idx = try ifindex(gpa, io, "rsa");
    var sock = try rawsock.Socket.open(rawsock.eth_p.arp, .{ .iface = "rsa", .recv_timeout_ms = 500 });
    defer sock.close();

    // The interface wrappers against what `ip` configured above (a foreign
    // truth, not this module's own reading): index, name, MAC, address, mask.
    const idx_b = try ifindex(gpa, io, "rsb");
    var name_buf: [16]u8 = undefined;
    const checks_ok = (try rawsock.ifaceByName("rsb")) == idx_b and
        std.mem.eql(u8, try rawsock.ifaceName(sock.fd, idx_b, &name_buf), "rsb") and
        std.mem.eql(u8, &(try rawsock.hwaddr(sock.fd, idx_b)), &mac_b) and
        std.mem.eql(u8, &(try rawsock.ipv4Addr(sock.fd, idx_b)), &ip_b) and
        std.mem.eql(u8, &(try rawsock.ipv4Netmask(sock.fd, idx_b)), &[4]u8{ 255, 255, 255, 0 });
    if (!checks_ok) {
        std.debug.print("interop-rawsock: ifaceByName/ifaceName/hwaddr/ipv4Addr/ipv4Netmask disagree with `ip` for rsb\n", .{});
        return 1;
    }
    std.debug.print("interop-rawsock: interface lookups agree with `ip` (rsb: index {d}, 02:00:00:00:aa:02, 10.88.0.2/24)\n", .{idx_b});

    const request = rawsock.arp.buildRequest(mac_a, ip_a, ip_b);
    var reply_bytes: ?[]u8 = null;
    defer if (reply_bytes) |b| gpa.free(b);
    var tries: usize = 0;
    // The veth link may take a moment to carry frames; ask again until it does.
    outer: while (tries < 20) : (tries += 1) {
        try sock.sendRaw(idx, &request);
        var buf: [256]u8 = undefined;
        var reads: usize = 0;
        while (reads < 8) : (reads += 1) {
            const f = sock.recv(&buf) catch continue :outer;
            const r = rawsock.arp.parseReply(f.bytes) orelse continue; // our own request, seen outgoing
            if (!std.mem.eql(u8, &r.mac, &mac_b)) continue;
            reply_bytes = try gpa.dupe(u8, f.bytes);
            break :outer;
        }
    }
    const reply = reply_bytes orelse {
        std.debug.print("interop-rawsock: the kernel never answered\n", .{});
        return 1;
    };
    std.debug.print("interop-rawsock: the kernel answered who-has 10.88.0.2 ({d} bytes)\n", .{reply.len});

    // The ancillary `vlan` form on a real tagged frame: a VLAN device on rsa
    // sends untagged, the kernel tags the frame, and the peer's AF_PACKET
    // socket sees it with the tag in packet metadata (the tag is stripped from
    // the bytes). `vlan 5` compiled with `vlan_ancillary` must pass it and
    // `vlan 6` must not; `Frame.vlan_tci` is the same tag through
    // PACKET_AUXDATA.
    try run(gpa, io, &.{ "ip", "link", "add", "link", "rsa", "name", "rsa.5", "type", "vlan", "id", "5" });
    try run(gpa, io, &.{ "ip", "link", "set", "rsa.5", "up" });
    const idx5 = try ifindex(gpa, io, "rsa.5");
    const prog5 = try rawsock.filter.compileOpts(gpa, "vlan 5", .{ .vlan_ancillary = true });
    defer gpa.free(prog5);
    const prog6 = try rawsock.filter.compileOpts(gpa, "vlan 6", .{ .vlan_ancillary = true });
    defer gpa.free(prog6);
    var vcap5 = try rawsock.Socket.open(rawsock.eth_p.all, .{ .iface = "rsb", .recv_timeout_ms = 300, .filter = prog5 });
    defer vcap5.close();
    var vcap6 = try rawsock.Socket.open(rawsock.eth_p.all, .{ .iface = "rsb", .recv_timeout_ms = 300, .filter = prog6 });
    defer vcap6.close();
    var vframe: [60]u8 = @splat(0);
    @memcpy(vframe[0..6], &mac_b);
    @memcpy(vframe[6..12], &mac_a);
    vframe[12] = 0x88;
    vframe[13] = 0xb5;
    @memcpy(vframe[14..][0..11], "tagged-vlan");
    var got5: ?rawsock.Frame = null;
    var got6 = false;
    var vtries: usize = 0;
    while (vtries < 10 and got5 == null) : (vtries += 1) {
        try sock.sendRaw(idx5, &vframe);
        var b5: [256]u8 = undefined;
        var reads: usize = 0;
        while (reads < 6) : (reads += 1) {
            const f = vcap5.recv(&b5) catch break;
            if (std.mem.find(u8, f.bytes, "tagged-vlan") != null) {
                got5 = f;
                break;
            }
        }
        var b6: [256]u8 = undefined;
        if (vcap6.recv(&b6)) |f| {
            if (std.mem.find(u8, f.bytes, "tagged-vlan") != null) got6 = true;
        } else |_| {}
    }
    const f5 = got5 orelse {
        std.debug.print("interop-rawsock: the tagged frame never passed the ancillary `vlan 5` filter\n", .{});
        return 1;
    };
    if (got6 or f5.vlan_tci == null or f5.vlan_tci.? & 0xfff != 5) {
        std.debug.print("interop-rawsock: ancillary vlan verdicts wrong (vlan 6 passed: {}, tci {?})\n", .{ got6, f5.vlan_tci });
        return 1;
    }
    std.debug.print("interop-rawsock: ancillary `vlan 5` passes a kernel-tagged frame (tci {d}), `vlan 6` does not\n", .{f5.vlan_tci.?});

    if (capture) {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try out.print(gpa,
            \\// SPDX-License-Identifier: MIT
            \\// Generated by `unshare -rn zig build interop-rawsock -- --capture`
            \\// (modules/rawsock/tools/interop.zig): this module's ARP request, which the Linux
            \\// kernel answered over a veth pair, and the kernel's reply. Do not edit by hand.
            \\
            \\pub const mac_a = [6]u8{{ 0x02, 0x00, 0x00, 0x00, 0xaa, 0x01 }};
            \\pub const mac_b = [6]u8{{ 0x02, 0x00, 0x00, 0x00, 0xaa, 0x02 }};
            \\pub const ip_a = [4]u8{{ 10, 88, 0, 1 }};
            \\pub const ip_b = [4]u8{{ 10, 88, 0, 2 }};
            \\pub const request = "{x}";
            \\pub const reply = "{x}";
            \\
        , .{ &request, reply });
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-rawsock: transcript written to {s}\n", .{transcript_path});
    }
    return 0;
}
