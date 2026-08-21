// SPDX-License-Identifier: MIT

//! What a consumer does with `wireguard` without a kernel: build the exact
//! `WG_CMD_SET_DEVICE` request bytes `Wireguard.setDevice` would send, and
//! decode a hand-assembled `WG_CMD_GET_DEVICE` reply the way
//! `Wireguard.getDevice` does — down to the wire, never opening a netlink
//! socket. `buildSetRequests` and `DeviceParser` are pure functions over
//! byte slices for exactly this reason (the module's own doc comment: "so
//! they are golden-byte-tested offline").
//!
//! Built against the PUBLISHED module (`@import("wireguard")`) only — plus
//! the sibling `netlink`/`genetlink` modules, whose attribute codec this
//! module is itself built on and re-exports only as `wireguard.genl`.

const std = @import("std");
const wireguard = @import("wireguard");
const netlink = @import("netlink");
const codec = netlink.codec;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── keys: the wg-tool base64 text form ──────────────────────────────
    const priv_text = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const priv = wireguard.keyFromBase64(priv_text) catch |err| switch (err) {
        error.InvalidKey => return error.BadKeyText,
    };
    std.debug.print("key round-trip ok: {s}\n", .{wireguard.keyToBase64(priv)});

    // A key text field from an untrusted config file: caught by name, not a
    // panic on a short slice.
    if (wireguard.keyFromBase64("too-short")) |_| {
        return error.ShortKeyShouldHaveBeenRejected;
    } else |err| switch (err) {
        error.InvalidKey => std.debug.print("rejected malformed key text\n", .{}),
    }

    const peer_pub = try wireguard.keyFromBase64("VOPk0GnFuAOhJhFyIhBM7ZTz08uWRRhSjF2gY8LR/HM=");
    const allowed = try wireguard.AllowedIp.parse("10.0.0.0/24");

    // ── build a WG_CMD_SET_DEVICE request and show its shape ────────────
    var reqs = try wireguard.buildSetRequests(gpa, 0x1a, 1, .{
        .ifname = "wg0",
        .private_key = priv,
        .listen_port = 51820,
        .replace_peers = true,
        .peers = &.{.{
            .public_key = peer_pub,
            .replace_allowed_ips = true,
            .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } },
            .allowed_ips = &.{allowed},
        }},
    }, wireguard.default_max_msg_len);
    defer reqs.deinit(gpa);
    std.debug.print("SET_DEVICE request: {d} message(s), {d} bytes total\n", .{ reqs.msg_count, reqs.buf.len });

    // ── decode a hand-assembled GET_DEVICE reply ────────────────────────
    // A real reply comes off the genetlink socket in `Wireguard.getDevice`;
    // here the payload is built with the same public `genl`/`netlink`
    // helpers that module uses internally, then fed to the same parser.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try wireguard.genl.appendHeader(gpa, &msg, wireguard.WG_CMD.GET_DEVICE, wireguard.WG_GENL_VERSION);
    try codec.appendAttrString(gpa, &msg, wireguard.WGDEVICE_A.IFNAME, "wg0");
    try codec.appendAttrU16(gpa, &msg, wireguard.WGDEVICE_A.LISTEN_PORT, 51820);
    {
        const peers = try codec.nestBegin(gpa, &msg, wireguard.WGDEVICE_A.PEERS);
        const entry = try codec.nestBegin(gpa, &msg, 0);
        try codec.appendAttr(gpa, &msg, wireguard.WGPEER_A.PUBLIC_KEY, &peer_pub);
        // struct sockaddr_in: family (native u16) | port (be16) | addr(4) | pad(8)
        var sockaddr: [16]u8 = @splat(0);
        std.mem.writeInt(u16, sockaddr[0..2], wireguard.AF.INET, @import("builtin").cpu.arch.endian());
        std.mem.writeInt(u16, sockaddr[2..4], 51820, .big);
        sockaddr[4..8].* = .{ 203, 0, 113, 5 };
        try codec.appendAttr(gpa, &msg, wireguard.WGPEER_A.ENDPOINT, &sockaddr);
        codec.nestEnd(&msg, entry);
        codec.nestEnd(&msg, peers);
    }

    var parser: wireguard.DeviceParser = .init(gpa);
    defer parser.deinit();
    try parser.feed(msg.items);
    var dev = try parser.finish();
    defer dev.deinit(gpa);

    std.debug.print("decoded device: name={s} listen_port={d} peers={d}\n", .{
        dev.ifname(),
        dev.listen_port,
        dev.peers.len,
    });
    std.debug.print("peer[0] public_key={s} endpoint_port={d}\n", .{
        wireguard.keyToBase64(dev.peers[0].public_key),
        dev.peers[0].endpoint.?.port(),
    });

    // A reply attribute with the wrong length never panics.
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try wireguard.genl.appendHeader(gpa, &bad, wireguard.WG_CMD.GET_DEVICE, wireguard.WG_GENL_VERSION);
    try codec.appendAttr(gpa, &bad, wireguard.WGDEVICE_A.PRIVATE_KEY, &.{ 1, 2, 3 }); // needs 32 bytes
    var bad_parser: wireguard.DeviceParser = .init(gpa);
    defer bad_parser.deinit();
    if (bad_parser.feed(bad.items)) |_| {
        return error.BadLengthKeyShouldHaveBeenRejected;
    } else |err| switch (err) {
        error.BadLength => std.debug.print("malformed PRIVATE_KEY attr rejected\n", .{}),
        else => return err,
    }
}
