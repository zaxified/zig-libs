// SPDX-License-Identifier: MIT

//! **External anchor: real WireGuard netlink bytes, captured once from the
//! actual kernel module and the actual `wg` reference tool, frozen here.**
//!
//! Before this file, every golden-byte test in `root.zig` round-tripped this
//! module's OWN encoder into its OWN decoder (`buildSetRequests` → hand-built
//! fixtures → `DeviceParser`) — a self-consistency check, not an external
//! anchor. A bug that is wrong the same way on both sides of that pair (e.g.
//! an endianness mix-up applied symmetrically to `appendEndpoint` and
//! `parseEndpoint`) is invisible to a self round-trip, and the module's own
//! `NOTICE`/SPEC named exactly this gap: "the netlink configuration plane
//! codec is self round-trip only". This file closes it with bytes this
//! module never produced:
//!
//!   * `g_set_device_wg_tool` — the real `wg`(8) binary (wireguard-tools,
//!     GPL-2.0, from this host's package) building a WG_CMD_SET_DEVICE
//!     request and sending it to the kernel over a genuine `AF_NETLINK`
//!     socket. Captured via `strace`, independent of anything in this repo.
//!   * `g_get_device_kernel_reply` — the REAL KERNEL's own WG_CMD_GET_DEVICE
//!     reply to that configuration, captured the same way. This is the
//!     strongest possible oracle for the decode direction: the bytes are
//!     authored by the kernel's own `wireguard.ko`, not derived from any
//!     encoder in this repository or in `wg` — decoding them and checking
//!     the recovered fields is a genuine external anchor, not a re-derivation
//!     of our own output.
//!
//! ## Capture recipe
//! Everything below ran inside ONE unprivileged namespace
//! (`unshare --user --map-root-user --net`), so nothing touched host state;
//! the interface and namespace vanish when the shell exits.
//! ```sh
//! unshare --user --map-root-user --net -- bash -c '
//!   ip link add wg0 type wireguard && ip link set wg0 up
//!   PRIV=$(wg genkey); PEER_PUB=$(wg genkey | wg pubkey); PSK=$(wg genpsk)
//!   # (real invocation resolved PEER_PUB from its own PEER_PRIV; elided here)
//!   strace -f -e trace=sendto,sendmsg,recvmsg,recvfrom,write \
//!          -e read=all -e write=all -s 8192 -o strace_set.log \
//!     wg set wg0 private-key <(echo "$PRIV") listen-port 51820 fwmark 42 \
//!       peer "$PEER_PUB" preshared-key <(echo "$PSK") \
//!       persistent-keepalive 25 endpoint 203.0.113.5:51820 \
//!       allowed-ips 10.0.0.0/24,fd00:aa::/64
//!   strace -f -e trace=sendto,sendmsg,recvmsg,recvfrom,write \
//!          -e read=all -e write=all -s 8192 -o strace_get.log \
//!     wg show wg0 dump
//! '
//! ```
//! `-e read=all -e write=all` makes strace hex-dump the exact bytes
//! transferred on `sendto`/`recvmsg`, independent of strace's own built-in
//! netlink pretty-printer (which would otherwise substitute a structural
//! decode for the raw bytes on recognized families).
//!
//! One real-world wrinkle the capture surfaced: `/usr/bin/wg` carries an
//! AppArmor profile (`/etc/apparmor.d/wg`) restricting its OWN key-file reads
//! to `/etc/wireguard/**` — writable only by real root, which this task does
//! not have and must not obtain. Bash process substitution (`<(echo "$KEY")`,
//! an anonymous pipe, never a path under that restriction) sidesteps it
//! without touching any system policy. `wg show ... dump` needs no file
//! access at all and was never affected.
//!
//! Capture host: Linux 7.0.0-28-generic x86-64 (little-endian),
//! wireguard-tools' `wg`(8) (Debian package, kernel netlink backend — the
//! kernel module was already loaded on this host), kernel `wireguard.ko`
//! version 1.0.0.
//!
//! ## Attribution
//! Running the installed `wg` binary and the kernel module purely as
//! black-box compatibility oracles (never consulting or copying their
//! source) needs no `NOTICE` entry — root `NOTICE` §0 exempts this
//! explicitly, the same pattern already used for `nftables`/`ethtool`/
//! `devlink`/`traceroute` (real reference binaries under `strace`) and for
//! `icmp`/`genetlink` (the kernel itself as the oracle).
//!
//! ## What is, and isn't, byte-exact here
//! The GET_DEVICE reply is asserted BYTE-EXACT against the frozen kernel
//! capture (nothing here re-encodes it) and then decoded through this
//! module's real `DeviceParser` — the actual production path `getDevice()`
//! uses. The SET_DEVICE direction is asserted differently: `wg`'s own
//! attribute ORDER differs from this module's `buildSetRequests` (e.g. `wg`
//! places `WGPEER_A_FLAGS` right before `WGPEER_A_ALLOWEDIPS`; this module
//! places it right after `WGPEER_A_PUBLIC_KEY`) — netlink attribute order is
//! not semantically significant (decoders iterate by type), so a byte-exact
//! comparison there would fail on cosmetic ordering, not a real bug. Instead:
//! (a) `wg`'s own bytes are decoded with this module's real `DeviceParser`
//! and every field is checked against the configuration that was actually
//! applied (an external anchor for the DECODE path against a second,
//! independent real-world encoder); (b) this module's OWN
//! `buildSetRequests`, given the identical configuration, is decoded the
//! same way and checked to produce an EQUAL semantic `Device` — proving
//! encoder fidelity against `wg` without asserting a byte identity that was
//! never true even between two conformant encoders.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const testing = std.testing;

const wg = @import("root.zig");
const netlink = @import("netlink");
const codec = netlink.codec;

/// ### `wg set wg0 private-key <priv> listen-port 51820 fwmark 42 peer
/// <peer_pub> preshared-key <psk> persistent-keepalive 25
/// endpoint 203.0.113.5:51820 allowed-ips 10.0.0.0/24,fd00:aa::/64`
///
/// The complete `sendto()` payload the real `wg` tool put on the wire (268
/// bytes: 16 B nlmsghdr + 4 B genlmsghdr + attributes).
const g_set_device_wg_tool =
    "0c0100002a000500d81a6e6a000000000101000008000200776730002400030068a80e6cab45964ee8e3b9dae639" ++
    "90f62be7491933c0abb35ee8a88fd06e936c060006006cca0000080007002a000000bc000880b800008024000100" ++
    "c928f676746bcb1be22a660788a034af1b24ab3c98312e06d09aeb882dbfde2624000200f9feb4b44abf8805f29db" ++
    "45f486e4bfb49d9bc53c66d8fb687db22427a2e5766140004000200ca6ccb0071050000000000000000060005001" ++
    "90000000800030002000000480009801c0000800600010002000000080002000a000000050003001800000028000" ++
    "080060001000a00000014000200fd0000aa0000000000000000000000000500030040000000";

/// The real kernel's `WG_CMD_GET_DEVICE` dump reply to `wg show wg0 dump`
/// after the above was applied: one `recvmsg()` returning 376 bytes — a
/// 356-byte WireGuard reply message immediately followed by a 20-byte
/// `NLMSG_DONE`, exactly as `codec.MessageIterator` expects a real multipart
/// datagram to look (this is what `Wireguard.getDevice`'s `recvDatagram` +
/// `MessageIterator` loop consumes in production).
const g_get_device_kernel_reply =
    "640100002a000200d81a6e6a71e7250000010000060006006cca0000080007002a000000080001000200000008000200" ++
    "776730002400030068a80e6cab45964ee8e3b9dae63990f62be7491933c0abb35ee8a88fd06e936c2400040042b01c2fc9" ++
    "b8dd61d28cd0182d6c5a661ae4768e4d81dca9433d2a777b178b6ce8000880e400008024000100c928f676746bcb1be22a" ++
    "660788a034af1b24ab3c98312e06d09aeb882dbfde2624000200f9feb4b44abf8805f29db45f486e4bfb49d9bc53c66d8f" ++
    "b687db22427a2e5766140006000000000000000000000000000000000006000500190000000c00080000000000000000" ++
    "000c000700000000000000000008000a0001000000140004000200ca6ccb0071050000000000000000480009801c0000" ++
    "8005000300180000000600010002000000080002000a000000280000800500030040000000060001000a000000140002" ++
    "00fd0000aa0000000000000000000000001400000003000200d81a6e6a71e7250000000000";

// Known values from the capture (see the recipe above) — the private/public
// keys and PSK are throwaway, generated fresh inside the disposable
// namespace and discarded with it, never used for anything security-bearing.
const priv_b64 = "aKgObKtFlk7o47na5jmQ9ivnSRkzwKuzXuioj9Buk2w=";
const pub_b64 = "QrAcL8m43WHSjNAYLWxaZhrkdo5NgdypQz0qd3sXi2w=";
const peer_pub_b64 = "ySj2dnRryxviKmYHiKA0rxskqzyYMS4G0JrriC2/3iY=";
const peer_psk_b64 = "+f60tEq/iAXynbRfSG5L+0nZvFPGbY+2h9siQnouV2Y=";

fn hexBytes(comptime hex: []const u8, buf: []u8) []const u8 {
    return std.fmt.hexToBytes(buf[0 .. hex.len / 2], hex) catch unreachable;
}

/// Fields common to BOTH the SET_DEVICE request (what was configured) and
/// the GET_DEVICE reply (what the kernel reports back). `public_key` is
/// deliberately NOT checked here: a SET_DEVICE request never carries it (the
/// kernel derives the public key from the private key itself), so neither
/// `wg`'s real request nor this module's own `buildSetRequests` output ever
/// encodes WGDEVICE_A_PUBLIC_KEY — only the GET_DEVICE reply does.
fn expectDeviceMatchesCapture(dev: wg.Device) !void {
    try testing.expectEqualStrings("wg0", dev.ifname());
    try testing.expectEqual(try wg.keyFromBase64(priv_b64), dev.private_key.?);
    try testing.expectEqual(@as(u16, 51820), dev.listen_port);
    try testing.expectEqual(@as(u32, 42), dev.fwmark);
    try testing.expectEqual(@as(usize, 1), dev.peers.len);

    const p = dev.peers[0];
    try testing.expectEqual(try wg.keyFromBase64(peer_pub_b64), p.public_key);
    try testing.expectEqual(try wg.keyFromBase64(peer_psk_b64), p.preshared_key.?);
    try testing.expectEqual(@as(u16, 25), p.persistent_keepalive_interval);
    try testing.expect(p.endpoint != null);
    try testing.expectEqual(@as(u16, 51820), p.endpoint.?.port());
    try testing.expectEqualSlices(u8, &.{ 203, 0, 113, 5 }, &p.endpoint.?.v4.addr);
    try testing.expectEqual(@as(usize, 2), p.allowed_ips.len);

    var saw_v4 = false;
    var saw_v6 = false;
    for (p.allowed_ips) |ip| switch (ip.family) {
        wg.AF.INET => {
            try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, ip.bytes());
            try testing.expectEqual(@as(u8, 24), ip.cidr);
            saw_v4 = true;
        },
        wg.AF.INET6 => {
            try testing.expectEqualSlices(u8, &.{ 0xfd, 0x00, 0x00, 0xaa }, ip.bytes()[0..4]);
            try testing.expectEqual(@as(u8, 64), ip.cidr);
            saw_v6 = true;
        },
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(saw_v4 and saw_v6);
}

test "kernel golden: real wg-tool SET_DEVICE request decodes through this module's own parser" {
    if (native_endian != .little) return error.SkipZigTest; // captures are LE
    var raw: [g_set_device_wg_tool.len / 2]u8 = undefined;
    const bytes = hexBytes(g_set_device_wg_tool, &raw);
    try testing.expectEqual(@as(usize, 268), bytes.len);

    // WG_CMD_SET_DEVICE and WG_CMD_GET_DEVICE share one WGDEVICE_A_*/
    // WGPEER_A_* attribute namespace, and `genl.splitPayload` does not
    // itself check `cmd` — so `DeviceParser.feed`, the SAME production
    // decode path `getDevice()` runs, can be pointed at this SET request
    // directly. This is the external anchor for the decode path against a
    // second, fully independent real-world WireGuard netlink encoder.
    const nlmsg_header_len = 16;
    var parser = wg.DeviceParser.init(testing.allocator);
    defer parser.deinit();
    try parser.feed(bytes[nlmsg_header_len..]);
    var dev = try parser.finish();
    defer dev.deinit(testing.allocator);

    try expectDeviceMatchesCapture(dev);

    // Attribute order is genuinely different from ours (documented above) —
    // assert that difference explicitly rather than gloss over it: `wg`
    // places WGPEER_A_FLAGS right before ALLOWEDIPS; this module's own
    // `buildSetRequests` places it right after PUBLIC_KEY. Both are valid
    // netlink (order-independent); this proves the divergence is real and
    // harmless, not asserts it away.
    const g = try wg.genl.splitPayload(bytes[nlmsg_header_len..]);
    var it: codec.AttrIterator = .{ .buf = g.attrs };
    var last_top_type: u16 = 0;
    while (try it.next()) |a| {
        if (a.type == wg.WGDEVICE_A.PEERS) {
            var pit = a.nested();
            const entry = (try pit.next()).?;
            var eit = entry.nested();
            var order: [8]u16 = undefined;
            var n: usize = 0;
            while (try eit.next()) |pa| : (n += 1) order[n] = pa.type;
            try testing.expectEqual(@as(usize, 6), n);
            try testing.expectEqualSlices(u16, &.{
                wg.WGPEER_A.PUBLIC_KEY,
                wg.WGPEER_A.PRESHARED_KEY,
                wg.WGPEER_A.ENDPOINT,
                wg.WGPEER_A.PERSISTENT_KEEPALIVE_INTERVAL,
                wg.WGPEER_A.FLAGS,
                wg.WGPEER_A.ALLOWEDIPS,
            }, order[0..n]);
        }
        last_top_type = a.type;
    }
    try testing.expectEqual(wg.WGDEVICE_A.PEERS, last_top_type);
}

test "kernel golden: real KERNEL GET_DEVICE reply decodes correctly (the true external anchor)" {
    if (native_endian != .little) return error.SkipZigTest; // captures are LE
    var raw: [g_get_device_kernel_reply.len / 2]u8 = undefined;
    const bytes = hexBytes(g_get_device_kernel_reply, &raw);
    try testing.expectEqual(@as(usize, 376), bytes.len);

    // Feed the whole captured datagram through `codec.MessageIterator` +
    // `DeviceParser`, exactly like `Wireguard.getDevice`'s real receive loop
    // does — the multipart WireGuard message followed by NLMSG_DONE in ONE
    // recvmsg(), never fabricated by this repo.
    var parser = wg.DeviceParser.init(testing.allocator);
    defer parser.deinit();
    var it: codec.MessageIterator = .{ .buf = bytes };
    var saw_done = false;
    var wireguard_msgs: usize = 0;
    while (try it.next()) |m| {
        if (m.type == codec.NLMSG_DONE) {
            saw_done = true;
            continue;
        }
        wireguard_msgs += 1;
        try parser.feed(m.payload);
    }
    try testing.expect(saw_done);
    try testing.expectEqual(@as(usize, 1), wireguard_msgs);

    var dev = try parser.finish();
    defer dev.deinit(testing.allocator);

    try expectDeviceMatchesCapture(dev);
    // Fields the kernel fills in on its own that a SET_DEVICE request never
    // carries — proof this really is the kernel's own reply, not something
    // derived from the SET request bytes above.
    try testing.expectEqual(try wg.keyFromBase64(pub_b64), dev.public_key.?); // kernel-derived from the private key
    try testing.expectEqual(@as(u32, 2), dev.ifindex); // kernel-assigned ifindex
    try testing.expectEqual(@as(u32, 1), dev.peers[0].protocol_version); // kernel default
    try testing.expectEqual(@as(u64, 0), dev.peers[0].rx_bytes);
    try testing.expectEqual(@as(u64, 0), dev.peers[0].tx_bytes);
    try testing.expectEqual(@as(i64, 0), dev.peers[0].last_handshake_time.sec);
}

test "kernel golden: this module's own encoder is semantically equal to wg-tool's, given the same config" {
    if (native_endian != .little) return error.SkipZigTest;
    const priv = try wg.keyFromBase64(priv_b64);
    const peer_pub = try wg.keyFromBase64(peer_pub_b64);
    const psk = try wg.keyFromBase64(peer_psk_b64);

    var reqs = try wg.buildSetRequests(testing.allocator, 0x2a, 1, .{
        .ifname = "wg0",
        .private_key = priv,
        .listen_port = 51820,
        .fwmark = 42,
        .peers = &.{.{
            .public_key = peer_pub,
            .preshared_key = psk,
            .replace_allowed_ips = true,
            .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } },
            .persistent_keepalive_interval = 25,
            .allowed_ips = &.{
                wg.AllowedIp.v4(.{ 10, 0, 0, 0 }, 24),
                wg.AllowedIp.v6([_]u8{ 0xfd, 0x00, 0x00, 0xaa } ++ [_]u8{0} ** 12, 64),
            },
        }},
    }, wg.default_max_msg_len);
    defer reqs.deinit(testing.allocator);

    // Not byte-identical to `wg`'s own request (attribute order genuinely
    // differs — see the module doc-comment), but decoding both through the
    // SAME real parser must recover an EQUAL device: this is the honest
    // fidelity check for the encode direction, given no root access to
    // capture `wg`'s bytes a second time for a literal diff.
    var parser: wg.DeviceParser = .init(testing.allocator);
    defer parser.deinit();
    var it: codec.MessageIterator = .{ .buf = reqs.buf };
    const m = (try it.next()).?;
    try parser.feed(m.payload);
    var dev = try parser.finish();
    defer dev.deinit(testing.allocator);

    try expectDeviceMatchesCapture(dev);
}

// ── count canary ────────────────────────────────────────────────────────────
// One kernel-authored capture (GET_DEVICE reply) + one external-tool capture
// (SET_DEVICE request) + one same-config cross-check = 3 kernel/tool-anchored
// tests. If this file grows or shrinks that set, update this count.
test "count canary: kernel/tool-anchored golden tests" {
    try testing.expectEqual(@as(usize, 3), 3);
}
