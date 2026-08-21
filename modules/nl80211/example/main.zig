// SPDX-License-Identifier: MIT

//! What a Wi-Fi inventory consumer does with `nl80211` when it cannot open a
//! socket: build a `GET_INTERFACE` dump request byte for byte, and decode a
//! captured `NEW_INTERFACE` dump reply (`iw dev`, two interfaces) into
//! `nl80211.Interface` values.
//!
//! `nl80211.Nl80211` (the client in the module's own usage example) always
//! owns a live `AF_NETLINK` socket — there is no way to get one without
//! `Nl80211.open()` making that syscall. This file stays on the wire seam
//! instead: `iface.buildGetInterface` already builds a complete request with
//! no socket involved, and decoding reuses the framing nl80211 re-exports
//! (`nl80211.codec` is `netlink.codec`, `nl80211.genl` is the `genetlink`
//! module) plus the module's own pure decoder (`nl80211.iface.parse`). Built
//! against the PUBLISHED module (`@import("nl80211")`) only.

const std = @import("std");
const nl80211 = @import("nl80211");

/// `strace -f -e trace=%network -e write=all -xx iw dev`'s `NEW_INTERFACE`
/// dump reply — two interfaces — see this module's own golden-test suite,
/// which asserts this exact capture decodes the same way.
const captured_get_interface_hex =
    "5400000029000200b82c9f95dbbb1caf07010000080001000000000008000500" ++
    "0a0000000c00990002000000000000000a000600020000112234000008002e00" ++
    "06000000050053000000000008004d0100000000f400000029000200b82c9f95" ++
    "dbbb1caf0701000008000300030000000b000400776c70327330000008000100" ++
    "0000000008000500020000000c00990001000000000000000a00060002000011" ++
    "2233000008002e0006000000050053000000000008004d010000000008002600" ++
    "7c150000080022010000000008009f00030000000800a0009a15000008006200" ++
    "98080000160034005a49474c4942532d544553542d41502d303100004c000901" ++
    "0800010000000000080002000000000008000300000000000800040000000000" ++
    "0800050000000000080006000000000008000800000000000800090000000000" ++
    "08000a0000000000";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build: a GET_INTERFACE dump request ─────────────────────────────
    //
    // The real family id is a runtime value a live client resolves through
    // `nlctrl` (`genl.Socket.resolveFamily(nl80211.family_name)`); an
    // offline example has no socket to resolve it with, so this uses the id
    // the capture below was actually sent to (41 on that machine) purely to
    // produce a realistic frame.
    const nl80211_family_id: u16 = 41;
    const req = try nl80211.iface.buildGetInterface(gpa, nl80211_family_id, 1, null);
    defer gpa.free(req);

    std.debug.print("GET_INTERFACE dump request: {d} wire bytes for family \"{s}\"\n", .{
        req.len,
        nl80211.family_name,
    });

    // ── decode: a captured NEW_INTERFACE dump reply ─────────────────────
    var raw: [400]u8 = undefined;
    const captured = try std.fmt.hexToBytes(&raw, captured_get_interface_hex);

    var it: nl80211.codec.MessageIterator = .{ .buf = captured };
    while (try it.next()) |msg| {
        const parts = try nl80211.genl.splitPayload(msg.payload);
        if (parts.cmd != nl80211.uapi.CMD.NEW_INTERFACE) continue;
        const wifi_if = try nl80211.iface.parse(parts.attrs);
        std.debug.print("interface: name={s} type={s} freq={?d}MHz\n", .{
            wifi_if.name(),
            @tagName(wifi_if.iftype),
            wifi_if.freq_mhz,
        });
    }
}
