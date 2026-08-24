// SPDX-License-Identifier: MIT

//! What a link-monitoring consumer does with `ethtool` when it cannot open a
//! socket: encode a complete `LINKSTATE_GET` request, and decode a
//! `LINKSTATE_GET_REPLY` captured from a real NIC into `ethtool.LinkState`.
//!
//! `ethtool.Ethtool` (the client shown in the module's own usage example)
//! always owns a live `AF_NETLINK` socket — there is no way to get one
//! without `Ethtool.open()` making that syscall. This file stays on the wire
//! seam instead, using the module's public request encoder
//! (`ethtool.buildLinkState`, the same one `Ethtool.linkState` sends) and its
//! pure decoders (`ethtool.link.parseLinkState`), plus the framing ethtool
//! re-exports for the reply walk (`ethtool.codec` is `netlink.codec`,
//! `ethtool.genl` is the `genetlink` module). Built against the PUBLISHED
//! module (`@import("ethtool")`) only.

const std = @import("std");
const ethtool = @import("ethtool");

/// `strace -f -e trace=%network -e write=all -xx ethtool enp0s31f6`'s
/// `LINKSTATE_GET_REPLY`, link down — see this module's own golden-test
/// suite, which asserts this exact capture decodes the same way.
const captured_linkstate_down_hex =
    "38000000170000000700000000000000" ++
    "060100001c0001800800010002000000" ++
    "0e000200656e70307333316636000000" ++
    "0500020000000000";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build: a LINKSTATE_GET request for one interface ───────────────
    //
    // The real family id is a runtime value a live client resolves through
    // `nlctrl` (`genl.Socket.resolveFamily(ethtool.family_name)`); an
    // offline example has no socket to resolve it with, so this uses the id
    // the capture below was actually sent to (23 on that machine) purely to
    // produce a realistic frame.
    const ethtool_family_id: u16 = 23;

    // One call returns the whole datagram — nlmsghdr, genlmsghdr and the
    // header nest that names the device — ready for a `sendto`.
    const req = try ethtool.buildLinkState(gpa, ethtool_family_id, 7, .byName("enp0s31f6"));
    defer gpa.free(req);

    std.debug.print("linkstate request: {d} wire bytes for family \"{s}\"\n", .{
        req.len,
        ethtool.family_name,
    });

    // ── decode: a captured LINKSTATE_GET_REPLY ─────────────────────────
    var raw: [128]u8 = undefined;
    const captured = try std.fmt.hexToBytes(&raw, captured_linkstate_down_hex);

    var it: ethtool.codec.MessageIterator = .{ .buf = captured };
    const msg = (try it.next()) orelse return error.NoMessage;
    const parts = try ethtool.genl.splitPayload(msg.payload);
    if (parts.cmd != ethtool.uapi.REPLY.LINKSTATE_GET) return error.UnexpectedCommand;

    const state = try ethtool.link.parseLinkState(parts.attrs);
    std.debug.print("{s}: link={?}\n", .{ state.device.name(), state.link });
}
