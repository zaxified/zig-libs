// SPDX-License-Identifier: MIT

//! What a SmartNIC inventory tool does with `devlink` when it wants to stay
//! off the live kernel path: build a `DEVLINK_CMD_GET` dump request byte for
//! byte, and decode a `DEVLINK_CMD_NEW` reply captured from a real
//! `netdevsim` device into the module's own `Device` type.
//!
//! `devlink.Devlink` (the client in the module's own usage example) always
//! owns a live `AF_NETLINK` socket — there is no way to get a `Devlink` value
//! without `Devlink.open()` making that syscall. This file stays on the wire
//! seam instead, using the framing devlink re-exports (`devlink.codec` is
//! `netlink.codec`, `devlink.genl` is the `genetlink` module) plus the
//! module's own pure decoders (`devlink.dev.parseDevice`). Built against the
//! PUBLISHED module (`@import("devlink")`) only.

const std = @import("std");
const devlink = @import("devlink");

/// `strace -f -e trace=%network -e write=all -xx devlink dev show` bytes for
/// `netdevsim/netdevsim1`, captured against a real `netdevsim` device — see
/// this module's own golden-test suite, which asserts this exact capture
/// decodes the same way.
const captured_dev_new_hex =
    "c8000000170002003513776a00000000030100000e0001006e65746465767369" ++
    "6d0000000f0002006e657464657673696d31000005008800000000008c009c80" ++
    "28009d802400a28005009900010000001800a38014009e8005009f0000000000" ++
    "0800a000000000006000a1802400a28005009900010000001800a38014009e80" ++
    "05009f00000000000800a000000000003800a28005009900020000002c00a380" ++
    "14009e8005009f00000000000800a0000000000014009e8005009f0001000000" ++
    "0800a00000000000";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build: a DEVLINK_CMD_GET dump request ──────────────────────────
    //
    // The real family id is a runtime value a live client resolves through
    // `nlctrl` (`genl.Socket.resolveFamily(devlink.family_name)`); an
    // offline example has no socket to resolve it with, so this uses the id
    // the capture below was actually sent to (25 on that machine) purely to
    // produce a realistic frame.
    const devlink_family_id: u16 = 25;

    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    const hdr_off = try devlink.codec.appendHeader(
        gpa,
        &req,
        devlink_family_id,
        devlink.codec.NLM_F_REQUEST | devlink.codec.NLM_F_DUMP,
        1, // seq
        0, // pid — kernel fills this in
    );
    try devlink.genl.appendHeader(gpa, &req, devlink.uapi.CMD.GET, 1);
    devlink.codec.finishHeader(&req, hdr_off);

    std.debug.print("dump request: {d} wire bytes for family \"{s}\"\n", .{
        req.items.len,
        devlink.family_name,
    });

    // ── decode: a captured DEVLINK_CMD_NEW reply ───────────────────────
    var raw: [256]u8 = undefined;
    const captured = try std.fmt.hexToBytes(&raw, captured_dev_new_hex);

    var it: devlink.codec.MessageIterator = .{ .buf = captured };
    const msg = (try it.next()) orelse return error.NoMessage;
    const parts = try devlink.genl.splitPayload(msg.payload);
    if (parts.cmd != devlink.uapi.CMD.NEW) return error.UnexpectedCommand;

    const device = try devlink.dev.parseDevice(parts.attrs);
    std.debug.print("device: {s}/{s} reload_failed={?}\n", .{
        device.handle.bus(),
        device.handle.dev(),
        device.reload_failed,
    });
}
