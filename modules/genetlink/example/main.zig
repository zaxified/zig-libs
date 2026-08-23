// SPDX-License-Identifier: MIT

//! What a generic-netlink consumer does with `genetlink`: open a
//! `NETLINK_GENERIC` socket, resolve a family and one of its multicast
//! groups by name, and handle the two ways a resolve can fail.
//!
//! ⚠ NOTHING HERE NEEDS PRIVILEGE. Unlike this module's raw-socket siblings
//! (`rawsock`, `traceroute`, `pathmtu`'s `probe`), opening a
//! `NETLINK_GENERIC` socket and resolving a family via `nlctrl`
//! (`CTRL_CMD_GETFAMILY`) is a plain, unprivileged operation on Linux —
//! `Socket.open`'s and `Socket.resolveFamily`'s own doc comments say so,
//! and this example proves it by running every call for real against this
//! host's live kernel, no fixtures, no gating on capability. The module's
//! own SPEC notes that *joining* a multicast group
//! (`NETLINK_ADD_MEMBERSHIP`) can need privilege depending on the family,
//! but that operation is not part of this module's public surface at all —
//! it is a plain `setsockopt` a caller makes on `Socket.handle()` — so
//! there is nothing privileged left for this example to gate on.
//!
//! Everything below runs against `nlctrl` itself (family id `0x10`,
//! fixed by the kernel), which always exists and always resolves to itself
//! — no assumption about which OTHER genetlink families (`wireguard`,
//! `nl80211`, …) happen to be loaded on the machine running this example.

const std = @import("std");
const genetlink = @import("genetlink");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── a real allocating failure path: Socket.open returns early ─────────
    //
    // `Socket.open` -> `netlink.Socket.openProtocol` opens and binds a real
    // NETLINK_GENERIC socket, THEN allocates its 8192-byte receive buffer
    // (netlink's root.zig) -- guarded by an `errdefer` that closes the fd
    // if that allocation fails. A 16-byte backing buffer is nowhere near
    // enough, so this proves the failure is clean (no fd leak) on a REAL
    // socket, not a simulated one.
    var tiny_backing: [16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&tiny_backing);
    if (genetlink.Socket.open(fba.allocator())) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.OutOfMemory => std.debug.print(
            "Socket.open with a 16-byte allocator: OutOfMemory (expected), after a real socket open+bind, before any request was sent\n",
            .{},
        ),
        else => return err,
    }

    // ── live: open for real, resolve nlctrl to itself ──────────────────────

    var sock = try genetlink.Socket.open(gpa);
    defer sock.close();

    const ctrl_id = try sock.resolveFamily("nlctrl");
    if (ctrl_id != genetlink.GENL_ID_CTRL) return error.WrongFamilyId;
    std.debug.print("resolveFamily(\"nlctrl\") = 0x{x} (matches GENL_ID_CTRL)\n", .{ctrl_id});

    // A second live round trip on the same socket, `seq` advancing: the
    // "notify" multicast group nlctrl itself always publishes.
    const notify_group = try sock.resolveMcastGroup("nlctrl", "notify");
    if (notify_group == 0) return error.UnexpectedZeroGroupId;
    std.debug.print("resolveMcastGroup(\"nlctrl\", \"notify\") = {d}\n", .{notify_group});

    // ── named negative cases, live ──────────────────────────────────────────

    if (sock.resolveFamily("zig-libs-nope")) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.FamilyNotFound => std.debug.print(
            "resolveFamily(\"zig-libs-nope\"): FamilyNotFound (expected)\n",
            .{},
        ),
        else => return err,
    }

    if (sock.resolveMcastGroup("nlctrl", "zig-libs-example-no-such-group")) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.GroupNotFound => std.debug.print(
            "resolveMcastGroup(\"nlctrl\", \"zig-libs-example-no-such-group\"): GroupNotFound (expected -- family resolves, group doesn't)\n",
            .{},
        ),
        else => return err,
    }

    if (sock.resolveFamily("a-family-name-way-too-long-for-genl-namsiz")) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.NameTooLong => std.debug.print(
            "resolveFamily(<17-byte name>): NameTooLong (expected -- rejected client-side, never sent)\n",
            .{},
        ),
        else => return err,
    }

    // ── pure: hostile bytes never panic the genl payload splitter ──────────

    if (genetlink.splitPayload(&.{ 1, 1, 0 })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("splitPayload(3 truncated bytes): Truncated (expected)\n", .{}),
        error.BadLength => return err,
    }

    std.debug.print("OK: all genetlink example checks passed\n", .{});
}
