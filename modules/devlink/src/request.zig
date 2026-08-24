// SPDX-License-Identifier: MIT
//! The one place a devlink request's headers are assembled.
//!
//! Every request this module can send — the typed ones and the `raw` escape
//! hatch alike — is `nlmsghdr` + `genlmsghdr` + attributes + `finishHeader`.
//! Spelling that out per command is how a family binding ends up with two
//! encoders for one message that drift apart, so it is spelled out **here**,
//! once, and the per-command `buildX` functions in the topic files are the
//! only callers.
//!
//! ```zig
//! var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_SET, false);
//! errdefer b.deinit();
//! try port.appendSetType(gpa, &b.list, p, .eth);
//! return b.finish();   // owned bytes, ready for the socket
//! ```
//!
//! `family_id` and `seq` are parameters rather than something this file knows:
//! the family id is whatever nlctrl assigned on this boot and the sequence
//! number belongs to the socket that will send the message. A caller building
//! a request offline supplies both.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");

/// What every `buildX` can fail with: allocation, or an argument this module
/// knows the kernel would reject (from the attribute appenders).
pub const Error = error{ OutOfMemory, InvalidRequest };

/// A request under construction: the bytes so far, plus the offset of the
/// `nlmsghdr` whose length `finish` back-patches.
pub const Builder = struct {
    gpa: std.mem.Allocator,
    /// The message bytes. Hand this to the topic file's `appendX` functions.
    list: std.ArrayList(u8) = .empty,
    off: usize = 0,

    /// Back-patch `nlmsg_len` and hand over the finished message. The caller
    /// owns the bytes and frees them with the same allocator.
    pub fn finish(b: *Builder) std.mem.Allocator.Error![]u8 {
        codec.finishHeader(&b.list, b.off);
        return b.list.toOwnedSlice(b.gpa);
    }

    pub fn deinit(b: *Builder) void {
        b.list.deinit(b.gpa);
    }
};

/// Start a typed devlink request: `NLM_F_REQUEST | NLM_F_ACK`, plus
/// `NLM_F_DUMP` when the command is a dump. The dump flag is part of the
/// *message*, not of the sending, which is why it is decided here.
pub fn begin(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    cmd: u8,
    dump: bool,
) std.mem.Allocator.Error!Builder {
    var flags = codec.NLM_F_REQUEST | codec.NLM_F_ACK;
    if (dump) flags |= codec.NLM_F_DUMP;
    return beginFlags(gpa, family_id, seq, cmd, flags, uapi.family_version);
}

/// Start a request with the flags and family version spelled out. Used by the
/// `raw` escape hatch, which lets a caller drop `NLM_F_ACK` (the real `devlink`
/// binary does that for `RESOURCE_DUMP` and `RESOURCE_SET`) or name a version
/// other than the family's current one.
pub fn beginFlags(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    cmd: u8,
    flags: u16,
    version: u8,
) std.mem.Allocator.Error!Builder {
    var b: Builder = .{ .gpa = gpa };
    errdefer b.list.deinit(gpa);
    b.off = try codec.appendHeader(gpa, &b.list, family_id, flags, seq, 0);
    try genl.appendHeader(gpa, &b.list, cmd, version);
    return b;
}

/// A request whose whole body is an optional device handle: the five dumps
/// (`GET`, `PORT_GET`, `PARAM_GET`, `REGION_GET`, `HEALTH_REPORTER_GET`) send
/// none, the handle-only `doit` reads (`INFO_GET`, `RESOURCE_DUMP`,
/// `ESWITCH_GET`, `GET` for one device) send one.
pub fn buildSimple(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    cmd: u8,
    dump: bool,
    h: ?handle.Handle,
) Error![]u8 {
    var b = try begin(gpa, family_id, seq, cmd, dump);
    errdefer b.deinit();
    if (h) |x| try handle.append(gpa, &b.list, x);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "begin frames the two headers, and finish back-patches the length" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var b = try begin(gpa, 0x19, 7, uapi.CMD.GET, true);
    errdefer b.deinit();
    const msg = try b.finish();
    defer gpa.free(msg);

    try testing.expectEqual(@as(usize, 20), msg.len);
    try testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, msg[0..4], .little));
    try testing.expectEqual(@as(u16, 0x19), std.mem.readInt(u16, msg[4..6], .little));
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP),
        std.mem.readInt(u16, msg[6..8], .little),
    );
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, msg[8..12], .little));
    // nlmsg_pid is 0: the kernel fills it in.
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, msg[12..16], .little));
    const p = try genl.splitPayload(msg[16..]);
    try testing.expectEqual(uapi.CMD.GET, p.cmd);
    try testing.expectEqual(@as(usize, 0), p.attrs.len);
}

test "begin without dump asks for an ACK and nothing else" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var b = try begin(gpa, 0x19, 1, uapi.CMD.PORT_SET, false);
    errdefer b.deinit();
    const msg = try b.finish();
    defer gpa.free(msg);
    try testing.expectEqual(
        @as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK),
        std.mem.readInt(u16, msg[6..8], .little),
    );
}

test "beginFlags can drop the ACK the way the devlink binary does" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var b = try beginFlags(gpa, 0x19, 1, uapi.CMD.RESOURCE_DUMP, codec.NLM_F_REQUEST, 3);
    errdefer b.deinit();
    const msg = try b.finish();
    defer gpa.free(msg);
    try testing.expectEqual(@as(u16, codec.NLM_F_REQUEST), std.mem.readInt(u16, msg[6..8], .little));
    // The version byte is the caller's too.
    try testing.expectEqual(@as(u8, 3), msg[17]);
}

test "buildSimple carries the handle when it is given one" {
    const gpa = testing.allocator;
    const bare = try buildSimple(gpa, 0x19, 1, uapi.CMD.GET, true, null);
    defer gpa.free(bare);
    try testing.expectEqual(@as(usize, 20), bare.len);

    const with = try buildSimple(gpa, 0x19, 1, uapi.CMD.INFO_GET, false, .pci("0000:00:00.0"));
    defer gpa.free(with);
    const o = try handle.parse(with[20..]);
    try testing.expectEqualStrings("0000:00:00.0", o.dev());

    // A handle the kernel would reject never becomes a message.
    try testing.expectError(error.InvalidRequest, buildSimple(
        gpa,
        0x19,
        1,
        uapi.CMD.INFO_GET,
        false,
        .{ .bus = "", .dev = "x" },
    ));
}
