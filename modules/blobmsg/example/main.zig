// SPDX-License-Identifier: MIT

//! What a consumer does with `blobmsg`'s wire codec directly, the way
//! `Client.invoke` uses it internally but staying entirely off the socket:
//! encode a method call's JSON arguments to blob/blobmsg bytes, frame it as
//! a ubus message the way the wire protocol requires, and decode a captured
//! DATA reply's children back to JSON. `codec` is exported precisely for a
//! consumer that wants the ubus wire format without the Linux-only
//! unix-socket `Client` — e.g. to log a request, replay a capture, or speak
//! ubus over a transport this module does not implement.
//!
//! Built against the PUBLISHED module (`@import("blobmsg")`) only.

const std = @import("std");
const blobmsg = @import("blobmsg");
const codec = blobmsg.codec;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── encode an INVOKE: system.board with JSON args ───────────────────
    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, "{\"verbose\":true}", .{});
    defer parsed.deinit();
    const args = try codec.encodeArgs(gpa, parsed.value);
    defer gpa.free(args);

    var children: std.ArrayList(u8) = .empty;
    defer children.deinit(gpa);
    try codec.appendAttrU32(gpa, &children, codec.ATTR.OBJID, 0x10);
    try codec.appendAttrString(gpa, &children, codec.ATTR.METHOD, "board");
    try codec.appendAttr(gpa, &children, codec.ATTR.DATA, args);

    const wire = try codec.encodeMessage(gpa, codec.MSG.INVOKE, 1, 0, children.items);
    defer gpa.free(wire);
    std.debug.print("INVOKE message: {d} bytes\n", .{wire.len});

    // Read the framing header back the way a transport would, off the wire.
    const hdr = codec.parseMsgHeader(wire[0..codec.msghdr_len]);
    std.debug.print("header: type={d} seq={d} peer={d}\n", .{ hdr.type, hdr.seq, hdr.peer });

    // Walk the attrs the way the client does after a `readMessage`.
    var it: codec.AttrIterator = .{ .buf = wire[codec.msghdr_len + codec.attr_header_len ..] };
    while (try it.next()) |a| {
        if (a.id == codec.ATTR.METHOD) {
            std.debug.print("method attr: {s}\n", .{std.mem.trimEnd(u8, a.data, "\x00")});
        }
    }

    // ── decode a captured DATA reply's children to JSON ─────────────────
    var reply_children: std.ArrayList(u8) = .empty;
    defer reply_children.deinit(gpa);
    try codec.appendString(gpa, &reply_children, "model", "TestRouter");
    try codec.appendInt32(gpa, &reply_children, "cores", 4);

    const json = try codec.decodeToJsonAlloc(gpa, reply_children.items);
    defer gpa.free(json);
    std.debug.print("decoded reply: {s}\n", .{json});

    // A field iterator gives typed access without going through JSON at all.
    var fit = codec.FieldIterator.init(reply_children.items);
    while (try fit.next()) |field| switch (field.value) {
        .string => |s| std.debug.print("field {s} = \"{s}\"\n", .{ field.name, s }),
        .int32 => |v| std.debug.print("field {s} = {d}\n", .{ field.name, v }),
        else => {},
    };

    // A field whose declared length lies about its payload never panics —
    // it is the first thing done with daemon-supplied bytes off the wire.
    var truncated: std.ArrayList(u8) = .empty;
    defer truncated.deinit(gpa);
    try codec.appendInt32(gpa, &truncated, "n", 1);
    const short = truncated.items[0 .. truncated.items.len - 2];
    var bad_it = codec.FieldIterator.init(short);
    if (bad_it.next()) |_| {
        return error.TruncatedFieldShouldHaveFailed;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated field rejected\n", .{}),
        else => return err,
    }
}
