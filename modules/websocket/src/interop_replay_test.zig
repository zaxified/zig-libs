// SPDX-License-Identifier: MIT

//! Replays what github.com/coder/websocket v1.8.15 and
//! github.com/gorilla/websocket v1.5.3 sent in `zig build interop-websocket`
//! (`tools/interop.zig --capture`): every byte after the handshake, as
//! `testdata/interop/<row id>.bin`. `client-*` files are their SERVERS'
//! frames to this module's client; `server-*` files are their CLIENTS'
//! masked frames to this module's server. Each goes through `conn.Conn` in
//! the role that received it, with no peer: their flate output (permessage-
//! deflate, no context takeover), their fragmentation, their pings and
//! closes. Tests only.

const std = @import("std");
const frame = @import("frame.zig");
const deflate = @import("deflate.zig");
const Conn = @import("conn.zig").Conn;

const testing = std.testing;

const frag_len = 4096;
const suite_lens = [_]usize{ 0, 1, 125, 126, 127, 65535, 65536, 1 << 20 };
const suite_utf8 = "žluťoučký kůň úpěl ďábelské ódy — 😀 €";
const suite_count = suite_lens.len * 2 + 1;

/// The interop program's message pattern (its `pattern`).
fn pattern(out: []u8, text: bool) []u8 {
    for (out, 0..) |*b, i| b.* = if (text) @intCast('a' + i % 26) else @truncate(i *% 31 +% 7);
    return out;
}

const Capture = struct {
    name: []const u8,
    bytes: []const u8,
};

fn cap(comptime name: []const u8) Capture {
    return .{ .name = name, .bytes = @embedFile("testdata/interop/" ++ name ++ ".bin") };
}

const captures = blk: {
    var out: []const Capture = &.{};
    for (.{ "client", "server" }) |family| {
        for (.{ "deflate", "frag", "frag-deflate", "sping", "ping", "close", "servclose" }) |sc| {
            // `sping` is the client family's (the server pings), `ping` the
            // server family's (the client pings).
            if (std.mem.eql(u8, family, "client") and std.mem.eql(u8, sc, "ping")) continue;
            if (std.mem.eql(u8, family, "server") and std.mem.eql(u8, sc, "sping")) continue;
            for (.{ "coder", "gorilla" }) |lib| out = out ++ &[_]Capture{cap(family ++ "-" ++ sc ++ "@" ++ lib)};
        }
    }
    break :blk out;
};

/// What the capture must yield: its messages, in order, then the peer's
/// close with `code` (and `reason` when not null).
fn replay(c: Capture) !void {
    const gpa = testing.allocator;
    const family_end = std.mem.findScalar(u8, c.name, '-').?;
    const role: frame.Role = if (std.mem.eql(u8, c.name[0..family_end], "client")) .client else .server;
    const at = std.mem.findScalar(u8, c.name, '@').?;
    const sc = c.name[family_end + 1 .. at];
    const deflating = std.mem.endsWith(u8, sc, "deflate");

    const msg_buf = try gpa.alloc(u8, 2 << 20);
    defer gpa.free(msg_buf);
    const cbuf = try gpa.alloc(u8, 2 << 20);
    defer gpa.free(cbuf);
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    var obuf: [64]u8 = undefined;

    // A small reader buffer on purpose: the 1 MiB messages go the direct
    // way, everything else through the buffer.
    var src: std.Io.Reader = .fixed(c.bytes);
    var rbuf: [16 * 1024]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = pass }, .buffer = &rbuf, .seek = 0, .end = 0 };
    pass_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var prng: std.Random.DefaultPrng = .init(1);
    var conn: Conn = .init(role, &in, &out.writer, msg_buf, .{
        .mask_random = if (role == .client) prng.random() else null,
        .deflate = if (deflating) .{ .compressed_buf = cbuf, .window = window, .compressor = comp, .out_buf = &obuf } else null,
        .max_frame_size = 2 << 20,
    });

    var expect_buf = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(expect_buf);
    var close_code: u16 = 1000;
    var close_reason: ?[]const u8 = null;
    if (std.mem.eql(u8, sc, "deflate")) {
        for (0..suite_count) |i| {
            const m = try conn.readMessage();
            if (i == suite_count - 1) {
                try testing.expectEqual(frame.Opcode.text, m.opcode);
                try testing.expectEqualStrings(suite_utf8, m.payload);
                continue;
            }
            const text = i % 2 == 0;
            try testing.expectEqual(@as(frame.Opcode, if (text) .text else .binary), m.opcode);
            try testing.expectEqualSlices(u8, pattern(expect_buf[0..suite_lens[i / 2]], text), m.payload);
        }
    } else if (std.mem.startsWith(u8, sc, "frag")) {
        const m = try conn.readMessage();
        try testing.expectEqual(frame.Opcode.text, m.opcode);
        try testing.expectEqualSlices(u8, pattern(expect_buf[0..frag_len], true), m.payload);
    } else if (std.mem.eql(u8, sc, "sping")) {
        // The server's ping is answered on the way to its "ping-ok".
        const m = try conn.readMessage();
        try testing.expect(std.mem.startsWith(u8, m.payload, "ping-ok"));
        try testing.expect(out.written().len > 0 and out.written()[0] == 0x8a);
    } else if (std.mem.eql(u8, sc, "ping")) {
        close_code = 1000;
    } else if (std.mem.eql(u8, sc, "close")) {
        close_code = 4001;
        if (role == .server) close_reason = "zl-client-bye";
    } else if (std.mem.eql(u8, sc, "servclose")) {
        close_code = 4002;
        if (role == .client) close_reason = "zl-bye";
    } else unreachable;

    try testing.expectError(error.Closed, conn.readMessage());
    try testing.expectEqual(@as(?u16, close_code), conn.peer_close.?.code);
    if (close_reason) |r| try testing.expectEqualStrings(r, conn.peer_close.?.reason);
    if (std.mem.eql(u8, sc, "ping")) {
        // The client's ping got its pong (unmasked: this side is the server).
        try testing.expect(out.written().len >= 2 and out.written()[0] == 0x8a and out.written()[1] & 0x80 == 0);
    }
    // Nothing after the close.
    try testing.expectEqual(@as(usize, 0), src.bufferedLen() + in.bufferedLen());
}

var pass_src: *std.Io.Reader = undefined;

/// A transport that hands over up to 4093 bytes per read, so frames
/// straddle reads at odd offsets.
fn pass(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    return pass_src.stream(w, limit.min(.limited(4093)));
}

test "interop replay: coder and gorilla frames through Conn, both roles" {
    try testing.expectEqual(@as(usize, 24), captures.len);
    for (captures) |c| {
        replay(c) catch |err| {
            std.debug.print("replay {s}: {t}\n", .{ c.name, err });
            return err;
        };
    }
}
