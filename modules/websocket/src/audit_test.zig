// SPDX-License-Identifier: MIT

//! Tests the 2026-10-26 mutation audit asked for: each pins a behaviour no
//! other test did (a boundary, a reset, a duplicate check, a path's
//! contract). Grouped by the file they exercise. Tests only.

const std = @import("std");
const testing = std.testing;
const http = @import("http");
const h1 = http.h1;
const frame = @import("frame.zig");
const deflate = @import("deflate.zig");
const handshake = @import("handshake.zig");
const connection = @import("connection.zig");
const Connection = connection.Connection;
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;

fn isNeedMore(r: Connection.Result) bool {
    return switch (r.event) {
        .need_more => true,
        else => false,
    };
}

fn isConsumed(r: Connection.Result) bool {
    return switch (r.event) {
        .frame_consumed => true,
        else => false,
    };
}

/// One short (< 126 bytes) frame, masked when `key` is given.
fn mk(out: []u8, b0: u8, key: ?[4]u8, payload: []const u8) []u8 {
    out[0] = b0;
    if (key) |k| {
        out[1] = 0x80 | @as(u8, @intCast(payload.len));
        @memcpy(out[2..6], &k);
        for (payload, 0..) |p, i| out[6 + i] = p ^ k[i % 4];
        return out[0 .. 6 + payload.len];
    }
    out[1] = @intCast(payload.len);
    @memcpy(out[2..][0..payload.len], payload);
    return out[0 .. 2 + payload.len];
}

fn feedWire(c: *Connection, wire: []const u8) !Connection.Result {
    var b: [160]u8 = undefined;
    @memcpy(b[0..wire.len], wire);
    return c.receive(b[0..wire.len]);
}

// ── frame.zig ────────────────────────────────────────────────────────────

test "the longest value a shorter length form carries is non-minimal in the longer form" {
    var a = [_]u8{ 0x82, 0x7e, 0x00, 0x7d }; // 125 in the 16-bit form
    try testing.expectError(error.InvalidPayloadLength, frame.parseFrame(&a, .client, 1 << 20));
    var b = [_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0xff, 0xff }; // 65535 in the 64-bit form
    try testing.expectError(error.InvalidPayloadLength, frame.parseFrame(&b, .client, 1 << 20));
    var ok = [_]u8{ 0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0x00, 0x00 }; // 65536: minimal
    try testing.expect((try frame.parseFrame(&ok, .client, 1 << 20)) == .need_more);
}

test "a 65535-byte payload is written in the 16-bit length form" {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 65535);
    defer gpa.free(payload);
    @memset(payload, 'x');
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    try frame.writeFrame(&w.writer, .{ .opcode = .binary, .payload = payload });
    try testing.expectEqual(@as(u8, 126), w.written()[1]);
    try testing.expectEqual(@as(usize, 4 + 65535), w.written().len);
}

test "a masked payload over the 512-byte write chunk round-trips" {
    const gpa = testing.allocator;
    var payload: [1300]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    try frame.writeFrame(&w.writer, .{ .opcode = .binary, .payload = &payload, .mask_key = .{ 1, 2, 3, 4 } });
    const wire = try gpa.dupe(u8, w.written());
    defer gpa.free(wire);
    const r = try frame.parseFrame(wire, .server, 1 << 20);
    try testing.expectEqualSlices(u8, &payload, r.frame.payload);
}

// ── connection.zig: IncrementalUtf8 ──────────────────────────────────────

test "IncrementalUtf8: a lone 0x80 inside a 32-byte ASCII run is invalid" {
    var b: [51]u8 = @splat('a');
    b[10] = 0x80;
    var v: connection.IncrementalUtf8 = .{};
    try testing.expectError(error.InvalidUtf8, v.feed(&b));
    b[10] = 'a';
    b[40] = 0x80;
    var v2: connection.IncrementalUtf8 = .{};
    try testing.expectError(error.InvalidUtf8, v2.feed(&b));
}

// ── connection.zig: receive / state resets ──────────────────────────────

test "an error in receiveFrame discards the message in progress" {
    var mb: [16]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    try testing.expect(isConsumed(try feedWire(&c, "\x01\x02ab")));
    var bad = [_]u8{0xff};
    try testing.expectError(error.InvalidUtf8, c.receiveFrame(.{ .fin = true, .opcode = .continuation, .masked = false, .payload = &bad, .consumed = 0 }));
    try testing.expectEqual(@as(?frame.Opcode, null), c.fragment_opcode);
    try testing.expectEqual(@as(usize, 0), c.message_len);
}

test "two fragmented messages in a row do not splice" {
    var mb: [16]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    const frames = [_][]const u8{ "\x01\x02ab", "\x80\x02cd", "\x01\x01e", "\x80\x01f" };
    var last: []const u8 = "";
    for (frames) |fr| {
        const r = try feedWire(&c, fr);
        switch (r.event) {
            .message => |m| last = m.payload,
            else => {},
        }
    }
    try testing.expectEqualStrings("ef", last);
}

test "partial-check progress does not outlive a completed frame" {
    var mb: [256]u8 = undefined;
    var c: Connection = .init(.server, &mb, 1 << 20);
    const key = [4]u8{ 1, 2, 3, 4 };
    var f: [64]u8 = undefined;
    var pa: [40]u8 = @splat('a');
    try testing.expect(isNeedMore(try c.receive(mk(&f, 0x81, key, &pa)[0 .. 6 + 20])));
    const done = try c.receive(mk(&f, 0x81, key, &pa));
    try testing.expect(done.event == .message);
    var pb = pa;
    pb[5] = 0xff;
    try testing.expectError(error.InvalidUtf8, c.receive(mk(&f, 0x81, key, &pb)[0 .. 6 + 25]));
}

test "partial-check progress does not outlive a failed frame" {
    var mb: [256]u8 = undefined;
    var c: Connection = .init(.server, &mb, 1 << 20);
    const key = [4]u8{ 1, 2, 3, 4 };
    var f: [128]u8 = undefined;
    var pa: [100]u8 = @splat('a');
    pa[70] = 0xff;
    try testing.expect(isNeedMore(try c.receive(mk(&f, 0x81, key, &pa)[0 .. 6 + 60])));
    try testing.expectError(error.InvalidUtf8, c.receive(mk(&f, 0x81, key, &pa)[0 .. 6 + 80]));
    var pb: [100]u8 = @splat('a');
    pb[10] = 0xff;
    try testing.expectError(error.InvalidUtf8, c.receive(mk(&f, 0x81, key, &pb)[0 .. 6 + 60]));
}

test "a retry with fewer bytes than were checked starts over" {
    var mb: [256]u8 = undefined;
    var c: Connection = .init(.server, &mb, 1 << 20);
    const key = [4]u8{ 1, 2, 3, 4 };
    var f: [64]u8 = undefined;
    var pa: [40]u8 = @splat('a');
    try testing.expect(isNeedMore(try c.receive(mk(&f, 0x81, key, &pa)[0 .. 6 + 30])));
    var pb = pa;
    pb[5] = 0xff;
    try testing.expectError(error.InvalidUtf8, c.receive(mk(&f, 0x81, key, &pb)[0 .. 6 + 10]));
}

test "a compressed fragmented message does not leave later plain fragments in the compressed path" {
    const gpa = testing.allocator;
    const win = try gpa.create(deflate.Window);
    defer gpa.destroy(win);
    var cbuf: [64]u8 = undefined;
    var mb: [64]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.enableDeflate(&cbuf, win);
    try testing.expect(isConsumed(try feedWire(&c, "\x41\x03\xf2\x48\xcd")));
    const r = try feedWire(&c, "\x80\x04\xc9\xc9\x07\x00");
    try testing.expectEqualStrings("Hello", r.event.message.payload);
    try testing.expect(isConsumed(try feedWire(&c, "\x01\x02ab")));
    try testing.expectEqualStrings("abcd", (try feedWire(&c, "\x80\x02cd")).event.message.payload);

    // The same after an ERROR in the middle of a compressed fragmented message.
    var cbuf2: [32]u8 = undefined;
    var c2: Connection = .init(.client, &mb, 1 << 20);
    c2.enableDeflate(&cbuf2, win);
    try testing.expect(isConsumed(try feedWire(&c2, "\x41\x03\xf2\x48\xcd")));
    var big: [32]u8 = @splat(0);
    big[0] = 0x00;
    big[1] = 30;
    try testing.expectError(error.MessageTooLarge, feedWire(&c2, &big));
    try testing.expect(isConsumed(try feedWire(&c2, "\x01\x02ab")));
    try testing.expectEqualStrings("abcd", (try feedWire(&c2, "\x80\x02cd")).event.message.payload);
}

test "after a close, a partial text frame is left to the frame-end check" {
    var mb: [64]u8 = undefined;
    var c: Connection = .init(.server, &mb, 1 << 20);
    const key = [4]u8{ 1, 2, 3, 4 };
    var f: [64]u8 = undefined;
    const closed = try c.receive(mk(&f, 0x88, key, ""));
    try testing.expect(closed.event == .close);
    var p: [10]u8 = @splat(0xff);
    try testing.expect(isNeedMore(try c.receive(mk(&f, 0x81, key, &p)[0 .. 6 + 2])));
}

test "compressed bytes are not checked as text while they arrive" {
    const gpa = testing.allocator;
    const win = try gpa.create(deflate.Window);
    defer gpa.destroy(win);
    var cbuf: [64]u8 = undefined;
    var mb: [64]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.enableDeflate(&cbuf, win);
    var first = [_]u8{ 0x41, 0x07, 0xf2, 0x48, 0xcd }; // compressed text, 3 of 7 bytes
    try testing.expect(isNeedMore(try c.receive(&first)));
    try testing.expect(isConsumed(try feedWire(&c, "\x41\x03\xf2\x48\xcd")));
    var cont = [_]u8{ 0x80, 0x04, 0xff }; // continuation of the compressed message, 1 of 4 bytes
    try testing.expect(isNeedMore(try c.receive(&cont)));
}

test "fragments that fill message_buf exactly fit" {
    var mb: [4]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    try testing.expect(isConsumed(try feedWire(&c, "\x01\x02ab")));
    try testing.expectEqualStrings("abcd", (try feedWire(&c, "\x80\x02cd")).event.message.payload);
}

test "the compressed cap counts the tail and is inclusive" {
    const gpa = testing.allocator;
    const win = try gpa.create(deflate.Window);
    defer gpa.destroy(win);
    var mb: [64]u8 = undefined;
    var cbuf16: [16]u8 = undefined; // 7 + 9 == 16: fits exactly
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.enableDeflate(&cbuf16, win);
    try testing.expectEqualStrings("Hello", (try feedWire(&c, "\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00")).event.message.payload);
    var cbuf15: [15]u8 = undefined; // 7 + 9 > 15
    var c2: Connection = .init(.client, &mb, 1 << 20);
    c2.enableDeflate(&cbuf15, win);
    try testing.expectError(error.MessageTooLarge, feedWire(&c2, "\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00"));
}

// ── conn.zig ─────────────────────────────────────────────────────────────

fn writeMasked(w: *std.Io.Writer, op: frame.Opcode, payload: []const u8) !void {
    try frame.writeFrame(w, .{ .opcode = op, .payload = payload, .mask_key = .{ 1, 2, 3, 4 } });
}

test "a message's pending toss is not applied twice" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try writeMasked(&wire.writer, .text, "aa");
    try writeMasked(&wire.writer, .close, "\x03\xe8");
    try writeMasked(&wire.writer, .text, "cc");
    var in: std.Io.Reader = .fixed(wire.written());
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [64]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectEqualStrings("aa", (try s.readMessage()).payload);
    try testing.expectError(error.Closed, s.readMessage());
    try testing.expectError(error.DataAfterClose, s.readMessage());
}

test "close bookkeeping" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(5);
    // 131: no pong after our own close.
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .ping, "p");
        var in: std.Io.Reader = .fixed(wire.written());
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
        try s.close(1000, "");
        try testing.expectEqual(@as(usize, 4), out.written().len);
        try testing.expectError(error.EndOfStream, s.readMessage());
        try testing.expectEqual(@as(usize, 4), out.written().len);
    }
    // 133: no second close frame when the peer's close answers ours.
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .close, "\x03\xe8");
        var in: std.Io.Reader = .fixed(wire.written());
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
        try s.close(1000, "bye");
        const n = out.written().len;
        try testing.expectError(error.Closed, s.readMessage());
        try testing.expectEqual(n, out.written().len);
    }
    // 135/136: after the echo, close_sent is set and the reader stands after the close frame.
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .close, "\x03\xe8");
        try wire.writer.writeAll(&.{ 0xAA, 0xBB, 0xCC });
        var in: std.Io.Reader = .fixed(wire.written());
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
        try testing.expectError(error.Closed, s.readMessage());
        try testing.expect(s.conn.close_sent);
        try testing.expect(s.conn.bothClosed());
        try testing.expectEqual(@as(usize, 3), in.bufferedLen());
    }
    // 137: a failure after our close sends no second close frame.
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .text, "hi"); // masked server frame: protocol error for a client
        var in: std.Io.Reader = .fixed(wire.written());
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var c: Conn = .init(.client, &in, &out.writer, &msg, .{ .mask_random = prng.random() });
        try c.close(1000, "");
        const n = out.written().len;
        try testing.expectError(error.MaskedServerFrame, c.readMessage());
        try testing.expectEqual(n, out.written().len);
    }
    // 138: a failure marks the close as sent.
    {
        var in: std.Io.Reader = .fixed("\x81\x02hi");
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
        try testing.expectError(error.UnmaskedClientFrame, s.readMessage());
        try testing.expect(s.conn.close_sent);
    }
    // 139/140: close() twice writes one frame and marks it sent.
    {
        var in: std.Io.Reader = .fixed("");
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var msg: [64]u8 = undefined;
        var c: Conn = .init(.client, &in, &out.writer, &msg, .{ .mask_random = prng.random() });
        try c.close(1000, "x");
        try testing.expect(c.conn.close_sent);
        const n = out.written().len;
        try c.close(1000, "again");
        try testing.expectEqual(n, out.written().len);
    }
}

test "a message of exactly min_size is compressed" {
    const gpa = testing.allocator;
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    var cbuf: [256]u8 = undefined;
    var obuf: [256]u8 = undefined;
    const d: conn_mod.Deflate = .{ .compressed_buf = &cbuf, .window = window, .compressor = comp, .out_buf = &obuf, .min_size = 64 };
    var prng: std.Random.DefaultPrng = .init(6);
    var in: std.Io.Reader = .fixed("");
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var c: Conn = .init(.client, &in, &out.writer, &msg, .{ .mask_random = prng.random(), .deflate = d });
    const payload: [64]u8 = @splat('a');
    try c.writeMessage(.text, &payload);
    try testing.expect(out.written()[0] & 0x40 != 0);
}

var trickle_src: *std.Io.Reader = undefined;

fn trickle7(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    return trickle_src.stream(w, limit.min(.limited(7)));
}

fn trickleAll(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = r;
    return trickle_src.stream(w, limit);
}

test "a frame that exactly fills the reader's buffer stays in it" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    const payload: [58]u8 = @splat('z');
    try writeMasked(&wire.writer, .binary, &payload); // 6 + 58 == 64
    var src: std.Io.Reader = .fixed(wire.written());
    var small: [64]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle7 }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [128]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    const m = try s.readMessage();
    try testing.expectEqualSlices(u8, &payload, m.payload);
    const p = @intFromPtr(m.payload.ptr);
    try testing.expect(p >= @intFromPtr(&small) and p < @intFromPtr(&small) + small.len);
}

test "a frame too big for the rest of the buffer is read straight in even if the whole buffer could hold it" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try writeMasked(&wire.writer, .binary, "x"); // 7 bytes
    const payload: [54]u8 = @splat('z');
    try writeMasked(&wire.writer, .binary, &payload); // 60 bytes: fits 64, not 64 - 7
    var src: std.Io.Reader = .fixed(wire.written());
    var small: [64]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickleAll }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [128]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectEqualStrings("x", (try s.readMessage()).payload);
    const m = try s.readMessage();
    try testing.expectEqualSlices(u8, &payload, m.payload);
    try testing.expectEqual(@intFromPtr(&msg), @intFromPtr(m.payload.ptr));
}

// ── deflate.zig ──────────────────────────────────────────────────────────

test "empty list elements are allowed in a response" {
    try testing.expect((try deflate.verifyResponse(&.{", permessage-deflate; server_no_context_takeover"})) != null);
}

test "the grammar iterators" {
    // 163: a non-token extension name.
    var it: deflate.ExtensionIterator = .{ .s = "a b" };
    try testing.expectError(error.Malformed, it.next());
    // 164: an escaped quote does not end the quoted string (nor split the list at a comma after it).
    var it2: deflate.ExtensionIterator = .{ .s = "a; x=\"\\\"q\", permessage-deflate" };
    try testing.expectError(error.Malformed, it2.next());
    const e = (try it2.next()).?;
    try testing.expectEqualStrings("permessage-deflate", e.name);
    // 165: a parameter must be introduced by ';'.
    try testing.expectError(error.Rejected, deflate.verifyResponse(&.{"permessage-deflate; server_no_context_takeover xclient_no_context_takeover"}));
    // 166: an empty parameter name.
    var p1 = (deflate.Extension{ .name = "a", .rest = ";" }).params();
    try testing.expectError(error.Malformed, p1.next());
    // 167: a quoted value of 16 bytes fits value_buf, 17 does not (and does not write past it).
    var p2 = (deflate.Extension{ .name = "a", .rest = "; x=\"aaaaaaaaaaaaaaaa\"" }).params();
    try testing.expectEqual(@as(usize, 16), (try p2.next()).?.value.?.len);
    var p3 = (deflate.Extension{ .name = "a", .rest = "; x=\"aaaaaaaaaaaaaaaaa\"" }).params();
    try testing.expectError(error.Malformed, p3.next());
    // 168: a quoted value must be a token once unescaped.
    var p4 = (deflate.Extension{ .name = "a", .rest = "; x=\"a b\"" }).params();
    try testing.expectError(error.Malformed, p4.next());
    // 169: so must an unquoted one.
    var p5 = (deflate.Extension{ .name = "a", .rest = "; x=a@b" }).params();
    try testing.expectError(error.Malformed, p5.next());
}

test "window bits 9, foreign extension name, valued flag" {
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; client_max_window_bits=9"}) != null);
    const r = (try deflate.verifyResponse(&.{"permessage-deflate; server_no_context_takeover; server_max_window_bits=9"})).?;
    try testing.expectEqual(@as(u4, 9), r.server_max_window_bits);
    try testing.expectError(error.Rejected, deflate.verifyResponse(&.{"x-foo; server_no_context_takeover"}));
    try testing.expectError(error.Rejected, deflate.verifyResponse(&.{"permessage-deflate; server_no_context_takeover=1"}));
    try testing.expectError(error.Rejected, deflate.verifyResponse(&.{"permessage-deflate; server_no_context_takeover; client_no_context_takeover=1"}));
}

test "a stream that needs bytes beyond the tail is refused" {
    // A final stored block of LEN 10 whose data would have to come from the tail and one byte more.
    var buf: [5 + deflate.inflate_tail.len]u8 = undefined;
    @memcpy(buf[0..5], &[_]u8{ 0x01, 0x0a, 0x00, 0xf5, 0xff });
    var out: [64]u8 = undefined;
    var window: deflate.Window = undefined;
    try testing.expectError(error.InvalidCompressedData, deflate.inflate(&buf, 5, &out, &window));
}

test "compressMessage output bounds and closing byte" {
    const gpa = testing.allocator;
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    var big: [4096]u8 = undefined;
    // 193/194: the closing 0x00 is the last byte and has a byte of room of its own.
    var text_buf: [240]u8 = undefined;
    for (&text_buf, 0..) |*b, i| b.* = "hello "[i % 6];
    const text: []const u8 = &text_buf;
    const z = comp.compressMessage(text, &big, 1) orelse return error.TestCompressedNull;
    try testing.expectEqual(@as(u8, 0), z[z.len - 1]);
    const n = z.len;
    try testing.expect(comp.compressMessage(text, big[0 .. n - 1], 1) == null);
    // Every room from a byte short of the output upward: the result is the
    // same frame or null, never a write past `out` (the closing byte keeps
    // a byte of room of its own).
    var room = n - 1;
    while (room < n + 64) : (room += 1) {
        if (comp.compressMessage(text, big[0..room], 1)) |zz| try testing.expectEqualSlices(u8, z, zz);
    }
    // 190: a 9-byte `out` holds nothing.
    var tiny: [9]u8 = undefined;
    var k: usize = 10;
    while (k < 400) : (k += 1) {
        var p: [400]u8 = @splat('a');
        _ = &p;
        try testing.expect(comp.compressMessage(p[0..k], &tiny, 1) == null);
    }
    // 191: never longer than or as long as the payload.
    var prng: std.Random.DefaultPrng = .init(7);
    const rnd = prng.random();
    var len: usize = 1;
    while (len < 300) : (len += 1) {
        var p: [300]u8 = undefined;
        for (p[0..len]) |*b| b.* = if (rnd.boolean()) 'a' + rnd.uintLessThan(u8, 3) else rnd.int(u8);
        if (comp.compressMessage(p[0..len], &big, 1)) |zz| try testing.expect(zz.len < len);
    }
}

// ── handshake.zig ────────────────────────────────────────────────────────

fn serverHead(comptime fields: []const u8) !h1.RequestHead {
    return h1.RequestHead.parse("GET /chat HTTP/1.1\r\n" ++ fields ++ "\r\n");
}

const std_fields = "Host: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n";
const std_key = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";

test "acceptHandshake: a duplicated Connection or Sec-WebSocket-Version is refused" {
    try testing.expectError(error.DuplicateHeader, handshake.acceptHandshake(try serverHead(std_fields ++ std_key ++ "Connection: Upgrade\r\n"), .{}));
    try testing.expectError(error.DuplicateHeader, handshake.acceptHandshake(try serverHead(std_fields ++ std_key ++ "Sec-WebSocket-Version: 13\r\n"), .{}));
    _ = try handshake.acceptHandshake(try serverHead(std_fields ++ std_key), .{});
}

test "acceptHandshake: a 24-character key that is not base64 is refused" {
    try testing.expectError(error.InvalidKey, handshake.acceptHandshake(try serverHead(std_fields ++ "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZ!==\r\n"), .{}));
}

test "acceptHandshake: an empty Host never reaches the same-host Origin check (h1 refuses it)" {
    // So the check's `authority.len != 0` is defence in depth: an empty
    // `Origin` authority can only meet an empty `Host`, which the parser
    // has already refused (mutation audit 2026-10-04 and 2026-10-26).
    if (serverHead("Host:\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" ++ std_key ++ "Origin: http://\r\n")) |_| {
        return error.EmptyHostParsed;
    } else |_| {}
    const head = try serverHead(std_fields ++ std_key ++ "Origin: http://\r\n");
    try testing.expectError(error.OriginNotAllowed, handshake.acceptHandshake(head, .{}));
}

test "acceptHandshake: more than eight extension lines decline permessage-deflate" {
    const l = "Sec-WebSocket-Extensions: permessage-deflate\r\n";
    const eight = try serverHead(std_fields ++ std_key ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ l);
    try testing.expect((try handshake.acceptHandshake(eight, .{ .permessage_deflate = true })).deflate != null);
    const nine = try serverHead(std_fields ++ std_key ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ l);
    try testing.expectEqual(@as(?deflate.Params, null), (try handshake.acceptHandshake(nine, .{ .permessage_deflate = true })).deflate);
}

test "verifyResponse: a wrong Upgrade or Connection, a duplicated Connection, nine extension lines are refused" {
    const gpa = testing.allocator;
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept = handshake.computeAcceptKey(key);
    const bad_up = try gpa.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: foo\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept});
    defer gpa.free(bad_up);
    try testing.expectError(error.MissingUpgrade, handshake.verifyResponse(try h1.ResponseHead.parse(bad_up), key, &.{}));
    const bad_conn = try gpa.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: close\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept});
    defer gpa.free(bad_conn);
    try testing.expectError(error.MissingConnection, handshake.verifyResponse(try h1.ResponseHead.parse(bad_conn), key, &.{}));
    const dup_conn = try gpa.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accept});
    defer gpa.free(dup_conn);
    try testing.expectError(error.DuplicateHeader, handshake.verifyResponse(try h1.ResponseHead.parse(dup_conn), key, &.{}));
    const l = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n";
    const nine = try gpa.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n" ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ l ++ "\r\n", .{accept});
    defer gpa.free(nine);
    try testing.expectError(error.UnexpectedExtension, handshake.verifyResponseWith(try h1.ResponseHead.parse(nine), key, .{ .permessage_deflate = true }));
}

test "checkPartialText: a text continuation within max_fragments is checked as it arrives" {
    var mb: [64]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.max_fragments = 4;
    c.fragment_opcode = .text;
    c.fragment_count = 3;
    // The 4th fragment is still allowed: its bad first byte fails now.
    var cont = [_]u8{ 0x80, 0x04, 0xff };
    try testing.expectError(error.InvalidUtf8, c.receive(&cont));
}

test "Conn: a direct read cut by the end of the stream discards the message in progress" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try frame.writeFrame(&wire.writer, .{ .fin = false, .opcode = .text, .payload = "ab", .mask_key = .{ 1, 2, 3, 4 } });
    try frame.writeFrame(&wire.writer, .{ .opcode = .continuation, .payload = &(@as([100]u8, @splat('c'))), .mask_key = .{ 1, 2, 3, 4 } });
    var src: std.Io.Reader = .fixed(wire.written()[0 .. 8 + 40]);
    var small: [32]u8 = undefined;
    var in: std.Io.Reader = .{ .vtable = &.{ .stream = trickle7 }, .buffer = &small, .seek = 0, .end = 0 };
    trickle_src = &src;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.EndOfStream, s.readMessage());
    try testing.expectEqual(@as(?frame.Opcode, null), s.conn.fragment_opcode);
    try testing.expectEqual(@as(usize, 0), s.conn.message_len);
    try testing.expectError(error.EndOfStream, s.readMessage());
}

test "Connection: a fragment too big for the rest of message_buf is MessageTooLarge whatever its bytes, whole or in pieces" {
    var mb: [8]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    try testing.expect(isConsumed(try feedWire(&c, "\x01\x03abc")));
    // 6 more bytes do not fit the 5 left; the first one is not UTF-8.
    try testing.expectError(error.MessageTooLarge, feedWire(&c, "\x80\x06\xffxxxxx"));
    // In pieces: the part that arrived is not checked as text, the frame
    // waits to fail on its size.
    var c2: Connection = .init(.client, &mb, 1 << 20);
    try testing.expect(isConsumed(try feedWire(&c2, "\x01\x03abc")));
    try testing.expect(isNeedMore(try feedWire(&c2, "\x80\x06\xff")));
    // A first fragment too big for message_buf, the same.
    var c3: Connection = .init(.client, &mb, 1 << 20);
    try testing.expectError(error.MessageTooLarge, feedWire(&c3, "\x01\x09\xffxxxxxxxx"));
}

// ── 2026-11-07 whole-module mutation run: tests its survivors asked for ─────

test "pongFor answers with a pong carrying the ping's payload" {
    const o = frame.pongFor("abc", null);
    try testing.expectEqual(frame.Opcode.pong, o.opcode);
    try testing.expectEqualStrings("abc", o.payload);
}

test "encodeCloseBody: an out one byte short is BufferTooSmall, never a write past it" {
    var out: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, frame.encodeCloseBody(&out, 1000, "abc"));
    try testing.expectEqualSlices(u8, "\x03\xe8ab", try frame.encodeCloseBody(&out, 1000, "ab"));
}

test "a compressed fragmented message counts its first frame toward max_fragments" {
    const gpa = testing.allocator;
    const win = try gpa.create(deflate.Window);
    defer gpa.destroy(win);
    var cbuf: [64]u8 = undefined;
    var mb: [64]u8 = undefined;
    // Two frames with max_fragments 2: fine.
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.max_fragments = 2;
    c.enableDeflate(&cbuf, win);
    try testing.expect(isConsumed(try feedWire(&c, "\x41\x05\xf2\x48\xcd\xc9\xc9")));
    try testing.expectEqualStrings("Hello", (try feedWire(&c, "\x80\x02\x07\x00")).event.message.payload);
    // Three frames: the third is one too many.
    var c2: Connection = .init(.client, &mb, 1 << 20);
    c2.max_fragments = 2;
    c2.enableDeflate(&cbuf, win);
    try testing.expect(isConsumed(try feedWire(&c2, "\x41\x03\xf2\x48\xcd")));
    try testing.expect(isConsumed(try feedWire(&c2, "\x00\x02\xc9\xc9")));
    try testing.expectError(error.TooManyFragments, feedWire(&c2, "\x80\x02\x07\x00"));
}

test "a first fragment that fills message_buf exactly fits" {
    var mb: [4]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    try testing.expect(isConsumed(try feedWire(&c, "\x01\x04abcd")));
    try testing.expectEqualStrings("abcd", (try feedWire(&c, "\x80\x00")).event.message.payload);
}

test "checkPartialText: a text frame exactly as long as message_buf is checked as it arrives" {
    var mb: [8]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    try testing.expectError(error.InvalidUtf8, feedWire(&c, "\x81\x08\xff"));
}

test "a compressed text message is checked for a code point cut at its end" {
    const gpa = testing.allocator;
    const win = try gpa.create(deflate.Window);
    defer gpa.destroy(win);
    var cbuf: [64]u8 = undefined;
    var mb: [64]u8 = undefined;
    var c: Connection = .init(.client, &mb, 1 << 20);
    c.enableDeflate(&cbuf, win);
    // A non-final stored block carrying E2 82 AC (U+20AC), then the 0x00 that
    // opens the sync flush's empty stored block (RFC 7692 §7.2.1): valid.
    try testing.expectEqualStrings("\xe2\x82\xac", (try feedWire(&c, "\xc1\x09\x00\x03\x00\xfc\xff\xe2\x82\xac\x00")).event.message.payload);
    // The same without its last byte: every byte is fine, the sequence is not finished.
    try testing.expectError(error.InvalidUtf8, feedWire(&c, "\xc1\x08\x00\x02\x00\xfd\xff\xe2\x82\x00"));
}

/// A writer with a buffer of its own in front of a fixed sink: bytes reach
/// `sink` only when the writer drains (a flush, or a full buffer).
const Sink = struct {
    sink: [256]u8 = undefined,
    len: usize = 0,
    buf: [64]u8 = undefined,
    w: std.Io.Writer,

    fn init(s: *Sink) void {
        s.w = .{ .vtable = &.{ .drain = drain }, .buffer = &s.buf };
    }

    fn put(s: *Sink, bytes: []const u8) std.Io.Writer.Error!void {
        if (s.len + bytes.len > s.sink.len) return error.WriteFailed;
        @memcpy(s.sink[s.len..][0..bytes.len], bytes);
        s.len += bytes.len;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const s: *Sink = @alignCast(@fieldParentPtr("w", w));
        try s.put(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try s.put(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try s.put(last);
        return n + last.len * splat;
    }
};

test "Conn: the automatic pong and the close echo are flushed" {
    const gpa = testing.allocator;
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .ping, "p");
        var in: std.Io.Reader = .fixed(wire.written());
        var out: Sink = .{ .w = undefined };
        out.init();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.w, &msg, .{});
        try testing.expectError(error.EndOfStream, s.readMessage());
        try testing.expectEqualSlices(u8, "\x8a\x01p", out.sink[0..out.len]);
    }
    {
        var wire: std.Io.Writer.Allocating = .init(gpa);
        defer wire.deinit();
        try writeMasked(&wire.writer, .close, "\x03\xe8");
        var in: std.Io.Reader = .fixed(wire.written());
        var out: Sink = .{ .w = undefined };
        out.init();
        var msg: [64]u8 = undefined;
        var s: Conn = .init(.server, &in, &out.w, &msg, .{});
        try testing.expectError(error.Closed, s.readMessage());
        try testing.expectEqualSlices(u8, "\x88\x02\x03\xe8", out.sink[0..out.len]);
    }
}

test "Conn: peer_close's reason outlives the reader's buffer" {
    const gpa = testing.allocator;
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();
    try writeMasked(&wire.writer, .close, "\x03\xe8bye");
    var in: std.Io.Reader = .fixed(wire.written());
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [64]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    try testing.expectError(error.Closed, s.readMessage());
    @memset(wire.written(), 0);
    try testing.expectEqual(@as(?u16, 1000), s.peer_close.?.code);
    try testing.expectEqualStrings("bye", s.peer_close.?.reason);
}

test "a message one byte under min_size is sent uncompressed" {
    const gpa = testing.allocator;
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    var cbuf: [256]u8 = undefined;
    var obuf: [256]u8 = undefined;
    const d: conn_mod.Deflate = .{ .compressed_buf = &cbuf, .window = window, .compressor = comp, .out_buf = &obuf, .min_size = 64 };
    var prng: std.Random.DefaultPrng = .init(8);
    var in: std.Io.Reader = .fixed("");
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [256]u8 = undefined;
    var c: Conn = .init(.client, &in, &out.writer, &msg, .{ .mask_random = prng.random(), .deflate = d });
    const payload: [63]u8 = @splat('a');
    try c.writeMessage(.text, &payload);
    try testing.expect(out.written()[0] & 0x40 == 0);
    try testing.expectEqual(@as(usize, 2 + 4 + 63), out.written().len);
}

test "Conn.close: a reason over 123 bytes is ReasonTooLong and writes nothing" {
    const gpa = testing.allocator;
    var in: std.Io.Reader = .fixed("");
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var msg: [64]u8 = undefined;
    var s: Conn = .init(.server, &in, &out.writer, &msg, .{});
    const long: [124]u8 = @splat('r');
    try testing.expectError(error.ReasonTooLong, s.close(1000, &long));
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expect(!s.conn.close_sent);
}

test "extension grammar: a list without spaces, quoted-string edge cases, window-bit values" {
    // No space after the comma: the next element starts right there.
    try testing.expect(deflate.selectOffer(&.{"x-foo,permessage-deflate"}) != null);
    // A malformed element does not hide the offers after it.
    try testing.expect(deflate.selectOffer(&.{"x y, permessage-deflate"}) != null);
    // Quoted values: unterminated, an escape at the end, an escaped digit.
    var p1 = (deflate.Extension{ .name = "a", .rest = "; x=\"b" }).params();
    try testing.expectError(error.Malformed, p1.next());
    var p2 = (deflate.Extension{ .name = "a", .rest = "; x=\"b\\" }).params();
    try testing.expectError(error.Malformed, p2.next());
    var p3 = (deflate.Extension{ .name = "a", .rest = "; x=\"1\\5\"" }).params();
    try testing.expectEqualStrings("15", (try p3.next()).?.value.?);
    // Window bits: two digits must be 10..15, one digit 8 or 9.
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; client_max_window_bits=25"}) == null);
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; client_max_window_bits=80"}) == null);
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; client_max_window_bits=\"15\""}) != null);
    // server_max_window_bits: 15 is accepted, an invalid value declines the offer.
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; server_max_window_bits=15"}) != null);
    try testing.expect(deflate.selectOffer(&.{"permessage-deflate; server_max_window_bits=16"}) == null);
    // A response's server_max_window_bits needs a value.
    try testing.expectError(error.Rejected, deflate.verifyResponse(&.{"permessage-deflate; server_no_context_takeover; server_max_window_bits"}));
}

test "inflate: a stored block that runs into the padding is refused, and the padding is zeros" {
    var window: deflate.Window = undefined;
    // A final stored block of LEN 14: the 9 tail bytes and 5 more from the
    // padding. Five padding bytes is as many as the peer sent, so only the
    // padding count tells it from a stream that ended in the tail.
    var b1: [5 + deflate.inflate_tail.len]u8 = undefined;
    @memcpy(b1[0..5], &[_]u8{ 0x01, 0x0e, 0x00, 0xf1, 0xff });
    var out: [64]u8 = undefined;
    try testing.expectError(error.InvalidCompressedData, deflate.inflate(&b1, 5, &out, &window));
    // Two empty fixed blocks, then a stored block of LEN 5 that takes the
    // first five tail bytes; the next stored header reads LEN 0xff00 from
    // the tail and NLEN's high byte from the padding. Zero padding makes
    // that NLEN valid, and the 65280 bytes it announces overflow `out`
    // (non-zero bytes there -- say, stale input -- would make it invalid).
    var b2: [7 + deflate.inflate_tail.len]u8 = undefined;
    @memcpy(b2[0..7], &[_]u8{ 0x02, 0x08, 0x80, 0x05, 0x00, 0xfa, 0xff });
    try testing.expectError(error.MessageTooLarge, deflate.inflate(&b2, 7, &out, &window));
}

test "compressMessage: no room at all is null, and the closing byte is written" {
    const gpa = testing.allocator;
    const comp = try gpa.create(deflate.Compressor);
    defer gpa.destroy(comp);
    const payload: [200]u8 = @splat('a');
    var none: [0]u8 = .{};
    try testing.expect(comp.compressMessage(&payload, &none, 1) == null);
    var one: [1]u8 = undefined;
    try testing.expect(comp.compressMessage(&payload, &one, 1) == null);
    var big: [512]u8 = undefined;
    @memset(&big, 0xff);
    const z = comp.compressMessage(&payload, &big, 1) orelse return error.TestCompressedNull;
    try testing.expectEqual(@as(u8, 0), z[z.len - 1]);
    var buf: [512 + deflate.inflate_tail.len]u8 = undefined;
    @memcpy(buf[0..z.len], z);
    var plain: [256]u8 = undefined;
    const window = try gpa.create(deflate.Window);
    defer gpa.destroy(window);
    try testing.expectEqualSlices(u8, &payload, try deflate.inflate(&buf, z.len, &plain, window));
    // A message whose last block is stored (an incompressible tail after a
    // compressible start): the closing byte follows raw bytes, not a
    // Huffman code whose store already zeroed the byte after it.
    var prng: std.Random.DefaultPrng = .init(9);
    for ([_][2]usize{ .{ 70000, 65536 }, .{ 40000, 40000 }, .{ 300, 200 } }) |shape| {
        const msg = try gpa.alloc(u8, shape[0] + shape[1]);
        defer gpa.free(msg);
        @memset(msg[0..shape[0]], 'a');
        prng.random().bytes(msg[shape[0]..]);
        const o = try gpa.alloc(u8, msg.len + 1024);
        defer gpa.free(o);
        @memset(o, 0xff);
        const zz = comp.compressMessage(msg, o, 1) orelse return error.TestCompressedNull;
        try testing.expectEqual(@as(u8, 0), zz[zz.len - 1]);
    }
}

test "acceptHandshake: a request without Sec-WebSocket-Version is refused" {
    try testing.expectError(error.UnsupportedVersion, handshake.acceptHandshake(try serverHead("Host: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++ std_key), .{}));
}

test "respond: a negotiated permessage-deflate is named in the 101" {
    const H = struct {
        fn handle(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
            const accept = try handshake.acceptHandshake(req.head, .{ .permessage_deflate = true });
            try handshake.respond(rw, accept);
        }
    };
    const wire = "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        std_key ++ "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
    var in: std.Io.Reader = .fixed(wire);
    var out_buf: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var head_buf: [1024]u8 = undefined;
    var body_buf: [64]u8 = undefined;
    var resp_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    _ = http.Server.serveStep(.{ .handler = H.handle, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &body_buf,
        .response_body = &resp_buf,
        .chunk = &chunk_buf,
    }, 0);
    try testing.expect(std.mem.find(u8, out.buffered(), "Sec-WebSocket-Extensions: " ++ deflate.response_value ++ "\r\n") != null);
}

test "generateKey is the base64 of 16 bytes drawn from the caller's random" {
    var p1: std.Random.DefaultPrng = .init(42);
    var p2: std.Random.DefaultPrng = .init(42);
    var raw: [16]u8 = undefined;
    p2.random().bytes(&raw);
    var want: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&want, &raw);
    try testing.expectEqualStrings(&want, &handshake.generateKey(p1.random()));
}

test "writeRequest: no protocols, no Sec-WebSocket-Protocol field" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try handshake.writeRequest(&w, .{ .host = "h", .key = "dGhlIHNhbXBsZSBub25jZQ==" });
    try testing.expect(std.mem.find(u8, w.buffered(), "Sec-WebSocket-Protocol") == null);
    try testing.expect(std.ascii.findIgnoreCase(w.buffered(), "sec-websocket-protocol") == null);
}
