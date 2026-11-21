// SPDX-License-Identifier: MIT

//! gRPC-Web on the server (`application/grpc-web[-text][+subtype]`): the same
//! length-prefixed messages as gRPC, but the trailers (`grpc-status`,
//! `grpc-message`, trailing metadata) travel as a last length-prefixed frame
//! with the high bit of the flag byte set (0x80) whose payload is
//! `name: value\r\n` lines, because browsers cannot read HTTP trailers; and
//! the `-text` flavour base64-encodes the whole body in both directions, so a
//! browser can use a plain `text` XHR. The encoder and decoder here are
//! stream-aware: bytes are carried between calls so the output is one valid
//! base64 stream however the messages were chunked.

const std = @import("std");

pub const Mode = enum { none, binary, text };

/// The gRPC-Web flavour of a request `content-type`, or `.none` for plain gRPC
/// (and anything else).
pub fn modeOf(ct: []const u8) Mode {
    const base = "application/grpc-web";
    if (ct.len < base.len or !std.ascii.eqlIgnoreCase(ct[0..base.len], base)) return .none;
    var rest = ct[base.len..];
    var mode: Mode = .binary;
    const text = "-text";
    if (rest.len >= text.len and std.ascii.eqlIgnoreCase(rest[0..text.len], text)) {
        mode = .text;
        rest = rest[text.len..];
    }
    if (rest.len == 0) return mode;
    return switch (rest[0]) {
        '+', ';', ' ' => mode,
        else => .none,
    };
}

/// The flag byte of the trailer frame.
pub const trailer_flag: u8 = 0x80;

/// Base64 (padded) encoder over a stream: whole 3-byte groups go out as they
/// complete, the remainder is carried, `finish` pads it.
pub const Encoder = struct {
    carry: [3]u8 = undefined,
    n: usize = 0,

    pub fn write(e: *Encoder, w: anytype, bytes: []const u8) !void {
        var rest = bytes;
        if (e.n != 0) {
            while (e.n < 3 and rest.len != 0) {
                e.carry[e.n] = rest[0];
                e.n += 1;
                rest = rest[1..];
            }
            if (e.n < 3) return;
            try emit(w, e.carry[0..3]);
            e.n = 0;
        }
        const whole = rest.len / 3 * 3;
        var off: usize = 0;
        while (off < whole) {
            const take = @min(768, whole - off);
            try emit(w, rest[off..][0..take]);
            off += take;
        }
        const tail = rest[whole..];
        @memcpy(e.carry[0..tail.len], tail);
        e.n = tail.len;
    }

    /// Flush the carried bytes with padding. Call once, last.
    pub fn finish(e: *Encoder, w: anytype) !void {
        if (e.n != 0) try emit(w, e.carry[0..e.n]);
        e.n = 0;
    }

    fn emit(w: anytype, bytes: []const u8) !void {
        var buf: [1024]u8 = undefined;
        try w.writeAll(std.base64.standard.Encoder.encode(&buf, bytes));
    }
};

/// Base64 decoder over a stream: decodes whole 4-character groups, carries the
/// rest. A group with padding ends the stream; anything after it is invalid.
pub const Decoder = struct {
    carry: [4]u8 = undefined,
    n: usize = 0,
    done: bool = false,

    pub const Error = error{InvalidBase64};

    /// Bytes `out` must hold for `push` of `len` input bytes.
    pub fn maxOut(d: *const Decoder, len: usize) usize {
        return (d.n + len) / 4 * 3;
    }

    /// Decode `in` (any length) into `out` (at least `maxOut(in.len)` bytes);
    /// the bytes produced.
    pub fn push(d: *Decoder, in: []const u8, out: []u8) Error![]u8 {
        var o: usize = 0;
        for (in) |c| {
            if (d.done) return error.InvalidBase64;
            d.carry[d.n] = c;
            d.n += 1;
            if (d.n < 4) continue;
            d.n = 0;
            const padded = d.carry[3] == '=';
            const len = std.base64.standard.Decoder.calcSizeForSlice(&d.carry) catch return error.InvalidBase64;
            std.base64.standard.Decoder.decode(out[o..][0..len], &d.carry) catch return error.InvalidBase64;
            o += len;
            if (padded) d.done = true;
        }
        return out[0..o];
    }

    /// The stream ended: a partial group is a truncated body.
    pub fn complete(d: *const Decoder) bool {
        return d.n == 0;
    }
};

const testing = std.testing;

const Sink = struct {
    list: std.ArrayList(u8) = .empty,
    fn writeAll(s: *Sink, b: []const u8) !void {
        try s.list.appendSlice(testing.allocator, b);
    }
};

test "content types" {
    try testing.expectEqual(Mode.binary, modeOf("application/grpc-web"));
    try testing.expectEqual(Mode.binary, modeOf("application/grpc-web+proto"));
    try testing.expectEqual(Mode.text, modeOf("application/grpc-web-text"));
    try testing.expectEqual(Mode.text, modeOf("Application/GRPC-Web-Text+proto; charset=x"));
    try testing.expectEqual(Mode.none, modeOf("application/grpc"));
    try testing.expectEqual(Mode.none, modeOf("application/grpc-webx"));
    try testing.expectEqual(Mode.none, modeOf("application/json"));
}

test "the encoder makes one valid stream however the bytes are chunked, and the decoder reads it back" {
    var src: [200]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var want_buf: [512]u8 = undefined;
    const want = std.base64.standard.Encoder.encode(&want_buf, &src);
    for ([_]usize{ 1, 2, 3, 4, 5, 7, 64, 199, 200 }) |chunk| {
        var sink: Sink = .{};
        defer sink.list.deinit(testing.allocator);
        var e: Encoder = .{};
        var off: usize = 0;
        while (off < src.len) : (off += chunk) try e.write(&sink, src[off..@min(src.len, off + chunk)]);
        try e.finish(&sink);
        try testing.expectEqualStrings(want, sink.list.items);

        var d: Decoder = .{};
        var out: [200]u8 = undefined;
        var got: usize = 0;
        var pos: usize = 0;
        while (pos < want.len) : (pos += chunk) {
            const piece = want[pos..@min(want.len, pos + chunk)];
            var tmp: [256]u8 = undefined;
            const part = try d.push(piece, tmp[0..d.maxOut(piece.len)]);
            @memcpy(out[got..][0..part.len], part);
            got += part.len;
        }
        try testing.expect(d.complete());
        try testing.expectEqualSlices(u8, &src, out[0..got]);
    }
}

test "the decoder refuses bad characters, bytes after padding and reports a cut group" {
    var d: Decoder = .{};
    var out: [16]u8 = undefined;
    try testing.expectError(error.InvalidBase64, d.push("ab*d", &out));
    var d2: Decoder = .{};
    _ = try d2.push("YQ==", &out);
    try testing.expectError(error.InvalidBase64, d2.push("YQ==", &out));
    var d3: Decoder = .{};
    _ = try d3.push("YQ", &out);
    try testing.expect(!d3.complete());
}
