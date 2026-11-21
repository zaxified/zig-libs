// SPDX-License-Identifier: MIT

//! Message compression (the gRPC `grpc-encoding` / `grpc-accept-encoding`
//! pair, doc/compression.md): `gzip` and `deflate` (RFC 1950 zlib streams, as
//! grpc-java and grpc-core name them), through `std.compress.flate` and
//! `http.gzip`'s encoder.
//!
//! **The bound that matters is on the decompressed size.** A compressed frame
//! is already limited on the wire by `max_recv_message_size`; the message it
//! inflates to is limited by the same number, checked while inflating: the
//! output buffer grows only by bytes actually produced and stops with
//! `error.TooLarge` one byte past the limit, so a 1 KiB frame of zeros cannot
//! become 4 GiB. That is the second instance of the invariant `frame.zig`
//! states for the wire length.

const std = @import("std");
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const http = @import("http");

/// A message encoding this module can produce and undo.
pub const Encoding = enum {
    identity,
    gzip,
    deflate,

    /// The `grpc-encoding` token, compared without regard to case.
    pub fn parse(token: []const u8) ?Encoding {
        inline for (@typeInfo(Encoding).@"enum".field_names) |field| {
            if (std.ascii.eqlIgnoreCase(token, field)) return @field(Encoding, field);
        }
        return null;
    }

    pub fn name(e: Encoding) []const u8 {
        return @tagName(e);
    }

    fn container(e: Encoding) flate.Container {
        return switch (e) {
            .identity => unreachable,
            .gzip => .gzip,
            .deflate => .zlib,
        };
    }
};

/// Which non-identity encodings a peer may use on the messages it sends us
/// (identity is always accepted). Everything is on by default: the receive
/// side is bounded (see the file doc).
pub const Accept = struct {
    gzip: bool = true,
    deflate: bool = true,

    pub fn allows(a: Accept, e: Encoding) bool {
        return switch (e) {
            .identity => true,
            .gzip => a.gzip,
            .deflate => a.deflate,
        };
    }

    /// The `grpc-accept-encoding` value: a static string for each of the four
    /// combinations, so no formatting and no allocation per call.
    pub fn header(a: Accept) []const u8 {
        if (a.gzip and a.deflate) return "gzip,deflate,identity";
        if (a.gzip) return "gzip,identity";
        if (a.deflate) return "deflate,identity";
        return "identity";
    }
};

/// Whether `list` (a `grpc-accept-encoding` value: comma-separated tokens)
/// names `e`.
pub fn listAccepts(list: []const u8, e: Encoding) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |tok| {
        if (Encoding.parse(std.mem.trim(u8, tok, " \t"))) |got| if (got == e) return true;
    }
    return false;
}

pub const Error = error{
    OutOfMemory,
    /// The message inflates to more than the limit.
    TooLarge,
    /// Not a valid stream of the stated encoding (or cut short).
    Corrupt,
};

const Inflater = struct {
    d: flate.Decompress,
    window: [flate.max_window_len]u8,
};

/// Inflate `in` (one whole message body, which the frame says is `enc`) into a
/// fresh buffer of at most `limit` bytes. Free with `gpa`.
pub fn decompress(gpa: Allocator, enc: Encoding, in: []const u8, limit: usize) Error![]u8 {
    std.debug.assert(enc != .identity);
    // ~100 KiB of state: not on the stack.
    const st = try gpa.create(Inflater);
    defer gpa.destroy(st);
    var r: std.Io.Reader = .fixed(in);
    st.d = .init(&r, enc.container(), &st.window);
    const out = st.d.reader.allocRemaining(gpa, .limited(limit)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.TooLarge,
        error.ReadFailed => return error.Corrupt,
    };
    errdefer gpa.free(out);
    // std reads the footer but leaves the checksum to the caller, and stops at
    // the end of the stream: verify both, and refuse bytes after it.
    if (r.seek != in.len) return error.Corrupt;
    switch (st.d.container_metadata) {
        .gzip => |g| {
            if (g.crc != std.hash.Crc32.hash(out) or g.count != @as(u32, @truncate(out.len))) return error.Corrupt;
        },
        .zlib => |z| {
            if (z.adler != std.hash.Adler32.hash(out)) return error.Corrupt;
        },
        .raw => {},
    }
    return out;
}

/// Compress `message` as `enc` into a fresh buffer. Free with `gpa`.
pub fn compress(gpa: Allocator, enc: Encoding, message: []const u8) Allocator.Error![]u8 {
    std.debug.assert(enc != .identity);
    const scratch = try gpa.create(http.gzip.Scratch);
    defer gpa.destroy(scratch);
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, @max(64, message.len / 2));
    errdefer out.deinit();
    const failed = error.OutOfMemory; // an Allocating writer fails only that way
    switch (enc) {
        .identity => unreachable,
        .gzip => {
            const w = scratch.begin(&out.writer, 6) catch return failed;
            w.writeAll(message) catch return failed;
            scratch.finish() catch return failed;
        },
        .deflate => {
            http.gzip.initCompress(&scratch.compress, &out.writer, &scratch.window, .zlib, http.gzip.levelOptions(6)) catch return failed;
            scratch.compress.writer.writeAll(message) catch return failed;
            scratch.compress.finish() catch return failed;
        },
    }
    return out.toOwnedSlice();
}

const testing = std.testing;

test "gzip and deflate round trip, and the bytes are what a foreign decoder reads" {
    const gpa = testing.allocator;
    var msg_buf: std.ArrayList(u8) = .empty;
    defer msg_buf.deinit(gpa);
    for (0..20) |_| try msg_buf.appendSlice(gpa, "hello hello hello hello hello, gRPC compression ");
    const msg = msg_buf.items;
    for ([_]Encoding{ .gzip, .deflate }) |enc| {
        const c = try compress(gpa, enc, msg);
        defer gpa.free(c);
        try testing.expect(c.len < msg.len);
        const back = try decompress(gpa, enc, c, msg.len);
        defer gpa.free(back);
        try testing.expectEqualStrings(msg, back);
    }
    const empty = try compress(gpa, .gzip, "");
    defer gpa.free(empty);
    const back = try decompress(gpa, .gzip, empty, 0);
    defer gpa.free(back);
    try testing.expectEqual(@as(usize, 0), back.len);
}

test "a decompression bomb stops at the limit, not at its claim" {
    const gpa = testing.allocator;
    const zeros = try gpa.alloc(u8, 4 * 1024 * 1024);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const c = try compress(gpa, .gzip, zeros);
    defer gpa.free(c);
    try testing.expect(c.len < 8 * 1024);
    try testing.expectError(error.TooLarge, decompress(gpa, .gzip, c, 1024 * 1024));
    // Exactly at the limit is fine; one under is not.
    const ok = try decompress(gpa, .gzip, c, zeros.len);
    defer gpa.free(ok);
    try testing.expectEqual(zeros.len, ok.len);
    try testing.expectError(error.TooLarge, decompress(gpa, .gzip, c, zeros.len - 1));
}

test "corrupt and wrong-encoding input is refused" {
    const gpa = testing.allocator;
    const c = try compress(gpa, .gzip, "some text some text some text");
    defer gpa.free(c);
    try testing.expectError(error.Corrupt, decompress(gpa, .deflate, c, 1024));
    try testing.expectError(error.Corrupt, decompress(gpa, .gzip, c[0 .. c.len - 4], 1024));
    try testing.expectError(error.Corrupt, decompress(gpa, .gzip, "not gzip at all, no", 1024));
    var flipped = try gpa.dupe(u8, c);
    defer gpa.free(flipped);
    flipped[flipped.len - 6] ^= 0xff; // inside the CRC
    try testing.expectError(error.Corrupt, decompress(gpa, .gzip, flipped, 1024));
}

test "encoding tokens and accept lists" {
    try testing.expectEqual(Encoding.gzip, Encoding.parse("GZip").?);
    try testing.expect(Encoding.parse("snappy") == null);
    try testing.expect(listAccepts("identity, gzip", .gzip));
    try testing.expect(!listAccepts("identity", .gzip));
    try testing.expect(!listAccepts("", .deflate));
    try testing.expectEqualStrings("gzip,identity", (Accept{ .deflate = false }).header());
}
