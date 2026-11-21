// SPDX-License-Identifier: MIT
//! Tests of `stream.PushDecoder` (the callback decoder): its events equal the
//! pull `Reader`'s tokens wherever the chunk boundaries fall, it refuses what
//! `Reader.skipValue` refuses, and text parts never split a code point.

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const stream = @import("stream.zig");
const kat = @import("kat_vectors.zig");

/// Hashes a token stream so that a string split into parts and a whole
/// string (the pull reader's token) give the same digest.
pub const Digest = struct {
    h: std.hash.Wyhash = .init(0),
    items: usize = 0,

    fn mark(self: *Digest, c: u8) void {
        self.h.update(&.{c});
    }

    pub fn token(self: *Digest, t: cbor.Token) void {
        self.mark(@backingInt(std.meta.activeTag(t)));
        switch (t) {
            .uint, .negint, .tag => |v| self.h.update(std.mem.asBytes(&v)),
            .array, .map => |v| {
                self.mark(@intFromBool(v != null));
                if (v) |n| self.h.update(std.mem.asBytes(&n));
            },
            .bytes, .text => |s| {
                self.mark('S');
                self.h.update(s);
                self.mark('E');
            },
            .simple => |v| self.mark(v),
            .bool => |v| self.mark(@intFromBool(v)),
            .f16 => |v| self.h.update(std.mem.asBytes(&@as(u16, @bitCast(v)))),
            .f32 => |v| self.h.update(std.mem.asBytes(&@as(u32, @bitCast(v)))),
            .f64 => |v| self.h.update(std.mem.asBytes(&@as(u64, @bitCast(v)))),
            .bytes_start, .text_start, .null_value, .undefined_value, .break_code => {},
        }
    }

    fn part(self: *Digest, tag: cbor.Token, p: stream.Part) void {
        if (p.first) {
            self.mark(@backingInt(std.meta.activeTag(tag)));
            self.mark('S');
        }
        self.h.update(p.data);
        if (p.last) self.mark('E');
    }

    pub fn event(self: *Digest, ev: stream.Event) error{}!void {
        switch (ev) {
            .token => |t| self.token(t),
            .bytes => |p| self.part(.{ .bytes = "" }, p),
            .text => |p| self.part(.{ .text = "" }, p),
            .item_end => self.items += 1,
        }
    }

    pub fn final(self: *Digest) u64 {
        return self.h.final();
    }
};

/// The digest of what the pull reader sees in `bytes` (every token, to the end).
pub fn readerDigest(bytes: []const u8) !Digest {
    var d: Digest = .{};
    var r: cbor.Reader = .init(bytes);
    while (try r.next()) |t| d.token(t);
    return d;
}

/// Feed `input` to a push decoder in pieces cut at `cuts` (ascending offsets).
pub fn pushed(comptime max_depth: u32, input: []const u8, cuts: []const usize, d: *Digest) !void {
    var dec = stream.PushDecoder(max_depth).init();
    var at: usize = 0;
    for (cuts) |c| {
        try dec.feed(input[at..c], d);
        at = c;
    }
    try dec.feed(input[at..], d);
    try dec.finish();
}

fn hexBytes(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(out, hex) catch unreachable;
}

test "push: RFC 8949 Appendix A gives the reader's tokens, whole and byte by byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (kat.vectors) |v| {
        const bytes = try hexBytes(a, v.hex);
        var want = try readerDigest(bytes);
        var whole: Digest = .{};
        try pushed(64, bytes, &.{}, &whole);
        try testing.expectEqual(want.final(), whole.final());
        try testing.expectEqual(@as(usize, 1), whole.items);
        const cuts = try a.alloc(usize, bytes.len -| 1);
        for (cuts, 0..) |*c, i| c.* = i + 1;
        var one: Digest = .{};
        try pushed(64, bytes, cuts, &one);
        try testing.expectEqual(whole.final(), one.final());
        try testing.expectEqual(@as(usize, 1), one.items);
    }
}

test "push: strings arrive in parts, text parts keep code points whole" {
    const Collect = struct {
        parts: usize = 0,
        bytes: [64]u8 = undefined,
        len: usize = 0,
        firsts: usize = 0,
        lasts: usize = 0,
        pub fn event(self: *@This(), ev: stream.Event) error{}!void {
            switch (ev) {
                .text => |p| {
                    // Every part is valid UTF-8 on its own.
                    if (!std.unicode.utf8ValidateSlice(p.data)) @panic("part splits a code point");
                    self.parts += 1;
                    self.firsts += @intFromBool(p.first);
                    self.lasts += @intFromBool(p.last);
                    @memcpy(self.bytes[self.len..][0..p.data.len], p.data);
                    self.len += p.data.len;
                },
                else => {},
            }
        }
    };
    // "a" U+00E9 U+20AC U+1F600 "z": 1 + 2 + 3 + 4 + 1 bytes.
    const text = "a\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80z";
    const input = "\x6b" ++ text;
    var c: Collect = .{};
    var dec = stream.PushDecoder(4).init();
    for (input) |b| try dec.feed(&.{b}, &c);
    try dec.finish();
    try testing.expectEqualStrings(text, c.bytes[0..c.len]);
    try testing.expectEqual(@as(usize, 1), c.firsts);
    try testing.expectEqual(@as(usize, 1), c.lasts);
    try testing.expectEqual(@as(usize, 5), c.parts); // a, é, €, the emoji, z

    // A length bigger than the input costs nothing: the string simply is not done.
    var c2: Collect = .{};
    var dec2 = stream.PushDecoder(4).init();
    try dec2.feed("\x7b\xff\xff\xff\xff\xff\xff\xff\xffabc", &c2);
    try testing.expectError(error.Truncated, dec2.finish());
    try testing.expectEqual(@as(usize, 3), c2.len);
}

fn runHex(comptime depth: u32, hex: []const u8) !usize {
    var buf: [64]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&buf, hex);
    var d: Digest = .{};
    try pushed(depth, bytes, &.{}, &d);
    return d.items;
}

test "push: malformed, truncated, depth and sequence verdicts" {
    try testing.expectEqual(@as(usize, 2), try runHex(64, "0102"));
    try testing.expectEqual(@as(usize, 0), try runHex(64, ""));
    try testing.expectEqual(@as(usize, 1), try runHex(64, "5fff"));
    try testing.expectEqual(@as(usize, 1), try runHex(64, "bf6161" ++ "01ff"));
    try testing.expectError(error.Malformed, runHex(64, "ff"));
    try testing.expectError(error.Malformed, runHex(64, "1c"));
    try testing.expectError(error.Malformed, runHex(64, "1f"));
    try testing.expectError(error.Malformed, runHex(64, "c1" ++ "1f"));
    try testing.expectError(error.Malformed, runHex(64, "f818"));
    try testing.expectError(error.Malformed, runHex(64, "5f6161ff")); // text chunk in a byte string
    try testing.expectError(error.Malformed, runHex(64, "5f5fff")); // indefinite chunk
    try testing.expectError(error.Malformed, runHex(64, "7f62e282ff")); // chunk ends inside a code point
    try testing.expectError(error.Malformed, runHex(64, "62c328")); // invalid UTF-8
    try testing.expectError(error.Malformed, runHex(64, "bf01ff")); // break where a value belongs
    try testing.expectError(error.Malformed, runHex(64, "81ff")); // break in a definite array
    try testing.expectError(error.Truncated, runHex(64, "83" ++ "0102"));
    try testing.expectError(error.Truncated, runHex(64, "5f4101"));
    try testing.expectError(error.Truncated, runHex(64, "19" ++ "01"));
    try testing.expectError(error.DepthLimitExceeded, runHex(2, "818181" ++ "01"));
    try testing.expectEqual(@as(usize, 1), try runHex(2, "81" ++ "8101"));
    try testing.expectEqual(@as(usize, 1), try runHex(2, "c1c1" ++ "01"));
    try testing.expectError(error.DepthLimitExceeded, runHex(2, "c1c1c1" ++ "01"));
}

test "push: a failed decoder stays failed" {
    var d: Digest = .{};
    var dec = stream.PushDecoder(4).init();
    try testing.expectError(error.Malformed, dec.feed("\xff", &d));
    try testing.expectError(error.Malformed, dec.feed("\x01", &d));
    try testing.expectError(error.Malformed, dec.finish());
}

/// The differential oracle for the fuzz driver: the push decoder reaches
/// `Reader.skipValue`'s verdict on `input` (`skip` is that verdict, the item's
/// length on success), whatever the chunking.
pub fn checkAgainstSkip(input: []const u8, max_depth: u32, skip: cbor.DecodeError!usize, cut_seed: u64) !void {
    switch (max_depth) {
        2 => try checkDepth(2, input, skip, cut_seed),
        4 => try checkDepth(4, input, skip, cut_seed),
        else => try checkDepth(64, input, skip, cut_seed),
    }
}

fn checkDepth(comptime depth: u32, input: []const u8, skip: cbor.DecodeError!usize, cut_seed: u64) !void {
    if (skip) |len| {
        const item = input[0..len];
        var whole: Digest = .{};
        try pushed(depth, item, &.{}, &whole);
        if (whole.items != 1) return error.PushItemCount;
        var want = try readerDigest(item);
        if (want.final() != whole.final()) return error.PushTokensDifferFromReader;
        var prng = std.Random.DefaultPrng.init(cut_seed);
        var cuts: [3]usize = undefined;
        for (&cuts) |*c| c.* = if (len == 0) 0 else prng.random().uintAtMost(usize, len);
        std.mem.sort(usize, &cuts, {}, std.sort.asc(usize));
        var split: Digest = .{};
        try pushed(depth, item, &cuts, &split);
        if (split.final() != whole.final() or split.items != 1) return error.PushChunkingChangesEvents;
        // Byte by byte, for short inputs.
        if (len <= 64) {
            var all: [64]usize = undefined;
            for (all[0..len -| 1], 0..) |*c, i| c.* = i + 1;
            var one: Digest = .{};
            try pushed(depth, item, all[0..len -| 1], &one);
            if (one.final() != whole.final()) return error.PushByteByByteDiffers;
        }
    } else |e| {
        var d: Digest = .{};
        if (pushed(depth, input, &.{}, &d)) |_| {
            // No input is an empty sequence, where `skipValue` wants an item.
            if (input.len == 0) return;
            // The first item is bad, so a clean run over all of `input` cannot be.
            std.debug.print("push accepted {x} (max_depth {d}), skip said {t}\n", .{ input, depth, e });
            return error.PushAcceptedWhatSkipRefused;
        } else |pe| {
            const ok = if (e == error.Truncated)
                // Text already delivered can be invalid before the cut shows.
                pe == error.Truncated or pe == error.Malformed
            else
                pe == e;
            if (!ok) {
                std.debug.print("push said {t} on {x} (max_depth {d}), skip said {t}\n", .{ pe, input, depth, e });
                return error.PushErrorDiffers;
            }
        }
    }
}
