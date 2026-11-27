// SPDX-License-Identifier: MIT
//! Decoding of the zlib-compressed lists of BOLT#7 `extended-queries.json`
//! (`bolt7.decodeShortIds` / `decodeTimestampPairs` / `QueryFlags.decode`): the
//! four rows with a zlib `encoded_short_ids`, the zlib `timestamps_tlv` and the
//! zlib `query_flags`, each checked against the decoded arrays that file states
//! beside the hex (`shortChannelIds.array`, `timestamps`, `tlvStream` records).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const bolt7 = @import("bolt7.zig");
const kat = @import("bolt7_extended_queries_kat_vectors.zig");

fn scid(block: u64, tx: u64, out: u64) u64 {
    return block << 40 | tx << 16 | out;
}

fn hexAlloc(a: Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "reply_channel_range rows: zlib short ids and timestamps decode to the arrays the file states" {
    const a = testing.allocator;
    {
        const bytes = try hexAlloc(a, kat.reply_channel_range_vectors[1].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeReplyChannelRange(a, bytes);
        defer m.deinit(a);
        const ids = try bolt7.decodeShortIds(a, m.encoded_short_ids, .{});
        defer a.free(ids);
        try testing.expectEqualSlices(u64, &.{ scid(0, 0, 142), scid(0, 0, 15465), scid(0, 4, 3318) }, ids);
    }
    {
        const bytes = try hexAlloc(a, kat.reply_channel_range_vectors[3].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeReplyChannelRange(a, bytes);
        defer m.deinit(a);
        const ids = try bolt7.decodeShortIds(a, m.encoded_short_ids, .{});
        defer a.free(ids);
        try testing.expectEqualSlices(u64, &.{ scid(0, 0, 12355), scid(0, 7, 30934), scid(0, 70, 57793) }, ids);
        const ts = try bolt7.decodeTimestampPairs(a, m.extension.find(1).?, .{});
        defer a.free(ts);
        try testing.expectEqual(@as(usize, 3), ts.len);
        try testing.expectEqual(bolt7.TimestampPair{ .timestamp_node_id_1 = 164545, .timestamp_node_id_2 = 948165 }, ts[0]);
        try testing.expectEqual(bolt7.TimestampPair{ .timestamp_node_id_1 = 489645, .timestamp_node_id_2 = 4786864 }, ts[1]);
        try testing.expectEqual(bolt7.TimestampPair{ .timestamp_node_id_1 = 46456, .timestamp_node_id_2 = 9788415 }, ts[2]);
    }
    // The uncompressed rows decode through the same function.
    {
        const bytes = try hexAlloc(a, kat.reply_channel_range_vectors[2].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeReplyChannelRange(a, bytes);
        defer m.deinit(a);
        const ids = try bolt7.decodeShortIds(a, m.encoded_short_ids, .{});
        defer a.free(ids);
        try testing.expectEqual(@as(usize, kat.reply_channel_range_vectors[2].scids.len), ids.len);
        const ts = try bolt7.decodeTimestampPairs(a, m.extension.find(1).?, .{});
        defer a.free(ts);
        try testing.expectEqual(@as(usize, kat.reply_channel_range_vectors[2].timestamps.len), ts.len);
    }
}

test "query_short_channel_ids rows: zlib short ids and zlib query_flags" {
    const a = testing.allocator;
    {
        const bytes = try hexAlloc(a, kat.query_short_channel_ids_vectors[1].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeQueryShortChannelIds(a, bytes);
        defer m.deinit(a);
        const ids = try bolt7.decodeShortIds(a, m.encoded_short_ids, .{});
        defer a.free(ids);
        try testing.expectEqualSlices(u64, &.{ scid(0, 0, 4564), scid(0, 2, 47550), scid(0, 69, 42692) }, ids);
    }
    {
        const bytes = try hexAlloc(a, kat.query_short_channel_ids_vectors[3].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeQueryShortChannelIds(a, bytes);
        defer m.deinit(a);
        const ids = try bolt7.decodeShortIds(a, m.encoded_short_ids, .{});
        defer a.free(ids);
        try testing.expectEqualSlices(u64, &.{ scid(0, 0, 14200), scid(0, 0, 46645), scid(0, 69, 42692) }, ids);
        const flags = m.queryFlags().?;
        try testing.expectEqual(bolt7.ENCODING_ZLIB, flags.encoding_type);
        try testing.expectError(error.UnsupportedEncoding, flags.iterator());
        const f = try flags.decode(a, .{});
        defer a.free(f);
        try testing.expectEqualSlices(u64, &.{ 1, 2, 4 }, f);
    }
    {
        // uncompressed ids + zlib flags
        const bytes = try hexAlloc(a, kat.query_short_channel_ids_vectors[2].hex);
        defer a.free(bytes);
        var m = try bolt7.decodeQueryShortChannelIds(a, bytes);
        defer m.deinit(a);
        const f = try m.queryFlags().?.decode(a, .{});
        defer a.free(f);
        try testing.expectEqualSlices(u64, &.{ 1, 2, 4 }, f);
    }
}

test "decode refusals: empty, odd length, unknown encoding, corrupt zlib, bomb, trailing bytes" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidEncodedList, bolt7.decodeShortIds(a, &.{}, .{}));
    try testing.expectError(error.InvalidEncodedList, bolt7.decodeShortIds(a, &.{ 0, 1, 2, 3 }, .{}));
    try testing.expectError(error.UnsupportedEncoding, bolt7.decodeShortIds(a, &.{ 2, 0, 0, 0, 0, 0, 0, 0, 1 }, .{}));
    // an empty uncompressed list is valid (no ids)
    const none = try bolt7.decodeShortIds(a, &.{0}, .{});
    a.free(none);
    // corrupt: zlib header, then garbage
    try testing.expectError(error.InvalidCompressedData, bolt7.decodeShortIds(a, &.{ 1, 0x78, 0x9c, 0xff, 0xff, 0xff }, .{}));
    try testing.expectError(error.InvalidCompressedData, bolt7.decodeShortIds(a, &.{ 1, 0x00, 0x00 }, .{}));
    // a valid stream cut short
    const good = try hexAlloc(a, "01789c63600001c12b608a69e73e30edbaec0800203b040e");
    defer a.free(good);
    // (good[0] is the encoding byte 0x01, followed by the zlib stream)
    try testing.expectError(error.InvalidCompressedData, bolt7.decodeShortIds(a, good[0 .. good.len - 3], .{}));
    // a flipped Adler-32 byte (std reads the trailer but does not compare it; inflateZlib does)
    var bad = try a.dupe(u8, good);
    defer a.free(bad);
    bad[bad.len - 1] ^= 0x01;
    try testing.expectError(error.InvalidCompressedData, bolt7.decodeShortIds(a, bad, .{}));
    // the same stream decoded under a 16-byte output cap: 24 bytes of ids do not fit
    try testing.expectError(error.OutputTooLarge, bolt7.decodeShortIds(a, good, .{ .max_output = 16 }));
    const ok = try bolt7.decodeShortIds(a, good, .{ .max_output = 24 });
    a.free(ok);
    // bytes after the zlib stream are ignored
    var trailing = try a.alloc(u8, good.len + 3);
    defer a.free(trailing);
    @memcpy(trailing[0..good.len], good);
    @memset(trailing[good.len..], 0xee);
    const t = try bolt7.decodeShortIds(a, trailing, .{});
    defer a.free(t);
    try testing.expectEqual(@as(usize, 3), t.len);
}

test "a zlib bomb (3 MiB of zeros in 3071 bytes) is stopped at the default cap" {
    const a = testing.allocator;
    const bomb = try hexAlloc(a, "0178daedc1010d000000c2a0f74f6d0e37a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be0d02d00001");
    defer a.free(bomb);
    try testing.expectError(error.OutputTooLarge, bolt7.decodeShortIds(a, bomb, .{}));
    try testing.expectEqual(@as(usize, 1 << 20), (bolt7.ListOptions{}).max_output);
    // with a cap above the output it decodes: 3 MiB of zero bytes are 393216 ids of 0
    const all = try bolt7.decodeShortIds(a, bomb, .{ .max_output = 3 << 20 });
    defer a.free(all);
    try testing.expectEqual(@as(usize, 393216), all.len);
}

test "query_flags decode: malformed bigsize is InvalidEncodedList; uncompressed matches iterator" {
    const a = testing.allocator;
    const qf: bolt7.QueryFlags = .{ .encoding_type = 0, .data = &.{ 0x01, 0xfd, 0x00, 0xfc, 0x02 } };
    // 0xfd 0x00 0xfc is a non-minimal bigsize (252 encoded in 3 bytes)
    try testing.expectError(error.InvalidEncodedList, qf.decode(a, .{}));
    const trunc: bolt7.QueryFlags = .{ .encoding_type = 0, .data = &.{ 0x01, 0xfd, 0x01 } };
    try testing.expectError(error.InvalidEncodedList, trunc.decode(a, .{}));
    const good: bolt7.QueryFlags = .{ .encoding_type = 0, .data = &.{ 0x01, 0x1f, 0xfd, 0x01, 0x2c } };
    const v = try good.decode(a, .{});
    defer a.free(v);
    try testing.expectEqualSlices(u64, &.{ 1, 31, 300 }, v);
    var it = try good.iterator();
    try testing.expectEqual(@as(?u64, 1), try it.next());
}

test "mutation 2026-11-25: max_output is exact (24 bytes fit 24, not 23); timestamps refuse a ragged length" {
    const a = testing.allocator;
    const good = try hexAlloc(a, "01789c63600001c12b608a69e73e30edbaec0800203b040e");
    defer a.free(good);
    try testing.expectError(error.OutputTooLarge, bolt7.decodeShortIds(a, good, .{ .max_output = 23 }));
    // timestamps: an empty list is valid, 4 and 9 bytes are not whole pairs
    const none = try bolt7.decodeTimestampPairs(a, &.{0}, .{});
    a.free(none);
    try testing.expectError(error.InvalidEncodedList, bolt7.decodeTimestampPairs(a, &.{}, .{}));
    try testing.expectError(error.InvalidEncodedList, bolt7.decodeTimestampPairs(a, &.{ 0, 1, 2, 3, 4 }, .{}));
    try testing.expectError(error.InvalidEncodedList, bolt7.decodeTimestampPairs(a, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, .{}));
}
