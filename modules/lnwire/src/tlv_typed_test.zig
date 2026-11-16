// SPDX-License-Identifier: MIT
//! Typed accessors for the per-message TLV records (BOLT#1 `init_tlvs`,
//! BOLT#2 `open_channel_tlvs` / `accept_channel_tlvs` / `closing_signed_tlvs` /
//! `update_fulfill_htlc_tlvs` / `update_fail_htlc_tlvs`, BOLT#7
//! `query_short_channel_ids_tlvs` / `query_channel_range_tlvs`).
//!
//! Evidence: where a vendored vector (rust-lightning `msgs.rs`, the BOLT#7
//! `extended-queries.json`) carries the record, it is decoded through the
//! typed API and the value asserted against the vector's own breakdown.
//! The malformed / unknown-record cases are built by appending bytes to a
//! vendored message body.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const tlv = message.tlv;
const bolt1 = @import("bolt1.zig");
const bolt2 = @import("bolt2.zig");
const bolt7 = @import("bolt7.zig");
const v2 = @import("bolt2_channel_management_kat_vectors.zig");
const v1 = @import("bolt1_kat_vectors.zig");
const v7 = @import("bolt7_extended_queries_kat_vectors.zig");

fn hexBytes(a: Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn framed(a: Allocator, msg_type: u16, payload_hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, 2 + payload_hex.len / 2);
    std.mem.writeInt(u16, out[0..2], msg_type, .big);
    _ = try std.fmt.hexToBytes(out[2..], payload_hex);
    return out;
}

/// `base` followed by a `tlv_stream` of `records`.
fn withTlvs(a: Allocator, base: []const u8, records: []const tlv.RawRecord) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    try list.appendSlice(a, base);
    try tlv.appendStream(&list, a, records);
    return list.toOwnedSlice(a);
}

fn arena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

// ── open_channel / accept_channel ───────────────────────────────────────

test "typed TLV: open_channel/accept_channel accessors agree with every vendored vector" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    for (v2.open_channel_vectors) |v| {
        const m = try bolt2.decodeOpenChannel(a, try framed(a, bolt2.OPEN_CHANNEL_TYPE, v.payload_hex));
        if (v.upfront_shutdown_script_hex) |h| {
            try testing.expectEqualSlices(u8, try hexBytes(a, h), m.upfrontShutdownScript().?);
        } else try testing.expect(m.upfrontShutdownScript() == null);
        if (v.channel_type_hex) |h| {
            try testing.expectEqualSlices(u8, try hexBytes(a, h), m.channelType().?.bits);
        } else try testing.expect(m.channelType() == null);
    }
    for (v2.accept_channel_vectors) |v| {
        const m = try bolt2.decodeAcceptChannel(a, try framed(a, bolt2.ACCEPT_CHANNEL_TYPE, v.payload_hex));
        if (v.upfront_shutdown_script_hex) |h| {
            try testing.expectEqualSlices(u8, try hexBytes(a, h), m.upfrontShutdownScript().?);
        } else try testing.expect(m.upfrontShutdownScript() == null);
        try testing.expect(m.channelType() == null);
    }
}

test "typed TLV: open_channel channel_type bits, round-trip, unknown odd tolerated, unknown even refused" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const base = try framed(a, bolt2.OPEN_CHANNEL_TYPE, v2.open_channel_vectors[0].payload_hex);
    const script = [_]u8{ 0x00, 0x14 } ++ @as([20]u8, @splat(0xaa));
    // channel_type with bits 12 and 22 (BOLT#9 byte order: last octet = bits 0..7).
    const ct = [_]u8{ 0x40, 0x10, 0x00 };
    const bytes = try withTlvs(a, base, &.{
        .{ .type = 0, .value = &script },
        .{ .type = 1, .value = &ct },
        .{ .type = 99, .value = &.{ 1, 2, 3 } }, // unknown odd
    });
    const m = try bolt2.decodeOpenChannel(a, bytes);
    try testing.expectEqualSlices(u8, &script, m.upfrontShutdownScript().?);
    const t = m.channelType().?;
    try testing.expect(t.isSet(12) and t.isSet(22));
    try testing.expect(!t.isSet(0) and !t.isSet(13) and !t.isSet(500));
    try testing.expectEqualSlices(u8, &ct, t.minimal());
    // Unknown odd record: tolerated (discarded, BOLT#1 "ok to be odd"); typed ones survive a re-encode.
    try testing.expectEqual(@as(usize, 2), m.extension.records.len);
    const again = try bolt2.serializeOpenChannel(a, m);
    const m2 = try bolt2.decodeOpenChannel(a, again);
    try testing.expectEqualSlices(u8, &ct, m2.channelType().?.bits);
    // Unknown even record: refused.
    const even = try withTlvs(a, base, &.{.{ .type = 2, .value = &.{} }});
    try testing.expectError(error.UnknownEvenType, bolt2.decodeOpenChannel(a, even));
    // A zero-length upfront_shutdown_script is a real value, not "absent".
    const empty = try withTlvs(a, base, &.{.{ .type = 0, .value = &.{} }});
    try testing.expectEqual(@as(usize, 0), (try bolt2.decodeOpenChannel(a, empty)).upfrontShutdownScript().?.len);
}

test "typed TLV: accept_channel accessors on a built stream" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const base = try framed(a, bolt2.ACCEPT_CHANNEL_TYPE, v2.accept_channel_vectors[0].payload_hex);
    const bytes = try withTlvs(a, base, &.{
        .{ .type = 0, .value = &.{ 0x51, 0x20 } },
        .{ .type = 1, .value = &.{0x08} },
    });
    const m = try bolt2.decodeAcceptChannel(a, bytes);
    try testing.expectEqualSlices(u8, &.{ 0x51, 0x20 }, m.upfrontShutdownScript().?);
    try testing.expect(m.channelType().?.isSet(3));
    try testing.expectEqualSlices(u8, bytes, try bolt2.serializeAcceptChannel(a, m));
}

// ── closing_signed fee_range ────────────────────────────────────────────

test "typed TLV: closing_signed fee_range vs vendored vectors, round-trip, malformed length" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    for (v2.closing_signed_vectors) |v| {
        const m = try bolt2.decodeClosingSigned(a, try framed(a, bolt2.CLOSING_SIGNED_TYPE, v.payload_hex));
        if (v.fee_range) |want| {
            const got = m.feeRange().?;
            try testing.expectEqual(want.min_fee_satoshis, got.min_fee_satoshis);
            try testing.expectEqual(want.max_fee_satoshis, got.max_fee_satoshis);
            // The encoder produces the vendored value octets.
            const raw = got.toBytes();
            try testing.expectEqualSlices(u8, &raw, m.extension.find(1).?);
        } else try testing.expect(m.feeRange() == null);
    }
    const base = try framed(a, bolt2.CLOSING_SIGNED_TYPE, v2.closing_signed_vectors[0].payload_hex);
    const fr: bolt2.FeeRange = .{ .min_fee_satoshis = 1, .max_fee_satoshis = std.math.maxInt(u64) };
    const raw = fr.toBytes();
    const good = try withTlvs(a, base, &.{.{ .type = 1, .value = &raw }});
    const m = try bolt2.decodeClosingSigned(a, good);
    try testing.expectEqual(fr, m.feeRange().?);
    try testing.expectEqualSlices(u8, good, try bolt2.serializeClosingSigned(a, m));
    // 15 and 17 octets: error, never a panic; the encoder refuses the same.
    for ([_]usize{ 0, 8, 15, 17 }) |n| {
        var buf: [17]u8 = @splat(0);
        const bad = try withTlvs(a, base, &.{.{ .type = 1, .value = buf[0..n] }});
        try testing.expectError(error.InvalidTlvLength, bolt2.decodeClosingSigned(a, bad));
        var msg = m;
        msg.extension = .{ .records = @constCast(&[_]tlv.RawRecord{.{ .type = 1, .value = buf[0..n] }}) };
        try testing.expectError(error.InvalidTlvLength, bolt2.serializeClosingSigned(a, msg));
    }
    const even = try withTlvs(a, base, &.{.{ .type = 2, .value = &.{} }});
    try testing.expectError(error.UnknownEvenType, bolt2.decodeClosingSigned(a, even));
    const odd = try withTlvs(a, base, &.{ .{ .type = 1, .value = &raw }, .{ .type = 3, .value = &.{9} } });
    try testing.expectEqual(fr, (try bolt2.decodeClosingSigned(a, odd)).feeRange().?);
}

// ── attribution_data ────────────────────────────────────────────────────

test "typed TLV: update_fail_htlc attribution_data vs the vendored vector, structure round-trip" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const vec = v2.update_fail_htlc_vector;
    const bytes = try framed(a, bolt2.UPDATE_FAIL_HTLC_TYPE, vec.payload_hex);
    const m = try bolt2.decodeUpdateFailHtlc(a, bytes);
    const ad = m.attributionData().?;
    // rust-lightning's AttributionData::new(): all zero.
    for (ad.htlc_hold_times) |t| try testing.expectEqual(@as(u32, 0), t);
    for (ad.truncated_hmacs) |h| try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &h);
    const raw = ad.toBytes();
    try testing.expectEqualSlices(u8, try hexBytes(a, vec.attribution_data_hex), &raw);
    try testing.expectEqual(@as(usize, 920), bolt2.AttributionData.wire_len);

    // A non-trivial structure survives encode -> decode.
    var d: bolt2.AttributionData = undefined;
    for (&d.htlc_hold_times, 0..) |*t, i| t.* = @as(u32, @intCast(i)) * 0x01010101 + 7;
    for (&d.truncated_hmacs, 0..) |*h, i| h.* = .{ @truncate(i), @truncate(i >> 1), 0xee, @truncate(~i) };
    const draw = d.toBytes();
    try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, draw[0..4], .big));
    const base = bytes[0 .. bytes.len - (1 + 3 + 920)]; // strip the vendored TLV (type, bigsize 920 = 0xfd 0x03 0x98, value)
    const built = try withTlvs(a, base, &.{.{ .type = 1, .value = &draw }});
    const m2 = try bolt2.decodeUpdateFailHtlc(a, built);
    const d2 = m2.attributionData().?;
    try testing.expectEqualSlices(u32, &d.htlc_hold_times, &d2.htlc_hold_times);
    try testing.expectEqualSlices([4]u8, &d.truncated_hmacs, &d2.truncated_hmacs);
    try testing.expectEqualSlices(u8, built, try bolt2.serializeUpdateFailHtlc(a, m2));
}

test "typed TLV: update_fulfill/fail attribution_data wrong length -> error; unknown records" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const ful = try framed(a, bolt2.UPDATE_FULFILL_HTLC_TYPE, v2.update_fulfill_htlc_vector.payload_hex);
    const fail_full = try framed(a, bolt2.UPDATE_FAIL_HTLC_TYPE, v2.update_fail_htlc_vector.payload_hex);
    const fail = fail_full[0 .. fail_full.len - (1 + 3 + 920)];
    var buf: [921]u8 = @splat(0);
    for ([_]usize{ 0, 919, 921 }) |n| {
        const bf = try withTlvs(a, ful, &.{.{ .type = 1, .value = buf[0..n] }});
        try testing.expectError(error.InvalidTlvLength, bolt2.decodeUpdateFulfillHtlc(a, bf));
        const bl = try withTlvs(a, fail, &.{.{ .type = 1, .value = buf[0..n] }});
        try testing.expectError(error.InvalidTlvLength, bolt2.decodeUpdateFailHtlc(a, bl));
    }
    // Fulfill with a correct record: typed read works and re-encodes.
    const ok = try withTlvs(a, ful, &.{.{ .type = 1, .value = buf[0..920] }});
    const m = try bolt2.decodeUpdateFulfillHtlc(a, ok);
    try testing.expect(m.attributionData() != null);
    try testing.expectEqualSlices(u8, ok, try bolt2.serializeUpdateFulfillHtlc(a, m));
    // Encoder refuses the same bad lengths.
    var bad = m;
    bad.extension = .{ .records = @constCast(&[_]tlv.RawRecord{.{ .type = 1, .value = buf[0..919] }}) };
    try testing.expectError(error.InvalidTlvLength, bolt2.serializeUpdateFulfillHtlc(a, bad));
    var badf = try bolt2.decodeUpdateFailHtlc(a, fail);
    badf.extension = bad.extension;
    try testing.expectError(error.InvalidTlvLength, bolt2.serializeUpdateFailHtlc(a, badf));
    // Unknown odd: tolerated; unknown even: refused.
    const odd = try withTlvs(a, ful, &.{.{ .type = 5, .value = &.{1} }});
    try testing.expect((try bolt2.decodeUpdateFulfillHtlc(a, odd)).attributionData() == null);
    const even = try withTlvs(a, fail, &.{.{ .type = 2, .value = &.{} }});
    try testing.expectError(error.UnknownEvenType, bolt2.decodeUpdateFailHtlc(a, even));
}

// ── init: networks, remote_addr ─────────────────────────────────────────

test "typed TLV: init networks vs the vendored vector; malformed length; remote_addr" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const vec = try framed(a, bolt1.INIT_TYPE, v1.init_networks_payload_hex);
    const m = try bolt1.decodeInit(a, vec);
    var it = m.networks().?;
    try testing.expectEqual(@as(usize, 1), it.count());
    try testing.expectEqualSlices(u8, try hexBytes(a, v1.init_networks_chain_hash), &it.next().?);
    try testing.expect(it.next() == null);
    try testing.expect(m.remoteAddr() == null);
    try testing.expectEqualSlices(u8, vec, try bolt1.serializeInit(a, m));

    const none = try framed(a, bolt1.INIT_TYPE, v1.init_no_tlv_payload_hex);
    try testing.expect((try bolt1.decodeInit(a, none)).networks() == null);

    // Two chains; 0 chains (empty value) is a whole number of hashes too.
    const base = vec[0 .. vec.len - (2 + 32)];
    const two = try withTlvs(a, base, &.{.{ .type = 1, .value = &(@as([32]u8, @splat(1)) ++ @as([32]u8, @splat(2))) }});
    var it2 = (try bolt1.decodeInit(a, two)).networks().?;
    try testing.expectEqual(@as(usize, 2), it2.count());
    try testing.expectEqual(@as(u8, 1), it2.next().?[0]);
    try testing.expectEqual(@as(u8, 2), it2.next().?[0]);
    // 31 / 33 / 63 octets: error.
    var buf: [64]u8 = @splat(0);
    for ([_]usize{ 1, 31, 33, 63 }) |n| {
        const bad = try withTlvs(a, base, &.{.{ .type = 1, .value = buf[0..n] }});
        try testing.expectError(error.InvalidTlvLength, bolt1.decodeInit(a, bad));
        var msg = m;
        msg.extension = .{ .records = @constCast(&[_]tlv.RawRecord{.{ .type = 1, .value = buf[0..n] }}) };
        try testing.expectError(error.InvalidTlvLength, bolt1.serializeInit(a, msg));
    }

    // remote_addr: IPv4 192.0.2.1:9735, IPv6, DNS.
    const v4 = [_]u8{ 0x01, 192, 0, 2, 1, 0x26, 0x07 };
    const ra = try bolt1.decodeInit(a, try withTlvs(a, base, &.{.{ .type = 3, .value = &v4 }}));
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &ra.remoteAddr().?.ipv4.addr);
    try testing.expectEqual(@as(u16, 9735), ra.remoteAddr().?.port());
    const dns = [_]u8{ 0x05, 3, 'a', '.', 'b', 0x00, 0x50 };
    const rd = try bolt1.decodeInit(a, try withTlvs(a, base, &.{.{ .type = 3, .value = &dns }}));
    try testing.expectEqualStrings("a.b", rd.remoteAddr().?.dns.hostname);
    // Truncated descriptor / trailing octet / non-ASCII hostname: error.
    for ([_][]const u8{ v4[0..6], &(v4 ++ [_]u8{0}), &[_]u8{ 0x05, 1, 0xff, 0, 80 }, &[_]u8{0x02} }) |bad_v| {
        const bad = try withTlvs(a, base, &.{.{ .type = 3, .value = bad_v }});
        try testing.expectError(error.InvalidTlvLength, bolt1.decodeInit(a, bad));
    }
    // An unknown descriptor type cannot be framed: accepted, reported as absent.
    const unk = try bolt1.decodeInit(a, try withTlvs(a, base, &.{.{ .type = 3, .value = &.{ 0x42, 1, 2, 3 } }}));
    try testing.expect(unk.remoteAddr() == null);
    try testing.expect(unk.extension.find(3) != null);
    // Unknown odd tolerated next to typed ones; unknown even refused.
    const odd = try bolt1.decodeInit(a, try withTlvs(a, base, &.{ .{ .type = 3, .value = &v4 }, .{ .type = 9, .value = &.{1} } }));
    try testing.expect(odd.remoteAddr() != null);
    try testing.expectError(error.UnknownEvenType, bolt1.decodeInit(a, try withTlvs(a, base, &.{.{ .type = 2, .value = &.{} }})));
}

// ── BOLT#7 query_option / query_flags ───────────────────────────────────

test "typed TLV: query_channel_range query_option vs vendored vectors; malformed" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    for (v7.query_channel_range_vectors) |v| {
        const m = try bolt7.decodeQueryChannelRange(a, try hexBytes(a, v.hex));
        if (v.query_option) |o| {
            try testing.expectEqual(@as(u64, o), m.queryOption().?);
        } else try testing.expect(m.queryOption() == null);
        try testing.expectEqualSlices(u8, try hexBytes(a, v.hex), try bolt7.serializeQueryChannelRange(a, m));
    }
    const m3 = try bolt7.decodeQueryChannelRange(a, try hexBytes(a, v7.query_channel_range_vectors[1].hex));
    try testing.expect(m3.queryOption().? & bolt7.QUERY_OPTION_TIMESTAMPS != 0);
    try testing.expect(m3.queryOption().? & bolt7.QUERY_OPTION_CHECKSUMS != 0);

    const base_full = try hexBytes(a, v7.query_channel_range_vectors[0].hex);
    // A multi-octet bigsize round-trips.
    const big = [_]u8{ 0xfd, 0x01, 0x00 };
    const bm = try bolt7.decodeQueryChannelRange(a, try withTlvs(a, base_full, &.{.{ .type = 1, .value = &big }}));
    try testing.expectEqual(@as(u64, 256), bm.queryOption().?);
    // Empty, two bigsizes, non-minimal, truncated: error.
    for ([_][]const u8{ &.{}, &.{ 0x03, 0x00 }, &.{ 0xfd, 0x00, 0x03 }, &.{ 0xfd, 0x01 } }) |bad_v| {
        const bad = try withTlvs(a, base_full, &.{.{ .type = 1, .value = bad_v }});
        try testing.expectError(error.InvalidTlvLength, bolt7.decodeQueryChannelRange(a, bad));
        var msg = bm;
        msg.extension = .{ .records = @constCast(&[_]tlv.RawRecord{.{ .type = 1, .value = bad_v }}) };
        try testing.expectError(error.InvalidTlvLength, bolt7.serializeQueryChannelRange(a, msg));
    }
    try testing.expectError(error.UnknownEvenType, bolt7.decodeQueryChannelRange(a, try withTlvs(a, base_full, &.{.{ .type = 2, .value = &.{} }})));
    const odd = try bolt7.decodeQueryChannelRange(a, try withTlvs(a, base_full, &.{ .{ .type = 1, .value = &.{3} }, .{ .type = 7, .value = &.{} } }));
    try testing.expectEqual(@as(u64, 3), odd.queryOption().?);
}

test "typed TLV: query_short_channel_ids query_flags; vendored zlib vectors; malformed" {
    var ar = arena();
    defer ar.deinit();
    const a = ar.allocator();
    const chain: [32]u8 = @splat(0x11);
    const head = try std.mem.concat(a, u8, &.{ &[_]u8{ 0x01, 0x05 }, &chain, &[_]u8{ 0x00, 0x01, 0x00 } });
    // encoding 0, three flag values, the last a multi-octet bigsize.
    const flags = [_]u8{ 0x00, 0x01, 0x1f, 0xfd, 0x01, 0x00 };
    const m = try bolt7.decodeQueryShortChannelIds(a, try withTlvs(a, head, &.{.{ .type = 1, .value = &flags }}));
    const qf = m.queryFlags().?;
    try testing.expectEqual(@as(u8, 0), qf.encoding_type);
    var it = try qf.iterator();
    try testing.expectEqual(@as(?u64, 1), try it.next());
    try testing.expectEqual(@as(?u64, 0x1f), try it.next());
    try testing.expectEqual(@as(?u64, 256), try it.next());
    try testing.expectEqual(@as(?u64, null), try it.next());
    try testing.expect(bolt7.QueryFlags.SEND_CHANNEL_UPDATE_NODE2 & 0x1f != 0);
    try testing.expectEqualSlices(u8, try bolt7.serializeQueryShortChannelIds(a, m), try withTlvs(a, head, &.{.{ .type = 1, .value = &flags }}));
    // zlib (1) and unknown encodings are carried, not walked.
    const z = try bolt7.decodeQueryShortChannelIds(a, try withTlvs(a, head, &.{.{ .type = 1, .value = &.{ 0x01, 0x78, 0x9c } }}));
    try testing.expectEqual(@as(u8, 1), z.queryFlags().?.encoding_type);
    try testing.expectError(error.UnsupportedEncoding, z.queryFlags().?.iterator());
    // Empty value (no encoding_type), non-minimal / truncated bigsize in an uncompressed list: error.
    for ([_][]const u8{ &.{}, &.{ 0x00, 0xfd, 0x00, 0x01 }, &.{ 0x00, 0xfd, 0x01 }, &.{ 0x00, 0x01, 0xff } }) |bad_v| {
        const bad = try withTlvs(a, head, &.{.{ .type = 1, .value = bad_v }});
        try testing.expectError(error.InvalidTlvLength, bolt7.decodeQueryShortChannelIds(a, bad));
        var msg = m;
        msg.extension = .{ .records = @constCast(&[_]tlv.RawRecord{.{ .type = 1, .value = bad_v }}) };
        try testing.expectError(error.InvalidTlvLength, bolt7.serializeQueryShortChannelIds(a, msg));
    }
    try testing.expectError(error.UnknownEvenType, bolt7.decodeQueryShortChannelIds(a, try withTlvs(a, head, &.{.{ .type = 2, .value = &.{} }})));
    // Vendored extended-query vectors that carry a (zlib) query_flags TLV decode through the typed API.
    var seen: usize = 0;
    for (v7.query_short_channel_ids_vectors) |v| {
        if (!v.has_query_flags_tlv) continue;
        const dm = try bolt7.decodeQueryShortChannelIds(a, try hexBytes(a, v.hex));
        try testing.expect(dm.queryFlags() != null);
        seen += 1;
    }
    try testing.expect(seen >= 1);
}
