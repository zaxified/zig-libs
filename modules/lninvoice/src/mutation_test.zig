// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-27 delta mutation run over the BOLT#12 blinded-path / offer layer (`blinded.zig`,
//! `offer.zig`) and the typed record accessors of `bolt12.zig`. Every expected value comes from BOLT#12 / BOLT#4
//! (big-endian integers, `num_hops` 1..255, `encrypted_recipient_data` up to 65535 bytes, TLV type ranges of an
//! offer), not from running the code.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const lnwire = @import("lnwire");
const bech32raw = @import("bech32_raw.zig");
const bitpack = @import("bitpack.zig");
const bolt12 = @import("bolt12.zig");
const blinded = @import("blinded.zig");
const offer_mod = @import("offer.zig");

/// 02 02 .. 02 is on the curve (see blinded.zig tests); 03 03 .. 03 is not.
const good33: [33]u8 = @splat(2);
const bad33: [33]u8 = @splat(3);

fn lnoOf(a: Allocator, records: []const lnwire.RawRecord) ![]u8 {
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(a);
    try lnwire.tlv.appendStream(&stream, a, records);
    const q = try bitpack.bytesToQuintets(a, stream.items);
    defer a.free(q);
    return bech32raw.encodeNoChecksum(a, "lno", q);
}

test "mutation 2026-11-27: blinded paths: an scid first node cut short is Truncated at every length" {
    for ([_]u8{ 0, 1 }) |kind| {
        var buf: [8]u8 = @splat(0);
        buf[0] = kind;
        for (1..9) |n| {
            var it: blinded.PathIterator = .{ .bytes = buf[0..n] };
            try testing.expectError(error.Truncated, it.next());
        }
    }
}

test "mutation 2026-11-27: blinded paths: a last hop with empty data, 255 hops, data length limits (65535-byte datum round trip, FIX 2026-11-27)" {
    const a = testing.allocator;
    // The last hop has no encrypted data: exactly 35 bytes remain for it.
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        try blinded.appendPath(a, &out, .{ .node_id = good33 }, good33, &.{.{ .blinded_node_id = good33, .encrypted_recipient_data = &.{} }});
        try testing.expectEqual(@as(usize, 33 + 33 + 1 + 35), out.items.len);
        var it: blinded.PathIterator = .{ .bytes = out.items };
        const p = (try it.next()).?;
        try testing.expectEqual(@as(u8, 1), p.num_hops);
        var h = p.hops();
        try testing.expectEqual(@as(usize, 0), h.next().?.encrypted_recipient_data.len);
        try testing.expect(h.next() == null);
        try testing.expect((try it.next()) == null);
    }
    // num_hops is one byte: 255 hops are legal, 256 are not.
    {
        const hops: [256]blinded.Hop = @splat(.{ .blinded_node_id = good33, .encrypted_recipient_data = &.{} });
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        try blinded.appendPath(a, &out, .{ .node_id = good33 }, good33, hops[0..255]);
        var it: blinded.PathIterator = .{ .bytes = out.items };
        const p = (try it.next()).?;
        try testing.expectEqual(@as(u8, 255), p.num_hops);
        var h = p.hops();
        var n: usize = 0;
        while (h.next()) |_| n += 1;
        try testing.expectEqual(@as(usize, 255), n);
        var out2: std.ArrayList(u8) = .empty;
        defer out2.deinit(a);
        try testing.expectError(error.FieldTooLong, blinded.appendPath(a, &out2, .{ .node_id = good33 }, good33, hops[0..256]));
    }
    // A hop's blinded node id must be a valid point.
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        try testing.expectError(error.InvalidPoint, blinded.appendPath(a, &out, .{ .node_id = good33 }, good33, &.{.{ .blinded_node_id = bad33, .encrypted_recipient_data = &.{} }}));
    }
    // encrypted_recipient_data: u16 length, so 65535 bytes are legal and 65536 are not.
    {
        const big = try a.alloc(u8, 65536);
        defer a.free(big);
        @memset(big, 0x5a);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        try blinded.appendPath(a, &out, .{ .node_id = good33 }, good33, &.{.{ .blinded_node_id = good33, .encrypted_recipient_data = big[0..65535] }});
        var it: blinded.PathIterator = .{ .bytes = out.items };
        const p = (try it.next()).?;
        var h = p.hops();
        try testing.expectEqual(@as(usize, 65535), h.next().?.encrypted_recipient_data.len);
        var out2: std.ArrayList(u8) = .empty;
        defer out2.deinit(a);
        try testing.expectError(error.FieldTooLong, blinded.appendPath(a, &out2, .{ .node_id = good33 }, good33, &.{.{ .blinded_node_id = good33, .encrypted_recipient_data = big }}));
    }
}

test "mutation 2026-11-27: blinded payinfo: every field big-endian on the wire and read back; features length limit (65535-byte round trip, FIX 2026-11-27)" {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try blinded.appendPayInfo(a, &out, .{ .fee_base_msat = 1, .fee_proportional_millionths = 2, .cltv_expiry_delta = 3, .htlc_minimum_msat = 4, .htlc_maximum_msat = 5, .features = &.{} });
    // BOLT#12 blinded_payinfo: u32 fee_base_msat, u32 fee_proportional_millionths, u16 cltv_expiry_delta,
    // u64 htlc_minimum_msat, u64 htlc_maximum_msat, u16 flen, features; all integers big-endian (BOLT#1).
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x01" ++ "\x00\x00\x00\x02" ++ "\x00\x03" ++ "\x00\x00\x00\x00\x00\x00\x00\x04" ++ "\x00\x00\x00\x00\x00\x00\x00\x05" ++ "\x00\x00", out.items);
    var it: blinded.PayInfoIterator = .{ .bytes = out.items };
    const p = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1), p.fee_base_msat);
    try testing.expectEqual(@as(u32, 2), p.fee_proportional_millionths);
    try testing.expectEqual(@as(u16, 3), p.cltv_expiry_delta);
    try testing.expectEqual(@as(u64, 4), p.htlc_minimum_msat);
    try testing.expectEqual(@as(u64, 5), p.htlc_maximum_msat);
    try testing.expectEqual(@as(usize, 0), p.features.len);

    const big = try a.alloc(u8, 65536);
    defer a.free(big);
    @memset(big, 0x01);
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(a);
    try blinded.appendPayInfo(a, &out2, .{ .fee_base_msat = 0, .fee_proportional_millionths = 0, .cltv_expiry_delta = 0, .htlc_minimum_msat = 0, .htlc_maximum_msat = 0, .features = big[0..65535] });
    var it2: blinded.PayInfoIterator = .{ .bytes = out2.items };
    try testing.expectEqual(@as(usize, 65535), (try it2.next()).?.features.len);
    var out3: std.ArrayList(u8) = .empty;
    defer out3.deinit(a);
    try testing.expectError(error.FieldTooLong, blinded.appendPayInfo(a, &out3, .{ .fee_base_msat = 0, .fee_proportional_millionths = 0, .cltv_expiry_delta = 0, .htlc_minimum_msat = 0, .htlc_maximum_msat = 0, .features = big }));
}

test "mutation 2026-11-27: offer: TLV type ranges 1..79 and 1000000000..1999999999 (reader rule)" {
    const a = testing.allocator;
    const id33: [33]u8 = good33;
    const Case = struct { first: u64, ok: bool };
    // `first` is a record placed before / after offer_issuer_id (22) so the stream stays ascending.
    const before = [_]Case{ .{ .first = 0, .ok = false }, .{ .first = 1, .ok = true } };
    for (before) |c| {
        const s = try lnoOf(a, &.{ .{ .type = c.first, .value = "x" }, .{ .type = 22, .value = &id33 } });
        defer a.free(s);
        if (c.ok) {
            var o = try offer_mod.readOffer(a, s, .{});
            o.deinit(a);
        } else {
            try testing.expectError(error.FieldOutOfRange, offer_mod.readOffer(a, s, .{}));
        }
    }
    const after = [_]Case{
        .{ .first = 79, .ok = true },
        .{ .first = 80, .ok = false },
        .{ .first = 81, .ok = false },
        .{ .first = 999_999_999, .ok = false },
        .{ .first = 1_000_000_001, .ok = true },
        .{ .first = 1_999_999_999, .ok = true },
        .{ .first = 2_000_000_000, .ok = false },
    };
    for (after) |c| {
        const s = try lnoOf(a, &.{ .{ .type = 22, .value = &id33 }, .{ .type = c.first, .value = "x" } });
        defer a.free(s);
        if (c.ok) {
            var o = try offer_mod.readOffer(a, s, .{});
            o.deinit(a);
        } else {
            try testing.expectError(error.FieldOutOfRange, offer_mod.readOffer(a, s, .{}));
        }
    }
}

test "mutation 2026-11-27: offer: an empty offer_paths record is not a path; empty features are legal; a 03-prefixed issuer id is legal" {
    const a = testing.allocator;
    const id33: [33]u8 = good33;
    {
        const s = try lnoOf(a, &.{ .{ .type = 16, .value = &.{} }, .{ .type = 22, .value = &id33 } });
        defer a.free(s);
        try testing.expectError(error.InvalidPaths, offer_mod.readOffer(a, s, .{}));
    }
    // A features bitfield of zero length: no feature bits, minimal.
    {
        const s = try offer_mod.encodeOffer(a, .{ .features = &.{}, .issuer_id = id33 });
        defer a.free(s);
        var o = try offer_mod.readOffer(a, s, .{});
        defer o.deinit(a);
        try testing.expectEqual(@as(usize, 0), o.features.?.len);
    }
    {
        var o = try bolt12.decodeOffer(a, "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese");
        defer o.deinit(a);
        var empty: [0]u8 = .{};
        o.features = &empty;
        try offer_mod.checkOffer(o, .{});
        o.features = null;
    }
    // The compressed prefix is 02 or 03: the same x with the odd-y prefix is a valid issuer id.
    var odd = id33;
    odd[0] = 3;
    const s = try offer_mod.encodeOffer(a, .{ .issuer_id = odd });
    defer a.free(s);
    var o = try offer_mod.readOffer(a, s, .{});
    defer o.deinit(a);
    try testing.expectEqualSlices(u8, &odd, &o.issuer_id.?);
}

test "mutation 2026-11-27: offer builder: utf8 of issuer and currency, an empty paths value is no path" {
    const a = testing.allocator;
    const id33: [33]u8 = good33;
    try testing.expectError(error.InvalidUtf8, offer_mod.encodeOffer(a, .{ .issuer = "\xff", .issuer_id = id33 }));
    try testing.expectError(error.InvalidUtf8, offer_mod.encodeOffer(a, .{ .currency = "\xff\xff\xff", .amount = 1, .description = "x", .issuer_id = id33 }));
    try testing.expectError(error.NoIssuerIdOrPaths, offer_mod.encodeOffer(a, .{ .paths = &.{} }));
    // FIX 2026-11-27: an empty `paths` value with an issuer id is "no paths": no empty type-16 record is written,
    // so the offer reads back (the reader refuses an empty offer_paths record).
    const s = try offer_mod.encodeOffer(a, .{ .paths = &.{}, .issuer_id = id33 });
    defer a.free(s);
    var o = try offer_mod.readOffer(a, s, .{});
    defer o.deinit(a);
    try testing.expectEqual(@as(usize, 0), o.paths.len);
    try testing.expectEqualSlices(u8, &id33, &o.issuer_id.?);
}

fn blankRequest(raw: []u8) bolt12.InvoiceRequest {
    return .{
        .raw = raw,
        .invreq_metadata = null,
        .offer_currency = null,
        .offer_amount = null,
        .offer_description = null,
        .offer_issuer_id = null,
        .invreq_chain = null,
        .invreq_amount = null,
        .invreq_quantity = null,
        .invreq_payer_id = null,
        .invreq_payer_note = null,
        .signature = null,
    };
}

test "mutation 2026-11-27: typed accessors: Offer.blindedPaths, InvoiceRequest.blindedPaths (type 90), InvoiceRequest.record knows only request types" {
    const a = testing.allocator;
    var paths: std.ArrayList(u8) = .empty;
    defer paths.deinit(a);
    try blinded.appendPath(a, &paths, .{ .node_id = good33 }, good33, &.{.{ .blinded_node_id = good33, .encrypted_recipient_data = &.{7} }});

    const s = try offer_mod.encodeOffer(a, .{ .paths = paths.items });
    defer a.free(s);
    var o = try bolt12.decodeOffer(a, s);
    defer o.deinit(a);
    try testing.expectEqual(@as(usize, 1), try o.blindedPaths().count());
    var none = try bolt12.decodeOffer(a, "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese");
    defer none.deinit(a);
    try testing.expectEqual(@as(usize, 0), try none.blindedPaths().count());

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(a);
    try lnwire.tlv.appendStream(&stream, a, &.{.{ .type = 90, .value = paths.items }});
    const ir = blankRequest(stream.items);
    try testing.expectEqual(@as(usize, 1), try (try ir.blindedPaths(a)).count());
    try testing.expectEqualSlices(u8, paths.items, (try ir.record(a, 90)).?);

    // Type 164 (invoice_created_at) is an unknown even type in an invoice_request (BOLT#12: request types are
    // 0, 80..159 and the offer's; 160..239 belong to the invoice): the stream is refused.
    var stream2: std.ArrayList(u8) = .empty;
    defer stream2.deinit(a);
    try lnwire.tlv.appendStream(&stream2, a, &.{.{ .type = 164, .value = &.{ 0, 0, 0, 1 } }});
    const ir2 = blankRequest(stream2.items);
    try testing.expectError(error.UnknownEvenType, ir2.record(a, 164));
}

test "mutation 2026-11-27: invoice_request check: one-sided issuer id and currency, chain list, quantity at the maximum, amount overflow" {
    var desc = "coffee".*;
    var cur = "USD".*;
    var chains = [_][32]u8{ @splat(0x11), @splat(0x22) };
    var offer: offer_mod.Offer = .{
        .chains = &.{},
        .metadata = null,
        .currency = null,
        .amount = 1000,
        .description = &desc,
        .features = null,
        .absolute_expiry = null,
        .paths = &.{},
        .issuer = null,
        .quantity_max = null,
        .issuer_id = null,
    };
    var ir = blankRequest(&.{});
    ir.offer_amount = 1000;
    ir.offer_description = &desc;
    try offer_mod.checkInvoiceRequest(offer, ir, .{});
    // The request names an issuer the offer does not have, and the other way round.
    ir.offer_issuer_id = good33;
    try testing.expectError(error.OfferMismatch, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    ir.offer_issuer_id = null;
    offer.issuer_id = good33;
    try testing.expectError(error.OfferMismatch, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    offer.issuer_id = null;
    // A currency on one side only.
    offer.currency = &cur;
    try testing.expectError(error.OfferMismatch, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    offer.currency = null;
    ir.offer_currency = &cur;
    try testing.expectError(error.OfferMismatch, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    ir.offer_currency = null;
    // A description on one side only.
    ir.offer_description = null;
    try testing.expectError(error.OfferMismatch, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    ir.offer_description = &desc;
    // offer_chains lists two chains: either is accepted, a third is not.
    offer.chains = &chains;
    ir.invreq_chain = chains[0];
    try offer_mod.checkInvoiceRequest(offer, ir, .{});
    ir.invreq_chain = chains[1];
    try offer_mod.checkInvoiceRequest(offer, ir, .{});
    ir.invreq_chain = @as([32]u8, @splat(0x33));
    try testing.expectError(error.ChainNotOffered, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_chain = null;
    offer.chains = &.{};
    // A quantity equal to offer_quantity_max is allowed.
    offer.quantity_max = 5;
    ir.invreq_quantity = 5;
    try offer_mod.checkInvoiceRequest(offer, ir, .{});
    ir.invreq_quantity = 6;
    try testing.expectError(error.QuantityOutOfRange, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    // offer_amount x quantity beyond u64 is above any invreq_amount.
    offer.amount = @as(u64, 1) << 63;
    ir.offer_amount = offer.amount;
    offer.quantity_max = 0;
    ir.invreq_quantity = 4;
    ir.invreq_amount = std.math.maxInt(u64);
    try testing.expectError(error.AmountTooLow, offer_mod.checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_quantity = 1;
    try offer_mod.checkInvoiceRequest(offer, ir, .{});
}
