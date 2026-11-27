// SPDX-License-Identifier: MIT
//! BOLT#12 offers: the reader's rules and an offer builder. `bolt12.decodeOffer`
//! decodes the wire form; `checkOffer` / `readOffer` apply BOLT#12 "Requirements
//! For Offers" ("A reader of an offer"), and `encodeOffer` builds an unsigned
//! `lno1...` offer from typed fields, refusing what the "writer of an offer" rules
//! forbid.
//!
//! The reader rules checked here: fields outside 1..79 / 1000000000..1999999999,
//! unknown even feature bits and non-minimal `offer_features`, `offer_description` /
//! `offer_issuer` / `offer_currency` that are not UTF-8, an amount without a
//! description, a zero amount, a currency without an amount, neither `offer_issuer_id`
//! nor `offer_paths`, a malformed or zero-hop blinded path, an `offer_issuer_id`
//! that is not a curve point, and (when given a clock) an expired offer. Not checked:
//! the chains the node accepts (the caller knows them) and BOLT#1's "Other" /
//! Zl / Zp character categories (only well-formed UTF-8 is required here).

const std = @import("std");
const Allocator = std.mem.Allocator;
const lnwire = @import("lnwire");
const bip340 = @import("bip340");
const bech32raw = @import("bech32_raw.zig");
const bitpack = @import("bitpack.zig");
const bolt12 = @import("bolt12.zig");
const blinded = @import("blinded.zig");

pub const RuleError = error{
    /// A TLV field outside 1..79 and 1000000000..1999999999.
    FieldOutOfRange,
    /// `offer_description`, `offer_issuer` or `offer_currency` is not well-formed UTF-8.
    InvalidUtf8,
    /// `offer_features` sets an even bit the caller does not know.
    UnknownEvenFeature,
    /// `offer_features` has a leading zero octet.
    FeaturesNotMinimal,
    /// `offer_amount` without `offer_description`.
    MissingDescription,
    /// `offer_amount` of zero.
    ZeroAmount,
    /// `offer_currency` without `offer_amount`.
    CurrencyWithoutAmount,
    /// Neither `offer_issuer_id` nor `offer_paths`.
    NoIssuerIdOrPaths,
    /// A malformed `blinded_path` in `offer_paths` (truncated, bad point, no hops).
    InvalidPaths,
    /// `offer_issuer_id` is not a valid compressed point.
    InvalidIssuerId,
    /// `now` is after `offer_absolute_expiry`.
    Expired,
};

pub const ReadOptions = struct {
    /// Feature bits the node understands (either bit of a pair), for the unknown-even-bit rule.
    known_features: []const u16 = &.{},
    /// The current time in seconds since the epoch; when set, an expired offer is refused.
    now: ?u64 = null,
};

fn validPoint(p: *const [33]u8) bool {
    if (p[0] != 2 and p[0] != 3) return false;
    _ = bip340.XOnlyPublicKey.fromBytes(p[1..33].*) catch return false;
    return true;
}

fn utf8Ok(s: ?[]const u8) bool {
    const v = s orelse return true;
    return std.unicode.utf8ValidateSlice(v);
}

/// The reader rules over a decoded offer (see the module doc).
pub fn checkOffer(offer: bolt12.Offer, opts: ReadOptions) RuleError!void {
    if (offer.features) |f| {
        if (f.len > 0 and f[0] == 0) return error.FeaturesNotMinimal;
        if (lnwire.features.firstUnknownEvenBit(f, opts.known_features) != null) return error.UnknownEvenFeature;
    }
    if (!utf8Ok(offer.description) or !utf8Ok(offer.issuer) or !utf8Ok(offer.currency)) return error.InvalidUtf8;
    if (offer.amount != null and offer.description == null) return error.MissingDescription;
    if (offer.amount) |a| if (a == 0) return error.ZeroAmount;
    if (offer.currency != null and offer.amount == null) return error.CurrencyWithoutAmount;
    if (offer.issuer_id == null and offer.paths.len == 0) return error.NoIssuerIdOrPaths;
    for (offer.paths) |value| {
        var it: blinded.PathIterator = .{ .bytes = value };
        _ = it.count() catch return error.InvalidPaths;
        // BOLT#12 "Second offer_path is empty": an empty array element is not a path.
        if (value.len == 0) return error.InvalidPaths;
    }
    if (offer.issuer_id) |*id| if (!validPoint(id)) return error.InvalidIssuerId;
    if (opts.now) |now| if (offer.absolute_expiry) |exp| if (now > exp) return error.Expired;
}

pub const ReadError = bolt12.DecodeError || RuleError;

/// Decodes an `lno1...` string and applies the reader rules, including the TLV type ranges
/// (which `decodeOffer` cannot see: it drops unknown odd records).
pub fn readOffer(allocator: Allocator, offer_str: []const u8, opts: ReadOptions) ReadError!Offer {
    {
        const stripped = try bech32raw.stripContinuation(allocator, offer_str);
        defer allocator.free(stripped);
        var raw = try bech32raw.decodeNoChecksum(allocator, stripped);
        defer raw.deinit(allocator);
        const bytes = try bitpack.quintetsToBytesMinimal(allocator, raw.data);
        defer allocator.free(bytes);
        var pos: usize = 0;
        while (pos < bytes.len) {
            const t = try lnwire.tlv.decodeBigSize(bytes[pos..]);
            pos += t.consumed;
            const l = try lnwire.tlv.decodeBigSize(bytes[pos..]);
            pos += l.consumed;
            if (l.value > bytes.len - pos) return error.Truncated;
            pos += @intCast(l.value);
            const in_range = (t.value >= 1 and t.value <= 79) or (t.value >= 1_000_000_000 and t.value <= 1_999_999_999);
            if (!in_range) return error.FieldOutOfRange;
        }
    }
    var offer = try bolt12.decodeOffer(allocator, offer_str);
    errdefer offer.deinit(allocator);
    try checkOffer(offer, opts);
    return offer;
}

pub const Offer = bolt12.Offer;

// ── an invoice_request against its offer ────────────────────────────────

pub const RequestError = error{
    /// The offer fields the request carries are not the offer's.
    OfferMismatch,
    /// `invreq_chain` (or bitcoin, when absent) is not a chain the offer is valid for.
    ChainNotOffered,
    /// The offer sets `offer_quantity_max` but the request has no `invreq_quantity`.
    QuantityMissing,
    /// The offer has no `offer_quantity_max` but the request has an `invreq_quantity`.
    QuantityNotAllowed,
    /// `invreq_quantity` is zero or above a non-zero `offer_quantity_max`.
    QuantityOutOfRange,
    /// The offer has no amount and the request no `invreq_amount`.
    AmountMissing,
    /// `invreq_amount` is below the expected amount (offer amount times quantity).
    AmountTooLow,
    /// The offer is priced in a currency: pass the per-item amount in msat as `unit_msat`.
    NeedsCurrencyConversion,
    OfferExpired,
};

pub const RequestOptions = struct {
    now: ?u64 = null,
    /// The bitcoin mainnet `chain_hash` in wire byte order, the default chain when `invreq_chain` is absent;
    /// pass the chain the node serves (the genesis hash of the network).
    default_chain: [32]u8 = .{ 0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /// Per-item amount in msat of an offer that is priced in `offer_currency`, converted by the caller.
    unit_msat: ?u64 = null,
};

fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

/// BOLT#12 "A reader of an invoice_request" for a request that answers one of our offers: the offer fields
/// the request copies must be the offer's, the chain must be offered, the quantity must fit
/// `offer_quantity_max`, `invreq_amount` must reach the expected amount (and is required when the offer has
/// no amount), and the offer must not have expired. Signature and feature checks are the caller's
/// (`InvoiceRequest.verify`).
pub fn checkInvoiceRequest(offer: Offer, ir: bolt12.InvoiceRequest, opts: RequestOptions) RequestError!void {
    if (ir.offer_issuer_id != null or offer.issuer_id != null) {
        const same_id = (ir.offer_issuer_id == null and offer.issuer_id == null) or
            (ir.offer_issuer_id != null and offer.issuer_id != null and std.mem.eql(u8, &ir.offer_issuer_id.?, &offer.issuer_id.?));
        if (!same_id) return error.OfferMismatch;
    }
    if (ir.offer_amount != offer.amount or !optEql(ir.offer_currency, offer.currency) or !optEql(ir.offer_description, offer.description))
        return error.OfferMismatch;

    if (opts.now) |now| if (offer.absolute_expiry) |exp| if (now > exp) return error.OfferExpired;

    const chain = ir.invreq_chain orelse opts.default_chain;
    if (offer.chains.len == 0) {
        if (!std.mem.eql(u8, &chain, &opts.default_chain)) return error.ChainNotOffered;
    } else {
        var found = false;
        for (offer.chains) |c| found = found or std.mem.eql(u8, &c, &chain);
        if (!found) return error.ChainNotOffered;
    }

    if (offer.quantity_max) |max| {
        const q = ir.invreq_quantity orelse return error.QuantityMissing;
        if (max != 0 and (q == 0 or q > max)) return error.QuantityOutOfRange;
    } else if (ir.invreq_quantity != null) return error.QuantityNotAllowed;

    if (offer.amount) |amount| {
        if (ir.invreq_amount) |paid| {
            const unit: u64 = if (offer.currency != null) (opts.unit_msat orelse return error.NeedsCurrencyConversion) else amount;
            const expected = std.math.mul(u64, unit, ir.invreq_quantity orelse 1) catch return error.AmountTooLow;
            if (paid < expected) return error.AmountTooLow;
        }
    } else if (ir.invreq_amount == null) return error.AmountMissing;
}

// ── builder ─────────────────────────────────────────────────────────────

pub const OfferFields = struct {
    /// Chains the offer is valid for; empty omits `offer_chains` (bitcoin only).
    chains: []const [32]u8 = &.{},
    metadata: ?[]const u8 = null,
    /// ISO 4217 code; needs `amount`.
    currency: ?[]const u8 = null,
    /// Per-item amount: msat, or `currency` units; greater than zero; needs `description`.
    amount: ?u64 = null,
    description: ?[]const u8 = null,
    /// BOLT#9 bytes, minimally encoded.
    features: ?[]const u8 = null,
    absolute_expiry: ?u64 = null,
    /// The VALUE of `offer_paths`: concatenated `blinded_path`s (see `blinded.appendPath`).
    paths: ?[]const u8 = null,
    issuer: ?[]const u8 = null,
    /// 0 means "more than one, no known maximum"; null omits the field.
    quantity_max: ?u64 = null,
    issuer_id: ?[33]u8 = null,
};

pub const BuildError = RuleError || bech32raw.EncodeError || Allocator.Error;

/// Builds an `lno1...` offer (no checksum, lowercase) from `f`, in ascending TLV order. The writer rules
/// of BOLT#12 are enforced with the same errors the reader rules use; `known_features` is not consulted
/// (a writer may set any bit).
pub fn encodeOffer(allocator: Allocator, f: OfferFields) BuildError![]u8 {
    if (f.features) |ft| if (ft.len > 0 and ft[0] == 0) return error.FeaturesNotMinimal;
    if (!utf8Ok(f.description) or !utf8Ok(f.issuer) or !utf8Ok(f.currency)) return error.InvalidUtf8;
    if (f.amount != null and f.description == null) return error.MissingDescription;
    if (f.amount) |a| if (a == 0) return error.ZeroAmount;
    if (f.currency != null and f.amount == null) return error.CurrencyWithoutAmount;
    const has_paths = if (f.paths) |p| p.len > 0 else false;
    if (f.issuer_id == null and !has_paths) return error.NoIssuerIdOrPaths;
    if (f.paths) |p| {
        var it: blinded.PathIterator = .{ .bytes = p };
        _ = it.count() catch return error.InvalidPaths;
    }
    if (f.issuer_id) |*id| if (!validPoint(id)) return error.InvalidIssuerId;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var records: std.ArrayList(lnwire.RawRecord) = .empty;
    if (f.chains.len > 0) {
        const buf = try arena.alloc(u8, f.chains.len * 32);
        for (f.chains, 0..) |c, i| @memcpy(buf[i * 32 ..][0..32], &c);
        try records.append(arena, .{ .type = 2, .value = buf });
    }
    if (f.metadata) |m| try records.append(arena, .{ .type = 4, .value = m });
    if (f.currency) |c| try records.append(arena, .{ .type = 6, .value = c });
    if (f.amount) |a| try records.append(arena, .{ .type = 8, .value = try truncated(arena, a) });
    if (f.description) |d| try records.append(arena, .{ .type = 10, .value = d });
    if (f.features) |ft| try records.append(arena, .{ .type = 12, .value = ft });
    if (f.absolute_expiry) |e| try records.append(arena, .{ .type = 14, .value = try truncated(arena, e) });
    if (f.paths) |p| if (p.len > 0) try records.append(arena, .{ .type = 16, .value = p });
    if (f.issuer) |i| try records.append(arena, .{ .type = 18, .value = i });
    if (f.quantity_max) |q| try records.append(arena, .{ .type = 20, .value = try truncated(arena, q) });
    if (f.issuer_id) |*id| try records.append(arena, .{ .type = 22, .value = id });

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try lnwire.tlv.appendStream(&stream, allocator, records.items);
    const quintets = try bitpack.bytesToQuintets(allocator, stream.items);
    defer allocator.free(quintets);
    return bech32raw.encodeNoChecksum(allocator, "lno", quintets);
}

fn truncated(arena: Allocator, v: u64) Allocator.Error![]u8 {
    var tmp: [8]u8 = undefined;
    const enc = lnwire.tlv.encodeTruncated(u64, v, &tmp) catch unreachable; // 8 bytes always fit a u64
    return arena.dupe(u8, enc);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("bolt12_offers_kat_vectors.zig");

test "offers-test.json: every row is read as the file says (valid rows pass the reader rules, the others fail)" {
    const a = testing.allocator;
    var valid: usize = 0;
    var invalid: usize = 0;
    for (kat.vectors) |v| {
        // "with feature" sets feature bits whose even half this node is told it knows.
        const opts: ReadOptions = .{ .known_features = &.{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64 } };
        if (readOffer(a, v.bolt12, opts)) |ok| {
            var o = ok;
            o.deinit(a);
            if (!v.valid) {
                std.debug.print("offer row accepted but invalid: {s}\n", .{v.description});
                return error.TestUnexpectedSuccess;
            }
            valid += 1;
        } else |err| {
            if (v.valid) {
                std.debug.print("offer row rejected ({s}) but valid: {s}\n", .{ @errorName(err), v.description });
                return err;
            }
            invalid += 1;
        }
    }
    try testing.expectEqual(@as(usize, 20), valid);
    try testing.expectEqual(@as(usize, 33), invalid);
}

test "unknown even feature bit and a non-minimal features field" {
    const a = testing.allocator;
    var o = try bolt12.decodeOffer(a, "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese");
    defer o.deinit(a);
    try checkOffer(o, .{});
    const bad_even = try a.dupe(u8, &.{ 0x04, 0x00 }); // bit 10 is even
    o.features = bad_even;
    defer a.free(bad_even);
    try testing.expectError(error.UnknownEvenFeature, checkOffer(o, .{}));
    try checkOffer(o, .{ .known_features = &.{10} });
    var odd = [_]u8{ 0x08, 0x00 }; // bit 11 is odd: ignored
    o.features = &odd;
    try checkOffer(o, .{});
    var lead = [_]u8{ 0x00, 0x01 };
    o.features = &lead;
    try testing.expectError(error.FeaturesNotMinimal, checkOffer(o, .{}));
    o.features = null;
    o.absolute_expiry = 1000;
    try checkOffer(o, .{ .now = 1000 });
    try testing.expectError(error.Expired, checkOffer(o, .{ .now = 1001 }));
    try checkOffer(o, .{});
    o.absolute_expiry = null;
}

test "builder reproduces every offers-test.json valid row that carries only known fields, byte for byte" {
    const a = testing.allocator;
    var built: usize = 0;
    for (kat.vectors) |v| {
        if (!v.valid) continue;
        var all_known = true;
        for (v.fields) |f| {
            if (!(f.type >= 2 and f.type <= 22 and f.type % 2 == 0)) all_known = false;
        }
        if (!all_known) continue;
        var o = try bolt12.decodeOffer(a, v.bolt12);
        defer o.deinit(a);
        const f: OfferFields = .{
            .chains = o.chains,
            .metadata = o.metadata,
            .currency = o.currency,
            .amount = o.amount,
            .description = o.description,
            .features = o.features,
            .absolute_expiry = o.absolute_expiry,
            .paths = if (o.paths.len > 0) o.paths[0] else null,
            .issuer = o.issuer,
            .quantity_max = o.quantity_max,
            .issuer_id = o.issuer_id,
        };
        const got = encodeOffer(a, f) catch |err| {
            std.debug.print("builder refused row {s}: {s}\n", .{ v.description, @errorName(err) });
            return err;
        };
        defer a.free(got);
        try testing.expectEqualStrings(v.bolt12, got);
        built += 1;
    }
    try testing.expect(built >= 18);
}

test "builder refuses what the writer rules forbid, and its output reads back" {
    const a = testing.allocator;
    const id: [33]u8 = @splat(2);
    try testing.expectError(error.NoIssuerIdOrPaths, encodeOffer(a, .{ .description = "x" }));
    try testing.expectError(error.MissingDescription, encodeOffer(a, .{ .amount = 5, .issuer_id = id }));
    try testing.expectError(error.ZeroAmount, encodeOffer(a, .{ .amount = 0, .description = "x", .issuer_id = id }));
    try testing.expectError(error.CurrencyWithoutAmount, encodeOffer(a, .{ .currency = "USD", .issuer_id = id }));
    try testing.expectError(error.InvalidUtf8, encodeOffer(a, .{ .description = "\xff", .issuer_id = id }));
    try testing.expectError(error.FeaturesNotMinimal, encodeOffer(a, .{ .features = &.{ 0, 1 }, .issuer_id = id }));
    try testing.expectError(error.InvalidIssuerId, encodeOffer(a, .{ .issuer_id = @as([33]u8, @splat(3)) }));
    try testing.expectError(error.InvalidPaths, encodeOffer(a, .{ .paths = &.{ 1, 2, 3 } }));

    var paths: std.ArrayList(u8) = .empty;
    defer paths.deinit(a);
    try blinded.appendPath(a, &paths, .{ .node_id = id }, id, &.{.{ .blinded_node_id = id, .encrypted_recipient_data = &.{ 9, 9 } }});
    const s = try encodeOffer(a, .{
        .currency = "USD",
        .amount = 1500,
        .description = "coffee",
        .absolute_expiry = 4102444800,
        .paths = paths.items,
        .issuer = "shop@example.com",
        .quantity_max = 0,
        .metadata = &.{ 1, 2 },
        .chains = &.{@as([32]u8, @splat(0x11))},
    });
    defer a.free(s);
    var o = try readOffer(a, s, .{ .now = 1_700_000_000 });
    defer o.deinit(a);
    try testing.expectEqualStrings("USD", o.currency.?);
    try testing.expectEqual(@as(u64, 1500), o.amount.?);
    try testing.expectEqual(@as(u64, 0), o.quantity_max.?);
    try testing.expectEqual(@as(usize, 1), o.chains.len);
    var it: blinded.PathIterator = .{ .bytes = o.paths[0] };
    try testing.expectEqual(@as(usize, 1), try it.count());
}

fn testRequest(offer: Offer) bolt12.InvoiceRequest {
    return .{
        .raw = &.{},
        .invreq_metadata = null,
        .offer_currency = offer.currency,
        .offer_amount = offer.amount,
        .offer_description = offer.description,
        .offer_issuer_id = offer.issuer_id,
        .invreq_chain = null,
        .invreq_amount = null,
        .invreq_quantity = null,
        .invreq_payer_id = null,
        .invreq_payer_note = null,
        .signature = null,
    };
}

test "invoice_request against its offer: quantity, amount, chain, expiry, copied fields" {
    const id: [33]u8 = @splat(2);
    var chains = [_][32]u8{@splat(0x11)};
    var desc = "coffee".*;
    var offer: Offer = .{
        .chains = &.{},
        .metadata = null,
        .currency = null,
        .amount = 1000,
        .description = &desc,
        .features = null,
        .absolute_expiry = 5000,
        .paths = &.{},
        .issuer = null,
        .quantity_max = 5,
        .issuer_id = id,
    };
    var ir = testRequest(offer);
    try testing.expectError(error.QuantityMissing, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_quantity = 0;
    try testing.expectError(error.QuantityOutOfRange, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_quantity = 6;
    try testing.expectError(error.QuantityOutOfRange, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_quantity = 3;
    try checkInvoiceRequest(offer, ir, .{}); // no invreq_amount: the offer's price applies
    ir.invreq_amount = 2999;
    try testing.expectError(error.AmountTooLow, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_amount = 3000;
    try checkInvoiceRequest(offer, ir, .{ .now = 5000 });
    try testing.expectError(error.OfferExpired, checkInvoiceRequest(offer, ir, .{ .now = 5001 }));
    // unlimited quantity (0): any positive quantity
    offer.quantity_max = 0;
    ir.invreq_quantity = 1_000_000;
    ir.invreq_amount = null;
    try checkInvoiceRequest(offer, ir, .{});
    // no quantity_max: a quantity is refused
    offer.quantity_max = null;
    try testing.expectError(error.QuantityNotAllowed, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_quantity = null;
    try checkInvoiceRequest(offer, ir, .{});
    // copied fields must be the offer's
    var other = ir;
    other.offer_amount = 999;
    try testing.expectError(error.OfferMismatch, checkInvoiceRequest(offer, other, .{}));
    other = ir;
    other.offer_issuer_id = @as([33]u8, @splat(3));
    try testing.expectError(error.OfferMismatch, checkInvoiceRequest(offer, other, .{}));
    other = ir;
    other.offer_description = "tea";
    try testing.expectError(error.OfferMismatch, checkInvoiceRequest(offer, other, .{}));
    // chains: default bitcoin only unless the offer lists others
    ir.invreq_chain = chains[0];
    try testing.expectError(error.ChainNotOffered, checkInvoiceRequest(offer, ir, .{}));
    offer.chains = &chains;
    try checkInvoiceRequest(offer, ir, .{});
    ir.invreq_chain = null;
    try testing.expectError(error.ChainNotOffered, checkInvoiceRequest(offer, ir, .{}));
    // no offer amount: invreq_amount is required; a currency-priced offer needs the converted unit
    offer.chains = &.{};
    offer.amount = null;
    ir.offer_amount = null;
    try testing.expectError(error.AmountMissing, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_amount = 1;
    try checkInvoiceRequest(offer, ir, .{});
    var cur = "USD".*;
    offer.amount = 150;
    offer.currency = &cur;
    ir.offer_amount = 150;
    ir.offer_currency = &cur;
    try testing.expectError(error.NeedsCurrencyConversion, checkInvoiceRequest(offer, ir, .{}));
    ir.invreq_amount = 100_000;
    try checkInvoiceRequest(offer, ir, .{ .unit_msat = 100_000 });
    try testing.expectError(error.AmountTooLow, checkInvoiceRequest(offer, ir, .{ .unit_msat = 100_001 }));
}

test "invoice: typed invoice_paths and invoice_blindedpay of a signed invoice, one payinfo per path" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sk = try bip340.SecretKey.fromBytes(@as([32]u8, @splat(0x33)));
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &sk);
    var node_id: [33]u8 = undefined;
    node_id[0] = 0x02;
    node_id[1..33].* = kp.public.x;

    const k: [33]u8 = @splat(2);
    var paths: std.ArrayList(u8) = .empty;
    defer paths.deinit(a);
    try blinded.appendPath(a, &paths, .{ .node_id = k }, k, &.{.{ .blinded_node_id = k, .encrypted_recipient_data = &.{ 1, 2 } }});
    try blinded.appendPath(a, &paths, .{ .scid = .{ .direction = 0, .short_channel_id = 42 } }, k, &.{ .{ .blinded_node_id = k, .encrypted_recipient_data = &.{} }, .{ .blinded_node_id = k, .encrypted_recipient_data = &.{9} } });
    var pay: std.ArrayList(u8) = .empty;
    defer pay.deinit(a);
    try blinded.appendPayInfo(a, &pay, .{ .fee_base_msat = 1000, .fee_proportional_millionths = 100, .cltv_expiry_delta = 144, .htlc_minimum_msat = 1, .htlc_maximum_msat = 1_000_000, .features = &.{} });
    try blinded.appendPayInfo(a, &pay, .{ .fee_base_msat = 5, .fee_proportional_millionths = 6, .cltv_expiry_delta = 40, .htlc_minimum_msat = 2, .htlc_maximum_msat = 3, .features = &.{0x01} });

    const payment_hash: [32]u8 = @splat(0xcd);
    const records = [_]lnwire.RawRecord{
        .{ .type = 160, .value = paths.items },
        .{ .type = 162, .value = pay.items },
        .{ .type = 164, .value = &.{ 0x66, 0x00, 0x00, 0x00 } },
        .{ .type = 168, .value = &payment_hash },
        .{ .type = 170, .value = &.{ 0x27, 0x10 } },
        .{ .type = 176, .value = &node_id },
    };
    const lni = try bolt12.encodeSignedInvoice(a, &records, &sk, @as([32]u8, @splat(0)), io);
    defer a.free(lni);
    var inv = try bolt12.decodeInvoice(a, lni);
    defer inv.deinit(a);
    try testing.expect(try inv.verify(a));
    const it = try inv.blindedPaths(a);
    try testing.expectEqual(@as(usize, 2), try it.count());
    const pit = try inv.blindedPayInfo(a);
    try testing.expectEqual(@as(usize, 2), try pit.count());
    var p = pit;
    try testing.expectEqual(@as(u16, 144), (try p.next()).?.cltv_expiry_delta);
    try testing.expectEqualSlices(u8, &.{0x01}, (try p.next()).?.features);
}
