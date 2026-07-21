// SPDX-License-Identifier: MIT
//! BOLT#12 offers — the `lno1...` bech32-*style* (no checksum) TLV-encoded
//! payment offer, precursor to an `invoice_request`/`invoice` exchange.
//! **Scope: offer PARSE only** (see the module-level rationale below for
//! why `invoice_request`/`invoice` are deferred rather than implemented
//! here — also documented in `../SPEC.md`).
//!
//! Encoding (BOLT#12 "Encoding"): human-readable prefix `lno`, `1`
//! separator, then the raw `offer` TLV stream's bytes bit-packed 5 bits at
//! a time (`bitpack.bytesToQuintets`/`quintetsToBytesStrict` — the same
//! MSB-first packing BOLT#11 uses, just over a whole TLV blob instead of
//! per-field values) — **no checksum** ("There is no checksum, unlike
//! bech32m"), and a `+` (optionally followed by whitespace) may split the
//! string across limited-length text fields; both are handled by
//! `bech32_raw.decodeNoChecksum`/`stripContinuation`.
//!
//! ## Why `invoice_request`/`invoice` are deferred
//!
//! Offers themselves are an *unsigned* TLV stream (every top-level `offer`
//! type is even/informational, no signature field) — a clean, self-
//! contained parse. `invoice_request`/`invoice`, by contrast, are signed
//! with a BIP-340 Schnorr signature over a **Merkle root of the TLV
//! stream** (BOLT#12 "Signature Calculation": a BIP-341-style tree with a
//! nonce leaf paired to every data leaf, tag `H("LnLeaf", tlv)` /
//! `H("LnNonce"||first-tlv, tlv-type)` / `H("LnBranch", lesser||greater)`)
//! — a self-contained sub-algorithm as substantial as this module's own
//! BOLT#11 ECDSA-recovery core, plus `offer_paths`' `blinded_path` TLV
//! sub-structure (BOLT#4 route blinding, a distinct spec). Bundling either
//! into this pass would trade BOLT#11 depth (its official test vectors,
//! the recoverable-ECDSA core) for breadth; both remain a clean follow-on
//! module addition (the TLV plumbing below is already shared/reusable).

const std = @import("std");
const Allocator = std.mem.Allocator;
const lnwire = @import("lnwire");
const bech32raw = @import("bech32_raw.zig");
const bitpack = @import("bitpack.zig");

// ── `offer` TLV field types (BOLT#12 "TLV Fields for Offers") ────────────

const TYPE_CHAINS: u64 = 2;
const TYPE_METADATA: u64 = 4;
const TYPE_CURRENCY: u64 = 6;
const TYPE_AMOUNT: u64 = 8;
const TYPE_DESCRIPTION: u64 = 10;
const TYPE_FEATURES: u64 = 12;
const TYPE_ABSOLUTE_EXPIRY: u64 = 14;
const TYPE_PATHS: u64 = 16;
const TYPE_ISSUER: u64 = 18;
const TYPE_QUANTITY_MAX: u64 = 20;
const TYPE_ISSUER_ID: u64 = 22;

const known_offer_types = [_]u64{
    TYPE_CHAINS,      TYPE_METADATA,     TYPE_CURRENCY,        TYPE_AMOUNT,
    TYPE_DESCRIPTION, TYPE_FEATURES,     TYPE_ABSOLUTE_EXPIRY, TYPE_PATHS,
    TYPE_ISSUER,      TYPE_QUANTITY_MAX, TYPE_ISSUER_ID,
};

pub const Offer = struct {
    /// `offer_chains` — raw 32-byte chain hashes, undecoded count-prefix
    /// (just however many whole 32-byte hashes the TLV value contains).
    chains: [][32]u8,
    metadata: ?[]u8,
    /// `offer_currency` — ISO 4217 code, UTF-8 (ASCII in practice).
    currency: ?[]u8,
    /// `offer_amount` — a `tu64` (BOLT#1 truncated integer): the amount in
    /// `currency` if set, else millisatoshi.
    amount: ?u64,
    description: ?[]u8,
    features: ?[]u8,
    absolute_expiry: ?u64,
    /// `offer_paths` — raw, UNDECODED `blinded_path` TLV value bytes, one
    /// entry per path (BOLT#4 route-blinding structure — deferred, see
    /// module doc comment). Callers needing path routing must decode these
    /// themselves for now.
    paths: [][]u8,
    issuer: ?[]u8,
    quantity_max: ?u64,
    /// `offer_issuer_id` — 33-byte compressed SEC1 pubkey.
    issuer_id: ?[33]u8,

    pub fn deinit(self: *Offer, allocator: Allocator) void {
        allocator.free(self.chains);
        if (self.metadata) |m| allocator.free(m);
        if (self.currency) |c| allocator.free(c);
        if (self.description) |d| allocator.free(d);
        if (self.features) |f| allocator.free(f);
        for (self.paths) |p| allocator.free(p);
        allocator.free(self.paths);
        if (self.issuer) |i| allocator.free(i);
        self.* = undefined;
    }
};

pub const DecodeError = bech32raw.SplitError || error{InvalidDataChar} ||
    bitpack.PaddingError || lnwire.tlv.StreamError || Allocator.Error || error{
    UnknownPrefix,
    BadChainsLength,
    BadAmount,
    BadAbsoluteExpiry,
    BadQuantityMax,
    BadIssuerIdLength,
};

/// Decode (and TLV-validate) a BOLT#12 offer string. Does NOT verify any
/// signature (offers are unsigned — see module doc comment) and does NOT
/// interpret `offer_paths` beyond handing back its raw per-path bytes.
pub fn decodeOffer(allocator: Allocator, offer_str: []const u8) DecodeError!Offer {
    const stripped = try bech32raw.stripContinuation(allocator, offer_str);
    defer allocator.free(stripped);

    var raw = try bech32raw.decodeNoChecksum(allocator, stripped);
    defer raw.deinit(allocator);
    if (!std.mem.eql(u8, raw.hrp, "lno")) return error.UnknownPrefix;

    const bytes = try bitpack.quintetsToBytesStrict(allocator, raw.data);
    defer allocator.free(bytes);

    var parsed = try lnwire.parseTlvStream(allocator, bytes, &known_offer_types);
    defer parsed.deinit(allocator);

    var chains: std.ArrayList([32]u8) = .empty;
    errdefer chains.deinit(allocator);
    var paths: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    var metadata: ?[]u8 = null;
    var currency: ?[]u8 = null;
    var description: ?[]u8 = null;
    var features: ?[]u8 = null;
    var issuer: ?[]u8 = null;
    errdefer {
        if (metadata) |m| allocator.free(m);
        if (currency) |c| allocator.free(c);
        if (description) |d| allocator.free(d);
        if (features) |f| allocator.free(f);
        if (issuer) |i| allocator.free(i);
    }
    var amount: ?u64 = null;
    var absolute_expiry: ?u64 = null;
    var quantity_max: ?u64 = null;
    var issuer_id: ?[33]u8 = null;

    for (parsed.records) |rec| {
        switch (rec.type) {
            TYPE_CHAINS => {
                if (rec.value.len % 32 != 0) return error.BadChainsLength;
                var i: usize = 0;
                while (i < rec.value.len) : (i += 32) {
                    try chains.append(allocator, rec.value[i..][0..32].*);
                }
            },
            TYPE_METADATA => if (metadata == null) {
                metadata = try allocator.dupe(u8, rec.value);
            },
            TYPE_CURRENCY => if (currency == null) {
                currency = try allocator.dupe(u8, rec.value);
            },
            TYPE_AMOUNT => if (amount == null) {
                amount = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            TYPE_DESCRIPTION => if (description == null) {
                description = try allocator.dupe(u8, rec.value);
            },
            TYPE_FEATURES => if (features == null) {
                features = try allocator.dupe(u8, rec.value);
            },
            TYPE_ABSOLUTE_EXPIRY => if (absolute_expiry == null) {
                absolute_expiry = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAbsoluteExpiry;
            },
            TYPE_PATHS => {
                try paths.append(allocator, try allocator.dupe(u8, rec.value));
            },
            TYPE_ISSUER => if (issuer == null) {
                issuer = try allocator.dupe(u8, rec.value);
            },
            TYPE_QUANTITY_MAX => if (quantity_max == null) {
                quantity_max = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadQuantityMax;
            },
            TYPE_ISSUER_ID => if (issuer_id == null) {
                if (rec.value.len != 33) return error.BadIssuerIdLength;
                issuer_id = rec.value[0..33].*;
            },
            else => {},
        }
    }

    return .{
        .chains = try chains.toOwnedSlice(allocator),
        .metadata = metadata,
        .currency = currency,
        .amount = amount,
        .description = description,
        .features = features,
        .absolute_expiry = absolute_expiry,
        .paths = try paths.toOwnedSlice(allocator),
        .issuer = issuer,
        .quantity_max = quantity_max,
        .issuer_id = issuer_id,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexToBytes(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// Hand-built (not fetched from a spec vector -- BOLT#12's own JSON test
// vectors are invoice_request/invoice-oriented, out of this pass's scope)
// minimal offer: `offer_description` (type 10) + `offer_amount` (type 8,
// `tu64` truncated-integer per BOLT#1) + `offer_issuer_id` (type 22, a
// 33-byte compressed pubkey), encoded via `lnwire`'s own `appendStream` so
// the TLV bytes are independently constructed (not hand-typed hex),
// bit-packed via `bitpack.bytesToQuintets` the same way `decodeOffer`
// unpacks them, and bech32-charset-encoded with NO checksum appended.
test "offer: round-trip decode of a hand-built minimal offer" {
    const allocator = testing.allocator;
    const issuer_id = hexToBytes(33, "022d22e23f966681f976e5f2c5c4a2ac8e97a9d2df6a72f5a677bc57e69b56d2ea");

    var tlv_bytes: std.ArrayList(u8) = .empty;
    defer tlv_bytes.deinit(allocator);
    const records = [_]lnwire.RawRecord{
        .{ .type = TYPE_AMOUNT, .value = &.{ 0x27, 0x10 } }, // tu64 minimal(10000) = 0x2710
        .{ .type = TYPE_DESCRIPTION, .value = "a test offer" },
        .{ .type = TYPE_ISSUER_ID, .value = &issuer_id },
    };
    try lnwire.tlv.appendStream(&tlv_bytes, allocator, &records);

    const quintets = try bitpack.bytesToQuintets(allocator, tlv_bytes.items);
    defer allocator.free(quintets);
    const offer_str = try bech32raw.encodeNoChecksum(allocator, "lno", quintets);
    defer allocator.free(offer_str);
    try testing.expect(std.mem.startsWith(u8, offer_str, "lno1"));

    var offer = try decodeOffer(allocator, offer_str);
    defer offer.deinit(allocator);
    try testing.expectEqual(@as(?u64, 10000), offer.amount);
    try testing.expectEqualStrings("a test offer", offer.description.?);
    try testing.expectEqualSlices(u8, &issuer_id, &offer.issuer_id.?);
    try testing.expectEqual(@as(usize, 0), offer.chains.len);
    try testing.expectEqual(@as(usize, 0), offer.paths.len);
}

test "offer: '+' continuation markers are stripped before decode" {
    const allocator = testing.allocator;
    var tlv_bytes: std.ArrayList(u8) = .empty;
    defer tlv_bytes.deinit(allocator);
    const records = [_]lnwire.RawRecord{.{ .type = TYPE_DESCRIPTION, .value = "split across a tweet" }};
    try lnwire.tlv.appendStream(&tlv_bytes, allocator, &records);
    const quintets = try bitpack.bytesToQuintets(allocator, tlv_bytes.items);
    defer allocator.free(quintets);
    const whole = try bech32raw.encodeNoChecksum(allocator, "lno", quintets);
    defer allocator.free(whole);

    const mid = whole.len / 2;
    const split = try std.mem.concat(allocator, u8, &.{ whole[0..mid], "+\n", whole[mid..] });
    defer allocator.free(split);

    var offer = try decodeOffer(allocator, split);
    defer offer.deinit(allocator);
    try testing.expectEqualStrings("split across a tweet", offer.description.?);
}

test "hostile: wrong human-readable prefix is rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnknownPrefix, decodeOffer(allocator, "lnbc1qqqqqq"));
}

test "hostile: an unknown EVEN top-level TLV type fails the stream (BOLT#1 'ok to be odd')" {
    const allocator = testing.allocator;
    var tlv_bytes: std.ArrayList(u8) = .empty;
    defer tlv_bytes.deinit(allocator);
    // type 100 (even, unrecognized by offers) -- must fail, not silently ignore.
    const records = [_]lnwire.RawRecord{.{ .type = 100, .value = &.{0x01} }};
    try lnwire.tlv.appendStream(&tlv_bytes, allocator, &records);
    const quintets = try bitpack.bytesToQuintets(allocator, tlv_bytes.items);
    defer allocator.free(quintets);
    const offer_str = try bech32raw.encodeNoChecksum(allocator, "lno", quintets);
    defer allocator.free(offer_str);
    try testing.expectError(error.UnknownEvenType, decodeOffer(allocator, offer_str));
}

test "hostile: an unknown ODD top-level TLV type is silently discarded, decode still succeeds" {
    const allocator = testing.allocator;
    var tlv_bytes: std.ArrayList(u8) = .empty;
    defer tlv_bytes.deinit(allocator);
    const records = [_]lnwire.RawRecord{
        .{ .type = TYPE_DESCRIPTION, .value = "still parses" },
        .{ .type = 101, .value = "future extension" }, // odd, unrecognized, strictly-increasing type
    };
    try lnwire.tlv.appendStream(&tlv_bytes, allocator, &records);
    const quintets = try bitpack.bytesToQuintets(allocator, tlv_bytes.items);
    defer allocator.free(quintets);
    const offer_str = try bech32raw.encodeNoChecksum(allocator, "lno", quintets);
    defer allocator.free(offer_str);

    var offer = try decodeOffer(allocator, offer_str);
    defer offer.deinit(allocator);
    try testing.expectEqualStrings("still parses", offer.description.?);
}
