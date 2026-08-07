// SPDX-License-Identifier: MIT
//! BOLT#12 — the `lno1...`/`lnr1...`/`lni1...` bech32-*style* (no checksum)
//! TLV-encoded offer/invoice_request/invoice exchange: `offer` decode, and
//! the signed `invoice_request`/`invoice` forms (parse + verify + build +
//! sign) built on BOLT#12's Merkle-tree BIP-340 Schnorr signature.
//!
//! Encoding (BOLT#12 "Encoding"): human-readable prefix (`lno`/`lnr`/`lni`),
//! `1` separator, then the raw TLV stream's bytes bit-packed 5 bits at a
//! time (`bitpack.bytesToQuintets`/`quintetsToBytesStrict` — the same
//! MSB-first packing BOLT#11 uses, just over a whole TLV blob instead of
//! per-field values) — **no checksum** ("There is no checksum, unlike
//! bech32m"), and a `+` (optionally followed by whitespace) may split the
//! string across limited-length text fields; both are handled by
//! `bech32_raw.decodeNoChecksum`/`stripContinuation`.
//!
//! ## Signature Calculation (BOLT#12) — the Merkle root
//!
//! `invoice_request`/`invoice` are signed with a BIP-340 Schnorr signature
//! over a **Merkle root of the TLV stream** (`merkleRoot`), a BIP-341-style
//! tree where every data leaf is paired with a nonce leaf:
//!   - leaf   = `H("LnLeaf", tlv)` — `tlv` = the record's full
//!     `type||length||value` serialization;
//!   - nonce  = `H("LnNonce"||first-tlv, tlv-type)` — the tag itself is the
//!     literal `"LnNonce"` concatenated with the *complete first TLV record*
//!     of the stream, and the message is the current record's **type field**
//!     (its 1–9-byte BigSize encoding);
//!   - branch = `H("LnBranch", lesser-SHA256 || greater-SHA256)` — the two
//!     child hashes ordered lexicographically (compact-proof convention).
//! The tree is built bottom-up; when a level's node count is not a power of
//! two the split point is the largest power of two strictly below the count
//! ("the deepest tree on the lowest-order leaves"). *Signature* TLV elements
//! (types 240–1000 inclusive) are EXCLUDED from the tree. The message signed
//! is then `H("lightning"||messagename||fieldname, merkle-root)` per BOLT#12
//! "Signature Calculation" (e.g. tag `"lightninginvoice_requestsignature"`),
//! fed to BIP-340 `sign`/`verify` (which applies its own `BIP0340/challenge`
//! tag on top). `invoice_request` is signed by `invreq_payer_id` (type 88);
//! `invoice` by `invoice_node_id` (type 176) — both stored as 33-byte
//! compressed points but verified x-only (BIP-340 forces even-y via
//! `lift_x`, so the parity prefix byte is not consulted).
//!
//! ## Deferred / pragmatic field coverage
//!
//! `offer_paths`/`invreq_paths`/`invoice_paths` (`blinded_path` entries) are
//! handed back as raw undecoded bytes — decoding the blinded-path structure
//! is BOLT#4 route-blinding, a distinct spec. `invoice`'s optional
//! `invoice_blindedpay`/`invoice_fallbacks` sub-structures are likewise kept
//! raw. The signed-blob correctness (the Merkle root + the BIP-340
//! signature) and the mandatory scalar fields are modelled fully; see
//! `../SPEC.md` for the exact list of typed vs. raw fields.

const std = @import("std");
const Allocator = std.mem.Allocator;
const lnwire = @import("lnwire");
const bip340 = @import("bip340");
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
    /// `offer_chains` TLV present but with a zero-length value (BOLT#12
    /// "Rationale": "An empty `offer_chains` (present but with zero
    /// entries) is explicitly invalid because it would make invoice
    /// requests impossible" — external anchor: `offers-test.json` "offer_chains
    /// with zero entries"). Distinct from `offer_chains` being absent
    /// entirely, which is the normal (and common) "bitcoin only" case and
    /// stays valid with `chains.len == 0`.
    EmptyOfferChains,
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

    const bytes = try bitpack.quintetsToBytesMinimal(allocator, raw.data);
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
                if (rec.value.len == 0) return error.EmptyOfferChains;
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

// ── BOLT#12 signature calculation: the Merkle root ───────────────────────

/// BOLT#12 "signature TLV elements": types 240–1000 inclusive are excluded
/// from the Merkle tree (they carry the signature(s) over that tree).
fn isSignatureType(t: u64) bool {
    return t >= 240 and t <= 1000;
}

/// `H("LnBranch", lesser || greater)` — the two 32-byte child hashes ordered
/// lexicographically before hashing (BOLT#12: "this ordering means proofs
/// are more compact since left/right is inherently determined").
fn branchHash(a: [32]u8, b: [32]u8) [32]u8 {
    var buf: [64]u8 = undefined;
    if (std.mem.lessThan(u8, &a, &b)) {
        buf[0..32].* = a;
        buf[32..64].* = b;
    } else {
        buf[0..32].* = b;
        buf[32..64].* = a;
    }
    return bip340.taggedHash("LnBranch", &buf);
}

/// `H("LnNonce"||first_tlv, tlv_type)` — the *tag* is the literal string
/// `"LnNonce"` concatenated with the whole first TLV record of the stream
/// (so it varies per stream and cannot use the comptime-midstate helper),
/// and the message is the current record's type-field bytes.
/// `bip340.hash.taggedHashRuntime` implements the shared runtime-tag form
/// of the tagged-hash definition `SHA256(SHA256(tag) || SHA256(tag) ||
/// msg)`, taking the tag as parts so the `"LnNonce" || first_tlv`
/// concatenation needs no intermediate buffer.
fn nonceLeaf(first_tlv: []const u8, type_bytes: []const u8) [32]u8 {
    return bip340.hash.taggedHashRuntime(&.{ "LnNonce", first_tlv }, type_bytes);
}

/// Recursively combine an ascending list of (already leaf+nonce-paired) node
/// hashes into a single root. When `nodes.len` is not a power of two, the
/// split is the largest power of two strictly less than the length — BOLT#12:
/// "the deepest tree on the lowest-order leaves".
fn merkleRecurse(nodes: []const [32]u8) [32]u8 {
    if (nodes.len == 1) return nodes[0];
    var split: usize = 1;
    while (split * 2 < nodes.len) split *= 2;
    return branchHash(merkleRecurse(nodes[0..split]), merkleRecurse(nodes[split..]));
}

pub const MerkleError = lnwire.tlv.BigSizeError || Allocator.Error || error{
    /// A record's declared length ran past the end of the stream.
    Truncated,
    /// The stream contained no non-signature TLV records — a signable
    /// message always has at least one field to sign over.
    EmptyMerkleStream,
};

/// The BOLT#12 Merkle root over a raw TLV stream (`type||length||value`
/// records, ascending order — as produced by `lnwire.tlv.appendStream` or
/// carried in a decoded `invoice_request`/`invoice`). *Signature* TLV
/// elements (types 240–1000) are skipped, per spec. The walk is
/// self-contained (it re-derives each record's raw byte range, which the
/// generic `parseStream` does not expose) and re-checks BigSize
/// minimality/truncation so it is safe on untrusted input.
pub fn merkleRoot(allocator: Allocator, tlv_stream: []const u8) MerkleError![32]u8 {
    var nodes: std.ArrayList([32]u8) = .empty;
    defer nodes.deinit(allocator);

    var first_tlv: ?[]const u8 = null;
    var offset: usize = 0;
    while (offset < tlv_stream.len) {
        const type_start = offset;
        const t = try lnwire.decodeBigSize(tlv_stream[offset..]);
        offset += t.consumed;
        const type_bytes = tlv_stream[type_start..offset];
        const l = try lnwire.decodeBigSize(tlv_stream[offset..]);
        offset += l.consumed;
        const remaining: u64 = tlv_stream.len - offset;
        if (l.value > remaining) return error.Truncated;
        const len: usize = @intCast(l.value);
        const rec_bytes = tlv_stream[type_start .. offset + len];
        offset += len;

        if (isSignatureType(t.value)) continue;
        if (first_tlv == null) first_tlv = rec_bytes;
        const leaf = bip340.taggedHash("LnLeaf", rec_bytes);
        const nonce = nonceLeaf(first_tlv.?, type_bytes);
        try nodes.append(allocator, branchHash(leaf, nonce));
    }
    if (nodes.items.len == 0) return error.EmptyMerkleStream;
    return merkleRecurse(nodes.items);
}

// ── generic BIP-340 sign/verify over a Merkle root ───────────────────────

/// The signature-TLV `messagename||fieldname` tags BOLT#12 defines, already
/// prefixed with the literal 9-byte `"lightning"`.
pub const invoice_request_sig_tag = "lightninginvoice_requestsignature";
pub const invoice_sig_tag = "lightninginvoicesignature";

pub const SignError = MerkleError || bip340.SignError;

/// `SIG(tag, merkle-root, key)` (BOLT#12): compute the Merkle root over
/// `tlv_stream` (which must NOT yet contain the signature record — sign over
/// the fields being committed to), tag-hash it, and BIP-340-sign that digest.
/// `comptime tag` is one of `invoice_request_sig_tag`/`invoice_sig_tag`.
pub fn signMerkle(
    allocator: Allocator,
    tlv_stream: []const u8,
    comptime tag: []const u8,
    secret_key: bip340.SecretKey,
    aux_rand: [32]u8,
    io: std.Io,
) SignError![64]u8 {
    const root = try merkleRoot(allocator, tlv_stream);
    const digest = bip340.taggedHash(tag, &root);
    return bip340.sign(secret_key, &digest, aux_rand, io);
}

pub const VerifyError = MerkleError || error{InvalidPublicKey};

/// Verify a BOLT#12 signature: recompute the Merkle root over `tlv_stream`
/// (signature TLVs excluded automatically), tag-hash it, and BIP-340-verify
/// `sig` against the x-only view of `signer` (a 32-byte x-only OR the
/// x-coordinate of a 33-byte compressed key — BIP-340 is x-only). Returns
/// `false` (never errors) on any signature/key mismatch; errors only on a
/// malformed stream or a non-curve public key.
pub fn verifyMerkle(
    allocator: Allocator,
    tlv_stream: []const u8,
    comptime tag: []const u8,
    signer_xonly: [32]u8,
    sig_bytes: [64]u8,
) VerifyError!bool {
    const root = try merkleRoot(allocator, tlv_stream);
    const digest = bip340.taggedHash(tag, &root);
    const pk = bip340.XOnlyPublicKey.fromBytes(signer_xonly) catch return error.InvalidPublicKey;
    const sig = bip340.Signature.fromBytes(sig_bytes) catch return false;
    return bip340.verify(pk, &digest, sig);
}

// ── invoice_request (`lnr1...`) TLV field types ──────────────────────────

const IREQ_METADATA: u64 = 0;
// offer_* fields (types 2..22) are copied verbatim from the offer; the
// constants above (TYPE_CHAINS..TYPE_ISSUER_ID) are reused.
const INVREQ_CHAIN: u64 = 80;
const INVREQ_AMOUNT: u64 = 82;
const INVREQ_FEATURES: u64 = 84;
const INVREQ_QUANTITY: u64 = 86;
const INVREQ_PAYER_ID: u64 = 88;
const INVREQ_PAYER_NOTE: u64 = 89;
const INVREQ_PATHS: u64 = 90;
const SIGNATURE: u64 = 240;

const known_invreq_types = known_offer_types ++ [_]u64{
    IREQ_METADATA,   INVREQ_CHAIN,    INVREQ_AMOUNT,     INVREQ_FEATURES,
    INVREQ_QUANTITY, INVREQ_PAYER_ID, INVREQ_PAYER_NOTE, INVREQ_PATHS,
    SIGNATURE,
};

/// A decoded BOLT#12 `invoice_request`. Scalar/opaque fields are typed;
/// `raw` owns the full decoded TLV stream and every `[]const u8` field
/// borrows from it (so `deinit` frees only `raw`). Point/signature fields
/// are copied by value. Fields not listed here (paths, features detail) are
/// left in `raw`; see the module doc comment for the deferred set.
pub const InvoiceRequest = struct {
    raw: []u8,
    invreq_metadata: ?[]const u8,
    offer_currency: ?[]const u8,
    offer_amount: ?u64,
    offer_description: ?[]const u8,
    offer_issuer_id: ?[33]u8,
    invreq_chain: ?[32]u8,
    invreq_amount: ?u64,
    invreq_quantity: ?u64,
    invreq_payer_id: ?[33]u8,
    invreq_payer_note: ?[]const u8,
    signature: ?[64]u8,

    pub fn deinit(self: *InvoiceRequest, allocator: Allocator) void {
        allocator.free(self.raw);
        self.* = undefined;
    }

    /// Verify the `signature` (type 240) as a BOLT#12 BIP-340 signature by
    /// `invreq_payer_id` (type 88) over the Merkle root of the request.
    /// Fails closed if either field is absent.
    pub fn verify(self: InvoiceRequest, allocator: Allocator) (VerifyError || error{ MissingSignature, MissingPayerId })!bool {
        const sig = self.signature orelse return error.MissingSignature;
        const payer = self.invreq_payer_id orelse return error.MissingPayerId;
        const xonly = bip340.xonlyBytesOf(&payer) catch unreachable; // fixed 33 bytes
        return verifyMerkle(allocator, self.raw, invoice_request_sig_tag, xonly, sig);
    }
};

pub const IReqDecodeError = bech32raw.SplitError || error{InvalidDataChar} ||
    bitpack.PaddingError || lnwire.tlv.StreamError || Allocator.Error || error{
    UnknownPrefix,
    BadChainsLength,
    BadAmount,
    BadIssuerIdLength,
    BadPayerIdLength,
    BadChainLength,
    BadSignatureLength,
};

/// Decode (and TLV-validate) a BOLT#12 `invoice_request` string (`lnr1...`).
/// Does NOT verify the signature — call `InvoiceRequest.verify` for that.
pub fn decodeInvoiceRequest(allocator: Allocator, str: []const u8) IReqDecodeError!InvoiceRequest {
    const stripped = try bech32raw.stripContinuation(allocator, str);
    defer allocator.free(stripped);
    var raw_dec = try bech32raw.decodeNoChecksum(allocator, stripped);
    defer raw_dec.deinit(allocator);
    if (!std.mem.eql(u8, raw_dec.hrp, "lnr")) return error.UnknownPrefix;

    const bytes = try bitpack.quintetsToBytesMinimal(allocator, raw_dec.data);
    errdefer allocator.free(bytes);

    var parsed = try lnwire.parseTlvStream(allocator, bytes, &known_invreq_types);
    defer parsed.deinit(allocator);

    var ir: InvoiceRequest = .{
        .raw = bytes,
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
    for (parsed.records) |rec| {
        switch (rec.type) {
            IREQ_METADATA => if (ir.invreq_metadata == null) {
                ir.invreq_metadata = rec.value;
            },
            TYPE_CURRENCY => if (ir.offer_currency == null) {
                ir.offer_currency = rec.value;
            },
            TYPE_AMOUNT => if (ir.offer_amount == null) {
                ir.offer_amount = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            TYPE_DESCRIPTION => if (ir.offer_description == null) {
                ir.offer_description = rec.value;
            },
            TYPE_ISSUER_ID => if (ir.offer_issuer_id == null) {
                if (rec.value.len != 33) return error.BadIssuerIdLength;
                ir.offer_issuer_id = rec.value[0..33].*;
            },
            INVREQ_CHAIN => if (ir.invreq_chain == null) {
                if (rec.value.len != 32) return error.BadChainLength;
                ir.invreq_chain = rec.value[0..32].*;
            },
            INVREQ_AMOUNT => if (ir.invreq_amount == null) {
                ir.invreq_amount = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            INVREQ_QUANTITY => if (ir.invreq_quantity == null) {
                ir.invreq_quantity = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            INVREQ_PAYER_ID => if (ir.invreq_payer_id == null) {
                if (rec.value.len != 33) return error.BadPayerIdLength;
                ir.invreq_payer_id = rec.value[0..33].*;
            },
            INVREQ_PAYER_NOTE => if (ir.invreq_payer_note == null) {
                ir.invreq_payer_note = rec.value;
            },
            SIGNATURE => if (ir.signature == null) {
                if (rec.value.len != 64) return error.BadSignatureLength;
                ir.signature = rec.value[0..64].*;
            },
            else => {},
        }
    }
    return ir;
}

/// Assemble the final wire TLV stream for a signed `invoice_request`/
/// `invoice`: `unsigned_records` with type < `SIGNATURE` (240), then the
/// `signature` record itself, then any `unsigned_records` with type >
/// `SIGNATURE`. BOLT#12 requires ascending TLV type order across the WHOLE
/// stream, signature slot included — a caller record with type > 240 (a
/// private/experimental field; ordinary BOLT#12 `invoice_*`/
/// `invoice_request_*` field types are all < 240) must therefore be written
/// AFTER the signature, not unconditionally last. Shared by
/// `encodeSignedInvoiceRequest`/`encodeSignedInvoice` since both follow the
/// identical assemble-after-sign shape. `sig` must already be computed (by
/// the caller, via `signMerkle` over `unsigned_records` in their original
/// order — that computation is unaffected by this split: `merkleRoot`/
/// `signMerkle` already exclude signature-range TLVs [240-1000] wherever
/// they happen to sit in a stream).
fn appendSignedStream(
    allocator: Allocator,
    stream: *std.ArrayList(u8),
    unsigned_records: []const lnwire.RawRecord,
    sig: [64]u8,
) Allocator.Error!void {
    var below: std.ArrayList(lnwire.RawRecord) = .empty;
    defer below.deinit(allocator);
    var above: std.ArrayList(lnwire.RawRecord) = .empty;
    defer above.deinit(allocator);
    for (unsigned_records) |r| {
        if (r.type < SIGNATURE) try below.append(allocator, r) else try above.append(allocator, r);
    }
    try lnwire.tlv.appendStream(stream, allocator, below.items);
    try lnwire.tlv.appendStream(stream, allocator, &.{.{ .type = SIGNATURE, .value = &sig }});
    try lnwire.tlv.appendStream(stream, allocator, above.items);
}

/// Sign a set of `invoice_request` fields (given as ascending, signature-free
/// TLV records — the caller must include `invreq_payer_id` matching
/// `secret_key`) and encode the result as an `lnr1...` string. The
/// `signature` record (type 240) is inserted in ascending-type position via
/// `appendSignedStream` — after every record with a lower type, before any
/// record with a higher one (private/experimental fields only; every
/// `invreq_*` type BOLT#12 itself defines is < 240, so for those this is
/// simply "last", same as before).
pub fn encodeSignedInvoiceRequest(
    allocator: Allocator,
    unsigned_records: []const lnwire.RawRecord,
    secret_key: bip340.SecretKey,
    aux_rand: [32]u8,
    io: std.Io,
) (SignError || bech32raw.EncodeError)![]u8 {
    var unsigned_stream: std.ArrayList(u8) = .empty;
    defer unsigned_stream.deinit(allocator);
    try lnwire.tlv.appendStream(&unsigned_stream, allocator, unsigned_records);
    const sig = try signMerkle(allocator, unsigned_stream.items, invoice_request_sig_tag, secret_key, aux_rand, io);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try appendSignedStream(allocator, &stream, unsigned_records, sig);

    const quintets = try bitpack.bytesToQuintets(allocator, stream.items);
    defer allocator.free(quintets);
    return bech32raw.encodeNoChecksum(allocator, "lnr", quintets);
}

// ── invoice (`lni1...`) TLV field types ──────────────────────────────────

const INVOICE_PATHS: u64 = 160;
const INVOICE_BLINDEDPAY: u64 = 162;
const INVOICE_CREATED_AT: u64 = 164;
const INVOICE_RELATIVE_EXPIRY: u64 = 166;
const INVOICE_PAYMENT_HASH: u64 = 168;
const INVOICE_AMOUNT: u64 = 170;
const INVOICE_FALLBACKS: u64 = 172;
const INVOICE_FEATURES: u64 = 174;
const INVOICE_NODE_ID: u64 = 176;

const known_invoice_types = known_invreq_types ++ [_]u64{
    INVOICE_PATHS,           INVOICE_BLINDEDPAY,   INVOICE_CREATED_AT,
    INVOICE_RELATIVE_EXPIRY, INVOICE_PAYMENT_HASH, INVOICE_AMOUNT,
    INVOICE_FALLBACKS,       INVOICE_FEATURES,     INVOICE_NODE_ID,
};

/// A decoded BOLT#12 `invoice`. Same ownership model as `InvoiceRequest`
/// (`raw` owns the stream; slice fields borrow). Optional sub-structures
/// (`invoice_paths`/`invoice_blindedpay`/`invoice_fallbacks`) stay in `raw` —
/// see the module doc comment.
pub const Invoice = struct {
    raw: []u8,
    invoice_created_at: ?u64,
    invoice_relative_expiry: ?u64,
    invoice_payment_hash: ?[32]u8,
    invoice_amount: ?u64,
    invoice_node_id: ?[33]u8,
    signature: ?[64]u8,

    pub fn deinit(self: *Invoice, allocator: Allocator) void {
        allocator.free(self.raw);
        self.* = undefined;
    }

    /// Verify the `signature` (type 240) as a BOLT#12 BIP-340 signature by
    /// `invoice_node_id` (type 176) over the Merkle root of the invoice.
    pub fn verify(self: Invoice, allocator: Allocator) (VerifyError || error{ MissingSignature, MissingNodeId })!bool {
        const sig = self.signature orelse return error.MissingSignature;
        const node = self.invoice_node_id orelse return error.MissingNodeId;
        const xonly = bip340.xonlyBytesOf(&node) catch unreachable; // fixed 33 bytes
        return verifyMerkle(allocator, self.raw, invoice_sig_tag, xonly, sig);
    }
};

pub const InvoiceDecodeError = bech32raw.SplitError || error{InvalidDataChar} ||
    bitpack.PaddingError || lnwire.tlv.StreamError || Allocator.Error || error{
    UnknownPrefix,
    BadAmount,
    BadPaymentHashLength,
    BadNodeIdLength,
    BadSignatureLength,
};

/// Decode (and TLV-validate) a BOLT#12 `invoice` string (`lni1...`). Does
/// NOT verify the signature — call `Invoice.verify` for that.
pub fn decodeInvoice(allocator: Allocator, str: []const u8) InvoiceDecodeError!Invoice {
    const stripped = try bech32raw.stripContinuation(allocator, str);
    defer allocator.free(stripped);
    var raw_dec = try bech32raw.decodeNoChecksum(allocator, stripped);
    defer raw_dec.deinit(allocator);
    if (!std.mem.eql(u8, raw_dec.hrp, "lni")) return error.UnknownPrefix;

    const bytes = try bitpack.quintetsToBytesMinimal(allocator, raw_dec.data);
    errdefer allocator.free(bytes);

    var parsed = try lnwire.parseTlvStream(allocator, bytes, &known_invoice_types);
    defer parsed.deinit(allocator);

    var inv: Invoice = .{
        .raw = bytes,
        .invoice_created_at = null,
        .invoice_relative_expiry = null,
        .invoice_payment_hash = null,
        .invoice_amount = null,
        .invoice_node_id = null,
        .signature = null,
    };
    for (parsed.records) |rec| {
        switch (rec.type) {
            INVOICE_CREATED_AT => if (inv.invoice_created_at == null) {
                inv.invoice_created_at = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            INVOICE_RELATIVE_EXPIRY => if (inv.invoice_relative_expiry == null) {
                inv.invoice_relative_expiry = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            INVOICE_PAYMENT_HASH => if (inv.invoice_payment_hash == null) {
                if (rec.value.len != 32) return error.BadPaymentHashLength;
                inv.invoice_payment_hash = rec.value[0..32].*;
            },
            INVOICE_AMOUNT => if (inv.invoice_amount == null) {
                inv.invoice_amount = lnwire.tlv.decodeTruncated(u64, rec.value) catch return error.BadAmount;
            },
            INVOICE_NODE_ID => if (inv.invoice_node_id == null) {
                if (rec.value.len != 33) return error.BadNodeIdLength;
                inv.invoice_node_id = rec.value[0..33].*;
            },
            SIGNATURE => if (inv.signature == null) {
                if (rec.value.len != 64) return error.BadSignatureLength;
                inv.signature = rec.value[0..64].*;
            },
            else => {},
        }
    }
    return inv;
}

/// Sign a set of `invoice` fields (ascending, signature-free TLV records —
/// the caller must include `invoice_node_id` matching `secret_key`) and
/// encode as an `lni1...` string. The `signature` record (type 240) is
/// inserted in ascending-type position via `appendSignedStream` — after
/// every record with a lower type, before any record with a higher one
/// (private/experimental fields only; every `invoice_*` type BOLT#12
/// itself defines is < 240, so for those this is simply "last", same as
/// before). Verified against a real external vector with a type > 240
/// field (`lightning/bolts` `bolt12/payer-proof-test.json`'s
/// "full_disclosure", type 3000000001) — see the "invoice ENCODE
/// byte-exact" KAT tests below.
pub fn encodeSignedInvoice(
    allocator: Allocator,
    unsigned_records: []const lnwire.RawRecord,
    secret_key: bip340.SecretKey,
    aux_rand: [32]u8,
    io: std.Io,
) (SignError || bech32raw.EncodeError)![]u8 {
    var unsigned_stream: std.ArrayList(u8) = .empty;
    defer unsigned_stream.deinit(allocator);
    try lnwire.tlv.appendStream(&unsigned_stream, allocator, unsigned_records);
    const sig = try signMerkle(allocator, unsigned_stream.items, invoice_sig_tag, secret_key, aux_rand, io);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try appendSignedStream(allocator, &stream, unsigned_records, sig);

    const quintets = try bitpack.bytesToQuintets(allocator, stream.items);
    defer allocator.free(quintets);
    return bech32raw.encodeNoChecksum(allocator, "lni", quintets);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const offers_kat = @import("bolt12_offers_kat_vectors.zig");
const format_string_kat = @import("bolt12_format_string_kat_vectors.zig");

fn hexToBytes(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// Hand-built (not fetched from a spec vector -- BOLT#12's own JSON test
// vectors are invoice_request/invoice-oriented, out of this pass's scope)
// [Corrected 2026-08-02: `bolt12/offers-test.json` IS offer-oriented after
// all -- the claim above was wrong, not just stale. It was reachable
// without a network fetch all along (vendored in the sibling
// `lightning/bolts` repo, not `bootstrap.bolt12.org`); it is now vendored
// as `bolt12_offers_kat_vectors.zig` and drives the ENCODE/DECODE KATs
// below, closing the offer-encode self-round-trip gap this hand-built test
// alone could not.]
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

// Byte-exact external KATs for `decodeOffer` — closes the gap the module
// doc comment used to flag as self-round-trip-only ("a hand-built minimal
// offer... independently constructed, not hand-typed hex"). Source:
// `lightning/bolts` `bolt12/offers-test.json` (fetched from
// raw.githubusercontent.com 2026-07-28; each `bolt12` string and `fields`
// list below is reproduced verbatim, not hand-typed).
const issuer_id_hex = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";

test "BOLT#12 KAT: decodeOffer 'Minimal bolt12 offer' — offers-test.json" {
    const allocator = testing.allocator;
    const bolt12_str = "lno1zcss9mk8y3wkklfvevcrszlmu23kfrxh49px20665dqwmn4p72pksese";
    var offer = try decodeOffer(allocator, bolt12_str);
    defer offer.deinit(allocator);
    const want_issuer_id = try hexAlloc(allocator, issuer_id_hex);
    defer allocator.free(want_issuer_id);
    try testing.expectEqualSlices(u8, want_issuer_id, &offer.issuer_id.?);
    try testing.expect(offer.description == null);
    try testing.expect(offer.amount == null);
}

test "BOLT#12 KAT: decodeOffer 'with description (but no amount)' — offers-test.json" {
    const allocator = testing.allocator;
    const bolt12_str = "lno1pgx9getnwss8vetrw3hhyuckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
    var offer = try decodeOffer(allocator, bolt12_str);
    defer offer.deinit(allocator);
    try testing.expectEqualStrings("Test vectors", offer.description.?);
    const want_issuer_id = try hexAlloc(allocator, issuer_id_hex);
    defer allocator.free(want_issuer_id);
    try testing.expectEqualSlices(u8, want_issuer_id, &offer.issuer_id.?);
    try testing.expect(offer.amount == null);
}

test "BOLT#12 KAT: decodeOffer 'with currency' (USD $100.00) — offers-test.json" {
    const allocator = testing.allocator;
    const bolt12_str = "lno1qcp4256ypqpzwyq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
    var offer = try decodeOffer(allocator, bolt12_str);
    defer offer.deinit(allocator);
    try testing.expectEqualStrings("USD", offer.currency.?);
    try testing.expectEqual(@as(?u64, 10000), offer.amount); // $100.00 in cents
    try testing.expectEqualStrings("Test vectors", offer.description.?);
}

test "BOLT#12 KAT: decodeOffer rejects an unknown EVEN TLV type (type 78) — offers-test.json 'Malformed'" {
    const allocator = testing.allocator;
    const bolt12_str = "lno1pgz5znzfgdz3vggzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpysgr0u2xq4dh3kdevrf4zg6hx8a60jv0gxe0ptgyfc6xkryqqqqqqqq";
    try testing.expectError(error.UnknownEvenType, decodeOffer(allocator, bolt12_str));
}

// ── BOLT#12 KAT: full `offers-test.json` sweep (ENCODE + DECODE + reject) ──
//
// The 3 KATs above (plus the "unknown EVEN TLV type" one) predate this sweep
// and are kept as-is (no duplicate anchor removed, per this pass's own
// instructions) — they happen to be a subset of what the table below now
// also covers. Everything below is new: it closes the "BOLT#12 offer ENCODE
// round-trip self-constructed" gap the ANCHOR-TASKS.tsv row named (the
// module could only round-trip its OWN encoder into its OWN decoder before
// this), and extends the DECODE anchor from 3 hand-picked vectors to every
// vector the official suite ships a `fields` list for.
//
// `offers-test.json` has 53 rows total. 22 carry a `fields` list (the
// TLV-record breakdown the suite publishes alongside the `bolt12` string):
// 20 of the 20 `"valid": true` rows, plus 2 of the 33 `"valid": false` rows
// ("Invalid: zero offer_amount" x2) whose TLV bytes are still wire-well-formed
// (a zero-length `tu64` is a legal minimal encoding of the integer 0) even
// though BOLT#12 says a reader "MUST NOT respond" to an offer with
// `offer_amount` set and not greater than zero -- that is a business-logic
// policy this module does not implement (it only decodes/extracts fields,
// same posture as `offer_paths`/`offer_features` staying raw/uninterpreted;
// see the module doc comment and SPEC.md), so both zero-amount rows are
// exercised for ENCODE/DECODE like any other row, not for the "MUST NOT
// respond" policy check.

fn findOfferVector(description: []const u8) offers_kat.Vector {
    for (offers_kat.vectors) |v| {
        if (std.mem.eql(u8, v.description, description)) return v;
    }
    unreachable; // a lookup miss is a bug in this test file, not the vectors
}

test "BOLT#12 KAT: offer ENCODE byte-exact against every offers-test.json vector with a `fields` list (closes the encode self-round-trip gap)" {
    const allocator = testing.allocator;
    var ran: usize = 0;
    for (offers_kat.vectors) |v| {
        if (v.fields.len == 0) continue;
        ran += 1;

        var values: std.ArrayList([]u8) = .empty;
        defer {
            for (values.items) |val| allocator.free(val);
            values.deinit(allocator);
        }
        var records: std.ArrayList(lnwire.RawRecord) = .empty;
        defer records.deinit(allocator);
        for (v.fields) |f| {
            const val = try hexAlloc(allocator, f.hex);
            try values.append(allocator, val);
            try records.append(allocator, .{ .type = f.type, .value = val });
        }

        var stream: std.ArrayList(u8) = .empty;
        defer stream.deinit(allocator);
        try lnwire.tlv.appendStream(&stream, allocator, records.items);
        const quintets = try bitpack.bytesToQuintets(allocator, stream.items);
        defer allocator.free(quintets);
        const got = try bech32raw.encodeNoChecksum(allocator, "lno", quintets);
        defer allocator.free(got);

        testing.expectEqualStrings(v.bolt12, got) catch |err| {
            std.debug.print("FAILED offer ENCODE vector: {s}\n", .{v.description});
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 22), ran);
}

test "BOLT#12 KAT: offer DECODE recovers every raw TLV record from every offers-test.json vector with a `fields` list" {
    const allocator = testing.allocator;
    var ran: usize = 0;
    for (offers_kat.vectors) |v| {
        if (v.fields.len == 0) continue;
        ran += 1;

        const stripped = try bech32raw.stripContinuation(allocator, v.bolt12);
        defer allocator.free(stripped);
        var raw = try bech32raw.decodeNoChecksum(allocator, stripped);
        defer raw.deinit(allocator);
        const bytes = try bitpack.quintetsToBytesMinimal(allocator, raw.data);
        defer allocator.free(bytes);
        var parsed = try lnwire.parseTlvStream(allocator, bytes, &known_offer_types);
        defer parsed.deinit(allocator);

        // Two vectors ("unknown odd field" / "unknown odd experimental
        // field") deliberately include an unknown-ODD-type record in their
        // `fields` list -- BOLT#1's "ok to be odd" rule has
        // `lnwire.parseTlvStream` walk past it (so the stream stays
        // byte-aligned) but never STORE it in `parsed.records` (see
        // `known_offer_types` and `parseStream`'s own doc comment). Filter
        // `v.fields` down to the known-type subset before comparing, so
        // this test asserts what `decodeOffer` actually keeps, not a raw
        // count that a correctly-discarded field would fail.
        var known_fields: std.ArrayList(offers_kat.Field) = .empty;
        defer known_fields.deinit(allocator);
        for (v.fields) |f| {
            if (isKnownOfferType(f.type)) try known_fields.append(allocator, f);
        }

        testing.expectEqual(known_fields.items.len, parsed.records.len) catch |err| {
            std.debug.print("FAILED offer DECODE record count for vector: {s}\n", .{v.description});
            return err;
        };
        for (known_fields.items, parsed.records) |f, rec| {
            try testing.expectEqual(f.type, rec.type);
            const want = try hexAlloc(allocator, f.hex);
            defer allocator.free(want);
            testing.expectEqualSlices(u8, want, rec.value) catch |err| {
                std.debug.print("FAILED offer DECODE value for vector: {s} (type {d})\n", .{ v.description, f.type });
                return err;
            };
        }
    }
    try testing.expectEqual(@as(usize, 22), ran);
}

fn isKnownOfferType(t: u64) bool {
    for (known_offer_types) |k| {
        if (k == t) return true;
    }
    return false;
}

// The following `"valid": false` rows carry NO `fields` list (the suite
// only republishes the TLV breakdown for rows it expects to parse cleanly),
// so ENCODE can't be exercised for them -- but each is a genuine WIRE-level
// defect this module's decode path is scoped to catch, so DECODE-rejection
// is checked directly against the vendored `bolt12` string, one test per
// row, asserting the SPECIFIC error (not just "some error"), so a vector
// rejected for the wrong reason would be caught, not silently passed.
test "BOLT#12 KAT: decodeOffer rejects out-of-order TLV types — offers-test.json 'Malformed: fields out of order'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: fields out of order");
    try testing.expectError(error.NotStrictlyIncreasing, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects a stream truncated mid-type — offers-test.json 'Malformed: truncated at type'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: truncated at type");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects a stream truncated mid-length — offers-test.json 'Malformed: truncated in length'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: truncated in length");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects a stream truncated right after length — offers-test.json 'Malformed: truncated after length'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: truncated after length");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects a value shorter than its declared length — offers-test.json 'Malformed: truncated in description'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: truncated in description");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects a non-32-byte-multiple offer_chains — offers-test.json 'Malformed: invalid offer_chains length'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Malformed: invalid offer_chains length");
    try testing.expectError(error.BadChainsLength, decodeOffer(allocator, v.bolt12));
}

// BOLT#12 "Rationale": "An empty `offer_chains` (present but with zero
// entries) is explicitly invalid" -- this vector is what exposed that
// `decodeOffer` did not yet enforce it (see `error.EmptyOfferChains`'s own
// doc comment on `DecodeError` and the fix in the `TYPE_CHAINS` arm above).
test "BOLT#12 KAT: decodeOffer rejects offer_chains present-but-empty — offers-test.json 'offer_chains with zero entries'" {
    const allocator = testing.allocator;
    const v = findOfferVector("offer_chains with zero entries");
    try testing.expectError(error.EmptyOfferChains, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects an unknown-even TLV type >= 80 — offers-test.json 'Contains type >= 80'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Contains type >= 80");
    try testing.expectError(error.UnknownEvenType, decodeOffer(allocator, v.bolt12));
}

test "BOLT#12 KAT: decodeOffer rejects an unknown even TLV type 1000000002 — offers-test.json 'Contains unknown even type (1000000002)'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Contains unknown even type (1000000002)");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

// "Contains type > 1999999999" and the sibling vector above both encode
// their oversized TLV type with the wider BigSize form its magnitude
// requires (a `bigsize` type this large needs the 4- or 8-byte form); empirically
// the bytes that follow do not then resolve to a length+value pair that
// fits in the remaining stream, so `lnwire.parseTlvStream` reports
// `error.Truncated` (checked before type-oddness is ever consulted) rather
// than `error.UnknownEvenType` -- both are genuine wire-level TLV
// rejections and either is a correct "reject this offer" outcome; this
// pins down WHICH one so a future change that silently swaps the failure
// mode is caught. No crash/overflow on the huge BigSize value either way.
test "BOLT#12 KAT: decodeOffer rejects TLV type > 1999999999 — offers-test.json 'Contains type > 1999999999'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Contains type > 1999999999");
    try testing.expectError(error.Truncated, decodeOffer(allocator, v.bolt12));
}

// BOLT#12 "Encoding": there is no checksum, so the whole `data` part must be
// bit-packed 5-bit quintets with NO more than 4 leftover padding bits after
// the last full byte -- 5+ leftover bits (even all-zero ones) means an
// extra, unnecessary all-zero quintet was appended, which this vector is:
// the "Minimal bolt12 offer" string plus one trailing zero-value bech32
// char. Exposed a real bug in `bitpack.quintetsToBytesStrict` (see
// `error.PaddingTooLong`'s own doc comment and the fix above) that the
// existing hostile-input tests never reached, because none of them
// exercised over-long-but-all-zero padding specifically.
test "BOLT#12 KAT: decodeOffer rejects bech32 padding of 5+ bits — offers-test.json 'Bech32 padding exceeds 4-bit limit'" {
    const allocator = testing.allocator;
    const v = findOfferVector("Bech32 padding exceeds 4-bit limit");
    try testing.expectError(error.PaddingTooLong, decodeOffer(allocator, v.bolt12));
}

// ── BOLT#12 KAT: `format-string-test.json` (`+`-continuation / case) ──────
//
// Exercises `bech32_raw.stripContinuation`/`splitHrp` through `decodeOffer`
// end-to-end. Found and fixed a real bug: `stripContinuation` used to strip
// EVERY `+` unconditionally, when BOLT#12 only requires removing one that
// sits BETWEEN two ordinary characters (see `stripContinuation`'s own
// corrected doc comment) -- a leading/trailing/doubled `+` was wrongly
// accepted (silently deleted) before the fix.
test "BOLT#12 KAT: decodeOffer accept/reject every format-string-test.json row (case + `+`-continuation)" {
    const allocator = testing.allocator;
    for (format_string_kat.vectors) |v| {
        if (v.valid) {
            var offer = decodeOffer(allocator, v.string) catch |err| {
                std.debug.print("FAILED (expected valid) format-string vector: {s}: {}\n", .{ v.comment, err });
                return err;
            };
            offer.deinit(allocator);
        } else {
            if (decodeOffer(allocator, v.string)) |*offer_ok| {
                var offer_mut = offer_ok.*;
                offer_mut.deinit(allocator);
                std.debug.print("FAILED (expected rejection) format-string vector: {s}\n", .{v.comment});
                return error.UnexpectedlyAccepted;
            } else |_| {} // any rejection is correct -- the suite doesn't name a single specific error class
        }
    }
}

// The remaining `offers-test.json` "valid": false rows (23 of the 33) are
// deliberately NOT driven through `decodeOffer` above: each exercises a
// check this module documents as out of scope, and asserting rejection
// against them would either fail honestly (proving the gap, which is
// already documented) or -- worse -- invite "fixing" it by adding scope
// this pass was not asked to add. Listed here, one line each, so the count
// is auditable against the vector file rather than silently narrowed:
//
//   UTF-8 validation (module stores currency/description/issuer as raw
//   bytes, never checked for UTF-8 validity -- see `Offer`'s field doc
//   comments): "Malformed: truncated currency UTF-8", "Malformed: invalid
//   currency UTF-8", "Malformed: truncated description UTF-8", "Malformed:
//   invalid description UTF-8", "Malformed: truncated issuer UTF-8",
//   "Malformed: invalid issuer UTF-8" (6 rows).
//
//   `offer_paths`/`blinded_path` internal structure (module keeps each
//   `offer_paths` TLV occurrence as an opaque raw blob -- BOLT#4
//   route-blinding is a distinct spec this module does not decode, per its
//   own doc comment): "Malformed: truncated offer_paths", "Malformed: zero
//   num_hops in blinded_path", "Malformed: truncated onionmsg_hop in
//   blinded_path", "Malformed: bad first_node_id in blinded_path",
//   "Malformed: bad path_key in blinded_path", "Malformed: bad
//   blinded_node_id in onionmsg_hop", "Second offer_path is empty" (7 rows).
//
//   `offer_issuer_id` curve-point validity (module stores the 33 raw bytes;
//   nothing at the offer-decode stage ever lifts it to a curve point --
//   that only happens later, for `invreq_payer_id`/`invoice_node_id`, during
//   signature verification): "Malformed: invalid offer_issuer_id" (1 row).
//
//   `offer_features` bit semantics (module hands `features` back as raw,
//   uninterpreted bytes -- BOLT#9 feature-bit meaning is out of BOLT#12's
//   own scope per this module's doc comment, same posture as BOLT#11's `9`
//   field): "Contains unknown feature 122" (1 row).
//
//   Reader "MUST NOT respond to the offer" BUSINESS-LOGIC policy (BOLT#12
//   "Requirements For Offers", "A reader of an offer:" list) -- this is a
//   should-I-act-on-this-offer decision, not a wire-decode failure; the
//   module decodes and hands back whatever fields are present, same as it
//   does not implement "is the current time after offer_absolute_expiry"
//   either: "Missing offer_description, but has offer_amount", "Missing
//   offer_amount with offer_currency", "Invalid: zero offer_amount",
//   "Invalid: zero offer_amount with currency", "Missing offer_issuer_id
//   and no offer_path", "Malformed: empty" (empty TLV stream decodes to an
//   all-null `Offer`, itself wire-valid; its invalidity is exactly this
//   same "neither issuer_id nor paths" policy) (6 rows).
//
//   6 + 7 + 1 + 1 + 6 = 21 rows skipped here for this specific "must reject"
//   sweep (2 of the 6 in the last bucket -- the zero-amount pair -- are
//   still exercised elsewhere, but only for ENCODE/DECODE wire fidelity,
//   never for this policy check, so there is no double standard, just two
//   different tests looking at two different properties of the same row).
//   The other 12 `"valid": false` rows ARE asserted rejected above:
//   out-of-order, truncated-at-type, truncated-in-length,
//   truncated-after-length, truncated-in-description, bad-chains-length,
//   chains-zero-entries, type>=80, unknown-even-1000000002,
//   type>1999999999, bech32-padding, plus the "unknown EVEN TLV type 78" KAT
//   that predates this pass. 21 + 12 = 33: every `"valid": false` row is
//   accounted for, none silently dropped.

// ── BOLT#12 Merkle / signature tests ─────────────────────────────────────

/// Decode a hex string (no separators, even length) into freshly-allocated
/// bytes — lets the spec's own `signature-test.json` record/merkle hex be
/// pasted verbatim rather than hand-transcribed into byte-array literals.
fn hexAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// Byte-exact KAT. Source: lightning/bolts `bolt12/signature-test.json`
// (github.com/lightning/bolts, "Signature Calculation" test vectors) — the
// `n1` namespace merkle-root rows (1, 2 and 3 TLVs). Each `tlv` string below
// is the concatenation of the spec's raw `type||length||value` records.
test "BOLT#12 KAT: n1 Merkle roots (1/2/3 leaves) — signature-test.json" {
    const allocator = testing.allocator;
    const tlv1 = "010203e8";
    const tlv2 = "02080000010000020003";
    const tlv3 = "03310266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351800000000000000010000000000000002";
    const Case = struct { stream: []const u8, merkle: []const u8 };
    const cases = [_]Case{
        .{ .stream = tlv1, .merkle = "b013756c8fee86503a0b4abdab4cddeb1af5d344ca6fc2fa8b6c08938caa6f93" },
        .{ .stream = tlv1 ++ tlv2, .merkle = "c3774abbf4815aa54ccaa026bff6581f01f3be5fe814c620a252534f434bc0d1" },
        .{ .stream = tlv1 ++ tlv2 ++ tlv3, .merkle = "ab2e79b1283b0b31e0b035258de23782df6b89a38cfa7237bde69aed1a658c5d" },
    };
    for (cases) |c| {
        const stream = try hexAlloc(allocator, c.stream);
        defer allocator.free(stream);
        const want = try hexAlloc(allocator, c.merkle);
        defer allocator.free(want);
        const got = try merkleRoot(allocator, stream);
        try testing.expectEqualSlices(u8, want, &got);
    }
}

// The invoice_request KAT from `signature-test.json`: offer_issuer_id = Alice,
// offer_description = "A Mathematical Treatise", offer_amount = 100,
// offer_currency = "USD", invreq_payer_id = Bob (privkey 0x4242..42),
// invreq_metadata = 0x00..00. Exercises the full 6-leaf tree PLUS the
// signature tag and the BIP-340 signature — all byte-exact.
const ireq_kat_records = [_][]const u8{
    "00080000000000000000", // invreq_metadata (type 0)
    "0603555344", // offer_currency "USD" (type 6)
    "080164", // offer_amount 100 (type 8)
    "0a1741204d617468656d61746963616c205472656174697365", // offer_description (type 10)
    "162102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619", // offer_issuer_id (type 22)
    "58210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", // invreq_payer_id (type 88)
};
const ireq_kat_merkle = "608407c18ad9a94d9ea2bcdbe170b6c20c462a7833a197621c916f78cf18e624";
const ireq_kat_signature = "b8f83ea3288cfd6ea510cdb481472575141e8d8744157f98562d162cc1c472526fdb24befefbdebab4dbb726bbd1b7d8aec057f8fa805187e5950d2bbe0e5642";
// Bob's x-only public key = x-coordinate of invreq_payer_id (strip 0x03 prefix).
const bob_xonly = "24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c";

test "BOLT#12 KAT: invoice_request Merkle root + signature verify — signature-test.json" {
    const allocator = testing.allocator;
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    for (ireq_kat_records) |rec_hex| {
        const rec = try hexAlloc(allocator, rec_hex);
        defer allocator.free(rec);
        try stream.appendSlice(allocator, rec);
    }

    // Merkle root byte-exact.
    const want_root = try hexAlloc(allocator, ireq_kat_merkle);
    defer allocator.free(want_root);
    const root = try merkleRoot(allocator, stream.items);
    try testing.expectEqualSlices(u8, want_root, &root);

    // Signature verifies against Bob's x-only key over H(sig_tag, root).
    const xonly_buf = try hexAlloc(allocator, bob_xonly);
    defer allocator.free(xonly_buf);
    const xonly = xonly_buf[0..32].*;
    const sig_buf = try hexAlloc(allocator, ireq_kat_signature);
    defer allocator.free(sig_buf);
    const sig = sig_buf[0..64].*;
    try testing.expect(try verifyMerkle(allocator, stream.items, invoice_request_sig_tag, xonly, sig));

    // Reject-teeth: flip one signature bit → verify fails (not errors).
    var bad_sig = sig;
    bad_sig[10] ^= 0x01;
    try testing.expect(!try verifyMerkle(allocator, stream.items, invoice_request_sig_tag, xonly, bad_sig));

    // Byte-exact SIGN KAT: signing with Bob's key (privkey 0x4242..42) and
    // BIP-340 aux_rand = 0 reproduces the published 64-byte signature exactly
    // (the vector's own signing convention — verified against signature-test.json).
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const bob_sk = try bip340.SecretKey.fromBytes([_]u8{0x42} ** 32);
    const signed = try signMerkle(allocator, stream.items, invoice_request_sig_tag, bob_sk, [_]u8{0} ** 32, io);
    try testing.expectEqualSlices(u8, sig_buf, &signed);
}

// End-to-end decode of the KAT `lnr1...` string through the bech32/bitpack/TLV
// path, then verify via the typed API. Same vector, exercising the decoder.
test "BOLT#12 KAT: decode lnr1 invoice_request string end-to-end + verify" {
    const allocator = testing.allocator;
    const lnr = "lnr1qqyqqqqqqqqqqqqqqcp4256ypqqkgzshgysy6ct5dpjk6ct5d93kzmpq23ex2ct5d9ek293pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpjkppqvjx204vgdzgsqpvcp4mldl3plscny0rt707gvpdh6ndydfacz43euzqhrurageg3n7kafgsek6gz3e9w52parv8gs2hlxzk95tzeswywffxlkeyhml0hh46kndmwf4m6xma3tkq2lu04qz3slje2rfthc89vss";

    var ir = try decodeInvoiceRequest(allocator, lnr);
    defer ir.deinit(allocator);
    try testing.expectEqual(@as(?u64, 100), ir.offer_amount);
    try testing.expectEqualStrings("USD", ir.offer_currency.?);
    try testing.expectEqualStrings("A Mathematical Treatise", ir.offer_description.?);
    try testing.expectEqual(@as(usize, 8), ir.invreq_metadata.?.len);
    try testing.expect(ir.invreq_payer_id != null);
    try testing.expect(ir.signature != null);
    // Its embedded signature verifies against its own payer_id.
    try testing.expect(try ir.verify(allocator));

    // Reject-tooth: corrupt a value byte in the stream → verify fails.
    ir.raw[3] ^= 0x01;
    try testing.expect(!try ir.verify(allocator));
}

test "BOLT#12 round-trip: build+sign+decode+verify an invoice_request" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sk = try bip340.SecretKey.fromBytes([_]u8{0x11} ** 32);
    const kp = try bip340.KeyPair.fromSecretKey(sk);
    var payer_id: [33]u8 = undefined;
    payer_id[0] = 0x02; // BIP-340 pubkey is always even-y
    payer_id[1..33].* = kp.public.x;

    const metadata = [_]u8{0xab} ** 8;
    const records = [_]lnwire.RawRecord{
        .{ .type = IREQ_METADATA, .value = &metadata },
        .{ .type = TYPE_CURRENCY, .value = "EUR" },
        .{ .type = TYPE_AMOUNT, .value = &.{0x64} }, // 100
        .{ .type = INVREQ_PAYER_ID, .value = &payer_id },
    };
    const lnr = try encodeSignedInvoiceRequest(allocator, &records, sk, [_]u8{0} ** 32, io);
    defer allocator.free(lnr);
    try testing.expect(std.mem.startsWith(u8, lnr, "lnr1"));

    var ir = try decodeInvoiceRequest(allocator, lnr);
    defer ir.deinit(allocator);
    try testing.expectEqualStrings("EUR", ir.offer_currency.?);
    try testing.expect(try ir.verify(allocator));

    // Wrong signer: swap in a different valid pubkey → verify fails.
    const sk2 = try bip340.SecretKey.fromBytes([_]u8{0x22} ** 32);
    const kp2 = try bip340.KeyPair.fromSecretKey(sk2);
    var other = payer_id;
    other[1..33].* = kp2.public.x;
    ir.invreq_payer_id = other;
    try testing.expect(!try ir.verify(allocator));
}

test "BOLT#12 round-trip: build+sign+decode+verify an invoice" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sk = try bip340.SecretKey.fromBytes([_]u8{0x33} ** 32);
    const kp = try bip340.KeyPair.fromSecretKey(sk);
    var node_id: [33]u8 = undefined;
    node_id[0] = 0x02;
    node_id[1..33].* = kp.public.x;

    const payment_hash = [_]u8{0xcd} ** 32;
    const records = [_]lnwire.RawRecord{
        .{ .type = INVOICE_CREATED_AT, .value = &.{ 0x66, 0x00, 0x00, 0x00 } },
        .{ .type = INVOICE_PAYMENT_HASH, .value = &payment_hash },
        .{ .type = INVOICE_AMOUNT, .value = &.{ 0x27, 0x10 } }, // 10000
        .{ .type = INVOICE_NODE_ID, .value = &node_id },
    };
    const lni = try encodeSignedInvoice(allocator, &records, sk, [_]u8{0} ** 32, io);
    defer allocator.free(lni);
    try testing.expect(std.mem.startsWith(u8, lni, "lni1"));

    var inv = try decodeInvoice(allocator, lni);
    defer inv.deinit(allocator);
    try testing.expectEqual(@as(?u64, 10000), inv.invoice_amount);
    try testing.expectEqualSlices(u8, &payment_hash, &inv.invoice_payment_hash.?);
    try testing.expect(try inv.verify(allocator));

    // Reject-tooth: tamper a value byte → verify fails.
    inv.raw[2] ^= 0x01;
    try testing.expect(!try inv.verify(allocator));
}

// Byte-exact external KAT for the `invoice` (`lni1`) Merkle root + signature
// — closes the gap the module doc comment used to describe as unclosable
// ("the official bolt12/signature-test.json ships an invoice_request worked
// example but no invoice one"). That claim was true of `signature-test.json`
// specifically, but NOT of the `bolt12/` directory as a whole: a full
// `invoice` worked example (Merkle root, sighash, and BIP-340 signature) is
// published in the sibling file `bolt12/payer-proof-test.json` (`lightning/
// bolts`, "full_disclosure" vector), fetched from
// `raw.githubusercontent.com/lightning/bolts/master/bolt12/payer-proof-test.json`
// 2026-07-28 and reproduced byte-for-byte below (`invoice_hex`/
// `invoice_merkle_root`/`invoice_signature`/the `invoice_node_id` keypair —
// no byte hand-edited). `merkleRoot`/`verifyMerkle` run directly over the
// raw TLV stream (not through `decodeInvoice`) since the vector carries
// several payer-proof-specific field types (e.g. a private/experimental
// type `3000000001`) this module's typed `Invoice` decoder doesn't model —
// the Merkle/signature core under test doesn't need field-level semantics.
test "BOLT#12 KAT: invoice Merkle root + signature verify — payer-proof-test.json 'full_disclosure'" {
    const allocator = testing.allocator;
    const invoice_hex = "0010000000000000000000000000000000001621024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382520203e858210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca076027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991" ++
        "0102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000a21c00000001000000020003000000000000000400000000000000050000a40467527988a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793aa0203e8ae0d08000000000000000000000000b021024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382f040fbb932e6a9d5b4d88ca0ddc9cf9f8cc880ef41e3ec9574da89f624db898ab3e9d3ed6caa8744633b855167da009119d9834ae71f7b06f02732dc4c1debab0577feb2d05e010142";
    const want_merkle = "cb9e0c81bb39fc244f9f523c748ab4de0e09f1a5fef74359c2e1f7cc7cdc7447";
    const invoice_signature = "fbb932e6a9d5b4d88ca0ddc9cf9f8cc880ef41e3ec9574da89f624db898ab3e9d3ed6caa8744633b855167da009119d9834ae71f7b06f02732dc4c1debab0577";
    // `invoice_node_id` (== `offer_issuer_id` here), x-only (33-byte
    // compressed pubkey with the leading 0x02/0x03 parity byte stripped).
    const invoice_node_id_xonly = "4bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382";

    const stream = try hexAlloc(allocator, invoice_hex);
    defer allocator.free(stream);

    const want_root = try hexAlloc(allocator, want_merkle);
    defer allocator.free(want_root);
    const root = try merkleRoot(allocator, stream);
    try testing.expectEqualSlices(u8, want_root, &root);

    const xonly_buf = try hexAlloc(allocator, invoice_node_id_xonly);
    defer allocator.free(xonly_buf);
    const xonly = xonly_buf[0..32].*;
    const sig_buf = try hexAlloc(allocator, invoice_signature);
    defer allocator.free(sig_buf);
    const sig = sig_buf[0..64].*;
    try testing.expect(try verifyMerkle(allocator, stream, invoice_sig_tag, xonly, sig));

    // Teeth: flip one signature bit → verify fails (not errors).
    var bad_sig = sig;
    bad_sig[10] ^= 0x01;
    try testing.expect(!try verifyMerkle(allocator, stream, invoice_sig_tag, xonly, bad_sig));
}

// Byte-exact external KAT for `invoice` ENCODE — closes the last gap
// ANCHOR-TASKS.tsv named for this module ("invoice_request/invoice's
// non-signature TLV-to-wire-string ENCODE is round-trip (build+decode+
// verify) tested only, not byte-compared against an official lnr1/lni1
// string"). `invoice_request` ENCODE already had one KAT string available
// (`signature-test.json`'s own `"bolt12"` field, used below in the
// "decode lnr1 ... end-to-end" test — that test only ever drove it through
// OUR decoder, never OUR encoder), but `invoice` had none until this vector
// was found: `payer-proof-test.json`'s `valid_vectors` array (the same file
// already used above for the Merkle-root/signature KAT, there via
// `valid_vectors[0]` "full_disclosure") carries a complete signed
// `lni1...` wire string in each `input.invoice` field (fetched from the
// same pinned commit as the rest of this module's BOLT#12 vectors — see
// `../NOTICE`).
//
// The first attempt at this anchor used `valid_vectors[0]`
// ("full_disclosure") directly and it did NOT match byte-exact: that
// vector's `invoice_hex` carries a private/experimental TLV (type
// 3000000001) positioned AFTER the type-240 signature record (ascending
// order: 240 < 3000000001), and `encodeSignedInvoice` at the time
// unconditionally appended the signature LAST, after every caller-supplied
// record — producing [...176, 3000000001, SIGNATURE] instead of the
// vector's [...176, SIGNATURE, 3000000001]. That was not a test-setup
// mismatch, it was `encodeSignedInvoice` emitting a stream BOLT#12's own
// ascending-type-order rule forbids. Fixed (this pass): `encodeSignedInvoice`/
// `encodeSignedInvoiceRequest` now insert the signature via the shared
// `appendSignedStream` helper, splitting `unsigned_records` at type 240
// instead of assuming everything comes before it — see that helper's doc
// comment. The signing computation (`signMerkle` over the unsigned stream
// in its original order) is untouched, so the pre-existing Merkle-root/
// signature KATs above stay byte-identical; only the OUTPUT assembly
// changed. `valid_vectors[0]` "full_disclosure" is used below specifically
// because it is the vector that exercises the fix (the one with a
// type > 240 field); `valid_vectors[1]` "minimal_disclosure" (no field
// above type 240) is kept alongside it as the ordinary-invoice case, which
// costs nothing extra and covers the common path unaffected by the split.
const invoice_encode_kat_fields = [_]struct { type: u64, hex: []const u8 }{
    .{ .type = 0, .hex = "00000000000000000000000000000000" },
    .{ .type = 22, .hex = "024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382" },
    .{ .type = 82, .hex = "03e8" },
    .{ .type = 88, .hex = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c" },
    .{ .type = 160, .hex = "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000" },
    .{ .type = 162, .hex = "00000001000000020003000000000000000400000000000000050000" },
    .{ .type = 164, .hex = "67527988" },
    .{ .type = 168, .hex = "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793" },
    .{ .type = 170, .hex = "03e8" },
    .{ .type = 176, .hex = "024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382" },
};
const invoice_encode_kat_want = "lni1qqgqqqqqqqqqqqqqqqqqqqqqqqqqq93pqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyecy5szq059sggry3jnatzrgjyqqtxqdwlm0ug0uxyerc6lnljrqtd75mfr20wq4vw2qasz0uc7h32x9s0aecdhxlk075kn046aafpuuyw8f5j652t3vha2yqrsxtqt0nu4xf9q05znnzeyq96dcrptu3zdj6c4n2nv0aa3ue5xszv3qypwm2aaz66peqm3hyh09uzvzxzmfupmdhx49w5m0rva0jyu3u3pz3gqzqqqqqqqqqqqqqqqqqqqqqqqqqq2y8qqqqqqzqqqqqpqqqcqqqqqqqqqqqzqqqqqqqqqqqq9qqq2gpr82fuc32pqwtxkappzcsrlkmgfs6g0zyct0hkhashh7hsaxz7e65slq9fkx7f65qsrazczzqjtc233yeg48ur7wrst4vy8ynntsh3p07xdv2xwkc5hgfrmkjfnstcyqz3nyfzk3d42umkj2gqjh4l7zpevq04aefl6gnu4kql3e5ymu29s4q7fcvsst9uvmqx6q6yhje3vsraqple9pnxuf5vtwz0l68r6uvvs";

test "BOLT#12 KAT: invoice ENCODE byte-exact against lni1 string — payer-proof-test.json 'minimal_disclosure'" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var values: std.ArrayList([]u8) = .empty;
    defer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }
    var records: std.ArrayList(lnwire.RawRecord) = .empty;
    defer records.deinit(allocator);
    for (invoice_encode_kat_fields) |f| {
        const val = try hexAlloc(allocator, f.hex);
        try values.append(allocator, val);
        try records.append(allocator, .{ .type = f.type, .value = val });
    }

    // `invoice_node_id`'s own secret key from `payer-proof-test.json`'s
    // "keys" object (secret 0x46 repeated 32 times, same as the KAT above).
    const sk = try bip340.SecretKey.fromBytes([_]u8{0x46} ** 32);
    const got = try encodeSignedInvoice(allocator, records.items, sk, [_]u8{0} ** 32, io);
    defer allocator.free(got);

    try testing.expectEqualStrings(invoice_encode_kat_want, got);

    // Decode our freshly-built string and check the typed fields the
    // module's decoder does model, so a future failure names which side
    // (encoder vs. decoder) broke.
    var inv = try decodeInvoice(allocator, got);
    defer inv.deinit(allocator);
    try testing.expectEqual(@as(?u64, 0x67527988), inv.invoice_created_at);
    try testing.expectEqual(@as(?u64, 0x03e8), inv.invoice_amount);
    const want_payment_hash = try hexAlloc(allocator, "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793");
    defer allocator.free(want_payment_hash);
    try testing.expectEqualSlices(u8, want_payment_hash, &inv.invoice_payment_hash.?);
    try testing.expect(try inv.verify(allocator));
}

// `valid_vectors[0]` "full_disclosure" — same fields as
// `invoice_encode_kat_fields` above PLUS `invoice_features` (type 174,
// ordinary, sits before `invoice_node_id`) PLUS a private/experimental TLV
// (type 3000000001, sits AFTER the type-240 signature in the official wire
// stream). This is the vector that actually exercises `appendSignedStream`'s
// split: with the pre-fix "always append signature last" behavior this
// test failed (see the comment block above the "minimal_disclosure" test).
test "BOLT#12 KAT: invoice ENCODE byte-exact against lni1 string — payer-proof-test.json 'full_disclosure' (exercises the type>240 split)" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const fields = [_]struct { type: u64, hex: []const u8 }{
        .{ .type = 0, .hex = "00000000000000000000000000000000" },
        .{ .type = 22, .hex = "024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382" },
        .{ .type = 82, .hex = "03e8" },
        .{ .type = 88, .hex = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c" },
        .{ .type = 160, .hex = "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910102edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145001000000000000000000000000000000000" },
        .{ .type = 162, .hex = "00000001000000020003000000000000000400000000000000050000" },
        .{ .type = 164, .hex = "67527988" },
        .{ .type = 168, .hex = "72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793" },
        .{ .type = 170, .hex = "03e8" },
        .{ .type = 174, .hex = "08000000000000000000000000" },
        .{ .type = 176, .hex = "024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382" },
        .{ .type = 3000000001, .hex = "42" },
    };
    const want_lni1 = "lni1qqgqqqqqqqqqqqqqqqqqqqqqqqqqq93pqf9u9gcjv52n7pl8pc96kzrjfe4ctcshlrxk9r8tv2t5y3amfyecy5szq059sggry3jnatzrgjyqqtxqdwlm0ug0uxyerc6lnljrqtd75mfr20wq4vw2qasz0uc7h32x9s0aecdhxlk075kn046aafpuuyw8f5j652t3vha2yqrsxtqt0nu4xf9q05znnzeyq96dcrptu3zdj6c4n2nv0aa3ue5xszv3qypwm2aaz66peqm3hyh09uzvzxzmfupmdhx49w5m0rva0jyu3u3pz3gqzqqqqqqqqqqqqqqqqqqqqqqqqqq2y8qqqqqqzqqqqqpqqqcqqqqqqqqqqqzqqqqqqqqqqqq9qqq2gpr82fuc32pqwtxkappzcsrlkmgfs6g0zyct0hkhashh7hsaxz7e65slq9fkx7f65qsrazhq6zqqqqqqqqqqqqqqqqqqqzczzqjtc233yeg48ur7wrst4vy8ynntsh3p07xdv2xwkc5hgfrmkjfnstcyp7aextn2n4d5mzx2phwfe70cejyqaaq78my4wndgna3ymwyc4vlf60kke258g33nhp23vldqpygemxp54ecl0vr0qfejm3xpm6atq4mlavkstcqszss";

    var values: std.ArrayList([]u8) = .empty;
    defer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }
    var records: std.ArrayList(lnwire.RawRecord) = .empty;
    defer records.deinit(allocator);
    for (fields) |f| {
        const val = try hexAlloc(allocator, f.hex);
        try values.append(allocator, val);
        try records.append(allocator, .{ .type = f.type, .value = val });
    }

    const sk = try bip340.SecretKey.fromBytes([_]u8{0x46} ** 32);
    const got = try encodeSignedInvoice(allocator, records.items, sk, [_]u8{0} ** 32, io);
    defer allocator.free(got);

    try testing.expectEqualStrings(want_lni1, got);

    // Decode + verify, same posture as the "minimal_disclosure" test above.
    // `decodeInvoice`'s typed decoder does not model type 3000000001 (an
    // unknown ODD type, silently skipped per BOLT#1's "ok to be odd" rule —
    // see `known_invoice_types`), so it does not appear in `inv` below; the
    // point of this test is the byte-exact ENCODE match plus confirming the
    // typed fields BOLT#12 does define still round-trip correctly.
    var inv = try decodeInvoice(allocator, got);
    defer inv.deinit(allocator);
    try testing.expectEqual(@as(?u64, 0x67527988), inv.invoice_created_at);
    try testing.expectEqual(@as(?u64, 0x03e8), inv.invoice_amount);
    try testing.expect(try inv.verify(allocator));
}

test "BOLT#12 Merkle: signature TLVs (240-1000) are excluded from the tree" {
    const allocator = testing.allocator;
    // Two data records + a fake type-240 record; the root must equal the
    // root over the two data records alone.
    const data = "010203e802080000010000020003";
    var with_sig: std.ArrayList(u8) = .empty;
    defer with_sig.deinit(allocator);
    const data_bytes = try hexAlloc(allocator, data);
    defer allocator.free(data_bytes);
    try with_sig.appendSlice(allocator, data_bytes);
    // type=240 (0xf0), len=2, value=0xdead — must be ignored by merkleRoot.
    try with_sig.appendSlice(allocator, &.{ 0xf0, 0x02, 0xde, 0xad });

    const r_with = try merkleRoot(allocator, with_sig.items);
    const r_data = try merkleRoot(allocator, data_bytes);
    try testing.expectEqualSlices(u8, &r_data, &r_with);
}

test "BOLT#12 Merkle: signature-type exclusion range [240,1000] is a range, not just its lower bound" {
    // F3: the only existing boundary case above uses type=240; that alone
    // cannot distinguish `isSignatureType`'s real range check
    // (`t >= 240 and t <= 1000`) from a degenerate `t == 240`. Types 241-999
    // are all odd-numbered in BOLT#12's own fixtures except 240 itself, and
    // no vendored vector carries a signature-range TLV other than exactly
    // type 240 — so both the fact that the exclusion is a RANGE (not one
    // value) and its upper edge (1000 excluded, 1001 included) are unpinned
    // without this. Type 999 (odd, top of the excluded range) must still be
    // dropped exactly like 240; type 1001 (odd, just past the range) must
    // be walked as an ordinary leaf.
    const allocator = testing.allocator;
    const data = "010203e802080000010000020003";
    const data_bytes = try hexAlloc(allocator, data);
    defer allocator.free(data_bytes);
    const r_data = try merkleRoot(allocator, data_bytes);

    // type=999 (BigSize 0xfd03e7), len=2, value=0xdead — top of the excluded
    // range; must still be ignored, same as type=240.
    var with_999: std.ArrayList(u8) = .empty;
    defer with_999.deinit(allocator);
    try with_999.appendSlice(allocator, data_bytes);
    try with_999.appendSlice(allocator, &.{ 0xfd, 0x03, 0xe7, 0x02, 0xde, 0xad });
    const r_999 = try merkleRoot(allocator, with_999.items);
    try testing.expectEqualSlices(u8, &r_data, &r_999);

    // type=1000 (BigSize 0xfd03e8) — the exact upper edge, still inclusive
    // per BOLT#12; must also be ignored.
    var with_1000: std.ArrayList(u8) = .empty;
    defer with_1000.deinit(allocator);
    try with_1000.appendSlice(allocator, data_bytes);
    try with_1000.appendSlice(allocator, &.{ 0xfd, 0x03, 0xe8, 0x02, 0xde, 0xad });
    const r_1000 = try merkleRoot(allocator, with_1000.items);
    try testing.expectEqualSlices(u8, &r_data, &r_1000);

    // type=1001 (BigSize 0xfd03e9), len=2, value=0xbeef — just past the
    // range; MUST be walked as an ordinary leaf, changing the root.
    var with_1001: std.ArrayList(u8) = .empty;
    defer with_1001.deinit(allocator);
    try with_1001.appendSlice(allocator, data_bytes);
    try with_1001.appendSlice(allocator, &.{ 0xfd, 0x03, 0xe9, 0x02, 0xbe, 0xef });
    const r_1001 = try merkleRoot(allocator, with_1001.items);
    try testing.expect(!std.mem.eql(u8, &r_data, &r_1001));
}

test "BOLT#12 Merkle: hostile inputs fail closed" {
    const allocator = testing.allocator;
    // Declared length overruns the buffer.
    const trunc = try hexAlloc(allocator, "0105aabb");
    defer allocator.free(trunc);
    try testing.expectError(error.Truncated, merkleRoot(allocator, trunc));
    // Empty (signable-message) stream.
    try testing.expectError(error.EmptyMerkleStream, merkleRoot(allocator, ""));
    // A stream of ONLY a signature TLV → no leaves.
    try testing.expectError(error.EmptyMerkleStream, merkleRoot(allocator, &.{ 0xf0, 0x01, 0x00 }));
}

test "BOLT#12: wrong prefix rejected for lnr / lni decoders" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnknownPrefix, decodeInvoiceRequest(allocator, "lno1qqqq"));
    try testing.expectError(error.UnknownPrefix, decodeInvoice(allocator, "lnr1qqqq"));
}

// ── fuzz: the checksum-LESS BOLT#12 parsers ──────────────────────────────
//
// This file needs a harness of its OWN even though the module already
// appears in `scripts/fuzz-sweep.sh`: that script derives its target list
// with `grep -rl 'testing.fuzz(' modules/*/src/*.zig`, i.e. at MODULE
// granularity, so `bech32_raw.zig`'s and `bolt11.zig`'s harnesses were
// making `lninvoice` look covered while every entry point in this file
// contributed nothing to the sweep.
//
// The exposure is strictly larger here than in `bolt11.zig`. A BOLT#11
// invoice is bech32-checksummed, so an arbitrary string dies at
// `InvalidChecksum` with probability 1 - 2^-30 and never reaches the
// parser (which is why that file's harness routes through `encode`).
// BOLT#12 has **no checksum at all** ("There is no checksum, unlike
// bech32m"), so *every* byte string a user scans off a QR code or pastes
// from a web page walks straight into `stripContinuation`, the bit
// unpacker, `lnwire.parseTlvStream`, the per-record semantic checks and
// `merkleRoot`'s recursive tree builder.
//
// Structure, not entropy: the interesting machinery is behind a TLV
// stream, and uniform bytes rarely produce a walkable one. So the harness
// generates the TLV records itself (BigSize type + BigSize length + value,
// with the type biased toward the real offer/invoice_request/invoice
// numbers and toward the 240..1000 signature range that `merkleRoot`
// excludes), then feeds those bytes BOTH raw to `merkleRoot` and, wrapped
// by the module's own `encodeNoChecksum`, to all three string decoders.
// A minority of iterations skip the generator and use raw entropy, and a
// minority mutate the finished string (case, `+` continuations, stray
// bytes) so the envelope's own reject paths are exercised too.
//
// Reachability was checked, not assumed: with a temporary `@panic` fired
// when `decodeOffer`'s `parseTlvStream` returned TWO OR MORE records —
// i.e. the envelope, the bit unpacker and the whole BOLT#1 TLV walk
// (ascending types, no unknown-even) all cleared — a 90 s
// `scripts/fuzz-sweep.sh` run found it. Probe then removed. `merkleRoot`
// needs no such check: the harness hands it raw bytes directly.
test "fuzz: BOLT#12 decoders and merkleRoot never panic on arbitrary input" {
    try testing.fuzz({}, fuzzBolt12, .{});
}

/// Minimal BigSize (BOLT#1) writer — the harness's own, so a bug in the
/// module's encoder cannot quietly stop the harness reaching the parser.
fn fuzzPutBigSize(buf: []u8, v: u64) usize {
    if (v < 0xfd) {
        buf[0] = @intCast(v);
        return 1;
    } else if (v <= 0xffff) {
        buf[0] = 0xfd;
        std.mem.writeInt(u16, buf[1..3], @intCast(v), .big);
        return 3;
    } else if (v <= 0xffff_ffff) {
        buf[0] = 0xfe;
        std.mem.writeInt(u32, buf[1..5], @intCast(v), .big);
        return 5;
    } else {
        buf[0] = 0xff;
        std.mem.writeInt(u64, buf[1..9], v, .big);
        return 9;
    }
}

fn fuzzBolt12(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;

    // ── 1. the raw TLV stream ────────────────────────────────────────────
    var tlv: [512]u8 = undefined;
    var n: usize = 0;
    if (smith.boolWeighted(1, 7)) {
        n = smith.slice(&tlv); // pure entropy, the minority case
    } else {
        // BOLT#1 requires STRICTLY ASCENDING types, and rejects an unknown
        // EVEN one — so a stream of independently-drawn types is thrown out
        // by `parseTlvStream` before any of this file's own logic runs.
        // Two thirds of records therefore walk the real offer type list
        // upward, which is what actually gets the harness past the TLV
        // walk and into the per-record semantics.
        var offer_idx: usize = 0;
        var first_offer = true;
        while (n + 32 < tlv.len and !smith.eosWeightedSimple(3, 1)) {
            const t: u64 = if (smith.boolWeighted(1, 2)) blk: {
                const step: usize = if (first_offer)
                    smith.valueRangeAtMost(u8, 0, 3)
                else
                    smith.valueRangeAtMost(u8, 1, 3);
                first_offer = false;
                offer_idx = @min(offer_idx + step, known_offer_types.len - 1);
                break :blk known_offer_types[offer_idx];
            } else switch (smith.value(enum { ireq, invoice, sig_range, tiny, huge })) {
                // The invoice_request / invoice number spaces, spanning the
                // 240..1000 signature exclusion on both sides.
                .ireq => smith.valueRangeAtMost(u16, 0, 250),
                .invoice => smith.valueRangeAtMost(u16, 160, 260),
                .sig_range => smith.valueRangeAtMost(u16, 235, 1005),
                .tiny => smith.value(u8),
                .huge => smith.value(u64),
            };
            var hdr: [9]u8 = undefined;
            const tl = fuzzPutBigSize(&hdr, t);
            if (n + tl >= tlv.len) break;
            @memcpy(tlv[n..][0..tl], hdr[0..tl]);
            n += tl;

            // The declared length is deliberately allowed to disagree with
            // what follows: `parseTlvStream`/`merkleRoot` must fail closed
            // on an over-claim rather than slice past the buffer.
            const claimed: u64 = if (smith.boolWeighted(6, 1))
                smith.valueRangeAtMost(u8, 0, 40)
            else
                smith.value(u64);
            const ll = fuzzPutBigSize(&hdr, claimed);
            if (n + ll >= tlv.len) break;
            @memcpy(tlv[n..][0..ll], hdr[0..ll]);
            n += ll;

            const want: usize = @min(@as(usize, @intCast(@min(claimed, 64))), tlv.len - n);
            n += smith.slice(tlv[n..][0..want]);
        }
    }
    const stream = tlv[0..n];

    // ── 2. merkleRoot, straight over the raw bytes ───────────────────────
    _ = merkleRoot(allocator, stream) catch {};

    // ── 3. the same bytes inside each string envelope ────────────────────
    const quintets = try bitpack.bytesToQuintets(allocator, stream);
    defer allocator.free(quintets);

    const hrps = [_][]const u8{ "lno", "lnr", "lni", "ln", "lnbc" };
    const hrp = hrps[smith.index(hrps.len)];
    const encoded = bech32raw.encodeNoChecksum(allocator, hrp, quintets) catch return;
    defer allocator.free(encoded);

    // Optional string-level damage: uppercase runs, `+` continuations and
    // out-of-charset bytes all have their own paths in `stripContinuation`
    // / `decodeNoChecksum`.
    var str_buf: [1024]u8 = undefined;
    var s: []const u8 = encoded;
    if (encoded.len <= str_buf.len and encoded.len > 0 and smith.boolWeighted(2, 1)) {
        @memcpy(str_buf[0..encoded.len], encoded);
        var muts: usize = 0;
        while (muts < 8 and !smith.eosWeightedSimple(3, 1)) : (muts += 1) {
            const i = smith.index(encoded.len);
            str_buf[i] = switch (smith.value(enum { plus, space, upper, byte })) {
                .plus => '+',
                .space => ' ',
                .upper => std.ascii.toUpper(str_buf[i]),
                .byte => smith.value(u8),
            };
        }
        s = str_buf[0..encoded.len];
    }

    if (decodeOffer(allocator, s)) |off| {
        var o = off;
        o.deinit(allocator);
    } else |_| {}
    if (decodeInvoiceRequest(allocator, s)) |ireq| {
        var r = ireq;
        r.deinit(allocator);
    } else |_| {}
    if (decodeInvoice(allocator, s)) |inv| {
        var v = inv;
        v.deinit(allocator);
    } else |_| {}
}
