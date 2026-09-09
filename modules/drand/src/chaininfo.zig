// SPDX-License-Identifier: MIT

//! chaininfo — parse a drand `/info` chain-information JSON document into
//! a plain-value `ChainInfo` (no retained allocations, no `deinit`).
//!
//! A drand beacon's `/info` endpoint publishes the immutable parameters
//! that pin every round it will ever emit: the group's master public key
//! (`public_key`), the beacon `period` (seconds between rounds),
//! `genesis_time` (the wall-clock instant of round 0/1), the chain
//! `hash`, the `groupHash`, the `schemeID` (which cryptographic scheme
//! the beacon runs), and a `metadata.beaconID` label. Example (mainnet
//! quicknet, RFC-9380 unchained-G1):
//!
//! ```json
//! {
//!   "public_key": "83cf0f28...45a",
//!   "period": 3,
//!   "genesis_time": 1692803367,
//!   "hash": "52db9ba7...e971",
//!   "groupHash": "f477d5c8...5d3e",
//!   "schemeID": "bls-unchained-g1-rfc9380",
//!   "metadata": { "beaconID": "quicknet" }
//! }
//! ```
//!
//! This parser is pure and bounds-checked: a malformed / truncated /
//! oversized document, bad hex, a wrong-length key, a missing field,
//! trailing garbage, or an out-of-range number all yield a typed
//! `ParseError`, never a panic, OOB read, hang, or amplified allocation.
//!
//! Scheme coverage: the master public key is decoded into a `bls12_381`
//! `G2` point ONLY for the sig-on-`G1` scheme family (quicknet's
//! `bls-unchained-g1-rfc9380`), whose key lives in `G2` (96-byte
//! compressed) and is `KeyValidate`d (on-curve + order-`r` subgroup).
//! Other schemes still parse (metadata, hash, period, raw key bytes) but
//! leave `pubkey_g2 == null`; `verify.verifyRound` rejects them with
//! `error.UnsupportedScheme`. See `SPEC.md`.

const std = @import("std");
const bls12_381 = @import("bls12_381");

const g2 = bls12_381.g2;

/// The largest `/info` document this parser will accept, as a guard
/// against an oversized input inducing a large allocation. A real drand
/// `/info` body is well under 1 KiB; 64 KiB is generous headroom while
/// still bounding the arena `std.json` fills.
pub const max_document_bytes: usize = 64 * 1024;

/// Longest `metadata.beaconID` this parser retains. Real beacon IDs are
/// short labels ("quicknet", "default", "fastnet"); anything longer is
/// truncated-rejected with `error.InvalidLength` rather than silently cut.
pub const max_beacon_id_bytes: usize = 64;

/// Compressed-`G2` public-key width (quicknet's master key). Chained
/// schemes carry a 48-byte compressed-`G1` key instead; both fit the
/// raw-bytes buffer below.
const pubkey_max_bytes: usize = g2.compressed_bytes; // 96

pub const ParseError = error{
    /// Input exceeds `max_document_bytes`.
    DocumentTooLarge,
    /// `std.json` could not parse the document as the expected shape
    /// (syntax error, wrong types, missing required field, trailing
    /// garbage, unterminated string, …). One coarse typed error — the
    /// module never panics on any of these.
    MalformedJson,
    /// A hex field contained a non-hex character or an odd length.
    InvalidHex,
    /// A hex field decoded to the wrong number of bytes (e.g. a `hash`
    /// that is not 32 bytes, or a `beaconID` past `max_beacon_id_bytes`).
    InvalidLength,
    /// A decoded public key is not a valid compressed point encoding.
    InvalidPoint,
    /// A decoded public key is a valid point but not in the order-`r`
    /// subgroup (drand `KeyValidate` — a small-subgroup / cofactor
    /// point that a naive verifier would wrongly accept).
    PublicKeyNotInSubgroup,
    /// A numeric field (`period`, `genesis_time`) overflowed `u64`.
    NumberOutOfRange,
    /// `period` is 0. No drand chain has a zero period, and every
    /// round-arithmetic helper divides by it (`expectedRound`), so a
    /// document claiming one is refused at the boundary instead of
    /// becoming a division by zero — SIGFPE in ReleaseFast — later.
    InvalidPeriod,
    /// The document's `hash` is not the chain hash the document's OWN
    /// contents determine (`computeChainHash`). drand's client checks the
    /// same identity (`chain.Info.Hash()`); without it a `/info` carrying
    /// a genuine chain hash and a FOREIGN public key was accepted, and
    /// rounds of the foreign chain then "verified" under the pinned hash
    /// (the A1 audit did exactly that, 5/5 rounds).
    ChainHashMismatch,
    OutOfMemory,
};

/// The beacon id drand treats as "no id": it is NOT folded into the chain
/// hash (`common.IsDefaultBeaconID` in drand/drand).
pub const default_beacon_id = "default";

/// The drand scheme a beacon runs, decoded from `schemeID`. Only
/// `unchained_g1_rfc9380` (quicknet) is verifiable by this module; the
/// others are recognized so callers get a precise `error.UnsupportedScheme`
/// from `verify` rather than a confusing parse failure.
pub const Scheme = enum {
    /// `bls-unchained-g1-rfc9380` — quicknet. Signatures in `G1`,
    /// master public key in `G2`, message = `H1(SHA256(round_be))` under
    /// the RFC-9380 `..._NUL_` `G1` DST. THE scheme this module verifies.
    unchained_g1_rfc9380,
    /// `pedersen-bls-chained` — the legacy default mainnet scheme.
    /// Signatures in `G2`, key in `G1`, message folds in the previous
    /// signature (`H(round || prev_sig)`). Recognized, not verified.
    pedersen_bls_chained,
    /// `bls-unchained-on-g1` — the deprecated pre-RFC-9380 unchained
    /// scheme (reuses the `G2` DST for `G1` hashing — a known
    /// non-conformance). Recognized, not verified.
    bls_unchained_on_g1,
    /// Any other / unknown `schemeID` string.
    other,

    /// Map a drand `schemeID` string to a `Scheme`.
    pub fn fromId(id: []const u8) Scheme {
        if (std.mem.eql(u8, id, "bls-unchained-g1-rfc9380")) return .unchained_g1_rfc9380;
        if (std.mem.eql(u8, id, "pedersen-bls-chained")) return .pedersen_bls_chained;
        if (std.mem.eql(u8, id, "bls-unchained-on-g1")) return .bls_unchained_on_g1;
        return .other;
    }

    /// True iff this module can BLS-verify a round under this scheme
    /// (i.e. quicknet). `verify.verifyRound` returns
    /// `error.UnsupportedScheme` for any scheme where this is false.
    pub fn isVerifiable(self: Scheme) bool {
        return self == .unchained_g1_rfc9380;
    }
};

/// Parsed, validated drand chain information — a plain value type: it
/// owns no heap memory and needs no `deinit`. Copy it freely.
pub const ChainInfo = struct {
    scheme: Scheme,
    /// Seconds between successive beacon rounds.
    period_seconds: u64,
    /// Unix time (seconds) of the beacon's genesis.
    genesis_time: u64,
    /// The chain hash (`hash`) — 32 bytes, identifies which beacon a
    /// round/ciphertext belongs to.
    chain_hash: [32]u8,
    /// The group hash (`groupHash`) — 32 bytes.
    group_hash: [32]u8,
    /// Raw compressed master-public-key bytes (48 for `G1`-key schemes,
    /// 96 for `G2`-key schemes). Always populated; `pubkey_g2` is the
    /// decoded point for the supported scheme only.
    pubkey_bytes: [pubkey_max_bytes]u8,
    pubkey_len: usize,
    /// The master public key decoded into a `bls12_381` `G2` point and
    /// `KeyValidate`d — present only for the sig-on-`G1` scheme
    /// (quicknet). `null` for every other scheme.
    pubkey_g2: ?g2.Affine,
    /// `metadata.beaconID` label bytes (e.g. "quicknet").
    beacon_id_buf: [max_beacon_id_bytes]u8,
    beacon_id_len: usize,

    /// The `metadata.beaconID` label as a slice.
    pub fn beaconId(self: *const ChainInfo) []const u8 {
        return self.beacon_id_buf[0..self.beacon_id_len];
    }

    /// The raw compressed public-key bytes as a slice.
    pub fn publicKeyBytes(self: *const ChainInfo) []const u8 {
        return self.pubkey_bytes[0..self.pubkey_len];
    }
};

/// The chain hash a `/info` document determines by its own contents —
/// drand's `chain.Info.Hash()` (drand/drand v2, `common/chain/info.go`):
///
/// ```
/// SHA-256( u32be(period) ‖ u64be(genesis_time) ‖ public_key_bytes ‖
///          groupHash ‖ beaconID unless "" or "default" )
/// ```
///
/// Cross-checked against drand's own Go implementation on three live
/// chains (quicknet, quicknet-t, the chained default) by the A1 audit;
/// the same three documents pin it in the tests below. `parseInfo`
/// refuses a document whose `hash` field disagrees (`ChainHashMismatch`).
pub fn computeChainHash(info: *const ChainInfo) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var b4: [4]u8 = undefined;
    std.mem.writeInt(u32, &b4, @truncate(info.period_seconds), .big);
    h.update(&b4);
    var b8: [8]u8 = undefined;
    std.mem.writeInt(u64, &b8, info.genesis_time, .big);
    h.update(&b8);
    h.update(info.publicKeyBytes());
    h.update(&info.group_hash);
    const bid = info.beaconId();
    if (bid.len != 0 and !std.mem.eql(u8, bid, default_beacon_id)) h.update(bid);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

// The raw JSON shape drand's `/info` emits. `ignore_unknown_fields`
// tolerates forward-compatible additions; every field this module needs
// is required (a missing one → `std.json`'s `error.MissingField` →
// `MalformedJson`). Numbers are taken as `u64`; an overflow becomes
// `error.Overflow` → `NumberOutOfRange`.
const InfoJson = struct {
    public_key: []const u8,
    period: u64,
    genesis_time: u64,
    hash: []const u8,
    groupHash: []const u8,
    schemeID: []const u8,
    metadata: ?Metadata = null,

    const Metadata = struct {
        beaconID: ?[]const u8 = null,
    };
};

/// Decode a hex string into an exactly-`n`-byte array, mapping every
/// failure to a typed `ParseError`.
fn hexExact(comptime n: usize, hex: []const u8) ParseError![n]u8 {
    if (hex.len != 2 * n) return error.InvalidLength;
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch return error.InvalidHex;
    return out;
}

/// Parse a drand `/info` document. `gpa` is used only transiently (an
/// internal arena, freed before return); the returned `ChainInfo` owns
/// nothing.
pub fn parseInfo(gpa: std.mem.Allocator, bytes: []const u8) ParseError!ChainInfo {
    if (bytes.len > max_document_bytes) return error.DocumentTooLarge;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = std.json.parseFromSliceLeaky(InfoJson, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJson,
    };

    const scheme = Scheme.fromId(raw.schemeID);

    // Fixed-width hashes.
    const chain_hash = try hexExact(32, raw.hash);
    const group_hash = try hexExact(32, raw.groupHash);

    // Public key: decode the raw compressed bytes (48 or 96), then — for
    // the sig-on-G1 family only — decode + KeyValidate the G2 point.
    if (raw.public_key.len == 0 or raw.public_key.len % 2 != 0) return error.InvalidHex;
    const pubkey_nbytes = raw.public_key.len / 2;
    if (pubkey_nbytes > pubkey_max_bytes) return error.InvalidLength;
    // Zeroed, not `undefined`: `ChainInfo` is a plain value callers copy
    // and compare; the bytes past `pubkey_len` must not be whatever the
    // stack held (the audit read a neighbour's leftovers there).
    var pubkey_bytes: [pubkey_max_bytes]u8 = [_]u8{0} ** pubkey_max_bytes;
    _ = std.fmt.hexToBytes(pubkey_bytes[0..pubkey_nbytes], raw.public_key) catch return error.InvalidHex;

    var pubkey_g2: ?g2.Affine = null;
    if (scheme.isVerifiable()) {
        if (pubkey_nbytes != g2.compressed_bytes) return error.InvalidLength;
        const pt = g2.fromBytesCompressed(pubkey_bytes[0..g2.compressed_bytes].*) catch return error.InvalidPoint;
        // drand KeyValidate: reject identity and non-subgroup keys.
        if (pt.infinity) return error.InvalidPoint;
        if (!g2.Jacobian.fromAffine(pt).subgroupCheck()) return error.PublicKeyNotInSubgroup;
        pubkey_g2 = pt;
    }

    // No chain has period 0; refusing it here keeps `expectedRound` total.
    if (raw.period == 0) return error.InvalidPeriod;
    // The chain hash must fit in drand's u32 period field to be derivable.
    if (raw.period > std.math.maxInt(u32)) return error.NumberOutOfRange;

    // Beacon ID label.
    var beacon_id_buf: [max_beacon_id_bytes]u8 = [_]u8{0} ** max_beacon_id_bytes;
    var beacon_id_len: usize = 0;
    if (raw.metadata) |m| {
        if (m.beaconID) |id| {
            if (id.len > max_beacon_id_bytes) return error.InvalidLength;
            @memcpy(beacon_id_buf[0..id.len], id);
            beacon_id_len = id.len;
        }
    }

    const info: ChainInfo = .{
        .scheme = scheme,
        .period_seconds = raw.period,
        .genesis_time = raw.genesis_time,
        .chain_hash = chain_hash,
        .group_hash = group_hash,
        .pubkey_bytes = pubkey_bytes,
        .pubkey_len = pubkey_nbytes,
        .pubkey_g2 = pubkey_g2,
        .beacon_id_buf = beacon_id_buf,
        .beacon_id_len = beacon_id_len,
    };
    // The document must name the chain it actually describes.
    if (!std.mem.eql(u8, &computeChainHash(&info), &info.chain_hash)) return error.ChainHashMismatch;
    return info;
}

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

// Genuine mainnet quicknet `/info` (fetched from
// `https://api.drand.sh/v2/beacons/quicknet/info`; the same public_key /
// chain hash `tlock`'s KAT harness pins live).
const quicknet_info_json =
    \\{
    \\  "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    \\  "period": 3,
    \\  "genesis_time": 1692803367,
    \\  "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    \\  "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
    \\  "schemeID": "bls-unchained-g1-rfc9380",
    \\  "metadata": { "beaconID": "quicknet" }
    \\}
;

test "parseInfo: genuine quicknet /info round-trips into a typed ChainInfo" {
    const info = try parseInfo(testing.allocator, quicknet_info_json);
    try testing.expectEqual(Scheme.unchained_g1_rfc9380, info.scheme);
    try testing.expectEqual(@as(u64, 3), info.period_seconds);
    try testing.expectEqual(@as(u64, 1692803367), info.genesis_time);
    try testing.expectEqualStrings("quicknet", info.beaconId());
    try testing.expectEqual(@as(usize, 96), info.pubkey_len);
    try testing.expect(info.pubkey_g2 != null);

    var expect_hash: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expect_hash, "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971");
    try testing.expectEqualSlices(u8, &expect_hash, &info.chain_hash);
}

test "parseInfo: decoded pubkey is in the G2 subgroup (KeyValidate ran)" {
    const info = try parseInfo(testing.allocator, quicknet_info_json);
    const pk = info.pubkey_g2.?;
    try testing.expect(!pk.infinity);
    try testing.expect(g2.Jacobian.fromAffine(pk).subgroupCheck());
}

/// An on-curve G2 point OUTSIDE the order-r subgroup, found by scanning
/// small x-coordinates (the audit's P9 found one at x = 2). Decompression
/// only checks the curve equation, so only `subgroupCheck` can refuse it.
fn nonSubgroupG2Compressed() ![g2.compressed_bytes]u8 {
    var x: u8 = 1;
    while (x < 255) : (x += 1) {
        var comp = [_]u8{0} ** g2.compressed_bytes;
        comp[0] = 0x80;
        comp[g2.compressed_bytes - 1] = x;
        const pt = g2.fromBytesCompressed(comp) catch continue;
        if (pt.infinity) continue;
        if (!g2.Jacobian.fromAffine(pt).subgroupCheck()) return comp;
    }
    return error.NoTorsionPointFound;
}

/// A quicknet-shaped /info around `pk_hex`, with the `hash` field
/// recomputed so that ONLY the key check can refuse it.
fn infoWithKey(gpa: std.mem.Allocator, pk_hex: []const u8) ![]u8 {
    var tmp: ChainInfo = .{
        .scheme = .unchained_g1_rfc9380,
        .period_seconds = 3,
        .genesis_time = 1692803367,
        .chain_hash = undefined,
        .group_hash = try hexExact(32, "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e"),
        .pubkey_bytes = [_]u8{0} ** pubkey_max_bytes,
        .pubkey_len = pk_hex.len / 2,
        .pubkey_g2 = null,
        .beacon_id_buf = [_]u8{0} ** max_beacon_id_bytes,
        .beacon_id_len = 8,
    };
    _ = try std.fmt.hexToBytes(tmp.pubkey_bytes[0 .. pk_hex.len / 2], pk_hex);
    @memcpy(tmp.beacon_id_buf[0..8], "quicknet");
    const hash = computeChainHash(&tmp);
    return std.fmt.allocPrint(gpa, "{{\"public_key\":\"{s}\",\"period\":3,\"genesis_time\":1692803367,\"hash\":\"{s}\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{{\"beaconID\":\"quicknet\"}}}}", .{ pk_hex, std.fmt.bytesToHex(hash, .lower) });
}

test "parseInfo: an on-curve public key OUTSIDE G2 → PublicKeyNotInSubgroup (audit F14)" {
    // The only key test was positive ("the genuine key IS in the subgroup"),
    // which holds with the check deleted or weakened to isOnCurve. This is
    // the rejection vector; the point is on the curve, so only the subgroup
    // check can catch it.
    const comp = try nonSubgroupG2Compressed();
    const pt = try g2.fromBytesCompressed(comp);
    try testing.expect(g2.Jacobian.fromAffine(pt).isOnCurve());
    const doc = try infoWithKey(testing.allocator, &std.fmt.bytesToHex(comp, .lower));
    defer testing.allocator.free(doc);
    try testing.expectError(error.PublicKeyNotInSubgroup, parseInfo(testing.allocator, doc));
    // Control: the same document shape around the genuine key parses.
    const good = try infoWithKey(testing.allocator, "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a");
    defer testing.allocator.free(good);
    _ = try parseInfo(testing.allocator, good);
}

test "computeChainHash reproduces the published hash of three live chains (drand chain.Info.Hash)" {
    const info = try parseInfo(testing.allocator, quicknet_info_json);
    try testing.expectEqualSlices(u8, &info.chain_hash, &computeChainHash(&info));
    const t = try parseInfo(testing.allocator, quicknet_t_info_json);
    var expect_t: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expect_t, "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5");
    try testing.expectEqualSlices(u8, &expect_t, &computeChainHash(&t));
    const chained = try parseInfo(testing.allocator, chained_default_info_json);
    var expect_d: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expect_d, "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce");
    try testing.expectEqualSlices(u8, &expect_d, &computeChainHash(&chained)); // beaconID "default" is NOT hashed
}

test "parseInfo: a genuine chain hash over a FOREIGN key → ChainHashMismatch (audit F1)" {
    // quicknet's hash and groupHash, quicknet-t's key: accepted before, and
    // 5/5 quicknet-t rounds then verified "as quicknet".
    const forged =
        \\{"public_key":"b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da","period":3,"genesis_time":1692803367,"hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","groupHash":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","schemeID":"bls-unchained-g1-rfc9380","metadata":{"beaconID":"quicknet"}}
    ;
    try testing.expectError(error.ChainHashMismatch, parseInfo(testing.allocator, forged));
    // Any single field the hash covers, altered: groupHash, period, genesis, beaconID.
    const bad_group = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":3,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"" ++ ("00" ** 32) ++ "\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet\"}}";
    try testing.expectError(error.ChainHashMismatch, parseInfo(testing.allocator, bad_group));
    const bad_period = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":30,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet\"}}";
    try testing.expectError(error.ChainHashMismatch, parseInfo(testing.allocator, bad_period));
    const bad_id = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":3,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet2\"}}";
    try testing.expectError(error.ChainHashMismatch, parseInfo(testing.allocator, bad_id));
}

test "parseInfo: period 0 → InvalidPeriod, never a later division by zero (audit F2)" {
    const zero = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":0,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet\"}}";
    try testing.expectError(error.InvalidPeriod, parseInfo(testing.allocator, zero));
}

test "parseInfo: bytes past pubkey_len and beacon_id_len are zero, not stack leftovers (audit F9)" {
    const chained = try parseInfo(testing.allocator, chained_default_info_json);
    try testing.expectEqual(@as(usize, 48), chained.pubkey_len);
    for (chained.pubkey_bytes[48..]) |b| try testing.expectEqual(@as(u8, 0), b);
    for (chained.beacon_id_buf[chained.beacon_id_len..]) |b| try testing.expectEqual(@as(u8, 0), b);
}

/// The live quicknet-t (testnet) /info. An earlier fixture in verify.zig
/// carried a groupHash that did not belong to this chain and nothing
/// noticed; with the chain-hash check that document no longer parses.
pub const quicknet_t_info_json =
    \\{"public_key":"b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da","period":3,"genesis_time":1689232296,"hash":"cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5","groupHash":"40d49d910472d4adb1d67f65db8332f11b4284eecf05c05c5eacd5eef7d40e2d","schemeID":"bls-unchained-g1-rfc9380","metadata":{"beaconID":"quicknet-t"}}
;

/// The live legacy chained mainnet ("default") /info.
pub const chained_default_info_json =
    \\{"public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31","period":30,"genesis_time":1595431050,"hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce","groupHash":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a","schemeID":"pedersen-bls-chained","metadata":{"beaconID":"default"}}
;

test "parseInfo: bad hex in public_key → InvalidHex" {
    const bad = "{\"public_key\":\"zzzz\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.InvalidHex, parseInfo(testing.allocator, bad));
}

test "parseInfo: wrong-length key for quicknet → InvalidLength" {
    // 47 bytes of hex (94 chars, even) — decodes fine but is not 96.
    const bad = "{\"public_key\":\"" ++ ("ab" ** 47) ++ "\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.InvalidLength, parseInfo(testing.allocator, bad));
}

test "parseInfo: huge period (> u32) → NumberOutOfRange" {
    const bad = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":4294967296,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.NumberOutOfRange, parseInfo(testing.allocator, bad));
}

test "parseInfo: identity (infinity) public key for quicknet → InvalidPoint, not silently accepted" {
    // Gap found by mutation testing: the `if (pt.infinity) return
    // error.InvalidPoint;` KeyValidate guard had NO test at all — disabling
    // it left every existing test in this module green. This matters more
    // than an ordinary missing-branch gap: `verify.verifyRoundPoints` (the
    // low-level primitive this module's decoded key ultimately feeds) has
    // no defense of its own against a degenerate identity point — an
    // identity G2 "public key" paired with an identity G1 "signature"
    // forges `e(sig,G2gen) == e(H1(round),pubkey)` for EVERY round (both
    // sides pair to the target-group identity). This parse-time guard is
    // the ONLY thing standing between a malicious/corrupted `/info`
    // document and that forgery for any caller going through
    // `chaininfo.parseInfo` + `verify.verifyRound`.
    //
    // Compressed-G2 identity encoding (see bls12_381 g2.zig
    // `toBytesCompressed`): byte 0 = compression|infinity flags (0xc0),
    // remaining 95 bytes zero.
    const identity_key_hex = "c0" ++ ("00" ** 95);
    const bad = "{\"public_key\":\"" ++ identity_key_hex ++
        "\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.InvalidPoint, parseInfo(testing.allocator, bad));
}

test "parseInfo: missing field → MalformedJson" {
    const bad = "{\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.MalformedJson, parseInfo(testing.allocator, bad));
}

test "parseInfo: trailing garbage → MalformedJson" {
    const bad = quicknet_info_json ++ " trailing";
    try testing.expectError(error.MalformedJson, parseInfo(testing.allocator, bad));
}

test "parseInfo: huge period number → NumberOutOfRange" {
    const bad = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":99999999999999999999999999,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    // std.json maps the u64 overflow to error.Overflow → MalformedJson in
    // our coarse mapping (number-shape errors are structural to json).
    try testing.expectError(error.MalformedJson, parseInfo(testing.allocator, bad));
}

test "parseInfo: oversized document → DocumentTooLarge" {
    const big = try testing.allocator.alloc(u8, max_document_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    try testing.expectError(error.DocumentTooLarge, parseInfo(testing.allocator, big));
}

test "parseInfo: max_document_bytes is pinned at 64 KiB, not just self-referential (A1 F13)" {
    // Same shape as round.zig's version of this test: the oversized-document
    // test above allocates `max_document_bytes + 1`, so it moves WITH the
    // constant and cannot catch it being widened by three orders of
    // magnitude. This pins the actual enforced byte count.
    try testing.expectEqual(@as(usize, 64 * 1024), max_document_bytes);
}

test "parseInfo: a chained-scheme /info parses but leaves pubkey_g2 null" {
    // A 48-byte (G1) key under the legacy chained scheme: metadata still
    // parses; the point is not decoded (verify would reject the scheme).
    const info = try parseInfo(testing.allocator, chained_default_info_json);
    try testing.expectEqual(Scheme.pedersen_bls_chained, info.scheme);
    try testing.expect(info.pubkey_g2 == null);
    try testing.expectEqual(@as(usize, 48), info.pubkey_len);
    try testing.expectEqualStrings("default", info.beaconId());
}
