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
    OutOfMemory,
};

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
    var pubkey_bytes: [pubkey_max_bytes]u8 = undefined;
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

    // Beacon ID label.
    var beacon_id_buf: [max_beacon_id_bytes]u8 = undefined;
    var beacon_id_len: usize = 0;
    if (raw.metadata) |m| {
        if (m.beaconID) |id| {
            if (id.len > max_beacon_id_bytes) return error.InvalidLength;
            @memcpy(beacon_id_buf[0..id.len], id);
            beacon_id_len = id.len;
        }
    }

    return .{
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

test "parseInfo: bad hex in public_key → InvalidHex" {
    const bad = "{\"public_key\":\"zzzz\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.InvalidHex, parseInfo(testing.allocator, bad));
}

test "parseInfo: wrong-length key for quicknet → InvalidLength" {
    // 47 bytes of hex (94 chars, even) — decodes fine but is not 96.
    const bad = "{\"public_key\":\"" ++ ("ab" ** 47) ++ "\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    try testing.expectError(error.InvalidLength, parseInfo(testing.allocator, bad));
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

test "parseInfo: a chained-scheme /info parses but leaves pubkey_g2 null" {
    // A 48-byte (G1) key under the legacy chained scheme: metadata still
    // parses; the point is not decoded (verify would reject the scheme).
    const chained = "{\"public_key\":\"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31\",\"period\":30,\"genesis_time\":1595431050,\"hash\":\"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce\",\"groupHash\":\"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a\",\"schemeID\":\"pedersen-bls-chained\",\"metadata\":{\"beaconID\":\"default\"}}";
    const info = try parseInfo(testing.allocator, chained);
    try testing.expectEqual(Scheme.pedersen_bls_chained, info.scheme);
    try testing.expect(info.pubkey_g2 == null);
    try testing.expectEqual(@as(usize, 48), info.pubkey_len);
    try testing.expectEqualStrings("default", info.beaconId());
}
