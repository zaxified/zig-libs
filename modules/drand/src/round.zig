// SPDX-License-Identifier: MIT

//! round — parse a drand `/public/<round>` beacon-round JSON document
//! into a plain-value `Round` (no retained allocations, no `deinit`).
//!
//! A beacon round document carries the `round` number, the threshold-BLS
//! `signature` for that round, the derived `randomness`, and — for the
//! legacy CHAINED scheme only — the `previous_signature` folded into the
//! round's signed message. Example (mainnet quicknet round 1000,
//! unchained — no `previous_signature`):
//!
//! ```json
//! {
//!   "round": 1000,
//!   "randomness": "fe290bec...4fdd",
//!   "signature": "b44679b9...5e39"
//! }
//! ```
//!
//! For the sig-on-`G1` scheme (quicknet), the 48-byte compressed
//! `signature` is decoded into a `bls12_381` `G1` point (the group
//! element `verify` pairs against). The signature is NOT subgroup-checked
//! at parse time — `verify.verifyRound`'s pairing equation is a full BLS
//! verify that rejects an off-subgroup or wrong point; a caller wanting a
//! standalone `KeyValidate` can call `Round.signatureG1` and subgroup-
//! check the result. `randomness`, when present, is retained for the
//! `randomness == SHA-256(signature)` check `verify` performs.
//!
//! The parser is pure and bounds-checked: malformed / truncated /
//! oversized JSON or hex yields a typed `RoundParseError`, never a panic,
//! OOB read, hang, or amplified allocation.

const std = @import("std");
const bls12_381 = @import("bls12_381");

const g1 = bls12_381.g1;

/// The largest `/public/<round>` document this parser accepts. A real
/// round body is ~300 bytes; 64 KiB is generous headroom that still
/// bounds the arena `std.json` fills.
pub const max_document_bytes: usize = 64 * 1024;

const sig_g1_bytes: usize = g1.compressed_bytes; // 48

pub const RoundParseError = error{
    /// Input exceeds `max_document_bytes`.
    DocumentTooLarge,
    /// `std.json` could not parse the document as the expected shape.
    MalformedJson,
    /// A hex field contained a non-hex character or an odd length.
    InvalidHex,
    /// A hex field decoded to the wrong number of bytes.
    InvalidLength,
    /// The signature bytes are not a valid compressed `G1` point.
    InvalidPoint,
    OutOfMemory,
};

/// Parsed, validated drand beacon round — a plain value type owning no
/// heap memory.
pub const Round = struct {
    /// The round number.
    round: u64,
    /// The round's threshold-BLS signature, raw compressed bytes
    /// (48 for `G1`, 96 for `G2` schemes). Retained for the
    /// `randomness == SHA-256(signature)` check.
    sig_bytes: [96]u8,
    sig_len: usize,
    /// The signature decoded into a `bls12_381` `G1` point — present
    /// only when it is a 48-byte compressed `G1` element (quicknet).
    /// `null` for a `G2`-signature (chained) round.
    sig_g1: ?g1.Affine,
    /// `randomness`, if the document carried it (32 bytes). drand
    /// defines `randomness = SHA-256(signature)`.
    randomness: ?[32]u8,
    /// `previous_signature`, if present (chained schemes). Retained as
    /// raw bytes for a future chained-message reconstruction; unused by
    /// quicknet verification.
    previous_signature: ?PreviousSignature,

    pub const PreviousSignature = struct {
        bytes: [96]u8,
        len: usize,
        pub fn slice(self: *const PreviousSignature) []const u8 {
            return self.bytes[0..self.len];
        }
    };

    /// The raw compressed signature bytes as a slice.
    pub fn signatureBytes(self: *const Round) []const u8 {
        return self.sig_bytes[0..self.sig_len];
    }

    /// The signature as a `G1` point, or `error.InvalidPoint` if the
    /// round is not a `G1`-signature round.
    pub fn signatureG1(self: *const Round) RoundParseError!g1.Affine {
        return self.sig_g1 orelse error.InvalidPoint;
    }
};

const RoundJson = struct {
    round: u64,
    signature: []const u8,
    randomness: ?[]const u8 = null,
    previous_signature: ?[]const u8 = null,
};

fn decodeHexVar(dst: []u8, hex: []const u8) RoundParseError!usize {
    if (hex.len == 0 or hex.len % 2 != 0) return error.InvalidHex;
    const nbytes = hex.len / 2;
    if (nbytes > dst.len) return error.InvalidLength;
    _ = std.fmt.hexToBytes(dst[0..nbytes], hex) catch return error.InvalidHex;
    return nbytes;
}

/// Parse a drand `/public/<round>` document. `gpa` is used only
/// transiently (freed before return); the returned `Round` owns nothing.
pub fn parseRound(gpa: std.mem.Allocator, bytes: []const u8) RoundParseError!Round {
    if (bytes.len > max_document_bytes) return error.DocumentTooLarge;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = std.json.parseFromSliceLeaky(RoundJson, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJson,
    };

    var sig_bytes: [96]u8 = undefined;
    const sig_len = try decodeHexVar(&sig_bytes, raw.signature);

    var sig_g1: ?g1.Affine = null;
    if (sig_len == sig_g1_bytes) {
        sig_g1 = g1.fromBytesCompressed(sig_bytes[0..sig_g1_bytes].*) catch return error.InvalidPoint;
    }

    var randomness: ?[32]u8 = null;
    if (raw.randomness) |r| {
        var rnd: [32]u8 = undefined;
        if (r.len != 64) return error.InvalidLength;
        _ = std.fmt.hexToBytes(&rnd, r) catch return error.InvalidHex;
        randomness = rnd;
    }

    var previous_signature: ?Round.PreviousSignature = null;
    if (raw.previous_signature) |p| {
        var pbuf: [96]u8 = undefined;
        const plen = try decodeHexVar(&pbuf, p);
        previous_signature = .{ .bytes = pbuf, .len = plen };
    }

    return .{
        .round = raw.round,
        .sig_bytes = sig_bytes,
        .sig_len = sig_len,
        .sig_g1 = sig_g1,
        .randomness = randomness,
        .previous_signature = previous_signature,
    };
}

/// Build the drand HTTP request path for a round, e.g.
/// `parseRoundPath(buf, "52db9ba7...", 1000)` → `/52db9ba7.../public/1000`.
/// FETCHING the path is the CALLER's job (this module is transport-
/// agnostic — see the module doc comment and `SPEC.md`); this is only a
/// convenience for constructing the URL path. Returns the slice of `buf`
/// written, or `error.NoSpaceLeft` if `buf` is too small.
pub fn roundPath(buf: []u8, chain_hash_hex: []const u8, round: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "/{s}/public/{d}", .{ chain_hash_hex, round }) catch
        return error.NoSpaceLeft;
}

/// The path for the LATEST round: `/<chain_hash>/public/latest`.
pub fn latestPath(buf: []u8, chain_hash_hex: []const u8) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "/{s}/public/latest", .{chain_hash_hex}) catch
        return error.NoSpaceLeft;
}

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

// Genuine mainnet quicknet round 1000 (signature is the same live-fetched
// value `tlock`'s KAT harness pins; `randomness` = SHA-256(signature),
// drand's definition).
const round_1000_json =
    \\{
    \\  "round": 1000,
    \\  "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
    \\  "signature": "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"
    \\}
;

test "parseRound: genuine quicknet round 1000 decodes to a typed Round with a G1 signature" {
    const r = try parseRound(testing.allocator, round_1000_json);
    try testing.expectEqual(@as(u64, 1000), r.round);
    try testing.expectEqual(@as(usize, 48), r.sig_len);
    try testing.expect(r.sig_g1 != null);
    try testing.expect(r.randomness != null);
    try testing.expect(r.previous_signature == null);
}

test "parseRound: decoded G1 signature is in the subgroup" {
    const r = try parseRound(testing.allocator, round_1000_json);
    const sig = try r.signatureG1();
    try testing.expect(!sig.infinity);
    try testing.expect(g1.Jacobian.fromAffine(sig).subgroupCheck());
}

test "parseRound: flipped-byte signature still decodes (a valid but different point) or fails at decode" {
    // Flip the last hex nibble of the signature: the result is either a
    // different valid G1 point or an invalid encoding — never a panic.
    const flipped =
        \\{"round":1000,"signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e38"}
    ;
    const res = parseRound(testing.allocator, flipped);
    if (res) |r| {
        try testing.expect(r.sig_g1 != null); // decoded to some point
    } else |err| {
        try testing.expect(err == error.InvalidPoint);
    }
}

test "parseRound: bad hex signature → InvalidHex" {
    const bad =
        \\{"round":1,"signature":"zzzz"}
    ;
    try testing.expectError(error.InvalidHex, parseRound(testing.allocator, bad));
}

test "parseRound: missing signature → MalformedJson" {
    const bad =
        \\{"round":1}
    ;
    try testing.expectError(error.MalformedJson, parseRound(testing.allocator, bad));
}

test "parseRound: wrong-length randomness → InvalidLength" {
    const bad =
        \\{"round":1000,"randomness":"abcd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    try testing.expectError(error.InvalidLength, parseRound(testing.allocator, bad));
}

test "parseRound: oversized document → DocumentTooLarge" {
    const big = try testing.allocator.alloc(u8, max_document_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    try testing.expectError(error.DocumentTooLarge, parseRound(testing.allocator, big));
}

test "parseRound: chained round carries previous_signature (G2 sig, sig_g1 null)" {
    // A 96-byte (G2) signature with a previous_signature — legacy chained
    // shape. sig_g1 stays null; previous_signature is retained.
    const chained = "{\"round\":2,\"signature\":\"" ++ ("ab" ** 96) ++
        "\",\"previous_signature\":\"" ++ ("cd" ** 96) ++ "\"}";
    const r = try parseRound(testing.allocator, chained);
    try testing.expectEqual(@as(usize, 96), r.sig_len);
    try testing.expect(r.sig_g1 == null);
    try testing.expect(r.previous_signature != null);
    try testing.expectEqual(@as(usize, 96), r.previous_signature.?.len);
}

test "roundPath / latestPath build the drand request path" {
    var buf: [128]u8 = undefined;
    const p = try roundPath(&buf, "52db9ba70e0cc0f6", 1000);
    try testing.expectEqualStrings("/52db9ba70e0cc0f6/public/1000", p);
    const l = try latestPath(&buf, "52db9ba70e0cc0f6");
    try testing.expectEqualStrings("/52db9ba70e0cc0f6/public/latest", l);
}

test "roundPath: too-small buffer → NoSpaceLeft" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, roundPath(&buf, "52db9ba70e0cc0f6", 1000));
}
