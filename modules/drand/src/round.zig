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
//! element `verify` pairs against) and that point IS subgroup-checked
//! here, mirroring what `chaininfo.parseInfo` does for the `G2` public
//! key and what drand's own Go client does on deserialization: its
//! `kyber-bls12381` `KyberG1.UnmarshalBinary` calls
//! `bls12381.NewG1().FromCompressed`, and kilic/bls12-381's
//! `G1.FromCompressed` ends with
//! `if !g.InCorrectSubgroup(p) { return nil, errors.New("point is not
//! on correct subgroup") }` (both read from upstream master while
//! making this fix).
//!
//! ⚠ The pairing equation in `verify.verifyRoundPoints` does NOT stand in
//! for this check. For a cofactor-torsion point `T` (`ord(T) | h1`,
//! `gcd(h1, r) = 1`) the pairing `e(T, Q)` lands in `μ_r` with order
//! dividing `ord(T)`, hence `e(T, Q) = 1`; so by bilinearity
//! `e(sig + T, Q) = e(sig, Q)` and `sig' = sig + T` is a DIFFERENT 48-byte
//! encoding that satisfies the same equation. Without this check two
//! honest verifiers could be handed different "verified" signatures — and
//! different `randomness`, since the attacker recomputes
//! `SHA-256(sig')` — for the same round. Found by the wave-2 audit
//! (W2-32), which demonstrated the acceptance live.
//!
//! `randomness`, when present, is retained for the
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
    /// The signature decoded to a point that is on the curve `E(Fp)` but
    /// NOT in the order-`r` subgroup `G1`. See the module doc comment:
    /// the pairing equation cannot see a cofactor-torsion addend, so this
    /// is the only place a malleated `sig + T` is caught.
    SignatureNotInSubgroup,
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
        const pt = g1.fromBytesCompressed(sig_bytes[0..sig_g1_bytes].*) catch return error.InvalidPoint;
        // The subgroup check the pairing equation cannot do for us — see
        // the module doc comment. Same guard `chaininfo.parseInfo` applies
        // to the G2 public key (`PublicKeyNotInSubgroup`).
        if (!g1.Jacobian.fromAffine(pt).subgroupCheck()) return error.SignatureNotInSubgroup;
        sig_g1 = pt;
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

test "parseRound: an on-curve signature OUTSIDE G1 → SignatureNotInSubgroup (W2-32)" {
    // The on-curve, non-subgroup point at x = 4 (the same construction
    // `bls12_381`'s own subgroupCheck test uses), presented as a round
    // signature. Decompression succeeds — `fromBytesCompressed` only
    // checks the curve equation — so `InvalidPoint` never fires and this
    // is the ONLY guard between such a point and the pairing equation,
    // which cannot see it.
    var comp = [_]u8{0} ** sig_g1_bytes;
    comp[0] = 0x80;
    comp[sig_g1_bytes - 1] = 4;
    const pt = try g1.fromBytesCompressed(comp);
    try testing.expect(g1.Jacobian.fromAffine(pt).isOnCurve());
    try testing.expect(!g1.Jacobian.fromAffine(pt).subgroupCheck());

    const doc = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"round\":1000,\"signature\":\"{s}\"}}",
        .{std.fmt.bytesToHex(comp, .lower)},
    );
    defer testing.allocator.free(doc);
    try testing.expectError(error.SignatureNotInSubgroup, parseRound(testing.allocator, doc));
}

test "parseRound: flipped-byte signature is REJECTED, not silently decoded" {
    // Flip the last hex nibble of the signature. Before W2-32's fix this
    // test allowed the parse to SUCCEED ("decoded to some point"), which
    // is precisely the hole: a tampered x-coordinate that still satisfies
    // the curve equation lands in the order-`r` subgroup with probability
    // `1/h1` (h1 ≈ 2^126), so what it actually produces is an off-subgroup
    // point — and it used to be handed straight to the pairing. The
    // expectation was widened, not the check: both outcomes below are
    // typed REJECTIONS, and success is no longer among them.
    const flipped =
        \\{"round":1000,"signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e38"}
    ;
    const res = parseRound(testing.allocator, flipped);
    try testing.expect(std.meta.isError(res));
    if (res) |_| unreachable else |err| {
        try testing.expect(err == error.InvalidPoint or err == error.SignatureNotInSubgroup);
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
