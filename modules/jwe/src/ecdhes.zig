// SPDX-License-Identifier: MIT

//! jwe.alg.ecdhes — RFC 7518 §4.6 ECDH-ES key agreement: ephemeral-static
//! Elliptic Curve Diffie-Hellman plus the Concat KDF (NIST SP 800-56A
//! §5.8.1, single-step, SHA-256) that turns the raw shared secret `Z` into
//! either the CEK itself (`ECDH-ES`, Direct Key Agreement) or a KEK for
//! RFC 3394 AES Key Wrap (`ECDH-ES+AxxxKW`, Key Agreement with Key
//! Wrapping — the wrap itself lives in `aeskw.zig`).
//!
//! Curves:
//!   - **P-256** (`"crv":"P-256"`, JWK kty `EC`) — `std.crypto.ecc.P256`.
//!     `Z` is the X coordinate of the shared point, big-endian, 32 bytes
//!     (SEC1 §3.3.1 field-element width). The RFC 7518 Appendix C KAT is
//!     P-256 and is asserted byte-exact below (Z AND the derived key).
//!   - **X25519** (`"crv":"X25519"`, JWK kty `OKP`, RFC 8037) —
//!     `std.crypto.dh.X25519.scalarmult`; `Z` is its 32-byte output.
//!     std's identity-element rejection covers RFC 7748's all-zero
//!     shared-secret check (low-order peer points fail as
//!     `error.InvalidKey`).
//!
//! Const-time notes: both scalar multiplications are std's constant-time
//! ladders (`P256.mul`, X25519's clamped Montgomery ladder — never the
//! `mulPublic` variable-time variants); the Concat KDF hashes `Z` plus
//! public-only inputs (alg name, apu/apv, keydatalen) with no
//! secret-dependent branching. Ephemeral key generation takes the CALLER's
//! `std.Random` (std 0.16 removed `std.crypto.random`) — it must be
//! cryptographically secure, same contract as `encryptCompact`'s `random`.

const std = @import("std");
const P256 = std.crypto.ecc.P256;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    /// Invalid peer point (off-curve / identity / low-order), invalid or
    /// zero private scalar, or coordinate bytes of the wrong length.
    InvalidKey,
    /// The `epk`'s curve doesn't match the recipient key's curve (or is a
    /// curve this module doesn't implement) — the typed rejection RFC 8725
    /// §3.x-style cross-curve confusion requires.
    CurveMismatch,
};

/// The curves this module implements. Tag names double as the union tags of
/// `PublicKey`/`PrivateKey`; the JOSE wire names come from `jwkCrv`.
pub const Curve = enum {
    p256,
    x25519,

    /// JWK `crv` value (RFC 7518 §6.2.1.1 / RFC 8037 §3.2).
    pub fn jwkCrv(self: Curve) []const u8 {
        return switch (self) {
            .p256 => "P-256",
            .x25519 => "X25519",
        };
    }

    /// JWK `kty` value: `EC` for Weierstrass curves, `OKP` (RFC 8037) for
    /// X25519.
    pub fn jwkKty(self: Curve) []const u8 {
        return switch (self) {
            .p256 => "EC",
            .x25519 => "OKP",
        };
    }

    pub fn fromJwkCrv(s: []const u8) ?Curve {
        if (std.mem.eql(u8, s, "P-256")) return .p256;
        if (std.mem.eql(u8, s, "X25519")) return .x25519;
        return null;
    }
};

/// Coordinate width for every supported curve (32 bytes) — also the width
/// of `Z` (SEC1: the shared X coordinate at field-element width).
pub const coordinate_len: usize = 32;
pub const max_z_len: usize = coordinate_len;

/// A recipient/ephemeral public key. For P-256 the point is validated
/// on-curve at construction (`fromCoordinates`); an identity/low-order peer
/// is additionally rejected inside `deriveZ` by std's scalar mult.
pub const PublicKey = union(Curve) {
    p256: P256,
    x25519: [coordinate_len]u8,

    /// Build from raw (base64url-decoded) JWK coordinates. P-256 requires
    /// both `x` and `y` (exactly 32 bytes each) and validates the curve
    /// equation; X25519 takes `x` only (`y` must be absent per RFC 8037).
    pub fn fromCoordinates(crv: Curve, x: []const u8, y: ?[]const u8) Error!PublicKey {
        switch (crv) {
            .p256 => {
                const yy = y orelse return error.InvalidKey;
                if (x.len != coordinate_len or yy.len != coordinate_len) return error.InvalidKey;
                const point = P256.fromSerializedAffineCoordinates(
                    x[0..coordinate_len].*,
                    yy[0..coordinate_len].*,
                    .big,
                ) catch return error.InvalidKey;
                return .{ .p256 = point };
            },
            .x25519 => {
                if (x.len != coordinate_len or y != null) return error.InvalidKey;
                return .{ .x25519 = x[0..coordinate_len].* };
            },
        }
    }

    /// The raw big-endian JWK coordinates — what the `epk` header carries.
    pub fn coordinates(self: PublicKey) Coordinates {
        switch (self) {
            .p256 => |point| {
                const aff = point.affineCoordinates();
                return .{ .x = aff.x.toBytes(.big), .y = aff.y.toBytes(.big) };
            },
            .x25519 => |x| return .{ .x = x, .y = null },
        }
    }
};

pub const Coordinates = struct {
    x: [coordinate_len]u8,
    /// null for X25519 (OKP keys have no `y`).
    y: ?[coordinate_len]u8,
};

/// A recipient-static or ephemeral private key. P-256: the SEC1 scalar,
/// big-endian, 32 bytes, validated canonical-and-nonzero inside `deriveZ`.
/// X25519: the 32-byte secret (clamped by std at use).
pub const PrivateKey = union(Curve) {
    p256: [coordinate_len]u8,
    x25519: [coordinate_len]u8,

    /// Best-effort scrub of the scalar bytes (the tag survives).
    pub fn wipe(self: *PrivateKey) void {
        switch (self.*) {
            inline else => |*bytes| std.crypto.secureZero(u8, bytes),
        }
    }
};

pub const EphemeralKeyPair = struct {
    private: PrivateKey,
    public: PublicKey,
};

/// Generate the encrypt-side ephemeral key pair on `curve`. `random` MUST
/// be cryptographically secure — this scalar protects every message key.
/// P-256 rejection-samples a canonical nonzero scalar (uniform over the
/// group order); X25519 takes any 32 random bytes (clamping happens in the
/// scalar mult, per RFC 7748).
pub fn generateEphemeral(curve: Curve, random: std.Random) EphemeralKeyPair {
    switch (curve) {
        .p256 => {
            while (true) {
                var d: [coordinate_len]u8 = undefined;
                random.bytes(&d);
                P256.scalar.rejectNonCanonical(d, .big) catch continue;
                // `mul` errors iff the result is the identity — i.e. d == 0.
                const point = P256.basePoint.mul(d, .big) catch continue;
                return .{ .private = .{ .p256 = d }, .public = .{ .p256 = point } };
            }
        },
        .x25519 => {
            while (true) {
                var sk: [coordinate_len]u8 = undefined;
                random.bytes(&sk);
                // Clamped-scalar identity output is not reachable from
                // random bytes, but the error union exists — resample.
                const pk = X25519.recoverPublicKey(sk) catch continue;
                return .{ .private = .{ .x25519 = sk }, .public = .{ .x25519 = pk } };
            }
        },
    }
}

/// The ECDH shared secret `Z` (RFC 7518 §4.6): encrypt side calls this with
/// (ephemeral private, recipient-static public); decrypt side with
/// (recipient-static private, header `epk`). P-256: `Z` = the X coordinate
/// of `d·Q`, big-endian, 32 bytes (SEC1 §3.3.1); X25519: the RFC 7748
/// function output. Returns the `Z` slice into `out` — callers should
/// `secureZero` it after the KDF. Cross-curve inputs are the typed
/// `error.CurveMismatch`.
pub fn deriveZ(private: PrivateKey, peer: PublicKey, out: *[max_z_len]u8) Error![]const u8 {
    if (@as(Curve, private) != @as(Curve, peer)) return error.CurveMismatch;
    switch (private) {
        .p256 => |d| {
            P256.scalar.rejectNonCanonical(d, .big) catch return error.InvalidKey;
            // Constant-time scalar mult; rejects an identity peer point and
            // an identity result (d == 0).
            const shared = peer.p256.mul(d, .big) catch return error.InvalidKey;
            out.* = shared.affineCoordinates().x.toBytes(.big);
            return out[0..coordinate_len];
        },
        .x25519 => |sk| {
            // std rejects the identity/all-zero output — RFC 7748's
            // low-order-point check.
            out.* = X25519.scalarmult(sk, peer.x25519) catch return error.InvalidKey;
            return out[0..coordinate_len];
        },
    }
}

/// The Concat KDF (NIST SP 800-56A §5.8.1, single-step, SHA-256) as RFC
/// 7518 §4.6.2 applies it:
///
///   DerivedKey = leftmost-keydatalen-bits of
///       Hash(counter_1 ‖ Z ‖ OtherInfo) ‖ Hash(counter_2 ‖ Z ‖ OtherInfo) ‖ …
///
/// with `OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo ‖
/// SuppPrivInfo`, where AlgorithmID/PartyUInfo/PartyVInfo are each
/// `len(Data) (32-bit big-endian) ‖ Data`, SuppPubInfo is keydatalen **in
/// bits** as a raw 32-bit big-endian integer (no length prefix), and
/// SuppPrivInfo is empty. `alg_id` is the ASCII algorithm name that chose
/// keydatalen (the `enc` value for `ECDH-ES`, the `alg` value for
/// `ECDH-ES+AxxxKW`); `apu`/`apv` are the base64url-DECODED `apu`/`apv`
/// header values (empty slices when absent). `derived.len` selects
/// keydatalen (bytes); for SHA-256 and keydatalen <= 256 bits a single
/// round runs, but the counter loop is general (A256CBC-HS512 direct needs
/// two rounds). Byte-exact against RFC 7518 Appendix C (test below).
pub fn concatKdfSha256(
    z: []const u8,
    alg_id: []const u8,
    apu: []const u8,
    apv: []const u8,
    derived: []u8,
) void {
    std.debug.assert(derived.len > 0);
    const keydata_bits: u32 = @intCast(derived.len * 8);
    var counter: u32 = 1;
    var off: usize = 0;
    while (off < derived.len) : (counter += 1) {
        var h = Sha256.init(.{});
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, counter, .big);
        h.update(&be);
        h.update(z);
        hashLenData(&h, alg_id); // AlgorithmID
        hashLenData(&h, apu); // PartyUInfo
        hashLenData(&h, apv); // PartyVInfo
        std.mem.writeInt(u32, &be, keydata_bits, .big);
        h.update(&be); // SuppPubInfo (raw u32, NOT length-prefixed)
        // SuppPrivInfo: empty.
        var digest: [Sha256.digest_length]u8 = undefined;
        h.final(&digest);
        const n = @min(digest.len, derived.len - off);
        @memcpy(derived[off..][0..n], digest[0..n]);
        std.crypto.secureZero(u8, &digest);
        off += n;
    }
}

fn hashLenData(h: *Sha256, data: []const u8) void {
    var be: [4]u8 = undefined;
    std.mem.writeInt(u32, &be, @intCast(data.len), .big);
    h.update(&be);
    h.update(data);
}

// -- tests -------------------------------------------------------------

const testing = std.testing;

fn b64dFixed(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    std.base64.url_safe_no_pad.Decoder.decode(&out, s) catch unreachable;
    return out;
}

// RFC 7518 Appendix C — the assigned KAT. Alice = producer (ephemeral),
// Bob = consumer (static), apu="Alice", apv="Bob", enc="A128GCM".
const appc_alice_d = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo";
const appc_alice_x = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
const appc_alice_y = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps";
const appc_bob_d = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";
const appc_bob_x = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ";
const appc_bob_y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck";
const appc_z = [32]u8{
    158, 86, 217, 29,  129, 113, 53,  211, 114, 131, 66,  131, 191, 132, 38,  156,
    251, 49, 110, 163, 218, 128, 106, 72,  246, 218, 167, 121, 140, 254, 144, 196,
};
const appc_derived = [16]u8{ 86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26 };

test "RFC 7518 Appendix C KAT — P-256 ECDH Z, byte-exact, both directions" {
    const bob_pub = try PublicKey.fromCoordinates(.p256, &b64dFixed(32, appc_bob_x), &b64dFixed(32, appc_bob_y));
    const alice_pub = try PublicKey.fromCoordinates(.p256, &b64dFixed(32, appc_alice_x), &b64dFixed(32, appc_alice_y));

    // Encrypt side: Z = ECDH(alice ephemeral private, bob static public).
    var z_buf: [max_z_len]u8 = undefined;
    const z1 = try deriveZ(.{ .p256 = b64dFixed(32, appc_alice_d) }, bob_pub, &z_buf);
    try testing.expectEqualSlices(u8, &appc_z, z1);

    // Decrypt side: Z = ECDH(bob static private, alice's epk) — same Z.
    var z_buf2: [max_z_len]u8 = undefined;
    const z2 = try deriveZ(.{ .p256 = b64dFixed(32, appc_bob_d) }, alice_pub, &z_buf2);
    try testing.expectEqualSlices(u8, &appc_z, z2);
}

test "RFC 7518 Appendix C KAT — Concat KDF derived key, byte-exact (VqqN6vgjbSBcIijNcacQGg)" {
    // keydatalen = 128 (A128GCM), AlgorithmID = "A128GCM", apu = "Alice",
    // apv = "Bob" — expected derived key straight from the RFC's octets.
    var derived: [16]u8 = undefined;
    concatKdfSha256(&appc_z, "A128GCM", "Alice", "Bob", &derived);
    try testing.expectEqualSlices(u8, &appc_derived, &derived);

    var b64_buf: [22]u8 = undefined;
    const enc = std.base64.url_safe_no_pad.Encoder.encode(&b64_buf, &derived);
    try testing.expectEqualStrings("VqqN6vgjbSBcIijNcacQGg", enc);
}

test "Concat KDF std-only sanity oracle — single SHA-256 over the RFC's literal round-1 input" {
    // The RFC prints the exact round-1 hash input octets: counter=1 ‖ Z ‖
    // OtherInfo. Recompute with a raw std Sha256 (no KDF code involved) and
    // check concatKdfSha256 agrees — the OtherInfo length-prefix encoding is
    // exactly what's being cross-checked here.
    const otherinfo = [_]u8{ 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 } // AlgorithmID "A128GCM"
        ++ [_]u8{ 0, 0, 0, 5, 65, 108, 105, 99, 101 } // PartyUInfo "Alice"
        ++ [_]u8{ 0, 0, 0, 3, 66, 111, 98 } // PartyVInfo "Bob"
        ++ [_]u8{ 0, 0, 0, 128 }; // SuppPubInfo (128 bits)
    var oracle_in: [4 + appc_z.len + otherinfo.len]u8 = undefined;
    oracle_in[0..4].* = .{ 0, 0, 0, 1 };
    oracle_in[4..][0..appc_z.len].* = appc_z;
    oracle_in[4 + appc_z.len ..].* = otherinfo;
    var oracle_digest: [32]u8 = undefined;
    Sha256.hash(&oracle_in, &oracle_digest, .{});

    var derived: [16]u8 = undefined;
    concatKdfSha256(&appc_z, "A128GCM", "Alice", "Bob", &derived);
    try testing.expectEqualSlices(u8, oracle_digest[0..16], &derived);
}

test "Concat KDF counter loop — 64-byte output is round-1 digest ‖ round-2 digest (std oracle)" {
    // keydatalen = 512 (an A256CBC-HS512 CEK under ECDH-ES direct) forces
    // two SHA-256 rounds; each round is oracled with a raw std hash, with
    // SuppPubInfo now 0x00000200 (512 bits).
    const otherinfo = [_]u8{ 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77 } ++
        [_]u8{ 0, 0, 0, 5, 65, 108, 105, 99, 101 } ++
        [_]u8{ 0, 0, 0, 3, 66, 111, 98 } ++
        [_]u8{ 0, 0, 2, 0 };
    var derived: [64]u8 = undefined;
    concatKdfSha256(&appc_z, "A128GCM", "Alice", "Bob", &derived);

    var round: u32 = 1;
    while (round <= 2) : (round += 1) {
        var oracle_in: [4 + appc_z.len + otherinfo.len]u8 = undefined;
        std.mem.writeInt(u32, oracle_in[0..4], round, .big);
        oracle_in[4..][0..appc_z.len].* = appc_z;
        oracle_in[4 + appc_z.len ..].* = otherinfo;
        var digest: [32]u8 = undefined;
        Sha256.hash(&oracle_in, &digest, .{});
        try testing.expectEqualSlices(u8, &digest, derived[(round - 1) * 32 ..][0..32]);
    }
}

test "ephemeral generation + agreement — both curves, both directions agree" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x37} ** 32);
    inline for (.{ Curve.p256, Curve.x25519 }) |curve| {
        const a = generateEphemeral(curve, csprng.random());
        const b = generateEphemeral(curve, csprng.random());
        var za_buf: [max_z_len]u8 = undefined;
        var zb_buf: [max_z_len]u8 = undefined;
        const za = try deriveZ(a.private, b.public, &za_buf);
        const zb = try deriveZ(b.private, a.public, &zb_buf);
        try testing.expectEqualSlices(u8, za, zb);
        try testing.expect(!std.mem.allEqual(u8, za, 0));

        // Public coordinates round-trip through the JWK wire form.
        const coords = a.public.coordinates();
        const back = try PublicKey.fromCoordinates(curve, &coords.x, if (coords.y) |*y| y else null);
        var zc_buf: [max_z_len]u8 = undefined;
        const zc = try deriveZ(b.private, back, &zc_buf);
        try testing.expectEqualSlices(u8, za, zc);
    }
}

test "cross-curve agreement is a typed CurveMismatch, never a wrong-key derivation" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x38} ** 32);
    const p = generateEphemeral(.p256, csprng.random());
    const x = generateEphemeral(.x25519, csprng.random());
    var z_buf: [max_z_len]u8 = undefined;
    try testing.expectError(error.CurveMismatch, deriveZ(p.private, x.public, &z_buf));
    try testing.expectError(error.CurveMismatch, deriveZ(x.private, p.public, &z_buf));
}

test "invalid peer material is rejected: off-curve point, bad lengths, missing y" {
    // Perturb the App. C x coordinate — overwhelmingly off-curve.
    var bad_x = b64dFixed(32, appc_bob_x);
    bad_x[31] ^= 0x01;
    try testing.expectError(error.InvalidKey, PublicKey.fromCoordinates(.p256, &bad_x, &b64dFixed(32, appc_bob_y)));
    // P-256 without y, or with short coordinates.
    try testing.expectError(error.InvalidKey, PublicKey.fromCoordinates(.p256, &b64dFixed(32, appc_bob_x), null));
    try testing.expectError(error.InvalidKey, PublicKey.fromCoordinates(.p256, &[_]u8{1} ** 31, &b64dFixed(32, appc_bob_y)));
    // X25519 with a stray y, or a short x.
    try testing.expectError(error.InvalidKey, PublicKey.fromCoordinates(.x25519, &[_]u8{1} ** 32, &[_]u8{2} ** 32));
    try testing.expectError(error.InvalidKey, PublicKey.fromCoordinates(.x25519, &[_]u8{1} ** 16, null));
}

test "invalid private scalars: zero / non-canonical P-256 d, low-order X25519 peer" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x39} ** 32);
    const peer = generateEphemeral(.p256, csprng.random());
    var z_buf: [max_z_len]u8 = undefined;
    try testing.expectError(error.InvalidKey, deriveZ(.{ .p256 = [_]u8{0} ** 32 }, peer.public, &z_buf));
    try testing.expectError(error.InvalidKey, deriveZ(.{ .p256 = [_]u8{0xff} ** 32 }, peer.public, &z_buf));

    // X25519 low-order peer (the all-zero point) must fail, not yield Z=0.
    const xkp = generateEphemeral(.x25519, csprng.random());
    try testing.expectError(error.InvalidKey, deriveZ(xkp.private, .{ .x25519 = [_]u8{0} ** 32 }, &z_buf));
}

test "PrivateKey.wipe zeroes the scalar" {
    var kp = generateEphemeral(.p256, blk: {
        const S = struct {
            var csprng = std.Random.DefaultCsprng.init([_]u8{0x3a} ** 32);
        };
        break :blk S.csprng.random();
    });
    kp.private.wipe();
    try testing.expect(std.mem.allEqual(u8, &kp.private.p256, 0));
}
