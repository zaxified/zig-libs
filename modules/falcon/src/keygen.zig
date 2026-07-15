// SPDX-License-Identifier: MIT
//! keygen — Falcon/FN-DSA key generation glue. Draws the NTRU secret
//! basis via `ntru.Ntru(Ring).generate` (NTRUGen + NTRUSolve — see
//! ntru.zig), derives the public key h = g*f^-1 mod q by REUSING
//! `poly.Ring.computePublic` (NIST-KAT-verified on the verify side),
//! and captures the secret basis via `ffsampling.buildTree` for
//! `sign.zig` to use at signing time.
//!
//! Everything in this file is mechanical wiring; the hard math lives in
//! ntru.zig (keygen) and ffsampling.zig/gaussian.zig (signing).

const std = @import("std");
const codec = @import("codec.zig");
const ntru = @import("ntru.zig");
const ffsampling = @import("ffsampling.zig");

/// Key generation, specialized to one `poly.Ring(logn)` degree.
pub fn Keygen(comptime Ring: type) type {
    const Codec = codec.Codec(Ring);
    const N = ntru.Ntru(Ring);
    const fg_bits: u4 = if (Ring.logn <= 9) 6 else 5;
    const big_f_bits: u4 = 8;
    const fg_len = Ring.n * fg_bits / 8;
    const big_f_len = Ring.n * big_f_bits / 8;

    return struct {
        const Self = @This();

        /// Byte length of the standard secret-key encoding (header + f +
        /// g + F) — matches `root.zig`'s `SecretKey.encoded_length` at
        /// the same degree exactly (both are computed from the same
        /// spec-fixed `fg_bits`/`big_f_bits` widths).
        pub const secret_key_encoded_length = 1 + 2 * fg_len + big_f_len;

        /// A freshly generated Falcon signing key: the full NTRU basis
        /// (f, g, F, G) plus its precomputed ffSampling tree. `G` and the
        /// tree are never part of the wire secret-key encoding (see
        /// `toSecretKeyBytes`) — they are only held here, for signing.
        pub const SigningKey = struct {
            f: [Ring.n]i8,
            g: [Ring.n]i8,
            big_f: [Ring.n]i8,
            big_g: [Ring.n]i8,
            tree: ffsampling.Tree(Ring),

            /// The wire-encodable secret key (0x50+logn header + trimmed
            /// f/g/F) — the SAME encoding `root.zig`'s
            /// `SecretKey.fromBytes` decodes (already NIST-KAT-verified),
            /// so a generated key round-trips through the existing
            /// decode path unchanged.
            pub fn toSecretKeyBytes(sk: *const SigningKey) [Self.secret_key_encoded_length]u8 {
                var out: [Self.secret_key_encoded_length]u8 = undefined;
                out[0] = 0x50 + @as(u8, Ring.logn);
                Codec.trimI8Encode(fg_bits, out[1 .. 1 + fg_len], &sk.f);
                Codec.trimI8Encode(fg_bits, out[1 + fg_len .. 1 + 2 * fg_len], &sk.g);
                Codec.trimI8Encode(big_f_bits, out[1 + 2 * fg_len ..], &sk.big_f);
                return out;
            }
        };

        /// Generate a fresh Falcon key pair. `rng` is the entropy
        /// source: `std.crypto.random` for production keygen, or
        /// `sign.ShakePrng` seeded from a KAT `seed` for
        /// deterministic/reproducible generation (see `sign.zig`).
        /// Errors only if the generated `f` is non-invertible mod q —
        /// `ntru.generate`'s own acceptance loop already rules that out
        /// before returning, so this is a belt-and-suspenders check
        /// mirroring `root.zig`'s existing `SecretKey.publicKey`.
        pub fn generate(rng: std.Random) error{NotInvertible}!struct {
            signing_key: SigningKey,
            public_key_h: Ring.Poly,
        } {
            const basis = N.generate(rng); // NTRUGen + NTRUSolve (ntru.zig)
            const h = try Ring.computePublic(&basis.f, &basis.g); // REUSED, already KAT-verified
            const tree = ffsampling.buildTree(Ring, &basis.f, &basis.g, &basis.big_f, &basis.big_g);
            return .{
                .signing_key = .{
                    .f = basis.f,
                    .g = basis.g,
                    .big_f = basis.big_f,
                    .big_g = basis.big_g,
                    .tree = tree,
                },
                .public_key_h = h,
            };
        }
    };
}

test "Keygen(Ring): secret_key_encoded_length matches root.zig's existing SecretKey sizes" {
    const poly = @import("poly.zig");
    // These two numbers (1281 / 2305) are already pinned byte-exact by
    // root.zig's own "public API surface" tests against the real wire
    // format; re-deriving them here from Keygen's independent fg_bits/
    // big_f_bits computation is a cheap cross-check that keygen.zig's
    // notion of the encoding shape actually agrees with root.zig's.
    try std.testing.expectEqual(@as(usize, 1281), Keygen(poly.Ring512).secret_key_encoded_length);
    try std.testing.expectEqual(@as(usize, 2305), Keygen(poly.Ring1024).secret_key_encoded_length);
}

test "Keygen(Ring).SigningKey.toSecretKeyBytes round-trips through root.zig's SecretKey.fromBytes" {
    // Exercises the REAL (non-stub) half of this file end-to-end: fill a
    // SigningKey with arbitrary-but-valid f/g/F (no NTRU relation needed
    // — toSecretKeyBytes/fromBytes only touch the wire encoding, not the
    // math), encode, and decode via the module's actual, already
    // KAT-verified `SecretKey.fromBytes`.
    const poly = @import("poly.zig");
    const falcon = @import("root.zig");
    const KG = Keygen(poly.Ring512);

    var prng = std.Random.DefaultPrng.init(0xf41c04);
    const random = prng.random();
    var sk: KG.SigningKey = undefined;
    for (&sk.f) |*x| x.* = @intCast(random.intRangeAtMost(i16, -31, 31)); // 6-bit range
    for (&sk.g) |*x| x.* = @intCast(random.intRangeAtMost(i16, -31, 31));
    for (&sk.big_f) |*x| x.* = @intCast(random.intRangeAtMost(i16, -127, 127)); // 8-bit range
    sk.big_g = std.mem.zeroes([poly.Ring512.n]i8); // unused by toSecretKeyBytes

    const bytes = sk.toSecretKeyBytes();
    try std.testing.expectEqual(@as(usize, 1281), bytes.len);
    const decoded = try falcon.SecretKey.fromBytes(&bytes);
    try std.testing.expectEqualSlices(i8, &sk.f, &decoded.f);
    try std.testing.expectEqualSlices(i8, &sk.g, &decoded.g);
    try std.testing.expectEqualSlices(i8, &sk.big_f, &decoded.big_f);
}
