// SPDX-License-Identifier: MIT
//! sign — Falcon/FN-DSA signing glue: hashes (nonce, message) to a point
//! via REUSED `codec.hashToPoint`, draws a candidate short vector via
//! `ffsampling.sampleSignature`, rejects candidates over the
//! degree's norm bound and retries (mirroring the spec's own outer
//! accept/reject loop — real code, not stubbed), and compresses the
//! accepted s2 via REUSED `codec.compEncode`. The one public entry
//! point, `root.zig`'s `signRandomized` (a real CSPRNG — production
//! use), funnels through the `signWithRng` core; tests that need
//! reproducible signatures seed `ShakePrng` and call `signWithRng`
//! directly, owning the PRNG substitution explicitly. `root.zig`
//! deliberately exposes NO seeded signing mode — a tape derived from a
//! seed alone reuses the 40-byte salt across messages; see the decision
//! comment in `root.zig` (below `signRandomized`).
//!
//! NOT constant-time, and cannot be made so by anything in this file:
//! the actual side-channel-sensitive step is `gaussian.samplerZ`
//! (reached transitively through `ffsampling.sampleSignature`) — that
//! audit has to happen there, not here. See `gaussian.zig`'s module doc
//! comment.

const std = @import("std");
const codec = @import("codec.zig");
const ffsampling = @import("ffsampling.zig");

pub const nonce_length = 40;

/// A SHAKE256-seeded deterministic byte stream, exposed as `std.Random`
/// via `random()`. This is the "signer-internal PRNG" layer the Falcon
/// reference implementation re-seeds per-signature from its
/// `randombytes()` output (`Zf(prng_init)`, itself SHAKE256-based) —
/// it is NOT the outer NIST-KAT AES-256-CTR-DRBG
/// (`KAT/generator/katrng.c`) that produces the .rsp `seed` field in the
/// first place; that harness-level DRBG is test tooling and has no
/// business in this module's public signing API. SIGNING CAVEAT: a
/// ShakePrng handed to `signWithRng` yields a salt (and sampling tape)
/// that is a function of the seed alone — sign two messages off one
/// instance, or two instances with one seed, and they share the salt.
/// That is why `root.zig` exposes no seeded signing mode (see the
/// decision comment there); this type is a test/KAT seam, and the KAT
/// tests replay the reference's two separate DRBG draws explicitly
/// instead (`kat_sign_test.zig`). This PRNG
/// IS, however, exactly the reference's SHAKE256 keygen RNG: seed it
/// with the DRBG's 48-byte keypair draw and `generateKeyPair`
/// reproduces the KAT pk/sk byte-for-byte (`keygen_sign_test.zig`).
pub const ShakePrng = struct {
    state: std.crypto.hash.sha3.Shake256,

    pub fn init(seed: []const u8) ShakePrng {
        var st = std.crypto.hash.sha3.Shake256.init(.{});
        st.update(seed);
        return .{ .state = st };
    }

    fn fill(self: *ShakePrng, buf: []u8) void {
        self.state.squeeze(buf);
    }

    pub fn random(self: *ShakePrng) std.Random {
        return std.Random.init(self, ShakePrng.fill);
    }
};

/// Signing, specialized to one `poly.Ring(logn)` degree.
pub fn Signer(comptime Ring: type) type {
    const Codec = codec.Codec(Ring);

    return struct {
        pub const sig_header: u8 = 0x20 + @as(u8, Ring.logn);

        pub const SignError = error{
            /// `sig_out` too small to hold even the header byte.
            NoSpaceLeft,
        };

        /// Sign `msg` under the ffSampling tree `tree`. Writes a fresh
        /// nonce into `nonce_out` and the compressed signature field
        /// (header byte + compressed s2 — the same layout
        /// `root.zig`'s `PublicKey.verify` expects as `sig_field`) into
        /// `sig_out`, returning the number of bytes written.
        ///
        /// Retries internally — fresh nonce, fresh `ffsampling` draw —
        /// until the candidate's squared norm is within `sig_bound`
        /// (mirrors `root.zig`'s verify-side check exactly, just
        /// computed directly from (s1, s2) instead of recovered from
        /// (s2, h, c)) AND `compEncode` accepts every s2 coefficient
        /// (|coefficient| <= 2047); the spec's own analysis says this
        /// essentially never iterates more than once or twice for an
        /// honest sampler.
        pub fn signWithRng(
            tree: *const ffsampling.Tree(Ring),
            msg: []const u8,
            rng: std.Random,
            nonce_out: *[nonce_length]u8,
            sig_out: []u8,
            sig_bound: u64,
        ) SignError!usize {
            if (sig_out.len == 0) return error.NoSpaceLeft;
            while (true) {
                rng.bytes(nonce_out);
                var c: Ring.Poly = undefined;
                Codec.hashToPoint(nonce_out, msg, &c); // REUSED

                const samp = ffsampling.sampleSignature(Ring, tree, &c, rng);

                var norm: u64 = 0;
                for (samp.s1, samp.s2) |a, b| {
                    norm += @as(u64, @intCast(@as(i32, a) * @as(i32, a)));
                    norm += @as(u64, @intCast(@as(i32, b) * @as(i32, b)));
                }
                if (norm > sig_bound) continue;

                sig_out[0] = sig_header;
                const len = Codec.compEncode(sig_out[1..], &samp.s2) catch continue; // REUSED
                return 1 + len;
            }
        }
    };
}

test "Signer(Ring).sig_header matches root.zig's existing sig_header constants" {
    const poly = @import("poly.zig");
    const falcon = @import("root.zig");
    // Cross-check against root.zig's independently-defined, KAT-pinned
    // header bytes (0x29 / 0x2a) — same cheap "does this file's notion
    // of the wire format agree with the real one" check as keygen.zig's
    // encoded-length test.
    try std.testing.expectEqual(falcon.sig_header, Signer(poly.Ring512).sig_header);
    try std.testing.expectEqual(falcon.sig_header_1024, Signer(poly.Ring1024).sig_header);
}

test "ShakePrng: deterministic given the same seed, different given a different one" {
    var a = ShakePrng.init("seed-a");
    var b = ShakePrng.init("seed-a");
    var c = ShakePrng.init("seed-b");
    var buf_a: [32]u8 = undefined;
    var buf_b: [32]u8 = undefined;
    var buf_c: [32]u8 = undefined;
    a.random().bytes(&buf_a);
    b.random().bytes(&buf_b);
    c.random().bytes(&buf_c);
    try std.testing.expectEqualSlices(u8, &buf_a, &buf_b);
    try std.testing.expect(!std.mem.eql(u8, &buf_a, &buf_c));
}
