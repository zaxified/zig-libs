// SPDX-License-Identifier: MIT
//! X448 — the Diffie-Hellman function over curve448 (RFC 7748 §4.2/§5),
//! the Montgomery-form twin of the `ed448.zig` Edwards curve, both built
//! on `field.zig`'s shared `Fp448`. Mirrors `std.crypto.dh.X25519`'s
//! shape (`scalarmult`, `KeyPair`, `recoverPublicKey`) one curve family
//! up.
//!
//! **Status: implemented.** Scalar clamping (RFC 7748 §5,
//! `decodeScalar448`), all byte/`KeyPair` plumbing, AND the Montgomery
//! ladder itself (`ladder`, RFC 7748 §5's `x_2`/`z_2`/`x_3`/`z_3`
//! recurrence — a direct transcription of the RFC pseudocode over
//! `field.zig`'s constant-time `Fe`, fixed 448 iterations, `Fe.ctSwap`
//! conditional swaps) are real. Validated byte-exact against RFC 7748
//! §5.2's scalarmult + iterated vectors and §6.2's Diffie-Hellman
//! example in `kat_test.zig`.
//!
//! Zig std GAP: yes — `std.crypto.dh` ships `X25519` (curve25519) but no
//! `X448`; the RFC 7748 §5 ladder algorithm is IDENTICAL in shape between
//! the two curves (same pseudocode, different `p`/`A`/scalar width), so
//! this module's `ladder` is a direct transcription of the same
//! recurrence `std.crypto.dh.X25519`'s own `Curve25519.mul`
//! (`std/crypto/25519/curve25519.zig`) implements over its 32-byte field
//! — that file is the model-after reference for shape/idiom, not ported
//! source (different field width, different constant `a24`).

const std = @import("std");
const entropy = @import("entropy");
const field = @import("field.zig");
const Fe = field.Fe;

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "RFC 7748 (X448 / curve448 Montgomery Diffie-Hellman) — same ladder shape as std.crypto.dh.X25519 (std/crypto/25519/curve25519.zig), one curve family up; this module's field.zig supplies the Fp448 base field X25519 gets from std.crypto.ecc.Curve25519's own field.zig",
    .deps = .{},
};

/// Length (in bytes) of a scalar (private key) — 56 bytes / 448 bits,
/// matching `field.zig`'s native `Fe` width (RFC 7748 §5).
pub const scalar_length = 56;
/// Length (in bytes) of a `u`-coordinate (public key / DH output).
pub const public_length = 56;
/// Length (in bytes) of the DH function's raw output.
pub const shared_length = 56;
/// Seed length for deterministic key-pair generation.
pub const seed_length = 56;

/// `a24 = (A - 2) / 4 = (156326 - 2) / 4 = 39081` — the single curve
/// constant the Montgomery ladder needs (RFC 7748 §5, "The constant a24
/// is ... 39081 for curve448/X448"). A PUBLIC, fixed comptime constant —
/// distinct from (and unrelated in sign to) `ed448.zig`'s Edwards `d =
/// -39081`; the RFC's own text flags this near-coincidence ("d of
/// edwards448 ... -39081") without further comment, and this module
/// keeps its own `a24` separate from that module's `d` (no code sharing
/// beyond the field) to avoid an accidental sign/domain mixup.
pub const a24: u32 = 39081;

/// The curve448 base point `u = 5` (RFC 7748 §4.2's "U(P) 5"), encoded as
/// `field.zig`'s native 56-byte little-endian `Fe` wire format: a single
/// byte `0x05` followed by 55 zero bytes.
pub const base_u: [public_length]u8 = blk: {
    var b = [_]u8{0} ** public_length;
    b[0] = 5;
    break :blk b;
};

/// RFC 7748 §5's `decodeScalar448`: clears the two low bits of the first
/// byte and sets the high bit of the last byte, in place. REAL — pure bit
/// manipulation, no field arithmetic. NOTE this is a DIFFERENT mask than
/// X25519's `decodeScalar25519` (which additionally clears the second-
/// highest bit of its last byte and uses 3, not 2, low-bit clears) — the
/// RFC's own text: "for X448, set the two least significant bits of the
/// first byte to 0, and the most significant bit of the last byte to 1."
/// Guarantees the resulting scalar, interpreted little-endian, is of the
/// form `2^447 + 4*t` for `0 <= t < 2^445` — i.e. a multiple of the
/// curve's cofactor (4) with the top bit fixed (constant ladder length).
pub fn clamp(s: *[scalar_length]u8) void {
    s[0] &= 0b1111_1100;
    s[scalar_length - 1] |= 0b1000_0000;
}

/// The Montgomery ladder (RFC 7748 §5's `x_2`/`z_2`/`x_3`/`z_3`
/// recurrence, transcribed directly below) — computes `k * u` in
/// projective `X:Z` coordinates over the affine `u`-coordinate-only
/// Montgomery model, MSB-to-LSB over the (already-clamped) scalar's 448
/// bits, using `field.zig`'s constant-time `Fe.ctSwap` for the
/// conditional swap. The loop structure, the swap condition, and the
/// final `x_2 * z_2^(p-2)` recovery are the exact RFC construction:
///
/// ```text
/// x_1 = u;  x_2 = 1;  z_2 = 0;  x_3 = u;  z_3 = 1;  swap = 0
/// for t = 447 downto 0:
///     k_t = (clamped_scalar >> t) & 1
///     swap ^= k_t
///     (x_2, x_3) = cswap(swap, x_2, x_3)
///     (z_2, z_3) = cswap(swap, z_2, z_3)
///     swap = k_t
///     A = x_2 + z_2;  AA = A^2
///     B = x_2 - z_2;  BB = B^2
///     E = AA - BB
///     C = x_3 + z_3;  D = x_3 - z_3
///     DA = D * A;  CB = C * B
///     x_3 = (DA + CB)^2
///     z_3 = x_1 * (DA - CB)^2
///     x_2 = AA * BB
///     z_2 = E * (AA + a24 * E)
/// (x_2, x_3) = cswap(swap, x_2, x_3);  (z_2, z_3) = cswap(swap, z_2, z_3)
/// return x_2 * z_2^(p-2)
/// ```
///
/// `bits - 1 = 447` for curve448 (RFC 7748 §5's generic `bits` parameter,
/// 448 for curve448 vs 255 for curve25519). The `a24 * E` step uses
/// `field.zig`'s dedicated `Fe.mulSmall` (a single 56×≤32-bit partial
/// product per limb, mirroring `std.crypto.ecc.Edwards25519.Fe.mul32`)
/// rather than a full 8×8 `Fe.mul` against a comptime-built `a24` field
/// element.
fn ladder(clamped_scalar: [scalar_length]u8, u: Fe) Fe {
    const x_1 = u;
    var x_2 = Fe.one;
    var z_2 = Fe.zero;
    var x_3 = u;
    var z_3 = Fe.one;
    var swap: u1 = 0;

    var t: usize = scalar_length * 8; // 448: fixed iteration count (bit 447 downto 0)
    while (t > 0) {
        t -= 1;
        const k_t: u1 = @truncate(clamped_scalar[t / 8] >> @intCast(t % 8));
        swap ^= k_t;
        Fe.ctSwap(swap == 1, &x_2, &x_3);
        Fe.ctSwap(swap == 1, &z_2, &z_3);
        swap = k_t;

        const a = x_2.add(z_2);
        const aa = a.square();
        const b = x_2.sub(z_2);
        const bb = b.square();
        const e = aa.sub(bb);
        const c = x_3.add(z_3);
        const dd = x_3.sub(z_3);
        const da = dd.mul(a);
        const cb = c.mul(b);
        x_3 = da.add(cb).square();
        z_3 = x_1.mul(da.sub(cb).square());
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(e.mulSmall(a24)));
    }
    Fe.ctSwap(swap == 1, &x_2, &x_3);
    Fe.ctSwap(swap == 1, &z_2, &z_3);

    // RFC 7748 §5: return x_2 * z_2^(p-2). For z_2 == 0 (small-order
    // input landing on the point at infinity) z_2^(p-2) is 0, so the
    // whole result is 0 — `catch Fe.zero` reproduces exactly that. The
    // caught branch depends only on whether the PUBLIC input point had
    // small order, never on scalar bits.
    const z_inv = z_2.invert() catch Fe.zero;
    return x_2.mul(z_inv);
}

/// `X448(k, u)`: the raw DH function. `k` (56 bytes) is clamped
/// internally (RFC 7748 §5's `decodeScalar448`, applied here rather than
/// requiring the caller to pre-clamp — mirroring `std.crypto.dh.X25519.
/// scalarmult`'s own convention of clamping inside the call); `u` (56
/// bytes, little-endian `Fe` encoding) need NOT be canonical per RFC 7748
/// §5's own note that implementations "SHOULD mask the most significant
/// bit in the final byte" rather than reject non-canonical `u` — this
/// module instead delegates to `field.zig`'s `Fe.fromBytes`, which
/// REJECTS non-canonical input outright (`error.NonCanonical`); this is a
/// stricter-than-RFC-mandated but interoperability-safe choice shared
/// with `std.crypto.dh.X25519.scalarmult`'s own behavior on `Curve25519.
/// fromBytes` for the equivalent 25519 case — see `../SPEC.md`'s threat
/// model for the rationale (silently masking a high bit that changes a
/// peer's intended input is a worse failure mode than a hard reject).
pub fn scalarmult(k: [scalar_length]u8, u: [public_length]u8) field.FieldError![shared_length]u8 {
    var clamped = k;
    defer std.crypto.secureZero(u8, &clamped);
    clamp(&clamped);
    const u_fe = try Fe.fromBytes(u);
    const result = ladder(clamped, u_fe);
    return result.toBytes();
}

/// Compute the public key for a given private (scalar) key:
/// `X448(secret_key, base_u)`.
pub fn recoverPublicKey(secret_key: [scalar_length]u8) field.FieldError![public_length]u8 {
    return scalarmult(secret_key, base_u);
}

/// An X448 key pair.
pub const KeyPair = struct {
    public_key: [public_length]u8,
    secret_key: [scalar_length]u8,

    /// Deterministically derive a key pair from a secret seed. As with
    /// `std.crypto.dh.X25519.KeyPair.generateDeterministic`, applications
    /// should generally prefer `generate()` for fresh keys.
    pub fn generateDeterministic(seed: [seed_length]u8) field.FieldError!KeyPair {
        return .{
            .public_key = try recoverPublicKey(seed),
            .secret_key = seed,
        };
    }

    /// Generate a new, random key pair. The seed IS the X448 private
    /// scalar, so it fails closed (`entropy.fill`) — `generate` returns a
    /// `KeyPair`, not an error union, and a predictable seed here hands
    /// over every DH shared secret this key ever computes.
    pub fn generate(io: std.Io) KeyPair {
        var seed: [seed_length]u8 = undefined;
        entropy.fill(io, &seed);
        // recoverPublicKey/scalarmult cannot fail on a freshly-clamped,
        // freshly-random `u`-coordinate path here (base_u is a fixed
        // canonical constant; the only FieldError source in this call
        // path is Fe.fromBytes rejecting a non-canonical `u`, which
        // base_u never is) — mirrors X25519.KeyPair.generate's
        // retry-on-error loop shape, simplified because X448's base
        // point can never itself trigger that error.
        return generateDeterministic(seed) catch unreachable;
    }

    /// Zeroize `secret_key` in place; `public_key` is left untouched (it
    /// is not secret). Idempotent. Hygiene only — no effect on any DH
    /// result computed before the call.
    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "meta.model_after names RFC 7748 / X448" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "7748") != null);
}

test "a24 == (156326 - 2) / 4 == 39081 (RFC 7748 §5)" {
    try std.testing.expectEqual(@as(u32, 39081), a24);
    try std.testing.expectEqual(@as(u32, (156326 - 2) / 4), a24);
}

test "base_u encodes u=5 in field.zig's native little-endian 56-byte layout (REAL)" {
    var expected = [_]u8{0} ** public_length;
    expected[0] = 5;
    try std.testing.expectEqualSlices(u8, &expected, &base_u);
}

test "clamp: two low bits of byte 0 cleared, high bit of byte 55 set (REAL, RFC 7748 §5)" {
    var s = [_]u8{0xff} ** scalar_length;
    clamp(&s);
    try std.testing.expectEqual(@as(u8, 0xfc), s[0]);
    try std.testing.expectEqual(@as(u8, 0xff), s[scalar_length - 1]); // 0xff | 0x80 == 0xff
    var z = [_]u8{0x00} ** scalar_length;
    clamp(&z);
    try std.testing.expectEqual(@as(u8, 0x00), z[0]);
    try std.testing.expectEqual(@as(u8, 0x80), z[scalar_length - 1]);
}

test "RFC 7748 §5.2 X448 test vector 1: scalarmult, byte-exact" {
    // Duplicated (with the expected output asserted) in ../kat_test.zig
    // alongside the full vector set; kept here too as this file's own
    // smoke test.
    var scalar: [56]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" ++
        "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    var u: [56]u8 = undefined;
    _ = try std.fmt.hexToBytes(&u, "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" ++
        "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    var expected: [56]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" ++
        "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
    const out = try scalarmult(scalar, u);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "KeyPair.deinit zeroizes secret_key in place (regression: fails if secureZero is removed)" {
    var seed: [56]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" ++
        "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    var kp = try KeyPair.generateDeterministic(seed);
    const zero_scalar = [_]u8{0} ** scalar_length;
    try std.testing.expect(!std.mem.eql(u8, &kp.secret_key, &zero_scalar));
    kp.deinit();
    try std.testing.expectEqualSlices(u8, &zero_scalar, &kp.secret_key);
    // public_key is NOT secret and must survive deinit untouched.
    try std.testing.expect(!std.mem.eql(u8, &kp.public_key, &zero_scalar));
}
