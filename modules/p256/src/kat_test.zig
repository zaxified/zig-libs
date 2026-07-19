// SPDX-License-Identifier: MIT

//! kat_test — the EXTERNAL-vector harness with teeth.
//!
//!   1. **RFC 6979 official vectors** (`kat_vectors.zig`). Each `(r, s)` must
//!      `ecdsaVerify` to TRUE under the RFC-published key and message, and a
//!      one-byte tamper must verify FALSE. This is the end-to-end anchor: it
//!      exercises p256's field, group, scalar, and double-base multiply together
//!      against a signature produced by an entirely independent (deterministic
//!      RFC 6979) implementation. As an extra cross-check, std's own P-256
//!      verifier is asserted to accept the SAME vector (so the transcription is
//!      pinned to std too, not just to p256's self-consistency).
//!   2. **Broken positive control** (`brokenReduceWide`). A field reduction with
//!      the P-256 Solinas fold constant off by one bit (`M ± 1` instead of `M =
//!      2^224 − 2^192 − 2^96 + 1`) disagrees with std on random inputs — proving
//!      the special reduction is load-bearing and the equality checks have teeth
//!      (a wrong constant would NOT sneak through green).

const std = @import("std");
const sign = @import("sign.zig");
const field = @import("field.zig");
const kv = @import("kat_vectors.zig");

const StdFe = std.crypto.ecc.P256.Fe;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn hexBytes(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 6979 P-256/SHA-256 vectors: p256 verifies TRUE, tamper FALSE, std agrees" {
    // Decode the uncompressed-SEC1 public key once.
    var pk_sec1: [65]u8 = undefined;
    _ = std.fmt.hexToBytes(&pk_sec1, kv.public_key_sec1) catch unreachable;
    const std_pk = try StdEcdsa.PublicKey.fromSec1(&pk_sec1);

    for (kv.vectors) |vec| {
        var sig: [64]u8 = undefined;
        sig[0..32].* = hexBytes(32, vec.r);
        sig[32..64].* = hexBytes(32, vec.s);

        // p256 must accept the published signature.
        try std.testing.expect(sign.ecdsaVerify(&pk_sec1, vec.message, sig));

        // Independent cross-check: std's P-256 verifier accepts the same vector
        // (confirms the transcription, not just p256's internal consistency).
        try StdEcdsa.Signature.fromBytes(sig).verify(vec.message, std_pk);

        // Tamper with one signature byte → p256 must reject.
        var bad = sig;
        bad[20] ^= 0x01;
        try std.testing.expect(!sign.ecdsaVerify(&pk_sec1, vec.message, bad));

        // Tamper with one message byte → p256 must reject.
        var bad_msg_buf: [64]u8 = undefined;
        @memcpy(bad_msg_buf[0..vec.message.len], vec.message);
        bad_msg_buf[0] ^= 0x01;
        try std.testing.expect(!sign.ecdsaVerify(&pk_sec1, bad_msg_buf[0..vec.message.len], sig));
    }
}

// ── broken positive control: a wrong Solinas fold constant must be caught ─────

/// The field reduction with the fold constant deliberately wrong: `M − 1`
/// instead of the correct `M = 2^224 − 2^192 − 2^96 + 1` (so `2^256 ≢ M` and the
/// congruence is broken). Structurally identical to `field.reduceWide` otherwise
/// — many folds, then reduce mod the REAL p, so the ONLY difference from the
/// oracle is the wrong fold, not a format skew.
fn brokenReduceWide(wide: u512) [4]u64 {
    const M_wrong: u512 = (1 << 224) - (1 << 192) - (1 << 96) + 1 - 1; // BUG: −1
    const mask: u512 = (@as(u512, 1) << 256) - 1;
    var x = wide;
    inline for (0..20) |_| {
        x = (x & mask) + M_wrong * (x >> 256);
    }
    var v: u256 = @truncate(x & mask);
    const P = field.field_order;
    while (v >= P) v -= P;
    return .{ @truncate(v), @truncate(v >> 64), @truncate(v >> 128), @truncate(v >> 192) };
}

test "positive control: wrong Solinas constant DISAGREES with std (harness has teeth)" {
    var prng = std.Random.DefaultPrng.init(0xB0_9E_9256);
    const rand = prng.random();
    var disagreements: usize = 0;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rand.bytes(&ab);
        rand.bytes(&bb);
        const sa = StdFe.fromBytes(ab, .big) catch continue;
        const sb = StdFe.fromBytes(bb, .big) catch continue;
        const want = sa.mul(sb).toBytes(.big);

        const av: u512 = std.mem.readInt(u256, &ab, .big);
        const bv: u512 = std.mem.readInt(u256, &bb, .big);
        const broken = brokenReduceWide(av * bv);
        var got: [32]u8 = undefined;
        std.mem.writeInt(u256, &got, @as(u256, broken[0]) | (@as(u256, broken[1]) << 64) |
            (@as(u256, broken[2]) << 128) | (@as(u256, broken[3]) << 192), .big);
        if (!std.mem.eql(u8, &want, &got)) disagreements += 1;
    }
    // The wrong constant must produce visible disagreement on almost every input.
    try std.testing.expect(disagreements > 400);
}
