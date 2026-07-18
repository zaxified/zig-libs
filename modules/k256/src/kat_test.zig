// SPDX-License-Identifier: MIT

//! kat_test — the EXTERNAL-vector harness with teeth.
//!
//!   1. **BIP340 official vectors** (`kat_vectors.zig`). The 8 secret-key rows
//!      must `bip340Sign` to the EXACT published signature (byte-exact), and all
//!      19 rows must `bip340Verify` to the published TRUE/FALSE. This is the
//!      end-to-end anchor: it exercises k256's field, group, scalar, and
//!      scalarmul together against a reference produced by an entirely
//!      independent implementation.
//!   2. **Broken positive control** (`brokenReduceWide`). A field reduction with
//!      the Solinas constant off by one (`2^32 + 976` instead of `+ 977`)
//!      disagrees with std on random inputs — proving the special reduction is
//!      load-bearing and the equality checks have teeth (a wrong constant would
//!      NOT sneak through green).

const std = @import("std");
const sign = @import("sign.zig");
const field = @import("field.zig");
const kv = @import("kat_vectors.zig");

const StdFe = std.crypto.ecc.Secp256k1.Fe;

fn hex32(comptime_or_runtime: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, comptime_or_runtime) catch unreachable;
    return out;
}

fn hex64(s: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "BIP340 official vectors: sign byte-exact + verify TRUE/FALSE" {
    var msg_buf: [128]u8 = undefined;
    for (kv.vectors) |vec| {
        const msg = msg_buf[0 .. vec.message.len / 2];
        _ = std.fmt.hexToBytes(msg, vec.message) catch unreachable;
        const pubkey = hex32(vec.public_key);
        const sig = hex64(vec.signature);

        // Sign rows: k256 must reproduce the exact published signature.
        if (vec.secret_key) |sk_hex| {
            const sk = hex32(sk_hex);
            const aux = hex32(vec.aux_rand.?);
            const produced = try sign.bip340Sign(sk, msg, aux);
            try std.testing.expectEqualSlices(u8, &sig, &produced);
        }

        // Every row: verify must match the published result.
        try std.testing.expectEqual(vec.result, sign.bip340Verify(pubkey, msg, sig));
    }
}

// ── broken positive control: a wrong Solinas constant must be caught ─────────

/// The field reduction with the fold constant deliberately wrong (`2^32 + 976`).
/// Structurally identical to `field.reduceWide` otherwise.
fn brokenReduceWide(wide: u512) [4]u64 {
    const C_wrong: u512 = (1 << 32) + 976; // BUG: should be +977
    const mask: u512 = (@as(u512, 1) << 256) - 1;
    var x = wide;
    inline for (0..6) |_| {
        x = (x & mask) + C_wrong * (x >> 256);
    }
    // Reduce the (possibly still slightly oversized) low part mod the REAL p so
    // the only difference from the oracle is the wrong fold — not a format skew.
    var v: u256 = @truncate(x & mask);
    const P = field.field_order;
    while (v >= P) v -= P;
    return .{ @truncate(v), @truncate(v >> 64), @truncate(v >> 128), @truncate(v >> 192) };
}

test "positive control: wrong Solinas constant DISAGREES with std (harness has teeth)" {
    var prng = std.Random.DefaultPrng.init(0xB0_9E_1D02);
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
