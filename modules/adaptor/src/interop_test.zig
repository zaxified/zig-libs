// SPDX-License-Identifier: MIT
//! EXTERNAL interop tests — the anchor `kat_test.zig` structurally cannot be.
//!
//! `kat_test.zig` pins this module against `kat_vectors.zig`, whose six vectors
//! were computed independently in Python but **from the same construction this
//! module implements** (they say so in their own header). That corpus catches
//! implementation drift precisely; it cannot catch a convention or soundness
//! error shared by the code and the vectors, because their common author is the
//! thing under test (audit finding `adaptor` F1).
//!
//! The vectors used here come from `interop_vectors.zig`, frozen from
//! LLFourn/secp256kfun's `schnorr_fun::adaptor` (0BSD) — an implementation with
//! no shared code, author or derivation. See that file for exact crate
//! versions and the literal command that produced the bytes. **These tests are
//! fully offline**: the Rust toolchain is needed only to regenerate, never to
//! run, and nothing here skips.
//!
//! Two corpora, testing two different things:
//!
//!   * **Corpus A** (`foreign_vectors`) — pre-signatures schnorr_fun ORIGINATED.
//!     `preSign` here can never produce these (the nonce derivations differ by
//!     design), so this is the only way `preVerify`/`adapt`/`extract` are ever
//!     exercised on inputs this module did not manufacture.
//!   * **Corpus B** (`self_authored_cross_check`) — schnorr_fun's verdict and
//!     outputs on our OWN six self-authored vectors, so the pre-existing corpus
//!     is now cross-validated by foreign code rather than by its own author.

const std = @import("std");
const adaptor = @import("root.zig");
const bip340 = @import("bip340");
const iv = @import("interop_vectors.zig");
const v = @import("kat_vectors.zig");

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

/// Decodes a hex-encoded message into caller-owned bytes (messages vary in
/// length, including empty and >64 bytes, so this cannot be a fixed array).
fn msgBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(buf);
    _ = try std.fmt.hexToBytes(buf, hex_str);
    return buf;
}

// ── corpus guards (a corpus that lost its coverage must fail loudly) ────

test "interop: the frozen foreign corpus is non-empty and covers BOTH needs_negation branches" {
    try std.testing.expect(iv.foreign_vectors.len >= 8);
    var negated: usize = 0;
    var plain: usize = 0;
    for (iv.foreign_vectors) |vec| {
        if (vec.needs_negation) negated += 1 else plain += 1;
    }
    // Without both branches present, the parity convention — the single field
    // two implementations must agree on to interoperate — would go unanchored.
    try std.testing.expect(negated > 0);
    try std.testing.expect(plain > 0);
}

test "interop: corpus B lines up index-for-index with kat_vectors.vectors" {
    try std.testing.expectEqual(v.vectors.len, iv.self_authored_cross_check.len);
}

// ── corpus A: schnorr_fun-originated pre-signatures ─────────────────────

test "interop: preVerify ACCEPTS every schnorr_fun-originated pre-signature" {
    const allocator = std.testing.allocator;
    for (iv.foreign_vectors) |vec| {
        const msg = try msgBytes(allocator, vec.msg_hex);
        defer allocator.free(msg);

        const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const presig = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = vec.needs_negation,
        };
        if (!adaptor.preVerify(px, msg, t_point, presig)) {
            std.debug.print("preVerify rejected foreign vector: {s}\n", .{vec.label});
            return error.ForeignPreSignatureRejected;
        }
    }
}

test "interop: adapt reproduces schnorr_fun's decrypt_signature BYTE-EXACTLY" {
    for (iv.foreign_vectors) |vec| {
        const presig = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = vec.needs_negation,
        };
        const sig = try adaptor.adapt(presig, hexN(32, vec.t));
        try std.testing.expectEqualSlices(u8, &hexN(64, vec.sig), &sig);
    }
}

test "interop: extract reproduces schnorr_fun's recover_decryption_key BYTE-EXACTLY" {
    for (iv.foreign_vectors) |vec| {
        // A `None` from recover_decryption_key would be encoded as an empty
        // string; the generator asserts it never happened, and so do we.
        try std.testing.expectEqual(@as(usize, 64), vec.recovered_t.len);

        const presig = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = vec.needs_negation,
        };
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const full_sig = try bip340.Signature.fromBytes(hexN(64, vec.sig));

        const recovered = try adaptor.extract(presig, full_sig, t_point);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.recovered_t), &recovered);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.t), &recovered);
    }
}

test "interop: plain bip340.verify accepts every schnorr_fun-decrypted signature" {
    // The scheme's headline property, asserted on signatures this module did
    // not produce: a decrypted adaptor signature is an ORDINARY BIP340
    // signature. Chains into bip340's own official BIP340 vectors.
    const allocator = std.testing.allocator;
    for (iv.foreign_vectors) |vec| {
        const msg = try msgBytes(allocator, vec.msg_hex);
        defer allocator.free(msg);

        const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
        const full_sig = try bip340.Signature.fromBytes(hexN(64, vec.sig));
        try std.testing.expect(bip340.verify(px, msg, full_sig));
    }
}

test "interop: preVerify REJECTS every foreign pre-signature with a FLIPPED needs_negation bit" {
    // This is the interop-critical assertion. `needs_negation` is a wire bit
    // whose MEANING (true == `R + T` had odd y, hence the decryptor negates)
    // is a convention two implementations must share. A globally consistent
    // relabelling of that bit round-trips perfectly inside this module and
    // would be reproduced by any corpus regenerated from the same
    // construction — but it breaks interop, and only a foreign corpus sees it.
    const allocator = std.testing.allocator;
    for (iv.foreign_vectors) |vec| {
        const msg = try msgBytes(allocator, vec.msg_hex);
        defer allocator.free(msg);

        const px = try bip340.XOnlyPublicKey.fromBytes(hexN(32, vec.px));
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));
        const flipped = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = !vec.needs_negation,
        };
        try std.testing.expect(!adaptor.preVerify(px, msg, t_point, flipped));
    }
}

// ── corpus B: foreign judgement on our OWN self-authored vectors ────────

test "interop: schnorr_fun ACCEPTED all six self-authored pre-signatures" {
    for (iv.self_authored_cross_check, v.vectors) |cross, vec| {
        if (!cross.foreign_pre_verify) {
            std.debug.print("schnorr_fun rejected self-authored vector: {s}\n", .{vec.label});
            return error.SelfAuthoredVectorRejectedByReference;
        }
        // And it recovered a key rather than returning None.
        try std.testing.expectEqual(@as(usize, 64), cross.foreign_recovered_t.len);
    }
}

test "interop: adapt/extract on the SELF-AUTHORED vectors match schnorr_fun's own outputs" {
    // Ties `kat_vectors.zig` to foreign bytes: mutate a self-authored
    // `s_prime`/`needs_negation` and our adapt output moves while the frozen
    // schnorr_fun output does not.
    for (iv.self_authored_cross_check, v.vectors) |cross, vec| {
        const presig = adaptor.PreSignature{
            .r = hexN(32, vec.r),
            .s_prime = hexN(32, vec.s_prime),
            .needs_negation = vec.needs_negation,
        };
        const t_point = try adaptor.AdaptorPoint.fromBytes(hexN(33, vec.adaptor_point));

        const sig = try adaptor.adapt(presig, hexN(32, vec.t));
        try std.testing.expectEqualSlices(u8, &hexN(64, cross.foreign_sig), &sig);

        const full_sig = try bip340.Signature.fromBytes(sig);
        const recovered = try adaptor.extract(presig, full_sig, t_point);
        try std.testing.expectEqualSlices(u8, &hexN(32, cross.foreign_recovered_t), &recovered);
    }
}
