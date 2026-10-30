// SPDX-License-Identifier: MIT
//! No-panic sweep regression tests (wave GT). The sweep found no defect in
//! slhdsa (see ~/CML/20261029-panic-sweep/slhdsa-sweep.report.md); these pin
//! the "Clean" claims: every attacker-reachable verify entry answers false for
//! malformed input and the signing entries refuse bad lengths with an error.
const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

const S = root.SlhDsaSha2_128f;

fn keypair() S.KeyPair {
    var seed: [3 * S.n]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var kp: S.KeyPair = undefined;
    S.keyGen(&kp, &seed);
    return kp;
}

test "verify: every wrong signature length is false, never a panic (sweep SL-clean)" {
    const kp = keypair();
    var sig: [S.signature_length + 1]u8 = @splat(0xA5);
    for ([_]usize{ 0, 1, S.n, S.signature_length - 1, S.signature_length + 1 }) |len| {
        try testing.expect(!S.verify(sig[0..len], "m", kp.pk, ""));
        try testing.expect(!S.verifyInternal(sig[0..len], "m", kp.pk));
        try testing.expect(!S.verifyPrehash(sig[0..len], "m", kp.pk, "", .sha2_256));
    }
}

test "verify: a full-length garbage signature, all-ones and all-zero keys are false (sweep SL-clean)" {
    var kp = keypair();
    const sig: [S.signature_length]u8 = @splat(0xFF);
    try testing.expect(!S.verify(&sig, "m", kp.pk, ""));
    const zero_sig: [S.signature_length]u8 = @splat(0);
    try testing.expect(!S.verify(&zero_sig, "m", kp.pk, "ctx"));
    kp.pk = S.PublicKey.fromBytes(@splat(0xFF));
    try testing.expect(!S.verify(&sig, "m", kp.pk, ""));
    kp.pk = S.PublicKey.fromBytes(@splat(0));
    try testing.expect(!S.verify(&zero_sig, "", kp.pk, ""));
}

test "context and digest lengths: 256-byte ctx and wrong digests are refused (sweep SL-clean)" {
    const kp = keypair();
    const ctx: [256]u8 = @splat(1);
    const sig: [S.signature_length]u8 = @splat(0);
    var out: [S.signature_length]u8 = undefined;
    try testing.expect(!S.verify(&sig, "m", kp.pk, &ctx));
    try testing.expect(!S.verifyPrehash(&sig, "m", kp.pk, &ctx, .sha2_256));
    try testing.expectError(error.ContextTooLong, S.sign(&out, "m", &kp.sk, &ctx, null));
    try testing.expectError(error.ContextTooLong, S.signPrehash(&out, "m", &kp.sk, &ctx, .sha2_256, null));
    const digest: [64]u8 = @splat(0);
    inline for (@typeInfo(S.PreHash).@"enum".field_values) |fv| {
        const ph: S.PreHash = @fromBackingInt(@intCast(fv));
        const want = ph.digestLength();
        try testing.expectError(error.DigestLengthMismatch, S.signPrehashDigest(&out, digest[0 .. want - 1], &kp.sk, "", ph, null));
        try testing.expectError(error.DigestLengthMismatch, S.signPrehashDigest(&out, digest[0..0], &kp.sk, "", ph, null));
        try testing.expect(!S.verifyPrehashDigest(&sig, digest[0 .. want - 1], kp.pk, "", ph));
        if (want < 64) try testing.expect(!S.verifyPrehashDigest(&sig, digest[0 .. want + 1], kp.pk, "", ph));
    }
}
