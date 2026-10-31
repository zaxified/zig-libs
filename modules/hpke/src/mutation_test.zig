// SPDX-License-Identifier: MIT
//! Tests added by the 2026-10-31 mutation audit of `hpke` (suite, kdf, dhkem,
//! schedule, pq): each one kills a mutant the pre-existing tests let survive.
//! The comment above a test names the line it pins.

const std = @import("std");
const testing = std.testing;
const aesgcm = @import("aesgcm");
const chachapoly = @import("chachapoly");
const suite = @import("suite.zig");
const kdf = @import("kdf.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");
const pq = @import("pq.zig");

const Aead = aesgcm.Aes128Gcm;

fn expectZeroed(ptr: anytype) !void {
    for (std.mem.asBytes(ptr)) |b| try testing.expectEqual(@as(u8, 0), b);
}

// suite.labeledExpand: the labeled info is assembled in a 512-byte scratch, so
// 2 (L) + 7 ("HPKE-v1") + 10 (suite_id) + label + info = 512 bytes is the
// largest that fits; one more byte is LabelTooLong.
test "labeledExpand: the 512-byte label scratch takes exactly 512 bytes of labeled info" {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const prk: [32]u8 = @splat(5);
    var info: [493]u8 = @splat('i');
    var out: [32]u8 = undefined;
    try suite.labeledExpand(Hkdf, &sid, &prk, "x", info[0..492], &out);
    try testing.expectError(error.LabelTooLong, suite.labeledExpand(Hkdf, &sid, &prk, "x", info[0..493], &out));
}

// kdf.labeledDerive: the label is length-prefixed in two bytes, so 65,535 fits.
test "labeledDerive: a label of 65535 bytes works, 65536 is LabelTooLong" {
    const label = try testing.allocator.alloc(u8, kdf.max_one_stage_len + 1);
    defer testing.allocator.free(label);
    @memset(label, 'l');
    var out: [32]u8 = undefined;
    try kdf.Shake256.labeledDerive(&out, "sid", &.{"ikm"}, label[0..kdf.max_one_stage_len], &.{});
    try testing.expectError(error.LabelTooLong, kdf.Shake256.labeledDerive(&out, "sid", &.{"ikm"}, label, &.{}));
}

// schedule.oneStageSchedule: every length-prefixed field (shared_secret, psk,
// psk_id, info) takes 65,535 bytes; 65,536 is LabelTooLong.
test "one-stage key schedule: shared_secret, psk, psk_id and info each take 65535 bytes and refuse 65536" {
    const K = kdf.Shake256;
    const sid = suite.suiteId(0x647a, K.kdf_id, 0x0001);
    var ctx: schedule.Context(Aead, K) = undefined;
    const big = try testing.allocator.alloc(u8, kdf.max_one_stage_len + 1);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    const ok = big[0..kdf.max_one_stage_len];
    const small: [32]u8 = @splat(1);
    // shared_secret
    try schedule.keySchedule(Aead, K, &ctx, .base, &sid, ok, "", "", "");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .base, &sid, big, "", "", ""));
    // info
    try schedule.keySchedule(Aead, K, &ctx, .base, &sid, &small, ok, "", "");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .base, &sid, &small, big, "", ""));
    // psk
    try schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", ok, "id");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", big, "id"));
    // psk_id
    try schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", &small, ok);
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", &small, big));
}

// schedule.sealBody: a plaintext past the AEAD's message limit is InvalidLength
// BEFORE any byte of it is read (fabricated slices; they are never touched).
test "seal: a plaintext past max_message_len is InvalidLength without reading it" {
    inline for (.{ Aead, chachapoly.ChaCha20Poly1305 }) |A| {
        const C = schedule.Context(A, 32);
        var ctx: C = .{ .key = @splat(1), .base_nonce = @splat(2), .exporter_secret = @splat(3) };
        const n: usize = @intCast(C.max_message_len + 1);
        const pt_ptr: [*]const u8 = @ptrFromInt(0x10000);
        const out_ptr: [*]u8 = @ptrFromInt(0x20000);
        try testing.expectError(error.InvalidLength, ctx.seal("", pt_ptr[0..n], out_ptr[0 .. n + A.tag_length]));
        try testing.expectEqual(@as(u64, 0), ctx.seq);
    }
}

// pq.zig, pure ML-KEM: a non-canonical encapsulation key (coefficient >= q) is
// DeserializeError (not another error) and `out` is zeroed.
test "ML-KEM encap: a non-canonical encapsulation key is DeserializeError and zeroes out" {
    inline for (.{ pq.MlKem512Kem, pq.MlKem768Kem, pq.MlKem1024Kem }) |K| {
        var kp: K.KeyPair = undefined;
        K.fromSeed(&kp, &@as([K.Nsk]u8, @splat(3)));
        var pk = kp.public_key;
        pk[0] = 0xff;
        pk[1] = 0xff;
        pk[2] = 0xff; // two coefficients of 4095 >= q = 3329
        const eph: K.Ephemeral = @splat(5);
        var out: K.Encapped = undefined;
        @memset(std.mem.asBytes(&out), 0xaa);
        try testing.expectError(error.DeserializeError, K.encapDeterministic(&out, pk, &eph));
        try expectZeroed(&out);
        try K.encapDeterministic(&out, kp.public_key, &eph); // positive control
    }
}

// pq.zig, hybrid decap: a low-order X25519 half is DhFailed and zeroes `out`
// (nothing wrote to `out` before the failure, so only the errdefer clears it).
test "hybrid decap: DhFailed zeroes out" {
    const K = pq.MlKem768X25519Kem;
    var kp: K.KeyPair = undefined;
    K.fromSeed(&kp, &@as([32]u8, @splat(7)));
    const enc: K.EncappedKey = @splat(0);
    var out: [32]u8 = @splat(0xaa);
    try testing.expectError(error.DhFailed, K.decap(&out, enc, &kp));
    try expectZeroed(&out);
}

// pq.zig NistGroup: a zero scalar is not a candidate (the first valid
// candidate is the one used), and a point that does not decode is
// DeserializeError on both the encap and the decap side.
test "hybrid NIST: zero candidates are skipped; an undecodable curve point is DeserializeError" {
    inline for (.{ .{ pq.MlKem768P256Kem, 1184 }, .{ pq.MlKem1024P384Kem, 1568 } }) |spec| {
        const K = spec[0];
        const ek_pq_len = spec[1];
        var kp: K.KeyPair = undefined;
        K.fromSeed(&kp, &@as([32]u8, @splat(9)));
        var out: K.Encapped = undefined;

        // No valid candidate (all zero): DhFailed.
        var zero_eph: K.Ephemeral = @splat(0);
        try testing.expectError(error.DhFailed, K.encapDeterministic(&out, kp.public_key, &zero_eph));

        // A zero candidate before a valid one is skipped: same as 0xff.. (>= n).
        if (K == pq.MlKem768P256Kem) {
            var eph_a: K.Ephemeral = @splat(0x11);
            var eph_b = eph_a;
            @memset(eph_a[32..][0..32], 0);
            @memset(eph_b[32..][0..32], 0xff);
            var out_b: K.Encapped = undefined;
            try K.encapDeterministic(&out, kp.public_key, &eph_a);
            try K.encapDeterministic(&out_b, kp.public_key, &eph_b);
            try testing.expectEqualSlices(u8, &out.shared_secret, &out_b.shared_secret);
            try testing.expectEqualSlices(u8, &out.enc, &out_b.enc);
        }

        // ek_T that is not a curve point.
        var bad_pk = kp.public_key;
        @memset(bad_pk[ek_pq_len..], 0);
        const good_eph: K.Ephemeral = @splat(0x11);
        try testing.expectError(error.DeserializeError, K.encapDeterministic(&out, bad_pk, &good_eph));

        // ct_T that is not a curve point.
        var enc: K.EncappedKey = @splat(0);
        var ss: [32]u8 = @splat(0xaa);
        try testing.expectError(error.DeserializeError, K.decap(&ss, enc, &kp));
        try expectZeroed(&ss);
        enc = @splat(0xff);
        try testing.expectError(error.DeserializeError, K.decap(&ss, enc, &kp));
    }
}

// dhkem.zig: a zero ephemeral scalar gives the identity as the DH result, which
// is DhFailed (not a deserialization error), for every NIST KEM.
test "DHKEM NIST encap with a zero ephemeral scalar is DhFailed" {
    inline for (.{ dhkem.P256Kem, dhkem.P384Kem, dhkem.P521Kem }) |K| {
        var r: K.KeyPair = undefined;
        K.deriveKeyPair(&r, "recipient");
        var eph: K.KeyPair = undefined;
        K.deriveKeyPair(&eph, "ephemeral");
        eph.secret_key = @splat(0);
        var out: K.Encapped = undefined;
        try testing.expectError(error.DhFailed, K.encapDeterministic(&out, r.public_key, &eph));
    }
}
