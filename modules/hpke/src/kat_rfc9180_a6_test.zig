// SPDX-License-Identifier: MIT
//! RFC 9180 A.6 (DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM), all
//! four modes, driven through the whole chain byte-exact — the same six
//! stages as `kat_rfc9180.zig`'s `driveVector`, at Nh = 64: DeriveKeyPair
//! (the 0x01 bitmask), (Auth)Encap/(Auth)Decap, key_schedule_context and
//! secret from the §4 primitives, KeySchedule, every published encryption
//! (seal and open), every exported value. Vectors: `kat_rfc9180_a6.zig`
//! (`tools/gen_rfc9180_a6.py`).

const std = @import("std");
const testing = std.testing;
const suite = @import("suite.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");
const a6 = @import("kat_rfc9180_a6.zig");

const HkdfSha512 = std.crypto.kdf.hkdf.HkdfSha512;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Kem = dhkem.P521Kem;

fn drive(comptime V: type) !void {
    const mode: suite.Mode = @enumFromInt(V.mode);
    const is_auth = comptime (mode == .auth or mode == .auth_psk);
    const psk: []const u8 = if (@hasDecl(V, "psk")) &V.psk else "";
    const psk_id: []const u8 = if (@hasDecl(V, "psk_id")) &V.psk_id else "";
    try testing.expectEqual(Kem.kem_id, V.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KdfId.hkdf_sha512)), V.kdf_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes256gcm)), V.aead_id);

    // 1. DeriveKeyPair (§7.1.3, bitmask 0x01).
    var kpE: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&kpE, &V.ikmE);
    try testing.expectEqualSlices(u8, &V.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &V.pkEm, &kpE.public_key);
    var kpR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&kpR, &V.ikmR);
    try testing.expectEqualSlices(u8, &V.skRm, &kpR.secret_key);
    try testing.expectEqualSlices(u8, &V.pkRm, &kpR.public_key);

    // 2. (Auth)Encap / (Auth)Decap (§4.1).
    var encapped: Kem.Encapped = undefined;
    var decapped: [Kem.Nsecret]u8 = undefined;
    if (comptime is_auth) {
        var kpS: Kem.KeyPair = undefined;
        Kem.deriveKeyPair(&kpS, &V.ikmS);
        try testing.expectEqualSlices(u8, &V.skSm, &kpS.secret_key);
        try testing.expectEqualSlices(u8, &V.pkSm, &kpS.public_key);
        try Kem.authEncapDeterministic(&encapped, V.pkRm, &kpS, &kpE);
        try Kem.authDecap(&decapped, V.enc, &kpR, V.pkSm);
    } else {
        try Kem.encapDeterministic(&encapped, V.pkRm, &kpE);
        try Kem.decap(&decapped, V.enc, &kpR);
    }
    try testing.expectEqualSlices(u8, &V.enc, &encapped.enc);
    try testing.expectEqualSlices(u8, &V.shared_secret, &encapped.shared_secret);
    try testing.expectEqualSlices(u8, &V.shared_secret, &decapped);

    // 3. key_schedule_context + secret from the §4 primitives.
    const suite_id = suite.suiteId(V.kem_id, V.kdf_id, V.aead_id);
    var psk_id_hash: [HkdfSha512.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha512, &psk_id_hash, &suite_id, "", "psk_id_hash", psk_id);
    var info_hash: [HkdfSha512.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha512, &info_hash, &suite_id, "", "info_hash", &V.info);
    var ksc: [129]u8 = undefined;
    ksc[0] = V.mode;
    ksc[1..65].* = psk_id_hash;
    ksc[65..129].* = info_hash;
    try testing.expectEqualSlices(u8, &V.key_schedule_context, &ksc);
    var secret: [HkdfSha512.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha512, &secret, &suite_id, &V.shared_secret, "secret", psk);
    try testing.expectEqualSlices(u8, &V.secret, &secret);

    // 4. KeySchedule (§5.1).
    var sender: schedule.Context(Aes256Gcm, 64) = undefined;
    try schedule.keySchedule(Aes256Gcm, 64, &sender, mode, &suite_id, &V.shared_secret, &V.info, psk, psk_id);
    try testing.expectEqualSlices(u8, &V.key, &sender.key);
    try testing.expectEqualSlices(u8, &V.base_nonce, &sender.base_nonce);
    try testing.expectEqualSlices(u8, &V.exporter_secret, &sender.exporter_secret);
    var receiver = sender;

    // 5. Every published encryption, sealed and opened (§5.2).
    try testing.expectEqual(@as(usize, 6), V.encryptions.len);
    for (V.encryptions) |e| {
        try testing.expectEqualSlices(u8, &e.nonce, &schedule.computeNonce(12, V.base_nonce, e.seq));
        sender.seq = e.seq;
        var ct: [45]u8 = undefined;
        try testing.expectEqual(ct.len, e.ct.len);
        try sender.seal(e.aad, e.pt, &ct);
        try testing.expectEqualSlices(u8, e.ct, &ct);
        receiver.seq = e.seq;
        var pt: [29]u8 = undefined;
        try receiver.open(e.aad, e.ct, &pt);
        try testing.expectEqualSlices(u8, e.pt, &pt);
    }

    // 6. Every published exported value (§5.3).
    try testing.expectEqual(@as(usize, 3), V.exports.len);
    for (V.exports) |x| {
        var got: [32]u8 = undefined;
        try sender.exportSecret(&suite_id, x.exporter_context, &got);
        try testing.expectEqualSlices(u8, &x.exported_value, &got);
    }
}

test "A.6.1 (base): P-521 + HKDF-SHA512 + AES-256-GCM, full vector end-to-end, byte-exact" {
    try drive(a6.a6);
}

test "A.6.2 (mode_psk): P-521, full vector end-to-end, byte-exact" {
    try drive(a6.a6_psk);
}

test "A.6.3 (mode_auth): P-521, full vector end-to-end, byte-exact" {
    try drive(a6.a6_auth);
}

test "A.6.4 (mode_auth_psk): P-521, full vector end-to-end, byte-exact" {
    try drive(a6.a6_auth_psk);
}

test "A.6.1: single-shot sealBaseDeterministic/openBase (Nh=64) reproduce enc + the first ciphertext" {
    const V = a6.a6;
    const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
    const first = V.encryptions[0];
    var ct: [45]u8 = undefined;
    const sealed = try schedule.sealBaseDeterministic(Kem, Aes256Gcm, 64, V.pkRm, &eph, &V.info, first.aad, first.pt, &ct);
    try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
    try testing.expectEqualSlices(u8, first.ct, &ct);
    const skR = Kem.KeyPair{ .secret_key = V.skRm, .public_key = V.pkRm };
    var pt: [29]u8 = undefined;
    try schedule.openBase(Kem, Aes256Gcm, 64, sealed.enc, &skR, &V.info, first.aad, &ct, &pt);
    try testing.expectEqualSlices(u8, first.pt, &pt);
}

test "P521Kem: malformed or off-curve peer points are DeserializeError, never a panic" {
    const V = a6.a6;
    var kpE: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&kpE, &V.ikmE);
    var o: Kem.Encapped = undefined;
    var bad = V.pkRm;
    bad[132] ^= 1; // off the curve
    try testing.expectError(error.DeserializeError, Kem.encapDeterministic(&o, bad, &kpE));
    bad = V.pkRm;
    bad[0] = 0x02; // a compressed prefix on a 133-byte key
    try testing.expectError(error.DeserializeError, Kem.encapDeterministic(&o, bad, &kpE));
    var kpR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&kpR, &V.ikmR);
    var s: [Kem.Nsecret]u8 = undefined;
    try testing.expectError(error.DeserializeError, Kem.decap(&s, [_]u8{0} ** Kem.Npk, &kpR));
}
