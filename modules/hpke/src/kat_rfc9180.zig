// SPDX-License-Identifier: MIT
//! RFC 9180 Appendix A known-answer test vectors, fetched directly from
//! <https://www.rfc-editor.org/rfc/rfc9180> for this module (not copied
//! from any other implementation's test suite).
//!
//! - **A.1** (`DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`,
//!   base mode, §A.1.1): embedded IN FULL — every field the RFC
//!   publishes (`ikmE`/`pkEm`/`skEm`/`ikmR`/`pkRm`/`skRm`/`enc`/
//!   `shared_secret`/`key_schedule_context`/`secret`/`key`/`base_nonce`/
//!   `exporter_secret`, all 6 published `(seq, pt, aad, nonce, ct)`
//!   encryption tuples, and all 3 exported-value tuples).
//! - **A.2** (`DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305`)
//!   and **A.3** (`DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`):
//!   header fields only (mode/kem_id/kdf_id/aead_id/info/keys/enc/
//!   shared_secret/key_schedule_context/secret/key/base_nonce/
//!   exporter_secret + one encryption tuple each) — enough to KAT the
//!   DHKEM/key-schedule crypto core for these two suites too, without
//!   this module owning the full encryption-tuple table for every suite
//!   (A.1's is the canonical, fully-worked example).
//!
//! The crypto cores (`dhkem.X25519Kem`/`P256Kem` Encap/Decap/DeriveKeyPair,
//! `schedule.keySchedule`/`Context.seal`/`.open`/`.exportSecret`/
//! `sealBase`/`openBase`) are implemented — every test below drives them
//! for real against these vectors, byte-exact, no skip guards left.

const std = @import("std");
const suite = @import("suite.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

fn hexTo(comptime n: usize, s: *const [n * 2]u8) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// ── A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (base) ────

pub const a1 = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x00; // base

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");

    pub const ikmE = hexTo(32, "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    pub const pkEm = hexTo(32, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    pub const skEm = hexTo(32, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    pub const ikmR = hexTo(32, "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    pub const pkRm = hexTo(32, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    pub const skRm = hexTo(32, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    pub const enc = hexTo(32, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    pub const shared_secret = hexTo(32, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    pub const key_schedule_context = hexTo(65, "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    pub const secret = hexTo(32, "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
    pub const key = hexTo(16, "4531685d41d65f03dc48f6b8302c05b0");
    pub const base_nonce = hexTo(12, "56d890e5accaaf011cff4b7d");
    pub const exporter_secret = hexTo(32, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");

    /// §A.1.1.1 — all 6 published `(sequence number, pt, aad, nonce, ct)`
    /// tuples, INCLUDING the two that skip ahead (seq 4 after 0/1/2, and
    /// seq 256 after 255) — proof a correct `Context` must derive the
    /// nonce from `seq` directly (`base_nonce XOR I2OSP(seq, Nn)`), not
    /// from a running XOR/increment of the previous nonce.
    pub const Encryption = struct { seq: u64, pt: []const u8, aad: []const u8, nonce: [12]u8, ct: []const u8 };
    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7d"),
            .ct = &hexTo(45, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7c"),
            .ct = &hexTo(45, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7f"),
            .ct = &hexTo(45, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b79"),
            .ct = &hexTo(45, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b82"),
            .ct = &hexTo(45, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4a7d"),
            .ct = &hexTo(45, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
        },
    };

    /// §A.1.1.2 — the 3 published `(exporter_context, L, exported_value)`
    /// tuples.
    pub const Export = struct { exporter_context: []const u8, l: usize, exported_value: [32]u8 };
    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5") },
        .{ .exporter_context = "TestContext", .l = 32, .exported_value = hexTo(32, "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931") },
    };
};

// ── A.2 header: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ──

pub const a2 = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0003;
    pub const mode: u8 = 0x00;

    pub const skEm = hexTo(32, "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
    pub const pkEm = hexTo(32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    pub const pkRm = hexTo(32, "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    pub const skRm = hexTo(32, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    pub const enc = hexTo(32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    pub const shared_secret = hexTo(32, "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
    pub const secret = hexTo(32, "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6");
    pub const key = hexTo(32, "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"); // ChaCha20Poly1305: Nk=32
    pub const base_nonce = hexTo(12, "5c4d98150661b848853b547f");
    pub const exporter_secret = hexTo(32, "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922");

    // §A.2.1.1, sequence number 0.
    pub const seq0_ct = hexTo(45, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");
};

// ── A.3 header: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ─────

pub const a3 = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x00;

    // SEC1 uncompressed points: 0x04 || X(32) || Y(32) = 65 bytes.
    pub const pkEm = hexTo(65, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    pub const skEm = hexTo(32, "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
    pub const pkRm = hexTo(65, "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    pub const skRm = hexTo(32, "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    pub const enc = hexTo(65, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    pub const shared_secret = hexTo(32, "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");
    pub const secret = hexTo(32, "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1");
    pub const key = hexTo(16, "868c066ef58aae6dc589b6cfdd18f97e");
    pub const base_nonce = hexTo(12, "4e0bc5018beba4bf004cca59");
    pub const exporter_secret = hexTo(32, "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f");

    // §A.3.1.1, sequence number 0.
    pub const seq0_ct = hexTo(45, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434");
};

// ── composition tests (real labeledExtract/labeledExpand, no dhkem/schedule) ──

test "A.1/A.2/A.3 header ids match suite.KemId/KdfId/AeadId" {
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_x25519_hkdf_sha256)), a1.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KdfId.hkdf_sha256)), a1.kdf_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes128gcm)), a1.aead_id);

    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_x25519_hkdf_sha256)), a2.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.chacha20poly1305)), a2.aead_id);

    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_p256_hkdf_sha256)), a3.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes128gcm)), a3.aead_id);
}

test "A.1.1: enc == pkEm (base-mode DHKEM's enc IS the ephemeral public key, no extra encoding)" {
    try testing.expectEqualSlices(u8, &a1.pkEm, &a1.enc);
}

test "A.1.1: key_schedule_context/secret/key/base_nonce/exporter_secret, byte-exact via real LabeledExtract/LabeledExpand" {
    // Same chain as suite.zig's own KAT test, driven from this file's copy
    // of the vector — proves the two files agree on both the recipe AND
    // the constants, independent of dhkem/schedule (which the tests
    // further down drive for real).
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const psk_id_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "psk_id_hash", "");
    const info_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "info_hash", &a1.info);

    var ksc: [65]u8 = undefined;
    ksc[0] = a1.mode;
    ksc[1..33].* = psk_id_hash;
    ksc[33..65].* = info_hash;
    try testing.expectEqualSlices(u8, &a1.key_schedule_context, &ksc);

    const secret = suite.labeledExtract(HkdfSha256, &suite_id, &a1.shared_secret, "secret", "");
    try testing.expectEqualSlices(u8, &a1.secret, &secret);

    var key: [16]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "key", &ksc, &key);
    try testing.expectEqualSlices(u8, &a1.key, &key);

    var base_nonce: [12]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "base_nonce", &ksc, &base_nonce);
    try testing.expectEqualSlices(u8, &a1.base_nonce, &base_nonce);

    var exporter_secret: [32]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "exp", &ksc, &exporter_secret);
    try testing.expectEqualSlices(u8, &a1.exporter_secret, &exporter_secret);
}

test "A.1.1.2: all 3 exported values, byte-exact via real LabeledExpand(exporter_secret, \"sec\", ...)" {
    // RFC 9180 §5.3 Context.Export = LabeledExpand(suite_id,
    // exporter_secret, "sec", exporter_context, L) — driven here through
    // suite.labeledExpand directly (the Context.exportSecret method is
    // exercised separately below), so the raw math and the wrapper are
    // verified independently.
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    for (a1.exports) |exp| {
        var got: [32]u8 = undefined;
        std.debug.assert(exp.l == 32);
        try suite.labeledExpand(HkdfSha256, &suite_id, a1.exporter_secret, "sec", exp.exporter_context, &got);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got);
    }
}

test "A.1.1.1: nonce = base_nonce XOR I2OSP(seq, Nn), byte-exact for all 6 published seq numbers" {
    for (a1.encryptions) |enc_case| {
        const got = schedule.computeNonce(12, a1.base_nonce, enc_case.seq);
        try testing.expectEqualSlices(u8, &enc_case.nonce, &got);
    }
}

// ── crypto-core tests (formerly stub-blocked, now driven for real) ──────

test "A.1.1: DHKEM(X25519).encapDeterministic(pkRm, {skEm,pkEm}) reproduces enc/shared_secret" {
    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    const got = try dhkem.X25519Kem.encapDeterministic(a1.pkRm, eph);
    try testing.expectEqualSlices(u8, &a1.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got.shared_secret);
}

test "A.1.1: DHKEM(X25519).decap(enc, skRm) reproduces shared_secret" {
    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    const got = try dhkem.X25519Kem.decap(a1.enc, skR);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got);
}

test "A.1.1: DHKEM(X25519).deriveKeyPair reproduces skEm/pkEm from ikmE and skRm/pkRm from ikmR" {
    const kpE = dhkem.X25519Kem.deriveKeyPair(&a1.ikmE);
    try testing.expectEqualSlices(u8, &a1.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkEm, &kpE.public_key);
    const kpR = dhkem.X25519Kem.deriveKeyPair(&a1.ikmR);
    try testing.expectEqualSlices(u8, &a1.skRm, &kpR.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkRm, &kpR.public_key);
}

test "A.1.1: schedule.keySchedule(.base, shared_secret, info) matches key/base_nonce/exporter_secret" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a1.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a1.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a1.exporter_secret, &ctx.exporter_secret);
    try testing.expectEqual(@as(u64, 0), ctx.seq);
}

test "A.1.1.1: Context.seal/.open reproduce all 6 published (pt,aad)->ct tuples (seq 0/1/2 sequential; 4/255 via direct seq set)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    var sender = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    var receiver = sender;

    for (a1.encryptions) |enc_case| {
        // seq 0/1/2 arrive sequentially via seal's own increment; the
        // vector then skips to 4 and 255 (proof the nonce derives from
        // `seq` directly, not a running counter) — `seq` is a plain pub
        // field, so skipping ahead is a direct assignment (the
        // noise.CipherState.setNonce precedent).
        sender.seq = enc_case.seq;
        var ct: [45]u8 = undefined;
        std.debug.assert(enc_case.ct.len == ct.len);
        try sender.seal(enc_case.aad, enc_case.pt, &ct);
        try testing.expectEqualSlices(u8, enc_case.ct, &ct);
        try testing.expectEqual(enc_case.seq + 1, sender.seq); // advanced exactly once

        receiver.seq = enc_case.seq;
        var pt: [29]u8 = undefined;
        try receiver.open(enc_case.aad, enc_case.ct, &pt);
        try testing.expectEqualSlices(u8, enc_case.pt, &pt);
        try testing.expectEqual(enc_case.seq + 1, receiver.seq);
    }
}

test "A.1.1.2: Context.exportSecret reproduces all 3 exported values (thin wrapper over the already-verified labeledExpand)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    for (a1.exports) |exp| {
        var got: [32]u8 = undefined;
        std.debug.assert(exp.l == 32);
        try ctx.exportSecret(&suite_id, exp.exporter_context, &got);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got);
    }
}

test "A.1: sealBaseDeterministic/openBase reproduce enc + the first ciphertext end-to-end in one call" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    const first = a1.encryptions[0];

    var ct: [45]u8 = undefined;
    const sealed = try schedule.sealBaseDeterministic(dhkem.X25519Kem, Aes128Gcm, 32, a1.pkRm, eph, &a1.info, first.aad, first.pt, &ct);
    try testing.expectEqualSlices(u8, &a1.enc, &sealed.enc);
    try testing.expectEqualSlices(u8, first.ct, &ct);

    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    var pt: [29]u8 = undefined;
    try schedule.openBase(dhkem.X25519Kem, Aes128Gcm, 32, sealed.enc, skR, &a1.info, first.aad, &ct, &pt);
    try testing.expectEqualSlices(u8, first.pt, &pt);
}

test "A.2: X25519 + ChaCha20Poly1305 — Encap/Decap + KeySchedule + seq-0 Seal, byte-exact" {
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a2.skEm, .public_key = a2.pkEm };
    const got = try dhkem.X25519Kem.encapDeterministic(a2.pkRm, eph);
    try testing.expectEqualSlices(u8, &a2.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a2.shared_secret, &got.shared_secret);
    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a2.skRm, .public_key = a2.pkRm };
    try testing.expectEqualSlices(u8, &a2.shared_secret, &(try dhkem.X25519Kem.decap(a2.enc, skR)));

    // A.2 uses the same info/pt/aad strings as A.1 (RFC 9180's Appendix A
    // fixes them across all vector sections: info "Ode on a Grecian Urn",
    // pt "Beauty is truth, truth beauty", aad "Count-0").
    const suite_id = suite.suiteId(a2.kem_id, a2.kdf_id, a2.aead_id);
    var ctx = try schedule.keySchedule(ChaCha20Poly1305, 32, .base, &suite_id, &a2.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a2.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a2.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a2.exporter_secret, &ctx.exporter_secret);

    var ct: [45]u8 = undefined;
    try ctx.seal(a1.encryptions[0].aad, a1.encryptions[0].pt, &ct);
    try testing.expectEqualSlices(u8, &a2.seq0_ct, &ct);
}

test "A.3: P-256 + AES-128-GCM — Encap/Decap + KeySchedule + seq-0 Seal, byte-exact" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    const eph = dhkem.P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    const got = try dhkem.P256Kem.encapDeterministic(a3.pkRm, eph);
    try testing.expectEqualSlices(u8, &a3.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &got.shared_secret);
    const skR = dhkem.P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    try testing.expectEqualSlices(u8, &a3.shared_secret, &(try dhkem.P256Kem.decap(a3.enc, skR)));

    // Same fixed info/pt/aad as A.1 (see the A.2 test's note).
    const suite_id = suite.suiteId(a3.kem_id, a3.kdf_id, a3.aead_id);
    var ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a3.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a3.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a3.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a3.exporter_secret, &ctx.exporter_secret);

    var ct: [45]u8 = undefined;
    try ctx.seal(a1.encryptions[0].aad, a1.encryptions[0].pt, &ct);
    try testing.expectEqualSlices(u8, &a3.seq0_ct, &ct);
}
