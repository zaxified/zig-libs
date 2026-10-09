// SPDX-License-Identifier: MIT

//! quic-crypto — RFC 9369 (QUIC v2) Appendix A, test-only. Drives the
//! published v2 sample packets through the PUBLIC API of the other files
//! (`deriveInitialSecretsFor`, `derivePacketKeysFor`, `Protection`,
//! `headerprot`) byte-exact: keys (A.1), the protected client Initial (A.2),
//! the protected server Initial (A.3) and the ChaCha20-Poly1305 short header
//! packet (A.5). The v2 Retry (A.4) lives with the Retry code in `retry.zig`.
//! All hex is copied from https://www.rfc-editor.org/rfc/rfc9369.txt (the
//! plain-text copy carries no page breaks, so sections are cited, not pages).
//! The v1 counterparts (RFC 9001 A.1-A.3, A.5) stay in the files that own
//! them and are untouched.

const std = @import("std");
const initial = @import("initial.zig");
const keyschedule = @import("keyschedule.zig");
const protection = @import("protection.zig");
const headerprot = @import("headerprot.zig");
const chachapoly = @import("chachapoly");

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const P128 = protection.Protection(Aes128Gcm);
const PChaCha = protection.Protection(chachapoly.ChaCha20Poly1305);

fn hexToC(comptime n: usize, comptime s: []const u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 9369 App. A: "an 8-byte client-chosen Destination Connection ID of
// 0x8394c8f03e515708".
const dcid = hexToC(8, "8394c8f03e515708");

// RFC 9369 A.1 "Keys": secrets, key, iv, hp for client and server (v2 labels).
const a1_client_secret = hexToC(32, "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b");
const a1_client_key = hexToC(16, "8b1a0bc121284290a29e0971b5cd045d");
const a1_client_iv = hexToC(12, "91f73e2351d8fa91660e909f");
const a1_client_hp = hexToC(16, "45b95e15235d6f45a6b19cbcb0294ba9");
const a1_server_secret = hexToC(32, "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1");
const a1_server_key = hexToC(16, "82db637861d55e1d011f19ea71d5d2a7");
const a1_server_iv = hexToC(12, "dd13c276499c0249d3310652");
const a1_server_hp = hexToC(16, "edf6d05c83121201b436e16877593c3a");

// RFC 9369 A.2 "Client Initial": the CRYPTO frame (padded with PADDING to a
// 1162-byte payload), the unprotected header, the sample/mask and the final
// protected packet.
const rfc9369_a2_crypto_frame = hexToC(
    245,
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" ++
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" ++
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" ++
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" ++
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" ++
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100" ++
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" ++
        "75300901100f088394c8f03e51570806048000ffff",
);
const rfc9369_a2_protected = hexToC(
    1200,
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485" ++
        "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04" ++
        "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d" ++
        "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a" ++
        "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500" ++
        "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68" ++
        "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33" ++
        "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3" ++
        "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd" ++
        "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520" ++
        "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045" ++
        "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f" ++
        "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12" ++
        "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5" ++
        "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4" ++
        "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b" ++
        "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7" ++
        "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9" ++
        "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91" ++
        "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd" ++
        "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db" ++
        "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18" ++
        "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15" ++
        "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc" ++
        "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61" ++
        "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710" ++
        "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b" ++
        "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e" ++
        "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce" ++
        "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1" ++
        "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1" ++
        "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd" ++
        "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3" ++
        "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89" ++
        "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53" ++
        "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19" ++
        "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b" ++
        "a18b2faa745b6fe189cf772a9f84cbfc",
);
const rfc9369_a3_payload = hexToC(
    99,
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304",
);
const rfc9369_a3_protected = hexToC(
    135,
    "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698" ++
        "baeea26b91eb761d9b89237bbf87263017915358230035f7fd3945d88965cf17" ++
        "f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2" ++
        "c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca8" ++
        "4bed8521e2e140",
);

const a2_header = hexToC(22, "d36b3343cf088394c8f03e5157080000449e00000002");
const a2_sample = hexToC(16, "ffe67b6abcdb4298b485dd04de806071");
const a2_mask = hexToC(5, "94a0c95e80");
const a2_protected_header = hexToC(22, "d76b3343cf088394c8f03e5157080000449ea0c95e82");
const a2_payload_len = 1162;

// RFC 9369 A.3 "Server Initial": payload (ACK + CRYPTO, no PADDING), header
// with a 2-byte packet number 1, sample/mask/protected header, final packet.
// (`rfc9369_a3_payload` and `rfc9369_a3_protected` above are the payload and
// the final protected packet.)
const a3_header = hexToC(20, "d16b3343cf0008f067a5502a4262b50040750001");
const a3_sample = hexToC(16, "6f05d8a4398c47089698baeea26b91eb");
const a3_mask = hexToC(5, "4dd92e91ea");
const a3_protected_header = hexToC(20, "dc6b3343cf0008f067a5502a4262b5004075d92f");

test "RFC 9369 A.1: v2 initial secrets and client/server key/iv/hp (same DCID as RFC 9001 A.1)" {
    var s: initial.InitialSecrets = undefined;
    initial.deriveInitialSecretsFor(.v2, &s, &dcid);
    try testing.expectEqualSlices(u8, &a1_client_secret, &s.client_initial_secret);
    try testing.expectEqualSlices(u8, &a1_server_secret, &s.server_initial_secret);

    var c: keyschedule.PacketKeys(16) = undefined;
    keyschedule.derivePacketKeysFor(.v2, HkdfSha256, 16, &c, &s.client_initial_secret);
    try testing.expectEqualSlices(u8, &a1_client_key, &c.key);
    try testing.expectEqualSlices(u8, &a1_client_iv, &c.iv);
    try testing.expectEqualSlices(u8, &a1_client_hp, &c.hp);
    var sv: keyschedule.PacketKeys(16) = undefined;
    keyschedule.derivePacketKeysFor(.v2, HkdfSha256, 16, &sv, &s.server_initial_secret);
    try testing.expectEqualSlices(u8, &a1_server_key, &sv.key);
    try testing.expectEqualSlices(u8, &a1_server_iv, &sv.iv);
    try testing.expectEqualSlices(u8, &a1_server_hp, &sv.hp);

    // The v1 derivation of the SAME secret must NOT produce the v2 keys.
    var v1: keyschedule.PacketKeys(16) = undefined;
    keyschedule.derivePacketKeys(HkdfSha256, 16, &v1, &s.client_initial_secret);
    try testing.expect(!std.mem.eql(u8, &v1.key, &a1_client_key));
}

test "RFC 9369 A.2: client Initial — protect (seal + header protection) is byte-exact" {
    var payload = [_]u8{0} ** a2_payload_len;
    @memcpy(payload[0..rfc9369_a2_crypto_frame.len], &rfc9369_a2_crypto_frame);

    var pkt: [a2_header.len + a2_payload_len + 16]u8 = undefined;
    @memcpy(pkt[0..a2_header.len], &a2_header);
    const n = try P128.seal(&a1_client_key, a1_client_iv, 2, &a2_header, &payload, pkt[a2_header.len..]);
    try testing.expectEqual(a2_payload_len + 16, n);
    try testing.expectEqual(rfc9369_a2_protected.len, pkt.len);

    // Header protection: sample = first 16 protected-payload bytes (PN is 4 bytes, pn_offset 18).
    const sample: [16]u8 = pkt[18 + 4 ..][0..16].*;
    try testing.expectEqualSlices(u8, &a2_sample, &sample);
    const mask = headerprot.computeMaskAes(&a1_client_hp, sample);
    try testing.expectEqualSlices(u8, &a2_mask, &mask);
    try headerprot.apply(&pkt, .long, 18, 4, mask);
    try testing.expectEqualSlices(u8, &a2_protected_header, pkt[0..a2_header.len]);
    try testing.expectEqualSlices(u8, &rfc9369_a2_protected, &pkt);
}

test "RFC 9369 A.2: client Initial — unprotect (remove header protection + open) recovers the frames" {
    var pkt = rfc9369_a2_protected;
    const sample: [16]u8 = pkt[18 + 4 ..][0..16].*;
    const mask = headerprot.computeMaskAes(&a1_client_hp, sample);
    const r = try headerprot.remove(&pkt, .long, 18, mask);
    try testing.expectEqual(@as(usize, 4), r.pn_len);
    try testing.expectEqualSlices(u8, &a2_header, pkt[0..a2_header.len]);
    var out: [a2_payload_len]u8 = undefined;
    const m = try P128.open(&a1_client_key, a1_client_iv, 2, pkt[0..a2_header.len], pkt[a2_header.len..], &out);
    try testing.expectEqual(a2_payload_len, m);
    try testing.expectEqualSlices(u8, &rfc9369_a2_crypto_frame, out[0..rfc9369_a2_crypto_frame.len]);
    for (out[rfc9369_a2_crypto_frame.len..m]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "RFC 9369 A.2: v1 keys cannot open the v2 client Initial; a flipped byte fails" {
    var pkt = rfc9369_a2_protected;
    const sample: [16]u8 = pkt[18 + 4 ..][0..16].*;
    const mask = headerprot.computeMaskAes(&a1_client_hp, sample);
    _ = try headerprot.remove(&pkt, .long, 18, mask);
    var out: [a2_payload_len]u8 = undefined;
    // v1 derivation of the v2 client secret (wrong labels) -> wrong key/iv.
    var wrong: keyschedule.PacketKeys(16) = undefined;
    keyschedule.derivePacketKeys(HkdfSha256, 16, &wrong, &a1_client_secret);
    try testing.expectError(error.DecryptionFailed, P128.open(&wrong.key, wrong.iv, 2, pkt[0..a2_header.len], pkt[a2_header.len..], &out));
    // v1 SALT (wrong initial salt) -> wrong secrets.
    var v1s: initial.InitialSecrets = undefined;
    initial.deriveInitialSecretsFor(.v1, &v1s, &dcid);
    var k1: keyschedule.PacketKeys(16) = undefined;
    keyschedule.derivePacketKeysFor(.v2, HkdfSha256, 16, &k1, &v1s.client_initial_secret);
    try testing.expectError(error.DecryptionFailed, P128.open(&k1.key, k1.iv, 2, pkt[0..a2_header.len], pkt[a2_header.len..], &out));
    // Flipped ciphertext byte.
    pkt[100] ^= 0x01;
    try testing.expectError(error.DecryptionFailed, P128.open(&a1_client_key, a1_client_iv, 2, pkt[0..a2_header.len], pkt[a2_header.len..], &out));
}

test "RFC 9369 A.3: server Initial — protect is byte-exact and unprotect recovers the payload" {
    var pkt: [a3_header.len + rfc9369_a3_payload.len + 16]u8 = undefined;
    @memcpy(pkt[0..a3_header.len], &a3_header);
    const n = try P128.seal(&a1_server_key, a1_server_iv, 1, &a3_header, &rfc9369_a3_payload, pkt[a3_header.len..]);
    try testing.expectEqual(rfc9369_a3_payload.len + 16, n);
    try testing.expectEqual(rfc9369_a3_protected.len, pkt.len);

    // "the header protection sample is taken, starting from the third protected byte":
    // pn_offset 18, +4 = 22 = header length 20 + 2.
    const sample: [16]u8 = pkt[18 + 4 ..][0..16].*;
    try testing.expectEqualSlices(u8, &a3_sample, &sample);
    const mask = headerprot.computeMaskAes(&a1_server_hp, sample);
    try testing.expectEqualSlices(u8, &a3_mask, &mask);
    try headerprot.apply(&pkt, .long, 18, 2, mask);
    try testing.expectEqualSlices(u8, &a3_protected_header, pkt[0..a3_header.len]);
    try testing.expectEqualSlices(u8, &rfc9369_a3_protected, &pkt);

    // Receive direction.
    var rx = rfc9369_a3_protected;
    const r = try headerprot.remove(&rx, .long, 18, mask);
    try testing.expectEqual(@as(usize, 2), r.pn_len);
    try testing.expectEqualSlices(u8, &a3_header, rx[0..a3_header.len]);
    var out: [rfc9369_a3_payload.len]u8 = undefined;
    const m = try P128.open(&a1_server_key, a1_server_iv, 1, rx[0..a3_header.len], rx[a3_header.len..], &out);
    try testing.expectEqualSlices(u8, &rfc9369_a3_payload, out[0..m]);
}

// RFC 9369 A.5 "ChaCha20-Poly1305 Short Header Packet".
const a5_secret = hexToC(32, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
const a5_key = hexToC(32, "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2");
const a5_iv = hexToC(12, "a6b5bc6ab7dafce30ffff5dd");
const a5_hp = hexToC(32, "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2");
const a5_ku = hexToC(32, "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88");

test "RFC 9369 A.5: v2 ChaCha20-Poly1305 key/iv/hp, key-update secret and the 21-byte short packet" {
    var k: keyschedule.PacketKeys(32) = undefined;
    keyschedule.derivePacketKeysFor(.v2, HkdfSha256, 32, &k, &a5_secret);
    try testing.expectEqualSlices(u8, &a5_key, &k.key);
    try testing.expectEqualSlices(u8, &a5_iv, &k.iv);
    try testing.expectEqualSlices(u8, &a5_hp, &k.hp);
    var ku: keyschedule.KeyUpdate(HkdfSha256, 32) = undefined;
    keyschedule.advanceKeysFor(.v2, HkdfSha256, 32, &ku, &a5_secret);
    try testing.expectEqualSlices(u8, &a5_ku, &ku.next_secret);
    // Not the v1 "quic ku" result.
    var ku1: keyschedule.KeyUpdate(HkdfSha256, 32) = undefined;
    keyschedule.advanceKeys(HkdfSha256, 32, &ku1, &a5_secret);
    try testing.expect(!std.mem.eql(u8, &ku1.next_secret, &a5_ku));

    // pn = 654360564, nonce = a6b5bc6ab7dafce328ff4a29.
    const pn: u64 = 654360564;
    try testing.expectEqualSlices(u8, &hexToC(12, "a6b5bc6ab7dafce328ff4a29"), &PChaCha.nonce(a5_iv, pn));
    const header = hexToC(4, "4200bff4");
    var pkt: [4 + 1 + 16]u8 = undefined;
    @memcpy(pkt[0..4], &header);
    const n = try PChaCha.seal(&a5_key, a5_iv, pn, &header, &[_]u8{0x01}, pkt[4..]);
    try testing.expectEqual(@as(usize, 17), n);
    try testing.expectEqualSlices(u8, &hexToC(17, "0ae7b6b932bc27d786f4bc2bb20f2162ba"), pkt[4..]);
    // "One byte is skipped to produce the sample": sample starts at pn_offset + 4 = 5.
    const sample: [16]u8 = pkt[5..][0..16].*;
    try testing.expectEqualSlices(u8, &hexToC(16, "e7b6b932bc27d786f4bc2bb20f2162ba"), &sample);
    const mask = headerprot.computeMaskChaCha20(&a5_hp, sample);
    try testing.expectEqualSlices(u8, &hexToC(5, "97580e32bf"), &mask);
    try headerprot.apply(&pkt, .short, 1, 3, mask);
    try testing.expectEqualSlices(u8, &hexToC(21, "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba"), &pkt);
}
