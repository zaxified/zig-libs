// SPDX-License-Identifier: MIT

//! quic-crypto.protection — RFC 9001 §5.3 packet protection: AEAD seal/open
//! with the QUIC per-packet nonce (`iv XOR left-pad(packet_number, 12)`) and
//! the unprotected packet header as additional data. Engine-agnostic: the
//! caller supplies the derived key/iv (`keyschedule.derivePacketKeys`), the
//! reconstructed 62-bit packet number, the packet header bytes, and the
//! payload — no packet-number reconstruction, no header parsing here.
//!
//! **Implemented and KAT-validated** against RFC 9001 Appendix A.2/A.3/A.5:
//! the `sanity` tests drive the vectors through `std.crypto` AEADs directly
//! (independent oracle), and the API tests drive the same vectors through
//! `nonce`/`seal`/`open` byte-exact. `open` returns a TYPED
//! `error.DecryptionFailed` on tag mismatch — NEVER a panic
//! (attacker-controlled ciphertext must not reach a panic path).
//!
//! **Mirrors `dtls/src/aead.zig`'s `Protection(comptime Aead)`** (seal/open
//! with `nonce = static_iv XOR left-pad(seq)`) — the SAME recipe, since
//! RFC 9001 §5.3's nonce construction is byte-identical to RFC 9147 §4.2.2's.
//! The QUIC variant differs only in vocabulary (a 62-bit "packet number"
//! left-padded into a 12-byte field, vs DTLS's 64-bit sequence number) and
//! in that QUIC's `additional_data` is the whole unprotected header. No dtls
//! code is imported or copied (deps stays `.{}`, std-only) — re-expressed
//! QUIC-shaped; see SPEC.md/NOTICE.

const std = @import("std");

pub const ProtectionError = error{
    /// AEAD tag verification failed on `open` — return this, never panic.
    DecryptionFailed,
    /// `ciphertext` on `open` is shorter than the AEAD tag.
    PacketTooShort,
    /// The provided output buffer cannot hold the result.
    BufferTooShort,
};

/// Binds one AEAD type to RFC 9001 §5.3's packet-protection operations.
/// Instantiate with `std.crypto.aead.aes_gcm.Aes128Gcm` (Initial + the
/// TLS_AES_128_GCM_SHA256 suite), `aes_gcm.Aes256Gcm`, or
/// `chacha_poly.ChaCha20Poly1305`. All QUIC v1 AEADs have a 12-byte nonce
/// and 16-byte tag.
pub fn Protection(comptime Aead: type) type {
    return struct {
        pub const key_length = Aead.key_length;
        pub const nonce_length = Aead.nonce_length;
        pub const tag_length = Aead.tag_length;

        comptime {
            // RFC 9001 §5.1/§5.3: the QUIC packet-protection nonce is 12
            // bytes (the "quic iv" output length). TLS_AES_128_CCM_8_SHA256
            // is excluded from QUIC (§5.3), so every wired AEAD is nonce-12.
            if (nonce_length != 12) @compileError(
                "quic-crypto: RFC 9001 §5.3 packet protection requires a 12-byte AEAD nonce; " ++
                    @typeName(Aead) ++ " has a different nonce_length",
            );
        }

        /// RFC 9001 §5.3: "The 62 bits of the reconstructed QUIC packet
        /// number in network byte order are left-padded with zeros to the
        /// size of the IV. The exclusive OR of the padded packet number and
        /// the IV forms the AEAD nonce." I.e. write `packet_number` big-endian
        /// into the LOW 8 bytes of a 12-byte zero field, XOR into `iv`. The
        /// full 64-bit `packet_number` is accepted (the top 2 bits are always
        /// zero for a valid QUIC PN, so this is equivalent to the 62-bit form).
        ///
        /// Mirrors `dtls.aead.Protection.nonce` (RFC 9147 §4.2.2) — identical
        /// construction; QUIC calls the input a packet number, DTLS a
        /// sequence number.
        pub fn nonce(iv: [nonce_length]u8, packet_number: u64) [nonce_length]u8 {
            var out = iv;
            var pn_be: [8]u8 = undefined;
            std.mem.writeInt(u64, &pn_be, packet_number, .big);
            // XOR the 8 packet-number bytes into the rightmost 8 nonce bytes
            // (left-pad with zeros = leave the leading nonce bytes untouched).
            const off = nonce_length - 8;
            inline for (0..8) |i| out[off + i] ^= pn_be[i];
            return out;
        }

        /// RFC 9001 §5.3: AEAD-seal `payload` under `key`/`nonce(iv,
        /// packet_number)`, authenticating `header` (the unprotected packet
        /// header — first header byte through the unprotected packet number,
        /// per §5.3). Writes `payload.len + tag_length` bytes into `out`
        /// (ciphertext followed by the tag); returns that count. The AEAD
        /// output replaces the payload on the wire; header protection (§5.4)
        /// is then applied on top by `headerprot.zig`.
        pub fn seal(
            key: [key_length]u8,
            iv: [nonce_length]u8,
            packet_number: u64,
            header: []const u8,
            payload: []const u8,
            out: []u8,
        ) ProtectionError!usize {
            const total = payload.len + tag_length;
            if (out.len < total) return error.BufferTooShort;
            const npub = nonce(iv, packet_number);
            var tag: [tag_length]u8 = undefined;
            Aead.encrypt(out[0..payload.len], &tag, payload, header, npub, key);
            @memcpy(out[payload.len..][0..tag_length], &tag);
            return total;
        }

        /// The `seal` mirror: AEAD-open `ciphertext` (ciphertext body ||
        /// trailing tag) under `key`/`nonce(iv, packet_number)`,
        /// authenticating `header`. Writes `ciphertext.len - tag_length`
        /// bytes into `out`; returns that count. Any tag mismatch is
        /// `error.DecryptionFailed` — NEVER a panic, and via std AEAD's
        /// constant-time tag compare (no timing leak between failure modes).
        pub fn open(
            key: [key_length]u8,
            iv: [nonce_length]u8,
            packet_number: u64,
            header: []const u8,
            ciphertext: []const u8,
            out: []u8,
        ) ProtectionError!usize {
            if (ciphertext.len < tag_length) return error.PacketTooShort;
            const body_len = ciphertext.len - tag_length;
            if (out.len < body_len) return error.BufferTooShort;
            const npub = nonce(iv, packet_number);
            var tag: [tag_length]u8 = undefined;
            @memcpy(&tag, ciphertext[body_len..][0..tag_length]);
            Aead.decrypt(out[0..body_len], ciphertext[0..body_len], tag, header, npub, key) catch
                return error.DecryptionFailed;
            return body_len;
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────
//
// RFC 9001 Appendix A.2 (client Initial, AES-128-GCM), A.3 (server Initial,
// AES-128-GCM) and A.5 (ChaCha20-Poly1305 short header) packet-protection
// vectors. Every hex constant was extracted verbatim from
// https://www.rfc-editor.org/rfc/rfc9001.txt and cross-checked against the
// `cryptography` package (OpenSSL AESGCM / ChaCha20Poly1305) before commit:
// each sanity test below reproduces the RFC's protected ciphertext exactly.

const testing = std.testing;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// App. A.2 client Initial: key/iv, unprotected header (AAD), CRYPTO frame
// (padded to 1162 bytes = the unprotected payload), packet number 2, and the
// first 32 bytes of the protected packet (22-byte header + start of body).
const rfc_client_key = hexTo(16, "1f369613dd76d5467730efcbe3b1a22d");
const rfc_client_iv = hexTo(12, "fa044b2f42a3fd3b46fb255c");
const rfc_client_header = hexTo(22, "c300000001088394c8f03e5157080000449e00000002");
const rfc_client_pn: u64 = 2;
// The AEAD nonce that pn 2 XOR iv produces (App. A.2 uses it implicitly).
const rfc_client_nonce = hexTo(12, "fa044b2f42a3fd3b46fb255e");
// First 16 bytes of the protected PAYLOAD (== the header-protection sample).
const rfc_client_ct_head = hexTo(16, "d1b1c98dd7689fb8ec11d242b123dc9b");

// App. A.3 server Initial.
const rfc_server_key = hexTo(16, "cf3a5331653c364c88f0f379b6067e37");
const rfc_server_iv = hexTo(12, "0ac1493ca1905853b0bba03e");
const rfc_server_header = hexTo(20, "c1000000010008f067a5502a4262b50040750001");
const rfc_server_pn: u64 = 1;
const rfc_server_payload = hexTo(99, "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304");
// The full protected server packet body (after the 20-byte header) = 115 bytes.
const rfc_server_ct = hexTo(115, "5a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee");

// App. A.5 ChaCha20-Poly1305 short header.
const rfc_a5_key = hexTo(32, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
const rfc_a5_iv = hexTo(12, "e0459b3474bdd0e44a41c144");
const rfc_a5_pn: u64 = 654360564;
const rfc_a5_nonce = hexTo(12, "e0459b3474bdd0e46d417eb0");
const rfc_a5_header = hexTo(4, "4200bff4");
const rfc_a5_plain = hexTo(1, "01");
const rfc_a5_ct = hexTo(17, "655e5cd55c41f69080575d7999c25a5bfb");

fn nonceXor(iv: [12]u8, pn: u64) [12]u8 {
    var n = iv;
    var pnb: [8]u8 = undefined;
    std.mem.writeInt(u64, &pnb, pn, .big);
    inline for (0..8) |i| n[4 + i] ^= pnb[i];
    return n;
}

test "sanity: App. A.2/A.3 nonce = iv XOR left-pad(pn) matches RFC" {
    // Reproduce the nonce construction Protection.nonce implements, via plain
    // byte ops, and check against the RFC's stated nonces.
    try testing.expectEqualSlices(u8, &rfc_client_nonce, &nonceXor(rfc_client_iv, rfc_client_pn));
    try testing.expectEqualSlices(u8, &rfc_a5_nonce, &nonceXor(rfc_a5_iv, rfc_a5_pn));
}

test "sanity: App. A.3 server Initial AES-128-GCM seal matches RFC ciphertext" {
    var out: [rfc_server_payload.len + 16]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(out[0..rfc_server_payload.len], &tag, &rfc_server_payload, &rfc_server_header, rfc_server_iv_xor_pn(), rfc_server_key);
    @memcpy(out[rfc_server_payload.len..][0..16], &tag);
    try testing.expectEqualSlices(u8, &rfc_server_ct, &out);
    // And it round-trips (open recovers the plaintext).
    var back: [rfc_server_payload.len]u8 = undefined;
    Aes128Gcm.decrypt(&back, out[0..rfc_server_payload.len], tag, &rfc_server_header, rfc_server_iv_xor_pn(), rfc_server_key) catch unreachable;
    try testing.expectEqualSlices(u8, &rfc_server_payload, &back);
}

test "sanity: App. A.2 client Initial AES-128-GCM protected-payload head matches RFC" {
    // The full client payload is 1162 bytes (CRYPTO frame + PADDING). We
    // only need the first 16 ciphertext bytes to match the RFC's header-
    // protection sample, so build the padded plaintext and check the head.
    const crypto_frame = hexTo(245, "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff");
    var plain: [1162]u8 = [_]u8{0} ** 1162;
    @memcpy(plain[0..crypto_frame.len], &crypto_frame);
    var out: [1162 + 16]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(out[0..1162], &tag, &plain, &rfc_client_header, rfc_client_nonce, rfc_client_key);
    try testing.expectEqualSlices(u8, &rfc_client_ct_head, out[0..16]);
}

test "sanity: App. A.5 ChaCha20-Poly1305 seal matches RFC ciphertext" {
    var out: [rfc_a5_plain.len + 16]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(out[0..rfc_a5_plain.len], &tag, &rfc_a5_plain, &rfc_a5_header, rfc_a5_nonce, rfc_a5_key);
    @memcpy(out[rfc_a5_plain.len..][0..16], &tag);
    try testing.expectEqualSlices(u8, &rfc_a5_ct, &out);
}

fn rfc_server_iv_xor_pn() [12]u8 {
    var n = rfc_server_iv;
    var pnb: [8]u8 = undefined;
    std.mem.writeInt(u64, &pnb, rfc_server_pn, .big);
    inline for (0..8) |i| n[4 + i] ^= pnb[i];
    return n;
}

test "Protection.nonce: App. A.2 client + A.5 chacha" {
    try testing.expectEqualSlices(u8, &rfc_client_nonce, &Protection(Aes128Gcm).nonce(rfc_client_iv, rfc_client_pn));
    try testing.expectEqualSlices(u8, &rfc_a5_nonce, &Protection(ChaCha20Poly1305).nonce(rfc_a5_iv, rfc_a5_pn));
}

test "Protection.seal: App. A.3 server Initial byte-exact" {
    var out: [rfc_server_ct.len]u8 = undefined;
    const n = try Protection(Aes128Gcm).seal(rfc_server_key, rfc_server_iv, rfc_server_pn, &rfc_server_header, &rfc_server_payload, &out);
    try testing.expectEqualSlices(u8, &rfc_server_ct, out[0..n]);
    // A.5 ChaCha20-Poly1305 short-header seal, byte-exact too.
    var out5: [rfc_a5_ct.len]u8 = undefined;
    const n5 = try Protection(ChaCha20Poly1305).seal(rfc_a5_key, rfc_a5_iv, rfc_a5_pn, &rfc_a5_header, &rfc_a5_plain, &out5);
    try testing.expectEqualSlices(u8, &rfc_a5_ct, out5[0..n5]);
}

test "Protection.open: App. A.3 round-trip + tamper->DecryptionFailed" {
    const P = Protection(Aes128Gcm);
    var back: [rfc_server_payload.len]u8 = undefined;
    const n = try P.open(rfc_server_key, rfc_server_iv, rfc_server_pn, &rfc_server_header, &rfc_server_ct, &back);
    try testing.expectEqualSlices(u8, &rfc_server_payload, back[0..n]);

    // Tampering yields error.DecryptionFailed — never a panic.
    var t1 = rfc_server_ct;
    t1[0] ^= 1; // flip a ciphertext byte
    try testing.expectError(error.DecryptionFailed, P.open(rfc_server_key, rfc_server_iv, rfc_server_pn, &rfc_server_header, &t1, &back));

    var t2 = rfc_server_ct;
    t2[t2.len - 1] ^= 1; // flip a tag byte
    try testing.expectError(error.DecryptionFailed, P.open(rfc_server_key, rfc_server_iv, rfc_server_pn, &rfc_server_header, &t2, &back));

    var bad_header = rfc_server_header;
    bad_header[0] ^= 1;
    try testing.expectError(error.DecryptionFailed, P.open(rfc_server_key, rfc_server_iv, rfc_server_pn, &bad_header, &rfc_server_ct, &back));

    // Wrong packet number => wrong nonce => open fails.
    try testing.expectError(error.DecryptionFailed, P.open(rfc_server_key, rfc_server_iv, rfc_server_pn + 1, &rfc_server_header, &rfc_server_ct, &back));

    // Ciphertext shorter than the tag is a typed error, not a slice panic.
    const tiny = [_]u8{ 1, 2, 3 };
    try testing.expectError(error.PacketTooShort, P.open(rfc_server_key, rfc_server_iv, rfc_server_pn, &rfc_server_header, &tiny, &back));
}
