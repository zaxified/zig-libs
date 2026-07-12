// SPDX-License-Identifier: MIT

//! tlsresume.earlydata — TLS 1.3 0-RTT early-data key derivation (RFC 8446
//! §4.2.10 + §7.1's early branch + §7.3). **REAL — KAT-validated byte-exact
//! against RFC 8448 §4's "Resumed 0-RTT Handshake" trace**, including
//! opening the trace's actual encrypted early-data record (see tests).
//!
//! Once a client resumes with a PSK (`psk.zig`'s chain), it may send
//! application data *before* the handshake completes, protected under keys
//! derived from the same `early_secret` the binder chain starts from:
//!
//! ```
//! PSK ── HKDF-Extract(0, PSK) ──────────────────────────> early_secret
//!            (psk.earlySecret — REUSED here, not reimplemented)
//! early_secret ─┬─ Derive-Secret(., "c e traffic", ClientHello)
//!               │      -> client_early_traffic_secret  (clientEarlyTrafficSecret)
//!               ├─ Derive-Secret(., "e exp master", ClientHello)
//!               │      -> early_exporter_master_secret (earlyExporterMasterSecret)
//!               └─ (Derive-Secret(., "res binder", "") -> binder_key lives
//!                   in psk.zig — the OTHER branch off the same secret)
//! client_early_traffic_secret ─┬─ HKDF-Expand-Label(., "key", "", key_len)
//!                              └─ HKDF-Expand-Label(., "iv",  "", 12)
//!                                     -> early-data record key/iv (§7.3)
//!                                        (earlyTrafficKeyIv)
//! ```
//!
//! **Transcript-hash pitfall (the one wrong input a caller can plausibly
//! pass):** the context for BOTH "c e traffic" and "e exp master" is the
//! hash of the *complete* ClientHello — binders included — whereas the PSK
//! binder itself (`psk.computeBinder`) hashes the *truncated* ClientHello
//! (binders excluded). RFC 8448 §4 shows both digests and they differ
//! (`08ad0f…` complete vs `63224b…` truncated); the tests below pin the
//! complete-hash one. As everywhere in this module, the caller passes the
//! already-computed digest — this file never touches handshake bytes,
//! keeping it engine-agnostic (see SPEC.md).
//!
//! **What this file deliberately does NOT own** (already real elsewhere in
//! this module — cross-references, not reimplementations):
//!
//! - **Advertising 0-RTT support / `max_early_data_size`** (RFC 8446
//!   §4.2.10): `ticket.zig` — `NewSessionTicket` carries the `early_data`
//!   extension (type 42, `ticket.early_data_extension_type`); read it via
//!   `NewSessionTicket.maxEarlyDataSize`, build it via
//!   `ticket.earlyDataExtension`. A server MUST NOT accept more early-data
//!   plaintext than the limit it advertised there.
//! - **Anti-replay** (RFC 8446 §8, §2.3): 0-RTT data has NO server-side
//!   freshness guarantee — an attacker can replay the captured ClientHello
//!   + early data verbatim, and the early-data keys derived here will
//!   decrypt the replay just fine. A server that accepts early data
//!   REQUIRES a replay defense; this module's is `replay.StrikeRegister`
//!   (single-use tickets, §8.1) plus `replay.withinFreshnessWindow`
//!   (§4.2.11.1/§8.2 age bounding). Deriving keys with this file WITHOUT
//!   wiring those is a replay vulnerability, not a working configuration.
//!
//! Like `psk.zig`, everything here is a thin, label-pinning wrapper over
//! `std.crypto.tls.hkdfExpandLabel` (std's hardcoded `"tls13 "` prefix is
//! exactly right for plain TLS 1.3 — see psk.zig's module doc); the value
//! added is the pinned labels ("c e traffic" / "e exp master" / "key" /
//! "iv"), the complete-vs-truncated-hash distinction, and the KAT proof.
//! SHA-256 and SHA-384 suites are supported via the `Hkdf` comptime
//! parameter; key_len 16 (AES-128-GCM) and 32 (AES-256-GCM,
//! ChaCha20-Poly1305) per RFC 8446 §B.4.

const std = @import("std");
const pskmod = @import("psk.zig");

/// RFC 8446 §7.1: `client_early_traffic_secret = Derive-Secret(early_secret,
/// "c e traffic", ClientHello)` — the secret protecting 0-RTT early-data
/// records (§7.3) and the early "finished"-style keys. `client_hello_
/// transcript_hash` is the hash of the COMPLETE ClientHello (binders
/// included) — NOT the truncated hash `psk.computeBinder` takes; see the
/// module doc's pitfall note.
pub fn clientEarlyTrafficSecret(
    comptime Hkdf: type,
    early_secret: [Hkdf.prk_length]u8,
    client_hello_transcript_hash: []const u8,
) [Hkdf.prk_length]u8 {
    // Derive-Secret(early_secret, "c e traffic", ClientHello) =
    // HKDF-Expand-Label(early_secret, "c e traffic", CH_hash, Hash.length).
    return std.crypto.tls.hkdfExpandLabel(Hkdf, early_secret, "c e traffic", client_hello_transcript_hash, Hkdf.prk_length);
}

/// RFC 8446 §7.1: `early_exporter_master_secret = Derive-Secret(early_secret,
/// "e exp master", ClientHello)` — the exporter secret available during the
/// 0-RTT phase (RFC 8446 §7.5 early exporters). Same complete-ClientHello
/// transcript-hash context as `clientEarlyTrafficSecret`.
pub fn earlyExporterMasterSecret(
    comptime Hkdf: type,
    early_secret: [Hkdf.prk_length]u8,
    client_hello_transcript_hash: []const u8,
) [Hkdf.prk_length]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, early_secret, "e exp master", client_hello_transcript_hash, Hkdf.prk_length);
}

/// The record-protection key + IV pair `earlyTrafficKeyIv` returns (RFC 8446
/// §7.3). The per-record nonce is `iv XOR left-padded(seq)` per §5.3 —
/// sequence numbering for early-data records starts at 0 and is separate
/// from the handshake/application spaces.
pub fn TrafficKeyIv(comptime key_len: usize) type {
    return struct {
        key: [key_len]u8,
        iv: [12]u8,
    };
}

/// RFC 8446 §7.3: the early-data record-protection keys —
/// `key = HKDF-Expand-Label(client_early_traffic_secret, "key", "", key_len)`
/// and `iv = HKDF-Expand-Label(client_early_traffic_secret, "iv", "", 12)`.
/// `key_len` is the negotiated AEAD's key length: 16 for TLS_AES_128_GCM_
/// SHA256, 32 for TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256
/// (RFC 8446 §B.4; all three use 12-byte IVs). The cipher for early data is
/// fixed by the PSK's original connection, NOT negotiated fresh (§4.2.10).
pub fn earlyTrafficKeyIv(
    comptime Hkdf: type,
    comptime key_len: usize,
    client_early_traffic_secret: [Hkdf.prk_length]u8,
) TrafficKeyIv(key_len) {
    comptime std.debug.assert(key_len == 16 or key_len == 32); // RFC 8446 §B.4 suites only
    return .{
        .key = std.crypto.tls.hkdfExpandLabel(Hkdf, client_early_traffic_secret, "key", "", key_len),
        .iv = std.crypto.tls.hkdfExpandLabel(Hkdf, client_early_traffic_secret, "iv", "", 12),
    };
}

/// Convenience: the full early-data derivation in one call — PSK ->
/// `early_secret` (via `psk.earlySecret`, reused not reimplemented) ->
/// `client_early_traffic_secret` -> record key/iv. Both endpoints run this
/// identically (the client to seal early-data records, the server — after
/// `select.selectPsk` has verified the binder AND `replay.StrikeRegister`
/// has admitted the ticket, see the module doc's anti-replay note — to open
/// them). `early_secret` is kept in the result because the server still
/// needs it to continue the §7.1 schedule ("derived" -> handshake secret).
pub fn EarlyDataContext(comptime Hkdf: type, comptime key_len: usize) type {
    return struct {
        early_secret: [Hkdf.prk_length]u8,
        client_early_traffic_secret: [Hkdf.prk_length]u8,
        key: [key_len]u8,
        iv: [12]u8,

        /// `psk` is the resumption PSK (`psk.derivePsk`'s output);
        /// `client_hello_transcript_hash` is the COMPLETE-ClientHello digest
        /// (see the module-doc pitfall note).
        pub fn derive(psk: []const u8, client_hello_transcript_hash: []const u8) @This() {
            const early_secret = pskmod.earlySecret(Hkdf, psk);
            const cets = clientEarlyTrafficSecret(Hkdf, early_secret, client_hello_transcript_hash);
            const key_iv = earlyTrafficKeyIv(Hkdf, key_len, cets);
            return .{
                .early_secret = early_secret,
                .client_early_traffic_secret = cets,
                .key = key_iv.key,
                .iv = key_iv.iv,
            };
        }
    };
}

// ── tests: RFC 8448 §4 ("Resumed 0-RTT Handshake") known-answer vectors ──
//
// RFC 8448 §4 is a full 0-RTT trace: it derives "tls13 c e traffic" and
// "tls13 e exp master" from the same early_secret psk.zig's KATs pin, then
// the early-data write key/iv, then shows the actual encrypted early-data
// record (payload "ABCDEF"). All constants below were extracted directly
// from https://www.rfc-editor.org/rfc/rfc8448 §4 (the same fetched source
// psk.zig's constants came from) — these are OFFICIAL byte-exact vectors,
// not a self-consistency oracle.

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 8448 §4: PSK = HKDF-Expand-Label(rms, "resumption", 0x0000, 32) —
// same value psk.zig's rfc8448_psk pins; repeated here so this file's chain
// test is self-contained.
const rfc8448_psk = hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
// RFC 8448 §4: early_secret = HKDF-Extract(0, PSK) (the PRK all three
// early-branch derivations below start from).
const rfc8448_early_secret = hexTo(32, "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
// RFC 8448 §4: Transcript-Hash(ClientHello) — the COMPLETE ClientHello,
// binders included (contrast psk.zig's rfc8448_binder_hash 63224b…, which
// is the TRUNCATED ClientHello — the pitfall the module doc calls out).
const rfc8448_client_hello_hash = hexTo(32, "08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913");
// RFC 8448 §4: client_early_traffic_secret = Derive-Secret(early_secret,
// "c e traffic", ClientHello).
const rfc8448_client_early_traffic_secret = hexTo(32, "3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62");
// RFC 8448 §4: early_exporter_master_secret = Derive-Secret(early_secret,
// "e exp master", ClientHello).
const rfc8448_early_exporter_master_secret = hexTo(32, "b2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df");
// RFC 8448 §4: "derive write traffic keys for early application data" —
// key = HKDF-Expand-Label(cets, "key", "", 16), iv = …("iv", "", 12).
const rfc8448_early_key = hexTo(16, "920205a5b7bf2115e6fc5c2942834f54");
const rfc8448_early_iv = hexTo(12, "6d475f0993c8e564610db2b9");
// RFC 8448 §4: the client's actual early-data application_data record —
// header (AAD) + ciphertext||tag protecting TLSInnerPlaintext
// "ABCDEF" || 0x17 (content type application_data, RFC 8446 §5.2).
const rfc8448_early_record_header = hexTo(5, "1703030017");
const rfc8448_early_record_ct = hexTo(7, "ab1df420e75c45");
const rfc8448_early_record_tag = hexTo(16, "7a7cc5d2844f76d5aee4b4edbf049be0");
// NOTE: ct/tag split of the record's 23 ciphertext octets ab1df420e75c45 ||
// 7a7cc5d2844f76d5aee4b4edbf049be0 — 7 bytes ct ("ABCDEF" + content-type
// byte), then the 16-byte GCM tag.

test "clientEarlyTrafficSecret matches RFC 8448 §4 'c e traffic' byte-exact" {
    const got = clientEarlyTrafficSecret(HkdfSha256, rfc8448_early_secret, &rfc8448_client_hello_hash);
    try testing.expectEqualSlices(u8, &rfc8448_client_early_traffic_secret, &got);
}

test "earlyExporterMasterSecret matches RFC 8448 §4 'e exp master' byte-exact" {
    const got = earlyExporterMasterSecret(HkdfSha256, rfc8448_early_secret, &rfc8448_client_hello_hash);
    try testing.expectEqualSlices(u8, &rfc8448_early_exporter_master_secret, &got);
}

test "earlyTrafficKeyIv matches RFC 8448 §4 early write key + iv byte-exact" {
    const got = earlyTrafficKeyIv(HkdfSha256, 16, rfc8448_client_early_traffic_secret);
    try testing.expectEqualSlices(u8, &rfc8448_early_key, &got.key);
    try testing.expectEqualSlices(u8, &rfc8448_early_iv, &got.iv);
}

test "EarlyDataContext.derive: full chain PSK -> early keys, RFC 8448 §4 end-to-end" {
    const ctx = EarlyDataContext(HkdfSha256, 16).derive(&rfc8448_psk, &rfc8448_client_hello_hash);
    try testing.expectEqualSlices(u8, &rfc8448_early_secret, &ctx.early_secret);
    try testing.expectEqualSlices(u8, &rfc8448_client_early_traffic_secret, &ctx.client_early_traffic_secret);
    try testing.expectEqualSlices(u8, &rfc8448_early_key, &ctx.key);
    try testing.expectEqualSlices(u8, &rfc8448_early_iv, &ctx.iv);
}

test "open RFC 8448 §4's actual early-data record with the derived key/iv" {
    // The strongest possible oracle: AEAD-open the trace's real 0-RTT
    // record. Record protection per RFC 8446 §5.2/§5.3: AAD = the 5-byte
    // record header, nonce = iv XOR left-padded seq (seq = 0 for the first
    // early-data record, so nonce == iv), plaintext = TLSInnerPlaintext =
    // content "ABCDEF" || ContentType application_data (0x17).
    const keys = earlyTrafficKeyIv(HkdfSha256, 16, rfc8448_client_early_traffic_secret);
    var plaintext: [7]u8 = undefined;
    try Aes128Gcm.decrypt(
        &plaintext,
        &rfc8448_early_record_ct,
        rfc8448_early_record_tag,
        &rfc8448_early_record_header,
        keys.iv, // seq 0: nonce = iv XOR 0 = iv
        keys.key,
    );
    try testing.expectEqualSlices(u8, "ABCDEF" ++ [_]u8{0x17}, &plaintext);
}

test "seal/open round-trip: derived early key/iv protect and recover a record" {
    // Complements the byte-exact open above with the sealing direction
    // (what a resuming CLIENT does with these keys): seal a fresh inner
    // plaintext under the derived key/iv, then open it back.
    const ctx = EarlyDataContext(HkdfSha256, 16).derive(&rfc8448_psk, &rfc8448_client_hello_hash);
    const inner_plaintext = "early GET /" ++ [_]u8{0x17};
    const header = [_]u8{ 0x17, 0x03, 0x03, 0x00, inner_plaintext.len + Aes128Gcm.tag_length };

    var seq_padded = [_]u8{0} ** 12;
    std.mem.writeInt(u64, seq_padded[4..12], 1, .big); // second record: seq = 1
    var nonce: [12]u8 = undefined;
    for (&nonce, ctx.iv, seq_padded) |*n, iv_b, s_b| n.* = iv_b ^ s_b;

    var ct: [inner_plaintext.len]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, inner_plaintext, &header, nonce, ctx.key);

    var recovered: [inner_plaintext.len]u8 = undefined;
    try Aes128Gcm.decrypt(&recovered, &ct, tag, &header, nonce, ctx.key);
    try testing.expectEqualSlices(u8, inner_plaintext, &recovered);

    // And a flipped ciphertext byte must fail authentication.
    var bad_ct = ct;
    bad_ct[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, Aes128Gcm.decrypt(&recovered, &bad_ct, tag, &header, nonce, ctx.key));
}

test "SHA-384 / key_len 32 suite: chain runs at the 48-byte digest length and is internally consistent" {
    // RFC 8448 carries no SHA-384 0-RTT vector (its §4 trace is
    // TLS_AES_128_GCM_SHA256 only), so — exactly like psk.zig's SHA-384
    // test — this asserts internal consistency at the larger digest length
    // (derive twice -> identical; convenience type == manual chain; seal/
    // open round-trip under AES-256-GCM) rather than a byte-exact external
    // target.
    const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
    const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

    const psk = [_]u8{0x5A} ** 48;
    var ch_hash: [48]u8 = undefined;
    Sha384.hash("fake complete client hello", &ch_hash, .{});

    const ctx = EarlyDataContext(Hkdf384, 32).derive(&psk, &ch_hash);

    // Convenience type must equal the manual step-by-step chain.
    const es = pskmod.earlySecret(Hkdf384, &psk);
    try testing.expectEqualSlices(u8, &es, &ctx.early_secret);
    const cets = clientEarlyTrafficSecret(Hkdf384, es, &ch_hash);
    try testing.expectEqualSlices(u8, &cets, &ctx.client_early_traffic_secret);
    const keys = earlyTrafficKeyIv(Hkdf384, 32, cets);
    try testing.expectEqualSlices(u8, &keys.key, &ctx.key);
    try testing.expectEqualSlices(u8, &keys.iv, &ctx.iv);

    // The exporter branch derives and differs from the traffic branch.
    const exp = earlyExporterMasterSecret(Hkdf384, es, &ch_hash);
    try testing.expect(!std.mem.eql(u8, &exp, &cets));

    // Seal/open round-trip under the derived AES-256-GCM key.
    const inner = "0rtt" ++ [_]u8{0x17};
    const header = [_]u8{ 0x17, 0x03, 0x03, 0x00, inner.len + Aes256Gcm.tag_length };
    var ct: [inner.len]u8 = undefined;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(&ct, &tag, inner, &header, ctx.iv, ctx.key); // seq 0: nonce = iv
    var recovered: [inner.len]u8 = undefined;
    try Aes256Gcm.decrypt(&recovered, &ct, tag, &header, ctx.iv, ctx.key);
    try testing.expectEqualSlices(u8, inner, &recovered);
}

test "different ClientHello hashes yield different early traffic secrets" {
    // Sanity that the transcript context actually feeds the derivation
    // (guards against a copy-paste bug passing "" as context, which would
    // silently produce a fixed secret per PSK).
    const other_hash = [_]u8{0xAB} ** 32;
    const a = clientEarlyTrafficSecret(HkdfSha256, rfc8448_early_secret, &rfc8448_client_hello_hash);
    const b = clientEarlyTrafficSecret(HkdfSha256, rfc8448_early_secret, &other_hash);
    try testing.expect(!std.mem.eql(u8, &a, &b));
}
