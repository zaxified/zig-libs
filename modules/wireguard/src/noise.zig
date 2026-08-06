// SPDX-License-Identifier: MIT
//! Noise_IKpsk2 primitives — the generic Noise Protocol Framework building
//! blocks (transcript hash, chaining-key KDF ratchet, keyed MAC) instantiated
//! with WireGuard's fixed primitive choices: Curve25519 (X25519) DH,
//! ChaCha20-Poly1305 AEAD, BLAKE2s hash + HMAC + KDF.
//!
//! `handshake.zig` (the Noise_IKpsk2 message flow / session state machine)
//! is built on top of these primitives.
//!
//! Verification: the KDF is tested against the test vectors published in the
//! official wireguard-go repository (`device/kdf_test.go`,
//! git.zx2c4.com/wireguard-go — vectors are protocol data, not code); the
//! initial chaining-key/hash constants are cross-checked against an
//! independent reference computation (Python hashlib BLAKE2s). The full
//! handshake built on these primitives is verified in `handshake.zig`
//! against a fixed-input known-answer vector from an independent reference
//! implementation and (gated) live against the Linux kernel's WireGuard.
//!
//! Provenance: clean-room from the WireGuard protocol description
//! (J. A. Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel",
//! NDSS 2017, https://www.wireguard.com/papers/wireguard.pdf, and the
//! protocol summary at https://www.wireguard.com/protocol/) and the Noise
//! Protocol Framework specification (https://noiseprotocol.org/noise.html),
//! pattern `IKpsk2`. Design reference: wireguard-go
//! (golang.zx2c4.com/wireguard, MIT) and the Linux kernel WireGuard
//! implementation (GPL-2.0) — behavior/shape only (the construction name,
//! labels and message layout are the standardized wire format, not
//! copyrightable expression); no source consulted or copied. See ../NOTICE.

const std = @import("std");
const chachapoly = @import("chachapoly");

// Note: `pub const meta` is declared once, canonically, in `root.zig` (per
// CONVENTIONS.md §4) — submodule files like this one do not repeat it.

// ── Noise construction identity (fixed strings, hashed at session start) ───

/// The Noise protocol name for WireGuard's instantiation. Hashed into the
/// initial chaining key (`Ck0 = HASH(CONSTRUCTION)`, since it is longer than
/// `hash_len`, per the Noise spec's `InitializeSymmetric`).
pub const CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// Mixed into the initial transcript hash after `CONSTRUCTION`:
/// `H0 = HASH(Ck0 || IDENTIFIER)`.
pub const IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
/// Label whose keyed hash of a peer's static public key yields that peer's
/// mac1 key: `mac1_key = HASH(LABEL_MAC1 || peer_static_public)`.
pub const LABEL_MAC1 = "mac1----";
/// Label whose keyed hash of a peer's static public key yields that peer's
/// cookie key: `cookie_key = HASH(LABEL_COOKIE || peer_static_public)`.
pub const LABEL_COOKIE = "cookie--";

// ── primitive instantiation (WireGuard's fixed choice of algorithms) ───────

/// BLAKE2s-256 — WireGuard's hash function (`Hash` in the Noise spec).
pub const Blake2s = std.crypto.hash.blake2.Blake2s256;
/// HMAC-BLAKE2s — the MAC underlying `Hkdf` (Noise's `HKDF` uses HMAC).
pub const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s);
/// HKDF-BLAKE2s — Noise's chaining-key ratchet (`KDF1`/`KDF2`/`KDF3` below).
pub const Hkdf = std.crypto.kdf.hkdf.Hkdf(HmacBlake2s);
/// Curve25519 Diffie-Hellman (`DH` in the Noise spec).
pub const X25519 = std.crypto.dh.X25519;
/// BLAKE2s-128 — keyed, for the 16-byte `mac1`/`mac2` fields. NOTE: this is
/// keyed BLAKE2s with a 16-byte *parameterized* output (the digest length is
/// encoded in the BLAKE2s parameter block), NOT a truncated BLAKE2s-256 —
/// the two produce different bytes. Matches the whitepaper's
/// `Mac(key, input) := Keyed-Blake2s(key, input, 16)`.
pub const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
/// ChaCha20-Poly1305 AEAD (`AEAD` in the Noise spec) — the SIMD `chachapoly`
/// sibling, not std. WireGuard is a data-plane protocol: every transport-data
/// packet is one AEAD seal/open at MTU size, so this is the one primitive in
/// the whole module whose throughput is on the packet path.
///
/// Byte-exact to `StdAead` below: `chachapoly` carries a differential against
/// std over every block-boundary edge length, and `handshake.zig`'s
/// independent-reference KAT plus `kernel_goldens.zig` re-prove it here on
/// real WireGuard wire bytes. The AEAD choice is an implementation detail; the
/// wire format is unchanged.
pub const Aead = chachapoly.ChaCha20Poly1305;

/// `std`'s ChaCha20-Poly1305. NOT used on any production path — it is kept
/// reachable purely so the module's own tests can run a vector through both
/// implementations and assert byte-identity (see `handshake.zig`'s
/// differential test).
pub const StdAead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// XChaCha20-Poly1305 AEAD — used for the (non-Noise) cookie-reply message,
/// which needs a 24-byte random nonce rather than a Noise-ratcheted counter.
///
/// **Stays on std deliberately.** `chachapoly` implements RFC 8439
/// ChaCha20-Poly1305 only; the X-variant is a DIFFERENT construction (an
/// HChaCha20 subkey derivation from the first 16 nonce bytes, then RFC 8439
/// under the remaining 8), which that module does not provide. Substituting
/// the non-X AEAD here would be a silent security break, not a speed-up. This
/// costs nothing: the cookie-reply path is a per-DoS-event control message,
/// not a data-plane one.
pub const XAead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

/// BLAKE2s digest length: chaining-key / transcript-hash / symmetric-key
/// width (32 bytes).
pub const hash_len = Blake2s.digest_length; // 32
/// Noise chaining key `ck` — the running KDF ratchet state.
pub const ChainKey = [hash_len]u8;
/// Noise transcript hash `h` — commits to every message exchanged so far.
pub const HandshakeHash = [hash_len]u8;
/// A derived symmetric AEAD key (32 bytes, `Aead.key_length`).
pub const SymmetricKey = [Aead.key_length]u8;
/// Keyed-BLAKE2s MAC1/MAC2 length (16 bytes — wireguard-go's
/// `blake2s.Size128`, i.e. BLAKE2s truncated to a 128-bit output).
pub const mac_len = 16;
pub const Mac = [mac_len]u8;
/// AEAD authentication tag length (Poly1305, 16 bytes).
pub const tag_len = Aead.tag_length;

// ── KDF: HKDF-BLAKE2s ratchet (Noise spec sec 4.3, `HKDF(ck, input, n)`) ───
//
// Noise's `HKDF(chaining_key, input_key_material, num_outputs)`:
//   temp_key := HMAC-HASH(chaining_key, input_key_material)   -- HKDF-Extract
//   output1  := HMAC-HASH(temp_key, 0x01)                     -- HKDF-Expand, 1 block
//   output2  := HMAC-HASH(temp_key, output1 || 0x02)          -- HKDF-Expand, 2nd block
//   output3  := HMAC-HASH(temp_key, output2 || 0x03)          -- HKDF-Expand, 3rd block (KDF3 only)
// `std.crypto.kdf.hkdf.Hkdf(Hmac).extract`/`.expand` implement exactly this
// two-stage extract/expand; KDF1/2/3 below just fix the number of blocks.

/// `Noise HKDF(ck, input, 1)`: ratchets `ck` in place to a fresh chaining
/// key derived from `input`, discarding the (single) output block. WireGuard
/// uses this for the two ephemeral-only chaining-key updates in the
/// responder's second message (mixing `DH(Er, Si)` and the initial
/// `DH(Er, Ei)`... — see `handshake.zig`'s `createResponse`/`consumeInitiation`
/// step comments for exactly where).
pub fn kdf1(ck: *ChainKey, input: []const u8) void {
    var t = kdf(1, ck, input);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t));
    ck.* = t[0];
}

/// `Noise HKDF(ck, input, 2)`: ratchets `ck` in place and returns one
/// derived 32-byte output key (e.g. the per-message AEAD key after a DH).
pub fn kdf2(ck: *ChainKey, input: []const u8) SymmetricKey {
    var t = kdf(2, ck, input);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t));
    ck.* = t[0];
    return t[1];
}

/// `Noise HKDF(ck, input, 3)`: ratchets `ck` in place and returns two
/// derived 32-byte outputs. WireGuard uses this exactly once per handshake:
/// mixing the preshared key in the responder's second message
/// (`ck, tau, k := Kdf3(ck, psk)`) and the final transport-key split
/// (`T_send, T_recv := Kdf2(ck, empty)` is a `kdf2`, NOT this — see
/// `Handshake.deriveTransportKeys`).
pub fn kdf3(ck: *ChainKey, input: []const u8) struct { out1: SymmetricKey, out2: SymmetricKey } {
    var t = kdf(3, ck, input);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&t));
    ck.* = t[0];
    return .{ .out1 = t[1], .out2 = t[2] };
}

/// Core `Noise HKDF(key, input, n)` over HMAC-BLAKE2s, returning all `n`
/// output blocks (`t1..tn`, 32 bytes each). Takes the key as a slice so the
/// wireguard-go KDF test vectors (which use short keys) can drive it
/// directly; the public `kdf1`/`kdf2`/`kdf3` ratchet a 32-byte chaining key.
/// `std.crypto.kdf.hkdf`'s extract/expand with an empty `ctx` is exactly the
/// Noise construction: `t0 = HMAC(key, input)`, `t1 = HMAC(t0, 0x01)`,
/// `t_i = HMAC(t0, t_{i-1} || i)`.
fn kdf(comptime n: comptime_int, key: []const u8, input: []const u8) [n]SymmetricKey {
    comptime std.debug.assert(n >= 1 and n <= 3);
    var prk = Hkdf.extract(key, input);
    defer std.crypto.secureZero(u8, &prk);
    var okm: [n * hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &okm);
    Hkdf.expand(&okm, "", prk);
    var out: [n]SymmetricKey = undefined;
    inline for (0..n) |i| out[i] = okm[i * hash_len ..][0..hash_len].*;
    return out;
}

// ── transcript hash / MixKey (Noise symmetric state, spec sec 5.2) ─────────

/// Noise `MixHash(h, data)`: extends the running transcript hash,
/// `h := HASH(h || data)`. Called after every value placed on the wire
/// (ephemeral pubkeys, ciphertexts) so both sides' final hash commits to
/// the whole transcript.
pub fn mixHash(h: *HandshakeHash, data: []const u8) void {
    var st = Blake2s.init(.{});
    st.update(h);
    st.update(data);
    st.final(h);
}

/// Noise `MixKey(ck, h, dh_output)`: folds a DH output into both the
/// chaining key and (via the derived key) implicitly authenticates it —
/// `ck := kdf2(ck, dh_output)` (the temp key is NOT mixed into `h` per the
/// Noise spec; only DH outputs and ciphertexts extend `h`, via `mixHash`
/// called separately by the caller for whatever goes on the wire).
pub fn mixKey(ck: *ChainKey, dh_output: []const u8) SymmetricKey {
    return kdf2(ck, dh_output);
}

// ── mac1 / mac2 (keyed BLAKE2s, WireGuard's cookie/DoS-mitigation layer) ───
//
// mac1/mac2 sit OUTSIDE the Noise transcript proper (Noise says nothing
// about them): every handshake message ends with two 16-byte MACs so a
// resource-starved responder can cheaply reject spoofed/replayed messages
// before doing any DH. See handshake.zig's `Handshake.computeMac1`/
// `computeMac2` for how these compose with the message bytes.

/// Keyed BLAKE2s-128 MAC, `mac_len` (16) bytes:
/// `MAC(key, data) = Keyed-Blake2s(key, data, 16)` (whitepaper sec 5.4) —
/// the 16-byte output length lives in the BLAKE2s parameter block (see
/// `Blake2s128` above), so this is NOT a truncated BLAKE2s-256.
pub fn keyedMac(key: []const u8, data: []const u8) Mac {
    var out: Mac = undefined;
    Blake2s128.hash(data, &out, .{ .key = key });
    return out;
}

/// Derive a peer's mac1 key: `HASH(LABEL_MAC1 || peer_static_public)`.
/// Precompute once per peer (it only depends on the peer's static public
/// key, not on handshake state).
pub fn mac1Key(peer_static_public: [32]u8) HandshakeHash {
    return labeledKey(LABEL_MAC1, peer_static_public);
}

/// Derive a peer's cookie key: `HASH(LABEL_COOKIE || peer_static_public)`.
pub fn cookieKey(peer_static_public: [32]u8) HandshakeHash {
    return labeledKey(LABEL_COOKIE, peer_static_public);
}

/// `HASH(label || peer_static_public)` — shared body of `mac1Key`/`cookieKey`.
fn labeledKey(label: []const u8, peer_static_public: [32]u8) HandshakeHash {
    var st = Blake2s.init(.{});
    st.update(label);
    st.update(&peer_static_public);
    var out: HandshakeHash = undefined;
    st.final(&out);
    return out;
}

// ── dark-tests: pulled into the aggregator via ../root.zig `test { }` ──────

const testing = std.testing;

test "constants: exact WireGuard protocol strings" {
    try testing.expectEqualStrings("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", CONSTRUCTION);
    try testing.expectEqualStrings("WireGuard v1 zx2c4 Jason@zx2c4.com", IDENTIFIER);
    try testing.expectEqualStrings("mac1----", LABEL_MAC1);
    try testing.expectEqualStrings("cookie--", LABEL_COOKIE);
    try testing.expectEqual(@as(usize, 8), LABEL_MAC1.len);
    try testing.expectEqual(@as(usize, 8), LABEL_COOKIE.len);
}

/// Hex-decode a compile-time string into a fixed byte array (test helper).
fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "KAT: KDF against the official wireguard-go test vectors" {
    // Source: wireguard-go `device/kdf_test.go` (git.zx2c4.com/wireguard-go /
    // github.com/WireGuard/wireguard-go) — the WireGuard project's own KDF
    // test vectors for HKDF over HMAC-BLAKE2s. t1/t2/t3 are KDF3's three
    // output blocks for the given (key, input).
    const Vec = struct { key: []const u8, input: []const u8, t1: [32]u8, t2: [32]u8, t3: [32]u8 };
    const vectors = [_]Vec{
        .{
            .key = "test-key",
            .input = "test-input",
            .t1 = hex("6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633"),
            .t2 = hex("df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a"),
            .t3 = hex("fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24"),
        },
        .{
            .key = "wireguard",
            .input = "wireguard",
            .t1 = hex("491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8"),
            .t2 = hex("1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f"),
            .t3 = hex("31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160"),
        },
        .{
            .key = "",
            .input = "",
            .t1 = hex("8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0"),
            .t2 = hex("58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e"),
            .t3 = hex("0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e"),
        },
    };
    for (vectors) |v| {
        const t = kdf(3, v.key, v.input);
        try testing.expectEqual(v.t1, t[0]);
        try testing.expectEqual(v.t2, t[1]);
        try testing.expectEqual(v.t3, t[2]);
        // The 1- and 2-output variants are prefixes of the 3-output one.
        try testing.expectEqual([1]SymmetricKey{v.t1}, kdf(1, v.key, v.input));
        try testing.expectEqual([2]SymmetricKey{ v.t1, v.t2 }, kdf(2, v.key, v.input));
    }
}

test "kdf1/kdf2/kdf3 ratchet the chaining key consistently" {
    const start = hex("491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8");
    var ck1: ChainKey = start;
    var ck2: ChainKey = start;
    var ck3: ChainKey = start;
    kdf1(&ck1, "input");
    const k2 = kdf2(&ck2, "input");
    const k3 = kdf3(&ck3, "input");
    try testing.expectEqual(ck1, ck2); // all ratchet ck to t1
    try testing.expectEqual(ck1, ck3);
    try testing.expect(!std.mem.eql(u8, &ck1, &start));
    try testing.expectEqual(k2, k3.out1); // t2 identical across variants
    var ck4: ChainKey = start;
    try testing.expectEqual(k2, mixKey(&ck4, "input")); // mixKey == kdf2
    try testing.expectEqual(ck2, ck4);
}

test "sub-KAT: initial chaining key, transcript hash, mixHash" {
    // Ck0 = HASH(CONSTRUCTION), H0 = HASH(Ck0 || IDENTIFIER) — cross-checked
    // against an independent reference computation (Python hashlib BLAKE2s).
    var ck0: ChainKey = undefined;
    Blake2s.hash(CONSTRUCTION, &ck0, .{});
    try testing.expectEqual(
        hex("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"),
        ck0,
    );
    var h0: HandshakeHash = ck0;
    mixHash(&h0, IDENTIFIER);
    try testing.expectEqual(
        hex("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"),
        h0,
    );
}

test "keyedMac is parameterized BLAKE2s-128, not truncated BLAKE2s-256" {
    const key = hex("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    const mac = keyedMac(&key, "data");
    var full: [hash_len]u8 = undefined;
    Blake2s.hash("data", &full, .{ .key = &key });
    try testing.expect(!std.mem.eql(u8, &mac, full[0..mac_len]));
}

test "primitive sizes agree with the WireGuard wire format" {
    try testing.expectEqual(@as(usize, 32), hash_len);
    try testing.expectEqual(@as(usize, 32), X25519.public_length);
    try testing.expectEqual(@as(usize, 32), X25519.secret_length);
    try testing.expectEqual(@as(usize, 32), Aead.key_length);
    try testing.expectEqual(@as(usize, 12), Aead.nonce_length);
    try testing.expectEqual(@as(usize, 16), Aead.tag_length);
    try testing.expectEqual(@as(usize, 16), mac_len);
    try testing.expectEqual(@as(usize, 24), XAead.nonce_length);

    // The AEAD swap (std -> chachapoly) must not move any of the three
    // constants the wire format is built out of. Verified, not assumed.
    try testing.expectEqual(StdAead.key_length, Aead.key_length);
    try testing.expectEqual(StdAead.nonce_length, Aead.nonce_length);
    try testing.expectEqual(StdAead.tag_length, Aead.tag_length);
    // XAead is a different construction and keeps its own, wider nonce.
    try testing.expect(XAead.nonce_length != Aead.nonce_length);
}
