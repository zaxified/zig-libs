// SPDX-License-Identifier: MIT
//! ctap2pin — CTAP 2.1 `pinUvAuthProtocol` One and Two (FIDO2 / WebAuthn
//! client-to-authenticator PIN/UV auth protocol, CTAP 2.1 §6.5.6–6.5.8):
//! the ECDH-P256 key agreement + AES-256-CBC encryption + HMAC-SHA-256
//! authentication layer a platform and an authenticator use to protect the
//! PIN/UV during CTAP2 (`getPinToken`, `setPIN`, `changePIN`, ...).
//!
//! **Status: complete.** Both protocols implemented end-to-end:
//! `PublicKey`/`publicKeyFromScalar`/`ecdhZ` (P-256 ECDH, Z = big-endian
//! x-coordinate of `platformScalar * authenticatorPoint`), `One` (§6.5.7:
//! `kdf = SHA-256(Z)`; AES-256-CBC with an all-zero IV, ciphertext only;
//! 16-byte truncated HMAC-SHA-256), `Two` (§6.5.8: `kdf` = HKDF-SHA-256
//! with a 32-zero-byte salt and the `"CTAP2 HMAC key"` / `"CTAP2 AES key"`
//! info strings into a 64-byte `hmacKey || aesKey` secret; AES-256-CBC with
//! a caller-supplied random IV, output `IV || ciphertext`; full 32-byte
//! HMAC-SHA-256), the shared `encapsulate`, and `Impl(protocol)` comptime
//! dispatch over the `Protocol` enum. All randomness (the platform ECDH
//! scalar, the protocol-Two IV) is caller-supplied — no internal RNG — so
//! every operation is deterministic and KAT-able.
//!
//! Zig std GAP: yes — **AES-256-CBC**. `std.crypto` ships the raw AES-256
//! block cipher (`std.crypto.core.aes.Aes256`: `initEnc`/`initDec`, ctx
//! `encrypt`/`decrypt` on single 16-byte blocks) and the AEAD modes
//! (GCM/CCM/OCB), but **no CBC mode** — `Aes256Cbc` below is this module's
//! own (encrypt: `c_i = E(p_i XOR c_{i-1})`, `c_0` chains from the IV;
//! decrypt: `p_i = D(c_i) XOR c_{i-1}`), validated byte-exact against NIST
//! SP 800-38A Appendix F.2.5/F.2.6 (`kat_test.zig`). Everything else is a
//! composition of std primitives: `std.crypto.ecc.P256` (`.mul`,
//! `fromAffineCoordinates`, `affineCoordinates()` for the x-coordinate),
//! `std.crypto.kdf.hkdf.HkdfSha256` (`extract`/`expand`),
//! `std.crypto.auth.hmac.sha2.HmacSha256`, `std.crypto.hash.sha2.Sha256`,
//! and `std.crypto.timing_safe.eql` (the MAC compare in `verify` is
//! constant-time and fail-closed).
//!
//! Validation (no single official CTAP2 KAT table exists; each primitive is
//! anchored to its own official vector, plus full protocol round-trips —
//! see `kat_vectors.zig` / `kat_test.zig`): AES-256-CBC byte-exact vs NIST
//! SP 800-38A F.2.5/F.2.6; HKDF-SHA-256 byte-exact vs RFC 5869 A.1;
//! P-256 ECDH `Z` byte-exact vs RFC 5903 §8.1; HMAC-SHA-256 byte-exact vs
//! RFC 4231 test case 2; both protocols: two-sided `encapsulate` agreement,
//! `decrypt(encrypt(m)) == m`, `verify(authenticate(m))`, tamper rejection,
//! and typed-error handling of wrong-length inputs (no panics).
//!
//! Clean-room from the FIDO Alliance CTAP 2.1 specification §6.5.6–6.5.8
//! (public specification; see `NOTICE`).

const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;
// P-256 curve group from the asm-accelerated `p256` module (byte-exact to
// `std.crypto.ecc.P256`) — the COSE ECDH + ES256 primitives.
const P256 = @import("p256").P256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "CTAP2 `pinUvAuthProtocol` (FIDO2/WebAuthn) — both protocol versions: ECDH-P256 key agreement, encrypt/decrypt, authenticate/verify.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no CBOR/CTAP wire framing
    .concurrency = .reentrant, // no globals; all state is caller-held values
    .model_after = "FIDO Alliance CTAP 2.1 spec 6.5.6-6.5.8 (pinUvAuthProtocol One/Two); std.crypto supplies AES block + P256 + HKDF + HMAC",
    .deps = .{"p256"}, // p256 supplies the P-256 curve (byte-exact to std.crypto.ecc.P256); AES/HKDF/HMAC stay on std
};

// ── errors ──────────────────────────────────────────────────────────────────

/// AES-256-CBC length errors: plaintext/ciphertext not a multiple of the
/// 16-byte block length, or a destination buffer of the wrong size.
pub const CbcError = error{InvalidLength};

/// ECDH errors: a peer COSE key whose coordinates are non-canonical or not
/// on P-256, or a private scalar that is zero / not canonical (the CTAP 2.1
/// contract is "regenerate and retry" for a bad platform scalar).
pub const EcdhError = error{ InvalidPublicKey, InvalidScalar };

// ── AES-256-CBC (the std gap — NIST SP 800-38A validated) ───────────────────

/// AES-256 in CBC mode (NIST SP 800-38A §6.2), without padding: inputs must
/// be a whole number of 16-byte blocks. Not in `std.crypto` (which has the
/// raw block cipher and AEADs only) — validated byte-exact against NIST
/// SP 800-38A Appendix F.2.5 (encrypt) and F.2.6 (decrypt) in
/// `kat_test.zig`. Exact in-place use (`dst.ptr == src.ptr`) is supported.
pub const Aes256Cbc = struct {
    pub const block_length = 16;
    pub const key_length = 32;

    /// `c_i = E_key(p_i XOR c_{i-1})`, with `c_0` chaining from `iv`.
    /// `dst.len` must equal `plaintext.len`, a multiple of 16 (0 is fine).
    pub fn encrypt(dst: []u8, plaintext: []const u8, key: [key_length]u8, iv: [block_length]u8) CbcError!void {
        if (plaintext.len % block_length != 0 or dst.len != plaintext.len)
            return error.InvalidLength;
        const ctx = Aes256.initEnc(key);
        var prev: [block_length]u8 = iv;
        var i: usize = 0;
        while (i < plaintext.len) : (i += block_length) {
            var block: [block_length]u8 = undefined;
            for (&block, plaintext[i..][0..block_length], prev) |*b, p, c| b.* = p ^ c;
            ctx.encrypt(dst[i..][0..block_length], &block);
            prev = dst[i..][0..block_length].*;
        }
    }

    /// `p_i = D_key(c_i) XOR c_{i-1}`, with `c_0` chaining from `iv`.
    /// `dst.len` must equal `ciphertext.len`, a multiple of 16 (0 is fine).
    pub fn decrypt(dst: []u8, ciphertext: []const u8, key: [key_length]u8, iv: [block_length]u8) CbcError!void {
        if (ciphertext.len % block_length != 0 or dst.len != ciphertext.len)
            return error.InvalidLength;
        const ctx = Aes256.initDec(key);
        var prev: [block_length]u8 = iv;
        var i: usize = 0;
        while (i < ciphertext.len) : (i += block_length) {
            // Copy c_i first so exact in-place decryption works.
            const c: [block_length]u8 = ciphertext[i..][0..block_length].*;
            var block: [block_length]u8 = undefined;
            ctx.decrypt(&block, &c);
            for (dst[i..][0..block_length], block, prev) |*d, b, p| d.* = b ^ p;
            prev = c;
        }
    }
};

// ── ECDH over NIST P-256 (CTAP 2.1 §6.5.6 key agreement) ────────────────────

/// A P-256 public key as carried in a CTAP2 COSE_Key (EC2, crv P-256):
/// the affine x and y coordinates, 32 bytes each, big-endian — the
/// `authenticatorKeyAgreementKey` / `platformKeyAgreementKey` shape.
pub const PublicKey = struct {
    x: [32]u8,
    y: [32]u8,

    /// Validate the coordinates: each must be a canonical field element and
    /// (x, y) must satisfy the P-256 curve equation. Returns the point.
    pub fn toPoint(pk: PublicKey) EcdhError!P256 {
        const x = P256.Fe.fromBytes(pk.x, .big) catch return error.InvalidPublicKey;
        const y = P256.Fe.fromBytes(pk.y, .big) catch return error.InvalidPublicKey;
        return P256.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidPublicKey;
    }
};

/// Derive the public key for a private scalar (big-endian, 32 bytes):
/// `scalar * G`. Rejects a zero or non-canonical scalar with
/// `error.InvalidScalar` — per CTAP 2.1, regenerate the random scalar.
pub fn publicKeyFromScalar(private_scalar: [32]u8) EcdhError!PublicKey {
    P256.scalar.rejectNonCanonical(private_scalar, .big) catch return error.InvalidScalar;
    const p = P256.basePoint.mul(private_scalar, .big) catch return error.InvalidScalar;
    const aff = p.affineCoordinates();
    return .{ .x = aff.x.toBytes(.big), .y = aff.y.toBytes(.big) };
}

/// `Z = ECDH(private, peer)`: the big-endian x-coordinate (32 bytes) of
/// `private_scalar * peerPoint` (CTAP 2.1 §6.5.6 `ecdh`, minus the
/// protocol-specific `kdf` step — feed the result to `One.kdf`/`Two.kdf`).
pub fn ecdhZ(private_scalar: [32]u8, peer: PublicKey) EcdhError![32]u8 {
    P256.scalar.rejectNonCanonical(private_scalar, .big) catch return error.InvalidScalar;
    // ⛔ NOT `std.mem.allEqual(u8, &private_scalar, 0)`, which is what this was
    // until 2026-09-09 (audit finding L1). That is a naive byte loop with an
    // early return: for a real scalar it stops after ~1 byte, for the all-zero
    // one it walks all 32 — a textbook distinguisher, on the SECRET scalar.
    //
    // ⚠ Measured, it did not compile that way: LLVM vectorised it into a single
    // data-independent `vptest`, twice over (here and in `sphinx`). So this was
    // never a live leak — it was SAFE BY ACCIDENT. `std.mem.allEqual` makes no
    // constant-time promise, nothing pins that vectorisation, and another LLVM,
    // `ReleaseSafe` or another target quietly turns it back into the byte loop
    // with no test able to notice.
    //
    // `timing_safe.eql` promises it instead, which is what the line 35 lines
    // above already does deliberately — and `scripts/check-ct-compare.py` now
    // pins the call so it cannot be swapped back unnoticed.
    if (std.crypto.timing_safe.eql([32]u8, private_scalar, [_]u8{0} ** 32)) return error.InvalidScalar;
    const point = try peer.toPoint();
    const shared = point.mul(private_scalar, .big) catch return error.InvalidPublicKey;
    return shared.affineCoordinates().x.toBytes(.big);
}

// ── protocol selector ───────────────────────────────────────────────────────

/// The CTAP 2.1 `pinUvAuthProtocol` identifier (the value sent on the wire
/// in e.g. `clientPin`'s `pinUvAuthProtocol` field).
pub const Protocol = enum(u8) {
    one = 1,
    two = 2,
};

/// Comptime dispatch: `Impl(.one) == One`, `Impl(.two) == Two`.
pub fn Impl(comptime protocol: Protocol) type {
    return switch (protocol) {
        .one => One,
        .two => Two,
    };
}

fn Encapsulation(comptime SharedSecret: type) type {
    return struct {
        /// The platform's key-agreement public key (send to the
        /// authenticator as a COSE_Key).
        platform_key_agreement: PublicKey,
        /// The protocol's `kdf(Z)` output. Zero it when done
        /// (`std.crypto.secureZero`) — CTAP 2.1 keeps it per-transaction.
        shared_secret: SharedSecret,
    };
}

// ── pinUvAuthProtocol One (CTAP 2.1 §6.5.7) ────────────────────────────────

pub const One = struct {
    pub const protocol: Protocol = .one;
    pub const shared_secret_length = 32;
    pub const signature_length = 16;
    pub const SharedSecret = [shared_secret_length]u8;
    pub const Encaps = Encapsulation(SharedSecret);

    /// §6.5.7 `kdf(Z) = SHA-256(Z)`.
    pub fn kdf(z: [32]u8) SharedSecret {
        var out: SharedSecret = undefined;
        Sha256.hash(&z, &out, .{});
        return out;
    }

    /// §6.5.6 `encapsulate(peerCoseKey)`: ECDH with the caller-supplied
    /// random platform scalar, then this protocol's `kdf`. Returns the
    /// platform public key + the shared secret; both sides of the same
    /// exchange derive the identical secret.
    pub fn encapsulate(platform_scalar: [32]u8, peer: PublicKey) EcdhError!Encaps {
        return .{
            .platform_key_agreement = try publicKeyFromScalar(platform_scalar),
            .shared_secret = kdf(try ecdhZ(platform_scalar, peer)),
        };
    }

    /// §6.5.7 `encrypt(key, demPlaintext)`: AES-256-CBC with an all-zero
    /// IV, no padding, output is the bare ciphertext (`dst.len ==
    /// plaintext.len`, a multiple of 16).
    pub fn encrypt(key: SharedSecret, dst: []u8, plaintext: []const u8) CbcError!void {
        try Aes256Cbc.encrypt(dst, plaintext, key, @splat(0));
    }

    /// §6.5.7 `decrypt(key, demCiphertext)`: inverse of `encrypt`
    /// (`dst.len == ciphertext.len`, a multiple of 16).
    pub fn decrypt(key: SharedSecret, dst: []u8, ciphertext: []const u8) CbcError!void {
        try Aes256Cbc.decrypt(dst, ciphertext, key, @splat(0));
    }

    /// §6.5.7 `authenticate(key, message)`: the first 16 bytes of
    /// `HMAC-SHA-256(key, message)`. `key` is generic per the spec's
    /// `authenticate` abstract operation: CTAP2 calls this both with the
    /// 32-byte shared secret (`setPin`/`getPinToken`'s `pinUvAuthParam`) and
    /// with a 16- or 32-byte `pinUvAuthToken` (every later command's
    /// per-request `pinUvAuthParam`, keyed by the token obtained from
    /// `getPinToken` — CTAP 2.1 §6.5.7 note under `getPinToken`) — the two
    /// keys differ in length, so this cannot be typed as `SharedSecret`.
    pub fn authenticate(key: []const u8, message: []const u8) [signature_length]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&mac, message, key);
        return mac[0..signature_length].*;
    }

    /// §6.5.7 `verify(key, message, signature)`: recompute and compare in
    /// constant time. Fail-closed: a wrong-length signature is `false`.
    /// `key`: see `authenticate` — shared secret or `pinUvAuthToken`.
    pub fn verify(key: []const u8, message: []const u8, signature: []const u8) bool {
        if (signature.len != signature_length) return false;
        const expected = authenticate(key, message);
        return std.crypto.timing_safe.eql([signature_length]u8, expected, signature[0..signature_length].*);
    }
};

// ── pinUvAuthProtocol Two (CTAP 2.1 §6.5.8) ────────────────────────────────

pub const Two = struct {
    pub const protocol: Protocol = .two;
    pub const shared_secret_length = 64;
    pub const signature_length = 32;
    pub const iv_length = 16;
    /// `HMAC-key (32) || AES-key (32)` — §6.5.8's 64-byte shared secret.
    pub const SharedSecret = [shared_secret_length]u8;
    pub const Encaps = Encapsulation(SharedSecret);

    /// §6.5.8 `kdf(Z)`: HKDF-SHA-256 with a 32-zero-byte salt, expanded
    /// once with info `"CTAP2 HMAC key"` and once with `"CTAP2 AES key"`
    /// (32 bytes each); the shared secret is `hmacKey || aesKey`.
    pub fn kdf(z: [32]u8) SharedSecret {
        const salt: [32]u8 = @splat(0);
        const prk = HkdfSha256.extract(&salt, &z);
        var out: SharedSecret = undefined;
        HkdfSha256.expand(out[0..32], "CTAP2 HMAC key", prk);
        HkdfSha256.expand(out[32..64], "CTAP2 AES key", prk);
        return out;
    }

    /// §6.5.6 `encapsulate(peerCoseKey)` with this protocol's `kdf` —
    /// see `One.encapsulate`.
    pub fn encapsulate(platform_scalar: [32]u8, peer: PublicKey) EcdhError!Encaps {
        return .{
            .platform_key_agreement = try publicKeyFromScalar(platform_scalar),
            .shared_secret = kdf(try ecdhZ(platform_scalar, peer)),
        };
    }

    /// Output size of `encrypt`: `IV || ciphertext`.
    pub fn encryptedLength(plaintext_len: usize) usize {
        return iv_length + plaintext_len;
    }

    /// Plaintext size for a §6.5.8 ciphertext, validating its shape
    /// (leading 16-byte IV + whole blocks).
    pub fn decryptedLength(ciphertext_len: usize) CbcError!usize {
        if (ciphertext_len < iv_length or (ciphertext_len - iv_length) % Aes256Cbc.block_length != 0)
            return error.InvalidLength;
        return ciphertext_len - iv_length;
    }

    /// §6.5.8 `encrypt(key, demPlaintext)`: AES-256-CBC keyed with the
    /// AES-key half, IV caller-supplied (the spec says a random IV — pass
    /// fresh randomness; taking it as a parameter keeps this deterministic
    /// and KAT-able). Output is `iv || ciphertext`, so `dst.len` must be
    /// `plaintext.len + 16` (`encryptedLength`).
    pub fn encrypt(key: SharedSecret, iv: [iv_length]u8, dst: []u8, plaintext: []const u8) CbcError!void {
        if (dst.len != encryptedLength(plaintext.len)) return error.InvalidLength;
        try Aes256Cbc.encrypt(dst[iv_length..], plaintext, key[32..64].*, iv);
        dst[0..iv_length].* = iv;
    }

    /// §6.5.8 `decrypt(key, demCiphertext)`: split off the leading 16-byte
    /// IV, AES-256-CBC-decrypt the rest with the AES-key half. `dst.len`
    /// must equal `decryptedLength(ciphertext.len)`.
    pub fn decrypt(key: SharedSecret, dst: []u8, ciphertext: []const u8) CbcError!void {
        const plaintext_len = try decryptedLength(ciphertext.len);
        if (dst.len != plaintext_len) return error.InvalidLength;
        try Aes256Cbc.decrypt(dst, ciphertext[iv_length..], key[32..64].*, ciphertext[0..iv_length].*);
    }

    /// §6.5.8 `authenticate(key, message)`: the full 32-byte
    /// `HMAC-SHA-256(hmacKey, message)`. `key` is generic per the spec's
    /// `authenticate` abstract operation, and must be at least 32 bytes:
    /// pass the 64-byte shared secret (`hmacKey` is its first 32 bytes,
    /// `key[0..32]` below) for `setPin`/`getPinToken`'s `pinUvAuthParam`, or
    /// pass a 32-byte `pinUvAuthToken` directly (already exactly `hmacKey`
    /// length, so `key[0..32]` is the whole token unchanged) for every later
    /// command's per-request `pinUvAuthParam` — CTAP 2.1 §6.5.7 note under
    /// `getPinToken`.
    pub fn authenticate(key: []const u8, message: []const u8) [signature_length]u8 {
        var mac: [signature_length]u8 = undefined;
        HmacSha256.create(&mac, message, key[0..32]);
        return mac;
    }

    /// §6.5.8 `verify(key, message, signature)`: recompute and compare in
    /// constant time. Fail-closed: a wrong-length signature is `false`.
    /// `key`: see `authenticate` — shared secret or `pinUvAuthToken`.
    pub fn verify(key: []const u8, message: []const u8, signature: []const u8) bool {
        if (signature.len != signature_length) return false;
        const expected = authenticate(key, message);
        return std.crypto.timing_safe.eql([signature_length]u8, expected, signature[0..signature_length].*);
    }
};

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("pin_protocol_oracle_vectors.zig");
    _ = @import("pin_protocol_oracle_test.zig");
}

// ── fuzz: untrusted-wire decoders never panic/OOB on arbitrary bytes ──────

fn fuzzPublicKeyToPoint(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    smith.bytes(&buf);
    const pk = PublicKey{ .x = buf[0..32].*, .y = buf[32..64].* };
    _ = pk.toPoint() catch return;
}
test "fuzz PublicKey.toPoint never panics" {
    try std.testing.fuzz({}, fuzzPublicKeyToPoint, .{});
}

/// ⛔ `Two.decrypt` accepts exactly the lengths `16 + 16k`, and `cipher_len`
/// came from a ranged draw taken after `smith.bytes` had eaten the input — so
/// it was **0** on every input this target ever ran outside `--fuzz`, and
/// `decryptedLength(0)` returned `InvalidLength` before a single AES round.
/// The harness had never decrypted anything.
///
/// A seed is the 64-octet shared secret RAW (drawn with `smith.bytes`, which
/// reads no length header), then the ciphertext framed the way `Smith.slice`
/// reads it: a little-endian `u32` length, then the octets. (Spelled out here
/// rather than via `testkit.fuzz.seed`, because the two halves have to be one
/// comptime-concatenated array with a static lifetime.)
const decrypt_seeds = [_][]const u8{
    // IV + exactly one block: the shortest input `decryptedLength` accepts.
    twoSeed(32),
    twoSeed(48), // IV + two blocks
    twoSeed(16), // IV and no blocks: a legal zero-length plaintext
    twoSeed(256), // the buffer's full width, 15 blocks
    twoSeed(15), // one octet short of the IV
    twoSeed(33), // IV + one block + one octet: not a whole number of blocks
    twoSeed(0), // and the input this target used to run for ever
};

/// The key is 64 zero octets: `Two.decrypt` keys AES from `key[32..64]`, and
/// which key is used decides nothing about the length gate under test.
fn twoSeed(comptime cipher_len: usize) []const u8 {
    return &struct {
        const bytes = [_]u8{0} ** Two.shared_secret_length ++
            std.mem.toBytes(@as(u32, cipher_len)) ++ [_]u8{0xA5} ** cipher_len;
    }.bytes;
}

fn fuzzTwoDecrypt(_: void, smith: *std.testing.Smith) !void {
    var key_buf: [Two.shared_secret_length]u8 = undefined;
    smith.bytes(&key_buf);
    var cipher_buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length.
    const cipher_len: usize = smith.slice(&cipher_buf);
    const ciphertext = cipher_buf[0..cipher_len];
    // Two.decrypt takes ciphertext.len from the wire; a malformed length
    // (< iv_length, or not a whole number of blocks past the IV) must
    // return a typed error, never panic/OOB, before any AES runs.
    const plaintext_len = Two.decryptedLength(ciphertext.len) catch return;
    var dst: [256]u8 = undefined;
    Two.decrypt(key_buf, dst[0..plaintext_len], ciphertext) catch return;
}
test "fuzz Two.decrypt never panics" {
    try std.testing.fuzz({}, fuzzTwoDecrypt, .{ .corpus = &decrypt_seeds });
}

test "corpus: the decrypt seeds reach the cipher, and the counts are pinned" {
    var nonempty: usize = 0;
    var accepted_length: usize = 0;
    // The number the collapsed draw could not produce: plaintext octets that
    // actually came out of AES. `decryptedLength(16)` is a legal 0, so a count
    // of accepted LENGTHS alone would not distinguish "decrypted nothing".
    var plaintext_octets: usize = 0;
    for (decrypt_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var key_buf: [Two.shared_secret_length]u8 = undefined;
        smith.bytes(&key_buf);
        var cipher_buf: [256]u8 = undefined;
        const cipher_len: usize = smith.slice(&cipher_buf);
        if (cipher_len != 0) nonempty += 1;
        const plaintext_len = Two.decryptedLength(cipher_len) catch continue;
        accepted_length += 1;
        var dst: [256]u8 = undefined;
        Two.decrypt(key_buf, dst[0..plaintext_len], cipher_buf[0..cipher_len]) catch continue;
        plaintext_octets += plaintext_len;
    }
    try std.testing.expectEqual(decrypt_seeds.len - 1, nonempty); // all but the empty seed
    try std.testing.expectEqual(@as(usize, 4), accepted_length);
    try std.testing.expectEqual(@as(usize, 288), plaintext_octets);
}
