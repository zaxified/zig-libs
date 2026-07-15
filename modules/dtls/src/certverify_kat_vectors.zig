// SPDX-License-Identifier: MIT

//! Known-answer vectors for `certverify.zig`'s RFC 8446 §4.4.3 CertificateVerify
//! signature construction. Every vector fixes a key + a `Side` + a (fake, fixed
//! -- NOT a real DTLS handshake transcript) "transcript hash" byte string, so
//! the exact `buildSignedContent` output and the exact signature over it are
//! both pinned. See each section's comment for exact provenance -- this file
//! is deliberately honest about which vectors are externally cross-checked
//! (OpenSSL/`cryptography`) vs. self-generated-deterministic (reproducible by
//! rerunning std's own deterministic sign path, no external oracle involved).
//!
//! The RSA key below is the SAME 2048-bit key as `rsa/src/root.zig`'s private
//! `kat2048` test fixture (p/q/e/d transcribed byte-for-byte from there) --
//! reused rather than generating a fresh key, per the "use an existing repo
//! fixture" guidance. It is a fixture key with no relation to any real-world
//! certificate.

const std = @import("std");
const rsa = @import("rsa");

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// ── Ed25519, client side ─────────────────────────────────────────────────
//
// PROVENANCE: self-generated-deterministic (Ed25519 signing is fully
// deterministic per RFC 8032 -- no salt/nonce randomness involved) AND
// externally cross-checked: reproduced byte-for-byte with Python's
// `cryptography` package (`Ed25519PrivateKey.from_private_bytes(seed).sign
// (content)`, OpenSSL-backed) against the exact `content` bytes below. Seed
// and transcript hash are arbitrary fixed test constants, not derived from
// anything sensitive.

pub const ed25519_client = struct {
    pub const seed = hexLit("abababababababababababababababababababababababababababababababab");
    pub const secret_key_bytes = hexLit("abababababababababababababababababababababababababababababababab248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930");
    pub const public_key_bytes = hexLit("248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930");
    /// Fixed 32-byte (SHA-256-sized) stand-in transcript hash -- NOT a real
    /// handshake transcript, just a fixed repeated byte for KAT purposes.
    pub const transcript_hash = [_]u8{0x11} ** 32;
    /// Byte-exact expected `buildSignedContent(.client, transcript_hash, _)`
    /// output (64x0x20 || "TLS 1.3, client CertificateVerify" || 0x00 || transcript_hash).
    pub const content = hexLit("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c20636c69656e74204365727469666963617465566572696679001111111111111111111111111111111111111111111111111111111111111111");
    pub const signature = hexLit("8e20555b33037efbc6dd501a88e5cd74fd4af6215dc1ad1d8ce4066d474a4422704899ecf361a45ede31e2754d30cb47728c9e983a4c17c6a8eaa086173f7102");

    pub fn keyPair() !std.crypto.sign.Ed25519.KeyPair {
        return std.crypto.sign.Ed25519.KeyPair.fromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes(secret_key_bytes));
    }
};

// ── ECDSA P-256 / SHA-256, server side ───────────────────────────────────
//
// PROVENANCE: self-generated-deterministic ONLY -- std's ECDSA `sign(msg,
// null)` path is deterministic (a fixed-secret/fixed-noise-null HMAC-DRBG
// construction, RFC 6979-*flavored* but NOT literally RFC 6979: see
// `std.crypto.sign.ecdsa`'s `deterministicScalar`), and rerunning it against
// this exact key + content will always reproduce this exact signature (that
// determinism, not an external oracle, is what pins this vector). No
// external tool (OpenSSL et al. do not implement std's exact deterministic
// scheme) was used to cross-check the signature bytes themselves; the DER
// encode/decode round-trip WAS cross-checked against std's own
// `Signature.fromDer`/`.toDer` + `.verify` in the scratch generator. Fable
// filling in the crypto stubs can independently re-derive this exact vector
// by running the same construction against std 0.16.

pub const ecdsa_p256_server = struct {
    pub const seed = hexLit("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    pub const secret_key_bytes = hexLit("d79d97378a09572484464e950ab78ebe10da96a244da4bb6560f23965c888dc4");
    pub const public_key_uncompressed_sec1 = hexLit("04e2fe7dc6c2128508c062cf493820af31868868017cc26520a6cf9b26458c162026a8b2e0810feaa6a3e172e2ff06f2154f988441df7bcc3f671d9186328f7c1c");
    pub const transcript_hash = [_]u8{0x11} ** 32;
    pub const content = hexLit("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c20736572766572204365727469666963617465566572696679001111111111111111111111111111111111111111111111111111111111111111");
    /// Raw (r || s), 64 bytes.
    pub const signature_raw = hexLit("e889a650ef35d306f443ddf2018e4091d0896944aacd1bab1b860c0628ef5cc03942ce232acfc1aad9154bc6a493be9c69cd95ce066f1b75d911dec4ff224e57");
    /// ASN.1 DER encoding of the same (r, s) -- what RFC 8446 §4.3.2 actually
    /// puts on the wire for ECDSA signature schemes.
    pub const signature_der = hexLit("3045022100e889a650ef35d306f443ddf2018e4091d0896944aacd1bab1b860c0628ef5cc002203942ce232acfc1aad9154bc6a493be9c69cd95ce066f1b75d911dec4ff224e57");

    pub fn publicKey() !std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&public_key_uncompressed_sec1);
    }
    pub fn secretKey() !std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey {
        return std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(secret_key_bytes);
    }
};

// ── ECDSA P-384 / SHA-384, server side ───────────────────────────────────
//
// PROVENANCE: same as ecdsa_p256_server above -- self-generated-deterministic
// via std's own deterministic sign path, DER round-trip self-verified.

pub const ecdsa_p384_server = struct {
    pub const seed = hexLit("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef");
    pub const secret_key_bytes = hexLit("b72d5a467df0b2eb1d5de3778e015d8ce868d290e555d0096d3c76e51aa12732db763a7c14e5decc87d3dda29caf716a");
    pub const public_key_uncompressed_sec1 = hexLit("042df805cdc6f5d2e9094bc2432a413e975d18da91fe920bbee152e8950de9b0dfdd6b1517c5ea5463c937ffd5dd721ebee5e4356468174dca8d2ca5e5469644014a899731b8b8bb3e197bfbe4ec987f4944dc60671b4b381fc8d6a90272b50864");
    pub const transcript_hash = [_]u8{0x22} ** 48;
    pub const content = hexLit("20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c2073657276657220436572746966696361746556657269667900222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
    pub const signature_raw = hexLit("e626f16735e281b1f20157db23355fe4ca4cc1a055e72fd633b63b06860bb37c518ab56ab665fed02ba1d896480a58a61881487571d0b80127ee5aa842bad2bbedd5f962b8f1c4d816580a8f5ecf5675e5ab4a780fea592255d826fd6b0eac36");
    pub const signature_der = hexLit("3065023100e626f16735e281b1f20157db23355fe4ca4cc1a055e72fd633b63b06860bb37c518ab56ab665fed02ba1d896480a58a602301881487571d0b80127ee5aa842bad2bbedd5f962b8f1c4d816580a8f5ecf5675e5ab4a780fea592255d826fd6b0eac36");

    pub fn publicKey() !std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey {
        return std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(&public_key_uncompressed_sec1);
    }
    pub fn secretKey() !std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey {
        return std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(secret_key_bytes);
    }
};

// ── RSA-PSS / SHA-256, server side ───────────────────────────────────────
//
// PROVENANCE: EXTERNAL, verify-only. The key (p, q, e, d) is transcribed
// byte-for-byte from `rsa/src/root.zig`'s private `kat2048` test fixture (a
// fixed 2048-bit key used nowhere outside this repo's own tests). The
// signature was produced by Python's `cryptography` package (OpenSSL 3.5.5
// under the hood) via `sk.sign(content, padding.PSS(mgf=padding.MGF1
// (SHA256()), salt_length=32), SHA256())` over the EXACT `content` bytes
// below, then independently re-verified with `cryptography`'s own `.verify`
// before being embedded here. RSA-PSS with salt_len > 0 is randomized, so
// this is a verify-only KAT (byte-exact-passes + tamper-fails); a
// sign-side KAT is not possible without fixing the salt (RFC 8446 §4.2.3
// mandates salt_len == Hash.digest_length, so unlike RFC 8017 there is no
// salt_len=0 deterministic option to fall back on for a TLS-conformant
// sign-side vector) -- `sign`'s correctness for this scheme is instead
// covered by a sign->verify round-trip test with a fresh random salt.

pub const rsa_pss_sha256_server = struct {
    pub const p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
    pub const q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
    pub const e = [_]u8{ 0x01, 0x00, 0x01 };
    pub const n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");
    pub const d = hexLit("181979e1323002643a37780f3b7ea647738fedbceb42eb96ecdcc875bcb872ad99ae86972acf22211df55dcc028be59fa988a398890934bbf8c2e1ef027216d2a83f1fc734fee62bfad02e086242f49d8b3f11693caf99ca1161a4a9423070c4722d8ecbe50eba6ce1a190afecf233b66668dc2f5d98d38eb2562108ec5987ae02819c97d0a2f60afa32d471766acdb8358b9a61cd8d4d4e1cd98aaa1193217558fb466be20ea48eda646929332e19c887f78ba423d573d44d05e74ce9757c79a59fb0377cace9e65f915b93dcc5b95fdc9cf026ab0ae69b48beed0e0238266b250ed55aa4e4bbf19ac8076a96a16e86b04058e565af55d8fc82726668d3062d");

    /// Same 32-byte transcript hash as `ecdsa_p256_server` (independent
    /// schemes may sign the same transcript in a real handshake -- reusing
    /// it here just keeps the fixture set smaller).
    pub const transcript_hash = ecdsa_p256_server.transcript_hash;
    pub const content = ecdsa_p256_server.content;
    pub const salt_len = 32; // Hash.digest_length for SHA-256, per RFC 8446 §4.2.3.
    pub const signature = hexLit("2a1d24af4161f2c5599c928928651f4b70a6194e50cc0bf837d5b5d855c20ce78371360866baa2c41d8cd90b0a2eb72e9c1ae5a08c0e306ec9f02c882798115c9e1fc7dfe8ebf0a77a5dd97a764a6d0bd13233928572117e0b0ca5d3b78fa5aa41fc2edd41231904b304a0bb70e34457cb7f4a61bd47701c8fc363b131abee4ec230abfcf5f80c864026330a98d16ad22a9e929cabeda659239875777dbcb2b44b1831a5ebd5456d96cbfaa661370798af424afd5c1273e812203b4f7293524e19e5f095b5da4a147be918b2fbc9c46d894dbdca11d5a524669357f75c34e5647e21d3a7a3ce8ee6a36d70e6ccb4d8d0eab9f9deeae1496512bd98b3be17ec28");

    pub fn secretKey() !rsa.SecretKey {
        return rsa.SecretKey.fromPrimes(&p, &q, &e);
    }
    pub fn publicKey() !rsa.PublicKey {
        return rsa.PublicKey.fromBytes(&n, &e);
    }
};
