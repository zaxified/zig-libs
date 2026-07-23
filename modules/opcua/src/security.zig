// SPDX-License-Identifier: MIT

//! SecureChannel security layer — SecurityMode Sign / SignAndEncrypt,
//! SecurityPolicy#Basic256Sha256 (OPC 10000-6 §6.7, OPC 10000-7 security
//! profiles). Clean-room from the spec, byte-level behavior ground-truthed
//! against open62541 (`ua_securechannel.c`: `padChunk`/`signAndEncryptAsym`/
//! `signAndEncryptSym` + the mbedtls/openssl Basic256Sha256 policy plugins).
//!
//! Basic256Sha256's primitive table (OPC 10000-7 §6.4.5):
//!   - asymmetric encryption (OPN body): RSA-OAEP / SHA-1, per-RSA-block
//!     (`rsa.encryptOaep`/`rsa.decryptOaep` from the `rsa` module)
//!   - asymmetric signature (OPN message): RSA-PKCS1v1.5 / SHA-256
//!     (`rsa.signPkcs1v15`/`rsa.verifyPkcs1v15`)
//!   - certificate signature algorithm: RSA-PKCS1v1.5 / SHA-256
//!   - key derivation: P-SHA256 (the TLS-1.2-style HMAC-SHA256 P_hash,
//!     without TLS's label) applied to the client/server nonce pair, per
//!     OPC 10000-6 §6.7.5 (`pSha256`/`deriveKeys`)
//!   - symmetric encryption (MSG/CLO chunks): AES-256-CBC — hand-built here
//!     over `std.crypto.core.aes.Aes256`'s raw block cipher (std ships no
//!     CBC mode; see `aes256CbcEncrypt`), with the *fixed* per-direction IV
//!     from the key derivation reused for every chunk (open62541 copies the
//!     KDF IV fresh before each CBC call — no chaining across chunks)
//!   - symmetric signature (MSG/CLO chunks): HMAC-SHA256
//!
//! Wire framing facts this file encodes (OPC 10000-6 §6.7.2-§6.7.6,
//! matching open62541 exactly):
//!   - **Sign-then-encrypt.** The signature is computed over the *plaintext*
//!     message from byte 0 of the 8-byte MessageHeader — whose MessageSize
//!     field already holds the FINAL post-encryption size — through the end
//!     of the padding; the signature is appended and then the
//!     SequenceHeader..signature region is encrypted.
//!   - **Encrypted region.** OPN: everything after MessageHeader (8) +
//!     SecureChannelId (4) + AsymmetricAlgorithmSecurityHeader. MSG/CLO:
//!     everything after MessageHeader (8) + SecureChannelId (4) +
//!     TokenId (4) = byte 16.
//!   - **Padding footer** (only when encrypting): one PaddingSize byte
//!     followed by PaddingSize padding bytes, every byte equal to
//!     PaddingSize's low byte, sized so plaintext-region + signature fills
//!     whole cipher blocks; a trailing ExtraPaddingSize (high) byte iff the
//!     *encryption* key is longer than 2048 bits (never for AES). Computed
//!     as open62541's `padChunk`: `lastBlock = (bytesToWrite + sigSize +
//!     padOverhead) % plainBlockSize; padding = lastBlock != 0 ?
//!     plainBlockSize - lastBlock : 0`.
//!   - **OPN is always signed AND encrypted** when SecurityMode != None —
//!     even at SecurityMode=Sign (OPC 10000-6 §6.7.4; open62541: "OPN is
//!     always encrypted even if the mode is sign only"). Only MSG/CLO
//!     chunks distinguish Sign (signature only, no padding, no encryption)
//!     from SignAndEncrypt.
//!
//! `SecurityMode = .none` keeps its pre-crypto behavior byte-for-byte:
//! `services.Channel`'s hook points only call into this file when
//! `channel.security != null` and `.mode != .none`.
//!
//! `Aes256_Sha256_RsaPss` (OPC 10000-7 §6.4.6) remains reserved as an enum
//! value + `uri()` only (asym encrypt = RSA-OAEP-SHA256, asym sign =
//! RSA-PSS-SHA256) — no crypto wiring.
//!
//! **Both roles use this file.** Nothing in it is client-specific: a client
//! seals with `.client_to_server` and opens with `.server_to_client`, a
//! server does the reverse, and `sealAsymmetricMessage`/
//! `openAsymmetricMessage` take *whose* key pair and *whose* peer
//! certificate as explicit parameters. `server.zig` drives exactly these
//! functions for the server half of Basic256Sha256 — the server side added
//! no crypto of its own, only the state machine around it (see SPEC.md).

const std = @import("std");
const rsa = @import("rsa");
const x509 = @import("x509");
const encoding = @import("encoding.zig");
const services = @import("services.zig");

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes256 = std.crypto.core.aes.Aes256;

pub const meta = .{
    .platform = .any, // pure computation + RSA (no I/O of its own)
    .role = .util,
    .concurrency = .reentrant, // no shared/global state
    .model_after = "OPC 10000-6 §6.7 SecureChannel + OPC 10000-7 security profiles (Basic256Sha256); RSA primitives from the `rsa` module",
    .deps = .{"rsa"},
};

// ── SecurityPolicy (OPC 10000-7) ─────────────────────────────────────────────

pub const SecurityPolicy = enum {
    none,
    basic256sha256,
    /// Reserved: enum value + `uri()` only (asym encrypt = RSA-OAEP-SHA256,
    /// asym sign = RSA-PSS-SHA256) — no `SecurityLengths`, no crypto wiring.
    aes256_sha256_rsapss,

    /// The real OPC Foundation SecurityPolicy URI (OPC 10000-7 §6.1/§6.4).
    pub fn uri(self: SecurityPolicy) []const u8 {
        return switch (self) {
            .none => "http://opcfoundation.org/UA/SecurityPolicy#None",
            .basic256sha256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            .aes256_sha256_rsapss => "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
        };
    }
};

/// Basic256Sha256's *asymmetric signature* algorithm URI — the value that
/// goes into a `SignatureData.Algorithm` field (`CreateSessionResponse.
/// ServerSignature`, `ActivateSessionRequest.ClientSignature`), OPC 10000-7
/// §6.4.5 "AsymmetricSignatureAlgorithm". RSA-SHA256 lives in the
/// *xmldsig-more* namespace; the older `…2000/09/xmldsig#rsa-sha1` namespace
/// only ever defined SHA-1 (see `signature_algorithm_rsa_sha256_legacy`).
pub const signature_algorithm_rsa_sha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// The `…2000/09/xmldsig#rsa-sha256` spelling some stacks emit. Not what
/// OPC 10000-7 says, but accepted on receipt (never sent) — refusing a
/// signature that verifies perfectly over a namespace typo helps nobody.
pub const signature_algorithm_rsa_sha256_legacy = "http://www.w3.org/2000/09/xmldsig#rsa-sha256";

/// Basic256Sha256's *asymmetric encryption* algorithm URI — the value that
/// goes into `UserNameIdentityToken.EncryptionAlgorithm` when the password
/// is encrypted to the server certificate (OPC 10000-4 §7.36.4,
/// OPC 10000-7 §6.4.5 "AsymmetricEncryptionAlgorithm": RSA-OAEP/SHA-1).
pub const encryption_algorithm_rsa_oaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";

/// Per-`SecurityPolicy` algorithm/length constants. Values below are for a
/// 2048-bit (256-byte) RSA key — the conventional size open62541/node-opcua
/// default an application certificate to for this profile. The functions in
/// this file do NOT hardcode these: every asymmetric length is recomputed
/// from the actual certificate's modulus, so other RSA key sizes work; this
/// table documents the profile's canonical shape (and feeds the tests).
pub const SecurityLengths = struct {
    /// RSA-OAEP-SHA1 max plaintext per asymmetrically-encrypted block:
    /// k - 2*hLen - 2 (RFC 8017 §7.1.1 step 1.b), k = 256 (2048-bit
    /// modulus), hLen = 20 (SHA-1 digest length) => 256 - 40 - 2 = 214.
    asymmetric_max_plaintext_len: usize,
    /// RSA signature/ciphertext length = k, the modulus length in bytes
    /// (256 for a 2048-bit key).
    asymmetric_signature_len: usize,
    /// AES-256 key length (both the signing-key and encrypting-key halves
    /// P-SHA256 derives are this long — OPC 10000-7 §6.4.5
    /// "DerivedEncryptionKeyLength").
    symmetric_key_len: usize = 32,
    /// AES block size in bytes — also the CBC IV length (one block).
    symmetric_block_len: usize = 16,
    /// HMAC-SHA256 output length — the symmetric (MSG/CLO chunk) signature
    /// length.
    symmetric_signature_len: usize = 32,
    /// Client/server nonce length (OPC 10000-6 §5.5.2.2 note: "the length
    /// of the nonce has to match the KeyLength" of the SecureChannel's
    /// SecurityPolicy's symmetric encryption algorithm — 32 bytes for the
    /// Sha256-keyed profiles).
    nonce_len: usize = 32,

    /// Basic256Sha256 (OPC 10000-7 §6.4.5), 2048-bit RSA.
    pub const basic256sha256: SecurityLengths = .{
        .asymmetric_max_plaintext_len = 256 - 2 * 20 - 2, // = 214
        .asymmetric_signature_len = 256,
    };
};

/// The length table for `policy`, or `null` for `.none` (no security, no
/// lengths to speak of) and `.aes256_sha256_rsapss` (reserved — see the
/// module doc comment; that policy has no `SecurityLengths` yet).
pub fn lengths(policy: SecurityPolicy) ?SecurityLengths {
    return switch (policy) {
        .none, .aes256_sha256_rsapss => null,
        .basic256sha256 => SecurityLengths.basic256sha256,
    };
}

/// RSA-OAEP/SHA-1 overhead per encrypted block: 2*hLen + 2 (RFC 8017
/// §7.1.1), hLen = 20.
const oaep_sha1_overhead: usize = 2 * Sha1.digest_length + 2; // = 42

/// HMAC-SHA256 output length — the symmetric chunk signature.
const sym_signature_len: usize = HmacSha256.mac_length; // = 32

/// AES block size — also the CBC IV size and the symmetric padding modulus.
const aes_block_len: usize = 16;

/// Modulus length in whole bytes for an `rsa` key with `bit_count` bits.
fn modulusByteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

// ── SecurityMode ──────────────────────────────────────────────────────────
// `MessageSecurityMode` (OPC 10000-4 §7.34) already exists in services.zig
// with the exact wire-correct values this task calls for (none=1, sign=2,
// sign_and_encrypt=3, plus invalid=0) — re-exported rather than duplicated
// (services.zig already imports this file back for `Channel.security`'s
// type, a harmless sibling-file import cycle; see CONVENTIONS.md — Zig
// resolves it fine since neither side needs the other at comptime-eval
// time, only at type-reference time).
pub const SecurityMode = services.MessageSecurityMode;

// ── ClientCredentials ─────────────────────────────────────────────────────

/// This client's own key pair + self-signed application certificate — sent
/// as `AsymmetricAlgorithmSecurityHeader.SenderCertificate` and used to
/// asymmetrically sign OPN messages when SecurityMode != None.
pub const ClientCredentials = struct {
    /// DER-encoded X.509 v3 certificate (`rsa.selfSignedCert`'s output).
    certificate_der: []const u8,
    private_key: rsa.SecretKey,
    public_key: rsa.PublicKey,

    pub const GenerateSelfSignedOptions = struct {
        /// RSA modulus size in bits. 2048 (the default) is the conventional
        /// application-certificate size for Basic256Sha256 (what
        /// `SecurityLengths.basic256sha256` documents); other sizes work —
        /// all asymmetric lengths are computed from the actual modulus.
        modulus_bits: usize = 2048,
        public_exponent: u64 = 65537,
        /// Certificate `commonName` (`rsa.CertOptions.common_name`).
        common_name: []const u8,
        /// `notBefore`, UTCTime `"YYMMDDHHMMSSZ"` (`rsa.CertOptions.not_before`).
        not_before: []const u8,
        /// `notAfter`, same shape as `not_before`.
        not_after: []const u8,
        /// OPC UA `ApplicationUri`, carried as a `subjectAltName` URI entry
        /// (OPC 10000-6 §6.2.3: the application certificate's SAN must
        /// contain the client's ApplicationUri). `null` omits the SAN
        /// extension entirely.
        application_uri: ?[]const u8 = null,
    };

    pub const GenerateSelfSignedError = rsa.GenerateError || rsa.SelfSignedCertError;

    /// Generate a fresh RSA key pair (`rsa.generate`) and wrap it in a
    /// self-signed X.509 v3 certificate (`rsa.selfSignedCert`, signed
    /// RSASSA-PKCS1-v1_5/SHA-256 per Basic256Sha256's certificate-signature
    /// algorithm). `random` MUST be a cryptographically secure generator
    /// for real use (see `rsa.generate`'s doc comment) — a seeded
    /// deterministic generator is acceptable only for tests. Returned
    /// `certificate_der` is `allocator`-owned; free with `deinit`.
    pub fn generateSelfSigned(
        allocator: std.mem.Allocator,
        random: std.Random,
        options: GenerateSelfSignedOptions,
    ) GenerateSelfSignedError!ClientCredentials {
        const kp = try rsa.generate(random, options.modulus_bits, options.public_exponent);

        var san_buf: [1]rsa.SubjectAltName = undefined;
        const sans: []const rsa.SubjectAltName = if (options.application_uri) |app_uri| blk: {
            san_buf[0] = .{ .uri = app_uri };
            break :blk san_buf[0..1];
        } else &.{};

        const certificate_der = try rsa.selfSignedCert(allocator, kp.secret_key, kp.public_key, std.crypto.hash.sha2.Sha256, .{
            .common_name = options.common_name,
            .not_before = options.not_before,
            .not_after = options.not_after,
            .subject_alt_names = sans,
        });

        return .{
            .certificate_der = certificate_der,
            .private_key = kp.secret_key,
            .public_key = kp.public_key,
        };
    }

    /// Frees `certificate_der` (the only heap-owned field — `private_key`/
    /// `public_key` are plain value types, same as everywhere else in the
    /// `rsa` module).
    pub fn deinit(self: ClientCredentials, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_der);
    }
};

/// Constant-time byte-slice equality for **runtime** lengths, built on
/// `std.crypto.timing_safe.compare` (std's `timing_safe.eql` needs a
/// comptime-known array type, which a wire-length nonce, thumbprint,
/// password or signature is not). The *length* comparison short-circuits and
/// is therefore leaked — a length is not the secret here, the contents are.
/// Every secret-dependent comparison in this module and in `server.zig` goes
/// through this function or through `timing_safe.eql` directly; there is no
/// `std.mem.eql` on a secret anywhere in the security path.
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return std.crypto.timing_safe.compare(u8, a, b, .big) == .eq;
}

/// An application's own key pair + certificate, whichever end of the wire it
/// sits on. `ClientCredentials` is the original (client-side) name; the
/// server half of this module holds exactly the same three fields, so this
/// alias exists to let `server.zig` say what it means without a second type.
pub const Credentials = ClientCredentials;

// ── Certificate helpers ───────────────────────────────────────────────────

/// SHA-1 thumbprint of a DER certificate — the value the OPN request's
/// `AsymmetricAlgorithmSecurityHeader.ReceiverCertificateThumbprint` carries
/// (OPC 10000-6 §6.7.2.3).
pub fn certificateThumbprint(certificate_der: []const u8) [Sha1.digest_length]u8 {
    var out: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(certificate_der, &out, .{});
    return out;
}

pub const CertificatePublicKeyError = error{InvalidCertificate};

/// Largest certificate the two parsing helpers below will look at. A 2048-bit
/// OPC UA application certificate is ~900 bytes and a 4096-bit one ~1.6 kB, so
/// this is generous; the point of a bound at all is that the parse runs in a
/// fixed-size scratch buffer. Aliased to the shared `x509.safe` bound this
/// module now routes through (kept public for source compatibility).
pub const max_parsed_certificate_len: usize = x509.safe.max_certificate_len;

/// Zero bytes appended behind the certificate in the scratch buffer.
const der_parse_slack: usize = x509.safe.parse_slack;

/// Validate `certificate_der` and return a `std.crypto.Certificate` over a
/// zero-padded copy of it in `scratch`, safe to hand to std's parser.
///
/// The guard itself — a recursive DER well-formedness walk plus the zero
/// padding that absorbs std's boundary probes — is the shared `x509.safe`
/// helper now; `std.crypto.Certificate`'s unchecked DER reader panics / reads
/// out of bounds on a hostile, attacker-supplied `SenderCertificate`, and this
/// was one of three modules that grew its own guard against it. See
/// `x509/src/safe.zig` and this module's `SPEC.md`.
fn safeCertificate(certificate_der: []const u8, scratch: []u8) CertificatePublicKeyError!std.crypto.Certificate {
    return x509.safe.safeCertificate(certificate_der, scratch) catch return error.InvalidCertificate;
}

/// Extract the RSA public key from a DER X.509 certificate — std's
/// independent `std.crypto.Certificate` parser locates the
/// `SubjectPublicKeyInfo`, the `rsa` module parses the `RSAPublicKey` inside.
/// Total on arbitrary bytes (see `safeCertificate`): a malformed certificate
/// is `error.InvalidCertificate`, never a panic.
pub fn certificatePublicKey(certificate_der: []const u8) CertificatePublicKeyError!rsa.PublicKey {
    var scratch: [max_parsed_certificate_len + der_parse_slack]u8 = undefined;
    const cert = try safeCertificate(certificate_der, &scratch);
    const parsed = cert.parse() catch return error.InvalidCertificate;
    if (parsed.pub_key_algo != .rsaEncryption) return error.InvalidCertificate;
    return rsa.PublicKey.fromDer(parsed.pubKey()) catch error.InvalidCertificate;
}

/// A DER certificate's `notBefore`/`notAfter`, in Unix seconds.
pub const CertificateValidity = struct {
    not_before_sec: i64,
    not_after_sec: i64,

    /// RFC 5280 §6.1.3 (a)(2) / OPC 10000-4 Table "BadCertificateTimeInvalid":
    /// is `now_sec` inside the certificate's validity period?
    pub fn covers(self: CertificateValidity, now_sec: i64) bool {
        return now_sec >= self.not_before_sec and now_sec <= self.not_after_sec;
    }
};

/// Parse a DER certificate's validity period (std's independent X.509
/// parser does the ASN.1). *Only* the time window — chain building and the
/// trust decision are deliberately not here: an OPC UA server's trust list
/// is a deployment artifact, so `server.zig` takes the accept/reject verdict
/// from a caller-supplied policy callback instead of inventing a trust store
/// (see `server.CertificatePolicy`).
pub fn certificateValidity(certificate_der: []const u8) CertificatePublicKeyError!CertificateValidity {
    var scratch: [max_parsed_certificate_len + der_parse_slack]u8 = undefined;
    const cert = try safeCertificate(certificate_der, &scratch);
    const parsed = cert.parse() catch return error.InvalidCertificate;
    return .{
        .not_before_sec = @intCast(parsed.validity.not_before),
        .not_after_sec = @intCast(parsed.validity.not_after),
    };
}

// ── ChannelKeys ───────────────────────────────────────────────────────────

/// The six symmetric keys/IVs `deriveKeys` (P-SHA256) produces from the
/// client/server nonce pair — one signing key + one encrypting key + one IV
/// per direction (OPC 10000-6 §6.7.5), sized for Basic256Sha256 (AES-256 =
/// 32-byte keys, AES block = 16-byte IV).
pub const ChannelKeys = struct {
    client_signing_key: [32]u8,
    client_encrypting_key: [32]u8,
    client_iv: [16]u8,
    server_signing_key: [32]u8,
    server_encrypting_key: [32]u8,
    server_iv: [16]u8,

    /// Zero all key material (`std.crypto.secureZero`) — call when the
    /// channel closes; the keys are as secret as the nonces they came from.
    pub fn wipe(self: *ChannelKeys) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Which peer *produced* (signed + encrypted) a symmetric chunk. A client
/// sends with `keys.client_*` and verifies/decrypts received chunks with
/// `keys.server_*`; a server (or a test playing one) does the reverse.
pub const Direction = enum { client_to_server, server_to_client };

const DirectionKeys = struct {
    signing_key: *const [32]u8,
    encrypting_key: *const [32]u8,
    iv: *const [16]u8,
};

fn directionKeys(keys: *const ChannelKeys, direction: Direction) DirectionKeys {
    return switch (direction) {
        .client_to_server => .{
            .signing_key = &keys.client_signing_key,
            .encrypting_key = &keys.client_encrypting_key,
            .iv = &keys.client_iv,
        },
        .server_to_client => .{
            .signing_key = &keys.server_signing_key,
            .encrypting_key = &keys.server_encrypting_key,
            .iv = &keys.server_iv,
        },
    };
}

// ── SecurityContext ───────────────────────────────────────────────────────

/// Bundles everything a `services.Channel`/`root.SecureChannel` needs to
/// know about the security this channel was opened with. `null` (the
/// default everywhere this is stored) means "SecurityMode=None", the
/// existing F2 behavior. Also doubles as `SecureChannel.OpenOptions.
/// security`'s type (`keys` is unset/`null` at open time; `SecureChannel.
/// open` populates it from the OPN nonce exchange via `deriveKeys`).
pub const SecurityContext = struct {
    policy: SecurityPolicy,
    mode: SecurityMode,
    /// This client's key pair + certificate. Required once `mode != .none`.
    credentials: ?ClientCredentials = null,
    /// The server's DER certificate, pinned out-of-band by the caller ahead
    /// of time (fetch it via a SecurityMode=None GetEndpoints/CreateSession
    /// exchange, or from the server's PKI directory). Required once
    /// `mode != .none`: the client both encrypts the OPN request to this
    /// certificate's public key and verifies the OPN response's signature
    /// against it.
    server_certificate: ?[]const u8 = null,
    /// Cryptographically secure random source — OAEP seeds + the client
    /// nonce. Required once `mode != .none`.
    random: ?std.Random = null,
    /// Populated by `SecureChannel.open` (via `deriveKeys`) once the OPN
    /// client/server nonce exchange has happened; `null` until then.
    keys: ?ChannelKeys = null,
};

// ── Asymmetric (OPN) crypto primitives ───────────────────────────────────

pub const AsymmetricEncryptError = std.mem.Allocator.Error || rsa.EncryptOaepError;

/// RSA-OAEP/SHA-1 encrypt `plaintext` under the receiver's public key (the
/// OPN body's asymmetric-encryption algorithm, Basic256Sha256), splitting
/// into per-RSA-block chunks of at most k - 42 bytes (k = modulus length;
/// 214 for a 2048-bit key), each encrypted to one k-byte cipher block.
/// `random` seeds OAEP and MUST be cryptographically secure. Returned
/// ciphertext is `allocator`-owned.
pub fn asymmetricEncrypt(allocator: std.mem.Allocator, plaintext: []const u8, receiver_public_key: rsa.PublicKey, random: std.Random) AsymmetricEncryptError![]u8 {
    const k = modulusByteLen(receiver_public_key.n.bits());
    if (k <= oaep_sha1_overhead) return error.MessageTooLong;
    const plain_block = k - oaep_sha1_overhead;
    const blocks = std.math.divCeil(usize, plaintext.len, plain_block) catch unreachable;
    const out = try allocator.alloc(u8, blocks * k);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < blocks) : (i += 1) {
        const chunk = plaintext[i * plain_block .. @min((i + 1) * plain_block, plaintext.len)];
        _ = try rsa.encryptOaep(receiver_public_key, Sha1, random, chunk, "", out[i * k ..][0..k]);
    }
    return out;
}

pub const AsymmetricDecryptError = std.mem.Allocator.Error || rsa.DecryptOaepError;

/// RSA-OAEP/SHA-1 decrypt `ciphertext` (a whole number of k-byte RSA blocks)
/// with this client's private key (the OPN response body's asymmetric-
/// decryption algorithm, Basic256Sha256). Returned plaintext is
/// `allocator`-owned.
pub fn asymmetricDecrypt(allocator: std.mem.Allocator, ciphertext: []const u8, private_key: rsa.SecretKey) AsymmetricDecryptError![]u8 {
    const k = modulusByteLen(private_key.n.bits());
    if (k <= oaep_sha1_overhead) return error.DecryptionError;
    if (ciphertext.len == 0 or ciphertext.len % k != 0) return error.DecryptionError;
    const plain_block = k - oaep_sha1_overhead;
    const blocks = ciphertext.len / k;
    const out = try allocator.alloc(u8, blocks * plain_block);
    errdefer {
        std.crypto.secureZero(u8, out);
        allocator.free(out);
    }
    var len: usize = 0;
    var i: usize = 0;
    while (i < blocks) : (i += 1) {
        const m = rsa.decryptOaep(private_key, Sha1, ciphertext[i * k ..][0..k], "", out[len..][0..plain_block]) catch |err| switch (err) {
            error.BufferTooSmall => unreachable, // out chunk is exactly the max message length
            error.DecryptionError => return error.DecryptionError,
        };
        len += m.len;
    }
    if (allocator.resize(out, len)) return out[0..len];
    const shrunk = try allocator.dupe(u8, out[0..len]);
    std.crypto.secureZero(u8, out);
    allocator.free(out);
    return shrunk;
}

pub const AsymmetricSignError = std.mem.Allocator.Error || rsa.SignPkcs1v15Error;

/// RSA-PKCS1v1.5/SHA-256 sign `message` (the whole assembled plaintext OPN
/// message) with this client's private key (Basic256Sha256's asymmetric-
/// signature algorithm). Returned signature (modulus-length) is
/// `allocator`-owned.
pub fn asymmetricSign(allocator: std.mem.Allocator, message: []const u8, private_key: rsa.SecretKey) AsymmetricSignError![]u8 {
    const k = modulusByteLen(private_key.n.bits());
    const out = try allocator.alloc(u8, k);
    errdefer allocator.free(out);
    _ = try rsa.signPkcs1v15(private_key, Sha256, message, out);
    return out;
}

/// Verify an RSA-PKCS1v1.5/SHA-256 signature over `message` against the
/// peer's public key (the OPN response's asymmetric signature). Follows
/// `rsa.verifyPkcs1v15`'s `!void` convention (an error return means "did not
/// verify", not a different failure mode) rather than `!bool`.
pub fn asymmetricVerify(message: []const u8, signature: []const u8, public_key: rsa.PublicKey) rsa.VerifyPkcs1v15Error!void {
    return rsa.verifyPkcs1v15(public_key, Sha256, message, signature);
}

// ── Key derivation: P-SHA256 (OPC 10000-6 §6.7.5) ────────────────────────

/// The TLS-1.2-style P_hash PRF with HMAC-SHA256 (RFC 5246 §5, minus TLS's
/// label — OPC UA feeds the seed directly):
///   A(0) = seed; A(i) = HMAC(secret, A(i-1))
///   output = HMAC(secret, A(1) ‖ seed) ‖ HMAC(secret, A(2) ‖ seed) ‖ …
/// truncated to `out.len`.
pub fn pSha256(secret: []const u8, seed: []const u8, out: []u8) void {
    var a: [HmacSha256.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &a);
    HmacSha256.create(&a, seed, secret); // A(1)
    var off: usize = 0;
    while (off < out.len) {
        var chunk: [HmacSha256.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &chunk);
        var ctx = HmacSha256.init(secret);
        ctx.update(&a);
        ctx.update(seed);
        ctx.final(&chunk);
        const n = @min(chunk.len, out.len - off);
        @memcpy(out[off..][0..n], chunk[0..n]);
        off += n;
        HmacSha256.create(&a, &a, secret); // A(i+1)
    }
}

/// P-SHA256 key derivation from the OPN nonce exchange (OPC 10000-6 §6.7.5):
/// the client's signing/encrypting keys + IV come from P_SHA256(secret =
/// serverNonce, seed = clientNonce), the server's from P_SHA256(secret =
/// clientNonce, seed = serverNonce); each 80-byte output splits as
/// signingKey(32) ‖ encryptingKey(32) ‖ initializationVector(16),
/// Basic256Sha256's DerivedSignatureKeyLength/key/block sizes. Pure
/// bytes-in-bytes-out — no allocation, no error. The caller should `wipe`
/// the returned keys when the channel dies.
pub fn deriveKeys(client_nonce: []const u8, server_nonce: []const u8, policy: SecurityPolicy) ChannelKeys {
    std.debug.assert(policy == .basic256sha256); // the only implemented policy
    var keys: ChannelKeys = undefined;
    var block: [32 + 32 + 16]u8 = undefined;
    defer std.crypto.secureZero(u8, &block);

    pSha256(server_nonce, client_nonce, &block);
    keys.client_signing_key = block[0..32].*;
    keys.client_encrypting_key = block[32..64].*;
    keys.client_iv = block[64..80].*;

    pSha256(client_nonce, server_nonce, &block);
    keys.server_signing_key = block[0..32].*;
    keys.server_encrypting_key = block[32..64].*;
    keys.server_iv = block[64..80].*;

    return keys;
}

// ── AES-256-CBC (hand-built over std's raw block cipher) ─────────────────
// std.crypto ships only the raw AES block cipher + AEAD modes — no CBC.
// Plain CBC per NIST SP 800-38A §6.2: C(i) = E(P(i) ^ C(i-1)), C(0) = IV.

/// In-place AES-256-CBC encryption. `data.len` must be a multiple of 16
/// (the caller pads — OPC UA's padding footer, not PKCS#7).
pub fn aes256CbcEncrypt(key: *const [32]u8, iv: *const [16]u8, data: []u8) void {
    std.debug.assert(data.len % aes_block_len == 0);
    const ctx = Aes256.initEnc(key.*);
    var prev: [aes_block_len]u8 = iv.*;
    var i: usize = 0;
    while (i < data.len) : (i += aes_block_len) {
        const block = data[i..][0..aes_block_len];
        for (block, &prev) |*b, p| b.* ^= p;
        ctx.encrypt(block, block);
        prev = block.*;
    }
}

/// In-place AES-256-CBC decryption (mirror of `aes256CbcEncrypt`).
pub fn aes256CbcDecrypt(key: *const [32]u8, iv: *const [16]u8, data: []u8) void {
    std.debug.assert(data.len % aes_block_len == 0);
    const ctx = Aes256.initDec(key.*);
    var prev: [aes_block_len]u8 = iv.*;
    var i: usize = 0;
    while (i < data.len) : (i += aes_block_len) {
        const block = data[i..][0..aes_block_len];
        const cipher: [aes_block_len]u8 = block.*;
        ctx.decrypt(block, block);
        for (block, &prev) |*b, p| b.* ^= p;
        prev = cipher;
    }
}

// ── Symmetric (MSG/CLO) chunk seal/open ──────────────────────────────────

pub const SymmetricSignAndEncryptError = std.mem.Allocator.Error;

/// Seal one outgoing MSG/CLO chunk: build the final wire message —
/// MessageHeader(8, with the final MessageSize) + `unsecured_body`
/// (SecureChannelId + TokenId + SequenceHeader + payload) + padding footer
/// (SignAndEncrypt only) + HMAC-SHA256 signature — sign-then-encrypt per
/// OPC 10000-6 §6.7.2 (see the module doc comment for the exact ranges).
/// `direction` picks whose keys sign/encrypt (`.client_to_server` for a
/// client sending). Returns the complete `allocator`-owned wire bytes,
/// ready to write to the socket verbatim.
pub fn symmetricSignAndEncrypt(
    allocator: std.mem.Allocator,
    msg_code: *const [3]u8,
    unsecured_body: []const u8,
    mode: SecurityMode,
    keys: ChannelKeys,
    direction: Direction,
) SymmetricSignAndEncryptError![]u8 {
    return symmetricSealChunk(allocator, msg_code, 'F', unsecured_body, mode, keys, direction);
}

/// `symmetricSignAndEncrypt` with an explicit chunk-type byte — `'F'` final,
/// `'C'` intermediate, `'A'` abort (OPC 10000-6 §7.1.1). A *chunked* secure
/// response secures each chunk on its own (the signature covers that chunk's
/// own MessageHeader, chunk byte included), which is why the server's
/// multi-chunk path cannot go through the `'F'`-only wrapper above.
pub fn symmetricSealChunk(
    allocator: std.mem.Allocator,
    msg_code: *const [3]u8,
    chunk_byte: u8,
    unsecured_body: []const u8,
    mode: SecurityMode,
    keys: ChannelKeys,
    direction: Direction,
) SymmetricSignAndEncryptError![]u8 {
    std.debug.assert(mode == .sign or mode == .sign_and_encrypt);
    std.debug.assert(unsecured_body.len >= 16); // ChannelId + TokenId + SequenceHeader
    const dk = directionKeys(&keys, direction);

    // Padding footer only when encrypting; sized so the encrypted region
    // (SequenceHeader.. = everything after body offset 8, message offset 16)
    // fills whole AES blocks.
    const pad_footprint: usize = if (mode == .sign_and_encrypt) blk: {
        const bytes_to_encrypt = unsecured_body.len - 8; // SequenceHeader + payload
        const last_block = (bytes_to_encrypt + sym_signature_len + 1) % aes_block_len;
        const padding: usize = if (last_block != 0) aes_block_len - last_block else 0;
        break :blk padding + 1; // + the PaddingSize byte itself
    } else 0;

    const total = 8 + unsecured_body.len + pad_footprint + sym_signature_len;
    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    buf[0..3].* = msg_code.*;
    buf[3] = chunk_byte;
    std.mem.writeInt(u32, buf[4..8], @intCast(total), .little);
    @memcpy(buf[8..][0..unsecured_body.len], unsecured_body);
    if (pad_footprint > 0) {
        @memset(buf[8 + unsecured_body.len ..][0..pad_footprint], @intCast(pad_footprint - 1));
    }

    // Sign the whole plaintext message (final header included), then
    // encrypt SequenceHeader..signature (message offset 16) in place.
    const sig_start = total - sym_signature_len;
    HmacSha256.create(buf[sig_start..][0..sym_signature_len], buf[0..sig_start], dk.signing_key);
    if (mode == .sign_and_encrypt) {
        aes256CbcEncrypt(dk.encrypting_key, dk.iv, buf[16..]);
    }
    return buf;
}

/// Largest service payload that still fits one `chunk_capacity`-byte MSG/CLO
/// chunk once the Secure-Conversation framing (MessageHeader 8 +
/// SecureChannelId 4 + TokenId 4 + SequenceHeader 8 = 24), the HMAC-SHA256
/// signature (32) and — at SignAndEncrypt — the worst-case padding footer
/// (PaddingSize byte + up to 15 padding bytes) are accounted for. Deliberately
/// the *worst case* rather than the exact per-chunk figure: a chunk a few
/// bytes shorter than it had to be is legal, an over-long one is not.
/// Returns 0 when the buffer cannot hold even an empty secured chunk.
pub fn maxSymmetricPayload(chunk_capacity: usize, mode: SecurityMode) usize {
    const framing: usize = 8 + 4 + 4 + 8;
    const overhead: usize = switch (mode) {
        .none, .invalid => framing,
        .sign => framing + sym_signature_len,
        .sign_and_encrypt => framing + sym_signature_len + aes_block_len,
    };
    return chunk_capacity -| overhead;
}

pub const SymmetricDecryptAndVerifyError = std.mem.Allocator.Error || error{
    /// The trailing HMAC-SHA256 signature didn't match (constant-time
    /// comparison).
    SignatureVerificationFailed,
    /// The chunk is structurally broken: encrypted region not whole AES
    /// blocks, too short for its own headers/footer, or a padding byte
    /// inconsistent with the PaddingSize value.
    InvalidSecureMessage,
};

/// Open one received MSG/CLO chunk: decrypt (SignAndEncrypt only), verify
/// the trailing HMAC-SHA256 over the plaintext (which covers the 8-byte
/// message header — pass it in `header_bytes` since the transport already
/// consumed it), validate + strip the padding footer, and return the
/// `allocator`-owned plaintext body (SecureChannelId + TokenId +
/// SequenceHeader + payload) — the same shape a SecurityMode=None chunk
/// body has on arrival. `direction` names the chunk's *producer*
/// (`.server_to_client` for a client receiving).
pub fn symmetricDecryptAndVerify(
    allocator: std.mem.Allocator,
    header_bytes: *const [8]u8,
    chunk_body: []const u8,
    mode: SecurityMode,
    keys: ChannelKeys,
    direction: Direction,
) SymmetricDecryptAndVerifyError![]u8 {
    std.debug.assert(mode == .sign or mode == .sign_and_encrypt);
    const dk = directionKeys(&keys, direction);

    // Minimum: ChannelId(4) + TokenId(4) + SequenceHeader(8) + signature.
    if (chunk_body.len < 16 + sym_signature_len) return error.InvalidSecureMessage;

    const plain = try allocator.dupe(u8, chunk_body);
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    if (mode == .sign_and_encrypt) {
        const encrypted = plain[8..]; // SequenceHeader.. (message offset 16)
        if (encrypted.len % aes_block_len != 0) return error.InvalidSecureMessage;
        aes256CbcDecrypt(dk.encrypting_key, dk.iv, encrypted);
    }

    const sig_start = plain.len - sym_signature_len;
    var expected: [sym_signature_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &expected);
    var ctx = HmacSha256.init(dk.signing_key);
    ctx.update(header_bytes);
    ctx.update(plain[0..sig_start]);
    ctx.final(&expected);
    if (!std.crypto.timing_safe.eql([sym_signature_len]u8, expected, plain[sig_start..][0..sym_signature_len].*)) {
        return error.SignatureVerificationFailed;
    }

    var body_end = sig_start;
    if (mode == .sign_and_encrypt) {
        const pad: usize = plain[sig_start - 1];
        const pad_footprint = pad + 1;
        if (sig_start < 16 + pad_footprint) return error.InvalidSecureMessage;
        body_end = sig_start - pad_footprint;
        for (plain[body_end..sig_start]) |b| {
            if (b != pad) return error.InvalidSecureMessage;
        }
    }
    if (body_end < 16) return error.InvalidSecureMessage;
    return allocator.dupe(u8, plain[0..body_end]);
}

// ── Asymmetric (OPN) message seal/open ───────────────────────────────────

/// Byte length of the `AsymmetricAlgorithmSecurityHeader` at the front of
/// `body[offset..]` (three length-prefixed fields — String + 2 ByteStrings,
/// identical wire shape), or `null` if truncated.
fn asymmetricHeaderEnd(body: []const u8, offset: usize) ?usize {
    var off = offset;
    var field: usize = 0;
    while (field < 3) : (field += 1) {
        if (off + 4 > body.len) return null;
        const len = std.mem.readInt(i32, body[off..][0..4], .little);
        off += 4;
        if (len > 0) {
            const l: usize = @intCast(len);
            if (off + l > body.len) return null;
            off += l;
        }
    }
    return off;
}

/// A *borrowed* look at the plaintext `AsymmetricAlgorithmSecurityHeader` at
/// the front of an OPN chunk body — every field points into the caller's
/// buffer, nothing is allocated.
pub const AsymmetricHeaderView = struct {
    /// `SecurityPolicyUri`; `""` when the field was null (never a valid
    /// policy, so the caller's `eql` against a real URI rejects it anyway).
    security_policy_uri: []const u8,
    /// `SenderCertificate` — the *peer's* DER certificate as it claims it.
    /// Attacker-controlled until validated: this is the certificate a server
    /// must run through its trust policy before trusting anything signed
    /// with it.
    sender_certificate: ?[]const u8,
    /// `ReceiverCertificateThumbprint` — SHA-1 of the certificate the sender
    /// encrypted to, i.e. ours.
    receiver_certificate_thumbprint: ?[]const u8,
    /// Offset within `chunk_body` where the (possibly encrypted) region
    /// begins — one past the header's last byte.
    encrypted_region_offset: usize,
};

/// Scan the OPN chunk body (which starts at `SecureChannelId`) far enough to
/// read the `AsymmetricAlgorithmSecurityHeader` without allocating and
/// without trusting a single length prefix. `null` = truncated/malformed.
/// This is the *first* thing a server can look at: the header rides in the
/// clear precisely so the receiver can pick a policy and a key before it can
/// decrypt anything (OPC 10000-6 §6.7.2.3).
pub fn viewAsymmetricHeader(chunk_body: []const u8) ?AsymmetricHeaderView {
    if (chunk_body.len < 4) return null;
    var off: usize = 4; // past SecureChannelId
    var fields: [3]?[]const u8 = .{ null, null, null };
    for (&fields) |*field| {
        if (off + 4 > chunk_body.len) return null;
        const len = std.mem.readInt(i32, chunk_body[off..][0..4], .little);
        off += 4;
        if (len == -1) continue;
        if (len < 0) return null;
        const l: usize = @intCast(len);
        if (off + l > chunk_body.len) return null;
        field.* = chunk_body[off..][0..l];
        off += l;
    }
    return .{
        .security_policy_uri = fields[0] orelse "",
        .sender_certificate = fields[1],
        .receiver_certificate_thumbprint = fields[2],
        .encrypted_region_offset = off,
    };
}

pub const SealAsymmetricError = std.mem.Allocator.Error || rsa.EncryptOaepError || rsa.SignPkcs1v15Error || error{InvalidCertificate};

/// Seal an outgoing OPN message (always sign + encrypt when SecurityMode !=
/// None — OPC 10000-6 §6.7.4, even at SecurityMode=Sign): build the final
/// wire message from `unsecured_body` (SecureChannelId +
/// AsymmetricAlgorithmSecurityHeader + SequenceHeader + payload;
/// `encrypted_region_offset` = where the SequenceHeader starts within it),
/// append the padding footer sized to the receiver key's OAEP plaintext
/// blocks, RSA-PKCS1v1.5/SHA-256-sign the whole plaintext message (final
/// MessageSize already in the header), then RSA-OAEP/SHA-1-encrypt
/// SequenceHeader..signature per block to the receiver certificate's public
/// key. Returns the complete `allocator`-owned wire bytes.
pub fn sealAsymmetricMessage(
    allocator: std.mem.Allocator,
    random: std.Random,
    msg_code: *const [3]u8,
    unsecured_body: []const u8,
    encrypted_region_offset: usize,
    credentials: ClientCredentials,
    receiver_certificate: []const u8,
) SealAsymmetricError![]u8 {
    std.debug.assert(encrypted_region_offset <= unsecured_body.len);
    const peer_pk = try certificatePublicKey(receiver_certificate);
    const k_peer = modulusByteLen(peer_pk.n.bits());
    if (k_peer <= oaep_sha1_overhead) return error.InvalidCertificate;
    const plain_block = k_peer - oaep_sha1_overhead;
    // ExtraPaddingSize byte iff the *encryption* key is > 2048 bits
    // (open62541 `padChunk`; padding can then exceed one byte's range).
    const pad_overhead: usize = if (k_peer > 256) 2 else 1;
    const sig_len = modulusByteLen(credentials.private_key.n.bits());

    const bytes_to_encrypt = unsecured_body.len - encrypted_region_offset;
    const last_block = (bytes_to_encrypt + sig_len + pad_overhead) % plain_block;
    const padding: usize = if (last_block != 0) plain_block - last_block else 0;
    const plain_region = bytes_to_encrypt + pad_overhead + padding + sig_len;
    const blocks = plain_region / plain_block; // exact by construction
    const wire_len = 8 + encrypted_region_offset + blocks * k_peer;
    if (wire_len > std.math.maxInt(u32)) return error.MessageTooLong;

    // Assemble the full plaintext message — the signature covers all of it,
    // including the header with the FINAL (post-encryption) MessageSize.
    const plain = try allocator.alloc(u8, 8 + encrypted_region_offset + plain_region);
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    plain[0..3].* = msg_code.*;
    plain[3] = 'F';
    std.mem.writeInt(u32, plain[4..8], @intCast(wire_len), .little);
    @memcpy(plain[8..][0..unsecured_body.len], unsecured_body);
    var p = 8 + unsecured_body.len;
    @memset(plain[p..][0 .. padding + 1], @truncate(padding));
    p += padding + 1;
    if (pad_overhead == 2) {
        plain[p] = @truncate(padding >> 8);
        p += 1;
    }
    const sig_start = plain.len - sig_len;
    std.debug.assert(p == sig_start);
    _ = try rsa.signPkcs1v15(credentials.private_key, Sha256, plain[0..sig_start], plain[sig_start..]);

    // Encrypt SequenceHeader..signature per OAEP block into the wire buffer.
    const out = try allocator.alloc(u8, wire_len);
    errdefer allocator.free(out);
    const clear_len = 8 + encrypted_region_offset;
    @memcpy(out[0..clear_len], plain[0..clear_len]);
    var i: usize = 0;
    while (i < blocks) : (i += 1) {
        _ = try rsa.encryptOaep(peer_pk, Sha1, random, plain[clear_len + i * plain_block ..][0..plain_block], "", out[clear_len + i * k_peer ..][0..k_peer]);
    }
    return out;
}

pub const OpenAsymmetricError = std.mem.Allocator.Error || rsa.DecryptOaepError || rsa.VerifyPkcs1v15Error || error{ InvalidCertificate, InvalidSecureMessage };

/// Open a received OPN message: locate the encrypted region behind the
/// `AsymmetricAlgorithmSecurityHeader`, RSA-OAEP/SHA-1-decrypt it with
/// `private_key`, verify the RSA-PKCS1v1.5/SHA-256 signature over the
/// reconstructed plaintext message (8-byte wire header — pass it in
/// `header_bytes`, the transport already consumed it — + clear headers +
/// decrypted region) against `sender_certificate`'s public key, validate +
/// strip the padding footer, and return the `allocator`-owned plaintext
/// body (SecureChannelId + AsymmetricAlgorithmSecurityHeader +
/// SequenceHeader + payload) — the same shape a SecurityMode=None OPN body
/// has on arrival. `sender_certificate` should be the *pinned* peer
/// certificate, not the one inside the (attacker-controlled) message.
pub fn openAsymmetricMessage(
    allocator: std.mem.Allocator,
    header_bytes: *const [8]u8,
    chunk_body: []const u8,
    private_key: rsa.SecretKey,
    sender_certificate: []const u8,
) OpenAsymmetricError![]u8 {
    if (chunk_body.len < 4) return error.InvalidSecureMessage;
    const enc_offset = asymmetricHeaderEnd(chunk_body, 4) orelse return error.InvalidSecureMessage;

    const k = modulusByteLen(private_key.n.bits());
    if (k <= oaep_sha1_overhead) return error.InvalidSecureMessage;
    const enc_len = chunk_body.len - enc_offset;
    if (enc_len == 0 or enc_len % k != 0) return error.InvalidSecureMessage;
    const blocks = enc_len / k;
    const plain_block = k - oaep_sha1_overhead;

    // Reconstruct the plaintext message: wire header + clear headers +
    // per-block decrypted region (blocks may decrypt shorter than
    // plain_block only if the sender under-filled them — tolerated).
    const plain = try allocator.alloc(u8, 8 + enc_offset + blocks * plain_block);
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    plain[0..8].* = header_bytes.*;
    @memcpy(plain[8..][0..enc_offset], chunk_body[0..enc_offset]);
    var plen: usize = 8 + enc_offset;
    var i: usize = 0;
    while (i < blocks) : (i += 1) {
        const m = rsa.decryptOaep(private_key, Sha1, chunk_body[enc_offset + i * k ..][0..k], "", plain[plen..][0..plain_block]) catch |err| switch (err) {
            error.BufferTooSmall => unreachable, // chunk is exactly the max message length
            error.DecryptionError => return error.DecryptionError,
        };
        plen += m.len;
    }

    // Verify the signature over everything before it (padding included).
    const peer_pk = try certificatePublicKey(sender_certificate);
    const sig_len = modulusByteLen(peer_pk.n.bits());
    const pad_overhead: usize = if (k > 256) 2 else 1; // mirror of sealAsymmetricMessage
    if (plen < 8 + enc_offset + 8 + pad_overhead + sig_len) return error.InvalidSecureMessage;
    try asymmetricVerify(plain[0 .. plen - sig_len], plain[plen - sig_len .. plen], peer_pk);

    // Strip the padding footer (PaddingSize low byte, padding bytes, then
    // the ExtraPaddingSize high byte just before the signature if present).
    var padding: usize = plain[plen - sig_len - 1];
    if (pad_overhead == 2) {
        padding = (padding << 8) | plain[plen - sig_len - 2];
    }
    const pad_footprint = padding + pad_overhead;
    if (plen - sig_len < 8 + enc_offset + 8 + pad_footprint) return error.InvalidSecureMessage;
    const body_end = plen - sig_len - pad_footprint;
    const pad_low: u8 = @truncate(padding);
    for (plain[body_end..][0 .. padding + 1]) |b| {
        if (b != pad_low) return error.InvalidSecureMessage;
    }
    return allocator.dupe(u8, plain[8..body_end]);
}

// ── Encrypted user identity token secret (OPC 10000-4 §7.36.4) ───────────

/// The plaintext a `UserNameIdentityToken.Password` (or an
/// `IssuedIdentityToken.TokenData`) is built from before RSA-OAEP encryption
/// to the *server's* certificate:
///
///     UInt32 length  ‖  secret  ‖  serverNonce
///
/// where `length` counts `secret ‖ serverNonce`, little-endian like every
/// other OPC UA UInt32. The server nonce is what makes the ciphertext
/// unreplayable — it comes from the `CreateSessionResponse`/previous
/// `ActivateSessionResponse` and is checked byte-for-byte on decryption
/// (`std.crypto.timing_safe.eql`).
pub const UserTokenSecretError = std.mem.Allocator.Error || error{
    /// Structurally broken: not a whole number of RSA blocks, a length
    /// prefix that does not match the recovered plaintext, or a plaintext
    /// too short to contain the nonce.
    InvalidSecureMessage,
    /// RSA-OAEP could not recover the block.
    DecryptionError,
    /// The trailing nonce is not the one this server issued (constant-time
    /// comparison) — a replayed or cross-session token.
    NonceMismatch,
    MessageTooLong,
};

/// Build and RSA-OAEP/SHA-1-encrypt the `length ‖ secret ‖ serverNonce` blob
/// above to `receiver_public_key` (the server's certificate key). The
/// caller-side half of `decryptUserTokenSecret`; used by the tests and
/// available to any client this module grows later.
pub fn encryptUserTokenSecret(
    allocator: std.mem.Allocator,
    secret: []const u8,
    server_nonce: []const u8,
    receiver_public_key: rsa.PublicKey,
    random: std.Random,
) UserTokenSecretError![]u8 {
    const plain = try allocator.alloc(u8, 4 + secret.len + server_nonce.len);
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    const declared = std.math.cast(u32, secret.len + server_nonce.len) orelse return error.MessageTooLong;
    std.mem.writeInt(u32, plain[0..4], declared, .little);
    @memcpy(plain[4..][0..secret.len], secret);
    @memcpy(plain[4 + secret.len ..], server_nonce);
    return asymmetricEncrypt(allocator, plain, receiver_public_key, random) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.MessageTooLong, error.BufferTooSmall => error.MessageTooLong,
    };
}

/// Decrypt an encrypted identity-token secret with this application's private
/// key, check the length prefix and the trailing server nonce, and return the
/// `allocator`-owned secret (the password). Every failure is a distinct
/// typed error, never a partially-recovered password.
pub fn decryptUserTokenSecret(
    allocator: std.mem.Allocator,
    ciphertext: []const u8,
    private_key: rsa.SecretKey,
    expected_server_nonce: []const u8,
) UserTokenSecretError![]u8 {
    const plain = asymmetricDecrypt(allocator, ciphertext, private_key) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DecryptionError, error.BufferTooSmall => return error.DecryptionError,
    };
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    if (plain.len < 4) return error.InvalidSecureMessage;
    const declared = std.mem.readInt(u32, plain[0..4], .little);
    // OAEP blocks recover exactly, so the declared length must land inside
    // the recovered plaintext; a longer one means the wrong key/format.
    if (declared > plain.len - 4) return error.InvalidSecureMessage;
    if (declared < expected_server_nonce.len) return error.InvalidSecureMessage;
    const secret_len = declared - expected_server_nonce.len;
    const nonce = plain[4 + secret_len ..][0..expected_server_nonce.len];
    if (!constantTimeEql(nonce, expected_server_nonce)) return error.NonceMismatch;
    return allocator.dupe(u8, plain[4..][0..secret_len]);
}

// ── AsymmetricAlgorithmSecurityHeader (OPC 10000-6 §7.2) ─────────────────────
// Pure encoding, ground-truthed against services.zig's `Channel.
// sendService`/`.recvService`, which already build/parse this exact
// three-field shape inline for the SecurityMode=None case (a
// `SecurityPolicyUri` String followed by two ByteStrings) — this gives that
// shape a name and a reusable codec for the Sign/SignAndEncrypt case where
// the two ByteStrings are no longer always null.

pub const AsymmetricAlgorithmSecurityHeader = struct {
    /// `SecurityPolicyUri` (String) — `SecurityPolicy.uri()`'s return value.
    security_policy_uri: ?[]const u8,
    /// `SenderCertificate` (ByteString) — the sender's DER certificate;
    /// `null` at SecurityMode=None.
    sender_certificate: ?[]const u8,
    /// `ReceiverCertificateThumbprint` (ByteString) — SHA-1 thumbprint of
    /// the receiver's certificate (`certificateThumbprint`); `null` at
    /// SecurityMode=None.
    receiver_certificate_thumbprint: ?[]const u8,
};

pub fn encodeAsymmetricAlgorithmSecurityHeader(e: *encoding.Encoder, v: AsymmetricAlgorithmSecurityHeader) encoding.EncodeError!void {
    try e.encodeString(v.security_policy_uri);
    try e.encodeByteString(v.sender_certificate);
    try e.encodeByteString(v.receiver_certificate_thumbprint);
}

pub fn decodeAsymmetricAlgorithmSecurityHeader(d: *encoding.Decoder) encoding.DecodeError!AsymmetricAlgorithmSecurityHeader {
    return .{
        .security_policy_uri = try d.decodeString(),
        .sender_certificate = try d.decodeByteString(),
        .receiver_certificate_thumbprint = try d.decodeByteString(),
    };
}

/// Frees every owned field `decodeAsymmetricAlgorithmSecurityHeader` may
/// have allocated.
pub fn freeAsymmetricAlgorithmSecurityHeader(a: std.mem.Allocator, v: AsymmetricAlgorithmSecurityHeader) void {
    if (v.security_policy_uri) |s| a.free(s);
    if (v.sender_certificate) |s| a.free(s);
    if (v.receiver_certificate_thumbprint) |s| a.free(s);
}

// ── tests ──

const testing = std.testing;

test "SecurityPolicy.uri" {
    try testing.expectEqualStrings("http://opcfoundation.org/UA/SecurityPolicy#None", SecurityPolicy.none.uri());
    try testing.expectEqualStrings("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", SecurityPolicy.basic256sha256.uri());
    try testing.expectEqualStrings("http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss", SecurityPolicy.aes256_sha256_rsapss.uri());
}

test "SecurityMode matches services.MessageSecurityMode's wire values" {
    try testing.expectEqual(@as(u32, 1), @intFromEnum(SecurityMode.none));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(SecurityMode.sign));
    try testing.expectEqual(@as(u32, 3), @intFromEnum(SecurityMode.sign_and_encrypt));
}

test "SecurityLengths.basic256sha256" {
    const l = lengths(.basic256sha256).?;
    try testing.expectEqual(@as(usize, 214), l.asymmetric_max_plaintext_len);
    try testing.expectEqual(@as(usize, 256), l.asymmetric_signature_len);
    try testing.expectEqual(@as(usize, 32), l.symmetric_key_len);
    try testing.expectEqual(@as(usize, 16), l.symmetric_block_len);
    try testing.expectEqual(@as(usize, 32), l.symmetric_signature_len);
    try testing.expectEqual(@as(usize, 32), l.nonce_len);
    try testing.expect(lengths(.none) == null);
    try testing.expect(lengths(.aes256_sha256_rsapss) == null);
}

test "AsymmetricAlgorithmSecurityHeader round-trip" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    try encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = "fake-client-cert-der",
        .receiver_certificate_thumbprint = "fake-server-thumbprint",
    });

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeAsymmetricAlgorithmSecurityHeader(&d);
    defer freeAsymmetricAlgorithmSecurityHeader(testing.allocator, decoded);

    try testing.expectEqualStrings(SecurityPolicy.basic256sha256.uri(), decoded.security_policy_uri.?);
    try testing.expectEqualStrings("fake-client-cert-der", decoded.sender_certificate.?);
    try testing.expectEqualStrings("fake-server-thumbprint", decoded.receiver_certificate_thumbprint.?);

    // `asymmetricHeaderEnd` (the seal/open path's cheap scanner) must agree
    // with the full codec about where the header ends.
    try testing.expectEqual(@as(?usize, w.buffered().len), asymmetricHeaderEnd(w.buffered(), 0));
}

test "AsymmetricAlgorithmSecurityHeader round-trip: SecurityMode=None shape (null cert/thumbprint)" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    try encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = SecurityPolicy.none.uri(),
        .sender_certificate = null,
        .receiver_certificate_thumbprint = null,
    });

    var r: std.Io.Reader = .fixed(w.buffered());
    var d = encoding.Decoder.init(&r, testing.allocator);
    const decoded = try decodeAsymmetricAlgorithmSecurityHeader(&d);
    defer freeAsymmetricAlgorithmSecurityHeader(testing.allocator, decoded);

    try testing.expectEqualStrings(SecurityPolicy.none.uri(), decoded.security_policy_uri.?);
    try testing.expect(decoded.sender_certificate == null);
    try testing.expect(decoded.receiver_certificate_thumbprint == null);
    try testing.expectEqual(@as(?usize, w.buffered().len), asymmetricHeaderEnd(w.buffered(), 0));
}

test "ClientCredentials.generateSelfSigned" {
    var prng = std.Random.DefaultCsprng.init(std.mem.zeroes([32]u8));
    const random = prng.random();

    var creds = try ClientCredentials.generateSelfSigned(testing.allocator, random, .{
        .modulus_bits = 512, // small, only to keep this test fast — see the option's own doc comment
        .common_name = "opcua-security-test",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
        .application_uri = "urn:zig-libs:opcua:security-test",
    });
    defer creds.deinit(testing.allocator);

    try testing.expect(creds.certificate_der.len > 0);
    // The certificate this module built must itself parse back with std's
    // independent X.509 parser and embed the same public key `generate`
    // returned — proves `generateSelfSigned` wires `rsa.generate` and
    // `rsa.selfSignedCert` together, and that `certificatePublicKey` (the
    // path the OPN seal/open uses on the peer certificate) agrees.
    const pk = try certificatePublicKey(creds.certificate_der);
    try testing.expectEqual(creds.public_key.n.bits(), pk.n.bits());
}

test "P-SHA256 KAT: TLS 1.2 PRF SHA-256 test vector" {
    // The de-facto-standard TLS 1.2 PRF/SHA-256 vector (IETF TLS WG mailing
    // list, reused by mbedTLS's test suite). TLS's PRF(secret, label, seed)
    // = P_hash(secret, label ‖ seed), so prefixing the label onto the seed
    // exercises exactly OPC UA's label-less P_SHA256 construction.
    const secret = [_]u8{ 0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35 };
    const seed = "test label" ++ [_]u8{ 0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c };
    const expected_hex = "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" ++
        "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" ++
        "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" ++
        "87347b66";
    var expected: [100]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);

    var out: [100]u8 = undefined;
    pSha256(&secret, seed, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "AES-256-CBC KAT: NIST SP 800-38A F.2.5/F.2.6" {
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    var iv: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&iv, "000102030405060708090a0b0c0d0e0f");
    var plaintext: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, "6bc1bee22e409f96e93d7e117393172a" ++
        "ae2d8a571e03ac9c9eb76fac45af8e51" ++
        "30c81c46a35ce411e5fbc1191a0a52ef" ++
        "f69f2445df4f9b17ad2b417be66c3710");
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "f58c4c04d6e5f1ba779eabfb5f7bfbd6" ++
        "9cfc4e967edb808d679f777bc6702c7d" ++
        "39f23369a9d9bacfa530e26304231461" ++
        "b2eb05e2c39be9fcda6c19078c6a9d1b");

    var data = plaintext;
    aes256CbcEncrypt(&key, &iv, &data);
    try testing.expectEqualSlices(u8, &expected, &data);
    aes256CbcDecrypt(&key, &iv, &data);
    try testing.expectEqualSlices(u8, &plaintext, &data);
}

test "deriveKeys: directions differ, deterministic, matches raw P-SHA256 layout" {
    const client_nonce = "client-nonce-0123456789abcdefghi"; // 32 bytes
    const server_nonce = "server-nonce-0123456789abcdefghi";
    const keys = deriveKeys(client_nonce, server_nonce, .basic256sha256);
    const again = deriveKeys(client_nonce, server_nonce, .basic256sha256);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&keys), std.mem.asBytes(&again));
    try testing.expect(!std.mem.eql(u8, &keys.client_signing_key, &keys.server_signing_key));

    // Layout check against the raw PRF: client block = P_SHA256(secret =
    // serverNonce, seed = clientNonce), split 32 ‖ 32 ‖ 16 (§6.7.5).
    var block: [80]u8 = undefined;
    pSha256(server_nonce, client_nonce, &block);
    try testing.expectEqualSlices(u8, block[0..32], &keys.client_signing_key);
    try testing.expectEqualSlices(u8, block[32..64], &keys.client_encrypting_key);
    try testing.expectEqualSlices(u8, block[64..80], &keys.client_iv);
    pSha256(client_nonce, server_nonce, &block);
    try testing.expectEqualSlices(u8, block[0..32], &keys.server_signing_key);

    var wiped = keys;
    wiped.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&wiped), 0));
}

test "asymmetricEncrypt -> asymmetricDecrypt round-trip (multi-block)" {
    var prng = std.Random.DefaultCsprng.init([_]u8{7} ** 32);
    const random = prng.random();
    const kp = try rsa.generate(random, 512, 65537); // k = 64, plain block = 22 -> multi-block fast

    const msg = "a message noticeably longer than one 22-byte OAEP block, spanning several RSA blocks";
    const ct = try asymmetricEncrypt(testing.allocator, msg, kp.public_key, random);
    defer testing.allocator.free(ct);
    try testing.expectEqual(@as(usize, 0), ct.len % 64);
    try testing.expect(ct.len / 64 == (msg.len + 21) / 22);

    const pt = try asymmetricDecrypt(testing.allocator, ct, kp.secret_key);
    defer testing.allocator.free(pt);
    try testing.expectEqualSlices(u8, msg, pt);

    // Corrupted ciphertext must not decrypt.
    const bad = try testing.allocator.dupe(u8, ct);
    defer testing.allocator.free(bad);
    bad[10] ^= 0x01;
    try testing.expectError(error.DecryptionError, asymmetricDecrypt(testing.allocator, bad, kp.secret_key));
    // Non-whole-block ciphertext is structurally invalid.
    try testing.expectError(error.DecryptionError, asymmetricDecrypt(testing.allocator, ct[0 .. ct.len - 1], kp.secret_key));
}

test "asymmetricSign -> asymmetricVerify round-trip + tamper" {
    var prng = std.Random.DefaultCsprng.init([_]u8{9} ** 32);
    const random = prng.random();
    const kp = try rsa.generate(random, 512, 65537);

    const msg = "OPN message bytes to be signed";
    const sig = try asymmetricSign(testing.allocator, msg, kp.secret_key);
    defer testing.allocator.free(sig);
    try testing.expectEqual(@as(usize, 64), sig.len);
    try asymmetricVerify(msg, sig, kp.public_key);
    try testing.expectError(error.SignatureVerificationFailed, asymmetricVerify("OPN message bytes to be signed!", sig, kp.public_key));
    sig[0] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, asymmetricVerify(msg, sig, kp.public_key));
}

/// A plausible plaintext MSG chunk body: ChannelId + TokenId +
/// SequenceHeader + `payload`.
fn testChunkBody(buf: []u8, payload: []const u8) []const u8 {
    std.mem.writeInt(u32, buf[0..4], 7, .little); // ChannelId
    std.mem.writeInt(u32, buf[4..8], 3, .little); // TokenId
    std.mem.writeInt(u32, buf[8..12], 42, .little); // SequenceNumber
    std.mem.writeInt(u32, buf[12..16], 42, .little); // RequestId
    @memcpy(buf[16..][0..payload.len], payload);
    return buf[0 .. 16 + payload.len];
}

test "symmetricSignAndEncrypt -> symmetricDecryptAndVerify round-trip (both modes, both directions)" {
    const keys = deriveKeys("client-nonce-0123456789abcdefghi", "server-nonce-0123456789abcdefghi", .basic256sha256);

    for ([_]SecurityMode{ .sign, .sign_and_encrypt }) |mode| {
        for ([_]Direction{ .client_to_server, .server_to_client }) |dir| {
            var body_buf: [64]u8 = undefined;
            const body = testChunkBody(&body_buf, "payload-bytes");

            const wire = try symmetricSignAndEncrypt(testing.allocator, "MSG", body, mode, keys, dir);
            defer testing.allocator.free(wire);
            // Wire shape: header echoes the final size; encrypted region
            // whole AES blocks for SignAndEncrypt.
            try testing.expectEqualSlices(u8, "MSG", wire[0..3]);
            try testing.expectEqual(@as(u8, 'F'), wire[3]);
            try testing.expectEqual(wire.len, std.mem.readInt(u32, wire[4..8], .little));
            if (mode == .sign_and_encrypt) {
                try testing.expectEqual(@as(usize, 0), (wire.len - 16) % 16);
            } else {
                try testing.expectEqual(body.len + 8 + 32, wire.len);
            }

            const recovered = try symmetricDecryptAndVerify(testing.allocator, wire[0..8], wire[8..], mode, keys, dir);
            defer testing.allocator.free(recovered);
            try testing.expectEqualSlices(u8, body, recovered);

            // Cross-direction keys must fail the signature.
            const other: Direction = if (dir == .client_to_server) .server_to_client else .client_to_server;
            try testing.expectError(error.SignatureVerificationFailed, symmetricDecryptAndVerify(testing.allocator, wire[0..8], wire[8..], mode, keys, other));
        }
    }
}

test "symmetricDecryptAndVerify negatives: tampered MAC / body / header, bad padding" {
    const keys = deriveKeys("client-nonce-0123456789abcdefghi", "server-nonce-0123456789abcdefghi", .basic256sha256);
    var body_buf: [64]u8 = undefined;
    const body = testChunkBody(&body_buf, "payload-bytes");
    const wire = try symmetricSignAndEncrypt(testing.allocator, "MSG", body, .sign_and_encrypt, keys, .client_to_server);
    defer testing.allocator.free(wire);

    // Tampered ciphertext (flips plaintext bits after decrypt -> MAC fails).
    {
        const bad = try testing.allocator.dupe(u8, wire);
        defer testing.allocator.free(bad);
        bad[bad.len - 1] ^= 0x01;
        try testing.expectError(error.SignatureVerificationFailed, symmetricDecryptAndVerify(testing.allocator, bad[0..8], bad[8..], .sign_and_encrypt, keys, .client_to_server));
    }
    // Tampered (unencrypted) header — the signature covers it.
    {
        var bad_header: [8]u8 = wire[0..8].*;
        bad_header[4] ^= 0x01; // MessageSize
        try testing.expectError(error.SignatureVerificationFailed, symmetricDecryptAndVerify(testing.allocator, &bad_header, wire[8..], .sign_and_encrypt, keys, .client_to_server));
    }
    // Structurally bad: encrypted region not whole AES blocks.
    try testing.expectError(error.InvalidSecureMessage, symmetricDecryptAndVerify(testing.allocator, wire[0..8], wire[8 .. wire.len - 1], .sign_and_encrypt, keys, .client_to_server));

    // Bad padding with a VALID signature: hand-craft a chunk whose
    // PaddingSize byte points past the message, sign it correctly, encrypt
    // — must surface InvalidSecureMessage (not a signature error, and
    // never an out-of-bounds walk).
    {
        var raw: [8 + 16 + 24 + 32]u8 = undefined; // header + ids/seq + 24 "padding" bytes + MAC -> encrypted region (72-8-8=64) is 16-aligned
        const total = raw.len;
        raw[0..3].* = "MSG".*;
        raw[3] = 'F';
        std.mem.writeInt(u32, raw[4..8], @intCast(total), .little);
        @memcpy(raw[8..][0..16], body[0..16]);
        @memset(raw[24..][0..24], 0xEE); // "padding" bytes + PaddingSize byte, value 0xEE = 238 > message length
        HmacSha256.create(raw[total - 32 ..][0..32], raw[0 .. total - 32], &keys.client_signing_key);
        aes256CbcEncrypt(&keys.client_encrypting_key, &keys.client_iv, raw[16..]);
        try testing.expectError(error.InvalidSecureMessage, symmetricDecryptAndVerify(testing.allocator, raw[0..8], raw[8..], .sign_and_encrypt, keys, .client_to_server));
    }
}

test "sealAsymmetricMessage -> openAsymmetricMessage round-trip (two key pairs)" {
    var prng = std.Random.DefaultCsprng.init([_]u8{5} ** 32);
    const random = prng.random();

    var client = try ClientCredentials.generateSelfSigned(testing.allocator, random, .{
        .modulus_bits = 512,
        .common_name = "seal-open-client",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
    });
    defer client.deinit(testing.allocator);
    var server = try ClientCredentials.generateSelfSigned(testing.allocator, random, .{
        .modulus_bits = 768, // deliberately a different size than the client's
        .common_name = "seal-open-server",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
    });
    defer server.deinit(testing.allocator);

    // Build a plausible OPN body: ChannelId + real asym header + SequenceHeader + payload.
    var body_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer body_writer.deinit();
    var e = encoding.Encoder.init(&body_writer.writer);
    try body_writer.writer.writeInt(u32, 0, .little); // ChannelId
    try encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = client.certificate_der,
        .receiver_certificate_thumbprint = &certificateThumbprint(server.certificate_der),
    });
    const enc_offset = body_writer.writer.buffered().len;
    try body_writer.writer.writeInt(u32, 1, .little); // SequenceNumber
    try body_writer.writer.writeInt(u32, 1, .little); // RequestId
    try body_writer.writer.writeAll("opn-request-payload-bytes");
    const body = body_writer.writer.buffered();

    const wire = try sealAsymmetricMessage(testing.allocator, random, "OPN", body, enc_offset, client, server.certificate_der);
    defer testing.allocator.free(wire);
    try testing.expectEqualSlices(u8, "OPN", wire[0..3]);
    try testing.expectEqual(wire.len, std.mem.readInt(u32, wire[4..8], .little));
    // Clear part (up to the asym header's end) rides plaintext; the
    // encrypted region is whole 96-byte (768-bit) RSA blocks.
    try testing.expectEqualSlices(u8, body[0..enc_offset], wire[8..][0..enc_offset]);
    try testing.expectEqual(@as(usize, 0), (wire.len - 8 - enc_offset) % 96);

    // Server side: decrypt with the server key, verify with the client cert.
    const recovered = try openAsymmetricMessage(testing.allocator, wire[0..8], wire[8..], server.private_key, client.certificate_der);
    defer testing.allocator.free(recovered);
    try testing.expectEqualSlices(u8, body, recovered);

    // Tampered wire bytes must fail (OAEP decrypt error).
    {
        const bad = try testing.allocator.dupe(u8, wire);
        defer testing.allocator.free(bad);
        bad[bad.len - 1] ^= 0x01;
        try testing.expectError(error.DecryptionError, openAsymmetricMessage(testing.allocator, bad[0..8], bad[8..], server.private_key, client.certificate_der));
    }
    // Wrong sender certificate must fail the signature.
    try testing.expectError(error.SignatureVerificationFailed, openAsymmetricMessage(testing.allocator, wire[0..8], wire[8..], server.private_key, server.certificate_der));
}

test "deriveKeys KAT: P-SHA256 over two fixed 32-byte nonces (OPC 10000-6 §6.7.5)" {
    // **Provenance.** The expected bytes below were produced by an
    // *independent* implementation of the published construction: Python's
    // `hmac`/`hashlib` running RFC 5246 §5's P_hash with SHA-256 and no TLS
    // label, exactly as OPC 10000-6 §6.7.5 specifies, over the two nonces
    // here. They are therefore self-derived rather than lifted from a
    // published OPC UA vector (the OPC Foundation publishes no key-derivation
    // KAT), but they are not this code checking itself:
    //   * `pSha256` is independently anchored by the TLS-1.2 PRF/SHA-256
    //     vector KAT above, an externally published test vector;
    //   * the *layout* (which 32/32/16-byte slice is which key, and which
    //     nonce is secret vs seed in each direction) is cross-checked by the
    //     live interop in `server_interop.zig`: a real open62541/asyncua
    //     client cannot exchange a single signed chunk with this server if
    //     any one of the six outputs is wrong or swapped.
    const client_nonce = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const server_nonce = [_]u8{
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    };
    const keys = deriveKeys(&client_nonce, &server_nonce, .basic256sha256);

    const cases = [_]struct { expected_hex: []const u8, got: []const u8 }{
        .{ .expected_hex = "a70a99cc2ac5a962005d4ec1762c192a07390a85772b5bf5e2c96d9fc18406d2", .got = &keys.client_signing_key },
        .{ .expected_hex = "5f99e138f539b8356b9b40d05411e856a7ff4bc5b416cf15f9600de1d8b652fa", .got = &keys.client_encrypting_key },
        .{ .expected_hex = "2c23b363b407b3f737fcae16bacebc2f", .got = &keys.client_iv },
        .{ .expected_hex = "49adaac108434c093e9175f2d07c7159ef60b69ea0159f874cba31f99c949ef2", .got = &keys.server_signing_key },
        .{ .expected_hex = "574b5bd1027338064dd4be7f0956e1910b5cfd5a873ae212c30f8d191890cc45", .got = &keys.server_encrypting_key },
        .{ .expected_hex = "0668bd6612fd9776cf39b099e064384b", .got = &keys.server_iv },
    };
    var buf: [32]u8 = undefined;
    for (cases) |c| {
        const expected = try std.fmt.hexToBytes(buf[0 .. c.expected_hex.len / 2], c.expected_hex);
        try testing.expectEqualSlices(u8, expected, c.got);
    }
    // Direction asymmetry is the whole point: swapping the nonces must NOT
    // reproduce the same table (it produces the mirror one).
    const swapped = deriveKeys(&server_nonce, &client_nonce, .basic256sha256);
    try testing.expectEqualSlices(u8, &keys.client_signing_key, &swapped.server_signing_key);
    try testing.expectEqualSlices(u8, &keys.server_signing_key, &swapped.client_signing_key);
}

test "symmetricSealChunk: intermediate ('C') chunks are secured individually" {
    const keys = deriveKeys("client-nonce-0123456789abcdefghi", "server-nonce-0123456789abcdefghi", .basic256sha256);
    var body_buf: [64]u8 = undefined;
    const body = testChunkBody(&body_buf, "chunk-payload");

    for ([_]u8{ 'C', 'F' }) |chunk_byte| {
        const wire = try symmetricSealChunk(testing.allocator, "MSG", chunk_byte, body, .sign_and_encrypt, keys, .server_to_client);
        defer testing.allocator.free(wire);
        try testing.expectEqual(chunk_byte, wire[3]);
        const recovered = try symmetricDecryptAndVerify(testing.allocator, wire[0..8], wire[8..], .sign_and_encrypt, keys, .server_to_client);
        defer testing.allocator.free(recovered);
        try testing.expectEqualSlices(u8, body, recovered);

        // The chunk byte is inside the signed range, so flipping it must
        // break verification — an attacker cannot turn a final chunk into an
        // intermediate one (or an abort) without the signing key.
        var forged: [8]u8 = wire[0..8].*;
        forged[3] = if (chunk_byte == 'C') 'F' else 'C';
        try testing.expectError(
            error.SignatureVerificationFailed,
            symmetricDecryptAndVerify(testing.allocator, &forged, wire[8..], .sign_and_encrypt, keys, .server_to_client),
        );
    }
}

test "symmetric padding: every payload length across two AES-block boundaries round-trips" {
    // Chunk padding under encryption is the classic place to be off by one:
    // the padding is sized so that SequenceHeader + payload + PaddingSize
    // byte + padding + signature fills whole 16-byte blocks, and the
    // PaddingSize byte itself counts. Sweeping 0..47 crosses three block
    // boundaries in the *payload*, so every residue of the modulus — and the
    // "padding is exactly 0" case — is hit.
    const keys = deriveKeys("client-nonce-0123456789abcdefghi", "server-nonce-0123456789abcdefghi", .basic256sha256);
    var payload: [48]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    var zero_padding_seen = false;
    for (0..payload.len + 1) |n| {
        var body_buf: [80]u8 = undefined;
        const body = testChunkBody(&body_buf, payload[0..n]);
        const wire = try symmetricSignAndEncrypt(testing.allocator, "MSG", body, .sign_and_encrypt, keys, .client_to_server);
        defer testing.allocator.free(wire);

        // The encrypted region (message offset 16 onwards) must be whole
        // AES blocks, every time.
        try testing.expectEqual(@as(usize, 0), (wire.len - 16) % 16);
        try testing.expectEqual(wire.len, std.mem.readInt(u32, wire[4..8], .little));
        // Total = header(8) + body + 1 PaddingSize byte + padding + MAC(32).
        const pad = wire.len - 8 - body.len - 1 - 32;
        try testing.expect(pad < 16);
        if (pad == 0) zero_padding_seen = true;

        const recovered = try symmetricDecryptAndVerify(testing.allocator, wire[0..8], wire[8..], .sign_and_encrypt, keys, .client_to_server);
        defer testing.allocator.free(recovered);
        try testing.expectEqualSlices(u8, body, recovered);
    }
    // The exactly-aligned case (no padding bytes at all beyond the
    // PaddingSize byte) really is exercised, not just the padded ones.
    try testing.expect(zero_padding_seen);
}

test "maxSymmetricPayload: the advertised budget always fits the buffer" {
    for ([_]SecurityMode{ .sign, .sign_and_encrypt }) |mode| {
        const keys = deriveKeys("client-nonce-0123456789abcdefghi", "server-nonce-0123456789abcdefghi", .basic256sha256);
        const capacity: usize = 512;
        const budget = maxSymmetricPayload(capacity, mode);
        try testing.expect(budget > 0);

        const payload = try testing.allocator.alloc(u8, budget);
        defer testing.allocator.free(payload);
        @memset(payload, 0xAB);
        const body = try testing.allocator.alloc(u8, 16 + budget);
        defer testing.allocator.free(body);
        _ = testChunkBody(body, payload);

        const wire = try symmetricSignAndEncrypt(testing.allocator, "MSG", body, mode, keys, .server_to_client);
        defer testing.allocator.free(wire);
        try testing.expect(wire.len <= capacity);
    }
    try testing.expectEqual(@as(usize, 0), maxSymmetricPayload(8, .sign_and_encrypt));
}

test "viewAsymmetricHeader: borrows the three plaintext fields, refuses truncation" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var e = encoding.Encoder.init(&w);
    try w.writeInt(u32, 0, .little); // SecureChannelId
    try encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = "peer-cert-der",
        .receiver_certificate_thumbprint = "0123456789abcdefghij",
    });
    const header_end = w.buffered().len;
    try w.writeAll("encrypted-region-bytes");
    const body = w.buffered();

    const view = viewAsymmetricHeader(body).?;
    try testing.expectEqualStrings(SecurityPolicy.basic256sha256.uri(), view.security_policy_uri);
    try testing.expectEqualStrings("peer-cert-der", view.sender_certificate.?);
    try testing.expectEqualStrings("0123456789abcdefghij", view.receiver_certificate_thumbprint.?);
    try testing.expectEqual(header_end, view.encrypted_region_offset);
    // The fields really are borrowed, not copied.
    try testing.expect(@intFromPtr(view.sender_certificate.?.ptr) >= @intFromPtr(body.ptr));

    // SecurityMode=None's shape: null certificate + null thumbprint.
    var none_buf: [128]u8 = undefined;
    var nw: std.Io.Writer = .fixed(&none_buf);
    var ne = encoding.Encoder.init(&nw);
    try nw.writeInt(u32, 0, .little);
    try encodeAsymmetricAlgorithmSecurityHeader(&ne, .{
        .security_policy_uri = SecurityPolicy.none.uri(),
        .sender_certificate = null,
        .receiver_certificate_thumbprint = null,
    });
    const none_view = viewAsymmetricHeader(nw.buffered()).?;
    try testing.expectEqualStrings(SecurityPolicy.none.uri(), none_view.security_policy_uri);
    try testing.expect(none_view.sender_certificate == null);

    // Truncation at every prefix must be `null`, never an out-of-bounds read.
    for (0..body.len) |cut| {
        if (cut >= header_end) continue;
        try testing.expect(viewAsymmetricHeader(body[0..cut]) == null);
    }
    // A negative (non -1) length prefix is malformed, not "null".
    var bad = try testing.allocator.dupe(u8, body);
    defer testing.allocator.free(bad);
    std.mem.writeInt(i32, bad[4..8], -7, .little);
    try testing.expect(viewAsymmetricHeader(bad) == null);
}

test "user identity token secret: encrypt -> decrypt, replayed nonce and wrong key rejected" {
    var prng = std.Random.DefaultCsprng.init([_]u8{0x21} ** 32);
    const random = prng.random();
    const server_kp = try rsa.generate(random, 512, 65537);
    const other_kp = try rsa.generate(random, 512, 65537);

    const server_nonce = "server-nonce-0123456789abcdefghi"; // 32 bytes
    const password = "correct horse battery staple";

    const blob = try encryptUserTokenSecret(testing.allocator, password, server_nonce, server_kp.public_key, random);
    defer testing.allocator.free(blob);
    // Whole RSA blocks, and nothing recognisable of the password in them.
    try testing.expectEqual(@as(usize, 0), blob.len % 64);
    try testing.expect(std.mem.indexOf(u8, blob, password) == null);

    const recovered = try decryptUserTokenSecret(testing.allocator, blob, server_kp.secret_key, server_nonce);
    defer testing.allocator.free(recovered);
    try testing.expectEqualStrings(password, recovered);

    // Replay into a different session (= a different server nonce) fails on
    // the nonce, not on the padding — that is what makes the blob
    // session-bound rather than a reusable bearer secret.
    try testing.expectError(
        error.NonceMismatch,
        decryptUserTokenSecret(testing.allocator, blob, server_kp.secret_key, "server-nonce-DIFFERENT-0123456789"[0..32]),
    );
    // Encrypted to us, decrypted with somebody else's key.
    try testing.expectError(
        error.DecryptionError,
        decryptUserTokenSecret(testing.allocator, blob, other_kp.secret_key, server_nonce),
    );
    // Structurally broken ciphertext.
    try testing.expectError(
        error.DecryptionError,
        decryptUserTokenSecret(testing.allocator, blob[0 .. blob.len - 1], server_kp.secret_key, server_nonce),
    );
    // An empty password is legal and must round-trip (some servers allow it).
    const empty = try encryptUserTokenSecret(testing.allocator, "", server_nonce, server_kp.public_key, random);
    defer testing.allocator.free(empty);
    const empty_back = try decryptUserTokenSecret(testing.allocator, empty, server_kp.secret_key, server_nonce);
    defer testing.allocator.free(empty_back);
    try testing.expectEqual(@as(usize, 0), empty_back.len);
}

test "certificateValidity: notBefore/notAfter come back out of a certificate we built" {
    var prng = std.Random.DefaultCsprng.init([_]u8{0x33} ** 32);
    var creds = try ClientCredentials.generateSelfSigned(testing.allocator, prng.random(), .{
        .modulus_bits = 512,
        .common_name = "validity-test",
        .not_before = "260101000000Z", // 2026-01-01T00:00:00Z
        .not_after = "270101000000Z", // 2027-01-01T00:00:00Z
    });
    defer creds.deinit(testing.allocator);

    const v = try certificateValidity(creds.certificate_der);
    try testing.expectEqual(@as(i64, 1_767_225_600), v.not_before_sec); // 2026-01-01
    try testing.expectEqual(@as(i64, 1_798_761_600), v.not_after_sec); // 2027-01-01
    try testing.expect(v.covers(1_767_225_600));
    try testing.expect(v.covers(1_798_761_600));
    try testing.expect(!v.covers(1_767_225_599));
    try testing.expect(!v.covers(1_798_761_601));
    try testing.expectError(error.InvalidCertificate, certificateValidity("not a certificate"));
}

test "constantTimeEql: agrees with mem.eql on every short case" {
    try testing.expect(constantTimeEql("", ""));
    try testing.expect(constantTimeEql("abc", "abc"));
    try testing.expect(!constantTimeEql("abc", "abd"));
    try testing.expect(!constantTimeEql("abc", "ab"));
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    for (&a, 0..) |*x, i| x.* = @truncate(i * 7);
    b = a;
    try testing.expect(constantTimeEql(&a, &b));
    for (0..b.len) |i| {
        b[i] ^= 0x80;
        try testing.expect(!constantTimeEql(&a, &b));
        b[i] ^= 0x80;
    }
}

test "hostile certificates: truncation, tampering and garbage are typed errors, never panics" {
    // `std.crypto.Certificate`'s DER reader is unchecked (`bytes[i]` with no
    // bounds test, `end = start + declared_len` with no clamp), and on a
    // server the certificate is entirely attacker-supplied — so the two
    // parsing helpers must be *total*. This is the test that keeps them so.
    var prng = std.Random.DefaultCsprng.init([_]u8{0x5A} ** 32);
    var creds = try ClientCredentials.generateSelfSigned(testing.allocator, prng.random(), .{
        .modulus_bits = 512,
        .common_name = "hostile-cert-test",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
        .application_uri = "urn:zig-libs:opcua:hostile-test",
    });
    defer creds.deinit(testing.allocator);
    // The genuine article still works — this test must not be vacuous.
    _ = try certificatePublicKey(creds.certificate_der);
    _ = try certificateValidity(creds.certificate_der);

    // Every prefix (the classic "declared length outruns the buffer").
    for (0..creds.certificate_der.len) |cut| {
        try testing.expectError(error.InvalidCertificate, certificatePublicKey(creds.certificate_der[0..cut]));
        try testing.expectError(error.InvalidCertificate, certificateValidity(creds.certificate_der[0..cut]));
    }

    // Every single-byte corruption: either it still parses (a byte inside a
    // string or key) or it is a typed error. Never a crash.
    const mutant = try testing.allocator.dupe(u8, creds.certificate_der);
    defer testing.allocator.free(mutant);
    for (0..mutant.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |v| {
            const original = mutant[i];
            mutant[i] = v;
            if (certificatePublicKey(mutant)) |_| {} else |err| try testing.expectEqual(error.InvalidCertificate, err);
            if (certificateValidity(mutant)) |_| {} else |err| try testing.expectEqual(error.InvalidCertificate, err);
            mutant[i] = original;
        }
    }

    // Hand-built hostile shapes.
    const nasties = [_][]const u8{
        "",
        &.{0x30},
        &.{ 0x30, 0x82 }, // long form, length bytes missing
        &.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }, // 4 GB SEQUENCE
        &.{ 0x30, 0x80, 0x00, 0x00 }, // BER indefinite length
        &.{ 0x30, 0x02, 0x30, 0x00 }, // SEQUENCE { SEQUENCE {} } — no fields at all
        &.{ 0x30, 0x03, 0x30, 0x01, 0x00 }, // child claims one byte it does not tile
        "not a certificate",
    };
    for (nasties) |bytes| {
        try testing.expectError(error.InvalidCertificate, certificatePublicKey(bytes));
        try testing.expectError(error.InvalidCertificate, certificateValidity(bytes));
    }

    // Oversize input is refused by length, before any parsing.
    const huge = try testing.allocator.alloc(u8, max_parsed_certificate_len + 1);
    defer testing.allocator.free(huge);
    @memset(huge, 0x30);
    try testing.expectError(error.InvalidCertificate, certificatePublicKey(huge));
}

test "fuzz: arbitrary bytes through the certificate parsers" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            smith.bytes(&buf);
            const n: usize = smith.valueRangeAtMost(u16, 0, buf.len);
            if (certificatePublicKey(buf[0..n])) |_| {} else |_| {}
            if (certificateValidity(buf[0..n])) |_| {} else |_| {}
            // Chunk-shaped input into the header scanner, same contract.
            _ = viewAsymmetricHeader(buf[0..n]);
        }
    }.run, .{});
}
