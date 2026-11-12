// SPDX-License-Identifier: MIT

//! Loading a server's certificate chain and private key from PEM — the
//! `CertifiedKey` a `Config` borrows. What `openssl` and the ACME clients
//! write: a chain of `CERTIFICATE` blocks (leaf first), and the key as
//! `EC PRIVATE KEY` (RFC 5915 / SEC1), `PRIVATE KEY` (PKCS#8, RFC 5958: EC on
//! P-256/P-384/P-521, Ed25519 per RFC 8410, RSA, or ML-DSA per RFC 9881 in
//! any of its three private-key forms) or `RSA PRIVATE KEY` (PKCS#1).
//! The key must belong to the leaf certificate (`KeyMismatch` otherwise, as
//! rustls's `CertifiedKey::keys_match` and Go's `tls.X509KeyPair` refuse).
//!
//! The PEM walk, the constant-time base64 decode and the strict DER read
//! of the key are `keycodec`'s (`parsePrivateKeyPem`): its block walk never
//! feeds a key body to a Boyer-Moore-Horspool scan, and its DER walk
//! branches on tags and lengths, i.e. on the key's (public) layout, not its
//! secret bytes. This file turns keycodec's parts into the key type that
//! signs, and checks what keycodec leaves to the key type: an ML-DSA `both`
//! key's halves agree, and the key belongs to the leaf.

const std = @import("std");
const delegated = @import("delegated.zig");
const keycodec = @import("keycodec");
const rsa = @import("rsa");
const x509 = @import("x509");
const p521 = @import("p521");
const certverify = @import("tls13").certverify;
const burn = @import("burn.zig");
const CertifiedKey = @import("server.zig").CertifiedKey;

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP521 = p521.EcdsaP521Sha512;
const Ed25519 = std.crypto.sign.Ed25519;
const mldsa = std.crypto.sign.mldsa;

pub const Error = error{
    OutOfMemory,
    /// No `CERTIFICATE` block in the chain text.
    MissingCertificate,
    /// No private-key block (`EC PRIVATE KEY`, `PRIVATE KEY`,
    /// `RSA PRIVATE KEY`) in the key text.
    MissingPrivateKey,
    /// A block without its END line, or a body that is not base64.
    InvalidPem,
    /// A certificate that `x509.spkiOf` cannot read.
    MalformedCertificate,
    /// The key's DER, or a scalar out of range.
    MalformedKey,
    /// A key this server cannot sign with: an encrypted key (PKCS#8 or the
    /// legacy `Proc-Type` form), an `OPENSSH PRIVATE KEY` block before any
    /// plain key block, a curve other than P-256/P-384/P-521, an algorithm
    /// other than EC, Ed25519, RSA and ML-DSA (an RSASSA-PSS key included),
    /// an ML-DSA key in the expanded-only form; or an RSA key under an
    /// id-RSASSA-PSS leaf.
    UnsupportedKey,
    /// The private key does not belong to the leaf certificate.
    KeyMismatch,
};

/// The longest key DER this reader takes: the largest PKCS#8 RSA key `rsa`
/// accepts, or an ML-DSA-87 key in the "both" form (seed and the 4,896-octet
/// expanded key); EC and Ed25519 keys are under 250 bytes.
pub const max_key_der_len: usize = @max(rsa.max_pkcs8_der_len, mldsa.MLDSA87.SecretKey.encoded_length + 128);

/// A private key held by value (RSA and ML-DSA by pointer: `rsa.SecretKey`
/// is 11.8 KiB, std's expanded ML-DSA keys 30-110 KiB).
pub const PrivateKey = union(enum) {
    ecdsa_p256: EcdsaP256.SecretKey,
    ecdsa_p384: EcdsaP384.SecretKey,
    ecdsa_p521: EcdsaP521.SecretKey,
    ed25519: Ed25519.SecretKey,
    rsa: *rsa.SecretKey,
    mldsa44: *mldsa.MLDSA44.SecretKey,
    mldsa65: *mldsa.MLDSA65.SecretKey,
    mldsa87: *mldsa.MLDSA87.SecretKey,
};

/// A certificate chain and its private key, owning both. `certifiedKey`
/// borrows from it (the EC and Ed25519 keys live inside the struct), so it
/// must not be moved or copied once `certifiedKey` has been called, and must
/// outlive every connection whose `Config` points into it. Load into a
/// pair that holds nothing (`fromPem` does not release a previous load).
pub const CertKeyPair = struct {
    /// Every certificate's DER, concatenated.
    der: []u8,
    /// Slices of `der`, leaf first.
    chain: [][]const u8,
    key: PrivateKey,
    /// An Ed25519 `key` prepared once at load (`certverify.Ed25519Signer`,
    /// public half checked against the seed): `certifiedKey` hands the server
    /// this, so a CertificateVerify is one base multiplication. Null for
    /// every other key type.
    ed25519_signer: ?certverify.Ed25519Signer = null,

    /// Loads `chain_pem` (one or more `CERTIFICATE` blocks; other blocks are
    /// skipped, so a combined key-and-chain file serves for both arguments)
    /// and the first private-key block of `key_pem` into `out`. On an error
    /// nothing is allocated and `out` is zeroed (`deinit` on it is then a
    /// no-op free of empty slices). Runs under a dead-stack burn
    /// (`burn.key_burn`): needs ~110 KiB of stack, more for an RSA key
    /// (`rsa` burns 200 KiB of its own) and much more for an ML-DSA one
    /// (`burn.mldsa_key_burn`: up to 1.3 MiB for ML-DSA-87) — call it from
    /// a thread with a normal-sized stack, not a small pool worker.
    pub fn fromPem(out: *CertKeyPair, gpa: std.mem.Allocator, chain_pem: []const u8, key_pem: []const u8) Error!void {
        return burn.run(burn.key_burn, Error!void, fromPemBody, .{ out, gpa, chain_pem, key_pem });
    }

    fn fromPemBody(out: *CertKeyPair, gpa: std.mem.Allocator, chain_pem: []const u8, key_pem: []const u8) Error!void {
        out.* = .{ .der = &.{}, .chain = &.{}, .key = .{ .ed25519 = undefined } };
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
        try loadChain(out, gpa, chain_pem);
        errdefer {
            gpa.free(out.chain);
            gpa.free(out.der);
        }
        try loadKey(&out.key, gpa, key_pem);
        errdefer wipeKey(&out.key, gpa);
        const spki = x509.spkiOf(out.chain[0]) catch return error.MalformedCertificate;
        try matches(&out.key, spki);
        try prepareSigner(out);
    }

    /// RFC 9345: as `fromPem`, for a delegated credential — the key is the
    /// credential's, so it must match `delegated_credential`'s
    /// SubjectPublicKeyInfo instead of the leaf's (`KeyMismatch`; a credential
    /// that does not parse is `MalformedKey`). The caller sets
    /// `CertifiedKey.delegated_credential` and calls `checkDelegated`.
    pub fn fromPemDelegated(out: *CertKeyPair, gpa: std.mem.Allocator, chain_pem: []const u8, key_pem: []const u8, delegated_credential: []const u8) Error!void {
        return burn.run(burn.key_burn, Error!void, fromPemDelegatedBody, .{ out, gpa, chain_pem, key_pem, delegated_credential });
    }

    fn fromPemDelegatedBody(out: *CertKeyPair, gpa: std.mem.Allocator, chain_pem: []const u8, key_pem: []const u8, delegated_credential: []const u8) Error!void {
        // First, so that every error path leaves `out` in the documented state.
        out.* = .{ .der = &.{}, .chain = &.{}, .key = .{ .ed25519 = undefined } };
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
        const c = delegated.parse(delegated_credential) catch return error.MalformedKey;
        const spki = x509.parseSpki(c.spki) catch return error.MalformedKey;
        try loadChain(out, gpa, chain_pem);
        errdefer {
            gpa.free(out.chain);
            gpa.free(out.der);
        }
        try loadKey(&out.key, gpa, key_pem);
        errdefer wipeKey(&out.key, gpa);
        try matches(&out.key, spki);
        try prepareSigner(out);
    }

    /// Wipes the key and frees everything.
    pub fn deinit(self: *CertKeyPair, gpa: std.mem.Allocator) void {
        wipeKey(&self.key, gpa);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.ed25519_signer));
        gpa.free(self.chain);
        gpa.free(self.der);
        self.* = undefined;
    }

    /// The `CertifiedKey` for `Config.certificate`, borrowing from `self`.
    /// secret-api-ok: returns pointers to the key held in `self` (`CertifiedKey.key` is a union of pointers), never key bytes.
    pub fn certifiedKey(self: *const CertKeyPair) CertifiedKey {
        if (self.ed25519_signer) |*signer| return .{ .chain = self.chain, .key = .{ .ed25519_prepared = signer } };
        return .{ .chain = self.chain, .key = switch (self.key) {
            .ecdsa_p256 => |*k| .{ .ecdsa_p256 = k },
            .ecdsa_p384 => |*k| .{ .ecdsa_p384 = k },
            .ecdsa_p521 => |*k| .{ .ecdsa_p521 = k },
            .ed25519 => |*k| .{ .ed25519 = k },
            .rsa => |k| .{ .rsa = k },
            .mldsa44 => |k| .{ .mldsa44 = k },
            .mldsa65 => |k| .{ .mldsa65 = k },
            .mldsa87 => |k| .{ .mldsa87 = k },
        } };
    }
};

/// Prepares the Ed25519 signer of a loaded `.ed25519` key (no-op otherwise).
/// The embedded public half is the seed's by construction here (`loadKey`
/// derives it), so `init` cannot fail on a key this module loaded.
fn prepareSigner(out: *CertKeyPair) Error!void {
    switch (out.key) {
        .ed25519 => |*k| out.ed25519_signer = certverify.Ed25519Signer.init(k) catch return error.KeyMismatch,
        else => {},
    }
}

fn wipeKey(key: *PrivateKey, gpa: std.mem.Allocator) void {
    switch (key.*) {
        .rsa => |k| {
            std.crypto.secureZero(u8, std.mem.asBytes(k));
            gpa.destroy(k);
        },
        inline .mldsa44, .mldsa65, .mldsa87 => |k| {
            std.crypto.secureZero(u8, std.mem.asBytes(k));
            gpa.destroy(k);
        },
        else => {},
    }
    std.crypto.secureZero(u8, std.mem.asBytes(key));
}

// ── the chain ───────────────────────────────────────────────────────────

fn loadChain(out: *CertKeyPair, gpa: std.mem.Allocator, text: []const u8) Error!void {
    // Two passes: sizes, then decode into one allocation.
    var count: usize = 0;
    var total: usize = 0;
    var it: keycodec.pem.Iterator = .init(text);
    while (try nextBlock(&it)) |b| if (std.mem.eql(u8, b.label, "CERTIFICATE")) {
        count += 1;
        total += b.decodedLenBound();
    };
    if (count == 0) return error.MissingCertificate;
    const der = try gpa.alloc(u8, total);
    errdefer gpa.free(der);
    const chain = try gpa.alloc([]const u8, count);
    errdefer gpa.free(chain);
    it = .init(text);
    var used: usize = 0;
    for (chain) |*c| {
        // The first pass walked the same text without an error.
        const block = while (nextBlock(&it) catch unreachable) |b| {
            if (std.mem.eql(u8, b.label, "CERTIFICATE")) break b;
        } else unreachable;
        // `decodedLenBound` sized `der`: NoSpaceLeft cannot happen.
        const d = block.decode(der[used..]) catch return error.InvalidPem;
        // Every certificate is sent to clients: each must have a
        // certificate's shape down to its public key (`x509.spkiOf`), not
        // merely be DER.
        _ = x509.spkiOf(d) catch return error.MalformedCertificate;
        c.* = d;
        used += d.len;
    }
    out.der = der;
    out.chain = chain;
}

fn nextBlock(it: *keycodec.pem.Iterator) Error!?keycodec.pem.Block {
    return it.next() catch error.InvalidPem;
}

// ── the private key ─────────────────────────────────────────────────────

/// The first private-key block of `text`, read by `keycodec` (block walk,
/// constant-time base64, strict DER, algorithm identifier, lengths, EC
/// scalar in [1, n)), then turned into the key type that signs.
fn loadKey(out: *PrivateKey, gpa: std.mem.Allocator, text: []const u8) Error!void {
    var der_buf: [max_key_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    const k = keycodec.parsePrivateKeyPem(text, &der_buf) catch |err| return switch (err) {
        error.MissingKey => error.MissingPrivateKey,
        error.InvalidPem => error.InvalidPem,
        // NoSpaceLeft: longer than any key this reader takes.
        error.MalformedKey, error.NoSpaceLeft => error.MalformedKey,
        // An encrypted key (PKCS#8 or the legacy `Proc-Type` form), an
        // `OPENSSH PRIVATE KEY` block, an algorithm outside keycodec's set.
        error.EncryptedKey, error.UnsupportedFormat, error.UnsupportedAlgorithm => error.UnsupportedKey,
    };
    switch (k.algorithm) {
        .ec_p256 => out.* = .{ .ecdsa_p256 = try ecScalar(EcdsaP256, &k) },
        .ec_p384 => out.* = .{ .ecdsa_p384 = try ecScalar(EcdsaP384, &k) },
        .ec_p521 => out.* = .{ .ecdsa_p521 = try ecScalar(EcdsaP521, &k) },
        .ed25519 => {
            const kp = Ed25519.KeyPair.generateDeterministic(k.secret[0..32].*) catch return error.MalformedKey;
            out.* = .{ .ed25519 = kp.secret_key };
        },
        // `secret` is the RSAPrivateKey (PKCS#1) DER in either encoding.
        .rsa => try loadRsa(out, gpa, k.secret),
        .ml_dsa_44 => try loadMlDsa(.mldsa44, out, gpa, &k),
        .ml_dsa_65 => try loadMlDsa(.mldsa65, out, gpa, &k),
        .ml_dsa_87 => try loadMlDsa(.mldsa87, out, gpa, &k),
        // secp256k1, Ed448, X25519/X448, RSASSA-PSS keys, ML-KEM: no
        // TLS 1.3 server signature with them here.
        .ec_secp256k1, .ed448, .x25519, .x448, .rsa_pss, .ml_kem_512, .ml_kem_768, .ml_kem_1024 => return error.UnsupportedKey,
    }
}

fn loadRsa(out: *PrivateKey, gpa: std.mem.Allocator, pkcs1: []const u8) Error!void {
    const k = try gpa.create(rsa.SecretKey);
    errdefer gpa.destroy(k);
    rsa.SecretKey.fromDer(k, pkcs1) catch return error.MalformedKey;
    out.* = .{ .rsa = k };
}

/// keycodec has checked the scalar is in [1, n); `fromBytes` takes it.
fn ecScalar(comptime E: type, k: *const keycodec.PrivateKey) Error!E.SecretKey {
    var bytes: [E.SecretKey.encoded_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    k.scalarInto(&bytes) catch return error.MalformedKey;
    return E.SecretKey.fromBytes(bytes) catch error.MalformedKey;
}

/// The std type behind an ML-DSA `PrivateKey` tag.
fn MlDsaOf(comptime tag: std.meta.Tag(PrivateKey)) type {
    return switch (tag) {
        .mldsa44 => mldsa.MLDSA44,
        .mldsa65 => mldsa.MLDSA65,
        .mldsa87 => mldsa.MLDSA87,
        else => @compileError("not an ML-DSA key"),
    };
}

fn loadMlDsa(comptime tag: std.meta.Tag(PrivateKey), out: *PrivateKey, gpa: std.mem.Allocator, key: *const keycodec.PrivateKey) Error!void {
    const M = MlDsaOf(tag);
    const k = try gpa.create(M.SecretKey);
    errdefer {
        std.crypto.secureZero(u8, std.mem.asBytes(k));
        gpa.destroy(k);
    }
    try burn.run(@field(burn.mldsa_key_burn, @tagName(tag)), Error!void, mlDsaExpand, .{ M, k, key });
    out.* = @unionInit(PrivateKey, @tagName(tag), k);
}

/// RFC 9881 §6's three forms, as keycodec reports them (lengths checked
/// there). The key is expanded from the seed; `both` must agree with its own
/// seed (OpenSSL refuses such a key too; keycodec leaves that to the key
/// type). `expandedKey` alone is `UnsupportedKey`: only its public half can
/// be checked against the leaf — a damaged `K`, `tr` or `t0` (std has no
/// call that recomputes them) would load and sign garbage or under another
/// key (found by the `tlsserver-keys` fuzz harness, 2026-10-21).
fn mlDsaExpand(comptime M: type, k: *M.SecretKey, key: *const keycodec.PrivateKey) Error!void {
    const form = key.pq_form orelse return error.MalformedKey;
    if (form == .expanded) return error.UnsupportedKey;
    if (key.secret.len != M.seed_length) return error.MalformedKey;
    k.* = M.newKeyFromSeed(key.secret[0..M.seed_length]).sk;
    if (form == .both) {
        if (key.expanded.len != M.SecretKey.encoded_length) return error.MalformedKey;
        var own = k.toBytes();
        defer std.crypto.secureZero(u8, &own);
        if (!std.crypto.timing_safe.eql([M.SecretKey.encoded_length]u8, own, key.expanded[0..M.SecretKey.encoded_length].*)) return error.MalformedKey;
    }
}

// ── the key against the leaf ────────────────────────────────────────────

fn matches(key: *const PrivateKey, spki: x509.Spki) Error!void {
    switch (key.*) {
        .ecdsa_p256 => |*k| try ecMatches(EcdsaP256, &x509.safe.oid_prime256v1, k, spki),
        .ecdsa_p384 => |*k| try ecMatches(EcdsaP384, &x509.safe.oid_secp384r1, k, spki),
        .ecdsa_p521 => |*k| try ecMatches(EcdsaP521, &x509.safe.oid_secp521r1, k, spki),
        inline .mldsa44, .mldsa65, .mldsa87 => |k, tag| try burn.run(@field(burn.mldsa_key_burn, @tagName(tag)), Error!void, mlDsaMatches, .{ MlDsaOf(tag), k, spki }),
        .ed25519 => |*k| {
            if (!spki.algorithmIs(&x509.safe.oid_ed25519)) return error.KeyMismatch;
            const public = k.publicKeyBytes();
            if (!std.mem.eql(u8, spki.key_bits, &public)) return error.KeyMismatch;
        },
        .rsa => |k| {
            if (spki.algorithmIs(&x509.safe.oid_rsassa_pss)) return error.UnsupportedKey; // an id-RSASSA-PSS leaf
            if (!spki.algorithmIs(&x509.safe.oid_rsa_encryption)) return error.KeyMismatch;
            const cert_key = rsa.PublicKey.fromDer(spki.der) catch return error.MalformedCertificate;
            const own = k.publicKey();
            if (!own.equal(&cert_key)) return error.KeyMismatch;
        },
    }
}

fn mlDsaMatches(comptime M: type, k: *const M.SecretKey, spki: x509.Spki) Error!void {
    const set = x509.MlDsa.map.get(spki.algorithm_oid) orelse return error.KeyMismatch;
    switch (set) {
        inline else => |s| if (x509.MlDsa.Impl(s) != M) return error.KeyMismatch,
    }
    if (spki.key_bits.len != M.PublicKey.encoded_length) return error.MalformedCertificate;
    var kp = M.KeyPair.fromSecretKey(k.*) catch return error.MalformedKey;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    if (!std.mem.eql(u8, &kp.public_key.toBytes(), spki.key_bits)) return error.KeyMismatch;
}

fn ecMatches(comptime E: type, curve_oid: []const u8, k: *const E.SecretKey, spki: x509.Spki) Error!void {
    if (!spki.algorithmIs(&x509.safe.oid_ec_public_key)) return error.KeyMismatch;
    const named = spki.namedCurveOid() orelse return error.KeyMismatch;
    if (!std.mem.eql(u8, named, curve_oid)) return error.KeyMismatch;
    const cert_point = E.PublicKey.fromSec1(spki.key_bits) catch return error.MalformedCertificate;
    var kp = E.KeyPair.fromSecretKey(k.*) catch return error.MalformedKey; // the zero scalar
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    if (!std.mem.eql(u8, &kp.public_key.toUncompressedSec1(), &cert_point.toUncompressedSec1())) return error.KeyMismatch;
}

// ── tests ───────────────────────────────────────────────────────────────

const testing = std.testing;
const key_vectors = @import("key_vectors.zig");

fn expectLoads(chain: []const u8, key: []const u8, kind: key_vectors.Kind) !void {
    var pair: CertKeyPair = undefined;
    try CertKeyPair.fromPem(&pair, testing.allocator, chain, key);
    defer pair.deinit(testing.allocator);
    try testing.expectEqualStrings(@tagName(kind), @tagName(std.meta.activeTag(pair.key)));
    try testing.expectEqual(@as(usize, 1), pair.chain.len);
    const ck = pair.certifiedKey();
    try testing.expectEqual(@as(usize, 1), ck.chain.len);
    // An Ed25519 key is handed to the server prepared (one base multiplication
    // per signature); every other kind stays the plain borrowed key.
    try testing.expectEqual(kind == .ed25519, std.meta.activeTag(ck.key.?) == .ed25519_prepared);
    if (kind == .ed25519) {
        var sig: [64]u8 = undefined;
        var plain: [64]u8 = undefined;
        const th: [32]u8 = @splat(5);
        _ = try certverify.sign(.ed25519, ck.key.?, .server, &th, null, &sig);
        _ = try certverify.sign(.ed25519, .{ .ed25519 = &pair.key.ed25519 }, .server, &th, null, &plain);
        try testing.expectEqualSlices(u8, &plain, &sig);
    }
}

test "every key form openssl writes loads and matches its certificate" {
    for (key_vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        try expectLoads(c.cert_pem, c.key_pem, c.kind);
    }
}

test "the key and the leaf must belong together" {
    // Every certificate against every other kind's key.
    for (key_vectors.cases) |c| for (key_vectors.cases) |k| {
        if (std.mem.eql(u8, c.cert_pem, k.cert_pem)) continue;
        var pair: CertKeyPair = undefined;
        errdefer std.debug.print("cert {s} key {s}\n", .{ c.name, k.name });
        try testing.expectError(error.KeyMismatch, CertKeyPair.fromPem(&pair, testing.allocator, c.cert_pem, k.key_pem));
    };
}

test "a key of the leaf's own kind but another key is refused" {
    // Two P-256 certificates: `test_certs`' and the vectors'.
    const p256_test_cert = "-----BEGIN CERTIFICATE-----\n" ++ comptime pemBody(&@import("test_certs.zig").p256_cert) ++ "-----END CERTIFICATE-----\n";
    var pair: CertKeyPair = undefined;
    for (key_vectors.cases) |c| if (c.kind == .ecdsa_p256) {
        try testing.expectError(error.KeyMismatch, CertKeyPair.fromPem(&pair, testing.allocator, p256_test_cert, c.key_pem));
    };
}

fn pemBody(comptime der: []const u8) []const u8 {
    @setEvalBranchQuota(100_000);
    var b64: [std.base64.standard.Encoder.calcSize(der.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64, der);
    var out: []const u8 = "";
    var rest: []const u8 = &b64;
    while (rest.len > 64) : (rest = rest[64..]) out = out ++ rest[0..64] ++ "\n";
    return out ++ rest ++ "\n";
}

test "a combined file, a chain of several, and blocks of other labels" {
    const c = key_vectors.cases[0];
    const combined = c.key_pem ++ "\n" ++ c.cert_pem ++ key_vectors.cases[2].cert_pem; // [2]: P-384
    var pair: CertKeyPair = undefined;
    try CertKeyPair.fromPem(&pair, testing.allocator, combined, combined);
    defer pair.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), pair.chain.len);
    try testing.expectEqual(std.meta.Tag(PrivateKey).ecdsa_p256, std.meta.activeTag(pair.key));
    // Each certificate decodes to the DER `x509` reads, in the text's order.
    _ = try x509.spkiOf(pair.chain[0]);
    const second = try x509.spkiOf(pair.chain[1]);
    try testing.expect(second.algorithmIs(&x509.safe.oid_ec_public_key));
    try testing.expectEqualSlices(u8, &x509.safe.oid_secp384r1, second.namedCurveOid().?);
}

fn armouredTest(comptime label: []const u8, comptime der: []const u8) []const u8 {
    return "-----BEGIN " ++ label ++ "-----\n" ++ comptime pemBody(der) ++ "-----END " ++ label ++ "-----\n";
}

test "an EC scalar of zero, the order or above is MalformedKey (independent review M1)" {
    const c = key_vectors.cases[0]; // P-256 SEC1, for its certificate
    const n256 = "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51";
    const n256_plus1 = n256[0..31] ++ "\x52";
    const zero: [32]u8 = @splat(0);
    var pair: CertKeyPair = undefined;
    inline for (.{ n256, n256_plus1, zero }) |d| {
        // ECPrivateKey { 1, OCTET STRING d, [0] prime256v1 }
        const der = "\x30\x31\x02\x01\x01\x04\x20" ++ d ++ "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, testing.allocator, c.cert_pem, armouredTest("EC PRIVATE KEY", der)));
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&pair), 0));
    }
}

test "PEM framing: CRLF, a malformed END never swallows the next block, legacy encryption, junk intermediates" {
    const c = key_vectors.cases[0];
    const gpa = testing.allocator;
    var pair: CertKeyPair = undefined;
    // CRLF line endings throughout.
    {
        var crlf_key: std.ArrayList(u8) = .empty;
        defer crlf_key.deinit(gpa);
        var crlf_cert: std.ArrayList(u8) = .empty;
        defer crlf_cert.deinit(gpa);
        for (c.key_pem) |ch| if (ch == '\n') try crlf_key.appendSlice(gpa, "\r\n") else try crlf_key.append(gpa, ch);
        for (c.cert_pem) |ch| if (ch == '\n') try crlf_cert.appendSlice(gpa, "\r\n") else try crlf_cert.append(gpa, ch);
        try CertKeyPair.fromPem(&pair, gpa, crlf_cert.items, crlf_key.items);
        pair.deinit(gpa);
    }
    // A block whose END line is cut short: refused, not merged with the
    // certificate after it.
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, "-----BEGIN FOO-----\nAAAA\n-----END FOO\n" ++ c.cert_pem, c.key_pem));
    // END naming another label.
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
    // Legacy (RFC 1421) encrypted key.
    try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem,
        \\-----BEGIN EC PRIVATE KEY-----
        \\Proc-Type: 4,ENCRYPTED
        \\DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF
        \\
        \\AAAA
        \\-----END EC PRIVATE KEY-----
        \\
    ));
    // A second "certificate" that is not one.
    try testing.expectError(error.MalformedCertificate, CertKeyPair.fromPem(&pair, gpa, c.cert_pem ++ "\n-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n", c.key_pem));
}

fn loadForAllocSweep(gpa: std.mem.Allocator, chain: []const u8, key: []const u8) !void {
    var pair: CertKeyPair = undefined;
    try CertKeyPair.fromPem(&pair, gpa, chain, key);
    pair.deinit(gpa);
}

test "every allocation failure is clean (no leak, no double free), every key form" {
    for (key_vectors.cases) |c| {
        try testing.checkAllAllocationFailures(testing.allocator, loadForAllocSweep, .{ c.cert_pem, c.key_pem });
    }
}

test "refusals: no blocks, encrypted keys, other curves, expanded-only ML-DSA, damaged PEM" {
    const c = key_vectors.cases[0];
    var pair: CertKeyPair = undefined;
    const gpa = testing.allocator;
    try testing.expectError(error.MissingCertificate, CertKeyPair.fromPem(&pair, gpa, c.key_pem, c.key_pem));
    try testing.expectError(error.MissingPrivateKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, c.cert_pem));
    try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, key_vectors.encrypted_pem));
    try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, key_vectors.k256_pem));
    for (key_vectors.cases) |m| if (m.kind == .mldsa44) {
        try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, m.cert_pem, key_vectors.mldsa44_expanded_pem));
    };
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n"));
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, "-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n"));
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
}

test "ML-DSA: a `both` key whose expanded half is not its seed's is MalformedKey" {
    for (key_vectors.cases) |c| if (c.kind == .mldsa44 and std.mem.endsWith(u8, c.name, "-both")) {
        const label, const body = blk: {
            var it: keycodec.pem.Iterator = .init(c.key_pem);
            const b = (try it.next()).?;
            break :blk .{ b.label, b };
        };
        var der_buf: [max_key_der_len]u8 = undefined;
        const der = try body.decode(&der_buf);
        der[der.len - 1] ^= 0x01; // the last octet of t0
        var b64: [2 * max_key_der_len]u8 = undefined;
        const text = std.base64.standard.Encoder.encode(&b64, der);
        var pem: std.ArrayList(u8) = .empty;
        defer pem.deinit(testing.allocator);
        try pem.print(testing.allocator, "-----BEGIN {s}-----\n{s}\n-----END {s}-----\n", .{ label, text, label });
        var pair: CertKeyPair = undefined;
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, testing.allocator, c.cert_pem, pem.items));
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&pair), 0));
    };
}

test "ML-DSA: a seed-form key with anything after the seed is MalformedKey" {
    for (key_vectors.cases) |c| if (c.kind == .mldsa44 and std.mem.endsWith(u8, c.name, "-seed")) {
        var it: keycodec.pem.Iterator = .init(c.key_pem);
        const b = (try it.next()).?;
        var der_buf: [max_key_der_len]u8 = undefined;
        const der = try b.decode(&der_buf);
        // PrivateKeyInfo { 0, AlgorithmIdentifier, OCTET STRING { [0] seed } }:
        // grow the OCTET STRING (and the SEQUENCE) by an empty OCTET STRING.
        try testing.expectEqual(@as(usize, 54), der.len);
        var grown: [56]u8 = undefined;
        @memcpy(grown[0..54], der);
        grown[54] = 0x04;
        grown[55] = 0x00;
        grown[1] += 2; // SEQUENCE length
        grown[19] += 2; // OCTET STRING length
        var b64: [128]u8 = undefined;
        const text = std.base64.standard.Encoder.encode(&b64, &grown);
        var pem_buf: [256]u8 = undefined;
        const pem = try std.fmt.bufPrint(&pem_buf, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----\n", .{text});
        var pair: CertKeyPair = undefined;
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, testing.allocator, c.cert_pem, pem));
    };
}

/// The DER of the first block of `pem_text` (a test vector).
fn vectorDer(buf: []u8, pem_text: []const u8) ![]u8 {
    var it: keycodec.pem.Iterator = .init(pem_text);
    const b = (try it.next()).?;
    return b.decode(buf);
}

/// `tag len content` with a one- or two-octet DER length.
fn tlv(out: []u8, tag: u8, content: []const u8) []u8 {
    out[0] = tag;
    if (content.len < 0x80) {
        out[1] = @intCast(content.len);
        @memcpy(out[2..][0..content.len], content);
        return out[0 .. 2 + content.len];
    }
    out[1] = 0x81;
    out[2] = @intCast(content.len);
    @memcpy(out[3..][0..content.len], content);
    return out[0 .. 3 + content.len];
}

fn pkcs8Pem(out: []u8, der: []const u8) ![]u8 {
    return keycodec.pem.encode(out, "PRIVATE KEY", der);
}

test "keycodec edges: OPENSSH block, RSASSA-PSS key, PKCS#8 EC without curve parameters, trailing PKCS#8 fields" {
    const gpa = testing.allocator;
    var pair: CertKeyPair = undefined;
    const c = key_vectors.cases[0]; // p256-sec1
    // An OPENSSH block before the key is refused; after the key the key loads.
    const openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, openssh ++ c.key_pem));
    try expectLoads(c.cert_pem, c.key_pem ++ openssh, .ecdsa_p256);

    // An RSA key under the RSASSA-PSS OID is UnsupportedKey (not MalformedKey, not loaded as RSA).
    for (key_vectors.cases) |r| if (std.mem.eql(u8, r.name, "rsa-pkcs1")) {
        var der_buf: [max_key_der_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &der_buf);
        const k = try keycodec.parsePrivateKeyPem(r.key_pem, &der_buf);
        var pss = k;
        pss.algorithm = .rsa_pss;
        pss.encoding = .pkcs8;
        var pem_buf: [keycodec.max_private_pem_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &pem_buf);
        const text = try keycodec.writePrivateKeyPem(&pem_buf, pss);
        try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPem(&pair, gpa, r.cert_pem, text));
    };

    // A certificate block whose body is not base64, or empty, is InvalidPem.
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", c.key_pem));
    try testing.expectError(error.InvalidPem, CertKeyPair.fromPem(&pair, gpa, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", c.key_pem));

    // PrivateKeyInfo { 0, { id-ecPublicKey }, OCTET STRING { SEC1 with [0] } }: the curve
    // comes from the inner [0] (Go's ParsePKCS8PrivateKey does the same).
    var sec1_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &sec1_buf);
    const sec1 = try vectorDer(&sec1_buf, c.key_pem[std.mem.find(u8, c.key_pem, "-----BEGIN EC PRIVATE").?..]);
    var ver_buf: [8]u8 = undefined;
    var alg_buf: [32]u8 = undefined;
    var oct_buf: [260]u8 = undefined;
    var body: [300]u8 = undefined;
    var info_buf: [310]u8 = undefined;
    var pem_buf: [512]u8 = undefined;
    const ver = tlv(&ver_buf, 0x02, "\x00");
    const alg = tlv(&alg_buf, 0x30, "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01");
    const oct = tlv(&oct_buf, 0x04, sec1);
    @memcpy(body[0..ver.len], ver);
    @memcpy(body[ver.len..][0..alg.len], alg);
    @memcpy(body[ver.len + alg.len ..][0..oct.len], oct);
    const n = ver.len + alg.len + oct.len;
    {
        const info = tlv(&info_buf, 0x30, body[0..n]);
        try expectLoads(c.cert_pem, try pkcs8Pem(&pem_buf, info), .ecdsa_p256);
    }
    // A field after the optional attributes / publicKey is MalformedKey (strict DER, nothing trailing).
    {
        @memcpy(body[n..][0..2], "\x05\x00");
        const info = tlv(&info_buf, 0x30, body[0 .. n + 2]);
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, try pkcs8Pem(&pem_buf, info)));
    }
    // Trailing bytes after the whole PrivateKeyInfo are MalformedKey too.
    {
        var info2: [320]u8 = undefined;
        const info = tlv(&info_buf, 0x30, body[0..n]);
        @memcpy(info2[0..info.len], info);
        info2[info.len] = 0;
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, gpa, c.cert_pem, try pkcs8Pem(&pem_buf, info2[0 .. info.len + 1])));
    }
}

test "fromPemDelegated: an early error (bad credential) leaves out zeroed and deinit-safe" {
    const c = key_vectors.cases[0];
    var pair: CertKeyPair = undefined;
    @memset(std.mem.asBytes(&pair), 0xaa);
    try testing.expectError(error.MalformedKey, CertKeyPair.fromPemDelegated(&pair, testing.allocator, c.cert_pem, c.key_pem, "junk"));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&pair), 0));
    pair.deinit(testing.allocator);
}

test "fromPemDelegated: an Ed25519 credential key is prepared at load like fromPem's, other kinds are not" {
    for (key_vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        // A credential for the very key (parse and SPKI match only; the signature is checked by `delegated.check`).
        var plain: CertKeyPair = undefined;
        try CertKeyPair.fromPem(&plain, testing.allocator, c.cert_pem, c.key_pem);
        defer plain.deinit(testing.allocator);
        const spki = try x509.spkiOf(plain.chain[0]);
        var cred: [4 + 2 + 3 + 4096 + 4 + 1]u8 = undefined;
        std.mem.writeInt(u32, cred[0..4], 60, .big);
        std.mem.writeInt(u16, cred[4..6], 0x0807, .big);
        std.mem.writeInt(u24, cred[6..9], @intCast(spki.der.len), .big);
        @memcpy(cred[9..][0..spki.der.len], spki.der);
        const at = 9 + spki.der.len;
        std.mem.writeInt(u16, cred[at..][0..2], 0x0807, .big);
        std.mem.writeInt(u16, cred[at + 2 ..][0..2], 1, .big);
        cred[at + 4] = 0;

        var pair: CertKeyPair = undefined;
        try CertKeyPair.fromPemDelegated(&pair, testing.allocator, c.cert_pem, c.key_pem, cred[0 .. at + 5]);
        defer pair.deinit(testing.allocator);
        try testing.expectEqual(c.kind == .ed25519, pair.ed25519_signer != null);
        const ck = pair.certifiedKey();
        try testing.expectEqual(c.kind == .ed25519, std.meta.activeTag(ck.key.?) == .ed25519_prepared);
        if (c.kind == .ed25519) {
            var sig: [64]u8 = undefined;
            var want: [64]u8 = undefined;
            const th: [32]u8 = @splat(7);
            _ = try certverify.sign(.ed25519, ck.key.?, .server, &th, null, &sig);
            _ = try certverify.sign(.ed25519, .{ .ed25519 = &pair.key.ed25519 }, .server, &th, null, &want);
            try testing.expectEqualSlices(u8, &want, &sig);
        }
    }
}

// ── wave 2 of the whole-module mutation run, 2026-11-06 ──────────────────

const builtin = @import("builtin");

/// `Allocator.free` poisons a block in Debug and ReleaseSafe before the backend sees it, so
/// a missing wipe is visible to `Spy` in the optimized modes only.
fn optimizedOnly() !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
}

/// Passes through to `child`; on every `free` of a block of `watch_len` bytes it records
/// whether the bytes were all zero (a secret must be wiped BEFORE it is freed).
const Spy = struct {
    child: std.mem.Allocator,
    watch_len: usize,
    zero_frees: usize = 0,
    dirty_frees: usize = 0,

    fn allocator(s: *Spy) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        return s.child.rawAlloc(len, alignment, ra);
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const s: *Spy = @ptrCast(@alignCast(ctx));
        if (memory.len == s.watch_len) {
            if (std.mem.allEqual(u8, memory, 0)) s.zero_frees += 1 else s.dirty_frees += 1;
        }
        s.child.rawFree(memory, alignment, ra);
    }
};

fn heapKeySize(kind: key_vectors.Kind) ?usize {
    return switch (kind) {
        .rsa => @sizeOf(rsa.SecretKey),
        .mldsa44 => @sizeOf(mldsa.MLDSA44.SecretKey),
        .mldsa65 => @sizeOf(mldsa.MLDSA65.SecretKey),
        .mldsa87 => @sizeOf(mldsa.MLDSA87.SecretKey),
        else => null,
    };
}

/// A DelegatedCredential for `spki` (parses; the signature is not checked here).
fn credFor(out: []u8, spki: []const u8) []u8 {
    std.mem.writeInt(u32, out[0..4], 60, .big);
    std.mem.writeInt(u16, out[4..6], 0x0807, .big);
    std.mem.writeInt(u24, out[6..9], @intCast(spki.len), .big);
    @memcpy(out[9..][0..spki.len], spki);
    const at = 9 + spki.len;
    std.mem.writeInt(u16, out[at..][0..2], 0x0807, .big);
    std.mem.writeInt(u16, out[at + 2 ..][0..2], 1, .big);
    out[at + 4] = 0;
    return out[0 .. at + 5];
}

/// A DER SubjectPublicKeyInfo of `alg_oid` (content octets), `params` (a whole element or
/// nothing) and `bits`; every length fits one octet.
fn spkiOfParts(out: []u8, alg_oid: []const u8, params: []const u8, bits: []const u8) []u8 {
    const alg_len = 2 + alg_oid.len + params.len;
    const total = 2 + 2 + alg_len + 2 + 1 + bits.len;
    out[0] = 0x30;
    out[1] = @intCast(total - 2);
    out[2] = 0x30;
    out[3] = @intCast(alg_len);
    out[4] = 0x06;
    out[5] = @intCast(alg_oid.len);
    @memcpy(out[6..][0..alg_oid.len], alg_oid);
    @memcpy(out[6 + alg_oid.len ..][0..params.len], params);
    const at = 6 + alg_oid.len + params.len;
    out[at] = 0x03;
    out[at + 1] = @intCast(1 + bits.len);
    out[at + 2] = 0;
    @memcpy(out[at + 3 ..][0..bits.len], bits);
    return out[0 .. at + 3 + bits.len];
}

test "wave 2: the heap key of RSA and ML-DSA is zero when freed, after deinit and on every failed load" {
    try optimizedOnly();
    const other = key_vectors.cases[0]; // a P-256 certificate: no RSA or ML-DSA key belongs to it
    var spki_buf: [2048]u8 = undefined;
    const other_spki = (try x509.spkiOf(try firstDer(&spki_buf, other.cert_pem))).der;
    for (key_vectors.cases) |c| {
        const watch = heapKeySize(c.kind) orelse continue;
        errdefer std.debug.print("case {s}\n", .{c.name});
        var spy: Spy = .{ .child = testing.allocator, .watch_len = watch };
        var pair: CertKeyPair = undefined;
        try CertKeyPair.fromPem(&pair, spy.allocator(), c.cert_pem, c.key_pem);
        pair.deinit(spy.allocator());
        try testing.expectEqual(@as(usize, 1), spy.zero_frees);
        try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
        // The key does not belong to the certificate: the loaded key is wiped before it is freed.
        try testing.expectError(error.KeyMismatch, CertKeyPair.fromPem(&pair, spy.allocator(), other.cert_pem, c.key_pem));
        try testing.expectEqual(@as(usize, 2), spy.zero_frees);
        var cred: [200]u8 = undefined;
        try testing.expectError(error.KeyMismatch, CertKeyPair.fromPemDelegated(&pair, spy.allocator(), c.cert_pem, c.key_pem, credFor(&cred, other_spki)));
        try testing.expectEqual(@as(usize, 3), spy.zero_frees);
        try testing.expectEqual(@as(usize, 0), spy.dirty_frees);
    }
}

/// The DER of the first block of `pem_text`, into `buf`.
fn firstDer(buf: []u8, pem_text: []const u8) ![]u8 {
    var it: keycodec.pem.Iterator = .init(pem_text);
    return (try it.next()).?.decode(buf);
}

test "wave 2: wipeKey zeroes the key it was given, whatever its kind" {
    const seed: [32]u8 = @splat(5);
    var k: PrivateKey = .{ .ed25519 = (Ed25519.KeyPair.generateDeterministic(seed) catch unreachable).secret_key };
    wipeKey(&k, testing.allocator);
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&k), 0));
    k = .{ .ecdsa_p256 = EcdsaP256.SecretKey.fromBytes(@splat(1)) catch unreachable };
    wipeKey(&k, testing.allocator);
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&k), 0));
    k = .{ .ecdsa_p384 = EcdsaP384.SecretKey.fromBytes(@splat(1)) catch unreachable };
    wipeKey(&k, testing.allocator);
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&k), 0));
}

test "wave 2: deinit zeroes the prepared Ed25519 signer (read through volatile: deinit then marks the pair undefined)" {
    try optimizedOnly();
    for (key_vectors.cases) |c| if (c.kind == .ed25519) {
        const p = try testing.allocator.create(CertKeyPair);
        defer testing.allocator.destroy(p);
        try CertKeyPair.fromPem(p, testing.allocator, c.cert_pem, c.key_pem);
        try testing.expect(p.ed25519_signer != null);
        p.deinit(testing.allocator);
        const bytes: [*]const volatile u8 = @ptrCast(&p.ed25519_signer);
        for (0..@sizeOf(@TypeOf(p.ed25519_signer))) |i| try testing.expectEqual(@as(u8, 0), bytes[i]);
    };
}

test "wave 2: fromPemDelegated — the credential's key against the loaded key: each refusal has its own error" {
    const gpa = testing.allocator;
    var pair: CertKeyPair = undefined;
    var cred: [400]u8 = undefined;
    var sb: [400]u8 = undefined;
    var der_buf: [16384]u8 = undefined; // an ML-DSA-87 certificate is ~7.5 KiB
    const rsa_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    const ec_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
    const p256_oid = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    for (key_vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const leaf_spki = try x509.spkiOf(try firstDer(&der_buf, c.cert_pem));
        switch (c.kind) {
            .rsa => {
                // A credential whose RSA key is not DER; an id-RSASSA-PSS key; another RSA key.
                try testing.expectError(error.MalformedCertificate, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, rsa_oid, "\x05\x00", &.{ 1, 2, 3, 4, 5, 6, 7, 8 }))));
                try testing.expectError(error.UnsupportedKey, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a", "", &.{ 1, 2, 3 }))));
                var big: [600]u8 = undefined;
                @memcpy(big[0..leaf_spki.der.len], leaf_spki.der);
                big[leaf_spki.der.len - 50] ^= 0x10; // inside the modulus
                var cred_big: [700]u8 = undefined;
                try testing.expectError(error.KeyMismatch, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred_big, big[0..leaf_spki.der.len])));
            },
            .mldsa44 => {
                // The right algorithm, a public key of three octets.
                try testing.expectError(error.MalformedCertificate, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, "\x60\x86\x48\x01\x65\x03\x04\x03\x11", "", &.{ 1, 2, 3 }))));
            },
            .ed25519 => {
                // Not an Ed25519 algorithm, though the key bits are the key's.
                try testing.expectError(error.KeyMismatch, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, "\x2a\x03", "", leaf_spki.key_bits))));
            },
            .ecdsa_p256 => {
                // id-ecDH (not id-ecPublicKey) over the very key; a point that is not on the curve.
                try testing.expectError(error.KeyMismatch, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, "\x2b\x81\x04\x01\x0c", p256_oid, leaf_spki.key_bits))));
                var point: [65]u8 = @splat(1);
                point[0] = 4;
                try testing.expectError(error.MalformedCertificate, CertKeyPair.fromPemDelegated(&pair, gpa, c.cert_pem, c.key_pem, credFor(&cred, spkiOfParts(&sb, ec_oid, p256_oid, &point))));
            },
            else => {},
        }
    }
    // A credential whose SubjectPublicKeyInfo is not DER.
    const c0 = key_vectors.cases[0];
    try testing.expectError(error.MalformedKey, CertKeyPair.fromPemDelegated(&pair, gpa, c0.cert_pem, c0.key_pem, credFor(&cred, &.{ 1, 2 })));
}

test "wave 2: an RSA key keycodec reads but rsa refuses is MalformedKey" {
    for (key_vectors.cases) |r| if (r.kind == .rsa) {
        var der_buf: [max_key_der_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &der_buf);
        const k = try keycodec.parsePrivateKeyPem(r.key_pem, &der_buf);
        // The last octet of the PKCS#1 DER is the CRT coefficient's.
        const secret: []u8 = @constCast(k.secret);
        secret[secret.len - 1] ^= 1;
        var pem_buf: [keycodec.max_private_pem_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &pem_buf);
        const text = try keycodec.writePrivateKeyPem(&pem_buf, k);
        var pair: CertKeyPair = undefined;
        try testing.expectError(error.MalformedKey, CertKeyPair.fromPem(&pair, testing.allocator, r.cert_pem, text));
        return;
    };
}

test "wave 4: an EC key against a certificate that holds another kind of key is a KeyMismatch" {
    const certs = @import("test_certs.zig");
    const E = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const sk = try E.SecretKey.fromBytes(certs.p256_scalar);
    const spki = try x509.spkiOf(&certs.rsa2048_cert);
    try testing.expectError(error.KeyMismatch, ecMatches(E, &.{ 0x2a, 0x86, 0x48 }, &sk, spki));
}

test "wave 4: an EC key of another curve than the certificate's is a KeyMismatch" {
    const certs = @import("test_certs.zig");
    const E = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const sk = try E.SecretKey.fromBytes(certs.p384_scalar);
    const spki = try x509.spkiOf(&certs.p256_cert);
    // P-384's OID (1.3.132.0.34) against a P-256 certificate.
    try testing.expectError(error.KeyMismatch, ecMatches(E, &.{ 0x2b, 0x81, 0x04, 0x00, 0x22 }, &sk, spki));
}
