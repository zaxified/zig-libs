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
//! The key's PEM body is decoded in constant time (`b64ct`) into a wiped
//! stack buffer; the block search walks the text block by block so a key
//! stored before or after the chain is never fed to a Boyer-Moore-Horspool
//! scan (the `acme` key reader's approach, `acme/src/x509.zig`
//! `pemBlockStart`). The DER walk branches on tags and lengths, i.e. on the
//! key's (public) layout, not its secret bytes.
//!
//! zig-libs request: x509 — no shared private-key reader (SEC1 / PKCS#8 EC
//! and Ed25519); `acme` and this file each carry one (backlog in
//! `modules/x509/SPEC.md`).

const std = @import("std");
const delegated = @import("delegated.zig");
const b64ct = @import("b64ct");
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
    /// legacy `Proc-Type` form), a curve other than P-256/P-384/P-521, an
    /// algorithm other than EC, Ed25519, RSA and ML-DSA; or an RSA key under
    /// an id-RSASSA-PSS leaf.
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
    }

    /// Wipes the key and frees everything.
    pub fn deinit(self: *CertKeyPair, gpa: std.mem.Allocator) void {
        wipeKey(&self.key, gpa);
        gpa.free(self.chain);
        gpa.free(self.der);
        self.* = undefined;
    }

    /// The `CertifiedKey` for `Config.certificate`, borrowing from `self`.
    /// secret-api-ok: returns pointers to the key held in `self` (`CertifiedKey.key` is a union of pointers), never key bytes.
    pub fn certifiedKey(self: *const CertKeyPair) CertifiedKey {
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
    var it: BlockIterator = .{ .text = text };
    while (try it.next()) |b| if (std.mem.eql(u8, b.label, "CERTIFICATE")) {
        count += 1;
        total += b64ct.standard.maxDecodedLen(b.body.len);
    };
    if (count == 0) return error.MissingCertificate;
    const der = try gpa.alloc(u8, total);
    errdefer gpa.free(der);
    const chain = try gpa.alloc([]const u8, count);
    errdefer gpa.free(chain);
    it = .{ .text = text };
    var used: usize = 0;
    for (chain) |*c| {
        // The first pass walked the same text without an error.
        const body = while (it.next() catch unreachable) |b| {
            if (std.mem.eql(u8, b.label, "CERTIFICATE")) break b.body;
        } else unreachable;
        const d = b64ct.standard.decodeIgnoring(der[used..], body, b64ct.pem_whitespace) catch return error.InvalidPem;
        if (d.len == 0) return error.InvalidPem;
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

/// Every `-----BEGIN <label>-----` block of `text`, in order: its label and
/// body. The END line must name the same label (a malformed END is
/// `InvalidPem`, never a block that swallows the next BEGIN). A body is
/// crossed with a scan for its END line's first `-`, which no base64
/// character equals, so a key body is never read character by character by
/// a Boyer-Moore-Horspool search. A legacy encrypted key (RFC 1421 headers,
/// `Proc-Type: 4,ENCRYPTED`) is reported with `encrypted` set.
const BlockIterator = struct {
    text: []const u8,
    pos: usize = 0,

    const Block = struct { label: []const u8, body: []const u8, encrypted: bool };

    fn next(it: *BlockIterator) Error!?Block {
        const begin = "-----BEGIN ";
        const end = "-----END ";
        const dashes = "-----";
        const bi = std.mem.findPos(u8, it.text, it.pos, begin) orelse return null;
        const label_start = bi + begin.len;
        const label_end = std.mem.findPos(u8, it.text, label_start, dashes) orelse return error.InvalidPem;
        const label = it.text[label_start..label_end];
        if (std.mem.findScalar(u8, label, '\n') != null) return error.InvalidPem;
        const line_end = std.mem.findScalarPos(u8, it.text, label_end, '\n') orelse return error.InvalidPem;
        var body_start = line_end + 1;
        var encrypted = false;
        if (std.mem.startsWith(u8, it.text[body_start..], "Proc-Type:")) {
            // RFC 1421 headers: public text, up to the first empty line.
            encrypted = true;
            while (true) {
                const eol = std.mem.findScalarPos(u8, it.text, body_start, '\n') orelse return error.InvalidPem;
                const line = std.mem.trimEnd(u8, it.text[body_start..eol], "\r");
                body_start = eol + 1;
                if (line.len == 0) break;
            }
        }
        const body_end = std.mem.findScalarPos(u8, it.text, body_start, '-') orelse return error.InvalidPem;
        const tail = it.text[body_end..];
        if (!std.mem.startsWith(u8, tail, end) or !std.mem.startsWith(u8, tail[end.len..], label) or
            !std.mem.startsWith(u8, tail[end.len + label.len ..], dashes)) return error.InvalidPem;
        // Past the END marker, not its line: `cat` of files without a final
        // newline puts the next BEGIN on the same line.
        it.pos = body_end + end.len + label.len + dashes.len;
        return .{ .label = label, .body = it.text[body_start..body_end], .encrypted = encrypted };
    }
};

// ── the private key ─────────────────────────────────────────────────────

const KeyLabel = enum { sec1, pkcs8, pkcs1, encrypted };

const key_labels = [_]struct { []const u8, KeyLabel }{
    .{ "EC PRIVATE KEY", .sec1 },
    .{ "PRIVATE KEY", .pkcs8 },
    .{ "RSA PRIVATE KEY", .pkcs1 },
    .{ "ENCRYPTED PRIVATE KEY", .encrypted },
};

/// The first private-key block of `text`: its form and body.
fn findKeyBlock(text: []const u8) Error!struct { KeyLabel, []const u8 } {
    var it: BlockIterator = .{ .text = text };
    while (try it.next()) |b| for (key_labels) |l| {
        if (std.mem.eql(u8, b.label, l[0])) return .{ if (b.encrypted) .encrypted else l[1], b.body };
    };
    return error.MissingPrivateKey;
}

fn loadKey(out: *PrivateKey, gpa: std.mem.Allocator, text: []const u8) Error!void {
    const form, const body = try findKeyBlock(text);
    if (form == .encrypted) return error.UnsupportedKey;
    var der_buf: [max_key_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);
    const der = b64ct.standard.decodeIgnoring(&der_buf, body, b64ct.pem_whitespace) catch |err| return switch (err) {
        error.NoSpaceLeft => error.MalformedKey, // longer than any key this reader takes
        else => error.InvalidPem,
    };
    if (der.len == 0) return error.InvalidPem;
    switch (form) {
        .pkcs1 => try loadRsa(out, gpa, der, .pkcs1),
        .sec1 => try ecFromSec1(out, der, null),
        .pkcs8 => try fromPkcs8(out, gpa, der),
        .encrypted => unreachable,
    }
}

fn loadRsa(out: *PrivateKey, gpa: std.mem.Allocator, der: []const u8, comptime form: enum { pkcs1, pkcs8 }) Error!void {
    const k = try gpa.create(rsa.SecretKey);
    errdefer gpa.destroy(k);
    (switch (form) {
        .pkcs1 => rsa.SecretKey.fromDer(k, der),
        .pkcs8 => rsa.fromPkcs8(k, der),
    }) catch return error.MalformedKey;
    out.* = .{ .rsa = k };
}

const Curve = enum { p256, p384, p521 };

fn curveOf(oid: []const u8) Error!Curve {
    if (std.mem.eql(u8, oid, &x509.safe.oid_prime256v1)) return .p256;
    if (std.mem.eql(u8, oid, &x509.safe.oid_secp384r1)) return .p384;
    if (std.mem.eql(u8, oid, &x509.safe.oid_secp521r1)) return .p521;
    return error.UnsupportedKey;
}

/// PrivateKeyInfo / OneAsymmetricKey ::= SEQUENCE { version 0|1,
/// AlgorithmIdentifier, privateKey OCTET STRING, ... } (RFC 5958); trailing
/// attributes and the v1 public key are ignored (the leaf check covers it).
fn fromPkcs8(out: *PrivateKey, gpa: std.mem.Allocator, der: []const u8) Error!void {
    var top = try Der.init(der);
    var info = try top.seq();
    try top.end();
    const version = try info.expect(0x02);
    if (version.len != 1 or version[0] > 1) return error.MalformedKey;
    var alg = try info.seqOf();
    const oid = try alg.expect(0x06);
    const private = try info.expect(0x04);
    if (std.mem.eql(u8, oid, &x509.safe.oid_ec_public_key)) {
        const curve = try curveOf(try alg.expect(0x06));
        try alg.end();
        return ecFromSec1(out, private, curve);
    }
    if (std.mem.eql(u8, oid, &x509.safe.oid_ed25519)) {
        try alg.end(); // RFC 8410 §3: parameters MUST be absent
        // CurvePrivateKey ::= OCTET STRING (the 32-byte seed).
        var inner = try Der.init(private);
        const seed = try inner.expect(0x04);
        try inner.end();
        if (seed.len != 32) return error.MalformedKey;
        const kp = Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return error.MalformedKey;
        out.* = .{ .ed25519 = kp.secret_key };
        return;
    }
    if (std.mem.eql(u8, oid, &x509.safe.oid_rsa_encryption)) return loadRsa(out, gpa, der, .pkcs8);
    if (x509.MlDsa.map.get(oid)) |set| {
        try alg.end(); // RFC 9881 §2: parameters MUST be absent
        return switch (set) {
            .ml_dsa_44 => loadMlDsa(.mldsa44, out, gpa, private),
            .ml_dsa_65 => loadMlDsa(.mldsa65, out, gpa, private),
            .ml_dsa_87 => loadMlDsa(.mldsa87, out, gpa, private),
        };
    }
    return error.UnsupportedKey;
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

fn loadMlDsa(comptime tag: std.meta.Tag(PrivateKey), out: *PrivateKey, gpa: std.mem.Allocator, private: []const u8) Error!void {
    const M = MlDsaOf(tag);
    const k = try gpa.create(M.SecretKey);
    errdefer {
        std.crypto.secureZero(u8, std.mem.asBytes(k));
        gpa.destroy(k);
    }
    try burn.run(@field(burn.mldsa_key_burn, @tagName(tag)), Error!void, mlDsaExpand, .{ M, k, private });
    out.* = @unionInit(PrivateKey, @tagName(tag), k);
}

/// ML-DSA-PrivateKey ::= CHOICE { seed [0] IMPLICIT OCTET STRING (SIZE (32)),
/// expandedKey OCTET STRING, both SEQUENCE { seed, expandedKey } } (RFC 9881
/// §6; OpenSSL 3.5 writes `both` by default). The key is expanded from the
/// seed; `both` must agree with its own seed (OpenSSL refuses such a key
/// too). `expandedKey` alone is `UnsupportedKey`: only its public half can
/// be checked against the leaf — a damaged `K`, `tr` or `t0` (std has no
/// call that recomputes them) would load and sign garbage or under another
/// key (found by the `tlsserver-keys` fuzz harness, 2026-10-21).
fn mlDsaExpand(comptime M: type, k: *M.SecretKey, private: []const u8) Error!void {
    var top = try Der.init(private);
    switch (top.peekTag() orelse return error.MalformedKey) {
        0x80 => {
            const seed = try top.expect(0x80);
            try top.end();
            if (seed.len != M.seed_length) return error.MalformedKey;
            k.* = M.newKeyFromSeed(seed[0..M.seed_length]).sk;
        },
        0x04 => return error.UnsupportedKey,
        0x30 => {
            var both = try top.seq();
            try top.end();
            const seed = try both.expect(0x04);
            const expanded = try both.expect(0x04);
            try both.end();
            if (seed.len != M.seed_length or expanded.len != M.SecretKey.encoded_length) return error.MalformedKey;
            k.* = M.newKeyFromSeed(seed[0..M.seed_length]).sk;
            var own = k.toBytes();
            defer std.crypto.secureZero(u8, &own);
            if (!std.crypto.timing_safe.eql([M.SecretKey.encoded_length]u8, own, expanded[0..M.SecretKey.encoded_length].*)) return error.MalformedKey;
        },
        else => return error.MalformedKey,
    }
}

/// ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING,
/// parameters [0] OID OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
/// (RFC 5915). `known` is the curve PKCS#8's AlgorithmIdentifier named; a
/// `[0]` naming another is `MalformedKey`, and a bare SEC1 key needs `[0]`.
fn ecFromSec1(out: *PrivateKey, der: []const u8, known: ?Curve) Error!void {
    var top = try Der.init(der);
    var key = try top.seq();
    try top.end();
    const version = try key.expect(0x02);
    if (version.len != 1 or version[0] != 1) return error.MalformedKey;
    const raw = try key.expect(0x04);
    var curve = known;
    if (key.peekTag() == 0xa0) {
        var params = try key.explicit(0xa0);
        const c = try curveOf(try params.expect(0x06));
        try params.end();
        if (curve) |k| if (k != c) return error.MalformedKey;
        curve = c;
    }
    switch (curve orelse return error.MalformedKey) {
        .p256 => out.* = .{ .ecdsa_p256 = try scalar(EcdsaP256, EcdsaP256.Curve.scalar.rejectNonCanonical, raw) },
        .p384 => out.* = .{ .ecdsa_p384 = try scalar(EcdsaP384, EcdsaP384.Curve.scalar.rejectNonCanonical, raw) },
        .p521 => out.* = .{ .ecdsa_p521 = try scalar(EcdsaP521, p521.scalar.rejectNonCanonical, raw) },
    }
}

/// RFC 5915 fixes the octet string at the order's length; a shorter one
/// (leading zeros dropped by some encoders) is left-padded, as OpenSSL reads it.
fn scalar(comptime E: type, comptime rejectNonCanonical: anytype, raw: []const u8) Error!E.SecretKey {
    const n = E.SecretKey.encoded_length;
    if (raw.len == 0 or raw.len > n) return error.MalformedKey;
    var bytes: [n]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &bytes);
    @memcpy(bytes[n - raw.len ..], raw);
    // std's `SecretKey.fromBytes` takes any bytes: a scalar >= the order
    // would load here and fail only when the first handshake signs
    // (independent review 2026-10-20, MEDIUM). Zero is refused below by
    // `fromSecretKey`'s identity check in `matches`.
    rejectNonCanonical(bytes, .big) catch return error.MalformedKey;
    return E.SecretKey.fromBytes(bytes) catch error.MalformedKey;
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

// ── a strict DER reader (definite lengths, minimal length octets) ───────

const Der = struct {
    b: []const u8,
    pos: usize = 0,

    fn init(b: []const u8) Error!Der {
        return .{ .b = b };
    }

    fn peekTag(d: *const Der) ?u8 {
        return if (d.pos < d.b.len) d.b[d.pos] else null;
    }

    /// The next element's content, which must carry `tag`.
    fn expect(d: *Der, tag: u8) Error![]const u8 {
        if (d.pos + 2 > d.b.len or d.b[d.pos] != tag) return error.MalformedKey;
        var len: usize = d.b[d.pos + 1];
        var at = d.pos + 2;
        if (len >= 0x80) {
            const n = len & 0x7f;
            if (n == 0 or n > 2 or at + n > d.b.len) return error.MalformedKey;
            len = 0;
            for (d.b[at..][0..n]) |o| len = len << 8 | o;
            if (len < 0x80 or (n == 2 and len < 0x100)) return error.MalformedKey; // not minimal
            at += n;
        }
        if (len > d.b.len - at) return error.MalformedKey;
        d.pos = at + len;
        return d.b[at..][0..len];
    }

    fn seq(d: *Der) Error!Der {
        return .{ .b = try d.expect(0x30) };
    }

    fn seqOf(d: *Der) Error!Der {
        return d.seq();
    }

    fn explicit(d: *Der, tag: u8) Error!Der {
        return .{ .b = try d.expect(tag) };
    }

    /// Nothing left. (Callers that tolerate trailing fields do not call it.)
    fn end(d: *const Der) Error!void {
        if (d.pos != d.b.len) return error.MalformedKey;
    }
};

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
            var it: BlockIterator = .{ .text = c.key_pem };
            const b = (try it.next()).?;
            break :blk .{ b.label, b.body };
        };
        var der_buf: [max_key_der_len]u8 = undefined;
        const der = try b64ct.standard.decodeIgnoring(&der_buf, body, b64ct.pem_whitespace);
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
        var it: BlockIterator = .{ .text = c.key_pem };
        const b = (try it.next()).?;
        var der_buf: [max_key_der_len]u8 = undefined;
        const der = try b64ct.standard.decodeIgnoring(&der_buf, b.body, b64ct.pem_whitespace);
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

test "fromPemDelegated: an early error (bad credential) leaves out zeroed and deinit-safe" {
    const c = key_vectors.cases[0];
    var pair: CertKeyPair = undefined;
    @memset(std.mem.asBytes(&pair), 0xaa);
    try testing.expectError(error.MalformedKey, CertKeyPair.fromPemDelegated(&pair, testing.allocator, c.cert_pem, c.key_pem, "junk"));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&pair), 0));
    pair.deinit(testing.allocator);
}
