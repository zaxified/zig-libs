// SPDX-License-Identifier: MIT
//! Tests for the ocsp module.
//!
//! Fixture provenance: all OCSP responses here are CONSTRUCTED — a
//! `BasicOCSPResponse` is hand-built with the module's own DER writer and
//! signed with the sibling `rsa` / `p256` modules (the same self-signed-fixture
//! approach other crypto modules in this repo use), rather than captured from a
//! public CA. That keeps the tests hermetic (no network, no embedded 3rd-party
//! certs) while exercising every verification branch against a real signature
//! over real DER. See SPEC.md "Validation".

const std = @import("std");
const testing = std.testing;
const ocsp = @import("root.zig");
const rsa = @import("rsa");
const p256 = @import("p256");
const der_writer = rsa.der_writer;

const der = std.crypto.Certificate.der;
const ext = @import("x509").extensions;

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;

// A fixed instant inside 2027 and the matching time strings.
const now_2027 = 1_800_000_000; // ~2027-01-15
const this_update = "20270101000000Z";
const next_update = "20271231000000Z";

// OIDs used to hand-build fixtures.
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256_curve = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_sha1 = [_]u8{ 0x2b, 0x0e, 0x03, 0x02, 0x1a };
const oid_sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
const oid_sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
const oid_sha224 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 }; // no CertID hash this module knows
const oid_sha1_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 };
const oid_sha384_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
const oid_sha512_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
const oid_ecdsa_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
const oid_ecdsa_sha512 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 };
const oid_p384_curve = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ocsp_basic = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
const oid_ocsp_nonce = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02 };
const oid_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 }; // 2.5.29.37
const oid_ocsp_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
const oid_any_extended_key_usage = [_]u8{ 0x55, 0x1d, 0x25, 0x00 }; // 2.5.29.37.0

// ── independent cert-field extraction (test oracle, mirrors parseCert) ──────

const IssuerBits = struct { subject_name: []const u8, key_bits: []const u8, serial: []const u8 };

fn elem(bytes: []const u8, idx: u32) !der.Element {
    return ext.parseElement(bytes, idx);
}

/// Independently walk a cert to its subject Name TLV, subjectPublicKey value
/// and serialNumber — an oracle for buildRequest/verify, not shared code.
fn extractBits(cert: []const u8) !IssuerBits {
    const c = try elem(cert, 0);
    const tbs = try elem(cert, c.slice.start);
    var pos = tbs.slice.start;
    var first = try elem(cert, pos);
    if (@as(u8, @bitCast(first.identifier)) == 0xa0) {
        pos = first.slice.end;
        first = try elem(cert, pos);
    }
    const serial = first; // INTEGER
    const sig_alg = try elem(cert, serial.slice.end);
    const issuer = try elem(cert, sig_alg.slice.end);
    const validity = try elem(cert, issuer.slice.end);
    const subject_start = validity.slice.end;
    const subject = try elem(cert, subject_start);
    const spki = try elem(cert, subject.slice.end);
    const alg_seq = try elem(cert, spki.slice.start);
    const spk = try elem(cert, alg_seq.slice.end); // BIT STRING
    return .{
        .subject_name = cert[subject_start..subject.slice.end],
        .key_bits = cert[spk.slice.start + 1 .. spk.slice.end], // strip unused-bits octet
        .serial = cert[serial.slice.start..serial.slice.end],
    };
}

// ── RSA issuer/subject cert fixtures ────────────────────────────────────────

const RsaFixture = struct {
    issuer_der: []u8,
    subject_der: []u8,
    kp: rsa.KeyPair,

    fn deinit(self: *RsaFixture, gpa: std.mem.Allocator) void {
        gpa.free(self.issuer_der);
        gpa.free(self.subject_der);
    }
};

/// Build a leaf certificate genuinely ISSUED BY `issuer_name` (i.e. its
/// `issuer` field is the CA's `subject` Name), signed with the CA key.
/// `rsa.selfSignedCert` cannot express this — it writes one Name into both
/// slots — so the leaf is assembled here from the module's own DER writer.
/// This is what makes the fixture a real chain, which `ocsp.verify`'s
/// subject↔issuer check requires.
fn buildLeafCert(
    gpa: std.mem.Allocator,
    issuer_sk: rsa.SecretKey,
    issuer_name: []const u8,
    leaf_spki: []const u8,
    leaf_cn: []const u8,
    serial_raw: []const u8,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    const version = try b.explicit(0, try b.integerU64(2)); // v3
    const serial = try b.integerRaw(serial_raw);
    const sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
    const validity = try b.seq(&.{
        try b.tlv(0x17, "200101000000Z"),
        try b.tlv(0x17, "400101000000Z"),
    });
    const tbs = try b.seq(&.{
        version,
        serial,
        sig_alg,
        issuer_name,
        validity,
        try buildName(b, leaf_cn),
        leaf_spki,
    });
    var out: [512]u8 = undefined;
    const sig = try rsa.signPkcs1v15(&issuer_sk, Sha256, tbs, &out);
    const cert = try b.seq(&.{
        tbs,
        try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() }),
        try b.bitString(sig),
    });
    return gpa.dupe(u8, cert);
}

fn makeRsaFixture(gpa: std.mem.Allocator) !RsaFixture {
    var prng = std.Random.DefaultPrng.init(0x0c005eed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    const issuer = try rsa.selfSignedCert(gpa, &kp.secret_key, kp.public_key, Sha256, .{
        .common_name = "zig-libs OCSP test CA",
        .serial = 1,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = true,
    });
    errdefer gpa.free(issuer);
    const issuer_bits = try extractBits(issuer);
    const subject = try buildLeafCert(
        gpa,
        kp.secret_key,
        issuer_bits.subject_name,
        try spkiOf(issuer), // same keypair; only the Names matter to `ocsp`
        "leaf.example.com",
        &.{ 0x42, 0x42 }, // serial 0x4242
    );
    return .{ .issuer_der = issuer, .subject_der = subject, .kp = kp };
}

// ── OCSP response builder (constructed fixtures) ────────────────────────────

const StatusKind = union(enum) {
    good,
    revoked: struct { time: []const u8, reason: ?u8 },
    unknown,
};

/// A further SingleResponse (same issuer, SHA-256 CertID) after the main one.
const ExtraSingle = struct {
    serial: []const u8,
    status: StatusKind = .good,
    next_update: ?[]const u8 = next_update,
};

const RespSpec = struct {
    issuer: IssuerBits,
    extra: []const ExtraSingle = &.{},
    subject_serial: []const u8,
    responder_by_name: ?[]const u8 = null, // Name TLV
    responder_by_key: ?[]const u8 = null, // KeyHash (SHA-1 digest bytes)
    status: StatusKind = .good,
    this_update: []const u8 = this_update,
    next_update: ?[]const u8 = next_update,
    certs: ?[]const u8 = null, // a single cert TLV to embed in certs [0]
    nonce: ?[]const u8 = null,
    /// signer: rsa secret key (SHA-256) — the direct/delegated RSA path.
    sign_rsa: ?rsa.SecretKey = null,
    /// signer: p256 secret key (ECDSA SHA-256).
    sign_ecdsa: ?[32]u8 = null,
    /// signer: Ed25519 seed (id-Ed25519, RFC 8410).
    sign_ed25519: ?[32]u8 = null,
    /// W2-A2/ocsp-F3: flip a byte of the CertID's issuerNameHash so it no
    /// longer matches the real issuer, leaving issuerKeyHash and serial
    /// correct — isolates the name-hash comparison from the other two.
    corrupt_issuer_name_hash: bool = false,
    /// W2-A2/ocsp-F3: flip a byte of the CertID's issuerKeyHash so it no
    /// longer matches the real issuer, leaving issuerNameHash and serial
    /// correct — isolates the key-hash comparison from the other two.
    corrupt_issuer_key_hash: bool = false,

    // ── 2026-11-17 whole-module mutation: knobs for shapes the builder could not make ──
    /// Hash of the matching SingleResponse's CertID.
    cert_hash: CertHash = .sha256,
    /// A non-matching SingleResponse ahead of the real one (`.sha1_zero`: SHA-1 CertID with zero
    /// hashes; `.unknown_alg`: a hash OID this module does not know, but the SHA-1 digests and
    /// serial of the real certificate, and status `revoked`).
    decoy: Decoy = .none,
    single_this_update: ?[]const u8 = null,
    /// Raw bytes appended inside the matching SingleResponse.
    single_trailer: ?[]const u8 = null,
    /// A raw TLV used as the matching single's certStatus.
    status_raw: ?[]const u8 = null,
    /// Raw CONTENT of the `responses` SEQUENCE.
    responses_raw: ?[]const u8 = null,
    /// An explicit `[0] version` as the first element of ResponseData.
    tbs_version: bool = false,
    /// A raw element after `responses` in ResponseData (before the extensions).
    tbs_trailer: ?[]const u8 = null,
    /// responseExtensions carries a critical non-nonce extension first.
    other_ext: bool = false,
    /// XOR 0x40 into the identifier octet of the element at this child path of ResponseData
    /// BEFORE signing (so the signature covers the damage and only the parser can object).
    tbs_flip_path: ?[]const u8 = null,
    /// Signs `tbsResponseData` and supplies the AlgorithmIdentifier and signature BIT STRING.
    signer: ?Signer = null,
};

const CertHash = enum { sha1, sha256, sha384, sha512 };
const Decoy = enum { none, sha1_zero, unknown_alg };
const SigOut = struct { alg: []const u8, sigval: []const u8 };
const Signer = struct {
    ctx: *const anyopaque,
    f: *const fn (ctx: *const anyopaque, b: der_writer.Builder, tbs: []const u8) anyerror!SigOut,
};

fn certIdDer(b: der_writer.Builder, spec: RespSpec) ![]const u8 {
    var nb: [64]u8 = undefined;
    var kb: [64]u8 = undefined;
    var n: usize = 0;
    var oid: []const u8 = undefined;
    switch (spec.cert_hash) {
        .sha1 => {
            n = 20;
            oid = &oid_sha1;
            Sha1.hash(spec.issuer.subject_name, nb[0..20], .{});
            Sha1.hash(spec.issuer.key_bits, kb[0..20], .{});
        },
        .sha256 => {
            n = 32;
            oid = &oid_sha256;
            Sha256.hash(spec.issuer.subject_name, nb[0..32], .{});
            Sha256.hash(spec.issuer.key_bits, kb[0..32], .{});
        },
        .sha384 => {
            n = 48;
            oid = &oid_sha384;
            Sha384.hash(spec.issuer.subject_name, nb[0..48], .{});
            Sha384.hash(spec.issuer.key_bits, kb[0..48], .{});
        },
        .sha512 => {
            n = 64;
            oid = &oid_sha512;
            Sha512.hash(spec.issuer.subject_name, nb[0..64], .{});
            Sha512.hash(spec.issuer.key_bits, kb[0..64], .{});
        },
    }
    if (spec.corrupt_issuer_name_hash) nb[0] ^= 0xff;
    if (spec.corrupt_issuer_key_hash) kb[0] ^= 0xff;
    const alg = try b.seq(&.{ try b.oid(oid), try b.null() });
    return b.seq(&.{
        alg,
        try b.octetString(nb[0..n]),
        try b.octetString(kb[0..n]),
        try b.integerRaw(spec.subject_serial),
    });
}

/// A CertID naming a hash this module does not know, but carrying the SHA-1 digests and the
/// serial of the real certificate: a verifier that guessed SHA-1 (or accepted the entry
/// unchecked) would match it.
fn decoyUnknownAlgCertIdDer(b: der_writer.Builder, spec: RespSpec) ![]const u8 {
    var nb: [20]u8 = undefined;
    var kb: [20]u8 = undefined;
    Sha1.hash(spec.issuer.subject_name, &nb, .{});
    Sha1.hash(spec.issuer.key_bits, &kb, .{});
    return b.seq(&.{
        try b.seq(&.{ try b.oid(&oid_sha224), try b.null() }),
        try b.octetString(&nb),
        try b.octetString(&kb),
        try b.integerRaw(spec.subject_serial),
    });
}

fn statusDer(b: der_writer.Builder, kind: StatusKind) ![]const u8 {
    switch (kind) {
        .good => return b.implicitPrimitive(0, &.{}), // good [0] IMPLICIT NULL
        .unknown => return b.implicitPrimitive(2, &.{}),
        .revoked => |r| {
            var parts = std.ArrayList([]const u8).empty;
            defer parts.deinit(b.a);
            try parts.append(b.a, try b.generalizedTime(r.time));
            if (r.reason) |code| {
                try parts.append(b.a, try b.explicit(0, try b.enumerated(code)));
            }
            const info = try std.mem.concat(b.a, u8, parts.items);
            return b.tlv(0xa1, info); // revoked [1] IMPLICIT RevokedInfo (SEQUENCE)
        },
    }
}

fn nonceExtsDer(b: der_writer.Builder, nonce: []const u8) ![]const u8 {
    const nonce_ext = try b.seq(&.{
        try b.oid(&oid_ocsp_nonce),
        try b.octetString(try b.octetString(nonce)),
    });
    return b.explicit(1, try b.seq(&.{nonce_ext})); // responseExtensions [1]
}

/// A CertID that names the same issuer as `spec` under SHA-1 (not SHA-256)
/// but with a deliberately wrong hash/serial — so it never matches, but it
/// *does* force a SHA-1 issuer-digest computation ahead of the real
/// SHA-256 entry when both are walked in one `BasicOCSPResponse`.
fn decoySha1CertIdDer(b: der_writer.Builder) ![]const u8 {
    const zero20 = @as([20]u8, @splat(0));
    const alg = try b.seq(&.{ try b.oid(&oid_sha1), try b.null() });
    return b.seq(&.{
        alg,
        try b.octetString(&zero20),
        try b.octetString(&zero20),
        try b.integerRaw(&[_]u8{0x01}),
    });
}

fn buildResponse(gpa: std.mem.Allocator, spec: RespSpec) ![]u8 {
    return buildResponseImpl(gpa, spec, false);
}

/// Same as `buildResponse`, but the `responses` SEQUENCE OF carries an extra,
/// non-matching SHA-1 `SingleResponse` *ahead of* the real SHA-256 one —
/// regression coverage for W2-B/ocsp-F6: `findMatchingSingle`'s per-algorithm
/// issuer-digest cache must key on the CertID's actual hash algorithm, not
/// just "the first algorithm seen in this walk", or the SHA-1 decoy's cached
/// digest gets silently reused (wrong length, wrong bytes) for the real
/// SHA-256 entry and the genuinely matching response is missed.
fn buildResponseWithSha1Decoy(gpa: std.mem.Allocator, spec: RespSpec) ![]u8 {
    return buildResponseImpl(gpa, spec, true);
}

fn buildResponseImpl(gpa: std.mem.Allocator, spec_in: RespSpec, with_decoy: bool) ![]u8 {
    var spec = spec_in;
    if (with_decoy and spec.decoy == .none) spec.decoy = .sha1_zero;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    // SingleResponse
    var single_parts = std.ArrayList([]const u8).empty;
    try single_parts.append(b.a, try certIdDer(b, spec));
    try single_parts.append(b.a, if (spec.status_raw) |raw| raw else try statusDer(b, spec.status));
    try single_parts.append(b.a, try b.generalizedTime(spec.single_this_update orelse spec.this_update));
    if (spec.next_update) |nu| {
        try single_parts.append(b.a, try b.explicit(0, try b.generalizedTime(nu)));
    }
    if (spec.single_trailer) |t| try single_parts.append(b.a, t);
    const single = try b.seq(single_parts.items);
    const responses = if (spec.responses_raw) |raw| try b.tlv(0x30, raw) else if (spec.decoy != .none) blk: {
        var decoy_parts = std.ArrayList([]const u8).empty;
        const decoy_status: StatusKind = if (spec.decoy == .unknown_alg) .{ .revoked = .{ .time = "20260101000000Z", .reason = 1 } } else spec.status;
        try decoy_parts.appendSlice(b.a, &[_][]const u8{
            if (spec.decoy == .unknown_alg) try decoyUnknownAlgCertIdDer(b, spec) else try decoySha1CertIdDer(b),
            try statusDer(b, decoy_status),
            try b.generalizedTime(spec.this_update),
        });
        if (spec.next_update) |nu| {
            try decoy_parts.append(b.a, try b.explicit(0, try b.generalizedTime(nu)));
        }
        const decoy = try b.seq(decoy_parts.items);
        break :blk try b.seq(&.{ decoy, single });
    } else if (spec.extra.len != 0) blk: {
        var all = std.ArrayList([]const u8).empty;
        try all.append(b.a, single);
        for (spec.extra) |x| {
            var xs = spec;
            xs.subject_serial = x.serial;
            var xp = std.ArrayList([]const u8).empty;
            try xp.appendSlice(b.a, &.{
                try certIdDer(b, xs),
                try statusDer(b, x.status),
                try b.generalizedTime(spec.this_update),
            });
            if (x.next_update) |nu| try xp.append(b.a, try b.explicit(0, try b.generalizedTime(nu)));
            try all.append(b.a, try b.seq(xp.items));
        }
        break :blk try b.seq(all.items);
    } else try b.seq(&.{single});

    // ResponseData (tbs): [version,] responderID byName [1] or byKey [2], producedAt, responses [, trailer] [, exts]
    const responder_id = if (spec.responder_by_name) |name|
        try b.explicit(1, name)
    else if (spec.responder_by_key) |kh|
        try b.explicit(2, try b.octetString(kh))
    else
        return error.NoResponderId;
    var rd_parts = std.ArrayList([]const u8).empty;
    if (spec.tbs_version) try rd_parts.append(b.a, try b.explicit(0, try b.integerU64(0)));
    try rd_parts.append(b.a, responder_id);
    try rd_parts.append(b.a, try b.generalizedTime(spec.this_update));
    try rd_parts.append(b.a, responses);
    if (spec.tbs_trailer) |t| try rd_parts.append(b.a, t);
    if (spec.nonce != null or spec.other_ext) {
        var ext_items = std.ArrayList([]const u8).empty;
        if (spec.other_ext) try ext_items.append(b.a, try b.seq(&.{
            try b.oid(&[_]u8{ 0x2a, 0x03, 0x04 }),
            try b.boolean(true),
            try b.octetString("x"),
        }));
        if (spec.nonce) |n| try ext_items.append(b.a, try b.seq(&.{
            try b.oid(&oid_ocsp_nonce),
            try b.octetString(try b.octetString(n)),
        }));
        try rd_parts.append(b.a, try b.explicit(1, try b.seq(ext_items.items)));
    }
    var tbs = try b.seq(rd_parts.items);
    if (spec.tbs_flip_path) |path| {
        const mt = try b.a.dupe(u8, tbs);
        mt[try tagOffsetAt(mt, 0, path)] ^= 0x40;
        tbs = mt;
    }

    // signatureAlgorithm + signature
    var sig_alg: []const u8 = undefined;
    var sigval: []const u8 = undefined;
    if (spec.signer) |sg| {
        const so = try sg.f(sg.ctx, b, tbs);
        sig_alg = so.alg;
        sigval = so.sigval;
    } else if (spec.sign_rsa) |sk| {
        var out: [512]u8 = undefined;
        const signature = try rsa.signPkcs1v15(&sk, Sha256, tbs, &out);
        sigval = try b.bitString(signature);
        sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
    } else if (spec.sign_ecdsa) |sk| {
        const rs = try p256.sign.ecdsaSign(&sk, tbs, &(@as([32]u8, @splat(0x2b))));
        sigval = try b.bitString(try ecdsaRsToDer(b, rs));
        sig_alg = try b.seq(&.{try b.oid(&oid_ecdsa_sha256)});
    } else if (spec.sign_ed25519) |seed| {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        sigval = try b.bitString(&(try kp.sign(tbs, null)).toBytes());
        sig_alg = try b.seq(&.{try b.oid(&oid_ed25519)});
    } else return error.NoSigner;

    // BasicOCSPResponse
    var bor_parts = std.ArrayList([]const u8).empty;
    try bor_parts.append(b.a, tbs);
    try bor_parts.append(b.a, sig_alg);
    try bor_parts.append(b.a, sigval);
    if (spec.certs) |cert_tlv| {
        try bor_parts.append(b.a, try b.explicit(0, try b.seq(&.{cert_tlv})));
    }
    const bor = try b.seq(bor_parts.items);

    const response_bytes = try b.seq(&.{ try b.oid(&oid_ocsp_basic), try b.octetString(bor) });
    const ocsp_response = try b.seq(&.{
        try b.enumerated(0), // successful
        try b.explicit(0, response_bytes),
    });
    return gpa.dupe(u8, ocsp_response);
}

/// The offset of the identifier octet of the element reached from the element at `start` by
/// taking the `path[0]`-th child, then its `path[1]`-th child, and so on.
fn tagOffsetAt(bytes: []const u8, start: u32, path: []const u8) !u32 {
    var off = start;
    for (path) |idx| {
        const e = try elem(bytes, off);
        var c: u32 = e.slice.start;
        var k: u8 = 0;
        while (k < idx) : (k += 1) c = (try elem(bytes, c)).slice.end;
        off = c;
    }
    return off;
}

/// r||s (64) → DER `SEQUENCE { INTEGER r, INTEGER s }`.
fn ecdsaRsToDer(b: der_writer.Builder, rs: [64]u8) ![]const u8 {
    return b.seq(&.{
        try b.integerRaw(try derIntMagnitude(b, rs[0..32])),
        try b.integerRaw(try derIntMagnitude(b, rs[32..64])),
    });
}

fn derIntMagnitude(b: der_writer.Builder, raw: []const u8) ![]const u8 {
    var v = raw;
    while (v.len > 1 and v[0] == 0) v = v[1..];
    if (v[0] & 0x80 != 0) {
        const out = try b.a.alloc(u8, v.len + 1);
        out[0] = 0;
        @memcpy(out[1..], v);
        return out;
    }
    return b.a.dupe(u8, v);
}

// ── delegate responder cert (signed by the issuer RSA key) ──────────────────

/// Which extKeyUsage the built delegate cert carries. `.any` is the
/// interesting one: a cert that is well-formed, correctly signed by the
/// issuer, valid at `now`, and names the responder — everything a responder
/// needs EXCEPT the one purpose RFC 6960 §4.2.2.2 asks for.
const DelegateEku = enum { none, ocsp_signing, any, other };

fn buildDelegateCert(
    gpa: std.mem.Allocator,
    issuer_sk: rsa.SecretKey,
    issuer_name: []const u8,
    delegate_spki: []const u8,
    delegate_name: []const u8,
    eku: DelegateEku,
) ![]u8 {
    return buildDelegateCertValidity(
        gpa,
        issuer_sk,
        issuer_name,
        delegate_spki,
        delegate_name,
        eku,
        "200101000000Z",
        "400101000000Z",
    );
}

fn buildDelegateCertValidity(
    gpa: std.mem.Allocator,
    issuer_sk: rsa.SecretKey,
    issuer_name: []const u8,
    delegate_spki: []const u8,
    delegate_name: []const u8,
    eku: DelegateEku,
    not_before: []const u8,
    not_after: []const u8,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    const version = try b.explicit(0, try b.integerU64(2)); // v3
    const serial = try b.integerU64(9);
    const sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
    const validity = try b.seq(&.{
        try b.tlv(0x17, not_before), // UTCTime notBefore
        try b.tlv(0x17, not_after), // UTCTime notAfter
    });

    var tbs_parts = std.ArrayList([]const u8).empty;
    try tbs_parts.appendSlice(b.a, &[_][]const u8{
        version, serial, sig_alg, issuer_name, validity, delegate_name, delegate_spki,
    });
    if (eku == .other) {
        // An extensions block with one extension (basicConstraints) and NO extendedKeyUsage.
        const bc_ext = try b.seq(&.{
            try b.oid(&[_]u8{ 0x55, 0x1d, 0x13 }),
            try b.octetString(try b.seq(&.{})),
        });
        try tbs_parts.append(b.a, try b.explicit(3, try b.seq(&.{bc_ext})));
    } else if (eku != .none) {
        const purpose_oid = switch (eku) {
            .ocsp_signing => &oid_ocsp_signing,
            .any => &oid_any_extended_key_usage,
            .none, .other => unreachable,
        };
        const eku_ext = try b.seq(&.{
            try b.oid(&oid_ext_key_usage),
            try b.octetString(try b.seq(&.{try b.oid(purpose_oid)})),
        });
        try tbs_parts.append(b.a, try b.explicit(3, try b.seq(&.{eku_ext})));
    }
    const tbs = try b.seq(tbs_parts.items);

    var out: [512]u8 = undefined;
    const sig = try rsa.signPkcs1v15(&issuer_sk, Sha256, tbs, &out);
    const cert = try b.seq(&.{
        tbs,
        try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() }),
        try b.bitString(sig),
    });
    return gpa.dupe(u8, cert);
}

// ── EC issuer cert (minimal; its own signature is never checked) ────────────

fn buildEcIssuerCert(gpa: std.mem.Allocator, sec1: []const u8, name: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const version = try b.explicit(0, try b.integerU64(2));
    const serial = try b.integerU64(3);
    const sig_alg = try b.seq(&.{try b.oid(&oid_ecdsa_sha256)});
    const validity = try b.seq(&.{
        try b.tlv(0x17, "200101000000Z"),
        try b.tlv(0x17, "400101000000Z"),
    });
    const spki = try b.seq(&.{
        try b.seq(&.{ try b.oid(&oid_ec_public_key), try b.oid(&oid_p256_curve) }),
        try b.bitString(sec1),
    });
    const tbs = try b.seq(&.{ version, serial, sig_alg, name, validity, name, spki });
    const cert = try b.seq(&.{
        tbs,
        try b.seq(&.{try b.oid(&oid_ecdsa_sha256)}),
        try b.bitString(&[_]u8{ 0xde, 0xad, 0xbe, 0xef }), // dummy — issuer cert sig not verified
    });
    return gpa.dupe(u8, cert);
}

// Build a minimal Name SEQUENCE TLV (RDN with a single CN) for delegate/EC names.
fn buildName(b: der_writer.Builder, cn: []const u8) ![]const u8 {
    const atv = try b.seq(&.{ try b.oid(&[_]u8{ 0x55, 0x04, 0x03 }), try b.utf8String(cn) });
    return b.seq(&.{try b.set(&.{atv})});
}

fn defaultOpts() ocsp.VerifyOptions {
    return .{ .now_unix = now_2027 };
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "buildRequest: CertID hashes match an independent recomputation" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);

    const nonce = "0123456789abcdef";
    const req = try ocsp.buildRequest(gpa, fx.subject_der, fx.issuer_der, .{ .hash = .sha1, .nonce = nonce });
    defer gpa.free(req);

    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);
    var exp_name: [20]u8 = undefined;
    var exp_key: [20]u8 = undefined;
    Sha1.hash(issuer.subject_name, &exp_name, .{});
    Sha1.hash(issuer.key_bits, &exp_key, .{});

    // Decode OCSPRequest → … → CertID and compare each field.
    const outer = try elem(req, 0);
    const tbs = try elem(req, outer.slice.start);
    const req_list = try elem(req, tbs.slice.start);
    const request = try elem(req, req_list.slice.start);
    const cert_id = try elem(req, request.slice.start);
    const alg = try elem(req, cert_id.slice.start);
    const name_hash = try elem(req, alg.slice.end);
    const key_hash = try elem(req, name_hash.slice.end);
    const serial = try elem(req, key_hash.slice.end);

    try testing.expectEqualSlices(u8, &exp_name, req[name_hash.slice.start..name_hash.slice.end]);
    try testing.expectEqualSlices(u8, &exp_key, req[key_hash.slice.start..key_hash.slice.end]);
    try testing.expectEqualSlices(u8, subject.serial, req[serial.slice.start..serial.slice.end]);

    // Nonce present in requestExtensions.
    try testing.expect(tbs.slice.end > req_list.slice.end);
}

test "verify: good status accepted (direct issuer, RSA)" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectEqual(ocsp.ResponseStatus.successful, parsed.status);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .good);
    try testing.expect(!verdict.delegated);
}

test "verify: revoked status parsed with time + reason" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .status = .{ .revoked = .{ .time = "20260601000000Z", .reason = 1 } }, // keyCompromise
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .revoked);
    try testing.expectEqual(@as(?u8, 1), verdict.status.revoked.reason);
}

test "verify: unknown status parsed end-to-end (not silently accepted as good)" {
    // WAVE-2 ocsp F4 / CAMPAIGN K5: the `CertStatus` builder (`buildResponse`'s
    // `.unknown` arm, above) could ALWAYS construct an `unknown [2]` DER
    // response, but nothing ever ran it through `verify()` and checked the
    // resulting `verdict.status` — fault injection at audit time confirmed a
    // mutant mapping `unknown` to `.good` left the whole suite green. This
    // closes that gap directly (the `revoked` case already had its own test
    // above; `unknown` did not).
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .status = .unknown,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .unknown);
    try testing.expect(verdict.status != .good);
}

test "verify: tampered tbsResponseData → SignatureInvalid" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    // Flip a byte inside the producedAt/response area (tbs), leaving the
    // signature intact — verification must reject.
    var tampered = try gpa.dupe(u8, resp_der);
    defer gpa.free(tampered);
    tampered[tampered.len / 2] ^= 0x01;

    const parsed = ocsp.parseResponse(tampered) catch {
        // A structural break is also an acceptable rejection.
        return;
    };
    try testing.expectError(error.SignatureInvalid, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

test "verify: CertID for a different serial → CertIdMismatch" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = &[_]u8{ 0x00, 0x99 }, // not the subject's serial
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(error.CertIdMismatch, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

// W2-A2/ocsp-F3: `certIdBinds` ANDs three independent comparisons
// (issuerNameHash, issuerKeyHash, serial). The only existing negative test
// (above) is on the serial; deleting the issuerNameHash comparison entirely
// left the whole suite green because nothing exercised a CertID whose name
// hash alone is wrong. These two tests isolate the other two conjuncts.
test "verify: CertID with wrong issuerNameHash alone → CertIdMismatch" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
        .corrupt_issuer_name_hash = true,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(error.CertIdMismatch, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

test "verify: CertID with wrong issuerKeyHash alone → CertIdMismatch" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
        .corrupt_issuer_key_hash = true,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(error.CertIdMismatch, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

// W2-B/ocsp-F6: `findMatchingSingle` walks a `BasicOCSPResponse`'s
// `responses` and caches the issuer's name/key digests to avoid recomputing
// them per entry. RFC 6960 lets different SingleResponses use different
// CertID hash algorithms, so the cache must key on the algorithm actually in
// each CertID — not just compute once and reuse regardless. This response
// carries a non-matching SHA-1 entry ahead of the real SHA-256 one; a cache
// that ignores the algorithm would populate itself from the SHA-1 entry and
// then wrongly reuse those (wrong-length) digests for the SHA-256 entry,
// missing the genuine match.
test "verify: a non-matching SHA-1 entry ahead of the real SHA-256 one does not poison the digest cache" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponseWithSha1Decoy(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .good);
}

// A second leaf of the same CA (serial 0x4343) plus a third never answered.
fn makeLeaf(gpa: std.mem.Allocator, fx: RsaFixture, cn: []const u8, serial: []const u8) ![]u8 {
    const issuer = try extractBits(fx.issuer_der);
    return buildLeafCert(gpa, fx.kp.secret_key, issuer.subject_name, try spkiOf(fx.issuer_der), cn, serial);
}

test "verifyMany: each queried certificate gets its own status; an absent one is reported absent" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der); // serial 0x4242 -> good
    const leaf2 = try makeLeaf(gpa, fx, "two.example.com", &.{ 0x43, 0x43 }); // revoked
    defer gpa.free(leaf2);
    const leaf3 = try makeLeaf(gpa, fx, "three.example.com", &.{ 0x44, 0x44 }); // unknown
    defer gpa.free(leaf3);
    const leaf4 = try makeLeaf(gpa, fx, "four.example.com", &.{ 0x45, 0x45 }); // not in the response
    defer gpa.free(leaf4);
    const leaf5 = try makeLeaf(gpa, fx, "five.example.com", &.{ 0x46, 0x46 }); // stale entry
    defer gpa.free(leaf5);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
        .extra = &.{
            .{ .serial = &.{ 0x43, 0x43 }, .status = .{ .revoked = .{ .time = "20260101000000Z", .reason = 1 } } },
            .{ .serial = &.{ 0x44, 0x44 }, .status = .unknown },
            .{ .serial = &.{ 0x46, 0x46 }, .next_update = "20270102000000Z" }, // before now_2027
        },
    });
    defer gpa.free(resp_der);
    const parsed = try ocsp.parseResponse(resp_der);

    const q = [_]ocsp.CertPair{
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = leaf2, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = leaf3, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = leaf4, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = leaf5, .issuer_cert_der = fx.issuer_der },
        // reversed order: the second certificate again, last
        .{ .subject_cert_der = leaf2, .issuer_cert_der = fx.issuer_der },
    };
    var out: [q.len]ocsp.CertOutcome = undefined;
    try ocsp.verifyMany(parsed, &q, &out, defaultOpts());

    try testing.expect(out[0] == .verdict and out[0].verdict.status == .good);
    try testing.expect(out[1] == .verdict);
    try testing.expectEqual(@as(?u8, 1), out[1].verdict.status.revoked.reason);
    try testing.expect(out[2] == .verdict and out[2].verdict.status == .unknown);
    try testing.expect(out[3] == .absent);
    try testing.expectEqual(error.ResponseStale, out[4].failed);
    try testing.expect(out[5] == .verdict and out[5].verdict.status == .revoked);

    // Agrees with the single-cert API for each pair.
    const v1 = try ocsp.verify(parsed, fx.issuer_der, leaf2, defaultOpts());
    try testing.expectEqual(v1.status.revoked.revocation_time_unix, out[1].verdict.status.revoked.revocation_time_unix);
    try testing.expectError(error.CertIdMismatch, ocsp.verify(parsed, fx.issuer_der, leaf4, defaultOpts()));
    try testing.expectError(error.ResponseStale, ocsp.verify(parsed, fx.issuer_der, leaf5, defaultOpts()));
}

test "verifyMany: per-pair failures are isolated; response-wide ones are call errors" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
        .nonce = "abc",
    });
    defer gpa.free(resp_der);
    var parsed = try ocsp.parseResponse(resp_der);

    // A pair that is not a chain (subject vs itself as issuer) fails alone.
    const q = [_]ocsp.CertPair{
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = fx.subject_der },
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = "junk", .issuer_cert_der = fx.issuer_der },
    };
    var out: [3]ocsp.CertOutcome = undefined;
    var opts = defaultOpts();
    opts.expected_nonce = "abc";
    try ocsp.verifyMany(parsed, &q, &out, opts);
    try testing.expectEqual(error.IssuerMismatch, out[0].failed);
    try testing.expect(out[1] == .verdict);
    try testing.expectEqual(error.Malformed, out[2].failed);

    // Wrong nonce: every well-formed pair fails with NonceMismatch.
    opts.expected_nonce = "xyz";
    try ocsp.verifyMany(parsed, &q, &out, opts);
    try testing.expectEqual(error.NonceMismatch, out[1].failed);

    // Tampered signed bytes (the responder name): the pair fails, never a verdict.
    const bad = try gpa.dupe(u8, resp_der);
    defer gpa.free(bad);
    const at = std.mem.find(u8, bad, "zig-libs OCSP test CA").?;
    bad[at] ^= 1;
    const parsed_bad = try ocsp.parseResponse(bad);
    try ocsp.verifyMany(parsed_bad, q[1..2], out[1..2], defaultOpts());
    try testing.expect(out[1] == .failed);

    // Call-level errors.
    try testing.expectError(error.LengthMismatch, ocsp.verifyMany(parsed, &q, out[0..2], defaultOpts()));
    parsed.status = .try_later;
    try testing.expectError(error.UnsuccessfulResponse, ocsp.verifyMany(parsed, &q, &out, defaultOpts()));
    parsed.status = .successful;
    parsed.basic = null;
    try testing.expectError(error.UnsupportedResponseType, ocsp.verifyMany(parsed, &q, &out, defaultOpts()));
    // empty query list on a good response is a no-op
    var none: [0]ocsp.CertOutcome = .{};
    parsed = try ocsp.parseResponse(resp_der);
    try ocsp.verifyMany(parsed, &.{}, &none, defaultOpts());
}

test "buildRequests: several Requests in order; one-entry form equals buildRequest; empty refused" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const leaf2 = try makeLeaf(gpa, fx, "two.example.com", &.{ 0x43, 0x43 });
    defer gpa.free(leaf2);
    const pairs = [_]ocsp.CertPair{
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = leaf2, .issuer_cert_der = fx.issuer_der },
    };

    // one entry == buildRequest, byte for byte
    const one = try ocsp.buildRequests(gpa, pairs[0..1], .{ .nonce = "n0nce" });
    defer gpa.free(one);
    const single = try ocsp.buildRequest(gpa, fx.subject_der, fx.issuer_der, .{ .nonce = "n0nce" });
    defer gpa.free(single);
    try testing.expectEqualSlices(u8, single, one);

    const req = try ocsp.buildRequests(gpa, &pairs, .{ .hash = .sha256 });
    defer gpa.free(req);
    const outer = try elem(req, 0);
    const tbs = try elem(req, outer.slice.start);
    const req_list = try elem(req, tbs.slice.start);
    var pos = req_list.slice.start;
    const want = [_][]const u8{ &.{ 0x42, 0x42 }, &.{ 0x43, 0x43 } };
    var n: usize = 0;
    var exp_name: [32]u8 = undefined;
    Sha256.hash((try extractBits(fx.issuer_der)).subject_name, &exp_name, .{});
    while (pos < req_list.slice.end) : (n += 1) {
        const request = try elem(req, pos);
        pos = request.slice.end;
        const cert_id = try elem(req, request.slice.start);
        const alg = try elem(req, cert_id.slice.start);
        const name_hash = try elem(req, alg.slice.end);
        const key_hash = try elem(req, name_hash.slice.end);
        const serial = try elem(req, key_hash.slice.end);
        try testing.expectEqualSlices(u8, &exp_name, req[name_hash.slice.start..name_hash.slice.end]);
        try testing.expectEqualSlices(u8, want[n], req[serial.slice.start..serial.slice.end]);
    }
    try testing.expectEqual(@as(usize, 2), n);

    try testing.expectError(error.Malformed, ocsp.buildRequests(gpa, &.{}, .{}));
    const badp = [_]ocsp.CertPair{.{ .subject_cert_der = "x", .issuer_cert_der = fx.issuer_der }};
    try testing.expectError(error.Malformed, ocsp.buildRequests(gpa, &badp, .{}));

    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, ocsp.buildRequests(failing.allocator(), &pairs, .{}));
}

test "verify: stale response (now > nextUpdate) → ResponseStale" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    var opts = defaultOpts();
    opts.now_unix = 2_000_000_000; // ~2033, well past nextUpdate (2027-12-31)
    try testing.expectError(error.ResponseStale, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, opts));
}

test "verify: not-yet-valid response (now < thisUpdate) → ResponseNotYetValid" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    var opts = defaultOpts();
    opts.now_unix = 1_000_000_000; // ~2001, before thisUpdate (2027-01-01)
    try testing.expectError(error.ResponseNotYetValid, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, opts));
}

test "verify: missing nextUpdate honours max_age" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .next_update = null,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    // thisUpdate = 2027-01-01; now = 2027-01-15 (~14 days later).
    var fresh = defaultOpts();
    fresh.max_age_seconds = 30 * 24 * 3600;
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, fresh);
    try testing.expect(verdict.status == .good);
    try testing.expect(verdict.next_update_unix == null);

    var stale = defaultOpts();
    stale.max_age_seconds = 3600; // 1h — 14 days is well past
    try testing.expectError(error.ResponseStale, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, stale));
}

test "verify: nonce mismatch → NonceMismatch; matching nonce accepted" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    const nonce = "nonce-abcdef-123456";
    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = issuer.subject_name,
        .nonce = nonce,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectEqualSlices(u8, nonce, parsed.basic.?.nonce.?);

    var good = defaultOpts();
    good.expected_nonce = nonce;
    _ = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, good);

    var bad = defaultOpts();
    bad.expected_nonce = "a-different-nonce";
    try testing.expectError(error.NonceMismatch, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, bad));
}

test "verify: successful status but unrecognized responseType → UnsupportedResponseType" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);

    // successful status, but responseBytes carries an OID this module does
    // not decode (any OID other than id-pkix-ocsp-basic).
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const response_bytes = try b.seq(&.{ try b.oid(&oid_sha256), try b.octetString("not-basic-ocsp") });
    const ocsp_response = try b.seq(&.{
        try b.enumerated(0), // successful
        try b.explicit(0, response_bytes),
    });

    const parsed = try ocsp.parseResponse(ocsp_response);
    try testing.expectEqual(ocsp.ResponseStatus.successful, parsed.status);
    try testing.expect(parsed.basic == null);
    try testing.expectError(
        error.UnsupportedResponseType,
        ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()),
    );
}

test "verify: responseStatus != successful → UnsuccessfulResponse" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);

    // Minimal OCSPResponse { responseStatus tryLater } — no responseBytes.
    const bytes = [_]u8{ 0x30, 0x03, 0x0a, 0x01, 0x03 };
    const parsed = try ocsp.parseResponse(&bytes);
    try testing.expectEqual(ocsp.ResponseStatus.try_later, parsed.status);
    try testing.expect(parsed.basic == null);
    try testing.expectError(error.UnsuccessfulResponse, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

test "verify: delegated responder with OCSPSigning EKU accepted" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    // Delegate has its own RSA key; its cert is signed by the issuer.
    var prng = std.Random.DefaultPrng.init(0xde1e6a7e);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "delegated responder",
        .serial = 7,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);

    // Extract the delegate's SPKI TLV from its self-signed cert.
    const dspki = try spkiOf(delegate_self);

    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, dspki, dbits.subject_name, .ocsp_signing);
    defer gpa.free(delegate_cert);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key, // signed by the DELEGATE key
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .good);
    try testing.expect(verdict.delegated);
}

test "verify: delegated responder WITHOUT OCSPSigning EKU rejected" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var prng = std.Random.DefaultPrng.init(0x00badecc);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "no-eku responder",
        .serial = 8,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const dspki = try spkiOf(delegate_self);

    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, dspki, dbits.subject_name, .none);
    defer gpa.free(delegate_cert);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(error.ResponderMissingOcspSigning, ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()));
}

test "verify: delegated responder carrying anyExtendedKeyUsage instead of id-kp-OCSPSigning is rejected (RFC 6960 §4.2.2.2 / CA-B BR)" {
    // The certificate below is not defective in any way a general-purpose
    // validator would notice: it is well-formed, correctly signed by the
    // issuing CA, inside its validity window, and its subject Name is exactly
    // the response's ResponderID. It carries an extKeyUsage extension listing
    // `anyExtendedKeyUsage` (2.5.29.37.0) — a purpose `x509`'s shared
    // `extensions.hasPurpose` treats as satisfying every request, correctly,
    // for the callers that ask it about server/client auth. It is NOT
    // sufficient here: RFC 6960 §4.2.2.2 requires `id-kp-OCSPSigning`
    // specifically, because otherwise ANY anyEKU leaf this CA has ever issued
    // could sign revocation answers for the CA's whole hierarchy.
    //
    // The response itself is signed with the delegate's own key and would
    // verify. The ONLY thing wrong with it is that this certificate is not
    // bound to the OCSP-responder role.
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var prng = std.Random.DefaultPrng.init(0xa11e6ce7);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "any-eku responder",
        .serial = 11,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const dspki = try spkiOf(delegate_self);

    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, dspki, dbits.subject_name, .any);
    defer gpa.free(delegate_cert);

    // Control on the fixture itself: the shared x509 helper DOES accept this
    // cert's EKU for `.ocsp_signing`. That is what makes the assertion below a
    // check of `ocsp`'s own strictness rather than of `x509`'s — and it pins
    // the shared helper's behaviour so a future change there is not silently
    // absorbed by this test.
    {
        const cert: std.crypto.Certificate = .{ .buffer = delegate_cert, .index = 0 };
        const slice = (try ext.findExtensions(cert)).?;
        var it = ext.iterate(slice, cert);
        var saw_eku = false;
        while (try it.next()) |entry| {
            if (entry.id != .ext_key_usage) continue;
            saw_eku = true;
            try testing.expect(try ext.hasPurpose(entry.value, .ocsp_signing));
        }
        try testing.expect(saw_eku);
    }

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key, // a genuine signature by the delegate key
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(
        error.ResponderMissingOcspSigning,
        ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()),
    );
}

test "verify: responder identified byKey (KeyHash) accepted; wrong key hash rejected" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var issuer_key_hash: [20]u8 = undefined;
    Sha1.hash(issuer.key_bits, &issuer_key_hash, .{});

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_key = &issuer_key_hash,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .good);
    try testing.expect(!verdict.delegated);

    // A KeyHash that does not match the issuer's key, and no delegate cert
    // present to fall back on, must be rejected as unauthorized.
    var wrong_hash = issuer_key_hash;
    wrong_hash[0] ^= 0xff;
    const resp_der2 = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_key = &wrong_hash,
        .sign_rsa = fx.kp.secret_key,
    });
    defer gpa.free(resp_der2);
    const parsed2 = try ocsp.parseResponse(resp_der2);
    try testing.expectError(
        error.UntrustedResponder,
        ocsp.verify(parsed2, fx.issuer_der, fx.subject_der, defaultOpts()),
    );
}

test "verify: delegated responder cert outside its validity window → ResponderCertExpired" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var prng = std.Random.DefaultPrng.init(0xe401eed);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "expired responder",
        .serial = 11,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const dspki = try spkiOf(delegate_self);

    // Delegate cert's own validity window already expired before `now_2027`.
    const delegate_cert = try buildDelegateCertValidity(
        gpa,
        fx.kp.secret_key,
        issuer.subject_name,
        dspki,
        dbits.subject_name,
        .ocsp_signing,
        "200101000000Z",
        "260101000000Z", // notAfter 2026-01-01, well before now_2027 (2027-01-15)
    );
    defer gpa.free(delegate_cert);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    try testing.expectError(
        error.ResponderCertExpired,
        ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()),
    );
}

test "verify: ECDSA-P256 direct-issuer signature accepted" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const subject = try extractBits(fx.subject_der);

    const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x77)));
    const sec1 = kp.public_key.toUncompressedSec1();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const nb: der_writer.Builder = .{ .a = arena.allocator() };
    const ec_name = try buildName(nb, "ECDSA OCSP CA");
    const ec_issuer = try buildEcIssuerCert(gpa, &sec1, ec_name);
    defer gpa.free(ec_issuer);
    const ec_bits = try extractBits(ec_issuer);

    // The leaf must chain to THIS issuer: `verify` refuses a subject/issuer
    // pair that is not a chain (the fixture's RSA leaf is issued by the RSA
    // CA). Its own signature is never checked by `ocsp`, so signing it with
    // the RSA key is fine — only the Names are load-bearing here.
    const ec_leaf = try buildLeafCert(gpa, fx.kp.secret_key, ec_bits.subject_name, try spkiOf(fx.subject_der), "leaf.example.com", subject.serial);
    defer gpa.free(ec_leaf);

    const resp_der = try buildResponse(gpa, .{
        .issuer = ec_bits,
        .subject_serial = subject.serial,
        .responder_by_name = ec_bits.subject_name,
        .sign_ecdsa = kp.secret_key.bytes,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, ec_issuer, ec_leaf, defaultOpts());
    try testing.expect(verdict.status == .good);
}

// ── the subject↔issuer link (F2 / P-01) ────────────────────────────────────
//
// `certIdBinds` binds the CertID's two hashes to the issuer the CALLER passed
// and the serial to the subject the CALLER passed; nothing in a `CertID`
// identifies the subject certificate itself. So without an explicit check, a
// caller that pairs a subject with the wrong issuer gets a confident verdict
// about a DIFFERENT certificate — the (issuer, serial) pair the response
// actually answers for. The response below is entirely genuine: correctly
// signed by CA-B, with a CertID that binds perfectly to CA-B and to a serial
// CA-B really did issue. The only thing wrong is that the leaf handed to
// `verify` was issued by CA-A, not CA-B.
test "verify: subject not issued by the supplied issuer → IssuerMismatch" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa); // CA-A + leaf issued by CA-A
    defer fx.deinit(gpa);
    const subject = try extractBits(fx.subject_der);

    // CA-B: a different CA, with its own key and its own name.
    var prng = std.Random.DefaultPrng.init(0xca0fbeef);
    var kp_b: rsa.KeyPair = undefined;
    try rsa.generate(&kp_b, prng.random(), 1024, 65537);
    const ca_b = try rsa.selfSignedCert(gpa, &kp_b.secret_key, kp_b.public_key, Sha256, .{
        .common_name = "zig-libs OCSP test CA B",
        .serial = 2,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = true,
    });
    defer gpa.free(ca_b);
    const bits_b = try extractBits(ca_b);

    // A completely valid response FROM CA-B about serial 0x4242 under CA-B.
    const resp_der = try buildResponse(gpa, .{
        .issuer = bits_b,
        .subject_serial = subject.serial,
        .responder_by_name = bits_b.subject_name,
        .sign_rsa = kp_b.secret_key,
    });
    defer gpa.free(resp_der);
    const parsed = try ocsp.parseResponse(resp_der);

    // Control: against CA-B's own leaf the very same response verifies `good`,
    // so the rejection below is the subject↔issuer link and nothing else.
    const leaf_b = try buildLeafCert(gpa, kp_b.secret_key, bits_b.subject_name, try spkiOf(ca_b), "leaf.example.com", subject.serial);
    defer gpa.free(leaf_b);
    const ok = try ocsp.verify(parsed, ca_b, leaf_b, defaultOpts());
    try testing.expect(ok.status == .good);

    // CA-A's leaf against CA-B's response and CA-B's cert: not a chain.
    try testing.expectError(
        error.IssuerMismatch,
        ocsp.verify(parsed, ca_b, fx.subject_der, defaultOpts()),
    );
}

test "parseResponse: malformed / truncated input never panics" {
    // A pile of hostile byte strings — all must return a typed error, no abort.
    const cases = [_][]const u8{
        &.{},
        &.{0x30},
        &.{ 0x30, 0x80 }, // indefinite/oversized length
        &.{ 0x30, 0x05, 0x0a, 0x01, 0x00, 0xff, 0xff }, // trailing garbage
        &.{ 0x30, 0x03, 0x0a, 0x01 }, // truncated ENUMERATED
        &.{ 0x02, 0x01, 0x00 }, // not a SEQUENCE
    };
    for (cases) |c| {
        _ = ocsp.parseResponse(c) catch continue;
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

// ── fuzz: OCSP response DER decode off the wire, never panics ──────────────
//
// `parseResponse` is what a TLS/certificate-validation client runs on the
// body of an HTTP response from an OCSP responder (or the raw bytes an
// attacker-in-the-middle substitutes) — untrusted DER, no signature checked
// yet at this layer.

const fuzzseed = @import("testkit").fuzz;

/// The buffer was 512. A response carrying its own responder certificate —
/// which is what a real responder returns, and what `fuzzVerify` builds — does
/// not fit that, and a seed longer than the buffer reads back EMPTY rather
/// than truncated, so **no delegated OCSP response could ever have passed
/// through this harness**. The corpus guard below asserts the fixture is over
/// 512 octets so this cannot quietly stop being true. 4096 is `fuzzVerify`'s
/// own `rbuf` size, i.e. the largest response this module builds for itself.
const parse_buf_len = 4096;

/// Hostile DER. These are the same shapes as the "malformed / truncated input
/// never panics" value test above, plus the length-form edges a `parseResponse`
/// caller meets on the wire; the ACCEPTING seed is built at run time in the
/// test below, because no hand-written string spells a complete OCSPResponse.
const parse_static_seeds = [_][]const u8{
    fuzzseed.seedHex(""), // the empty slice: exactly what the collapsed draw ran, for ever
    fuzzseed.seedHex("30"), // a SEQUENCE tag with no length
    fuzzseed.seedHex("3080"), // indefinite length, which DER forbids
    fuzzseed.seedHex("30050a0100ffff"), // trailing garbage after a complete element
    fuzzseed.seedHex("30030a01"), // a truncated ENUMERATED
    fuzzseed.seedHex("020100"), // an INTEGER where a SEQUENCE belongs
    fuzzseed.seedHex("30840000ffff"), // a 4-octet long-form length claiming 65535 octets
    fuzzseed.seedHex("300a0a010030050603551d13"), // status 0 then a nested OID, not the basic-response wrapper
    fuzzseed.seedHex("30060a0101a00100"), // a non-zero responseStatus with a body behind it
    fuzzseed.seedHex(strRepeat("ff", 64)), // no DER structure at all
};

test "fuzz: parseResponse never panics on arbitrary bytes" {
    const gpa = testing.allocator;
    var c: ParseCorpus = .{};
    const built = try c.build(gpa);
    defer c.deinit(gpa);
    try testing.fuzz({}, fuzzParseResponse, .{ .corpus = built });
}

fn fuzzParseResponse(_: void, smith: *std.testing.Smith) !void {
    try parseHarness(std.testing.Smith, smith, testing.allocator);
}

const fz = @import("fuzz_test.zig");
const ParseMark = fz.Marker(enum { empty, rejected, parsed, with_basic });
const VerifyMark = fz.Marker(enum { genuine_accepted, flipped_refused, cert_damaged });

/// The corpus the driver draws its damaged inputs from, and the fixture the
/// verify harness runs on, built once per process (a key generation each).
/// They outlive every test's allocator, hence the page allocator.
var driver_parse_corpus: ?ParseCorpus = null;
var driver_verify_ctx: ?VerifyFuzzCtx = null;

fn driverParseCorpus() ![]const []const u8 {
    if (driver_parse_corpus == null) {
        driver_parse_corpus = .{};
        return driver_parse_corpus.?.build(std.heap.page_allocator); // global-alloc-ok: process-lifetime fuzz/test fixture cached across driver runs, outlives testing.allocator's per-test teardown
    }
    return &driver_parse_corpus.?.seeds;
}

fn driverVerifyCtx() !*const VerifyFuzzCtx {
    if (driver_verify_ctx == null) {
        const gpa = std.heap.page_allocator; // global-alloc-ok: process-lifetime fuzz fixture, as above
        const fx = try makeRsaFixture(gpa);
        const issuer = try extractBits(fx.issuer_der);
        const subject = try extractBits(fx.subject_der);
        var prng = std.Random.DefaultPrng.init(0xf0e1d2c3);
        var dkp: rsa.KeyPair = undefined;
        try rsa.generate(&dkp, prng.random(), 1024, 65537);
        const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
            .common_name = "fuzz delegated responder",
            .serial = 9,
            .not_before = "200101000000Z",
            .not_after = "400101000000Z",
            .is_ca = false,
        });
        const dbits = try extractBits(delegate_self);
        const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, try spkiOf(delegate_self), dbits.subject_name, .ocsp_signing);
        const resp_der = try buildResponse(gpa, .{
            .issuer = issuer,
            .subject_serial = subject.serial,
            .responder_by_name = dbits.subject_name,
            .certs = delegate_cert,
            .sign_rsa = dkp.secret_key,
        });
        driver_verify_ctx = .{ .response = resp_der, .issuer = fx.issuer_der, .subject = fx.subject_der };
    }
    return &driver_verify_ctx.?;
}

/// `parseResponse` over arbitrary bytes, or (driver) a corpus entry -- the
/// genuine plain and delegated responses among them -- with 0-3 octets
/// damaged: random DER never spells an OCSPResponse.
fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [parse_buf_len]u8 = undefined;
    const corpus: []const []const u8 = if (S == fz.fuzz_driver.Rng) try driverParseCorpus() else &.{};
    const len = fz.drawInput(S, src, &buf, corpus);
    if (len == 0) ParseMark.mark(.empty);
    const parsed = ocsp.parseResponse(buf[0..len]) catch {
        ParseMark.mark(.rejected);
        return;
    };
    ParseMark.mark(.parsed);
    if (parsed.basic != null) ParseMark.mark(.with_basic);
}

fn parseHarnessDriver(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    return parseHarness(S, src, gpa);
}

test "fuzz driver: OCSP_FUZZ (parseResponse)" {
    if (fz.driverRequested("OCSP_FUZZ")) _ = try driverParseCorpus();
    try fz.fuzz_driver.run(parseHarnessDriver, .{ .prefix = "OCSP_FUZZ", .name = "parse" });
}

test "fuzz harness: 400 seeds of parseResponse in every test run, and they get everywhere" {
    try ParseMark.reach(parseHarnessDriver, "ocsp-parse", 400);
}

/// The static seeds plus a genuine response and that response with one octet
/// of its `tbsResponseData` flipped — built at run time because the fixture
/// comes out of this module's own DER writer and an RSA key it generates.
const ParseCorpus = struct {
    /// The response with an embedded responder certificate — what a real
    /// responder actually returns, and the one that does not fit the buffer
    /// this harness used to have.
    delegated: []u8 = &.{},
    /// The same without embedded certificates, for the short-response shape.
    plain: []u8 = &.{},
    stores: [3][]u8 = .{ &.{}, &.{}, &.{} },
    seeds: [parse_static_seeds.len + 3][]const u8 = undefined,

    fn build(self: *ParseCorpus, gpa: std.mem.Allocator) ![]const []const u8 {
        var fx = try makeRsaFixture(gpa);
        defer fx.deinit(gpa);
        const issuer = try extractBits(fx.issuer_der);
        const subject = try extractBits(fx.subject_der);

        self.plain = try buildResponse(gpa, .{
            .issuer = issuer,
            .subject_serial = subject.serial,
            .responder_by_name = issuer.subject_name,
            .sign_rsa = fx.kp.secret_key,
        });

        var prng = std.Random.DefaultPrng.init(0xf0e1d2c3);
        var dkp: rsa.KeyPair = undefined;
        try rsa.generate(&dkp, prng.random(), 1024, 65537);
        const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
            .common_name = "fuzz delegated responder",
            .serial = 9,
            .not_before = "200101000000Z",
            .not_after = "400101000000Z",
            .is_ca = false,
        });
        defer gpa.free(delegate_self);
        const dbits = try extractBits(delegate_self);
        const delegate_cert = try buildDelegateCert(
            gpa,
            fx.kp.secret_key,
            issuer.subject_name,
            try spkiOf(delegate_self),
            dbits.subject_name,
            .ocsp_signing,
        );
        defer gpa.free(delegate_cert);
        self.delegated = try buildResponse(gpa, .{
            .issuer = issuer,
            .subject_serial = subject.serial,
            .responder_by_name = dbits.subject_name,
            .certs = delegate_cert,
            .sign_rsa = dkp.secret_key,
        });

        for (parse_static_seeds, 0..) |sd, i| self.seeds[i] = sd;
        const frames = [_][]const u8{ self.plain, self.delegated, self.delegated };
        for (frames, 0..) |frame, k| {
            self.stores[k] = try gpa.alloc(u8, 4 + frame.len);
            self.seeds[parse_static_seeds.len + k] = fuzzseed.seedInto(self.stores[k], frame);
        }
        // The third is the delegated response with one octet of it flipped.
        self.stores[2][4 + self.delegated.len / 2] ^= 0x01;
        return &self.seeds;
    }

    fn deinit(self: *ParseCorpus, gpa: std.mem.Allocator) void {
        gpa.free(self.plain);
        gpa.free(self.delegated);
        for (self.stores) |st| gpa.free(st);
    }
};

test "corpus: every parseResponse seed reaches the parser, and what it decodes is pinned" {
    // The number that matters is not "did anything parse" but whether the
    // corpus can carry a REAL response at all: at the old 512-octet buffer it
    // could not, because a seed longer than the buffer reads back empty rather
    // than truncated, and this module's own fixture is over 1500 octets.
    const gpa = testing.allocator;
    var c: ParseCorpus = .{};
    const seeds = try c.build(gpa);
    defer c.deinit(gpa);

    var nonempty: usize = 0;
    var octets: usize = 0;
    var accepted: usize = 0;
    var with_basic: usize = 0;
    for (seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [parse_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        octets += len;
        const parsed = ocsp.parseResponse(buf[0..len]) catch continue;
        accepted += 1;
        if (parsed.basic != null) with_basic += 1;
    }
    // One seed is deliberately the empty slice.
    try testing.expectEqual(seeds.len - 1, nonempty);
    // Measured 2026-09-07. Before the draw was restructured every round parsed
    // the empty slice: 0 non-empty, 0 octets, 0 accepted.
    try testing.expectEqual(@as(usize, 2172), octets);
    try testing.expectEqual(@as(usize, 4), accepted);
    // The number the degenerate input cannot produce: a decoded BasicOCSPResponse.
    try testing.expectEqual(@as(usize, 3), with_basic);
    // And the point of the buffer change: the response a real responder
    // returns — the one carrying its own certificate — does NOT fit the 512
    // octets this harness used to have, and a seed over the buffer reads back
    // EMPTY, not truncated. So the accepting path was unreachable for the only
    // response shape that matters.
    try testing.expect(c.delegated.len > 512);
    try testing.expect(c.delegated.len <= parse_buf_len);
}

// ── fuzz: the parsers behind `verify`, which the harness above cannot reach ──
//
// W2 A3 (F5) recorded that `fuzzParseResponse` was the module's only harness,
// and that a 90-second coverage-guided window over it never entered `verify`
// at all. The obstacle is structural, not statistical: `verify` takes an
// already-parsed `Response`, and reaching one means a corpus of arbitrary
// octets first has to spell a complete DER `OCSPResponse` — nested SEQUENCEs,
// an ENUMERATED status, the `id-pkix-ocsp-basic` OID, an OCTET STRING wrapper
// — which it never does. So `resolveDelegate`'s walk over `certs [0]`, the
// `parseCert` structure walk it runs on each embedded responder certificate,
// `findMatchingSingle`/`parseSingleTail`/`parseRevoked`, and
// `hasOcspSigningEku` had never been handed a hostile byte, even though every
// one of them consumes bytes a MITM chose.
//
// The fixture below is a *delegated* response, so `certs [0]` is populated and
// the delegate path is on by default rather than by luck. The fuzzer then
// chooses where to damage it: the response (which the signature covers end to
// end), the caller's issuer or subject certificate, or — the direct route into
// `parseCert` — arbitrary octets where a certificate is expected.
//
// Two of the assertions are there to keep the harness honest rather than to
// find a bug: on the iterations that damage nothing, the fixture MUST still
// verify `.good` and `.delegated`. A harness that stops reaching `verify` (a
// fixture that rots, an option that drifts) then fails loudly instead of
// quietly reporting "no crashes" forever.

const VerifyFuzzCtx = struct {
    response: []const u8,
    issuer: []const u8,
    subject: []const u8,
};

test "fuzz: verify's certificate and delegate parsers on damaged input" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var prng = std.Random.DefaultPrng.init(0xf0e1d2c3);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "fuzz delegated responder",
        .serial = 9,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const delegate_cert = try buildDelegateCert(
        gpa,
        fx.kp.secret_key,
        issuer.subject_name,
        try spkiOf(delegate_self),
        dbits.subject_name,
        .ocsp_signing,
    );
    defer gpa.free(delegate_cert);

    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key,
    });
    defer gpa.free(resp_der);

    // Positive control, before a single fuzz input runs: without this, every
    // "no crash" below could be reporting on a fixture that stopped verifying.
    const control = try ocsp.verify(
        try ocsp.parseResponse(resp_der),
        fx.issuer_der,
        fx.subject_der,
        defaultOpts(),
    );
    try testing.expect(control.status == .good);
    try testing.expect(control.delegated);

    const ctx = VerifyFuzzCtx{
        .response = resp_der,
        .issuer = fx.issuer_der,
        .subject = fx.subject_der,
    };
    try verifyCorpusGuard(&ctx);
    try testing.fuzz(&ctx, fuzzVerify, .{ .corpus = &verify_seeds });
}

/// Flips between one and four octets, then reports whether the buffer actually
/// differs from the original — two flips of the same octet can cancel, and an
/// "it was mutated" flag that is not measured is how a false positive gets
/// into a security assertion.
fn damage(script: *fuzzseed.Cursor, buf: []u8, original: []const u8) bool {
    if (buf.len == 0) return false;
    const n = script.ranged(1, 4);
    var k: usize = 0;
    while (k < n) : (k += 1) {
        // A 16-bit offset, not an octet: `resp` is over 1500 octets, so an
        // offset drawn from ONE octet could only ever damage the first 256 —
        // the whole `tbsResponseData` past that, and the signature over it,
        // would have been out of reach of the assertion below.
        const at = script.word() % buf.len;
        buf[at] ^= @intCast(script.ranged(1, 255));
    }
    return !std.mem.eql(u8, buf, original);
}

/// How many octets of script `fuzzVerify` will read. Big enough for mode 4 to
/// fill both certificate buffers from the seed rather than from a cycle.
const verify_script_len = 2560;

fn fuzzVerify(ctx: *const VerifyFuzzCtx, smith: *std.testing.Smith) !void {
    try verifyHarness(std.testing.Smith, smith, ctx);
}

fn verifyHarnessDriver(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    return verifyHarness(S, src, try driverVerifyCtx());
}

test "fuzz driver: OCSP_FUZZ (verify: genuine accepted, flipped refused)" {
    if (fz.driverRequested("OCSP_FUZZ")) _ = try driverVerifyCtx();
    try fz.fuzz_driver.run(verifyHarnessDriver, .{ .prefix = "OCSP_FUZZ", .name = "verify" });
}

test "fuzz harness: 300 seeds of verify in every test run, genuine accepted and flipped refused" {
    try VerifyMark.reach(verifyHarnessDriver, "ocsp-verify", 300);
}

fn verifyHarness(comptime S: type, smith: *S, ctx: *const VerifyFuzzCtx) !void {
    // One byte-first draw, read as a SCRIPT. It used to be a chain of ranged
    // `Smith` draws opening with `smith.valueRangeAtMost(u8, 0, 4)` for the
    // mode, with a `verifySeed(mode, bits, n)` helper writing each choice as
    // its own little-endian `u64` word. That worked — the words were sized to
    // fall inside their ranges — but it made every seed an opaque list of
    // 64-bit words, and any range this harness later widens past a word that
    // was hand-chosen for the old one silently collapses that draw to its
    // minimum with the suite still green. `Cursor` reads the choices out of
    // the seed's own octets instead, so a seed is a reviewable script and the
    // gate is satisfied by the same change.
    var script_buf: [verify_script_len]u8 = undefined;
    const script_len: usize = smith.slice(&script_buf);
    var script: fuzzseed.Cursor = .{ .bytes = script_buf[0..script_len] };

    var rbuf: [4096]u8 = undefined;
    var ibuf: [2048]u8 = undefined;
    var sbuf: [2048]u8 = undefined;
    if (ctx.response.len > rbuf.len or ctx.issuer.len > ibuf.len or ctx.subject.len > sbuf.len)
        return error.FixtureLargerThanHarnessBuffers;
    @memcpy(rbuf[0..ctx.response.len], ctx.response);
    @memcpy(ibuf[0..ctx.issuer.len], ctx.issuer);
    @memcpy(sbuf[0..ctx.subject.len], ctx.subject);
    const resp = rbuf[0..ctx.response.len];
    var iss: []const u8 = ibuf[0..ctx.issuer.len];
    var subj: []const u8 = sbuf[0..ctx.subject.len];

    // Script layout: one octet of mode, then whatever that mode reads.
    const mode = script.ranged(0, 4);
    var response_damaged = false;
    switch (mode) {
        0 => {}, // untouched — the positive control
        1 => response_damaged = damage(&script, resp, ctx.response),
        2 => _ = damage(&script, ibuf[0..ctx.issuer.len], ctx.issuer),
        3 => _ = damage(&script, sbuf[0..ctx.subject.len], ctx.subject),
        else => {
            // Arbitrary octets where a certificate is expected: the direct
            // route into `parseCert`'s structure walk. Lengths first, then the
            // bytes, so a short script cycles into them instead of leaving the
            // buffers at whatever the last round wrote.
            const iss_len: usize = script.word() % 1025;
            const subj_len: usize = script.word() % 1025;
            for (ibuf[0..iss_len]) |*b| b.* = script.byte();
            for (sbuf[0..subj_len]) |*b| b.* = script.byte();
            iss = ibuf[0..iss_len];
            subj = sbuf[0..subj_len];
        },
    }

    // ⚠ The clock is PINNED for the response-damage mode, and that is the whole
    // difference between this harness testing what it says and testing nothing.
    // With `now_unix` randomized here too, the freshness check rejected almost
    // every damaged response before reaching the `DamagedResponseAccepted`
    // assertion below — so the assertion was dead, and the harness reported "no
    // crashes" for as long as it existed. Pinning it made the assertion fire in
    // 287 coverage-guided runs, on a real defect. The other modes keep the
    // random clock, which is what exercises the freshness logic itself.
    const opts: ocsp.VerifyOptions = if (mode == 0 or mode == 1) defaultOpts() else .{
        .now_unix = @as(i64, @as(i32, @bitCast((@as(u32, script.word()) << 16) | @as(u32, script.word())))),
        .max_age_seconds = script.word(),
        .expected_nonce = null,
    };

    const parsed = ocsp.parseResponse(resp) catch {
        if (mode != 1) return error.UndamagedFixtureNoLongerParses;
        if (response_damaged) VerifyMark.mark(.flipped_refused);
        return;
    };
    const verdict = ocsp.verify(parsed, iss, subj, opts) catch {
        if (mode == 0) return error.UndamagedFixtureRejected;
        if (response_damaged) VerifyMark.mark(.flipped_refused);
        if (mode >= 2) VerifyMark.mark(.cert_damaged);
        return;
    };
    if (mode == 0) {
        if (verdict.status != .good) return error.UndamagedFixtureNotGood;
        if (!verdict.delegated) return error.UndamagedFixtureNotDelegated;
        VerifyMark.mark(.genuine_accepted);
    }
    // Every octet of this response is inside the signed `tbsResponseData`,
    // inside the signature over it, inside a certificate the issuer signed, or
    // in a wrapper this module's parser holds to exactly one encoding — so
    // altering any of them must stop it verifying.
    //
    // ⚠ This assertion used to exempt the embedded certificates. A single-bit
    // sweep had left the delegate certificate's outer signatureAlgorithm NULL
    // parameters malleable, and the exemption blamed `x509`. Wrong owner: the
    // certificate is parsed by this module's own `parseCert`, which now holds
    // the outer AlgorithmIdentifier to the signed inner one (RFC 5280
    // §4.1.1.2). `TEETH: no byte of a response ...` pins the same claim
    // deterministically.
    if (response_damaged) return error.DamagedResponseAccepted;
}

/// ⭐ The lesson this module already paid for, made permanent. `fuzzVerify`'s
/// `DamagedResponseAccepted` assertion — "a response altered anywhere outside
/// its embedded certificates must not verify" — is only ARMED on the rounds
/// where `mode == 1` AND `damage` actually changed an octet. It was once dead
/// for a different reason (a randomized `now_unix` refused nearly every
/// damaged response on freshness first, so the assertion was never reached),
/// and the fix was to pin the clock for that mode. Nothing pinned the OTHER
/// half: how many rounds arm it at all. A corpus that drifts to mode 0, or
/// whose flips cancel, would leave "no crashes" reported for ever again — so
/// the count of armed rounds is measured here, deterministically.
fn verifyCorpusGuard(ctx: *const VerifyFuzzCtx) !void {
    var modes = @as([5]usize, @splat(0));
    var armed: usize = 0;
    var nonempty: usize = 0;
    var script_octets: usize = 0;
    for (verify_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script_buf: [verify_script_len]u8 = undefined;
        const n: usize = smith.slice(&script_buf);
        if (n != 0) nonempty += 1;
        script_octets += n;
        var script: fuzzseed.Cursor = .{ .bytes = script_buf[0..n] };
        const mode = script.ranged(0, 4);
        modes[mode] += 1;
        if (mode != 1) continue;
        var rbuf: [4096]u8 = undefined;
        @memcpy(rbuf[0..ctx.response.len], ctx.response);
        if (damage(&script, rbuf[0..ctx.response.len], ctx.response)) armed += 1;
    }
    // Every seed carries a script; none of them is the empty one, because an
    // empty script IS mode 0 and mode 0 is already spelled out.
    try testing.expectEqual(verify_seeds.len, nonempty);
    // Measured 2026-09-07.
    try testing.expectEqual(@as(usize, 157), script_octets);
    // All five modes are selected, which the old u64-word seeds also achieved
    // — the number that was never pinned is the next one.
    for (modes) |m| try testing.expect(m > 0);
    // ⭐ The rounds on which `DamagedResponseAccepted` is live. One mode-1 seed
    // flips the same octet twice on purpose, so it is NOT armed, which is what
    // makes this a measurement of `damage`'s return value and not of the seed
    // count.
    try testing.expectEqual(@as(usize, 5), armed);
}

/// Without `--fuzz` the runner feeds only `options.corpus` plus one empty
/// input, and an empty script makes every `Cursor` read return its range
/// minimum — mode 0 for ever. Each seed is a plain octet script: the first
/// octet picks the mode, and the rest is read by that mode in the order
/// `fuzzVerify` documents.
const verify_seeds = [_][]const u8{
    fuzzseed.seedHex("00"), // the positive control: nothing is damaged
    fuzzseed.seedHex("01" ++ "01" ++ "0000" ++ "7f"), // damage the response's FIRST octet — the outer SEQUENCE tag
    fuzzseed.seedHex("01" ++ "01" ++ "0004" ++ "01"), // one bit inside the length of the outer wrapper
    fuzzseed.seedHex("01" ++ "01" ++ "0140" ++ "ff"), // ⭐ offset 320: past what a one-octet offset could ever have reached
    fuzzseed.seedHex("01" ++ "04" ++ "0032" ++ "11" ++ "0190" ++ "22" ++ "02bc" ++ "44" ++ "0400" ++ "88"), // four flips spread across the response
    fuzzseed.seedHex("01" ++ "02" ++ "0080" ++ "01" ++ "0080" ++ "01"), // ⭐ two flips of the SAME octet: they cancel, and `damage` must report false
    fuzzseed.seedHex("02" ++ "01" ++ "0010" ++ "5a" ++ "0000" ++ "0000" ++ "0e10"), // damage the issuer cert, then a clock and a max_age
    fuzzseed.seedHex("03" ++ "02" ++ "0020" ++ "7f" ++ "0100" ++ "01" ++ "ffff" ++ "ffff" ++ "ffff"), // damage the subject cert, with the clock at its far end
    fuzzseed.seedHex("04" ++ "0000" ++ "0000" ++ "0000" ++ "0000" ++ "0000"), // ⭐ mode 4 with BOTH certificates empty
    fuzzseed.seedHex("04" ++ "0001" ++ "0001" ++ "30" ++ "30" ++ "0000" ++ "0000" ++ "0000"), // a single octet each
    fuzzseed.seedHex("04" ++ "0400" ++ "0400" ++ strRepeat("30820100", 4) ++ "0000" ++ "0000" ++ "0e10"), // 1024 octets each, opening like a certificate and then cycling
    fuzzseed.seedHex("04" ++ "03e8" ++ "0064" ++ strRepeat("ff", 32) ++ "0000" ++ "0000" ++ "0000"), // no DER structure at all where a certificate belongs
};

/// Extract the SubjectPublicKeyInfo TLV bytes from a certificate.
fn spkiOf(cert: []const u8) ![]const u8 {
    const c = try elem(cert, 0);
    const tbs = try elem(cert, c.slice.start);
    var pos = tbs.slice.start;
    var first = try elem(cert, pos);
    if (@as(u8, @bitCast(first.identifier)) == 0xa0) {
        pos = first.slice.end;
        first = try elem(cert, pos);
    }
    const serial = first;
    const sig_alg = try elem(cert, serial.slice.end);
    const issuer = try elem(cert, sig_alg.slice.end);
    const validity = try elem(cert, issuer.slice.end);
    const subject = try elem(cert, validity.slice.end);
    const spki_start = subject.slice.end;
    const spki = try elem(cert, spki_start);
    return cert[spki_start..spki.slice.end];
}

test "TEETH: no byte of a response, its embedded delegate certificate included, can be altered undetected" {
    // `verify`'s own fuzz harness asserts "a response altered anywhere must not
    // verify". That assertion was DEAD: the damage mode also randomized
    // `now_unix`, so the freshness check rejected almost every damaged input
    // before the assertion could be reached. Pinning the clock — one change —
    // made it fire in 287 coverage-guided runs.
    //
    // And it fires because it is TRUE. A single bit flipped at each offset in
    // turn, over a whole 848-byte response: **14 offsets still verified
    // `good`.** Every one of them sits outside `tbsResponseData`, so the
    // signature cannot object; only the parser can, and it did not:
    //
    //   9,10 13,14 28 32 374,378  container LENGTH octets, never checked for
    //                             exact closure ([0] EXPLICIT, ResponseBytes,
    //                             the response OCTET STRING, BasicOCSPResponse,
    //                             the certs wrapper)
    //   238,239                   the `05 00` NULL parameters of the response's
    //                             own signatureAlgorithm, never read
    //   243                       the signature BIT STRING's unused-bits octet,
    //                             which DER requires to be zero, never read
    //   714,715                   the same NULL parameters in the embedded
    //                             DELEGATE CERTIFICATE's outer signatureAlgorithm
    //                             (all 8 bits of both: 16 flips)
    //
    // The first three classes were fixed first. The last was exempted here for
    // a while as `x509`'s, which it was not: `parseCert` in this module reads
    // the certificate, and now requires its outer AlgorithmIdentifier to equal
    // the signed one (RFC 5280 §4.1.1.2). With the exemption gone, restoring any
    // of the four gaps turns this red.
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);

    var prng = std.Random.DefaultPrng.init(0xf0e1d2c3);
    var dkp: rsa.KeyPair = undefined;
    try rsa.generate(&dkp, prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, &dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "fuzz delegated responder",
        .serial = 9,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, try spkiOf(delegate_self), dbits.subject_name, .ocsp_signing);
    defer gpa.free(delegate_cert);
    const resp_der = try buildResponse(gpa, .{
        .issuer = issuer,
        .subject_serial = subject.serial,
        .responder_by_name = dbits.subject_name,
        .certs = delegate_cert,
        .sign_rsa = dkp.secret_key,
    });
    defer gpa.free(resp_der);

    // The sweep covers the embedded delegate certificate too, so it must be there.
    const parsed_ok = try ocsp.parseResponse(resp_der);
    _ = parsed_ok.basic.?.certs orelse return error.FixtureHasNoCerts;

    // Positive control first: the undamaged fixture verifies, so a run of zero
    // survivors below cannot be "nothing verifies any more".
    try testing.expect((try ocsp.verify(parsed_ok, fx.issuer_der, fx.subject_der, defaultOpts())).status == .good);

    const buf = try gpa.dupe(u8, resp_der);
    defer gpa.free(buf);
    var outside_survivors: usize = 0;
    // ⚠ ALL EIGHT bit positions, not just bit 0. The first version of this
    // sweep flipped `^= 0x01` and reported the response clean once ten offsets
    // were fixed; the module's own fuzz harness then immediately found more,
    // because it flips arbitrary bits. A probe weaker than the harness it is
    // meant to explain will agree with you.
    for (0..resp_der.len) |off| {
        for (0..8) |bit| {
            @memcpy(buf, resp_der);
            buf[off] ^= (@as(u8, 1) << @intCast(bit));
            const parsed = ocsp.parseResponse(buf) catch continue;
            const verdict = ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts()) catch continue;
            if (verdict.status != .good) continue;
            outside_survivors += 1;
            if (outside_survivors <= 20) {
                std.debug.print("malleable at offset {d} bit {d}: byte {x:0>2}  ctx {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
                    off,                                       bit,                                    resp_der[off],
                    resp_der[if (off >= 2) off - 2 else 0],    resp_der[if (off >= 1) off - 1 else 0], resp_der[@min(off + 1, resp_der.len - 1)],
                    resp_der[@min(off + 2, resp_der.len - 1)],
                });
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), outside_survivors);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── Ed25519 responder signatures (2026-11-16) ──────────────────────────────
// No external vector: key, certificate and response are built in-test with
// std's Ed25519 (RFC 8032 itself is std's concern); the module's own verifier
// is what is exercised.

/// Minimal Ed25519 issuer cert (SPKI = id-Ed25519, no parameters); its own
/// signature is never checked by `ocsp.verify`.
fn buildEdIssuerCert(gpa: std.mem.Allocator, pk: [32]u8, name: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const version = try b.explicit(0, try b.integerU64(2));
    const serial = try b.integerU64(4);
    const sig_alg = try b.seq(&.{try b.oid(&oid_ed25519)});
    const validity = try b.seq(&.{
        try b.tlv(0x17, "200101000000Z"),
        try b.tlv(0x17, "400101000000Z"),
    });
    const spki = try b.seq(&.{ try b.seq(&.{try b.oid(&oid_ed25519)}), try b.bitString(&pk) });
    const tbs = try b.seq(&.{ version, serial, sig_alg, name, validity, name, spki });
    const cert = try b.seq(&.{ tbs, sig_alg, try b.bitString(&@as([64]u8, @splat(0))) });
    return gpa.dupe(u8, cert);
}

const EdCase = struct {
    issuer: []u8,
    leaf: []u8,
    bits: IssuerBits,
    serial: []const u8,
    kp: std.crypto.sign.Ed25519.KeyPair,
    seed: [32]u8,
    rsa_fx: RsaFixture,

    fn deinit(self: *EdCase, gpa: std.mem.Allocator) void {
        gpa.free(self.issuer);
        gpa.free(self.leaf);
        self.rsa_fx.deinit(gpa);
    }
};

fn makeEdCase(gpa: std.mem.Allocator) !EdCase {
    const seed: [32]u8 = @splat(0x5d);
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const nb: der_writer.Builder = .{ .a = arena.allocator() };
    const name = try buildName(nb, "Ed25519 OCSP CA");
    const issuer = try buildEdIssuerCert(gpa, kp.public_key.toBytes(), name);
    errdefer gpa.free(issuer);
    var fx = try makeRsaFixture(gpa);
    errdefer fx.deinit(gpa);
    const bits = try extractBits(issuer);
    const subject = try extractBits(fx.subject_der);
    const leaf = try buildLeafCert(gpa, fx.kp.secret_key, bits.subject_name, try spkiOf(fx.subject_der), "leaf.example.com", subject.serial);
    return .{ .issuer = issuer, .leaf = leaf, .bits = bits, .serial = subject.serial, .kp = kp, .seed = seed, .rsa_fx = fx };
}

test "verify: Ed25519 direct-issuer signature accepted" {
    const gpa = testing.allocator;
    var c = try makeEdCase(gpa);
    defer c.deinit(gpa);
    const resp = try buildResponse(gpa, .{
        .issuer = c.bits,
        .subject_serial = c.serial,
        .responder_by_name = c.bits.subject_name,
        .sign_ed25519 = c.seed,
    });
    defer gpa.free(resp);
    const v = try ocsp.verify(try ocsp.parseResponse(resp), c.issuer, c.leaf, defaultOpts());
    try testing.expect(v.status == .good);
    try testing.expect(!v.delegated);
}

test "verify: Ed25519 tampered signed byte and tampered signature are SignatureInvalid" {
    const gpa = testing.allocator;
    var c = try makeEdCase(gpa);
    defer c.deinit(gpa);
    const resp = try buildResponse(gpa, .{
        .issuer = c.bits,
        .subject_serial = c.serial,
        .responder_by_name = c.bits.subject_name,
        .sign_ed25519 = c.seed,
    });
    defer gpa.free(resp);

    const tampered = try gpa.dupe(u8, resp);
    defer gpa.free(tampered);
    const at = std.mem.find(u8, tampered, "20270101").?;
    tampered[at + 7] = '2'; // thisUpdate day 01 -> 02, still a valid time
    try testing.expectError(error.SignatureInvalid, ocsp.verify(try ocsp.parseResponse(tampered), c.issuer, c.leaf, defaultOpts()));

    // The response signature BIT STRING: 03 41 00 <64 bytes>, right after the
    // id-Ed25519 AlgorithmIdentifier 30 05 06 03 2b 65 70.
    const sig = try gpa.dupe(u8, resp);
    defer gpa.free(sig);
    const alg = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    const sa = std.mem.find(u8, sig, &alg).? + alg.len;
    try testing.expectEqual(@as(u8, 0x03), sig[sa]);
    sig[sa + 3 + 5] ^= 0x01;
    try testing.expectError(error.SignatureInvalid, ocsp.verify(try ocsp.parseResponse(sig), c.issuer, c.leaf, defaultOpts()));
}

test "verify: Ed25519 signature by a different key is SignatureInvalid" {
    const gpa = testing.allocator;
    var c = try makeEdCase(gpa);
    defer c.deinit(gpa);
    const resp = try buildResponse(gpa, .{
        .issuer = c.bits,
        .subject_serial = c.serial,
        .responder_by_name = c.bits.subject_name,
        .sign_ed25519 = @as([32]u8, @splat(0x5e)),
    });
    defer gpa.free(resp);
    try testing.expectError(error.SignatureInvalid, ocsp.verify(try ocsp.parseResponse(resp), c.issuer, c.leaf, defaultOpts()));
}

test "verify: key/algorithm mismatch is refused (Ed25519 signature under a P-256 key, ECDSA signature under an Ed25519 key)" {
    const gpa = testing.allocator;
    // (1) Ed25519 signatureAlgorithm, responder (issuer) key is P-256.
    {
        var fx = try makeRsaFixture(gpa);
        defer fx.deinit(gpa);
        const subject = try extractBits(fx.subject_der);
        const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x77)));
        const sec1 = kp.public_key.toUncompressedSec1();
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const nb: der_writer.Builder = .{ .a = arena.allocator() };
        const ec_issuer = try buildEcIssuerCert(gpa, &sec1, try buildName(nb, "ECDSA OCSP CA"));
        defer gpa.free(ec_issuer);
        const ec_bits = try extractBits(ec_issuer);
        const leaf = try buildLeafCert(gpa, fx.kp.secret_key, ec_bits.subject_name, try spkiOf(fx.subject_der), "leaf.example.com", subject.serial);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = ec_bits, .subject_serial = subject.serial, .responder_by_name = ec_bits.subject_name, .sign_ed25519 = @as([32]u8, @splat(1)) });
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, ocsp.verify(try ocsp.parseResponse(resp), ec_issuer, leaf, defaultOpts()));
    }
    // (2) ecdsa-with-SHA256 signatureAlgorithm, responder key is Ed25519.
    {
        var c = try makeEdCase(gpa);
        defer c.deinit(gpa);
        const resp = try buildResponse(gpa, .{ .issuer = c.bits, .subject_serial = c.serial, .responder_by_name = c.bits.subject_name, .sign_ecdsa = @as([32]u8, @splat(0x33)) });
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, ocsp.verify(try ocsp.parseResponse(resp), c.issuer, c.leaf, defaultOpts()));
    }
    // (3) RSA signatureAlgorithm, responder key is Ed25519.
    {
        var c = try makeEdCase(gpa);
        defer c.deinit(gpa);
        const resp = try buildResponse(gpa, .{ .issuer = c.bits, .subject_serial = c.serial, .responder_by_name = c.bits.subject_name, .sign_rsa = c.rsa_fx.kp.secret_key });
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, ocsp.verify(try ocsp.parseResponse(resp), c.issuer, c.leaf, defaultOpts()));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 2026-11-17 whole-module mutation: tests added for the survivors of round 1
// ════════════════════════════════════════════════════════════════════════════

const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const t_now: i64 = 1_800_000_000; // 2027-01-15 08:00:00 UTC
const t_stamp = "20270115080000Z";

fn makeRsaFixtureWith(gpa: std.mem.Allocator, seed: u64, cn: []const u8, serial: []const u8) !RsaFixture {
    var prng = std.Random.DefaultPrng.init(seed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    const issuer = try rsa.selfSignedCert(gpa, &kp.secret_key, kp.public_key, Sha256, .{
        .common_name = cn,
        .serial = 1,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = true,
    });
    errdefer gpa.free(issuer);
    const issuer_bits = try extractBits(issuer);
    const subject = try buildLeafCert(gpa, kp.secret_key, issuer_bits.subject_name, try spkiOf(issuer), "leaf2.example.com", serial);
    return .{ .issuer_der = issuer, .subject_der = subject, .kp = kp };
}

// ── signer hooks ──

fn rsaSigner(comptime H: type, comptime alg: []const u8) *const fn (*const anyopaque, der_writer.Builder, []const u8) anyerror!SigOut {
    const S = struct {
        fn f(ctx: *const anyopaque, b: der_writer.Builder, tbs: []const u8) anyerror!SigOut {
            const sk: *const rsa.SecretKey = @ptrCast(@alignCast(ctx));
            var out: [512]u8 = undefined;
            const sig = try rsa.signPkcs1v15(sk, H, tbs, &out);
            return .{ .alg = try b.seq(&.{ try b.oid(alg), try b.null() }), .sigval = try b.bitString(sig) };
        }
    };
    return &S.f;
}

fn ecSigner(comptime E: type, comptime alg: []const u8) *const fn (*const anyopaque, der_writer.Builder, []const u8) anyerror!SigOut {
    const S = struct {
        fn f(ctx: *const anyopaque, b: der_writer.Builder, tbs: []const u8) anyerror!SigOut {
            const kp: *const E.KeyPair = @ptrCast(@alignCast(ctx));
            const sig = try kp.sign(tbs, null);
            var buf: [E.Signature.der_encoded_length_max]u8 = undefined;
            return .{ .alg = try b.seq(&.{try b.oid(alg)}), .sigval = try b.bitString(sig.toDer(&buf)) };
        }
    };
    return &S.f;
}

const Params = enum { none, null_ok, null_with_content };
/// A signer that writes exactly the AlgorithmIdentifier and BIT STRING it is told to.
const RawSig = struct {
    alg_oid: []const u8,
    params: Params = .null_ok,
    sigval: []const u8, // full BIT STRING TLV
    fn f(ctx: *const anyopaque, b: der_writer.Builder, _: []const u8) anyerror!SigOut {
        const self: *const RawSig = @ptrCast(@alignCast(ctx));
        const alg = switch (self.params) {
            .none => try b.seq(&.{try b.oid(self.alg_oid)}),
            .null_ok => try b.seq(&.{ try b.oid(self.alg_oid), try b.null() }),
            .null_with_content => try b.seq(&.{ try b.oid(self.alg_oid), try b.tlv(0x05, "\x00") }),
        };
        return .{ .alg = alg, .sigval = self.sigval };
    }
    fn signer(self: *const RawSig) Signer {
        return .{ .ctx = self, .f = f };
    }
};

fn baseSpec(fx: *const RsaFixture) !RespSpec {
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);
    return .{ .issuer = issuer, .subject_serial = subject.serial, .responder_by_name = issuer.subject_name, .sign_rsa = fx.kp.secret_key };
}

fn verifyBytes(resp: []const u8, issuer: []const u8, subject: []const u8) !ocsp.Verdict {
    return ocsp.verify(try ocsp.parseResponse(resp), issuer, subject, defaultOpts());
}

// ── certificate builders for odd keys ──

fn spkiWith(b: der_writer.Builder, key_oid: []const u8, params: ?[]const u8, spk: []const u8) ![]const u8 {
    const alg = if (params) |pr| try b.seq(&.{ try b.oid(key_oid), pr }) else try b.seq(&.{try b.oid(key_oid)});
    return b.seq(&.{ alg, spk });
}

/// A certificate whose own signature nobody checks (an issuer): `name` (a Name TLV) as issuer and
/// subject, the given SPKI, and `outer_sigval` (a BIT STRING TLV) or a dummy one.
fn buildCertWith(gpa: std.mem.Allocator, name: []const u8, spki: []const u8, outer_sigval: ?[]const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const version = try b.explicit(0, try b.integerU64(2));
    const serial = try b.integerU64(3);
    const sig_alg = try b.seq(&.{try b.oid(&oid_ecdsa_sha256)});
    const validity = try b.seq(&.{ try b.tlv(0x17, "200101000000Z"), try b.tlv(0x17, "400101000000Z") });
    const tbs = try b.seq(&.{ version, serial, sig_alg, name, validity, name, spki });
    const cert = try b.seq(&.{ tbs, try b.seq(&.{try b.oid(&oid_ecdsa_sha256)}), outer_sigval orelse try b.bitString(&[_]u8{ 0xde, 0xad, 0xbe, 0xef }) });
    return gpa.dupe(u8, cert);
}

fn leafFor(gpa: std.mem.Allocator, fx: *const RsaFixture, issuer_name: []const u8) ![]u8 {
    const subject = try extractBits(fx.subject_der);
    return buildLeafCert(gpa, fx.kp.secret_key, issuer_name, try spkiOf(fx.subject_der), "leaf.example.com", subject.serial);
}

// ── A. CertID hash algorithms, and a CertID whose hash we do not know ──

test "verify: CertIDs hashed with SHA-1, SHA-384 and SHA-512 bind; so does SHA-256" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    inline for (.{ CertHash.sha1, CertHash.sha256, CertHash.sha384, CertHash.sha512 }) |h| {
        var spec = try baseSpec(&fx);
        spec.cert_hash = h;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
        try testing.expect(v.status == .good);
    }
}

test "verify: a CertID naming a hash this module does not know never matches, even with SHA-1's digests" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var spec = try baseSpec(&fx);
    spec.decoy = .unknown_alg;
    const resp = try buildResponse(gpa, spec);
    defer gpa.free(resp);
    const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
    try testing.expect(v.status == .good); // the genuine entry, not the revoked decoy ahead of it
}

// ── B. responder signature schemes: every hash with every key type, accepted and refused ──

test "verify: RSA responder signatures with SHA-1, SHA-384 and SHA-512" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var sk = fx.kp.secret_key;
    inline for (.{
        .{ Sha1, &oid_sha1_rsa },
        .{ Sha384, &oid_sha384_rsa },
        .{ Sha512, &oid_sha512_rsa },
    }) |c| {
        var spec = try baseSpec(&fx);
        spec.sign_rsa = null;
        spec.signer = .{ .ctx = &sk, .f = rsaSigner(c[0], c[1]) };
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
        try testing.expect(v.status == .good);
    }
}

fn ecMatrixCase(gpa: std.mem.Allocator, fx: *const RsaFixture, comptime Curve: type, comptime Hash: type, comptime alg: []const u8, comptime curve_oid: []const u8) !void {
    const E = std.crypto.sign.ecdsa.Ecdsa(Curve, Hash);
    const kp = try E.KeyPair.generateDeterministic(@as([E.KeyPair.seed_length]u8, @splat(0x61)));
    const sec1 = kp.public_key.toUncompressedSec1();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const name = try buildName(b, "EC matrix CA");
    const issuer = try buildCertWith(gpa, name, try spkiWith(b, &oid_ec_public_key, try b.oid(curve_oid), try b.bitString(&sec1)), null);
    defer gpa.free(issuer);
    const bits = try extractBits(issuer);
    const leaf = try leafFor(gpa, fx, bits.subject_name);
    defer gpa.free(leaf);
    const subject = try extractBits(fx.subject_der);
    const resp = try buildResponse(gpa, .{
        .issuer = bits,
        .subject_serial = subject.serial,
        .responder_by_name = bits.subject_name,
        .signer = .{ .ctx = &kp, .f = ecSigner(E, alg) },
    });
    defer gpa.free(resp);
    const v = try verifyBytes(resp, issuer, leaf);
    try testing.expect(v.status == .good);

    // One bit of r flipped: a well-formed signature that does not verify.
    const sig_at = @intFromPtr((try ocsp.parseResponse(resp)).basic.?.signature.ptr) - @intFromPtr(resp.ptr);
    const bad = try gpa.dupe(u8, resp);
    defer gpa.free(bad);
    bad[sig_at + 8] ^= 0x01;
    try testing.expectError(error.SignatureInvalid, verifyBytes(bad, issuer, leaf));
    // Not an Ecdsa-Sig-Value at all.
    bad[sig_at + 8] ^= 0x01;
    bad[sig_at] = 0x31;
    try testing.expectError(error.SignatureInvalid, verifyBytes(bad, issuer, leaf));
}

test "verify: ECDSA responder signatures, P-256 and P-384 with SHA-256, SHA-384 and SHA-512; a damaged one is SignatureInvalid" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const P256 = std.crypto.ecc.P256;
    const P384 = std.crypto.ecc.P384;
    inline for (.{
        .{ P256, Sha256, &oid_ecdsa_sha256, &oid_p256_curve },
        .{ P256, Sha384, &oid_ecdsa_sha384, &oid_p256_curve },
        .{ P256, Sha512, &oid_ecdsa_sha512, &oid_p256_curve },
        .{ P384, Sha256, &oid_ecdsa_sha256, &oid_p384_curve },
        .{ P384, Sha384, &oid_ecdsa_sha384, &oid_p384_curve },
        .{ P384, Sha512, &oid_ecdsa_sha512, &oid_p384_curve },
    }) |c| try ecMatrixCase(gpa, &fx, c[0], c[1], c[2], c[3]);
}

test "verify: an unknown signature algorithm, and keys that cannot be loaded, have their own errors" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const subject = try extractBits(fx.subject_der);
    const issuer_bits = try extractBits(fx.issuer_der);

    // (1) signatureAlgorithm OID this module does not know.
    {
        var raw: RawSig = .{ .alg_oid = &[_]u8{ 0x2a, 0x03, 0x04, 0x05 }, .sigval = try b.bitString("x") };
        var spec = try baseSpec(&fx);
        spec.signer = raw.signer();
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
    // (2) an issuer whose RSA key does not parse.
    {
        const name = try buildName(b, "garbage RSA key CA");
        const spki = try spkiWith(b, &oid_rsa_encryption, try b.null(), try b.bitString(&[_]u8{ 0x00, 0x01, 0x02 }));
        const issuer = try buildCertWith(gpa, name, spki, null);
        defer gpa.free(issuer);
        const leaf = try leafFor(gpa, &fx, name);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = .{ .subject_name = name, .key_bits = "", .serial = subject.serial }, .subject_serial = subject.serial, .responder_by_name = name, .sign_rsa = fx.kp.secret_key });
        defer gpa.free(resp);
        try testing.expectError(error.InvalidResponderKey, verifyBytes(resp, issuer, leaf));
    }
    // (3) an issuer key of a type this module does not know, under an RSA signature.
    {
        const name = try buildName(b, "unknown key type CA");
        const spki = try spkiWith(b, &[_]u8{ 0x2a, 0x03, 0x04 }, null, try b.bitString(&[_]u8{ 0x04, 0x01, 0x02 }));
        const issuer = try buildCertWith(gpa, name, spki, null);
        defer gpa.free(issuer);
        const leaf = try leafFor(gpa, &fx, name);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = .{ .subject_name = name, .key_bits = &[_]u8{ 0x04, 0x01, 0x02 }, .serial = subject.serial }, .subject_serial = subject.serial, .responder_by_name = name, .sign_rsa = fx.kp.secret_key });
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verifyBytes(resp, issuer, leaf));
    }
    // (4) an EC key with no named curve is not P-256 by default.
    {
        const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x71)));
        const sec1 = kp.public_key.toUncompressedSec1();
        const name = try buildName(b, "no curve CA");
        const spki = try spkiWith(b, &oid_ec_public_key, null, try b.bitString(&sec1));
        const issuer = try buildCertWith(gpa, name, spki, null);
        defer gpa.free(issuer);
        const leaf = try leafFor(gpa, &fx, name);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = .{ .subject_name = name, .key_bits = &sec1, .serial = subject.serial }, .subject_serial = subject.serial, .responder_by_name = name, .sign_ecdsa = kp.secret_key.bytes });
        defer gpa.free(resp);
        try testing.expectError(error.UnsupportedSignatureAlgorithm, verifyBytes(resp, issuer, leaf));
    }
    // (5) an EC key that is not a point, under the std ECDSA path (SHA-384).
    {
        const E = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha384);
        const kp = try E.KeyPair.generateDeterministic(@as([32]u8, @splat(0x72)));
        const bad_key = [_]u8{0x04} ++ @as([64]u8, @splat(0));
        const name = try buildName(b, "bad EC key CA");
        const spki = try spkiWith(b, &oid_ec_public_key, try b.oid(&oid_p256_curve), try b.bitString(&bad_key));
        const issuer = try buildCertWith(gpa, name, spki, null);
        defer gpa.free(issuer);
        const leaf = try leafFor(gpa, &fx, name);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = .{ .subject_name = name, .key_bits = &bad_key, .serial = subject.serial }, .subject_serial = subject.serial, .responder_by_name = name, .signer = .{ .ctx = &kp, .f = ecSigner(E, &oid_ecdsa_sha384) } });
        defer gpa.free(resp);
        try testing.expectError(error.InvalidResponderKey, verifyBytes(resp, issuer, leaf));
    }
    _ = issuer_bits;
}

test "verify: Ed25519 key and signature lengths, and a non-canonical key" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const subject = try extractBits(fx.subject_der);
    // A real Ed25519 issuer with a 63-byte signature.
    {
        var c = try makeEdCase(gpa);
        defer c.deinit(gpa);
        var raw: RawSig = .{ .alg_oid = &oid_ed25519, .params = .none, .sigval = try b.bitString(&@as([63]u8, @splat(1))) };
        const resp = try buildResponse(gpa, .{ .issuer = c.bits, .subject_serial = c.serial, .responder_by_name = c.bits.subject_name, .signer = raw.signer() });
        defer gpa.free(resp);
        try testing.expectError(error.SignatureInvalid, verifyBytes(resp, c.issuer, c.leaf));
    }
    // Keys of 31 bytes and 32 non-canonical bytes.
    const keys = [_][]const u8{ &@as([31]u8, @splat(7)), &@as([32]u8, @splat(0xff)) };
    const expect = [_]anyerror{ error.SignatureInvalid, error.InvalidResponderKey };
    for (keys, expect) |key, want| {
        const name = try buildName(b, "odd Ed25519 CA");
        const spki = try spkiWith(b, &oid_ed25519, null, try b.bitString(key));
        const issuer = try buildCertWith(gpa, name, spki, null);
        defer gpa.free(issuer);
        const leaf = try leafFor(gpa, &fx, name);
        defer gpa.free(leaf);
        const resp = try buildResponse(gpa, .{ .issuer = .{ .subject_name = name, .key_bits = key, .serial = subject.serial }, .subject_serial = subject.serial, .responder_by_name = name, .sign_ed25519 = @as([32]u8, @splat(3)) });
        defer gpa.free(resp);
        try testing.expectError(want, verifyBytes(resp, issuer, leaf));
    }
}

// ── C. delegated responders ──

const Dlg = struct {
    kp: rsa.KeyPair,
    self: []u8,
    bits: IssuerBits,
    spki: []const u8,
    fn deinit(d: *Dlg, gpa: std.mem.Allocator) void {
        gpa.free(d.self);
    }
};

fn mkDlg(gpa: std.mem.Allocator, seed: u64, cn: []const u8) !Dlg {
    var prng = std.Random.DefaultPrng.init(seed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    const self = try rsa.selfSignedCert(gpa, &kp.secret_key, kp.public_key, Sha256, .{
        .common_name = cn,
        .serial = 7,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    return .{ .kp = kp, .self = self, .bits = try extractBits(self), .spki = try spkiOf(self) };
}

test "verify: a delegated responder is found among decoys by name or by key; garbage or foreign certificates are refused" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var real = try mkDlg(gpa, 0xde1e6a7e, "real responder");
    defer real.deinit(gpa);
    var decoy = try mkDlg(gpa, 0xdec0de01, "decoy responder");
    defer decoy.deinit(gpa);
    const real_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, real.spki, real.bits.subject_name, .ocsp_signing);
    defer gpa.free(real_cert);
    const decoy_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, decoy.spki, decoy.bits.subject_name, .ocsp_signing);
    defer gpa.free(decoy_cert);
    const both = try std.mem.concat(gpa, u8, &.{ decoy_cert, real_cert });
    defer gpa.free(both);
    var key_hash: [20]u8 = undefined;
    Sha1.hash(real.bits.key_bits, &key_hash, .{});

    var spec = try baseSpec(&fx);
    spec.sign_rsa = real.kp.secret_key;
    spec.certs = both;
    // By name, then by key: the decoy comes first in `certs` and must be skipped.
    for ([_]bool{ false, true }) |by_key| {
        spec.responder_by_name = if (by_key) null else real.bits.subject_name;
        spec.responder_by_key = if (by_key) &key_hash else null;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
        try testing.expect(v.status == .good);
        try testing.expect(v.delegated);
    }
    // Only a decoy: no certificate matches the ResponderID.
    spec.responder_by_name = real.bits.subject_name;
    spec.responder_by_key = null;
    spec.certs = decoy_cert;
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.UntrustedResponder, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
    // The matching certificate is signed by somebody else, not by the issuer.
    const foreign = try buildDelegateCert(gpa, decoy.kp.secret_key, issuer.subject_name, real.spki, real.bits.subject_name, .ocsp_signing);
    defer gpa.free(foreign);
    spec.certs = foreign;
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.UntrustedResponder, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
    // `certs` that is not a certificate list at all.
    for ([_][]const u8{ "\x04\xff", "\x30\x00" }) |junk| {
        spec.certs = junk;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.Malformed, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
}

test "verify: a delegate's validity window is closed at both ends; an extension block without extendedKeyUsage is not enough" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var d = try mkDlg(gpa, 0xde1e6a7e, "window responder");
    defer d.deinit(gpa);
    var spec = try baseSpec(&fx);
    spec.sign_rsa = d.kp.secret_key;
    spec.responder_by_name = d.bits.subject_name;
    spec.this_update = t_stamp;
    spec.next_update = t_stamp;
    const opts: ocsp.VerifyOptions = .{ .now_unix = t_now };

    // notBefore == notAfter == now: accepted (the window is inclusive).
    {
        const cert = try buildDelegateCertValidity(gpa, fx.kp.secret_key, issuer.subject_name, d.spki, d.bits.subject_name, .ocsp_signing, "270115080000Z", "270115080000Z");
        defer gpa.free(cert);
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const parsed = try ocsp.parseResponse(resp);
        const v = try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, opts);
        try testing.expect(v.delegated);
        // thisUpdate == nextUpdate == now: also accepted, and the times come back exactly.
        try testing.expectEqual(t_now, v.this_update_unix);
        try testing.expectEqual(@as(?i64, t_now), v.next_update_unix);
        try testing.expectEqual(t_now, v.produced_at_unix);
        try testing.expectEqual(t_now, parsed.basic.?.produced_at_unix);
    }
    // One second before notBefore: expired (not yet valid).
    {
        const cert = try buildDelegateCertValidity(gpa, fx.kp.secret_key, issuer.subject_name, d.spki, d.bits.subject_name, .ocsp_signing, "270115080001Z", "400101000000Z");
        defer gpa.free(cert);
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.ResponderCertExpired, ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, opts));
    }
    // Extensions present, extendedKeyUsage absent.
    {
        const cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, d.spki, d.bits.subject_name, .other);
        defer gpa.free(cert);
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.ResponderMissingOcspSigning, ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, opts));
    }
}

test "verify: a delegate may use another key type than the issuer; its certificate is checked under ITS signature algorithm" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    // (1) P-256 delegate under an RSA issuer.
    {
        const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x55)));
        const sec1 = kp.public_key.toUncompressedSec1();
        const dname = try buildName(b, "EC responder");
        const spki = try spkiWith(b, &oid_ec_public_key, try b.oid(&oid_p256_curve), try b.bitString(&sec1));
        const cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, spki, dname, .ocsp_signing);
        defer gpa.free(cert);
        var spec = try baseSpec(&fx);
        spec.sign_rsa = null;
        spec.sign_ecdsa = kp.secret_key.bytes;
        spec.responder_by_name = dname;
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
        try testing.expect(v.delegated);
    }
    // (2) the delegate certificate signed with sha384WithRSA while the issuer's own certificate says sha256WithRSA.
    {
        var d = try mkDlg(gpa, 0xde1e6a7e, "sha384 responder");
        defer d.deinit(gpa);
        const version = try b.explicit(0, try b.integerU64(2));
        const sig_alg = try b.seq(&.{ try b.oid(&oid_sha384_rsa), try b.null() });
        const validity = try b.seq(&.{ try b.tlv(0x17, "200101000000Z"), try b.tlv(0x17, "400101000000Z") });
        const tbs = try b.seq(&.{ version, try b.integerU64(9), sig_alg, issuer.subject_name, validity, d.bits.subject_name, d.spki, try b.explicit(3, try b.seq(&.{try b.seq(&.{ try b.oid(&oid_ext_key_usage), try b.octetString(try b.seq(&.{try b.oid(&oid_ocsp_signing)})) })})) });
        var out: [512]u8 = undefined;
        const sig = try rsa.signPkcs1v15(&fx.kp.secret_key, Sha384, tbs, &out);
        const cert = try b.seq(&.{ tbs, sig_alg, try b.bitString(sig) });
        var spec = try baseSpec(&fx);
        spec.sign_rsa = d.kp.secret_key;
        spec.responder_by_name = d.bits.subject_name;
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
        try testing.expect(v.delegated);
    }
}

// ── D. nonce, malformed inputs, verifyMany ──

test "verify: a missing nonce, a nonce that differs in an early byte, and a 128-byte nonce" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var spec = try baseSpec(&fx);
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.NonceMismatch, ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, .{ .now_unix = now_2027, .expected_nonce = "abcd" }));
    }
    spec.nonce = "xbcd";
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.NonceMismatch, ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, .{ .now_unix = now_2027, .expected_nonce = "abcd" }));
        // a different length is refused too (and does not run the comparison off the end)
        try testing.expectError(error.NonceMismatch, ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, .{ .now_unix = now_2027, .expected_nonce = "xbc" }));
    }
    // DER's first long-form length: exactly 128 content bytes.
    const long = @as([128]u8, @splat(0x5a));
    spec.nonce = &long;
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const v = try ocsp.verify(try ocsp.parseResponse(resp), fx.issuer_der, fx.subject_der, .{ .now_unix = now_2027, .expected_nonce = &long });
        try testing.expect(v.status == .good);
    }
}

test "verify and verifyMany: an unparsable issuer or subject is Malformed; an unauthorized responder is judged per issuer" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var fx2 = try makeRsaFixtureWith(gpa, 0x5eed2222, "second test CA", &.{0x77});
    defer fx2.deinit(gpa);
    const spec = try baseSpec(&fx);
    const resp = try buildResponse(gpa, spec);
    defer gpa.free(resp);
    const parsed = try ocsp.parseResponse(resp);
    try testing.expectError(error.Malformed, ocsp.verify(parsed, "garbage", fx.subject_der, defaultOpts()));
    try testing.expectError(error.Malformed, ocsp.verify(parsed, fx.issuer_der, "garbage", defaultOpts()));

    var out: [3]ocsp.CertOutcome = undefined;
    const queries = [_]ocsp.CertPair{
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = fx.issuer_der },
        .{ .subject_cert_der = fx2.subject_der, .issuer_cert_der = fx2.issuer_der },
        .{ .subject_cert_der = fx.subject_der, .issuer_cert_der = "garbage" },
    };
    try ocsp.verifyMany(parsed, &queries, &out, defaultOpts());
    try testing.expect(out[0] == .verdict);
    switch (out[1]) {
        .failed => |e| try testing.expectEqual(error.UntrustedResponder, e),
        else => return error.TestUnexpectedResult,
    }
    switch (out[2]) {
        .failed => |e| try testing.expectEqual(error.Malformed, e),
        else => return error.TestUnexpectedResult,
    }
}

// ── E. structure: every container closes exactly, every identifier is the one DER gives it ──

const RespOffsets = struct {
    outer: u32,
    rb_ctx: u32,
    rb: u32,
    resp_type: u32,
    resp_octet: u32,
    bor: u32,
    tbs: u32,
    sig_alg: u32,
    sig_oid: u32,
    sigval: u32,
    certs_ctx: u32,
    certs_seq: u32,
    kh: u32,
    responses_seq: u32,
    exts_seq: u32,
    extn: u32,
    ext_oid: u32,
    ext_octet: u32,
    inner: u32,
};

/// The identifier offsets of a response built with a byKey responder, a nonce and `certs`.
fn respOffsets(r: []const u8) !RespOffsets {
    const outer = try elem(r, 0);
    const status = try elem(r, outer.slice.start);
    const rb_ctx_off = status.slice.end;
    const rb_ctx = try elem(r, rb_ctx_off);
    const rb_off = rb_ctx.slice.start;
    const rb = try elem(r, rb_off);
    const rt_off = rb.slice.start;
    const rt = try elem(r, rt_off);
    const ro_off = rt.slice.end;
    const ro = try elem(r, ro_off);
    const bor_off = ro.slice.start;
    const bor = try elem(r, bor_off);
    const tbs_off = bor.slice.start;
    const tbs = try elem(r, tbs_off);
    const sa_off = tbs.slice.end;
    const sa = try elem(r, sa_off);
    const sv_off = sa.slice.end;
    const sv = try elem(r, sv_off);
    const cc_off = sv.slice.end;
    const cc = try elem(r, cc_off);
    const rid = try elem(r, tbs.slice.start);
    const prod = try elem(r, rid.slice.end);
    const rs_off = prod.slice.end;
    const rs = try elem(r, rs_off);
    const ec_off = rs.slice.end;
    const ec = try elem(r, ec_off);
    const es = try elem(r, ec.slice.start);
    const en = try elem(r, es.slice.start);
    const eo = try elem(r, en.slice.start);
    const ev = try elem(r, eo.slice.end);
    return .{
        .outer = 0,
        .rb_ctx = rb_ctx_off,
        .rb = rb_off,
        .resp_type = rt_off,
        .resp_octet = ro_off,
        .bor = bor_off,
        .tbs = tbs_off,
        .sig_alg = sa_off,
        .sig_oid = sa.slice.start,
        .sigval = sv_off,
        .certs_ctx = cc_off,
        .certs_seq = cc.slice.start,
        .kh = rid.slice.start,
        .responses_seq = rs_off,
        .exts_seq = ec.slice.start,
        .extn = es.slice.start,
        .ext_oid = en.slice.start,
        .ext_octet = eo.slice.end,
        .inner = ev.slice.start,
    };
}

/// Insert one 0x00 byte at the END of the content of the last element named in `ancestors`
/// (outermost first, each inside the one before), and widen every named element's length.
fn growInside(gpa: std.mem.Allocator, bytes: []const u8, ancestors: []const u32) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(gpa);
    var from: u32 = 0;
    for (ancestors) |off| {
        const e = try elem(bytes, off);
        try out.appendSlice(gpa, bytes[from..off]);
        const n: usize = (e.slice.end - e.slice.start) + 1;
        try out.append(gpa, bytes[off]);
        if (n < 128) {
            try out.append(gpa, @intCast(n));
        } else if (n < 256) {
            try out.appendSlice(gpa, &.{ 0x81, @intCast(n) });
        } else {
            try out.appendSlice(gpa, &.{ 0x82, @intCast(n >> 8), @intCast(n & 0xff) });
        }
        from = e.slice.start;
    }
    const last = try elem(bytes, ancestors[ancestors.len - 1]);
    try out.appendSlice(gpa, bytes[from..last.slice.end]);
    try out.append(gpa, 0x00);
    try out.appendSlice(gpa, bytes[last.slice.end..]);
    return out.toOwnedSlice(gpa);
}

fn structSpec(fx: *const RsaFixture, key_hash: *const [20]u8) !RespSpec {
    var spec = try baseSpec(fx);
    spec.responder_by_name = null;
    spec.responder_by_key = key_hash;
    spec.nonce = "n0nce";
    spec.certs = fx.subject_der; // any certificate: `certs` is only walked for a delegate
    return spec;
}

test "parseResponse: junk inside any container, after the response, or after a NULL, is Malformed" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var kh: [20]u8 = undefined;
    Sha1.hash(issuer.key_bits, &kh, .{});
    const resp = try buildResponse(gpa, try structSpec(&fx, &kh));
    defer gpa.free(resp);
    _ = try ocsp.parseResponse(resp); // the unmodified response is fine
    const o = try respOffsets(resp);

    // trailing byte after the outer SEQUENCE
    {
        const longer = try gpa.alloc(u8, resp.len + 1);
        defer gpa.free(longer);
        @memcpy(longer[0..resp.len], resp);
        longer[resp.len] = 0;
        try testing.expectError(error.Malformed, ocsp.parseResponse(longer));
    }
    const chains = [_][]const u32{
        &.{o.outer}, // after [0] EXPLICIT, inside the outer SEQUENCE
        &.{ o.outer, o.rb_ctx },
        &.{ o.outer, o.rb_ctx, o.rb },
        &.{ o.outer, o.rb_ctx, o.rb, o.resp_octet },
        &.{ o.outer, o.rb_ctx, o.rb, o.resp_octet, o.bor },
        &.{ o.outer, o.rb_ctx, o.rb, o.resp_octet, o.bor, o.certs_ctx },
        &.{ o.outer, o.rb_ctx, o.rb, o.resp_octet, o.bor, o.sig_alg }, // after the NULL parameters
    };
    for (chains) |chain| {
        const grown = try growInside(gpa, resp, chain);
        defer gpa.free(grown);
        try testing.expectError(error.Malformed, ocsp.parseResponse(grown));
    }
}

test "parseResponse: a wrong identifier octet (class bits) on any structural element is Malformed" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var kh: [20]u8 = undefined;
    Sha1.hash(issuer.key_bits, &kh, .{});
    const resp = try buildResponse(gpa, try structSpec(&fx, &kh));
    defer gpa.free(resp);
    const o = try respOffsets(resp);
    const offs = [_]u32{ o.outer, o.rb, o.resp_type, o.resp_octet, o.bor, o.tbs, o.sig_alg, o.sig_oid, o.sigval, o.certs_seq, o.kh, o.responses_seq, o.exts_seq, o.extn, o.ext_oid, o.ext_octet, o.inner };
    const bad = try gpa.dupe(u8, resp);
    defer gpa.free(bad);
    for (offs) |off| {
        bad[off] ^= 0x40;
        try testing.expectError(error.Malformed, ocsp.parseResponse(bad));
        bad[off] ^= 0x40;
    }
    _ = try ocsp.parseResponse(bad);
}

test "verify: a wrong identifier octet inside a SIGNED SingleResponse is Malformed, not a silent skip" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const paths = [_][]const u8{
        &.{ 2, 0 }, // SingleResponse
        &.{ 2, 0, 0 }, // CertID
        &.{ 2, 0, 0, 0 }, // hashAlgorithm
        &.{ 2, 0, 0, 0, 0 }, // its OID
        &.{ 2, 0, 0, 1 }, // issuerNameHash
        &.{ 2, 0, 0, 2 }, // issuerKeyHash
        &.{ 2, 0, 0, 3 }, // serialNumber
        &.{ 2, 0, 1 }, // certStatus
    };
    for (paths) |path| {
        var spec = try baseSpec(&fx);
        spec.tbs_flip_path = path;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.Malformed, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
}

test "verify: the certificates handed in are held to DER too (identifier octets, junk in the key algorithm, empty BIT STRINGs)" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const resp = try buildResponse(gpa, try baseSpec(&fx));
    defer gpa.free(resp);
    const parsed = try ocsp.parseResponse(resp);
    const cert = fx.issuer_der;

    // Offsets: certificate, tbsCertificate, its children, the key algorithm, the key, the outer algorithm and signature.
    const tbs_off = try tagOffsetAt(cert, 0, &.{0});
    const first = try elem(cert, try tagOffsetAt(cert, 0, &.{ 0, 0 }));
    const base: u8 = if (@as(u8, @bitCast(first.identifier)) == 0xa0) 1 else 0;
    const serial = try tagOffsetAt(cert, 0, &.{ 0, base });
    const issuer_n = try tagOffsetAt(cert, 0, &.{ 0, base + 2 });
    const validity = try tagOffsetAt(cert, 0, &.{ 0, base + 3 });
    const subject_n = try tagOffsetAt(cert, 0, &.{ 0, base + 4 });
    const spki = try tagOffsetAt(cert, 0, &.{ 0, base + 5 });
    const alg_seq = try tagOffsetAt(cert, 0, &.{ 0, base + 5, 0 });
    const alg_oid = try tagOffsetAt(cert, 0, &.{ 0, base + 5, 0, 0 });
    const spk = try tagOffsetAt(cert, 0, &.{ 0, base + 5, 1 });
    const outer_alg = try tagOffsetAt(cert, 0, &.{1});
    const outer_oid = try tagOffsetAt(cert, 0, &.{ 1, 0 });
    const offs = [_]u32{ 0, tbs_off, serial, issuer_n, validity, subject_n, spki, alg_seq, alg_oid, spk, outer_alg, outer_oid };
    const bad = try gpa.dupe(u8, cert);
    defer gpa.free(bad);
    for (offs) |off| {
        bad[off] ^= 0x40;
        try testing.expectError(error.Malformed, ocsp.verify(parsed, bad, fx.subject_der, defaultOpts()));
        bad[off] ^= 0x40;
    }
    // junk after the key algorithm's parameters
    {
        const grown = try growInside(gpa, cert, &.{ 0, tbs_off, spki, alg_seq });
        defer gpa.free(grown);
        try testing.expectError(error.Malformed, ocsp.verify(parsed, grown, fx.subject_der, defaultOpts()));
    }
    // empty BIT STRINGs: the key (nothing to read), the certificate's own signature (nobody checks it)
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const issuer = try extractBits(cert);
    const rsa_spki = try spkiOf(cert);
    const empty_spk_cert = try buildCertWith(gpa, issuer.subject_name, try spkiWith(b, &oid_rsa_encryption, try b.null(), "\x03\x00"), null);
    defer gpa.free(empty_spk_cert);
    try testing.expectError(error.Malformed, ocsp.verify(parsed, empty_spk_cert, fx.subject_der, defaultOpts()));
    const no_sig_bytes = try buildCertWith(gpa, issuer.subject_name, rsa_spki, "\x03\x00");
    defer gpa.free(no_sig_bytes);
    try testing.expectError(error.Malformed, ocsp.verify(parsed, no_sig_bytes, fx.subject_der, defaultOpts()));
    // An empty signature value (just the unused-bits octet) is accepted: the issuer's own signature is not examined.
    const empty_sig = try buildCertWith(gpa, issuer.subject_name, rsa_spki, "\x03\x01\x00");
    defer gpa.free(empty_sig);
    try testing.expect((try ocsp.verify(parsed, empty_sig, fx.subject_der, defaultOpts())).status == .good);
    // An empty key (just the unused-bits octet) parses; there is then nothing to verify with.
    const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x71)));
    const ec_issuer = try buildCertWith(gpa, issuer.subject_name, try spkiWith(b, &oid_ec_public_key, try b.oid(&oid_p256_curve), "\x03\x01\x00"), null);
    defer gpa.free(ec_issuer);
    var spec = try baseSpec(&fx);
    spec.sign_rsa = null;
    spec.sign_ecdsa = kp.secret_key.bytes;
    const ec_resp = try buildResponse(gpa, spec);
    defer gpa.free(ec_resp);
    try testing.expectError(error.SignatureInvalid, verifyBytes(ec_resp, ec_issuer, fx.subject_der));
}

test "parseResponse: the response's own signature BIT STRING and algorithm parameters" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    // `03 00` (no unused-bits octet): Malformed.  `03 01 00` (empty signature): parses, then SignatureInvalid.
    var raw: RawSig = .{ .alg_oid = &oid_sha256_rsa, .sigval = "\x03\x00" };
    var spec = try baseSpec(&fx);
    spec.signer = raw.signer();
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.Malformed, ocsp.parseResponse(resp));
    }
    raw.sigval = "\x03\x01\x00";
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.SignatureInvalid, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
    // A NULL that is not empty.
    raw.sigval = try b.bitString("x");
    raw.params = .null_with_content;
    {
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.Malformed, ocsp.parseResponse(resp));
    }
}

test "parseResponse and verify: version, unknown trailing elements, extensions without a nonce, critical extensions" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    // An explicit [0] version, a trailing element that is not [1], and no nonce.
    {
        var spec = try baseSpec(&fx);
        spec.tbs_version = true;
        spec.tbs_trailer = "\xa5\x00";
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        const parsed = try ocsp.parseResponse(resp);
        try testing.expect(parsed.basic.?.nonce == null);
        try testing.expect((try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, defaultOpts())).status == .good);
    }
    // A critical foreign extension: with no nonce (found nothing), and before the nonce.
    {
        var spec = try baseSpec(&fx);
        spec.other_ext = true;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expect((try ocsp.parseResponse(resp)).basic.?.nonce == null);
        spec.nonce = "the-nonce";
        const resp2 = try buildResponse(gpa, spec);
        defer gpa.free(resp2);
        const parsed = try ocsp.parseResponse(resp2);
        try testing.expectEqualStrings("the-nonce", parsed.basic.?.nonce.?);
        try testing.expect((try ocsp.verify(parsed, fx.issuer_der, fx.subject_der, .{ .now_unix = now_2027, .expected_nonce = "the-nonce" })).status == .good);
    }
}

// ── F. the tail of a SingleResponse ──

test "verify: malformed or foreign elements inside a SingleResponse" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const t = "\x18\x0f20270101000000Z"; // a GeneralizedTime TLV
    const Case = struct { spec_edit: *const fn (*RespSpec) void, want: ?anyerror, reason: ?u8 = null };
    const edits = struct {
        fn badThis(s: *RespSpec) void {
            s.single_this_update = "2027";
        }
        fn trailerJunk(s: *RespSpec) void {
            s.next_update = null;
            s.this_update = t_stamp;
            s.single_trailer = "\x04\xff";
        }
        fn trailerForeign(s: *RespSpec) void {
            s.next_update = null;
            s.this_update = t_stamp;
            s.single_trailer = "\x30\x00";
        }
        fn trailerNextEmpty(s: *RespSpec) void {
            s.next_update = null;
            s.this_update = t_stamp;
            s.single_trailer = "\xa0\x02\x04\xff";
        }
        fn trailerNextBadTime(s: *RespSpec) void {
            s.next_update = null;
            s.this_update = t_stamp;
            s.single_trailer = "\xa0\x03\x18\x01\x31";
        }
        fn revokedJunk(s: *RespSpec) void {
            s.status_raw = "\xa1\x02\x04\xff";
        }
        fn revokedBadTime(s: *RespSpec) void {
            s.status_raw = "\xa1\x03\x18\x01\x31";
        }
        fn revokedAfterTimeJunk(s: *RespSpec) void {
            s.status_raw = "\xa1\x13" ++ "\x18\x0f20270101000000Z" ++ "\x04\xff";
        }
        fn revokedForeign(s: *RespSpec) void {
            s.status_raw = "\xa1\x15" ++ "\x18\x0f20270101000000Z" ++ "\x30\x02\x04\xff";
        }
        fn revokedReasonJunk(s: *RespSpec) void {
            s.status_raw = "\xa1\x15" ++ "\x18\x0f20270101000000Z" ++ "\xa0\x02\x04\xff";
        }
        fn revokedReasonTwoBytes(s: *RespSpec) void {
            s.status_raw = "\xa1\x17" ++ "\x18\x0f20270101000000Z" ++ "\xa0\x04\x0a\x02\x01\x02";
        }
        fn badStatusTag(s: *RespSpec) void {
            s.status_raw = "\x83\x00";
        }
        fn responsesJunk(s: *RespSpec) void {
            s.responses_raw = "\x04\xff";
        }
        fn singleJunk(s: *RespSpec) void {
            s.responses_raw = "\x30\x02\x04\xff";
        }
    };
    _ = t;
    const cases = [_]Case{
        .{ .spec_edit = edits.badThis, .want = error.Malformed },
        .{ .spec_edit = edits.trailerJunk, .want = error.Malformed },
        .{ .spec_edit = edits.trailerForeign, .want = null },
        .{ .spec_edit = edits.trailerNextEmpty, .want = error.Malformed },
        .{ .spec_edit = edits.trailerNextBadTime, .want = error.Malformed },
        .{ .spec_edit = edits.revokedJunk, .want = error.Malformed },
        .{ .spec_edit = edits.revokedBadTime, .want = error.Malformed },
        .{ .spec_edit = edits.revokedAfterTimeJunk, .want = error.Malformed },
        .{ .spec_edit = edits.revokedForeign, .want = null },
        .{ .spec_edit = edits.revokedReasonJunk, .want = error.Malformed },
        .{ .spec_edit = edits.revokedReasonTwoBytes, .want = null },
        .{ .spec_edit = edits.badStatusTag, .want = error.Malformed },
        .{ .spec_edit = edits.responsesJunk, .want = error.Malformed },
        .{ .spec_edit = edits.singleJunk, .want = error.Malformed },
    };
    for (cases) |c| {
        var spec = try baseSpec(&fx);
        c.spec_edit(&spec);
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        if (c.want) |e| {
            try testing.expectError(e, verifyBytes(resp, fx.issuer_der, fx.subject_der));
        } else {
            const v = try verifyBytes(resp, fx.issuer_der, fx.subject_der);
            // a foreign trailing element is ignored; a two-byte reason is not a reason
            switch (v.status) {
                .good => {},
                .revoked => |r| try testing.expectEqual(@as(?u8, null), r.reason),
                .unknown => return error.TestUnexpectedResult,
            }
        }
    }
}

// ── G. buildRequest: the exact bytes ──

fn expectedRequest(b: der_writer.Builder, algo: ocsp.RequestHashAlgo, issuer: IssuerBits, subject: IssuerBits, nonce: ?[]const u8) ![]const u8 {
    var nh: [32]u8 = undefined;
    var kh: [32]u8 = undefined;
    var n: usize = 20;
    var oid: []const u8 = &oid_sha1;
    switch (algo) {
        .sha1 => {
            Sha1.hash(issuer.subject_name, nh[0..20], .{});
            Sha1.hash(issuer.key_bits, kh[0..20], .{});
        },
        .sha256 => {
            n = 32;
            oid = &oid_sha256;
            Sha256.hash(issuer.subject_name, nh[0..32], .{});
            Sha256.hash(issuer.key_bits, kh[0..32], .{});
        },
    }
    const alg = try b.seq(&.{ try b.oid(oid), try b.null() });
    const cert_id = try b.seq(&.{ alg, try b.octetString(nh[0..n]), try b.octetString(kh[0..n]), try b.integerRaw(subject.serial) });
    const list = try b.seq(&.{try b.seq(&.{cert_id})});
    const tbs = if (nonce) |nc| blk: {
        const ext_ = try b.seq(&.{ try b.oid(&oid_ocsp_nonce), try b.octetString(try b.octetString(nc)) });
        break :blk try b.seq(&.{ list, try b.explicit(2, try b.seq(&.{ext_})) });
    } else try b.seq(&.{list});
    return b.seq(&.{tbs});
}

test "buildRequest: the exact DER for SHA-1 and SHA-256, with and without a nonce" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    const subject = try extractBits(fx.subject_der);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    for ([_]ocsp.RequestHashAlgo{ .sha1, .sha256 }) |algo| {
        for ([_]?[]const u8{ null, "request-nonce" }) |nonce| {
            const want = try expectedRequest(b, algo, issuer, subject, nonce);
            const got = try ocsp.buildRequest(gpa, fx.subject_der, fx.issuer_der, .{ .hash = algo, .nonce = nonce });
            defer gpa.free(got);
            try testing.expectEqualSlices(u8, want, got);
        }
    }
    // the default is SHA-1
    const dflt = try ocsp.buildRequest(gpa, fx.subject_der, fx.issuer_der, .{});
    defer gpa.free(dflt);
    try testing.expectEqualSlices(u8, try expectedRequest(b, .sha1, issuer, subject, null), dflt);
}

test "verify: a delegate certificate whose extension block cannot be walked is Malformed, at every level of the walk" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const issuer = try extractBits(fx.issuer_der);
    var d = try mkDlg(gpa, 0xde1e6a7e, "broken extensions responder");
    defer d.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };
    const bad_value = try b.tlv(0x30, "\x04\xff"); // a SEQUENCE whose first element has an impossible length
    const eku_with = struct {
        fn f(bb: der_writer.Builder, value: []const u8) ![]const u8 {
            return bb.explicit(3, try bb.seq(&.{try bb.seq(&.{ try bb.oid(&oid_ext_key_usage), try bb.octetString(value) })}));
        }
    }.f;
    const variants = [_][]const u8{
        "\xa3\x02\x04\xff", // [3] holding an element that does not parse
        "\xa3\x04\x30\x02\x04\xff", // [3] { SEQUENCE { junk } }: the first extension does not parse
        try eku_with(b, "\x04\xff"), // extnValue is not an element
        try eku_with(b, bad_value), // extendedKeyUsage whose purposes do not parse
    };
    for (variants) |ext_tlv| {
        const version = try b.explicit(0, try b.integerU64(2));
        const sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
        const validity = try b.seq(&.{ try b.tlv(0x17, "200101000000Z"), try b.tlv(0x17, "400101000000Z") });
        const tbs = try b.seq(&.{ version, try b.integerU64(9), sig_alg, issuer.subject_name, validity, d.bits.subject_name, d.spki, ext_tlv });
        var out: [512]u8 = undefined;
        const sig = try rsa.signPkcs1v15(&fx.kp.secret_key, Sha256, tbs, &out);
        const cert = try b.seq(&.{ tbs, sig_alg, try b.bitString(sig) });
        var spec = try baseSpec(&fx);
        spec.sign_rsa = d.kp.secret_key;
        spec.responder_by_name = d.bits.subject_name;
        spec.certs = cert;
        const resp = try buildResponse(gpa, spec);
        defer gpa.free(resp);
        try testing.expectError(error.Malformed, verifyBytes(resp, fx.issuer_der, fx.subject_der));
    }
}
