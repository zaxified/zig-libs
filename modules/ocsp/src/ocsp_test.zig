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
const der_writer = @import("der_writer.zig");

const der = std.crypto.Certificate.der;
const ext = @import("x509").extensions;

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

// A fixed instant inside 2027 and the matching time strings.
const now_2027 = 1_800_000_000; // ~2027-01-15
const this_update = "20270101000000Z";
const next_update = "20271231000000Z";

// OIDs used to hand-build fixtures.
const oid_sha256_rsa = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256_curve = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
const oid_ocsp_basic = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
const oid_ocsp_nonce = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02 };
const oid_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 }; // 2.5.29.37
const oid_ocsp_signing = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

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

fn makeRsaFixture(gpa: std.mem.Allocator) !RsaFixture {
    var prng = std.Random.DefaultPrng.init(0x0c005eed);
    const kp = try rsa.generate(prng.random(), 1024, 65537);
    const issuer = try rsa.selfSignedCert(gpa, kp.secret_key, kp.public_key, Sha256, .{
        .common_name = "zig-libs OCSP test CA",
        .serial = 1,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = true,
    });
    errdefer gpa.free(issuer);
    const subject = try rsa.selfSignedCert(gpa, kp.secret_key, kp.public_key, Sha256, .{
        .common_name = "leaf.example.com",
        .serial = 0x4242,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    return .{ .issuer_der = issuer, .subject_der = subject, .kp = kp };
}

// ── OCSP response builder (constructed fixtures) ────────────────────────────

const StatusKind = union(enum) {
    good,
    revoked: struct { time: []const u8, reason: ?u8 },
    unknown,
};

const RespSpec = struct {
    issuer: IssuerBits,
    subject_serial: []const u8,
    responder_by_name: []const u8, // Name TLV
    status: StatusKind = .good,
    this_update: []const u8 = this_update,
    next_update: ?[]const u8 = next_update,
    certs: ?[]const u8 = null, // a single cert TLV to embed in certs [0]
    nonce: ?[]const u8 = null,
    /// signer: rsa secret key (SHA-256) — the direct/delegated RSA path.
    sign_rsa: ?rsa.SecretKey = null,
    /// signer: p256 secret key (ECDSA SHA-256).
    sign_ecdsa: ?[32]u8 = null,
};

fn certIdDer(b: der_writer.Builder, spec: RespSpec) ![]const u8 {
    var nb: [64]u8 = undefined;
    var kb: [64]u8 = undefined;
    Sha256.hash(spec.issuer.subject_name, nb[0..32], .{});
    Sha256.hash(spec.issuer.key_bits, kb[0..32], .{});
    const alg = try b.seq(&.{ try b.oid(&oid_sha256), try b.null() });
    return b.seq(&.{
        alg,
        try b.octet(nb[0..32]),
        try b.octet(kb[0..32]),
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
        try b.octet(try b.octet(nonce)),
    });
    return b.explicit(1, try b.seqOf(&.{nonce_ext})); // responseExtensions [1]
}

fn buildResponse(gpa: std.mem.Allocator, spec: RespSpec) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    // SingleResponse
    const single_parts_head = [_][]const u8{
        try certIdDer(b, spec),
        try statusDer(b, spec.status),
        try b.generalizedTime(spec.this_update),
    };
    var single_parts = std.ArrayList([]const u8).empty;
    try single_parts.appendSlice(b.a, &single_parts_head);
    if (spec.next_update) |nu| {
        try single_parts.append(b.a, try b.explicit(0, try b.generalizedTime(nu)));
    }
    const single = try b.seq(single_parts.items);
    const responses = try b.seqOf(&.{single});

    // ResponseData (tbs): responderID byName [1], producedAt, responses [, exts]
    const responder_id = try b.explicit(1, spec.responder_by_name);
    var rd_parts = std.ArrayList([]const u8).empty;
    try rd_parts.append(b.a, responder_id);
    try rd_parts.append(b.a, try b.generalizedTime(spec.this_update));
    try rd_parts.append(b.a, responses);
    if (spec.nonce) |n| try rd_parts.append(b.a, try nonceExtsDer(b, n));
    const tbs = try b.seq(rd_parts.items);

    // signatureAlgorithm + signature
    var sig_alg: []const u8 = undefined;
    var signature: []const u8 = undefined;
    if (spec.sign_rsa) |sk| {
        var out: [512]u8 = undefined;
        signature = try rsa.signPkcs1v15(sk, Sha256, tbs, &out);
        signature = try b.a.dupe(u8, signature);
        sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
    } else if (spec.sign_ecdsa) |sk| {
        const rs = try p256.sign.ecdsaSign(sk, tbs, [_]u8{0x2b} ** 32);
        signature = try ecdsaRsToDer(b, rs);
        sig_alg = try b.seq(&.{try b.oid(&oid_ecdsa_sha256)});
    } else return error.NoSigner;

    // BasicOCSPResponse
    var bor_parts = std.ArrayList([]const u8).empty;
    try bor_parts.append(b.a, tbs);
    try bor_parts.append(b.a, sig_alg);
    try bor_parts.append(b.a, try b.bitString(signature));
    if (spec.certs) |cert_tlv| {
        try bor_parts.append(b.a, try b.explicit(0, try b.seqOf(&.{cert_tlv})));
    }
    const bor = try b.seq(bor_parts.items);

    const response_bytes = try b.seq(&.{ try b.oid(&oid_ocsp_basic), try b.octet(bor) });
    const ocsp_response = try b.seq(&.{
        try b.enumerated(0), // successful
        try b.explicit(0, response_bytes),
    });
    return gpa.dupe(u8, ocsp_response);
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

fn buildDelegateCert(
    gpa: std.mem.Allocator,
    issuer_sk: rsa.SecretKey,
    issuer_name: []const u8,
    delegate_spki: []const u8,
    delegate_name: []const u8,
    with_eku: bool,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const b: der_writer.Builder = .{ .a = arena.allocator() };

    const version = try b.explicit(0, try b.integerU8(2)); // v3
    const serial = try b.integerU8(9);
    const sig_alg = try b.seq(&.{ try b.oid(&oid_sha256_rsa), try b.null() });
    const validity = try b.seq(&.{
        try b.tlv(0x17, "200101000000Z"), // UTCTime notBefore
        try b.tlv(0x17, "400101000000Z"), // UTCTime notAfter
    });

    var tbs_parts = std.ArrayList([]const u8).empty;
    try tbs_parts.appendSlice(b.a, &[_][]const u8{
        version, serial, sig_alg, issuer_name, validity, delegate_name, delegate_spki,
    });
    if (with_eku) {
        const eku = try b.seq(&.{
            try b.oid(&oid_ext_key_usage),
            try b.octet(try b.seqOf(&.{try b.oid(&oid_ocsp_signing)})),
        });
        try tbs_parts.append(b.a, try b.explicit(3, try b.seqOf(&.{eku})));
    }
    const tbs = try b.seq(tbs_parts.items);

    var out: [512]u8 = undefined;
    const sig = try rsa.signPkcs1v15(issuer_sk, Sha256, tbs, &out);
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
    const version = try b.explicit(0, try b.integerU8(2));
    const serial = try b.integerU8(3);
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
    return b.seq(&.{try b.setOf(&.{atv})});
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
    const dkp = try rsa.generate(prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, dkp.secret_key, dkp.public_key, Sha256, .{
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

    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, dspki, dbits.subject_name, true);
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
    const dkp = try rsa.generate(prng.random(), 1024, 65537);
    const delegate_self = try rsa.selfSignedCert(gpa, dkp.secret_key, dkp.public_key, Sha256, .{
        .common_name = "no-eku responder",
        .serial = 8,
        .not_before = "200101000000Z",
        .not_after = "400101000000Z",
        .is_ca = false,
    });
    defer gpa.free(delegate_self);
    const dbits = try extractBits(delegate_self);
    const dspki = try spkiOf(delegate_self);

    const delegate_cert = try buildDelegateCert(gpa, fx.kp.secret_key, issuer.subject_name, dspki, dbits.subject_name, false);
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

test "verify: ECDSA-P256 direct-issuer signature accepted" {
    const gpa = testing.allocator;
    var fx = try makeRsaFixture(gpa);
    defer fx.deinit(gpa);
    const subject = try extractBits(fx.subject_der);

    const kp = try p256.EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{0x77} ** 32);
    const sec1 = kp.public_key.toUncompressedSec1();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const nb: der_writer.Builder = .{ .a = arena.allocator() };
    const ec_name = try buildName(nb, "ECDSA OCSP CA");
    const ec_issuer = try buildEcIssuerCert(gpa, &sec1, ec_name);
    defer gpa.free(ec_issuer);
    const ec_bits = try extractBits(ec_issuer);

    const resp_der = try buildResponse(gpa, .{
        .issuer = ec_bits,
        .subject_serial = subject.serial,
        .responder_by_name = ec_bits.subject_name,
        .sign_ecdsa = kp.secret_key.bytes,
    });
    defer gpa.free(resp_der);

    const parsed = try ocsp.parseResponse(resp_der);
    const verdict = try ocsp.verify(parsed, ec_issuer, fx.subject_der, defaultOpts());
    try testing.expect(verdict.status == .good);
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

test "fuzz: parseResponse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseResponse, .{});
}

fn fuzzParseResponse(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = ocsp.parseResponse(buf[0..len]) catch return;
}

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
