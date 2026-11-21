// SPDX-License-Identifier: MIT
//! Responder side (`parseRequest`, `createResponse`, `errorResponse`) against OpenSSL 3.5.5.
//!
//! Fixtures (throwaway keys; `testdata/responder/`), made once:
//!
//! ```sh
//! openssl ecparam -name prime256v1 -genkey -noout -out ca256.key
//! openssl req -x509 -new -key ca256.key -sha256 -days 3650 -subj "/CN=Test P-256 CA" -out ca256.pem \
//!     -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
//! # leaf256: a P-256 leaf, serial 0x3001, signed by the CA; ca384 / leaf384 likewise (secp384r1 CA,
//! # CN "Test P-384 Created CA", leaf serial 0x3002, -sha384). *.key.bin: the CA's raw private scalar.
//! openssl ocsp -sha1   -issuer ca256.pem -cert leaf256.pem -reqout req256.der -nonce
//! openssl ocsp -sha256 -issuer ca384.pem -cert leaf384.pem -reqout req384.der -no_nonce
//! ```
//!
//! The two `created*.der` responses are this module's output for those requests (`createResponse`,
//! deterministic signatures, fixed times). OpenSSL accepted both: `openssl ocsp -respin created256.der
//! -reqin req256.der -CAfile ca256.pem -VAfile ca256.pem` printed "Response verify OK" with no
//! nonce complaint (the responder certificate is not embedded, hence `-VAfile`); `-respin
//! created256.der -issuer ca256.pem -cert leaf256.pem -CAfile ca256.pem -no_nonce` printed
//! `leaf256.pem: good`; `-respin created384.der -sha256 -issuer ca384.pem -cert leaf384.pem -CAfile
//! ca384.pem -reqin req384.der` printed "Response verify OK", `leaf384.pem: revoked`, Reason
//! keyCompromise, and its `-text` dump the responder id as the key hash, ecdsa-with-SHA384.

const std = @import("std");
const testing = std.testing;
const ocsp = @import("root.zig");

const ca256 = @embedFile("testdata/responder/ca256.der");
const leaf256 = @embedFile("testdata/responder/leaf256.der");
const req256 = @embedFile("testdata/responder/req256.der");
const ca256_key = @embedFile("testdata/responder/ca256.key.bin");
const ca384 = @embedFile("testdata/responder/ca384.der");
const leaf384 = @embedFile("testdata/responder/leaf384.der");
const req384 = @embedFile("testdata/responder/req384.der");
const ca384_key = @embedFile("testdata/responder/ca384.key.bin");

/// 2026-11-22 00:00:00 UTC, inside every fixture certificate's validity (from 2026-11-21 22:52 UTC).
const produced: i64 = 1795305600;
const this_update: i64 = produced - 3600;
const next_update: i64 = produced + 7 * 86400;
const revoked_at: i64 = produced - 86400 / 2;

fn p384Key() !std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair {
    const E = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    return E.KeyPair.fromSecretKey(try E.SecretKey.fromBytes(ca384_key[0..48].*));
}

fn only(req: ocsp.Request) !ocsp.CertId {
    var it = req.iterator();
    const first = (try it.next()).?;
    try testing.expectEqual(@as(?ocsp.CertId, null), try it.next());
    return first;
}

test "parseRequest: OpenSSL's request with a nonce (SHA-1 CertID)" {
    const req = try ocsp.parseRequest(req256);
    const id = try only(req);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x01 }, id.serial);
    try testing.expect(id.namesIssuer(ca256));
    try testing.expect(!id.namesIssuer(ca384));
    try testing.expect(!id.namesIssuer(leaf256));
    try testing.expect(!id.namesIssuer("not a certificate"));
    try testing.expectEqual(@as(usize, 20), id.issuer_key_hash.len);
    const nonce = req.nonce.?;
    try testing.expectEqual(@as(usize, 16), nonce.len);
}

test "parseRequest: OpenSSL's request without a nonce (SHA-256 CertID)" {
    const req = try ocsp.parseRequest(req384);
    const id = try only(req);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x02 }, id.serial);
    try testing.expectEqual(@as(usize, 32), id.issuer_name_hash.len);
    try testing.expect(id.namesIssuer(ca384));
    try testing.expect(!id.namesIssuer(ca256));
    try testing.expectEqual(@as(?[]const u8, null), req.nonce);
}

test "parseRequest: this module's own request, several CertIDs, round trip" {
    const gpa = testing.allocator;
    const pairs = [_]ocsp.CertPair{
        .{ .subject_cert_der = leaf256, .issuer_cert_der = ca256 },
        .{ .subject_cert_der = leaf384, .issuer_cert_der = ca384 },
    };
    const bytes = try ocsp.buildRequests(gpa, &pairs, .{ .hash = .sha256, .nonce = "abc" });
    defer gpa.free(bytes);
    const req = try ocsp.parseRequest(bytes);
    try testing.expectEqualStrings("abc", req.nonce.?);
    var it = req.iterator();
    const a = (try it.next()).?;
    const b = (try it.next()).?;
    try testing.expectEqual(@as(?ocsp.CertId, null), try it.next());
    try testing.expect(a.namesIssuer(ca256) and b.namesIssuer(ca384));
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x01 }, a.serial);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x02 }, b.serial);
}

test "parseRequest: truncation, trailing bytes and an empty list are Malformed, no flip panics" {
    const gpa = testing.allocator;
    for (0..req256.len) |n| try testing.expectError(error.Malformed, ocsp.parseRequest(req256[0..n]));
    const extra = try gpa.alloc(u8, req256.len + 1);
    defer gpa.free(extra);
    @memcpy(extra[0..req256.len], req256);
    extra[req256.len] = 0;
    try testing.expectError(error.Malformed, ocsp.parseRequest(extra));
    // SEQUENCE { SEQUENCE { SEQUENCE {} } }: a request list without a Request.
    try testing.expectError(error.Malformed, ocsp.parseRequest(&.{ 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 }));
    const flipped = try gpa.dupe(u8, req256);
    defer gpa.free(flipped);
    for (0..req256.len) |i| for (0..8) |bit| {
        flipped[i] ^= @as(u8, 1) << @intCast(bit);
        if (ocsp.parseRequest(flipped)) |r| {
            var it = r.iterator();
            while (it.next() catch null) |_| {}
        } else |_| {}
        flipped[i] = req256[i];
    };
}

test "errorResponse: the five bytes of RFC 6960 §2.3, parsed back" {
    inline for (.{ .malformed_request, .internal_error, .try_later, .sig_required, .unauthorized }) |st| {
        const r = try ocsp.errorResponse(st);
        const parsed = try ocsp.parseResponse(&r);
        try testing.expectEqual(@as(ocsp.ResponseStatus, st), parsed.status);
        try testing.expect(parsed.basic == null);
    }
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x03, 0x0a, 0x01, 0x01 }, &(try ocsp.errorResponse(.malformed_request)));
    try testing.expectError(error.NotAnError, ocsp.errorResponse(.successful));
}

fn entryFor(id: ocsp.CertId, issuer: []const u8, status: ocsp.CertStatus, hash: ocsp.RequestHashAlgo) ocsp.ResponseEntry {
    return .{
        .issuer_cert_der = issuer,
        .serial = id.serial,
        .status = status,
        .this_update_unix = this_update,
        .next_update_unix = next_update,
        .hash = hash,
    };
}

fn createP256(gpa: std.mem.Allocator) ![]u8 {
    const id = try only(try ocsp.parseRequest(req256));
    return ocsp.createResponse(gpa, &.{entryFor(id, ca256, .good, .sha1)}, .{ .ecdsa_p256 = ca256_key[0..32] }, .{
        .responder_cert_der = ca256,
        .produced_at_unix = produced,
        .nonce = (try ocsp.parseRequest(req256)).nonce,
    });
}

fn createP384(gpa: std.mem.Allocator) ![]u8 {
    const id = try only(try ocsp.parseRequest(req384));
    var kp = try p384Key();
    return ocsp.createResponse(
        gpa,
        &.{entryFor(id, ca384, .{ .revoked = .{ .revocation_time_unix = revoked_at, .reason = 1 } }, .sha256)},
        .{ .ecdsa_p384 = &kp },
        .{ .responder_cert_der = ca384, .responder_id = .by_key, .produced_at_unix = produced },
    );
}

const created256 = @embedFile("testdata/responder/created256.der");
const created384 = @embedFile("testdata/responder/created384.der");

test "createResponse: P-256, nonce echoed, the bytes OpenSSL verified" {
    const gpa = testing.allocator;
    const resp = try createP256(gpa);
    defer gpa.free(resp);
    try testing.expectEqualSlices(u8, created256, resp);
    const nonce = (try ocsp.parseRequest(req256)).nonce.?;
    const v = try ocsp.verify(try ocsp.parseResponse(resp), ca256, leaf256, .{ .now_unix = produced, .expected_nonce = nonce });
    try testing.expect(v.status == .good and !v.delegated and v.responder == .by_name);
    try testing.expectEqual(this_update, v.this_update_unix);
    try testing.expectEqual(@as(?i64, next_update), v.next_update_unix);
    try testing.expectEqual(produced, v.produced_at_unix);
    // The wrong nonce is refused, as for any response.
    try testing.expectError(error.NonceMismatch, ocsp.verify(try ocsp.parseResponse(resp), ca256, leaf256, .{ .now_unix = produced, .expected_nonce = "other" }));
}

test "createResponse: P-384 by key hash, revoked with a reason, the bytes OpenSSL verified" {
    const gpa = testing.allocator;
    const resp = try createP384(gpa);
    defer gpa.free(resp);
    try testing.expectEqualSlices(u8, created384, resp);
    const v = try ocsp.verify(try ocsp.parseResponse(resp), ca384, leaf384, .{ .now_unix = produced });
    try testing.expect(v.responder == .by_key);
    switch (v.status) {
        .revoked => |r| {
            try testing.expectEqual(revoked_at, r.revocation_time_unix);
            try testing.expectEqual(@as(?u8, 1), r.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    // Another issuer's certificate is refused.
    try testing.expectError(error.IssuerMismatch, ocsp.verify(try ocsp.parseResponse(resp), ca384, leaf256, .{ .now_unix = produced }));
}

test "createResponse: every status, optional nextUpdate, a revocation without a reason, several entries" {
    const gpa = testing.allocator;
    const id = try only(try ocsp.parseRequest(req256));
    const base = entryFor(id, ca256, .good, .sha1);
    var no_next = base;
    no_next.next_update_unix = null;
    var unknown = base;
    unknown.status = .unknown;
    var revoked = base;
    revoked.status = .{ .revoked = .{ .revocation_time_unix = revoked_at, .reason = null } };
    revoked.hash = .sha256;
    const opts: ocsp.ResponseOptions = .{ .responder_cert_der = ca256, .produced_at_unix = produced };
    const key: ocsp.SigningKey = .{ .ecdsa_p256 = ca256_key[0..32] };

    const r1 = try ocsp.createResponse(gpa, &.{no_next}, key, opts);
    defer gpa.free(r1);
    const v1 = try ocsp.verify(try ocsp.parseResponse(r1), ca256, leaf256, .{ .now_unix = produced });
    try testing.expectEqual(@as(?i64, null), v1.next_update_unix);

    const r2 = try ocsp.createResponse(gpa, &.{unknown}, key, opts);
    defer gpa.free(r2);
    const v2 = try ocsp.verify(try ocsp.parseResponse(r2), ca256, leaf256, .{ .now_unix = produced });
    try testing.expect(v2.status == .unknown);

    const r3 = try ocsp.createResponse(gpa, &.{revoked}, key, opts);
    defer gpa.free(r3);
    const v3 = try ocsp.verify(try ocsp.parseResponse(r3), ca256, leaf256, .{ .now_unix = produced });
    try testing.expectEqual(@as(?u8, null), v3.status.revoked.reason);
    try testing.expectEqual(revoked_at, v3.status.revoked.revocation_time_unix);

    // Two entries for one certificate (SHA-1 unknown first, SHA-256 revoked second): the first match answers.
    const r4 = try ocsp.createResponse(gpa, &.{ unknown, revoked }, key, opts);
    defer gpa.free(r4);
    const parsed = try ocsp.parseResponse(r4);
    try testing.expect((try ocsp.verify(parsed, ca256, leaf256, .{ .now_unix = produced })).status == .unknown);
}

test "createResponse: refuses nothing to answer, a bad certificate, a time beyond GeneralizedTime" {
    const gpa = testing.allocator;
    const id = try only(try ocsp.parseRequest(req256));
    const key: ocsp.SigningKey = .{ .ecdsa_p256 = ca256_key[0..32] };
    const opts: ocsp.ResponseOptions = .{ .responder_cert_der = ca256, .produced_at_unix = produced };
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{}, key, opts));
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{entryFor(id, "junk", .good, .sha1)}, key, opts));
    var bad_serial = entryFor(id, ca256, .good, .sha1);
    bad_serial.serial = "";
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{bad_serial}, key, opts));
    var far = entryFor(id, ca256, .good, .sha1);
    far.next_update_unix = 253402300800; // year 10000
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{far}, key, opts));
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{entryFor(id, ca256, .good, .sha1)}, key, .{ .responder_cert_der = "junk", .produced_at_unix = produced }));
    var embed = opts;
    embed.embed_certs = &.{"junk"};
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{entryFor(id, ca256, .good, .sha1)}, key, embed));
}

test "createResponse: an embedded certificate rides in certs" {
    const gpa = testing.allocator;
    const id = try only(try ocsp.parseRequest(req256));
    const resp = try ocsp.createResponse(gpa, &.{entryFor(id, ca256, .good, .sha1)}, .{ .ecdsa_p256 = ca256_key[0..32] }, .{
        .responder_cert_der = ca256,
        .produced_at_unix = produced,
        .embed_certs = &.{ca256},
    });
    defer gpa.free(resp);
    const basic = (try ocsp.parseResponse(resp)).basic.?;
    try testing.expect(std.mem.eql(u8, basic.certs.?, ca256));
}
