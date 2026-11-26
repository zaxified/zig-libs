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

// ── delta mutation 2026-11-25 ───────────────────────────────────────────────

/// DER TLV with a short or two-byte length (test fixtures only).
fn tlv(gpa: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var n: usize = 0;
    for (parts) |p| n += p.len;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, tag);
    if (n < 128) {
        try out.append(gpa, @intCast(n));
    } else {
        try out.appendSlice(gpa, &.{ 0x82, @intCast(n >> 8), @intCast(n & 0xff) });
    }
    for (parts) |p| try out.appendSlice(gpa, p);
    return out.toOwnedSlice(gpa);
}

/// One OCSPRequest built by hand, each structural element's tag and trailing bytes overridable.
const Shape = struct {
    outer_tag: u8 = 0x30,
    tbs_tag: u8 = 0x30,
    list_tag: u8 = 0x30,
    req_tag: u8 = 0x30,
    certid_tag: u8 = 0x30,
    alg_tag: u8 = 0x30,
    oid_tag: u8 = 0x06,
    oid: []const u8 = &.{ 0x2b, 0x0e, 0x03, 0x02, 0x1a }, // sha1
    alg_params: []const u8 = &.{ 0x05, 0x00 },
    name_tag: u8 = 0x04,
    key_tag: u8 = 0x04,
    serial_tag: u8 = 0x02,
    certid_trailing: []const u8 = "",
    req_ext: []const u8 = "", // a whole TLV after the CertID inside the Request
    req_trailing: []const u8 = "",
    version: []const u8 = "", // a whole TLV before the request list
    requestor: []const u8 = "",
    exts: []const u8 = "", // a whole TLV after the request list
    tbs_trailing: []const u8 = "",
    sig: []const u8 = "", // a whole TLV after tbsRequest
    outer_trailing: []const u8 = "",

    fn build(s: Shape, gpa: std.mem.Allocator) ![]u8 {
        const name_hash: [20]u8 = @splat(0x11);
        const key_hash: [20]u8 = @splat(0x22);
        const oid = try tlv(gpa, s.oid_tag, &.{s.oid});
        defer gpa.free(oid);
        const alg = try tlv(gpa, s.alg_tag, &.{ oid, s.alg_params });
        defer gpa.free(alg);
        const nh = try tlv(gpa, s.name_tag, &.{&name_hash});
        defer gpa.free(nh);
        const kh = try tlv(gpa, s.key_tag, &.{&key_hash});
        defer gpa.free(kh);
        const serial = try tlv(gpa, s.serial_tag, &.{&.{0x07}});
        defer gpa.free(serial);
        const certid = try tlv(gpa, s.certid_tag, &.{ alg, nh, kh, serial, s.certid_trailing });
        defer gpa.free(certid);
        const req = try tlv(gpa, s.req_tag, &.{ certid, s.req_ext, s.req_trailing });
        defer gpa.free(req);
        const list = try tlv(gpa, s.list_tag, &.{req});
        defer gpa.free(list);
        const tbs = try tlv(gpa, s.tbs_tag, &.{ s.version, s.requestor, list, s.exts, s.tbs_trailing });
        defer gpa.free(tbs);
        return tlv(gpa, s.outer_tag, &.{ tbs, s.sig, s.outer_trailing });
    }

    fn parse(s: Shape, gpa: std.mem.Allocator) !void {
        const bytes = try s.build(gpa);
        defer gpa.free(bytes);
        const req = try ocsp.parseRequest(bytes);
        _ = req;
    }
};

test "mutation 2026-11-25: parseRequest and the CertID iterator check every tag and every closing length" {
    const gpa = testing.allocator;
    try (Shape{}).parse(gpa); // the base shape is valid
    const bad = [_]Shape{
        .{ .req_tag = 0x31 },
        .{ .certid_tag = 0x31 },
        .{ .alg_tag = 0x31 },
        .{ .oid_tag = 0x04 },
        .{ .alg_params = &.{ 0x05, 0x01, 0x00 } }, // NULL parameters with content
        .{ .name_tag = 0x02 },
        .{ .key_tag = 0x02 },
        .{ .serial_tag = 0x04 },
        .{ .certid_trailing = &.{ 0x05, 0x00 } },
        .{ .req_ext = &.{ 0xa1, 0x00 } }, // singleRequestExtensions with the wrong tag
        .{ .req_ext = &.{ 0xa0, 0x00 }, .req_trailing = &.{ 0x05, 0x00 } },
        .{ .outer_tag = 0x31 },
        .{ .tbs_tag = 0x31 },
        .{ .sig = &.{ 0xa1, 0x00 } }, // optionalSignature with the wrong tag
        .{ .sig = &.{ 0xa0, 0x00 }, .outer_trailing = &.{ 0x05, 0x00 } },
        .{ .version = &.{ 0xa0, 0x03, 0x04, 0x01, 0x00 } }, // version holding an OCTET STRING
        .{ .version = &.{ 0xa0, 0x05, 0x02, 0x01, 0x00, 0x05, 0x00 } }, // version with trailing bytes
        .{ .list_tag = 0x31 },
        .{ .exts = &.{ 0xa3, 0x02, 0x30, 0x00 } }, // requestExtensions with the wrong tag
        .{ .exts = &.{ 0xa2, 0x02, 0x30, 0x00 }, .tbs_trailing = &.{ 0x05, 0x00 } },
        .{ .exts = &.{ 0xa2, 0x02, 0x31, 0x00 } }, // Extensions as a SET
        .{ .exts = &.{ 0xa2, 0x04, 0x30, 0x00, 0x05, 0x00 } },
    };
    for (bad, 0..) |s, i| {
        s.parse(gpa) catch |err| {
            try testing.expectEqual(error.Malformed, err);
            continue;
        };
        std.debug.print("variant {d} was accepted\n", .{i});
        return error.TestUnexpectedResult;
    }
}

test "mutation 2026-11-25: parseRequest skips a version and a requestorName, then reads the list" {
    const gpa = testing.allocator;
    const s: Shape = .{
        .version = &.{ 0xa0, 0x03, 0x02, 0x01, 0x00 },
        .requestor = &.{ 0xa1, 0x05, 0x82, 0x03, 'a', '.', 'b' },
    };
    const bytes = try s.build(gpa);
    defer gpa.free(bytes);
    const id = try only(try ocsp.parseRequest(bytes));
    try testing.expectEqualSlices(u8, &.{0x07}, id.serial);
    try testing.expectEqualSlices(u8, &@as([20]u8, @splat(0x11)), id.issuer_name_hash);
    try testing.expectEqualSlices(u8, &@as([20]u8, @splat(0x22)), id.issuer_key_hash);
    // each alone as well
    const only_version = try (Shape{ .version = s.version }).build(gpa);
    defer gpa.free(only_version);
    _ = try only(try ocsp.parseRequest(only_version));
    const only_requestor = try (Shape{ .requestor = s.requestor }).build(gpa);
    defer gpa.free(only_requestor);
    _ = try only(try ocsp.parseRequest(only_requestor));
}

test "mutation 2026-11-25: CertId.namesIssuer wants an issuer name hash AND key hash AND a known hash algorithm" {
    const id = try only(try ocsp.parseRequest(req256));
    try testing.expect(id.namesIssuer(ca256));
    var bad_name = id;
    var name_hash: [20]u8 = undefined;
    @memcpy(&name_hash, id.issuer_name_hash);
    name_hash[0] ^= 1;
    bad_name.issuer_name_hash = &name_hash;
    try testing.expect(!bad_name.namesIssuer(ca256));
    var bad_key = id;
    var key_hash: [20]u8 = undefined;
    @memcpy(&key_hash, id.issuer_key_hash);
    key_hash[19] ^= 1;
    bad_key.issuer_key_hash = &key_hash;
    try testing.expect(!bad_key.namesIssuer(ca256));
    // the right SHA-1 hashes under an algorithm identifier this module does not know
    var unknown_algo = id;
    unknown_algo.hash_oid = &.{ 0x2a, 0x03, 0x04 };
    try testing.expect(!unknown_algo.namesIssuer(ca256));
}

test "mutation 2026-11-25: createResponse takes a time in year 9999 and refuses one before year 0" {
    const gpa = testing.allocator;
    const id = try only(try ocsp.parseRequest(req256));
    const key: ocsp.SigningKey = .{ .ecdsa_p256 = ca256_key[0..32] };
    const opts: ocsp.ResponseOptions = .{ .responder_cert_der = ca256, .produced_at_unix = produced };
    var last = entryFor(id, ca256, .good, .sha1);
    last.next_update_unix = 253402300799; // 9999-12-31T23:59:59Z
    const resp = try ocsp.createResponse(gpa, &.{last}, key, opts);
    defer gpa.free(resp);
    const v = try ocsp.verify(try ocsp.parseResponse(resp), ca256, leaf256, .{ .now_unix = produced });
    try testing.expectEqual(@as(?i64, 253402300799), v.next_update_unix);
    var early = last;
    early.next_update_unix = -62167219201; // 0000-12-31T23:59:59Z, one second before year 0... in year -1
    try testing.expectError(error.Malformed, ocsp.createResponse(gpa, &.{early}, key, opts));
}
