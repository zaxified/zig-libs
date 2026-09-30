// SPDX-License-Identifier: MIT
//! Tests for `crl.zig` over the fixtures in `data/crl/` (made by
//! `tools/gen_crl_fixtures.py`; every good/revoked/out-of-scope verdict below
//! was confirmed by `openssl verify -crl_check` when they were generated).

const std = @import("std");
const testing = std.testing;
const crl = @import("crl.zig");

fn fx(comptime name: []const u8) []const u8 {
    return @embedFile("data/crl/" ++ name);
}

/// Fixture time base: CRLs issued at T0 = 2026-01-01T00:00:00Z, next update
/// T0 + 7 days; entries revoked at T0 - 1 day.
const t0: i64 = 1_767_225_600;
const now: i64 = t0 + 3600;
const day: i64 = 86_400;
const opts: crl.Options = .{ .now_sec = now };

fn check(comptime crl_name: []const u8, comptime leaf: []const u8, comptime ca: []const u8) crl.CheckError!crl.Status {
    return crl.checkRevocation(fx(crl_name), fx(leaf), fx(ca), opts);
}

fn expectRevoked(st: crl.Status, reason: ?crl.Reason) !void {
    try testing.expect(st == .revoked);
    try testing.expectEqual(t0 - day, st.revoked.revocation_time);
    try testing.expectEqual(reason, st.revoked.reason);
}

test "RSA CRL: revoked with reason and invalidity date, hold, good" {
    const st = try check("rsa.crl", "rsa_leaf_revoked.der", "rsa_ca.der");
    try expectRevoked(st, .key_compromise);
    try testing.expectEqual(@as(?i64, t0 - 2 * day), st.revoked.invalidity_time);
    try expectRevoked(try check("rsa.crl", "rsa_leaf_hold.der", "rsa_ca.der"), .certificate_hold);
    try testing.expect(try check("rsa.crl", "rsa_leaf_good.der", "rsa_ca.der") == .good);
    try testing.expect(try check("rsa_empty.crl", "rsa_leaf_revoked.der", "rsa_ca.der") == .good);
}

test "every signature algorithm: RSASSA-PSS, ECDSA P-256 / P-384, Ed25519" {
    try expectRevoked(try check("rsa_pss.crl", "rsa_leaf_revoked.der", "rsa_ca.der"), .key_compromise);
    try testing.expect(try check("rsa_pss.crl", "rsa_leaf_good.der", "rsa_ca.der") == .good);
    try expectRevoked(try check("ec256.crl", "ec256_leaf_revoked.der", "ec256_ca.der"), .cessation_of_operation);
    try testing.expect(try check("ec256.crl", "ec256_leaf_good.der", "ec256_ca.der") == .good);
    try expectRevoked(try check("ec384.crl", "ec384_leaf_revoked.der", "ec384_ca.der"), .cessation_of_operation);
    try testing.expect(try check("ec384.crl", "ec384_leaf_good.der", "ec384_ca.der") == .good);
    try expectRevoked(try check("ed25519.crl", "ed25519_leaf_revoked.der", "ed25519_ca.der"), .cessation_of_operation);
    try testing.expect(try check("ed25519.crl", "ed25519_leaf_good.der", "ed25519_ca.der") == .good);
}

test "ML-DSA-44 CRL made by OpenSSL 3.5" {
    const c = try crl.parse(fx("mldsa.crl"));
    const o: crl.Options = .{ .now_sec = c.this_update + 60 };
    const st = try crl.checkRevocation(fx("mldsa.crl"), fx("mldsa_leaf_revoked.der"), fx("mldsa_ca.der"), o);
    try testing.expect(st == .revoked);
    try testing.expectEqual(@as(?crl.Reason, .key_compromise), st.revoked.reason);
    try testing.expect(try crl.checkRevocation(fx("mldsa.crl"), fx("mldsa_leaf_good.der"), fx("mldsa_ca.der"), o) == .good);
}

test "freshness: thisUpdate <= now < nextUpdate; no nextUpdate needs max_age" {
    const c = fx("rsa.crl");
    const leaf = fx("rsa_leaf_good.der");
    const ca = fx("rsa_ca.der");
    try testing.expectError(error.CrlNotYetValid, crl.checkRevocation(c, leaf, ca, .{ .now_sec = t0 - 1 }));
    try testing.expect(try crl.checkRevocation(c, leaf, ca, .{ .now_sec = t0 }) == .good);
    try testing.expect(try crl.checkRevocation(c, leaf, ca, .{ .now_sec = t0 + 7 * day - 1 }) == .good);
    try testing.expectError(error.CrlExpired, crl.checkRevocation(c, leaf, ca, .{ .now_sec = t0 + 7 * day }));

    const nn = fx("rsa_no_next.crl");
    try testing.expect((try crl.parse(nn)).next_update == null);
    try testing.expectError(error.CrlMissingNextUpdate, crl.checkRevocation(nn, leaf, ca, opts));
    try testing.expect(try crl.checkRevocation(nn, leaf, ca, .{ .now_sec = now, .max_age_sec = 2 * 3600 }) == .good);
    try expectRevoked(try crl.checkRevocation(nn, fx("rsa_leaf_revoked.der"), ca, .{ .now_sec = now, .max_age_sec = 2 * 3600 }), .key_compromise);
    try testing.expectError(error.CrlExpired, crl.checkRevocation(nn, leaf, ca, .{ .now_sec = now, .max_age_sec = 3600 }));
}

test "fail closed: delta, critical unknown extensions (CRL and entry); non-critical unknown is fine" {
    try testing.expectError(error.DeltaCrlUnsupported, check("rsa_delta.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try testing.expectError(error.UnsupportedCriticalExtension, check("rsa_critical_ext.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try testing.expectError(error.UnsupportedCriticalExtension, check("rsa_entry_critical.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try expectRevoked(try check("rsa_noncritical_ext.crl", "rsa_leaf_revoked.der", "rsa_ca.der"), .key_compromise);
}

test "issuing distribution point: partition by name, user/CA scope, unsupported scopes refused" {
    try expectRevoked(try check("rsa_idp1.crl", "rsa_leaf_dp1.der", "rsa_ca.der"), .superseded);
    // Another partition's certificate, one naming no distribution point, and a CA on a user-only CRL.
    try testing.expectError(error.CrlScopeMismatch, check("rsa_idp1.crl", "rsa_leaf_dp2.der", "rsa_ca.der"));
    try testing.expectError(error.CrlScopeMismatch, check("rsa_idp1.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try testing.expectError(error.CrlScopeMismatch, check("rsa_idp1.crl", "rsa_sub_ca_dp1.der", "rsa_ca.der"));
    try testing.expectError(error.CrlScopeMismatch, check("rsa_idp_ca_only.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try testing.expectError(error.CrlScopeUnsupported, check("rsa_idp_some_reasons.crl", "rsa_leaf_good.der", "rsa_ca.der"));
    try testing.expectError(error.IndirectCrlUnsupported, check("rsa_idp_indirect.crl", "rsa_leaf_good.der", "rsa_ca.der"));
}

test "issuer binding: foreign issuer, impostor key, lying AKI, no cRLSign" {
    // CRL of another CA than the certificate's.
    try testing.expectError(error.CrlIssuerMismatch, check("ec256.crl", "rsa_leaf_revoked.der", "rsa_ca.der"));
    // Same CA name, another key: its AKI gives it away...
    try testing.expectError(error.CrlKeyIdentifierMismatch, check("rsa_impostor.crl", "rsa_leaf_revoked.der", "rsa_ca.der"));
    // ...and when the AKI lies, the signature does.
    try testing.expectError(error.CertificateSignatureInvalid, check("rsa_impostor_rsa_aki.crl", "rsa_leaf_revoked.der", "rsa_ca.der"));
    // The right CRL checked against the wrong issuer certificate.
    if (check("rsa.crl", "rsa_leaf_revoked.der", "ec256_ca.der")) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectError(error.KeyUsageForbidsCrlSigning, check("nosign.crl", "nosign_leaf.der", "nosign_ca.der"));
}

test "structure: v2 only, inner and outer algorithm byte-equal, no certificateIssuer, zero unused bits" {
    try testing.expectError(error.CrlUnsupportedVersion, crl.parse(fx("rsa_bad_version.crl")));
    // Validly signed, same algorithm, but the inner AlgorithmIdentifier omits the NULL.
    try testing.expectError(error.CrlSignatureAlgorithmMismatch, crl.parse(fx("rsa_alg_mismatch.crl")));
    // A non-critical certificateIssuer is still an indirect CRL.
    try testing.expectError(error.IndirectCrlUnsupported, crl.parse(fx("rsa_entry_cert_issuer.crl")));

    const full = fx("rsa.crl");
    const c = try crl.parse(full);
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..full.len], full);
    buf[c.signed.signature_slice.start - 1] = 1; // the BIT STRING's unused-bits octet
    try testing.expectError(error.CrlMalformed, crl.parse(buf[0..full.len]));
}

test "parse: fields, entries, lookup by value of the serial" {
    const c = try crl.parse(fx("rsa.crl"));
    try testing.expectEqual(t0, c.this_update);
    try testing.expectEqual(@as(?i64, t0 + 7 * day), c.next_update);
    try testing.expectEqualSlices(u8, &.{1}, c.crl_number.?);
    try testing.expect(c.authority_key_id != null);
    try testing.expectEqual(@as(u32, 3), c.entry_count);
    var it = c.iterator();
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expect(c.find(&.{ 0x10, 0x01 }) != null);
    try testing.expect(c.find(&.{ 0x00, 0x10, 0x01 }) != null); // non-minimal encoding, same value
    try testing.expect(c.find(&.{ 0x10, 0x02 }) == null);
    try testing.expect(c.find(&.{ 0x09, 0x99 }).?.reason == null);
}

test "malformed input: every truncation fails, trailing bytes fail" {
    const full = fx("rsa.crl");
    var i: usize = 0;
    while (i < full.len) : (i += 1) {
        if (crl.parse(full[0..i])) |_| return error.TestUnexpectedResult else |_| {}
    }
    var extended: [4096]u8 = undefined;
    @memcpy(extended[0..full.len], full);
    extended[full.len] = 0;
    try testing.expectError(error.CrlMalformed, crl.parse(extended[0 .. full.len + 1]));
}

test "tampering: no single-byte change turns the revoked certificate into a different answer" {
    const full = fx("rsa.crl");
    const leaf = fx("rsa_leaf_revoked.der");
    const ca = fx("rsa_ca.der");
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..full.len], full);
    var accepted: usize = 0;
    for (0..full.len) |i| {
        buf[i] ^= 0x01;
        defer buf[i] ^= 0x01;
        const st = crl.checkRevocation(buf[0..full.len], leaf, ca, opts) catch continue;
        // Only a change the signature does not cover may be accepted, and it
        // must not change the verdict.
        accepted += 1;
        try expectRevoked(st, .key_compromise);
    }
    // The signed part is almost all of the CRL: nearly every change is refused.
    try testing.expect(accepted < 8);
}
