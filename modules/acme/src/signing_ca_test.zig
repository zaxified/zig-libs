// SPDX-License-Identifier: MIT

//! Test-only certificate authority for the mock ACME CA: signs a leaf certificate for the public key and the
//! names of a CSR (`SigningCa.issue`), under a fixed-seed ECDSA P-256 CA key, so the `Manager`'s full path runs
//! against it (the issued chain's leaf carries the key the Manager just minted, which `checkPair` requires and a
//! canned chain never does). A minimal DER writer, deterministic (std's deterministic ECDSA), no randomness.

const std = @import("std");
const x509 = @import("x509.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Allocator = std.mem.Allocator;

const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_cn = [_]u8{ 0x55, 0x04, 0x03 };

/// An arena-backed DER writer.
const Der = struct {
    a: Allocator,

    fn tlv(d: Der, tag: u8, parts: []const []const u8) ![]u8 {
        var n: usize = 0;
        for (parts) |p| n += p.len;
        var out: std.ArrayList(u8) = .empty;
        try out.append(d.a, tag);
        if (n < 0x80) {
            try out.append(d.a, @intCast(n));
        } else if (n < 0x100) {
            try out.appendSlice(d.a, &.{ 0x81, @intCast(n) });
        } else {
            try out.appendSlice(d.a, &.{ 0x82, @intCast(n >> 8), @truncate(n) });
        }
        for (parts) |p| try out.appendSlice(d.a, p);
        return out.items;
    }

    fn seq(d: Der, parts: []const []const u8) ![]u8 {
        return d.tlv(0x30, parts);
    }

    fn oid(d: Der, content: []const u8) ![]u8 {
        return d.tlv(0x06, &.{content});
    }

    fn int(d: Der, v: u32) ![]u8 {
        var be: [5]u8 = undefined;
        be[0] = 0;
        std.mem.writeInt(u32, be[1..5], v, .big);
        var i: usize = 0;
        while (i < 4 and be[i] == 0 and be[i + 1] & 0x80 == 0) i += 1;
        return d.tlv(0x02, &.{be[i..]});
    }

    fn name(d: Der, cn: []const u8) ![]u8 {
        const atv = try d.seq(&.{ try d.oid(&oid_cn), try d.tlv(0x0c, &.{cn}) });
        return d.seq(&.{try d.tlv(0x31, &.{atv})});
    }

    fn utcTime(d: Der, unix: i64) ![]u8 {
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var buf: [13]u8 = undefined;
        const s = try std.mem.print(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            @as(u32, yd.year) % 100,
            md.month.numeric(),
            md.day_index + 1,
            ds.getHoursIntoDay(),
            ds.getMinutesIntoHour(),
            ds.getSecondsIntoMinute(),
        });
        return d.tlv(0x17, &.{s});
    }

    fn extension(d: Der, ext_oid: []const u8, critical: bool, value: []const u8) ![]u8 {
        const octets = try d.tlv(0x04, &.{value});
        if (critical) return d.seq(&.{ try d.oid(ext_oid), try d.tlv(0x01, &.{&.{0xff}}), octets });
        return d.seq(&.{ try d.oid(ext_oid), octets });
    }

    /// `tbs` signed under `kp`: the Certificate SEQUENCE.
    fn signed(d: Der, kp: Ecdsa.KeyPair, tbs: []const u8) ![]u8 {
        const sig = try kp.sign(tbs, null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const sig_der = sig.toDer(&der_buf);
        const alg = try d.seq(&.{try d.oid(&oid_ecdsa_sha256)});
        return d.seq(&.{ tbs, alg, try d.tlv(0x03, &.{ &.{0x00}, sig_der }) });
    }
};

/// Where to find the SubjectPublicKeyInfo of a CSR: `CertificationRequest ::= SEQ { info SEQ { version, subject, spki ... } }`.
fn csrSpki(csr: []const u8) ![]const u8 {
    const Elem = struct { start: usize, end: usize, hdr: usize };
    const read = struct {
        fn f(buf: []const u8, at: usize) !Elem {
            if (at + 2 > buf.len) return error.Malformed;
            var len: usize = buf[at + 1];
            var hdr: usize = 2;
            if (len & 0x80 != 0) {
                const n = len & 0x7f;
                if (n == 0 or n > 2 or at + 2 + n > buf.len) return error.Malformed;
                len = 0;
                for (buf[at + 2 ..][0..n]) |b| len = (len << 8) | b;
                hdr = 2 + n;
            }
            if (at + hdr + len > buf.len) return error.Malformed;
            return .{ .start = at + hdr, .end = at + hdr + len, .hdr = at };
        }
    }.f;
    const outer = try read(csr, 0);
    const info = try read(csr, outer.start);
    const version = try read(csr, info.start);
    const subject = try read(csr, version.end);
    const spki = try read(csr, subject.end);
    return csr[spki.hdr..spki.end];
}

pub const SigningCa = struct {
    kp: Ecdsa.KeyPair,
    /// The CA certificate (self-signed), DER and PEM (gpa-owned).
    ca_der: []u8,
    ca_pem: []u8,
    /// SHA-1 of the CA public key point: the leaves' authorityKeyIdentifier (ARI's CertID needs one).
    key_id: [20]u8,
    next_serial: u32 = 0x1000,

    pub fn init(gpa: Allocator, seed_byte: u8, not_before: i64, not_after: i64) !SigningCa {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const d: Der = .{ .a = arena_state.allocator() };
        const kp = try Ecdsa.KeyPair.generateDeterministic(@splat(seed_byte));
        const sec1 = kp.public_key.toUncompressedSec1();
        var key_id: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(&sec1, &key_id, .{});

        const spki = try spkiOf(d, &sec1);
        const ca_name = try d.name("acme mock CA");
        const bc = try d.extension(&.{ 0x55, 0x1d, 0x13 }, true, try d.seq(&.{try d.tlv(0x01, &.{&.{0xff}})}));
        const ku = try d.extension(&.{ 0x55, 0x1d, 0x0f }, true, try d.tlv(0x03, &.{&.{ 0x02, 0x04 }})); // keyCertSign
        const ski = try d.extension(&.{ 0x55, 0x1d, 0x0e }, false, try d.tlv(0x04, &.{&key_id}));
        const tbs = try d.seq(&.{
            try d.tlv(0xa0, &.{try d.int(2)}),
            try d.int(1),
            try d.seq(&.{try d.oid(&oid_ecdsa_sha256)}),
            ca_name,
            try d.seq(&.{ try d.utcTime(not_before), try d.utcTime(not_after) }),
            ca_name,
            spki,
            try d.tlv(0xa3, &.{try d.seq(&.{ bc, ku, ski })}),
        });
        const cert = try d.signed(kp, tbs);
        const ca_der = try gpa.dupe(u8, cert);
        errdefer gpa.free(ca_der);
        return .{ .kp = kp, .ca_der = ca_der, .ca_pem = try x509.pemEncode(gpa, "CERTIFICATE", cert), .key_id = key_id };
    }

    pub fn deinit(ca: *SigningCa, gpa: Allocator) void {
        gpa.free(ca.ca_der);
        gpa.free(ca.ca_pem);
        ca.* = undefined;
    }

    /// A leaf for the key and the dNSName SANs of `csr_der` (already verified by the caller), valid for
    /// `not_before .. not_after`; the PEM of the leaf followed by the CA certificate, gpa-owned.
    pub fn issue(ca: *SigningCa, gpa: Allocator, csr_der: []const u8, not_before: i64, not_after: i64) ![]u8 {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const d: Der = .{ .a = arena_state.allocator() };
        var parsed = try x509.parseCsrAny(gpa, csr_der);
        defer parsed.deinit();
        if (parsed.sans.len == 0) return error.NoNames;

        var names: std.ArrayList([]const u8) = .empty;
        for (parsed.sans) |s| try names.append(d.a, try d.tlv(0x82, &.{s})); // dNSName [2]
        const san = try d.extension(&.{ 0x55, 0x1d, 0x11 }, false, try d.seq(names.items));
        const bc = try d.extension(&.{ 0x55, 0x1d, 0x13 }, true, try d.seq(&.{}));
        const ku = try d.extension(&.{ 0x55, 0x1d, 0x0f }, true, try d.tlv(0x03, &.{&.{ 0x07, 0x80 }})); // digitalSignature
        const eku = try d.extension(&.{ 0x55, 0x1d, 0x25 }, false, try d.seq(&.{try d.oid(&.{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 })}));
        const aki = try d.extension(&.{ 0x55, 0x1d, 0x23 }, false, try d.seq(&.{try d.tlv(0x80, &.{&ca.key_id})}));
        const serial = ca.next_serial;
        ca.next_serial += 1;
        const tbs = try d.seq(&.{
            try d.tlv(0xa0, &.{try d.int(2)}),
            try d.int(serial),
            try d.seq(&.{try d.oid(&oid_ecdsa_sha256)}),
            try d.name("acme mock CA"),
            try d.seq(&.{ try d.utcTime(not_before), try d.utcTime(not_after) }),
            try d.name(parsed.sans[0]),
            try csrSpkiCopy(d, csr_der),
            try d.tlv(0xa3, &.{try d.seq(&.{ bc, ku, eku, san, aki })}),
        });
        const leaf = try d.signed(ca.kp, tbs);
        const leaf_pem = try x509.pemEncode(gpa, "CERTIFICATE", leaf);
        defer gpa.free(leaf_pem);
        return std.mem.concat(gpa, u8, &.{ leaf_pem, ca.ca_pem });
    }
};

fn csrSpkiCopy(d: Der, csr_der: []const u8) ![]u8 {
    return d.a.dupe(u8, try csrSpki(csr_der));
}

fn spkiOf(d: Der, sec1: *const [65]u8) ![]u8 {
    const alg = try d.seq(&.{ try d.oid(&oid_ec_public_key), try d.oid(&oid_prime256v1) });
    return d.seq(&.{ alg, try d.tlv(0x03, &.{ &.{0x00}, sec1 }) });
}

test "SigningCa: a leaf for a CSR verifies under the CA and carries the CSR's key and names" {
    const testing = std.testing;
    const gpa = testing.allocator;
    const jws = @import("jws.zig");
    var key: jws.KeyPair = undefined;
    try jws.Es256.KeyPair.generateDeterministicInto(&key, &@as([32]u8, @splat(9)));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    const csr = try x509.csrDer(gpa, &key, &.{ "a.example", "www.a.example" });
    defer gpa.free(csr);

    var ca = try SigningCa.init(gpa, 7, 1735689600, 2051222400);
    defer ca.deinit(gpa);
    const chain = try ca.issue(gpa, csr, 1767225600, 1769817600);
    defer gpa.free(chain);

    // Two certificates; the leaf parses and its signature verifies under the CA key.
    const leaf_der = try x509.pemDecode(gpa, "CERTIFICATE", chain);
    defer gpa.free(leaf_der);
    const cert: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
    const parsed = try cert.parse();
    try testing.expectEqualStrings("a.example", parsed.commonName());
    const ca_cert: std.crypto.Certificate = .{ .buffer = ca.ca_der, .index = 0 };
    try parsed.verify(try ca_cert.parse(), 1768000000);
    // The leaf's key is the CSR's.
    var csr_parsed = try x509.parseCsrAny(gpa, csr);
    defer csr_parsed.deinit();
    try testing.expectEqualSlices(u8, &csr_parsed.public_key.es256.toUncompressedSec1(), parsed.pubKey());
    try testing.expect(std.mem.count(u8, chain, "BEGIN CERTIFICATE") == 2);
}
