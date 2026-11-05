// SPDX-License-Identifier: MIT

//! Tests against `vectors.zig` (OpenSSL 3.5.5 output, `tools/vectors.py`):
//! every key read back into the parts OpenSSL printed, and written back to
//! OpenSSL's exact bytes; then the refusals.

const std = @import("std");
const kc = @import("root.zig");
const vectors = @import("vectors.zig");
const t = std.testing;

fn expectHex(expected: []const u8, bytes: []const u8) !void {
    var buf: [2 * kc.max_private_der_len]u8 = undefined;
    const chars = "0123456789abcdef";
    try t.expect(bytes.len <= kc.max_private_der_len);
    for (bytes, 0..) |b, i| {
        buf[2 * i] = chars[b >> 4];
        buf[2 * i + 1] = chars[b & 15];
    }
    try t.expectEqualStrings(expected, buf[0 .. 2 * bytes.len]);
}

fn labelOf(encoding: []const u8) []const u8 {
    return (std.meta.stringToEnum(kc.Encoding, encoding) orelse unreachable).pemLabel();
}

test "every OpenSSL private key reads back into the parts OpenSSL printed" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const k = try kc.parsePrivateKeyPem(c.pem, &buf);
        try t.expectEqualStrings(c.algorithm, @tagName(k.algorithm));
        try t.expectEqualStrings(c.encoding, @tagName(k.encoding));
        if (c.pq_form) |f| try t.expectEqualStrings(f, @tagName(k.pq_form.?)) else try t.expect(k.pq_form == null);
        if (k.algorithm.isEc()) {
            var scalar: [66]u8 = undefined;
            const n = k.algorithm.secretLen().?;
            try k.scalarInto(scalar[0..n]);
            try expectHex(c.secret, scalar[0..n]);
            try expectHex(c.public, k.public.?); // OpenSSL writes the point into both forms
        } else {
            try expectHex(c.secret, k.secret);
            try t.expect(k.public == null); // OpenSSL writes PKCS#8 v1
        }
        try expectHex(c.expanded, k.expanded);
    }
}

test "every OpenSSL private key is written back byte for byte" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    var out: [kc.max_private_pem_len]u8 = undefined;
    var der2: [kc.max_private_der_len]u8 = undefined;
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const k = try kc.parsePrivateKeyPem(c.pem, &buf);
        try t.expectEqualStrings(c.pem, try kc.writePrivateKeyPem(&out, k));
        // The DER entry point reads the same key from the bare DER.
        const block = (try kc.pem.find(c.pem, labelOf(c.encoding))).?;
        const bytes = try block.decode(&der2);
        const k2 = try kc.parsePrivateKeyDer(bytes);
        try t.expectEqual(k.algorithm, k2.algorithm);
        try t.expectEqual(k.encoding, k2.encoding);
        try t.expectEqualSlices(u8, k.secret, k2.secret);
        // An EC key converts between its two forms as `openssl ec` / `pkcs8` do.
        if (k.algorithm.isEc()) {
            var other = k;
            other.encoding = if (k.encoding == .sec1) .pkcs8 else .sec1;
            const pem2 = try kc.writePrivateKeyPem(&out, other);
            for (vectors.cases) |c2| if (std.mem.eql(u8, c2.algorithm, c.algorithm) and !std.mem.eql(u8, c2.encoding, c.encoding))
                try t.expectEqualStrings(c2.pem, pem2);
        }
    }
}

test "every OpenSSL public key reads back and is written back byte for byte" {
    var buf: [kc.max_public_der_len]u8 = undefined;
    var out: [kc.max_private_pem_len]u8 = undefined;
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const pk = try kc.parsePublicKeyPem(c.spki_pem, &buf);
        try t.expectEqualStrings(c.algorithm, @tagName(pk.algorithm));
        try expectHex(c.public, pk.key);
        try t.expectEqualStrings(c.spki_pem, try kc.writePublicKeyPem(&out, pk));
    }
}

test "the parsed parts are the key: derived public keys match OpenSSL's" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const k = try kc.parsePrivateKeyPem(c.pem, &buf);
        var pub_buf: [kc.max_public_der_len]u8 = undefined;
        const pk = try kc.parsePublicKeyPem(c.spki_pem, &pub_buf);
        switch (k.algorithm) {
            .ec_p256 => {
                var s: [32]u8 = undefined;
                try k.scalarInto(&s);
                const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(try .fromBytes(s));
                try t.expectEqualSlices(u8, pk.key, &kp.public_key.toUncompressedSec1());
            },
            .ec_p384 => {
                var s: [48]u8 = undefined;
                try k.scalarInto(&s);
                const kp = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.fromSecretKey(try .fromBytes(s));
                try t.expectEqualSlices(u8, pk.key, &kp.public_key.toUncompressedSec1());
            },
            .ed25519 => {
                const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(k.secret[0..32].*);
                try t.expectEqualSlices(u8, pk.key, &kp.public_key.toBytes());
            },
            .x25519 => {
                const p = std.crypto.dh.X25519.recoverPublicKey(k.secret[0..32].*);
                try t.expectEqualSlices(u8, pk.key, &p);
            },
            .ml_kem_768 => if (k.pq_form.? != .expanded) {
                const kp = try std.crypto.kem.ml_kem.MLKem768.KeyPair.generateDeterministic(k.secret[0..64].*);
                try t.expectEqualSlices(u8, pk.key, &kp.public_key.toBytes());
                if (k.pq_form.? == .both) try t.expectEqualSlices(u8, k.expanded, &kp.secret_key.toBytes());
            },
            .ml_dsa_44 => if (k.pq_form.? != .expanded) {
                const M = std.crypto.sign.mldsa.MLDSA44;
                const kp = M.newKeyFromSeed(k.secret[0..M.seed_length]);
                try t.expectEqualSlices(u8, pk.key, &kp.pk.toBytes());
                if (k.pq_form.? == .both) try t.expectEqualSlices(u8, k.expanded, &kp.sk.toBytes());
            },
            else => {},
        }
    }
}

test "orders: the P-521 constant is the p521 module's" {
    const p521 = @import("p521");
    var b: [66]u8 = undefined;
    std.mem.writeInt(u528, &b, p521.scalar.field_order, .big);
    try t.expectEqualSlices(u8, &b, kc.Algorithm.ec_p521.order().?);
    try t.expect(kc.Algorithm.rsa.order() == null);
}

// ── refusals ────────────────────────────────────────────────────────────────

test "pem: encrypted keys, OpenSSH keys, no key, small buffer" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    try t.expectError(error.EncryptedKey, kc.parsePrivateKeyPem(vectors.encrypted_pkcs8_pem, &buf));
    try t.expectError(error.EncryptedKey, kc.parsePrivateKeyPem(vectors.encrypted_sec1_pem, &buf));
    try t.expectError(error.UnsupportedFormat, kc.parsePrivateKeyPem("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", &buf));
    try t.expectError(error.MissingKey, kc.parsePrivateKeyPem(vectors.cases[0].spki_pem, &buf));
    try t.expectError(error.MissingKey, kc.parsePrivateKeyPem("", &buf));
    try t.expectError(error.MissingKey, kc.parsePublicKeyPem(vectors.cases[0].pem, &buf));
    try t.expectError(error.NoSpaceLeft, kc.parsePrivateKeyPem(vectors.cases[0].pem, buf[0..16]));
    try t.expectError(error.InvalidPem, kc.parsePrivateKeyPem("-----BEGIN PRIVATE KEY-----\nAAAA\n", &buf));
    // Skipped blocks before the key, and the key found after them.
    const combined = vectors.cases[0].spki_pem ++ "garbage\n" ++ vectors.cases[0].pem;
    _ = try kc.parsePrivateKeyPem(combined, &buf);
}

/// A PKCS#8 wrapper around `private` under `alg_content` (the
/// AlgorithmIdentifier's content), built with the module's own writer.
fn pkcs8(out: []u8, version: u8, alg_content: []const u8, private: []const u8, extra: []const u8) []u8 {
    const der = kc.der;
    var w = der.Writer.init(out);
    w.header(0x30, der.tlvLen(1) + der.tlvLen(alg_content.len) + der.tlvLen(private.len) + extra.len);
    w.tlv(0x02, &.{version});
    w.tlv(0x30, alg_content);
    w.tlv(0x04, private);
    w.bytes(extra);
    return w.finish() catch unreachable;
}

const ed_alg = [_]u8{ 0x06, 0x03 } ++ kc.oid.ed25519;
fn edPrivate() [34]u8 {
    var p: [34]u8 = @splat(7);
    p[0..2].* = .{ 0x04, 0x20 };
    return p;
}

test "pkcs8: versions, attributes, the v2 public key" {
    var buf: [256]u8 = undefined;
    const priv = edPrivate();
    const ok = try kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, &priv, ""));
    try t.expectEqual(kc.Algorithm.ed25519, ok.algorithm);
    try t.expect(ok.public == null);

    var pub_field: [35]u8 = @splat(9);
    pub_field[0..3].* = .{ 0x81, 0x21, 0x00 };
    const attrs = [_]u8{ 0xa0, 0x02, 0x05, 0x00 };
    const v2 = try kc.parsePkcs8(pkcs8(&buf, 1, &ed_alg, &priv, &(attrs ++ pub_field)));
    try t.expectEqualSlices(u8, pub_field[3..], v2.public.?);
    // v2 written back: version 1 with the public key, no attributes.
    var out: [256]u8 = undefined;
    try t.expectEqualSlices(u8, pkcs8(&buf, 1, &ed_alg, &priv, &pub_field), try kc.writePkcs8(&out, v2));

    // publicKey in a v1 structure, version 2, a wrong public length, unused bits.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, &priv, &pub_field)));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 2, &ed_alg, &priv, "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &ed_alg, &priv, pub_field[0..34])));
    var bad_bits = pub_field;
    bad_bits[2] = 1;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &ed_alg, &priv, &bad_bits)));
    // Attributes after the public key: out of order is trailing data.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &ed_alg, &priv, &(pub_field ++ attrs))));
}

test "pkcs8: RFC 8410 §10.3 examples" {
    var buf: [256]u8 = undefined;
    const v1 =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
        \\-----END PRIVATE KEY-----
    ;
    const k1 = try kc.parsePrivateKeyPem(v1, &buf);
    try t.expectEqual(kc.Algorithm.ed25519, k1.algorithm);
    try t.expectEqual(@as(u8, 0xd4), k1.secret[0]);
    const v2 =
        \\-----BEGIN PRIVATE KEY-----
        \\MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
        \\oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
        \\Z9w7lshQhqowtrbLDFw4rXAxZuE=
        \\-----END PRIVATE KEY-----
    ;
    var buf2: [256]u8 = undefined;
    const k2 = try kc.parsePrivateKeyPem(v2, &buf2);
    try t.expectEqualSlices(u8, k1.secret, k2.secret);
    try t.expectEqual(@as(usize, 32), k2.public.?.len);
    try t.expectEqual(@as(u8, 0x19), k2.public.?[0]);
}

test "pkcs8: algorithm identifiers" {
    var buf: [256]u8 = undefined;
    const priv = edPrivate();
    // Ed25519 with parameters (RFC 8410 §3: MUST be absent).
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &(ed_alg ++ [_]u8{ 0x05, 0x00 }), &priv, "")));
    // A wrong Ed25519 length, and a CurvePrivateKey that is not an OCTET STRING.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, priv[0..33], "")));
    var not_octets = priv;
    not_octets[0] = 0x03;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, &not_octets, "")));
    // DSA (1.2.840.10040.4.1): well-formed, unsupported.
    const dsa = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
    try t.expectError(error.UnsupportedAlgorithm, kc.parsePkcs8(pkcs8(&buf, 0, &dsa, &priv, "")));
    // EC with an unknown curve (brainpoolP256r1 1.3.36.3.3.2.8.1.1.7), with
    // explicit parameters, with no parameters.
    const ec = [_]u8{ 0x06, 0x07 } ++ kc.oid.ec_public_key;
    const brainpool = ec ++ [_]u8{ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    try t.expectError(error.UnsupportedAlgorithm, kc.parsePkcs8(pkcs8(&buf, 0, &brainpool, &priv, "")));
    try t.expectError(error.UnsupportedAlgorithm, kc.parsePkcs8(pkcs8(&buf, 0, &(ec ++ [_]u8{ 0x30, 0x00 }), &priv, "")));
    try t.expectError(error.UnsupportedAlgorithm, kc.parsePkcs8(pkcs8(&buf, 0, &ec, &priv, "")));
    // rsaEncryption parameters other than NULL.
    const rsa_bad = [_]u8{ 0x06, 0x09 } ++ kc.oid.rsa_encryption ++ [_]u8{ 0x05, 0x01, 0x00 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &rsa_bad, &priv, "")));
}

fn caseNamed(name: []const u8) vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

fn derOf(c: vectors.Case, out: []u8) ![]u8 {
    return (try kc.pem.find(c.pem, labelOf(c.encoding))).?.decode(out);
}

test "sec1: scalar range, curve agreement" {
    var buf: [256]u8 = undefined;
    const bytes = try derOf(caseNamed("ec_p256-sec1"), &buf);
    const k = try kc.parseSec1(bytes, null);
    const at = @intFromPtr(k.secret.ptr) - @intFromPtr(bytes.ptr);
    const n = kc.Algorithm.ec_p256.order().?;

    var m: [256]u8 = undefined;
    @memcpy(m[0..bytes.len], bytes);
    const scalar = m[at..][0..32];
    @memcpy(scalar, n); // n itself
    try t.expectError(error.MalformedKey, kc.parseSec1(m[0..bytes.len], null));
    @memset(scalar, 0); // zero
    try t.expectError(error.MalformedKey, kc.parseSec1(m[0..bytes.len], null));
    @memcpy(scalar, n); // n - 1: the largest valid scalar
    scalar[31] -= 1;
    _ = try kc.parseSec1(m[0..bytes.len], null);
    @memset(scalar, 0xff);
    try t.expectError(error.MalformedKey, kc.parseSec1(m[0..bytes.len], null));

    // The context names P-384, the key's [0] P-256.
    try t.expectError(error.MalformedKey, kc.parseSec1(bytes, .ec_p384));
    _ = try kc.parseSec1(bytes, .ec_p256);
    try t.expectError(error.MalformedKey, kc.parseSec1(bytes, .ed25519));
    // A PKCS#8 for P-384 around this P-256 SEC1 key (with its [0]).
    const ec384 = [_]u8{ 0x06, 0x07 } ++ kc.oid.ec_public_key ++ [_]u8{ 0x06, 0x05 } ++ kc.oid.secp384r1;
    var wrapped: [512]u8 = undefined;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&wrapped, 0, &ec384, bytes, "")));
}

test "sec1: a short scalar is padded, a bare key needs its curve" {
    // ECPrivateKey { 1, OCTET STRING 01 } with no [0]: the curve must come from outside.
    const bare = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01 };
    try t.expectError(error.MalformedKey, kc.parseSec1(&bare, null));
    const k = try kc.parseSec1(&bare, .ec_p256);
    var s: [32]u8 = undefined;
    try k.scalarInto(&s);
    try t.expectEqual(@as(u8, 1), s[31]);
    try t.expectEqual(@as(u8, 0), s[0]);
    try t.expectError(error.MalformedKey, k.scalarInto(s[0..31]));
    // Written back, the scalar takes the order's full length (RFC 5915 §3).
    var out: [128]u8 = undefined;
    const w = try kc.writeSec1(&out, k);
    const back = try kc.parseSec1(w, null);
    try t.expectEqual(@as(usize, 32), back.secret.len);
    // Version 0 is not an ECPrivateKey.
    const v0 = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x04, 0x01, 0x01 };
    try t.expectError(error.MalformedKey, kc.parseSec1(&v0, .ec_p256));
}

test "pq: the three forms, lengths and tags" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    const c = caseNamed("ml_kem_512-both");
    const bytes = try derOf(c, &buf);
    const k = try kc.parsePkcs8(bytes);
    var out: [kc.max_private_der_len]u8 = undefined;
    // Each form rebuilt from the `both` parts parses back as that form.
    for ([_]kc.PqForm{ .seed, .expanded, .both }) |f| {
        var k2 = k;
        k2.pq_form = f;
        switch (f) {
            .seed => k2.expanded = &.{},
            .expanded => {
                k2.secret = k.expanded;
                k2.expanded = &.{};
            },
            .both => {},
        }
        const w = try kc.writePkcs8(&out, k2);
        const back = try kc.parsePkcs8(w);
        try t.expectEqual(f, back.pq_form.?);
        try t.expectEqualSlices(u8, k2.secret, back.secret);
    }
    // Inconsistent fields are refused by the writer.
    var bad = k;
    bad.pq_form = .seed; // with an expanded part still set
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, bad));
    bad = k;
    bad.secret = k.secret[0..32];
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, bad));
    bad = k;
    bad.pq_form = null;
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, bad));
    // A wrong seed length and an unknown CHOICE tag on the parse side.
    const alg = [_]u8{ 0x06, 0x09 } ++ kc.oid.ml_kem_512;
    var p: [66]u8 = @splat(1);
    p[0..2].* = .{ 0x80, 0x40 };
    _ = try kc.parsePkcs8(pkcs8(&out, 0, &alg, &p, ""));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, p[0..65], "")));
    p[0] = 0x81;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, &p, "")));
}

test "writers refuse fields that do not fit the algorithm" {
    var out: [512]u8 = undefined;
    const seven: [32]u8 = @splat(7);
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = seven[0..31] }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ed25519, .encoding = .sec1, .secret = &seven }));
    try t.expectError(error.MalformedKey, kc.writeSec1(&out, .{ .algorithm = .ed25519, .encoding = .sec1, .secret = &seven }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven, .parameters = &.{ 0x30, 0x00 } }));
    const zero: [32]u8 = @splat(0);
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ec_p256, .encoding = .pkcs8, .secret = &zero }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ec_p256, .encoding = .pkcs8, .secret = &seven, .public = &seven }));
    try t.expectError(error.MalformedKey, kc.writePrivateKeyDer(&out, .{ .algorithm = .ec_p256, .encoding = .pkcs1, .secret = &seven }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .rsa, .encoding = .pkcs8, .secret = &seven }));
    try t.expectError(error.NoSpaceLeft, kc.writePkcs8(out[0..10], .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&out, .{ .algorithm = .ed25519, .key = seven[0..31] }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&out, .{ .algorithm = .ec_p256, .key = &seven }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&out, .{ .algorithm = .rsa, .key = &seven }));
    try t.expectError(error.NoSpaceLeft, kc.writePrivateKeyPem(out[0..20], .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven }));
}

test "spki: refusals" {
    var buf: [kc.max_public_der_len]u8 = undefined;
    const c = caseNamed("ec_p256-pkcs8");
    const bytes = (try kc.pem.find(c.spki_pem, "PUBLIC KEY")).?.decode(&buf) catch unreachable;
    _ = try kc.parseSpki(bytes);
    var m: [128]u8 = undefined;
    @memcpy(m[0..bytes.len], bytes);
    m[bytes.len - 65] = 0x05; // not a SEC1 point prefix
    try t.expectError(error.MalformedKey, kc.parseSpki(m[0..bytes.len]));
    // A compressed point is accepted.
    var point: [33]u8 = @splat(1);
    point[0] = 0x02;
    const spki = try kc.writeSpki(&m, .{ .algorithm = .ec_p256, .key = &point });
    try t.expectEqualSlices(u8, &point, (try kc.parseSpki(spki)).key);
    // Trailing bytes after the SPKI.
    var trailing: [128]u8 = undefined;
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try t.expectError(error.MalformedKey, kc.parseSpki(trailing[0 .. bytes.len + 1]));
}

test "no prefix of any vector parses, and no mutation panics" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    var m: [kc.max_private_der_len]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x6b6579636f646563);
    const r = prng.random();
    for (vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const bytes = try derOf(c, &buf);
        // Every proper prefix is an error (the outer length no longer fits).
        var n: usize = 0;
        while (n < bytes.len) : (n += if (bytes.len > 600) 7 else 1) {
            try t.expect(std.meta.isError(kc.parsePrivateKeyDer(bytes[0..n])));
        }
        // Random byte mutations: any result but a panic.
        for (0..200) |_| {
            @memcpy(m[0..bytes.len], bytes);
            const flips = r.intRangeAtMost(usize, 1, 4);
            for (0..flips) |_| m[r.uintLessThan(usize, bytes.len)] = r.int(u8);
            const len = if (r.boolean()) bytes.len else r.uintLessThan(usize, bytes.len + 1);
            if (kc.parsePrivateKeyDer(m[0..len])) |k| {
                // Whatever parsed must be writable back, or refused cleanly.
                var out: [kc.max_private_der_len]u8 = undefined;
                _ = kc.writePrivateKeyDer(&out, k) catch {};
            } else |_| {}
            _ = kc.parseSpki(m[0..len]) catch {};
        }
    }
}
