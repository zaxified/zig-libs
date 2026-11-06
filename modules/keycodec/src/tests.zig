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
            var siblings: usize = 0;
            for (vectors.cases) |c2| if (std.mem.eql(u8, c2.algorithm, c.algorithm) and !std.mem.eql(u8, c2.encoding, c.encoding)) {
                try t.expectEqualStrings(c2.pem, pem2);
                siblings += 1;
            };
            try t.expectEqual(@as(usize, 1), siblings); // every EC vector has its other form
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
    const attrs = [_]u8{ 0xa0, 0x07, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x31, 0x00 }; // one Attribute { 1.2, {} }
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
    // No curve at all: falls back to the inner [0], which this inner key lacks.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ec, &priv, "")));
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

// ── review 2026-11-05 ───────────────────────────────────────────────────────

/// A bare SEC1 key `{ 1, OCTET STRING raw }` (no [0], no [1]).
fn bareSec1(out: []u8, raw: []const u8) []u8 {
    const der = kc.der;
    var w = der.Writer.init(out);
    w.header(0x30, der.tlvLen(1) + der.tlvLen(raw.len));
    w.tlv(0x02, &.{1});
    w.tlv(0x04, raw);
    return w.finish() catch unreachable;
}

test "scalar range on every curve: n, n - 1, a short scalar, a long one" {
    var buf: [128]u8 = undefined;
    var s: [67]u8 = undefined;
    for ([_]kc.Algorithm{ .ec_p256, .ec_p384, .ec_p521, .ec_secp256k1 }) |a| {
        errdefer std.debug.print("curve {s}\n", .{@tagName(a)});
        const n = a.order().?;
        try t.expectEqual(a.secretLen().?, n.len);
        @memcpy(s[0..n.len], n);
        try t.expectError(error.MalformedKey, kc.parseSec1(bareSec1(&buf, s[0..n.len]), a));
        s[n.len - 1] -= 1; // n - 1 (no order ends in a zero byte)
        _ = try kc.parseSec1(bareSec1(&buf, s[0..n.len]), a);
        // One byte shorter than the order, all ones: below n, padded on read.
        @memset(s[0 .. n.len - 1], 0xff);
        const k = try kc.parseSec1(bareSec1(&buf, s[0 .. n.len - 1]), a);
        var padded: [66]u8 = undefined;
        try k.scalarInto(padded[0..n.len]);
        try t.expectEqual(@as(u8, 0), padded[0]);
        // Longer than the order: refused before any comparison.
        @memset(s[0 .. n.len + 1], 0);
        s[n.len] = 1;
        try t.expectError(error.MalformedKey, kc.parseSec1(bareSec1(&buf, s[0 .. n.len + 1]), a));
    }
    // P-521: its order's top byte is 0x01, so 0x02 at the top is out of range.
    var p521: [66]u8 = @splat(0);
    p521[0] = 0x02;
    try t.expectError(error.MalformedKey, kc.parseSec1(bareSec1(&buf, &p521), .ec_p521));
    p521[0] = 0x01;
    _ = try kc.parseSec1(bareSec1(&buf, &p521), .ec_p521);
}

/// The eight INTEGERs of the vectors' RSA key, rebuilt as an RSAPrivateKey
/// with `version` and an optional raw `otherPrimeInfos` TLV.
fn rebuildPkcs1(out: []u8, version: u8, others: []const u8, empty_int: bool) ![]u8 {
    var dbuf: [kc.max_private_der_len]u8 = undefined;
    const bytes = try derOf(caseNamed("rsa-pkcs1"), &dbuf);
    var r = kc.der.Reader.init(bytes);
    var seq = try r.sub(0x30);
    _ = try seq.expect(0x02);
    var ints: [8][]const u8 = undefined;
    for (&ints) |*i| i.* = try seq.expect(0x02);
    if (empty_int) ints[2] = &.{};
    var len: usize = kc.der.tlvLen(1) + others.len;
    for (ints) |i| len += kc.der.tlvLen(i.len);
    var w = kc.der.Writer.init(out);
    w.header(0x30, len);
    w.tlv(0x02, &.{version});
    for (ints) |i| w.tlv(0x02, i);
    w.bytes(others);
    return w.finish();
}

test "pkcs1: version decides otherPrimeInfos, INTEGERs are never empty" {
    var out: [kc.max_private_der_len]u8 = undefined;
    _ = try kc.parsePkcs1(try rebuildPkcs1(&out, 0, "", false));
    const others = [_]u8{ 0x30, 0x02, 0x30, 0x00 };
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&out, 0, &others, false)));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&out, 1, "", false)));
    _ = try kc.parsePkcs1(try rebuildPkcs1(&out, 1, &others, false));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&out, 1, &.{ 0x30, 0x00 }, false)));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&out, 0, "", true)));
    try t.expectError(error.MalformedKey, kc.parsePkcs1Public(&.{ 0x30, 0x04, 0x02, 0x00, 0x02, 0x00 }));
}

test "pkcs8: attributes must be Attribute SEQUENCEs; an RSA v2 public key is checked and written" {
    var buf: [kc.max_private_der_len]u8 = undefined;
    const priv = edPrivate();
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, &priv, &.{ 0xa0, 0x01, 0xff })));
    const good_attr = [_]u8{ 0xa0, 0x07, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x31, 0x00 };
    _ = try kc.parsePkcs8(pkcs8(&buf, 0, &ed_alg, &priv, &good_attr));

    var rsa_der_buf: [kc.max_private_der_len]u8 = undefined;
    const rsa_der = try derOf(caseNamed("rsa-pkcs1"), &rsa_der_buf);
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    const pk = try kc.parsePublicKeyPem(caseNamed("rsa-pkcs1").spki_pem, &pub_buf);
    const rsa_alg = [_]u8{ 0x06, 0x09 } ++ kc.oid.rsa_encryption ++ [_]u8{ 0x05, 0x00 };
    // Junk as the v2 public key: refused.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &rsa_alg, rsa_der, &.{ 0x81, 0x03, 0x00, 0x41, 0x41 })));
    // The real RSAPublicKey: read, and written back to the same bytes.
    var field: [kc.max_public_der_len]u8 = undefined;
    var fw = kc.der.Writer.init(&field);
    fw.header(0x81, 1 + pk.key.len);
    fw.byte(0);
    fw.bytes(pk.key);
    const v2 = pkcs8(&buf, 1, &rsa_alg, rsa_der, try fw.finish());
    const k = try kc.parsePkcs8(v2);
    try t.expectEqualSlices(u8, pk.key, k.public.?);
    var out: [kc.max_private_der_len]u8 = undefined;
    try t.expectEqualSlices(u8, v2, try kc.writePkcs8(&out, k));
    // PKCS#1 carries no public key.
    var as_pkcs1 = k;
    as_pkcs1.encoding = .pkcs1;
    try t.expectError(error.MalformedKey, kc.writePrivateKeyDer(&out, as_pkcs1));
}

test "pkcs8: EC without a curve in the AlgorithmIdentifier takes the inner [0] (Go's fallback)" {
    var dbuf: [256]u8 = undefined;
    const sec1 = try derOf(caseNamed("ec_p384-sec1"), &dbuf); // has [0]
    const ec_only = [_]u8{ 0x06, 0x07 } ++ kc.oid.ec_public_key;
    var buf: [512]u8 = undefined;
    const k = try kc.parsePkcs8(pkcs8(&buf, 0, &ec_only, sec1, ""));
    try t.expectEqual(kc.Algorithm.ec_p384, k.algorithm);
    // Without [0] either, there is no curve.
    const bare = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &ec_only, &bare, "")));
}

test "writers: a failed write leaves no secret behind; pkcs1 checks its fields" {
    // ML-KEM `both`: the seed fits, the expanded key does not -- the seed
    // already written must not stay in `out`.
    var kbuf: [kc.max_private_der_len]u8 = undefined;
    const mk = try kc.parsePkcs8(try derOf(caseNamed("ml_kem_512-both"), &kbuf));
    var out: [200]u8 = @splat(0xee);
    try t.expectError(error.NoSpaceLeft, kc.writePkcs8(&out, mk));
    try t.expect(std.mem.indexOf(u8, &out, mk.secret[0..16]) == null);

    var dbuf: [kc.max_private_der_len]u8 = undefined;
    const k = try kc.parsePrivateKeyDer(try derOf(caseNamed("rsa-pkcs1"), &dbuf));
    var bad = k;
    bad.pq_form = .seed;
    var big: [kc.max_private_der_len]u8 = undefined;
    try t.expectError(error.MalformedKey, kc.writePrivateKeyDer(&big, bad));
    bad = k;
    bad.parameters = &.{ 0x30, 0x00 };
    try t.expectError(error.MalformedKey, kc.writePrivateKeyDer(&big, bad));
}

test "RSA PUBLIC KEY: written as OpenSSL's -RSAPublicKey_out, read back" {
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    var out: [kc.max_private_pem_len]u8 = undefined;
    var back_buf: [kc.max_public_der_len]u8 = undefined;
    for (vectors.cases) |c| if (std.mem.eql(u8, c.algorithm, "rsa")) {
        const pk = try kc.parsePublicKeyPem(c.spki_pem, &pub_buf);
        const text = try kc.writeRsaPublicKeyPem(&out, pk);
        try t.expect(std.mem.startsWith(u8, text, "-----BEGIN RSA PUBLIC KEY-----\n"));
        const back = try kc.parsePublicKeyPem(text, &back_buf);
        try t.expectEqualSlices(u8, pk.key, back.key);
        try expectHex(c.public, back.key); // OpenSSL's -RSAPublicKey_out DER
    };
    const ed: [32]u8 = @splat(1);
    try t.expectError(error.MalformedKey, kc.writeRsaPublicKeyPem(&out, .{ .algorithm = .ed25519, .key = &ed }));
}

// ── mutation run 2026-11-06 ─────────────────────────────────────────────────
// Each test below kills mutants the earlier tests let live (guards that the
// vectors never reach: trailing data at every nesting level, parameters where
// the RFCs forbid them, length checks per form, error mappings, limits).

/// One TLV of `tag` around `parts`, concatenated.
fn el(out: []u8, tag: u8, parts: []const []const u8) []u8 {
    var w = kc.der.Writer.init(out);
    var n: usize = 0;
    for (parts) |p| n += p.len;
    w.header(tag, n);
    for (parts) |p| w.bytes(p);
    return w.finish() catch unreachable;
}

fn cat(out: []u8, parts: []const []const u8) []u8 {
    var n: usize = 0;
    for (parts) |p| {
        @memcpy(out[n..][0..p.len], p);
        n += p.len;
    }
    return out[0..n];
}

/// A SubjectPublicKeyInfo around `alg_content` and `key`, with `extra` after the BIT STRING.
fn spkiOf(out: []u8, alg_content: []const u8, key: []const u8, extra: []const u8) []u8 {
    var w = kc.der.Writer.init(out);
    w.header(0x30, kc.der.tlvLen(alg_content.len) + kc.der.tlvLen(1 + key.len) + extra.len);
    w.tlv(0x30, alg_content);
    w.header(0x03, 1 + key.len);
    w.byte(0);
    w.bytes(key);
    w.bytes(extra);
    return w.finish() catch unreachable;
}

const ver1 = [_]u8{ 0x02, 0x01, 0x01 };
const null_tlv = [_]u8{ 0x05, 0x00 };
const ec256_alg = [_]u8{ 0x06, 0x07 } ++ kc.oid.ec_public_key ++ [_]u8{ 0x06, 0x08 } ++ kc.oid.prime256v1;
const rsa_alg_null = [_]u8{ 0x06, 0x09 } ++ kc.oid.rsa_encryption ++ null_tlv;
const pss_oid = [_]u8{ 0x06, 0x09 } ++ kc.oid.rsassa_pss;

/// An ECPrivateKey `{ 1, OCTET STRING 01, extra }`.
fn ecKey(out: []u8, extra: []const u8) []u8 {
    return el(out, 0x30, &.{ &ver1, &.{ 0x04, 0x01, 0x01 }, extra });
}

test "der: indefinite and short long-form lengths, 16 MiB lengths, exact-fit writer, header limit" {
    // 0x80 is the indefinite form even when enough bytes follow.
    var ind: [2 + 128]u8 = @splat(0);
    ind[0..2].* = .{ 0x04, 0x80 };
    var r = kc.der.Reader.init(&ind);
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // The long form for 0x7f is not minimal.
    var l7: [3 + 127]u8 = @splat(0);
    l7[0..3].* = .{ 0x04, 0x81, 0x7f };
    r = kc.der.Reader.init(&l7);
    try t.expectError(error.MalformedKey, r.expect(0x04));
    // A four-octet length is refused even when the 16 MiB are there.
    const big = try t.allocator.alloc(u8, 6 + 0x1000000);
    defer t.allocator.free(big);
    @memset(big, 0);
    big[0..6].* = .{ 0x04, 0x84, 0x01, 0x00, 0x00, 0x00 };
    r = kc.der.Reader.init(big);
    try t.expectError(error.MalformedKey, r.expect(0x04));

    // A buffer of exactly the right size takes the write.
    var exact: [4]u8 = undefined;
    var w = kc.der.Writer.init(&exact);
    w.tlv(0x04, &.{ 1, 2 });
    try t.expectEqual(@as(usize, 4), (try w.finish()).len);
    // Overflow is sticky: a later write that would fit still writes nothing.
    var small: [3]u8 = @splat(0xaa);
    w = kc.der.Writer.init(&small);
    w.tlv(0x04, &.{ 1, 2 });
    w.byte(0);
    try t.expectError(error.NoSpaceLeft, w.finish());
    try t.expectEqual(@as(u8, 0xaa), small[2]);
    // The header limit is 0xffffff: three length octets.
    var hb: [8]u8 = undefined;
    w = kc.der.Writer.init(&hb);
    w.header(0x04, 0xffffff);
    try t.expectEqualSlices(u8, &.{ 0x04, 0x83, 0xff, 0xff, 0xff }, try w.finish());
    w = kc.der.Writer.init(&hb);
    w.header(0x04, 0x1000000);
    try t.expectError(error.NoSpaceLeft, w.finish());
    // `tlv` writes the header and then the content.
    w = kc.der.Writer.init(&hb);
    w.tlv(0x04, &.{ 7, 8 });
    try t.expectEqualSlices(u8, &.{ 0x04, 0x02, 7, 8 }, try w.finish());
}

test "pem: exact bodies, blanks on the BEGIN line, CRLF headers, positions, label limit" {
    for ([_][]const u8{
        "-----BEGIN K-----\nAAEC\n-----END K-----\n",
        "-----BEGIN K-----  \nAAEC\n-----END K-----\n",
        "-----BEGIN K-----\t\nAAEC\n-----END K-----\n",
        "-----BEGIN K----- \t\r\nAAEC\n-----END K-----\n",
    }) |text| {
        const b = (try kc.pem.find(text, "K")).?;
        try t.expectEqualStrings("AAEC\n", b.body);
        try t.expectEqualStrings("", b.headers);
    }
    // CRLF line ends in the headers: the blank line is "\r".
    const crlf = "-----BEGIN K-----\r\nProc-Type: 4,ENCRYPTED\r\nDEK-Info: AES-128-CBC,00\r\n\r\nAAEC\r\n-----END K-----\r\n";
    const c = (try kc.pem.find(crlf, "K")).?;
    try t.expect(c.isEncrypted());
    try t.expectEqualStrings("Proc-Type: 4,ENCRYPTED\r\nDEK-Info: AES-128-CBC,00\r\n\r\n", c.headers);
    try t.expectEqualStrings("AAEC\r\n", c.body);
    // Headers that are not a legacy encryption.
    const mic = (try kc.pem.find("-----BEGIN K-----\nProc-Type: 4,MIC-ONLY\n\nAAEC\n-----END K-----\n", "K")).?;
    try t.expect(!mic.isEncrypted());
    try t.expect(mic.headers.len != 0);
    const dek = (try kc.pem.find("-----BEGIN K-----\nDEK-Info: AES,ENCRYPTED\n\nAAEC\n-----END K-----\n", "K")).?;
    try t.expect(!dek.isEncrypted());
    // decodedLenBound really bounds the decode.
    var buf: [kc.max_private_der_len]u8 = undefined;
    const big = (try kc.pem.find(caseNamed("ml_kem_512-both").pem, "PRIVATE KEY")).?;
    const n = big.decodedLenBound();
    try t.expect(n <= buf.len);
    _ = try big.decode(buf[0..n]);
    // `pos` stands just after the END marker of the last block, and at the end after the last.
    const text = "-----BEGIN K-----\nAAEC\n-----END K-----\nTAIL";
    var it: kc.pem.Iterator = .init(text);
    _ = (try it.next()).?;
    try t.expectEqual(std.mem.indexOf(u8, text, "\nTAIL").?, it.pos);
    try t.expectEqual(@as(?kc.pem.Block, null), try it.next());
    try t.expectEqual(text.len, it.pos);
    var it2: kc.pem.Iterator = .init("-----BEGIN X");
    try t.expectEqual(@as(?kc.pem.Block, null), try it2.next());
    try t.expectEqual(@as(usize, 12), it2.pos);
    // A BEGIN whose label is not closed by five dashes is skipped.
    const stray = (try kc.pem.find("-----BEGIN A-x\n-----BEGIN K-----\nAAEC\n-----END K-----\n", "K")).?;
    try t.expectEqualStrings("AAEC\n", stray.body);
    // An END line that is not "-----END " is refused even if the label follows at the right offset.
    var bad: kc.pem.Iterator = .init("-----BEGIN K-----\nAAEC\n-23456789K-----\n");
    try t.expectError(error.InvalidPem, bad.next());
    // Label length: 64 reads, 65 is skipped like any stray BEGIN line.
    const l64_arr: [64]u8 = @splat('L');
    const l65_arr: [65]u8 = @splat('L');
    const l64: []const u8 = &l64_arr;
    const l65: []const u8 = &l65_arr;
    var tb: [300]u8 = undefined;
    const t64 = try std.fmt.bufPrint(&tb, "-----BEGIN {s}-----\nAAEC\n-----END {s}-----\n", .{ l64, l64 });
    try t.expect((try kc.pem.find(t64, l64)) != null);
    const t65 = try std.fmt.bufPrint(&tb, "-----BEGIN {s}-----\nAAEC\n-----END {s}-----\n", .{ l65, l65 });
    try t.expectEqual(@as(?kc.pem.Block, null), try kc.pem.find(t65, l65));
    // encode: the same limit, and sizes that agree with encodedLen for every length.
    var out: [512]u8 = undefined;
    _ = try kc.pem.encode(&out, l64, "abc");
    try t.expectError(error.InvalidPem, kc.pem.encode(&out, l65, "abc"));
    try t.expectError(error.InvalidPem, kc.pem.encode(&out, "A-B", "abc"));
    var der: [200]u8 = undefined;
    for (&der, 0..) |*d, i| d.* = @intCast(i);
    for (1..201) |len| {
        const total = kc.pem.encodedLen("K", len);
        const pem = try kc.pem.encode(out[0..total], "K", der[0..len]);
        try t.expectEqual(total, pem.len);
        try t.expectError(error.NoSpaceLeft, kc.pem.encode(out[0 .. total - 1], "K", der[0..len]));
    }
}

test "orders: secp256k1 and P-256 are pinned to their published values" {
    var hex: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hex, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    try t.expectEqualSlices(u8, &hex, kc.Algorithm.ec_secp256k1.order().?);
    _ = try std.fmt.hexToBytes(&hex, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    try t.expectEqualSlices(u8, &hex, kc.Algorithm.ec_p256.order().?);
}

test "scalarInto refuses what it cannot pad" {
    var out: [32]u8 = undefined;
    const ed: kc.PrivateKey = .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &out };
    try t.expectError(error.MalformedKey, ed.scalarInto(&out));
    const empty: kc.PrivateKey = .{ .algorithm = .ec_p256, .encoding = .sec1, .secret = &.{} };
    try t.expectError(error.MalformedKey, empty.scalarInto(&out));
    const long_secret: [33]u8 = @splat(1);
    const long: kc.PrivateKey = .{ .algorithm = .ec_p256, .encoding = .sec1, .secret = &long_secret };
    try t.expectError(error.MalformedKey, long.scalarInto(&out));
    const one: kc.PrivateKey = .{ .algorithm = .ec_p256, .encoding = .sec1, .secret = &.{ 1, 2 } };
    try one.scalarInto(&out);
    try t.expectEqual(@as(u8, 2), out[31]);
    try t.expectEqual(@as(u8, 1), out[30]);
    try t.expectEqual(@as(u8, 0), out[29]);
}

test "pkcs8 and sec1: trailing data, EC parameters, public keys at every level" {
    var buf: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    var b3: [512]u8 = undefined;
    var b4: [512]u8 = undefined;
    const priv = edPrivate();
    // Trailing byte after the outer SEQUENCE.
    const good = pkcs8(&buf, 0, &ed_alg, &priv, "");
    const trailed = cat(&b2, &.{ good, &.{0} });
    try t.expectError(error.MalformedKey, kc.parsePkcs8(trailed));

    var dbuf: [256]u8 = undefined;
    const sec1 = try derOf(caseNamed("ec_p256-sec1"), &dbuf); // has [0] and [1]
    const bare = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x01 };
    var pt: [65]u8 = @splat(0x11);
    pt[0] = 0x04;
    // The AlgorithmIdentifier names the curve and then something else.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 0, &(ec256_alg ++ null_tlv), sec1, "")));
    // A v2 outer public key on an EC key: read, shape-checked, and not allowed twice.
    var pubf: [68]u8 = undefined;
    pubf[0..3].* = .{ 0x81, 0x42, 0x00 };
    @memcpy(pubf[3..], &pt);
    const k = try kc.parsePkcs8(pkcs8(&buf, 1, &ec256_alg, &bare, &pubf));
    try t.expectEqualSlices(u8, &pt, k.public.?);
    try t.expectEqual(kc.Algorithm.ec_p256, k.algorithm);
    var pbad = pubf;
    pbad[3] = 0x05;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &ec256_alg, &bare, &pbad)));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&buf, 1, &ec256_alg, sec1, &pubf)));

    // SEC1 [0]: explicit parameters, an unknown curve, trailing data; [1] with trailing data; trailing key data.
    try t.expectError(error.UnsupportedAlgorithm, kc.parseSec1(ecKey(&buf, &.{ 0xa0, 0x02, 0x30, 0x00 }), .ec_p256));
    const brainpool = [_]u8{ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    try t.expectError(error.UnsupportedAlgorithm, kc.parseSec1(ecKey(&buf, el(&b2, 0xa0, &.{&brainpool})), .ec_p256));
    const p256_oid = [_]u8{ 0x06, 0x08 } ++ kc.oid.prime256v1;
    _ = try kc.parseSec1(ecKey(&buf, el(&b2, 0xa0, &.{&p256_oid})), null);
    try t.expectError(error.MalformedKey, kc.parseSec1(ecKey(&buf, el(&b2, 0xa0, &.{ &p256_oid, &null_tlv })), null));
    const bits = el(&b2, 0x03, &.{ &.{0}, &pt });
    const tag1_ok = el(&b3, 0xa1, &.{bits});
    _ = try kc.parseSec1(ecKey(&buf, tag1_ok), .ec_p256);
    const tag1_extra = el(&b4, 0xa1, &.{ bits, &null_tlv });
    try t.expectError(error.MalformedKey, kc.parseSec1(ecKey(&buf, tag1_extra), .ec_p256));
    // A trailing element after the key's SEQUENCE, and one inside it after [1].
    const key_ok = ecKey(&buf, tag1_ok);
    try t.expectError(error.MalformedKey, kc.parseSec1(cat(&b4, &.{ key_ok, &null_tlv }), .ec_p256));
    const inside = ecKey(&b4, cat(&b2, &.{ tag1_ok, &null_tlv }));
    try t.expectError(error.MalformedKey, kc.parseSec1(inside, .ec_p256));
    // A bare key with a context that is no EC curve.
    try t.expectError(error.MalformedKey, kc.parseSec1(&bare, .ed25519));
}

test "pkcs8: Ed/X and ML lengths and trailing data" {
    var out: [4096]u8 = undefined;
    var m: [2200]u8 = undefined;
    // CurvePrivateKey: trailing data in it, and one octet too many.
    var p35: [35]u8 = @splat(7);
    p35[0..2].* = .{ 0x04, 0x20 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &ed_alg, &p35, "")));
    var p35b: [35]u8 = @splat(7);
    p35b[0..2].* = .{ 0x04, 0x21 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &ed_alg, &p35b, "")));
    // v2 public key of the wrong length.
    const priv = edPrivate();
    var short_pub: [34]u8 = @splat(9);
    short_pub[0..3].* = .{ 0x81, 0x1f, 0x00 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 1, &ed_alg, &priv, short_pub[0..33])));

    var kbuf: [kc.max_private_der_len]u8 = undefined;
    const mk = try kc.parsePkcs8(try derOf(caseNamed("ml_kem_512-both"), &kbuf));
    const alg = [_]u8{ 0x06, 0x09 } ++ kc.oid.ml_kem_512;
    var seed: [67]u8 = @splat(1);
    seed[0] = 0x80;
    seed[1] = 64;
    _ = try kc.parsePkcs8(pkcs8(&out, 0, &alg, seed[0..66], ""));
    // seed [0] of 63 and 65 octets; expandedKey of 64.
    seed[1] = 63;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, seed[0..65], "")));
    seed[1] = 65;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, seed[0..67], "")));
    seed[1] = 64;
    var small_exp: [66]u8 = @splat(1);
    small_exp[0..2].* = .{ 0x04, 64 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, &small_exp, "")));
    // Trailing data after the CHOICE, parameters on the AlgorithmIdentifier, a v2 public key of the wrong length.
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, cat(&m, &.{ seed[0..66], &.{0} }), "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &(alg ++ null_tlv), seed[0..66], "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 1, &alg, seed[0..66], &.{ 0x81, 0x03, 0x00, 0xaa, 0xbb })));
    // `both`: wrong seed, wrong expanded key, a third element.
    var s64: [66]u8 = @splat(1);
    s64[0..2].* = .{ 0x04, 0x40 };
    var s63: [65]u8 = @splat(1);
    s63[0..2].* = .{ 0x04, 0x3f };
    var tmp: [1700]u8 = undefined;
    var tmp2: [1700]u8 = undefined;
    const exp_ok = el(&tmp, 0x04, &.{mk.expanded});
    const exp_short = el(&tmp2, 0x04, &.{mk.expanded[0..1631]});
    var big: [2200]u8 = undefined;
    const both_ok = el(&big, 0x30, &.{ &s64, exp_ok });
    const parsed = try kc.parsePkcs8(pkcs8(&out, 0, &alg, both_ok, ""));
    try t.expectEqual(kc.PqForm.both, parsed.pq_form.?);
    var big2: [2200]u8 = undefined;
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, el(&big2, 0x30, &.{ &s64, exp_short }), "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, el(&big2, 0x30, &.{ &s63, exp_ok }), "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &alg, el(&big2, 0x30, &.{ &s64, exp_ok, &.{ 0x04, 0x00 } }), "")));
    // The three CHOICE tags are told apart.
    try t.expectEqual(kc.PqForm.seed, (try kc.parsePkcs8(pkcs8(&out, 0, &alg, seed[0..66], ""))).pq_form.?);
}

test "rsa and pss: parameters, PKCS#1 shape, attributes, SPKI refusals" {
    var dbuf: [kc.max_private_der_len]u8 = undefined;
    const rsa_der = try derOf(caseNamed("rsa-pkcs1"), &dbuf);
    var out: [kc.max_private_der_len]u8 = undefined;
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    const pk = try kc.parsePublicKeyPem(caseNamed("rsa-pkcs1").spki_pem, &pub_buf);
    const oid_rsa = [_]u8{ 0x06, 0x09 } ++ kc.oid.rsa_encryption;
    // rsaEncryption parameters: NULL with content, a SEQUENCE, two NULLs.
    _ = try kc.parsePkcs8(pkcs8(&out, 0, &rsa_alg_null, rsa_der, ""));
    _ = try kc.parsePkcs8(pkcs8(&out, 0, &oid_rsa, rsa_der, ""));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &(oid_rsa ++ [_]u8{ 0x05, 0x01, 0x00 }), rsa_der, "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &(oid_rsa ++ [_]u8{ 0x30, 0x00 }), rsa_der, "")));
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &(oid_rsa ++ null_tlv ++ null_tlv), rsa_der, "")));
    // PSS parameters: one SEQUENCE, kept; a second element is refused.
    var o2: [kc.max_private_der_len]u8 = undefined;
    const pss_ok = pss_oid ++ [_]u8{ 0x30, 0x00 };
    const kp = try kc.parsePkcs8(pkcs8(&out, 0, &pss_ok, rsa_der, ""));
    try t.expectEqualSlices(u8, &.{ 0x30, 0x00 }, kp.parameters);
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &(pss_ok ++ null_tlv), rsa_der, "")));
    // The same on the SPKI side, and the key inside it is checked.
    var s: [kc.max_public_der_len]u8 = undefined;
    const spki_ok = spkiOf(&s, &rsa_alg_null, pk.key, "");
    _ = try kc.parseSpki(spki_ok);
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(oid_rsa ++ [_]u8{ 0x05, 0x01, 0x00 }), pk.key, "")));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(oid_rsa ++ null_tlv ++ null_tlv), pk.key, "")));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(oid_rsa ++ [_]u8{ 0x30, 0x00 }), pk.key, "")));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &rsa_alg_null, "junk", "")));
    const spki_pss = try kc.parseSpki(spkiOf(&s, &pss_ok, pk.key, ""));
    try t.expectEqualSlices(u8, &.{ 0x30, 0x00 }, spki_pss.parameters);
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(pss_ok ++ null_tlv), pk.key, "")));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &pss_ok, "junk", "")));
    // Other SPKI refusals: trailing element, no parameters on EC, an unknown curve or algorithm, extra
    // parameters, a wrong key length, an empty BIT STRING.
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &rsa_alg_null, pk.key, &null_tlv)));
    var pt: [65]u8 = @splat(0x11);
    pt[0] = 0x04;
    const ec_only = [_]u8{ 0x06, 0x07 } ++ kc.oid.ec_public_key;
    try t.expectError(error.UnsupportedAlgorithm, kc.parseSpki(spkiOf(&s, &ec_only, &pt, "")));
    const brainpool = [_]u8{ 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
    try t.expectError(error.UnsupportedAlgorithm, kc.parseSpki(spkiOf(&s, &(ec_only ++ brainpool), &pt, "")));
    _ = try kc.parseSpki(spkiOf(&s, &ec256_alg, &pt, ""));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(ec256_alg ++ null_tlv), &pt, "")));
    const dsa = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
    try t.expectError(error.UnsupportedAlgorithm, kc.parseSpki(spkiOf(&s, &dsa, &pt, "")));
    const ed_oid = [_]u8{ 0x06, 0x03 } ++ kc.oid.ed25519;
    const key32: [32]u8 = @splat(5);
    _ = try kc.parseSpki(spkiOf(&s, &ed_oid, &key32, ""));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &(ed_oid ++ null_tlv), &key32, "")));
    try t.expectError(error.MalformedKey, kc.parseSpki(spkiOf(&s, &ed_oid, key32[0..31], "")));
    const empty_bits = [_]u8{ 0x30, 0x09, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x00 };
    try t.expectError(error.MalformedKey, kc.parseSpki(&empty_bits));

    // PKCS#1: trailing data, a ninth INTEGER, version 2, multi-prime entries that are no SEQUENCE.
    const trailed = cat(&out, &.{ rsa_der, &.{0} });
    try t.expectError(error.MalformedKey, kc.parsePkcs1(trailed));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&o2, 0, &.{ 0x02, 0x01, 0x01 }, false)));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&o2, 2, "", false)));
    try t.expectError(error.MalformedKey, kc.parsePkcs1(try rebuildPkcs1(&o2, 1, &.{ 0x30, 0x03, 0x02, 0x01, 0x01 }, false)));
    const pub_trailed = cat(&out, &.{ pk.key, &.{0} });
    try t.expectError(error.MalformedKey, kc.parsePkcs1Public(pub_trailed));
    const three = [_]u8{ 0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    try t.expectError(error.MalformedKey, kc.parsePkcs1Public(&three));
    // An Attribute is { OID, SET } and nothing more.
    const priv = edPrivate();
    const attr_extra = [_]u8{ 0xa0, 0x09, 0x30, 0x07, 0x06, 0x01, 0x2a, 0x31, 0x00, 0x05, 0x00 };
    try t.expectError(error.MalformedKey, kc.parsePkcs8(pkcs8(&out, 0, &ed_alg, &priv, &attr_extra)));
}

/// A well-formed PKCS#1 RSAPrivateKey DER of exactly `total` bytes (total > 300).
fn bigPkcs1(out: []u8, total: usize) []u8 {
    const m = total - 32; // content = 3 (version) + 4 + m (modulus) + 7 * 3
    var w = kc.der.Writer.init(out);
    w.header(0x30, total - 4);
    w.tlv(0x02, &.{0});
    w.header(0x02, m);
    for (0..m) |_| w.byte(1);
    for (0..7) |_| w.tlv(0x02, &.{1});
    return w.finish() catch unreachable;
}

test "writers: every field check, error mappings, the RSA size limit" {
    var out: [kc.max_private_der_len + 1024]u8 = undefined;
    var dbuf: [kc.max_private_der_len]u8 = undefined;
    const rsa_der = try derOf(caseNamed("rsa-pkcs1"), &dbuf);
    const seven: [32]u8 = @splat(7);
    // writeSec1 is for EC keys whatever the key's own encoding says.
    try t.expectError(error.MalformedKey, kc.writeSec1(&out, .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven }));
    // Non-PQ keys carry no expanded part; EC scalars are at most the order's length; public keys fit.
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven, .expanded = &seven }));
    const long: [33]u8 = @splat(1);
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ec_p256, .encoding = .pkcs8, .secret = &long }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .ed25519, .encoding = .pkcs8, .secret = &seven, .public = seven[0..31] }));
    // RSA: a bad v2 public key, bad PSS parameters.
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .rsa, .encoding = .pkcs8, .secret = rsa_der, .public = "junk" }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .rsa_pss, .encoding = .pkcs8, .secret = rsa_der, .parameters = &.{ 0x31, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = .rsa_pss, .encoding = .pkcs8, .secret = rsa_der, .parameters = &.{ 0x30, 0x00, 0x05, 0x00 } }));
    _ = try kc.writePkcs8(&out, .{ .algorithm = .rsa_pss, .encoding = .pkcs8, .secret = rsa_der, .parameters = &.{ 0x30, 0x00 } });
    // PQ forms: each row of the length checks, a missing form.
    var kbuf: [kc.max_private_der_len]u8 = undefined;
    const mk = try kc.parsePkcs8(try derOf(caseNamed("ml_kem_512-both"), &kbuf));
    const pq = kc.Algorithm.ml_kem_512;
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.secret, .pq_form = null }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.secret[0..63], .pq_form = .seed }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.expanded[0..1631], .pq_form = .expanded }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.expanded, .expanded = mk.expanded, .pq_form = .expanded }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.secret, .expanded = mk.expanded[0..100], .pq_form = .both }));
    try t.expectError(error.MalformedKey, kc.writePkcs8(&out, .{ .algorithm = pq, .encoding = .pkcs8, .secret = mk.secret, .pq_form = .seed, .public = "short" }));

    // The PKCS#1 writer: a short out is NoSpaceLeft, an exact one is enough.
    const k1: kc.PrivateKey = .{ .algorithm = .rsa, .encoding = .pkcs1, .secret = rsa_der };
    try t.expectError(error.NoSpaceLeft, kc.writePrivateKeyDer(out[0 .. rsa_der.len - 1], k1));
    try t.expectEqualSlices(u8, rsa_der, try kc.writePrivateKeyDer(out[0..rsa_der.len], k1));
    // The size limit of an RSA key: max_private_der_len - 64 is the last one admitted.
    var big1: [kc.max_private_der_len]u8 = undefined;
    const at_limit = bigPkcs1(&big1, kc.max_private_der_len - 64);
    _ = try kc.writePrivateKeyDer(&out, .{ .algorithm = .rsa, .encoding = .pkcs1, .secret = at_limit });
    var big2: [kc.max_private_der_len]u8 = undefined;
    const over = bigPkcs1(&big2, kc.max_private_der_len - 63);
    try t.expectError(error.MalformedKey, kc.writePrivateKeyDer(&out, .{ .algorithm = .rsa, .encoding = .pkcs1, .secret = over }));

    // A key that overflows the stack buffer of the PEM writer is MalformedKey (not NoSpaceLeft:
    // the caller's `out` is large enough); the DER writer takes it.
    var params: [kc.max_private_der_len + 100]u8 = undefined;
    const filler: [kc.max_private_der_len + 32]u8 = @splat(0);
    const huge_params = el(&params, 0x30, &.{filler[0 .. kc.max_private_der_len + 8]});
    var pem_out: [2 * kc.max_private_pem_len]u8 = undefined;
    const huge: kc.PrivateKey = .{ .algorithm = .rsa_pss, .encoding = .pkcs8, .secret = rsa_der, .parameters = huge_params };
    try t.expectError(error.MalformedKey, kc.writePrivateKeyPem(&pem_out, huge));
    var der_out: [2 * kc.max_private_der_len]u8 = undefined;
    _ = try kc.writePrivateKeyDer(&der_out, huge);

    // SPKI writer: parameters only on PSS, and well-formed ones; round trip keeps them.
    var pub_buf: [kc.max_public_der_len]u8 = undefined;
    const rpk = try kc.parsePublicKeyPem(caseNamed("rsa-pkcs1").spki_pem, &pub_buf);
    var sb: [kc.max_public_der_len]u8 = undefined;
    try t.expectError(error.MalformedKey, kc.writeSpki(&sb, .{ .algorithm = .ed25519, .key = &seven, .parameters = &.{ 0x30, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&sb, .{ .algorithm = .rsa, .key = rpk.key, .parameters = &.{ 0x30, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&sb, .{ .algorithm = .rsa_pss, .key = rpk.key, .parameters = &.{ 0x31, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&sb, .{ .algorithm = .rsa_pss, .key = rpk.key, .parameters = &.{ 0x30, 0x00, 0x05, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writeSpki(&sb, .{ .algorithm = .rsa, .key = "junk" }));
    const pss_spki = try kc.writeSpki(&sb, .{ .algorithm = .rsa_pss, .key = rpk.key, .parameters = &.{ 0x30, 0x00 } });
    try t.expectEqualSlices(u8, &.{ 0x30, 0x00 }, (try kc.parseSpki(pss_spki)).parameters);
    // RSA PUBLIC KEY: RSA only, no parameters, a well-formed key; NoSpaceLeft stays NoSpaceLeft.
    try t.expectError(error.MalformedKey, kc.writeRsaPublicKeyPem(&pem_out, .{ .algorithm = .rsa_pss, .key = rpk.key }));
    try t.expectError(error.MalformedKey, kc.writeRsaPublicKeyPem(&pem_out, .{ .algorithm = .rsa, .key = rpk.key, .parameters = &.{ 0x30, 0x00 } }));
    try t.expectError(error.MalformedKey, kc.writeRsaPublicKeyPem(&pem_out, .{ .algorithm = .rsa, .key = "junk" }));
    try t.expectError(error.NoSpaceLeft, kc.writeRsaPublicKeyPem(pem_out[0..10], rpk));
    try t.expectError(error.NoSpaceLeft, kc.writePublicKeyPem(pem_out[0..10], rpk));
    // An SPKI that does not fit the 4 KiB stack buffer is MalformedKey.
    var pp: [5000]u8 = undefined;
    const big_params = el(&pp, 0x30, &.{filler[0..4200]});
    try t.expectError(error.MalformedKey, kc.writePublicKeyPem(&pem_out, .{ .algorithm = .rsa_pss, .key = rpk.key, .parameters = big_params }));
}

test "parsePrivateKeyPem wipes the decoded part when the parse fails" {
    var dbuf: [kc.max_private_der_len]u8 = undefined;
    const good = try derOf(caseNamed("ed25519-pkcs8"), &dbuf);
    var bad: [128]u8 = undefined;
    @memcpy(bad[0..good.len], good);
    bad[good.len] = 0x77; // trailing byte: the parse fails after the decode
    var pem_buf: [512]u8 = undefined;
    const text = try kc.pem.encode(&pem_buf, "PRIVATE KEY", bad[0 .. good.len + 1]);
    var out: [128]u8 = @splat(0xee);
    try t.expectError(error.MalformedKey, kc.parsePrivateKeyPem(text, &out));
    for (out[0 .. good.len + 1]) |b| try t.expectEqual(@as(u8, 0), b);
    try t.expectEqual(@as(u8, 0xee), out[good.len + 1]);
}
