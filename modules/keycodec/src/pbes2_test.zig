// SPDX-License-Identifier: MIT

//! Encrypted PKCS#8 (PBES2) against `vectors_enc.zig` (OpenSSL 3.5.5 output,
//! `tools/vectors.py --encrypted`): every file decrypts to the key OpenSSL
//! wrote, and re-encrypting that key with the salt and IV found in the file
//! reproduces the file byte for byte -- which is also the proof that OpenSSL
//! reads what `encryptPkcs8` writes. Then the refusals: hostile parameters,
//! damaged ciphertext, option ranges, buffer sizes, wiping.

const std = @import("std");
const kc = @import("root.zig");
const pbes2 = kc.pbes2;
const vectors = @import("vectors.zig");
const enc_vectors = @import("vectors_enc.zig");
const t = std.testing;

/// scrypt memory for the largest fixture (N = 16384, r = 8, p = 1).
var work: [17 * 1024 * 1024]u8 = undefined;

const test_opts: kc.DecryptOptions = .{ .scrypt_work = &work };

/// A `std.Random` that hands out the bytes it was given, in order.
const FixedRandom = struct {
    data: []const u8,
    pos: usize = 0,

    fn fill(self: *FixedRandom, buf: []u8) void {
        @memcpy(buf, self.data[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }

    fn random(self: *FixedRandom) std.Random {
        return .init(self, fill);
    }
};

fn blockDer(pem_text: []const u8, label: []const u8, buf: []u8) ![]u8 {
    const b = (try kc.pem.find(pem_text, label)).?;
    return b.decode(buf);
}

fn allZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

test "every OpenSSL encrypted key: parameters, decryption, byte-exact re-encryption" {
    var enc_buf: [kc.max_encrypted_der_len]u8 = undefined;
    var plain_buf: [kc.max_private_der_len]u8 = undefined;
    var out: [kc.max_encrypted_der_len]u8 = undefined;
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    for (enc_vectors.cases) |c| {
        errdefer std.debug.print("case {s}\n", .{c.name});
        const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
        const plain = try blockDer(c.plain_pem, "PRIVATE KEY", &plain_buf);

        // The parameters OpenSSL was asked for.
        const info = try kc.parseEncryptedInfo(enc);
        try t.expectEqualStrings(c.cipher, @tagName(info.cipher));
        switch (info.kdf) {
            .pbkdf2 => |k| {
                try t.expectEqualStrings("pbkdf2", c.kdf);
                try t.expectEqualStrings(c.prf, @tagName(k.prf));
                try t.expectEqual(c.iterations, k.iterations);
            },
            .scrypt => |s| {
                try t.expectEqualStrings("scrypt", c.kdf);
                try t.expectEqual(c.n, @as(u64, 1) << s.log2_n);
                try t.expectEqual(c.r, s.r);
                try t.expectEqual(c.p, s.p);
            },
        }
        try t.expectEqual(@as(usize, 16), info.salt.len);

        // Decryption gives OpenSSL's own plaintext, through every entry point.
        @memset(&dec, 0);
        const pt = try kc.decryptPkcs8(enc, c.password, &dec, test_opts);
        try t.expectEqualSlices(u8, plain, pt);
        try t.expect(allZero(dec[pt.len..])); // the padding is wiped
        std.crypto.secureZero(u8, &dec);
        const k = try kc.parseEncryptedPkcs8(enc, c.password, &dec, test_opts);
        const want = try kc.parsePkcs8(plain);
        try t.expectEqualStrings(c.algorithm, @tagName(k.algorithm));
        try t.expectEqualSlices(u8, want.secret, k.secret);
        std.crypto.secureZero(u8, &dec);
        const kp = try kc.parseEncryptedPrivateKeyPem(c.pem, c.password, &dec, test_opts);
        try t.expectEqualStrings(c.algorithm, @tagName(kp.algorithm));
        try t.expectEqualSlices(u8, want.secret, kp.secret);
        std.crypto.secureZero(u8, &dec);

        // Re-encrypting with the file's own salt and IV gives the file.
        var rnd_bytes: [16 + pbes2.max_write_salt_len]u8 = undefined;
        @memcpy(rnd_bytes[0..info.salt.len], info.salt);
        @memcpy(rnd_bytes[info.salt.len..][0..16], info.iv);
        var fr: FixedRandom = .{ .data = &rnd_bytes };
        const eo: kc.EncryptOptions = .{ .cipher = info.cipher, .kdf = info.kdf, .salt_len = @intCast(info.salt.len), .scrypt_work = &work };
        const ours = try kc.encryptPkcs8(&out, want, c.password, fr.random(), eo);
        try t.expectEqualSlices(u8, enc, ours);
        try t.expectEqual(ours.len, pbes2.encryptedLen(plain.len, eo));

        // The same through the PEM writer: OpenSSL's text.
        var pem_out: [kc.max_encrypted_pem_len]u8 = undefined;
        fr.pos = 0;
        try t.expectEqualStrings(c.pem, try kc.writeEncryptedPrivateKeyPem(&pem_out, want, c.password, fr.random(), eo));

        // A wrong password is one error, and leaves nothing behind.
        try t.expectError(error.IncorrectPasswordOrCorrupt, kc.decryptPkcs8(enc, "wrong password", &dec, test_opts));
        try t.expect(allZero(&dec));
        try t.expectError(error.IncorrectPasswordOrCorrupt, kc.parseEncryptedPkcs8(enc, "", &dec, test_opts));
        try t.expect(allZero(&dec));
    }
}

test "the default options are openssl pkcs8 -topk8's output shape" {
    const c = enc_vectors.cases[0]; // ed25519-default
    var enc_buf: [512]u8 = undefined;
    const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
    const info = try kc.parseEncryptedInfo(enc);
    const d: kc.EncryptOptions = .{};
    try t.expectEqual(info.cipher, d.cipher);
    try t.expectEqual(info.kdf.pbkdf2.prf, d.kdf.pbkdf2.prf);
    try t.expectEqual(info.kdf.pbkdf2.iterations, d.kdf.pbkdf2.iterations);
    try t.expectEqual(info.salt.len, @as(usize, d.salt_len));
}

test "round trip for every KDF, PRF, cipher, password length, on every vector key" {
    var prng = std.Random.DefaultPrng.init(0x7e57_0001);
    const rnd = prng.random();
    var enc: [kc.max_encrypted_der_len]u8 = undefined;
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    var pw: [200]u8 = undefined;
    rnd.bytes(&pw);
    var small_work: [64 * 1024]u8 = undefined;
    var n_cases: usize = 0;
    for (vectors.cases) |c| {
        if (c.pq_form != null and !std.mem.eql(u8, c.pq_form.?, "both")) continue;
        var kbuf: [kc.max_private_der_len]u8 = undefined;
        const k = try kc.parsePrivateKeyPem(c.pem, &kbuf);
        for (std.enums.values(pbes2.Cipher)) |cipher| {
            for ([_]usize{ 0, 1, 64, 200 }) |pw_len| {
                for (std.enums.values(pbes2.Prf)) |prf| {
                    const eo: kc.EncryptOptions = .{ .cipher = cipher, .kdf = .{ .pbkdf2 = .{ .prf = prf, .iterations = 3 } }, .salt_len = 8 };
                    const out = try kc.encryptPkcs8(&enc, k, pw[0..pw_len], rnd, eo);
                    const got = try kc.parseEncryptedPkcs8(out, pw[0..pw_len], &dec, .{});
                    try t.expectEqualStrings(@tagName(k.algorithm), @tagName(got.algorithm));
                    try t.expectEqualSlices(u8, k.secret, got.secret);
                    try t.expectEqualSlices(u8, k.expanded, got.expanded);
                    std.crypto.secureZero(u8, &dec);
                    n_cases += 1;
                }
            }
            const sp: pbes2.ScryptParams = .{ .log2_n = 4, .r = 2, .p = 2 };
            const eo: kc.EncryptOptions = .{ .cipher = cipher, .kdf = .{ .scrypt = sp }, .salt_len = 32, .scrypt_work = &small_work };
            const out = try kc.encryptPkcs8(&enc, k, "pw", rnd, eo);
            const got = try kc.parseEncryptedPkcs8(out, "pw", &dec, .{ .scrypt_work = &small_work });
            try t.expectEqualSlices(u8, k.secret, got.secret);
            std.crypto.secureZero(u8, &dec);
            try t.expectEqual(pbes2.encryptedLen(try plainLen(k), eo), out.len);
        }
    }
    try t.expect(n_cases > 100);
}

fn plainLen(k: kc.PrivateKey) !usize {
    var b: [kc.max_private_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &b);
    return (try kc.writePkcs8(&b, k)).len;
}

test "the longest keys fit max_encrypted_der_len and max_encrypted_pem_len" {
    var prng = std.Random.DefaultPrng.init(2);
    var enc: [kc.max_encrypted_der_len]u8 = undefined;
    var pem_out: [kc.max_encrypted_pem_len]u8 = undefined;
    var kbuf: [kc.max_private_der_len]u8 = undefined;
    var small_work: [4096]u8 = undefined;
    for (vectors.cases) |c| {
        if (!std.mem.eql(u8, c.name, "ml_dsa_87-both") and !std.mem.eql(u8, c.name, "rsa-pkcs8")) continue;
        const k = try kc.parsePrivateKeyPem(c.pem, &kbuf);
        const eo: kc.EncryptOptions = .{ .kdf = .{ .scrypt = .{ .log2_n = 2, .r = 1, .p = 1 } }, .salt_len = pbes2.max_write_salt_len, .scrypt_work = &small_work };
        const der_len = (try kc.encryptPkcs8(&enc, k, "pw", prng.random(), eo)).len;
        try t.expect(der_len <= kc.max_encrypted_der_len);
        const text = try kc.writeEncryptedPrivateKeyPem(&pem_out, k, "pw", prng.random(), eo);
        try t.expect(text.len <= kc.max_encrypted_pem_len);
    }
}

// ── a hand-built EncryptedPrivateKeyInfo, for the structures OpenSSL never writes ──

fn tlv(a: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var n: usize = 0;
    for (parts) |p| n += p.len;
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, tag);
    if (n < 0x80) {
        try out.append(a, @intCast(n));
    } else if (n <= 0xff) {
        try out.appendSlice(a, &.{ 0x81, @intCast(n) });
    } else {
        try out.appendSlice(a, &.{ 0x82, @intCast(n >> 8), @truncate(n) });
    }
    for (parts) |p| try out.appendSlice(a, p);
    return out.items;
}

const oid_hmac_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09 };

const Spec = struct {
    alg_oid: []const u8 = &pbes2.oid_pbes2,
    kdf_oid: []const u8 = &pbes2.oid_pbkdf2,
    salt_tag: u8 = 0x04,
    salt: []const u8 = "saltsalt",
    /// PBKDF2: iterationCount content; scrypt: N.
    iter: []const u8 = &.{0x20},
    key_len: ?[]const u8 = null,
    /// A whole AlgorithmIdentifier TLV for the PRF, null: absent (sha1).
    prf: ?[]const u8 = null,
    /// scrypt: r and p content (null: this is PBKDF2).
    scrypt_rp: ?[2][]const u8 = null,
    enc_oid: []const u8 = &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a },
    iv: []const u8 = &(@as([16]u8, @splat(7))),
    data: []const u8 = &(@as([32]u8, @splat(9))),
    trailing: []const u8 = &.{},
    kp_trailing: []const u8 = &.{},
};

fn build(a: std.mem.Allocator, s: Spec) ![]u8 {
    var kp: std.ArrayList([]const u8) = .empty;
    try kp.append(a, try tlv(a, s.salt_tag, &.{s.salt}));
    try kp.append(a, try tlv(a, 0x02, &.{s.iter}));
    if (s.scrypt_rp) |rp| {
        try kp.append(a, try tlv(a, 0x02, &.{rp[0]}));
        try kp.append(a, try tlv(a, 0x02, &.{rp[1]}));
    }
    if (s.key_len) |kl| try kp.append(a, try tlv(a, 0x02, &.{kl}));
    if (s.prf) |p| try kp.append(a, p);
    try kp.append(a, s.kp_trailing);
    const kdf = try tlv(a, 0x30, &.{ try tlv(a, 0x06, &.{s.kdf_oid}), try tlv(a, 0x30, kp.items) });
    const enc = try tlv(a, 0x30, &.{ try tlv(a, 0x06, &.{s.enc_oid}), try tlv(a, 0x04, &.{s.iv}) });
    const alg = try tlv(a, 0x30, &.{ try tlv(a, 0x06, &.{s.alg_oid}), try tlv(a, 0x30, &.{ kdf, enc }) });
    return tlv(a, 0x30, &.{ alg, try tlv(a, 0x04, &.{s.data}), s.trailing });
}

fn expectDecrypt(a: std.mem.Allocator, s: Spec, opts: kc.DecryptOptions, want: anyerror) !void {
    const der = try build(a, s);
    var out: [64]u8 = undefined;
    try t.expectError(want, kc.decryptPkcs8(der, "pw", &out, opts));
}

test "hostile and unusual PBES2 structures" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var small_work: [16384]u8 = undefined;
    const sw: kc.DecryptOptions = .{ .scrypt_work = &small_work };

    // The builder's default is a well-formed PBES2/PBKDF2/AES-256-CBC file
    // whose ciphertext is garbage: right structure, wrong everything else.
    try expectDecrypt(a, .{}, .{}, error.IncorrectPasswordOrCorrupt);
    const sha256_prf = try tlv(a, 0x30, &.{ try tlv(a, 0x06, &.{&oid_hmac_sha256}), try tlv(a, 0x05, &.{}) });
    try expectDecrypt(a, .{ .prf = sha256_prf }, .{}, error.IncorrectPasswordOrCorrupt);
    // PRF parameters absent instead of NULL: accepted (OpenSSL reads both).
    try expectDecrypt(a, .{ .prf = try tlv(a, 0x30, &.{try tlv(a, 0x06, &.{&oid_hmac_sha256})}) }, .{}, error.IncorrectPasswordOrCorrupt);
    // keyLength present: right and wrong.
    try expectDecrypt(a, .{ .key_len = &.{0x20} }, .{}, error.IncorrectPasswordOrCorrupt);
    try expectDecrypt(a, .{ .key_len = &.{0x10} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .key_len = &.{0x20}, .prf = sha256_prf }, .{}, error.IncorrectPasswordOrCorrupt);

    // Iteration counts: zero, negative, padded, over the cap, over a raised cap, wider than 64 bits.
    try expectDecrypt(a, .{ .iter = &.{0x00} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .iter = &.{0x80} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .iter = &.{ 0x00, 0x01 } }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .iter = &.{} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .iter = &.{ 0x10, 0x00, 0x01 } }, .{}, error.KdfParamsTooLarge); // 2^20 + 1
    try expectDecrypt(a, .{ .iter = &.{ 0x10, 0x00, 0x00 } }, .{}, error.IncorrectPasswordOrCorrupt); // 2^20 exactly: allowed
    try expectDecrypt(a, .{ .iter = &.{ 0x7f, 0xff, 0xff, 0xff } }, .{}, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .iter = &(@as([20]u8, @splat(0x7f))) }, .{ .max_pbkdf2_iterations = std.math.maxInt(u32) }, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .iter = &.{0x30} }, .{ .max_pbkdf2_iterations = 0x2f }, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .iter = &.{0x30} }, .{ .max_pbkdf2_iterations = 0x30 }, error.IncorrectPasswordOrCorrupt);

    // Salt: empty, over the read limit, at it, otherSource instead of an OCTET STRING.
    try expectDecrypt(a, .{ .salt = "" }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .salt = &(@as([pbes2.max_read_salt_len + 1]u8, @splat(1))) }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .salt = &(@as([pbes2.max_read_salt_len]u8, @splat(1))) }, .{}, error.IncorrectPasswordOrCorrupt);
    try expectDecrypt(a, .{ .salt_tag = 0x30, .salt = "" }, .{}, error.UnsupportedEncryption);

    // IV and ciphertext shapes.
    try expectDecrypt(a, .{ .iv = &(@as([15]u8, @splat(1))) }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .iv = &(@as([17]u8, @splat(1))) }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .data = &.{} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .data = &(@as([17]u8, @splat(1))) }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .data = &(@as([16]u8, @splat(1))) }, .{}, error.IncorrectPasswordOrCorrupt);
    // Trailing bytes at two levels.
    try expectDecrypt(a, .{ .trailing = &.{0} }, .{}, error.MalformedKey);
    try expectDecrypt(a, .{ .kp_trailing = &.{ 0x05, 0x00 } }, .{}, error.MalformedKey);

    // Other algorithms: refused by name, not misread.
    // PBES1 (pbeWithSHA1And3-KeyTripleDES-CBC), PKCS#5 PBES1 MD5/DES.
    try expectDecrypt(a, .{ .alg_oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03 } }, .{}, error.UnsupportedEncryption);
    try expectDecrypt(a, .{ .alg_oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 } }, .{}, error.UnsupportedEncryption);
    // An unknown KDF; a PRF outside SHA-1/224/256/384/512 (hmacWithSHA512-224).
    try expectDecrypt(a, .{ .kdf_oid = &.{ 0x2a, 0x03 } }, .{}, error.UnsupportedEncryption);
    try expectDecrypt(a, .{ .prf = try tlv(a, 0x30, &.{ try tlv(a, 0x06, &.{&.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c }}), try tlv(a, 0x05, &.{}) }) }, .{}, error.UnsupportedEncryption);
    // Ciphers: DES-EDE3-CBC, AES-256-GCM, AES-256-CTR-like, camellia, a neighbour of each AES arc.
    const ciphers = [_][]const u8{
        &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07 },
        &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e },
        &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2b },
        &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x03 },
        &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a, 0x01 },
        &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01 },
        &.{ 0x03, 0xa1, 0x00 },
    };
    for (ciphers) |o| try expectDecrypt(a, .{ .enc_oid = o }, .{}, error.UnsupportedEncryption);
    // The three AES-CBC OIDs are the only ones read, each with its key length.
    for ([_]u8{ 0x02, 0x16, 0x2a }, [_]u8{ 16, 24, 32 }) |last, kl| {
        const o = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, last };
        try expectDecrypt(a, .{ .enc_oid = &o, .key_len = &.{kl} }, .{}, error.IncorrectPasswordOrCorrupt);
        try expectDecrypt(a, .{ .enc_oid = &o, .key_len = &.{kl + 1} }, .{}, error.MalformedKey);
    }

    // scrypt: parameters at the edges.
    const sc = pbes2.oid_scrypt;
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{2}, &.{1} } }, sw, error.IncorrectPasswordOrCorrupt);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{2}, &.{1} }, .key_len = &.{0x20} }, sw, error.IncorrectPasswordOrCorrupt);
    // No work buffer: scrypt is not enabled at all.
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{2}, &.{1} } }, .{}, error.UnsupportedEncryption);
    // N: 0, 1, 3, not minimal, negative.
    for ([_][]const u8{ &.{0}, &.{1}, &.{3}, &.{ 0x00, 0x04 }, &.{0x80}, &.{}, &.{ 0x00, 0x80 } }) |n| {
        const e = if (n.len == 2 and n[1] == 0x80) error.KdfParamsTooLarge else error.MalformedKey; // 128 is a power of two
        try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = n, .scrypt_rp = .{ &.{2}, &.{1} } }, sw, e);
    }
    // r, p: zero, negative.
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{0}, &.{1} } }, sw, error.MalformedKey);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{1}, &.{0} } }, sw, error.MalformedKey);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{0x80}, &.{1} } }, sw, error.MalformedKey);
    // Memory: more than the buffer holds (N = 2^20, r = 8 is 1 GiB), and the same
    // parameters with N * r * p over the default cost cap and under a raised one.
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{ 0x10, 0x00, 0x00 }, .scrypt_rp = .{ &.{8}, &.{1} } }, sw, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{ 0x20, 0x00, 0x00 }, .scrypt_rp = .{ &.{8}, &.{1} } }, sw, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{ 0x7f, 0xff, 0xff, 0xff }, &.{1} } }, sw, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x10}, .scrypt_rp = .{ &.{1}, &.{ 0x7f, 0xff, 0xff, 0xff } } }, sw, error.KdfParamsTooLarge);
    // Wider than 64 bits: N a power of two only up to 2^63; the rest is malformed or too large.
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &(@as([40]u8, @splat(0x7f))), .scrypt_rp = .{ &.{2}, &.{1} } }, sw, error.MalformedKey);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{ 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0 }, .scrypt_rp = .{ &.{2}, &.{1} } }, sw, error.KdfParamsTooLarge); // N = 2^63
    // A time cap below the work, with memory to spare.
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x20}, .scrypt_rp = .{ &.{2}, &.{4} } }, .{ .scrypt_work = &small_work, .max_scrypt_cost = 0x20 * 8 - 1 }, error.KdfParamsTooLarge);
    try expectDecrypt(a, .{ .kdf_oid = &sc, .iter = &.{0x20}, .scrypt_rp = .{ &.{2}, &.{4} } }, .{ .scrypt_work = &small_work, .max_scrypt_cost = 0x20 * 8 }, error.IncorrectPasswordOrCorrupt);
}

test "buffers: too short, overlapping, in place" {
    const c = enc_vectors.cases[0];
    var enc_buf: [512]u8 = undefined;
    const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
    const info = try kc.parseEncryptedInfo(enc);
    var out: [64]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, kc.decryptPkcs8(enc, c.password, out[0 .. info.ciphertext.len - 1], .{}));
    // Exactly the ciphertext's length works.
    _ = try kc.decryptPkcs8(enc, c.password, out[0..info.ciphertext.len], .{});

    // Output overlapping the ciphertext other than at its start: refused, not corrupted.
    const ct_at = @intFromPtr(info.ciphertext.ptr) - @intFromPtr(&enc_buf);
    try t.expectError(error.NoSpaceLeft, kc.decryptPkcs8(enc, c.password, enc_buf[ct_at + 1 ..][0..info.ciphertext.len], .{}));
    try t.expectError(error.NoSpaceLeft, kc.decryptPkcs8(enc, c.password, enc_buf[ct_at - 1 ..][0..info.ciphertext.len], .{}));
    // In place: exactly at the start.
    const pt = try kc.decryptPkcs8(enc, c.password, enc_buf[ct_at..][0..info.ciphertext.len], .{});
    const plain_k = try kc.parsePkcs8(pt);
    try t.expectEqual(kc.Algorithm.ed25519, plain_k.algorithm);
}

test "PEM: which block counts, and the refusals" {
    const c = enc_vectors.cases[0];
    var buf: [1024]u8 = undefined;

    // Other blocks first are skipped.
    const mixed = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" ++ c.pem;
    const k = try kc.parseEncryptedPrivateKeyPem(mixed, c.password, &buf, .{});
    try t.expectEqual(kc.Algorithm.ed25519, k.algorithm);

    // A plain key first: the caller should have used parsePrivateKeyPem.
    for (vectors.cases) |v| {
        if (!std.mem.eql(u8, v.name, "ed25519-pkcs8") and !std.mem.eql(u8, v.name, "ec_p256-sec1") and !std.mem.eql(u8, v.name, "rsa-pkcs1")) continue;
        try t.expectError(error.NotEncrypted, kc.parseEncryptedPrivateKeyPem(v.pem, "x", &buf, .{}));
    }
    try t.expectError(error.MissingKey, kc.parseEncryptedPrivateKeyPem("", "x", &buf, .{}));
    try t.expectError(error.MissingKey, kc.parseEncryptedPrivateKeyPem("-----BEGIN PUBLIC KEY-----\nAAEC\n-----END PUBLIC KEY-----\n", "x", &buf, .{}));
    try t.expectError(error.UnsupportedFormat, kc.parseEncryptedPrivateKeyPem("-----BEGIN OPENSSH PRIVATE KEY-----\nAAEC\n-----END OPENSSH PRIVATE KEY-----\n", "x", &buf, .{}));
    try t.expectError(error.InvalidPem, kc.parseEncryptedPrivateKeyPem("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAEC\n", "x", &buf, .{}));
    try t.expectError(error.InvalidPem, kc.parseEncryptedPrivateKeyPem("-----BEGIN ENCRYPTED PRIVATE KEY-----\n*AEC\n-----END ENCRYPTED PRIVATE KEY-----\n", "x", &buf, .{}));
    try t.expectError(error.MalformedKey, kc.parseEncryptedPrivateKeyPem("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAEC\n-----END ENCRYPTED PRIVATE KEY-----\n", "x", &buf, .{}));
    // The legacy RFC 1421 encrypted form (MD5 KDF, no wrong-password check): not read.
    try t.expectError(error.UnsupportedEncryption, kc.parseEncryptedPrivateKeyPem(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899aabbccddeeff\n\nAAEC\n-----END ENCRYPTED PRIVATE KEY-----\n",
        "x",
        &buf,
        .{},
    ));
    // A buffer too small for the decoded file.
    var tiny: [8]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, kc.parseEncryptedPrivateKeyPem(c.pem, c.password, &tiny, .{}));
    // The plain-key reader still says what it says.
    try t.expectError(error.EncryptedKey, kc.parsePrivateKeyPem(c.pem, &buf));
    // Wrong password through the PEM path wipes the plaintext region.
    try t.expectError(error.IncorrectPasswordOrCorrupt, kc.parseEncryptedPrivateKeyPem(c.pem, "nope", &buf, .{}));
}

fn caseNamed(name: []const u8) vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

test "encrypt: option ranges, buffer sizes, wiping" {
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    var kbuf: [kc.max_private_der_len]u8 = undefined;
    const k = try kc.parsePrivateKeyPem(caseNamed("ed25519-pkcs8").pem, &kbuf);
    var out: [kc.max_encrypted_der_len]u8 = undefined;
    var small_work: [8192]u8 = undefined;

    const bad = [_]kc.EncryptOptions{
        .{ .kdf = .{ .pbkdf2 = .{ .iterations = 0 } } },
        .{ .kdf = .{ .pbkdf2 = .{ .iterations = pbes2.max_written_pbkdf2_iterations + 1 } } },
        .{ .salt_len = 0 },
        .{ .salt_len = pbes2.max_write_salt_len + 1 },
        .{ .kdf = .{ .scrypt = .{} } }, // no work buffer
        .{ .kdf = .{ .scrypt = .{ .log2_n = 0 } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .r = 0 } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .p = 0 } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .log2_n = 14 } }, .scrypt_work = &small_work }, // buffer too small
        .{ .kdf = .{ .scrypt = .{ .log2_n = 40, .r = 1, .p = 1 } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .log2_n = 2, .r = std.math.maxInt(u32), .p = 1 } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .log2_n = 2, .r = 1, .p = std.math.maxInt(u32) } }, .scrypt_work = &small_work },
        .{ .kdf = .{ .scrypt = .{ .log2_n = 63, .r = std.math.maxInt(u32), .p = std.math.maxInt(u32) } }, .scrypt_work = &small_work },
    };
    for (bad, 0..) |o, i| {
        errdefer std.debug.print("bad option set {d}\n", .{i});
        @memset(&out, 0xaa);
        try t.expectError(error.InvalidOptions, kc.encryptPkcs8(&out, k, "pw", rnd, o));
        try t.expect(allZero(&out)); // wiped on every error
    }

    // The edges that are allowed.
    _ = try kc.encryptPkcs8(&out, k, "pw", rnd, .{ .kdf = .{ .pbkdf2 = .{ .iterations = 1 } }, .salt_len = 1 });
    _ = try kc.encryptPkcs8(&out, k, "pw", rnd, .{ .salt_len = pbes2.max_write_salt_len });
    _ = try kc.encryptPkcs8(&out, k, "pw", rnd, .{ .kdf = .{ .scrypt = .{ .log2_n = 1, .r = 1, .p = 1 } }, .scrypt_work = &small_work });

    // Buffer sizes: exactly right works, one short does not and is wiped.
    const want = pbes2.encryptedLen(try plainLen(k), .{});
    const exact = try kc.encryptPkcs8(out[0..want], k, "pw", rnd, .{});
    try t.expectEqual(want, exact.len);
    @memset(&out, 0xaa);
    try t.expectError(error.NoSpaceLeft, kc.encryptPkcs8(out[0 .. want - 1], k, "pw", rnd, .{}));
    try t.expect(allZero(out[0 .. want - 1]));

    // A key that does not fit its algorithm.
    var bad_key = k;
    bad_key.secret = k.secret[0..5];
    try t.expectError(error.MalformedKey, kc.encryptPkcs8(&out, bad_key, "pw", rnd, .{}));

    // The key is written as PKCS#8 whatever its encoding said.
    var sbuf: [kc.max_private_der_len]u8 = undefined;
    const sec1 = try kc.parsePrivateKeyPem(caseNamed("ec_p256-sec1").pem, &sbuf);
    try t.expectEqual(kc.Encoding.sec1, sec1.encoding);
    const e = try kc.encryptPkcs8(&out, sec1, "pw", rnd, .{});
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    const back = try kc.parseEncryptedPkcs8(e, "pw", &dec, .{});
    try t.expectEqual(kc.Encoding.pkcs8, back.encoding);
    try t.expectEqualSlices(u8, sec1.secret, back.secret);
}

test "damaged files: no panic, only the documented outcomes" {
    var prng = std.Random.DefaultPrng.init(0xbad_f11e);
    const rnd = prng.random();
    var enc_buf: [kc.max_encrypted_der_len]u8 = undefined;
    var mut: [kc.max_encrypted_der_len]u8 = undefined;
    var dec: [kc.max_encrypted_der_len]u8 = undefined;
    for (enc_vectors.cases) |c| {
        const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
        // Cheap parameters only: a mutated count would otherwise run for the cap.
        const cheap: kc.DecryptOptions = .{ .max_pbkdf2_iterations = 4096, .max_scrypt_cost = 1 << 12, .scrypt_work = work[0 .. 512 * 1024] };
        for (0..300) |_| {
            @memcpy(mut[0..enc.len], enc);
            const flips = 1 + rnd.uintLessThan(usize, 3);
            for (0..flips) |_| mut[rnd.uintLessThan(usize, enc.len)] ^= @as(u8, 1) << rnd.int(u3);
            const n = if (rnd.uintLessThan(u8, 8) == 0) rnd.uintLessThan(usize, enc.len) else enc.len;
            if (kc.parseEncryptedPkcs8(mut[0..n], c.password, &dec, cheap)) |k| {
                _ = k;
            } else |err| switch (err) {
                error.MalformedKey, error.UnsupportedEncryption, error.KdfParamsTooLarge, error.IncorrectPasswordOrCorrupt, error.NoSpaceLeft, error.UnsupportedAlgorithm => {},
            }
            std.crypto.secureZero(u8, &dec);
        }
    }
}

test "constant error for wrong password: padding and structure failures look alike" {
    // Truncating or editing the last ciphertext block breaks the padding;
    // editing an earlier one breaks the DER. Both are one error.
    const c = enc_vectors.cases[0];
    var enc_buf: [512]u8 = undefined;
    const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
    const info = try kc.parseEncryptedInfo(enc);
    const ct_at = @intFromPtr(info.ciphertext.ptr) - @intFromPtr(&enc_buf);
    var dec: [128]u8 = undefined;
    var errs: [2]anyerror = undefined;
    for ([_]usize{ ct_at + info.ciphertext.len - 1, ct_at + 3 }, 0..) |at, i| {
        var copy: [512]u8 = enc_buf;
        copy[at] ^= 0x55;
        errs[i] = if (kc.parseEncryptedPkcs8(copy[0..enc.len], c.password, &dec, .{})) |_| error.Unexpected else |e| e;
        std.crypto.secureZero(u8, &dec);
    }
    try t.expectEqual(errs[0], error.IncorrectPasswordOrCorrupt);
    try t.expectEqual(errs[1], error.IncorrectPasswordOrCorrupt);
}

test "decrypt side wiping: out, scrypt work, the in-place PEM region" {
    // Coordinator review 2026-11-07 (MED-2): the wiping on the decrypt side
    // was in the code but asserted nowhere.
    var enc_buf: [kc.max_encrypted_der_len]u8 = undefined;
    var out: [kc.max_encrypted_der_len]u8 = undefined;
    for ([_][]const u8{ "ed25519-default", "rsa-default", "ec_p256-scrypt-small" }) |name| {
        errdefer std.debug.print("case {s}\n", .{name});
        const c = caseNamed2(name);
        const enc = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &enc_buf);
        const info = try kc.parseEncryptedInfo(enc);
        const need: usize = switch (info.kdf) {
            .pbkdf2 => 0,
            .scrypt => |s| pbes2.scryptWorkLen(s),
        };

        // Wrong password: whatever held plaintext is zero afterwards.
        @memset(&out, 0xaa);
        @memset(work[0..need], 0xaa);
        try t.expectError(error.IncorrectPasswordOrCorrupt, kc.parseEncryptedPkcs8(enc, "nope", &out, test_opts));
        try t.expect(allZero(out[0..info.ciphertext.len]));
        try t.expect(allZero(work[0..need]));

        // Right password: the scrypt work is wiped on success too.
        @memset(work[0..need], 0xaa);
        const k = try kc.parseEncryptedPkcs8(enc, c.password, &out, test_opts);
        _ = k;
        try t.expect(allZero(work[0..need]));
        std.crypto.secureZero(u8, &out);

        // The in-place PEM path: the ciphertext region of the decode buffer.
        var der_buf: [kc.max_encrypted_der_len]u8 = undefined;
        const decoded = try blockDer(c.pem, "ENCRYPTED PRIVATE KEY", &der_buf);
        const ct_at = @intFromPtr((try kc.parseEncryptedInfo(decoded)).ciphertext.ptr) - @intFromPtr(&der_buf);
        @memset(&der_buf, 0xaa);
        try t.expectError(error.IncorrectPasswordOrCorrupt, kc.parseEncryptedPrivateKeyPem(c.pem, "nope", &der_buf, test_opts));
        try t.expect(allZero(der_buf[ct_at..][0..info.ciphertext.len]));
    }
}

fn caseNamed2(name: []const u8) enc_vectors.Case {
    for (enc_vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    unreachable;
}

test "PEM: a legacy encrypted block under a plain label is UnsupportedEncryption" {
    // Coordinator review 2026-11-07 (MED-1): `openssl genrsa -aes128` and
    // `openssl ec -aes128` write the plain label plus RFC 1421 headers; this
    // used to answer NotEncrypted and send the caller to the plain reader.
    var buf: [256]u8 = undefined;
    for ([_][]const u8{ "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY" }) |label| {
        var text_buf: [256]u8 = undefined;
        const text = try std.mem.print(&text_buf, "-----BEGIN {s}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAEC\n-----END {s}-----\n", .{ label, label });
        try t.expectError(error.UnsupportedEncryption, kc.parseEncryptedPrivateKeyPem(text, "x", &buf, .{}));
    }
}
