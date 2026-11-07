// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the two burned entry points,
//! `parsePrivateKeyPem` and `writePrivateKeyPem` (SPEC § Open; the burn
//! mutants of the 2026-11-06 mutation run are visible only here). Every key
//! shape the burns must cover: the smallest (P-256 SEC1), the deepest DER
//! walk (ML-DSA-87 `both`, the longest PEM), RSA PKCS#1 and PKCS#8.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip).

const std = @import("std");
const kc = @import("root.zig");
const vectors = @import("vectors.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{});

var der_buf: [kc.max_private_der_len]u8 = undefined;
var der_copy: [kc.max_private_der_len]u8 = undefined;
var pem_out: [kc.max_private_pem_len]u8 = undefined;

const probed = [_][]const u8{ "ec_p256-sec1", "ec_p521-pkcs8", "rsa-pkcs1", "rsa-pkcs8", "ml_dsa_87-both" };

fn caseNamed(name: []const u8) ?vectors.Case {
    for (vectors.cases) |c| if (std.mem.eql(u8, c.name, name)) return c;
    return null;
}

test "STACKPROBE: no key residue after parsePrivateKeyPem / writePrivateKeyPem" {
    try sp.skipUnlessOptimized();
    var seen: usize = 0;
    for (probed) |name| {
        const c = caseNamed(name) orelse continue;
        seen += 1;
        // The key's DER, outside the probe: the needle the dead stack must
        // not hold.
        const block = (try kc.pem.find(c.pem, (std.meta.stringToEnum(kc.Encoding, c.encoding).?).pemLabel())).?;
        const der = try block.decode(&der_copy);
        const secrets = &[_][]const u8{der};

        _ = try P.run("parsePrivateKeyPem", kc.parsePrivateKeyPem, .{ c.pem, &der_buf }, secrets, .{});
        const k = try kc.parsePrivateKeyPem(c.pem, &der_buf);
        _ = try P.run("writePrivateKeyPem", kc.writePrivateKeyPem, .{ &pem_out, k }, secrets, .{});
    }
    try std.testing.expectEqual(probed.len, seen);
}

const enc_vectors = @import("vectors_enc.zig");

var enc_out: [kc.max_encrypted_der_len]u8 = undefined;
var dec_buf: [kc.max_encrypted_der_len]u8 = undefined;
var scrypt_work: [32 * 1024]u8 = undefined;

test "STACKPROBE: no key residue after the encrypted-key entry points" {
    try sp.skipUnlessOptimized();
    var seen: usize = 0;
    for (enc_vectors.cases) |c| {
        // PBKDF2 with the file's PRF and cipher, and the small scrypt fixture's
        // parameters: both KDF frames, all three ciphers' round keys.
        if (!std.mem.eql(u8, c.name, "ed25519-default") and !std.mem.eql(u8, c.name, "ed25519-aes192") and
            !std.mem.eql(u8, c.name, "ed25519-sha512") and !std.mem.eql(u8, c.name, "rsa-default") and
            !std.mem.eql(u8, c.name, "ed25519-scrypt-small")) continue;
        seen += 1;
        const block = (try kc.pem.find(c.plain_pem, "PRIVATE KEY")).?;
        const plain = try block.decode(&der_copy);
        const secrets = &[_][]const u8{plain};
        const opts: kc.DecryptOptions = .{ .scrypt_work = &scrypt_work };

        _ = try P.run("parseEncryptedPrivateKeyPem", kc.parseEncryptedPrivateKeyPem, .{ c.pem, c.password, &dec_buf, opts }, secrets, .{});
        std.crypto.secureZero(u8, &dec_buf);
        const eblock = (try kc.pem.find(c.pem, "ENCRYPTED PRIVATE KEY")).?;
        var enc_der: [kc.max_encrypted_der_len]u8 = undefined;
        const enc = try eblock.decode(&enc_der);
        _ = try P.run("parseEncryptedPkcs8", kc.parseEncryptedPkcs8, .{ enc, c.password, &dec_buf, opts }, secrets, .{});
        std.crypto.secureZero(u8, &dec_buf);

        const k = try kc.parsePkcs8(plain);
        var prng: std.Random.DefaultPrng = .init(5);
        const info = try kc.parseEncryptedInfo(enc);
        const eo: kc.EncryptOptions = .{ .cipher = info.cipher, .kdf = info.kdf, .scrypt_work = &scrypt_work };
        _ = try P.run("encryptPkcs8", kc.encryptPkcs8, .{ &enc_out, k, c.password, prng.random(), eo }, secrets, .{});
    }
    try std.testing.expectEqual(@as(usize, 5), seen);
}
