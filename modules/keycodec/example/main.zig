// SPDX-License-Identifier: MIT

//! What a server's key loader does with `keycodec`: take whatever PEM file
//! the operator dropped in, read the private key, rewrite it as PKCS#8 (what
//! `openssl pkcs8 -topk8 -nocrypt` does) and publish the public half as a
//! `PUBLIC KEY` block (`openssl pkey -pubout`). Files it cannot use are
//! refused by name, so the operator gets the right hint.
//!
//! The key is a published TEST key written by OpenSSL 3.5.5 (the module's
//! own vectors); the expected outputs are OpenSSL's, so the example checks
//! real bytes, not its own round trip.
//!
//! Built against the PUBLISHED module (`@import("keycodec")`) only.

const std = @import("std");
const keycodec = @import("keycodec");

// `openssl ecparam -genkey -name prime256v1` — a SEC1 `EC PRIVATE KEY`.
const sec1_pem =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIJRw6lYRs9aRS/Ty5LSY4HRgoexfkeDefKf8wepLEdT6oAoGCCqGSM49
    \\AwEHoUQDQgAEXOMG4DtMsknAhLspSG7ShEylqIEsMOra/VngNqkUNsQDmmqcULOE
    \\1A8EdiAnF0txGzDgW8rSaerZj+YildD1Yg==
    \\-----END EC PRIVATE KEY-----
    \\
;

// The same key as OpenSSL writes it in PKCS#8 and as SubjectPublicKeyInfo.
const pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglHDqVhGz1pFL9PLk
    \\tJjgdGCh7F+R4N58p/zB6ksR1PqhRANCAARc4wbgO0yyScCEuylIbtKETKWogSww
    \\6tr9WeA2qRQ2xAOaapxQs4TUDwR2ICcXS3EbMOBbytJp6tmP5iKV0PVi
    \\-----END PRIVATE KEY-----
    \\
;
const spki_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXOMG4DtMsknAhLspSG7ShEylqIEs
    \\MOra/VngNqkUNsQDmmqcULOE1A8EdiAnF0txGzDgW8rSaerZj+YildD1Yg==
    \\-----END PUBLIC KEY-----
    \\
;

/// Load one operator-supplied PEM file; `null` = refused, with the reason.
fn load(text: []const u8, der_buf: []u8) ?keycodec.PrivateKey {
    return keycodec.parsePrivateKeyPem(text, der_buf) catch |err| {
        const hint = switch (err) {
            error.EncryptedKey => "encrypted key: decrypt it first (openssl pkcs8 -in k.pem)",
            error.UnsupportedFormat => "OpenSSH key: use the ssh module or ssh-keygen -m PKCS8",
            error.MissingKey => "no private key block in the file",
            error.UnsupportedAlgorithm => "key type not supported",
            error.InvalidPem, error.MalformedKey => "damaged key file",
            error.NoSpaceLeft => "key larger than the buffer",
        };
        std.debug.print("refused: {s}\n", .{hint});
        return null;
    };
}

pub fn main() !void {
    // The DER of a parsed key lives in the caller's buffer and holds the
    // secret: wipe it when done.
    var der_buf: [keycodec.max_private_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);

    const key = load(sec1_pem, &der_buf) orelse return error.KeyRefused;
    std.debug.print("loaded {t} key ({t})\n", .{ key.algorithm, key.encoding });

    // ── rewrite as PKCS#8 ────────────────────────────────────────────────
    var out: [keycodec.max_private_pem_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    var as_pkcs8 = key;
    as_pkcs8.encoding = .pkcs8;
    const written = try keycodec.writePrivateKeyPem(&out, as_pkcs8);
    if (!std.mem.eql(u8, written, pkcs8_pem)) return error.Pkcs8Mismatch;
    std.debug.print("PKCS#8 matches openssl pkcs8 -topk8\n", .{});

    // ── publish the public half ─────────────────────────────────────────
    const public = key.public orelse return error.NoPublicKey;
    var pub_out: [1024]u8 = undefined;
    const pub_pem = try keycodec.writePublicKeyPem(&pub_out, .{ .algorithm = key.algorithm, .key = public });
    if (!std.mem.eql(u8, pub_pem, spki_pem)) return error.SpkiMismatch;
    std.debug.print("{s}", .{pub_pem});

    // A public key read back from the published block names the same curve.
    var pub_der: [keycodec.max_public_der_len]u8 = undefined;
    const pk = try keycodec.parsePublicKeyPem(pub_pem, &pub_der);
    if (pk.algorithm != key.algorithm) return error.AlgorithmMismatch;

    // ── files the loader must refuse, by name ───────────────────────────
    var scratch: [keycodec.max_private_der_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    const encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n";
    if (load(encrypted, &scratch) != null) return error.EncryptedAccepted;
    if (load(spki_pem, &scratch) != null) return error.PublicAccepted;
}
