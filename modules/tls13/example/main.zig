// SPDX-License-Identifier: MIT

//! What a TLS 1.3 engine does with `tls13`, server side, for
//! TLS_AES_256_GCM_SHA384: walk the RFC 8446 §7.1 key schedule from an
//! (EC)DHE secret to the handshake and application traffic keys, sign the
//! CertificateVerify with an ECDSA P-384 key and let the client verify it,
//! check the client's Finished in constant time, then roll the application
//! secret forward (KeyUpdate) and derive a resumption PSK for a ticket. The
//! failures a caller must be able to tell apart come back by name.
//!
//! The transcript here is a running SHA-384 over placeholder message bytes;
//! a real engine hashes the handshake messages it sends and receives.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `tls13` does not export.

const std = @import("std");
const tls13 = @import("tls13");

const ks = tls13.keyschedule.tls13;
const cv = tls13.certverify;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha384;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub fn main() !void {
    var transcript = Sha384.init(.{});
    var empty_hash: [Sha384.digest_length]u8 = undefined;
    Sha384.hash("", &empty_hash, .{});

    // No PSK: the early secret is HKDF-Extract over zeros.
    var early: [Hkdf.prk_length]u8 = undefined;
    ks.earlySecret(Hkdf, &early, &@as([Hkdf.prk_length]u8, @splat(0)));

    // ClientHello + ServerHello, then the (EC)DHE secret the key exchange produced.
    transcript.update("ClientHello...ServerHello");
    const dhe_shared: [32]u8 = @splat(0x5a);
    var hs: [Hkdf.prk_length]u8 = undefined;
    ks.deriveHandshakeSecret(Hkdf, &hs, &early, &empty_hash, &dhe_shared);
    var c_hs: [Hkdf.prk_length]u8 = undefined;
    var s_hs: [Hkdf.prk_length]u8 = undefined;
    ks.deriveHandshakeTrafficSecrets(Hkdf, &c_hs, &s_hs, &hs, &transcript.peek());
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    ks.deriveTrafficKeyIv(Hkdf, 32, 12, &key, &iv, &s_hs);
    std.debug.print("server handshake key {x}...\n", .{key[0..4]});

    // EncryptedExtensions + Certificate, then the server's CertificateVerify.
    transcript.update("EncryptedExtensions...Certificate");
    const kp = try P384.KeyPair.generateDeterministic(@splat(0x42));
    var sig_buf: [cv.maxSignatureLen(.ecdsa_secp384r1_sha384)]u8 = undefined;
    const th_cv = transcript.peek();
    const sig = try cv.sign(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = &kp.secret_key }, .server, &th_cv, null, &sig_buf);
    try cv.verify(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = kp.public_key }, .server, &th_cv, sig);
    std.debug.print("CertificateVerify: {d}-byte DER signature verified\n", .{sig.len});

    // The same signature under the client's context string is not a valid
    // client CertificateVerify, and a SHA-256-sized hash is refused before
    // any crypto runs.
    if (cv.verify(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = kp.public_key }, .client, &th_cv, sig)) |_| {
        return error.CrossContextSignatureAccepted;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("server signature refused as a client one (InvalidSignature)\n", .{}),
        else => return err,
    }
    if (cv.verify(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = kp.public_key }, .server, th_cv[0..32], sig)) |_| {
        return error.WrongHashLengthAccepted;
    } else |err| switch (err) {
        error.HashLengthMismatch => std.debug.print("32-byte hash for a SHA-384 scheme refused (HashLengthMismatch)\n", .{}),
        else => return err,
    }

    // Server Finished, then the application secrets over the transcript through it.
    transcript.update(sig);
    var s_fin_key: [Hmac.mac_length]u8 = undefined;
    ks.deriveFinishedKey(Hkdf, Hmac.mac_length, &s_fin_key, &s_hs);
    var s_verify: [Hmac.mac_length]u8 = undefined;
    ks.computeFinishedVerifyData(Hmac, &s_verify, &s_fin_key, &transcript.peek());
    transcript.update(&s_verify);
    var master: [Hkdf.prk_length]u8 = undefined;
    ks.deriveMasterSecret(Hkdf, &master, &hs, &empty_hash);
    var c_ap: [Hkdf.prk_length]u8 = undefined;
    var s_ap: [Hkdf.prk_length]u8 = undefined;
    ks.deriveApplicationTrafficSecrets(Hkdf, &c_ap, &s_ap, &master, &transcript.peek());

    // The client's Finished: compare with timing_safe.eql, never mem.eql.
    var c_fin_key: [Hmac.mac_length]u8 = undefined;
    ks.deriveFinishedKey(Hkdf, Hmac.mac_length, &c_fin_key, &c_hs);
    var expected: [Hmac.mac_length]u8 = undefined;
    ks.computeFinishedVerifyData(Hmac, &expected, &c_fin_key, &transcript.peek());
    const received = expected; // what an honest client sends
    if (!std.crypto.timing_safe.eql([Hmac.mac_length]u8, expected, received)) return error.ClientFinishedMismatch;
    transcript.update(&received);
    std.debug.print("client Finished verified\n", .{});

    // KeyUpdate: the next generation of the server's application secret.
    var s_ap1: [Hkdf.prk_length]u8 = undefined;
    ks.nextApplicationTrafficSecret(Hkdf, &s_ap1, &s_ap);
    if (std.mem.eql(u8, &s_ap1, &s_ap)) return error.KeyUpdateDidNotChangeSecret;

    // A NewSessionTicket's PSK, from the transcript through the client Finished.
    var res_master: [Hkdf.prk_length]u8 = undefined;
    ks.deriveResumptionMasterSecret(Hkdf, &res_master, &master, &transcript.peek());
    var psk: [Hkdf.prk_length]u8 = undefined;
    ks.deriveResumptionPsk(Hkdf, &psk, &res_master, &.{ 0, 1 });
    std.debug.print("resumption PSK for ticket nonce 0001: {x}...\n", .{psk[0..4]});

    std.crypto.secureZero(u8, &early);
    std.crypto.secureZero(u8, &hs);
    std.crypto.secureZero(u8, &master);
    std.crypto.secureZero(u8, &psk);
}
