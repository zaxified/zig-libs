// SPDX-License-Identifier: MIT
//! Known-answer + behavior tests for `ctap2pin` (see `kat_vectors.zig` for
//! the cited official vectors).
//!
//! Coverage:
//!   - AES-256-CBC byte-exact vs NIST SP 800-38A F.2.5 (encrypt) and
//!     F.2.6 (decrypt), plus chaining/prefix, in-place, empty-input, and
//!     length-validation behavior.
//!   - HKDF-SHA-256 byte-exact vs RFC 5869 A.1 (PRK and OKM).
//!   - HMAC-SHA-256 byte-exact vs RFC 4231 test case 2.
//!   - P-256 ECDH byte-exact vs RFC 5903 §8.1: both public keys derive
//!     from their private scalars, and both directions of the exchange
//!     produce the published `girx` as Z.
//!   - Both pinUvAuthProtocols end-to-end: two-sided `encapsulate`
//!     agreement, `decrypt(encrypt(m)) == m`, `verify(authenticate(m))`,
//!     tampered ciphertext/signature rejection, wrong-length inputs as
//!     typed errors / `false` (never panics), and the protocol-Two
//!     `IV || ciphertext` framing + kdf info-string anchoring.

const std = @import("std");
const t = std.testing;
const ctap2pin = @import("root.zig");
const v = @import("kat_vectors.zig");

const Aes256Cbc = ctap2pin.Aes256Cbc;
const One = ctap2pin.One;
const Two = ctap2pin.Two;

/// Hex → bytes for the comptime-known vectors (all of which are valid hex,
/// asserted by the well-formedness test in `kat_vectors.zig`).
fn hx(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

// ── AES-256-CBC vs NIST SP 800-38A ─────────────────────────────────────────

const cbc_key = hx(v.nist_sp800_38a_cbc_aes256.key);
const cbc_iv = hx(v.nist_sp800_38a_cbc_aes256.iv);
const cbc_pt = hx(v.nist_sp800_38a_cbc_aes256.plaintext);
const cbc_ct = hx(v.nist_sp800_38a_cbc_aes256.ciphertext);

test "NIST SP 800-38A F.2.5: AES-256-CBC encrypt byte-exact" {
    var out: [64]u8 = undefined;
    try Aes256Cbc.encrypt(&out, &cbc_pt, cbc_key, cbc_iv);
    try t.expectEqualSlices(u8, &cbc_ct, &out);
}

test "NIST SP 800-38A F.2.6: AES-256-CBC decrypt byte-exact" {
    var out: [64]u8 = undefined;
    try Aes256Cbc.decrypt(&out, &cbc_ct, cbc_key, cbc_iv);
    try t.expectEqualSlices(u8, &cbc_pt, &out);
}

test "AES-256-CBC: chaining — an n-block prefix encrypts to the CT prefix" {
    inline for (.{ 16, 32, 48 }) |len| {
        var out: [len]u8 = undefined;
        try Aes256Cbc.encrypt(&out, cbc_pt[0..len], cbc_key, cbc_iv);
        try t.expectEqualSlices(u8, cbc_ct[0..len], &out);
    }
}

test "AES-256-CBC: exact in-place encrypt and decrypt" {
    var buf: [64]u8 = cbc_pt;
    try Aes256Cbc.encrypt(&buf, &buf, cbc_key, cbc_iv);
    try t.expectEqualSlices(u8, &cbc_ct, &buf);
    try Aes256Cbc.decrypt(&buf, &buf, cbc_key, cbc_iv);
    try t.expectEqualSlices(u8, &cbc_pt, &buf);
}

test "AES-256-CBC: empty input is a no-op, not an error" {
    var out: [0]u8 = undefined;
    try Aes256Cbc.encrypt(&out, "", cbc_key, cbc_iv);
    try Aes256Cbc.decrypt(&out, "", cbc_key, cbc_iv);
}

test "AES-256-CBC: length validation (typed errors, no panic)" {
    var out: [64]u8 = undefined;
    // Input not a multiple of the block length.
    try t.expectError(error.InvalidLength, Aes256Cbc.encrypt(out[0..15], cbc_pt[0..15], cbc_key, cbc_iv));
    try t.expectError(error.InvalidLength, Aes256Cbc.decrypt(out[0..17], cbc_ct[0..17], cbc_key, cbc_iv));
    // Destination size mismatch.
    try t.expectError(error.InvalidLength, Aes256Cbc.encrypt(out[0..32], cbc_pt[0..16], cbc_key, cbc_iv));
    try t.expectError(error.InvalidLength, Aes256Cbc.decrypt(out[0..16], cbc_ct[0..32], cbc_key, cbc_iv));
}

// ── HKDF-SHA-256 vs RFC 5869 A.1 ───────────────────────────────────────────

test "RFC 5869 A.1: HKDF-SHA-256 extract + expand byte-exact" {
    const ikm = hx(v.rfc5869_a1.ikm);
    const salt = hx(v.rfc5869_a1.salt);
    const info = hx(v.rfc5869_a1.info);
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(&salt, &ikm);
    try t.expectEqualSlices(u8, &hx(v.rfc5869_a1.prk), &prk);
    var okm: [42]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&okm, &info, prk);
    try t.expectEqualSlices(u8, &hx(v.rfc5869_a1.okm), &okm);
}

// ── HMAC-SHA-256 vs RFC 4231 ───────────────────────────────────────────────

test "RFC 4231 test case 2: HMAC-SHA-256 byte-exact" {
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, v.rfc4231_tc2.data, v.rfc4231_tc2.key);
    try t.expectEqualSlices(u8, &hx(v.rfc4231_tc2.mac), &mac);
}

// ── P-256 ECDH vs RFC 5903 §8.1 ────────────────────────────────────────────

const i_priv = hx(v.rfc5903_p256.i);
const r_priv = hx(v.rfc5903_p256.r);
const gi = ctap2pin.PublicKey{ .x = hx(v.rfc5903_p256.gix), .y = hx(v.rfc5903_p256.giy) };
const gr = ctap2pin.PublicKey{ .x = hx(v.rfc5903_p256.grx), .y = hx(v.rfc5903_p256.gry) };

test "RFC 5903 8.1: P-256 public keys derive from the private scalars" {
    const gi_derived = try ctap2pin.publicKeyFromScalar(i_priv);
    try t.expectEqualSlices(u8, &gi.x, &gi_derived.x);
    try t.expectEqualSlices(u8, &gi.y, &gi_derived.y);
    const gr_derived = try ctap2pin.publicKeyFromScalar(r_priv);
    try t.expectEqualSlices(u8, &gr.x, &gr_derived.x);
    try t.expectEqualSlices(u8, &gr.y, &gr_derived.y);
}

test "RFC 5903 8.1: ECDH shared secret Z byte-exact, both directions" {
    const girx = hx(v.rfc5903_p256.girx);
    const z_initiator = try ctap2pin.ecdhZ(i_priv, gr);
    const z_responder = try ctap2pin.ecdhZ(r_priv, gi);
    try t.expectEqualSlices(u8, &girx, &z_initiator);
    try t.expectEqualSlices(u8, &girx, &z_responder);
}

test "ECDH: invalid inputs are typed errors, no panic" {
    // (x, y+1) is (with overwhelming probability, and verified for this
    // vector) not on the curve.
    var off_curve = gi;
    off_curve.y[31] +%= 1;
    try t.expectError(error.InvalidPublicKey, ctap2pin.ecdhZ(i_priv, off_curve));
    // Non-canonical coordinate (all 0xff >= p).
    const bad_coord = ctap2pin.PublicKey{ .x = @splat(0xff), .y = gi.y };
    try t.expectError(error.InvalidPublicKey, ctap2pin.ecdhZ(i_priv, bad_coord));
    // Zero and non-canonical private scalars.
    try t.expectError(error.InvalidScalar, ctap2pin.ecdhZ(@splat(0), gi));
    try t.expectError(error.InvalidScalar, ctap2pin.ecdhZ(@splat(0xff), gi));
    try t.expectError(error.InvalidScalar, ctap2pin.publicKeyFromScalar(@splat(0)));
    try t.expectError(error.InvalidScalar, ctap2pin.publicKeyFromScalar(@splat(0xff)));
}

// ── pinUvAuthProtocol One ──────────────────────────────────────────────────

test "protocol one: kdf(Z) is SHA-256(Z)" {
    const z = hx(v.rfc5903_p256.girx);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&z, &expected, .{});
    try t.expectEqualSlices(u8, &expected, &One.kdf(z));
}

test "protocol one: encapsulate agrees on both sides" {
    // Platform = RFC 5903 initiator, authenticator = responder.
    const platform = try One.encapsulate(i_priv, gr);
    try t.expectEqualSlices(u8, &gi.x, &platform.platform_key_agreement.x);
    try t.expectEqualSlices(u8, &gi.y, &platform.platform_key_agreement.y);
    // The authenticator derives the same secret from the platform's key.
    const authenticator = try One.encapsulate(r_priv, platform.platform_key_agreement);
    try t.expectEqualSlices(u8, &platform.shared_secret, &authenticator.shared_secret);
    // And it is kdf of the published Z.
    try t.expectEqualSlices(u8, &One.kdf(hx(v.rfc5903_p256.girx)), &platform.shared_secret);
}

test "protocol one: encrypt is zero-IV AES-256-CBC; decrypt round-trips" {
    const key = One.kdf(hx(v.rfc5903_p256.girx));
    const msg = "0123456789abcdef0123456789abcdefTHIRD-BLOCK-...!"; // 48 bytes
    var ct: [48]u8 = undefined;
    try One.encrypt(key, &ct, msg);
    // Same bytes as the raw CBC primitive with an all-zero IV.
    var ct_raw: [48]u8 = undefined;
    try Aes256Cbc.encrypt(&ct_raw, msg, key, @splat(0));
    try t.expectEqualSlices(u8, &ct_raw, &ct);
    // Round-trip.
    var pt: [48]u8 = undefined;
    try One.decrypt(key, &pt, &ct);
    try t.expectEqualSlices(u8, msg, &pt);
    // Wrong lengths are typed errors.
    try t.expectError(error.InvalidLength, One.encrypt(key, ct[0..15], msg[0..15]));
    try t.expectError(error.InvalidLength, One.decrypt(key, pt[0..32], &ct));
}

test "protocol one: authenticate/verify, tamper and wrong-length rejection" {
    const key = One.kdf(hx(v.rfc5903_p256.girx));
    const msg = "ctap2 pinUvAuthToken payload";
    const sig = One.authenticate(key, msg);
    try t.expectEqual(@as(usize, 16), sig.len);
    // It is the truncated full HMAC.
    var full: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&full, msg, &key);
    try t.expectEqualSlices(u8, full[0..16], &sig);
    try t.expect(One.verify(key, msg, &sig));
    // Tampered signature, tampered message, wrong key.
    var bad_sig = sig;
    bad_sig[0] ^= 0x01;
    try t.expect(!One.verify(key, msg, &bad_sig));
    try t.expect(!One.verify(key, "ctap2 pinUvAuthToken payloae", &sig));
    var other_key = key;
    other_key[31] ^= 0x80;
    try t.expect(!One.verify(other_key, msg, &sig));
    // Wrong-length signatures fail closed (including the full 32-byte MAC).
    try t.expect(!One.verify(key, msg, sig[0..15]));
    try t.expect(!One.verify(key, msg, &full));
    try t.expect(!One.verify(key, msg, ""));
}

test "protocol one: tampered ciphertext fails MAC verification" {
    // CBC alone is malleable; CTAP2 integrity = authenticate over the
    // ciphertext. Tampering must flip verify to false.
    const key = One.kdf(hx(v.rfc5903_p256.girx));
    const msg = "0123456789abcdef0123456789abcdef";
    var ct: [32]u8 = undefined;
    try One.encrypt(key, &ct, msg);
    const sig = One.authenticate(key, &ct);
    try t.expect(One.verify(key, &ct, &sig));
    ct[7] ^= 0x40;
    try t.expect(!One.verify(key, &ct, &sig));
}

// ── pinUvAuthProtocol Two ──────────────────────────────────────────────────

test "protocol two: kdf is zero-salt HKDF with the CTAP2 info strings" {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const z = hx(v.rfc5903_p256.girx);
    const secret = Two.kdf(z);
    const salt: [32]u8 = @splat(0);
    const prk = Hkdf.extract(&salt, &z);
    var hmac_key: [32]u8 = undefined;
    var aes_key: [32]u8 = undefined;
    Hkdf.expand(&hmac_key, "CTAP2 HMAC key", prk);
    Hkdf.expand(&aes_key, "CTAP2 AES key", prk);
    try t.expectEqualSlices(u8, &hmac_key, secret[0..32]);
    try t.expectEqualSlices(u8, &aes_key, secret[32..64]);
    // The two halves must differ (distinct info strings).
    try t.expect(!std.mem.eql(u8, secret[0..32], secret[32..64]));
}

test "protocol two: encapsulate agrees on both sides" {
    const platform = try Two.encapsulate(i_priv, gr);
    try t.expectEqualSlices(u8, &gi.x, &platform.platform_key_agreement.x);
    try t.expectEqualSlices(u8, &gi.y, &platform.platform_key_agreement.y);
    const authenticator = try Two.encapsulate(r_priv, platform.platform_key_agreement);
    try t.expectEqualSlices(u8, &platform.shared_secret, &authenticator.shared_secret);
    try t.expectEqualSlices(u8, &Two.kdf(hx(v.rfc5903_p256.girx)), &platform.shared_secret);
}

test "protocol two: encrypt emits IV || CBC(aesKey); decrypt round-trips" {
    const key = Two.kdf(hx(v.rfc5903_p256.girx));
    const iv = hx(v.nist_sp800_38a_cbc_aes256.iv); // any fixed 16 bytes
    const msg = "0123456789abcdef0123456789abcdef"; // 32 bytes
    try t.expectEqual(@as(usize, 48), Two.encryptedLength(msg.len));
    var ct: [48]u8 = undefined;
    try Two.encrypt(key, iv, &ct, msg);
    // Framing: leading IV, then CBC under the AES-key half.
    try t.expectEqualSlices(u8, &iv, ct[0..16]);
    var ct_raw: [32]u8 = undefined;
    try Aes256Cbc.encrypt(&ct_raw, msg, key[32..64].*, iv);
    try t.expectEqualSlices(u8, &ct_raw, ct[16..48]);
    // Round-trip.
    try t.expectEqual(@as(usize, 32), try Two.decryptedLength(ct.len));
    var pt: [32]u8 = undefined;
    try Two.decrypt(key, &pt, &ct);
    try t.expectEqualSlices(u8, msg, &pt);
    // A different IV yields a different ciphertext for the same plaintext.
    var ct2: [48]u8 = undefined;
    try Two.encrypt(key, @splat(0xa5), &ct2, msg);
    try t.expect(!std.mem.eql(u8, ct[16..48], ct2[16..48]));
    var pt2: [32]u8 = undefined;
    try Two.decrypt(key, &pt2, &ct2);
    try t.expectEqualSlices(u8, msg, &pt2);
}

test "protocol two: wrong-length inputs are typed errors, no panic" {
    const key = Two.kdf(hx(v.rfc5903_p256.girx));
    var buf: [48]u8 = undefined;
    var pt: [32]u8 = undefined;
    // Ciphertext shorter than the IV, or trailing partial block.
    try t.expectError(error.InvalidLength, Two.decryptedLength(15));
    try t.expectError(error.InvalidLength, Two.decrypt(key, pt[0..0], buf[0..15]));
    try t.expectError(error.InvalidLength, Two.decrypt(key, pt[0..1], buf[0..17]));
    try t.expectError(error.InvalidLength, Two.decrypt(key, pt[0..8], buf[0..40]));
    // IV-only ciphertext = empty plaintext, valid.
    const empty_ct = [_]u8{0x11} ** 16;
    try Two.decrypt(key, pt[0..0], &empty_ct);
    // Destination mismatches.
    try t.expectError(error.InvalidLength, Two.decrypt(key, pt[0..16], &buf));
    try t.expectError(error.InvalidLength, Two.encrypt(key, @splat(0), buf[0..32], "0123456789abcdef0123456789abcdef"));
    // Non-block plaintext.
    try t.expectError(error.InvalidLength, Two.encrypt(key, @splat(0), buf[0..31], "not-a-block-multiple"));
}

test "protocol two: authenticate/verify, tamper and wrong-length rejection" {
    const key = Two.kdf(hx(v.rfc5903_p256.girx));
    const msg = "ctap2 clientPin command payload";
    const sig = Two.authenticate(key, msg);
    try t.expectEqual(@as(usize, 32), sig.len);
    // Full HMAC under the HMAC-key half only.
    var expected: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, msg, key[0..32]);
    try t.expectEqualSlices(u8, &expected, &sig);
    try t.expect(Two.verify(key, msg, &sig));
    var bad_sig = sig;
    bad_sig[31] ^= 0x01;
    try t.expect(!Two.verify(key, msg, &bad_sig));
    try t.expect(!Two.verify(key, "ctap2 clientPin command payloae", &sig));
    // Wrong-length signatures fail closed (incl. protocol-one-style 16).
    try t.expect(!Two.verify(key, msg, sig[0..16]));
    try t.expect(!Two.verify(key, msg, ""));
}

test "protocol two: tampered ciphertext (incl. IV) fails MAC verification" {
    const key = Two.kdf(hx(v.rfc5903_p256.girx));
    const msg = "0123456789abcdef0123456789abcdef";
    var ct: [48]u8 = undefined;
    try Two.encrypt(key, @splat(0x3c), &ct, msg);
    const sig = Two.authenticate(key, &ct);
    try t.expect(Two.verify(key, &ct, &sig));
    ct[0] ^= 0x01; // tamper the IV
    try t.expect(!Two.verify(key, &ct, &sig));
    ct[0] ^= 0x01;
    ct[47] ^= 0x80; // tamper the last ciphertext byte
    try t.expect(!Two.verify(key, &ct, &sig));
}

// ── dispatch ───────────────────────────────────────────────────────────────

test "Impl(): comptime dispatch maps the wire enum to the namespaces" {
    try t.expectEqual(One, ctap2pin.Impl(.one));
    try t.expectEqual(Two, ctap2pin.Impl(.two));
    try t.expectEqual(@as(u8, 1), @intFromEnum(ctap2pin.Protocol.one));
    try t.expectEqual(@as(u8, 2), @intFromEnum(ctap2pin.Protocol.two));
    // The generic path works for both protocols.
    inline for (.{ .one, .two }) |p| {
        const P = ctap2pin.Impl(p);
        const enc = try P.encapsulate(i_priv, gr);
        const sig = P.authenticate(enc.shared_secret, "m");
        try t.expect(P.verify(enc.shared_secret, "m", &sig));
    }
}
