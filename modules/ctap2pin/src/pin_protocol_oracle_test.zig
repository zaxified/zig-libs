// SPDX-License-Identifier: MIT
//! Asserts this module's CTAP2 PIN/UV auth protocol FRAMING reproduces real
//! output from Yubico's `python-fido2` SDK (`PinProtocolV1`/`PinProtocolV2`),
//! captured once and frozen in `pin_protocol_oracle_vectors.zig`.
//!
//! `kat_test.zig` anchors every primitive this module composes (AES-256-CBC,
//! HKDF, ECDH, HMAC) to its own official spec vector, but the composition --
//! `encapsulate` -> `kdf` -> `encrypt`/`decrypt` -> `authenticate`/`verify`,
//! exactly as CTAP2's `getPinToken`/`setPin`/`changePin` command framing uses
//! them -- had only ever been checked against itself (round-trip). This file
//! closes that gap: every assertion below compares our output against bytes a
//! real, independent implementation produced, not against our own prior
//! output.
//!
//! Covers, for both `pinUvAuthProtocol` One and Two:
//!   - `publicKeyFromScalar` / `ecdhZ` / `kdf` reproduce fido2's
//!     `encapsulate()` (platform pubkey + shared secret).
//!   - `encrypt`/`decrypt` reproduce fido2's `pinHashEnc` (the `getPinToken`
//!     wire value) byte-exact, both directions.
//!   - `encrypt`/`decrypt` reproduce a simulated authenticator-issued
//!     `pinUvAuthToken` ciphertext byte-exact, both directions.
//!   - `authenticate`/`verify` reproduce `pinUvAuthParam` in both shapes CTAP2
//!     uses it: keyed by the shared secret (the `setPin`/`getPinToken` wire
//!     MAC) and keyed by the decrypted `pinUvAuthToken` (the per-command MAC
//!     over `clientDataHash`).

const std = @import("std");
const t = std.testing;
const ctap2pin = @import("root.zig");
const o = @import("pin_protocol_oracle_vectors.zig");

const One = ctap2pin.One;
const Two = ctap2pin.Two;

fn hx(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

const platform_scalar = hx(o.inputs.platform_scalar);
const auth_pub = ctap2pin.PublicKey{
    .x = hx(o.inputs.auth_pub_x),
    .y = hx(o.inputs.auth_pub_y),
};
const client_data_hash = hx(o.inputs.client_data_hash);

test "oracle: publicKeyFromScalar reproduces fido2's platform key-agreement pubkey" {
    const pk = try ctap2pin.publicKeyFromScalar(platform_scalar);
    try t.expectEqualSlices(u8, &hx(o.v1.platform_x), &pk.x);
    try t.expectEqualSlices(u8, &hx(o.v1.platform_y), &pk.y);
    // Key derivation doesn't depend on the PIN/UV protocol -- fido2 minted
    // the identical platform pubkey for both V1 and V2 in the same capture.
    try t.expectEqualSlices(u8, &hx(o.v2.platform_x), &pk.x);
    try t.expectEqualSlices(u8, &hx(o.v2.platform_y), &pk.y);
}

test "oracle: protocol One kdf(ecdhZ) reproduces fido2's PinProtocolV1 shared secret" {
    const z = try ctap2pin.ecdhZ(platform_scalar, auth_pub);
    const secret = One.kdf(z);
    try t.expectEqualSlices(u8, &hx(o.v1.shared_secret), &secret);
}

test "oracle: protocol Two kdf(ecdhZ) reproduces fido2's PinProtocolV2 shared secret" {
    const z = try ctap2pin.ecdhZ(platform_scalar, auth_pub);
    const secret = Two.kdf(z);
    try t.expectEqualSlices(u8, &hx(o.v2.shared_secret), &secret);
}

test "oracle: protocol One reproduces fido2's pinHashEnc (getPinToken wire value)" {
    const secret = One.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const pin_hash = hx(o.v1.pin_hash);
    var enc: [16]u8 = undefined;
    try One.encrypt(secret, &enc, &pin_hash);
    try t.expectEqualSlices(u8, &hx(o.v1.pin_hash_enc), &enc);
    // And the reverse: fido2's ciphertext decrypts to the same pin_hash.
    var dec: [16]u8 = undefined;
    try One.decrypt(secret, &dec, &hx(o.v1.pin_hash_enc));
    try t.expectEqualSlices(u8, &pin_hash, &dec);
}

test "oracle: protocol Two reproduces fido2's pinHashEnc (getPinToken wire value)" {
    const secret = Two.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const pin_hash = hx(o.v2.pin_hash);
    const wire = hx(o.v2.pin_hash_enc); // fido2's IV || ciphertext
    const iv = wire[0..16].*;
    var enc: [32]u8 = undefined;
    try Two.encrypt(secret, iv, &enc, &pin_hash);
    try t.expectEqualSlices(u8, &wire, &enc);
    var dec: [16]u8 = undefined;
    try Two.decrypt(secret, &dec, &wire);
    try t.expectEqualSlices(u8, &pin_hash, &dec);
}

test "oracle: protocol One reproduces a simulated authenticator pinUvAuthToken exchange" {
    const secret = One.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const token = hx(o.v1.pin_uv_token);
    var enc: [16]u8 = undefined;
    try One.encrypt(secret, &enc, &token);
    try t.expectEqualSlices(u8, &hx(o.v1.pin_uv_token_enc), &enc);
    var dec: [16]u8 = undefined;
    try One.decrypt(secret, &dec, &hx(o.v1.pin_uv_token_enc));
    try t.expectEqualSlices(u8, &token, &dec);
}

test "oracle: protocol Two reproduces a simulated authenticator pinUvAuthToken exchange" {
    const secret = Two.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const token = hx(o.v2.pin_uv_token);
    const wire = hx(o.v2.pin_uv_token_enc);
    const iv = wire[0..16].*;
    var enc: [48]u8 = undefined;
    try Two.encrypt(secret, iv, &enc, &token);
    try t.expectEqualSlices(u8, &wire, &enc);
    var dec: [32]u8 = undefined;
    try Two.decrypt(secret, &dec, &wire);
    try t.expectEqualSlices(u8, &token, &dec);
}

test "oracle: protocol One pinUvAuthParam reproduces fido2, both keying shapes" {
    const secret = One.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const token = hx(o.v1.pin_uv_token);
    // setPin/getPinToken shape: authenticate(sharedSecret, pinHashEnc).
    const sig_shared = One.authenticate(&secret, &hx(o.v1.pin_hash_enc));
    try t.expectEqualSlices(u8, &hx(o.v1.pin_uv_param_over_pin_hash_enc), &sig_shared);
    try t.expect(One.verify(&secret, &hx(o.v1.pin_hash_enc), &sig_shared));
    // command shape: authenticate(pinUvAuthToken, clientDataHash) — this is
    // exactly the call the previous `SharedSecret`-typed signature could not
    // express for protocol Two (see root.zig's authenticate/verify docs).
    const sig_token = One.authenticate(&token, &client_data_hash);
    try t.expectEqualSlices(u8, &hx(o.v1.pin_uv_param_over_client_data_hash), &sig_token);
    try t.expect(One.verify(&token, &client_data_hash, &sig_token));
}

test "oracle: protocol Two pinUvAuthParam reproduces fido2, both keying shapes" {
    const secret = Two.kdf(try ctap2pin.ecdhZ(platform_scalar, auth_pub));
    const token = hx(o.v2.pin_uv_token);
    const sig_shared = Two.authenticate(&secret, &hx(o.v2.pin_hash_enc));
    try t.expectEqualSlices(u8, &hx(o.v2.pin_uv_param_over_pin_hash_enc), &sig_shared);
    try t.expect(Two.verify(&secret, &hx(o.v2.pin_hash_enc), &sig_shared));
    // The 32-byte pinUvAuthToken as key — categorically impossible to pass
    // through the old `key: SharedSecret` ([64]u8) signature.
    const sig_token = Two.authenticate(&token, &client_data_hash);
    try t.expectEqualSlices(u8, &hx(o.v2.pin_uv_param_over_client_data_hash), &sig_token);
    try t.expect(Two.verify(&token, &client_data_hash, &sig_token));
}
