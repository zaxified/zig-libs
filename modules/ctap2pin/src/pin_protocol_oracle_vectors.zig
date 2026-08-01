// SPDX-License-Identifier: MIT
//! Real PIN/UV auth protocol framing material, captured from a live run of
//! Yubico's `python-fido2` SDK (`fido2.ctap2.pin.PinProtocolV1`/`PinProtocolV2`,
//! version 2.2.1) run once as a black-box oracle. This anchors the FRAMING
//! layer (encapsulate, pinHashEnc, the pinUvAuthToken exchange, and
//! pinUvAuthParam) that `kat_vectors.zig` does not reach -- that file anchors
//! only the underlying primitives (raw AES-256-CBC, HKDF, ECDH, HMAC), not the
//! CTAP2-specific composition on top of them, which is this module's actual
//! contribution.
//!
//! Provenance: fido2's `ec.generate_private_key` was monkeypatched for the
//! `encapsulate()` call only, to pin the "ephemeral" platform scalar to a fixed
//! test value so the capture is reproducible -- the same technique published KAT
//! tables use to fix an otherwise-random ephemeral value (e.g. RFC 5903's fixed
//! initiator/responder scalars). `encapsulate`, `encrypt`, `decrypt`,
//! `authenticate`, and `validate_token` themselves ran unmodified. All other
//! values (the authenticator scalar, client_data_hash, the simulated
//! pinUvAuthToken) were generated once via `secrets.token_bytes` and frozen.
//! Every python/cryptography-side result was cross-checked in the same run
//! (round-trip decrypt, `validate_token`) before being transcribed here; see
//! this module's NOTICE for the attribution note (python-fido2 run as a
//! black-box oracle, no source consulted or copied).

/// Fixed ECDH inputs shared by both protocols: a platform "ephemeral" scalar
/// (pinned via monkeypatch so the capture is reproducible) and a fixed
/// authenticator key-agreement keypair (`auth_scalar` -> `auth_pub_{x,y}`).
pub const inputs = .{
    .platform_scalar = "47bbb56478be492dd1dab6a5ea00d37b178a078363652d0402797aaaa0df603f",
    .auth_scalar = "4f4d86a2e5423b2f3ff57529165ec6b6ce7544585be16e3242a675bfb1eb6855",
    .auth_pub_x = "b3b9febfa1a8d2c1339fd567fda125b604d2067cc2546ca5f492f34946e8d056",
    .auth_pub_y = "ca76c93cf7d39516f5e60c6d562e9a2fd50b80f8a345a4c25bc2dc4457b33cdd",
    .client_data_hash = "1b84a09dfa3810244f8c86b0457fd7066e958690ea1f4527f38140078b3ed49e",
    .test_pin_ascii = "1234", // sha256(this)[0..16] = pin_hash below
};

/// `PinProtocolV1.encapsulate`/`.encrypt`/`.authenticate` output, captured live.
pub const v1 = .{
    .platform_x = "bb447d45ac86e09030b9d2f892152b4d6649a8666ece63768d5d32c90103e027",
    .platform_y = "3303fdc106688e38df258c8697157422fea2c1ac0a70285b856a39c940658e03",
    .shared_secret = "2a1a5e476328bf5846e62ee8e0cb43cebafbb7f8ab074db6bb3dc4ccf7433b9f",
    .pin_hash = "03ac674216f3e15c761ee1a5e255f067",
    .pin_hash_enc = "b269d22eb8f25a6c6e7f50a720d837eb",
    .pin_uv_token = "9b9fa85bad3af39ef391c1de54348d54", // simulated authenticator-issued token
    .pin_uv_token_enc = "69860db112c09275b17c910e312b173f",
    .pin_uv_param_over_pin_hash_enc = "26a53aec2d95277b019263a2118a88b8", // authenticate(shared_secret, pin_hash_enc) -- setPin/getPinToken shape
    .pin_uv_param_over_client_data_hash = "2ebaa478ec17fd822a95ff8a4210861e", // authenticate(pin_uv_token, clientDataHash) -- command shape
};

/// `PinProtocolV2.encapsulate`/`.encrypt`/`.authenticate` output, captured live.
pub const v2 = .{
    .platform_x = "bb447d45ac86e09030b9d2f892152b4d6649a8666ece63768d5d32c90103e027",
    .platform_y = "3303fdc106688e38df258c8697157422fea2c1ac0a70285b856a39c940658e03",
    .shared_secret = "01b4319a3df21ec5fbfb601f48c64bc06f650eaa0bbe958d8b674629d499f1fd395dca9348a9eb7d74fb83775dcd888ee5e3642ab6cf2cd9efa003910194bf85",
    .pin_hash = "03ac674216f3e15c761ee1a5e255f067",
    .pin_hash_enc = "2980e8a9f0488dab22f4aa8aba828542b8d027be4558211de3445638fa021eb4",
    .pin_uv_token = "b09aa8ff4768554814c16bdef13dd14822d090d4663fd19f1138df09809603d8", // simulated authenticator-issued token
    .pin_uv_token_enc = "2813081e9140b1680a5c34f3ed0e21f549bcd6843e693575f34bc8b1ce40a618be599796158f2fce1b1a790b703759c4",
    .pin_uv_param_over_pin_hash_enc = "83308a6cac0ed40609f55aa528610fdca5d4886e97cdffffba3bc20774a902f6", // authenticate(shared_secret, pin_hash_enc) -- setPin/getPinToken shape
    .pin_uv_param_over_client_data_hash = "655feb200692083b2578b594028fe5d0c3fd2261f8a9f26572052cbf1df89694", // authenticate(pin_uv_token, clientDataHash) -- command shape
};

test "oracle vectors: hex fields are well-formed" {
    const std = @import("std");
    const t = std.testing;
    inline for (.{ inputs.platform_scalar, inputs.auth_scalar, inputs.auth_pub_x, inputs.auth_pub_y, inputs.client_data_hash }) |field| {
        try t.expectEqual(@as(usize, 64), field.len);
    }
    inline for (.{ v1, v2 }) |proto| {
        try t.expectEqual(@as(usize, 64), proto.platform_x.len); // hex chars, 32 bytes
        try t.expectEqual(@as(usize, 64), proto.platform_y.len);
        try t.expectEqual(@as(usize, 32), proto.pin_hash.len); // hex chars, 16 bytes
    }
    try t.expectEqual(@as(usize, 64), v1.shared_secret.len);
    try t.expectEqual(@as(usize, 128), v2.shared_secret.len);
}
