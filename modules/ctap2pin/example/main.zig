// SPDX-License-Identifier: MIT

//! What a FIDO2 platform and authenticator actually do with `ctap2pin`:
//! run the CTAP 2.1 `pinUvAuthProtocol` key-agreement handshake, exchange
//! a `pinUvAuthToken` under it, and use that token to authenticate a
//! command's `pinUvAuthParam` -- entirely offline, driving BOTH sides of
//! the exchange in one process (there is no live authenticator on this
//! machine, and none is needed: `ctap2pin` is the pure crypto layer
//! beneath the CTAP2 wire protocol, not a USB/NFC/BLE transport -- see
//! `../SPEC.md`'s "Non-goals").
//!
//! Run twice, once per protocol version (CTAP 2.1 §6.5.7 Protocol One,
//! then §6.5.8 Protocol Two) -- a second, independent session with its
//! own key pair, shared secret, and token, so state left over from the
//! first exchange (there should be none: the module has no globals and
//! every value is caller-held) cannot hide behind a single run.
//!
//! Every private scalar / token / message byte below is SYNTHETIC test
//! material this example invents on the spot (fixed byte patterns, never
//! drawn from real entropy) -- clearly not real key material, and there
//! is no real PIN or real authenticator involved anywhere.
//!
//! ⚠ WHAT COULD NOT BE EXERCISED HERE, AND WHY: a real FIDO2 authenticator
//! (hardware or platform-resident) over USB HID / NFC / BLE. This
//! machine has no such device attached and this module does not speak
//! any transport anyway (CTAP2 command framing / CBOR is a future `ctap2`
//! module's job, per `root.zig`'s own doc comment and `SPEC.md`'s
//! "Non-goals" -- `ctap2pin` is only the ECDH + AES-CBC + HMAC layer
//! underneath). What CAN be shown, and is, is that layer's actual
//! contract: two independently-computed ECDH shared secrets agreeing,
//! a token surviving encrypt-then-decrypt across the "wire", and a
//! `pinUvAuthParam` produced by one party verifying under the other's
//! copy of the same token -- the exact three properties a real
//! authenticator/platform pair relies on `ctap2pin` for.
//!
//! `ctap2pin` allocates NOWHERE (`root.zig`: every type is a fixed-size
//! array or a `std.crypto`/`p256` value type; grep confirms no
//! `Allocator` reaches any file in `src/`) -- there is no leak to check
//! in the module itself. The `DebugAllocator` below is kept only as a
//! defensive harness convention (nothing in this file allocates through
//! it either); its `deinit` still asserts no leak.
//!
//! Built against the PUBLISHED module (`@import("ctap2pin")` plus its one
//! declared dep `p256`) -- no `test_deps`, no reaching into `src/`.

const std = @import("std");
const ctap2pin = @import("ctap2pin");

/// One full key-agreement + token exchange + command-authentication
/// round, generic over the protocol version. Drives BOTH sides
/// (authenticator and platform) so the "two independently-derived shared
/// secrets agree" property is actually checked, not assumed.
fn runProtocol(comptime protocol: ctap2pin.Protocol, auth_scalar: [32]u8, platform_scalar: [32]u8) !void {
    const Impl = ctap2pin.Impl(protocol);

    // ── key agreement: both sides derive the SAME shared secret ────────
    const authenticator_pub = try ctap2pin.publicKeyFromScalar(auth_scalar);

    // Platform side: encapsulate against the authenticator's public key.
    var platform_enc = try Impl.encapsulate(platform_scalar, authenticator_pub);
    defer std.crypto.secureZero(u8, &platform_enc.shared_secret);

    // Authenticator side: independently compute Z against the platform's
    // public key (the one it just received), then this protocol's kdf.
    const z_auth = try ctap2pin.ecdhZ(auth_scalar, platform_enc.platform_key_agreement);
    var auth_secret = Impl.kdf(z_auth);
    defer std.crypto.secureZero(u8, &auth_secret);

    if (!std.mem.eql(u8, &platform_enc.shared_secret, &auth_secret)) return error.SharedSecretMismatch;
    std.debug.print("protocol {s}: platform and authenticator agree on the shared secret independently\n", .{@tagName(protocol)});

    // ── pinUvAuthToken exchange: authenticator encrypts, platform decrypts ──
    // A synthetic 32-byte token standing in for what getPinToken would
    // actually return -- never a real PIN or real token.
    const token = [_]u8{0x42} ** 32;

    if (protocol == .one) {
        var ciphertext: [32]u8 = undefined;
        try Impl.encrypt(auth_secret, &ciphertext, &token);
        var recovered: [32]u8 = undefined;
        try Impl.decrypt(platform_enc.shared_secret, &recovered, &ciphertext);
        if (!std.mem.eql(u8, &token, &recovered)) return error.TokenMismatch;
    } else {
        // Protocol Two: caller-supplied IV (the module takes it as a
        // parameter rather than drawing it internally -- see root.zig's
        // Two.encrypt doc comment); a fixed pattern here, never reused
        // as real key material.
        const iv = [_]u8{0xa5} ** 16;
        var ciphertext: [16 + 32]u8 = undefined;
        try Impl.encrypt(auth_secret, iv, &ciphertext, &token);
        var recovered: [32]u8 = undefined;
        try Impl.decrypt(platform_enc.shared_secret, &recovered, &ciphertext);
        if (!std.mem.eql(u8, &token, &recovered)) return error.TokenMismatch;
    }
    std.debug.print("protocol {s}: pinUvAuthToken survives encrypt (authenticator) -> decrypt (platform)\n", .{@tagName(protocol)});

    // ── command authentication: platform signs, authenticator verifies ──
    // A synthetic clientDataHash-shaped message, not a real WebAuthn hash.
    const client_data_hash = [_]u8{0x99} ** 32;
    const pin_uv_auth_param = Impl.authenticate(&token, &client_data_hash);
    if (!Impl.verify(&token, &client_data_hash, &pin_uv_auth_param)) return error.VerifyFailed;
    std.debug.print("protocol {s}: pinUvAuthParam computed by the platform verifies under the authenticator's copy of the token\n", .{@tagName(protocol)});

    // ── negative: a DIFFERENT token must not verify the same param ──────
    const wrong_token = [_]u8{0x43} ** 32;
    if (Impl.verify(&wrong_token, &client_data_hash, &pin_uv_auth_param)) return error.UnexpectedVerifyAccept;
    std.debug.print("protocol {s}: pinUvAuthParam rejected under a different token (verify -> false, as designed)\n", .{@tagName(protocol)});
}

/// A malformed/mismatched authenticator public key -- standing in for a
/// MITM substituting its own key, or a corrupted COSE_Key on the wire --
/// is rejected by NAME before any shared secret (right or wrong) is ever
/// derived. `(0, 0)` satisfies neither the P-256 curve equation nor
/// happens to be the point at infinity's compressed form, so
/// `fromAffineCoordinates` rejects it outright.
fn checkBadPeerKeyRejected() !void {
    const platform_scalar = [_]u8{0x02} ** 32;
    const bogus_peer = ctap2pin.PublicKey{ .x = [_]u8{0} ** 32, .y = [_]u8{0} ** 32 };
    if (ctap2pin.ecdhZ(platform_scalar, bogus_peer)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPublicKey => std.debug.print("ecdhZ against a bogus (0,0) peer key: InvalidPublicKey (expected) -- no shared secret, right or wrong, is ever produced\n", .{}),
        else => return err,
    }
}

/// A zero private scalar must be rejected at key-derivation time (CTAP
/// 2.1's own contract: "regenerate and retry") rather than silently
/// producing the point at infinity.
fn checkZeroScalarRejected() !void {
    const zero_scalar = [_]u8{0} ** 32;
    if (ctap2pin.publicKeyFromScalar(zero_scalar)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidScalar => std.debug.print("publicKeyFromScalar(0): InvalidScalar (expected)\n", .{}),
        else => return err,
    }
}

/// A wire-shaped Protocol Two ciphertext shorter than one IV cannot even
/// carry an IV, let alone a whole AES block past it -- rejected by name,
/// before any AES runs, never an out-of-bounds slice.
fn checkTruncatedCiphertextRejected() !void {
    var short: [8]u8 = undefined; // shorter than Two.iv_length (16)
    @memset(&short, 0xff);
    if (ctap2pin.Two.decryptedLength(short.len)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidLength => std.debug.print("Two.decryptedLength(8 bytes, shorter than the 16-byte IV): InvalidLength (expected)\n", .{}),
    }
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    // Nothing below actually allocates through `gpa` -- see the file
    // header. Kept only so a leak introduced by a future edit here would
    // still be caught.

    const auth_scalar = [_]u8{0x01} ** 32;
    const platform_scalar_one = [_]u8{0x02} ** 32;
    const platform_scalar_two = [_]u8{0x03} ** 32; // a genuinely different platform key pair for the second session

    try runProtocol(.one, auth_scalar, platform_scalar_one);
    try runProtocol(.two, auth_scalar, platform_scalar_two);

    try checkBadPeerKeyRejected();
    try checkZeroScalarRejected();
    try checkTruncatedCiphertextRejected();

    std.debug.print("OK: all ctap2pin example checks passed\n", .{});
}
