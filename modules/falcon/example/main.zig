// SPDX-License-Identifier: MIT

//! What a firmware-signing pipeline does with `falcon`: sign a release
//! manifest with a post-quantum lattice signature, publish the 897-byte
//! public key once into the device's ROM, and have the device refuse
//! anything that does not verify against it. Falcon is the reason to bother:
//! its signatures are ~650 bytes where a Dilithium one is ~2.4 kB, which on a
//! device that must hold the whole update in RAM is the difference between
//! fitting and not.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("falcon")` and nothing else). If a type needed to call
//! the API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! Both roles run here: the build server (keygen + sign) and the device
//! (decode + verify). In reality only the second half ships to the device,
//! and it needs nothing but `PublicKey.fromBytes` and `verify`.

const std = @import("std");
const falcon = @import("falcon");

/// The release manifest being signed — in practice a digest list, here the
/// bytes themselves.
const manifest = "firmware 4.2.1 sha256=9f2c…";

pub fn main() !void {
    // ── build server: key generation ─────────────────────────────────────
    // `generateKeyPair` takes the entropy source as a plain `std.Random`, so
    // the caller owns that choice entirely. A SEEDED PRNG is used here only
    // so this program is reproducible; a build server MUST pass a
    // CSPRNG-backed `std.Random`, because the NTRU basis this draws IS the
    // private key.
    var prng = std.Random.DefaultPrng.init(0x8f2a_1c73_55d0_9e41);
    const rng = prng.random();

    const pair = falcon.generateKeyPair(rng) catch |err| switch (err) {
        // Keygen rejects a candidate `f` that is not invertible mod q and
        // normally retries internally; surfacing it means the draw was
        // pathological, and the caller's move is to draw again.
        error.NotInvertible => {
            std.debug.print("keygen drew a non-invertible basis, retry\n", .{});
            return;
        },
    };

    // What goes into ROM: header byte + 14-bit-packed h. Fixed size, so a
    // device can reserve the slot at link time.
    const rom_key: [falcon.PublicKey.encoded_length]u8 = pair.public_key.toBytes();
    std.debug.print("public key: {d} bytes burned into ROM\n", .{rom_key.len});

    // ── build server: sign ───────────────────────────────────────────────
    // The nonce and signature travel separately: 40 bytes of salt plus a
    // variable-length compressed field, whose ceiling is a public constant
    // so the caller can size a static buffer.
    var nonce: [falcon.nonce_length]u8 = undefined;
    var sig_buf: [falcon.max_sig_field_length]u8 = undefined;
    const sig_len = falcon.signRandomized(&pair.signing_key, manifest, rng, &nonce, &sig_buf) catch |err| switch (err) {
        error.NoSpaceLeft => return err, // cannot happen with max_sig_field_length
    };
    const sig_field = sig_buf[0..sig_len];
    std.debug.print("signature: {d} bytes (+{d} nonce)\n", .{ sig_field.len, nonce.len });

    // There is no deterministic signing mode, deliberately: two signatures
    // over one message under one key are DIFFERENT, and a caller that
    // expected byte-equality to mean "same release" needs to compare the
    // manifest instead.
    var second_nonce: [falcon.nonce_length]u8 = undefined;
    var second_buf: [falcon.max_sig_field_length]u8 = undefined;
    const second_len = try falcon.signRandomized(&pair.signing_key, manifest, rng, &second_nonce, &second_buf);
    if (std.mem.eql(u8, sig_field, second_buf[0..second_len])) return error.SigningWasDeterministic;

    // ── device: decode the ROM key ───────────────────────────────────────
    // The device does not trust its own flash: a bit-rotted key must be
    // caught here rather than turning every update into a mystery failure.
    const device_key = falcon.PublicKey.fromBytes(&rom_key) catch |err| switch (err) {
        error.InvalidPublicKey => {
            std.debug.print("ROM key corrupt — refusing all updates\n", .{});
            return;
        },
    };

    // ── device: verify ───────────────────────────────────────────────────
    device_key.verify(manifest, &nonce, sig_field) catch |err| switch (err) {
        error.InvalidSignature, error.SignatureVerificationFailed => return error.HonestUpdateRejected,
    };
    std.debug.print("manifest verified — update accepted\n", .{});

    // ── the rejection a caller must handle ───────────────────────────────
    // A flipped byte in the manifest yields a well-formed signature over the
    // wrong message: the lattice norm check fails. This is the ordinary
    // attack case, and it is a DIFFERENT error from a malformed blob — a
    // device wants to log "tampered image" separately from "truncated
    // download", and the two are distinguishable by name.
    const tampered = "firmware 4.2.2 sha256=9f2c…";
    if (device_key.verify(tampered, &nonce, sig_field)) |_| {
        return error.TamperedManifestAccepted;
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("tampered manifest rejected\n", .{}),
        error.InvalidSignature => return error.WrongRejectionReason,
    }

    // A download cut short does not even decode.
    if (device_key.verify(manifest, &nonce, sig_field[0 .. sig_len / 2])) |_| {
        return error.TruncatedSignatureAccepted;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("truncated signature rejected\n", .{}),
        error.SignatureVerificationFailed => return error.WrongRejectionReason,
    }

    // ── persisting the private key ───────────────────────────────────────
    // The signing key serialises to the standard 1281-byte encoding, and
    // that blob decodes back into a `SecretKey` which can recompute the
    // public key — enough for an auditor to confirm a stored key matches a
    // published one.
    //
    // It is NOT enough to sign again. `signRandomized` wants a `SigningKey`
    // (the NTRU basis plus its ffSampling tree) and only `generateKeyPair`
    // produces one; the wire encoding deliberately omits the `G` half of the
    // basis, and nothing here recovers it. So an appliance that restarts has
    // to keep the generated key in memory for its whole life, or rotate.
    const stored: [falcon.SecretKey.encoded_length]u8 = pair.signing_key.toSecretKeyBytes();
    const reloaded = falcon.SecretKey.fromBytes(&stored) catch |err| switch (err) {
        error.InvalidSecretKey => {
            std.debug.print("stored private key is corrupt\n", .{});
            return;
        },
    };
    const recomputed = reloaded.publicKey() catch |err| switch (err) {
        // `f` not invertible mod q means the stored bytes are not a Falcon
        // basis at all, however well-formed they looked.
        error.InvalidSecretKey => return error.StoredKeyIsNotABasis,
    };
    if (!std.mem.eql(u8, &recomputed.toBytes(), &rom_key)) return error.StoredKeyDoesNotMatchRom;
    std.debug.print("stored private key re-derives the published public key\n", .{});

    // ── interop with the reference implementation's envelope ─────────────
    // Falcon's NIST API ships one blob: 2-byte big-endian signature length,
    // nonce, message, signature. `openNistSignedMessage` reads that layout
    // and hands back the message. Nothing in the module WRITES it, so a
    // consumer talking to a reference-implementation peer assembles the four
    // fields by hand — as below.
    var envelope: [2 + falcon.nonce_length + manifest.len + falcon.max_sig_field_length]u8 = undefined;
    std.mem.writeInt(u16, envelope[0..2], @intCast(sig_len), .big);
    envelope[2..][0..falcon.nonce_length].* = nonce;
    @memcpy(envelope[2 + falcon.nonce_length ..][0..manifest.len], manifest);
    @memcpy(envelope[2 + falcon.nonce_length + manifest.len ..][0..sig_len], sig_field);
    const envelope_len = 2 + falcon.nonce_length + manifest.len + sig_len;

    const opened = try falcon.openNistSignedMessage(&device_key, envelope[0..envelope_len]);
    if (!std.mem.eql(u8, opened, manifest)) return error.EnvelopeOpenedWrongMessage;
    std.debug.print("NIST envelope opened: \"{s}\"\n", .{opened});
}
