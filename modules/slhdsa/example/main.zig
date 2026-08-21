// SPDX-License-Identifier: MIT

//! What a firmware-update client does with `slhdsa`: check that the image it
//! just downloaded was signed by the vendor's post-quantum release key before
//! it writes a single byte to flash. SLH-DSA is the conservative choice for
//! this job — its security rests on the hash function alone, so a device that
//! will still be in the field in fifteen years does not have to bet on a
//! lattice assumption holding.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("slhdsa")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! Nothing here touches the OS. FIPS 205 key generation takes caller-supplied
//! seed bytes, so a vendor's release pipeline feeds it an HSM-held secret and
//! this file feeds it a fixed literal; the module never reads a CSPRNG behind
//! the caller's back.

const std = @import("std");
const slhdsa = @import("slhdsa");

/// The parameter set the vendor publishes. "f" is the fast-signing / larger-
/// signature variant: a build server signs once, but every device in the field
/// pays the download, so this is a real product decision and it belongs at the
/// consumer's call site, not buried in the library.
const Scheme = slhdsa.SlhDsaSha2_128f;

/// The vendor's 48-byte key seed (`3*n` for n = 16). In production this is
/// HSM-held; here it is fixed so the example is reproducible.
const key_seed: [3 * Scheme.n]u8 = .{
    0x9c, 0x1e, 0x42, 0x77, 0x05, 0xb3, 0xda, 0x60, 0x18, 0x2f, 0xc4, 0x91, 0x3a, 0x7e, 0x56, 0x08,
    0xe1, 0x33, 0x0a, 0xbc, 0x64, 0x9f, 0x27, 0x5d, 0x80, 0x11, 0xf6, 0x4a, 0x2c, 0x73, 0x98, 0xd5,
    0x47, 0x6b, 0x1d, 0xe0, 0x52, 0x89, 0x3f, 0xa4, 0xc7, 0x08, 0x96, 0x21, 0xbe, 0x5a, 0x0f, 0x34,
};

/// A per-signature hedging value. FIPS 205 recommends it where randomness is
/// available; passing `null` gives the deterministic variant instead, and both
/// verify identically, so a signer with no entropy source is not stuck.
const hedge: [Scheme.n]u8 = @splat(0x5a);

/// The context string. This is the domain separator that keeps a firmware
/// signature from being replayed as, say, a configuration-bundle signature
/// under the same key — so the client MUST pass the same one the signer used.
const firmware_context = "vendor/firmware/v1";

const image = "\x7fELF...(pretend this is 4 MiB of firmware)";

pub fn main() !void {
    // ── the vendor's release pipeline ────────────────────────────────────
    const kp = Scheme.keyGen(key_seed);

    // The public key ships in the device's read-only partition, so it has to
    // survive a byte round-trip through storage — which means both directions
    // must be public. They are.
    const pk_bytes = kp.pk.toBytes();
    const shipped_pk = Scheme.PublicKey.fromBytes(pk_bytes);
    std.debug.print("release key: {d}-byte public key, {d}-byte signatures\n", .{
        Scheme.public_key_length,
        Scheme.signature_length,
    });

    // `sign` writes into a caller-owned buffer whose exact size is a public
    // constant — a device with no allocator can size its download slot at
    // compile time, which is the whole reason `signature_length` is exported.
    var sig: [Scheme.signature_length]u8 = undefined;
    Scheme.sign(&sig, image, kp.sk, firmware_context, hedge) catch |err| switch (err) {
        // The one thing that can go wrong on the signing side, and it is a
        // programming error in the caller's context string, not a crypto
        // failure — worth naming so a build pipeline reports it usefully.
        error.ContextTooLong => {
            std.debug.print("context string exceeds the FIPS 205 limit of 255 bytes\n", .{});
            return;
        },
    };

    // ── the device ───────────────────────────────────────────────────────
    // `verify` returns a bool, not an error union: a caller that writes `try`
    // here has written nothing at all.
    if (!Scheme.verify(&sig, image, shipped_pk, firmware_context)) {
        return error.HonestFirmwareRejected;
    }
    std.debug.print("image accepted under the shipped public key\n", .{});

    // ── the rejections a caller must handle ──────────────────────────────
    // 1. A flipped byte anywhere in the image. This is the ordinary case: a
    //    corrupted or substituted download.
    var tampered = image.*;
    tampered[1] ^= 0x01;
    if (Scheme.verify(&sig, &tampered, shipped_pk, firmware_context)) {
        return error.TamperedImageAccepted;
    }
    std.debug.print("tampered image rejected\n", .{});

    // 2. The same signature offered under a DIFFERENT context. This is the
    //    attack the context string exists to stop: a genuine, vendor-issued
    //    signature over these exact bytes, replayed into a slot that expects
    //    a different kind of artifact. It must fail even though nothing about
    //    the image or the key is wrong.
    if (Scheme.verify(&sig, image, shipped_pk, "vendor/config/v1")) {
        return error.CrossContextReplayAccepted;
    }
    std.debug.print("cross-context replay rejected\n", .{});

    // 3. A truncated download. `verify` must return false rather than read
    //    past the buffer or panic, because the length is attacker-controlled.
    if (Scheme.verify(sig[0 .. Scheme.signature_length - 1], image, shipped_pk, firmware_context)) {
        return error.TruncatedSignatureAccepted;
    }
    std.debug.print("truncated signature rejected\n", .{});
}
