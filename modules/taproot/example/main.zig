// SPDX-License-Identifier: MIT

//! What a Taproot wallet does with `taproot`: turn a freshly-generated
//! internal BIP340 key into a spendable Taproot output key — once for a
//! key-path-only output (no script tree at all) and once for an output
//! that commits to a script tree via its Merkle root — then sign for the
//! OUTPUT key with `tweakSecretKey`'s scalar and verify against it, the
//! exact assembly order a signer follows (tweak the pubkey to know what
//! address to receive to, tweak the secret key to know what scalar signs
//! for it).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `taproot`/`bip340` allocate nowhere
//! (plain value types over `k256`'s curve group), so there is nothing for
//! a leak detector to watch.
//!
//! `modules/taproot/src/kat_test.zig` already drives all 7 rows of the
//! official BIP341 `wallet-test-vectors.json` through this module
//! (tweak hash, tweaked pubkey + parity, tweaked privkey, plus a
//! sign->verify round-trip) — this file does NOT restate that table. Every
//! key/root/message below is FRESH (SHA-256 of an example-specific label,
//! not any of the 7 vectors' `internalPrivkey`/`merkleRoot` values).
//!
//! External judge — ACTUALLY RUN, with a caught oracle bug: `embit` (MIT,
//! a third, independent Python Bitcoin library distinct from the BIP341
//! spec authors' own vectors this module is already checked against)
//! computed `PublicKey.taproot_tweak`/`PrivateKey.taproot_tweak` for both
//! scenarios below at authoring time. Its tweaked x-only PUBKEYS matched
//! this module's exactly — but its reported PARITY did not: `embit`
//! reported even (0) for both scenarios' output key, versus this module's
//! odd (1). The tie was broken with a THIRD, from-spec re-implementation
//! (Python `hashlib` for the tagged hash + the `ecdsa` package's raw
//! secp256k1 `Point` arithmetic for `lift_x`/point-add — no BIP341 logic
//! borrowed from either `embit` or this module), first sanity-checked
//! byte-exact — tweak hash, x, AND parity — against two of BIP341's own
//! official vectors (rows 1 and 2, chosen for opposite parities, from
//! `kat_vectors.zig`) before being trusted for the fresh scenario below. It
//! agreed with THIS module (odd/1), not `embit`. Best guess at the cause:
//! `embit`'s `PublicKey.taproot_tweak` was called on `sk.get_public_key()`
//! directly, whose actual point here has odd y (`sec()[0] == 0x03`) — its
//! tweak evidently still lands on the mathematically correct x (matched),
//! but its returned parity looks hardcoded to the input point's own y
//! sign rather than recomputed for the tweaked result. Not a defect in
//! this module; recorded here because the instinct to "trust the third-
//! party oracle" would have shipped a WRONG expected value otherwise. The
//! tweaked-*secret*-key scalars were cross-checked the same way `embit`'s
//! raw scalar would have been unreliable regardless (BIP341 doesn't pin
//! which of the two valid representations {q, n-q} a re-implementation
//! returns — both sign correctly once `bip340.sign` re-normalizes): the
//! exact signature `bip340.sign` produces below (deterministic given
//! `aux_rand`) was confirmed to verify under `embit`'s own
//! `PublicKey.schnorr_verify` against the tweaked output key — a check
//! `embit`'s parity bug cannot skew, since verification recomputes parity
//! from the x-only key itself.

const std = @import("std");
const bip340 = @import("bip340");
const taproot = @import("taproot");

fn hexBytes(comptime hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// SHA-256("zig-libs taproot example internal key") / ("...merkle root") /
// ("...message") — fresh, fabricated example material, none of it any of
// the 7 official BIP341 vectors' values.
const internal_sk_bytes = hexBytes("a182ad7ca9d187a08f47226034022b3d76142318aa57a5efeda10a2a93001a1b");
const merkle_root_bytes = hexBytes("359ff81303a6f88dcb0b9436fadb34dfe5f8a7860341e93f77977581f27042db");
const message = hexBytes("da9b9399d45edcc8e52a1901c6b756d2171b024663ac6ea49d709821720054b5");
// Fixed (not random) so the signature below is reproducible byte-for-byte
// for the offline `embit` cross-check documented above — a real signer
// must use actual randomness here, not a hardcoded constant.
const aux_rand = [_]u8{0x24} ** 32;

pub fn main() !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    const internal_sk = try bip340.SecretKey.fromBytes(internal_sk_bytes);
    var internal_kp = try bip340.KeyPair.fromSecretKey(internal_sk);
    defer internal_kp.deinit();
    const internal_pub = internal_kp.public;
    // ACTUALLY RUN: embit `PrivateKey(...).get_public_key().xonly()`.
    const expected_internal_x = hexBytes("fd35c07037862d197059d2a5b7a53d0325192f7a924451ad54904b009bc8ec57");
    std.debug.assert(std.mem.eql(u8, &internal_pub.x, &expected_internal_x));

    // ── key-path-only output: no script tree at all ────────────────────────
    {
        const tweak = try taproot.tweakPublicKey(internal_pub, null);
        const expected_x = hexBytes("c5add8d76df8f1a674125667572a82b5bc499b71d457a310017e6bfcc4ffea84");
        std.debug.assert(std.mem.eql(u8, &tweak.output.x, &expected_x));
        // Parity confirmed via the from-spec re-implementation, NOT embit
        // — see file doc comment.
        std.debug.assert(tweak.output.parity == 1);
        std.debug.print("key-path-only output key: {x} parity={d}\n", .{ tweak.output.x, tweak.output.parity });

        const q_bytes = try taproot.tweakSecretKey(internal_sk, null);
        const q_sk = try bip340.SecretKey.fromBytes(q_bytes);
        const sig = try bip340.sign(q_sk, &message, aux_rand, io);
        std.debug.assert(bip340.verify(tweak.output.asXOnly(), &message, try bip340.Signature.fromBytes(sig)));
        std.debug.print("key-path-only signature: {x}\n", .{sig});
        // ACTUALLY RUN: embit's `PublicKey.schnorr_verify(sig, msg)` against
        // `tweak.output`'s xonly accepted this exact signature.
    }

    // ── script-path-committed output: a real Merkle root ───────────────────
    {
        const tweak = try taproot.tweakPublicKey(internal_pub, merkle_root_bytes);
        const expected_x = hexBytes("1355fd61d30950d5d7afbc6bfb80d6b45a202fb29932b20fb868d7292d448935");
        std.debug.assert(std.mem.eql(u8, &tweak.output.x, &expected_x));
        // Parity confirmed via the from-spec re-implementation, NOT embit
        // — see file doc comment.
        std.debug.assert(tweak.output.parity == 1);
        std.debug.print("script-committed output key: {x} parity={d}\n", .{ tweak.output.x, tweak.output.parity });

        const q_bytes = try taproot.tweakSecretKey(internal_sk, merkle_root_bytes);
        const q_sk = try bip340.SecretKey.fromBytes(q_bytes);
        const sig = try bip340.sign(q_sk, &message, aux_rand, io);
        std.debug.assert(bip340.verify(tweak.output.asXOnly(), &message, try bip340.Signature.fromBytes(sig)));
        std.debug.print("script-committed signature: {x}\n", .{sig});
        // ACTUALLY RUN: embit's `PublicKey.schnorr_verify(sig, msg)` against
        // `tweak.output`'s xonly accepted this exact signature too.

        // Sanity: committing a script tree changes the output key versus
        // the key-path-only case above, even from the same internal key.
        const keypath_only = try taproot.tweakPublicKey(internal_pub, null);
        std.debug.assert(!std.mem.eql(u8, &tweak.output.x, &keypath_only.output.x));
    }

    // ── negative paths: named errors, never a blanket catch ───────────────

    // (1) The REAL untrusted-input path: an attacker-supplied 32-byte
    // "internal pubkey" straight off the wire, off-curve. `XOnlyPublicKey.
    // fromBytes` (bip340's own front door — SHA-256("zig-libs taproot
    // example off-curve 1"), verified offline to be off-curve, distinct
    // from BIP340's own KAT off-curve vector) rejects it before `taproot`
    // ever sees it.
    {
        const off_curve_x = hexBytes("769a90c61eaf294e5e643b16cf4d1be6580b434946e320830ad6a5e04a2a5c37");
        if (bip340.XOnlyPublicKey.fromBytes(off_curve_x)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidPublicKey => std.debug.print("off-curve pubkey at the wire boundary: InvalidPublicKey (expected, bip340's own front door)\n", .{}),
        }
    }

    // (2) `taproot`'s OWN defense in depth: a caller who builds an
    // `XOnlyPublicKey` directly (bypassing `fromBytes`'s validation — e.g.
    // a value cached from elsewhere without re-validating) still gets a
    // fail-closed result out of `tweakPublicKey` itself, not a panic or a
    // garbage output key.
    {
        const off_curve_x = hexBytes("769a90c61eaf294e5e643b16cf4d1be6580b434946e320830ad6a5e04a2a5c37");
        const bypassed: bip340.XOnlyPublicKey = .{ .x = off_curve_x };
        if (taproot.tweakPublicKey(bypassed, null)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidInternalKey => std.debug.print("off-curve pubkey past the front door: InvalidInternalKey (expected, taproot's own check)\n", .{}),
            else => return err,
        }
    }
}
