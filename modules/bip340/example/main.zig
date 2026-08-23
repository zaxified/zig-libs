// SPDX-License-Identifier: MIT

//! What a signer (and the peer who checks its work) does with `bip340`:
//! derive two keys, sign two messages under one of them across two
//! independent sessions (fresh `aux_rand` each time — the module's own
//! sign() doc calls reuse dangerous), verify all three signatures, batch
//! verify a mixed-signer set and then watch the same batch fail once one
//! signature is corrupted, and hit every public error by name at the wire
//! boundary a real deserializer sits behind.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `bip340` allocates nowhere (plain value
//! types over `k256`'s curve group — `KeyPair`, `Signature`, `sign`,
//! `verify`, `verifyBatch` all operate on fixed-size arrays on the stack),
//! so there is nothing for a leak detector to watch.
//!
//! `modules/bip340/src/kat_test.zig` already drives all 19 official BIP340
//! test vectors through this module — this file does NOT restate that
//! table. Every key/message/aux_rand below is FRESH (SHA-256 of an
//! example-specific label), none of it any of the 19 vectors' values.
//!
//! External judge — ACTUALLY RUN: a from-spec Python re-implementation of
//! BIP340 sign/verify (tagged hash + lift_x + the sign/verify equations
//! written directly from the BIP340 spec text, never copied from any
//! implementation; point add/scalar-mul borrowed from the MIT-licensed
//! `ecdsa` package's SECP256k1 group, the same shape the `taproot` example
//! uses for its own cross-check). That re-implementation was first
//! sanity-checked byte-exact — derived pubkey, signature, and verify —
//! against official BIP340 vector index 0, THEN used to compute every
//! pubkey/signature constant embedded below. It agrees with this module on
//! all of them.
//!
//! `sign`'s mandatory self-verification (step 10) means an internal
//! computation bug fails CLOSED as `error.SignatureVerificationFailed`
//! rather than silently returning a bad signature — worth knowing as a
//! consumer: `sign` can fail even when the secret key is fine.

const std = @import("std");
const bip340 = @import("bip340");

fn hexBytes(comptime hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexSig(comptime hex: *const [128]u8) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// SHA-256("zig-libs bip340 example ...") — fresh, fabricated example
// material, cross-checked (pubkeys + signatures) against the from-spec
// Python re-implementation described above.
const alice_sk_bytes = hexBytes("be0c249c963f5d76f769c962302d336f5c17193ca16f997ab31a8b0111518ba4");
const bob_sk_bytes = hexBytes("f587fbf108b75d372386d8aad7a7adbc5bd5ad6d0f0fff0b431c8471b29c3061");
const alice_aux1 = hexBytes("659ce7d4672bfe92d1c23f064a7d5ef2d3fb60fc7c347dbcb711e8b1e01d7fc0");
const alice_aux2 = hexBytes("575825542dd0806ac77e838adb9ad24136209a2fed3ebf43d3a7523ea8e894fc");
const bob_aux1 = hexBytes("dab609f5914e5cf00bc9cd280fc0b06d3c09ed20aa3db06b6da63981be4d74cd");
const msg1 = hexBytes("a946e145507ff911c4c745d8d8e54cdc1c15064072060dc87dacde758445f41a");
const msg2 = hexBytes("bd89ae695f798bc86ca91953943be5ae29f36dc5affec6a71b0579539f3ba807");

// ACTUALLY RUN: the from-spec Python re-implementation's derived x-only
// pubkeys, expected byte-exact.
const expected_alice_pub = hexBytes("b641b102fb8bf2700c54d1fecd3890361fc82cdc83881e4acf669b771ab6490b");
const expected_bob_pub = hexBytes("40d8a8963f1021a56cf23a997ccef5447c868f9642c2f0386989e2a727061062");
// ACTUALLY RUN: same re-implementation's signature, expected byte-exact
// (deterministic given the aux_rand constants above — a real signer draws
// fresh CSPRNG aux_rand instead of a hardcoded value).
const expected_alice_sig1 = hexSig("cff8c3a638ab9369807b07bd91e2a17a01b7da090af45232a7c68139a7308d7aaa6e10fc638214b49afd20b191b034cf00c42c9bccedeb6f3151bf5027775d31");

pub fn main() !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    // ── setup: two independent signers ──────────────────────────────────
    const alice_sk = try bip340.SecretKey.fromBytes(alice_sk_bytes);
    const bob_sk = try bip340.SecretKey.fromBytes(bob_sk_bytes);
    var alice_kp = try bip340.KeyPair.fromSecretKey(alice_sk);
    defer alice_kp.deinit();
    var bob_kp = try bip340.KeyPair.fromSecretKey(bob_sk);
    defer bob_kp.deinit();
    std.debug.assert(std.mem.eql(u8, &alice_kp.public.x, &expected_alice_pub));
    std.debug.assert(std.mem.eql(u8, &bob_kp.public.x, &expected_bob_pub));
    std.debug.print("alice pubkey: {x}\n", .{alice_kp.public.x});
    std.debug.print("bob pubkey:   {x}\n", .{bob_kp.public.x});

    // ── session 1: alice signs msg1, bob signs the same msg1 ────────────
    // Two independently keyed sessions over one message — the shape a
    // multi-party protocol checks each contribution against.
    const alice_sig1 = try bip340.sign(alice_sk, &msg1, alice_aux1, io);
    std.debug.assert(std.mem.eql(u8, &alice_sig1, &expected_alice_sig1));
    const bob_sig1 = try bip340.sign(bob_sk, &msg1, bob_aux1, io);
    std.debug.assert(bip340.verify(alice_kp.public, &msg1, try bip340.Signature.fromBytes(alice_sig1)));
    std.debug.assert(bip340.verify(bob_kp.public, &msg1, try bip340.Signature.fromBytes(bob_sig1)));
    std.debug.print("session 1: both signatures verify\n", .{});

    // ── session 2: alice signs a SECOND, unrelated message ──────────────
    // A fresh session with fresh aux_rand — exactly the repeat-use shape
    // that would surface leftover state (bip340 keeps none: `sign` takes
    // everything by value and returns a plain array, so there is nothing to
    // carry between calls).
    const alice_sig2 = try bip340.sign(alice_sk, &msg2, alice_aux2, io);
    std.debug.assert(bip340.verify(alice_kp.public, &msg2, try bip340.Signature.fromBytes(alice_sig2)));
    // Cross-session confusion must fail: session 1's signature does not
    // verify against session 2's message, even under the same key.
    std.debug.assert(!bip340.verify(alice_kp.public, &msg2, try bip340.Signature.fromBytes(alice_sig1)));
    std.debug.print("session 2: verifies; session-1 signature correctly rejected under msg2\n", .{});

    // ── batch verification: a mixed-signer set ──────────────────────────
    const good_batch = [_]bip340.BatchItem{
        .{ .pubkey = alice_kp.public, .msg = &msg1, .sig = try bip340.Signature.fromBytes(alice_sig1) },
        .{ .pubkey = bob_kp.public, .msg = &msg1, .sig = try bip340.Signature.fromBytes(bob_sig1) },
    };
    std.debug.assert(bip340.verifyBatch(&good_batch, io));
    std.debug.print("batch of 2 (alice + bob over msg1): verifies\n", .{});

    // Corrupt just bob's signature in the batch — the whole batch must
    // fail, not just silently drop the bad item.
    var corrupted_bob_sig = bob_sig1;
    corrupted_bob_sig[63] ^= 0x01;
    const bad_batch = [_]bip340.BatchItem{
        good_batch[0],
        .{ .pubkey = bob_kp.public, .msg = &msg1, .sig = try bip340.Signature.fromBytes(corrupted_bob_sig) },
    };
    std.debug.assert(!bip340.verifyBatch(&bad_batch, io));
    std.debug.print("batch with one corrupted signature: rejected\n", .{});

    // ── negative paths at the wire boundary: named errors only ─────────

    // (1) An all-zero secret key: BIP340 requires d in [1, n-1].
    if (bip340.SecretKey.fromBytes([_]u8{0} ** 32)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidSecretKey => std.debug.print("all-zero secret key: InvalidSecretKey (expected)\n", .{}),
    }

    // (2) An attacker-supplied 32-byte "pubkey" whose x has no valid
    // even-y point on the curve — the real untrusted-input shape a
    // deserializer meets before ever calling `verify`. Fresh label,
    // verified offline (via the same Python re-implementation) to be
    // off-curve, distinct from BIP340's own off-curve KAT vector.
    const off_curve_x = hexBytes("772abf9555dbca13ba55e4f64f2300199f3d4818578d4acdd3f5f30503d68033");
    if (bip340.XOnlyPublicKey.fromBytes(off_curve_x)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPublicKey => std.debug.print("off-curve x-only pubkey: InvalidPublicKey (expected)\n", .{}),
    }

    // (3) A signature whose `s` is exactly the curve order `n` (BIP340's
    // "Verification" step 3: `s` must be `< n`) — the well-known public
    // secp256k1 scalar-field order, not a value derived from any secret.
    const n_bytes = hexBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    var bad_sig_bytes: [64]u8 = undefined;
    bad_sig_bytes[0..32].* = alice_sig1[0..32].*;
    bad_sig_bytes[32..64].* = n_bytes;
    if (bip340.Signature.fromBytes(bad_sig_bytes)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("signature with s == n: InvalidSignature (expected)\n", .{}),
    }

    // (4) A signature whose `r` is exactly the field order `p` (step 2:
    // `r` must be `< p`) — again the well-known public secp256k1 field
    // order, not secret-derived.
    const p_bytes = hexBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    bad_sig_bytes[0..32].* = p_bytes;
    bad_sig_bytes[32..64].* = alice_sig1[32..64].*;
    if (bip340.Signature.fromBytes(bad_sig_bytes)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("signature with r == p: InvalidSignature (expected)\n", .{}),
    }

    // (5) `verify` never errors — it returns `false` on every failure path.
    // A bit-flipped, otherwise well-formed signature exercises that
    // boolean contract directly.
    var tampered = alice_sig1;
    tampered[0] ^= 0x01;
    std.debug.assert(!bip340.verify(alice_kp.public, &msg1, try bip340.Signature.fromBytes(tampered)));
    std.debug.print("bit-flipped signature: verify() == false (expected)\n", .{});
}
