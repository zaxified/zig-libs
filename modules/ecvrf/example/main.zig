// SPDX-License-Identifier: MIT

//! What a relying party and two independent VRF holders do with `ecvrf`:
//! two provers (Alice, Bob) each hold their own key and prove over the
//! SAME public input, plus one prover proves over TWO different inputs
//! (rounds) under one key — the shape a real deployment takes (a
//! validator's key is fixed across many blocks/rounds; `alpha_string`
//! changes every round). For every proof, both the direct
//! `proofToHash(pi)` path and the `verify(pk, alpha, pi)` path are driven
//! and checked to agree — that agreement, not either call alone, is what a
//! relying party depends on.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `ecvrf` allocates nowhere — `SecretKey`/
//! `PublicKey`/`Proof`/`Output` are fixed-size byte arrays and every
//! function (`prove`, `proofToHash`, `verify`, `decodeProof`,
//! `validateKey`) operates on stack values only, so there is nothing for a
//! leak detector to watch.
//!
//! `modules/ecvrf/src/kat_test.zig` already drives RFC 9381 Appendix B.3's
//! three official ECVRF-EDWARDS25519-SHA512-TAI vectors (every published
//! intermediate value) through this module — this file does NOT restate
//! that table. Every secret key/alpha below is FRESH (SHA-256 of an
//! example-specific label), none of it any of the three vectors' values.
//!
//! External oracle: NONE was run, and that is reported honestly rather
//! than glossed over. No maintained, license-clear Python/OpenSSL
//! implementation of RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI specifically
//! (as opposed to the differently-keyed VRF constructions some
//! blockchain SDKs ship, e.g. Algorand's ECVRF-ED25519-SHA512-Elgamal
//! naming from the pre-RFC draft) was found: a pip package literally
//! named `vrf` exists, but its author/license are unlisted and its
//! construction is unidentified, so per this repo's "verify a license
//! BEFORE reading" rule it was left uninstalled/unused rather than
//! trusted as a judge. In its place, this file leans on the properties
//! RFC 9381 itself guarantees and that a relying party actually relies
//! on: `prove` is DETERMINISTIC (same `(sk, alpha)` always yields the same
//! `pi`, checked below by calling it twice), `proofToHash(pi)` and
//! `verify(pk, alpha, pi)` must agree on `beta` whenever `pi` is valid,
//! and two different provers (or the same prover on two different inputs)
//! must not collide. RFC 9381 Appendix B.3's official vectors remain the
//! real external judge for byte-exact correctness, already exercised at
//! the module level.

const std = @import("std");
const ecvrf = @import("ecvrf");

fn keyFromLabel(label: []const u8) ecvrf.SecretKey {
    var sk: ecvrf.SecretKey = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &sk, .{});
    return sk;
}

pub fn main() !void {
    // ── two independent VRF holders ───────────────────────────────────
    const alice_sk = keyFromLabel("zig-libs ecvrf example alice secret key");
    const bob_sk = keyFromLabel("zig-libs ecvrf example bob secret key");
    const alice_pk = ecvrf.publicKey(alice_sk);
    const bob_pk = ecvrf.publicKey(bob_sk);
    std.debug.print("alice pk: {x}\n", .{alice_pk});
    std.debug.print("bob pk:   {x}\n", .{bob_pk});

    const round1_alpha = "zig-libs ecvrf example: round 1 seed / block height 1000";
    const round2_alpha = "zig-libs ecvrf example: round 2 seed / block height 1001";

    // ── round 1: alice proves, a relying party verifies ──────────────────
    const pi1 = ecvrf.prove(alice_sk, round1_alpha);
    const beta1_direct = try ecvrf.proofToHash(pi1);
    const beta1_verify = try ecvrf.verify(alice_pk, round1_alpha, pi1);
    std.debug.assert(std.mem.eql(u8, &beta1_direct, &beta1_verify));
    std.debug.print("round 1: proofToHash and verify agree on beta\n", .{});

    // Determinism (RFC 9381's uniqueness property, and the module's own
    // "no hidden state" property — same (sk, alpha) in, byte-identical pi
    // out, every time; nothing carried between calls).
    const pi1_again = ecvrf.prove(alice_sk, round1_alpha);
    std.debug.assert(std.mem.eql(u8, &pi1, &pi1_again));
    std.debug.print("round 1: prove is deterministic (same pi both times)\n", .{});

    // ── round 2: the SAME key, a DIFFERENT round's input ──────────────
    const pi2 = ecvrf.prove(alice_sk, round2_alpha);
    const beta2 = try ecvrf.verify(alice_pk, round2_alpha, pi2);
    std.debug.assert(!std.mem.eql(u8, &beta1_direct, &beta2));
    std.debug.print("round 2: fresh beta, distinct from round 1\n", .{});

    // ── bob proves over round 1's SAME alpha, under his OWN key ─────────
    // The unbiasable property a relying party depends on: two different
    // keys over the identical input do not collide.
    const pi_bob = ecvrf.prove(bob_sk, round1_alpha);
    const beta_bob = try ecvrf.verify(bob_pk, round1_alpha, pi_bob);
    std.debug.assert(!std.mem.eql(u8, &beta1_direct, &beta_bob));
    std.debug.print("round 1, bob's key: fresh beta, distinct from alice's\n", .{});

    // Bob's proof is not valid under Alice's public key, even for the same
    // alpha and even though both proofs decode structurally.
    if (ecvrf.verify(alice_pk, round1_alpha, pi_bob)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidProof => std.debug.print("bob's proof under alice's key: InvalidProof (expected)\n", .{}),
        else => return err,
    }

    // ── negative paths: named errors only ─────────────────────────────

    // (1) A tampered Gamma (the proof's first 32 bytes) must be rejected
    // by the challenge-comparison step, not silently accepted.
    var tampered_pi = pi1;
    tampered_pi[0] ^= 0x01;
    if (ecvrf.verify(alice_pk, round1_alpha, tampered_pi)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidProof => std.debug.print("tampered Gamma byte: InvalidProof (expected)\n", .{}),
        error.InvalidPublicKey => return error.WrongNamedError,
    }

    // (2) The right proof, the wrong alpha.
    if (ecvrf.verify(alice_pk, round2_alpha, pi1)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidProof => std.debug.print("proof replayed under a different alpha: InvalidProof (expected)\n", .{}),
        error.InvalidPublicKey => return error.WrongNamedError,
    }

    // (3) A structurally-valid-looking but low-order public key: the
    // canonical encoding of the curve identity point (y=1, x=0 -> little-
    // endian y with sign bit 0 is byte 0x01 followed by 31 zero bytes).
    // `ECVRF_validate_key` (RFC 9381 §5.4.5) must reject it even though
    // `Edwards25519.fromBytes` decodes it as a structurally valid point.
    var identity_pk: ecvrf.PublicKey = [_]u8{0} ** 32;
    identity_pk[0] = 0x01;
    if (ecvrf.validateKey(identity_pk)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPublicKey => std.debug.print("identity-element public key: InvalidPublicKey (expected, validateKey)\n", .{}),
        error.InvalidProof => return error.WrongNamedError,
    }
    // The same rejection must surface through the full verify() path too.
    if (ecvrf.verify(identity_pk, round1_alpha, pi1)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPublicKey => std.debug.print("identity-element public key via verify(): InvalidPublicKey (expected)\n", .{}),
        error.InvalidProof => return error.WrongNamedError,
    }

    // (4) `decodeProof`'s own named error: `s >= q` (a non-canonical
    // scalar) — the well-known public edwards25519 group order `L`, not a
    // value derived from any secret. Structurally otherwise a fine-looking
    // proof (Gamma copied from the real pi1).
    const l_bytes = blk: {
        var out: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010") catch unreachable;
        break :blk out;
    };
    var noncanonical_pi = pi1;
    noncanonical_pi[ecvrf.pt_len + ecvrf.c_len ..][0..ecvrf.q_len].* = l_bytes;
    if (ecvrf.decodeProof(noncanonical_pi)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidProof => std.debug.print("s == group order L (non-canonical): InvalidProof (expected, decodeProof)\n", .{}),
        error.InvalidPublicKey => return error.WrongNamedError,
    }
}
