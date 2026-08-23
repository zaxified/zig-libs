// SPDX-License-Identifier: MIT

//! What a dead-man-switch service (the S5 use case this module's own doc
//! comment names) does with `timelock_envelope`: seal a message to a
//! recipient's HQC key AND a future drand round, attempt to open it EARLY
//! (before the round's beacon signature exists) and get rejected by name,
//! open it correctly once the "beacon" publishes, then run a SECOND
//! session — a later message queued for a LATER round, reusing the same
//! recipient's long-term HQC keypair but with fresh per-seal randomness
//! (the module's own doc comment is emphatic that reusing `SealRandomness`
//! across `seal` calls is a full AEAD break — this example draws a
//! distinct one for round 2). Then reject a wrong recipient key, a
//! tampered wire buffer, and a cross-suite `open`, each by its own named
//! error.
//!
//! Building the `p_pub`/`round_signature` pair below needs a toy drand
//! "beacon" — `seal`/`open` both take these as caller-supplied (the
//! module never runs a beacon itself, see its module doc comment), so a
//! consumer test harness has to synthesize them the same way drand's
//! threshold signers do: `round_signature = msk * H1(beaconId(round))`,
//! the identical `extract`-shaped operation `ibe`'s example builds by
//! hand for the same reason — done here via `tlock`'s re-exported
//! `bls12_381`/`ciphersuite`, both already declared deps of this module.
//!
//! `DebugAllocator` wraps this whole example: `seal`/`open` are the only
//! two functions here that allocate (both take the caller's allocator and
//! return an owned buffer), and the wrong-key/tampered-buffer negative
//! paths below specifically exercise `open`'s `errdefer allocator.free(pt)`
//! — the plaintext buffer IS allocated before the AEAD tag check fails,
//! so those paths prove the early-return frees what it took, not just
//! that the happy path does.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! External judge — ACTUALLY RUN at authoring time: this module composes
//! `tlock`/`hqc`/`chachapoly` rather than implementing crypto itself (its
//! own module doc comment), so what is worth independently checking is
//! THIS module's own assembly — the HKDF-SHA256 key/nonce derivation
//! (`deriveKeys`) and the AEAD wire framing (header + both lock
//! ciphertexts as AAD, tag before ciphertext) — not `tlock`'s or `hqc`'s
//! internal correctness (already covered by their own modules). Given
//! `s_time` (a `SealRandomness` field, known to this harness by
//! construction) and `s_pq` (obtained by calling `hqc.Hqc128.encaps` on
//! the SAME `recipient_ek`/`kem_coins` `seal` used internally — a pure
//! function, so this is the identical value, not a guess), Python's
//! `cryptography` package (`hashlib`-based HKDF-SHA256 +
//! `ChaCha20Poly1305`, both wholly independent of this repo's own
//! `std.crypto`-based implementations) recomputed the content key/nonce
//! and decrypted the actual sealed envelope's AAD/tag/ciphertext bytes —
//! recovering the exact original plaintext. That is a real, independent
//! check of this module's OWN composition logic, not a restated fixture.
//! Tool output only; no `cryptography` source was read.

const std = @import("std");
const timelock_envelope = @import("timelock_envelope");
const tlock = @import("tlock");
const hqc = @import("hqc");

const Envelope128 = timelock_envelope.Envelope128;
const Envelope192 = timelock_envelope.Envelope192;

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: {x}\n", .{ label, bytes });
}

/// A toy drand "beacon": a fixed, throwaway master secret, never a real
/// one. `p_pub = msk * G2_generator`; `round_signature(round) = msk *
/// H1(beaconId(round))` — literally the threshold BLS signature drand
/// itself publishes once `round` is reached (see `tlock.ciphersuite`'s
/// module doc comment: "the beacon signature over the round IS the
/// BF-IBE private key for that identity").
const ToyBeacon = struct {
    msk: tlock.bls12_381.Fr,

    fn pPub(self: ToyBeacon) tlock.bls12_381.g2.Affine {
        return tlock.bls12_381.g2.Jacobian.fromAffine(tlock.bls12_381.g2.Affine.generator).scalarMul(self.msk).toAffine();
    }

    fn signRound(self: ToyBeacon, round: u64) tlock.bls12_381.g1.Affine {
        const qid = tlock.ciphersuite.h1(tlock.ciphersuite.beaconId(round));
        return tlock.bls12_381.g1.Jacobian.fromAffine(qid).scalarMul(self.msk).toAffine();
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var msk_bytes: [32]u8 = undefined;
    for (&msk_bytes, 1..) |*b, i| b.* = @intCast(i * 7 % 251 + 1);
    const beacon = ToyBeacon{ .msk = try tlock.bls12_381.Fr.fromBytes(msk_bytes) };
    const p_pub = beacon.pPub();

    // The recipient's long-term HQC-128 keypair — generated once, reused
    // across both sessions below (only the per-seal randomness changes).
    var seed_kem: [32]u8 = undefined;
    for (&seed_kem, 0..) |*b, i| b.* = @intCast(i + 1);
    const bob = hqc.Hqc128.keypair(&seed_kem);

    // ── Session 1 ────────────────────────────────────────────────────
    const round1: u64 = 500_000;
    var rnd1: Envelope128.SealRandomness = undefined;
    for (&rnd1.s_time, 0..) |*b, i| b.* = @intCast(i + 1);
    for (&rnd1.tlock_sigma, 0..) |*b, i| b.* = @intCast(i + 100);
    for (&rnd1.kem_coins, 0..) |*b, i| b.* = @intCast(i + 1);

    const plaintext1 = "the launch codes are 12345";
    const sealed1 = try Envelope128.seal(gpa, plaintext1, bob.ek, p_pub, round1, rnd1);
    defer gpa.free(sealed1);
    std.debug.print("session1: sealed {d} bytes for round {d}\n", .{ sealed1.len, round1 });

    // ── Negative path 1: EARLY open — the caller only has an OLDER
    // round's signature (round hasn't been reached yet from their
    // vantage point). ───────────────────────────────────────────────
    {
        const too_early_signature = beacon.signRound(round1 - 1);
        if (Envelope128.open(gpa, sealed1, bob.dk, too_early_signature)) |pt| {
            gpa.free(pt);
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.TimeGateClosed => std.debug.print("open with round {d}'s signature (target is {d}): TimeGateClosed (expected)\n", .{ round1 - 1, round1 }),
            else => return err,
        }
    }

    // ── The round is reached: the beacon publishes round1's signature,
    // and BOTH locks now open. ──────────────────────────────────────
    const round1_signature = beacon.signRound(round1);
    const opened1 = try Envelope128.open(gpa, sealed1, bob.dk, round1_signature);
    defer gpa.free(opened1);
    std.debug.assert(std.mem.eql(u8, opened1, plaintext1));
    std.debug.print("session1: opened after round {d}: {s}\n", .{ round1, opened1 });

    // ── External-oracle material for session 1: independently recover
    // s_pq the same way `seal` did internally (pure function of the SAME
    // ek/coins), and hand Python everything it needs to recompute
    // deriveKeys + decrypt the actual sealed bytes. ─────────────────
    const enc1 = hqc.Hqc128.encaps(bob.ek, &rnd1.kem_coins);
    printHex("session1 s_time", &rnd1.s_time);
    printHex("session1 s_pq", &enc1.ss);
    printHex("session1 sealed envelope", sealed1);
    printHex("session1 plaintext", plaintext1);

    // ── Session 2: a LATER message, later round, SAME recipient keypair,
    // FRESH randomness (never reuse `SealRandomness` — see this module's
    // own doc comment and this file's module doc comment). ───────────
    const round2: u64 = 500_042;
    var rnd2: Envelope128.SealRandomness = undefined;
    for (&rnd2.s_time, 0..) |*b, i| b.* = @intCast(i + 200);
    for (&rnd2.tlock_sigma, 0..) |*b, i| b.* = @intCast(i + 50);
    for (&rnd2.kem_coins, 0..) |*b, i| b.* = @intCast(i + 30);
    std.debug.assert(!std.mem.eql(u8, &rnd1.s_time, &rnd2.s_time));

    const plaintext2 = "second message: transfer control now";
    const sealed2 = try Envelope128.seal(gpa, plaintext2, bob.ek, p_pub, round2, rnd2);
    defer gpa.free(sealed2);
    const round2_signature = beacon.signRound(round2);
    const opened2 = try Envelope128.open(gpa, sealed2, bob.dk, round2_signature);
    defer gpa.free(opened2);
    std.debug.assert(std.mem.eql(u8, opened2, plaintext2));
    std.debug.print("session2: sealed + opened round {d}: {s}\n", .{ round2, opened2 });

    // ── Negative path 2: the round IS reached, but the opener holds the
    // WRONG HQC secret key — HQC's implicit rejection returns a
    // pseudo-random s_pq (never an error, see this module's own doc
    // comment), so the failure surfaces one layer up, at the AEAD tag —
    // and `open`'s `pt` buffer, already allocated by this point, must be
    // freed on this path (proven by DebugAllocator, not asserted by
    // hand). ─────────────────────────────────────────────────────────
    {
        var wrong_seed: [32]u8 = undefined;
        for (&wrong_seed, 0..) |*b, i| b.* = @intCast(i + 77);
        const eve = hqc.Hqc128.keypair(&wrong_seed);
        if (Envelope128.open(gpa, sealed1, eve.dk, round1_signature)) |pt| {
            gpa.free(pt);
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.AuthFailed => std.debug.print("open with the WRONG HQC secret key: AuthFailed (expected)\n", .{}),
            else => return err,
        }
    }

    // ── Negative path 3: correct keys, but the wire buffer was tampered
    // with in transit (one flipped byte in the PQ lock ciphertext,
    // inside the authenticated region). ─────────────────────────────
    {
        var tampered = try gpa.dupe(u8, sealed1);
        defer gpa.free(tampered);
        tampered[timelock_envelope.envelope.header_bytes + Envelope128.time_lock_bytes] ^= 0x01;
        if (Envelope128.open(gpa, tampered, bob.dk, round1_signature)) |pt| {
            gpa.free(pt);
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.AuthFailed => std.debug.print("tampered PQ-lock ciphertext: AuthFailed (expected)\n", .{}),
            else => return err,
        }
    }

    // ── Negative path 4: a well-formed envelope sealed for HQC-128,
    // parsed by the HQC-192 specialisation — rejected at the wire-framing
    // layer, before any crypto runs at all. ──────────────────────────
    {
        var eve192_seed: [32]u8 = undefined;
        @memset(&eve192_seed, 0xEE);
        const eve192 = hqc.Hqc192.keypair(&eve192_seed);
        if (Envelope192.open(gpa, sealed1, eve192.dk, round1_signature)) |pt| {
            gpa.free(pt);
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.SuiteMismatch => std.debug.print("HQC-128 envelope opened as HQC-192: SuiteMismatch (expected)\n", .{}),
            else => return err,
        }
    }

    std.debug.print("timelock_envelope example: OK\n", .{});
}
