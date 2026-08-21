// SPDX-License-Identifier: MIT

//! What a confidential-ledger node does with `bulletproofs`: accept a transfer
//! whose amount is hidden inside a Pedersen commitment, and still refuse the
//! one thing a hidden amount makes possible — a negative value, which wraps
//! modulo the group order into a mint of free money. The sender attaches a
//! range proof; the node checks it against the commitment alone and never
//! learns the amount.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("bulletproofs")` and nothing else; `ct25519` is the
//! module's own dependency, not this file's). If a type needed to call the API
//! is not public, or an error cannot be named from outside, this file stops
//! compiling. The module's own tests cannot notice either, because they live
//! inside it.
//!
//! Two things a consumer has to internalise and this file demonstrates: the
//! generators are NUMS-derived, so prover and verifier build identical ones
//! without exchanging anything; and the Fiat-Shamir transcript is this
//! module's own, so a proof only ever verifies against this module.

const std = @import("std");
const bulletproofs = @import("bulletproofs");

/// The range width the ledger commits to. A real one uses 64; 8 keeps this
/// example's arithmetic small, and the width is part of the public statement
/// either way — an 8-bit proof does not verify against a 64-bit generator set.
const range_bits = 8;

/// The transfer amount. Secret in the real system; the whole point is that
/// nothing below this line except `prove` ever sees it.
const amount: u64 = 42;

/// The commitment blinding factor. A sender draws this from a CSPRNG and keeps
/// it: without it the commitment is just an encoding of the amount, and anyone
/// can confirm a guess. Fixed here so the example is reproducible.
const gamma: [32]u8 = .{
    0x0b, 0x74, 0x21, 0x5e, 0xa9, 0x30, 0xcd, 0x18, 0x6f, 0x02, 0x93, 0x4c, 0xe7, 0x51, 0x8a, 0x36,
    0x1d, 0xc8, 0x40, 0x7b, 0x25, 0x96, 0x0e, 0xb3, 0x58, 0x2a, 0xf1, 0x67, 0x39, 0x04, 0xdd, 0x0a,
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── both sides derive the same generators, independently ─────────────
    // No trusted setup, no exchange: `init` is a pure function of `n`. A node
    // that derived its own set from the width in the transaction header is
    // guaranteed to match the sender's.
    const gens = try bulletproofs.Generators.init(gpa, range_bits);
    defer gens.deinit(gpa);

    // ── the sender ───────────────────────────────────────────────────────
    // The commitment is what goes on the ledger. `commit` is public precisely
    // because the sender and the verifying node both need to name the same
    // point — the node receives it, the sender must produce it.
    const v_commitment = bulletproofs.commit(gens, scalarOf(amount), gamma);

    var prover_transcript: bulletproofs.Transcript = .init(bulletproofs.rangeproof_domain);
    const proof = bulletproofs.prove(gpa, gens, &prover_transcript, amount, gamma) catch |err| switch (err) {
        error.OutOfMemory => return err,
        // A wallet that lets a user type an amount wider than the ledger's
        // range must report that as a user-facing refusal, not a crash — so
        // the variant has to be nameable from out here.
        error.ValueOutOfRange => {
            std.debug.print("amount does not fit in a {d}-bit range\n", .{range_bits});
            return;
        },
    };
    defer proof.deinit(gpa);

    // The proof crosses a network, so it has to survive a byte round-trip.
    const wire = try proof.toBytesAlloc(gpa);
    defer gpa.free(wire);
    std.debug.print("range proof: {d} bytes for a {d}-bit range\n", .{ wire.len, range_bits });

    // ── the node ─────────────────────────────────────────────────────────
    const received = bulletproofs.RangeProof.fromBytesAlloc(gpa, wire) catch |err| switch (err) {
        error.OutOfMemory => return err,
        // Attacker-controlled bytes: a malformed blob is an ordinary reject,
        // never a panic.
        error.InvalidEncoding => {
            std.debug.print("proof blob does not parse, dropping transaction\n", .{});
            return;
        },
    };
    defer received.deinit(gpa);

    // The verifier starts a FRESH transcript with the same domain label. It
    // replays the challenges from the proof's own fields — which is why the
    // label is exported rather than hidden: get it wrong and every proof
    // fails, with no diagnostic distinguishing that from a forgery.
    var verifier_transcript: bulletproofs.Transcript = .init(bulletproofs.rangeproof_domain);
    if (!bulletproofs.verify(gens, &verifier_transcript, v_commitment, received)) {
        return error.HonestProofRejected;
    }
    std.debug.print("transfer accepted: amount is in range, and still secret\n", .{});

    // ── the rejections a node must handle ────────────────────────────────
    // 1. The proof replayed against a DIFFERENT commitment. This is the
    //    attack that matters: a valid proof for someone else's small amount,
    //    attached to a commitment hiding an enormous one.
    const other_commitment = bulletproofs.commit(gens, scalarOf(amount + 1), gamma);
    var replay_transcript: bulletproofs.Transcript = .init(bulletproofs.rangeproof_domain);
    if (bulletproofs.verify(gens, &replay_transcript, other_commitment, received)) {
        return error.CrossCommitmentReplayAccepted;
    }
    std.debug.print("proof replayed onto another commitment rejected\n", .{});

    // 2. A tampered response scalar. `verify` returns false rather than
    //    erroring, so a node that writes `try` here has written nothing.
    var forged = received;
    forged.t_hat[0] ^= 0x01;
    var forged_transcript: bulletproofs.Transcript = .init(bulletproofs.rangeproof_domain);
    if (bulletproofs.verify(gens, &forged_transcript, v_commitment, forged)) {
        return error.TamperedProofAccepted;
    }
    std.debug.print("tampered proof rejected\n", .{});

    // 3. The same proof offered against a wider generator set. The range
    //    width is part of the statement; a node that reads the width from the
    //    transaction instead of its own policy would otherwise accept an
    //    8-bit proof where it required 64 bits.
    const wide_gens = try bulletproofs.Generators.init(gpa, range_bits * 2);
    defer wide_gens.deinit(gpa);
    var wide_transcript: bulletproofs.Transcript = .init(bulletproofs.rangeproof_domain);
    if (bulletproofs.verify(wide_gens, &wide_transcript, v_commitment, received)) {
        return error.WrongWidthProofAccepted;
    }
    std.debug.print("narrower-range proof rejected against a wider policy\n", .{});
}

/// A `u64` as the 32-byte little-endian scalar the Ristretto255 API takes.
/// `commit` deals in scalars, not integers, because the blinding factor is
/// never an integer — so a caller that wants to commit to a plain amount does
/// this conversion itself.
fn scalarOf(v: u64) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u64, out[0..8], v, .little);
    return out;
}
