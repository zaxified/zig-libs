// SPDX-License-Identifier: MIT

//! What a verifiable-credential wallet does with `bbs`: hold one signature the
//! issuer gave it over five attributes, and hand a bar's door scanner a proof
//! that reveals only two of them — the credential type and the over-18 flag —
//! while the name, the document number and the birth date stay hidden. The
//! scanner learns nothing else, and cannot link this visit to the next one,
//! because the proof is freshly randomised each time.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("bbs")`; `bls12_381` and `entropy` are the module's own
//! dependencies, not this file's). If a type needed to call the API is not
//! public, or an error cannot be named from outside, this file stops
//! compiling. The module's own tests cannot notice either, because they live
//! inside it.
//!
//! Note where the randomness enters: `proofGen` takes the blinding scalars as
//! an ordinary parameter, so the wallet decides where they come from. That is
//! what lets the draft's own deterministic vectors be reproduced without a
//! test-only code path inside the module — and it is also why this file has to
//! build an `std.Io` instance, since the production source
//! (`calculateRandomScalars`) reads through one.

const std = @import("std");
const bbs = @import("bbs");

/// The attribute vector, in the order the issuer signed it. Order is part of
/// the statement: index 1 means "over 18" to both sides or the proof means
/// nothing.
const attributes = [_][]const u8{
    "credential-type:mobile-driving-licence", // 0 — disclosed
    "over-18:true", // 1 — disclosed
    "name:A. Holder", // 2 — hidden
    "document-number:X0918342", // 3 — hidden
    "birth-date:1994-03-11", // 4 — hidden
};

/// What the door scanner is allowed to see.
const disclosed_indexes = [_]usize{ 0, 1 };

/// The header binds the signature to its issuance context (scheme version,
/// issuer policy). It is NOT hidden and both sides must supply the same bytes.
const header = "issuer:dvla/2026;scheme:mdl-v2";

/// The presentation header binds a proof to THIS presentation — the verifier's
/// nonce goes here. Without it the scanner would accept a proof replayed from
/// a previous visit.
const presentation_header = "door-scanner-nonce:6f21b8c4";

/// The issuer's key material. A real issuer draws this once from a CSPRNG and
/// keeps it in an HSM; `keyGen` takes the bytes rather than reading entropy
/// itself, so where they came from stays the caller's decision.
const issuer_key_material: [32]u8 = .{
    0x74, 0x6f, 0x0b, 0xc2, 0x91, 0x3d, 0xa8, 0x55, 0x1e, 0x07, 0xf4, 0x69, 0x2b, 0xcd, 0x30, 0x86,
    0x5a, 0x13, 0xe0, 0x47, 0x9c, 0x22, 0x6b, 0xf1, 0x08, 0xd5, 0x3e, 0x70, 0xab, 0x14, 0x59, 0x02,
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── the issuer ───────────────────────────────────────────────────────
    var sk = bbs.keyGen(&issuer_key_material, "dvla-issuance-2026", null) catch |err| switch (err) {
        // The draft's own reject conditions on the key derivation. An issuer
        // that hits one re-derives with different key_info rather than
        // shipping a key it cannot use.
        error.KeyMaterialTooShort, error.KeyInfoTooLong, error.DeriveInputTooLong, error.InvalidSecretKey => {
            std.debug.print("key material rejected by KeyGen\n", .{});
            return;
        },
    };
    defer sk.deinit();
    const pk = bbs.skToPk(sk);

    const signature = try bbs.sign(gpa, sk, pk, header, &attributes);
    std.debug.print("issued credential: {d} attributes, {d}-byte signature\n", .{
        attributes.len,
        signature.len,
    });

    // ── the wallet, on receipt ───────────────────────────────────────────
    // A holder verifies before storing: a signature that does not check now
    // is a credential that will fail at the door, and it is far better to
    // find out at the issuing desk.
    if (!try bbs.verify(gpa, pk, signature, header, &attributes)) {
        return error.IssuedCredentialRejected;
    }
    std.debug.print("wallet accepted the credential\n", .{});

    // ── the wallet, at the door ──────────────────────────────────────────
    // `proofGen` needs `3 + undisclosed` blinding scalars. Getting that count
    // wrong is a named error rather than a silent short read, which matters
    // because the count depends on the disclosure the user just chose.
    const undisclosed = attributes.len - disclosed_indexes.len;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const random_scalars = bbs.ciphersuite.calculateRandomScalars(3 + undisclosed, io);

    const proof = bbs.proofGen(
        gpa,
        pk,
        signature,
        header,
        presentation_header,
        &attributes,
        &disclosed_indexes,
        &random_scalars,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        // A wallet whose UI let the user tick an attribute that is not in
        // this credential must report that, not crash.
        error.DisclosedIndexOutOfRange, error.TooManyDisclosedIndexes => {
            std.debug.print("disclosure selection does not fit this credential\n", .{});
            return;
        },
        error.RandomScalarCountMismatch => {
            std.debug.print("blinding scalar count does not match the disclosure\n", .{});
            return;
        },
        else => return err,
    };
    defer gpa.free(proof);
    std.debug.print("presented {d}-byte proof revealing {d} of {d} attributes\n", .{
        proof.len,
        disclosed_indexes.len,
        attributes.len,
    });

    // ── the door scanner ─────────────────────────────────────────────────
    // It knows the issuer's public key, the header, its own nonce, and the
    // two attribute values it was shown. It never sees the signature.
    const shown = [_][]const u8{ attributes[0], attributes[1] };
    if (!try bbs.proofVerify(gpa, pk, proof, header, presentation_header, &shown, &disclosed_indexes)) {
        return error.HonestProofRejected;
    }
    std.debug.print("door scanner accepted: over-18 holds, identity not revealed\n", .{});

    // ── the rejections a verifier must handle ────────────────────────────
    // 1. The holder claims a different value for a disclosed attribute. The
    //    proof commits to the signed value, so a rewritten claim fails —
    //    `proofVerify` returns false, so a caller that writes `try` alone has
    //    written nothing.
    const lied = [_][]const u8{ attributes[0], "over-18:false" };
    if (try bbs.proofVerify(gpa, pk, proof, header, presentation_header, &lied, &disclosed_indexes)) {
        return error.RewrittenAttributeAccepted;
    }
    std.debug.print("rewritten disclosed attribute rejected\n", .{});

    // 2. The proof replayed at the next door, which issued its own nonce.
    //    This is what the presentation header is for; without this check a
    //    captured proof would be a reusable token.
    if (try bbs.proofVerify(gpa, pk, proof, header, "door-scanner-nonce:00000000", &shown, &disclosed_indexes)) {
        return error.ReplayedProofAccepted;
    }
    std.debug.print("proof replayed under another nonce rejected\n", .{});

    // 3. A truncated or corrupted proof blob. Attacker-controlled bytes must
    //    be a reject, never a panic.
    const corrupted = try gpa.dupe(u8, proof);
    defer gpa.free(corrupted);
    corrupted[0] ^= 0x01;
    if (try bbs.proofVerify(gpa, pk, corrupted, header, presentation_header, &shown, &disclosed_indexes)) {
        return error.CorruptProofAccepted;
    }
    std.debug.print("corrupted proof blob rejected\n", .{});

    // 4. The scanner miscounts: as many indexes as values, or nothing can be
    //    matched up. This one IS an error, not a false — a mismatch is a bug
    //    in the verifier, not a failed proof, and the distinction is what
    //    stops it being logged as an attack.
    if (bbs.proofVerify(gpa, pk, proof, header, presentation_header, &shown, disclosed_indexes[0..1])) |_| {
        return error.MismatchedDisclosureAccepted;
    } else |err| switch (err) {
        error.DisclosedMessageCountMismatch => std.debug.print("index/value count mismatch reported as a caller error\n", .{}),
        else => return err,
    }
}
