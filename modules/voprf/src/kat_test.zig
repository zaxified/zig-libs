// SPDX-License-Identifier: MIT
//! KAT tests: every assertion below pins a public function of `root.zig`
//! byte-exact to RFC 9497 Appendix A.1's official ristretto255-SHA512
//! vectors (OPRF + VOPRF + POPRF, including the batch-size-2 vectors),
//! plus a standalone RFC 9380 Appendix K.3 check of `expandMessageXmd`
//! and end-to-end round trips with fresh (non-vector) key material.

const std = @import("std");
const testing = std.testing;
const voprf = @import("root.zig");
const kat = @import("kat_vectors.zig");

const Element = voprf.Element;
const Proof = voprf.Proof;

// ── expand_message_xmd (RFC 9380 K.3) ────────────────────────────────────

test "expandMessageXmd matches RFC 9380 Appendix K.3 (SHA-512, ell = 1)" {
    for (kat.xmd_vectors) |v| {
        const got = voprf.expandMessageXmd(32, &.{v.msg}, kat.xmd_dst);
        try testing.expectEqualSlices(u8, &v.uniform_bytes, &got);
    }
}

// ── DeriveKeyPair (§3.2.1) reproduces skSm/pkSm for all three modes ──────

test "deriveKeyPair reproduces A.1.1 OPRF skSm" {
    const kp = try voprf.deriveKeyPair(.oprf, kat.seed, &kat.key_info);
    try testing.expectEqualSlices(u8, &kat.oprf_sk, &kp.sk);
}

test "deriveKeyPair reproduces A.1.2 VOPRF skSm and pkSm" {
    const kp = try voprf.deriveKeyPair(.voprf, kat.seed, &kat.key_info);
    try testing.expectEqualSlices(u8, &kat.voprf_sk, &kp.sk);
    try testing.expectEqualSlices(u8, &kat.voprf_pk, &kp.pk.toBytes());
}

test "deriveKeyPair reproduces A.1.3 POPRF skSm and pkSm" {
    const kp = try voprf.deriveKeyPair(.poprf, kat.seed, &kat.key_info);
    try testing.expectEqualSlices(u8, &kat.poprf_sk, &kp.sk);
    try testing.expectEqualSlices(u8, &kat.poprf_pk, &kp.pk.toBytes());
}

// ── OPRF mode (A.1.1) ────────────────────────────────────────────────────

test "OPRF A.1.1: blind, blindEvaluate, finalize, and direct evaluate all match" {
    for (kat.oprf_vectors) |v| {
        // (2) Blind reproduces BlindedElement (also pins HashToGroup,
        // hence expandMessageXmd-64 and Ristretto255.fromUniform).
        const blinded = try voprf.blind(.oprf, v.input, v.blind);
        try testing.expectEqualSlices(u8, &v.blinded_element, &blinded.toBytes());

        // (3) BlindEvaluate reproduces EvaluationElement.
        const evaluated = try voprf.blindEvaluate(kat.oprf_sk, blinded);
        try testing.expectEqualSlices(u8, &v.evaluation_element, &evaluated.toBytes());

        // (6) Finalize reproduces Output.
        const output = try voprf.finalize(v.input, v.blind, evaluated);
        try testing.expectEqualSlices(u8, &v.output, &output);

        // (7) The direct PRF agrees with the blinded round trip.
        const direct = try voprf.evaluate(.oprf, kat.oprf_sk, v.input);
        try testing.expectEqualSlices(u8, &v.output, &direct);

        // Wire-validation round trip for the transmitted elements.
        _ = try Element.fromBytes(v.blinded_element);
        _ = try Element.fromBytes(v.evaluation_element);
    }
}

// ── VOPRF mode (A.1.2) ───────────────────────────────────────────────────

test "VOPRF A.1.2: blind, blindEvaluate+proof, verify, finalize all match" {
    const pk = try Element.fromBytes(kat.voprf_pk);
    for (kat.voprf_vectors) |v| {
        const blinded = try voprf.blind(.voprf, v.input, v.blind);
        try testing.expectEqualSlices(u8, &v.blinded_element, &blinded.toBytes());

        // (3)+(4) BlindEvaluate reproduces EvaluationElement AND the
        // DLEQ Proof byte-exact given the vector's ProofRandomScalar.
        const eval = try voprf.blindEvaluateVerifiable(kat.voprf_sk, pk, blinded, v.proof_random_scalar);
        try testing.expectEqualSlices(u8, &v.evaluation_element, &eval.evaluated_element.toBytes());
        try testing.expectEqualSlices(u8, &v.proof, &eval.proof.toBytes());

        // (5) verifyProof accepts the published proof...
        const proof = try Proof.fromBytes(v.proof);
        try voprf.verifyProof(
            .voprf,
            Element.generator,
            pk,
            &.{blinded},
            &.{eval.evaluated_element},
            proof,
        );

        // ...and REJECTS tampered ones (flip a bit in c, in s, and swap
        // the statement's public key) — always the typed error.
        var bad_c = proof;
        bad_c.c[0] ^= 0x01;
        try testing.expectError(error.InvalidProof, voprf.verifyProof(
            .voprf,
            Element.generator,
            pk,
            &.{blinded},
            &.{eval.evaluated_element},
            bad_c,
        ));
        var bad_s = proof;
        bad_s.s[31] ^= 0x04;
        try testing.expectError(error.InvalidProof, voprf.verifyProof(
            .voprf,
            Element.generator,
            pk,
            &.{blinded},
            &.{eval.evaluated_element},
            bad_s,
        ));
        const wrong_pk = try Element.fromBytes(kat.poprf_pk);
        try testing.expectError(error.InvalidProof, voprf.verifyProof(
            .voprf,
            Element.generator,
            wrong_pk,
            &.{blinded},
            &.{eval.evaluated_element},
            proof,
        ));

        // (6) Verifiable Finalize (verify-then-unblind) reproduces Output.
        const output = try voprf.finalizeVerifiable(
            v.input,
            v.blind,
            eval.evaluated_element,
            blinded,
            pk,
            proof,
        );
        try testing.expectEqualSlices(u8, &v.output, &output);

        // finalizeVerifiable fails CLOSED on a bad proof (no output).
        try testing.expectError(error.InvalidProof, voprf.finalizeVerifiable(
            v.input,
            v.blind,
            eval.evaluated_element,
            blinded,
            pk,
            bad_c,
        ));

        // (7) The direct PRF agrees with the verified round trip.
        const direct = try voprf.evaluate(.voprf, kat.voprf_sk, v.input);
        try testing.expectEqualSlices(u8, &v.output, &direct);
    }
}

test "VOPRF A.1.2.3: batch size 2 — one proof covers both evaluations" {
    const pk = try Element.fromBytes(kat.voprf_pk);
    const v = kat.voprf_batch;

    var blinded: [2]Element = undefined;
    for (v.input, v.blind, 0..) |input, blind_scalar, i| {
        blinded[i] = try voprf.blind(.voprf, input, blind_scalar);
        try testing.expectEqualSlices(u8, &v.blinded_element[i], &blinded[i].toBytes());
    }

    var evaluated: [2]Element = undefined;
    const proof = try voprf.blindEvaluateVerifiableBatch(
        kat.voprf_sk,
        pk,
        &blinded,
        &evaluated,
        v.proof_random_scalar,
    );
    for (v.evaluation_element, evaluated) |expected, got| {
        try testing.expectEqualSlices(u8, &expected, &got.toBytes());
    }
    try testing.expectEqualSlices(u8, &v.proof, &proof.toBytes());

    // Client side: verify the batched proof once, then finalize each.
    try voprf.verifyProof(.voprf, Element.generator, pk, &blinded, &evaluated, proof);
    for (v.input, v.blind, evaluated, v.output) |input, blind_scalar, eval_element, expected| {
        const output = try voprf.finalize(input, blind_scalar, eval_element);
        try testing.expectEqualSlices(u8, &expected, &output);
    }

    // A tampered batch (swapped evaluation elements) must not verify.
    const swapped = [2]Element{ evaluated[1], evaluated[0] };
    try testing.expectError(error.InvalidProof, voprf.verifyProof(
        .voprf,
        Element.generator,
        pk,
        &blinded,
        &swapped,
        proof,
    ));
}

// ── POPRF mode (A.1.3) ───────────────────────────────────────────────────

test "POPRF A.1.3: blind, blindEvaluate+proof, finalize all match" {
    const pk = try Element.fromBytes(kat.poprf_pk);
    for (kat.poprf_vectors) |v| {
        const blind_result = try voprf.blindPoprf(v.input, v.info, pk, v.blind);
        try testing.expectEqualSlices(u8, &v.blinded_element, &blind_result.blinded_element.toBytes());

        const eval = try voprf.blindEvaluatePoprf(
            kat.poprf_sk,
            blind_result.blinded_element,
            v.info,
            v.proof_random_scalar,
        );
        try testing.expectEqualSlices(u8, &v.evaluation_element, &eval.evaluated_element.toBytes());
        try testing.expectEqualSlices(u8, &v.proof, &eval.proof.toBytes());

        const proof = try Proof.fromBytes(v.proof);
        const output = try voprf.finalizePoprf(
            v.input,
            v.blind,
            eval.evaluated_element,
            blind_result.blinded_element,
            proof,
            v.info,
            blind_result.tweaked_key,
        );
        try testing.expectEqualSlices(u8, &v.output, &output);

        // Fail closed on a tampered proof.
        var bad = proof;
        bad.c[5] ^= 0x80;
        try testing.expectError(error.InvalidProof, voprf.finalizePoprf(
            v.input,
            v.blind,
            eval.evaluated_element,
            blind_result.blinded_element,
            bad,
            v.info,
            blind_result.tweaked_key,
        ));

        // The direct POPRF agrees with the blinded round trip.
        const direct = try voprf.evaluatePoprf(kat.poprf_sk, v.input, v.info);
        try testing.expectEqualSlices(u8, &v.output, &direct);
    }
}

test "POPRF A.1.3.3: batch size 2 — one proof covers both evaluations" {
    const pk = try Element.fromBytes(kat.poprf_pk);
    const v = kat.poprf_batch;

    var blinded: [2]Element = undefined;
    var tweaked_key: Element = undefined;
    for (v.input, v.blind, 0..) |input, blind_scalar, i| {
        const res = try voprf.blindPoprf(input, v.info, pk, blind_scalar);
        blinded[i] = res.blinded_element;
        tweaked_key = res.tweaked_key; // identical for both (same info/pkS)
        try testing.expectEqualSlices(u8, &v.blinded_element[i], &blinded[i].toBytes());
    }

    var evaluated: [2]Element = undefined;
    const proof = try voprf.blindEvaluatePoprfBatch(
        kat.poprf_sk,
        &blinded,
        v.info,
        &evaluated,
        v.proof_random_scalar,
    );
    for (v.evaluation_element, evaluated) |expected, got| {
        try testing.expectEqualSlices(u8, &expected, &got.toBytes());
    }
    try testing.expectEqualSlices(u8, &v.proof, &proof.toBytes());

    // Verify once (note the swapped composite lists), finalize each.
    try voprf.verifyProof(.poprf, Element.generator, tweaked_key, &evaluated, &blinded, proof);
    for (v.input, v.blind, evaluated, v.output) |input, blind_scalar, eval_element, expected| {
        const output = try voprf.finalizePoprfUnverified(input, blind_scalar, eval_element, v.info);
        try testing.expectEqualSlices(u8, &expected, &output);
    }
}

// ── end-to-end round trips with fresh (non-vector) material ─────────────

test "e2e OPRF: fresh key + fresh blind round-trips and agrees with evaluate" {
    const seed = [_]u8{0x7e} ** 32;
    const kp = try voprf.deriveKeyPair(.oprf, seed, "e2e oprf");
    // Deterministic stand-ins for CSPRNG output (tests must not use RNG).
    const blind_scalar = voprf.scalarFromWideBytes([_]u8{0x11} ** 64);
    const input = "e2e private input";

    const blinded = try voprf.blind(.oprf, input, blind_scalar);
    const evaluated = try voprf.blindEvaluate(kp.sk, blinded);
    const output = try voprf.finalize(input, blind_scalar, evaluated);
    const direct = try voprf.evaluate(.oprf, kp.sk, input);
    try testing.expectEqualSlices(u8, &direct, &output);

    // A different input must not collide.
    const other = try voprf.evaluate(.oprf, kp.sk, "another input");
    try testing.expect(!std.mem.eql(u8, &other, &output));
}

test "e2e VOPRF: fresh key, verified round trip agrees with evaluate" {
    const seed = [_]u8{0x2b} ** 32;
    const kp = try voprf.deriveKeyPair(.voprf, seed, "e2e voprf");
    const blind_scalar = voprf.scalarFromWideBytes([_]u8{0x22} ** 64);
    const proof_r = voprf.scalarFromWideBytes([_]u8{0x33} ** 64);
    const input = "e2e verifiable input";

    const blinded = try voprf.blind(.voprf, input, blind_scalar);
    const eval = try voprf.blindEvaluateVerifiable(kp.sk, kp.pk, blinded, proof_r);
    const output = try voprf.finalizeVerifiable(
        input,
        blind_scalar,
        eval.evaluated_element,
        blinded,
        kp.pk,
        eval.proof,
    );
    const direct = try voprf.evaluate(.voprf, kp.sk, input);
    try testing.expectEqualSlices(u8, &direct, &output);

    // A proof made under a DIFFERENT key must be rejected by finalize.
    const other_kp = try voprf.deriveKeyPair(.voprf, [_]u8{0x2c} ** 32, "e2e voprf");
    const forged = try voprf.blindEvaluateVerifiable(other_kp.sk, other_kp.pk, blinded, proof_r);
    try testing.expectError(error.InvalidProof, voprf.finalizeVerifiable(
        input,
        blind_scalar,
        forged.evaluated_element,
        blinded,
        kp.pk, // client expects kp.pk, server used other_kp.sk
        forged.proof,
    ));
}

test "e2e POPRF: fresh key, verified round trip agrees with evaluate" {
    const seed = [_]u8{0x5d} ** 32;
    const kp = try voprf.deriveKeyPair(.poprf, seed, "e2e poprf");
    const blind_scalar = voprf.scalarFromWideBytes([_]u8{0x44} ** 64);
    const proof_r = voprf.scalarFromWideBytes([_]u8{0x55} ** 64);
    const input = "e2e partially oblivious input";
    const info = "public metadata";

    const blind_result = try voprf.blindPoprf(input, info, kp.pk, blind_scalar);
    const eval = try voprf.blindEvaluatePoprf(kp.sk, blind_result.blinded_element, info, proof_r);
    const output = try voprf.finalizePoprf(
        input,
        blind_scalar,
        eval.evaluated_element,
        blind_result.blinded_element,
        eval.proof,
        info,
        blind_result.tweaked_key,
    );
    const direct = try voprf.evaluatePoprf(kp.sk, input, info);
    try testing.expectEqualSlices(u8, &direct, &output);

    // Different public info must change the output.
    const other = try voprf.evaluatePoprf(kp.sk, input, "other metadata");
    try testing.expect(!std.mem.eql(u8, &other, &output));
}

test "Proof.fromBytes rejects non-canonical scalars" {
    var bytes = [_]u8{0} ** 64;
    @memset(bytes[0..32], 0xff); // c >= group order
    try testing.expectError(error.InvalidScalar, Proof.fromBytes(bytes));
}
