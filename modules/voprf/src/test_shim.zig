// SPDX-License-Identifier: MIT

//! Test-only by-value adapters over the pointer / out-parameter API. The
//! public secret-handling entry points take secrets by `*const` and return
//! them through `out` (so no copy sits in a returned-by-value temporary, see
//! `burn.zig`); the KAT and end-to-end tests are easier to read with values.
//! Never imported outside tests.

const std = @import("std");
const voprf = @import("root.zig");

const Ns = voprf.Ns;
const Nh = voprf.Nh;
const Element = voprf.Element;
const Mode = voprf.Mode;

pub fn scalarFromWideBytes(wide: [64]u8) [Ns]u8 {
    var out: [Ns]u8 = undefined;
    voprf.scalarFromWideBytes(&wide, &out);
    return out;
}

pub fn deriveKeyPair(comptime mode: Mode, seed: [32]u8, info: []const u8) voprf.DeriveKeyPairError!voprf.KeyPair {
    var kp: voprf.KeyPair = undefined;
    try voprf.deriveKeyPair(mode, &seed, info, &kp);
    return kp;
}

pub fn generateProof(comptime mode: Mode, k: [Ns]u8, a: Element, b: Element, c: []const Element, d: []const Element, r: [Ns]u8) voprf.GenerateProofError!voprf.Proof {
    return voprf.generateProof(mode, &k, a, b, c, d, &r);
}

pub fn blind(comptime mode: Mode, input: []const u8, blind_scalar: [Ns]u8) voprf.BlindError!Element {
    return voprf.blind(mode, input, &blind_scalar);
}

pub fn blindEvaluate(sk: [Ns]u8, blinded: Element) Element {
    return voprf.blindEvaluate(&sk, blinded);
}

pub fn finalize(input: []const u8, blind_scalar: [Ns]u8, evaluated: Element) voprf.FinalizeError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.finalize(input, &blind_scalar, evaluated, &out);
    return out;
}

pub fn evaluate(comptime mode: Mode, sk: [Ns]u8, input: []const u8) voprf.EvaluateError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.evaluate(mode, &sk, input, &out);
    return out;
}

pub fn blindEvaluateVerifiable(sk: [Ns]u8, pk: Element, blinded: Element, r: [Ns]u8) voprf.BlindEvaluateVerifiableError!voprf.VerifiableEvaluation {
    return voprf.blindEvaluateVerifiable(&sk, pk, blinded, &r);
}

pub fn blindEvaluateVerifiableBatch(sk: [Ns]u8, pk: Element, blinded: []const Element, out: []Element, r: [Ns]u8) voprf.BlindEvaluateVerifiableError!voprf.Proof {
    return voprf.blindEvaluateVerifiableBatch(&sk, pk, blinded, out, &r);
}

pub fn finalizeVerifiable(input: []const u8, blind_scalar: [Ns]u8, evaluated: Element, blinded: Element, pk: Element, proof: voprf.Proof) voprf.FinalizeVerifiableError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.finalizeVerifiable(input, &blind_scalar, evaluated, blinded, pk, proof, &out);
    return out;
}

pub fn blindPoprf(input: []const u8, info: []const u8, pk: Element, blind_scalar: [Ns]u8) voprf.BlindError!voprf.PoprfBlindResult {
    return voprf.blindPoprf(input, info, pk, &blind_scalar);
}

pub fn blindEvaluatePoprfBatch(sk: [Ns]u8, blinded: []const Element, info: []const u8, out: []Element, r: [Ns]u8) voprf.PoprfEvaluateError!voprf.Proof {
    return voprf.blindEvaluatePoprfBatch(&sk, blinded, info, out, &r);
}

pub fn blindEvaluatePoprf(sk: [Ns]u8, blinded: Element, info: []const u8, r: [Ns]u8) voprf.PoprfEvaluateError!voprf.VerifiableEvaluation {
    return voprf.blindEvaluatePoprf(&sk, blinded, info, &r);
}

pub fn finalizePoprf(input: []const u8, blind_scalar: [Ns]u8, evaluated: Element, blinded: Element, proof: voprf.Proof, info: []const u8, tweaked: Element) voprf.FinalizeVerifiableError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.finalizePoprf(input, &blind_scalar, evaluated, blinded, proof, info, tweaked, &out);
    return out;
}

pub fn finalizePoprfUnverified(input: []const u8, blind_scalar: [Ns]u8, evaluated: Element, info: []const u8) voprf.FinalizeError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.finalizePoprfUnverified(input, &blind_scalar, evaluated, info, &out);
    return out;
}

pub fn evaluatePoprf(sk: [Ns]u8, input: []const u8, info: []const u8) voprf.PoprfDirectEvaluateError![Nh]u8 {
    var out: [Nh]u8 = undefined;
    try voprf.evaluatePoprf(&sk, input, info, &out);
    return out;
}
