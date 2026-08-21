// SPDX-License-Identifier: MIT

//! What a password-hardening client/server pair does with `voprf`: the
//! server derives a key pair, the client blinds its password, the server
//! evaluates it and attaches a DLEQ proof (VOPRF mode), and the client
//! verifies the proof and finalizes to the same output the server could
//! compute directly with `evaluate` — then confirms a tampered proof is
//! rejected by name rather than silently accepted.
//!
//! This module has NO internal RNG (RFC 9497's random scalars are all
//! caller-supplied), so this example draws its own via `getrandom(2)` —
//! the real thing a production client/server would do, not a stand-in.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! plus its declared `ct25519` dep, no `test_deps`, no access to anything
//! the module does not export). If a type needed to call the API is not
//! public, or an error cannot be named from outside, this file stops
//! compiling.

const std = @import("std");
const voprf = @import("voprf");

fn randomScalar() [voprf.Ns]u8 {
    var wide: [64]u8 = undefined;
    _ = std.os.linux.getrandom(&wide, wide.len, 0);
    return voprf.scalarFromWideBytes(wide);
}

fn randomSeed() [32]u8 {
    var seed: [32]u8 = undefined;
    _ = std.os.linux.getrandom(&seed, seed.len, 0);
    return seed;
}

pub fn main() !void {
    // ── server: derive a long-term VOPRF key pair ───────────────────────
    const server_key = try voprf.deriveKeyPair(.voprf, randomSeed(), "voprf-example-v1");

    // ── client: blind its private input ──────────────────────────────────
    const password = "correct horse battery staple";
    const blind_scalar = randomScalar();
    const blinded = try voprf.blind(.voprf, password, blind_scalar);

    // ── server: evaluate the blinded element and prove it used server_key ─
    const proof_r = randomScalar();
    const eval = try voprf.blindEvaluateVerifiable(server_key.sk, server_key.pk, blinded, proof_r);

    // ── client: verify the proof, then finalize to the PRF output ────────
    const output = try voprf.finalizeVerifiable(password, blind_scalar, eval.evaluated_element, blinded, server_key.pk, eval.proof);

    // Cross-check: the server (or anyone holding sk) can compute the same
    // output directly, non-obliviously — the correctness property a VOPRF
    // has to have to be useful at all.
    const direct = try voprf.evaluate(.voprf, server_key.sk, password);
    std.debug.print("oblivious output matches direct evaluate: {}\n", .{std.mem.eql(u8, &output, &direct)});

    // A tampered proof must be rejected by name, not accepted or panicked
    // on — the client's whole reason to run VOPRF instead of plain OPRF.
    var bad_proof = eval.proof;
    bad_proof.s[0] ^= 0x01;
    _ = voprf.finalizeVerifiable(password, blind_scalar, eval.evaluated_element, blinded, server_key.pk, bad_proof) catch |err| switch (err) {
        error.InvalidProof => std.debug.print("tampered proof correctly rejected\n", .{}),
        error.InvalidBlind => return err,
    };

    // A corrupt wire element (not a valid, non-identity ristretto255 point)
    // is rejected the same way, before it ever reaches group arithmetic.
    const zero_bytes: [voprf.Ne]u8 = @splat(0); // the identity element's encoding
    _ = voprf.Element.fromBytes(zero_bytes) catch |err| switch (err) {
        error.InvalidElement => std.debug.print("identity-element wire bytes correctly rejected\n", .{}),
    };
}
