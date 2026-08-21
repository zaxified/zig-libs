// SPDX-License-Identifier: MIT

//! What a proving service does with `groth16`: hold a circuit and a proving
//! key, take a client's private witness, and hand back a proof plus the
//! public inputs it commits to — in the JSON shape snarkjs already speaks, so
//! the relying party's existing verifier needs no new code.
//!
//! The statement here is "I know two factors of this public number", which is
//! the smallest circuit with a genuinely private wire: `x` and `y` never
//! leave the prover, and the verifier learns only `n`.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("groth16")` and nothing else). If a type needed to call
//! the API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! **What a consumer of this module alone cannot do: check its own output.**
//! The verifier is `bn254.groth16Verify`, in the sibling module — so the one
//! property that defines a correct proof is not reachable from
//! `@import("groth16")`, even though `Proof` and `VerifyingKey` here ARE
//! re-exports of that verifier's own types. This program therefore ends by
//! serialising the proof for someone else to check; a service that wants to
//! self-check before responding has to depend on `bn254` as well.

const std = @import("std");
const groth16 = @import("groth16");

const Fr = groth16.Fr;

/// Witness layout. Wire 0 is the constant 1, then the public wires, then the
/// private ones — the order `setup`/`prove` assume when they split the CRS
/// into the γ (public) and δ (private) halves.
///
///   w = [ 1, n, x, y ]
const num_vars: usize = 4;
const num_public: usize = 1; // just `n`
/// Evaluation-domain size: a power of two at least as large as the
/// constraint count.
const domain_size: usize = 2;

/// The single constraint `x · y = n`.
fn factorCircuit() [1]groth16.Constraint {
    const one = Fr.one;
    return .{.{
        .a = &[_]groth16.Term{.{ .index = 2, .coeff = one }}, // x
        .b = &[_]groth16.Term{.{ .index = 3, .coeff = one }}, // y
        .c = &[_]groth16.Term{.{ .index = 1, .coeff = one }}, // n
    }};
}

/// The prover's secret: 91 = 7 · 13.
fn honestWitness() [num_vars]Fr {
    return .{
        Fr.one,
        groth16.field.frFromU64(91), // n, public
        groth16.field.frFromU64(7), // x, private
        groth16.field.frFromU64(13), // y, private
    };
}

/// A client that got its arithmetic wrong: 7 · 12 ≠ 91.
fn wrongWitness() [num_vars]Fr {
    var w = honestWitness();
    w[3] = groth16.field.frFromU64(12);
    return w;
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const constraints = factorCircuit();
    const sys: groth16.System = .{ .num_vars = num_vars, .constraints = &constraints };

    // ── the rejection a caller must handle, and it is not an error ───────
    // `prove` will happily assemble a proof from a witness that does not
    // satisfy the circuit; the QAP quotient is then inexact and the proof
    // simply fails to verify, with nothing at the prover naming why. A
    // service that skips this check ships a 503-shaped bug to its clients.
    if (sys.isSatisfied(&wrongWitness())) return error.WrongWitnessAccepted;
    std.debug.print("bad witness refused before proving\n", .{});

    const witness = honestWitness();
    if (!sys.isSatisfied(&witness)) return error.HonestWitnessRejected;

    // ── trusted setup ────────────────────────────────────────────────────
    // INSECURE by construction: whoever holds these five scalars can forge
    // proofs. A deployment ingests a CRS from a multi-party ceremony
    // instead; that is why the type is named after what it is.
    var toxic: groth16.ToxicWaste = .{
        .tau = groth16.field.frFromU64(7),
        .alpha = groth16.field.frFromU64(11),
        .beta = groth16.field.frFromU64(13),
        .gamma = groth16.field.frFromU64(17),
        .delta = groth16.field.frFromU64(19),
    };

    // A zero γ or δ is not a ceremony, it is a bug: both are inverted to
    // build the CRS. The error is nameable from out here, which is what lets
    // a caller tell "bad ceremony input" apart from "out of memory".
    var degenerate = toxic;
    degenerate.delta = Fr.zero;
    if (groth16.setup(domain_size, gpa, sys, num_public, degenerate)) |kp| {
        groth16.freeKeyPair(gpa, kp);
        return error.DegenerateSetupAccepted;
    } else |err| switch (err) {
        error.OutOfMemory => return err,
        error.DegenerateToxicWaste => std.debug.print("zero delta rejected by setup\n", .{}),
    }

    const keys = try groth16.setup(domain_size, gpa, sys, num_public, toxic);
    defer groth16.freeKeyPair(gpa, keys);
    // The five scalars have served their purpose; a real ceremony destroys
    // them, and so does this.
    toxic.deinit();

    // `ic` carries one group element per public wire plus the constant, so a
    // relying party can tell straight away which circuit a key is for.
    std.debug.print("CRS built: {d} public commitments, domain {d}\n", .{
        keys.vk.ic.len,
        keys.pk.domain_size,
    });

    // ── prove ────────────────────────────────────────────────────────────
    // `r` and `s` are the zero-knowledge randomizers: fresh per proof in a
    // deployment (two proofs of the same statement must not be equal), fixed
    // here so this program is reproducible.
    const proof = groth16.prove(domain_size, keys.pk, sys, num_public, &witness, .{
        .r = groth16.field.frFromU64(23),
        .s = groth16.field.frFromU64(29),
    });

    // ── ship it ──────────────────────────────────────────────────────────
    // snarkjs' own three files. The verifying key goes out once, at deploy
    // time; the proof and public inputs go out per request.
    const vk_json = try groth16.snarkjs_export.verifyingKeyJson(gpa, keys.vk);
    defer gpa.free(vk_json);
    const proof_json = try groth16.snarkjs_export.proofJson(gpa, proof);
    defer gpa.free(proof_json);
    const public_json = try groth16.snarkjs_export.publicJson(gpa, witness[1 .. num_public + 1]);
    defer gpa.free(public_json);

    std.debug.print("verification_key.json: {d} bytes\n", .{vk_json.len});
    std.debug.print("proof.json: {d} bytes\n", .{proof_json.len});
    std.debug.print("public.json: {s}\n", .{public_json});

    // The private wires never appear in any of the three: `public.json`
    // holds `n` alone, and the proof is three group elements.
    if (std.mem.indexOf(u8, public_json, "13") != null) return error.PrivateWireLeaked;
    std.debug.print("private factors absent from the published inputs\n", .{});
}
