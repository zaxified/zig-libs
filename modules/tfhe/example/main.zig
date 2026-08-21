// SPDX-License-Identifier: MIT

//! What an outsourced-policy evaluator does with `tfhe`: run a boolean
//! circuit on a client's encrypted inputs, on a machine that is never allowed
//! to learn them, and return an encrypted answer only the client can open.
//!
//! The reason to reach for TFHE rather than the sibling leveled `bfv` is
//! depth: every gate here ends in a bootstrap, which re-decodes the message
//! through a lookup table and emits a FRESH low-noise ciphertext, so the
//! circuit can be as deep as the policy needs and nobody has to size a noise
//! budget in advance. The cost is that a gate is milliseconds, not
//! nanoseconds.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("tfhe")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! **Toy parameters — no security level is claimed.** They are the only ones
//! the module ships, which is itself the thing a consumer needs to know
//! before deploying anything built on this.

const std = @import("std");
const tfhe = @import("tfhe");

/// The parameter set. `Tfhe` is generic over it, so a deployment that
/// commissions a secure set changes this line and nothing else.
const Fhe = tfhe.Tfhe(tfhe.params.toy);

/// Bit scale for the 2-input gate below. Single-bit values live at `Δ = q/4`,
/// but a gate that adds two ciphertexts first needs the SUM `a + b ∈ {0,1,2}`
/// to stay inside the LUT's lower half, so its inputs go in at `q/8`.
const gate_delta: tfhe.Torus = 1 << 29;
const gate_delta_log: u6 = 29;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Every production key-generation and encryption entry point draws
    // through `std.Io`, and that is the module's most consumer-visible design
    // decision: a predictable stream here does not weaken LWE, it dissolves
    // it — `n` ciphertexts recover the secret key by Gaussian elimination —
    // so the seeded twins are all suffixed `…ForTest` to keep a
    // `DefaultPrng.init(0)` from ever appearing at a call site that looks
    // production-shaped. The consequence for a consumer is this block: an I/O
    // implementation is required even though nothing below touches a file or
    // a socket.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io: std.Io = threaded.io();

    // Validates the parameter set's structure (power-of-two ring degree,
    // gadget decompositions that fit the 32-bit torus). NOT a security check.
    _ = Fhe.init() catch |err| {
        std.debug.print("parameter set is malformed: {s}\n", .{@errorName(err)});
        return;
    };

    // ── the rejection a caller must handle ───────────────────────────────
    // Anyone tuning parameters — the only way to get a secure set, since the
    // shipped one is a toy — hits this first. `validate` names the specific
    // structural fault, which is what makes it actionable rather than a
    // wrong answer three thousand gates later.
    var tuned = tfhe.params.toy;
    tuned.ell = 6; // 7 bits x 6 levels = 42 > 32: the gadget no longer fits
    if (tuned.validate()) |_| {
        return error.BadGadgetAccepted;
    } else |err| switch (err) {
        error.BadGgswGadget => std.debug.print("rejected a gadget wider than the torus\n", .{}),
        else => return err,
    }

    // ── client: keys ─────────────────────────────────────────────────────
    // The two secret keys stay with the client. The bootstrap key and the
    // key-switch key go to the evaluator: both are ENCRYPTIONS of secret
    // material, not the material itself, which is what makes outsourcing
    // possible at all.
    var small = Fhe.lweKeyGen(Fhe.lwe_dim, io);
    defer small.deinit();
    var glwe = Fhe.glweKeyGen(io);
    defer glwe.deinit();

    // Heap, not stack: the evaluation keys are megabytes for even these toy
    // parameters (the bootstrap key alone is one GGSW ciphertext per bit of
    // the LWE key). They are returned by value, so a consumer that wants them
    // off the stack has to place them itself, as here.
    const bsk = try gpa.create(Fhe.BootstrapKey);
    defer gpa.destroy(bsk);
    bsk.* = Fhe.bootstrapKeyGen(&small, &glwe, io);
    defer bsk.deinit();

    const ksk = try gpa.create(Fhe.KeySwitchKey);
    defer gpa.destroy(ksk);
    ksk.* = Fhe.keySwitchKeyGen(&glwe, &small, io);
    defer ksk.deinit();

    // ── client: encrypt the policy inputs ────────────────────────────────
    // "is a paid subscriber" AND "is inside the licensed region" — two bits
    // the evaluator must not learn.
    var subscriber = Fhe.lweEncrypt(Fhe.lwe_dim, &small, tfhe.torus.encode(1, gate_delta), io);
    const in_region = Fhe.lweEncrypt(Fhe.lwe_dim, &small, tfhe.torus.encode(1, gate_delta), io);

    // ── evaluator: one homomorphic AND ───────────────────────────────────
    // A 2-input gate is an LWE sum followed by a bootstrap whose LUT reads
    // the sum: output 1 only when `a + b == 2`.
    //
    // The sum is written out by hand because the module publishes `glweAdd`/
    // `glweSub` for GLWE ciphertexts but nothing equivalent for LWE ones —
    // so every consumer building any two-input gate re-derives this loop from
    // the ciphertext's raw `(a, b)` components.
    for (&subscriber.a, in_region.a) |*x, y| x.* +%= y;
    subscriber.b +%= in_region.b;

    const and_lut = Fhe.testPolynomial(3, .{ 0, 0, gate_delta, 0 });
    const answer = Fhe.bootstrap(bsk, ksk, &and_lut, &subscriber);

    // ── client: decrypt ──────────────────────────────────────────────────
    const allowed = tfhe.torus.decode(
        Fhe.lwePhase(Fhe.lwe_dim, &small, &answer),
        gate_delta_log,
        1,
    );
    std.debug.print("policy evaluated blind: allowed = {d}\n", .{allowed});
    if (allowed != 1) return error.GateComputedWrongAnswer;

    // ── unbounded depth ──────────────────────────────────────────────────
    // The point of bootstrapping: the output of a gate is as clean as a fresh
    // encryption, so it can feed the next gate forever. A leveled scheme
    // stops long before this loop does.
    const identity = Fhe.testPolynomial(2, .{ Fhe.encodeBit(0), Fhe.encodeBit(1) });
    var carried = Fhe.lweEncrypt(Fhe.lwe_dim, &small, Fhe.encodeBit(1), io);
    for (0..8) |_| carried = Fhe.bootstrap(bsk, ksk, &identity, &carried);
    if (Fhe.lweDecryptBit(Fhe.lwe_dim, &small, &carried) != 1) return error.DepthLostTheMessage;
    std.debug.print("8 chained bootstraps: message intact\n", .{});

    // ── what a caller cannot check ───────────────────────────────────────
    // There is no rejection path on this side. A ciphertext decrypted under
    // the wrong key, or an evaluation key that was corrupted in transit,
    // yields a bit — just not the right one — and nothing in the API reports
    // it. A deployment that cares must authenticate the keys and ciphertexts
    // itself; FHE hides the data, it does not authenticate it.
    var other = Fhe.lweKeyGen(Fhe.lwe_dim, io);
    defer other.deinit();
    const nonsense = Fhe.lweDecryptBit(Fhe.lwe_dim, &other, &carried);
    std.debug.print("under an unrelated key the same ciphertext reads {d}, with no error\n", .{nonsense});
}
