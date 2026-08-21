// SPDX-License-Identifier: MIT

//! What a privacy-preserving billing service does with `bfv`: hold customer
//! counters it can add to and multiply, without ever being able to read them.
//! The customer keeps the secret key; the service gets the public key, the
//! relinearisation key, and ciphertexts, and returns ciphertexts. Only the
//! customer decrypts.
//!
//! BFV is *leveled*: every homomorphic operation grows the noise inside the
//! ciphertext, and once the budget runs out the plaintext is gone — not
//! corrupted-with-an-error, gone, decrypting to a number that looks like any
//! other number. Watching that budget is the consumer's job and it is the
//! main thing this program demonstrates. (The sibling `tfhe` module is the
//! answer when the depth is not known in advance.)
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("bfv")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.

const std = @import("std");
const bfv = @import("bfv");

/// The parameter set is a comptime constant, so swapping it is a one-line
/// change: `bfv.params.sec_n8192_logq218` is the `N = 8192`, `log q = 218`
/// set the HomomorphicEncryption.org tables give for ~128-bit security. This
/// smaller one keeps the example quick to build; it claims NO security level.
const Engine = bfv.Bfv(bfv.params.bfv_toy);

/// Plaintext modulus of the chosen set — every encoded value's base.
const t = bfv.params.bfv_toy.t;

/// How many bits of noise budget a caller insists on keeping in hand before
/// spending another multiply. Below this the next operation is a coin flip,
/// and a silently-wrong invoice is worse than a refused one.
const budget_floor: u32 = 10;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();

    // Key generation and encryption draw their secrets through `std.Io`, so
    // a consumer must have an I/O implementation on hand even though nothing
    // here touches a socket or a file. That is deliberate: the module refuses
    // to accept a bare `std.Random`, because a caller passing a seeded PRNG
    // would not weaken this scheme, it would remove it.
    var threaded: std.Io.Threaded = .init(gpa_state.allocator(), .{});
    defer threaded.deinit();
    const io: std.Io = threaded.io();

    // Builds the NTT engines and the CRT constants for the parameter set.
    // Fails only on a structurally invalid set (a non-power-of-two degree, a
    // prime that is not NTT-friendly), which is a comptime-constant mistake —
    // so this error means "fix your parameters", not "retry".
    const engine = Engine.init() catch |err| {
        std.debug.print("parameter set is not usable: {s}\n", .{@errorName(err)});
        return;
    };

    // ── customer: keys ───────────────────────────────────────────────────
    var keys = engine.keyGen(io);
    defer keys.sk.deinit(); // wipe the ternary secret polynomial

    // The relinearisation key lets the SERVICE multiply. It is derived from
    // the secret key but is not itself a decryption key — this is the one
    // extra artifact a consumer has to know to ship, and forgetting it means
    // ciphertexts grow a component per multiply until nothing can decrypt.
    const relin_key = engine.genRelinKey(&keys.sk, io);

    // ── customer: encrypt two counters ───────────────────────────────────
    // Integer encoding: little-endian base-`t` digits. `error.Overflow` when
    // the value needs more digits than the ring has coefficients — the
    // rejection a caller gets when it tries to store more than the parameter
    // set can hold.
    const usage = Engine.Plaintext.encodeUint(t, 7) catch |err| switch (err) {
        error.Overflow => {
            std.debug.print("value too large for this parameter set\n", .{});
            return;
        },
    };
    const rate = try Engine.Plaintext.encodeUint(t, 13);

    const ct_usage = engine.encrypt(&keys.pk, &usage, io);
    const ct_rate = engine.encrypt(&keys.pk, &rate, io);
    std.debug.print("fresh ciphertext: {d} components, {d} bits of budget\n", .{
        ct_usage.numComponents(),
        engine.noiseBudget(&keys.sk, &ct_usage),
    });

    // ── service: compute on ciphertext ───────────────────────────────────
    // Addition is nearly free in noise terms; multiplication is not.
    const ct_sum = engine.add(&ct_usage, &ct_rate);

    if (engine.noiseBudget(&keys.sk, &ct_usage) < budget_floor) {
        std.debug.print("refusing to multiply: budget exhausted\n", .{});
        return;
    }
    // A raw product has THREE components and can no longer be multiplied
    // again or decrypted by an ordinary two-component path; relinearisation
    // folds it back to two using the key the customer supplied.
    const ct_raw_product = engine.mul(&ct_usage, &ct_rate);
    if (ct_raw_product.numComponents() != 3) return error.UnexpectedCiphertextShape;
    const ct_product = engine.relinearize(&ct_raw_product, &relin_key);
    if (ct_product.numComponents() != 2) return error.RelinearizationDidNotReduce;

    const budget_after = engine.noiseBudget(&keys.sk, &ct_product);
    std.debug.print("after one multiply + relin: {d} bits of budget left\n", .{budget_after});

    // ── the rejection a caller must handle ───────────────────────────────
    // This is the whole discipline of a leveled scheme. The budget is a
    // number, not an error: nothing stops the next multiply, and nothing
    // reports afterwards that it destroyed the value. A service that does not
    // check here returns a plausible wrong invoice.
    if (budget_after < budget_floor) {
        std.debug.print("depth exhausted — returning the depth-1 result only\n", .{});
    } else {
        const ct_squared = engine.relinearize(&engine.mul(&ct_product, &ct_product), &relin_key);
        std.debug.print("depth 2 affordable: {d} bits left\n", .{
            engine.noiseBudget(&keys.sk, &ct_squared),
        });
    }

    // ── customer: decrypt ────────────────────────────────────────────────
    const sum_pt = engine.decrypt(&keys.sk, &ct_sum);
    const product_pt = engine.decrypt(&keys.sk, &ct_product);

    // Decoding is the second place a caller must refuse. A plaintext whose
    // base-`t` digits no longer describe a `u128` is exactly what an
    // exhausted budget or an overflowed plaintext modulus produces, and
    // `decodeUint` says so rather than truncating.
    const sum = sum_pt.decodeUint() catch |err| switch (err) {
        error.Overflow => {
            std.debug.print("sum did not decode — parameters were exceeded\n", .{});
            return;
        },
    };
    const product = product_pt.decodeUint() catch |err| switch (err) {
        error.Overflow => {
            std.debug.print("product did not decode — parameters were exceeded\n", .{});
            return;
        },
    };

    std.debug.print("7 + 13 = {d}, 7 * 13 = {d} (computed blind)\n", .{ sum, product });
    if (sum != 20 or product != 91) return error.HomomorphicResultWrong;

    // A plaintext the service never produced: high digits set, so the Horner
    // evaluation runs past `u128`. Same refusal, reached deliberately.
    var wild: [Engine.degree]u64 = @splat(0);
    wild[20] = 1; // t^20 = 2^200
    const bogus = Engine.Plaintext.fromCoeffs(t, wild);
    if (bogus.decodeUint()) |_| {
        return error.OversizedPlaintextDecoded;
    } else |err| switch (err) {
        error.Overflow => std.debug.print("out-of-range plaintext refused by decode\n", .{}),
    }
}
