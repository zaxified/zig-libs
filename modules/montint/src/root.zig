// SPDX-License-Identifier: MIT

//! montint — fast constant-time Montgomery big-integer modular arithmetic over
//! arbitrary ODD moduli (prime or composite), the performance-competitive
//! native-Zig alternative to `std.crypto.ff`.
//!
//! `std.crypto.ff` is a portable scalar constant-time Montgomery implementation
//! that reserves a carry bit per limb (63-bit redundant limbs) and multiplies
//! limbs 4 half-limbs at a time — which forecloses the host add-with-carry and
//! widening-multiply instructions and costs ~8–29× vs OpenSSL across every
//! bignum-crypto module in this repo (`rsa`, `paillier`, `vdf`,
//! `bls12_381`/`bn254` fields — see `SPEC.md`). We cannot patch std. `montint`
//! is a fresh module on **full radix-2^64 limbs** so the amd64
//! `MULX/ADCX/ADOX` dual-carry-chain Montgomery multiply (the `x86_64-mont5`
//! technique) can reach ≤3× OpenSSL, with a portable CIOS fallback on every
//! other arch. Inline asm in Zig is still native Zig — no libc, no C — so the
//! zero-C invariant holds.
//!
//! ## Scaffold status (this phase)
//! The PORTABLE path is **real, constant-time, and byte-exact vs an independent
//! CPython-bignum oracle** at 256/512/2048/4096 bits — it is the correctness
//! oracle. The irreducible amd64 asm core is a GATED stub
//! (`gate.asm_core_implemented = false`); dispatch runs entirely on the
//! portable oracle until a Fable agent fills `asm_core.montMul` and flips the
//! flag, at which point the asm-vs-portable differential harness lights up. See
//! `gate.zig`, `asm_core.zig`, `SPEC.md`.

const std = @import("std");

pub const meta = .{
    .platform = .any, // portable CIOS everywhere; amd64 asm is an accel path
    .role = .util,
    .concurrency = .reentrant, // immutable modulus; no shared state
    .model_after = "OpenSSL x86_64-mont5 (MULX/ADCX/ADOX Montgomery) + std.crypto.ff API shape",
    .deps = .{}, // std-only
};

const montint = @import("montint.zig");

/// `Modint(max_bits)` — a modulus type for odd moduli up to `max_bits` wide.
pub const Modint = montint.Modint;
pub const Error = montint.Error;
/// `-x⁻¹ mod 2^64` for odd `x` (the CIOS reduction constant).
pub const negInvMod2_64 = montint.negInvMod2_64;
/// True iff the accelerated amd64 core is available AND switched on.
pub const asm_active = montint.asm_active;

pub const gate = @import("gate.zig");
pub const asm_core = @import("asm_core.zig");
pub const limbs = @import("limbs.zig");
pub const kat_vectors = @import("kat_vectors.zig");

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    std.testing.refAllDecls(@This());
    _ = montint;
    _ = limbs;
    _ = kat_vectors;
    _ = @import("kat_test.zig");
    _ = @import("bench.zig");
}

test "meta.model_after names the OpenSSL Montgomery technique" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "MULX") != null);
}
