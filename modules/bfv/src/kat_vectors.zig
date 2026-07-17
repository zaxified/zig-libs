// SPDX-License-Identifier: MIT

//! kat_vectors — recorded KNOWN-ANSWER vectors for the arithmetic backbone,
//! the ANTI-SELF-CONSISTENCY anchor for the `ntt`/`rns` layers.
//!
//! Every value here was produced by an INDEPENDENT Python re-derivation of the
//! textbook negacyclic NTT (Cooley-Tukey forward with `zetas[k]=psi^bitrev(k)`,
//! Gentleman-Sande inverse) and CRT, NOT by this module's Zig code (see the
//! `scratchpad/gen_kat.py` reference described in SPEC.md "External-reference
//! anchoring"). The Zig `ntt`/`rns` implementations must reproduce them
//! byte-exact:
//!   - `*_forward_a` pins the FORWARD transform (bit-reversed output order) of
//!     a fixed input — a Gen/order mistake cannot match it.
//!   - `*_negamul_ab` is the canonical negacyclic product `a·b mod (X^N+1)`,
//!     computed schoolbook in Python — ORDER-INDEPENDENT, so it pins the ring
//!     product regardless of transform convention.
//!   - the `rns_*` vectors pin CRT reconstruction on primes `{17,97}`.
//! Parameters: `N=8`, primes `q∈{17,97}` (both `≡ 1 mod 16`).

// --- q=17, N=8, psi=3 ---
pub const ntt_q17_input_a = [_]u64{ 1, 4, 7, 10, 13, 16, 2, 5 };
pub const ntt_q17_input_b = [_]u64{ 2, 7, 12, 0, 5, 10, 15, 3 };
pub const ntt_q17_forward_a = [_]u64{ 0, 16, 6, 12, 1, 11, 12, 1 };
pub const ntt_q17_negamul_ab = [_]u64{ 1, 16, 16, 14, 6, 5, 7, 8 };
pub const ntt_q17_psi: u64 = 3;

// --- q=97, N=8, psi=8 ---
pub const ntt_q97_input_a = [_]u64{ 1, 4, 7, 10, 13, 16, 19, 22 };
pub const ntt_q97_input_b = [_]u64{ 2, 7, 12, 17, 22, 27, 32, 37 };
pub const ntt_q97_forward_a = [_]u64{ 23, 49, 36, 70, 42, 95, 80, 1 };
pub const ntt_q97_negamul_ab = [_]u64{ 69, 86, 81, 84, 28, 40, 53, 0 };
pub const ntt_q97_psi: u64 = 8;

// --- RNS CRT, primes={17, 97}, M=1649 ---
pub const rns_primes = [_]u64{ 17, 97 };
pub const rns_modulus: u64 = 1649;
pub const rns_values = [_]u64{ 0, 1, 100, 1000, 1648, 823 };
pub const rns_res_p0 = [_]u64{ 0, 1, 15, 14, 16, 7 };
pub const rns_res_p1 = [_]u64{ 0, 1, 3, 30, 96, 47 };
