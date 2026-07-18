// SPDX-License-Identifier: MIT

//! fast_core — the GATED irreducible x86-64 field core (IMPLEMENTED).
//!
//! The hand-written `MULX/ADCX/ADOX` dual-carry-chain secp256k1 base-field
//! multiply and square: a 256×256→512-bit product over four full 2^64 limbs,
//! followed by the special-prime fold `2^256 ≡ 2^32 + 977 (mod p)` back into
//! 256 bits. It is the single biggest, most curve-specific win — every point
//! operation (and therefore every scalar multiply, sign, and verify) is
//! dominated by field multiplies.
//!
//! ## Contract (do NOT change without updating the field dispatch + differential)
//!
//! `fieldMul(z, a, b)` computes `z = a·b mod p` and `fieldSq(z, a)` computes
//! `z = a² mod p`, where `a`, `b`, `z` are the same `[4]u64` little-endian,
//! FULLY REDUCED (`< p`) limbs the portable `field.mulPortable` / `field.sqPortable`
//! consume and return. `z` may alias neither `a` nor `b` (`field.zig` passes a
//! fresh out-buffer; the stores happen only at the end, so aliasing would in
//! fact be harmless — but the contract stays strict). The result MUST be `< p`
//! and byte-for-byte identical to the portable Solinas reduction — enforced by
//! the differential in `oracle_test.zig`.
//!
//! ## Structure
//!
//! One fully-unrolled straight-line asm block per entry point (fixed n = 4, so
//! unlike `montint`'s looped CIOS there is no loop control at all — zero
//! branches, conditional or otherwise):
//!
//!   * **product** — 4×4→8-limb schoolbook (NOT Montgomery). Row 0 is a plain
//!     `MULX` + `add/adc` chain; rows 1–3 run the mont5-style dual carry
//!     chains: `MULX` computes the widening products without touching any
//!     flag, `ADCX` propagates the lo-word chain through **CF**, `ADOX` adds
//!     the hi words through **OF**. Each row ends by folding OF (provably 0
//!     after the last `adox` into the freshly-zeroed top limb) and CF (via a
//!     flag-preserving `movl $0` + `adcx`) into the row's top limb — no wrap,
//!     because the partial sum after row i is `< 2^(64·(i+5))`.
//!   * **square** — off-diagonal products computed ONCE (rows a0·{a1,a2,a3},
//!     a1·{a2,a3}, a2·a3), doubled via a single `add/adc` self-add chain
//!     (the ×2 lives OUTSIDE the carry chains, on the completed cross sum, so
//!     no interleaved-doubling subtlety exists), then the diagonal `a_i²`
//!     terms are added with one `adc` chain. The doubled cross sum is
//!     `< 2^449` and the final sum is exactly `a² < 2^512`, so every top-limb
//!     carry provably fits.
//!   * **Solinas reduce** (shared string, appended to both blocks) — the SAME
//!     fold sequence as the portable oracle `field.reduceWide` + `normalize`,
//!     on explicit limbs, bounds `<2^290 → <2^257 → <2^256+c → <2^256`:
//!       1. fold 1: `(t0..t3) += c·(t4..t7)` via dual carry chains; both
//!          chains' final carries land in the excess word `x4 < 2^34`.
//!       2. fold 2: `+= c·x4` (`c·x4 < 2^67`, a 2-limb add); carry-out CF2.
//!       3. fold 3: `+= c·CF2` — the 2^256 bit folded BRANCHLESS via
//!          `imul` of the 0/1 carry byte (no data-dependent Jcc); carry CF3.
//!       4. fold 4: `+= c·CF3` (when CF3 = 1 the low word is `< c`, so the
//!          add cannot carry again — same argument as `field.normalize`).
//!       5. canonicalise: compute `V + c` in scratch; its carry-out ⟺
//!          `V ≥ p` (because `p = 2^256 − c`); select the wrapped value with
//!          an `sbb` mask + XOR-blend — masked select, no branch, no CMOV
//!          needed. Result `< p`.
//!
//! ## Constant-time contract
//!
//! Field mul/sq run on SECRET data (signing). Both blocks are straight-line
//! code with **zero branches** — the instruction sequence is a compile-time
//! constant, independent of every input bit. No secret-indexed loads/stores
//! (all addressing is fixed offsets off the pinned pointers). The final
//! reduce is a masked select (`sbb` mask + XOR-blend). All value-carrying
//! instructions (`MULX`, `IMUL`, `ADCX/ADOX/ADC/SBB`, `XOR/AND/MOV`) are in
//! the DIT (data-independent-timing) set.
//!
//! ## Register/flag discipline (inherited from `montint/src/asm_core.zig`)
//!
//! Every input is pinned to an explicit register and the modified ones are
//! tied to discarded outputs (letting the allocator place `"r"` inputs was
//! observed to collide with the fixed `{rdx}` binding under the self-hosted
//! x86-64 backend). AT&T size suffixes throughout (`mulxq`). `MULX` touches
//! no flag; `movl $imm` / `movq reg,reg` preserve flags where a chain is
//! live; `xorl` (which clears CF+OF) only ever runs where flags are dead.

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target can host the amd64 field core (x86-64 with
/// the ADX + BMI2 feature flags that supply `ADCX/ADOX` and `MULX`). On every
/// other target the dispatch in `field.zig` stays on the portable Solinas path
/// forever, regardless of the gate flag.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);

/// `z = a·b mod p` over four full 2^64 limbs (see the module doc for the full
/// contract). Dispatched iff `supported and gate.field_asm_implemented`.
pub fn fieldMul(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    if (comptime supported) {
        fieldMulAmd64(z, a, b);
    } else {
        // Unreachable by construction: the dispatcher in `field.zig` and the
        // differential harness both comptime-guard on `supported`.
        unreachable;
    }
}

/// `z = a² mod p` over four full 2^64 limbs. The dedicated square computes
/// each off-diagonal product once and doubles (~1.5× cheaper than a general
/// multiply). Dispatched iff `supported and gate.field_asm_implemented`.
pub fn fieldSq(z: *[4]u64, a: *const [4]u64) void {
    if (comptime supported) {
        fieldSqAmd64(z, a);
    } else {
        unreachable;
    }
}

// ── the shared Solinas reduce+store tail (t0..t7 in r8..r15 → z at rdi) ──────
//
// Consumes: r8..r15 (the 512-bit product), rdi (z). Scratch: rax, rcx, rdx,
// rsi, r12..r15 (the high product limbs are dead after fold 1). Straight-line,
// branch-free; see the module doc for the fold bounds.
const solinas_reduce =
    // rdx ← c = 2^32 + 977 (the Solinas fold constant). Built from two imm32
    // moves + shift + or (`movabsq` is not accepted by the self-hosted x86-64
    // assembler); flags are dead here, so the flag-clobbering shl/or are fine.
    \\ movl $1, %%edx
    \\ shlq $32, %%rdx
    \\ orq $977, %%rdx
    // fold 1: (r8..r11) += c·(r12..r15); excess word x4 → rcx.
    // ADCX chain: lo words through CF; ADOX chain: hi words through OF; both
    // final carries fold into x4 (rcx ≤ c+1 < 2^34, cannot wrap).
    \\ xorl %%esi, %%esi
    \\ mulxq %%r12, %%rax, %%rcx
    \\ adcxq %%rax, %%r8
    \\ adoxq %%rcx, %%r9
    \\ mulxq %%r13, %%rax, %%rcx
    \\ adcxq %%rax, %%r9
    \\ adoxq %%rcx, %%r10
    \\ mulxq %%r14, %%rax, %%rcx
    \\ adcxq %%rax, %%r10
    \\ adoxq %%rcx, %%r11
    \\ mulxq %%r15, %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adcxq %%rsi, %%rcx
    \\ adoxq %%rsi, %%rcx
    // flags dead; r15 becomes the zero register for the remaining folds.
    \\ xorl %%r15d, %%r15d
    // fold 2: += c·x4 (c·x4 < 2^67: lo→rax, hi→rcx ≤ 2^3); CF2 → rsi (was 0).
    \\ mulxq %%rcx, %%rax, %%rcx
    \\ addq %%rax, %%r8
    \\ adcq %%rcx, %%r9
    \\ adcq %%r15, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq %%r15, %%rsi
    // fold 3: += c·CF2 — branchless: multiply the 0/1 carry by c. CF3 → rsi.
    \\ imulq %%rdx, %%rsi
    \\ addq %%rsi, %%r8
    \\ adcq %%r15, %%r9
    \\ adcq %%r15, %%r10
    \\ adcq %%r15, %%r11
    \\ movq %%r15, %%rsi
    \\ adcq %%r15, %%rsi
    // fold 4: += c·CF3 (no carry out: when CF3 = 1 the low word is < c).
    \\ imulq %%rdx, %%rsi
    \\ addq %%rsi, %%r8
    \\ adcq %%r15, %%r9
    \\ adcq %%r15, %%r10
    \\ adcq %%r15, %%r11
    // canonicalise: T = V + c carries out ⟺ V ≥ p = 2^256 − c, and then T's
    // low 256 bits are exactly V − p. Masked select via sbb + XOR-blend.
    \\ movq %%r8, %%rax
    \\ addq %%rdx, %%rax
    \\ movq %%r9, %%rcx
    \\ adcq %%r15, %%rcx
    \\ movq %%r10, %%rsi
    \\ adcq %%r15, %%rsi
    \\ movq %%r11, %%rdx
    \\ adcq %%r15, %%rdx
    \\ sbbq %%r13, %%r13
    \\ xorq %%r8, %%rax
    \\ andq %%r13, %%rax
    \\ xorq %%rax, %%r8
    \\ xorq %%r9, %%rcx
    \\ andq %%r13, %%rcx
    \\ xorq %%rcx, %%r9
    \\ xorq %%r10, %%rsi
    \\ andq %%r13, %%rsi
    \\ xorq %%rsi, %%r10
    \\ xorq %%r11, %%rdx
    \\ andq %%r13, %%rdx
    \\ xorq %%rdx, %%r11
    \\ movq %%r8, (%%rdi)
    \\ movq %%r9, 8(%%rdi)
    \\ movq %%r10, 16(%%rdi)
    \\ movq %%r11, 24(%%rdi)
;

// ── multiply: 4×4→8-limb schoolbook product, then the shared reduce ──────────
//
// t0..t7 = r8..r15. Row 0 (b0) initialises t0..t4 with a plain add/adc chain;
// rows 1..3 (b1..b3) each add a·b_i into t_i..t_{i+3} with dual ADCX/ADOX
// chains and land their top in the freshly-zeroed t_{i+4}.
const mul_product =
    // row 0: t0..t4 ← a·b0
    \\ movq (%%rbx), %%rdx
    \\ xorl %%r13d, %%r13d
    \\ mulxq (%%rsi), %%r8, %%r9
    \\ mulxq 8(%%rsi), %%rax, %%r10
    \\ addq %%rax, %%r9
    \\ mulxq 16(%%rsi), %%rax, %%r11
    \\ adcq %%rax, %%r10
    \\ mulxq 24(%%rsi), %%rax, %%r12
    \\ adcq %%rax, %%r11
    \\ adcq %%r13, %%r12
    // row 1: t1..t5 += a·b1 (t5 fresh)
    \\ movq 8(%%rbx), %%rdx
    \\ xorl %%r13d, %%r13d
    \\ mulxq (%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r9
    \\ adoxq %%rcx, %%r10
    \\ mulxq 8(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r10
    \\ adoxq %%rcx, %%r11
    \\ mulxq 16(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adoxq %%rcx, %%r12
    \\ mulxq 24(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r12
    \\ adoxq %%rcx, %%r13
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r13
    // row 2: t2..t6 += a·b2 (t6 fresh)
    \\ movq 16(%%rbx), %%rdx
    \\ xorl %%r14d, %%r14d
    \\ mulxq (%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r10
    \\ adoxq %%rcx, %%r11
    \\ mulxq 8(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adoxq %%rcx, %%r12
    \\ mulxq 16(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r12
    \\ adoxq %%rcx, %%r13
    \\ mulxq 24(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r13
    \\ adoxq %%rcx, %%r14
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r14
    // row 3: t3..t7 += a·b3 (t7 fresh)
    \\ movq 24(%%rbx), %%rdx
    \\ xorl %%r15d, %%r15d
    \\ mulxq (%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adoxq %%rcx, %%r12
    \\ mulxq 8(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r12
    \\ adoxq %%rcx, %%r13
    \\ mulxq 16(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r13
    \\ adoxq %%rcx, %%r14
    \\ mulxq 24(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r14
    \\ adoxq %%rcx, %%r15
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r15
;

fn fieldMulAmd64(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    asm volatile (mul_product ++ "\n" ++ solinas_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
          [bp] "{rbx}" (b),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}

// ── square: cross products once, double, diagonal, then the shared reduce ────
//
// Cross terms (each a_i·a_j, i<j, computed ONCE) accumulate into t1..t6; the
// doubling is a single add/adc self-add chain over the completed cross sum
// (t7 fresh = the carry out); the diagonal a_i² terms land on one adc chain.
// The result is exactly a² < 2^512, so every carry provably fits.
const sq_product =
    // cross row a0: t1..t4 ← a0·(a1,a2,a3)
    \\ movq (%%rsi), %%rdx
    \\ xorl %%r13d, %%r13d
    \\ mulxq 8(%%rsi), %%r9, %%r10
    \\ mulxq 16(%%rsi), %%rax, %%r11
    \\ addq %%rax, %%r10
    \\ mulxq 24(%%rsi), %%rax, %%r12
    \\ adcq %%rax, %%r11
    \\ adcq %%r13, %%r12
    // cross row a1: t3..t5 += a1·(a2,a3) (t5 fresh)
    \\ movq 8(%%rsi), %%rdx
    \\ xorl %%r13d, %%r13d
    \\ mulxq 16(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adoxq %%rcx, %%r12
    \\ mulxq 24(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r12
    \\ adoxq %%rcx, %%r13
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r13
    // cross row a2: t5..t6 += a2·a3 (t6 fresh)
    \\ movq 16(%%rsi), %%rdx
    \\ mulxq 24(%%rsi), %%rax, %%r14
    \\ addq %%rax, %%r13
    \\ movl $0, %%ecx
    \\ adcq %%rcx, %%r14
    // double the cross sum: t1..t7 ← 2·(t1..t6) (t7 = carry out, < 2 by bound)
    \\ xorl %%r15d, %%r15d
    \\ addq %%r9, %%r9
    \\ adcq %%r10, %%r10
    \\ adcq %%r11, %%r11
    \\ adcq %%r12, %%r12
    \\ adcq %%r13, %%r13
    \\ adcq %%r14, %%r14
    \\ adcq %%r15, %%r15
    // diagonal: t0..t7 += Σ a_i²·2^(128i) on one adc chain (exact a², fits)
    \\ movq (%%rsi), %%rdx
    \\ mulxq %%rdx, %%r8, %%rax
    \\ addq %%rax, %%r9
    \\ movq 8(%%rsi), %%rdx
    \\ mulxq %%rdx, %%rax, %%rcx
    \\ adcq %%rax, %%r10
    \\ adcq %%rcx, %%r11
    \\ movq 16(%%rsi), %%rdx
    \\ mulxq %%rdx, %%rax, %%rcx
    \\ adcq %%rax, %%r12
    \\ adcq %%rcx, %%r13
    \\ movq 24(%%rsi), %%rdx
    \\ mulxq %%rdx, %%rax, %%rcx
    \\ adcq %%rax, %%r14
    \\ adcq %%rcx, %%r15
;

fn fieldSqAmd64(z: *[4]u64, a: *const [4]u64) void {
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    asm volatile (sq_product ++ "\n" ++ solinas_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}
