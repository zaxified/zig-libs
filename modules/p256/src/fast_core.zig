// SPDX-License-Identifier: MIT

//! fast_core — the GATED irreducible x86-64 field core (IMPLEMENTED).
//!
//! The hand-written `MULX/ADCX/ADOX` dual-carry-chain P-256 base-field multiply
//! and square: a 256×256→512-bit product over four full 2^64 limbs, followed by
//! the **NIST P-256 word-shuffle reduction** back into 256 bits. It is the
//! single biggest, most curve-specific win — every point operation (and
//! therefore every scalar multiply, sign, and verify) is dominated by field
//! multiplies.
//!
//! ## Contract (do NOT change without updating the field dispatch + differential)
//!
//! `fieldMul(z, a, b)` computes `z = a·b mod p` and `fieldSq(z, a)` computes
//! `z = a² mod p`, where `a`, `b`, `z` are the same `[4]u64` little-endian,
//! FULLY REDUCED (`< p`) limbs the portable `field.mulPortable` /
//! `field.sqPortable` consume and return. `z` may alias neither `a` nor `b`
//! (`field.zig` passes a fresh out-buffer; the stores happen only at the end,
//! so aliasing would in fact be harmless — but the contract stays strict). The
//! result MUST be `< p` and byte-for-byte identical to the portable Solinas
//! reduction — enforced by the gated differential in `oracle_test.zig`.
//!
//! ## The reduction — signed word-shuffle, NOT the wide-M fold
//!
//! ⚠ Stale until corrected: the portable path took the eleven-fold `2^256 ≡ M`
//! route when this was written, and the word-shuffle below was the "instead".
//! `field.reduceWide` now runs the **same** word-shuffle, so this core and the
//! portable path are no longer algorithmically independent — the fold survives
//! only as `field.reduceWideFold`, exercised by one differential test in that
//! file. See `field.reduceWide`'s doc for what that means for assurance.
//!
//! The fold (`field.reduceWideFold`) folds `2^256 ≡ M` eleven times with
//! a wide `M = 2^224 − 2^192 − 2^96 + 1` multiply — correct but slow, and a poor
//! shape for asm (each fold shrinks the excess only ~32 bits). This core uses
//! the classic **NIST/Solinas word-shuffle** (HMV "Guide to ECC"
//! Alg. 2.29, the reduction OpenSSL's 32-bit P-256 and many others use): over
//! the sixteen 32-bit product words c0..c15,
//!
//!   r ≡ s1 + 2·s2 + 2·s3 + s4 + s5 − s6 − s7 − s8 − s9  (mod p)
//!
//! where each s_i is a fixed permutation of the words. Both reductions compute
//! the same canonical `x mod p`, so the oracle differential pins them
//! bit-for-bit. Limb-level shape (validated against a bignum `% p` oracle on
//! 2,000,000 random full products + operand edges before the asm was written):
//!
//!   1. **accumulate** — the nine terms as 64-bit limb pairs of the high product
//!      half, added/subtracted on plain `ADD/ADC`/`SUB/SBB` chains into a
//!      **signed 5-limb accumulator** (top limb = two's-complement sign limb;
//!      the SIGNED intermediates the s6..s9 borrows produce live only in that
//!      top limb). Bounds: top ∈ [−4, +6].
//!   2. **fold 1** — `V ≡ V_lo + s·M` with `s` the signed top limb: `|s|` by
//!      masked negate, `|s|·M` via three `MULX` (M's limbs are constants), the
//!      product conditionally negated by the sign mask and added back. New top
//!      ∈ {−1, 0, +1}.
//!   3. **fold 2** — same shape with `|s| ∈ {0,1}`, so `|s|·M` is a masked AND
//!      of M's limbs. The resulting top limb is provably 0: if the fold-1 value
//!      overflowed 2^256 its low part was `< 2^227`, so `+M < 2^228` cannot
//!      re-overflow; if it went negative it was `> −2^227`, so the two's-
//!      complement low part is `≥ 2^256 − 2^227` and `−M` cannot underflow.
//!   4. **canonicalise** — `V < 2^256 < 2p`, so one constant-time conditional
//!      subtract of `p` (SBB mask + XOR-blend, no branch, no CMOV) lands the
//!      result in `[0, p)`.
//!
//! ## Constant-time contract
//!
//! Field mul/sq run on SECRET data (signing). Both blocks are straight-line
//! code with **zero branches** — the instruction sequence is a compile-time
//! constant, independent of every input bit. No secret-indexed loads/stores
//! (all addressing is fixed offsets off the pinned pointers). Sign handling in
//! the folds is masked arithmetic (`shr $63` + masked negate), and the final
//! reduce is a masked select (`sbb` mask + XOR-blend). All value-carrying
//! instructions (`MULX`, `ADCX/ADOX/ADC/SBB`, `SHL/SHR/AND/OR/XOR/MOV`) are in
//! the DIT (data-independent-timing) set.
//!
//! ## Register/flag discipline (inherited from `montint/src/asm_core.zig`)
//!
//! Every input is pinned to an explicit register and the modified ones are
//! tied to discarded outputs. AT&T size suffixes throughout (`mulxq`). `MULX`
//! touches no flag; `movl $imm` / `movq reg,reg` preserve flags where a chain
//! is live; the flag-clobbering `xorl`/`shlq`/`shrq`/`orq`/`andq` only ever run
//! where flags are dead. No `movabsq` (rejected by the self-hosted assembler)
//! and no negative immediates — wide constants are built with
//! `movl $imm32` + `shlq`/`orq`, and all-ones via `xorl` + `subq $1`.

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

// ── the shared word-shuffle reduce+store tail (t0..t7 in r8..r15 → z at rdi) ──
//
// Consumes: r8..r15 (the 512-bit product), rdi (z). Scratch: rax, rbx, rcx,
// rdx, rsi, and r12..r15 once the high product limbs are dead. Straight-line,
// branch-free; see the module doc for the algorithm and bounds.
//
// 32-bit product words: c_{2i} = lo32(t_i), c_{2i+1} = hi32(t_i). The high
// half lives in A = t4 = (c9,c8), B = t5 = (c11,c10), C = t6 = (c13,c12),
// D = t7 = (c15,c14) — r12..r15. The signed accumulator is (r8..r11, rbx).
// Term limbs (l0..l3, low→high) straight from HMV Alg. 2.29:
//   s2 = (0,        c11<<32,      (c13,c12),  (c15,c14))   ×2
//   s3 = (0,        c12<<32,      (c14,c13),  c15      )   ×2
//   s4 = ((c9,c8),  c10,          0,          (c15,c14))
//   s5 = ((c10,c9), (c13,c11),    (c15,c14),  (c8,c13) )
//   s6 = ((c12,c11), c13,         0,          (c10,c8) )   −
//   s7 = ((c13,c12), (c15,c14),   0,          (c11,c9) )   −
//   s8 = ((c14,c13), (c8,c15),    (c10,c9),   c12<<32  )   −
//   s9 = ((c15,c14), c9<<32,      (c11,c10),  c13<<32  )   −
const shuffle_reduce =
    // accumulator top limb (signed) — flags are dead at entry.
    \\ xorl %%ebx, %%ebx
    // s2 (l0 = 0, so the chain starts at limb 1), added twice.
    \\ movq %%r13, %%rax
    \\ shrq $32, %%rax
    \\ shlq $32, %%rax
    \\ addq %%rax, %%r9
    \\ adcq %%r14, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq $0, %%rbx
    \\ addq %%rax, %%r9
    \\ adcq %%r14, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq $0, %%rbx
    // s3, added twice.
    \\ movq %%r14, %%rax
    \\ shlq $32, %%rax
    \\ movq %%r14, %%rcx
    \\ shrq $32, %%rcx
    \\ movq %%r15, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rcx
    \\ movq %%r15, %%rdx
    \\ shrq $32, %%rdx
    \\ addq %%rax, %%r9
    \\ adcq %%rcx, %%r10
    \\ adcq %%rdx, %%r11
    \\ adcq $0, %%rbx
    \\ addq %%rax, %%r9
    \\ adcq %%rcx, %%r10
    \\ adcq %%rdx, %%r11
    \\ adcq $0, %%rbx
    // s4.
    \\ movl %%r13d, %%eax
    \\ addq %%r12, %%r8
    \\ adcq %%rax, %%r9
    \\ adcq $0, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq $0, %%rbx
    // s5.
    \\ movq %%r12, %%rax
    \\ shrq $32, %%rax
    \\ movq %%r13, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rax
    \\ movq %%r13, %%rcx
    \\ shrq $32, %%rcx
    \\ movq %%r14, %%rdx
    \\ shrq $32, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rcx
    \\ movq %%r14, %%rsi
    \\ shrq $32, %%rsi
    \\ movq %%r12, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rsi
    \\ addq %%rax, %%r8
    \\ adcq %%rcx, %%r9
    \\ adcq %%r15, %%r10
    \\ adcq %%rsi, %%r11
    \\ adcq $0, %%rbx
    // s6 (subtracted).
    \\ movq %%r13, %%rax
    \\ shrq $32, %%rax
    \\ movq %%r14, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rax
    \\ movq %%r14, %%rcx
    \\ shrq $32, %%rcx
    \\ movl %%r12d, %%esi
    \\ movq %%r13, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rsi
    \\ subq %%rax, %%r8
    \\ sbbq %%rcx, %%r9
    \\ sbbq $0, %%r10
    \\ sbbq %%rsi, %%r11
    \\ sbbq $0, %%rbx
    // s7 (subtracted).
    \\ movq %%r12, %%rax
    \\ shrq $32, %%rax
    \\ movq %%r13, %%rdx
    \\ shrq $32, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rax
    \\ subq %%r14, %%r8
    \\ sbbq %%r15, %%r9
    \\ sbbq $0, %%r10
    \\ sbbq %%rax, %%r11
    \\ sbbq $0, %%rbx
    // s8 (subtracted).
    \\ movq %%r14, %%rax
    \\ shrq $32, %%rax
    \\ movq %%r15, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rax
    \\ movq %%r15, %%rcx
    \\ shrq $32, %%rcx
    \\ movq %%r12, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rcx
    \\ movq %%r12, %%rsi
    \\ shrq $32, %%rsi
    \\ movq %%r13, %%rdx
    \\ shlq $32, %%rdx
    \\ orq %%rdx, %%rsi
    \\ movq %%r14, %%rdx
    \\ shlq $32, %%rdx
    \\ subq %%rax, %%r8
    \\ sbbq %%rcx, %%r9
    \\ sbbq %%rsi, %%r10
    \\ sbbq %%rdx, %%r11
    \\ sbbq $0, %%rbx
    // s9 (subtracted). The high product limbs die here.
    \\ movq %%r12, %%rax
    \\ shrq $32, %%rax
    \\ shlq $32, %%rax
    \\ movq %%r14, %%rcx
    \\ shrq $32, %%rcx
    \\ shlq $32, %%rcx
    \\ subq %%r15, %%r8
    \\ sbbq %%rax, %%r9
    \\ sbbq %%r13, %%r10
    \\ sbbq %%rcx, %%r11
    \\ sbbq $0, %%rbx
    // ── fold 1: V ≡ V_lo + s·M, s = rbx (signed, ∈ [−4, +6]) ──
    // sign bit → inc (rax) and all-ones mask (rcx); |s| → rdx (the MULX source).
    \\ movq %%rbx, %%rax
    \\ shrq $63, %%rax
    \\ xorl %%ecx, %%ecx
    \\ subq %%rax, %%rcx
    \\ movq %%rbx, %%rdx
    \\ xorq %%rcx, %%rdx
    \\ subq %%rcx, %%rdx
    \\ movq %%rax, %%rbx
    // Q = |s|·M over 4 limbs (fits: |s| ≤ 6 ⇒ Q < 2^227). M's limbs are
    // m0 = 1, m1 = 2^64−2^32, m2 = 2^64−1, m3 = 2^32−2; q0 = |s| stays in rdx.
    \\ movl $4294967295, %%eax
    \\ shlq $32, %%rax
    \\ mulxq %%rax, %%r13, %%r14
    \\ xorl %%eax, %%eax
    \\ subq $1, %%rax
    \\ mulxq %%rax, %%rsi, %%r15
    \\ movl $4294967294, %%eax
    \\ mulxq %%rax, %%rax, %%r12
    \\ addq %%rsi, %%r14
    \\ adcq %%rax, %%r15
    // conditionally negate Q by the sign mask (two's complement: XOR + inc),
    // capturing sign limb + negate carry in rsi (movl preserves the live CF).
    \\ xorq %%rcx, %%rdx
    \\ xorq %%rcx, %%r13
    \\ xorq %%rcx, %%r14
    \\ xorq %%rcx, %%r15
    \\ addq %%rbx, %%rdx
    \\ adcq $0, %%r13
    \\ adcq $0, %%r14
    \\ adcq $0, %%r15
    \\ movl $0, %%esi
    \\ adcq %%rcx, %%rsi
    // V += Q' (signed); new top limb → rsi ∈ {−1, 0, +1}.
    \\ addq %%rdx, %%r8
    \\ adcq %%r13, %%r9
    \\ adcq %%r14, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq $0, %%rsi
    // ── fold 2: same shape, |s| ∈ {0,1} so |s|·M is a masked AND of M ──
    \\ movq %%rsi, %%rax
    \\ shrq $63, %%rax
    \\ xorl %%ecx, %%ecx
    \\ subq %%rax, %%rcx
    \\ movq %%rsi, %%rdx
    \\ xorq %%rcx, %%rdx
    \\ subq %%rcx, %%rdx
    \\ xorl %%ebx, %%ebx
    \\ subq %%rdx, %%rbx
    // Q2 = (abs2, m1 & rbx, rbx, m3 & rbx); conditionally negate by mask2 (rcx).
    \\ movl $4294967295, %%esi
    \\ shlq $32, %%rsi
    \\ andq %%rbx, %%rsi
    \\ movl $4294967294, %%r13d
    \\ andq %%rbx, %%r13
    \\ xorq %%rcx, %%rdx
    \\ xorq %%rcx, %%rsi
    \\ movq %%rbx, %%r14
    \\ xorq %%rcx, %%r14
    \\ xorq %%rcx, %%r13
    \\ addq %%rax, %%rdx
    \\ adcq $0, %%rsi
    \\ adcq $0, %%r14
    \\ adcq $0, %%r13
    // V += Q2'. The top limb provably cancels to 0 (module doc) — discarded.
    \\ addq %%rdx, %%r8
    \\ adcq %%rsi, %%r9
    \\ adcq %%r14, %%r10
    \\ adcq %%r13, %%r11
    // ── canonicalise: V < 2^256 < 2p ⇒ one masked conditional subtract of p ──
    // p limbs: p0 = 2^64−1, p1 = 2^32−1, p2 = 0, p3 = 2^64−2^32+1.
    \\ xorl %%eax, %%eax
    \\ subq $1, %%rax
    \\ movl $4294967295, %%ecx
    \\ movl $4294967295, %%edx
    \\ shlq $32, %%rdx
    \\ orq $1, %%rdx
    \\ xorl %%esi, %%esi
    \\ movq %%r8, %%r12
    \\ subq %%rax, %%r12
    \\ movq %%r9, %%r13
    \\ sbbq %%rcx, %%r13
    \\ movq %%r10, %%r14
    \\ sbbq %%rsi, %%r14
    \\ movq %%r11, %%r15
    \\ sbbq %%rdx, %%r15
    \\ sbbq %%rax, %%rax
    // masked select (keep V iff the subtract borrowed, i.e. V < p): XOR-blend.
    \\ xorq %%r12, %%r8
    \\ andq %%rax, %%r8
    \\ xorq %%r12, %%r8
    \\ xorq %%r13, %%r9
    \\ andq %%rax, %%r9
    \\ xorq %%r13, %%r9
    \\ xorq %%r14, %%r10
    \\ andq %%rax, %%r10
    \\ xorq %%r14, %%r10
    \\ xorq %%r15, %%r11
    \\ andq %%rax, %%r11
    \\ xorq %%r15, %%r11
    \\ movq %%r8, (%%rdi)
    \\ movq %%r9, 8(%%rdi)
    \\ movq %%r10, 16(%%rdi)
    \\ movq %%r11, 24(%%rdi)
;

// ── multiply: 4×4→8-limb schoolbook product, then the shared reduce ──────────
//
// t0..t7 = r8..r15. Row 0 (b0) initialises t0..t4 with a plain add/adc chain;
// rows 1..3 (b1..b3) each add a·b_i into t_i..t_{i+3} with dual ADCX/ADOX
// chains and land their top in the freshly-zeroed t_{i+4}. (Identical to the
// k256 product — the schoolbook is curve-independent; only the reduce differs.)
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
    var d4: u64 = undefined;
    asm volatile (mul_product ++ "\n" ++ shuffle_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
          [d4] "={rbx}" (d4),
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
// The result is exactly a² < 2^512, so every carry provably fits. (Identical
// to the k256 square; curve-independent.)
pub const sq_product =
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
    var d4: u64 = undefined;
    asm volatile (sq_product ++ "\n" ++ shuffle_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
          [d4] "={rbx}" (d4),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}

// ── Montgomery reduce tail (R = 2^256) — what `field.Fe` runs on since 2026-10-10 ──
//
// Consumes the same state as `shuffle_reduce`: the 512-bit product t0..t7 in
// r8..r15, rdi = z. Computes `REDC(t) = t·2^−256 mod p`, canonical, bit-exact
// with `field.montReducePortable` (pinned by the gated differential in
// `oracle_test.zig`).
//
// REDC of the LOW half only, then the high half added once: `t = H·2^256 + L`
// gives `t·R⁻¹ ≡ H + REDC(L)`, `H < p` (because `t < p²`) and `REDC(L) ≤ p`,
// so the sum is `< 2p` and one masked conditional subtract canonicalises it.
// `REDC(L)` is four rounds on a rotating 4-limb window (a0..a3): `p ≡ −1 (mod
// 2^64)` makes the quotient digit `m = a0` itself and kills limb 0 exactly
// (`a0 + m·p0 = m·2^64`, the carry of which is folded below as the `+m` term).
// What remains of `m·p + m` is `m·2^96` (two shifts: `m<<32` into a1, `m>>32`
// into a2) and `m·p3·2^192` (`p3 = 2^64 − 2^32 + 1`: ONE `MULX`, lo into a3,
// hi = the new top limb). One add/adc chain per round; the hi limb absorbs
// the final carry without wrapping (`hi(m·p3) ≤ 2^64 − 2^32`), and the window
// value stays `< 2^192 + p < 2^256`, so nothing is ever dropped.
//
// Constant-time: straight-line, no branch, no secret-indexed address, only
// DIT-set instructions; the final select is the same `sbb` mask + XOR-blend as
// the Solinas tail. Clobbers rax, rbx, rcx, rdx, rsi, r8..r15, flags.
pub const mont_reduce_core =
    \\ movabsq $0xFFFFFFFF00000001, %%rsi
    // round 0: m = r8; (r8,r9,r10,r11) -> (r9,r10,r11,r8)
    \\ movq %%r8, %%rdx
    \\ mulxq %%rsi, %%rbx, %%rcx
    \\ movq %%r8, %%rax
    \\ shlq $32, %%rax
    \\ shrq $32, %%r8
    \\ addq %%rax, %%r9
    \\ adcq %%r8, %%r10
    \\ adcq %%rbx, %%r11
    \\ adcq $0, %%rcx
    \\ movq %%rcx, %%r8
    // round 1: m = r9; (r9,r10,r11,r8) -> (r10,r11,r8,r9)
    \\ movq %%r9, %%rdx
    \\ mulxq %%rsi, %%rbx, %%rcx
    \\ movq %%r9, %%rax
    \\ shlq $32, %%rax
    \\ shrq $32, %%r9
    \\ addq %%rax, %%r10
    \\ adcq %%r9, %%r11
    \\ adcq %%rbx, %%r8
    \\ adcq $0, %%rcx
    \\ movq %%rcx, %%r9
    // round 2: m = r10; (r10,r11,r8,r9) -> (r11,r8,r9,r10)
    \\ movq %%r10, %%rdx
    \\ mulxq %%rsi, %%rbx, %%rcx
    \\ movq %%r10, %%rax
    \\ shlq $32, %%rax
    \\ shrq $32, %%r10
    \\ addq %%rax, %%r11
    \\ adcq %%r10, %%r8
    \\ adcq %%rbx, %%r9
    \\ adcq $0, %%rcx
    \\ movq %%rcx, %%r10
    // round 3: m = r11; (r11,r8,r9,r10) -> (r8,r9,r10,r11)
    \\ movq %%r11, %%rdx
    \\ mulxq %%rsi, %%rbx, %%rcx
    \\ movq %%r11, %%rax
    \\ shlq $32, %%rax
    \\ shrq $32, %%r11
    \\ addq %%rax, %%r8
    \\ adcq %%r11, %%r9
    \\ adcq %%rbx, %%r10
    \\ adcq $0, %%rcx
    \\ movq %%rcx, %%r11
    // + high half
    \\ xorl %%eax, %%eax
    \\ addq %%r12, %%r8
    \\ adcq %%r13, %%r9
    \\ adcq %%r14, %%r10
    \\ adcq %%r15, %%r11
    \\ adcq $0, %%rax
    // acc − p in place; `carry − borrow` (rax) is then 0 (keep acc − p) or
    // all ones (acc < p: add p back) — the borrow implies carry 0, and a
    // carry implies a borrow, so it is never −2. p masked by it is added
    // back: p0 = mask, p1 = mask & (2^32 − 1), p2 = 0, p3 = mask & rsi. Twelve
    // instructions against the twenty-two of a subtract into copies and an
    // XOR-blend (2026-10-13); branch-free, no CMOV.
    \\ movl $4294967295, %%ecx
    \\ subq $-1, %%r8
    \\ sbbq %%rcx, %%r9
    \\ sbbq $0, %%r10
    \\ sbbq %%rsi, %%r11
    \\ sbbq $0, %%rax
    \\ andq %%rax, %%rcx
    \\ andq %%rax, %%rsi
    \\ addq %%rax, %%r8
    \\ adcq %%rcx, %%r9
    \\ adcq $0, %%r10
    \\ adcq %%rsi, %%r11
;

/// `mont_reduce_core` + the store of the result to `z` (rdi).
const mont_reduce = mont_reduce_core ++
    \\
    \\ movq %%r8, (%%rdi)
    \\ movq %%r9, 8(%%rdi)
    \\ movq %%r10, 16(%%rdi)
    \\ movq %%r11, 24(%%rdi)
;

/// `z = a·b·2^−256 mod p` (Montgomery multiply) over four full 2^64 limbs, all
/// canonical (`< p`). Same calling contract as `fieldMul`. Dispatched by
/// `field.Fe.mul` iff `supported and gate.field_asm_implemented`.
pub fn montMul(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    if (comptime supported) {
        montMulAmd64(z, a, b);
    } else {
        unreachable;
    }
}

/// `z = a²·2^−256 mod p` (Montgomery square): the dedicated square product +
/// the Montgomery tail. Dispatched by `field.Fe.sq` like `montMul`.
pub fn montSq(z: *[4]u64, a: *const [4]u64) void {
    if (comptime supported) {
        montSqAmd64(z, a);
    } else {
        unreachable;
    }
}

fn montMulAmd64(z: *[4]u64, a: *const [4]u64, b: *const [4]u64) void {
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    var d4: u64 = undefined;
    asm volatile (mul_product ++ "\n" ++ mont_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
          [d4] "={rbx}" (d4),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
          [bp] "{rbx}" (b),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}

fn montSqAmd64(z: *[4]u64, a: *const [4]u64) void {
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    var d4: u64 = undefined;
    asm volatile (sq_product ++ "\n" ++ mont_reduce
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
          [d4] "={rbx}" (d4),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}

// ── interleaved (CIOS) Montgomery multiply — the register-returning hot path ──
//
// Each row `a·b_i` is accumulated into a rotating 5-limb window and the
// window's low limb is reduced right away (`m = t0`, the same two shifts and
// one `MULX` by `p3` as `mont_reduce_core`), so the reduction of row i runs
// while row i+1 multiplies instead of after the whole 512-bit product: the
// critical path through a field multiply is what bounds the point doubling
// chain (measured 2026-10-13: 14 % fewer instructions in `Jac.dbl` from the
// cheaper tails moved ECDH by nothing). Invariant after every round: window
// value < 2p (a, b < p), so five limbs suffice, the top one ∈ {0,1} at the
// end, and one masked subtract canonicalises. Straight-line, no branch, no
// CMOV, DIT-set instructions only. Pinned to `field.montMulPortable` by the
// gated differential. rsi = a, rbx = b (neither modified); out in r12, r13,
// r8, r9.
pub const mont_mul_cios =
    \\ movabsq $0xFFFFFFFF00000001, %%rdi
    // round 0: (r8..r12) = a·b0, then reduce on r8 into (r9..r12, r13)
    \\ movq (%%rbx), %%rdx
    \\ mulxq (%%rsi), %%r8, %%r9
    \\ mulxq 8(%%rsi), %%rax, %%r10
    \\ addq %%rax, %%r9
    \\ mulxq 16(%%rsi), %%rax, %%r11
    \\ adcq %%rax, %%r10
    \\ mulxq 24(%%rsi), %%rax, %%r12
    \\ adcq %%rax, %%r11
    \\ adcq $0, %%r12
    \\ movl $0, %%r13d
    \\ movq %%r8, %%rdx
    \\ mulxq %%rdi, %%rax, %%rcx
    \\ movq %%r8, %%r14
    \\ shlq $32, %%r14
    \\ shrq $32, %%r8
    \\ addq %%r14, %%r9
    \\ adcq %%r8, %%r10
    \\ adcq %%rax, %%r11
    \\ adcq %%rcx, %%r12
    \\ adcq $0, %%r13
    // round 1: window (r9,r10,r11,r12,r13) += a·b1, top in r8; reduce on r9
    \\ movq 8(%%rbx), %%rdx
    \\ xorl %%r8d, %%r8d
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
    \\ adcxq %%r8, %%r13
    \\ adoxq %%r8, %%r8
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r8
    \\ movq %%r9, %%rdx
    \\ mulxq %%rdi, %%rax, %%rcx
    \\ movq %%r9, %%r14
    \\ shlq $32, %%r14
    \\ shrq $32, %%r9
    \\ addq %%r14, %%r10
    \\ adcq %%r9, %%r11
    \\ adcq %%rax, %%r12
    \\ adcq %%rcx, %%r13
    \\ adcq $0, %%r8
    // round 2: window (r10,r11,r12,r13,r8) += a·b2, top in r9; reduce on r10
    \\ movq 16(%%rbx), %%rdx
    \\ xorl %%r9d, %%r9d
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
    \\ adoxq %%rcx, %%r8
    \\ adcxq %%r9, %%r8
    \\ adoxq %%r9, %%r9
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r9
    \\ movq %%r10, %%rdx
    \\ mulxq %%rdi, %%rax, %%rcx
    \\ movq %%r10, %%r14
    \\ shlq $32, %%r14
    \\ shrq $32, %%r10
    \\ addq %%r14, %%r11
    \\ adcq %%r10, %%r12
    \\ adcq %%rax, %%r13
    \\ adcq %%rcx, %%r8
    \\ adcq $0, %%r9
    // round 3: window (r11,r12,r13,r8,r9) += a·b3, top in r10; reduce on r11
    \\ movq 24(%%rbx), %%rdx
    \\ xorl %%r10d, %%r10d
    \\ mulxq (%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r11
    \\ adoxq %%rcx, %%r12
    \\ mulxq 8(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r12
    \\ adoxq %%rcx, %%r13
    \\ mulxq 16(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r13
    \\ adoxq %%rcx, %%r8
    \\ mulxq 24(%%rsi), %%rax, %%rcx
    \\ adcxq %%rax, %%r8
    \\ adoxq %%rcx, %%r9
    \\ adcxq %%r10, %%r9
    \\ adoxq %%r10, %%r10
    \\ movl $0, %%eax
    \\ adcxq %%rax, %%r10
    \\ movq %%r11, %%rdx
    \\ mulxq %%rdi, %%rax, %%rcx
    \\ movq %%r11, %%r14
    \\ shlq $32, %%r14
    \\ shrq $32, %%r11
    \\ addq %%r14, %%r12
    \\ adcq %%r11, %%r13
    \\ adcq %%rax, %%r8
    \\ adcq %%rcx, %%r9
    \\ adcq $0, %%r10
    // value < 2p in (r12, r13, r8, r9) + r10 ∈ {0,1}: subtract p in place, add it back masked
    \\ movl $4294967295, %%ecx
    \\ subq $-1, %%r12
    \\ sbbq %%rcx, %%r13
    \\ sbbq $0, %%r8
    \\ sbbq %%rdi, %%r9
    \\ sbbq $0, %%r10
    \\ andq %%r10, %%rcx
    \\ andq %%r10, %%rdi
    \\ addq %%r10, %%r12
    \\ adcq %%rcx, %%r13
    \\ adcq $0, %%r8
    \\ adcq %%rdi, %%r9
;

/// `montMul` returning the product in registers instead of storing it through
/// a pointer: the caller's frame gets no out-buffer to fill and reload, so a
/// chain of field operations keeps its values in registers between multiplies.
pub fn montMulRegs(a: *const [4]u64, b: *const [4]u64) [4]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    var d4: u64 = undefined;
    var d5: u64 = undefined;
    asm volatile (mont_mul_cios
        : [r0] "={r12}" (r0),
          [r1] "={r13}" (r1),
          [r2] "={r8}" (r2),
          [r3] "={r9}" (r3),
          [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rdi}" (d3),
          [d4] "={r10}" (d4),
          [d5] "={r14}" (d5),
        : [ap] "{rsi}" (a),
          [bp] "{rbx}" (b),
        : .{ .r11 = true, .cc = true, .memory = true });
    return .{ r0, r1, r2, r3 };
}

/// `montSq` returning the square in registers (see `montMulRegs`).
pub fn montSqRegs(a: *const [4]u64) [4]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    var d4: u64 = undefined;
    asm volatile (sq_product ++ "\n" ++ mont_reduce_core
        : [r0] "={r8}" (r0),
          [r1] "={r9}" (r1),
          [r2] "={r10}" (r2),
          [r3] "={r11}" (r3),
          [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rsi}" (d3),
          [d4] "={rbx}" (d4),
        : [ap] "{rsi}" (a),
        : .{ .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
    return .{ r0, r1, r2, r3 };
}

/// `(a + b) mod p` for canonical `a`, `b`, in registers — the amd64 twin of
/// `field.Fe.add`'s portable body. LLVM lowers the portable u256 version with
/// `setb` to memory and a chain of `sbb $0` mask builds (about forty
/// instructions and stack traffic); this is nineteen, with no memory operand.
/// `p` is subtracted from the sum in place; the carry out of the add is
/// collected into `c` (0/1) and `c − borrow` is then 0 (the sum was ≥ p: keep
/// the difference) or all ones (sum < p: add `p` back, masked — the same
/// tail as `mont_reduce_core`). Straight-line, no branch, no CMOV, DIT-set
/// instructions only.
pub fn addRegs(a: [4]u64, b: [4]u64) [4]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var c: u64 = undefined;
    var k: u64 = undefined;
    var k3: u64 = undefined;
    asm (
        \\ movq $0, %[c]
        \\ addq %[b0], %[r0]
        \\ adcq %[b1], %[r1]
        \\ adcq %[b2], %[r2]
        \\ adcq %[b3], %[r3]
        \\ adcq $0, %[c]
        \\ subq $-1, %[r0]
        \\ movabsq $0xffffffff, %[k]
        \\ sbbq %[k], %[r1]
        \\ sbbq $0, %[r2]
        \\ movabsq $0xffffffff00000001, %[k3]
        \\ sbbq %[k3], %[r3]
        \\ sbbq $0, %[c]
        \\ andq %[c], %[k]
        \\ andq %[c], %[k3]
        \\ addq %[c], %[r0]
        \\ adcq %[k], %[r1]
        \\ adcq $0, %[r2]
        \\ adcq %[k3], %[r3]
        : [r0] "=r" (r0),
          [r1] "=r" (r1),
          [r2] "=r" (r2),
          [r3] "=r" (r3),
          [c] "=&r" (c),
          [k] "=&r" (k),
          [k3] "=&r" (k3),
        : [a0] "0" (a[0]),
          [a1] "1" (a[1]),
          [a2] "2" (a[2]),
          [a3] "3" (a[3]),
          [b0] "r" (b[0]),
          [b1] "r" (b[1]),
          [b2] "r" (b[2]),
          [b3] "r" (b[3]),
        : .{ .cc = true });
    return .{ r0, r1, r2, r3 };
}

/// `(a − b) mod p` for canonical `a`, `b`, in registers — the amd64 twin of
/// `field.Fe.sub`. On a borrow, `p` masked by the all-ones borrow mask is
/// added back once (`p0 = 2^64 − 1` is the mask itself, `p1 = mask >> 32`,
/// `p2 = 0`, `p3 = mask & (2^64 − 2^32 + 1)`). Straight-line, no branch.
pub fn subRegs(a: [4]u64, b: [4]u64) [4]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var t0: u64 = undefined;
    var t1: u64 = undefined;
    var t2: u64 = undefined;
    var t3: u64 = undefined;
    asm (
        \\ subq %[t0], %[r0]
        \\ sbbq %[t1], %[r1]
        \\ sbbq %[t2], %[r2]
        \\ sbbq %[t3], %[r3]
        \\ sbbq %[t0], %[t0]
        \\ movq %[t0], %[t1]
        \\ shrq $32, %[t1]
        \\ movabsq $0xffffffff00000001, %[t2]
        \\ andq %[t0], %[t2]
        \\ addq %[t0], %[r0]
        \\ adcq %[t1], %[r1]
        \\ adcq $0, %[r2]
        \\ adcq %[t2], %[r3]
        : [r0] "=r" (r0),
          [r1] "=r" (r1),
          [r2] "=r" (r2),
          [r3] "=r" (r3),
          [t0] "=r" (t0),
          [t1] "=r" (t1),
          [t2] "=r" (t2),
          [t3] "=r" (t3),
        : [a0] "0" (a[0]),
          [a1] "1" (a[1]),
          [a2] "2" (a[2]),
          [a3] "3" (a[3]),
          [b0] "4" (b[0]),
          [b1] "5" (b[1]),
          [b2] "6" (b[2]),
          [b3] "7" (b[3]),
        : .{ .cc = true });
    return .{ r0, r1, r2, r3 };
}
