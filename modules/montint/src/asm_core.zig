// SPDX-License-Identifier: MIT

//! asm_core — the GATED irreducible x86-64 core (IMPLEMENTED).
//!
//! The hand-written `MULX/ADCX/ADOX` dual-carry-chain CIOS Montgomery multiply
//! (the OpenSSL `x86_64-mont5` technique), plus the dedicated Montgomery
//! SQUARING (`montSqr`: SOS driven by the `mulRow` row primitive — see its
//! doc). Everything else in the module (the portable CIOS oracle, to/from
//! Montgomery, add/sub, windowed modexp, and the whole verification + bench
//! harness) lives outside this file. See `gate.zig` for the cut-line and
//! `SPEC.md` for the algorithm + threat model.
//!
//! ## Structure
//!
//! A Zig outer loop drives the exact CIOS schedule of the portable oracle
//! (`montMulCios` in `montint.zig`), calling ONE inline-asm block per outer
//! limb (`ciosIter`) that performs both CIOS rows back to back:
//!
//!   * mul row — `t[0..n] += x·v[0..n]`, carry out `c1`;
//!   * `u = t[0]·n0inv mod 2^64` (in-asm `imul`, chains are dead there);
//!   * reduction row — `t = (t + u·m) >> 64` with the store shifted down one
//!     limb (limb 0 of the sum is zero by construction and discarded), carry
//!     out `c2`.
//!
//! Merging the rows halves the asm-block transitions per outer limb; the
//! reduction row's bases/counters ride in callee-saved registers across the
//! mul row (rbx/r12/r13/r14 as pinned inputs, `c1` handed out in r15).
//!
//! Each row runs TWO independent carry chains in parallel, exactly mont5-style:
//! `MULX` (BMI2) computes the widening products without touching any flag,
//! `ADCX` propagates the hi→lo product chain through **CF**, and `ADOX` adds
//! the accumulator words through **OF**. The main loop is unrolled 4 limbs per
//! iteration with the OF chain live across the group; a remainder loop (n mod 4
//! low limbs first, so limb order is preserved) folds OF back into the pending
//! hi limb every iteration. Two subtleties keep the chains intact across loop
//! control (the classic mont5 pitfalls):
//!
//!   * `dec` is the loop counter update because it preserves **CF** (unlike
//!     `sub`/`test`); **OF** is always folded to 0 before it (`adox` of the
//!     zero register into the pending-hi, which cannot wrap because a 64×64
//!     product's high half is ≤ 2^64−2).
//!   * At loop boundaries the live CF is folded into the pending-hi limb with
//!     `adc` — provably no wrap, because the carry into any limb position of
//!     `t + x·v` (with `t < 2^64n`, `x < 2^64`, `v < 2^64n`) fits in 64 bits —
//!     after which the flags are dead and a plain `test`/`jz` is legal.
//!
//! ## Constant-time contract
//!
//! The instruction sequence depends only on the PUBLIC limb count `n` (loop
//! trip counts `n/4`, `n mod 4`): no secret-dependent branch, load address, or
//! store address anywhere. The final conditional subtract (`condSub`) is a
//! masked limb-select over every limb — never a branch on the secret compare —
//! same structure as the portable `condSubTop` and `std.crypto.ff`.
//!
//! Signature contract (do NOT change without updating `montint.zig`'s dispatch
//! and the differential harness): compute `z = a·b·R⁻¹ mod m` where all of
//! `z,a,b,m` are `n`-limb little-endian **full 2^64** limbs (`n = m.len`),
//! `n0inv = -m[0]⁻¹ mod 2^64`, and the inputs satisfy `a,b < m`. `z` must not
//! alias `a`, `b`, or `m` (the dispatcher always passes a fresh out-buffer;
//! `a == b` aliasing is fine and used by squaring). The result is fully
//! reduced (`z < m`) and byte-for-byte identical to the portable `montMulCios`
//! — enforced by the asm-vs-portable differential test.

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target can host the amd64 core (x86-64 with the
/// ADX + BMI2 feature flags that supply `ADCX/ADOX` and `MULX`). On every other
/// target the dispatch in `montint.zig` stays on the portable path forever.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);

/// `z = a·b·R⁻¹ mod m` over `n = m.len` full 2^64 limbs (see the module doc
/// for the full contract). Dispatched iff `supported and gate.asm_core_implemented`.
pub fn montMul(z: []u64, a: []const u64, b: []const u64, m: []const u64, n0inv: u64) void {
    if (comptime supported) {
        montMulAmd64(z, a, b, m, n0inv);
    } else {
        // Unreachable by construction: the dispatcher in `montint.zig` and the
        // differential harness both comptime/runtime-guard on `supported`.
        unreachable;
    }
}

fn montMulAmd64(z: []u64, a: []const u64, b: []const u64, m: []const u64, n0inv: u64) void {
    const n = m.len;
    std.debug.assert(n >= 1);
    std.debug.assert(z.len == n and a.len == n and b.len == n);

    // CIOS accumulator: t[0..n-1] lives in z (freshly zeroed); the top two
    // words t[n], t[n+1] only ever carry row tails, so they stay in scalars.
    @memset(z, 0);
    var top0: u64 = 0; // t[n]
    var top1: u64 = 0; // t[n+1]

    // Public loop-trip counts (limb count only — no secret dependence).
    const rem = n & 3;
    const grp = n >> 2;
    const rrem = (n - 1) & 3; // reduction row handles limb 0 in its preamble
    const rgrp = (n - 1) >> 2;

    // Reduction-row trip counts packed into one register (rrem ≤ 3 in 2 bits).
    const redpack = (rgrp << 2) | rrem;

    for (b) |bi| {
        // One asm block per outer limb: t += a·b[i]; u = t[0]·n0inv;
        // t = (t + u·m) >> 64 — carries out c1 (mul row) and c2 (reduce row).
        const c = ciosIter(z.ptr, a.ptr, m.ptr, rem, grp, redpack, n0inv, bi);
        const s = @as(u128, top0) + c.c1;
        top0 = @truncate(s);
        top1 = @intCast(s >> 64);
        const s2 = @as(u128, top0) + c.c2;
        z[n - 1] = @truncate(s2);
        top0 = top1 +% @as(u64, @intCast(s2 >> 64));
    }
    // t < 2m here, so t[n] (top0) is 0 or 1; constant-time final reduce.
    condSub(z, top0, m);
}

/// `z = a²·R⁻¹ mod m` over `n = m.len` full 2^64 limbs — the dedicated
/// Montgomery SQUARING (same contract as `montMul` with `b == a`, but ~½ the
/// off-diagonal limb products). `scratch` must be `2·n` words and, like `z`,
/// must not alias `a`/`m` (the dispatcher passes fresh stack buffers).
/// Dispatched iff `supported and gate.asm_core_implemented` and the modulus
/// clears the large-L cutoff (see `montint.montSqr`).
pub fn montSqr(z: []u64, a: []const u64, m: []const u64, n0inv: u64, scratch: []u64) void {
    if (comptime supported) {
        montSqrAmd64(z, a, m, n0inv, scratch);
    } else {
        // Unreachable by construction: the dispatcher in `montint.zig` and the
        // differential harness both comptime/runtime-guard on `supported`.
        unreachable;
    }
}

/// SOS Montgomery squaring, structurally IDENTICAL to the portable oracle
/// `montSqrCios` (its four phases, in order), with the two O(n²) inner loops —
/// the off-diagonal product rows and the REDC reduction rows — replaced by the
/// `MULX/ADCX/ADOX` dual-carry-chain row primitive `mulRow`. The O(n) glue
/// (doubling, diagonal, per-row tail carries) stays in Zig and is the SAME
/// arithmetic as the portable oracle, so bit-exactness reduces to the row
/// identity `t += x·v` (the row is the labels-1–4 half of `ciosIter`, already
/// proven by the montMul differential).
///
///   1. cross products — row i: `A[2i+1 .. i+n-1] += a[i]·a[i+1..n]`, carry
///      stored to `A[i+n]` (fresh: row i−1 topped out at `A[i+n−1]`). Each
///      off-diagonal product `a[i]·a[j]` (i<j) is computed ONCE.
///   2. double — `A ← 2·A` as the downward funnel shift
///      `A[k] = (A[k]<<1) | (A[k−1]>>63)` (identical value to the oracle's
///      carried upward shift; the dropped top bit is provably 0 because
///      `cross < B^(2n−1)`). This is where the ×2 lives — OUTSIDE the carry
///      chains, on the completed partial sum, so no interleaved-doubling carry
///      subtlety exists by construction.
///   3. diagonal — `A += Σ a[i]²·B^(2i)` with the 0/1 inter-pair carry
///      (`dcarry`) threaded exactly like the oracle.
///   4. word-serial REDC — row i: `u = A[i]·n0inv`; `A[i..i+n] += u·m` via
///      `mulRow` (the in-place row zeroes `A[i]` by construction); the row
///      carry + the pending `cc` fold into column `i+n` in Zig (u128), exactly
///      the oracle's threading. Result = `A[n..2n]` topped by `cc ∈ {0,1}`,
///      then the same masked `condSub`.
///
/// Constant-time: every trip count derives from the PUBLIC `n` and the loop
/// index (`len = n−1−i`); which products are halved is structural; no
/// secret-dependent branch, index, or store address; final reduce is masked.
fn montSqrAmd64(z: []u64, a: []const u64, m: []const u64, n0inv: u64, scratch: []u64) void {
    const n = m.len;
    std.debug.assert(n >= 1);
    std.debug.assert(z.len == n and a.len == n and scratch.len == 2 * n);
    const A = scratch;
    @memset(A, 0);

    // ── 1. cross products: A = Σ_{i<j} a[i]·a[j]·B^(i+j) ──
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        const len = n - 1 - i;
        A[i + n] = mulRow(A.ptr + (2 * i + 1), a.ptr + (i + 1), len & 3, len >> 2, a[i]);
    }
    // A[2n−1] is still 0 here: cross < B^(2n−1) (row n−2 topped out at A[2n−2]).

    // ── 2. double: A ← 2·A ──
    var k: usize = 2 * n - 1;
    while (k > 0) : (k -= 1) A[k] = (A[k] << 1) | (A[k - 1] >> 63);
    A[0] <<= 1;

    // ── 3. diagonal: A ← A + Σ_i a[i]²·B^(2i) ──
    var dcarry: u64 = 0;
    i = 0;
    while (i < n) : (i += 1) {
        const sq = @as(u128, a[i]) * @as(u128, a[i]);
        const p1 = @as(u128, A[2 * i]) + @as(u64, @truncate(sq)) + dcarry;
        A[2 * i] = @truncate(p1);
        const p2 = @as(u128, A[2 * i + 1]) + @as(u64, @truncate(sq >> 64)) + @as(u64, @truncate(p1 >> 64));
        A[2 * i + 1] = @truncate(p2);
        dcarry = @truncate(p2 >> 64); // ≤ 1; flows to A[2(i+1)] next round
    }
    // dcarry == 0 here: a² < B^(2n) fits exactly in 2n words.

    // ── 4. Montgomery reduce: z = A·R⁻¹ mod m ──
    const rrem = n & 3;
    const rgrp = n >> 2;
    var cc: u64 = 0; // carry into column i+n, carried between steps
    i = 0;
    while (i < n) : (i += 1) {
        const u = A[i] *% n0inv;
        const carry = mulRow(A.ptr + i, m.ptr, rrem, rgrp, u);
        // Column i+n collects the row carry plus the pending cc from step i−1
        // (the carry out of column (i−1)+n = i+n−1); the 0/1 carry out becomes
        // the next step's cc — no variable ripple (see montSqrCios phase 4).
        const s = @as(u128, A[i + n]) + carry + cc;
        A[i + n] = @truncate(s);
        cc = @truncate(s >> 64);
    }
    // result = A[n..2n] with top word cc (0/1 since A = a² < R·m).
    @memcpy(z, A[n .. 2 * n]);
    condSub(z, cc, m);
}

const IterCarries = struct { c1: u64, c2: u64 };

/// ONE full CIOS iteration for outer multiplier `x`:
///
///   mul row     `t[0..n] += x·v[0..n]`                      (labels 1–4)
///   u           `t[0]·n0inv mod 2^64` (imul; chains dead)
///   reduce row  `t[0..n-1] = (t[0..n] + u·m[0..n]) >> 64`   (labels 5–8)
///
/// with `n = rem + 4·grp = 1 + rrem + 4·rgrp` and `redpack = (rgrp<<2)|rrem`.
/// Returns the two row carries; the caller folds them into t[n]/t[n+1] and
/// stores t[n-1] (the reduce row writes only t[0..n-2]; limb 0 of its sum is
/// zero by construction and is computed only for its carry in the preamble;
/// the remaining limbs store shifted down one position: read `8(%rdi)`,
/// write `(%rdi)`).
///
/// Register plan: rdx = multiplier (implicit MULX operand; x, then u),
/// rdi/rsi = advancing t/v-or-m cursors, rcx = trip counter, rax = pending-hi
/// (becomes each row's carry out), r8 = current lo, r9/r11 = alternating hi,
/// r10 = zero. Across the mul row the reduce row's state rides in
/// callee-saved registers: rbx = m base, r12 = t base, r13 = n0inv,
/// r14 = redpack; r15 hands out c1. `grp` is parked in r11 across each
/// remainder loop (which doesn't touch r11).
///
/// Dual-carry-chain discipline (both rows): MULX touches no flag; ADCX
/// propagates the hi→lo product chain through CF; ADOX adds the t words
/// through OF. Loop control: `dec` preserves CF; OF is folded into the
/// pending-hi (`adoxq %r10`) before every `dec`; at loop boundaries CF is
/// folded with `adc` (provably cannot wrap — the carry into any limb position
/// fits 64 bits), after which flags are dead and `test`/`jz` is legal.
///
/// Every input is pinned to an explicit register and the modified ones are
/// tied to (discarded) outputs — the read-write idiom — because letting the
/// allocator place "r" inputs was observed to collide with the fixed `{rdx}`
/// binding under the self-hosted x86-64 backend (Debug builds).
inline fn ciosIter(tp: [*]u64, vp: [*]const u64, mp: [*]const u64, rem: usize, grp: usize, redpack: usize, n0inv: u64, x: u64) IterCarries {
    var c1: u64 = undefined;
    var c2: u64 = undefined;
    var d0: usize = undefined;
    var d1: usize = undefined;
    var d2: usize = undefined;
    var d3: usize = undefined;
    var d4: usize = undefined;
    asm volatile (
        \\ xorl %%r10d, %%r10d
        \\ xorl %%eax, %%eax
        \\ testq %%rcx, %%rcx
        \\ jz 2f
        \\1:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq (%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ movq %%r9, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 8(%%rsi), %%rsi
        \\ leaq 8(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 1b
        \\2:
        \\ adcq %%r10, %%rax
        \\ movq %%r11, %%rcx
        \\ testq %%rcx, %%rcx
        \\ jz 4f
        \\3:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq (%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ mulxq 8(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 8(%%rdi), %%r8
        \\ movq %%r8, 8(%%rdi)
        \\ mulxq 16(%%rsi), %%r8, %%r9
        \\ adcxq %%r11, %%r8
        \\ adoxq 16(%%rdi), %%r8
        \\ movq %%r8, 16(%%rdi)
        \\ mulxq 24(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 24(%%rdi), %%r8
        \\ movq %%r8, 24(%%rdi)
        \\ movq %%r11, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 32(%%rsi), %%rsi
        \\ leaq 32(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 3b
        \\4:
        \\ adcq %%r10, %%rax
        \\ movq %%rax, %%r15
        \\ movq (%%r12), %%rdx
        \\ imulq %%r13, %%rdx
        \\ movq %%r12, %%rdi
        \\ movq %%rbx, %%rsi
        \\ movq %%r14, %%rcx
        \\ andq $3, %%rcx
        \\ movq %%r14, %%r11
        \\ shrq $2, %%r11
        \\ xorl %%r10d, %%r10d
        \\ mulxq (%%rsi), %%r8, %%rax
        \\ adcxq (%%rdi), %%r8
        \\ adcq %%r10, %%rax
        \\ leaq 8(%%rsi), %%rsi
        \\ testq %%rcx, %%rcx
        \\ jz 6f
        \\5:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq 8(%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ movq %%r9, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 8(%%rsi), %%rsi
        \\ leaq 8(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 5b
        \\6:
        \\ adcq %%r10, %%rax
        \\ movq %%r11, %%rcx
        \\ testq %%rcx, %%rcx
        \\ jz 8f
        \\7:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq 8(%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ mulxq 8(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 16(%%rdi), %%r8
        \\ movq %%r8, 8(%%rdi)
        \\ mulxq 16(%%rsi), %%r8, %%r9
        \\ adcxq %%r11, %%r8
        \\ adoxq 24(%%rdi), %%r8
        \\ movq %%r8, 16(%%rdi)
        \\ mulxq 24(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 32(%%rdi), %%r8
        \\ movq %%r8, 24(%%rdi)
        \\ movq %%r11, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 32(%%rsi), %%rsi
        \\ leaq 32(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 7b
        \\8:
        \\ adcq %%r10, %%rax
        : [c2] "={rax}" (c2),
          [c1] "={r15}" (c1),
          [d0] "={rdi}" (d0),
          [d1] "={rsi}" (d1),
          [d2] "={rcx}" (d2),
          [d3] "={r11}" (d3),
          [d4] "={rdx}" (d4),
        : [tp] "{rdi}" (tp),
          [vp] "{rsi}" (vp),
          [rem] "{rcx}" (rem),
          [grp] "{r11}" (grp),
          [x] "{rdx}" (x),
          [mp] "{rbx}" (mp),
          [tb] "{r12}" (tp),
          [n0inv] "{r13}" (n0inv),
          [redpack] "{r14}" (redpack),
        : .{ .r8 = true, .r9 = true, .r10 = true, .cc = true, .memory = true });
    return .{ .c1 = c1, .c2 = c2 };
}

/// ONE `MULX/ADCX/ADOX` dual-carry-chain accumulate row:
///
///   `t[0..n) += x·v[0..n)`,  `n = rem + 4·grp`,  returns the carry-out word.
///
/// This is exactly the mul-row half of `ciosIter` (its labels 1–4), verbatim:
/// same remainder-then-4-unrolled structure (low limbs first, so limb order is
/// preserved), same flag discipline (MULX touches no flag; ADCX propagates the
/// hi→lo product chain through CF; ADOX adds the t words through OF; OF folded
/// into the pending-hi before every `dec`; CF folded with `adc` at loop
/// boundaries — provably no wrap, the carry into any limb position of
/// `t + x·v` fits 64 bits). `n == 0` is legal: touches nothing, returns 0.
///
/// The dedicated squaring (`montSqrAmd64`) drives this for both its
/// off-diagonal product rows and its REDC reduction rows. `pub` so the test
/// harness can build a deliberately-broken square from the SAME row primitive
/// (the positive control proving the squaring differential has teeth).
///
/// Register plan (subset of `ciosIter`'s): rdx = multiplier x (implicit MULX
/// operand, never written), rdi/rsi = advancing t/v cursors, rcx = trip
/// counter, rax = pending-hi (becomes the carry out), r8 = current lo,
/// r9/r11 = alternating hi (r11 doubles as the parked `grp` — the remainder
/// loop does not touch it), r10 = zero. Every input pinned to an explicit
/// register, modified ones tied to discarded outputs (see `ciosIter`'s note on
/// the self-hosted backend).
pub inline fn mulRow(tp: [*]u64, vp: [*]const u64, rem: usize, grp: usize, x: u64) u64 {
    if (comptime supported) {
        return mulRowAmd64(tp, vp, rem, grp, x);
    } else {
        // Unreachable by construction, exactly as in `montMul`/`montSqr` — but
        // this one needed the wrapper for a reason those two did not have. It
        // is `pub` because the KAT harness in this module builds a deliberately
        // broken square from the same primitive, and `pub` is what crosses a
        // file boundary in Zig. `check-pubfn-reach` instantiates every `pub fn`
        // DIRECTLY, on whatever target is being built, so the x86 asm below was
        // analysed on aarch64 and the aarch64 `Clobbers` struct has no `.r8`:
        // the ReleaseSafe arm64 lane of 2026-08-24 went red on it. Its callers
        // were all guarded; the guard belongs on the function, because the one
        // caller that skipped it was not a caller at all.
        unreachable;
    }
}

inline fn mulRowAmd64(tp: [*]u64, vp: [*]const u64, rem: usize, grp: usize, x: u64) u64 {
    var carry: u64 = undefined;
    var d0: usize = undefined;
    var d1: usize = undefined;
    var d2: usize = undefined;
    var d3: usize = undefined;
    asm volatile (
        \\ xorl %%r10d, %%r10d
        \\ xorl %%eax, %%eax
        \\ testq %%rcx, %%rcx
        \\ jz 2f
        \\1:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq (%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ movq %%r9, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 8(%%rsi), %%rsi
        \\ leaq 8(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 1b
        \\2:
        \\ adcq %%r10, %%rax
        \\ movq %%r11, %%rcx
        \\ testq %%rcx, %%rcx
        \\ jz 4f
        \\3:
        \\ mulxq (%%rsi), %%r8, %%r9
        \\ adcxq %%rax, %%r8
        \\ adoxq (%%rdi), %%r8
        \\ movq %%r8, (%%rdi)
        \\ mulxq 8(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 8(%%rdi), %%r8
        \\ movq %%r8, 8(%%rdi)
        \\ mulxq 16(%%rsi), %%r8, %%r9
        \\ adcxq %%r11, %%r8
        \\ adoxq 16(%%rdi), %%r8
        \\ movq %%r8, 16(%%rdi)
        \\ mulxq 24(%%rsi), %%r8, %%r11
        \\ adcxq %%r9, %%r8
        \\ adoxq 24(%%rdi), %%r8
        \\ movq %%r8, 24(%%rdi)
        \\ movq %%r11, %%rax
        \\ adoxq %%r10, %%rax
        \\ leaq 32(%%rsi), %%rsi
        \\ leaq 32(%%rdi), %%rdi
        \\ decq %%rcx
        \\ jnz 3b
        \\4:
        \\ adcq %%r10, %%rax
        : [carry] "={rax}" (carry),
          [d0] "={rdi}" (d0),
          [d1] "={rsi}" (d1),
          [d2] "={rcx}" (d2),
          [d3] "={r11}" (d3),
        : [tp] "{rdi}" (tp),
          [vp] "{rsi}" (vp),
          [rem] "{rcx}" (rem),
          [grp] "{r11}" (grp),
          [x] "{rdx}" (x),
        : .{ .r8 = true, .r9 = true, .r10 = true, .cc = true, .memory = true });
    return carry;
}

// Constant-time conditional subtract of `m` from the (n+1)-word value
// (`z` low n words, `top` the 0/1 carry word). Subtracts m iff the full value
// ≥ m, via a masked limb-select — no branch, no secret-dependent access.
// Same two-pass shape as `condSubTop` in `montint.zig`, which adopted it from
// here. One difference remains, and it is deliberate: `condSubTop` additionally
// launders `smask` through a `blackBox` barrier, because at its comptime-known
// `L` the loops fully unroll and LLVM recovers `smask ∈ {0, ~0}` and hoists
// pass 2 behind a branch on the secret borrow — measured. `n` is a runtime
// slice length here, this function measures 0 contexts under
// `scripts/ctgrind.sh montint` (target `asmcore`), and that measurement is the
// only reason it goes unlaundered. If it ever reads non-zero, add the barrier.
fn condSub(z: []u64, top: u64, m: []const u64) void {
    // Pass 1: borrow of z - m (value untouched).
    var borrow: u1 = 0;
    for (z, m) |zi, mi| {
        const s = @subWithOverflow(zi, mi);
        const s2 = @subWithOverflow(s[0], borrow);
        borrow = s[1] | s2[1];
    }
    // full value ≥ m ⟺ no underflow when subtracting borrow from top.
    const under = @subWithOverflow(top, @as(u64, borrow))[1]; // 1 ⇒ value < m
    const smask: u64 = 0 -% (1 -% @as(u64, under)); // all-ones ⇒ subtract m
    // Pass 2: z -= m & smask.
    var b2: u1 = 0;
    for (z, m) |*zi, mi| {
        const s = @subWithOverflow(zi.*, mi & smask);
        const s2 = @subWithOverflow(s[0], b2);
        zi.* = s2[0];
        b2 = s[1] | s2[1];
    }
}

// ── fixed-L unrolled CIOS (comptime-generated rows) — the hot path since 2026-10-10 ──
//
// `montMul` above runs RUNTIME-`n` rows (4-way unrolled loops, remainder loops,
// OF/CF folds at every group boundary, one asm block per outer limb). At the
// sizes RSA actually runs — the CRT halves at L = 16/24/32 — that bookkeeping
// cost more than the products: the portable comptime-unrolled CIOS beat it at
// L = 16 and the rsa bench sat at 1.9–2.4× OpenSSL (2026-10-10). `Modint` knows
// `L` at comptime, so this kernel spells each row out completely — `L` copies
// of `mulx / adcx mem / adox / mov` for the multiply row and the same for the
// reduction row — and keeps only the OUTER loop (trip count `L`, public) in the
// asm. Measured on the bench host (TSC cycles per multiply, ReleaseFast):
//   L = 16: 1273 → 989 · L = 24: 3032 → 1930 · L = 32: 4064 → 3154
// against the best of the previous `montMul`/`montSqr` at each size.
//
// One CIOS iteration (`t` = z, L words in memory; t[L] in r13, t[L+1] in r14):
//   mul row     (t[0..L], t[L], t[L+1]) += a·b[i]
//   u           t[0]·n0inv (imul — flags dead there)
//   reduce row  t = (t + u·m) >> 64, the store shifted down one limb
// Each row runs the two independent carry chains of the module doc: CF carries
// `t[j]` (`adcx` with a memory source), OF carries the previous product's high
// half (`adox`); the alternating hi register is r11/r12. The row tails fold
// both flags into t[L] / t[L+1] with a zero register (rax) — the same
// arithmetic, in the same order, as the portable `montMulCios`, which is the
// oracle the differential pins it to.
//
// Constant-time: the instruction stream is a comptime constant of `L`; the
// only branch is the outer loop's `jnz` on a public counter; every address is
// a fixed offset off a pinned base pointer; the final reduction is the masked
// `condSubFixed` (laundered mask, see `condSub`'s note on why that matters at
// a comptime `L`). Code size: ~8·L instructions per row pair, ~1.6 KB at L = 32.

/// Decimal text of a comptime integer (the row generator's byte offsets),
/// without `std.fmt` — whose comptime cost, at ~4·L formatted lines per
/// kernel and up to eight kernel sizes per build, ran into the eval quota.
fn decStr(comptime n: usize) []const u8 {
    comptime {
        if (n == 0) return "0";
        var buf: [20]u8 = undefined;
        var i: usize = buf.len;
        var x = n;
        while (x > 0) : (x /= 10) {
            i -= 1;
            buf[i] = '0' + @as(u8, @intCast(x % 10));
        }
        const out = buf[i..].*;
        return &out;
    }
}

/// A comptime text builder appending into a fixed buffer: linear in the
/// output size, where repeated `++` re-copies the whole prefix per piece
/// (quadratic — it doubled montint's test compile time with the square
/// kernel's ~2·L² lines).
fn AsmText(comptime cap: usize) type {
    return struct {
        buf: [cap]u8 = undefined,
        len: usize = 0,
        fn put(self: *@This(), comptime piece: []const u8) void {
            @memcpy(self.buf[self.len..][0..piece.len], piece);
            self.len += piece.len;
        }
    };
}

fn hiReg(comptime j: usize) []const u8 {
    return if (j % 2 == 0) "%%r11" else "%%r12";
}

/// The asm text of ONE outer CIOS iteration for a fixed `L` (see above).
/// Register plan: rdi = t (= z), rsi = a, rbx = &b[i] (advanced by the loop),
/// rcx = m, r8 = n0inv, r9 = outer counter, rdx = MULX multiplier, rax = 0,
/// r10 = current lo, r11/r12 = alternating hi, r13 = t[L], r14 = t[L+1],
/// r15 = t[0] (memory word t[0] is written only by the reduce row).
fn ciosFixedBody(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var s: AsmText(400 * L + 512) = .{};
        // mul row: t[j] += a[j]·b_i (+ hi of j−1), j = 0..L−1
        // t[0] lives in r15 across rows (never reloaded from memory): the
        // reduce row's `u = t[0]·n0inv` and the next mul row's first add
        // would otherwise each wait on a store-to-load forward of t[0], and
        // both sit on the row-to-row critical path.
        s.put(" movq (%%rbx), %%rdx\n xorl %%eax, %%eax\n");
        s.put(" mulxq (%%rsi), %%r10, %%r11\n adcxq %%r15, %%r10\n movq %%r10, %%r15\n");
        for (1..L) |j| {
            const o = decStr(8 * j);
            s.put(" mulxq " ++ o ++ "(%%rsi), %%r10, " ++ hiReg(j) ++ "\n" ++
                " adcxq " ++ o ++ "(%%rdi), %%r10\n" ++
                " adoxq " ++ hiReg(j - 1) ++ ", %%r10\n" ++
                " movq %%r10, " ++ o ++ "(%%rdi)\n");
        }
        // (t[L+1]:t[L]) = t[L] + hi_{L−1} + CF + OF
        s.put(" adcxq %%rax, %%r13\n adoxq " ++ hiReg(L - 1) ++ ", %%r13\n" ++
            " movl $0, %%r14d\n adcxq %%rax, %%r14\n adoxq %%rax, %%r14\n");
        // reduce row: u = t[0]·n0inv; t = (t + u·m) >> 64
        s.put(" movq %%r15, %%rdx\n imulq %%r8, %%rdx\n xorl %%eax, %%eax\n");
        s.put(" mulxq (%%rcx), %%r10, %%r11\n adcxq %%r15, %%r10\n");
        for (1..L) |j| {
            const o = decStr(8 * j);
            s.put(" mulxq " ++ o ++ "(%%rcx), %%r10, " ++ hiReg(j) ++ "\n" ++
                " adcxq " ++ o ++ "(%%rdi), %%r10\n" ++
                " adoxq " ++ hiReg(j - 1) ++ ", %%r10\n" ++
                " movq %%r10, " ++ decStr(8 * (j - 1)) ++ "(%%rdi)\n");
            if (j == 1) s.put(" movq %%r10, %%r15\n");
        }
        // t[L−1] = t[L] + hi_{L−1} + CF + OF; t[L] = t[L+1] + the two carries
        s.put(" adcxq %%rax, %%r13\n adoxq " ++ hiReg(L - 1) ++ ", %%r13\n" ++
            " movq %%r13, " ++ decStr(8 * (L - 1)) ++ "(%%rdi)\n" ++
            " movq %%r14, %%r13\n adcxq %%rax, %%r13\n adoxq %%rax, %%r13\n");
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// `z = a·b·R⁻¹ mod m` for a COMPTIME limb count `L` (same contract as
/// `montMul`: full 2^64 limbs, `a, b < m`, `z` aliases none of `a`, `b`, `m`;
/// `a == b` is fine). Dispatched by `Modint.montMul`/`montSqr` iff
/// `supported and gate.asm_core_implemented` and `L >= montint.fixed_min_limbs`.
pub fn montMulFixed(comptime L: usize, z: *[L]u64, a: *const [L]u64, b: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    if (comptime supported) {
        montMulFixedAmd64(L, z, a, b, m, n0inv);
    } else {
        unreachable; // guarded by every caller; see `mulRow` for why `pub` needs this
    }
}

fn montMulFixedAmd64(comptime L: usize, z: *[L]u64, a: *const [L]u64, b: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    comptime std.debug.assert(L >= 2);
    @memset(z, 0);
    const body = comptime ciosFixedBody(L);
    var top: u64 = undefined;
    var d_b: usize = undefined;
    var d_cnt: usize = undefined;
    asm volatile (" xorl %%r13d, %%r13d\n xorl %%r15d, %%r15d\n" ++ "1:\n" ++ body ++ " addq $8, %%rbx\n decq %%r9\n jnz 1b\n"
        : [top] "={r13}" (top),
          [db] "={rbx}" (d_b),
          [dc] "={r9}" (d_cnt),
        : [zp] "{rdi}" (z),
          [ap] "{rsi}" (a),
          [bp] "{rbx}" (b),
          [mp] "{rcx}" (m),
          [n0] "{r8}" (n0inv),
          [cnt] "{r9}" (@as(usize, L)),
        : .{ .rax = true, .rdx = true, .r10 = true, .r11 = true, .r12 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
    // t < 2m: top ∈ {0, 1}; constant-time final reduce.
    condSubFixed(L, z, top, m);
}

/// The asm text of the fixed-`L` SOS Montgomery SQUARE (see `montSqrFixed`).
/// Register plan: rsi = a, rdi = A (2L-word scratch; advanced only in the
/// final reduction loop), rcx = m, r8 = n0inv, r9 = reduction counter,
/// rdx = MULX multiplier, rax = 0, r10 = lo, r11/r12 = alternating hi,
/// r13 = the pending column carry `cc`, r14 = scratch, r15 = A[i] (REDC).
fn sqrFixedText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(2_000_000);
        var s: AsmText(100 * L * L + 400 * L + 512) = .{};
        // 1. cross products: row i adds a[i]·a[i+1..L−1] into A[2i+1 .. i+L−1]
        //    (CF: the A words, OF: the previous high half); the row carry
        //    lands in the still-untouched A[i+L].
        for (0..L - 1) |i| {
            s.put(" movq " ++ decStr(8 * i) ++ "(%%rsi), %%rdx\n xorl %%eax, %%eax\n");
            for (i + 1..L) |j| {
                const k = decStr(8 * (i + j));
                s.put(" mulxq " ++ decStr(8 * j) ++ "(%%rsi), %%r10, " ++ hiReg(j) ++ "\n" ++
                    " adcxq " ++ k ++ "(%%rdi), %%r10\n");
                if (j > i + 1) s.put(" adoxq " ++ hiReg(j - 1) ++ ", %%r10\n");
                s.put(" movq %%r10, " ++ k ++ "(%%rdi)\n");
            }
            s.put(" adcxq %%rax, " ++ hiReg(L - 1) ++ "\n adoxq %%rax, " ++ hiReg(L - 1) ++ "\n" ++
                " movq " ++ hiReg(L - 1) ++ ", " ++ decStr(8 * (i + L)) ++ "(%%rdi)\n");
        }
        // 2. A ← 2·A + Σ a[i]²·B^(2i): CF doubles each word in place (adcx r,r),
        //    OF adds the diagonal halves; a² < B^(2L), so both chains end at 0.
        s.put(" xorl %%eax, %%eax\n");
        for (0..L) |i| {
            const lo = decStr(16 * i);
            const hi = decStr(16 * i + 8);
            s.put(" movq " ++ decStr(8 * i) ++ "(%%rsi), %%rdx\n mulxq %%rdx, %%r11, %%r12\n" ++
                " movq " ++ lo ++ "(%%rdi), %%r10\n adcxq %%r10, %%r10\n adoxq %%r11, %%r10\n movq %%r10, " ++ lo ++ "(%%rdi)\n" ++
                " movq " ++ hi ++ "(%%rdi), %%r10\n adcxq %%r10, %%r10\n adoxq %%r12, %%r10\n movq %%r10, " ++ hi ++ "(%%rdi)\n");
        }
        // 3. word-serial REDC: L rows of A[i..i+L−1] += u·m (u = A[i]·n0inv),
        //    the row carry plus the pending cc folded into A[i+L] — the
        //    portable `montSqrCios` phase 4, one asm loop iteration per row.
        //    A[i] rides in r15 from the previous row (its j = 1 word), so
        //    `u` never waits on a store-to-load forward; the row's own word 0
        //    (≡ 0 by the choice of u) is not stored — nothing reads it.
        s.put(" xorl %%r13d, %%r13d\n movl $" ++ decStr(L) ++ ", %%r9d\n movq (%%rdi), %%r15\n2:\n");
        s.put(" movq %%r15, %%rdx\n imulq %%r8, %%rdx\n xorl %%eax, %%eax\n");
        s.put(" mulxq (%%rcx), %%r10, %%r11\n adcxq %%r15, %%r10\n");
        for (1..L) |j| {
            const o = decStr(8 * j);
            s.put(" mulxq " ++ o ++ "(%%rcx), %%r10, " ++ hiReg(j) ++ "\n" ++
                " adcxq " ++ o ++ "(%%rdi), %%r10\n" ++
                " adoxq " ++ hiReg(j - 1) ++ ", %%r10\n" ++
                " movq %%r10, " ++ o ++ "(%%rdi)\n");
            if (j == 1) s.put(" movq %%r10, %%r15\n");
        }
        const top = decStr(8 * L);
        s.put(" adcxq %%rax, " ++ hiReg(L - 1) ++ "\n adoxq %%rax, " ++ hiReg(L - 1) ++ "\n" ++
            " movq " ++ top ++ "(%%rdi), %%r10\n xorl %%r14d, %%r14d\n" ++
            " addq %%r13, %%r10\n adcq $0, %%r14\n addq " ++ hiReg(L - 1) ++ ", %%r10\n adcq $0, %%r14\n" ++
            " movq %%r10, " ++ top ++ "(%%rdi)\n movq %%r14, %%r13\n" ++
            " addq $8, %%rdi\n decq %%r9\n jnz 2b\n");
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// Upper limb count served by the dedicated fixed square: its cross-product
/// phase is fully unrolled (~2·L² instructions — ~12 KB at L = 32), so wider
/// moduli keep squaring through `montMulFixed(a, a)`.
pub const sqr_fixed_max_limbs: usize = 32;

/// `z = a²·R⁻¹ mod m` for a comptime `L` in `[2, sqr_fixed_max_limbs]` —
/// the SOS square with every row unrolled: `L(L−1)/2` cross products (each
/// computed once, doubled in one pass with the diagonal), then `L` REDC rows.
/// `L² + L(L−1)/2` products against `montMulFixed`'s `2·L²`. Same contract as
/// `montMulFixed` with `b == a`; `z` must not alias `a` or `m`. The REDC
/// threading is exactly the portable `montSqrCios`'s (and the runtime-`n`
/// `montSqr`'s), so both are its oracles. Constant-time on the same terms as
/// `montMulFixed`: a comptime instruction stream, one public loop counter,
/// fixed offsets, the laundered `condSubFixed`.
pub fn montSqrFixed(comptime L: usize, z: *[L]u64, a: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    if (comptime supported) {
        montSqrFixedAmd64(L, z, a, m, n0inv);
    } else {
        unreachable; // guarded by every caller; see `mulRow`
    }
}

fn montSqrFixedAmd64(comptime L: usize, z: *[L]u64, a: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    comptime std.debug.assert(L >= 2 and L <= sqr_fixed_max_limbs);
    var A: [2 * L]u64 = @as([2 * L]u64, @splat(0));
    defer std.crypto.secureZero(u64, &A);
    const text = comptime sqrFixedText(L);
    var cc: u64 = undefined;
    var d_a: usize = undefined;
    var d_cnt: usize = undefined;
    asm volatile (text
        : [cc] "={r13}" (cc),
          [da] "={rdi}" (d_a),
          [dc] "={r9}" (d_cnt),
        : [ap] "{rsi}" (a),
          [Ap] "{rdi}" (&A),
          [mp] "{rcx}" (m),
          [n0] "{r8}" (n0inv),
        : .{ .rax = true, .rdx = true, .r10 = true, .r11 = true, .r12 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
    z.* = A[L..].*;
    condSubFixed(L, z, cc, m);
}

inline fn blackBox(x: u64) u64 {
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

/// `condSub` at a comptime `L`: `z ← z − m` iff `top·B^L + z ≥ m` (the
/// value is `< 2m`, `top ∈ {0, 1}`), in asm since 2026-10-14. The Zig form
/// (`condSubFixedZig`, kept as the test oracle) needed a laundered mask —
/// fully unrolled, LLVM recovers `smask ∈ {0, ~0}` and hoists pass 2 behind a
/// branch on the secret borrow — and even laundered it compiled to ~240
/// cycles at L = 16, a quarter of a block-kernel square (perf, bench host).
/// Pass 1 runs the `sub/sbb` borrow chain without storing; `sbb $0, top` then
/// `sbb rcx, rcx` turn the outcome into a keep mask; pass 2 subtracts
/// `m << c << c` with `c = keep ? 32 : 0` — `shlx` leaves the flags alone, so
/// the masked operand never interrupts pass 2's own borrow chain (an `and`
/// would clear CF), and its latency does not depend on the count. (`pdep`
/// would also mask without flags, but is microcoded with value-dependent
/// timing on AMD Zen 1/2.)
fn condSubFixed(comptime L: usize, z: *[L]u64, top: u64, m: *const [L]u64) void {
    condSubInto(L, z, z, top, m);
}

/// `condSubFixed` reading the value from `src` and writing the result to
/// `z` (either may alias) — the block kernels reduce straight out of their
/// accumulator's high half, with no copy (an L-word copy is a
/// `compiler_rt.memcpy` call at L = 48).
fn condSubInto(comptime L: usize, z: *[L]u64, src: *const [L]u64, top: u64, m: *const [L]u64) void {
    const text = comptime condSubText(L);
    var d_top: u64 = undefined;
    var d_cx: u64 = undefined;
    asm volatile (text
        : [t] "={rdx}" (d_top),
          [c] "={rcx}" (d_cx),
        : [z] "{rdi}" (z),
          [src] "{r8}" (src),
          [m] "{rsi}" (m),
          [top] "{rdx}" (top),
        : .{ .rax = true, .cc = true, .memory = true });
}

fn condSubText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var s: AsmText(240 * L + 256) = .{};
        s.put(" movq (%%r8), %%rax\n subq (%%rsi), %%rax\n");
        for (1..L) |i| s.put(" movq " ++ decStr(8 * i) ++ "(%%r8), %%rax\n sbbq " ++ decStr(8 * i) ++ "(%%rsi), %%rax\n");
        s.put(" sbbq $0, %%rdx\n sbbq %%rcx, %%rcx\n andl $32, %%ecx\n");
        // Pass 2 loads, subtracts in a register and stores: a memory-
        // destination `sbb` puts its load/store round trip on the CF chain
        // (measured 3× slower at L = 48).
        s.put(" shlxq %%rcx, (%%rsi), %%rax\n shlxq %%rcx, %%rax, %%rax\n movq (%%r8), %%rdx\n subq %%rax, %%rdx\n movq %%rdx, (%%rdi)\n");
        for (1..L) |i| {
            const o = decStr(8 * i);
            s.put(" shlxq %%rcx, " ++ o ++ "(%%rsi), %%rax\n shlxq %%rcx, %%rax, %%rax\n movq " ++ o ++ "(%%r8), %%rdx\n sbbq %%rax, %%rdx\n movq %%rdx, " ++ o ++ "(%%rdi)\n");
        }
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// The portable-Zig form of `condSubFixed` — the oracle its test compares to.
fn condSubFixedZig(comptime L: usize, z: *[L]u64, top: u64, m: *const [L]u64) void {
    var borrow: u1 = 0;
    for (z, m) |zi, mi| {
        const s = @subWithOverflow(zi, mi);
        const s2 = @subWithOverflow(s[0], borrow);
        borrow = s[1] | s2[1];
    }
    const under = @subWithOverflow(top, @as(u64, borrow))[1]; // 1 ⇒ value < m
    const smask: u64 = blackBox(0 -% (1 -% @as(u64, under)));
    var b2: u1 = 0;
    for (z, m) |*zi, mi| {
        const s = @subWithOverflow(zi.*, mi & smask);
        const s2 = @subWithOverflow(s[0], b2);
        zi.* = s2[0];
        b2 = s[1] | s2[1];
    }
}

test "condSubFixed (asm) == condSubFixedZig at the decision edges" {
    if (comptime !supported) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0xC0D5_0B);
    const rand = prng.random();
    inline for (.{ 2, 16, 17, 64 }) |L| {
        for (0..3000) |t| {
            var m: [L]u64 = undefined;
            for (&m) |*w| w.* = rand.int(u64);
            m[L - 1] |= 1 << 63;
            var z: [L]u64 = m;
            var top: u64 = 0;
            switch (t % 6) {
                0 => {}, // z == m: subtract to 0
                1 => z[0] -%= 1, // m − 1 (or, if m[0] == 0, a value in (m, 2m))
                2 => z[t % L] +%= 1,
                3 => { // top = 1, z small: value = B^L + z < 2m
                    top = 1;
                    for (&z) |*w| w.* = rand.int(u64) >> 2;
                },
                else => for (&z) |*w| {
                    w.* = rand.int(u64);
                }, // random z < B^L ≤ 2m
            }
            var want = z;
            condSubFixedZig(L, &want, top, &m);
            var got = z;
            condSubFixed(L, &got, top, &m);
            try std.testing.expectEqualSlices(u64, &want, &got);
        }
    }
}

// ── 8-row block kernels (2026-10-14) ────────────────────────────────────────
//
// What `montMulFixed`/`montSqrFixed` dispatch to when `L % 8 == 0` — every
// RSA CRT half (L = 16/24/32) and modulus (L = 32/48/64). The fixed kernels
// above add each limb product into a MEMORY word (`adcx mem` + `mov` back),
// so every row reads and writes all of `t` and the next row waits on those
// stores: ~6.6 µops per product at L = 16 issued at ~3 µops/cycle (perf, the
// bench host), and the square no better than 0.9 of a multiply.
//
// Here eight rows share an accumulator WINDOW of eight registers (r8–r15):
// position `q` of the double-width accumulator always lives in
// `r(8 + q mod 8)`, so the window slides one register per row with no moves,
// and a chunk of eight rows × eight columns is the same instruction text at
// every chunk offset (one public loop). One limb product is
//   mulx Y[j], lo, hi · adcx lo → w[P+j] (CF chain) · adox hi → w[P+j+1] (OF)
// four fused µops; memory is touched once per eight rows. Row r of a chunk
// covers positions P..P+8 (P = chunk base + r); its last product writes the
// high half straight into the register just vacated by position P (stored,
// or discarded where it is zero by construction), then folds CF and OF into
// it. That fold cannot overflow: the window P..P+7 holds a value < B^8 and
// x·Y[chunk] < (B−1)(B^8−1), so their sum is < B^9 (B = 2^64).
//
// Memory words of the accumulator enter the window once per chunk (eight
// `adcx mem` — a carry chain of its own whose carry-out is parked in a stack
// slot and resumed at the next chunk, the position it belongs to) and leave it
// once per row (the final word P). Three phases use the one engine:
//   product   A = a·b: blocks of eight rows b[8t..8t+8), chunks over a
//   cross     A = Σ_{i<j} a[i]a[j]B^(i+j): block t = rows a[8t..8t+8) over
//             columns a[8t..L); chunk 0 is the triangle (row r starts at
//             column r+1), the rest full chunks
//   REDC      A ← (A + U·m)/R in place: block t computes u_r = A[8t+r]·n0inv
//             in its chunk 0 (where that word is final), parks them in stack
//             slots for the later chunks, and adds the high half of A at the
//             block end with the previous block's carry-out word.
// The product and cross phases write only fresh (zero) words at a block end,
// so A must be zeroed first; the square adds the doubling + diagonal pass of
// `sqrFixedText` between cross and REDC.
//
// Stack: each asm block moves rsp down 256 bytes (the 128-byte red zone below
// the compiler's rsp stays untouched) and keeps 16 qword slots at 0(%rsp):
//   0..56 u_0..u_7 · 64 s (parked chunk carry) · 72 p (REDC carry word)
//   80 chunk counter · 88 block counter · 96 block A base · 104 chunk count
//   112 Y base
// and zeroes the secret-derived ones (0..72) before returning.
//
// Constant-time on the same terms as the kernels above: the instruction
// stream and both loop counts are comptime functions of `L` (the cross
// phase's chunk count per block is too: `L/8 − 1 − t`), every address is a
// fixed offset from a pointer advanced by public amounts, and the final
// reduction is the laundered `condSubFixed`.

/// Smallest `L` the block kernels serve (one full chunk beyond a block's own
/// columns), and the stride they need.
pub const block_min_limbs: usize = 16;

fn winReg(comptime q: usize) []const u8 {
    return switch (q % 8) {
        0 => "%%r8",
        1 => "%%r9",
        2 => "%%r10",
        3 => "%%r11",
        4 => "%%r12",
        5 => "%%r13",
        6 => "%%r14",
        else => "%%r15",
    };
}

fn winReg32(comptime q: usize) []const u8 {
    return switch (q % 8) {
        0 => "%%r8d",
        1 => "%%r9d",
        2 => "%%r10d",
        3 => "%%r11d",
        4 => "%%r12d",
        5 => "%%r13d",
        6 => "%%r14d",
        else => "%%r15d",
    };
}

/// What a row does with its multiplier and its final word.
const RowMode = enum {
    /// multiplier at `8r(%rcx)`; final word stored to `8r(%rdi)`
    load_rcx_store,
    /// multiplier at `8r(%rsp)` (a parked u); final word stored
    load_slot_store,
    /// REDC chunk 0: u = w[P]·n0inv (n0inv in rcx), parked at `8r(%rsp)`;
    /// the final word is 0 by the choice of u and is dropped
    redc_first,
};

/// One row `r` of a chunk: products `x·Y[j]` for `j` in `first..8`
/// (`first > 0` only in the cross phase's triangle). Entry and exit: CF = OF = 0.
fn emitRow(comptime s: anytype, comptime r: usize, comptime first: usize, comptime mode: RowMode) void {
    const r8 = decStr(8 * r);
    // Flags are 0 at every row boundary (the fold bound above), so the
    // `xor` changes no value: it WRITES CF/OF without reading them, which
    // cuts the flag dependency on the previous row's last `adcx`. Without it
    // the eight rows of a chunk are one serial CF chain; with it a row starts
    // as soon as its window words are in (two products into the row before).
    switch (mode) {
        .load_rcx_store => s.put(" movq " ++ r8 ++ "(%%rcx), %%rdx\n xorl %%eax, %%eax\n"),
        .load_slot_store => s.put(" movq " ++ r8 ++ "(%%rsp), %%rdx\n xorl %%eax, %%eax\n"),
        // imul leaves CF/OF undefined: the xor restores the row's entry state.
        .redc_first => s.put(" movq " ++ winReg(r) ++ ", %%rdx\n imulq %%rcx, %%rdx\n movq %%rdx, " ++ r8 ++ "(%%rsp)\n xorl %%eax, %%eax\n"),
    }
    if (first > 0) {
        // Triangle row: position P gets nothing from this row and is final.
        s.put(" movq " ++ winReg(r) ++ ", " ++ r8 ++ "(%%rdi)\n");
        if (first == 8) {
            // No products at all: P+8 starts empty. (Flags are 0 already;
            // xor keeps them 0.)
            s.put(" xorl " ++ winReg32(r) ++ ", " ++ winReg32(r) ++ "\n");
            return;
        }
    }
    for (first..8) |j| {
        const yo = decStr(8 * j);
        if (j < 7) {
            s.put(" mulxq " ++ yo ++ "(%%rsi), %%rax, %%rbx\n" ++
                " adcxq %%rax, " ++ winReg(r + j) ++ "\n" ++
                " adoxq %%rbx, " ++ winReg(r + j + 1) ++ "\n");
        } else {
            s.put(" mulxq " ++ yo ++ "(%%rsi), %%rax, " ++ winReg(r + 8) ++ "\n" ++
                " adcxq %%rax, " ++ winReg(r + 7) ++ "\n" ++
                " movl $0, %%eax\n" ++
                " adoxq %%rax, " ++ winReg(r + 8) ++ "\n" ++
                " adcxq %%rax, " ++ winReg(r + 8) ++ "\n");
        }
        if (j == 0 and mode != .redc_first) {
            // P is final once its own product is in.
            s.put(" movq " ++ winReg(r) ++ ", " ++ r8 ++ "(%%rdi)\n");
        }
    }
}

/// Load the window from `0..56(%rdi)` at a block's first chunk; s = 0.
fn emitChunkLoad(comptime s: anytype) void {
    for (0..8) |i| s.put(" movq " ++ decStr(8 * i) ++ "(%%rdi), " ++ winReg(i) ++ "\n");
    s.put(" movq $0, 64(%%rsp)\n xorl %%eax, %%eax\n");
}

/// Add the memory words `0..56(%rdi)` into the window at a later chunk,
/// resuming the parked carry s and parking the new one. Leaves CF = OF = 0.
fn emitChunkAdd(comptime s: anytype) void {
    s.put(" movq 64(%%rsp), %%rax\n negq %%rax\n"); // CF = s, OF = 0
    for (0..8) |i| s.put(" adcxq " ++ decStr(8 * i) ++ "(%%rdi), " ++ winReg(i) ++ "\n");
    s.put(" movl $0, %%eax\n adcxq %%rax, %%rax\n movq %%rax, 64(%%rsp)\n");
}

/// Block end over FRESH words (product, cross): window + s → `0..56(%rdi)`.
fn emitBlockEndFresh(comptime s: anytype) void {
    s.put(" movq 64(%%rsp), %%rax\n negq %%rax\n movl $0, %%eax\n");
    for (0..8) |i| s.put(" adcxq %%rax, " ++ winReg(i) ++ "\n");
    for (0..8) |i| s.put(" movq " ++ winReg(i) ++ ", " ++ decStr(8 * i) ++ "(%%rdi)\n");
}

/// REDC block end: window + A-high words + s + p (the previous block's
/// carry-out word, which lands on this block's end position) → `0..56(%rdi)`;
/// the carry-out (CF + OF, a small word) becomes the new p.
fn emitBlockEndRedc(comptime s: anytype) void {
    s.put(" movq 64(%%rsp), %%rax\n negq %%rax\n movq 72(%%rsp), %%rbx\n movl $0, %%eax\n");
    s.put(" adcxq 0(%%rdi), " ++ winReg(0) ++ "\n adoxq %%rbx, " ++ winReg(0) ++ "\n");
    for (1..8) |i| s.put(" adcxq " ++ decStr(8 * i) ++ "(%%rdi), " ++ winReg(i) ++ "\n adoxq %%rax, " ++ winReg(i) ++ "\n");
    s.put(" movl $0, %%ebx\n adcxq %%rax, %%rbx\n adoxq %%rax, %%rbx\n movq %%rbx, 72(%%rsp)\n");
    for (0..8) |i| s.put(" movq " ++ winReg(i) ++ ", " ++ decStr(8 * i) ++ "(%%rdi)\n");
}

fn emitChunk(comptime s: anytype, comptime mode: RowMode) void {
    for (0..8) |r| emitRow(s, r, 0, mode);
}

const frame_bytes = "256";

fn emitFrameEnter(comptime s: anytype) void {
    s.put(" subq $" ++ frame_bytes ++ ", %%rsp\n");
}

fn emitFrameLeave(comptime s: anytype) void {
    // Slots 0..72 (u_0..u_7, s, p) are secret-derived; 80..112 hold public
    // counters and pointers.
    for (0..10) |i| s.put(" movq $0, " ++ decStr(8 * i) ++ "(%%rsp)\n");
    s.put(" addq $" ++ frame_bytes ++ ", %%rsp\n");
}

/// A = a·b (A: 2L words, zeroed by the caller). Registers on entry:
/// rdi = A, rsi = a, rcx = b.
fn productBlockText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(400_000);
        var s: AsmText(40_000) = .{};
        const nb = L / 8;
        emitFrameEnter(&s);
        s.put(" movq $" ++ decStr(nb) ++ ", 88(%%rsp)\n movq %%rdi, 96(%%rsp)\n movq %%rsi, 112(%%rsp)\n");
        s.put("3:\n");
        emitChunkLoad(&s);
        emitChunk(&s, .load_rcx_store);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n movq $" ++ decStr(nb - 1) ++ ", 80(%%rsp)\n");
        s.put("4:\n");
        emitChunkAdd(&s);
        emitChunk(&s, .load_rcx_store);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n decq 80(%%rsp)\n jnz 4b\n");
        emitBlockEndFresh(&s);
        s.put(" addq $64, %%rcx\n movq 96(%%rsp), %%rdi\n addq $64, %%rdi\n movq %%rdi, 96(%%rsp)\n" ++
            " movq 112(%%rsp), %%rsi\n decq 88(%%rsp)\n jnz 3b\n");
        emitFrameLeave(&s);
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// A = Σ_{i<j} a[i]a[j]B^(i+j) (A: 2L words, zeroed by the caller).
/// Registers on entry: rdi = A, rsi = rcx = a.
fn crossBlockText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(400_000);
        var s: AsmText(40_000) = .{};
        const nb = L / 8;
        emitFrameEnter(&s);
        s.put(" movq $" ++ decStr(nb) ++ ", 88(%%rsp)\n movq %%rdi, 96(%%rsp)\n movq $" ++ decStr(nb - 1) ++ ", 104(%%rsp)\n");
        s.put("3:\n");
        emitChunkLoad(&s);
        for (0..8) |r| emitRow(&s, r, r + 1, .load_rcx_store);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n movq 104(%%rsp), %%rax\n movq %%rax, 80(%%rsp)\n testq %%rax, %%rax\n jz 5f\n");
        s.put("4:\n");
        emitChunkAdd(&s);
        emitChunk(&s, .load_rcx_store);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n decq 80(%%rsp)\n jnz 4b\n");
        s.put("5:\n");
        emitBlockEndFresh(&s);
        // next block: rows a[8t+8..], columns from a[8t+8], A base + 16 words
        s.put(" addq $64, %%rcx\n movq %%rcx, %%rsi\n movq 96(%%rsp), %%rdi\n addq $128, %%rdi\n movq %%rdi, 96(%%rsp)\n" ++
            " decq 104(%%rsp)\n decq 88(%%rsp)\n jnz 3b\n");
        emitFrameLeave(&s);
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// A ← (A + U·m)/R in place over 2L words; the result is A[L..2L) with the
/// carry word returned in rax. Registers on entry: rdi = A, rsi = m,
/// rcx = n0inv.
fn redcBlockText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(400_000);
        var s: AsmText(40_000) = .{};
        const nb = L / 8;
        emitFrameEnter(&s);
        s.put(" movq $" ++ decStr(nb) ++ ", 88(%%rsp)\n movq %%rdi, 96(%%rsp)\n movq %%rsi, 112(%%rsp)\n movq $0, 72(%%rsp)\n");
        s.put("3:\n");
        emitChunkLoad(&s);
        emitChunk(&s, .redc_first);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n movq $" ++ decStr(nb - 1) ++ ", 80(%%rsp)\n");
        s.put("4:\n");
        emitChunkAdd(&s);
        emitChunk(&s, .load_slot_store);
        s.put(" addq $64, %%rsi\n addq $64, %%rdi\n decq 80(%%rsp)\n jnz 4b\n");
        emitBlockEndRedc(&s);
        s.put(" movq 96(%%rsp), %%rdi\n addq $64, %%rdi\n movq %%rdi, 96(%%rsp)\n" ++
            " movq 112(%%rsp), %%rsi\n decq 88(%%rsp)\n jnz 3b\n");
        s.put(" movq 72(%%rsp), %%rax\n");
        emitFrameLeave(&s);
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

/// A ← 2·A + Σ a[i]²·B^(2i) over 2L words (`sqrFixedText` phase 2 on its own).
/// Registers on entry: rsi = a, rdi = A.
fn doubleDiagText(comptime L: usize) []const u8 {
    comptime {
        @setEvalBranchQuota(400_000);
        var s: AsmText(400 * L + 64) = .{};
        s.put(" xorl %%eax, %%eax\n");
        for (0..L) |i| {
            const lo = decStr(16 * i);
            const hi = decStr(16 * i + 8);
            s.put(" movq " ++ decStr(8 * i) ++ "(%%rsi), %%rdx\n mulxq %%rdx, %%r11, %%r12\n" ++
                " movq " ++ lo ++ "(%%rdi), %%r10\n adcxq %%r10, %%r10\n adoxq %%r11, %%r10\n movq %%r10, " ++ lo ++ "(%%rdi)\n" ++
                " movq " ++ hi ++ "(%%rdi), %%r10\n adcxq %%r10, %%r10\n adoxq %%r12, %%r10\n movq %%r10, " ++ hi ++ "(%%rdi)\n");
        }
        const out = s.buf[0..s.len].*;
        return &out;
    }
}

const have_avx = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx);

/// Zero `n` words with vector stores, in asm. Two reasons not to write
/// `@memset`/`secureZero`: past a few hundred bytes LLVM lowers `@memset` to
/// a call into Zig 0.16's byte-wise `compiler_rt.memset` (735 cycles for the
/// 768-byte `A` of an L = 48 multiply, about a quarter of its product phase —
/// perf on the bench host, 2026-10-14), and an asm store with a memory
/// clobber can never be elided, so the same routine is the wipe.
pub fn zeroWords(comptime n: usize, p: *[n]u64) void {
    const text = comptime blk: {
        @setEvalBranchQuota(100_000);
        var s: AsmText(40 * n + 64) = .{};
        const vw = if (have_avx) 4 else 2;
        s.put(if (have_avx) " vpxor %%xmm0, %%xmm0, %%xmm0\n" else " pxor %%xmm0, %%xmm0\n");
        var i: usize = 0;
        while (i + vw <= n) : (i += vw) {
            s.put((if (have_avx) " vmovdqu %%ymm0, " else " movdqu %%xmm0, ") ++ decStr(8 * i) ++ "(%%rdi)\n");
        }
        while (i < n) : (i += 1) s.put(" movq $0, " ++ decStr(8 * i) ++ "(%%rdi)\n");
        const out = s.buf[0..s.len].*;
        break :blk &out;
    };
    asm volatile (text
        :
        : [p] "{rdi}" (p),
        : .{ .xmm0 = true, .ymm0 = true, .memory = true });
}

const block_clobbers: std.builtin.assembly.Clobbers = .{
    .rax = true,
    .rbx = true,
    .rdx = true,
    .r8 = true,
    .r9 = true,
    .r10 = true,
    .r11 = true,
    .r12 = true,
    .r13 = true,
    .r14 = true,
    .r15 = true,
    .cc = true,
    .memory = true,
};

fn productBlock(comptime L: usize, A: *[2 * L]u64, a: *const [L]u64, b: *const [L]u64) void {
    const text = comptime productBlockText(L);
    var d_di: usize = undefined;
    var d_si: usize = undefined;
    var d_cx: usize = undefined;
    asm volatile (text
        : [di] "={rdi}" (d_di),
          [si] "={rsi}" (d_si),
          [cx] "={rcx}" (d_cx),
        : [A] "{rdi}" (A),
          [a] "{rsi}" (a),
          [b] "{rcx}" (b),
        : block_clobbers);
}

fn crossBlock(comptime L: usize, A: *[2 * L]u64, a: *const [L]u64) void {
    const text = comptime crossBlockText(L);
    var d_di: usize = undefined;
    var d_si: usize = undefined;
    var d_cx: usize = undefined;
    asm volatile (text
        : [di] "={rdi}" (d_di),
          [si] "={rsi}" (d_si),
          [cx] "={rcx}" (d_cx),
        : [A] "{rdi}" (A),
          [a] "{rsi}" (a),
          [a2] "{rcx}" (a),
        : block_clobbers);
}

fn doubleDiag(comptime L: usize, A: *[2 * L]u64, a: *const [L]u64) void {
    const text = comptime doubleDiagText(L);
    asm volatile (text
        :
        : [A] "{rdi}" (A),
          [a] "{rsi}" (a),
        : .{ .rax = true, .rdx = true, .r10 = true, .r11 = true, .r12 = true, .cc = true, .memory = true });
}

/// Returns the carry word of `(A + U·m)/R` (0 or 1 for `A < m·R`).
fn redcBlock(comptime L: usize, A: *[2 * L]u64, m: *const [L]u64, n0inv: u64) u64 {
    const text = comptime redcBlockText(L);
    var d_di: usize = undefined;
    var d_si: usize = undefined;
    var d_cx: usize = undefined;
    const top = asm volatile (text
        : [ret] "={rax}" (-> u64),
          [di] "={rdi}" (d_di),
          [si] "={rsi}" (d_si),
          [cx] "={rcx}" (d_cx),
        : [A] "{rdi}" (A),
          [m] "{rsi}" (m),
          [n0] "{rcx}" (n0inv),
        : block_clobbers);
    return top;
}

/// `z = a·b·R⁻¹ mod m` through the 8-row block engine (`L % 8 == 0`,
/// `L >= block_min_limbs`); same contract as `montMulFixed`.
pub fn montMulBlock(comptime L: usize, z: *[L]u64, a: *const [L]u64, b: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    if (comptime supported) {
        comptime std.debug.assert(L % 8 == 0 and L >= block_min_limbs);
        var A: [2 * L]u64 = undefined;
        zeroWords(2 * L, &A);
        defer zeroWords(2 * L, &A);
        productBlock(L, &A, a, b);
        const top = redcBlock(L, &A, m, n0inv);
        condSubInto(L, z, A[L..], top, m);
    } else {
        unreachable; // guarded by every caller; see `mulRow`
    }
}

/// `z = a²·R⁻¹ mod m` through the block engine: cross products, doubling +
/// diagonal, REDC. Same contract as `montSqrFixed`, any `L % 8 == 0`,
/// `L >= block_min_limbs` (no code-size cap: every phase loops).
pub fn montSqrBlock(comptime L: usize, z: *[L]u64, a: *const [L]u64, m: *const [L]u64, n0inv: u64) void {
    if (comptime supported) {
        comptime std.debug.assert(L % 8 == 0 and L >= block_min_limbs);
        var A: [2 * L]u64 = undefined;
        zeroWords(2 * L, &A);
        defer zeroWords(2 * L, &A);
        crossBlock(L, &A, a);
        doubleDiag(L, &A, a);
        const top = redcBlock(L, &A, m, n0inv);
        condSubInto(L, z, A[L..], top, m);
    } else {
        unreachable;
    }
}

// ── condSub borrow-chain coverage ───────────────────────────────────────────

test "condSub pass 2: the borrow must survive a limb where z[i] == m[i]" {
    // Companion to `montint.zig`'s "condSubTop: the borrow must survive a limb
    // where v[i] == m[i]". Both implementations of the conditional subtract
    // carry the same easy-to-drop, hard-to-notice term: the outgoing borrow is
    // `s[1] | s2[1]`, and `s2[1]` is live ONLY when `z[i] == m[i]` (so `s[1]`
    // and `s[0]` are both 0) with a borrow already coming in — probability
    // ~2⁻⁶⁴ per limb under random sampling. Verified by mutation: `b2 = s[1]`
    // alone left `zig build test-montint` fully green, including the 5000-case
    // asm-vs-portable differential and the squaring differentials, because
    // nothing they generate ever lands on an equal limb mid-borrow.
    //
    // This case pins PASS 2 only. In both cases below the subtract fires
    // (`smask` all-ones) and the mutated and correct PASS-1 borrows agree on
    // that decision — dropping pass 1's `s2[1]` here is masked by a later real
    // `s[1]`. Pass 1's copy of the term therefore needs its own input, and
    // gets it in the test that follows.
    //
    // Built at `n = 32` — 2048-bit, the smallest width the dispatch ever routes
    // here (`asm_min_limbs`) — against a FULL-WIDTH modulus. Full width also
    // discharges the `value < 2m` precondition for free: `m ≥ 2^2047` makes
    // `2m ≥ B^32`, so any `z < B^32` qualifies. Expectations are hand-computed,
    // not oracle-compared.
    const n = 32;
    const ones: u64 = 0xffff_ffff_ffff_ffff;
    const top_bit: u64 = @as(u64, 1) << 63;

    // (a) top == 1, with the equal limbs being the modulus's interior ZEROS.
    //     m = 2^2047 + 7; value = B^32 + 3, which is ≥ m and < 2m = B^32 + 14.
    //     Limbs 1..30 are 0 on both sides with a borrow in from limb 0, so the
    //     `s2[1]` term has to fire 30 times in a row. Result 2^2047 − 4.
    var m_a = @as([n]u64, @splat(0));
    m_a[0] = 7;
    m_a[n - 1] = top_bit;
    var z_a = @as([n]u64, @splat(0));
    z_a[0] = 3;
    condSub(&z_a, 1, &m_a);
    var want_a = @as([n]u64, @splat(ones));
    want_a[0] = ones - 3;
    want_a[n - 1] = top_bit - 1;
    try std.testing.expectEqualSlices(u64, &want_a, &z_a);

    // (b) top == 0, and the equal limb is a NONZERO one, so (a) cannot be
    //     dismissed as an artifact of zero limbs. m and z agree on limbs 3..31;
    //     z − m = B² − 2, which needs the borrow to cross the equal limb 1.
    var m_b = @as([n]u64, @splat(0xa5a5_a5a5_a5a5_a5a5));
    m_b[0] = 5;
    m_b[1] = 7;
    m_b[2] = 9;
    m_b[n - 1] = top_bit;
    var z_b = m_b;
    z_b[0] = 3;
    z_b[2] = 10; // z > m, so the subtract fires
    condSub(&z_b, 0, &m_b);
    var want_b = @as([n]u64, @splat(0));
    want_b[0] = ones - 1;
    want_b[1] = ones;
    try std.testing.expectEqualSlices(u64, &want_b, &z_b);
}

test "condSub pass 1: the outgoing borrow must survive a limb where z[i] == m[i]" {
    // PASS 1 carries its own copy of the same `borrow = s[1] | s2[1]` term, and
    // it is the copy that decides — `smask` is computed from pass 1's outgoing
    // borrow, so dropping `s2[1]` there does not corrupt a value, it flips the
    // reduction DECISION. Verified by mutation: `borrow = s[1]` in pass 1 left
    // `zig build test-montint` fully green (28 pass, exit 0) with the pass-2
    // case above already committed, which is why this case exists. This is the
    // copy on the amd64 asm path, i.e. the one RSA-2048/4096, `paillier` and
    // `vdf` take at `L >= asm_min_limbs`.
    //
    // The shape that isolates pass 1: pick `z = m − 1` with `top == 0`, so the
    // correct answer is "leave it alone". Limb 0 is the only place a real
    // `s[1]` borrow is generated; every limb above it has `z[i] == m[i]`, so
    // the borrow reaches the top ONLY through `s2[1]`. Dropping the term makes
    // pass 1 report no borrow, `smask` goes all-ones, and the mutant subtracts
    // `m` from a value below it, returning `B^n − 1`. Both cases below have
    // `smask == 0` at HEAD, so pass 2's own `s2[1]` term never fires and cannot
    // be what makes them red.
    //
    // Same `n = 32` full-width construction as above: `m ≥ 2^2047` makes
    // `2m ≥ B^32`, so the `value < 2m` precondition holds for free. Hand-
    // computed, not oracle-compared.
    const n = 32;
    const ones: u64 = 0xffff_ffff_ffff_ffff;
    const top_bit: u64 = @as(u64, 1) << 63;

    // (a) the equal limbs are the modulus's interior ZEROS. m = 2^2047 + 1,
    //     z = m − 1 = 2^2047. Limbs 1..31 are equal with a borrow in from
    //     limb 0, so `s2[1]` has to fire 31 times in a row for pass 1 to see
    //     that z < m.
    var m_a = @as([n]u64, @splat(0));
    m_a[0] = 1;
    m_a[n - 1] = top_bit;
    var z_a = m_a;
    z_a[0] = 0;
    const want_a = z_a; // unchanged: z < m
    condSub(&z_a, 0, &m_a);
    try std.testing.expectEqualSlices(u64, &want_a, &z_a);

    // (b) the equal limbs are NONZERO, so (a) cannot be dismissed as an
    //     artifact of zero limbs. m = 0xa5a5… in every limb but limb 0 (top
    //     bit already set, so it is full width), z = m − 1 again.
    var m_b = @as([n]u64, @splat(0xa5a5_a5a5_a5a5_a5a5));
    m_b[0] = 5;
    var z_b = m_b;
    z_b[0] = 4;
    const want_b = z_b; // unchanged: z < m
    condSub(&z_b, 0, &m_b);
    try std.testing.expectEqualSlices(u64, &want_b, &z_b);

    // A guard on the guard: the mutant's answer is `B^n − 1`, so if either
    // case above ever starts returning that, it is the mutation's signature
    // and not a new correct behaviour.
    const all_ones = @as([n]u64, @splat(ones));
    try std.testing.expect(!std.mem.eql(u64, &all_ones, &z_a));
    try std.testing.expect(!std.mem.eql(u64, &all_ones, &z_b));
}
