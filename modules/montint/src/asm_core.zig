// SPDX-License-Identifier: MIT

//! asm_core — the GATED irreducible x86-64 core (IMPLEMENTED).
//!
//! The hand-written `MULX/ADCX/ADOX` dual-carry-chain CIOS Montgomery multiply
//! (the OpenSSL `x86_64-mont5` technique). Everything else in the module (the
//! portable CIOS oracle, to/from Montgomery, add/sub, windowed modexp, and the
//! whole verification + bench harness) lives outside this file. See `gate.zig`
//! for the cut-line and `SPEC.md` for the algorithm + threat model.
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

// Constant-time conditional subtract of `m` from the (n+1)-word value
// (`z` low n words, `top` the 0/1 carry word). Subtracts m iff the full value
// ≥ m, via a masked limb-select — no branch, no secret-dependent access.
// Mirrors `condSubTop` in `montint.zig` (two passes instead of a stack diff
// buffer, because `n` is runtime here).
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
