// SPDX-License-Identifier: MIT

//! The amd64 field multiply and square: a Montgomery product mod m over six
//! limbs with `MULX` and the two independent carry chains of `ADCX` (CF) /
//! `ADOX` (OF), the reduction written for m's shape. m is the field order p
//! (`Kind.p`, `field.zig`) or the group order n (`Kind.n`, `scalar.zig`).
//!
//! The portable `mont.zig` product is correct but serial: LLVM lowers every
//! `u128` multiply-accumulate to `mulx` plus two `add`/`adc` pairs on one
//! carry chain, 550 instructions per multiply (2026-10-13, 70 ns). The first
//! amd64 core here (CIOS, a six-`mulx` row for q·p) took 360 instructions and
//! 50 ns; this one takes about 265 (2026-11-01, see SPEC § Performance).
//!
//! ## Algorithm: CIOS (word-by-word Montgomery), six rounds
//!
//! Accumulator T in eight registers T0..T7 (T < 2p after every round, but
//! T + a·b_i + q·p reaches 2^449, so one word above the six). Round i:
//!   1. T += a · b_i: six `mulx`, lows into T0..T5 (CF), highs into
//!      T1..T6 (OF), the OF chain flushed into T6 before the last product so
//!      that the last two words and T7 are closed by a plain `adc` chain;
//!   2. q = T0 · (−p⁻¹) mod 2^64 = T0 · (2^32 + 1), by shift and add (for n,
//!      an `imul` by −n⁻¹);
//!   3. T += q · p. Here p = 2^384 − K with K = 2^128 + 2^96 − 2^32 + 1 =
//!      (2^64 + 2^32 − 1)·2^64 + (2^64 − 2^32 + 1), so q·p = q·2^384 − q·K and
//!      the low word of q·K equals T0 (that is what q was chosen for): T0
//!      cancels with no borrow, and what is left of the round is
//!      T[1..] −= (q·2^64 + q·(2^32 − 1) + hi(q · (2^64 − 2^32 + 1))) and
//!      T[6] += q. That is two `mulx` (by 0xffffffff00000001 and 0xffffffff),
//!      two `adc`, a six-instruction subtract chain through T5 whose last
//!      borrow is taken off q before the add into T6 (q is 0 exactly when no
//!      borrow can arise), and one `adc` into T7;
//!   4. T /= 2^64: no instruction, the register names rotate by one (the
//!      generator below does it at comptime); the old T0 register (written
//!      with a discarded product half) becomes the next round's T7, zeroed
//!      by the row's `xor`.
//! (For n = 2^384 − c with c < 2^190: q·c is three `mulx`, w = (q·c) >> 64 the
//! three words subtracted from T1..T3, the rest of the round the same.)
//! Then one addition of 2^384 − m whose carry out of T6 is the "take it" flag
//! of six `cmov`s, so the result is canonical, the same value
//! `mont.Mont(p).mul` returns (pinned by the differential test in `field.zig`).
//! The round structure follows the shape of s2n-bignum's `bignum_montmul_p384`
//! (Apache-2.0 OR ISC OR MIT-0), which was read for it; the code is ours.
//!
//! ## Constant time
//!
//! Straight-line code, no branch, no secret-dependent address: every load is
//! a fixed offset off the two pointers. `CMOVcc` is in Intel's
//! data-independent-timing set together with `MULX`, `ADCX/ADOX/ADC/SBB`,
//! `ADD/SUB`, `SHL/XOR/MOV`; the selector is the carry of a fixed computation.
//!
//! ## Interface
//!
//! `mul(kind, a, b)` and `sq(kind, a)` read the limb arrays through `%rsi` /
//! `%rcx` and return the result in registers (no store, no load of the result).
//! Inputs must be canonical (< m): the reduction bounds below assume it.

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target has `MULX` (BMI2), `ADCX/ADOX` (ADX) and
/// AVX (the square parks four words in xmm registers with `vmovq`).
/// Elsewhere `field.zig` stays on the portable product.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx);

/// The two moduli the cores serve.
pub const Kind = enum { p, n };

const n_int: u384 = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;

/// K = 2^384 − modulus, as three words (the rest are zero): p is reduced by
/// shifts and two `mulx`, n by three `mulx` (K < 2^190).
fn kWords(comptime kind: Kind) [3]u64 {
    return switch (kind) {
        .p => .{ 0xffffffff00000001, 0xffffffff, 1 },
        .n => blk: {
            const k: u768 = (@as(u768, 1) << 384) - n_int;
            break :blk .{ @truncate(k), @truncate(k >> 64), @truncate(k >> 128) };
        },
    };
}

/// −n⁻¹ mod 2^64 (Newton iteration on the low word, as `mont.zig`).
const n_m0: u64 = blk: {
    const n0: u64 = @truncate(n_int);
    var inv: u64 = 1;
    for (0..7) |_| inv = inv *% (2 -% n0 *% inv);
    break :blk 0 -% inv;
};

const acc = [8][]const u8{ "%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13", "%%r14", "%%r15" };
const acc32 = [8][]const u8{ "%%r8d", "%%r9d", "%%r10d", "%%r11d", "%%r12d", "%%r13d", "%%r14d", "%%r15d" };

/// The accumulator word k during round i (after i rotations).
fn T(comptime i: usize, comptime k: usize) []const u8 {
    return acc[(i + k) % 8];
}

fn line(comptime fmt: []const u8, args: anytype) []const u8 {
    return std.fmt.comptimePrint(fmt ++ "\n", args);
}

/// The part of a reduction round that depends on the modulus: q (into rdx)
/// from the register `t0`, and the three words w0, w1, w2 (rax, rbx, rdi) of
/// (q·K) >> 64 that the round subtracts from T1, T2, T3. `t0` ends up junk.
/// For p, K = (2^64 + 2^32 − 1)·2^64 + (2^64 − 2^32 + 1) and the low word of
/// q·K is t0 itself (q = t0·(2^32 + 1)); for n, K = c0 + c1·2^64 + c2·2^128
/// and the low word of q·c0 is t0 (q = t0·(−n⁻¹)).
fn prelude(comptime kind: Kind, comptime t0: []const u8) []const u8 {
    comptime var s: []const u8 = "";
    switch (kind) {
        .p => {
            s = s ++ line("movq {s}, %%rdx", .{t0});
            s = s ++ line("shlq $32, %%rdx", .{});
            s = s ++ line("addq {s}, %%rdx", .{t0});
            s = s ++ line("xorl %%edi, %%edi", .{}); // CF = 0
            s = s ++ line("movabsq $0xffffffff00000001, %%rax", .{});
            s = s ++ line("mulxq %%rax, %%rbx, %%rax", .{}); // rax = hi(q · (2^64 − 2^32 + 1))
            s = s ++ line("movl $0xffffffff, %%ebx", .{});
            s = s ++ line("mulxq %%rbx, {s}, %%rbx", .{t0}); // t0 = lo(q·(2^32−1)), rbx = hi
            s = s ++ line("adcq {s}, %%rax", .{t0});
            s = s ++ line("adcq %%rdx, %%rbx", .{});
            s = s ++ line("adcl %%edi, %%edi", .{});
        },
        .n => {
            const k = kWords(.n);
            s = s ++ line("movabsq $0x{x}, %%rdx", .{n_m0});
            s = s ++ line("imulq {s}, %%rdx", .{t0}); // q
            s = s ++ line("movabsq $0x{x}, %%rax", .{k[0]});
            s = s ++ line("mulxq %%rax, {s}, %%rax", .{t0}); // rax = h0 (the low word cancels t0)
            s = s ++ line("movabsq $0x{x}, %%rbx", .{k[1]});
            s = s ++ line("mulxq %%rbx, %%rdi, %%rbx", .{}); // rdi = l1, rbx = h1
            s = s ++ line("addq %%rdi, %%rax", .{}); // w0 = h0 + l1
            s = s ++ line("movabsq $0x{x}, %%rdi", .{k[2]});
            s = s ++ line("mulxq %%rdi, {s}, %%rdi", .{t0}); // t0 = l2, rdi = h2
            s = s ++ line("adcq {s}, %%rbx", .{t0}); // w1 = h1 + l2 + carry
            s = s ++ line("adcq $0, %%rdi", .{}); // w2 = h2 + carry
        },
    }
    return s;
}

/// A reduction round of the CIOS product: T += q·m with T0 dropped (module
/// doc, step 3). Clobbers rax, rbx, rdi; T0's register ends up junk.
fn reduceRound(comptime kind: Kind, comptime i: usize) []const u8 {
    comptime var s: []const u8 = prelude(kind, T(i, 0));
    s = s ++ line("subq %%rax, {s}", .{T(i, 1)});
    s = s ++ line("sbbq %%rbx, {s}", .{T(i, 2)});
    s = s ++ line("sbbq %%rdi, {s}", .{T(i, 3)});
    s = s ++ line("sbbq $0, {s}", .{T(i, 4)});
    s = s ++ line("sbbq $0, {s}", .{T(i, 5)});
    s = s ++ line("sbbq $0, %%rdx", .{});
    s = s ++ line("addq %%rdx, {s}", .{T(i, 6)});
    s = s ++ line("adcq $0, {s}", .{T(i, 7)});
    return s;
}

/// Round 0's row: T = a · b_0 with nothing to accumulate (rdx = b_0).
fn firstRow() []const u8 {
    comptime var s: []const u8 = "";
    s = s ++ line("movq (%%rcx), %%rdx", .{});
    s = s ++ line("xorl {s}, {s}", .{ acc32[7], acc32[7] }); // T7 = 0
    s = s ++ line("mulxq (%%rsi), {s}, {s}", .{ T(0, 0), T(0, 1) });
    inline for (1..6) |j| {
        s = s ++ line("mulxq {d}(%%rsi), %%rax, {s}", .{ 8 * j, T(0, j + 1) });
        s = s ++ line("{s} %%rax, {s}", .{ if (j == 1) "addq" else "adcq", T(0, j) });
    }
    s = s ++ line("adcq $0, {s}", .{T(0, 6)});
    return s;
}

/// Round i ≥ 1's row: T += a · b_i, T7 (zero on entry to the `adox`) closed.
fn row(comptime i: usize) []const u8 {
    comptime var s: []const u8 = "";
    s = s ++ line("movq {d}(%%rcx), %%rdx", .{8 * i});
    s = s ++ line("xorl {s}, {s}", .{ acc32[(i + 7) % 8], acc32[(i + 7) % 8] }); // T7 = 0, CF = OF = 0
    inline for (0..5) |j| {
        s = s ++ line("mulxq {d}(%%rsi), %%rax, %%rbx", .{8 * j});
        s = s ++ line("adcxq %%rax, {s}", .{T(i, j)});
        s = s ++ line("adoxq %%rbx, {s}", .{T(i, j + 1)});
    }
    s = s ++ line("adoxq {s}, {s}", .{ T(i, 7), T(i, 6) }); // flush OF into T6
    s = s ++ line("mulxq 40(%%rsi), %%rax, %%rbx", .{});
    s = s ++ line("adcq %%rax, {s}", .{T(i, 5)});
    s = s ++ line("adcq %%rbx, {s}", .{T(i, 6)});
    s = s ++ line("adcq {s}, {s}", .{ T(i, 7), T(i, 7) }); // T7 = CF
    return s;
}

fn montMulAsm(comptime kind: Kind) []const u8 {
    @setEvalBranchQuota(2_000_000);
    comptime var s: []const u8 = firstRow() ++ reduceRound(kind, 0);
    inline for (1..6) |i| s = s ++ row(i) ++ reduceRound(kind, i);
    // After six rounds T0..T5 live at T(6, 0..5) = r14, r15, r8, r9, r10, r11 and
    // T(6, 6) = r12 is 0 or 1.
    s = s ++ finalSub(
        .{ T(6, 0), T(6, 1), T(6, 2), T(6, 3), T(6, 4), T(6, 5) },
        T(6, 6),
        .{ "%%rax", "%%rbx", "%%rcx", "%%rdx", "%%rdi", "%%rsi" },
        kind,
    );
    return s;
}

/// 32-bit name of a 64-bit register name from the tables in this file.
fn r32(comptime r: []const u8) []const u8 {
    const n = r[2..]; // without the doubled %
    if (n[1] >= '0' and n[1] <= '9') return r ++ "d"; // r8 .. r15 -> r8d
    return "%%e" ++ n[1..]; // rax -> eax
}

/// The last step, the same for both products: the value R (six words in the
/// registers `R`, a seventh word `top` that is 0 or 1) is below 2m; add
/// K = 2^384 − m, whose carry out is 1 iff R ≥ m, and `cmov` the sums into `R`
/// then. `tmp` are six scratch registers, none of them in `R` or `top`.
fn finalSub(comptime R: [6][]const u8, comptime top: []const u8, comptime tmp: [6][]const u8, comptime kind: Kind) []const u8 {
    comptime var s: []const u8 = "";
    for (3..6) |j| s = s ++ line("xorl {s}, {s}", .{ r32(tmp[j]), r32(tmp[j]) });
    const k = kWords(kind);
    inline for (0..3) |j| {
        s = s ++ line("movabsq $0x{x}, {s}", .{ k[j], tmp[j] });
        s = s ++ line("{s} {s}, {s}", .{ if (j == 0) "addq" else "adcq", R[j], tmp[j] });
    }
    for (3..6) |j| s = s ++ line("adcq {s}, {s}", .{ R[j], tmp[j] });
    s = s ++ line("adcq $0, {s}", .{top});
    for (0..6) |j| s = s ++ line("cmovneq {s}, {s}", .{ tmp[j], R[j] });
    return s;
}

/// The square's product phase: ends with P0..P7 in r8..r15, P8 in rcx, P9 in
/// rsi, P10 and P11 in xmm0 and xmm1.
///
/// Off-diagonal products a_i·a_j (i < j) once, S = Σ S_k 2^(64k) in S1..S10
/// (r9..r15, rcx, rdi, rbx; r8 = 0 is the zero operand of the carry closes),
/// row by row with the two carry chains; then P = 2·S + Σ a_i² 2^(128 i) in
/// one pass (CF doubles, OF adds the diagonal).
const sq_product: []const u8 = blk: {
    @setEvalBranchQuota(2_000_000);
    const S = [11][]const u8{ "", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13", "%%r14", "%%r15", "%%rcx", "%%rdi", "%%rbx" };
    var s: []const u8 = "";
    s = s ++ line("xorl %%r15d, %%r15d", .{});
    s = s ++ line("xorl %%ecx, %%ecx", .{});
    s = s ++ line("xorl %%edi, %%edi", .{});
    // Row 0: a_0 · a_1..a_5, nothing to accumulate yet.
    s = s ++ line("movq (%%rsi), %%rdx", .{});
    s = s ++ line("mulxq 8(%%rsi), {s}, {s}", .{ S[1], S[2] });
    for (2..6) |j| {
        s = s ++ line("mulxq {d}(%%rsi), %%rax, {s}", .{ 8 * j, S[j + 1] });
        s = s ++ line("{s} %%rax, {s}", .{ if (j == 2) "addq" else "adcq", S[j] });
    }
    s = s ++ line("adcq $0, {s}", .{S[6]});
    // Rows 1..3: a_i · a_(i+1)..a_5, lows into S(2i+1).., highs one above.
    for (1..4) |i| {
        s = s ++ line("movq {d}(%%rsi), %%rdx", .{8 * i});
        s = s ++ line("xorl %%r8d, %%r8d", .{}); // r8 = 0, CF = OF = 0
        for (i + 1..6) |j| {
            s = s ++ line("mulxq {d}(%%rsi), %%rax, %%rbx", .{8 * j});
            s = s ++ line("adcxq %%rax, {s}", .{S[i + j]});
            s = s ++ line("adoxq %%rbx, {s}", .{S[i + j + 1]});
        }
        s = s ++ line("adcxq %%r8, {s}", .{S[i + 6]}); // the top word is fresh: only CF is left
    }
    // Row 4: a_4 · a_5.
    s = s ++ line("movq 32(%%rsi), %%rdx", .{});
    s = s ++ line("mulxq 40(%%rsi), %%rax, %%rbx", .{});
    s = s ++ line("addq %%rax, %%rdi", .{});
    s = s ++ line("adcq $0, %%rbx", .{});
    // 2·S + diagonal.
    s = s ++ line("xorl %%eax, %%eax", .{});
    s = s ++ line("movq (%%rsi), %%rdx", .{});
    s = s ++ line("mulxq %%rdx, %%r8, %%rax", .{}); // P0 = lo(a_0²)
    s = s ++ line("adcxq {s}, {s}", .{ S[1], S[1] });
    s = s ++ line("adoxq %%rax, {s}", .{S[1]});
    for (1..5) |i| {
        s = s ++ line("movq {d}(%%rsi), %%rdx", .{8 * i});
        s = s ++ line("mulxq %%rdx, %%rax, %%rdx", .{});
        s = s ++ line("adcxq {s}, {s}", .{ S[2 * i], S[2 * i] });
        s = s ++ line("adoxq %%rax, {s}", .{S[2 * i]});
        s = s ++ line("adcxq {s}, {s}", .{ S[2 * i + 1], S[2 * i + 1] });
        s = s ++ line("adoxq %%rdx, {s}", .{S[2 * i + 1]});
    }
    s = s ++ line("movq 40(%%rsi), %%rdx", .{});
    s = s ++ line("mulxq %%rdx, %%rax, %%rdx", .{});
    s = s ++ line("adcxq %%rbx, %%rbx", .{});
    s = s ++ line("adoxq %%rax, %%rbx", .{});
    s = s ++ line("movl $0, %%eax", .{});
    s = s ++ line("adcxq %%rax, %%rdx", .{});
    s = s ++ line("adoxq %%rax, %%rdx", .{}); // P11
    s = s ++ line("movq %%rdi, %%rsi", .{}); // P9 (the pointer is dead)
    s = s ++ line("vmovq %%rbx, %%xmm0", .{}); // P10
    s = s ++ line("vmovq %%rdx, %%xmm1", .{}); // P11
    break :blk s;
};

/// Registers of the square's product words P0..P9 (P10, P11 wait in xmm0,
/// xmm1 until the last round and the last addition).
const P = [10][]const u8{ "%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13", "%%r14", "%%r15", "%%rcx", "%%rsi" };

/// One reduction round of the square. All twelve product words stay where they
/// are (the window of `reduceRound` would carry out of its top word into one
/// that is not in a register): round i changes P(i+1)..P(i+5) only, and the
/// word q_i − borrow that `reduceRound` adds into P(i+6) is parked in P(i)'s
/// register (free: q_i has been taken from it) for one addition at the end.
fn sqRound(comptime kind: Kind, comptime i: usize) []const u8 {
    comptime var s: []const u8 = prelude(kind, P[i]);
    s = s ++ line("subq %%rax, {s}", .{P[i + 1]});
    s = s ++ line("sbbq %%rbx, {s}", .{P[i + 2]});
    s = s ++ line("sbbq %%rdi, {s}", .{P[i + 3]});
    s = s ++ line("sbbq $0, {s}", .{P[i + 4]});
    if (i < 5) {
        s = s ++ line("sbbq $0, {s}", .{P[i + 5]});
    } else {
        // P10 comes out of xmm0 into the register rbx just freed (vmovq keeps the flags).
        s = s ++ line("vmovq %%xmm0, %%rbx", .{});
        s = s ++ line("sbbq $0, %%rbx", .{});
    }
    s = s ++ line("movq %%rdx, {s}", .{P[i]});
    s = s ++ line("sbbq $0, {s}", .{P[i]});
    return s;
}

/// After the rounds: R_k = P(6+k) + d_k (d_k in P(k)'s register), P10 in rbx,
/// P11 from xmm1 into rax; the carry out is the seventh word, in rdi.
fn sqTail(comptime kind: Kind) []const u8 {
    return line("movl $0, %%edi", .{}) ++
        line("addq {s}, {s}", .{ P[0], P[6] }) ++
        line("adcq {s}, {s}", .{ P[1], P[7] }) ++
        line("adcq {s}, {s}", .{ P[2], P[8] }) ++
        line("adcq {s}, {s}", .{ P[3], P[9] }) ++
        line("adcq {s}, %%rbx", .{P[4]}) ++
        line("vmovq %%xmm1, %%rax", .{}) ++
        line("adcq {s}, %%rax", .{P[5]}) ++
        line("adcl %%edi, %%edi", .{}) ++
        finalSub(
            .{ "%%r14", "%%r15", "%%rcx", "%%rsi", "%%rbx", "%%rax" },
            "%%rdi",
            .{ "%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13" },
            kind,
        );
}

fn montSqAsm(comptime kind: Kind) []const u8 {
    @setEvalBranchQuota(2_000_000);
    comptime var s: []const u8 = sq_product;
    inline for (0..6) |i| s = s ++ sqRound(kind, i);
    return s ++ sqTail(kind);
}

/// `a² · 2^−384 mod m`, `a` canonical, result canonical.
pub inline fn sq(comptime kind: Kind, a: *const [6]u64) [6]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var r4: u64 = undefined;
    var r5: u64 = undefined;
    asm volatile (montSqAsm(kind)
        : [r0] "={r14}" (r0),
          [r1] "={r15}" (r1),
          [r2] "={rcx}" (r2),
          [r3] "={rsi}" (r3),
          [r4] "={rbx}" (r4),
          [r5] "={rax}" (r5),
        : [ap] "{rsi}" (a),
        : .{ .rdx = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .xmm0 = true, .xmm1 = true, .cc = true, .memory = true });
    return .{ r0, r1, r2, r3, r4, r5 };
}

/// `a · b · 2^−384 mod m`, both canonical (< m), result canonical. The
/// operands are read through `%rsi` / `%rcx`; the product comes back in
/// registers.
pub inline fn mul(comptime kind: Kind, a: *const [6]u64, b: *const [6]u64) [6]u64 {
    if (comptime !supported) unreachable;
    var r0: u64 = undefined;
    var r1: u64 = undefined;
    var r2: u64 = undefined;
    var r3: u64 = undefined;
    var r4: u64 = undefined;
    var r5: u64 = undefined;
    var ap = a;
    var bp = b;
    asm volatile (montMulAsm(kind)
        : [r0] "={r14}" (r0),
          [r1] "={r15}" (r1),
          [r2] "={r8}" (r2),
          [r3] "={r9}" (r3),
          [r4] "={r10}" (r4),
          [r5] "={r11}" (r5),
          [ap] "+{rsi}" (ap),
          [bp] "+{rcx}" (bp),
        :
        : .{ .rax = true, .rbx = true, .rdx = true, .rdi = true, .r12 = true, .r13 = true, .cc = true, .memory = true });
    return .{ r0, r1, r2, r3, r4, r5 };
}
