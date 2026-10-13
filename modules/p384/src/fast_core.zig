// SPDX-License-Identifier: MIT

//! The amd64 field multiply: a Montgomery product mod p over six limbs with
//! `MULX` and the two independent carry chains of `ADCX` (CF) / `ADOX` (OF).
//!
//! The portable `mont.zig` product is correct but serial: LLVM lowers every
//! `u128` multiply-accumulate to `mulx` plus two `add`/`adc` pairs on one
//! carry chain, 550 instructions per multiply (2026-10-13, 70 ns). Here each
//! partial product's low half goes down the CF chain and its high half down
//! the OF chain, interleaved.
//!
//! ## Algorithm — CIOS (word-by-word Montgomery), six rounds
//!
//! Accumulator T in eight registers T0..T7 (T < 2p after every round, but
//! T + a·b_i + q·p reaches 2^449, so one word above the six). Round i:
//!   1. T += a · b_i — six `mulx`, lows into T0..T5 (CF), highs into
//!      T1..T6 (OF), both chains closed into T6/T7 with a zero register;
//!   2. q = T0 · (2^32 + 1) mod 2^64 (−p⁻¹ mod 2^64), by shift and add;
//!   3. T += q · p — the same six-`mulx` pattern over p's limbs; T0 becomes 0;
//!   4. T /= 2^64 — no instruction: the register names rotate by one (the
//!      generator below does it at comptime), and the zeroed T0 register
//!      becomes the next round's T7, which step 1 requires to be zero.
//! Then one subtraction of p (`SUB/SBB`) whose final borrow out of T6 is the
//! keep mask, and an XOR-blend selects T or T − p. Result canonical, the
//! same value `mont.Mont(p).mul` returns (pinned by the differential test in
//! `field.zig`).
//!
//! ## Constant time
//!
//! Straight-line code, no branch, no `CMOV`, no secret-dependent address:
//! every load is a fixed offset off the two pointers. All instructions used
//! (`MULX`, `ADCX/ADOX/ADD/SUB/SBB`, `SHL/XOR/AND/MOV`) are in the
//! data-independent-timing set.
//!
//! ## Interface
//!
//! `buf[0..6]` holds a, `buf[6..12]` p (copied in by the caller, so p needs
//! no register of its own: fifteen registers are all taken); the result
//! overwrites `buf[0..6]`. AT&T syntax with size suffixes; no `movabsq`
//! (p256's rule for the self-hosted assembler).

const std = @import("std");
const builtin = @import("builtin");

/// True at comptime iff this target has `MULX` (BMI2) and `ADCX/ADOX` (ADX).
/// Elsewhere `field.zig` stays on the portable product.
pub const supported = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .adx) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);

const acc = [8][]const u8{ "%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13", "%%r14", "%%r15" };

/// The accumulator word k during round i (after i rotations).
fn T(comptime i: usize, comptime k: usize) []const u8 {
    return acc[(i + k) % 8];
}

fn line(comptime fmt: []const u8, args: anytype) []const u8 {
    return std.fmt.comptimePrint(fmt ++ "\n", args);
}

/// One multiply-accumulate row: T(i, ·) += rdx · src[0..6], where src[j]
/// is at byte offset `base + 8j` off `%rsi` (a) or `%rbx`-free memory.
fn row(comptime i: usize, comptime base: usize) []const u8 {
    comptime var s: []const u8 = line("xorl %%eax, %%eax", .{}); // CF = OF = 0
    inline for (0..6) |j| {
        s = s ++ line("mulxq {d}(%%rsi), %%rax, %%rcx", .{base + 8 * j});
        s = s ++ line("adcxq %%rax, {s}", .{T(i, j)});
        s = s ++ line("adoxq %%rcx, {s}", .{T(i, j + 1)});
    }
    // Close both chains: CF into T6 then T7, OF into T7.
    s = s ++ line("adcxq %%rdi, {s}", .{T(i, 6)});
    s = s ++ line("adoxq %%rdi, {s}", .{T(i, 7)});
    s = s ++ line("adcxq %%rdi, {s}", .{T(i, 7)});
    return s;
}

const mont_mul_asm: []const u8 = blk: {
    @setEvalBranchQuota(100_000);
    var s: []const u8 = line("xorl %%edi, %%edi", .{}); // the zero register
    for (acc) |r| s = s ++ line("movq %%rdi, {s}", .{r});
    for (0..6) |i| {
        s = s ++ line("movq {d}(%%rbx), %%rdx", .{8 * i});
        s = s ++ row(i, 0);
        // q = T0 · (2^32 + 1) mod 2^64.
        s = s ++ line("movq {s}, %%rdx", .{T(i, 0)});
        s = s ++ line("shlq $32, %%rdx", .{});
        s = s ++ line("addq {s}, %%rdx", .{T(i, 0)});
        s = s ++ row(i, 48);
    }
    // After six rotations T0..T6 live at T(6, 0..6); T(6, 7) is zero.
    // diff = T − p into rax, rcx, rdx, rdi, rbx, and the spare register.
    const tmp = [6][]const u8{ "%%rax", "%%rcx", "%%rdx", "%%rdi", "%%rbx", T(6, 7) };
    for (0..6) |j| {
        s = s ++ line("movq {s}, {s}", .{ T(6, j), tmp[j] });
        s = s ++ line("{s} {d}(%%rsi), {s}", .{ if (j == 0) "subq" else "sbbq", 48 + 8 * j, tmp[j] });
    }
    // T6 − borrow: all ones iff T < p (keep T), else 0 (take T − p).
    s = s ++ line("sbbq $0, {s}", .{T(6, 6)});
    for (0..6) |j| {
        s = s ++ line("xorq {s}, {s}", .{ tmp[j], T(6, j) });
        s = s ++ line("andq {s}, {s}", .{ T(6, 6), T(6, j) });
        s = s ++ line("xorq {s}, {s}", .{ tmp[j], T(6, j) });
        s = s ++ line("movq {s}, {d}(%%rsi)", .{ T(6, j), 8 * j });
    }
    break :blk s;
};

/// `buf[0..6] = buf[0..6] · b · 2^−384 mod p`, with `buf[6..12] = p`; every
/// input canonical (< p). See the module doc.
pub inline fn montMul(buf: *[12]u64, b: *const [6]u64) void {
    if (comptime !supported) unreachable;
    var d0: u64 = undefined;
    var d1: u64 = undefined;
    var d2: u64 = undefined;
    var d3: u64 = undefined;
    var d4: u64 = undefined;
    var d5: u64 = undefined;
    asm volatile (mont_mul_asm
        : [d0] "={rax}" (d0),
          [d1] "={rcx}" (d1),
          [d2] "={rdx}" (d2),
          [d3] "={rdi}" (d3),
          [d4] "={rbx}" (d4),
          [d5] "={rsi}" (d5),
        : [ap] "{rsi}" (buf),
          [bp] "{rbx}" (b),
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}
