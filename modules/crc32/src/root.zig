// SPDX-License-Identifier: MIT

//! crc32 — CRC-32 (IEEE 802.3, gzip, zlib, PNG), in hardware where the CPU
//! has it.
//!
//! The checksum of gzip (RFC 1952), zlib's `crc32()`, PNG chunks, Ethernet
//! frames and ZIP entries: reflected, polynomial 0x04C11DB7 (0xEDB88320
//! reflected), initial value and final XOR 0xFFFFFFFF;
//! `hash("123456789") == 0xCBF43926`.
//!
//! std has it as `std.hash.Crc32`, one table lookup per byte — about
//! 0.4 GB/s. This module picks, once, the fastest of:
//!
//! - **x86-64 PCLMULQDQ folding**: four 128-bit lanes folded forward by 512
//!   bits per 64 bytes, then into one lane, then reduced to 32 bits (the
//!   construction of Intel's "Fast CRC Computation for Generic Polynomials
//!   Using PCLMULQDQ Instruction", 2009, reflected variant);
//! - **ARMv8** `crc32x`, three streams interleaved over 8 KiB and 256-byte
//!   blocks and joined by precomputed shift tables (the same construction as
//!   the sibling `crc32c`);
//! - **slicing-by-8** tables, eight bytes per step, anywhere else and for
//!   inputs too short for the folding kernel to pay off.
//!
//! The choice is made at run time — CPUID on x86-64, `AT_HWCAP` on Linux
//! arm64 — unless the build's target already guarantees the instruction, so
//! a binary built for baseline x86-64 still folds with PCLMULQDQ where it runs
//! on a CPU that has it. Zig 0.16 has no per-function target features, so the
//! instructions are emitted by inline assembly, which does not need them.
//!
//! Every backend returns the same value for the same bytes; the tests hold
//! each available one to std's implementation over every length up to past
//! the largest block, at every alignment.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .doc = "CRC-32 (IEEE: gzip/zlib/PNG) — x86-64 PCLMULQDQ folding and ARMv8 CRC instructions picked at run time, slicing-by-8 fallback; drop-in for std.hash.Crc32, streaming, extend, combine.",
    .platform_note = "any (x86-64 PCLMULQDQ / arm64 CRC asm + portable fallback)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "zlib crc32 (crc32_combine, braid/SIMD folding) / Linux crc32-pclmul; Intel PCLMULQDQ CRC white paper",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

/// The CRC-32 of `bytes`.
pub fn hash(bytes: []const u8) u32 {
    return extend(0, bytes);
}

/// The CRC-32 of `prefix ++ bytes`, given `crc == hash(prefix)`. `extend(0,
/// b)` is `hash(b)`, so a checksum can be built up piece by piece (zlib's
/// `crc32(crc, buf, len)`).
pub fn extend(crc: u32, bytes: []const u8) u32 {
    return ~raw(backend(), ~crc, bytes);
}

/// The CRC-32 of `a ++ b` from `hash(a)`, `hash(b)` and `b.len`, without the
/// bytes (zlib's `crc32_combine`). Logarithmic in `len_b`.
pub fn combine(crc_a: u32, crc_b: u32, len_b: u64) u32 {
    return multModP(xPow8n(len_b), crc_a) ^ crc_b;
}

/// Streaming form, with the shape of `std.hash.Crc32`: `init`, `update`,
/// `final`, `hash`.
pub const Crc32 = struct {
    /// The CRC-32 of everything so far (conditioned, unlike std's register).
    crc: u32 = 0,

    pub fn init() Crc32 {
        return .{};
    }

    pub fn update(self: *Crc32, bytes: []const u8) void {
        self.crc = extend(self.crc, bytes);
    }

    pub fn final(self: Crc32) u32 {
        return self.crc;
    }

    pub fn hash(bytes: []const u8) u32 {
        return extend(0, bytes);
    }
};

pub const Backend = enum {
    /// Slicing-by-8 tables: any CPU.
    table,
    /// x86-64 PCLMULQDQ folding (short inputs still go through the table).
    pclmul,
    /// The ARMv8 CRC32 extension's `crc32x/w/h/b` instructions.
    armv8,
};

/// The backend `hash`, `extend` and `Crc32` use on this CPU.
pub fn backend() Backend {
    if (comptime staticBackend()) |b| return b;
    const cached = detected.load(.monotonic);
    if (cached != 0) return @enumFromInt(cached - 1);
    const b = detect();
    detected.store(@intFromEnum(b) + 1, .monotonic);
    return b;
}

/// Whether `b` runs on this CPU. `.table` always does.
pub fn available(b: Backend) bool {
    return switch (b) {
        .table => true,
        // `backend()` picks the hardware whenever the CPU has it, and caches
        // the detection (CPUID is slow, and a VM exit under a hypervisor).
        .pclmul => pclmul_emittable and backend() == .pclmul,
        .armv8 => builtin.cpu.arch == .aarch64 and backend() == .armv8,
    };
}

/// `hash` through one particular backend, or null when this CPU lacks it —
/// for tests and measurements that must compare the backends.
pub fn hashWith(b: Backend, bytes: []const u8) ?u32 {
    if (!available(b)) return null;
    return ~raw(b, 0xffff_ffff, bytes);
}

// ── dispatch ────────────────────────────────────────────────────────────────

/// 0 = not yet detected, else `@intFromEnum(Backend) + 1`. Detection is
/// idempotent, so two threads racing to fill it store the same value.
var detected: std.atomic.Value(u8) = .init(0);

/// `pclmulqdq` can be compiled at all. Zig 0.16's self-hosted x86_64 backend
/// (the Debug default) encodes only what the target CPU model has, so there
/// the run-time-dispatched path exists only when the target guarantees
/// PCLMULQDQ anyway; LLVM assembles it for any x86_64 target.
const pclmul_emittable = builtin.cpu.arch == .x86_64 and
    (builtin.zig_backend != .stage2_x86_64 or std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul));

/// The backend the build target guarantees, when it guarantees one.
fn staticBackend() ?Backend {
    const cpu = builtin.cpu;
    return switch (cpu.arch) {
        .x86_64 => if (std.Target.x86.featureSetHas(cpu.features, .pclmul)) .pclmul else if (pclmul_emittable) null else .table,
        .aarch64 => if (std.Target.aarch64.featureSetHas(cpu.features, .crc)) .armv8 else null,
        else => .table,
    };
}

fn detect() Backend {
    return switch (builtin.cpu.arch) {
        .x86_64 => if (pclmul_emittable and cpuidPclmul()) .pclmul else .table,
        .aarch64 => if (hwcapCrc32()) .armv8 else .table,
        else => .table,
    };
}

fn cpuidPclmul() bool {
    if (builtin.cpu.arch != .x86_64) return false;
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (@as(u32, 1)),
          [_] "{ecx}" (@as(u32, 0)),
    );
    return (ecx >> 1) & 1 == 1; // CPUID.01H:ECX.PCLMULQDQ[bit 1]
}

fn hwcapCrc32() bool {
    if (builtin.cpu.arch != .aarch64 or builtin.os.tag != .linux) return false;
    const hwcap_crc32: usize = 1 << 7; // arch/arm64/include/uapi/asm/hwcap.h
    return std.os.linux.getauxval(std.elf.AT_HWCAP) & hwcap_crc32 != 0;
}

/// The CRC register after `bytes`, from register value `reg` — no pre- or
/// post-inversion.
fn raw(b: Backend, reg: u32, bytes: []const u8) u32 {
    return switch (b) {
        .table => tableUpdate(reg, bytes),
        .pclmul => if (pclmul_emittable) pclmulUpdate(reg, bytes) else unreachable,
        .armv8 => if (builtin.cpu.arch == .aarch64) threeWay(reg, bytes) else unreachable,
    };
}

// ── the polynomial ──────────────────────────────────────────────────────────

/// 0x04C11DB7, bit-reflected.
const poly: u32 = 0xEDB8_8320;

/// a·b mod P, in the reflected representation (x⁰ is the top bit). The
/// shift-and-add multiply zlib's `crc32_combine` also uses.
fn multModP(a: u32, b: u32) u32 {
    var m: u32 = 1 << 31;
    var p: u32 = 0;
    var bb = b;
    while (true) {
        if (a & m != 0) {
            p ^= bb;
            if (a & (m - 1) == 0) break;
        }
        m >>= 1;
        bb = if (bb & 1 != 0) (bb >> 1) ^ poly else bb >> 1;
    }
    return p;
}

/// x^(2^k) mod P for k = 0 … 31. x^(2^32) ≡ x mod P for this polynomial
/// (tested below), so the table repeats with period 32 — zlib's `x2n_table`.
const x2n: [32]u32 = blk: {
    var t: [32]u32 = undefined;
    var p: u32 = 1 << 30; // x¹
    t[0] = p;
    for (1..32) |i| {
        p = multModP(p, p);
        t[i] = p;
    }
    break :blk t;
};

/// x^n mod P, reflected, by square-and-multiply over `x2n`; `k` is the
/// log2 of the unit (0 = bits, 3 = bytes).
fn xPowShifted(n: u64, k0: usize) u32 {
    @setEvalBranchQuota(100_000);
    var p: u32 = 1 << 31; // x⁰
    var k = k0;
    var rest = n;
    while (rest != 0) : (rest >>= 1) {
        if (rest & 1 != 0) p = multModP(x2n[k & 31], p);
        k += 1;
    }
    return p;
}

/// x^(8n) mod P: what appending `n` zero bytes multiplies a register by.
fn xPow8n(n: u64) u32 {
    return xPowShifted(n, 3);
}

/// x^n mod P.
fn xPow(n: u64) u32 {
    return xPowShifted(n, 0);
}

// ── slicing-by-8 ────────────────────────────────────────────────────────────

/// `tables[k][i]`: the register after byte `i` followed by `k` zero bytes,
/// from register 0.
const tables: [8][256]u32 = blk: {
    @setEvalBranchQuota(20_000);
    var t: [8][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = i;
        for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ poly else c >> 1;
        t[0][i] = c;
    }
    for (1..8) |k| {
        for (0..256) |i| t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xff];
    }
    break :blk t;
};

fn tableUpdate(reg: u32, bytes: []const u8) u32 {
    var c = reg;
    var p = bytes;
    while (p.len >= 8) : (p = p[8..]) {
        const lo = std.mem.readInt(u32, p[0..4], .little) ^ c;
        const hi = std.mem.readInt(u32, p[4..8], .little);
        c = tables[7][lo & 0xff] ^ tables[6][(lo >> 8) & 0xff] ^
            tables[5][(lo >> 16) & 0xff] ^ tables[4][lo >> 24] ^
            tables[3][hi & 0xff] ^ tables[2][(hi >> 8) & 0xff] ^
            tables[1][(hi >> 16) & 0xff] ^ tables[0][hi >> 24];
    }
    for (p) |b| c = (c >> 8) ^ tables[0][(c ^ b) & 0xff];
    return c;
}

/// c·x^32 mod P: the register after four zero bytes, from register `c`.
fn zeros4(c: u32) u32 {
    return tables[3][c & 0xff] ^ tables[2][(c >> 8) & 0xff] ^
        tables[1][(c >> 16) & 0xff] ^ tables[0][c >> 24];
}

// ── x86-64: PCLMULQDQ folding ───────────────────────────────────────────────
//
// Conventions. A 16-byte block loaded little-endian into an xmm register has
// message bit j (bit j%8 of byte j/8, the order a reflected CRC consumes
// them) at register bit j, and that bit is the coefficient of x^(127−j) of
// the block read as a polynomial — first bit highest. So the low qword L
// holds x¹²⁷…x⁶⁴ and the high qword H holds x⁶³…x⁰:
//
//     block(x) = L~(x)·x⁶⁴ + H~(x),   V~(x) = Σ V_i·x^(63−i) for a qword V.
//
// `pclmulqdq` multiplies two qwords as integers over GF(2); read back in the
// same convention the 127-bit product is x·A~·B~ — reflection costs one
// factor of x, which every constant below absorbs by using exponent − 1.
//
// Folding a block X forward over D bits (X·x^D, congruent mod P):
//
//     X·x^D = L~·x^(64+D) + H~·x^D
//           ≡ x·L~·K1~ + x·H~·K2~      with K1~ ≡ x^(63+D), K2~ ≡ x^(D−1)
//
// A constant K with K~ ≡ x^e is stored as rev32(x^(e−31) mod P) << 1 — the
// 32-bit reflected remainder in bits 1…32, so that K~ = x³¹·(x^(e−31) mod P).
// The products then stay below degree 127 and fit a block. The low qword of
// the constant pair multiplies L (imm 0x00), the high qword H (imm 0x11).
//
// The message is folded into one block X standing for the whole input, whose
// register is X·x³² mod P. Two more multiplies bring it to 64 bits, with
// constants stored as rev32(x^e mod P) << 32 (K~ = x^e mod P exactly, degree
// ≤ 31, so each product lands in fewer bits):
//
//     W = x·L~·(x⁹⁵ mod P) + H~·x³²      degree ≤ 95, bits 32…127
//     V = x·Wlo~·(x⁶³ mod P) + Whi        degree ≤ 63, the high qword
//
// and V = V₁·x³² + V₀ gives the register as (V₁·x³² mod P) + V₀ — four table
// lookups (`zeros4`).

/// Below this many bytes the table is as fast as the folding kernel, whose
/// fixed cost is the final reduction (measured, see SPEC.md).
const pclmul_min = 32;

/// K with K~ ≡ x^e (fold constant form).
fn foldK(e: u64) u64 {
    return @as(u64, xPow(e - 31)) << 1;
}

/// K with K~ = x^e mod P (reduction constant form).
fn reduceK(e: u64) u64 {
    return @as(u64, xPow(e)) << 32;
}

/// Fold constants as consecutive 16-byte pairs: fold by 512 bits (four
/// lanes), by 128 bits (one lane), and the two reduction steps.
const fold_consts: [6]u64 align(16) = .{
    foldK(63 + 512), foldK(512 - 1),
    foldK(63 + 128), foldK(128 - 1),
    reduceK(95),     reduceK(63),
};

fn pclmulUpdate(reg: u32, bytes: []const u8) u32 {
    if (bytes.len < pclmul_min) return tableUpdate(reg, bytes);
    const V = @Vector(2, u64);
    const k512: V = fold_consts[0..2].*;
    const k128: V = fold_consts[2..4].*;
    const kred: V = fold_consts[4..6].*;
    var p = bytes;
    // The running register enters as an XOR into the first four bytes.
    var x0 = load(p[0..16]) ^ V{ reg, 0 };
    p = p[16..];
    if (p.len >= 48) {
        var x1 = load(p[0..16]);
        var x2 = load(p[16..32]);
        var x3 = load(p[32..48]);
        p = p[48..];
        while (p.len >= 64) : (p = p[64..]) {
            x0 = foldInto(x0, k512, load(p[0..16]));
            x1 = foldInto(x1, k512, load(p[16..32]));
            x2 = foldInto(x2, k512, load(p[32..48]));
            x3 = foldInto(x3, k512, load(p[48..64]));
        }
        x0 = foldInto(x0, k128, x1);
        x0 = foldInto(x0, k128, x2);
        x0 = foldInto(x0, k128, x3);
    }
    while (p.len >= 16) : (p = p[16..]) x0 = foldInto(x0, k128, load(p[0..16]));
    // 128 → 96 bits: W = x·L~·(x⁹⁵ mod P) + H~·x³² (H moved to bits 32…95).
    const h = x0[1];
    const w = X86.clmul(0x00, x0, kred) ^ V{ h << 32, h >> 32 };
    // 96 → 64 bits: V = x·Wlo~·(x⁶³ mod P) + Whi, the high qword.
    const v = X86.clmul(0x10, w, kred)[1] ^ w[1];
    const c = zeros4(@truncate(v)) ^ @as(u32, @truncate(v >> 32));
    return tableUpdate(c, p);
}

inline fn load(b: *const [16]u8) @Vector(2, u64) {
    return .{ std.mem.readInt(u64, b[0..8], .little), std.mem.readInt(u64, b[8..16], .little) };
}

/// x·x^D + next: `x` folded forward by the distance `k` was built for.
inline fn foldInto(x: @Vector(2, u64), k: @Vector(2, u64), next: @Vector(2, u64)) @Vector(2, u64) {
    return X86.clmul(0x00, x, k) ^ X86.clmul(0x11, x, k) ^ next;
}

const X86 = struct {
    /// One `pclmulqdq`: the qword of `a` picked by imm bit 0 times the qword
    /// of `k` picked by imm bit 4. Register operands only — the self-hosted
    /// x86 backend (Zig 0.16 Debug) cannot size an SSE memory operand, and
    /// the loads are Zig's anyway. Legacy SSE encoding (SSE2 + PCLMULQDQ),
    /// so it runs wherever the CPUID bit is set.
    inline fn clmul(comptime imm: u8, a: @Vector(2, u64), k: @Vector(2, u64)) @Vector(2, u64) {
        return asm (std.fmt.comptimePrint("pclmulqdq $0x{x:0>2}, %[k], %[a]", .{imm})
            : [a] "=x" (-> @Vector(2, u64)),
            : [_] "0" (a),
              [k] "x" (k),
        );
    }
};

// ── ARMv8: three interleaved `crc32x` streams ───────────────────────────────
//
// One `crc32x` takes 8 bytes but has a latency of about three cycles, so a
// single dependent chain leaves the unit two thirds idle. Three chains over
// three consecutive blocks A, B, C keep it busy; the registers are then
// joined by linearity: the register after A‖B from `r` is
// shift_|B|(reg(A, r)) ⊕ reg(B, 0), where shift_n multiplies by x^(8n) mod P.
// For the two fixed block sizes shift_n is a precomputed linear map, applied
// a byte at a time from four 256-entry tables. (Identical to `crc32c`'s
// construction but for the polynomial.)

const long_block = 8192;
const short_block = 256;

/// The linear map "append n zero bytes" as four byte tables.
fn shiftTables(comptime n: u64) [4][256]u32 {
    @setEvalBranchQuota(4_000_000);
    const m = xPow8n(n);
    var t: [4][256]u32 = undefined;
    for (0..4) |k| {
        for (0..256) |i| t[k][i] = multModP(m, @as(u32, @intCast(i)) << @intCast(8 * k));
    }
    return t;
}

const shift_long = shiftTables(long_block);
const shift_short = shiftTables(short_block);

fn shift(comptime t: *const [4][256]u32, c: u32) u32 {
    return t[0][c & 0xff] ^ t[1][(c >> 8) & 0xff] ^ t[2][(c >> 16) & 0xff] ^ t[3][c >> 24];
}

const Arm = struct {
    fn step8(c: u32, v: u64) u32 {
        return asm (
            \\.arch_extension crc
            \\crc32x %[c:w], %[c:w], %[v:x]
            : [c] "=r" (-> u32),
            : [v] "r" (v),
              [_] "0" (c),
        );
    }
    fn step4(c: u32, v: u32) u32 {
        return asm (
            \\.arch_extension crc
            \\crc32w %[c:w], %[c:w], %[v:w]
            : [c] "=r" (-> u32),
            : [v] "r" (v),
              [_] "0" (c),
        );
    }
    fn step2(c: u32, v: u32) u32 {
        return asm (
            \\.arch_extension crc
            \\crc32h %[c:w], %[c:w], %[v:w]
            : [c] "=r" (-> u32),
            : [v] "r" (v),
              [_] "0" (c),
        );
    }
    fn step1(c: u32, v: u32) u32 {
        return asm (
            \\.arch_extension crc
            \\crc32b %[c:w], %[c:w], %[v:w]
            : [c] "=r" (-> u32),
            : [v] "r" (v),
              [_] "0" (c),
        );
    }
};

fn threeWay(reg: u32, bytes: []const u8) u32 {
    var c = reg;
    var p = bytes;
    inline for (.{ .{ long_block, &shift_long }, .{ short_block, &shift_short } }) |blk| {
        const n = blk[0];
        while (p.len >= 3 * n) : (p = p[3 * n ..]) {
            var c0 = c;
            var c1: u32 = 0;
            var c2: u32 = 0;
            var i: usize = 0;
            while (i < n) : (i += 8) {
                c0 = Arm.step8(c0, std.mem.readInt(u64, p[i..][0..8], .little));
                c1 = Arm.step8(c1, std.mem.readInt(u64, p[n + i ..][0..8], .little));
                c2 = Arm.step8(c2, std.mem.readInt(u64, p[2 * n + i ..][0..8], .little));
            }
            c = shift(blk[1], c0) ^ c1;
            c = shift(blk[1], c) ^ c2;
        }
    }
    while (p.len >= 8) : (p = p[8..]) c = Arm.step8(c, std.mem.readInt(u64, p[0..8], .little));
    if (p.len >= 4) {
        c = Arm.step4(c, std.mem.readInt(u32, p[0..4], .little));
        p = p[4..];
    }
    if (p.len >= 2) {
        c = Arm.step2(c, std.mem.readInt(u16, p[0..2], .little));
        p = p[2..];
    }
    if (p.len >= 1) c = Arm.step1(c, p[0]);
    return c;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const all_backends = [_]Backend{ .table, .pclmul, .armv8 };

test "published vectors: the CRC catalogue check value and zlib's values" {
    // "123456789" is the check value of CRC-32/ISO-HDLC in the reveng CRC
    // catalogue; the rest were computed with CPython's `zlib.crc32` (zlib
    // 1.3), a foreign implementation.
    var zeros: [32]u8 = @splat(0);
    var ones: [32]u8 = @splat(0xff);
    var up: [32]u8 = undefined;
    var down: [32]u8 = undefined;
    for (0..32) |i| {
        up[i] = @intCast(i);
        down[i] = @intCast(31 - i);
    }
    const cases = [_]struct { []const u8, u32 }{
        .{ "123456789", 0xCBF4_3926 },
        .{ "a", 0xE8B7_BE43 },
        .{ "abc", 0x3524_41C2 },
        .{ "The quick brown fox jumps over the lazy dog", 0x414F_A339 },
        .{ &zeros, 0x190A_55AD },
        .{ &ones, 0xFF6C_AB0B },
        .{ &up, 0x9126_7E8A },
        .{ &down, 0x9AB0_EF72 },
        .{ "", 0 },
    };
    var ran: usize = 0;
    for (all_backends) |b| {
        for (cases) |c| {
            const got = hashWith(b, c[0]) orelse continue;
            try testing.expectEqual(c[1], got);
            ran += 1;
        }
    }
    try testing.expect(ran >= cases.len);
    for (cases) |c| {
        try testing.expectEqual(c[1], hash(c[0]));
        try testing.expectEqual(c[1], std.hash.Crc32.hash(c[0]));
    }
}

test "every backend agrees with std's implementation at every length and alignment" {
    // std's `Crc32` is an independent, bytewise implementation. Every length
    // up to past three short blocks (and so past every threshold of the
    // folding kernel: 16, 64, the 4-lane loop, the 1-lane tail) at all 64
    // alignments; then ±24 bytes around one and three long blocks and six
    // long blocks at a few alignments.
    const max = 3 * long_block * 2 + 3 * short_block + 64;
    const buf = try testing.allocator.alloc(u8, max + 64);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(0xc4c32);
    prng.random().bytes(buf);

    var lengths: std.ArrayList(usize) = .empty;
    defer lengths.deinit(testing.allocator);
    for (0..3 * short_block + 80) |n| try lengths.append(testing.allocator, n);
    for ([_]usize{ long_block, 3 * long_block, 2 * 3 * long_block }) |edge| {
        var n = edge - 24;
        while (n <= edge + 24) : (n += 1) try lengths.append(testing.allocator, n);
    }
    try lengths.append(testing.allocator, max);

    var hw_checked = false;
    for (all_backends) |b| {
        if (!available(b)) continue;
        if (b != .table) hw_checked = true;
        for (lengths.items) |n| {
            for (0..64) |off| {
                if (n > 1024 and off % 9 != 0) continue; // the long ones at a few offsets
                const data = buf[off..][0..n];
                const want = std.hash.Crc32.hash(data);
                try testing.expectEqual(want, hashWith(b, data).?);
            }
        }
    }
    // On the machines this suite runs on (x86-64 with PCLMULQDQ, arm64 with
    // CRC) a hardware path exists, and a suite that never took it proves
    // nothing about it — unless this build cannot contain one.
    if (pclmul_emittable or builtin.cpu.arch == .aarch64) try testing.expect(hw_checked);
}

test "backend picks the hardware when the CPU has it" {
    const b = backend();
    try testing.expect(available(b));
    switch (builtin.cpu.arch) {
        .x86_64 => try testing.expectEqual(if (pclmul_emittable and cpuidPclmul()) Backend.pclmul else Backend.table, b),
        .aarch64 => try testing.expectEqual(if (available(.armv8)) Backend.armv8 else Backend.table, b),
        else => try testing.expectEqual(Backend.table, b),
    }
    const foreign: Backend = if (builtin.cpu.arch == .x86_64) .armv8 else .pclmul;
    try testing.expect(!available(foreign));
    try testing.expectEqual(@as(?u32, null), hashWith(foreign, "x"));
}

test "the table backend is always available and gives the catalogue value" {
    // `hashWith` returns null for an unavailable backend and the other tests
    // skip those, so without this a `.table` that reported itself unavailable
    // would drop out of every comparison unnoticed.
    try testing.expect(available(.table));
    try testing.expectEqual(@as(?u32, 0xCBF4_3926), hashWith(.table, "123456789"));
}

test "run-time detection agrees with the kernel's CPU flags" {
    // `cpuidPclmul` / `hwcapCrc32` are what a baseline build dispatches on, and
    // the dispatch test above compares them with themselves. /proc/cpuinfo is
    // the kernel's own reading of the same bits.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const key: []const u8, const flag: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => .{ "flags", "pclmulqdq" },
        .aarch64 => .{ "Features", "crc32" },
        else => return error.SkipZigTest,
    };
    const text = std.Io.Dir.cwd().readFileAlloc(testing.io, "/proc/cpuinfo", testing.allocator, .limited(4 << 20)) catch return error.SkipZigTest;
    defer testing.allocator.free(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        var has = false;
        var toks = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t");
        while (toks.next()) |t| {
            if (std.mem.eql(u8, t, flag)) has = true;
        }
        const detected_now = if (builtin.cpu.arch == .x86_64) cpuidPclmul() else hwcapCrc32();
        try testing.expectEqual(has, detected_now);
        return;
    }
    return error.SkipZigTest;
}

test "extend and the streaming form build the checksum of a whole from its pieces" {
    var buf: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&buf);
    const whole = std.hash.Crc32.hash(&buf);
    var cuts: [40]usize = undefined;
    for (&cuts, 0..) |*c, i| c.* = if (i < 10)
        ([_]usize{ 0, 1, 7, 8, 9, 63, 64, 769, 2999, 3000 })[i]
    else
        prng.random().uintAtMost(usize, buf.len);
    for (cuts) |cut| {
        try testing.expectEqual(whole, extend(hash(buf[0..cut]), buf[cut..]));
        var s = Crc32.init();
        s.update(buf[0..cut]);
        s.update(buf[cut..]);
        try testing.expectEqual(whole, s.final());
        // And std's streaming form, split the same way, to the same value.
        var t = std.hash.Crc32.init();
        t.update(buf[0..cut]);
        t.update(buf[cut..]);
        try testing.expectEqual(whole, t.final());
    }
    // Many pieces of random sizes.
    for (0..20) |_| {
        var s = Crc32.init();
        var at: usize = 0;
        while (at < buf.len) {
            const n = @min(buf.len - at, prng.random().uintAtMost(usize, 200));
            s.update(buf[at..][0..n]);
            at += n;
        }
        try testing.expectEqual(whole, s.final());
    }
    try testing.expectEqual(whole, Crc32.hash(&buf));
}

test "combine joins two checksums without the bytes" {
    const buf = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(11);
    prng.random().bytes(buf);
    const whole = std.hash.Crc32.hash(buf);
    for ([_]usize{ 0, 1, 3, 8, 1000, 32_768, 69_999, 70_000 }) |cut| {
        const a = hash(buf[0..cut]);
        const b = hash(buf[cut..]);
        try testing.expectEqual(whole, combine(a, b, buf.len - cut));
    }
    // An empty right-hand side changes nothing, whatever its "checksum".
    try testing.expectEqual(hash("abc"), combine(hash("abc"), 0, 0));
}

test "combine over lengths past 2^32 bytes: x2n repeats with period 32" {
    // `xPowShifted` indexes `x2n` with k mod 32, which is right only if
    // x^(2^32) ≡ x mod P. Check it, and check a length past 2^32 bytes
    // against the same power built by squaring alone, with no table.
    try testing.expectEqual(x2n[0], multModP(x2n[31], x2n[31]));
    const n: u64 = (1 << 40) + 12345;
    var p: u32 = 1 << 31; // x⁰
    var sq: u32 = 1 << 30; // x^(2^k), k = 0, 1, …
    var bits: u64 = 8 * n;
    while (bits != 0) : (bits >>= 1) {
        if (bits & 1 != 0) p = multModP(sq, p);
        sq = multModP(sq, sq);
    }
    try testing.expectEqual(p, xPow8n(n));
}

/// x^e mod P, reflected, one multiplication by x at a time — an oracle for
/// the square-and-multiply `xPow` that shares nothing with it but `poly`.
fn xPowSlow(e: u64) u32 {
    var p: u32 = 1 << 31; // x⁰
    for (0..e) |_| p = if (p & 1 != 0) (p >> 1) ^ poly else p >> 1;
    return p;
}

test "the folding constants are the powers of x they claim to be" {
    // Recomputed one multiplication by x at a time, independently of the
    // square-and-multiply that built them. Whether the exponents are the
    // right ones is the differential tests' question.
    const exps = [_]u64{ 63 + 512, 512 - 1, 63 + 128, 128 - 1 };
    for (exps, 0..) |e, i| {
        try testing.expectEqual(@as(u64, xPowSlow(e - 31)) << 1, fold_consts[i]);
        try testing.expect(fold_consts[i] >> 33 == 0 and fold_consts[i] & 1 == 0);
    }
    try testing.expectEqual(@as(u64, xPowSlow(95)) << 32, fold_consts[4]);
    try testing.expectEqual(@as(u64, xPowSlow(63)) << 32, fold_consts[5]);
    for (0..64) |e| try testing.expectEqual(xPowSlow(e), xPow(e));
    try testing.expectEqual(xPowSlow(8 * 1000), xPow8n(1000));
}

test "fuzz: every backend, extend and combine agree with std on arbitrary bytes" {
    try testing.fuzz({}, fuzzAgree, .{});
}

/// Room for two rounds of three long blocks, so the fuzzer can reach every
/// path of the three-way split and of the folding kernel.
var fuzz_buf: [6 * long_block + 3 * short_block + 64]u8 = undefined;

fn fuzzAgree(_: void, smith: *std.testing.Smith) !void {
    const len = smith.slice(&fuzz_buf);
    const data = fuzz_buf[0..len];
    const want = std.hash.Crc32.hash(data);
    for (all_backends) |b| if (hashWith(b, data)) |got| try testing.expectEqual(want, got);
    const cut = smith.valueRangeAtMost(u32, 0, len);
    try testing.expectEqual(want, extend(hash(data[0..cut]), data[cut..]));
    try testing.expectEqual(want, combine(hash(data[0..cut]), hash(data[cut..]), len - cut));
}

test "the shift tables are the zero-byte operator they claim to be" {
    const zeros = [_]u8{0} ** long_block;
    var prng = std.Random.DefaultPrng.init(3);
    for (0..40) |i| {
        const r: u32 = if (i < 32) @as(u32, 1) << @intCast(i) else prng.random().int(u32);
        try testing.expectEqual(tableUpdate(r, &zeros), shift(&shift_long, r));
        try testing.expectEqual(tableUpdate(r, zeros[0..short_block]), shift(&shift_short, r));
        try testing.expectEqual(tableUpdate(r, zeros[0..4]), zeros4(r));
    }
}
