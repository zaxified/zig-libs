// SPDX-License-Identifier: MIT

//! CRC-64/XZ (ECMA-182, reflected), the `.xz` CRC64 check. On x86-64 with
//! PCLMULQDQ (detected at run time) the folding kernel of liblzma's
//! `check/crc_x86_clmul.h` (0BSD, see NOTICE): four lanes folded 512 bits at
//! a time, one lane 128 bits at a time, Barrett reduction to 64 bits. The
//! constants are liblzma's (`crc_clmul_consts_gen.c`). Below 16 bytes, for
//! the tail under 16 bytes and on other targets, slicing-by-8 tables.
//!
//! Private to lzma: std's `CRC-64/XZ` is table-driven one byte at a time
//! (~5 % of an lzma decode). A public CRC-64 next to the `crc32` module is
//! SPEC.md Backlog B7.

const std = @import("std");
const builtin = @import("builtin");

/// 0x42F0E1EBA9EA3693, bit-reflected.
const poly: u64 = 0xC96C_5795_D787_0F42;

pub const Crc64 = struct {
    /// The finished CRC of the bytes so far (0 for none).
    value: u64 = 0,

    pub fn init() Crc64 {
        return .{};
    }

    pub fn update(self: *Crc64, bytes: []const u8) void {
        self.value = extend(self.value, bytes);
    }

    pub fn final(self: Crc64) u64 {
        return self.value;
    }

    pub fn hash(bytes: []const u8) u64 {
        return extend(0, bytes);
    }
};

/// The CRC of `a ++ bytes` from the CRC `crc` of `a`.
pub fn extend(crc: u64, bytes: []const u8) u64 {
    var reg = ~crc;
    var p = bytes;
    if (p.len >= 16 and usePclmul()) {
        const n = p.len & ~@as(usize, 15);
        reg = pclmulRegister(reg, p[0..n]);
        p = p[n..];
    }
    return ~tableUpdate(reg, p);
}

// ── tables ──────────────────────────────────────────────────────────────────

/// `tables[k][i]`: the register after byte `i` followed by `k` zero bytes,
/// from register 0.
const tables: [8][256]u64 = blk: {
    @setEvalBranchQuota(40_000);
    var t: [8][256]u64 = undefined;
    for (0..256) |i| {
        var c: u64 = i;
        for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ poly else c >> 1;
        t[0][i] = c;
    }
    for (1..8) |k| {
        for (0..256) |i| t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xff];
    }
    break :blk t;
};

fn tableUpdate(reg: u64, bytes: []const u8) u64 {
    var c = reg;
    var p = bytes;
    while (p.len >= 8) : (p = p[8..]) {
        const x = std.mem.readInt(u64, p[0..8], .little) ^ c;
        c = tables[7][x & 0xff] ^ tables[6][(x >> 8) & 0xff] ^
            tables[5][(x >> 16) & 0xff] ^ tables[4][(x >> 24) & 0xff] ^
            tables[3][(x >> 32) & 0xff] ^ tables[2][(x >> 40) & 0xff] ^
            tables[1][(x >> 48) & 0xff] ^ tables[0][x >> 56];
    }
    for (p) |b| c = (c >> 8) ^ tables[0][(c ^ b) & 0xff];
    return c;
}

// ── x86-64: PCLMULQDQ ───────────────────────────────────────────────────────

/// LLVM assembles `pclmulqdq` for any x86_64 target; the self-hosted backend
/// only when the target model has it (as in the `crc32` module).
const pclmul_emittable = builtin.cpu.arch == .x86_64 and
    (builtin.zig_backend != .stage2_x86_64 or std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul));

/// 0 = not yet detected, 1 = no, 2 = yes. Detection is idempotent, so two
/// threads racing to fill it store the same value.
var detected: std.atomic.Value(u8) = .init(0);

inline fn usePclmul() bool {
    if (!pclmul_emittable) return false;
    if (comptime std.Target.x86.featureSetHas(builtin.cpu.features, .pclmul)) return true;
    var d = detected.load(.monotonic);
    if (d == 0) {
        d = if (cpuidPclmul()) 2 else 1;
        detected.store(d, .monotonic);
    }
    return d == 2;
}

fn cpuidPclmul() bool {
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

const V = @Vector(2, u64);

/// liblzma's constants as `_mm_set_epi64x(hi, lo)` pairs: `.{ lo, hi }`.
const fold512: V = .{ 0x6ae3efbb9dd441f3, 0x081f6054a7842df4 };
const fold128: V = .{ 0xe05dd497ca393ae4, 0xdabe95afc7875f40 };
const mu_p: V = .{ 0x92d8af2baf0e1e84, 0x9c3e466c172963d5 };

/// The register (no inversions) after `bytes`, a non-empty multiple of 16.
fn pclmulRegister(reg: u64, bytes: []const u8) u64 {
    if (!pclmul_emittable) unreachable;
    var p = bytes;
    var v0 = load(p[0..16]) ^ V{ reg, 0 };
    p = p[16..];
    if (p.len >= 48) {
        var v1 = load(p[0..16]);
        var v2 = load(p[16..32]);
        var v3 = load(p[32..48]);
        p = p[48..];
        while (p.len >= 64) : (p = p[64..]) {
            v0 = fold(v0, fold512) ^ load(p[0..16]);
            v1 = fold(v1, fold512) ^ load(p[16..32]);
            v2 = fold(v2, fold512) ^ load(p[32..48]);
            v3 = fold(v3, fold512) ^ load(p[48..64]);
        }
        v0 = v1 ^ fold(v0, fold128);
        v0 = v2 ^ fold(v0, fold128);
        v0 = v3 ^ fold(v0, fold128);
    }
    while (p.len >= 16) : (p = p[16..]) v0 = fold(v0, fold128) ^ load(p[0..16]);

    // 128 -> 64 bits, then Barrett reduction (liblzma's tail, verbatim).
    var v1: V = .{ v0[1], 0 };
    v0 = clmul(0x10, v0, fold128) ^ v1;
    v1 = clmul(0x10, v0, mu_p);
    const v2: V = .{ 0, v1[0] };
    v1 = clmul(0x00, v1, mu_p);
    v0 = v0 ^ v2 ^ v1;
    return v0[1];
}

inline fn load(b: *const [16]u8) V {
    return .{ std.mem.readInt(u64, b[0..8], .little), std.mem.readInt(u64, b[8..16], .little) };
}

inline fn fold(v: V, k: V) V {
    return clmul(0x00, v, k) ^ clmul(0x11, v, k);
}

/// One `pclmulqdq` = `_mm_clmulepi64_si128(a, k, imm)`: the qword of `a`
/// picked by imm bit 0 times the qword of `k` picked by imm bit 4.
inline fn clmul(comptime imm: u8, a: V, k: V) V {
    return asm (std.fmt.comptimePrint("pclmulqdq $0x{x:0>2}, %[k], %[a]", .{imm})
        : [a] "=x" (-> V),
        : [_] "0" (a),
          [k] "x" (k),
    );
}

test "crc64: equals std CRC-64/XZ at every length and split" {
    var buf: [600]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x64);
    prng.random().bytes(&buf);
    for (0..buf.len + 1) |n| {
        const want = std.hash.crc.@"CRC-64/XZ".hash(buf[0..n]);
        try std.testing.expectEqual(want, Crc64.hash(buf[0..n]));
        // Split at a few points: the streaming form must agree.
        for ([_]usize{ 0, 1, 15, 16, 17, 63, 64, 65 }) |k| {
            if (k > n) continue;
            var c = Crc64.init();
            c.update(buf[0..k]);
            c.update(buf[k..n]);
            try std.testing.expectEqual(want, c.final());
        }
    }
    // The check value of the catalogue entry.
    try std.testing.expectEqual(@as(u64, 0x995DC9BBDF1939FA), Crc64.hash("123456789"));
}

test "crc64: the table path alone equals the kernel" {
    if (!usePclmul()) return error.SkipZigTest;
    var buf: [4096 + 48]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x65);
    prng.random().bytes(&buf);
    var n: usize = 16;
    while (n <= buf.len) : (n += 16) {
        try std.testing.expectEqual(tableUpdate(~@as(u64, 0x1234), buf[0..n]), pclmulRegister(~@as(u64, 0x1234), buf[0..n]));
    }
}
