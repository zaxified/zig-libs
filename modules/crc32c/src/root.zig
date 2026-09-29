// SPDX-License-Identifier: MIT

//! crc32c — CRC-32C (Castagnoli), in hardware where the CPU has it.
//!
//! The checksum of iSCSI (RFC 3720), SCTP (RFC 9260), ext4 and Btrfs
//! metadata, LevelDB/RocksDB logs, Kafka record batches and Prometheus's WAL:
//! reflected, polynomial 0x1EDC6F41 (0x82F63B78 reflected), initial value and
//! final XOR 0xFFFFFFFF; `hash("123456789") == 0xE3069283`.
//!
//! std has it as `std.hash.crc.Crc32Iscsi`, one table lookup per byte —
//! about 0.4 GB/s. This module picks, once, the fastest of:
//!
//! - **x86-64 SSE4.2** `crc32` instruction, three streams interleaved over
//!   8 KiB and 256-byte blocks and joined by precomputed shift tables
//!   (the construction of Intel's "Fast CRC Computation for iSCSI Polynomial
//!   Using CRC32 Instruction", 2011);
//! - **ARMv8** `crc32cx`, the same three-stream construction;
//! - **slicing-by-8** tables, eight bytes per step, anywhere else.
//!
//! The choice is made at run time — CPUID on x86-64, `AT_HWCAP` on Linux
//! arm64 — unless the build's target already guarantees the instruction, so
//! a binary built for baseline x86-64 still uses SSE4.2 where it runs on a CPU
//! that has it. Zig 0.16 has no per-function target features, so the
//! instructions are emitted by inline assembly, which does not need them.
//!
//! Every backend returns the same value for the same bytes; the tests hold
//! each available one to std's implementation over every length up to past
//! the largest block, at every alignment.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .doc = "CRC-32C (Castagnoli) — SSE4.2 and ARMv8 CRC instructions picked at run time (three interleaved streams), slicing-by-8 fallback; streaming, extend, combine.",
    .platform_note = "any (x86-64 SSE4.2 / arm64 CRC asm + portable fallback)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Go hash/crc32 (Castagnoli, SSE4.2 three-way) / zlib crc32_combine; Intel iSCSI CRC32 white paper",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

/// The CRC-32C of `bytes`.
pub fn hash(bytes: []const u8) u32 {
    return extend(0, bytes);
}

/// The CRC-32C of `prefix ++ bytes`, given `crc == hash(prefix)`. `extend(0,
/// b)` is `hash(b)`, so a checksum can be built up piece by piece.
pub fn extend(crc: u32, bytes: []const u8) u32 {
    return ~raw(backend(), ~crc, bytes);
}

/// The CRC-32C of `a ++ b` from `hash(a)`, `hash(b)` and `b.len`, without the
/// bytes — for checksums computed in parallel over pieces of one buffer.
/// Logarithmic in `len_b`.
pub fn combine(crc_a: u32, crc_b: u32, len_b: u64) u32 {
    return multModP(xPow8n(len_b), crc_a) ^ crc_b;
}

/// Streaming form, with the shape of `std.hash.crc.Crc32Iscsi`.
pub const Crc32c = struct {
    crc: u32 = 0,

    pub fn init() Crc32c {
        return .{};
    }

    pub fn update(self: *Crc32c, bytes: []const u8) void {
        self.crc = extend(self.crc, bytes);
    }

    pub fn final(self: Crc32c) u32 {
        return self.crc;
    }

    pub fn hash(bytes: []const u8) u32 {
        return extend(0, bytes);
    }
};

pub const Backend = enum {
    /// Slicing-by-8 tables: any CPU.
    table,
    /// The x86-64 SSE4.2 `crc32` instruction.
    sse42,
    /// The ARMv8 CRC32 extension's `crc32c*` instructions.
    armv8,
};

/// The backend `hash`, `extend` and `Crc32c` use on this CPU.
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
        .sse42 => sse42_emittable and ((comptime staticBackend() == .sse42) or cpuidSse42()),
        .armv8 => builtin.cpu.arch == .aarch64 and ((comptime staticBackend() == .armv8) or hwcapCrc32()),
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

/// The SSE4.2 `crc32` instruction can be compiled at all. Zig 0.16's
/// self-hosted x86_64 backend (the Debug default) encodes only what the
/// target CPU model has, so there the run-time-dispatched path exists only
/// when the target guarantees SSE4.2 anyway; LLVM assembles it for any
/// x86_64 target.
const sse42_emittable = builtin.cpu.arch == .x86_64 and
    (builtin.zig_backend != .stage2_x86_64 or std.Target.x86.featureSetHas(builtin.cpu.features, .sse4_2));

/// The backend the build target guarantees, when it guarantees one.
fn staticBackend() ?Backend {
    const cpu = builtin.cpu;
    return switch (cpu.arch) {
        .x86_64 => if (std.Target.x86.featureSetHas(cpu.features, .sse4_2)) .sse42 else if (sse42_emittable) null else .table,
        .aarch64 => if (std.Target.aarch64.featureSetHas(cpu.features, .crc)) .armv8 else null,
        else => .table,
    };
}

fn detect() Backend {
    return switch (builtin.cpu.arch) {
        .x86_64 => if (sse42_emittable and cpuidSse42()) .sse42 else .table,
        .aarch64 => if (hwcapCrc32()) .armv8 else .table,
        else => .table,
    };
}

fn cpuidSse42() bool {
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
    return (ecx >> 20) & 1 == 1; // CPUID.01H:ECX.SSE4_2[bit 20]
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
        .sse42 => if (sse42_emittable) threeWay(X86, reg, bytes) else unreachable,
        .armv8 => if (builtin.cpu.arch == .aarch64) threeWay(Arm, reg, bytes) else unreachable,
    };
}

// ── the polynomial ──────────────────────────────────────────────────────────

/// 0x1EDC6F41, bit-reflected.
const poly: u32 = 0x82F6_3B78;

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

/// x^(2^k) mod P for k = 0 … 31.
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

/// x^(8n) mod P: what appending `n` zero bytes multiplies a register by.
fn xPow8n(n: u64) u32 {
    @setEvalBranchQuota(100_000);
    var p: u32 = 1 << 31; // x⁰
    var k: usize = 3;
    var rest = n;
    while (rest != 0) : (rest >>= 1) {
        if (rest & 1 != 0) p = multModP(x2n[k & 31], p);
        k += 1;
    }
    return p;
}

// ── slicing-by-8 ────────────────────────────────────────────────────────────

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

// ── three interleaved hardware streams ──────────────────────────────────────
//
// One `crc32` instruction takes 8 bytes but has a latency of about three
// cycles, so a single dependent chain leaves the unit two thirds idle. Three
// chains over three consecutive blocks A, B, C keep it busy; the registers
// are then joined by linearity: the register after A‖B from `r` is
// shift_|B|(reg(A, r)) ⊕ reg(B, 0), where shift_n multiplies by x^(8n) mod P.
// For the two fixed block sizes shift_n is a precomputed linear map, applied
// a byte at a time from four 256-entry tables.

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

const X86 = struct {
    fn step8(c: u32, v: u64) u32 {
        return @truncate(asm ("crc32q %[v], %[c]"
            : [c] "=r" (-> u64),
            : [v] "r" (v),
              [_] "0" (@as(u64, c)),
        ));
    }
};

const Arm = struct {
    fn step8(c: u32, v: u64) u32 {
        return asm (
            \\.arch_extension crc
            \\crc32cx %[c:w], %[c:w], %[v:x]
            : [c] "=r" (-> u32),
            : [v] "r" (v),
              [_] "0" (c),
        );
    }
};

fn threeWay(comptime Isa: type, reg: u32, bytes: []const u8) u32 {
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
                c0 = Isa.step8(c0, std.mem.readInt(u64, p[i..][0..8], .little));
                c1 = Isa.step8(c1, std.mem.readInt(u64, p[n + i ..][0..8], .little));
                c2 = Isa.step8(c2, std.mem.readInt(u64, p[2 * n + i ..][0..8], .little));
            }
            c = shift(blk[1], c0) ^ c1;
            c = shift(blk[1], c) ^ c2;
        }
    }
    while (p.len >= 8) : (p = p[8..]) c = Isa.step8(c, std.mem.readInt(u64, p[0..8], .little));
    // The last few bytes by table: the byte-wide instruction is the one the
    // self-hosted x86 backend's assembler cannot encode (Zig 0.16, Debug).
    return tableUpdate(c, p);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const all_backends = [_]Backend{ .table, .sse42, .armv8 };

test "published vectors: the CRC catalogue check value and RFC 3720 B.4" {
    // The check value of CRC-32/ISCSI in the reveng CRC catalogue, and the
    // four 32-byte examples of RFC 3720 appendix B.4.
    var zeros: [32]u8 = @splat(0);
    var ones: [32]u8 = @splat(0xff);
    var up: [32]u8 = undefined;
    var down: [32]u8 = undefined;
    for (0..32) |i| {
        up[i] = @intCast(i);
        down[i] = @intCast(31 - i);
    }
    const cases = [_]struct { []const u8, u32 }{
        .{ "123456789", 0xE306_9283 },
        .{ &zeros, 0x8A91_36AA },
        .{ &ones, 0x62A8_AB43 },
        .{ &up, 0x46DD_794E },
        .{ &down, 0x113F_DB5C },
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
    // The table and this CPU's hardware, when this build can contain a hardware path.
    const paths: usize = if (sse42_emittable or builtin.cpu.arch == .aarch64) 2 else 1;
    try testing.expect(ran >= paths * cases.len);
    for (cases) |c| try testing.expectEqual(c[1], hash(c[0]));
}

test "every backend agrees with std's implementation at every length and alignment" {
    // std's `Crc32Iscsi` is an independent, bytewise implementation. Lengths
    // run densely through every threshold of the three-way split: 8, one and
    // three short blocks, one and three long blocks, and past them.
    const max = 3 * long_block * 2 + 3 * short_block + 64;
    const buf = try testing.allocator.alloc(u8, max + 16);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(0xc4c32c);
    prng.random().bytes(buf);

    var lengths: std.ArrayList(usize) = .empty;
    defer lengths.deinit(testing.allocator);
    for (0..3 * short_block + 40) |n| try lengths.append(testing.allocator, n);
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
            for (0..16) |off| {
                if (n > 2048 and off % 5 != 0) continue; // the long ones at a few offsets
                const data = buf[off..][0..n];
                const want = std.hash.crc.Crc32Iscsi.hash(data);
                try testing.expectEqual(want, hashWith(b, data).?);
            }
        }
    }
    // On the machines this suite runs on (x86-64 with SSE4.2, arm64 with CRC)
    // a hardware path exists, and a suite that never took it proves nothing
    // about it — unless this build cannot contain one.
    if (sse42_emittable or builtin.cpu.arch == .aarch64) try testing.expect(hw_checked);
}

test "backend picks the hardware when the CPU has it" {
    const b = backend();
    try testing.expect(available(b));
    switch (builtin.cpu.arch) {
        .x86_64 => try testing.expectEqual(if (sse42_emittable and cpuidSse42()) Backend.sse42 else Backend.table, b),
        .aarch64 => try testing.expectEqual(if (available(.armv8)) Backend.armv8 else Backend.table, b),
        else => try testing.expectEqual(Backend.table, b),
    }
    try testing.expect(!available(if (builtin.cpu.arch == .x86_64) .armv8 else .sse42));
    try testing.expectEqual(@as(?u32, null), hashWith(if (builtin.cpu.arch == .x86_64) .armv8 else .sse42, "x"));
}

test "extend and the streaming form build the checksum of a whole from its pieces" {
    var buf: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&buf);
    const whole = std.hash.crc.Crc32Iscsi.hash(&buf);
    for ([_]usize{ 0, 1, 7, 8, 9, 255, 256, 769, 2999, 3000 }) |cut| {
        try testing.expectEqual(whole, extend(hash(buf[0..cut]), buf[cut..]));
        var s = Crc32c.init();
        s.update(buf[0..cut]);
        s.update(buf[cut..]);
        try testing.expectEqual(whole, s.final());
    }
    try testing.expectEqual(whole, Crc32c.hash(&buf));
}

test "combine joins two checksums without the bytes" {
    const buf = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(11);
    prng.random().bytes(buf);
    const whole = std.hash.crc.Crc32Iscsi.hash(buf);
    for ([_]usize{ 0, 1, 3, 8, 1000, 32_768, 69_999, 70_000 }) |cut| {
        const a = hash(buf[0..cut]);
        const b = hash(buf[cut..]);
        try testing.expectEqual(whole, combine(a, b, buf.len - cut));
    }
    // An empty right-hand side changes nothing, whatever its "checksum".
    try testing.expectEqual(hash("abc"), combine(hash("abc"), 0, 0));
}

test "fuzz: every backend, extend and combine agree with std on arbitrary bytes" {
    try testing.fuzz({}, fuzzAgree, .{});
}

/// Room for two rounds of three long blocks, so the fuzzer can reach every
/// path of the three-way split.
var fuzz_buf: [6 * long_block + 3 * short_block + 64]u8 = undefined;

fn fuzzAgree(_: void, smith: *std.testing.Smith) !void {
    const len = smith.slice(&fuzz_buf);
    const data = fuzz_buf[0..len];
    const want = std.hash.crc.Crc32Iscsi.hash(data);
    for (all_backends) |b| if (hashWith(b, data)) |got| try testing.expectEqual(want, got);
    const cut = smith.valueRangeAtMost(u32, 0, len);
    try testing.expectEqual(want, extend(hash(data[0..cut]), data[cut..]));
    try testing.expectEqual(want, combine(hash(data[0..cut]), hash(data[cut..]), len - cut));
}

test "the shift tables are the zero-byte operator they claim to be" {
    // Appending n zero bytes to a register is the same as the table map for
    // n: checked against the plain table update over real zero bytes, for
    // registers with single bits and random ones.
    const zeros = [_]u8{0} ** long_block;
    var prng = std.Random.DefaultPrng.init(3);
    for (0..40) |i| {
        const r: u32 = if (i < 32) @as(u32, 1) << @intCast(i) else prng.random().int(u32);
        try testing.expectEqual(tableUpdate(r, &zeros), shift(&shift_long, r));
        try testing.expectEqual(tableUpdate(r, zeros[0..short_block]), shift(&shift_short, r));
    }
}
