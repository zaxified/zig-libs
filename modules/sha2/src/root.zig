// SPDX-License-Identifier: MIT

//! sha2 — SHA-224/256/384/512 (FIPS 180-4), a faster drop-in for
//! `std.crypto.hash.sha2`.
//!
//! `Sha224`, `Sha256`, `Sha384` and `Sha512` have the declarations of their
//! std namesakes — `block_length`, `digest_length`, `Options`, `init`,
//! `update`, `peek`, `final`, `finalResult`, `hash` — so a consumer swaps the
//! type and nothing else, and `std.crypto.auth.hmac.Hmac(sha2.Sha256)` /
//! `std.crypto.kdf.hkdf.Hkdf(...)` instantiate over them unchanged.
//!
//! Where the speed comes from: the message schedule (FIPS 180-4 §6.2.2 step 1,
//! §6.4.2 step 1) depends only on the message block, never on the chaining
//! value, so the schedules of several consecutive blocks of one message can be
//! computed together. On an AVX2 target the SIMD backend transposes up to 8
//! SHA-256 blocks (4 SHA-512 blocks) so that each vector lane carries one
//! block, runs the schedule recurrence once for all of them, adds the round
//! constants, and then runs the scalar rounds of each block reading its
//! `W[t] + K[t]` from that table. The idea of moving the schedule to SIMD
//! registers is Intel's ("Fast SHA-256 Implementations on Intel Architecture
//! Processors", Guilford et al., 2012; Gulley et al. for SHA-512); computing it
//! across blocks, one block per lane, rather than four words of one block per
//! vector, is this module's choice: it needs no intra-vector dependency fix-up
//! and the same code serves both word sizes.
//!
//! The rounds are plain Zig; on a BMI2 target LLVM emits `rorx`/`andn` for the
//! rotations and `Ch`. Two textbook rewrites shorten each round: `Maj(a,b,c) =
//! ((a ^ b) & (b ^ c)) ^ b`, whose `b ^ c` is the previous round's `a ^ b`,
//! and `Ch(e,f,g) = (e & f) ^ (~e & g)`, two independent halves.
//!
//! Dispatch is at compile time (`backend()`):
//!
//! - `.stdlib` — SHA-256/224 on a target where std itself uses SHA hardware
//!   instructions (x86-64 SHA-NI + AVX2, arm64 `sha2`): compression is handed
//!   to std, which is faster than anything here on such a CPU.
//! - `.simd` — the multi-block schedule above, on x86-64 with AVX2 under the
//!   LLVM backend. Runs of two or more whole blocks take it; a lone block
//!   (and the padding block of `final`) takes the scalar path.
//! - `.scalar` — everything else: the same rounds with the schedule computed
//!   inline, 16 words at a time. Pure Zig, every target and backend.
//!
//! Every backend produces the same bytes; the tests hold each one to std and to
//! the FIPS 180-4 / NIST example vectors.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .doc = "SHA-224/256/384/512 (FIPS 180-4) — drop-in for std.crypto.hash.sha2 (also under std's Hmac/Hkdf); an AVX2 multi-block message schedule makes runs of 2+ blocks 1.24–1.40× std on x86-64 without SHA-NI, std's own SHA-NI/ARMv8 path where the target has it.",
    .platform_note = "any (AVX2 SIMD schedule on x86-64 + portable scalar fallback)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "FIPS 180-4; Intel \"Fast SHA-256 Implementations on Intel Architecture Processors\" (2012) and Gulley et al. SHA-512 (vectorized message schedule)",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

pub const Sha224 = Sha2(u32, iv224, 224);
pub const Sha256 = Sha2(u32, iv256, 256);
pub const Sha384 = Sha2(u64, iv384, 384);
pub const Sha512 = Sha2(u64, iv512, 512);

/// How the compression function runs. Fixed at compile time per word size.
pub const Backend = enum {
    /// Handed to std's compression, because std has SHA hardware
    /// instructions for this target (SHA-256/224 only).
    stdlib,
    /// Multi-block SIMD message schedule + scalar rounds (x86-64 AVX2, LLVM).
    simd,
    /// Scalar rounds with the schedule computed inline. Any target.
    scalar,
};

fn Sha2(comptime Word: type, comptime iv: [8]Word, comptime digest_bits: comptime_int) type {
    const E = Engine(Word);
    comptime std.debug.assert(digest_bits % @bitSizeOf(Word) == 0);
    return struct {
        const Self = @This();
        /// Bytes per compression block: 64 for SHA-224/256, 128 for SHA-384/512.
        pub const block_length = E.block_len;
        /// Bytes of output.
        pub const digest_length = digest_bits / 8;
        /// No options; present for `std.crypto.hash.sha2` compatibility.
        pub const Options = struct {};

        /// Length counter width: FIPS 180-4 appends a 64-bit (SHA-224/256) or
        /// 128-bit (SHA-384/512) big-endian bit count.
        const LenInt = if (Word == u32) u64 else u128;

        s: [8]Word,
        buf: [block_length]u8 = undefined,
        buf_len: u8 = 0,
        total_len: LenInt = 0,

        pub fn init(options: Options) Self {
            _ = options;
            // Field by field into an undefined value: a struct literal
            // relying on the `buf = undefined` default can compile to a
            // memset of the whole buffer (Zig 0.16 ReleaseFast), which HMAC's
            // short messages would pay on every call.
            var d: Self = undefined;
            d.s = iv;
            d.buf_len = 0;
            d.total_len = 0;
            return d;
        }

        /// One-shot: `out = H(b)`.
        pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
            var d = Self.init(options);
            d.update(b);
            d.final(out);
        }

        pub fn update(d: *Self, b: []const u8) void {
            var rest = b;
            if (d.buf_len != 0) {
                const take = @min(block_length - d.buf_len, rest.len);
                @memcpy(d.buf[d.buf_len..][0..take], rest[0..take]);
                d.buf_len += @intCast(take);
                rest = rest[take..];
                if (d.buf_len < block_length) {
                    d.total_len +%= b.len;
                    return;
                }
                E.compressBlocks(&d.s, &d.buf);
                d.buf_len = 0;
            }
            const whole = rest.len - rest.len % block_length;
            if (whole != 0) E.compressBlocks(&d.s, rest[0..whole]);
            rest = rest[whole..];
            @memcpy(d.buf[0..rest.len], rest);
            d.buf_len = @intCast(rest.len);
            d.total_len +%= b.len;
        }

        /// The digest of everything so far, leaving `d` unchanged.
        pub fn peek(d: Self) [digest_length]u8 {
            var copy = d;
            return copy.finalResult();
        }

        pub fn final(d: *Self, out: *[digest_length]u8) void {
            const len_bytes = @sizeOf(LenInt);
            var i: usize = d.buf_len;
            d.buf[i] = 0x80;
            i += 1;
            if (i > block_length - len_bytes) {
                @memset(d.buf[i..], 0);
                E.compressBlocks(&d.s, &d.buf);
                i = 0;
            }
            @memset(d.buf[i .. block_length - len_bytes], 0);
            // Bit count; bits above the counter's width are dropped, as the
            // counter is a byte count of the same width (FIPS 180-4 bounds
            // the message below 2^64 / 2^128 bits anyway).
            std.mem.writeInt(LenInt, d.buf[block_length - len_bytes ..][0..len_bytes], d.total_len << 3, .big);
            E.compressBlocks(&d.s, &d.buf);

            const n_words = digest_length / @sizeOf(Word);
            inline for (0..n_words) |j| {
                std.mem.writeInt(Word, out[j * @sizeOf(Word) ..][0..@sizeOf(Word)], d.s[j], .big);
            }
        }

        pub fn finalResult(d: *Self) [digest_length]u8 {
            var result: [digest_length]u8 = undefined;
            d.final(&result);
            return result;
        }

        /// The backend this type's compression runs on (fixed per target).
        pub fn backend() Backend {
            return E.default_backend;
        }
    };
}

// ── test-only switch ────────────────────────────────────────────────────────

/// Test builds only: `forced` overrides the compile-time backend choice, so
/// one test run can hold every backend to std. It does not exist outside
/// `zig test` (the struct is empty), so no production path can read it.
pub const test_hooks = if (builtin.is_test) struct {
    pub var forced: ?Backend = null;

    /// Whether `b` can run in this build (compiled in, and correct here).
    pub fn available(comptime Word: type, b: Backend) bool {
        return switch (b) {
            .stdlib, .scalar => true,
            .simd => Engine(Word).simd_compiled,
        };
    }
} else struct {};

// ── constants (FIPS 180-4 §4.2.2, §4.2.3, §5.3), derived, not transcribed ───

/// The first `n` primes.
fn firstPrimes(comptime n: usize) [n]u32 {
    var out: [n]u32 = undefined;
    var count: usize = 0;
    var c: u32 = 2;
    while (count < n) : (c += 1) {
        var d: u32 = 2;
        const prime = while (d * d <= c) : (d += 1) {
            if (c % d == 0) break false;
        } else true;
        if (prime) {
            out[count] = c;
            count += 1;
        }
    }
    return out;
}

/// The first `@bitSizeOf(Word)` bits of the fractional part of `p^(1/root)`:
/// `floor(p^(1/root) · 2^w) mod 2^w`, as the integer `root`-th root of
/// `p · 2^(root·w)` — exact, no floating point.
fn fracRoot(comptime Word: type, comptime p: u32, comptime root: comptime_int) Word {
    const w = @bitSizeOf(Word);
    const target: u256 = @as(u256, p) << (root * w);
    // p < 2^9, so the root is below 2^(w+4) and its cube below 2^(3w+12) ≤ 2^204.
    var lo: u256 = 0;
    var hi: u256 = @as(u256, 1) << (w + 4);
    while (hi - lo > 1) {
        const mid = (lo + hi) / 2;
        var pw: u256 = 1;
        for (0..root) |_| pw *= mid;
        if (pw <= target) lo = mid else hi = mid;
    }
    return @truncate(lo);
}

fn roundConstants(comptime Word: type, comptime n: usize) [n]Word {
    @setEvalBranchQuota(2_000_000);
    const primes = firstPrimes(n);
    var k: [n]Word = undefined;
    for (&k, primes) |*x, p| x.* = fracRoot(Word, p, 3);
    return k;
}

fn initialValues(comptime Word: type, comptime first_prime: usize) [8]Word {
    @setEvalBranchQuota(2_000_000);
    const primes = firstPrimes(first_prime + 8);
    var v: [8]Word = undefined;
    for (&v, primes[first_prime..]) |*x, p| x.* = fracRoot(Word, p, 2);
    return v;
}

/// Square roots of the first 8 primes (§5.3.3).
const iv256 = initialValues(u32, 0);
/// Square roots of the first 8 primes, 64 bits (§5.3.5).
const iv512 = initialValues(u64, 0);
/// Square roots of the 9th–16th primes (§5.3.4).
const iv384 = initialValues(u64, 8);
/// §5.3.2's SHA-224 values are the low halves of SHA-384's.
const iv224 = blk: {
    var v: [8]u32 = undefined;
    for (&v, iv384) |*x, y| x.* = @truncate(y);
    break :blk v;
};

// ── the compression engine, generic over the word size ─────────────────────

fn Engine(comptime Word: type) type {
    return struct {
        const bytes = @sizeOf(Word);
        const bits = @bitSizeOf(Word);
        const block_len = 16 * bytes;
        const rounds = if (Word == u32) 64 else 80;
        const K: [rounds]Word = roundConstants(Word, rounds);

        // Rotation/shift amounts, FIPS 180-4 §4.1.2 (4.4–4.7), §4.1.3 (4.10–4.13).
        const big0: [3]comptime_int = if (Word == u32) .{ 2, 13, 22 } else .{ 28, 34, 39 };
        const big1: [3]comptime_int = if (Word == u32) .{ 6, 11, 25 } else .{ 14, 18, 41 };
        const small0: [3]comptime_int = if (Word == u32) .{ 7, 18, 3 } else .{ 1, 8, 7 };
        const small1: [3]comptime_int = if (Word == u32) .{ 17, 19, 10 } else .{ 19, 61, 6 };

        /// Blocks per SIMD schedule: 256-bit vectors, one block per lane.
        const lanes = 32 / bytes;
        const V = @Vector(lanes, Word);

        /// The SIMD backend is compiled only under LLVM (the self-hosted
        /// backends are for the edit loop and are not asked to lower 256-bit
        /// shuffles) and only for a target that has AVX2 — on anything
        /// narrower the vectors would be split and the win is unmeasured.
        const simd_compiled = builtin.zig_backend == .stage2_llvm and
            builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx2);

        /// std compresses SHA-256 with SHA-NI (x86-64, together with AVX2) or
        /// the ARMv8 SHA2 instructions; its SHA-512 is scalar everywhere.
        const std_has_hw = Word == u32 and builtin.zig_backend != .stage2_c and switch (builtin.cpu.arch) {
            .x86_64 => builtin.cpu.hasAll(.x86, &.{ .sha, .avx2 }),
            .aarch64 => builtin.cpu.has(.aarch64, .sha2),
            else => false,
        };

        const default_backend: Backend = if (std_has_hw) .stdlib else if (simd_compiled) .simd else .scalar;

        const StdHash = if (Word == u32) std.crypto.hash.sha2.Sha256 else std.crypto.hash.sha2.Sha512;

        fn activeBackend() Backend {
            if (@inComptime()) return .scalar;
            if (builtin.is_test) {
                if (test_hooks.forced) |f| return f;
            }
            return default_backend;
        }

        /// Compress `data` (a whole number of blocks) into `s`.
        fn compressBlocks(s: *[8]Word, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            switch (activeBackend()) {
                .stdlib => {
                    // std's state struct is public; its `update` over whole
                    // blocks with an empty buffer is exactly its compression.
                    var h = StdHash.init(.{});
                    h.s = s.*;
                    h.update(data);
                    s.* = h.s;
                },
                .simd => if (simd_compiled) compressSimd(s, data) else unreachable,
                .scalar => {
                    var p = data;
                    while (p.len != 0) : (p = p[block_len..]) compressScalar(s, p[0..block_len]);
                },
            }
        }

        inline fn rotr(x: Word, comptime n: comptime_int) Word {
            return std.math.rotr(Word, x, n);
        }

        inline fn sigma0(x: Word) Word {
            return rotr(x, small0[0]) ^ rotr(x, small0[1]) ^ (x >> small0[2]);
        }

        inline fn sigma1(x: Word) Word {
            return rotr(x, small1[0]) ^ rotr(x, small1[1]) ^ (x >> small1[2]);
        }

        /// One round t on the working variables, which live in `v` under
        /// rotating names: at round t, `a` is `v[(0 - t) mod 8]`, `b` is
        /// `v[(1 - t) mod 8]`, … so no value is moved, only renamed. `bc`
        /// carries `b ^ c` for Maj, which is the previous round's `a ^ b`.
        inline fn round(v: *[8]Word, bc: *Word, comptime t: usize, wk: Word) void {
            const r = t % 8;
            const a = (0 + 8 - r) % 8;
            const b = (1 + 8 - r) % 8;
            const c = (2 + 8 - r) % 8;
            const d = (3 + 8 - r) % 8;
            const e = (4 + 8 - r) % 8;
            const f = (5 + 8 - r) % 8;
            const g = (6 + 8 - r) % 8;
            const h = (7 + 8 - r) % 8;
            _ = c;

            const ev = v[e];
            const s1 = rotr(ev, big1[0]) ^ rotr(ev, big1[1]) ^ rotr(ev, big1[2]);
            const ch = (ev & v[f]) ^ (~ev & v[g]);
            const t1 = (v[h] +% wk) +% ch +% s1;

            const av = v[a];
            const s0 = rotr(av, big0[0]) ^ rotr(av, big0[1]) ^ rotr(av, big0[2]);
            const ab = av ^ v[b];
            const maj = (ab & bc.*) ^ v[b];
            bc.* = ab;

            v[d] +%= t1;
            v[h] = t1 +% s0 +% maj;
        }

        /// Scalar compression of one block, schedule computed inline in a
        /// 16-word ring (FIPS 180-4 §6.2.2 / §6.4.2).
        fn compressScalar(s: *[8]Word, block: *const [block_len]u8) void {
            // The unrolled rounds exceed the default quota when this runs at
            // compile time (`comptime Sha256.hash(...)`).
            @setEvalBranchQuota(100_000);
            var w: [16]Word = undefined;
            inline for (0..16) |i| w[i] = std.mem.readInt(Word, block[i * bytes ..][0..bytes], .big);
            var v = s.*;
            var bc = v[1] ^ v[2];
            inline for (0..rounds) |t| {
                if (t >= 16) {
                    w[t % 16] = w[t % 16] +% sigma1(w[(t - 2) % 16]) +% w[(t - 7) % 16] +% sigma0(w[(t - 15) % 16]);
                }
                round(&v, &bc, t, w[t % 16] +% K[t]);
            }
            inline for (s, v) |*x, y| x.* +%= y;
        }

        // ── SIMD backend ──────────────────────────────────────────────────

        const Shift = std.math.Log2Int(Word);

        inline fn vrotr(x: V, comptime n: comptime_int) V {
            return (x >> @as(@Vector(lanes, Shift), @splat(n))) | (x << @as(@Vector(lanes, Shift), @splat(bits - n)));
        }

        inline fn vshr(x: V, comptime n: comptime_int) V {
            return x >> @as(@Vector(lanes, Shift), @splat(n));
        }

        inline fn vsigma0(x: V) V {
            return vrotr(x, small0[0]) ^ vrotr(x, small0[1]) ^ vshr(x, small0[2]);
        }

        inline fn vsigma1(x: V) V {
            return vrotr(x, small1[0]) ^ vrotr(x, small1[1]) ^ vshr(x, small1[2]);
        }

        /// `@shuffle` masks for one stage of the block-swap transpose: rows
        /// `i` and `i + half` (bit `half` of `i` clear) exchange their
        /// off-diagonal `half`-wide blocks.
        fn maskLow(comptime half: usize) @Vector(lanes, i32) {
            var m: [lanes]i32 = undefined;
            for (0..lanes) |col| m[col] = if (col & half == 0) @intCast(col) else ~@as(i32, @intCast(col - half));
            return m;
        }

        fn maskHigh(comptime half: usize) @Vector(lanes, i32) {
            var m: [lanes]i32 = undefined;
            for (0..lanes) |col| m[col] = if (col & half == 0) @intCast(col + half) else ~@as(i32, @intCast(col));
            return m;
        }

        /// Transpose a lanes × lanes matrix held as row vectors, in place:
        /// log2(lanes) stages of block swaps, halving the block each stage.
        inline fn transpose(rows: *[lanes]V) void {
            comptime var half: usize = lanes / 2;
            inline while (half >= 1) : (half /= 2) {
                inline for (0..lanes) |i| {
                    if (i & half == 0) {
                        const x = rows[i];
                        const y = rows[i + half];
                        rows[i] = @shuffle(Word, x, y, maskLow(half));
                        rows[i + half] = @shuffle(Word, x, y, maskHigh(half));
                    }
                }
            }
        }

        /// `wk[t][j] = W_t + K_t` for block `j` of `data` (1 ≤ n ≤ lanes
        /// blocks; lanes past `n` repeat the last block and are ignored).
        fn scheduleSimd(data: []const u8, n: usize, wk: *[rounds]V) void {
            var w: [16]V = undefined;
            inline for (0..16 / lanes) |chunk| {
                var rows: [lanes]V = undefined;
                inline for (0..lanes) |j| {
                    const blk: usize = @min(j, n - 1);
                    const src: *align(1) const V = @ptrCast(data[blk * block_len + chunk * lanes * bytes ..][0 .. lanes * bytes]);
                    const raw = src.*;
                    rows[j] = if (builtin.cpu.arch.endian() == .little) @byteSwap(raw) else raw;
                }
                transpose(&rows);
                inline for (0..lanes) |i| w[chunk * lanes + i] = rows[i];
            }
            inline for (0..rounds) |t| {
                if (t >= 16) {
                    w[t % 16] = w[t % 16] +% vsigma1(w[(t - 2) % 16]) +% w[(t - 7) % 16] +% vsigma0(w[(t - 15) % 16]);
                }
                wk[t] = w[t % 16] +% @as(V, @splat(K[t]));
            }
        }

        /// The rounds of block `j`, reading `W_t + K_t` from the table.
        fn roundsFromTable(s: *[8]Word, wk: *const [rounds][lanes]Word, j: usize) void {
            var v = s.*;
            var bc = v[1] ^ v[2];
            inline for (0..rounds) |t| round(&v, &bc, t, wk[t][j]);
            inline for (s, v) |*x, y| x.* +%= y;
        }

        fn compressSimd(s: *[8]Word, data: []const u8) void {
            var p = data;
            // A lone block would pay a whole lanes-wide schedule for one lane.
            while (p.len >= 2 * block_len) {
                const n: usize = @min(lanes, p.len / block_len);
                var wk: [rounds]V = undefined;
                scheduleSimd(p[0 .. n * block_len], n, &wk);
                const table: *const [rounds][lanes]Word = @ptrCast(&wk);
                for (0..n) |j| roundsFromTable(s, table, j);
                p = p[n * block_len ..];
            }
            if (p.len != 0) compressScalar(s, p[0..block_len]);
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = @import("bench.zig");
    _ = @import("count.zig");
}

fn unhex(comptime n: usize, hex: []const u8) [n]u8 {
    std.debug.assert(hex.len == 2 * n);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Every backend this build can run, for the Word size of `H`.
fn backendsFor(comptime Word: type) []const Backend {
    return comptime blk: {
        var buf: [3]Backend = undefined;
        var n: usize = 0;
        for ([_]Backend{ .stdlib, .simd, .scalar }) |b| {
            if (test_hooks.available(Word, b)) {
                buf[n] = b;
                n += 1;
            }
        }
        const out = buf;
        break :blk out[0..n];
    };
}

fn WordOf(comptime H: type) type {
    return if (H.block_length == 64) u32 else u64;
}

fn StdOf(comptime H: type) type {
    return if (H == Sha224) std.crypto.hash.sha2.Sha224 else if (H == Sha256) std.crypto.hash.sha2.Sha256 else if (H == Sha384) std.crypto.hash.sha2.Sha384 else std.crypto.hash.sha2.Sha512;
}

const m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

const Kat = struct { msg: []const u8, hex: []const u8 };

/// FIPS 180-4 examples (NIST CSRC "Examples with Intermediate Values": "abc",
/// the 448- and 896-bit messages) and the empty / one-million-'a' messages of
/// the NIST SHAVS / FIPS 180-2 appendix; values cross-checked against CPython's
/// `hashlib` (OpenSSL) on 2026-09-29.
fn kats(comptime H: type) [4]Kat {
    return switch (H.digest_length * 8) {
        224 => .{
            .{ .msg = "", .hex = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
            .{ .msg = "abc", .hex = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
            .{ .msg = m448, .hex = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
            .{ .msg = m896, .hex = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" },
        },
        256 => .{
            .{ .msg = "", .hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            .{ .msg = "abc", .hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
            .{ .msg = m448, .hex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
            .{ .msg = m896, .hex = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
        },
        384 => .{
            .{ .msg = "", .hex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
            .{ .msg = "abc", .hex = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
            .{ .msg = m448, .hex = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b" },
            .{ .msg = m896, .hex = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },
        },
        512 => .{
            .{ .msg = "", .hex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
            .{ .msg = "abc", .hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
            .{ .msg = m448, .hex = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
            .{ .msg = m896, .hex = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
        },
        else => unreachable,
    };
}

fn millionA(comptime H: type) []const u8 {
    return switch (H.digest_length * 8) {
        224 => "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        256 => "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        384 => "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        512 => "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        else => unreachable,
    };
}

const all_hashes = .{ Sha224, Sha256, Sha384, Sha512 };

test "derived constants match FIPS 180-4" {
    const E32 = Engine(u32);
    const E64 = Engine(u64);
    // §4.2.2 / §4.2.3, first and last of each table.
    try testing.expectEqual(@as(u32, 0x428a2f98), E32.K[0]);
    try testing.expectEqual(@as(u32, 0xc67178f2), E32.K[63]);
    try testing.expectEqual(@as(u64, 0x428a2f98d728ae22), E64.K[0]);
    try testing.expectEqual(@as(u64, 0x6c44198c4a475817), E64.K[79]);
    // SHA-256's constants are the high halves of SHA-512's first 64.
    for (E32.K, 0..) |k, i| try testing.expectEqual(k, @as(u32, @truncate(E64.K[i] >> 32)));
    // §5.3.
    try testing.expectEqual(@as(u32, 0x6a09e667), iv256[0]);
    try testing.expectEqual(@as(u32, 0x5be0cd19), iv256[7]);
    try testing.expectEqual(@as(u32, 0xc1059ed8), iv224[0]);
    try testing.expectEqual(@as(u32, 0xbefa4fa4), iv224[7]);
    try testing.expectEqual(@as(u64, 0xcbbb9d5dc1059ed8), iv384[0]);
    try testing.expectEqual(@as(u64, 0x47b5481dbefa4fa4), iv384[7]);
    try testing.expectEqual(@as(u64, 0x6a09e667f3bcc908), iv512[0]);
    try testing.expectEqual(@as(u64, 0x5be0cd19137e2179), iv512[7]);
}

test "std-compatible declarations" {
    inline for (all_hashes) |H| {
        const S = StdOf(H);
        try testing.expectEqual(S.block_length, H.block_length);
        try testing.expectEqual(S.digest_length, H.digest_length);
        const o: H.Options = .{};
        var d = H.init(o);
        d.update("x");
        const p = d.peek();
        var out: [H.digest_length]u8 = undefined;
        d.final(&out);
        try testing.expectEqualSlices(u8, &p, &out);
        var one: [H.digest_length]u8 = undefined;
        H.hash("x", &one, .{});
        try testing.expectEqualSlices(u8, &one, &out);
    }
}

test "the default backend on this target" {
    // On an x86-64 AVX2 build under LLVM without SHA-NI (the development
    // machine), the fast path must be the one taken — a dispatch regression
    // that silently fell back to scalar would otherwise pass every KAT.
    const expect32: Backend = if (Engine(u32).std_has_hw) .stdlib else if (Engine(u32).simd_compiled) .simd else .scalar;
    try testing.expectEqual(expect32, Sha256.backend());
    try testing.expectEqual(Sha256.backend(), Sha224.backend());
    const expect64: Backend = if (Engine(u64).simd_compiled) .simd else .scalar;
    try testing.expectEqual(expect64, Sha512.backend());
    try testing.expectEqual(Sha512.backend(), Sha384.backend());
    if (builtin.cpu.arch == .x86_64 and builtin.cpu.has(.x86, .avx2) and
        !builtin.cpu.has(.x86, .sha) and builtin.zig_backend == .stage2_llvm)
    {
        try testing.expectEqual(Backend.simd, Sha256.backend());
        try testing.expectEqual(Backend.simd, Sha384.backend());
    }
}

test "FIPS 180-4 known answers, every backend" {
    defer test_hooks.forced = null;
    inline for (all_hashes) |H| {
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            for (kats(H)) |k| {
                var out: [H.digest_length]u8 = undefined;
                H.hash(k.msg, &out, .{});
                const want = unhex(H.digest_length, k.hex);
                testing.expectEqualSlices(u8, &want, &out) catch |e| {
                    std.debug.print("backend {t}, digest {d}, msg len {d}\n", .{ b, H.digest_length, k.msg.len });
                    return e;
                };
            }
        }
    }
}

test "one million 'a', every backend" {
    defer test_hooks.forced = null;
    // Fed in uneven pieces so both the whole-block run and the buffered
    // path carry it.
    var chunk: [1000]u8 = undefined;
    @memset(&chunk, 'a');
    inline for (all_hashes) |H| {
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            var d = H.init(.{});
            var left: usize = 1_000_000;
            var step: usize = 1;
            while (left > 0) {
                const n = @min(left, step % 1000 + 1);
                d.update(chunk[0..n]);
                left -= n;
                step = (step * 7 + 3) % 1_000_003;
            }
            const want = unhex(H.digest_length, millionA(H));
            try testing.expectEqualSlices(u8, &want, &d.finalResult());
        }
    }
}

test "differential vs std: every length 0..1024, one-shot and split" {
    defer test_hooks.forced = null;
    var prng = std.Random.DefaultPrng.init(0x5ba2_0000_0000_0001);
    var msg: [1024]u8 = undefined;
    prng.random().bytes(&msg);
    inline for (all_hashes) |H| {
        const S = StdOf(H);
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            for (0..msg.len + 1) |len| {
                const m = msg[0..len];
                var want: [H.digest_length]u8 = undefined;
                S.hash(m, &want, .{});
                var got: [H.digest_length]u8 = undefined;
                H.hash(m, &got, .{});
                testing.expectEqualSlices(u8, &want, &got) catch |e| {
                    std.debug.print("backend {t}, digest {d}, len {d}\n", .{ b, H.digest_length, len });
                    return e;
                };
                // Split at a block boundary when there is one, else in the middle.
                const cut = if (len > H.block_length) H.block_length else len / 2;
                var d = H.init(.{});
                d.update(m[0..cut]);
                d.update(m[cut..]);
                try testing.expectEqualSlices(u8, &want, &d.finalResult());
            }
        }
    }
}

test "differential vs std: random lengths to 64 KiB, random and block-edge splits" {
    defer test_hooks.forced = null;
    const max = 64 * 1024;
    const msg = try testing.allocator.alloc(u8, max);
    defer testing.allocator.free(msg);
    var prng = std.Random.DefaultPrng.init(0x5ba2_0000_0000_0002);
    const rnd = prng.random();
    rnd.bytes(msg);
    inline for (all_hashes) |H| {
        const S = StdOf(H);
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            for (0..24) |iter| {
                const len = if (iter == 0) max else rnd.uintAtMost(usize, max);
                const m = msg[0..len];
                var want: [H.digest_length]u8 = undefined;
                S.hash(m, &want, .{});

                // Random cut points, with block edges (and ±1) mixed in.
                var d = H.init(.{});
                var off: usize = 0;
                while (off < len) {
                    const bl = H.block_length;
                    const n = switch (rnd.uintLessThan(u8, 6)) {
                        0 => bl,
                        1 => bl - 1,
                        2 => bl + 1,
                        3 => bl * rnd.uintAtMost(usize, 12),
                        4 => rnd.uintAtMost(usize, 3 * bl),
                        else => rnd.uintAtMost(usize, 4096),
                    };
                    const take = @min(n, len - off);
                    d.update(m[off..][0..take]);
                    off += take;
                }
                testing.expectEqualSlices(u8, &want, &d.finalResult()) catch |e| {
                    std.debug.print("backend {t}, digest {d}, len {d}\n", .{ b, H.digest_length, len });
                    return e;
                };
            }
        }
    }
}

test "every lane count of the SIMD batch, at every offset" {
    // 1..2·lanes+1 whole blocks after a 0..block-1 byte prefix: every
    // partial batch n in 2..lanes, a full batch plus a scalar tail, and
    // repeated-last-block padding lanes.
    defer test_hooks.forced = null;
    var prng = std.Random.DefaultPrng.init(0x5ba2_0000_0000_0003);
    var msg: [20 * 128]u8 = undefined;
    prng.random().bytes(&msg);
    inline for (all_hashes) |H| {
        const S = StdOf(H);
        const lanes = Engine(WordOf(H)).lanes;
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            for (0..H.block_length) |pre| {
                for (1..2 * lanes + 2) |nb| {
                    const m = msg[0 .. pre + nb * H.block_length];
                    var want: [H.digest_length]u8 = undefined;
                    S.hash(m, &want, .{});
                    var d = H.init(.{});
                    d.update(m[0..pre]);
                    d.update(m[pre..]);
                    try testing.expectEqualSlices(u8, &want, &d.finalResult());
                }
            }
        }
    }
}

test "byte-at-a-time and peek" {
    defer test_hooks.forced = null;
    var msg: [300]u8 = undefined;
    for (&msg, 0..) |*x, i| x.* = @truncate(i *% 131 +% 7);
    inline for (all_hashes) |H| {
        const S = StdOf(H);
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            var d = H.init(.{});
            var sd = S.init(.{});
            for (msg) |x| {
                d.update(&.{x});
                sd.update(&.{x});
                try testing.expectEqualSlices(u8, &sd.peek(), &d.peek());
            }
        }
    }
}

test "comptime evaluation" {
    const got = comptime blk: {
        @setEvalBranchQuota(200_000);
        var out: [32]u8 = undefined;
        Sha256.hash("abc", &out, .{});
        break :blk out;
    };
    try testing.expectEqualSlices(u8, &unhex(32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), &got);
}

test "fuzz: every backend and any split agree with std on arbitrary bytes" {
    try testing.fuzz({}, fuzzAgree, .{});
}

/// Past the largest SIMD batch of either word size (8 × 64 = 4 × 128 bytes)
/// several times over, so a fuzzer reaches full and partial batches.
var fuzz_buf: [3 * 1024]u8 = undefined;

fn fuzzAgree(_: void, smith: *std.testing.Smith) !void {
    const len = smith.slice(&fuzz_buf);
    const data = fuzz_buf[0..len];
    const cut = smith.valueRangeAtMost(u32, 0, len);
    defer test_hooks.forced = null;
    inline for (all_hashes) |H| {
        var want: [H.digest_length]u8 = undefined;
        StdOf(H).hash(data, &want, .{});
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            var d = H.init(.{});
            d.update(data[0..cut]);
            d.update(data[cut..]);
            try testing.expectEqualSlices(u8, &want, &d.finalResult());
        }
    }
}

const Hmac = std.crypto.auth.hmac.Hmac;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;

test "HMAC through std's Hmac: RFC 4231 test cases 1, 2, 6, 7" {
    defer test_hooks.forced = null;
    const Case = struct { key: []const u8, data: []const u8, h256: []const u8, h384: []const u8, h512: []const u8 };
    const key131 = [_]u8{0xaa} ** 131;
    const cases = [_]Case{
        .{
            .key = &([_]u8{0x0b} ** 20),
            .data = "Hi There",
            .h256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            .h384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            .h512 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        },
        .{
            .key = "Jefe",
            .data = "what do ya want for nothing?",
            .h256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            .h384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            .h512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        },
        .{
            .key = &key131,
            .data = "Test Using Larger Than Block-Size Key - Hash Key First",
            .h256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            .h384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            .h512 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        },
        .{
            .key = &key131,
            .data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            .h256 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            .h384 = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            .h512 = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        },
    };
    inline for (.{ Sha256, Sha384, Sha512 }) |H| {
        const M = Hmac(H);
        for (backendsFor(WordOf(H))) |b| {
            test_hooks.forced = b;
            for (cases) |c| {
                var out: [M.mac_length]u8 = undefined;
                M.create(&out, c.data, c.key);
                const hex = switch (H.digest_length) {
                    32 => c.h256,
                    48 => c.h384,
                    else => c.h512,
                };
                var want: [M.mac_length]u8 = undefined;
                _ = try std.fmt.hexToBytes(&want, hex);
                try testing.expectEqualSlices(u8, &want, &out);
            }
        }
    }
}

test "HKDF through std's Hkdf: RFC 5869 A.1–A.3 (SHA-256), SHA-384 vs std and CPython" {
    defer test_hooks.forced = null;
    const H256 = Hkdf(Hmac(Sha256));
    const Case = struct { ikm: []const u8, salt: []const u8, info: []const u8, prk: []const u8, okm: []const u8 };
    var ikm2: [80]u8 = undefined;
    var salt2: [80]u8 = undefined;
    var info2: [80]u8 = undefined;
    for (0..80) |i| {
        ikm2[i] = @intCast(i);
        salt2[i] = @intCast(0x60 + i);
        info2[i] = @intCast(0xb0 + i);
    }
    const ikm22 = [_]u8{0x0b} ** 22;
    const salt1 = unhex(13, "000102030405060708090a0b0c");
    const info1 = unhex(10, "f0f1f2f3f4f5f6f7f8f9");
    const cases = [_]Case{
        .{ .ikm = &ikm22, .salt = &salt1, .info = &info1, .prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", .okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" },
        .{ .ikm = &ikm2, .salt = &salt2, .info = &info2, .prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", .okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87" },
        .{ .ikm = &ikm22, .salt = "", .info = "", .prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", .okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" },
    };
    for (backendsFor(u32)) |b| {
        test_hooks.forced = b;
        for (cases) |c| {
            const prk = H256.extract(c.salt, c.ikm);
            var want_prk: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&want_prk, c.prk);
            try testing.expectEqualSlices(u8, &want_prk, &prk);
            var okm_buf: [82]u8 = undefined;
            const okm = okm_buf[0 .. c.okm.len / 2];
            H256.expand(okm, c.info, prk);
            var want_okm: [82]u8 = undefined;
            _ = try std.fmt.hexToBytes(want_okm[0..okm.len], c.okm);
            try testing.expectEqualSlices(u8, want_okm[0..okm.len], okm);
        }
    }

    // RFC 5869 has no SHA-384 vectors: case A.1's inputs through HKDF-SHA-384,
    // against std's own HKDF-SHA-384 and against CPython's hmac (OpenSSL).
    const H384 = Hkdf(Hmac(Sha384));
    const S384 = Hkdf(Hmac(std.crypto.hash.sha2.Sha384));
    const want384_prk = unhex(48, "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade");
    const want384_okm = unhex(42, "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5");
    for (backendsFor(u64)) |b| {
        test_hooks.forced = b;
        const prk = H384.extract(&salt1, &ikm22);
        try testing.expectEqualSlices(u8, &want384_prk, &prk);
        try testing.expectEqualSlices(u8, &S384.extract(&salt1, &ikm22), &prk);
        var okm: [42]u8 = undefined;
        H384.expand(&okm, &info1, prk);
        try testing.expectEqualSlices(u8, &want384_okm, &okm);
    }
}
