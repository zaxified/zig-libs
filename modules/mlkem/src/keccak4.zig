// SPDX-License-Identifier: MIT
//! Keccak-f[1600] on four independent states at once. Each of the 25 state
//! words is a `@Vector(4, u64)` whose lane i belongs to stream i, so the
//! round is plain vector xor/rotate/andn (AVX2 on x86-64). On top of it sits
//! a batched one-shot SHAKE for four equal-length short inputs (the ML-KEM
//! matrix and noise expansion, FIPS 203 §4.1).

const std = @import("std");

pub const V4 = @Vector(4, u64);
pub const State4 = [25]V4;

const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

// Rho rotation offsets and pi lane order, in the order the in-place
// rho/pi walk visits the lanes (the classic compact Keccak formulation).
const rho = [24]u6{ 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
const pi = [24]u5{ 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

inline fn rotl(x: V4, comptime n: u6) V4 {
    const S = @Vector(4, u6);
    const l: S = @splat(n);
    const r: S = @splat(@as(u6, @truncate(@as(u7, 64) - n)));
    return (x << l) | (x >> r);
}

/// Runtime-indexed lane store (vectors only allow comptime-known indices).
fn setLane(v: *V4, lane: usize, x: u64) void {
    var arr: [4]u64 = v.*;
    arr[lane] = x;
    v.* = arr;
}

/// Keccak-f[1600] (24 rounds) on four states in parallel. Not fully
/// unrolled: 24 inlined rounds are ~35 KB of code that overflows the uop
/// cache and runs decoder-bound — 2239 vs 1740–1769 TSC cycles per call
/// (i7-7920HQ, 2026-11-01); one or two rounds per iteration measured equal.
pub fn permute(s: *State4) void {
    var a = s.*;
    var r: usize = 0;
    while (r < 24) : (r += 2) {
        round(&a, round_constants[r]);
        round(&a, round_constants[r + 1]);
    }
    s.* = a;
}

inline fn round(a: *State4, rc: u64) void {
    // theta
    var bc: [5]V4 = undefined;
    inline for (0..5) |i| bc[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
    inline for (0..5) |i| {
        const t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
        inline for (0..5) |j| a[i + 5 * j] ^= t;
    }
    // rho + pi
    var t = a[1];
    inline for (0..24) |i| {
        const j = pi[i];
        const keep = a[j];
        a[j] = rotl(t, rho[i]);
        t = keep;
    }
    // chi
    inline for (0..5) |j| {
        inline for (0..5) |i| bc[i] = a[5 * j + i];
        inline for (0..5) |i| a[5 * j + i] = bc[i] ^ (~bc[(i + 1) % 5] & bc[(i + 2) % 5]);
    }
    // iota
    a[0] ^= @as(V4, @splat(rc));
}

/// Four parallel one-shot SHAKE instances with a common `rate`
/// (168 = SHAKE128, 136 = SHAKE256). Inputs must have equal length < rate.
pub fn Shake4(comptime rate: usize) type {
    comptime std.debug.assert(rate == 168 or rate == 136);
    return struct {
        const Self = @This();
        pub const block_len = rate;

        s: State4,

        /// Absorb one (padded) block per stream: SHAKE domain 0x1F, final
        /// bit 0x80 at rate-1 (FIPS 202 pad10*1). The input length is a
        /// comptime parameter, so "equal lengths, shorter than the rate" is
        /// a type error rather than a runtime check.
        pub fn init(comptime len: usize, inputs: [4]*const [len]u8) Self {
            comptime std.debug.assert(len < rate);
            var self: Self = .{ .s = @splat(@splat(0)) };
            for (inputs, 0..) |in, lane| {
                var blk: [rate]u8 = @splat(0);
                defer std.crypto.secureZero(u8, &blk);
                blk[0..len].* = in.*;
                blk[len] ^= 0x1f;
                blk[rate - 1] ^= 0x80;
                for (0..rate / 8) |w| {
                    setLane(&self.s[w], lane, std.mem.readInt(u64, blk[8 * w ..][0..8], .little));
                }
            }
            return self;
        }

        /// Next output block of each stream.
        pub fn squeezeBlocks(self: *Self, out: *[4][rate]u8) void {
            self.squeezeInto(.{ &out[0], &out[1], &out[2], &out[3] });
        }

        /// Next output block of each stream, into four separate buffers.
        /// Groups of four state words are transposed in registers (lane l
        /// of words w..w+3 → 32 contiguous bytes of stream l).
        pub fn squeezeInto(self: *Self, out: [4]*[rate]u8) void {
            permute(&self.s);
            const words = rate / 8;
            comptime var w: usize = 0;
            inline while (w + 4 <= words) : (w += 4) {
                const a = self.s[w];
                const b = self.s[w + 1];
                const c = self.s[w + 2];
                const d = self.s[w + 3];
                const t0 = @shuffle(u64, a, b, [4]i32{ 0, ~@as(i32, 0), 2, ~@as(i32, 2) });
                const t1 = @shuffle(u64, a, b, [4]i32{ 1, ~@as(i32, 1), 3, ~@as(i32, 3) });
                const t2 = @shuffle(u64, c, d, [4]i32{ 0, ~@as(i32, 0), 2, ~@as(i32, 2) });
                const t3 = @shuffle(u64, c, d, [4]i32{ 1, ~@as(i32, 1), 3, ~@as(i32, 3) });
                const l0 = @shuffle(u64, t0, t2, [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 1) });
                const l2 = @shuffle(u64, t0, t2, [4]i32{ 2, 3, ~@as(i32, 2), ~@as(i32, 3) });
                const l1 = @shuffle(u64, t1, t3, [4]i32{ 0, 1, ~@as(i32, 0), ~@as(i32, 1) });
                const l3 = @shuffle(u64, t1, t3, [4]i32{ 2, 3, ~@as(i32, 2), ~@as(i32, 3) });
                out[0][8 * w ..][0..32].* = @bitCast(l0);
                out[1][8 * w ..][0..32].* = @bitCast(l1);
                out[2][8 * w ..][0..32].* = @bitCast(l2);
                out[3][8 * w ..][0..32].* = @bitCast(l3);
            }
            inline while (w < words) : (w += 1) {
                const lanes: [4]u64 = self.s[w];
                inline for (0..4) |lane| std.mem.writeInt(u64, out[lane][8 * w ..][0..8], lanes[lane], .little);
            }
        }
    };
}

pub const Shake128x4 = Shake4(168);
pub const Shake256x4 = Shake4(136);

// ---------------------------------------------------------------- tests

const testing = std.testing;
const StdKeccak = std.crypto.core.keccak.KeccakF(1600);

test "permute equals std KeccakF(1600) on four random states" {
    var prng = std.Random.DefaultPrng.init(0x4b3c);
    const rnd = prng.random();
    var s: State4 = undefined;
    var ref: [4]StdKeccak = undefined;
    for (0..4) |lane| {
        var bytes: [200]u8 = undefined;
        rnd.bytes(&bytes);
        ref[lane] = StdKeccak.init(bytes);
        for (0..25) |w| setLane(&s[w], lane, std.mem.readInt(u64, bytes[8 * w ..][0..8], .little));
    }
    for (0..3) |_| {
        permute(&s);
        for (&ref) |*r| r.permute();
    }
    for (0..4) |lane| {
        for (0..25) |w| {
            const want = std.mem.readInt(u64, ref[lane].asBytes()[8 * w ..][0..8], .little);
            const got: [4]u64 = s[w];
            try testing.expectEqual(want, got[lane]);
        }
    }
}

fn checkShake(comptime rate: usize, comptime Std: type, comptime len: usize, rnd: std.Random) !void {
    var bufs: [4][len]u8 = undefined;
    var ins: [4]*const [len]u8 = undefined;
    for (&bufs, 0..) |*b, i| {
        rnd.bytes(b);
        ins[i] = b;
    }
    var x4 = Shake4(rate).init(len, ins);
    var refs: [4]Std = undefined;
    for (&refs, 0..) |*r, i| {
        r.* = Std.init(.{});
        r.update(ins[i]);
    }
    for (0..4) |_| {
        var out: [4][rate]u8 = undefined;
        x4.squeezeBlocks(&out);
        for (0..4) |i| {
            var want: [rate]u8 = undefined;
            refs[i].squeeze(&want);
            try testing.expectEqualSlices(u8, &want, &out[i]);
        }
    }
}

test "Shake128x4 / Shake256x4 equal std SHAKE for several lengths and blocks" {
    var prng = std.Random.DefaultPrng.init(0x5a4e);
    const rnd = prng.random();
    inline for ([_]usize{ 0, 1, 33, 34, 135, 167 }) |len| {
        if (len < 168) try checkShake(168, std.crypto.hash.sha3.Shake128, len, rnd);
        if (len < 136) try checkShake(136, std.crypto.hash.sha3.Shake256, len, rnd);
    }
}
