// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks. Off by default; opt in with `MONTINT_BENCH`:
//!
//!   MONTINT_BENCH=1 zig build test-montint -Doptimize=ReleaseFast
//!
//! For each of 256/512/1024/2048/4096-bit it prints, on a fresh random odd
//! top-bit-set modulus: montint modmul on BOTH paths (portable `montMulCios`
//! and the amd64 asm core directly), montint modexp via `powMont` (tagged with
//! the path the small-L dispatch actually selects — see `montint.asm_min_limbs`),
//! and the `std.crypto.ff` baseline (the "before" reference the audit measured).
//! One Montgomery multiply per modmul (mont-domain operands), so the modmul row
//! is directly comparable to OpenSSL `BN_mod_mul_montgomery`; modexp is a full-
//! width constant-time exponent, comparable to `BN_mod_exp_mont_consttime`. The
//! OpenSSL column of the SPEC table is produced by a separate libcrypto driver
//! on the same host (SPEC "Benchmarks"). Numbers are noisy on mobile CPUs
//! (turbo/thermal); treat them as ratios, not absolutes.
const std = @import("std");
const builtin = @import("builtin");
const montint = @import("montint.zig");
const asm_core = @import("asm_core.zig");
const ff = std.crypto.ff;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn benchSize(comptime bits: comptime_int, rand: std.Random) void {
    const M = montint.Modint(bits);
    // random odd modulus, top bit set (full-width work).
    var mv: M.Elem = undefined;
    for (&mv) |*w| w.* = rand.int(u64);
    mv[0] |= 1;
    mv[M.L - 1] |= 1 << 63;
    const m = M.fromElem(mv) catch return;

    var a: M.Elem = undefined;
    var b: M.Elem = undefined;
    var e: M.Elem = undefined;
    for (&a) |*w| w.* = rand.int(u64);
    for (&b) |*w| w.* = rand.int(u64);
    for (&e) |*w| w.* = rand.int(u64);
    // m has bit63 of its top limb set, so clearing bit63 of a/b's top limb
    // guarantees a,b < m (valid residues) without a full compare.
    a[M.L - 1] &= (1 << 63) - 1;
    b[M.L - 1] &= (1 << 63) - 1;
    e[M.L - 1] &= (1 << 63) - 1; // keep e < m so ff.Fe.fromBytes accepts it

    const am = m.toMontgomery(&a);
    const bm = m.toMontgomery(&b);

    const mul_iters: usize = if (bits >= 4096) 500_000 else 1_500_000;
    const exp_iters: usize = if (bits >= 4096) 60 else (if (bits >= 2048) 200 else 3000);
    const ff_exp_iters: usize = if (bits >= 4096) 20 else (if (bits >= 2048) 60 else 800);

    // ── montint modmul: portable (montMulCios) ──
    {
        var sink: u64 = 0;
        var z = am;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < mul_iters) : (i += 1) {
            z = m.montMulCios(&z, &bm);
            sink ^= z[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-PORT modmul {d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / mul_iters });
    }
    // ── montint modsqr: portable dedicated square (montSqrCios) ──
    {
        var sink: u64 = 0;
        var z = am;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < mul_iters) : (i += 1) {
            z = m.montSqrCios(&z);
            sink ^= z[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-PORT modsqr {d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / mul_iters });
    }
    // ── montint modmul: asm ──
    if (asm_core.supported) {
        var sink: u64 = 0;
        var z = am;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < mul_iters) : (i += 1) {
            asm_core.montMul(&z, &z, &bm, &m.m, m.n0inv);
            sink ^= z[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-ASM  modmul {d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / mul_iters });
    }
    // ── montint sqr-via-mul: asm montMul(a,a) (what the square replaced) ──
    if (asm_core.supported) {
        var sink: u64 = 0;
        var z = am;
        var t: M.Elem = undefined;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < mul_iters / 2) : (i += 1) {
            asm_core.montMul(&t, &z, &z, &m.m, m.n0inv);
            asm_core.montMul(&z, &t, &t, &m.m, m.n0inv);
            sink ^= z[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-ASM  sqr/mul{d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / (2 * (mul_iters / 2)) });
    }
    // ── montint modsqr: asm dedicated square ──
    if (asm_core.supported) {
        var sink: u64 = 0;
        var z = am;
        var t: M.Elem = undefined;
        var scratch: [2 * M.L]u64 = undefined;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < mul_iters / 2) : (i += 1) {
            asm_core.montSqr(&t, &z, &m.m, m.n0inv, &scratch);
            asm_core.montSqr(&z, &t, &m.m, m.n0inv, &scratch);
            sink ^= z[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-ASM  modsqr {d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / (2 * (mul_iters / 2)) });
    }
    // ── montint modexp: powMont (dispatch-dependent; tag) ──
    {
        var sink: u64 = 0;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < exp_iters) : (i += 1) {
            const r = m.powMont(&a, &e);
            sink ^= r[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint-{s} modexp {d:>5}-bit: {d:>10} ns/op\n", .{
            if (M.dispatchesToAsm()) "ASM " else "PORT", bits, dt / exp_iters,
        });
    }

    // ── std.crypto.ff baseline (same bit width) ──
    {
        const Mod = ff.Modulus(bits);
        var mbytes: [M.encoded_bytes]u8 = undefined;
        m.toBytesBE(&m.m, &mbytes);
        const mf = Mod.fromBytes(&mbytes, .big) catch return;
        var abytes: [M.encoded_bytes]u8 = undefined;
        var ebytes: [M.encoded_bytes]u8 = undefined;
        m.toBytesBE(&a, &abytes);
        m.toBytesBE(&e, &ebytes);
        const xf = Mod.Fe.fromBytes(mf, &abytes, .big) catch return;
        const yf = Mod.Fe.fromBytes(mf, &abytes, .big) catch return;
        const ef = Mod.Fe.fromBytes(mf, &ebytes, .big) catch return;
        {
            var sink: u64 = 0;
            var z = xf;
            const t0 = nowNs();
            var i: usize = 0;
            while (i < mul_iters) : (i += 1) {
                z = mf.mul(z, yf);
                sink ^= @intFromBool(z.eql(yf));
            }
            const dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(sink);
            std.debug.print("ff           modmul {d:>5}-bit: {d:>8} ns/op\n", .{ bits, dt / mul_iters });
        }
        {
            var sink: u64 = 0;
            const t0 = nowNs();
            var i: usize = 0;
            while (i < ff_exp_iters) : (i += 1) {
                const r = mf.pow(xf, ef) catch break;
                sink ^= @intFromBool(r.eql(yf));
            }
            const dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(sink);
            std.debug.print("ff           modexp {d:>5}-bit: {d:>10} ns/op\n", .{ bits, dt / ff_exp_iters });
        }
    }
    std.debug.print("\n", .{});
}

test "bench (opt-in via MONTINT_BENCH)" {
    if (std.testing.environ.getPosix("MONTINT_BENCH") == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0xB0FFED_BEEF);
    const rand = prng.random();
    std.debug.print("\n=== montint full-table bench (asm_active={}) ===\n", .{montint.asm_active});
    benchSize(256, rand);
    benchSize(512, rand);
    benchSize(1024, rand);
    benchSize(2048, rand);
    benchSize(4096, rand);
}
