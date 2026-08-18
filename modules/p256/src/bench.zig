// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks. Off by default; opt in with `P256_BENCH`:
//!
//!   P256_BENCH=1 zig build test-p256 -Doptimize=ReleaseFast
//!
//! Prints p256 (portable in this scaffold; the label says which) vs
//! `std.crypto.ecc.P256` for the field multiply/square, the constant-time
//! base-point scalar multiply (`combMulBase`), the variable-base public multiply,
//! and ECDSA sign/verify. This is the SCAFFOLD "before" baseline; the accelerated
//! numbers come once the gated `MULX/ADX` field core + comb/windowed scalarmuls
//! land. Target: ~2–3× OpenSSL nistz256 (reference on comparable hw ≈ 25µs sign /
//! ≈ 79µs verify). Numbers are noisy on mobile CPUs — treat them as ratios.

const std = @import("std");
const field = @import("field.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

const P256 = group.P256;
const Std = std.crypto.ecc.P256;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

const p256_label = if (field.field_asm_active) "p256-ASM " else "p256-PORT";

test "bench (opt-in via P256_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("P256_BENCH") == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x2B15_9256);
    const rand = prng.random();
    std.debug.print("\n=== p256 bench (field_asm={}, fast_scalarmul={}) ===\n", .{
        field.field_asm_active, @import("gate.zig").fast_scalarmul_implemented,
    });

    var ab: [32]u8 = undefined;
    var bb: [32]u8 = undefined;
    var sb: [32]u8 = undefined;
    while (true) {
        rand.bytes(&ab);
        if (field.Fe.fromBytes(ab, .big)) |_| break else |_| {}
    }
    while (true) {
        rand.bytes(&bb);
        if (field.Fe.fromBytes(bb, .big)) |_| break else |_| {}
    }
    rand.bytes(&sb);
    const ka = field.Fe.fromBytes(ab, .big) catch unreachable;
    const kb = field.Fe.fromBytes(bb, .big) catch unreachable;
    const sa = Std.Fe.fromBytes(ab, .big) catch unreachable;
    const sbf = Std.Fe.fromBytes(bb, .big) catch unreachable;

    const fmul_iters: usize = 5_000_000;
    const smul_iters: usize = 20_000;
    const sig_iters: usize = 20_000;

    // ── field multiply / square (chained so the optimizer cannot hoist) ──
    {
        var kz = ka;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < fmul_iters) : (i += 1) kz = kz.mul(kb);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(kz);
        std.debug.print("{s} field mul: {d:>6} ns/op   ", .{ p256_label, dt / fmul_iters });

        var sz = sa;
        t0 = nowNs();
        i = 0;
        while (i < fmul_iters) : (i += 1) sz = sz.mul(sbf);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sz);
        std.debug.print("std field mul: {d:>6} ns/op\n", .{dt / fmul_iters});
    }
    {
        var kz = ka;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < fmul_iters) : (i += 1) kz = kz.sq().mul(kb);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(kz);
        std.debug.print("{s} field sq : {d:>6} ns/op   ", .{ p256_label, dt / fmul_iters });

        var sz = sa;
        t0 = nowNs();
        i = 0;
        while (i < fmul_iters) : (i += 1) sz = sz.sq().mul(sbf);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sz);
        std.debug.print("std field sq : {d:>6} ns/op\n", .{dt / fmul_iters});
    }

    // ── constant-time base-point scalar multiply (k·G, the signing path) ──
    {
        var sink: u64 = 0;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < smul_iters) : (i += 1) {
            const r = P256.combMulBase(sb, .big) catch continue;
            sink ^= r.x.limbs[0];
        }
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} scalarmul (CT k·G): {d:>8} ns/op\n", .{ p256_label, dt / smul_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < smul_iters) : (i += 1) {
            const r = Std.basePoint.mul(sb, .big) catch continue;
            sink ^= r.x.toBytes(.little)[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("std       scalarmul (CT k·G): {d:>8} ns/op\n", .{dt / smul_iters});
    }

    // ── variable-base PUBLIC multiply: p256 vs std ──
    {
        const p = P256.combMulBase(sb, .big) catch unreachable;
        const sp = Std.basePoint.mul(sb, .big) catch unreachable;
        var s2: [32]u8 = undefined;
        rand.bytes(&s2);

        var sink: u64 = 0;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < smul_iters) : (i += 1) {
            const r = p.mulPublic(s2, .big) catch continue;
            sink ^= r.x.limbs[0];
        }
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} mulPublic         : {d:>8} ns/op\n", .{ p256_label, dt / smul_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < smul_iters) : (i += 1) {
            const r = sp.mulPublic(s2, .big) catch continue;
            sink ^= r.x.toBytes(.little)[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("std       mulPublic         : {d:>8} ns/op\n", .{dt / smul_iters});
    }

    // ── ECDSA verify + sign (p256 vs std) on a real std key ──
    {
        const kp = StdEcdsa.KeyPair.generateDeterministic([_]u8{7} ** 32) catch return;
        const msg = "p256 bench message";
        const sig = kp.sign(msg, null) catch return;
        const sig_rs = sig.toBytes();
        const pk_sec1 = kp.public_key.toUncompressedSec1();

        var sink: u64 = 0;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < sig_iters) : (i += 1) sink ^= @intFromBool(sign.ecdsaVerify(&pk_sec1, msg, sig_rs));
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} ecdsa verify      : {d:>8} ns/op\n", .{ p256_label, dt / sig_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) {
            sig.verify(msg, kp.public_key) catch {};
            sink ^= i;
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("std       ecdsa verify      : {d:>8} ns/op\n", .{dt / sig_iters});

        // p256 sign (caller-nonce; std sign for the comparison column).
        const sk = [_]u8{3} ** 32;
        var nonce: [32]u8 = undefined;
        rand.bytes(&nonce);
        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) {
            const s2 = sign.ecdsaSign(sk, msg, nonce) catch continue;
            sink ^= s2[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} ecdsa sign        : {d:>8} ns/op\n", .{ p256_label, dt / sig_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) {
            const s2 = kp.sign(msg, null) catch continue;
            sink ^= s2.toBytes()[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("std       ecdsa sign        : {d:>8} ns/op\n", .{dt / sig_iters});
    }
    std.debug.print("(reference: OpenSSL nistz256 on comparable hw ≈ 25µs sign, ≈ 79µs verify)\n\n", .{});
}
