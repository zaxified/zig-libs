// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks. Off by default; opt in with `K256_BENCH`:
//!
//!   K256_BENCH=1 zig build test-k256 -Doptimize=ReleaseFast
//!
//! Prints portable-k256 vs `std.crypto.ecc.Secp256k1` (the "before") for the
//! field multiply/square, the constant-time base-point scalar multiply, and
//! ECDSA verify — plus k256's own BIP340 sign/verify. These are the SCAFFOLD
//! baseline: they show where the portable path starts. The ~2–4×-libsecp256k1
//! target is reached only after the gated `MULX/ADX` field core + GLV land
//! (`gate.field_asm_implemented` / `gate.glv_scalarmul_implemented`); the owner
//! verify + Fable phases produce the real accelerated numbers. Numbers are noisy
//! on mobile CPUs (turbo/thermal) — treat them as ratios, not absolutes.

const std = @import("std");
const field = @import("field.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

const Secp256k1 = group.Secp256k1;
const Std = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "bench (opt-in via K256_BENCH)" {
    if (std.testing.environ.getPosix("K256_BENCH") == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x2B15_C0DE);
    const rand = prng.random();
    std.debug.print("\n=== k256 SCAFFOLD baseline (portable path, field_asm={}, glv={}) ===\n", .{
        field.field_asm_active, @import("gate.zig").glv_scalarmul_implemented,
    });

    // A random field element pair + a random scalar.
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

    // ── field multiply (chained z = z·b so the optimizer cannot hoist) ──
    {
        var kz = ka;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < fmul_iters) : (i += 1) kz = kz.mul(kb);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(kz);
        std.debug.print("k256-PORT field mul: {d:>6} ns/op   ", .{dt / fmul_iters});

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
        std.debug.print("k256-PORT field sq : {d:>6} ns/op   ", .{dt / fmul_iters});

        var sz = sa;
        t0 = nowNs();
        i = 0;
        while (i < fmul_iters) : (i += 1) sz = sz.sq().mul(sbf);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sz);
        std.debug.print("std field sq : {d:>6} ns/op\n", .{dt / fmul_iters});
    }

    // ── constant-time base-point scalar multiply ──
    {
        var sink: u64 = 0;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < smul_iters) : (i += 1) {
            const r = Secp256k1.basePoint.mul(sb, .big) catch continue;
            sink ^= r.x.limbs[0];
        }
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("k256-PORT scalarmul (CT G·s): {d:>8} ns/op\n", .{dt / smul_iters});

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < smul_iters) : (i += 1) {
            const r = Std.basePoint.mul(sb, .big) catch continue;
            sink ^= r.x.toBytes(.little)[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("std       scalarmul (CT G·s): {d:>8} ns/op\n", .{dt / smul_iters});
    }

    // ── ECDSA verify (k256 vs std) on a real std signature ──
    {
        const kp = Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32) catch return;
        const msg = "k256 bench message";
        const sig = kp.sign(msg, null) catch return;
        const sig_rs = sig.toBytes();
        const pk_sec1 = kp.public_key.toUncompressedSec1();

        var sink: u64 = 0;
        var t0 = nowNs();
        var i: usize = 0;
        while (i < sig_iters) : (i += 1) sink ^= @intFromBool(sign.ecdsaVerify(&pk_sec1, msg, sig_rs));
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("k256-PORT ecdsa verify      : {d:>8} ns/op\n", .{dt / sig_iters});

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

        // k256 BIP340 sign/verify (no direct std analog; report standalone).
        const sk = [_]u8{3} ** 32;
        const bsig = sign.bip340Sign(sk, msg, [_]u8{0} ** 32) catch return;
        const pub_xonly = (Secp256k1.basePoint.mul(sk, .big) catch return).affineCoordinates().x.toBytes(.big);
        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) sink ^= @intFromBool(sign.bip340Verify(pub_xonly, msg, bsig));
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("k256-PORT bip340 verify     : {d:>8} ns/op\n", .{dt / sig_iters});
    }
    std.debug.print("(target after gated MULX/ADX field + GLV: ~2–4× libsecp256k1)\n\n", .{});
}
