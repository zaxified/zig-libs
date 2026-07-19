// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks. Off by default; opt in with `K256_BENCH`:
//!
//!   K256_BENCH=1 zig build test-k256 -Doptimize=ReleaseFast
//!
//! Prints k256 (asm field + GLV when gated on; the label says which) vs
//! `std.crypto.ecc.Secp256k1` for the field multiply/square, the constant-time
//! base-point scalar multiply, the variable-base public multiply (GLV vs the
//! portable double-and-add vs std), and ECDSA verify — plus k256's own BIP340
//! sign/verify. Target: ~2–4× libsecp256k1. Numbers are noisy on mobile CPUs
//! (turbo/thermal) — treat them as ratios, not absolutes.

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

const k256_label = if (field.field_asm_active) "k256-ASM " else "k256-PORT";

test "bench (opt-in via K256_BENCH)" {
    if (std.testing.environ.getPosix("K256_BENCH") == null) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x2B15_C0DE);
    const rand = prng.random();
    std.debug.print("\n=== k256 bench (field_asm={}, glv={}) ===\n", .{
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
        std.debug.print("{s} field mul: {d:>6} ns/op   ", .{ k256_label, dt / fmul_iters });

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
        std.debug.print("{s} field sq : {d:>6} ns/op   ", .{ k256_label, dt / fmul_iters });

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
        std.debug.print("{s} scalarmul (CT G·s, ladder): {d:>8} ns/op\n", .{ k256_label, dt / smul_iters });

        // The fixed-base comb: the fast CT base-point multiply the signing path
        // now uses (no doublings; comb_t table-gathered adds).
        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < smul_iters) : (i += 1) {
            const r = Secp256k1.combMulBase(sb, .big) catch continue;
            sink ^= r.x.limbs[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} scalarmul (CT G·s, comb)  : {d:>8} ns/op\n", .{ k256_label, dt / smul_iters });

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

    // ── variable-base PUBLIC multiply: GLV vs portable vs std ──
    {
        const p = Secp256k1.basePoint.mul(sb, .big) catch unreachable;
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
        std.debug.print("{s} mulPublic (GLV)   : {d:>8} ns/op\n", .{ k256_label, dt / smul_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < smul_iters) : (i += 1) {
            const r = p.mulPublicDoubleAdd(s2, .big) catch continue;
            sink ^= r.x.limbs[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} mulPublic (D&A)   : {d:>8} ns/op\n", .{ k256_label, dt / smul_iters });

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
        std.debug.print("{s} ecdsa verify      : {d:>8} ns/op\n", .{ k256_label, dt / sig_iters });

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

        // ── ECDSA sign (std, for the end-to-end sign story) ──
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

        // k256 BIP340 sign/verify (no direct std analog; report standalone).
        const sk = [_]u8{3} ** 32;
        const bsig = sign.bip340Sign(sk, msg, [_]u8{0} ** 32) catch return;
        const pub_xonly = (Secp256k1.basePoint.mul(sk, .big) catch return).affineCoordinates().x.toBytes(.big);
        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) {
            const s2 = sign.bip340Sign(sk, msg, [_]u8{0} ** 32) catch continue;
            sink ^= s2[0];
        }
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} bip340 sign       : {d:>8} ns/op\n", .{ k256_label, dt / sig_iters });

        sink = 0;
        t0 = nowNs();
        i = 0;
        while (i < sig_iters) : (i += 1) sink ^= @intFromBool(sign.bip340Verify(pub_xonly, msg, bsig));
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("{s} bip340 verify     : {d:>8} ns/op\n", .{ k256_label, dt / sig_iters });
    }
    std.debug.print("(reference: libsecp256k1 on comparable hw ≈ 50µs verify, ≈ 25-40µs sign)\n\n", .{});
}
