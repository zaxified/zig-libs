// SPDX-License-Identifier: MIT

//! Audit A1 H4 instrument, moved into the module per `CONVENTIONS.md` §9 (an
//! instrument that checks ONE module belongs to that module, not to the
//! audit record — the original lived at
//! `~/CML/20260901-zig-libs-audit/A1/repro/hqc/zeroize.zig`). Diagnostic,
//! not a gate: it PRINTS dead-stack hit counts rather than asserting them,
//! same posture as `adaptor/src/stackprobe_test.zig`'s F3 probe —
//! `std.crypto.secureZero` defeats dead-store elimination but does not
//! promise no OTHER copy (a spilled register, a returned-by-value struct's
//! caller-side copy) survives elsewhere on the stack, so an `== 0` assert
//! would be compiler/optimizer-version-dependent, i.e. flaky or dishonest.
//!
//! Off by default; opt in with `HQC_ZEROIZE_SCAN`, same shape as
//! `bench.zig`'s `HQC_BENCH`:
//!
//!   HQC_ZEROIZE_SCAN=1 scripts/lib/capped zig build test-hqc -Doptimize=ReleaseFast
//!
//! Read the printed counts against `A1/hqc.md` H4's RED (before
//! `secureZero`, 2026-09-05) numbers: `seed_dk` x1, `sigma` x2, `m'` x5,
//! `K'` x1, `y` (first 64 B) x7. The `CONTROL` row is never written
//! anywhere and exists to calibrate: any nonzero hit count on it means the
//! scan technique itself is producing false positives on this compiler/
//! host, and the other rows should be read as noise until that's zero.

const std = @import("std");
const hqc = @import("root.zig");

const Kem = hqc.Hqc128;
const params = hqc.params;
const P = params.hqc128;
const Ring = hqc.gf2x.Ring(P.n);

const WINDOW = 1 << 20; // 1 MiB — same window the original audit probe used

var g_seed: [32]u8 = undefined;
var g_kp: Kem.KeyPair = undefined;
var g_ct: Kem.Ciphertext = undefined;
var g_ss: Kem.SharedSecret = undefined;

noinline fn doDecaps() void {
    g_ss = Kem.decaps(g_kp.dk, g_ct);
    std.mem.doNotOptimizeAway(&g_ss);
}

/// Claim a large stack window overlapping the frame `doDecaps` used (called
/// immediately before this, so the allocator is likely to hand back the
/// same physical stack memory) and count occurrences of each needle in it.
/// Volatile reads so the compiler cannot fold the deliberately-uninitialised
/// buffer away.
noinline fn scan(needles: []const []const u8, names: []const []const u8) void {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    std.debug.print("ZEROIZE PROBE (H4) after decaps, window {d} KiB:\n", .{WINDOW / 1024});
    for (needles, names) |nd, nm| {
        var hits: usize = 0;
        var i: usize = 0;
        outer: while (i + nd.len <= buf.len) : (i += 1) {
            for (nd, 0..) |b, j| {
                if (p[i + j] != b) continue :outer;
            }
            hits += 1;
        }
        std.debug.print("  {s:<32} len={d:<5} occurrences on the dead stack: {d}\n", .{ nm, nd.len, hits });
    }
    std.mem.doNotOptimizeAway(&buf);
}

test "ZEROIZE PROBE (H4, opt-in via HQC_ZEROIZE_SCAN): secrets on decaps's dead stack" {
    if (@import("builtin").mode == .Debug) return error.SkipZigTest; // Debug's frame layout is not the claim under test
    if (std.testing.environ.getPosix("HQC_ZEROIZE_SCAN") == null) return error.SkipZigTest;

    var rng = std.Random.DefaultPrng.init(0xDEAD10CC);
    rng.random().bytes(&g_seed);
    g_kp = Kem.keypair(&g_seed);
    var coins: [Kem.coins_bytes]u8 = undefined;
    rng.random().bytes(&coins);
    const enc = Kem.encaps(g_kp.ek, &coins);
    g_ct = enc.ct;

    // Independently recompute the secrets `decaps` handles internally --
    // NOT read back out of `decaps` itself, which is exactly the thing
    // under test -- so the needles exist whether or not the fix works.
    const seed_dk: [32]u8 = g_kp.dk[Kem.ek_bytes..][0..32].*;
    const sigma: [Kem.security_bytes]u8 = g_kp.dk[Kem.ek_bytes + 32 ..][0..Kem.security_bytes].*;
    var dk_xof = hqc.prng.Xof.init(&seed_dk);
    var y_support: [P.omega]u32 = undefined;
    hqc.prng.sampleFixedWeightRejection(&dk_xof, P.n, P.nMu(), P.rejectionThreshold(), P.omega, &y_support);
    var y = Ring.zero;
    hqc.prng.writeSupportToVector(P.omega, &y_support, &y);
    var y_bytes: [Ring.n_bytes]u8 = undefined;
    Ring.toBytes(y, &y_bytes);
    const m_prime: [Kem.security_bytes]u8 = coins[0..Kem.security_bytes].*;
    const k_prime: Kem.SharedSecret = enc.ss;

    var control: [32]u8 = undefined;
    rng.random().bytes(&control);

    doDecaps();

    // `y` is a sparse fixed-weight vector (only `P.omega` bits set out of
    // `P.n`), so a short prefix of its packed bytes is mostly zero and a
    // "does this all-zero-ish needle occur" scan is dominated by
    // coincidental zero runs elsewhere on the stack -- worse, it gets
    // NOISIER the more `secureZero` calls this fix adds, since those also
    // leave zero-filled regions behind. Use the FULL packed vector as the
    // needle instead: the exact byte string (zero runs AND the handful of
    // set bits, in their exact positions) is astronomically unlikely to
    // recur by chance, so a hit is real evidence of a lingering copy.
    scan(
        &.{ seed_dk[0..], sigma[0..], m_prime[0..], k_prime[0..], y_bytes[0..], control[0..] },
        &.{ "seed_dk (dk_pke)", "sigma (implicit-reject key)", "m' (FO plaintext)", "K' (the shared secret)", "y packed (full n_bytes)", "CONTROL never-written random 32B" },
    );
}
