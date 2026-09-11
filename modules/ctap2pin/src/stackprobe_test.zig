// SPDX-License-Identifier: MIT

//! Audit A1 M3 instrument, moved into the module per `CONVENTIONS.md` §9 (an
//! instrument that checks ONE module belongs to that module, not to the audit
//! record). Diagnostic, not a gate: it PRINTS dead-stack hit counts rather
//! than asserting them, because the count is compiler/optimizer dependent
//! (`adaptor`'s equivalent probe measured 2 surviving copies of `d` even
//! THROUGH `bip340.sign`'s own `secureZero` calls — asserting `== 0` here
//! would be either flaky or dishonest). Read with `scripts/modtest ctap2pin
//! -Doptimize=ReleaseFast` and compare the printed counts; see `A1/ctap2pin.md`
//! M3 for the RED (before) numbers this probe originally produced.
//!
//! Adapted from `~/CML/20260901-zig-libs-audit/A1/repro/ctap2pin/zeroize.zig`
//! (same needles, same transaction shape), rewritten as a `zig test` so the
//! instrument runs under the module's own gate instead of living only in a
//! throwaway audit script.

const std = @import("std");
const c = @import("root.zig");

const platform_scalar: [32]u8 = @splat(0x47);
const auth_scalar: [32]u8 = @splat(0x4f);

const Needles = struct {
    prk: [32]u8,
    ss1: [32]u8, // protocol One's shared secret, One.kdf(Z)
    hmac_key: [32]u8, // protocol Two's shared secret, first half
    aes_key: [32]u8, // protocol Two's shared secret, second half
};

/// Recompute, out of band, everything the transaction below will hold.
fn needles() !Needles {
    const auth_pub = try c.publicKeyFromScalar(auth_scalar);
    const z = try c.ecdhZ(platform_scalar, auth_pub);
    const ss1 = c.One.kdf(z);
    const ss2 = c.Two.kdf(z);
    const salt: [32]u8 = @splat(0);
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(&salt, &z);
    return .{ .prk = prk, .ss1 = ss1, .hmac_key = ss2[0..32].*, .aes_key = ss2[32..64].* };
}

/// One complete transaction, played by the book: both protocols, and every
/// secret the module hands the caller (`Encaps.shared_secret`, per its own
/// doc comment) is `secureZero`d before return.
noinline fn transaction() !void {
    const auth_pub = try c.publicKeyFromScalar(auth_scalar);

    var e1 = try c.One.encapsulate(platform_scalar, auth_pub);
    defer std.crypto.secureZero(u8, &e1.shared_secret);
    var e2 = try c.Two.encapsulate(platform_scalar, auth_pub);
    defer std.crypto.secureZero(u8, &e2.shared_secret);

    const pin_hash: [16]u8 = @splat(0x03);
    var ct1: [16]u8 = undefined;
    try c.One.encrypt(e1.shared_secret, &ct1, &pin_hash);
    var ct2: [32]u8 = undefined;
    try c.Two.encrypt(e2.shared_secret, @splat(0x3c), &ct2, &pin_hash);

    const p1 = try c.One.authenticate(&e1.shared_secret, &ct1);
    const p2 = c.Two.authenticate(e2.shared_secret[0..32], &ct2);
    std.mem.doNotOptimizeAway(&ct1);
    std.mem.doNotOptimizeAway(&ct2);
    std.mem.doNotOptimizeAway(&p1);
    std.mem.doNotOptimizeAway(&p2);
}

const WINDOW = 96 * 1024;

/// Claim a large stack window over the frames `transaction` used and count
/// occurrences of `needle` in it. Volatile reads so the compiler cannot fold
/// the (deliberately uninitialised) buffer away.
noinline fn scanDeadStack(needle: *const [32]u8) usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: usize = 0;
    var i: usize = 0;
    const limit = WINDOW - 32;
    outer: while (i <= limit) : (i += 1) {
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (p[i + j] != needle[j]) continue :outer;
        }
        hits += 1;
    }
    std.mem.doNotOptimizeAway(&buf);
    return hits;
}

fn report(name: []const u8, needle: *const [32]u8) void {
    const h = scanDeadStack(needle);
    std.debug.print("  {s:<34} hits={d}\n", .{ name, h });
}

test "STACKPROBE (M3): secret material on the dead stack after a by-the-book transaction, ReleaseFast only" {
    if (@import("builtin").mode == .Debug) return error.SkipZigTest; // Debug's frame layout is not the claim under test

    const n = try needles();

    var control: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1234);
    prng.random().bytes(&control);

    try transaction();
    std.debug.print("STACKPROBE M3 after a by-the-book transaction, window {d} KiB:\n", .{WINDOW / 1024});
    report("prk (Two HKDF-Extract)", &n.prk);
    report("ss1 (One shared secret)", &n.ss1);
    report("hmacKey (Two)", &n.hmac_key);
    report("aesKey (Two)", &n.aes_key);
    report("CONTROL never-used random 32B", &control);
}
