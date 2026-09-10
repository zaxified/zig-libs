// SPDX-License-Identifier: MIT

//! Audit A1 F3 instrument, moved into the module per `CONVENTIONS.md` §9 (an
//! instrument that checks ONE module belongs to that module, not to the audit
//! record). Diagnostic, not a gate: it PRINTS a dead-stack hit count rather
//! than asserting one, because the count is compiler/optimizer dependent (the
//! audit measured the same technique leaving 2 copies of `d` even THROUGH
//! `bip340.sign`'s own `secureZero` calls — asserting `== 0` here would be
//! either flaky or dishonest). Read with `scripts/modtest adaptor
//! -Doptimize=ReleaseFast` and compare the printed counts; see `A1/adaptor.md`
//! F3 for the RED (before) numbers this probe originally produced.

const std = @import("std");
const adaptor = @import("root.zig");
const bip340 = @import("bip340");
const k256 = @import("k256");
const Secp256k1 = k256.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;

const WINDOW = 512 * 1024;

fn reduceToScalar(b32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = b32;
    return Scalar.fromBytes48(wide, .big);
}

/// Claim a large stack window over the frames the previous call used and
/// count occurrences of `needle` in it. Volatile reads so the compiler cannot
/// fold the (deliberately uninitialised) buffer away.
noinline fn scanDeadStack(needle: *const [32]u8, window: usize) usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: usize = 0;
    var i: usize = 0;
    const limit = @min(window, WINDOW) - 32;
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

noinline fn callPreSign(sk: bip340.SecretKey, msg: []const u8, aux: [32]u8, t: adaptor.AdaptorPoint, io: std.Io) !adaptor.PreSignature {
    return adaptor.preSign(sk, msg, aux, t, io);
}

fn report(name: []const u8, needle: *const [32]u8, window: usize) void {
    const h = scanDeadStack(needle, window);
    std.debug.print("  {s:<34} hits={d}\n", .{ name, h });
}

test "STACKPROBE (F3): secret material on the dead stack after preSign, ReleaseFast only" {
    if (@import("builtin").mode == .Debug) return error.SkipZigTest; // Debug's frame layout is not the claim under test

    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    const io = th.io();

    const sk_raw = [_]u8{
        0x3f, 0x7c, 0x11, 0xa9, 0x54, 0x2d, 0xe0, 0x8b, 0x91, 0x6e, 0x44, 0x0c, 0xd7, 0x2a, 0xb3, 0x58,
        0x1d, 0x60, 0xe9, 0x77, 0x4b, 0x05, 0xc2, 0x3e, 0x88, 0xf1, 0x2c, 0x96, 0x70, 0xda, 0x51, 0x07,
    };
    const t_raw = [_]u8{
        0x6a, 0x02, 0xbe, 0x35, 0x19, 0xc8, 0x7d, 0x40, 0xe3, 0x5b, 0x72, 0x0f, 0xaa, 0x91, 0x36, 0xd4,
        0x08, 0x2f, 0x65, 0xc1, 0x9b, 0x4e, 0x83, 0x17, 0x50, 0xfc, 0x26, 0xa8, 0x3d, 0x71, 0xe6, 0x99,
    };
    const aux = [_]u8{0x5c} ** 32;
    const msg = "dead stack probe message";

    const sk = try bip340.SecretKey.fromBytes(sk_raw);
    const kp = try bip340.KeyPair.fromSecretKey(sk);
    const t_point = try adaptor.AdaptorPoint.fromSecret(t_raw);

    // Recompute preSign's own d so we know exactly what to look for (this
    // probe's own copy of `d_bytes`, NOT preSign's internal one).
    const d_bytes = kp.secret;

    var control: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1234);
    prng.random().bytes(&control);

    const ps = try callPreSign(sk, msg, aux, t_point, io);
    std.debug.print("STACKPROBE F3 after preSign (needs_negation={}), window {d} KiB:\n", .{ ps.needs_negation, WINDOW / 1024 });
    report("effective signing scalar d", &d_bytes, WINDOW);
    report("raw SecretKey bytes", &sk_raw, WINDOW);
    report("CONTROL never-used random 32B", &control, WINDOW);
}
