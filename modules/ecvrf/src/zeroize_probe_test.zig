// SPDX-License-Identifier: MIT

//! Audit A1 E4 instrument, moved into the module per `CONVENTIONS.md` §9 (an
//! instrument that checks ONE module belongs to that module, not to the audit
//! record — see `feedback_a_fix_to_an_instrument_is_not_done_until_measured`
//! and the fixer-campaign brief). Diagnostic, not a gate: it PRINTS dead-stack
//! hit counts rather than asserting them at 0, because the exact count is
//! compiler/optimizer dependent (asserting a specific number here would be
//! either flaky or dishonest). Read with `scripts/modtest ecvrf
//! -Doptimize=ReleaseFast` and compare against `A1/ecvrf.md` E4's RED
//! (before-fix) numbers.
//!
//! `paint`/`scanFor` MUST be called from the same function that scans right
//! after the call under test (`hitsAfterProve`) — two different functions get
//! two different frame layouts, and a scan of a frame the paint never touched
//! silently reads all zeros (the audit's own first attempt at this probe hit
//! exactly that trap; `sentinels_left` is the control that would catch it
//! again). `POS`/`WIPED` are controls: `POS` proves the scan CAN see a
//! deliberately-left secret on a dead frame at this depth, `WIPED` proves the
//! same secret reads 0 once explicitly zeroed through the same call path.

const std = @import("std");
const ecvrf = @import("root.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

fn hex32(s: []const u8) [32]u8 {
    var o: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&o, s) catch unreachable;
    return o;
}

const paint_words = 24 * 1024; // 192 KiB
const sentinel: u64 = 0xA5A5_5A5A_DEAD_BEEF;

var g_hits: usize = 0;
var g_sentinels: usize = 0;

noinline fn stackWindow(paint_it: bool, needle: []const u8) void {
    var buf: [paint_words]u64 = undefined;
    if (paint_it) {
        for (&buf) |*w| w.* = sentinel;
        std.mem.doNotOptimizeAway(&buf);
        return;
    }
    std.mem.doNotOptimizeAway(&buf);
    const bytes = std.mem.asBytes(&buf);
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= bytes.len) : (i += 1) {
        if (std.mem.eql(u8, bytes[i .. i + needle.len], needle)) hits += 1;
    }
    var sent: usize = 0;
    for (buf) |w| {
        if (w == sentinel) sent += 1;
    }
    g_hits = hits;
    g_sentinels = sent;
}

const nothing: []const u8 = &[_]u8{};
fn paint() void {
    stackWindow(true, nothing);
}
fn scanFor(needle: []const u8) usize {
    stackWindow(false, needle);
    return g_hits;
}

/// A secret deliberately LEFT on a dead frame -- the POS control. Must
/// recurse: a single shallow frame puts its 32 bytes above the scan window's
/// own buffer and the control reads 0 for a reason that has nothing to do
/// with the module under test (measured once by the audit; it happened).
noinline fn deepLeak(secret: *const [32]u8, depth: u32, wipe: bool) void {
    var pad: [512]u8 = undefined;
    for (secret, 0..) |b, i| {
        const vp: *volatile u8 = &pad[i];
        vp.* = b;
    }
    if (depth > 0) deepLeak(secret, depth - 1, wipe);
    if (wipe) std.crypto.secureZero(u8, &pad);
    std.mem.doNotOptimizeAway(&pad);
}

fn posControl(secret: *const [32]u8) void {
    deepLeak(secret, 8, false);
}
fn negControlWiped(secret: *const [32]u8) void {
    deepLeak(secret, 8, true);
}

fn hitsAfterProve(sk: [32]u8, alpha: []const u8, needle: []const u8) usize {
    paint();
    const pi = ecvrf.prove(sk, alpha);
    std.mem.doNotOptimizeAway(&pi);
    return scanFor(needle);
}

test "STACKPROBE (E4): x/prefix/k/k_string/sk on the dead stack after prove(), ReleaseFast only" {
    if (@import("builtin").mode == .Debug) return error.SkipZigTest; // Debug's frame layout is not the claim under test

    const sk = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const alpha = "";
    var hashed: [64]u8 = undefined;
    Sha512.hash(&sk, &hashed, .{});
    var x: [32]u8 = hashed[0..32].*;
    Edwards25519.scalar.clamp(&x);
    const prefix: [32]u8 = hashed[32..64].*;
    const h_string = ecvrf.encodeToCurve(ecvrf.publicKey(sk), alpha);
    const k_string = ecvrf.nonceGenerationString(sk, h_string);
    const k = ecvrf.nonceGeneration(sk, h_string);
    // NEG control: a public value of the same width `prove` never holds.
    var neg: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ecvrf-audit-negative-control", &neg, .{});

    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const hx = hitsAfterProve(sk, alpha, &x);
        const hp = hitsAfterProve(sk, alpha, &prefix);
        const hk = hitsAfterProve(sk, alpha, &k);
        const hks = hitsAfterProve(sk, alpha, k_string[0..32]);
        const hsk = hitsAfterProve(sk, alpha, &sk);
        const hn = hitsAfterProve(sk, alpha, &neg);
        paint();
        posControl(&x);
        const hpos = scanFor(&x);
        paint();
        negControlWiped(&x);
        const hwiped = scanFor(&x);
        paint();
        const hpaint = scanFor(&x);
        std.debug.print("  r{d}: x={d} prefix={d} k={d} k_string={d} sk={d} | NEG={d} POS={d} WIPED={d} PAINT-ONLY={d} | sentinels_left={d}/{d}\n", .{ r, hx, hp, hk, hks, hsk, hn, hpos, hwiped, hpaint, g_sentinels, paint_words });
    }
}
