// SPDX-License-Identifier: MIT

//! Audit A1 F2 instrument, in the module per `CONVENTIONS.md` §9 (an
//! instrument that checks ONE module belongs to that module, not to the
//! audit record — see also `~/CML/20260901-zig-libs-audit/A1/bip340.md` F2
//! and its sibling `modules/adaptor/src/stackprobe_test.zig` F3, same
//! technique against a caller of this module's `sign`).
//!
//! Diagnostic, not a hard gate: it PRINTS dead-stack hit counts rather than
//! asserting `== 0`, because the count is compiler/optimizer dependent (the
//! sibling `adaptor` probe measured 2 copies of `d` surviving even THROUGH
//! `bip340.sign`'s own `secureZero` calls — asserting an exact count here
//! would be either flaky across compiler versions or simply dishonest about
//! what a stack scan can promise). Read with `scripts/modtest bip340
//! -Doptimize=ReleaseFast` and compare the printed counts against the
//! RED baseline recorded in `A1/bip340.md`'s F2 disposition. Debug and
//! ReleaseSafe fill `undefined` with `0xAA` and are skipped — a "0 hits"
//! there would prove nothing (see F2's own "meze měření" note).

const std = @import("std");
const bip340 = @import("root.zig");

const WINDOW = 256 * 1024;

/// Overwrite the stack region below us so nothing this probe's OWN
/// recomputation (`kp`, `d_bytes`, ...) left behind can be mistaken for
/// `sign`'s residue.
noinline fn wipeStack() void {
    var scratch: [WINDOW + 16 * 1024]u8 align(16) = undefined;
    @memset(&scratch, 0x5A);
    std.mem.doNotOptimizeAway(&scratch);
}

/// Claim a stack window over the frames the previous call used and count
/// occurrences of `needle` in it. Volatile reads so the compiler cannot fold
/// the (deliberately uninitialised) buffer away.
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

noinline fn callSign(sk: bip340.SecretKey, msg: []const u8, aux: [32]u8, io: std.Io) ![64]u8 {
    return bip340.sign(sk, msg, aux, io);
}

fn report(name: []const u8, needle: *const [32]u8, window: usize) usize {
    const h = scanDeadStack(needle, window);
    std.debug.print("  {s:<34} hits={d}\n", .{ name, h });
    return h;
}

test "STACKPROBE (F2): effective signing scalar d on the dead stack after sign(), ReleaseFast only" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest; // Debug/ReleaseSafe fill undefined with 0xAA -- the scan would be meaningless

    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    const io = th.io();

    // Audit-local key material -- not from any wallet, not any BIP340 vector.
    const sk_raw = [_]u8{
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    };
    const aux = [_]u8{0x5e} ** 32;
    const msg = "bip340 F2 dead-stack probe message";

    const sk = try bip340.SecretKey.fromBytes(sk_raw);
    const kp = try bip340.KeyPair.fromSecretKey(sk);

    // The value `sign` computes as its effective signing scalar -- recomputed
    // here (this probe's own copy, not `sign`'s internal one) so we know
    // exactly what to look for.
    const d_bytes = kp.secret;

    var control: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xF2);
    prng.random().bytes(&control);

    // Erase this probe's own recomputation residue BEFORE calling sign, so a
    // hit below can only have come from sign()'s own dead frame.
    wipeStack();
    const sig = try callSign(sk, msg, aux, io);
    const rx: [32]u8 = sig[0..32].*;

    std.debug.print("STACKPROBE F2 after sign(), window {d} KiB:\n", .{WINDOW / 1024});
    const d_hits = report("d (effective signing scalar) SECRET", &d_bytes, WINDOW);
    _ = report("sk (raw secret key)          SECRET", &sk_raw, WINDOW);
    _ = report("CONTROL never-used random 32B public", &control, WINDOW);
    _ = report("rx = sig[0:32]                public", &rx, WINDOW);

    // `d_hits` is the number this probe's disposition compares RED (before
    // the F2 fix) against GREEN (after it). Left as a print, not an
    // assertion -- see the module doc comment above for why.
    _ = d_hits;
}
