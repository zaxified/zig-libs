// SPDX-License-Identifier: MIT

//! A1/sealedbox.md L4, kept in the module per `CONVENTIONS.md` §9: the
//! property `wipe` exists for — that the optimiser cannot remove its zeroing —
//! is one no value test can see. `wipe: the encoded secret really is gone`
//! reads the buffer right after wiping it, which keeps even a plain `@memset`
//! alive; the audit's mutant that swapped `secureZero` for `@memset` passed
//! every test.
//!
//! This test sees it. A buffer is forced into memory by volatile writes, then
//! wiped and never read again — exactly the dead store an optimiser may
//! delete — and after the function returns a scan of the stack at that depth
//! looks for the secret. Measured at ReleaseFast: `secureZero` 0/5, plain
//! `@memset` (audit mutant M10) 5/5, a no-op (M11) 5/5.
//!
//! Method as `bip340`'s and `k256`'s probes: paint a stack window, call at
//! that depth, claim an equally large UNINITIALISED buffer there and count the
//! needle. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill
//! `undefined` with 0xaa, so the scan cannot see a dead frame there.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees the secret, must find 0) and a
//! POSITIVE control (the same buffer, not wiped, must be found).

const std = @import("std");
const builtin = @import("builtin");
const sb = @import("root.zig");

const WINDOW = 64 * 1024;

// Module-level, so the only stack copy of the secret is the one under test.
var secret: [sb.base64_sk_len]u8 = undefined;

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Count `needle` in one uninitialised window claimed at the depth the
/// previous call used. Volatile reads so the buffer cannot be folded away.
noinline fn scan(needle: []const u8) usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: usize = 0;
    var i: usize = 0;
    outer: while (i + needle.len <= WINDOW) : (i += 1) {
        for (needle, 0..) |b, j| if (p[i + j] != b) continue :outer;
        hits += 1;
    }
    std.mem.doNotOptimizeAway(&buf);
    return hits;
}

/// The volatile writes keep `text` in memory; after `wipe` nothing reads it,
/// so a zeroing the optimiser may drop leaves the secret behind.
noinline fn holdThenWipe() void {
    var text: [sb.base64_sk_len]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&text);
    for (secret, 0..) |b, i| p[i] = b;
    sb.wipe(&text);
}

/// Positive control: the same buffer, not wiped.
noinline fn holdNoWipe() void {
    var text: [sb.base64_sk_len]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&text);
    for (secret, 0..) |b, i| p[i] = b;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

test "STACKPROBE (A1 L4): wipe's zeroing survives the optimiser on a buffer nothing reads again" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    for (&secret, 0..) |*b, i| b.* = @truncate(0x41 + (i * 7) % 26);

    paint();
    callInnocent();
    const neg = scan(&secret);
    paint();
    holdNoWipe();
    const pos = scan(&secret);

    var wiped: usize = 0;
    for (0..5) |_| {
        paint();
        holdThenWipe();
        wiped += scan(&secret);
    }
    std.debug.print("\n=== STACKPROBE sealedbox L4 ({t}): NEG={d} POS(not wiped)={d} wiped={d}/5 ===\n", .{ builtin.mode, neg, pos, wiped });

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1); // the scan can see an unwiped buffer
    try std.testing.expectEqual(@as(usize, 0), wiped);
}
