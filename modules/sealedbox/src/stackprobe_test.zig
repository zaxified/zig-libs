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
    // Printed only when an assertion below fails: the lane treats stderr from
    // a passing test as a FAIL (scripts/lib/test-lib.sh).
    errdefer std.debug.print("\n=== STACKPROBE sealedbox L4 ({t}): NEG={d} POS(not wiped)={d} wiped={d}/5 ===\n", .{ builtin.mode, neg, pos, wiped });

    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1); // the scan can see an unwiped buffer
    try std.testing.expectEqual(@as(usize, 0), wiped);
}

// ── the secret-key codecs `wipe`'s doc comment tells callers to wipe after ──
//
// Wiping the caller's buffer only helps if the codec left no copy of its own
// (audit A1 L8). In value-in/value-out form, with the result wiped at once,
// `encodeSecretKeyBase64` left the raw key twice and the base64 text once per
// call (ReleaseFast), and the two parsers left the decoded key once (base64)
// and three times (hex) per call in this full test binary — though not in a
// stand-alone or a filtered one, because it depended on inlining. They now
// write into caller buffers from `noinline` codecs whose stack is zeroed.
// `encodeSecretKeyHex` and `keyPairFromSecretKey` measured clean. This checks
// all of them, each result wiped the moment it is available.

var codec_sk: [sb.secret_length]u8 = undefined;
var codec_b64: [sb.base64_sk_len]u8 = undefined;
var codec_hex: [sb.hex_sk_len]u8 = undefined;

noinline fn encodeB64AndWipe() void {
    var text: [sb.base64_sk_len]u8 = undefined;
    sb.encodeSecretKeyBase64(&text, &codec_sk);
    sb.wipe(&text);
}

noinline fn encodeHexAndWipe() void {
    var text = sb.encodeSecretKeyHex(codec_sk);
    sb.wipe(&text);
}

noinline fn parseB64AndWipe() void {
    var key: [sb.secret_length]u8 = undefined;
    sb.parseSecretKeyBase64(&key, &codec_b64) catch unreachable;
    sb.wipe(&key);
}

noinline fn parseHexAndWipe() void {
    var key: [sb.secret_length]u8 = undefined;
    sb.parseSecretKeyHex(&key, &codec_hex) catch unreachable;
    sb.wipe(&key);
}

noinline fn keyPairAndWipe() void {
    var kp = sb.keyPairFromSecretKey(codec_sk) catch unreachable;
    sb.wipe(&kp.secret_key);
}

/// Positive control for this test: parks the raw key in a local and returns.
noinline fn parkKey() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = codec_sk;
    std.mem.doNotOptimizeAway(&local);
}

test "STACKPROBE (A1 L4): the secret-key codecs leave neither the text nor the key on the dead stack" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    for (&codec_sk, 0..) |*b, i| b.* = @truncate(i * 13 + 5);
    sb.encodeSecretKeyBase64(&codec_b64, &codec_sk);
    codec_hex = sb.encodeSecretKeyHex(codec_sk);

    paint();
    callInnocent();
    const neg = scan(&codec_sk) + scan(&codec_b64) + scan(&codec_hex);
    paint();
    parkKey();
    const pos = scan(&codec_sk);
    // Printed only when an assertion fails, as in the test above.
    errdefer std.debug.print("\n=== STACKPROBE sealedbox L4 codecs ({t}): NEG={d} POS(key parked)={d} ===\n", .{ builtin.mode, neg, pos });
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);

    const calls = [_]struct { name: []const u8, f: *const fn () void }{
        .{ .name = "encodeSecretKeyBase64", .f = encodeB64AndWipe },
        .{ .name = "encodeSecretKeyHex", .f = encodeHexAndWipe },
        .{ .name = "parseSecretKeyBase64", .f = parseB64AndWipe },
        .{ .name = "parseSecretKeyHex", .f = parseHexAndWipe },
        .{ .name = "keyPairFromSecretKey", .f = keyPairAndWipe },
    };
    var total: usize = 0;
    var per_call: [calls.len][3]usize = undefined;
    for (calls, &per_call) |call, *row| {
        var key: usize = 0;
        var b64: usize = 0;
        var hex: usize = 0;
        for (0..5) |_| {
            paint();
            call.f();
            key += scan(&codec_sk);
            paint();
            call.f();
            b64 += scan(&codec_b64);
            paint();
            call.f();
            hex += scan(&codec_hex);
        }
        row.* = .{ key, b64, hex };
        total += key + b64 + hex;
    }
    errdefer {
        for (calls, per_call) |call, row| {
            std.debug.print("  {s:<24} key={d}/5 base64 text={d}/5 hex text={d}/5\n", .{ call.name, row[0], row[1], row[2] });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), total);
}
