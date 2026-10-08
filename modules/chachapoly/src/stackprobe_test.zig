// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the keyed entry points (review 2026-10-08;
//! found through `bolt8`'s transport), kept in the module per
//! `CONVENTIONS.md` §9. Same method as `bip340`'s `stackprobe_test.zig`:
//! paint a large stack window, run one call at that depth, then claim an
//! equally large UNINITIALISED buffer at the same depth and count 32-byte
//! needles in it. ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill
//! `undefined` with 0xaa, so the scan cannot see a dead frame there (the push
//! lane runs it in ReleaseFast: `test.sh`'s `run_rf_only`).
//!
//! The needles are the key (its bytes are also its eight little-endian state
//! words) and the AEAD's one-time Poly1305 key `r ‖ s` (the first 32 bytes of
//! keystream block 0), plus `r` clamped. Every length runs twice: as shipped
//! (short calls are std's code) and with `force_wide`, so both engines are
//! measured. Inputs and outputs are globals, so a hit is a copy left in a
//! dead frame.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const cp = @import("root.zig");

const WINDOW = 256 * 1024;
const needle_count = 3;
const needle_names = [needle_count][]const u8{ "key", "poly key r||s", "poly key r clamped || s" };

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

noinline fn scan(needles: *const [needle_count][32]u8) [needle_count]usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var hits: [needle_count]usize = @splat(0);
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        for (needles, &hits) |*nd, *h| {
            var j: usize = 0;
            while (j < 32 and p[i + j] == nd[j]) : (j += 1) {}
            if (j == 32) h.* += 1;
        }
    }
    std.mem.doNotOptimizeAway(&buf);
    return hits;
}

/// How deep the previous call dirtied the stack below the scan frame's top.
/// Printed, not asserted; sizes `root.zig`'s burns.
noinline fn dirtyDepth() usize {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    var i: usize = 0;
    while (i < WINDOW and p[i] == 0xC7) : (i += 1) {}
    std.mem.doNotOptimizeAway(&buf);
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = key;
    std.mem.doNotOptimizeAway(&local);
}

const key: [32]u8 = blk: {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(0x80 + i * 3);
    break :blk k;
};
const nonce: [12]u8 = @splat(0x24);
const ad = "probe associated data";

var msg_len: usize = 0;
var plain: [4096]u8 = @splat(0x61);
var cipher: [4096]u8 = undefined;
var back: [4096]u8 = undefined;
var tag: [16]u8 = undefined;

noinline fn callEncrypt() void {
    cp.ChaCha20Poly1305.encrypt(cipher[0..msg_len], &tag, plain[0..msg_len], ad, nonce, key);
}
noinline fn callDecrypt() void {
    cp.ChaCha20Poly1305.decrypt(back[0..msg_len], cipher[0..msg_len], tag, ad, nonce, key) catch unreachable;
}
noinline fn callXor() void {
    cp.ChaCha20.xor(cipher[0..msg_len], plain[0..msg_len], 1, key, nonce);
}
noinline fn callStream() void {
    cp.ChaCha20.stream(cipher[0..msg_len], 1, key, nonce);
}

const calls = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "AEAD encrypt", .call = callEncrypt },
    .{ .name = "AEAD decrypt", .call = callDecrypt },
    .{ .name = "ChaCha20.xor", .call = callXor },
    .{ .name = "ChaCha20.stream", .call = callStream },
};

const lengths = [_]usize{ 16, 100, 200, 1024, 4096 };

test "STACKPROBE (review 2026-10-08): no key residue on the dead stack after the AEAD and the stream cipher" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    defer cp.force_wide = false;

    var poly: [32]u8 = @splat(0);
    std.crypto.stream.chacha.ChaCha20IETF.xor(&poly, &poly, 0, key, nonce);
    var clamped = poly;
    for (clamped[0..16], [16]u8{ 0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f }) |*b, m| b.* &= m;
    const needles = [needle_count][32]u8{ key, poly, clamped };

    paint();
    callInnocent();
    const neg = scan(&needles);
    paint();
    callLeaky();
    const pos = scan(&needles);

    var bad = false;
    var report: [2][lengths.len][calls.len][needle_count]usize = @splat(@splat(@splat(@splat(0))));
    var depth: [2][lengths.len][calls.len]usize = @splat(@splat(@splat(0)));
    for (0..2) |wide| {
        cp.force_wide = wide == 1;
        for (lengths, 0..) |len, li| {
            msg_len = len;
            callEncrypt(); // decrypt needs a valid tag
            for (calls, 0..) |c, ci| {
                for (0..3) |_| {
                    paint();
                    c.call();
                    for (&report[wide][li][ci], scan(&needles)) |*t, x| t.* += x;
                }
                paint();
                c.call();
                depth[wide][li][ci] = dirtyDepth();
                for (report[wide][li][ci]) |x| bad = bad or x != 0;
            }
        }
    }
    for (neg) |x| bad = bad or x != 0;
    bad = bad or pos[0] < 1;

    // Printed only on failure: the lane treats stderr from a passing test as
    // a FAIL (scripts/lib/test-lib.sh).
    if (bad) {
        std.debug.print("\n=== STACKPROBE chachapoly ({t}) NEG={any} POS={d} ===\n", .{ builtin.mode, neg, pos[0] });
        for (0..2) |wide| for (lengths, 0..) |len, li| for (calls, 0..) |c, ci| {
            const r = report[wide][li][ci];
            std.debug.print("  {s:<5} {d:>4} B {s:<16} dirty={d:>5} B", .{ if (wide == 1) "wide" else "ship", len, c.name, depth[wide][li][ci] });
            for (needle_names, r) |n, x| {
                if (x != 0) std.debug.print("  {s}={d}", .{ n, x });
            }
            std.debug.print("\n", .{});
        };
        return error.TestUnexpectedResult;
    }
}
