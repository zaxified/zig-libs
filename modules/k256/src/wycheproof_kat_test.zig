// SPDX-License-Identifier: MIT
//! ECDSA secp256k1 verification against Wycheproof (audit G3) — this module
//! shipped NO ECDSA test vectors of its own; the sibling `p256` transcribes
//! its P-256 counterpart via `scripts/gen-p256-wycheproof.py`. Wycheproof is
//! the right fixture precisely because it is hostile: its rows are built to
//! catch verifiers that skip range checks, mishandle the point at infinity,
//! accept `r`/`s` outside `[1, n-1]`, or take a signature whose integers
//! were re-encoded — exactly the mistakes a self-written positive test
//! never finds (audit G3's own mutation battery found this gap: 7 of 15
//! mutations survived the module's own suite, and Wycheproof killed two of
//! them with an accepted forgery — tcId 116/132/245 for `r >= n` silently
//! reduced instead of rejected, tcId 133 for `s >= n`).
//!
//! Two files, two entry points: `wycheproof_kat_vectors.zig` (P1363 raw
//! `r || s`) against `sign.ecdsaVerify`, `wycheproof_bitcoin_vectors.zig`
//! (DER converted to raw `r || s` where strictly canonical) against
//! `sign.ecdsaVerifyLowS`.

const std = @import("std");
const testing = std.testing;
const sign = @import("sign.zig");
const vectors = @import("wycheproof_kat_vectors.zig");
const bitcoin_vectors = @import("wycheproof_bitcoin_vectors.zig");

fn hexAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(out, hex);
}

test "Wycheproof ECDSA secp256k1/SHA-256: every P1363 vector gets the verdict upstream says" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var accepted: usize = 0;
    var rejected: usize = 0;
    for (vectors.vectors) |v| {
        const pk = try hexAlloc(a, v.pubkey_hex);
        const msg = try hexAlloc(a, v.msg_hex);
        var sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig, v.sig_hex);

        const got = sign.ecdsaVerify(pk, msg, sig);
        testing.expectEqual(v.should_verify, got) catch |err| {
            std.debug.print("wycheproof tcId {d} ({s}): expected {}, got {}\n", .{
                v.tc_id, v.comment, v.should_verify, got,
            });
            return err;
        };
        if (got) accepted += 1 else rejected += 1;
    }
    // A verifier stuck at `false` would satisfy every invalid row; one stuck
    // at `true` would satisfy every valid row. Neither can satisfy both.
    try testing.expect(accepted > 0);
    try testing.expect(rejected > 0);
    try testing.expectEqual(@as(usize, 167), accepted);
    try testing.expectEqual(@as(usize, 67), rejected);
}

test "Wycheproof ECDSA secp256k1/SHA-256: every low-S/Bitcoin vector gets the verdict upstream says" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var accepted: usize = 0;
    var rejected: usize = 0;
    for (bitcoin_vectors.vectors) |v| {
        const pk = try hexAlloc(a, v.pubkey_hex);
        const msg = try hexAlloc(a, v.msg_hex);
        var sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig, v.sig_hex);

        const got = sign.ecdsaVerifyLowS(pk, msg, sig);
        testing.expectEqual(v.should_verify, got) catch |err| {
            std.debug.print("wycheproof (bitcoin) tcId {d} ({s}): expected {}, got {}\n", .{
                v.tc_id, v.comment, v.should_verify, got,
            });
            return err;
        };
        if (got) accepted += 1 else rejected += 1;
    }
    try testing.expect(accepted > 0);
    try testing.expect(rejected > 0);
    try testing.expectEqual(@as(usize, 109), accepted);
    try testing.expectEqual(@as(usize, 14), rejected);
}
