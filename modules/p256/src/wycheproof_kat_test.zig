// SPDX-License-Identifier: MIT
//! ECDSA P-256 verification against Wycheproof — the adversarial fixture this
//! module claimed to pass but never ran.
//!
//! `sign.zig` carried the sentence "every RFC 6979 / Wycheproof vector that
//! passes on std passes here unchanged". That is a reasonable argument about
//! `EcdsaP256Sha256`, which is std's generic ECDSA instantiated over our
//! group — but `ecdsaVerify` is this module's OWN verifier, a separate code
//! path the argument does not reach, and no harness existed either way. A
//! prose claim is not a test.
//!
//! Wycheproof is the right fixture here precisely because it is hostile: its
//! rows are built to catch verifiers that skip range checks, mishandle the
//! point at infinity, accept `r` or `s` outside `[1, n-1]`, or take a
//! signature whose integers were re-encoded. Those are exactly the mistakes a
//! self-written positive test never finds.
//!
//! Both entry points are run against every vector, so a divergence between
//! this module's own verifier and the std-generic one shows up as a failure.

const std = @import("std");
const testing = std.testing;
const sign = @import("sign.zig");
const vectors = @import("wycheproof_kat_vectors.zig");

fn hexAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(out, hex);
}

test "Wycheproof ECDSA P-256/SHA-256: every P1363 vector gets the verdict upstream says" {
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
}

test "Wycheproof ECDSA P-256/SHA-256: std's generic ECDSA over our group agrees row for row" {
    // The claim in `sign.zig` was about this path. Now it is checked, and
    // checked against the SAME rows as our own verifier — if the two ever
    // disagree, one of these two tests fails and names the row.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for (vectors.vectors) |v| {
        const pk_bytes = try hexAlloc(a, v.pubkey_hex);
        const msg = try hexAlloc(a, v.msg_hex);
        var sig_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig_bytes, v.sig_hex);

        const ok = blk: {
            const pk = sign.EcdsaP256Sha256.PublicKey.fromSec1(pk_bytes) catch break :blk false;
            const sig = sign.EcdsaP256Sha256.Signature.fromBytes(sig_bytes);
            sig.verify(msg, pk) catch break :blk false;
            break :blk true;
        };
        testing.expectEqual(v.should_verify, ok) catch |err| {
            std.debug.print("wycheproof tcId {d} ({s}) via std-generic: expected {}, got {}\n", .{
                v.tc_id, v.comment, v.should_verify, ok,
            });
            return err;
        };
    }
}
