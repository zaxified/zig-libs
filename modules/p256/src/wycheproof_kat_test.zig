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
const der_vectors = @import("wycheproof_der_kat_vectors.zig");

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

test "Wycheproof ECDSA P-256/SHA-256: DER vectors, decode strictly then verify" {
    // `derToRaw` and `ecdsaVerify` are checked as one pipeline because that is
    // how a caller uses them: an X.509/OCSP/CMS signature arrives as DER and a
    // verdict comes out. A decoder that quietly accepted BER would show up
    // here as an "invalid" row that verifies.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var accepted: usize = 0;
    var rejected_by_decoder: usize = 0;
    for (der_vectors.vectors) |v| {
        const pk = try hexAlloc(a, v.pubkey_hex);
        const msg = try hexAlloc(a, v.msg_hex);
        const der = try hexAlloc(a, v.sig_hex);

        const got = if (sign.derToRaw(der)) |raw| blk: {
            break :blk sign.ecdsaVerify(pk, msg, raw);
        } else blk: {
            rejected_by_decoder += 1;
            break :blk false;
        };
        testing.expectEqual(v.should_verify, got) catch |err| {
            std.debug.print("wycheproof DER tcId {d} ({s}): expected {}, got {}\n", .{
                v.tc_id, v.comment, v.should_verify, got,
            });
            return err;
        };
        if (got) accepted += 1;
    }
    try testing.expect(accepted > 0);
    // Most of this file is malformed DER, so the decoder — not the curve
    // arithmetic — has to be doing the rejecting.
    try testing.expect(rejected_by_decoder > 100);
}

test "rawToDer round-trips through derToRaw, including the sign-bit padding case" {
    // A magnitude with the high bit set needs a 0x00 prefix, and one with
    // leading zero bytes must not keep them. Both directions have to agree, or
    // a signature we emit would be one we refuse to read back.
    var raw: [64]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xDE_12_34_56);
    const rand = prng.random();

    var saw_padded: usize = 0;
    var saw_short: usize = 0;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        rand.bytes(&raw);
        // Force the interesting shapes often enough to be sure they occur.
        if (i % 3 == 0) raw[0] |= 0x80;
        if (i % 5 == 0) raw[32] = 0x00;
        var buf: [sign.der_max_len]u8 = undefined;
        const der = sign.rawToDer(raw, &buf);
        const back = sign.derToRaw(der) orelse return error.RoundTripFailed;
        try testing.expectEqualSlices(u8, &raw, &back);
        if (raw[0] & 0x80 != 0) saw_padded += 1;
        if (raw[32] == 0x00) saw_short += 1;
    }
    try testing.expect(saw_padded > 0);
    try testing.expect(saw_short > 0);
}
