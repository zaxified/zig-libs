// SPDX-License-Identifier: MIT
//! mls.kat_test — official RFC 9420 interop test vectors, embedded
//! verbatim from `mlswg/mls-implementations` (`test-vectors/tree-math.json`
//! / `test-vectors/crypto-basics.json`) and driven end-to-end against
//! `treemath.zig`/`crypto.zig`. See `NOTICE` for the exact source commit
//! and fetch date, and `SPEC.md` for how each vector maps to a function
//! under test.
//!
//! Parsed as generic `std.json.Value` (not typed structs) — the vector
//! files mix fixed-shape objects (`ref_hash`, `derive_secret`, ...) with
//! `null`-or-integer array elements (`tree-math.json`'s `left`/`right`/
//! `parent`/`sibling`), which a single `std.json` struct schema can't
//! cleanly express without per-field custom parsing; `Value` navigation
//! keeps this file a direct transcription of "what the JSON says" rather
//! than a schema fight.

const std = @import("std");
const hpke = @import("hpke");
const treemath = @import("treemath.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");

const tree_math_json = @embedFile("data/tree-math.json");
const crypto_basics_json = @embedFile("data/crypto-basics.json");

const testing = std.testing;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn asI64(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        else => unreachable,
    };
}

/// Compares a `tree-math.json` array element (`null` or a JSON integer)
/// against a `treemath.zig` function's `?usize` result.
fn expectMaybeIndex(want: std.json.Value, got: ?usize) !void {
    switch (want) {
        .null => try testing.expectEqual(@as(?usize, null), got),
        .integer => |i| try testing.expectEqual(@as(?usize, @intCast(i)), got),
        else => unreachable,
    }
}

test "tree-math.json: root/left/right/parent/sibling for every n_leaves x every node index, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, tree_math_json, .{});
    defer parsed.deinit();

    var checked_cases: usize = 0;
    for (parsed.value.array.items) |entry| {
        const n_leaves: usize = @intCast(asI64(entry.object.get("n_leaves").?));
        const n_nodes: usize = @intCast(asI64(entry.object.get("n_nodes").?));
        try testing.expectEqual(n_nodes, treemath.node_width(n_leaves));
        try testing.expectEqual(@as(usize, @intCast(asI64(entry.object.get("root").?))), treemath.root(n_leaves));

        const left_arr = entry.object.get("left").?.array.items;
        const right_arr = entry.object.get("right").?.array.items;
        const parent_arr = entry.object.get("parent").?.array.items;
        const sibling_arr = entry.object.get("sibling").?.array.items;
        try testing.expectEqual(n_nodes, left_arr.len);
        try testing.expectEqual(n_nodes, right_arr.len);
        try testing.expectEqual(n_nodes, parent_arr.len);
        try testing.expectEqual(n_nodes, sibling_arr.len);

        var x: usize = 0;
        while (x < n_nodes) : (x += 1) {
            try expectMaybeIndex(left_arr[x], treemath.left(x));
            try expectMaybeIndex(right_arr[x], treemath.right(x));
            try expectMaybeIndex(parent_arr[x], treemath.parent(x, n_leaves));
            try expectMaybeIndex(sibling_arr[x], treemath.sibling(x, n_leaves));
            checked_cases += 1;
        }
    }
    // Sanity: this vector set covers real ground (n_leaves in
    // {1,2,4,...,512}; sum of node_width = 2036 nodes, x4 functions each).
    try testing.expect(checked_cases >= 2000);
}

test "crypto-basics.json: cipher suite 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519), byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, crypto_basics_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();

    const S = suite.default;
    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    for (parsed.value.array.items) |entry| {
        const cs = asI64(entry.object.get("cipher_suite").?);
        if (cs != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue; // this Part only wires suite 0x0001 — see suite.zig
        }
        found_suite_1 = true;

        // ── ref_hash (RFC 9420 §5.2) ──
        {
            const rh = entry.object.get("ref_hash").?.object;
            const label = rh.get("label").?.string;
            const value = try hexDecode(arena, rh.get("value").?.string);
            const want = try hexDecode(arena, rh.get("out").?.string);
            const got = try crypto.RefHash(S, label, value);
            try testing.expectEqualSlices(u8, want, &got);
        }

        // ── derive_secret (RFC 9420 §8) ──
        {
            const ds = entry.object.get("derive_secret").?.object;
            const label = ds.get("label").?.string;
            const secret_bytes = try hexDecode(arena, ds.get("secret").?.string);
            const want = try hexDecode(arena, ds.get("out").?.string);
            var secret: [S.Nh]u8 = undefined;
            @memcpy(&secret, secret_bytes[0..S.Nh]);
            const got = try crypto.DeriveSecret(S, secret, label);
            try testing.expectEqualSlices(u8, want, &got);
        }

        // ── derive_tree_secret (RFC 9420 §9.1) ──
        {
            const dts = entry.object.get("derive_tree_secret").?.object;
            const label = dts.get("label").?.string;
            const generation: u32 = @intCast(asI64(dts.get("generation").?));
            const length: usize = @intCast(asI64(dts.get("length").?));
            const secret_bytes = try hexDecode(arena, dts.get("secret").?.string);
            const want = try hexDecode(arena, dts.get("out").?.string);
            var secret: [S.Nh]u8 = undefined;
            @memcpy(&secret, secret_bytes[0..S.Nh]);
            const got = try arena.alloc(u8, length);
            try crypto.DeriveTreeSecret(S, secret, label, generation, got);
            try testing.expectEqualSlices(u8, want, got);
        }

        // ── expand_with_label (RFC 9420 §8) ──
        {
            const ew = entry.object.get("expand_with_label").?.object;
            const label = ew.get("label").?.string;
            const context = try hexDecode(arena, ew.get("context").?.string);
            const length: usize = @intCast(asI64(ew.get("length").?));
            const secret_bytes = try hexDecode(arena, ew.get("secret").?.string);
            const want = try hexDecode(arena, ew.get("out").?.string);
            var secret: [S.Nh]u8 = undefined;
            @memcpy(&secret, secret_bytes[0..S.Nh]);
            const got = try arena.alloc(u8, length);
            try crypto.ExpandWithLabel(S, secret, label, context, got);
            try testing.expectEqualSlices(u8, want, got);
        }

        // ── sign_with_label / VerifyWithLabel (RFC 9420 §5.1.2) ──
        {
            const sw = entry.object.get("sign_with_label").?.object;
            const label = sw.get("label").?.string;
            const content = try hexDecode(arena, sw.get("content").?.string);
            const priv_bytes = try hexDecode(arena, sw.get("priv").?.string);
            const pub_bytes = try hexDecode(arena, sw.get("pub").?.string);
            const want_sig = try hexDecode(arena, sw.get("signature").?.string);

            var seed: [32]u8 = undefined;
            @memcpy(&seed, priv_bytes[0..32]);
            const kp = try S.Sig.KeyPair.generateDeterministic(seed);
            var want_pub: [32]u8 = undefined;
            @memcpy(&want_pub, pub_bytes[0..32]);
            try testing.expectEqualSlices(u8, &want_pub, &kp.public_key.toBytes());

            // Ed25519 is DETERMINISTIC (RFC 8032, no hedging/`noise`
            // passed) — re-signing must reproduce the vector's signature
            // byte-exact, a strictly stronger check than "the published
            // signature merely verifies" (which is all a randomized
            // scheme like ECDSA could offer).
            const sig = try crypto.SignWithLabel(S, kp, label, content);
            try testing.expectEqualSlices(u8, want_sig, &sig.toBytes());

            // And the published signature independently verifies too.
            var sig_bytes: [64]u8 = undefined;
            @memcpy(&sig_bytes, want_sig[0..64]);
            const parsed_sig = S.Sig.Signature.fromBytes(sig_bytes);
            const pub_key = try S.Sig.PublicKey.fromBytes(want_pub);
            try crypto.VerifyWithLabel(S, pub_key, label, content, parsed_sig);
        }

        // ── encrypt_with_label / DecryptWithLabel (RFC 9420 §5.1.3) ──
        {
            const ew = entry.object.get("encrypt_with_label").?.object;
            const label = ew.get("label").?.string;
            const context = try hexDecode(arena, ew.get("context").?.string);
            const priv_bytes = try hexDecode(arena, ew.get("priv").?.string);
            const pub_bytes = try hexDecode(arena, ew.get("pub").?.string);
            const kem_output = try hexDecode(arena, ew.get("kem_output").?.string);
            const ciphertext = try hexDecode(arena, ew.get("ciphertext").?.string);
            const want_plaintext = try hexDecode(arena, ew.get("plaintext").?.string);

            var skR: hpke.X25519Kem.KeyPair = undefined;
            @memcpy(&skR.secret_key, priv_bytes[0..32]);
            @memcpy(&skR.public_key, pub_bytes[0..32]);
            var enc: hpke.X25519Kem.EncappedKey = undefined;
            @memcpy(&enc, kem_output[0..32]);

            // HPKE seal is RANDOMIZED, but the vector already gives us a
            // fixed `kem_output`/`ciphertext` pair: decrypt it and check
            // the plaintext matches byte-exact (the task's required
            // check for a randomized primitive).
            const plaintext_out = try arena.alloc(u8, want_plaintext.len);
            try crypto.DecryptWithLabel(S, enc, skR, label, context, ciphertext, plaintext_out);
            try testing.expectEqualSlices(u8, want_plaintext, plaintext_out);

            // Then round-trip OUR OWN EncryptWithLabel/DecryptWithLabel —
            // exercises the real non-deterministic entry point the fixed
            // vector above can't (a fresh ephemeral key every call).
            const our_ct = try arena.alloc(u8, want_plaintext.len + S.Aead.tag_length);
            const our_enc = try crypto.EncryptWithLabel(S, skR.public_key, io, label, context, want_plaintext, our_ct);
            const roundtrip_out = try arena.alloc(u8, want_plaintext.len);
            try crypto.DecryptWithLabel(S, our_enc, skR, label, context, our_ct, roundtrip_out);
            try testing.expectEqualSlices(u8, want_plaintext, roundtrip_out);
        }
    }

    try testing.expect(found_suite_1);
    // Suites 0x0002-0x0007 are present in the file and intentionally
    // skipped — this Part only wires the mandatory suite (see
    // suite.zig's module doc comment + SPEC.md's arc breakdown).
    try testing.expectEqual(@as(usize, 6), skipped_other_suites);
}
