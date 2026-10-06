// SPDX-License-Identifier: MIT
//! kat_test — the byte-exact KAT harness, driven from `kat_vectors.zig`
//! (generated from draft-irtf-cfrg-bbs-signatures-12's own vectors, the
//! BLS12-381-SHA-256 suite: §8.4 and Appendix D.2 — see `../SPEC.md`).
//!
//! Primitives: `keyGen`/`skToPk`, `createGenerators`, `messagesToScalars`,
//! `mockedRandomScalars`, `hashToScalar`. Cores: `sign` byte-exact and
//! `verify` on every signature case (two valid, seven invalid from D.2.1);
//! `proofGen` byte-exact under the draft's mocked RNG and `proofVerify` on
//! every proof case (§8.4.5 and D.2.2), plus tamper rejections.

const std = @import("std");
const testing = std.testing;

const ciphersuite = @import("ciphersuite.zig");
const keys = @import("keys.zig");
const bbs = @import("bbs.zig");
const kv = @import("kat_vectors.zig");

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexToArray(comptime n: usize, hex: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (hex.len != 2 * n) return error.WrongLength;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn decodeMessages(allocator: std.mem.Allocator, hex_messages: []const []const u8) ![][]const u8 {
    const out = try allocator.alloc([]const u8, hex_messages.len);
    var done: usize = 0;
    errdefer {
        for (out[0..done]) |m| allocator.free(m);
        allocator.free(out);
    }
    for (hex_messages, 0..) |h, i| {
        out[i] = try hexToBytesAlloc(allocator, h);
        done += 1;
    }
    return out;
}

fn freeMessages(allocator: std.mem.Allocator, msgs: [][]const u8) void {
    for (msgs) |m| allocator.free(m);
    allocator.free(msgs);
}

// ── primitives ─────────────────────────────────────────────────────────

test "KAT -12 §8.4.1: keyGen(key_material, key_info, key_dst) and skToPk" {
    const key_material = try hexToBytesAlloc(testing.allocator, kv.keypair.key_material);
    defer testing.allocator.free(key_material);
    const key_info = try hexToBytesAlloc(testing.allocator, kv.keypair.key_info);
    defer testing.allocator.free(key_info);
    const key_dst = try hexToBytesAlloc(testing.allocator, kv.keypair.key_dst);
    defer testing.allocator.free(key_dst);

    // The published key_dst is the default (api_id || "KEYGEN_DST_"); both
    // spellings must give the published SK.
    try testing.expectEqualStrings(ciphersuite.keygen_dst, key_dst);
    const sk = try keys.keyGen(key_material, key_info, null);
    const sk2 = try keys.keyGen(key_material, key_info, key_dst);
    const expected_sk = try hexToArray(32, kv.keypair.sk);
    try testing.expectEqualSlices(u8, &expected_sk, &sk.toBytes());
    try testing.expectEqualSlices(u8, &expected_sk, &sk2.toBytes());

    const expected_pk = try hexToArray(96, kv.keypair.pk);
    try testing.expectEqualSlices(u8, &expected_pk, &keys.skToPk(sk).toBytes());
}

test "KAT -12 §8.4.3: createGenerators(11) is Q_1 then H_1..H_10" {
    const gens = try ciphersuite.createGenerators(testing.allocator, 11);
    defer testing.allocator.free(gens);
    try testing.expectEqualSlices(u8, &(try hexToArray(48, kv.generators.q1)), &ciphersuite.G1.toBytesCompressed(gens[0]));
    for (kv.generators.msg_generators, gens[1..]) |expected_hex, got| {
        try testing.expectEqualSlices(u8, &(try hexToArray(48, expected_hex)), &ciphersuite.G1.toBytesCompressed(got));
    }
}

test "KAT -12 §8.4.2: messagesToScalars over the ten messages, under the published dst" {
    const dst = try hexToBytesAlloc(testing.allocator, kv.map_messages_to_scalar.dst);
    defer testing.allocator.free(dst);
    try testing.expectEqualStrings(ciphersuite.map_msg_dst, dst);

    const msgs = try decodeMessages(testing.allocator, &kv.messages);
    defer freeMessages(testing.allocator, msgs);
    const scalars = try ciphersuite.messagesToScalars(testing.allocator, msgs);
    defer testing.allocator.free(scalars);
    for (kv.map_messages_to_scalar.scalars, scalars) |expected_hex, got| {
        try testing.expectEqualSlices(u8, &(try hexToArray(32, expected_hex)), &got.toBytes());
    }
}

test "KAT -12 §8.4.5: mockedRandomScalars(10, SEED)" {
    const seed = try hexToBytesAlloc(testing.allocator, kv.mocked_rng.seed);
    defer testing.allocator.free(seed);
    const scalars = ciphersuite.mockedRandomScalars(kv.mocked_rng.scalars.len, seed);
    for (kv.mocked_rng.scalars, scalars) |expected_hex, got| {
        try testing.expectEqualSlices(u8, &(try hexToArray(32, expected_hex)), &got.toBytes());
    }
}

test "KAT -12 D.2.3: hashToScalar" {
    const msg = try hexToBytesAlloc(testing.allocator, kv.h2s.msg);
    defer testing.allocator.free(msg);
    const dst = try hexToBytesAlloc(testing.allocator, kv.h2s.dst);
    defer testing.allocator.free(dst);
    try testing.expectEqualStrings(ciphersuite.h2s_dst, dst);
    try testing.expectEqualSlices(u8, &(try hexToArray(32, kv.h2s.scalar)), &ciphersuite.hashToScalar(msg, dst).toBytes());
}

// ── sign / verify ──────────────────────────────────────────────────────

test "KAT -12 §8.4.4 + D.2.1: sign is byte-exact on the valid cases, verify agrees on all nine" {
    var valid_seen: usize = 0;
    var invalid_seen: usize = 0;
    for (kv.signature_cases) |case| {
        const pk = try keys.PublicKey.fromBytes(try hexToArray(96, case.pk));
        const header = try hexToBytesAlloc(testing.allocator, case.header);
        defer testing.allocator.free(header);
        const msgs = try decodeMessages(testing.allocator, case.messages);
        defer freeMessages(testing.allocator, msgs);
        const sig = try hexToArray(bbs.Signature.encoded_bytes, case.signature);

        const ok = try bbs.verify(testing.allocator, pk, sig, header, msgs);
        if (ok != case.valid) {
            std.debug.print("case {s}: verify = {}\n", .{ case.name, ok });
            return error.TestUnexpectedResult;
        }
        if (case.valid) {
            const sk = try keys.SecretKey.fromBytes(try hexToArray(32, case.sk));
            const got = try bbs.sign(testing.allocator, sk, pk, header, msgs);
            try testing.expectEqualSlices(u8, &sig, &got);
            valid_seen += 1;
        } else invalid_seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), valid_seen);
    try testing.expectEqual(@as(usize, 6), invalid_seen);
}

// ── proofGen / proofVerify ─────────────────────────────────────────────

test "KAT -12 §8.4.5 + D.2.2: proofGen byte-exact under the mocked RNG, proofVerify accepts" {
    const seed = try hexToBytesAlloc(testing.allocator, kv.mocked_rng.seed);
    defer testing.allocator.free(seed);
    for (kv.proof_cases) |case| {
        const pk = try keys.PublicKey.fromBytes(try hexToArray(96, case.pk));
        const sig = try hexToArray(bbs.Signature.encoded_bytes, case.signature);
        const header = try hexToBytesAlloc(testing.allocator, case.header);
        defer testing.allocator.free(header);
        const ph = try hexToBytesAlloc(testing.allocator, case.presentation_header);
        defer testing.allocator.free(ph);
        const msgs = try decodeMessages(testing.allocator, case.messages);
        defer freeMessages(testing.allocator, msgs);
        const expected = try hexToBytesAlloc(testing.allocator, case.proof);
        defer testing.allocator.free(expected);

        const u = msgs.len - case.disclosed_indexes.len;
        var rs_buf: [5 + 10]ciphersuite.Fr = undefined;
        const rs = rs_buf[0..bbs.randomScalarCount(u)];
        inline for (5..16) |n| {
            if (n == rs.len) @memcpy(rs, &ciphersuite.mockedRandomScalars(n, seed));
        }
        const proof = try bbs.proofGen(testing.allocator, pk, sig, header, ph, msgs, case.disclosed_indexes, rs);
        defer testing.allocator.free(proof);
        if (!std.mem.eql(u8, expected, proof)) {
            std.debug.print("case {s}: proofGen differs\n", .{case.name});
            return error.TestExpectedEqual;
        }

        const disclosed = try testing.allocator.alloc([]const u8, case.disclosed_indexes.len);
        defer testing.allocator.free(disclosed);
        for (case.disclosed_indexes, disclosed) |i, *d| d.* = msgs[i];
        try testing.expect(try bbs.proofVerify(testing.allocator, pk, expected, header, ph, disclosed, case.disclosed_indexes));

        // Tamper controls on genuine published proofs: another presentation
        // header, another header, a dropped disclosed message.
        try testing.expect(!try bbs.proofVerify(testing.allocator, pk, expected, header, "other ph", disclosed, case.disclosed_indexes));
        try testing.expect(!try bbs.proofVerify(testing.allocator, pk, expected, "other header", ph, disclosed, case.disclosed_indexes));
        if (disclosed.len > 1) {
            try testing.expect(!try bbs.proofVerify(testing.allocator, pk, expected, header, ph, disclosed[1..], case.disclosed_indexes[1..]));
        }
    }
}
