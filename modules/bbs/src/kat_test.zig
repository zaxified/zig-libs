// SPDX-License-Identifier: MIT
//! kat_test — the byte-exact KAT harness, driven from `kat_vectors.zig`
//! (generated from draft-irtf-cfrg-bbs-signatures-12's own vectors for
//! BOTH ciphersuites: BLS12-381-SHA-256 §8.4 + Appendix D.2 and
//! BLS12-381-SHAKE-256 §8.3 + Appendix D.1 — see `../SPEC.md`). Every
//! test runs once per suite.
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

/// (vectors, ciphersuite, scheme) per suite.
const suites = .{
    .{ kv.sha256, ciphersuite.Sha256, bbs.sha256 },
    .{ kv.shake256, ciphersuite.Shake256, bbs.shake256 },
};

// ── primitives ─────────────────────────────────────────────────────────

test "KAT -12 §8.x.1: keyGen(key_material, key_info, key_dst) and skToPk" {
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        const key_material = try hexToBytesAlloc(testing.allocator, V.keypair.key_material);
        defer testing.allocator.free(key_material);
        const key_info = try hexToBytesAlloc(testing.allocator, V.keypair.key_info);
        defer testing.allocator.free(key_info);
        if (V.keypair.key_dst) |hex| {
            // The published key_dst is the suite default (api_id || "KEYGEN_DST_").
            const key_dst = try hexToBytesAlloc(testing.allocator, hex);
            defer testing.allocator.free(key_dst);
            try testing.expectEqualStrings(S.keygen_dst, key_dst);
        }
        var sk: keys.SecretKey = undefined;
        try keys.keyGenWith(S, &sk, key_material, key_info, null);
        const expected_sk = try hexToArray(32, V.keypair.sk);
        var sk_bytes: [32]u8 = undefined;
        sk.toBytes(&sk_bytes);
        try testing.expectEqualSlices(u8, &expected_sk, &sk_bytes);
        try testing.expectEqualSlices(u8, &(try hexToArray(96, V.keypair.pk)), &keys.skToPk(&sk).toBytes());
    }
}

test "KAT -12 §8.x.3: createGenerators(11) is Q_1 then H_1..H_10, and P1 re-derives" {
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        const gens = try S.createGenerators(testing.allocator, 11);
        defer testing.allocator.free(gens);
        try testing.expectEqualSlices(u8, &(try hexToArray(48, V.generators.q1)), &ciphersuite.G1.toBytesCompressed(gens[0]));
        for (V.generators.msg_generators, gens[1..]) |expected_hex, got| {
            try testing.expectEqualSlices(u8, &(try hexToArray(48, expected_hex)), &ciphersuite.G1.toBytesCompressed(got));
        }
        const bp = try S.createGeneratorsWithSeed(testing.allocator, 1, S.bp_generator_seed_message);
        defer testing.allocator.free(bp);
        try testing.expectEqualSlices(u8, &ciphersuite.G1.toBytesCompressed(S.P1), &ciphersuite.G1.toBytesCompressed(bp[0]));
    }
}

test "KAT -12 §8.x.2: messagesToScalars over the ten messages" {
    const msgs = try decodeMessages(testing.allocator, &kv.messages);
    defer freeMessages(testing.allocator, msgs);
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        if (V.map_messages_to_scalar.dst) |hex| {
            const dst = try hexToBytesAlloc(testing.allocator, hex);
            defer testing.allocator.free(dst);
            try testing.expectEqualStrings(S.map_msg_dst, dst);
        }
        const scalars = try S.messagesToScalars(testing.allocator, msgs);
        defer testing.allocator.free(scalars);
        for (V.map_messages_to_scalar.scalars, scalars) |expected_hex, got| {
            try testing.expectEqualSlices(u8, &(try hexToArray(32, expected_hex)), &got.toBytes());
        }
    }
}

test "KAT -12 §8.x.5: mockedRandomScalars(10, SEED)" {
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        const seed = try hexToBytesAlloc(testing.allocator, V.mocked_rng.seed);
        defer testing.allocator.free(seed);
        const scalars = S.mockedRandomScalars(V.mocked_rng.scalars.len, seed);
        for (V.mocked_rng.scalars, scalars) |expected_hex, got| {
            try testing.expectEqualSlices(u8, &(try hexToArray(32, expected_hex)), &got.toBytes());
        }
    }
}

test "KAT -12 D.x.3: hashToScalar" {
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        const msg = try hexToBytesAlloc(testing.allocator, V.h2s.msg);
        defer testing.allocator.free(msg);
        const dst = try hexToBytesAlloc(testing.allocator, V.h2s.dst);
        defer testing.allocator.free(dst);
        try testing.expectEqualStrings(S.h2s_dst, dst);
        try testing.expectEqualSlices(u8, &(try hexToArray(32, V.h2s.scalar)), &S.hashToScalar(msg, dst).toBytes());
    }
}

// ── sign / verify ──────────────────────────────────────────────────────

test "KAT -12 §8.x.4 + D.x.1: sign is byte-exact on the valid cases, verify agrees on all nine" {
    inline for (suites) |su| {
        const V = su[0];
        const B = su[2];
        var valid_seen: usize = 0;
        var invalid_seen: usize = 0;
        for (V.signature_cases) |case| {
            const pk = try keys.PublicKey.fromBytes(try hexToArray(96, case.pk));
            const header = try hexToBytesAlloc(testing.allocator, case.header);
            defer testing.allocator.free(header);
            const msgs = try decodeMessages(testing.allocator, case.messages);
            defer freeMessages(testing.allocator, msgs);
            const sig = try hexToArray(bbs.Signature.encoded_bytes, case.signature);

            const ok = try B.verify(testing.allocator, pk, sig, header, msgs);
            if (ok != case.valid) {
                std.debug.print("case {s}: verify = {}\n", .{ case.name, ok });
                return error.TestUnexpectedResult;
            }
            if (case.valid) {
                var sk: keys.SecretKey = undefined;
                try keys.SecretKey.fromBytes(&sk, &(try hexToArray(32, case.sk.?)));
                const got = try B.sign(testing.allocator, &sk, pk, header, msgs);
                try testing.expectEqualSlices(u8, &sig, &got);
                valid_seen += 1;
            } else invalid_seen += 1;
        }
        try testing.expectEqual(@as(usize, 3), valid_seen);
        try testing.expectEqual(@as(usize, 6), invalid_seen);
    }
}

test "a signature from one suite does not verify under the other" {
    const sig_case = kv.sha256.signature_cases[0];
    const pk = try keys.PublicKey.fromBytes(try hexToArray(96, sig_case.pk));
    const header = try hexToBytesAlloc(testing.allocator, sig_case.header);
    defer testing.allocator.free(header);
    const msgs = try decodeMessages(testing.allocator, sig_case.messages);
    defer freeMessages(testing.allocator, msgs);
    const sig = try hexToArray(bbs.Signature.encoded_bytes, sig_case.signature);
    try testing.expect(try bbs.sha256.verify(testing.allocator, pk, sig, header, msgs));
    try testing.expect(!try bbs.shake256.verify(testing.allocator, pk, sig, header, msgs));
}

// ── proofGen / proofVerify ─────────────────────────────────────────────

test "KAT -12 §8.x.5 + D.x.2: proofGen byte-exact under the mocked RNG, proofVerify accepts" {
    inline for (suites) |su| {
        const V = su[0];
        const S = su[1];
        const B = su[2];
        const seed = try hexToBytesAlloc(testing.allocator, V.mocked_rng.seed);
        defer testing.allocator.free(seed);
        for (V.proof_cases) |case| {
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
                if (n == rs.len) @memcpy(rs, &S.mockedRandomScalars(n, seed));
            }
            const proof = try B.proofGen(testing.allocator, pk, &sig, header, ph, msgs, case.disclosed_indexes, rs);
            defer testing.allocator.free(proof);
            if (!std.mem.eql(u8, expected, proof)) {
                std.debug.print("case {s}: proofGen differs\n", .{case.name});
                return error.TestExpectedEqual;
            }

            const disclosed = try testing.allocator.alloc([]const u8, case.disclosed_indexes.len);
            defer testing.allocator.free(disclosed);
            for (case.disclosed_indexes, disclosed) |i, *d| d.* = msgs[i];
            try testing.expect(try B.proofVerify(testing.allocator, pk, expected, header, ph, disclosed, case.disclosed_indexes));

            // Tamper controls on genuine published proofs: another presentation
            // header, another header, a dropped disclosed message.
            try testing.expect(!try B.proofVerify(testing.allocator, pk, expected, header, "other ph", disclosed, case.disclosed_indexes));
            try testing.expect(!try B.proofVerify(testing.allocator, pk, expected, "other header", ph, disclosed, case.disclosed_indexes));
            if (disclosed.len > 1) {
                try testing.expect(!try B.proofVerify(testing.allocator, pk, expected, header, ph, disclosed[1..], case.disclosed_indexes[1..]));
            }
        }
    }
}
