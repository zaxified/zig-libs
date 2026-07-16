// SPDX-License-Identifier: MIT
//! kat_test — the byte-exact KAT harness, driven from `kat_vectors.zig`
//! (`mattrglobal/pairing_crypto`'s `bls12_381_sha_256` fixture
//! directory, pinned to draft-irtf-cfrg-bbs-signatures-**04** — see
//! `../SPEC.md`).
//!
//! **Ungated (run today, PASS)**: `keyGen`/`skToPk` against
//! `kat_vectors.keypair`; `ciphersuite.createGenerators`/
//! `createGeneratorsWithSeed` against `kat_vectors.generators`;
//! `ciphersuite.messagesToScalars` against
//! `kat_vectors.map_message_to_scalar`; `ciphersuite.mockedRandomScalars`
//! against `kat_vectors.mocked_rng`. None of these touch `bbs.zig`'s four
//! Fable cores.
//!
//! **Gated (behind `gate.core_implemented`, now `true` — these run and
//! pass, byte-exact)**: `sign` against
//! `kat_vectors.signature001`/`signature004`; `verify` against those
//! plus `signature002`'s tamper case; `proofGen` (fed
//! `ciphersuite.mockedRandomScalars(N, kat_vectors.mocked_rng.seed_ascii)`
//! for the fixture's own `N`) against `kat_vectors.proof001`/`proof003`;
//! `proofVerify` against those plus `proof004`'s tamper case.

const std = @import("std");
const testing = std.testing;

const ciphersuite = @import("ciphersuite.zig");
const keys = @import("keys.zig");
const bbs = @import("bbs.zig");
const gate = @import("gate.zig");
const kv = @import("kat_vectors.zig");

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexToArray(comptime n: usize, hex: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

// ── ungated: KeyGen ─────────────────────────────────────────────────────

test "KAT: keyGen(key_material, key_info) matches keypair.json's SK" {
    const key_material = try hexToBytesAlloc(testing.allocator, kv.keypair.key_material);
    defer testing.allocator.free(key_material);
    const key_info = try hexToBytesAlloc(testing.allocator, kv.keypair.key_info);
    defer testing.allocator.free(key_info);

    const sk = try keys.keyGen(key_material, key_info, null);
    const expected_sk = try hexToArray(32, kv.keypair.sk);
    try testing.expectEqualSlices(u8, &expected_sk, &sk.toBytes());
}

test "KAT: skToPk(SK) matches keypair.json's PK" {
    const expected_sk = try hexToArray(32, kv.keypair.sk);
    const sk = try keys.SecretKey.fromBytes(expected_sk);
    const pk = keys.skToPk(sk);
    const expected_pk = try hexToArray(96, kv.keypair.pk);
    try testing.expectEqualSlices(u8, &expected_pk, &pk.toBytes());
}

// ── ungated: generators ─────────────────────────────────────────────────

test "KAT: createGenerators(11) matches generators.json's Q1 + 10 MsgGenerators" {
    const gens = try ciphersuite.createGenerators(testing.allocator, 11);
    defer testing.allocator.free(gens);

    const expected_q1 = try hexToArray(48, kv.generators.q1);
    try testing.expectEqualSlices(u8, &expected_q1, &ciphersuite.G1.toBytesCompressed(gens[0]));

    for (kv.generators.msg_generators, gens[1..]) |expected_hex, got| {
        const expected = try hexToArray(48, expected_hex);
        try testing.expectEqualSlices(u8, &expected, &ciphersuite.G1.toBytesCompressed(got));
    }
}

test "KAT: P1 (ciphersuite.P1) matches generators.json's BP" {
    const expected_bp = try hexToArray(48, kv.generators.bp);
    try testing.expectEqualSlices(u8, &expected_bp, &ciphersuite.G1.toBytesCompressed(ciphersuite.P1));
}

// ── ungated: messages_to_scalars ────────────────────────────────────────

test "KAT: messagesToScalars matches MapMessageToScalarAsHash.json for all 10 messages" {
    var msg_bytes: [10][]u8 = undefined;
    for (kv.map_message_to_scalar, 0..) |case, i| {
        msg_bytes[i] = try hexToBytesAlloc(testing.allocator, case.message);
    }
    defer for (msg_bytes) |m| testing.allocator.free(m);

    var msgs: [10][]const u8 = undefined;
    for (msg_bytes, 0..) |m, i| msgs[i] = m;

    const scalars = try ciphersuite.messagesToScalars(testing.allocator, &msgs);
    defer testing.allocator.free(scalars);

    for (kv.map_message_to_scalar, scalars) |case, got| {
        const expected = try hexToArray(32, case.scalar);
        try testing.expectEqualSlices(u8, &expected, &got.toBytes());
    }
}

// ── ungated: mocked random scalars ──────────────────────────────────────

test "KAT: mockedRandomScalars(10, pi-seed) matches mockedRng.json" {
    const scalars = ciphersuite.mockedRandomScalars(kv.mocked_rng.count, kv.mocked_rng.seed_ascii);
    for (kv.mocked_rng.mocked_scalars, scalars) |expected_hex, got| {
        const expected = try hexToArray(32, expected_hex);
        try testing.expectEqualSlices(u8, &expected, &got.toBytes());
    }
}

// ── gated: sign / verify ────────────────────────────────────────────────

fn skFromFixture() !keys.SecretKey {
    return keys.SecretKey.fromBytes(try hexToArray(32, kv.keypair.sk));
}

fn pkFromFixture() !keys.PublicKey {
    return keys.PublicKey.fromBytes(try hexToArray(96, kv.keypair.pk));
}

fn decodeMessages(allocator: std.mem.Allocator, hex_messages: []const []const u8) ![][]const u8 {
    const out = try allocator.alloc([]const u8, hex_messages.len);
    for (hex_messages, 0..) |h, i| out[i] = try hexToBytesAlloc(allocator, h);
    return out;
}

fn freeMessages(allocator: std.mem.Allocator, msgs: [][]const u8) void {
    for (msgs) |m| allocator.free(@constCast(m));
    allocator.free(msgs);
}

test "KAT (gated): sign(single message) matches signature001.json" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const sk = try skFromFixture();
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const msgs = try decodeMessages(testing.allocator, kv.signature001.msgs);
    defer freeMessages(testing.allocator, msgs);

    const sig = try bbs.sign(testing.allocator, sk, pk, header, msgs);
    const expected = try hexToArray(bbs.Signature.encoded_bytes, kv.signature001.signature);
    try testing.expectEqualSlices(u8, &expected, &sig);
}

test "KAT (gated): sign(10 messages) matches signature004.json" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const sk = try skFromFixture();
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const msgs = try decodeMessages(testing.allocator, kv.signature004.msgs);
    defer freeMessages(testing.allocator, msgs);

    const sig = try bbs.sign(testing.allocator, sk, pk, header, msgs);
    const expected = try hexToArray(bbs.Signature.encoded_bytes, kv.signature004.signature);
    try testing.expectEqualSlices(u8, &expected, &sig);
}

test "KAT (gated): verify(signature001) == true, verify(signature002 tamper) == false" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const sig = try hexToArray(bbs.Signature.encoded_bytes, kv.signature001.signature);

    const ok_msgs = try decodeMessages(testing.allocator, kv.signature001.msgs);
    defer freeMessages(testing.allocator, ok_msgs);
    try testing.expect(try bbs.verify(testing.allocator, pk, sig, header, ok_msgs));

    // signature002.json: signature001's EXACT bytes, verified against a
    // different message set — must reject.
    const bad_msgs = try decodeMessages(testing.allocator, &kv.signature002.msgs);
    defer freeMessages(testing.allocator, bad_msgs);
    try testing.expect(!try bbs.verify(testing.allocator, pk, sig, header, bad_msgs));
}

// ── gated: proofGen / proofVerify ───────────────────────────────────────

fn runProofGenCase(comptime case: type) !void {
    const sk = try skFromFixture();
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const ph = try hexToBytesAlloc(testing.allocator, kv.presentation_header);
    defer testing.allocator.free(ph);
    const msgs = try decodeMessages(testing.allocator, case.msgs);
    defer freeMessages(testing.allocator, msgs);

    const sig = try bbs.sign(testing.allocator, sk, pk, header, msgs);
    try testing.expect(try bbs.verify(testing.allocator, pk, sig, header, msgs));

    const random_scalars = ciphersuite.mockedRandomScalars(case.random_scalars_count, kv.mocked_rng.seed_ascii);
    const proof = try bbs.proofGen(testing.allocator, pk, sig, header, ph, msgs, &case.disclosed_indexes, &random_scalars);
    defer testing.allocator.free(proof);

    const expected = try hexToBytesAlloc(testing.allocator, case.proof);
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, proof);
}

test "KAT (gated): proofGen(single message, fully revealed) matches proof001.json" {
    if (!gate.core_implemented) return error.SkipZigTest;
    try runProofGenCase(kv.proof001);
}

test "KAT (gated): proofGen(10 messages, 4 revealed) matches proof003.json" {
    if (!gate.core_implemented) return error.SkipZigTest;
    try runProofGenCase(kv.proof003);
}

test "KAT (gated): proofVerify(proof001) == true" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const ph = try hexToBytesAlloc(testing.allocator, kv.presentation_header);
    defer testing.allocator.free(ph);
    const proof = try hexToBytesAlloc(testing.allocator, kv.proof001.proof);
    defer testing.allocator.free(proof);
    const disclosed = try decodeMessages(testing.allocator, kv.proof001.disclosed_messages);
    defer freeMessages(testing.allocator, disclosed);

    const ok = try bbs.proofVerify(testing.allocator, pk, proof, header, ph, disclosed, &kv.proof001.disclosed_indexes);
    try testing.expect(ok);
}

test "KAT (gated): proofVerify(proof003) == true, proofVerify(proof004 tampered ph) == false" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const pk = try pkFromFixture();
    const header = try hexToBytesAlloc(testing.allocator, kv.header);
    defer testing.allocator.free(header);
    const proof = try hexToBytesAlloc(testing.allocator, kv.proof003.proof);
    defer testing.allocator.free(proof);
    const disclosed = try decodeMessages(testing.allocator, &kv.proof003.disclosed_messages);
    defer freeMessages(testing.allocator, disclosed);

    const ph_ok = try hexToBytesAlloc(testing.allocator, kv.presentation_header);
    defer testing.allocator.free(ph_ok);
    try testing.expect(try bbs.proofVerify(testing.allocator, pk, proof, header, ph_ok, disclosed, &kv.proof003.disclosed_indexes));

    // proof004.json: proof003's EXACT proof bytes, verified against a
    // different presentation header — must reject.
    const ph_bad = try hexToBytesAlloc(testing.allocator, kv.proof004.presentation_header_tampered);
    defer testing.allocator.free(ph_bad);
    try testing.expect(!try bbs.proofVerify(testing.allocator, pk, proof, header, ph_bad, disclosed, &kv.proof004.disclosed_indexes));
}
