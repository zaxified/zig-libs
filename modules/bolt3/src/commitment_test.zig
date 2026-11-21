// SPDX-License-Identifier: MIT
//! `commitment.zig` against the signed transactions of BOLT#3 Appendix C (16 legacy cases), F (9
//! option_anchors cases) and H (11 zero_fee_commitments cases). Each published commitment and HTLC
//! transaction is parsed; ours is built from the case's parameters; the signatures inside the published
//! transaction must verify over OUR signature hash (so the scripts, amounts and sighash type agree), and
//! putting those signatures into our transaction must reproduce the published bytes exactly.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const bitcointx = @import("bitcointx");
const k256 = @import("k256");
const root = @import("root.zig");
const c = @import("commitment.zig");
const vectors = @import("commitment_vectors.zig");

fn hex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hexAlloc(allocator: Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn pubkeyOf(secret_hex: []const u8) ![33]u8 {
    const sk = hex(32, secret_hex);
    const p = try k256.Secp256k1.combMulBase(sk, .big);
    return p.toCompressedSec1();
}

const Sig = struct { rs: [64]u8, hash_type: u8 };

/// Splits `<DER><sighash byte>` into the compact signature and the byte.
fn splitSig(item: []const u8) !Sig {
    if (item.len < 9 or item[0] != 0x30 or @as(usize, item[1]) + 3 != item.len) return error.BadDer;
    var rs: [64]u8 = @splat(0);
    var i: usize = 2;
    inline for (.{ 0, 32 }) |off| {
        if (item[i] != 0x02) return error.BadDer;
        var len: usize = item[i + 1];
        var start = i + 2;
        if (len > 32) {
            if (item[start] != 0) return error.BadDer;
            start += 1;
            len -= 1;
        }
        @memcpy(rs[off + 32 - len .. off + 32], item[start .. start + len]);
        i = start + len;
    }
    return .{ .rs = rs, .hash_type = item[item.len - 1] };
}

fn verifies(pubkey: [33]u8, digest: [32]u8, item: []const u8, want_hash_type: u8) !bool {
    const s = try splitSig(item);
    if (s.hash_type != want_hash_type) return false;
    return k256.sign.ecdsaVerifyPrehashed(&pubkey, digest, s.rs);
}

const Keys = struct {
    keys: c.Keys,
    opener_basepoint: [33]u8,
    accepter_basepoint: [33]u8,
};

/// Appendix C / F keys (the BOLT's own public values).
fn appendixKeys() Keys {
    const local_pay = hex(33, "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    const remote_pay = hex(33, "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
    return .{
        .keys = .{
            .revocation_pubkey = hex(33, "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19"),
            .local_delayed_pubkey = hex(33, "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c"),
            .local_htlc_pubkey = hex(33, "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"),
            .remote_htlc_pubkey = hex(33, "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b"),
            .remote_pubkey = remote_pay,
            .local_funding_pubkey = hex(33, "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            .remote_funding_pubkey = hex(33, "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
        },
        .opener_basepoint = local_pay,
        .accepter_basepoint = remote_pay,
    };
}

fn reversed(b: [32]u8) [32]u8 {
    var r: [32]u8 = undefined;
    for (b, 0..) |x, i| r[31 - i] = x;
    return r;
}

/// Checks `commitment` and every published HTLC transaction against the case's expected hex.
fn checkCommitment(allocator: Allocator, p: c.CommitmentParams, commit_hex: []const u8, htlc_hexes: []const []const u8) !void {
    var com = try c.buildCommitment(allocator, p);
    defer com.deinit();

    const expected_bytes = try hexAlloc(allocator, commit_hex);
    defer allocator.free(expected_bytes);
    var expected = try bitcointx.deserialize(allocator, expected_bytes);
    defer expected.deinit(allocator);

    // The signatures in the published transaction verify over our digest.
    const items = expected.witness[0].items;
    try testing.expectEqual(@as(usize, 4), items.len);
    try testing.expectEqualSlices(u8, com.funding_script, items[3]);
    const digest = try com.sighash(allocator);
    const lesser_is_local = std.mem.lessThan(u8, &p.keys.local_funding_pubkey, &p.keys.remote_funding_pubkey);
    const k1 = if (lesser_is_local) p.keys.local_funding_pubkey else p.keys.remote_funding_pubkey;
    const k2 = if (lesser_is_local) p.keys.remote_funding_pubkey else p.keys.local_funding_pubkey;
    try testing.expect(try verifies(k1, digest, items[1], 1));
    try testing.expect(try verifies(k2, digest, items[2], 1));

    // And placing them reproduces the published transaction byte for byte.
    const local_sig = if (lesser_is_local) items[1] else items[2];
    const remote_sig = if (lesser_is_local) items[2] else items[1];
    try com.finalize(local_sig, remote_sig, p.keys.local_funding_pubkey, p.keys.remote_funding_pubkey);
    const ours = try bitcointx.serialize(allocator, com.tx);
    defer allocator.free(ours);
    try testing.expectEqualSlices(u8, expected_bytes, ours);

    // The HTLC outputs of the commitment are exactly the published HTLC transactions.
    var n_htlc: usize = 0;
    for (com.kinds) |k| {
        if (k == .htlc) n_htlc += 1;
    }
    try testing.expectEqual(htlc_hexes.len, n_htlc);

    for (htlc_hexes) |h_hex| {
        const bytes = try hexAlloc(allocator, h_hex);
        defer allocator.free(bytes);
        var exp = try bitcointx.deserialize(allocator, bytes);
        defer exp.deinit(allocator);
        const idx = exp.vin[0].prevout.vout;
        var ht = try c.buildHtlcTx(allocator, p, com, idx);
        defer ht.deinit();

        const wit = exp.witness[0].items;
        try testing.expectEqual(@as(usize, 5), wit.len);
        try testing.expectEqualSlices(u8, ht.spent_script, wit[4]);
        const d_remote = try ht.sighash(allocator, ht.remote_hash_type);
        try testing.expect(try verifies(p.keys.remote_htlc_pubkey, d_remote, wit[1], @intCast(ht.remote_hash_type)));
        // The local node signs with its own type (SIGHASH_ALL in every published vector).
        const local_type = wit[2][wit[2].len - 1];
        try testing.expectEqual(c.sighash_all, @as(u32, local_type));
        const d_local = try ht.sighash(allocator, local_type);
        try testing.expect(try verifies(p.keys.local_htlc_pubkey, d_local, wit[2], local_type));
        var preimage: ?[32]u8 = null;
        if (wit[3].len != 0) {
            try testing.expectEqual(@as(usize, 32), wit[3].len);
            preimage = wit[3][0..32].*;
            // The HTLC-success preimage hashes to the output's payment hash.
            var hash: [32]u8 = undefined;
            Sha256.hash(&preimage.?, &hash, .{});
            try testing.expect(!ht.offered);
            try testing.expect(htlcHashMatches(p, com, idx, hash));
        } else {
            try testing.expect(ht.offered);
        }
        try ht.finalize(wit[1], wit[2], preimage);
        const ours_h = try bitcointx.serialize(allocator, ht.tx);
        defer allocator.free(ours_h);
        try testing.expectEqualSlices(u8, bytes, ours_h);
    }
}

fn htlcHashMatches(p: c.CommitmentParams, com: c.Commitment, idx: usize, hash: [32]u8) bool {
    return std.mem.eql(u8, &p.htlcs[com.kinds[idx].htlc].payment_hash, &hash);
}

fn caseParams(allocator: Allocator, k: Keys, case: vectors.Case, format: c.Format) !c.CommitmentParams {
    const htlcs = try allocator.alloc(c.Htlc, case.htlc_ids.len);
    for (case.htlc_ids, htlcs) |id, *h| {
        const t = vectors.test_htlcs[id];
        const preimage: [32]u8 = @splat(t.preimage_byte);
        var hash: [32]u8 = undefined;
        Sha256.hash(&preimage, &hash, .{});
        h.* = .{ .offered = t.offered, .amount_msat = t.amount_msat, .cltv_expiry = t.cltv_expiry, .payment_hash = hash };
    }
    const funding_txid = reversed(hex(32, "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"));
    return .{
        .funding_txid = funding_txid,
        .funding_output_index = 0,
        .funding_amount_sat = 10_000_000,
        .commitment_number = 42,
        .opener_payment_basepoint = k.opener_basepoint,
        .accepter_payment_basepoint = k.accepter_basepoint,
        .to_local_msat = case.to_local_msat,
        .to_remote_msat = case.to_remote_msat,
        .local_is_funder = true,
        .dust_limit_satoshis = case.dust_limit_satoshis,
        .feerate_per_kw = case.feerate_per_kw,
        .to_self_delay = 144,
        .keys = k.keys,
        .format = format,
        .htlcs = htlcs,
    };
}

test "BOLT#3 Appendix C: all 16 legacy commitment cases and their HTLC transactions" {
    const k = appendixKeys();
    for (vectors.appendix_c) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const p = try caseParams(arena.allocator(), k, case, .{});
        checkCommitment(arena.allocator(), p, case.commit_tx, case.htlc_txs) catch |err| {
            std.debug.print("FAIL Appendix C: {s}: {}\n", .{ case.name, err });
            return err;
        };
    }
}

test "BOLT#3 Appendix F: all 9 option_anchors cases and their HTLC transactions" {
    const k = appendixKeys();
    for (vectors.appendix_f) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const p = try caseParams(arena.allocator(), k, case, .{ .anchors = true });
        checkCommitment(arena.allocator(), p, case.commit_tx, case.htlc_txs) catch |err| {
            std.debug.print("FAIL Appendix F: {s}: {}\n", .{ case.name, err });
            return err;
        };
    }
}

test "BOLT#3 Appendix H: all 11 zero_fee_commitments cases and their HTLC transactions" {
    const z = vectors.zf_common;
    const remote_pay = try pubkeyOf(z.remote_payment_basepoint_secret);
    const pcp = hex(33, z.per_commitment_point);
    const delayed_base = try pubkeyOf(z.local_delayed_payment_basepoint_secret);
    const local_htlc_base = try pubkeyOf(z.local_htlc_basepoint_secret);
    const remote_htlc_base = try pubkeyOf(z.remote_htlc_basepoint_secret);
    const keys: c.Keys = .{
        .revocation_pubkey = try root.deriveRevocationPublicKey(hex(33, z.revocation_basepoint), pcp),
        .local_delayed_pubkey = try root.derivePublicKey(delayed_base, pcp),
        .local_htlc_pubkey = try root.derivePublicKey(local_htlc_base, pcp),
        .remote_htlc_pubkey = try root.derivePublicKey(remote_htlc_base, pcp),
        .remote_pubkey = remote_pay,
        .local_funding_pubkey = try pubkeyOf(z.local_funding_priv),
        .remote_funding_pubkey = try pubkeyOf(z.remote_funding_priv),
    };
    for (vectors.appendix_h) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const n_in = case.incoming.len;
        const htlcs = try a.alloc(c.Htlc, n_in + case.outgoing.len);
        for (case.incoming, htlcs[0..n_in]) |h, *o| o.* = .{ .offered = false, .amount_msat = h.amount_msat, .cltv_expiry = h.cltv_expiry, .payment_hash = hex(32, h.payment_hash) };
        for (case.outgoing, htlcs[n_in..]) |h, *o| o.* = .{ .offered = true, .amount_msat = h.amount_msat, .cltv_expiry = h.cltv_expiry, .payment_hash = hex(32, h.payment_hash) };
        const p: c.CommitmentParams = .{
            .funding_txid = reversed(hex(32, z.funding_txid)),
            .funding_output_index = z.funding_index,
            .funding_amount_sat = z.funding_amount_satoshis,
            .commitment_number = z.commitment_number,
            .opener_payment_basepoint = try pubkeyOf(z.local_payment_basepoint_secret),
            .accepter_payment_basepoint = remote_pay,
            .to_local_msat = case.to_local_msat,
            .to_remote_msat = case.to_remote_msat,
            .local_is_funder = true,
            .dust_limit_satoshis = case.dust_limit_satoshis,
            .feerate_per_kw = 0,
            .to_self_delay = z.to_self_delay,
            .keys = keys,
            .format = .{ .zero_fee_commitments = true },
            .htlcs = htlcs,
        };
        checkCommitment(a, p, case.commit_tx, case.htlc_txs) catch |err| {
            std.debug.print("FAIL Appendix H: {s}: {}\n", .{ case.name, err });
            return err;
        };
    }
}

// ── pieces ──────────────────────────────────────────────────────────────

test "obscuring factor of Appendix C: 0x2bb038521914, and the locktime / sequence of commitment 42" {
    const k = appendixKeys();
    const f = c.obscuringFactor(k.opener_basepoint, k.accepter_basepoint);
    try testing.expectEqual(@as(u48, 0x2bb038521914), f);
    const ls = c.obscuredLocktimeSequence(42, f);
    // The published "simple" commitment: sequence bytes `38b02b80`, locktime bytes `3e195220` (little endian).
    try testing.expectEqual(@as(u32, 0x802bb038), ls.sequence);
    try testing.expectEqual(@as(u32, 0x2052193e), ls.locktime);
}

test "fee arithmetic of BOLT#3 §Fee Calculation example (feerate 5000: HTLC fees 3315 / 3515, commitment 5340 for two HTLC outputs)" {
    try testing.expectEqual(@as(u64, 3315), c.htlcTxFee(5000, true, .{}));
    try testing.expectEqual(@as(u64, 3515), c.htlcTxFee(5000, false, .{}));
    try testing.expectEqual(@as(u64, 5340), c.commitmentFee(5000, 2, .{}));
    try testing.expectEqual(@as(u64, 0), c.htlcTxFee(5000, true, .{ .anchors = true }));
    try testing.expectEqual(@as(u64, 0), c.htlcTxFee(5000, false, .{ .zero_fee_commitments = true }));
    try testing.expectEqual(@as(u64, 0), c.commitmentFee(5000, 2, .{ .zero_fee_commitments = true }));
    try testing.expectEqual(@as(u64, 1296), c.commitmentFee(1000, 1, .{ .anchors = true }));
}

test "funding script of Appendix B/C: the lesser key first, whichever order they come in" {
    const a = hex(33, "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
    const b = hex(33, "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");
    const want = hex(71, "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae");
    const s1 = try c.fundingScript(testing.allocator, a, b);
    defer testing.allocator.free(s1);
    const s2 = try c.fundingScript(testing.allocator, b, a);
    defer testing.allocator.free(s2);
    try testing.expectEqualSlices(u8, &want, s1);
    try testing.expectEqualSlices(u8, &want, s2);
}

test "script numbers are minimal: 0, 1..16 as opcodes, 144 as 0x9000, 500, a sign byte when the top bit is set" {
    const k = appendixKeys();
    // to_self_delay 144 -> `02 9000` (Appendix C); 16 -> OP_16; 128 -> `02 8000`.
    const s144 = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 144, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(s144);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x90, 0x00 }, s144[36..39]);
    const s16 = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 16, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(s16);
    try testing.expectEqual(@as(u8, 0x60), s16[36]);
    const s128 = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 128, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(s128);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x80, 0x00 }, s128[36..39]);
    const s1 = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 1, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(s1);
    try testing.expectEqual(@as(u8, 0x51), s1[36]);
    const big = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 0x7fffffff, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(big);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0xff, 0xff, 0xff, 0x7f }, big[36..41]);
    const big2 = try c.toLocalScript(testing.allocator, k.keys.revocation_pubkey, 0x80000000, k.keys.local_delayed_pubkey);
    defer testing.allocator.free(big2);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0x00, 0x00, 0x80, 0x00 }, big2[36..42]);
}

test "derSignature round-trips compact signatures, with and without a high first bit and leading zeros" {
    var rs: [64]u8 = undefined;
    for (&rs, 0..) |*b, i| b.* = @intCast(0x80 + (i % 7));
    const d1 = c.derSignature(rs, 1);
    const s1 = try splitSig(d1.slice());
    try testing.expectEqualSlices(u8, &rs, &s1.rs);
    try testing.expectEqual(@as(u8, 1), s1.hash_type);
    try testing.expectEqual(@as(usize, 73), d1.slice().len);
    var rs2: [64]u8 = @splat(0);
    rs2[2] = 0x01;
    rs2[40] = 0x7f;
    const d2 = c.derSignature(rs2, 0x83);
    const s2 = try splitSig(d2.slice());
    try testing.expectEqualSlices(u8, &rs2, &s2.rs);
    try testing.expectEqual(@as(u8, 0x83), s2.hash_type);
    try testing.expectEqual(@as(u8, 0x30), d2.slice()[0]);
}

test "buildHtlcTx refuses an output that is not an HTLC" {
    const k = appendixKeys();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try caseParams(arena.allocator(), k, vectors.appendix_c[1], .{});
    var com = try c.buildCommitment(testing.allocator, p);
    defer com.deinit();
    var non_htlc: usize = 0;
    for (com.kinds, 0..) |kind, i| {
        if (kind != .htlc) non_htlc = i;
    }
    try testing.expectError(error.NotAnHtlcOutput, c.buildHtlcTx(testing.allocator, p, com, non_htlc));
    try testing.expectError(error.NotAnHtlcOutput, c.buildHtlcTx(testing.allocator, p, com, 99));
}

test "amounts beyond i64 are refused, not wrapped" {
    const k = appendixKeys();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var p = try caseParams(arena.allocator(), k, vectors.appendix_c[0], .{});
    p.funding_amount_sat = std.math.maxInt(u64);
    try testing.expectError(error.AmountOutOfRange, c.buildCommitment(testing.allocator, p));
}
