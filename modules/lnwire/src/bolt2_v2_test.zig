// SPDX-License-Identifier: MIT
//! Tests for `bolt2_v2.zig`. The wire vectors are built field by field from the
//! `lightning/bolts` `02-peer-protocol.md` layouts by an independent script
//! (Python `struct`, no code shared with the codec; the spec carries no byte
//! vectors for these messages), so a layout slip in the codec cannot be
//! mirrored in the expectation. Every message: decode -> fields -> serialize is
//! byte-identical, plus the length checks of known TLV records, truncation,
//! the wrong frame type and an unknown even record.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const v2 = @import("bolt2_v2.zig");

fn hex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

const cid = blk: {
    var b: [32]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = @intCast(i + 1);
    break :blk b;
};
const txid = blk: {
    var b: [32]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = @intCast(0x40 + i);
    break :blk b;
};
fn sigAt(i: usize) [64]u8 {
    var s: [64]u8 = undefined;
    for (&s, 0..) |*x, k| x.* = @intCast(0x80 + k);
    if (i == 1) std.mem.reverse(u8, &s);
    return s;
}

const wire = struct {
    const stfu = "00020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001";
    const tx_add_input = "00420102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2001020304050607080005deadbeef0100000003fffffffd0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const tx_add_input_plain = "00420102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000002000000000000ffffffff";
    const tx_add_output = "00430102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000000000400000000000186a0001600140909090909090909090909090909090909090909";
    const tx_remove_input = "00440102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000006";
    const tx_remove_output = "00450102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000008";
    const tx_complete = "00460102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const tx_signatures = "00470102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0002000361626300000040808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const tx_init_rbf = "00480102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200009eb10000009c40008ffffffffffffcfc70200";
    const tx_ack_rbf = "00490102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200008000000000000c350";
    const tx_abort = "004a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000046f6f7073";
    const splice_locked = "004d0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const splice_init = "00500102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fffffffffffe7960000000fd000aae600301010101010101010101010101010101010101010101010101010101010101010200";
    const splice_ack = "00510102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000003d090020202020202020202020202020202020202020202020202020202020202020202";
    const closing_complete = "00280102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000160014010101010101010101010101010101010101010100160014020202020202020202020202020202020202020200000000000003e8000c35000140808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0340bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180";
    const closing_sig = "00290102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200003616263000278790000000000000001000000020240808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const start_batch = "007f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000301020084";
    const open_channel2 = "00406fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000fd000009c400000000000f424000000000000002220000000005f5e1000000000000000001009001e3000c3500020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a030b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b020c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c030d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d020e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e030f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f021010101010101010101010101010101010101010101010101010101010101010010016001407070707070707070707070707070707070707070101100200";
    const accept_channel2 = "00410102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000000007a12000000000000002220000000005f5e100000000000000000100000003009001e3021414141414141414141414141414141414141414141414141414141414141414031515151515151515151515151515151515151515151515151515151515151515021616161616161616161616161616161616161616161616161616161616161616031717171717171717171717171717171717171717171717171717171717171717021818181818181818181818181818181818181818181818181818181818181818031919191919191919191919191919191919191919191919191919191919191919021a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a0200";
};

test "stfu" {
    const a = testing.allocator;
    const b = try hex(a, wire.stfu);
    defer a.free(b);
    const m = try v2.decodeStfu(b);
    try testing.expectEqualSlices(u8, &cid, &m.channel_id);
    try testing.expectEqual(@as(u8, 1), m.initiator);
    const back = try v2.serializeStfu(a, m);
    defer a.free(back);
    try testing.expectEqualSlices(u8, b, back);
}

test "tx_add_input: with and without shared_input_txid" {
    const a = testing.allocator;
    const b = try hex(a, wire.tx_add_input);
    defer a.free(b);
    var m = try v2.decodeTxAddInput(a, b);
    defer m.deinit(a);
    try testing.expectEqual(@as(u64, 0x0102030405060708), m.serial_id);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef, 0x01 }, m.prevtx);
    try testing.expectEqual(@as(u32, 3), m.prevtx_vout);
    try testing.expectEqual(@as(u32, 0xfffffffd), m.sequence);
    try testing.expectEqualSlices(u8, &txid, &m.sharedInputTxid().?);
    const back = try v2.serializeTxAddInput(a, m);
    defer a.free(back);
    try testing.expectEqualSlices(u8, b, back);

    const p = try hex(a, wire.tx_add_input_plain);
    defer a.free(p);
    var m2 = try v2.decodeTxAddInput(a, p);
    defer m2.deinit(a);
    try testing.expectEqual(@as(usize, 0), m2.prevtx.len);
    try testing.expect(m2.sharedInputTxid() == null);
    const back2 = try v2.serializeTxAddInput(a, m2);
    defer a.free(back2);
    try testing.expectEqualSlices(u8, p, back2);
}

test "tx_add_output, tx_remove_input, tx_remove_output, tx_complete, tx_abort, splice_locked" {
    const a = testing.allocator;
    {
        const b = try hex(a, wire.tx_add_output);
        defer a.free(b);
        const m = try v2.decodeTxAddOutput(b);
        try testing.expectEqual(@as(u64, 4), m.serial_id);
        try testing.expectEqual(@as(u64, 100000), m.sats);
        try testing.expectEqual(@as(usize, 22), m.script.len);
        const back = try v2.serializeTxAddOutput(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.tx_remove_input);
        defer a.free(b);
        const m = try v2.decodeTxRemoveInput(b);
        try testing.expectEqual(@as(u64, 6), m.serial_id);
        const back = try v2.serializeTxRemoveInput(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
        try testing.expectError(error.WrongType, v2.decodeTxRemoveOutput(b));
    }
    {
        const b = try hex(a, wire.tx_remove_output);
        defer a.free(b);
        const m = try v2.decodeTxRemoveOutput(b);
        try testing.expectEqual(@as(u64, 8), m.serial_id);
        const back = try v2.serializeTxRemoveOutput(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.tx_complete);
        defer a.free(b);
        var m = try v2.decodeTxComplete(a, b);
        defer m.deinit(a);
        try testing.expectEqualSlices(u8, &cid, &m.channel_id);
        const back = try v2.serializeTxComplete(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.tx_abort);
        defer a.free(b);
        const m = try v2.decodeTxAbort(b);
        try testing.expectEqualStrings("oops", m.data);
        const back = try v2.serializeTxAbort(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.splice_locked);
        defer a.free(b);
        const m = try v2.decodeSpliceLocked(b);
        try testing.expectEqualSlices(u8, &txid, &m.splice_txid);
        const back = try v2.serializeSpliceLocked(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
}

test "tx_signatures: witnesses and shared_input_signature" {
    const a = testing.allocator;
    const b = try hex(a, wire.tx_signatures);
    defer a.free(b);
    var m = try v2.decodeTxSignatures(a, b);
    defer m.deinit(a);
    try testing.expectEqualSlices(u8, &txid, &m.txid);
    try testing.expectEqual(@as(usize, 2), m.witnesses.len);
    try testing.expectEqualStrings("abc", m.witnesses[0]);
    try testing.expectEqual(@as(usize, 0), m.witnesses[1].len);
    try testing.expectEqualSlices(u8, &sigAt(0), &m.sharedInputSignature().?);
    const back = try v2.serializeTxSignatures(a, m);
    defer a.free(back);
    try testing.expectEqualSlices(u8, b, back);
    // A count that promises more witnesses than there are bytes is refused before allocating.
    var huge = try a.dupe(u8, b);
    defer a.free(huge);
    huge[2 + 32 + 32] = 0xff;
    huge[2 + 32 + 32 + 1] = 0xff;
    try testing.expectError(error.Truncated, v2.decodeTxSignatures(a, huge));
}

test "tx_init_rbf / tx_ack_rbf: s64 contribution and require_confirmed_inputs" {
    const a = testing.allocator;
    {
        const b = try hex(a, wire.tx_init_rbf);
        defer a.free(b);
        var m = try v2.decodeTxInitRbf(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(u32, 650000), m.locktime);
        try testing.expectEqual(@as(u32, 2500), m.feerate);
        try testing.expectEqual(@as(i64, -12345), m.fundingOutputContribution().?);
        try testing.expect(m.requireConfirmedInputs());
        const back = try v2.serializeTxInitRbf(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.tx_ack_rbf);
        defer a.free(b);
        var m = try v2.decodeTxAckRbf(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(i64, 50000), m.fundingOutputContribution().?);
        try testing.expect(!m.requireConfirmedInputs());
        const back = try v2.serializeTxAckRbf(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
}

test "splice_init / splice_ack: negative contribution, require_confirmed_inputs" {
    const a = testing.allocator;
    {
        const b = try hex(a, wire.splice_init);
        defer a.free(b);
        var m = try v2.decodeSpliceInit(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(i64, -100000), m.funding_contribution_satoshis);
        try testing.expectEqual(@as(u32, 253), m.funding_feerate_perkw);
        try testing.expectEqual(@as(u32, 700000), m.locktime);
        try testing.expectEqual(@as(u8, 3), m.funding_pubkey[0]);
        try testing.expect(m.requireConfirmedInputs());
        const back = try v2.serializeSpliceInit(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.splice_ack);
        defer a.free(b);
        var m = try v2.decodeSpliceAck(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(i64, 250000), m.funding_contribution_satoshis);
        try testing.expect(!m.requireConfirmedInputs());
        const back = try v2.serializeSpliceAck(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
}

test "closing_complete / closing_sig share one layout and their signature records" {
    const a = testing.allocator;
    {
        const b = try hex(a, wire.closing_complete);
        defer a.free(b);
        var m = try v2.decodeClosingComplete(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(usize, 22), m.closer_scriptpubkey.len);
        try testing.expectEqual(@as(u8, 2), m.closee_scriptpubkey[2]);
        try testing.expectEqual(@as(u64, 1000), m.fee_satoshis);
        try testing.expectEqual(@as(u32, 800000), m.locktime);
        try testing.expectEqualSlices(u8, &sigAt(0), &m.closerOutputOnly().?);
        try testing.expect(m.closeeOutputOnly() == null);
        try testing.expectEqualSlices(u8, &sigAt(1), &m.closerAndCloseeOutputs().?);
        const back = try v2.serializeClosingComplete(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
        try testing.expectError(error.WrongType, v2.decodeClosingSig(a, b));
    }
    {
        const b = try hex(a, wire.closing_sig);
        defer a.free(b);
        var m = try v2.decodeClosingSig(a, b);
        defer m.deinit(a);
        try testing.expectEqualStrings("abc", m.closer_scriptpubkey);
        try testing.expectEqualStrings("xy", m.closee_scriptpubkey);
        try testing.expectEqualSlices(u8, &sigAt(0), &m.closeeOutputOnly().?);
        const back = try v2.serializeClosingSig(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
}

test "start_batch" {
    const a = testing.allocator;
    const b = try hex(a, wire.start_batch);
    defer a.free(b);
    var m = try v2.decodeStartBatch(a, b);
    defer m.deinit(a);
    try testing.expectEqual(@as(u16, 3), m.batch_size);
    try testing.expectEqual(@as(u16, 132), m.messageType().?);
    const back = try v2.serializeStartBatch(a, m);
    defer a.free(back);
    try testing.expectEqualSlices(u8, b, back);
}

test "open_channel2 / accept_channel2" {
    const a = testing.allocator;
    {
        const b = try hex(a, wire.open_channel2);
        defer a.free(b);
        var m = try v2.decodeOpenChannel2(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(u32, 253), m.funding_feerate_perkw);
        try testing.expectEqual(@as(u32, 2500), m.commitment_feerate_perkw);
        try testing.expectEqual(@as(u64, 1000000), m.funding_satoshis);
        try testing.expectEqual(@as(u64, 546), m.dust_limit_satoshis);
        try testing.expectEqual(@as(u16, 144), m.to_self_delay);
        try testing.expectEqual(@as(u16, 483), m.max_accepted_htlcs);
        try testing.expectEqual(@as(u32, 800000), m.locktime);
        try testing.expectEqual(@as(u8, 2), m.funding_pubkey[0]);
        try testing.expectEqual(@as(u8, 10), m.funding_pubkey[1]);
        try testing.expectEqual(@as(u8, 16), m.second_per_commitment_point[1]);
        try testing.expectEqual(@as(u8, 1), m.channel_flags);
        try testing.expectEqual(@as(usize, 22), m.upfrontShutdownScript().?.len);
        try testing.expect(m.channelType().?.isSet(4));
        try testing.expect(m.requireConfirmedInputs());
        const back = try v2.serializeOpenChannel2(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
    {
        const b = try hex(a, wire.accept_channel2);
        defer a.free(b);
        var m = try v2.decodeAcceptChannel2(a, b);
        defer m.deinit(a);
        try testing.expectEqual(@as(u64, 500000), m.funding_satoshis);
        try testing.expectEqual(@as(u32, 3), m.minimum_depth);
        try testing.expectEqual(@as(u8, 20), m.funding_pubkey[1]);
        try testing.expectEqual(@as(u8, 26), m.second_per_commitment_point[1]);
        try testing.expect(m.requireConfirmedInputs());
        try testing.expect(m.upfrontShutdownScript() == null);
        const back = try v2.serializeAcceptChannel2(a, m);
        defer a.free(back);
        try testing.expectEqualSlices(u8, b, back);
    }
}

test "every message refuses a truncated frame at every cut point and the wrong type" {
    const a = testing.allocator;
    inline for (.{
        .{ wire.tx_add_input, v2.decodeTxAddInput },
        .{ wire.tx_signatures, v2.decodeTxSignatures },
        .{ wire.tx_init_rbf, v2.decodeTxInitRbf },
        .{ wire.splice_init, v2.decodeSpliceInit },
        .{ wire.closing_complete, v2.decodeClosingComplete },
        .{ wire.open_channel2, v2.decodeOpenChannel2 },
        .{ wire.accept_channel2, v2.decodeAcceptChannel2 },
    }) |pair| {
        const b = try hex(a, pair[0]);
        defer a.free(b);
        // Cutting inside the fixed part always fails; cutting inside the trailing tlv stream
        // may fail or (at a record boundary) succeed, but never panics or leaks.
        var cut: usize = 0;
        while (cut < b.len) : (cut += 1) {
            if (pair[1](a, b[0..cut])) |ok| {
                var mm = ok;
                mm.deinit(a);
            } else |_| {}
        }
        var wrong = try a.dupe(u8, b);
        defer a.free(wrong);
        wrong[1] ^= 0x01;
        try testing.expectError(error.WrongType, pair[1](a, wrong));
    }
}

test "known TLV records of the wrong length are refused (decode and encode); unknown even types too" {
    const a = testing.allocator;
    // require_confirmed_inputs must be empty.
    const bad_rci = try hex(a, wire.splice_ack ++ "0201ff");
    defer a.free(bad_rci);
    try testing.expectError(error.InvalidTlvLength, v2.decodeSpliceAck(a, bad_rci));
    // funding_output_contribution must be 8 bytes.
    const ack = try hex(a, "0049" ++ "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" ++ "000200ff");
    defer a.free(ack);
    try testing.expectError(error.InvalidTlvLength, v2.decodeTxAckRbf(a, ack));
    // shared_input_txid must be 32 bytes, a closing signature 64, message_type 2.
    const sit = try hex(a, wire.tx_add_input_plain ++ "000100");
    defer a.free(sit);
    try testing.expectError(error.InvalidTlvLength, v2.decodeTxAddInput(a, sit));
    const clo = try hex(a, "0029" ++ "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" ++ "0000" ++ "0000" ++ "00000000000000010000000201020a0b");
    defer a.free(clo);
    // (records: type 1, len 2) -> wrong length for a signature
    try testing.expectError(error.InvalidTlvLength, v2.decodeClosingSig(a, clo));
    const sb = try hex(a, wire.start_batch ++ "");
    defer a.free(sb);
    var ok = try v2.decodeStartBatch(a, sb);
    ok.deinit(a);
    // An unknown EVEN record is a decode error ("it's OK to be odd").
    const even = try hex(a, wire.tx_complete ++ "0400");
    defer a.free(even);
    try testing.expectError(error.UnknownEvenType, v2.decodeTxComplete(a, even));
    // An unknown ODD record is skipped (only the message's known records are returned).
    const odd = try hex(a, wire.tx_complete ++ "0501aa");
    defer a.free(odd);
    var m = try v2.decodeTxComplete(a, odd);
    defer m.deinit(a);
    try testing.expectEqual(@as(usize, 0), m.extension.records.len);
    // Encode side: a wrong-length record in a message is refused before anything is written.
    var recs = [_]message.tlv.RawRecord{.{ .type = 2, .value = &.{0xff} }};
    try testing.expectError(error.InvalidTlvLength, v2.serializeSpliceAck(a, .{
        .channel_id = cid,
        .funding_contribution_satoshis = 0,
        .funding_pubkey = @as([33]u8, @splat(2)),
        .extension = .{ .records = &recs },
    }));
}

test "variable-length fields over 65535 bytes are FieldTooLong, not truncated" {
    const a = testing.allocator;
    const big = try a.alloc(u8, 65536);
    defer a.free(big);
    @memset(big, 0);
    try testing.expectError(error.FieldTooLong, v2.serializeTxAbort(a, .{ .channel_id = cid, .data = big }));
    try testing.expectError(error.FieldTooLong, v2.serializeTxAddOutput(a, .{ .channel_id = cid, .serial_id = 0, .sats = 0, .script = big }));
}

/// The message of `hexs` decoded and serialized again with an empty trailing tlv_stream.
fn plainWire(comptime dec: anytype, comptime ser: anytype, a: Allocator, hexs: []const u8) ![]u8 {
    const b = try hex(a, hexs);
    defer a.free(b);
    var m = try dec(a, b);
    var ext = m.extension;
    ext.deinit(a);
    m.extension = .{};
    defer m.deinit(a);
    return ser(a, m);
}

test "mutation 2026-11-25: every known TLV rule refuses a wrong length in every message, decode and encode" {
    const a = testing.allocator;
    const zeros: [70]u8 = @splat(0);
    inline for (.{
        .{ wire.open_channel2, v2.decodeOpenChannel2, v2.serializeOpenChannel2, 2, 1 },
        .{ wire.accept_channel2, v2.decodeAcceptChannel2, v2.serializeAcceptChannel2, 2, 1 },
        .{ wire.tx_add_input, v2.decodeTxAddInput, v2.serializeTxAddInput, 0, 31 },
        .{ wire.tx_signatures, v2.decodeTxSignatures, v2.serializeTxSignatures, 0, 63 },
        .{ wire.tx_init_rbf, v2.decodeTxInitRbf, v2.serializeTxInitRbf, 0, 7 },
        .{ wire.tx_init_rbf, v2.decodeTxInitRbf, v2.serializeTxInitRbf, 2, 1 },
        .{ wire.tx_ack_rbf, v2.decodeTxAckRbf, v2.serializeTxAckRbf, 0, 7 },
        .{ wire.tx_ack_rbf, v2.decodeTxAckRbf, v2.serializeTxAckRbf, 2, 1 },
        .{ wire.splice_init, v2.decodeSpliceInit, v2.serializeSpliceInit, 2, 1 },
        .{ wire.splice_ack, v2.decodeSpliceAck, v2.serializeSpliceAck, 2, 1 },
        .{ wire.closing_complete, v2.decodeClosingComplete, v2.serializeClosingComplete, 1, 63 },
        .{ wire.closing_complete, v2.decodeClosingComplete, v2.serializeClosingComplete, 2, 63 },
        .{ wire.closing_complete, v2.decodeClosingComplete, v2.serializeClosingComplete, 3, 63 },
        .{ wire.closing_sig, v2.decodeClosingSig, v2.serializeClosingSig, 1, 65 },
        .{ wire.closing_sig, v2.decodeClosingSig, v2.serializeClosingSig, 2, 63 },
        .{ wire.closing_sig, v2.decodeClosingSig, v2.serializeClosingSig, 3, 65 },
        .{ wire.start_batch, v2.decodeStartBatch, v2.serializeStartBatch, 1, 1 },
    }) |c| {
        const plain = try plainWire(c[1], c[2], a, c[0]);
        defer a.free(plain);
        // decode: the record appended to the plain message
        const bad = try a.alloc(u8, plain.len + 2 + c[4]);
        defer a.free(bad);
        @memcpy(bad[0..plain.len], plain);
        bad[plain.len] = c[3];
        bad[plain.len + 1] = c[4];
        @memset(bad[plain.len + 2 ..], 0);
        try testing.expectError(error.InvalidTlvLength, c[1](a, bad));
        // encode: the same record in the struct
        var m = try c[1](a, plain);
        var recs = [_]message.tlv.RawRecord{.{ .type = c[3], .value = zeros[0..c[4]] }};
        m.extension.deinit(a);
        m.extension = .{ .records = &recs };
        try testing.expectError(error.InvalidTlvLength, c[2](a, m));
        m.extension = .{};
        m.deinit(a);
    }
}

fn txSigFrame(a: Allocator, n: u16, tail: usize) ![]u8 {
    const b = try a.alloc(u8, 2 + 32 + 32 + 2 + tail);
    @memset(b, 0);
    std.mem.writeInt(u16, b[0..2], v2.TX_SIGNATURES_TYPE, .big);
    std.mem.writeInt(u16, b[66..68], n, .big);
    return b;
}

test "mutation 2026-11-25: tx_signatures count bound: exactly n*2 bytes decode, a larger count is refused before allocating" {
    const a = testing.allocator;
    // n empty witnesses need exactly 2n bytes: the boundary is allowed
    const exact = try txSigFrame(a, 2, 4);
    defer a.free(exact);
    var m = try v2.decodeTxSignatures(a, exact);
    try testing.expectEqual(@as(usize, 2), m.witnesses.len);
    m.deinit(a);
    // 3 witnesses cannot fit in 4 bytes: Truncated without any allocation (a failing allocator
    // would turn an allocation attempt into OutOfMemory)
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const few = try txSigFrame(a, 3, 4);
    defer a.free(few);
    try testing.expectError(error.Truncated, v2.decodeTxSignatures(failing.allocator(), few));
    const huge = try txSigFrame(a, 0xffff, 0);
    defer a.free(huge);
    try testing.expectError(error.Truncated, v2.decodeTxSignatures(failing.allocator(), huge));
}

test "mutation 2026-11-25: tx_signatures encodes 65535 witnesses, refuses 65536" {
    const a = testing.allocator;
    const wits = try a.alloc([]const u8, 65536);
    defer a.free(wits);
    for (wits) |*w| w.* = &.{};
    const ok = try v2.serializeTxSignatures(a, .{ .channel_id = cid, .txid = txid, .witnesses = wits[0..65535] });
    defer a.free(ok);
    try testing.expectEqual(@as(usize, 2 + 32 + 32 + 2 + 65535 * 2), ok.len);
    try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, ok[66..68], .big));
    try testing.expectError(error.FieldTooLong, v2.serializeTxSignatures(a, .{ .channel_id = cid, .txid = txid, .witnesses = wits }));
}

test "mutation 2026-11-25: splice_ack keeps the sign of a negative contribution on the wire and back" {
    const a = testing.allocator;
    const b = try v2.serializeSpliceAck(a, .{ .channel_id = cid, .funding_contribution_satoshis = -5, .funding_pubkey = @as([33]u8, @splat(2)) });
    defer a.free(b);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb }, b[34..42]);
    var m = try v2.decodeSpliceAck(a, b);
    defer m.deinit(a);
    try testing.expectEqual(@as(i64, -5), m.funding_contribution_satoshis);
}
