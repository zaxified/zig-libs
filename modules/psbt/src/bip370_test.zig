// SPDX-License-Identifier: MIT
//! BIP370 (PSBT version 2): the BIP's own test vectors (24 invalid, 14 valid, 10
//! locktime cases), the Constructor, the combiner and the Finalizer/Extractor on a
//! version 2 PSBT built from BIP174's official finalize example.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const psbt = @import("root.zig");
const v2 = psbt.v2;
const vectors = @import("bip370_vectors.zig");
const kat = @import("kat_vectors.zig");

fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "BIP370 invalid vectors: every one is refused with the error its defect names" {
    for (vectors.invalid) |case| {
        const result = psbt.fromBase64(testing.allocator, case.b64);
        if (result) |r| {
            var owned = r;
            owned.deinit(testing.allocator);
            std.debug.print("FAIL (accepted): {s}\n", .{case.name});
            return error.TestUnexpectedSuccess;
        } else |err| testing.expectEqual(case.err, err) catch |e| {
            std.debug.print("FAIL: {s}: got {}\n", .{ case.name, err });
            return e;
        };
    }
}

test "BIP370 valid vectors: parsed as version 2, byte-exact round trip, transaction builds" {
    for (vectors.valid) |case| {
        var owned = psbt.fromBase64(testing.allocator, case.b64) catch |err| {
            std.debug.print("FAIL: {s}: {}\n", .{ case.name, err });
            return err;
        };
        defer owned.deinit(testing.allocator);
        try testing.expectEqual(@as(u32, 2), owned.psbt.psbtVersion());
        try testing.expect(owned.psbt.global.find(psbt.global_key.UNSIGNED_TX) == null);
        const again = try psbt.serialize(testing.allocator, owned.psbt);
        defer testing.allocator.free(again);
        try testing.expectEqualSlices(u8, owned.bytes, again);
        var tx = try owned.psbt.unsignedTx(testing.allocator);
        defer tx.deinit(testing.allocator);
        try testing.expectEqual(owned.psbt.inputs.len, tx.vin.len);
        try testing.expectEqual(owned.psbt.outputs.len, tx.vout.len);
        try testing.expectEqual(v2.txVersion(owned.psbt).?, tx.version);
    }
}

test "BIP370 locktime vectors: the computed nLockTime, and the one case that cannot be computed" {
    for (vectors.lock) |case| {
        var owned = try psbt.fromBase64(testing.allocator, case.b64);
        defer owned.deinit(testing.allocator);
        if (case.locktime) |want| {
            testing.expectEqual(want, try v2.lockTime(owned.psbt)) catch |e| {
                std.debug.print("FAIL: {s}\n", .{case.name});
                return e;
            };
            var tx = try owned.psbt.unsignedTx(testing.allocator);
            defer tx.deinit(testing.allocator);
            try testing.expectEqual(want, tx.locktime);
        } else {
            try testing.expectError(error.ConflictingLocktimes, v2.lockTime(owned.psbt));
            try testing.expectError(error.ConflictingLocktimes, owned.psbt.unsignedTx(testing.allocator));
        }
    }
}

test "BIP370 fields of the first valid vector read back" {
    var owned = try psbt.fromBase64(testing.allocator, vectors.valid[0].b64);
    defer owned.deinit(testing.allocator);
    const ps = owned.psbt;
    try testing.expectEqual(@as(i32, 2), v2.txVersion(ps).?);
    try testing.expectEqual(@as(?u32, null), v2.fallbackLocktime(ps));
    try testing.expectEqual(@as(?u8, null), v2.txModifiable(ps));
    try testing.expectEqual(@as(usize, 1), ps.inputs.len);
    try testing.expectEqual(@as(usize, 2), ps.outputs.len);
    try testing.expectEqual(@as(?u32, 0), v2.inputOutputIndex(ps.inputs[0]));
    try testing.expect(v2.inputPreviousTxid(ps.inputs[0]) != null);
    try testing.expectEqual(@as(?u32, null), v2.inputSequence(ps.inputs[0]));
    try testing.expect(v2.outputAmount(ps.outputs[0]) != null);
    try testing.expect(v2.outputScript(ps.outputs[1]) != null);
}

// ── hostile input ───────────────────────────────────────────────────────

fn rec(keytype: u64, value: []const u8) psbt.Record {
    return .{ .keytype = keytype, .keydata = &.{}, .value = value };
}

/// A version 2 global map with the given count values (raw bytes), then `maps` empty maps.
fn v2Bytes(allocator: Allocator, in_count: []const u8, out_count: []const u8, maps: usize) ![]u8 {
    var recs = [_]psbt.Record{
        rec(psbt.global_key.TX_VERSION, &.{ 2, 0, 0, 0 }),
        rec(psbt.global_key.INPUT_COUNT, in_count),
        rec(psbt.global_key.OUTPUT_COUNT, out_count),
        rec(psbt.global_key.VERSION, &.{ 2, 0, 0, 0 }),
    };
    const empties = try allocator.alloc(psbt.Map, maps);
    defer allocator.free(empties);
    for (empties) |*m| m.* = .{ .records = &.{} };
    return psbt.serialize(allocator, .{ .global = .{ .records = &recs }, .inputs = empties, .outputs = &.{} });
}

test "hostile: a huge or non-minimal input count is refused without allocating for it" {
    const big = try v2Bytes(testing.allocator, &.{ 0xfe, 0xff, 0xff, 0xff, 0x7f }, &.{0}, 0);
    defer testing.allocator.free(big);
    try testing.expectError(error.Truncated, psbt.parse(testing.allocator, big));
    const huge = try v2Bytes(testing.allocator, &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, &.{0}, 0);
    defer testing.allocator.free(huge);
    try testing.expectError(error.Truncated, psbt.parse(testing.allocator, huge));
    const nonminimal = try v2Bytes(testing.allocator, &.{ 0xfd, 0x01, 0x00 }, &.{0}, 0);
    defer testing.allocator.free(nonminimal);
    try testing.expectError(error.InvalidFixedFieldLength, psbt.parse(testing.allocator, nonminimal));
    const trailing = try v2Bytes(testing.allocator, &.{ 1, 0 }, &.{0}, 0);
    defer testing.allocator.free(trailing);
    try testing.expectError(error.InvalidFixedFieldLength, psbt.parse(testing.allocator, trailing));
    const empty = try v2Bytes(testing.allocator, &.{}, &.{0}, 0);
    defer testing.allocator.free(empty);
    try testing.expectError(error.InvalidFixedFieldLength, psbt.parse(testing.allocator, empty));
}

test "hostile: a count with fewer maps than declared is Truncated; a bare version 2 PSBT with no inputs or outputs parses" {
    const short = try v2Bytes(testing.allocator, &.{2}, &.{0}, 1);
    defer testing.allocator.free(short);
    try testing.expectError(error.Truncated, psbt.parse(testing.allocator, short));
    const none = try v2Bytes(testing.allocator, &.{0}, &.{0}, 0);
    defer testing.allocator.free(none);
    var ps = try psbt.parse(testing.allocator, none);
    defer ps.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ps.inputs.len);
    // No inputs: the transaction still builds (nothing in BIP370 forbids it).
    var tx = try ps.unsignedTx(testing.allocator);
    tx.deinit(testing.allocator);
}

test "version 2 field shapes: record-level refusals" {
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateGlobalRecord(rec(psbt.global_key.TX_VERSION, &.{ 2, 0, 0 })));
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateGlobalRecord(rec(psbt.global_key.TX_MODIFIABLE, &.{ 1, 0 })));
    try testing.expectError(error.UnexpectedKeyData, psbt.validateGlobalRecord(.{ .keytype = psbt.global_key.FALLBACK_LOCKTIME, .keydata = &.{0}, .value = &.{ 0, 0, 0, 0 } }));
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateInputRecord(rec(psbt.input_key.PREVIOUS_TXID, &@as([31]u8, @splat(0)))));
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateInputRecord(rec(psbt.input_key.SEQUENCE, &.{ 0, 0, 0 })));
    try testing.expectError(error.InvalidFixedFieldLength, psbt.validateOutputRecord(rec(psbt.output_key.AMOUNT, &@as([4]u8, @splat(0)))));
    // Locktime bounds: time >= 500000000; height 1..499999999.
    const t_ok = std.mem.toBytes(std.mem.nativeToLittle(u32, 500_000_000));
    const t_low = std.mem.toBytes(std.mem.nativeToLittle(u32, 499_999_999));
    const h_ok = std.mem.toBytes(std.mem.nativeToLittle(u32, 499_999_999));
    const h_zero = std.mem.toBytes(std.mem.nativeToLittle(u32, 0));
    const h_high = std.mem.toBytes(std.mem.nativeToLittle(u32, 500_000_000));
    try psbt.validateInputRecord(rec(psbt.input_key.REQUIRED_TIME_LOCKTIME, &t_ok));
    try testing.expectError(error.InvalidLocktime, psbt.validateInputRecord(rec(psbt.input_key.REQUIRED_TIME_LOCKTIME, &t_low)));
    try psbt.validateInputRecord(rec(psbt.input_key.REQUIRED_HEIGHT_LOCKTIME, &h_ok));
    try testing.expectError(error.InvalidLocktime, psbt.validateInputRecord(rec(psbt.input_key.REQUIRED_HEIGHT_LOCKTIME, &h_zero)));
    try testing.expectError(error.InvalidLocktime, psbt.validateInputRecord(rec(psbt.input_key.REQUIRED_HEIGHT_LOCKTIME, &h_high)));
    // VERSION: 0 and 2 only.
    try psbt.validateGlobalRecord(rec(psbt.global_key.VERSION, &.{ 0, 0, 0, 0 }));
    try psbt.validateGlobalRecord(rec(psbt.global_key.VERSION, &.{ 2, 0, 0, 0 }));
    try testing.expectError(error.UnsupportedPsbtVersion, psbt.validateGlobalRecord(rec(psbt.global_key.VERSION, &.{ 1, 0, 0, 0 })));
    try testing.expectError(error.UnsupportedPsbtVersion, psbt.validateGlobalRecord(rec(psbt.global_key.VERSION, &.{ 3, 0, 0, 0 })));
}

// ── Creator / Constructor ───────────────────────────────────────────────

const txid_a: [32]u8 = @splat(0xaa);
const txid_b: [32]u8 = @splat(0xbb);
const spk = [_]u8{ 0x00, 0x14 } ++ @as([20]u8, @splat(0x11));
const pk33 = [_]u8{0x02} ++ @as([32]u8, @splat(0x33));

test "Constructor: create, add two inputs and two outputs, serialize, parse back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ps = try v2.create(a, 2, 700_000, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 1, .sequence = 0xfffffffd });
    try v2.addInput(a, &ps, .{ .txid = txid_b, .vout = 0, .required_height_locktime = 800_000 });
    try v2.addOutput(a, &ps, 50_000, &spk);
    try v2.addOutput(a, &ps, 1_000, &.{0x6a});
    try testing.expectEqual(@as(usize, 2), ps.inputs.len);
    try testing.expectEqual(@as(usize, 2), ps.outputs.len);

    const wire = try psbt.serialize(a, ps);
    var back = try psbt.parse(testing.allocator, wire);
    defer back.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 2), back.psbtVersion());
    try testing.expectEqual(@as(?u32, 700_000), v2.fallbackLocktime(back));
    try testing.expectEqual(@as(?u8, 3), v2.txModifiable(back));

    var tx = try back.unsignedTx(testing.allocator);
    defer tx.deinit(testing.allocator);
    try testing.expectEqual(@as(i32, 2), tx.version);
    try testing.expectEqual(@as(u32, 800_000), tx.locktime); // the input's height lock beats the fallback
    try testing.expectEqualSlices(u8, &txid_a, &tx.vin[0].prevout.txid);
    try testing.expectEqual(@as(u32, 1), tx.vin[0].prevout.vout);
    try testing.expectEqual(@as(u32, 0xfffffffd), tx.vin[0].sequence);
    try testing.expectEqual(@as(u32, 0xffffffff), tx.vin[1].sequence);
    try testing.expectEqual(@as(i64, 50_000), tx.vout[0].value);
    try testing.expectEqualSlices(u8, &spk, tx.vout[0].script_pubkey);
    try testing.expectEqualSlices(u8, &.{0x6a}, tx.vout[1].script_pubkey);
}

test "Constructor: the modifiable flags gate additions; an absent flag means final" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var closed = try v2.create(a, 2, null, null);
    try testing.expectError(error.InputsNotModifiable, v2.addInput(a, &closed, .{ .txid = txid_a, .vout = 0 }));
    try testing.expectError(error.OutputsNotModifiable, v2.addOutput(a, &closed, 1, &spk));
    try testing.expectEqual(@as(usize, 0), closed.inputs.len);

    var only_in = try v2.create(a, 2, null, v2.modifiable_inputs);
    try v2.addInput(a, &only_in, .{ .txid = txid_a, .vout = 0 });
    try testing.expectError(error.OutputsNotModifiable, v2.addOutput(a, &only_in, 1, &spk));
    // Closing the transaction afterwards.
    try v2.setTxModifiable(a, &only_in, 0);
    try testing.expectError(error.InputsNotModifiable, v2.addInput(a, &only_in, .{ .txid = txid_b, .vout = 0 }));
    try testing.expectEqual(@as(usize, 1), only_in.inputs.len);

    var v0 = try psbt.parse(a, try hexToBytesAlloc(a, kat.finalize_combined_hex));
    try testing.expectError(error.NotPsbtV2, v2.addInput(a, &v0, .{ .txid = txid_a, .vout = 0 }));
    try testing.expectError(error.NotPsbtV2, v2.setTxModifiable(a, &v0, 1));
    try testing.expectError(error.NotPsbtV2, v2.setInputSequence(a, &v0, 0, 1));
}

test "Constructor: an input whose locktime kind conflicts is refused and nothing changes; a signed PSBT's locktime is protected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ps = try v2.create(a, 2, null, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 0, .required_height_locktime = 10_000 });
    try testing.expectError(error.ConflictingLocktimes, v2.addInput(a, &ps, .{ .txid = txid_b, .vout = 0, .required_time_locktime = 1_657_048_460 }));
    try testing.expectEqual(@as(usize, 1), ps.inputs.len);
    try testing.expectEqual(@as(u32, 10_000), try v2.lockTime(ps));
    // The count field is still 1.
    try testing.expectEqualSlices(u8, &.{1}, ps.global.find(psbt.global_key.INPUT_COUNT).?.value);
    // An input allowing both kinds combines; the height rule wins on a tie.
    try v2.addInput(a, &ps, .{ .txid = txid_b, .vout = 0, .required_height_locktime = 9_000, .required_time_locktime = 1_657_048_460 });
    try testing.expectEqual(@as(u32, 10_000), try v2.lockTime(ps));

    // Once an input is signed, no new input may move the locktime.
    try psbt.setInputPartialSig(a, &ps, 0, &pk33, &.{ 0x30, 0x01 });
    try testing.expectError(error.ChangesLocktime, v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 7, .required_height_locktime = 20_000 }));
    try testing.expectEqual(@as(usize, 2), ps.inputs.len);
    try testing.expectEqual(@as(u32, 10_000), try v2.lockTime(ps));
    // One that leaves it alone is fine.
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 8, .required_height_locktime = 5_000 });
    try testing.expectEqual(@as(usize, 3), ps.inputs.len);

    // The fallback is not consulted when an input constrains the locktime, so changing it is harmless; with
    // no constraint it is the locktime, and signatures protect it.
    try v2.setFallbackLocktime(a, &ps, 42);
    var free = try v2.create(a, 2, 5, v2.modifiable_inputs);
    try v2.addInput(a, &free, .{ .txid = txid_a, .vout = 0 });
    try psbt.setInputPartialSig(a, &free, 0, &pk33, &.{ 0x30, 0x01 });
    try testing.expectError(error.ChangesLocktime, v2.setFallbackLocktime(a, &free, 6));
    try testing.expectEqual(@as(?u32, 5), v2.fallbackLocktime(free));
    try testing.expectEqual(@as(u32, 5), try v2.lockTime(free));
}

test "Updater: setInputSequence, and an invalid locktime is refused by the Constructor" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ps = try v2.create(a, 2, null, v2.modifiable_inputs);
    try testing.expectError(error.InvalidLocktime, v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 0, .required_time_locktime = 5 }));
    try testing.expectEqual(@as(usize, 0), ps.inputs.len);
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 0 });
    try v2.setInputSequence(a, &ps, 0, 7);
    try testing.expectEqual(@as(?u32, 7), v2.inputSequence(ps.inputs[0]));
    try testing.expectError(error.InputIndexOutOfRange, v2.setInputSequence(a, &ps, 1, 7));
}

// ── combiner and unique id ──────────────────────────────────────────────

test "combine on version 2: same unique id merges (sequences may differ), different transactions and versions are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var p1 = try v2.create(a, 2, null, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &p1, .{ .txid = txid_a, .vout = 0, .sequence = 1 });
    try v2.addOutput(a, &p1, 5, &spk);
    var p2 = try v2.create(a, 2, null, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &p2, .{ .txid = txid_a, .vout = 0, .sequence = 2 });
    try v2.addOutput(a, &p2, 5, &spk);
    try psbt.setInputPartialSig(a, &p2, 0, &pk33, &.{ 0x30, 0x01 });

    const id1 = try v2.uniqueId(a, p1);
    const id2 = try v2.uniqueId(a, p2);
    try testing.expectEqualSlices(u8, &id1, &id2);

    const merged = try psbt.combine(a, p1, p2);
    try testing.expectEqual(@as(?u32, 1), v2.inputSequence(merged.inputs[0])); // first wins
    try testing.expect(merged.inputs[0].findKeyed(psbt.input_key.PARTIAL_SIG, &pk33) != null);

    var p3 = try v2.create(a, 2, null, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &p3, .{ .txid = txid_b, .vout = 0 });
    try v2.addOutput(a, &p3, 5, &spk);
    try testing.expectError(error.DifferentTransactions, psbt.combine(a, p1, p3));

    var p4 = try v2.create(a, 2, null, v2.modifiable_inputs | v2.modifiable_outputs);
    try v2.addInput(a, &p4, .{ .txid = txid_a, .vout = 0 });
    try testing.expectError(error.DifferentTransactions, psbt.combine(a, p1, p4)); // one output fewer

    const v0_raw = try hexToBytesAlloc(a, kat.finalize_combined_hex);
    const v0 = try psbt.parse(a, v0_raw);
    try testing.expectError(error.DifferentTransactions, psbt.combine(a, v0, p1));
}

/// Sets the flags byte of `p`, or drops the field when `flags` is null.
fn withFlags(a: std.mem.Allocator, p: *psbt.Psbt, flags: ?u8) !void {
    if (flags) |f| return v2.setTxModifiable(a, p, f);
    var keep: std.ArrayList(psbt.Record) = .empty;
    for (p.global.records) |r| {
        if (r.keytype != psbt.global_key.TX_MODIFIABLE) try keep.append(a, r);
    }
    p.global.records = try keep.toOwnedSlice(a);
}

test "combine on version 2 merges TX_MODIFIABLE as Bitcoin Core does: AND, except bit 2 which is OR" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cases = [_]struct { x: ?u8, y: ?u8, want: ?u8 }{
        .{ .x = 3, .y = 1, .want = 1 },
        .{ .x = 3, .y = 3, .want = 3 },
        .{ .x = 1, .y = 2, .want = 0 },
        .{ .x = 3, .y = 4, .want = 4 }, // bit 2 from either side
        .{ .x = 3 | 4, .y = 1, .want = 1 | 4 },
        .{ .x = 0x0b, .y = 0x03, .want = 3 }, // undefined bit 3 needs both
        .{ .x = null, .y = 3, .want = 0 }, // an absent field counts as 0
        .{ .x = 3, .y = null, .want = 0 },
        .{ .x = null, .y = 4, .want = 4 },
        .{ .x = null, .y = null, .want = null },
    };
    for (cases) |c| {
        var p1 = try v2.create(a, 2, null, 3);
        try v2.addInput(a, &p1, .{ .txid = txid_a, .vout = 0 });
        try withFlags(a, &p1, c.x);
        var p2 = try v2.create(a, 2, null, 3);
        try v2.addInput(a, &p2, .{ .txid = txid_a, .vout = 0 });
        try withFlags(a, &p2, c.y);
        const m = try psbt.combine(a, p1, p2);
        try testing.expectEqual(c.want, v2.txModifiable(m));
        // The result is symmetric.
        const m2 = try psbt.combine(a, p2, p1);
        try testing.expectEqual(c.want, v2.txModifiable(m2));
    }
}

// ── finalize / extract on version 2 ─────────────────────────────────────

test "a version 2 PSBT of BIP174's finalize example finalizes and extracts to the same transaction" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw = try hexToBytesAlloc(a, kat.finalize_combined_hex);
    const old = try psbt.parse(a, raw);
    const utx = try old.unsignedTx(a);

    // The same transaction as a version 2 PSBT: structure from the transaction, every other
    // record of each map copied.
    var ps = try v2.create(a, utx.version, utx.locktime, v2.modifiable_inputs | v2.modifiable_outputs);
    for (utx.vin) |vin| try v2.addInput(a, &ps, .{ .txid = vin.prevout.txid, .vout = vin.prevout.vout, .sequence = vin.sequence });
    for (utx.vout) |vout| try v2.addOutput(a, &ps, vout.value, vout.script_pubkey);
    for (old.inputs, ps.inputs) |src, *dst| for (src.records) |r| try dst.put(a, r);
    for (old.outputs, ps.outputs) |src, *dst| for (src.records) |r| try dst.put(a, r);
    try v2.setTxModifiable(a, &ps, 0);

    // The v2 PSBT round-trips and has the same unique-id shape (sequence-zeroed txid).
    const wire = try psbt.serialize(a, ps);
    const reparsed = try psbt.parse(a, wire);
    try testing.expectEqual(@as(u32, 2), reparsed.psbtVersion());

    const results_old = try psbt.finalize(a, old, .{});
    const results_new = try psbt.finalize(a, reparsed, .{});
    for (results_old, results_new) |o, n| {
        try testing.expect(o == null);
        try testing.expect(n == null);
    }
    // BIP370 §Input Finalizer: the version 2 input fields survive finalization.
    for (reparsed.inputs) |m| {
        try testing.expect(v2.inputPreviousTxid(m) != null);
        try testing.expect(v2.inputOutputIndex(m) != null);
        try testing.expect(m.find(psbt.input_key.FINAL_SCRIPTSIG) != null);
    }

    const tx_old = try psbt.extract(a, old);
    const tx_new = try psbt.extract(a, reparsed);
    const bytes_old = try bitcointx.serialize(a, tx_old);
    const bytes_new = try bitcointx.serialize(a, tx_new);
    try testing.expectEqualSlices(u8, bytes_old, bytes_new);
    const want = try hexToBytesAlloc(a, kat.finalize_extracted_tx_hex);
    try testing.expectEqualSlices(u8, want, bytes_new);
}

test "locktime rule: unit cases over hand-built inputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = try v2.create(a, 2, 77, v2.modifiable_inputs);
    try testing.expectEqual(@as(u32, 77), try v2.lockTime(ps)); // fallback, no inputs
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 0, .required_time_locktime = 600_000_000 });
    try testing.expectEqual(@as(u32, 600_000_000), try v2.lockTime(ps)); // time only
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 1 }); // unconstrained input
    try testing.expectEqual(@as(u32, 600_000_000), try v2.lockTime(ps));
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 2, .required_time_locktime = 700_000_000 });
    try testing.expectEqual(@as(u32, 700_000_000), try v2.lockTime(ps)); // maximum of the kind
    try v2.addInput(a, &ps, .{ .txid = txid_a, .vout = 3, .required_time_locktime = 650_000_000, .required_height_locktime = 3 });
    try testing.expectEqual(@as(u32, 700_000_000), try v2.lockTime(ps)); // time-only inputs rule out the height kind
}
