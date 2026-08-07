// SPDX-License-Identifier: MIT
//! Legacy sighash: byte-exact against `legacy_kat_vectors.zig` (sourced
//! from Bitcoin Core's own `sighash.json`, the reference-oracle fixture).

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const legacy = @import("sighash_legacy.zig");
const vectors = @import("legacy_kat_vectors.zig");
const testutil = @import("testutil.zig");

test "legacy sighash: byte-exact against every sighash.json vector (ALL/NONE/SINGLE x plain/ANYONECANPAY)" {
    const allocator = testing.allocator;
    for (vectors.vectors) |v| {
        const raw = try testutil.hexToBytesAlloc(allocator, v.raw_tx_hex);
        defer allocator.free(raw);
        const script_code = try testutil.hexToBytesAlloc(allocator, v.script_code_hex);
        defer allocator.free(script_code);
        const want = testutil.hexToArray(32, v.expected_sighash_hex);

        var t = try tx.deserialize(allocator, raw);
        defer t.deinit(allocator);

        const got = try legacy.sighash(allocator, t, v.input_index, script_code, v.hash_type);
        testing.expectEqualSlices(u8, &want, &got) catch |err| {
            std.debug.print("FAILED vector: {s}\n", .{v.comment});
            return err;
        };
    }
}

test "teeth: corrupting one byte of a vector's expected sighash makes the byte-exact comparison fail" {
    // Proves this KAT can actually detect a wrong answer, not just echo
    // whatever bytes `sighash` computes (a degenerate oracle would pass no
    // matter what). Mirrors the manual demonstration performed against the
    // vendored fixture file itself (flip one byte, confirm RED, restore,
    // confirm md5 matches the original) -- this is the permanent, automated
    // version of that same check, run against an in-memory copy so it never
    // needs the fixture file to be (even transiently) wrong on disk.
    const allocator = testing.allocator;
    const v = vectors.vectors[0];
    const raw = try testutil.hexToBytesAlloc(allocator, v.raw_tx_hex);
    defer allocator.free(raw);
    const script_code = try testutil.hexToBytesAlloc(allocator, v.script_code_hex);
    defer allocator.free(script_code);

    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    const got = try legacy.sighash(allocator, t, v.input_index, script_code, v.hash_type);

    // Control: the real recorded expectation matches (guards against the
    // corruption step below being silently skipped).
    var want = testutil.hexToArray(32, v.expected_sighash_hex);
    try testing.expectEqualSlices(u8, &want, &got);

    // Flip one byte of a LOCAL copy of the expectation and confirm the
    // comparison now fails closed.
    want[31] ^= 0x01;
    try testing.expect(!std.mem.eql(u8, &want, &got));
}

test "the sighash corpus is the whole file, and reaches the OP_CODESEPARATOR path" {
    // Corpus-shape sanity: a truncated or re-filtered vectors file must not
    // pass with reduced coverage. Counted on upstream v29.0's `sighash.json`:
    // 501 array entries, 1 header comment, 500 data rows, of which exactly 210
    // carry a raw 0xab byte in the `script` column — and, measured, all 210 of
    // those are real OP_CODESEPARATOR opcodes rather than push payload.
    try testing.expectEqual(@as(usize, 500), vectors.vectors.len);
    var with_separator: usize = 0;
    for (vectors.vectors) |v| {
        var i: usize = 0;
        while (i + 1 < v.script_code_hex.len) : (i += 2) {
            if (std.ascii.eqlIgnoreCase(v.script_code_hex[i .. i + 2], "ab")) {
                with_separator += 1;
                break;
            }
        }
    }
    try testing.expectEqual(@as(usize, 210), with_separator);
}
