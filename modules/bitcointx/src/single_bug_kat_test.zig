// SPDX-License-Identifier: MIT
//! The SIGHASH_SINGLE boundary, byte-exact against `single_bug_kat_vectors.zig`
//! (python-bitcoinlib's `RawSignatureHash` -- the corner Core's `sighash.json`
//! leaves untested; see that file's doc comment).

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const legacy = @import("sighash_legacy.zig");
const vectors = @import("single_bug_kat_vectors.zig");
const testutil = @import("testutil.zig");

test "SIGHASH_SINGLE boundary: byte-exact against an oracle from outside this repo" {
    const allocator = testing.allocator;
    var saw_bug: usize = 0;
    var saw_normal: usize = 0;
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
        if (std.mem.eql(u8, &want, &legacy.sighash_single_bug)) saw_bug += 1 else saw_normal += 1;
    }
    // The set has to straddle the boundary, or "always take the bug path" and
    // "never take it" would each pass half of it unnoticed.
    try testing.expect(saw_bug >= 2);
    try testing.expect(saw_normal >= 2);
}
