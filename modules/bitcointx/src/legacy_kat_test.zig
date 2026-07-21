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
