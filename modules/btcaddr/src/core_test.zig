// SPDX-License-Identifier: MIT
//! Bitcoin Core `key_io_valid.json` / `key_io_invalid.json` (via
//! `core_vectors.zig`, generated) run against the public API, in both
//! directions and on the row's own chain.

const std = @import("std");
const testing = std.testing;
const btcaddr = @import("root.zig");
const vectors = @import("core_vectors.zig");

fn network(c: vectors.Chain) btcaddr.Network {
    return switch (c) {
        .main => .mainnet,
        .testnet4 => .testnet,
        .signet => .signet,
        .regtest => .regtest,
    };
}

fn isBech32(s: []const u8) bool {
    var lower: [100]u8 = undefined;
    const n = @min(s.len, lower.len);
    for (s[0..n], 0..) |c, i| lower[i] = std.ascii.toLower(c);
    const l = lower[0..n];
    return std.mem.startsWith(u8, l, "bc1") or std.mem.startsWith(u8, l, "tb1") or
        std.mem.startsWith(u8, l, "bcrt1");
}

test "Core key_io_valid: address rows, both directions, right chain" {
    var n_addr: usize = 0;
    for (vectors.valid) |row| {
        if (row.is_privkey) continue;
        n_addr += 1;
        const net = network(row.chain);
        var want_buf: [btcaddr.max_script_len]u8 = undefined;
        const want = try std.fmt.hexToBytes(&want_buf, row.hex);

        // address -> scriptPubKey
        const d = try btcaddr.toScriptPubKey(row.string);
        try testing.expectEqualSlices(u8, want, d.script());
        try testing.expect(d.chains.contains(net));
        try testing.expectEqual(row.chain == .main, d.chains.contains(.mainnet));
        try testing.expectEqual(btcaddr.classify(want).?, d.kind);
        _ = try btcaddr.toScriptPubKeyFor(row.string, net);

        // scriptPubKey -> address on that chain
        const a = try btcaddr.fromScriptPubKey(want, net);
        try testing.expectEqualStrings(row.string, a.slice());

        // the same address is rejected on a network it is not valid on
        const other: btcaddr.Network = if (net == .mainnet) .testnet else .mainnet;
        try testing.expectError(error.WrongNetwork, btcaddr.toScriptPubKeyFor(row.string, other));

        // Core's case flip: a bech32 address is valid in all-upper case too
        if (row.try_case_flip and isBech32(row.string)) {
            var up: [btcaddr.max_address_len]u8 = undefined;
            const u = std.ascii.upperString(&up, row.string);
            const du = try btcaddr.toScriptPubKey(u);
            try testing.expectEqualSlices(u8, want, du.script());
        }

        // a WIF decoder must not accept an address
        var wd: btcaddr.Wif = undefined;
        if (btcaddr.wifDecode(&wd, row.string)) |_| return error.TestUnexpectedResult else |_| {}
    }
    try testing.expect(n_addr > 40);
}

test "Core key_io_valid: WIF rows, both directions, compressed flag" {
    var n_key: usize = 0;
    for (vectors.valid) |row| {
        if (!row.is_privkey) continue;
        n_key += 1;
        const net = network(row.chain);
        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, row.hex);

        var w: btcaddr.Wif = undefined;
        try btcaddr.wifDecode(&w, row.string);
        defer w.wipe();
        try testing.expectEqualSlices(u8, &key, &w.key);
        try testing.expectEqual(row.is_compressed, w.compressed);
        try testing.expect(w.chains.contains(net));
        try testing.expectEqual(row.chain == .main, w.chains.contains(.mainnet));

        var out: [btcaddr.max_wif_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        const s = try btcaddr.wifEncode(&key, row.is_compressed, net, &out);
        try testing.expectEqualStrings(row.string, s);

        // and a WIF string is not an address
        try testing.expectError(error.UnknownVersionByte, btcaddr.toScriptPubKey(row.string));
    }
    try testing.expect(n_key >= 15);
}

test "Core key_io_invalid: rejected as address and as WIF" {
    try testing.expect(vectors.invalid.len >= 70);
    for (vectors.invalid) |s| {
        if (btcaddr.toScriptPubKey(s)) |_| {
            std.debug.print("accepted as address: {s}\n", .{s});
            return error.TestUnexpectedResult;
        } else |_| {}
        var wd: btcaddr.Wif = undefined;
        if (btcaddr.wifDecode(&wd, s)) |_| {
            std.debug.print("accepted as WIF: {s}\n", .{s});
            return error.TestUnexpectedResult;
        } else |_| {}
        inline for (.{ btcaddr.Network.mainnet, .testnet, .signet, .regtest }) |net| {
            if (btcaddr.toScriptPubKeyFor(s, net)) |_| return error.TestUnexpectedResult else |_| {}
        }
    }
}
