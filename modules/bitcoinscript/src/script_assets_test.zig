// SPDX-License-Identifier: MIT
//! The whole of Bitcoin Core's BIP341/342 consensus corpus
//! `script_assets_test.json` (bitcoin-core/qa-assets, the file
//! `script_tests.cpp`'s `script_assets_test` runs; 2244 entries, 9.2 MB) as an
//! opt-in oracle: too big to vendor, so `tools/script_assets_fetch.sh`
//! downloads it (sha256-pinned) into a gitignored directory and this test runs
//! it when `BITCOINSCRIPT_SCRIPT_ASSETS` names the file. Unset, it is skipped;
//! `consensus_kat_vectors.zig` keeps five of its entries pinned in the tree.
//!
//! Each entry is a real transaction with all its prevouts, the flag set, and a
//! `success` witness/scriptSig pair that MUST verify and (for 1493 entries) a
//! `failure` pair, same transaction and flags, that MUST fail — the way Core's
//! runner treats them (`success` replaces the tested input's scriptSig and
//! witness; entries without `failure` have no negative counterpart).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const bitcointx = @import("bitcointx");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const kat = @import("consensus_kat_test.zig");

const env_name = "BITCOINSCRIPT_SCRIPT_ASSETS";

fn parseFlags(s: []const u8) !flags_mod.ScriptFlags {
    var f: flags_mod.ScriptFlags = .{};
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |name| {
        if (std.mem.eql(u8, name, "P2SH")) {
            f.p2sh = true;
        } else if (std.mem.eql(u8, name, "DERSIG")) {
            f.dersig = true;
        } else if (std.mem.eql(u8, name, "CHECKLOCKTIMEVERIFY")) {
            f.checklocktimeverify = true;
        } else if (std.mem.eql(u8, name, "CHECKSEQUENCEVERIFY")) {
            f.checksequenceverify = true;
        } else if (std.mem.eql(u8, name, "WITNESS")) {
            f.witness = true;
        } else if (std.mem.eql(u8, name, "NULLDUMMY")) {
            f.nulldummy = true;
        } else if (std.mem.eql(u8, name, "TAPROOT")) {
            f.taproot = true;
        } else return error.UnknownFlag;
    }
    return f;
}

fn witnessOf(a: std.mem.Allocator, v: std.json.Value) ![][]const u8 {
    const items = v.array.items;
    const out = try a.alloc([]const u8, items.len);
    for (items, 0..) |h, i| out[i] = try kat.hexDecode(a, h.string);
    return out;
}

/// Verifies input `index` of `tx` with `pair`'s scriptSig and witness.
fn runPair(
    a: std.mem.Allocator,
    tx: bitcointx.Transaction,
    spent: []const bitcointx.TxOut,
    index: usize,
    flags: flags_mod.ScriptFlags,
    pair: std.json.Value,
) !void {
    const script_sig = try kat.hexDecode(a, pair.object.get("scriptSig").?.string);
    const witness = try witnessOf(a, pair.object.get("witness").?);
    const ctx: txctx.TxContext = .{ .tx = tx, .input_index = index, .spent_outputs = spent };
    return verify.verifyScript(a, script_sig, spent[index].script_pubkey, witness, flags, ctx);
}

test "script_assets_test.json: every success pair verifies, every failure pair fails (opt-in oracle)" {
    const path = testkit.getEnv(env_name) orelse return error.SkipZigTest;
    var file_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer file_arena.deinit();
    const text = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, file_arena.allocator(), .limited(64 << 20));
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, file_arena.allocator(), text, .{});

    var n_fail_pairs: usize = 0;
    var bad: usize = 0;
    for (doc.array.items, 0..) |entry, n| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const comment = entry.object.get("comment").?.string;
        const tx = try bitcointx.deserialize(a, try kat.hexDecode(a, entry.object.get("tx").?.string));
        const prevouts = entry.object.get("prevouts").?.array.items;
        const spent = try a.alloc(bitcointx.TxOut, prevouts.len);
        for (prevouts, 0..) |p, i| spent[i] = try kat.decodePrevout(try kat.hexDecode(a, p.string));
        const index: usize = @intCast(entry.object.get("index").?.integer);
        const flags = try parseFlags(entry.object.get("flags").?.string);

        runPair(a, tx, spent, index, flags, entry.object.get("success").?) catch |err| {
            std.debug.print("\nASSETS entry {d} ({s}): success pair failed with error.{s}\n", .{ n, comment, @errorName(err) });
            bad += 1;
            continue;
        };
        if (entry.object.get("failure")) |failure| {
            n_fail_pairs += 1;
            if (runPair(a, tx, spent, index, flags, failure)) |_| {
                std.debug.print("\nASSETS entry {d} ({s}): failure pair verified\n", .{ n, comment });
                bad += 1;
            } else |_| {}
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expectEqual(@as(usize, 2244), doc.array.items.len);
    try testing.expectEqual(@as(usize, 1493), n_fail_pairs);
}
