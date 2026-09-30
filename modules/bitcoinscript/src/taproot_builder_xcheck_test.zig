// SPDX-License-Identifier: MIT
//! Cross-check: the `taproot` script-tree BUILDER against this module's
//! consensus VERIFIER (`tapscript.tapleafHash`/`verifyCommitment`). `taproot`
//! is a test-only dependency here; production code does not import it.
//!
//! For the BIP341 vector trees and for deterministic pseudo-random trees (up
//! to depth 8, mixed leaf versions and script sizes): the leaf hashes agree,
//! every leaf's control block verifies against the output key, and flipping
//! any single path/internal-key byte, the parity bit, or the script is
//! rejected.

const std = @import("std");
const bip340 = @import("bip340");
const taproot = @import("taproot");
const tapscript = @import("tapscript.zig");
const vectors = taproot.tree_vectors;

const testing = std.testing;
const ta = testing.allocator;

/// Verify every leaf of `info`; flip each control-block byte (path, internal
/// key) and the parity bit in turn and require rejection.
fn checkInfo(info: taproot.SpendInfo) !void {
    const q = info.output.x;
    for (info.leaves, 0..) |leaf, i| {
        try testing.expectEqualSlices(u8, &tapscript.tapleafHash(leaf.version, leaf.script), &leaf.leaf_hash);
        const cb = try info.controlBlockAlloc(ta, i);
        defer ta.free(cb);
        try testing.expect(tapscript.controlBlockValid(cb));
        try testing.expect(tapscript.verifyCommitment(&q, cb, leaf.script));

        // Parity bit.
        cb[0] ^= 1;
        try testing.expect(!tapscript.verifyCommitment(&q, cb, leaf.script));
        cb[0] ^= 1;
        // Path bytes (bytes 33.., one flip per node is enough: bit 0 of its
        // first byte) plus one flip in the internal key's last byte, which
        // changes P (possibly to a non-point: still must reject).
        var k: usize = 33;
        while (k < cb.len) : (k += 32) {
            cb[k] ^= 0x01;
            try testing.expect(!tapscript.verifyCommitment(&q, cb, leaf.script));
            cb[k] ^= 0x01;
        }
        cb[32] ^= 0x01;
        try testing.expect(!tapscript.verifyCommitment(&q, cb, leaf.script));
        cb[32] ^= 0x01;
        // Still fine after restoring, and a different script is rejected.
        try testing.expect(tapscript.verifyCommitment(&q, cb, leaf.script));
        try testing.expect(!tapscript.verifyCommitment(&q, cb, "\x00 not the committed script"));
    }
}

fn hex32(hex: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

test "xcheck: BIP341 vector trees — builder output passes the consensus verifier" {
    for (vectors.rows) |row| {
        const internal = try bip340.XOnlyPublicKey.fromBytes(try hex32(row.internal_pubkey));
        var info = try taproot.buildFromLeaves(ta, internal, row.leaves);
        defer info.deinit(ta);
        try checkInfo(info);
    }
}

/// A random complete binary tree as a depth-first list: split recursively
/// with probability, bounded by `max_depth`.
fn genTree(rng: std.Random, arena: std.mem.Allocator, out: *std.ArrayList(taproot.DepthLeaf), depth: u8, max_depth: u8) !void {
    if (depth >= max_depth or (depth > 0 and rng.uintLessThan(u8, 4) == 0)) {
        const len = switch (rng.uintLessThan(u8, 4)) {
            0 => 0,
            1 => rng.uintLessThan(usize, 40),
            2 => 250 + rng.uintLessThan(usize, 10), // straddles the 0xfd CompactSize boundary
            else => rng.uintLessThan(usize, 400),
        };
        const script = try arena.alloc(u8, len);
        rng.bytes(script);
        // Even versions, never 0x50.
        var ver: u8 = if (rng.boolean()) 0xc0 else rng.int(u8) & 0xfe;
        if (ver == 0x50) ver = 0x52;
        try out.append(arena, .{ .depth = depth, .version = ver, .script = script });
        return;
    }
    try genTree(rng, arena, out, depth + 1, max_depth);
    try genTree(rng, arena, out, depth + 1, max_depth);
}

test "xcheck: deterministic random trees up to depth 8" {
    var prng = std.Random.DefaultPrng.init(0x7461_7072_6f6f_74);
    const rng = prng.random();
    // A fixed valid internal key (row 1 of the BIP341 vectors).
    const internal = try bip340.XOnlyPublicKey.fromBytes(try hex32(vectors.rows[0].internal_pubkey));
    var trees: usize = 0;
    while (trees < 24) : (trees += 1) {
        var arena_state = std.heap.ArenaAllocator.init(ta);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var list: std.ArrayList(taproot.DepthLeaf) = .empty;
        // Force at least one split so most trees have several leaves.
        try genTree(rng, arena, &list, 0, 1 + rng.uintLessThan(u8, 8));
        var info = try taproot.buildFromLeaves(ta, internal, list.items);
        defer info.deinit(ta);
        try checkInfo(info);
    }
}
