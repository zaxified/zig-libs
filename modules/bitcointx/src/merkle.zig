// SPDX-License-Identifier: MIT
//! Block Merkle roots (over txids and over wtxids), the BIP141 witness
//! commitment, and the checks a block header needs: Bitcoin Core's
//! `ComputeMerkleRoot(hashes, &mutated)`, `BlockMerkleRoot`,
//! `BlockWitnessMerkleRoot` and `CheckWitnessCommitment`/`GetWitnessCommitmentIndex`
//! (`src/consensus/merkle.cpp`, `src/validation.cpp`, `src/validation.h`), and
//! rust-bitcoin's `Block::check_merkle_root` / `check_witness_commitment`.
//!
//! ## The tree
//!
//! Leaves are 32-octet hashes in internal (wire) order; an inner node is
//! `sha256d(left || right)`; a level with an odd number of nodes pairs its last
//! node with itself. One leaf is its own root; no leaves give the all-zero hash
//! (Core's `ComputeMerkleRoot` of an empty vector). The root of a block is over
//! `txid`s; the witness root is over `wtxid`s with the coinbase's leaf forced to
//! all zero (BIP141).
//!
//! ## CVE-2012-2459 (duplicate-txid mutation)
//!
//! The duplicate-last-on-odd rule makes the list `[a, b, c]` and `[a, b, c, c]`
//! hash to the same root, so a block with a repeated trailing transaction has a
//! valid-looking header although it is not the block the header commits to (and
//! can be used to poison a node's "known invalid" cache). Core detects it by
//! flagging any level where two REAL neighbours (not the padding copy) are equal;
//! every function here returns that flag as `mutated`, and the block-level
//! `checkMerkleRoot` refuses it (Core's `CheckBlock`: "bad-txns-duplicate").
//!
//! ## Allocation
//!
//! The tree is folded as it is read with a 64-entry stack (`MerkleBuilder`,
//! about 2 KiB, on the caller's stack): the leaves are never copied and the
//! cost is one `sha256d` per node. Only the per-transaction `txid`/`wtxid`
//! serialization uses the caller's allocator.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tx_mod = @import("tx.zig");
const hash256 = @import("hash256.zig");
const Transaction = tx_mod.Transaction;

pub const Hash = [32]u8;

pub const MerkleResult = struct {
    root: Hash,
    /// True when two real (non-padding) neighbours at some level were equal --
    /// the CVE-2012-2459 shape. The root is still the one Core computes.
    mutated: bool,
};

fn hashPair(a: *const Hash, b: *const Hash) Hash {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], a);
    @memcpy(buf[32..64], b);
    return hash256.sha256d(&buf);
}

/// Incremental Merkle fold: `push` the leaves in order, then `finish`. Holds a
/// stack of complete-subtree roots (a binary counter), so memory is `O(log n)`.
pub const MerkleBuilder = struct {
    nodes: [64]Hash = undefined,
    levels: [64]u8 = undefined,
    len: usize = 0,
    mutated: bool = false,

    pub fn push(self: *MerkleBuilder, leaf: Hash) void {
        self.nodes[self.len] = leaf;
        self.levels[self.len] = 0;
        self.len += 1;
        // Two complete subtrees of the same height are real neighbours: join.
        while (self.len >= 2 and self.levels[self.len - 1] == self.levels[self.len - 2]) {
            const l = &self.nodes[self.len - 2];
            const r = &self.nodes[self.len - 1];
            if (std.mem.eql(u8, l, r)) self.mutated = true;
            self.nodes[self.len - 2] = hashPair(l, r);
            self.levels[self.len - 2] += 1;
            self.len -= 1;
        }
    }

    /// The root over everything pushed so far (zero hash if nothing was).
    pub fn finish(self: MerkleBuilder) MerkleResult {
        if (self.len == 0) return .{ .root = @splat(0), .mutated = false };
        var mutated = self.mutated;
        var i = self.len - 1;
        var h = self.nodes[i];
        var lvl = self.levels[i];
        while (i > 0) {
            i -= 1;
            // The odd node at this level is paired with itself until it reaches
            // the height of the next complete subtree to its left (padding: never
            // a mutation).
            while (lvl < self.levels[i]) : (lvl += 1) h = hashPair(&h, &h);
            if (std.mem.eql(u8, &self.nodes[i], &h)) mutated = true;
            h = hashPair(&self.nodes[i], &h);
            lvl += 1;
        }
        return .{ .root = h, .mutated = mutated };
    }
};

/// Merkle root over ready-made leaves.
pub fn rootOfHashes(hashes: []const Hash) MerkleResult {
    var b: MerkleBuilder = .{};
    for (hashes) |h| b.push(h);
    return b.finish();
}

/// Block Merkle root: over the `txid` of each transaction (Core
/// `BlockMerkleRoot`). Empty list: zero root.
pub fn txidRoot(allocator: Allocator, txs: []const Transaction) Allocator.Error!MerkleResult {
    var b: MerkleBuilder = .{};
    for (txs) |t| b.push(try t.txid(allocator));
    return b.finish();
}

/// Witness Merkle root (BIP141, Core `BlockWitnessMerkleRoot`): over the `wtxid`
/// of each transaction, the first (coinbase) leaf replaced by 32 zero octets
/// whatever `txs[0]` holds.
pub fn wtxidRoot(allocator: Allocator, txs: []const Transaction) tx_mod.SerializeError!MerkleResult {
    var b: MerkleBuilder = .{};
    for (txs, 0..) |t, i| b.push(if (i == 0) @as(Hash, @splat(0)) else try t.wtxid(allocator));
    return b.finish();
}

pub const MerkleCheckError = Allocator.Error || error{
    /// The computed root differs from the header's (Core "bad-txnmrklroot").
    MerkleRootMismatch,
    /// The root matches but the list is a CVE-2012-2459 mutation (Core
    /// "bad-txns-duplicate").
    DuplicateTransactions,
};

/// Header check, as Core's `CheckBlock` and rust-bitcoin's `check_merkle_root`:
/// `txs`' txid root must equal `header_merkle_root` (the 32 octets at offset 36
/// of the 80-octet header, wire order) AND the list must not be a duplicate-tail
/// mutation. An empty `txs` has the zero root and therefore only matches a zero
/// header field; a real block has at least its coinbase, which is the caller's
/// (consensus) check to make.
pub fn checkMerkleRoot(allocator: Allocator, txs: []const Transaction, header_merkle_root: Hash) MerkleCheckError!void {
    const r = try txidRoot(allocator, txs);
    if (!std.mem.eql(u8, &r.root, &header_merkle_root)) return error.MerkleRootMismatch;
    if (r.mutated) return error.DuplicateTransactions;
}

/// BIP141: the 4-octet tag after `OP_RETURN OP_PUSHBYTES_36` that marks the
/// commitment output.
pub const COMMITMENT_HEADER = [4]u8{ 0xaa, 0x21, 0xa9, 0xed };
/// `OP_RETURN (1) + push-36 (1) + header (4) + commitment (32)`.
pub const MIN_COMMITMENT_SCRIPT_LEN: usize = 38;

/// Index of the coinbase output carrying the witness commitment, as Core's
/// `GetWitnessCommitmentIndex`: the LAST output whose scriptPubKey is at least 38
/// octets and starts `6a 24 aa21a9ed` (BIP141: "if there are more than one ... the
/// one with highest output index is assumed to be the commitment"). Null if none.
/// The commitment is `script_pubkey[6..38]`.
pub fn witnessCommitmentIndex(coinbase: Transaction) ?usize {
    var found: ?usize = null;
    for (coinbase.vout, 0..) |o, i| {
        const s = o.script_pubkey;
        if (s.len >= MIN_COMMITMENT_SCRIPT_LEN and s[0] == 0x6a and s[1] == 0x24 and
            std.mem.eql(u8, s[2..6], &COMMITMENT_HEADER)) found = i;
    }
    return found;
}

/// BIP141: `sha256d(witness_root || reserved_value)`, the 32 octets the coinbase
/// commits to. (Core `BlockWitnessMerkleRoot` + `GenerateCoinbaseCommitment`.)
pub fn witnessCommitment(witness_root: Hash, reserved_value: Hash) Hash {
    return hashPair(&witness_root, &reserved_value);
}

pub const WitnessCommitmentError = tx_mod.SerializeError || error{
    /// `txs` is empty.
    NoTransactions,
    /// `txs[0]` is not a coinbase transaction.
    NotCoinbase,
    /// The coinbase witness is not exactly one 32-octet reserved value (Core
    /// "bad-witness-nonce-size").
    BadWitnessNonce,
    /// The commitment output differs from `sha256d(witness root || reserved)`
    /// (Core "bad-witness-merkle-match").
    BadWitnessCommitment,
    /// No commitment output, yet some transaction carries witness data (Core
    /// "unexpected-witness").
    UnexpectedWitness,
};

/// Core's `CheckWitnessCommitment` (the witness half of `ContextualCheckBlock`;
/// rust-bitcoin's `Block::check_witness_commitment`), for a block whose height is
/// past segwit activation. With a commitment output: the coinbase's witness must be
/// the single 32-octet reserved value and `witnessCommitment(wtxidRoot, reserved)`
/// must equal the output's payload. Without one the block is valid only if no
/// transaction has witness data (rust-bitcoin returns plain false in that case;
/// use `witnessCommitmentIndex` to tell the two apart). The witness root's
/// `mutated` flag is ignored, as Core does.
pub fn checkWitnessCommitment(allocator: Allocator, txs: []const Transaction) WitnessCommitmentError!void {
    if (txs.len == 0) return error.NoTransactions;
    const cb = txs[0];
    if (!cb.isCoinbase()) return error.NotCoinbase;
    const idx = witnessCommitmentIndex(cb) orelse {
        for (txs) |t| if (t.hasWitnessData()) return error.UnexpectedWitness;
        return;
    };
    if (cb.witness.len != 1 or cb.witness[0].items.len != 1 or cb.witness[0].items[0].len != 32)
        return error.BadWitnessNonce;
    const reserved: Hash = cb.witness[0].items[0][0..32].*;
    const root = (try wtxidRoot(allocator, txs)).root;
    const want = witnessCommitment(root, reserved);
    if (!std.mem.eql(u8, &want, cb.vout[idx].script_pubkey[6..38])) return error.BadWitnessCommitment;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("merkle_kat_vectors.zig");
const testutil = @import("testutil.zig");

/// Straight transcription of the textbook algorithm (Core's `ComputeMerkleRoot`
/// shape: level-by-level over a vector) -- the oracle the streaming fold is
/// compared against.
fn referenceRoot(allocator: Allocator, leaves: []const Hash) !MerkleResult {
    if (leaves.len == 0) return .{ .root = @splat(0), .mutated = false };
    var cur = try allocator.dupe(Hash, leaves);
    defer allocator.free(cur);
    var n = cur.len;
    var mutated = false;
    while (n > 1) {
        var p: usize = 0;
        while (p + 1 < n) : (p += 2) if (std.mem.eql(u8, &cur[p], &cur[p + 1])) {
            mutated = true;
        };
        if (n & 1 == 1) {
            cur = try allocator.realloc(cur, n + 1);
            cur[n] = cur[n - 1];
            n += 1;
        }
        var i: usize = 0;
        while (i < n) : (i += 2) cur[i / 2] = hashPair(&cur[i], &cur[i + 1]);
        n /= 2;
    }
    return .{ .root = cur[0], .mutated = mutated };
}

test "merkle: streaming fold equals the level-by-level reference for 0..70 leaves, distinct and repeated" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x2012_2459);
    const rnd = prng.random();
    var leaves: [70]Hash = undefined;
    for (&leaves) |*l| rnd.bytes(l);
    var n: usize = 0;
    while (n <= 70) : (n += 1) {
        const got = rootOfHashes(leaves[0..n]);
        const want = try referenceRoot(a, leaves[0..n]);
        try testing.expectEqualSlices(u8, &want.root, &got.root);
        try testing.expectEqual(false, got.mutated);
        try testing.expectEqual(false, want.mutated);
        // Duplicate a leaf at every position: both flag exactly the same inputs.
        var j: usize = 0;
        while (j + 1 < n) : (j += 1) {
            var d = leaves;
            d[j + 1] = d[j];
            const g = rootOfHashes(d[0..n]);
            const w = try referenceRoot(a, d[0..n]);
            try testing.expectEqualSlices(u8, &w.root, &g.root);
            try testing.expectEqual(w.mutated, g.mutated);
        }
    }
}

test "merkle: boundary shapes" {
    const x: Hash = @splat(1);
    const y: Hash = @splat(2);
    const z: Hash = @splat(3);
    // empty: zero root, not mutated
    const e = rootOfHashes(&.{});
    try testing.expectEqual(@as(Hash, @splat(0)), e.root);
    try testing.expectEqual(false, e.mutated);
    // one leaf is its own root
    try testing.expectEqual(x, rootOfHashes(&.{x}).root);
    // two leaves
    try testing.expectEqual(hashPair(&x, &y), rootOfHashes(&.{ x, y }).root);
    // three leaves: the odd one is paired with itself
    const xy = hashPair(&x, &y);
    const zz = hashPair(&z, &z);
    const r3 = rootOfHashes(&.{ x, y, z });
    try testing.expectEqual(hashPair(&xy, &zz), r3.root);
    try testing.expectEqual(false, r3.mutated);
}

test "merkle: CVE-2012-2459 - [a,b,c] and [a,b,c,c] share a root, only the second is mutated" {
    const a: Hash = @splat(0x0a);
    const b: Hash = @splat(0x0b);
    const c: Hash = @splat(0x0c);
    const r3 = rootOfHashes(&.{ a, b, c });
    const r4 = rootOfHashes(&.{ a, b, c, c });
    try testing.expectEqual(r3.root, r4.root);
    try testing.expectEqual(false, r3.mutated);
    try testing.expectEqual(true, r4.mutated);
    // A repeat in the MIDDLE of a level is just as much a mutation ...
    try testing.expectEqual(true, rootOfHashes(&.{ a, a, b, c }).mutated);
    // ... and so are equal subtrees, not only equal leaves: [a,b,a,b] pairs the
    // identical (a,b) subtrees at level 1.
    try testing.expectEqual(true, rootOfHashes(&.{ a, b, a, b }).mutated);
    // Padding is not a pair: a lone odd leaf never trips the flag.
    try testing.expectEqual(false, rootOfHashes(&.{ a, b, c, a, b }).mutated);
}

const Block = struct {
    header: []const u8,
    txs: []Transaction,

    fn parse(allocator: Allocator, raw: []const u8) !Block {
        const n = try tx_mod.decodeCompactSize(raw[80..]);
        var list: std.ArrayList(Transaction) = .empty;
        errdefer {
            for (list.items) |*t| t.deinit(allocator);
            list.deinit(allocator);
        }
        var off: usize = 80 + n.consumed;
        var i: u64 = 0;
        while (i < n.value) : (i += 1) {
            const r = try tx_mod.deserializePartial(allocator, raw[off..]);
            try list.append(allocator, r.tx);
            off += r.consumed;
        }
        try testing.expectEqual(raw.len, off);
        return .{ .header = raw[0..80], .txs = try list.toOwnedSlice(allocator) };
    }

    fn deinit(self: *Block, allocator: Allocator) void {
        for (self.txs) |*t| t.deinit(allocator);
        allocator.free(self.txs);
    }

    fn merkleRootField(self: Block) Hash {
        return self.header[36..68].*;
    }
};

test "block KAT: header merkle root = txid root for genesis, block 170 and a segwit block" {
    const a = testing.allocator;
    inline for (.{
        .{ vectors.genesis_hex, vectors.genesis_tx_count },
        .{ vectors.block170_hex, vectors.block170_tx_count },
        .{ vectors.block484435_hex, vectors.block484435_tx_count },
    }) |c| {
        const raw = try testutil.hexToBytesAlloc(a, c[0]);
        defer a.free(raw);
        var blk = try Block.parse(a, raw);
        defer blk.deinit(a);
        try testing.expectEqual(@as(usize, c[1]), blk.txs.len);
        const r = try txidRoot(a, blk.txs);
        try testing.expectEqualSlices(u8, &blk.merkleRootField(), &r.root);
        try testing.expectEqual(false, r.mutated);
        try checkMerkleRoot(a, blk.txs, blk.merkleRootField());
    }
}

test "block KAT: checkMerkleRoot refuses a wrong root and a duplicate-tail mutation" {
    const a = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(a, vectors.block484435_hex);
    defer a.free(raw);
    var blk = try Block.parse(a, raw);
    defer blk.deinit(a);
    var bad = blk.merkleRootField();
    bad[31] ^= 1;
    try testing.expectError(error.MerkleRootMismatch, checkMerkleRoot(a, blk.txs, bad));
    // Dropping the last transaction changes the root.
    try testing.expectError(error.MerkleRootMismatch, checkMerkleRoot(a, blk.txs[0 .. blk.txs.len - 1], blk.merkleRootField()));
    // A real 7-transaction prefix, then the same list with its last transaction
    // repeated: both have the 7-tx root, only the second is a mutation.
    const seven = blk.txs[0..7];
    const root7 = (try txidRoot(a, seven)).root;
    const mutated_list = try a.alloc(Transaction, 8);
    defer a.free(mutated_list);
    @memcpy(mutated_list[0..7], seven);
    mutated_list[7] = seven[6];
    try checkMerkleRoot(a, seven, root7);
    try testing.expectError(error.DuplicateTransactions, checkMerkleRoot(a, mutated_list, root7));
    const empty = try txidRoot(a, &.{});
    try testing.expectEqual(@as(Hash, @splat(0)), empty.root);
}

test "block KAT: wtxid root and BIP141 witness commitment (real segwit block)" {
    const a = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(a, vectors.block484435_hex);
    defer a.free(raw);
    var blk = try Block.parse(a, raw);
    defer blk.deinit(a);
    const want_wroot = testutil.hexToArray(32, vectors.block484435_witness_root_hex);
    const wr = try wtxidRoot(a, blk.txs);
    try testing.expectEqualSlices(u8, &want_wroot, &wr.root);
    // The wtxid root differs from the txid root: the coinbase leaf is zero.
    try testing.expect(!std.mem.eql(u8, &wr.root, &blk.merkleRootField()));

    const cb = blk.txs[0];
    try testing.expect(cb.isCoinbase());
    const idx = witnessCommitmentIndex(cb).?;
    const script = cb.vout[idx].script_pubkey;
    const reserved: Hash = cb.witness[0].items[0][0..32].*;
    const c = witnessCommitment(wr.root, reserved);
    try testing.expectEqualSlices(u8, script[6..38], &c);
    try checkWitnessCommitment(a, blk.txs);
}

test "block KAT: checkWitnessCommitment refusals" {
    const a = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(a, vectors.block484435_hex);
    defer a.free(raw);
    var blk = try Block.parse(a, raw);
    defer blk.deinit(a);

    try testing.expectError(error.NoTransactions, checkWitnessCommitment(a, &.{}));
    // First transaction not a coinbase.
    try testing.expectError(error.NotCoinbase, checkWitnessCommitment(a, blk.txs[1..]));
    // Dropping a transaction changes the witness root.
    try testing.expectError(error.BadWitnessCommitment, checkWitnessCommitment(a, blk.txs[0 .. blk.txs.len - 1]));

    // A different reserved value.
    var cb = blk.txs[0];
    var other: [32]u8 = cb.witness[0].items[0][0..32].*;
    other[0] ^= 0xff;
    var items = [_][]const u8{&other};
    var stacks = [_]tx_mod.Witness{.{ .items = &items }};
    cb.witness = &stacks;
    var txs_copy = try a.dupe(Transaction, blk.txs);
    defer a.free(txs_copy);
    txs_copy[0] = cb;
    try testing.expectError(error.BadWitnessCommitment, checkWitnessCommitment(a, txs_copy));

    // Wrong reserved-value length / count.
    var short_items = [_][]const u8{other[0..31]};
    stacks[0].items = &short_items;
    try testing.expectError(error.BadWitnessNonce, checkWitnessCommitment(a, txs_copy));
    var two_items = [_][]const u8{ &other, &other };
    stacks[0].items = &two_items;
    try testing.expectError(error.BadWitnessNonce, checkWitnessCommitment(a, txs_copy));
    stacks[0].items = &.{};
    try testing.expectError(error.BadWitnessNonce, checkWitnessCommitment(a, txs_copy));
}

test "block KAT: no commitment output - legacy blocks pass, a witness-carrying one is refused" {
    const a = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(a, vectors.block170_hex);
    defer a.free(raw);
    var blk = try Block.parse(a, raw);
    defer blk.deinit(a);
    try testing.expectEqual(@as(?usize, null), witnessCommitmentIndex(blk.txs[0]));
    try checkWitnessCommitment(a, blk.txs);

    // Same transactions, the second now carrying a witness item.
    var wit_items = [_][]const u8{"x"};
    var wits = [_]tx_mod.Witness{.{ .items = &.{} }};
    var t1 = blk.txs[1];
    try testing.expectEqual(@as(usize, 1), t1.vin.len);
    wits[0].items = &wit_items;
    t1.witness = &wits;
    t1.has_witness = true;
    const txs = [_]Transaction{ blk.txs[0], t1 };
    try testing.expectError(error.UnexpectedWitness, checkWitnessCommitment(a, &txs));
}

test "witnessCommitmentIndex: last matching output wins; short, wrong-tag and wrong-opcode scripts do not match" {
    var good: [38]u8 = @splat(0);
    good[0] = 0x6a;
    good[1] = 0x24;
    @memcpy(good[2..6], &COMMITMENT_HEADER);
    var tagbad = good;
    tagbad[5] ^= 1;
    var opbad = good;
    opbad[0] = 0x6b;
    var pushbad = good;
    pushbad[1] = 0x23;
    const outs = [_]tx_mod.TxOut{
        .{ .value = 0, .script_pubkey = &good },
        .{ .value = 0, .script_pubkey = good[0..37] },
        .{ .value = 0, .script_pubkey = &tagbad },
        .{ .value = 0, .script_pubkey = &opbad },
        .{ .value = 0, .script_pubkey = &pushbad },
    };
    var o = outs;
    var cb: Transaction = .{ .version = 1, .vin = &.{}, .vout = &o, .witness = &.{}, .locktime = 0, .has_witness = false };
    try testing.expectEqual(@as(?usize, 0), witnessCommitmentIndex(cb));
    // Longer script (extra data after the commitment) also matches, and a later match wins.
    var longer: [50]u8 = @splat(0);
    @memcpy(longer[0..38], &good);
    o[3] = .{ .value = 0, .script_pubkey = &longer };
    try testing.expectEqual(@as(?usize, 3), witnessCommitmentIndex(cb));
    cb.vout = o[1..3];
    try testing.expectEqual(@as(?usize, null), witnessCommitmentIndex(cb));
}
