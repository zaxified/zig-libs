// SPDX-License-Identifier: MIT
//! `TxContext.precomputed`: the consumer half of `bitcointx`'s
//! `PrecomputedTransactionData` seam.
//!
//! BIP143 and BIP341 exist because legacy sighashing made validation
//! **quadratic** in transaction size — an attacker who chose the transaction
//! chose the validation cost. Their per-transaction commitment hashes are the
//! fix, and `bitcointx` hoists them behind `*With` entry points. But "compute
//! once" is a property of the CALL PATTERN: a verifier that holds the cache and
//! never passes it is byte-exact against every published vector and still
//! `O(n²)`. `bitcoinscript` is that verifier, so the property has to be pinned
//! HERE, at the call sites, not only in `bitcointx`.
//!
//! Two oracles, because each is blind to what the other catches:
//!
//!  1. **Cost.** A deterministic counter, never a stopwatch (a complexity
//!     assertion made with a clock is a flaky test on a loaded box). The
//!     natural counter — `bitcointx`'s own `instrument.count()` — is not
//!     reachable from here (`instrument.zig` is private to that module), so
//!     this counts BYTES ALLOCATED while verifying one input instead. Every
//!     commitment hash serializes the whole transaction into a buffer first,
//!     so recomputing them is visible as allocation that scales with `vin`/
//!     `vout`, and hoisting them is visible as allocation that does not.
//!     `std.testing.FailingAllocator` with the default (never-fail) config is
//!     exactly that counter.
//!
//!  2. **Bytes.** Consensus code: faster is worthless if it is different. Real
//!     signatures over the UNCACHED sighashes, verified through the cached
//!     path, across all three switched call sites in ONE transaction.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const k256 = @import("k256");
const ripemd160 = @import("ripemd160");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const tapscript = @import("tapscript.zig");
const flags_mod = @import("flags.zig");

const EcdsaSecp256k1Sha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const SIGHASH_ALL: u32 = 1;

// ── 1. cost: verifying one input must not scale with transaction size ────

/// A signature that parses as DER and a 33-byte "pubkey" whose SEC1 prefix is
/// invalid. The sighash is computed BEFORE the curve check rejects the key, so
/// this exercises the full sighash path at negligible curve cost.
const parseable_sig = [_]u8{ 0x30, 0x44, 0x02, 0x20 } ++ [_]u8{0x11} ** 32 ++ [_]u8{ 0x02, 0x20 } ++ [_]u8{0x22} ** 32 ++ [_]u8{0x01};
const unparseable_pk = [_]u8{0x09} ++ [_]u8{0x07} ** 32;

const Kind = enum { segwit_v0, taproot_keypath, taproot_scriptpath };

fn buildWideTx(a: std.mem.Allocator, n: usize, spk: []const u8) !struct { tx: bitcointx.Transaction, spent: []bitcointx.TxOut } {
    const vin = try a.alloc(bitcointx.TxIn, n);
    for (vin, 0..) |*v, i| v.* = .{
        .prevout = .{ .txid = [_]u8{@truncate(i)} ** 32, .vout = @intCast(i) },
        .script_sig = &.{},
        .sequence = 0xfffffffe,
    };
    const vout = try a.alloc(bitcointx.TxOut, n);
    for (vout, 0..) |*o, i| o.* = .{ .value = @intCast(1000 + i), .script_pubkey = spk };
    const spent = try a.alloc(bitcointx.TxOut, n);
    for (spent, 0..) |*o, i| o.* = .{ .value = @intCast(5000 + i), .script_pubkey = spk };
    return .{
        .tx = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = true },
        .spent = spent,
    };
}

/// Bytes `verifyScript` allocates while verifying ONE input of an `n`-input,
/// `n`-output transaction. Building the transaction and (when asked) the cache
/// happens outside the measured region — the question is what ONE input costs.
fn verifyOneInputBytes(gpa: std.mem.Allocator, n: usize, kind: Kind, use_pre: bool) !usize {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var witness_buf: [3][]const u8 = undefined;
    var witness: []const []const u8 = undefined;
    var spk: []u8 = undefined;
    var flags: flags_mod.ScriptFlags = .{ .witness = true };

    switch (kind) {
        .segwit_v0 => {
            // P2WSH of `<pk> OP_CHECKSIG`.
            const witness_script = try a.dupe(u8, &([_]u8{0x21} ++ unparseable_pk ++ [_]u8{0xac}));
            var wsh: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(witness_script, &wsh, .{});
            spk = try a.alloc(u8, 34);
            spk[0] = 0x00;
            spk[1] = 0x20;
            @memcpy(spk[2..], &wsh);
            witness_buf[0] = try a.dupe(u8, &parseable_sig);
            witness_buf[1] = witness_script;
            witness = witness_buf[0..2];
        },
        .taproot_keypath => {
            spk = try a.alloc(u8, 34);
            spk[0] = 0x51;
            spk[1] = 0x20;
            @memset(spk[2..], 0xbb);
            witness_buf[0] = try a.dupe(u8, &([_]u8{0x33} ** 64));
            witness = witness_buf[0..1];
            flags.taproot = true;
        },
        .taproot_scriptpath => {
            // A REAL single-leaf taproot commitment (the control block must
            // check out, or execution never reaches the leaf's CHECKSIG and
            // no BIP341/342 sighash is ever computed). The leaf signature is
            // bogus — again, the sighash is computed before it fails.
            const internal = try bip340.KeyPair.fromSecretKey(try bip340.SecretKey.fromBytes([_]u8{0x66} ** 32));
            const leaf_key = try bip340.KeyPair.fromSecretKey(try bip340.SecretKey.fromBytes([_]u8{0x55} ** 32));
            const leaf_script = try a.dupe(u8, &([_]u8{0x20} ++ [_]u8{0} ** 32 ++ [_]u8{0xac}));
            @memcpy(leaf_script[1..33], &leaf_key.public.x);
            const out = taprootOutput(internal.public.x, tapscript.tapleafHash(0xc0, leaf_script));
            spk = try a.alloc(u8, 34);
            spk[0] = 0x51;
            spk[1] = 0x20;
            @memcpy(spk[2..], &out.q);
            const control_block = try a.dupe(u8, &([_]u8{0} ** 33));
            control_block[0] = 0xc0 | out.parity;
            @memcpy(control_block[1..], &internal.public.x);
            witness_buf[0] = try a.dupe(u8, &([_]u8{0x33} ** 64));
            witness_buf[1] = leaf_script;
            witness_buf[2] = control_block;
            witness = witness_buf[0..3];
            flags.taproot = true;
        },
    }

    const built = try buildWideTx(a, n, spk);
    var ctx: txctx.TxContext = .{ .tx = built.tx, .input_index = 0, .spent_outputs = built.spent };
    if (use_pre) ctx = try ctx.withPrecomputed(a);

    // Everything below is on the counting allocator, backed by its own arena
    // so nothing has to be freed by hand.
    var run_arena = std.heap.ArenaAllocator.init(gpa);
    defer run_arena.deinit();
    var fa: std.testing.FailingAllocator = .init(run_arena.allocator(), .{});

    // The spend is expected to FAIL (bogus signature) — the sighash is
    // computed first, which is the cost under test.
    verify.verifyScript(fa.allocator(), &.{}, spk, witness, flags, ctx) catch {};
    return fa.allocated_bytes;
}

test "cost: with the cache, verifying an input allocates the same regardless of transaction size" {
    const gpa = testing.allocator;
    const small = 64;
    const big = 512; // 8x

    for ([_]Kind{ .segwit_v0, .taproot_keypath, .taproot_scriptpath }) |kind| {
        // Cached: the commitment hashes are not rebuilt, so nothing the
        // verification of one input allocates depends on `vin`/`vout` at all.
        // Not "grows slowly" — EQUAL, the same shape as `bitcointx`'s own
        // `count() == 8` assertion.
        const cached_small = try verifyOneInputBytes(gpa, small, kind, true);
        const cached_big = try verifyOneInputBytes(gpa, big, kind, true);
        try testing.expect(cached_small > 0);
        try testing.expectEqual(cached_small, cached_big);

        // Control — this is what guards the oracle from being inert. The SAME
        // counter must see the uncached path grow with the transaction: each
        // commitment hash serializes every input/output again, so 8x the
        // transaction is ~8x the allocation for the same ONE input.
        const raw_small = try verifyOneInputBytes(gpa, small, kind, false);
        const raw_big = try verifyOneInputBytes(gpa, big, kind, false);
        try testing.expect(raw_big >= 4 * raw_small);

        // And the cache is what removes the growth, not some unrelated bound.
        try testing.expect(cached_big * 4 < raw_big);
    }
}

// ── 2. bytes: consensus output must be identical, cached or not ──────────

/// `Q = lift_x(internal) + t*G` for a single-leaf tree (Merkle root == leaf
/// hash). Mirrors `tapscript.verifyCommitment`'s derivation, which is itself
/// validated against external BIP341 wallet-test-vectors.
fn taprootOutput(internal_x: [32]u8, merkle_root: [32]u8) struct { q: [32]u8, parity: u8 } {
    var th = bip340.hash.taggedHasher("TapTweak");
    th.update(&internal_x);
    th.update(&merkle_root);
    const t = th.finalResult();
    const P = (bip340.XOnlyPublicKey.fromBytes(internal_x) catch unreachable).lift() catch unreachable;
    const tG = k256.Secp256k1.basePoint.mulPublic(t, .big) catch unreachable;
    const Q = P.add(tG);
    const aff = Q.affineCoordinates();
    return .{ .q = aff.x.toBytes(.big), .parity = if (aff.y.isOdd()) 1 else 0 };
}

fn normalizeLowS(sig: EcdsaSecp256k1Sha256.Signature) EcdsaSecp256k1Sha256.Signature {
    const n: u256 = k256.scalar.field_order;
    const half = n >> 1;
    const s_val = std.mem.readInt(u256, &sig.s, .big);
    if (s_val <= half) return sig;
    var new_s: [32]u8 = undefined;
    std.mem.writeInt(u256, &new_s, n - s_val, .big);
    return .{ .r = sig.r, .s = new_s };
}

test "bytes: one cache, three inputs, three sighash algorithms — every real signature still verifies" {
    // The three call sites this seam runs through, in ONE transaction, so the
    // cache really is shared across inputs and across sig versions:
    //   input 0 — P2WPKH        -> BIP143  (sigcheck.zig)
    //   input 1 — P2TR key-path -> BIP341  (verify.zig)
    //   input 2 — P2TR tapscript-> BIP341/342 (tapscript.zig via interpreter)
    // Every signature is made over the UNCACHED sighash. If a call site handed
    // a sighash routine the wrong cache, the wrong half of it, or the wrong
    // input index, the digest would move and these signatures would stop
    // verifying — a consensus split, which is exactly what must not happen.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // --- input 0: P2WPKH
    const ec_kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    const ec_pub = ec_kp.public_key.toCompressedSec1();
    var pkh: [20]u8 = undefined;
    ripemd160.hash160(&ec_pub, &pkh);
    const p2wpkh_spk = try a.dupe(u8, &([_]u8{ 0x00, 0x14 } ++ [_]u8{0} ** 20));
    @memcpy(p2wpkh_spk[2..], &pkh);
    const script_code = try a.dupe(u8, &([_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0} ** 20 ++ [_]u8{ 0x88, 0xac }));
    @memcpy(script_code[3..23], &pkh);

    // --- input 1: P2TR key-path (internal key used directly as output key)
    const key_sk = try bip340.SecretKey.fromBytes([_]u8{0x33} ** 32);
    const key_kp = try bip340.KeyPair.fromSecretKey(key_sk);
    const p2tr_key_spk = try a.dupe(u8, &([_]u8{ 0x51, 0x20 } ++ [_]u8{0} ** 32));
    @memcpy(p2tr_key_spk[2..], &key_kp.public.x);

    // --- input 2: P2TR script-path, single leaf `<pk> OP_CHECKSIG`
    const leaf_sk = try bip340.SecretKey.fromBytes([_]u8{0x55} ** 32);
    const leaf_kp = try bip340.KeyPair.fromSecretKey(leaf_sk);
    const internal_kp = try bip340.KeyPair.fromSecretKey(try bip340.SecretKey.fromBytes([_]u8{0x66} ** 32));
    const leaf_script = try a.dupe(u8, &([_]u8{0x20} ++ [_]u8{0} ** 32 ++ [_]u8{0xac}));
    @memcpy(leaf_script[1..33], &leaf_kp.public.x);
    const leaf_hash = tapscript.tapleafHash(0xc0, leaf_script);
    const out = taprootOutput(internal_kp.public.x, leaf_hash);
    const p2tr_script_spk = try a.dupe(u8, &([_]u8{ 0x51, 0x20 } ++ [_]u8{0} ** 32));
    @memcpy(p2tr_script_spk[2..], &out.q);
    const control_block = try a.dupe(u8, &([_]u8{0} ** 33));
    control_block[0] = 0xc0 | out.parity;
    @memcpy(control_block[1..], &internal_kp.public.x);

    const spks = [_][]const u8{ p2wpkh_spk, p2tr_key_spk, p2tr_script_spk };
    const values = [_]i64{ 5000, 7000, 20000 };

    const vin = try a.alloc(bitcointx.TxIn, 3);
    for (vin, 0..) |*v, i| v.* = .{
        .prevout = .{ .txid = [_]u8{@truncate(0xA0 + i)} ** 32, .vout = @intCast(i) },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    };
    const vout = try a.alloc(bitcointx.TxOut, 2);
    vout[0] = .{ .value = 15000, .script_pubkey = p2wpkh_spk };
    vout[1] = .{ .value = 10000, .script_pubkey = p2tr_key_spk };
    const tx: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = true };

    const spent = try a.alloc(bitcointx.TxOut, 3);
    for (spent, 0..) |*o, i| o.* = .{ .value = values[i], .script_pubkey = spks[i] };

    // Signatures over the UNCACHED sighashes.
    const sh0 = try bitcointx.bip143.sighash(a, tx, 0, script_code, values[0], SIGHASH_ALL);
    const ec_sig = normalizeLowS(try ec_kp.signPrehashed(sh0, null));
    var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = ec_sig.toDer(&der_buf);
    const sig0 = try a.alloc(u8, der.len + 1);
    @memcpy(sig0[0..der.len], der);
    sig0[der.len] = 0x01;

    const io: std.Io = undefined;
    const sh1 = try bitcointx.bip341.sighash(a, tx, 1, bitcointx.bip341.SIGHASH_DEFAULT, spent);
    const sig1 = try bip340.sign(key_sk, &sh1, [_]u8{0x44} ** 32, io);

    var exec: tapscript.ExecData = .{ .tapleaf_hash = leaf_hash, .codesep_pos = 0xffffffff };
    const sh2 = try tapscript.sighash(a, tx, 2, tapscript.SIGHASH_DEFAULT, spent, &exec);
    const sig2 = try bip340.sign(leaf_sk, &sh2, [_]u8{0x77} ** 32, io);

    const w0 = [_][]const u8{ sig0, &ec_pub };
    const w1 = [_][]const u8{&sig1};
    const w2 = [_][]const u8{ &sig2, leaf_script, control_block };
    const witnesses = [_][]const []const u8{ &w0, &w1, &w2 };

    const base: txctx.TxContext = .{ .tx = tx, .input_index = 0, .spent_outputs = spent };
    const cached = try base.withPrecomputed(a);
    try testing.expect(cached.precomputed != null);
    try testing.expect(cached.taprootPrecomputed() != null);

    var checked: usize = 0;
    for ([_]txctx.TxContext{ base, cached }) |proto| {
        for (0..3) |i| {
            var ctx = proto;
            ctx.input_index = i;
            try verify.verifyScript(a, &.{}, spks[i], witnesses[i], flags_mod.ScriptFlags.standard, ctx);
            checked += 1;
        }
        // Positive control: a one-byte tamper must still fail on BOTH routes,
        // so "it verified" is not a verifier that accepts anything.
        var bad = try a.dupe(u8, &sig1);
        bad[10] ^= 0x01;
        var ctx = proto;
        ctx.input_index = 1;
        try testing.expectError(
            error.InvalidTaprootSignature,
            verify.verifyScript(a, &.{}, spks[1], &[_][]const u8{bad}, flags_mod.ScriptFlags.standard, ctx),
        );
    }
    try testing.expectEqual(@as(usize, 6), checked);
}

test "cache is optional and its absence is the old behaviour" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const vin = try a.alloc(bitcointx.TxIn, 2);
    for (vin, 0..) |*v, i| v.* = .{
        .prevout = .{ .txid = [_]u8{@truncate(i)} ** 32, .vout = @intCast(i) },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 1, .script_pubkey = &.{} };
    const tx: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };

    // Default-constructed: no cache, and both accessors say so.
    const ctx: txctx.TxContext = .{ .tx = tx, .input_index = 0, .spent_outputs = &.{} };
    try testing.expect(ctx.precomputed == null);
    try testing.expect(ctx.segwitV0Precomputed() == null);
    try testing.expect(ctx.taprootPrecomputed() == null);

    // BIP341 commits to every input's spent output, so a short list cannot
    // produce a taproot cache — and must say so rather than cache half a
    // transaction.
    try testing.expectError(error.PrevoutsCountMismatch, ctx.withPrecomputed(a));
}
