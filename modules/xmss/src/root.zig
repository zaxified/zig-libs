// SPDX-License-Identifier: MIT
//! xmss — XMSS, the eXtended Merkle Signature Scheme (RFC 8391): stateful
//! hash-based digital signatures, pure Zig over std.crypto's SHA-256.
//!
//! Status: complete for the single-tree SHA-256 ciphersuite (n = 32, w = 16,
//! len = 67). All three REQUIRED RFC 8391 parameter sets are exported —
//! XMSS-SHA2_10_256 / _16_256 / _20_256 (IANA OIDs 0x01/0x02/0x03) — and any
//! tree height can be instantiated via `XmssSha2(h, oid)`. Implements keygen,
//! sign and verify: the WOTS+ one-time signatures (§3.1: chain, pkGen, sign,
//! pkFromSig, base-w + checksum), the hash-address scheme (§2.5), the keyed
//! hash functions F/H/H_msg/PRF (§5.1: SHA-256(toByte(i, 32) || KEY || M)
//! with domain-separation prefixes i = 0..3), L-trees (§4.1.5), treeHash
//! (§4.1.6), randomized message hashing (§4.1.9) and the RFC wire formats
//! (public key OID || root || SEED; signature idx || r || sig_ots || auth).
//!
//! Validation (see src/kat_vectors.zig for provenance): byte-exact against
//! the official XMSS reference implementation (github.com/XMSS/xmss-reference,
//! the code linked from RFC 8391 §7) for (a) the F/H/H_msg/PRF primitives,
//! (b) full WOTS+ pkGen + sign + pkFromSig, (c) XMSS keygen + sign at a
//! reduced test height h = 4, and (d) `verify` of two reference-generated
//! XMSS-SHA2_10_256 signatures (leaf 0 and leaf 517) under the reference's
//! h = 10 public key — i.e. a real external (pk, msg, sig) interop triple.
//! Additionally, h = 10 keyGen reproduces the reference root byte-exactly
//! (verified out-of-band; excluded from the unit suite — ~40 s in Debug).
//! keygen/sign at h = 16/20 are the same code path, exercised only at h ≤ 10.
//!
//! ** STATEFUL-SIGNATURE HAZARD ** — XMSS is stateful: every WOTS+ one-time
//! key (leaf index) MUST sign at most one message. Reusing an index reveals
//! enough chain intermediates to forge signatures — it breaks the scheme,
//! not just one signature. `sign` advances `SecretKey.idx` before producing
//! output (RFC 8391 §4.1.9) and errors with `KeyExhausted` after 2^h uses,
//! but the CALLER owns durability: persist the updated private key before
//! releasing a signature, never restore an old key copy from backup, never
//! share one key across processes/machines without index partitioning
//! (§4.1.12). If you cannot guarantee that, use a stateless scheme (sibling
//! `slhdsa` module) instead.
//!
//! WOTS+ secret chains are derived from `sk_seed`, not stored: sk[i] =
//! PRF_keygen(sk_seed, SEED || ADRS) with prefix toByte(4, 32) — the
//! NIST SP 800-208 / xmss-reference derivation (RFC 8391 §3.1.7 explicitly
//! leaves this implementation-defined; it does not affect verify interop).
//! Key generation takes caller-supplied seeds — bring your own CSPRNG (std
//! 0.16 removed std.crypto.random); there is no internal randomness, so all
//! operations are deterministic and reproducible.
//!
//! Auth-path traversal: BDS (Buchmann–Dahmen–Schneider) log-space Merkle
//! traversal is maintained in `SecretKey.bds`, ported from the reference
//! `xmss_core_fast.c` with parameter k = 0. `sign` emits the current leaf's
//! precomputed auth path and advances the state to the next leaf in ~O(h)
//! hashing (≈ verify cost) rather than rebuilding it O(2^h). The BDS state
//! advances in lockstep with `idx`; a caller that jumps `idx` out of band
//! triggers an automatic O(2^h) resync so the emitted signature stays
//! byte-exact. keyGen is still O(2^h) (it now also seeds the BDS state).
//!
//! Hash suites: the code is generic over the suite (`suite.zig`: SHA-256,
//! SHA-512, SHAKE128, SHAKE256 at n = 24 / 32 / 64, the RFC 8391 OPTIONAL and
//! NIST SP 800-208 sets) through `Xmss(suite.<set>, h, oid)`. Only the SHA-256
//! sets are validated against xmss-reference; every other RFC 8391 / SP 800-208
//! set (`XmssSha2_10_512` … `XmssShake256_20_192`) against the RustCrypto
//! `xmss` crate (keygen from a seed, signatures, verification; h = 10).
//! Out of scope: XMSS^MT (§4.2 multi-tree).
//! Not constant-time hardened (hash-based; no secret-dependent branching
//! beyond the hash inputs themselves — verify is public-data only).
//!
//! Zig std GAP: yes — std.crypto has no stateful hash-based signature
//! (RFC 8391 XMSS / RFC 8554 LMS). Recon: std.crypto.hash.sha2.Sha256 for
//! all keyed hashes; std.mem.writeInt/readInt for toByte/index encodings;
//! plain comparison for verify (public data — no std.crypto.timing_safe
//! needed). Consumer: SCADA firmware signing (IEC 62443-style code-signing
//! chains standardize on SP 800-208 stateful HBS).

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");
const Sha256 = std.crypto.hash.sha2.Sha256;
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "XMSS (RFC 8391, NIST SP 800-208), single-tree, every SHA-2 / SHAKE set — **stateful** hash-based signatures. Index reuse breaks the scheme; `sign` advances the index first.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation
    // No globals. Bare `SecretKey` mutation is caller-owned and NOT safe to
    // share across threads. That used to be an index-reuse hazard only
    // ("`sign` reads then writes `idx`"); since the BDS rewrite it is also
    // MEMORY-unsafety: `sign` mutates `bds.stackoffset`/`stacklevels`, two
    // racing signers drive `stackoffset` to 0 while `stackusage > 0`, and
    // `stackoffset - 1` underflows a `u32` — an integer-overflow panic in
    // Debug and a **SIGSEGV in ReleaseFast**, the shipping mode. `SigningKey`
    // is the hardened handle that IS safe to share — see its doc comment.
    .concurrency = .reentrant,
    .model_after = "RFC 8391 (XMSS), NIST SP 800-208; XMSS/xmss-reference and RustCrypto xmss as KAT oracles",
    .deps = .{}, // std only (SHA-2, SHAKE)
};

pub const suite = @import("suite.zig");
pub const scheme = @import("scheme.zig");
pub const Xmss = scheme.Xmss;

/// The SHA-256, n = 32 suite (RFC 8391 §5.1, OIDs 0x01..0x03): its primitives
/// are re-exported at the top level, as before the suites were generic.
pub const Sha256Suite = suite.Suite(suite.sha2_256);
pub const n = Sha256Suite.n;
pub const w = Sha256Suite.w;
pub const wots_len1 = Sha256Suite.wots_len1;
pub const wots_len2 = Sha256Suite.wots_len2;
pub const wots_len = Sha256Suite.wots_len;
pub const toByte32 = suite.toByte32;
pub const Adrs = suite.Adrs;
pub const hashF = Sha256Suite.hashF;
pub const hashH = Sha256Suite.hashH;
pub const prf = Sha256Suite.prf;
pub const hashMsg = Sha256Suite.hashMsg;
pub const prfKeygen = Sha256Suite.prfKeygen;
pub const chainStep = Sha256Suite.chainStep;
pub const chain = Sha256Suite.chain;
pub const randHash = Sha256Suite.randHash;
pub const wotsSkGen = Sha256Suite.wotsSkGen;
pub const wotsPkGen = Sha256Suite.wotsPkGen;
pub const msgToBaseW = Sha256Suite.msgToBaseW;
pub const wotsSign = Sha256Suite.wotsSign;
pub const wotsPkFromSig = Sha256Suite.wotsPkFromSig;
pub const ltree = Sha256Suite.ltree;
pub const genLeaf = Sha256Suite.genLeaf;

/// Single-tree XMSS over the SHA-256 suite (n = 32, w = 16) at a comptime
/// tree height (`Xmss(suite.sha2_256, h, oid)`).
pub fn XmssSha2(comptime tree_height: u5, comptime wire_oid: u32) type {
    return Xmss(suite.sha2_256, tree_height, wire_oid);
}

/// XMSS-SHA2_10_256 (§5.3 REQUIRED; IANA OID 0x00000001): 2^10 signatures,
/// 2500-byte signature. The byte-exact KAT/interop target of this module.
pub const XmssSha2_10_256 = XmssSha2(10, 0x00000001);
/// XMSS-SHA2_16_256 (§5.3 REQUIRED; IANA OID 0x00000002): 2^16 signatures.
/// Same code path as h = 10; keygen ≈ 79e6 hashes — minutes, not seconds.
pub const XmssSha2_16_256 = XmssSha2(16, 0x00000002);
/// XMSS-SHA2_20_256 (§5.3 REQUIRED + RFC default; IANA OID 0x00000003):
/// 2^20 signatures. Keygen ≈ 1.3e9 hashes; naive auth paths make signing
/// O(2^20) hashing too — practical only with out-of-band caching.
pub const XmssSha2_20_256 = XmssSha2(20, 0x00000003);

// ── RFC 8391 OPTIONAL and NIST SP 800-208 parameter sets (IANA OIDs) ──
// Byte-exact against the RustCrypto `xmss` crate at h = 10
// (`kat_suites_test.zig`); h = 16 / 20 are the same code at another height.

/// XMSS-SHA2_h_512 (RFC 8391 §5.3, OIDs 0x04..0x06): SHA-512, n = 64.
pub const XmssSha2_10_512 = Xmss(suite.sha2_512, 10, 0x00000004);
pub const XmssSha2_16_512 = Xmss(suite.sha2_512, 16, 0x00000005);
pub const XmssSha2_20_512 = Xmss(suite.sha2_512, 20, 0x00000006);
/// XMSS-SHAKE_h_256 (RFC 8391 §5.3, OIDs 0x07..0x09): SHAKE128, n = 32.
pub const XmssShake_10_256 = Xmss(suite.shake128_256, 10, 0x00000007);
pub const XmssShake_16_256 = Xmss(suite.shake128_256, 16, 0x00000008);
pub const XmssShake_20_256 = Xmss(suite.shake128_256, 20, 0x00000009);
/// XMSS-SHAKE_h_512 (RFC 8391 §5.3, OIDs 0x0a..0x0c): SHAKE256, n = 64.
pub const XmssShake_10_512 = Xmss(suite.shake256_512, 10, 0x0000000a);
pub const XmssShake_16_512 = Xmss(suite.shake256_512, 16, 0x0000000b);
pub const XmssShake_20_512 = Xmss(suite.shake256_512, 20, 0x0000000c);
/// XMSS-SHA2_h_192 (SP 800-208 §5.1, OIDs 0x0d..0x0f): SHA-256/192, n = 24.
pub const XmssSha2_10_192 = Xmss(suite.sha2_192, 10, 0x0000000d);
pub const XmssSha2_16_192 = Xmss(suite.sha2_192, 16, 0x0000000e);
pub const XmssSha2_20_192 = Xmss(suite.sha2_192, 20, 0x0000000f);
/// XMSS-SHAKE256_h_256 (SP 800-208 §5.3, OIDs 0x10..0x12): SHAKE256, n = 32.
pub const XmssShake256_10_256 = Xmss(suite.shake256_256, 10, 0x00000010);
pub const XmssShake256_16_256 = Xmss(suite.shake256_256, 16, 0x00000011);
pub const XmssShake256_20_256 = Xmss(suite.shake256_256, 20, 0x00000012);
/// XMSS-SHAKE256_h_192 (SP 800-208 §5.4, OIDs 0x13..0x15): SHAKE256/192, n = 24.
pub const XmssShake256_10_192 = Xmss(suite.shake256_192, 10, 0x00000013);
pub const XmssShake256_16_192 = Xmss(suite.shake256_192, 16, 0x00000014);
pub const XmssShake256_20_192 = Xmss(suite.shake256_192, 20, 0x00000015);

test "API surface: RFC 8391 sizes" {
    // §4.1.8: |Sig| = 4 + n + (len + h)*n; Table 3 |Sig| column.
    try std.testing.expectEqual(@as(usize, 2500), XmssSha2_10_256.signature_length);
    try std.testing.expectEqual(@as(usize, 2692), XmssSha2_16_256.signature_length);
    try std.testing.expectEqual(@as(usize, 2820), XmssSha2_20_256.signature_length);
    try std.testing.expectEqual(@as(usize, 68), XmssSha2_10_256.public_key_length);
    try std.testing.expectEqual(@as(u64, 1024), XmssSha2_10_256.max_signatures);
}

test "public key wire round-trip and OID rejection" {
    const X = XmssSha2_10_256;
    var pk = X.PublicKey{ .root = undefined, .seed = undefined };
    for (&pk.root, 0..) |*b, i| b.* = @truncate(i);
    for (&pk.seed, 0..) |*b, i| b.* = @truncate(i * 3);
    const bytes = pk.toBytes();
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, bytes[0..4], .big));
    const back = try X.PublicKey.fromBytes(&bytes);
    try std.testing.expectEqualSlices(u8, &pk.root, &back.root);
    try std.testing.expectEqualSlices(u8, &pk.seed, &back.seed);
    try std.testing.expectError(error.UnsupportedOid, XmssSha2_16_256.PublicKey.fromBytes(&bytes));
}

test "base-w + checksum example (§2.6: 0x1234 -> 1,2,3,4)" {
    var msg = @as([n]u8, @splat(0));
    msg[0] = 0x12;
    msg[1] = 0x34;
    const digits = msgToBaseW(&msg);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, digits[0..4]);
    // Checksum: 64 digits, csum = 64*15 - (1+2+3+4) = 950; digits from
    // toByte(950 << 4, 2) = 0x3b60 -> 3, 11, 6.
    try std.testing.expectEqualSlices(u8, &.{ 3, 11, 6 }, digits[wots_len1..]);
}

test "stateful discipline: sign advances idx, never repeats, fails closed when exhausted" {
    // Reduced height h = 4 (16 one-time keys) — full lifecycle in ~ms.
    const X = XmssSha2(4, 0xDDDDDDDD);
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @truncate(i + 1);
    for (&sk_prf, 0..) |*b, i| b.* = @truncate(i + 101);
    for (&pub_seed, 0..) |*b, i| b.* = @truncate(i + 201);
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);

    var sig: [X.signature_length]u8 = undefined;
    var seen = @as([X.max_signatures]bool, @splat(false));
    var k: u32 = 0;
    while (k < X.max_signatures) : (k += 1) {
        // `idx` is the NEXT unused leaf before signing.
        try std.testing.expectEqual(k, kp.sk.idx);
        try X.sign(&kp.sk, &sig, "message");
        // The wire index equals the leaf that was just consumed …
        const wire_idx = std.mem.readInt(u32, sig[0..4], .big);
        try std.testing.expectEqual(k, wire_idx);
        // … which must never have been used before (no silent reuse) …
        try std.testing.expect(!seen[wire_idx]);
        seen[wire_idx] = true;
        // … and the state advanced by exactly one.
        try std.testing.expectEqual(k + 1, kp.sk.idx);
        // Every emitted signature verifies under the public key.
        try std.testing.expect(X.verify(kp.pk, "message", &sig));
    }

    // All 2^h one-time keys consumed: further signing fails closed, and the
    // index neither wraps nor rolls back to a reusable leaf.
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "message"));
    try std.testing.expectEqual(@as(u32, X.max_signatures), kp.sk.idx);
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "message"));
    try std.testing.expectEqual(@as(u32, X.max_signatures), kp.sk.idx);
}

// ── the hardened handle (audit F1) ──────────────────────────────────────────

const TestX = XmssSha2(4, 0xDDDDDDDD); // 16 one-time keys — full lifecycle in ms

fn testKeyPair(kp: *TestX.KeyPair) void {
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @truncate(i + 3);
    for (&sk_prf, 0..) |*b, i| b.* = @truncate(i + 103);
    for (&pub_seed, 0..) |*b, i| b.* = @truncate(i + 203);
    TestX.keyGen(kp, &sk_seed, &sk_prf, &pub_seed);
}

test "SigningKey: a COPIED handle refuses to sign instead of forking the counter" {
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    var handle: TestX.SigningKey = undefined;
    TestX.SigningKey.init(&handle, &kp.sk, null);

    var sig: [TestX.signature_length]u8 = undefined;
    try handle.sign(&sig, "one");
    try std.testing.expectEqual(@as(u32, 1), handle.index());

    // THE HAZARD: a plain struct copy of a stateful key. Both copies believe
    // they are at leaf 1, so both would sign with the same one-time key — a
    // key-recovery break, not a duplicate signature. The bare `SecretKey` API
    // cannot see this; the handle can.
    var forked = handle;
    try std.testing.expectEqual(@as(u32, 1), forked.sk.idx); // the fork is real…
    try std.testing.expectError(error.KeyHandleCopied, forked.sign(&sig, "two"));
    try std.testing.expectEqual(@as(u32, 1), forked.sk.idx); // …and it consumed nothing

    // The original is unaffected and keeps signing.
    try handle.sign(&sig, "two");
    try std.testing.expectEqual(@as(u32, 2), handle.index());
    try std.testing.expect(TestX.verify(kp.pk, "two", &sig));
}

const PersistLog = struct {
    last: u32 = 0,
    calls: usize = 0,
    fail: bool = false,

    fn write(ctx: *anyopaque, next_idx: u32) anyerror!void {
        const self: *PersistLog = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (self.fail) return error.DiskFull;
        self.last = next_idx;
    }

    fn hook(self: *PersistLog) TestX.SigningKey.Persist {
        return .{ .ctx = self, .write = write };
    }
};

test "SigningKey.init retires its source: seeds wiped, a stale sign is KeyExhausted" {
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    const before = kp.sk;
    var handle: TestX.SigningKey = undefined;
    TestX.SigningKey.init(&handle, &kp.sk, null);
    try std.testing.expectEqualSlices(u8, &before.sk_seed, &handle.sk.sk_seed);
    try std.testing.expectEqualSlices(u8, &before.sk_prf, &handle.sk.sk_prf);
    try std.testing.expect(std.mem.allEqual(u8, &kp.sk.sk_seed, 0));
    try std.testing.expect(std.mem.allEqual(u8, &kp.sk.sk_prf, 0));
    var sig: [TestX.signature_length]u8 = undefined;
    try std.testing.expectError(error.KeyExhausted, TestX.sign(&kp.sk, &sig, "stale"));
    try handle.sign(&sig, "fresh");
    try std.testing.expect(TestX.verify(kp.pk, "fresh", &sig));
}

test "SigningKey: the durable index is written BEFORE the signature, and a failed write burns no leaf" {
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    var log: PersistLog = .{};
    var handle: TestX.SigningKey = undefined;
    TestX.SigningKey.init(&handle, &kp.sk, log.hook());

    var sig: [TestX.signature_length]u8 = undefined;
    try handle.sign(&sig, "a");
    // The hook saw the index AFTER this signature — never behind it, which is
    // the direction that would permit reuse after a crash+restart.
    try std.testing.expectEqual(@as(usize, 1), log.calls);
    try std.testing.expectEqual(@as(u32, 1), log.last);
    try std.testing.expectEqual(@as(u32, 1), handle.index());

    // A failing persist aborts the sign with the leaf UNCONSUMED …
    log.fail = true;
    try std.testing.expectError(error.PersistFailed, handle.sign(&sig, "b"));
    try std.testing.expectEqual(@as(u32, 1), handle.index());
    try std.testing.expectEqual(@as(u32, 1), log.last);

    // … and once storage recovers, leaf 1 is still available.
    log.fail = false;
    try handle.sign(&sig, "b");
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, sig[0..4], .big));
    try std.testing.expectEqual(@as(u32, 2), log.last);

    // Exhaustion must not move the durable index either.
    while (handle.index() < TestX.max_signatures) try handle.sign(&sig, "x");
    const at_end = log.last;
    try std.testing.expectError(error.KeyExhausted, handle.sign(&sig, "over"));
    try std.testing.expectEqual(at_end, log.last);
}

test "SigningKey: concurrent signing on one shared handle never repeats a leaf" {
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    var handle: TestX.SigningKey = undefined;
    TestX.SigningKey.init(&handle, &kp.sk, null);

    const Worker = struct {
        hk: *TestX.SigningKey,
        seen: *[TestX.max_signatures]std.atomic.Value(u32),
        fn run(self: @This()) void {
            var sig: [TestX.signature_length]u8 = undefined;
            while (true) {
                self.hk.sign(&sig, "concurrent") catch return; // KeyExhausted ends it
                const idx = std.mem.readInt(u32, sig[0..4], .big);
                _ = self.seen[idx].fetchAdd(1, .monotonic);
            }
        }
    };

    var seen: [TestX.max_signatures]std.atomic.Value(u32) = undefined;
    for (&seen) |*s| s.* = .init(0);

    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{Worker{ .hk = &handle, .seen = &seen }});
    for (&threads) |*t| t.join();

    // Every one-time key was used EXACTLY once. Without the interlock two
    // threads read the same `sk.idx` and one leaf signs two messages.
    for (&seen, 0..) |*s, i| {
        std.testing.expectEqual(@as(u32, 1), s.load(.monotonic)) catch |e| {
            std.debug.print("leaf {d} used {d} times\n", .{ i, s.load(.monotonic) });
            return e;
        };
    }
    try std.testing.expectEqual(@as(u32, TestX.max_signatures), handle.index());
}

test "SigningKey: with Persist.io, signers wait through the Io and still never repeat a leaf" {
    // Spinlock audit after the simio kv pilot: the guard is held across the
    // persist hook, which writes to storage. With `Persist.io` a waiting
    // signer parks on the `Io` instead of spinning on a holder suspended in
    // that write. Here the hook really yields (an `Io` sleep) while held.
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    const io = std.testing.io;
    const Slow = struct {
        io: std.Io,
        fn write(ctx: *anyopaque, _: u32) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.io.sleep(.fromMicroseconds(50), .awake);
        }
    };
    var slow: Slow = .{ .io = io };
    var handle: TestX.SigningKey = undefined;
    TestX.SigningKey.init(&handle, &kp.sk, .{ .ctx = &slow, .write = Slow.write, .io = io });

    const Worker = struct {
        fn run(hk: *TestX.SigningKey, seen: *[TestX.max_signatures]std.atomic.Value(u32)) void {
            var sig: [TestX.signature_length]u8 = undefined;
            while (true) {
                hk.sign(&sig, "concurrent") catch return; // KeyExhausted ends it
                _ = seen[std.mem.readInt(u32, sig[0..4], .big)].fetchAdd(1, .monotonic);
            }
        }
    };
    var seen: [TestX.max_signatures]std.atomic.Value(u32) = undefined;
    for (&seen) |*x| x.* = .init(0);
    var tasks: [4]std.Io.Future(void) = undefined;
    for (&tasks) |*t| t.* = try io.concurrent(Worker.run, .{ &handle, &seen });
    for (&tasks) |*t| t.await(io);
    for (&seen) |*x| try std.testing.expectEqual(@as(u32, 1), x.load(.monotonic));
}

test "a key restored at index 0 resyncs instead of signing an all-zero auth path (re-audit F1)" {
    // `BdsState` has all-default fields, so `SecretKey{ …, .bds = .{} }`
    // compiles — and that is exactly what a caller restoring a key writes,
    // because SPEC.md described the private key as "4 seeds + a 4-byte index".
    // With `covered_idx` defaulting to 0, a key restored AT INDEX 0 — a brand
    // new key persisted before its first signature, the single most likely
    // restore point — matched `idx`, skipped the resync, emitted the all-zero
    // auth path, returned success and CONSUMED the leaf. It never recovered:
    // `covered_idx` then tracks `idx` in lockstep, so all eight following
    // signatures failed too. Every other index self-healed, which is what made
    // it invisible: `kat_test.zig`'s jump test uses 1/5/11/15/32, never 0.
    const X = XmssSha2(4, 0xDDDDDDD0);
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &@as([n]u8, @splat(7)), &@as([n]u8, @splat(8)), &@as([n]u8, @splat(9)));
    var sig: [X.signature_length]u8 = undefined;

    for ([_]u32{ 0, 1, 5 }) |start| {
        var restored: X.SecretKey = .{
            .idx = start,
            .sk_seed = kp.sk.sk_seed,
            .sk_prf = kp.sk.sk_prf,
            .pub_seed = kp.sk.pub_seed,
            .root = kp.sk.root,
            .bds = .{},
        };
        try X.sign(&restored, &sig, "firmware v1");
        try std.testing.expect(X.verify(kp.pk, "firmware v1", &sig));
        try std.testing.expectEqual(start + 1, restored.idx);
        // ...and it stays correct for the rest of the key's life.
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            try X.sign(&restored, &sig, "next");
            try std.testing.expect(X.verify(kp.pk, "next", &sig));
        }
    }

    // The sentinel is not a valid leaf, so "unsynchronised" can never be read
    // as "synchronised for leaf N".
    try std.testing.expect(X.not_synced >= X.max_signatures);
    const fresh: X.BdsState = .{};
    try std.testing.expectEqual(X.not_synced, fresh.covered_idx);
    // A key straight out of keyGen IS synchronised, for leaf 0.
    try std.testing.expectEqual(@as(u32, 0), kp.sk.bds.covered_idx);
}

test "SecretKey.zeroize wipes the seeds and leaves the public state alone" {
    var kp: TestX.KeyPair = undefined;
    testKeyPair(&kp);
    const root_before = kp.sk.root;
    kp.sk.idx = 7;
    kp.sk.zeroize();
    try std.testing.expectEqualSlices(u8, &@as([n]u8, @splat(0)), &kp.sk.sk_seed);
    try std.testing.expectEqualSlices(u8, &@as([n]u8, @splat(0)), &kp.sk.sk_prf);
    try std.testing.expectEqualSlices(u8, &root_before, &kp.sk.root);
    try std.testing.expectEqual(@as(u32, 7), kp.sk.idx); // a zeroed idx would look fresh
}

// The dead-stack probe (keyGen, sign, buildAuth) lives in `stackprobe_test.zig`.

test "fuzz: PublicKey.fromBytes never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPublicKeyFromBytes, .{});
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    const X = XmssSha2_10_256;
    var bytes: [X.public_key_length]u8 = undefined;
    smith.bytes(&bytes);
    _ = X.PublicKey.fromBytes(&bytes) catch return;
}

/// ⛔ An XMSS signature that verifies is not reachable from arbitrary bytes,
/// so the accepting frame comes from the module's own `keyGen` + `sign`. A
/// seed is the public key and the 64-octet message RAW (both are drawn with
/// `smith.bytes`, which reads no length header), then the signature as a
/// `testkit.fuzz` slice seed.
const XmssCorpus = struct {
    const X = XmssSha2_10_256;
    const head = X.public_key_length + 64;
    const cap = 8;
    store: [cap * (head + 4 + X.signature_length)]u8 = undefined,
    used: usize = 0,
    entries: [cap][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *XmssCorpus, pk: [X.public_key_length]u8, msg: [64]u8, sig: []const u8) void {
        const start = self.used;
        @memcpy(self.store[start..][0..X.public_key_length], &pk);
        @memcpy(self.store[start + X.public_key_length ..][0..64], &msg);
        var at = start + head;
        at += testkit.fuzz.seedInto(self.store[at..], sig).len;
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *XmssCorpus) []const []const u8 {
        var kp: X.KeyPair = undefined;
        X.keyGen(&kp, &(@as([n]u8, @splat(1))), &(@as([n]u8, @splat(2))), &(@as([n]u8, @splat(3))));
        const pk = kp.pk.toBytes();
        const msg = @as([64]u8, @splat(0xA7));
        var sig: [X.signature_length]u8 = undefined;
        X.sign(&kp.sk, &sig, &msg) catch unreachable;

        self.push(pk, msg, &sig); // the signature that verifies
        var t = sig;
        t[3] ^= 0x01; // the leaf index: points at a different WOTS+ key
        self.push(pk, msg, &t);
        t = sig;
        t[4] ^= 0x01; // one octet of the randomizer `r`
        self.push(pk, msg, &t);
        t = sig;
        t[X.signature_length - 1] ^= 0x01; // the top authentication-path node
        self.push(pk, msg, &t);
        var other_msg = msg;
        other_msg[0] ^= 0x01;
        self.push(pk, other_msg, &sig); // the right signature, the wrong message
        var bad_pk = pk;
        bad_pk[X.public_key_length - 1] ^= 0x01; // a different root
        self.push(bad_pk, msg, &sig);
        self.push(pk, msg, sig[0 .. X.signature_length - 1]); // one octet short
        self.push(pk, msg, ""); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: verify (the wire signature parser) never panics on arbitrary pk/msg/sig bytes" {
    var corpus: XmssCorpus = .{};
    try std.testing.fuzz({}, fuzzVerify, .{ .corpus = corpus.build() });
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    // XmssSha2_10_256: the 2500-byte-signature, smallest/fastest variant —
    // same `verify` code path as every other height, cheapest for fuzzing.
    const X = XmssSha2_10_256;
    var pk_bytes: [X.public_key_length]u8 = undefined;
    smith.bytes(&pk_bytes);
    // Force a valid OID so `PublicKey.fromBytes` succeeds most of the time
    // and `verify`'s actual signature-parsing body (not just the early OID
    // guard) gets exercised.
    std.mem.writeInt(u32, pk_bytes[0..4], X.oid, .big);
    const pk = X.PublicKey.fromBytes(&pk_bytes) catch return;

    var msg: [64]u8 = undefined;
    smith.bytes(&msg);

    var sig_buf: [X.signature_length]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz` (a ranged draw needs eight octets and `bytes` had eaten them),
    // so `verify` returned false off its `sig.len != signature_length` guard
    // every round — the `idx`/`r`/`sig_ots`/`auth` parse this harness's own
    // comment is about had never run.
    const len: usize = smith.slice(&sig_buf);
    // `verify` parses `idx`/`r`/`sig_ots`/`auth` straight out of `sig` with
    // no bounds checks beyond the `sig.len != signature_length` guard — it
    // must never panic/OOB regardless of length or content.
    _ = X.verify(pk, &msg, sig_buf[0..len]);
}

test "corpus: the XMSS seeds reach the signature parser, and the counts are pinned" {
    const X = XmssSha2_10_256;
    var corpus: XmssCorpus = .{};
    var accepted: usize = 0;
    // ⛔ The number the collapsed draw could not produce: seeds that got past
    // the length guard and into the WOTS+/authentication-path reconstruction.
    // It was 0 — `verify` never once looked at a signature's content.
    var full_length: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var pk_bytes: [X.public_key_length]u8 = undefined;
        smith.bytes(&pk_bytes);
        std.mem.writeInt(u32, pk_bytes[0..4], X.oid, .big);
        const pk = X.PublicKey.fromBytes(&pk_bytes) catch continue;
        var msg: [64]u8 = undefined;
        smith.bytes(&msg);
        var sig_buf: [X.signature_length]u8 = undefined;
        const len: usize = smith.slice(&sig_buf);
        if (len == X.signature_length) full_length += 1;
        if (X.verify(pk, &msg, sig_buf[0..len])) accepted += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), full_length);
    try std.testing.expectEqual(@as(usize, 1), accepted);
}

test {
    _ = @import("kat_suites_test.zig");
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("stackprobe2_test.zig");
}

// ── the generic suites: round trips at h = 4 (KATs in kat_suites_test.zig) ──

fn suiteRoundTrip(comptime cfg: suite.Config) !void {
    const X = Xmss(cfg, 4, 0xDDDDDDDE);
    const N = X.S.n;
    var sk_seed: [N]u8 = undefined;
    var sk_prf: [N]u8 = undefined;
    var pub_seed: [N]u8 = undefined;
    for (&sk_seed, &sk_prf, &pub_seed, 0..) |*a, *b, *c, i| {
        a.* = @intCast(i);
        b.* = @intCast(i + N);
        c.* = @intCast(i + 2 * N);
    }
    var kp: X.KeyPair = undefined;
    X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);
    defer kp.sk.zeroize();
    try std.testing.expectEqual(@as(usize, 4 + 2 * N), X.public_key_length);
    try std.testing.expectEqual(@as(usize, 4 + N + (2 * N + 3) * N + 4 * N), X.signature_length);
    var sig: [X.signature_length]u8 = undefined;
    for (0..3) |k| {
        var m: [8]u8 = undefined;
        std.mem.writeInt(u64, &m, k, .little);
        try X.sign(&kp.sk, &sig, &m);
        try std.testing.expect(X.verify(kp.pk, &m, &sig));
        m[0] ^= 1;
        try std.testing.expect(!X.verify(kp.pk, &m, &sig));
        m[0] ^= 1;
        sig[4 + N + 7] ^= 1;
        try std.testing.expect(!X.verify(kp.pk, &m, &sig));
    }
    const back = try X.PublicKey.fromBytes(&kp.pk.toBytes());
    try std.testing.expectEqualSlices(u8, &kp.pk.root, &back.root);
}

test "suites: SHA-512, SHAKE128/256, SHAKE256/512, SHA-256/192, SHAKE256/256, SHAKE256/192 sign and verify at h = 4" {
    try suiteRoundTrip(suite.sha2_512);
    try suiteRoundTrip(suite.shake128_256);
    try suiteRoundTrip(suite.shake256_512);
    try suiteRoundTrip(suite.sha2_192);
    try suiteRoundTrip(suite.shake256_256);
    try suiteRoundTrip(suite.shake256_192);
}

test "suites: the 192-bit sets pad with toByte(i, 4), the others with toByte(i, n)" {
    try std.testing.expectEqual(@as(usize, 4), suite.Suite(suite.sha2_192).padding_len);
    try std.testing.expectEqual(@as(usize, 4), suite.Suite(suite.shake256_192).padding_len);
    try std.testing.expectEqual(@as(usize, 64), suite.Suite(suite.sha2_512).padding_len);
    try std.testing.expectEqual(@as(usize, 32), Sha256Suite.padding_len);
    try std.testing.expectEqual(@as(usize, 51), suite.Suite(suite.sha2_192).wots_len);
    try std.testing.expectEqual(@as(usize, 131), suite.Suite(suite.shake256_512).wots_len);
}
