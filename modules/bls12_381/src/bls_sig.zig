// SPDX-License-Identifier: MIT
//! bls_sig — Part 4 of the `bls12_381` arc: BLS signatures per
//! **draft-irtf-cfrg-bls-signature-05**, all six ciphersuites of §4.2.
//! This file holds what they share — `SecretKey`, `keyGen` (§2.3), the
//! error set — and re-exports `scheme.zig`'s `Bls(variant, scheme)` and
//! its six instances (`MinPkBasic`, `MinPkAug`, `MinPkPop`, `MinSigBasic`,
//! `MinSigAug`, `MinSigPop`).
//!
//! The file-level names (`PublicKey`, `Signature`, `sign`, `verify`,
//! `aggregate*`, `fastAggregateVerify`, `popProve`/`popVerify`,
//! `verifyBatch`, `dst_sig`, `dst_pop`) are the **minimal-pubkey-size
//! ProofOfPossession** suite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
//! — Ethereum's consensus-layer suite, and this module's only one before
//! the other five existed. They are aliases of `MinPkPop`, so code written
//! against them is unchanged.
//!
//! Evidence: the min-pk POP suite is byte-exact against
//! `ethereum/bls12-381-tests` v0.1.2 (tests below); all six suites are
//! byte-exact against supranational/blst run as a black box
//! (`blst_interop_test.zig`); min-pk and min-sig Basic also verify live
//! drand mainnet beacons (`scheme.zig`). Every verify-family entry point
//! is TOTAL on attacker-controlled input — see `scheme.zig`.
//!
//! Const-time discipline: the secret-key paths (`keyGen`, `skToPk`,
//! `sign`, `popProve`) use the constant-time double-and-add-always
//! `scalarMul` and contain no secret-dependent branches (`keyGen`'s retry
//! branch fires with probability ~2^-255); the verify family operates on
//! PUBLIC data only and is variable-time (`SPEC.md`, "Constant-time
//! choices").

const std = @import("std");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const scalarmod = @import("scalar.zig");
const pairingmod = @import("pairing.zig");
const hash_to_curve = @import("hash_to_curve.zig");
const burn = @import("burn.zig");

pub const Fr = scalarmod.Fr;

pub const BlsError = error{
    /// `keyGen`'s IKM precondition (draft §2.3: "IKM MUST be at least
    /// 32 bytes long, but it MAY be longer").
    IkmTooShort,
    /// `aggregate`/`aggregatePublicKeys`/`coreAggregateVerify`/
    /// `aggregateVerify`/`fastAggregateVerify`'s precondition `n >= 1`
    /// (draft §2.8/§3.3.3/§3.3.4: an empty input set is INVALID, not
    /// vacuously true).
    EmptySet,
    /// `coreAggregateVerify`/`aggregateVerify`'s precondition that the
    /// public-key list and message list have the same length.
    LengthMismatch,
} || g1.G1Error || g2.G2Error || scalarmod.FrError;

// ── key / signature types ───────────────────────────────────────────

/// A BLS secret key: an `Fr` scalar `1 <= sk < r` (`keyGen`'s
/// postcondition — see that function). Wraps `scalar.zig`'s `Fr`
/// directly. `toBytes`/`fromBytes` are `Fr`'s own REAL 32-byte
/// big-endian codec — the draft does not mandate a secret-key wire
/// format; the plain scalar encoding is the common convention (e.g.
/// Ethereum deposit data, EIP-2335 keystores).
pub const SecretKey = struct {
    scalar: Fr,

    pub const encoded_bytes = Fr.encoded_bytes;

    /// REAL — `Fr.toBytes` into `out` (a secret: never returned through the
    /// stack).
    pub fn toBytes(self: *const SecretKey, out: *[encoded_bytes]u8) void {
        burn.run(burn.codec_burn, void, toBytesBody, .{ self, out });
    }

    fn toBytesBody(self: *const SecretKey, out: *[encoded_bytes]u8) void {
        out.* = self.scalar.toBytes();
    }

    /// REAL — delegates to `Fr.fromBytes` directly (rejects `>= r`,
    /// same canonical-encoding contract as `Fr` itself; does NOT
    /// reject `0`, since a zero scalar is merely a degenerate key, not
    /// a malformed encoding — `keyGen` itself never returns one, but a
    /// hand-crafted or corrupted key might decode to one). The key is
    /// written to `out`; on error `out` is zeroed.
    pub fn fromBytes(out: *SecretKey, bytes: *const [encoded_bytes]u8) BlsError!void {
        burn.run(burn.codec_burn, BlsError!void, fromBytesBody, .{ out, bytes }) catch |e| {
            out.deinit();
            return e;
        };
    }

    fn fromBytesBody(out: *SecretKey, bytes: *const [encoded_bytes]u8) BlsError!void {
        out.scalar = try Fr.fromBytes(bytes.*);
    }

    /// Zeroize the secret scalar in place. `SecretKey` is entirely
    /// secret material (a single `Fr` field, no public parts), so this
    /// zeroes the whole struct. Idempotent. Hygiene only — no effect on
    /// any public key/signature already derived from it.
    pub fn deinit(self: *SecretKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

// ── key generation / derivation / validation (REAL) ─────────────────

/// The literal `"BLS-SIG-KEYGEN-SALT-"` ASCII string (20 octets) —
/// `keyGen`'s salt on its FIRST HKDF-Extract call (draft §2.3). NOT
/// pre-hashed: the draft explicitly notes "Setting salt to the value
/// H(\"BLS-SIG-KEYGEN-SALT-\") ... results in a KeyGen algorithm that is
/// compatible with version 4 of this document" — i.e. pre-hashing is
/// the OLDER (`-04`) behavior, not this (`-05`) one. See `keyGen`'s doc
/// comment for why this distinction matters (it is exactly why this
/// file does NOT reuse an EIP-2333 test vector).
const default_salt = "BLS-SIG-KEYGEN-SALT-";
comptime {
    std.debug.assert(default_salt.len == 20);
}

/// `L = ceil((3 * ceil(log2(r))) / 16)` (draft §2.3) for BLS12-381's
/// scalar-field order `r` — comptime-derived from `scalar.zig`'s own
/// independently-verified `modulus.bits()` (255), NOT transcribed as a
/// bare literal: `ceil(3*255/16) = ceil(47.8125) = 48`.
const l_bytes: usize = (3 * scalarmod.modulus.bits() + 15) / 16;
comptime {
    std.debug.assert(l_bytes == 48);
}

/// draft-irtf-cfrg-bls-signature-05 §2.3 `KeyGen(IKM, key_info)`. REAL
/// — mechanical HKDF wiring over already-REAL primitives
/// (`std.crypto.kdf.hkdf.HkdfSha256`; `Fr.reduceWide` for the
/// `OS2IP(OKM) mod r` step, itself REAL — `scalar.zig`). Construction
/// (quoted from the draft, fetched 2026-07-14 — see NOTICE):
///
/// ```
/// salt = "BLS-SIG-KEYGEN-SALT-"              // literal, FIRST iteration only
/// while True:
///     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
///     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
///     SK  = OS2IP(OKM) mod r
///     if SK != 0:
///         return SK
///     salt = H(salt)                          // SHA-256 of the PREVIOUS salt, retry only
/// ```
///
/// `IKM` MUST be `>= 32` bytes (draft's own MUST — `error.IkmTooShort`
/// otherwise, rather than silently proceeding on weak input). `key_info`
/// defaults to the empty string in the draft; here it is an explicit
/// (possibly-empty) slice, matching this module's other explicit-
/// parameter style. `key_info.len` is bounded to fit a fixed 256-byte
/// stack buffer (`key_info.len <= 254`) — generous for every realistic
/// caller (the draft imposes no upper bound itself); widen the buffer
/// if a longer `key_info` caller ever appears.
///
/// Anchored byte-exact to blst's `key_gen_v5` (`blst_interop_test.zig`)
/// and to an independent recomputation of the -05 text: the draft's own
/// Appendix B is still "TBA". **EIP-2333 and blst's default `key_gen` are
/// the -04-compatible variant** — they pre-hash the salt on the first
/// round (`salt = H("BLS-SIG-KEYGEN-SALT-")`), which -05 does only on a
/// retry — so the same IKM gives a DIFFERENT key there. For Ethereum-
/// style hierarchical keys use `eip2333.zig`.
///
/// The key is written to `out`; on error `out` is zeroed. The body runs one
/// frame down and the stack it dirtied (PRK, OKM, the key) is zeroed after it.
pub fn keyGen(out: *SecretKey, ikm: []const u8, key_info: []const u8) BlsError!void {
    if (ikm.len < 32) {
        out.deinit();
        return error.IkmTooShort;
    }
    std.debug.assert(key_info.len <= 254);
    burn.run(burn.keygen_burn, void, keyGenBody, .{ out, ikm, key_info });
}

fn keyGenBody(out: *SecretKey, ikm: []const u8, key_info: []const u8) void {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    var salt_buf: [32]u8 = undefined;
    var salt: []const u8 = default_salt;

    while (true) {
        var prk_state = Hkdf.extractInit(salt);
        prk_state.update(ikm);
        prk_state.update(&[_]u8{0}); // I2OSP(0, 1): a single zero octet
        var prk: [Hkdf.prk_length]u8 = undefined;
        prk_state.final(&prk);

        var ctx_buf: [256]u8 = undefined;
        @memcpy(ctx_buf[0..key_info.len], key_info);
        std.mem.writeInt(u16, ctx_buf[key_info.len..][0..2], @intCast(l_bytes), .big); // I2OSP(L, 2)
        const ctx = ctx_buf[0 .. key_info.len + 2];

        var okm: [l_bytes]u8 = undefined;
        Hkdf.expand(&okm, ctx, prk);

        out.scalar = Fr.reduceWide(&okm);
        if (!out.scalar.isZero()) return;

        std.crypto.hash.sha2.Sha256.hash(salt, &salt_buf, .{});
        salt = &salt_buf;
    }
}

// ── the ciphersuites (scheme.zig) and this file's min-pk POP names ──────

const schememod = @import("scheme.zig");
pub const Variant = schememod.Variant;
pub const Scheme = schememod.Scheme;
pub const Bls = schememod.Bls;
pub const MinPkPop = schememod.MinPkPop;
pub const MinPkBasic = schememod.MinPkBasic;
pub const MinPkAug = schememod.MinPkAug;
pub const MinSigBasic = schememod.MinSigBasic;
pub const MinSigAug = schememod.MinSigAug;
pub const MinSigPop = schememod.MinSigPop;
pub const negatedG1Generator = schememod.negatedG1Generator;

pub const dst_sig = MinPkPop.dst_sig;
pub const dst_pop = MinPkPop.dst_pop;
pub const PublicKey = MinPkPop.PublicKey;
pub const Signature = MinPkPop.Signature;
pub const skToPk = MinPkPop.skToPk;
pub const keyValidate = MinPkPop.keyValidate;
pub const sign = MinPkPop.sign;
pub const verify = MinPkPop.verify;
pub const aggregate = MinPkPop.aggregate;
pub const aggregatePublicKeys = MinPkPop.aggregatePublicKeys;
pub const coreAggregateVerify = MinPkPop.coreAggregateVerify;
pub const aggregateVerify = MinPkPop.aggregateVerify;
pub const fastAggregateVerify = MinPkPop.fastAggregateVerify;
pub const popProve = MinPkPop.popProve;
pub const popVerify = MinPkPop.popVerify;
pub const verifyBatch = MinPkPop.verifyBatch;

// ── test helpers ─────────────────────────────────────────────────────

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── tests: REAL, PASS today ──────────────────────────────────────────

test "SecretKey.deinit zeroizes the secret scalar (regression: fails if secureZero is removed)" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 7;
    var sk: SecretKey = undefined;
    try SecretKey.fromBytes(&sk, &sk_bytes);
    const zero_bytes = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &testSkBytes(&sk), &zero_bytes));
    sk.deinit();
    // `Fr`'s in-memory (Montgomery) size may exceed its 32-byte canonical
    // encoding, so assert every raw byte of the struct is zero rather than
    // comparing against a fixed-width buffer.
    for (std.mem.asBytes(&sk)) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "SecretKey/PublicKey/Signature byte codecs round-trip through Part-1-3 machinery" {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 7;
    var sk: SecretKey = undefined;
    try SecretKey.fromBytes(&sk, &sk_bytes);
    try std.testing.expectEqualSlices(u8, &sk_bytes, &testSkBytes(&sk));

    const pk: PublicKey = .{ .point = g1.Affine.generator };
    const pk_bytes = pk.toBytes();
    try std.testing.expectEqual(@as(usize, 48), pk_bytes.len);
    const pk2 = try PublicKey.fromBytes(pk_bytes);
    try std.testing.expect(pk2.point.x.eql(g1.Affine.generator.x));

    const sig: Signature = .{ .point = g2.Affine.generator };
    const sig_bytes = sig.toBytes();
    try std.testing.expectEqual(@as(usize, 96), sig_bytes.len);
    const sig2 = try Signature.fromBytes(sig_bytes);
    try std.testing.expect(sig2.point.x.eql(g2.Affine.generator.x));
}

test "keyGen rejects IKM shorter than 32 bytes" {
    var short: SecretKey = undefined;
    try std.testing.expectError(error.IkmTooShort, keyGen(&short, &[_]u8{0} ** 31, ""));
    try keyGen(&short, &[_]u8{0x42} ** 32, ""); // 32 bytes: must not error
}

test "keyGen is deterministic (same IKM/key_info -> same SK) and produces a nonzero scalar" {
    const ikm = [_]u8{0xab} ** 32;
    var a: SecretKey = undefined;
    try keyGen(&a, &ikm, "");
    var b: SecretKey = undefined;
    try keyGen(&b, &ikm, "");
    try std.testing.expect(a.scalar.eql(b.scalar));
    try std.testing.expect(!a.scalar.isZero());

    // Different key_info overwhelmingly likely gives a different SK
    // (not a correctness requirement, just a sanity check that
    // key_info actually participates in the derivation).
    var c: SecretKey = undefined;
    try keyGen(&c, &ikm, "some-key-info");
    try std.testing.expect(!a.scalar.eql(c.scalar));
}

test "keyGen matches an independent Python recomputation of the -05 construction" {
    // NOT an external KAT (the draft has none, see keyGen's doc comment):
    // the -05 text above re-implemented with Python's hmac/hashlib
    // (2026-10-05), so the IKM || I2OSP(0, 1) suffix, the I2OSP(L, 2)
    // info suffix and the raw first-iteration salt are each pinned. The
    // mutation run of that date dropped the I2OSP(0, 1) octet and nothing
    // failed.
    var a: SecretKey = undefined;
    try keyGen(&a, &([_]u8{0xab} ** 32), "");
    try std.testing.expectEqualSlices(u8, &hexBytes(32, "5122c7e03ead241c21b84fe0afce6ce677f68bb82fb5ca6253b3c7e862a61905"), &a.scalar.toBytes());
    var ikm: [32]u8 = undefined;
    for (&ikm, 0..) |*b, i| b.* = @intCast(i);
    var b: SecretKey = undefined;
    try keyGen(&b, &ikm, "key-info");
    try std.testing.expectEqualSlices(u8, &hexBytes(32, "15c5471e3f4598a3108d05a8bd55669c4b65d857442cacdb274e38b909ec81f5"), &b.scalar.toBytes());
}

test "skToPk produces a subgroup-valid, non-identity public key; keyValidate accepts it" {
    var sk: SecretKey = undefined;
    try keyGen(&sk, &([_]u8{0x11} ** 32), "");
    const pk = skToPk(&sk);
    try std.testing.expect(!pk.point.infinity);
    try std.testing.expect(keyValidate(pk));
}

test "keyValidate rejects the identity public key" {
    const pk: PublicKey = .{ .point = g1.Affine.identity };
    try std.testing.expect(!keyValidate(pk));
}

test "keyValidate rejects a non-subgroup G1 point" {
    // Same x=4 non-subgroup construction g1.zig's own subgroupCheck
    // test uses (independently verified there: on-curve, NOT in the
    // order-r subgroup).
    var comp = [_]u8{0} ** g1.compressed_bytes;
    comp[0] = 0x80;
    comp[g1.compressed_bytes - 1] = 4;
    // The decoder refuses it; a `PublicKey` built around it some other way
    // must still fail `keyValidate`.
    try std.testing.expectError(error.NotInSubgroup, PublicKey.fromBytes(comp));
    const pk: PublicKey = .{ .point = try g1.fromBytesCompressedUnchecked(comp) };
    try std.testing.expect(!keyValidate(pk));
}

test "aggregate/aggregatePublicKeys reject an empty input slice" {
    try std.testing.expectError(error.EmptySet, aggregate(&.{}));
    try std.testing.expectError(error.EmptySet, aggregatePublicKeys(&.{}));
}

test "aggregate of a single signature returns that signature unchanged" {
    const sig: Signature = .{ .point = g2.Affine.generator };
    const agg = try aggregate(&.{sig});
    try std.testing.expectEqualSlices(u8, &sig.toBytes(), &agg.toBytes());
}

test "aggregate is commutative/associative over G2 points (property; no signature semantics needed)" {
    const g = g2.Jacobian.fromAffine(g2.Affine.generator);
    const a: Signature = .{ .point = g.double().toAffine() }; // [2]G2
    const b: Signature = .{ .point = g.double().double().toAffine() }; // [4]G2
    const c: Signature = .{ .point = g.double().double().double().toAffine() }; // [8]G2

    const ab = try aggregate(&.{ a, b });
    const ba = try aggregate(&.{ b, a });
    try std.testing.expectEqualSlices(u8, &ab.toBytes(), &ba.toBytes());

    const abc = try aggregate(&.{ a, b, c });
    const expected = g2.Jacobian.fromAffine(a.point).add(g2.Jacobian.fromAffine(b.point)).add(g2.Jacobian.fromAffine(c.point)).toAffine();
    try std.testing.expectEqualSlices(u8, &g2.toBytesCompressed(expected), &abc.toBytes());
}

test "aggregate KAT: three published signatures over the same message combine to the published aggregate" {
    // Source: ethereum/bls12-381-tests, tag v0.1.2, JSON encoding,
    // aggregate/aggregate_0xabab...ab.json (message = 32 bytes of
    // 0xab). Downloaded 2026-07-14 from
    // https://github.com/ethereum/bls12-381-tests/releases/download/v0.1.2/bls_tests_json.tar.gz
    // — see NOTICE. This is the same ciphersuite/vector family the
    // Ethereum consensus-spec-tests general/phase0/bls/aggregate suite
    // publishes (same handler name, same ciphersuite); the JSON here
    // was fetched and verified directly, not merely assumed identical
    // to the (much larger, not directly fetched) consensus-spec-tests
    // release tarball.
    //
    // REAL today: `aggregate` itself is fully implemented (plain G2
    // point summation, no pairing) — this test genuinely PASSES right
    // now, unlike the sign/verify/fastAggregateVerify KATs below.
    const sig1 = Signature{ .point = try g2.fromBytesCompressed(hexBytes(96, "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121")) };
    const sig2 = Signature{ .point = try g2.fromBytesCompressed(hexBytes(96, "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df")) };
    const sig3 = Signature{ .point = try g2.fromBytesCompressed(hexBytes(96, "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9")) };
    const expected = hexBytes(96, "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930");

    const agg = try aggregate(&.{ sig1, sig2, sig3 });
    try std.testing.expectEqualSlices(u8, &expected, &agg.toBytes());
}

test "coreAggregateVerify/aggregateVerify reject empty sets and length mismatches before any pairing work" {
    const sig: Signature = .{ .point = g2.Affine.generator };
    try std.testing.expectError(error.EmptySet, aggregateVerify(&.{}, &.{}, sig));

    const pk: PublicKey = .{ .point = g1.Affine.generator };
    try std.testing.expectError(error.LengthMismatch, aggregateVerify(&.{ pk, pk }, &.{"only one message"}, sig));
}

test "fastAggregateVerify rejects an empty pubkey slice before any pairing work" {
    const sig: Signature = .{ .point = g2.Affine.generator };
    try std.testing.expectError(error.EmptySet, fastAggregateVerify(&.{}, "msg", sig));
}

// ── tests: byte-exact KATs + round-trips over the pairing-based ─────
// ── cores (all REAL and passing since the crypto-core pass) ─────────

test "sign KAT: privkey/message -> published signature (ethereum/bls12-381-tests v0.1.2, sign/sign_case_11b8c7cad5238946.json)" {
    // Source: same tarball as the aggregate KAT above — see NOTICE.
    var sk: SecretKey = undefined;
    try SecretKey.fromBytes(&sk, &hexBytes(32, "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138"));
    const msg = hexBytes(32, "0000000000000000000000000000000000000000000000000000000000000000");
    const expected = hexBytes(96, "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9");

    const sig = sign(&sk, &msg);
    try std.testing.expectEqualSlices(u8, &expected, &sig.toBytes());
}

test "verify KAT: accepts a valid signature and rejects a mismatched one (ethereum/bls12-381-tests v0.1.2, verify/verify_valid_case_195246ee3bd3b6ec.json)" {
    // Source: same tarball as the aggregate KAT above — see NOTICE.
    // NOTE: this pubkey/message/signature triple is the SAME one used
    // as the third element of the aggregate KAT above and the third
    // pubkey of the fastAggregateVerify KAT below — all four vectors
    // are drawn from one mutually-consistent published set.
    //
    // The "tamper" case deliberately does NOT use the upstream suite's
    // own verify_tampered_signature_case_195246ee3bd3b6ec.json: that
    // vector flips trailing bytes of the compressed point into a
    // non-canonical encoding that fails to DESERIALIZE at all
    // (`g2.fromBytesCompressed` returns `error.NotOnCurve` — confirmed
    // empirically), which would test `Signature.fromBytes`'s rejection,
    // not `verify`'s pairing check, since this module's `verify` takes
    // an already-decoded `Signature`, not raw bytes. Instead: `sig1`
    // (the aggregate KAT's first signature, a genuine, on-curve,
    // in-subgroup G2 point — just for a DIFFERENT signer/message) is
    // substituted as a "wrong signature" for `pk`/`msg`, which isolates
    // exactly the pairing-equation rejection `verify` is responsible
    // for.
    const pk = try PublicKey.fromBytes(hexBytes(48, "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"));
    const msg = hexBytes(32, "abababababababababababababababababababababababababababababababab");
    const sig = try Signature.fromBytes(hexBytes(96, "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9"));
    const wrong_sig = try Signature.fromBytes(hexBytes(96, "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121"));

    try std.testing.expect(verify(pk, &msg, sig));
    try std.testing.expect(!verify(pk, &msg, wrong_sig));
}

test "fastAggregateVerify KAT: three pubkeys + the aggregate signature over their shared message (ethereum/bls12-381-tests v0.1.2, fast_aggregate_verify/fast_aggregate_verify_valid_3d7576f3c0e3570a.json)" {
    // Source: same tarball as the aggregate KAT above — see NOTICE.
    // The signature here is the SAME aggregate the "aggregate KAT" test
    // above independently reproduces from its 3 inputs.
    const pk1 = try PublicKey.fromBytes(hexBytes(48, "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"));
    const pk2 = try PublicKey.fromBytes(hexBytes(48, "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"));
    const pk3 = try PublicKey.fromBytes(hexBytes(48, "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f"));
    const msg = hexBytes(32, "abababababababababababababababababababababababababababababababab");
    const sig = try Signature.fromBytes(hexBytes(96, "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930"));

    const ok = try fastAggregateVerify(&.{ pk1, pk2, pk3 }, &msg, sig);
    try std.testing.expect(ok);
}

test "PopProve/PopVerify round-trip (self-consistent — no external vector needed)" {
    var sk: SecretKey = undefined;
    try keyGen(&sk, &([_]u8{0x22} ** 32), "");
    const pk = skToPk(&sk);
    const proof = popProve(&sk);
    try std.testing.expect(popVerify(pk, proof));

    // A proof for a DIFFERENT key must not verify.
    var other_sk: SecretKey = undefined;
    try keyGen(&other_sk, &([_]u8{0x33} ** 32), "");
    const other_pk = skToPk(&other_sk);
    try std.testing.expect(!popVerify(other_pk, proof));
}

test "end-to-end round trip: keyGen -> skToPk -> sign -> verify -> aggregate -> aggregateVerify (fresh key material, no external constant needed)" {
    var sk1: SecretKey = undefined;
    try keyGen(&sk1, &([_]u8{0x01} ** 32), "");
    var sk2: SecretKey = undefined;
    try keyGen(&sk2, &([_]u8{0x02} ** 32), "");
    const pk1 = skToPk(&sk1);
    const pk2 = skToPk(&sk2);

    const msg1 = "first message";
    const msg2 = "second message";
    const sig1 = sign(&sk1, msg1);
    const sig2 = sign(&sk2, msg2);

    try std.testing.expect(verify(pk1, msg1, sig1));
    try std.testing.expect(!verify(pk1, msg2, sig1)); // wrong message
    try std.testing.expect(!verify(pk2, msg1, sig1)); // wrong key

    const agg_sig = try aggregate(&.{ sig1, sig2 });
    const ok = try aggregateVerify(&.{ pk1, pk2 }, &.{ msg1, msg2 }, agg_sig);
    try std.testing.expect(ok);

    // Tamper: swapping the messages must fail.
    const bad = try aggregateVerify(&.{ pk1, pk2 }, &.{ msg2, msg1 }, agg_sig);
    try std.testing.expect(!bad);
}

// ── tests: the mandatory security checks actually FIRE ──────────────

test "verify rejects the identity public key (KeyValidate fires, fail-closed, no panic)" {
    // A well-formed signature by a REAL key over this message — the
    // only invalid ingredient is the identity pubkey, so a `true` or a
    // panic here would mean the mandatory KeyValidate step is missing.
    var sk: SecretKey = undefined;
    try keyGen(&sk, &([_]u8{0x55} ** 32), "");
    const msg = "identity pk must never verify";
    const sig = sign(&sk, msg);

    const identity_pk: PublicKey = .{ .point = g1.Affine.identity };
    try std.testing.expect(!verify(identity_pk, msg, sig));
    try std.testing.expect(!popVerify(identity_pk, sig));

    // Aggregate entry points too: an identity pk anywhere in the set
    // must fail closed, not error and not panic.
    const good_pk = skToPk(&sk);
    const two_msgs: []const []const u8 = &.{ msg, msg };
    try std.testing.expect(!(try aggregateVerify(&.{ good_pk, identity_pk }, two_msgs, sig)));
}

test "fastAggregateVerify rejects a ROGUE-KEY pair (cancels to identity) + the trivial identity signature" {
    // The complete forgery `keyValidate`'s aggregate-level check exists to
    // stop, spelled out: TWO individually-valid, non-identity, subgroup-
    // valid public keys whose SUM is the identity (`pk2 = -pk1`), paired
    // with the TRIVIAL identity signature. For an identity `PK`, the
    // verify equation `e(PK, Q) == e(G, sig)` becomes `1_GT ==
    // e(G, sig)`, which holds iff `sig` is ALSO the identity in G2 — and
    // the identity has order 1, so `signature_subgroup_check` (order
    // divides r for every element, including the identity) does not
    // reject it either. Nothing in the pairing arithmetic itself can
    // catch this forgery; ONLY `keyValidate`'s explicit check on the
    // aggregated key stands between an attacker who controls no secret
    // key at all and a signature that "verifies" for any message.
    var sk: SecretKey = undefined;
    try keyGen(&sk, &([_]u8{0x77} ** 32), "");
    const pk1 = skToPk(&sk);
    try std.testing.expect(keyValidate(pk1)); // precondition: pk1 alone is fine
    const pk2: PublicKey = .{ .point = g1.Jacobian.fromAffine(pk1.point).negate().toAffine() };
    try std.testing.expect(keyValidate(pk2)); // precondition: pk2 alone is fine too

    const identity_sig: Signature = .{ .point = g2.Affine.identity };
    try std.testing.expect(!(try fastAggregateVerify(&.{ pk1, pk2 }, "any message at all", identity_sig)));
}

test "verify rejects a non-subgroup G2 signature (signature_subgroup_check fires, fail-closed, no panic)" {
    // Craft an on-curve E'(Fp2) point OUTSIDE the order-r subgroup:
    // `mapToCurveG2` (Part 3's SSWU + 3-isogeny) lands on the curve but
    // does NOT clear the ~636-bit cofactor — that is `hashToCurveG2`'s
    // separate final step. The test asserts the crafted point genuinely
    // fails the subgroup check (test precondition, not an assumption).
    const u = hash_to_curve.hashToFieldFp2(1, "non-subgroup G2 point seed", dst_sig);
    const raw = hash_to_curve.mapToCurveG2(u[0]);
    try std.testing.expect(g2.Jacobian.fromAffine(raw).isOnCurve());
    try std.testing.expect(!g2.Jacobian.fromAffine(raw).subgroupCheck());

    var sk: SecretKey = undefined;

    try keyGen(&sk, &([_]u8{0x66} ** 32), "");
    const pk = skToPk(&sk);
    const bad_sig: Signature = .{ .point = raw };
    const msg = "non-subgroup sig must never verify";

    try std.testing.expect(!verify(pk, msg, bad_sig));
    try std.testing.expect(!popVerify(pk, bad_sig));
    try std.testing.expect(!(try aggregateVerify(&.{pk}, &.{msg}, bad_sig)));
    try std.testing.expect(!(try fastAggregateVerify(&.{pk}, msg, bad_sig)));
}

test "popVerify rejects the identity key with the identity proof (KeyValidate is the only guard)" {
    // e(O, Q) · e(-G, O) == 1 for every Q, and O passes the subgroup
    // check, so without KeyValidate this pair verifies.
    const identity_pk: PublicKey = .{ .point = g1.Affine.identity };
    const identity_sig: Signature = .{ .point = g2.Affine.identity };
    try std.testing.expect(!popVerify(identity_pk, identity_sig));
    try std.testing.expect(!verify(identity_pk, "any message", identity_sig));
}

test "aggregateVerify with more signers than one Miller chunk (exercises the chunked pairing accumulator)" {
    // coreAggregateVerify accumulates PairingPairs in stack chunks of 8
    // (matching pairing.zig's internal batch width); 8 signers + the
    // trailing (-G1, sig) pair = 9 pairs, forcing one full chunk flush
    // plus a trailer chunk — the boundary a chunking bug would hide at.
    const n = 8;
    var sks: [n]SecretKey = undefined;
    var pks: [n]PublicKey = undefined;
    var msgs: [n][]const u8 = .{
        "chunk msg 0", "chunk msg 1", "chunk msg 2", "chunk msg 3",
        "chunk msg 4", "chunk msg 5", "chunk msg 6", "chunk msg 7",
    };
    var sigs: [n]Signature = undefined;
    for (0..n) |i| {
        var ikm = [_]u8{0x70} ** 32;
        ikm[31] = @intCast(i);
        try keyGen(&sks[i], &ikm, "");
        pks[i] = skToPk(&sks[i]);
        sigs[i] = sign(&sks[i], msgs[i]);
    }

    const agg_sig = try aggregate(&sigs);
    try std.testing.expect(try aggregateVerify(&pks, &msgs, agg_sig));

    // Tamper across the chunk boundary: swap the last two messages.
    std.mem.swap([]const u8, &msgs[n - 2], &msgs[n - 1]);
    try std.testing.expect(!(try aggregateVerify(&pks, &msgs, agg_sig)));
}

// ── fuzz harnesses (untrusted-wire decoders) ────────────────────────────

test "fuzz: SecretKey.fromBytes never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzSecretKeyFromBytes, .{});
}

fn fuzzSecretKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [SecretKey.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    var sk: SecretKey = undefined;
    SecretKey.fromBytes(&sk, &buf) catch return;
    defer sk.deinit();
    var bytes: [32]u8 = undefined;
    sk.toBytes(&bytes);
}

test "fuzz: PublicKey.fromBytes never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPublicKeyFromBytes, .{});
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [PublicKey.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const pk = PublicKey.fromBytes(buf) catch return;
    _ = pk.toBytes();
    _ = keyValidate(pk);
}

test "fuzz: Signature.fromBytes never crashes on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzSignatureFromBytes, .{});
}

fn fuzzSignatureFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Signature.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const sig = Signature.fromBytes(buf) catch return;
    _ = sig.toBytes();
}

/// Test helper: a key's encoding as a value (tests compare it; library code
/// never returns a secret through the stack).
fn testSkBytes(sk: *const SecretKey) [SecretKey.encoded_bytes]u8 {
    var b: [SecretKey.encoded_bytes]u8 = undefined;
    sk.toBytes(&b);
    return b;
}
