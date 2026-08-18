// SPDX-License-Identifier: MIT
//! ciphersuite — the `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` ciphersuite
//! constants and the "mechanical" (non-Fable) building blocks
//! draft-irtf-cfrg-bbs-signatures-04 §4 defines on top of them:
//! `expand_message`/`hash_to_scalar` (§4.2.2), `create_generators`
//! (§4.1.1), `messages_to_scalars` (§4.1.2), `calculate_domain`
//! (§4.2.3), and the two random-scalar sources ProofGen needs
//! (`calculate_random_scalars` §4.2.1 / the mocked, deterministic
//! `seeded_random_scalars` §7.1). Every function here is REAL — none of
//! it involves the zero-knowledge JUDGMENT `bbs.zig`'s four Fable cores
//! carry; it is all either hashing (`std.crypto.hash.sha2.Sha256`
//! via `bls12_381`'s `expandMessageXmd`) or deterministic point/scalar
//! derivation with no soundness argument of its own.
//!
//! Builds directly on `bls12_381`: `G1`/`G2` point arithmetic and wire
//! codecs, `hash_to_curve.expandMessageXmd`/`hashToCurveG1` for the
//! RFC-9380 hash-to-curve machinery `create_generators` needs, and
//! `Fr.reduceWide` for the `OS2IP(..) mod r` reduction every
//! `hash_to_scalar`-shaped operation in this file performs. See
//! `../SPEC.md` for the exact draft version pinned (draft-04) and why.
//!
//! ## DST hierarchy (draft-04 §3.8 / §4.1 / §4.2)
//!
//! ```
//! ciphersuite_id  = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"           (35 bytes)
//! api_id          = ciphersuite_id || "H2G_HM2S_"                  (44 bytes;
//!                    the BBS Signatures Interface's fixed api_id — draft §3.5)
//! seed_dst        = api_id || "SIG_GENERATOR_SEED_"
//! generator_dst   = api_id || "SIG_GENERATOR_DST_"
//! generator_seed_message = api_id || "MESSAGE_GENERATOR_SEED"      (the
//!                    seed MESSAGE create_generators expands from — not a
//!                    DST; renamed here from the draft's confusing
//!                    reuse of "generator_seed" for a non-DST value)
//! map_msg_dst     = api_id || "MAP_MSG_TO_SCALAR_AS_HASH_"
//! h2s_dst         = api_id || "H2S_"          (domain_dst == signature_dst
//!                    == challenge_dst — all three draft names for the
//!                    SAME literal DST value)
//! keygen_dst          = api_id || "KEYGEN_DST_"
//! mocked_scalars_dst  = api_id || "MOCK_RANDOM_SCALARS_DST_"
//! ```
//!
//! **`keygen_dst`/`mocked_scalars_dst` use `api_id`, NOT the bare
//! `ciphersuite_id` — despite draft §3.4.1/§7.1's abstract prose
//! literally reading "ciphersuite_id || KEYGEN_DST_" / "ciphersuite_id
//! || MOCK_RANDOM_SCALARS_DST_"**: draft §6.2.2's CONCRETE
//! `BLS12-381-SHA-256` ciphersuite section publishes its OWN
//! `Ciphersuite_ID` literal as
//! `"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"` — i.e. the
//! CONCRETE `ciphersuite_id` these two abstract formulas resolve to,
//! for THIS ciphersuite, is ALREADY the 44-byte value this file calls
//! `api_id` (the draft ships only one Interface for this ciphersuite,
//! so its concrete `ciphersuite_id` and that Interface's `api_id`
//! happen to coincide). Confirmed empirically, not merely inferred
//! from a close reading: `keys.keyGen`'s `KAT: keyGen(..) matches
//! keypair.json's SK` and this file's `mockedRandomScalars` KAT below
//! only reproduce the fixtures' published values with `api_id` as the
//! prefix — the bare 35-byte `ciphersuite_id` produces a DIFFERENT
//! (wrong) scalar. `mattrglobal/pairing_crypto`'s own reference
//! implementation resolves the same way: its
//! `bls12_381_g1_sha_256::ciphersuite_id()` function (consulted per
//! `../NOTICE`) returns the 44-byte value, and
//! `tools/bbs-fixtures-generator/src/mock_rng.rs`'s
//! `test_sha256_expected_random_scalars` builds its DST as `[
//! sha_256_ciphersuite_id(), b"MOCK_RANDOM_SCALARS_DST_"].concat()` —
//! i.e. exactly `api_id || "MOCK_RANDOM_SCALARS_DST_"`.
//!
//! `P1`'s own derivation additionally uses a THIRD seed message,
//! `api_id || "BP_MESSAGE_GENERATOR_SEED"` (draft §6.2.2: "replacing the
//! defined generator_seed with the value: ciphersuite_id ||
//! \"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED\"" — the SAME
//! concrete-vs-abstract `ciphersuite_id` resolution as above, so this
//! is exactly `api_id || "BP_MESSAGE_GENERATOR_SEED"`) with the SAME
//! `seed_dst`/`generator_dst` as the standard generators — see
//! `bp_generator_seed_message` and the `P1` KAT test below.

const std = @import("std");
const bls = @import("bls12_381");
const entropy = @import("entropy");

pub const G1 = bls.G1;
pub const G2 = bls.G2;
pub const Fr = bls.Fr;
pub const hash_to_curve = bls.hash_to_curve;
pub const pairing = bls.pairing;
pub const Fp = bls.Fp;

/// `octet_scalar_length` (draft §6.2.2) — the fixed wire width of every
/// `Fr` scalar this ciphersuite serializes, and (not coincidentally)
/// exactly `Fr.encoded_bytes`.
pub const octet_scalar_length = Fr.encoded_bytes; // 32
/// `octet_point_length` (draft §6.2.2) — the fixed wire width of every
/// `G1` point this ciphersuite serializes (compressed), and exactly
/// `G1.compressed_bytes`.
pub const octet_point_length = G1.compressed_bytes; // 48
/// `expand_len` (draft §6.2.2): `ceil((ceil(log2(r)) + k) / 8)` for
/// `k = 128`, `log2(r) = 255` — i.e. `ceil(383/8) = 48`.
pub const expand_len = 48;

pub const ciphersuite_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// The BBS Signatures Interface's (draft §3.5) fixed `api_id` — draft
/// §3.8's format `ciphersuite_id || CREATE_GENERATORS_ID ||
/// MAP_TO_SCALAR_ID`, with `CREATE_GENERATORS_ID = "H2G_"` (§4.1.1) and
/// `MAP_TO_SCALAR_ID = "HM2S_"` (§4.1.2) and no `ADD_INFO`.
pub const api_id = ciphersuite_id ++ "H2G_HM2S_";

pub const seed_dst = api_id ++ "SIG_GENERATOR_SEED_";
pub const generator_dst = api_id ++ "SIG_GENERATOR_DST_";
pub const generator_seed_message = api_id ++ "MESSAGE_GENERATOR_SEED";
pub const bp_generator_seed_message = api_id ++ "BP_MESSAGE_GENERATOR_SEED";
pub const map_msg_dst = api_id ++ "MAP_MSG_TO_SCALAR_AS_HASH_";
/// Shared by `calculate_domain` (as `domain_dst`), `CoreSign` (as
/// `signature_dst`), and `ProofChallengeCalculate` (as `challenge_dst`)
/// — draft §4.2.3/§3.6.1/§3.7.4 each independently define "api_id ||
/// H2S_" under a different local name; it is the SAME literal DST.
pub const h2s_dst = api_id ++ "H2S_";
/// `api_id`-prefixed, NOT `ciphersuite_id`-prefixed — see this file's
/// module doc comment ("DST hierarchy") for why, and the byte-exact
/// KAT confirmation in `keys.zig`.
pub const keygen_dst = api_id ++ "KEYGEN_DST_";
/// `api_id`-prefixed, NOT `ciphersuite_id`-prefixed — see this file's
/// module doc comment ("DST hierarchy") and the KAT test below.
pub const mocked_scalars_dst = api_id ++ "MOCK_RANDOM_SCALARS_DST_";

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `P1`, the ciphersuite's fixed `G1` point (draft §6.2.2) — the
/// constant summand in `CoreSign`/`CoreVerify`/`ProofInit`/
/// `ProofVerifyInit`'s `B`/`D` accumulation (`bbs.zig`). Hardcoded as
/// affine `(x, y)` coordinates — DECOMPRESSED OFFLINE (not via
/// `G1.fromBytesCompressed` at comptime: that path's `recoverY` calls
/// `Fp.sqrt`, a modular exponentiation whose comptime cost blows past
/// `@setEvalBranchQuota`'s practical range for a bare top-level
/// constant — the same reason `bls12_381.g1.Affine.generator` itself is
/// stored as raw `(x, y)`, not derived from a compressed literal) from
/// the draft's own published compressed literal
/// (`a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e
/// 7c59698588e70d11406d161b4e28c9`, verified byte-for-byte against
/// `mattrglobal/pairing_crypto`'s `generators.json` fixture's `"BP"`
/// field — see `../SPEC.md`/`../NOTICE`). The KAT test below verifies
/// `toBytesCompressed(P1)` reproduces that exact literal AND
/// re-derives `P1` via `createGeneratorsWithSeed(1,
/// bp_generator_seed_message)` for independent self-consistency.
pub const P1: G1.Affine = .{
    .x = Fp.fromBytes(hexBytes(48, "08ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9")) catch
        @compileError("bbs: bad P1.x constant"),
    .y = Fp.fromBytes(hexBytes(48, "10a711acd16ff43e30b3373b7b6a9233945ec74adf00b0481fbcd5e3b1e342e7a105b4966195e6a678857a0e0493d5b1")) catch
        @compileError("bbs: bad P1.y constant"),
};

/// `BP2`, the ciphersuite's fixed `G2` base point (draft §6.2: "The base
/// points BP1 and BP2 ... are the points BP and BP' ... as defined in
/// [pairing-friendly-curves]") — exactly `bls12_381`'s own standard `G2`
/// generator; no separate constant is needed.
pub const BP2: G2.Affine = G2.Affine.generator;

/// `expand_message` (RFC 9380 §5.3.1, `expand_message_xmd` variant) —
/// thin re-export of `bls12_381.hash_to_curve.expandMessageXmd`, kept as
/// a local name so every draft-shaped call site here reads
/// `ciphersuite.expandMessage(..)` rather than reaching into a sibling
/// module directly. `len_in_bytes` is `comptime` for the same reason
/// `expandMessageXmd` itself requires it — see that function's doc
/// comment (`bls12_381/src/hash_to_curve.zig`).
pub fn expandMessage(comptime len_in_bytes: usize, msg: []const u8, dst: []const u8) [len_in_bytes]u8 {
    return hash_to_curve.expandMessageXmd(len_in_bytes, msg, dst);
}

/// `hash_to_scalar(msg, dst)` (draft §4.2.2): `OS2IP(expand_message(msg,
/// dst, expand_len)) mod r`. REAL — `expand_message` (above) plus
/// `Fr.reduceWide` (already real, `bls12_381/src/scalar.zig`) for the
/// `mod r` reduction; `expand_len = 48 <= 64`, `Fr.reduceWide`'s own
/// width ceiling.
///
/// NOTE: this is the GENERIC hash-to-scalar helper used internally by
/// `calculate_domain`/`messages_to_scalars`/`keys.keyGen`/
/// `mockedRandomScalars` (each supplying its own `dst`) — do NOT confuse
/// with `messagesToScalars` (below), which is the draft's
/// `MapMessageToScalarAsHash`-specific wrapper (fixed `map_msg_dst`) a
/// caller signing/proving messages should actually use.
pub fn hashToScalar(msg: []const u8, dst: []const u8) Fr {
    return Fr.reduceWide(&expandMessage(expand_len, msg, dst));
}

/// `create_generators(count)` (draft §4.1.1) using the STANDARD seed
/// message (`generator_seed_message`) — the `(Q_1, H_1, ..., H_{count-1})`
/// sequence the Interface (`Sign`/`Verify`/`ProofGen`/`ProofVerify`) uses
/// when `create_generators(L+1, ...)` is called: `out[0]` is `Q_1`,
/// `out[1..]` are `H_1..H_L`. Caller owns the returned slice (free with
/// `allocator`). REAL — see `createGeneratorsWithSeed` for the
/// construction; `P1`'s OWN derivation (a DIFFERENT, one-off seed
/// message) is the reason that function takes `seed_message` as a
/// parameter instead of being inlined here.
pub fn createGenerators(allocator: std.mem.Allocator, count: usize) std.mem.Allocator.Error![]G1.Affine {
    return createGeneratorsWithSeed(allocator, count, generator_seed_message);
}

/// `create_generators(count)` (draft §4.1.1), generalized over the seed
/// MESSAGE (draft's own `generator_seed` input — renamed here to avoid
/// colliding with `seed_dst`, a DST, in naming) so `P1`'s derivation
/// (`bp_generator_seed_message`) and the standard Interface derivation
/// (`generator_seed_message`, via `createGenerators`) share one
/// implementation, per the draft's own note ("replacing the defined
/// generator_seed with the value ...").
///
/// Construction (draft §4.1.1, verbatim, 1-indexed):
/// ```
/// v = expand_message(seed_message, seed_dst, expand_len)
/// for i in 1..=count:
///     v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
///     generator_i = hash_to_curve_g1(v, generator_dst)
/// return (generator_1, ..., generator_count)
/// ```
/// `hash_to_curve_g1` is `bls12_381.hash_to_curve.hashToCurveG1` — full
/// RFC 9380 hash-to-curve (hash-to-field, SSWU map, 11-isogeny,
/// cofactor clear), already real (`bls12_381` Part 3).
pub fn createGeneratorsWithSeed(allocator: std.mem.Allocator, count: usize, seed_message: []const u8) std.mem.Allocator.Error![]G1.Affine {
    const out = try allocator.alloc(G1.Affine, count);
    errdefer allocator.free(out);
    var v = expandMessage(expand_len, seed_message, seed_dst);
    // `i` only ever ranges over `1..=count`, and `count` is already `usize`
    // (it bounds the `allocator.alloc` above) — there is no value `i` can
    // hold that a `usize` can't. The `u64` here was accidental width, not a
    // requirement: the draft's `I2OSP(i, 8)` is the WIRE format (an 8-byte
    // big-endian field), not a claim that `i` itself needs 64-bit range, and
    // `std.mem.writeInt(u64, ...)` accepts a `usize` argument via ordinary
    // implicit widening on every host. Narrowed rather than cast at the
    // boundary; identical semantics, so no new test.
    var i: usize = 1;
    while (i <= count) : (i += 1) {
        var input: [expand_len + 8]u8 = undefined;
        input[0..expand_len].* = v;
        std.mem.writeInt(u64, input[expand_len..][0..8], i, .big);
        v = expandMessage(expand_len, &input, seed_dst);
        out[i - 1] = hash_to_curve.hashToCurveG1(&v, generator_dst);
    }
    return out;
}

/// `messages_to_scalars(messages)` (draft §4.1.2, `MAP_TO_SCALAR_ID =
/// "HM2S_"`): each message independently mapped via `hash_to_scalar(msg,
/// map_msg_dst)`. REAL. Caller owns the returned slice.
pub fn messagesToScalars(allocator: std.mem.Allocator, messages: []const []const u8) std.mem.Allocator.Error![]Fr {
    const out = try allocator.alloc(Fr, messages.len);
    errdefer allocator.free(out);
    for (messages, 0..) |m, i| out[i] = hashToScalar(m, map_msg_dst);
    return out;
}

/// `calculate_domain(PK, Q_1, H_points, header)` (draft §4.2.3), `api_id`
/// fixed to this ciphersuite's Interface `api_id`:
/// ```
/// dom_octs  = I2OSP(L, 8) || ser(Q_1) || ser(H_1) || .. || ser(H_L) || api_id
/// dom_input = ser(PK) || dom_octs || I2OSP(len(header), 8) || header
/// domain    = hash_to_scalar(dom_input, h2s_dst)
/// ```
/// `ser(..)` for a `G1`/`G2` point is its ciphersuite-fixed compressed
/// encoding (`G1.toBytesCompressed`/`G2.toBytesCompressed` — already
/// real). REAL: pure concatenation + `hashToScalar`, no ZK judgment.
pub fn calculateDomain(
    allocator: std.mem.Allocator,
    pk_bytes: [G2.compressed_bytes]u8,
    q1: G1.Affine,
    h_points: []const G1.Affine,
    header: []const u8,
) std.mem.Allocator.Error!Fr {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &pk_bytes);
    var l_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &l_buf, h_points.len, .big);
    try buf.appendSlice(allocator, &l_buf);
    try buf.appendSlice(allocator, &G1.toBytesCompressed(q1));
    for (h_points) |h| try buf.appendSlice(allocator, &G1.toBytesCompressed(h));
    try buf.appendSlice(allocator, api_id);
    var h_len_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &h_len_buf, header.len, .big);
    try buf.appendSlice(allocator, &h_len_buf);
    try buf.appendSlice(allocator, header);
    return hashToScalar(buf.items, h2s_dst);
}

/// `calculate_random_scalars(count)` (draft §4.2.1): `count` INDEPENDENT
/// draws of `OS2IP(get_random(expand_len)) mod r` from a real CSPRNG —
/// the entropy `ProofGen` needs in normal (non-test) operation. `count`
/// is `comptime` so the return type is a plain array (no allocator);
/// every real call site (a future `proofGen` wrapper computing `3 + U`
/// undisclosed messages) knows `U` at the call site already. REAL — pure
/// `std.Io` entropy draw + `Fr.reduceWide`, no ZK judgment (mirrors
/// `bls12_381.scalar.Fr.random`'s `io: std.Io` convention, NOT an
/// internal `getrandom(2)` call — see `../README.md`'s "Randomness"
/// section for why this module takes `io`/`random_scalars` as an
/// explicit parameter rather than reading global/internal entropy,
/// unlike `bulletproofs`).
///
/// Fail-closed (`entropy.fill`, not `io.random`): these are `proofGen`'s
/// blinding scalars, and predicting them de-anonymises the proof —
/// linking presentations back to one credential is exactly what this
/// scheme exists to prevent. The return type is an array, so a degraded
/// draw has nowhere to surface.
pub fn calculateRandomScalars(comptime count: usize, io: std.Io) [count]Fr {
    var out: [count]Fr = undefined;
    for (&out) |*r| {
        var buf: [expand_len]u8 = undefined;
        entropy.fill(io, &buf);
        r.* = Fr.reduceWide(&buf);
    }
    return out;
}

/// `seeded_random_scalars(SEED, count)` (draft §7.1) — the DETERMINISTIC
/// mock RNG the draft's own test vectors use so `ProofGen`'s output is
/// reproducible: ONE `expand_message(SEED, mocked_scalars_dst, expand_len
/// * count)` call, sliced into `count` consecutive `expand_len`-byte
/// chunks, each `OS2IP(..) mod r`-reduced. `count` is `comptime` (same
/// reasoning as `calculateRandomScalars`) — every KAT call site knows the
/// fixture's `count = 3 + U` at compile time. **NOT for production use**
/// (the entire point of a "mocked" RNG is that it is PUBLIC and
/// PREDICTABLE given `SEED`) — see `kat_test.zig`'s gated `proofGen`
/// tests for how the fixture's `SEED` ("3.141592653589793238462643383279",
/// the first 30 digits of pi — a nothing-up-my-sleeve value) and
/// `count` (`3 + U`, varying per fixture) are used.
///
/// Verified byte-exact against `mattrglobal/pairing_crypto`'s
/// `mockedRng.json` fixture (`count = 10`) in `kat_test.zig`; see
/// `../SPEC.md` for why this SAME `SEED`/dst pair (confirmed from that
/// project's `tools/bbs-fixtures-generator/src/mock_rng.rs`, not merely
/// inferred) is reused — with a DIFFERENT `count` each time — across
/// every proof fixture in that ciphersuite's directory.
pub fn mockedRandomScalars(comptime count: usize, seed: []const u8) [count]Fr {
    const v = expandMessage(expand_len * count, seed, mocked_scalars_dst);
    var out: [count]Fr = undefined;
    inline for (0..count) |i| {
        out[i] = Fr.reduceWide(v[i * expand_len ..][0..expand_len]);
    }
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "ciphersuite_id / api_id byte lengths match the draft's own byte counts" {
    try testing.expectEqual(@as(usize, 35), ciphersuite_id.len);
    try testing.expectEqual(@as(usize, 35 + 9), api_id.len); // + "H2G_HM2S_" (9 bytes)
    try testing.expectEqualStrings("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", api_id);
}

test "P1 re-derives byte-exact via createGeneratorsWithSeed(1, bp_generator_seed_message)" {
    const gens = try createGeneratorsWithSeed(testing.allocator, 1, bp_generator_seed_message);
    defer testing.allocator.free(gens);
    try testing.expectEqualSlices(u8, &G1.toBytesCompressed(P1), &G1.toBytesCompressed(gens[0]));
}

test "hashToScalar KAT: draft-04 Appendix hash-to-scalar worked example" {
    // Message m_1 (draft §7.2) hashed under h2s_dst — this specific
    // worked example is published unchanged across every bbs-signatures
    // draft revision from -03 through -10 (see SPEC.md's version-pinning
    // note), so it is not itself draft-04-version-sensitive, but is
    // reproduced here from mattrglobal/pairing_crypto's `h2s.json`
    // fixture for consistency with this module's other embedded vectors.
    var msg_buf: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg_buf, "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02");
    const msg = msg_buf[0..32];
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c");
    const scalar = hashToScalar(msg, h2s_dst);
    try testing.expectEqualSlices(u8, &expected, &scalar.toBytes());
}

// `mockedRandomScalars`'s own KAT (against `kat_vectors.mocked_rng`,
// count = 10) lives in `kat_test.zig` alongside the rest of the
// fixture-driven suite, rather than duplicating that fixture's literal
// hex constants here — `createGeneratorsWithSeed`/`hashToScalar` above
// get their own small, self-contained KATs in THIS file because they
// are exercised with values that are not already part of the larger
// `kat_vectors.zig` fixture set.
