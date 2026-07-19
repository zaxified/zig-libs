// SPDX-License-Identifier: MIT
//! taproot — BIP341 key-path output-key tweaking for Bitcoin Taproot
//! (SegWit version 1 outputs): the `"TapTweak"` tagged hash, the tweaked
//! public/secret key types + codecs, and the two crypto cores that turn an
//! internal BIP340 key into its Taproot output key/scalar.
//!
//! **Status: complete.** The `"TapTweak"` tagged hash, `TweakedPublicKey`
//! codec, error types, AND both crypto cores — `tweakPublicKey` (BIP341's
//! `taproot_output_key`) and `tweakSecretKey` (the matching secret-key
//! tweak) — are real and tested against all 7 rows of the official BIP341
//! `wallet-test-vectors.json` (`kat_test.zig`): the tweak hash, the tweaked
//! public key + its y-parity, and the tweaked secret scalar are each
//! reproduced byte-exact, plus a full sign→verify round-trip through
//! `bip340` with the tweaked key pair. See each function's doc comment for
//! the exact algorithm and `SPEC.md` for the threat model — a WRONG tweak
//! either burns the coins (unspendable output) or hands them to an attacker
//! who can predict the tweak.
//!
//! Zig std GAP: yes — same as `bip340` (`std.crypto.ecc.Secp256k1` supplies
//! the curve group; it has no BIP341 layer of its own). Depends on the
//! sibling `bip340` module for `XOnlyPublicKey`/`SecretKey`/`lift_x` and the
//! tagged-hash machinery (`bip340.hash.taggedHash`/`taggedHasher`) — this
//! module only adds the new `"TapTweak"` domain tag and the BIP341-specific
//! algebra on top. Clean-room from the BIP341 specification (public spec,
//! not copyrightable expression — see `NOTICE`); the official
//! `bitcoin/bips` `wallet-test-vectors.json` is a public spec artifact,
//! cited (not copied from any third-party test suite) in `kat_vectors.zig`.

const std = @import("std");
const bip340 = @import("bip340");
const Secp256k1 = @import("k256").Secp256k1;
const scalar = Secp256k1.scalar;
const Scalar = scalar.Scalar;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; keys are plain value types
    .model_after = "BIP341 (bitcoin/bips) — Taproot: key-path spending's output-key tweak; builds on the sibling bip340 module + the k256 curve group (byte-exact to std.crypto.ecc.Secp256k1)",
    .deps = .{ "bip340", "k256" },
};

// ── "TapTweak" tagged hash (BIP341 §"Constructing and Spending Taproot Outputs") ──

/// BIP341's `"TapTweak"` domain tag — a NEW tag, distinct from BIP340's
/// three (`aux`/`nonce`/`challenge`), but built with the exact same
/// `taggedHash` construction (`SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`,
/// `bip340.hash`).
pub const tap_tweak_tag = "TapTweak";

/// BIP341's tweak hash: `t_hash = taggedHash("TapTweak", P_x ‖
/// merkle_root)`.
///
/// `merkle_root` is 32 bytes for a script-path-enabled output (the Merkle
/// root of the script tree — possibly itself a single leaf hash, or even a
/// caller-supplied all-zero root for "script path disabled but still
/// committed", per BIP341's "no scripts" convention), or `null` for a
/// KEY-PATH-ONLY output: no script tree exists at all, so the hash runs
/// over `P_x` alone with nothing appended (BIP341 §"Constructing and
/// Spending Taproot Outputs": "If the spending policy doesn't require a
/// script path, the output key should commit to an unspendable script
/// path" is a *caller* choice about what 32 bytes to pass as
/// `merkle_root`; passing `null` here is the distinct "no script tree at
/// all" case, not "a script tree whose root happens to be zero").
pub fn tapTweakHash(internal_x: [32]u8, merkle_root: ?[32]u8) [32]u8 {
    if (merkle_root) |mr| {
        var buf: [64]u8 = undefined;
        buf[0..32].* = internal_x;
        buf[32..64].* = mr;
        return bip340.taggedHash(tap_tweak_tag, &buf);
    }
    return bip340.taggedHash(tap_tweak_tag, &internal_x);
}

// ── tweaked public key ──────────────────────────────────────────────────────

/// BIP341's Taproot output key `Q`: a 32-byte x-only point plus the parity
/// of its (implicit) y-coordinate. Unlike `bip340.XOnlyPublicKey` (which
/// always represents the EVEN-y resolution and drops the parity bit
/// entirely), Taproot spending needs the parity explicitly — it is encoded
/// into the low bit of a script-path control block's leading byte
/// (`leaf_version | parity`) so verifiers can re-lift `Q` with the right
/// sign.
pub const TweakedPublicKey = struct {
    x: [32]u8,
    /// 0 = even y, 1 = odd y.
    parity: u1,

    pub const encoded_length = 32;

    /// The 32-byte x-only encoding alone (what actually goes in a
    /// `scriptPubKey`/witness program — the parity is carried
    /// out-of-band, e.g. in a control block, not in this 32-byte value).
    pub fn toBytes(k: TweakedPublicKey) [32]u8 {
        return k.x;
    }

    /// Reinterpret as a plain BIP340 x-only key (e.g. to feed
    /// `bip340.verify` when checking a key-path spend's signature against
    /// the output key). Always succeeds structurally — an
    /// already-computed `TweakedPublicKey` is by construction the x
    /// coordinate of a real curve point (whichever crypto core produced
    /// it validated that); this is a relabeling, not a re-validation.
    pub fn asXOnly(k: TweakedPublicKey) bip340.XOnlyPublicKey {
        return .{ .x = k.x };
    }
};

pub const TweakError = error{
    /// `t = int(tapTweakHash(...))` landed `>= n` (the curve order) —
    /// BIP341 requires the whole tweak to fail in this case rather than
    /// silently reduce it. Astronomically unlikely for a real SHA-256
    /// output (probability ~ n/2^256, i.e. essentially the SHA-256
    /// preimage-density gap) but not zero, and MUST be checked rather than
    /// assumed away.
    TweakOutOfRange,
    /// The internal x-only public key does not lift to a valid curve point
    /// (non-canonical x, or x has no on-curve y at all).
    InvalidInternalKey,
};

/// The result of a public-key tweak: the output key plus the raw tweak
/// hash bytes `t` (exposed for callers that need to re-derive/verify the
/// tweak independently, e.g. a script-path verifier checking a control
/// block against a claimed internal key).
pub const TweakResult = struct {
    output: TweakedPublicKey,
    tweak: [32]u8,
};

// ── crypto cores ─────────────────────────────────────────────────────────

/// BIP341's `taproot_output_key` (§"Constructing and Spending Taproot
/// Outputs"): the public-key half of the key-path tweak. A wrong
/// implementation here is fund-losing in one of two directions: too
/// permissive (e.g. skipping the `t >= n` check, or getting the parity
/// convention backwards) can hand an attacker a spendable output; too
/// strict, or an arithmetic slip in the point addition, produces an output
/// nobody — including the legitimate owner — can ever spend.
///
/// The algorithm, as implemented:
///
/// 1. `t = int(tapTweakHash(internal.toBytes(), merkle_root))` — the tweak
///    hash above, interpreted as a big-endian scalar.
/// 2. Fail with `error.TweakOutOfRange` if `t >= n` (`n` = the curve
///    order, `Secp256k1.scalar`'s modulus) — `Scalar.fromBytes`'s canonical
///    check rejects exactly this; it never reduces. A zero `t` is in range
///    and allowed (BIP341 rejects only `t >= n`).
/// 3. `P = internal.lift()` (BIP340 `lift_x`, i.e. `bip340.XOnlyPublicKey.
///    lift` — always resolves to internal's even-y point; fail with
///    `error.InvalidInternalKey` on lift failure).
/// 4. `Q = P + t*G` (`Secp256k1.combMulBase(t_bytes, .big)` then complete
///    point addition with `P` — NOT a double-base multiply; this is a
///    single scalar-mult plus one point-add, since `P` is not itself a
///    public generator-relative term here). `mul` refuses a zero scalar
///    (the one case where `t*G` is the identity), so that branch degrades
///    to `Q = P` explicitly. `Q` itself being the identity would mean
///    `P == -t*G` — unconstructible for a SHA-256-derived `t` without a
///    secp256k1 discrete-log break, but checked anyway (mapped to
///    `error.InvalidInternalKey`) because the identity has no affine
///    x/y to encode.
/// 5. `output.x = bytes(x(Q))` (32-byte big-endian x coordinate).
/// 6. `output.parity = 1` if `y(Q)` is odd, else `0`.
/// 7. Return `.{ .output = .{ .x = ..., .parity = ... }, .tweak =
///    t_bytes }` (the pre-reduction 32-byte tweak-hash bytes, i.e. the
///    `tapTweakHash` output computed in step 1 — NOT `t`'s post-check
///    scalar re-encoding, which would be byte-identical anyway since step
///    2 only rejects, never reduces).
///
/// Constant-time: NOT required and not attempted — every input here is
/// public (an x-only public key, a Merkle root that appears on-chain in
/// the control block, and a hash of the two), mirroring `bip340.verify`'s
/// documented exemption.
///
/// KAT: `kat_test.zig` checks this end-to-end against all 7 official
/// BIP341 wallet-test-vector rows — `tweakedPubkey` byte-exact, `parity`
/// against the control-block-recovered bit (rows 1-6), and the returned
/// `tweak` against the published `tweak` field.
pub fn tweakPublicKey(internal: bip340.XOnlyPublicKey, merkle_root: ?[32]u8) TweakError!TweakResult {
    // Step 1: the tagged tweak hash over the internal x + optional root.
    const t_bytes = tapTweakHash(internal.toBytes(), merkle_root);

    // Step 2: reject t >= n; never reduce.
    _ = Scalar.fromBytes(t_bytes, .big) catch return error.TweakOutOfRange;

    // Step 3: P = lift_x(internal) — the even-y point.
    const p = internal.lift() catch return error.InvalidInternalKey;

    // Step 4: Q = P + t*G. `mul` errors only on a zero scalar (it refuses
    // to produce the identity); t == 0 means t*G is the identity, so Q = P.
    const q = if (Secp256k1.combMulBase(t_bytes, .big)) |tg|
        p.add(tg)
    else |_|
        p;

    // Defensive (see doc comment): the identity has no affine coordinates.
    q.rejectIdentity() catch return error.InvalidInternalKey;

    // Steps 5-7: x-only encoding + y-parity of Q, plus the raw tweak bytes.
    const xy = q.affineCoordinates();
    return .{
        .output = .{
            .x = xy.x.toBytes(.big),
            .parity = @intFromBool(xy.y.isOdd()),
        },
        .tweak = t_bytes,
    };
}

/// BIP341's key-path secret-key tweak (§"Constructing and Spending Taproot
/// Outputs", the signing-side counterpart of `tweakPublicKey`): produces
/// the scalar `q` that signs for output key `Q = q*G`.
///
/// The algorithm, as implemented:
///
/// 1. Let `d0 = int(internal_sk.bytes)` (the RAW secret scalar, exactly as
///    stored in `bip340.SecretKey` — BEFORE any even-y normalization).
/// 2. Compute `P0 = d0*G` and its y-parity.
/// 3. Even-y normalize (steps 1-3 are delegated to
///    `bip340.KeyPair.fromSecretKey` VERBATIM — BIP341 tweaks the SAME
///    normalized scalar BIP340 signing would use, not the raw one, so
///    reusing bip340's own normalization code path makes divergence
///    structurally impossible): `d = d0` if `P0.y` is even, else `d = n -
///    d0`. After this step `d*G` has the SAME x-coordinate as `d0*G` but
///    is guaranteed even-y — i.e. `x(d*G) == internal`'s x-only encoding
///    (`KeyPair.public`).
/// 4. `t = int(tapTweakHash(internal_x, merkle_root))` where `internal_x =
///    bytes(x(d*G))` (the same 32 bytes as step 3's even-y point, and the
///    same value `tweakPublicKey` would take as its `internal` argument).
///    Fail with `error.TweakOutOfRange` if `t >= n` (`Scalar.fromBytes`'s
///    canonical check — reject, never reduce).
/// 5. `q = (d + t) mod n` — `Secp256k1.scalar`'s constant-time field add
///    (`d` is secret). Step 3's parity branch inside bip340 is the exact
///    branch `bip340.sign` itself takes via `KeyPair.fromSecretKey` — this
///    function introduces no secret-dependent branching beyond what the
///    bip340 signing path already has. A zero `q` (only if
///    `t == n - d`, unconstructible for a SHA-256-derived `t` without
///    knowing `d`) would be rejected downstream by
///    `bip340.SecretKey.fromBytes`'s zero check.
/// 6. Return `q` as 32 bytes big-endian.
///
/// The caller signs the OUTPUT key's messages with `q` via
/// `bip340.sign`/`bip340.verify` against `tweakPublicKey`'s `output` — this
/// module does not itself wrap signing.
///
/// **Even-y interaction (the single most error-prone step here):** the
/// additive tweak `+ t` must land on the NORMALIZED scalar `d` from step 3,
/// never on the raw `d0` from step 1 — tweaking the raw scalar produces a
/// `q` whose public key is `d0*G + t*G`, which has the WRONG x-coordinate
/// whenever `d0*G` had odd y (i.e. correct exactly half the time,
/// wrong the other half — a bug of exactly this shape is a classic Taproot
/// implementation pitfall, not a hypothetical one).
///
/// KAT: `kat_test.zig`'s secret-key-tweak KAT checks all 7 vectors'
/// `internalPrivkey` + `merkleRoot` → the exact published `tweakedPrivkey`
/// scalar, plus a sign→verify round-trip: `bip340.sign` under this `q`
/// verifies against `tweakPublicKey`'s output key for every vector.
pub fn tweakSecretKey(internal_sk: bip340.SecretKey, merkle_root: ?[32]u8) TweakError![32]u8 {
    // Steps 1-3: even-y normalization + internal_x = bytes(x(d*G)), exactly
    // bip340.KeyPair.fromSecretKey's own computation (kp.secret = the
    // normalized d, kp.public.x = the even-y x-only encoding). fromSecretKey
    // fails only on a zero/non-canonical scalar — bip340.SecretKey.fromBytes
    // already rejects those, so this is a defensive re-check.
    const kp = bip340.KeyPair.fromSecretKey(internal_sk) catch return error.InvalidInternalKey;
    const d = Scalar.fromBytes(kp.secret, .big) catch unreachable; // canonical by construction

    // Step 4: t over the even-y internal x; reject t >= n, never reduce.
    const t_bytes = tapTweakHash(kp.public.x, merkle_root);
    const t = Scalar.fromBytes(t_bytes, .big) catch return error.TweakOutOfRange;

    // Steps 5-6: q = (d + t) mod n, constant-time scalar add.
    return d.add(t).toBytes(.big);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names BIP341" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BIP341") != null);
}

test "TweakedPublicKey.encoded_length" {
    try std.testing.expectEqual(@as(usize, 32), TweakedPublicKey.encoded_length);
}

test "tap_tweak_tag is the BIP341 domain tag string" {
    try std.testing.expectEqualStrings("TapTweak", tap_tweak_tag);
}
