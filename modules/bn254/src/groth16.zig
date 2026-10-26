// SPDX-License-Identifier: MIT
//! **Part 6 (final)** of this module's multi-part arc (`README.md`): a
//! Groth16 zk-SNARK proof VERIFIER over BN254 — `VerifyingKey`/`Proof`
//! structs plus `verify`, composing Part 3's `G1`/`G2` group arithmetic
//! with Part 4's `pairing.pairingCheck`. Pure COMPOSITION, no new field/
//! curve/pairing primitive: the multi-scalar accumulation of the public
//! -input commitment (`vk_x`, a loop of `G1.Jacobian.add`/`scalarMul`)
//! and one `pairingCheck` call over four `(G1,G2)` pairs.
//!
//! **Status: implemented.** `verify` is byte/semantically exact against
//! a snarkjs-produced Groth16/BN254 proof over our own circuit —
//! see this file's own "KAT provenance" doc comment below and
//! `SPEC.md`'s "Part 6" section for the full accounting.
//!
//! ## The verification equation
//!
//! Verifying key: `α ∈ G1`, `β, γ, δ ∈ G2`, `IC[0..n] ∈ G1` (`n` = the
//! number of public inputs; `IC` has `n+1` elements — `IC[0]` is the
//! constant term). Proof: `A, C ∈ G1`, `B ∈ G2`. Public inputs:
//! `pub[1..n] ∈ Fr`.
//!
//! 1. `vk_x = IC[0] + Σ_{i=1..n} pub[i] · IC[i]` — a `G1` multi-scalar
//!    accumulation (`msm`, below).
//! 2. `e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)`, checked as ONE
//!    `pairingCheck` product-equals-1 (the standard snarkjs/Ethereum
//!    -verifier single-pairing-check form, negating `A`):
//!    ```
//!    e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
//!    ```
//!    **Sign convention confirmed against the KAT, not assumed**: negating
//!    `A` (not `C`, not `vk_x`) is the form that makes the snarkjs proof
//!    below verify TRUE, and the "negated A" tamper test shows the other
//!    sign fails (see "KAT provenance").
//!
//! ## Trust boundary — which points get validated, and why
//!
//! `vk` is the TRUSTED output of a circuit-specific setup ceremony — this
//! module does not re-validate `vk`'s points (same trust-boundary
//! discipline `pairing.zig`'s module doc comment already draws: `p`/`q`
//! inputs to `millerLoop` are assumed on-curve/in-subgroup, a caller
//! obligation). `proof` is the UNTRUSTED external input (attacker
//! -controlled calldata/API input in any real deployment), so `verify`
//! validates it before ever calling the pairing core:
//! - **`A`, `C` (`G1`)**: `isOnCurve()` — for `G1`, this IS
//!   `subgroupCheck()` (`g1.zig`'s module doc comment: `G1`'s cofactor is
//!   1), so one cheap curve-equation check is the FULL subgroup guarantee,
//!   no scalar multiplication needed.
//! - **`B` (`G2`)**: `subgroupCheck()` — the REAL `[r]P == O` check
//!   (`g2.zig`'s module doc comment: `G2`'s cofactor is nontrivial, so
//!   on-curve alone is NOT sufficient). This is the security-relevant
//!   check the task brief calls out: an unchecked small-subgroup `B`
//!   lets an attacker force a degenerate/predictable pairing result — the
//!   same pitfall Ethereum's own `ecPairing` precompile semantics guard
//!   against (`precompiles.zig`'s `ecPairingCheck`, Part 5, does the
//!   identical check on every decoded `G2` operand).
//!
//! A proof point failing either check makes `verify` return `false` — the
//! same outcome as a proof that is on-curve/in-subgroup but simply
//! doesn't satisfy the pairing equation, not a distinct error variant:
//! from a caller's perspective both are "this proof does not verify".
//!
//! ## Public inputs are `Fr`, not raw bytes
//!
//! `verify` takes `public_inputs: []const Fr`, not raw byte strings — so
//! "reject a public input `>= r`" is enforced by the TYPE, at the point a
//! caller parses calldata into `Fr` (`Fr.fromBytes` already rejects
//! non-canonical values, `error.NonCanonical` — `scalar.zig`), not by a
//! separate check inside this file. Same "make illegal states
//! unrepresentable" discipline as the rest of this module's API surface
//! (e.g. `G2.Jacobian.subgroupCheck`'s mandatory-before-trusting
//! contract). See this file's own test for the explicit KAT-adjacent
//! demonstration.
const std = @import("std");
const fp = @import("fp.zig");
const fp2mod = @import("fp2.zig");
const scalarmod = @import("scalar.zig");
const g1mod = @import("g1.zig");
const g2mod = @import("g2.zig");
const pairingmod = @import("pairing.zig");

pub const Fp = fp.Fp;
pub const Fp2 = fp2mod.Fp2;
pub const Fr = scalarmod.Fr;
pub const G1 = g1mod;
pub const G2 = g2mod;

/// A circuit-specific Groth16 verifying key. `ic.len` MUST be
/// `public_inputs.len + 1` for any `verify` call (`ic[0]` is the constant
/// term; `ic[1..]` pair one-to-one with the public inputs) — a mismatch
/// is `error.WrongPublicInputCount`, not a panic or a silently-wrong
/// accumulation.
///
/// TRUSTED input (see module doc comment's "Trust boundary" section):
/// `verify` does not re-validate `alpha_g1`/`beta_g2`/`gamma_g2`/
/// `delta_g2`/`ic` are on-curve/in-subgroup — a `vk` is the output of a
/// circuit's setup ceremony, not attacker-controlled per-call input.
pub const VerifyingKey = struct {
    alpha_g1: G1.Affine,
    beta_g2: G2.Affine,
    gamma_g2: G2.Affine,
    delta_g2: G2.Affine,
    /// `ic[0]` is the constant term; `ic[1..]` are the per-public-input
    /// commitment bases. Length `n+1` for `n` public inputs.
    ic: []const G1.Affine,
};

/// A Groth16 proof: `A, C ∈ G1`, `B ∈ G2`. UNTRUSTED input — see module
/// doc comment's "Trust boundary" section; `verify` validates every
/// field before using it in the pairing check.
pub const Proof = struct {
    a: G1.Affine,
    b: G2.Affine,
    c: G1.Affine,
};

/// Errors `verify` can return — malformed CALL shape, not "the proof is
/// cryptographically invalid" (that outcome is the ordinary `false`
/// return, not an error — see the module doc comment's "Trust boundary"
/// section).
pub const Groth16Error = error{
    /// `public_inputs.len + 1 != vk.ic.len` — the caller supplied the
    /// wrong verifying key for this proof's public-input count (or vice
    /// versa). There is no sensible `vk_x` to accumulate, so this is
    /// rejected before any curve arithmetic runs, distinctly from a
    /// cryptographically-false proof.
    WrongPublicInputCount,
};

/// The `G1` multi-scalar accumulation `IC[0] + Σ pub[i]·IC[i]` — a plain
/// loop of `G1.Jacobian.scalarMul`/`add` (no batching/Pippenger; `n` here
/// is a handful of public inputs, not a SNARK-scale MSM, so the simple
/// loop is the right tool — see `SPEC.md`'s Backlog for the explicit
/// non-goal). Allocation-free: `vk.ic.len` (checked equal to
/// `public_inputs.len + 1` by `verify` before this is called) bounds the
/// loop, no dynamic storage needed.
fn msm(ic: []const G1.Affine, public_inputs: []const Fr) G1.Jacobian {
    var acc = G1.Jacobian.fromAffine(ic[0]);
    for (public_inputs, ic[1..]) |s, base| {
        acc = acc.add(G1.Jacobian.fromAffine(base).scalarMul(s));
    }
    return acc;
}

/// Verifies a Groth16 proof against `vk` and `public_inputs`. Returns
/// `true` iff the proof is well-formed (see "Trust boundary" above) AND
/// satisfies `e(A,B) == e(α,β)·e(vk_x,γ)·e(C,δ)`; `false` for EITHER a
/// malformed proof point OR a well-formed-but-cryptographically-invalid
/// one (see module doc comment — both are "this proof does not verify"
/// from a caller's perspective). `Groth16Error.WrongPublicInputCount` is
/// the one distinct error: a call-shape mismatch between `vk` and
/// `public_inputs`, not a property of the proof itself.
pub fn verify(vk: VerifyingKey, proof: Proof, public_inputs: []const Fr) Groth16Error!bool {
    if (public_inputs.len + 1 != vk.ic.len) return error.WrongPublicInputCount;

    // Untrusted-input validation (module doc comment's "Trust boundary"):
    // A/C on-curve (== subgroup membership, G1 cofactor 1); B in-subgroup
    // (the real [r]P == O check — G2's cofactor is nontrivial, on-curve
    // alone is not enough). A failure here is "does not verify", not a
    // distinct error — see this function's own doc comment.
    if (!G1.Jacobian.fromAffine(proof.a).isOnCurve()) return false;
    if (!G1.Jacobian.fromAffine(proof.c).isOnCurve()) return false;
    if (!G2.Jacobian.fromAffine(proof.b).subgroupCheck()) return false;

    const vk_x = msm(vk.ic, public_inputs).toAffine();
    const neg_a = G1.Jacobian.fromAffine(proof.a).negate().toAffine();

    return pairingmod.pairingCheck(&.{
        .{ .p = neg_a, .q = proof.b },
        .{ .p = vk.alpha_g1, .q = vk.beta_g2 },
        .{ .p = vk_x, .q = vk.gamma_g2 },
        .{ .p = proof.c, .q = vk.delta_g2 },
    });
}

// ── tests ────────────────────────────────────────────────────────────────
//
// ## KAT provenance
//
// The positive vector (a proof that verifies TRUE) is a snarkjs-produced
// Groth16/BN254 proof over a circuit of OUR OWN — the `groth16` module's
// fixture `t.circom` (`out <== a*b*c + a`, `a` public), with its
// `vk.json`/`proof.json`/`public.json` in `groth16/src/testdata/snarkjs/`
// (`nPublic: 2` — `out` and `a` — 3 `IC` points). snarkjs and circom are
// GPL-3.0 and were run as black boxes by `groth16/tools/snarkjs/gen.sh`;
// what is kept is their output over our circuit and witness, nothing they
// authored (root `NOTICE` §0). The proof is NOT produced by this module, so
// it is still an independent vector: snarkjs's own prover and its
// `groth16 verify` (which printed OK on it) share no code with the Zig
// tower and pairing below. The values were copied from those JSON files by
// script, not by hand.
//
// Until 2026-10-26 this KAT was a proof taken from a third-party repository
// that carries no licence; it was replaced because data without an
// MIT-compatible grant may not live in this repository.
//
// **Coordinate ordering — the snarkjs footgun.** `verification_key.json`/
// `proof.json`'s `Fp2` values (`vk_beta_2`, `vk_gamma_2`, `vk_delta_2`,
// `pi_b`) are nested `[c0, c1]` arrays in MATH order (real part first) —
// this file's `fp2FromDecimal` below reads the JSON's index-0 element as
// `c0` and index-1 as `c1` DIRECTLY, the opposite of `g2.zig`'s EIP-197
// byte-codec order (`c1||c0`, imaginary-first — see that file's module
// doc comment). Routing these decimal values through `G2.fromBytes`
// instead would silently produce a DIFFERENT, wrong point; every `Fp2`
// value below is built with `fp2FromDecimal` (direct `(c0, c1)`
// construction from field coordinates), never through the byte codec.
//
fn decimalBytes(comptime dec: []const u8) [32]u8 {
    @setEvalBranchQuota(1_000_000);
    comptime var x: comptime_int = 0;
    inline for (dec) |c| {
        if (c < '0' or c > '9') @compileError("bn254/groth16: non-digit in decimal literal");
        x = x * 10 + (@as(comptime_int, c) - '0');
    }
    comptime var out: [32]u8 = undefined;
    comptime var i: usize = 32;
    inline while (i > 0) {
        i -= 1;
        out[i] = x % 256;
        x = x / 256;
    }
    if (x != 0) @compileError("bn254/groth16: decimal literal does not fit in 32 bytes");
    return out;
}

/// Builds an `Fp` element directly from a comptime DECIMAL string (the
/// snarkjs JSON encoding) — deliberately NOT routed through any byte
/// codec, since these values are field coordinates, not wire-encoded
/// points (see this file's "KAT provenance" doc comment).
fn fpFromDecimal(comptime dec: []const u8) Fp {
    return Fp.fromBytes(decimalBytes(dec)) catch @compileError("bn254/groth16: KAT Fp coordinate >= p");
}

/// Builds an `Fp2` element `c0 + c1*u` from a snarkjs-JSON-order
/// `(c0, c1)` decimal pair — MATH order (real part first), the opposite
/// of `g2.zig`'s EIP-197 imaginary-first byte encoding. See this file's
/// "KAT provenance" / "coordinate ordering" doc comment.
fn fp2FromDecimal(comptime c0_dec: []const u8, comptime c1_dec: []const u8) Fp2 {
    return .{ .c0 = fpFromDecimal(c0_dec), .c1 = fpFromDecimal(c1_dec) };
}

fn g1FromDecimal(comptime x_dec: []const u8, comptime y_dec: []const u8) G1.Affine {
    return .{ .x = fpFromDecimal(x_dec), .y = fpFromDecimal(y_dec) };
}

fn g2FromDecimal(
    comptime x_c0_dec: []const u8,
    comptime x_c1_dec: []const u8,
    comptime y_c0_dec: []const u8,
    comptime y_c1_dec: []const u8,
) G2.Affine {
    return .{
        .x = fp2FromDecimal(x_c0_dec, x_c1_dec),
        .y = fp2FromDecimal(y_c0_dec, y_c1_dec),
    };
}

fn frFromDecimal(comptime dec: []const u8) Fr {
    return Fr.fromBytes(decimalBytes(dec)) catch @compileError("bn254/groth16: KAT Fr scalar >= r");
}

// verification_key.json (`groth16/src/testdata/snarkjs/vk.json`: nPublic = 2,
// 3 IC points).
const kat_alpha_g1 = g1FromDecimal(
    "17194067215177041878589164966991994016895416184814165903247027795653879226995",
    "15403394429150395065001333463325728915741773325345401033876241693460831606328",
);
const kat_beta_g2 = g2FromDecimal(
    "20542349174503030478046243108787432323906994508768383323229058822632910720936",
    "5277445623977068858857460748756951748087296250533080917076924402690578920105",
    "2007691431064191235205559353882917270616350608911935033870859042433699630089",
    "18850894077416510159720496668953538279061300508382582393117053373329337040710",
);
const kat_gamma_g2 = g2FromDecimal(
    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
);
const kat_delta_g2 = g2FromDecimal(
    "19759546116302439515913796353693124977784811190890342151857472271055123999317",
    "18969905741490029259719168743533886586083645291179089771699499478439417278599",
    "4306559093018355567721159723132703181538229385856044409222137980251252085722",
    "20016467453230641247384250723989547184193960036832102208945869855990697400847",
);
const kat_ic = [_]G1.Affine{
    g1FromDecimal(
        "8817735012969253789104959819485611063656294847227733398431493698040102630082",
        "18517122151648854944451462041833868350447510084300619901892754556455524592311",
    ),
    g1FromDecimal(
        "14191462614478929590382138503588235367034109494001411468332941775423007179109",
        "15148644290687535405727121877800705781755561746419603133891271397522600599170",
    ),
    g1FromDecimal(
        "18491675563798379015159990238294496516400348366767815712954526863348306076587",
        "11039597132983456868775493537562819921371012207450487164851927850765854663691",
    ),
};

fn kat_vk() VerifyingKey {
    return .{
        .alpha_g1 = kat_alpha_g1,
        .beta_g2 = kat_beta_g2,
        .gamma_g2 = kat_gamma_g2,
        .delta_g2 = kat_delta_g2,
        .ic = &kat_ic,
    };
}

// proof.json.
const kat_proof_a = g1FromDecimal(
    "11133384817273659792978187364835229014525558616656753126499819754640227171004",
    "115740237013644187654392672517975389239815734729651081528880693562200059466",
);
const kat_proof_b = g2FromDecimal(
    "7616159001038717447475525614721867609415072810422885391742600836230099715402",
    "930421990067148897082299582773611533919589368472272475131164803190465444060",
    "9078568855568297651246479999350168711566779221099552850600060775855017300947",
    "5438837462340158321374782977818611062143439970738392298527491755768324240509",
);
const kat_proof_c = g1FromDecimal(
    "10214359781094766257382034681025545698210130318212707671732762454079013819570",
    "14037384209473574870898462766004358144758933124697380173293684955458403757499",
);

fn kat_proof() Proof {
    return .{ .a = kat_proof_a, .b = kat_proof_b, .c = kat_proof_c };
}

// public.json.
const kat_public = [_]Fr{
    frFromDecimal("108"),
    frFromDecimal("3"),
};

test "KAT: a snarkjs-produced Groth16 proof over our own circuit verifies TRUE" {
    const ok = try verify(kat_vk(), kat_proof(), &kat_public);
    try std.testing.expect(ok);
}

test "tampered proof: A.x + 1 (lands off-curve) verifies FALSE" {
    var bad = kat_proof();
    bad.a.x = bad.a.x.add(Fp.one);
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered proof: negated A (on-curve, wrong point) verifies FALSE" {
    var bad = kat_proof();
    bad.a = G1.Jacobian.fromAffine(bad.a).negate().toAffine();
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered proof: C.y + 1 (lands off-curve) verifies FALSE" {
    var bad = kat_proof();
    bad.c.y = bad.c.y.add(Fp.one);
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered proof: negated C (on-curve, wrong point) verifies FALSE" {
    var bad = kat_proof();
    bad.c = G1.Jacobian.fromAffine(bad.c).negate().toAffine();
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered proof: B.x.c0 + 1 (lands off-curve, subgroupCheck rejects) verifies FALSE" {
    var bad = kat_proof();
    bad.b.x.c0 = bad.b.x.c0.add(Fp.one);
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered proof: B on-curve but OUTSIDE the r-subgroup verifies FALSE" {
    // Same on-twist-but-not-in-subgroup G2 point as precompiles.zig's own
    // "on-twist-but-not-in-subgroup G2 operand is rejected" test (x = u,
    // c0 = 0, c1 = 1) — on-curve (isOnCurve would accept it) but NOT a
    // member of the order-r subgroup, independently confirmed there. Before
    // this test, NO test in this file ever fed verify a proof.b that was
    // on-curve-but-not-in-subgroup at all (only "off-curve" B was tested).
    //
    // NOTE (mutation testing, not overclaiming): mutating this call site's
    // `subgroupCheck()` to `isOnCurve()` does NOT make this test fail — a
    // wrong/unrelated B still fails the pairing equation for ordinary
    // reasons, so this is an equivalent mutant *for a naively substituted
    // B*. Actually forcing a divergence needs a genuine small-subgroup
    // malleability construction (add a nontrivial cofactor-order point to a
    // real proof's B and show the pairing equation still holds without the
    // subgroup check) — a nontrivial crypto construction, not just a KAT
    // substitution. Documented as a gap, not closed: see module doc
    // comment's "Trust boundary" section for why the check is still
    // required (EIP-197's own precedent), even though this test alone
    // cannot discriminate its removal.
    var c1_bytes = @as([32]u8, @splat(0));
    c1_bytes[31] = 1;
    var y_c0_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c0_bytes, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    var y_c1_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c1_bytes, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    const bad_b = G2.Affine{
        .x = .{ .c0 = Fp.zero, .c1 = try Fp.fromBytes(c1_bytes) },
        .y = .{ .c0 = try Fp.fromBytes(y_c0_bytes), .c1 = try Fp.fromBytes(y_c1_bytes) },
    };
    // Sanity, independent of verify: on-curve, but not subgroup (matches
    // precompiles.zig's own sanity check on the identical point).
    try std.testing.expect(G2.Jacobian.fromAffine(bad_b).isOnCurve());
    try std.testing.expect(!G2.Jacobian.fromAffine(bad_b).subgroupCheck());

    var bad = kat_proof();
    bad.b = bad_b;
    const ok = try verify(kat_vk(), bad, &kat_public);
    try std.testing.expect(!ok);
}

test "tampered public input: pub[0] + 1 verifies FALSE" {
    var bad_public = kat_public;
    bad_public[0] = bad_public[0].add(Fr.one);
    const ok = try verify(kat_vk(), kat_proof(), &bad_public);
    try std.testing.expect(!ok);
}

test "wrong public-input count is rejected (too few and too many)" {
    try std.testing.expectError(
        error.WrongPublicInputCount,
        verify(kat_vk(), kat_proof(), kat_public[0..1]),
    );
    var too_many: [kat_public.len + 1]Fr = undefined;
    @memcpy(too_many[0..kat_public.len], &kat_public);
    too_many[kat_public.len] = Fr.zero;
    try std.testing.expectError(
        error.WrongPublicInputCount,
        verify(kat_vk(), kat_proof(), &too_many),
    );
}

test "empty public inputs against a 1-element IC (n=0 circuit shape) is a valid call shape" {
    // Not the real KAT's vk (which has 3 IC entries) — just confirms the
    // n=0 msm/count-check path (ic.len == 1, public_inputs.len == 0)
    // doesn't panic or misfire the count check, using the real alpha/beta
    // /gamma/delta and the real IC[0] alone as a minimal well-formed vk.
    const vk: VerifyingKey = .{
        .alpha_g1 = kat_alpha_g1,
        .beta_g2 = kat_beta_g2,
        .gamma_g2 = kat_gamma_g2,
        .delta_g2 = kat_delta_g2,
        .ic = kat_ic[0..1],
    };
    try std.testing.expectError(error.WrongPublicInputCount, verify(vk, kat_proof(), &kat_public));
    // Correct shape (0 public inputs, 1-element IC) — cryptographically
    // false (this vk/proof pairing doesn't correspond to a 0-public-input
    // circuit) but must return `false`, not error or panic.
    const ok = try verify(vk, kat_proof(), &.{});
    try std.testing.expect(!ok);
}

test "public input >= r is rejected BY THE Fr TYPE, before it could reach verify" {
    // verify's signature takes []const Fr, not raw bytes — Fr.fromBytes
    // (scalar.zig) already rejects any value >= r as error.NonCanonical,
    // so an out-of-field public input can never be constructed to pass
    // to verify in the first place. This is the module doc comment's
    // "Public inputs are Fr, not raw bytes" design point, demonstrated
    // directly against r itself and r-1 (the boundary).
    try std.testing.expectError(error.NonCanonical, Fr.fromBytes(scalarmod.r_bytes));
    var r_minus_1 = scalarmod.r_bytes;
    r_minus_1[31] -= 1;
    _ = try Fr.fromBytes(r_minus_1); // must NOT error: r-1 is canonical
}

test "VerifyingKey/Proof field shapes match the task's documented API" {
    const vk = kat_vk();
    try std.testing.expect(vk.ic.len == 3);
    const proof = kat_proof();
    try std.testing.expect(!proof.a.infinity);
    try std.testing.expect(!proof.b.infinity);
    try std.testing.expect(!proof.c.infinity);
}
