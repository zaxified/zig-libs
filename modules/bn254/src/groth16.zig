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
//! a REAL, independently-sourced snarkjs-produced Groth16/BN254 proof —
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
//!    `A` (not `C`, not `vk_x`) is the form that makes the REAL proof
//!    below verify TRUE — independently re-derived with `py_ecc` before
//!    this file trusted it (see "KAT provenance").
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
// The positive vector (a proof that verifies TRUE) is a REAL,
// independently-sourced snarkjs-produced Groth16/BN254 proof — NOT
// self-generated by this module or its author. Source: the Dark Forest
// v0.3 game's "move" circuit (a proof-of-visibility zk-SNARK, a
// well-known production zkSNARK dApp from the Ethereum zk community),
// `github.com/darkforest-eth/darkforest-v0.3`, path `circuits/move/`,
// commit `1c83685e22e0463d5481c83e21616745b3204c9c` (fetched 2026-07-15):
// `verification_key.json` (`nPublic: 5`, 6 `IC` points), `proof.json`
// (`pi_a`/`pi_b`/`pi_c`), `public.json` (5 public-input integers). Field
// names (`vk_alfa_1`/`vk_beta_2`/.../`IC`, `protocol: "groth"`) are an
// EARLY snarkjs naming convention (pre-`groth16`-rename) for the SAME
// Groth16 construction this file implements — confirmed structurally
// (the `vk_alfabeta_12`-shaped verifying key and the `e(A,B) ==
// e(α,β)·e(vk_x,γ)·e(C,δ)` equation this module's own "verification
// equation" doc comment states) AND numerically (below).
//
// **Independently re-verified with `py_ecc` before being trusted as this
// file's KAT** (a THIRD implementation — neither this module's own Zig
// tower/pairing code nor snarkjs/circom's, so it cannot share a bug with
// either): a standalone Python script parsed the three JSON files,
// confirmed every vk/proof point is on its respective curve, computed
// `vk_x` via `py_ecc.bn128`'s own EC arithmetic, and confirmed
// `pairing(B,-A) * pairing(beta,alpha) * pairing(gamma,vk_x) *
// pairing(delta,C) == FQ12.one()` — i.e. the exact single-product
// `pairingCheck` form and sign convention (`-A`, not `-C`/`-vk_x`) this
// module's `verify` implements, confirmed to be the form that makes THIS
// specific real proof verify TRUE. The same script confirmed each
// tamper case below (`+1` to a coordinate, `+1` to a public input) makes
// the equation fail — either by landing off-curve (`py_ecc` raises,
// mirroring this file's `isOnCurve`/`subgroupCheck` rejection) or by
// landing on-curve but at the wrong point (the pairing product `!=
// FQ12.one()`).
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
// Provenance/licensing: `darkforest-eth/darkforest-v0.3` carries no
// explicit OSS license file (GitHub reports `NOASSERTION`) — the three
// embedded JSON files are NUMERIC PROOF/KEY DATA (elliptic-curve point
// coordinates and field elements, the deterministic output of running
// the Groth16 protocol over a specific circuit/witness), the same
// "public numeric conformance data, not copyrightable expression" category
// `SPEC.md`'s "Part 5 — KAT sourcing" and `NOTICE` item 5 already treat
// `ethereum/go-ethereum`'s (LGPL-3.0) precompile test vectors as — listed
// here out of the same caution, not because the data is source code or
// creative expression. No darkforest-v0.3 SOURCE (circuit/application
// code) was read or ported; only these three already-computed JSON data
// files were fetched. See `NOTICE`'s new entry for the full accounting.

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

// verification_key.json (darkforest-v0.3 "move" circuit, nPublic = 5,
// 6 IC points).
const kat_alpha_g1 = g1FromDecimal(
    "12356802866449684997754107026347724953200774039678274471013975138517593361087",
    "21147804457019395991806869559397462101175520127921542208311373203012833194601",
);
const kat_beta_g2 = g2FromDecimal(
    "15808958171969166309350067434410880068685601765078930692701835659651547482842",
    "20312436584921143996382367775395050029037126489576390051832424712464633156881",
    "9008008905525251120175076460731597382202744275427804476364024531090012620564",
    "11841408325541200734034253864958381613260236318165289062766853151562613702905",
);
const kat_gamma_g2 = g2FromDecimal(
    "7122013203828801274422153445030402003881969525105563481484708347337413201538",
    "11361795804780224978844178001925729689650024058711422666157584535385144431705",
    "20096615172017458085651599655933948938448025857163979534957128223939618198388",
    "5002285043841389455832994040165569944922238258053153530287333974352125021902",
);
const kat_delta_g2 = g2FromDecimal(
    "523054318759045886270478616254946240625318844591509494535337822553965419812",
    "8232217592337110330679426534589513839782865123649121485999683802146395728986",
    "18308456029233847815432487462880449809684697385055594585677517361167895152523",
    "4775559301227633713252197493351530092469029275309412496189875893005909128344",
);
const kat_ic = [_]G1.Affine{
    g1FromDecimal(
        "5137757912911425606111596161256428319175968695746466094372617689727883934476",
        "16947946068729419285709126507628073529337421739971475956480754903096508265527",
    ),
    g1FromDecimal(
        "12579634223583854130962938841109141174899560596507357021188528481766728424450",
        "20525055772249706643897653591342282874821822793792227510348605834653297945682",
    ),
    g1FromDecimal(
        "14622227896628130111052972056837140629321300430578590306328210813525830072328",
        "6184833258955319070536885489455869985346738032641561420359557770756648976828",
    ),
    g1FromDecimal(
        "16066947475381981290744201544908693647123066648401692774090893152870028461573",
        "10771769201246879183931872929279706856164311318494670331707717089024576077594",
    ),
    g1FromDecimal(
        "12610108600517026896705631215189062744819841027302360627680860843541213513408",
        "11288659798374481219360116219410436830823818049675377774842959008385292732179",
    ),
    g1FromDecimal(
        "15049428532631936537505424841304033088208616239552421553261584779111819398267",
        "10555418485704636736423712433298028713772103788953598601644039199059490897251",
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
    "8693580005467787402460678660515973961142392899453639560526351336649800165763",
    "1601960680801596667817559470006110882570369874219842186152136495286280624131",
);
const kat_proof_b = g2FromDecimal(
    "14029560171854909665267935652914649829322866757898164937528488925974520160322",
    "20167102410543351441845961699560361047379115866726351891287032480588855852566",
    "4067170394048281868925707330729333219257775539673586037587456263615667143048",
    "1777060998712810128912209467049453081042421757690353889525667230007229789253",
);
const kat_proof_c = g1FromDecimal(
    "17717411333710378385103570907569203687135836965196721930610196137391609857457",
    "1995210733499610896252288166613262074275730723292391481005133984485761634655",
);

fn kat_proof() Proof {
    return .{ .a = kat_proof_a, .b = kat_proof_b, .c = kat_proof_c };
}

// public.json.
const kat_public = [_]Fr{
    frFromDecimal("9270064407844522250726019704400577206166940151360906923837371740888388330563"),
    frFromDecimal("667038176106916676386407528871558531070201918615189347292699666788998294977"),
    frFromDecimal("16"),
    frFromDecimal("5000"),
    frFromDecimal("53"),
};

test "KAT: the REAL darkforest-v0.3 move-circuit Groth16 proof verifies TRUE" {
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
    var c1_bytes = [_]u8{0} ** 32;
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
        verify(kat_vk(), kat_proof(), kat_public[0..4]),
    );
    var too_many: [6]Fr = undefined;
    @memcpy(too_many[0..5], &kat_public);
    too_many[5] = Fr.zero;
    try std.testing.expectError(
        error.WrongPublicInputCount,
        verify(kat_vk(), kat_proof(), &too_many),
    );
}

test "empty public inputs against a 1-element IC (n=0 circuit shape) is a valid call shape" {
    // Not the real KAT's vk (which has 6 IC entries) — just confirms the
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
    try std.testing.expect(vk.ic.len == 6);
    const proof = kat_proof();
    try std.testing.expect(!proof.a.infinity);
    try std.testing.expect(!proof.b.infinity);
    try std.testing.expect(!proof.c.infinity);
}
