// SPDX-License-Identifier: MIT
//! Byte-exact known-answer tests against **external** vectors.
//!
//! Anchoring grade, in this repo's vocabulary:
//!
//!   * **Grade 1 — published vectors / reference-implementation output.**
//!     Everything in this file. Three independent upstream sources, each
//!     listed with the exact command that produced the numbers:
//!
//!     1. `hadeshash/code/test_vectors.txt` — the Poseidon *authors'* own
//!        permutation vectors, for all four GF(p) instances they publish.
//!     2. `circomlibjs/test/poseidon.js` — the known-answer values in the
//!        deployed reference implementation's own test suite.
//!     3. circomlibjs *executed* — a width sweep produced by running
//!        `poseidon_reference.js` and `poseidon_opt.js` and requiring the two
//!        to agree, so all 16 published widths are covered rather than only
//!        the three the upstream suite happens to exercise.
//!
//!   * Grade 2 (independent re-derivation) and grade 3 (self round-trip) are
//!     **not** what this file rests on. A grade-2 cross-check did happen
//!     during development — a from-scratch Python port of
//!     `generate_parameters_grain.sage` plus the permutation, which reproduced
//!     every value below — but it shares a source with this implementation, so
//!     it is corroboration, not the anchor.
//!
//! ## Reproducing the sources
//!
//! ```sh
//! git clone --depth 1 https://extgit.iaik.tugraz.at/krypto/hadeshash.git
//! cat hadeshash/code/test_vectors.txt          # source 1, verbatim below
//!
//! git clone --depth 1 https://github.com/iden3/circomlibjs.git
//! sed -n '20,40p' circomlibjs/test/poseidon.js # source 2 (decimal there)
//! ```
//!
//! Source 3, the width sweep — `bun install` in the circomlibjs clone, then
//! run this from inside it (node works too; `bun` is what was used here):
//!
//! ```js
//! // gen_vectors.mjs
//! import buildPoseidonReference from "./src/poseidon_reference.js";
//! import buildPoseidonOpt from "./src/poseidon_opt.js";
//! const ref = await buildPoseidonReference(), opt = await buildPoseidonOpt();
//! const F = ref.F, hex = (x) => F.toObject(x).toString(16).padStart(64, "0");
//! for (let n = 1; n <= 16; n++) {
//!   const inputs = Array.from({length: n}, (_, i) => i + 1);
//!   const r = hex(ref(inputs)), o = hex(opt(inputs));
//!   if (r !== o) throw new Error("ref != opt");   // cross-check, not decoration
//!   console.log("t=" + (n + 1) + " " + r);
//! }
//! ```

const std = @import("std");
const bn = @import("bn254_poseidon.zig");
const bls = @import("bls12_381_poseidon.zig");

fn expectFr(want_hex: *const [64:0]u8, got: anytype) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try std.testing.expectEqualSlices(u8, &want, &got.toBytes());
}

// ── source 1: the Poseidon authors' published permutation vectors ────────────
//
// `hadeshash/code/test_vectors.txt`. Every case is the permutation applied to
// the state `[0, 1, 2, …, t-1]`; the file lists all `t` output words and all
// of them are checked here, not just the first.
//
// These pin the *permutation*, not a hash: no capacity convention, no padding,
// nothing a framing choice could paper over. If the round split, the
// partial-round S-box position, or one round constant is wrong, every word
// moves.

test "hadeshash poseidonperm_x5_254_3 (BN254, t=3)" {
    const P = bn.Perm(3).init();
    const out = P.permute(.{ bn.fromU64(0), bn.fromU64(1), bn.fromU64(2) });
    try expectFr("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", out[0]);
    try expectFr("0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29", out[1]);
    try expectFr("0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c", out[2]);
}

// ── the all-zero state ────────────────────────────────────────────────────
//
// Every other vector in this file has at least one nonzero input; a coding
// bug that special-cases zero (a stray `if (x.isZero()) return x/state`
// shortcut, an S-box that mishandles `0^5`, an MDS row that only mixes
// nonzero entries correctly) would be invisible to all of them. This vector
// — capacity element AND both inputs zero — is source 3's methodology
// (circomlibjs `poseidon_reference.js`/`poseidon_opt.js`, executed, cross-
// checked against each other) applied to `inputs=[0,0]`, `initState=0`,
// `nOut=3`, so it pins the full permuted state exactly like the hadeshash
// vector above, not just one hash output.
test "circomlibjs (executed): the all-zero permutation state (BN254, t=3)" {
    const P = bn.Perm(3).init();
    const out = P.permute(.{ bn.Fr.zero, bn.Fr.zero, bn.Fr.zero });
    try expectFr("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", out[0]);
    try expectFr("13a545a13f1d91dddb87f46679dfaec0900ce24791a924bee7fa4d69a9569d85", out[1]);
    try expectFr("06be479e5fcd717c6c21b32f108033bf1da6cf4d8e3e8c48042c475e0b121480", out[2]);
    // `hash`/`compress` must agree with the raw permutation, the same
    // identity the non-zero "bridge" test below checks.
    try expectFr("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", P.hash(.{ bn.Fr.zero, bn.Fr.zero }));
    try expectFr("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", P.compress(bn.Fr.zero, bn.Fr.zero));
}

test "hadeshash poseidonperm_x5_254_5 (BN254, t=5)" {
    const P = bn.Perm(5).init();
    var st: [5]bn.Fr = undefined;
    for (0..5) |i| st[i] = bn.fromU64(i);
    const out = P.permute(st);
    try expectFr("299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465", out[0]);
    try expectFr("1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d", out[1]);
    try expectFr("24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907", out[2]);
    try expectFr("0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e", out[3]);
    try expectFr("07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7", out[4]);
}

test "hadeshash poseidonperm_x5_255_3 (BLS12-381, t=3)" {
    const P = bls.Perm(3).init();
    const out = P.permute(.{ bls.fromU64(0), bls.fromU64(1), bls.fromU64(2) });
    try expectFr("28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a", out[0]);
    try expectFr("51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4", out[1]);
    try expectFr("3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a", out[2]);
}

test "hadeshash poseidonperm_x5_255_5 (BLS12-381, t=5)" {
    const P = bls.Perm(5).init();
    var st: [5]bls.Fr = undefined;
    for (0..5) |i| st[i] = bls.fromU64(i);
    const out = P.permute(st);
    try expectFr("2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18", out[0]);
    try expectFr("65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7", out[1]);
    try expectFr("2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce", out[2]);
    try expectFr("4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566", out[3]);
    try expectFr("03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1", out[4]);
}

// ── source 2: circomlibjs' own test suite ────────────────────────────────────
//
// `circomlibjs/test/poseidon.js`. Values are decimal there; the hex below is
// `int(v).to_bytes(32, "big").hex()`. These exercise the *hash* framing —
// state `[initialState] ++ inputs` — including the non-zero `initialState`
// and multi-output paths that `hadeshash` does not cover.

test "circomlibjs Poseidon(2) and Poseidon(4)" {
    // it("Should check constrain reference implementation poseidonperm_x5_254_3")
    const p3 = bn.Perm(3).init();
    try expectFr("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", p3.hash(.{ bn.fromU64(1), bn.fromU64(2) }));

    // it("… poseidonperm_x5_254_5")
    const p5 = bn.Perm(5).init();
    try expectFr(
        "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
        p5.hash(.{ bn.fromU64(1), bn.fromU64(2), bn.fromU64(3), bn.fromU64(4) }),
    );
}

test "circomlibjs Poseidon with 16 inputs" {
    // it("Should check poseidon with 16 inputs")
    const P = bn.Perm(17).init();
    var in: [16]bn.Fr = undefined;

    for (0..16) |i| in[i] = bn.fromU64(i + 1);
    try expectFr("16159a551cbb66108281a48099fff949ae08afd7f1f2ec06de2ffb96b919b765", P.hash(in));

    // [1..9] then seven zeros — proves trailing zeros are real inputs, not
    // padding that could be dropped.
    for (0..16) |i| in[i] = bn.fromU64(if (i < 9) i + 1 else 0);
    try expectFr("1a456f8563b98c9649877f38b7e36534b241c29d457d307c481cbd12b69bb721", P.hash(in));
}

test "circomlibjs Poseidon with a non-zero initial state" {
    // it("Should check poseidon with init state")
    const p7 = bn.Perm(7).init();
    var in6: [6]bn.Fr = undefined;
    for (0..6) |i| in6[i] = bn.fromU64(i + 1);
    try expectFr("2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1", p7.hashN(1, bn.Fr.zero, in6)[0]);

    const p5 = bn.Perm(5).init();
    const in4 = [4]bn.Fr{ bn.fromU64(1), bn.fromU64(2), bn.fromU64(3), bn.fromU64(4) };
    try expectFr("0378246d3e22e3b62550a84213718b0ed9764f723aad339cbd533742ec582b2e", p5.hashN(1, bn.fromU64(7), in4)[0]);

    const p17 = bn.Perm(17).init();
    var in16: [16]bn.Fr = undefined;
    for (0..16) |i| in16[i] = bn.fromU64(i + 1);
    try expectFr("1163741e4f65057a9f670377aaa2ba62f52ab13f6732283f02a105b965591fbe", p17.hashN(1, bn.fromU64(17), in16)[0]);
}

test "circomlibjs Poseidon with n outputs" {
    // it("Should check poseidon with n outputs")
    const p2 = bn.Perm(2).init();
    try expectFr("29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133", p2.hash(.{bn.fromU64(1)}));

    const p3 = bn.Perm(3).init();
    const o2 = p3.hashN(2, bn.Fr.zero, .{ bn.fromU64(1), bn.fromU64(2) });
    try expectFr("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", o2[0]);
    try expectFr("0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29", o2[1]);

    const p6 = bn.Perm(6).init();
    const o3 = p6.hashN(3, bn.Fr.zero, .{
        bn.fromU64(1), bn.fromU64(2), bn.fromU64(0), bn.fromU64(0), bn.fromU64(0),
    });
    try expectFr("024058dd1e168f34bac462b6fffe58fd69982807e9884c1c6148182319cee427", o3[0]);
    try expectFr("02ce38b0ee8299cf60033331a0c16d781479e9793b326f929f83010003c4f3b4", o3[1]);
    try expectFr("136b35876ea275fe30d8721944a1fc499fa2e9bf81a1711074ccb0d6023936ba", o3[2]);
}

// ── source 3: circomlibjs executed, every published width ────────────────────
//
// `Poseidon(n)` over inputs `[1, 2, …, n]` for n = 1..16, i.e. t = 2..17.
// This is the test with the most teeth in the file: it touches every entry of
// `N_ROUNDS_P` and every derived MDS matrix, so a width-indexing slip or a
// single wrong round count cannot hide behind the three widths the upstream
// suite happens to exercise. Produced by `gen_vectors.mjs` above, with the
// optimized and the reference JS implementations required to agree.

const width_sweep = [16]*const [64:0]u8{
    "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133", // t=2
    "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", // t=3
    "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732", // t=4
    "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465", // t=5
    "0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0", // t=6
    "2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1", // t=7
    "1c2f3482dbb140c4ebb9ada49abdbc374a9a85fcfc6533ec2e9df45b4921c318", // t=8
    "2921ab9bd0140cbc98e40395c0fefb40337a4d54fbbecd9a4d43b3d8d0c4d8d1", // t=9
    "1e0b893aa2ad802275e749d260330b7675b22bb3aaa4461d204af32e60cd9078", // t=10
    "0816126a09c29ecfcc0628461dacfb9459816fc60d6738b78db9ad07206fdc21", // t=11
    "07e5b070aa2dba008f30a6b785b6c5ae2429e211f71cacdbdae0e07fc05b47a8", // t=12
    "058814945232937db248a01e7cc55b3d681cc08702c8168494e856c1ef7693b5", // t=13
    "0f918939632fadca6456a2fe6e65a124828d4c3920d379cc744e90a666887806", // t=14
    "1278779aaafc5ca58bf573151005830cdb4683fb26591c85a7464d4f0e527776", // t=15
    "094ae33b67a845998abb55e917642d4022d078d96f7c36ea11da4273ecf20f50", // t=16
    "16159a551cbb66108281a48099fff949ae08afd7f1f2ec06de2ffb96b919b765", // t=17
};

test "circomlibjs width sweep, t = 2..17" {
    inline for (2..18) |t| {
        const P = bn.Perm(t).init();
        var in: [t - 1]bn.Fr = undefined;
        for (0..t - 1) |i| in[i] = bn.fromU64(i + 1);
        try expectFr(width_sweep[t - 2], P.hash(in));
    }
}

test "circomlibjs, inputs at the top of the field" {
    // Same source, `gen_vectors.mjs` with inputs `[r-1, r-1]`. The largest
    // canonical element is where a sloppy reduction or an off-by-one in
    // `fromBytes` shows up and small-integer inputs never would.
    const P = bn.Perm(3).init();
    var be: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&be, "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
    const r_minus_1 = try bn.Fr.fromBytes(be);

    const out = P.hashN(3, bn.Fr.zero, .{ r_minus_1, r_minus_1 });
    try expectFr("2c6bd813a6338781378d8706cb82fd4216ab52b752ccd41564d7b98756a6e0fb", out[0]);
    try expectFr("1c95b184ebe5d89108c844ae1e0b71c410ae8b67f14074a95fb244d385b0f967", out[1]);
    try expectFr("0a39228d63816045998ffcc2f0d2a48722c979c306490dd91e0bd210a4aeba31", out[2]);
}

// ── framing checks (not anchors) ────────────────────────────────────────────

test "compress is Poseidon(2) is the t=3 permutation on [0, l, r]" {
    // A statement about the API surface, so `compress` cannot drift away from
    // the vector-pinned `hash`/`permute` beneath it. Uses the `Compress2`
    // alias, which is the name callers building Merkle trees will reach for.
    const P = bn.Compress2.init();
    comptime std.debug.assert(bn.Compress2 == bn.Perm(3));
    const l = bn.fromU64(0xdead_beef);
    const r = bn.fromU64(0x1234_5678_9abc_def0);
    const c = P.compress(l, r);
    try std.testing.expectEqualSlices(u8, &c.toBytes(), &P.hash(.{ l, r }).toBytes());
    try std.testing.expectEqualSlices(u8, &c.toBytes(), &P.permute(.{ bn.Fr.zero, l, r })[0].toBytes());
}

test "the two fields do not accidentally share an instance" {
    // Same t, same R_F/R_P, different prime *and* different Grain seed width
    // (254 vs 255). If a copy-paste ever pointed both at one config the
    // published vectors above would catch it, but this says it in one line.
    const b3 = bn.Perm(3).init();
    const l3 = bls.Perm(3).init();
    const a = b3.permute(.{ bn.fromU64(0), bn.fromU64(1), bn.fromU64(2) })[0].toBytes();
    const b = l3.permute(.{ bls.fromU64(0), bls.fromU64(1), bls.fromU64(2) })[0].toBytes();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
