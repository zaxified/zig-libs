// SPDX-License-Identifier: MIT
//! Frozen snarkjs cross-check — closing SPEC.md's one corrected blind spot
//! (see this file's own reasoning, and `snarkjs_export.zig`'s module doc
//! comment): the sibling `bn254` verifier is a complete ALGEBRAIC oracle,
//! but it decodes the SAME encoding this module's prover writes, so a
//! serialization-convention bug both sides agreed on (coordinate order,
//! endianness, a swapped G2 pair) would round-trip cleanly forever while a
//! genuinely FOREIGN verifier rejected the bytes. This file freezes the one
//! artifact that closes that gap: our own proof, exported through
//! `snarkjs_export.zig`'s JSON encoder, judged by `snarkjs@0.7.6`
//! (iden3, Apache-2.0) — fetched via `bunx`, run OUTSIDE this test suite,
//! never vendored, never invoked from `zig build test` (no network/process
//! spawn happens below — this file only asserts against the frozen
//! transcript).
//!
//! ## The fixture: reproducible, not hand-transcribed
//!
//! The circuit/witness/toxic-waste/randomizers are the EXACT values
//! `harness_test.zig`'s "end-to-end anchor" test already uses (duplicated
//! here rather than shared, since that file's helpers are private — same
//! nt circuit: prove knowledge of private `x,y` with public
//! `out1=x², out2=y², out3=(x+y)²`, toxic waste
//! `tau=7,alpha=11,beta=13,gamma=17,delta=19`, randomizers `r=123,s=456`).
//! Because every one of those is a small fixed integer, re-running
//! `setup`+`prove` below reproduces the SAME proof bytes snarkjs judged —
//! no G1/G2 coordinate is hand-copied into this file. What IS frozen as a
//! literal is the JSON TEXT snarkjs actually saw and the transcript of its
//! verdict — that is the artifact this task freezes (per the task brief:
//! "freeze the specific proof that snarkjs accepted... What is being
//! anchored is the encoding, not the randomness").
//!
//! ## What ran, verbatim (both attempts)
//!
//! `bunx` (`~/.bun/bin/bunx`) fetches `snarkjs@0.7.6` into ITS OWN cache —
//! not a repo dependency; `build.zig`/`build.zig.zon` are untouched.
//!
//! **First attempt — the literal documented CLI**, against exactly the JSON
//! `verifyingKeyJson`/`proofJson`/`publicJson` (below) produce for this
//! fixture:
//! ```
//! $ bunx snarkjs groth16 verify verification_key.json public.json proof.json
//! ```
//! Crashed before ever reading the files — a Bun-RUNTIME bug, unrelated to
//! our data: `ffjavascript`'s WASM curve builder spawns a `Worker` thread
//! pool by default, and Bun's `web-worker` npm package shim for
//! `worker_threads` throws inside the worker thread —
//! `TypeError: Argument 1 ('event') to EventTarget.dispatchEvent must be an
//! instance of Event` — taking the process down with `SIGILL` (exit 132).
//! Confirmed environment-specific (reproduces for ANY input, before JSON
//! parsing even starts), not a rejection of our proof.
//!
//! **Final — the SAME unmodified `snarkjs@0.7.6` `groth16.verify`
//! function**, invoked directly (bypassing only the CLI's process entry
//! point, not one line of its verification logic) with the library's own
//! documented single-thread fallback forced on — `ffjavascript`'s
//! `buildThreadManager` source: `if (process.browser && !globalThis.Worker)
//! singleThread = true;` — via `process.browser = true; delete
//! globalThis.Worker;` before `require("snarkjs")`, the same technique real
//! snarkjs deployments use to run inside browsers/bundlers with no thread
//! pool (NOT a change to snarkjs's own code, just an environment condition
//! its own source already branches on):
//! ```
//! $ bun run run_verify.js
//! # run_verify.js:
//! #   process.browser = true; delete globalThis.Worker;
//! #   const snarkjs = require("snarkjs");
//! #   const vk = require("./verification_key.json");
//! #   const proof = require("./proof.json");
//! #   const pub = require("./public.json");
//! #   snarkjs.groth16.verify(vk, pub, proof).then(res => {
//! #     console.log("RESULT", res); process.exit(res ? 0 : 1);
//! #   });
//! RESULT true
//! $ echo $?
//! 0
//! ```
//! **snarkjs accepted our proof on the FIRST correctly-invoked try** — no
//! serialization deviation found. The exporter's conventions (decimal-string
//! field elements; `G1` as `[x,y,"1"]`; `G2` as
//! `[[x.c0,x.c1],[y.c0,y.c1],["1","0"]]`, `(c0,c1)` MATH order — reverse-
//! engineered from `snarkjs@0.7.6`'s own bundled source, see
//! `snarkjs_export.zig`'s module doc comment) matched snarkjs's parser
//! exactly.
//!
//! **Tamper check — the converse, proving the oracle has teeth:** `pi_a`'s
//! x-coordinate incremented by one decimal
//! (`...805600623` → `...805600624`, landing off-curve), otherwise
//! byte-identical `proof.json`, same driver:
//! ```
//! $ bun run run_verify_tampered.js
//! RESULT false
//! $ echo $?
//! 1
//! ```
//! Rejected, as required (`isWellConstructed`'s on-curve check catches it
//! before the pairing equation is even evaluated).
//!
//! No `.zkey`/`.wtns` file was read or produced. `curve`/`protocol` field
//! NAMES are snarkjs's own schema vocabulary (not copyrightable expression —
//! same category as `NOTICE`'s existing format-only citations), and every
//! NUMERIC value in the exported JSON is THIS module's OWN `setup`/`prove`
//! output, not third-party data — no `NOTICE` entry is needed here
//! (contrast the sibling `bn254/NOTICE`'s Dark Forest entry, which vendors a
//! THIRD PARTY's numeric proof; nothing in this file is vendored, only
//! produced-by-us and independently judged).
//!
//! ## What this does NOT anchor
//!
//! The QAP/R1CS layer (constraint→polynomial correctness) stays a
//! self-oracle (`qap.checkDivisible == r1cs.isSatisfied`, `harness_test.zig`)
//! — snarkjs was never given our R1CS/QAP, only the final group elements, so
//! it has no opinion on whether THIS proof corresponds to THIS circuit's
//! intended semantics, only on whether the bytes decode to a valid Groth16
//! proof that satisfies the pairing equation for the given `vk`/public
//! inputs. That is exactly the algebra SPEC.md already claimed was complete;
//! this file's news is the ENCODING, which is now foreign-verified too.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const r1cs = @import("r1cs.zig");
const prover = @import("prover.zig");
const snarkjs_export = @import("snarkjs_export.zig");
const Fr = field.Fr;

// ── the nt circuit/witness/toxic-waste/randomizers (identical fixture to
// harness_test.zig's end-to-end anchor test) ────────────────────────────

const nt_num_vars: usize = 7;
const nt_num_public: usize = 3;
const nt_domain: usize = 4;

fn ntConstraints() [4]r1cs.Constraint {
    const one = Fr.one;
    return .{
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 6, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 4, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 1, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .b = &[_]r1cs.Term{.{ .index = 5, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 2, .coeff = one }},
        },
        .{
            .a = &[_]r1cs.Term{
                .{ .index = 1, .coeff = one },
                .{ .index = 2, .coeff = one },
                .{ .index = 6, .coeff = one },
                .{ .index = 6, .coeff = one },
            },
            .b = &[_]r1cs.Term{.{ .index = 0, .coeff = one }},
            .c = &[_]r1cs.Term{.{ .index = 3, .coeff = one }},
        },
    };
}

/// Satisfying witness for x=3, y=4: xy=12, out1=9, out2=16, out3=49.
fn ntWitness() [7]Fr {
    return .{
        Fr.one,
        field.frFromU64(9),
        field.frFromU64(16),
        field.frFromU64(49),
        field.frFromU64(3),
        field.frFromU64(4),
        field.frFromU64(12),
    };
}

fn ntToxicWaste() prover.ToxicWaste {
    return .{
        .tau = field.frFromU64(7),
        .alpha = field.frFromU64(11),
        .beta = field.frFromU64(13),
        .gamma = field.frFromU64(17),
        .delta = field.frFromU64(19),
    };
}

/// The exact `verification_key.json` text `bunx`/`bun run` fed to
/// `snarkjs@0.7.6` — see this file's module doc comment for the transcript.
/// `nPublic:3`, `IC` has 4 points (constant + 3 public inputs).
const frozen_vkey_json =
    "{\"protocol\":\"groth16\",\"curve\":\"bn128\",\"nPublic\":3," ++
    "\"vk_alpha_1\":[\"19033251874843656108471242320417533909414939332036131356573128480367742634479\"," ++
    "\"20792135454608030201903199625673964159744755218442260092768620403349374102584\",\"1\"]," ++
    "\"vk_beta_2\":[[\"16137324789686743234629608741537369181251990815455155257427276976918350071287\"," ++
    "\"280672898440571232725436467950720547829638241593507531241322547969961007057\"]," ++
    "[\"12136420650226457477690750437223209427924916790606163705631661913973995426040\"," ++
    "\"17641806683785498955878869918183868440783188556637975525088932771694068429840\"],[\"1\",\"0\"]]," ++
    "\"vk_gamma_2\":[[\"5571996575954125260736435753480252954196528247617148060558631406349160775832\"," ++
    "\"15577308679414974642168536368096450326086203870944559758314800234684337462316\"]," ++
    "[\"11302850696403459405052467769487663388868168369318255751101607320138145101673\"," ++
    "\"3949072583587836530885517791345259776526014207612010591436388615095276192789\"],[\"1\",\"0\"]]," ++
    "\"vk_delta_2\":[[\"9858527670347636692234166401928174269791741769432234490836150038270445961293\"," ++
    "\"16849508654450081119304017172227396057124361478955927014163046732185922553166\"]," ++
    "[\"20108569381576808061469857349769609506804248011311707108758562062556705125393\"," ++
    "\"13963340053412710066602628493986245254268869857782169725667227673717164818367\"],[\"1\",\"0\"]]," ++
    "\"IC\":[[\"5048564054397894825386047652590508253062083530209767127000118978017585876500\"," ++
    "\"7951468184429781614798982919763166347452384074229332329702519699169644959218\",\"1\"]," ++
    "[\"17290316078113485847974913800639043478026567024005198144516917797900550083855\"," ++
    "\"15610643765549448096937189864915916552444567812838742707134919901889104895391\",\"1\"]," ++
    "[\"6667757198294336952221920866817546816118138695273026546428907892026522145928\"," ++
    "\"17936396306390611359413752932439844405618671553557430105335281689212388723451\",\"1\"]," ++
    "[\"12331978264173845845547182051411778392781489253208697089821283143000558979526\"," ++
    "\"9067605197885988898139898458348578540663528741062412796600344529111295215516\",\"1\"]]}";

/// The exact `proof.json` text `bunx`/`bun run` fed to `snarkjs@0.7.6` —
/// `RESULT true`, exit 0 (see module doc comment).
const frozen_proof_json =
    "{\"pi_a\":[\"19587703548641671366761737642385135263156966687507454983227812476335605600623\"," ++
    "\"3484371943130088224738578550917419502970704458972089602478464149821400686015\",\"1\"]," ++
    "\"pi_b\":[[\"18216014425844904438651403196602091265715455092820112235851615737949484109815\"," ++
    "\"6452322672664455717566245449526033160116771950636278969251790250571418570856\"]," ++
    "[\"12041168663459188990095813379266431213477600429765562174234647336112078421597\"," ++
    "\"16205613072312027927646384450985687533131049685059506013738830809583752744804\"],[\"1\",\"0\"]]," ++
    "\"pi_c\":[\"7324998683233831126446596077764753397964784595670466539821067580378835056914\"," ++
    "\"3431065850838452281500036950435567434409311269330986757883719889375666145277\",\"1\"]," ++
    "\"protocol\":\"groth16\",\"curve\":\"bn128\"}";

/// The exact `public.json` text `bunx`/`bun run` fed to `snarkjs@0.7.6`:
/// `[out1, out2, out3] = [9, 16, 49]` for `x=3, y=4`.
const frozen_public_json = "[\"9\",\"16\",\"49\"]";

fn buildKatFixture(alloc: std.mem.Allocator) !struct {
    kp: prover.KeyPair,
    proof: bn254.Groth16Proof,
    witness: [7]Fr,
} {
    const cons = ntConstraints();
    const sys = r1cs.System{ .num_vars = nt_num_vars, .constraints = &cons };
    const w = ntWitness();
    std.debug.assert(sys.isSatisfied(&w));

    const kp = try prover.setup(nt_domain, alloc, sys, nt_num_public, ntToxicWaste());
    const proof = prover.prove(nt_domain, kp.pk, sys, nt_num_public, &w, .{
        .r = field.frFromU64(123),
        .s = field.frFromU64(456),
    });
    return .{ .kp = kp, .proof = proof, .witness = w };
}

test "snarkjs KAT: re-derived fixture still verifies under bn254 (self-consistency)" {
    const alloc = std.testing.allocator;
    const fx = try buildKatFixture(alloc);
    defer prover.freeKeyPair(alloc, fx.kp);

    const public = fx.witness[1 .. nt_num_public + 1];
    try std.testing.expect(try bn254.groth16Verify(fx.kp.vk, fx.proof, public));
}

test "snarkjs KAT: exporter reproduces the EXACT JSON snarkjs accepted (byte-for-byte)" {
    const alloc = std.testing.allocator;
    const fx = try buildKatFixture(alloc);
    defer prover.freeKeyPair(alloc, fx.kp);

    const public = fx.witness[1 .. nt_num_public + 1];

    const vkey_json = try snarkjs_export.verifyingKeyJson(alloc, fx.kp.vk);
    defer alloc.free(vkey_json);
    try std.testing.expectEqualStrings(frozen_vkey_json, vkey_json);

    const proof_json = try snarkjs_export.proofJson(alloc, fx.proof);
    defer alloc.free(proof_json);
    try std.testing.expectEqualStrings(frozen_proof_json, proof_json);

    const public_json = try snarkjs_export.publicJson(alloc, public);
    defer alloc.free(public_json);
    try std.testing.expectEqualStrings(frozen_public_json, public_json);
}

test "snarkjs KAT: the tamper snarkjs rejected (pi_a.x + 1) is ALSO rejected by bn254" {
    // Same tamper sent to snarkjs in the frozen transcript above
    // (`proof_tampered.json`: pi_a's x-coordinate + 1, landing off-curve) —
    // confirming the sibling verifier and the foreign one agree on this
    // rejection, independently.
    const alloc = std.testing.allocator;
    const fx = try buildKatFixture(alloc);
    defer prover.freeKeyPair(alloc, fx.kp);

    const public = fx.witness[1 .. nt_num_public + 1];
    try std.testing.expect(try bn254.groth16Verify(fx.kp.vk, fx.proof, public)); // baseline

    var bad = fx.proof;
    bad.a.x = bad.a.x.add(bn254.Fp.one);
    try std.testing.expect(!(try bn254.groth16Verify(fx.kp.vk, bad, public)));
}
