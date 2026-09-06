// SPDX-License-Identifier: MIT
//
// The circomlibjs oracle behind `src/vectors_test.zig`.
//
// WHY THIS EXISTS. Every circomlibjs-derived number in `src/vectors_test.zig`
// is produced by RUNNING circomlibjs, never by reading its sources. That is a
// licence boundary, not a style preference: `iden3/circomlibjs` is GPL-3.0, so
// a value transcribed out of its test suite would be copyleft-licensed data
// sitting in an MIT repository, while a value obtained by executing it is this
// repository's own measurement of a black box (root NOTICE §0). The recipe
// therefore has to be re-runnable by anyone, which a comment is not — hence a
// file, in the module it serves (CONVENTIONS.md §9).
//
// WHAT IT NEEDS.
//
//     git clone --depth 1 https://github.com/iden3/circomlibjs.git
//     cd circomlibjs && bun install          # or `npm install`
//     bun <path-to-this-file> .              # or `node`, same output
//
// The argument is the circomlibjs checkout to run; it is imported from there
// and nothing is copied out of it. Put the clone somewhere disposable — in
// this repository, `.zig-cache/` — and delete it afterwards; it must never be
// added to this tree.
//
// WHAT IT PRODUCES. One line per known-answer value pinned in
// `src/vectors_test.zig`, keyed by the test that carries it, as 64-hex-digit
// big-endian field elements — the form `expectFr` takes. Every value is
// computed TWICE, by circomlibjs's reference implementation
// (`poseidon_reference.js`) and by its optimized one (`poseidon_opt.js`),
// and the two are required to agree; a disagreement throws rather than
// printing. That cross-check is the reason this is worth running at all: the
// two implementations store the MDS matrix differently and fold the partial
// rounds differently, so agreement between them is evidence about the
// PARAMETERS, not just about one code path.
//
// The call is `poseidon(inputs, initState, nOut)`, which is exactly this
// module's `Perm(inputs.length + 1).hashN(nOut, initState, inputs)`.

import { pathToFileURL } from "url";
import { resolve } from "path";

const root = process.argv[2];
if (!root) {
  console.error("usage: bun gen_vectors.mjs <path-to-circomlibjs-checkout>");
  process.exit(2);
}
const from = (rel) => pathToFileURL(resolve(root, rel)).href;

const buildRef = (await import(from("src/poseidon_reference.js"))).default;
const buildOpt = (await import(from("src/poseidon_opt.js"))).default;
const ref = await buildRef();
const opt = await buildOpt();
const F = ref.F;

const hex = (x) => F.toObject(x).toString(16).padStart(64, "0");

// Run both implementations and require them to agree. Returns `nOut` hex words.
function poseidon(inputs, initState, nOut) {
  const one = (p) => {
    const out = p(inputs, initState, nOut);
    return (Array.isArray(out) ? out : [out]).map(hex);
  };
  const r = one(ref);
  const o = one(opt);
  if (r.join(",") !== o.join(",")) {
    throw new Error(`poseidon_reference != poseidon_opt for ${JSON.stringify({ inputs: inputs.map(String), initState: String(initState), nOut })}`);
  }
  return r;
}

const upto = (n) => Array.from({ length: n }, (_, i) => i + 1);
const r_minus_1 = F.toObject(F.negone).toString(10);

const cases = [
  // ── "circomlibjs (executed): the all-zero permutation state (BN254, t=3)"
  ["zero-state t=3, nOut=3", [0, 0], 0, 3],

  // ── "circomlibjs Poseidon(2) and Poseidon(4)"
  ["Poseidon(2) of [1,2]", [1, 2], 0, 1],
  ["Poseidon(4) of [1,2,3,4]", upto(4), 0, 1],

  // ── "circomlibjs Poseidon with 16 inputs"
  ["Poseidon(16) of [1..16]", upto(16), 0, 1],
  ["Poseidon(16) of [1..9,0*7]", upto(16).map((v) => (v <= 9 ? v : 0)), 0, 1],

  // ── "circomlibjs Poseidon with a non-zero initial state"
  ["Poseidon(6) of [1..6], initState=0", upto(6), 0, 1],
  ["Poseidon(4) of [1..4], initState=7", upto(4), 7, 1],
  ["Poseidon(16) of [1..16], initState=17", upto(16), 17, 1],

  // ── "circomlibjs Poseidon with n outputs"
  ["Poseidon(1) of [1]", [1], 0, 1],
  ["Poseidon(2) of [1,2], nOut=2", [1, 2], 0, 2],
  ["Poseidon(5) of [1,2,0,0,0], nOut=3", [1, 2, 0, 0, 0], 0, 3],

  // ── "circomlibjs, inputs at the top of the field"
  ["Poseidon(2) of [r-1,r-1], nOut=3", [r_minus_1, r_minus_1], 0, 3],
];

for (const [label, inputs, initState, nOut] of cases) {
  for (const [i, word] of poseidon(inputs, initState, nOut).entries()) {
    console.log(`${label}${nOut > 1 ? `[${i}]` : ""} ${word}`);
  }
}

// ── "circomlibjs width sweep, t = 2..17" ──────────────────────────────────
//
// `Poseidon(n)` over `[1, 2, …, n]` for n = 1..16, i.e. t = 2..17: every entry
// of `N_ROUNDS_P` and every derived MDS matrix, so a width-indexing slip
// cannot hide behind the three widths the upstream suite happens to exercise.
for (let n = 1; n <= 16; n++) {
  console.log(`width sweep t=${n + 1} ${poseidon(upto(n), 0, 1)[0]}`);
}
