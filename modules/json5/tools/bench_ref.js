// SPDX-License-Identifier: MIT
//
// The reference side of `zig build bench-json5` (modules/json5/tools/bench.zig):
// the `json5` package 2.2.3 (json5/json5) run under bun.
//
//   bun bench_ref.js <work dir> <workload>
//
// Prints `name \t ns/op \t count` on stdout, the banner on stderr. Same timing
// method as the Zig side: double the batch until it takes over 100 ms, then the
// best of five batches, per op. The text is read from the work dir (the files
// the Zig side wrote) and parsed with `JSON5.parse`; `count` is the number of
// object members + array elements in the parsed tree (summed over the 1000
// parses of `small_config`), which the Zig side must reproduce exactly.
//
// The package is found like ref_oracle.js finds it: bun's install cache
// (`bun add json5@2.2.3` once, anywhere); JSON5_REF=<path to lib/index.js>
// overrides. No network.

const fs = require("fs");
const path = require("path");
const os = require("os");

const refPath = process.env.JSON5_REF || path.join(os.homedir(), ".bun/install/cache/json5@2.2.3@@@1/lib/index.js");
const JSON5 = require(refPath);
console.warn = () => {};
const refVersion = JSON.parse(fs.readFileSync(path.join(path.dirname(refPath), "..", "package.json"), "utf8")).version;

const FILES = { small_config: "small_config.json5", large_json: "large_json.json", large_json5: "large_json5.json5" };
const REPS = { small_config: 1000, large_json: 1, large_json5: 1 };

const [dir, name] = process.argv.slice(2);
if (!dir || !FILES[name]) {
  console.error("usage: bun bench_ref.js <work dir> <" + Object.keys(FILES).join("|") + ">");
  process.exit(2);
}
const text = fs.readFileSync(path.join(dir, FILES[name]), "utf8");
const reps = REPS[name];

function count(v) {
  let n = 0;
  if (Array.isArray(v)) {
    n += v.length;
    for (let i = 0; i < v.length; i++) n += count(v[i]);
  } else if (v !== null && typeof v === "object") {
    const keys = Object.keys(v);
    n += keys.length;
    for (let i = 0; i < keys.length; i++) n += count(v[keys[i]]);
  }
  return n;
}

let sink = 0;
function once() {
  let sum = 0;
  for (let i = 0; i < reps; i++) sum += count(JSON5.parse(text));
  return sum;
}

const now = () => Number(process.hrtime.bigint());
let n = 1;
for (;;) {
  const t = now();
  for (let i = 0; i < n; i++) sink += once();
  if (now() - t > 100_000_000) break;
  n *= 2;
}
let best = Infinity;
let result = 0;
for (let r = 0; r < 5; r++) {
  const t = now();
  for (let i = 0; i < n; i++) result = once();
  best = Math.min(best, now() - t);
}
if (sink < 0) console.error(sink); // keep the loop observable
console.error(`json5 ${refVersion}, bun ${Bun.version}`);
process.stdout.write(`${name}\t${best / n}\t${result}\n`);
