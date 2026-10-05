// SPDX-License-Identifier: MIT
//
// The ajv half of tools/schema_oracle.py: reads JSON lines `{"schema": ..., "doc": "<JSON text>"}`
// on stdin and prints one line per case: `1` valid, `0` invalid, `E` ajv refused the schema.
// Prints the ajv version first. ajv 8 (MIT), JSON Schema 2020-12 dialect, run as a black box:
//
//   bun modules/validate/tools/ajv_verdicts.js < cases.jsonl
//
// Needs ajv@8.20.0 in bun's cache (`bun add ajv@8.20.0` once, anywhere); bun auto-installs
// from the cache when no node_modules is in reach. No network.

const fs = require("fs");
const Ajv2020 = require("ajv/dist/2020");

// strict:false -- the exported schema carries annotations (`x-minBytes`, `x-custom`) that a
// 2020-12 validator must ignore, and strict mode would refuse them as unknown keywords.
const ajv = new Ajv2020({ strict: false, validateFormats: false });
const out = [require("ajv/package.json").version];
const cache = new Map();
for (const line of fs.readFileSync(0, "utf8").split("\n")) {
  if (line === "") continue;
  const c = JSON.parse(line);
  const key = JSON.stringify(c.schema);
  let v = cache.get(key);
  if (v === undefined) {
    try {
      v = ajv.compile(c.schema);
    } catch (e) {
      v = null;
    }
    cache.set(key, v);
  }
  out.push(v === null ? "E" : v(JSON.parse(c.doc)) ? "1" : "0");
}
process.stdout.write(out.join("\n") + "\n");
