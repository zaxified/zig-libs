// SPDX-License-Identifier: MIT
//
// Differential oracle for modules/json5: the reference JSON5 implementation
// (the `json5` package by the JSON5 project, 2.2.3, MIT), run as a black box
// under bun. The documents are OURS -- generated from the JSON5 grammar with a
// fixed seed, plus single-character mutations of them -- and the reference
// only answers: the value it parses each to, or that it refuses it.
//
//   bun modules/json5/tools/ref_oracle.js > modules/json5/src/ref_oracle_vectors.zig
//   bun modules/json5/tools/ref_oracle.js --check   # re-take, compare with the committed file
//
// Needs the package in bun's cache (`bun add json5@2.2.3` once, anywhere);
// JSON5_REF=<path to its lib/index.js> overrides the lookup. No network.
//
// A value is written in a canonical text both sides can produce exactly:
//   null z | true t | false f
//   number  n<16 hex digits: the IEEE-754 bits>   (NaN as 7ff8000000000000)
//   string  s<UTF-16 code units, 4 hex digits each>;
//   array   [v,v,...]
//   object  {k=v,...} members sorted by key code units, last duplicate wins
// Infinity, -Infinity and NaN are written as the STRINGS "Infinity",
// "-Infinity", "NaN": this module's `non_finite = .quoted` turns them into
// those strings, and the replay runs in that mode.

const fs = require("fs");
const path = require("path");
const os = require("os");

const refPath = process.env.JSON5_REF || path.join(os.homedir(), ".bun/install/cache/json5@2.2.3@@@1/lib/index.js");
const JSON5 = require(refPath);
// The reference warns on stderr about U+2028/9 in strings (valid JSON5, not ES5); silence it.
console.warn = () => {};
const refVersion = JSON.parse(fs.readFileSync(path.join(path.dirname(refPath), "..", "package.json"), "utf8")).version;

// ── deterministic PRNG (mulberry32) ──
let seed = 0x6a736f6e;
function rnd() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = (a) => a[Math.floor(rnd() * a.length)];
const chance = (p) => rnd() < p;
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));

// ── JSON5 generator ──
const WS = [" ", "\t", "\n", "\r\n", "\v", "\f", " ", "﻿", " ", " ", "　"];
function ws() {
  let s = "";
  while (chance(0.3)) {
    const r = rnd();
    if (r < 0.6) s += pick(WS);
    else if (r < 0.8) s += "// c" + pick(["", "x", "/* */"]) + pick(["\n", "\r\n", " "]);
    else s += "/* " + pick(["", "*", "//", "\n"]) + " */";
  }
  return s;
}

const NUMS = [
  "0", "-0", "+0", "1", "-1", "+1", "123", "1.5", ".5", "5.", "-.5", "+5.", "1e3", "1E-3", "1e+3", "-1.5e-10",
  "0x0", "0x1F", "0XAB", "-0x10", "+0xff", "0x7FFFFFFFFFFFF", "0xFFFFFFFFFFFFF", "1e400", "-1e400", "1e-400",
  "9007199254740993", "123456789012345678901234567890", "0.1", "2.5e-324", "Infinity", "-Infinity", "+Infinity",
  "NaN", "-NaN", "+NaN", "0.0", "00", "01", "1..2", "0x", "1e", ".e1", "0b1", "0o7", "1_000", "-", "+",
];

function num() {
  if (chance(0.7)) return pick(NUMS.slice(0, 39));
  return pick(NUMS);
}

const ESC = [
  "\\n", "\\t", "\\r", "\\b", "\\f", "\\v", "\\0", "\\'", '\\"', "\\\\", "\\/", "\\x41", "\\xe9", "\\u00e9",
  "\\u2028", "\\uD83D\\uDE00", "\\uD800", "\\uDC00", "\\\n", "\\\r\n", "\\ ", "\\q", "\\1", "\\x4", "\\u12",
];
const CH = ["a", "Z", "0", " ", "é", "\u{1F600}", " ", " ", "'", '"', "\t", "/", "*", "$", "\u0001"];

function str() {
  const q = pick(["'", '"']);
  let s = q;
  const n = int(0, 6);
  for (let i = 0; i < n; i++) {
    let c = chance(0.35) ? pick(ESC) : pick(CH);
    if (c === q) c = "\\" + q;
    s += c;
  }
  return s + q;
}

const IDENT_START = ["a", "Z", "_", "$", "é", "\\u0061", "\\u0024", "ab", "π"];
const IDENT_PART = ["", "1", "_x", "$", "‌", "‍", "̀", "\\u0062"];
function key() {
  const r = rnd();
  if (r < 0.5) return pick(IDENT_START) + pick(IDENT_PART);
  if (r < 0.9) return str();
  return pick(["true", "null", "Infinity", "NaN", "1a", "a-b", "a b", "__proto__", "constructor", "", "\\u0031"]);
}

function value(depth) {
  const r = rnd();
  if (depth > 3 || r < 0.45) {
    const s = rnd();
    if (s < 0.4) return num();
    if (s < 0.75) return str();
    return pick(["true", "false", "null"]);
  }
  if (r < 0.72) {
    const n = int(0, 4);
    const items = [];
    for (let i = 0; i < n; i++) items.push(ws() + value(depth + 1) + ws());
    return "[" + items.join(",") + (n > 0 && chance(0.4) ? "," + ws() : "") + "]";
  }
  const n = int(0, 4);
  const items = [];
  for (let i = 0; i < n; i++) items.push(ws() + key() + ws() + ":" + ws() + value(depth + 1) + ws());
  return "{" + items.join(",") + (n > 0 && chance(0.4) ? "," + ws() : "") + "}";
}

function doc() {
  return ws() + value(0) + ws();
}

function mutate(s) {
  const alphabet = [",", ":", "{", "}", "[", "]", "'", '"', "\\", "/", "*", "\n", " ", "x", "0", ".", "+", "-", "e"];
  const cps = Array.from(s);
  const i = int(0, cps.length);
  const op = int(0, 2);
  if (op === 0) cps.splice(i, 0, pick(alphabet));
  else if (op === 1 && i < cps.length) cps.splice(i, 1);
  else if (i < cps.length) cps[i] = pick(alphabet);
  else cps.push(pick(alphabet));
  return cps.join("");
}

// ── canonical form ──
function hex4(n) {
  return n.toString(16).padStart(4, "0");
}
function canonStr(s) {
  let out = "s";
  for (let i = 0; i < s.length; i++) out += hex4(s.charCodeAt(i));
  return out + ";";
}
function canon(v) {
  if (v === null) return "z";
  if (v === true) return "t";
  if (v === false) return "f";
  if (typeof v === "number") {
    if (Number.isNaN(v)) return canonStr("NaN");
    if (v === Infinity) return canonStr("Infinity");
    if (v === -Infinity) return canonStr("-Infinity");
    const dv = new DataView(new ArrayBuffer(8));
    dv.setFloat64(0, v);
    let h = "";
    for (let i = 0; i < 8; i++) h += dv.getUint8(i).toString(16).padStart(2, "0");
    return "n" + h;
  }
  if (typeof v === "string") return canonStr(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.getOwnPropertyNames(v).sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const d = a.charCodeAt(i) - b.charCodeAt(i);
      if (d !== 0) return d;
    }
    return a.length - b.length;
  });
  return "{" + keys.map((k) => canonStr(k) + "=" + canon(v[k])).join(",") + "}";
}

function zigStr(s) {
  const bytes = Buffer.from(s, "utf8");
  let out = '"';
  for (const b of bytes) {
    if (b === 0x22) out += '\\"';
    else if (b === 0x5c) out += "\\\\";
    else if (b === 0x0a) out += "\\n";
    else if (b === 0x0d) out += "\\r";
    else if (b === 0x09) out += "\\t";
    else if (b >= 0x20 && b < 0x7f) out += String.fromCharCode(b);
    else out += "\\x" + b.toString(16).padStart(2, "0");
  }
  return out + '"';
}

function generate() {
  const docs = [];
  const seen = new Set();
  const add = (d) => {
    if (!seen.has(d)) {
      seen.add(d);
      docs.push(d);
    }
  };
  // Every lone token too, so each grammar corner is asked on its own.
  for (const n of NUMS) add(n);
  for (const e of ESC) add("'" + e + "'");
  for (const k of [...IDENT_START, "true", "null", "a b", "1a", "\\u0031", "__proto__"]) add("{" + k + ": 1}");
  for (const w of WS) add("[1," + w + "2]");
  const base = [];
  for (let i = 0; i < 1600; i++) {
    const d = doc();
    base.push(d);
    add(d);
  }
  for (let i = 0; i < 1400; i++) add(mutate(pick(base)));

  let out = "";
  out += "// SPDX-License-Identifier: MIT\n";
  out += `// GENERATED by modules/json5/tools/ref_oracle.js (json5 ${refVersion}, bun ${Bun.version}) -- do not hand-edit.\n`;
  out += "//! The reference JSON5 implementation's verdicts on this module's own documents,\n";
  out += "//! replayed by `ref_oracle_test.zig`. Canonical value form: see the script's header.\n\n";
  out += `pub const ref_version = ${zigStr(refVersion)};\n\n`;
  out += "/// `ref`: the canonical form of the value the reference parsed `src` to, or null when it refused it.\n";
  out += "pub const Case = struct { src: []const u8, ref: ?[]const u8 };\n\n";
  out += "pub const cases = [_]Case{\n";
  for (const d of docs) {
    let ref = null;
    try {
      ref = canon(JSON5.parse(d));
    } catch (e) {
      ref = null;
    }
    out += `    .{ .src = ${zigStr(d)}, .ref = ${ref === null ? "null" : zigStr(ref)} },\n`;
  }
  out += "};\n";
  return out;
}

const text = generate();
if (process.argv.includes("--check")) {
  const committed = fs.readFileSync(path.join(__dirname, "..", "src", "ref_oracle_vectors.zig"), "utf8");
  if (committed !== text) {
    console.error("ref_oracle_vectors.zig is stale: the reference, bun or the generator moved -- regenerate and re-judge the divergences");
    process.exit(1);
  }
  console.log("ref_oracle_vectors.zig is fresh");
} else {
  process.stdout.write(text);
}
