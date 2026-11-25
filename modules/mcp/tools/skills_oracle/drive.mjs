// SPDX-License-Identifier: MIT
// Differential oracle for mcp's Skills extension (src/skills.zig): the official
// MCP TypeScript SDK's host side, `SkillsClient` from @modelcontextprotocol/client
// 2.4.0 (Apache-2.0/MIT, run as a black box through its public API), drives
// `server.zig` over stdio once per protocol era (the default `initialize` session,
// and `versionNegotiation` pinned to 2026-07-28) and must accept every answer:
// `list()` walks the pages and throws on any entry it finds invalid, `read()`
// checks every file's size and sha256 digest against the entry and the
// SKILL.md frontmatter field by field, `readDirectory()` walks directory pages.
// The verdict is the exit code; nothing is written.
//
//   B=~/.local/share/zig-libs
//   # Node at $B/oracle-bin/node (a release tarball, no root), then, fetched without running scripts:
//   (mkdir -p $B/oracle-node/mcp-skills && cd $B/oracle-node/mcp-skills && npm init -y \
//      && npm install --ignore-scripts @modelcontextprotocol/client@2.4.0)
//   # from the repository root (builds the server into .zig-cache/skills-oracle/):
//   hw run -- unshare -rn $B/oracle-bin/node/bin/node modules/mcp/tools/skills_oracle/drive.mjs
//
// Run by hand (not wired into `zig build interop-mcp`).
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = process.env.MCP_SKILLS_NODE_MODULES ?? path.join(os.homedir(), ".local/share/zig-libs/oracle-node/mcp-skills");
const require = createRequire(path.join(root, "x.js"));
const { Client } = await import(require.resolve("@modelcontextprotocol/client"));
const { StdioClientTransport } = await import(require.resolve("@modelcontextprotocol/client/stdio"));
const { SkillsClient } = await import(require.resolve("@modelcontextprotocol/client/ext/skills"));
const sdkVersion = JSON.parse(fs.readFileSync(path.join(root, "node_modules/@modelcontextprotocol/client/package.json"), "utf8")).version;

const work = path.join(".zig-cache", "skills-oracle");
const bin = path.join(work, "server");
fs.mkdirSync(work, { recursive: true });
// The module list mirrors mcp's row in build.zig (deps: jsontext, yaml); keep them in step.
execFileSync("zig", ["build-exe", "-OReleaseSafe", "-fllvm", "--dep", "mcp",
  "-Mroot=modules/mcp/tools/skills_oracle/server.zig",
  "--dep", "jsontext", "--dep", "yaml", "-Mmcp=modules/mcp/src/root.zig",
  "-Mjsontext=modules/jsontext/src/root.zig",
  "-Myaml=modules/yaml/src/root.zig",
  `-femit-bin=${bin}`], { stdio: "inherit" });

let failed = 0;
let total = 0;
function check(what, ok, detail = "") {
  total += 1;
  if (!ok) {
    failed += 1;
    console.error(`FAIL ${what}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
}
async function expectReject(what, p, code) {
  try {
    await p;
    check(what, false, "resolved");
  } catch (e) {
    check(what, code === undefined || e?.code === code, `${e?.code} ${e?.message}`);
  }
}

const want = {
  "skill://acme/billing/refunds/SKILL.md": 4,
  "skill://outer/SKILL.md": 3,
  "skill://outer/inner/SKILL.md": 2,
  "skill://pdf-processing/SKILL.md": 3,
  "skill://reports/daily/SKILL.md": "dynamic",
};

async function runEra(era) {
  const client = new Client({ name: "skills-oracle-driver", version: "0" },
    era === "modern" ? { versionNegotiation: { mode: { pin: "2026-07-28" } } } : {});
  await client.connect(new StdioClientTransport({ command: bin, stderr: "inherit" }));
  const sc = new SkillsClient(client);
  check(`${era} supported`, sc.supported);
  check(`${era} directoryRead`, sc.directoryRead);

  // list(): every page walked; throws on an entry it finds invalid.
  const listing = await sc.list();
  const uris = listing.skills.map((s) => s.uri).sort();
  check(`${era} list uris`, JSON.stringify(uris) === JSON.stringify(Object.keys(want).sort()), uris);
  check(`${era} list no invalid`, listing.invalid.length === 0, listing.invalid);
  if (era === "modern") check(`${era} list caching`, listing.ttlMs === undefined || typeof listing.ttlMs === "number", listing);

  for (const s of listing.skills) {
    const n = want[s.uri];
    if (n === "dynamic") {
      check(`${era} ${s.uri} dynamic`, s.resources === "dynamic", s.resources);
      const md = await sc.read(s);
      check(`${era} ${s.uri} SKILL.md read`, md.verified === false && md.frontmatter?.name === "daily", md);
      const gen = await sc.read(s, "today.md");
      check(`${era} ${s.uri} generated file`, gen.text?.startsWith("# Today"), gen);
      continue;
    }
    check(`${era} ${s.uri} manifest size`, Array.isArray(s.resources) && s.resources.length === n, s.resources);
    // Every listed file reads back verified (size + sha256 + SKILL.md frontmatter).
    for (const r of s.resources) {
      const f = await sc.read(s, r.uri);
      check(`${era} read ${r.uri}`, f.verified === true && f.bytes.length === r.size, { verified: f.verified, len: f.bytes.length, size: r.size });
    }
    const md = await sc.read(s);
    check(`${era} ${s.uri} frontmatter`, md.frontmatter?.name === s.frontmatter.name && typeof md.body === "string", md.frontmatter);
    // get() returns the same entry.
    const got = await sc.get(s.uri);
    check(`${era} get ${s.uri}`, JSON.stringify(got.skill) === JSON.stringify(s), got.skill);
    if (era === "modern") check(`${era} get caching ${s.uri}`, got.ttlMs === 60000 && got.cacheScope === "public", got);
  }

  const refunds = listing.skills.find((s) => s.uri === "skill://acme/billing/refunds/SKILL.md");
  check(`${era} refunds frontmatter passthrough`,
    refunds?.frontmatter.license === "Apache-2.0" && refunds?.frontmatter.metadata?.version === "1.0" && refunds?.frontmatter["allowed-tools"] === "Read",
    refunds?.frontmatter);
  const binFile = await sc.read(refunds, "assets/logo.bin");
  check(`${era} binary bytes`, binFile.bytes.length === 18 && binFile.bytes[0] === 0x89 && binFile.text === undefined, binFile);
  const spaced = await sc.read(refunds, "notes with space.md");
  check(`${era} percent-encoded name`, spaced.text === "čeština ✓\n", spaced);

  // Directories, paged (page_size 2), and a skill root's SKILL.md named by the skill.
  const dir = await sc.readDirectory("skill://acme/billing/refunds");
  const names = dir.resources.map((r) => r.name).sort();
  check(`${era} directory children`, JSON.stringify(names) === JSON.stringify(["assets", "examples", "notes with space.md", "refunds"]), names);
  if (era === "modern") check(`${era} directory caching`, dir.ttlMs === 300000 && dir.cacheScope === "public", dir);
  const top = await sc.readDirectory("skill://acme");
  check(`${era} prefix directory`, top.resources.length === 1 && top.resources[0].mimeType === "inode/directory", top.resources);

  // Errors.
  await expectReject(`${era} get unknown`, sc.get("skill://acme/billing/chargebacks/SKILL.md"), -32602);
  await expectReject(`${era} get broken`, sc.get("skill://broken/SKILL.md"), -32602);
  await expectReject(`${era} directory of a file`, sc.readDirectory("skill://pdf-processing/SKILL.md"), -32602);
  await expectReject(`${era} read unlisted`, sc.read(refunds, "nope.md"));

  await client.close();
}

// Teeth: the same client must refuse a file whose bytes differ from the manifest.
async function teeth() {
  const client = new Client({ name: "skills-oracle-driver", version: "0" });
  await client.connect(new StdioClientTransport({ command: bin, stderr: "inherit", env: { SKILLS_ORACLE_TEETH: "1" } }));
  const sc = new SkillsClient(client);
  const { skill } = await sc.get("skill://pdf-processing/SKILL.md");
  try {
    await sc.read(skill, "templates/invoice.md");
    check("teeth: tampered file refused", false, "accepted");
  } catch (e) {
    check("teeth: tampered file refused", e?.name === "SkillVerificationError" || e?.reason !== undefined, `${e?.name} ${e?.reason} ${e?.message}`);
  }
  await client.close();
}

await teeth();
await runEra("session");
await runEra("modern");
console.error(`skills oracle (@modelcontextprotocol/client ${sdkVersion}): ${total} checks, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
