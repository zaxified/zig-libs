// SPDX-License-Identifier: MIT
// TypeScript side of `zig build bench-mcp` (modules/mcp/tools/bench.zig): times the official MCP
// TypeScript SDK (the version is printed on stderr), used through its public API only
// (`McpServer` and `StdioServerTransport` over in-memory streams), over the session bytes the Zig
// program writes into the directory given as the first argument, for the one workload named by the
// second. Prints one line: name, ns/op, result count (tab-separated), like tools/py_bench.
//
// One op = one whole session (`initialize`, `notifications/initialized`, then 64 requests of one
// kind) read from an in-memory stream by the SDK's stdio transport, the responses collected in
// memory; the input ends only once every request is answered (the SDK abandons requests still in
// flight when its reader ends). Node startup and import time are outside the timed region. Timing
// matches the other sides: double the batch until it takes over 100 ms, then the best of three.
//
// Count = response lines + `"isError":true` occurrences. A session whose output holds a JSON-RPC
// error is refused.
//
//   B=~/.local/share/zig-libs   # as tools/sdk_oracle/drive_ts.mjs: Node tarball in $B/oracle-bin/node,
//                               # the SDK installed in $B/oracle-node/mcp
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough, Writable } from "node:stream";

const root = process.env.MCP_ORACLE_NODE_MODULES ?? path.join(os.homedir(), ".local/share/zig-libs/oracle-node/mcp");
const require = createRequire(path.join(root, "x.js"));
const { McpServer } = await import(require.resolve("@modelcontextprotocol/sdk/server/mcp.js"));
const { StdioServerTransport } = await import(require.resolve("@modelcontextprotocol/sdk/server/stdio.js"));
const { z } = await import(require.resolve("zod"));
const sdkVersion = JSON.parse(fs.readFileSync(path.join(root, "node_modules/@modelcontextprotocol/sdk/package.json"), "utf8")).version;

const NAMES = ["tools_call_echo", "tools_list_20", "resources_read", "prompts_get", "initialize_only"];

function serverFor(name) {
  const s = new McpServer({ name: "bench", version: "1.0.0" });
  if (name === "tools_call_echo") {
    s.registerTool("echo", { description: "Echo the text back", inputSchema: { text: z.string() }, outputSchema: { echo: z.string() } }, async ({ text }) => ({
      content: [{ type: "text", text: JSON.stringify({ echo: text }) }],
      structuredContent: { echo: text },
    }));
  } else if (name === "tools_list_20") {
    for (let i = 0; i < 20; i++) {
      const n = `tool_${String(i).padStart(2, "0")}`;
      s.registerTool(n, { description: `Small tool number ${i}`, inputSchema: { a: z.string(), b: z.number().int().optional() } }, async () => ({ content: [{ type: "text", text: "ok" }] }));
    }
  } else if (name === "resources_read") {
    const text = "0123456789abcdef".repeat(64);
    s.registerResource("doc", "file:///doc.txt", { mimeType: "text/plain" }, async (uri) => ({ contents: [{ uri: uri.href, mimeType: "text/plain", text }] }));
  } else if (name === "prompts_get") {
    s.registerPrompt("greet", { description: "Greet someone", argsSchema: { name: z.string() } }, async ({ name }) => ({ messages: [{ role: "user", content: { type: "text", text: `Hello, ${name}!` } }] }));
  } else if (name !== "initialize_only") {
    console.error(`unknown workload ${name}`);
    process.exit(2);
  }
  return s;
}

async function oneSession(wire) {
  const lines = wire.split("\n").filter((l) => l.length > 0);
  const want = lines.filter((l) => l.includes('"id"')).length;
  const stdin = new PassThrough();
  let out = "";
  let answered = 0;
  let done;
  const finished = new Promise((r) => (done = r));
  const stdout = new Writable({
    write(chunk, _enc, cb) {
      const t = chunk.toString("utf8");
      out += t;
      for (const ch of t) if (ch === "\n") answered++;
      if (answered >= want) done();
      cb();
    },
  });
  const server = serverFor(currentName);
  const transport = new StdioServerTransport(stdin, stdout);
  await server.connect(transport);
  for (const l of lines) stdin.write(l + "\n");
  if (want > 0) await finished;
  await server.close();
  if (out.includes('"error":{')) {
    console.error("mcp (typescript) answered a JSON-RPC error: " + out.slice(0, 300));
    process.exit(1);
  }
  return out.split("\n").filter((l) => l.length > 0).length + (out.match(/"isError":\s*true/g) ?? []).length;
}

async function timeIt(f) {
  let n = 1;
  for (;;) {
    const t = process.hrtime.bigint();
    for (let i = 0; i < n; i++) await f();
    if (Number(process.hrtime.bigint() - t) / 1e9 > 0.1) break;
    n *= 2;
  }
  let best = Infinity;
  let count = 0;
  for (let r = 0; r < 3; r++) {
    const t = process.hrtime.bigint();
    for (let i = 0; i < n; i++) count = await f();
    best = Math.min(best, Number(process.hrtime.bigint() - t));
  }
  return [best / n, count];
}

if (process.argv.length !== 4) {
  console.error("usage: main.mjs <work dir> <workload>");
  process.exit(2);
}
const [dir, currentName] = process.argv.slice(2);
if (!NAMES.includes(currentName)) {
  console.error(`unknown workload ${currentName}`);
  process.exit(2);
}
const wire = fs.readFileSync(path.join(dir, currentName + ".wire"), "utf8");
console.error(`modelcontextprotocol typescript-sdk (@modelcontextprotocol/sdk) ${sdkVersion}`);
const [ns, count] = await timeIt(() => oneSession(wire));
console.log(`${currentName}\t${Math.round(ns)}\t${count}`);
process.exit(0);
