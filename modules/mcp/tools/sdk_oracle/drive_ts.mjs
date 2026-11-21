// SPDX-License-Identifier: MIT
// Differential oracle for modules/mcp, second SDK: the official MCP TypeScript SDK
// (@modelcontextprotocol/sdk, MIT, run as a black box through its public client API;
// its source is not read) drives `server.zig` over stdio and checks every answer, as
// `drive.py` does for the Python SDK. Session era only: the SDK's stateless
// 2026-07-28 path is not in the release this was taken against. Writes no
// transcript (the replay vectors come from `drive.py`); the verdict is the exit code.
//
//   B=~/.local/share/zig-libs
//   # a Node release tarball unpacked to $B/oracle-bin/node (no root), then:
//   (mkdir -p $B/oracle-node/mcp && cd $B/oracle-node/mcp && npm init -y && npm install @modelcontextprotocol/sdk)
//   $B/oracle-bin/node/bin/node modules/mcp/tools/sdk_oracle/drive_ts.mjs <server binary>
//
// Run by hand (not wired into `zig build interop-mcp`). The server binary is the one
// drive.py builds (`.zig-cache/sdk-oracle/server`). Taken 2026-11-21 against SDK 1.32.2 on Node 22: 18 checks, 0 failed.
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = process.env.MCP_ORACLE_NODE_MODULES ?? path.join(os.homedir(), ".local/share/zig-libs/oracle-node/mcp");
const require = createRequire(path.join(root, "x.js"));
const { Client } = await import(require.resolve("@modelcontextprotocol/sdk/client/index.js"));
const { StdioClientTransport } = await import(require.resolve("@modelcontextprotocol/sdk/client/stdio.js"));
const sdkVersion = JSON.parse(fs.readFileSync(path.join(root, "node_modules/@modelcontextprotocol/sdk/package.json"), "utf8")).version;

const bin = process.argv[2];
if (!bin) {
  console.error("usage: drive_ts.mjs <server binary>");
  process.exit(2);
}

let failed = 0;
let total = 0;
function check(what, ok, detail = "") {
  total += 1;
  if (!ok) {
    failed += 1;
    console.error(`FAIL ${what}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
}
const textOf = (res) => (res.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("");
async function refused(what, codes, fn) {
  try {
    await fn();
    check(what, false, "no error");
  } catch (e) {
    check(what, codes.includes(e.code), { code: e.code, message: e.message });
  }
}

const client = new Client({ name: "ts-oracle", version: "0" }, { capabilities: {} });
await client.connect(new StdioClientTransport({ command: bin, args: [] }));
const info = client.getServerVersion();
check("initialize", info?.name === "oracle-srv" && client.getInstructions() === "SDK oracle", info);

const tools = await client.listTools();
check("tools/list", JSON.stringify(tools.tools.map((x) => x.name)) === JSON.stringify(["echo", "broken", "add", "greet"]), tools.tools.map((x) => x.name));
const add = tools.tools.find((x) => x.name === "add");
check("tools/list add", add?.outputSchema != null && add.annotations?.readOnlyHint === true && add.title === "Adder", add);

let res = await client.callTool({ name: "echo", arguments: { text: "hi č" } });
check("echo", textOf(res) === "hi č" && !res.isError, res);
res = await client.callTool({ name: "echo", arguments: {} });
check("echo missing arg", res.isError === true, res);
res = await client.callTool({ name: "broken", arguments: {} });
check("broken", res.isError === true && textOf(res).includes("always fails"), res);
res = await client.callTool({ name: "add", arguments: { a: 2, b: 40 } }); // the SDK validates structuredContent against outputSchema
check("add", JSON.stringify(res.structuredContent) === JSON.stringify({ sum: 42 }) && !res.isError, res);
await refused("unknown tool", [-32602, -32601], () => client.callTool({ name: "nope", arguments: {} }));
res = await client.callTool({ name: "greet", arguments: {} });
check("greet", textOf(res) === "session path: no multi round-trip", res);

const rl = await client.listResources();
check("resources/list", JSON.stringify(rl.resources.map((x) => x.uri)) === JSON.stringify(["oracle://readme"]), rl);
const rt = await client.listResourceTemplates();
check("resources/templates/list", JSON.stringify(rt.resourceTemplates.map((x) => x.uriTemplate)) === JSON.stringify(["oracle://items/{id}"]), rt);
let rr = await client.readResource({ uri: "oracle://readme" });
check("read readme", rr.contents[0].text === "read me\n" && rr.contents[0].mimeType === "text/plain", rr);
rr = await client.readResource({ uri: "oracle://items/7" });
check("read template", rr.contents[0].text === '{"item":true}', rr);
await refused("read missing", [-32002, -32602], () => client.readResource({ uri: "oracle://missing" }));

const pl = await client.listPrompts();
check("prompts/list", JSON.stringify(pl.prompts.map((p) => p.name)) === JSON.stringify(["review"]) && pl.prompts[0].arguments?.[0]?.name === "lang", pl);
const gp = await client.getPrompt({ name: "review", arguments: { lang: "rust" } });
check("prompts/get", JSON.stringify(gp.messages.map((m) => m.content.text)) === JSON.stringify(["Review this rust code.", "Paste it."]) &&
  JSON.stringify(gp.messages.map((m) => m.role)) === JSON.stringify(["user", "assistant"]), gp);
await refused("unknown prompt", [-32602, -32601], () => client.getPrompt({ name: "nope", arguments: {} }));
await client.ping();
check("ping", true);
await client.close();

console.error(`MCP TypeScript SDK ${sdkVersion}: ${total} checks, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
