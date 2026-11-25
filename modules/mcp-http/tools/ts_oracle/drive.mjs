// SPDX-License-Identifier: MIT
// Second differential oracle for mcp-http: the official MCP TypeScript SDK's
// client (@modelcontextprotocol/client 2.4.0, black box through its public API)
// over a real socket against `tools/interop.zig --ts`, which serves
// `tools/sdk_oracle/catalog.zig` at /mcp (sessions, held GET stream, held
// listens) and the same server behind the bearer gate at /mcp-auth.
//   session era  initialize, tools/list, tools/call (text, structured, live
//                progress over SSE), resources/read, prompts/get, a pushed
//                tools/list_changed on the held GET stream, DELETE
//   2026-07-28   versionNegotiation pinned: tools/list, tools/call, a held
//                subscriptions/listen receiving a pushed tools/list_changed
//   auth         a POST without a token: 401 whose WWW-Authenticate the SDK's
//                own parser (`extractWWWAuthenticateParams`) reads; the RFC 9728
//                document through `discoverOAuthProtectedResourceMetadata` (the
//                SDK's schema); a client with the token is served; a wrong token
//                is refused at connect.
// The verdict is the exit code.
//
//   B=~/.local/share/zig-libs
//   (mkdir -p $B/oracle-node/mcp-skills && cd $B/oracle-node/mcp-skills && npm init -y \
//      && npm install --ignore-scripts @modelcontextprotocol/client@2.4.0)
//   hw run -- unshare -rn zig build interop-mcp-http -- --ts      # from the repository root
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = process.env.MCP_SKILLS_NODE_MODULES ?? path.join(os.homedir(), ".local/share/zig-libs/oracle-node/mcp-skills");
const require = createRequire(path.join(root, "x.js"));
const sdk = await import(require.resolve("@modelcontextprotocol/client"));
const { Client, StreamableHTTPClientTransport, extractWWWAuthenticateParams, discoverOAuthProtectedResourceMetadata } = sdk;
const sdkVersion = JSON.parse(fs.readFileSync(path.join(root, "node_modules/@modelcontextprotocol/client/package.json"), "utf8")).version;

const port = process.argv[2];
if (!port) {
  console.error("usage: drive.mjs PORT");
  process.exit(2);
}
const base = `http://127.0.0.1:${port}`;

let failed = 0;
let total = 0;
function check(what, ok, detail = "") {
  total += 1;
  if (!ok) {
    failed += 1;
    console.error(`FAIL ${what}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
  }
}
const text = (r) => (r?.content ?? []).filter((c) => c.type === "text").map((c) => c.text).join("");
const waitFor = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);

async function sessionEra() {
  const client = new Client({ name: "ts-oracle", version: "0" });
  let changed;
  const gotChange = new Promise((res) => (changed = res));
  client.setNotificationHandler("notifications/tools/list_changed", () => changed(true));
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`));
  await client.connect(transport);
  check("session: serverInfo", client.getServerVersion()?.name === "oracle-http", client.getServerVersion());
  check("session: id minted", typeof transport.sessionId === "string" && transport.sessionId.length > 0, transport.sessionId);
  const tools = await client.listTools();
  check("session: tools/list", tools.tools.some((t) => t.name === "echo") && tools.tools.some((t) => t.name === "add"), tools.tools.map((t) => t.name));
  const e = await client.callTool({ name: "echo", arguments: { text: "hi č" } });
  check("session: echo", text(e) === "hi č" && !e.isError, e);
  const add = await client.callTool({ name: "add", arguments: { a: 2, b: 40 } });
  check("session: structured", add.structuredContent?.sum === 42, add);
  const progress = [];
  const w = await client.callTool({ name: "work", arguments: {} }, { onprogress: (p) => progress.push(p) });
  check("session: live progress", text(w) === "worked" && progress.length === 2 && progress[1].progress === 2 && progress[1].message === "done", { w, progress });
  const rd = await client.readResource({ uri: "oracle://readme" });
  check("session: resources/read", rd.contents?.[0]?.text === "read me\n", rd);
  const pr = await client.getPrompt({ name: "review", arguments: { lang: "zig" } });
  check("session: prompts/get", pr.messages?.length === 2 && pr.messages[0].content.text === "Review this zig code.", pr);
  // The held GET stream: a change pushed from inside a tool reaches the client.
  // The server's queue holds less than one event (interop.zig --ts), so each
  // push ends the stream; the client resumes it with Last-Event-ID and the
  // server replays what it missed: every one of the pushes must arrive.
  await new Promise((r) => setTimeout(r, 200)); // let the client open its GET stream
  await client.callTool({ name: "touch", arguments: {} });
  const seen = await waitFor(gotChange, 5000).catch(() => false);
  check("session: list_changed on the GET stream", seen === true);
  let count = 0;
  let all;
  const gotAll = new Promise((res) => (all = res));
  client.setNotificationHandler("notifications/tools/list_changed", () => {
    count += 1;
    if (count >= 5) all(true);
  });
  for (let i = 0; i < 5; i++) await client.callTool({ name: "touch", arguments: {} });
  const resumed = await waitFor(gotAll, 15000).catch(() => false);
  check("session: pushes across stream ends arrive through Last-Event-ID replay", resumed === true, count);
  await transport.terminateSession();
  check("session: DELETE ended it", transport.sessionId === undefined, transport.sessionId);
  await client.close();
}

async function modernEra() {
  const client = new Client({ name: "ts-oracle", version: "0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`));
  await client.connect(transport);
  check("modern: no session", transport.sessionId === undefined, transport.sessionId);
  const tools = await client.listTools();
  check("modern: tools/list", tools.tools.some((t) => t.name === "echo"), tools.tools.map((t) => t.name));
  const e = await client.callTool({ name: "echo", arguments: { text: "hi" } });
  check("modern: echo", text(e) === "hi", e);
  const add = await client.callTool({ name: "add", arguments: { a: 1, b: 2 } });
  check("modern: structured", add.structuredContent?.sum === 3, add);
  await client.close();
}

async function auth() {
  // No token: 401, and the SDK's own parser reads our challenge.
  const res = await fetch(`${base}/mcp-auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  check("auth: 401 without a token", res.status === 401, res.status);
  const params = extractWWWAuthenticateParams(res);
  check("auth: challenge resource_metadata", params.resourceMetadataUrl?.pathname === "/.well-known/oauth-protected-resource/mcp-auth", params);
  check("auth: challenge scope", params.scope === "mcp:tools", params);
  check("auth: no error code without a token", params.error === undefined, params);
  // The RFC 9728 document through the SDK's discovery (and its schema).
  const md = await discoverOAuthProtectedResourceMetadata(`${base}/mcp-auth`, { resourceMetadataUrl: `${base}/.well-known/oauth-protected-resource/mcp-auth` });
  check("auth: metadata document", md?.resource === "http://127.0.0.1/mcp-auth" && md.authorization_servers?.[0] === "https://auth.oracle.example" && md.scopes_supported?.[0] === "mcp:tools", md);
  // A wrong token: refused with invalid_token.
  const bad = await fetch(`${base}/mcp-auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer wrong", "MCP-Protocol-Version": "2025-11-25" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  check("auth: wrong token 401 invalid_token", bad.status === 401 && extractWWWAuthenticateParams(bad).error === "invalid_token", bad.status);
  const refused = new Client({ name: "ts-oracle", version: "0" });
  let threw = false;
  try {
    await refused.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp-auth`), { requestInit: { headers: { Authorization: "Bearer wrong" } } }));
  } catch {
    threw = true;
  }
  check("auth: client with a wrong token refused at connect", threw);
  // The right token: the SDK client is served through the gate.
  const client = new Client({ name: "ts-oracle", version: "0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp-auth`), { requestInit: { headers: { Authorization: "Bearer oracle-token" } } }));
  const e = await client.callTool({ name: "echo", arguments: { text: "authorized" } });
  check("auth: served with the token", text(e) === "authorized", e);
  await client.close();
}

for (const [name, f] of [["session", sessionEra], ["modern", modernEra], ["auth", auth]]) {
  try {
    await f();
  } catch (e) {
    check(`${name}: no exception`, false, e?.stack ?? String(e));
  }
}
console.error(`ts oracle (@modelcontextprotocol/client ${sdkVersion}): ${total} checks, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
