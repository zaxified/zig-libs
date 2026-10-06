// SPDX-License-Identifier: MIT
//
// The cors browser oracle: headless Google Chrome, driven over the DevTools
// protocol, runs fetch() from pages on two origins against this module's
// middleware (tools/interop.zig `serve`, one configuration per port), and
// what the script got -- the response or a network error, and which of two
// response headers it could read -- is compared with what the configured
// policy says (`want`, the Fetch Standard's CORS checks applied to the
// configuration, below). The requests Chrome sent and the heads the module
// answered are frozen, so the replay (src/browser_oracle_test.zig) needs
// neither Chrome nor bun.
//
//   zig build interop-cors               # writes src/browser_oracle_vectors.zig
//   zig build interop-cors -- --check    # re-take, compare with the committed file
//
// Started by tools/interop.zig with `--server <its own path>`. Fixed ports
// (pages 18601-18602, configurations 18700+) keep the frozen requests the
// same from run to run; a port in use is a failure.

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const server = args[args.indexOf("--server") + 1];
const check = args.includes("--check");
const ROOT = path.resolve(__dirname, "..", "..", "..");
const SCRATCH = path.join(ROOT, ".zig-cache", "interop-cors");
const OUT = path.join(ROOT, "modules", "cors", "src", "browser_oracle_vectors.zig");
const PAGE_PORTS = [18601, 18602];
const ORIGINS = PAGE_PORTS.map((p) => `http://127.0.0.1:${p}`);
const BASE = 18700;
const DEVTOOLS = 18690;
const [O0, O1] = ORIGINS;

// ── configurations (cors.Options) ────────────────────────────────────────────
const CONFIGS = [
  { origins: [O0], methods: ["GET", "HEAD", "POST"], headers: "reflect" },
  { origins: [O0], methods: ["GET", "PUT", "DELETE", "PATCH"], headers: "reflect" },
  { origins: [O0], methods: ["GET", "POST", "PUT"], headers: ["X-A", "Content-Type"] },
  { origins: [O0], methods: ["GET", "PUT"], headers: ["x-a"], credentials: true, expose: ["X-Total"] },
  { origins: "any", methods: ["GET", "POST", "PUT", "PATCH"], headers: "reflect", expose: ["X-Total", "X-Secret"] },
  { origins: "any", methods: ["GET", "PUT"], headers: ["X-A"], unconditional: true },
  { origins: "none", methods: ["GET", "HEAD", "POST"], headers: "reflect" },
  { origins: [O0, O1], methods: ["PUT"], headers: "reflect" },
  { origins: [O0], methods: ["GET", "POST"], headers: "reflect", expose: ["*"] },
  { origins: "any", methods: ["GET"], headers: "reflect", expose: ["*"] },
  { origins: [O0], methods: ["GET"], headers: "reflect", credentials: true, expose: ["*"] },
  { origins: [O0], methods: ["GET", "PATCH"], headers: ["Authorization"], credentials: true },
  { origins: [O0], methods: ["GET", "PUT"], headers: "reflect", credentials: true, max_age: 600 },
  { origins: [O0 + "/"], methods: ["GET", "HEAD", "POST"], headers: "reflect" },
  { origins: [O0.replace("http", "HTTP")], methods: ["GET", "HEAD", "POST"], headers: "reflect" },
  { origins: [O0], methods: ["GET", "PUT"], headers: [" X-A ", "X-B"], expose: ["x-total"] },
];

// The static posture's two configurations (cors.StaticOptions), served after
// CONFIGS; tools/interop.zig and src/browser_oracle_test.zig hold the same.
const STATICS = [
  { allow_origin: "*", allow_methods: "GET, HEAD", allow_headers: null, expose: null },
  { allow_origin: O0, allow_methods: "GET, PUT", allow_headers: "X-A", expose: "X-Total" },
];

// ── requests (what the page's script asks fetch() for) ───────────────────────
const REQUESTS = [
  { name: "GET", method: "GET" },
  { name: "POST text/plain", method: "POST", headers: { "Content-Type": "text/plain" }, body: "x" },
  { name: "GET credentials", method: "GET", credentials: "include" },
  { name: "PUT", method: "PUT" },
  { name: "DELETE", method: "DELETE" },
  { name: "patch", method: "patch" },
  { name: "PATCH", method: "PATCH" },
  { name: "GET X-A", method: "GET", headers: { "X-A": "1" } },
  { name: "GET X-A X-B", method: "GET", headers: { "X-A": "1", "X-B": "2" } },
  { name: "POST json", method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
  { name: "GET Authorization", method: "GET", headers: { Authorization: "Bearer t" } },
  { name: "PUT credentials X-A", method: "PUT", credentials: "include", headers: { "X-A": "1" } },
  { name: "HEAD", method: "HEAD" },
  { name: "PATCH credentials Authorization", method: "PATCH", credentials: "include", headers: { Authorization: "Bearer t" } },
];

// ── the policy, as the Fetch Standard's CORS checks read the configuration ──
const SAFE_METHODS = ["GET", "HEAD", "POST"];
const SAFE_CT = ["application/x-www-form-urlencoded", "multipart/form-data", "text/plain"];
// fetch() upper-cases exactly these method names (Fetch, "normalize a method").
const NORMALIZED = ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"];

function normMethod(m) {
  return NORMALIZED.includes(m.toUpperCase()) ? m.toUpperCase() : m;
}

function unsafeHeaders(req) {
  const out = [];
  for (const [k, v] of Object.entries(req.headers || {})) {
    const n = k.toLowerCase();
    if (["accept", "accept-language", "content-language"].includes(n)) continue;
    if (n === "content-type" && SAFE_CT.includes(v.toLowerCase())) continue;
    out.push(n);
  }
  return out.sort();
}

function wantStatic(so, origin, req) {
  const m = normMethod(req.method);
  const creds = req.credentials === "include";
  const unsafe = unsafeHeaders(req);
  const preflight = !SAFE_METHODS.includes(m) || unsafe.length > 0;
  const split = (v) => (v == null ? [] : v.split(",").map((x) => x.trim().toLowerCase()).filter((x) => x));
  // A constant grant: no gate of its own, so only the browser's checks apply. It never
  // sends Access-Control-Allow-Credentials, so a credentialed fetch always fails.
  let ok = (so.allow_origin === "*" || so.allow_origin === origin) && !creds;
  if (preflight) {
    const methods = so.allow_methods.split(",").map((x) => x.trim());
    const headers = split(so.allow_headers);
    ok = ok && (methods.includes(m) || SAFE_METHODS.includes(m)) && (so.allow_headers == null || unsafe.every((n) => headers.includes(n)));
  }
  const expose = split(so.expose);
  return { ok, total: ok && expose.includes("x-total"), secret: ok && expose.includes("x-secret") };
}

function want(cfg, origin, req) {
  const m = normMethod(req.method);
  const creds = req.credentials === "include";
  const any = cfg.origins === "any";
  const originOk = any || (Array.isArray(cfg.origins) && cfg.origins.includes(origin));
  // A method is the token configured, byte for byte (RFC 9110: case-sensitive).
  const methodOk = cfg.methods.includes(m);
  const unsafe = unsafeHeaders(req);
  const preflight = !SAFE_METHODS.includes(m) || unsafe.length > 0;
  const listed = (n) => cfg.headers === "reflect" || cfg.headers.some((h) => h.trim().toLowerCase() === n);
  const headersOk = unsafe.every(listed);
  let ok = originOk && (!creds || (!!cfg.credentials && !any));
  if (preflight) ok = ok && methodOk && headersOk;
  if (!cfg.unconditional) ok = ok && methodOk; // the module's actual-request method gate
  const expose = (cfg.expose || []).map((h) => h.trim().toLowerCase());
  const readable = (n) => ok && (expose.includes(n) || (expose.includes("*") && !creds));
  return { ok, total: readable("x-total"), secret: readable("x-secret") };
}

// ── Chrome over the DevTools protocol ────────────────────────────────────────
async function waitJson(url, tries = 100) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return await r.json();
    } catch (_) {}
    await Bun.sleep(100);
  }
  throw new Error("no answer from " + url);
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    }
  };
  const ready = new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const msg = { id: ++id, method, params };
      if (sessionId) msg.sessionId = sessionId;
      pending.set(msg.id, { resolve, reject });
      ws.send(JSON.stringify(msg));
    });
  return { ready, send, close: () => ws.close() };
}

function zstr(s) {
  let out = '"';
  for (const b of Buffer.from(s, "utf8")) {
    const c = String.fromCharCode(b);
    if (c === '"') out += '\\"';
    else if (c === "\\") out += "\\\\";
    else if (c === "\n") out += "\\n";
    else if (c === "\r") out += "\\r";
    else if (b >= 0x20 && b < 0x7f) out += c;
    else out += "\\x" + b.toString(16).padStart(2, "0");
  }
  return out + '"';
}

// Request headers that carry the browser's identity or version, not CORS: left
// out of the frozen request so a Chrome update does not change the vectors.
const NOISE = /^(host|connection|user-agent|accept|accept-encoding|accept-language|referer|sec-.*|cache-control|pragma|content-length|priority)$/i;

async function main() {
  fs.mkdirSync(SCRATCH, { recursive: true });
  const cfgPath = path.join(SCRATCH, "configs.json");
  const logPath = path.join(SCRATCH, "log.jsonl");
  fs.writeFileSync(cfgPath, JSON.stringify(CONFIGS));

  const pages = PAGE_PORTS.map((port) =>
    Bun.serve({ port, hostname: "127.0.0.1", fetch: () => new Response("<!doctype html><title>page</title>", { headers: { "content-type": "text/html" } }) }),
  );
  const srv = Bun.spawn([server, "serve", cfgPath, logPath, String(BASE)], { stdin: "pipe", stdout: "pipe", stderr: "inherit" });
  const reader = srv.stdout.getReader();
  let first = "";
  while (!first.includes("\n")) {
    const { value, done } = await reader.read();
    if (done) throw new Error("server exited before printing its ports");
    first += new TextDecoder().decode(value);
  }
  const ports = JSON.parse(first.split("\n")[0]).ports;

  const profile = path.join(SCRATCH, "chrome-profile");
  const chrome = Bun.spawn(
    ["google-chrome", "--headless=new", `--remote-debugging-port=${DEVTOOLS}`, `--user-data-dir=${profile}`, "--no-first-run", "--password-store=basic", "--use-mock-keychain", "--no-default-browser-check", "--disable-gpu", "--disable-extensions", "about:blank"],
    { stdout: "ignore", stderr: "ignore" },
  );
  let chromeVersion = "";
  const results = [];
  try {
    const version = await waitJson(`http://127.0.0.1:${DEVTOOLS}/json/version`);
    chromeVersion = version.Browser;
    const c = cdp(version.webSocketDebuggerUrl);
    await c.ready;
    const sessions = [];
    for (const origin of ORIGINS) {
      const { targetId } = await c.send("Target.createTarget", { url: origin + "/" });
      const { sessionId } = await c.send("Target.attachToTarget", { targetId, flatten: true });
      await c.send("Runtime.enable", {}, sessionId);
      // Wait for the page to be at its origin.
      let at = false;
      for (let i = 0; i < 100 && !at; i++) {
        const r = await c.send("Runtime.evaluate", { expression: "location.origin + ' ' + document.readyState", returnByValue: true }, sessionId);
        at = r.result.value === origin + " complete";
        if (!at) await Bun.sleep(100);
      }
      if (!at) throw new Error("page never settled at " + origin);
      sessions.push(sessionId);
    }
    for (let k = 0; k < CONFIGS.length + STATICS.length; k++) {
      for (let o = 0; o < ORIGINS.length; o++) {
        for (let r = 0; r < REQUESTS.length; r++) {
          const req = REQUESTS[r];
          const target = `/k${k}/o${o}/r${r}`;
          const url = `http://127.0.0.1:${ports[k]}${target}`;
          const init = { method: req.method, mode: "cors", credentials: req.credentials || "same-origin", cache: "no-store" };
          if (req.headers) init.headers = req.headers;
          if (req.body) init.body = req.body;
          const expr = `(async () => { try { const r = await fetch(${JSON.stringify(url)}, ${JSON.stringify(init)});
            await r.text(); return { ok: true, status: r.status, total: r.headers.get("X-Total"), secret: r.headers.get("X-Secret") };
          } catch (e) { return { ok: false, err: String(e) }; } })()`;
          const res = await c.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, sessions[o]);
          results.push({ k, o, r, target, chrome: res.result.value });
        }
      }
    }
    c.close();
  } finally {
    chrome.kill();
    srv.stdin.end();
    await srv.exited;
    for (const p of pages) p.stop(true);
  }

  // The server's log: every request it got and the head it answered, by target.
  const byTarget = new Map();
  for (const line of fs.readFileSync(logPath, "utf8").split("\n")) {
    if (!line) continue;
    const e = JSON.parse(line);
    if (!byTarget.has(e.target)) byTarget.set(e.target, []);
    byTarget.get(e.target).push(e);
  }

  const o = [];
  o.push("// SPDX-License-Identifier: MIT");
  o.push(`// GENERATED by modules/cors/tools/browser_oracle.js (${chromeVersion.split("/")[0]}, bun ${Bun.version}) -- do not hand-edit.`);
  o.push("//! What headless Chrome sent to and got from this module's middleware, per configuration,");
  o.push("//! origin and fetch(); replayed by `browser_oracle_test.zig`. Regenerate: `zig build interop-cors`.");
  o.push("");
  o.push('const cors = @import("root.zig");');
  o.push("");
  o.push("pub const origins = [_][]const u8{ " + ORIGINS.map(zstr).join(", ") + " };");
  o.push("");
  o.push("pub const configs = [_]cors.Options{");
  for (const cfg of CONFIGS) {
    const f = [];
    if (cfg.origins === "any") f.push(".allowed_origins = .any");
    else if (cfg.origins === "none") f.push(".allowed_origins = .none");
    else f.push(".allowed_origins = .{ .list = &.{ " + cfg.origins.map(zstr).join(", ") + " } }");
    f.push(".allowed_methods = &.{ " + cfg.methods.map((m) => "." + m.toLowerCase()).join(", ") + " }");
    f.push(cfg.headers === "reflect" ? ".allowed_headers = .reflect" : ".allowed_headers = .{ .list = &.{ " + cfg.headers.map(zstr).join(", ") + " } }");
    if (cfg.expose) f.push(".exposed_headers = &.{ " + cfg.expose.map(zstr).join(", ") + " }");
    if (cfg.credentials) f.push(".allow_credentials = true");
    if (cfg.max_age != null) f.push(`.max_age_s = ${cfg.max_age}`);
    if (cfg.unconditional) f.push(".allow_unconditional_wildcard = true");
    o.push("    .{ " + f.join(", ") + " },");
  }
  o.push("};");
  o.push("");
  o.push("/// `Case.config` past `configs` names the static posture's configuration `config - configs.len`");
  o.push("/// (the two `statics` in browser_oracle_test.zig and tools/interop.zig).");
  o.push(`pub const statics_len = ${STATICS.length};`);
  o.push("");
  o.push("/// One request the middleware got and the head it answered: `request` is the wire bytes the");
  o.push("/// replay sends (Chrome's method, target and CORS-relevant headers); `head` the status and every");
  o.push("/// `Access-Control-*` and `Vary` field it answered, in order.");
  o.push("pub const Exchange = struct { request: []const u8, status: u16, head: []const [2][]const u8 };");
  o.push("/// What the script saw (`ok`: a response, not a network error; `total`/`secret`: it could read");
  o.push("/// `X-Total`/`X-Secret`), and what the configured policy says it should see (`want_*`).");
  o.push("pub const Case = struct { config: u8, origin: u8, name: []const u8, ok: bool, total: bool, secret: bool,");
  o.push("    want_ok: bool, want_total: bool, want_secret: bool, exchanges: []const Exchange };");
  o.push("");
  o.push("pub const cases = [_]Case{");
  let mismatches = 0;
  for (const res of results) {
    const req = REQUESTS[res.r];
    const w = res.k < CONFIGS.length ? want(CONFIGS[res.k], ORIGINS[res.o], req) : wantStatic(STATICS[res.k - CONFIGS.length], ORIGINS[res.o], req);
    const got = { ok: !!res.chrome.ok, total: res.chrome.total != null, secret: res.chrome.secret != null };
    if (got.ok !== w.ok || got.total !== w.total || got.secret !== w.secret) {
      mismatches++;
      process.stderr.write(`MISMATCH k${res.k} o${res.o} ${req.name}: chrome ${JSON.stringify(got)} want ${JSON.stringify(w)} ${res.chrome.err || ""}\n`);
    }
    const sent = byTarget.get(res.target) || [];
    for (const e of sent) {
      const og = e.headers.find(([n]) => n.toLowerCase() === "origin");
      if (!og || og[1] !== ORIGINS[res.o]) throw new Error(`${res.target}: sent with Origin ${og && og[1]}, not from its page`);
    }
    const ex = sent.map((e) => {
      let wire = `${e.method} ${e.target} HTTP/1.1\r\nHost: t\r\n`;
      for (const [n, v] of e.headers) if (!NOISE.test(n)) wire += `${n}: ${v}\r\n`;
      wire += "Connection: close\r\n\r\n";
      const head = e.resp.filter(([n]) => /^(access-control-|vary$)/i.test(n));
      return `.{ .request = ${zstr(wire)}, .status = ${e.status}, .head = &.{ ${head.map(([n, v]) => `.{ ${zstr(n)}, ${zstr(v)} }`).join(", ")} } }`;
    });
    o.push(
      `    .{ .config = ${res.k}, .origin = ${res.o}, .name = ${zstr(req.name)}, .ok = ${got.ok}, .total = ${got.total}, .secret = ${got.secret}, ` +
        `.want_ok = ${w.ok}, .want_total = ${w.total}, .want_secret = ${w.secret}, .exchanges = &.{ ${ex.join(", ")} } },`,
    );
  }
  o.push("};");
  let text = o.join("\n") + "\n";
  const fmt = Bun.spawnSync(["zig", "fmt", "--stdin"], { stdin: Buffer.from(text) });
  if (fmt.exitCode !== 0) throw new Error("zig fmt: " + fmt.stderr.toString());
  text = fmt.stdout.toString();

  process.stderr.write(`${results.length} fetches, ${mismatches} where Chrome and the policy disagree (${chromeVersion})\n`);
  if (check) {
    const strip = (t) => t.split("\n").slice(2).join("\n");
    if (strip(fs.readFileSync(OUT, "utf8")) !== strip(text)) {
      process.stderr.write("browser_oracle: committed vectors differ from a fresh run\n");
      process.exit(1);
    }
    process.stderr.write("browser_oracle: vectors fresh\n");
  } else {
    fs.writeFileSync(OUT, text);
  }
}

main().catch((e) => {
  process.stderr.write(String(e.stack || e) + "\n");
  process.exit(1);
});
