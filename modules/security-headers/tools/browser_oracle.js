// SPDX-License-Identifier: MIT
//
// The security-headers browser oracle: headless Google Chrome, over the
// DevTools protocol, loads a page from this module's middleware
// (tools/interop.zig `serve`, one configuration per port) and, from a page on
// another origin, frames it, embeds its image and opens it. What Chrome did --
// which scripts ran, whether the inline style and the data: image applied,
// what Referer it sent, whether the frame, the image and the opener survived,
// and every complaint it logged about a header -- is compared with what each
// header is specified to do (`want`, below). The heads the module answered are
// frozen, so the replay (src/browser_oracle_test.zig) needs neither Chrome nor
// bun.
//
//   zig build interop-security-headers               # writes src/browser_oracle_vectors.zig
//   zig build interop-security-headers -- --check    # re-take, compare
//
// Fixed ports: the other origin's page 18811, DevTools 18691, configurations
// 18720+. A port in use is a failure.

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const server = args[args.indexOf("--server") + 1];
const check = args.includes("--check");
const ROOT = path.resolve(__dirname, "..", "..", "..");
const SCRATCH = path.join(ROOT, ".zig-cache", "interop-security-headers");
const OUT = path.join(ROOT, "modules", "security-headers", "src", "browser_oracle_vectors.zig");
const OTHER = 18811;
const DEVTOOLS = 18691;
const BASE = 18720;

// ── configurations: null = the field's default, "" = header off, "@api"/"@helmet" = the module's CSPs
const CONFIGS = [
  { name: "defaults" },
  { name: "csp_api", csp: "@api" },
  { name: "csp_helmet_default", csp: "@helmet" },
  { name: "csp_api report-only", csp_report_only: "@api" },
  {
    name: "relaxed",
    hsts: false,
    nosniff: false,
    x_frame_options: "",
    referrer_policy: "strict-origin-when-cross-origin",
    coop: "",
    corp: "cross-origin",
    permissions_policy: "camera=(), geolocation=(self)",
  },
  { name: "SAMEORIGIN, unsafe-none", x_frame_options: "SAMEORIGIN", coop: "unsafe-none", referrer_policy: "same-origin" },
  // The negative control: malformed values Chrome must complain about, so a silent run means no complaint, not a deaf listener.
  { name: "malformed (control)", csp_report_only: "default-src 'self' 'bogus'; frobnicate 'none'", permissions_policy: "camera=*;", control: true },
];

// ── what each header is specified to do, for the page and its subresources ──
function want(cfg, k) {
  const csp = cfg.csp === "@api" ? "api" : cfg.csp === "@helmet" ? "helmet" : null;
  const nosniff = cfg.nosniff !== false;
  const xfo = cfg.x_frame_options === undefined ? "DENY" : cfg.x_frame_options;
  const ref = cfg.referrer_policy === undefined ? "no-referrer" : cfg.referrer_policy;
  const coop = cfg.coop === undefined ? "same-origin" : cfg.coop;
  const corp = cfg.corp === undefined ? "same-origin" : cfg.corp;
  const self = `http://127.0.0.1:${BASE + k}`;
  return {
    // CSP script-src: 'none' (api) blocks both; 'self' (helmet) blocks only the inline one.
    inline: csp === null,
    ext: csp !== "api",
    // X-Content-Type-Options: nosniff refuses a script served as text/plain.
    plain: csp !== "api" && !nosniff,
    // style-src: helmet allows 'unsafe-inline'; api's default-src 'none' does not.
    style: csp !== "api",
    // img-src: helmet allows data:; api does not.
    dataImg: csp !== "api",
    // connect-src (api: 'none') blocks the fetch; otherwise Referer per Referrer-Policy (same-origin fetch).
    referer: csp === "api" ? "blocked" : ref === "no-referrer" ? "-" : `${self}/c/page`,
    // X-Frame-Options DENY/SAMEORIGIN and helmet's frame-ancestors 'self' keep another origin from framing it.
    framed: xfo === "" && csp !== "api" && csp !== "helmet",
    // Cross-Origin-Resource-Policy: same-origin refuses the image to another origin.
    corpImg: corp === "cross-origin",
    // Cross-Origin-Opener-Policy: same-origin severs the opener's handle.
    severed: coop === "same-origin",
    complaints: [],
    complaint_expected: !!cfg.control,
  };
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
  const listeners = [];
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    } else if (msg.method) {
      for (const l of listeners) l(msg);
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
  return { ready, send, on: (f) => listeners.push(f), close: () => ws.close() };
}

async function openTab(c, url) {
  const { targetId } = await c.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await c.send("Target.attachToTarget", { targetId, flatten: true });
  for (const d of ["Runtime", "Page", "Log", "Audits"]) await c.send(d + ".enable", {}, sessionId);
  await c.send("Page.navigate", { url }, sessionId);
  const origin = new URL(url).origin;
  for (let i = 0; i < 100; i++) {
    const r = await c.send("Runtime.evaluate", { expression: "location.origin + ' ' + document.readyState", returnByValue: true }, sessionId);
    if (r.result.value === origin + " complete") return { targetId, sessionId };
    await Bun.sleep(100);
  }
  throw new Error("page never settled at " + url);
}

async function evaluate(c, sessionId, expression) {
  const r = await c.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
  return r.result.value;
}

function zstr(s) {
  let out = '"';
  for (const b of Buffer.from(s, "utf8")) {
    const c = String.fromCharCode(b);
    if (c === '"') out += '\\"';
    else if (c === "\\") out += "\\\\";
    else if (c === "\n") out += "\\n";
    else if (b >= 0x20 && b < 0x7f) out += c;
    else out += "\\x" + b.toString(16).padStart(2, "0");
  }
  return out + '"';
}

// The headers this module sets: the ones frozen and replayed.
const MANAGED = /^(strict-transport-security|content-security-policy(-report-only)?|x-content-type-options|x-frame-options|referrer-policy|permissions-policy|cross-origin-(opener|resource|embedder)-policy|server)$/i;
// A complaint is about a header: not a CSP refusal (expected), not a load failure.
function isComplaint(text) {
  if (/^(Refused to|\[Report Only\] Refused to|Failed to load resource)/.test(text)) return false;
  // An enforced (or reported) CSP decision, not a complaint about the header's syntax.
  if (/violates the following Content Security Policy directive/.test(text)) return false;
  return /header|directive|Unrecognized|ignored|invalid/i.test(text);
}

async function main() {
  fs.mkdirSync(SCRATCH, { recursive: true });
  const cfgPath = path.join(SCRATCH, "configs.json");
  const logPath = path.join(SCRATCH, "log.jsonl");
  fs.writeFileSync(cfgPath, JSON.stringify(CONFIGS.map(({ name, control, ...c }) => c)));

  const other = Bun.serve({ port: OTHER, hostname: "127.0.0.1", fetch: () => new Response("<!doctype html><title>other</title><body></body>", { headers: { "content-type": "text/html" } }) });
  const srv = Bun.spawn([server, "serve", cfgPath, logPath, String(BASE)], { stdin: "pipe", stdout: "pipe", stderr: "inherit" });
  const reader = srv.stdout.getReader();
  let first = "";
  while (!first.includes("\n")) {
    const { value, done } = await reader.read();
    if (done) throw new Error("server exited before it was ready");
    first += new TextDecoder().decode(value);
  }

  const profile = path.join(SCRATCH, "chrome-profile");
  const chrome = Bun.spawn(
    ["google-chrome", "--headless=new", `--remote-debugging-port=${DEVTOOLS}`, `--user-data-dir=${profile}`, "--no-first-run", "--password-store=basic", "--use-mock-keychain", "--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-popup-blocking", "about:blank"],
    { stdout: "ignore", stderr: "ignore" },
  );
  let chromeVersion = "";
  const results = [];
  try {
    const version = await waitJson(`http://127.0.0.1:${DEVTOOLS}/json/version`);
    chromeVersion = version.Browser;
    const c = cdp(version.webSocketDebuggerUrl);
    await c.ready;
    const complaints = new Map(); // sessionId -> [text]
    c.on((msg) => {
      if (!msg.sessionId || !complaints.has(msg.sessionId)) return;
      let text = null;
      if (msg.method === "Log.entryAdded") text = msg.params.entry.text;
      else if (msg.method === "Runtime.consoleAPICalled") text = msg.params.args.map((a) => a.value ?? a.description ?? "").join(" ");
      // A ContentSecurityPolicyIssue is an enforced (or reported) CSP decision; syntax problems come as log entries.
      else if (msg.method === "Audits.issueAdded" && msg.params.issue.code !== "ContentSecurityPolicyIssue")
        text = "issue " + msg.params.issue.code + " " + JSON.stringify(msg.params.issue.details).slice(0, 200);
      if (text != null) complaints.get(msg.sessionId).push(text);
    });
    const otherTab = await openTab(c, `http://127.0.0.1:${OTHER}/`);
    for (let k = 0; k < CONFIGS.length; k++) {
      const A = `http://127.0.0.1:${BASE + k}/c`;
      // A fresh tab per configuration, its complaints collected from the first byte.
      const { targetId } = await c.send("Target.createTarget", { url: "about:blank" });
      const { sessionId } = await c.send("Target.attachToTarget", { targetId, flatten: true });
      complaints.set(sessionId, []);
      for (const d of ["Runtime", "Page", "Log", "Audits"]) await c.send(d + ".enable", {}, sessionId);
      await c.send("Page.navigate", { url: A + "/page" }, sessionId);
      for (let i = 0; i < 100; i++) {
        const r = await c.send("Runtime.evaluate", { expression: "location.href + ' ' + document.readyState", returnByValue: true }, sessionId);
        if (r.result.value === A + "/page complete") break;
        await Bun.sleep(100);
      }
      const page = await evaluate(c, sessionId, `(async () => ({
        inline: !!window.inlineRan, ext: !!window.extRan, plain: !!window.plainRan,
        style: getComputedStyle(document.getElementById("s")).color === "rgb(1, 2, 3)",
        dataImg: (() => { const d = document.getElementById("d"); return d.complete && d.naturalWidth > 0; })(),
        referer: await fetch("ref", { cache: "no-store" }).then((x) => x.text(), () => "blocked"),
      }))()`);
      await Bun.sleep(300); // late console entries
      const cross = await evaluate(c, otherTab.sessionId, `(async () => {
        const img = await new Promise((res) => { const i = new Image(); i.onload = () => res(true); i.onerror = () => res(false); i.src = ${JSON.stringify(A + "/img.gif")}; });
        const f = document.createElement("iframe"); f.src = ${JSON.stringify(A + "/page")}; document.body.appendChild(f);
        await new Promise((res) => { f.onload = res; setTimeout(res, 3000); });
        const w = window.open(${JSON.stringify(A + "/page")});
        await new Promise((r) => setTimeout(r, 1500));
        const severed = !w || w.closed;
        try { w && w.close(); } catch (_) {}
        return { corpImg: img, severed };
      })()`);
      const tree = await c.send("Page.getFrameTree", {}, otherTab.sessionId);
      const kids = tree.frameTree.childFrames || [];
      const framed = kids.some((f) => f.frame.url === A + "/page");
      await evaluate(c, otherTab.sessionId, `document.querySelectorAll("iframe").forEach((f) => f.remove()); 1`);
      const got = { ...page, framed, ...cross, complaints: [...new Set(complaints.get(sessionId).filter(isComplaint))].sort() };
      results.push({ k, got });
      await c.send("Target.closeTarget", { targetId });
    }
    c.close();
  } finally {
    chrome.kill();
    srv.stdin.end();
    await srv.exited;
    other.stop(true);
  }

  // The heads the module answered, per configuration: every response must carry the same managed set.
  const heads = new Map();
  for (const line of fs.readFileSync(logPath, "utf8").split("\n")) {
    if (!line) continue;
    const e = JSON.parse(line);
    const set = e.resp.filter(([n]) => MANAGED.test(n));
    const key = JSON.stringify(set);
    if (!heads.has(e.cfg)) heads.set(e.cfg, key);
    else if (heads.get(e.cfg) !== key) throw new Error(`config ${e.cfg}: ${e.target} answered a different header set`);
  }

  const o = [];
  o.push("// SPDX-License-Identifier: MIT");
  o.push(`// GENERATED by modules/security-headers/tools/browser_oracle.js (${chromeVersion.split("/")[0]}, bun ${Bun.version}) -- do not hand-edit.`);
  o.push("//! What headless Chrome did with the page, its subresources and another origin's use of them, per");
  o.push("//! configuration; replayed by `browser_oracle_test.zig`. Regenerate: `zig build interop-security-headers`.");
  o.push("");
  o.push('const sh = @import("root.zig");');
  o.push("");
  o.push("/// What Chrome observed (and, `want_*`, what the headers are specified to cause).");
  o.push("pub const Seen = struct { inline_script: bool, ext_script: bool, plain_script: bool, inline_style: bool, data_img: bool,");
  o.push("    referer: []const u8, framed: bool, corp_img: bool, opener_severed: bool, complaints: []const []const u8 };");
  o.push("/// `head`: the headers this module set on every response under `options`, in order.");
  o.push("/// `complaint_expected`: the negative control, whose malformed values Chrome must complain about.");
  o.push("pub const Case = struct { name: []const u8, options: sh.Options, head: []const [2][]const u8, seen: Seen, want: Seen, complaint_expected: bool };");
  o.push("");
  o.push("pub const cases = [_]Case{");
  let mismatches = 0;
  const zopt = (v, dflt) => (v === undefined ? null : v === "" ? "null" : v === "@api" ? "sh.csp_api" : v === "@helmet" ? "sh.csp_helmet_default" : zstr(v));
  const zseen = (s) =>
    `.{ .inline_script = ${s.inline}, .ext_script = ${s.ext}, .plain_script = ${s.plain}, .inline_style = ${s.style}, .data_img = ${s.dataImg}, ` +
    `.referer = ${zstr(s.referer)}, .framed = ${s.framed}, .corp_img = ${s.corpImg}, .opener_severed = ${s.severed}, ` +
    `.complaints = &.{ ${s.complaints.map(zstr).join(", ")} } }`;
  for (const { k, got } of results) {
    const cfg = CONFIGS[k];
    const w = want(cfg, k);
    for (const f of Object.keys(w)) {
      if (f === "complaint_expected") continue;
      if (f === "complaints" ? (got.complaints.length > 0) !== w.complaint_expected : JSON.stringify(w[f]) !== JSON.stringify(got[f])) {
        mismatches++;
        process.stderr.write(`MISMATCH ${cfg.name}: ${f} chrome ${JSON.stringify(got[f])} want ${JSON.stringify(w[f])}\n`);
      }
    }
    const f = [];
    if (cfg.hsts === false) f.push(".hsts = null");
    const pairs = [
      ["csp", "content_security_policy"], ["csp_report_only", "content_security_policy_report_only"], ["x_frame_options", "x_frame_options"],
      ["referrer_policy", "referrer_policy"], ["permissions_policy", "permissions_policy"], ["coop", "cross_origin_opener_policy"],
      ["corp", "cross_origin_resource_policy"], ["coep", "cross_origin_embedder_policy"],
    ];
    for (const [js, zig] of pairs) {
      const v = zopt(cfg[js]);
      if (v !== null) f.push(`.${zig} = ${v}`);
    }
    if (cfg.nosniff === false) f.push(".x_content_type_options = false");
    const head = JSON.parse(heads.get(k) || "[]");
    o.push(
      `    .{ .name = ${zstr(cfg.name)}, .options = .{ ${f.join(", ")} }, .head = &.{ ${head.map(([n, v]) => `.{ ${zstr(n)}, ${zstr(v)} }`).join(", ")} }, ` +
        `.seen = ${zseen(got)}, .want = ${zseen(w)}, .complaint_expected = ${w.complaint_expected} },`,
    );
  }
  o.push("};");
  let text = o.join("\n") + "\n";
  const fmt = Bun.spawnSync(["zig", "fmt", "--stdin"], { stdin: Buffer.from(text) });
  if (fmt.exitCode === 0) text = fmt.stdout.toString();
  else process.stderr.write("browser_oracle: zig fmt unavailable or failed -- the vectors are written unformatted\n");

  process.stderr.write(`${results.length} configurations, ${mismatches} observations where Chrome and the headers' specification disagree (${chromeVersion})\n`);
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
