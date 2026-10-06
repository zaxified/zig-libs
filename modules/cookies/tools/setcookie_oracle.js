// SPDX-License-Identifier: MIT
//
// The Set-Cookie BUILD oracle: what `SetCookie.write` serializes is what a
// browser stores. Each case is a `SetCookie` (fields below). Its header line
// is composed in the module's attribute order and served by a raw TCP server
// to headless Google Chrome, driven over the DevTools protocol; the cookie
// Chrome stored (or that it stored none) is compared with what the fields
// mean. Go's `net/http.ParseSetCookie` (tools/go_setcookie) reads the same
// line as a second opinion. The replay (src/setcookie_oracle_test.zig) needs
// neither Chrome, Go nor bun: `write` must produce exactly the frozen line
// for every case the oracle says works, and refuse every other one.
//
//   bun modules/cookies/tools/setcookie_oracle.js            # writes src/setcookie_vectors.zig
//   bun modules/cookies/tools/setcookie_oracle.js --check    # re-take, compare with the committed file
//   bun modules/cookies/tools/setcookie_oracle.js --report   # print the verdicts, write nothing
//
// Chrome runs with a throwaway profile, no OS keyring (--password-store=basic),
// `*.example.test` mapped to 127.0.0.1 and http://www.example.test:18740
// treated as a secure origin, so `Secure` and the prefixes can be judged
// without TLS. Loopback only; fixed ports 18740 (server) and 18741 (DevTools).

const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const check = args.includes("--check");
const report = args.includes("--report");
const ROOT = path.resolve(__dirname, "..", "..", "..");
const SCRATCH = path.join(ROOT, ".zig-cache", "setcookie-oracle");
const OUT = path.join(ROOT, "modules", "cookies", "src", "setcookie_vectors.zig");
const PORT = 18740;
const DEVTOOLS = 18741;
const HOST = "www.example.test";
const ORIGIN = `http://${HOST}:${PORT}`;
const DATE = "Wed, 21 Oct 2099 07:28:00 GMT";

// Strings are byte strings: every char code is one byte (latin1).
const b = (s) => Buffer.from(s, "utf8").toString("latin1");
const X = (n) => "x".repeat(n);

// ── the cases: SetCookie fields ──────────────────────────────────────────────
const CASES = [
  { name: "a", value: "1" },
  { name: "a", value: "" },
  { name: "a", value: "!#$%&'()*+-./09:<=>?@AZ[]^_`az{|}~" },
  { name: "a", value: '"x"' },
  { name: "a", value: '"', cls: "RFC_GRAMMAR" },
  { name: "a", value: "a b", cls: "RFC_GRAMMAR" },
  { name: "a", value: "a,b", cls: "RFC_GRAMMAR" },
  { name: "a", value: "a\\b", cls: "RFC_GRAMMAR" },
  { name: "a", value: b("é"), cls: "RFC_GRAMMAR" },
  { name: "a", value: "a;b" },
  { name: "a", value: "a\tb" },
  { name: "!#$%&'*+-.^_`|~09AZaz", value: "1" },
  { name: "a b", value: "1", cls: "RFC_GRAMMAR" },
  { name: "a=b", value: "1" },
  { name: "", value: "1", cls: "RFC_GRAMMAR" },
  { name: b("é"), value: "1", cls: "RFC_GRAMMAR" },
  { name: "(a)", value: "1", cls: "RFC_GRAMMAR" },
  { name: "a", value: "1", path: "/" },
  { name: "a", value: "1", path: "/c/x" },
  { name: "a", value: "1", path: "/a b" },
  { name: "a", value: "1", path: "/a,b" },
  { name: "a", value: "1", path: b("/é"), cls: "RFC_GRAMMAR" },
  { name: "a", value: "1", path: "relative" },
  { name: "a", value: "1", path: "" },
  { name: "a", value: "1", path: "/" + X(1023) },
  { name: "a", value: "1", path: "/" + X(1024) },
  { name: "a", value: "1", path: "/a\tb" },
  { name: "a", value: "1", domain: "example.test" },
  { name: "a", value: "1", domain: ".example.test" },
  { name: "a", value: "1", domain: "EXAMPLE.TEST" },
  { name: "a", value: "1", domain: "www.example.test" },
  { name: "a", value: "1", domain: "other.test", cls: "CONTEXT" },
  { name: "a", value: "1", domain: "exa mple.test" },
  { name: "a", value: "1", domain: "" },
  { name: "a", value: "1", domain: "example.test." },
  { name: "a", value: "1", domain: b("ěxample.test") },
  { name: "a", value: "1", domain: "test", cls: "CONTEXT" },
  { name: "a", value: "1", max_age: 3600 },
  { name: "a", value: "1", max_age: 0 },
  { name: "a", value: "1", max_age: -1 },
  { name: "a", value: "1", max_age: "9223372036854775807" },
  { name: "a", value: "1", expires: DATE },
  { name: "a", value: "1", expires: "tomorrow" },
  { name: "a", value: "1", expires: DATE + "; Domain=example.test" },
  { name: "a", value: "1", expires: DATE + "; HttpOnly" },
  { name: "a", value: "1", max_age: 3600, expires: "Wed, 21 Oct 2015 07:28:00 GMT" },
  { name: "a", value: "1", secure: true },
  { name: "a", value: "1", http_only: true },
  { name: "a", value: "1", same_site: "lax" },
  { name: "a", value: "1", same_site: "strict" },
  { name: "a", value: "1", same_site: "none", secure: true },
  { name: "a", value: "1", same_site: "none" },
  { name: "__Secure-a", value: "1", secure: true },
  { name: "__Secure-a", value: "1" },
  { name: "__secure-a", value: "1" },
  { name: "__SECURE-a", value: "1" },
  { name: "__Host-a", value: "1", secure: true, path: "/" },
  { name: "__Host-a", value: "1", secure: true },
  { name: "__Host-a", value: "1", secure: true, path: "/", domain: "www.example.test" },
  { name: "__Host-a", value: "1", path: "/" },
  { name: "__host-a", value: "1", secure: true, path: "/c" },
  { name: "__HOST-a", value: "1", secure: true },
  { name: "a", value: X(4095) },
  { name: "a", value: X(4096) },
  { name: "a", value: "1", path: "/", domain: "example.test", max_age: 60, secure: true, http_only: true, same_site: "strict" },
];

// Where `want` is not Chrome's verdict: `want` = the stored cookie is what the
// fields mean, unless the case names one of these.
const CLASSES = {
  RFC_GRAMMAR: "Chrome stores it as meant, but the RFC 6265 §4.1.1 grammar a server must produce excludes the " +
    "byte (cookie-octet, token, path-value) and Go's net/http refuses or drops it -- refused",
  CONTEXT: "Chrome drops it for the request's host (Domain of another site, a public suffix), which the " +
    "header alone cannot know -- written",
};

// The line, in `SetCookie.write`'s attribute order (RFC 6265 §4.1).
function compose(c) {
  let s = `${c.name}=${c.value}`;
  if (c.path !== undefined) s += `; Path=${c.path}`;
  if (c.domain !== undefined) s += `; Domain=${c.domain}`;
  if (c.max_age !== undefined) s += `; Max-Age=${c.max_age}`;
  if (c.expires !== undefined) s += `; Expires=${c.expires}`;
  if (c.secure) s += "; Secure";
  if (c.http_only) s += "; HttpOnly";
  if (c.same_site) s += `; SameSite=${{ lax: "Lax", strict: "Strict", none: "None" }[c.same_site]}`;
  return s;
}

// What the fields mean, in the terms Chrome reports a stored cookie in. A
// case whose fields mean "no cookie" (Max-Age <= 0, a past date) is `null`.
const DEFAULT_PATH = "/c"; // every case is set from /c/<i>
// A prefixed name is judged from http://localhost: Chrome takes `Secure` from
// an origin the flag above marks secure, but the `__Secure-`/`__Host-` checks
// want a secure scheme, which localhost stands in for.
const hostOf = (c) => (/^__(secure|host)-/i.test(c.name) ? "localhost" : HOST);
function meaning(c) {
  if (c.max_age !== undefined && Number(c.max_age) <= 0) return null;
  const domain = c.domain === undefined ? hostOf(c) : "." + c.domain.toLowerCase().replace(/^\./, "");
  return {
    name: c.name,
    value: c.value,
    domain,
    path: c.path === undefined ? DEFAULT_PATH : c.path,
    secure: !!c.secure,
    httpOnly: !!c.http_only,
    sameSite: c.same_site ? { lax: "Lax", strict: "Strict", none: "None" }[c.same_site] : undefined,
    session: c.max_age === undefined && c.expires === undefined,
  };
}

// ── the server: one raw response per case, the line byte for byte ───────────
function serve(lines) {
  return Bun.listen({
    hostname: "127.0.0.1",
    port: PORT,
    socket: {
      data(sock, data) {
        const req = Buffer.from(data).toString("latin1");
        const target = req.split(" ")[1] || "/";
        const m = /^\/c\/(\d+)$/.exec(target);
        const body = "<!doctype html><title>c</title>";
        let head = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\nConnection: close\r\n`;
        if (m) head += `Set-Cookie: ${lines[Number(m[1])]}\r\n`;
        sock.write(Buffer.from(head + "\r\n" + body, "latin1"));
        sock.end();
      },
    },
  });
}

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

async function chromeVerdicts(lines, hosts) {
  fs.mkdirSync(SCRATCH, { recursive: true });
  const server = serve(lines);
  const chrome = Bun.spawn(
    ["google-chrome", "--headless=new", `--remote-debugging-port=${DEVTOOLS}`, `--user-data-dir=${path.join(SCRATCH, "chrome-profile")}`,
      "--no-first-run", "--password-store=basic", "--use-mock-keychain", "--no-default-browser-check", "--disable-gpu", "--disable-extensions",
      `--host-resolver-rules=MAP *.example.test 127.0.0.1`, `--unsafely-treat-insecure-origin-as-secure=${ORIGIN}`, "about:blank"],
    { stdout: "ignore", stderr: "ignore" },
  );
  const out = [];
  let version = "";
  try {
    const v = await waitJson(`http://127.0.0.1:${DEVTOOLS}/json/version`);
    version = v.Browser;
    const c = cdp(v.webSocketDebuggerUrl);
    await c.ready;
    const { targetId } = await c.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await c.send("Target.attachToTarget", { targetId, flatten: true });
    await c.send("Runtime.enable", {}, sessionId);
    for (let i = 0; i < lines.length; i++) {
      await c.send("Storage.clearCookies", {});
      await c.send("Page.navigate", { url: `http://${hosts[i]}:${PORT}/c/${i}` }, sessionId);
      let done = false;
      for (let t = 0; t < 100 && !done; t++) {
        const r = await c.send("Runtime.evaluate", { expression: "location.pathname + ' ' + document.readyState", returnByValue: true }, sessionId);
        done = r.result.value === `/c/${i} complete`;
        if (!done) await Bun.sleep(30);
      }
      if (!done) throw new Error(`case ${i}: page never loaded`);
      const { cookies } = await c.send("Storage.getCookies", {});
      if (cookies.length > 1) throw new Error(`case ${i}: ${cookies.length} cookies`);
      const k = cookies[0];
      out.push(k ? {
        name: Buffer.from(k.name, "utf8").toString("latin1"),
        value: Buffer.from(k.value, "utf8").toString("latin1"),
        domain: k.domain, path: Buffer.from(k.path, "utf8").toString("latin1"),
        secure: k.secure, httpOnly: k.httpOnly, sameSite: k.sameSite, session: k.session,
      } : null);
    }
    c.close();
  } finally {
    chrome.kill();
    await chrome.exited;
    server.stop(true);
  }
  return { version, out };
}

function goVerdicts(lines) {
  const p = Bun.spawnSync(["go", "run", "."], {
    cwd: path.join(__dirname, "go_setcookie"),
    stdin: Buffer.from(lines.map((l) => Buffer.from(l, "latin1").toString("hex")).join("\n") + "\n"),
  });
  if (p.exitCode !== 0) throw new Error("go_setcookie: " + p.stderr.toString());
  const goVersion = Bun.spawnSync(["go", "version"]).stdout.toString().split(" ")[2];
  return { goVersion, out: p.stdout.toString().trim().split("\n").map((l) => JSON.parse(l)) };
}

function same(a, b) {
  if (a === null || b === null) return a === b;
  return a.name === b.name && a.value === b.value && a.domain === b.domain && a.path === b.path && a.secure === b.secure &&
    a.httpOnly === b.httpOnly && a.sameSite === b.sameSite && a.session === b.session;
}

function show(k) {
  if (k === null) return "(none)";
  const v = k.value.length > 12 ? k.value.slice(0, 12) + `…(${k.value.length})` : k.value;
  const p = k.path.length > 12 ? k.path.slice(0, 12) + `…(${k.path.length})` : k.path;
  return `${JSON.stringify(k.name)}=${JSON.stringify(v)} d=${k.domain} p=${p} s=${k.secure} h=${k.httpOnly} ss=${k.sameSite} sess=${k.session}`;
}

const lines = CASES.map(compose);
const ch = await chromeVerdicts(lines, CASES.map(hostOf));
const go = goVerdicts(lines);

if (report) {
  CASES.forEach((c, i) => {
    const want = meaning(c);
    const got = ch.out[i];
    const ok = same(want, got);
    console.log(`${String(i).padStart(2)} ${ok ? "AGREE " : "DIFFER"} ${JSON.stringify(lines[i]).slice(0, 90)}`);
    if (!ok) console.log(`     means ${show(want)}\n     chrome ${show(got)}`);
    const g = go.out[i];
    console.log(`     go ${g.err ? "ERR " + g.err : `${JSON.stringify(g.name)}=${JSON.stringify(g.value.slice(0, 12))} p=${g.path.slice(0, 12)} d=${g.domain} ma=${g.maxAge} exp=${g.expires} s=${g.secure} h=${g.httpOnly} ss=${g.sameSite}`}`);
  });
  console.log(ch.version, go.goVersion);
  process.exit(0);
}

// ── the vectors ──────────────────────────────────────────────────────────────
function zstr(s) {
  let out = '"';
  for (const byte of Buffer.from(s, "latin1")) {
    if (byte === 0x22) out += '\\"';
    else if (byte === 0x5c) out += "\\\\";
    else if (byte >= 0x20 && byte < 0x7f) out += String.fromCharCode(byte);
    else out += "\\x" + byte.toString(16).padStart(2, "0");
  }
  return out + '"';
}

function zcase(c) {
  const f = [`.name = ${zstr(c.name)}`, `.value = ${zstr(c.value)}`];
  if (c.path !== undefined) f.push(`.path = ${zstr(c.path)}`);
  if (c.domain !== undefined) f.push(`.domain = ${zstr(c.domain)}`);
  if (c.max_age !== undefined) f.push(`.max_age = ${c.max_age}`);
  if (c.expires !== undefined) f.push(`.expires = ${zstr(c.expires)}`);
  if (c.secure) f.push(".secure = true");
  if (c.http_only) f.push(".http_only = true");
  if (c.same_site) f.push(`.same_site = .${c.same_site}`);
  return ".{ " + f.join(", ") + " }";
}

function goShow(g) {
  if (g.err) return "error: " + g.err;
  return `${g.name}=${g.value.length > 16 ? g.value.slice(0, 16) + "..." : g.value}` + (g.quoted ? " quoted" : "") +
    (g.path ? ` path=${g.path.length > 16 ? g.path.slice(0, 16) + "..." : g.path}` : "") + (g.domain ? ` domain=${g.domain}` : "") +
    (g.maxAge ? ` max-age=${g.maxAge}` : "") + (g.expires ? " expires" : "") + (g.secure ? " secure" : "") +
    (g.httpOnly ? " httponly" : "") + (g.sameSite ? ` samesite=${g.sameSite}` : "");
}

const o = [];
o.push("// SPDX-License-Identifier: MIT");
o.push(`// GENERATED by modules/cookies/tools/setcookie_oracle.js (${ch.version}, ${go.goVersion}, bun ${Bun.version}) -- do not hand-edit.`);
o.push("//! Set-Cookie lines and what Chrome stored / Go read from them, replayed by `setcookie_oracle_test.zig`.");
o.push("//! Regenerate with the command in the script's header.");
o.push("");
o.push('const SetCookie = @import("root.zig").SetCookie;');
o.push("");
o.push("/// `line`: the case's fields in `write`'s attribute order. `chrome`: true when Chrome stored exactly");
o.push("/// what the fields mean (a delete counts when it stored nothing); `go`: what net/http.ParseSetCookie");
o.push("/// read. `want`: `write` must produce `line` (true) or refuse (false); `class` names the rule in");
o.push("/// the script that decided it when it is not Chrome's verdict.");
o.push("pub const Case = struct { sc: SetCookie, line: []const u8, chrome: bool, go: []const u8, want: bool, class: []const u8 };");
o.push("");
o.push("pub const classes = [_][]const u8{ " + Object.keys(CLASSES).map(zstr).join(", ") + " };");
o.push("");
o.push("pub const cases = [_]Case{");
CASES.forEach((c, i) => {
  const agree = same(meaning(c), ch.out[i]);
  const want = c.cls === "RFC_GRAMMAR" ? false : c.cls === "CONTEXT" ? true : agree;
  if (c.cls && (c.cls === "RFC_GRAMMAR") !== agree) throw new Error(`case ${i}: class ${c.cls} but Chrome agree=${agree}`);
  o.push(`    .{ .sc = ${zcase(c)}, .line = ${zstr(lines[i])}, .chrome = ${agree}, .go = ${zstr(goShow(go.out[i]))}, .want = ${want}, .class = ${zstr(c.cls || "")} },`);
});
o.push("};");
const text = o.join("\n") + "\n";
if (check) {
  if (fs.readFileSync(OUT, "utf8") !== text) {
    console.error("setcookie_oracle: src/setcookie_vectors.zig is stale -- regenerate it");
    process.exit(1);
  }
  console.log("setcookie_oracle: vectors match");
} else {
  fs.writeFileSync(OUT, text);
  console.log(`setcookie_oracle: ${CASES.length} cases -> ${path.relative(ROOT, OUT)}`);
}
