# webhooksig

HMAC-SHA256 request/webhook signature **signing** and **verification**,
plus a `router` middleware that gates inbound webhooks (GitHub / Stripe
style) on a valid signature header — the signature layer of the Web/API
cluster.

Provenance: clean-room from the GitHub / Stripe webhook-HMAC convention
(`X-Signature-256: sha256=<hex>` / `X-Hub-Signature-256`) and RFC 2104
(HMAC) over FIPS 180-4 SHA-256; no third-party source consulted or copied.
Constant-time compare and the middleware shape mirror the sibling
`aaa-gate` module (same repo, MIT).

- **Status:** `gap`.
- **Model after:** GitHub / Stripe webhook HMAC signatures; RFC 2104 HMAC.
- **Platform:** any. **Role:** server. **Concurrency:** threadsafe — the
  `Verifier` is immutable after `init` (fixed secret set + config, no
  shared counters), so one instance is safely shared across all of
  `http.Server`'s connection threads; the free functions are pure.
- **Deps:** `router` (Middleware / Ctx / Next, the reserved `Ctx.data`
  slot), `http` (`Request.header`, the body `reader()`, `ResponseWriter`),
  and `std.crypto.auth.hmac.sha2.HmacSha256` + `std.crypto.timing_safe`.

Import name: registers as **`webhooksig`** — `@import("webhooksig")`.

## The model

The sender computes `HMAC-SHA256(secret, raw_body)` and presents it in a
header, e.g. `X-Signature-256: sha256=<hex-lowercase>` (GitHub). The
receiver recomputes the MAC over the **exact bytes it received** and
compares. Both the header name and the `sha256=` prefix are configurable.

The compare is **constant-time**: the recomputed MAC and the decoded
presented MAC are checked with `std.crypto.timing_safe.eql` over the
fixed-size raw MAC — never `std.mem.eql` on the signature (which leaks a
byte-at-a-time timing oracle an attacker walks to forge a valid
signature). A small **secret set** supports zero-downtime rotation: every
configured secret is tried and OR-accumulated **without early exit**, so
neither which secret matched nor whether any did leaks through timing.

## Usage

Verify inbound webhooks as `router` middleware:

```zig
const webhooksig = @import("webhooksig");
const router = @import("router");

var verifier = try webhooksig.Verifier.init(gpa, .{
    .secret = webhook_secret,            // raw bytes (retained)
    .extra_secrets = &.{old_secret},     // rotation set — any one passes
    .header = "X-Hub-Signature-256",      // default: X-Signature-256
    .prefix = "sha256=",                  // default; "" for bare hex
    .max_body_bytes = 1 << 20,            // reject larger bodies 413
});
defer verifier.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(verifier.middleware());        // before the protected routes
try r.post("/webhooks/github", onWebhook);

fn onWebhook(ctx: *router.Ctx) !void {
    const body = webhooksig.bodyOf(ctx).?; // the verified raw bytes
    // parse `body` — do NOT call ctx.req.reader(); the stream is consumed.
}
```

Sign an outbound webhook (or in a test):

```zig
var buf: [webhooksig.signatureBufLen(webhooksig.default_prefix)]u8 = undefined;
const value = webhooksig.sign(secret, body, &buf); // "sha256=<hex>"
try req.setHeader("X-Signature-256", value);
```

One-shot verify without the middleware:

```zig
if (!webhooksig.verify(secret, raw_body, presented_header)) return error.BadSignature;
```

The `Verifier` must outlive the `Router`, at a stable address (the
middleware's `state` points at it).

## Semantics

- **Reading the body consumes the stream.** To compute the MAC the
  middleware reads the entire raw body via
  `ctx.req.reader().allocRemaining(gpa, .limited(max_body_bytes))`. That
  drains the request stream, so the handler **cannot re-read it** from
  `ctx.req.reader()`. The verified bytes are stashed on `ctx.data` for the
  inner chain and retrieved with `bodyOf(ctx)`; they are freed when the
  middleware returns — copy anything kept past the handler.
- **Rejection.** A missing signature header, a malformed value
  (wrong prefix / wrong length / non-hex), or a MAC that matches no
  configured secret answers **401** with a `WWW-Authenticate: Signature`
  challenge (scheme configurable via `Options.challenge`) and a plain-text
  body; the chain is short-circuited (the handler never runs). A body
  larger than `max_body_bytes` answers **413** before any verification.
- **Secrets in memory.** An HMAC verifier must recompute the MAC over each
  body, so — unlike a bearer-token gate that stores only a digest — the
  `Verifier` retains the **raw** secrets for its lifetime. Keep it off any
  serialized/loggable surface.
- **Prefix / header.** `header` (case-insensitive) and `prefix` are both
  configurable; `prefix = ""` accepts a bare-hex value. Surrounding
  SP/TAB in the header value is tolerated; the hex is decoded
  case-insensitively.

## API

- `sign(secret, body, out_buf) []const u8` — `"sha256=<hex>"` into
  `out_buf`; `signWithPrefix(prefix, …)` for a custom prefix;
  `signatureBufLen(prefix)` sizes the buffer.
- `computeHex(secret, body) [64]u8` — the raw lowercase-hex MAC (no
  prefix).
- `verify(secret, body, presented) bool` — constant-time single-secret
  check; `verifyWithPrefix(prefix, …)` for a custom prefix.
- `Verifier.init/​deinit`, `Verifier.middleware()`,
  `Verifier.verifyBody(body, presented)` (multi-secret, constant-time),
  `Verifier.secretCount()`.
- `bodyOf(ctx) ?[]const u8` — the verified body inside a gated handler.

## Verification

`zig build test-webhooksig` — pure sign→verify round-trip; tampered-body /
wrong-secret / malformed / wrong-prefix / same-length-flip rejection; a
known HMAC-SHA256 test vector; custom / empty prefix; `Verifier` rotation
(old + new secret both accepted, no early exit); plus wire-level tests over
the socket-free `http.Server.serveStream` (correctly-signed body → 200 with
the handler re-reading the stashed body; missing header / tampered body /
wrong secret → 401 with the `WWW-Authenticate: Signature` challenge; custom
header name + rotation over the wire).
