# webhooksig

Webhook signature **signing** and **verification** for the schemes
receivers meet — **Standard Webhooks** (the Svix scheme: `v1` HMAC-SHA256
and `v1a` Ed25519), **Stripe**, **Slack**, and the GitHub-style single
`<prefix><mac>` value (SHA-1/SHA-256/SHA-512, hex or base64) — with a replay
tolerance on every timestamped scheme, plus a `router` middleware that gates
inbound webhooks on a valid signature. The signature layer of the Web/API
cluster.

Provenance: clean-room from RFC 2104 (HMAC) over FIPS 180-4 SHA-256 and the
publicly-documented GitHub/Stripe webhook-signature schemes (`sha256=<hex>` over
the body) — original work of the zig-libs authors (MIT); HMAC via Zig
`std.crypto`, no third-party source consulted or copied. RFC 4231 (HMAC-SHA-2
KATs) was evaluated as a test anchor and rejected: the HMAC primitive is
`std.crypto` directly, already anchored in Zig std's own suite, so RFC 4231
would anchor nothing this module contributes. Instead, one test transcribes
GitHub's own webhook-validation docs' published canonical example (secret
"It's a Secret to Everybody", body "Hello, World!",
`sha256=757107ea0eb2…`) — a short factual secret/payload/digest triple GitHub
publishes specifically as a self-check oracle for third-party implementations of
its `sha256=<hex>` convention, independently re-verified with `openssl dgst
-sha256 -hmac` before adoption. That is a provenance record, not a vendored
corpus: three short strings used as a test oracle, the same relationship root
`NOTICE` §0 describes for a black-box binary, not third-party source or a
reproduced data table — so **no `modules/webhooksig/NOTICE` is created for it**.
Constant-time compare and the middleware shape mirror the sibling `aaa-gate`
module (same repo, MIT).

- **Model after:** GitHub webhook HMAC signatures (`sha256=<hex>`); RFC 2104 HMAC.
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
compares. Both the header name and the `sha256=` prefix are configurable —
that covers any provider using GitHub's single-value `<prefix><hex>` shape.

## Schemes

| Scheme | Headers | Signed content | Signature | Key |
|---|---|---|---|---|
| `.prefixed` (`Format`) | one, configurable (`X-Hub-Signature-256`) | the body | `<prefix><hex\|base64>` of HMAC-SHA-1/256/512 | the secret as given |
| `standard` | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `id.ts.body` | space-separated `v1,<b64 HMAC-SHA256>` / `v1a,<b64 Ed25519>` | `whsec_<b64>` (decode with `standard.decodeSecret`), `whpk_`/`whsk_` |
| `stripe` | `Stripe-Signature` | `ts.body` | `t=<ts>,v1=<hex>[,v1=…]` | `whsec_…` as text |
| `slack` | `X-Slack-Signature`, `X-Slack-Request-Timestamp` | `v0:ts:body` | `v0=<hex>` | the signing secret as text |

**Replay.** The timestamped schemes refuse a timestamp more than
`tolerance_s` (default `default_tolerance_s` = 300 s, as every reference)
from `now` in **either** direction (Stripe's SDKs check only the past). The
module reads no clock: the free functions take `now`, the middleware a
`Clock` (`Clock.fromIo(&io)` for the real one). A replay *inside* the window
is the caller's to stop (remember `webhook-id`s for `tolerance_s`).

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

Standard Webhooks (Svix) receiver:

```zig
var key_buf: [webhooksig.standard.max_secret_len]u8 = undefined;
const key = try webhooksig.standard.decodeSecret(&key_buf, "whsec_…");
var verifier = try webhooksig.Verifier.init(gpa, .{
    .secret = key,                                   // the decoded key, not "whsec_…"
    .scheme = .standard_webhooks,
    .public_keys = &.{try webhooksig.standard.decodePublicKey("whpk_…")}, // optional, for v1a
    .clock = webhooksig.Clock.fromIo(&io),
});
// or without the middleware:
try webhooksig.standard.verify(.{ .secrets = &.{key} }, id, ts_header, sig_header, body, now, 300);
```

Stripe / Slack without the middleware:

```zig
try webhooksig.stripe.verify(&.{endpoint_secret}, stripe_signature, body, now, 300);
try webhooksig.slack.verify(&.{signing_secret}, slack_ts, slack_sig, body, now, 300);
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
  configurable; `prefix = ""` accepts a bare value. Surrounding
  SP/TAB in the header value is tolerated; hex is decoded
  case-insensitively, base64 is standard-alphabet and padded.
- **Stale first.** For the timestamped schemes the middleware checks the
  timestamp from the headers alone and answers 401 **before reading the
  body**.
- **Bounded work.** At most `max_signatures` (16) entries of one signature
  header, of them at most `max_ed25519_signatures` (4) `v1a`; at most
  `max_keys` (8) secrets / public keys. Each HMAC is computed once per key,
  not per presented signature.

## API

- `sign(secret, body, out_buf) []const u8` — `"sha256=<hex>"` into
  `out_buf`; `signWithPrefix(prefix, …)` for a custom prefix;
  `signatureBufLen(prefix)` sizes the buffer.
- `computeHex(secret, body) [64]u8` — the raw lowercase-hex MAC (no
  prefix).
- `verify(secret, body, presented) bool` — constant-time single-secret
  check; `verifyWithPrefix(prefix, …)` for a custom prefix.
- `Format{prefix, digest, encoding}`, `signFormat`, `verifyFormat` — the
  prefixed scheme with any `Digest` (`sha1`/`sha256`/`sha512`) and
  `Encoding` (`hex`/`base64`).
- `standard.{sign, signEd25519, verify, decodeSecret, encodeSecret,
  decodePublicKey, decodeSigningKey}`, `stripe.{sign, verify}`,
  `slack.{sign, verify}`, `checkTimestamp`, `VerifyError`, `Clock`.
- `Verifier.init/​deinit`, `Verifier.middleware()`,
  `Verifier.verifyBody(body, presented)` (prefixed, multi-secret,
  constant-time), `Verifier.verifyRequest(headers, body, now)` (any scheme),
  `Verifier.checkFreshness`, `Verifier.secretCount()`; `Options.scheme`,
  `digest`, `encoding`, `public_keys`, `clock`, `tolerance_s`.
- `bodyOf(ctx) ?[]const u8` — the verified body inside a gated handler.

## Verification

`zig build test-webhooksig` — pure sign→verify round-trip; tampered-body /
wrong-secret / malformed / wrong-prefix / same-length-flip rejection; a
known HMAC-SHA256 test vector; custom / empty prefix; `Verifier` rotation
(old + new secret both accepted, no early exit); plus wire-level tests over
the socket-free `http.Server.serveStream` (correctly-signed body → 200 with
the handler re-reading the stashed body; missing header / tampered body /
wrong secret → 401 with the `WWW-Authenticate: Signature` challenge; custom
header name + rotation over the wire). Since 2026-10-04: the Standard
Webhooks reference library's sign vector, Slack's documented example,
Python-`hmac` vectors for Stripe / SHA-1 / SHA-512 / base64, an
`openssl`-signed Ed25519 `v1a` vector, the tolerance boundary both ways,
every scheme through the middleware, and a seeded hostile-header sweep with
a sign→verify→flip oracle.
