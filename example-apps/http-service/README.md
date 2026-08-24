# http-service

A hardened Task-tracking JSON API — one binary, built on the `http` +
`router` modules and the middleware family that composes onto them.

## Get it

Take this directory and nothing else — it is a self-contained project, and
the rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-08-24.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-08-24/example-apps/http-service'
cd http-service
```

With git instead, if you would rather have history:

```sh
git clone --depth 1 --filter=blob:none --sparse -b 2026-08-24 \
  https://github.com/zaxified/zig-libs.git
cd zig-libs && git sparse-checkout set example-apps/http-service
cd example-apps/http-service
```

## Which version of zig-libs this is written against

The tree, like every app here — see `example-apps/README.md` for the rule and
why the pin exists anyway. This app was written freely against whatever the
working tree's 14 composable middleware modules offer, without checking each
shape against a tag first, and `zig build --fork=../..` is the build that is
guaranteed to pass on every commit.

Measured, not assumed: `init.sh` — the customer path, fetching the **pinned**
tag — also builds cleanly. Every middleware API this app uses was already
present, unchanged, at that tag. That is not a standing promise between tags;
it is checked on the tag ref, where the pin and the commit are the same
content, by `scripts/check-apps.sh --pinned`.

## Build and run

```sh
./init.sh                     # fetch dependencies, build — see the note above
./zig-out/bin/http-service    # listens on 127.0.0.1:8087
```

`init.sh` needs Zig 0.16.0 on `PATH` and installs nothing for you. It prints
a fixed demo `X-Api-Key` and webhook HMAC secret on startup — override both
with `--api-key`/`--webhook-secret` for anything beyond a loopback demo (and
never on a real deployment's command line, where `ps` can read it — the same
caveat `ssh-demo`'s `--password-is` carries).

## What it does

An in-memory task list behind two client shapes:

- **`/api/tasks*`** — a machine API client authenticates with an `X-Api-Key`
  header. `GET`/`POST /api/tasks`, `GET`/`PUT`/`DELETE /api/tasks/:id`.
- **`/webhooks/tasks`** — an external system (no API key of its own) posts a
  completion event, authenticated by an HMAC-SHA256 signature instead
  (GitHub's `X-Signature-256: sha256=<hex>` convention) — the shape a payment
  processor or CI system uses, not a bearer token.
- **`/healthz`**, **`/readyz`**, **`/openapi.json`** — public, no auth.

## The middleware chain, and why this order

Global (`router.use`, applies to every request), outermost first:

1. **`tracecontext`** — outermost per the module's own doc: every response,
   including a 401/429/503 short-circuit, must carry the trace context.
2. **`requestid`** — same reasoning, and it deliberately avoids `Ctx.data` so
   it composes with the auth middleware nested below it.
3. **accesslog** (hand-written wrapper, not a `.middleware()` — see below) —
   wraps everything so its logged status/latency reflect the final outcome,
   whichever layer decided it.
4. **`security-headers`** — stamps headers *before* calling `next` (verified
   in the module source), so they land on every response, error pages
   included. Configured with `security_headers.csp_api`: a pure JSON API
   renders nothing a browser executes, so deny-everything is strictly more
   correct than the browser-app CSP default.
5. **`cors`** — must run before the auth gate: a preflight `OPTIONS` carries
   no `Authorization`/`X-Api-Key`, so `aaa-gate` would reject it if it ran
   first (this ordering is the module's own usage example).
6. **`health`** — "register before auth/rate-limit" (module doc): an
   orchestrator probe cannot present a credential.
7. **`openapi`** — public docs belong next to health; no client should need
   a key just to read the spec.
8. **`metrics`** — two pieces, in the module's own order: the `/metrics`
   endpoint first (a Prometheus scrape is an orchestrator probe like
   `/healthz` — no credential, no rate-limit, and not counted as traffic),
   then the request middleware, ABOVE the three shedding layers below so a
   short-circuited 429/503 still lands in `http_requests_total`. Deliberate
   consequence: `/healthz`, the OpenAPI doc and the scrape itself do not
   pollute the request metrics. The app also registers one business
   counter, `tasks_created_total` — and the smoke test uses it to prove an
   idempotent replay does NOT double-count, which is two modules
   cross-checking each other.
9. **`abuseguard`** — "register FIRST" relative to `ratelimit` (the module's
   own usage example), so its auto-strike sees the 429s below it, plus the
   401s from `aaa-gate` and the 400/409/422/413s from `idempotency` once
   those groups nest inside this chain.
10. **`ratelimit`** — per-client token bucket (5 req/s, burst 10).
11. **`throttle`** — the last-resort global concurrency shed (32 in flight);
    protects the server even when every per-client check passed.

Per-group (only the clients that need it pay for it):

- **`/api`**: `aaa-gate` (API-key auth) → `idempotency` (dedupe POST/PUT
  retries).
- **`/webhooks`**: `webhooksig` (HMAC verification).

`abuseguard` is also wired at the connection level
(`http.Server.Options.on_connect`/`on_conn_state`) — a *second*, earlier
layer that rejects an abusive peer at TCP accept time, before a byte of the
request is read. That is separate from `guard.middleware()`'s
response-status auto-strike above; the module ships both and this app uses
both, on purpose.

## Left out of the 14

- **`sessions`** (and its `csrf` sibling) — this is a machine-to-machine
  JSON API with no browser-rendered login page: there is no form to protect
  and no session cookie to issue. A customer adding a browser admin panel on
  top would wire `sessions` exactly the way `aaa-gate` is wired here
  (`router.use` on its own group).

## The three that are not `router.Middleware`

- **`accesslog`** — *used*, but in its documented shape: a plain
  `Entry -> std.Io.Writer` formatter, not a `.middleware()` that does not
  exist. `src/main.zig`'s `accessLogRun` is a hand-written
  `router.Middleware` that calls `next.run`, then hands the finished
  exchange to `accesslog.writeJsonLines`.
- **`staticfiles`** — left out. This service has no static assets to serve.
- **`websocket`** — left out. Nothing here needs a long-lived bidirectional
  stream; a customer wanting live task-update push would upgrade a
  dedicated route with it, outside the router chain — the module's own
  shape requires exactly that, not a bent-in middleware slot.

## Try it

```sh
./zig-out/bin/http-service
# prints the demo X-Api-Key / webhook secret and a curl cheat-sheet

curl -sSD- http://127.0.0.1:8087/healthz
curl -sSD- http://127.0.0.1:8087/openapi.json

curl -sSD- -H "X-Api-Key: demo-api-key-change-me" \
  -H 'Content-Type: application/json' -d '{"title":"write the report"}' \
  http://127.0.0.1:8087/api/tasks
# 201, security headers (CSP/HSTS/X-Frame-Options/...), an X-Request-Id

# 15 requests against a 5/s-burst-10 bucket: some come back 429
for i in $(seq 1 15); do
  curl -s -o /dev/null -w '%{http_code} ' -H "X-Api-Key: demo-api-key-change-me" \
    http://127.0.0.1:8087/api/tasks
done; echo

# signed webhook (id from the task you created above)
SECRET=demo-webhook-secret-change-me
BODY='{"id":1}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')
curl -sSD- -H "X-Signature-256: sha256=$SIG" -H 'Content-Type: application/json' \
  -d "$BODY" http://127.0.0.1:8087/webhooks/tasks
```

## A measured interaction: a stray `Allow` header on a CORS preflight

Send a real preflight to a route that has no `OPTIONS` handler and does not
have `auto_options` on (this app has neither):

```sh
curl -sSD- -X OPTIONS -H "Origin: http://localhost:5173" \
  -H "Access-Control-Request-Method: POST" http://127.0.0.1:8087/api/tasks
```

The response is a correct `204` with the right `Access-Control-*` headers —
and it *also* carries `Allow: GET, HEAD, POST`, ahead of every other header,
including `traceparent` (which the outermost middleware sets before anything
else runs). Neither module is wrong. `router.Router.dispatch` sets `Allow`
on the response the instant it finds a path match with no method match,
*before* the global middleware chain (which is how it reaches `cors`) even
starts — the comment at the call site says why: "Allow goes on first so an
overridden handler inherits it," for a caller who overrides
`method_not_allowed`. `cors.Cors.handlePreflight` genuinely never calls
`next` for a preflight, exactly as its own doc says — but `Allow` was
already written to the *same* `ResponseWriter` before `cors` ever got a
turn, and nothing about intercepting the chain un-writes an already-set
header. Two correct, independently-documented behaviors compose into a
response neither module's own docs describe. It is harmless here (an extra
`Allow` alongside `Access-Control-Allow-Methods` on a 204 is not incorrect
HTTP), but a customer relying on "cors fully owns the preflight response"
would be surprised by it, and `auto_options = true` does not avoid it —
`Allow` is set on the same code path regardless of which fallback endpoint
follows.

## No PTY, no interactive shell — this is a plain HTTP JSON API

There is nothing to note here that `ssh-demo`'s equivalent section covers;
this app has no comparable module-boundary refusal to report. What it does
NOT have is TLS termination — same posture as the `http` module's own
example (`http-demo`): terminate TLS in front, this listens plaintext on
loopback.
