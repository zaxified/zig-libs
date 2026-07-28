# webhooksig — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Constant-time compare of the computed vs received signature (`std.crypto.timing_safe.eql`) — never a
byte-wise early-exit compare. Key rotation: verification accepts any of a set of active secrets
(rotate without downtime); signing uses the primary. HMAC via `std.crypto.auth.hmac` (SHA-256);
allocation-free; the signature is always **lowercase hex** — no base64 variant is implemented. The
header name and the value prefix in front of the hex are both configurable, which covers GitHub's
own scheme (`X-Hub-Signature-256: sha256=<hex>`) exactly. The middleware reads the
raw body **before** any parsing so the MAC covers exactly the bytes received. Immutable after init
(secret set + config fixed); no shared mutable state, so sharing a single `Verifier` across all
connection threads is safe without locking. Clean-room from RFC 2104 (HMAC) and the publicly-
documented GitHub `X-Hub-Signature-256: sha256=<hex>` webhook convention — see NOTICE.

**Stripe is not implemented.** Stripe's `Stripe-Signature` header is a different shape — a
comma-separated `t=<timestamp>,v1=<hex>[,v0=<hex>]` list — and its MAC is computed over
`"<timestamp>.<raw body>"`, not over the raw body alone. Neither the header parsing nor the
signed-payload construction exists anywhere in `src/`; the module's configurable `header`/`prefix`
fields cannot be bent into Stripe's format (they expect one fixed prefix followed directly by the
hex, not a multi-field comma list, and they MAC the body alone). Supporting Stripe is a separate
feature, not implemented here.

## Threat model / out of scope
Defends against forged/unauthenticated webhook calls (an attacker without the secret cannot produce a
valid MAC) and against timing side-channels on the compare. **Replay:** a captured valid request can
be replayed unless the caller also checks a timestamp/nonce; this module has no timestamp field at
all (see "Stripe is not implemented" above) — a freshness window is entirely the caller's
responsibility, layered on top (e.g. a caller-supplied header of its own). Out of scope: secret
storage/distribution, transport security (TLS is the server's), and asymmetric webhook signatures
(Ed25519-style, e.g. some providers) — this is symmetric HMAC only. Secret material lives in caller
memory; the module does not zeroize it.

## Verification
An HMAC-SHA256 known-answer check, sign→verify round-trip and GitHub-style
(`sha256=<hex>`) header-format parse/reject tests, constant-time-compare accept/reject, key-rotation
(old+new secret) acceptance, tamper negatives (wrong secret, mutated body → reject). There is no
Stripe-format test — no Stripe parsing exists to test (see above). Run: `zig build test-webhooksig`.

## Backlog / deferred
Stripe's `t=…,v1=…` header format and its `timestamp.body` MAC construction (not implemented — see
above); a base64 signature encoding (only lowercase hex exists today); beyond that, the documented
replay-window-is-caller-policy and symmetric-only (no Ed25519) scope notes above.

## Status
`gap · any · server · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.
