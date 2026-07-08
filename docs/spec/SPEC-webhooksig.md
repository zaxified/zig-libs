# SPEC — `webhooksig`

**Purpose** — Verify (and produce) HMAC webhook signatures in the GitHub / Stripe style: gate an
inbound webhook by checking `HMAC-SHA256(secret, body)` against a signature header before the
handler trusts the payload. A `router` middleware plus standalone `sign`/`verify`.

**Model after / Seed** — clean-room from RFC 2104 (HMAC) and the publicly-documented GitHub
(`X-Hub-Signature-256`) / Stripe (`Stripe-Signature`, `t=…,v1=…`) webhook conventions. Greenfield.
See NOTICE.

**Design & invariants**
- **Constant-time compare** of the computed vs received signature (`std.crypto.timing_safe.eql`) —
  never a byte-wise early-exit compare.
- **Key rotation:** verification accepts any of a set of active secrets (rotate without downtime);
  signing uses the primary.
- HMAC via `std.crypto.auth.hmac` (SHA-256); allocation-free; hex/base64 signature encodings per the
  provider convention. The middleware reads the raw body **before** any parsing so the MAC covers
  exactly the bytes received.

**Threat model / out of scope**
- Defends against forged/unauthenticated webhook calls (attacker without the secret cannot produce a
  valid MAC) and against timing side-channels on the compare.
- **Replay:** a captured valid request can be replayed unless the caller also checks a timestamp/
  nonce — the Stripe-style `t=` timestamp is parsed/exposed but enforcing a freshness window is the
  caller's policy (documented). 
- **Out of scope:** secret storage/distribution, transport security (TLS is the server's), and
  asymmetric webhook signatures (Ed25519-style, e.g. some providers) — this is symmetric HMAC only.
- Secret material lives in caller memory; the module does not zeroize.

**Verification** — HMAC-SHA256 known-answer checks, GitHub/Stripe header-format parse tests,
constant-time-compare accept/reject, key-rotation (old+new secret) acceptance, and tamper negatives
(wrong secret, mutated body → reject). 8 tests.

**Status** — `gap · any · server · threadsafe` · deps: `router`, `http`.
