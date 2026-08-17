# aaa-gate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — Bearer parity with the API-key half, plus two escape hatches. New
  `TokenVerifyFn` + `Options.token_verify`/`token_verify_ctx`: the bearer mirror of
  `api_key_verify` — consulted after the static token set misses, outside the lock, and
  **its presence alone closes the bearer open plane** (a gate with no static tokens and a
  verifier denies even under `allow_when_unconfigured`). This is what a runtime-edited
  token file needs: without it a consumer had to mirror the external store into the gate
  on every request via `addToken`/`removeToken` diffing — retaining the secrets in
  plaintext to do so, since the gate hashes and forgets — and fake a deny-everything state
  with a sentinel token no header could present. New `Options.deny_body` /
  `deny_content_type` (default `Unauthorized\n` / `text/plain`, so the 401 is byte-identical
  unless set) let a JSON API answer denials in its own error shape instead of rewriting the
  response from an outer middleware; status, challenge, audit and throttle are unaffected.
  New `ExemptFn` + `Options.exempt`, a predicate over `*router.Ctx` that takes individual
  routes out of the protected scope whatever `protect` says — one open liveness probe on a
  service where `.mutations` would wrongly open every read; an exempt request gets no
  credential check, no identity and no audit. All three default to today's behaviour, so no
  existing consumer or test changes. Also new: an `init` test that fails the allocator at
  every index in turn — the two allocations added here extended an `errdefer` chain that
  nothing executed, let alone checked (deleting one errdefer now reports the leak).
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-04** — New module: Bearer + API-key auth (constant-time) + audit hook +
  denied-request throttle.
