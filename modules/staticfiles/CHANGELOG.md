# staticfiles — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Test-only, no production change: `fuzzSanitizePath`'s own comment said
  "Length drawn BEFORE the bytes it bounds: every mutated byte the fuzzer spends then lands
  inside the slice", and that was not true when it was written. A ranged `Smith` draw
  returns the range MINIMUM unless a whole eight-octet word already lies inside the range,
  so `raw_len` was **0** on every input the ordinary lane ever ran: `smith.bytes` got a
  zero-length slice and `sanitizePath` was called on `""` every round. The traversal-safety
  contract this harness exists to check had never been evaluated on a path. It now draws
  with one `smith.slice(&raw_buf)`, and carries a corpus: the clean paths and every
  traversal/injection vector the value tests above pin (encoded `../`, encoded backslash,
  NUL truncation, truncated percent), each with the `u64` word `allow_dotfiles` reads -
  without which that knob is dead on a corpus replay and the `allow_dotfiles = true` half,
  which is a different contract, would never run. Measured by the new `corpus:` guard: 19
  non-empty seeds, 10 accepted, **14 path segments walked**, and 2 seeds under
  `allow_dotfiles`. Segments rather than acceptance, because `sanitizePath("")` succeeds -
  the empty path is the root - so an acceptance count reads as a pass over a corpus that
  reached nothing.

- **2026-08-18** — `Handler.sendFile` is now `pub` (was `fn`, internal-only). A caller
  who already holds a resolved/opened file — e.g. it called `resolveFile` itself to
  compose an app-specific 404 page before falling back to the static handler — can
  now serve it directly (`h.sendFile(req, rw, &opened)`) instead of paying a second
  `resolveFile` inside `serve`. Ownership unchanged: `sendFile` still just borrows
  `opened` and never closes it, same as the internal call site in `serve`.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a `304 Not Modified` that cannot
  carry its `ETag` is no longer sent as a 304. `http.conditional.apply` stages the
  304 status *before* it writes the validator, so the `catch false` on that call
  swallowed the failure with the status already staged: the measured wire was
  `304 Not Modified` carrying `Content-Type` and `Content-Length: 11` for a body a
  304 must not have, with no `ETag` for the client to revalidate with next time —
  framing that contradicts itself, and a validator-less 304 that guarantees the same
  outcome on every following request. Reachable through header-**table** exhaustion
  (32 slots), not the byte budget, which is exactly the route last entry's
  escalate-to-500 cannot rescue: once middleware has set `Content-Type`, this
  handler's own `setHeader` for it is a replace that needs no slot and succeeds.
  **What changes for a consumer:** such a request now gets the full representation —
  `200 OK` with `Content-Type`, matching `Content-Length` and the body — instead of
  the malformed 304. Declining a 304 is always conformant (RFC 9110 §15.4.5 makes it
  a SHOULD, never a MUST), so the client sees a slower but correct answer rather than
  a broken one. Deliberately *not* the 500 escalation used for `Content-Type` and
  `Cache-Control`: there, what would go out is unsafe and no correct response exists;
  here a correct, safe response exists and a 500 would throw it away to advertise a
  lost round trip. The `.proceed` arm of the same call is untouched — a lost `ETag`
  on a 200 stays best-effort, like `Last-Modified`. Nothing within the header table
  changes.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a representation header that cannot be set
  now answers 500 instead of serving the body without it. `Content-Type` (both
  the file path and the directory index) and a configured `Cache-Control` were
  set with a bare `catch {}`, so once the response writer's 4 KiB copy store
  was spent — by middleware ahead of this handler — the file went out looking
  fine and silently unlabelled. An unlabelled body is MIME-sniffed by the
  browser, which is how an uploaded .txt or .jpg becomes stored XSS; a dropped
  `Cache-Control` puts content in a shared cache the operator meant to keep out
  of one. Both now discard the half-composed response and answer 500.
  **What changes for a consumer:** a response that used to be a 200 missing its
  Content-Type or Cache-Control is now a 500. Nothing within the budget
  changes. `Last-Modified`, `Accept-Ranges` and the 405's `Allow` stay
  best-effort and now say why at the call site: the first two cost only a
  conditional-request round trip or resumable downloads, and answering 500 in
  place of a 405 would throw away the more useful answer.
- **2026-08-06** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified against RFC 9110
  §13.1.2.
- **2026-07-22** — New module: path-traversal-safe static file handler over `http`.
